/*
 * kafkaSink.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "kafkaSink.h"

#include <errno.h>              // for errno, strerror
#include <librdkafka/rdkafka.h> // for rd_kafka_t, rd_kafka_produce, ...

#if BLOCK_BUF == 0


// Static variables

static FILE *kafka_file;
static char *kafka_buffer;
static size_t kafka_buffer_size;
static uint32_t corrupt_flows;

static rd_kafka_t *rk;
static rd_kafka_topic_t *topic;

static int kfk_partition;


#if KAFKA_DEBUG > 0

// Static functions prototypes

static void msg_delivered(rd_kafka_t *rk, const rd_kafka_message_t *msg, void *opaque);

#endif // KAFKA_DEBUG > 0

#endif // BLOCK_BUF == 0


// Tranalyzer functions

T2_PLUGIN_INIT("kafkaSink", "0.9.3", 0, 9);


void t2Init() {
#if BLOCK_BUF == 1
    T2_PWRN(plugin_name, "BLOCK_BUF is set in 'tranalyzer.h', no output will be produced");
#else // BLOCK_BUF == 0

    char errstr[512];
    t2_env_t env[ENV_KAFKA_N] = {};

#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_KAFKA_N, env);
    kfk_partition = T2_ENV_VAL_INT(KAFKA_PARTITION);
#else // ENVCNTRL == 0
    T2_SET_ENV_STR(KAFKA_BROKERS);
    T2_SET_ENV_STR(KAFKA_TOPIC);
    //T2_SET_ENV_NUM(KAFKA_PARTITION);
    kfk_partition = KAFKA_PARTITION;
#endif // ENVCNTRL

    KAFKA_DBG_INF("librdkafka version %s (0x%08x)", rd_kafka_version_str(), rd_kafka_version());

    kafka_file = open_memstream(&kafka_buffer, &kafka_buffer_size);
    if (UNLIKELY(kafka_file == NULL)) {
        T2_PFATAL(plugin_name, "open_memstream failed: %s", strerror(errno));
    }

    // Kafka configuration
    rd_kafka_conf_t *conf = rd_kafka_conf_new();

    // Set bootstrap servers
    rd_kafka_conf_res_t res = rd_kafka_conf_set(conf, "bootstrap.servers", T2_ENV_VAL(KAFKA_BROKERS), errstr, sizeof(errstr));
    if (UNLIKELY(res != RD_KAFKA_CONF_OK)) {
        T2_PFATAL(plugin_name, "%s", errstr);
    }

    // Quick termination
    char tmp[16];
    snprintf(tmp, sizeof(tmp), "%i", SIGIO);
    rd_kafka_conf_set(conf, "internal.termination.signal", tmp, NULL, 0);

#if KAFKA_DEBUG > 0
    // Message delivery report callback
    rd_kafka_conf_set_dr_msg_cb(conf, msg_delivered);
#endif // KAFKA_DEBUG > 0

    // Create producer
    rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
    if (UNLIKELY(rk == NULL)) {
        T2_PFATAL(plugin_name, "Failed to create new producer: %s", errstr);
    }

    // Create topic
    topic = rd_kafka_topic_new(rk, T2_ENV_VAL(KAFKA_TOPIC), rd_kafka_topic_conf_new());
    if (UNLIKELY(topic == NULL)) {
        T2_PFATAL(plugin_name, "Failed to create topic '%s'", T2_ENV_VAL(KAFKA_TOPIC));
    }

#if ENVCNTRL > 0
    t2_free_env(ENV_KAFKA_N, env);
#endif // ENVCNTRL > 0
#endif // BLOCK_BUF == 1
}


// If BLOCK_BUF == 1, the plugin does not produce any output.
// All the code below is therefore not activated.


#if BLOCK_BUF == 0

void t2BufferToSink(outputBuffer_t *buf, binary_value_t *bv) {
    // Convert buffer to JSON
    if (UNLIKELY(!parse_buffer_bin2json(buf, bv, kafka_file, b2t_funcs))) {
        KAFKA_DBG_ERR("Failed to convert buffer to json");
        corrupt_flows++;
        // Poll to handle delivery reports
        rd_kafka_poll(rk, 0);
        // Reset buffer
        fflush(kafka_file);
        return;
    }

    fflush(kafka_file);

    int err;

#if KAFKA_RETRIES > 0
    uint_fast8_t retries = 0;

retry:
#endif

    // Send the buffer to Kafka
    err = rd_kafka_produce(
        topic,                           // Topic
        kfk_partition,                   // Partition
        RD_KAFKA_MSG_F_COPY,
        kafka_buffer, kafka_buffer_size, // Payload and length
        NULL, 0,                         // Optional key and its length
        NULL);                           // Message opaque

    if (UNLIKELY(err != 0)) {
        KAFKA_DBG_ERR("Failed to produce to topic %s partition %i: %s",
                rd_kafka_topic_name(topic), kfk_partition,
                rd_kafka_err2str(rd_kafka_last_error()));
#if KAFKA_RETRIES > 0
        if (err == RD_KAFKA_RESP_ERR__QUEUE_FULL && ++retries < KAFKA_RETRIES) {
            rd_kafka_poll(rk, 1000); // block for max 1000ms
            goto retry;
        }
#endif

        corrupt_flows++;
        // Poll to handle delivery reports
        rd_kafka_poll(rk, 0);
        // Reset buffer
        fflush(kafka_file);
        return;
    }

    KAFKA_DBG_INF("Sent %zu bytes to topic %s partition %i",
            kafka_buffer_size, rd_kafka_topic_name(topic), kfk_partition);

    // Poll to handle delivery reports
    rd_kafka_poll(rk, 0);
}


void t2PluginReport(FILE *stream) {
    T2_FPWRN_NUMP_NP(stream, plugin_name, "Number of flows discarded", corrupt_flows, totalFlows);
}


void t2Finalize() {
    rd_kafka_flush(rk, 10 * 1000); // Wait for max 10 seconds

    const int left = rd_kafka_outq_len(rk);
    if (left > 0) {
        T2_PWRN(plugin_name, "%d message%s %s not delivered",
                left,
                ((left == 1) ? "" : "s"),
                ((left == 1) ? "was" : "were"));
    }

    rd_kafka_topic_destroy(topic);
    rd_kafka_destroy(rk);
    fclose(kafka_file);
    free(kafka_buffer);
}


#if KAFKA_DEBUG > 0
static void msg_delivered(rd_kafka_t *rk UNUSED, const rd_kafka_message_t *msg, void *opaque UNUSED) {
    if (msg->err) {
        KAFKA_DBG_ERR("Message delivery failed (broker %" PRId32 "): %s",
                rd_kafka_message_broker_id(msg),
                rd_kafka_err2str(msg->err));
    } else {
        KAFKA_DBG_INF("Message delivered (%zd bytes, offset %" PRId64 ", "
                "partition %" PRId32 ", broker %" PRId32 "): %.*s\n",
                        msg->len, msg->offset, msg->partition,
                        rd_kafka_message_broker_id(msg),
                        (int)msg->len, (const char *)msg->payload);
    }
}
#endif // KAFKA_DEBUG > 0

#endif // BLOCK_BUF == 0
