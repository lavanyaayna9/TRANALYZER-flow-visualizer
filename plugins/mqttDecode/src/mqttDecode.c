/*
 * mqttDecode.c
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

#include "mqttDecode.h"

#include "t2buf.h"


/*
 * Plugin variables that may be used by other plugins (MUST be declared in
 * the header file as 'extern mqttFlow_t *mqttFlows;'
 */
mqttFlow_t *mqttFlows;


// Static variables

static uint64_t numMQTTPkts;
static uint64_t numMQTTPkts0;
static uint16_t mqttCPT;
static uint8_t  mqttStat;
static uint8_t  mqttConAck;

#if MQTT_TOPIC_MSG == 1
static FILE *mqttFile;
#endif


/*
 * Function prototypes
 */

static inline void mqtt_pluginReport(FILE *stream);


/*
 * Macros
 */

// Packet mode
#define MQTT_SPKTMD_PRI_NONE() if (sPktFile) fputs("0x00" /* mqttStat */ SEP_CHR, sPktFile);
#define MQTT_SPKTMD_PRI() if (sPktFile) fprintf(sPktFile, "0x%02" B2T_PRIX8 /* mqttStat */ SEP_CHR, mqttFlowP->stat);


// Wrappers around t2buf_read/skip
#define MQTT_READ(size, t2buf, dst) \
    if (!t2buf_read_ ## size((t2buf), (dst))) { \
        mqttFlowP->stat |= MQTT_STAT_SNAP; \
        MQTT_SPKTMD_PRI(); \
        return; \
    }
#define MQTT_READ_U8(t2buf, dst)  MQTT_READ(u8,  t2buf, dst)
#define MQTT_READ_U16(t2buf, dst) MQTT_READ(u16, t2buf, dst)

#define MQTT_SKIP_N(t2buf, n) \
    if (!t2buf_skip_n(t2buf, n)) { \
        mqttFlowP->stat |= MQTT_STAT_SNAP; \
        MQTT_SPKTMD_PRI(); \
        return; \
    }
#define MQTT_SKIP_U8(t2buf)  MQTT_SKIP_N(t2buf, 1)
#define MQTT_SKIP_U16(t2buf) MQTT_SKIP_N(t2buf, 2)


// Tranalyzer functions

T2_PLUGIN_INIT("mqttDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(mqttFlows);

#if MQTT_TOPIC_MSG == 1
    t2_env_t env[ENV_MQTT_N] = {};

#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_MQTT_N, env);
#else // ENVCNTRL == 0
    T2_SET_ENV_STR(MQTT_TOPIC_MSG_SUFFIX);
#endif // ENVCNTRL

    mqttFile = t2_fopen_with_suffix(baseFileName, T2_ENV_VAL(MQTT_TOPIC_MSG_SUFFIX), "w");
    if (UNLIKELY(!mqttFile)) exit(EXIT_FAILURE);

    fputs(HDR_CHR "pktNo\tflowInd\tmqttTopic\tmqttMsg\n", mqttFile);

#if ENVCNTRL > 0
    t2_free_env(ENV_MQTT_N, env);
#endif // ENVCNTRL > 0
#endif // MQTT_TOPIC_MSG == 1

    // Packet mode
    if (sPktFile) {
        fputs("mqttStat" SEP_CHR, sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H8(  bv, "mqttStat"      , "MQTT status");
    BV_APPEND_H16( bv, "mqttCPT"       , "MQTT control packet types");

    // Connect
    BV_APPEND_STRC(bv, "mqttProto"     , "MQTT protocol name");
    BV_APPEND_U8(  bv, "mqttProtoLevel", "MQTT protocol level");
    BV_APPEND_STRC(bv, "mqttClientID"  , "MQTT client ID");

    // Connect Ack
    BV_APPEND_H8(  bv, "mqttConAck"    , "MQTT connection status");

    // Publish/Subscribe
    BV_APPEND_STR(bv, "mqttTopic"      , "MQTT topic");  // TODO repetitive?

    // Publish
    //BV_APPEND_STR(bv, "mqttMsg"        , "MQTT Message");

    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    mqttFlow_t * const mqttFlowP = &mqttFlows[flowIndex];
    memset(mqttFlowP, '\0', sizeof(*mqttFlowP));

    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW || flowP->l4Proto != L3_TCP) return;

    if (flowP->srcPort == MQTT_PORT || flowP->dstPort == MQTT_PORT) {
        mqttFlowP->stat |= MQTT_STAT_MQTT;
    }
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    // This packet does not have a layer 4.
    // Print tabs to keep the packet file aligned
    MQTT_SPKTMD_PRI_NONE();
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    mqttFlow_t * const mqttFlowP = &mqttFlows[flowIndex];
    if (!mqttFlowP->stat) {
        // not a MQTT packet
        MQTT_SPKTMD_PRI_NONE();
        return;
    }

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) {
        MQTT_SPKTMD_PRI();
        return;
    }

    numMQTTPkts++;

    const uint16_t snaplen = packet->snapL7Len;
    const uint8_t * const l7HdrP = packet->l7HdrP;
    t2buf_t t2buf = t2buf_create(l7HdrP, snaplen);

    while (t2buf_left(&t2buf) >= MQTT_MIN_HDRLEN) {
        // Fixed Header:
        //  - Control Packet type (4 bits)
        //  - Flags (4 bits)
        //  - Length (1-4 bytes)

        /* Control Header () */
        uint8_t hdrflags;
        MQTT_READ_U8(&t2buf, &hdrflags);

        /* Length (this does NOT include the length of the fixed header) */
        uint_fast32_t msglen = 0;
        uint_fast32_t multiplier = 1;
        uint8_t tmp;
        do {
            MQTT_READ_U8(&t2buf, &tmp);
            msglen += (tmp & 0x7f) * multiplier;
            multiplier *= 0x80;
            if (multiplier > MQTT_LEN_MAX) {
                // TODO set a bit
                MQTT_SPKTMD_PRI();
                return;
            }
        } while ((tmp & 0x80) != 0);

        const uint_fast8_t cpt = MQTT_CPT(hdrflags);
        mqttFlowP->cpt |= (1 << cpt);

        switch (cpt) {
            case MQTT_CPT_CONNECT: {
                /* Protocol Name Length */
                uint16_t len;
                MQTT_READ_U16(&t2buf, &len);
                if (len != 4 && len != 6) {
                    // Invalid proto name length, abort
                    mqttFlowP->stat = 0;
                    mqttFlowP->cpt = 0;
                    numMQTTPkts--;
                    MQTT_SPKTMD_PRI();
                    return;
                }
                /* Protocol Name */
                char proto[len+1];
                t2buf_readstr(&t2buf, (uint8_t*)proto, sizeof(proto), T2BUF_UTF8, true);
                if (memcmp(proto, MQTT_PROTONAME1, len) != 0 &&
                    memcmp(proto, MQTT_PROTONAME2, len) != 0)
                {
                    // Unrecognized proto name, abort
                    mqttFlowP->stat = 0;
                    mqttFlowP->cpt = 0;
                    numMQTTPkts--;
                    MQTT_SPKTMD_PRI();
                    return;
                }
                t2_strcpy(mqttFlowP->proto, proto, sizeof(mqttFlowP->proto), T2_STRCPY_ELLIPSIS);
                /* Protocol Level */
                MQTT_READ_U8(&t2buf, &mqttFlowP->proto_level);
                /* Connect Flags */
                uint8_t connectFlags;
                MQTT_READ_U8(&t2buf, &connectFlags);
                mqttFlowP->connect_flags |= connectFlags;
                /* Keep Alive */
                uint16_t keepAlive;
                MQTT_READ_U16(&t2buf, &keepAlive);
                /* Client ID Length */
                MQTT_READ_U16(&t2buf, &len);
                if (len == 0 || len > 23) {
                    // Server should reply with CONNACK
                    MQTT_SPKTMD_PRI();
                    return;
                }
                /* Client ID */
                char clientID[len+1];
                t2buf_readstr(&t2buf, (uint8_t*)clientID, sizeof(clientID), T2BUF_UTF8, true);
                t2_strcpy(mqttFlowP->clientID, clientID, sizeof(mqttFlowP->clientID), T2_STRCPY_ELLIPSIS);
                // TODO
                //if (connectFlags & 0x04) {
                //    /* Will Topic */
                //    /* Will Message */
                //}
                //if (connectFlags & 0x80) {
                //    /* User Name */
                //}
                //if (connectFlags & 0x40) {
                //    /* Password */
                //}
                MQTT_SPKTMD_PRI();
                return;
            }

            case MQTT_CPT_CONNACK: {
                /* Connect Flags */
                uint8_t connectFlags;
                MQTT_READ_U8(&t2buf, &connectFlags);
                mqttFlowP->connect_flags |= connectFlags;
                /* Connect Return Code */
                uint8_t retCode;
                MQTT_READ_U8(&t2buf, &retCode);
                if (retCode < 6) {
                    retCode = (1 << retCode);
                } else {
                    retCode = 0x80;
                }
                mqttFlowP->conAck = retCode;
                mqttConAck |= retCode;
                break;
            }

            case MQTT_CPT_PUBLISH: {
                /* Topic Length */
                uint16_t len;
                MQTT_READ_U16(&t2buf, &len);
                if (len == 0 || len > 256 || len > msglen) {
                    MQTT_SPKTMD_PRI();
                    return;
                }
                /* Topic */
                char topic[len+1];
                t2buf_readstr(&t2buf, (uint8_t*)topic, sizeof(topic), T2BUF_UTF8, true);
                t2_strcpy(mqttFlowP->topic, topic, sizeof(mqttFlowP->topic), T2_STRCPY_ELLIPSIS);
                /* Message */
                char msg[msglen-2-len+1];
                t2buf_readstr(&t2buf, (uint8_t*)msg, sizeof(msg), T2BUF_UTF8, true);
                //t2_strcpy(mqttFlowP->message, msg, sizeof(mqttFlowP->message), T2_STRCPY_ELLIPSIS);
#if MQTT_TOPIC_MSG == 1
                fprintf(mqttFile, "%" PRIu64 "\t%" PRIu64 "\t%s\t%s\n",
                        numPackets, flows[flowIndex].findex, topic, msg);
#endif
                // TODO where does this go?!
                const uint_fast8_t qos = (MQTT_FLAGS(hdrflags) & MQTT_PUBLISH_F_QOS);
                if (qos == 1 || qos == 2) {
                     /* Message Identifier */
                     MQTT_SKIP_U16(&t2buf);
                }
                break;
            }

            case MQTT_CPT_PUBACK:
            case MQTT_CPT_PUBREC:
            case MQTT_CPT_PUBREL:
            case MQTT_CPT_PUBCOMP: {
                /* Message Identifier */
                MQTT_SKIP_U16(&t2buf);
                break;
            }

            case MQTT_CPT_SUBSCRIBE: {
                /* Message Identifier */
                MQTT_SKIP_U16(&t2buf);
                // TODO there could be more than one topic...
                /* Topic Length */
                uint16_t len;
                MQTT_READ_U16(&t2buf, &len);
                if (len == 0 || len > 256 || len > msglen) {
                    MQTT_SPKTMD_PRI();
                    return;
                }
                /* Topic */
                char topic[len+1];
                t2buf_readstr(&t2buf, (uint8_t*)topic, sizeof(topic), T2BUF_UTF8, true);
                t2_strcpy(mqttFlowP->topic, topic, sizeof(mqttFlowP->topic), T2_STRCPY_ELLIPSIS);
                /* Requested QoS */
                MQTT_SKIP_U8(&t2buf);
                break;
            }

            case MQTT_CPT_SUBACK: {
                /* Message Identifier */
                MQTT_SKIP_U16(&t2buf);
                /* Return Code */
                MQTT_SKIP_U8(&t2buf);
                break;
            }

            case MQTT_CPT_UNSUBSCRIBE:
            case MQTT_CPT_UNSUBACK: {
                /* Message Identifier */
                MQTT_SKIP_U16(&t2buf);
                break;
            }

            case MQTT_CPT_PINGREQ:
            case MQTT_CPT_PINGRESP:
            case MQTT_CPT_DISCONNECT:
                /* No variable header, no payload */
                break;

            case MQTT_CPT_RESERVED0:
            case MQTT_CPT_RESERVED15:
                mqttFlowP->stat |= MQTT_STAT_RSVD;
                MQTT_SPKTMD_PRI();
                return;

            default:
                // Should not happen
                break;
        }
        MQTT_SKIP_N(&t2buf, msglen);
    }

    MQTT_SPKTMD_PRI();
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const mqttFlow_t * const mqttFlowP = &mqttFlows[flowIndex];

    mqttStat |= mqttFlowP->stat;
    mqttCPT  |= mqttFlowP->cpt;

    OUTBUF_APPEND_U8( buf, mqttFlowP->stat);
    OUTBUF_APPEND_U16(buf, mqttFlowP->cpt);
    OUTBUF_APPEND_STR(buf, mqttFlowP->proto);
    OUTBUF_APPEND_U8( buf, mqttFlowP->proto_level);
    OUTBUF_APPEND_STR(buf, mqttFlowP->clientID);
    OUTBUF_APPEND_U8( buf, mqttFlowP->conAck);
    OUTBUF_APPEND_STR(buf, mqttFlowP->topic);
    //OUTBUF_APPEND_STR(buf, mqttFlowP->message);
}


static inline void mqtt_pluginReport(FILE *stream) {
    if (mqttStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, mqttStat);
        T2_FPLOG_DIFFNUMP(stream, plugin_name, "Number of MQTT packets", numMQTTPkts, numPackets);
        if (mqttCPT) T2_FPLOG(stream, plugin_name, "Aggregated Control Packet Types: mqttCPT=0x%04" B2T_PRIX16, mqttCPT);
        if (mqttConAck) T2_FPLOG(stream, plugin_name, "Aggregated Connection Status: mqttConAck=0x%02" B2T_PRIX8, mqttConAck);
    }
}


void t2Monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        case T2_MON_PRI_HDR:
            fputs("mqttPkts" SEP_CHR
                  , stream);
            return;

        case T2_MON_PRI_VAL:
            fprintf(stream,
                    "%" PRIu64 /* mqttPkts */ SEP_CHR
                    , numMQTTPkts - numMQTTPkts0);
            break;

        case T2_MON_PRI_REPORT:
            mqtt_pluginReport(stream);
            break;

        // Invalid state, do nothing
        default:
            return;
    }

#if DIFF_REPORT == 1
    numMQTTPkts0 = numMQTTPkts;
#endif
}


void t2PluginReport(FILE *stream) {
#if DIFF_REPORT == 1
    numMQTTPkts0 = 0;
#endif
    mqtt_pluginReport(stream);
}


void t2Finalize() {
    free(mqttFlows);
#if MQTT_TOPIC_MSG == 1
    fclose(mqttFile);
#endif
}


void t2SaveState(FILE *stream) {
    fprintf(stream, "%" PRIu64 "\t%" PRIu64 "\t"    // numMQTTPkts, numMQTTPkts0
                    "0x%02" PRIx8 "\t0x%04" PRIx16, // mqttStat, mqttCPT
                    numMQTTPkts, numMQTTPkts0,
                    mqttStat, mqttCPT);
}


void t2RestoreState(const char *str) {
    sscanf(str, "%" SCNu64 "\t%" SCNu64 "\t"    // numMQTTPkts, numMQTTPkts0
                "0x%02" SCNx8 "\t0x%04" SCNx16, // mqttStat, mqttCPT
                &numMQTTPkts, &numMQTTPkts0,
                &mqttStat, &mqttCPT);
}
