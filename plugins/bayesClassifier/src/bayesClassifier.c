/*
 * bayesClassifier.c
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

#include "bayesClassifier.h"

#include "naivebayes.h"
#include "nFrstPkts.h"


// Plugin variables

classifier_t* classifier;


/*
 * Variables from dependencies, i.e., other plugins, MUST be declared weak,
 * in order to prevent dlopen() from trying to resolve them. If the symbols
 * are missing, it means the required dependency was not loaded. The error
 * will be reported by loadPlugins.c when checking for the dependencies
 * listed in the t2Dependencies() or T2_PLUGIN_INIT_WITH_DEPS() function.
 */
extern nFrstPkts_t *nFrstPkts __attribute__((weak));


// Tranalyzer functions

T2_PLUGIN_INIT_WITH_DEPS("bayesClassifier", "0.9.3", 0, 9, "nFrstPkts");


void t2Init() {
    FILE *file = t2_fopen_in_dir(pluginFolder, BAYES_CFG, "r");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);

    if (UNLIKELY(fseek(file, 0, SEEK_END) != 0)) {
        T2_PERR(plugin_name, "Failed to seek to end of '%s'", BAYES_CFG);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    const long buf_size = ftell(file);
    if (UNLIKELY(buf_size == -1)) {
        T2_PERR(plugin_name, "Failed to get the '%s' file size", BAYES_CFG);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    rewind(file);

    char * const json_encoded = t2_malloc(buf_size+1);
    if (UNLIKELY(!json_encoded)) {
        T2_PERR(plugin_name, "Failed to allocate memory for json_encoded");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    const size_t bytes_read = fread(json_encoded, sizeof(char), buf_size, file);
    if (UNLIKELY(bytes_read == 0)) {
        T2_PERR(plugin_name, "Failed to read '%s' file", BAYES_CFG);
        free(json_encoded);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    json_encoded[bytes_read] = '\0';

    fclose(file);

    classifier = classifier_from_json(json_encoded);
    if (UNLIKELY(!classifier)) {
        T2_PERR(plugin_name, "Failed to create classifier from json '%s'", json_encoded);
        free(json_encoded);
        exit(EXIT_FAILURE);
    }

    free(json_encoded);
}


binary_value_t* t2PrintHeader() {
    binary_value_t* bv = NULL;
    BV_APPEND_STRC(bv, "bayesClass", "Naive Bayes Class Name");
    return bv;
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {

    nFrstPkts_t *packet_stats = &nFrstPkts[flowIndex];
    if (UNLIKELY(!packet_stats)) {
        T2_PFATAL(plugin_name, "nFrstPkts dependency pointer is NULL");
    }

    if (packet_stats->pktCnt < BAYES_MIN_NUM_PKT) {
        T2_PDBG(plugin_name, "Flow with id: %lu, not enough packets..", flowIndex);
        OUTBUF_APPEND_STR(buf, BAYES_UNKNOWN);
        return;
    }

    // Prepare dataset
    const uint64_t dataset_len = packet_stats->pktCnt;
    uint64_t * const dataset = t2_malloc_fatal(dataset_len * sizeof(*dataset));
    for (size_t i = 0; i < dataset_len; i++) {
        dataset[i] = (uint64_t)packet_stats->pkt[i].pktLen;
    }

    const int32_t index = classifier_score_dataset(classifier, dataset, dataset_len);

    free(dataset);

    if (index < 0) {
        OUTBUF_APPEND_STR(buf, BAYES_UNKNOWN);
    } else {
        const model_t model = classifier->models[index];
        if (model.posteriori < log(BAYES_MIN_POST_PROB)) {
            OUTBUF_APPEND_STR(buf, BAYES_UNKNOWN);
        } else {
            const char *label = model.label;
            OUTBUF_APPEND_STR(buf, label);
        }
    }
}


void t2Finalize() {
    classifier_destroy(classifier);
}
