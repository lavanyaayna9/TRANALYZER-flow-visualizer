/*
 * nDPI.c
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

// local includes
#include "nDPI.h"
#include "t2Plugin.h"

#if NDPI_OUTPUT_STATS != 0
#include "ndpi_protocol_ids.h"
#endif

// global includes
#include <stdio.h>


// Global variables

nDPI_flow_t *nDPI_flows;


// Static variables

static uint64_t num_classified;
static struct ndpi_detection_module_struct *nDPIstruct;

#if NDPI_OUTPUT_STATS != 0
static struct {
    uint64_t pkts;
    uint64_t bytes;
} nDPIstats[NDPI_MAX_SUPPORTED_PROTOCOLS];
#endif


// Static functions prototypes

#if NDPI_GUESS_UNKNOWN == 0
static inline const char *ndpi_cfg_error2string(const ndpi_cfg_error err);
#endif // NDPI_GUESS_UNKNOWN == 0


// Tranalyzer functions

T2_PLUGIN_INIT("nDPI", "0.9.3", 0, 9);


void t2Init() {
    // allocate struct for all flows and initialize to 0
    T2_PLUGIN_STRUCT_NEW(nDPI_flows);

    // initialize nDPI global strucure
    NDPI_PROTOCOL_BITMASK all;
    nDPIstruct = ndpi_init_detection_module(NULL);

    // enable all protocols
    NDPI_BITMASK_SET_ALL(all);
    ndpi_set_protocol_detection_bitmask2(nDPIstruct, &all);

#if NDPI_GUESS_UNKNOWN == 0
    int rc;
    rc = ndpi_set_config(nDPIstruct, NULL, "dpi.guess_on_giveup", "0");
    if (UNLIKELY(rc != NDPI_CFG_OK)) {
        T2_PWRN(plugin_name, "Failed to disable protocol guessing: %s", ndpi_cfg_error2string(rc));
    }
#endif // NDPI_GUESS_UNKNOWN == 0

    ndpi_finalize_initialization(nDPIstruct);

#if (NDPI_OUTPUT_NUM || NDPI_OUTPUT_STR)
   if (sPktFile) {
      fputs(
#if NDPI_OUTPUT_NUM != 0
            "nDPIMstrProto" SEP_CHR
            "nDPISubProto"  SEP_CHR
#endif //NDPI_OUTPUT_NUM != 0
#if NDPI_OUTPUT_STR != 0
            "nDPIclass"     SEP_CHR
#endif // NDPI_OUTPUT_STR != 0
      , sPktFile);
   }
#endif // (NDPI_OUTPUT_NUM || NDPI_OUTPUT_STR)
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

#if NDPI_OUTPUT_NUM != 0
    BV_APPEND_U16(bv, "nDPIMstrProto", "nDPI numerical master protocol");
    BV_APPEND_U16(bv, "nDPISubProto" , "nDPI numerical sub protocol");
#endif // NDPI_OUTPUT_NUM != 0

#if NDPI_OUTPUT_STR != 0
    BV_APPEND_STR(bv, "nDPIclass", "nDPI based protocol classification");
#endif // NDPI_OUTPUT_STR != 0

    return bv;
}


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    flow_t *flowP = &flows[flowIndex];
    nDPI_flow_t *nDPI_P = &nDPI_flows[flowIndex];
    memset(nDPI_P, 0, sizeof(nDPI_flow_t)); // set everything to 0

    // if nDPI structures are already defined in opposite flow, link them in this flow
    const unsigned long oppositeFlowIndex = flowP->oppositeFlowIndex;
    if (oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
        nDPI_flow_t *opposite_nDPI_P = &nDPI_flows[oppositeFlowIndex];
        nDPI_P->ndpiFlow = opposite_nDPI_P->ndpiFlow;
        return;
    }

    // otherwise, initialize nDPI structures in this flow
    if (!(nDPI_P->ndpiFlow = ndpi_flow_malloc(SIZEOF_FLOW_STRUCT))) {
        T2_PERR(plugin_name, "failed to allocate memory for ndpi_flow_struct");
        terminate();
    }
    memset(nDPI_P->ndpiFlow, 0, SIZEOF_FLOW_STRUCT);
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
#if (NDPI_OUTPUT_NUM || NDPI_OUTPUT_STR)
    if (sPktFile) {
        fputs(
#if NDPI_OUTPUT_NUM != 0
            /* nDPIMstrProto */ SEP_CHR
            /* nDPISubProto  */ SEP_CHR
#endif //NDPI_OUTPUT_NUM != 0
#if NDPI_OUTPUT_STR != 0
            /* nDPIclass     */ SEP_CHR
#endif // NDPI_OUTPUT_STR != 0
            , sPktFile);
    }
#endif // (NDPI_OUTPUT_NUM || NDPI_OUTPUT_STR)
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
    nDPI_flow_t *nDPI_P = &nDPI_flows[flowIndex];
    ++nDPI_P->sent_pkts;
#if NDPI_OUTPUT_STATS == 1
    nDPI_P->sent_bytes += packet->snapLen;
#endif
    if (nDPI_P->done) {
#if (NDPI_OUTPUT_NUM || NDPI_OUTPUT_STR)
        goto ndpe;
#else // (NDPI_OUTPUT_NUM || NDPI_OUTPUT_STR) == 0
        return;
#endif // (NDPI_OUTPUT_NUM || NDPI_OUTPUT_STR)
    }

    flow_t *flowP = &flows[flowIndex];

    const uint64_t time_ms = ((uint64_t) packet->pcapHdrP->ts.tv_sec) * 1000 +
            packet->pcapHdrP->ts.tv_usec / (TSTAMPFAC / 1000);

#if NDPI_GUESS_UNKNOWN != 0
    uint16_t ip_len = packet->snapL3Len;
    if (ip_len > NDPI_MAX_PKT_LEN) {
        //T2_PWRN(plugin_name, "packet too long: %u snapped to %u", ip_len, NDPI_MAX_PKT_LEN);
        ip_len = NDPI_MAX_PKT_LEN;
    }
    memcpy(nDPI_P->ndpi_pkt, packet->l3HdrP, ip_len);
    const uint8_t * const ip_pkt = nDPI_P->ndpi_pkt;
#else // NDPI_GUESS_UNKNOWN == 0
    const uint16_t ip_len = packet->snapL3Len;
    const uint8_t * const ip_pkt = (uint8_t *)packet->l3HdrP;
#endif // NDPI_GUESS_UNKNOWN != 0

    // detect protocol using nDPI
    nDPI_P->classification = ndpi_detection_process_packet(
        nDPIstruct, // nDPI global data structure
        nDPI_P->ndpiFlow, // nDPI per flow data structure
        ip_pkt,
        ip_len,
        time_ms,
        NULL);

    if (nDPI_P->classification.app_protocol != NDPI_PROTOCOL_UNKNOWN ||
            // give up conditions: taken from ndpiReader
            (flowP->l4Proto == L3_UDP && nDPI_P->sent_pkts > 8) ||
            (flowP->l4Proto == L3_TCP && nDPI_P->sent_pkts > 10)) {
        nDPI_P->done = true;
        // newer version of nDPI do not work properly without guessing
        if (nDPI_P->classification.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
            uint8_t protocol_was_guessed;
            nDPI_P->classification = ndpi_detection_giveup(nDPIstruct, nDPI_P->ndpiFlow,
                    &protocol_was_guessed);
        }
        // also store classification in opposite flow
        const unsigned long oppositeFlowIndex = flowP->oppositeFlowIndex;
        if (oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
            nDPI_flows[oppositeFlowIndex].classification = nDPI_P->classification;
            nDPI_flows[oppositeFlowIndex].done = true;
        }
    }

#if (NDPI_OUTPUT_NUM || NDPI_OUTPUT_STR)
ndpe:
    if (sPktFile) {
#if NDPI_OUTPUT_STR != 0
        char buf[NDPI_BUFFER_LEN];
        ndpi_protocol2name(nDPIstruct, nDPI_P->classification, buf, NDPI_BUFFER_LEN);
#endif // NDPI_OUTPUT_STR != 0
        fprintf(sPktFile,
#if NDPI_OUTPUT_NUM != 0
             "%" PRIu16 /* nDPIMstrProto */ SEP_CHR
             "%" PRIu16 /* nDPISubProto  */ SEP_CHR
#endif //NDPI_OUTPUT_NUM != 0
#if NDPI_OUTPUT_STR != 0
             "%s"       /* nDPIclass     */ SEP_CHR
#endif // NDPI_OUTPUT_STR != 0
#if NDPI_OUTPUT_NUM != 0
             , nDPI_P->classification.master_protocol
             , nDPI_P->classification.app_protocol
#endif // NDPI_OUTPUT_NUM != 0
#if NDPI_OUTPUT_STR != 0
             , buf
#endif // NDPI_OUTPUT_STR != 0
         );
    }
#endif // (NDPI_OUTPUT_NUM || NDPI_OUTPUT_STR)
}

void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf
#if (NDPI_OUTPUT_NUM == 0 && NDPI_OUTPUT_STR == 0)
    UNUSED
#endif
) {
    nDPI_flow_t *nDPI_P = &nDPI_flows[flowIndex];
    const flow_t * const flowP = &flows[flowIndex];
    const unsigned long oppositeFlowIndex = flowP->oppositeFlowIndex;

    // if nDPI detection was not finished before end of flow, try guessing
    if (!nDPI_P->done) {
        uint8_t protocol_was_guessed;
        nDPI_P->classification = ndpi_detection_giveup(nDPIstruct, nDPI_P->ndpiFlow,
                &protocol_was_guessed);
        if (oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
            nDPI_flows[oppositeFlowIndex].classification = nDPI_P->classification;
        }
    }

    uint16_t masterProtocol = nDPI_P->classification.master_protocol;

#if (NDPI_OUTPUT_NUM | NDPI_OUTPUT_STATS) != 0
    uint16_t appProtocol = nDPI_P->classification.app_protocol;
    // if only app protocol is defined, move it to master protocol
    if (masterProtocol == NDPI_PROTOCOL_UNKNOWN && appProtocol != NDPI_PROTOCOL_UNKNOWN) {
        masterProtocol = appProtocol;
        appProtocol = NDPI_PROTOCOL_UNKNOWN;
    }
#endif // (NDPI_OUTPUT_NUM | NDPI_OUTPUT_STATS) != 0

#if NDPI_OUTPUT_NUM != 0
    OUTBUF_APPEND_U16(buf, masterProtocol);
    OUTBUF_APPEND_U16(buf, appProtocol);
#endif // NDPI_OUTPUT_NUM != 0

    // output nDPI protocol classification string
#if NDPI_OUTPUT_STR != 0
    char buffer[NDPI_BUFFER_LEN];
    ndpi_protocol2name(nDPIstruct, nDPI_P->classification, buffer, NDPI_BUFFER_LEN);
    OUTBUF_APPEND_STR(buf, buffer);
#endif // NDPI_OUTPUT_STR != 0

    // release nDPI per flow structures
    if (oppositeFlowIndex == HASHTABLE_ENTRY_NOT_FOUND || FLOW_IS_B(flowP)) {
        ndpi_free_flow(nDPI_P->ndpiFlow);
    }

    if (masterProtocol != NDPI_PROTOCOL_UNKNOWN) num_classified++;

#if NDPI_OUTPUT_STATS != 0
    // increase the stats counters
    nDPIstats[masterProtocol].pkts += nDPI_P->sent_pkts;
    nDPIstats[masterProtocol].bytes += nDPI_P->sent_bytes;
    // if there is a sub protocol, count this flow in both protocols
    // for instance DNS.Google will count in Google and in DNS
    if (appProtocol != NDPI_PROTOCOL_UNKNOWN) {
        nDPIstats[appProtocol].pkts += nDPI_P->sent_pkts;
        nDPIstats[appProtocol].bytes += nDPI_P->sent_bytes;
    }
#endif // NDPI_OUTPUT_STATS != 0
}


void t2PluginReport(FILE *stream) {
    T2_FPLOG_NUMP(stream, plugin_name, "Number of flows classified", num_classified, totalFlows);
}


void t2Finalize() {
#if NDPI_OUTPUT_STATS != 0
    // open file
    FILE *file = t2_fopen_with_suffix(baseFileName, NDPI_STATS_SUFFIX, "w");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);

    // print the header line
    fprintf(file, "# Protocol ID\t%30s\t%30s\tDescription\n", "Packets", "Bytes");

    // print the frequency for each protocol
    const double percent_pkts = 100.0 / (double)numPackets;
    const double percent_bytes = 100.0 / (double)bytesProcessed;
    for (uint_fast16_t i = 0; i < NDPI_MAX_SUPPORTED_PROTOCOLS; ++i) {
        const uint64_t pkt_count = nDPIstats[i].pkts;
        if (pkt_count != 0) {
            const uint64_t byte_count = nDPIstats[i].bytes;
            const double pkt_freq = pkt_count * percent_pkts;
            const double byte_freq = byte_count * percent_bytes;
            const char * const protoDescr = ndpi_get_proto_name(nDPIstruct, i);
            fprintf(file, "%3" PRIuFAST16 "\t"    // i
                    "%20" PRIu64 " [%6.02f%%]\t"  // pkt_count, pkt_freq
                    "%20" PRIu64 " [%6.02f%%]\t"  // byte_count, byte_freq
                    "%s\n", i,                    // protoDescr
                    pkt_count, pkt_freq,
                    byte_count, byte_freq,
                    protoDescr);
        }
    }

    // flush and close the file
    fflush(file);
    fclose(file);
#endif // NDPI_OUTPUT_STATS != 0

    // release nDPI global structure
    if (nDPIstruct) {
        ndpi_exit_detection_module(nDPIstruct);
        nDPIstruct = NULL;
    }

    // release memory allocated for this plugin
    free(nDPI_flows);
}


#if NDPI_GUESS_UNKNOWN == 0
// Adapted from ndpiReader.c
static inline const char *ndpi_cfg_error2string(const ndpi_cfg_error err) {
    switch (err) {
        case NDPI_CFG_INVALID_CONTEXT:
            return "Invalid context";
        case NDPI_CFG_NOT_FOUND:
            return "Configuration not found";
        case NDPI_CFG_INVALID_PARAM:
            return "Invalid configuration parameter";
        case NDPI_CFG_CONTEXT_ALREADY_INITIALIZED:
            return "Configuration context already initialized";
        case NDPI_CFG_CALLBACK_ERROR:
            return "Configuration callback error";
        case NDPI_CFG_OK:
            return "Success";
        default:
            return "Unknown";
    }
}
#endif // NDPI_GUESS_UNKNOWN == 0
