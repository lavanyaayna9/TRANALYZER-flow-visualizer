/*
 * t2PSkel.c
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

#include "t2PSkel.h"

//#include "t2buf.h"


/*
 * Plugin variables that may be used by other plugins MUST be declared in
 * the header file as 'extern t2PSkelFlow_t *t2PSkelFlows;'
 */

t2PSkelFlow_t *t2PSkelFlows;


/*
 * Variables from dependencies, i.e., other plugins, MUST be declared weak,
 * in order to prevent dlopen() from trying to resolve them. If the symbols
 * are missing, it means the required dependency was not loaded. The error
 * will be reported by loadPlugins.c when checking for the dependencies
 * listed in the t2Dependencies() or T2_PLUGIN_INIT_WITH_DEPS() function.
 */

//extern pktSIAT_t *pktSIAT_trees __attribute__((weak));


/*
 * If the dependency is optional, it MUST be defined with the following two
 * statements and the dependency MUST NOT be listed in t2Dependencies()
 */

//extern pktSIAT_t *pktSIAT_trees __attribute__((weak));
//pktSIAT_t *pktSIAT_trees;


/*
 * Static variables are only visible in this file
 */

static uint64_t numT2PSkelPkts;
static uint64_t numT2PSkelPkts0;

static uint8_t t2PSkelStat;


/*
 * Static functions prototypes
 */

static inline void t2PSkel_pluginReport(FILE *stream);


// Tranalyzer functions

/*
 * This describes the plugin name, version, major and minor version of
 * Tranalyzer required and dependencies
 */
T2_PLUGIN_INIT("t2PSkel", "0.9.3", 0, 9);
//T2_PLUGIN_INIT_WITH_DEPS("t2PSkel", "0.9.3", 0, 9, "tcpFlags,tcpStates");


/*
 * This function is called before processing any packet.
 */
void t2Init() {
    // allocate struct for all flows and initialize to 0
    T2_PLUGIN_STRUCT_NEW(t2PSkelFlows);
    //if (UNLIKELY(!(t2PSkelFlows = t2_calloc(mainHashMap->hashChainTableSize, sizeof(*t2PSkelFlows))))) {
    //    T2_PERR(plugin_name, "failed to allocate memory for t2PSkelFlows");
    //    exit(EXIT_FAILURE);
    //}

    t2_env_t env[ENV_T2PSKEL_N] = {};

#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_T2PSKEL_N, env);
    const int env_num = T2_ENV_VAL_INT(T2PSKEL_ENV_NUM);
    //const int env_num = strtoll(env[ENV_T2PSKEL_ENV_NUM].val, NULL, 0);
    const uint8_t rmdir = T2_ENV_VAL_UINT(T2PSKEL_RMDIR);
    //const uint8_t rmdir = strtoull(T2_ENV_VAL(T2PSKEL_RMDIR), NULL, 0);
#else // ENVCNTRL == 0
    const uint8_t rmdir = T2PSKEL_RMDIR;
    T2_SET_ENV_NUM(T2PSKEL_RMDIR);
    T2_SET_ENV_STR(T2PSKEL_F_PATH);
    T2_SET_ENV_STR(T2PSKEL_ENV_STR);
    //env[ENV_T2PSKEL_ENV_STR].key = "T2PSKEL_ENV_STR";
    //env[ENV_T2PSKEL_ENV_STR].val = T2PSKEL_ENV_STR;
    T2_SET_ENV_NUM(T2PSKEL_ENV_NUM);
    const int env_num = T2PSKEL_ENV_NUM;
#endif // ENVCNTRL

#if T2PSKEL_SAVE == 1
    T2_MKPATH(T2_ENV_VAL(T2PSKEL_F_PATH), rmdir);
#endif // T2PSKEL_SAVE == 1

    // Packet mode
    if (sPktFile) {
        // Note the trailing separators (SEP_CHR)
        fputs("t2PSkelStat" SEP_CHR
              "t2PSkelText" SEP_CHR
              , sPktFile);
    }

#if T2PSKEL_LOAD == 1
    // Load a file from the plugin folder
    FILE *file = t2_fopen_in_dir(pluginFolder, T2PSKEL_FNAME, "r");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);

    //const size_t plen = pluginFolder_len;
    //char filename[pluginFolder_len + sizeof(T2PSKEL_FNAME)];
    //memcpy(filename, pluginFolder, plen);
    //memcpy(filename + plen, T2PSKEL_FNAME, sizeof(T2PSKEL_FNAME));

    //FILE *f = fopen(filename, "r");
    //if (UNLIKELY(!f)) {
    //    T2_PERR(plugin_name, "failed to open file '%s' for reading: %s", filename, strerror(errno));
    //    exit(EXIT_FAILURE);
    //}

    // TODO do something with the file

    fclose(file);
#endif // T2PSKEL_LOAD == 1

#if ENVCNTRL > 0
    t2_free_env(ENV_T2PSKEL_N, env);
#endif // ENVCNTRL > 0
}


/*
 * This function is used to describe the columns output by the plugin
 */
binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    // 8-bits hexadecimal variable, e.g., 0x12
    BV_APPEND_H8(bv, "t2PSkelStat", "t2PSkel status");
    //bv = bv_append_bv(bv, bv_new_bv("t2PSkelStat", "t2PSkel status", BV_REPEAT_NO, 1, bt_hex_8));

    // String, e.g., "text"
    BV_APPEND_STR(bv, "t2PSkelText", "Description t2PSkelText");
    //bv = bv_append_bv(bv, bv_new_bv("t2PSkelText", "Description of t2PSkelText", BV_REPEAT_NO, 1, bt_string));

#if T2PSKEL_VAR1 == 1
    // 64-bits unsigned variable
    BV_APPEND_U64(bv, "t2PSkelVar1", "Description of t2PSkelVar1");
    //bv = bv_append_bv(bv, bv_new_bv("t2PSkelVar1", "Description of t2PSkelVar1", BV_REPEAT_NO, 1, bt_uint_64));
#endif

#if T2PSKEL_IP == 1
    // IPv4 address (32 bits), e.g., 10.0.1.2 or 0x0a000102
    // (Output format is controlled by IP4_FORMAT in utils/bin2txt.h)
    BV_APPEND_IP4(bv, "t2PSkelIP", "Description of t2PSkelIP");
    //bv = bv_append_bv(bv, bv_new_bv("t2PSkelIP", "Description of t2PSkelIP", BV_REPEAT_NO, 1, bt_ip4_addr));
#endif

    // Compound: 32-bits hexadecimal value and 16-bits hexadecimal value, e.g., 0x12488421_0x14
    BV_APPEND(bv, "t2PSkelVar3_Var4", "Description of t2PSkelVar3_Var4", 2, bt_hex_32, bt_hex_16);
    //bv = bv_append_bv(bv, bv_new_bv("t2PSkelVar3_Var4", "Description of t2PSkelVar3_Var4", BV_REPEAT_NO, 2, bt_hex_32, bt_hex_16));

#if T2PSKEL_VEC == 1
    // Repetitive compound: vector of two 8-bits unsigned int, e.g., 0_1;2_3;4_5;6_7;8_9
    BV_APPEND_R(bv, "t2PSkelVar5_Var6", "Description of t2PSkelVar5_Var6", 2, bt_uint_8, bt_uint_8);
    //bv = bv_append_bv(bv, bv_new_bv("t2PSkelVar5_Var6", "Description of t2PSkelVar5_Var6", BV_REPEAT_YES, 2, bt_uint_8, bt_uint_8));

    // A matrix
    const binary_value_t * const act_bv = bv_new_bv("t2PSkelVector", "Matrix/Multiple Vector Output", BV_REPEAT_YES, 1, bt_compound);
    bv = bv_append_bv(bv, bv_add_sv_to_bv(act_bv, 0, BV_REPEAT_YES, 1, bt_double));
#endif // T2PSKEL_VEC == 1

    return bv;
}


/*
 * This function is called every time a new flow is created.
 */
void t2OnNewFlow(packet_t *packet, unsigned long flowIndex) {
    // Reset the structure for this flow
    t2PSkelFlow_t * const t2PSkelFlowP = &t2PSkelFlows[flowIndex];
    memset(t2PSkelFlowP, '\0', sizeof(*t2PSkelFlowP));
    //T2_PLUGIN_STRUCT_RESET_ITEM(t2PSkelFlows, flowIndex);

    // If your plugin analyzes a layer 3, 4 or 7 protocol,
    // you do not need to process layer 2 flows, e.g., ARP
    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW) return;

    // In this example, we are only interested in TCP
    const uint8_t proto = flowP->l4Proto;
    if (proto != L3_TCP) return;
    // if (!PROTO_IS_TCP(flowP)) return;
    // if (!PROTO_IS_TCP(packet)) return;

    const uint16_t srcPort = flowP->srcPort;
    const uint16_t dstPort = flowP->dstPort;
    if (srcPort == T2PSKEL_PORT || dstPort == T2PSKEL_PORT) {
        t2PSkelFlowP->stat |= T2PSKEL_STAT_MYPROT;

        // Open a file
        char *filename = t2_strdup_printf("/tmp/%" PRIu64 ".txt", flowP->findex);
        t2PSkelFlowP->file = file_manager_open(t2_file_manager, filename, "w");
        free(filename);

        if (UNLIKELY(!t2PSkelFlowP->file)) {
            exit(EXIT_FAILURE);
        }
    }
}


#if ETH_ACTIVATE > 0
/*
 * This function is called for every packet with a layer 2.
 * If flowIndex is HASHTABLE_ENTRY_NOT_FOUND, this means the packet also
 * has a layer 4 and thus a call to t2OnLayer4() will follow.
 */
void t2OnLayer2(packet_t *packet, unsigned long flowIndex) {
    const ethernetHeader_t * const ethP = ETH_HEADER(packet);
    //const ethernetHeader_t * const ethP = (ethernetHeader_t*)packet->l2HdrP;

    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    // This packet does not have a layer 4.
    // Print separators (SEP_CHR) to keep the packet file aligned
    if (sPktFile) {
        fputs("0x00" /* t2PSkelStat */ SEP_CHR
                     /* t2PSkelText */ SEP_CHR
              , sPktFile);
    }
}
#endif // ETH_ACTIVATE > 0


/*
 * This function is called for every packet with a layer 4.
 */
void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    t2PSkelFlow_t * const t2PSkelFlowP = &t2PSkelFlows[flowIndex];
    const flow_t * const flowP = &flows[flowIndex];

    if (sPktFile) {
        // Do not forget the trailing separators (SEP_CHR)
        fprintf(sPktFile,
                "0x%02" B2T_PRIX8 /* t2PSkelStat */ SEP_CHR
                "%s"              /* t2PSkelText */ SEP_CHR
                , t2PSkelFlowP->stat, t2PSkelFlowP->text);
    }

    if (!t2PSkelFlowP->stat) return; // not a t2PSkel packet

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

    numT2PSkelPkts++;

    const uint16_t src_port = flowP->srcPort;
    const uint16_t dst_port = flowP->dstPort;
    const uint16_t snaplen = packet->snapL7Len;
    const uint8_t * const l7HdrP = packet->l7HdrP;

    //t2buf_t t2buf = t2buf_create(l7HdrP, snaplen);
    //while (t2buf_left(&t2buf) > 0) {
    //    uint8_t byte;
    //    if (!t2buf_read_u8(&t2buf, &byte)) return;
    //    switch (byte) {
    //        case 0: t2buf_skip_u8(&t2buf);  break;
    //        case 1: t2buf_skip_u16(&t2buf); break;
    //        case 2: t2buf_skip_u32(&t2buf); break;
    //        case 3: t2buf_skip_u64(&t2buf); break;
    //        case 4: {
    //            char *str[byte+1];
    //            t2buf_readstr(&t2buf, (uint8_t*)str, sizeof(str), T2BUF_UTF8, true);
    //            break;
    //        }
    //        default: t2buf_skip_n(&t2buf, byte); break;
    //}

    const uint8_t proto = L4_PROTO(packet);
    //const uint8_t proto = L4_PROTO(flowP);
    //const uint8_t proto = flowP->l4Proto;
    if (proto == 234) t2PSkelFlowP->numAlarms++; // dummy alarm on proto 234

    // const uint_fast8_t ipver = PACKET_IPVER(packet);
    if (PACKET_IS_IPV6(packet)) {
        const ip6Header_t * const ip6HdrP = IPV6_HEADER(packet);
        //const ip6Header_t * const ip6HdrP = (ip6Header_t*)packet->l3HdrP;
    } else { // IPv4
        const ipHeader_t * const ipHdrP = IPV4_HEADER(packet);
        //const ipHeader_t * const ipHdrP = (ipHeader_t*)packet->l3HdrP;
    }

    FILE * const file = file_manager_fp(t2_file_manager, t2PSkelFlowP->file);
    fprintf(file, "Hello Andy!\n");
    //file_manager_fputs(t2_file_manager, t2PSkelFlowP->file, "Hello Andy!");
    //file_manager_fputc(t2_file_manager, t2PSkelFlowP->file, '\n');
    //file_manager_fprintf(t2_file_manager, t2PSkelFlowP->file, "Hello %s!\n", "Andy");

    // your code
}


/*
 * This function is called once a flow is terminated.
 * Output all the statistics for the flow here.
 */
void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const t2PSkelFlow_t * const t2PSkelFlowP = &t2PSkelFlows[flowIndex];
    const flow_t * const flowP = &flows[flowIndex];

    t2PSkelStat |= t2PSkelFlowP->stat;

    T2_REPORT_ALARMS(t2PSkelFlowP->numAlarms);

    // close the file
    file_manager_close(t2_file_manager, t2PSkelFlowP->file);

    // t2PSkelStat: 8-bits variable
    OUTBUF_APPEND_U8(buf, t2PSkelFlowP->stat);
    //outputBuffer_append(buf, (char*) &t2PSkelFlowP->stat, sizeof(uint8_t));

    // t2PSkelText: String/text
    OUTBUF_APPEND_STR(buf, t2PSkelFlowP->text);
    //outputBuffer_append(buf, t2PSkelFlowP->text, strlen(t2PSkelFlowP->text)+1);

#if T2PSKEL_VAR1 == 1
    // t2PSkelVar1: 64-bits variable
    OUTBUF_APPEND_U64(buf, t2PSkelFlowP->var1);
    //outputBuffer_append(buf, (char*) &t2PSkelFlowP->var1, sizeof(uint64_t));
#endif

#if T2PSKEL_IP == 1
    // t2PSkelIP: IPv4 address: 32 bits
    OUTBUF_APPEND_IP4(buf, t2PSkelFlowP->var2);
    //OUTBUF_APPEND_U32(buf, t2PSkelFlowP->var2.IPv4.s_addr);
    //outputBuffer_append(buf, (char*) &t2PSkelFlowP->var2, sizeof(uint32_t));
#endif

    // t2PSkelVar3_Var4: compound: 32 and 16 bits
    OUTBUF_APPEND_U32(buf, t2PSkelFlowP->var3);
    OUTBUF_APPEND_U16(buf, t2PSkelFlowP->var4);
    //outputBuffer_append(buf, (char*) &t2PSkelFlowP->var3, sizeof(uint32_t));
    //outputBuffer_append(buf, (char*) &t2PSkelFlowP->var4, sizeof(uint16_t));

#if T2PSKEL_VEC == 1
    // t2PSkelVar5_Var6: repetitive compound: vector of pairs of uint8

    // First output the number of repetitions (vector length)
    OUTBUF_APPEND_NUMREP(buf, T2PSKEL_NUM);
    //uint32_t cnt = T2PSKEL_NUM;
    //OUTBUF_APPEND_NUMREP(buf, cnt);
    //OUTBUF_APPEND_U32(buf, cnt);
    //outputBuffer_append(buf, (char*) &cnt, sizeof(uint32_t));

    // Then, output the vector elements
    for (uint_fast32_t i = 0; i < T2PSKEL_NUM; i++) {
        OUTBUF_APPEND_U8(buf, t2PSkelFlowP->var5);
        OUTBUF_APPEND_U8(buf, t2PSkelFlowP->var6);
        //outputBuffer_append(buf, (char*) &t2PSkelFlowP->var5, sizeof(uint8_t));
        //outputBuffer_append(buf, (char*) &t2PSkelFlowP->var6, sizeof(uint8_t));
    }

    // Matrix / Multiple vector: doubles separated by ";" and "_"

    // First output the number of rows
    OUTBUF_APPEND_NUMREP(buf, T2PSKEL_NUM);
    //cnt = T2PSKEL_NUM;
    //OUTBUF_APPEND_NUMREP(buf, cnt);
    //OUTBUF_APPEND_U32(buf, cnt);
    //outputBuffer_append(buf, (char*) &cnt, sizeof(uint32_t));

    for (uint_fast32_t i = 0; i < T2PSKEL_NUM; i++) {
        // Then output the number of columns in this row
        OUTBUF_APPEND_NUMREP(buf, T2PSKEL_WURST);
        //cnt = T2PSKEL_WURST;
        //OUTBUF_APPEND_NUMREP(buf, cnt);
        //outputBuffer_append(buf, (char*) &cnt, sizeof(uint32_t));

        // Finally, output the entire row
        OUTBUF_APPEND(buf, t2PSkelFlowP->var7[i], T2PSKEL_WURST * sizeof(double));
        //outputBuffer_append(buf, (char*) &t2PSkelFlowP->var7[i][0], T2PSKEL_WURST * sizeof(double));
    }
#endif // T2PSKEL_VEC == 1
}


/*
 * This callback is only required for sink plugins
 * Refer to parse_binary2text() in utils/bin2txt.c for an example
 */
//void t2BufferToSink(outputBuffer_t *buf, binary_value_t *bv) {
//    // parse the buffer and dump it somewhere...
//}


/*
 * This function is provided for convenience only to avoid duplicating code and
 * to make sure the monitoring mode and the final plugin reports are synchronized.
 * If only the plugin report is needed, this function can be deleted and its
 * content directly copied to the t2PluginReport() callback below.
 */
static inline void t2PSkel_pluginReport(FILE *stream) {
    T2_FPLOG_AGGR_HEX(stream, plugin_name, t2PSkelStat); // Only print if t2PSkelStat > 0
    if (t2PSkelStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, t2PSkelStat); // Omit the test for t2PSkelStat > 0
        //T2_FPLOG_AGGR_H8(stream, plugin_name, t2PSkelStat);
        //T2_FPLOG(stream, plugin_name, "Aggregated t2PSkelStat=0x%02" B2T_PRIX8, t2PSkelStat);
        // t2PSkel: Number of t2PSkel packets: 1472 (1.47 K) [2.84%]
        T2_FPLOG_DIFFNUMP(stream, plugin_name, "Number of t2PSkel packets", numT2PSkelPkts, numPackets);
        if (numT2PSkelPkts) {
            const uint64_t numT2PSkelPktsDiff = numT2PSkelPkts - numT2PSkelPkts0;
            const double numPacketsDiff = numPackets - numPackets0;
            char hrnum[64];
            T2_CONV_NUM(numT2PSkelPktsDiff, hrnum);
            T2_FPLOG(stream, plugin_name, "Number of %s packets: %" PRIu64 "%s [%.2f%%]", plugin_name,
                    numT2PSkelPktsDiff, hrnum, 100.0 * (numT2PSkelPktsDiff / numPacketsDiff));
        }
    }
}


/*
 * This function is used to report information regarding the plugin
 * at regular interval or when a USR1 signal is received.
 */
void t2Monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        // Print the name of the variables that will be output
        case T2_MON_PRI_HDR:
            // Note the trailing separators (SEP_CHR)
            fputs("t2PSkelVar"  SEP_CHR
                  "t2PSkelStat" SEP_CHR
                  , stream);
            return;

        // Print the variables to monitor
        case T2_MON_PRI_VAL:
            // Note the trailing separators (SEP_CHR)
            fprintf(stream,
                    "%"     PRIu64    /* t2PSkelVar  */ SEP_CHR
                    "0x%02" B2T_PRIX8 /* t2PSkelStat */ SEP_CHR
                    , numT2PSkelPkts - numT2PSkelPkts0
                    , t2PSkelStat);
            break;

        // Print a report similar to t2PluginReport()
        case T2_MON_PRI_REPORT:
            t2PSkel_pluginReport(stream);
            break;

        // Invalid state, do nothing
        default:
            return;
    }

#if DIFF_REPORT == 1
    numT2PSkelPkts0 = numT2PSkelPkts;
#endif
}


/*
 * This function is used to report information regarding the plugin.
 * This will appear in the final report.
 */
void t2PluginReport(FILE *stream) {
#if DIFF_REPORT == 1
    numT2PSkelPkts0 = 0;
#endif
    t2PSkel_pluginReport(stream);
}


/*
 * This function is called once all the packets have been processed.
 * Cleanup all used memory here.
 */
void t2Finalize() {
#if T2PSKEL_STATS == 1
    // Save statistics in a new file
    FILE *file = t2_fopen_with_suffix(baseFileName, T2PSKEL_SUFFIX, "w");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);
    fputs("Write something in the file...\n", file);
    fprintf(file, "Number of %s packets: %" PRIu64 " packets\n", plugin_name, numT2PSkelPkts);
    fclose(file);
#endif // T2PSKEL_STATS == 1

    free(t2PSkelFlows);
}


/*
 * This function is used to save the state of the plugin.
 * Tranalyzer can then restore the state in a future execution.
 */
void t2SaveState(FILE *stream) {
    fprintf(stream, "%" PRIu64 "\t0x%02" PRIx8, numT2PSkelPkts, t2PSkelStat);
}


/*
 * This function is used to restore the state of the plugin.
 * 'str' represents the line written in t2SaveState()
 */
void t2RestoreState(const char *str) {
    sscanf(str, "%" SCNu64 "\t0x%02" SCNx8, &numT2PSkelPkts, &t2PSkelStat);
}


#if USE_T2BUS == 1
/*
 * XXX This callback is currently NOT used
 */
void t2BusCallback(uint32_t status) {
    // Handle t2Bus messages...
}
#endif // USE_T2BUS == 1
