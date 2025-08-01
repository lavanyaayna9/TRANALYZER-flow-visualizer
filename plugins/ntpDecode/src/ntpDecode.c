/*
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

#include "ntpDecode.h"


// Global variables

ntpFlow_t *ntpFlow;


// Static variables

static uint64_t numNTPPkts, numNTPPkts0;
static uint8_t ntpStat;


// Tranalyzer functions

T2_PLUGIN_INIT("ntpDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(ntpFlow);
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H8(bv, "ntpStat", "NTP status, warnings and errors");

#if NTP_LIVM_HEX == 1
    BV_APPEND_H8(bv, "ntpLiVM", "NTP leap indicator, version number and mode");
#else // NTP_LIVM_HEX == 0
    BV_APPEND(bv, "ntpLi_V_M", "NTP leap indicator, version number and mode", 3, bt_uint_8, bt_uint_8, bt_uint_8);
#endif // NTP_LIVM_HEX == 0
    BV_APPEND_H8(bv,   "ntpStrat"    , "NTP stratum");
    BV_APPEND_IP4(bv,  "ntpRefClkId" , "NTP root reference clock ID (stratum >= 2)");
    BV_APPEND_STRC(bv, "ntpRefStrId" , "NTP root reference string (stratum <= 1)");
    BV_APPEND_U32(bv,  "ntpPollInt"  , "NTP poll interval");
    BV_APPEND_FLT(bv,  "ntpPrec"     , "NTP precision");
    BV_APPEND_FLT(bv,  "ntpRtDelMin" , "NTP root delay minimum");
    BV_APPEND_FLT(bv,  "ntpRtDelMax" , "NTP root delay maximum");
    BV_APPEND_FLT(bv,  "ntpRtDispMin", "NTP root dispersion minimum");
    BV_APPEND_FLT(bv,  "ntpRtDispMax", "NTP root dispersion maximum");
#if NTP_TS == 1
    BV_APPEND_TIMESTAMP(bv, "ntpRefTS" , "NTP reference timestamp");
    BV_APPEND_TIMESTAMP(bv, "ntpOrigTS", "NTP originate timestamp");
    BV_APPEND_TIMESTAMP(bv, "ntpRecTS" , "NTP receive timestamp");
    BV_APPEND_TIMESTAMP(bv, "ntpTranTS", "NTP transmit timestamp");
#endif // NTP_TS == 1

    return bv;
}


void t2OnNewFlow(packet_t* packet, unsigned long flowIndex) {
    ntpFlow_t * const ntpFlowP = &ntpFlow[flowIndex];
    memset(ntpFlowP, '\0', sizeof(ntpFlow_t));

    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->l4Proto != L3_UDP) return;

    const udpHeader_t * const udpHdrP = UDP_HEADER(packet);
    if (udpHdrP->dest != L3_NTPn && udpHdrP->source != L3_NTPn) return;

    const uint8_t * const ntpDP = packet->l7HdrP;
    const uint32_t * const ntpDP32 = (uint32_t*)(packet->l7HdrP + 4);

    ntpFlowP->livm = *ntpDP;
    ntpFlowP->strat = ntpDP[1];
    ntpFlowP->pollInt = ntpDP[2];
    ntpFlowP->prec = ntpDP[3];

    ntpFlowP->rootDelMin = ntpFlowP->rootDelMax = ntohl(*ntpDP32);
    ntpFlowP->rootDispMin = ntpFlowP->rootDispMax = ntohl(ntpDP32[1]);

    ntpFlowP->refClkID = ntpDP32[2];

    ntpFlowP->stat = NTP_DTCT;
}


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {

    ntpFlow_t * const ntpFlowP = &ntpFlow[flowIndex];
    if (!ntpFlowP->stat) return;

    numNTPPkts++;

    const uint8_t * const ntpDP = packet->l7HdrP;
    const uint32_t * const ntpDP32 = (uint32_t*)(ntpDP+4);

    uint32_t root = ntohl(*ntpDP32);
    if (root > ntpFlowP->rootDelMax) ntpFlowP->rootDelMax = root;
    if (root < ntpFlowP->rootDelMin) ntpFlowP->rootDelMin = root;

    root = ntohl(ntpDP32[1]);
    if (root > ntpFlowP->rootDispMax) ntpFlowP->rootDispMax = root;
    if (root < ntpFlowP->rootDispMin) ntpFlowP->rootDispMin = root;

#if NTP_TS == 1
    const uint64_t * const ntpDP64 = (uint64_t*)(ntpDP+16);
    for (uint_fast8_t j = 0; j < 4; j++) ntpFlowP->tS[j] = ntpDP64[j];
#endif // NTP_TS == 1
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    ntpFlow_t * const ntpFlowP = &ntpFlow[flowIndex];

    ntpStat |= ntpFlowP->stat;

    OUTBUF_APPEND_U8(buf, ntpFlowP->stat); // ntpStat

    // ntpLiVM/ntpLi_V_M
#if NTP_LIVM_HEX == 1
    OUTBUF_APPEND_U8(buf, ntpFlowP->livm);
#else // NTP_LIVM_HEX == 0
    uint8_t tmp = ntpFlowP->livm >> 6; // leap indicator
    OUTBUF_APPEND_U8(buf, tmp);
    tmp = (ntpFlowP->livm & 0x38) >> 3; // version number
    OUTBUF_APPEND_U8(buf, tmp);
    tmp = (ntpFlowP->livm & 0x7); // mode
    OUTBUF_APPEND_U8(buf, tmp);
#endif // NTP_LIVM_HEX == 0

    OUTBUF_APPEND_U8(buf, ntpFlowP->strat); // ntpStrat

    // ntpRefClkId, ntpRefStrId
    char s[5] = {};
    if (ntpFlowP->strat < 2) {
        memcpy(s, &ntpFlowP->refClkID, 4);
        ntpFlowP->refClkID = 0;
    }
    OUTBUF_APPEND_U32(buf, ntpFlowP->refClkID); // ntpRefClkId
    OUTBUF_APPEND_STR(buf, s);                  // ntpRefStrId

    uint32_t pollInt = 0;
    float root_f[5] = {};

    if (ntpFlowP->stat) {
        pollInt = 1 << ntpFlowP->pollInt;
        uint64_t prec = ~ntpFlowP->prec;
        root_f[0] = 1.0 / (1 << ++prec);
        root_f[1] = (float)(ntpFlowP->rootDelMin  >> 16) + (float)(ntpFlowP->rootDelMin  & 0x0000ffff) / 65535.0;
        root_f[2] = (float)(ntpFlowP->rootDelMax  >> 16) + (float)(ntpFlowP->rootDelMax  & 0x0000ffff) / 65535.0;
        root_f[3] = (float)(ntpFlowP->rootDispMin >> 16) + (float)(ntpFlowP->rootDispMin & 0x0000ffff) / 65535.0;
        root_f[4] = (float)(ntpFlowP->rootDispMax >> 16) + (float)(ntpFlowP->rootDispMax & 0x0000ffff) / 65535.0;
    }

    OUTBUF_APPEND_U32(buf, pollInt); // ntpPollInt

    // ntpPrec, ntpRtDelMin, ntpRtDelMax, ntpRtDispMin, ntpRtDelMax
    OUTBUF_APPEND(buf, root_f, 5 * sizeof(float));

#if NTP_TS == 1
    // ntpRefTS, ntpOrigTS, ntpRecTS, ntpTranTS
    uint64_t sec[4] = {};
    uint32_t ms[4] = {};
    for (uint_fast8_t j = 0; j < 4; j++) {
        const uint64_t tS = htobe64(ntpFlowP->tS[j]);
        if (tS) {
            sec[j] = ((tS >> 32) - NTPTSHFT);
            ms[j] = 1000000000 * (double)(tS & 0xffffffff) / (double)0xffffffff;
            // make sure the milliseconds get rounded to the nearest value
            ms[j] = 1000 * (ms[j] / 1000.0 + 0.5);
        }
        OUTBUF_APPEND_TIME(buf, sec[j], ms[j]);
    }
#endif // NTP_TS == 1
}


static inline void ntp_pluginReport(FILE *stream) {
    if (ntpStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, ntpStat);
        T2_FPLOG_DIFFNUMP(stream, plugin_name, "Number of NTP packets", numNTPPkts, numPackets);
    }
}


void t2PluginReport(FILE *stream) {
#if DIFF_REPORT == 1
    numNTPPkts0 = 0;
#endif // DIFF_REPORT == 1
    ntp_pluginReport(stream);
}


void t2Monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        case T2_MON_PRI_HDR:
            fputs("ntpPkts" SEP_CHR
                  , stream);
            return;

        case T2_MON_PRI_VAL:
            fprintf(stream,
                    "%" PRIu64 /* ntpPkts */ SEP_CHR
                    , numNTPPkts - numNTPPkts0);
            break;

        case T2_MON_PRI_REPORT:
            ntp_pluginReport(stream);
            break;

        default:  // Invalid state, do nothing
            return;
    }

#if DIFF_REPORT == 1
    numNTPPkts0 = numNTPPkts;
#endif // DIFF_REPORT == 1
}


void t2Finalize() {
    free(ntpFlow);
}
