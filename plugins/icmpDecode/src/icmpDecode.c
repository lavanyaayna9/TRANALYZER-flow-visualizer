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

#include "icmpDecode.h"


// Global variables

icmpFlow_t *icmpFlows;


// Static variables

static uint8_t icmpStat;
static uint64_t numEchoRequests, numEchoRequests0;
static uint64_t numEchoReplies, numEchoReplies0;
static uint64_t numICMPPackets, numICMPPackets0;

#if IPV6_ACTIVATE > 0
static uint64_t numDestUnreach6[8];
static uint64_t numEcho6[2];
static uint64_t numParamProblem[3];
static uint64_t numPktTooBig;
static uint64_t numTimeExceeded6[2];
static uint64_t num_icmp6[255][8];
#endif // IPV6_ACTIVATE > 0

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
static uint64_t numDestUnreach4[16];
static uint64_t numEcho4[2];
static uint64_t numRedirect[4];
static uint64_t numSourceQuench;
static uint64_t numTimeExceeded4[2];
static uint64_t numTraceroutes;
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if ICMP_STATFILE == 1
#if IPV6_ACTIVATE > 0
// From 130 (MCAST_QUERY) to 158 (DUP_ADDR_CONF)
// Access with code - 130
static const char *icmp6_code_str[] = {
    "ICMP6_MCAST_QUERY",
    "ICMP6_MCAST_REP",
    "ICMP6_MCAST_DONE",
    "ICMP6_RTER_SOLICIT",
    "ICMP6_RTER_ADVERT",
    "ICMP6_NBOR_SOLICIT",
    "ICMP6_NBOR_ADVERT",
    "ICMP6_REDIRECT_MSG",
    "ICMP6_RTER_RENUM",
    "ICMP6_NODE_INFO_QUERY",
    "ICMP6_NODE_INFO_RESP",
    "ICMP6_INV_NBOR_DSM",
    "ICMP6_INV_NBOR_DAM",
    "ICMP6_MLD2",
    "ICMP6_ADDR_DISC_REQ",
    "ICMP6_ADDR_DISC_REP",
    "ICMP6_MOB_PREF_SOL",
    "ICMP6_MOB_PREF_ADV",
    "ICMP6_CERT_PATH_SOL",
    "ICMP6_CERT_PATH_ADV",
    "ICMP6_EXP_MOBI",
    "ICMP6_MRD_ADV",
    "ICMP6_MRD_SOL",
    "ICMP6_MRD_TERM",
    "ICMP6_FMIPV6",
    "ICMP6_RPL_CTRL",
    "ICMP6_ILNP_LOC_UP",
    "ICMP6_DUP_ADDR_REQ",
    "ICMP6_DUP_ADDR_CON"
};
static const char *icmp6_dest_unreach_code_str[] = {
    "ICMP6_NO_ROUTE"     , // 0
    "ICMP6_COMM_PROHIBIT", // 1
    "ICMP6_BEYOND_SCOPE" , // 2
    "ICMP6_ADDR_UNREACH" , // 3
    "ICMP6_PORT_UNREACH" , // 4
    "ICMP6_SR_FAILED"    , // 5
    "ICMP6_REJECT"       , // 6
    "ICMP6_ERROR_HDR"      // 7
};
#endif // IPV6_ACTIVATE > 0

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
static const char *icmp_dest_unreach_code_str[] = {
    "ICMP_NET_UNREACH"   , //  0
    "ICMP_HOST_UNREACH"  , //  1
    "ICMP_PROT_UNREACH"  , //  2
    "ICMP_PORT_UNREACH"  , //  3
    "ICMP_FRAG_NEEDED"   , //  4
    "ICMP_SR_FAILED"     , //  5
    "ICMP_NET_UNKNOWN"   , //  6
    "ICMP_HOST_UNKNOWN"  , //  7
    "ICMP_HOST_ISOLATED" , //  8
    "ICMP_NET_ANO"       , //  9
    "ICMP_HOST_ANO"      , // 10
    "ICMP_NET_UNR_TOS"   , // 11
    "ICMP_HOST_UNR_TOS"  , // 12
    "ICMP_PKT_FILTERED"  , // 13
    "ICMP_PREC_VIOLATION", // 14
    "ICMP_PREC_CUTOFF"     // 15
};
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
#endif // ICMP_STATFILE == 1


#if ICMP_PARENT == 1 && ETH_ACTIVATE != 2
#define ICMP_SPKTMD_PRI_NONE() \
    if (sPktFile) { \
        fputs("0x00" /* icmpStat    */ SEP_CHR \
                     /* icmpType    */ SEP_CHR \
                     /* icmpCode    */ SEP_CHR \
                     /* icmpID      */ SEP_CHR \
                     /* icmpSeq     */ SEP_CHR \
                     /* icmpPFindex */ SEP_CHR \
              , sPktFile); \
    }
#else // ICMP_PARENT == 0 || ETH_ACTIVATE == 2
#define ICMP_SPKTMD_PRI_NONE() \
    if (sPktFile) { \
        fputs("0x00" /* icmpStat    */ SEP_CHR \
                     /* icmpType    */ SEP_CHR \
                     /* icmpCode    */ SEP_CHR \
                     /* icmpID      */ SEP_CHR \
                     /* icmpSeq     */ SEP_CHR \
              , sPktFile); \
    }
#endif // ICMP_PARENT == 0 || ETH_ACTIVATE == 2

#define ICMP_PERCENT(num, tot) (100.0f * (num) / (float)(tot))
#define ICMP_LOG_TYPE_CODE(stream, type, code, num, tot) \
    if ((num) > 0) { \
        fprintf((stream), "%s\t%s\t%30" PRIu64 " [%6.02f%%]\n", (type), (code), (num), ICMP_PERCENT((num), (tot))); \
    }


// Tranalyzer function

T2_PLUGIN_INIT("icmpDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(icmpFlows);

    if (sPktFile) {
        fputs("icmpStat"    SEP_CHR
              "icmpType"    SEP_CHR
              "icmpCode"    SEP_CHR
              "icmpID"      SEP_CHR
              "icmpSeq"     SEP_CHR
#if ICMP_PARENT == 1 && ETH_ACTIVATE != 2
              "icmpPFindex" SEP_CHR
#endif // ICMP_PARENT == 1 && ETH_ACTIVATE != 2
              , sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H8(bv, "icmpStat" , "ICMP status");
    BV_APPEND_U8(bv, "icmpTCcnt", "ICMP type code count");

#if ICMP_TC_MD == 1
    BV_APPEND_R(bv, "icmpType_Code"       , "ICMP type and code fields", 2, bt_uint_8, bt_uint_8);
#else // IPV6_TC_MD == 0
    BV_APPEND(bv  , "icmpBFTypH_TypL_Code", "ICMP Aggregated type H (IPv6>128, IPv4>31), L (<32) & code bit field", 3, bt_hex_32, bt_hex_32, bt_hex_16);
    //BV_APPEND(bv  , "icmpBFType_Code"     , "ICMP Aggregated type and codE", 2, bt_hex_64, bt_hex_16);
#endif // ICMP_TC_MD

    BV_APPEND_H32(bv, "icmpTmGtw"        , "ICMP time/gateway");
    BV_APPEND_FLT(bv, "icmpEchoSuccRatio", "ICMP Echo reply/request success ratio");

#if ICMP_PARENT == 1 && ETH_ACTIVATE != 2
    BV_APPEND_U64(bv, "icmpPFindex", "ICMP parent flowIndex");
#endif // ICMP_PARENT == 1 && ETH_ACTIVATE != 2

    return bv;
}


void t2OnNewFlow(packet_t *packet, unsigned long flowIndex) {
    icmpFlow_t * const icmpFlowP = &icmpFlows[flowIndex];
    memset(icmpFlowP, '\0', sizeof(*icmpFlowP));

    // Only ICMP
    const uint_fast8_t l4Proto = packet->l4Proto;
    if (l4Proto != L3_ICMP && l4Proto != L3_ICMP6) return;

    icmpFlowP->stat |= ICMP_STAT_ICMP;

    // Only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

    const icmpHeader_t * const icmpHdrP = ICMP_HEADER(packet);
    if (icmpHdrP->echo.sequence == LOKISEQ) icmpFlowP->stat |= ICMP_COV_LOKI;
    icmpFlowP->lstSeq = ntohs(icmpHdrP->echo.sequence) - 1;

#if ICMP_FDCORR == 1
    uint_fast8_t j;
    if (PACKET_IS_IPV6(packet)) j = (icmpHdrP->type != ICMP6_ECHO);
    else j = (icmpHdrP->type != ICMP4_ECHO);

    flow_t * const flowP = &flows[flowIndex];
    if (!FLOW_HAS_OPPOSITE(flowP)) {
        if ((flowP->status & L3FLOWINVERT) ^ j) {
            flowP->status ^= L3FLOWINVERT;
        }
    }
#endif // ICMP_FDCORR == 1
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    ICMP_SPKTMD_PRI_NONE();
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {

    // Only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) {
        ICMP_SPKTMD_PRI_NONE();
        return;
    }

    // Only ICMP
    icmpFlow_t * const icmpFlowP = &icmpFlows[flowIndex];
    if (!icmpFlowP->stat) {
        ICMP_SPKTMD_PRI_NONE();
        return;
    }

    numICMPPackets++; // count only unfragmented ICMP packets

    const int32_t icmpL7Len = packet->snapL7Len - 40;
    const icmpHeader_t * const icmpHdrP = ICMP_HEADER(packet);
    const uint8_t type = icmpHdrP->type;
    const uint8_t code = icmpHdrP->code;
    const uint16_t echoSeq = ntohs(icmpHdrP->echo.sequence);


#if ICMP_TC_MD == 1
//#if ICMP_TC_MD_AGG == 1
//  for (int i = 0; i < icmpFlowP->numat, icmpFlowP->numat < ICMP_NUM; i++) if (icmpFlowP->type[i] == type) break;
//  for (int i = 0; i < icmpFlowP->numac, icmpFlowP->numac < ICMP_NUM; i++) if (icmpFlowP->code[i] == code) break;
//#else // ICMP_TC_MD_AGG == 0
    if (icmpFlowP->numtc < ICMP_NUM) {
        icmpFlowP->type[icmpFlowP->numtc] = type;
        icmpFlowP->code[icmpFlowP->numtc] = code;
    }
//#endif // ICMP_TC_MD_AGG
#endif // ICMP_TC_MD == 1

    icmpFlowP->numtc++;

#if ICMP_PARENT == 1 && ETH_ACTIVATE != 2
    uint64_t hasParent = 0;
#endif // ICMP_PARENT == 1 && ETH_ACTIVATE != 2

    if (PACKET_IS_IPV6(packet)) {

#if IPV6_ACTIVATE > 0

#if ICMP_TC_MD == 0
        if (type < 160) {
                 if (type < ICMP6_NTYPE) icmpFlowP->type_bfieldL |= (1U << type);
            else if (type >= ICMP6_ECHO) icmpFlowP->type_bfieldH |= (1U << (type - ICMP6_ECHO));
        }
        if (code < ICMP6_NCODE) icmpFlowP->code_bfield |= (1U << code);
#endif // ICMP_TC_MD == 0

        switch (type) {

            case ICMP6_ECHO:
                numEcho6[0]++;
                numEchoRequests++;
                icmpFlowP->echoReq++;

                if (!memcmp(packet->l7HdrP + 6, "WANG2", 5)) {
                    icmpFlowP->stat |= ICMP_STAT_WANG;
                }

                if (icmpL7Len > 0 && memmem(packet->l7HdrP+40, icmpL7Len, ICMPSSH, ICMPSSHLEN)) {
                    icmpFlowP->stat |= ICMP_COV_SSH;
                }

                if ((icmpFlowP->stat & ICMP_COV_LOKI) && (icmpHdrP->echo.sequence != LOKISEQ)) {
                    icmpFlowP->stat &= ~ICMP_COV_LOKI;
                }

                if (++icmpFlowP->lstSeq != echoSeq) icmpFlowP->stat |= ICMP_SEQ_ABNRM;
                icmpFlowP->lstSeq = echoSeq;
                break;

            case ICMP6_ECHOREPLY:
                numEcho6[1]++;
                numEchoReplies++;
                icmpFlowP->echoRep++;

                if (icmpL7Len > 0 && memmem(packet->l7HdrP+40, icmpL7Len, ICMPSSH, ICMPSSHLEN)) {
                    icmpFlowP->stat |= ICMP_COV_SSH;
                }

                if ((icmpFlowP->stat & ICMP_COV_LOKI) && (icmpHdrP->echo.sequence != LOKISEQ)) {
                    icmpFlowP->stat &= ~ICMP_COV_LOKI;
                }

                if (++icmpFlowP->lstSeq != echoSeq) icmpFlowP->stat |= ICMP_SEQ_ABNRM;
                icmpFlowP->lstSeq = echoSeq;
                break;

            case ICMP6_DEST_UNREACH:
                if (code < 8) numDestUnreach6[code]++;
                SET_HAS_PARENT();
                break;

            case ICMP6_TIME_EXCEEDED:
                if (code < 2) numTimeExceeded6[code]++;
                else if (code < 8) num_icmp6[type][code]++;
                SET_HAS_PARENT();
                break;

            case ICMP6_PKT_TOO_BIG:
                numPktTooBig++;
                SET_HAS_PARENT();
                break;

            case ICMP6_PARAM_PROBLEM:
                if (code < 3) numParamProblem[code]++;
                else if (code < 8) num_icmp6[type][code]++;
                SET_HAS_PARENT();
                break;

            default:
                if (type < 255 && code < 8) num_icmp6[type][code]++;
                break;
        }
#endif // IPV6_ACTIVATE > 0

    } else { // IPv4

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if ICMP_TC_MD == 0
        if (type < ICMP4_NTYPE) icmpFlowP->type_bfieldL |= (1U << type);
        else icmpFlowP->type_bfieldH |= (1U << type);
        if (code < ICMP4_NCODE) icmpFlowP->code_bfield  |= (1U << code);
#endif // ICMP_TC_MD == 0

        // count code

        switch (type) {

            case ICMP4_ECHO:
                numEcho4[0]++;
                numEchoRequests++;
                icmpFlowP->echoReq++;

                if (!memcmp(packet->l7HdrP + 6, "WANG2", 5)) {
                    icmpFlowP->stat |= ICMP_STAT_WANG;
                }

                if (icmpL7Len > 0 && memmem(packet->l7HdrP+40, icmpL7Len, ICMPSSH, ICMPSSHLEN)) {
                    icmpFlowP->stat |= ICMP_COV_SSH;
                }

                if ((icmpFlowP->stat & ICMP_COV_LOKI) && (icmpHdrP->echo.sequence != LOKISEQ)) {
                    icmpFlowP->stat &= ~ICMP_COV_LOKI;
                }

                if (++icmpFlowP->lstSeq != echoSeq) icmpFlowP->stat |= ICMP_SEQ_ABNRM;
                icmpFlowP->lstSeq = echoSeq;
                break;

            case ICMP4_ECHOREPLY:
                numEcho4[1]++;
                numEchoReplies++;
                icmpFlowP->echoRep++;

                if (icmpL7Len > 0 && memmem(packet->l7HdrP+40, icmpL7Len, ICMPSSH, ICMPSSHLEN)) {
                    icmpFlowP->stat |= ICMP_COV_SSH;
                }

                if ((icmpFlowP->stat & ICMP_COV_LOKI) && (icmpHdrP->echo.sequence != LOKISEQ)) {
                    icmpFlowP->stat &= ~ICMP_COV_LOKI;
                }

                if (++icmpFlowP->lstSeq != echoSeq) icmpFlowP->stat |= ICMP_SEQ_ABNRM;
                icmpFlowP->lstSeq = echoSeq;
                break;

            case ICMP4_SOURCE_QUENCH:
                numSourceQuench++;
                SET_HAS_PARENT();
                break;

            case ICMP4_DEST_UNREACH:
                if (code < 16) numDestUnreach4[code]++;
                SET_HAS_PARENT();
                break;

            case ICMP4_TIME_EXCEEDED:
                if (code < 2) numTimeExceeded4[code]++;
                SET_HAS_PARENT();
                break;

            case ICMP4_REDIRECT:
                if (code < 4) numRedirect[code]++;
                SET_HAS_PARENT();
                break;

            case ICMP4_TIMESTAMP:
                icmpFlowP->tmStmp = icmpHdrP->gateway;
                break;

            case ICMP4_TIMESTAMPREPLY:
                icmpFlowP->tmStmp = icmpHdrP->gateway;
                break;

            case ICMP4_TRACEROUTE:
                numTraceroutes++;
                break;

            default:
                break;
        }

#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

    }

    // TODO if no code, do not print anything
    if (sPktFile) {
        fprintf(sPktFile,
                "0x%02" B2T_PRIX8  /* icmpStat */ SEP_CHR
                "%"     PRIu8      /* icmpType */ SEP_CHR
                "%"     PRIu8      /* icmpCode */ SEP_CHR
                "0x%04" B2T_PRIX16 /* icmpID   */ SEP_CHR
                "0x%04" B2T_PRIX16 /* icmpSeq  */ SEP_CHR
                , icmpFlowP->stat, type, code
                , ntohs(icmpHdrP->echo.id), echoSeq);
    }

#if ICMP_PARENT == 1 && ETH_ACTIVATE != 2
    if (hasParent) {
        uint8_t l4Proto;
        uint8_t l7off;
        flow_t parent = {};
        const flow_t * const flowP = &flows[flowIndex];
        parent.vlanId = flowP->vlanId;
#if IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
        parent.ethType = packet->ethType;
#endif // IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
        if (PACKET_IS_IPV6(packet)) {
            const ip6Header_t * const ip6HdrP = IPV6_HEADER(packet);
            l4Proto = ip6HdrP->next_header;
            l7off = 40;
#if IPV6_ACTIVATE > 0
            parent.srcIP = ip6HdrP->ip_src;
            parent.dstIP = ip6HdrP->ip_dst;
#endif // IPV6_ACTIVATE > 0
        } else { // IPv4
            const ipHeader_t * const ipHdrP = IPV4_HEADER(packet);
            l4Proto = ipHdrP->ip_p;
            l7off = (IP_HL(ipHdrP) << 2);
            parent.srcIP.IPv4 = ipHdrP->ip_src;
            parent.dstIP.IPv4 = ipHdrP->ip_dst;
        }
        parent.l4Proto = l4Proto;
        switch (l4Proto) {
            case L3_TCP:
            case L3_UDP:
            case L3_UDPLITE: {
                const tcpHeader_t * const tcpHdrP = (tcpHeader_t*) ((uint8_t*)packet->l7HdrP + l7off);
                parent.srcPort = ntohs(tcpHdrP->source);
                parent.dstPort = ntohs(tcpHdrP->dest);
                break;
            }
            case L3_ICMP:
            case L3_ICMP6:
                // srcPort = dstPort = 0
                break;
            default:
                break;
        }
        hasParent = hashTable_lookup(mainHashMap, (char*)&parent.srcIP);
        if (hasParent != HASHTABLE_ENTRY_NOT_FOUND) {
            icmpFlowP->pfi = flows[hasParent].findex;
            if (sPktFile) fprintf(sPktFile, "%" PRIu64, icmpFlowP->pfi);
        }
    }

    if (sPktFile) fputs(/* icmpPFindex */ SEP_CHR, sPktFile);
#endif // ICMP_PARENT == 1 && ETH_ACTIVATE != 2
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const icmpFlow_t * const icmpFlowP = &icmpFlows[flowIndex];

    icmpStat |= icmpFlowP->stat;

    OUTBUF_APPEND_U8(buf, icmpFlowP->stat);  // icmpStat
    OUTBUF_APPEND_U8(buf, icmpFlowP->numtc); // icmpTCcnt

    // icmpType_Code/icmpBFType_Code/icmpBFTypH_TypL_Code
#if ICMP_TC_MD == 1
    // icmpType_Code
    const uint32_t j = MIN(icmpFlowP->numtc, ICMP_NUM);
    OUTBUF_APPEND_NUMREP(buf, j);
    for (uint_fast32_t i = 0; i < j; i++) {
        OUTBUF_APPEND_U8(buf, icmpFlowP->type[i]);
        OUTBUF_APPEND_U8(buf, icmpFlowP->code[i]);
    }
#else // ICMP_TC_MD == 0
    // icmpBFType_Code/icmpBFTypH_TypL_Code
    //const uint64_t bf = ((uint64_t)icmpFlowP->type_bfieldH << 32) | icmpFlowP->type_bfieldL;
    //OUTBUF_APPEND_U64(buf, bf);
    OUTBUF_APPEND_U32(buf, icmpFlowP->type_bfieldH);
    OUTBUF_APPEND_U32(buf, icmpFlowP->type_bfieldL);
    OUTBUF_APPEND_U16(buf, icmpFlowP->code_bfield);
#endif // ICMP_TC_MD == 0

    OUTBUF_APPEND_U32(buf, icmpFlowP->tmStmp); // icmpTmGtw

    // icmpEchoSuccRatio
    float tmp = 0.0f;
    const unsigned long revFlowIndex = flows[flowIndex].oppositeFlowIndex;
    if (revFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
        const icmpFlow_t * const icmpFlowRev = &icmpFlows[revFlowIndex];
        if (icmpFlowP->echoReq != 0) tmp = (float)icmpFlowRev->echoRep / (float)icmpFlowP->echoReq;
        else if (icmpFlowRev->echoRep != 0) tmp = -1.0f * (float)icmpFlowRev->echoRep;
    }
    OUTBUF_APPEND_FLT(buf, tmp);

#if ICMP_PARENT == 1 && ETH_ACTIVATE != 2
    OUTBUF_APPEND_U64(buf, icmpFlowP->pfi); // icmpPFindex
#endif // ICMP_PARENT == 1 && ETH_ACTIVATE != 2
}


void t2PluginReport(FILE *stream) {
    if (!icmpStat) return;

    T2_FPLOG_AGGR_HEX0(stream, plugin_name, icmpStat);

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    const uint_fast64_t numICMP4 = numPacketsL3[L3_ICMP];
    if (numICMP4) {
        T2_FPLOG_NUMP(stream, plugin_name, "Number of ICMP echo request packets", numEcho4[0], numICMP4);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of ICMP echo reply packets", numEcho4[1], numICMP4);
        const float tmp4 = (numEcho4[0] != 0) ? numEcho4[1] / (float)numEcho4[0] : 0.0f;
        if (tmp4) T2_FPLOG(stream, plugin_name, "ICMP echo reply / request ratio: %.2f", tmp4);
    }
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if IPV6_ACTIVATE > 0
    const uint_fast64_t numICMP6 = numPacketsL3[L3_ICMP6];
    if (numICMP6) {
        T2_FPLOG_NUMP(stream, plugin_name, "Number of ICMPv6 echo request packets", numEcho6[0], numICMP6);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of ICMPv6 echo reply packets", numEcho6[1], numICMP6);
        const float tmp6 = (numEcho6[0] != 0) ? numEcho6[1] / (float)numEcho6[0] : 0.0f;
        if (tmp6) T2_FPLOG(stream, plugin_name, "ICMPv6 echo reply / request ratio: %.2f", tmp6);
    }
#endif // IPV6_ACTIVATE > 0
}


void t2Monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        case T2_MON_PRI_HDR:
            fputs("icmpPkts"    SEP_CHR
                  "icmpEchoReq" SEP_CHR
                  "icmpEchoRep" SEP_CHR
                  , stream);
            return;

        case T2_MON_PRI_VAL:
            fprintf(stream,
                    "%" PRIu64 /* icmpPkts    */ SEP_CHR
                    "%" PRIu64 /* icmpEchoReq */ SEP_CHR
                    "%" PRIu64 /* icmpEchoRep */ SEP_CHR
                    , numICMPPackets  - numICMPPackets0
                    , numEchoRequests - numEchoRequests0
                    , numEchoReplies  - numEchoReplies0);
            break;

        case T2_MON_PRI_REPORT:
            T2_FPLOG_AGGR_HEX(stream, plugin_name, icmpStat);
            T2_PLOG_DIFFNUMP(stream, plugin_name, "Number of ICMP echo request packets", numEchoRequests, numICMPPackets);
            T2_PLOG_DIFFNUMP(stream, plugin_name, "Number of ICMP echo reply packets", numEchoReplies, numICMPPackets);
            break;

        // Invalid state, do nothing
        default:
            return;
    }

#if DIFF_REPORT == 1
    numICMPPackets0 = numICMPPackets;
    numEchoRequests0 = numEchoRequests;
    numEchoReplies0 = numEchoReplies;
#endif // DIFF_REPORT == 1
}


void t2Finalize() {
    free(icmpFlows);

#if ICMP_STATFILE == 1
    t2_env_t env[ENV_ICMP_N] = {};
#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_ICMP_N, env);
    const char * const nocode = T2_ENV_VAL(ICMP_NOCODE);
#else // ENVCNTRL == 0
    const char * const nocode = ICMP_NOCODE;
    T2_SET_ENV_STR(ICMP_SUFFIX)
#endif // ENVCNTRL

    // open ICMP statistics file
    FILE *file = t2_fopen_with_suffix(baseFileName, T2_ENV_VAL(ICMP_SUFFIX), "w");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);

    const uint_fast64_t numICMP4 = numPacketsL3[L3_ICMP];
    const uint_fast64_t numICMP6 = numPacketsL3[L3_ICMP6];
    const uint_fast64_t totalICMP = numICMP4 + numICMP6;

    T2_FLOG_NUMP0(file, "Total number of ICMP packets", totalICMP, numPackets);

    if (totalICMP == 0) {
        fclose(file);
        return;
    }

    fputc('\n', file);

    T2_FLOG_NUMP(file, "Number of ICMP packets", numICMP4, numPackets);
    T2_FLOG_NUMP(file, "Number of ICMPv6 packets", numICMP6, numPackets);
    fputc('\n', file);

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    const float tmp4 = (numEcho4[0] != 0) ? numEcho4[1] / (float)numEcho4[0] : 0.0f;
    if (tmp4) fprintf(file, "ICMP echo reply / request ratio: %5.3f\n", tmp4);
#endif

#if IPV6_ACTIVATE > 0
    const float tmp6 = (numEcho6[0] != 0) ? numEcho6[1] / (float)numEcho6[0] : 0.0f;
    if (tmp6) fprintf(file, "ICMPv6 echo reply / request ratio: %5.3f\n", tmp6);
#endif

    fputc('\n', file);

    uint_fast32_t i;

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    if (numICMP4 > 0) {
        fprintf(file, "# ICMP Type\tCode\t%30s\n", "Packets");

        ICMP_LOG_TYPE_CODE(file, "ICMP_ECHOREQUEST"  , nocode, numEcho4[0]    , numICMP4);
        ICMP_LOG_TYPE_CODE(file, "ICMP_ECHOREPLY"    , nocode, numEcho4[1]    , numICMP4);
        ICMP_LOG_TYPE_CODE(file, "ICMP_SOURCE_QUENCH", nocode, numSourceQuench, numICMP4);
        ICMP_LOG_TYPE_CODE(file, "ICMP_TRACEROUTE"   , nocode, numTraceroutes , numICMP4);

        for (i = 0; i < 16; i++) {
            ICMP_LOG_TYPE_CODE(file, "ICMP_DEST_UNREACH", icmp_dest_unreach_code_str[i], numDestUnreach4[i], numICMP4);
        }

        ICMP_LOG_TYPE_CODE(file, "ICMP_REDIRECT", "ICMP_REDIR_NET"    , numRedirect[0], numICMP4);
        ICMP_LOG_TYPE_CODE(file, "ICMP_REDIRECT", "ICMP_REDIR_HOST"   , numRedirect[1], numICMP4);
        ICMP_LOG_TYPE_CODE(file, "ICMP_REDIRECT", "ICMP_REDIR_NETTOS" , numRedirect[2], numICMP4);
        ICMP_LOG_TYPE_CODE(file, "ICMP_REDIRECT", "ICMP_REDIR_HOSTTOS", numRedirect[3], numICMP4);

        ICMP_LOG_TYPE_CODE(file, "ICMP_TIME_EXCEEDED", "ICMP_EXC_TTL"     , numTimeExceeded4[0], numICMP4);
        ICMP_LOG_TYPE_CODE(file, "ICMP_TIME_EXCEEDED", "ICMP_EXC_FRAGTIME", numTimeExceeded4[1], numICMP4);

#if IPV6_ACTIVATE == 2
        fputc('\n', file);
#endif
    }
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if IPV6_ACTIVATE > 0
    if (numICMP6 > 0) {
        fprintf(file, "# ICMPv6 Type\tCode\t%30s\n", "Packets");

        ICMP_LOG_TYPE_CODE(file, "ICMP6_ECHOREQUEST", nocode, numEcho6[0] , numICMP6);
        ICMP_LOG_TYPE_CODE(file, "ICMP6_ECHOREPLY"  , nocode, numEcho6[1] , numICMP6);
        ICMP_LOG_TYPE_CODE(file, "ICMP6_PKT_TOO_BIG", nocode, numPktTooBig, numICMP6);

        for (i = 0; i < 8; i++) {
            ICMP_LOG_TYPE_CODE(file, "ICMP6_DEST_UNREACH", icmp6_dest_unreach_code_str[i], numDestUnreach6[i], numICMP6);
        }

        ICMP_LOG_TYPE_CODE(file, "ICMP6_TIME_EXCEEDED", "ICMP6_EXC_HOPS"    , numTimeExceeded6[0], numICMP6);
        ICMP_LOG_TYPE_CODE(file, "ICMP6_TIME_EXCEEDED", "ICMP6_EXC_FRAGTIME", numTimeExceeded6[1], numICMP6);

        ICMP_LOG_TYPE_CODE(file, "ICMP6_PARAM_PROBLEM", "ICMP6_ERR_HDR"        , numParamProblem[0], numICMP6);
        ICMP_LOG_TYPE_CODE(file, "ICMP6_PARAM_PROBLEM", "ICMP6_UNRECO_NEXT_HDR", numParamProblem[1], numICMP6);
        ICMP_LOG_TYPE_CODE(file, "ICMP6_PARAM_PROBLEM", "ICMP6_UNRECO_IP6_OPT" , numParamProblem[2], numICMP6);

        uint_fast32_t j;
        for (i = 0; i < 255 ; i++) {
            for (j = 0; j < 8 ; j++) {
                if (num_icmp6[i][j]) {
                    if (i >= ICMP6_MCAST_QUERY && i <= ICMP6_DUP_ADDR_CONF) {
                        if (j >= 138 && j <= 140) { // codes 138, 139 and 140 have types
                            fprintf(file, "%s\t%" PRIuFAST32 "\t%30" PRIu64 " [%6.02f%%]\n", icmp6_code_str[i-ICMP6_MCAST_QUERY],
                                    j, num_icmp6[i][j], ICMP_PERCENT(num_icmp6[i][j], numICMP6));
                        } else {
                            ICMP_LOG_TYPE_CODE(file, icmp6_code_str[i-ICMP6_MCAST_QUERY], nocode, num_icmp6[i][j], numICMP6);
                        }
                    } else {
                        fprintf(file, "%" PRIuFAST32 "\t%" PRIuFAST32 "\t%30" PRIu64 " [%6.02f%%]\n", i, j,
                                 num_icmp6[i][j], ICMP_PERCENT(num_icmp6[i][j], numICMP6));
                    }
                }
            }
        }
    }
#endif // IPV6_ACTIVATE > 0

    fclose(file);

    t2_free_env(ENV_ICMP_N, env);
#endif // ICMP_STATFILE == 1
}
