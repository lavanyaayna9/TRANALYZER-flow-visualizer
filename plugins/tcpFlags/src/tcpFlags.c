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

#include "tcpFlags.h"

#include <math.h>


// Global variables

tcpFlagsFlow_t *tcpFlagsFlows;


// Static variables

static uint64_t winMinCnt, tcpPktvCnt;
static uint64_t totalTCPScans, totalTCPScans0;
static uint64_t totalTCPSuccScans, totalTCPSuccScans0;
static uint64_t totalTCPRetry, totalTCPRetry0;
static uint64_t totalSynRetry, totalSynRetry0;
static uint16_t ipFlags, tcpFStat, tcpFlags, tcpAnomaly;

#if MPTCP == 1
static uint64_t mpTCPcnt;
static uint16_t tcpMPTBF;
static uint8_t tcpMPF;
#endif // MPTCP == 1

static uint8_t ipToS;


// Tranalyzer plugin functions

T2_PLUGIN_INIT("tcpFlags", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(tcpFlagsFlows);

    if (sPktFile) {
        fputs(
#if IPTOS == 2
              "ipToSPrec_ecn" SEP_CHR
#elif IPTOS == 1
              "ipToSDscp_ecn" SEP_CHR
#else // IPTOS == 0
              "ipToS"         SEP_CHR
#endif // IPTOS
              "ipID"          SEP_CHR
              "ipIDDiff"      SEP_CHR
              "ipFrag"        SEP_CHR
              "ipTTL"         SEP_CHR
              "ipHdrChkSum"   SEP_CHR
              "ipCalChkSum"   SEP_CHR
              "l4HdrChkSum"   SEP_CHR
              "l4CalChkSum"   SEP_CHR
              "ipFlags"       SEP_CHR
#if IPV6_ACTIVATE > 0
              "ip6HHOptLen"   SEP_CHR
              "ip6HHOpts"     SEP_CHR
              "ip6DOptLen"    SEP_CHR
              "ip6DOpts"      SEP_CHR
#endif // IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
              "ipOptLen"      SEP_CHR
              "ipOpts"        SEP_CHR
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
#if SEQ_ACK_NUM == 1
              "seq"           SEP_CHR
              "ack"           SEP_CHR
              "seqMax"        SEP_CHR
              "seqDiff"       SEP_CHR
              "ackDiff"       SEP_CHR
              "seqLen"        SEP_CHR
              "ackLen"        SEP_CHR
              "seqFlowLen"    SEP_CHR
              "ackFlowLen"    SEP_CHR
              "tcpMLen"       SEP_CHR
              "tcpBFlgt"      SEP_CHR
#endif // SEQ_ACK_NUM == 1
              "tcpFStat"      SEP_CHR
              "tcpFlags"      SEP_CHR
              "tcpAnomaly"    SEP_CHR
              "tcpWin"        SEP_CHR
              "tcpWS"         SEP_CHR
              "tcpMSS"        SEP_CHR
#if NAT_BT_EST == 1
              "tcpTmS"        SEP_CHR
              "tcpTmER"       SEP_CHR
#endif // NAT_BT_EST == 1
#if MPTCP == 1
              "tcpMPTyp"      SEP_CHR
              "tcpMPF"        SEP_CHR
              "tcpMPAID"      SEP_CHR
              "tcpMPDSSF"     SEP_CHR
#endif // MPTCP == 1
              "tcpOptLen"     SEP_CHR
              "tcpOpts"       SEP_CHR
              , sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H16(bv, "tcpFStat"  , "tcpFlags status");
    BV_APPEND_U16(bv, "ipMindIPID", "IP minimum delta IP ID");
    BV_APPEND_U16(bv, "ipMaxdIPID", "IP maximum delta IP ID");
    BV_APPEND_U8( bv, "ipMinTTL"  , "IP minimum TTL");
    BV_APPEND_U8( bv, "ipMaxTTL"  , "IP maximum TTL");
    BV_APPEND_U8( bv, "ipTTLChg"  , "IP TTL change count");
#if IPTOS == 2
    BV_APPEND(bv, "ipToSPrec_ecn", "IP Type of Service: Precedence and ECN", 2, bt_uint_8, bt_uint_8);
#elif IPTOS == 1
    BV_APPEND(bv, "ipToSDscp_ecn", "IP Type of Service: DSCP and ECN decimal", 2, bt_uint_8, bt_uint_8);
#else // IPTOS == 0
    BV_APPEND_H8( bv, "ipToS", "IP Type of Service hex");
#endif // IPTOS
    BV_APPEND_H16(bv, "ipFlags"   , "IP aggregated flags");

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    //BV_APPEND_U16(bv, "ipOptPktCnt", "IP options packet count");
    BV_APPEND_U16(bv, "ipOptCnt", "IP options count");
    BV_APPEND(bv, "ipOptCpCl_Num", "IP aggregated options, copy-class and number", 2, bt_hex_8, bt_hex_32);
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if IPV6_ACTIVATE > 0
    BV_APPEND(bv, "ip6OptCntHH_D", "IPv6 Hop-by-Hop destination option counts"     , 2, bt_uint_16, bt_uint_16);
    BV_APPEND(bv, "ip6OptHH_D"   , "IPv6 aggregated Hop-by-Hop destination options", 2, bt_hex_32 , bt_hex_32);
#endif // IPV6_ACTIVATE > 0

#if SEQ_ACK_NUM == 1
    BV_APPEND_U32(bv, "tcpISeqN"             , "TCP initial sequence number");
    BV_APPEND_U16(bv, "tcpPSeqCnt"           , "TCP packet seq count");
    BV_APPEND_U64(bv, "tcpSeqSntBytes"       , "TCP sent seq diff bytes");
    BV_APPEND_U16(bv, "tcpSeqFaultCnt"       , "TCP sequence number fault count");
    BV_APPEND_U16(bv, "tcpPAckCnt"           , "TCP packet ACK count");
    BV_APPEND_U64(bv, "tcpFlwLssAckRcvdBytes", "TCP flawless ACK received bytes");
    BV_APPEND_U16(bv, "tcpAckFaultCnt"       , "TCP ACK number fault count");
    BV_APPEND_U32(bv, "tcpBFlgtMx"           , "TCP Bytes in Flight MAX");
#endif // SEQ_ACK_NUM == 1

#if WINDOWSIZE == 1
    BV_APPEND_U32(bv, "tcpInitWinSz"     , "TCP initial effective window size");
    BV_APPEND_FLT(bv, "tcpAvgWinSz"      , "TCP average effective window size");
    BV_APPEND_U32(bv, "tcpMinWinSz"      , "TCP minimum effective window size");
    BV_APPEND_U32(bv, "tcpMaxWinSz"      , "TCP maximum effective window size");
    BV_APPEND_U16(bv, "tcpWinSzDwnCnt"   , "TCP effective window size change down count");
    BV_APPEND_U16(bv, "tcpWinSzUpCnt"    , "TCP effective window size change up count");
    BV_APPEND_U16(bv, "tcpWinSzChgDirCnt", "TCP effective window size direction change count");
    BV_APPEND_FLT(bv, "tcpWinSzThRt"     , "TCP packet count ratio below window size WINMIN threshold");
#endif // WINDOWSIZE == 1

    BV_APPEND_H16( bv, "tcpFlags"   , "TCP aggregated protocol flags (FIN-ACK, SYN-ACK, RST-ACK, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)");
    BV_APPEND_H16(bv, "tcpAnomaly"  , "TCP aggregated header anomaly flags");

#if TCPFLGCNT == 1
    BV_APPEND(bv, "tcpCntF_S_R_P_A_U_E_C_FA_SA_RA_N_SF_SFR_RF_X", "TCP flags counts", 16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16);
#endif // tcpFLGCNT == 1

#if TCPJA4T == 1
    BV_APPEND_STRC(bv, "tcpJA4T", "TCP JA4T/JA4TS fingerprint");
#endif // TCPJA4T == 1

    BV_APPEND_U16(bv, "tcpOptPktCnt", "TCP options packet count");
    BV_APPEND_U16(bv, "tcpOptCnt"   , "TCP options count");
    BV_APPEND_H32(bv, "tcpOptions"  , "TCP aggregated options");
    BV_APPEND_U16(bv, "tcpMSS"      , "TCP maximum segment size");
    BV_APPEND_U16(bv, "tcpWS"       , "TCP window scale");

#if MPTCP == 1
    BV_APPEND_H16(bv, "tcpMPTBF" , "TCP MPTCP type bitfield");
    BV_APPEND_H8( bv, "tcpMPF"   , "TCP MPTCP flags");
    BV_APPEND_U8( bv, "tcpMPAID" , "TCP MPTCP address ID");
    BV_APPEND_H8( bv, "tcpMPDSSF", "TCP MPTCP DSS flags");
#endif // MPTCP == 1

#if NAT_BT_EST == 1
    BV_APPEND_U32(bv, "tcpTmS" , "TCP time stamp");
    BV_APPEND_U32(bv, "tcpTmER", "TCP time echo reply");
    BV_APPEND_FLT(bv, "tcpEcI" , "TCP estimated counter increment");
    //BV_APPEND_FLT(bv, "tcpAcI" , "TCP estimated counter increment");
    BV_APPEND_DBL(bv, "tcpUtm" , "TCP estimated up time");
    BV_APPEND_TIMESTAMP(bv, "tcpBtm", "TCP estimated boot time");
#endif // NAT_BT_EST == 1

#if RTT_ESTIMATE == 1
    BV_APPEND_FLT(bv, "tcpSSASAATrip"      , "TCP trip time (A: SYN, SYN-ACK, B: SYN-ACK, ACK)");
    BV_APPEND_FLT(bv, "tcpRTTAckTripMin"   , "TCP ACK trip min");
    BV_APPEND_FLT(bv, "tcpRTTAckTripMax"   , "TCP ACK trip max");
    BV_APPEND_FLT(bv, "tcpRTTAckTripAvg"   , "TCP ACK trip average");
    BV_APPEND_FLT(bv, "tcpRTTAckTripJitAvg", "TCP ACK trip jitter average");
    BV_APPEND_FLT(bv, "tcpRTTSseqAA"       , "TCP round trip time (A: SYN, SYN-ACK, ACK, B: ACK-ACK)");
    BV_APPEND_FLT(bv, "tcpRTTAckJitAvg"    , "TCP ACK round trip average jitter");
#endif // RTT_ESTIMATE == 1

    return bv;
}


void t2OnNewFlow(packet_t *packet, unsigned long flowIndex) {
    const flow_t * const flowP = &flows[flowIndex];

    tcpFlagsFlow_t * const tcpFlagsP = &tcpFlagsFlows[flowIndex];
    memset(tcpFlagsP, '\0', sizeof(*tcpFlagsP));

    tcpFlagsP->lastPktTime = flowP->lastSeen;

    tcpFlagsP->ipMinIDT = 0xffff;

#if RTT_ESTIMATE == 1
    tcpFlagsP->tcpRTTAckTripMin = 0xffff;
#endif // RTT_ESTIMATE == 1

    if (flowP->status & L2_FLOW) return;

    uint8_t ttl;
    if (PACKET_IS_IPV6(packet)) {
        const ip6Header_t * const ip6HdrP = IPV6_HEADER(packet);
        ttl = ip6HdrP->ip_ttl;
    } else { // IPv4
        const ipHeader_t * const ipHdrP = IPV4_HEADER(packet);
        tcpFlagsP->ipIDT = ntohs(ipHdrP->ip_id);
        ttl = ipHdrP->ip_ttl;
    }

    tcpFlagsP->ipTTLT    = ttl;
    tcpFlagsP->ipMinTTLT = ttl;
    tcpFlagsP->ipMaxTTLT = ttl;

    if (packet->l4Proto != L3_TCP) return;

    const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
    const uint8_t flags = *((uint8_t*)tcpHdrP + 13);

#if SEQ_ACK_NUM == 1
    const uint32_t seq = ntohl(tcpHdrP->seq);
    const uint32_t ack_seq = ntohl(tcpHdrP->ack_seq);
    tcpFlagsP->tcpSeqI = seq;
    tcpFlagsP->tcpSeqT = seq;
    tcpFlagsP->tcpSeqN = seq;
    tcpFlagsP->seqMax = seq;
    tcpFlagsP->tcpAckT = ack_seq;
    tcpFlagsP->tcpPLstLen = packet->l7Len;

#if SPKTMD_SEQACKREL == 1
    if (FLOW_HAS_OPPOSITE(flowP)) {
        tcpFlagsFlow_t * const tcpFlagsPO = &tcpFlagsFlows[flowP->oppositeFlowIndex];
        tcpFlagsPO->tcpAckI = seq;
        tcpFlagsP->tcpAckI = tcpFlagsPO->tcpSeqI;
    } else {
        tcpFlagsP->tcpAckI = ack_seq;
    }
#endif // SPKTMD_SEQACKREL == 1
#endif // SEQ_ACK_NUM == 1

    if (flags == SYN && packet->snapL7Len) tcpFlagsP->tcpAnomaly |= TCP_SYN_L7CNT;
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    if (sPktFile) {
        fputs(/* ipToS/ipToSDscp_ecn/ipToSPrec_ecn */ SEP_CHR
              /* ipID                              */ SEP_CHR
              /* ipIDDiff                          */ SEP_CHR
              /* ipFrag                            */ SEP_CHR
              /* ipTTL                             */ SEP_CHR
              /* ipHdrChkSum                       */ SEP_CHR
              /* ipCalChkSum                       */ SEP_CHR
              /* l4HdrChkSum                       */ SEP_CHR
              /* l4CalChkSum                       */ SEP_CHR
              /* ipFlags                           */ SEP_CHR
#if IPV6_ACTIVATE > 0
              /* ip6HHOptLen                       */ SEP_CHR
              /* ip6HHOpts                         */ SEP_CHR
              /* ip6DOptLen                        */ SEP_CHR
              /* ip6DOpts                          */ SEP_CHR
#endif // IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
              /* ipOptLen                          */ SEP_CHR
              /* ipOpts                            */ SEP_CHR
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
#if SEQ_ACK_NUM == 1
              /* seq                               */ SEP_CHR
              /* ack                               */ SEP_CHR
              /* seqMax                            */ SEP_CHR
              /* seqDiff                           */ SEP_CHR
              /* ackDiff                           */ SEP_CHR
              /* seqLen                            */ SEP_CHR
              /* ackLen                            */ SEP_CHR
              /* seqFlowLen                        */ SEP_CHR
              /* ackFlowLen                        */ SEP_CHR
              /* tcpMLen                           */ SEP_CHR
              /* tcpBFlgt                          */ SEP_CHR
#endif // SEQ_ACK_NUM == 1
              /* tcpFStat                          */ SEP_CHR
              /* tcpFlags                          */ SEP_CHR
              /* tcpAnomaly                        */ SEP_CHR
              /* tcpWin                            */ SEP_CHR
              /* tcpWS                             */ SEP_CHR
              /* tcpMSS                            */ SEP_CHR
#if NAT_BT_EST == 1
              /* tcpTmS                            */ SEP_CHR
              /* tcpTmER                           */ SEP_CHR
#endif // NAT_BT_EST == 1
#if MPTCP == 1
              /* tcpMPTyp                          */ SEP_CHR
              /* tcpMPF                            */ SEP_CHR
              /* tcpMPAID                          */ SEP_CHR
              /* tcpMPDSSF                         */ SEP_CHR
#endif // MPTCP == 1
              /* tcpOptLen                         */ SEP_CHR
              /* tcpOpts                           */ SEP_CHR
              , sPktFile);
    }
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    flow_t * const flowP = &flows[flowIndex];
    tcpFlagsFlow_t * const tcpFlagsP = &tcpFlagsFlows[flowIndex];

    flow_t *revFlowP;
    tcpFlagsFlow_t *tcpFlagsPO;
    if (FLOW_HAS_OPPOSITE(flowP)) {
        tcpFlagsPO = &tcpFlagsFlows[flowP->oppositeFlowIndex];
        revFlowP = &flows[flowP->oppositeFlowIndex];
    } else {
        tcpFlagsPO = NULL;
        revFlowP = NULL;
    }

#if RTT_ESTIMATE == 1
    tcpFlagsP->tcpPktCnt += 1.0;
#endif // RTT_ESTIMATE == 1

#if IPV6_ACTIVATE > 0
    const ip6Header_t * const ip6HdrP = IPV6_HEADER(packet);
    const ip6FragHdr_t * const ip6FragHdrP = packet->ip6FragHdrP;
    int16_t ip6HHOptLen = 0;
    int16_t ip6DOptLen = 0;
    const uint8_t *ip6HHOpt = NULL;
    const uint8_t *ip6DOpt = NULL;
#endif // IPV6_ACTIVATE > 0

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    int16_t ipOptLen = 0;
    const uint8_t *ipOpt = NULL;
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

    const ipHeader_t  * const ipHdrP  = IPV4_HEADER(packet);
    const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
    const udpHeader_t * const udpHdrP = UDP_HEADER(packet);

    int32_t ipIDDiff = 0;
    uint16_t ipFlags = 0, ipID = 0;
    uint16_t l3Len = 0;
    uint16_t l3HDLen = 0;
    uint16_t ipFrag = 0;
    uint16_t tcpFStat = tcpFlagsP->stat & TCPFSFLW;
    uint8_t ttl = 0, ipToSL = 0;

    const uint16_t * const l4HdrP16 = (uint16_t*)packet->l4HdrP;

    if (PACKET_IS_IPV6(packet)) {
#if IPV6_ACTIVATE > 0
        if (ip6FragHdrP) {
            // fragmentation bits (Res, MF), | tcpFlags->ipFlagsT;
            ipFlags = (ip6FragHdrP->frag_off << 1) & IP_FRAG_BITS;
            ipFrag = ntohs(ip6FragHdrP->frag_off) >> 3;
        }

//        l3Len = ntohs(ip6HdrP->payload_len) + 40; // FIXME TSO case
        l3Len = packet->l3Len;
        l3HDLen = packet->l3HdrLen;
        ttl = ip6HdrP->ip_ttl;

        const ip6OptHdr_t * const ip6HHOptHdrP = (ip6OptHdr_t*)packet->ip6HHOptHdrP;
        if (ip6HHOptHdrP) {
            ip6HHOptLen = ((ip6HHOptHdrP->len + 1) << 3) - 2;
            ip6HHOpt = (uint8_t*)&ip6HHOptHdrP->options;
        }

        const ip6OptHdr_t * const ip6DOptHdrP = (ip6OptHdr_t*)packet->ip6DOptHdrP;
        if (ip6DOptHdrP) {
            ip6DOptLen = ((ip6DOptHdrP->len + 1) << 3) - 2;
            ip6DOpt = (uint8_t*)&ip6DOptHdrP->options;
        }

        if (ip6HHOptLen > 0 || ip6DOptLen > 0) {
            // option field truncated or crafted packet?
            if (packet->snapL3Len < l3HDLen || l3Len < l3HDLen) {
                ipFlags |= IP_OPT_CORRPT; // warning: crafted packet or option field not acquired
            } else {
                for (int i = 0; i < ip6HHOptLen && ip6HHOpt[i] > 0; i += (ip6HHOpt[i] > 0) ? ip6HHOpt[i+1]+2 : 1) {
                    tcpFlagsP->ip6HHOptionsT |= 1U << (ip6HHOpt[i] & 0x1F); // ipOptions < 32
                    tcpFlagsP->ip6HHOptCntT++;
                }

                for (int i = 0; i < ip6DOptLen && ip6DOpt[i] > 0; i += (ip6DOpt[i] > 0) ? ip6DOpt[i+1]+2 : 1) {
                    tcpFlagsP->ip6DOptionsT |= 1U << (ip6DOpt[i] & 0x1F); // ipOptions < 32
                    tcpFlagsP->ip6DOptCntT++;
                }

                //tcpFlagsP->ipOptPktCntT++;
            }
        }
#endif // IPV6_ACTIVATE > 0
    } else { // IPv4
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
        // fragmentation bits (Res, DF, MF), | tcpFlags->ipFlagsT;
        ipFlags = (uint16_t) *((char*)ipHdrP + 6) & IP_FRAG_BITS;
//        l3Len = ntohs(ipHdrP->ip_len); // FIXME TSO case
        l3Len = packet->l3Len;
        l3HDLen = IP_HL(ipHdrP) << 2;
        ipOptLen = l3HDLen - 20;
        ipOpt = ((uint8_t*)ipHdrP + 20);
        ipFrag = ipHdrP->ip_off & FRAGIDM_N;
        ttl = ipHdrP->ip_ttl;
        if (ipOptLen > 0) {
            // option field truncated or crafted packet?
            if (packet->snapL3Len < l3HDLen || l3Len < l3HDLen) {
                ipFlags |= IP_OPT_CORRPT; // warning: crafted packet or option field not acquired
            } else {
                for (int i = 0; i < ipOptLen && ipOpt[i] > 0; i += (ipOpt[i] > 1) ? ipOpt[i+1]: 1) {
                    tcpFlagsP->ipCpClT |= ipOpt[i] & 0xE0; // copy & class
                    tcpFlagsP->ipOptionsT |= 1U << (ipOpt[i] & 0x1F); // ipOptions < 32
                    tcpFlagsP->ipOptCntT++;
                    // Option is not 1 (No-Operation) and length is 0... abort IP options processing
                    if (ipOpt[i] > 1 && ipOpt[i+1] == 0) {
                        ipFlags |= IP_OPT_CORRPT;
                        break;
                    }
                }

                //tcpFlagsP->ipOptPktCntT++;
            }
        }
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    }

    // minTTL and maxTTL, os guessing and network reversing
    if (ttl != tcpFlagsP->ipTTLT) tcpFlagsP->ipTTLChgT++;
    tcpFlagsP->ipTTLT = ttl;
    tcpFlagsP->ipMinTTLT = MIN(ttl, tcpFlagsP->ipMinTTLT);
    tcpFlagsP->ipMaxTTLT = MAX(ttl, tcpFlagsP->ipMaxTTLT);

    uint16_t l4HDLen = 8;
    const uint16_t l4Len = l3Len - l3HDLen;

    uint16_t ipHdrChkSum = 0, ipCalChkSum = 0;
    uint16_t l4HdrChkSum = 0, l4CalChkSum = 0;

    // minIPID and maxIPID, good estimate for windows about load state of the source machine

    if (PACKET_IS_IPV6(packet)) {
#if IPV6_ACTIVATE > 0
        ipToSL = (uint8_t) (ntohs(*(uint16_t*)ip6HdrP) >> 4); // get TOS byte
        tcpFlagsP->ipTosT |= ipToSL;
#endif // IPV6_ACTIVATE > 0
    } else { // IPv4
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
        ipToSL = ipHdrP->ip_tos; // get TOS byte
        tcpFlagsP->ipTosT |= ipToSL;
        ipID = ntohs(ipHdrP->ip_id);

        // 1. Packet not suitable for IPID assessment, reset at inter-distance
        if (tcpFStat & IP_INTDIS_OK) {
            ipIDDiff = ipID - tcpFlagsP->ipIDT;
            if (ipID < tcpFlagsP->ipIDT) {
                if (ipIDDiff < IP_ID_RLLOVR) ipFlags |= IP_ID_ROLL_OVER; // roll-over
                else ipFlags |= IP_ID_OUT_ORDER; // messy packet order
            }
            tcpFlagsP->ipMinIDT = MIN(ipIDDiff, tcpFlagsP->ipMinIDT);
            tcpFlagsP->ipMaxIDT = MAX(ipIDDiff, tcpFlagsP->ipMaxIDT);
        }

        // ip checksum processing
        ipHdrChkSum = ntohs(ipHdrP->ip_sum);

        if (packet->snapL3Len < l3HDLen) ipFlags |= (IP_SNP_HLEN_WRN | IP_L3CHK_SUMERR);
#if IPCHECKSUM > 0
        else {
            // This somewhat messy code is to silence address-of-packed-member warnings
            const uint8_t * const hdr8 = (uint8_t*)ipHdrP;
            const uint16_t * const hdr16 = (uint16_t*)hdr8;
            ipCalChkSum = ntohs(~(Checksum(hdr16, 0, l3HDLen, 5)));
            if (ipHdrChkSum != ipCalChkSum) ipFlags |= IP_L3CHK_SUMERR;
        }
#endif // IPCHECKSUM > 0

#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    }

#if IPCHECKSUM > 1 || FRAG_ANALYZE == 1
    // L4 Checksum processing
    bool frag = false;

    if (PACKET_IS_IPV6(packet)) {
#if IPV6_ACTIVATE > 0
        frag = (ip6FragHdrP && (ip6FragHdrP->frag_off & MORE_FRAG6_N));
#endif // IPV6_ACTIVATE > 0
    } else { // IPv4
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
        frag = (ipHdrP->ip_off & MORE_FRAG_N);
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    }
#endif // IPCHECKSUM > 1 || FRAG_ANALYZE == 1

#if IPCHECKSUM > 1
    uint16_t chkLen = l4Len;
    uint8_t pHdr = 1;
#endif // IPCHECKSUM > 1

    // only the first header fragment has a L4 header
    if ((ipFrag & FRAGID_N) == 0x0000) {
        uint16_t chkSumWrdPos = 0;

        tcpFStat |= L4CHKSUMC;

        switch (packet->l4Proto) {
            case L3_ICMP:
            case L3_IGMP:
                chkSumWrdPos = 1;
#if IPCHECKSUM > 1
                pHdr = 0;
#endif // IPCHECKSUM > 1
                break;

#if IPV6_ACTIVATE > 0
            case L3_ICMP6:
                chkSumWrdPos = 1;
                l4HDLen = 4;
                break;
#endif // IPV6_ACTIVATE > 0

            case L3_TCP:
                chkSumWrdPos = 8;
                //l4HDLen = tcpHdrP->doff<<2;
                l4HDLen = packet->l4HdrLen;
                break;

            case L3_UDPLITE: {
                const int ulen = ntohs(udpHdrP->len);
                if (LIKELY(ulen >= (int)sizeof(udpliteHeader_t) && ulen <= l4Len)) {
#if IPCHECKSUM > 1
                    chkLen = ulen;
#endif // IPCHECKSUM > 1
                } else {
                    ipFlags |= L4_CHKCOVERR;
                }
            }
                /* FALLTHRU */
            case L3_UDP: {
                const int ulen = ntohs(udpHdrP->len);
                if (packet->snapL4Len != ulen) ipFlags |= IP_HLEN_WRN;
                chkSumWrdPos = 3;
                break;
            }
            case L3_GRE:
                if (*l4HdrP16 & 0x0080) chkSumWrdPos = 2;
                else l4HDLen = 4;
                break;

            case L3_OSPF:
                chkSumWrdPos = 6;
                if (*(uint8_t*)l4HdrP16 == 2) {
                    l4HDLen = 24;
#if IPCHECKSUM > 1
                    pHdr = 0;
#endif // IPCHECKSUM > 1
                } else {
                    l4HDLen = 16;
                }
                break;

            default:
                if (packet->snapL3Len < l3Len) ipFlags |= (IP_SNP_HLEN_WRN | IP_L4CHK_SUMERR);
                tcpFStat &= ~L4CHKSUMC;
                goto intdis;
        }

        l4HdrChkSum = ntohs(l4HdrP16[chkSumWrdPos]);

#if FRAGMENTATION == 1
        tcpFlagsP->l4HdrChkSum = l4HdrChkSum;
        tcpFlagsP->totL4Len = 0;
#endif // FRAGMENTATION == 1

        if (packet->snapL3Len < l3Len || packet->snapL4Len < l4Len) ipFlags |= (IP_SNP_HLEN_WRN | IP_L4CHK_SUMERR);
#if IPCHECKSUM > 1
        else if (chkSumWrdPos) tcpFlagsP->l4CalChkSum = Checksum(l4HdrP16, (uint32_t)l4CalChkSum, chkLen, chkSumWrdPos); // use the largest structure pointer: TCP
#endif // IPCHECKSUM > 1
    } // ((ipFrag & FRAGID_N) == 0x0000)
#if IPCHECKSUM > 1
#if FRAGMENTATION == 1
    else if (tcpFStat & L4CHKSUMC) {
        tcpFlagsP->l4CalChkSum = Checksum((uint16_t*)packet->l7HdrP, (uint32_t)tcpFlagsP->l4CalChkSum, packet->snapL7Len, 0); // use the largest structure pointer: TCP
    }

    tcpFlagsP->totL4Len += l4Len;
#endif // FRAGMENTATION == 1

    if (!frag) {
        if (pHdr) { // ICMP and IGMP use no pseudo header
#if FRAGMENTATION == 1
            if ((ipFrag & FRAGID_N) != 0x0000) chkLen = tcpFlagsP->totL4Len;
            else chkLen = l4Len;
#else // FRAGMENTATION == 0
            chkLen = l4Len;
#endif // FRAGMENTATION

            if (PACKET_IS_IPV6(packet)) {
#if IPV6_ACTIVATE > 0
                psyL3Header6_t psyL3Header6 = {
                    .ip_src = ip6HdrP->ip_src,
                    .ip_dst = ip6HdrP->ip_dst,
                    .ip_p = packet->l4Proto << 24,
                    .l4_len = htonl(chkLen),
                };
                // This somewhat messy code is to silence address-of-packed-member warnings
                const uint8_t * const hdr8 = (uint8_t*)&psyL3Header6;
                const uint16_t * const hdr16 = (uint16_t*)hdr8;
                tcpFlagsP->l4CalChkSum = Checksum(hdr16, (uint32_t)tcpFlagsP->l4CalChkSum, sizeof(psyL3Header6), 0);
#endif // IPV6_ACTIVATE > 0
            } else { // IPv4
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
                psyL3Header4_t psyL3Header4 = {
                    .ip_src = ipHdrP->ip_src,
                    .ip_dst = ipHdrP->ip_dst,
                    .ip_p = ((uint16_t)packet->l4Proto) << 8,
                    .l4_len = htons(chkLen),
                };
                // This somewhat messy code is to silence address-of-packed-member warnings
                const uint8_t * const hdr8 = (uint8_t*)&psyL3Header4;
                const uint16_t * const hdr16 = (uint16_t*)hdr8;
                tcpFlagsP->l4CalChkSum = Checksum(hdr16, (uint32_t)tcpFlagsP->l4CalChkSum, sizeof(psyL3Header4), 0);
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
            }
        }

#if FRAGMENTATION == 1
        l4HdrChkSum = tcpFlagsP->l4HdrChkSum;
#endif // FRAGMENTATION == 1
        if (tcpFlagsP->l4CalChkSum != 0xffff) l4CalChkSum = ntohs(~tcpFlagsP->l4CalChkSum);
        else l4CalChkSum = ntohs(tcpFlagsP->l4CalChkSum); // fix for devils 0x0000 checksum

        if (l4HdrChkSum != l4CalChkSum) ipFlags |= IP_L4CHK_SUMERR;
        tcpFStat &= ~L4CHKSUMC;
    }
#endif // IPCHECKSUM > 1

intdis: ;
    const float pktInterDis = (uint32_t)flowP->lastSeen.tv_sec - (uint32_t)tcpFlagsP->lastPktTime.tv_sec + (flowP->lastSeen.tv_usec - tcpFlagsP->lastPktTime.tv_usec) / TSTAMPFAC;
    if (tcpFStat & IP_INTDIS_OK) {
        if (pktInterDis == 0) {
            ipFlags |= IP_PKT_INTDIS;
        } else if (pktInterDis < 0) {
            ipFlags |= IP_PKT_INTDISN;
            globalWarn |= TIMEJUMP;
            flowP->status |= TIMEJUMP;
        }
    }

    tcpFlagsP->lastPktTime = flowP->lastSeen;

#if FRAG_ANALYZE == 1
    if (ipFrag) { // fragments with and without L4 header
        ipFrag = ntohs(ipFrag) & IPFRAGPKTSZMAX;
        if (frag && l3Len < IPFRAGPKTSZMIN) ipFlags |= IP_FRAG_BLW_MIN; // below minimum RFC fragments
        if (ipFrag - tcpFlagsP->ipNxtFragBgnExp > 1) ipFlags |= IP_FRAG_NXTPPOS; // fragments not at the expected position, pkt loss or attack
        tcpFlagsP->ipNxtFragBgnExp = ipFrag + (l4Len >> 3);
        if (tcpFlagsP->ipNxtFragBgnExp > IPFRAGPKTSZMAX) ipFlags |= IP_FRAG_OUT_RNG; // fragments out of buffer range, possible teardrop
    }
#endif // FRAG_ANALYZE

    tcpFlagsP->ipFlagsT |= ipFlags;
    tcpFlagsP->ipIDT = ipID;

    // Round trip estimate for non TCP

#if RTT_ESTIMATE == 1
    float tcpRTTemp = 0.0;
    if (revFlowP && tcpFlagsP->tcpRTTFlag != TCP_RTT_STOP) {
        tcpRTTemp = fabs(flowP->lastSeen.tv_sec - revFlowP->lastSeen.tv_sec + ((float)flowP->lastSeen.tv_usec - (float)revFlowP->lastSeen.tv_usec) / TSTAMPFAC);
        tcpFlagsPO->tcpRTTAckTripMin = MIN(tcpRTTemp, tcpFlagsPO->tcpRTTAckTripMin);
        tcpFlagsPO->tcpRTTAckTripMax = MAX(tcpRTTemp, tcpFlagsPO->tcpRTTAckTripMax);
        if ((tcpFlagsPO->tcpRTTFlag & (TCP_RTT_SYN_ST | TCP_RTT_SYN_ACK)) && tcpFlagsPO->tcpPktCnt == 1.0) {
            tcpFlagsPO->tcpRTTtrip = tcpRTTemp;
            tcpFlagsPO->tcpRTTAckTripAvg = tcpRTTemp;
        } else {
            const float tcpRTTDTemp = tcpRTTemp - tcpFlagsPO->tcpRTTAckTripAvg;
            tcpFlagsPO->tcpRTTAckTripAvg += tcpRTTDTemp / tcpFlagsP->tcpPktCnt;
            tcpFlagsPO->tcpRTTAckTripJitAvg += (tcpRTTDTemp * tcpRTTDTemp - tcpFlagsPO->tcpRTTAckTripJitAvg) / tcpFlagsP->tcpPktCnt;
            tcpFlagsPO->tcpRTTFlag = TCP_RTT_ACK;
            //tcpFlagsP->tcpRTTFlag = TCP_RTT_ACK;
        }
    }
#else // RTT_ESTIMATE == 0
    if (tcpFlagsPO) tcpFlagsPO->tcpRTTFlag = TCP_RTT_NO_SYN;
#endif // RTT_ESTIMATE

    if (sPktFile) {
        uint16_t frag_off;
        if (PACKET_IS_IPV6(packet)) {
            frag_off = (packet->ip6FragHdrP) ? ntohs(packet->ip6FragHdrP->frag_off) : 0;
        } else { // IPv4
            frag_off = ntohs(ipHdrP->ip_off);
        }

#if IPTOS > 0
        uint8_t n = ipToSL & 0xe0;
             if (n == 0x20) n = 1;
        else if (n == 0x40) n = 2;
        else if (n == 0x60) n = 3;
        else if (n == 0x80) n = 4;
        else if (n == 0xa0) n = 5;
        else if (n == 0xc0) n = 6;
        else if (n == 0xe0) n = 7;
#endif // IPTOS

        fprintf(sPktFile,
#if IPTOS > 0
                "%" PRIu8 "_%" PRIu8 /* ipToSDscp_ecn/ipToSPrec_ecn */ SEP_CHR
#else // IPTOS == 0
                "0x%02" B2T_PRIX8    /* ipToS                       */ SEP_CHR
#endif // IPTOS
                "%"     PRIu16       /* ipID                        */ SEP_CHR
                "%"     PRId32       /* ipIDDiff                    */ SEP_CHR
                "0x%04" B2T_PRIX16   /* ipFrag                      */ SEP_CHR
                "%"     PRIu8        /* ipTTL                       */ SEP_CHR
                "0x%04" B2T_PRIX16   /* ipHdrChkSum                 */ SEP_CHR
                "0x%04" B2T_PRIX16   /* ipCalChkSum                 */ SEP_CHR
                "0x%04" B2T_PRIX16   /* l4HdrChkSum                 */ SEP_CHR
                "0x%04" B2T_PRIX16   /* l4CalChkSum                 */ SEP_CHR
                "0x%04" B2T_PRIX16   /* ipFlags                     */ SEP_CHR
                ,
#if IPTOS == 2
                  n, (uint8_t)i(ipToSL & 0x03),
#elif IPTOS == 1
                  (uint8_t)(ipToSL >> 2), (uint8_t)(ipToSL & 0x03),
#else // IPTOS == 0
                  ipToSL,
#endif // IPTOS
                  ipID, ipIDDiff, frag_off, ttl,
                  ipHdrChkSum, ipCalChkSum,
                  l4HdrChkSum, l4CalChkSum,
                  ipFlags);

        if (PACKET_IS_IPV6(packet)) {
#if IPV6_ACTIVATE > 0
            // ip6HHOptLen
            fprintf(sPktFile, "%" PRId16 /* ip6HHOptLen */ SEP_CHR, ip6HHOptLen);
            if (ip6HHOptLen > 0) {
                // ip6HHOpts
                fprintf(sPktFile, "0x%02" B2T_PRIX8, ip6HHOpt[0]);
                for (int i = 1; i < ip6HHOptLen; i++) fprintf(sPktFile, ";0x%02" B2T_PRIX8, ip6HHOpt[i]);
            }

            // ip6DOptLen
            fprintf(sPktFile,
                               /* ip6HHOpts  */ SEP_CHR
                    "%" PRId16 /* ip6DOptLen */ SEP_CHR
                    , ip6DOptLen);
            if (ip6DOptLen > 0) {
                // ip6DOpts
                fprintf(sPktFile, "0x%02" B2T_PRIX8, ip6DOpt[0]);
                for (int i = 1; i < ip6DOptLen; i++) fprintf(sPktFile, ";0x%02" B2T_PRIX8, ip6DOpt[i]);
            }

            fputs(/* ip6DOptLen */ SEP_CHR, sPktFile);
#if IPV6_ACTIVATE == 2
            fputs("0" /* ipOptLen */ SEP_CHR
                      /* ipOpts   */ SEP_CHR
                  , sPktFile);
#endif // IPV6_ACTIVATE == 2
#endif // IPV6_ACTIVATE > 0
        } else { // IPv4
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE == 2
            fputs("0" /* ip6HHOptLen */ SEP_CHR
                      /* ip6HHOpts   */ SEP_CHR
                  "0" /* ip6DOptLen  */ SEP_CHR
                      /* ip6DOpts    */ SEP_CHR
                  , sPktFile);
#endif // IPV6_ACTIVATE == 2

            // ipOptLen
            fprintf(sPktFile, "%" PRId16 /* ipOptLen */ SEP_CHR, ipOptLen);
            if (ipOptLen > 0) {
                // ipOpts
                fprintf(sPktFile, "0x%02" B2T_PRIX8, ipOpt[0]);
                for (int i = 1; i < ipOptLen; i++) fprintf(sPktFile, ";0x%02" B2T_PRIX8, ipOpt[i]);
            }

            fputs(/* ipOptLen */ SEP_CHR, sPktFile);
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
        }

        if (packet->l4Proto != L3_TCP || ipFrag & FRAGID_N) {
#if SEQ_ACK_NUM == 1
            fputs(/* seq        */ SEP_CHR
                  /* ack        */ SEP_CHR
                  /* seqMax     */ SEP_CHR
                  /* seqDiff    */ SEP_CHR
                  /* ackDiff    */ SEP_CHR
                  /* seqLen     */ SEP_CHR
                  /* ackLen     */ SEP_CHR
                  /* seqFlowLen */ SEP_CHR
                  /* ackFlowLen */ SEP_CHR
                  /* tcpMLen    */ SEP_CHR
                  /* tcpBFlgt   */ SEP_CHR
                  , sPktFile);
#endif // SEQ_ACK_NUM == 1

            fputs("0x0000" /* tcpFStat   */ SEP_CHR
                           /* tcpFlags   */ SEP_CHR
                           /* tcpAnomaly */ SEP_CHR
                           /* tcpWin     */ SEP_CHR
                           /* tcpWS      */ SEP_CHR
                           /* tcpMSS     */ SEP_CHR
                  , sPktFile);

#if NAT_BT_EST == 1
            fputs(/* tcpTmS  */ SEP_CHR
                  /* tcpTmER */ SEP_CHR
                  , sPktFile);
#endif // NAT_BT_EST == 1

#if MPTCP == 1
            fputs(/* tcpMPTyp  */ SEP_CHR
                  /* tcpMPF    */ SEP_CHR
                  /* tcpMPAID  */ SEP_CHR
                  /* tcpMPDSSF */ SEP_CHR
                  , sPktFile);
#endif // MPTCP == 1

            fputs("0" /* tcpOptLen */ SEP_CHR
                      /* tcpOpts   */ SEP_CHR
                  , sPktFile);
        }
    }

    if (packet->l4Proto != L3_TCP || ipFrag & FRAGID_N) {
#if RTT_ESTIMATE == 1
        if (tcpFlagsP->tcpPktCnt == 1) tcpFlagsP->tcpRTTFlag = TCP_RTT_SYN_ACK;
        else if (tcpFlagsP->tcpRTTFlag == TCP_RTT_SYN_ACK) tcpFlagsP->tcpRTTFlag = TCP_RTT_ACK;
#endif // RTT_ESTIMATE == 1
        tcpFStat |= IP_INTDIS_OK;
        tcpFlagsP->stat |= tcpFStat;
        return; // return if not TCP and not 1. fragment
    }

    // only TCP is processed here
    uint16_t tcpAnomaly = 0;

    // TCP flags and options
    //uint16_t tcpFlags = *((char*)tcpHdrP + 13) & 0x00ff;
    uint16_t tcpFlags = tcpHdrP->flags;
    const uint8_t * const tcpOpt = ((uint8_t*)tcpHdrP + 20);
    const int32_t tcpOptLen = l4HDLen - 20;
    const uint16_t l7Len = packet->l7Len;

#if MPTCP == 1
    uint16_t tcpmpSTyp = 0;
    uint8_t tcpmpF = 0, tcpmpAID = 0, tcpmpDSSF = 0;
#endif //MPTCP == 1

    // aggregated anomaly flags and RTT add state machine TCP
    const uint8_t tf = (uint8_t)(tcpFlags & TH_ALL_FLAGS);
    if (tf == TH_NULL) {
        tcpFlags |= TCP_NULL;
        tcpAnomaly |= TCP_SCAN_DET;
#if TCPFLGCNT == 1
        tcpFlagsP->tcpFlgCnt[11]++;
#endif // TCPFLGCNT == 1
    } else if (tf == TH_XMAS) {
        tcpFlags |= TCP_XMAS;
        tcpAnomaly |= TCP_SCAN_DET;
#if TCPFLGCNT == 1
        tcpFlagsP->tcpFlgCnt[15]++;
#endif // TCPFLGCNT == 1
    }

#if TCPFLGCNT == 1
    uint8_t flc = tcpFlags;
    for (uint_fast8_t i = 0; i < 8; i++) {
        if (tcpFlagsP->tcpFlgCnt[i] < 0xffff) tcpFlagsP->tcpFlgCnt[i] += (flc & 0x01);
        flc >>= 1;
    }
#endif // TCPFLGCNT == 1

    switch (tcpFlags & TH_ARSF) { // grab only relevant TCP flag bits

        case TH_SYN: // SYN
            if (tcpFlagsP->tcpRTTFlag == TCP_RTT_SYN_ST) {
                if (pktInterDis > 0.9) {
                    totalSynRetry++;
                    tcpAnomaly |= TCP_SYN_RETRY; // SYN retransmit detected
                } else {
                    tcpAnomaly |= TCP_SCAN_DET;
                    totalTCPScans++;
                }
            }
            if (l7Len) tcpAnomaly |= TCP_SYN_L7CNT;
            tcpFlagsP->tcpRTTFlag = TCP_RTT_SYN_ST;
            break;

        case TH_SYN_ACK:
            tcpFlags |= SYN_ACK;
            tcpFlagsP->tcpRTTFlag = TCP_RTT_SYN_ACK;
#if TCPFLGCNT == 1
            tcpFlagsP->tcpFlgCnt[9]++;
#endif // TCPFLGCNT == 1
            break;

        case TH_ACK:
            if (tcpFlagsP->tcpRTTFlag == TCP_RTT_SYN_ACK) tcpFlagsP->tcpRTTFlag = TCP_RTT_ACK;
            if (!revFlowP) break;
#if RTT_ESTIMATE == 1
            if (!tcpFlagsPO->tcpRTTFlag || tcpFlagsPO->tcpRTTFlag == TCP_RTT_SYN_ACK) tcpFlagsPO->tcpRTTFlag = TCP_RTT_ACK;
#endif // RTT_ESTIMATE == 1
#if SEQ_ACK_NUM == 1
            tcpFlagsPO->tcpWinTLen = 0;
            tcpFlagsP->tcpWinTLen += l7Len;
            tcpFlagsP->tcpWinTLenMax = MAX(tcpFlagsP->tcpWinTLen, tcpFlagsP->tcpWinTLenMax);
#endif // SEQ_ACK_NUM == 1
            break;

        case TH_FIN_ACK:
            tcpFlags |= FIN_ACK;
            tcpFlagsP->tcpRTTFlag = TCP_RTT_STOP;
#if TCPFLGCNT == 1
            tcpFlagsP->tcpFlgCnt[8]++;
#endif // TCPFLGCNT == 1
            break;

        case TH_RST_ACK:
            tcpFlags |= RST_ACK;
            tcpFlagsP->tcpRTTFlag = TCP_RTT_STOP;
#if TCPFLGCNT == 1
            tcpFlagsP->tcpFlgCnt[10]++;
#endif // TCPFLGCNT == 1
            break;

        case TH_SYN_FIN:
            tcpFlags |= TCP_SYN_FIN;
            tcpFlagsP->tcpRTTFlag = TCP_RTT_STOP;
#if TCPFLGCNT == 1
            tcpFlagsP->tcpFlgCnt[12]++;
#endif // TCPFLGCNT == 1
            break;

        case TH_SYN_FIN_RST:
            tcpFlags |= TCP_SYN_FIN_RST;
            tcpFlagsP->tcpRTTFlag = TCP_RTT_STOP;
#if TCPFLGCNT == 1
            tcpFlagsP->tcpFlgCnt[13]++;
#endif // TCPFLGCNT == 1
            break;

        case TH_RST_FIN:
            tcpFlags |= TCP_RST_FIN;
            tcpFlagsP->tcpRTTFlag = TCP_RTT_STOP;
#if TCPFLGCNT == 1
            tcpFlagsP->tcpFlgCnt[14]++;
#endif // TCPFLGCNT == 1
            break;

        default:
            tcpFlagsP->tcpRTTFlag = TCP_RTT_STOP;
            break;
    }

    if (tcpOptLen > 0) { // consider all TCP options and set flag bits
        if (packet->snapL3Len < (l3HDLen + l4HDLen) && l4Len >= l4HDLen) { // option field exists or crafted packet?
            tcpFStat |= TCP_L4OPTCORRPT; // warning: crafted packet or option field not acquired
        } else {
            tcpFlagsP->tcpOptPktCntT++;
            for (int i = 0; i < tcpOptLen && tcpOpt[i] > 0; i += (tcpOpt[i] > 1) ? tcpOpt[i+1] : 1) {
                tcpFlagsP->tcpOptCntT++;
#if TCPJA4T == 1
                if (tcpFlagsP->tcpSsaOptsCnt < JA4TOPTMX && (tcpFlags & SYN)) {
                    tcpFlagsP->tcpSsaOpts[tcpFlagsP->tcpSsaOptsCnt++] = tcpOpt[i];
                }
#endif // TCPJA4T == 1
                if (tcpOpt[i] < 31) tcpFlagsP->tcpOptionsT |= 1U << tcpOpt[i];
                else tcpFlagsP->tcpOptionsT |= 1U << 31;

                // Option is not 1 (No-Operation) and length is 0... abort TCP options processing
                if (tcpOpt[i] > 1 && tcpOpt[i+1] == 0) {
                    tcpFStat |= TCP_L4OPTCORRPT;
                    break;
                }

                if (tcpOpt[i] == 2) {
                    tcpFlagsP->tcpMssT = (tcpOpt[i+2] << 8) + tcpOpt[i+3]; // save the last MSS
                } else if (tcpOpt[i] == 5) {
                    tcpFStat |= TCP_SACK;
                } else if (tcpOpt[i] == 3 && (tcpFlags & TH_SYN)) {
                    tcpFlagsP->tcpWST = tcpOpt[i+2]; // save the window scale TODO: max MSS, ave etc bandwidth and pipe length estimation
                    if ((tcpFlags & TH_SYN_ACK) == TH_SYN_ACK) {
                        tcpFlagsP->stat |= TCP_WS_USED;
                        if (tcpFlagsPO) tcpFlagsPO->stat |= TCP_WS_USED;
                    }
                }

#if NAT_BT_EST == 1
                else if (tcpOpt[i] == 8) {
                    const uint32_t *tcpTM = (uint32_t*)&tcpOpt[i+2];
                    tcpFlagsP->tcpTmS = ntohl(*tcpTM++);
                    tcpFlagsP->tcpTmER = ntohl(*tcpTM);
                    tcpFlagsP->tmOptLstPkt = flowP->lastSeen;
                    if (tcpFlagsP->tcpTmS < tcpFlagsP->tcpTmSLst) {
                        tcpFStat |= TCP_OPT_TM_DEC;
                    } else {
                        tcpFlagsP->tcpTmSLst = tcpFlagsP->tcpTmS;
                        if (!(tcpFStat & TCP_OPT_INIT)) {
                            tcpFlagsP->tcpTmSI = tcpFlagsP->tcpTmS;
                            tcpFlagsP->tmOptFrstPkt = flowP->lastSeen;
                            tcpFStat |= TCP_OPT_INIT;
                        }
                        //tcpFlagsP->tmOptLstPkt = flowP->lastSeen;
                        //tcpTM++;
                        //tcpFlagsP->tcpTmER = ntohl(*tcpTM);
                    }
                }
#endif // NAT_BT_EST == 1

#if MPTCP == 1
                else if (tcpOpt[i] == 30) {
                    const int st = (tcpOpt[i+2] & 0xf0) >> 4;
                    tcpmpSTyp = st;
                    tcpFlagsP->tcpmpTBF |= 1U << st; // save sub type
                    switch (st) {
                        case TCP_MP_CAPABLE:
                            tcpmpF = tcpOpt[i+3];
                            tcpFlagsP->tcpmpF |= tcpmpF; // save flags
                            break;
                        case TCP_MP_JOIN:
                        case TCP_MP_PRIO:
                            if (tcpOpt[i+1] <= 16) {
                                tcpmpF = tcpOpt[i+2] & 0x0f;
                                tcpmpAID = tcpOpt[i+3];
                                tcpFlagsP->tcpmpF |= tcpmpF; // save flags
                                tcpFlagsP->tcpmpAID = tcpmpAID; // save Address ID
                            }
                            break;
                        case TCP_MP_DSS:
                            tcpmpDSSF = tcpOpt[i+3] & 0x1f; // save flags
                            tcpFlagsP->tcpmpDSSF |= tcpmpDSSF; // save flags
                            break;
                        case TCP_MP_ADD_ADDR:
                        case TCP_MP_REM_ADDR:
                            tcpmpAID = tcpOpt[i+3];
                            tcpFlagsP->tcpmpAID = tcpmpAID; // save Address ID
                            break;
                        case TCP_MP_FAIL:
                        case TCP_MP_FSTCLS:
                        case TCP_MP_PRIV:
                        default:
                            break;
                    }

                    tcpFStat |= TCP_MPTCP;
                    mpTCPcnt++;
                }
#endif // MPTCP == 1
            }
        }
    }

    // TCP window size processing engine
    uint32_t tcpWin = ntohs(tcpHdrP->window);
    uint16_t tcpWSC = 0;
    if (tcpFStat & TCP_WS_USED) {
        tcpWSC = 1U << tcpFlagsP->tcpWST;
        tcpWin *= tcpWSC;
    }

#if WINDOWSIZE == 1
    tcpPktvCnt++;
    tcpFlagsP->tcpPktvCnt++;

#if WINMIN > 0
    if (!(tcpFlags & TH_SYN_FIN_RST) && tcpWin < WINMIN) {
        winMinCnt++;
        tcpFlagsP->tcpWinMinCnt++;
        tcpFStat |= TCP_ZWIN;
    }
#endif // WINMIN > 0

    if (!(tcpFStat & TCP_WIN_INIT)) {
        tcpFlagsP->tcpWinMinT  = tcpWin;
        tcpFlagsP->tcpWinMaxT  = tcpWin;
        tcpFlagsP->tcpWinInitT = tcpWin; // save initial window size
        tcpFlagsP->tcpWinLstT  = tcpWin; // first is the last Window
        tcpFlagsP->tcpWinAvgT  = tcpWin; // start with average
        tcpFStat |= TCP_WIN_INIT;
    }

    tcpFlagsP->tcpWinAvgT = tcpFlagsP->tcpWinAvgT * 0.7 + (float)tcpWin * 0.3; // IIR filter for winsize

    switch (tcpFStat & TCP_WIN_UP) {

        case TCP_WIN_DWN: // tcpWin decreases
            if (tcpWin <= tcpFlagsP->tcpWinLstT) {
                if (tcpWin < tcpFlagsP->tcpWinLstT) {
                    tcpFlagsP->tcpWdwnCntT++;
                    tcpFlagsP->tcpWinMinT = MIN(tcpWin, tcpFlagsP->tcpWinMinT);
                }
            } else {
                tcpFlagsP->tcpWchgCntT++;
                tcpFlagsP->tcpWupCntT++;
                tcpFlagsP->tcpWinMaxT = MAX(tcpWin, tcpFlagsP->tcpWinMaxT);
                tcpFStat |= TCP_WIN_UP;
            }
            break;

        case TCP_WIN_UP: // tcpWin increases
            if (tcpWin >= tcpFlagsP->tcpWinLstT) {
                if (tcpWin > tcpFlagsP->tcpWinLstT) {
                    tcpFlagsP->tcpWupCntT++;
                    tcpFlagsP->tcpWinMaxT = MAX(tcpWin, tcpFlagsP->tcpWinMaxT);
                }
            } else {
                tcpFlagsP->tcpWchgCntT++;
                tcpFlagsP->tcpWdwnCntT++;
                tcpFlagsP->tcpWinMinT = MIN(tcpWin, tcpFlagsP->tcpWinMinT);
                tcpFStat &= ~TCP_WIN_UP;
            }
            break;
    }
#endif // WINDOWSIZE == 1

    // sequence number processing
#if SEQ_ACK_NUM == 1
    const uint32_t seq = ntohl(tcpHdrP->seq);
    const uint32_t ack = ntohl(tcpHdrP->ack_seq);
    int32_t sd = 0, ad = 0;
    int32_t seqDiff = 0, ackDiff = 0;

    // Keep-Alive
    if (tcpFlagsPO && !(tcpFlags & TH_SYN_FIN_RST)) {
        if (!tcpFlagsPO->tcpWinLstT && l7Len == 1) tcpFStat |= TCP_WIN_0PRB;
        else if ((tcpFlagsPO->statLst & TCP_WIN_0PRB) && !tcpWin && !l7Len) tcpFStat |= TCP_WIN_0PRBACK;
    }
    if ((tcpFlags & TH_ACK) && !(tcpFStat & (TCP_WIN_0PRB | TCP_WIN_0PRBACK))) {
        if (l7Len <= 1 && !(tcpFlags & TH_SYN_FIN_RST)) {
            if (seq == tcpFlagsP->seqMax - 1) {
                tcpAnomaly |= TCP_KPALV;
            } else if (tcpFlagsPO && tcpFlagsPO->tcpSeqN == ack-1) {
                tcpAnomaly |= TCP_KPALVACK;
            }
        }
        if (tcpFlagsP->tcpAckT == ack && !(tcpFStat & (TCP_WIN_0PRB | TCP_WIN_0PRBACK)) && !(tcpAnomaly & (TCP_KPALV | TCP_KPALVACK))) {
            if ((tcpFStat & IP_INTDIS_OK) && !(tcpFlags & TH_SYN_FIN_RST) && l7Len == 0) {
                if (tcpFlagsP->tcpWinLstT == tcpWin || ((tcpFStat & TCP_WS_USED) && tcpFlagsP->tcpWinLstT*tcpWSC==tcpWin)) {
                    tcpAnomaly |= TCP_ACK_2;
                    tcpFlagsP->tcpAckFaultCntT++;
                } else if (seq == tcpFlagsP->tcpSeqN) {
                    tcpFStat |= TCP_WIN_UPD;
                }
            }
            if (!(tcpFlags & TH_SYN_FIN_RST) && seq < tcpFlagsP->seqMax) {
                tcpAnomaly |= TCP_SEQ_OUTORDR;
            } else if (seq < tcpFlagsP->tcpSeqN) {
#if RTT_ESTIMATE == 0
                if (pktInterDis > RTRFAC) {
#else // RTT_ESTIMATE == 1
                if (tcpFlagsPO && pktInterDis > (tcpFlagsPO->tcpRTTAckTripAvg +tcpFlagsP->tcpRTTAckTripAvg) * RTRFAC) {
#endif // RTT_ESTIMATE
                    if (tcpFlagsP->tcpWinLstT == tcpWin) {
                        tcpAnomaly |= TCP_SEQ_TRETRY;
                        totalTCPRetry++;
                        tcpFlagsP->tcpSeqFaultCntT++;
                    }
                }
            }

            if ((tcpFlagsPO && (tcpFlagsPO->tcpAnomalyLst & TCP_ACK_2)) && seq == tcpFlagsPO->tcpAckT) {
                if ( (l7Len > 0 || (tcpFlags & TH_SYN_FIN)) && seq < tcpFlagsP->tcpSeqN) {
                    tcpAnomaly |= TCP_SEQ_FRETRY;
                    totalTCPRetry++;
                    tcpFlagsP->tcpSeqFaultCntT++;
                }
            }

            if (tcpFlagsPO && tcpFlagsPO->tcpAckT > seq) tcpAnomaly |= TCP_SEQ_PLSSMS; // mess in flow packet order, rather spurious Retransmission
        }

        if (seq == tcpFlagsP->tcpSeqN) tcpFlagsP->tcpPSeqCntT++; // count good packets in flow

        if (tcpFlagsPO && tcpFlagsPO->seqMax < ack) {
            tcpAnomaly |= TCP_ACK_UNSEEN;
            tcpFlagsP->tcpAckFaultCntT++;
        }

        if (!(tcpFlagsP->tcpFlagsL & TH_SYN_FIN_RST) && seq > tcpFlagsP->seqMax) tcpAnomaly |= TCP_PKT_NCAP;
        //if ((!(tcpFlagsP->tcpFlagsL & TH_SYN_FIN_RST) || (tcpFlagsPO && !(tcpFlagsPO->tcpFlagsL & TH_SYN_FIN_RST))) && seq > tcpFlagsP->seqMax)) tcpAnomaly |= TCP_PKT_NCAP;

        if (tcpFlagsP->tcpSeqT) {
            sd = (int32_t)(seq - tcpFlagsP->tcpSeqT);
            if (sd > 0) seqDiff = sd;
            if (tcpFlagsP->tcpFlagsL & TH_SYN_FIN_RST && sd == 1) seqDiff = 0;
            tcpFlagsP->tcpOpSeqPktLength += seqDiff;
        }

        if (tcpFlagsP->tcpAckT) {
            ad = (int32_t)(ack - tcpFlagsP->tcpAckT);
            if (ad > 0) ackDiff = ad;
            if (((tcpFlagsP->tcpFlagsL & TH_SYN_FIN_RST) || (tcpFlagsPO && (tcpFlagsPO->tcpFlagsL & TH_SYN_FIN_RST))) && ad == 1) ackDiff = 0;
            tcpFlagsP->tcpOpAckPktLength += ackDiff;
        }

        tcpFlagsP->tcpPAckCntT++; // only good if all packets are ACKed
    }

    tcpFlagsP->tcpMLen += l7Len;
    if (tcpFlagsPO && !(tcpFStat & (TCP_WIN_0PRB | TCP_WIN_0PRBACK)) && tcpFlagsP->tcpWinTLen >= tcpFlagsPO->tcpWinLstT) {
        if (!(tcpFlagsPO->tcpFlagsL & TH_RST) && tcpFlagsP->tcpFlagsT & TH_SYN) tcpFStat |= TCP_WIN_FLL;
    }

    if ((tcpAnomaly & TCP_SCAN_DET) || (tcpFlagsP->tcpAnomaly & TCP_SCAN_DET)) tcpAnomaly &= ~TCP_ECNTR;
#endif // SEQ_ACK_NUM == 1

    if (sPktFile) {
#if SEQ_ACK_NUM == 1
        uint32_t seqR = seq;
        uint32_t ackR = ack;
#if SPKTMD_SEQACKREL == 1
        seqR -= tcpFlagsP->tcpSeqI;
        ackR -= tcpFlagsP->tcpAckI;
#endif // SPKTMD_SEQACKREL == 1
#endif // SEQ_ACK_NUM == 1

        fprintf(sPktFile,
#if SEQ_ACK_NUM == 1
#if SPKTMD_SEQACKHEX == 1
                "0x%08" B2T_PRIX32 /* seq        */ SEP_CHR
                "0x%08" B2T_PRIX32 /* ack        */ SEP_CHR
                "0x%08" B2T_PRIX32 /* seqMax     */ SEP_CHR
#else // SPKTMD_SEQACKHEX == 0
                "%"     PRIu32     /* seq        */ SEP_CHR
                "%"     PRIu32     /* ack        */ SEP_CHR
                "%"     PRIu32     /* seqMax     */ SEP_CHR
#endif // SPKTMD_SEQACKHEX == 1
                "%"     PRId32     /* seqDiff    */ SEP_CHR
                "%"     PRId32     /* ackDiff    */ SEP_CHR
                "%"     PRIu32     /* seqLen     */ SEP_CHR
                "%"     PRIu32     /* ackLen     */ SEP_CHR
                "%"     PRId64     /* seqFlowLen */ SEP_CHR
                "%"     PRId64     /* ackFlowLen */ SEP_CHR
                "%"     PRId64     /* tcpMLen    */ SEP_CHR
                "%"     PRIu32     /* tcpBFlgt   */ SEP_CHR
#endif // SEQ_ACK_NUM == 1
                "0x%04" B2T_PRIX16 /* tcpFStat   */ SEP_CHR
                "0x%04" B2T_PRIX16 /* tcpFlags   */ SEP_CHR
                "0x%04" B2T_PRIX16 /* tcpAnomaly */ SEP_CHR
                "%"     PRIu32     /* tcpWin     */ SEP_CHR
                "%"     PRIu16     /* tcpWS      */ SEP_CHR
                "%"     PRIu16     /* tcpMSS     */ SEP_CHR
#if NAT_BT_EST == 1
                "%"     PRIu32     /* tcpTmS     */ SEP_CHR
                "%"     PRIu32     /* tcpTmER    */ SEP_CHR
#endif // NAT_BT_EST == 1
#if MPTCP == 1
                "%"     PRIu16     /* tcpMPTyp   */ SEP_CHR
                "0x%02" B2T_PRIX8  /* tcpMPF     */ SEP_CHR
                "%"     PRIu8      /* tcpMPAID   */ SEP_CHR
                "0x%02" B2T_PRIX8  /* tcpMPDSSF  */ SEP_CHR
#endif // MPTCP == 1
                "%"     PRId32     /* tcpOptLen  */ SEP_CHR
                ,
#if SEQ_ACK_NUM == 1
                  seqR, ackR,
                  tcpFlagsP->seqMax - (SPKTMD_SEQACKREL * tcpFlagsP->tcpSeqI),
                  sd, ad, seqDiff, ackDiff,
                  tcpFlagsP->tcpOpSeqPktLength, tcpFlagsP->tcpOpAckPktLength, tcpFlagsP->tcpMLen, tcpFlagsP->tcpWinTLen,
#endif // SEQ_ACK_NUM == 1
                  tcpFStat, tcpFlags, tcpAnomaly, tcpWin, tcpWSC, tcpFlagsP->tcpMssT,
#if NAT_BT_EST == 1
                  tcpFlagsP->tcpTmS, tcpFlagsP->tcpTmER,
#endif // NAT_BT_EST == 1
#if MPTCP == 1
                  tcpmpSTyp, tcpmpF, tcpmpAID, tcpmpDSSF,
#endif //MPTCP == 1
                  tcpOptLen);

        // tcpOpts
        if (tcpOptLen > 0) {
            fprintf(sPktFile, "0x%02" B2T_PRIX8, tcpOpt[0]);
            for (int i = 1; i < tcpOptLen; i++) fprintf(sPktFile, ";0x%02" B2T_PRIX8, tcpOpt[i]);
        }

        fputs(/* tcpOpts */ SEP_CHR, sPktFile);
    }

    //if ((tcpFlags & TH_RST) == 0) {
#if SEQ_ACK_NUM == 1
        tcpFlagsP->tcpSeqT = seq;
        tcpFlagsP->tcpSeqN = seq + l7Len;
        if (tcpFlags & TH_SYN_FIN_RST) tcpFlagsP->tcpSeqN++;
        else if (tcpFStat & TCP_WIN_0PRB) tcpFlagsP->tcpSeqN--;
        tcpFlagsP->tcpAckT = ack;
        tcpFlagsP->tcpPLstLen = l7Len;
        tcpFlagsP->seqMax = MAX(tcpFlagsP->tcpSeqN, tcpFlagsP->seqMax);
#endif // SEQ_ACK_NUM == 1

#if WINDOWSIZE == 1
        tcpFlagsP->tcpWinLstT = tcpWin;
#endif // WINDOWSIZE == 1
        tcpFlagsP->tcpFlagsL = tcpFlags;
    //}

    tcpFlagsP->tcpFlagsT |= tcpFlags;
    tcpFlagsP->tcpAnomaly |= tcpAnomaly;
    tcpFlagsP->tcpAnomalyLst = tcpAnomaly;
    tcpFStat |= IP_INTDIS_OK;
    tcpFlagsP->stat |= tcpFStat;
    tcpFlagsP->statLst = tcpFStat;

#if FRAG_ANALYZE == 1
    if (revFlowP && (revFlowP->status & IPV4_FRAG_PENDING) && (tcpFlags & TH_RST_FIN)) {
        tcpFlagsPO->ipFlagsT |= IP_FRAG_SEQERR;
    }
#endif // FRAG_ANALYZE == 1

#if SCAN_DETECTOR == 1
    if (tcpFlagsP->pktCnt < TCP_SCAN_PMAX + 2) tcpFlagsP->pktCnt++;
#endif // SCAN_DETECTOR == 1
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    tcpFlagsFlow_t * const tcpFlagsP = &tcpFlagsFlows[flowIndex];

#if FRAG_ANALYZE == 1 || SCAN_DETECTOR == 1 || RTT_ESTIMATE == 1
    const flow_t * const flowP = &flows[flowIndex];
#endif // FRAG_ANALYZE == 1 || SCAN_DETECTOR == 1 || RTT_ESTIMATE == 1

#if SCAN_DETECTOR == 1 || RTT_ESTIMATE == 1
    tcpFlagsFlow_t *tcpFlagsPO;
    const uint64_t revFlowInd = flowP->oppositeFlowIndex;
    if (revFlowInd != HASHTABLE_ENTRY_NOT_FOUND) {
        tcpFlagsPO = &tcpFlagsFlows[revFlowInd];
    } else {
        tcpFlagsPO = NULL;
    }
#endif // SCAN_DETECTOR == 1 || RTT_ESTIMATE == 1

    ipFlags    |= tcpFlagsP->ipFlagsT;
    ipToS      |= tcpFlagsP->ipTosT;
    tcpFStat   |= tcpFlagsP->stat;
    tcpFlags   |= tcpFlagsP->tcpFlagsT;
    tcpAnomaly |= tcpFlagsP->tcpAnomaly;

#if SCAN_DETECTOR == 1
    if (!(tcpFlagsP->tcpAnomaly & TCP_SYN_RETRY) && ((tcpFlagsP->tcpFlagsT & (SYN | FIN | TCP_SCAN_FLAGS)))) {
        if (tcpFlagsP->pktCnt < TCP_SCAN_PMAX && !(tcpFlagsP->tcpAnomaly & (TCP_SCAN_DET | TCP_SCAN_SU_DET))) {
            tcpFlagsP->tcpAnomaly |= TCP_SCAN_DET;
            totalTCPScans++;
        }

        if (tcpFlagsPO) {
            if (((tcpFlagsP->tcpAnomaly & TCP_SCAN_DET) && !(tcpFlagsP->tcpAnomaly & TCP_SCAN_SU_DET)) ||
                (
                    (tcpFlagsPO->tcpAnomaly & TCP_SCAN_DET && !(tcpFlagsPO->tcpAnomaly & TCP_SCAN_SU_DET)) &&
                    (tcpFlagsP->pktCnt < TCP_SCAN_PMAX && tcpFlagsPO->pktCnt < TCP_SCAN_PMAX)
                )
            ) {
                tcpFlagsP->tcpAnomaly |= TCP_SCAN_SU_DET;
                tcpFlagsPO->tcpAnomaly |= TCP_SCAN_SU_DET;
                totalTCPSuccScans++;
            }
        }
    }
#endif // SCAN_DETECTOR == 1

#if FRAG_ANALYZE == 1
    if (flowP->status & IPV4_FRAG_ERR) tcpFlagsP->ipFlagsT |= IP_FRAG_SEQERR;
#endif // FRAG_ANALYZE == 1

    OUTBUF_APPEND_U16(buf, tcpFlagsP->stat);      // tcpFStat
    OUTBUF_APPEND_U16(buf, tcpFlagsP->ipMinIDT);  // ipMindIPID
    OUTBUF_APPEND_U16(buf, tcpFlagsP->ipMaxIDT);  // ipMaxdIPID
    OUTBUF_APPEND_U8(buf , tcpFlagsP->ipMinTTLT); // ipMinTTL
    OUTBUF_APPEND_U8(buf , tcpFlagsP->ipMaxTTLT); // ipMaxTTL
    OUTBUF_APPEND_U8(buf , tcpFlagsP->ipTTLChgT); // ipTTLChg

    // ipToSPrec_ecn/ipToSDscp_ecn/ipToS
#if IPTOS == 2
    // ipToSPrec_ecn
    uint8_t n = tcpFlagsP->ipTosT & 0xe0;
         if (n == 0x20) n = 1;
    else if (n == 0x40) n = 2;
    else if (n == 0x60) n = 3;
    else if (n == 0x80) n = 4;
    else if (n == 0xa0) n = 5;
    else if (n == 0xc0) n = 6;
    else if (n == 0xe0) n = 7;
    OUTBUF_APPEND_U8(buf , n);    // ipToSPrec
    n = tcpFlagsP->ipTosT & 0x03;
    OUTBUF_APPEND_U8(buf , n);    // ecn
#elif IPTOS == 1
    // ipToSDscp_ecn
    uint8_t n = tcpFlagsP->ipTosT >> 2;
    OUTBUF_APPEND_U8(buf , n);    // ipToSDscp
    n = tcpFlagsP->ipTosT & 0x03;
    OUTBUF_APPEND_U8(buf , n);    // ecn
#else // IPTOS == 0
    OUTBUF_APPEND_U8(buf , tcpFlagsP->ipTosT);    // ipToS
#endif // IPTOS

    OUTBUF_APPEND_U16(buf, tcpFlagsP->ipFlagsT);  // ipFlags

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    //OUTBUF_APPEND_U16(buf, tcpFlagsP->ipOptPktCntT); // ipOptPktCnt
    OUTBUF_APPEND_U16(buf, tcpFlagsP->ipOptCntT);    // ipOptCnt

    // ipOptCpCl_Num
    OUTBUF_APPEND_U8( buf, tcpFlagsP->ipCpClT);    // bt_hex_8 : copy, class
    OUTBUF_APPEND_U32(buf, tcpFlagsP->ipOptionsT); // bt_hex_32: IP option
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if IPV6_ACTIVATE > 0
    // ip6OptCntHH_D
    OUTBUF_APPEND_U16(buf, tcpFlagsP->ip6HHOptCntT);
    OUTBUF_APPEND_U16(buf, tcpFlagsP->ip6DOptCntT);

    // ip6OptHH_D
    OUTBUF_APPEND_U32(buf, tcpFlagsP->ip6HHOptionsT);
    OUTBUF_APPEND_U32(buf, tcpFlagsP->ip6DOptionsT);
#endif // IPV6_ACTIVATE > 0

#if SEQ_ACK_NUM == 1
    OUTBUF_APPEND_U32(buf, tcpFlagsP->tcpSeqI);           // tcpISeqN
    OUTBUF_APPEND_U16(buf, tcpFlagsP->tcpPSeqCntT);       // tcpPSeqCnt
    OUTBUF_APPEND_U64(buf, tcpFlagsP->tcpOpSeqPktLength); // tcpSeqSntBytes
    OUTBUF_APPEND_U16(buf, tcpFlagsP->tcpSeqFaultCntT);   // tcpSeqFaultCnt
    OUTBUF_APPEND_U16(buf, tcpFlagsP->tcpPAckCntT);       // tcpPAckCnt
    OUTBUF_APPEND_U64(buf, tcpFlagsP->tcpOpAckPktLength); // tcpFlwLssAckRcvdBytes
    OUTBUF_APPEND_U16(buf, tcpFlagsP->tcpAckFaultCntT);   // tcpAckFaultCnt
    OUTBUF_APPEND_U32(buf, tcpFlagsP->tcpWinTLenMax);     // tcpWinTLenMax
#endif // SEQ_ACK_NUM == 1

#if WINDOWSIZE == 1
    OUTBUF_APPEND_U32(buf, tcpFlagsP->tcpWinInitT); // tcpInitWinSz
    OUTBUF_APPEND_FLT(buf, tcpFlagsP->tcpWinAvgT);  // tcpAvgWinSz
    OUTBUF_APPEND_U32(buf, tcpFlagsP->tcpWinMinT);  // tcpMinWinSz
    OUTBUF_APPEND_U32(buf, tcpFlagsP->tcpWinMaxT);  // tcpMaxWinSz
    OUTBUF_APPEND_U16(buf, tcpFlagsP->tcpWdwnCntT); // tcpWinSzDwnCnt
    OUTBUF_APPEND_U16(buf, tcpFlagsP->tcpWupCntT);  // tcpWinSzUpCnt
    OUTBUF_APPEND_U16(buf, tcpFlagsP->tcpWchgCntT); // tcpWinSzChgDirCnt

    // tcpWinSzThRt
    const float f1 = (tcpFlagsP->tcpPktvCnt) ? (float)tcpFlagsP->tcpWinMinCnt/(float)tcpFlagsP->tcpPktvCnt : 0.0f;
    OUTBUF_APPEND_FLT(buf, f1);
#endif // WINDOWSIZE == 1

    OUTBUF_APPEND_U16(buf, tcpFlagsP->tcpFlagsT);     // tcpFlags
    OUTBUF_APPEND_U16(buf, tcpFlagsP->tcpAnomaly);    // tcpAnomaly

#if TCPFLGCNT == 1
    // tcpCntFIN_SYN_RST_PSH_ACK_URG_ECE_CWR
    OUTBUF_APPEND(buf, tcpFlagsP->tcpFlgCnt, 16 * sizeof(uint16_t));
#endif // TCPFLGCNT == 1

#if TCPJA4T == 1
    // tcpJA4T
    // JA4T fingerprints (each part separated by an underscore):
    //  - JA4T_a: TCP Window Size
    //  - JA4T_b: TCP Options (in the order they are seen, separated by a dash)
    //  - JA4T_c: TCP Maximum Segment Size (MSS)
    //  - JA4T_d: TCP Window Scale
    char ja4t[JA4TOPTMX*4+1] = {};
    char *p = ja4t;
    p += snprintf(p, sizeof(ja4t) - (p - ja4t), "%" PRIu32 "_", tcpFlagsP->tcpWinInitT);
    if (tcpFlagsP->tcpSsaOptsCnt == 0) {
        p += snprintf(p, sizeof(ja4t) - (p - ja4t), "00_");
    } else {
        for (uint_fast32_t i = 0; i < tcpFlagsP->tcpSsaOptsCnt; i++) {
            p += snprintf(p, sizeof(ja4t) - (p - ja4t), "%" PRIu8 "-", tcpFlagsP->tcpSsaOpts[i]);
        }
        *(--p) = '_';
    }
    p += snprintf(p, sizeof(ja4t) - (p - ja4t), "%02" PRIu16 "_", tcpFlagsP->tcpMssT);
    if (tcpFStat & TCP_WS_USED) {
        p += snprintf(p, sizeof(ja4t) - (p - ja4t), "%" PRIu8, tcpFlagsP->tcpWST);
    } else {
        p += snprintf(p, sizeof(ja4t) - (p - ja4t), "00");
    }
    OUTBUF_APPEND_STR(buf, ja4t);
#endif // TCPJA4T == 1

    OUTBUF_APPEND_U16(buf, tcpFlagsP->tcpOptPktCntT); // tcpOptPktCnt
    OUTBUF_APPEND_U16(buf, tcpFlagsP->tcpOptCntT);    // tcpOptCnt
    OUTBUF_APPEND_U32(buf, tcpFlagsP->tcpOptionsT);   // tcpOptions
    OUTBUF_APPEND_U16(buf, tcpFlagsP->tcpMssT);       // tcpMSS

    // tcpWS
    const uint16_t wst = ((tcpFStat & TCP_WS_USED) ? (1U << tcpFlagsP->tcpWST) : 0);
    OUTBUF_APPEND_U16(buf, wst);

#if MPTCP == 1
    tcpMPTBF |= tcpFlagsP->tcpmpTBF;
    tcpMPF   |= tcpFlagsP->tcpmpF;

    OUTBUF_APPEND_U16(buf, tcpFlagsP->tcpmpTBF);  // tcpMPTBF
    OUTBUF_APPEND_U8(buf , tcpFlagsP->tcpmpF);    // tcpMPF
    OUTBUF_APPEND_U8(buf , tcpFlagsP->tcpmpAID);  // tcpMPAID
    OUTBUF_APPEND_U8(buf , tcpFlagsP->tcpmpDSSF); // tcpMPdssF
#endif // MPTCP == 1

#if NAT_BT_EST == 1 || RTT_ESTIMATE == 1
    float f = 0.0;
#endif

#if NAT_BT_EST == 1
    OUTBUF_APPEND_U32(buf, tcpFlagsP->tcpTmS);  // tcpTmS
    OUTBUF_APPEND_U32(buf, tcpFlagsP->tcpTmER); // tcpTmER

    struct timeval tempT;

    // tcpEcI, tcpAcI, tcpUtm
    double d = 0.0;
    if (tcpFlagsP->tcpOptionsT & TCPOPTTM) {
        timersub(&tcpFlagsP->tmOptLstPkt, &tcpFlagsP->tmOptFrstPkt, &tempT);
        f = tempT.tv_sec + tempT.tv_usec / TSTAMPFAC;
        const uint32_t i = tcpFlagsP->tcpTmS - tcpFlagsP->tcpTmSI;
        if (i) {
            f /= (float)i;
            //h = f;
                 if (f < 0.002) f = 0.001; // Cisco, Windows
            else if (f < 0.005) f = 0.004; // Linux
            else if (f < 0.02)  f = 0.01;  // Linux
            else if (f < 0.2)   f = 0.1;   // Solaris
            else if (f < 0.7)   f = 0.1;   // OpenBSD
            else                f = 1.0;
        } else { // default heuristics
                 if (tcpFlagsP->ipMinTTLT >= 128) f = 0.1;
            else if (tcpFlagsP->ipMinTTLT >=  64) f = 0.004;
            else if (tcpFlagsP->ipMinTTLT >   32) f = 0.01;
            else                                  f = 0.001;
        }

        d = (double)tcpFlagsP->tcpTmS * (double)f;
    }

    OUTBUF_APPEND_FLT(buf, f);                  // tcpEcI
    //OUTBUF_APPEND_FLT(buf, h);                  // tcpAcI
    OUTBUF_APPEND_DBL(buf, d);                  // tcpUtm

    // tcpBtm
    tempT.tv_sec = (uint64_t)d;
    tempT.tv_usec = (uint32_t)((d - tempT.tv_sec) * TSTAMPFAC);
    struct timeval tcpBTmS;
    timersub(&tcpFlagsP->tmOptLstPkt, &tempT, &tcpBTmS);
    const uint64_t secs = tcpBTmS.tv_sec;
    const uint32_t usecs = tcpBTmS.tv_usec;
    OUTBUF_APPEND_TIME(buf, secs, usecs);
#endif // NAT_BT_EST == 1

#if RTT_ESTIMATE == 1
    // tcpSSASAATrip, tcpRTTAckTripMin, tcpRTTAckTripMax, tcpRTTAckTripAvg
    OUTBUF_APPEND(buf, tcpFlagsP->tcpRTTtrip, 4 * sizeof(float));

    // tcpRTTAckTripJitAvg
    f = sqrt(tcpFlagsP->tcpRTTAckTripJitAvg);
    OUTBUF_APPEND_FLT(buf, f);

    // tcpRTTSseqAA
    if (!tcpFlagsPO) {
        f = 0.0;
    } else if (flowP->status & L3FLOWINVERT) {
        f = tcpFlagsP->tcpRTTAckTripAvg + tcpFlagsPO->tcpRTTAckTripAvg;
    } else {
        f = tcpFlagsP->tcpRTTtrip + tcpFlagsPO->tcpRTTtrip;
    }
    OUTBUF_APPEND_FLT(buf, f);

    // tcpRTTAckJitAvg
    if (tcpFlagsPO && flowP->status & L3FLOWINVERT) f = sqrt(tcpFlagsP->tcpRTTAckTripJitAvg + tcpFlagsPO->tcpRTTAckTripJitAvg);
    else f = 0.0;
    OUTBUF_APPEND_FLT(buf, f);
#endif // RTT_ESTIMATE == 1
}


void t2PluginReport(FILE *stream) {
    T2_FPLOG_AGGR_HEX(stream, plugin_name, ipFlags);
    T2_FPLOG_AGGR_HEX(stream, plugin_name, tcpFStat);
    T2_FPLOG_AGGR_HEX(stream, plugin_name, tcpFlags);
    T2_FPLOG_AGGR_HEX(stream, plugin_name, tcpAnomaly);
    T2_FPLOG_AGGR_HEX(stream, plugin_name, ipToS);

    char str1[64];

    if (totalTCPScans || totalTCPSuccScans) {
        char str2[64];
        T2_CONV_NUM(totalTCPScans, str1);
        T2_CONV_NUM(totalTCPSuccScans, str2);
        T2_FPLOG(stream, plugin_name, "Number of TCP scans attempted, successful: %" PRIu64 "%s, %" PRIu64 "%s [%.2f%%]",
                 totalTCPScans, str1, totalTCPSuccScans, str2, 100.0*totalTCPSuccScans/(double)totalTCPScans);
    }

    if (totalTCPRetry || totalSynRetry) {
        char str2[64];
        T2_CONV_NUM(totalSynRetry, str1);
        T2_CONV_NUM(totalTCPRetry, str2);
        T2_FPLOG(stream, plugin_name, "Number of TCP SYN retries, seq retries: %" PRIu64 "%s, %" PRIu64 "%s",
                 totalSynRetry, str1, totalTCPRetry, str2);
    }

    if (winMinCnt && tcpPktvCnt) {
        T2_CONV_NUM(winMinCnt, str1);
        T2_FPLOG(stream, plugin_name, "Number WinSz below %d: %" PRIu64 "%s [%.2f%%]",
                 WINMIN, winMinCnt, str1, 100.0*winMinCnt/(double)tcpPktvCnt);
    }

#if MPTCP == 1
    if (mpTCPcnt) {
        T2_FPLOG(stream, plugin_name, "Aggregated MPTCP subtypes: tcpMPTBF=0x%04" B2T_PRIX16, tcpMPTBF);
        T2_FPLOG(stream, plugin_name, "Aggregated MPTCP flags: tcpMPF=0x%02" B2T_PRIX8, tcpMPF);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of MPTCP packets", mpTCPcnt, numPackets);
    }
#endif // MPTCP == 1
}


void t2Monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        case T2_MON_PRI_HDR:
            fputs("ipFlags"       SEP_CHR
                  "tcpFStat"      SEP_CHR
                  "tcpFlags"      SEP_CHR
                  "tcpAnomaly"    SEP_CHR
                  "tcpScan"       SEP_CHR
                  "tcpSuccScan"   SEP_CHR
                  "tcpSynRetries" SEP_CHR
                  "tcpSeqRetries" SEP_CHR
                  , stream);
            return;

        case T2_MON_PRI_VAL:
            fprintf(stream,
                   "0x%" PRIx16 /* ipFlags       */ SEP_CHR
                   "0x%" PRIx16 /* tcpFStat      */ SEP_CHR
                   "0x%" PRIx16 /* tcpFlags      */ SEP_CHR
                   "0x%" PRIx16 /* tcpAnomaly    */ SEP_CHR
                   "%" PRIu64 /* tcpScan       */ SEP_CHR
                   "%" PRIu64 /* tcpSuccScan   */ SEP_CHR
                   "%" PRIu64 /* tcpSynRetries */ SEP_CHR
                   "%" PRIu64 /* tcpSeqRetries */ SEP_CHR
                   , ipFlags
                   , tcpFStat
                   , tcpFlags
                   , tcpAnomaly
                   , totalTCPScans - totalTCPScans0
                   , totalTCPSuccScans - totalTCPSuccScans0
                   , totalSynRetry - totalSynRetry0
                   , totalTCPRetry - totalTCPRetry0);
            break;

        case T2_MON_PRI_REPORT: {
            T2_FPLOG_AGGR_HEX(stream, plugin_name, ipFlags);
            T2_FPLOG_AGGR_HEX(stream, plugin_name, tcpFStat);
            T2_FPLOG_AGGR_HEX(stream, plugin_name, tcpFlags);
            T2_FPLOG_AGGR_HEX(stream, plugin_name, tcpAnomaly);
            T2_FPLOG_AGGR_HEX(stream, plugin_name, ipToS);
            char str1[64], str2[64];
            const uint_fast64_t totalTCPSuccScansDiff = (totalTCPSuccScans - totalTCPSuccScans0);
            if (totalTCPSuccScansDiff) {
                const uint_fast64_t totalTCPScansDiff = (totalTCPScans - totalTCPScans0);
                T2_CONV_NUM(totalTCPScansDiff, str1);
                T2_CONV_NUM(totalTCPSuccScansDiff, str2);
                T2_FPLOG(stream, plugin_name, "Number of TCP scans attempted, successful: %" PRIu64 "%s, %" PRIu64 "%s [%.2f%%]",
                        totalTCPScansDiff, str1, totalTCPSuccScansDiff, str2, 100.0*totalTCPSuccScansDiff/(double)totalTCPScansDiff);
            }
            const uint_fast64_t totalSynRetryDiff = (totalSynRetry - totalSynRetry0);
            if (totalSynRetryDiff) {
                const uint_fast64_t totalTCPRetryDiff = (totalTCPRetry - totalTCPRetry0);
                T2_CONV_NUM(totalSynRetryDiff, str1);
                T2_CONV_NUM(totalTCPRetryDiff, str2);
                T2_FPLOG(stream, plugin_name, "Number of TCP SYN retries, seq retries: %" PRIu64 "%s, %" PRIu64 "%s",
                        totalSynRetryDiff, str1, totalTCPRetryDiff, str2);
            }
            break;
        }

        // Invalid state, do nothing
        default:
            return;
    }

#if DIFF_REPORT == 1
    totalTCPScans0 = totalTCPScans;
    totalTCPSuccScans0 = totalTCPSuccScans;
    totalTCPRetry0 = totalTCPRetry;
    totalSynRetry0 = totalSynRetry;
#endif // DIFF_REPORT == 1
}


void t2Finalize() {
    free(tcpFlagsFlows);
}
