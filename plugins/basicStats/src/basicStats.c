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

#include "basicStats.h"

#include <ctype.h> // for isdigit and toupper

#if BS_VARSTD > 0
#include <math.h>
#endif // BS_VARSTD > 0


// Global variables

bSFlow_t *bSFlow;


// Static variables

#if ETH_ACTIVATE > 0
static struct {
    uint8_t  addr[ETH_ALEN];
    uint64_t count;
} macBPktsTalker, macBByteTalker;
#endif // ETH_ACTIVATE > 0

static struct {
#if IPV6_ACTIVATE > 0
    ipAddr_t addr;
#else // IPV6_ACTIVATE == 0
    ip4Addr_t    addr;
#endif // IPV6_ACTIVATE
#if SUBNET_INIT != 0
    uint32_t     subnet;
#endif // SUBNET_INIT != 0
    uint64_t     count;
    uint_fast8_t ipver;
} ipBPktsTalker, ipBByteTalker;


#if BS_STATS == 1
static float    mxBytsps;
static uint64_t mxByts;
static uint64_t mxPkts;
#endif // BS_STATS == 1

#if BS_STATS == 1 && BS_XCLD > 0
#if ENVCNTRL > 0
#if BS_XCLD != 2
static uint16_t bsXMin;
#endif
#if BS_XCLD != 1
static uint16_t bsXMax;
#endif
#else // ENVCNTRL == 0
#if BS_XCLD != 2
static const uint16_t bsXMin = BS_XMIN;
#endif
#if BS_XCLD != 1
static const uint16_t bsXMax = BS_XMAX;
#endif
#endif // ENVCNTRL
#endif // BS_STATS == 1 && BS_XCLD > 0


// Tranalyzer functions

T2_PLUGIN_INIT("basicStats", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(bSFlow);
#if ENVCNTRL > 0 && BS_STATS == 1 && BS_XCLD > 0
    t2_env_t env[ENV_BS_N] = {};
    t2_get_env(PLUGIN_SRCH, ENV_BS_N, env);
#if BS_XCLD != 2
    bsXMin = T2_ENV_VAL_UINT(BS_XMIN);
#endif
#if BS_XCLD != 1
    bsXMax = T2_ENV_VAL_UINT(BS_XMAX);
#endif
    t2_free_env(ENV_BS_N, env);
#endif // ENVCNTRL > 0 && BS_STATS == 1 && BS_XCLD > 0

    if (sPktFile) {
        fputs("pktLen"    SEP_CHR
              "snapL3Len" SEP_CHR
              "snapL4Len" SEP_CHR
              "snapL7Len" SEP_CHR
              "l3Len"     SEP_CHR
              "udpLen"    SEP_CHR
              "l7Len"     SEP_CHR
#if BS_MOD > 1
              "pktLenMod" SEP_CHR
#endif // BS_MOD > 1
              "padLen"    SEP_CHR
              , sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    char desc[47], name[20];
    const int layer = ((PACKETLENGTH > 2) ? 7 : (PACKETLENGTH+2));  // 2,3,4,7

    BV_APPEND_U64(bv, "pktsSnt", "Number of transmitted packets");

#if BS_REV_CNT == 1
    BV_APPEND_U64(bv, "pktsRcvd", "Number of received packets");
#endif // BS_REV_CNT == 1

#if BS_AGGR_CNT == 1
    BV_APPEND_U64(bv, "pktsRTAggr", "Number of received + transmitted packets");
#endif // BS_AGGR_CNT == 1

#if BS_PAD == 1
    BV_APPEND_I64(bv, "padBytesSnt", "Number of transmitted padding bytes");
#endif // BS_PAD == 1

    // l2BytesSnt/l3BytesSnt/l4BytesSnt/l7BytesSnt
    sprintf(desc, "Number of transmitted layer %d bytes", layer);
    sprintf(name, "l%dBytesSnt", layer);
    BV_APPEND_U64(bv, name, desc);

#if BS_REV_CNT == 1
    // l2BytesRcvd/l3BytesRcvd/l4BytesRcvd/l7BytesRcvd
    sprintf(desc, "Number of received layer %d bytes", layer);
    sprintf(name, "l%dBytesRcvd", layer);
    BV_APPEND_U64(bv, name, desc);
#endif // BS_REV_CNT == 1

#if BS_AGGR_CNT == 1
    // l2BytesRTAggr/l3BytesRTAggr/l4BytesRTAggr/l7BytesRTAggr
    sprintf(desc, "Number of received + transmitted layer %d bytes", layer);
    sprintf(name, "l%dBytesRTAggr", layer);
    BV_APPEND_U64(bv, name, desc);
#endif // BS_AGGR_CNT == 1

#if BS_STATS == 1

#if BS_PL_STATS == 1
    // minL2PktsSz/minL3PktsSz/minL4PktsSz/minL7PktsSz
    sprintf(desc, "Minimum layer %d packet size", layer);
    sprintf(name, "minL%dPktSz", layer);
    BV_APPEND_U16(bv, name, desc);

    // maxL2PktsSz/maxL3PktsSz/maxL4PktsSz/maxL7PktsSz
    sprintf(desc, "Maximum layer %d packet size", layer);
    sprintf(name, "maxL%dPktSz", layer);
    BV_APPEND_U16(bv, name, desc);

    // avgL2PktsSz/avgL3PktsSz/avgL4PktsSz/avgL7PktsSz
    sprintf(desc, "Average layer %d packet size", layer);
    sprintf(name, "avgL%dPktSz", layer);
    BV_APPEND_FLT(bv, name, desc);

#if BS_STDDEV == 1
    // stdL2PktsSz/stdL3PktsSz/stdL4PktsSz/stdL7PktsSz
    sprintf(desc, "Standard deviation layer %d packet size", layer);
    sprintf(name, "stdL%dPktSz", layer);
    BV_APPEND_FLT(bv, name, desc);
#endif // BS_STDDEV == 1

#if BS_VAR == 1
    // varL2PktsSz/varL3PktsSz/varL4PktsSz/varL7PktsSz
    sprintf(desc, "Variance layer %d packet size", layer);
    sprintf(name, "varL%dPktSz", layer);
    BV_APPEND_FLT(bv, name, desc);

#if BS_SK == 1
    // skewL2PktsSz/skewL3PktsSz/skewL4PktsSz/skewL7PktsSz
    sprintf(desc, "Skewness layer %d packet size", layer);
    sprintf(name, "skewL%dPktSz", layer);
    BV_APPEND_FLT(bv, name, desc);

    // kurL2PktsSz/kurL3PktsSz/kurL4PktsSz/kurL7PktsSz
    sprintf(desc, "Kurtosis layer %d packet size", layer);
    sprintf(name, "kurL%dPktSz", layer);
    BV_APPEND_FLT(bv, name, desc);
#endif // BS_SK == 1
#endif // BS_VAR == 1
#endif // BS_PL_STATS == 1

#if BS_IAT_STATS == 1
    BV_APPEND_FLT(bv, "minIAT", "Minimum IAT");
    BV_APPEND_FLT(bv, "maxIAT", "Maximum IAT");
    BV_APPEND_FLT(bv, "avgIAT", "Average IAT");

#if BS_STDDEV == 1
    BV_APPEND_FLT(bv, "stdIAT", "Standard deviation IAT");
#endif // BS_STDDEV == 1

#if BS_VAR == 1
    BV_APPEND_FLT(bv, "varIAT", "Variance IAT");

#if BS_SK == 1
    BV_APPEND_FLT(bv, "skewIAT", "Skewness IAT");
    BV_APPEND_FLT(bv, "kurIAT" , "Kurtosis IAT");
#endif // BS_SK == 1
#endif // BS_VAR == 1
#endif // BS_IAT_STATS == 1

    BV_APPEND_FLT(bv, "pktps" , "Sent packets per second");
    BV_APPEND_FLT(bv, "bytps" , "Sent bytes per second");
    BV_APPEND_FLT(bv, "pktAsm", "Packet stream asymmetry");
    BV_APPEND_FLT(bv, "bytAsm", "Byte stream asymmetry");
#endif // BS_STATS == 1

    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    bSFlow_t * const bSFlowP = &bSFlow[flowIndex];
    memset(bSFlowP, '\0', sizeof(bSFlow_t));

#if BS_STATS == 1
    // init variables that record a minimum
    bSFlowP->minPktSz = UINT16_MAX;
    bSFlowP->minIAT = 4.0e12;
    bSFlowP->lst = flows[flowIndex].lastSeen;
#if BS_MOD > 1
    bSFlowP->avgPktSz = packet->len % BS_MOD; // depends on frag and PACKETLENGTH status
#else // BS_MOD <= 1
    bSFlowP->avgPktSz = packet->len; // depends on frag and PACKETLENGTH status
#endif // BS_MOD
#endif // BS_STATS == 1
}


static inline void bl_claimInfo(packet_t *packet, unsigned long flowIndex) {
    bSFlow_t * const bSFlowP = &bSFlow[flowIndex];
#if BS_MOD > 1
    const uint16_t pktLen = packet->len % BS_MOD; // depends on frag and PACKETLENGTH status
#else // BS_MOD <= 1
    const uint16_t pktLen = packet->len; // depends on frag and PACKETLENGTH status
#endif // BS_MOD

    // update basic statistics
    bSFlowP->numTPkts++; // depends on frag status
    bSFlowP->numTBytes += pktLen;

#if BS_STATS == 1

#if BS_XCLD > 0

#if BS_XCLD == 1
    if (pktLen > bsXMin) {
#elif BS_XCLD == 2
    if (pktLen < bsXMax) {
#elif BS_XCLD == 3
    if (pktLen >= bsXMin && pktLen <= bsXMax) {
#else // BS_XCLD == 4
    if (pktLen < bsXMin && pktLen > bsXMax) {
#endif // BS_XCLD == 4
        bSFlowP->numTPkts0++; // depends on frag

#endif // BS_XCLD > 0

#if BS_PL_STATS == 1
        bSFlowP->minPktSz = MIN(pktLen, bSFlowP->minPktSz);
        bSFlowP->maxPktSz = MAX(pktLen, bSFlowP->maxPktSz);
#endif // BS_PL_STATS == 1

#if BS_IAT_STATS == 1
        flow_t * const flowP = &flows[flowIndex];
        const float iat = (float)((uint32_t)flowP->lastSeen.tv_sec - (uint32_t)bSFlowP->lst.tv_sec) + (float)(flowP->lastSeen.tv_usec - bSFlowP->lst.tv_usec) / TSTAMPFAC;
        bSFlowP->minIAT = MIN(iat, bSFlowP->minIAT);
        bSFlowP->maxIAT = MAX(iat, bSFlowP->maxIAT);
        bSFlowP->lst = flowP->lastSeen;
#endif // BS_IAT_STATS == 1

#if BS_VARSTD > 0 && (BS_PL_STATS == 1 || BS_IAT_STATS == 1)
        // estimate <> <<> >
#if BS_XCLD > 0
        const float div = (bSFlowP->numTPkts0) ? (float)bSFlowP->numTPkts0 : 1.0;
#else // BS_XCLD == 0
        const float div = (bSFlowP->numTPkts) ? (float)bSFlowP->numTPkts : 1.0;
#endif // BS_XCLD

        float m;

#if BS_PL_STATS == 1
        m = pktLen - bSFlowP->avgPktSz;
        bSFlowP->avgPktSz += m / div;
        const float mmp = m * m;
        bSFlowP->varPktSz += (mmp - bSFlowP->varPktSz) / div;
#if BS_SK == 1
        bSFlowP->skewPktSz += (mmp * m - bSFlowP->skewPktSz) / div;
        bSFlowP->kurPktSz += (mmp * mmp - bSFlowP->kurPktSz) / div;
#endif // BS_SK == 1
#endif // BS_PL_STATS == 1

#if BS_IAT_STATS == 1
        m = iat - bSFlowP->avgIAT;
        bSFlowP->avgIAT += m / div;
        const float mmi = m * m;
        bSFlowP->varIAT += (mmi - bSFlowP->varIAT) / div;
#if BS_SK == 1
        bSFlowP->skewIAT += (mmi * m - bSFlowP->skewIAT) / div;
        bSFlowP->kurIAT += (mmi * mmi - bSFlowP->kurIAT) / div;
#endif // BS_SK == 1
#endif // BS_IAT_STATS == 1

#endif // BS_VARSTD > 0 && (BS_PL_STATS == 1 || BS_IAT_STATS == 1)

#if BS_XCLD > 0
    }
#endif // BS_XCLD > 0
#endif // BS_STATS == 1

#if FORCE_MODE == 1
    if (UNLIKELY(UINT64_MAX - bSFlowP->numTBytes < pktLen || bSFlowP->numTPkts >= UINT64_MAX)) {
        flow_t * const flowP = &flows[flowIndex];
        T2_RM_FLOW(flowP);
    }
#endif // FORCE_MODE == 1

    if (sPktFile) {
        uint16_t udpLen = 0;
        const uint_fast8_t l4Proto = L4_PROTO(packet);
        if (l4Proto == L3_UDP || l4Proto == L3_UDPLITE) {
             if (t2_is_first_fragment(packet)) udpLen = ntohs(UDP_HEADER(packet)->len);
        }

        fprintf(sPktFile,
                "%" PRIu32 /* pktLen    */ SEP_CHR
                "%" PRIu16 /* snapL3Len */ SEP_CHR
                "%" PRIu16 /* snapL4Len */ SEP_CHR
                "%" PRIu16 /* snapL7Len */ SEP_CHR
                "%" PRIu16 /* l3Len     */ SEP_CHR
                "%" PRIu16 /* udpLen    */ SEP_CHR
                "%" PRIu16 /* l7Len     */ SEP_CHR
#if BS_MOD > 1
                "%" PRIu16 /* pktLenMod */ SEP_CHR
#endif // BS_MOD > 1
                "%" PRId64 /* padLen    */ SEP_CHR
                , packet->rawLen
                , packet->snapL3Len
                , packet->snapL4Len
                , packet->snapL7Len
                , packet->l3Len
                , udpLen
                , packet->l7Len
#if BS_MOD > 1
                , pktLen
#endif // BS_MOD > 1
                , packet->padLen
        );
    }
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    bl_claimInfo(packet, flowIndex);
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    bl_claimInfo(packet, flowIndex);
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const flow_t * const flowP = &flows[flowIndex];
    const bSFlow_t * const bSFlowP = &bSFlow[flowIndex];

#if (BS_STATS == 1 || BS_REV_CNT == 1 || BS_AGGR_CNT == 1)

#if ESOM_DEP == 0
    uint64_t oNumPkts, oNumBytes;
#endif // ESOM_DEP == 0

    // get info from opposite flow
#if BS_STATS == 1
    float dir = 1.0;
#endif
    if (FLOW_HAS_OPPOSITE(flowP)) {
        oNumPkts = bSFlow[flowP->oppositeFlowIndex].numTPkts;
        oNumBytes = bSFlow[flowP->oppositeFlowIndex].numTBytes;
    } else {
        oNumPkts = 0;
        oNumBytes = 0;
#if BS_STATS == 1
        if (FLOW_IS_B(flowP)) dir = -1.0;
#endif
    }
#endif // (BS_STATS == 1 || BS_REV_CNT == 1 || BS_AGGR_CNT == 1)

#if BS_STATS == 1

#if ESOM_DEP == 0
    float packet_sym_ratio, byte_sym_ratio;
    float packetsPerSec, bytesPerSec;
#endif // ESOM_DEP == 0

    // packets/bytes per second
    if (flowP->duration.tv_sec != 0 || flowP->duration.tv_usec != 0) {
        const float duration = (float)((uint32_t)flowP->duration.tv_sec + flowP->duration.tv_usec / TSTAMPFAC);
        packetsPerSec = bSFlowP->numTPkts / duration;
        bytesPerSec = bSFlowP->numTBytes / duration;
    } else {
        packetsPerSec = 0.0f;
        bytesPerSec = 0.0f;
    }

    if (bytesPerSec > mxBytsps) {
        mxBytsps = bytesPerSec;
        mxPkts = bSFlowP->numTPkts;
    }

    // asymmetry of packets sent and received
    if (oNumPkts > 0 || bSFlowP->numTPkts > 0) {
        packet_sym_ratio = dir * ((float)bSFlowP->numTPkts - (float)oNumPkts) / (float)(bSFlowP->numTPkts + oNumPkts);
    } else {
        packet_sym_ratio = 0.0f;
    }

    // asymmetry of bytes sent and received
    if (oNumBytes > 0 || bSFlowP->numTBytes > 0) {
        byte_sym_ratio = ((float)bSFlowP->numTBytes - (float)oNumBytes) / (float)(bSFlowP->numTBytes + oNumBytes);
    } else {
        byte_sym_ratio = 0.0f;
    }

#endif // BS_STATS == 1

    OUTBUF_APPEND_U64(buf, bSFlowP->numTPkts); // pktsSnt

#if BS_REV_CNT == 1
    OUTBUF_APPEND_U64(buf, oNumPkts);          // pktsRcvd
#endif // BS_REV_CNT == 1

#if BS_AGGR_CNT == 1
    // pktsRTAggr
#if ESOM_DEP == 0
    uint64_t aggPkts;
#endif // ESOM_DEP == 0
    aggPkts = bSFlowP->numTPkts + oNumPkts;
    OUTBUF_APPEND_U64(buf, aggPkts);
#endif // BS_AGGR_CNT == 1

#if BS_PAD == 1
    OUTBUF_APPEND_I64(buf, flowP->padLen);  // padBytesSnt
#endif // BS_PAD == 1

    // l2BytesSnt/l3BytesSnt/l4BytesSnt/l7BytesSnt
    OUTBUF_APPEND_U64(buf, bSFlowP->numTBytes);

#if BS_REV_CNT == 1
    // l2BytesRcvd/l3BytesRcvd/l4BytesRcvd/l7BytesRcvd
    OUTBUF_APPEND_U64(buf, oNumBytes);
#endif // BS_REV_CNT == 1

#if BS_AGGR_CNT == 1
    // l2BytesRTAggr/l3BytesRTAggr/l4BytesRTAggr/l7BytesRTAggr
#if ESOM_DEP == 0
    uint64_t aggBytes;
#endif // ESOM_DEP == 0
    aggBytes = bSFlowP->numTBytes + oNumBytes;
    OUTBUF_APPEND_U64(buf, aggBytes);
#endif // BS_AGGR_CNT == 1

#if BS_STATS == 1

#if BS_STDDEV == 1 && (BS_PL_STATS == 1 || BS_IAT_STATS == 1)
    float stddev;
#endif

#if BS_PL_STATS == 1
    // minL2PktsSz/minL3PktsSz/minL4PktsSz/minL7PktsSz
    OUTBUF_APPEND_U16(buf, bSFlowP->minPktSz);

    // maxL2PktsSz/maxL3PktsSz/maxL4PktsSz/maxL7PktsSz
    OUTBUF_APPEND_U16(buf, bSFlowP->maxPktSz);

    // avgL2PktsSz/avgL3PktsSz/avgL4PktsSz/avgL7PktsSz
#if ESOM_DEP == 0
    float avgPktSize;
#endif // ESOM_DEP == 0
#if BS_XCLD > 0
    avgPktSize = (bSFlowP->numTPkts0) ? bSFlowP->numTBytes / (float)bSFlowP->numTPkts0 : 0;
#else // BS_XCLD == 0
    avgPktSize = (bSFlowP->numTPkts) ? bSFlowP->numTBytes / (float)bSFlowP->numTPkts : 0;
#endif // BS_XCLD > 0
    if (avgPktSize > mxByts) mxByts = avgPktSize;
    OUTBUF_APPEND_FLT(buf, avgPktSize);

#if BS_STDDEV == 1
    // stdL2PktsSz/stdL3PktsSz/stdL4PktsSz/stdL7PktsSz
    stddev = sqrt(bSFlowP->varPktSz);
    OUTBUF_APPEND_FLT(buf, stddev);
#endif // BS_STDDEV == 1

#if BS_VAR == 1
    // varL2PktsSz/varL3PktsSz/varL4PktsSz/varL7PktsSz
    OUTBUF_APPEND_FLT(buf, bSFlowP->varPktSz);

#if BS_SK == 1
    // skewL2PktsSz/skewL3PktsSz/skewL4PktsSz/skewL7PktsSz
    float skpp = (bSFlowP->varPktSz) ? bSFlowP->skewPktSz / (bSFlowP->varPktSz * sqrt(bSFlowP->varPktSz)) : 0;
    OUTBUF_APPEND_FLT(buf, skpp);

    // kurL2PktsSz/kurL3PktsSz/kurL4PktsSz/kurL7PktsSz
    skpp = (bSFlowP->varPktSz) ? bSFlowP->kurPktSz / (bSFlowP->varPktSz * bSFlowP->varPktSz) : 0;
    OUTBUF_APPEND_FLT(buf, skpp);
#endif // BS_SK == 1
#endif // BS_VAR == 1


#endif // BS_PL_STATS == 1

#if BS_IAT_STATS == 1
    OUTBUF_APPEND_FLT(buf, bSFlowP->minIAT);  // minIAT
    OUTBUF_APPEND_FLT(buf, bSFlowP->maxIAT);  // maxIAT
    OUTBUF_APPEND_FLT(buf, bSFlowP->avgIAT);  // avgIAT

#if BS_STDDEV == 1
    // stdIAT
    stddev = sqrt(bSFlowP->varIAT);
    OUTBUF_APPEND_FLT(buf, stddev);
#endif // BS_STDDEV == 1

#if BS_VAR == 1
    OUTBUF_APPEND_FLT(buf, bSFlowP->varIAT);  // varIAT

#if BS_SK == 1
    // skewIAT
    float skpi = (bSFlowP->varIAT) ? bSFlowP->skewIAT / (bSFlowP->varIAT * sqrt(bSFlowP->varIAT)) : 0;
    OUTBUF_APPEND_FLT(buf, skpi);

    // kurIAT
    skpi = (bSFlowP->varIAT) ? bSFlowP->kurIAT / (bSFlowP->varIAT * bSFlowP->varIAT) : 0;
    OUTBUF_APPEND_FLT(buf, skpi);
#endif // BS_SK == 1
#endif // BS_VAR == 1


#endif // BS_IAT_STATS == 1

    OUTBUF_APPEND_FLT(buf, packetsPerSec);    // pktps
    OUTBUF_APPEND_FLT(buf, bytesPerSec);      // bytps
    OUTBUF_APPEND_FLT(buf, packet_sym_ratio); // pktAsm
    OUTBUF_APPEND_FLT(buf, byte_sym_ratio);   // bytAsm
#endif // BS_STATS == 1

#if LAPD_ACTIVATE == 1
    if (FLOW_IS_LAPD(flowP)) return;
#endif

    if (FLOW_IS_L2(flowP)) {
#if ETH_ACTIVATE > 0
        if (bSFlowP->numTPkts > macBPktsTalker.count) {
            macBPktsTalker.count = bSFlowP->numTPkts;
            memcpy(macBPktsTalker.addr, flowP->ethDS.ether_shost, ETH_ALEN);
        }

        if (bSFlowP->numTBytes > macBByteTalker.count) {
            macBByteTalker.count = bSFlowP->numTBytes;
            memcpy(macBByteTalker.addr, flowP->ethDS.ether_shost, ETH_ALEN);
        }
#endif // ETH_ACTIVATE > 0
    } else {
        const uint_fast8_t ipver = FLOW_IPVER(flowP);

        if (bSFlowP->numTPkts > ipBPktsTalker.count) {
            ipBPktsTalker.count = bSFlowP->numTPkts;
            ipBPktsTalker.addr  = flowP->srcIP;
            ipBPktsTalker.ipver = ipver;
#if SUBNET_INIT != 0
            ipBPktsTalker.subnet = flowP->subnetNrSrc;
#endif // SUBNET_INIT != 0
        }

        if (bSFlowP->numTBytes > ipBByteTalker.count) {
            ipBByteTalker.count = bSFlowP->numTBytes;
            ipBByteTalker.addr  = flowP->srcIP;
            ipBByteTalker.ipver = ipver;
#if SUBNET_INIT != 0
            ipBByteTalker.subnet = flowP->subnetNrSrc;
#endif // SUBNET_INIT != 0
        }
    }
}


#if ANONYM_IP == 0 && SUBNET_INIT != 0
#define BS_FORMAT_LOC(loc) \
    if ((loc)[0] == '-' || isdigit((loc)[0])) { \
        loc = ""; \
    } else { \
        loc_str[2] = toupper((loc)[0]); \
        loc_str[3] = toupper((loc)[1]); \
        loc = loc_str; \
    }
#endif // ANONYM_IP == 0 && SUBNET_INIT != 0


#if ETH_ACTIVATE > 0 || ANONYM_IP == 0

static inline void bs_pluginReport(FILE *stream) {
    char str[64];
    const uint64_t numBytes = numABytes + numBBytes;

#if BS_STATS == 1
    char str1[64];
    const uint64_t mxb = mxBytsps * 8;
    T2_CONV_NUM(mxByts, str);
    T2_FPLOG(stream, plugin_name, "Flow max(pktload): %" PRIu64 "%s", mxByts, str);
    T2_CONV_NUM_SFX(mxb, str, "b/s");
    T2_CONV_NUM(mxPkts, str1);
    T2_FPLOG(stream, plugin_name, "Flow max(b/s), pkts: %" PRIu64 "%s, %" PRIu64 "%s", mxb, str, mxPkts, str1);
#endif // BS_STATS == 1

#if ETH_ACTIVATE > 0
    if (macBPktsTalker.count) {
        char mac[T2_MAC_STRLEN+1] = {};
        t2_mac_to_str(macBPktsTalker.addr, mac, sizeof(mac));
        T2_CONV_NUM(macBPktsTalker.count, str);
        T2_FPLOG(stream, plugin_name,
                 "Biggest L2 flow talker: %s: %" PRIu64 "%s [%.2f%%] packets",
                 mac, macBPktsTalker.count, str, 100.0*macBPktsTalker.count/numPackets);

        t2_mac_to_str(macBByteTalker.addr, mac, sizeof(mac));
        T2_CONV_NUM(macBByteTalker.count, str);
        T2_FPLOG(stream, plugin_name,
                 "Biggest L2 flow talker: %s: %" PRIu64 "%s [%.2f%%] bytes",
                 mac, macBByteTalker.count, str, 100.0*macBByteTalker.count/numBytes);
    }
#endif // ETH_ACTIVATE > 0

#if ANONYM_IP == 0
    char *loc = "";
#if SUBNET_INIT != 0
    char loc_str[] = " (XX)"; // XX will be replaced by the country code
#endif // SUBNET_INIT != 0

    if (ipBPktsTalker.count) {
#if (AGGREGATIONFLAG & SUBNET) != 0
        static const char * const ipstr = "N/A";
#else // (AGGREGATIONFLAG & SUBNET == 0)
        char ipstr[INET6_ADDRSTRLEN];
        T2_IP_TO_STR(ipBPktsTalker.addr, ipBPktsTalker.ipver, ipstr, sizeof(ipstr));
#endif // (AGGREGATIONFLAG & SUBNET)
        T2_CONV_NUM(ipBPktsTalker.count, str);
#if SUBNET_INIT != 0
        SUBNET_LOC(loc, ipBPktsTalker.ipver, ipBPktsTalker.subnet);
        BS_FORMAT_LOC(loc);
#endif // SUBNET_INIT != 0
        T2_FPLOG(stream, plugin_name,
                 "Biggest L3 flow talker: %s%s: %" PRIu64 "%s [%.2f%%] packets",
                 ipstr, loc, ipBPktsTalker.count, str, 100.0*ipBPktsTalker.count/numPackets);

#if (AGGREGATIONFLAG & SUBNET) == 0
        T2_IP_TO_STR(ipBByteTalker.addr, ipBByteTalker.ipver, ipstr, sizeof(ipstr));
#endif // (AGGREGATIONFLAG & SUBNET)
        T2_CONV_NUM(ipBByteTalker.count, str);
#if SUBNET_INIT != 0
        SUBNET_LOC(loc, ipBByteTalker.ipver, ipBByteTalker.subnet);
        BS_FORMAT_LOC(loc);
#endif // SUBNET_INIT != 0
        T2_FPLOG(stream, plugin_name,
                 "Biggest L3 flow talker: %s%s: %" PRIu64 "%s [%.2f%%] bytes",
                 ipstr, loc, ipBByteTalker.count, str, 100.0*ipBByteTalker.count/numBytes);
    }
#endif // ANONYM_IP == 0
}


void t2PluginReport(FILE *stream) {
    bs_pluginReport(stream);
}


void t2Monitoring(FILE *stream, uint8_t state) {
    switch (state) {
        case T2_MON_PRI_HDR:
            break;
        case T2_MON_PRI_REPORT:
            bs_pluginReport(stream);
            break;
        case T2_MON_PRI_VAL:
            break;
        default:
            return;

    }
}

#endif // ETH_ACTIVATE > 0 || ANONYM_IP == 0


void t2Finalize() {
    free(bSFlow);
}
