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

#include "nFrstPkts.h"


nFrstPkts_t *nFrstPkts;


// Tranalyzer Plugin functions

T2_PLUGIN_INIT("nFrstPkts", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(nFrstPkts);
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_U32(bv, "nFpCnt", "Number of signal samples");

#if NFRST_HDRINFO == 1
#if (NFRST_MINIAT > 0)
    BV_APPEND_R(bv, "HD3l_HD4l_L2L3L4Pl_Iat_nP",
            "L3 and L4 header length, L2/L3/L4/Payload (s. PACKETLENGTH in packetCapture.h) length, IAT and pulse for the N first packets",
            5, bt_uint_8, bt_uint_8, bt_uint_32, bt_duration, bt_duration);
#else // !(NFRST_MINIAT > 0)
    BV_APPEND_R(bv, "HD3l_HD4l_L2L3L4Pl_Iat",
            "L3 and L4 header length, L2/L3/L4/Payload (s. PACKETLENGTH in packetCapture.h) length and IAT for the N first packets",
            4, bt_uint_8, bt_uint_8, bt_uint_32, bt_duration);
#endif // (NFRST_MINIAT > 0)
#else // NFRST_HDRINFO == 0
#if (NFRST_MINIAT > 0)
    BV_APPEND_R(bv, "L2L3L4Pl_Iat_nP",
            "L2/L3/L4/Payload (s. PACKETLENGTH in packetCapture.h) length, IAT and pulse for the N first packets",
            3, bt_uint_32, bt_duration, bt_duration);
#else // !(NFRST_MINIAT > 0)
    BV_APPEND_R(bv, "L2L3L4Pl_Iat",
            "L2/L3/L4/Payload (s. PACKETLENGTH in packetCapture.h) length and IAT for the N first packets",
            2, bt_uint_32, bt_duration);
#endif // (NFRST_MINIAT > 0)
#endif // NFRST_HDRINFO

    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    nFrstPkts_t * const nFpP = &nFrstPkts[flowIndex];
    memset(nFpP, '\0', sizeof(*nFpP));
    const flow_t * const flowP = &flows[flowIndex];
    nFpP->lstPktTm0 = nFpP->lstPktTm = flowP->firstSeen;
#if (NFRST_IAT == 0 && NFRST_BCORR > 0)
    if (FLOW_IS_B(flowP)) {
        // local variables are required as the flow_t structure is packed
        // (see clang -Waddress-of-packed-member option)
        const struct timeval firstSeenB = flowP->firstSeen;
        const struct timeval firstSeenA = flows[flowP->oppositeFlowIndex].firstSeen;
        T2_TIMERSUB(&firstSeenB, &firstSeenA, &nFpP->tdiff);
    }
#endif
}


static inline void nfp_claimInfo(packet_t *packet, unsigned long flowIndex) {
    nFrstPkts_t * const nFpP = &nFrstPkts[flowIndex];

#if (NFRST_BCORR > 0 && NFRST_IAT == 0)
    const flow_t * const flowP = &flows[flowIndex];
#endif // (NFRST_BCORR > 0 && NFRST_IAT == 0)

#if NFRST_MINIAT > 0
uu:;
#endif // NFRST_MINIAT > 0
    const uint32_t ipC = nFpP->pktCnt;
    if (ipC >= NFRST_PKTCNT) return;
    pkt_t *pP = &nFpP->pkt[ipC];

#if NFRST_HDRINFO == 1
    pP->l3HDLen = packet->l3HdrLen;
    pP->l4HDLen = packet->l4HdrLen;
#endif // NFRST_HDRINFO == 1

#if NFRST_MINIAT > 0
    struct timeval iat;
    T2_TIMERSUB(&packet->pcapHdrP->ts, &nFpP->lstPktTm, &iat);
    if (!nFpP->puls || (iat.tv_sec < NFRST_MINIATS || (iat.tv_sec == NFRST_MINIATS && iat.tv_usec < NFRST_MINIATU))) {
        nFpP->lstPktTm = packet->pcapHdrP->ts;
#if NFRST_IAT == 1
        T2_TIMERADD(&nFpP->lstPktiat, &iat , &nFpP->lstPktiat);
#endif // NFRST_IAT == 1
        if (!nFpP->puls) {
            if (!packet->len) return;
	    nFpP->lstPktPTm = nFpP->lstPktTm;
	}
#if (NFRST_XMIN > 0 || NFRST_XMAX < UINT16_MAX)
        if (
#if NFRST_XMIN > 0
            packet->len >= NFRST_XMIN &&
#endif // NFRST_XMIN > 0
            packet->len <= NFRST_XMAX
        )
#endif // (NFRST_XMIN > 0 || NFRST_XMAX < UINT16_MAX)
            pP->pktLen += packet->len;

        nFpP->puls++;
        return;
    } else {
        static const struct timeval pulse = {NFRST_NINPLSS, NFRST_NINPLSU};
#if NFRST_PLAVE == 1
        pP->pktLen /= nFpP->puls;
#endif // NFRST_PLAVE == 1
        T2_TIMERSUB(&nFpP->lstPktTm, &nFpP->lstPktPTm, &pP->piat);
        if (nFpP->puls == 1) T2_TIMERADD(&pP->piat, &pulse, &pP->piat);
#if NFRST_IAT == 2
        pP->iat = nFpP->lstPktPTm;
#elif NFRST_IAT == 1
        pP->iat = nFpP->lstPktiat;
	nFpP->lstPktiat = iat;
#else // NFRST_IAT == 0
        T2_TIMERSUB(&nFpP->lstPktPTm, &nFpP->lstPktTm0, &pP->iat);
#if NFRST_BCORR > 0
        if (FLOW_IS_B(flowP)) T2_TIMERADD(&pP->iat, &nFpP->tdiff, &pP->iat);
#endif // NFRST_BCORR > 0
#endif // NFRST_IAT
        nFpP->lstPktTm = packet->pcapHdrP->ts;
        nFpP->puls = 0;
        nFpP->pktCnt++;
        goto uu;
    }

#else // NFRST_MINIAT == 0
#if NFRST_IAT == 2
    pP->iat = packet->pcapHdrP->ts;
#elif NFRST_IAT == 1
    T2_TIMERSUB(&packet->pcapHdrP->ts, &nFpP->lstPktTm, &pP->iat);
    nFpP->lstPktTm = packet->pcapHdrP->ts;
#else // NFRST_IAT == 0
    T2_TIMERSUB(&packet->pcapHdrP->ts, &nFpP->lstPktTm, &pP->iat);
#if NFRST_BCORR > 0
    if (FLOW_IS_B(flowP)) T2_TIMERADD(&pP->iat, &nFpP->tdiff, &pP->iat);
#endif // NFRST_BCORR > 0
#endif // NFRST_IAT
    pP->pktLen = packet->len;
    nFpP->pktCnt++;
#endif // NFRST_MINIAT
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND || (packet->status & L2_FLOW) == 0) return;
    nfp_claimInfo(packet, flowIndex);
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    nfp_claimInfo(packet, flowIndex);
}


#if BLOCK_BUF == 0
void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    nFrstPkts_t * const nFpP = &nFrstPkts[flowIndex];

#if NFRST_MINIAT > 0
    if (nFpP->puls) {
        const struct timeval pulse = {NFRST_NINPLSS, NFRST_NINPLSU};
        const uint32_t ipC = nFpP->pktCnt;
        pkt_t * const pP = &nFpP->pkt[ipC];
#if NFRST_PLAVE == 1
        pP->pktLen /= nFpP->puls;
#endif // NFRST_PLAVE == 1
        T2_TIMERSUB(&nFpP->lstPktTm, &nFpP->lstPktPTm, &pP->piat);
        if (nFpP->puls == 1) T2_TIMERADD(&pP->piat, &pulse, &pP->piat);
#if NFRST_IAT == 2
        pP->iat = nFpP->lstPktPTm;
#elif NFRST_IAT == 1
        pP->iat = nFpP->lstPktiat;
#else // NFRST_IAT == 0
        T2_TIMERSUB(&nFpP->lstPktPTm, &nFpP->lstPktTm0, &pP->iat);
#if NFRST_BCORR > 0
        const flow_t * const flowP = &flows[flowIndex];
        if (FLOW_IS_B(flowP)) T2_TIMERADD(&pP->iat, &nFpP->tdiff, &pP->iat);
#endif // NFRST_BCORR > 0
#endif // NFRST_IAT
        nFpP->puls = 0;
        //nFpP->pktCnt++;
    }
#endif // NFRST_MINIAT > 0

    // Number of signal samples
    OUTBUF_APPEND_U32(buf, nFpP->pktCnt); // nFpCnt

    // number of entries, because output is repeatable
    OUTBUF_APPEND_NUMREP(buf, nFpP->pktCnt);

    uint64_t secs;
    uint32_t usecs;
    for (uint_fast32_t i = 0; i < nFpP->pktCnt; i++) {

#if NFRST_HDRINFO == 1
        OUTBUF_APPEND_U8(buf, nFpP->pkt[i].l3HDLen); // HD3l
        OUTBUF_APPEND_U8(buf, nFpP->pkt[i].l4HDLen); // HD4l
#endif // NFRST_HDRINFO == 1

        OUTBUF_APPEND_U32(buf, nFpP->pkt[i].pktLen); // L2L3L4Pl

        // Iat
        secs = (uint32_t)nFpP->pkt[i].iat.tv_sec;
        usecs = nFpP->pkt[i].iat.tv_usec;
        OUTBUF_APPEND_TIME(buf, secs, usecs);

        // nP
#if NFRST_MINIAT > 0
        secs = (uint32_t)nFpP->pkt[i].piat.tv_sec;
        usecs = nFpP->pkt[i].piat.tv_usec;
        OUTBUF_APPEND_TIME(buf, secs, usecs);
#endif // NFRST_MINIAT > 0
    }
}
#endif // BLOCK_BUF == 0


void t2Finalize() {
    free(nFrstPkts);
}
