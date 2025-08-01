/*
 * netflowSink.c
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

#include "basicFlow.h"
#include "basicStats.h"
#include "tcpFlags.h"
#if ETH_ACTIVATE < 2
#include "macRecorder.h"
#endif
#include "netflow9.h"

#include <errno.h>  // for errno
#include <unistd.h> // for close
#include <netdb.h>  // for gethostbyname


// Static variables

static int nfS;
#if NF_SOCKTYPE == 0
static struct sockaddr_in server;
#endif // NF_SOCKTYPE == 0
static uint32_t ipseq;
static int nfFlw4Cnt, nfFlw6Cnt;
//static int nfMFB4Cnt, nfMFBG6Cnt;
static nfBfT_t nfBfT;
static nfBf4_t nfBf4;
static nfBf6_t nfBf6;

#if ENVCNTRL > 0
static char *addr;
static uint16_t port;
#else // ENVCNTRL == 0
static const char * const addr = NF_SERVADD;
static const uint16_t port = NF_DPORT;
#endif // ENVCNTRL == 0


// Static functions

static inline void sendbuf4(int nfFlwCnt);
static inline void sendbuf6(int nfFlwCnt);


// Variables from dependencies

extern bfoFlow_t *bfoFlow __attribute__((weak));
extern bSFlow_t *bSFlow __attribute__((weak));
extern tcpFlagsFlow_t *tcpFlagsFlows __attribute__((weak));


// Variable from optional dependencies

extern macRecorder_t *macArray __attribute__((weak));
macRecorder_t *macArray;


// Tranalyzer functions

T2_PLUGIN_INIT_WITH_DEPS("netflowSink", "0.9.3", 0, 9, "basicFlow,basicStats,tcpFlags");


void t2Init() {
#if ENVCNTRL > 0
    t2_env_t env[ENV_NF_N] = {};
    t2_get_env(PLUGIN_SRCH, ENV_NF_N, env);
    addr = T2_STEAL_ENV_VAL(NF_SERVADD);
    port = T2_ENV_VAL_UINT(NF_DPORT);
    const uint16_t num4Flws = T2_ENV_VAL_UINT(NF_NUM4FLWS);
    const uint16_t num6Flws = T2_ENV_VAL_UINT(NF_NUM6FLWS);
#else // ENVCNTRL == 0
    const uint16_t num4Flws = NF_NUM4FLWS;
    const uint16_t num6Flws = NF_NUM6FLWS;
#endif // ENVCNTRL

#if NF_SOCKTYPE == 1
    nfS = t2_tcp_socket_connect(plugin_name, addr, port, false);
#else // NF_SOCKTYPE == 0
    if (UNLIKELY(!(nfS = socket(AF_INET, SOCK_DGRAM, 0)))) {
        T2_PFATAL(plugin_name, "Failed to create UDP socket: %s", strerror(errno));
    }

    struct hostent *host = gethostbyname(addr);
    server.sin_addr = *(struct in_addr*)host->h_addr;
    server.sin_family = AF_INET;
    server.sin_port = ntohs(port);
#endif // NF_SOCKTYPE == 0

    size_t written = 0, act_written;

    char *nfBP = nfBfT.nfBuff;
    netv9Hdr_t *netv9HP = &nfBfT.nfMsgT.netv9H;
    netv9HP->version = NF9_VER;
    netv9HP->count = 0x0200;
    netv9HP->upTime = 0;
    netv9HP->unixSec = ntohl(startTStamp0.tv_sec);
    netv9HP->ipseq = 0;
    netv9HP->srcID = ntohl(T2_SENSORID);

    nv9T_t *nv9TP = &nfBfT.nfMsgT.nv9T;
    nv9TP->setID4 = FLSID;
    nv9TP->len4 = INV9T4LEN;
    nv9TP->tmpltID4 = TPLIDT4;
    nv9TP->fieldCnt4 = htons(sizeof(nv9Tv4)/4);
    memcpy((char*)nv9TP->nTDef4, (char*)nv9Tv4, sizeof(nv9Tv4));
    nv9TP->setID6 = FLSID;
    nv9TP->len6 = INV9T6LEN;
    nv9TP->tmpltID6 = TPLIDT6;
    nv9TP->fieldCnt6 = htons(sizeof(nv9Tv6)/4);
    memcpy((char*)nv9TP->nTDef6, (char*)nv9Tv6, sizeof(nv9Tv6));

    const size_t bufLen = sizeof(netv9Hdr_t) + sizeof(nv9T_t);

    while (written < bufLen) {
#if NF_SOCKTYPE == 1
        act_written = write(nfS, nfBP + written, bufLen - written);
#else // NF_SOCKTYPE == 0
        act_written = sendto(nfS, nfBP + written, bufLen - written, 0, (struct sockaddr*)&server, sizeof(server));
#endif // NF_SOCKTYPE == 0
        if (UNLIKELY(act_written <= 0)) {
            T2_PFATAL(plugin_name, "Failed to write flow data to %s socket %s:%" PRIu16 ": %s",
                                   ((NF_SOCKTYPE == 1) ? "TCP" : "UDP"), addr, port, strerror(errno));
        }
        written += act_written;
    }

    netv9HP = &nfBf4.nfMsg4.netv9H;
    netv9HP->version = NF9_VER;
    netv9HP->upTime = 0;
    netv9HP->srcID = ntohl(T2_SENSORID);
    netv9HP->unixSec = ntohl(startTStamp0.tv_sec);
    netv9HP->count = 0x0100;
    nfBf4.nfMsg4.flwSet = TPLIDT4;
    if (num4Flws > MAXFB4CNT) T2_PWRN(plugin_name, "Number of IPv4 flows per message too high: was reduced to %d", MAXFB4CNT);
    nfBf4.nfMsg4.len = htons(MSG4LEN);

    netv9HP = &nfBf6.nfMsg6.netv9H;
    netv9HP->version = NF9_VER;
    netv9HP->upTime = 0;
    netv9HP->srcID = ntohl(T2_SENSORID);
    netv9HP->unixSec = ntohl(startTStamp0.tv_sec);
    netv9HP->count = 0x0100;
    nfBf6.nfMsg6.flwSet = TPLIDT6;
    if (num6Flws > MAXFB6CNT) T2_PWRN(plugin_name, "Number of IPv6 flows per message too high: was reduced to %d", MAXFB6CNT);
    nfBf6.nfMsg6.len = htons(MSG6LEN);

#if ENVCNTRL > 0
    t2_free_env(ENV_NF_N, env);
#endif // ENVCNTRL > 0
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf UNUSED) {
    const flow_t * const flowP = &flows[flowIndex];
    const bSFlow_t * const bSFlowP = &bSFlow[flowIndex];
    const tcpFlagsFlow_t * const tcpFlagsP = &tcpFlagsFlows[flowIndex];

#if ETH_ACTIVATE < 2
    macList_t * const macListP = macArray ? macArray[flowIndex].macList : NULL;
#endif // ETH_ACTIVATE < 2

    const uint_fast8_t dir = (flowP->status & L3FLOWINVERT);

    uint32_t flowStart = (flowP->firstSeen.tv_sec - startTStamp0.tv_sec) * 1000 +
                         (flowP->firstSeen.tv_usec - startTStamp0.tv_usec) / (TSTAMPFAC / 1000);
    if (!flowStart) flowStart = 1;

    uint32_t flowEnd = (flowP->lastSeen.tv_sec - startTStamp0.tv_sec) * 1000 +
                       (flowP->lastSeen.tv_usec - startTStamp0.tv_usec) / (TSTAMPFAC / 1000);
    if (!flowEnd) flowEnd = 1;

    if (FLOW_IS_IPV4(flowP)) {
        // Empty the buffer if it is full
        if (nfFlw4Cnt >= NFB4CNTC) {
            sendbuf4(NFB4CNTC);
        }

        nf9Data4_t *nfDP = &nfBf4.nfMsg4.nfD4[nfFlw4Cnt++];
        nfDP->ipVer = 4;
        nfDP->dir = dir;
        nfDP->flowSSec = htonl(flowStart);
        nfDP->flowESec = htonl(flowEnd);
        nfDP->srcIPv4 = flowP->srcIP.IPv4.s_addr;
        nfDP->dstIPv4 = flowP->dstIP.IPv4.s_addr;
        nfDP->srcPort = htons(flowP->srcPort);
        nfDP->dstPort = htons(flowP->dstPort);
        nfDP->srcVlanId = htons(flowP->vlanId);
        nfDP->l4Proto = flowP->l4Proto;
        nfDP->engID = 1;

#if ETH_ACTIVATE > 1
        memcpy(nfDP->dsInMac, flowP->ethDS.ether_dhost, 12);
#else // ETH_ACTIVATE <= 1
        if (macListP) {
            macList_t *tmpList = macListP;
            memcpy(nfDP->dsInMac, tmpList->ethHdr.ether_dhost, 12);
            if ((tmpList = tmpList->next)) memcpy(nfDP->dsOutMac, tmpList->ethHdr.ether_dhost, 12);
            else memset(nfDP->dsOutMac, '\0', 12);
        }
#endif // ETH_ACTIVATE <= 1

        if (bSFlowP) {
            nfDP->pktCnt = htobe64(bSFlowP->numTPkts);
            nfDP->byteCnt = htobe64(bSFlowP->numTBytes);
            nfDP->minL3Len = htons(bSFlowP->minPktSz);
            nfDP->maxL3Len = htons(bSFlowP->maxPktSz);
        }

        if (tcpFlagsP) {
            nfDP->tcpFlags = tcpFlagsP->tcpFlagsT;
            nfDP->ipToS = tcpFlagsP->ipTosT;
            nfDP->minTTL = tcpFlagsP->ipMinTTLT;
            nfDP->maxTTL = tcpFlagsP->ipMaxTTLT;
        }

#if (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
        const bfoFlow_t * const bfoFlowP = &bfoFlow[flowIndex];
        if (bfoFlowP) {
            const uint_fast32_t num_mpls = bfoFlowP->num_mpls;
            for (uint_fast32_t i = 0, j = 0; i < num_mpls; i++, j += 3) {
                const uint32_t mpls = htonl(bfoFlowP->mplsHdr[i]);
                memcpy(&nfDP->nfMpls[j], (char*)&mpls, 3);
            }
        }
#endif // (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
    } else if (FLOW_IS_IPV6(flowP)) {
        // Empty the buffer if it is full
        if (nfFlw6Cnt >= NFB6CNTC) {
            sendbuf6(NFB6CNTC);
        }

        nf9Data6_t *nfDP = &nfBf6.nfMsg6.nfD6[nfFlw6Cnt++];
        nfDP->ipVer = 6;
        nfDP->dir = dir;
        nfDP->flowSSec = htonl(flowStart);
        nfDP->flowESec = htonl(flowEnd);
#if IPV6_ACTIVATE > 0
        nfDP->srcIP = flowP->srcIP;
        nfDP->dstIP = flowP->dstIP;
#endif // IPV6_ACTIVATE > 0
        nfDP->srcPort = htons(flowP->srcPort);
        nfDP->dstPort = htons(flowP->dstPort);
        nfDP->srcVlanId = htons(flowP->vlanId);
        nfDP->l4Proto = flowP->l4Proto;
        nfDP->engID = 1;

#if ETH_ACTIVATE > 1
        memcpy(nfDP->dsInMac, flowP->ethDS.ether_dhost, 12);
#else // ETH_ACTIVATE <= 1
        if (macListP) {
            macList_t *tmpList = macListP;
            memcpy(nfDP->dsInMac, tmpList->ethHdr.ether_dhost, 12);
            if ((tmpList = tmpList->next)) memcpy(nfDP->dsOutMac, tmpList->ethHdr.ether_dhost, 12);
            else memset(nfDP->dsOutMac, '\0', 12);
        }
#endif // ETH_ACTIVATE <= 1

        if (bSFlowP) {
            nfDP->pktCnt = htobe64(bSFlowP->numTPkts);
            nfDP->byteCnt = htobe64(bSFlowP->numTBytes);
            nfDP->minL3Len = htons(bSFlowP->minPktSz);
            nfDP->maxL3Len = htons(bSFlowP->maxPktSz);
        }

        if (tcpFlagsP) {
            nfDP->tcpFlags = tcpFlagsP->tcpFlagsT;
            nfDP->ipToS = tcpFlagsP->ipTosT;
            nfDP->minTTL = tcpFlagsP->ipMinTTLT;
            nfDP->maxTTL = tcpFlagsP->ipMaxTTLT;
        }

#if (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
        const bfoFlow_t * const bfoFlowP = &bfoFlow[flowIndex];
        if (bfoFlowP) {
            const uint_fast32_t num_mpls = bfoFlowP->num_mpls;
            for (uint_fast32_t i = 0, j = 0; i < num_mpls; i++, j += 3) {
                const uint32_t mpls = htonl(bfoFlowP->mplsHdr[i]);
                memcpy(&nfDP->nfMpls[j], (char*)&mpls, 3);
            }
        }
#endif // (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
    }
}


void t2Finalize() {
    if (nfFlw4Cnt) {
        nfBf4.nfMsg4.len = htons(sizeof(nf9Data4_t)*nfFlw4Cnt + 4 + NFDPAD4);
        sendbuf4(nfFlw4Cnt);
    }

    if (nfFlw6Cnt) {
        nfBf6.nfMsg6.len = htons(sizeof(nf9Data6_t)*nfFlw6Cnt + 4 + NFDPAD6);
        sendbuf6(nfFlw6Cnt);
    }

    if (LIKELY(nfS)) close(nfS);

#if ENVCNTRL > 0
    free(addr);
#endif // ENVCNTRL > 0
}


static inline void sendbuf4(int nfFlwCnt) {
    size_t written = 0, act_written;
    const size_t bufLen = sizeof(netv9Hdr_t) + sizeof(nf9Data4_t)*nfFlwCnt + 4 + NFDPAD4;
    const char * const nfBP = nfBf4.nfBuff;
    netv9Hdr_t * const netv9HP = &nfBf4.nfMsg4.netv9H;

    netv9HP->unixSec = ntohl(startTStamp0.tv_sec);
    netv9HP->ipseq = ntohl(++ipseq);

    while (written < bufLen) {
#if NF_SOCKTYPE == 1
        act_written = write(nfS, nfBP + written, bufLen - written);
#else // NF_SOCKTYPE == 0
        act_written = sendto(nfS, nfBP + written, bufLen - written, 0, (struct sockaddr*)&server, sizeof(server));
#endif // NF_SOCKTYPE == 0
        if (UNLIKELY(act_written <= 0)) {
            T2_PFATAL(plugin_name, "Failed to write IPv4 flow data to %s socket %s:%" PRIu16 ": %s",
                                   ((NF_SOCKTYPE == 1) ? "TCP" : "UDP"), addr, port, strerror(errno));
        }
        written += act_written;
    }

    nfFlw4Cnt = 0;
}


static inline void sendbuf6(int nfFlwCnt) {
    size_t written = 0, act_written;
    const size_t bufLen = sizeof(netv9Hdr_t) + sizeof(nf9Data6_t)*nfFlwCnt + 4 + NFDPAD6;
    const char * const nfBP = nfBf6.nfBuff;
    netv9Hdr_t * const netv9HP = &nfBf6.nfMsg6.netv9H;

    netv9HP->unixSec = ntohl(startTStamp0.tv_sec);
    netv9HP->ipseq = ntohl(++ipseq);

    while (written < bufLen) {
#if NF_SOCKTYPE == 1
        act_written = write(nfS, nfBP + written, bufLen - written);
#else // NF_SOCKTYPE == 0
        act_written = sendto(nfS, nfBP + written, bufLen - written, 0, (struct sockaddr*)&server, sizeof(server));
#endif // NF_SOCKTYPE == 0
        if (UNLIKELY(act_written <= 0)) {
            T2_PFATAL(plugin_name, "Failed to write IPv6 flow data to %s socket %s:%" PRIu16 ": %s",
                                   ((NF_SOCKTYPE == 1) ? "TCP" : "UDP"), addr, port, strerror(errno));
        }
        written += act_written;
    }

    nfFlw6Cnt = 0;
}
