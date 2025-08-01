/*
 * flow.c
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

#include "flow.h"

#include <pcap/pcap.h>      // for pcap_pkthdr
#include <stdlib.h>         // for exit
#include <string.h>         // for memcpy, memset

#include "hashTable.h"      // for HASHTABLE_ENTRY_NOT_FOUND, hashTable_insert
#include "loadPlugins.h"    // for t2_plugin_t, FOREACH_PLUGIN_DO
#include "main.h"           // for T2_SET_STATUS, flows, mainHashMap
#include "packetCapture.h"  // for updateLRUList
#include "t2log.h"          // for T2_FATAL
#include "t2stats.h"        // for maxNumFlows, maxNumFlowsPeak, totalAFlows, totalBFlows
#include "t2utils.h"        // for UNLIKELY, PACKET_IS_IPV6


#if ETH_ACTIVATE > 0
inline unsigned long flowETHCreate(packet_t *packet, flow_t *hashHelper) {
    const unsigned long flowIndex = hashTable_insert(mainHashMap, (char*)&hashHelper->srcIP);
    if (UNLIKELY(flowIndex == HASHTABLE_ENTRY_NOT_FOUND)) {
        T2_FATAL("Failed to insert L2 flow into mainHashMap"); // Should not happen
    }

    flow_t * const flowP = &flows[flowIndex];
    memset(flowP, '\0', sizeof(flow_t));

    flowP->timeout = FLOW_TIMEOUT;
    flowP->flowIndex = flowIndex;
    flowP->oppositeFlowIndex = HASHTABLE_ENTRY_NOT_FOUND;
    flowP->firstSeen = packet->pcapHdrP->ts;
    flowP->lastSeen = flowP->firstSeen;
    flowP->ethDS = ETH_HEADER(packet)->ethDS;
    flowP->ethType = packet->ethType;

#if (AGGREGATIONFLAG & VLANID) == 0
    flowP->vlanId = packet->vlanId;
#endif // (AGGREGATIONFLAG & VLANID) == 0

    T2_SET_STATUS(flowP, L2_FLOW);
    totalL2Flows++;

    // append the flow at the head of the LRU list
    updateLRUList(flowP);

    // check whether the reverse flow exists and link both flows
    t2_swap_mac(&hashHelper->ethDS);

    const unsigned long reverseFlowIndex = hashTable_lookup(mainHashMap, (char*)&hashHelper->srcIP);
    if (UNLIKELY(reverseFlowIndex == flowIndex)) {
        flowP->findex = ++totalfIndex;
        totalAFlows++;
    } else if (reverseFlowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
        flowP->findex = ++totalfIndex;
        totalAFlows++;
    } else {
        // reverse flow is in the hashTable
        flow_t * const revFlowP = &flows[reverseFlowIndex];
        revFlowP->oppositeFlowIndex = flowIndex;
        flowP->oppositeFlowIndex = reverseFlowIndex;
        flowP->findex = revFlowP->findex;
        totalBFlows++;
        if (!(revFlowP->status & L3FLOWINVERT)) flowP->status |= L3FLOWINVERT;
    }

    if (++maxNumFlows > maxNumFlowsPeak) maxNumFlowsPeak = maxNumFlows;

    FOREACH_PLUGIN_DO(onFlowGen, packet, flowIndex);

    return flowIndex;
}
#endif // ETH_ACTIVATE > 0


#if LAPD_ACTIVATE > 0
inline unsigned long flowLAPDCreate(packet_t *packet, flow_t *hashHelper) {
    const unsigned long flowIndex = hashTable_insert(mainHashMap, (char*)&hashHelper->srcIP);
    if (UNLIKELY(flowIndex == HASHTABLE_ENTRY_NOT_FOUND)) {
        T2_FATAL("Failed to insert LAPD flow into mainHashMap"); // Should not happen
    }

    flow_t * const flowP = &flows[flowIndex];
    memset(flowP, '\0', sizeof(flow_t));

    flowP->timeout = FLOW_TIMEOUT;
    flowP->flowIndex = flowIndex;
    flowP->oppositeFlowIndex = HASHTABLE_ENTRY_NOT_FOUND;
    flowP->firstSeen = packet->pcapHdrP->ts;
    flowP->lastSeen = flowP->firstSeen;
    flowP->ethType = hashHelper->ethType;

    T2_SET_STATUS(flowP, (LAPD_FLOW | L2_FLOW));
    totalL2Flows++;

    // append the flow at the head of the LRU list
    updateLRUList(flowP);

    // check whether the reverse flow exists and link both flows
    hashHelper->ethType ^= LAPD_AF_CR_16;
    const unsigned long reverseFlowIndex = hashTable_lookup(mainHashMap, (char*)&hashHelper->srcIP);
    if (UNLIKELY(reverseFlowIndex == flowIndex)) {
        flowP->findex = ++totalfIndex;
        totalAFlows++;
    } else if (reverseFlowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
        flowP->findex = ++totalfIndex;
        totalAFlows++;
    } else {
        // reverse flow is in the hashTable
        flow_t * const revFlowP = &flows[reverseFlowIndex];
        revFlowP->oppositeFlowIndex = flowIndex;
        flowP->oppositeFlowIndex = reverseFlowIndex;
        flowP->findex = revFlowP->findex;
        totalBFlows++;
        if (!(revFlowP->status & L3FLOWINVERT)) flowP->status |= L3FLOWINVERT;
    }

    if (++maxNumFlows > maxNumFlowsPeak) maxNumFlowsPeak = maxNumFlows;

    FOREACH_PLUGIN_DO(onFlowGen, packet, flowIndex);

    return flowIndex;
}
#endif // LAPD_ACTIVATE > 0


inline unsigned long flowCreate(packet_t *packet, flow_t *hashHelper) {
    const unsigned long flowIndex = hashTable_insert(mainHashMap, (char*)&hashHelper->srcIP);
    if (UNLIKELY(flowIndex == HASHTABLE_ENTRY_NOT_FOUND)) {
        T2_FATAL("Failed to insert L3/4 flow into mainHashMap"); // Should not happen
    }

    flow_t * const flowP = &flows[flowIndex];
    memset(flowP, '\0', sizeof(flow_t));

    flowP->timeout = FLOW_TIMEOUT;
    flowP->flowIndex = flowIndex;
    flowP->oppositeFlowIndex = HASHTABLE_ENTRY_NOT_FOUND;
    flowP->firstSeen = packet->pcapHdrP->ts;
    flowP->lastSeen = flowP->firstSeen;

#if ETH_ACTIVATE == 2
    flowP->ethDS = ETH_HEADER(packet)->ethDS;
#endif // ETH_ACTIVATE == 2

#if (IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0)
    flowP->ethType = packet->ethType;
#endif // (IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0)

#if (AGGREGATIONFLAG & VLANID) == 0
    flowP->vlanId = packet->vlanId;
#endif // (AGGREGATIONFLAG & VLANID) == 0

    flowP->srcIP = packet->srcIP;
    flowP->dstIP = packet->dstIP;
    flowP->srcPort = packet->srcPort;
    flowP->dstPort = packet->dstPort;
    flowP->l4Proto = packet->l4Proto;

#if SCTP_ACTIVATE & 1
    flowP->sctpStrm = hashHelper->sctpStrm;
#endif // SCTP_ACTIVATE & 1

#if SCTP_ACTIVATE & 2
    flowP->sctpVtag = hashHelper->sctpVtag;
#endif // SCTP_ACTIVATE & 2

#if SUBNET_INIT != 0
    flowP->subnetNrSrc = packet->subnetNrSrc;
    flowP->subnetNrDst = packet->subnetNrDst;

#if (AGGREGATIONFLAG & SUBNET) == 0
    uint32_t torAdd = 0;
    const uint_fast8_t ipver = PACKET_IPVER(packet);
    if (flowP->subnetNrSrc) {
        uint32_t srcNetID;
        SUBNET_NETID(srcNetID, ipver, flowP->subnetNrSrc);
        torAdd |= srcNetID & TOR_MSK;
    }

    if (flowP->subnetNrDst) {
        uint32_t dstNetID;
        SUBNET_NETID(dstNetID, ipver, flowP->subnetNrDst);
        torAdd |= dstNetID & TOR_MSK;
    }

    if (torAdd) T2_SET_STATUS(flowP, TORADD);
#endif // (AGGREGATIONFLAG & SUBNET) == 0
#endif // SUBNET_INIT != 0

    if (PACKET_IS_IPV6(packet)) {
        T2_SET_STATUS(flowP, L2_IPV6);
        totalIPv6Flows++;
    } else {
        flowP->lastIPID = UINT32_MAX;
        T2_SET_STATUS(flowP, L2_IPV4);
        totalIPv4Flows++;
    }

    // append the flow at the head of the LRU list
    updateLRUList(flowP);

    // check whether the reverse flow exists and link both flows
#if ETH_ACTIVATE == 2
    t2_swap_mac(&hashHelper->ethDS);
#endif // ETH_ACTIVATE == 2

    hashHelper->srcIP = hashHelper->dstIP;
    hashHelper->dstIP = packet->srcIP;
    hashHelper->srcPort = packet->dstPort;
    hashHelper->dstPort = packet->srcPort;

    const unsigned long reverseFlowIndex = hashTable_lookup(mainHashMap, (char*)&hashHelper->srcIP);
    if (UNLIKELY(reverseFlowIndex == flowIndex)) {
#if (AGGREGATIONFLAG & (SUBNET | SRCIP | DSTIP)) == 0
        if (flowP->l4Proto == L3_TCP) T2_SET_STATUS(flowP, LANDATTACK);
#endif // (AGGREGATIONFLAG & (SUBNET | SRCIP | DSTIP)) == 0
        flowP->findex = ++totalfIndex;
        totalAFlows++;
    } else if (reverseFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
        // reverse flow is in the hashTable
        flow_t * const revFlowP = &flows[reverseFlowIndex];
        revFlowP->oppositeFlowIndex = flowIndex;
        flowP->oppositeFlowIndex = reverseFlowIndex;
        flowP->findex = revFlowP->findex;
        totalBFlows++;
        if (!(revFlowP->status & L3FLOWINVERT)) flowP->status |= L3FLOWINVERT;
        //flowP->status |= ~(revFlowP->status & L3FLOWINVERT);
#if (FDURLIMIT > 0 && FDLSFINDEX == 1)
        flowP->status |= (revFlowP->status & FDLSIDX);
#endif // (FDURLIMIT > 0 && FDLSFINDEX == 1)
    } else {
#if (SCTP_ACTIVATE > 0 && SCTP_STATFINDEX == 1)
        if (packet->l4Proto == L3_SCTP) {
#if SCTP_ACTIVATE & 1
            const uint16_t i = hashHelper->sctpStrm;
            hashHelper->sctpStrm = 0;
#endif // SCTP_ACTIVATE & 1
#if SCTP_ACTIVATE & 2
            const uint32_t j = hashHelper->sctpVtag;
            hashHelper->sctpVtag = 0;
#endif // SCTP_ACTIVATE & 2
            const unsigned long fidx = hashTable_lookup(mainHashMap, (char*)&hashHelper->srcIP);
#if SCTP_ACTIVATE & 1
            flowP->sctpStrm = i;
#endif // SCTP_ACTIVATE & 1
#if SCTP_ACTIVATE & 2
            flowP->sctpVtag = j;
#endif // SCTP_ACTIVATE & 2
            flowP->sctpFindex = fidx;
            if (fidx == HASHTABLE_ENTRY_NOT_FOUND) ++totalfIndex;
            flowP->findex = totalfIndex;
        } else {  // packet->l4Proto != L3_SCTP
#endif // (SCTP_ACTIVATE > 0 && SCTP_STATFINDEX == 1)
#if (FDURLIMIT > 0 && FDLSFINDEX == 1)
            if (packet->status & FDLSIDX) {
                T2_SET_STATUS(flowP, FDLSIDX);
                //flowP->status |= FDLSIDX;
                flowP->findex = packet->findex;
            } else
#endif // (FDURLIMIT > 0 && FDLSFINDEX == 1)
                flowP->findex = ++totalfIndex;
#if (SCTP_ACTIVATE > 0 && SCTP_STATFINDEX == 1)
        }  // packet->l4Proto != L3_SCTP
#endif // (SCTP_ACTIVATE > 0 && SCTP_STATFINDEX == 1)

        totalAFlows++;

        // check flow direction
        if ((packet->srcPort < 1024 && packet->srcPort < packet->dstPort) ||
            (packet->srcPort & 0xfff6) == 8080 ||
            (packet->l4Proto == L3_TCP && ((*((char*)packet->l4HdrP + 13) & TH_SYN_ACK) == TH_SYN_ACK))
        ) {
            flowP->status |= L3FLOWINVERT;
        }
#if FDURLIMIT > 0
        else {
            //flowP->status |= packet->status & L3FLOWINVERT;
            flowP->status |= packet->status;
        }
#endif // FDURLIMIT
    }

    if (++maxNumFlows > maxNumFlowsPeak) maxNumFlowsPeak = maxNumFlows;

    FOREACH_PLUGIN_DO(onFlowGen, packet, flowIndex);

    return flowIndex;
}
