/*
 * packetCapture.c
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

#include "packetCapture.h"

#include <arpa/inet.h>              // for ntohs
#include <ctype.h>                  // for isprint
#include <inttypes.h>               // for PRIu64, PRIu16, PRIu32
#include <netinet/in.h>             // for in_addr
#include <pcap/pcap.h>              // for pcap_pkthdr
#include <stdbool.h>                // for false, bool, true
#include <stdint.h>                 // for uint8_t, uint16_t, uint32_t, uint...
#include <stdio.h>                  // for fputs, NULL, fprintf, fputc, FILE
#include <stdlib.h>                 // for exit
//#include <string.h>                 // for memcpy
#include <time.h>                   // for clock_gettime, CLOCK_REALTIME

#include "bin2txt.h"                // for B2T_PRIX64, B2T_PRIX16, B2T_PRIX32
#include "hashTable.h"              // for hashTable_lookup, HASHTABLE_ENTRY...
#include "hdrDesc.h"                // for T2_PKTDESC_ADD_HDR, T2_PKTDESC_AD...
#include "ioBuffer.h"               // for IO_BUFFERING
#include "loadPlugins.h"            // for t2_plugin_t, FOREACH_PLUGIN_DO
#include "main.h"                   // for cycleLRULists, fragPend, fragPendMap, sPktFile, flows, globalWarn, ...
#include "networkHeaders.h"         // for IPV6_ACTIVATE, ipHeader_t, ...
#include "proto/t2_proto.h"         // for t2_process_ethertype, t2_process_vlan, ...
#include "t2log.h"                  // for T2_WRN, t2_log_date, T2_PERR, T2_...
#include "t2stats.h"                // for maxHdrDesc, numGREPackets, numAYIYAPackets, ...
#include "tranalyzer.h"             // for SUBNET_INIT

#if ((AGGREGATIONFLAG & SUBNET) == 0 && (AGGREGATIONFLAG & (SRCIP | DSTIP)))
#include "missing/missing.h"        // for be64toh
#endif // ((AGGREGATIONFLAG & SUBNET) == 0 && (AGGREGATIONFLAG & (SRCIP | DSTIP)))

#if (SPKTMD_BOPS > 0 && (SPKTMD_PCNTH == 1 || SPKTMD_PCNTC == 1))
#include "t2asm.h"                  // for NSWP, BINV_8
#endif // (SPKTMD_BOPS > 0 && (SPKTMD_PCNTH == 1 || SPKTMD_PCNTC == 1))

#if SUBNET_INIT
#include "../../utils/subnetHL4.h"  // for subnet_testHL4, subnettable4_t
#include "../../utils/subnetHL6.h"  // for subnet_testHL6, subnettable6_t
#endif // SUBNET_INIT


// Static inline functions prototypes

static inline void processPacket(const struct pcap_pkthdr *pcapHeader, const u_char *packet);
static inline void t2_dispatch_l2_packet(packet_t *packet);
static inline void t2_print_payload(FILE *stream, const packet_t *packet);


// Variables

flow_t lruHead, lruTail;
//#if FRAGMENTATION == 1 && FRAG_HLST_CRFT == 1
//packet_t packetBuf[9600];
//#endif // FRAGMENTATION == 1 && FRAG_HLST_CRFT == 1

#if SUBNET_INIT != 0
extern void *subnetTableP[2];
extern subnettable4_t *subnetTable4P;
extern subnettable6_t *subnetTable6P;
#endif // SUBNET_INIT != 0


// Static variables

#if MONINTTMPCP == 1
static float timeDiff0;
#endif


// callback function triggered every time we receive/read a new packet from the pcap descriptor
inline void perPacketCallback(u_char *inqueue UNUSED, const struct pcap_pkthdr *pcapHeader, const u_char *packet) {

#if PKT_CB_STATS == 1
    struct timespec startT;
    clock_gettime(CLOCK_REALTIME, &startT);
#endif // PKT_CB_STATS == 1

    actTime = pcapHeader->ts;

    if (UNLIKELY(numPackets == 0)) {
        startTStamp = actTime;
        startTStamp0 = startTStamp;
#if MIN_MAX_ESTIMATE > 0
        lagTm = actTime.tv_sec + actTime.tv_usec / TSTAMPFAC;
#endif // MIN_MAX_ESTIMATE > 0
#if VERBOSE > 0
        t2_log_date(dooF, "Dump start: ", startTStamp, TSTAMP_UTC);
#endif
    }

#if MONINTTMPCP == 1
    const float timeDiff = actTime.tv_sec - startTStamp.tv_sec;
    if (timeDiff - timeDiff0 >= MONINTV) {
        globalInt |= GI_RPRT;
        timeDiff0 = timeDiff;
    }
#endif

    cycleLRULists();
    processPacket(pcapHeader, packet);

#if PKT_CB_STATS == 1
    struct timespec endT;
    clock_gettime(CLOCK_REALTIME, &endT);

    const double cpuTime = (endT.tv_sec - startT.tv_sec) + (endT.tv_nsec - startT.tv_nsec) / 1000000000.0;

    maxCpuTime = MAX(cpuTime, maxCpuTime);
    minCpuTime = MIN(cpuTime, minCpuTime);
    const double dt = cpuTime - avgCpuTime;
    avgCpuTime += dt / (double)numPackets;
    varCpuTime += (dt * dt - varCpuTime) / (double)numPackets;
#endif // PKT_CB_STATS == 1
}


// the function that starts the processing of a packet
static inline void processPacket(const struct pcap_pkthdr *pcapHeader, const u_char *packet) {

    const uint32_t len = pcapHeader->len;
    const uint32_t caplen = pcapHeader->caplen;

    numPackets++;
    rawBytesOnWire += pcapHeader->len;

    if (UNLIKELY(caplen == 0)) {
#if VERBOSE > 1
        T2_WRN("No data available for packet %" PRIu64, numPackets);
#endif
        return;
    }

    packet_t newPacket = {
        .raw_packet = packet,
        .end_packet = packet + caplen,
        .pcapHdrP   = pcapHeader,
        .snapLen    = caplen,
        .snapL2Len  = caplen,
        .rawLen     = len,
    };

    bytesProcessed += caplen;

#if IO_BUFFERING == 1
    if (gBufStat) {
        gBufStat = 0;
        newPacket.status = PCAPSNPD;
    }
#endif

    uint8_t *pktptr = (uint8_t*)packet;

#if NOLAYER2 == 1 // manual mode: set your own L3 pointer
    T2_SET_STATUS(&newPacket, L2_NO_ETH);
    newPacket.l2HdrP = pktptr;
    pktptr += NOL2_L3HDROFFSET;
    newPacket.l3HdrP = pktptr;
    const uint_fast8_t ipver = (*pktptr & 0xf0);
    if (ipver == 0x40) {
        dissembleIPv4Packet(&newPacket);
    } else if (ipver == 0x60) {
        dissembleIPv6Packet(&newPacket);
    }
    goto endpPkt;
#endif // NOLAYER2 == 1

    // Real traffic

    _8021Q_t *shape = (_8021Q_t*)t2_process_linktype(pktptr, &newPacket);
    if (!shape) goto endpPkt;

    // check for 802.1Q/ad signature (VLANs)
    shape = t2_process_vlans(shape, &newPacket);

    // check for LLC
    const uint32_t shape_id = ntohs(shape->identifier);
    if (shape_id > LLC_LEN && shape_id != ETHERTYPE_JUMBO_LLC) { // Ethernet II with length or IEEE 802.3 (802.2 LLC) frames with length
        newPacket.outerEthType = shape_id; // Not LLC
    } else {
        T2_PKTDESC_ADD_HDR(&newPacket, ":llc");
        newPacket.etherLLC = (etherLLCHeader_t*)shape;
        if (newPacket.etherLLC->dssap == 0xaaaa) { // SNAP
            shape = (_8021Q_t*)((uint8_t*)shape + 8);
            newPacket.outerEthType = ntohs(shape->identifier);
        } else {
            uint32_t llc_len = 5; // 3 for DSAP, SSAP, Ctrl, 2 for Ethernet length
            // Information and Supervisory frames use 2 bytes for Control
            if ((newPacket.etherLLC->cmd.cntrl & 0x3) != 3) llc_len++;

            pktptr = (uint8_t*)shape + llc_len;

            const uint8_t dsap = (newPacket.etherLLC->dssap & 0xff);
            if (dsap != LLC_SAP_IP) {
                T2_PKTDESC_ADD_LLCPROTO(&newPacket, dsap);
            } else {
                switch (*pktptr & 0xf0) {
                    case 0x40:
                        newPacket.l3HdrP = pktptr;
                        dissembleIPv4Packet(&newPacket);
                        goto endpPkt;
                    case 0x60:
                        newPacket.l3HdrP = pktptr;
                        dissembleIPv6Packet(&newPacket);
                        goto endpPkt;
                    default:
                        T2_PKTDESC_ADD_HDR(&newPacket, ":ipvx");
                        T2_SET_STATUS(&newPacket, L3_IPVX);
                        break;
                }
            }

            newPacket.ethType = ntohs(newPacket.etherLLC->dssap);
            newPacket.outerEthType = newPacket.ethType;

            if (newPacket.rawLen <= MINRAWLEN) {
                // XXX +2 is required as etherLLC points to the ethertype...
                const int64_t pad = (int64_t)((int64_t)newPacket.rawLen - (int64_t)shape_id - (int64_t)((uint8_t*)shape + 2 - newPacket.raw_packet));
                if (pad < 0) {
                    // TODO set a bit in flowStat?
                } else {
                    newPacket.padLen = pad;
                    padBytesOnWire += pad;
                }
            }

            // No flow could be created... flag the packet as L2_FLOW and create a L2 flow
            newPacket.l7HdrP = pktptr;
            t2_dispatch_l2_packet(&newPacket);

            goto endpPkt;
        } // SNAP
    } // LLC

    pktptr = t2_process_ethertype((uint8_t*)shape, &newPacket);
    if (pktptr) {
        // No flow could be created... flag the packet as L2_FLOW and create a L2 flow
        //if (newPacket.rawLen <= 60) {
        //  // TODO how to compute the padding length here?!
        //}
        newPacket.l7HdrP = ((uint8_t*)pktptr + 2);
        if (newPacket.rawLen <= MINRAWLEN) {
            int64_t pad;
            // XXX +2 is required as etherLLC points to the ethertype...
            if (newPacket.etherLLC) {
                pad = (int64_t)((int64_t)newPacket.rawLen - (int64_t)shape_id - (int64_t)((uint8_t*)pktptr - 6 - newPacket.raw_packet));
            } else if ((*(uint16_t*)pktptr) == 0x0608){
                pad = (int64_t)newPacket.rawLen - sizeof(arpMsg_t) - (int64_t)((uint8_t*)pktptr + 2 - newPacket.raw_packet);
            } else {
                pad = (int64_t)newPacket.rawLen - (int64_t)((uint8_t*)pktptr + 2 - newPacket.raw_packet);
            }

            if (pad < 0) {
                // TODO set a bit in flowStat?
            } else {
                newPacket.padLen = pad;
                padBytesOnWire += pad;
            }
        }
        t2_dispatch_l2_packet(&newPacket);
    }

endpPkt:;

    const uint_fast64_t status = newPacket.status;
    globalWarn |= status;

    if (newPacket.etherLLC) numLLCPackets++;
#if IPV6_ACTIVATE == 2
    if (status & L2_IPV4) numV4Packets++;
    else if (status & L2_IPV6) numV6Packets++;
#elif IPV6_ACTIVATE == 1
    if (status & FS_IPV4_PKT) numV4Packets++;
    else if (status & FS_IPV6_PKT) numV6Packets++;
#else // IPV6_ACTIVATE == 0
    if (status & FS_IPV6_PKT) numV6Packets++;
    else if (status & FS_IPV4_PKT) numV4Packets++;
#endif // IPV6_ACTIVATE == 0
    if (status & L3_IPVX) numVxPackets++;
#if TEREDO == 1
    if (status & L3_TRDO) numTeredoPackets++;
#endif
#if AYIYA == 1
    if (status & L3_AYIYA) numAYIYAPackets++;
#endif
    if (status & L2_GRE) numGREPackets++;

#if T2_PRI_HDRDESC == 1
    const uint16_t numHdrDesc = newPacket.numHdrDesc;
    maxHdrDesc = MAX(numHdrDesc, maxHdrDesc);
    minHdrDesc = MIN(numHdrDesc, minHdrDesc);
    const float t = 1.0 / numPackets;
    avgHdrDesc = (1.0 - t) * avgHdrDesc + t * (float)numHdrDesc;
#endif // T2_PRI_HDRDESC == 1
}


inline void dissembleIPv4Packet(packet_t *packet) {

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if (FRAGMENTATION == 1 && FRAG_HLST_CRFT == 1)
    uint64_t sw_fnohead = 0;
#endif // (FRAGMENTATION == 1 && FRAG_HLST_CRFT == 1)

    flow_t *flowP = NULL;
    unsigned long flowIndex = HASHTABLE_ENTRY_NOT_FOUND;

#if SCTP_ACTIVATE > 0
    int32_t sctpL7Len = 0, sctpChnkLen = 0, sctpChnkPLen = 0;
    sctpChunk_t *sctpChunkP = NULL;
    uint8_t *sctpL7P = NULL;
#endif // SCTP_ACTIVATE > 0

#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

    packet->ethType = ETHERTYPE_IP;
    packet->l3Proto = packet->ethType;
    T2_SET_STATUS(packet, FS_IPV4_PKT);

#if IPVX_INTERPRET == 1
    if ((*packet->l3HdrP & 0xf0) != 0x40) {
        T2_PKTDESC_ADD_HDR(packet, ":ipvx");
        T2_SET_STATUS(packet, L3_IPVX);
    } else
#endif // IPVX_INTERPRET == 1
        T2_PKTDESC_ADD_HDR(packet, ":ipv4");

    const ipHeader_t *ipHdrP = IPV4_HEADER(packet);
    const uint16_t l3HdrLen = IP_HL(ipHdrP) << 2;
    if (l3HdrLen < 20) {
        T2_SET_STATUS(packet, IPV4_HL_TOO_SHORT);
        return;
    }

    packet->l3HdrLen = l3HdrLen;

    // adjust header to the beginning of the encapsulated protocol
    packet->l4HdrP = ((uint8_t*)ipHdrP + l3HdrLen);

#if (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2 || L2TP == 1 || TEREDO == 1 || AYIYA == 1 || GTP == 1 || VXLAN == 1 || CAPWAP == 1 || GENEVE == 1 || LWAPP == 1)
    bool priproto = true;
#endif // (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2 || L2TP == 1 || TEREDO == 1 || AYIYA == 1 || GTP == 1 || VXLAN == 1 || CAPWAP == 1 || GENEVE == 1 || LWAPP == 1)

    if (ipHdrP->ip_off & FRAGID_N) { // if 2nd++ fragmented packet, stop processing
        T2_SET_STATUS(packet, STPDSCT);
    }

#if (AYIYA | L2TP | TEREDO | GTP | VXLAN | CAPWAP | GENEVE | LWAPP | LAPD_OVER_UDP)
    const uint_fast8_t proto = ipHdrP->ip_p;

    uint16_t sport = 0;
    uint16_t dport = 0;
    size_t hdrlen = 0;

    if (!(ipHdrP->ip_off & FRAGID_N)) { // if NOT 2nd++ fragmented packet
        if (proto == L3_TCP) {
            const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
            sport = ntohs(tcpHdrP->source);
            dport = ntohs(tcpHdrP->dest);
            hdrlen = tcpHdrP->doff << 2;
        } else if (proto == L3_UDP || proto == L3_UDPLITE) {
            const udpHeader_t * const udpHdrP = UDP_HEADER(packet);
            sport = ntohs(udpHdrP->source);
            dport = ntohs(udpHdrP->dest);
            hdrlen = sizeof(*udpHdrP);
        } else if (proto == L3_SCTP) {
            const sctpHeader_t * const sctpHdrP = SCTP_HEADER(packet);
            sport = ntohs(sctpHdrP->source);
            dport = ntohs(sctpHdrP->dest);
            hdrlen = sizeof(*sctpHdrP);
        }
    }

    packet->srcPort = sport;
    packet->dstPort = dport;

    // AYIYA, L2TP, TEREDO, GTP, VXLAN, CAPWAP and LWAPP all require a port
    if (sport != 0 && dport != 0) {

#if AYIYA == 1 // AYIYA: Anything in Anything
        if (!(packet->status & STPDSCT) && t2_is_ayiya(sport, dport)) {
            if (proto == L3_SCTP) {
                if (LIKELY(priproto)) {
                    T2_PKTDESC_ADD_HDR(packet, ":sctp");
                    priproto = false;
                }
                T2_PKTDESC_ADD_HDR(packet, ":ayiya");
                T2_SET_STATUS(packet, STPDSCT);
            } else {
                const int reqlen = ntohs(ipHdrP->ip_len) - l3HdrLen - hdrlen - sizeof(ayiyaHeader_t); // FIXME TSO case
                if (reqlen >= 0) {
                    if (LIKELY(priproto)) {
                        T2_PKTDESC_ADD_PROTO(packet, proto);
                        priproto = false;
                    }
                    uint8_t * const pktptr = (uint8_t*)packet->l4HdrP + hdrlen; // advance to AYIYA
                    if (!t2_process_ayiya(pktptr, packet)) return;
                    // AYIYA could not be processed...
                }
            }
        }
#endif // AYIYA == 1

#if (L2TP | TEREDO | GTP | VXLAN | CAPWAP | GENEVE | LWAPP | LAPD_OVER_UDP)
        if (!(packet->status & STPDSCT) && proto == L3_UDP) {
#if GTP == 1
            // GPRS Tunneling Protocol (GTP)
            if (!(packet->status & STPDSCT) && t2_is_gtp(sport, dport)) {
                if (priproto) {
                    T2_PKTDESC_ADD_HDR(packet, ":udp");
                    priproto = false;
                }
                uint8_t * const pktptr = (uint8_t*)packet->l4HdrP + hdrlen; // advance to GTP
                if (!t2_process_gtp(pktptr, packet)) return;
                // GTP could not be processed...
            }
#endif // GTP == 1

#if VXLAN == 1
            // Virtual eXtensible Local Area Network (VXLAN)
            if (!(packet->status & STPDSCT) && t2_is_vxlan(sport, dport)) {
                if (priproto) {
                    T2_PKTDESC_ADD_HDR(packet, ":udp");
                    priproto = false;
                }
                uint8_t * const pktptr = (uint8_t*)packet->l4HdrP + hdrlen; // advance to VXLAN
                if (!t2_process_vxlan(pktptr, packet)) return;
                // VXLAN could not be processed...
            }
#endif // VXLAN == 1

#if GENEVE == 1
            // Generic Network Virtualization Encapsulation (GENEVE)
            if (!(packet->status & STPDSCT) && t2_is_geneve(sport, dport)) {
                if (priproto) {
                    T2_PKTDESC_ADD_HDR(packet, ":udp");
                    priproto = false;
                }
                uint8_t * const pktptr = (uint8_t*)packet->l4HdrP + hdrlen; // advance to GENEVE
                if (!t2_process_geneve(pktptr, packet)) return;
                // GENEVE could not be processed...
            }
#endif // GENEVE == 1

#if CAPWAP == 1
            // Control And Provisioning of Wireless Access Points (CAPWAP)
            if (!(packet->status & STPDSCT) && t2_is_capwap(sport, dport)) {
                if (priproto) {
                    T2_PKTDESC_ADD_HDR(packet, ":udp");
                    priproto = false;
                }
                uint8_t * const pktptr = (uint8_t*)packet->l4HdrP + hdrlen; // advance to CAPWAP
                if (!t2_process_capwap(pktptr, packet)) return;
                // CAPWAP could not be processed...
            }
#endif // CAPWAP == 1

#if LWAPP == 1
            // Lightweight Access Point Protocol (LWAPP)
            if (!(packet->status & STPDSCT) && t2_is_lwapp(sport, dport)) {
                if (priproto) {
                    T2_PKTDESC_ADD_HDR(packet, ":udp");
                    priproto = false;
                }
                uint8_t * const pktptr = (uint8_t*)packet->l4HdrP + hdrlen; // advance to LWAPP
                if (!t2_process_lwapp(pktptr, packet)) return;
                // LWAPP could not be processed...
            }
#endif // LWAPP == 1

#if L2TP == 1
            if (!(packet->status & STPDSCT) && t2_is_l2tp(sport, dport)) {
                if (priproto) {
                    T2_PKTDESC_ADD_HDR(packet, ":udp");
                    priproto = false;
                }
                uint8_t * const pktptr = (uint8_t*)packet->l4HdrP + hdrlen; // advance to L2TP
                if (!t2_process_l2tp(pktptr, packet)) return;
                // L2TP could not be processed...
            }
#endif // L2TP == 1

#if TEREDO == 1
            if (!(packet->status & STPDSCT) && t2_is_teredo(sport, dport)) {
                if (priproto) {
                    T2_PKTDESC_ADD_HDR(packet, ":udp");
                    priproto = false;
                }
                uint8_t * const pktptr = (uint8_t*)packet->l4HdrP + hdrlen; // advance to Teredo
                if (!t2_process_teredo(pktptr, packet)) return;
                // Teredo could not be processed...
            }
#endif // TEREDO == 1

#if LAPD_OVER_UDP == 1
            if (!(packet->status & STPDSCT)) {
                if (priproto) {
                    T2_PKTDESC_ADD_HDR(packet, ":udp");
                    priproto = false;
                }
                // LAPD
                uint8_t *pktptr = (uint8_t*)packet->l4HdrP;
                pktptr += hdrlen; // advance to LAPD
                if ((*pktptr & 0x01) == 0 && (*(pktptr + 1) & 0x01) == 1) { // EA1 = 0, EA2 = 1
                    packet->l2HdrP = pktptr;
                    packet->l3HdrP = pktptr;
                    pktptr += 2; // skip address
                    if ((*pktptr & 0x03) == 0x03) pktptr++; // Unnumbered frame
                    else pktptr += 2; // Information or Supervisory frame
                    packet->l7HdrP = pktptr;
                    T2_PKTDESC_ADD_HDR(packet, ":lapd");
                    t2_dispatch_lapd_packet(packet);
                    return;
                }
            }
#endif // LAPD_OVER_UDP
        } // UDP
#endif // (L2TP | TEREDO | GTP | VXLAN | CAPWAP | GENEVE | LWAPP | LAPD_OVER_UDP)
    } // sport != 0 && dport != 0
#endif // (AYIYA | L2TP | TEREDO | GTP | VXLAN | CAPWAP | GENEVE | LWAPP | LAPD_OVER_UDP)

#if GRE == 1
    uint32_t *grePPP = NULL, *greHD = NULL;
    if (ipHdrP->ip_p == L3_GRE && !(packet->status & STPDSCT)) {
        T2_PKTDESC_ADD_HDR(packet, ":gre");
        T2_SET_STATUS(packet, L2_GRE);
        packet->l4HdrP = ((uint8_t*)ipHdrP + (IP_HL(ipHdrP) << 2)); // adjust header to the beginning of the encapsulated protocol
        grePPP = (uint32_t*) packet->l4HdrP;
        greHD = grePPP++;
        packet->greHdrP = (greHeader_t*)greHD;
        packet->greL3HdrP = packet->l3HdrP;
        if (*greHD & GRE_CKSMn) grePPP++;
        if (*greHD & GRE_RTn) grePPP++;
        if (*greHD & GRE_KEYn) grePPP++;
        if (*greHD & GRE_SQn) grePPP++;
        if (*greHD & GRE_SSRn) grePPP++;
        if (*greHD & GRE_ACKn) grePPP++;
        if ((*greHD & GRE_PROTOn) == GRE_IP4n) {
            T2_PKTDESC_ADD_HDR(packet, ":ipv4");
            packet->l3HdrP = (uint8_t*)grePPP;
            packet->l3Proto = ETHERTYPE_IP;
            ipHdrP = IPV4_HEADER(packet);
            packet->l3HdrLen = IP_HL(ipHdrP) << 2;
        } else if ((*greHD & GRE_PROTOn) == GRE_PPPn) {
            T2_PKTDESC_ADD_HDR(packet, ":ppp");
            T2_SET_STATUS(packet, L2_PPP);
            packet->pppHdrP = (pppHu_t*)grePPP; // save PPP header
            if ((*grePPP & 0x000000ff) == GRE_PPP_CMPRSS) {
                // compressed, no readable header; info for later processing of flow
                T2_PKTDESC_ADD_HDR(packet, ":comp_data");
                T2_SET_STATUS(packet, (PPP_NRHD | STPDSCT));
            // Enhanced GRE (1) with payload length == 0
            } else if ((*greHD & GRE_Vn) == 0x100 && (*(uint16_t*)((uint16_t*)greHD + 2) == 0)) {
                packet->pppHdrP = NULL; // reset PPP header (not present)
                T2_SET_STATUS(packet, STPDSCT);
            } else if ((*grePPP & 0x000000ff) != 0xff) { // address and control are null
                if (*grePPP & 0x00000001) {
                    // One byte protocol ID
                    if ((*grePPP & 0x000000ff) == 0x21) {
                        T2_PKTDESC_ADD_HDR(packet, ":ipv4");
                        packet->l3HdrP = ((uint8_t*)grePPP + 1);
                        packet->l3Proto = ETHERTYPE_IP;
                        ipHdrP = IPV4_HEADER(packet);
                        packet->l3HdrLen = IP_HL(ipHdrP) << 2;
                    }
                } else {
                    // Two bytes protocol ID
                    if ((*grePPP & 0x0000ffff) == PPP_IP4n) {
                        T2_PKTDESC_ADD_HDR(packet, ":ipv4");
                        packet->l3HdrP = (uint8_t*)(++grePPP);
                        packet->l3Proto = ETHERTYPE_IP;
                        ipHdrP = IPV4_HEADER(packet);
                        packet->l3HdrLen = IP_HL(ipHdrP) << 2;
                    //} else if ((*grePPP & 0x0000ffff) == PPP_IP6n) { // TODO
                    } else {
                        T2_PKTDESC_ADD_PPPPROTO(packet, (*grePPP & 0x0000ffff));
                        T2_SET_STATUS(packet, STPDSCT);
                    }
                }
            } else if (((pppHdr_t*)grePPP)->prot == PPP_IP4n) {
                T2_PKTDESC_ADD_HDR(packet, ":ipv4");
                packet->l3HdrP = (uint8_t*)(++grePPP);
                packet->l3Proto = ETHERTYPE_IP;
                ipHdrP = IPV4_HEADER(packet);
                packet->l3HdrLen = IP_HL(ipHdrP) << 2;
            } else if (((pppHdr_t*)grePPP)->prot == PPP_IP6n) {
#if IPV6_ACTIVATE > 0
                packet->l3HdrP = (uint8_t*)(++grePPP);
                dissembleIPv6Packet(packet);
                return;
#else // IPV6_ACTIVATE == 0
                T2_PKTDESC_ADD_HDR(packet, ":ipv6");
                T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)(++grePPP))->next_header);
                T2_SET_STATUS(packet, (FS_IPV6_PKT | STPDSCT));
#endif // IPV6_ACTIVATE == 0
            } else {
                // Enhanced GRE (1) with payload length == 0
                if ((*greHD & GRE_Vn) == 0x100 && (*(uint16_t*)((uint16_t*)greHD + 2) == 0)) {
                    packet->pppHdrP = NULL; // reset PPP header (not present)
                } else {
                    T2_PKTDESC_ADD_PPPPROTO(packet, ((pppHdr_t*)grePPP)->prot);
                }
                T2_SET_STATUS(packet, STPDSCT);
            }
        } else if ((*greHD & GRE_PROTOn) == GRE_TEBn ||
                   (*greHD & GRE_PROTOn) == GRE_ERSPANn)
        {
            if ((*greHD & GRE_PROTOn) == GRE_ERSPANn) {
                T2_PKTDESC_ADD_HDR(packet, ":erspan");
                T2_SET_STATUS(packet, L2_ERSPAN);
                grePPP += 2; // skip ERSPAN header (64 bytes)
            }
            const uint8_t *hp = (uint8_t*)grePPP;
            const uint8_t * const hp1 = hp;
            const uint16_t i = (uint16_t)(hp - packet->l2HdrP); // L2, VLAN length
            hp += 12;
            T2_PKTDESC_ADD_HDR(packet, ":eth");
            // check for 802.1Q/ad signature (VLANs)
            _8021Q_t *shape = (_8021Q_t*)hp;
            if (packet->snapL2Len >= sizeof(_8021Q_t)) {
                shape = t2_process_vlans(shape, packet);
                hp = (uint8_t*)shape;
            }
            const uint16_t shapeid = ntohs(shape->identifier);
            if (shapeid <= LLC_LEN || shapeid == ETHERTYPE_JUMBO_LLC) {
                T2_PKTDESC_ADD_HDR(packet, ":llc");
                packet->etherLLC = (etherLLCHeader_t*)hp;
                hp = ((uint8_t*)packet->etherLLC + 8); // jump to ethertype
                shape = (_8021Q_t*)hp;
            } else hp += 2; // skip ethertype

            if (shape->identifier == ETHERTYPE_IPn) {
                T2_PKTDESC_ADD_HDR(packet, ":ipv4");
                packet->l2HdrP = hp1;
                packet->snapL2Len -= i;
                packet->l3HdrP = hp;
                ipHdrP = IPV4_HEADER(packet);
                packet->l3HdrLen = IP_HL(ipHdrP) << 2;
                packet->l3Proto = ETHERTYPE_IP;
            } else if (shape->identifier == ETHERTYPE_IPV6n) {
#if IPV6_ACTIVATE > 0
                packet->l2HdrP = hp1;
                packet->l3HdrP = hp;
                packet->snapL2Len -= i;
                dissembleIPv6Packet(packet);
                return;
#else // IPV6_ACTIVATE == 0
                T2_PKTDESC_ADD_HDR(packet, ":ipv6");
                T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)hp)->next_header);
                T2_SET_STATUS(packet, (FS_IPV6_PKT | STPDSCT));
#endif // IPV6_ACTIVATE == 0
            } else {
                T2_PKTDESC_ADD_ETHPROTO(packet, shape->identifier);
                T2_SET_STATUS(packet, STPDSCT);
            }
        } else if ((*greHD & GRE_PROTOn) == GRE_WCCPn) {
            T2_PKTDESC_ADD_HDR(packet, ":wccp");
            T2_SET_STATUS(packet, L2_WCCP);
            const uint8_t *pktptr = (uint8_t*)grePPP;
            pktptr += 4;
            if ((*pktptr & 0xf0) == 0x40) {
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
                packet->l3HdrP = pktptr;
                dissembleIPv4Packet(packet);
                return;
#else // IPV6_ACTIVATE == 1
                T2_PKTDESC_ADD_HDR(packet, ":ipv4");
                T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)pktptr)->ip_p);
#endif // IPV6_ACTIVATE == 1
            } else if ((*pktptr & 0xf0) == 0x60) {
#if IPV6_ACTIVATE > 0
                packet->l3HdrP = pktptr;
                dissembleIPv6Packet(packet);
                return;
#else // IPV6_ACTIVATE == 0
                T2_PKTDESC_ADD_HDR(packet, ":ipv6");
                T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)pktptr)->next_header);
                T2_SET_STATUS(packet, (FS_IPV6_PKT | STPDSCT));
#endif // IPV6_ACTIVATE == 0
            } else {
                T2_SET_STATUS(packet, STPDSCT);
            }
        } else {
            T2_PKTDESC_ADD_ETHPROTO(packet, ((*greHD & GRE_PROTOn) >> 16));
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
            priproto = false;
#endif
            T2_SET_STATUS(packet, STPDSCT);
        }
    }
#endif // GRE == 1

#if ETHIP == 1
    const uint8_t *hp = packet->l3HdrP + packet->l3HdrLen;
    if (ipHdrP->ip_p == L3_ETHIP && (*hp & 0xf0) >= ETHIPVERN && !(packet->status & STPDSCT)) {
        T2_PKTDESC_ADD_HDR(packet, ":etherip");
        T2_PKTDESC_ADD_HDR(packet, ":eth");

        T2_SET_STATUS(packet, L3_ETHIPF);

        const uint16_t i = (uint16_t)(hp - packet->l2HdrP) + 2; // L2, VLAN length
        packet->snapL2Len -= i;
        packet->l2HdrP = (hp + 2);

        hp += 14;

        // check for 802.1Q/ad signature (VLANs)
        _8021Q_t *shape = (_8021Q_t*)hp;
        shape = t2_process_vlans(shape, packet);
        hp = (uint8_t*)shape + 2;
        if (shape->identifier == ETHERTYPE_IPn) {
            T2_PKTDESC_ADD_HDR(packet, ":ipv4");
            packet->l3HdrP = hp;
            ipHdrP = (ipHeader_t*)hp;
            packet->l3HdrLen = IP_HL(ipHdrP) << 2;
            packet->l3Proto = ntohs(*(uint16_t*)(hp - 2));
        } else if (shape->identifier == ETHERTYPE_IPV6n) {
#if IPV6_ACTIVATE > 0
            packet->l3HdrP = hp;
            dissembleIPv6Packet(packet);
            return;
#else // IPV6_ACTIVATE == 0
            T2_PKTDESC_ADD_HDR(packet, ":ipv6");
            T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)hp)->next_header);
            T2_SET_STATUS(packet, (FS_IPV6_PKT | STPDSCT));
#endif // IPV6_ACTIVATE
        } else {
            T2_PKTDESC_ADD_ETHPROTO(packet, shape->identifier);
            T2_SET_STATUS(packet, STPDSCT);
        }
    }
#endif // ETHIP == 1

    if (!(packet->status & STPDSCT)) {
        if (ipHdrP->ip_p == L3_IPIP4) {
            T2_SET_STATUS(packet, L3_IPIP);
#if IPIP == 1
            T2_PKTDESC_ADD_HDR(packet, ":ipv4");
            const uint8_t * const hp = packet->l3HdrP + packet->l3HdrLen;
            if (hp > packet->end_packet) {
                T2_SET_STATUS(packet, STPDSCT);
            } else {
                packet->l3HdrP = hp;
                ipHdrP = IPV4_HEADER(packet);
                packet->l3HdrLen = IP_HL(ipHdrP) << 2;
            }
#endif // IPIP == 1
        } else if (ipHdrP->ip_p == L3_IPIP6) {
            T2_SET_STATUS(packet, L3_IPIP);
            const uint8_t * const hp = packet->l3HdrP + packet->l3HdrLen;
            if (hp > packet->end_packet) {
                T2_SET_STATUS(packet, (FS_IPV6_PKT | STPDSCT));
            } else {
#if IPIP == 1 && IPV6_ACTIVATE > 0
                packet->l3HdrP = hp;
                dissembleIPv6Packet(packet);
                return;
#else // IPIP == 0 || IPV6_ACTIVATE == 0
                T2_PKTDESC_ADD_HDR(packet, ":ipv6");
                T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)hp)->next_header);
                T2_SET_STATUS(packet, (FS_IPV6_PKT | STPDSCT));
#endif // IPV6_ACTIVATE == 0
            }
        }
    }

#if IPV6_ACTIVATE == 1
#if ETH_ACTIVATE > 0
    packet->l7HdrP = packet->l3HdrP;
    t2_dispatch_l2_packet(packet);
#endif // ETH_ACTIVATE > 0
} // END OF FUNCTION dissembleIPv4Packet
#else // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

    if ((ipHdrP->ip_vhl & 0xf0) != 0x40) {
        T2_SET_STATUS(packet, L3_IPVX);
#if IPVX_INTERPRET == 0
        T2_PKTDESC_ADD_HDR(packet, ":ipvx");
        return;
#endif
    }

#if FRAGMENTATION == 0
    // do not handle fragmented packets
    if (ipHdrP->ip_off & FRAGID_N) {
        T2_SET_STATUS(packet, IPV4_FRAG);
        numFragV4Packets++;
        return; // fragmentation switch off: ignore fragmented packets except the 1. protocol header
    }
#endif // FRAGMENTATION == 0

    const uint16_t i = (uint16_t)(packet->l3HdrP - packet->l2HdrP); // L2, VLAN length
    packet->snapL3Len = packet->snapL2Len - i; // L3 packet length

    const uint16_t calcL3Len = packet->rawLen - (packet->l3HdrP - packet->raw_packet);
    const uint16_t ipLen = ntohs(ipHdrP->ip_len); // get IP packet length from IP header
    const uint16_t l3Len = (!ipLen || ipLen > calcL3Len) ? calcL3Len : ipLen; // TSO case
    if (!ipLen && calcL3Len) packet->status |= IP_PL_MSMTCH;

    packet->l2HdrLen = i;
    const uint16_t l2Len = l3Len + i;
    packet->l2Len = l2Len;
    packet->l3Len = l3Len;
    bytesOnWire += l2Len; // estimate all Ethernet & IP bytes seen on wire

    // Layer 3 snaplength too short or IP packet too short?
    if (packet->snapL3Len < l3Len) {
        // Snap length warning
        packet->status |= L3SNAPLENGTH;
        if (!(globalWarn & L3SNAPLENGTH)) {
            globalWarn |= L3SNAPLENGTH;
#if VERBOSE > 0
            T2_WRN("snapL2Length: %" PRIu32 " - snapL3Length: %" PRIu32 " - IP length in header: %d",
                    packet->snapL2Len, packet->snapL3Len, l3Len);
#endif
        }
    } else if (packet->snapL3Len > l3Len) { // FIXME contradiction to line 791???
        packet->snapL2Len = l2Len;
        packet->snapL3Len = l3Len;
    }

    if (l3Len < 20) { // Layer 3 snaplength too short or IP packet too short?
        T2_SET_STATUS(packet, L3HDRSHRTLEN);
    }

    int32_t packetLen;

#if PACKETLENGTH == 0
    packetLen = l2Len;
#else // PACKETLENGTH != 0
    packetLen = l3Len;
#endif // PACKETLENGTH != 0

    // -------------------------------- layer 3 --------------------------------

#if PACKETLENGTH <= 1

#if (FRGIPPKTLENVIEW == 1 && FRAGMENTATION == 1)
    // IP packet view mode in case of fragmentation
    // remove IP header len only from 2nd++ frag if whole packet
    // statistical view is required: default
    if (ipHdrP->ip_off & FRAGID_N) packetLen -= packet->l3HdrLen;
#endif

    if (packetLen >= 0) {
        packet->len = packetLen;
    } else {
        packet->len = 0;
        T2_SET_STATUS(packet, L3HDRSHRTLEN);
    }
#endif // PACKETLENGTH <= 1

    // -------------------------------- layer 4 --------------------------------

    packet->l4Proto = ipHdrP->ip_p; // set l4Proto already for global plugins such as protoStats
    packet->l4HdrP = ((uint8_t*)ipHdrP + packet->l3HdrLen); // adjust header to the beginning of the encapsulated protocol

    const uint32_t l4ToEnd = packet->end_packet - packet->l4HdrP;
    uint16_t l4HdrOff;
#if FRAGMENTATION == 1
    if ((ipHdrP->ip_off & FRAGID_N) != FRAGID_1P_N) l4HdrOff = 0;
    else {
#endif
        switch (ipHdrP->ip_p) {
#if IPIP == 1
            case L3_IPIP4:
                l4HdrOff = (ipHdrP->ip_vhl & 0x0f) << 2;
                break;
#endif

            case L3_ICMP:
                l4HdrOff = sizeof(icmpHeader_t);
                break;

            case L3_TCP:
                if ((packet->status & L3SNAPLENGTH) && l4ToEnd < 20) {
                    l4HdrOff = 20;
                } else {
                    l4HdrOff = TCP_HEADER(packet)->doff << 2;
                }
                break;

            case L3_GRE:
#if GRE == 1
                l4HdrOff = (uint16_t)((uint8_t*)grePPP - (uint8_t*)greHD);
#else // GRE == 0
                l4HdrOff = 0;
#endif // GRE == 1
                break;

            case L3_OSPF: {
                const uint8_t version = *(packet->l4HdrP);
                switch (version) {
                    case 2: l4HdrOff = 24; break;  // OSPFv2
                    case 3: l4HdrOff = 16; break;  // OSPFv3
                    default:
#if VERBOSE > 2
                        T2_ERR("Packet %" PRIu64 ": Invalid OSPF version %" PRIu8, numPackets, version);
#endif
                        l4HdrOff = 16;
                        break;
                }
                break;
            }

            case L3_SCTP:
                l4HdrOff = 12;
                break;

            default:
                l4HdrOff = 8;
                break;
        }

        if ((packet->status & L3SNAPLENGTH) && l4ToEnd < l4HdrOff) {
            T2_SET_STATUS(packet, L4HDRSHRTLEN);
        }
#if FRAGMENTATION == 1
    }
#endif

    packet->l4HdrLen = l4HdrOff;

#if PACKETLENGTH >= 2
    packetLen -= IP_HL(ipHdrP) << 2;
#if PACKETLENGTH == 3 // subtract L4 header
    packetLen -= l4HdrOff;
#endif
    if (packetLen >= 0) {
        packet->len = packetLen;
    } else {
        packet->len = 0;
        T2_SET_STATUS(packet, L4HDRSHRTLEN);
    }
#endif // PACKETLENGTH >= 2

    // -------------------------------- layer 7 --------------------------------

    packet->l7Len = l3Len - packet->l3HdrLen - l4HdrOff;

    packet->l7HdrP = packet->l4HdrP + l4HdrOff;
    if (packet->snapL3Len >= l3Len) { // L3 length not snapped
        if (UNLIKELY(packet->snapL3Len < packet->l3HdrLen)) packet->snapL4Len = 0; // return or frag??? TODO
        else packet->snapL4Len = l3Len - packet->l3HdrLen;
        if (LIKELY(l4HdrOff < packet->snapL4Len)) packet->snapL7Len = packet->snapL4Len - l4HdrOff; // Protocol L3/4 header lengths are valid
        else packet->snapL7Len = 0;
    } else { // L3 length snapped so calculate real header L7 length
        if (UNLIKELY(packet->snapL3Len < packet->l3HdrLen)) packet->snapL4Len = 0; // return or frag??? TODO
        else packet->snapL4Len = packet->snapL3Len - packet->l3HdrLen;
        packet->snapL7Len = (uint16_t)(packet->l7HdrP - packet->l3HdrP); // offset between L3 and L7
        if (UNLIKELY(packet->snapL3Len < packet->snapL7Len)) packet->snapL7Len = 0;
        else packet->snapL7Len = packet->snapL3Len - packet->snapL7Len; // real L7 length
    }

    // source and destination port of a layer 4 header

#if (AGGREGATIONFLAG & SUBNET)
    packet->srcIPC.IPv4 = ipHdrP->ip_src;
    packet->dstIPC.IPv4 = ipHdrP->ip_dst;
    if (subnetTable4P) {
        uint32_t netNum = subnet_testHL4(subnetTable4P, ipHdrP->ip_src.s_addr); // subnet test src ip
        packet->subnetNrSrc = netNum;
#if (AGGREGATIONFLAG & SRCIP)
        packet->srcIP.IPv4.s_addr = ntohl(subnetTable4P->subnets[netNum].netID & NETIDMSK);
#else // (AGGREGATIONFLAG & SRCIP) == 0
        packet->srcIP.IPv4.s_addr = ntohl(subnetTable4P->subnets[netNum].netID);
#endif // (AGGREGATIONFLAG & SRCIP)
        netNum = subnet_testHL4(subnetTable4P, ipHdrP->ip_dst.s_addr); // subnet test dst ip
        packet->subnetNrDst = netNum;
#if (AGGREGATIONFLAG & DSTIP)
        packet->dstIP.IPv4.s_addr = ntohl(subnetTable4P->subnets[netNum].netID & NETIDMSK);
#else // (AGGREGATIONFLAG & DSTIP) == 0
        packet->dstIP.IPv4.s_addr = ntohl(subnetTable4P->subnets[netNum].netID);
#endif // (AGGREGATIONFLAG & DSTIP)
    }

#else // (AGGREGATIONFLAG & SUBNET) == 0

#if (AGGREGATIONFLAG & SRCIP)
    packet->srcIPC.IPv4 = ipHdrP->ip_src;
    packet->srcIP.IPv4.s_addr = ipHdrP->ip_src.s_addr & ntohl(SRCIP4MSK);
#else // (AGGREGATIONFLAG & SRCIP) == 0
    packet->srcIP.IPv4 = ipHdrP->ip_src;
#endif // (AGGREGATIONFLAG & SRCIP)

#if (AGGREGATIONFLAG & DSTIP)
    packet->dstIPC.IPv4 = ipHdrP->ip_dst;
    packet->dstIP.IPv4.s_addr = ipHdrP->ip_dst.s_addr & ntohl(DSTIP4MSK);
#else // (AGGREGATIONFLAG & DSTIP) == 0
    packet->dstIP.IPv4 = ipHdrP->ip_dst;
#endif // (AGGREGATIONFLAG & DSTIP)

#endif // (AGGREGATIONFLAG & SUBNET)

    flow_t hashHelper = {
#if ETH_ACTIVATE == 2
        .ethDS = ETH_HEADER(packet)->ethDS,
#endif
#if (IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0)
        .ethType = packet->ethType,
#endif
#if (AGGREGATIONFLAG & VLANID)
        .vlanId = 0,
#else // (AGGREGATIONFLAG & VLANID) == 0
        .vlanId = packet->vlanId,
#endif // (AGGREGATIONFLAG & VLANID)
        .srcIP = packet->srcIP,
        .dstIP = packet->dstIP,
        .l4Proto = packet->l4Proto,
    };

    if (!(packet->status & STPDSCT)) {
        packet->srcPort = 0;
        packet->dstPort = 0;
    }

#if FRAGMENTATION == 1

    unsigned long fragPendIndex;

    if (ipHdrP->ip_off & FRAGID_N) { // if 2nd++ fragmented packet

        if (priproto) T2_PKTDESC_ADD_PROTO(packet, ipHdrP->ip_p);

        hashHelper.fragID = ipHdrP->ip_id;
        fragPendIndex = hashTable_lookup(fragPendMap, (char*)&hashHelper.srcIP);

        if (fragPendIndex == HASHTABLE_ENTRY_NOT_FOUND) { // probably missed 1. frag packet or packet swap
            globalWarn |= (IPV4_FRAG | IPV4_FRAG_HDSEQ_ERR);
#if (VERBOSE > 0 && FRAG_ERROR_DUMP == 1)
            char srcIP[INET_ADDRSTRLEN];
            char dstIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(hashHelper.srcIP), srcIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(hashHelper.dstIP), dstIP, INET_ADDRSTRLEN);
            const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
            T2_PWRN("packetCapture", "1. frag not found @ %ld.%ld %" PRIu16
                    " %s %" PRIu16 " %s %" PRIu16 " %" PRIu8
                    " - 0x%04" B2T_PRIX16 " 0x%04" B2T_PRIX16 "- %" PRIu16 " pktn: %" PRIu64,
                    packet->pcapHdrP->ts.tv_sec, (long int)packet->pcapHdrP->ts.tv_usec, hashHelper.vlanId,
                    srcIP, ntohs(tcpHdrP->source), dstIP, ntohs(tcpHdrP->dest), packet->l4Proto,
                    ntohs(ipHdrP->ip_id), ntohs(ipHdrP->ip_off), ntohs(ipHdrP->ip_id), numPackets);
#endif // (VERBOSE > 0 && FRAG_ERROR_DUMP == 1)

#if FRAG_HLST_CRFT == 1
            sw_fnohead = IPV4_FRAG_HDSEQ_ERR;
            goto create_packetF; // we don't know the flow, but create one anyway, because might be interesting crafted packet
#else // FRAG_HLST_CRFT == 0
            return; // we don't know the flow, so ignore packet
#endif // FRAG_HLST_CRFT == 0
        } else {
            numFragV4Packets++;
            packet->status |= L2_IPV4;
            flowIndex = fragPend[fragPendIndex];
            flowP = &flows[flowIndex];
            if (!(ipHdrP->ip_off & MORE_FRAG_N)) {
                // remove packet from frag queue when last fragment received
                if (hashTable_remove(fragPendMap, (char*) &hashHelper.srcIP) == HASHTABLE_ENTRY_NOT_FOUND) {
                    T2_PWRN("packetCapture", "fragPend remove failed");
                }
                if (flowP->status & IPV4_FRAG_PENDING) {
                    flowP->status &= ~IPV4_FRAG_PENDING;
                }
            }
        }

    } else { // not fragmented or 1. fragmented packet

#endif // FRAGMENTATION == 1

        // encapsulated packet
        if (packet->status & STPDSCT) goto create_packetF;

        switch (packet->l4Proto) {
            case L3_IPIP4: { // IP in IP
                T2_SET_STATUS(packet, L3_IPIP);
                const uint8_t * const hp = packet->l3HdrP + packet->l3HdrLen;
#if IPIP == 0
                T2_PKTDESC_ADD_HDR(packet, ":ipv4");
                T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)hp)->ip_p);
                break;
#else // IPIP != 0
                if (hp > packet->end_packet || packet->l3HdrLen == 0) {
                    T2_SET_STATUS(packet, STPDSCT);
                    break;
                }
                packet->l3HdrP = hp;
                dissembleIPv4Packet(packet);
                return;
#endif // IPIP
            }

            case L3_IPIP6: {
                const ip6Header_t * const ip6HdrP = IPV6_HEADER(packet);
#if IPV6_ACTIVATE == 0 && IPIP == 0
                T2_PKTDESC_ADD_HDR(packet, ":ipv6");
                T2_PKTDESC_ADD_PROTO(packet, ip6HdrP->next_header);
                T2_SET_STATUS(packet, (FS_IPV6_PKT | STPDSCT));
                break;
#else // IPV6_ACTIVATE != 0 || IPIP == 1
                if ((uint8_t*)ip6HdrP + sizeof(ip6Header_t) > packet->end_packet) {
                    T2_PKTDESC_ADD_HDR(packet, ":ipv6");
                    T2_SET_STATUS(packet, STPDSCT);
                    break;
                }
                packet->l3HdrP = (uint8_t*)ip6HdrP;
                dissembleIPv6Packet(packet);
                return;
#endif // IPV6_ACTIVATE != 0 || IPIP == 1
            }

            case L3_TCP:
                if (priproto) {
                    T2_PKTDESC_ADD_HDR(packet, ":tcp");
                }
                if (l3Len < 40) {
                    T2_SET_STATUS(packet, L4HDRSHRTLEN);
                } else {
                    const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
                    const uint16_t sport = ntohs(tcpHdrP->source);
                    const uint16_t dport = ntohs(tcpHdrP->dest);
                    packet->srcPort = sport;
                    packet->dstPort = dport;
                    if ((dport == UPNP_PORT && sport > 1024) ||
                        (sport == UPNP_PORT && dport > 1024))
                    {
                        T2_PKTDESC_ADD_HDR(packet, ":ssdp");
                        T2_SET_STATUS(packet, L4_UPNP);
                    }
                }
                break;

            case L3_UDPLITE:
                if (priproto) {
                    T2_PKTDESC_ADD_HDR(packet, ":udplite");
                    priproto = false;
                }
                /* FALLTHRU */
            case L3_UDP:
                if (priproto) {
                    T2_PKTDESC_ADD_HDR(packet, ":udp");
                }
                if (l3Len < 28) {
                    T2_SET_STATUS(packet, L4HDRSHRTLEN);
                } else {
                    const udpHeader_t * const udpHdrP = UDP_HEADER(packet);
                    const uint16_t sport = ntohs(udpHdrP->source);
                    const uint16_t dport = ntohs(udpHdrP->dest);
                    packet->srcPort = sport;
                    packet->dstPort = dport;

#if L2TP == 0
                    if (t2_is_l2tp(sport, dport)) {
                        T2_PKTDESC_ADD_HDR(packet, ":l2tp");
                        T2_SET_STATUS(packet, L2_L2TP);
                        packet->l3Proto = L2TP_V2;
                    }
#endif // L2TP == 0

#if DTLS == 1
                    const dtls12Header_t *dtlsP = (dtls12Header_t*)(udpHdrP + 1);
                    while (dtlsP->ctype > 0x13 && dtlsP->ctype < 0x40) {
                        if (dtlsP->version == DTLS_V12_N) {
                            T2_PKTDESC_ADD_HDR(packet, ":dtls1.2");
                        } else if (dtlsP->version == DTLS_V10_N || dtlsP->version == DTLS_V10_OPENSSL_N) {
                            T2_PKTDESC_ADD_HDR(packet, ":dtls1.0");
                        } else {
                            break;
                        }
                        //else T2_PKTDESC_ADD_HDR(packet, ":dtls"); // test with snake oil
                        T2_SET_STATUS(packet, L7_DTLS);
                        numDTLSPackets++;
                        const int32_t dlen = sizeof(dtls12Header_t) + ntohs(dtlsP->len);
                        if ((packet->end_packet - (const uint8_t*)dtlsP) <= dlen) {
                            break;
                        }
                        dtlsP = (dtls12Header_t*)((char*)dtlsP + dlen);
                    }
#endif // DTLS == 1

                    if ((dport == UPNP_PORT && sport > 1024) ||
                        (sport == UPNP_PORT && dport > 1024))
                    {
                        T2_PKTDESC_ADD_HDR(packet, ":ssdp");
                        T2_SET_STATUS(packet, L4_UPNP);
                    } else if (dport == UDPENCAP_PORT || sport == UDPENCAP_PORT) { // checksum should be 0
                        // UDP encapsulation of IPsec
                        const uint8_t * const pktptr = packet->l4HdrP + sizeof(udpHeader_t);
                        T2_PKTDESC_ADD_HDR(packet, ":udpencap");
                        if (*pktptr == 0xff && (ntohs(udpHdrP->len) - sizeof(udpHeader_t)) == 1) {
                            // NAT-keepalive
                        } else if (*((uint32_t*)pktptr) != 0) {
                            T2_PKTDESC_ADD_HDR(packet, ":esp");
                            T2_SET_STATUS(packet, L3_IPSEC_ESP);
                        } else {
                            // TODO *(pktptr + 4) == 0xff? wireshark labels as data instead of isakmp
                            T2_PKTDESC_ADD_HDR(packet, ":isakmp");
                        }
                    }
                }
                break;

            case L3_GRE:
                if (priproto) {
                    T2_PKTDESC_ADD_HDR(packet, ":gre");
                }
                T2_SET_STATUS(packet, L2_GRE);
#if GRE == 1
                grePPP = (uint32_t*) packet->l4HdrP;
                greHD = grePPP++;
                packet->greHdrP = (greHeader_t*)greHD;
                packet->greL3HdrP = packet->l3HdrP;
                if (*greHD & GRE_CKSMn) grePPP++;
                if (*greHD & GRE_RTn) grePPP++;
                if (*greHD & GRE_KEYn) grePPP++;
                if (*greHD & GRE_SQn) grePPP++;
                if (*greHD & GRE_SSRn) grePPP++;
                if (*greHD & GRE_ACKn) grePPP++;
                if ((*greHD & GRE_PROTOn) == GRE_IP4n) {
                    T2_PKTDESC_ADD_HDR(packet, ":ipv4");
                    packet->l3HdrP = (uint8_t*)grePPP;
                    packet->l3Proto = ETHERTYPE_IP;
                    ipHdrP = IPV4_HEADER(packet);
                    packet->l3HdrLen = IP_HL(ipHdrP) << 2;
                } else if ((*greHD & GRE_PROTOn) == GRE_PPPn) {
                    T2_PKTDESC_ADD_HDR(packet, ":ppp");
                    T2_SET_STATUS(packet, L2_PPP);
                    packet->pppHdrP = (pppHu_t*)grePPP; // save PPP header
                    if ((*grePPP & 0x000000ff) == GRE_PPP_CMPRSS) {
                        // compressed, no readable header; info for later processing of flow
                        T2_PKTDESC_ADD_HDR(packet, ":comp_data");
                        T2_SET_STATUS(packet, (PPP_NRHD | STPDSCT));
                        break;
                    } else if (((pppHdr_t*)grePPP)->prot == PPP_IP4n) {
                        T2_PKTDESC_ADD_HDR(packet, ":ipv4");
                        packet->l3HdrP = (uint8_t*)(++grePPP);
                        packet->l3Proto = ETHERTYPE_IP;
                        ipHdrP = IPV4_HEADER(packet);
                        packet->l3HdrLen = IP_HL(ipHdrP) << 2;
                    } else if (((pppHdr_t*)grePPP)->prot == PPP_IP6n) {
#if IPV6_ACTIVATE > 0
                        packet->l3HdrP = (uint8_t*)(++grePPP);
                        dissembleIPv6Packet(packet);
                        return;
#else // IPV6_ACTIVATE == 0
                        T2_PKTDESC_ADD_HDR(packet, ":ipv6");
                        T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)(++grePPP))->next_header);
                        T2_SET_STATUS(packet, (FS_IPV6_PKT | STPDSCT));
                        break;
#endif // IPV6_ACTIVATE == 0
                    } else {
                        // Enhanced GRE (1) with payload length == 0
                        if ((*greHD & GRE_Vn) == 0x100 && (*(uint16_t*)((uint16_t*)greHD + 2) == 0)) {
                            packet->pppHdrP = NULL; // reset PPP header (not present)
                        } else {
                            T2_PKTDESC_ADD_PPPPROTO(packet, ((pppHdr_t*)grePPP)->prot);
                        }
                        T2_SET_STATUS(packet, STPDSCT);
                        break;
                    }
                } else if ((*greHD & GRE_PROTOn) == GRE_TEBn) {
                    const uint8_t *hp = (uint8_t*)grePPP;
                    const uint8_t * const hp1 = hp;
                    const uint16_t i = (uint16_t)(hp - packet->l2HdrP); // L2, VLAN length
                    hp += 12;
                    // check for 802.1Q/ad signature (VLANs)
                    _8021Q_t *shape = (_8021Q_t*)hp;
                    shape = t2_process_vlans(shape, packet);
                    if (hp != (uint8_t*)shape) hp = (uint8_t*)shape;
                    else hp += 2;

                    if (shape->identifier == ETHERTYPE_IPn) {
                        packet->l2HdrP = hp1;
                        packet->snapL2Len -= i;
                        packet->l3HdrP = hp;
                        dissembleIPv4Packet(packet);
                        return;
                    } else if (shape->identifier == ETHERTYPE_IPV6n) {
#if IPV6_ACTIVATE > 0
                        packet->l2HdrP = hp1;
                        packet->l3HdrP = hp;
                        packet->snapL2Len -= i;
                        dissembleIPv6Packet(packet);
                        return;
#else // IPV6_ACTIVATE == 0
                        T2_PKTDESC_ADD_HDR(packet, ":ipv6");
                        T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)hp)->next_header);
                        T2_SET_STATUS(packet, (FS_IPV6_PKT | STPDSCT));
                        break;
#endif // IPV6_ACTIVATE
                    } else {
                        T2_PKTDESC_ADD_ETHPROTO(packet, shape->identifier);
                        return;
                    }
                } else return;
#endif // GRE == 1
                break;

            case L3_ESP:
                T2_PKTDESC_ADD_HDR(packet, ":esp");
                T2_SET_STATUS(packet, L3_IPSEC_ESP);
                // TODO
                // - Detect and decode NULLL encrypted payload
                // - Analyze ESP next header (protocol) field
                break;

            case L3_AH: // authentication header
                T2_PKTDESC_ADD_HDR(packet, ":ah");
                T2_SET_STATUS(packet, L3_IPSEC_AH);
                T2_PKTDESC_ADD_PROTO(packet, *packet->l4HdrP);
                // TODO: check encapsulated protocol
                break;

            case L3_L2TP: // L2TPv3
                T2_PKTDESC_ADD_HDR(packet, ":l2tp");
                T2_SET_STATUS(packet, L2_L2TP);
                packet->l3Proto = L2TP_V3;
                break;

            case L3_SCTP: // SCTP, ports at the same position as TCP
                if (priproto) {
                    T2_PKTDESC_ADD_HDR(packet, ":sctp");
                }
                T2_SET_STATUS(packet, L4_SCTP);
                if (l3Len < 36) {
                    T2_SET_STATUS(packet, L4HDRSHRTLEN);
                } else {
                    const sctpHeader_t * const sctpHdrP = SCTP_HEADER(packet);
                    packet->srcPort = ntohs(sctpHdrP->source);
                    packet->dstPort = ntohs(sctpHdrP->dest);
                }
#if SCTP_ACTIVATE > 0
                sctpL7P = (uint8_t*)packet->l7HdrP;
                packet->l7SctpHdrP = sctpL7P;
                sctpChunkP = (sctpChunk_t*)sctpL7P;
                sctpChnkPLen = ntohs(sctpChunkP->len);
                sctpChnkLen = sctpChnkPLen;
                sctpL7Len = packet->snapL7Len;
                if (sctpChunkP->type == 0) {
                    packet->l7HdrP += 16;
                    const uint32_t sctpPad = 4 - sctpChnkLen % 4;
                    packet->sctpPad = sctpPad;
                    if (sctpPad < 4) sctpChnkPLen += sctpPad;
                    if (sctpL7Len >= sctpChnkLen) {
                        packet->snapSctpL7Len = sctpChnkLen;
                        if (sctpChnkLen < 16) packet->snapL7Len = 0;
                        else packet->snapL7Len = sctpChnkLen - 16;
                    } else {
                        packet->snapSctpL7Len = sctpL7Len;
                        if (sctpL7Len < 16) packet->snapL7Len = 0;
                        else packet->snapL7Len = sctpL7Len - 16;
                    }
                    if (sctpChnkLen < 16) packet->l7Len = 0;
                    else packet->l7Len = sctpChnkLen - 16;
                    packet->len = packet->l7Len;
                } else {
                    packet->l7HdrP += sctpChnkLen;
                    packet->snapSctpL7Len = sctpChnkLen;
                    packet->snapL7Len = 0;
                }
#endif // SCTP_ACTIVATE > 0
                break;

#if T2_PRI_HDRDESC == 1
            case L3_IGMP: {
                T2_PKTDESC_ADD_HDR(packet, ":igmp");
                const igmpHeader_t * const igmp = IGMP_HEADER(packet);
                switch (igmp->type) {
                    case IGMP_TYPE_DVMRP:
                        T2_PKTDESC_ADD_HDR(packet, ":dvmrp");
                        break;
                    case IGMP_TYPE_PIM:
                        T2_PKTDESC_ADD_HDR(packet, ":pim");
                        break;
                    case IGMP_TYPE_RGMP_LEAVE:
                    case IGMP_TYPE_RGMP_JOIN:
                    case IGMP_TYPE_RGMP_BYE:
                    case IGMP_TYPE_RGMP_HELLO:
                        if (ipHdrP->ip_dst.s_addr == IGMP_RGMP_DADDRn) { // 224.0.0.25
                            T2_PKTDESC_ADD_HDR(packet, ":rgmp");
                        }
                        break;
                    default:
                        break;
                }
                break;
            }
#endif // T2_PRI_HDRDESC == 1

            case L3_PIM: {
                T2_PKTDESC_ADD_HDR(packet, ":pim");
                const pimHeader_t * const pim = PIM_HEADER(packet);
                if (pim->type == PIM_TYPE_REGISTER) {
                    const uint8_t * const pktptr = ((uint8_t*)pim + PIM_REGISTER_LEN);
                    if ((*pktptr & 0xf0) == 0x40) {
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
                        packet->l3HdrP = pktptr;
                        dissembleIPv4Packet(packet);
                        return;
#else // IPV6_ACTIVATE == 1
                        T2_PKTDESC_ADD_HDR(packet, ":ipv4");
                        T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)pktptr)->ip_p);
#endif // IPV6_ACTIVATE == 1
                    } else if ((*pktptr & 0xf0) == 0x60) {
#if IPV6_ACTIVATE > 0
                        packet->l3HdrP = pktptr;
                        dissembleIPv6Packet(packet);
                        return;
#else // IPV6_ACTIVATE == 0
                        T2_PKTDESC_ADD_HDR(packet, ":ipv6");
                        T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)pktptr)->next_header);
                        T2_SET_STATUS(packet, (FS_IPV6_PKT | STPDSCT));
#endif // IPV6_ACTIVATE == 0
                    }
                }
                break;
            }

            default: // every other port = 0
                T2_PKTDESC_ADD_PROTO(packet, packet->l4Proto);
                break;
        }

create_packetF:

        packet->status |= L2_IPV4;

#if AGGREGATIONFLAG & SRCPORT
        packet->srcPortC = packet->srcPort;
#if SRCPORTLW == SRCPORTHW
        packet->srcPort = (packet->srcPort == SRCPORTLW) ? SRCPORTLW : 0;
#else // SRCPORTLW != SRCPORTHW
        packet->srcPort = (packet->srcPort >= SRCPORTLW && packet->srcPort <= SRCPORTHW) ? 1 : 0;
#endif // SRCPORTLW != SRCPORTHW
#endif // AGGREGATIONFLAG & SRCPORT
        hashHelper.srcPort = packet->srcPort;

#if AGGREGATIONFLAG & DSTPORT
        packet->dstPortC = packet->dstPort;
#if DSTPORTLW == DSTPORTHW
        packet->dstPort = (packet->dstPort == DSTPORTLW) ? DSTPORTLW : 0;
#else // DSTPORTLW != DSTPORTHW
        packet->dstPort = (packet->dstPort >= DSTPORTLW && packet->dstPort <= DSTPORTHW) ? 1 : 0;
#endif // DSTPORTLW != DSTPORTHW
#endif // AGGREGATIONFLAG & DSTPORT
        hashHelper.dstPort = packet->dstPort;

#if AGGREGATIONFLAG & L4PROT
        packet->l4ProtoC = packet->l4Proto;
        packet->l4Proto = 0;
#endif
        hashHelper.l4Proto = packet->l4Proto;

#if (IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0)
        hashHelper.ethType = packet->ethType;
#endif

#if SCTP_ACTIVATE & 1
        if (sctpChunkP) hashHelper.sctpStrm = sctpChunkP->sis;
#endif // SCTP_ACTIVATE & 1

#if SCTP_ACTIVATE & 2
        const sctpHeader_t * const sctpHdrP = SCTP_HEADER(packet);
        hashHelper.sctpVtag = sctpHdrP->verTag;
#endif // SCTP_ACTIVATE & 2

        flowIndex = hashTable_lookup(mainHashMap, (char*)&hashHelper.srcIP);
        if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
#if NOFLWCRT == 1
            if ((globalInt & GI_RUN) < GI_TERM_THRES) return;
#endif // NOFLWCRT == 1
//#if FRAG_HLST_CRFT == 1
//          if (sw_fnohead && !pBufStat) { // don't store the packet and return
//              memcpy(packetBuf, packet, packet->rawLen);
//              pBufStat |= FRAGBUF;
//              return;
//          }
//          if (pBufStat) swap packetBuf, packet;
//#endif
#if SUBNET_INIT == 1
            SUBNET_TEST_IP4(packet->subnetNrSrc, packet->srcIP);
            SUBNET_TEST_IP4(packet->subnetNrDst, packet->dstIP);
#endif // SUBNET_INIT == 1
#if FDURLIMIT > 0
cnflow4:
#endif // FDURLIMIT > 0
            flowIndex = flowCreate(packet, &hashHelper);
            flowP = &flows[flowIndex];

#if (SALRM == 1 && SUBNET_INIT == 1)
#if SALRMINV == 1
            if (!(packet->subnetNrSrc && packet->subnetNrDst)) {
#else // SALRMINV == 0
            if (packet->subnetNrSrc || packet->subnetNrDst) {
#endif // SALRMINV
                T2_SET_STATUS(flowP, FL_ALARM);
            }
#endif // (SALRM == 1 && SUBNET_INIT == 1)

        } else {
            flowP = &flows[flowIndex];
#if FDURLIMIT > 0
            if (actTime.tv_sec - flowP->firstSeen.tv_sec >= FDURLIMIT) {
#if (SUBNET_INIT == 1)
                packet->subnetNrSrc = flowP->subnetNrSrc;
                packet->subnetNrDst = flowP->subnetNrDst;
#endif // (SUBNET_INIT == 1)

                T2_SET_STATUS(flowP, RMFLOW);
                packet->status |= (flowP->status & L3FLOWINVERT);

#if FDLSFINDEX == 1
                packet->status |= FDLSIDX;
                packet->findex = flowP->findex;
#endif // FDLSFINDEX == 1

                //printf("flwfidx: %" PRIu64 "  %" PRIx64 "  %" PRIu64 ".%" PRIu64 "  %" PRIu64 ".%" PRIu64 "  %" PRIu64 "\n",
                //       flowP->findex, flowP->status, actTime.tv_sec, actTime.tv_usec, flowP->firstSeen.tv_sec, flowP->firstSeen.tv_usec, numPackets);

                lruPrintFlow(flowP);
                removeFlow(flowP);
                goto cnflow4;
            }
#endif // FDURLIMIT > 0

            updateLRUList(flowP);

            const ipHeader_t * const ipHdrP = IPV4_HEADER(packet);
            const uint32_t fragID = ipHdrP->ip_id;
            if (fragID && fragID == flowP->lastIPID) {
                T2_SET_STATUS(flowP, DUPIPID);
#if MULTIPKTSUP == 1
                return;
#endif
            }
            flowP->lastIPID = fragID;
        }

#if FRAGMENTATION == 1
        if ((ipHdrP->ip_off & FRAGIDM_N) == MORE_FRAG_N
#if FRAG_HLST_CRFT == 1
                || sw_fnohead
#endif
        ) { // if 1. fragmented packet or mangled fragment
#if FRAG_HLST_CRFT == 1
            if (sw_fnohead) T2_SET_STATUS(flowP, IPV4_FRAG_HDSEQ_ERR);
#endif // FRAG_HLST_CRFT == 1
            const ipHeader_t * const ipHdrP = IPV4_HEADER(packet);
            const uint32_t fragID = ipHdrP->ip_id;
            numFragV4Packets++;
            T2_SET_STATUS(flowP, IPV4_FRAG);
            packet->status |= IPV4_FRAG;
#if ETH_ACTIVATE == 2
            hashHelper.ethDS = ETH_HEADER(packet)->ethDS;
#endif
            hashHelper.srcIP = packet->srcIP; // flowCreate looked into reverse flow
            hashHelper.dstIP = packet->dstIP; // so set orig flow again
            hashHelper.fragID = fragID;
            fragPendIndex = HASHTABLE_ENTRY_NOT_FOUND; // no collision

            if (flowP->status & IPV4_FRAG_PENDING) {
                hashHelper.fragID = flowP->lastFragIPID;
                if (hashTable_remove(fragPendMap, (char*) &hashHelper.srcIP) == HASHTABLE_ENTRY_NOT_FOUND) {
#if VERBOSE > 2
                    char srcIP[INET_ADDRSTRLEN];
                    char dstIP[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(hashHelper.srcIP), srcIP, INET_ADDRSTRLEN);
                    inet_ntop(AF_INET, &(hashHelper.dstIP), dstIP, INET_ADDRSTRLEN);
                    T2_PWRN("packetCapture", "IPv4 remove IPID notfound: "
                            "findex: %" PRIu64 ", flowIndex: %lu, "
                            "srcIP: %s, srcPort: %" PRIu16 ", "
                            "dstIP: %s, dstPort: %" PRIu16 ", "
                            "IPID: 0x%04" B2T_PRIX16 ", flowStat: 0x%016" B2T_PRIX64,
                            flowP->findex, flowIndex,
                            srcIP, packet->srcPort,
                            dstIP, packet->dstPort,
                            fragID, flowP->status);
#endif // VERBOSE > 2
                    T2_SET_STATUS(flowP, IPV4_FRAG_ERR);
                } else if (flowP->lastFragIPID != fragID) {
                    T2_SET_STATUS(flowP, IPV4_FRAG_ERR);
                }
                // put back current IPID in hashHelper for the hashtable insert below
                hashHelper.fragID = fragID;
            } else if ((fragPendIndex = hashTable_lookup(fragPendMap, (char*)&hashHelper.srcIP)) != HASHTABLE_ENTRY_NOT_FOUND) {
                // IPID hash collision between two flows
                flow_t* flow2 = &flows[fragPend[fragPendIndex]];
#if VERBOSE > 2
                T2_PWRN("packetCapture", "two IPv4 flows (%" PRIu64 " and %" PRIu64 ") with same IPID hash", flow2->findex, flowP->findex);
                T2_PINF("packetCapture", "removing fragment of flow %" PRIu64 " pktn: %" PRIu64" fragID: %d", flow2->findex, numPackets, ntohs(fragID));
#endif
                flow2->status &= ~IPV4_FRAG_PENDING;
                // instead of removing fragment from hashmap here and adding the exact same
                // key below, we just check for collision before adding.
                fragPend[fragPendIndex] = flowIndex;
            }
            // if no collision, add new fragment to hashmap, on collision fragment is already in it.
            if (fragPendIndex == HASHTABLE_ENTRY_NOT_FOUND) {
                fragPendIndex = hashTable_insert(fragPendMap, (char*)&hashHelper.srcIP);
                if (UNLIKELY(fragPendIndex == HASHTABLE_ENTRY_NOT_FOUND)) { // Should not happen
                    T2_PFATAL("packetCapture", "IPv4 frag insert failed: "
                            "findex: %" PRIu64 ", flowIndex: %lu, "
                            "srcPort: %" PRIu16 ", dstPort: %" PRIu16 ", "
                            "IPID: 0x%04" B2T_PRIX32 ", flowStat: 0x%016" B2T_PRIX64,
                            flowP->findex, flowIndex,
                            packet->srcPort, packet->dstPort,
                            fragID, flowP->status);
                }
                fragPend[fragPendIndex] = flowIndex;
            }
            flowP->lastFragIPID = fragID;
            flowP->status |= IPV4_FRAG_PENDING;
        } else if (flowP->status & IPV4_FRAG_PENDING) {
            T2_SET_STATUS(flowP, IPV4_FRAG_ERR);
        }
    } // endif not fragmented or 1. fragmented packet
#endif // FRAGMENTATION == 1

//pcallback:

#if ETH_STAT_MODE == 1
    numPacketsL2[packet->outerEthType]++;
    numBytesL2[packet->outerEthType] += packet->snapLen;
#else // ETH_STAT_MODE == 0
    numPacketsL2[packet->ethType]++;
    numBytesL2[packet->ethType] += packet->snapLen;
#endif // ETH_STAT_MODE == 0

    numPacketsL3[packet->l4Proto]++;
    numBytesL3[packet->l4Proto] += packet->snapLen;

    if (packet->rawLen <= MINRAWLEN) {
        const int64_t pad = (int64_t)((int64_t)packet->rawLen - (int32_t)l3Len - (int64_t)((uint8_t*)ipHdrP - packet->raw_packet));
        if (pad < 0) {
            // TODO set a bit in flowStat?
        } else {
            packet->padLen = pad;
            flowP->padLen += pad;
            padBytesOnWire += pad;
        }
    }

    // Layer 2
    FOREACH_PLUGIN_DO(claimL2Info, packet, HASHTABLE_ENTRY_NOT_FOUND);

    // Layer 3 & 4

#if SCTP_ACTIVATE > 0
#if SCTP_ACTIVATE & 2
    const sctpHeader_t * const sctpHdrP = SCTP_HEADER(packet);
#endif // SCTP_ACTIVATE & 2
    while (1) {
#endif // SCTP_ACTIVATE > 0
        flowP->status |= packet->status;
        flowP->lastSeen = packet->pcapHdrP->ts;

        if (sPktFile) {
#if SPKTMD_PKTNO == 1
            fprintf(sPktFile, "%" PRIu64 /* pktNo   */ SEP_CHR
                              "%" PRIu64 /* flowInd */ SEP_CHR
                              , numPackets
                              , flowP->findex);
#else // SPKTMD_PKTNO == 0
            fprintf(sPktFile, "%" PRIu64 /* flowInd */ SEP_CHR, flowP->findex);
#endif // SPKTMD_PKTNO
        }

        // Layer 4
        FOREACH_PLUGIN_DO(claimL4Info, packet, flowIndex);

        if (sPktFile) t2_print_payload(sPktFile, packet);

#if SCTP_ACTIVATE > 0
        if (packet->l4Proto != L3_SCTP || sctpChnkLen < 1) break;
        sctpL7Len -= sctpChnkPLen;
        if (sctpL7Len < 4) break;
        sctpL7P += sctpChnkPLen;

#if ETH_ACTIVATE == 2
        hashHelper.ethDS = ETH_HEADER(packet)->ethDS;
#endif // ETH_ACTIVATE == 2

        hashHelper.srcIP = packet->srcIP; // flowCreate looked into reverse flow
        hashHelper.dstIP = packet->dstIP; // so set orig flow again
        hashHelper.srcPort = packet->srcPort;
        hashHelper.dstPort = packet->dstPort;

        packet->l7SctpHdrP = sctpL7P;
        packet->l7HdrP += sctpChnkPLen; // jump over previous chunk

        sctpChunkP = (sctpChunk_t*)sctpL7P;
        sctpChnkPLen = ntohs(sctpChunkP->len);
        sctpChnkLen = sctpChnkPLen;

#if SCTP_ACTIVATE & 2
        hashHelper.sctpVtag = sctpHdrP->verTag;
#endif // SCTP_ACTIVATE & 2

        if (sctpChunkP->type == 0) {
#if SCTP_ACTIVATE & 1
            hashHelper.sctpStrm = sctpChunkP->sis;
#endif // SCTP_ACTIVATE & 1
            const uint32_t sctpPad = 4 - sctpChnkLen % 4;
            if (sctpPad < 4) sctpChnkPLen += sctpPad;
            packet->sctpPad = sctpPad;
            if (sctpL7Len >= sctpChnkLen) {
                packet->snapSctpL7Len = sctpChnkLen;
                if (sctpChnkLen < 16) packet->snapL7Len = 0;
                else packet->snapL7Len = sctpChnkLen - 16;
            } else {
                packet->snapSctpL7Len = sctpL7Len;
                if (sctpL7Len < 16) packet->snapL7Len = 0;
                else packet->snapL7Len = sctpL7Len - 16;
            }
            if (sctpChnkLen < 16) packet->l7Len = 0;
            else packet->l7Len = sctpChnkLen - 16;
            packet->len = packet->l7Len;
        } else {
#if SCTP_ACTIVATE & 2
            hashHelper.sctpVtag = 0;
#endif // SCTP_ACTIVATE & 2
#if SCTP_ACTIVATE & 1
            hashHelper.sctpStrm = 0;
#endif // SCTP_ACTIVATE & 1
            packet->snapSctpL7Len = sctpChnkLen;
            packet->snapL7Len = 0;
        }

        flowIndex = hashTable_lookup(mainHashMap, (char*)&hashHelper.srcIP);
        if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
#if NOFLWCRT == 1
            if ((globalInt & GI_RUN) < GI_TERM_THRES) return;
#endif // NOFLWCRT == 1
            flowIndex = flowCreate(packet, &hashHelper);
            flowP = &flows[flowIndex];
        } else {
            flowP = &flows[flowIndex];
            updateLRUList(flowP);
        }
    }
#endif // SCTP_ACTIVATE > 0

    if (FLOW_IS_B(flowP)) {
        numBPackets++;
        numBBytes += packet->snapLen;
    } else {
        numAPackets++;
        numABytes += packet->snapLen;
    }

//  if (pBufStat & FRAGBUF) {
//      pBufStat = 0;
//      goto pcallback;
//  }
}
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2


inline void dissembleIPv6Packet(packet_t *packet) {
    uint16_t ip6HDLen = 40;

#if IPV6_ACTIVATE > 0

#if (FRAGMENTATION == 1 && FRAG_HLST_CRFT == 1)
    uint64_t sw_fnohead = 0;
#endif // (FRAGMENTATION == 1 && FRAG_HLST_CRFT == 1)

    flow_t *flowP;
    unsigned long flowIndex;
#endif // IPV6_ACTIVATE > 0

#if SCTP_ACTIVATE > 0
    int32_t sctpL7Len = 0, sctpChnkLen = 0, sctpChnkPLen = 0;
    sctpChunk_t *sctpChunkP = NULL;
    uint8_t *sctpL7P = NULL;
#endif // SCTP_ACTIVATE > 0

    ip6Header_t *ip6HdrP = IPV6_HEADER(packet);
    ip6FragHdr_t *ip6FragHdrP = NULL;
    ip6OptHdr_t *ip6OptHdrP = NULL;

    packet->ethType = ETHERTYPE_IPV6;
    packet->l3Proto = packet->ethType;
    T2_SET_STATUS(packet, FS_IPV6_PKT);

#if IPVX_INTERPRET == 1
    if ((ip6HdrP->vtc_flw_lbl & 0xf0) != 0x60) {
        T2_PKTDESC_ADD_HDR(packet, ":ipvx");
        T2_SET_STATUS(packet, L3_IPVX);
    } else
#endif // IPVX_INTERPRET == 1
        T2_PKTDESC_ADD_HDR(packet, ":ipv6");

    if (ip6HdrP->next_header == L3_FRAG6) {
        ip6FragHdrP = (ip6FragHdr_t*)(ip6HdrP + 1);
#if FRAGMENTATION == 0
        // do not handle fragmented packets
        if (ip6FragHdrP->frag_off & FRAG6ID_N) {
            T2_PKTDESC_ADD_HDR(packet, ":ipv6.fraghdr");
            globalWarn |= IPV4_FRAG;
            numFragV6Packets++;
            return; // fragmentation switch off: ignore fragmented packets except the 1. protocol header
        }
#endif // FRAGMENTATION == 0
    }

    const uint16_t iO = (uint16_t)(packet->l3HdrP - packet->l2HdrP); // L2, VLAN length
    packet->snapL3Len = packet->snapL2Len - iO; // L3 packet length

    const uint16_t calcL3LenO = packet->rawLen - (uint32_t)(packet->l3HdrP - packet->raw_packet);
    const uint16_t ip6LenO = ntohs(ip6HdrP->payload_len); // get IP packet length from IP header
    const uint16_t l3LenO = (!ip6LenO || ip6LenO + 40 > calcL3LenO) ? calcL3LenO : ip6LenO + 40; // TSO case
    if ((!ip6LenO && calcL3LenO) || l3LenO > calcL3LenO) packet->status |= IP_PL_MSMTCH;

    packet->l2HdrLen = iO;
    const uint16_t l2Len = packet->rawLen;
    bytesOnWire += l2Len; // estimate all Ethernet & IP bytes seen on wire
    packet->l2Len = l2Len;
    packet->l3Len = l3LenO;

    // Layer 3 snaplength too short or IP packet too short?
    if (packet->snapL3Len < l3LenO) {
        // Snap length warning
        packet->status |= L3SNAPLENGTH;
        if (!(globalWarn & L3SNAPLENGTH)) {
            globalWarn |= L3SNAPLENGTH;
#if VERBOSE > 0
            T2_WRN("Outer -- snapL2Length: %" PRIu32 " - snapL3Length: %" PRIu32 " - IP length in header: %d",
                    packet->snapL2Len, packet->snapL3Len, l3LenO);
#endif // VERBOSE > 0
        }
    } else if (packet->snapL3Len > l3LenO) {
        packet->snapL2Len = l2Len;
        packet->snapL3Len = l3LenO;
    }

#if (IPV6_ACTIVATE > 0 || PACKETLENGTH <= 1)
    int32_t packetLen;
#if PACKETLENGTH == 0
    packetLen = l2Len;
#else // PACKETLENGTH != 0
    packetLen = l3LenO;
#endif // PACKETLENGTH != 0
    packet->len = packetLen;
#endif // (IPV6_ACTIVATE > 0 || PACKETLENGTH <= 1)

    // -------------------------------- layer 3 --------------------------------

    // set l4Proto already for global plugins such as protoStats
    uint8_t nxtHdr = ip6HdrP->next_header;
    packet->l4Proto = nxtHdr;

#if (IPV6_ACTIVATE > 0 || SCTP_ACTIVATE > 0)
    uint16_t l4HdrOff;
#endif // (IPV6_ACTIVATE > 0 || SCTP_ACTIVATE > 0)

    for (uint_fast32_t j = 0; j < MAXHDRCNT; j++) {
        packet->srcPort = 0;
        packet->dstPort = 0;
        packet->l4HdrP = ((uint8_t*)ip6HdrP + ip6HDLen); // adjust header to the beginning of the encapsulated protocol
        const uint32_t l4ToEnd = packet->end_packet - packet->l4HdrP;
#if (IPV6_ACTIVATE > 0 || SCTP_ACTIVATE > 0)
        l4HdrOff = 0;
#endif // (IPV6_ACTIVATE > 0 || SCTP_ACTIVATE > 0)
        if (l4ToEnd < 8) break;
        switch (nxtHdr) {
            case L3_IPIP4: { // IPv4 in IPv6
                const uint8_t * const hp = packet->l4HdrP;
                if (hp > packet->end_packet) {
                    T2_PKTDESC_ADD_HDR(packet, ":ipv4");
                    T2_SET_STATUS(packet, (FS_IPV4_PKT | STPDSCT));
                    j = MAXHDRCNT;
                    break;
                }
#if IPIP == 1 && (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
                packet->l3HdrP = hp;
                dissembleIPv4Packet(packet);
                return;
#else // IPIP == 0 || IPV6_ACTIVATE == 1
                T2_PKTDESC_ADD_HDR(packet, ":ipv4");
                T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)hp)->ip_p);
                j = MAXHDRCNT;
                break;
#endif // IPIP && IPV6_ACTIVATE
            }

            case L3_HHOPT6: // options
                T2_PKTDESC_ADD_HDR(packet, ":ipv6.hopopts");
                ip6OptHdrP = (ip6OptHdr_t*)packet->l4HdrP;
                packet->ip6HHOptHdrP = ip6OptHdrP;
                goto dopt6p;

            case L3_DOPT6:
                T2_PKTDESC_ADD_HDR(packet, ":ipv6.dstopts");
                ip6OptHdrP = (ip6OptHdr_t*)packet->l4HdrP;
                packet->ip6DOptHdrP = ip6OptHdrP;
dopt6p:
                nxtHdr = ip6OptHdrP->next_header;
                const uint16_t io = (ip6OptHdrP->len + 1) << 3;
                ip6HDLen += io;
                continue;

            case L3_ICMP6:
                T2_PKTDESC_ADD_HDR(packet, ":icmpv6");
#if IPV6_ACTIVATE > 0
                l4HdrOff = 8;
                if ((packet->status & L3SNAPLENGTH) && l4ToEnd < l4HdrOff) {
                    T2_SET_STATUS(packet, L4HDRSHRTLEN);
                }
#endif // IPV6_ACTIVATE > 0
                j = MAXHDRCNT;
                break;

            case L3_TCP:
                T2_PKTDESC_ADD_HDR(packet, ":tcp");
#if IPV6_ACTIVATE > 0
                if ((packet->status & L3SNAPLENGTH) && l4ToEnd < 20) {
                    T2_SET_STATUS(packet, L4HDRSHRTLEN);
                    l4HdrOff = 20;
                } else {
                    l4HdrOff = TCP_HEADER(packet)->doff << 2;
                }
#endif // IPV6_ACTIVATE > 0
                if (l4ToEnd < 20) {
                    T2_SET_STATUS(packet, L4HDRSHRTLEN);
                } else {
                    const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
                    const uint16_t sport = ntohs(tcpHdrP->source);
                    const uint16_t dport = ntohs(tcpHdrP->dest);
                    packet->srcPort = sport;
                    packet->dstPort = dport;
                    if ((dport == UPNP_PORT && sport > 1024) ||
                        (sport == UPNP_PORT && dport > 1024))
                    {
                        T2_PKTDESC_ADD_HDR(packet, ":ssdp");
                        T2_SET_STATUS(packet, L4_UPNP);
                    }
                }
                j = MAXHDRCNT;
                break;

            case L3_UDPLITE:
            case L3_UDP:
                if (nxtHdr == L3_UDPLITE) {
                    T2_PKTDESC_ADD_HDR(packet, ":udplite");
                } else {
                    T2_PKTDESC_ADD_HDR(packet, ":udp");
                }
#if IPV6_ACTIVATE > 0
                l4HdrOff = 8;
#endif // IPV6_ACTIVATE > 0
                if (l4ToEnd < 8) {
                    T2_SET_STATUS(packet, L4HDRSHRTLEN);
                } else {
                    const udpHeader_t * const udpHdrP = UDP_HEADER(packet);
                    const uint16_t sport = ntohs(udpHdrP->source);
                    const uint16_t dport = ntohs(udpHdrP->dest);
                    packet->srcPort = sport;
                    packet->dstPort = dport;

#if DTLS == 1
                    const dtls12Header_t *dtlsP = (dtls12Header_t*)(udpHdrP + 1);
                    while (dtlsP->ctype > 0x13 && dtlsP->ctype < 0x40) {
                        if (dtlsP->version == DTLS_V12_N) {
                            T2_PKTDESC_ADD_HDR(packet, ":dtls1.2");
                        } else if (dtlsP->version == DTLS_V10_N || dtlsP->version == DTLS_V10_OPENSSL_N) {
                            T2_PKTDESC_ADD_HDR(packet, ":dtls1.0");
                        } else break;
                        //else T2_PKTDESC_ADD_HDR(packet, ":dtls"); // test with snake oil
                        T2_SET_STATUS(packet, L7_DTLS);
                        numDTLSPackets++;
                        const int32_t dlen = sizeof(dtls12Header_t) + ntohs(dtlsP->len);
                        if ((packet->end_packet - (const uint8_t*)dtlsP) <= dlen) break;
                        dtlsP = (dtls12Header_t*)((char*)dtlsP + dlen);
                    }
#endif // DTLS == 1

#if L2TP == 1
                    if (t2_is_l2tp(sport, dport)) {
                        uint8_t * const pktptr = (uint8_t*)packet->l4HdrP + sizeof(udpHeader_t);
                        if (!t2_process_l2tp(pktptr, packet)) return;
                    }
#endif // L2TP == 1

                    if ((dport == UPNP_PORT && sport > 1024) ||
                        (sport == UPNP_PORT && dport > 1024))
                    {
                        T2_PKTDESC_ADD_HDR(packet, ":ssdp");
                        T2_SET_STATUS(packet, L4_UPNP);
                    }

                    if (sport == 9899 && dport == 9899) { // SCTP tunneling ports
#if SCTP_ACTIVATE > 0
                        packet->l4HdrP += 8;
                        nxtHdr = L3_SCTP;
                        goto sctp6;
#else // SCTP_ACTIVATE == 0
                        //T2_SET_STATUS(packet, L2_SCTPTNL);
#endif // SCTP_ACTIVATE
                    }
                }
                j = MAXHDRCNT;
                break;

            case L3_IPIP6: { // IPv6 encapsulation
                T2_PKTDESC_ADD_HDR(packet, ":ipv6");
                T2_SET_STATUS(packet, L3_IPIP);
                const uint8_t * const hp = packet->l4HdrP;
#if IPIP == 0
                T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)hp)->next_header);
                j = MAXHDRCNT;
                break;
#else // IPIP == 1
                if (l4ToEnd < 40) {
                    T2_SET_STATUS(packet, STPDSCT);
                    j = MAXHDRCNT;
                    break;
                }
                packet->l3HdrP = hp;
                ip6HdrP = IPV6_HEADER(packet);
                nxtHdr = ip6HdrP->next_header;
                ip6HDLen = 40;
                continue;
#endif // IPIP == 1
            }

            case L3_ROUT6: { // routing
                T2_PKTDESC_ADD_HDR(packet, ":ipv6.routing");
                const ip6RouteHdr_t * const ip6RouteHdrP = (ip6RouteHdr_t*)packet->l4HdrP;
                packet->ip6RouteHdrP = ip6RouteHdrP;
                nxtHdr = ip6RouteHdrP->next_header;
                const uint16_t ir = (ip6RouteHdrP->len + 1) << 3;
                ip6HDLen += ir;
                continue;
            }

            case L3_FRAG6: // fragmentation
                T2_PKTDESC_ADD_HDR(packet, ":ipv6.fraghdr");
                ip6FragHdrP = (ip6FragHdr_t*)packet->l4HdrP;
                numFragV6Packets++;
#if FRAGMENTATION == 0
                // do not handle fragmented packets
                if (ip6FragHdrP->frag_off & FRAG6ID_N) {
                    globalWarn |= IPV4_FRAG;
                    return; // fragmentation switch off: ignore fragmented packets except the 1. protocol header
                }
#endif // FRAGMENTATION == 0
                nxtHdr = ip6FragHdrP->next_header;
                packet->ip6FragHdrP = ip6FragHdrP;
                ip6HDLen += 8;
                if (ip6FragHdrP->frag_off & FRAG6ID_N) { // 2nd++ fragmented packet
                    packet->l4HdrP += 8;
                    j = MAXHDRCNT;
                    break;
                }
                continue;

            case L3_GRE: {
                T2_PKTDESC_ADD_HDR(packet, ":gre");
                T2_SET_STATUS(packet, L2_GRE);
#if GRE == 1
                uint32_t *grePPP = (uint32_t*) packet->l4HdrP;
                const uint32_t * const greHD = grePPP++;
                packet->greHdrP = (greHeader_t*)greHD;
                packet->greL3HdrP = packet->l3HdrP;
                if (*greHD & GRE_CKSMn) grePPP++;
                if (*greHD & GRE_RTn) grePPP++;
                if (*greHD & GRE_KEYn) grePPP++;
                if (*greHD & GRE_SQn) grePPP++;
                if (*greHD & GRE_SSRn) grePPP++;
                if (*greHD & GRE_ACKn) grePPP++;
                if ((*greHD & GRE_PROTOn) == GRE_IP6n) {
                    packet->l3HdrP = (uint8_t*)grePPP;
                    packet->l3Proto = (uint16_t)(*greHD & GRE_PROTOn);
                    ip6HdrP = IPV6_HEADER(packet);
                    ip6HDLen = 40;
                    continue;
                } else if ((*greHD & GRE_PROTOn) == GRE_PPPn) {
                    T2_PKTDESC_ADD_HDR(packet, ":ppp");
                    T2_SET_STATUS(packet, L2_PPP);
                    packet->pppHdrP = (pppHu_t*)grePPP; // save PPP header
                    if ((*grePPP & 0x000000ff) == GRE_PPP_CMPRSS) {
                        // compressed, no readable header; info for later processing of flow
                        T2_PKTDESC_ADD_HDR(packet, ":comp_data");
                        T2_SET_STATUS(packet, (PPP_NRHD | STPDSCT));
                        j = MAXHDRCNT;
                        break;
                    } else if (((pppHdr_t*)grePPP)->prot == PPP_IP6n) {
                        packet->l3HdrP = (uint8_t*)(++grePPP);
                        packet->l3Proto = ETHERTYPE_IPV6;
                        ip6HdrP = IPV6_HEADER(packet);
                        ip6HDLen = 40;
                        continue;
                    } else {
                        // Enhanced GRE (1) with payload length == 0
                        if ((*greHD & GRE_Vn) == 0x100 && (*(uint16_t*)((uint16_t*)greHD + 2) == 0)) {
                            packet->pppHdrP = NULL; // reset PPP header (not present)
                        } else {
                            T2_PKTDESC_ADD_PPPPROTO(packet, ((pppHdr_t*)grePPP)->prot);
                        }
                        T2_SET_STATUS(packet, STPDSCT);
                        j = MAXHDRCNT;
                        break;
                    }
                } else if ((*greHD & GRE_PROTOn) == GRE_TEBn) {
                    const uint8_t * const hp = (uint8_t*)grePPP + 12;
                    packet->l3HdrP = (hp + 2);
                    ip6HdrP = IPV6_HEADER(packet);
                    packet->l3Proto = ntohs(*(uint16_t*)hp);
                    ip6HDLen = 40;
                    continue;
                } else {
                    T2_PKTDESC_ADD_ETHPROTO(packet, ((*greHD & GRE_PROTOn) >> 16));
                    T2_SET_STATUS(packet, STPDSCT);
                    j = MAXHDRCNT;
                    break;
                }

#else // GRE == 0
#if IPV6_ACTIVATE > 0
                if (!(*(uint16_t*)packet->l4HdrP & 0x000080f0)) l4HdrOff = 8;
#endif
#endif // GRE == 0
                j = MAXHDRCNT;
                break;
            }

            case L3_AH: { // authentication header
                T2_PKTDESC_ADD_HDR(packet, ":ah");
                const ip6AHHdr_t * const ip6AHHdrP = (ip6AHHdr_t*)packet->l4HdrP;
                T2_SET_STATUS(packet, L3_IPSEC_AH);
                nxtHdr = ip6AHHdrP->next_header;
                const uint16_t i = (ip6AHHdrP->len + 2) << 2;
                ip6HDLen += i;
                continue;
            }

#if ETHIP == 1
            case L3_ETHIP: { // ethernet within ipv6
                const uint8_t *hp = packet->l3HdrP + ip6HDLen;
                if ((*hp & 0xf0) < ETHIPVERN) return;
                //const uint8_t * const hp1 = hp;
                T2_PKTDESC_ADD_HDR(packet, ":etherip");
                T2_PKTDESC_ADD_HDR(packet, ":eth");
                T2_SET_STATUS(packet, L3_ETHIPF);
                const uint16_t ie = (uint16_t)(hp - packet->l2HdrP) + 2; // L2, VLAN length
                packet->snapL2Len -= ie;
                packet->l2Len -= ie;
                packet->l2HdrP = (hp + 2);

                hp += 14;

                // check for 802.1Q/ad signature (VLANs)
                _8021Q_t *shape = (_8021Q_t*)hp;
                shape = t2_process_vlans(shape, packet);
                hp = (uint8_t*)shape + 2;
                if (shape->identifier == ETHERTYPE_IPV6n) {
                    packet->l3HdrP = hp;
                    T2_PKTDESC_ADD_HDR(packet, ":ipv6");
                    ip6HdrP = (ip6Header_t*)hp;
                    packet->l3Proto = ntohs(*(uint16_t*)(hp - 2));
                    ip6HDLen = 40;
                    continue;
                } else if (shape->identifier == ETHERTYPE_IPn) {
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
                    packet->l3HdrP = hp;
                    dissembleIPv4Packet(packet);
                    return;
#else // IPV6_ACTIVATE == 1
                    T2_PKTDESC_ADD_HDR(packet, ":ipv4");
                    T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)(hp))->ip_p);
#endif // IPV6_ACTIVATE == 1
                } else {
                    T2_PKTDESC_ADD_ETHPROTO(packet, shape->identifier);
                }
#if IPV6_ACTIVATE > 0
                l4HdrOff = 0;
#endif
                T2_SET_STATUS(packet, STPDSCT);
                j = MAXHDRCNT;
                break;
            }
#endif // ETHIP == 1

            case L3_OSPF: {
                T2_PKTDESC_ADD_HDR(packet, ":ospf");
#if IPV6_ACTIVATE > 0
                const uint8_t version = *packet->l4HdrP;
                switch (version) {
                    case 2: l4HdrOff = 24; break;
                    case 3: l4HdrOff = 16; break;
                    default:
#if VERBOSE > 2
                        T2_ERR("Packet %" PRIu64 ": Invalid OSPF version %" PRIu8, numPackets, version);
#endif
                        l4HdrOff = 16;
                        break;
                }
#endif // IPV6_ACTIVATE > 0
                j = MAXHDRCNT;
                break;
            }

            case L3_L2TP: // L2TPv3
                T2_PKTDESC_ADD_HDR(packet, ":l2tp");
                T2_SET_STATUS(packet, L2_L2TP);
                packet->l3Proto = L2TP_V3;
                j = MAXHDRCNT;
                break;

            case L3_SCTP:
#if SCTP_ACTIVATE > 0
sctp6:
#endif // SCTP_ACTIVATE > 0
                T2_PKTDESC_ADD_HDR(packet, ":sctp");
                T2_SET_STATUS(packet, L4_SCTP);

#if (IPV6_ACTIVATE > 0 || SCTP_ACTIVATE > 0)
                l4HdrOff = 12;
                if ((packet->status & L3SNAPLENGTH) && l4ToEnd < l4HdrOff) {
                    T2_SET_STATUS(packet, L4HDRSHRTLEN);
                }
#endif // (IPV6_ACTIVATE > 0 || SCTP_ACTIVATE > 0)

                if (l4ToEnd < 16) {
                    T2_SET_STATUS(packet, L4HDRSHRTLEN);
                } else {
                    const sctpHeader_t * const sctpHdrP = SCTP_HEADER(packet);
                    packet->srcPort = ntohs(sctpHdrP->source);
                    packet->dstPort = ntohs(sctpHdrP->dest);
                }

#if SCTP_ACTIVATE > 0 // this code goes beyond the l7snaplen calc or the snapL7Len, packetLen etc calc is omitted for sctp
                packet->l7HdrP = packet->l4HdrP + l4HdrOff;
                sctpL7P = (uint8_t*)packet->l7HdrP;
                packet->l7SctpHdrP = sctpL7P;
                sctpChunkP = (sctpChunk_t*)sctpL7P;
                sctpChnkPLen = ntohs(sctpChunkP->len);
                sctpChnkLen = sctpChnkPLen;
                sctpL7Len = l4ToEnd - l4HdrOff;
                if (sctpChunkP->type == 0) {
                    packet->l7HdrP += 16;
                    const uint32_t sctpPad = 4 - sctpChnkLen % 4;
                    if (sctpPad < 4) sctpChnkPLen += sctpPad;
                    packet->sctpPad = sctpPad;
                    if (sctpL7Len >= sctpChnkLen) {
                        packet->snapSctpL7Len = sctpChnkLen;
                        if (sctpChnkLen < 16) packet->snapL7Len = 0;
                        else packet->snapL7Len = sctpChnkLen - 16;
                    } else {
                        packet->snapSctpL7Len = sctpL7Len;
                        if (sctpL7Len < 16) packet->snapL7Len = 0;
                        else packet->snapL7Len = sctpL7Len - 16;
                    }
                    if (sctpChnkLen < 16) packet->l7Len = 0;
                    else packet->l7Len = sctpChnkLen - 16;
                    packet->len = packet->l7Len;
                } else {
                    packet->l7HdrP += sctpChnkLen;
                    packet->snapSctpL7Len = sctpChnkLen;
                    packet->snapL7Len = 0;
                }
#endif // SCTP_ACTIVATE > 0

                j = MAXHDRCNT;
                break;

            case L3_PIM: {
                T2_PKTDESC_ADD_HDR(packet, ":pim");
                const pimHeader_t * const pim = PIM_HEADER(packet);
                if (pim->type == PIM_TYPE_REGISTER) {
                    const uint8_t * const pktptr = ((uint8_t*)pim + PIM_REGISTER_LEN);
                    if ((*pktptr & 0xf0) == 0x40) {
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
                        packet->l3HdrP = pktptr;
                        dissembleIPv4Packet(packet);
                        return;
#else // IPV6_ACTIVATE == 1
                        T2_PKTDESC_ADD_HDR(packet, ":ipv4");
                        T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)pktptr)->ip_p);
#endif // IPV6_ACTIVATE == 1
                    } else if ((*pktptr & 0xf0) == 0x60) {
#if IPV6_ACTIVATE > 0
                        packet->l3HdrP = pktptr;
                        ip6HdrP = IPV6_HEADER(packet);
                        nxtHdr = ip6HdrP->next_header;
                        ip6HDLen = 40;
                        continue;
                        //dissembleIPv6Packet(packet);
                        //return;
#else // IPV6_ACTIVATE == 0
                        T2_PKTDESC_ADD_HDR(packet, ":ipv6");
                        T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)pktptr)->next_header);
                        T2_SET_STATUS(packet, (FS_IPV6_PKT | STPDSCT));
#endif // IPV6_ACTIVATE == 0
                    }
                }
                j = MAXHDRCNT;
                break;
            }

            case L3_NXTH6:
#if IPV6_ACTIVATE > 0
                l4HdrOff = 0;
#endif // IPV6_ACTIVATE > 0
                j = MAXHDRCNT;
                break;

            default: // all other protocols not implemented yet
                T2_PKTDESC_ADD_PROTO(packet, nxtHdr);
                j = MAXHDRCNT;
                break;
            }
        }

#if IPV6_ACTIVATE == 0
        return;
    }
#else // IPV6_ACTIVATE > 0

    packet->l4Proto = nxtHdr; // set l4Proto already for global plugins such as protoStats
    packet->l3HdrLen = ip6HDLen;
    const uint32_t l3ToEnd = packet->end_packet - packet->l3HdrP;
    packet->snapL3Len = l3ToEnd;

    const uint16_t calcL3Len = packet->rawLen - (uint32_t)(packet->l3HdrP - packet->raw_packet);
    const uint16_t ip6Len = ntohs(ip6HdrP->payload_len); // get IP packet length from IP header
    const uint16_t l3Len = (!ip6Len || ip6Len + 40 > calcL3Len) ? calcL3Len : ip6Len + 40; // TSO case
    packet->l3Len = l3Len;
    if (!ip6Len && calcL3Len) packet->status |= IP_PL_MSMTCH;

    // -------------------------------- layer 4 --------------------------------
    const int32_t l4ToEnd = packet->end_packet - packet->l4HdrP;

#if SCTP_ACTIVATE & 2
    const sctpHeader_t * const sctpHdrP = SCTP_HEADER(packet);
#endif // SCTP_ACTIVATE & 2

    if (ip6FragHdrP && (ip6FragHdrP->frag_off & FRAG6ID_N)) l4HdrOff = 0; // 2nd++ fragmented packet

    packet->l4HdrLen = l4HdrOff;


    // -------------------------------- layer 7 --------------------------------

#if SCTP_ACTIVATE == 0
    packet->l7Len = l3Len - ip6HDLen - l4HdrOff;
#endif // SCTP_ACTIVATE == 0

    packet->l7HdrP = packet->l4HdrP + l4HdrOff;

    if (packet->snapL3Len >= l3Len) { // L3 length not snapped
        if (UNLIKELY(packet->snapL3Len < packet->l3HdrLen)) packet->snapL4Len = 0; // return or frag??? TODO
        else packet->snapL4Len = l4ToEnd; // Protocol L3/4 header lengths are valid
#if SCTP_ACTIVATE == 0
        if (LIKELY(l4HdrOff < packet->snapL4Len)) packet->snapL7Len = packet->snapL4Len - l4HdrOff; // Protocol L3/4 header lengths are valid
        else packet->snapL7Len = 0;
#endif // SCTP_ACTIVATE == 0
    } else { // L3 length snapped so calculate real header L7 length
        if (UNLIKELY(packet->snapL3Len < packet->l3HdrLen)) packet->snapL4Len = 0; // return or frag??? TODO
        else packet->snapL4Len = l4ToEnd;
        packet->snapL7Len = (uint16_t)(packet->l7HdrP - packet->l3HdrP); // offset between L3 and L7
#if SCTP_ACTIVATE == 0
        if (UNLIKELY(packet->snapL3Len < packet->snapL7Len)) packet->snapL7Len = 0;
        else packet->snapL7Len = (uint16_t)(packet->end_packet - packet->l7HdrP); // real L7 length
#endif // SCTP_ACTIVATE == 0
    }

#if PACKETLENGTH == 0
    packetLen = l2Len;
#elif PACKETLENGTH == 1
    packetLen = l3Len;
#elif PACKETLENGTH == 2
    packetLen = l3Len - ip6HDLen;
#else // PACKETLENGTH == 3
    packetLen = packet->l7Len;
#endif // PACKETLENGTH

#if PACKETLENGTH >= 2
    if (packetLen >= 0) {
        packet->len = packetLen;
    } else {
        packet->len = 0;
        T2_SET_STATUS(packet, L4HDRSHRTLEN);
    }
#endif // PACKETLENGTH >= 2

#if (AGGREGATIONFLAG & SUBNET)
    packet->srcIPC = ip6HdrP->ip_src;
    packet->dstIPC = ip6HdrP->ip_dst;
    if (subnetTable6P) {
        uint32_t netNum = subnet_testHL6(subnetTable6P, ip6HdrP->ip_src); // subnet test src ip
        packet->subnetNrSrc = netNum;
#if (AGGREGATIONFLAG & SRCIP)
        packet->srcIP.IPv6L[0] = ntohl(subnetTable6P->subnets[netNum].netID & NETIDMSK);
#else // (AGGREGATIONFLAG & SRCIP) == 0
        packet->srcIP.IPv6L[0] = ntohl(subnetTable6P->subnets[netNum].netID);
#endif // (AGGREGATIONFLAG & SRCIP)
        packet->srcIP.IPv6L[1] = 0;
        netNum = subnet_testHL6(subnetTable6P, ip6HdrP->ip_dst); // subnet test dst ip
        packet->subnetNrDst = netNum;
#if (AGGREGATIONFLAG & DSTIP)
        packet->dstIP.IPv6L[0] = ntohl(subnetTable6P->subnets[netNum].netID & NETIDMSK);
#else // (AGGREGATIONFLAG & DSTIP) == 0
        packet->dstIP.IPv6L[0] = ntohl(subnetTable6P->subnets[netNum].netID);
#endif // (AGGREGATIONFLAG & DSTIP)
        packet->dstIP.IPv6L[1] = 0;
    }

#else // (AGGREGATIONFLAG & SUBNET) == 0

#if (AGGREGATIONFLAG & SRCIP)
    packet->srcIPC = ip6HdrP->ip_src;
    packet->srcIP.IPv6L[0] = ip6HdrP->ip_src.IPv6L[0] & be64toh(SRCIP6MSKH);
    packet->srcIP.IPv6L[1] = ip6HdrP->ip_src.IPv6L[1] & be64toh(SRCIP6MSKL);
#else // (AGGREGATIONFLAG & SRCIP) == 0
    packet->srcIP = ip6HdrP->ip_src;
#endif // (AGGREGATIONFLAG & SRCIP)

#if (AGGREGATIONFLAG & DSTIP)
    packet->dstIPC = ip6HdrP->ip_dst;
    packet->dstIP.IPv6L[0] = ip6HdrP->ip_dst.IPv6L[0] & be64toh(DSTIP6MSKH);
    packet->dstIP.IPv6L[1] = ip6HdrP->ip_dst.IPv6L[1] & be64toh(DSTIP6MSKL);
#else // (AGGREGATIONFLAG & DSTIP) == 0
    packet->dstIP = ip6HdrP->ip_dst;
#endif // (AGGREGATIONFLAG & DSTIP)

#endif // (AGGREGATIONFLAG & SUBNET)

    flow_t hashHelper = {
#if ETH_ACTIVATE == 2
        .ethDS   = ETH_HEADER(packet)->ethDS,
#endif
#if (IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0)
        .ethType = packet->ethType,
#endif
#if (AGGREGATIONFLAG & VLANID)
        .vlanId  = 0,
#else // (AGGREGATIONFLAG & VLANID) == 0
        .vlanId  = packet->vlanId,
#endif // (AGGREGATIONFLAG & VLANID)
        .srcIP   = packet->srcIP,
        .dstIP   = packet->dstIP,
    };

#if FRAGMENTATION == 1
    unsigned long fragPendIndex;

    if (ip6FragHdrP && (ip6FragHdrP->frag_off & FRAG6ID_N)) { // 2nd++ fragmented packet

        hashHelper.fragID = ip6FragHdrP->id;
        fragPendIndex = hashTable_lookup(fragPendMap, (char*)&hashHelper.srcIP);

        if (fragPendIndex == HASHTABLE_ENTRY_NOT_FOUND) { // probably missed 1. frag packet or packet mangling
            globalWarn |= (IPV4_FRAG | IPV4_FRAG_HDSEQ_ERR);
#if (VERBOSE > 0 && FRAG_ERROR_DUMP == 1)
            char srcIP[INET6_ADDRSTRLEN];
            char dstIP[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(hashHelper.srcIP), srcIP, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(hashHelper.dstIP), dstIP, INET6_ADDRSTRLEN);
            const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
            T2_PWRN("packetCapture", "1. frag not found @ %ld.%ld %" PRIu16
                    " %s %" PRIu16 " %s %" PRIu16 " %" PRIu8
                    " - 0x%08" B2T_PRIX32 " 0x%04" B2T_PRIX16 "- %" PRIu32 " pktn: %" PRIu64,
                    packet->pcapHdrP->ts.tv_sec, (long int)packet->pcapHdrP->ts.tv_usec, hashHelper.vlanId,
                    srcIP, ntohs(tcpHdrP->source), dstIP, ntohs(tcpHdrP->dest), packet->l4Proto,
                    ntohl(hashHelper.fragID), ntohs(ip6FragHdrP->frag_off), ntohl(ip6FragHdrP->id), numPackets);
#endif // (VERBOSE > 0 && FRAG_ERROR_DUMP == 1)

#if FRAG_HLST_CRFT == 1
            sw_fnohead = IPV4_FRAG_HDSEQ_ERR;
            goto create_packetF6; // we don't know the flow, but create one anyway, because might be interesting crafted packet
#else // FRAG_HLST_CRFT == 0
            return; // we don't know the flow, so ignore packet
#endif // FRAG_HLST_CRFT == 0
        } else {
            numFragV6Packets++;
            packet->status |= L2_IPV6;
            flowIndex = fragPend[fragPendIndex];
            flowP = &flows[flowIndex];
            if (!(ip6FragHdrP->frag_off & MORE_FRAG6_N)) {
                // remove packet from frag queue when last fragment received
                if (hashTable_remove(fragPendMap, (char*) &hashHelper.srcIP) == HASHTABLE_ENTRY_NOT_FOUND) {
                    T2_PWRN("packetCapture", "fragPend remove failed");
                }
                if (flowP->status & IPV4_FRAG_PENDING) {
                    flowP->status &= ~IPV4_FRAG_PENDING;
                }
            }
        }
    } else { // not fragmented or 1. fragmented packet

#if FRAG_HLST_CRFT == 1
create_packetF6:
#endif

#endif // FRAGMENTATION == 1

        packet->status |= L2_IPV6;

#if AGGREGATIONFLAG & SRCPORT
        packet->srcPortC = packet->srcPort;
#if SRCPORTLW == SRCPORTHW
        packet->srcPort = (packet->srcPort == SRCPORTLW) ? SRCPORTLW : 0;
#else // SRCPORTLW != SRCPORTHW
        packet->srcPort = (packet->srcPort >= SRCPORTLW && packet->srcPort <= SRCPORTHW) ? 1 : 0;
#endif // SRCPORTLW != SRCPORTHW
#endif // AGGREGATIONFLAG & SRCPORT

#if AGGREGATIONFLAG & DSTPORT
        packet->dstPortC = packet->dstPort;
#if DSTPORTLW == DSTPORTHW
        packet->dstPort = (packet->dstPort == DSTPORTLW) ? DSTPORTLW : 0;
#else // DSTPORTLW != DSTPORTHW
        packet->dstPort = (packet->dstPort >= DSTPORTLW && packet->dstPort <= DSTPORTHW) ? 1 : 0;
#endif // DSTPORTLW != DSTPORTHW
#endif // AGGREGATIONFLAG & DSTPORT

#if AGGREGATIONFLAG & L4PROT
        packet->l4ProtoC = packet->l4Proto;
        packet->l4Proto = 0;
#endif // AGGREGATIONFLAG & L4PROT

        hashHelper.srcPort = packet->srcPort;
        hashHelper.dstPort = packet->dstPort;
        hashHelper.l4Proto = packet->l4Proto;

#if (IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0)
        hashHelper.ethType = packet->ethType;
#endif

#if SCTP_ACTIVATE & 1
        if (sctpChunkP) hashHelper.sctpStrm = sctpChunkP->sis;
#endif // SCTP_ACTIVATE & 1

#if SCTP_ACTIVATE & 2
        hashHelper.sctpVtag = sctpHdrP->verTag;
#endif // SCTP_ACTIVATE & 2

        flowIndex = hashTable_lookup(mainHashMap, (char*)&hashHelper.srcIP);
        if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
#if NOFLWCRT == 1
            if ((globalInt & GI_RUN) < GI_TERM_THRES) return;
#endif // NOFLWCRT == 1
#if SUBNET_INIT == 1
            SUBNET_TEST_IP6(packet->subnetNrSrc, packet->srcIP);
            SUBNET_TEST_IP6(packet->subnetNrDst, packet->dstIP);
#endif // SUBNET_INIT == 1

#if FDURLIMIT > 0
cnflow6:
#endif // FDURLIMIT > 0
            flowIndex = flowCreate(packet, &hashHelper);
            flowP = &flows[flowIndex];
        } else {
            flowP = &flows[flowIndex];
#if FDURLIMIT > 0
            if (actTime.tv_sec - flowP->firstSeen.tv_sec >= FDURLIMIT) {
#if (SUBNET_INIT == 1)
                packet->subnetNrSrc = flowP->subnetNrSrc;
                packet->subnetNrDst = flowP->subnetNrDst;
#endif // (SUBNET_INIT == 1)

                T2_SET_STATUS(flowP, RMFLOW);
                packet->status |= (flowP->status & L3FLOWINVERT);

#if FDLSFINDEX == 1
                packet->status |= FDLSIDX;
                packet->findex = flowP->findex;
#endif // FDLSFINDEX == 1

                //printf("flwfidx: %" PRIu64 "  %" PRIx64 "  %" PRIu64 ".%" PRIu64 "  %" PRIu64 ".%" PRIu64 "  %" PRIu64 "\n",
                //       flowP->findex, flowP->status, actTime.tv_sec, actTime.tv_usec, flowP->firstSeen.tv_sec, flowP->firstSeen.tv_usec, numPackets);

                lruPrintFlow(flowP);
                removeFlow(flowP);
                goto cnflow6;
            }
#endif // FDURLIMIT > 0

            updateLRUList(flowP);
        }

#if FRAGMENTATION == 1
        if ((ip6FragHdrP && (ip6FragHdrP->frag_off & FRAG6IDM_N) == MORE_FRAG6_N)
#if FRAG_HLST_CRFT == 1
                || sw_fnohead
#endif
        ) { // if 1. fragmented packet or mangled fragment
#if FRAG_HLST_CRFT == 1
            if (sw_fnohead) T2_SET_STATUS(flowP, IPV4_FRAG_HDSEQ_ERR);
#endif // FRAG_HLST_CRFT == 1

            const uint32_t fragID = packet->ip6FragHdrP->id;
            numFragV6Packets++;
            T2_SET_STATUS(flowP, IPV4_FRAG);

#if ETH_ACTIVATE == 2
            hashHelper.ethDS = ETH_HEADER(packet)->ethDS;
#endif

            hashHelper.srcIP = packet->srcIP; // flowCreate looked into reverse flow
            hashHelper.dstIP = packet->dstIP; // so set orig flow again
            hashHelper.fragID = fragID;
            fragPendIndex = HASHTABLE_ENTRY_NOT_FOUND; // no collision

            if (flowP->status & IPV4_FRAG_PENDING) {
                hashHelper.fragID = flowP->lastFragIPID;
                if (hashTable_remove(fragPendMap, (char*) &hashHelper.srcIP) == HASHTABLE_ENTRY_NOT_FOUND) {
#if VERBOSE > 2
                    char srcIP[INET6_ADDRSTRLEN];
                    char dstIP[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &(hashHelper.srcIP), srcIP, INET6_ADDRSTRLEN);
                    inet_ntop(AF_INET6, &(hashHelper.dstIP), dstIP, INET6_ADDRSTRLEN);
                    T2_PWRN("packetCapture", "IPv6 remove IPID notfound: "
                            "findex: %" PRIu64 ", flowIndex: %lu, "
                            "srcIP: %s, srcPort: %" PRIu16 ", "
                            "dstIP: %s, dstPort: %" PRIu16 ", "
                            "IPID: 0x%08" B2T_PRIX32 ", flowStat: 0x%016" B2T_PRIX64,
                            flowP->findex, flowIndex,
                            srcIP, packet->srcPort,
                            dstIP, packet->dstPort,
                            fragID, flowP->status);
#endif // VERBOSE > 2
                    T2_SET_STATUS(flowP, IPV4_FRAG_ERR);
                } else if (flowP->lastFragIPID != fragID) {
                    T2_SET_STATUS(flowP, IPV4_FRAG_ERR);
                }
                // put back current IPID in hashHelper for the hashtable insert below
                hashHelper.fragID = fragID;
            } else if ((fragPendIndex = hashTable_lookup(fragPendMap, (char*)&hashHelper.srcIP)) != HASHTABLE_ENTRY_NOT_FOUND) {
                // IPID hash collision between two flows
                flow_t* flow2 = &flows[fragPend[fragPendIndex]];
#if VERBOSE > 2
                T2_PWRN("packetCapture", "two IPv6 flows (%" PRIu64 " and %" PRIu64 ") with same IPID hash", flow2->findex, flowP->findex);
                T2_PINF("packetCapture", "removing fragment of flow %" PRIu64 " pktn: %" PRIu64" fragID: %u", flow2->findex, numPackets, ntohl(fragID));
#endif
                flow2->status &= ~IPV4_FRAG_PENDING;
                // instead of removing fragment from hashmap here and adding the exact same
                // key below, we just check for collision before adding.
                fragPend[fragPendIndex] = flowIndex;
            }

            // if no collision, add new fragment to hashmap, on collision fragment is already in it.
            if (fragPendIndex == HASHTABLE_ENTRY_NOT_FOUND) {
                fragPendIndex = hashTable_insert(fragPendMap, (char*)&hashHelper.srcIP);
                if (UNLIKELY(fragPendIndex == HASHTABLE_ENTRY_NOT_FOUND)) { // Should not happen
                    T2_PFATAL("packetCapture", "IPv6 frag insert failed: "
                            "findex: %" PRIu64 ", flowIndex: %lu, "
                            "srcPort: %" PRIu16 ", dstPort: %" PRIu16 ", "
                            "IPID: 0x%08" B2T_PRIX32 ", flowStat: 0x%016" B2T_PRIX64,
                            flowP->findex, flowIndex,
                            packet->srcPort, packet->dstPort,
                            fragID, flowP->status);
                }
                fragPend[fragPendIndex] = flowIndex;
            }
            flowP->lastFragIPID = fragID;
            flowP->status |= IPV4_FRAG_PENDING;
        } else if (flowP->status & IPV4_FRAG_PENDING) {
            T2_SET_STATUS(flowP, IPV4_FRAG_ERR);
        }
    } // endif not fragmented or 1. fragmented packet
#endif // FRAGMENTATION

#if ETH_STAT_MODE == 1
    numPacketsL2[packet->outerEthType]++;
    numBytesL2[packet->outerEthType] += packet->snapLen;
#else // ETH_STAT_MODE == 0
    numPacketsL2[packet->ethType]++;
    numBytesL2[packet->ethType] += packet->snapLen;
#endif // ETH_STAT_MODE == 0

    numPacketsL3[packet->l4Proto]++;
    numBytesL3[packet->l4Proto] += packet->snapLen;

    if (packet->rawLen <= MINRAWLEN) {
        const int64_t pad = (int64_t)((int64_t)packet->rawLen - (int32_t)l3Len - (int64_t)((uint8_t*)ip6HdrP - packet->raw_packet));
        if (pad < 0) {
            // TODO set a bit in flowStat?
        } else {
            packet->padLen = pad;
            flowP->padLen += pad;
            padBytesOnWire += pad;
        }
    }

    // Layer 2
    FOREACH_PLUGIN_DO(claimL2Info, packet, HASHTABLE_ENTRY_NOT_FOUND);

    // Layer 3 & 4

#if SCTP_ACTIVATE > 0
    while (1) {
#endif // SCTP_ACTIVATE > 0
        T2_SET_STATUS(flowP, packet->status);
        flowP->lastSeen = packet->pcapHdrP->ts;

        if (sPktFile) {
#if SPKTMD_PKTNO == 1
            fprintf(sPktFile, "%" PRIu64 /* pktNo   */ SEP_CHR
                              "%" PRIu64 /* flowInd */ SEP_CHR
                              , numPackets
                              , flowP->findex);
#else // SPKTMD_PKTNO == 0
            fprintf(sPktFile, "%" PRIu64 /* flowInd */ SEP_CHR, flowP->findex);
#endif // SPKTMD_PKTNO
        }

        // Layer 4
        FOREACH_PLUGIN_DO(claimL4Info, packet, flowIndex);

        if (sPktFile) t2_print_payload(sPktFile, packet);

#if SCTP_ACTIVATE > 0
        if (packet->l4Proto != L3_SCTP || sctpChnkLen < 1) break;
        sctpL7Len -= sctpChnkPLen;
        if (sctpL7Len < 4) break;
        sctpL7P += sctpChnkPLen;

#if ETH_ACTIVATE == 2
        hashHelper.ethDS = ETH_HEADER(packet)->ethDS;
#endif

        hashHelper.srcIP = packet->srcIP; // flowCreate looked into reverse flow
        hashHelper.dstIP = packet->dstIP; // so set orig flow again
        hashHelper.srcPort = packet->srcPort;
        hashHelper.dstPort = packet->dstPort;

        packet->l7SctpHdrP = sctpL7P;
        packet->l7HdrP += sctpChnkLen; // jump over previous chunk

        sctpChunkP = (sctpChunk_t*)sctpL7P;
        sctpChnkPLen = sctpChnkLen = ntohs(sctpChunkP->len);

#if SCTP_ACTIVATE & 2
        hashHelper.sctpVtag = sctpHdrP->verTag;
#endif // SCTP_ACTIVATE & 2

        if (sctpChunkP->type == 0) {
#if SCTP_ACTIVATE & 1
            hashHelper.sctpStrm = sctpChunkP->sis;
#endif // SCTP_ACTIVATE & 1

            const uint32_t sctpPad = 4 - sctpChnkLen % 4;
            if (sctpPad < 4) sctpChnkPLen += sctpPad;
            packet->sctpPad = sctpPad;
            if (sctpL7Len >= sctpChnkLen) {
                packet->snapSctpL7Len = sctpChnkLen;
                if (sctpChnkLen < 16) packet->snapL7Len = 0;
                else packet->snapL7Len = sctpChnkLen - 16;
            } else {
                packet->snapSctpL7Len = sctpL7Len;
                if (sctpL7Len < 16) packet->snapL7Len = 0;
                else packet->snapL7Len = sctpL7Len - 16;
            }
            if (sctpChnkLen < 16) packet->l7Len = 0;
            else packet->l7Len = sctpChnkLen - 16;
            packet->len = packet->l7Len;
        } else {
#if SCTP_ACTIVATE & 2
            hashHelper.sctpVtag = 0;
#endif // SCTP_ACTIVATE & 2

#if SCTP_ACTIVATE & 1
            hashHelper.sctpStrm = 0;
#endif // SCTP_ACTIVATE & 1

            packet->snapSctpL7Len = sctpChnkLen;
            packet->snapL7Len = 0;
        }

        flowIndex = hashTable_lookup(mainHashMap, (char*)&hashHelper.srcIP);
        if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
#if NOFLWCRT == 1
            if ((globalInt & GI_RUN) < GI_TERM_THRES) return;
#endif // NOFLWCRT == 1
            flowIndex = flowCreate(packet, &hashHelper);
            flowP = &flows[flowIndex];
        } else {
            flowP = &flows[flowIndex];
            updateLRUList(flowP);
        }
    }
#endif // SCTP_ACTIVATE > 0

    if (FLOW_IS_B(flowP)) {
        numBPackets++;
        numBBytes += packet->snapLen;
    } else {
        numAPackets++;
        numABytes += packet->snapLen;
    }
}
#endif // IPV6_ACTIVATE > 0


static inline void t2_dispatch_l2_packet(packet_t *packet) {
    // No flow could be created... flag the packet as L2_FLOW and create a L2 flow
    T2_SET_STATUS(packet, L2_FLOW);

    numL2Packets++;

#if ETH_STAT_MODE == 1
    numPacketsL2[packet->outerEthType]++;
    numBytesL2[packet->outerEthType] += packet->snapLen;
#else // ETH_STAT_MODE == 0
    numPacketsL2[packet->ethType]++;
    numBytesL2[packet->ethType] += packet->snapLen;
#endif // ETH_STAT_MODE == 0

#if ETH_ACTIVATE == 0
    FOREACH_PLUGIN_DO(claimL2Info, packet, HASHTABLE_ENTRY_NOT_FOUND);
    return;
#else // ETH_ACTIVATE > 0
    const uint32_t l2_hdrlen = packet->l7HdrP - packet->l2HdrP;
    packet->l7Len = packet->rawLen - (packet->l7HdrP - packet->raw_packet);

#if PACKETLENGTH >= 1
    packet->len = packet->l7Len;
#else // PACKETLENGTH == 0
    packet->len = packet->rawLen;
#endif // PACKETLENGTH == 0

    packet->snapL3Len = packet->snapL2Len - l2_hdrlen;
    packet->snapL4Len = packet->snapL3Len;
    packet->snapL7Len = packet->snapL4Len;

    packet->l2HdrLen = l2_hdrlen;

    flow_t hashHelper = {
        .ethDS   = ETH_HEADER(packet)->ethDS,
        .ethType = packet->ethType,
#if (AGGREGATIONFLAG & VLANID)
        .vlanId  = 0,
#else // (AGGREGATIONFLAG & VLANID) == 0
        .vlanId  = packet->vlanId,
#endif // (AGGREGATIONFLAG & VLANID)
    };

    flow_t *flowP;
    unsigned long flowIndex = hashTable_lookup(mainHashMap, (char*)&hashHelper.srcIP);
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
#if NOFLWCRT == 1
        if ((globalInt & GI_RUN) < GI_TERM_THRES) return;
#endif // NOFLWCRT == 1
        flowIndex = flowETHCreate(packet, &hashHelper);
        flowP = &flows[flowIndex];
    } else {
        flowP = &flows[flowIndex];
        updateLRUList(flowP);
    }

    flowP->lastSeen = packet->pcapHdrP->ts;
    T2_SET_STATUS(flowP, packet->status);
    flowP->padLen += packet->padLen;

    if (sPktFile) {
#if SPKTMD_PKTNO == 1
        fprintf(sPktFile, "%" PRIu64 /* pktNo   */ SEP_CHR
                          "%" PRIu64 /* flowInd */ SEP_CHR
                          , numPackets
                          , flowP->findex);
#else // SPKTMD_PKTNO == 0
        fprintf(sPktFile, "%" PRIu64 /* flowInd */ SEP_CHR, flowP->findex);
#endif // SPKTMD_PKTNO
    }

    FOREACH_PLUGIN_DO(claimL2Info, packet, flowIndex);

    if (sPktFile) t2_print_payload(sPktFile, packet);

    if (FLOW_IS_B(flowP)) {
        numBPackets++;
        numBBytes += packet->snapLen;
    } else {
        numAPackets++;
        numABytes += packet->snapLen;
    }
#endif // ETH_ACTIVATE > 0
}


#if LAPD_ACTIVATE == 1
inline void t2_dispatch_lapd_packet(packet_t *packet) {
    // No flow could be created... flag the packet as LAPD_FLOW and L2_FLOW and create a L2 flow
    T2_SET_STATUS(packet, (LAPD_FLOW | L2_FLOW));

    numLAPDPackets++;

    const lapdHdr_t *lapdHdrP = LAPD_HEADER(packet);
    const uint16_t lapdType = ((lapdHdrP->sapi << 8) | lapdHdrP->tei);
    packet->ethType = lapdType;
    packet->outerEthType = packet->ethType;

#if ETH_STAT_MODE == 1
    numPacketsL2[packet->outerEthType]++;
    numBytesL2[packet->outerEthType] += packet->snapLen;
#else // ETH_STAT_MODE == 0
    numPacketsL2[packet->ethType]++;
    numBytesL2[packet->ethType] += packet->snapLen;
#endif // ETH_STAT_MODE == 0

#if ETH_ACTIVATE == 0
    FOREACH_PLUGIN_DO(claimL2Info, packet, HASHTABLE_ENTRY_NOT_FOUND);
    return;
#else // ETH_ACTIVATE > 0
    const uint32_t l2_hdrlen = packet->l7HdrP - packet->l2HdrP;
    packet->l7Len = packet->rawLen - (packet->l7HdrP - packet->raw_packet);

#if PACKETLENGTH >= 1
    packet->len = packet->l7Len;
#else // PACKETLENGTH == 0
    packet->len = packet->rawLen;
#endif // PACKETLENGTH == 0

    packet->snapL2Len = packet->snapLen - (packet->l2HdrP - packet->raw_packet);
    packet->snapL3Len = packet->snapL2Len - l2_hdrlen;
    packet->snapL4Len = packet->snapL3Len;
    packet->snapL7Len = packet->snapL4Len;

    packet->l2HdrLen = l2_hdrlen;

    flow_t hashHelper = {
        .ethType = lapdType
    };

    flow_t *flowP;
    unsigned long flowIndex = hashTable_lookup(mainHashMap, (char*)&hashHelper.srcIP);
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) {
#if NOFLWCRT == 1
        if ((globalInt & GI_RUN) < GI_TERM_THRES) return;
#endif // NOFLWCRT == 1
        flowIndex = flowLAPDCreate(packet, &hashHelper);
        flowP = &flows[flowIndex];
    } else {
        flowP = &flows[flowIndex];
        updateLRUList(flowP);
    }

    flowP->lastSeen = packet->pcapHdrP->ts;
    T2_SET_STATUS(flowP, packet->status);

    if (sPktFile) {
#if SPKTMD_PKTNO == 1
        fprintf(sPktFile, "%" PRIu64 /* pktNo   */ SEP_CHR
                          "%" PRIu64 /* flowInd */ SEP_CHR
                          , numPackets
                          , flowP->findex);
#else // SPKTMD_PKTNO == 0
        fprintf(sPktFile, "%" PRIu64 /* flowInd */ SEP_CHR, flowP->findex);
#endif // SPKTMD_PKTNO
    }

    FOREACH_PLUGIN_DO(claimL2Info, packet, flowIndex);

    if (sPktFile) t2_print_payload(sPktFile, packet);

    if (FLOW_IS_B(flowP)) {
        numBPackets++;
        numBBytes += packet->snapLen;
    } else {
        numAPackets++;
        numABytes += packet->snapLen;
    }
#endif // ETH_ACTIVATE > 0
}
#endif // LAPD_ACTIVATE == 0


inline void updateLRUList(flow_t *flowP) {
    if (lruHead.lruNextFlow != flowP) {
        // we have work to do, move flowP to the front (head)

        // remove flowP from its current position
        if (flowP->lruPrevFlow) flowP->lruPrevFlow->lruNextFlow = flowP->lruNextFlow;
        if (flowP->lruNextFlow) flowP->lruNextFlow->lruPrevFlow = flowP->lruPrevFlow;

        // append it at the head of the LRU list
        flowP->lruNextFlow = lruHead.lruNextFlow;
        lruHead.lruNextFlow->lruPrevFlow = flowP;
        lruHead.lruNextFlow = flowP;
        flowP->lruPrevFlow = &lruHead;
    }
}


static inline void t2_print_payload(FILE *stream, const packet_t *packet
#if SPKTMD_PCNTC == 0 && SPKTMD_PCNTH == 0
    UNUSED
#endif
) {
#if (SPKTMD_PCNTC == 0 && SPKTMD_PCNTH == 0)
    t2_discard_trailing_char(stream, '\t');
#else // (SPKTMD_PCNTC == 1 || SPKTMD_PCNTH == 1)

#if SPKTMD_PCNTL == 0
    const uint8_t * const payload = packet->raw_packet;
    const uint_fast16_t snaplen = packet->snapLen;
#elif SPKTMD_PCNTL == 1
    const uint8_t * const payload = packet->l2HdrP;
    const uint_fast16_t snaplen = packet->snapL2Len;
#elif SPKTMD_PCNTL == 2
    const uint8_t * const payload = packet->l3HdrP;
    const uint_fast16_t snaplen = packet->snapL3Len;
#elif SPKTMD_PCNTL == 3
    const uint8_t * const payload = packet->l4HdrP;
    const uint_fast16_t snaplen = packet->snapL4Len;
#else // SPKTMD_PCNTL == 4
    const uint8_t * const payload = packet->l7HdrP;
    const uint_fast16_t snaplen = packet->snapL7Len;
#endif // SPKTMD_PCNTL == 4

#if SPKTMD_PCNTH == 1
    // uint8_t pbuff[2048]; or vector 64
    // memcpy(pbuff, payload, snaplen);
    // [TODO] process pbuff if hex and char, if both are enabled
    // print bulk pbuff

    // Print payload as hex
#if ((SPKTMD_BOPS & 0x10) == 0x10) && (SPKTMD_BSHFT > 0 && SPKTMD_BSHFT < 8)
    const int32_t msw = snaplen - SPKTMD_BSHFT_POS;
#endif // ((SPKTMD_BOPS & 0x10) == 0x10) && (SPKTMD_BSHFT > 0 && SPKTMD_BSHFT < 8)
    if (snaplen > 0) {
        uint8_t b = payload[0];
#if (SPKTMD_BOPS & 0x10)
#if SPKTMD_BSHFT_POS == 0
        b >>= SPKTMD_BSHFT;
#if (SPKTMD_BOPS & 0x01)
        BINV_8(b);
#endif // (SPKTMD_BOPS & 0x01)
#if (SPKTMD_BOPS & 0x02)
        NSWP(b);
#endif // (SPKTMD_BOPS & 0x02)
#elif SPKTMD_BSHFT_POS == 1
        b &= (0xff << SPKTMD_BSHFT);
#endif // SPKTMD_BSHFT_POS
#endif // (SPKTMD_BOPS & 0x10)
        fprintf(stream, "%s%02" B2T_PRIX8, SPKTMD_PCNTH_PREF, b);
        for (uint_fast16_t i = 1; i < snaplen; i++) {
            b = payload[i];
            if (i >= SPKTMD_BSHFT_POS) {
#if ((SPKTMD_BOPS & 0x10) && (SPKTMD_BSHFT > 0 && SPKTMD_BSHFT < 8))
                b >>= SPKTMD_BSHFT;
                b |= (SPKTMD_BSHFT_MSK & (payload[i - 1] << (8 - SPKTMD_BSHFT)));
#endif // ((SPKTMD_BOPS & 0x10) && (SPKTMD_BSHFT > 0 && SPKTMD_BSHFT < 8))
#if (SPKTMD_BOPS & 0x01)
                BINV_8(b);
#endif // (SPKTMD_BOPS & 0x01)
#if (SPKTMD_BOPS & 0x02)
                NSWP(b);
#endif // (SPKTMD_BOPS & 0x02)
            }
#if ((SPKTMD_BOPS & 0x10) && (SPKTMD_BSHFT > 0 && SPKTMD_BSHFT < 8))
            else if (msw > 0 && i == SPKTMD_BSHFT_POS - 1) b &= SPKTMD_BSHFT_AMSK;
#endif // ((SPKTMD_BOPS & 0x10) && (SPKTMD_BSHFT > 0 && SPKTMD_BSHFT < 8))
            fprintf(stream, "%s%s%02" B2T_PRIX8, SPKTMD_PCNTH_SEP, SPKTMD_PCNTH_PREF, b);
        }
#if ((SPKTMD_BOPS & 0x30) == 0x30) && (SPKTMD_BSHFT > 0 && SPKTMD_BSHFT < 8)
        if (msw > 0) {
            b = payload[snaplen - 1] << (8 - SPKTMD_BSHFT);
#if (SPKTMD_BOPS & 0x01)
            BINV_8(b);
#endif // (SPKTMD_BOPS & 0x01)
#if (SPKTMD_BOPS & 0x02)
            NSWP(b);
#endif // (SPKTMD_BOPS & 0x02)
            fprintf(stream, "%s%s%02" B2T_PRIX8, SPKTMD_PCNTH_SEP, SPKTMD_PCNTH_PREF, b);
        }
#endif // ((SPKTMD_BOPS & 0x30) == 0x30) && (SPKTMD_BSHFT > 0 && SPKTMD_BSHFT < 8)
    }
#endif // SPKTMD_PCNTH == 1

#if (SPKTMD_PCNTC == 1 && SPKTMD_PCNTH == 1)
    fputc('\t', stream); // only print a tab if hex content was displayed
#endif // (SPKTMD_PCNTC == 1 && SPKTMD_PCNTH == 1)

#if SPKTMD_PCNTC == 1
    // Print payload as char
    for (uint_fast16_t i = 0; i < snaplen; i++) {
        char c = payload[i];

        if (i >= SPKTMD_BSHFT_POS) {
#if ((SPKTMD_BOPS & 0x10) && (SPKTMD_BSHFT > 0 && SPKTMD_BSHFT < 8))
            c >>= SPKTMD_BSHFT;
            if (i > 0) c |= (SPKTMD_BSHFT_MSK & (payload[i - 1] << (8 - SPKTMD_BSHFT)));
#endif // ((SPKTMD_BOPS & 0x10) && (SPKTMD_BSHFT > 0 && SPKTMD_BSHFT < 8))
#if (SPKTMD_BOPS & 0x01)
            BINV_8(c);
#endif // (SPKTMD_BOPS & 0x01)
#if (SPKTMD_BOPS & 0x02)
            NSWP(c);
#endif // (SPKTMD_BOPS & 0x02)
        }

        switch (c) {
            case '\b': fputs("\\b", stream);  break;  // backspace
            case '\f': fputs("\\f", stream);  break;  // form feed
            case '\n': fputs("\\n", stream);  break;  // line feed
            case '\r': fputs("\\r", stream);  break;  // carriage return
            case '\t': fputs("\\t", stream);  break;  // horizontal tab
            case '\v': fputs("\\v", stream);  break;  // vertical tab
            case '\\': fputs("\\\\", stream); break;  // backslash
            default: {
                if (isprint(c)) {
                    fputc(c, stream);
                } else {
                    fputc('.', stream);
                }
                break;
            }
        }
    }
#endif // SPKTMD_PCNTC == 1

#endif // (SPKTMD_PCNTC == 1 || SPKTMD_PCNTH > 0)

    fputc('\n', stream);
}
