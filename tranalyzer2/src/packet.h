/*
 * packet.h
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

#ifndef T2_PACKET_H_INCLUDED
#define T2_PACKET_H_INCLUDED

#include <stdint.h>         // for uint8_t, uint16_t, uint32_t, uint64_t

#include "ipaddr.h"         // for ipAddr_t, ip4Addr_t
#include "networkHeaders.h" // for T2_PRI_HDRDESC, IPV6_ACTIVATE, SCTP_ACTIVATE, ...
#include "tranalyzer.h"     // for FDURLIMIT, FDLSFINDEX, SUBNET_INIT, AGGREGATIONFLAG, ...


// Forward declarations

struct pcap_pkthdr;


// Defines

#define L2_HEADER(p) ((p)->l2HdrP)
#define L3_HEADER(p) ((p)->l3HdrP)
#define L4_HEADER(p) ((p)->l4HdrP)
#define L7_HEADER(p) ((p)->l7HdrP)

#define L3_PROTO(p)  ((p)->l3Proto)


// Structs

typedef struct {
#if (FDURLIMIT > 0 && FDLSFINDEX == 1)
    uint64_t findex;
#endif //(FDURLIMIT > 0 && FDLSFINDEX == 1)

    uint64_t status;

    /* --------------------------------------------------------------------- */
    /* Pointers (network order)                                              */
    /* --------------------------------------------------------------------- */

    const struct pcap_pkthdr * const pcapHdrP;

    const uint8_t * const   raw_packet;    // Beginning of the packet
    const uint8_t * const   end_packet;    // Beyond the end of the packet
                                           // (raw_packet + snapLen);

    const uint8_t *         l2HdrP;        // Layer 2 (Ethernet, LLC, LAPD, ...)
    const uint8_t *         l3HdrP;        // Layer 3 (IPv4, IPv6, ...)
    const uint8_t *         l4HdrP;        // Layer 4 (TCP, UDP, ICMP, IGMP, SCTP, ...)
    const uint8_t *         l7HdrP;        // Layer 7 (payload)

    const etherLLCHeader_t* etherLLC;      // Ethernet header LLC part if present (set but not used)
    const pppHu_t *         pppHdrP;       // PPP header
    const pppoEH_t *        pppoeHdrP;     // PPPoE header
    const uint32_t *        mplsHdrP;      // MPLS pointer
    const uint32_t *        vlanHdrP;      // VLAN pointer

    // GRE headers
    const greHeader_t *     greHdrP;       // GRE v1,2 header
    const uint8_t     *     greL3HdrP;     // L3 header before GRE header

    // GTP headers
    const uint8_t *         gtpHdrP;       // GTP v0,1,2 header (set but no used)

    // L2TP headers
    const uint16_t *        l2tpHdrP;      // L2TPv2 header
    const uint8_t  *        l2tpL3HdrP;    // L3 header before L2TP header

    // IPv6 headers
    const ip6OptHdr_t *     ip6HHOptHdrP;  // IPv6 Hop-by-Hop Option header
    const ip6OptHdr_t *     ip6DOptHdrP;   // IPv6 Destination Option header
    const ip6FragHdr_t *    ip6FragHdrP;   // IPv6 Fragment header
    const ip6RouteHdr_t *   ip6RouteHdrP;  // IPv6 Routing header (set but not used)

    // Teredo headers
    const uint8_t *         trdoOIHdrP;    // Teredo Origin Indication header
    const uint8_t *         trdoAHdrP;     // Teredo Authentication header

#if SCTP_ACTIVATE > 0
    const uint8_t *         l7SctpHdrP;    // First SCTP payload
#endif // SCTP_ACTIVATE > 0

    /* --------------------------------------------------------------------- */
    /* Lengths (host order)                                                  */
    /*   - Snap lengths can be truncated due to limited snaplength           */
    /*     (derived by header dissection)                                    */
    /* --------------------------------------------------------------------- */

    int64_t                 padLen;          // Number of padding bytes

    const uint32_t          rawLen;          // extracted from pcapHdrP
    uint32_t                l2Len;           // derived from IP header length field + length of L2 header (set but not used)
    uint32_t                l3Len;           // derived from IP header length field, if TSO then l3Len = calcL3Len
    uint32_t                len;             // derived from IP header length field, defined by PACKETLENGTH in packetCapture.h:
                                             //   0: Including L2-4 header,
                                             //   1: including L3-4 header,
                                             //   2: Including L4 header,
                                             //   3: Only payload L7

    // Snap lengths (can be truncated due to limited snaplength, derived by header dissection)
    const uint32_t          snapLen;         // extracted from pcapHdrP
    uint32_t                snapL2Len;       // includes L2 header
    uint32_t                snapL3Len;       // includes L3 header
    uint16_t                snapL4Len;       // includes L4 header
    uint16_t                snapL7Len;       // only higher packet payload (L7)

    uint16_t                l7Len;           // L7 length

#if SCTP_ACTIVATE > 0
    uint16_t                snapSctpL7Len;   // only higher packet payload (L7)
#endif // SCTP_ACTIVATE > 0

    uint16_t                l2HdrLen;        // set but not used
    uint16_t                l3HdrLen;
    uint16_t                l4HdrLen;

    /* --------------------------------------------------------------------- */
    /* Flow identification (IP addresses, ports and protocols (host order),  */
    /* headers count and description, ...                                    */
    /* --------------------------------------------------------------------- */

#if IPV6_ACTIVATE > 0
    ipAddr_t                srcIP;
    ipAddr_t                dstIP;
#else // IPV6_ACTIVATE == 0
    ip4Addr_t               srcIP;
    ip4Addr_t               dstIP;
#endif // IPV6_ACTIVATE == 0

#if ((SUBNET_INIT != 0) || (AGGREGATIONFLAG & (SUBNET | SRCIP | DSTIP)))
#if IPV6_ACTIVATE > 0
    ipAddr_t                srcIPC;
    ipAddr_t                dstIPC;
#else // IPV6_ACTIVATE == 0
    ip4Addr_t               srcIPC;
    ip4Addr_t               dstIPC;
#endif // IPV6_ACTIVATE == 0

    uint32_t                subnetNrSrc;
    uint32_t                subnetNrDst;
    uint16_t                srcPortC;
    uint16_t                dstPortC;
    uint8_t                 l4ProtoC;
#endif // ((SUBNET_INIT != 0) || (AGGREGATIONFLAG & (SUBNET | SRCIP | DSTIP)))

    uint16_t                vlanId;
    uint16_t                srcPort;
    uint16_t                dstPort;
    uint16_t                ethType;
    uint16_t                outerEthType;
    uint16_t                l3Proto;                    // IPv4, IPv6, L2TPv2/3, ...

    // Headers description, e.g., eth:ipv4:tcp
#if T2_PRI_HDRDESC == 1
    uint16_t                numHdrDesc;                 // Number of headers description
    uint16_t                hdrDescPos;                 // Headers description position
    char                    hdrDesc[T2_HDRDESC_LEN];    // Headers description
#endif // T2_PRI_HDRDESC == 1

    uint8_t                 l4Proto;                    // TCP, UDP, ICMP, IGMP, ...
    uint8_t                 mplsHdrCnt;
    uint8_t                 vlanHdrCnt;

#if SCTP_ACTIVATE > 0
    uint8_t                 sctpPad;                    // SCTP padding of content
#endif // SCTP_ACTIVATE > 0

} packet_t;

#endif // T2_PACKET_H_INCLUDED
