/*
 * flow.h
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

#ifndef T2_FLOW_H_INCLUDED
#define T2_FLOW_H_INCLUDED

#include <math.h>            // for INFINITY
#include <stdint.h>          // for uint32_t, uint16_t, uint64_t, uint8_t
#include <sys/time.h>        // for timeval

#include "hashTable.h"       // for HASHTABLE_ENTRY_NOT_FOUND
#include "ipaddr.h"          // for ipAddr_t, ip4Addr_t
#include "networkHeaders.h"  // for ETH_ACTIVATE, IPV6_ACTIVATE, SCTP_ACTIVATE, SCTP_STATFINDEX
#include "packet.h"          // for packet_t
#include "tranalyzer.h"      // for SUBNET_INIT


// flowStat: global, packet and flow status

#define L3FLOWINVERT        0x0000000000000001  // Inverted flow, did not initiate connection
#define L2_NO_ETH           0x0000000000000002  // No Ethernet header
#define L2_FLOW             0x0000000000000004  // Pure L2 flow
#define L2_PPPoE_D          0x0000000000000008  // Point to Point Protocol over Ethernet Discovery (PPPoED)

#define L2_PPPoE_S          0x0000000000000010  // Point to Point Protocol over Ethernet Service (PPPoES)
#define L2_LLDP             0x0000000000000020  // Link Layer Discovery Protocol (LLDP)
#define L2_ARP              0x0000000000000040  // ARP
#define L2_RARP             0x0000000000000080  // Reverse ARP

#define L2_VLAN             0x0000000000000100  // VLANs
#define L2_MPLS_UCAST       0x0000000000000200  // MPLS unicast
#define L2_MPLS_MCAST       0x0000000000000400  // MPLS multicast
#define L2_L2TP             0x0000000000000800  // L2TP v2/3

#define L2_GRE              0x0000000000001000  // GRE v1/2
#define L2_PPP              0x0000000000002000  // PPP header after L2TP or GRE
#define L2_IPV4             0x0000000000004000  // IPv4 flow
#define L2_IPV6             0x0000000000008000  // IPv6 flow

#define L3_IPVX             0x0000000000010000  // IPvX bogus packet
#define L3_IPIP             0x0000000000020000  // IPv4/6 in IPv4/6
#define L3_ETHIPF           0x0000000000040000  // Ethernet over IP
#define L3_TRDO             0x0000000000080000  // Teredo tunnel

#define L3_AYIYA            0x0000000000100000  // Anything in Anything (AYIYA) tunnel
#define L3_GTP              0x0000000000200000  // GPRS Tunneling Protocol (GTP)
#define L3_VXLAN            0x0000000000400000  // Virtual eXtensible Local Area Network (VXLAN)
#define L3_CAPWAP           0x0000000000800000  // Control And Provisioning of Wireless Access Points (CAPWAP),
                                                // Lightweight Access Point Protocol (LWAPP)

#define L4_SCTP             0x0000000001000000  // Stream Control Transmission Protocol (SCTP)
#define L4_UPNP             0x0000000002000000  // SSDP/UPnP
#define L2_ERSPAN           0x0000000004000000  // Encapsulated Remote Switch Packet ANalysis (ERSPAN)
#define L2_WCCP             0x0000000008000000  // Cisco Web Cache Communication Protocol (WCCP)

#define L7_SIPRTP           0x0000000010000000  // SIP/RTP
#define L3_GENEVE           0x0000000020000000  // Generic Network Virtualization Encapsulation (GENEVE)
#define L3_IPSEC_AH         0x0000000040000000  // IPsec Authentication Header (AH)
#define L3_IPSEC_ESP        0x0000000080000000  // IPsec Encapsulating Security Payload (ESP)

// global, packet and flow warning
#define L2SNAPLENGTH        0x0000000100000000  // Acquired packet length < minimal L2 datagram
#define L3SNAPLENGTH        0x0000000200000000  // Acquired packet length < packet length in L3 header
#define L3HDRSHRTLEN        0x0000000400000000  // Acquired packet length < minimal L3 header
#define L4HDRSHRTLEN        0x0000000800000000  // Acquired packet length < minimal L4 header

#define IPV4_FRAG           0x0000001000000000  // IPv4 fragmentation present
#define IPV4_FRAG_ERR       0x0000002000000000  // IPv4 fragmentation error (detailed err s. tcpFlags plugin)
#define IPV4_FRAG_HDSEQ_ERR 0x0000004000000000  // IPv4 1. fragment out of sequence or missing
#define IPV4_FRAG_PENDING   0x0000008000000000  // Packet fragmentation pending or fragmentation sequence not completed when flow timed-out

#define FLWTMOUT            0x0000010000000000  // Flow timeout instead of protocol termination
#define RMFLOW              0x0000020000000000  // Force mode: remove this flow instantly
#define RMFLOW_HFULL        0x0000040000000000  // Autopilot: flow removed to free space in main hash map
#define STPDSCT             0x0000080000000000  // Stop dissecting: Clipped packet, unhandled protocol or subsequent fragment

#define DUPIPID             0x0000100000000000  // Consecutive duplicate IP ID
#define PPP_NRHD            0x0000200000000000  // PPPL3 header not readable, compressed
#define IPV4_HL_TOO_SHORT   0x0000400000000000  // IPv4 header length < 20 bytes
#define IP_PL_MSMTCH        0x0000800000000000  // IPv4/6 payload length != framing length

#define HDOVRN              0x0001000000000000  // Header description overrun
#define FL_ALARM            0x0002000000000000  // Alarm mode & pcapd dumps packets from this flow to new pcap if not -e option
#define LANDATTACK          0x0004000000000000  // Same srcIP && dstIP and srcPort && dstPort
#define TIMEJUMP            0x0008000000000000  // Timestamp jump, probably due to multi-path packet delay or NTP operation

#define LIVEXTR             0x0010000000000000  // Flow should be extracted by the liveXtr plugin
#define __FS_UNUSED_1__     0x0020000000000000  // UNUSED
#define __FS_UNUSED_2__     0x0040000000000000  // UNUSED
#define SUBN_FLW_TST        0x0080000000000000  // Subnet tested for that flow

#define TORADD              0x0100000000000000  // Tor address detected
#define FS_VLAN0            0x0200000000000000  // A packet had a priority tag (VLAN tag with ID 0)
#define FS_IPV4_PKT         0x0400000000000000  // IPv4 packet
#define FS_IPV6_PKT         0x0800000000000000  // IPv6 packet

#define LAPD_FLOW           0x1000000000000000  // LAPD flow
#define L7_DTLS             0x2000000000000000  // DTLS in layer 7
#define FDLSIDX             0x4000000000000000  // Flow duration limit, same findex for all subflows
#define PCAPSNPD            0x8000000000000000  // PCAP packet length > MAX_MTU in ioBuffer.h, caplen reduced


#define L2_MPLS     (L2_MPLS_UCAST | L2_MPLS_MCAST)
#define SNAPLENGTH  (L2SNAPLENGTH | L3SNAPLENGTH)


/* Macros */

// Return true if flow f is a sentinel
#define FLOW_IS_SENTINEL(f) ((f)->timeout == INFINITY)

// Return true if flow f has an opposite flow
#define FLOW_HAS_OPPOSITE(f) ((f)->oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND)

// Return true if flow f is an A flow
#define FLOW_IS_A(f) (!((f)->status & L3FLOWINVERT))

// Return true if flow f is a B flow
#define FLOW_IS_B(f) ((f)->status & L3FLOWINVERT)

// Flow direction as char
#define FLOW_DIR_C_A 'A'
#define FLOW_DIR_C_B 'B'

// Flow direction as string
#define FLOW_DIR_S_A "A"
#define FLOW_DIR_S_B "B"

// Return the direction of a flow (A or B) as a char
#define FLOW_DIR_C(f) (FLOW_IS_B(f) ? FLOW_DIR_C_B : FLOW_DIR_C_A)

// Return the direction of a flow (A or B) as a string
#define FLOW_DIR_S(f) (FLOW_IS_B(f) ? FLOW_DIR_S_B : FLOW_DIR_S_A)


/* Structs */

typedef struct flow_s {
    // Pointers to next and previous flow in LRU list
    struct flow_s *  lruNextFlow;
    struct flow_s *  lruPrevFlow;

    uint64_t         findex;                // flow index
    uint64_t         status;                // flow status, e.g., fragmentation processing

    unsigned long    flowIndex;
    unsigned long    oppositeFlowIndex;

#if (SCTP_ACTIVATE > 0 && SCTP_STATFINDEX == 1)
    unsigned long    sctpFindex;
#endif // (SCTP_ACTIVATE > 0 && SCTP_STATFINDEX == 1)

    struct timeval   lastSeen;   // last time we've seen this flow
    struct timeval   firstSeen;  // first time we've seen this flow
    struct timeval   duration;   // lastSeen - firstSeen
                                 // (NOT available before flow completely terminated)

    /* --------------------------------------------------------------------- */
    /* Begin flow identification                                             */
    /* --------------------------------------------------------------------- */

#if IPV6_ACTIVATE > 0
    ipAddr_t         srcIP;
    ipAddr_t         dstIP;
#else // IPV6_ACTIVATE == 0
    ip4Addr_t        srcIP;
    ip4Addr_t        dstIP;
#endif // IPV6_ACTIVATE == 0

#if ETH_ACTIVATE > 0
    ethDS_t          ethDS;
#endif

#if (IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0 || LAPD_ACTIVATE == 1)
    uint16_t         ethType;
#endif

    uint16_t         vlanId;

    union {
        struct {
            uint16_t srcPort;
            uint16_t dstPort;
        };
        uint32_t     fragID;
    };

#if SCTP_ACTIVATE & 2
    uint32_t         sctpVtag;
#endif // SCTP_ACTIVATE & 2

#if SCTP_ACTIVATE & 1
    uint16_t         sctpStrm;
#endif // SCTP_ACTIVATE & 1

    uint8_t          l4Proto;

    /* --------------------------------------------------------------------- */
    /* End flow identification                                               */
    /* --------------------------------------------------------------------- */

    int64_t          padLen;                // aggregated padding length

    float            timeout;               // flow timeout in seconds

    uint32_t         lastIPID;              // for duplicate IP ID detection

#if SUBNET_INIT != 0
    uint32_t         subnetNrSrc;
    uint32_t         subnetNrDst;
#endif // SUBNET_INIT != 0

#if FRAGMENTATION >= 1
    // for fragPend hash cleanup
#if IPV6_ACTIVATE > 0
    uint32_t        lastFragIPID;
#else // IPV6_ACTIVATE == 0
    uint16_t        lastFragIPID;
#endif // IPV6_ACTIVATE == 0
#endif // FRAGMENTATION >= 1

} __attribute__((packed)) flow_t;


/* Functions prototypes */

#if ETH_ACTIVATE > 0
unsigned long flowETHCreate(packet_t *packet, flow_t *hashHelper)
    __attribute__((__nonnull__(1, 2)));
#endif // ETH_ACTIVATE > 0

#if LAPD_ACTIVATE > 0
unsigned long flowLAPDCreate(packet_t *packet, flow_t *hashHelper)
    __attribute__((__nonnull__(1, 2)));
#endif // LAPD_ACTIVATE > 0

unsigned long flowCreate(packet_t *packet, flow_t *hashHelper)
    __attribute__((__nonnull__(1, 2)));

#endif // T2_FLOW_H_INCLUDED
