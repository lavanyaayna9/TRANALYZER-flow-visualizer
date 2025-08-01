/*
 * networkHeaders.h
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

#ifndef T2_NETWORKHEADERS_H_INCLUDED
#define T2_NETWORKHEADERS_H_INCLUDED

#include <netinet/in.h>     // for in_addr, in6_addr
#include <stdint.h>         // for uint8_t, uint16_t, uint32_t, uint64_t

#include "proto/dtls.h"     // for dtlsHeader_t
#include "proto/gre.h"      // for greHeader_t
#include "proto/icmp.h"     // for icmpHeader_t
#include "proto/igmp.h"     // for igmpHeader_t
#include "proto/ipv4.h"     // for ipHeader_t
#include "proto/ipv6.h"     // for ip6OptHdr_t, ...
#include "proto/lapd.h"     // for lapdHdr_t
#include "proto/llc.h"      // for etherLLCHeader_t
#include "proto/mpls.h"     // for mplsHeader_t
#include "proto/pim.h"      // for pimHeader_t
#include "proto/sctp.h"     // for sctpHeader_t
#include "proto/tcp.h"      // for tcpHeader_t
#include "proto/udp.h"      // for udpHeader_t
#include "proto/udplite.h"  // for udpliteHeader_t


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define IPV6_ACTIVATE     2 // 0: IPv4 only
                            // 1: IPv6 only
                            // 2: dual mode

#define ETH_ACTIVATE      1 // 0: No L2 flows,
                            // 1: Activate L2 flows,
                            // 2: Also use Ethernet addresses for IPv4/6 flows

#define LAPD_ACTIVATE     0 // 0: No LAPD/Q.931 flows
                            // 1: Activate LAPD/Q.931 flow generation
#define LAPD_OVER_UDP     0 // 0: Do not try dissecting LAPD over UDP
                            // 1: Dissect LAPD over UDP (experimental)

#define SCTP_ACTIVATE     0 // 0: standard flows
                            // 1: activate SCTP chunk streams -> flows
                            // 2: activate SCTP association -> flows
                            // 3: activate SCTP chunk & association -> flows
#define SCTP_STATFINDEX   1 // 0: findex increments
                            // 1: findex constant for all SCTP streams in a packet

#define MULTIPKTSUP       0 // multi-packet suppression

#define T2_PRI_HDRDESC    1 // keep track of the headers traversed
#define T2_HDRDESC_AGGR   1 // aggregate repetitive headers, e.g., vlan{2}
#define T2_HDRDESC_LEN  128 // max length of the headers description

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


#if LAPD_ACTIVATE == 0 && LAPD_OVER_UDP == 1
#undef LAPD_OVER_UDP
#define LAPD_OVER_UDP 0
#endif

// macOS fix
#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

// IPsec
#define UDPENCAP_PORT   4500
#define UDPENCAP_PORT_N 0x9411 // 4500

// SSDP/UPnP
#define UPNP_PORT   1900
#define UPNP_PORT_N 0x6c07 // 1900

// PPP
#define PPP_ADD_CTLn    0x03ff // not numbered/listen to all

#define PPP_CDPn        0x0702 // Cisco Discovery Protocol (CDP)
#define PPP_IP4n        0x2100 // IPv4
#define PPP_IPCPn       0x2180 // IP Control Protocol (IPCP)
#define PPP_LCPn        0x21c0 // Link Control Protocol (LCP)
#define PPP_OSIn        0x2300 // OSI Network Layer
#define PPP_PAPn        0x23c0 // Password Authentication Protocol (PAP)
#define PPP_CHAPn       0x23c2 // Challenge Handshake Authentication Protocol (CHAP)
#define PPP_MPn         0x3d00 // PPP Multilink Protocol
#define PPP_IP6n        0x5700 // IPv6
#define PPP_MPLS_UCASTn 0x8102 // MPLS Unicast
#define PPP_MPLS_MCASTn 0x8302 // MPLS Multicast
#define PPP_COMPRESSn   0xfd00 // PPP Compressed Datagram
#define PPP_CCPn        0xfd80 // Compression Control Protocol

// L4 codes in L3 header
#define L3_HHOPT6   0x00
#define L3_ICMP     0x01
#define L3_IGMP     0x02
#define L3_IPIP4    0x04
#define L3_ST       0x05 // Internet Stream Protocol
#define L3_TCP      0x06
#define L3_CBT      0x07
#define L3_EGP      0x08
#define L3_IGP      0x09
#define L3_UDP      0x11
#define L3_DCCP     0x21 // Datagram Congestion Control Protocol
#define L3_XTP      0x24 // Xpress Transport Protocol
#define L3_DDP      0x25 // Datagram Delivery Protocol
#define L3_IPIP6    0x29
#define L3_ROUT6    0x2b
#define L3_FRAG6    0x2c
#define L3_IDRP     0x2d // Inter-Domain Routing Protocol
#define L3_RSVP     0x2e
#define L3_GRE      0x2f // IPSEC
#define L3_DSR      0x30 // Dynamic Source Routing Protocol
#define L3_ESP      0x32 // IPSEC
#define L3_AH       0x33
#define L3_SWIPE    0x35 // SwIPe
#define L3_NHRP     0x36 // Next Hop Resolution Protocol
#define L3_ICMP6    0x3a
#define L3_NXTH6    0x3b // No next header
#define L3_DOPT6    0x3c
#define L3_OSI      0x50 // ISO Internet Protocol
#define L3_VINES    0x53
#define L3_EIGRP    0x58
#define L3_OSPF     0x59
#define L3_AX25     0x5d
#define L3_ETHIP    0x61
#define L3_PIM      0x67
#define L3_IPCOMP   0x6c // IP Payload Compression Protocol
#define L3_VRRP     0x70
#define L3_PGM      0x71 // PGM Reliable Transport Protocol
#define L3_L2TP     0x73
#define L3_PTP      0x7b
#define L3_SCTP     0x84
#define L3_RSVPE2EI 0x86 // Reservation Protocol (RSVP) End-to-End Ignore
#define L3_MOB6     0x87
#define L3_UDPLITE  0x88 // Lightweight User Datagram Protocol
#define L3_MPLSIP   0x89 // MPLS in IP
#define L3_HIP      0x8b // Host Identity Protocol
#define L3_SHIM6    0x8c

// Ethernet over IP
#define ETHIPVERN 0x30 // Version


// structs

// Ethernet header

typedef struct {
    uint8_t ether_dhost[ETH_ALEN]; // destination eth addr
    uint8_t ether_shost[ETH_ALEN]; // source ether addr
} __attribute__((packed)) ethDS_t;

typedef struct {
    ethDS_t  ethDS;
    uint16_t ether_type; // packet type ID field or length
    uint16_t data;
} __attribute__((packed)) ethernetHeader_t;

// ISL header

#define ISL_HEADER_LEN      26 // 26-bytes

#define ISL_TYPE_ETHER       0
#define ISL_TYPE_TOKEN_RING  1
#define ISL_TYPE_FDDI        2
#define ISL_TYPE_ATM         3

typedef struct {
    ethDS_t  ether_dhost[ETH_ALEN]; // DA (40 bits), Type (4 bits), User (4 bits)
    ethDS_t  ether_shost[ETH_ALEN];
    uint16_t len;
    uint16_t dssap;    // 0xaa
    uint8_t  control;  // 0x03
    uint8_t  hsa[3];   // High bits of Source Address
    uint16_t vlanId:15;
    uint16_t bpdu:1;
    uint16_t indx;
    uint16_t reserved;
} __attribute__((packed)) islHeader_t;

// PPP header

typedef struct {
    uint16_t addctl;
    uint16_t prot;
} pppHdr_t;

// PPPoE header

typedef struct {
    uint8_t  ver_typ;
    uint8_t  code;
    uint16_t sessID;
    uint16_t len;
    uint16_t pppProt;
} __attribute__((packed)) pppoEH_t;

// general Layer 2 - 4 headers

typedef union {
    pppHdr_t pppHdru;
    uint32_t pppHdrc;
} pppHu_t;

#endif // T2_NETWORKHEADERS_H_INCLUDED
