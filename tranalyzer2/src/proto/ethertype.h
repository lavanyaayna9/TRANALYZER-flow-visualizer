/*
 * ethertype.h
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

#ifndef T2_ETHERTYPE_H_INCLUDED
#define T2_ETHERTYPE_H_INCLUDED

#include <stdint.h>  // for uint8_t

#include "packet.h"  // for packet_t


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define PW_ETH_CW  1 // Detect Pseudowire (PW) Ethernet Control Word (Heuristic, experimental)

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// EtherTypes host order
#define ETHERTYPE_PVSTP          0x010b // PVSTP+
#define ETHERTYPE_IP             0x0800
#define ETHERTYPE_ARP            0x0806
#define ETHERTYPE_CDP            0x2000 // Cisco Discovery Protocol (CDP)
#define ETHERTYPE_VTP            0x2003 // VLAN Trunking Protocol (VTP)
#define ETHERTYPE_RARP           0x8035
#define ETHERTYPE_VLAN           0x8100 // IEEE 802.1Q
#define ETHERTYPE_IPV6           0x86dd
#define ETHERTYPE_PPP            0x880b
#define ETHERTYPE_MPLS_UNICAST   0x8847
#define ETHERTYPE_MPLS_MULTICAST 0x8848
#define ETHERTYPE_PPPoE_D        0x8863
#define ETHERTYPE_PPPoE_S        0x8864
#define ETHERTYPE_JUMBO_LLC      0x8870
#define ETHERTYPE_EAPOL          0x888e // 802.1X Authentication
#define ETHERTYPE_QINQ           0x88a8 // IEEE 802.1ad
#define ETHERTYPE_LLDP           0x88cc
#define ETHERTYPE_LOOP           0x9000
#define ETHERTYPE_QINQD1         0x9100 // IEEE 802.1ad older def
#define ETHERTYPE_QINQD2         0x9200 // IEEE 802.1ad older def

// EtherTypes network order
#define ETHERTYPE_LLC_WLCCPn      0x0000 // WLCCP over LLC
#define ETHERTYPE_IDPn            0x0006 // Internetwork Datagram Protocol
#define ETHERTYPE_IPn             0x0008
#define ETHERTYPE_CDPn            0x0020 // Cisco Discovery Protocol / Foundry Discovery Protocol
#define ETHERTYPE_VLANn           0x0081 // IEEE 802.1Q
#define ETHERTYPE_LOOPn           0x0090
#define ETHERTYPE_CGMPn           0x0120 // Cisco Group Management Protocol (CGMP)
#define ETHERTYPE_DEC_MOPn        0x0260 // DEC MOP Remote Console
#define ETHERTYPE_CFMn            0x0289 // IEEE 802.1ag Connectivity Fault Management (CFM) Protocol
#define ETHERTYPE_VTPn            0x0320 // VLAN Trunking Protocol
#define ETHERTYPE_DEC_DNAn        0x0360 // DEC DNA Routing Protocol
#define ETHERTYPE_PAGPn           0x0401 // Port Aggregation Protocol
#define ETHERTYPE_DTPn            0x0420 // Dynamic Trunk Protocol
#define ETHERTYPE_LATn            0x0460 // DEC Local Area Transfer (LAT)
#define ETHERTYPE_ARPn            0x0608
#define ETHERTYPE_FCoEn           0x0689 // Fibre Channel over Ethernet (FCoE)
#define ETHERTYPE_SLOWn           0x0988 // Slow Protocol
#define ETHERTYPE_PVSTPn          0x0b01 // PVSTP+
#define ETHERTYPE_PPPn            0x0b88
#define ETHERTYPE_TDLSn           0x0d89 // IEEE 802.11 data encapsulation / TDLS
#define ETHERTYPE_UDLDn           0x1101 // Unidirectional Link Detection
#define ETHERTYPE_IPCPn           0x2180 // PPP IP Control Protocol
#define ETHERTYPE_LCPn            0x21c0 // PPP Link Control Protocol
#define ETHERTYPE_CHAPn           0x23c2 // PPP Challenge Handshake Authentication Protocol (CHAP)
#define ETHERTYPE_CBCPn           0x29c0 // PPP Callback Control Protocol
#define ETHERTYPE_WLCCPn          0x2d87 // Cisco Wireless LAN Context Control Protocol (WLCCP)
#define ETHERTYPE_RARPn           0x3580
#define ETHERTYPE_IPXn            0x3781 // Netware IPX/SPX
#define ETHERTYPE_DEC_STPn        0x3880 // DEC Spanning Tree Protocol (STP)
#define ETHERTYPE_WCCPn           0x3e88 // Cisco Web Cache Communication Protocol (WCCP)
#define ETHERTYPE_MPLS_UNICASTn   0x4788
#define ETHERTYPE_MPLS_MULTICASTn 0x4888
#define ETHERTYPE_TEBn            0x5865 // Transparent Ethernet bridging
#define ETHERTYPE_PPPoE_Dn        0x6388
#define ETHERTYPE_PPPoE_Sn        0x6488
#define ETHERTYPE_MS_NLBn         0x6f88 // MS Network Load Balancing
#define ETHERTYPE_JUMBO_LLCn      0x7088
#define ETHERTYPE_EAPOLn          0x8e88 // 802.1X Authentication
#define ETHERTYPE_QINQD1n         0x0091 // IEEE 802.1ad older def
#define ETHERTYPE_QINQD2n         0x0092 // IEEE 802.1ad older def
#define ETHERTYPE_REALTEKn        0x9988 // Realtek Layer 2 Protocols
#define ETHERTYPE_DDPn            0x9b80 // AppleTalk Datagram Delivery Protocol
#define ETHERTYPE_NDP_Fn          0xa101 // Nortel Discovery Protocol flatnet hello
#define ETHERTYPE_NDP_Sn          0xa201 // Nortel Discovery Protocol segment hello
#define ETHERTYPE_AOEn            0xa288 // ATA over Ethernet
#define ETHERTYPE_QINQn           0xa888 // IEEE 802.1ad
#define ETHERTYPE_VINES_IPn       0xad0b // Banyan Vines IP
#define ETHERTYPE_EDPn            0xbb00 // Extreme Discovery Protocol
#define ETHERTYPE_LWAPPn          0xbb88 // Lightweight Access Point Protocol (LWAPP)
#define ETHERTYPE_ERSPANn         0xbe88 // ERSPAN (encapsulated in GRE)
#define ETHERTYPE_LLDPn           0xcc88
#define ETHERTYPE_IPV6n           0xdd86
#define ETHERTYPE_AARPn           0xf380 // AppleTalk Address Resolution Protocol
#define ETHERTYPE_CCPn            0xfd80 // PPP Compression Control Protocol
#define ETHERTYPE_PTPn            0xf788 // Precision Time Protocol (PTP) over Ethernet (IEEE 1588)

// Cisco
#define ETHERTYPE_CISCO_CGMPn     0x0120 // Cisco Group Management Protocol (CGMP)
#define ETHERTYPE_CISCO_SLARPn    0x3580 // Serial Line Address Resolution Protocol (SLARP)
#define ETHERTYPE_CISCO_OSIn      0xfefe

// Host order
#define ETHERTYPE_IS_VLAN(ethType) ( \
    (ethType) == ETHERTYPE_VLAN   || \
    (ethType) == ETHERTYPE_QINQ   || \
    (ethType) == ETHERTYPE_QINQD1 || \
    (ethType) == ETHERTYPE_QINQD2    \
)

// Network order
#define ETHERTYPEn_IS_VLAN(ethType) ( \
    (ethType) == ETHERTYPE_VLANn   || \
    (ethType) == ETHERTYPE_QINQn   || \
    (ethType) == ETHERTYPE_QINQD1n || \
    (ethType) == ETHERTYPE_QINQD2n    \
)

uint8_t *t2_process_ethertype (uint8_t *pktptr, packet_t *packet) __attribute__((__nonnull__(1, 2)));

#endif // T2_ETHERTYPE_H_INCLUDED
