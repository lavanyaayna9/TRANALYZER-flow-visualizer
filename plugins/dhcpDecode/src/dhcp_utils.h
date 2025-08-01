/*
 * dhcp_utils.h
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

#ifndef __DHCP_UTILS_H__
#define __DHCP_UTILS_H__

#include <stdint.h> // for uint8_t, uint16_t, uint32_t

#define DHCP64MSK     0x3f
#define DHCPBCST      0x0080                // network order
#define MAGICNUMBERn  0x63538263            // DHCP/BOOTP option magic number
#define DHCP_HDRLEN   sizeof(dhcpHeader_t)  // DHCP header length
#define DHCPOPTUDPOFF (DHCP_HDRLEN + 8)     // DHCP header + UDP header
#define DHCPOPTEND    0xff                  // DHCP option end marker

// IPv4
#define DHCP4UDPCP    68  // DHCP client port 68
#define DHCP4UDPSP    67  // DHCP server port 67

// IPv6
#define DHCP6UDPCP    546  // DHCP client port 546
#define DHCP6UDPSP    547  // DHCP server port 547

// Number of message type
#define DHCP_NUM_MSGT  18
#define DHCP_NUM_MSGT6 23

// Message op codes / message type
#define BOOTREQUEST 1
#define BOOTREPLY   2

// IPv4

// Message Type (53)
#define DHCP_MSGT_DISCOVER   1
#define DHCP_MSGT_OFFER      2
#define DHCP_MSGT_REQUEST    3
#define DHCP_MSGT_DECLINE    4
#define DHCP_MSGT_ACK        5
#define DHCP_MSGT_NACK       6
#define DHCP_MSGT_RELEASE    7
#define DHCP_MSGT_INFORM     8
#define DHCP_MSGT_FORCERENEW 9
#define DHCP_MSGT_LSQUERY   10
#define DHCP_MSGT_LSUASSGND 11
#define DHCP_MSGT_LSUNKNWN  12
#define DHCP_MSGT_LSACTV    13
#define DHCP_MSGT_BLKLSQRY  14
#define DHCP_MSGT_LSQRYDNE  15
#define DHCP_MSGT_ACTVLSQRY 16
#define DHCP_MSGT_LSQRYSTAT 17
#define DHCP_MSGT_TLS       18

// NetWar/IP Option Type (63)

#define DCHP_NWIP_DNOTEXST      1
#define DCHP_NWIP_EXSTINOPTAREA 2
#define DCHP_NWIP_EXSTINSNMFLE  3
#define DCHP_NWIP_EXSTBTTOOBG   4
#define DCHP_NSQ_BRDCST         5
#define DCHP_PRFRRD_DSS         6
#define DCHP_NRST_NWIPSRVR      7
#define DCHP_AUTORTRS           8
#define DCHP_AUTORTRY_SECS      9
#define DCHP_NWIP_1_1          10
#define DCHP_PRIM_DSS          11

// IPv6

// Message Types
#define Reserved          0
#define SOLICIT           1
#define ADVERTISE         2
#define REQUEST           3
#define CONFIRM           4
#define RENEW             5
#define REBIND            6
#define REPLY             7
#define RELEASE           8
#define DECLINE           9
#define RECONF           10
#define INF_REQ          11
#define RELAY_FRWRD      12
#define RELAY_RPLY       13
#define LEASEQUERY       14
#define LEASEQUERY_RPLY  15


// Structs

typedef struct {
    uint8_t  opcode; // 1: BOOTREQUEST, 2: BOOTREPLY
    uint8_t  hwType; // 1: Ethernet
    uint8_t  hwAddrLen;
    uint8_t  hopCnt;
    uint32_t transID;
    uint16_t num_sec;
    uint16_t flags;
    uint32_t clientIP;
    uint32_t yourIP;
    uint32_t servIP;
    uint32_t gwIP;
    uint32_t clientHWaddr[4];
    uint8_t  servHostName[64];
    uint8_t  bootFname[128];
    uint32_t optMagNum;
} __attribute__((packed)) dhcpHeader_t;


// IPv4

extern const char * const dhcpMsgTToStr[];
extern const char * const dhcpState53[];
extern const char * const dhcpOptNm[];

// IPv6

extern const char * const dhcpMsgT6ToStr[];
extern const char * const dhcpMT6[];

#endif // __DHCP_UTILS_H__
