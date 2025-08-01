/*
 * gre.h
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

#ifndef T2_GRE_H_INCLUDED
#define T2_GRE_H_INCLUDED

#include <stdint.h> // for uint16_t, uint32_t


// GRE - Generic Routing Encapsulation

// GRE-in-UDP Encapsulation (RFC 8086)
#define GRE_IN_UDP_PORT      4754
#define GRE_IN_UDP_DTLS_PORT 4755

#define GRE_CKSMn  0x00000080 // Checksum
#define GRE_RTn    0x00000040 // Routing offset
#define GRE_KEYn   0x00000020 // Key
#define GRE_SQn    0x00000010 // Sequence Number
#define GRE_SSRn   0x00000008 // Strict Source Routing
#define GRE_RECURn 0x00000007 // Recursion control
#define GRE_ACKn   0x00008000 // Acknowledge Number
#define GRE_FLAGSn 0x00007800 // Flags
#define GRE_Vn     0x00000700 // Version

#define GRE_PROTOn 0xffff0000 // encapsulated protocols

// GRE protocols

#define GRE_PPPn        0x0b880000 // PPP
#define GRE_IP4n        0x00080000 // IPv4
#define GRE_WCCPn       0x3e880000 // WCCP
#define GRE_MPLS_UCASTn 0x47880000 // MPLS Unicast
#define GRE_ERSPANn     0xbe880000 // ERSPAN
#define GRE_IP6n        0xdd860000 // IPv6
#define GRE_TEBn        0x58650000 // Transparent Ethernet bridging

// GRE PPP

#define GRE_PPP_CMPRSS 0xfd


// Structs

typedef struct {
    uint32_t hdrFlags:5;
    uint32_t recur:3;
    uint32_t ack:1;
    uint32_t flags:4;
    uint32_t ver:3;
    uint32_t proto:16;
    uint16_t plength;
    int16_t  CallID;
} greHeader_t;

#endif // T2_GRE_H_INCLUDED
