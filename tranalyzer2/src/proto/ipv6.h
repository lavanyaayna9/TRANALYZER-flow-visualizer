/*
 * ipv6.h
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

#ifndef T2_IPV6_H_INCLUDED
#define T2_IPV6_H_INCLUDED

#include <stdint.h> // for uint16_t, uint32_t

#include "ipaddr.h" // for ipAddr_t


// IPv6 - Internet Protocol version 6


// Defines

// IPv6 fragmentation
#define FRAG6ID_N    0xf8ff
#define MORE_FRAG6_N 0x0100
#define FRAG6IDM_N   0xf9ff
#define FRAG6ID_1P_N 0x0000


// Structs

// IPv6 Header

typedef struct {
    uint32_t    vtc_flw_lbl;  // first word: ver, tcl, flow
    uint16_t    payload_len;  // payload length
    uint8_t     next_header;  // next protocol
    union {
        uint8_t hop_limit;    // hop limit
        uint8_t ip_ttl;       // TTL
    };
    ipAddr_t    ip_src;       // source address
    ipAddr_t    ip_dst;       // destination address
} __attribute__((packed)) ip6Header_t;


// IPv6 Option Header

typedef struct {
    uint8_t next_header;
    uint8_t len;
    uint8_t options;
} ip6OptHdr_t;


// IPv6 Hop-by-Hop Option

typedef struct {
    uint8_t  next_header;
    uint8_t  len;
    uint16_t reserved;
    uint32_t spi;          // security parameters index
    uint32_t seqnum;
    // Integrity Check Value (ICV): multiple of 32 bits
} ip6AHHdr_t;


// Fragment Header for IPv6

typedef struct {
    uint8_t  next_header;
    uint8_t  res;
    uint16_t frag_off;
    uint32_t id;
} ip6FragHdr_t;


// Routing Header for IPv6

typedef struct {
    uint8_t next_header;
    uint8_t len;
    uint8_t route_type;
    uint8_t seg_left;
} ip6RouteHdr_t;

#endif // T2_IPV6_H_INCLUDED
