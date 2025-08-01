/*
 * ipaddr.h
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

#ifndef T2_IPADDR_H_INCLUDED
#define T2_IPADDR_H_INCLUDED

#include <netinet/in.h>     // for struct in_addr, struct in6_addr
#include <stdint.h>         // for uint8_t, uint16_t, uint32_t, uint64_t


// Structs

// IP address

typedef union {
    uint32_t        IPv4x[4];
    struct in_addr  IPv4;       // IPv4 address
    struct in6_addr IPv6;       // IPv6 address
    uint64_t        IPv6L[2];   // IPv6 address 2*64 bit max chunk for masking ops
} __attribute__((packed)) ipAddr_t;

typedef struct {
    uint8_t  ver;    // version
    ipAddr_t addr;
} ipVAddr_t;

typedef union {
    uint32_t       IPv4x[1];
    struct in_addr IPv4;
} __attribute__((packed)) ip4Addr_t;

#endif // T2_IPADDR_H_INCLUDED
