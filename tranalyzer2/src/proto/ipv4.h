/*
 * ipv4.h
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

#ifndef T2_IPV4_H_INCLUDED
#define T2_IPV4_H_INCLUDED

#include <netinet/in.h> // for struct in_addr
#include <stdint.h>     // for uint8_t, uint16_t, uint32_t


// IPv4 - Internet Protocol version 4


// Defines

#define IP_V(ip) (((ip)->ip_vhl & 0xf0) >> 4) // Version
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)       // Header length

#define IP_DF       0x4000                    // Don't fragment flag
#define IP_MF       0x2000                    // More fragments flag
#define IP_OFFMASK  0x1fff                    // Mask for fragmenting bits

// IPv4 fragmentation
#define FRAGID_N    0xff1f
#define MORE_FRAG_N 0x0020
#define FRAGIDM_N   0xff3f
#define FRAGID_1P_N 0x0000


// Structs

typedef struct {
    uint8_t        ip_vhl;  // version, header length
    uint8_t        ip_tos;  // type of service
    uint16_t       ip_len;  // total length
    uint16_t       ip_id;   // identification
    uint16_t       ip_off;  // fragment offset field
    uint8_t        ip_ttl;  // time to live
    uint8_t        ip_p;    // protocol
    uint16_t       ip_sum;  // checksum
    struct in_addr ip_src;  // source address
    struct in_addr ip_dst;  // destination address
} __attribute__((packed)) ipHeader_t;

#endif // T2_IPV4_H_INCLUDED
