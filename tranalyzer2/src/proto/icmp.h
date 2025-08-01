/*
 * icmp.h
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

#ifndef T2_ICMP_H_INCLUDED
#define T2_ICMP_H_INCLUDED

#include <stdint.h> // for uint8_t, uint16_t, uint32_t


// ICMP - Internet Control Message Protocol


// Structs

// ICMP header

typedef struct {
    uint8_t  type;  // message type
    uint8_t  code;  // type sub-code
    uint16_t checksum;
    union {
        // echo datagram
        struct {
            uint16_t id;
            uint16_t sequence;
        } echo;
        // gateway address
        uint32_t gateway;
        // path mtu discovery
        struct {
            uint16_t unused;
            uint16_t mtu;
        } frag;
    };
} __attribute__((packed)) icmpHeader_t;

#endif // T2_ICMP_H_INCLUDED
