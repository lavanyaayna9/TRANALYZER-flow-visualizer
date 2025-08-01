/*
 * geneve.h
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

#ifndef T2_GENEVE_H_INCLUDED
#define T2_GENEVE_H_INCLUDED

#include <stdbool.h>  // for bool
#include <stdint.h>   // for uint8_t, uint16_t, uint32_t

#include "packet.h"   // for packet_t


// GENEVE - Generic Network Virtualization Encapsulation

#define GENEVE_PORT 6081
//#define GENEVE_PORT_N 0xc117 // 6081

typedef struct {
    uint8_t optlen:6;     // Number of 4 bytes words
    uint8_t version:2;    // 0
    uint8_t reserved1:6;  // MUST be 0
    uint8_t critical:1;   // Critical options present
    uint8_t oam:1;        // OAM packet
    uint16_t proto;       // Protocol type
    uint32_t reserved2:8; // MUST be 0
    uint32_t vni:24;      // Virtual Network Identifier (VNI)
    // Variable Length Options
} __attribute__((packed)) geneve_header_t;

bool     t2_is_geneve      (uint16_t sport, uint16_t dport)    __attribute__((__const__));
uint8_t *t2_process_geneve (uint8_t *pktptr, packet_t *packet) __attribute__((__nonnull__(1, 2)));

#endif // T2_GENEVE_H_INCLUDED
