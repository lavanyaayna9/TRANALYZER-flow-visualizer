/*
 * teredo.h
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

#ifndef T2_TEREDO_H_INCLUDED
#define T2_TEREDO_H_INCLUDED

#include <stdbool.h>  // for bool
#include <stdint.h>   // for uint8_t, uint16_t, uint32_t, uint64_t

#include "packet.h"   // for packet_t


// Teredo

#define TEREDO_PORT   3544
//#define TEREDO_PORT_N 0xd80d // 3544

// Teredo IPv6 addresses start with 2001:0000:...
#define TEREDO_IPV6_PREFIX_N 0x00000120

typedef struct {
    uint16_t marker;            // 0x1000
    uint8_t  client_id_len;     // Client identifier length
    uint8_t  auth_value_len;    // Authentication value length
    uint64_t nonce;             // Nonce value
    uint8_t  confirmation_byte;
} __attribute__((packed)) teredo_authentication_header_t;

typedef struct {
    uint16_t marker;            // 0x0000
    uint16_t origin_udp_port;
    uint32_t origin_ipv4_address;
} __attribute__((packed)) teredo_origin_indication_header_t;

bool     t2_is_teredo      (uint16_t sport, uint16_t dport)    __attribute__((__const__));
uint8_t *t2_process_teredo (uint8_t *pktptr, packet_t *packet) __attribute__((__nonnull__(1, 2)));

#endif // T2_TEREDO_H_INCLUDED
