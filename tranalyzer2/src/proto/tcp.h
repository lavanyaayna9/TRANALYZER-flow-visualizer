/*
 * tcp.h
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

#ifndef T2_TCP_H_INCLUDED
#define T2_TCP_H_INCLUDED

#include <stdint.h> // for uint16_t, uint32_t


// TCP - Transmission Control Protocol


// TCP flags

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80

#define TH_SYN_ACK     0x12
#define TH_FIN_ACK     0x11
#define TH_RST_ACK     0x14
#define TH_SYN_FIN     0x03
#define TH_RST_FIN     0x05
#define TH_SYN_FIN_RST 0x07
#define TH_ARSF        0x17
#define TH_NULL        0x00
#define TH_XMAS        0x29
#define TH_ALL_FLAGS   0x3f


// Structs

// TCP header

typedef struct {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t  res1:4;
    uint8_t  doff:4;
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} __attribute__((packed)) tcpHeader_t;

#endif // T2_TCP_H_INCLUDED
