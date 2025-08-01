/*
 * arp.h
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

#ifndef T2_ARP_H_INCLUDED
#define T2_ARP_H_INCLUDED

#include <stdint.h> // for uint16_t, uint32_t


// ARP - Address Resolution Protocol

// ARP opcode
#define ARP_OPCODE_REQ   1 // ARP request
#define ARP_OPCODE_REP   2 // ARP reply
#define RARP_OPCODE_REQ  3 // Reverse ARP (RARP) request
#define RARP_OPCODE_REP  4 // Reverse ARP (RARP) reply
#define DRARP_OPCODE_REQ 5 // Dynamic Reverse ARP (DRARP) request
#define DRARP_OPCODE_REP 6 // Dynamic Reverse ARP (DRARP) reply
#define DRARP_OPCODE_ERR 7 // Dynamic Reverse ARP (DRARP) error
#define INARP_OPCODE_REQ 8 // Inverse ARP (InARP) request
#define INARP_OPCODE_REP 9 // Inverse ARP (InARP) reply


// Structs

typedef struct {
    uint16_t hwType;    // Hardware type
    uint16_t protoType; // Protocol type
    uint8_t  hwSize;    // Hardware size
    uint8_t  protoSize; // Protocol size
    uint16_t opCode;    // Operation Code
    uint8_t  srcMAC[6]; // Sender MAC address
    uint32_t srcIP;     // Sender IP address
    uint8_t  dstMAC[6]; // Target MAC address
    uint32_t dstIP;     // Target IP address
} __attribute__((packed)) arpMsg_t;

#endif // T2_ARP_H_INCLUDED
