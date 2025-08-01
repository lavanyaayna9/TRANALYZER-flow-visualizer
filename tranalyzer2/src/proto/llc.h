/*
 * llc.h
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

#ifndef T2_LLC_H_INCLUDED
#define T2_LLC_H_INCLUDED

#include <stdint.h>  // for uint8_t, uint16_t, uint32_t, uint64_t


// Logical Link Control (LLC)


// Defines

#define LLC_DSAP_S  0x01
#define LLC_SSAP_CR 0x01
#define LLC_STP     0x42
#define LLC_SNAPC   0xfe
#define LLC_SNAPR   0xff

#define LLC_LEN    0x05dc // 1500
#define LLC_DCODE  0x00fe
#define LLC_DCODEn 0xfe00

// LLC SAP
#define LLC_SAP_NULL     0x00 // NULL SAP
#define LLC_SAP_LLC      0x02 // LLC Sublayer Management
#define LLC_SAP_SNA_PATH 0x04 // SNA Path Control
#define LLC_SAP_IP       0x06 // TCP/IP
#define LLC_SAP_SNA1     0x08 // SNA
#define LLC_SAP_SNA2     0x0c // SNA
#define LLC_SAP_PNM      0x0e // Proway Network Management
#define LLC_SAP_NETWARE1 0x10 // NetWare (unofficial?)
#define LLC_SAP_OSINL1   0x14 // ISO Network Layer (OSLAN 1)
#define LLC_SAP_TI       0x18 // Texas Instruments
#define LLC_SAP_OSINL2   0x20 // ISO Network Layer (unofficial?)
#define LLC_SAP_OSINL3   0x34 // ISO Network Layer (unofficial?)
#define LLC_SAP_SNA3     0x40 // SNA
#define LLC_SAP_BSPAN    0x42 // Bridge Spanning Tree Proto
#define LLC_SAP_MMS      0x4e // Manufacturing Message Srv
#define LLC_SAP_OSINL4   0x54 // ISO Network Layer (OSLAN 2)
#define LLC_SAP_8208     0x7e // ISO 8208
#define LLC_SAP_3COM     0x80 // 3COM
#define LLC_SAP_BACNET   0x82 // BACnet
#define LLC_SAP_NESTAR   0x86 // Nestar
#define LLC_SAP_PRO      0x8e // Proway Active Station List
#define LLC_SAP_ARP      0x98 // ARP
#define LLC_SAP_SNAP     0xaa // SNAP
#define LLC_SAP_HPJD     0xb4 // HP JetDirect Printer
#define LLC_SAP_VINES1   0xba // Banyan Vines
#define LLC_SAP_VINES2   0xbc // Banyan Vines
#define LLC_SAP_SNA4     0xc8 // SNA
#define LLC_SAP_LAR      0xdc // LAN Address Resolution
#define LLC_SAP_RM       0xd4 // Resource Management
#define LLC_SAP_IPX      0xe0 // IPX/SPX
#define LLC_SAP_NETBEUI  0xf0 // NetBEUI
#define LLC_SAP_LANMGR   0xf4 // LanManager
#define LLC_SAP_IMPL     0xf8 // IMPL
#define LLC_SAP_UB       0xfa // Ungermann-Bass
#define LLC_SAP_DISC     0xfc // Discovery
#define LLC_SAP_OSI      0xfe // OSI Network Layers
#define LLC_SAP_GLOBAL   0xff // Global SAP


// Structs

typedef struct {
    uint16_t typ_len;   // ether type or length XXX this does NOT belong to the LLC header...
    uint16_t dssap;     // Destination & Source Service Access Point
    union {
        // command
        struct {
            uint32_t cntrl:8;
            uint32_t org:24;
            uint16_t type;
            uint16_t res;
        } cmd;
        // response
        struct {
            uint16_t cntrl;
            uint16_t org1;
            uint8_t  org2;
            uint16_t type;
            uint8_t  res;
        } res;
    };
} __attribute__((packed)) etherLLCHeader_t;

#endif // T2_LLC_H_INCLUDED
