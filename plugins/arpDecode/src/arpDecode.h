/*
 * arpDecode.h
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

#ifndef __ARP_DECODE_H__
#define __ARP_DECODE_H__

#include "t2Plugin.h"
#include "proto/arp.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define ARP_MAX_IP 10 // Max. number of MAC/IP pairs to list [1 - 255]

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*        No env / runtime configuration flags available for arpDecode        */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// plugin defines

// Use those packets to build the ARP table
#define ARP_SUPPORTED_OPCODE ( \
    1 << ARP_OPCODE_REQ  | \
    1 << ARP_OPCODE_REP  | \
    1 << RARP_OPCODE_REP   \
)

#define ARP_MAC_MASK 0x0000ffffffffffff


// arpStat
#define ARP_STAT_DET       0x01 // ARP detected
#define ARP_STAT_GRAT      0x02 // Gratuitous ARP
#define ARP_STAT_PROBE     0x04 // ARP Probe
#define ARP_STAT_ANNOUNCE  0x08 // ARP Announcement
#define ARP_STAT_FULL      0x20 // MAC/IP list truncated... increase ARP_MAX_IP
//#define ARP_STAT_MAC_SPOOF 0x40 // MAC spoofing (same IP assigned to multiple MACs)
#define ARP_STAT_SPOOF     0x80 // ARP spoofing (same MAC assigned to multiple IPs)


// Protocol structures

typedef struct {
    union {
        uint64_t u64;
        uint8_t  u8[8];
    };
} __attribute__((packed)) mac64_t;


// Plugin structure

typedef struct {
    uint32_t ip[ARP_MAX_IP];
    uint16_t ipCnt[ARP_MAX_IP];
    uint16_t opCode;
    uint16_t hwType;
    uint16_t cnt;
    uint8_t mac[ARP_MAX_IP][ETH_ALEN];
    uint8_t stat;
} arpFlow_t;


// plugin struct pointer for potential dependencies
extern arpFlow_t *arpFlows;

#endif // __ARP_DECODE_H__
