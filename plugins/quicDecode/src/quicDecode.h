/*
 * quicDecode.h
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

#ifndef __QUIC_DECODE_H__
#define __QUIC_DECODE_H__

#include "quic_utils.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define QUIC_SPKT_TYPE_STR 1 // Format of packet type in packet mode:
                             //     0: number
                             //     1: string
#define QUIC_DECODE_TLS    1 // Decode TLS handshake in QUIC Initial packets
#define QUIC_DEBUG         0 // Activate debug output

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// plugin defines

#define QUIC_TSTAMP_2015 1420070400L // Unix Timestamp for 2015 (when QUIC was introduced)
#define QUIC_V1 0x00000001

// Used for 'print' in quic_spkt_t (bit set => field was set)
#define QUIC_SPKT_flags    0x01
#define QUIC_SPKT_pktType  0x02
#define QUIC_SPKT_version  0x04
#define QUIC_SPKT_srcCID   0x08
#define QUIC_SPKT_dstCID   0x10
#define QUIC_SPKT_origCID  0x20
#define QUIC_SPKT_pktnum   0x40

// Status variable
#define QUIC_STAT_QUIC           0x01 // Flow is QUIC
#define QUIC_STAT_HANDSHAKE      0x02 // Packet Type 2
#define QUIC_STAT_VERSION_NEGO   0x04 // Version negotiation (version is 0)
#define QUIC_STAT_VERSION_CHANGE 0x08 // Version changed
#define QUIC_STAT_DCID_CHANGE    0x10 // Destination Connection ID changed
#define QUIC_STAT_SCID_CHANGE    0x20 // Source Connection ID changed
#define QUIC_STAT_ODCID_CHANGE   0x40 // Original Destination Connection ID changed
#define QUIC_STAT_SNAPPED        0x80 // Snapped (t2buf failed)
//#define QUIC_STAT_MALFORMED      0x80 // Malformed

// Structs

// Packet mode
typedef struct {
    uint32_t   version;
    uint32_t   pktnum;
    uint8_t    flags;
    uint8_t    pktType;
    uint8_t    stat;
    quic_cid_t dstCID;
    quic_cid_t srcCID;
    quic_cid_t origCID; // Retry
    uint8_t    print;
} quic_spkt_t;

typedef struct {
    quic_cid_t dstCID;   // Destination Connection ID
    quic_cid_t srcCID;   // Source Connection ID
    quic_cid_t origCID;  // Original Destination Connection ID (Retry)
    uint32_t   version;
    uint8_t    pktType;
    uint8_t    flags;
    uint8_t    stat;
#if QUIC_DECODE_TLS != 0
    quic_cid_t first_dst_cid;   // 1st Client Destination Connection ID
    uint8_t    *decrypted_payload;
    size_t     decrypted_payload_len;
#endif // QUIC_DECODE_TLS != 0
} quic_flow_t;


// plugin struct pointer for potential dependencies
extern quic_flow_t *quic_flows;
//extern quic_spkt_t *quic_packet;  // TODO so other plugins may access the various fields

#endif // __QUIC_DECODE_H__
