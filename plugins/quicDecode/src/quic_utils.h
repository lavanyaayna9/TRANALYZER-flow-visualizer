/*
 * quic_utils.h
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

#ifndef __QUIC_UTILS_H__
#define __QUIC_UTILS_H__

#include <stdbool.h>
#include <stdint.h>

#include "t2buf.h"


// UDP ports over which QUIC runs
#define QUIC_PORT_1 443
#define QUIC_PORT_2 4433

// 1st initial packet must fit in a single UDP packet:
// https://tools.ietf.org/html/draft-ietf-quic-tls-20#section-4.3
#define QUIC_MAX_INITIAL_PKT_LEN 1500

// Flags
#define QUIC_FLAGS_HDR_FORM(flags)  (((flags) & 0x80) >> 7) // Header Form: 0: Short, 1: Long
#define QUIC_FLAGS_FIXED_BIT(flags) (((flags) & 0x40) >> 6) // Fixed Bit
#define QUIC_FLAGS_SPIN_BIT(flags)  (((flags) & 0x20) >> 5) // Spin Bit [Short Header only]
#define QUIC_FLAGS_PKT_TYPE(flags)  (((flags) & 0x30) >> 4) // Packet Type [Long Header only]
#define QUIC_FLAGS_RESERVED(flags)  (((flags) & 0x0c) >> 2) // Reserved [Long Header only]
#define QUIC_FLAGS_PKTNUMLEN(flags)  ((flags) & 0x03)       // Packet Number Length [Long Header only]

// Header Form
#define QUIC_HAS_SHORT_HEADER(flags) (QUIC_FLAGS_HDR_FORM(flags) == 0)
#define QUIC_HAS_LONG_HEADER(flags)  (QUIC_FLAGS_HDR_FORM(flags) == 1)

// Packet Type
enum {
    QUIC_PKT_TYPE_INITIAL,   // 0
    QUIC_PKT_TYPE_0_RTT,     // 1
    QUIC_PKT_TYPE_HANDSHAKE, // 2
    QUIC_PKT_TYPE_RETRY,     // 3
    QUIC_NUM_PKT_TYPE
};

// QUIC Versions
#define QUIC_VERSION_DRAFT_20 0xff000014
#define QUIC_VERSION_DRAFT_21 0xff000015
#define QUIC_VERSION_DRAFT_22 0xff000016
#define QUIC_VERSION_DRAFT_23 0xff000017
#define QUIC_VERSION_DRAFT_24 0xff000018
#define QUIC_VERSION_DRAFT_25 0xff000019
#define QUIC_VERSION_DRAFT_26 0xff00001a
#define QUIC_VERSION_DRAFT_27 0xff00001b
#define QUIC_VERSION_DRAFT_28 0xff00001c
#define QUIC_VERSION_DRAFT_29 0xff00001d
#define QUIC_VERSION_DRAFT_30 0xff00001e
#define QUIC_VERSION_DRAFT_31 0xff00001f
#define QUIC_VERSION_DRAFT_32 0xff000020
#define QUIC_VERSION_DRAFT_33 0xff000021
#define QUIC_VERSION_DRAFT_34 0xff000022
#define QUIC_VERSION_2        0x6b3343cf

#define QUIC_CID_BYTES_MAX  20
#define QUIC_CID_STRLEN_MAX (2 * QUIC_CID_BYTES_MAX)

// QUIC frame types
#define QUIC_FT_PADDING              0x00 // PADDING
#define QUIC_FT_PING                 0x01 // PING
#define QUIC_FT_ACK                  0x02 // ACK Ranges
#define QUIC_FT_ACK_ECN              0x03 // ECN Counts
#define QUIC_FT_RESET_STREAM         0x04 // RESET_STREAM
#define QUIC_FT_STOP_SENDING         0x05 // STOP_SENDING
#define QUIC_FT_CRYPTO               0x06 // CRYPTO
#define QUIC_FT_NEW_TOKEN            0x07 // NEW_TOKEN
#define QUIC_FT_STREAM_8             0x08 // STREAM
#define QUIC_FT_STREAM_9             0x09 // STREAM
#define QUIC_FT_STREAM_A             0x0a // STREAM
#define QUIC_FT_STREAM_B             0x0b // STREAM
#define QUIC_FT_STREAM_C             0x0c // STREAM
#define QUIC_FT_STREAM_D             0x0d // STREAM
#define QUIC_FT_STREAM_E             0x0e // STREAM
#define QUIC_FT_STREAM_F             0x0f // STREAM
#define QUIC_FT_MAX_DATA             0x10 // MAX_DATA
#define QUIC_FT_MAX_STREAM_DATA      0x11 // MAX_STREAM_DATA
#define QUIC_FT_MAX_STREAMS_BI       0x12 // MAX_STREAMS (bidirectional streams)
#define QUIC_FT_MAX_STREAMS_UNI      0x13 // MAX_STREAMS (unidirectional streams)
#define QUIC_FT_DATA_BLOCKED         0x14 // DATA_BLOCKED
#define QUIC_FT_STREAM_DATA_BLOCKED  0x15 // STREAM_DATA_BLOCKED
#define QUIC_FT_STREAMS_BLOCKED_BI   0x16 // STREAMS_BLOCKED (bidirectional streams)
#define QUIC_FT_STREAMS_BLOCKED_UNI  0x17 // STREAMS_BLOCKED (unidirectional streams)
#define QUIC_FT_NEW_CONNECTION_ID    0x18 // NEW_CONNECTION_ID
#define QUIC_FT_RETIRE_CONNECTION_ID 0x19 // RETIRE_CONNECTION_ID
#define QUIC_FT_PATH_CHALLENGE       0x1a // PATH_CHALLENGE
#define QUIC_FT_PATH_RESPONSE        0x1b // PATH_RESPONSE
#define QUIC_FT_CONNECTION_CLOSE_TPT 0x1c // CONNECTION_CLOSE (Transport: NO_ERROR or errors at the QUIC layer)
#define QUIC_FT_CONNECTION_CLOSE_APP 0x1d // CONNECTION_CLOSE (Application: errors with the application that uses QUIC)
#define QUIC_FT_LAST_FT              0x1e // Not a frame type, just a marker to detect invalid/unknown frame types

// Only for STREAM frames
#define QUIC_FT_STREAM_OFF(frame_type) (((frame_type) & 0x04) > 0) // Offset field is present
#define QUIC_FT_STREAM_LEN(frame_type) (((frame_type) & 0x02) > 0) // Length field is present
#define QUIC_FT_STREAM_FIN(frame_type) (((frame_type) & 0x01) > 0) // End of the stream

#define QUIC_FRAME_IS_STREAM(frame_type) \
    ((frame_type) >= QUIC_FT_STREAM_8 && \
     (frame_type) <= QUIC_FT_STREAM_F)


// Structs

typedef struct {
    uint8_t cid[QUIC_CID_BYTES_MAX+1];
    uint8_t len;
} quic_cid_t;


// Variables

extern const char * const quic_pkt_type_str[];
extern const char * const quic_frame_type_str[];


// Functions

extern void quic_cid_to_str(const uint8_t * const cid, uint8_t cid_len, char *dest);

extern bool t2buf_read_quic_int(t2buf_t *t2buf, uint64_t *dst);
extern bool t2buf_skip_quic_int(t2buf_t *t2buf);

extern bool t2buf_skip_quic_frame(t2buf_t *t2buf);

#endif // __QUIC_UTILS__
