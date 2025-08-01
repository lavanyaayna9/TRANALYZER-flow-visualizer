/*
 * gquicDecode.h
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

#ifndef __GQUIC_DECODE_H__
#define __GQUIC_DECODE_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define GQUIC_DEBUG  0 // 1: print warnings about unhandled cases
                       // 2: + print regular info about decoding status
#define GQUIC_SLEN  63 // Max length for string columns

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// plugin defines

 // UDP ports over which GQUIC runs
#define GQUIC_PORT1  80
#define GQUIC_PORT2 443

// Public Flags
#define GQUIC_PUB_FLAG_VERSION  0x01 // Header contains a GQUIC Version
#define GQUIC_PUB_FLAG_RESET    0x02 // Public Reset packet
#define GQUIC_PUB_FLAG_DNONCE   0x04 // 32 byte diversification nonce is present
#define GQUIC_PUB_FLAG_CID      0x08 // 8 byte Connection ID is present
#define GQUIC_PUB_FLAG_CID_OLD  0x0c // 8 byte Connection ID is present (version < 33)
#define GQUIC_PUB_FLAG_PKTNO    0x30 // Number of low-order bytes of the packet number
#define GQUIC_PUB_FLAG_MPATH    0x40 // Reserved for multipath use
#define GQUIC_PUB_FLAG_RESERVED 0x80 // Currently unused, MUST be 0

// Private Flags
#define GQUIC_PRIV_FLAG_ENTROPY  0x01 // Entropy
#define GQUIC_PRIV_FLAG_FEC_GRP  0x02 // FEC Group
#define GQUIC_PRIV_FLAG_FEC      0x04 // FEC
#define GQUIC_PRIV_FLAG_RESERVED 0xf8 // Reserved, MUST be 0

// Frame types
#define GQUIC_FRAME_TYPE_PADDING    0x00
#define GQUIC_FRAME_TYPE_RST_STREAM 0x01
#define GQUIC_FRAME_TYPE_CONN_CLOSE 0x02 // CONNECTION_CLOSE
#define GQUIC_FRAME_TYPE_GOAWAY     0x03
#define GQUIC_FRAME_TYPE_WIN_UPDATE 0x04 // WINDOW_UPDATE
#define GQUIC_FRAME_TYPE_BLOCKED    0x05
#define GQUIC_FRAME_TYPE_STOP_WAIT  0x06 // STOP_WAITING
#define GQUIC_FRAME_TYPE_PING       0x07
// Special Frame types
//#define GQUIC_FRAME_TYPE_CONG_FBACK 0x20 // CONGESTION_FEEDBACK
#define GQUIC_FRAME_TYPE_ACK        0x40 // 01nullmm
#define GQUIC_FRAME_TYPE_STREAM     0x80 // 1fdoooss

// ACK frame
#define GQUIC_ACK_FRAME_MP_LEN   0x03 // Length of the Missing Packet Sequence Number Delta field (2 bits)
#define GQUIC_ACK_FRAME_LL_LEN   0x0c // Length of the Largest Observed field (2 bits)
#define GQUIC_ACK_FRAME_RESERVED 0x10 // Reserved, MUST be 0
#define GQUIC_ACK_FRAME_ACK_N    0x20 // Frame has more than 1 ack range
#define GQUIC_ACK_FRAME_ACK      0x40

// STREAM frame
#define GQUIC_STREAM_FRAME_SLEN   0x03 // Stream Length (2 bits)
#define GQUIC_STREAM_FRAME_OLEN   0x1c // Offset Length (3 bits)
#define GQUIC_STREAM_FRAME_DLEN   0x20 // Data Length
#define GQUIC_STREAM_FRAME_FIN    0x40
#define GQUIC_STREAM_FRAME_STREAM 0x80

// Error codes (TODO)
// The number to code mappings for GQuicErrorCodes are currently defined in
// the Chromium source code in src/net/quic/quic_protocol.h

// Tag types
#define GQUIC_TAG_CHLO 0x43484c4f // Client Hello (CHLO)
#define GQUIC_TAG_SHLO 0x53484c4f // Server Hello (SHLO)
#define GQUIC_TAG_REJ  0x52454a00 // Rejection (REJ)
#define GQUIC_TAG_PRST 0x50525354 // Public Reset (PRST)

// Tag types
#define GQUIC_TAG_TYPE_AEAD 0x41454144 // Authenticated encryption algorithm
#define GQUIC_TAG_TYPE_CCRT 0x43435254 // Cached certificates
#define GQUIC_TAG_TYPE_CCS  0x43435300 // Common Certificate Sets
#define GQUIC_TAG_TYPE_CETV 0x43455456 // Client encrypted tag-value
#define GQUIC_TAG_TYPE_CFCW 0x43464357 // Initial session/connection
#define GQUIC_TAG_TYPE_CGST 0x43475354 // ???
#define GQUIC_TAG_TYPE_COPT 0x434f5054 // Connection options
#define GQUIC_TAG_TYPE_CRT  0x435254ff // XXX Certificate chain
#define GQUIC_TAG_TYPE_CSCT 0x43534354 // Signed cert timestamp (RFC6962) or leaf cert
#define GQUIC_TAG_TYPE_CTIM 0x4354494d // XXX Client Timestamp
#define GQUIC_TAG_TYPE_EXPY 0x45585059 // XXX Expiry
#define GQUIC_TAG_TYPE_FHOL 0x46484f4c // XXX Force Head of Line blocking
#define GQUIC_TAG_TYPE_ICSL 0x4943534c // Idle connection state
#define GQUIC_TAG_TYPE_IRTT 0x49525454 // Estimated initial RTT
#define GQUIC_TAG_TYPE_KEXS 0x4b455853 // Key exchange algorithms
#define GQUIC_TAG_TYPE_MIDS 0x4d494453 // XXX Max incoming dynamic streams
#define GQUIC_TAG_TYPE_MSPC 0x4d535043 // Max streams per connection
#define GQUIC_TAG_TYPE_NONC 0x4e4f4e43 // Client Nonce
#define GQUIC_TAG_TYPE_NONP 0x4e4f4e50 // Client Proof Nonce
#define GQUIC_TAG_TYPE_OBIT 0x4f424954 // XXX Server Orbit
#define GQUIC_TAG_TYPE_PAD  0x50414400 // Padding
#define GQUIC_TAG_TYPE_PDMD 0x50444d44 // Proof demand
#define GQUIC_TAG_TYPE_PROF 0x50524f46 // Proof (Signature) (PROF)
#define GQUIC_TAG_TYPE_PUBS 0x50554253 // Public value
#define GQUIC_TAG_TYPE_RREJ 0x5252454a // Reasons for server sending
#define GQUIC_TAG_TYPE_SCFG 0x53434647 // Server Config (SCFG)
#define GQUIC_TAG_TYPE_SCID 0x53434944 // Server config ID
#define GQUIC_TAG_TYPE_SCLS 0x53434c53 // Silently close on timeout
#define GQUIC_TAG_TYPE_SFCW 0x53464357 // Initial stream flow control
#define GQUIC_TAG_TYPE_SNI  0x534e4900 // Server Name Indication
#define GQUIC_TAG_TYPE_SNO  0x534e4f00 // Server Nonce (SNO)
#define GQUIC_TAG_TYPE_SRBF 0x53524246 // Socket receive buffer
#define GQUIC_TAG_TYPE_STK  0x53544b00 // Source Address Token
#define GQUIC_TAG_TYPE_STTL 0x5354544c // XXX Server Config TTL
#define GQUIC_TAG_TYPE_TCID 0x54434944 // Connection ID truncation
#define GQUIC_TAG_TYPE_UAID 0x55414944 // Client's User Agent ID
#define GQUIC_TAG_TYPE_VER  0x56455200 // Version
#define GQUIC_TAG_TYPE_XLCT 0x584c4354 // Expected leaf certificate

// Wrappers for t2buf
#define GQUIC_SEEK(t2buf, pos, whence) \
    if (UNLIKELY(!t2buf_seek((t2buf), (pos), (whence)))) { \
        gquicFlowP->stat |= GQUIC_STAT_SNAPPED; \
        return; \
    }

#define GQUIC_READ_STR(t2buf, dest, len) \
    if (UNLIKELY(!t2buf_readstr((t2buf), (uint8_t*)(dest), (len)+1, T2BUF_ASCII, true))) { \
        gquicFlowP->stat |= GQUIC_STAT_SNAPPED; \
        return; \
    }

#define GQUIC_SKIP_U8(t2buf) \
    if (UNLIKELY(!t2buf_skip_u8((t2buf)))) { \
        gquicFlowP->stat |= GQUIC_STAT_SNAPPED; \
        return; \
    }

#define GQUIC_SKIP_U16(t2buf) \
    if (UNLIKELY(!t2buf_skip_u16((t2buf)))) { \
        gquicFlowP->stat |= GQUIC_STAT_SNAPPED; \
        return; \
    }

#define GQUIC_SKIP_U32(t2buf) \
    if (UNLIKELY(!t2buf_skip_u32((t2buf)))) { \
        gquicFlowP->stat |= GQUIC_STAT_SNAPPED; \
        return; \
    }

#define GQUIC_SKIP_U64(t2buf) \
    if (UNLIKELY(!t2buf_skip_u64((t2buf)))) { \
        gquicFlowP->stat |= GQUIC_STAT_SNAPPED; \
        return; \
    }

#define GQUIC_SKIP_N(t2buf, n) \
    if (UNLIKELY(!t2buf_skip_n((t2buf), (n)))) { \
        gquicFlowP->stat |= GQUIC_STAT_SNAPPED; \
        return; \
    }

#define GQUIC_READ_U8(t2buf, dest) \
    if (UNLIKELY(!t2buf_read_u8((t2buf), (dest)))) { \
        gquicFlowP->stat |= GQUIC_STAT_SNAPPED; \
        return; \
    }

#define GQUIC_READ_U16(t2buf, dest) \
    if (UNLIKELY(!t2buf_read_u16((t2buf), (dest)))) { \
        gquicFlowP->stat |= GQUIC_STAT_SNAPPED; \
        return; \
    }

#define GQUIC_READ_U24(t2buf, dest) \
    if (UNLIKELY(!t2buf_read_u24((t2buf), (dest)))) { \
        gquicFlowP->stat |= GQUIC_STAT_SNAPPED; \
        return; \
    }

#define GQUIC_READ_U32(t2buf, dest) \
    if (UNLIKELY(!t2buf_read_u32((t2buf), (dest)))) { \
        gquicFlowP->stat |= GQUIC_STAT_SNAPPED; \
        return; \
    }

#define GQUIC_READ_U48(t2buf, dest) \
    if (UNLIKELY(!t2buf_read_u48((t2buf), (dest)))) { \
        gquicFlowP->stat |= GQUIC_STAT_SNAPPED; \
        return; \
    }

#define GQUIC_READ_LE_U16(t2buf, dest) \
    if (UNLIKELY(!t2buf_read_le_u16((t2buf), (dest)))) { \
        gquicFlowP->stat |= GQUIC_STAT_SNAPPED; \
        return; \
    }

#define GQUIC_READ_LE_U32(t2buf, dest) \
    if (UNLIKELY(!t2buf_read_le_u32((t2buf), (dest)))) { \
        gquicFlowP->stat |= GQUIC_STAT_SNAPPED; \
        return; \
    }

#define GQUIC_READ_LE_U64(t2buf, dest) \
    if (UNLIKELY(!t2buf_read_le_u64((t2buf), (dest)))) { \
        gquicFlowP->stat |= GQUIC_STAT_SNAPPED; \
        return; \
    }

// Status variable
#define GQUIC_STAT_GQUIC      0x01 // Flow is GQUIC
#define GQUIC_STAT_HANDSHAKE  0x02 // Stream ID 1
#define GQUIC_STAT_CID_CHANGE 0x04 // Connection ID changed
#define GQUIC_STAT_SNAPPED    0x40 // Snapped (t2buf failed)
#define GQUIC_STAT_MALFORMED  0x80 // Malformed

typedef struct {
    uint64_t connID;        // Connection ID
    uint16_t frame_type;
    char sni[GQUIC_SLEN+1];  // Server Name Indication (SNI)
    char uaid[GQUIC_SLEN+1]; // Client's User Agent ID (UAID)
    uint8_t pub_flags;
    //uint8_t priv_flags;
    uint8_t stat;
} gquic_flow_t;

// plugin struct pointer for potential dependencies
extern gquic_flow_t *gquic_flows;

#endif // __GQUIC_DECODE_H__
