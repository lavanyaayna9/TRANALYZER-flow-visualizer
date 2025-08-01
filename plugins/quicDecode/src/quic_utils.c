/*
 * quic_utils.c
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

#include "quic_utils.h"
#include <stdio.h>


const char * const quic_pkt_type_str[] = {
    "Initial",
    "0-RTT",
    "Handshake",
    "Retry"
};

const char * const quic_frame_type_str[] = {
    "PADDING",
    "PING",
    "ACK",
    "ACK",
    "RESET_STREAM",
    "STOP_SENDING",
    "CRYPTO",
    "NEW_TOKEN",
    "STREAM",
    "STREAM",
    "STREAM",
    "STREAM",
    "STREAM",
    "STREAM",
    "STREAM",
    "STREAM",
    "MAX_DATA",
    "MAX_STREAM_DATA",
    "MAX_STREAMS (bidirectional)",
    "MAX_STREAMS (unidirectional)",
    "DATA_BLOCKED",
    "STREAM_DATA_BLOCKED",
    "STREAMS_BLOCKED (bidirectional)",
    "STREAMS_BLOCKED (unidirectional)",
    "NEW_CONNECTION_ID",
    "RETIRE_CONNECTION_ID",
    "PATH_CHALLENGE",
    "PATH_RESPONSE",
    "CONNECTION_CLOSE (Transport)",
    "CONNECTION_CLOSE (Application)",
};


inline void quic_cid_to_str(const uint8_t * const cid, uint8_t cid_len, char *dest) {
    if (cid_len == 0) {
        dest[0] = '\0';
    } else {
        for (uint_fast32_t i = 0, j = 0; i < cid_len; i++, j += 2) {
            snprintf(&(dest[j]), 3, "%02x", cid[i]);
        }
    }
}


/**
 * Read a QUIC variable length integer from a t2buf
 *
 * https://tools.ietf.org/html/draft-ietf-quic-transport-20#section-16
 */
inline bool t2buf_read_quic_int(t2buf_t *t2buf, uint64_t *dst) {
    uint8_t b1;
    if (!t2buf_peek_u8(t2buf, &b1)) {
        return false;
    }
    switch (b1 >> 6) {
        case 0:
            t2buf_skip_u8(t2buf);
            *dst = (uint64_t)b1 & 0x3f;
            break;
        case 1: {
            uint16_t tmp;
            if (!t2buf_read_u16(t2buf, &tmp)) {
                return false;
            }
            *dst = (uint64_t)tmp & 0x3fff;
            break;
        }
        case 2: {
            uint32_t tmp;
            if (!t2buf_read_u32(t2buf, &tmp)) {
                return false;
            }
            *dst = (uint64_t)tmp & 0x3fffffff;
            break;
        }
        case 3: {
            uint64_t tmp;
            if (!t2buf_read_u64(t2buf, &tmp)) {
                return false;
            }
            *dst = (uint64_t)tmp & 0x3fffffffffffffff;
            break;
        }
    }
    return true;
}


inline bool t2buf_skip_quic_int(t2buf_t *t2buf) {
    uint8_t b1;
    if (!t2buf_peek_u8(t2buf, &b1)) {
        return false;
    }
    switch (b1 >> 6) {
        case  0: return t2buf_skip_u8(t2buf);
        case  1: return t2buf_skip_u16(t2buf);
        case  2: return t2buf_skip_u32(t2buf);
        case  3: return t2buf_skip_u64(t2buf);
        default: return true;
    }
}


inline bool t2buf_skip_quic_frame(t2buf_t *t2buf) {

    uint8_t frame_type;
    if (!t2buf_read_u8(t2buf, &frame_type)) {
    //if (!t2buf_read_quic_int(t2buf, &frame_type)) {
        return false;
    }

    switch (frame_type) {

        case QUIC_FT_PADDING:
            // Skip all PADDING frames in one go
            while (t2buf_peek_u8(t2buf, &frame_type)) {
                if (frame_type != QUIC_FT_PADDING) {
                    return true;
                }
                t2buf_skip_u8(t2buf);
            }
            return false;

        case QUIC_FT_PING:
            return true;

        case QUIC_FT_ACK:
        case QUIC_FT_ACK_ECN: {
            uint64_t count;
            if (!t2buf_skip_quic_int(t2buf)         || // Largest Acknowledged
                !t2buf_skip_quic_int(t2buf)         || // ACK Delay
                !t2buf_read_quic_int(t2buf, &count) || // ACK Range Count
                !t2buf_skip_quic_int(t2buf))           // First ACK Range
            {
                return false;
            }

            while (count) {
                if (!t2buf_skip_quic_int(t2buf) || // Gap
                    !t2buf_skip_quic_int(t2buf))   // ACK Range
                {
                    return false;
                }
                --count;
            }

            if (frame_type == QUIC_FT_ACK_ECN) {
                if (!t2buf_skip_quic_int(t2buf) || // ECT(0) Count
                    !t2buf_skip_quic_int(t2buf) || // ECT(1) Count
                    !t2buf_skip_quic_int(t2buf))   // ECN-CE Count
                {
                    return false;
                }
            }

            return true;
        }

        case QUIC_FT_RESET_STREAM:
            if (!t2buf_skip_quic_int(t2buf) || // Stream ID
                !t2buf_skip_u16(t2buf)      || // Application Error Code
                !t2buf_skip_quic_int(t2buf))   // Final Size
            {
                return false;
            }
            return true;

        case QUIC_FT_STOP_SENDING:
            if (!t2buf_skip_quic_int(t2buf) || // Stream ID
                !t2buf_skip_u16(t2buf))        // Application Error Code
            {
                return false;
            }
            return true;

        case QUIC_FT_CRYPTO: {
            uint64_t offset, length;
            if (!t2buf_read_quic_int(t2buf, &offset) ||
                !t2buf_read_quic_int(t2buf, &length))
            {
                return false;
            }
            return t2buf_skip_n(t2buf, length);
        }

        case QUIC_FT_NEW_TOKEN: {
            uint64_t length;
            if (!t2buf_read_quic_int(t2buf, &length) || // Token Length
                !t2buf_skip_n(t2buf, length))           // Token
            {
                return false;
            }
            return true;
        }

        case QUIC_FT_STREAM_8:
        case QUIC_FT_STREAM_9:
        case QUIC_FT_STREAM_A:
        case QUIC_FT_STREAM_B:
        case QUIC_FT_STREAM_C:
        case QUIC_FT_STREAM_D:
        case QUIC_FT_STREAM_E:
        case QUIC_FT_STREAM_F: {
            if (!t2buf_skip_quic_int(t2buf)) { // Stream ID
               return false;
            }

            if (QUIC_FT_STREAM_OFF(frame_type)) {
                if (!t2buf_skip_quic_int(t2buf)) { // Offset
                    return false;
                }
            }

            if (QUIC_FT_STREAM_LEN(frame_type)) {
                uint64_t length;
                if (!t2buf_read_quic_int(t2buf, &length)) { // Length
                    return false;
                }

                return t2buf_skip_n(t2buf, length);
            }

            // Length field not present, Stream data consumes everything!
            return t2buf_skip_n(t2buf, t2buf_left(t2buf));
        }

        case QUIC_FT_MAX_DATA:
            return t2buf_skip_quic_int(t2buf); // Maximum Data

        case QUIC_FT_MAX_STREAM_DATA:
            if (!t2buf_skip_quic_int(t2buf) || // Stream ID
                !t2buf_skip_quic_int(t2buf))   // Maximum Stream Data
            {
                return false;
            }
            return true;

        case QUIC_FT_MAX_STREAMS_BI:
        case QUIC_FT_MAX_STREAMS_UNI:
            return t2buf_skip_quic_int(t2buf); // Maximum Streams

        case QUIC_FT_DATA_BLOCKED:
            return t2buf_skip_quic_int(t2buf); // Data Limit

        case QUIC_FT_STREAM_DATA_BLOCKED:
            if (!t2buf_skip_quic_int(t2buf) || // Stream ID
                !t2buf_skip_quic_int(t2buf))   // Stream Data Limit
            {
                return false;
            }
            return true;

        case QUIC_FT_STREAMS_BLOCKED_BI:
        case QUIC_FT_STREAMS_BLOCKED_UNI:
            return t2buf_skip_quic_int(t2buf); // Stream Limit

        case QUIC_FT_NEW_CONNECTION_ID: {
            uint8_t length;
            if (!t2buf_skip_quic_int(t2buf)    || // Sequence Number
                !t2buf_read_u8(t2buf, &length) || // Connection ID Length
                !t2buf_skip_n(t2buf, length)   || // Connection ID
                !t2buf_skip_n(t2buf, 128))        // Stateless Reset Token
            {
                return false;
            }
            return true;
        }

        case QUIC_FT_RETIRE_CONNECTION_ID:
            return t2buf_skip_quic_int(t2buf); // Sequence Number

        case QUIC_FT_PATH_CHALLENGE:
        case QUIC_FT_PATH_RESPONSE:
            return t2buf_skip_u64(t2buf); // Data

        case QUIC_FT_CONNECTION_CLOSE_TPT:
        case QUIC_FT_CONNECTION_CLOSE_APP: {
            if (!t2buf_skip_u16(t2buf)) { // Error Code
                return false;
            }

            if (frame_type == QUIC_FT_CONNECTION_CLOSE_TPT) {
                if (!t2buf_skip_quic_int(t2buf)) { // Frame Type
                    return false;
                }
            }

            uint64_t length;
            if (!t2buf_read_quic_int(t2buf, &length) || // Reason Phrase Length
                !t2buf_skip_n(t2buf, length))           // Reason Phrase
            {
                return false;
            }

            return true;
        }

        default:
            // Unknown frame type
            return false;
    }

    return false;
}
