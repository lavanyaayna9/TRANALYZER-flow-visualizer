/*
 * outputBuffer.h
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

#ifndef T2_OUTPUTBUFFER_H_INCLUDED
#define T2_OUTPUTBUFFER_H_INCLUDED

#include <stddef.h>      // for size_t
#include <stdint.h>      // for uint32_t

#include "tranalyzer.h"  // for BLOCK_BUF


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define BUF_DATA_SHFT    0  // adds for each binary output record the length and
                            // shifts the record by n uint32_t words to the right
                            // (see binSink and socketSink plugins)
#define OUTBUF_AUTOPILOT 1  // Automatically increase the output buffer when required
#define OUTBUF_MAXSIZE_F 5  // Maximal factor to increase the output buffer size to
                            // (f * MAIN_OUTBUF_SIZE)

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// local defines
#define BUFFER_DATAP ((BUF_DATA_SHFT) * 4)

typedef struct {
    size_t    size;
    uint32_t  pos;
    char     *buffer;
} outputBuffer_t;


/* Variables */

extern const uint32_t ZERO;
extern const uint32_t ONE;


/* Functions */

outputBuffer_t *outputBuffer_initialize(size_t size);
void outputBuffer_destroy(outputBuffer_t *buffer);

void outputBuffer_append(outputBuffer_t *buffer, const char *output, size_t size) __attribute__((__nonnull__(1, 2)));
void outputBuffer_reset(outputBuffer_t *buffer) __attribute__((__nonnull__(1)));

// Append values with given size
#define OUTBUF_APPEND(buf, val, size) outputBuffer_append((buf), (char*)&(val), (size))

// Append unsigned values
#define OUTBUF_APPEND_U8(buf, val)  OUTBUF_APPEND((buf), (val), sizeof(uint8_t))
#define OUTBUF_APPEND_U16(buf, val) OUTBUF_APPEND((buf), (val), sizeof(uint16_t))
#define OUTBUF_APPEND_U32(buf, val) OUTBUF_APPEND((buf), (val), sizeof(uint32_t))
#define OUTBUF_APPEND_U64(buf, val) OUTBUF_APPEND((buf), (val), sizeof(uint64_t))

// Append unsigned values converted from network to host order
#define OUTBUF_APPEND_U16_NTOH(buf, val) { \
    const uint16_t u16 = ntohs(val); \
    OUTBUF_APPEND((buf), u16, sizeof(uint16_t)); \
}
#define OUTBUF_APPEND_U32_NTOH(buf, val) { \
    const uint32_t u32 = ntohl(val); \
    OUTBUF_APPEND((buf), u32, sizeof(uint32_t)); \
}
#define OUTBUF_APPEND_U64_NTOH(buf, val) { \
    const uint64_t u64 = htobe64(val); \
    OUTBUF_APPEND((buf), u64, sizeof(uint64_t)); \
}

// Append unsigned value 0
#define OUTBUF_APPEND_U64_ZERO(buf) { \
    const uint64_t zero = 0; \
    OUTBUF_APPEND_U64((buf), zero); \
}
#define OUTBUF_APPEND_U32_ZERO(buf) { \
    const uint32_t zero = 0; \
    OUTBUF_APPEND_U32((buf), zero); \
}
#define OUTBUF_APPEND_U16_ZERO(buf) { \
    const uint16_t zero = 0; \
    OUTBUF_APPEND_U16((buf), zero); \
}
#define OUTBUF_APPEND_U8_ZERO(buf) { \
    const uint8_t zero = 0; \
    OUTBUF_APPEND_U8((buf), zero); \
}

// Append signed values
#define OUTBUF_APPEND_I8(buf, val)  OUTBUF_APPEND((buf), (val), sizeof(int8_t))
#define OUTBUF_APPEND_I16(buf, val) OUTBUF_APPEND((buf), (val), sizeof(int16_t))
#define OUTBUF_APPEND_I32(buf, val) OUTBUF_APPEND((buf), (val), sizeof(int32_t))
#define OUTBUF_APPEND_I64(buf, val) OUTBUF_APPEND((buf), (val), sizeof(int64_t))

// Append signed value 0
#define OUTBUF_APPEND_I64_ZERO(buf) { \
    const int64_t zero = 0; \
    OUTBUF_APPEND_I64((buf), zero); \
}
#define OUTBUF_APPEND_I32_ZERO(buf) { \
    const int32_t zero = 0; \
    OUTBUF_APPEND_I32((buf), zero); \
}
#define OUTBUF_APPEND_I16_ZERO(buf) { \
    const int16_t zero = 0; \
    OUTBUF_APPEND_I16((buf), zero); \
}
#define OUTBUF_APPEND_I8_ZERO(buf) { \
    const int8_t zero = 0; \
    OUTBUF_APPEND_I8((buf), zero); \
}

// Append floating point values
#define OUTBUF_APPEND_FLT(buf, val) OUTBUF_APPEND((buf), (val), sizeof(float))
#define OUTBUF_APPEND_DBL(buf, val) OUTBUF_APPEND((buf), (val), sizeof(double))

// Append floating point value 0
#define OUTBUF_APPEND_FLT_ZERO(buf) { \
    const float zero = 0; \
    OUTBUF_APPEND_FLT((buf), zero); \
}
#define OUTBUF_APPEND_DBL_ZERO(buf) { \
    const double zero = 0; \
    OUTBUF_APPEND_DBL((buf), zero); \
}

// Append string values
#define OUTBUF_APPEND_STR(buf, val) outputBuffer_append((buf), (char*)(val), strlen((char*)(val))+1)
#define OUTBUF_APPEND_STR_EMPTY(buf) outputBuffer_append((buf), "", 1)
#define OUTBUF_APPEND_STR_AND_FREE(buf, val) { \
    if (val) { \
        OUTBUF_APPEND_STR(buf, val); \
        free(val); \
    } else { \
        OUTBUF_APPEND_STR_EMPTY(buf); \
    } \
}

// Append time values
#define OUTBUF_APPEND_TIME(buf, sec, usec) { \
    OUTBUF_APPEND_U64((buf), (sec)); \
    OUTBUF_APPEND_U32((buf), (usec)); \
}

// Append time value with seconds only (usec set to 0)
#define OUTBUF_APPEND_TIME_SEC(buf, sec) { \
    const uint32_t zero32 = 0; \
    OUTBUF_APPEND_TIME((buf), (sec), zero32); \
}

// Append time value 0
#define OUTBUF_APPEND_TIME_ZERO(buf) { \
    const uint64_t zero64 = 0; \
    OUTBUF_APPEND_TIME_SEC((buf), zero64); \
}

// Append MAC values
#define OUTBUF_APPEND_MAC(buf, mac) OUTBUF_APPEND((buf), (mac)[0], ETH_ALEN)

// Append MAC value 00:00:00:00:00:00
#define OUTBUF_APPEND_MAC_ZERO(buf) { \
    const uint8_t mac[ETH_ALEN] = {}; \
    OUTBUF_APPEND_MAC((buf), mac); \
}

// Append IP values
#define OUTBUF_APPEND_IP4(buf, ip) OUTBUF_APPEND_U32((buf), (ip).IPv4.s_addr)
#define OUTBUF_APPEND_IP6(buf, ip) OUTBUF_APPEND((buf), (ip).IPv6.s6_addr[0], 16)

// Append IP value 0
#define OUTBUF_APPEND_IP4_ZERO(buf) OUTBUF_APPEND_U32_ZERO((buf))
#define OUTBUF_APPEND_IP6_ZERO(buf) { \
    const uint8_t ip6[16] = {}; \
    OUTBUF_APPEND((buf), ip6, sizeof(ip6)); \
}

// Append an ipVAddr_t
#define OUTBUF_APPEND_IPV(buf, ip) OUTBUF_APPEND_IPVX((buf), (ip).ver, (ip).addr)

// Append IPvX
#define OUTBUF_APPEND_IPVX(buf, version, ip) { \
    OUTBUF_APPEND_U8((buf), (version)); \
    if ((version) == 6) { \
        OUTBUF_APPEND_IP6((buf), (ip)); \
    } else if ((version) == 4) { \
        OUTBUF_APPEND_IP4((buf), (ip)); \
    } else { \
        /* Not IPv4, nor IPv6... do not append anything */ \
    } \
}

// Appends the number of repetitive values (uint32_t)
extern void outputBuffer_append_numrep(outputBuffer_t *outbuf, uint32_t reps);

#define OUTBUF_APPEND_NUMREP(buf, reps) outputBuffer_append_numrep((buf), (reps));

#define OUTBUF_APPEND_NUMREP_ZERO(buf) OUTBUF_APPEND_NUMREP((buf), 0)
#define OUTBUF_APPEND_NUMREP_ONE(buf)  OUTBUF_APPEND_NUMREP((buf), 1)

// Append optional repetitive string (0 or 1), i.e.,
// if val is NULL or empty, append 0 (uint32_t)
// else append 1 (uint32_t) and the string
#define OUTBUF_APPEND_OPT_STR(buf, val) { \
    const size_t len = (val) ? strlen((val)) : 0; \
    if (len == 0) { \
        OUTBUF_APPEND_NUMREP_ZERO((buf)); \
    } else { \
        OUTBUF_APPEND_NUMREP_ONE((buf)); \
        outputBuffer_append((buf), (val), len+1); \
    } \
}

// Append repetitive values, i.e., append the 'size' of an array, then 'size' elements
// Type may be:
//  - I8, I16, I32, I64
//  - U8, U16, U32, U64
//  - FLT, DBL
//  - MAC, IP4, IP6
//  - STR
#define OUTBUF_APPEND_ARRAY(buf, array, size, type) { \
    OUTBUF_APPEND_NUMREP((buf), (size)); \
    for (uint_fast32_t i = 0; i < (size); i++) { \
        OUTBUF_APPEND_ ## type ((buf), (array)[i]); \
    } \
}

// Append repetitive unsigned values
#define OUTBUF_APPEND_ARRAY_U8(buf, array, size)  OUTBUF_APPEND_ARRAY((buf), (array), (size), U8)
#define OUTBUF_APPEND_ARRAY_U16(buf, array, size) OUTBUF_APPEND_ARRAY((buf), (array), (size), U16)
#define OUTBUF_APPEND_ARRAY_U32(buf, array, size) OUTBUF_APPEND_ARRAY((buf), (array), (size), U32)
#define OUTBUF_APPEND_ARRAY_U64(buf, array, size) OUTBUF_APPEND_ARRAY((buf), (array), (size), U64)

// Append repetitive signed values
#define OUTBUF_APPEND_ARRAY_I8(buf, array, size)  OUTBUF_APPEND_ARRAY((buf), (array), (size), I8)
#define OUTBUF_APPEND_ARRAY_I16(buf, array, size) OUTBUF_APPEND_ARRAY((buf), (array), (size), I16)
#define OUTBUF_APPEND_ARRAY_I32(buf, array, size) OUTBUF_APPEND_ARRAY((buf), (array), (size), I32)
#define OUTBUF_APPEND_ARRAY_I64(buf, array, size) OUTBUF_APPEND_ARRAY((buf), (array), (size), I64)

// Append repetitive floating point values
#define OUTBUF_APPEND_ARRAY_FLT(buf, array, size) OUTBUF_APPEND_ARRAY((buf), (array), (size), FLT)
#define OUTBUF_APPEND_ARRAY_DBL(buf, array, size) OUTBUF_APPEND_ARRAY((buf), (array), (size), DBL)

// Append repetitive string values
#define OUTBUF_APPEND_ARRAY_STR(buf, array, size) OUTBUF_APPEND_ARRAY((buf), (array), (size), STR)
#define OUTBUF_APPEND_ARRAY_STR_AND_FREE(buf, array, size) OUTBUF_APPEND_ARRAY((buf), (array), (size), STR_AND_FREE)

// Append repetitive MAC values
#define OUTBUF_APPEND_ARRAY_MAC(buf, array, size) OUTBUF_APPEND_ARRAY((buf), (array), (size), MAC)

// Append repetitive IP values
#define OUTBUF_APPEND_ARRAY_IP4(buf, array, size) OUTBUF_APPEND_ARRAY((buf), (array), (size), IP4)
#define OUTBUF_APPEND_ARRAY_IP6(buf, array, size) OUTBUF_APPEND_ARRAY((buf), (array), (size), IP6)
#define OUTBUF_APPEND_ARRAY_IPV(buf, array, size) OUTBUF_APPEND_ARRAY((buf), (array), (size), IPV)
#define OUTBUF_APPEND_ARRAY_IPVX(buf, version, array, size) { \
    OUTBUF_APPEND_NUMREP((buf), (size)); \
    for (uint_fast32_t i = 0; i < (size); i++) { \
        OUTBUF_APPEND_IPVX((buf), (version), (array)[i]); \
    } \
}

#endif // T2_OUTPUTBUFFER_H_INCLUDED
