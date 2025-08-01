/*
 * torDetector.h
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

/*
 * References:
 *   SSL 2.0 [https://tools.ietf.org/html/draft-hickman-netscape-ssl-00]
 *   SSL 3.0 [RFC 6101]
 *
 *   TLS 1.0 [RFC 2246]
 *   TLS 1.1 [RFC 4346]
 *   TLS 1.2 [RFC 5246]
 *
 *   DTLS 1.0 [RFC 4347]
 *   DTLS 1.2 [RFC 6347]
 *
 *   DTLS for DCCP [RFC 5238]
 *   DTLS for SRTP [RFC 5764]
 *   DTLS for SCTP [RFC 6083]
 *
 *  Tor certificates generation:
 *      https://gitweb.torproject.org/tor.git/tree/src/common/tortls.c?h=release-0.2.8#n1045
 *  Tor server name generation (used if we only have client flow):
 *      https://gitweb.torproject.org/tor.git/tree/src/common/tortls.c?h=release-0.2.8#n1609
 *  Tor cipher list (extracted from Firefox):
 *      https://gitweb.torproject.org/tor.git/tree/src/common/ciphers.inc?h=release-0.2.8
 *  Other Tor characteristics where deduced from manual comparison between HTTPS and Tor traffic:
 *      client supported cipher list, TLS extensions, ...
 *
 */

#ifndef __TORDETECTOR_H__
#define __TORDETECTOR_H__

#include <stdbool.h>  // for bool
#include <stdint.h>   // for uint16_t, uint32_t, uint8_t
#include <time.h>     // for struct tm

#include "sslDefines.h" // for SSL_CERT_COUNTRY_LEN, SSL_CERT_NAME_MAXLEN SSL_CERT_PK_TYPE_SLEN


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define TOR_DETECT_OBFUSCATION 1 // Detect obfuscation protocols
#define TOR_DEBUG_MESSAGES     0 // Activate debug output
#define TOR_PKTL               1 // Activate packet length modulo 8 heuristic

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*       No env / runtime configuration flags available for torDetector       */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


#define TOR_MAX_CERT_LEN     600

#define TOR_OBFUSC_BYTES     1024
#define TOR_OBFUSC_THRESHOLD 0.97 // defined by trial and error

// t2buf read/skip macros
#define TOR_READ_MACRO(suffix, t2buf, dest) \
    if (!t2buf_read_ ## suffix (t2buf, dest)) { \
        torFlowP->stat |= TOR_STAT_SNAP; \
        goto nxtpkt; \
    }

#define TOR_SKIP_MACRO(suffix, t2buf) \
    if (!t2buf_skip_ ## suffix (t2buf)) { \
        torFlowP->stat |= TOR_STAT_SNAP; \
        goto nxtpkt; \
    }

#define TOR_READ_N(t2buf, dest, n) \
    if (!t2buf_read_n(t2buf, dest, n)) { \
        torFlowP->stat |= TOR_STAT_SNAP; \
        goto nxtpkt; \
    }

#define TOR_SKIP_N(t2buf, n) \
    if (!t2buf_skip_n(t2buf, n)) { \
        torFlowP->stat |= TOR_STAT_SNAP; \
        goto nxtpkt; \
    }

#define TOR_READ_U8(t2buf, dest)  TOR_READ_MACRO(u8,  t2buf, dest)
#define TOR_READ_U16(t2buf, dest) TOR_READ_MACRO(u16, t2buf, dest)
#define TOR_READ_U24(t2buf, dest) TOR_READ_MACRO(u24, t2buf, dest)

#define TOR_SKIP_U16(t2buf) TOR_SKIP_MACRO(u16, t2buf)
#define TOR_SKIP_U24(t2buf) TOR_SKIP_MACRO(u24, t2buf)
#define TOR_SKIP_U32(t2buf) TOR_SKIP_MACRO(u32, t2buf)
#define TOR_SKIP_U48(t2buf) TOR_SKIP_MACRO(u48, t2buf)


// torStat
#define TOR_STAT_TOR    0x01 // Tor flow
#define TOR_STAT_OBFUSC 0x02 // Obfuscated Tor flow
#define TOR_STAT_ADDR   0x04 // Tor address detected
#define TOR_STAT_PKTL   0x08 // Tor pktlen modulo 8 detected
#define TOR_STAT_SYN    0x10 // Internal state: SYN detected
#define TOR_STAT_OBFCHK 0x20 // Internal state: obfuscation checked
#define TOR_STAT_SNAP   0x80 // Packet snapped or decoding failed



// plugin structs
typedef struct {
    uint8_t type;     // record type (SSL_RT_*)
    uint16_t version; // major(8), minor(8)
    uint16_t len;     // length of data in the record (excluding the header)
                      // (MUST NOT exceed 16384)
} sslRecordHeader_t;

typedef struct {
    uint8_t type;
    uint32_t len; // message length
} sslHandshake_t;

typedef struct {
    uint16_t pkey_size; // public key size (bits)
    char pkey_type[SSL_CERT_PK_TYPE_SLEN+1];   // public key type (RSA, DSA, ECDSA, UNK (Unknown))

    // Certificate Subject
    char sCommon[SSL_CERT_NAME_MAXLEN+1];
    char sOrg[SSL_CERT_NAME_MAXLEN+1];
    char sCountry[SSL_CERT_COUNTRY_LEN+1]; // ISO3166 two character country code

    // Certificate Issuer
    char iCommon[SSL_CERT_NAME_MAXLEN+1];
    char iOrg[SSL_CERT_NAME_MAXLEN+1];
    char iCountry[SSL_CERT_COUNTRY_LEN+1]; // ISO3166 two character country code

    struct tm cert_not_before;
    struct tm cert_not_after;
} sslCert_t;

typedef struct {
#if TOR_DETECT_OBFUSCATION == 1
    size_t byte_count;
    uint8_t bytes[256];
#endif // TOR_DETECT_OBFUSCATION
#if TOR_PKTL == 1
    uint16_t minL3PktSz;
    uint16_t maxL3PktSz;
#endif // TOR_PKTL == 1
    uint8_t stat;
} torFlow_t;

extern torFlow_t *torFlows;

#endif // __TORDETECTOR_H__
