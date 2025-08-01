/*
 * dtls.h
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

#ifndef T2_DTLS_H_INCLUDED
#define T2_DTLS_H_INCLUDED

#include <stdint.h> // for uint8_t, uint16_t


// DTLS - Datagram Transport Layer Security


// DTLS versions

// Network order
#define DTLS_V10_N         0xfffe // DTLS 1.0
#define DTLS_V10_OPENSSL_N 0x0001 // DTLS 1.0 openssl
#define DTLS_V12_N         0xfdfe // DTLS 1.2
// DTLS 1.1 does not exist
#define DTLS_V13_N         0xfcfe // DTLS 1.3

// Host order
#define DTLS_V10         0xfeff // DTLS 1.0
#define DTLS_V10_OPENSSL 0x0100 // DTLS 1.0 openssl
#define DTLS_V12         0xfefd // DTLS 1.2
// DTLS 1.1 does not exist
#define DTLS_V13         0xfefc // DTLS 1.3


// DTLS content types

#define DTLS_CT_CHGCS 0x14  // Change Cipher Spec
#define DTLS_CT_ALRT  0x15  // Alert
#define DTLS_CT_HDSHK 0x16  // Handshake
#define DTLS_CT_DATA  0x17  // Application data
#define DTLS_CT_HRTBT 0x18  // Heartbeat
#define DTLS_CT_CID   0x19  // TLS 1.2 CID
#define DTLS_CT_ACK   0x1a


// Structs

// DTLS 1.2 header

typedef struct {
    uint8_t  ctype;     // Content type
    uint16_t version;   // Protocol version
    uint16_t epoch;
    uint64_t seqn:48;   // Sequence number
    uint64_t len:16;    // Length
} __attribute__((packed)) dtls12Header_t;

#endif // T2_DTLS_H_INCLUDED
