/*
 * p0f.h
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

#ifndef __P0F_H__
#define __P0F_H__

#include "t2Plugin.h"
#include "sslDecode.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define P0F_SSL_VER     1 // Consider the version for fingerprint match
#define P0F_SSL_NCIPHER 1 // Consider the number of ciphers for fingerprint match
#define P0F_SSL_NUMEXT  1 // Consider the number of extensions for fingerprint match
#define P0F_SSL_FLAGS   1 // Consider flags for fingerprint match
#define P0F_SSL_CIPHER  1 // Consider ciphers for fingerprint match
#define P0F_SSL_EXT     1 // Consider extensions for fingerprint match

#define P0F_SSL_ELEN    6 // Maximum length of cipher or extension
#define P0F_SSL_NSIG   64 // Maximum number of signatures to read
#define P0F_SSL_SLEN  128 // Maximum length of a string (os, browser, comment)

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define P0F_SSL_DB "p0f-ssl.txt" // Name of the database to use

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_P0F_SSL_DB,
    ENV_P0F_N
};


// plugin defines

#if SSL_CIPHER_LIST == 0 && (P0F_SSL_NCIPHER == 1 || P0F_SSL_CIPHER == 1)
#warning "SSL_CIPHER_LIST not set in sslDecode.h... disabling P0F_SSL_NCIPHER and P0F_SSL_CIPHER"
#undef P0F_SSL_NCIPHER
#define P0F_SSL_NCIPHER 0
#undef P0F_SSL_CIPHER
#define P0F_SSL_CIPHER 0
#endif

#if SSL_EXT_LIST == 0 && (P0F_SSL_NUMEXT == 1 || P0F_SSL_EXT == 1)
#warning "SSL_EXT_LIST not set in sslDecode.h... disabling P0F_SSL_NUMEXT and P0F_SSL_EXT"
#undef P0F_SSL_NUMEXT
#define P0F_SSL_NUMEXT 0
#undef P0F_SSL_EXT
#define P0F_SSL_EXT 0
#endif


// Struct

typedef struct {
    uint16_t rulenum;
    uint16_t version;
    uint16_t nciphers;
    uint16_t numext;
#if P0F_SSL_CIPHER == 1
    char ciphers[SSL_MAX_CIPHER][P0F_SSL_ELEN];
#endif // P0F_SSL_CIPHER == 1
#if P0F_SSL_EXT == 1
    char ext[SSL_MAX_EXT][P0F_SSL_ELEN];
#endif // P0F_SSL_EXT == 1
    char os[P0F_SSL_SLEN];
    char os2[P0F_SSL_SLEN];
    char browser[P0F_SSL_SLEN];
    char comment[P0F_SSL_SLEN];
    uint8_t flags;
} p0f_ssl_sig;

#endif // __P0F_H__
