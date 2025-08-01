/*
 * sshDecode.h
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

#ifndef __SSHDECODE_H__
#define __SSHDECODE_H__

// local includes
#include "t2Plugin.h"

#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define SSH_USE_PORT         0 // Count all packets to/from SSH_PORT as SSH
#define SSH_DECODE           2 // 0: Do not decode SSH handshake messages
                               // 1: Only decode SSH Key Exchange Init messages
                               // 2: Decode all SSH Exchange messages
#define SSH_FINGERPRINT      1 // Algorithm to use for the fingerprint (require SSH_DECODE == 2)
                               // 0: no fingerprint, 1: MD5, 2: SHA256
#define SSH_ALGO             1 // Output chosen algorithms
#define SSH_LISTS            0 // Output lists of supported algorithms
#define SSH_HASSH            1 // Output HASSH fingerprint (hash and description)
#define SSH_HASSH_STR        0 // Also output HASSH fingerprint before hashing
#define SSH_HASSH_DLEN     512 // Max length for HASSH descriptions
#define SSH_HASSH_STR_LEN 1024 // Max length for uncompressed HASSH signatures

#define SSH_BUF_SIZE 512 // Buffer size for strings
#define SSH_HKT_SIZE  48 // Host Key Type

#define SSH_DEBUG      0 // Activate debug output

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define SSH_HASSH_NAME "hassh_fingerprints.tsv" // Name of the HASSH database

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_SSH_HASSH_NAME,
    ENV_SSH_N
};


// plugin defines

#define SSH_COOKIE_SIZE  16

// Ports
#define SSH_PORT 22

// Protocols
#define SSH_MAGIC 0x5353482d // SSH- in network order

// Chosen MAC to display when a cipher comes with its own MAC
#define SSH_IMPLICIT "<implicit>"

#define SSH_MSG_KEXINIT 20 // [RFC4253]
#define SSH_MSG_NEWKEYS 21 // [RFC4253]

// sshStat status variable
#define SSH_STAT_SSH           0x0001 // Flow contains SSH protocol
#define SSH_STAT_VER_FIRST     0x0002 // Keep track of who sent the SSH banner first
#define SSH_STAT_BANNER        0x0004 // Banner does not end with CRLF or contains NULL
#define SSH_STAT_KEXINIT       0x0008 // Key Exchange Init message seen
#define SSH_STAT_DH_KEXINIT    0x0010 // Diffie-Hellman Key Exchange Init message seen
#define SSH_STAT_DH_KEXREPLY   0x0020 // Diffie-Hellman Key Exchange Reply message seen
#define SSH_STAT_ECDH_KEXINIT  0x0040 // Elliptic Curve Diffie-Hellman Key Exchange Init message seen
#define SSH_STAT_ECDH_KEXREPLY 0x0080 // Elliptic Curve Diffie-Hellman Key Exchange Reply message seen
#define SSH_STAT_DH_GEX_GROUP  0x0100 // Diffie-Hellman Group Exchange Group
#define SSH_STAT_DH_GEX_INIT   0x0200 // Diffie-Hellman Group Exchange Init
#define SSH_STAT_DH_GEX_REQ    0x0400 // Diffie-Hellman Group Exchange Request
#define SSH_STAT_DH_GEX_REP    0x0800 // Diffie-Hellman Group Exchange Reply
#define SSH_STAT_NEWKEYS       0x1000 // New Keys message seen
#define SSH_STAT_STR_TRUNC     0x2000 // String truncated.. increase SSH_BUF_SIZE
#define SSH_STAT_HKT_TRUNC     0x4000 // Host key type truncated.. increase SSH_HKT_SIZE
#define SSH_STAT_MALFORMED     0x8000 // Malformed (decoding error, encrypted, ...)


// Structs

typedef struct {
    uint16_t stat;

    char version[SSH_BUF_SIZE+1];

#if SSH_DECODE == 2
#if SSH_FINGERPRINT == 2
    char fingerprint[3*SHA256_DIGEST_LENGTH];
#elif SSH_FINGERPRINT == 1
    char fingerprint[3*MD5_DIGEST_LENGTH];
#endif // SSH_FINGERPRINT == 1
    char host_key_type[SSH_HKT_SIZE+1];
    //char kex_dh_h_sig[SSH_BUF_SIZE+1];
#endif // SSH_DECODE == 2

#if SSH_DECODE > 0 || SSH_HASSH == 1
    // SSH_MSG_KEXINIT
    char cookie[2*SSH_COOKIE_SIZE+1];
    char kex_algo[SSH_BUF_SIZE+1];
    char kex[SSH_HKT_SIZE+1];

#if SSH_ALGO == 1
    char comp_cs1[SSH_HKT_SIZE+1];
    char comp_sc1[SSH_HKT_SIZE+1];
    char enc_cs1[SSH_HKT_SIZE+1];
    char enc_sc1[SSH_HKT_SIZE+1];
    char lang_cs1[SSH_HKT_SIZE+1];
    char lang_sc1[SSH_HKT_SIZE+1];
    char mac_cs1[SSH_HKT_SIZE+1];
    char mac_sc1[SSH_HKT_SIZE+1];
    char srv_hkey[SSH_HKT_SIZE+1];
#endif // SSH_ALGO == 1

#if SSH_ALGO == 1 || SSH_LISTS == 1 || SSH_HASSH == 1
    char srv_hkey_algo[SSH_BUF_SIZE+1];
    char enc_cs[SSH_BUF_SIZE+1];
    char enc_sc[SSH_BUF_SIZE+1];
    char mac_cs[SSH_BUF_SIZE+1];
    char mac_sc[SSH_BUF_SIZE+1];
    char comp_cs[SSH_BUF_SIZE+1];
    char comp_sc[SSH_BUF_SIZE+1];
    char lang_cs[SSH_BUF_SIZE+1];
    char lang_sc[SSH_BUF_SIZE+1];
#endif // SSH_ALGO == 1 || SSH_LISTS == 1 || SSH_HASSH == 1

#endif // SSH_DECODE > 0 || SSH_HASSH == 1

#if SSH_HASSH == 1
    char hassh_desc[SSH_HASSH_DLEN+1];
    char hassh[2*MD5_DIGEST_LENGTH+1];
#if SSH_HASSH_STR == 1
    char hassh_str[SSH_HASSH_STR_LEN+1];
#endif
#endif // SSH_HASSH == 1
} sshFlow_t;

// plugin struct pointer for potential dependencies
extern sshFlow_t *sshFlows;

#endif // __SSHDECODE_H__
