/*
 * ntlmsspDecode.h
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

#ifndef T2_NTLMSSPDECODE_H_INCLUDED
#define T2_NTLMSSPDECODE_H_INCLUDED

// Global includes
//#include <stdio.h>
//#include <string.h>

// Local includes
#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define NTLMSSP_CLI_CHALL     0 // Output client challenge
#define NTLMSSP_DNS           1 // Output DNS computer/domain/tree name
#define NTLMSSP_NETBIOS       1 // Output NetBIOS computer/domain name
#define NTLMSSP_VERSION       2 // Output format for the version:
                                //     0: do not output the version
                                //     1: output the version as string
                                //     2: output the version as major_minor_build_rev
                                //
#define NTLMSSP_SAVE_AUTH_V1  1 // Extract NetNTLMv1 hashes
#define NTLMSSP_SAVE_AUTH_V2  1 // Extract NetNTLMv2 hashes
#define NTLMSSP_SAVE_INFO     0 // Add flow information in the hashes files

#define NTLMSSP_NAME_LEN     64 // Max length for string output

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define NTLMSSP_AUTH_V1_FILE "_NetNTLMv1.txt" // suffix for NetNTLMv1 hashes filename
#define NTLMSSP_AUTH_V2_FILE "_NetNTLMv2.txt" // suffix for NetNTLMv2 hashes filename

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_NTLMSSP_AUTH_V1_FILE,
    ENV_NTLMSSP_AUTH_V2_FILE,
    ENV_NTLMSSP_N
};


// plugin defines

#define NTLMSSP_SAVE_AUTH (NTLMSSP_SAVE_AUTH_V1 | NTLMSSP_SAVE_AUTH_V2)

#define NTLMSSP "NTLMSSP"

// NTLMSSP Message Type
#define NTLMSSP_NEGOTIATE    0x00000001
#define NTLMSSP_CHALLENGE    0x00000002
#define NTLMSSP_AUTHENTICATE 0x00000003

// NTLMSSP Negotiate Flags
#define NTLMSSP_NEGOTIATE_UNICODE                  0x00000001
#define NTLMSSP_NEGOTIATE_OEM                      0x00000002
#define NTLMSSP_REQUEST_TARGET                     0x00000004
#define NTLMSSP_NEGOTIATE_00000008                 0x00000008 // Reserved, MUST be 0
#define NTLMSSP_NEGOTIATE_SIGN                     0x00000010
#define NTLMSSP_NEGOTIATE_SEAL                     0x00000020
#define NTLMSSP_NEGOTIATE_DATAGRAM                 0x00000040
#define NTLMSSP_NEGOTIATE_LM_KEY                   0x00000080
#define NTLMSSP_NEGOTIATE_00000100                 0x00000100 // Reserved, MUST be 0
#define NTLMSSP_NEGOTIATE_NTLM                     0x00000200
//#define NTLMSSP_NEGOTIATE_NT_ONLY                  0x00000400 // Reserved, MUST be 0?
#define NTLMSSP_NEGOTIATE_ANONYMOUS                0x00000800
#define NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED      0x00001000
#define NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED 0x00002000
#define NTLMSSP_NEGOTIATE_00004000                 0x00004000 // Reserved, MUST be 0
#define NTLMSSP_NEGOTIATE_ALWAYS_SIGN              0x00008000
#define NTLMSSP_TARGET_TYPE_DOMAIN                 0x00010000
#define NTLMSSP_TARGET_TYPE_SERVER                 0x00020000
//#define NTLMSSP_TARGET_TYPE_SHARE                  0x00040000 // Reserved, MUST be 0?
#define NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY 0x00080000
#define NTLMSSP_NEGOTIATE_IDENTIFY                 0x00100000
#define NTLMSSP_NEGOTIATE_00200000                 0x00200000 // Reserved, MUST be 0
#define NTLMSSP_REQUEST_NON_NT_SESSION_KEY         0x00400000
#define NTLMSSP_NEGOTIATE_TARGET_INFO              0x00800000
#define NTLMSSP_NEGOTIATE_01000000                 0x01000000 // Reserved, MUST be 0
#define NTLMSSP_NEGOTIATE_VERSION                  0x02000000
#define NTLMSSP_NEGOTIATE_04000000                 0x04000000 // Reserved, MUST be 0
#define NTLMSSP_NEGOTIATE_08000000                 0x08000000 // Reserved, MUST be 0
#define NTLMSSP_NEGOTIATE_10000000                 0x10000000 // Reserved, MUST be 0
#define NTLMSSP_NEGOTIATE_128                      0x20000000
#define NTLMSSP_NEGOTIATE_KEY_EXCH                 0x40000000
#define NTLMSSP_NEGOTIATE_56                       0x80000000

// NTLMSSP Attribute Flags
// 0x00000001: Indicates to the client that the account authentication is constrained
// 0x00000002: Indicates that the client is providing message integrity in the MIC field in the AUTHENTICATE_MESSAGE
// 0x00000004: Indicates that the client is providing a target SPN generated from an untrusted source

// NTLMSSP Channel Bindings
// An all-zero value of the hash is used to indicate absence of channel bindings.

// ntlmsspStat
#define NTLMSSP_STAT_NTLMSSP      0x01 // flow is NTLMSSP
#define NTLMSSP_STAT_NEGOTIATE    0x02 // flow contains negotiate messages
#define NTLMSSP_STAT_CHALLENGE    0x04 // flow contains challenge messages
#define NTLMSSP_STAT_AUTHENTICATE 0x08 // flow contains authenticate messages
#define NTLMSSP_STAT_HASH_V1      0x10 // NetNTLMv1 hash was extracted for this flow
#define NTLMSSP_STAT_HASH_V2      0x20 // NetNTLMv2 hash was extracted for this flow
#define NTLMSSP_STAT_TRUNC        0x40 // string output was truncated... increase NTLMSSP_NAME_LEN
#define NTLMSSP_STAT_MALFORMED    0x80 // decoding error, invalid message type, ...


// Plugin structure

typedef struct {
    uint16_t build;
    uint8_t  major;
    uint8_t  minor;
    uint8_t  rev;
} ntlmsspVersion_t;

typedef struct {
    uint64_t timestamp;
    uint32_t negoFlags; // NegotiateFlags
    ntlmsspVersion_t version;

    char ntlmserverchallenge[16+1];
    char ntproof[64+1];
    char sesskey[32+1]; // always 16?
    char ntlmclientchallenge[1024+1]; // XXX max size???
    char target[NTLMSSP_NAME_LEN+1];
    char domain[NTLMSSP_NAME_LEN+1];
    char user[NTLMSSP_NAME_LEN+1];
    char workstation[NTLMSSP_NAME_LEN+1];

    // NetBIOS
    char nbComputer[NTLMSSP_NAME_LEN+1];
    char nbDomain[NTLMSSP_NAME_LEN+1];

    // DNS
    char dnsComputer[NTLMSSP_NAME_LEN+1];
    char dnsDomain[NTLMSSP_NAME_LEN+1];
    char dnsTree[NTLMSSP_NAME_LEN+1];

    char aTargetN[NTLMSSP_NAME_LEN+1]; // Attribute: Target Name
    //char aChannBinding[32+1]; // Attribute: Channel Binding (MD5 hash)

    uint8_t atype;
    uint8_t status;
} ntlmsspFlow_t;


// plugin struct pointer for potential dependencies
extern ntlmsspFlow_t *ntlmsspFlows;

#endif // T2_NTLMSSPDECODE_H_INCLUDED
