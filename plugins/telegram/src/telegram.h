/*
 * telegram.h
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

#ifndef __TELEGRAM_H__
#define __TELEGRAM_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define TG_SAVE           0  // 1: save telegram flows
#define TG_DEOBFUSCATE    0  // remove obfuscation layer when possible
#define TG_4_9_OR_NEWER   1  // Telegram 4.9.0 or newer (better deobfuscation)
#define TG_DEBUG_MESSAGES 0  // print debug messages

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// plugin defines

#define TG_INTCTRL  0xc0

#define TG_TC6M     0x0ff00000
#define TG_INT6CTRL 0x0c000000
#define TG_ORGCODE  0x0002394c

#define TG_MTULIMIT 1460
#define MODLIMIT 3

// Status variable
#define TG_DETECT 0x0001 // Telegram detected by state machine
#define TG_CNTRL  0x0002 // Control channel
#define TG_VOICE  0x0004 // Voice
#define TG_ADTCT  0x0008 // Telegram detected by IP
#define TG_FLS    0x0010 // File save
#define TG_TOSD   0x0020 // Bot app
#define TG_PWFERR 0x0100 // Write error
#define TG_PLNFLG 0x1000 // Internal state machine
#define TG_PLIGN2 0x2000 // Internal state machine
#define TG_PLIGN1 0x4000 // Internal state machine
#define TG_INIT   0x8000 // Internal state machine init

#define MAX_PKT_SIZE 10000

#if TG_DEOBFUSCATE != 0
typedef enum {
    OBFUSC_UNDEF,  // default state at beginning of flow
    OBFUSC_SYN,    // SYN packet seen
    OBFUSC_KEY,    // obfuscation key extracted, deobfuscation possible
    OBFUSC_NOPE,   // deobfuscation impossible
} obfusc_state;

#include <openssl/aes.h>
#define BLOCK_SIZE 16
#define KEY_LENGTH 32
#define OBFUSC_HDR_LEN (16 + KEY_LENGTH + BLOCK_SIZE)

typedef struct {
    AES_KEY key;
    uint8_t iv[BLOCK_SIZE];
} ctr_crypt;
#endif // TG_DEOBFUSCATE != 0

// plugin structure

typedef struct {
#if TG_SAVE == 1
    file_object_t *fd;
    char *tgName;
#endif // TG_SAVE == 1
#if TG_DEOBFUSCATE != 0
    uint64_t auth_key_id;
    obfusc_state obf_state;
    ctr_crypt crypt;
    bool client_flow;
    uint32_t next_msg_seq;
#endif // TG_DEOBFUSCATE != 0
#if TG_SAVE == 1 || TG_DEOBFUSCATE != 0
    uint32_t seqInit;
#endif // TG_SAVE == 1 || TG_DEOBFUSCATE != 0
    int32_t numTbytes;
    uint32_t numTpkts;
    int32_t modCnt;
    uint16_t l7LenMin;
    uint16_t stat;
} tgFlow_t;

// plugin struct pointer for potential dependencies
extern tgFlow_t *tgFlows;

#endif // __TELEGRAM_H__
