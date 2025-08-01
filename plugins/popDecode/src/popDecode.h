/*
 * popDecode.h
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

#ifndef __POP_DECODE_H__
#define __POP_DECODE_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define POP_SAVE      0 // save content to POP_F_PATH

#define POP_BTFLD     1 // 1: enable bit field output, 0: disable

#define POP_MXNMLN   65 // maximal name length
#define POP_MXUNM     5 // maximal number of users
#define POP_MXPNM     5 // maximal number of passwords/parameters
#define POP_MXCNM    10 // maximal number of content

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define POP_RMDIR                 1 // empty POP_F_PATH before starting (require POP_SAVE=1)
#define POP_F_PATH "/tmp/POPFILES/" // Path for extracted content
#define POP_NONAME "nudel"          // no name file name

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_POP_RMDIR,
    ENV_POP_F_PATH,
    ENV_POP_NONAME,
    ENV_POP_N
};


// POP ports
#define POP2_PORT 109
#define POP3_PORT 110


#define APOP 0x504F5041 // Login with MD5 signature.
#define AUTH 0x48545541 // Authentication request.
#define CAPA 0x41504143 // Get a list of capabilities supported by the server.
#define DELE 0x454C4544 // Mark the message as deleted.
#define LIST 0x5453494C // Get a scan listing of one or all messages.
#define NOOP 0x504F4F4E // Return a +OK reply.
#define PASS 0x53534150 // Cleartext password entry.
#define QUIT 0x54495551 // Exit session. Remove all deleted messages from the server.
#define RETR 0x52544552 // Retrieve the message.
#define RSET 0x54455352 // Remove the deletion marking from all messages.
#define STAT 0x54415453 // Get the drop listing.
#define STLS 0x534C5453 // Begin a TLS negotiation.
#define TOP  0x20504F54 // Get the top n lines of the message.
#define UIDL 0x4C444955 // Get a unique-id listing for one or all messages.
#define USER 0x52455355 // Mailbox login.
#define XTND 0x444E5458


// popCBF
#define POP_APOP 0x0001 //  1
#define POP_AUTH 0x0002 //  2
#define POP_CAPA 0x0004 //  3
#define POP_DELE 0x0008 //  4
#define POP_LIST 0x0010 //  5
#define POP_NOOP 0x0020 //  6
#define POP_PASS 0x0040 //  7
#define POP_QUIT 0x0080 //  8
#define POP_RETR 0x0100 //  9
#define POP_RSET 0x0200 // 10
#define POP_STAT 0x0400 // 11
#define POP_STLS 0x0800 // 12
#define POP_TOP  0x1000 // 13
#define POP_UIDL 0x2000 // 14
#define POP_USER 0x4000 // 15
#define POP_XTND 0x8000 // 16


// popStat
#define POP2_INIT 0x0001 // POP2 port found
#define POP3_INIT 0x0002 // POP3 port found
#define POP_ROK   0x0004 // Response +OK
#define POP_RERR  0x0008 // Response -ERR
#define POP_DWF   0x0010 // Data storage exists under POP_F_PATH, POP_SAVE == 1
#define POP_DTP   0x0020 // Data storage in progress, POP_SAVE == 1
#define POP_RNVL  0x0040 // Response not valid or data
#define POP_OVFL  0x0080 // Array overflow
#define POP_PAUT  0x0100 // Authentication pending
#define POP_RPATH 0x0200 // Return path pending


// plugin structures

typedef struct {
#if POP_SAVE == 1
    file_object_t *fd;      // file descriptor per flow
    uint32_t seqInit;
#endif // POP_SAVE == 1
    uint16_t recCode[POP_MXCNM];
    uint16_t tCodeBF;
    uint16_t stat;
    uint8_t tCode[POP_MXCNM];
    char nameU[POP_MXUNM][POP_MXNMLN+1];
    char nameP[POP_MXPNM][POP_MXNMLN+1];
    char nameC[POP_MXCNM][POP_MXNMLN+1];
    uint8_t tCCnt;
    uint8_t rCCnt;
    uint8_t nameUCnt;
    uint8_t namePCnt;
    uint8_t nameCCnt;
} popFlow_t;

// plugin struct pointer for potential dependencies
extern popFlow_t *popFlows;

#endif // __POP_DECODE_H__
