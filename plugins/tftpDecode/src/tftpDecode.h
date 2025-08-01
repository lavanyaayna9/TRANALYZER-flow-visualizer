/*
 * tftpDecode.h
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

#ifndef __TFTP_DECODE_H__
#define __TFTP_DECODE_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define TFTP_SAVE       0 // save content to TFTP_F_PATH

#define TFTP_CMD_AGGR   1 // Aggregate TFTP commands/errors
#define TFTP_BTFLD      0 // Bitfield coding of TFTP commands/errors

#define TFTP_MXNMLN    15 // maximal name length
#define TFTP_MAXCNM     4 // maximal length of command field

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define TFTP_RMDIR                  1 // empty TFTP_F_PATH before starting (require TFTP_SAVE=1)
#define TFTP_F_PATH "/tmp/TFTPFILES/" // Path for extracted content

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_TFTP_RMDIR,
    ENV_TFTP_F_PATH,
    ENV_TFTP_N
};


// TFTP ports
#define TFTP_PORT         69
#define ETFTP_PORT      1818 // Enhanced TFTP
#define TFTP_MCAST_PORT 1758 // TFTP multicast
#define TFTPS_PORT      3713 // TFTP over TLS

// TFTP opcodes
#define RRQ  1
#define WRQ  2
#define DATA 3
#define ACK  4
#define ERR  5
#define OACK 6


// plugin defines

// tftpOpCBF
#define TFTP_RRQ  0x01 // 1: Read request
#define TFTP_WRQ  0x02 // 2: Write request
#define TFTP_DATA 0x04 // 3: Read or write the next block of data
#define TFTP_ACK  0x08 // 4: Acknowledgment
#define TFTP_ERR  0x10 // 5: Error message
#define TFTP_OACK 0x20 // 6: Option acknowledgment

// tftpErrCBF
#define TFTP_NOERR  0x00 // 0: No Error
#define TFTP_FLNFND 0x01 // 1: File not found
#define TFTP_ACCVLT 0x02 // 2: Access violation
#define TFTP_DSKFLL 0x04 // 3: Disk full or allocation exceeded
#define TFTP_ILGLOP 0x08 // 4: Illegal TFTP operation
#define TFTP_UKWNID 0x10 // 5: Unknown transfer ID
#define TFTP_FLEXST 0x20 // 6: File already exists
#define TFTP_NOSUSR 0x40 // 7: No such user
#define TFTP_TRMOPN 0x80 // 8: Terminate transfer due to option negotiation

// tftpStat
#define TFTPS_INIT      0x0001 // TFTP flow found
#define TFTPS_DRD       0x0002 // TFTP data read
#define TFTPS_DWR       0x0004 // TFTP data write
#define TFTPS_FERR      0x0008 // file open error
#define TFTPS_BSERR     0x0010 // error in block send sequence
#define TFTPS_BSAERR    0x0020 // error in block ack sequence
#define TFTPS_PERR      0x0040 // error, or tftp prot error or not tftp
#define TFTPS_OVFL      0x0080 // array overflow... increase TFTP_MAXCNM
#define TFTPS_TRUNC     0x0100 // string truncated... increase TFTP_MXNMLN
#define TFTPS_RW_PLNERR 0x0800 // crafted packet or TFTP read/write parameter length error
#define TFTPS_ACT       0x1000 // active
#define TFTPS_PSV       0x2000 // passive


// plugin structures

typedef struct {
#if TFTP_SAVE == 1
    file_object_t *fd;
#endif // TFTP_SAVE == 1
    uint64_t pfi;
    uint16_t sndBlk;
    uint16_t lstBlk;
    uint16_t stat;
#if TFTP_MAXCNM > 0
    char nameC[TFTP_MAXCNM][TFTP_MXNMLN+1];
    uint8_t opCode[TFTP_MAXCNM];
    uint8_t errCode[TFTP_MAXCNM];
#endif // TFTP_MAXCNM > 0
#if TFTP_BTFLD == 1
    uint8_t opCodeBF;
    uint8_t errCodeBF;
#endif // TFTP_BTFLD == 1
    uint8_t opCnt;
    uint8_t pCnt;
    uint8_t errCnt;
} tftpFlow_t;

// plugin struct pointer for potential dependencies
extern tftpFlow_t *tftpFlows;

#endif // __TFTP_DECODE_H__
