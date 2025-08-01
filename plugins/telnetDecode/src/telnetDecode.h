/*
 * telnetDecode.h
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

#ifndef TELNETDECODE_H_
#define TELNETDECODE_H_

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define TEL_SAVE       0 // Save content to TEL_F_PATH
#define TEL_SAVE_SPLIT 1 // Save requests (A) and responses (B): (TEL_SAVE=1)
                         //   0: in the same file
                         //   1: in separate files
#define TEL_SEQPOS     0 // 0: no file position control,
                         // 1: seq number file position control (TEL_SAVE=1)

#define TEL_BTFLD      1 // Enable bitfields output

#define TEL_CMDOPTS    1 // Commands/options format:
                         //   0: Output commands/options,
                         //   1: Output commands/options names

#define TEL_CMD_AGGR   1 // Aggregate commands
#define TEL_OPT_AGGR   1 // Aggregate options

#define TELUPLN       25 // Maximal length user/password
#define TELCMDN       25 // Maximal command / flow
#define TELOPTN       25 // Maximal options / flow

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define TEL_RMDIR                 1 // empty TEL_F_PATH before starting (TEL_SAVE=1)
#define TEL_F_PATH "/tmp/TELFILES/" // Path for extracted content

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_TEL_RMDIR,
    ENV_TEL_F_PATH,
    ENV_TEL_N
};


// plugin defines

#define TLNTPRT   23   // Telnet port

#define CMDSTRT   0xf0
#define CMDEND    0xff
#define TELCMD    0xff

#define MINTELLEN 1
#define TELFLEN   20

// Command codes (actually start at 0xf0)
#define SE   0x00 // End of subnegotiation parameters
#define NOP  0x01 // No operation
#define DM   0x02 // Data Mark
#define BRK  0x03 // Break
#define IP   0x04 // Interrupt Process
#define AO   0x05 // Abort Output
#define AYT  0x06 // Are You There
#define EC   0x07 // Erase Character
#define EL   0x08 // Erase Line
#define GA   0x09 // Go Ahead
#define SB   0x0a // Subnegotiation
#define WILL 0x0b // Will Perform
#define WONT 0x0c // Won't Perform
#define DO   0x0d // Do Perform
#define DONT 0x0e // Don't Perform
#define IAC  0x0f // Interpret As Command


// Plugin defines

// telStat
#define TEL_INIT     0x01 // Telnet port found
#define TEL_FWRT     0x02 // successful files extraction
#define TEL_USR      0x04 // successful username found
#define TEL_PWD      0x08 // successful password found
#define TEL_OFERR    0x10 // File open error (TEL_SAVE=1)
#define TEL_UP_OVFL  0x20 // User/PW length overflow... increase TELUPLN
#define TEL_CMD_OVFL 0x40 // Command array overflow... increase TELCMDN
#define TEL_OPT_OVFL 0x80 // Options array overflow... increase TELOPTN


// flow plugin struct

typedef struct {
#if TEL_SAVE == 1
    file_object_t *fd;
    uint32_t seqInit;
#endif // TEL_SAVE == 1
#if TEL_BTFLD == 1
    uint32_t cmdBF;
    uint32_t optBF;
#endif // TEL_BTFLD == 1
    uint16_t cmdCnt;
    uint16_t optCnt;
    uint8_t cmdCode[TELCMDN];
    uint8_t optCode[TELOPTN];
    uint8_t idx;
    char user[TELUPLN+1];
    char passwd[TELUPLN+1];
    uint8_t stat;
} telFlow_t;

// plugin struct pointer for potential dependencies
extern telFlow_t *telFlows;

#endif // TELNETDECODE_H_
