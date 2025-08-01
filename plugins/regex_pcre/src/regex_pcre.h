/*
 * regex_pcre.h
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


#ifndef __REGEX_PCRE_H__
#define __REGEX_PCRE_H__

// local includes
#include "regfile_pcre.h"
#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define EXPERTMODE  0 // 0: only display the most severe class,
                      // 1: display all matched classes plus some extra information
#define PKTTIME     0 // whether or not to display the time at which a rule was matched
#define AGGR        0 // 1: Aggregate Alarms

#define SALRMFLG    0 // 1: enable sending FL_ALARM for pcapd

// defines Regex
#define OVECCOUNT   3 // value % 3
#define MAXREGPOS  30 // Maximal # of matches stored / flow

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define RGX_POSIX_FILE "regexfile.txt"   // regexfile name under .tranalyzer/plugins

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_RGX_POSIX_FILE,
    ENV_RGX_N
};


// flag definition
#define REG_F_NON   0x00 // None, solitary rule
#define REG_F_AND   0x01 // and(pred1, pred2, ...)
#define REG_F_OR    0x02 // or(pred1, pred2, ...)
#define REG_F_XOR   0x03 // xor(pred1, pred2, ...)

#define REG_F_LEAF  0x04 // leaf
#define REG_F_PALRM 0x10 // print alarm in flow file
#define REG_F_FLOW  0x20 // Rule active only in flow boundary
#define REG_F_RST   0x40 // Reset REG_F_MTCH tree if match
#define REG_F_MTCH  0x80 // Internal: regex match

// flag aggregate definition
#define REG_F_OP    0x03 // 00: none, 01: &, 10: |, 11: ^
#define REG_F_RMT   (REG_F_RST | REG_F_MTCH)
#define REG_F_RLF   (REG_F_RST | REG_F_LEAF)

// sel flags
#define SEL_F_P  0x0fffffff // conditional bit positions

#define SEL_F_L2 0x10000000 // Offset start L2 Header
#define SEL_F_L3 0x20000000 // Offset start L3 Header
#define SEL_F_L4 0x40000000 // Offset start L4 Header
#define SEL_F_L7 0x80000000 // Offset start L7 Header

#define SEL_F_L  0xf0000000 // Offset bits


// plugin structs

typedef struct {
#if EXPERTMODE == 1
#if PKTTIME == 1
    struct timeval time[MAXREGPOS];
#endif // PKTTIME == 1
    uint32_t pktN;
    uint32_t pkt[MAXREGPOS];
    uint16_t pregPos[MAXREGPOS];
#endif // EXPERTMODE == 1
    uint16_t count;
    uint16_t id[MAXREGPOS];  // pattern match Regex ID
    uint16_t flags[MAXREGPOS];
} rexFlow_t;

// global pointer for plugin and potential dependencies
rexFlow_t *rexFlow;

#endif // __REGEX_PCRE_H__
