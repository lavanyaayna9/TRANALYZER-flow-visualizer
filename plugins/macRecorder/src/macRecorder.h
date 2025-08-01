/*
 * macRecorder.h
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

#ifndef __MAC_RECORDER_H__
#define __MAC_RECORDER_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define MR_MAC_FMT  1 // Format for MAC addresses:
                      //     0: hex
                      //     1: mac
                      //     2: int
#define MR_NPAIRS   1 // Report number of distinct src/dst MAC pairs
#define MR_MACLBL   2 // Format for MAC addresses labels:
                      //     0: no mac label
                      //     1: numerical (int)
                      //     2: short names
                      //     3: long names
#define MR_MAX_MAC 16 // Max number of MAC addresses per flow

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*       No env / runtime configuration flags available for macRecorder       */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// plugin defines

#if MR_MAC_FMT == 0
#define MR_MAC_TYPE bt_hex_64   // MAC as hex
#elif MR_MAC_FMT == 1
#define MR_MAC_TYPE bt_mac_addr // MAC (string)
#else // MR_MAC_FMT == 2
#define MR_MAC_TYPE bt_uint_64  // MAC as int
#endif // MR_MAC_FMT

#if MR_MACLBL == 1
#define MR_LBL_PRI PRIu32
#define MR_LBL_TYPE bt_uint_32
#elif MR_MACLBL == 2
#define MR_LBL_TYPE bt_string_class
#elif MR_MACLBL == 3
#define MR_LBL_TYPE bt_string
#endif


// macStat
#define MR_F_OVRN 0x01 // MAC list overflow... increase MR_MAX_MAC


// plugin structs

typedef struct macList_s {
    ethDS_t ethHdr;
    uint64_t numPkts;
    struct macList_s *next;
} macList_t;

typedef struct {
    uint32_t num_entries;
    macList_t *macList;
    uint16_t ethType;
    uint8_t stat;
} macRecorder_t;

extern macRecorder_t *macArray; // the big struct for all flows

#endif // __MAC_RECORDER_H__
