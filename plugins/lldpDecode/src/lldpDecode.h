/*
 * lldpDecode.h
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

#ifndef __LLDP_DECODE_H__
#define __LLDP_DECODE_H__

#include "t2Plugin.h"

/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define LLDP_TTL_AGGR   1 // aggregate TTL values
#define LLDP_NUM_TTL    8 // Number of different TTL values to store
#define LLDP_OPT_TLV    1 // output optional TLVs
#define LLDP_STRLEN    20 // maximum length of short strings to store
#define LLDP_LSTRLEN  100 // maximum length of long strings to store

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*       No env / runtime configuration flags available for lldpDecode        */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// plugin defines

#define LLDP_TYPE(type_len) ((type_len) >> 9)    // 7 bits
#define LLDP_LEN(type_len)  ((type_len) & 0x1ff) // 9 bits

// Mandatory TLV Types
#define LLDP_TLV_END        0 // End of LLDPDU
#define LLDP_TLV_CHASSIS_ID 1 // Chassis ID
#define LLDP_TLV_PORT_ID    2 // Port ID
#define LLDP_TLV_TTL        3 // Time To Live (sec)

// Optional TLV Types
#define LLDP_TLV_PORT_DESC  4 // Port description
#define LLDP_TLV_SYS_NAME   5 // System name
#define LLDP_TLV_SYS_DESC   6 // System description
#define LLDP_TLV_SYS_CAPS   7 // System capabilities
#define LLDP_TLV_MNGMT_ADDR 8 // Management address
// 9-126: reserved
#define LLDP_TLV_ORG_SPEC 127 // Organization specific

// Chassis ID Subtypes
#define LLDP_CID_CHASSIS_COMP 1 // Chassis component
#define LLDP_CID_IF_ALIAS     2 // Interface alias
#define LLDP_CID_PORT_COMP    3 // Port component
#define LLDP_CID_MAC_ADDR     4 // MAC address
#define LLDP_CID_NET_ADDR     5 // Network address
#define LLDP_CID_IF_NAME      6 // Interface name
#define LLDP_CID_LOCAL        7 // Locally assigned
// 8-255: reserved

// Port ID Subtypes
#define LLDP_PID_IF_ALIAS     1 // Interface alias
#define LLDP_PID_PORT_COMP    2 // Port component
#define LLDP_PID_MAC_ADDR     3 // MAC address
#define LLDP_PID_NET_ADDR     4 // Network address
#define LLDP_PID_IF_NAME      5 // Interface name
#define LLDP_PID_CIRC_ID      6 // Agent Circuit ID
#define LLDP_PID_LOCAL        7 // Locally assigned
// 8-255: reserved

// lldpStat status variable
#define LLDP_STAT_LLDP 0x0001 // Flow is LLDP
#define LLDP_STAT_MAND 0x0002 // Mandatory TLV missing
#define LLDP_STAT_OPT  0x0004 // Optional TLV present
#define LLDP_STAT_RSVD 0x0008 // Reserved TLV type/subtype used
#define LLDP_STAT_SPEC 0x0010 // Organization specific TLV used
#define LLDP_STAT_UNK  0x0020 // Unhandled TLV used
#define LLDP_STAT_LEN  0x0040 // Invalid TLV length
#define LLDP_STAT_STR  0x2000 // String truncated... increase LLDP_STRLEN
#define LLDP_STAT_TTL  0x4000 // Too many TTL, increase LLDP_NUM_TTL
#define LLDP_STAT_SNAP 0x8000 // Snapped payload


// Struct

typedef struct {
    uint32_t lldpTLVTypes;
    uint32_t numTTL;
    uint16_t ttl[LLDP_NUM_TTL];
    uint16_t caps;
    uint16_t enabledCaps;
    uint16_t lldpStat;
    char chassis[LLDP_STRLEN+1];
    char portID[LLDP_STRLEN+1];
#if LLDP_OPT_TLV == 1
    char portdesc[LLDP_STRLEN+1];
    char sysname[LLDP_STRLEN+1];
    char sysdesc[LLDP_LSTRLEN+1];
    char mngmtAddr[LLDP_STRLEN+1];
#endif // LLDP_OPT_TLV == 1
} lldpFlow_t;

// plugin struct pointer for potential dependencies
extern lldpFlow_t *lldpFlows;

#endif // __LLDP_DECODE_H__
