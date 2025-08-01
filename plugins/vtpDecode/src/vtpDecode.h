/*
 * vtpDecode.h
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

#ifndef T2_VTPDECODE_H_INCLUDED
#define T2_VTPDECODE_H_INCLUDED

// Global includes
#include <time.h> // for struct tm

// Local includes
#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define VTP_AGGR           1 // Aggregate updater identity
#define VTP_SAVE           1 // Extract all VLANs info in a separate file
#define VTP_DEBUG          0 // Print debug messages
#define VTP_TS_FRMT        1 // Format for timestamps: 0: string, 1: timestamp
#define VTP_VLANID_FRMT    1 // Format for VLAN ID: 0: int, 1: hex
#define VTP_NUM_UPDID     16 // Max number of updater identity
#define VTP_STR_MAX       64 // Max length for strings

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

// The followings flags require VTP_SAVE = 1
#define VTP_SUFFIX        "_vtp.txt" // Suffix for separate file

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_VTP_SUFFIX,
    ENV_VTP_N
};


// VTP versions
#define VTP_V1 0x01
#define VTP_V2 0x02
#define VTP_V3 0x03

// VTP codes
#define VTP_C_SUMADV  0x01 // Summary Advertisement
#define VTP_C_SUBADV  0x02 // Subset Advertisement
#define VTP_C_ADVREQ  0x03 // Advertisement Request
#define VTP_C_JOIN    0x04 // Join/Prune Message

// VLAN types
#define VTP_VLAN_ETH      0x01 // Ethernet
#define VTP_VLAN_FDDI     0x02 // FDDI
#define VTP_VLAN_TRCRF    0x03 // TrCRF
#define VTP_VLAN_FDDI_NET 0x04 // FDDI-net
#define VTP_VLAN_TRBRF    0x05 // TrBRF


// Plugin defines
#define VTP_V_LAST       VTP_V3 // Number of VTP versions
#define VTP_C_UNKNOWN    0x07   // Artificial type used for unknown VTP codes
#define VTP_VLAN_UNKNOWN 0x06   // Artificial type used for unknown VTP VLAN types
#define VTP_NUM_CODES    4      // Number of VTP codes
#define VTP_TS_LEN       12     // Length of updated timestamp (do not edit!)
#define VTP_MD5_STRLEN   32     // Length of MD5


// t2buf read/skip wrappers

#define VTP_READ_STR(t2buf, dest, len, maxlen) { \
    const size_t read = MIN(maxlen, len); \
    if (read != (size_t)len) { \
        vtpFlowP->stat |= VTP_STAT_STR; \
    } \
    if (!t2buf_read_n(t2buf, (uint8_t*)dest, read)) { \
        vtpFlowP->stat |= VTP_STAT_SNAP; \
        VTP_SPKTMD_PRI(); \
        return; \
    } \
    dest[read] = '\0'; \
    if (read != (size_t)len) { \
        if (!t2buf_skip_n(t2buf, len - read)) { \
            vtpFlowP->stat |= VTP_STAT_SNAP; \
            VTP_SPKTMD_PRI(); \
            return; \
        } \
    } \
}

#define VTP_READ_HEX(t2buf, dest, len, maxlen) { \
    const size_t read = MIN(len, (maxlen)/2); \
    if (read != (size_t)len) { \
        vtpFlowP->stat |= VTP_STAT_STR; \
    } \
    if (t2buf_hexdecode(t2buf, read, dest, 0) != read) { \
        vtpFlowP->stat |= VTP_STAT_SNAP; \
        VTP_SPKTMD_PRI(); \
        return; \
    } \
    dest[2*read] = '\0'; \
    if (read != (size_t)len) { \
        if (!t2buf_skip_n(t2buf, len - read)) { \
            vtpFlowP->stat |= VTP_STAT_SNAP; \
            VTP_SPKTMD_PRI(); \
            return; \
        } \
    } \
}

#define VTP_READ_MACRO(suffix, t2buf, dest) \
    if (!t2buf_read_ ## suffix (t2buf, dest)) { \
        vtpFlowP->stat |= VTP_STAT_SNAP; \
        VTP_SPKTMD_PRI(); \
        return; \
    }

#define VTP_READ_N(t2buf, dest, n) \
    if (!t2buf_read_n(t2buf, dest, n)) { \
        vtpFlowP->stat |= VTP_STAT_SNAP; \
        VTP_SPKTMD_PRI(); \
        return; \
    }

#define VTP_SKIP_N(t2buf, n) \
    if (!t2buf_skip_n(t2buf, n)) { \
        vtpFlowP->stat |= VTP_STAT_SNAP; \
        VTP_SPKTMD_PRI(); \
        return; \
    }

#define VTP_READ_U8(t2buf, dest)  VTP_READ_MACRO(u8,  t2buf, dest)
#define VTP_READ_U16(t2buf, dest) VTP_READ_MACRO(u16, t2buf, dest)
#define VTP_READ_U32(t2buf, dest) VTP_READ_MACRO(u32, t2buf, dest)

#define VTP_READ_LE_U32(t2buf, dest) VTP_READ_MACRO(le_u32, t2buf, dest)

#define VTP_SKIP_U8(t2buf)  VTP_SKIP_N(t2buf, 1)
#define VTP_SKIP_U16(t2buf) VTP_SKIP_N(t2buf, 2)
#define VTP_SKIP_U32(t2buf) VTP_SKIP_N(t2buf, 4)


// Binary value type for timestamps
#if VTP_TS_FRMT == 1
#define VTP_TS_TYPE bt_timestamp
#else // VTP_TS_FRMT == 0
#define VTP_TS_TYPE bt_string
#endif // VTP_TS_FRMT == 0


// vtpStat
#define VTP_STAT_VTP        0x0001 // Flow is VTP
#define VTP_STAT_DVER       0x0002 // Different versions used
#define VTP_STAT_DMD        0x0004 // Different Management Domains used
// 0x0008 unused
#define VTP_STAT_MDLEN      0x0010 // Invalid Management Domain Length (> 32)
#define VTP_STAT_IVER       0x0020 // Invalid version
#define VTP_STAT_CODE       0x0040 // Invalid code
#define VTP_STAT_VLAN_TYPE  0x0080 // Invalid VLAN type
// 0x0100-0x1000 unused
#define VTP_STAT_ARR        0x2000 // Array truncated... increase VTP_NUM_UPDID
#define VTP_STAT_STR        0x4000 // String truncated... increase VTP_STR_MAX
#define VTP_STAT_SNAP       0x8000 // Packet snapped, decoding failed


// Plugin structure

typedef struct {
#if VTP_NUM_UPDID > 0
    uint32_t updId[VTP_NUM_UPDID];
    uint32_t numUpdId;
#endif // VTP_NUM_UPDID > 0
    uint8_t  firstUpTS[VTP_TS_LEN];
    uint8_t  lastUpTS[VTP_TS_LEN];
    char     domain[VTP_STR_MAX+1];
    uint8_t  codeBF;
    uint8_t  vlanTypeBF;
    uint8_t  ver;
    uint8_t  stat;
} vtpFlow_t;


// plugin struct pointer for potential dependencies
extern vtpFlow_t *vtpFlows;

#endif // T2_VTPDECODE_H_INCLUDED
