/*
 * mndpDecode.h
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

#ifndef T2_MNDPDECODE_H_INCLUDED
#define T2_MNDPDECODE_H_INCLUDED

// Local includes
#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define MNDP_DEBUG   0           // Print debug messages
#define MNDP_LSTLEN  5           // Max number of elements for lists (flow output)
#define MNDP_STRLEN 32           // Max length for strings

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*        No env / runtime configuration flags available for mndpDecode       */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// plugin defines

#if MNDP_DEBUG == 1
#define MNDP_DBG(format, args...) T2_PLOG(plugin_name, format, ##args)
#else // MNDP_DEBUG == 0
#define MNDP_DBG(format, args...)
#endif // MNDP_DEBUG


// plugin defines

#define MNDP_PORT 5678

#define MNDP_MIN_SIZE 8 // Header (2), SeqNo (2), TLV (2 + 2)

// TLV types
#define MNDP_TLV_MAC_ADDR   1 // MAC-Address
#define MNDP_TLV_IDENTITY   5 // Identity
#define MNDP_TLV_VERSION    7 // Version
#define MNDP_TLV_PLATFORM   8 // Platform
#define MNDP_TLV_UPTIME    10 // Uptime
#define MNDP_TLV_SW_ID     11 // Software-ID
#define MNDP_TLV_BOARD     12 // Board
#define MNDP_TLV_UNPACK    14 // Unpack
#define MNDP_TLV_IPV6_ADDR 15 // IPv6-Address
#define MNDP_TLV_IFACE     16 // Interface-Name
#define MNDP_TLV_IPV4_ADDR 17 // IPv4-Address

// mndpStat status variable
#define MNDP_STAT_MNDP    0x01 // Flow is MNDP
#define MNDP_STAT_IPV4    0x02 // IPv4 address
#define MNDP_STAT_IPV6    0x04 // IPv6 address
#define MNDP_STAT_UNK_TLV 0x08 // Unknown TLV type
#define MNDP_STAT_TLV_LEN 0x10 // Invalid TLV length, e.g., length of MAC address > 6
#define MNDP_STAT_LIST    0x20 // List was truncated... increase MNDP_LSTLEN
#define MNDP_STAT_STR     0x40 // String was truncated... increase MNDP_STRLEN
#define MNDP_STAT_SNAP    0x80 // Packet was snapped


// Plugin structure

typedef struct {
#if MNDP_LSTLEN > 0
    ipAddr_t ipv6_list[MNDP_LSTLEN];
    uint8_t num_ipv6;
    uint32_t ipv4_list[MNDP_LSTLEN];
    uint8_t num_ipv4;
    uint8_t mac_list[MNDP_LSTLEN][ETH_ALEN];
    uint8_t num_mac;
    uint8_t identity_list[MNDP_LSTLEN][MNDP_STRLEN+1];
    uint8_t num_identity;
    uint8_t version_list[MNDP_LSTLEN][MNDP_STRLEN+1];
    uint8_t num_version;
    uint8_t platform_list[MNDP_LSTLEN][MNDP_STRLEN+1];
    uint8_t num_platform;
    uint8_t sw_id_list[MNDP_LSTLEN][MNDP_STRLEN+1];
    uint8_t num_sw_id;
    uint8_t board_list[MNDP_LSTLEN][MNDP_STRLEN+1];
    uint8_t num_board;
    uint8_t unpack_list[MNDP_LSTLEN];
    uint8_t num_unpack;
    uint8_t iface_list[MNDP_LSTLEN][MNDP_STRLEN+1];
    uint8_t num_iface;
#endif
    uint8_t stat;
} mndpFlow_t;


// plugin struct pointer for potential dependencies
extern mndpFlow_t *mndpFlows;

#endif // T2_MNDPDECODE_H_INCLUDED
