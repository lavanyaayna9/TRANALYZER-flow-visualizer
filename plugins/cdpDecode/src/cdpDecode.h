/*
 * cdpDecode.h
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

#ifndef __CDP_DECODE_H__
#define __CDP_DECODE_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define CDP_NADDR    5   // maximum number of IPv4 addresses
#define CDP_NMADDR   5   // maximum number of management addresses
#define CDP_NIPPG    5   // maximum number of IP prefix gateways
#define CDP_STRLEN   25  // maximum length of strings to store
#define CDP_LSTRLEN  100 // maximum length of long strings to store

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*        No env / runtime configuration flags available for cdpDecode        */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// plugin defines

#define CDP_TLV_DEVICE_ID    0x0001 // Device ID
#define CDP_TLV_ADDRESSES    0x0002 // Addresses
#define CDP_TLV_PORT_ID      0x0003 // Port ID
#define CDP_TLV_CAPS         0x0004 // Capabilities
#define CDP_TLV_SW_VERSION   0x0005 // Software Version
#define CDP_TLV_PLATFORM     0x0006 // Platform
#define CDP_TLV_IP_PREFIXES  0x0007 // IP Prefixes
#define CDP_TLV_PROTO_HELLO  0x0008 // Protocol Hello
#define CDP_TLV_VTP_MNGMT    0x0009 // VTP Management Domain
#define CDP_TLV_NATIVE_VLAN  0x000a // Native VLAN
#define CDP_TLV_DUPLEX       0x000b // Duplex
#define CDP_TLV_VOIP_VLAN_R  0x000e // VoIP VLAN Reply
#define CDP_TLV_VOIP_VLAN_Q  0x000f // VoIP VLAN Query
#define CDP_TLV_POWER_CONS   0x0010 // Power Consumption
#define CDP_TLV_MTU          0x0011 // MTU
#define CDP_TLV_TRUST_BMAP   0x0012 // Trust Bitmap
#define CDP_TLV_UNTRUST_PORT 0x0013 // Untrusted Port CoS
#define CDP_TLV_SYSNAME      0x0014 // System Name
#define CDP_TLV_SYSOID       0x0015 // System OID
#define CDP_TLV_MNGMT_ADDR   0x0016 // Management Address
#define CDP_TLV_LOCATION     0x0017 // Location
#define CDP_TLV_EXTPORTID    0x0018 // External Port ID
#define CDP_TLV_POWER_REQ    0x0019 // Power Requested
#define CDP_TLV_POWER_AVAIL  0x001a // Power Available
#define CDP_TLV_PORTUNIDIR   0x001b // Port Unidirectional
#define CDP_TLV_ENERGYWISE   0x001d // Energy Wise
#define CDP_TLV_SPAREPAIRPOE 0x001f // Spare Pair POE


// Wrappers around t2buf_read functions
#define CDP_READ_N(t2buf, dest, n) \
    if (!t2buf_read_n(t2buf, dest, n)) { \
        cdpFlowP->cdpStat |= CDP_STAT_SNAP; \
        goto cdp_pktout; \
    }
#define CDP_READ_MACRO(suffix, t2buf, dest) \
    if (!t2buf_read_ ## suffix (t2buf, dest)) { \
        cdpFlowP->cdpStat |= CDP_STAT_SNAP; \
        goto cdp_pktout; \
    }
#define CDP_READ_U8(t2buf, dest)  CDP_READ_MACRO(u8,  t2buf, dest)
#define CDP_READ_U16(t2buf, dest) CDP_READ_MACRO(u16, t2buf, dest)
#define CDP_READ_U32(t2buf, dest) CDP_READ_MACRO(u32, t2buf, dest)

#define CDP_READ_LE_U32(t2buf, dest) CDP_READ_MACRO(le_u32, t2buf, dest)


// Wrappers around t2buf_skip functions
#define CDP_SKIP_N(t2buf, n) \
    if (!t2buf_skip_n(t2buf, n)) { \
        cdpFlowP->cdpStat |= CDP_STAT_SNAP; \
        goto cdp_pktout; \
    }
#define CDP_SKIP_U8(t2buf)  CDP_SKIP_N(t2buf, 1)
#define CDP_SKIP_U16(t2buf) CDP_SKIP_N(t2buf, 2)
#define CDP_SKIP_U32(t2buf) CDP_SKIP_N(t2buf, 4)


// cdpStat
#define CDP_STAT_CDP  0x01 // Flow is CDP
#define CDP_STAT_STR  0x20 // String truncated... increase CDP_STRLEN
#define CDP_STAT_LEN  0x40 // Invalid TLV length
#define CDP_STAT_SNAP 0x80 // Snapped payload


// Struct

typedef struct {
    uint32_t IPPG[CDP_NIPPG];
    uint32_t maddr[CDP_NMADDR];
    uint32_t addr[CDP_NADDR];
    uint32_t nippg;
    uint32_t naddr;
    uint32_t nmaddr;
    uint32_t cdpCaps;
    uint32_t cdpTLVTypes;
    uint16_t vlan;
    uint16_t voipVlan;
    uint8_t IPPGcdr[CDP_NIPPG];
    uint8_t duplex;
    uint8_t cdpStat;
    uint8_t ttl;
    uint8_t version;
    char swver[CDP_LSTRLEN+1];
    char device[CDP_STRLEN+1];
    char platform[CDP_STRLEN+1];
    char port[CDP_STRLEN+1];
    char vtpdom[CDP_STRLEN+1];
} cdpFlow_t;

// plugin struct pointer for potential dependencies
extern cdpFlow_t *cdpFlows;

#endif // __CDP_DECODE_H__
