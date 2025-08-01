/*
 * bgpDecode.h
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

/*
 * References:
 *      BGP-4 [rfc4271]
 */

#ifndef __BGP_DECODE_H__
#define __BGP_DECODE_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define BGP_DEBUG        0 // activate debug output
#define BGP_IP_FORMAT    1 // 0: hex, 1: IP, 2: int
#define BGP_AS_FORMAT    0 // 0: ASPLAIN, 1: ASDOT, 2: ASDOT+
#define BGP_NOTIF_FORMAT 0 // 0: uint8, 1: string (code only)
#define BGP_TRAD_BOGONS  1 // flag traditional bogons

#define BGP_OUTPUT_RT    1 // output routing tables

#if BGP_OUTPUT_RT == 1
#define BGP_ORIG_ID      0 // output originator id
#define BGP_AGGR         0 // output aggregator
#define BGP_CLUSTER      0 // output cluster list
#define BGP_COMMUNITIES  0 // output communities
#define BGP_MASK_FORMAT  1 // 0: hex, 1: IP, 2: int
#define BGP_AS_PATH_AGGR 0 // aggregate repetitions of the same AS
#endif // BGP_OUTPUT_RT

// Experimental
#define BGP_RT           1 // store routing information in a hashtable (required for MOAS detection)
#define BGP_DEBUG_RT     0 // activate debug output for routing information
#define BGP_RT_MASK      0 // use the mask as part of the key for the routing table

#define BGP_ASIZE      512 // Size of arrays for update records

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define BGP_SUFFIX      "_bgp.txt"
#define BGP_ANOM_SUFFIX "_bgp_anomalies.txt"
#define BGP_MOAS_SUFFIX "_bgp_moas.txt"

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_BGP_SUFFIX,
    ENV_BGP_ANOM_SUFFIX,
    ENV_BGP_MOAS_SUFFIX,
    ENV_BGP_N
};


// plugin defines

// BGP_READ_*

#define BGP_READ_U8(t2buf, val) do { \
    if (!t2buf_read_u8(t2buf, val)) { \
        bgpFlowP->stat |= BGP_STAT_SNAPLEN; \
        return; \
    } \
} while(0)
#define BGP_READ_U16(t2buf, val) do { \
    if (!t2buf_read_u16(t2buf, val)) { \
        bgpFlowP->stat |= BGP_STAT_SNAPLEN; \
        return; \
    } \
} while (0)
#define BGP_READ_U32(t2buf, val) do { \
    if (!t2buf_read_u32(t2buf, val)) { \
        bgpFlowP->stat |= BGP_STAT_SNAPLEN; \
        return; \
    } \
} while (0)
#define BGP_READ_U64(t2buf, val) do { \
    if (!t2buf_read_u64(t2buf, val)) { \
        bgpFlowP->stat |= BGP_STAT_SNAPLEN; \
        return; \
    } \
} while (0)

#define BGP_READ_IP4(t2buf, val) do { \
    if (!t2buf_read_le_u32(t2buf, val)) { \
        bgpFlowP->stat |= BGP_STAT_SNAPLEN; \
        return; \
    } \
} while (0)

// BGP_SKIP_*

#define BGP_SKIP_U8(t2buf) do { \
    if (!t2buf_skip_u8(t2buf)) { \
        bgpFlowP->stat |= BGP_STAT_SNAPLEN; \
        return; \
    } \
} while(0)
#define BGP_SKIP_U16(t2buf) do { \
    if (!t2buf_skip_u16(t2buf)) { \
        bgpFlowP->stat |= BGP_STAT_SNAPLEN; \
        return; \
    } \
} while (0)
#define BGP_SKIP_U32(t2buf) do { \
    if (!t2buf_skip_u32(t2buf)) { \
        bgpFlowP->stat |= BGP_STAT_SNAPLEN; \
        return; \
    } \
} while (0)
#define BGP_SKIP_U64(t2buf) do { \
    if (!t2buf_skip_u64(t2buf)) { \
        bgpFlowP->stat |= BGP_STAT_SNAPLEN; \
        return; \
    } \
} while (0)
#define BGP_SKIP_N(t2buf, n) do { \
    if (!t2buf_skip_n(t2buf, (n))) { \
        bgpFlowP->stat |= BGP_STAT_SNAPLEN; \
        return; \
    } \
} while (0)


#if BGP_IP_FORMAT == 1
#define BGP_IP_TYPE bt_ip4_addr
#elif BGP_IP_FORMAT == 2
#define BGP_IP_TYPE bt_uint_32
#else // BGP_IP_FORMAT == 0
#define BGP_IP_TYPE bt_hex_32
#endif // BGP_IP_FORMAT

#if BGP_OUTPUT_RT == 1
#if BGP_MASK_FORMAT == 1
#define BGP_MASK_TYPE bt_ip4_addr
#elif BGP_MASK_FORMAT == 2
#define BGP_MASK_TYPE bt_uint_32
#elif BGP_MASK_FORMAT == 3
#define BGP_MASK_TYPE bt_uint_8
#else // BGP_MASK_FORMAT == 0
#define BGP_MASK_TYPE bt_hex_32
#endif // BGP_MASK_FORMAT
#endif // BGP_OUTPUT_RT == 1

#if BGP_NOTIF_FORMAT == 1
#define BGP_NOTIF_TYPE bt_string_class
#else // BGP_NOTIF_FORMAT == 0
#define BGP_NOTIF_TYPE bt_uint_8
#endif // BGP_NOTIF_FORMAT

#if BGP_AS_FORMAT > 0
#define BGP_ASDOT_LEN 12
#define BGP_AS_TYPE bt_string_class
#else // BGP_AS_FORMAT == 0
#define BGP_AS_TYPE bt_uint_32
#endif // BGP_AS_FORMAT == 0

// Protocol defines
#define BGP_PORT       179
#define BGP_AS_TRANS 23456
#define BGP_HDRLEN      19 // bytes
#define BGP_MAXLEN    4096 // bytes
#define BGP_MARKER 0xffffffffffffffff

// Subsequent Address Family Identifier
#define BGP_AFI_IP4 1
#define BGP_AFI_IP6 2

// Subsequent Address Family Identifier
#define BGP_SAFI_UNICAST   1
#define BGP_SAFI_MULTICAST 2

#define BGP_SND_RCV_BOTH 3

// BGP types
#define BGP_T_OPEN       1
#define BGP_T_UPDATE     2
#define BGP_T_NOTIF      3
#define BGP_T_KEEPALIVE  4
#define BGP_T_RTE_REFRSH 5 // rfc2918

// Capabilities
#define BGP_C_MULTI_PROTO   1 // Multiprotocol Extensions for BGP-4 [RFC2858]
#define BGP_C_RTE_RFRSH     2 // Route Refresh Capability for BGP-4 [RFC2918]
#define BGP_C_RTE_FILTER    3 // Outbound Route Filtering Capability [RFC5291]
#define BGP_C_MULT_RTE      4 // Multiple routes to a destination capability [RFC3107]
#define BGP_C_EXT_NEXTHOP   5 // Extended Next Hop Encoding [RFC5549]
#define BGP_C_GRACE_RSTART 64 // Graceful Restart Capability [RFC4724]
#define BGP_C_AS4_SUPPORT  65 // Support for 4-octet AS number capability [RFC6793]
#define BGP_C_DYN_SUPPORT  67 // Support for Dynamic Capability (capability specific) [draft-ietf-idr-dynamic-cap]
#define BGP_C_MULTISESS    68 // Multisession BGP Capability [draft-ietf-idr-bgp-multisession]
#define BGP_C_ADD_PATH     69 // ADD-PATH Capability [draft-ietf-idr-add-paths]
#define BGP_C_ENH_RFRSH    70 // Enhanced Route Refresh Capability [RFC7313]
#define BGP_C_LLGR         71 // Long-Lived Graceful Restart (LLGR) Capability
#define BGP_C_FQDN         73 // FQDN Capability [draft-walton-bgp-hostname-capability]

// BGP error codes
#define BGP_E_MSG_HDR  1 // Message Header Error
#define BGP_E_OPEN_MSG 2 // OPEN Message Error
#define BGP_E_UPD_MSG  3 // UPDATE Message Error
#define BGP_E_HT_EXPIR 4 // Hold Timer Expired
#define BGP_E_FSM      5 // Finite State Machine Error
#define BGP_E_CEASE    6 // Cease
#define BGP_E_RTE_REFR 7 // ROUTE-REFRESH Message Error

// BGP error subcodes
// Message Header
#define BGP_E1_CONN_NOT_SYNC  1 // Connection Not Synchronized
#define BGP_E1_BAD_MSG_LEN    2 // Bad Message Length
#define BGP_E1_BAD_MSG_TYPE   3 // Bad Message Type
// OPEN Message
#define BGP_E2_UNSUP_VER      1 // Unsupported Version Number
#define BGP_E2_BAD_PEER_AS    2 // Bad Peer AS
#define BGP_E2_BAD_BGP_ID     3 // Bad BGP Identifier
#define BGP_E2_UNSUP_OPTPARAM 4 // Unsupported Optional Parameter
#define BGP_E2_DEPRECATED     5 // [Deprecated]
#define BGP_E2_UNACCEPT_HTIME 6 // Unacceptable Hold time
#define BGP_E2_UNSUP_CAP      7 // Unsupported capability
// UPDATE Message
#define BGP_E3_MAFORM_ATTR    1 // Malformed Attribute List
#define BGP_E3_UNREC_ATTR     2 // Unrecognized Well-known Attribute
#define BGP_E3_MISSING_ATTR   3 // Missing Well-known Attribute
#define BGP_E3_ATTR_FLAG      4 // Attribute Flags Error
#define BGP_E3_ATTR_LEN       5 // Attribute Length Error
#define BGP_E3_INVALID_ORIG   6 // Invalid ORIGIN Attribute
#define BGP_E3_DEPRECATED     7 // [Deprecated]
#define BGP_E3_INVALID_NHOP   8 // Invalid NEXT_HOP Attribute
#define BGP_E3_OPT_ATTR       9 // Optional Attribute Error
#define BGP_E3_INVALID_NET   10 // Invalid Network Field
#define BGP_E3_MALFORMED_AS  11 // Malformed AS_PATH
// Hold Timer Expired
// No subcodes
// Finite State Machine
#define BGP_E5_OPEN_SENT      1 // Receive Unexpected Message in OpenSent State
#define BGP_E5_OPEN_CONF      2 // Receive Unexpected Message in OpenConfirm State
#define BGP_E5_ESTABLISH      3 // Receive Unexpected Message in Established State
// Cease
#define BGP_E6_MAX_PREF       1 // Maximum Number of Prefixes Reached
#define BGP_E6_ADMIN_SHUTDWN  2 // Administrative Shutdown
#define BGP_E6_PEER_DECONF    3 // Peer De-configured
#define BGP_E6_ADMIN_RESET    4 // Administrative Reset
#define BGP_E6_CONN_REJECT    5 // Connection Rejected
#define BGP_E6_CONF_CHANGE    6 // Other Configuration Change
#define BGP_E6_COLLISION      7 // Connection Collision Resolution
#define BGP_E6_OUT_OF_RES     8 // Out of Resources
// ROUTE-REFRESH Message
#define BGP_E7_INV_MSG_LEN    1 // Invalid Message Length

// BGP path attributes
#define BGP_A_ORIGIN           1 // mandatory
#define BGP_A_AS_PATH          2 // mandatory
#define BGP_A_NEXT_HOP         3 // mandatory
#define BGP_A_MUL_EXIT_DISC    4 // Multi Exit Discriminator
#define BGP_A_LOCAL_PREF       5
#define BGP_A_ATOMIC_AGGR      6 // ATOMIC_AGGREGATE
#define BGP_A_AGGR             7 // AGGREGATOR
#define BGP_A_COMMUNITIES      8 // rfc1997
#define BGP_A_ORIG_ID          9 // ORIGINATOR_ID, rfc4456
#define BGP_A_CLUSTER_LIST    10 // rfc4456
#define BGP_A_DPA             11 // deprecated, rfc6938
#define BGP_A_ADVERTISER      12 // deprecated
#define BGP_A_RCID_PATH       13 // deprecated
#define BGP_A_MP_REACH_NLRI   14 // deprecated
#define BGP_A_MP_UNREACH_NLRI 15 // deprecated
#define BGP_A_EXT_COMM        16 // EXTENDED COMMUNITIES, rfc4360
#define BGP_A_AS4_PATH        17 // rfc6793
#define BGP_A_AS4_AGGR        18 // AS4_AGGREGATOR, rfc6793

// BGP Communities
#define BGP_COM_PLAN_SHUT     0xffff0000 // planned-shut [draft-francois-bgp-gshut][Pierre_Francois]
#define BGP_COM_ACCEPT_OWN    0xffff0001 // ACCEPT-OWN [RFC-ietf-l3vpn-acceptown-community-10]
#define BGP_COM_RTE_FILTR_TR4 0xffff0002 // ROUTE_FILTER_TRANSLATED_v4 [draft-l3vpn-legacy-rtc]
#define BGP_COM_RTE_FILTR_4   0xffff0003 // ROUTE_FILTER_v4 [draft-l3vpn-legacy-rtc]
#define BGP_COM_RTE_FILTR_TR6 0xffff0004 // ROUTE_FILTER_TRANSLATED_v6 [draft-l3vpn-legacy-rtc]
#define BGP_COM_RTE_FILTR_6   0xffff0005 // ROUTE_FILTER_v6 [draft-l3vpn-legacy-rtc]
#define BGP_COM_LLGR_STALE    0xffff0006 // LLGR_STALE [draft-uttaro-idr-bgp-persistence]
#define BGP_COM_NO_LLGR       0xffff0007 // NO_LLGR [draft-uttaro-idr-bgp-persistence]
#define BGP_COM_ACCEPT_OWN_NH 0xffff0008 // accept-own-nexthop [Ashutosh_Grewal]
#define BGP_COM_BLACKHOLE     0Xffff029a // BLACKHOLE Community
#define BGP_COM_NO_EXPORT     0xffffff01 // NO_EXPORT [rfc1997]
#define BGP_COM_NO_ADVERT     0xffffff02 // NO_ADVERTISE [rfc1997]
#define BGP_COM_NO_EXP_SUB    0xffffff03 // NO_EXPORT_SUBCONFED [rfc1997]
#define BGP_COM_NOPEER        0xffffff04 // NOPEER [rfc3765]

// BGP Communities tag
#define BGP_COM_TAG_BLACKHOLE 666

// BGP AS_PATH segment types
#define BGP_AS_SET             1 // Unordered set of ASes
#define BGP_AS_SEQUENCE        2 // Ordered set of ASes
#define BGP_AS_CONFED_SET      3 // Unordered set of Member AS numbers in the local confederation
#define BGP_AS_CONFED_SEQUENCE 4 // Ordered set of Member AS numbers in the local confederation

// bgpStat: BGP Status
#define BGP_STAT_BGP         0x0001 // Flow is BGP
#define BGP_STAT_CONN_SYNC   0x0002 // Connection Not Synchronized
#define BGP_STAT_BAD_LEN     0x0004 // Bad Message Length
#define BGP_STAT_BAD_TYPE    0x0008 // Bad Message Type
#define BGP_STAT_VERSION     0x0010 // Unsupported Version Number
//#define BGP_STAT_BOGON       0x0020 // Bogons advertisement
//#define BGP_STAT_BAD_PEER    0x0020 // Bad Peer AS
#define BGP_STAT_HTIME       0x0040 // Unacceptable Hold Time
#define BGP_STAT_INVMASK     0x0080 // Invalid network mask (> 32)
//#define BGP_STAT_BAD_ID      0x0080 // Bad BGP Identifier
//#define BGP_STAT_OPT_PARAM   0x0100 // Unsupported Optional Parameters
#define BGP_STAT_IAT         0x0100 // IAT for update or keep-alive < 0
#define BGP_STAT_AS_MISMATCH 0x0200 // Mismatch
#define BGP_STAT_ATOMIC_AGGR 0x0400 // Atomic Aggregate
//#define BGP_STAT_SPEC_PREF   0x0800 // Prefix more specific than /24 was advertised
//#define BGP_STAT_LSPEC_PREF   0x0800 // Prefix less specific than /8 was advertised
//#define BGP_STAT_BLACKHOLE   0x1000 // Possible blackhole: community with tag 666
//#define BGP_STAT_LOOP        0x2000 // Possible loop: my_as in as path
#define BGP_STAT_AFULL       0x4000 // One of the array was full... increase BGP_ASIZE
#define BGP_STAT_SNAPLEN     0x8000 // Malformed packet (snaplen)

// bgpAFlgs: BGP Anomaly flags
#define BGP_AFLGS_BOGON      0x0001 // Bogons advertisement
#define BGP_AFLGS_SPEC_PREF  0x0002 // Prefix more specific than /24 was advertised
#define BGP_AFLGS_LSPEC_PREF 0x0004 // Prefix less specific than /8 was advertised
#define BGP_AFLGS_BLACKHOLE  0x0008 // Possible blackhole: community with tag 666
#define BGP_AFLGS_LOOP       0x0010 // Possible loop: my_as in as path
#define BGP_AFLGS_MOAS       0x0020 // Multiple Origin AS (same prefix announced by more than one origin AS)
#define BGP_AFLGS_NPREPAS    0x0040 // AS prepended more than 10 times in AS path (average AS path length is between 4 and 5)
#define BGP_AFLGS_RESRVD_AS  0x0080 // AS number reserved for private use (AS: 64512-65534, AS4: 4200000000-4294967294)
#define BGP_AFLGS_MSPEC_PREF 0x0100 // Route for more specific prefix advertised

#if BGP_DEBUG_RT == 1
#define BGP_INF(format, args...) T2_PINF(plugin_name, format, ##args)
//#define BGP_INF(format, args...) T2_PINF(plugin_name, "pkt %4lu: " format, pkt, ##args)
#else // BGP_DEBUG_RT == 0
#define BGP_INF(format, args...) /* do nothing */
#endif // BGP_DEBUG_RT == 0

// plugin structures
typedef struct {
    uint8_t flag;
    uint8_t type;
    uint16_t len;
} bgp_orf_t;

typedef struct {
    // uint32_t pathid; // if BGP_C_ADD_PATH
    uint8_t mask;
    uint8_t prefix[4];
} bgp_nlri_t;

typedef struct {
    uint16_t nw;
    bgp_nlri_t withdrawn[BGP_ASIZE]; // Withdrawn routes
    uint8_t orig;                    // 0: IGP, 1: EGP, 2: INCOMPLETE, 255: (UNKNOWN)
    uint16_t nas;
    uint16_t nas4;                   // points to AS4 path if present
    struct {
        uint8_t stype;
        uint16_t nasn;
        uint32_t as[BGP_ASIZE];
    } aspath[BGP_ASIZE];
    uint32_t nexthop;
    uint32_t med;                    // Multi exit discriminator
    uint32_t locpref;                // Cisco routers use a Local Preference of 100 for all routes
    uint16_t nn;                     // number of networks (nlri)
    bgp_nlri_t nlri[BGP_ASIZE];
    uint32_t orig_id;
    uint32_t aggr[2];
    uint16_t nclust;                 // number of clusters
    uint32_t cluster[BGP_ASIZE];
    uint16_t nc;                     // number of communities
    uint32_t comm[BGP_ASIZE][2];     // AS:tag
} bgp_flow_update_t;

typedef struct {
    uint32_t rid;       // router id
    uint32_t nexthop;
    uint32_t med;       // Multi exit discriminator
    uint32_t locpref;
    uint32_t orig_as;   // Origin AS: last AS in the path
    //struct {
    //    uint8_t stype;
    //    uint16_t nasn;
    //    uint32_t as[25];
    //} aspath[25];
    uint16_t nas;
    uint8_t orig;       // IGP, EGP, INCOMPLETE
    uint8_t mask;
} bgp_rt_elem_t;

typedef struct {
    uint32_t num_t[BGP_T_RTE_REFRSH+1];

    uint16_t hdrlen;
    uint16_t stat;
    uint16_t aFlgs;

    // NOTIFICATION message
    uint8_t notif[2];    // Notification (fatal error): code, subcode

    // KEEPALIVE messages
    double lastka;       // time of the last keep-alive message
    double miniatka;     // minimum inter-arrival time for keep-alive messages
    double maxiatka;     // maximum inter-arrival time for keep-alive messages
    double avgiatka;     // average inter-arrival time for keep-alive messages

    uint8_t msgT;

    // OPEN message
    uint8_t  version;
    uint16_t caps;       // capabilities
    uint16_t htime;      // Juniper: 90, Cisco: 180, Min: 3
    uint32_t src_as;
    uint32_t dst_as;
    uint32_t src_id;
    uint32_t dst_id;
    uint32_t attr;       // path attributes, e.g., atomic aggregate

    // UPDATE messages
    uint32_t nadver;     // total number of advertised routes
    uint32_t nwdrwn;     // total number of withdrawn routes
    uint32_t maxadver;   // maximum number of advertised routes per record
    uint32_t maxwdrwn;   // maximum number of withdrawn routes per record
    uint32_t advpref;    // advertised prefixes
    uint32_t wdrnpref;   // withdrawn prefixes
    uint32_t origin[3];  // number of routes from origin IGP, EGP, INCOMPLETE
    uint32_t nasp;       // number of non empty AS path messages
    uint32_t maxnprepas; // maximum number of prepended AS
    uint8_t  minasplen;  // maximum length of AS path
    uint8_t  maxasplen;  // minimum length of AS path
    double   avgasplen;  // average AS path length
    double   avgadver;   // average number of advertised routes per record
    double   avgwdrwn;   // average number of withdrawn routes per record
    double   lastup;     // time of the last update message
    double   miniatup;   // minimum inter-arrival time for update messages
    double   maxiatup;   // maximum inter-arrival time for update messages
    double   avgiatup;   // average inter-arrival time for update messages

    double now;

} bgp_flow_t;

extern bgp_flow_t *bgp_flows;

#endif // __BGP_DECODE_H__
