/*
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
 *   [RFC 1131] The OSPF Specification (obsolete)
 *   [RFC 2328] OSPF Version 2
 *   [RFC 5340] OSPF for IPv6
 */

#ifndef __OSPFDECODE_H__
#define __OSPFDECODE_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define OSPF_OUTPUT_HLO   1 // output hello message file
#define OSPF_OUTPUT_DBD   1 // output database message file
#define OSPF_OUTPUT_MSG   1 // output all other message file
#define OSPF_OUTPUT_STATS 1 // output statistics file

#define OSPF_MASK_AS_IP   1 // Netmasks representation:
                            //   0: hex,
                            //   1: IPv4
#define OSPF_AREA_AS_IP   0 // Areas representation:
                            //   0: int,
                            //   1: IPv4,
                            //   2: hex
#define OSPF_LSID_AS_IP   1 // Link State ID representation:
                            //   0: int,
                            //   1: IPv4
#define OSPF_TYP_STR      1 // Message type representation:
                            //   0: aggregated hex bitfield
                            //   1: list of strings
#define OSPF_LSTYP_STR    1 // LS type representation:
                            //   0: int
                            //   1: string
#define OSPF_NEIGMAX     10 // Maximum number of neighbors to store
#define OSPF_NUMTYP      10 // Maximum number of LS types to store (require OSPF_TYP_STR == 1)

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

// Suffixes for output files
#define OSPF_SUFFIX       "_ospfStats.txt"
#define OSPF_HELLO_SUFFIX "_ospfHello.txt"  // OSPFv2/3 hello messages
#define OSPF_DBD_SUFFIX   "_ospfDBD.txt"    // OSPFv2/3 database description (routing tables)
#define OSPF2_MSG_SUFFIX  "_ospf2Msg.txt"   // All other messages from OSPFv2 (Link State Request/Update/Ack)
#define OSPF3_MSG_SUFFIX  "_ospf3Msg.txt"   // All other messages from OSPFv3 (Link State Request/Update/Ack)

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_OSPF_SUFFIX,
    ENV_OSPF_HELLO_SUFFIX,
    ENV_OSPF_DBD_SUFFIX,
    ENV_OSPF2_MSG_SUFFIX,
    ENV_OSPF3_MSG_SUFFIX,
    ENV_OSPF_N
};


// plugin defines

#if (OSPF_OUTPUT_STATS == 1 || \
     OSPF_OUTPUT_HLO   == 1 || \
     OSPF_OUTPUT_DBD   == 1 || \
     OSPF_OUTPUT_MSG   == 1)
#define OSPF_NEED_ENV
#endif

#if OSPF_AREA_AS_IP == 1
#define OSPF_AREA_TYPE bt_ip4_addr  // Area as IP (string)
#define OSPF_PRI_AREA "s"
#elif OSPF_AREA_AS_IP == 2
#define OSPF_AREA_TYPE bt_hex_32    // Area as hex
#define OSPF_PRI_AREA "#08x"
#else // OSPF_AREA_AS_IP == 0
#define OSPF_AREA_TYPE bt_uint_32   // Area as int
#define OSPF_PRI_AREA PRIu32
#endif // OSPF_AREA_AS_IP

#if OSPF_LSTYP_STR == 1
#define OSPF_PRI_LSTYPE "s"
#else // OSPF_LSTYP_STR == 0
#define OSPF_PRI_LSTYPE "d"
#endif // OSPF_LSTYP_STR

//31 19 20 20 11 15
// OSPF length
#define OSPF2_HDR_LEN 24
#define OSPF3_HDR_LEN 16
#define OSPF2_LSA_LEN 20 // LSA Header = sizeof(ospfLSA_t)
#define OSPF3_LSA_LEN 20 // LSA Header = sizeof(ospfLSA_t)
#define OSPF2_DBD_LEN  8 // sizeof(ospfDBD_t) - sizeof(uint32_t) [optional fields]
#define OSPF3_DBD_LEN 12 // sizeof(ospf3DBD_t) - sizeof(uint32_t) [optional fields]

// OSPF types
#define OSPF_HELLO     1 // Discovers/maintains neighbors
#define OSPF_DB_DESCR  2 // Summarizes database contents
#define OSPF_LS_REQ    3 // (Link State) Database download
#define OSPF_LS_UPDATE 4 // (Link State) Database upload
#define OSPF_LS_ACK    5 // (Link State) Flooding acknowledgment
#define OSPF_TYPE_N    6 // Size of array to store OSPF types

#define OSPF_TYPE_UNK   "UNK"

// IP Multicast addresses
// Packets sent to those addresses MUST have their IP TTL set to 1
#define OSPF_ALL_SPF_ROUTERS htonl(0xe0000005) // 224.0.0.5
#define OSPF_ALL_D_ROUTERS   htonl(0xe0000006) // 224.0.0.6 (designated routers)

#define OSPF3_ALL_SPF_ROUTERS ff02::5 //
#define OSPF3_ALL_D_ROUTERS   ff02::6 // (designated routers)

// OSPF Authentication Type
#define OSPF_AUTH_NULL   0
#define OSPF_AUTH_PASSWD 1
#define OSPF_AUTH_CRYPTO 2
#define OSPF_AUTH_N      3 // Size of array to store OSPF auth types

// OSPFv2/3 LS Type
// 0 reserved
#define OSPF_LSTYPE_ROUTER       1 // Router-LSA
#define OSPF_LSTYPE_NETWORK      2 // Network-LSA

// OSPFv2 LS Type
#define OSPF_LSTYPE_SUMMARY      3 // Summary-LSA (IP network)
#define OSPF_LSTYPE_ASBR         4 // Summary-LSA (ASBR)
#define OSPF_LSTYPE_ASEXT        5 // AS-External-LSA
#define OSPF_LSTYPE_MCAST        6 // Multicast group LSA (not implemented by Cisco)
#define OSPF_LSTYPE_NSSA         7 // Not-so-stubby area (NSSA) External LSA
#define OSPF_LSTYPE_EXTATTR      8 // External attribute LSA for BGP
#define OSPF_LSTYPE_OPAQUE_LLS   9 // Opaque LSA: Link-local scope
#define OSPF_LSTYPE_OPAQUE_ALS  10 // Opaque LSA: Area-local scope
#define OSPF_LSTYPE_OPAQUE_ASS  11 // Opaque LSA: autonomous system scope
#define OSPF_LSTYPE_N           12 // Size of array to store LS types

// OSPFv3 LS Type
#define OSPF3_LT3_INT_A_PREF     3 // Inter-Area-Prefix-LSA
#define OSPF3_LT3_INT_A_RTR      4 // Inter-Area-Router-LSA
#define OSPF3_AS_EXT             5 // AS-External-LSA
#define OSPF3_DEPR               6 // Deprecated in OSPFv3
#define OSPF3_NSSA               7 // NSSA-LSA
#define OSPF3_LINK               8 // Link-LSA
#define OSPF3_INTR_A_PREF        9 // Intra-Area-Prefix-LSA
#define OSPF3_INTR_A_TE_LSA     10 // Intra-Area-TE-LSA
#define OSPF3_GRACE_LSA         11 // GRACE-LSA
#define OSPF3_RI_LSA            12 // OSPFv3 Router Information (RI)
#define OSPF3_INTR_AS_TE_LSA    13 // Inter-AS-TE-v3 LSA
#define OSPF3_L1VPN_LSA         14 // OSPFv3 L1VPN LSA
#define OSPF3_AC_LSA            15 // OSPFv3 Autoconfiguration (AC) LSA
#define OSPF3_DYNFL_LSA         16 // OSPFv3 Dynamic Flooding LSA
// 17-32 unassigned
#define OSPF3_E_RTR_LSA         33 // E-Router-LSA
#define OSPF3_E_NET_LSA         34 // E-Network-LSA
#define OSPF3_E_INT_A_PREF_LSA  35 // E-Inter-Area-Prefix-LSA
#define OSPF3_E_INT_A_RTR_LSA   36 // E-Inter-Area-Router-LSA
#define OSPF3_E_AS_EXT_LSA      37 // E-AS-External-LSA
// 38 unused (not to be allocated)
#define OSPF3_E_TYP_7_LSA       39 // E-Type-7-LSA
#define OSPF3_E_LINK_LSA        40 // E-Link-LSA
#define OSPF3_E_INTR_A_PREF_LSA 41 // E-Intra-Area-Prefix-LSA
// 42-255 unassigned
// 256-8175 reserved
// 8176-8183 experimentation
// 8184-8190 Vendor Private Use
// 8191 reserved
#define OSPF3_LSTYPE_N          42 // Size of array to store LS types

//
#define OSPF_LINK_PTP    1 // Point-to-point connection to another router
#define OSPF_LINK_TRAN   2 // Connection to a transit network
#define OSPF_LINK_STUB   3 // Connection to a stub network
#define OSPF_LINK_VIRT   4 // Virtual link
#define OSPF_LINK_TYPE_N 5 // Size of array to store link types

// OSPFv2 Hello options
#define OSPF_OPT_DN 0x80 // BGP/MPLS VPNs [rfc4576]
#define OSPF_OPT_O  0x40 // Opaque LSA capable
#define OSPF_OPT_DC 0x20 // Demand circuits, describes the router's handling of demand circuits
#define OSPF_OPT_LL 0x10 // packet contains LLS data block
#define OSPF_OPT_NP 0x08 // NSSA is supported (N) / Propagate (P)
#define OSPF_OPT_MC 0x04 // Multicast Capable, describes whether IP multicast datagrams are forwarded according to the specifications
#define OSPF_OPT_E  0x02 // External Routing Capability, describes the way AS-external-LSAs are flooded
#define OSPF_OPT_MT 0x01 // Multi-Topology Routing

// OSPF DBD description
#define OSPF_DBD_RSYN  0x08 //
#define OSPF_DBD_INIT  0x04 //
#define OSPF_DBD_MORE  0x02 //
#define OSPF_DBD_MSTR  0x01 //


// OSPFv3 1,2 options
#define OSPF_LSAOPT_AT 0x4000 //
#define OSPF_LSAOPT_L  0x2000 //
#define OSPF_LSAOPT_AF 0x1000 //
#define OSPF_LSAOPT_DC 0x0020 // Demand Circuit, describes the router's handling of demand circuits
#define OSPF_LSAOPT_R  0x0010 // 1: originator is an active router, 0: routes that transit the advertising node cannot be computed, multi-homed host that wants to participate in routing, but does not want to forward non locally addressed packets
#define OSPF_LSAOPT_N  0x0008 // Indicates whether or not the router is attached to an NSSA
#define OSPF_LSAOPT_MC 0x0004 // Multicast, describes whether IP multicast datagrams are forwarded according to the specifications
#define OSPF_LSAOPT_E  0x0002 // External routing capability, describes the way AS-external-LSAs are flooded,
#define OSPF_LSAOPT_V6 0x0001 // 0: the router/link should be excluded from IPv6 routing calculations.
                              // R:1 & V6:0 IPv6 datagrams are not forwarded but datagrams belonging to another protocol family may be forwarded

// OSPFv3 LSA 1 Flags
#define OSPF_LSAFLG_W 0x08 // Wild-card multicast receiver
#define OSPF_LSAFLG_V 0x04 // Virtual Link endpoint
#define OSPF_LSAFLG_E 0x02 // AS boundary router
#define OSPF_LSAFLG_B 0x01 // Area border router

// OSPFv3 LSA 5, 7, 8, 9
#define OSPF_PRFOPT_N  0x20 // Identifies advertising router, not set when /128 or /32
#define OSPF_PRFOPT_DN 0x10 //
#define OSPF_PRFOPT_P  0x08 // Propagate
#define OSPF_PRFOPT_MC 0x04 // Multicast
#define OSPF_PRFOPT_LA 0x02 // Local Address
#define OSPF_PRFOPT_NU 0x01 // NoUnicast

// ospfStat
#define OSPF_STAT_DETECT     0x01 // OSPF detected
#define OSPF_STAT_BAD_TTL    0x02 // OSPFv2 TTL != 1 when dst addr is mcast
#define OSPF_STAT_BAD_DST    0x04 // OSPFv2 invalid destination address, e.g. HELLO always sent to ALL_SPF_ROUTERS
#define OSPF_STAT_BAD_TYPE   0x08 // invalid OSPF type
#define OSPF_STAT_WRNG_VER   0x10 // wrong version
//#define OSPF_STAT_BAD_CSUM   0x20 // invalid checksum (TODO)
#define OSPF_STAT_MALFORMED  0x80 // unused fields in use... snapped, covert channel?


// plugin structs

typedef struct {
    uint8_t version;
    uint8_t type;
    uint16_t len;
    struct in_addr routerID;
    uint32_t areaID;
    uint16_t chksum;
    uint16_t auType;    // v2 (IPv4)
    union { // v2 only
        uint64_t auField;   // auType == 1
        struct {            // auType == 2
            uint16_t zero16;
            uint8_t  keyID;
            uint8_t  auDataLen;
            uint32_t cryptoSeqNum;
        };
    };
    uint8_t data;
} ospfHeader_t;

typedef struct {
    uint8_t version;
    uint8_t type;
    uint16_t len;
    struct in_addr routerID;
    uint32_t areaID;
    uint16_t chksum;
    struct {            // v3 (IPv6)
         uint8_t instID;
         uint8_t zero8;
    };
    uint8_t data;
} ospf3Header_t;

typedef struct {
    uint16_t lsAge;
    union {
       struct {
          uint8_t opts;
          uint8_t lsType;
       };
       uint16_t ls3Type;
    };
    struct in_addr lsaID;
    struct in_addr advRtr;
    uint32_t lsSeqNum;
    uint16_t lsChksum;
    uint16_t lsLen;
} ospfLSA_t;

#define OSPF_LSA_DNA(lsa) (ntohs((lsa)->lsAge) >> 0xf) // Do Not Age

typedef struct {
    struct in_addr linkID; // type=1 or 4: neighboring router's Router ID,
                           // type=2: IP address of Designated Router
                           // type=3: IP network/subnet number
    uint32_t linkData; // type=3: netmask, type=1: interface MIB-II ifIndex value,
                       // other types: router's associated IP interface address
    uint8_t type;
    uint8_t numTOS;
    uint16_t metric;
} ospfRouterLSALink_t;
//} __attribute__((packed)) ospfRouterLSALink_t;

typedef struct {
    ospfLSA_t lsaHdr;
    uint32_t flgs_numLnks;
    ospfRouterLSALink_t rInt;
} ospfRouterLSA_t;

typedef struct {
    uint8_t type;
    uint8_t res;
    uint16_t metric;
    uint32_t intID;
    uint32_t neighIntID;
    struct in_addr neighIntRtrID;
} ospf3RouterLSAInt_t;

typedef struct {
    ospfLSA_t lsaHdr;
    uint32_t flgs_opt;
    ospf3RouterLSAInt_t rInt;
} ospf3RouterLSA_t;

#define OSPF3_RLSA_N(rlsa) ((rlsa)->flags & 0x10) // NSSA border router
#define OSPF3_RLSA_W(rlsa) ((rlsa)->flags & 0x08) // wildcard multicast receiver
#define OSPF3_RLSA_W(rlsa) ((rlsa)->flags & 0x08) // deprecated
#define OSPF3_RLSA_V(rlsa) ((rlsa)->flags & 0x04) // virtual link endpoint
#define OSPF3_RLSA_E(rlsa) ((rlsa)->flags & 0x02) // AS boundary router (external)
#define OSPF3_RLSA_B(rlsa) ((rlsa)->flags & 0x01) // area border router

typedef struct {
    ospfLSA_t lsaHdr;
    uint32_t netmask;
    struct in_addr router; // attached router(s)
} ospfNetworkLSA_t;

typedef struct {
    ospfLSA_t lsaHdr;
    uint32_t opts;
    struct in_addr router; // attached router(s)
} ospf3NetworkLSA_t;

typedef struct {
    ospfLSA_t lsaHdr;
    uint32_t netmask;
//    uint32_t metric;
    uint32_t tos_tmtrc;
} ospfSummaryLSA_t; // lsType = 3 or 4

typedef struct {
    ospfLSA_t lsaHdr;
    uint32_t metric;
    uint8_t prefLen;
    uint8_t prefOpt;
    uint16_t zero;
    uint32_t addrPref;
} ospf3IntAreaPref3LSA_t; // lsType = 3

typedef struct {
    ospfLSA_t lsaHdr;
    uint32_t opts;
    uint32_t metric;
    uint32_t destRtrID;
} ospf3IntAreaRtr4LSA_t; // lsType = 4

typedef struct {
    ospfLSA_t lsaHdr;
    uint32_t netmask;
    uint32_t e_tos_mtrc;
    struct in_addr forwardAddr; // forwarding address
    uint32_t extRtTg; // External Route Tag (not used by OSPF)
} ospfASExtLSA_t; // lsType = 5

typedef struct {
    ospfLSA_t lsaHdr;
    uint32_t flgs_mtrc;
    uint8_t prefLen;
    uint8_t prefOpt;
    uint16_t refLSType;
    uint32_t addrPref;
} ospf3ASsExtLSA_t; // lsType = 5

typedef struct {
    ipAddr_t fwdAddr;
    uint32_t extRtTg;
    uint32_t refLnkStID;
} ospf3ASaddExtLSA_t; // lsType = 5

typedef struct {
    ospfLSA_t lsaHdr;
    uint32_t eft_mtrc;
    uint8_t prefLen;
    uint8_t prefOpt;
    uint16_t refLSType;
    uint32_t addrPref;
} ospf3NSSALSA_t; // lsTypes = 7

typedef struct {
    ipAddr_t fwdAddr; // forwarding address (optional)
    uint32_t extRtTg; // External Route Tag (optional)
    uint32_t refLnkStID; // referenced Link State ID (optional)
} ospf3NSSALSAopt_t; // lsTypes = 7

typedef struct {
    uint32_t rtrPrio:8;
    uint32_t Options:24;
    ipAddr_t llIAddr;
    uint32_t numPref;
} ospf3LinkLSA_t; // 8

typedef struct {
    uint16_t numPref;
    uint16_t refLSType;
    struct in_addr refLnkStID;
    struct in_addr refAdRtr;
} ospf3IAreaPrefLSA9_t; // 9

typedef struct {
    uint8_t prefLen;
    uint8_t prefOpt;
    uint16_t metric;
    uint32_t addrPref;
} ospf3IAreaPref9_t; // 9 / 8

typedef struct {
    uint16_t type;
    uint16_t len;
    uint32_t options; //
} ospfLLSTLV_t;

typedef struct {
    uint16_t chksum;
    uint16_t len;
    // Followed by TLV
    uint16_t tlvType;
    uint16_t tlvLen;
    uint32_t tlvVal;
} ospfLLS_t;

typedef struct {
    uint32_t netmask;
    uint16_t helloInt;     // default is 10
    uint8_t options;
    uint8_t rtrPri;
    uint32_t routDeadInt;  // default is 4*helloInt
    struct in_addr desRtr;
    struct in_addr backupRtr;
    struct in_addr neighbors;
} ospfHello_t;

typedef struct {
    uint32_t intID;
    uint32_t rpopt;
    uint16_t helloInt;
    uint16_t routDeadInt;  // default is 4*helloInt
    struct in_addr desRtr;
    struct in_addr backupRtr;
    struct in_addr neighbors;
} ospfHello3_t;

typedef struct {
    uint16_t intMTU;
    uint8_t options;
    uint8_t dbDesc;
    uint32_t DDSeqNum;
    uint8_t lsaHdr;
} ospfDBD_t; // Database description

typedef struct {
    uint32_t options;
    uint16_t intMTU;
    uint16_t dbDesc;
    uint32_t DDSeqNum;
    uint8_t lsaHdr;
} ospf3DBD_t; // Database description

typedef struct {
    uint32_t lsType;
    struct in_addr lsID;
    struct in_addr advRtr;
} ospfLSR_t; // LS Request

typedef struct {
    uint32_t numLSA;
    uint8_t lsaHdr;
} ospfLSU_t; // LS Update

/*
// OSPF length
#define OSPF2_HDR_LEN (sizeof(ospfHeader_t))
#define OSPF3_HDR_LEN (sizeof(ospf3Header_t))
#define OSPF2_LSA_LEN sizeof(ospfLSA_t)
#define OSPF3_LSA_LEN sizeof(ospf3LSA_t)
#define OSPF2_DBD_LEN (sizeof(ospfDBD_t))
#define OSPF3_DBD_LEN (sizeof(ospf3DBD_t))
*/

// plugin struct

typedef struct {
    uint64_t lsType;
    uint32_t areaID;
    uint32_t numTyp;
    uint32_t numNeigh;
    struct in_addr routerID;
    struct in_addr backupRtr;
    struct in_addr neighbors[OSPF_NEIGMAX];
    uint16_t auType; // authentication type (0: none, 1: password, 2: crypto)
    uint8_t version;
    uint8_t stat;
#if OSPF_TYP_STR == 1
    uint8_t type[OSPF_NUMTYP];
#else // OSPF_TYP_STR == 0
    uint8_t type;
#endif // OSPF_TYP_STR
    char auPass[9];  // authentication password
} ospfFlow_t;

extern ospfFlow_t *ospfFlow;

#endif // __OSPFDECODE_H__
