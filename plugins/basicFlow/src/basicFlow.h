/*
 * basicFlow.h
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

#ifndef __BASIC_FLOW_H__
#define __BASIC_FLOW_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define BFO_SENSORID       0 // Output sensorID

#define BFO_HDRDESC_PKTCNT 0 // Include packet count for header description

#define BFO_MAC            1 // Output MAC addresses
#define BFO_ETHERTYPE      1 // Output EtherType (require IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0)

#define BFO_MPLS    0 // 0: Do not output MPLS information,
                      // 1: Output MPLS labels,
                      // 2: Output MPLS labels as hex,
                      // 3: Output MPLS headers as hex,
                      // 4: Output decoded MPLS headers as label_ToS_S_TTL

#define BFO_VLAN    1 // 0: Do not output VLAN information,
                      // 1: Output VLAN numbers,
                      // 2: Output VLAN headers as hex
                      // 3: Output decoded VLAN headers as TPID_PCP_DEI_VID

//#define BFO_GTP     0 // Enable GTP output (TODO)
#define BFO_GRE     0 // Enable GRE output
#define BFO_L2TP    0 // Enable L2TP output
#define BFO_PPP     0 // Enable PPP output
#define BFO_LAPD    0 // Enable LAPD output (require LAPD_ACTIVATE=1)
#define BFO_TEREDO  0 // Enable Teredo output

#define BFO_SUBNET_IPLIST      0 // 0: Display only the IP masked by SRCIP[46]CMSK and DSTIP[46]CMSK
                                 // 1: Display a list of IP aggregated

#define BFO_SUBNET_TEST        1 // Enable subnet test on inner IP
#define BFO_SUBNET_TEST_GRE    0 // Enable subnet test on GRE addresses
#define BFO_SUBNET_TEST_L2TP   0 // Enable subnet test on L2TP addresses
#define BFO_SUBNET_TEST_TEREDO 0 // Enable subnet test on Teredo addresses

#define BFO_SUBNET_ASN  0 // Output Autonomous System Numbers (ASN)
#define BFO_SUBNET_LL   0 // Output position (latitude, longitude and reliability)
#define BFO_SUBNET_ORG  1 // Output Organization
#define BFO_SUBNET_HEX  0 // Output the country code and organization information as one 32-bit hex number

// Maximum number of values to store

#define BFO_MAX_HDRDESC 4 // Maximum number of headers descriptions to store
#define BFO_MAX_MAC     3 // Maximum different MAC addresses to output
#define BFO_MAX_IP      5 // Maximum different IP addresses to output
#define BFO_MAX_MPLS    3 // Maximum MPLS headers/tags to output
#define BFO_MAX_VLAN    3 // Maximum VLAN headers/numbers to output

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*        No env / runtime configuration flags available for basicFlow        */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


#if BFO_VLAN > 0 && BFO_MAX_VLAN <= 0
#error "BFO_VLAN > 0, but BFO_MAX_VLAN <= 0"
#endif // BFO_VLAN > 0 && BFO_MAX_VLAN <= 0


// Plugin definitions

#if IPV6_ACTIVATE == 1
#undef BFO_SUBNET_TEST_GRE
#define BFO_SUBNET_TEST_GRE 0
#undef BFO_SUBNET_TEST_L2TP
#define BFO_SUBNET_TEST_L2TP 0
#endif

#if SUBNET_INIT == 0
#undef  BFO_SUBNET_TEST
#define BFO_SUBNET_TEST 0
#undef  BFO_SUBNET_TEST_GRE
#define BFO_SUBNET_TEST_GRE 0
#undef  BFO_SUBNET_TEST_L2TP
#define BFO_SUBNET_TEST_L2TP 0
#undef  BFO_SUBNET_TEST_TEREDO
#define BFO_SUBNET_TEST_TEREDO 0
// SUBNET_INIT != 0
#elif (BFO_SUBNET_TEST == 1 || \
       (BFO_GRE    == 1 && BFO_SUBNET_TEST_GRE    == 1) || \
       (BFO_L2TP   == 1 && BFO_SUBNET_TEST_L2TP   == 1) || \
       (BFO_TEREDO == 1 && BFO_SUBNET_TEST_TEREDO == 1))
// core subnet initialized and basicFlow subnet enabled
#define BFO_SUBNETHL_INCLUDED 1
#endif // SUBNET_INIT != 0

#ifndef BFO_SUBNETHL_INCLUDED
#define BFO_SUBNETHL_INCLUDED 0
#endif // BFO_SUBNETHL_INCLUDED

#if (AGGREGATIONFLAG & SUBNET)
#undef BFO_SUBNET_IPLIST
#define BFO_SUBNET_IPLIST 1
#elif (AGGREGATIONFLAG & (SRCIP | DSTIP)) == 0
#undef BFO_SUBNET_IPLIST
#define BFO_SUBNET_IPLIST 0
#endif // (AGGREGATION & SUBNET)

#if IPV6_ACTIVATE == 2
#define BFO_IP_TYPE bt_ipx_addr
#elif IPV6_ACTIVATE == 1
#define BFO_IP_TYPE bt_ip6_addr
#else // IPV6_ACTIVATE == 0
#define BFO_IP_TYPE bt_ip4_addr
#endif // IPV6_ACTIVATE == 0


// Plugin Flow structures

typedef struct {
#if (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)
    uint64_t pktCnt[BFO_MAX_HDRDESC];
#endif

    struct timeval lastPktTime;

#if (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
    uint32_t mplsHdr[BFO_MAX_MPLS];
    uint32_t num_mpls;
#endif

#if BFO_PPP == 1
    pppHu_t pppHdr;
#endif

#if BFO_GRE == 1
    struct in_addr gre_srcIP;
    struct in_addr gre_dstIP;
    uint32_t greHdrBF;
#endif

#if (BFO_MAC == 1 && BFO_MAX_MAC > 0)
    uint32_t num_srcMac;
    uint32_t num_dstMac;
    uint8_t srcMac[BFO_MAX_MAC][ETH_ALEN];
    uint8_t dstMac[BFO_MAX_MAC][ETH_ALEN];
#endif

#if (BFO_VLAN > 0 && BFO_MAX_VLAN > 0)
    uint32_t num_vlans;
    uint32_t vlans[BFO_MAX_VLAN];
#endif

#if (AGGREGATIONFLAG & (SUBNET | SRCIP | DSTIP)) || BFO_SUBNET_IPLIST == 1
    uint32_t ipCnt[2];
#if IPV6_ACTIVATE > 0
    ipAddr_t ip[2][BFO_MAX_IP];
#else // IPV6_ACTIVATE == 0
    ip4Addr_t ip[2][BFO_MAX_IP];
#endif // IPV6_ACTIVATE
#endif // (AGGREGATIONFLAG & (SUBNET | SRCIP | DSTIP)) || BFO_SUBNET_IPLIST == 1

#if BFO_TEREDO == 1
    uint32_t trdoIP;
    uint16_t trdoPort;
#endif // BFO_TEREDO == 1

#if BFO_L2TP == 1
    struct in_addr l2tp_srcIP;
    struct in_addr l2tp_dstIP;
    uint16_t l2tpHdrBF;
    union {
        struct {
            uint16_t l2tpHdrTID;
            uint16_t l2tpHdrSID;
        };
        uint32_t l2tpv3HdrccID;
    };
#endif // BFO_L2TP == 1

#if (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)
    char hdrDesc[BFO_MAX_HDRDESC][T2_HDRDESC_LEN];
    uint16_t hdrCnt[BFO_MAX_HDRDESC];
    uint8_t hDCnt;
#endif // (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)

#if LAPD_ACTIVATE == 1 && BFO_LAPD == 1
    uint8_t lapdSAPI;
    uint8_t lapdTEI;
#endif // LAPD_ACTIVATE && BFO_LAPD == 1

} bfoFlow_t;

// plugin struct pointer for potential dependencies
extern bfoFlow_t *bfoFlow;

#endif // __BASIC_FLOW_H__
