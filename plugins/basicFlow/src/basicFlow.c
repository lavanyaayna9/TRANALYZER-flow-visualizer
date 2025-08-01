/*
 * basicFlow.c
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

#include "basicFlow.h"

#include <time.h>  // for strftime, gmtime, localtime

#include "proto/ethertype.h"
#include "proto/l2tp.h"
#include "proto/vlan.h"


// plugin global vars

bfoFlow_t *bfoFlow;


// Function prototypes

static inline void claimInfo(packet_t *packet, unsigned long flowIndex);
#if BLOCK_BUF == 0 && BFO_SUBNETHL_INCLUDED == 1 && ANONYM_IP == 0
static inline void bfo_add_ip_geo_info(outputBuffer_t *buf, uint_fast8_t ipver, uint32_t subnetNr);
static inline void bfo_add_empty_geo_info(outputBuffer_t *buf);
#if (BFO_GRE    == 1 && BFO_SUBNET_TEST_GRE    == 1) || \
    (BFO_L2TP   == 1 && BFO_SUBNET_TEST_L2TP   == 1) || \
    (BFO_TEREDO == 1 && BFO_SUBNET_TEST_TEREDO == 1)
static inline void bfo_test_and_add_ip_geo_info(outputBuffer_t *buf, ipAddr_t ip, uint_fast8_t ipver);
static inline void bfo_test_and_add_ipv4_geo_info(outputBuffer_t *buf, uint32_t ipv4);
#endif
#endif // BLOCK_BUF == 0 && BFO_SUBNETHL_INCLUDED == 1 && ANONYM_IP == 0


// Tranalyzer Plugin Functions

T2_PLUGIN_INIT("basicFlow", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(bfoFlow);

    if (sPktFile) {
        fputs("flowStat"             SEP_CHR
#if RELTIME == 1
              "relTime"              SEP_CHR
#else // RELTIME == 0
              "time"                 SEP_CHR
#endif // RELTIME
              "pktIAT"               SEP_CHR
              "pktTrip"              SEP_CHR
              "flowDuration"         SEP_CHR
#if T2_PRI_HDRDESC == 1
              "numHdrs"              SEP_CHR
              "hdrDesc"              SEP_CHR
#endif // T2_PRI_HDRDESC == 1

#if BFO_VLAN > 0
#if BFO_VLAN == 3
              "vlanTPID_PCP_DEI_VID" SEP_CHR
#elif BFO_VLAN == 2
              "vlanHdr"              SEP_CHR
#else // BFO_VLAN == 1
              "vlanID"               SEP_CHR
#endif // BFO_VLAN
#endif // BFO_VLAN > 0

#if (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
#if BFO_MPLS == 4
              "mplsLabel_ToS_S_TTL"  SEP_CHR
#elif BFO_MPLS == 3
              "mplsHdrsHex"          SEP_CHR
#elif BFO_MPLS == 2
              "mplsLabelsHex"        SEP_CHR
#else // BFO_MPLS == 1
              "mplsLabels"           SEP_CHR
#endif // BFO_MPLS == 1
#endif // (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
              "srcMac"               SEP_CHR
              "dstMac"               SEP_CHR
              "ethType"              SEP_CHR
#if LAPD_ACTIVATE == 1 && BFO_LAPD == 1
              "lapdSAPI"             SEP_CHR
              "lapdTEI"              SEP_CHR
              "lapdFType"            SEP_CHR
              "lapdFunc"             SEP_CHR
              "lapdNR"               SEP_CHR
              "lapdNS"               SEP_CHR
#endif // LAPD_ACTIVATE == 1 && BFO_LAPD == 1
#if ANONYM_IP == 0
              "srcIP"                SEP_CHR
#if BFO_SUBNET_TEST == 1
              "srcIPCC"              SEP_CHR
#if BFO_SUBNET_ORG == 1
              "srcIPOrg"             SEP_CHR
#endif // BFO_SUBNET_ORG == 1
#endif // BFO_SUBNET_TEST == 1
#endif // ANONYM_IP == 0
              "srcPort"              SEP_CHR
#if ANONYM_IP == 0
              "dstIP"                SEP_CHR
#if BFO_SUBNET_TEST == 1
              "dstIPCC"              SEP_CHR
#if BFO_SUBNET_ORG == 1
              "dstIPOrg"             SEP_CHR
#endif // BFO_SUBNET_ORG == 1
#endif // BFO_SUBNET_TEST == 1
#endif // ANONYM_IP == 0
              "dstPort"              SEP_CHR
              "l4Proto"              SEP_CHR
              , sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

#if BFO_SENSORID == 1
    BV_APPEND_U32(bv, "sensorID", "Sensor ID");
#endif // BFO_SENSORID == 1

    BV_APPEND_H64(bv, "flowStat", "Flow status and warnings");

    BV_APPEND_TIMESTAMP(bv, "timeFirst", "Date time of first packet");
    BV_APPEND_TIMESTAMP(bv, "timeLast", "Date time of last packet");

    BV_APPEND_DURATION(bv, "duration", "Flow duration");

#if (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)
    BV_APPEND_U8(bv, "numHdrDesc", "Number of different headers descriptions");
    BV_APPEND_U16_R(bv, "numHdrs", "Number of headers (depth) in hdrDesc");
#if BFO_HDRDESC_PKTCNT == 1
    BV_APPEND_R(bv, "hdrDesc_pktCnt",
                "Headers description and packet count",
                2, bt_string_class, bt_uint_64);
#else // BFO_HDRDESC_PKTCNT == 0
    BV_APPEND_STRC_R(bv, "hdrDesc", "Headers description");
#endif // BFO_HDRDESC_PKTCNT
#endif // (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)

#if (BFO_MAC == 1 && BFO_MAX_MAC > 0)
    BV_APPEND_MAC_R(bv, "srcMac", "Mac source");
    BV_APPEND_MAC_R(bv, "dstMac", "Mac destination");
#endif

#if ((ETH_ACTIVATE > 0 || IPV6_ACTIVATE == 2) && BFO_ETHERTYPE == 1)
    BV_APPEND_H16(bv, "ethType", "Ethernet type");
#endif

#if (BFO_VLAN > 0 && BFO_MAX_VLAN > 0)
#if BFO_VLAN == 3
    BV_APPEND_R(bv, "vlanTPID_PCP_DEI_VID",
                "VLAN tag protocol identifier, priority code point, drop eligible indicator, VLAN identifier",
                4, bt_hex_16, bt_uint_8, bt_uint_8, bt_uint_16);
#elif BFO_VLAN == 2
    BV_APPEND_H32_R(bv, "vlanHdr", "VLAN headers (hex)");
#else // BFO_VLAN == 1
    BV_APPEND_U16_R(bv, "vlanID", "VLAN IDs");
#endif // BFO_VLAN == 1
#endif // (BFO_VLAN > 0 && BFO_MAX_VLAN > 0)

#if (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
#if BFO_MPLS == 4
    BV_APPEND_R(bv, "mplsLabel_ToS_S_TTL",
                "MPLS headers details",
                4, bt_uint_32, bt_uint_8, bt_uint_8, bt_uint_8);
#elif BFO_MPLS == 3
    BV_APPEND_H32_R(bv, "mplsHdrsHex", "MPLS headers (hex)");
#elif BFO_MPLS == 2
    BV_APPEND_H32_R(bv, "mplsLabelsHex", "MPLS labels (hex)");
#else // BFO_MPLS == 1
    BV_APPEND_U32_R(bv, "mplsLabels", "MPLS labels");
#endif // BFO_MPLS == 1
#endif // (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)

#if BFO_PPP == 1
    BV_APPEND_H32(bv, "pppHdr", "PPP header");
#endif

#if LAPD_ACTIVATE == 1 && BFO_LAPD == 1
    BV_APPEND_U8(bv, "lapdSAPI", "LAPD SAPI");
    BV_APPEND_U8(bv, "lapdTEI" , "LAPD TEI");
#endif // LAPD_ACTIVATE == 1 && BFO_LAPD == 1

#if ANONYM_IP == 0

#if BFO_L2TP == 1
    BV_APPEND_H16(bv, "l2tpHdr", "L2TP header");
    BV_APPEND_U16(bv, "l2tpTID", "L2TPv2 tunnel ID");
    BV_APPEND_U16(bv, "l2tpSID", "L2TPv2 session ID");
    BV_APPEND_U32(bv, "l2tpCCSID", "L2TPv3 control connection/session ID");

#if (AGGREGATIONFLAG & SUBNET) == 0
    BV_APPEND_IP4(bv, "l2tpSrcIP", "L2TP source IP address");
#endif

#if BFO_SUBNET_TEST_L2TP == 1
#if BFO_SUBNET_ASN == 1
    BV_APPEND_U32(bv, "l2tpSrcIPASN", "L2TP source ASN");
#endif // BFO_SUBNET_ASN == 1
#if BFO_SUBNET_HEX == 1
    BV_APPEND_H32(bv, "l2tpSrcIPCOC", "L2TP source IP country organization code");
#endif // BFO_SUBNET_HEX == 1
    BV_APPEND_STRC(bv, "l2tpSrcIPCC", "L2TP source IP country");
#if CNTYCTY == 1
    BV_APPEND_STR(bv, "l2tpSrcIPCnty", "L2TP source IP county");
    BV_APPEND_STR(bv, "l2tpSrcIPCity", "L2TP source IP city");
#endif // CNTYCTY == 1
#if BFO_SUBNET_ORG == 1
    BV_APPEND_STR(bv, "l2tpSrcIPOrg", "L2TP source IP organization");
#endif
#if BFO_SUBNET_LL == 1
    BV_APPEND(bv, "l2tpSrcIPLat_Lng_relP",
              "L2TP source IP latitude, longitude, reliability",
              3, bt_float, bt_float, bt_float);
#endif // BFO_SUBNET_LL == 1
#endif // BFO_SUBNET_TEST_L2TP == 1

#if (AGGREGATIONFLAG & SUBNET) == 0
    BV_APPEND_IP4(bv, "l2tpDstIP", "L2TP destination IP address");
#endif

#if BFO_SUBNET_TEST_L2TP == 1
#if BFO_SUBNET_ASN == 1
    BV_APPEND_U32(bv, "l2tpDstIPASN", "L2TP destination ASN");
#endif // BFO_SUBNET_ASN == 1
#if BFO_SUBNET_HEX == 1
    BV_APPEND_H32(bv, "l2tpDstIPCOC", "L2TP destination IP country organization code");
#endif // BFO_SUBNET_HEX == 1
    BV_APPEND_STRC(bv, "l2tpDstIPCC", "L2TP destination IP country");
#if CNTYCTY == 1
    BV_APPEND_STR(bv, "l2tpDstIPCnty", "L2TP destination IP county");
    BV_APPEND_STR(bv, "l2tpDstIPCity", "L2TP destination IP city");
#endif // CNTYCTY == 1
#if BFO_SUBNET_ORG == 1
    BV_APPEND_STR(bv, "l2tpDstIPOrg", "L2TP destination IP organization");
#endif
#if BFO_SUBNET_LL == 1
    BV_APPEND(bv, "l2tpDstIPLat_Lng_relP",
              "L2TP destination IP latitude, longitude, reliability",
              3, bt_float, bt_float, bt_float);
#endif // BFO_SUBNET_LL == 1
#endif // BFO_SUBNET_TEST_L2TP == 1

#endif // BFO_L2TP == 1

#if BFO_GRE == 1
    BV_APPEND_H32(bv, "greHdr", "GRE header");

#if (AGGREGATIONFLAG & SUBNET) == 0
    BV_APPEND_IP4(bv, "greSrcIP", "GRE source IP address");
#endif // (AGGREGATIONFLAG & SUBNET) == 0

#if BFO_SUBNET_TEST_GRE == 1
#if BFO_SUBNET_ASN == 1
    BV_APPEND_U32(bv, "greSrcIPASN", "GRE source ASN");
#endif // BFO_SUBNET_ASN == 1
#if BFO_SUBNET_HEX == 1
    BV_APPEND_H32(bv, "greSrcIPCOC", "GRE source IP country organization code");
#endif // BFO_SUBNET_HEX == 1
    BV_APPEND_STRC(bv, "greSrcIPCC", "GRE source IP country");
#if CNTYCTY == 1
    BV_APPEND_STR(bv, "greSrcIPCnty", "GRE source IP county");
    BV_APPEND_STR(bv, "greSrcIPCity", "GRE source IP city");
#endif // CNTYCTY == 1
#if BFO_SUBNET_ORG == 1
    BV_APPEND_STR(bv, "greSrcIPOrg", "GRE source IP organization");
#endif
#if BFO_SUBNET_LL == 1
    BV_APPEND(bv, "greSrcIPLat_Lng_relP",
              "GRE source IP latitude, longitude, reliability",
              3, bt_float, bt_float, bt_float);
#endif // BFO_SUBNET_LL == 1
#endif // BFO_SUBNET_TEST_GRE == 1

#if (AGGREGATIONFLAG & SUBNET) == 0
    BV_APPEND_IP4(bv, "greDstIP", "GRE destination IP address");
#endif // (AGGREGATIONFLAG & SUBNET) == 0

#if BFO_SUBNET_TEST_GRE == 1
#if BFO_SUBNET_ASN == 1
    BV_APPEND_U32(bv, "greDstIPASN", "GRE destination ASN");
#endif // BFO_SUBNET_ASN == 1
#if BFO_SUBNET_HEX == 1
    BV_APPEND_H32(bv, "greDstIPCOC", "GRE destination IP country organization code");
#endif // BFO_SUBNET_HEX == 1
    BV_APPEND_STRC(bv, "greDstIPCC", "GRE destination IP country");
#if CNTYCTY == 1
    BV_APPEND_STR(bv, "greDstIPCnty", "GRE destination IP county");
    BV_APPEND_STR(bv, "greDstIPCity", "GRE destination IP city");
#endif // CNTYCTY == 1
#if BFO_SUBNET_ORG == 1
    BV_APPEND_STR(bv, "greDstIPOrg", "GRE destination IP organization");
#endif
#if BFO_SUBNET_LL == 1
    BV_APPEND(bv, "greDstIPLat_Lng_relP",
              "GRE destination IP latitude, longitude, reliability",
              3, bt_float, bt_float, bt_float);
#endif // BFO_SUBNET_LL == 1
#endif // BFO_SUBNET_TEST_GRE == 1

#endif // BFO_GRE == 1

#if BFO_TEREDO == 1
#if (AGGREGATIONFLAG & SUBNET) == 0
    BV_APPEND_IP4(bv, "trdoDstIP", "Teredo IPv4 address");
#endif // (AGGREGATIONFLAG & SUBNET) == 0
#if BFO_SUBNET_TEST_TEREDO == 1
#if BFO_SUBNET_ASN == 1
    BV_APPEND_U32(bv, "trdoDstIPASN", "Teredo IPv4 ASN");
#endif // BFO_SUBNET_ASN == 1
#if BFO_SUBNET_HEX == 1
    BV_APPEND_H32(bv, "trdoDstIPCOC", "Teredo IPv4 country organization code");
#endif // BFO_SUBNET_HEX == 1
    BV_APPEND_STRC(bv, "trdoDstIPCC", "Teredo IPv4 country");
#if CNTYCTY == 1
    BV_APPEND_STR(bv, "trdoDstIPCnty", "Teredo IPv4 county");
    BV_APPEND_STR(bv, "trdoDstIPCity", "Teredo IPv4 city");
#endif // CNTYCTY == 1
#if BFO_SUBNET_ORG == 1
    BV_APPEND_STR(bv, "trdoDstIPOrg", "Teredo IPv4 organization");
#endif
#if BFO_SUBNET_LL == 1
    BV_APPEND(bv, "trdoDstIPLat_Lng_relP",
              "Teredo IPv4 latitude, longitude, reliability",
              3, bt_float, bt_float, bt_float);
#endif // BFO_SUBNET_LL == 1
#endif // BFO_SUBNET_TEST_TEREDO == 1
    BV_APPEND_U16(bv, "trdoDstPort", "Teredo destination port");
#if IPV6_ACTIVATE > 0
    BV_APPEND_H8(bv, "trdo6SrcFlgs", "Teredo IPv6 source address decode: Flags");
    BV_APPEND_IP4(bv, "trdo6SrcSrvIP4", "Teredo IPv6 source address decode: Server IPv4");
#if BFO_SUBNET_TEST_TEREDO == 1
#if BFO_SUBNET_ASN == 1
    BV_APPEND_U32(bv, "trdo6SrcSrvIP4ASN", "Teredo IPv6 source address decode: Server IPv4 ASN");
#endif // BFO_SUBNET_ASN == 1
#if BFO_SUBNET_HEX == 1
    BV_APPEND_H32(bv, "trdo6SrcSrvIP4COC", "Teredo IPv6 source address decode: Server IPv4 country organization code");
#endif // BFO_SUBNET_HEX == 1
    BV_APPEND_STRC(bv, "trdo6SrcSrvIP4CC", "Teredo IPv6 source address decode: Server IPv4 country");
#if CNTYCTY == 1
    BV_APPEND_STR(bv, "trdo6SrcSrvIP4Cnty", "Teredo IPv6 source address decode: Server IPv4 county");
    BV_APPEND_STR(bv, "trdo6SrcSrvIP4City", "Teredo IPv6 source address decode: Server IPv4 city");
#endif // CNTYCTY == 1
#if BFO_SUBNET_ORG == 1
    BV_APPEND_STR(bv, "trdo6SrcSrvIP4Org", "Teredo IPv6 source address decode: Server IPv4 organization");
#endif
#if BFO_SUBNET_LL == 1
    BV_APPEND(bv, "trdo6SrcSrvIP4Lat_Lng_relP",
              "Teredo IPv6 source address decode: Server IPv4 latitude, longitude, reliability",
              3, bt_float, bt_float, bt_float);
#endif // BFO_SUBNET_LL == 1
#endif // BFO_SUBNET_TEST_TEREDO == 1
#if (AGGREGATIONFLAG & SUBNET) == 0
    BV_APPEND_IP4(bv, "trdo6SrcCPIP4", "Teredo IPv6 source address decode: Client public IPv4");
#endif // (AGGREGATIONFLAG & SUBNET) == 0
#if BFO_SUBNET_TEST_TEREDO == 1
#if BFO_SUBNET_ASN == 1
    BV_APPEND_U32(bv, "trdo6SrcCPIP4ASN", "Teredo IPv6 source address decode: Client public IPv4 ASN");
#endif // BFO_SUBNET_ASN == 1
#if BFO_SUBNET_HEX == 1
    BV_APPEND_H32(bv, "trdo6SrcCPIP4COC", "Teredo IPv6 source address decode: Client public IPv4 country organization code");
#endif // BFO_SUBNET_HEX == 1
    BV_APPEND_STRC(bv, "trdo6SrcCPIP4CC", "Teredo IPv6 source address decode: Client public IPv4 country");
#if CNTYCTY == 1
    BV_APPEND_STR(bv, "trdo6SrcCPIP4Cnty", "Teredo IPv6 source address decode: Client public IPv4 county");
    BV_APPEND_STR(bv, "trdo6SrcCPIP4City", "Teredo IPv6 source address decode: Client public IPv4 city");
#endif // CNTYCTY == 1
#if BFO_SUBNET_ORG == 1
    BV_APPEND_STR(bv, "trdo6SrcCPIP4Org", "Teredo IPv6 source address decode: Client public IPv4 organization");
#endif
#if BFO_SUBNET_LL == 1
    BV_APPEND(bv, "trdo6SrcCPIP4Lat_Lng_relP",
              "Teredo IPv6 source address decode: Client public IPv4 latitude, longitude, reliability",
              3, bt_float, bt_float, bt_float);
#endif // BFO_SUBNET_LL == 1
#endif // BFO_SUBNET_TEST_TEREDO == 1
    BV_APPEND_U16(bv, "trdo6SrcCPPort", "Teredo IPv6 source address decode: Client public port");

    BV_APPEND_H8(bv, "trdo6DstFlgs", "Teredo IPv6 destination address decode: Flags");
    BV_APPEND_IP4(bv, "trdo6DstSrvIP4", "Teredo IPv6 destination address decode: Server IPv4");
#if BFO_SUBNET_TEST_TEREDO == 1
#if BFO_SUBNET_ASN == 1
    BV_APPEND_U32(bv, "trdo6DstSrvIP4ASN", "Teredo IPv6 destination address decode: Server IPv4 ASN");
#endif // BFO_SUBNET_ASN == 1
#if BFO_SUBNET_HEX == 1
    BV_APPEND_H32(bv, "trdo6DstSrvIP4COC", "Teredo IPv6 destination address decode: Server IPv4 country organization code");
#endif // BFO_SUBNET_HEX == 1
    BV_APPEND_STRC(bv, "trdo6DstSrvIP4CC", "Teredo IPv6 destination address decode: Server IPv4 country");
#if CNTYCTY == 1
    BV_APPEND_STR(bv, "trdo6DstSrvIP4Cnty", "Teredo IPv6 destination address decode: Server IPv4 county");
    BV_APPEND_STR(bv, "trdo6DstSrvIP4City", "Teredo IPv6 destination address decode: Server IPv4 city");
#endif // CNTYCTY == 1
#if BFO_SUBNET_ORG == 1
    BV_APPEND_STR(bv, "trdo6DstSrvIP4Org", "Teredo IPv6 destination address decode: Server IPv4 organization");
#endif
#if BFO_SUBNET_LL == 1
    BV_APPEND(bv, "trdo6DstSrvIP4Lat_Lng_relP",
              "Teredo IPv6 destination address decode: Server IPv4 latitude, longitude, reliability",
              3, bt_float, bt_float, bt_float);
#endif // BFO_SUBNET_LL == 1
#endif // BFO_SUBNET_TEST_TEREDO == 1
    BV_APPEND_IP4(bv, "trdo6DstCPIP4", "Teredo IPv6 destination address decode: Client public IPv4");
#if BFO_SUBNET_TEST_TEREDO == 1
#if BFO_SUBNET_ASN == 1
    BV_APPEND_U32(bv, "trdo6DstCPIP4ASN", "Teredo IPv6 destination address decode: Client public IPv4 ASN");
#endif // BFO_SUBNET_ASN == 1
#if BFO_SUBNET_HEX == 1
    BV_APPEND_H32(bv, "trdo6DstCPIP4COC", "Teredo IPv6 destination address decode: Client public IPv4 country organization code");
#endif // BFO_SUBNET_HEX == 1
    BV_APPEND_STRC(bv, "trdo6DstCPIP4CC", "Teredo IPv6 destination address decode: Client public IPv4 country");
#if CNTYCTY == 1
    BV_APPEND_STR(bv, "trdo6DstCPIP4Cnty", "Teredo IPv6 destination address decode: Server IPv4 county");
    BV_APPEND_STR(bv, "trdo6DstCPIP4City", "Teredo IPv6 destination address decode: Server IPv4 city");
#endif // CNTYCTY == 1
#if BFO_SUBNET_ORG == 1
    BV_APPEND_STR(bv, "trdo6DstCPIP4Org", "Teredo IPv6 destination address decode: Client public IPv4 organization");
#endif // BFO_SUBNET_ORG == 1
#if BFO_SUBNET_LL == 1
    BV_APPEND(bv, "trdo6DstCPIP4Lat_Lng_relP",
              "Teredo IPv6 destination address decode: Client public IPv4 latitude, longitude, reliability",
              3, bt_float, bt_float, bt_float);
#endif // BFO_SUBNET_LL == 1
#endif // BFO_SUBNET_TEST_TEREDO == 1
    BV_APPEND_U16(bv, "trdo6DstCPPort", "Teredo IPv6 destination address decode: Client public port");
#endif // IPV6_ACTIVATE > 0
#endif // BFO_TEREDO == 1

#if BFO_SUBNET_IPLIST == 1
    BV_APPEND_R(bv, "srcIP", "Source IP addresses", 1, BFO_IP_TYPE);
#else // BFO_SUBNET_IPLIST == 0
    BV_APPEND(  bv, "srcIP", "Source IP address", 1, BFO_IP_TYPE);
#endif // BFO_SUBNET_IPLIST

#if BFO_SUBNET_TEST == 1
#if BFO_SUBNET_ASN == 1
    BV_APPEND_U32( bv, "srcIPASN", "Source ASN");
#endif // BFO_SUBNET_ASN == 1
#if BFO_SUBNET_HEX == 1
    BV_APPEND_H32( bv, "srcIPCOC", "Source IP country organization code");
#endif // BFO_SUBNET_HEX == 1
    BV_APPEND_STRC(bv, "srcIPCC", "Source IP country");
#if CNTYCTY == 1
    BV_APPEND_STR( bv, "srcIPCnty", "Source IP county");
    BV_APPEND_STR( bv, "srcIPCity", "Source IP city");
#endif // CNTYCTY == 1
#if BFO_SUBNET_ORG == 1
    BV_APPEND_STR( bv, "srcIPOrg", "Source IP organization");
#endif // BFO_SUBNET_ORG == 1
#if BFO_SUBNET_LL == 1
    BV_APPEND(bv, "srcIPLat_Lng_relP",
              "Source IP latitude, longitude, reliability",
              3, bt_float, bt_float, bt_float);
#endif // BFO_SUBNET_LL == 1
#endif // BFO_SUBNET_TEST == 1

#endif // ANONYM_IP == 0

    BV_APPEND_U16(bv, "srcPort", "Source port");

#if ANONYM_IP == 0

#if BFO_SUBNET_IPLIST == 1
    BV_APPEND_R(bv, "dstIP", "Destination IP addresses", 1, BFO_IP_TYPE);
#else // BFO_SUBNET_IPLIST == 0
    BV_APPEND(  bv, "dstIP", "Destination IP address", 1, BFO_IP_TYPE);
#endif // BFO_SUBNET_IPLIST

#if BFO_SUBNET_TEST == 1
#if BFO_SUBNET_ASN == 1
    BV_APPEND_U32( bv, "dstIPASN" , "Destination ASN");
#endif // BFO_SUBNET_ASN == 1
#if BFO_SUBNET_HEX == 1
    BV_APPEND_H32( bv, "dstIPCOC" , "Destination IP country organization code");
#endif // BFO_SUBNET_HEX == 1
    BV_APPEND_STRC(bv, "dstIPCC"  , "Destination IP country");
#if CNTYCTY == 1
    BV_APPEND_STR( bv, "dstIPCnty", "Destination IP county");
    BV_APPEND_STR( bv, "dstIPCity" , "Destination IP city");
#endif // CNTYCTY == 1
#if BFO_SUBNET_ORG == 1
    BV_APPEND_STR( bv, "dstIPOrg" , "Destination IP organization");
#endif
#if BFO_SUBNET_LL == 1
    BV_APPEND(bv, "dstIPLat_Lng_relP",
              "Destination IP latitude, longitude, reliability",
              3, bt_float, bt_float, bt_float);
#endif // BFO_SUBNET_LL == 1
#endif // BFO_SUBNET_TEST == 1

#endif // ANONYM_IP == 0

    BV_APPEND_U16(bv, "dstPort", "Destination port");
    BV_APPEND_U8( bv, "l4Proto", "Layer 4 protocol");

    return bv;
}


#if (BFO_VLAN > 0 && BFO_MAX_VLAN > 0) || (BFO_MPLS > 0 && BFO_MAX_MPLS > 0) || \
     BFO_PPP == 1 || BFO_L2TP == 1 || BFO_GRE == 1 || BFO_TEREDO == 1
void t2OnNewFlow(packet_t* packet, unsigned long flowIndex) {
#else
void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
#endif

    bfoFlow_t * const bfoFlowP = &bfoFlow[flowIndex];
    memset(bfoFlowP, '\0', sizeof(bfoFlow_t));

    flow_t * const flowP = &flows[flowIndex];
    bfoFlowP->lastPktTime = flowP->lastSeen;

#if (BFO_VLAN > 0 && BFO_MAX_VLAN > 0)
    // TODO warn if bfoFlowP->vlans is not large enough to store all the vlans
    // alternatively output num_vlans
    if ((packet->status & L2_VLAN) && packet->vlanHdrP) {
        uint32_t * const vlans = bfoFlowP->vlans;
        uint32_t i = 0;
        uint16_t ethType;
        do {
            vlans[i] = ntohl(packet->vlanHdrP[i]);
            ethType = (vlans[i] & VLAN_ETYPE_MASK32);
            i++;
        } while (i < BFO_MAX_VLAN && ETHERTYPE_IS_VLAN(ethType));
        bfoFlowP->num_vlans = i;
    }
#endif // (BFO_VLAN > 0 && BFO_MAX_VLAN > 0)

#if (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
    // TODO warn if bfoFlowP->mplsHdr is not large enough to store all the tags
    // alternatively output num_mpls
    if (packet->status & L2_MPLS) {
        uint32_t i = 0;
        do {
            bfoFlowP->mplsHdr[i] = ntohl(packet->mplsHdrP[i]);
            i++;
        } while (i < BFO_MAX_MPLS && !(packet->mplsHdrP[i-1] & BTM_MPLS_STKn32));
        bfoFlowP->num_mpls = i;
    }
#endif // (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)

#if BFO_PPP == 1
    if ((packet->status & L2_PPP) && packet->pppHdrP) {
        bfoFlowP->pppHdr = (pppHu_t)ntohl(packet->pppHdrP->pppHdrc);
    }
#endif // BFO_PPP == 1

#if LAPD_ACTIVATE == 1 && BFO_LAPD == 1
    if (flowP->status & LAPD_FLOW) {
        const lapdHdr_t * const lapdHdrP = (lapdHdr_t*)packet->l2HdrP;
        bfoFlowP->lapdSAPI = lapdHdrP->mdsapi;
        bfoFlowP->lapdTEI = lapdHdrP->atei;
    }
#endif // LAPD_ACTIVATE == 1 && BFO_LAPD == 1

#if BFO_L2TP == 1
    if ((packet->status & L2_L2TP) && packet->l2tpL3HdrP) {
        const ipHeader_t * const ipHdrP = (ipHeader_t*)packet->l2tpL3HdrP;
        bfoFlowP->l2tp_srcIP = ipHdrP->ip_src;
        bfoFlowP->l2tp_dstIP = ipHdrP->ip_dst;
        bfoFlowP->l2tpHdrBF = ntohs(*(uint16_t*)packet->l2tpHdrP);
        const uint_fast8_t i = (bfoFlowP->l2tpHdrBF & L2TP_LEN) ? 1 : 0;
        const uint16_t * const l2tpHdrP = packet->l2tpHdrP;
        if (packet->l3Proto == L2TP_V3) {
            bfoFlowP->l2tpv3HdrccID = ntohl(*(uint32_t*)(l2tpHdrP+i+2));
        } else {
            bfoFlowP->l2tpHdrTID = ntohs(*(l2tpHdrP+i+1));
            bfoFlowP->l2tpHdrSID = ntohs(*(l2tpHdrP+i+2));
        }
    }
#endif // BFO_L2TP == 1

#if BFO_GRE == 1
    if (packet->status & L2_GRE && packet->greL3HdrP) {
        bfoFlowP->greHdrBF = *(uint32_t*)packet->greHdrP;
        const ipHeader_t * const ipHdrP = (ipHeader_t*)packet->greL3HdrP;
        bfoFlowP->gre_srcIP = ipHdrP->ip_src;
        bfoFlowP->gre_dstIP = ipHdrP->ip_dst;
    }
#endif // BFO_GRE == 1

#if BFO_TEREDO == 1
    if (packet->status & L3_TRDO && packet->trdoOIHdrP) {
        const uint8_t * const teredo = packet->trdoOIHdrP;
        bfoFlowP->trdoPort = ntohs((*(uint16_t*)(teredo+2)) ^ 0xffff);
        bfoFlowP->trdoIP = (*(uint32_t*)(teredo+4)) ^ 0xffffffff;
    }
#endif // BFO_TEREDO == 1
}


#if (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)
static inline void bfo_copy_hdrDesc(packet_t *packet, unsigned long flowIndex) {
    bfoFlow_t * const bfoFlowP = &bfoFlow[flowIndex];

    if (bfoFlowP->hDCnt >= BFO_MAX_HDRDESC) { // New header description
        flows[flowIndex].status |= HDOVRN;
        return;
    }

    uint_fast8_t i = 0;
    for (i = 0; i < bfoFlowP->hDCnt; i++) {
        if (strcmp(bfoFlowP->hdrDesc[i], packet->hdrDesc) == 0) {
            bfoFlowP->hdrCnt[i] = packet->numHdrDesc;
            bfoFlowP->pktCnt[i]++;
            return;
        }
    }

    if (i == bfoFlowP->hDCnt) {
        memcpy(bfoFlowP->hdrDesc[i], packet->hdrDesc, strlen(packet->hdrDesc));
        bfoFlowP->hdrCnt[i] = packet->numHdrDesc;
        bfoFlowP->pktCnt[i]++;
        bfoFlowP->hDCnt = ++i;
    }

}
#endif // (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    claimInfo(packet, flowIndex);
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    claimInfo(packet, flowIndex);
}


static inline void claimInfo(packet_t *packet, unsigned long flowIndex) {
#if (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)
    bfo_copy_hdrDesc(packet, flowIndex);
#endif // (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)

    flow_t * const flowP = &flows[flowIndex];
    bfoFlow_t * const bfoFlowP = &bfoFlow[flowIndex];
    const uint8_t * const l2HdrP = (uint8_t*)packet->l2HdrP;

#if (BFO_MAC == 1 && BFO_MAX_MAC > 0)
    if (l2HdrP && !(flowP->status & (L2_NO_ETH | LAPD_FLOW))) {
        const ethernetHeader_t * const ethHdrP = (ethernetHeader_t*)l2HdrP;
        if (bfoFlowP->num_srcMac >= BFO_MAX_MAC) {
            // TODO warn if bfoFlowP->num_srcMac is not large enough to store all the addresses
            // alternatively output num_srcMac
        } else {
            uint_fast32_t i;
            const uint8_t * const srcMac = &ethHdrP->ethDS.ether_shost[0];
            for (i = 0; i < bfoFlowP->num_srcMac; i++) {
                if (memcmp(bfoFlowP->srcMac[i], srcMac, ETH_ALEN) == 0) break;
            }

            if (i == bfoFlowP->num_srcMac) {
                memcpy(&bfoFlowP->srcMac[i][0], srcMac, ETH_ALEN);
                bfoFlowP->num_srcMac++;
            }
        }

        if (bfoFlowP->num_dstMac >= BFO_MAX_MAC) {
            // TODO warn if bfoFlowP->num_dstMac is not large enough to store all the addresses
            // alternatively output num_dstMac
        } else {
            uint_fast32_t i;
            const uint8_t * const dstMac = &ethHdrP->ethDS.ether_dhost[0];
            for (i = 0; i < bfoFlowP->num_dstMac; i++) {
                if (memcmp(&bfoFlowP->dstMac[i][0], dstMac, ETH_ALEN) == 0) break;
            }

            if (i == bfoFlowP->num_dstMac) {
                memcpy(&bfoFlowP->dstMac[i][0], dstMac, ETH_ALEN);
                bfoFlowP->num_dstMac++;
            }
        }
    }
#endif // (BFO_MAC == 1 && BFO_MAX_MAC > 0)

#if BFO_SUBNET_IPLIST == 1
    const uint_fast8_t ipver = PACKET_IPVER(packet);
    if (packet->l3HdrP && ipver) {
#if IPV6_ACTIVATE > 0
        const ipAddr_t ip[2] = {
#else // IPV6_ACTIVATE == 0
        const ip4Addr_t ip[2] = {
#endif
            packet->srcIPC,
            packet->dstIPC
        };
        uint_fast32_t i, j;
        for (j = 0; j <= 1; j++) {
            if (bfoFlowP->ipCnt[j] >= BFO_MAX_IP) {
                bfoFlowP->ipCnt[j] = BFO_MAX_IP;
                continue;
            }

            for (i = 0; i < bfoFlowP->ipCnt[j]; i++) {
                if (T2_CMP_FLOW_IP(bfoFlowP->ip[j][i], ip[j], ipver)) goto nxtip;
            }

            bfoFlowP->ip[j][i] = ip[j];
            bfoFlowP->ipCnt[j]++;
nxtip:
            continue;
        }
    }
#endif // BFO_SUBNET_IPLIST == 1

    if (!sPktFile) return;

    const double flwDur = (uint32_t)flowP->lastSeen.tv_sec - (uint32_t)flowP->firstSeen.tv_sec + (flowP->lastSeen.tv_usec - flowP->firstSeen.tv_usec) / TSTAMPFAC;
    const double pktInterDis = (uint32_t)flowP->lastSeen.tv_sec - (uint32_t)bfoFlowP->lastPktTime.tv_sec + (flowP->lastSeen.tv_usec - bfoFlowP->lastPktTime.tv_usec) / TSTAMPFAC;

    double pktTripDis = 0;
    if (FLOW_HAS_OPPOSITE(flowP)) {
        const flow_t * const revFlowP = &flows[flowP->oppositeFlowIndex];
        pktTripDis = flowP->lastSeen.tv_sec - revFlowP->lastSeen.tv_sec + ((float)flowP->lastSeen.tv_usec - (float)revFlowP->lastSeen.tv_usec) / TSTAMPFAC;
    }

    if (pktInterDis < 0) {
        globalWarn |= TIMEJUMP;
        flowP->status |= TIMEJUMP;
    }

    bfoFlowP->lastPktTime = flowP->lastSeen;

#if RELTIME == 1
    struct timeval relTime;
    const struct timeval lastSeen = flowP->lastSeen;
    T2_TIMERSUB(&lastSeen, &startTStamp, &relTime);
#endif // RELTIME == 1

    fprintf(sPktFile, "0x%016" B2T_PRIX64 /* flowStat */ SEP_CHR, flowP->status);

#if B2T_TIMESTR == 1 || RELTIME == 0
    const intmax_t usec = flowP->lastSeen.tv_usec;
#else // B2T_TIMESTR == 0 && RELTIME == 1
    const intmax_t usec = relTime.tv_usec;
#endif // RELTIME == 0 && B2T_TIMESTR == 0

#if B2T_TIMESTR == 1
    // Human readable date
    const struct tm *t;
    const time_t sec = (uint32_t)flowP->lastSeen.tv_sec;

#if TSTAMP_UTC == 1
    t = gmtime(&sec);
#else // TSTAMP_UTC == 0
    t = localtime(&sec);
#endif // TSTAMP_UTC == 0
    char timeBuf[20];
    strftime(timeBuf, sizeof(timeBuf), "%FT%T", t);
    char timeOff[6];
#if TSTAMP_UTC == 1 && defined(__APPLE__)
    memcpy(timeOff, "+0000", 5);
#else // TSTAMP_UTC == 0 || !defined(__APPLE__)
    strftime(timeOff, sizeof(timeOff), "%z", t);
#endif // TSTAMP_UTC == 0 || !defined(__APPLE__)
    fprintf(sPktFile, "%s.%" T2_PRI_USEC "%s"      /* time/relTime                  */ SEP_CHR
#else // B2T_TIMESTR == 0
    fprintf(sPktFile, "%" PRIu32 ".%" T2_PRI_USEC  /* time/relTime (Unix timestamp) */ SEP_CHR
#endif // B2T_TIMESTR
                      "%." T2_USEC_PREC "f"        /* pktIAT                        */ SEP_CHR
                      "%." T2_USEC_PREC "f"        /* pktTrip                       */ SEP_CHR
                      "%." T2_USEC_PREC "f"        /* flowDuration                  */ SEP_CHR
#if B2T_TIMESTR == 1
                      , timeBuf, usec, timeOff
#else // B2T_TIMESTR == 0
                      , (uint32_t)flowP->lastSeen.tv_sec, usec
#endif // B2T_TIMESTR
                      , pktInterDis
                      , pktTripDis
                      , flwDur);

#if T2_PRI_HDRDESC == 1
    fprintf(sPktFile,
            "%" PRIu16 /* numHdrs */ SEP_CHR
            "%s"       /* hdrDesc */ SEP_CHR
            , packet->numHdrDesc
            , packet->hdrDesc);
#endif // T2_PRI_HDRDESC == 1

     // vlanID/vlanHdr/vlanTPID_PCP_DEI_VID
#if BFO_VLAN > 0
    if (packet->status & L2_VLAN) {
        const uint32_t * const vlans = bfoFlowP->vlans;
        for (uint_fast32_t i = 0; i < bfoFlowP->num_vlans; i++) {
            if (i) fputc(';', sPktFile);
#if BFO_VLAN == 3
            // vlanTPID_PCP_DEI_VID
            fprintf(sPktFile, "%04" PRIx16 "_%" PRIu8 "_%" PRIu8 "_%" PRIu16
                    , (vlans[i] & VLAN_ETYPE_MASK32)
                    , (vlans[i] >> 13) & 0x07
                    , (vlans[i] >> 12) & 0x01
                    , (vlans[i] >> 16));
#elif BFO_VLAN == 2
            fprintf(sPktFile, "%08" PRIx32, vlans[i]);      // vlanHdr
#else // BFO_VLAN == 1
            fprintf(sPktFile, "%" PRIu16, vlans[i] >> 16);  // vlanID
#endif // BFO_VLAN
        }
    }
    fputs(/* vlanTPID_PCP_DEI_VID/vlanHdr/vlanID */ SEP_CHR, sPktFile);
#endif // BFO_VLAN > 0

#if (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
    // mplsLabels/mplsLabelsHex/mplsHdrsHex/mplsLabel_ToS_S_TTL
    if (packet->status & L2_MPLS) {
        uint32_t i = 0;
        do {
            if (i > 0) fputc(';', sPktFile);
#if BFO_MPLS == 4
            // mplsLabel_ToS_S_TTL
            const uint32_t mpls = ntohl(packet->mplsHdrP[i]);
            fprintf(sPktFile, "%" PRIu32 "_%" PRIu8 "_%" PRIu8 "_%" PRIu8,
                    MPLS_LABEL(mpls), MPLS_EXP(mpls), MPLS_BOTTOM(mpls), MPLS_TTL(mpls));
#elif BFO_MPLS == 3
            fprintf(sPktFile, "0x%08" B2T_PRIX32, ntohl(packet->mplsHdrP[i]));         // mplsHdrsHex
#elif BFO_MPLS == 2
            fprintf(sPktFile, "0x%08" B2T_PRIX32, MPLS_LABEL_N(packet->mplsHdrP[i]));  // mplsLabelsHex
#else // BFO_MPLS == 1
            fprintf(sPktFile, "%" PRIu32, MPLS_LABEL_N(packet->mplsHdrP[i]));          // mplsLabels
#endif // BFO_MPLS == 1
            i++;
        } while (i < BFO_MAX_MPLS && !(packet->mplsHdrP[i-1] & BTM_MPLS_STKn32));
    }
    fputs(/* mplsLabels/mplsLabelsHex/mplsHdrsHex/mplsLabel_ToS_S_TTL */ SEP_CHR, sPktFile);
#endif // (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)

    // srcMac, dstMac, ethType
    char srcMac[T2_MAC_STRLEN+1] = {}, dstMac[T2_MAC_STRLEN+1] = {};
    if (packet->l2HdrP && !(flowP->status & (L2_NO_ETH | LAPD_FLOW))) {
        t2_mac_to_str(&l2HdrP[6], srcMac, sizeof(srcMac));
        t2_mac_to_str(&l2HdrP[0], dstMac, sizeof(dstMac));
    }

    fprintf(sPktFile,
            "%s"               /* srcMac  */ SEP_CHR
            "%s"               /* dstMac  */ SEP_CHR
            "0x%04" B2T_PRIX16 /* ethType */ SEP_CHR
            , srcMac, dstMac, packet->ethType);

#if LAPD_ACTIVATE == 1 && BFO_LAPD == 1
    if (flowP->status & LAPD_FLOW) {
        const lapdHdr_t * const lapdHdrP = (lapdHdr_t*)l2HdrP;
        fprintf(sPktFile,
                "%" PRIu8 /* lapdSAPI */ SEP_CHR
                "%" PRIu8 /* lapdTEI  */ SEP_CHR
                , lapdHdrP->mdsapi, lapdHdrP->atei);
        const uint8_t ftype = (lapdHdrP->cf1 & 0x03);
        if (!(ftype & 0x01)) { // Information frame
            const uint8_t nr = ((lapdHdrP->cf & 0xfe00) >> 9);
            const uint8_t ns = ((lapdHdrP->cf & 0x00fe) >> 1);
            fprintf(sPktFile,
                    "0"       /* lapdFType */ SEP_CHR
                              /* lapdFunc  */ SEP_CHR
                    "%" PRIu8 /* lapdNR    */ SEP_CHR
                    "%" PRIu8 /* lapdNS    */ SEP_CHR
                    , nr, ns);
        } else if (ftype == 1) { // Supervisory frame
            const uint8_t nr = ((lapdHdrP->cf & 0xfe00) >> 9);
            const char *func;
            switch ((lapdHdrP->cf1 & 0x0c) >> 2) {
                case 0x00: func = "RR"; break;
                case 0x01: func = "RNR"; break;
                case 0x02: func = "REJ"; break;
                default: func = ""; break;
            }
            fprintf(sPktFile,
                    "%" PRIu8 /* lapdFType */ SEP_CHR
                    "%s"      /* lapdFunc  */ SEP_CHR
                    "%u"      /* lapdNR    */ SEP_CHR
                              /* lapdNS    */ SEP_CHR
                    , ftype, func, nr);
        } else if (ftype == 3) { // Unnumbered frame
            const char *func;
            switch ((lapdHdrP->cf1 & 0x0c) >> 2) {
                case 0x00:
                    switch (lapdHdrP->cf1 & 0xe0) {
                        case 0x00: func = "UI"; break;
                        case 0x20: func = "UP"; break;
                        case 0x40: func = "DISC"; break;
                        case 0x60: func = "UA"; break;
                        case 0xe0: func = "TEST"; break;
                        default: func = ""; break;
                    }
                    break;
                case 0x01:
                    switch (lapdHdrP->cf1 & 0xe0) {
                        case 0x00: func = "SIM"; break;
                        case 0x80: func = "FRMR"; break;
                        case 0xc0: func = "CFGR"; break;
                        default: func = ""; break;
                    }
                    break;
                case 0x03:
                    switch (lapdHdrP->cf1 & 0xe0) {
                        case 0x00: func = "DM"; break;
                        case 0x30: func = "SABME"; break;
                        case 0x50: func = "XID"; break;
                        default: func = ""; break;
                    }
                    break;
                default:
                    func = "";
                    break;
            }
            fprintf(sPktFile,
                    "%" PRIu8 /* lapdFType */ SEP_CHR
                    "%s"      /* lapdFunc  */ SEP_CHR
                              /* lapdNR    */ SEP_CHR
                              /* lapdNS    */ SEP_CHR
                    , ftype, func);
        } else {
            fprintf(sPktFile,
                    "%" PRIu8 /* lapdFType */ SEP_CHR
                              /* lapdFunc  */ SEP_CHR
                              /* lapdNR    */ SEP_CHR
                              /* lapdNS    */ SEP_CHR
                              , ftype);
        }
    } else {
        // Not LAPD, just print empty fields
        fputs(/* lapdSAPI  */ SEP_CHR
              /* lapdTEI   */ SEP_CHR
              /* lapdFType */ SEP_CHR
              /* lapdFunc  */ SEP_CHR
              /* lapdNR    */ SEP_CHR
              /* lapdNS    */ SEP_CHR
              , sPktFile);
    }
#endif // LAPD_ACTIVATE == 1 && BFO_LAPD == 1

    if (!packet->l3HdrP) {
#if ANONYM_IP == 1
        fputs(/* srcPort */ SEP_CHR
              /* dstPort */ SEP_CHR
              /* l4Proto */ SEP_CHR
              , sPktFile);
#elif BFO_SUBNET_TEST == 0
        fputs(/* srcIP   */ SEP_CHR
              /* srcPort */ SEP_CHR
              /* dstIP   */ SEP_CHR
              /* dstPort */ SEP_CHR
              /* l4Proto */ SEP_CHR
              , sPktFile);
#else // BFO_SUBNET_TEST == 1
        fputs(/* srcIP   */ SEP_CHR
              /* srcIPCC */ SEP_CHR
              , sPktFile);
#if BFO_SUBNET_ORG == 1
        fputs(/* srcIPOrg */ SEP_CHR, sPktFile);
#endif // BFO_SUBNET_ORG == 1
        fputs(/* srcPort */ SEP_CHR
              /* dstIP   */ SEP_CHR
              /* dstIPCC */ SEP_CHR
              , sPktFile);
#if BFO_SUBNET_ORG == 1
        fputs(/* dstIPOrg */ SEP_CHR, sPktFile);
#endif // BFO_SUBNET_ORG == 1
        fputs(/* dstPort */ SEP_CHR
              /* l4Proto */ SEP_CHR
              , sPktFile);
#endif // BFO_SUBNET_TEST == 1
    } else {
        const uint_fast8_t ipver = FLOW_IPVER(flowP);

        char srcIP[INET6_ADDRSTRLEN], dstIP[INET6_ADDRSTRLEN];

#if (AGGREGATIONFLAG & (SUBNET | SRCIP | DSTIP))
        T2_IP_TO_STR(packet->srcIPC, ipver, srcIP, INET6_ADDRSTRLEN);
        T2_IP_TO_STR(packet->dstIPC, ipver, dstIP, INET6_ADDRSTRLEN);
        const uint_fast8_t proto = packet->l4ProtoC;
        const uint16_t srcPort = packet->srcPortC;
        const uint16_t dstPort = packet->dstPortC;
#else // (AGGREGATIONFLAG & SUBNET) == 0
        T2_IP_TO_STR(flowP->srcIP, ipver, srcIP, INET6_ADDRSTRLEN);
        T2_IP_TO_STR(flowP->dstIP, ipver, dstIP, INET6_ADDRSTRLEN);
        const uint_fast8_t proto = packet->l4Proto;
        const uint16_t srcPort = packet->srcPort;
        const uint16_t dstPort = packet->dstPort;
#endif // (AGGREGATIONFLAG & SUBNET)

#if ANONYM_IP == 0
#if BFO_SUBNET_TEST == 1
#if BFO_SUBNET_ORG == 1
        char *srcOrg, *dstOrg;
        SUBNET_ORG(srcOrg, ipver, flowP->subnetNrSrc);
        SUBNET_ORG(dstOrg, ipver, flowP->subnetNrDst);
#endif // BFO_SUBNET_ORG == 1
        char *srcLoc, *dstLoc;
        SUBNET_LOC(srcLoc, ipver, flowP->subnetNrSrc);
        SUBNET_LOC(dstLoc, ipver, flowP->subnetNrDst);
#endif // BFO_SUBNET_TEST == 1
#endif // ANONYM_IP == 0

        const bool hasPorts = (proto == L3_TCP || proto == L3_UDP || proto == L3_UDPLITE || proto == L3_SCTP);

#if ANONYM_IP == 0
        fprintf(sPktFile, "%s" /* srcIP    */ SEP_CHR, srcIP);
#if BFO_SUBNET_TEST == 1
        fprintf(sPktFile, "%s" /* srcIPCC  */ SEP_CHR, srcLoc);
#if BFO_SUBNET_ORG == 1
        fprintf(sPktFile, "%s" /* srcIPOrg */ SEP_CHR, srcOrg);
#endif // BFO_SUBNET_ORG == 1
#endif // BFO_SUBNET_TEST == 1
#endif // ANONYM_IP == 0

        if (hasPorts) fprintf(sPktFile, "%" PRIu16, srcPort);
        fputs(SEP_CHR, sPktFile);

#if ANONYM_IP == 0
        fprintf(sPktFile, "%s" /* dstIP    */ SEP_CHR, dstIP);
#if BFO_SUBNET_TEST == 1
        fprintf(sPktFile, "%s" /* dstIPCC  */ SEP_CHR, dstLoc);
#if BFO_SUBNET_ORG == 1
        fprintf(sPktFile, "%s" /* dstIPOrg */ SEP_CHR, dstOrg);
#endif // BFO_SUBNET_ORG == 1
#endif // BFO_SUBNET_TEST == 1
#endif // ANONYM_IP == 0

        if (hasPorts) fprintf(sPktFile, "%" PRIu16, dstPort);

        fprintf(sPktFile,
                          /* dstPort */ SEP_CHR
                "%" PRIu8 /* l4Proto */ SEP_CHR
                , proto);
    }
}


#if BLOCK_BUF == 0
void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
#if (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0) || \
    (BFO_MAC == 1 && BFO_MAX_MAC  > 0) || \
    (BFO_VLAN > 0 && BFO_MAX_VLAN > 0) || \
    (BFO_MPLS > 0 && BFO_MAX_MPLS > 0) || \
    BFO_PPP == 1 || \
    (ANONYM_IP == 0 && ( \
        BFO_L2TP          == 1 || \
        BFO_GRE           == 1 || \
        BFO_TEREDO        == 1 || \
        BFO_SUBNET_IPLIST == 1))
    const bfoFlow_t * const bfoFlowP = &bfoFlow[flowIndex];
#endif

#if (BFO_TEREDO == 1 && IPV6_ACTIVATE > 0 && ANONYM_IP == 0) || \
    (BFO_VLAN > 0 && BFO_MAX_VLAN > 0)
    uint16_t temp16;
#endif

    uint32_t temp32;

    const flow_t * const flowP = &flows[flowIndex];

#if BFO_SENSORID == 1
    OUTBUF_APPEND_U32(buf, sensorID);      // sensorID
#endif // BFO_SENSORID == 1

    OUTBUF_APPEND_U64(buf, flowP->status); // flowStat

    // timeFirst, timeLast
    uint64_t secs;
    struct timeval timeFirst, timeLast;

    // timeFirst
#if RELTIME == 1
    const struct timeval firstSeen = flowP->firstSeen;
    T2_TIMERSUB(&firstSeen, &startTStamp, &timeFirst);
#else // RELTIME == 1
    timeFirst = flowP->firstSeen;
#endif // RELTIME == 1
    secs = (uint32_t)timeFirst.tv_sec;
    temp32 = timeFirst.tv_usec;
    OUTBUF_APPEND_TIME(buf, secs, temp32);

    // timeLast
#if RELTIME == 1
    const struct timeval lastSeen = flowP->lastSeen;
    T2_TIMERSUB(&lastSeen, &startTStamp, &timeLast);
#else // RELTIME == 0
    timeLast = flowP->lastSeen;
#endif // RELTIME
    secs = (uint32_t)timeLast.tv_sec;
    temp32 = timeLast.tv_usec;
    OUTBUF_APPEND_TIME(buf, secs, temp32);

    // duration
    secs = (uint32_t)flowP->duration.tv_sec;
    temp32 = flowP->duration.tv_usec;
    OUTBUF_APPEND_TIME(buf, secs, temp32);

#if (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)
    OUTBUF_APPEND_U8(buf, bfoFlowP->hDCnt);                          // numHdrDesc
    OUTBUF_APPEND_ARRAY_U16(buf, bfoFlowP->hdrCnt, bfoFlowP->hDCnt); // numHdrs

    // hdrDesc/hdrDesc_pktCnt
    temp32 = (uint32_t)bfoFlowP->hDCnt;
    OUTBUF_APPEND_NUMREP(buf, temp32);
    for (uint_fast32_t i = 0; i < temp32; i++) {
        OUTBUF_APPEND_STR(buf, bfoFlowP->hdrDesc[i]); // hdrDesc
#if BFO_HDRDESC_PKTCNT == 1
        OUTBUF_APPEND_U64(buf, bfoFlowP->pktCnt[i]);  // pktCnt
#endif // BFO_HDRDESC_PKTCNT == 1
    }
#endif // (T2_PRI_HDRDESC == 1 && BFO_MAX_HDRDESC > 0)

#if (BFO_MAC == 1 && BFO_MAX_MAC > 0)
    OUTBUF_APPEND_ARRAY_MAC(buf, bfoFlowP->srcMac, bfoFlowP->num_srcMac); // srcMac
    OUTBUF_APPEND_ARRAY_MAC(buf, bfoFlowP->dstMac, bfoFlowP->num_dstMac); // dstMac
#endif // (BFO_MAC == 1 && BFO_MAX_MAC > 0)

#if ((ETH_ACTIVATE > 0 || IPV6_ACTIVATE == 2) && BFO_ETHERTYPE == 1)
    OUTBUF_APPEND_U16(buf, flowP->ethType); // ethType
#endif

#if (BFO_VLAN > 0 && BFO_MAX_VLAN > 0)
    // vlanID/vlanHdr/vlanTPID_PCP_DEI_VID
    const uint32_t num_vlans = bfoFlowP->num_vlans;
    const uint32_t * const vlans = bfoFlowP->vlans;
    OUTBUF_APPEND_NUMREP(buf, num_vlans);
    for (uint_fast32_t i = 0; i < num_vlans; i++) {
#if BFO_VLAN == 3
        // vlanTPID_PCP_DEI_VID
        temp16 = vlans[i] & VLAN_ETYPE_MASK32;
        OUTBUF_APPEND_U16(buf, temp16);
        uint8_t temp8 = (vlans[i] >> 13) & 0x07;
        OUTBUF_APPEND_U8(buf, temp8);
        temp8 = (vlans[i] >> 12) & 0x01;
        OUTBUF_APPEND_U8(buf, temp8);
        temp16 = vlans[i] >> 16;
        OUTBUF_APPEND_U16(buf, temp16);
#elif BFO_VLAN == 2
        OUTBUF_APPEND_U32(buf, vlans[i]);  // vlanHdr
#else // BFO_VLAN == 1
        temp16 = vlans[i] >> 16;
        OUTBUF_APPEND_U16(buf, temp16);    // vlanID
#endif // BFO_VLAN == 1
    }
#endif // (BFO_VLAN > 0 && BFO_MAX_VLAN > 0)

#if (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)
    // mplsLabels/mplsLabelsHex/mplsHdrsHex/mplsLabel_ToS_S_TTL
    const uint32_t num_mpls = bfoFlowP->num_mpls;
    OUTBUF_APPEND_NUMREP(buf, num_mpls);
    for (uint_fast32_t i = 0; i < num_mpls; i++) {
        const uint32_t mpls = bfoFlowP->mplsHdr[i];
#if BFO_MPLS == 1 || BFO_MPLS == 2
        // mplsLabels/mplsLabelsHex
        const uint32_t label = MPLS_LABEL(mpls);
        OUTBUF_APPEND_U32(buf, label);
#elif BFO_MPLS == 3
        // mplsHdrsHex
        OUTBUF_APPEND_U32(buf, mpls);
#else // BFO_MPLS == 4
        // mplsLabel_ToS_S_TTL
        const uint32_t label = MPLS_LABEL(mpls);
        const uint8_t expToS = MPLS_EXP(mpls);
        const uint8_t bottom = MPLS_BOTTOM(mpls);
        const uint8_t ttl = MPLS_TTL(mpls);
        OUTBUF_APPEND_U32(buf, label);
        OUTBUF_APPEND_U8(buf, expToS);
        OUTBUF_APPEND_U8(buf, bottom);
        OUTBUF_APPEND_U8(buf, ttl);
#endif // BFO_MPLS == 4
    }
#endif // (BFO_MPLS > 0 && BFO_MAX_MPLS > 0)

#if BFO_PPP == 1
    OUTBUF_APPEND_U32(buf, bfoFlowP->pppHdr.pppHdrc); // pppHdr
#endif // BFO_PPP == 1

#if LAPD_ACTIVATE == 1 && BFO_LAPD == 1
    OUTBUF_APPEND_U8(buf, bfoFlowP->lapdSAPI); // lapdSAPI
    OUTBUF_APPEND_U8(buf, bfoFlowP->lapdTEI);  // lapdTEI
#endif // LAPD_ACTIVATE == 1 && BFO_LAPD == 1

#if ANONYM_IP == 0

#if BFO_L2TP == 1
    OUTBUF_APPEND_U16(buf, bfoFlowP->l2tpHdrBF);         // l2tpHdr
    OUTBUF_APPEND_U16(buf, bfoFlowP->l2tpHdrTID);        // l2tpTID
    OUTBUF_APPEND_U16(buf, bfoFlowP->l2tpHdrSID);        // l2tpSID
    OUTBUF_APPEND_U32(buf, bfoFlowP->l2tpv3HdrccID);     // l2tpCCSID

#if (AGGREGATIONFLAG & SUBNET) == 0
    OUTBUF_APPEND_U32(buf, bfoFlowP->l2tp_srcIP.s_addr); // l2tpSrcIP
#endif // (AGGREGATIONFLAG & SUBNET) == 0

#if BFO_SUBNET_TEST_L2TP == 1
    // l2tpSrcIPASN, l2tpSrcIPCOC, l2tpSrcIPCC, l2tpSrcIPCnty,
    // l2tpSrcIPCity, l2tpSrcIPOrg, l2tpSrcIPLat_Lng_relP
    bfo_test_and_add_ipv4_geo_info(buf, bfoFlowP->l2tp_srcIP.s_addr);
#endif // BFO_SUBNET_TEST_L2TP == 1

#if (AGGREGATIONFLAG & SUBNET) == 0
    OUTBUF_APPEND_U32(buf, bfoFlowP->l2tp_dstIP.s_addr); // l2tpDstIP
#endif // (AGGREGATIONFLAG & SUBNET) == 0

#if BFO_SUBNET_TEST_L2TP == 1
    // l2tpDstIPASN, l2tpDstIPCOC, l2tpDstIPCC, l2tpDstIPCnty,
    // l2tpDstIPCity, l2tpDstIPOrg, l2tpDstIPLat_Lng_relP
    bfo_test_and_add_ipv4_geo_info(buf, bfoFlowP->l2tp_dstIP.s_addr);
#endif // BFO_SUBNET_TEST_L2TP == 1
#endif // BFO_L2TP == 1

#if BFO_GRE == 1
    OUTBUF_APPEND_U32_NTOH(buf, bfoFlowP->greHdrBF);    // greHdr

#if (AGGREGATIONFLAG & SUBNET) == 0
    OUTBUF_APPEND_U32(buf, bfoFlowP->gre_srcIP.s_addr); // greSrcIP
#endif // (AGGREGATIONFLAG & SUBNET) == 0

#if BFO_SUBNET_TEST_GRE == 1
    // greSrcIPASN, greSrcIPCOC, greSrcIPCC, greSrcIPCnty,
    // greSrcIPCity, greSrcIPOrg, greSrcIPLat_Lng_relP
    bfo_test_and_add_ipv4_geo_info(buf, bfoFlowP->gre_srcIP.s_addr);
#endif // BFO_SUBNET_TEST_GRE == 1

#if (AGGREGATIONFLAG & SUBNET) == 0
    OUTBUF_APPEND_U32(buf, bfoFlowP->gre_dstIP.s_addr); // greDstIP
#endif // (AGGREGATIONFLAG & SUBNET) == 0

#if BFO_SUBNET_TEST_GRE == 1
    // greDstIPASN, greDstIPCOC, greDstIPCC, greDstIPCnty,
    // greDstIPCity, greDstIPOrg, greDstIPLat_Lng_relP
    bfo_test_and_add_ipv4_geo_info(buf, bfoFlowP->gre_dstIP.s_addr);
#endif // BFO_SUBNET_TEST_GRE == 1
#endif // BFO_GRE == 1

#if BFO_TEREDO == 1
    OUTBUF_APPEND_U32(buf, bfoFlowP->trdoIP); // trdoDstIP

#if BFO_SUBNET_TEST_TEREDO == 1
    // trdoDstIPASN, trdoDstIPCOC, trdoDstIPCC, trdoDstIPCnty,
    // trdoDstIPCity, trdoDstIPOrg, trdoDstIPLat_Lng_relP
    bfo_test_and_add_ipv4_geo_info(buf, bfoFlowP->trdoIP);
#endif // BFO_SUBNET_TEST_TEREDO == 1

    OUTBUF_APPEND_U16(buf, bfoFlowP->trdoPort); // trdoDstPort

#if IPV6_ACTIVATE > 0
    // Teredo IPv6 source and destination addresses
    const uint32_t * const sA[] = {
        (uint32_t*)flowP->srcIP.IPv4x,
        (uint32_t*)flowP->dstIP.IPv4x,
    };
    for (uint_fast32_t i = 0; i < 2; i++) {
        if (FLOW_IS_IPV6(flowP) && *sA[i] == 0x00000120) {
            const char ss = (char)(sA[i][2] & 0xc3000000);
            temp32 = sA[i][3] ^ 0xffffffff;
            temp16 = (htobe32(sA[i][2]) ^ 0xffff) & 0xffff;

            OUTBUF_APPEND_U8(buf, ss);        // trdo6SrcFlgs, trdo6DstFlgs
            OUTBUF_APPEND_U32(buf, sA[i][1]); // trdo6SrcSrvIP4, trdo6DstSrvIP4

#if BFO_SUBNET_TEST_TEREDO == 1
            // trdo6SrcSrvIP4ASN, trdo6SrcSrvIP4COC, trdo6SrcSrvIP4CC, trdo6SrcSrvIP4Cnty,
            // trdo6SrcSrvIP4City, trdo6SrcSrvIP4Org, trdo6SrcSrvIP4Lat_Lng_relP
            // trdo6DstSrvIP4ASN, trdo6DstSrvIP4COC, trdo6DstSrvIP4CC, trdo6DstSrvIP4Cnty,
            // trdo6DstSrvIP4City, trdo6DstSrvIP4Org, trdo6DstSrvIP4Lat_Lng_relP
            bfo_test_and_add_ipv4_geo_info(buf, sA[i][1]);
#endif // BFO_SUBNET_TEST_TEREDO == 1

            OUTBUF_APPEND_U32(buf, temp32);   // trdo6SrcCPIP4, trdo6DstCPIP4

#if BFO_SUBNET_TEST_TEREDO == 1
            // trdo6SrcCPIP4ASN, trdo6SrcCPIP4COC, trdo6SrcCPIP4CC, trdo6SrcCPIP4Cnty,
            // trdo6SrcCPIP4City, trdo6SrcCPIP4Org, trdo6SrcCPIP4Lat_Lng_relP
            // trdo6DstCPIP4ASN, trdo6DstCPIP4COC, trdo6DstCPIP4CC, trdo6DstCPIP4Cnty,
            // trdo6DstCPIP4City, trdo6DstCPIP4Org, trdo6DstCPIP4Lat_Lng_relP
            bfo_test_and_add_ipv4_geo_info(buf, temp32);
#endif // BFO_SUBNET_TEST_TEREDO == 1

            OUTBUF_APPEND_U16(buf, temp16);   // trdo6SrcCPPort, trdo6DstCPPort
        } else {
            OUTBUF_APPEND_U8_ZERO(buf);       // trdo6SrcFlgs, trdo6DstFlgs
            OUTBUF_APPEND_U32_ZERO(buf);      // trdo6SrcSrvIP4, trdo6DstSrvIP4

#if BFO_SUBNET_TEST_TEREDO == 1
            // trdo6SrcSrvIP4ASN, trdo6SrcSrvIP4COC, trdo6SrcSrvIP4CC, trdo6SrcSrvIP4Cnty,
            // trdo6SrcSrvIP4City, trdo6SrcSrvIP4Org, trdo6SrcSrvIP4Lat_Lng_relP
            // trdo6DstSrvIP4ASN, trdo6DstSrvIP4COC, trdo6DstSrvIP4CC, trdo6DstSrvIP4Cnty,
            // trdo6DstSrvIP4City, trdo6DstSrvIP4Org, trdo6DstSrvIP4Lat_Lng_relP
            bfo_add_empty_geo_info(buf);
#endif // BFO_SUBNET_TEST_TEREDO == 1

            OUTBUF_APPEND_U32_ZERO(buf);      // trdo6SrcCPIP4, trdo6DstCPIP4

#if BFO_SUBNET_TEST_TEREDO == 1
            // trdo6SrcCPIP4ASN, trdo6SrcCPIP4COC, trdo6SrcCPIP4CC, trdo6SrcCPIP4Cnty,
            // trdo6SrcCPIP4City, trdo6SrcCPIP4Org, trdo6SrcCPIP4Lat_Lng_relP
            // trdo6DstCPIP4ASN, trdo6DstCPIP4COC, trdo6DstCPIP4CC, trdo6DstCPIP4Cnty,
            // trdo6DstCPIP4City, trdo6DstCPIP4Org, trdo6DstCPIP4Lat_Lng_relP
            bfo_add_empty_geo_info(buf);
#endif // BFO_SUBNET_TEST_TEREDO == 1

            OUTBUF_APPEND_U16_ZERO(buf);      // trdo6SrcCPPort, trdo6DstCPPort
        }
    }
#endif // IPV6_ACTIVATE > 0
#endif // BFO_TEREDO == 1

#if (IPV6_ACTIVATE == 2 || BFO_SUBNET_TEST == 1)
    const uint_fast8_t ipver = FLOW_IPVER(flowP);
#endif // (IPV6_ACTIVATE == 2 || BFO_SUBNET_TEST == 1)

    // srcIP
#if BFO_SUBNET_IPLIST == 1
    OUTBUF_APPEND_NUMREP(buf, bfoFlowP->ipCnt[0]);
    for (uint_fast32_t i = 0; i < bfoFlowP->ipCnt[0]; i++) {
#if IPV6_ACTIVATE == 2
        OUTBUF_APPEND_IPVX(buf, ipver, bfoFlowP->ip[0][i]);
#elif IPV6_ACTIVATE == 1
        OUTBUF_APPEND_IP6(buf, bfoFlowP->ip[0][i]);
#else // IPV6_ACTIVATE == 0
        OUTBUF_APPEND_IP4(buf, bfoFlowP->ip[0][i]);
#endif // IPV6_ACTIVATE == 0
    }
#else // BFO_SUBNET_IPLIST == 0
#if IPV6_ACTIVATE == 2
    OUTBUF_APPEND_IPVX(buf, ipver, flowP->srcIP);
#elif IPV6_ACTIVATE == 1
    OUTBUF_APPEND_IP6(buf, flowP->srcIP);
#else // IPV6_ACTIVATE == 0
    OUTBUF_APPEND_IP4(buf, flowP->srcIP);
#endif // IPV6_ACTIVATE == 0
#endif // BFO_SUBNET_IPLIST

#if BFO_SUBNET_TEST == 1
    // srcIPASN, srcIPCOC, srcIPCC, srcIPCnty,
    // srcIPCity, srcIPOrg, srcIPLat_Lng_relP
    bfo_add_ip_geo_info(buf, ipver, flowP->subnetNrSrc);
#endif // BFO_SUBNET_TEST == 1

#endif // ANONYM_IP == 0

    OUTBUF_APPEND_U16(buf, flowP->srcPort); // srcPort

#if ANONYM_IP == 0

    // dstIP
#if BFO_SUBNET_IPLIST == 1
    OUTBUF_APPEND_NUMREP(buf, bfoFlowP->ipCnt[1]);
    for (uint_fast32_t i = 0; i < bfoFlowP->ipCnt[1]; i++) {
#if IPV6_ACTIVATE == 2
        OUTBUF_APPEND_IPVX(buf, ipver, bfoFlowP->ip[1][i]);
#elif IPV6_ACTIVATE == 1
        OUTBUF_APPEND_IP6(buf, bfoFlowP->ip[1][i]);
#else // IPV6_ACTIVATE == 0
        OUTBUF_APPEND_IP4(buf, bfoFlowP->ip[1][i]);
#endif // IPV6_ACTIVATE == 0
    }
#else // BFO_SUBNET_IPLIST == 0
#if IPV6_ACTIVATE == 2
    OUTBUF_APPEND_IPVX(buf, ipver, flowP->dstIP);
#elif IPV6_ACTIVATE == 1
    OUTBUF_APPEND_IP6(buf, flowP->dstIP);
#else // IPV6_ACTIVATE == 0
    OUTBUF_APPEND_IP4(buf, flowP->dstIP);
#endif // IPV6_ACTIVATE == 0
#endif // BFO_SUBNET_IPLIST

#if BFO_SUBNET_TEST == 1
    // dstIPASN, dstIPCOC, dstIPCC, dstIPCnty,
    // dstIPCity, dstIPOrg, dstIPLat_Lng_relP
    bfo_add_ip_geo_info(buf, ipver, flowP->subnetNrDst);
#endif // BFO_SUBNET_TEST == 1

#endif // ANONYM_IP == 0

    OUTBUF_APPEND_U16(buf, flowP->dstPort); // dstPort
    OUTBUF_APPEND_U8(buf, flowP->l4Proto);  // l4Proto
}
#endif // BLOCK_BUF == 0


#if BLOCK_BUF == 0 && BFO_SUBNETHL_INCLUDED == 1 && ANONYM_IP == 0 && ( \
        (BFO_GRE    == 1 && BFO_SUBNET_TEST_GRE    == 1) || \
        (BFO_L2TP   == 1 && BFO_SUBNET_TEST_L2TP   == 1) || \
        (BFO_TEREDO == 1 && BFO_SUBNET_TEST_TEREDO == 1))
static inline void bfo_test_and_add_ipv4_geo_info(outputBuffer_t *buf, uint32_t ipv4) {
    ipAddr_t ip = { .IPv4x[0] = ipv4 };
    bfo_test_and_add_ip_geo_info(buf, ip, 4);
}


static inline void bfo_test_and_add_ip_geo_info(outputBuffer_t *buf, ipAddr_t ip, uint_fast8_t ipver) {
    uint_fast32_t subnetNr;
    SUBNET_TEST_IP(subnetNr, ip, ipver);
    bfo_add_ip_geo_info(buf, ipver, subnetNr);
}
#endif


#if BLOCK_BUF == 0 && BFO_SUBNETHL_INCLUDED == 1 && ANONYM_IP == 0
static inline void bfo_add_ip_geo_info(outputBuffer_t *buf, uint_fast8_t ipver, uint32_t subnetNr) {

    if (ipver == 0 || subnetNr == 0) {
        bfo_add_empty_geo_info(buf);
        return;
    }

#if BFO_SUBNET_ASN == 1
    uint32_t asn;
    SUBNET_ASN(asn, ipver, subnetNr);
    OUTBUF_APPEND_U32(buf, asn);
#endif // BFO_SUBNET_ASN == 1

#if BFO_SUBNET_HEX == 1
    uint32_t netID;
    SUBNET_NETID(netID, ipver, subnetNr);
    OUTBUF_APPEND_U32(buf, netID);
#endif // BFO_SUBNET_HEX == 1

    char *loc;
    SUBNET_LOC(loc, ipver, subnetNr);
    OUTBUF_APPEND_STR(buf, loc);

#if CNTYCTY == 1
    SUBNET_CNTY(loc, ipver, subnetNr);
    OUTBUF_APPEND_STR(buf, loc);
    SUBNET_CTY(loc, ipver, subnetNr);
    OUTBUF_APPEND_STR(buf, loc);
#endif // CNTYCTY == 1

#if BFO_SUBNET_ORG == 1
    char *org;
    SUBNET_ORG(org, ipver, subnetNr);
    OUTBUF_APPEND_STR(buf, org);
#endif

#if BFO_SUBNET_LL == 1
    float lat_lng_oP[3];
    SUBNET_LAT(lat_lng_oP[0], ipver, subnetNr);
    SUBNET_LNG(lat_lng_oP[1], ipver, subnetNr);
    SUBNET_PREC(lat_lng_oP[2], ipver, subnetNr);
    OUTBUF_APPEND(buf, lat_lng_oP, 3 * sizeof(float));
#endif // BFO_SUBNET_LL == 1
}
#endif // BLOCK_BUF == 0 && BFO_SUBNETHL_INCLUDED == 1 && ANONYM_IP == 0


#if BLOCK_BUF == 0 && BFO_SUBNETHL_INCLUDED == 1 && ANONYM_IP == 0
static inline void bfo_add_empty_geo_info(outputBuffer_t *buf) {
#if BFO_SUBNET_ASN == 1
    OUTBUF_APPEND_U32_ZERO(buf);        // ASN
#endif // BFO_SUBNET_ASN == 1
#if BFO_SUBNET_HEX == 1
    OUTBUF_APPEND_U32_ZERO(buf);        // COC
#endif // BFO_SUBNET_HEX == 1
    OUTBUF_APPEND_STR(buf, SUBNET_UNK); // CC
#if CNTYCTY == 1
    OUTBUF_APPEND_STR(buf, SUBNET_UNK); // Cnty
    OUTBUF_APPEND_STR(buf, SUBNET_UNK); // City
#endif // CNTYCTY == 1
#if BFO_SUBNET_ORG == 1
    OUTBUF_APPEND_STR(buf, SUBNET_UNK); // Org
#endif
#if BFO_SUBNET_LL == 1
    // Lat_Lng_relP
    const float lat_lng_oP[3] = { 0.0f, 0.0f, 0.0f };
    OUTBUF_APPEND(buf, lat_lng_oP, 3 * sizeof(float));
#endif // BFO_SUBNET_LL == 1
}
#endif // BLOCK_BUF == 0 && BFO_SUBNETHL_INCLUDED == 1 && ANONYM_IP == 0


void t2Finalize() {
    free(bfoFlow);
}
