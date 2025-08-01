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

#include "ospfDecode.h"

#include <arpa/inet.h>  // for inet_ntoa, inet_ntop
#include <netinet/in.h>
#include <sys/socket.h>


// Global variables

ospfFlow_t *ospfFlow;


// Static variables

#if OSPF_OUTPUT_STATS == 1
#if ENVCNTRL > 0
static const char *ospfSuffix;
#else // ENVCNTRL == 0
static const char * const ospfSuffix = OSPF_SUFFIX;
#endif // ENVCNTRL
#endif // OSPF_OUTPUT_STATS == 1

#if OSPF_OUTPUT_HLO == 1
static FILE *ospfHelloFile;
#endif // OSPF_OUTPUT_HLO == 1

#if OSPF_OUTPUT_DBD == 1
static FILE *ospfDBDFile;
#endif // OSPF_OUTPUT_DBD == 1

#if OSPF_OUTPUT_MSG == 1
static FILE *ospf2MsgFile;
static FILE *ospf3MsgFile;
#endif // OSPF_OUTPUT_MSG == 1

static uint64_t numOSPF2[OSPF_TYPE_N];          // store number of OSPFv2 packets at pos 0
static uint64_t numOSPF3[OSPF_TYPE_N];          // store number of OSPFv3 packets at pos 0
static uint64_t numOSPF2LSType[OSPF_LSTYPE_N];  // store number of unknown OSPFv2 LS type at pos 0
static uint64_t numOSPF3LSType[OSPF3_LSTYPE_N]; // store number of unknown OSPFv3 LS type at pos 0
static uint64_t numOSPFAuType[OSPF_AUTH_N+1];   // store number of unknown auth type at pos OSPF_AUTH_N
static uint64_t numInvalidType;

#if ((IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2) && OSPF_OUTPUT_HLO == 1) || OSPF_OUTPUT_STATS == 1
static uint64_t numInvalidDest;
#endif

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2 || OSPF_OUTPUT_STATS == 1
static uint64_t numInvalidTTL;
static uint64_t numMCastPkts;
#endif

static uint8_t ospfStat;
static uint8_t ospf2Type;
static uint8_t ospf3Type;

static char *ospfTypeStr[OSPF_TYPE_N+1] = {
    "0",
    "Hello",
    "DBD",
    "LSReq",
    "LSUp",
    "LSAck",
    OSPF_TYPE_UNK
};

#if (OSPF_LSTYP_STR == 1 && (OSPF_OUTPUT_DBD == 1 || OSPF_OUTPUT_MSG == 1)) || OSPF_OUTPUT_STATS == 1

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2 || OSPF_OUTPUT_STATS == 1
static const char *ospf2LSTypeStr[OSPF_LSTYPE_N+1] = {
    "Unknown_0",
    "Router_1",   // Router-LSA
    "Network_2",  // Network-LSA
    "Summary_3",  // Summary-LSA (IP network)
    "ASBR_4",     // Summary-LSA (ASBR)
    "ASext_5",    // As-external-LSA
    "MCast_6",    // Multicast Group LSA
    "NSSA_7",     // NSSA-External-LSA
    "BGP_8",      // External Attribute LSA for BGP
    "OP_Link_9",  // Opaque-LSA (link-local scope)
    "OP_Area_10", // Opaque-LSA (area-local scope)
    "OP_AS_11",   // Opaque-LSA (AS scope)
    OSPF_TYPE_UNK
};
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2 || OSPF_OUTPUT_STATS == 1

#if IPV6_ACTIVATE > 0 || OSPF_OUTPUT_STATS == 1
static const char *ospf3LSTypeStr[OSPF3_LSTYPE_N+1] = {
    "Unknown_0",            //  0
    "Router_1",             //  1
    "Network_2",            //  2
    "Int_Area_Pref_3",      //  3
    "Int_Area_Router_4",    //  4
    "AS_EXT_5",             //  5
    "Deprecated_6",         //  6
    "NSSA-LSA_7",           //  7
    "Link_LSA_8",           //  8
    "Intra_Area_Pref_9",    //  9
    "INTR_A_TE_LSA_10",     // 10
    "GRACE_LSA_11",         // 11
    "RI_LSA_12",            // 12
    "INTR_AS_TE_LSA_13",    // 13
    "OSPF3_L1VPN_LSA_14",   // 14
    "AC_LSA_15",            // 15
    "DYNFL_LSA_16",         // 16
    "res_17",               // 17
    "res_18",               // 18
    "res_19",               // 19
    "res_20",               // 20
    "res_21",               // 21
    "res_22",               // 22
    "res_23",               // 23
    "res_24",               // 24
    "res_25",               // 25
    "res_26",               // 26
    "res_27",               // 27
    "res_28",               // 28
    "res_29",               // 29
    "res_30",               // 30
    "res_31",               // 31
    "res_32",               // 32
    "E_RTR_LSA_33",         // 33
    "E_NET_LSA_34",         // 34
    "E_INT_A_PREF_LSA_35",  // 35
    "E_INT_A_RTR_LSA_36",   // 36
    "E_AS_EXT_LSA_37",      // 37
    "E_TYP_7_LSA_39",       // 39
    "E_LINK_LSA_40",        // 40
    "E_INTR_A_PREF_LSA_41", // 41
    OSPF_TYPE_UNK
};
#endif // IPV6_ACTIVATE > 0 || OSPF_OUTPUT_STATS == 1

#endif // (OSPF_LSTYP_STR == 1 && (OSPF_OUTPUT_DBD == 1 || OSPF_OUTPUT_MSG == 1)) || OSPF_OUTPUT_STATS == 1

#if OSPF_OUTPUT_MSG == 1 && OSPF_LSTYP_STR == 1
static const char *ospfLinkTypeStr[OSPF_LINK_TYPE_N+1] = {
    "0",
    "PTP",      // "Point-to-point connection to another router",
    "Transit",  // "Connection to a transit network",
    "Stub",     // "Connection to a stub network",
    "Virtual",  // "Virtual link"
    OSPF_TYPE_UNK
};
#endif // OSPF_OUTPUT_MSG == 1 && OSPF_LSTYP_STR == 1


#define OSPF_PERCENT(num, tot) (100.0f * (num) / (float)(tot))
#define OSPF_LOG_TYPE(stream, type, num, tot) \
    if ((num) > 0) { \
        fprintf((stream), "%-20s\t%20" PRIu64" [%6.02f%%]\n", (type), (num), OSPF_PERCENT((num), (tot))); \
    }
#define OSPF_LOG_LSTYPE(stream, type, num) \
    if ((num > 0)) { \
        fprintf(file, "%-20s\t%20" PRIu64 "\n", (type), (num)); \
    }

#define OSPF_TYPE_TO_STR(type)      (((type) < OSPF_TYPE_N)      ? ospfTypeStr[(type)]     : ospfTypeStr[OSPF_TYPE_N])
#define OSPF2_LSTYPE_TO_STR(type)   (((type) < OSPF_LSTYPE_N)    ? ospf2LSTypeStr[(type)]  : ospf2LSTypeStr[OSPF_LSTYPE_N])
#define OSPF3_LSTYPE_TO_STR(type)   (((type) < OSPF3_LSTYPE_N)   ? ospf3LSTypeStr[(type)]  : ospf3LSTypeStr[OSPF3_LSTYPE_N])
#define OSPF_LINK_TYPE_TO_STR(type) (((type) < OSPF_LINK_TYPE_N) ? ospfLinkTypeStr[(type)] : ospfLinkTypeStr[OSPF_LINK_TYPE_N])

#define OSPF_SPKTMD_PRI_HDR() \
    if (sPktFile) { \
        fputs("ospfStat"    SEP_CHR \
              "ospfVersion" SEP_CHR \
              "ospfArea"    SEP_CHR \
              "ospfType"    SEP_CHR \
              "ospfLSType"  SEP_CHR \
              , sPktFile); \
    }
#define OSPF_SPKTMD_PRI_NONE(ospfFlowP) \
    if (sPktFile) { \
        fprintf(sPktFile, \
                "0x%02" B2T_PRIX8 /* ospfStat    */ SEP_CHR \
                                  /* ospfVersion */ SEP_CHR \
                                  /* ospfArea    */ SEP_CHR \
                                  /* ospfType    */ SEP_CHR \
                                  /* ospfLSType  */ SEP_CHR \
                , ospfFlowP->stat); \
    }
#define OSPF_SPKTMD_PRI_1(ospfFlowP, ver) \
    if (sPktFile) { \
        fprintf(sPktFile, \
                "0x%02" B2T_PRIX8 /* ospfStat    */ SEP_CHR \
                "%"     PRIuFAST8 /* ospfVersion */ SEP_CHR \
                                  /* ospfArea    */ SEP_CHR \
                                  /* ospfType    */ SEP_CHR \
                                  /* ospfLSType  */ SEP_CHR \
                , ospfFlowP->stat, ver); \
    }
#define OSPF_SPKTMD_PRI_2(ospfFlowP, ver, areaID, type) \
    if (sPktFile) { \
        fprintf(sPktFile, \
                "0x%02" B2T_PRIX8     /* ospfStat    */ SEP_CHR \
                "%"     PRIuFAST8     /* ospfVersion */ SEP_CHR \
                "%"     OSPF_PRI_AREA /* ospfArea    */ SEP_CHR \
                "%s"                  /* ospfType    */ SEP_CHR \
                                      /* ospfLSType  */ SEP_CHR \
                , ospfFlowP->stat, ver, areaID, OSPF_TYPE_TO_STR(type)); \
    }
#define OSPF_SPKTMD_PRI_3(ospfFlowP, ver, areaID, type, xlsType) \
    if (sPktFile) { \
        fprintf(sPktFile, \
                "0x%02"  B2T_PRIX8     /* ospfStat    */ SEP_CHR \
                "%"      PRIuFAST8     /* ospfVersion */ SEP_CHR \
                "%"      OSPF_PRI_AREA /* ospfArea    */ SEP_CHR \
                "%s"                   /* ospfType    */ SEP_CHR \
                "0x%016" B2T_PRIX64    /* ospfLSType  */ SEP_CHR \
                , ospfFlowP->stat, ver, areaID, OSPF_TYPE_TO_STR(type), xlsType); \
    }


/*
#if (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
#if OSPF_OUTPUT_MSG == 1
static const char *ospfMetricToIface(uint16_t metric) {
    // Default OSPF Interface Cost (reference-bandwidth (=10^8) / interface bandwidth)
    switch (metric) {
        case 0:
            return "Loopback";
        case 1:
            return "> 100 Mbps";
            //return "FDDI, TM, Fast Ethernet, Gigabit Ethernet (> 100 Mbps)";
        case 2:
            return "45 Mbps";
            //return "HSSI (45 Mbps)";
        case 6:
            return "16-Mbps";
            //return "16-Mbps Token Ring";
        case 10:
            return "10-Mbps";
            //return "10-Mbps Ethernet";
        case 25:
            return "4-Mbps";
            //return "4-Mbps Token Ring";
        case 48:
            return "2.048 Mbps";
            //return "E1 (2.048 Mbps)";
        case 64:
            return "1.544 Mbps";
            //return "T1 (1.544 Mbps)";
        case 1562:
            return "64 kbps";
            //return "DS-0 (64 kbps)";
        case 1785:
            return "56 kbps";
        case 11111:
            return "9 kbps";
            //return "Tunnel (9 kbps)";
        default:
            return "";
    }
}
#endif // OSPF_OUTPUT_MSG == 1
#endif // (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
*/

static void ospfDecode_clean();


// Tranalyzer functions

T2_PLUGIN_INIT("ospfDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(ospfFlow);

#ifdef OSPF_NEED_ENV
#if !(ENVCNTRL == 0 && OSPF_OUTPUT_HLO == 0 && OSPF_OUTPUT_DBD == 0 && OSPF_OUTPUT_MSG == 0)
    t2_env_t env[ENV_OSPF_N] = {};
#endif // !(ENVCNTRL == 0 && OSPF_OUTPUT_HLO == 0 && OSPF_OUTPUT_DBD == 0 && OSPF_OUTPUT_MSG == 0)

#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_OSPF_N, env);
#if OSPF_OUTPUT_STATS == 1
    ospfSuffix = T2_STEAL_ENV_VAL(OSPF_SUFFIX);
#endif // OSPF_OUTPUT_STATS == 1
#else // ENVCNTRL == 0
#if OSPF_OUTPUT_HLO == 1
    T2_SET_ENV_STR(OSPF_HELLO_SUFFIX);
#endif // OSPF_OUTPUT_HLO == 1
#if OSPF_OUTPUT_DBD == 1
    T2_SET_ENV_STR(OSPF_DBD_SUFFIX);
#endif // OSPF_OUTPUT_DBD == 1
#if OSPF_OUTPUT_MSG == 1
    T2_SET_ENV_STR(OSPF2_MSG_SUFFIX);
    T2_SET_ENV_STR(OSPF3_MSG_SUFFIX);
#endif // OSPF_OUTPUT_MSG == 1
#endif // ENVCNTRL

#if OSPF_OUTPUT_HLO == 1
    ospfHelloFile = t2_fopen_with_suffix(baseFileName, T2_ENV_VAL(OSPF_HELLO_SUFFIX), "w");
    if (UNLIKELY(!ospfHelloFile)) {
        ospfDecode_clean();
        exit(EXIT_FAILURE);
    }

    fputs(HDR_CHR
            "pktNo"     SEP_CHR
            "Ver"       SEP_CHR
            "AreaID"    SEP_CHR
            "SrcOSPRtr" SEP_CHR
            "srcIP"     SEP_CHR
            "Netmask"   SEP_CHR
            "Network"   SEP_CHR
            "IntID"     SEP_CHR
            "RtrPrio"   SEP_CHR
            "Opt"       SEP_CHR
            "HelloInt"  SEP_CHR
            "RtrDInt"   SEP_CHR
            "DRtr"      SEP_CHR
            "BkupRtr"   SEP_CHR
            "NumNeigh"  SEP_CHR
            "Neighbors" "\n"
            , ospfHelloFile);
#endif // OSPF_OUTPUT_HLO == 1

#if OSPF_OUTPUT_DBD == 1
    ospfDBDFile = t2_fopen_with_suffix(baseFileName, T2_ENV_VAL(OSPF_DBD_SUFFIX), "w");
    if (UNLIKELY(!ospfDBDFile)) {
        ospfDecode_clean();
        exit(EXIT_FAILURE);
    }

    fputs(HDR_CHR
            "pktNo"     SEP_CHR
            "Ver"       SEP_CHR
            "AreaID"    SEP_CHR
            "RtrID"     SEP_CHR
            "LSLinkID"  SEP_CHR
            "ADVRouter" SEP_CHR
            "Dna"       SEP_CHR
            "Age"       SEP_CHR
            "SeqNum"    SEP_CHR
            "Checksum"  SEP_CHR
            "MTU"       SEP_CHR
            "Flags"     SEP_CHR
            "LSType"    SEP_CHR
            "tlvType"   SEP_CHR
            "tlvValOpt" "\n"
            , ospfDBDFile);
#endif // OSPF_OUTPUT_DBD == 1

#if OSPF_OUTPUT_MSG == 1
    ospf2MsgFile = t2_fopen_with_suffix(baseFileName, T2_ENV_VAL(OSPF2_MSG_SUFFIX), "w");
    if (UNLIKELY(!ospf2MsgFile)) {
        ospfDecode_clean();
        exit(EXIT_FAILURE);
    }

    fputs(HDR_CHR
          "pktNo"             SEP_CHR
          "Ver"               SEP_CHR
          "Area"              SEP_CHR
          "MsgType"           SEP_CHR
          "LSType"            SEP_CHR
          "srcIP"             SEP_CHR
          "LSLinkID"          SEP_CHR
          "NetmaskOrRouterIP" SEP_CHR
          "ADVRouter"         SEP_CHR
          "LSAOpt"            SEP_CHR
          "LnkType"           SEP_CHR
          "Metric"            SEP_CHR
          "IfaceType"         SEP_CHR
          "LSFlgs"            SEP_CHR
          "AttchRtrs"         SEP_CHR
          "FwdIP"             SEP_CHR
          "ExtRtTag"          "\n"
          , ospf2MsgFile);

    ospf3MsgFile = t2_fopen_with_suffix(baseFileName, T2_ENV_VAL(OSPF3_MSG_SUFFIX), "w");
    if (UNLIKELY(!ospf3MsgFile)) {
        ospfDecode_clean();
        exit(EXIT_FAILURE);
    }

    fputs(HDR_CHR
          "pktNo"                 SEP_CHR
          "Ver"                   SEP_CHR
          "Area"                  SEP_CHR
          "SrcRtr"                SEP_CHR
          "MsgType"               SEP_CHR
          "LSType"                SEP_CHR
          "srcIP"                 SEP_CHR
          "dstIP"                 SEP_CHR
          "LSAAdvRtr"             SEP_CHR
          "LSAOpts"               SEP_CHR
          "LSLinkID"              SEP_CHR
          "IntID"                 SEP_CHR
          "NeighIntID"            SEP_CHR
          "RefAdvRtrOrAttchRtrs"  SEP_CHR
          "Type"                  SEP_CHR
          "PrefOpts"              SEP_CHR
          "Metric"                SEP_CHR
          "RefLSA"                SEP_CHR
          "RefPrefix"             SEP_CHR
          "LnkLclIPOrFwdIP"       SEP_CHR
          "ExtRtTag"              "\n"
          , ospf3MsgFile);
#endif // OSPF_OUTPUT_MSG == 1

#if ENVCNTRL > 0
    t2_free_env(ENV_OSPF_N, env);
#endif // ENVCNTRL > 0
#endif // OSPF_NEED_ENV

    OSPF_SPKTMD_PRI_HDR();
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8(bv    , "ospfStat"     , "OSPF status");
    BV_APPEND_U8(bv    , "ospfVersion"  , "OSPF version");
#if OSPF_TYP_STR == 1
    BV_APPEND_STRC_R(bv, "ospfType"     , "OSPF message type");
#else // OSPF_TYP_STR == 0
    BV_APPEND_H8(bv    , "ospfType"     , "OSPF Message type");
#endif // OSPF_TYP_STR
    BV_APPEND_H64(bv   , "ospfLSType"   , "OSPF Update LS type");
    BV_APPEND_H16(bv   , "ospfAuType"   , "OSPF authentication type");
    BV_APPEND_STR_R(bv , "ospfAuPass"   , "OSPF authentication password");
    BV_APPEND_TYPE(bv  , "ospfArea"     , "OSPF Area ID", OSPF_AREA_TYPE);
    BV_APPEND_IP4(bv   , "ospfSrcRtr"   , "OSPF Hello source router");
    BV_APPEND_IP4(bv   , "ospfBkupRtr"  , "OSPF Hello backup router");
    BV_APPEND_IP4_R(bv , "ospfNeighbors", "OSPF Hello neighbor routers");
    return bv;
}


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    ospfFlow_t * const ospfFlowP = &ospfFlow[flowIndex];
    memset(ospfFlowP, '\0', sizeof(ospfFlow_t));
    if (packet->l4Proto == L3_OSPF) {
        ospfFlowP->stat = OSPF_STAT_DETECT;
    }
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t* packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    // This packet does not have a layer 4.
    // Print tabs to keep the packet file aligned
    ospfFlow_t * const ospfFlowP = &ospfFlow[flowIndex];
    OSPF_SPKTMD_PRI_NONE(ospfFlowP);
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
    ospfFlow_t * const ospfFlowP = &ospfFlow[flowIndex];

    if (!ospfFlowP->stat) {
        OSPF_SPKTMD_PRI_NONE(ospfFlowP);
        return;
    }

    const uint16_t snaplen = packet->snapL4Len;
    if (snaplen <= OSPF3_HDR_LEN) {
        OSPF_SPKTMD_PRI_NONE(ospfFlowP);
        return;
    }

    const ospfHeader_t * const ospfHdrP = (ospfHeader_t*)packet->l4HdrP;
#if IPV6_ACTIVATE > 0
    const ospf3Header_t * const ospf3HdrP = (ospf3Header_t*)packet->l4HdrP;
#endif // IPV6_ACTIVATE > 0

    const uint_fast8_t ver = ospfHdrP->version;
    ospfFlowP->version = ver;

    if (ver == 2) numOSPF2[0]++;
    else if (ver == 3) numOSPF3[0]++;
    else {
        ospfFlowP->stat |= OSPF_STAT_WRNG_VER;
        OSPF_SPKTMD_PRI_1(ospfFlowP, ver);
        return;
    }

    const uint8_t type = ospfHdrP->type;

#if OSPF_TYP_STR == 0
    ospfFlowP->type |= (1 << type);
#elif OSPF_TYP_STR == 1
    if (ospfFlowP->numTyp < OSPF_NUMTYP) {
        uint_fast32_t i;
        for (i = 0; i < ospfFlowP->numTyp; i++) {
            if (ospfFlowP->type[i] == type) break;
        }
        if (i == ospfFlowP->numTyp) {
            ospfFlowP->type[ospfFlowP->numTyp] = type;
            ospfFlowP->numTyp++;
        }
    }
#endif // OSPF_TYP_STR == 1

#if IPV6_ACTIVATE > 0
    const ip6Header_t * const ip6HdrP = IPV6_HEADER(packet);
#endif // IPV6_ACTIVATE > 0

#if (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
    const ipHeader_t * const ipHdrP = IPV4_HEADER(packet);
    const struct in_addr dstIp = ipHdrP->ip_dst;

    if (PACKET_IS_IPV4(packet)) {
        if (dstIp.s_addr == OSPF_ALL_SPF_ROUTERS || dstIp.s_addr == OSPF_ALL_D_ROUTERS) {
            numMCastPkts++;
            // when dstIP is mcast, TTL must be 1
            if (ipHdrP->ip_ttl != 1) {
                ospfFlowP->stat |= OSPF_STAT_BAD_TTL;
                numInvalidTTL++;
            }
        }
    }
#endif // (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)

#if OSPF_AREA_AS_IP == 1
    char areaID[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ospfHdrP->areaID, areaID, INET_ADDRSTRLEN);
    ospfFlowP->areaID = ospfHdrP->areaID;
#else // OSPF_AREA_AS_IP == 0
    const uint32_t areaID = ntohl(ospfHdrP->areaID);
    ospfFlowP->areaID = areaID;
#endif // OSPF_AREA_AS_IP

    ospfFlowP->routerID = ospfHdrP->routerID;

    uint16_t auType;
    const uint16_t ospfPktLen = ntohs(ospfHdrP->len);
    char saddr[INET6_ADDRSTRLEN];
#if IPV6_ACTIVATE > 0
    char daddr[INET6_ADDRSTRLEN];
#endif // IPV6_ACTIVATE > 0
    if (ver == 2) {
        if (type && type < OSPF_TYPE_N) numOSPF2[type]++;
        ospf2Type |= (1 << type);
        auType = ntohs(ospfHdrP->auType);
        ospfFlowP->auType |= (1 << auType);
        if (auType < OSPF_AUTH_N) numOSPFAuType[auType]++;
        else numOSPFAuType[OSPF_AUTH_N]++; // unknown auth type

        if (snaplen < OSPF2_HDR_LEN || ospfPktLen < OSPF2_HDR_LEN) {
            ospfFlowP->stat |= OSPF_STAT_MALFORMED;
            OSPF_SPKTMD_PRI_2(ospfFlowP, ver, areaID, type);
            return;
        }

        switch (auType) {
            case OSPF_AUTH_NULL:
                // Authentication Type is null, but auField is non-zero... covert channel?
                if (ospfHdrP->auField != 0) ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                break;
            case OSPF_AUTH_PASSWD:
                // password contained in clear text in auField
                t2_strcpy(ospfFlowP->auPass, (char*)&(ospfHdrP->auField), sizeof(ospfFlowP->auPass), T2_STRCPY_TRUNC);
                break;
            case OSPF_AUTH_CRYPTO:
                // do nothing
                break;
            default:
                break;
        }

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
        inet_ntop(AF_INET, &ipHdrP->ip_src, saddr, INET_ADDRSTRLEN);
        //inet_ntop(AF_INET, &ipHdrP->ip_dst, daddr, INET_ADDRSTRLEN);
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    } else {
        if (type && type < OSPF_TYPE_N) numOSPF3[type]++;
        ospf3Type |= (1 << type);

        if (snaplen < OSPF3_HDR_LEN || ospfPktLen < OSPF3_HDR_LEN) {
            ospfFlowP->stat |= OSPF_STAT_MALFORMED;
            OSPF_SPKTMD_PRI_2(ospfFlowP, ver, areaID, type);
            return;
        }
#if IPV6_ACTIVATE > 0
        inet_ntop(AF_INET6, &ip6HdrP->ip_src, saddr, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6HdrP->ip_dst, daddr, INET6_ADDRSTRLEN);
#endif // IPV6_ACTIVATE > 0
    } // ver == 3

    uint_fast32_t j;
    uint64_t xlsType = 0;

    switch (type) {
        case OSPF_HELLO: {
            // can be used to list routers in given area

#if (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
            if (ver == 2) {
                ospfHello_t * const hello2 = (ospfHello_t*)&ospfHdrP->data;
                ospfFlowP->backupRtr = hello2->backupRtr;
#if OSPF_OUTPUT_HLO == 1
                const struct in_addr ip_src = ipHdrP->ip_src;
                if (dstIp.s_addr != OSPF_ALL_SPF_ROUTERS) {
                    numInvalidDest++;
                    ospfFlowP->stat |= OSPF_STAT_BAD_DST;
                }
                fprintf(ospfHelloFile,
                        "%" PRIu64        /* pktNo     */ SEP_CHR
                        "%d"              /* Ver       */ SEP_CHR
                        "%" OSPF_PRI_AREA /* AreaID    */ SEP_CHR
                        "%s"              /* SrcOSPRtr */ SEP_CHR
                        "%s"              /* srcIP     */ SEP_CHR
                        , numPackets
                        , ver
                        , areaID
                        , inet_ntoa(ospfHdrP->routerID)
                        , saddr);

                uint32_t masked = ntohl(*((uint32_t*)&ip_src)) & ntohl(hello2->netmask);
                masked = ntohl(masked);

#if OSPF_MASK_AS_IP == 1
                fprintf(ospfHelloFile,
                    "%s" /* Netmask */ SEP_CHR
                    , inet_ntoa(*(struct in_addr*)&hello2->netmask));
#else // OSPF_MASK_AS_IP == 0
                fprintf(ospfHelloFile,
                    "\t0x%08" B2T_PRIX32 /* Netmask */ SEP_CHR
                    , ntohl(hello2->netmask));
#endif // OSPF_MASK_AS_IP == 0

                fprintf(ospfHelloFile,
                        "%s" /* Network */ SEP_CHR
                        , inet_ntoa(*(struct in_addr*)&masked));

                fprintf(ospfHelloFile,
                        "-"                /* IntID    */ SEP_CHR
                        "%" PRIu8          /* RtrPrio  */ SEP_CHR
                        "0x%08" B2T_PRIX32 /* Opt      */ SEP_CHR
                        "%" PRIu16         /* HelloInt */ SEP_CHR
                        "%" PRIu32         /* RtrDInt  */ SEP_CHR
                        "%s"               /* DRtr     */ SEP_CHR
                        , hello2->rtrPri
                        , hello2->options
                        , ntohs(hello2->helloInt)
                        , ntohl(hello2->routDeadInt)
                        , inet_ntoa(hello2->desRtr));

                fprintf(ospfHelloFile,
                        "%s" /* BkupRtr */ SEP_CHR
                        , inet_ntoa(hello2->backupRtr));
#endif // OSPF_OUTPUT_HLO == 1

                const int_fast32_t numNeighbors = (ospfPktLen - OSPF2_HDR_LEN - (sizeof(ospfHello_t)-4)) / sizeof(uint32_t);
#if OSPF_OUTPUT_HLO == 1
                fprintf(ospfHelloFile,
                        "%" PRIdFAST32 /* NumNeigh */ SEP_CHR
                        , numNeighbors);
#endif // OSPF_OUTPUT_HLO == 1

                struct in_addr *p = &hello2->neighbors;
                for (int_fast32_t i = 0; i < numNeighbors && (uint8_t*)p <= packet->end_packet - sizeof(uint32_t); i++) {
                    for (j = 0; j < ospfFlowP->numNeigh; j++) {
                        if (ospfFlowP->neighbors[j].s_addr == hello2->neighbors.s_addr) break;
                    }
                    if (j == ospfFlowP->numNeigh && j < OSPF_NEIGMAX) {
                        ospfFlowP->neighbors[ospfFlowP->numNeigh++] = hello2->neighbors;
                    }
#if OSPF_OUTPUT_HLO == 1
                    fprintf(ospfHelloFile,
                            "%s%s" /* Neighbors */
                            , inet_ntoa(*p++)
                            , ((i < numNeighbors-1) ? ";" : ""));
#endif // OSPF_OUTPUT_HLO == 1
                }

                if ((hello2->options & OSPF_OPT_LL) != 0) {
                    // LLS block present
                }

#if OSPF_OUTPUT_HLO == 1
                fputc('\n', ospfHelloFile);
#endif // OSPF_OUTPUT_HLO == 1
            } // ver == 2
#if IPV6_ACTIVATE == 2
            else { // ver == 3
#endif // IPV6_ACTIVATE == 2
#endif // (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
#if IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 1
            if (ver == 3) {
#endif // IPV6_ACTIVATE == 1
                ospfHello3_t * const hello3 = (ospfHello3_t*)&ospf3HdrP->data;
                ospfFlowP->backupRtr = hello3->backupRtr;
#if OSPF_OUTPUT_HLO == 1
                fprintf(ospfHelloFile,
                        "%" PRIu64         /* pktNo     */ SEP_CHR
                        "%d"               /* Ver       */ SEP_CHR
                        "%" OSPF_PRI_AREA  /* AreaID    */ SEP_CHR
                        "%s"               /* SrcOSPRtr */ SEP_CHR
                        "%s"               /* srcIP     */ SEP_CHR
                        "-"                /* Netmask   */ SEP_CHR
                        "-"                /* Network   */ SEP_CHR
                        "%" PRIu32         /* IntID     */ SEP_CHR
                        "%" PRIu32         /* RtrPrio   */ SEP_CHR
                        "0x%08" B2T_PRIX32 /* Opt       */ SEP_CHR
                        "%" PRIu16         /* HelloInt  */ SEP_CHR
                        "%" PRIu16         /* RtrDInt   */ SEP_CHR
                        , numPackets
                        , ver
                        , areaID
                        , inet_ntoa(ospf3HdrP->routerID)
                        , saddr
                        , ntohl(hello3->intID)
                        , hello3->rpopt & 0xff
                        , ntohl(hello3->rpopt) & 0x00ffffff
                        , ntohs(hello3->helloInt)
                        , ntohs(hello3->routDeadInt));

                fprintf(ospfHelloFile,
                        "%s" /* DRtr */ SEP_CHR
                        , inet_ntoa(hello3->desRtr));

                fprintf(ospfHelloFile,
                        "%s" /* BkupRtr */ SEP_CHR
                        , inet_ntoa(hello3->backupRtr));
#endif // OSPF_OUTPUT_HLO == 1

                const int_fast32_t numNeighbors = (ospfPktLen - OSPF3_HDR_LEN - (sizeof(ospfHello3_t)-4)) / sizeof(uint32_t);
#if OSPF_OUTPUT_HLO == 1
                fprintf(ospfHelloFile,
                        "%" PRIdFAST32 /* NumNeigh */ SEP_CHR
                        , numNeighbors);
#endif // OSPF_OUTPUT_HLO == 1

                struct in_addr *p = &hello3->neighbors;
                for (int_fast32_t i = 0; i < numNeighbors && (uint8_t*)p <= packet->end_packet - sizeof(uint32_t); i++) {
                    for (j = 0; j < ospfFlowP->numNeigh; j++) {
                        if (ospfFlowP->neighbors[j].s_addr == hello3->neighbors.s_addr) break;
                    }
                    if (j == ospfFlowP->numNeigh && j < OSPF_NEIGMAX) {
                        ospfFlowP->neighbors[ospfFlowP->numNeigh++] = hello3->neighbors;
                    }
#if OSPF_OUTPUT_HLO == 1
                    fprintf(ospfHelloFile,
                            "%s%s" /* Neighbors */
                            , inet_ntoa(*p++)
                            , ((i < numNeighbors-1) ? ";" : ""));
#endif // OSPF_OUTPUT_HLO == 1
                }

#if OSPF_OUTPUT_HLO == 1
                fputc('\n', ospfHelloFile);
#endif // OSPF_OUTPUT_HLO == 1
            } // ver == 3
#endif // IPV6_ACTIVATE > 0

            break;
        }

        case OSPF_DB_DESCR: {
#if (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
            if (ver == 2) {
                if (ospfPktLen < OSPF2_HDR_LEN + OSPF2_DBD_LEN) {
                    ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                    OSPF_SPKTMD_PRI_3(ospfFlowP, ver, areaID, type, xlsType);
                    return;
                }

                const ospfDBD_t * const dbd = (ospfDBD_t*)&(ospfHdrP->data);
                if (dbd->dbDesc > 7  || dbd->dbDesc == 4 ||  // only 3 bits are used: I,M,MS
                    dbd->dbDesc == 5 || dbd->dbDesc == 6) {   // (I), (I,MS), (I,M) not valid
                    ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                }

                uint16_t dataLen = ospfPktLen - OSPF2_HDR_LEN - OSPF2_DBD_LEN;

                if (snaplen < OSPF2_HDR_LEN+OSPF2_DBD_LEN+dataLen) {
                    OSPF_SPKTMD_PRI_3(ospfFlowP, ver, areaID, type, xlsType);
                    return;
                }

                size_t offset = 0;
                while (dataLen > 0) {
                    const ospfLSA_t * const lsa = (ospfLSA_t*)(&(dbd->lsaHdr) + offset);
                    const uint8_t lsType = lsa->lsType;
                    if (lsType > 0 && lsType < OSPF_LSTYPE_N) {
                        numOSPF2LSType[lsType]++;
#if OSPF_OUTPUT_DBD == 1
                        const uint16_t lsAge = ntohs(lsa->lsAge);
                        fprintf(ospfDBDFile,
                                "%" PRIu64        /* pktNo     */ SEP_CHR
                                "%" PRIuFAST8     /* Ver       */ SEP_CHR
                                "%" OSPF_PRI_AREA /* AreaID    */ SEP_CHR
                                "%s"              /* RtrID     */ SEP_CHR
                                , numPackets
                                , ver
                                , areaID
                                , inet_ntoa(ospfHdrP->routerID));

                        fprintf(ospfDBDFile,
                                "%s" /* LSLinkID */ SEP_CHR
                                , inet_ntoa(lsa->lsaID));

                        fprintf(ospfDBDFile,
                                "%s"                /* ADVRouter */ SEP_CHR
                                "%d"                /* Dna       */ SEP_CHR
                                "%d"                /* Age       */ SEP_CHR
                                "0x%08" B2T_PRIX32  /* SeqNum    */ SEP_CHR
                                "0x%04" B2T_PRIX16  /* Checksum  */ SEP_CHR
                                "%" PRIu32          /* MTU       */ SEP_CHR
                                "0x%04" B2T_PRIX16  /* Flags     */ SEP_CHR
                                "%" OSPF_PRI_LSTYPE /* LSType    */ SEP_CHR
                                                    /* tlvType   */ SEP_CHR
                                                    /* tlvValOpt */ "\n"
                                , inet_ntoa(lsa->advRtr)
                                , lsAge >> 15
                                , lsAge & 0x7fff
                                , ntohl(lsa->lsSeqNum)
                                , ntohs(lsa->lsChksum)
                                , ntohs(dbd->intMTU)
                                , dbd->dbDesc
#if OSPF_LSTYP_STR == 1
                                , OSPF2_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                , lsType
#endif // OSPF_LSTYP_STR
                        );

#endif // OSPF_OUTPUT_DBD == 1
                        dataLen -= sizeof(*lsa);
                        offset += sizeof(*lsa);
                    } else {
                        ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                        numOSPF2LSType[0]++;
                        // invalid record, abort processing of record
                        break;
                    }
                }

#if OSPF_OUTPUT_DBD == 1
                if (dbd->options & OSPF_OPT_LL) { // LLS block present
                    const ospfLLS_t * const lls = (ospfLLS_t*)(&(dbd->lsaHdr) + offset);
                    fprintf(ospfDBDFile,
                            "%" PRIu64         /* pktNo     */ SEP_CHR
                            "%" PRIuFAST8      /* Ver       */ SEP_CHR
                            "%" OSPF_PRI_AREA  /* AreaID    */ SEP_CHR
                            "%s"               /* RtrID     */ SEP_CHR
                                               /* LSLinkID  */ SEP_CHR
                                               /* ADVRouter */ SEP_CHR
                                               /* Dna       */ SEP_CHR
                                               /* Age       */ SEP_CHR
                                               /* SeqNum    */ SEP_CHR
                                               /* Checksum  */ SEP_CHR
                                               /* MTU       */ SEP_CHR
                                               /* Flags     */ SEP_CHR
                                               /* LSType    */ SEP_CHR
                            "%" PRIu16         /* tlvType   */ SEP_CHR
                            "0x%08" B2T_PRIX32 /* tlvValOpt */ "\n"
                            , numPackets
                            , ver
                            , areaID
                            , inet_ntoa(ospfHdrP->routerID)
                            , ntohs(lls->tlvType)
                            , ntohl(lls->tlvVal));
                }
#endif // OSPF_OUTPUT_DBD == 1
            } // ver == 2
#if IPV6_ACTIVATE == 2
            else { // ver == 3
#endif // IPV6_ACTIVATE == 2
#endif // (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
#if IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 1
            if (ver == 3) {
#endif // IPV6_ACTIVATE == 1
                if (ospfPktLen < OSPF3_HDR_LEN + OSPF3_DBD_LEN) {
                    ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                    OSPF_SPKTMD_PRI_3(ospfFlowP, ver, areaID, type, xlsType);
                    return;
                }

                uint16_t dataLen = ospfPktLen - OSPF3_HDR_LEN - OSPF3_DBD_LEN;
                size_t offset = 0;
                while (dataLen > 0) {
                    const ospf3DBD_t * const dbd = (ospf3DBD_t*)&(ospf3HdrP->data);
                    const ospfLSA_t * const lsa = (ospfLSA_t*)(&(dbd->lsaHdr) + offset);
                    const uint16_t lsType = ntohs(lsa->ls3Type) & 0x1fff;
                    if (lsType > 0 && lsType < OSPF3_LSTYPE_N) {
                        numOSPF3LSType[lsType]++;
#if OSPF_OUTPUT_DBD == 1
                        const uint16_t lsAge = ntohs(lsa->lsAge);
                        fprintf(ospfDBDFile,
                                "%" PRIu64        /* pktNo   */ SEP_CHR
                                "%" PRIuFAST8     /* Ver     */ SEP_CHR
                                "%" OSPF_PRI_AREA /* AreaID  */ SEP_CHR
                                "%s"              /* RtrID   */ SEP_CHR
                                , numPackets
                                , ver
                                , areaID
                                , inet_ntoa(ospf3HdrP->routerID));

                        fprintf(ospfDBDFile,
                                "%s" /* LSLinkID */ SEP_CHR
                                , inet_ntoa(lsa->lsaID));

                        fprintf(ospfDBDFile,
                                "%s"                /* ADVRouter */ SEP_CHR
                                "%d"                /* Dna       */ SEP_CHR
                                "%d"                /* Age       */ SEP_CHR
                                "0x%08" B2T_PRIX32  /* SeqNum    */ SEP_CHR
                                "0x%04" B2T_PRIX16  /* Checksum  */ SEP_CHR
                                "%" PRIu16          /* MTU       */ SEP_CHR
                                "0x%04" B2T_PRIX16  /* Flags     */ SEP_CHR
                                "%" OSPF_PRI_LSTYPE /* LSType    */ SEP_CHR
                                                    /* tlvType   */ SEP_CHR
                                                    /* tlvValOpt */ "\n"
                                , inet_ntoa(lsa->advRtr)
                                , lsAge >> 15
                                , lsAge & 0x7fff
                                , ntohl(lsa->lsSeqNum)
                                , ntohs(lsa->lsChksum)
                                , ntohs(dbd->intMTU)
                                , dbd->dbDesc
#if OSPF_LSTYP_STR == 1
                                , OSPF3_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                , lsType
#endif // OSPF_LSTYP_STR
                        );
#endif // OSPF_OUTPUT_DBD == 1

                        dataLen -= sizeof(*lsa);
                        offset += sizeof(*lsa);
                    } else {
                        ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                        if (ver == 2) numOSPF2LSType[0]++;
                        else numOSPF3LSType[0]++;
                        // invalid record, abort processing of record
                        break;
                    }
                }
            } // ver == 3
#endif // IPV6_ACTIVATE > 0
            break;
        }

        case OSPF_LS_REQ: {
#if (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
            if (ver == 2) {
                if (ospfPktLen < OSPF2_HDR_LEN + sizeof(ospfLSR_t)) {
                    ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                    OSPF_SPKTMD_PRI_3(ospfFlowP, ver, areaID, type, xlsType);
                    return;
                }

                const uint16_t numLSR = (ospfPktLen - OSPF2_HDR_LEN) / sizeof(ospfLSR_t);
                for (uint_fast16_t j = 0; j < numLSR; j++) {
                    if (snaplen < OSPF2_HDR_LEN + j * sizeof(ospfLSR_t)) {
                        OSPF_SPKTMD_PRI_3(ospfFlowP, ver, areaID, type, xlsType);
                        return;
                    }
                    const ospfLSR_t * const lsr = (ospfLSR_t*)(&ospfHdrP->data+j*sizeof(ospfLSR_t));
                    const uint32_t lsType = ntohl(lsr->lsType);
                    if (lsType > 0 && lsType < OSPF_LSTYPE_N) {
                        numOSPF2LSType[lsType]++;
#if OSPF_OUTPUT_MSG == 1
                        fprintf(ospf2MsgFile,
                                "%" PRIu64          /* pktNo   */ SEP_CHR
                                "%" PRIuFAST8       /* Ver     */ SEP_CHR
                                "%" OSPF_PRI_AREA   /* Area    */ SEP_CHR
                                "%" OSPF_PRI_LSTYPE /* MsgType */ SEP_CHR
                                "%" OSPF_PRI_LSTYPE /* LSType  */ SEP_CHR
                                "%s"                /* srcIP   */ SEP_CHR
                                , numPackets
                                , ver
                                , areaID
#if OSPF_LSTYP_STR == 1
                                , OSPF_TYPE_TO_STR(type)
                                , OSPF2_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                , type
                                , lsType
#endif // OSPF_LSTYP_STR
                                , saddr);

                        fprintf(ospf2MsgFile,
#if OSPF_MASK_AS_IP == 1
                                "%s"       /* LSLinkID          */ SEP_CHR
#else // OSPF_MASK_AS_IP == 0
                                "%" PRIu32 /* LSLinkID          */ SEP_CHR
#endif // OSPF_MASK_AS_IP
                                           /* NetmaskOrRouterIP */ SEP_CHR
#if OSPF_MASK_AS_IP == 1
                                , inet_ntoa(lsr->lsID)
#else // OSPF_MASK_AS_IP == 0
                                , ntohl(lsr->lsID.s_addr)
#endif // OSPF_MASK_AS_IP
                        );

                        fprintf(ospf2MsgFile,
                                "%s" /* ADVRouter */ SEP_CHR
                                     /* LSAOpt    */ SEP_CHR
                                     /* LnkType   */ SEP_CHR
                                     /* Metric    */ SEP_CHR
                                     /* IfaceType */ SEP_CHR
                                     /* LSFlgs    */ SEP_CHR
                                     /* AttchRtrs */ SEP_CHR
                                     /* FwdIP     */ SEP_CHR
                                     /* ExtRtTag  */ "\n"
                                , inet_ntoa(lsr->advRtr));
#endif // OSPF_OUTPUT_MSG == 1
                    } else {
                        ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                        numOSPF2LSType[0]++;
                    }
                }
            } // ver == 2
#if IPV6_ACTIVATE == 2
            else { // ver == 3
#endif // IPV6_ACTIVATE == 2
#endif // (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
#if IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 1
            if (ver == 3) {
#endif // IPV6_ACTIVATE == 1
                if (ospfPktLen < OSPF3_HDR_LEN + sizeof(ospfLSR_t)) {
                    ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                    OSPF_SPKTMD_PRI_3(ospfFlowP, ver, areaID, type, xlsType);
                    return;
                }

                const uint16_t numLSR = (ospfPktLen - OSPF3_HDR_LEN)/sizeof(ospfLSR_t);
                for (uint_fast16_t j = 0; j < numLSR; j++) {
                    if (snaplen < OSPF3_HDR_LEN + j * sizeof(ospfLSR_t)) {
                        OSPF_SPKTMD_PRI_3(ospfFlowP, ver, areaID, type, xlsType);
                        return;
                    }
                    const ospfLSR_t * const lsr = (ospfLSR_t*)(&ospf3HdrP->data+j*sizeof(ospfLSR_t));
                    const uint32_t lsType = ntohl(lsr->lsType) & 0x00001fff;
                    if (lsType > 0 && lsType < OSPF3_LSTYPE_N) {
                        numOSPF3LSType[lsType]++;
#if OSPF_OUTPUT_MSG == 1
                        fprintf(ospf3MsgFile,
                                "%" PRIu64          /* pktNo   */ SEP_CHR
                                "%" PRIuFAST8       /* Ver     */ SEP_CHR
                                "%" OSPF_PRI_AREA   /* Area    */ SEP_CHR
                                "%s"                /* SrcRtr  */ SEP_CHR
                                "%" OSPF_PRI_LSTYPE /* MsgType */ SEP_CHR
                                "%" OSPF_PRI_LSTYPE /* LSType  */ SEP_CHR
                                "%s"                /* srcIP   */ SEP_CHR
                                "%s"                /* dstIP   */ SEP_CHR
                                , numPackets
                                , ver
                                , areaID
                                , inet_ntoa(ospfHdrP->routerID)
#if OSPF_LSTYP_STR == 1
                                , OSPF_TYPE_TO_STR(type)
                                , OSPF3_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                , type
                                , lsType
#endif // OSPF_LSTYP_STR
                                , saddr
                                , daddr);

                        fprintf(ospf3MsgFile,
                                "%s" /* LSAAdvRtr */ SEP_CHR
                                "-"  /* LSAOpts   */ SEP_CHR
                                , inet_ntoa(lsr->advRtr));

#if OSPF_LSID_AS_IP == 1
                        fprintf(ospf3MsgFile,
                                "%s" /* LSLinkID */ SEP_CHR
                                , inet_ntoa(lsr->lsID));
#else // OSPF_LSID_AS_IP == 0
                        fprintf(ospf3MsgFile,
                                "%" PRIu32 /* LSLinkID */ SEP_CHR
                                , ntohl(lsr->lsID.s_addr));
#endif // OSPF_LSID_AS_IP

                        fputs("-"  /* IntID                 */ SEP_CHR
                              "-"  /* NeighIntID            */ SEP_CHR
                                   /* RefAdvRtrOrAttchRtrs  */ SEP_CHR
                                   /* Type                  */ SEP_CHR
                                   /* PrefOpts              */ SEP_CHR
                                   /* Metric                */ SEP_CHR
                                   /* RefLSA                */ SEP_CHR
                                   /* RefPrefix             */ SEP_CHR
                                   /* LnkLclIPOrFwdIP       */ SEP_CHR
                                   /* ExtRtTag              */ "\n"
                                , ospf3MsgFile);
#endif // OSPF_OUTPUT_MSG == 1
                    } else {
                        ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                        numOSPF3LSType[0]++;
                    }
                }
            } // ver == 3
#endif // IPV6_ACTIVATE > 0
            break;
        }

        case OSPF_LS_UPDATE: {
            ospfLSU_t *lsu;
            if (ver == 2) {
                if (ospfPktLen < OSPF2_HDR_LEN + sizeof(ospfLSU_t)) {
                    ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                    OSPF_SPKTMD_PRI_3(ospfFlowP, ver, areaID, type, xlsType);
                    return;
                }
                lsu = (ospfLSU_t*)&(ospfHdrP->data);
            } else { // ver == 3
                if (ospfPktLen < OSPF3_HDR_LEN + sizeof(ospfLSU_t)) {
                    ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                    OSPF_SPKTMD_PRI_3(ospfFlowP, ver, areaID, type, xlsType);
                    return;
                }
                lsu = (ospfLSU_t*)&(ospfHdrP->auField);
            }
            const uint32_t numLSA = ntohl(lsu->numLSA);
            int32_t lsaLen;
            uint16_t lsType;

            const ospfLSA_t *lsa = (ospfLSA_t*)&(lsu->lsaHdr);

            for (uint_fast32_t i = 0; i < numLSA && (uint8_t*)lsa <= packet->end_packet - sizeof(*lsa); i++) {
                lsaLen = ntohs(lsa->lsLen);
                if (ver == 2) {
                    lsType = lsa->lsType & 0xff;
                    if (lsType > 0 && lsType < OSPF_LSTYPE_N) numOSPF2LSType[lsType]++;
                } else {
                    lsType = ntohs(lsa->ls3Type) & 0x1fff;
                    if (lsType > 0 && lsType < OSPF3_LSTYPE_N) numOSPF3LSType[lsType]++;
                }
                xlsType |= (1 << lsType);

                switch (lsType) {
#if OSPF_OUTPUT_MSG == 1
                    case OSPF_LSTYPE_ROUTER: { // 1
#if (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
                        if (ver == 2) {
                            const ospfRouterLSA_t * const rlsa = (ospfRouterLSA_t*)(lsa);
                            const uint16_t numLinks = ntohl(rlsa->flgs_numLnks) & 0x0000ffff;
                            const ospfRouterLSALink_t *link = (ospfRouterLSALink_t*) &rlsa->rInt;
                            for (uint_fast16_t j = 0; j < numLinks && (uint8_t*)link <= packet->end_packet - sizeof(*link); j++) {
                                fprintf(ospf2MsgFile,
                                        "%" PRIu64          /* pktNo    */ SEP_CHR
                                        "%" PRIuFAST8       /* Ver      */ SEP_CHR
                                        "%" OSPF_PRI_AREA   /* Area     */ SEP_CHR
                                        "%" OSPF_PRI_LSTYPE /* MsgType  */ SEP_CHR
                                        "%" OSPF_PRI_LSTYPE /* LSType   */ SEP_CHR
                                        "%s"                /* srcIP    */ SEP_CHR
                                        "%s"                /* LSLinkID */ SEP_CHR
                                        , numPackets
                                        , ver
                                        , areaID
#if OSPF_LSTYP_STR == 1
                                        , OSPF_TYPE_TO_STR(type)
                                        , OSPF2_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                        , type
                                        , lsType
#endif // OSPF_LSTYP_STR
                                        , saddr
                                        , inet_ntoa(link->linkID));

                                if (link->type == OSPF_LINK_STUB) { // linkData is the netmask
#if OSPF_LSID_AS_IP == 1
                                   fprintf(ospf2MsgFile,
                                           "%s" /* NetmaskOrRouterIP */ SEP_CHR
                                           , inet_ntoa(*(struct in_addr*)&link->linkData));
#else // OSPF_LSID_AS_IP == 0
                                   fprintf(ospf2MsgFile,
                                           "%" PRIu32 /* NetmaskOrRouterIP */ SEP_CHR
                                           , ntohl(link->linkData));
#endif // OSPF_LSID_AS_IP
                                } else { // linkData is the router IP
                                   fprintf(ospf2MsgFile,
                                           "%s" /* NetmaskOrRouterIP */ SEP_CHR
                                           , inet_ntoa(*(struct in_addr*)&(link->linkData)));
                                }

                                fprintf(ospf2MsgFile,
                                        "%s"                /* ADVRouter */ SEP_CHR
                                        "0x%02" B2T_PRIX8   /* LSAOpt    */ SEP_CHR
                                        "%" OSPF_PRI_LSTYPE /* LnkType   */ SEP_CHR
                                        "%" PRIu16          /* Metric    */ SEP_CHR
                                                            /* IfaceType */ SEP_CHR
                                        "0x%02" B2T_PRIX8   /* LSFlgs    */ SEP_CHR
                                                            /* AttchRtrs */ SEP_CHR
                                                            /* FwdIP     */ SEP_CHR
                                                            /* ExtRtTag  */ "\n"
                                        , inet_ntoa(lsa->advRtr)
                                        , lsa->opts
#if OSPF_LSTYP_STR == 1
                                        , OSPF_LINK_TYPE_TO_STR(link->type)
#else // OSPF_LSTYP_STR == 0
                                        , link->type
#endif // OSPF_LSTYP_STR
                                        , ntohs(link->metric)
                                        , (uint8_t)(rlsa->flgs_numLnks & 0xff));
                                link++;
                            }
                        } // ver == 2
#if IPV6_ACTIVATE == 2
                        else { // ver == 3
#endif // IPV6_ACTIVATE == 2
#endif // (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
#if IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 1
                        if (ver == 3) {
#endif // IPV6_ACTIVATE == 1
                            const ospf3RouterLSA_t * const rlsa = (ospf3RouterLSA_t*)(lsa);
                            ospf3RouterLSAInt_t *rInt = (ospf3RouterLSAInt_t*)&rlsa->rInt;
                            int32_t i = lsaLen - sizeof(ospfLSA_t) - 4;
                            while (i > 0 && (uint8_t*)rInt <= packet->end_packet - sizeof(*rInt)) {
                                fprintf(ospf3MsgFile,
                                        "%" PRIu64          /* pktNo   */ SEP_CHR
                                        "%" PRIuFAST8       /* Ver     */ SEP_CHR
                                        "%" OSPF_PRI_AREA   /* Area    */ SEP_CHR
                                        "%s"                /* SrcRtr  */ SEP_CHR
                                        "%" OSPF_PRI_LSTYPE /* MsgType */ SEP_CHR
                                        "%" OSPF_PRI_LSTYPE /* LSType  */ SEP_CHR
                                        "%s"                /* srcIP   */ SEP_CHR
                                        "%s"                /* dstIP   */ SEP_CHR
                                        , numPackets
                                        , ver
                                        , areaID
                                        , inet_ntoa(ospfHdrP->routerID)
#if OSPF_LSTYP_STR == 1
                                        , OSPF_TYPE_TO_STR(type)
                                        , OSPF3_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                        , type
                                        , lsType
#endif // OSPF_LSTYP_STR
                                        , saddr
                                        , daddr);

                                fprintf(ospf3MsgFile,
                                        "%s"               /* LSAAdvRtr */ SEP_CHR
                                        "0x%08" B2T_PRIX32 /* LSAOpts   */ SEP_CHR
                                                           /* LSLinkID  */ SEP_CHR
                                        , inet_ntoa(lsa->advRtr)
                                        , ntohl(rlsa->flgs_opt));

                                fprintf(ospf3MsgFile,
                                        "%s" /* IntID */ SEP_CHR
                                        , inet_ntoa(*(struct in_addr*)&(rInt->intID)));

                                fprintf(ospf3MsgFile,
                                        "%s" /* NeighIntID */ SEP_CHR
                                        , inet_ntoa(*(struct in_addr*)&(rInt->neighIntID)));

                                fprintf(ospf3MsgFile,
                                        "%s"                /* RefAdvRtrOrAttchRtrs  */ SEP_CHR
                                        "%" OSPF_PRI_LSTYPE /* Type                  */ SEP_CHR
                                                            /* PrefOpts              */ SEP_CHR
                                        "%" PRIu16          /* Metric                */ SEP_CHR
                                                            /* RefLSA                */ SEP_CHR
                                                            /* RefPrefix             */ SEP_CHR
                                                            /* LnkLclIPOrFwdIP       */ SEP_CHR
                                                            /* ExtRtTag              */ "\n"
                                        , inet_ntoa(rInt->neighIntRtrID)
#if OSPF_LSTYP_STR == 1
                                        , OSPF_LINK_TYPE_TO_STR(rInt->type)
#else // OSPF_LSTYP_STR == 0
                                        , rInt->type
#endif // OSPF_LSTYP_STR
                                        , ntohs(rInt->metric));
                                rInt++;
                                i -= sizeof(ospf3RouterLSAInt_t);
                            }
                        } // ver == 3
#endif // IPV6_ACTIVATE > 0
                        break;
                    }

                    case OSPF_LSTYPE_NETWORK: { // 2
#if (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
                        if (ver == 2) {
                            const ospfNetworkLSA_t * const nlsa = (ospfNetworkLSA_t*)(lsa);
                            fprintf(ospf2MsgFile,
                                    "%" PRIu64          /* pktNo   */ SEP_CHR
                                    "%" PRIuFAST8       /* Ver     */ SEP_CHR
                                    "%" OSPF_PRI_AREA   /* Area    */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* MsgType */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* LSType  */ SEP_CHR
                                    "%s"                /* srcIP   */ SEP_CHR
                                    , numPackets
                                    , ver
                                    , areaID
#if OSPF_LSTYP_STR == 1
                                    , OSPF_TYPE_TO_STR(type)
                                    , OSPF2_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                    , type
                                    , lsType
#endif // OSPF_LSTYP_STR
                                    , saddr);

#if OSPF_LSID_AS_IP == 1
                            fprintf(ospf2MsgFile,
                                    "%s" /* LSLinkID */ SEP_CHR
                                    , inet_ntoa(lsa->lsaID));
#else // OSPF_LSID_AS_IP == 0
                            fprintf(ospf2MsgFile,
                                    "%" PRIu32 /* LSLinkID */ SEP_CHR
                                    , ntohl(lsa->lsaID.s_addr));
#endif // OSPF_LSID_AS_IP

#if OSPF_MASK_AS_IP == 1
                            fprintf(ospf2MsgFile,
                                    "%s" /* NetmaskOrRouterIP */ SEP_CHR
                                    , inet_ntoa(*(struct in_addr*)&nlsa->netmask));
#else // OSPF_MASK_AS_IP == 0
                            fprintf(ospf2MsgFile,
                                    "0x%08" B2T_PRIX32 /* NetmaskOrRouterIP */ SEP_CHR
                                    , ntohl(nlsa->netmask));
#endif // OSPF_MASK_AS_IP

                            fprintf(ospf2MsgFile,
                                    "%s"              /* ADVRouter */ SEP_CHR
                                    "0x%02" B2T_PRIX8 /* LSAOpt    */ SEP_CHR
                                    , inet_ntoa(lsa->advRtr)
                                    , lsa->opts);

                            const int32_t nr = (ntohs(lsa->lsLen) - OSPF2_LSA_LEN) / sizeof(uint32_t) - 1;
                            fputs(/* LnkType   */ SEP_CHR
                                  /* Metric    */ SEP_CHR
                                  /* IfaceType */ SEP_CHR
                                  /* LSFlgs    */ SEP_CHR
                                  , ospf2MsgFile);

                            for (int32_t j = 1; j <= nr; j++) {
                                fprintf(ospf2MsgFile,
                                        "%s%s" /* AttchRtrs */
                                        , inet_ntoa(*(struct in_addr*)(&nlsa->router+(j-1)))
                                        , ((j < nr) ? ";" : ""));
                            }

                            fputs(/* AttchRtrs */ SEP_CHR
                                  /* FwdIP     */ SEP_CHR
                                  /* ExtRtTag  */ "\n"
                                  , ospf2MsgFile);
                        } // ver == 2
#if IPV6_ACTIVATE == 2
                        else { // ver == 3
#endif // IPV6_ACTIVATE == 2
#endif // (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
#if IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 1
                        if (ver == 3) {
#endif // IPV6_ACTIVATE == 1
                            const ospf3NetworkLSA_t * const rlsa = (ospf3NetworkLSA_t*)(lsa);
                            struct in_addr *rInt = (struct in_addr*)&rlsa->router;
                            int32_t i = lsaLen - sizeof(ospfLSA_t) - 4;
                            fprintf(ospf3MsgFile,
                                    "%" PRIu64          /* pktNo     */ SEP_CHR
                                    "%" PRIuFAST8       /* Ver       */ SEP_CHR
                                    "%" OSPF_PRI_AREA   /* Area      */ SEP_CHR
                                    "%s"                /* SrcRtr    */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* MsgType   */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* LSType    */ SEP_CHR
                                    "%s"                /* srcIP     */ SEP_CHR
                                    "%s"                /* dstIP     */ SEP_CHR
                                    "%s"                /* LSAAdvRtr */ SEP_CHR
                                    "0x%08" B2T_PRIX32  /* LSAOpts   */ SEP_CHR
                                    , numPackets
                                    , ver
                                    , areaID
                                    , inet_ntoa(ospfHdrP->routerID)
#if OSPF_LSTYP_STR == 1
                                    , OSPF_TYPE_TO_STR(type)
                                    , OSPF3_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                    , type
                                    , lsType
#endif // OSPF_LSTYP_STR
                                    , saddr
                                    , daddr
                                    , inet_ntoa(lsa->advRtr)
                                    , ntohl(rlsa->opts));

#if OSPF_LSID_AS_IP == 1
                            fprintf(ospf3MsgFile,
                                    "%s" /* LSLinkID */ SEP_CHR
                                    , inet_ntoa(lsa->lsaID));
#else // OSPF_LSID_AS_IP == 0
                            fprintf(ospf3MsgFile,
                                    "%" PRIu32 /* LSLinkID */ SEP_CHR
                                    , ntohl(lsa->lsaID.s_addr));
#endif // OSPF_LSID_AS_IP

                            fprintf(ospf3MsgFile,
                                    "-" /* IntID      */ SEP_CHR
                                    "-" /* NeighIntID */ SEP_CHR);

                            while (i > 0 && (uint8_t*)rInt <= packet->end_packet - sizeof(uint32_t)) {
#if OSPF_MASK_AS_IP == 1
                                fprintf(ospf3MsgFile,
                                        "%s" /* RefAdvRtrOrAttchRtrs */
                                        , inet_ntoa(*rInt));
#else // OSPF_MASK_AS_IP == 0
                                fprintf(ospf3MsgFile,
                                        "0x%08" B2T_PRIX32 /* RefAdvRtrOrAttchRtrs */
                                        , ntohl(rInt->s_addr));
#endif // OSPF_MASK_AS_IP
                                if (i > 4) putc(';' /* RefAdvRtrOrAttchRtrs */, ospf3MsgFile);

                                rInt++;
                                i -= sizeof(struct in_addr);
                            }

                            fputs(/* RefAdvRtrOrAttchRtrs  */ SEP_CHR
                                  /* Type                  */ SEP_CHR
                                  /* PrefOpts              */ SEP_CHR
                                  /* Metric                */ SEP_CHR
                                  /* RefLSA                */ SEP_CHR
                                  /* RefPrefix             */ SEP_CHR
                                  /* LnkLclIPOrFwdIP       */ SEP_CHR
                                  /* ExtRtTag              */ "\n"
                                  , ospf3MsgFile);
                        } // ver == 3
#endif // IPV6_ACTIVATE > 0
                        break;
                    }

                    case OSPF_LSTYPE_SUMMARY: // OSPF3_LT3_INT_A_PREF, 3
#if (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
                        if (ver == 2) {
                            /* FALLTHRU */
                            __attribute__((fallthrough));  // silence warning
                        } // ver == 2
#if IPV6_ACTIVATE == 0
                        else break; // ver == 3
#else // IPV6_ACTIVATE == 2
                        else { // ver == 3
#endif // IPV6_ACTIVATE == 2
#endif // (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
#if IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 1
                        if (ver == 3) {
#endif // IPV6_ACTIVATE == 1
                            const ospf3IntAreaPref3LSA_t * const rlsa = (ospf3IntAreaPref3LSA_t*)(lsa);
                            fprintf(ospf3MsgFile,
                                    "%" PRIu64          /* pktNo   */ SEP_CHR
                                    "%" PRIuFAST8       /* Ver     */ SEP_CHR
                                    "%" OSPF_PRI_AREA   /* Area    */ SEP_CHR
                                    "%s"                /* SrcRtr  */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* MsgType */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* LSType  */ SEP_CHR
                                    "%s"                /* srcIP   */ SEP_CHR
                                    "%s"                /* dstIP   */ SEP_CHR
                                    , numPackets
                                    , ver
                                    , areaID
                                    , inet_ntoa(ospfHdrP->routerID)
#if OSPF_LSTYP_STR == 1
                                    , OSPF_TYPE_TO_STR(type)
                                    , OSPF3_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                    , type
                                    , lsType
#endif // OSPF_LSTYP_STR
                                    , saddr
                                    , daddr);

                            fprintf(ospf3MsgFile,
                                    "%s" /* LSAAdvRtr */ SEP_CHR
                                         /* LSAOpts   */ SEP_CHR
                                    , inet_ntoa(lsa->advRtr));

#if OSPF_LSID_AS_IP == 1
                            fprintf(ospf3MsgFile,
                                    "%s" /* LSLinkID */ SEP_CHR
                                    , inet_ntoa(lsa->lsaID));
#else // OSPF_LSID_AS_IP == 0
                            fprintf(ospf3MsgFile,
                                    "%" PRIu32 /* LSLinkID */ SEP_CHR
                                    , ntohl(lsa->lsaID.s_addr));
#endif // OSPF_LSID_AS_IP

                            ipAddr_t ip = {};
                            const uint32_t *u = (uint32_t*)&rlsa->addrPref;
                            if (rlsa->prefLen >  0) ip.IPv4x[0] = *u++;
                            if (rlsa->prefLen > 32) ip.IPv4x[1] = *u++;
                            if (rlsa->prefLen > 64) ip.IPv4x[2] = *u++;
                            if (rlsa->prefLen > 96) ip.IPv4x[3] = *u;

                            char addr[INET6_ADDRSTRLEN];
                            inet_ntop(AF_INET6, &ip, addr, INET6_ADDRSTRLEN);
                            fprintf(ospf3MsgFile,
                                                      /* IntID                 */ SEP_CHR
                                                      /* NeightIntID           */ SEP_CHR
                                    "%s/%" PRIu8      /* RefAdvRtrOrAttchRtrs  */ SEP_CHR
                                                      /* Type                  */ SEP_CHR
                                    "0x%02" B2T_PRIX8 /* PrefOpts              */ SEP_CHR
                                    "%" PRIu32        /* Metric                */ SEP_CHR
                                                      /* RefLSA                */ SEP_CHR
                                                      /* RefPrefix             */ SEP_CHR
                                                      /* LnkLclIPOrFwdIP       */ SEP_CHR
                                                      /* ExtRtTag              */ "\n"
                                    , addr, rlsa->prefLen
                                    , rlsa->prefOpt
                                    , ntohl(rlsa->metric));
                            break;
                        } // ver == 3
#if IPV6_ACTIVATE == 1
                        break;
#endif // IPV6_ACTIVATE == 1
#endif // IPV6_ACTIVATE > 0

                    case OSPF_LSTYPE_ASBR: {  // OSPF3_LT3_INT_A_RTR, 4
#if (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
                        if (ver == 2) {
                            const ospfSummaryLSA_t * const slsa = (ospfSummaryLSA_t*)(lsa);
                            fprintf(ospf2MsgFile,
                                    "%" PRIu64          /* pktNo   */ SEP_CHR
                                    "%" PRIuFAST8       /* Ver     */ SEP_CHR
                                    "%" OSPF_PRI_AREA   /* Area    */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* MsgType */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* LSType  */ SEP_CHR
                                    "%s"                /* srcIP   */ SEP_CHR
                                    , numPackets
                                    , ver
                                    , areaID
#if OSPF_LSTYP_STR == 1
                                    , OSPF_TYPE_TO_STR(type)
                                    , OSPF2_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                    , type
                                    , lsType
#endif // OSPF_LSTYP_STR
                                    , saddr);

#if OSPF_LSID_AS_IP == 1
                            fprintf(ospf2MsgFile,
                                    "%s" /* LSLinkID */ SEP_CHR
                                    , inet_ntoa(lsa->lsaID));
#else // OSPF_LSID_AS_IP == 0
                            fprintf(ospf2MsgFile,
                                    "%" PRIu32 /* LSLinkID */ SEP_CHR
                                    , ntohl(lsa->lsaID.s_addr));
#endif // OSPF_LSID_AS_IP

#if OSPF_MASK_AS_IP == 1
                            fprintf(ospf2MsgFile,
                                    "%s" /* NetmaskOrRouterIP */ SEP_CHR
                                    , inet_ntoa(*(struct in_addr*)&slsa->netmask));
#else // OSPF_MASK_AS_IP == 0
                            fprintf(ospf2MsgFile,
                                    "0x%08" B2T_PRIX32 /* NetmaskOrRouterIP */ SEP_CHR
                                    , ntohl(slsa->netmask));
#endif // OSPF_MASK_AS_IP

                            fprintf(ospf2MsgFile,
                                    "%s"              /* ADVRouter */ SEP_CHR
                                    "0x%02" B2T_PRIX8 /* LSAOpt    */ SEP_CHR
                                    "%" PRIu32        /* LnkType   */ SEP_CHR
                                    "%" PRIu32        /* Metric    */ SEP_CHR
                                                      /* IfaceType */ SEP_CHR
                                                      /* LSFlgs    */ SEP_CHR
                                                      /* AttchRtrs */ SEP_CHR
                                                      /* FwdIP     */ SEP_CHR
                                                      /* ExtRtTag  */ "\n"
                                    , inet_ntoa(lsa->advRtr)
                                    , lsa->opts
                                    , slsa->tos_tmtrc & 0xff
                                    , ntohl(slsa->tos_tmtrc) & 0x00ffffff);
                        } // ver == 2
#if IPV6_ACTIVATE == 2
                        else { // ver == 3
#endif // IPV6_ACTIVATE == 2
#endif // (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
#if IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 1
                        if (ver == 3) {
#endif // IPV6_ACTIVATE == 1
                            const ospf3IntAreaRtr4LSA_t * const rlsa = (ospf3IntAreaRtr4LSA_t*)(lsa);
                            fprintf(ospf3MsgFile,
                                    "%" PRIu64          /* pktNo     */ SEP_CHR
                                    "%" PRIuFAST8       /* Ver       */ SEP_CHR
                                    "%" OSPF_PRI_AREA   /* Area      */ SEP_CHR
                                    "%s"                /* SrcRtr    */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* MsgType   */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* LSType    */ SEP_CHR
                                    "%s"                /* srcIP     */ SEP_CHR
                                    "%s"                /* dstIP     */ SEP_CHR
                                    , numPackets
                                    , ver
                                    , areaID
                                    , inet_ntoa(ospfHdrP->routerID)
#if OSPF_LSTYP_STR == 1
                                    , OSPF_TYPE_TO_STR(type)
                                    , OSPF3_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                    , type
                                    , lsType
#endif // OSPF_LSTYP_STR
                                    , saddr
                                    , daddr);

                            fprintf(ospf3MsgFile,
                                    "%s" /* LSAAdvRtr */ SEP_CHR
                                         /* LSAOpts   */ SEP_CHR
                                    , inet_ntoa(lsa->advRtr));

#if OSPF_LSID_AS_IP == 1
                            fprintf(ospf3MsgFile,
                                    "%s" /* LSLinkID */ SEP_CHR
                                    , inet_ntoa(lsa->lsaID));
#else // OSPF_LSID_AS_IP == 0
                            fprintf(ospf3MsgFile,
                                    "%" PRIu32 /* LSLinkID */ SEP_CHR
                                    , ntohl(lsa->lsaID.s_addr));
#endif // OSPF_LSID_AS_IP

                            fputs(/* IntID      */ SEP_CHR
                                  /* NeighIntID */ SEP_CHR
                                  , ospf3MsgFile);

#if OSPF_MASK_AS_IP == 1
                            fprintf(ospf3MsgFile,
                                    "%s" /* RefAdvRtrOrAttchRtrs */ SEP_CHR
                                    , inet_ntoa(*(struct in_addr*)&rlsa->destRtrID));
#else // OSPF_MASK_AS_IP == 0
                            fprintf(ospf3MsgFile,
                                    "0x%08" B2T_PRIX32 /* RefAdvRtrOrAttchRtrs */ SEP_CHR
                                    , ntohl(rlsa->destRtrID));
#endif // OSPF_MASK_AS_IP

                            fprintf(ospf3MsgFile,
                                                       /* Type            */ SEP_CHR
                                    "0x%08" B2T_PRIX32 /* PrefOpts        */ SEP_CHR
                                    "%" PRIu32         /* Metric          */ SEP_CHR
                                                       /* RefLSA          */ SEP_CHR
                                                       /* RefPrefix       */ SEP_CHR
                                                       /* LnkLclIPOrFwdIP */ SEP_CHR
                                                       /* ExtRtTag        */ "\n"
                                    , rlsa->opts
                                    , ntohl(rlsa->metric));
                        } // ver == 3
#endif // IPV6_ACTIVATE > 0
                        break;
                    }

                    case OSPF_LSTYPE_ASEXT: { // OSPF3_AS_EXT, 5
#if (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
                        if (ver == 2) {
                            const ospfASExtLSA_t * const elsa = (ospfASExtLSA_t*)(lsa);
                            fprintf(ospf2MsgFile,
                                    "%" PRIu64          /* pktNo   */ SEP_CHR
                                    "%" PRIuFAST8       /* Ver     */ SEP_CHR
                                    "%" OSPF_PRI_AREA   /* Area    */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* MsgType */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* LSType  */ SEP_CHR
                                    "%s"                /* srcIP   */ SEP_CHR
                                    , numPackets
                                    , ver
                                    , areaID
#if OSPF_LSTYP_STR == 1
                                    , OSPF_TYPE_TO_STR(type)
                                    , OSPF2_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                    , type
                                    , lsType
#endif // OSPF_LSTYP_STR
                                    , saddr);

#if OSPF_LSID_AS_IP == 1
                            fprintf(ospf2MsgFile,
                                    "%s" /* LSLinkID */ SEP_CHR
                                    , inet_ntoa(lsa->lsaID));
#else // OSPF_LSID_AS_IP == 0
                            fprintf(ospf2MsgFile,
                                    "%" PRIu32 /* LSLinkID */ SEP_CHR
                                    , ntohl(lsa->lsaID.s_addr));
#endif // OSPF_LSID_AS_IP

#if OSPF_MASK_AS_IP == 1
                            fprintf(ospf2MsgFile,
                                    "%s" /* NetmaskOrRouterIP */ SEP_CHR
                                    , inet_ntoa(*(struct in_addr*)&elsa->netmask));
#else // OSPF_MASK_AS_IP == 0
                            fprintf(ospf2MsgFile,
                                    "0x%08" B2T_PRIX32 /* NetmaskOrRouterIP */ SEP_CHR
                                    , ntohl(elsa->netmask));
#endif // OSPF_MASK_AS_IP

                            fprintf(ospf2MsgFile,
                                    "%s"              /* ADVRouter */ SEP_CHR
                                                      /* LSAOpt    */ SEP_CHR
                                    "%" PRIu32        /* LnkType   */ SEP_CHR
                                    "0x%02" B2T_PRIX8 /* Metric    */ SEP_CHR
                                                      /* IfaceType */ SEP_CHR
                                                      /* LSFlgs    */ SEP_CHR
                                                      /* AttchRtrs */ SEP_CHR
                                    "%s"              /* FwdIP     */ SEP_CHR
                                    "%" PRIu32        /* ExtRtTag  */ "\n"
                                    , inet_ntoa(lsa->advRtr)
                                    , elsa->e_tos_mtrc & 0x80
                                    , ntohl(elsa->e_tos_mtrc) & 0x00ffffff
                                    , inet_ntoa(elsa->forwardAddr)
                                    , ntohl(elsa->extRtTg));
                        } // ver == 2
#if IPV6_ACTIVATE == 2
                        else { // ver == 3
#endif // IPV6_ACTIVATE == 2
#endif // (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
#if IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 1
                        if (ver == 3) {
#endif // IPV6_ACTIVATE == 1
                            fprintf(ospf3MsgFile,
                                    "%" PRIu64          /* pktNo   */ SEP_CHR
                                    "%" PRIuFAST8       /* Ver     */ SEP_CHR
                                    "%" OSPF_PRI_AREA   /* Area    */ SEP_CHR
                                    "%s"                /* SrcRtr  */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* msgType */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* LSType  */ SEP_CHR
                                    "%s"                /* srcIP   */ SEP_CHR
                                    "%s"                /* dstIP   */ SEP_CHR
                                    , numPackets
                                    , ver
                                    , areaID
                                    , inet_ntoa(ospfHdrP->routerID)
#if OSPF_LSTYP_STR == 1
                                    , OSPF_TYPE_TO_STR(type)
                                    , OSPF3_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                    , type
                                    , lsType
#endif // OSPF_LSTYP_STR
                                    , saddr
                                    , daddr);

                            fprintf(ospf3MsgFile,
                                    "%s" /* LSAAdvRtr */ SEP_CHR
                                    "-"  /* LSAOpts   */ SEP_CHR
                                    , inet_ntoa(lsa->advRtr));

#if OSPF_LSID_AS_IP == 1
                            fprintf(ospf3MsgFile,
                                    "%s" /* LSLinkID */ SEP_CHR
                                    , inet_ntoa(lsa->lsaID));
#else // OSPF_LSID_AS_IP == 0
                            fprintf(ospf3MsgFile,
                                    "%" PRIu32 /* LSLinkID */ SEP_CHR
                                    , ntohl(lsa->lsaID.s_addr));
#endif // OSPF_LSID_AS_IP

                            const ospf3ASsExtLSA_t * const elsas = (ospf3ASsExtLSA_t*)lsa;

                            ipAddr_t ip = {};
                            const uint32_t *u = (uint32_t*)&elsas->addrPref;
                            if (elsas->prefLen >  0) ip.IPv4x[0] = *u++;
                            if (elsas->prefLen > 32) ip.IPv4x[1] = *u++;
                            if (elsas->prefLen > 64) ip.IPv4x[2] = *u++;
                            if (elsas->prefLen > 96) ip.IPv4x[3] = *u++;
                            char addr[INET6_ADDRSTRLEN];
                            inet_ntop(AF_INET6, &ip, addr, INET6_ADDRSTRLEN);
                            const ospf3ASaddExtLSA_t * const elsadd = (ospf3ASaddExtLSA_t*)u;
                            const uint32_t mtrc = ntohl(elsas->flgs_mtrc) & 0x00ffffff;
                            const uint16_t rlst = ntohl(elsas->refLSType) & 0x0fff;
                            const uint8_t flgs = elsas->flgs_mtrc & 0xff;
                            fprintf(ospf3MsgFile,
                                    "-"                 /* IntID                */ SEP_CHR
                                    "-"                 /* NeighIntID           */ SEP_CHR
                                    "-"                 /* RefAdvRtrOrAttchRtrs */ SEP_CHR
                                    "0x%02" B2T_PRIX8   /* Type                 */ SEP_CHR
                                    "0x%02" B2T_PRIX8   /* PrefOpts             */ SEP_CHR
                                    "%" PRIu32          /* Metric               */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* RefLSA               */ SEP_CHR
                                    "%s/%" PRIu8        /* RefPrefix            */ SEP_CHR
                                    , flgs
                                    , elsas->prefOpt
                                    , mtrc
#if OSPF_LSTYP_STR == 1
                                    , OSPF3_LSTYPE_TO_STR(rlst)
#else // OSPF_LSTYP_STR == 0
                                    , rlst
#endif // OSPF_LSTYP_STR
                                    , addr, elsas->prefLen);

                            if (flgs & 0x02) {
                                inet_ntop(AF_INET6, &elsadd->fwdAddr, addr, INET6_ADDRSTRLEN);
                                fprintf(ospf3MsgFile,
                                        "%s" /* LnkLclIPOrFwdIP */ SEP_CHR
                                        , addr);
                            } else {
                                fputs("-" /* LnkLclIPOrFwdIP */ SEP_CHR
                                      , ospf3MsgFile);
                            }

                            if (flgs & 0x01) {
                                fprintf(ospf3MsgFile,
                                        "%" PRIu32 /* ExtRtTag */ "\n"
                                        , elsadd->extRtTg);
                            } else {
                                fputs("-" /* ExtRtTag */ "\n"
                                      , ospf3MsgFile);
                            }
                        } // ver == 3
#endif // IPV6_ACTIVATE > 0
                        break;
                    }

                    case OSPF_LSTYPE_NSSA: // OSPF3_NSSA, 7
#if IPV6_ACTIVATE > 0
                        if (ver == 3) {
                            fprintf(ospf3MsgFile,
                                    "%" PRIu64          /* pktNo   */ SEP_CHR
                                    "%" PRIuFAST8       /* Ver     */ SEP_CHR
                                    "%" OSPF_PRI_AREA   /* Area    */ SEP_CHR
                                    "%s"                /* SrcRtr  */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* MsgType */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* LSType  */ SEP_CHR
                                    "%s"                /* srcIP   */ SEP_CHR
                                    "%s"                /* dstIP   */ SEP_CHR
                                    , numPackets
                                    , ver
                                    , areaID
                                    , inet_ntoa(ospfHdrP->routerID)
#if OSPF_LSTYP_STR == 1
                                    , OSPF_TYPE_TO_STR(type)
                                    , OSPF3_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                    , type
                                    , lsType
#endif // OSPF_LSTYP_STR
                                    , saddr
                                    , daddr);

                            fprintf(ospf3MsgFile,
                                    "%s" /* LSAAdvRtr */ SEP_CHR
                                    "-"  /* LSAOpts   */ SEP_CHR
                                    , inet_ntoa(lsa->advRtr));

#if OSPF_LSID_AS_IP == 1
                            fprintf(ospf3MsgFile,
                                    "%s" /* LSLinkID */ SEP_CHR
                                    , inet_ntoa(lsa->lsaID));
#else // OSPF_LSID_AS_IP == 0
                            fprintf(ospf3MsgFile,
                                    "%" PRIu32 /* LSLinkID */ SEP_CHR
                                    , ntohl(lsa->lsaID.s_addr));
#endif // OSPF_LSID_AS_IP

                            const ospf3NSSALSA_t* const nlsa = (ospf3NSSALSA_t*)lsa;
                            ipAddr_t ip = {};
                            const uint32_t *u = (uint32_t*)&nlsa->addrPref;
                            if (nlsa->prefLen >  0) ip.IPv4x[0] = *u++;
                            if (nlsa->prefLen > 32) ip.IPv4x[1] = *u++;
                            if (nlsa->prefLen > 64) ip.IPv4x[2] = *u++;
                            if (nlsa->prefLen > 96) ip.IPv4x[3] = *u++;
                            char addr[INET6_ADDRSTRLEN];
                            inet_ntop(AF_INET6, &ip, addr, INET6_ADDRSTRLEN);
                            const ospf3NSSALSAopt_t* const nlsadd = (ospf3NSSALSAopt_t*)u;
                            const uint32_t mtrc = ntohl(nlsa->eft_mtrc) & 0x00ffffff;
                            const uint16_t rlst = ntohl(nlsa->refLSType);
                            const uint8_t flgs = nlsa->eft_mtrc & 0xff;

                            fprintf(ospf3MsgFile,
                                                       /* LSLinkID             */ SEP_CHR
                                                       /* IntID                */ SEP_CHR
                                                       /* NeighIntID           */ SEP_CHR
                                                       /* RefAdvRtrOrAttchRtrs */ SEP_CHR
                                    "0x%02" B2T_PRIX8  /* Type                 */ SEP_CHR
                                    "0x%02" B2T_PRIX8  /* PrefOpts             */ SEP_CHR
                                    "%" PRIu32         /* Metric               */ SEP_CHR
                                    "0x%04" B2T_PRIX16 /* RefLSA               */ SEP_CHR
                                    "%s"               /* RefPrefix            */ SEP_CHR
                                    , flgs
                                    , nlsa->prefOpt
                                    , mtrc
                                    , rlst
                                    , addr);

                            if (flgs & 0x02) {
                                 inet_ntop(AF_INET6, &nlsadd->fwdAddr, addr, INET6_ADDRSTRLEN);
                                 fprintf(ospf3MsgFile,
                                         "%s" /* LnkLclIPOrFwdIP */ SEP_CHR
                                         , addr);
                            } else {
                                fputs("-" /* LnkLclIPOrFwdIP */ SEP_CHR
                                      , ospf3MsgFile);
                            }

                            if (flgs & 0x01) {
                                fprintf(ospf3MsgFile,
                                        "%" PRIu32 /* ExtRtTag */ "\n"
                                        , nlsadd->extRtTg);
                            } else {
                                fputs("-" /* ExtRtTag*/ "\n"
                                      , ospf3MsgFile);
                            }
                        } // ver == 3
#endif // IPV6_ACTIVATE > 0
                        break;

                    case OSPF3_LINK: { // OSPF_LSTYPE_EXTATTR, 8
#if (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
                        if (ver == 2) {
                            fprintf(ospf2MsgFile,
                                    "%" PRIu64          /* pktNo    */ SEP_CHR
                                    "%" PRIuFAST8       /* Ver      */ SEP_CHR
                                    "%" OSPF_PRI_AREA   /* Area     */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* MsgType  */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* LSType   */ SEP_CHR
                                    "%s"                /* srcIP    */ SEP_CHR
                                    "-"                 /* LSLinkID */ SEP_CHR
                                    , numPackets
                                    , ver
                                    , areaID
#if OSPF_LSTYP_STR == 1
                                    , OSPF_TYPE_TO_STR(type)
                                    , OSPF2_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                    , type
                                    , lsType,
#endif // OSPF_LSTYP_STR
                                    , saddr);

#if OSPF_LSID_AS_IP == 1
                            fprintf(ospf2MsgFile,
                                    "%s" /* NetmaskOrRouterIP */ SEP_CHR
                                    , inet_ntoa(lsa->lsaID));
#else // OSPF_LSID_AS_IP == 0
                            fprintf(ospf2MsgFile,
                                    "%" PRIu32 /* NetmaskOrRouterIP */ SEP_CHR
                                    , ntohl(lsa->lsaID.s_addr));
#endif // OSPF_LSID_AS_IP
                            fputs(/* ADVRouter */ SEP_CHR
                                  /* LSAOpt    */ SEP_CHR
                                  /* LnkType   */ SEP_CHR
                                  /* Metric    */ SEP_CHR
                                  /* IfaceType */ SEP_CHR
                                  /* LSFlgs    */ SEP_CHR
                                  /* AttchRtrs */ SEP_CHR
                                  /* FwdIP     */ SEP_CHR
                                  /* ExtRtTag  */ "\n"
                                  , ospf2MsgFile);
                        } // ver == 2
#if IPV6_ACTIVATE == 2
                        else { // ver == 3
#endif // IPV6_ACTIVATE == 2
#endif // (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
#if IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 1
                        if (ver == 3) {
#endif // IPV6_ACTIVATE == 1
                            const ospf3LinkLSA_t * const iapr = (ospf3LinkLSA_t*)((char*)lsa + sizeof(ospfLSA_t));
                            const uint32_t numPref = ntohl(iapr->numPref);
                            if (numPref) {
                                ospf3IAreaPref9_t *apref = (ospf3IAreaPref9_t*)(iapr+1);
                                for (uint_fast32_t j = 0; j < numPref && (uint8_t*)apref <= packet->end_packet - sizeof(*apref); j++) {
                                    fprintf(ospf3MsgFile,
                                            "%" PRIu64          /* pktNo   */ SEP_CHR
                                            "%" PRIuFAST8       /* Ver     */ SEP_CHR
                                            "%" OSPF_PRI_AREA   /* Area    */ SEP_CHR
                                            "%s"                /* SrcRtr  */ SEP_CHR
                                            "%" OSPF_PRI_LSTYPE /* MsgType */ SEP_CHR
                                            "%" OSPF_PRI_LSTYPE /* LSType  */ SEP_CHR
                                            "%s"                /* srcIP   */ SEP_CHR
                                            "%s"                /* dstIP   */ SEP_CHR
                                            , numPackets
                                            , ver
                                            , areaID
                                            , inet_ntoa(ospfHdrP->routerID)
#if OSPF_LSTYP_STR == 1
                                            , OSPF_TYPE_TO_STR(type)
                                            , OSPF3_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                            , type
                                            , lsType
#endif // OSPF_LSTYP_STR
                                            , saddr
                                            , daddr);

                                    fprintf(ospf3MsgFile,
                                            "%s"               /* LSAAdvRtr */ SEP_CHR
                                            "0x%08" B2T_PRIX32 /* LSAOpts   */ SEP_CHR
                                            ,  inet_ntoa(lsa->advRtr)
                                            , ntohl(iapr->Options) >>  8);

#if OSPF_LSID_AS_IP == 1
                                    fprintf(ospf3MsgFile,
                                            "%s" /* LSLinkID */ SEP_CHR
                                            , inet_ntoa(lsa->lsaID));
#else // OSPF_LSID_AS_IP == 0
                                    fprintf(ospf3MsgFile,
                                            "%" PRIu32 /* LSLinkID */ SEP_CHR
                                            , ntohl(lsa->lsaID.s_addr));
#endif // OSPF_LSID_AS_IP

                                    fprintf(ospf3MsgFile,
                                            "-"               /* IntID                */ SEP_CHR
                                            "-"               /* NeighIntID           */ SEP_CHR
                                            "-"               /* RefAdvRtrOrAttchRtrs */ SEP_CHR
                                                              /* Type                 */ SEP_CHR
                                            "0x%02" B2T_PRIX8 /* PrefOpts             */ SEP_CHR
                                            "%" PRIu32        /* Metric               */ SEP_CHR
                                                              /* RefLSA               */ SEP_CHR
                                            , apref->prefOpt
                                            , iapr->rtrPrio); // metric is always 0

                                    ipAddr_t ip = {};
                                    const uint32_t *u = (uint32_t*)&apref->addrPref;
                                    if (apref->prefLen  > 0) ip.IPv4x[0] = *u++;
                                    if (apref->prefLen > 32) ip.IPv4x[1] = *u++;
                                    if (apref->prefLen > 64) ip.IPv4x[2] = *u++;
                                    if (apref->prefLen > 96) ip.IPv4x[3] = *u++;
                                    char addr[INET6_ADDRSTRLEN];
#if OSPF_MASK_AS_IP == 1
                                    inet_ntop(AF_INET6, &ip, addr, INET6_ADDRSTRLEN);
                                    fprintf(ospf3MsgFile,
                                            "%s/%" PRIu8 /* RefPrefix */ SEP_CHR
                                            , addr, apref->prefLen);
#else // OSPF_MASK_AS_IP == 0
                                    fprintf(ospf3MsgFile,
                                            "0x%016" B2T_PRIX64 /* RefPrefix */ SEP_CHR
                                            , htobe64(ip.IPv6L[0]));
#endif // OSPF_MASK_AS_IP

                                    inet_ntop(AF_INET6, &iapr->llIAddr, addr, INET6_ADDRSTRLEN);
                                    fprintf(ospf3MsgFile,
                                            "%s" /* LnkLclIPOrFwdIP */ SEP_CHR
                                                 /* ExtRtTag        */ "\n"
                                            , addr);

                                    apref = (ospf3IAreaPref9_t*)u;
                                }
                            }
                        } // ver == 3
#endif // IPV6_ACTIVATE > 0
                        break;
                    }

                    case OSPF3_INTR_A_PREF: { // OSPF_LSTYPE_OPAQUE_LLS, 9
#if IPV6_ACTIVATE > 0
                        if (ver == 3) {
                            const ospf3IAreaPrefLSA9_t * const iapr = (ospf3IAreaPrefLSA9_t*)((char*)lsa + sizeof(ospfLSA_t));
                            const uint16_t numPref = ntohs(iapr->numPref);
                            if (numPref) {
                                ospf3IAreaPref9_t *apref = (ospf3IAreaPref9_t*)(iapr+1);
                                for (uint_fast16_t j = 0; j < numPref && (uint8_t*)apref <= packet->end_packet - sizeof(*apref); j++) {
                                    fprintf(ospf3MsgFile,
                                            "%" PRIu64          /* pktNo     */ SEP_CHR
                                            "%" PRIuFAST8       /* Ver       */ SEP_CHR
                                            "%" OSPF_PRI_AREA   /* Area      */ SEP_CHR
                                            "%s"                /* SrcRtr    */ SEP_CHR
                                            "%" OSPF_PRI_LSTYPE /* MsgType   */ SEP_CHR
                                            "%" OSPF_PRI_LSTYPE /* LSType    */ SEP_CHR
                                            "%s"                /* srcIP     */ SEP_CHR
                                            "%s"                /* dstIP     */ SEP_CHR
                                            "%s"                /* LSAAdvRtr */ SEP_CHR
                                            "-"                 /* LSAOpts   */ SEP_CHR
                                            , numPackets
                                            , ver
                                            , areaID
                                            , inet_ntoa(ospfHdrP->routerID)
#if OSPF_LSTYP_STR == 1
                                            , OSPF_TYPE_TO_STR(type)
                                            , OSPF3_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                            , type
                                            , lsType
#endif // OSPF_LSTYP_STR
                                            , saddr
                                            , daddr
                                            , inet_ntoa(lsa->advRtr));

#if OSPF_LSID_AS_IP == 1
                                    fprintf(ospf3MsgFile,
                                            "%s" /* LSLinkID */ SEP_CHR
                                            , inet_ntoa(lsa->lsaID));
#else // OSPF_LSID_AS_IP == 0
                                    fprintf(ospf3MsgFile,
                                            "%" PRIu32 /* LSLinkID */ SEP_CHR
                                            , ntohl(lsa->lsaID.s_addr));
#endif // OSPF_LSID_AS_IP

                                    fprintf(ospf3MsgFile,
                                            "-"  /* IntID      */ SEP_CHR
                                            "%s" /* NeighIntID */ SEP_CHR
                                            , inet_ntoa(iapr->refLnkStID));

                                    const uint16_t i = ntohs(iapr->refLSType) & 0x0fff;
                                    fprintf(ospf3MsgFile,
                                            "%s"                /* RefAdvRtrOrAttchRtrs */ SEP_CHR
                                                                /* Type                 */ SEP_CHR
                                            "0x%02" B2T_PRIX8   /* PrefOpts             */ SEP_CHR
                                            "%" PRIu16          /* Metric               */ SEP_CHR
                                            "%" OSPF_PRI_LSTYPE /* RefLSA               */ SEP_CHR
                                            , inet_ntoa(iapr->refAdRtr)
                                            , apref->prefOpt
                                            , ntohs(apref->metric)
#if OSPF_LSTYP_STR == 1
                                            , OSPF3_LSTYPE_TO_STR(i)
#else // OSPF_LSTYP_STR == 0
                                            , i
#endif // OSPF_LSTYP_STR
                                    );

                                    ipAddr_t ip = {};
                                    const uint32_t *u = (uint32_t*)&apref->addrPref;
                                    if (apref->prefLen >  0) ip.IPv4x[0] = *u++;
                                    if (apref->prefLen > 32) ip.IPv4x[1] = *u++;
                                    if (apref->prefLen > 64) ip.IPv4x[2] = *u++;
                                    if (apref->prefLen > 96) ip.IPv4x[3] = *u++;
#if OSPF_MASK_AS_IP == 1
                                    char addr[INET6_ADDRSTRLEN];
                                    inet_ntop(AF_INET6, &ip, addr, INET6_ADDRSTRLEN);
                                    fprintf(ospf3MsgFile,
                                            "%s/%" PRIu8 /* RefPrefix */ SEP_CHR
                                            , addr, apref->prefLen);
#else // OSPF_MASK_AS_IP == 0
                                    fprintf(ospf3MsgFile,
                                            "0x%016" B2T_PRIX64 /* RefPrefix */ SEP_CHR
                                            , htobe64(ip.IPv6L[0]));
#endif // OSPF_MASK_AS_IP

                                    fputs(/* LnkLclIPOrFwdIP */ SEP_CHR
                                          /* ExtRtTag        */ "\n"
                                          , ospf3MsgFile);

                                    apref = (ospf3IAreaPref9_t*)u;
                                }
                            }
                        } // ver == 3
#endif // IPV6_ACTIVATE > 0
                        break;
                    }

                    case OSPF3_INTR_A_TE_LSA: { // OSPF_LSTYPE_OPAQUE_ALS, 10
#if IPV6_ACTIVATE > 0
                        if (ver == 3) {
                            uint32_t *u = (uint32_t*)((char*)lsa + sizeof(ospfLSA_t));
                            int32_t numPref = ntohs(lsa->lsLen) / 4;
                            if (numPref) {
                                fprintf(ospf3MsgFile,
                                        "%" PRIu64          /* pktNo   */ SEP_CHR
                                        "%" PRIuFAST8       /* Ver     */ SEP_CHR
                                        "%" OSPF_PRI_AREA   /* Area    */ SEP_CHR
                                        "%s"                /* SrcRtr  */ SEP_CHR
                                        "%" OSPF_PRI_LSTYPE /* MsgType */ SEP_CHR
                                        "%" OSPF_PRI_LSTYPE /* LSType  */ SEP_CHR
                                        "%s"                /* srcIP   */ SEP_CHR
                                        "%s"                /* dstIPP  */ SEP_CHR
                                        , numPackets
                                        , ver
                                        , areaID
                                        , inet_ntoa(ospfHdrP->routerID)
#if OSPF_LSTYP_STR == 1
                                        , OSPF_TYPE_TO_STR(type)
                                        , OSPF3_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                        , type
                                        , lsType
#endif // OSPF_LSTYP_STR
                                        , saddr
                                        , daddr);

                                fprintf(ospf3MsgFile,
                                        "%s" /* LSAAdvRtr */ SEP_CHR
                                        "-"  /* LSAOpts   */ SEP_CHR
                                        , inet_ntoa(lsa->advRtr));

                                fprintf(ospf3MsgFile,
                                        "%" PRIu32 ";%" PRIu32 /* LSLinkID             */ SEP_CHR
                                                               /* IntID                */ SEP_CHR
                                                               /* NeightIntID          */ SEP_CHR
                                                               /* RefAdvRtrOrAttchRtrs */ SEP_CHR
                                                               /* Type                 */ SEP_CHR
                                                               /* PrefOpts             */ SEP_CHR
                                                               /* Metric               */ SEP_CHR
                                                               /* RefLSA               */ SEP_CHR
                                        , lsa->lsaID.s_addr & 0xff
                                        , ntohl(lsa->lsaID.s_addr) & 0x00ffffff);

                                for (int32_t j = 0; j < numPref && (uint8_t*)u <= packet->end_packet - sizeof(uint32_t); j++) {
                                    fprintf(ospf3MsgFile,
                                            "0x%08" B2T_PRIX32 ";" /* RefPrefix */, ntohl(*u++));
                                }

                                fputs(/* RefPrefix       */ SEP_CHR
                                      /* LnkLclIPOrFwdIP */ SEP_CHR
                                      /* ExtRtTag        */ "\n"
                                      , ospf3MsgFile);
                            }
                        }
                        break;
#endif // IPV6_ACTIVATE > 0
                    }

                    case OSPF3_GRACE_LSA: { // OSPF_LSTYPE_OPAQUE_ASS, 11
#if IPV6_ACTIVATE > 0
                        if (ver == 3) {
                            uint32_t *u = (uint32_t*)((char*)lsa + sizeof(ospfLSA_t));
                            const uint_fast32_t numPref = ntohs(lsa->lsLen) / 4;
                            if (numPref == 0) break;
                            fprintf(ospf3MsgFile,
                                    "%" PRIu64          /* pktNo   */ SEP_CHR
                                    "%" PRIuFAST8       /* Ver     */ SEP_CHR
                                    "%" OSPF_PRI_AREA   /* Area    */ SEP_CHR
                                    "%s"                /* SrcRtr  */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* MsgType */ SEP_CHR
                                    "%" OSPF_PRI_LSTYPE /* LSType  */ SEP_CHR
                                    "%s"                /* srcIP   */ SEP_CHR
                                    "%s"                /* dstIP   */ SEP_CHR
                                    , numPackets
                                    , ver
                                    , areaID
                                    , inet_ntoa(ospfHdrP->routerID)
#if OSPF_LSTYP_STR == 1
                                    , OSPF_TYPE_TO_STR(type)
                                    , OSPF3_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                    , type
                                    , lsType
#endif // OSPF_LSTYP_STR
                                    , saddr
                                    , daddr);

                            fprintf(ospf3MsgFile,
                                    "%s" /* LSAAdvRtr */ SEP_CHR
                                    "-"  /* LSAOpts   */ SEP_CHR
                                    , inet_ntoa(lsa->advRtr));

                            fprintf(ospf3MsgFile,
                                    "%" PRIu32 ";%" PRIu32 /* LSLinkID             */ SEP_CHR
                                                           /* IntID                */ SEP_CHR
                                                           /* NeighIntID           */ SEP_CHR
                                                           /* RefAdvRtrOrAttchRtrs */ SEP_CHR
                                                           /* Type                 */ SEP_CHR
                                                           /* PrefOpts             */ SEP_CHR
                                                           /* Metric               */ SEP_CHR
                                                           /* RefLSA               */ SEP_CHR
                                    , lsa->lsaID.s_addr & 0xff
                                    , ntohl(lsa->lsaID.s_addr) & 0x00ffffff);
                            for (uint_fast32_t j = 0; j < numPref && (uint8_t*)u <= packet->end_packet - sizeof(uint32_t); j++) {
                                fprintf(ospf3MsgFile, "0x%08" B2T_PRIX32 ";" /* RefPrefix */, ntohl(*u++));
                            }

                            fputs(/* RefPrefix       */ SEP_CHR
                                  /* LnkLclIPOrFwdIP */ SEP_CHR
                                  /* ExtRtTag        */ "\n"
                                  , ospf3MsgFile);
                        }
                        break;
#endif // IPV6_ACTIVATE > 0
                    }
#endif // OSPF_OUTPUT_MSG == 1

                    default:
                        if (ver == 2 && lsType < OSPF_LSTYPE_N) break;
                        else if (ver == 3 && lsType < OSPF3_LSTYPE_N) break;
                        ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                        if (ver == 2) numOSPF2LSType[0]++;
                        else numOSPF3LSType[0]++;
                        break;
                }

                lsa = (ospfLSA_t*)((uint8_t*)lsa + lsaLen);
                ospfFlowP->lsType |= xlsType;
            }
            break;
        }

        case OSPF_LS_ACK: {
#if (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
            if (ver == 2) {
                if (ospfPktLen < OSPF2_HDR_LEN + sizeof(ospfLSA_t)) {
                    ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                    OSPF_SPKTMD_PRI_3(ospfFlowP, ver, areaID, type, xlsType);
                    return;
                }

                const uint16_t numLSA = (ospfPktLen - OSPF2_HDR_LEN) / OSPF2_LSA_LEN;
                if (numLSA == 0) break;
                for (uint_fast16_t j = 0; j < numLSA && &ospfHdrP->data + j * OSPF2_LSA_LEN <= packet->end_packet - sizeof(ospfLSA_t); j++) {
                    const ospfLSA_t * const lsa = (ospfLSA_t*)(&ospfHdrP->data + j * OSPF2_LSA_LEN);
                    const uint8_t lsType = lsa->lsType;
                    if (lsType > 0 && lsType < OSPF_LSTYPE_N) {
                        numOSPF2LSType[lsType]++;
#if OSPF_OUTPUT_MSG == 1
                        fprintf(ospf2MsgFile,
                                "%" PRIu64          /* pktNo   */ SEP_CHR
                                "%" PRIuFAST8       /* Ver     */ SEP_CHR
                                "%" OSPF_PRI_AREA   /* Area    */ SEP_CHR
                                "%" OSPF_PRI_LSTYPE /* MsgType */ SEP_CHR
                                "%" OSPF_PRI_LSTYPE /* LSType  */ SEP_CHR
                                "%s"                /* srcIP   */ SEP_CHR
                                , numPackets
                                , ver
                                , areaID
#if OSPF_LSTYP_STR == 1
                                , OSPF_TYPE_TO_STR(type)
                                , OSPF2_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                , type
                                , lsType
#endif // OSPF_LSTYP_STR
                                , saddr);

#if OSPF_MASK_AS_IP == 1
                        fprintf(ospf2MsgFile,
                                "%s" /* LSLinkID          */ SEP_CHR
                                , inet_ntoa(lsa->lsaID));

                        fprintf(ospf2MsgFile,
                                     /* NetmaskOrRouterIP */ SEP_CHR
                                "%s" /* ADVRouter         */ SEP_CHR
                                , inet_ntoa(lsa->advRtr));
#else // OSPF_MASK_AS_IP == 0
                        fprintf(ospf2MsgFile,
                                "0x%08" B2T_PRIX32 /* LSLinkID          */ SEP_CHR
                                                   /* NetmaskOrRouterIP */ SEP_CHR
                                "0x%08" B2T_PRIX32 /* ADVRouter         */ SEP_CHR
                                , ntohl(lsa->lsaID.s_addr)
                                , ntohl(lsa->advRtr.s_addr));
#endif // OSPF_MASK_AS_IP

                        fputs(/* LSAOpt    */ SEP_CHR
                              /* LnkType   */ SEP_CHR
                              /* Metric    */ SEP_CHR
                              /* IfaceType */ SEP_CHR
                              /* LSFlgs    */ SEP_CHR
                              /* AttchRtrs */ SEP_CHR
                              /* FwdIP     */ SEP_CHR
                              /* ExtRtTag  */ "\n"
                              , ospf2MsgFile);
#endif // OSPF_OUTPUT_MSG == 1
                    } else {
                        ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                        numOSPF2LSType[0]++;
                    }
                }
            } // ver == 2
#if IPV6_ACTIVATE == 2
            else { // ver == 3
#endif // IPV6_ACTIVATE == 2
#endif // (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
#if IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 1
            if (ver == 3) {
#endif // IPV6_ACTIVATE == 1
                if (ospfPktLen < OSPF3_HDR_LEN + sizeof(ospfLSA_t)) {
                    ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                    OSPF_SPKTMD_PRI_3(ospfFlowP, ver, areaID, type, xlsType);
                    return;
                }

                const uint16_t numLSA = (ospfPktLen - OSPF3_HDR_LEN) / OSPF3_LSA_LEN;
                if (numLSA == 0) break;
                for (uint_fast16_t j = 0; j < numLSA && &ospf3HdrP->data + j * OSPF3_LSA_LEN <= packet->end_packet - sizeof(ospfLSA_t); j++) {
                    const ospfLSA_t * const lsaa = (ospfLSA_t*)(&ospf3HdrP->data + j * OSPF3_LSA_LEN);
                    const uint16_t lsType = lsaa->lsType & 0xff1f;
                    if (lsType > 0 && lsType < OSPF3_LSTYPE_N) {
                        numOSPF3LSType[lsType]++;
#if OSPF_OUTPUT_MSG == 1
                        fprintf(ospf3MsgFile,
                                "%" PRIu64          /* pktNo   */ SEP_CHR
                                "%" PRIuFAST8       /* Ver     */ SEP_CHR
                                "%" OSPF_PRI_AREA   /* Area    */ SEP_CHR
                                "%s"                /* SrcRtr  */ SEP_CHR
                                "%" OSPF_PRI_LSTYPE /* MsgType */ SEP_CHR
                                "%" OSPF_PRI_LSTYPE /* LSType  */ SEP_CHR
                                "%s"                /* srcIP   */ SEP_CHR
                                "%s"                /* dstIP   */ SEP_CHR
                                , numPackets
                                , ver
                                , areaID
                                , inet_ntoa(ospfHdrP->routerID)
#if OSPF_LSTYP_STR == 1
                                , OSPF_TYPE_TO_STR(type)
                                , OSPF3_LSTYPE_TO_STR(lsType)
#else // OSPF_LSTYP_STR == 0
                                , type
                                , lsType
#endif // OSPF_LSTYP_STR
                                , saddr
                                , daddr);

                        fprintf(ospf3MsgFile,
                                "%s" /* LSAAdvRtr */ SEP_CHR
                                "-"  /* LSAOpts   */ SEP_CHR
                                , inet_ntoa(lsaa->advRtr));

#if OSPF_MASK_AS_IP == 1
                        fprintf(ospf3MsgFile,
                                "%s" /* LSLinkID */ SEP_CHR
                                , inet_ntoa(lsaa->lsaID));
#else // OSPF_MASK_AS_IP == 0
                        fprintf(ospf3MsgFile,
                                "0x%08" B2T_PRIX32 /* LSLinkID */ SEP_CHR
                                , ntohl(lsaa->lsaID.s_addr));
#endif // OSPF_MASK_AS_IP

                        fputs("-" /* IntID                 */ SEP_CHR
                              "-" /* NeighIntID            */ SEP_CHR
                              "-" /* RefAdvRtrOrAttchRtrs  */ SEP_CHR
                              "-" /* Type                  */ SEP_CHR
                              "-" /* PrefOpts              */ SEP_CHR
                              "-" /* Metric                */ SEP_CHR
                              "-" /* RefLSA                */ SEP_CHR
                              "-" /* RefPrefix             */ SEP_CHR
                              "-" /* LnkLclIPOrFwdIP       */ SEP_CHR
                                  /* ExtRtTag              */ "\n"
                              , ospf3MsgFile);
#endif // OSPF_OUTPUT_MSG == 1
                    } else {
                        ospfFlowP->stat |= OSPF_STAT_MALFORMED;
                        numOSPF3LSType[0]++;
                    }
                }
            } // ver == 3
#endif // IPV6_ACTIVATE > 0
            break;
        }

        default:
            ospfFlowP->stat |= OSPF_STAT_BAD_TYPE;
            numInvalidType++;
            break;
    }

    OSPF_SPKTMD_PRI_3(ospfFlowP, ver, areaID, type, xlsType);
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    ospfFlow_t *ospfFlowP = &ospfFlow[flowIndex];

    ospfStat |= ospfFlowP->stat;

    OUTBUF_APPEND_U8(buf, ospfFlowP->stat);      // ospfStat
    OUTBUF_APPEND_U8(buf, ospfFlowP->version);   // ospfVersion

    // ospfType
#if OSPF_TYP_STR == 1
    OUTBUF_APPEND_NUMREP(buf, ospfFlowP->numTyp);
    for (uint_fast32_t i = 0; i < ospfFlowP->numTyp; i++) {
        OUTBUF_APPEND_STR(buf, OSPF_TYPE_TO_STR(ospfFlowP->type[i]));
    }
#else // OSPF_TYP_STR == 0
    OUTBUF_APPEND_U8(buf, ospfFlowP->type);
#endif // OSPF_TYP_STR

    OUTBUF_APPEND_U64(buf   , ospfFlowP->lsType);    // ospfLSType
    OUTBUF_APPEND_U16(buf   , ospfFlowP->auType);    // ospfAuType
    OUTBUF_APPEND_OPT_STR(buf, ospfFlowP->auPass);   // ospfAuPass
    OUTBUF_APPEND_U32(buf   , ospfFlowP->areaID);    // ospfArea
    OUTBUF_APPEND_U32(buf   , ospfFlowP->routerID);  // ospfSrcRtr
    OUTBUF_APPEND_U32(buf   , ospfFlowP->backupRtr); // ospfBkupRtr
    OUTBUF_APPEND_ARRAY_U32(buf, ospfFlowP->neighbors, ospfFlowP->numNeigh); // ospfNeighbors
}


void t2PluginReport(FILE *stream) {
    if (ospfStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, ospfStat);
        if (ospf2Type) T2_FPLOG(stream, plugin_name, "Aggregated OSPFv2 types: ospfType=0x%02" B2T_PRIX8, ospf2Type);
        if (ospf3Type) T2_FPLOG(stream, plugin_name, "Aggregated OSPFv3 types: ospfType=0x%02" B2T_PRIX8, ospf3Type);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of OSPFv2 packets", numOSPF2[0], numPackets);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of OSPFv3 packets", numOSPF3[0], numPackets);
    }
}


void t2Finalize() {
#if OSPF_OUTPUT_STATS == 1
    const uint64_t numOSPF = numOSPF2[0] + numOSPF3[0];
    if (numOSPF > 0) {
        FILE *file = t2_fopen_with_suffix(baseFileName, ospfSuffix, "w");
        if (UNLIKELY(!file)) exit(EXIT_FAILURE);

        T2_FLOG_NUMP0(file, "Number of OSPF packets", numOSPF, numPackets);
        T2_FLOG_NUMP(file, "Number of OSPFv2 packets", numOSPF2[0], numPackets);
        T2_FLOG_NUMP(file, "Number of OSPFv3 packets", numOSPF3[0], numPackets);
        fputc('\n', file);

        T2_FLOG_NUMP(file, "Number of OSPFv2 multicast packets", numMCastPkts, numOSPF);
        T2_FLOG_NUMP(file, "Number of OSPFv2 packets with null authentication", numOSPFAuType[OSPF_AUTH_NULL], numOSPF);
        T2_FLOG_NUMP(file, "Number of OSPFv2 packets with password authentication", numOSPFAuType[OSPF_AUTH_PASSWD], numOSPF);
        T2_FLOG_NUMP(file, "Number of OSPFv2 packets with cryptographic authentication", numOSPFAuType[OSPF_AUTH_CRYPTO], numOSPF);
        T2_FLOG_NUMP(file, "Number of OSPFv2 packets with unknown authentication", numOSPFAuType[OSPF_AUTH_N], numOSPF);
        T2_FLOG_NUMP(file, "Number of OSPFv2 packets with bad TTL", numInvalidTTL, numOSPF);
        T2_FLOG_NUMP(file, "Number of OSPFv2 packets with bad dest", numInvalidDest, numOSPF);
        T2_FLOG_NUMP(file, "Number of OSPF packets with bad type", numInvalidType, numOSPF);
        //T2_FLOG_NUMP(file, "Number of OSPF packets with bad checksum", numInvalidCSum, numOSPF);
        fputc('\n', file);

        float tmp = ((numOSPF2[OSPF_LS_UPDATE] != 0) ? numOSPF2[OSPF_LS_REQ] / (float)numOSPF2[OSPF_LS_UPDATE] : 0.0f);
        fprintf(file, "OSPFv2 Link State Request / Update ratio: %5.3f\n", tmp);
        tmp = (numOSPF2[OSPF_LS_ACK] != 0) ? numOSPF2[OSPF_LS_UPDATE] / (float)numOSPF2[OSPF_LS_ACK] : 0.0f;
        fprintf(file, "OSPFv2 Link State Update / Acknowledgment ratio: %5.3f\n\n", tmp);

        tmp = ((numOSPF3[OSPF_LS_UPDATE] != 0) ? numOSPF3[OSPF_LS_REQ] / (float)numOSPF3[OSPF_LS_UPDATE] : 0.0f);
        fprintf(file, "OSPFv3 Link State Request / Update ratio: %5.3f\n", tmp);
        tmp = (numOSPF3[OSPF_LS_ACK] != 0) ? numOSPF3[OSPF_LS_UPDATE] / (float)numOSPF3[OSPF_LS_ACK] : 0.0f;
        fprintf(file, "OSPFv3 Link State Update / Acknowledgment ratio: %5.3f\n\n", tmp);

        uint_fast8_t i;

        // OSPFv2 type statistics
        fprintf(file, "%-20s\t%20s\n", "# OSPFv2 Type", "Packets");
        for (i = 1; i < OSPF_TYPE_N; i++) {
            OSPF_LOG_TYPE(file, ospfTypeStr[i], numOSPF2[i], numOSPF2[0]);
        }
        fputc('\n', file);

        // OSPFv3 type statistics
        fprintf(file, "%-20s\t%20s\n", "# OSPFv3 Type", "Packets");
        for (i = 1; i < OSPF_TYPE_N; i++) {
            OSPF_LOG_TYPE(file, ospfTypeStr[i], numOSPF3[i], numOSPF3[0]);
        }
        fputc('\n', file);

        // OSPFv2 LS type statistics
        fprintf(file, "%-20s\t%20s\n", "# OSPFv2 LS Type", "Count");
        for (i = 1; i < OSPF_LSTYPE_N; i++) {
            OSPF_LOG_LSTYPE(file, ospf2LSTypeStr[i], numOSPF2LSType[i]);
        }
        if (numOSPF2LSType[0]) fprintf(file, "\nNumber of OSPFv2 LSA with unknown type: %" PRIu64 "\n", numOSPF2LSType[0]);
        fputc('\n', file);

        // OSPFv3 LS type statistics
        fprintf(file, "%-20s\t%20s\n", "# OSPFv3 LS Type", "Count");
        for (i = 1; i < OSPF3_LSTYPE_N; i++) {
            OSPF_LOG_LSTYPE(file, ospf3LSTypeStr[i], numOSPF3LSType[i]);
        }
        if (numOSPF3LSType[0]) fprintf(file, "\nNumber of OSPFv3 LSA with unknown type: %" PRIu64 "\n", numOSPF3LSType[0]);

        fclose(file);
    }

#if ENVCNTRL > 0
    T2_FREE_CONST(ospfSuffix);
#endif // ENVCNTRL > 0

#endif // OSPF_OUTPUT_STATS == 1

    ospfDecode_clean();
}


static void ospfDecode_clean() {
    free(ospfFlow);

#if OSPF_OUTPUT_HLO == 1
    if (LIKELY(ospfHelloFile != NULL)) fclose(ospfHelloFile);
#endif // OSPF_OUTPUT_HLO == 1

#if OSPF_OUTPUT_DBD == 1
    if (LIKELY(ospfDBDFile != NULL)) fclose(ospfDBDFile);
#endif // OSPF_OUTPUT_DBD == 1

#if OSPF_OUTPUT_MSG == 1
    if (LIKELY(ospf2MsgFile != NULL)) fclose(ospf2MsgFile);
    if (LIKELY(ospf3MsgFile != NULL)) fclose(ospf3MsgFile);
#endif // OSPF_OUTPUT_MSG == 1
}
