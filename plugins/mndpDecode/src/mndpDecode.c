/*
 * mndpDecode.c
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

#include "mndpDecode.h"

#include "t2buf.h"


/*
 * Plugin variables
 */

mndpFlow_t *mndpFlows;


/*
 * Static variables
 */

static uint64_t numMndpPkts;

static uint8_t mndpStat;


/*
 * Macros
 */

#define MNDP_SPKTMD_PRI_NONE(status) \
    if (sPktFile) { \
        fprintf(sPktFile, \
                "0x%02" B2T_PRIX8 /* mndpStat       */ SEP_CHR \
                                  /* mndpSeqNo      */ SEP_CHR \
                                  /* mndpMAC        */ SEP_CHR \
                                  /* mndpIdentity   */ SEP_CHR \
                                  /* mndpVersion    */ SEP_CHR \
                                  /* mndpPlatform   */ SEP_CHR \
                                  /* mndpUptime     */ SEP_CHR \
                                  /* mndpSoftwareID */ SEP_CHR \
                                  /* mndpBoard      */ SEP_CHR \
                                  /* mndpUnpack     */ SEP_CHR \
                                  /* mndpIface      */ SEP_CHR \
                                  /* mndpIPv4       */ SEP_CHR \
                                  /* mndpIPv6       */ SEP_CHR \
                , (uint8_t)status); \
    }

#define MNDP_READ_STR(t2buf, dest, len) { \
    const size_t read = MIN((len), sizeof(dest)); \
    if (read != (size_t)(len)) { \
        mndpFlowP->stat |= MNDP_STAT_STR; \
    } \
    if (!t2buf_read_n((t2buf), (uint8_t*)dest, read)) { \
        mndpFlowP->stat |= MNDP_STAT_SNAP; \
        goto mndp_pktmd; \
    } \
    dest[read] = '\0'; \
    if (read != (size_t)(len)) t2buf_skip_n((t2buf), (len) - read); \
}

#if MNDP_LSTLEN == 0
#define MNDP_STORE_IN_FLOW(mndpFlowP, value, field, count)
#else // MNDP_LSTLEN > 0
#define MNDP_STORE_IN_FLOW(mndpFlowP, value, field, count) { \
    uint_fast8_t i; \
    const size_t len = sizeof(value); \
    for (i = 0; i < (mndpFlowP)->count; i++) { \
        if (memcmp(&((mndpFlowP)->field[i]), &(value), len) == 0) break; \
    } \
    if (i >= MNDP_LSTLEN) { \
        pkt_stat |= MNDP_STAT_LIST; \
    } else if (i == (mndpFlowP)->count) { \
        memcpy(&(mndpFlowP)->field[i], &(value), len); \
        (mndpFlowP)->count++; \
    } \
}
#endif // MNDP_LSTLEN > 0


// Tranalyzer functions

T2_PLUGIN_INIT("mndpDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(mndpFlows);

    if (sPktFile) {
        fputs(
            "mndpStat"       SEP_CHR
            "mndpSeqNo"      SEP_CHR
            "mndpMAC"        SEP_CHR
            "mndpIdentity"   SEP_CHR
            "mndpVersion"    SEP_CHR
            "mndpPlatform"   SEP_CHR
            "mndpUptime"     SEP_CHR
            "mndpSoftwareID" SEP_CHR
            "mndpBoard"      SEP_CHR
            "mndpUnpack"     SEP_CHR
            "mndpIface"      SEP_CHR
            "mndpIPv4"       SEP_CHR
            "mndpIPv6"       SEP_CHR
            , sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H8(bv, "mndpStat", "mndpDecode status");

#if MNDP_LSTLEN > 0
    BV_APPEND_MAC_R(bv, "mndpMAC"       , "MNDP MAC-Address");
    BV_APPEND_STR_R(bv, "mndpIdentity"  , "MNDP Identity");
    BV_APPEND_STR_R(bv, "mndpVersion"   , "MNDP Version");
    BV_APPEND_STR_R(bv, "mndpPlatform"  , "MNDP Platform");
    //BV_APPEND_DBL_R(bv, "mndpUptime"    , "MNDP Uptime");
    BV_APPEND_STR_R(bv, "mndpSoftwareID", "MNDP Software-ID");
    BV_APPEND_STR_R(bv, "mndpBoard"     , "MNDP Board");
    BV_APPEND_U8_R(bv, "mndpUnpack"     , "MNDP Unpack");
    BV_APPEND_STR_R(bv, "mndpIface"     , "MNDP Interface name");
    BV_APPEND_IP4_R(bv, "mndpIPv4"      , "MNDP IPv4-Address");
    BV_APPEND_IP6_R(bv, "mndpIPv6"      , "MNDP IPv6-Address");
#endif // MNDP_LSTLEN > 0

    return bv;
}


void t2OnNewFlow(packet_t *packet, unsigned long flowIndex) {
    mndpFlow_t * const mndpFlowP = &mndpFlows[flowIndex];
    memset(mndpFlowP, '\0', sizeof(*mndpFlowP));

    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW) return;

    const uint_fast8_t proto = flowP->l4Proto;
    if (proto != L3_UDP) return;

    if (packet->l7Len < MNDP_MIN_SIZE) return;

    const uint_fast16_t srcPort = flowP->srcPort;
    const uint_fast16_t dstPort = flowP->dstPort;
    if (srcPort == MNDP_PORT || dstPort == MNDP_PORT) {
        mndpFlowP->stat |= MNDP_STAT_MNDP;
    }
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    // This packet does not have a layer 4.
    // Print tabs to keep the packet file aligned
    MNDP_SPKTMD_PRI_NONE(0x00);
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    mndpFlow_t * const mndpFlowP = &mndpFlows[flowIndex];

    if (!mndpFlowP->stat || packet->l7Len < MNDP_MIN_SIZE) {
        // Not a MNDP packet
        MNDP_SPKTMD_PRI_NONE(0x00);
        return;
    }

    uint8_t pkt_stat = MNDP_STAT_MNDP;

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) {
        MNDP_SPKTMD_PRI_NONE(pkt_stat);
        return;
    }

    numMndpPkts++;

    const uint16_t snaplen = packet->snapL7Len;
    const uint8_t * const l7HdrP = packet->l7HdrP;

    t2buf_t t2buf = t2buf_create(l7HdrP, snaplen);

    /* Header */
    t2buf_skip_u16(&t2buf);

    /* Sequence Number */
    uint16_t seqNo;
    if (!t2buf_read_u16(&t2buf, &seqNo)) {
        pkt_stat |= MNDP_STAT_SNAP;
        MNDP_SPKTMD_PRI_NONE(pkt_stat);
        return;
    }

    char identity[MNDP_STRLEN+1] = {};
    char version[MNDP_STRLEN+1] = {};
    char platform[MNDP_STRLEN+1] = {};
    char software_id[MNDP_STRLEN+1] = {};
    char board[MNDP_STRLEN+1] = {};
    char iface_name[MNDP_STRLEN+1] = {};
    char mac[32] = {};
    char ipv4[INET_ADDRSTRLEN] = {};
    char ipv6[INET6_ADDRSTRLEN] = {};
    uint8_t unpack = 0;
    uint32_t uptime = 0;

    while (t2buf_left(&t2buf) > 4) {
        /* TLV type */
        uint16_t type;
        if (!t2buf_read_u16(&t2buf, &type)) {
            pkt_stat |= MNDP_STAT_SNAP;
            goto mndp_pktmd;
        }

        /* TLV length */
        uint16_t len;
        if (!t2buf_read_u16(&t2buf, &len)) {
            pkt_stat |= MNDP_STAT_SNAP;
            goto mndp_pktmd;
        }

        if (t2buf_left(&t2buf) < len) {
            pkt_stat |= MNDP_STAT_SNAP;
            goto mndp_pktmd;
        }

        /* TLV value */
        switch (type) {
            case MNDP_TLV_MAC_ADDR: { /* MAC-Address */
                if (len != ETH_ALEN) {
                    pkt_stat |= MNDP_STAT_TLV_LEN;
                }
                uint8_t addr[ETH_ALEN] = {};
                for (uint_fast8_t i = 0; i < ETH_ALEN; i++) {
                    if (!t2buf_read_u8(&t2buf, &addr[i])) goto mndp_pktmd;
                }
                MNDP_STORE_IN_FLOW(mndpFlowP, addr, mac_list, num_mac);
                t2_mac_to_str(addr, mac, sizeof(mac));
                break;
            }

            case MNDP_TLV_IDENTITY: { /* Identity */
                MNDP_READ_STR(&t2buf, identity, len);
                MNDP_STORE_IN_FLOW(mndpFlowP, identity, identity_list, num_identity);
                break;
            }

            case MNDP_TLV_VERSION: { /* Version */
                MNDP_READ_STR(&t2buf, version, len);
                MNDP_STORE_IN_FLOW(mndpFlowP, version, version_list, num_version);
                break;
            }

            case MNDP_TLV_PLATFORM: { /* Platform */
                MNDP_READ_STR(&t2buf, platform, len);
                MNDP_STORE_IN_FLOW(mndpFlowP, platform, platform_list, num_platform);
                break;
            }

            case MNDP_TLV_UPTIME: { /* Uptime */
                if (len != sizeof(uint32_t)) {
                    pkt_stat |= MNDP_STAT_TLV_LEN;
                }
                if (!t2buf_read_le_u32(&t2buf, &uptime)) goto mndp_pktmd;
                break;
            }

            case MNDP_TLV_SW_ID: { /* Software-ID */
                MNDP_READ_STR(&t2buf, software_id, len);
                MNDP_STORE_IN_FLOW(mndpFlowP, software_id, sw_id_list, num_sw_id);
                break;
            }

            case MNDP_TLV_BOARD: { /* Board */
                MNDP_READ_STR(&t2buf, board, len);
                MNDP_STORE_IN_FLOW(mndpFlowP, board, board_list, num_board);
                break;
            }

            case MNDP_TLV_UNPACK: { /* Unpack */
                if (len != sizeof(uint8_t)) {
                    pkt_stat |= MNDP_STAT_TLV_LEN;
                }
                if (!t2buf_read_u8(&t2buf, &unpack)) goto mndp_pktmd;
                MNDP_STORE_IN_FLOW(mndpFlowP, unpack, unpack_list, num_unpack);
                break;
            }

            case MNDP_TLV_IPV6_ADDR: { /* IPv6-Address */
                pkt_stat |= MNDP_STAT_IPV6;
                if (len != 16) {
                    pkt_stat |= MNDP_STAT_TLV_LEN;
                }
                ipAddr_t ip;
                for (uint_fast8_t i = 0; i < 16; i++) {
                    if (!t2buf_read_u8(&t2buf, &ip.IPv6.s6_addr[i])) goto mndp_pktmd;
                }
                MNDP_STORE_IN_FLOW(mndpFlowP, ip, ipv6_list, num_ipv6);
                t2_ipv6_to_str(ip.IPv6, ipv6, sizeof(ipv6));
                break;
            }

            case MNDP_TLV_IFACE: { /* Interface name */
                MNDP_READ_STR(&t2buf, iface_name, len);
                MNDP_STORE_IN_FLOW(mndpFlowP, iface_name, iface_list, num_iface);
                break;
            }

            case MNDP_TLV_IPV4_ADDR: { /* IPv4-Address */
                pkt_stat |= MNDP_STAT_IPV4;
                if (len != 4) {
                    pkt_stat |= MNDP_STAT_TLV_LEN;
                }
                struct in_addr ip;
                if (!t2buf_read_le_u32(&t2buf, &ip.s_addr)) goto mndp_pktmd;
                MNDP_STORE_IN_FLOW(mndpFlowP, ip.s_addr, ipv4_list, num_ipv4);
                t2_ipv4_to_str(ip, ipv4, sizeof(ipv4));
                break;
            }

            default: {
                pkt_stat |= MNDP_STAT_UNK_TLV;
                MNDP_DBG("Unknown TLV type 0x%04" B2T_PRIX16, type);
                t2buf_skip_n(&t2buf, len);
                break;
            }
        }
    }

mndp_pktmd:

    mndpFlowP->stat |= pkt_stat;

    if (sPktFile) {
        fprintf(sPktFile,
            "0x%02" B2T_PRIX8 /* mndpStat       */ SEP_CHR
            "%"     PRIu16    /* mndpSeqNo      */ SEP_CHR
            "%s"              /* mndpMAC        */ SEP_CHR
            "%s"              /* mndpIdentity   */ SEP_CHR
            "%s"              /* mndpVersion    */ SEP_CHR
            "%s"              /* mndpPlatform   */ SEP_CHR
            "%"     PRIu32    /* mndpUptime     */ SEP_CHR
            "%s"              /* mndpSoftwareID */ SEP_CHR
            "%s"              /* mndpBoard      */ SEP_CHR
            "%"     PRIu8     /* mndpUnpack     */ SEP_CHR
            "%s"              /* mndpIface      */ SEP_CHR
            "%s"              /* mndpIPv4       */ SEP_CHR
            "%s"              /* mndpIPv6       */ SEP_CHR
            , pkt_stat, seqNo,
              mac, identity, version, platform,
              uptime, software_id, board,
              unpack, iface_name, ipv4, ipv6);
    }
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const mndpFlow_t * const mndpFlowP = &mndpFlows[flowIndex];

    mndpStat |= mndpFlowP->stat;

    // mndpStat
    OUTBUF_APPEND_U8(buf, mndpFlowP->stat);

#if MNDP_LSTLEN > 0
    // mndpMAC
    OUTBUF_APPEND_ARRAY_MAC(buf, mndpFlowP->mac_list, mndpFlowP->num_mac);
    // mndpIdentity
    OUTBUF_APPEND_ARRAY_STR(buf, mndpFlowP->identity_list, mndpFlowP->num_identity);
    // mndpVersion
    OUTBUF_APPEND_ARRAY_STR(buf, mndpFlowP->version_list, mndpFlowP->num_version);
    // mndpPlatform
    OUTBUF_APPEND_ARRAY_STR(buf, mndpFlowP->platform_list, mndpFlowP->num_platform);
    // mndpSoftwareID
    OUTBUF_APPEND_ARRAY_STR(buf, mndpFlowP->sw_id_list, mndpFlowP->num_sw_id);
    // mndpBoard
    OUTBUF_APPEND_ARRAY_STR(buf, mndpFlowP->board_list, mndpFlowP->num_board);
    // mndpUnpack
    OUTBUF_APPEND_ARRAY_U8(buf, mndpFlowP->unpack_list, mndpFlowP->num_unpack);
    // mndpIface
    OUTBUF_APPEND_ARRAY_STR(buf, mndpFlowP->iface_list, mndpFlowP->num_iface);
    // mndpIPv4
    OUTBUF_APPEND_ARRAY_U32(buf, mndpFlowP->ipv4_list, mndpFlowP->num_ipv4);
    // mndpIPv6
    OUTBUF_APPEND_ARRAY_IP6(buf, mndpFlowP->ipv6_list, mndpFlowP->num_ipv6);
#endif
}


void t2PluginReport(FILE *stream) {
    T2_FPLOG_AGGR_HEX(stream, plugin_name, mndpStat);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of MNDP packets", numMndpPkts, numPackets);
}


void t2Finalize() {
    free(mndpFlows);
}
