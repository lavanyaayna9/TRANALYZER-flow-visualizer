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

#include "stpDecode.h"
#include "proto/ethertype.h"


// Global variables

stpFlow_t *stpFlows;


#if ETH_ACTIVATE > 0

// Static variables

static uint64_t numStpPkts, numStpPkts0;
static uint8_t stpStat, stpType, stpFlags;


#define STP_SPKTMD_PRI_NONE() \
    if (sPktFile) { \
        fputs("0x00" /* stpStat         */ SEP_CHR  \
                     /* stpProto        */ SEP_CHR  \
                     /* stpVer          */ SEP_CHR  \
                     /* stpType         */ SEP_CHR  \
                     /* stpFlags        */ SEP_CHR  \
                     /* stpRtCst        */ SEP_CHR  \
                     /* STP_RTPREXT -> see below */ \
                     /* stpPort         */ SEP_CHR  \
                     /* stpMsgAge       */ SEP_CHR  \
                     /* stpMaxAge       */ SEP_CHR  \
                     /* stpHello        */ SEP_CHR  \
                     /* stpFrwrd        */ SEP_CHR  \
                     /* stpPvstOrigVlan */ SEP_CHR  \
             , sPktFile); \
        if (STP_RTPREXT == 1) { \
            fputs(/* stpRtPrio       */ SEP_CHR \
                  /* stpRtExt        */ SEP_CHR \
                  /* stpRtMAC        */ SEP_CHR \
                  /* stpBrdgPrio     */ SEP_CHR \
                  /* stpBrdgExt      */ SEP_CHR \
                  /* stpBrdgMAC      */ SEP_CHR \
                  , sPktFile); \
        } else { /* STP_RTPREXT == 0 */ \
            fputs(/* stpRtBID        */ SEP_CHR \
                  /* stpBrdgID       */ SEP_CHR \
                  , sPktFile); \
        } \
    }

#endif // ETH_ACTIVATE > 0


// Tranalyzer functions

T2_PLUGIN_INIT("stpDecode", "0.9.3", 0, 9);


void t2Init() {
#if ETH_ACTIVATE == 0
    T2_PWRN(plugin_name, "ETH_ACTIVATE is set to 0 in 'networkHeaders.h', no output will be produced");
#else // ETH_ACTIVATE > 0
    T2_PLUGIN_STRUCT_NEW(stpFlows);

    if (sPktFile) {
        fputs("stpStat"         SEP_CHR
              "stpProto"        SEP_CHR
              "stpVer"          SEP_CHR
              "stpType"         SEP_CHR
              "stpFlags"        SEP_CHR
              "stpRtCst"        SEP_CHR
#if STP_RTPREXT == 1
              "stpRtPrio"       SEP_CHR
              "stpRtExt"        SEP_CHR
              "stpRtMAC"        SEP_CHR
              "stpBrdgPrio"     SEP_CHR
              "stpBrdgExt"      SEP_CHR
              "stpBrdgMAC"      SEP_CHR
#else // STP_RTPREXT == 0
              "stpRtBID"        SEP_CHR
              "stpBrdgID"       SEP_CHR
#endif // STP_RTPREXT
              "stpPort"         SEP_CHR
              "stpMsgAge"       SEP_CHR
              "stpMaxAge"       SEP_CHR
              "stpHello"        SEP_CHR
              "stpFrwrd"        SEP_CHR
              "stpPvstOrigVlan" SEP_CHR
              , sPktFile);
    }
#endif // ETH_ACTIVATE > 0
}


// If ETH_ACTIVATE == 0, the plugin does not produce any output.
// All the code below is therefore not activated.


#if ETH_ACTIVATE > 0

binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8( bv, "stpStat"    , "STP status");
    //BV_APPEND_H16(bv, "stpProto"   , "STP Protocol Identifier"); // Always 0x0000
    BV_APPEND_U8( bv, "stpVer"     , "STP protocol version identifier");
    BV_APPEND_H8( bv, "stpType"    , "STP aggregated BPDU types");
    BV_APPEND_H8( bv, "stpFlags"   , "STP aggregated BPDU flags");
    BV_APPEND_U32(bv, "stpRtCst"   , "STP root cost");
#if STP_RTPREXT == 1
    BV_APPEND_U16(bv, "stpRtPrio"  , "STP root priority");
    BV_APPEND_U16(bv, "stpRtExt"   , "STP root extension (VLAN)");
    //BV_APPEND_STRC(bv, "stpRtMAC"  , "STP Root MAC");
    BV_APPEND_MAC(bv, "stpRtMAC"   , "STP root MAC");
    BV_APPEND_U16(bv, "stpBrdgPrio", "STP bridge priority");
    BV_APPEND_U16(bv, "stpBrdgExt" , "STP bridge extension (VLAN)");
    BV_APPEND_MAC(bv, "stpBrdgMAC" , "STP bridge MAC");
#else // STP_RTPREXT == 0
    BV_APPEND_H64(bv, "stpRtBID"   , "STP root bridge ID");
    BV_APPEND_H64(bv, "stpBrdgID"  , "STP bridge ID");
#endif // STP_RTPREXT
    BV_APPEND_U16(bv, "stpFrwrd"   , "STP forward delay");
    return bv;
}


void t2OnNewFlow(packet_t* packet, unsigned long flowIndex) {
    stpFlow_t * const stpFlowP = &stpFlows[flowIndex];
    memset(stpFlowP, '\0', sizeof(*stpFlowP));

    if (!(packet->status & L2_FLOW)) return;

    const uint_fast16_t l2Type = packet->ethType;
    if ((l2Type & LLC_DCODE) != LLC_STP && l2Type != ETHERTYPE_PVSTP) return;

    stpFlowP->stpStat |= STP_STAT_STP;

    const stpMsg_t * const stpMsgP = (stpMsg_t*)packet->l7HdrP;
    //stpFlowP->proto = stpMsgP->proto;
    stpFlowP->version = stpMsgP->version;
    stpFlowP->rootCost = stpMsgP->rootCost;
    stpFlowP->root = stpMsgP->root;
    stpFlowP->bridge = stpMsgP->bridge;
    stpFlowP->frwrd = stpMsgP->forward;
    stpFlowP->stpType |= stpMsgP->type;
}


void t2OnLayer2(packet_t* packet, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    stpFlow_t * const stpFlowP = &stpFlows[flowIndex];
    if (!stpFlowP->stpStat) {
        STP_SPKTMD_PRI_NONE();
        return;
    }

    numStpPkts++;

    const stpMsg_t * const stpMsgP = (stpMsg_t*)packet->l7HdrP;
    stpFlowP->stpFlags |= stpMsgP->flags;

    if (!sPktFile) return;

    fprintf(sPktFile,
            "0x%02" B2T_PRIX8  /* stpStat  */ SEP_CHR
            "0x%04" B2T_PRIX16 /* stpProto */ SEP_CHR
            "%"     PRIu8      /* stpVer   */ SEP_CHR
            "0x%02" B2T_PRIX8  /* stpType  */ SEP_CHR
            , stpFlowP->stpStat, stpMsgP->proto, stpMsgP->version, stpMsgP->type);

    if (stpMsgP->type == STP_BPDU_T_TCN) {
        fputs(/* stpFlags        */ SEP_CHR
              /* stpRtCst        */ SEP_CHR
#if STP_RTPREXT == 1
              /* stpRtPrio       */ SEP_CHR
              /* stpRtExt        */ SEP_CHR
              /* stpRtMAC        */ SEP_CHR
              /* stpBrdgPrio     */ SEP_CHR
              /* stpBrdgExt      */ SEP_CHR
              /* stpBrdgMAC      */ SEP_CHR
#else // STP_RTPREXT == 0
              /* stpRtBID        */ SEP_CHR
              /* stpBrdgID       */ SEP_CHR
#endif // STP_RTPREXT
              /* stpPort         */ SEP_CHR
              /* stpMsgAge       */ SEP_CHR
              /* stpMaxAge       */ SEP_CHR
              /* stpHello        */ SEP_CHR
              /* stpFrwrd        */ SEP_CHR
              /* stpPvstOrigVlan */ SEP_CHR
              , sPktFile);
        return;
    }

    char bridgeHw[T2_MAC_STRLEN+1] = {}, rootHw[T2_MAC_STRLEN+1] = {};
    t2_mac_to_str(&stpMsgP->rootHW[0], rootHw, sizeof(rootHw));
    t2_mac_to_str(&stpMsgP->bridgeHW[0], bridgeHw, sizeof(bridgeHw));

    fprintf(sPktFile,
            "0x%02"  B2T_PRIX8  /* stpFlags    */ SEP_CHR
            "%"      PRIu32     /* stpRtCst    */ SEP_CHR
#if STP_RTPREXT == 1
            "%"      PRIu16     /* stpRtPrio   */ SEP_CHR
            "%"      PRIu16     /* stpRtExt    */ SEP_CHR
            "%s"                /* stpRtMAC    */ SEP_CHR
            "%"      PRIu16     /* stpBrdgPrio */ SEP_CHR
            "%"      PRIu16     /* stpBrdgExt  */ SEP_CHR
            "%s"                /* stpBrdgMAC  */ SEP_CHR
#else // STP_RTPREXT == 0
            "0x%016" B2T_PRIX64 /* stpRtBID    */ SEP_CHR
            "0x%016" B2T_PRIX64 /* stpBrdgID   */ SEP_CHR
#endif // STP_RTPREXT
            "0x%04"  B2T_PRIX16 /* stpPort     */ SEP_CHR
            "%"      PRIu16     /* stpMsgAge   */ SEP_CHR
            "%"      PRIu16     /* stpMaxAge   */ SEP_CHR
            "%"      PRIu16     /* stpHello    */ SEP_CHR
            "%"      PRIu16     /* stpFrwrd    */ SEP_CHR
            , stpMsgP->flags,
              ntohl(stpMsgP->rootCost),
#if STP_RTPREXT == 1
              STP_ROOT_PRIO(stpMsgP), STP_ROOT_EXT(stpMsgP), rootHw,
              STP_BRIDGE_PRIO(stpMsgP), STP_BRIDGE_EXT(stpMsgP), bridgeHw,
#else // STP_RTPREXT == 0
              be64toh(stpMsgP->root),
              be64toh(stpMsgP->bridge),
#endif // STP_RTPREXT
              ntohs(stpMsgP->port), stpMsgP->msgAge,
              stpMsgP->maxAge, stpMsgP->hello, stpMsgP->forward);

    // TODO MST Extension

    // stpPvstOrigVlan
    if (packet->ethType == ETHERTYPE_PVSTP && ((uint8_t*)stpMsgP + sizeof(stpMsg_t)) < packet->end_packet) {
        const pvstpTLV_t * const tlv = (pvstpTLV_t*)((uint8_t*)stpMsgP + sizeof(stpMsg_t));
        if (tlv->type == 0 && ntohs(tlv->len) == 2) {
            fprintf(sPktFile, "%" PRIu16, ntohs(tlv->value));
        }
    }
    fputs(SEP_CHR, sPktFile);
}


void t2OnLayer4(packet_t* packet UNUSED, unsigned long flowIndex UNUSED) {
    STP_SPKTMD_PRI_NONE();
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const stpFlow_t * const stpFlowP = &stpFlows[flowIndex];

    stpStat  |= stpFlowP->stpStat;
    stpFlags |= stpFlowP->stpFlags;
    stpType  |= stpFlowP->stpType;

    OUTBUF_APPEND_U8(buf, stpFlowP->stpStat);  // stpStat
    //OUTBUF_APPEND_U16(buf, stpFlowP->proto); // stpProto
    OUTBUF_APPEND_U8(buf, stpFlowP->version);  // stpVer
    OUTBUF_APPEND_U8(buf, stpFlowP->stpType);  // stpType
    OUTBUF_APPEND_U8(buf, stpFlowP->stpFlags); // stpFlags

    OUTBUF_APPEND_U32_NTOH(buf, stpFlowP->rootCost); // stpRtCst

#if STP_RTPREXT == 1
    const bid_t bidsr = { .bid = stpFlowP->root };
    // stpRtPrio
    const uint16_t j1 = STP_PRIO(bidsr.prioExt);
    OUTBUF_APPEND_U16(buf, j1);
    // stpRtExt
    const uint16_t j2 = STP_EXT(bidsr.prioExt);
    OUTBUF_APPEND_U16(buf, j2);
    // stpRtMAC
    OUTBUF_APPEND_MAC(buf, bidsr.mac);

    const bid_t bidse = { .bid = stpFlowP->bridge };
    // stpBrdgPrio
    const uint16_t k1 = STP_PRIO(bidse.prioExt);
    OUTBUF_APPEND_U16(buf, k1);
    // stpBrdgExt
    const uint16_t k2 = STP_EXT(bidse.prioExt);
    OUTBUF_APPEND_U16(buf, k2);
    // stpBrdgMAC
    OUTBUF_APPEND_MAC(buf, bidse.mac);
#else // STP_RTPREXT == 0
    // stpRtBID
    const uint64_t j1 = be64toh(stpFlowP->root);
    OUTBUF_APPEND_U64(buf, j1);

    // stpBrdgID
    const uint64_t k1 = be64toh(stpFlowP->bridge);
    OUTBUF_APPEND_U64(buf, k1);
#endif // STP_RTPREXT == 1

    OUTBUF_APPEND_U16(buf, stpFlowP->frwrd); // stpFrwrd
}


static inline void stp_pluginReport(FILE *stream) {
    if (numStpPkts) {
        T2_FPLOG_AGGR_HEX(stream, plugin_name, stpStat);
        T2_FPLOG(stream, plugin_name, "Aggregated BPDU stpType=0x%02" B2T_PRIX8, stpType);
        T2_FPLOG(stream, plugin_name, "Aggregated BPDU stpFlags=0x%02" B2T_PRIX8, stpFlags);
        T2_FPLOG_DIFFNUMP(stream, plugin_name, "Number of STP packets", numStpPkts, numPackets);
    }
}


void t2PluginReport(FILE *stream) {
#if DIFF_REPORT == 1
    numStpPkts0 = 0;
#endif // DIFF_REPORT == 1
    stp_pluginReport(stream);
}


void t2Monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        case T2_MON_PRI_HDR:
            fputs("stpPkts" SEP_CHR
                  , stream);
            return;

        case T2_MON_PRI_VAL:
            fprintf(stream,
                    "%" PRIu64 /* stpPkts */ SEP_CHR
                    , numStpPkts - numStpPkts0);
            break;

        case T2_MON_PRI_REPORT:
            stp_pluginReport(stream);
            break;

        // Invalid state, do nothing
        default:
            return;
    }

#if DIFF_REPORT == 1
    numStpPkts0 = numStpPkts;
#endif // DIFF_REPORT == 1
}


void t2Finalize() {
    free(stpFlows);
}

#endif // ETH_ACTIVATE > 0
