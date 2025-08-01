/*
 * gquicDecode.c
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

#include "gquicDecode.h"
#include "t2buf.h"

#include <ctype.h> // for isalnum


// Global variables

gquic_flow_t *gquic_flows;


// Static variables

static uint8_t gquicStat;
static uint64_t num_gquic_pkts;
static uint64_t num_gquic_chlo;    // Client Hello
static uint64_t num_gquic_shlo;    // Server Hello
static uint64_t num_gquic_rej;     // Rejection
static uint64_t num_gquic_pub_rst; // Public Reset


// Defines

#define GQUIC_SPKTMD_PRI_HDR() \
    if (sPktFile) { \
        fputs("gquicPubFlags" SEP_CHR \
              "gquicCID"      SEP_CHR \
              "gquicVersion"  SEP_CHR \
              "gquicPktNo"    SEP_CHR \
              , sPktFile); \
    }

#define GQUIC_SPKTMD_PRI_NONE() \
    if (sPktFile) { \
        fputs(/* gquicPubFlags */ SEP_CHR \
              /* gquicCID      */ SEP_CHR \
              /* gquicVersion  */ SEP_CHR \
              /* gquicPktNo    */ SEP_CHR \
              , sPktFile); \
    }


// Function prototypes


// Tranalyzer functions

T2_PLUGIN_INIT("gquicDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(gquic_flows);

    GQUIC_SPKTMD_PRI_HDR();
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8  (bv, "gquicStat"      , "GQUIC status");
    BV_APPEND_H8  (bv, "gquicPubFlags"  , "GQUIC Public Flags");
    //BV_APPEND_H8  (bv, "gquicPrivFlags" , "GQUIC Private Flags");
    BV_APPEND_H16 (bv, "gquicFrameTypes", "GQUIC Frame Types");
    BV_APPEND_U64 (bv, "gquicCID"       , "GQUIC Connection ID");
    //BV_APPEND_H64 (bv, "quicSID"        , "GQUIC Stream IDs");
    BV_APPEND_STRC(bv, "gquicSNI"       , "GQUIC Server Name Indication (SNI)");
    BV_APPEND_STR (bv, "gquicUAID"      , "GQUIC Client's User Agent ID (UAID)");
    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    gquic_flow_t * const gquicFlowP = &gquic_flows[flowIndex];
    memset(gquicFlowP, '\0', sizeof(*gquicFlowP));

    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW) return;

    if (flowP->l4Proto != L3_UDP) return;

    const uint_fast16_t sport = flowP->srcPort;
    const uint_fast16_t dport = flowP->dstPort;

    if (sport == GQUIC_PORT1 || dport == GQUIC_PORT1 ||
        sport == GQUIC_PORT2 || dport == GQUIC_PORT2)
    {
        gquicFlowP->stat |= GQUIC_STAT_GQUIC;
    }
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    GQUIC_SPKTMD_PRI_NONE();
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) {
        GQUIC_SPKTMD_PRI_NONE();
        return;
    }

    gquic_flow_t * const gquicFlowP = &gquic_flows[flowIndex];
    if (!gquicFlowP->stat) { // not a GQUIC packet
        GQUIC_SPKTMD_PRI_NONE();
        return;
    }

    num_gquic_pkts++;

#if DTLS == 1
    uint16_t dHOff = 0;
    if (packet->status & L7_DTLS) dHOff = sizeof(dtls12Header_t);
    const uint16_t snaplen = packet->snapL7Len - dHOff;
    const uint8_t * const l7HdrP = packet->l7HdrP + dHOff;
#else // DTLS == 0
    const uint16_t snaplen = packet->snapL7Len;
    const uint8_t * const l7HdrP = packet->l7HdrP;
#endif // DTLS

    t2buf_t t2buf = t2buf_create(l7HdrP, snaplen);

    flow_t * const flowP = &flows[flowIndex];

    /* Public Flags */
    uint8_t pub_flags;
    if (UNLIKELY(!t2buf_read_u8(&t2buf, &pub_flags))) {
        gquicFlowP->stat |= GQUIC_STAT_SNAPPED;
        GQUIC_SPKTMD_PRI_NONE();
        return;
    }
    gquicFlowP->pub_flags |= pub_flags;
    if (sPktFile) fprintf(sPktFile, "0x%02" B2T_PRIX8 /* gquicPubFlags */ SEP_CHR, pub_flags);
    if (pub_flags & GQUIC_PUB_FLAG_RESERVED) gquicFlowP->stat |= GQUIC_STAT_MALFORMED;

    /* Connection ID (CID) */
    // TODO if version < 33 use GQUIC_PUB_FLAG_CID_OLD
    if (!(pub_flags & GQUIC_PUB_FLAG_CID)) {
        if (sPktFile) fputs(/* gquicCID */ SEP_CHR, sPktFile);
    } else {
        uint64_t cid;
        if (UNLIKELY(!t2buf_read_le_u64(&t2buf, &cid))) {
            gquicFlowP->stat |= GQUIC_STAT_SNAPPED;
            if (sPktFile) {
                fputs(/* gquicCID     */ SEP_CHR
                      /* gquicVersion */ SEP_CHR
                      /* gquicPktNo   */ SEP_CHR
                      , sPktFile);
            }
            return;
        }
        if (sPktFile) fprintf(sPktFile, "%" PRIu64 /* gquicCID */ SEP_CHR, cid);
        if (gquicFlowP->connID != 0 && gquicFlowP->connID != cid) {
            //T2_PWRN(plugin_name, "Flow %" PRIu64 ": connection ID changed from %" PRIu64 " to %" PRIu64,
            //      flowP->findex, gquicFlowP->connID, cid);
            // TODO store the multiple values?
            gquicFlowP->stat |= GQUIC_STAT_CID_CHANGE;
        }
        gquicFlowP->connID = cid;
    }

    // TODO Version Negotiation packet: flag & cid, version (N x 4 bytes)
    // TODO check dir

    /* Version */
    uint8_t version = 0;
    /* Version */
    if (!(pub_flags & GQUIC_PUB_FLAG_VERSION)) {
        // Regular Packet
        if (sPktFile) fputs(/* gquicVersion */ SEP_CHR, sPktFile);
    } else {
        uint8_t ver[4];
        if (UNLIKELY(!t2buf_read_u32(&t2buf, (uint32_t*)ver))) {
            gquicFlowP->stat |= GQUIC_STAT_SNAPPED;
            if (sPktFile) {
                fputs(/* gquicVersion */ SEP_CHR
                      /* gquicPktNo   */ SEP_CHR
                      , sPktFile);
            }
            return;
        }
        version = strtoul((char*)&ver[1], NULL, 10);
        if (sPktFile) {
            for (uint_fast32_t i = 0; i < 4; i++) {
                uint8_t vi = ver[3 - i];
                if (isalnum(vi)) {
                    fprintf(sPktFile, "%c", vi);
                } else {
                    switch (vi) {
                        case '\n':
                            fputs("\\n", sPktFile);
                            break;
                        case '\r':
                            fputs("\\r", sPktFile);
                            break;
                        case '\t':
                            fputs("\\t", sPktFile);
                            break;
                        default:
                            fprintf(sPktFile, "\\0%02o", vi);
                            break;
                    }
                }
            }
            fputs(/* gquicVersion */ SEP_CHR, sPktFile);
        }
        // TODO store version in gquicFlowP
    }

    if (pub_flags & GQUIC_PUB_FLAG_RESET) {
        // Public Reset Packet
        if (!(pub_flags & GQUIC_PUB_FLAG_CID)) gquicFlowP->stat |= GQUIC_STAT_MALFORMED;
        num_gquic_pub_rst++;
        // TODO decode as PRST: RNON, RSEQ, CADR
        if (sPktFile) fputs(/* gquicPktNo */ SEP_CHR, sPktFile);
        return;
    }

    /* Diversification Nonce */
    if (version >= 33 && (pub_flags & GQUIC_PUB_FLAG_DNONCE) && FLOW_IS_B(flowP)) {
        if (UNLIKELY(!t2buf_skip_n(&t2buf, 32))) {
            gquicFlowP->stat |= GQUIC_STAT_SNAPPED;
            if (sPktFile) fputs(/* gquicPktNo */ SEP_CHR, sPktFile);
            return;
        }
    }

    /* Packet Number */
    uint64_t pktnum;
    const uint_fast8_t pktnum_len = MIN(1 << ((pub_flags & GQUIC_PUB_FLAG_PKTNO) >> 4), 6); // 1, 2, 4, 6 bytes
    switch (pktnum_len) {
        case 1: {
            uint8_t pnum;
            if (UNLIKELY(!t2buf_read_u8(&t2buf, &pnum))) {
                gquicFlowP->stat |= GQUIC_STAT_SNAPPED;
                if (sPktFile) fputs(/* gquicPktNo */ SEP_CHR, sPktFile);
                return;
            }
            pktnum = pnum;
            break;
        }
        case 2: {
            uint16_t pnum;
            if (UNLIKELY(!t2buf_read_u16(&t2buf, &pnum))) {
                gquicFlowP->stat |= GQUIC_STAT_SNAPPED;
                if (sPktFile) fputs(/* gquicPktNo */ SEP_CHR, sPktFile);
                return;
            }
            pktnum = pnum;
            break;
        }
        case 4: {
            uint32_t pnum;
            if (UNLIKELY(!t2buf_read_u32(&t2buf, &pnum))) {
                gquicFlowP->stat |= GQUIC_STAT_SNAPPED;
                if (sPktFile) fputs(/* gquicPktNo */ SEP_CHR, sPktFile);
                return;
            }
            pktnum = pnum;
            break;
        }
        default: // pktnum_len == 6
            if (UNLIKELY(!t2buf_read_u48(&t2buf, &pktnum))) {
                gquicFlowP->stat |= GQUIC_STAT_SNAPPED;
                if (sPktFile) fputs(/* gquicPktNo */ SEP_CHR, sPktFile);
                return;
            }
            break;
    }

    if (sPktFile) fprintf(sPktFile, "%" PRIu64 /* gquicPktNo */ SEP_CHR, pktnum);

    // TODO detect if message is encrypted
    //const long pos = t2buf_tell(&t2buf);
    //while (t2buf_left(&t2buf) > 0) {  // TODO use total length (not snapped)
    //    uint8_t ft = GQUIC_READ_U8();
    //}
    //GQUIC_SEEK(&t2buf, pos, SEEK_SET);

    /* Message Authentication Hash */
    GQUIC_SKIP_N(&t2buf, 12);

    /* Private Flags */
    if (version < 34) {
        GQUIC_SKIP_U8(&t2buf);
        //uint8_t priv_flags;
        //GQUIC_READ_U8(&t2buf, &priv_flags);
        //if (priv_flags & GQUIC_PRIV_FLAG_RESERVED) gquicFlowP->stat |= GQUIC_STAT_MALFORMED;
        //gquicFlowP->priv_flags |= priv_flags;
    }

    // Frame Packet

    while (t2buf_left(&t2buf) > 0) {

        /* Frame Type */
        uint8_t ftype;
        GQUIC_READ_U8(&t2buf, &ftype);

        if (ftype & GQUIC_FRAME_TYPE_STREAM) {
#if GQUIC_DEBUG == 2
            T2_PINF(plugin_name, "Packets %" PRIu64 ": STREAM FRAME", numPackets);
#endif
            gquicFlowP->frame_type |= 0x8000;

            const uint_fast8_t data_len = ((ftype & GQUIC_STREAM_FRAME_DLEN) >> 5) << 1;
            uint_fast8_t off_len = ((ftype & GQUIC_STREAM_FRAME_OLEN) >> 2); // 0, 2, 3, 4, 5, 6, 7, 8 bytes
            if (off_len > 0) off_len++;
            const uint_fast8_t sid_len = ((ftype & GQUIC_STREAM_FRAME_SLEN)+1); // 1, 2, 3, 4 bytes

            if (!data_len && !(ftype & GQUIC_STREAM_FRAME_FIN)) gquicFlowP->stat |= GQUIC_STAT_MALFORMED;

            /* Stream ID */
            uint32_t stream_id;
            switch (sid_len) {
                case 1: {
                    uint8_t sid;
                    GQUIC_READ_U8(&t2buf, &sid);
                    stream_id = sid;
                    break;
                }
                case 2: {
                    uint16_t sid;
                    GQUIC_READ_U16(&t2buf, &sid);
                    stream_id = sid;
                    break;
                }
                case 3:
                    GQUIC_READ_U24(&t2buf, &stream_id);
                    break;
                default:
                    GQUIC_READ_U32(&t2buf, &stream_id);
                    break;
            }
            if (stream_id == 0) gquicFlowP->stat |= GQUIC_STAT_MALFORMED;
            else if (stream_id == 1) gquicFlowP->stat |= GQUIC_STAT_HANDSHAKE;
            //if (sPktFile) fprintf(sPktFile, "%" PRIu32 /* gquicSID */ SEP_CHR, stream_id);

            /* Offset */
            GQUIC_SKIP_N(&t2buf, off_len);

            /* Data Length */
            GQUIC_SKIP_N(&t2buf, data_len);

            // stream_id 1 is reserved for GQUIC handshake
            if (stream_id != 1) {
                // TODO
                return;
            }

            /* Tag */
            uint32_t tag;
            GQUIC_READ_U32(&t2buf, &tag);

            if (tag == GQUIC_TAG_CHLO) { // CHLO (Client Hello)
                // Correct the direction
                //if (FLOW_IS_B(flowP)) {
                //    flowP->status &= ~L3FLOWINVERT;
                //    const uint64_t revFlowIndex = flowP->oppositeFlowIndex;
                //    if (revFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
                //        flows[revFlowIndex].status |= L3FLOWINVERT;
                //    }
                //}
                num_gquic_chlo++;
            } else if (tag == GQUIC_TAG_SHLO) { // SHLO (Server Hello)
                // Correct the direction
                //if (FLOW_IS_A(flowP)) {
                //    flowP->status |= L3FLOWINVERT;
                //    const uint64_t revFlowIndex = flowP->oppositeFlowIndex;
                //    if (revFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
                //        flows[revFlowIndex].status &= ~L3FLOWINVERT;
                //    }
                //}
                num_gquic_shlo++;
            } else if (tag == GQUIC_TAG_REJ) { // REJ (Rejection)
                num_gquic_rej++;
            } else if (tag == GQUIC_TAG_PRST) { // PRST (Public Reset)
                num_gquic_pub_rst++;
            } else {
#if GQUIC_DEBUG > 0
                T2_PWRN(plugin_name, "Packet %" PRIu64 ": Unhandled GQUIC tag 0x%08" B2T_PRIX32, numPackets, tag);
#endif
                return;
            }

            /* Tag Number */
            uint16_t tag_number;
            GQUIC_READ_LE_U16(&t2buf, &tag_number);

            /* Padding */
            GQUIC_SKIP_U16(&t2buf);

            const long first_tag_pos = t2buf_tell(&t2buf);
            const long first_val_pos = first_tag_pos + (tag_number << 3);

            uint_fast32_t last_end = 0;

            /* Tag/Value */
            for (uint_fast16_t i = 0; i < tag_number; i++) {
                /* Tag Type */
                uint32_t tag_type;
                GQUIC_READ_U32(&t2buf, &tag_type);

                /* Tag offset end */
                uint32_t tag_end;
                GQUIC_READ_LE_U32(&t2buf, &tag_end);

                uint_fast32_t tag_len = tag_end-last_end;

                /* Tag/Value */
                switch (tag_type) {
                    case GQUIC_TAG_TYPE_SNI: {
                        const long pos = t2buf_tell(&t2buf);
                        GQUIC_SEEK(&t2buf, first_val_pos + last_end, SEEK_SET);
                        GQUIC_READ_STR(&t2buf, gquicFlowP->sni, MIN(tag_len, GQUIC_SLEN));
                        GQUIC_SEEK(&t2buf, pos, SEEK_SET);
//#if GQUIC_DEBUG == 2
//                        T2_INF("%" PRIu64 ": SNI : %s", flows[flowIndex].findex, gquicFlowP->sni);
//#endif
                        break;
                    }
                    case GQUIC_TAG_TYPE_UAID: {
                        const long pos = t2buf_tell(&t2buf);
                        GQUIC_SEEK(&t2buf, first_val_pos + last_end, SEEK_SET);
                        GQUIC_READ_STR(&t2buf, gquicFlowP->uaid, MIN(tag_len, GQUIC_SLEN));
                        GQUIC_SEEK(&t2buf, pos, SEEK_SET);
//#if GQUIC_DEBUG == 2
//                        T2_INF("%" PRIu64 ": UAID : %s", flows[flowIndex].findex, gquicFlowP->uaid);
//#endif
                        break;
                    }
                    case GQUIC_TAG_TYPE_AEAD:
                    case GQUIC_TAG_TYPE_CCRT:
                    case GQUIC_TAG_TYPE_CCS:
                    case GQUIC_TAG_TYPE_CETV:
                    case GQUIC_TAG_TYPE_CFCW:
                    case GQUIC_TAG_TYPE_CGST:
                    case GQUIC_TAG_TYPE_COPT:
                    case GQUIC_TAG_TYPE_CSCT:
                    case GQUIC_TAG_TYPE_ICSL:
                    case GQUIC_TAG_TYPE_IRTT:
                    case GQUIC_TAG_TYPE_KEXS:
                    case GQUIC_TAG_TYPE_MSPC:
                    case GQUIC_TAG_TYPE_NONC:
                    case GQUIC_TAG_TYPE_NONP:
                    case GQUIC_TAG_TYPE_PAD:
                    case GQUIC_TAG_TYPE_PDMD:
                    case GQUIC_TAG_TYPE_PROF:
                    case GQUIC_TAG_TYPE_PUBS:
                    case GQUIC_TAG_TYPE_RREJ:
                    case GQUIC_TAG_TYPE_SCFG:
                    case GQUIC_TAG_TYPE_SCID:
                    case GQUIC_TAG_TYPE_SCLS:
                    case GQUIC_TAG_TYPE_SFCW:
                    case GQUIC_TAG_TYPE_SNO:
                    case GQUIC_TAG_TYPE_SRBF:
                    case GQUIC_TAG_TYPE_STK:
                    case GQUIC_TAG_TYPE_TCID:
                    case GQUIC_TAG_TYPE_VER:
                    case GQUIC_TAG_TYPE_XLCT:
                        break;
                    default:
                        // Nothing to do
#if GQUIC_DEBUG > 0
                        T2_PWRN(plugin_name, "Packet %" PRIu64 ": Unhandled Tag type 0x%08" B2T_PRIX32, numPackets, tag_type);
#endif
                        break;
                }

                last_end = tag_end;
            }
            GQUIC_SEEK(&t2buf, first_val_pos + last_end, SEEK_SET);
        } else if (ftype & GQUIC_FRAME_TYPE_ACK) {
#if GQUIC_DEBUG == 2
            T2_PINF(plugin_name, "Packets %" PRIu64 ": ACK FRAME", numPackets);
#endif
            gquicFlowP->frame_type |= 0x4000;
            //if (sPktFile) fputs(/* gquicSID */ SEP_CHR, sPktFile);
            const uint_fast8_t ll_len = MIN(1 << ((ftype & GQUIC_ACK_FRAME_LL_LEN) >> 2), 6); // 1, 2, 4, 6 bytes
            const uint_fast8_t mm_len = MIN(1 << (ftype & GQUIC_ACK_FRAME_MP_LEN), 6); // 1, 2, 4, 6 bytes
            if (version < 34) {
                GQUIC_SKIP_U8(&t2buf); // Received entropy
                GQUIC_SKIP_N(&t2buf, ll_len); // Largest Observed
                GQUIC_SKIP_U16(&t2buf); // Ack Delay Time
                uint8_t num_ts;
                GQUIC_READ_U8(&t2buf, &num_ts); // Num Timestamp
                if (num_ts > 0) {
                    GQUIC_SKIP_U8(&t2buf); // Delta Largest Observed
                    GQUIC_SKIP_U32(&t2buf); // First timestamp
                    GQUIC_SKIP_N(&t2buf, (num_ts-1) * (1 + 2)); // Delta Largest Observed, Time Since Previous Timestamp
                }
                if (ftype & GQUIC_ACK_FRAME_ACK_N) {
                    uint8_t num_ranges;
                    GQUIC_READ_U8(&t2buf, &num_ranges);
                    GQUIC_SKIP_N(&t2buf, num_ranges * (mm_len+1));
                    uint8_t num_revived;
                    GQUIC_READ_U8(&t2buf, &num_revived);
                    GQUIC_SKIP_N(&t2buf, num_revived * (ll_len+1));
                }
            } else {  // version >= 34
                GQUIC_SKIP_N(&t2buf, ll_len); // Largest Acked
                GQUIC_SKIP_U16(&t2buf);       // Largest Acked Delta Time
                if (ftype & GQUIC_ACK_FRAME_ACK_N) {
                    uint8_t num_blocks;
                    GQUIC_READ_U8(&t2buf, &num_blocks);  // Num blocks
                    if (num_blocks) {
                        GQUIC_SKIP_N(&t2buf, mm_len);
                        GQUIC_SKIP_U8(&t2buf); // Gap to next block
                        GQUIC_SKIP_N(&t2buf, (num_blocks-2)*mm_len);
                    }
                }
                uint8_t num_ts;
                GQUIC_READ_U8(&t2buf, &num_ts);  // Num Timestamp
                if (num_ts) {
                    GQUIC_SKIP_U8(&t2buf); // Delta Largest Acked
                    GQUIC_SKIP_U32(&t2buf); // Time Since Largest Acked
                    GQUIC_SKIP_N(&t2buf, num_ts * (1 + 2));
                }
            }
        } else {
            //if (sPktFile) fputs(/* gquicSID */ SEP_CHR, sPktFile);
            switch (ftype) {
                case GQUIC_FRAME_TYPE_PADDING:
                    // No more interesting data...
                    // TODO check that the padding is 0
#if GQUIC_DEBUG == 2
                    T2_PINF(plugin_name, "Packet %" PRIu64 ": PADDING FRAME", numPackets);
#endif
                    gquicFlowP->frame_type |= (1 << ftype);
                    return;
                case GQUIC_FRAME_TYPE_RST_STREAM:
#if GQUIC_DEBUG == 2
                    T2_PINF(plugin_name, "Packet %" PRIu64 ": RST_STREAM FRAME", numPackets);
#endif
                    gquicFlowP->frame_type |= (1 << ftype);
                    /* Stream ID */
                    GQUIC_SKIP_U32(&t2buf);
                    /* Byte offset */
                    GQUIC_SKIP_U64(&t2buf);
                    /* Error code */
                    GQUIC_SKIP_U32(&t2buf);
                    break;
                case GQUIC_FRAME_TYPE_CONN_CLOSE: {
#if GQUIC_DEBUG == 2
                    T2_PINF(plugin_name, "Packet %" PRIu64 ": CONNECTION_CLOSE FRAME", numPackets);
#endif
                    gquicFlowP->frame_type |= (1 << ftype);
                    /* Error code */
                    GQUIC_SKIP_U32(&t2buf);
                    /* Reason phrase length */
                    uint16_t rlen;
                    GQUIC_READ_U16(&t2buf, &rlen);
                    /* Reason phrase */
                    GQUIC_SKIP_N(&t2buf, rlen);
                    break;
                }
                case GQUIC_FRAME_TYPE_GOAWAY: {
#if GQUIC_DEBUG == 2
                    T2_PINF(plugin_name, "Packet %" PRIu64 ": GOAWAY FRAME", numPackets);
#endif
                    gquicFlowP->frame_type |= (1 << ftype);
                    /* Error code */
                    GQUIC_SKIP_U32(&t2buf);
                    /* Last Good Stream ID */
                    GQUIC_SKIP_U32(&t2buf);
                    /* Reason phrase length */
                    uint16_t rlen;
                    GQUIC_READ_U16(&t2buf, &rlen);
                    /* Reason phrase */
                    GQUIC_SKIP_N(&t2buf, rlen);
                    break;
                }
                case GQUIC_FRAME_TYPE_WIN_UPDATE:
#if GQUIC_DEBUG == 2
                    T2_PINF(plugin_name, "Packet %" PRIu64 ": WINDOW_UPDATE FRAME", numPackets);
#endif
                    gquicFlowP->frame_type |= (1 << ftype);
                    /* Stream ID */
                    GQUIC_SKIP_U32(&t2buf);
                    /* Byte offset */
                    GQUIC_SKIP_U64(&t2buf);
                    break;
                case GQUIC_FRAME_TYPE_BLOCKED:
#if GQUIC_DEBUG == 2
                    T2_PINF(plugin_name, "Packet %" PRIu64 ": BLOCKED FRAME", numPackets);
#endif
                    gquicFlowP->frame_type |= (1 << ftype);
                    /* Stream ID */
                    GQUIC_SKIP_U32(&t2buf);
                    break;
                case GQUIC_FRAME_TYPE_STOP_WAIT:
#if GQUIC_DEBUG == 2
                    T2_PINF(plugin_name, "Packet %" PRIu64 ": STOP_WAITING FRAME", numPackets);
#endif
                    gquicFlowP->frame_type |= (1 << ftype);
                    if (version < 34) GQUIC_SKIP_U8(&t2buf); // Send entropy
                    /* Least Unacked Delta */
                    GQUIC_SKIP_N(&t2buf, pktnum_len);
                    break;
                case GQUIC_FRAME_TYPE_PING:
#if GQUIC_DEBUG == 2
                    T2_PINF(plugin_name, "Packet %" PRIu64 ": PING FRAME", numPackets);
#endif
                    gquicFlowP->frame_type |= (1 << ftype);
                    /* No payload */
                    break;
                default:
#if GQUIC_DEBUG > 0
                    T2_PWRN(plugin_name, "Packet %" PRIu64 ": Unhandled frame type 0x%02" B2T_PRIX8, numPackets, ftype);
#endif
                    break;
            }
        }
    } // end while frame type
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const gquic_flow_t * const gquicFlowP = &gquic_flows[flowIndex];

    gquicStat |= gquicFlowP->stat;

    OUTBUF_APPEND_U8 (buf, gquicFlowP->stat);
    OUTBUF_APPEND_U8 (buf, gquicFlowP->pub_flags);
    OUTBUF_APPEND_U16(buf, gquicFlowP->frame_type);
    OUTBUF_APPEND_U64(buf, gquicFlowP->connID);
    OUTBUF_APPEND_STR(buf, gquicFlowP->sni);
    OUTBUF_APPEND_STR(buf, gquicFlowP->uaid);
}


void t2PluginReport(FILE *stream) {
    if (num_gquic_pkts) {
        T2_FPLOG_AGGR_HEX(stream, plugin_name, gquicStat);
        T2_FPLOG_NUMP0(stream, plugin_name, "Number of GQUIC packets", num_gquic_pkts, numPackets);
        //T2_FPLOG_NUMP(stream, plugin_name, "Number of GQUIC Version Negotiation packets", num_gquic_chlo, num_gquic_pkts);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GQUIC Client Hello packets", num_gquic_chlo, num_gquic_pkts);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GQUIC Server Hello packets", num_gquic_shlo, num_gquic_pkts);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GQUIC Rejection packets", num_gquic_rej, num_gquic_pkts);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GQUIC Public Reset packets", num_gquic_pub_rst, num_gquic_pkts);
    }
}


void t2Finalize() {
    free(gquic_flows);
}
