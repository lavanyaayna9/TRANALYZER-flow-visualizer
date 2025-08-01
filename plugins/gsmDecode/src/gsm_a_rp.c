/*
 * gsm_a_rp.c
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

#include "gsm_a_rp.h"

#include "gsm_sms.h"   // for dissect_gsm_sms
#include "gsm_utils.h" // for t2buf_read_bcd_number


/* ========================================================================= */
/* GSM A-I/F RP                                                              */
/* ========================================================================= */
inline bool dissect_gsm_a_rp(t2buf_t *t2buf, gsm_metadata_t *md) {

    bool has_next_layer = false;

    const uint16_t pktlen = md->packet->l7Len;

    md->gsmFlowP->pstat |= GSM_STAT_RP;

    /* Message Type */
    uint8_t rp_msg_type;
    t2buf_read_u8(t2buf, &rp_msg_type);
    md->a_rp.msg_type = rp_msg_type;

    /* RP-Message Reference */
    uint8_t rp_msg_ref;
    t2buf_read_u8(t2buf, &rp_msg_ref);
    GSM_DBG_A_RP("%" PRIu64 ": RP-Message Reference: 0x%02" B2T_PRIX8, numPackets, rp_msg_ref);

    switch (rp_msg_type) {
        case 0x00:   // RP-DATA (MS to Network)
        case 0x01: { // RP-DATA (Network to MS)
            GSM_DBG_A_RP("%" PRIu64 ": RP-DATA", numPackets);
            if (rp_msg_type == 0x00) {
                md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
                md->a_rp.ms_sc = true;
            } else {
                md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
                md->a_rp.ms_sc = false;
            }
            /* RP-Originator Address */
            md->a_rp.originator_addr = t2buf_read_bcd_number(t2buf);
            /* RP-Destination Address */
            md->a_rp.destination_addr = t2buf_read_bcd_number(t2buf);
            /* RP-User-Data */
            has_next_layer = true;
            break;
        }

        case 0x02:   // RP-ACK (MS to Network)
        case 0x03: { // RP-ACK (Network to MS)
            GSM_DBG_A_RP("%" PRIu64 ": RP-ACK", numPackets);
            if (rp_msg_type == 0x02) {
                md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
                md->a_rp.ms_sc = true;
            } else {
                md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
                md->a_rp.ms_sc = false;
            }
            /* RP-User-Data */
            uint8_t iei;
            if (t2buf_peek_u8(t2buf, &iei) && iei == 0x41) {
                t2buf_skip_u8(t2buf); // iei
                has_next_layer = true;
            }
            break;
        }

        case 0x04:   // RP-ERROR (MS to Network)
        case 0x05: { // RP-ERROR (Network to MS)
            GSM_DBG_A_RP("%" PRIu64 ": RP-ERROR", numPackets);
            if (rp_msg_type == 0x04) {
                md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
                md->a_rp.ms_sc = true;
            } else {
                md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
                md->a_rp.ms_sc = false;
            }
            /* RP-Cause*/
            uint8_t len;
            t2buf_read_u8(t2buf, &len);
            if (len > 0) {
                uint8_t cause;
                t2buf_read_u8(t2buf, &cause);
                GSM_DBG_A_RP("%" PRIu64 ": RP-Cause: %u", numPackets, cause & 0x7f);
                t2buf_skip_n(t2buf, len-1);
            }
            /* RP-User-Data */
            uint8_t iei;
            if (!t2buf_peek_u8(t2buf, &iei) && iei == 0x41) {
                t2buf_skip_u8(t2buf); // iei
                has_next_layer = true;
            }
            break;
        }

        case 0x06: { // RP-SMMA (MS to Network)
            GSM_DBG_A_RP("%" PRIu64 ": RP-SMMA", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            md->a_rp.ms_sc = true;
            break;
        }

        default: {
#if GSM_DBG_A_RP_UNK == 1
            GSM_DBG_A_RP("%" PRIu64 ": Unknown GSM A-I/F RP message type: 0x%02" B2T_PRIX8, numPackets, rp_msg_type);
#endif
            md->gsmFlowP->pstat |= GSM_STAT_MALFORMED;
            break;
        }
    }

    /* RP-User Data */
    if (has_next_layer) {
        /* RP-User Data Length */
        uint8_t rp_ud_len;
        t2buf_read_u8(t2buf, &rp_ud_len);
        GSM_DBG_A_RP("%" PRIu64 ": RP-User Data Length: %" PRIu8 " (0x%0" B2T_PRIX8 ")", numPackets, rp_ud_len, rp_ud_len);
        if (rp_ud_len != pktlen - t2buf_tell(t2buf)) {
#if GSM_DBG_A_RP_UNK == 1
            GSM_DBG_A_RP("%" PRIu64 ": Byte %lu (RP) is not the PDU length: 0x%02" B2T_PRIX8 " (%" PRIu8 ") != %lu", numPackets, t2buf_tell(t2buf), rp_ud_len, rp_ud_len, pktlen - t2buf_tell(t2buf));
#endif
            md->gsmFlowP->pstat |= GSM_STAT_MALFORMED;
            return false;
        }

        has_next_layer = dissect_gsm_sms(t2buf, md);
    }

    return has_next_layer;
}
