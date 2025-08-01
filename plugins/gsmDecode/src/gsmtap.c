/*
 * gsmtap.c
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

#include "gsmtap.h"

#include "gsm_a_dtap.h" // for dissect_gsm_a_dtap
#include "gsm_lapdm.h"  // for dissect_lapdm


/* ========================================================================= */
/* GSMTAP                                                                    */
/* ========================================================================= */
inline bool dissect_gsmtap(t2buf_t *t2buf, gsm_metadata_t *md) {

    const long start = t2buf_tell(t2buf);

    uint8_t version;
    t2buf_read_u8(t2buf, &version);

    uint8_t hdrlen;
    t2buf_read_u8(t2buf, &hdrlen);
    hdrlen <<= 2;

    uint8_t payload_type;
    t2buf_read_u8(t2buf, &payload_type); // 1: Um, 2: Abis, 3: Um burst, 12: UMTS RRC, 13: LTE RRC

    if (
               version != 2
            || hdrlen <= 2
            || t2buf_left(t2buf) < hdrlen - 1
            || (payload_type != 1 && payload_type != 2)
    ) {
        t2buf_seek(t2buf, start, SEEK_SET);
        return false;
    }

    numGSMTAP++;

    uint8_t time_slot;
    t2buf_read_u8(t2buf, &time_slot);

    uint16_t arfcn; // & 0x8000: PCS band indicator,
                    // & 0x4000: 0=Uplink, 1=Downlink
    t2buf_read_u16(t2buf, &arfcn);
    if (arfcn & 0x4000) {
        md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
    } else {
        md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
    }

    uint8_t signal_level;
    t2buf_read_u8(t2buf, &signal_level);

    uint8_t signal_noise_ratio;
    t2buf_read_u8(t2buf, &signal_noise_ratio);

    uint32_t gsm_frame_number;
    t2buf_read_u32(t2buf, &gsm_frame_number);

    uint8_t channel_type;
    t2buf_read_u8(t2buf, &channel_type);

    uint8_t antenna_number;
    t2buf_read_u8(t2buf, &antenna_number);

    uint8_t sub_slot;
    t2buf_read_u8(t2buf, &sub_slot);

    t2buf_skip_u8(t2buf); // Reserved for future use

    GSM_DBG_GSMTAP("%" PRIu64 ": version: %u, header_length: %u, payload_type: %u, time_slot: %u, arfcn: %u, signal_level: %u, signal_noise_ratio: %u, frame_number: %" PRIu32 ", channel_type: %u, antenna_number: %u, sub_slot: %u",
            numPackets, version, hdrlen, payload_type, time_slot, arfcn, signal_level, signal_noise_ratio, gsm_frame_number, channel_type, antenna_number, sub_slot);

    if (payload_type == 2) { // Abis
        return dissect_gsm_a_dtap(t2buf, md);
    } else { // Um
        switch (channel_type) {
            case 0x01:   // BCCH
            case 0x02:   // CCCH
            case 0x03:   // RACH
            case 0x04:   // AGCH
            case 0x05: { // PCH
                uint8_t pseudo_length;
                t2buf_read_u8(t2buf, &pseudo_length);
                return dissect_gsm_a_dtap(t2buf, md);
            }

            case 0x06:   // SDCCH
            case 0x07:   // SDCCH/4
            case 0x08:   // SDCCH/8
            case 0x09:   // TCH/F
            case 0x0a: { // TCH/H
                dissect_lapdm(t2buf, md);
                return dissect_gsm_a_dtap(t2buf, md);
            }

            case 0x84:   // SACCH/4
            case 0x88:   // SACCH/8
            case 0x89: { // SACCH/F
                // SACCH L1 Header
                t2buf_skip_u8(t2buf); // & 0x40: SRO/SRR (SACCH Repetition)
                                      // & 0x20: FPC (Fast Power Control)
                                      // & 0x1f: MS power level
                t2buf_skip_u8(t2buf); // Actual Timing Advance
                dissect_lapdm(t2buf, md);
                return dissect_gsm_a_dtap(t2buf, md);
            }

            case 0x0b: // PACCH
                // TODO GSM RLC/MAC
                break;
            case 0x0c: // CBCH52
                break;
            case 0x0d: // PDTCH
                break;
            case 0x0e: // PTCCH
                break;
            case 0x0f: // CBCH51
                break;
            case 0x10: // VOICE/F
                break;
            case 0x11: // VOICE/H
                break;
            case 0x80: // ACCH
                break;

            default:
#if GSM_DBG_GSMTAP_UNK == 1
                GSM_DBG_GSMTAP("%" PRIu64 ": Unknown channel type 0x%02" B2T_PRIX8, numPackets, channel_type);
#endif
                return false;
        }
    }

    return false;
}
