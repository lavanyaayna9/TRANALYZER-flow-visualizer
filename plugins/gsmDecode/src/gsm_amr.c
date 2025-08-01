/*
 * gsm_amr.c
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

#include "gsm_amr.h"

#include "gsmDecode.h" // for numAMR


#if GSM_SPEECHFILE == 1

// This function assumes 'in' is a valid RTP AMR frame
inline void rtp_amr_convert_and_write(const uint8_t *in, FILE *file, gsmFlow_t *gsmFlowP) {
    /*
     * | P |    FT   | Q |
     * |---|---------|---|
     * | 0 | 0 0 1 1 | 1 |
     * |---|---------|---|
     *
     * P is padding (0)
     * FT is the frame type:
     *    0: AMR 4.75 kbps               -> 0x04 + 12 bytes
     *    1: AMR 5.15 kbps               -> 0x0c + 13 bytes
     *    2: AMR 5.90 kbps               -> 0x14 + 15 bytes
     *    3: AMR 6.70 kbps               -> 0x1c + 17 bytes
     *    4: AMR 7.40 kbps               -> 0x24 + 19 bytes
     *    5: AMR 7.95 kbps               -> 0x2c + 20 bytes
     *    6: AMR 10.2 kbps               -> 0x34 + 26 bytes
     *    7: AMR 12.2 kbps               -> 0x3c + 31 bytes
     *    8: AMR SID                     -> 0x44 +  5 bytes
     *    9: GSM_EFR_SID                 -> 0x4c
     *   10: TDMA_EFR_SID                -> 0x54
     *   11: PDC_EFR_SID                 -> 0x5c
     *   12: Reserved for future use     -> 0x64
     *   13: Reserved for future use     -> 0x6c
     *   14: Reserved for future use     -> 0x74
     *   15: No data to transmit/receive -> 0x7c
     * Q is the quality indicator:
     *   0: bad
     *   1: good
     */

    const uint8_t ftq = (*in & 0xfc);
    const uint8_t amr_ft = ((ftq & 0xf8) >> 3);
    if (!osmo_amr_is_speech(amr_ft)) return;

    const bool good_frame = ((*in & 0x04) >> 2);
    numAMRFrames[good_frame]++;
    numAMR[amr_ft][good_frame]++;
    gsmFlowP->num_amr[good_frame]++;

    // Discard bad frames
    if (!good_frame) return;

    const uint_fast32_t dlen = amr_len_by_ft[amr_ft] + 1;

    uint8_t conv[33] = {};
    conv[0] = ftq;
    for (uint_fast32_t i = 1; i < dlen; i++, in++) {
        conv[i] = (((*in & 0x03) << 6) | ((*(in + 1) & 0xfc) >> 2));
    }

    /*if (*(in-1)==0x4f)*/
    fwrite(conv, 1, dlen, file);
}


inline bool is_rtp_amr_speech(uint8_t amr_type) {
    switch (amr_type) {
        case AMR_4_75:
        case AMR_5_15:
        case AMR_5_90:
        case AMR_6_70:
        case AMR_7_40:
        case AMR_7_95:
        case AMR_10_2:
        case AMR_12_2:
        case AMR_SID:
            return true;
        default:
            return false;
    }
}

#endif // GSM_SPEECHFILE == 1
