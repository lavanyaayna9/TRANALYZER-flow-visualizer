/*
 * gsm_lapd.c
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

#include "gsm_lapd.h"


/*************************************************************************/
/* Link Access Protocol for D Channel (LAPD)                             */
/*************************************************************************/

inline bool dissect_lapd(t2buf_t *t2buf, gsm_metadata_t *md) {
    bool has_next_layer = false;

    /* Address field */
    uint16_t address;
    if (!t2buf_read_u16(t2buf, &address)) return false;

    /* Control field */
    uint8_t ctrl_octet;
    if (!t2buf_peek_u8(t2buf, &ctrl_octet)) return false;

    uint16_t ctrl;
    if ((ctrl_octet & 0x03) == 0x03) {     // Unnumbered frame
        t2buf_read_u8(t2buf, &ctrl_octet); // We know this byte exists as we peek'd it!
        ctrl = ctrl_octet;
    } else {                               // Information or Supervisory frame
        if (!t2buf_read_u16(t2buf, &ctrl)) return false;
    }

    const uint8_t address1 = ((address & 0xff00) >> 8);
    const uint8_t address2 = (address & 0x00ff);

    // Service Access Point Identifier (SAPI)
    const uint8_t sapi = ((address1 & 0xfc) >> 2);
    md->gsmFlowP->sapi = sapi;

    // Terminal Endpoint Identifier (TEI)
    const uint8_t tei = ((address2 & 0xfe) >> 1);
    md->gsmFlowP->tei = tei;

    //const uint8_t cr = ((sapi & 0x02) >> 1);    // Command/Response bit
    //const uint8_t ea1 = (address1 & 0x01);      // First Address Extension bit (=1)
    //const uint8_t ea2 = (address2 & 0x01);      // Second Address Extension bit (=0)

    //if (ea1 != 0 || ea2 != 1) {
    //    md->gsmFlowP->pstat |= GSM_STAT_LAPD_MALFORMED;
    //}

    switch (sapi) {
        case 0: // Radio signaling (radio signaling link or RSL)
            md->gsmFlowP->pstat |= GSM_STAT_LAPD_RSL;
            break;
        case 62: // 0&M messages (O&M link or OML)
            md->gsmFlowP->pstat |= GSM_STAT_LAPD_OML;
            GSM_DBG_LAPD("%" PRIu64 ": Ignoring OML for now...", numPackets);
            break;
        case 63: // Layer 2 management
            md->gsmFlowP->pstat |= GSM_STAT_LAPD_L2M;
            GSM_DBG_LAPD("%" PRIu64 ": Ignoring Layer 2 management for now...", numPackets);
            break;
        default:
#if GSM_DBG_LAPD_UNK == 1
            GSM_DBG_LAPD("%" PRIu64 ": Ignoring unknown LAPD SAPI %u", numPackets, sapi);
#endif
            md->gsmFlowP->pstat |= GSM_STAT_LAPD_MALFORMED;
            break;
    }

    if ((ctrl_octet & 0x01) == 0x00) {
        // Only process information frames with SAPI 0
        has_next_layer = (sapi == 0);
#if GSM_DEBUG_LAPD == 1
        // N(R) (3/7 bits), P (1 bit), N(S) (3/7 bits), 0
        const uint8_t ns = ((ctrl & 0xfe00) >> 9);
        const uint8_t nr = ((ctrl & 0x00fe) >> 1);
        GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, I-Frame, N(R)=%u, N(S)=%u", numPackets, sapi, tei, nr, ns);
#endif
    } else {
        switch (ctrl_octet & 0x03) {
            case 0x01: {
                const uint8_t nr = ((ctrl & 0x00fe) >> 1);
                GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, Supervisory Frame, N(R)=%u", numPackets, sapi, tei, nr);
                switch (ctrl_octet & 0x0c) {
                    case 0x00: GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, RR-Frame", numPackets, sapi, tei);  break; // 01 xx
                    case 0x01: GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, RNR-Frame", numPackets, sapi, tei); break; // 05 xx
                    case 0x02: GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, REJ-Frame", numPackets, sapi, tei); break; // 09 xx
                    default:
#if GSM_DBG_LAPD_UNK == 1
                        GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, Unknown supervisory frame: 0x%02" B2T_PRIX8,
                                numPackets, sapi, tei, (uint8_t)(ctrl_octet & 0x0c));
#endif
                        md->gsmFlowP->pstat |= GSM_STAT_LAPD_MALFORMED;
                        break;
                }
                break;
            }
            case 0x03:
                GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, Unnumbered Frame", numPackets, sapi, tei);
                switch (ctrl_octet & 0x0c) {
                    case 0x00:
                        switch (ctrl_octet & 0xe0) {
                            case 0x00: GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, UI-Frame", numPackets, sapi, tei);   break; // 03
                            case 0x20: GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, DISC-Frame", numPackets, sapi, tei); break; // 53
                            case 0x30: GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, UA-Frame", numPackets, sapi, tei);   break; // 73
                            default:
#if GSM_DBG_LAPD_UNK == 1
                                GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, Unknown unnumbered frame: 0x%02" B2T_PRIX8,
                                             numPackets, sapi, tei, (uint8_t)(ctrl_octet & 0xe0));
#endif
                                md->gsmFlowP->pstat |= GSM_STAT_LAPD_MALFORMED;
                                break;
                        }
                        break;
                    case 0x01:
                        switch (ctrl_octet & 0xe0) {
                            case 0x00: GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, SIM-Frame", numPackets, sapi, tei); break;
                            default: GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, FRMR-Frame", numPackets, sapi, tei); break;  // 87, 97
                        }
                        break;
                    case 0x03:
                        switch (ctrl_octet & 0xe0) {
                            case 0x00: GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, DM-Frame", numPackets, sapi, tei);    break; // 0f, 1f
                            case 0x30: GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, SABME-Frame", numPackets, sapi, tei); break; // 7f
                            case 0x50: GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, XID-Frame", numPackets, sapi, tei);   break; // af, bf
                            default:
#if GSM_DBG_LAPD_UNK == 1
                                GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, Unknown unnumbered frame: 0x%02" B2T_PRIX8,
                                             numPackets, sapi, tei, (uint8_t)(ctrl_octet & 0xe0));
#endif
                                md->gsmFlowP->pstat |= GSM_STAT_LAPD_MALFORMED;
                                break;
                        }
                        break;
                    default:
#if GSM_DBG_LAPD_UNK == 1
                        GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, Unknown unnumbered frame: 0x%02" B2T_PRIX8,
                                     numPackets, sapi, tei, (uint8_t)(ctrl_octet & 0x0c));
#endif
                        md->gsmFlowP->pstat |= GSM_STAT_LAPD_MALFORMED;
                        break;
                }
                break;
            default:
#if GSM_DBG_LAPD_UNK == 1
                GSM_DBG_LAPD("%" PRIu64 ": SAPI: %u, TEI: %u, unknown frame: 0x%02" B2T_PRIX8,
                             numPackets, sapi, tei, (uint8_t)(ctrl_octet & 0x03));
#endif
                md->gsmFlowP->pstat |= GSM_STAT_LAPD_MALFORMED;
                break;
        }
    }

    if (md->gsmFlowP->pstat & GSM_STAT_LAPD_MALFORMED) {
        GSM_DBG_LAPD("%" PRIu64 ": Ignoring malformed LAPD packet", numPackets);
        return false;
    }

    return (has_next_layer && t2buf_left(t2buf) > 0);
}
