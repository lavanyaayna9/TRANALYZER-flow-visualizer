/*
 * gsm_lapdm.c
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

#include "gsm_lapdm.h"


/* ========================================================================= */
/* Link Access Protocol for Dm Channel (LAPDm)                               */
/* ========================================================================= */
inline bool dissect_lapdm(t2buf_t *t2buf, gsm_metadata_t *md) {

    /* Address field */
    uint8_t address;
    if (!t2buf_read_u8(t2buf, &address)) return false;

    //const uint8_t spare = ((address & 0x80) >> 7);
    const uint8_t lpd  = ((address & 0x60) >> 5); // Link Protocol Discriminator (LPD): 1: SMSCB
    const uint8_t sapi = ((address & 0x1c) >> 2); // Service access point identifier (SAPI): 0: Signalling, 3: SMS
    const uint8_t cr   = ((address & 0x02) >> 1); // Command/response field bit (C/R)
    const uint8_t ea   =  (address & 0x01);       // Address field extension bit (EA)

    /* Control field */
    uint8_t ctrl;
    if (!t2buf_read_u8(t2buf, &ctrl)) return false;

    /* Length Indicator */
    uint8_t len;
    if (!t2buf_peek_u8(t2buf, &len)) return false;

    const uint8_t more = ((len & 0x02) >> 1); // More data bit (M)
    const uint8_t el   =  (len & 0x01);       // Length indicator field extension bit (EL)
    len = ((len & 0xfc) >> 2);

    const uint16_t pktlen =  md->packet->l7Len;
    if (len != pktlen - t2buf_tell(t2buf) - 1) {
        // Padding is NOT included in len...
        if (t2buf_left(t2buf) <= len + 1 && t2buf->buffer[t2buf->pos + len + 1] != 0x2b) {
            GSM_DBG_LAPDM("%" PRIu64 ": Byte %lu (0x%02" B2T_PRIX8 ") is not the PDU length: found %u, expected %lu",
                    numPackets, t2buf_tell(t2buf), len, len, pktlen - t2buf_tell(t2buf) - 1);
            md->gsmFlowP->pstat |= GSM_STAT_LAPDM_MALFORMED;
        }
    }

    t2buf_skip_u8(t2buf); // Length

    GSM_DBG_LAPDM("%" PRIu64 ": LPD: %u, SAPI: %u, C/R: %u, EA: %u, CTRL: 0x%02" B2T_PRIX8 ", Length: %u",
            numPackets, lpd, sapi, cr, ea, ctrl, len);

    if (md->gsmFlowP->pstat & GSM_STAT_LAPDM_MALFORMED) {
        GSM_DBG_LAPDM("%" PRIu64 ": Ignoring malformed LAPDm packet", numPackets);
        return false;
    }

    return (t2buf_left(t2buf) > 0);
}
