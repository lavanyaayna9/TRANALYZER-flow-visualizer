/*
 * gsm_utils.h
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

#ifndef T2_GSM_UTILS_H_INCLUDED
#define T2_GSM_UTILS_H_INCLUDED

// Global includes

#include <stdbool.h>   // for bool
#include <stdint.h>    // for uint8_t
#include <stdlib.h>    // for free


// Local includes

#include "gsmDecode.h" // for gsmChannel_t, gsmChannelDescription_t, ...
#include "t2buf.h"     // for t2buf_t


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

// No configuration flags available

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


typedef struct {
    const unsigned char out[16];
} dgt_set_t;


extern const dgt_set_t Dgt0_9_bcd;
extern const dgt_set_t Dgt_tbcd;
extern const dgt_set_t Dgt_keypad_abc_tbcd;


#define T2BUF_SKIP_LV(t2buf) { \
    uint8_t len; \
    t2buf_read_u8(t2buf, &len); \
    t2buf_skip_n(t2buf, len); \
}

#define T2BUF_SKIP_TLV(t2buf) { \
    t2buf_skip_u8(t2buf); /* IEI */ \
    T2BUF_SKIP_LV(t2buf); \
}

#define GSM_FREE_AND_NULL(f) { \
    free(f); \
    f = NULL; \
}


// Returned value MUST be free'd with gsm_mobile_number_free()
gsmMobileNumber_t t2buf_read_bcd_number(t2buf_t *t2buf)
    __attribute__((__nonnull__(1)))
    __attribute__((__warn_unused_result__));

// Returned value MUST be free'd with gsm_mobile_number_free()
gsmMobileNumber_t t2buf_read_bcd_number_with_len(t2buf_t *t2buf, uint8_t len)
    __attribute__((__nonnull__(1)))
    __attribute__((__warn_unused_result__));

void t2_normalize_e164(gsmMobileNumber_t *a, const gsmMobileNumber_t * const b)
    __attribute__((__nonnull__(1)));

// Returned value MUST be free'd with gsm_channel_free()
char *channel_to_str(const gsmChannel_t * const channel)
    __attribute__((__nonnull__(1)))
    __attribute__((__warn_unused_result__));

// Returned value MUST be free'd with free()
char *t2buf_read_ucs2_as_utf8(t2buf_t *t2buf, uint8_t len)
    __attribute__((__nonnull__(1)))
    __attribute__((__warn_unused_result__));

// Returned value MUST be free'd with gsm_channel_description_free()
gsmChannelDescription_t t2buf_read_channel_description(t2buf_t *t2buf, gsm_metadata_t *md)
    __attribute__((__nonnull__(1, 2)))
    __attribute__((__warn_unused_result__));

gsmMobileIdentity_t t2buf_read_mobile_identity(t2buf_t *t2buf, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,2)))
    __attribute__((__warn_unused_result__));

// Returned value MUST be free'd with free()
char *t2buf_read_multirate_configuration(t2buf_t *t2buf, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,2)))
    __attribute__((__warn_unused_result__));

bool t2buf_read_request_reference(t2buf_t *t2buf, gsm_request_reference_t *ref)
    __attribute__((__nonnull__(1,2)));

bool t2buf_read_timing_advance(t2buf_t *t2buf, uint8_t *ta, uint16_t *bts_dist)
    __attribute__((__nonnull__(1,2,3)));

void mcc_mnc_aux(uint8_t *octs, char *mcc, char *mnc)
    __attribute__((__nonnull__(1,2,3)));

// Cleanup functions
void gsm_channel_description_free(gsmChannelDescription_t *ch_desc) __attribute__((__nonnull__(1)));
void gsm_channel_free            (gsmChannel_t            *channel) __attribute__((__nonnull__(1)));
void gsm_metadata_free           (gsm_metadata_t          *md     ) __attribute__((__nonnull__(1)));
void gsm_mobile_identity_free    (gsmMobileIdentity_t     *id     ) __attribute__((__nonnull__(1)));
void gsm_mobile_number_free      (gsmMobileNumber_t       *number ) __attribute__((__nonnull__(1)));

#endif // T2_GSM_UTILS_H_INCLUDED
