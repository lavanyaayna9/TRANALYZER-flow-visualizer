/*
 * gsm_amr.h
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

#ifndef T2_GSM_AMR_H_INCLUDED
#define T2_GSM_AMR_H_INCLUDED

// Global includes

#include <stdbool.h>   // for bool
#include <stdint.h>    // for uint8_t, uint32_t
#include <stdio.h>     // for FILE


// Local includes
#include "gsmDecode.h" // for gsmFlow_t


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

// No configuration flags available

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


void rtp_amr_convert_and_write(const uint8_t *in, FILE *file, gsmFlow_t *gsmFlowP)
    __attribute__((__nonnull__(1, 2, 3)));
bool is_rtp_amr_speech(uint8_t amr_type);

#endif // T2_GSM_AMR_H_INCLUDED
