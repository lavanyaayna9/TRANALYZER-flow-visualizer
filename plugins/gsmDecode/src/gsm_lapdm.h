/*
 * gsm_lapdm.h
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

#ifndef T2_GSM_LAPDM_H_INCLUDED
#define T2_GSM_LAPDM_H_INCLUDED

// Global includes

#include <stdbool.h>   // for bool


// Local includes

#include "gsmDecode.h" // for gsm_metadata_t
#include "t2buf.h"     // for t2buf_t
#include "t2log.h"     // for T2_PERR


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define GSM_DEBUG_LAPDM   0 // Print debug messages for LAPDm layer
#define GSM_DBG_LAPDM_UNK 0 // Report unknown values for LAPDm layer

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


#if GSM_DEBUG_LAPDM == 1
#define GSM_DBG_LAPDM(format, args...) T2_PERR("LAPDm", format, ##args)
#else
#define GSM_DBG_LAPDM(format, args...)
#endif


// Functions prototypes

bool dissect_lapdm(t2buf_t *t2buf, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,2)));

#endif // T2_GSM_LAPDM_H_INCLUDED
