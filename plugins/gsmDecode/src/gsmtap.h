/*
 * gsmtap.h
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

#ifndef T2_GSMTAP_H_INCLUDED
#define T2_GSMTAP_H_INCLUDED

// Global includes

#include <stdbool.h>   // for bool


// Local includes

#include "gsmDecode.h" // for gsm_metadata_t
#include "t2buf.h"     // for t2buf_t
#include "t2log.h"     // for T2_PERR


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define GSM_DEBUG_GSMTAP   0 // Print debug messages for GSMTAP layer
#define GSM_DBG_GSMTAP_UNK 0 // Report unknown values for GSMTAP layer

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


#define GSMTAP_UDP_PORT 4729

#if GSM_DEBUG_GSMTAP == 1
#define GSM_DBG_GSMTAP(format, args...) T2_PERR("GSMTAP", format, ##args)
#else
#define GSM_DBG_GSMTAP(format, args...)
#endif


// Functions prototypes

bool dissect_gsmtap(t2buf_t *t2buf, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,2)));

#endif // T2_GSMTAP_H_INCLUDED
