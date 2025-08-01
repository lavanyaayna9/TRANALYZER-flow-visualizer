/*
 * mcc_list.h
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

#ifndef T2_MCC_LIST_H_INCLUDED
#define T2_MCC_LIST_H_INCLUDED


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define GSM_MCC_FORMAT 0 // 0: country code, 1: country name
#define GSM_MNC_FORMAT 0 // 0: operator name, 1: brand name

#define GSM_NOT_FOUND "" // Value to use when no entry was found

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


#if GSM_MCC_FORMAT == 1
#define GSM_MCC_FIELD countryName
#else
#define GSM_MCC_FIELD countryCode
#endif

#if GSM_MNC_FORMAT == 1
#define GSM_MNC_FIELD brand
#else
#define GSM_MNC_FIELD operator
#endif


// Functions prototypes

const char *mcc_to_str(const char * const  mcc_s)
    __attribute__((__nonnull__(1)));
const char *mnc_to_str(const char * const  mcc_s, const char * const  mnc_s)
    __attribute__((__nonnull__(1,2)));

#endif // T2_MCC_LIST_H_INCLUDED
