/*
 * e164_list.h
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

#ifndef T2_E164_LIST_H_INCLUDED
#define T2_E164_LIST_H_INCLUDED


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define GSM_E164_FORMAT 0 // 0: Country code, 1: Country name

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


#if GSM_E164_FORMAT == 1
#define GSM_E164_FIELD country_name
#else // GSM_E164_FORMAT == 0
#define GSM_E164_FIELD country_code
#endif


const char *e164_country(char num[3], int len);
int e164_country_code(const char * const country);

#endif // T2_E164_LIST_H_INCLUDED
