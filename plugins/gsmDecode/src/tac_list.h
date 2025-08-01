/*
 * tac_list.h
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

#ifndef T2_TAC_LIST_H_INCLUDED
#define T2_TAC_LIST_H_INCLUDED

// Global includes

#include <inttypes.h> // for uint32_t


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

// No configuration flags available

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Structs

typedef struct {
    uint32_t tac;
    char manuf[43];
    char model[55];
} gsm_tac_t;

typedef struct {
    uint32_t size;
    gsm_tac_t *item;
} gsm_tac_list_t;


// Functions prototypes

gsm_tac_list_t gsm_tac_list_load(const char *dir, const char *filename)
    __attribute__((__nonnull__(2)));
const gsm_tac_t *gsm_tac_list_lookup(gsm_tac_list_t *list, uint32_t tac)
    __attribute__((__nonnull__(1)));
void gsm_tac_list_free(gsm_tac_list_t *list);

#endif // T2_TAC_LIST_H_INCLUDED
