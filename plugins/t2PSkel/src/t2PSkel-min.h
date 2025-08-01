/*
 * t2PSkel.h
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

#ifndef T2_T2PSKEL_H_INCLUDED
#define T2_T2PSKEL_H_INCLUDED

// Global includes


// Local includes

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

/*                No configuration flags available for t2PSkel                */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// plugin defines

// t2PSkelStat status variable
#define T2PSKEL_STAT_MYPROT 0x01 // use this in t2OnNewFlow() to flag flows of interest


// Plugin structure

typedef struct { // always large variables first to limit memory fragmentation
    uint8_t stat;
} t2PSkelFlow_t;


// plugin struct pointer for potential dependencies
extern t2PSkelFlow_t *t2PSkelFlows;

#endif // T2_T2PSKEL_H_INCLUDED
