/*
 * dfft.h
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

#ifndef T2_DFFT_H_INCLUDED
#define T2_DFFT_H_INCLUDED

// Global includes

#include <math.h>


// Local includes

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define DFFT_F    1 // Algorithm: 0: DFT, 1: FFT
#define DFFT_N    8 // Number of Samples

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*           No env / runtime configuration flags available for dfft          */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// plugin defines

#define PI2 (M_PI * 2)
#define NB (log(DFFT_N) / log(2))

#if DFFT_F == 1
#if DFFT_N < 2
#undef DFFT_N
#define DFFT_N 2
#endif // DFFT_N < 1
#define N2 (DFFT_N / 2)
#else // DFFT_F == 0
#if DFFT_N < 1
#undef DFFT_N
#define DFFT_N 1
#endif // DFFT_N < 1
#define N2 DFFT_N
#endif // DFFT_F == 1


// dfftStat status variable
#define DFFT_S_S    0x01
#define DFFT_S_NF   0x10
#define DFFT_S_CLP  0x20


// Plugin structure

typedef struct {
    file_object_t *file;
    uint8_t stat;
} dfftFlow_t;


// plugin struct pointer for potential dependencies
extern dfftFlow_t *dfftFlows;

#endif // T2_DFFT_H_INCLUDED
