/*
 * entropy.h
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

#ifndef ENTROPY_H_
#define ENTROPY_H_

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define ENT_NORM    1      // 1: Normalized entropy, 0: # bits
#define ENT_NBITS   8      // N bit word, vocabulary: 2^N
#define ENT_ALPHAD  0      // 1: print alphabet distribution in flow file

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define ENT_HPKTIG  0      // Ignore first N packets
#define ENT_HEAD    0      // Start word of entropy calc in payload
#define ENT_TAIL    1500   // Position until entropy is calculated
#define ENT_THRESL  8      // Threshold for minimal flow payload length
#define ENT_THRESH  8192   // Threshold for maximal flow payload length

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_ENT_HPKTIG,
    ENV_ENT_HEAD,
    ENV_ENT_TAIL,
    ENV_ENT_THRESL,
    ENV_ENT_THRESH,
    ENV_ENT_N
};


// plugin defines

#if (ENT_NBITS < 1 || ENT_NBITS > 8)
#undef ENT_NBITS
#define ENT_NBITS 8
#endif // (ENT_NBITS < 1 || ENT_NBITS > 8)

#define ENT_MAXPBIN (1 << (ENT_NBITS))
#define ENT_MSK     (0xff >> (8 - (ENT_NBITS)))
#define ENT_NSHFT   (8 / (ENT_NBITS))

#if ENT_NORM == 0
#define ENT_NORMMB 2
#else // ENT_NORM == 1
#define ENT_NORMMB (1 << (ENT_NBITS))
#endif // ENT_NORM

// entStat status variable
#define ENT_NCALC  0x01  // Entropy not calculated
#define ENT_CUTOFF 0x02  // Length cut off


// plugin structures

typedef struct {
    uint64_t numWrds;               // Number of words collected
    int32_t  numPktIgn;             // Number of packets ignored from entropy calc
    uint32_t binCnt[ENT_MAXPBIN];   // Count of each bin value
} entropyFlow_t;


// plugin struct pointer for potential dependencies
extern entropyFlow_t *entropyFlow;

#endif // ENTROPY_H_
