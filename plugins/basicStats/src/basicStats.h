/*
 * basicStats.h
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

#ifndef __BASIC_STATS_H__
#define __BASIC_STATS_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define BS_AGGR_CNT  0  // 1: add A+B counts 0: A+B counts off
#define BS_REV_CNT   1  // 1: add reverse counts from opposite flow, 0: native send counts
#define BS_MOD       0  // > 1: modulo factor of packet length; else: off
#define BS_PAD       1  // 1: aggregated padding bytes

#define BS_STATS     1  // 1: basic statistics, 0: only counts

// The following flags require BS_STATS == 1

#define BS_PL_STATS  1  // 1: basic Packet Length statistics, 0: only counts
#define BS_IAT_STATS 1  // 1: basic IAT statistics, 0: only counts

#define BS_VAR       0  // 0: no var calc, 1: variance
#define BS_STDDEV    1  // 0: no stddev calc, 1: stddev
#define BS_SK        1  // 0: no skew/kurtosis, 1: skew/kurtosis calc, BS_VAR==1

#define BS_XCLD      0  // 0: include all
                        // 1: include (BS_XMIN, UINT16_MAX],
                        // 2: include [0, BS_XMAX),
                        // 3: include [BS_XMIN, BS_XMAX]
                        // 4: exclude (BS_XMIN, BS_XMAX)

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define BS_XMIN      1           // if (BS_XCLD) minimal packet length
#define BS_XMAX      UINT16_MAX  // if (BS_XCLD) maximal packet length

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_BS_XMIN,
    ENV_BS_XMAX,
    ENV_BS_N
};


// Plugin defines

#define BS_VARSTD (BS_VAR > 0 || BS_STDDEV > 0)


// Structs

typedef struct {
    uint64_t numTPkts;  // Number of packets transmitted.
    uint64_t numTBytes; // Number of bytes transmitted (depends on PACKETLENGTH)
    //uint64_t totTBytes; // Number of bytes transmitted (total rawLen)

#if BS_STATS == 1
#if BS_XCLD > 0
    uint64_t numTPkts0; // Number of packets transmitted pktlen > 0
#endif // BS_XCLD > 0

    struct timeval lst;

    float avgIAT;
    float minIAT;
    float maxIAT;

    float avgPktSz;

#if BS_VARSTD > 0
    float varIAT;
    float varPktSz;

#if BS_SK == 1
    float skewIAT;
    float skewPktSz;
    float kurIAT;
    float kurPktSz;
#endif // BS_SK == 1
#endif // BS_VARSTD > 0

    uint16_t minPktSz; // Smallest packet size detected
    uint16_t maxPktSz; // Largest packet size detected
#endif // BS_STATS == 1
} bSFlow_t;

// plugin struct pointer for potential dependencies
extern bSFlow_t *bSFlow;


// global variables for esom dependencies

#if ESOM_DEP == 1

#if (BS_STATS == 1 || BS_REV_CNT == 1 || BS_AGGR_CNT == 1)
int64_t oNumPkts, oNumBytes; // num of packets/bytes of opposite flow
#endif

#if BS_AGGR_CNT == 1
uint64_t aggPkts, aggBytes;
#endif // BS_AGGR_CNT == 1

#if BS_STATS == 1
float packet_sym_ratio, byte_sym_ratio; // packet- and byte asymmetry
float packetsPerSec, bytesPerSec;
float avgPktSize;
#endif // BS_STATS == 1

#endif // ESOM_DEP == 1

#endif // __BASIC_STATS_H__
