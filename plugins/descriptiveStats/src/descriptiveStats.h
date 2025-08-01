/*
 * descriptiveStats.h
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

#ifndef __DESCRIPTIVE_STATS_H__
#define __DESCRIPTIVE_STATS_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define DS_PS_CALC   1 // Compute statistics for packet sizes
#define DS_IAT_CALC  1 // Compute statistics for inter-arrival times
#define DS_QUARTILES 0 // Quartiles calculation:
                       //   0: use linear interpolation
                       //   1: use the mean

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*    No env / runtime configuration flags available for descriptiveStats     */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Structs

typedef struct {
    uint64_t numPackets;    // number of packets used to calculate these statistics
    float min;              // minimum value
    float max;              // maximum value
    float mean;             // mean value
    float lowerQuartile;    // lower quartile
    float median;           // median value
    float upperQuartile;    // upper quartile
    float iqd;              // inter quartile distance = distance between lower and upper quartile
    float mode;             // mode = value with the most occurrence
    float range;            // range = maximum value - minimum value
    float stddev;           // standard deviation of the values
    float stdrob;           // robust standard deviation = minimum of the standard deviation and the 0.7413'th iqd
    float skewness;         // skewness of the values
    float excess;           // excess kurtosis (= kurtosis - 3) of the values
} dStats_t;

#if ESOM_DEP == 1
unsigned long *dStats_numPkts;
dStats_t dStats_PLs, dStats_IATs;
#endif // ESOM_DEP == 1

#endif // __DESCRIPTIVE_STATS_H__
