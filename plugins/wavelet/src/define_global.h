/*
 * define_global.h
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

#ifndef DEFINE_GLOBAL_H
#define DEFINE_GLOBAL_H

#include <stdint.h>    // for uint16_t
#include <sys/time.h>  // for struct timeval

/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define WAVELET_IAT       0 // 0: pktLen, 1: IAT calc
#define WAVELET_SIG       0 // 1: print signal
#define WAVELET_PREC      0 // 0: float; 1: double
#define WAVELET_THRES     8 // Min number of packets for analysis
#define WAVELET_MAX_PKT  40 // Max number of selected packets

#define WAVELET_LEVEL     3 // Decomposition level
#define WAVELET_EXTMODE ZPD // Extension Mode: NON, SYM, ZPD
#define WAVELET_TYPE    DB3 // Mother Wavelet: DB1, DB2, DB3, DB4

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*         No env / runtime configuration flags available for wavelet         */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// global defines

#define WAVELET_SIG_MAX    (WAVELET_MAX_PKT + 4 * WAVELET_TYPE)                // Max number of packets considered for the wavelet transform + if extended 2 * waveletlength
#define WAVELET_MAX_WT_LEN (WAVELET_MAX_PKT * (2 - 1 / (2 << WAVELET_LEVEL)))  // Max WT signal length

#if WAVELET_PREC == 1
#define WPREC double
#define BTWPREC bt_double
#else // WAVELET_PREC == 0
#define WPREC float
#define BTWPREC bt_float
#endif // WAVELET_PREC

// data types

enum {
    NON, // no extension
    SYM, // DEFAULT-Symmetric-Padding (Half Point): Boundary value symmetric replication
    ZPD  // Zero padding: X --> [00..00] X [00..00] from 0 to lf-1
};

// The order between the wavelet in the enum and WAVELETS[] in wavelet_types.h *MUST* be the same

enum {
    DB1,
    DB2,
    DB3,
    DB4
};

typedef struct {
    WPREC wtDetail[WAVELET_MAX_WT_LEN];
    WPREC wtApprox[WAVELET_MAX_WT_LEN];
    WPREC sig[WAVELET_SIG_MAX];
#if WAVELET_IAT > 0
    struct timeval lstPktTm;
#endif // WAVELET_IAT
    uint16_t numSig;
    uint16_t waveStat;
    uint16_t wtlvl_len[WAVELET_LEVEL]; // len of wavelet detail/approximation
} wavelet_t;

#endif // DEFINE_GLOBAL_H
