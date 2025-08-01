/*
 * nFrstPkts.h
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

#ifndef __N_FRST_PKTS_H__
#define __N_FRST_PKTS_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define NFRST_IAT                 1 // 0: Time relative to flow start;
                                    // 1: Inter-arrival time;
                                    // 2: Absolute time
#define NFRST_BCORR               0 // 0: A,B start at 0.0;
                                    // 1: B shift by flow start; if (NFRST_IAT == 0)
#define NFRST_PKTCNT             20 // Define how many first packets are recorded
#define NFRST_HDRINFO             0 // Add L3 and L4 header length
				    //
// Pulse Mode for proper sampling and signal processing
#define NFRST_MINIATS             0 // Minimal IAT sec to define a pulse
#define NFRST_MINIATU             0 // Minimal IAT usec/nsec to define a pulse (depends on TSTAMP_PREC=0/1 in tranalyzer.h)
#define NFRST_MINPLENFRC          2 // Minimal pulse length fraction
#define NFRST_PLAVE               1 // 1: Packet Length Average;
                                    // 0: Sum(PL) (BPP); if (NFRST_MINIATS|NFRST_MINIATU) > 0
#define NFRST_XMIN                0// Min PL boundary; Pulse mode
#define NFRST_XMAX       UINT16_MAX // Max PL boundary; Pulse mode

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*        No env / runtime configuration flags available for nFrstPkts        */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Plugin defines
// NFRST_MINIAT > 0: Switch Pulse mod on
#define NFRST_MINIAT (NFRST_MINIATS || NFRST_MINIATU)

#if NFRST_MINPLENFRC > 0
#define NFRST_NINPLSS (NFRST_MINIATS/NFRST_MINPLENFRC)
#define NFRST_NINPLSU (NFRST_MINIATU/NFRST_MINPLENFRC)
#else // NFRST_MINPLENFRC == 0
#define NFRST_NINPLSS NFRST_MINIATS
#define NFRST_NINPLSU NFRST_MINIATU
#endif // NFRST_MINPLENFRC

#if NFRST_PKTCNT == 0
#error "NFRST_PKTCNT must be > 0"
#endif

#if NFRST_XMIN > NFRST_XMAX
#error "NFRST_XMIN must be smaller than NFRST_XMAX"
#endif


// Structs

// struct to save basic statistic of a single packet
typedef struct {
    struct timeval iat;
#if NFRST_MINIAT > 0
    struct timeval piat;
#endif // NFRST_MINIAT > 0
    uint32_t pktLen;
#if NFRST_HDRINFO == 1
    uint8_t l3HDLen;
    uint8_t l4HDLen;
#endif // NFRST_HDRINFO == 1
} pkt_t;

// struct to collect the stats of the first n packets of a flow
typedef struct {
    struct timeval lstPktTm;
    struct timeval lstPktTm0;
#if NFRST_BCORR > 0
    struct timeval tdiff;
#endif // NFRST_BCORR > 0
#if NFRST_MINIAT > 0
    struct timeval lstPktPTm;
    struct timeval lstPktiat;
    uint32_t puls;
#endif // NFRST_MINIAT > 0
    uint32_t pktCnt;
    pkt_t pkt[NFRST_PKTCNT];
} nFrstPkts_t;

// Pointer for potential dependencies
extern nFrstPkts_t *nFrstPkts;

#endif // __N_FRST_PKTS_H__
