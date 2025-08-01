/*
 * payloadDumper.h
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

#ifndef T2_PAYLOADDUMPER_H_INCLUDED
#define T2_PAYLOADDUMPER_H_INCLUDED

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define PLDUMP_L2          0 // Extract payload for layer 2 flows (require ETH_ACTIVATE > 0)
#define PLDUMP_TCP         1 // Extract payload for TCP flows
#define PLDUMP_UDP         1 // Extract payload for UDP flows
#define PLDUMP_SCTP        0 // Extract payload for SCTP stream flows (require SCTP_ACTIVATE > 0)

#define PLDUMP_ETHERTYPES {} // Only extract L2 payloads for those ethertypes, e.g., {0x2000,0x2003}
#define PLDUMP_TCP_PORTS  {} // Only extract TCP payloads on those ports, e.g., {80,8080}
#define PLDUMP_UDP_PORTS  {} // Only extract UDP payloads on those ports, e.g., {80,8080}
#define PLDUMP_SCTP_PORTS {} // Only extract SCTP payloads on those ports, e.g., {80,8080}

#define PLDUMP_MAX_BYTES   0 // Max number of bytes per flow to dump (use 0 for no limits)
#define PLDUMP_START_OFF   0 // Start dumping bytes at a specific offset (L2 and UDP only)

#define PLDUMP_NAMES       0 // Format for filenames:
                             //    0: flowInd '_' [AB]
                             //    1: srcIP.srcPort-dstIP.dstPort-l4Proto[_sctpStream],
                             //       srcMac-dstMac-etherType
                             //    2: Same as 1, but prefixed with timestampT

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define PLDUMP_RMDIR     1                     // Empty PLDUMP_FOLDER before starting
#define PLDUMP_FOLDER    "/tmp/payloadDumper"  // output folder
#define PLDUMP_PREFIX    ""                    // prefix for output files
#define PLDUMP_SUFFIX    ""                    // suffix for output files

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_PLDUMP_RMDIR,
    ENV_PLDUMP_FOLDER,
    ENV_PLDUMP_PREFIX,
    ENV_PLDUMP_SUFFIX,
    ENV_PLDUMP_N
};


// Plugin constants

#if PLDUMP_SCTP == 1 && SCTP_ACTIVATE == 0
#warning "PLDUMP_SCTP require SCTP_ACTIVATE > 0: SCTP payload will NOT be extracted"
#undef PLDUMP_SCTP
#define PLDUMP_SCTP 0
#endif

#if PLDUMP_L2 == 1 && ETH_ACTIVATE == 0
#warning "PLDUMP_L2 require ETH_ACTIVATE > 0: payload of L2 flows will NOT be extracted"
#undef PLDUMP_L2
#define PLDUMP_L2 0
#endif


// pldStat
#define PLDUMP_MTCH       0x01 // Match for this flow
#define PLDUMP_DUMP       0x02 // Dump payload for this flow
#define PLDUMP_SCTP_FDP   0x04 // SCTP init TSN diff engine
#define PLDUMP_PTRNC      0x08 // SCTP payload truncated
#define PLDUMP_TCP_SQERR  0x10 // TCP sequence numbers out of order or roll-over or TCP keep-alive
#define PLDUMP_SCTP_SQERR 0x20 // SCTP TSN out of order or roll-over
#define PLDUMP_FTRNC      0x40 // Filename truncated
#define PLDUMP_ERR        0x80 // Failed to open file


// Plugin structure

typedef struct {
#if (PLDUMP_L2 | PLDUMP_UDP == 1 || PLDUMP_SCTP == 1)
    uint64_t lastOff;
#endif // (PLDUMP_UDP == 1 || PLDUMP_SCTP == 1)

    file_object_t *fd; // file descriptor per flow

#if PLDUMP_SCTP == 1
    uint32_t tsnInit;
    uint32_t tsnLst;
#endif // PLDUMP_SCTP

#if PLDUMP_TCP == 1
    uint32_t seqInit;
    uint32_t seqNext;
#endif // PLDUMP_TCP

    uint8_t stat;
} plDumpFlow_t;


// plugin struct pointer for potential dependencies
extern plDumpFlow_t *plDumpFlows;

#endif // T2_PAYLOADDUMPER_H_INCLUDED
