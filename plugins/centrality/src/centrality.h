/*
 * centrality.h
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

/*
 * Counts every directed connection from srcIP to dstIP,
 * stores them in a Matrix and calculates the eigenvector-Centrality
 * for each IP.
 *
 * Current Version: Write srcIP, dstIP and Number of Connections to
 * "baseFileName_centrality.txt"
 */

#ifndef CENTRALITY_H_
#define CENTRALITY_H_

#include <stdint.h>      // for uint16_t, uint64_t
#include <netinet/in.h>  // for in_addr_t


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define CENTRALITY_MATRIXENTRIES 1 // 0: {0,1} in matrix
                                   // 1: Total number of flows in matrix
                                   // 2: Bytes sent
                                   // 3: Bytes asymmetry
                                   // 4: Packets sent
                                   // 5: Packets asymmetry

#define CENTRALITY_TIME_CALC     1 //   0: Only one calculation at application terminate
                                   // > 0: calculate every (int) seconds (dependent on dump duration)

#define CENTRALITY_IP_FORMAT     1 // Format of IP addresses:
                                   //   0: Unsigned integer
                                   //   1: Hexadecimal
                                   //   2: Human readable, e.g., 1.2.3.4

#define CENTRALITY_MATRIXFILE    0 // 1: Write a file with triplet matrix; 0: do not
#define CENTRALITY_TRAVIZ        0 // Traviz output mode

// Suffix for output files
#define CENTRALITY_SUFFIX        "_centrality.txt"
#define MATRIX_SUFFIX            "_matrix.txt"     // require CENTRALITY_MATRIXFILE == 1

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// centAStat
#define CIPP_HFLL 0x01 // connectionHashMap full
#define CIP_HFLL  0x02 // centralityIpHashMap full

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

// Structs

/* Struct for saving srcIP_ID, dstIP_ID and number of directed connections between them */
typedef struct {
    unsigned long srcIP_ID, dstIP_ID;
    uint16_t numberOfConnections;
    uint16_t subConnections;
#if CENTRALITY_MATRIXENTRIES == 2
    uint64_t sentBytes;
#elif CENTRALITY_MATRIXENTRIES == 3
    float byteAsym;
#elif CENTRALITY_MATRIXENTRIES == 4
    uint64_t sentPkts;
#elif CENTRALITY_MATRIXENTRIES == 5
    float pktAsym;
#endif // CENTRALITY_MATRIXENTRIES
} ipPairsConnections_t;

/* Struct for current flow srcIPs and dstIPs */
typedef struct {
    // TODO add support for IPv6
    in_addr_t srcIP, dstIP;
} ipPairs_t;

#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#endif // CENTRALITY_H_
