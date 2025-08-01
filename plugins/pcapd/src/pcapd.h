/*
 * pcapd.h
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

#ifndef __PCAPD_H__
#define __PCAPD_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define PD_MODE_PKT  0  // Packets to process:
                        //   0: all packets
                        //   1: packet range selection (see PD_STRPKT and PD_ENDPKT)

// The following two flags only apply if PD_MODE_PKT == 1

#define PD_STRTPKT    1 // Packet at which processing starts
#define PD_ENDPKT    10 // Packet at which processing ends (0: end of flow)

#define PD_MODE_IN    0 // 0: extract flows listed in input file (if -e option was used),
                        //    or extract flows if alarm bit is set (if -e option was not used)
                        // 1: dump all packets

#define PD_LBSRCH     1 // Search algorithm:
                        //   0: linear search
                        //   1: binary search

// The following three flags require PD_MODE_IN == 0

#define PD_EQ        1 // 0: dump non-matching flows
                       // 1: dump matching flows
#define PD_OPP       0 // 0: do not extract the opposite flow
                       // 1: extract also the opposite flow
#define PD_DIRSEL    0 // 0: extract A and B flows
                       // 2: extract A flow
                       // 3: extract B flow

// Output

#define PD_MODE_OUT  0 // 0: one pcap
                       // 1: one pcap per flow

#define PD_SPLIT     0 // Split output file (-W option)

// PCAP generation

#define PD_TSHFT     0 // Timeshift
#define PD_TTSFTS    0 // Add value to secs
#define PD_TTSFTNMS  1 // Add value to usec/nsec (depends on TSTAMP_PREC in tranalyzer.h)

#define PD_MACSHFT   0 // MAC shift last byte
#define PD_MACSSHFT  1 // Add value to src MAC
#define PD_MACDSHFT  1 // Add value to dst MAC

#define PD_VLNSHFT   0 // VLAN ID shift
#define PD_VLNISHFT  1 // Add value to inner VLAN ID

#define PD_IPSHFT    0                  // Add to src/dst IP
#define PD_IP4SHFT   0x00000001         // Add value to IPv4 32 bit
#define PD_IP6SHFT   0x0000000000000001 // Add value to IPv6 shift last 64 bit

#define PD_TTLSHFT   0    // 0: no TTL change,
                          // 1: TTL shift,
                          // 2: random shift
#define PD_TTL       8    // sub value from TTL
#define PD_TTLMOD    128  // TTL modulo

#define PD_CHKSUML3  0    // Correct checksum in IPv4 header

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define PD_MAX_FD 128           // Maximum number of simultaneously open file descriptors
#define PD_SUFFIX "_pcapd.pcap" // extension for generated pcap file

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_PD_MAX_FD,
    ENV_PD_SUFFIX,
    ENV_PD_N
};


#if PD_VLNSHFT == 1
#define PDMXNUMVLN 2
#endif // PD_VLNSHFT == 1


// status
#define PCPD_DMP 0x01


// Plugin structure

typedef struct {
   uint8_t stat;
} pcpdFlow_t;


// plugin struct pointer for potential dependencies
extern pcpdFlow_t *pcpdFlows;

#endif // __PCAPD_H__
