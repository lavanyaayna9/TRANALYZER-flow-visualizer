/*
 * packetCapture.h
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

#ifndef T2_PACKETCAPTURE_H_INCLUDED
#define T2_PACKETCAPTURE_H_INCLUDED

// includes

#include <sys/types.h>   // for u_char

#include "flow.h"        // for flow_t
#include "packet.h"      // for packet_t
#include "t2utils.h"     // for UNUSED
#include "tranalyzer.h"  // for FDURLIMIT


// Forward declarations

struct pcap_pkthdr;


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

// Interpretation of packet length
// Following plugins are influenced by PACKETLENGTH:
//      nFrstPkts, pktSIATHisto, basicStats, descriptiveStats
#define PACKETLENGTH     3  // 0: including L2, L3 and L4 header,
                            // 1: including L3 and L4 header,
                            // 2: including L4 header,
                            // 3: only higher layer payload (Layer 7)
// If PACKETLENGTH <= 1:
#define FRGIPPKTLENVIEW  1  // 0: IP header stays with 2nd++ fragmented packets,
                            // 1: IP header stripped from 2nd++ fragmented packets

#define NOLAYER2         0  // 0: Automatic L3 header discovery,
                            // 1: Manual L3 header positioning
// If NOLAYER2 == 1:
#define NOL2_L3HDROFFSET 0  // Offset of L3 header

// Special IPv6 user defines
#define MAXHDRCNT        5   // maximal header count IPv6, minimum 3

#define SALRM            0   // 1: enable sending FL_ALARM for pcapd
#define SALRMINV         0   // 1: invert selection; if SALRM == 1

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */

#define MINRAWLEN 64

// Functions prototypes

void dissembleIPv4Packet(packet_t *packet) __attribute__((__nonnull__(1)));

void dissembleIPv6Packet(packet_t *packet) __attribute__((__nonnull__(1)));

void t2_dispatch_lapd_packet(packet_t *packet) __attribute__((__nonnull__(1)));

void perPacketCallback(u_char *inqueue UNUSED, const struct pcap_pkthdr *pcapHeader, const u_char *packet) __attribute__((__nonnull__(2, 3)));

void updateLRUList(flow_t *flowP) __attribute__((__nonnull__(1)));

#endif // T2_PACKETCAPTURE_H_INCLUDED
