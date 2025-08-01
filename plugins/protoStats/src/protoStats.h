/*
 * protoStats.h
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

#ifndef __PROTO_STATS_H__
#define __PROTO_STATS_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define PST_ETH_STAT     1 // output layer 2 statistics
#define PST_UDPLITE_STAT 0 // output UDP-Lite statistics
#define PST_SCTP_STAT    0 // output SCTP statistics

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define PST_SUFFIX       "_protocols.txt" // suffix for output file

#define PST_L2ETHFILE    "ethertypes.txt" // file containing ethertypes description
#define PST_PORTFILE     "portmap.txt"    // file containing ports description
#define PST_PROTOFILE    "proto.txt"      // file containing protocols description

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_PST_SUFFIX,
    ENV_PST_L2ETHFILE,
    ENV_PST_PORTFILE,
    ENV_PST_PROTOFILE,
    ENV_PST_N
};


// Local defines

#define L2ETHTYPEMAX 65535
#define L2ETHMAXLEN     99

#define MAXFILENAMELEN 255
#define IPPROTMAX      255
#define IPPROTMAXLEN    99

#define L4PORTMAX    65535
#define L4PORTMAXLEN    99

#endif // __PROTO_STATS_H__
