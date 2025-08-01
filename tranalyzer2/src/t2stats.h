/*
 * t2stats.h
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

#ifndef T2_T2STATS_H_INCLUDED
#define T2_T2STATS_H_INCLUDED

#include <stdint.h>     // for uint16_t, uint32_t, uint64_t, uint8_t

#include "main.h"       // for MIN_MAX_ESTIMATE
#include "tranalyzer.h" // for FORCE_MODE,


// Forward declarations

struct timeval;


extern uint64_t totalfIndex;

// counter and monitoring statistics absolute/diff mode

extern uint64_t bytesOnWire, bytesOnWire0;
extern uint64_t bytesProcessed, bytesProcessed0;
extern uint64_t corrReplFlws, corrReplFlws0;
extern uint64_t maxNumFlows; //, maxNumFlows0;
extern uint64_t maxNumFlowsPeak; //, maxNumFlowsPeak0;
extern uint64_t numABytes, numABytes0;
extern uint64_t numAlarmFlows, numAlarmFlows0;
extern uint64_t numAlarms, numAlarms0;
extern uint64_t numAPackets, numAPackets0;
extern uint64_t numAYIYAPackets, numAYIYAPackets0;
extern uint64_t numBBytes, numBBytes0;
extern uint64_t numBPackets, numBPackets0;
#if FORCE_MODE == 1
extern uint64_t numForced, numForced0;
#endif // FORCE_MODE == 1
extern uint64_t numFragV4Packets, numFragV4Packets0;
extern uint64_t numFragV6Packets, numFragV6Packets0;
extern uint64_t numGREPackets, numGREPackets0;
extern uint64_t numLAPDPackets, numLAPDPackets0;
extern uint64_t numLLCPackets, numLLCPackets0;
extern uint64_t numPackets, numPackets0;
extern uint64_t numTeredoPackets, numTeredoPackets0;
extern uint64_t numL2Packets, numL2Packets0;
extern uint64_t numV4Packets, numV4Packets0;
extern uint64_t numV6Packets, numV6Packets0;
extern uint64_t numVxPackets, numVxPackets0;
extern uint64_t padBytesOnWire, padBytesOnWire0;
extern uint64_t rawBytesOnWire, rawBytesOnWire0;
extern uint64_t totalAFlows, totalAFlows0;
extern uint64_t totalBFlows, totalBFlows0;
extern uint64_t totalFlows, totalFlows0;
extern uint64_t totalIPv4Flows, totalIPv4Flows0;
extern uint64_t totalIPv6Flows, totalIPv6Flows0;
extern uint64_t totalL2Flows, totalL2Flows0;
#if DTLS == 1
extern uint64_t numDTLSPackets, numDTLSPackets0;
#endif // DTLS == 1

// global L2 protocols
extern uint64_t numBytesL2[65536], numBytes0L2[65536];
extern uint64_t numPacketsL2[65536], numPackets0L2[65536];

// global L3 protocols
extern uint64_t numBytesL3[256], numBytes0L3[256];
extern uint64_t numPacketsL3[256], numPackets0L3[256];

extern uint16_t maxHdrDesc, minHdrDesc;
extern float avgHdrDesc;

#if PKT_CB_STATS == 1
extern double minCpuTime, maxCpuTime, avgCpuTime, varCpuTime;
#endif // PKT_CB_STATS == 1

// end report max min bandwidth info
#if MIN_MAX_ESTIMATE == 1
extern double lagTm;
#endif // MIN_MAX_ESTIMATE == 1

// VLAN, MPLS cnts
extern uint8_t mplsHdrCntMx;
extern uint8_t vlanHdrCntMx;

extern struct timeval startTStamp, startTStamp0;

#endif // T2_T2STATS_H_INCLUDED
