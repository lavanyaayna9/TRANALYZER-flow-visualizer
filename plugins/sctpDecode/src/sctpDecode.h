/*
 * sctpDecode.h
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

#ifndef __SCTPDECODE_H__
#define __SCTPDECODE_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define SCTP_CRCADL32CHK  0 // Checksum computation:
                            //   0: none,
                            //   1: CRC32,
                            //   2: ADLER
#define SCTP_CHNKVAL      0 // 0: chunk type bit field,
                            // 1: chunk type value,
                            // 2: chunk type as string
#define SCTP_CHNKAGGR     0 // Aggregate chunk types, if SCTP_CHNKVAL > 0
#define SCTP_TSNREL       0 // 0: Absolute TSN
                            // 1: Relative TSN
#define SCTP_MAXCTYPE    15 // Maximum chunk types to store/flow, if SCTP_CHNKVAL > 0
#define SCTP_ASMX        10 // Maximum ASCONF IP
#define SCTP_MXADDR       5 // Maximum number of addresses to print in packet mode

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*        No env / runtime configuration flags available for sctpDecode       */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// plugin defines

#define SCTP_C_TACT 0xc0 // Chunk type action, if the processing endpoint does not recognize the Chunk Type.
// 0x00: Stop processing this SCTP packet and discard it, do not process any further chunks within it.
// 0x40: Stop processing this SCTP packet and discard it, do not process any further chunks within it, and report the unrecognized chunk in an 'Unrecognized Chunk Type'.
// 0x80: Skip this chunk and continue processing.
// 0xc0: Skip this chunk and continue processing, but report in an ERROR chunk using the 'Unrecognized Chunk Type' cause of error.

// sctpStat
#define SCTP_C_ADLERR 0x01 // adler32 error
#define SCTP_C_CRCERR 0x02 // crc32 error
#define SCTP_C_PAD    0x04 // Chunk padded
#define SCTP_C_TRNC   0x08 // Chunk truncated
#define SCTP_C_3ACK   0x10 // 3 Ack
#define SCTP_C_TPVFL  0x20 // Type Field overflow
#define SCTP_C_NREP   0x40 // Do not report
#define SCTP_C_STOP   0x80 // Stop processing of the packet

//#define SCTP_C_WIN0   0x1000 // Window Size 0


// sctpCFlags: chunk flags
#define SCTP_LST_SEQ    0x01 // Last segment
#define SCTP_FRST_SEQ   0x02 // First segment
#define SCTP_ORD_DEL    0x04 // Ordered delivery
#define SCTP_DEL_SACK   0x08 // Possibly delay SACK
#define SCTP_C_HRTBT    0x10 // Heartbeat, similar to tcp KeepAlive
#define SCTP_C_HRTBTACK 0x20 // Heartbeat, similar to tcp KeepAlive Ack
#define SCTP_TSN_ERR    0x40 // Transmission sequence number Error
#define SCTP_ASN_ERR    0x80 // Association Sequence Number Error


// sctp chunk parameter structs

typedef struct {
    uint16_t aType;
    uint16_t aLen;
    uint32_t aAddr;
} __attribute__((packed)) sctpAddr4_t;

typedef struct {
    uint16_t aType;
    uint16_t aLen;
    ipAddr_t aAddr;
} __attribute__((packed)) sctpAddr6_t;

typedef struct {
    uint16_t aType;
    uint16_t aLen;
    uint32_t corrID;
    union {
       sctpAddr6_t ip4AddrPar;
       sctpAddr4_t ip6AddrPar;
    };
} __attribute__((packed)) sctpAddAP_t;


// plugin struct

typedef struct {
//#if IPV6_ACTIVATE > 0
    ipAddr_t asIP6[SCTP_ASMX];
//#endif // IPV6_ACTIVATE > 0
    float ct1_2_3_arwc;
    uint32_t ct3_arwcMin;
    uint32_t ct3_arwcMax;
    uint32_t verTag;
    uint32_t ct0_ppi;
    uint32_t ct1_2_3_arwcI;
    uint32_t tsnInit;
    uint32_t tsnAckInit;
    uint32_t tsnLst;
    uint32_t tsnAckLst;
//#if IPV6_ACTIVATE == 1
    uint32_t asIP[SCTP_ASMX];
//#endif // IPV6_ACTIVATE == 1
    union {
        uint32_t ct1_2_nos_nis;
        struct {
            uint16_t ct1_2_nos;
            uint16_t ct1_2_nis;
        };
    };
    uint16_t numasIP;
    uint16_t numasIP6;
    uint16_t typeBF;
    uint16_t ct1_initCnt;
    uint16_t ct0_dataCnt;
    uint16_t ct6_abrtCnt;
    uint16_t ct0_sid;
    uint16_t ct9_cc;
#if SCTP_CHNKVAL > 0
    uint16_t numTypeS;
    uint8_t cTypeS[SCTP_MAXCTYPE];
#endif
    uint8_t stat;
    uint8_t cflags;
} sctpFlow_t;

#endif // __SCTPDECODE_H__
