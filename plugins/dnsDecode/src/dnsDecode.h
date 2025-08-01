/*
 * dnsDecode.h
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

#ifndef __DNSDECODE_H__
#define __DNSDECODE_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define DNS_MODE         4 // 0: Only aggregated header info
                           // 1: +Req Content Info
                           // 2: +Answer Records
                           // 3: +AUX records
                           // 4: +Add records

#define DNS_HEXON        0 // Output hex flags:
                           //   0: no
                           //   1: yes
#define DNS_HDRMD        0 // Header Flags_OpCode_RetCode:
                           //   0: Bitfield
                           //   1: Integer
                           //   2: String
#define DNS_TYPE         0 // Q/A Type:
                           //   0: numeric
                           //   1: string
#define DNS_AGGR         0 // Aggregate records:
                           //   0: no
                           //   1: yes

#define DNS_QRECMAX     15 // Max # of query records / flow
#define DNS_ARECMAX     20 // Max # of answer records / flow

#define DNS_WHO          0 // Report country and organization of DNS reply addresses:
                           //   0: no
                           //   1: yes

#define DNS_MAL_TEST     0 // Test for malware:
                           //   0: no
                           //   1: test @ flow terminated
                           //   2: test @ L4 callback, pcap ops
#define DNS_MAL_TYPE     1 // Malware type format:
                           //   0: code
                           //   1: type string

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*        No env / runtime configuration flags available for dnsDecode        */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Plugin definitions

// DNS record types bit field defs from dnsType.h
#define DNS_BF0 64
#define DNS_BF1 DNS_SPF
#define DNS_BF2 DNS_TKEY
#define DNS_BF3 DNS_TA

// local plugin defines
#define DNS_QRECMXI (DNS_QRECMAX - 1)
#define DNS_ARECMXI (DNS_ARECMAX - 1)

// Local defines
#if SUBNET_INIT == 0 && DNS_WHO == 1
#warning "DNS_WHO reset to 0 as SUBNET_INIT=0 in tranalyzer.h"
#undef DNS_WHO
#define DNS_WHO 0
#endif // SUBNET_INIT != 0

// DNS boundary conditions
#define DNS_MAXUDPLEN 65000 // Max DNS UDP payload length
#define DNS_MAXTCPLEN 65443 // Max DNS TCP payload length
#define DNS_MINDNSLEN    17 // Minimal acceptable DNS record length
#define DNS_RSTART       12 // DNS record start in payload
#define DNS_MXNAME      253 // RFC maximal DNS name length
#define DNS_LEN_REJECT    4 // minimal L7 safety length of a DNS packet

#define DNS_HNLMAX      253 // Max name length in flow structure

// DNS Ports network order
#define DNSPORT    53  // DNS
#define DNSNPORT  137  // DNS NetBios
#define DNSPORTM 5353  // DNS Multicast
#define DNSPORTB 5355  // DNS Broadcast

// DNS types
#define DNS_QR  0x8000
#define DNS_QRN 0x0080
#define DNS_AA  0x0400
#define DNS_TC  0x0200
#define DNS_RD  0x0100
#define DNS_RA  0x0080
#define DNS_BF  0x0780

#define DNS_OPC_MASKn 0x7000
#define DNS_RC_MASKn  0x000F

#define DNS_PTRN  0x00C0
#define DNS_PTRVN ~DNS_PTRN

// Type codes binary mask
#define DNS_HOST_B  0x0000000000000002
#define DNS_CNAME_B 0x0000000000000020
#define DNS_MX_B    0x0000000000008000
#define DNS_AAAA_B  0x0000000010000000

// dnsStat
#define DNS_PRTDT   0x0001 // DNS ports detected
#define DNS_NBIOS   0x0002 // NetBIOS DNS
#define DNS_FRAGA   0x0004 // DNS TCP aggregated fragmented content
#define DNS_FRAGS   0x0008 // DNS TCP fragmented content state

//#define DNS_FTRUNC  0x0010 // Warning: Name truncated
#define DNS_ANY     0x0020 // Warning: ANY: Zone all from a domain or cached server
#define DNS_IZTRANS 0x0040 // Warning: Incremental DNS zone transfer detected
#define DNS_ZTRANS  0x0080 // Warning: DNS zone transfer detected

#define DNS_WRNULN  0x0100 // Warning: DNS UDP length exceeded
#define DNS_WRNIGN  0x0200 // Warning: following records ignored
#define DNS_WRNDEX  0x0400 // Warning: Max DNS query records exceeded... increase DNS_QRECMAX
#define DNS_WRNAEX  0x0800 // Warning: Max DNS answer records exceeded... increase DNS_ARECMAX

#define DNS_ERRLEN  0x1000 // Error: DNS record length error
#define DNS_ERRPTR  0x2000 // Error: Wrong DNS PTR detected
#define DNS_WRNMLN  0x4000 // Warning: DNS length undercut
#define DNS_ERRCRPT 0x8000 // Error: UDP/TCP DNS header corrupt or TCP packets missing


// local plugin structures

typedef struct {
    uint16_t rCode:4;
    uint16_t z:3;
    uint16_t aCode:4;
    uint16_t opCode:4;
    uint16_t qr:1;
} dnsHCode_t;

typedef union {
    dnsHCode_t dnsHCs;
    uint16_t dnsHCu;
} dnsHC_t;

typedef struct {
    //uint16_t len; // only TCP
    uint16_t id;
    dnsHC_t dnsHCode;
    uint16_t qdCount;
    uint16_t anCount;
    uint16_t nsCount;
    uint16_t arCount;
} dnsHeader_t;

typedef struct {
    uint16_t dtype;
    uint16_t dclass;
    uint32_t dttl;
    uint16_t eLen;
    uint8_t data;
} dnsRecHdr_t;

typedef struct {
    uint64_t typeBF0;

    char    *aName[DNS_ARECMAX];
    char    *pName[DNS_ARECMAX];
    char    *qName[DNS_QRECMAX];

#if DNS_AGGR == 1
    ipAddr_t aAddr6[DNS_ARECMAX];
    uint32_t aAddr4[DNS_ARECMAX];
#else // DNS_AGGR == 0
    ipAddr_t aAddr[DNS_ARECMAX];
#endif // DNS_AGGR == 1

    uint32_t aaLen;
    uint32_t qaLen;
    uint32_t seqT;
    uint32_t aTTL[DNS_ARECMAX];
    uint32_t optStat[DNS_ARECMAX];

#if DNS_MAL_TEST > 1
    uint32_t numAF;
    uint32_t malcode[DNS_QRECMAX];
#endif // DNS_MAL_TEST > 1

    uint16_t aClass[DNS_ARECMAX];
    uint16_t aType[DNS_ARECMAX];
    uint16_t qClass[DNS_ARECMAX];
    uint16_t qType[DNS_ARECMAX];
    uint16_t mxPref[DNS_ARECMAX];
    uint16_t srvPrio[DNS_ARECMAX];
    uint16_t srvPort[DNS_ARECMAX];
    uint16_t srvWeight[DNS_ARECMAX];

    uint16_t anaCnt;
    uint16_t araCnt;
    uint16_t arnCnt;
    uint16_t nsaCnt;
    uint16_t qnaCnt;
    uint16_t qrnCnt;

#if DNS_AGGR == 1
    uint16_t arnaCnt;
    uint16_t arnaaCnt;
    uint16_t arnacCnt;
    uint16_t arnatCnt;
    uint16_t aAddr4Cnt;
    uint16_t aAddr6Cnt;
    uint16_t pCnt;
    uint16_t qrnaCnt;
    uint16_t mxpCnt;
    uint16_t optCnt;
    uint16_t pwpCnt;
#endif // DNS_AGGR

    uint16_t anCnt;
    uint16_t arCnt;
    uint16_t nsCnt;
    uint16_t qnCnt;
    uint16_t hdrOPField;
    uint16_t rCodeBF;
    uint16_t opCodeBF;
    uint16_t stat;
    uint16_t tLen;

#if DNS_HDRMD > 0
    uint16_t opCodeCnt;
    uint16_t rCodeCnt;
    uint8_t  opCode[DNS_QRECMAX];
    uint8_t  rCode[DNS_QRECMAX];
#endif // DNS_HDRMD > 0

#if DNS_HEXON == 1
    uint16_t typeBF1;
    uint16_t typeBF2;
    uint8_t  typeBF3;
#endif // DNS_HEXON == 1

    uint8_t  hFlagsBF;
} dnsFlow_t;

extern dnsFlow_t *dnsFlow;

#endif // __DNSDECODE_H__
