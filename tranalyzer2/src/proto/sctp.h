/*
 * sctp.h
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

#ifndef T2_SCTP_H_INCLUDED
#define T2_SCTP_H_INCLUDED

#include <stdint.h> // for uint8_t, uint16_t, uint32_t

// SCTP - Stream Control Transmission Protocol

#define SCTP_C_TYPE 0x0f // Chunk type mask

// SCTP chunk types
#define SCTP_CT_DATA               0 // Payload data
#define SCTP_CT_INIT               1 // Initiation
#define SCTP_CT_INIT_ACK           2 // Initiation acknowledgement
#define SCTP_CT_SACK               3 // Selective acknowledgement
#define SCTP_CT_HEARTBEAT          4 // Heartbeat request
#define SCTP_CT_HEARTBEAT_ACK      5 // Heartbeat acknowledgement
#define SCTP_CT_ABORT              6 // Abort
#define SCTP_CT_SHUTDOWN           7 // Shutdown
#define SCTP_CT_SHUTDOWN_ACK       8 // Shutdown acknowledgement
#define SCTP_CT_ERROR              9 // Operation error
#define SCTP_CT_COOKIE_ECHO       10 // State cookie
#define SCTP_CT_COOKIE_ACK        11 // Cookie acknowledgement
#define SCTP_CT_ECNE              12 // Explicit congestion notification echo (reserved)
#define SCTP_CT_CWR               13 // Congestion window reduced (reserved)
#define SCTP_CT_SHTDWN_CMPLT      14 // Shutdown complete
#define SCTP_CT_AUTH              15 // Authentication chunk
#define SCTP_CT_IDATA             64 // Payload data supporting packet interleaving
#define SCTP_CT_ASCONF_ACK       128 // Address configuration change acknowledgement
#define SCTP_CT_RECONFIG         130 // Stream reconfiguration
#define SCTP_CT_PAD              132 // Packet padding
#define SCTP_CT_FORWARD_TSN      192 // Increment expected TSN
#define SCTP_CT_ASCONF           193 // Address configuration change
#define SCTP_CT_IFORWARD_TSN     194 // Increment expected TSN, supporting packet interleaving

// PPI types
#define SCTP_PPI_IUA               1
#define SCTP_PPI_M2UA              2
#define SCTP_PPI_M3UA              3
#define SCTP_PPI_SUA               4
#define SCTP_PPI_M2PA              5
#define SCTP_PPI_V5UA              6
#define SCTP_PPI_H248              7
#define SCTP_PPI_BICC_Q21503       8
#define SCTP_PPI_TALI              9
#define SCTP_PPI_DUA              10
#define SCTP_PPI_ASAP             11
#define SCTP_PPI_ENRP             12
#define SCTP_PPI_H323             13
#define SCTP_PPI_QIPC_Q21503      14
#define SCTP_PPI_SIMCO            15
#define SCTP_PPI_DDPSeg           16
#define SCTP_PPI_DDPStrm          17
#define SCTP_PPI_S1AP             18
#define SCTP_PPI_RUA              19
#define SCTP_PPI_HNBAP            20
#define SCTP_PPI_ForCES_HP        21
#define SCTP_PPI_ForCES_MP        22
#define SCTP_PPI_ForCES_LP        23
#define SCTP_PPI_SBc_AP           24
#define SCTP_PPI_NBAP             25
#define SCTP_PPI_X2AP             27
#define SCTP_PPI_IRCP_INTRRTR     28
#define SCTP_PPI_LCS_AP           29
#define SCTP_PPI_MPICH2           30
#define SCTP_PPI_ServiceArea      31
#define SCTP_PPI_FractalGen       32
#define SCTP_PPI_PingPong         33
#define SCTP_PPI_CalcAppProt      34
#define SCTP_PPI_ScriptingServ    35
#define SCTP_PPI_NetPerfMtrP_CTRL 36
#define SCTP_PPI_NetPerfMtrP_DATA 37
#define SCTP_PPI_Echo             38
#define SCTP_PPI_DISCARD          39
#define SCTP_PPI_DAYTIME          40
#define SCTP_PPI_CharGen          41
#define SCTP_PPI_3GPPRNA          42
#define SCTP_PPI_3GPPM2A          43
#define SCTP_PPI_3GPPM3AP         44
#define SCTP_PPI_SSHover          45
#define SCTP_PPI_Diamtr_SCTPD     46
#define SCTP_PPI_Diamtr_DTLSD     47
#define SCTP_PPI_R14P_BER         48
#define SCTP_PPI_GenData          49
#define SCTP_PPI_WebRTCDCEP       50
#define SCTP_PPI_WebRTCStrng      51
#define SCTP_PPI_WebRTCBinP       52
#define SCTP_PPI_WebRTCBin        53
#define SCTP_PPI_WebRTCStrngP     54
#define SCTP_PPI_3GPPPUA          55
#define SCTP_PPI_WebRTCStrngE     56
#define SCTP_PPI_WebRTCBinE       57
#define SCTP_PPI_3GPPXwAP         58
#define SCTP_PPI_3GPPXw_Cntrl     59
#define SCTP_PPI_3GPPNG           60
#define SCTP_PPI_3GPPXn           61
#define SCTP_PPI_3GPPF1           62
#define SCTP_PPI_HTTP             63
#define SCTP_PPI_3GPPE1           64
#define SCTP_PPI_ELE2Lawful       65
#define SCTP_PPI_3GPPNGAP         66

// payload types
#define PT_HRTBEAT    0x0100
#define PT_IPV4       0x0500
#define PT_IPV6       0x0600
#define PT_UNRECPRM   0x0800
#define PT_COOKIPREV  0x0900
#define PT_HSTNMADD   0x0b00
#define PT_SUPADDTYP  0x0c00
#define PT_OSSNRESRQP 0x0d00
#define PT_ISSNRESRQP 0x0e00
#define PT_SSNTSNRRP  0x0f00
#define PT_RECONFRP   0x1000
#define PT_ADDOSRP    0x1100
#define PT_ADDISRP    0x1200
#define PT_ECNCAP     0x0080
#define PT_RAND       0x0280
#define PT_CHNKLST    0x0380
#define PT_RHMACAP    0x0480
#define PT_PAD        0x0580
#define PT_SUPEXT     0x0880
#define PT_FWRDTSNSUP 0x00c0
#define PT_ADDIPADD   0x01c0
#define PT_DELIPADD   0x02c0
#define PT_ERRCSI     0x03c0
#define PT_SETPADD    0x04c0
#define PT_SUCIND     0x05c0
#define PT_ADPTLYRI   0x06c0


// Structs

// SCTP header

typedef struct {
    uint16_t source;    // Source port
    uint16_t dest;      // Destination port
    uint32_t verTag;    // Verification tag
    uint32_t chkSum;    // Checksum
    uint32_t data;
} __attribute__((packed)) sctpHeader_t;

// SCTP chunks

typedef struct {
    uint8_t  type;              // Chunk type
    uint8_t  flags;             // Chunk flags
    uint16_t len;               // Chunk length
    union {
        uint32_t tsn_it_cta;    // Transmission sequence number (TSN)  [DATA]
                                // Initiate tag                        [INIT, INIT_ACK]
                                // Cumulative TSN ACK                  [SACK, SHUTDOWN]
        struct {
            uint16_t cc;        // Cause code                          [ERROR]
            uint16_t cl;        // Cause length                        [ERROR]
        };
    };
    union {
        uint32_t arwc;          // Advertised receiver window credit    [INIT, INIT_ACK, SACK]
        struct {
            uint16_t sis;       // Stream identifier                    [DATA]
            uint16_t ssn;       // Stream sequence number               [DATA]
        };
    };
    union {
        uint32_t ppi;           // Payload protocol identifier          [DATA]
        struct {
            uint16_t nos;       // Number of outbound streams           [INIT, INIT_ACK]
            uint16_t nis;       // Number of inbound streams            [INIT, INIT_ACK]
        };
        struct {
            uint16_t gab;       // Number of gap acknowledgement blocks [SACK]
            uint16_t ndtsn;     // Number of duplicated TSNs            [SACK]
        };
    };
    union {
        uint32_t itsn;          // Initial TSN                          [INIT, INIT_ACK]
        uint8_t a[4];
    };
    uint8_t data;
} __attribute__((packed)) sctpChunk_t;

#endif // T2_SCTP_H_INCLUDED
