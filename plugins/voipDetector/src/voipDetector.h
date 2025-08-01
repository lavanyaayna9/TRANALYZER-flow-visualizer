/*
 * voipDetector.h
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

#ifndef VOIP_DETECTOR_H_
#define VOIP_DETECTOR_H_

#include "t2Plugin.h"   // for file_object_t


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define VOIP_SIP     2 // > 0 Enable SIP decoder, 2: add RTP / SIP findex/ssrc flow correlation
#define VOIP_SIP_PRV 0 // 1: add srcIP for flow correlation, 2: add srcIP of SIP flow (VOIP_SIP=2)
#define VOIP_RTP     1 // Enable RTP/RTCP decoder
#define VOIP_RTCP    1 // Enable RTCP decoder
#define VOIP_ANALEN  0 // Check reported len against snap payload len

#define VOIP_SAVE    0 // Save RTP content
#define VOIP_BUFMODE 1 // Enable buffering of saved RTP content
#define VOIP_SILREST 1 // Restore back G.711 suppressed silences (require VOIP_SAVE=1)
#define VOIP_PLDOFF  0 // Offset for payload to save (require VOIP_SAVE=1)
#define VOIP_SVFDX   1 // Merge ops: 0: SSRC, 1: findex

#define VOIP_MINPKT  1 // Minimum packet length of a flow (require VOIP_SAVE=1)

#define RTPFMAX     20 // Maximal SSRC files (VOIP_SVFDX == 0)
#define SIPNMMAX    35 // Maximal SIP caller name length
#define SIPSTATMAX   8 // Maximal SIP state requests
#define SIPCLMAX     3 // Maximal SIP state requests name length
#define SIPRFXMAX  100 // Maximal SIP IP addr, m=audio / video ports
//#define SIPADDMAX  100 // Maximal SIP addr
#define NUMCSRCMX   30

#define RTPBUFSIZE 4096 // Size of buffer for RTP content

#define VOIP_PERM S_IRWXU // File permissions

#define RTPMAXVERS  1 // Maximal # version violations

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define VOIP_RMDIR   1                // Empty VOIP_V_PATH before starting (require VOIP_SAVE=1)
#define VOIP_V_PATH  "/tmp/TranVoIP"  // Path for raw VoIP
#define VOIP_FNAME   "nudel"          // Default content file name prefix

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_VOIP_RMDIR,
    ENV_VOIP_V_PATH,
    ENV_VOIP_FNAME,
    ENV_VOIP_N
};


// Fix config
#if VOIP_RTP == 0 && VOIP_SAVE == 1
#undef VOIP_SAVE
#define VOIP_SAVE 0
#endif // VOIP_RTP == 0 && VOIP_SAVE == 1

#if VOIP_SVFDX == 0
#undef VOIP_BUFMODE
#define VOIP_BUFMODE 0
#endif // VOIP_SVFDX == 0

// iptypes
#if IPV6_ACTIVATE == 2
#define VOIP_IP_TYPE bt_ipx_addr
#elif IPV6_ACTIVATE == 1
#define VOIP_IP_TYPE bt_ip6_addr
#else // IPV6_ACTIVATE == 0
#define VOIP_IP_TYPE bt_ip4_addr
#endif // IPV6_ACTIVATE == 0

// plugin constants
#define VOIP_FNLNMX (sizeof(VOIP_V_PATH) + sizeof(VOIP_FNAME) + 128)

#define VSIP       "SIP/"
#define SDP        "Content-Type: application/sdp"
#define RTPMAP     "a=rtpmap:"

#define RTPVER     0x80 // RTP version 2
#define RTPVERMASK 0xc0 // 2 upper bits for the version
#define RTPCSICNT  0x0f // Contributing sources

#define RTPDOFF    sizeof(voipRtpH_t)
#define BEDE 0xbede
#define RTCPSSRCNT  0x1f //

#define VOIPMINRPKTD 3 // min number of RTP/RTCP packets for decision

#define SCMASK (          \
    (uint64_t)1 << '>'  | \
    (uint64_t)1 << ' '  | \
    (uint64_t)1 << '\r' | \
    (uint64_t)1 << ';'  | \
    (uint64_t)1 << ':'    \
)


// voipStat
#define RTP           0x0001 // RTP detected
#define RTCP          0x0002 // RTCP detected
#define SIP           0x0004 // SIP detected
#define STUN          0x0008 // STUN detected

#define RTP_X         0x0010 // RTP extension header
#define RTP_P         0x0020 // RT(C)P padding bytes
#define VOIP_STAT_SDP 0x0040 // SDP detected
#define RTP_M         0x0080 // RTP marker

#define RTP_WROP      0x0100 // RTP content write operation
#define SIP_AUDFP     0x0200 // SIP audio RTP flow announced
#define SIP_VIDFP     0x0400 // SIP video RTP flow announced
#define SIP_OVRN      0x0800 // voipSIPRFAdd field truncated... increase SIPRFXMAX
//#define SIP_PHN       0x0800 // 1: SIP; 0: Phone

#define RTP_PKTLSS    0x1000 // RTP packet loss detected
#define RTP_SEQPJ     0x2000 // RTP sequence number jump to past
#define RTP_NFRM      0x4000 // RTP new frame header flag
#define RTP_ERRMD     0x8000 // RTP error in detection


#define RTPTCP (RTP | RTCP)

#define RTP_CC 0x000f
#define RTP_CP 0x000c


// protocol defs

#define VOIP_METH_N 15 // Number of SIP methods

struct {
    const char * const s_name;  // short name
    const char * const m_name;  // monitoring name
    const char * const l_name;  // long name
} sip_methods[] = {
    { "UNK", "sipUnkPkts", "UNKNOWN"   },  //  0
    { "INV", "sipInvPkts", "INVITE"    },  //  1
    { "ACK", "sipAckPkts", "ACK"       },  //  2
    { "BYE", "sipByePkts", "BYE"       },  //  3
    { "CAN", "sipCanPkts", "CANCEL"    },  //  4
    { "REG", "sipRegPkts", "REGISTER"  },  //  5
    { "OPT", "sipOptPkts", "OPTIONS"   },  //  6
    { "PRA", "sipPraPkts", "PRACK"     },  //  7
    { "SUB", "sipSubPkts", "SUBSCRIBE" },  //  8
    { "NOT", "sipNotPkts", "NOTIFY"    },  //  9
    { "PUB", "sipPubPkts", "PUBLISH"   },  // 10
    { "INF", "sipInfPkts", "INFO"      },  // 11
    { "REF", "sipRefPkts", "REFER"     },  // 12
    { "MSG", "sipMsgPkts", "MESSAGE"   },  // 13
    { "UPD", "sipUpdPkts", "UPDATE"    },  // 14
    { NULL , NULL        , NULL        }   // 15
};

// Unused...
const char * const voip_ioi[] = {
    "User-Agent: ",
    "Server: ",
    "username=",
    "Call-ID",
    "Contact:",
    "Register",
    "Via: ",
    "codec",
    "Authorization: ",
    "INVITE",
    "BYE",
    "ACK",
    "CANCEL",
    "OPTIONS",
    "REFER",
    "NOTIFY",
    "MESSAGE",
    "INFO",
    "PRACK",
    "UPDATE",
    "=audio",
    "=rtpmap"
};

// this is embedded into SIP so if SIP found -> check for SDP
// see RFC 4317, RFC 4566
const char * const voip_sdp[] = {
    "v=", // Proto-Version
    "o=", // Session ID
    "s=", // Session name
    "i=", // Session Info
    "u=", // URI
    "e=", // email-address
    "p=", // phone no
    "c=", // connection info
    "b=", // bandwidth info
    "z=", // Timezone info
    "k=", // encryption key
    "a=", // session attribute
    "t=", // time
    "r=", // call repetition
    "m=", // media type and formats
    "i="  // title
};

struct {
    uint16_t status;
    char interpretation[40];
} sip_status_codes[] = {
    { 100, "Trying" },
    { 180, "Ringing" },
    { 181, "Call Is Being Forwarded" },
    { 182, "Queued" },
    { 183, "Session Progress" },
    { 200, "OK" },
    { 202, "Accepted" },
    { 204, "No Notification" },
    { 300, "Multiple Choices" },
    { 301, "Moved Permanently" },
    { 302, "Moved Temporarily" },
    { 305, "Use Proxy" },
    { 380, "Alternative Service" },
    { 400, "Bad Request" },
    { 401, "Unauthorized" },
    { 402, "Payment Required" },
    { 403, "Forbidden" },
    { 404, "Not Found" },
    { 405, "Method Not Allowed" },
    { 406, "Not Acceptable" },
    { 407, "Proxy Authentication Required" },
    { 408, "Request Timeout" },
    { 410, "Gone" },
    { 412, "Conditional Request Failed" },
    { 413, "Request Entity Too Large" },
    { 414, "Request URI Too Long" },
    { 415, "Unsupported Media Type" },
    { 416, "Unsupported URI Scheme" },
    { 417, "Unknown Resource-Priority" },
    { 420, "Bad Extension" },
    { 421, "Extension Required" },
    { 422, "Session Interval Too Small" },
    { 423, "Interval Too Brief" },
    { 428, "Use Identity Header" },
    { 429, "Provide Referrer Identity" },
    { 430, "Flow Failed" },
    { 433, "Anonymity Disallowed" },
    { 436, "Bad Identity-Info" },
    { 437, "Unsupported Certificate" },
    { 438, "Invalid Identity Header" },
    { 439, "First Hop Lacks Outbound Support" },
    { 440, "Max-Breadth Exceeded" },
    { 469, "Bad Info Package" },
    { 470, "Consent Needed" },
    { 480, "Temporarily Unavailable" },
    { 481, "Call/Transaction Does Not Exist" },
    { 482, "Loop Detected" },
    { 483, "Too Many Hops" },
    { 484, "Address Incomplete" },
    { 485, "Ambiguous" },
    { 486, "Busy Here" },
    { 487, "Request Terminated" },
    { 488, "Not Acceptable Here" },
    { 489, "Bad Event" },
    { 491, "Request Pending" },
    { 493, "Undecipherable" },
    { 494, "Security Agreement Required" },
    { 500, "Server Internal Error" },
    { 501, "Not Implemented" },
    { 502, "Bad Gateway" },
    { 503, "Service Unavailable" },
    { 504, "Server Time-out" },
    { 505, "Version Not Supported" },
    { 513, "Message Too Large" },
    { 580, "Precondition Failure" },
    { 600, "Busy Everywhere" },
    { 603, "Declined" },
    { 604, "Does Not Exist Anywhere" },
    { 606, "Not Acceptable" }
};

#define PT_PCMU  0  // G711u
#define PT_PCMA  8  // G711a

const char * const voipRTPFEL[] = {
    "G711u", // 0
    "1016",  // 1
    "G721",  // 2
    "GSM",   // 3
    "G723",  // 4
    "DVI4",  // 5
    "DVI4",  // 6
    "LPC",   // 7
    "G711a", // 8
    "G722",  // 9
    "L16",   // 10
    "L16",   // 11
    "QCELP", // 12
    "CN",    // 13
    "MPA",   // 14
    "G728",  // 15
    "DVI4",  // 16
    "DVI4",  // 17
    "G729",  // 18
    "CelB",  // 19
    "JPEG",  // 20
    "nv",    // 21
    "H261",  // 22
    "MPV",   // 23
    "MP2T",  // 24
    "H263",  // 25
    "JPEG",  // 26
    "una",   // 27
    "nv",    // 28
    "una",   // 29
    "una",   // 30
    "H261",  // 31
    "MPV",   // 32
    "MP2T",  // 33
    "H263",  // 34
    "nil"    // 35
};

const char * const voipRTPFEH[] = {
    "PCM16M8",    // 96
    "uLaw8m24",   // 97
    "aLaw8m24",   // 98
    "PCM16mMs24", // 99
    "uLaw8m32",   // 100
    "aLaw8m32",   // 101
    "PM16mMs32",  // 102
    "PM16sMs48",  // 103
    "PM16mLs8",   // 104
    "PM16mLs24",  // 105
    "PM16mLs32",  // 106
    "PM16mLs44.1",// 107
    "PM16sLs48",  // 108
    "uLaw8m12",   // 109
    "aLaw8m12",   // 110
    "P16mMs12",   // 111
    "G722.1",     // 112
    "WBAMR16",    // 113
    "RTAud",      // 114
    "RTAud" ,     // 115
    "G726",       // 116
    "G722",       // 117
    "CN",         // 118
    "PCMA",       // 119
    "CSDATA",     // 120
    "RTVid",      // 121
    "H264",       // 122
    "H264",       // 123
    "una",        // 124
    "una",        // 125
    "una",        // 126
    "xdata"       // 127
};

const char * const voipRTCP[] = {
    "SR",     // Sender Report
    "RR",     // Receive Report
    "SDES",   // Source Description
    "BYE",    // Goodbye
    "APP"     // Application defined
};


// plugin structs

typedef struct {
#if IPV6_ACTIVATE > 0
    ipAddr_t addr;
#else // IPV6_ACTIVATE == 0
    ip4Addr_t addr;
#endif // IPV6_ACTIVATE == 0
    uint16_t port;
#if IPV6_ACTIVATE == 2
    //uint8_t ver;
#endif // IPV6_ACTIVATE == 2
} __attribute__((packed)) ipPrt_t;

typedef struct {
    uint8_t  vpec;
    uint8_t  typ;
    uint16_t seq;
    uint32_t tS;
    uint32_t ssi;
} __attribute__((packed)) voipRtpH_t;

typedef struct {
    uint8_t  vpr;
    uint8_t  typ;
    uint16_t len;
    uint32_t ssrc;
    uint32_t id;
} __attribute__((packed)) voipRtcpH_t;

typedef struct {
    uint64_t ntpTime;
    uint32_t rtpTime;
    uint32_t tPktCnt;
    uint32_t tbytCnt;
} __attribute__((packed)) voipRtcpSR_t;

typedef struct {
    uint32_t ssrcnS;
    uint32_t cumNpcktLst;
    uint32_t ESeqNrec;
    uint32_t iatJit;
    uint32_t lsrTime;
    uint32_t dlsrTime;
} __attribute__((packed)) voipRtcpRR_t;

typedef struct {
    uint8_t sdes;
    uint8_t sdesLen;
    char    sdesName;
} __attribute__((packed)) voipRtcpSDES_t;

typedef struct {
    uint32_t ssrc;
    uint8_t  len;
    char     reason;
} __attribute__((packed)) voipRtcpBYE_t;

typedef struct {
    uint32_t n;
    char     data;
} __attribute__((packed)) voipRtcpAPP_t;

typedef struct {
    uint16_t extTLen;
    uint8_t  extHdr;
    uint16_t extLen;
    uint8_t  data;
} __attribute__((packed)) voipRtpExt_t;

typedef struct {
    ipAddr_t ip;
    uint16_t min;
    uint16_t max;
} __attribute__((packed)) voipRTPFAdd_t;


// flow struct

typedef struct {
#if VOIP_SIP > 0
    ipVAddr_t sipRTPFAdd[SIPRFXMAX];
#endif // VOIP_SIP > 0

#if VOIP_SAVE == 1
#if VOIP_SVFDX == 1
    file_object_t *fd;   // file descriptor per flow
#else // VOIP_SVFDX == 0
    file_object_t *fd[RTPFMAX+1];   // file descriptor per flow
#endif // VOIP_SVFDX

#if VOIP_BUFMODE == 1
    size_t  rtpbufpos;
    uint8_t rtpbuf[RTPBUFSIZE];
#endif // VOIP_BUFMODE == 1
#endif // VOIP_SAVE == 1

#if VOIP_SIP > 0
    uint64_t findex[SIPRFXMAX+1];
#endif // VOIP_SIP > 0

    uint32_t csrc[NUMCSRCMX];

#if VOIP_RTP == 1 && VOIP_SILREST == 1
    uint32_t next_timestamp;
#endif // VOIP_RTP == 1 && VOIP_SILREST == 1

    uint32_t tsLst;
    uint32_t pktCnt;
    uint32_t rtpScnt;
    uint32_t rtpSeqN;
    uint32_t ssN[RTPFMAX+1];
    uint32_t actSSRCi;
    uint32_t rtcpSsN;

#if VOIP_RTCP == 1
    uint32_t tPktCnt;
    uint32_t tbytCnt;
    uint32_t cumNpcktLst;
    uint32_t iatJit;
#endif // VOIP_RTCP == 1

    uint16_t pCnt;
    uint16_t stat;
    uint16_t sipSSRCi;

#if VOIP_SIP > 0
    uint16_t sipRAFPrt[SIPRFXMAX];
    uint16_t sipRVFPrt[SIPRFXMAX];
    uint16_t sipStat[SIPSTATMAX];
    uint16_t sipRAPi;
    uint16_t sipFdxi;
    uint16_t sdpRTPMi;
    uint16_t sipMethods;
    uint8_t  sipFrmi;
    uint8_t  sipToi;
    uint8_t  sipCIDi;
    uint8_t  sipContacti;
    uint8_t  sipStatCnt;
    uint8_t  sipRqCnt;
    uint8_t  sdpSessIdi;
    char     sipRq[SIPSTATMAX][SIPCLMAX+1];
    char     sipFrm[SIPSTATMAX][SIPNMMAX+1];
    char     sipTo[SIPSTATMAX][SIPNMMAX+1];
    char     sipCID[SIPSTATMAX][SIPNMMAX+1];
    char     sipContact[SIPSTATMAX][SIPNMMAX+1];
    char     usrAgnt[SIPNMMAX+1];
    char     realIP[SIPNMMAX+1];
    char     sdpSessId[SIPSTATMAX][SIPNMMAX+1];
    char     sdpRTPM[SIPSTATMAX][SIPNMMAX+1];
    char     typS[SIPSTATMAX][SIPNMMAX+1];
#endif // VOIP_SIP > 0

#if VOIP_RTCP == 1
    uint8_t  fracLst;
#endif // VOIP_RTCP == 1

    uint8_t  rCnt;
    uint8_t  csrci;
    uint8_t  sipTypCnt;
    uint8_t  typ[SIPSTATMAX];

#if VOIP_SAVE == 1
    char     vname[VOIP_FNLNMX+1];
#endif // VOIP_SAVE == 1
} voipFlow_t;

extern voipFlow_t *voipFlows;

#endif // VOIP_DETECTOR_H_
