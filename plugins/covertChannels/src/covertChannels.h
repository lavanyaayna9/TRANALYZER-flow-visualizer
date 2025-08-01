/*
 * covertChannels.h
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

#ifndef TRANALYZER_COVERT_CHANNELS_H_
#define TRANALYZER_COVERT_CHANNELS_H_

#include <stdint.h>   // for uint16_t, uint32_t, uint64_t, uint8_t
#include <stdbool.h>  // for bool


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define CC_DEBUG_MESSAGES   0 // print debug information about detected CC

#define CC_DETECT_DNS       1
#define CC_DETECT_ICMP_ASYM 1 // ICMP flow asymmetry
#define CC_DETECT_ICMP_WL   0 // ping payload whitelist
#define CC_DETECT_ICMP_NP   0 // ICMP bidirectional non-ping flow
                              // Disabled by default because of high false-positives
#define CC_DETECT_HCOVERT   1 // HTTP url-encoding
#define CC_DETECT_DEVCC     1 // TCP timestamp LSB
#define CC_DETECT_IPID      1 // Detect CCs in IP identification field
#define CC_DETECT_RTP_TS    0
#define CC_DETECT_SKYDE     0

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// ICMP payload whitelist detection
#define CC_PING_WHITELIST_NAME "cc_ping_whitelist.txt"

// DNS covert channels domain whitelist
#define CC_DNS_WHITELIST_NAME  "cc_dns_whitelist.txt"

#define CC_DETECT_ICMP (CC_DETECT_ICMP_ASYM | CC_DETECT_ICMP_WL | CC_DETECT_ICMP_NP)

// DNS covert channels. Values taken from this article:
// http://www.cloudshield.com/blog/dns-security-expert-series/dns-covert-channels-solution-design-and-implementation/
#define CC_DNS_MAX_CONSONANTS  9
#define CC_DNS_MAX_VOWELS      9
#define CC_DNS_MAX_DIGITS      8
#define CC_DNS_MAX_SPECIALS    4
#define CC_DNS_MAX_LABEL_COUNT 5
#define CC_DNS_MAX_LABEL_LEN   25
#define CC_DNS_MAX_QUERY_LEN   90

// how many anomalies in a single domain name before flagging as DNS covert channel
#define CC_DNS_ANOMALY_THRESHOLD 2

// DNS RFC values
#define DNS_TYPE_QUERY     0
#define DNS_TYPE_IQUERY    1
#define DNS_OPCODE_MASK    0x7800
#define DNS_POINTER_MASK   0xC000
#define DNS_MAX_DOMAIN_LEN 253 // 255 - (byte for label length) - (byte for terminating 0)
#define DNS_MAX_LABEL_LEN  63

// buffers length
#define BUFFER_LEN (DNS_MAX_DOMAIN_LEN + 1)

// ICMP asymmetry detection
#define CC_ICMP_ASYM_MIN_BYTES 500
#define CC_ICMP_ASYM_MAX_DEV   0.1f // 10%

// ICMP TFC values
#define ICMP_ECHOREPLY 0  // Echo Reply
#define ICMP_ECHO      8  // Echo Reply

// hcovert (HTTP url-encoding) defines
#define CC_HC_MIN_URL_LEN 20
#define CC_HC_MAX_RATIO   0.4f // 40%

// DEVCC (TCP timestamp) defines
#define CC_DEVCC_MIN_PACKETS 512
#define CC_DEVCC_MAX_DEV     0.1f // 10%

// IPID defines
#define IP_ID_SPACE (1 << 16)
#define IP_ID_BUCKET_SIZE 256 // must be a divisor of IP_ID_SPACE
#define IP_ID_BUCKET_COUNT (IP_ID_SPACE / IP_ID_BUCKET_SIZE)

// SykDe defines
#define CC_SKYDE_W               10
#define CC_SKYDE_DELTA           20
#define CC_SKYDE_MAX_PACKET_RATE 100

// CC output values enum
typedef enum {
    CC_DNS,       // DNS covert channel
    CC_ICMP_ASYM, // ICMP flow asymmetry
    CC_ICMP_WL,   // ICMP payload not in whitelist
    CC_ICMP_NP,   // ICMP bidirectional non-PING flow
    CC_HCOVERT,   // HTTP url-encoding
    CC_DEVCC,     // TCP timestamp
    CC_IPID,      // IP identification field
    CC_RTP_TS,    // RTP timestamp
    CC_SKYDE,     // Skype silent packets
} cc_type;

// macro to transform the cc_type into its bitmask representation
#define CC_BITMASK(x) (1 << (x))

// covertChannels plugin structure
typedef struct {
#if CC_DETECT_ICMP_ASYM == 1
    uint64_t icmp_count;
#endif // CC_DETECT_ICMP_ASYM
#if CC_DETECT_ICMP_NP == 1
    uint64_t non_ping_count;
#endif // CC_DETECT_ICMP_NP
#if CC_DETECT_DEVCC == 1
    uint64_t timestamp0;
    uint64_t timestamp1;
#endif // CC_DETECT_DEVCC
#if CC_DETECT_IPID == 1
    uint16_t ipIds[IP_ID_BUCKET_COUNT];
    uint64_t nullIpIds;
    uint64_t ipIdCount;
    bool ignore_ipid;
#endif // CC_DETECT_IPID
#if CC_DETECT_RTP_TS == 1
    uint64_t rtpCount;
    double xShift;
    uint32_t yShift;
    double sx;
    double sy;
    double sxx;
    double sxy;
    double syy;
#endif // CC_DETECT_RTP_TS
#if CC_DETECT_SKYDE == 1
    double lastPkt;
    double ipdAvg;
    uint64_t skypeCount;
    //double lastUpdate;
    //list2_t* silentPkts;
    //uint16_t sizeThreshold;
    //uint8_t initialized;
#endif // CC_DETECT_SKYDE
    // detected covert channels
    uint16_t detected_cc;
} cc_flow_t;

// plugin struct pointer for potential dependencies
extern cc_flow_t *cc_flows;

#endif // TRANALYZER_COVERT_CHANNELS_H_
