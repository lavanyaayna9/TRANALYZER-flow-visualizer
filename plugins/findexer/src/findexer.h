// Copyright (c) 2008-2022 Tranalyzer Development Team
// SPDX-License-Identifier: AGPL-3.0-only

#ifndef __findexer_H__
#define __findexer_H__

#include <stdint.h>
#include <sys/queue.h>


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define FNDXR_SPLIT  1 // Split the output file (-W option)

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define FNDXR_SUFFIX          "_flows.xer"    // Suffix for flows output file
#define FNDXR_PKTSXER_SUFFIX  "_packets.xer"  // Suffix for packets output file

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_FNDXR_SUFFIX,
    ENV_FNDXR_PKTSXER_SUFFIX,
    ENV_FNDXR_N
};


// Plugin definitions

#define FINDEXER_MAGIC  0x32455845444e4946 // FINDEXE2 : findexer v2
#define PKTSXER_MAGIC   0x3252455853544b50 // PKTSXER2 : packet mode (t2 -s)
// initial number of packet offsets allocated in the findexerFlow_t struct
#define FINDEXER_INITIAL_PACKET_ALLOC 8
// number of packet offset to collect before writing them to _packets.xer
#define PKTSXER_BUFFER_SIZE (128 * 1024)

// Minimum file size of a _flows.xer file
//  8 bytes (MAGIC)
//  4 bytes (pcap count)
//  8 bytes (first pcap index)
#define FINDEXER_MIN_HDRLEN 20
// Minimum file size of a _packets.xer file
//  FINDEXER_MIN_HDR_LEN
//  8 bytes (first packet number)
//  8 bytes (last packet number)
#define PKTSXER_MIN_HDRLEN 36

// findexer flow flags
enum FlowFlag {
    REVERSE_FLOW, // flow is a B flow
    FIRST_XER,    // this is the first .xer file in which this flow appears
    LAST_XER,     // this is the last .xer file in which this flow appears
    // reserved for future flags
};

// macro to transform a FlowFlag into its bitmask representation
#define TO_BITMASK(x) (1 << (x))

typedef struct {
    uint64_t *data;       // list of items
    size_t size;          // number of items currently in list
    size_t allocated;     // currently allocated items in data
} list_uint64_t;

// findexer flow structure
typedef struct findexerFlow_s {
    unsigned long flow_index;
    list_uint64_t pkt_pos;                // list of packet positions in PCAP
    TAILQ_ENTRY(findexerFlow_s) entries;  // struct for queue of open flows in current PCAP
    uint8_t flags;
} findexerFlow_t;

#endif // __findexer_H__

// vim: ts=4:sw=4:sts=4:expandtab
