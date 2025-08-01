/*
 * liveXtr.h
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

#ifndef __LIVE_XTR_H__
#define __LIVE_XTR_H__

/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

// INFO: LIVEXTR (=0x0010000000000000) was reserved in flow->status to indicate which
//       flows must be extracted. Any plugin can set this flag and liveXtr will take
//       care of extracting the flow.

#define LIVEXTR_BUFSIZE  (1ull << 31)  // size of round-robin buffer (default: 2GB)
#define LIVEXTR_MEMORY   1             // store the RR buffer in memory or in a file
                                       //   0: round-robin buffer in a file
                                       //   1: round-robin buffer in memory

#define LIVEXTR_SPLIT    1   // split the output file (-W option)

#if LIVEXTR_MEMORY == 0
#define LIVEXTR_FILE   "/tmp/livextr.data" // path to round-robin buffer file
#endif // LIVEXTR_MEMORY == 0

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


#define LIVEXTR_SUFFIX           "_livextr.pcap" // suffix for output filenames

#if LIVEXTR_SPLIT != 0
#define LIVEXTR_SUFFIX_CNT_LEN 20  // maximum number of digits to append to output filenames
#else
#define LIVEXTR_SUFFIX_CNT_LEN 0
#endif

#define LIVEXTR_INITIAL_PACKETS  8     // initial number of packet offsets allocated per flow
#define LIVEXTR_MAX_PKT_SIZE     65536 // maximum packet size

#include <inttypes.h>
#include <stdbool.h>

// round robin buffer used to store this flow packet offsets in the main round-robin buffer/file
// its internal buffer can be expanded, packets at index already over-written in the main
// buffer/file will be discarded.
struct offset_rrbuffer {
    uint64_t *offsets;
    uint64_t allocated;
    uint64_t first;
    uint64_t last;
};

// liveXtr per flow plugin structure
typedef struct {
    struct offset_rrbuffer offset_buf;
    bool extract;
} liveXtr_flow_t;

// plugin struct pointer for potential dependencies
extern liveXtr_flow_t *liveXtr_flows;

#endif // __LIVE_XTR_H__
