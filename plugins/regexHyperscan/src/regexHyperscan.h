/*
 * regexHyperscan.h
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

#ifndef __REGEX_HYPERSCAN_H__
#define __REGEX_HYPERSCAN_H__

/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define RHS_STREAMING          1  // 0: apply regexes packet per packet
                                  // 1: apply regexes on the whole flow as a continuous stream
#define RHS_RELOADING          1  // dynamically reload regex file when modified (linux only)
#define RHS_EXTRACT_OPPOSITE   1  // also extract the opposite flow when regex match
#define RHS_MAX_FLOW_MATCH    16  // maximum number of regexes which can match on a single flow.
#define RHS_REGEX_FILE        "hsregexes.txt"

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


#if defined(__APPLE__) && RHS_RELOADING == 1
#undef RHS_RELOADING
#define RHS_RELOADING 0 // inotify is not available on macOS
#endif

#include <inttypes.h>
#include "hs.h"

// opaque declaration of a regex set (defined in .c)
typedef struct regex_set_internal regex_set;

// regexHyperscan per flow plugin structure
typedef struct {
    unsigned int matches[RHS_MAX_FLOW_MATCH]; // list of regexes matching this flow
    unsigned long flow_index;
//#if RHS_RELOADING == 1
    // regex set can change on reloading, each flow keeps track of which one it is using
    regex_set *set;
//#endif // RHS_RELOADING == 1
#if RHS_STREAMING == 1
    hs_stream_t *stream;
    uint32_t last_seq;    // last TCP sequence number
#endif // RHS_STREAMING == 1
    uint16_t count;       // # of matches, uint16_t in case RHS_MAX_FLOW_MATCH > 255
    bool terminated;      // true if the flow should not be scanned anymore
} rhs_flow_t;

// plugin struct pointer for potential dependencies
extern rhs_flow_t *rhs_flows;

#endif // __REGEX_HYPERSCAN_H__
