/*
 * regex_re2.h
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

#ifndef __REGEX_RE2_H__
#define __REGEX_RE2_H__

#include <inttypes.h>


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define RE2_DEBUG_MESSAGES   0 // print debug messages

#define RE2_REGEX_FILE  "re2file.txt"
#define RE2_MAX_MEMORY  (1ull << 35) // 32 GB
#define RE2_MERGE       1 // merge all regexes in a single automaton (faster but uses more memory)
#ifndef __APPLE__
#define RE2_RELOADING   1 // dynamically reload regex file when modified
#endif // __APPLE__

#define RE2_MAX_MATCH_PER_PACKET  8 // Max number of regexes which can match on a single packet
#define RE2_MAX_MATCH_PER_FLOW   32 // Max number of regexes which can match on a single flow

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


#ifdef __APPLE__
// macOS does not provide the required notify library
// Force the deactivation of dynamic files reloading
#undef RE2_RELOADING
#define RE2_RELOADING 0
#endif // __APPLE__

// intermediate output buffer which dynamically expends
// necessary because the regex set can change in the middle of a flow
typedef struct {
    char* buffer;
    size_t size;      // position of the next byte to write
    size_t allocated; // allocated bytes in buffer
    uint32_t count;   // number of entires (if repeating values)
} dynamic_buffer;

// re2_regex per flow plugin structure
typedef struct {
    uint16_t match_count; // uint16_t in case RE2_MAX_MATCH_PER_FLOW > 255
    uint32_t matches[RE2_MAX_MATCH_PER_FLOW]; // list of regexes name hashes to speed up comparison
    dynamic_buffer buffer;
} re2_flow_t;

// plugin struct pointer for potential dependencies
extern re2_flow_t *re2_flows;

#endif // __REGEX_RE2_H__
