/*
 * gz2txt.h
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

#ifndef T2_GZ2TXT_H_INCLUDED
#define T2_GZ2TXT_H_INCLUDED


#ifndef USE_ZLIB

/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define USE_ZLIB 1  // activate code for gzip-(de)compression

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */

#endif // USE_ZLIB

// Local defines

#if USE_ZLIB == 0

// No support for ZLIB requested... use the standard functions => no suffix required
#define GZ_SUFFIX ""

#else // USE_ZLIB != 0

#include <stdbool.h>        // for bool
#include <stdio.h>          // for FILE
#include <zlib.h>           // for gzFile

#include "binaryValue.h"    // for binary_value_t

#define GZ_SUFFIX ".gz"

#define ZLIB_REQUIRED_VERSION 0x1290 // Minimum version of zlib required (1.2.9, for gzfread)


// Function prototypes

bool parse_file_gz2txt(gzFile input, binary_value_t * const bv, FILE *outfile, bool compress) __attribute__((__nonnull__(1, 3)));
bool parse_file_gz2json(gzFile input, binary_value_t * const bv, FILE *outfile, bool compress) __attribute__((__nonnull__(1, 3)));

#endif // USE_ZLIB != 0

#endif // T2_GZ2TXT_H_INCLUDED
