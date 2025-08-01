/*
 * jsonSink.h
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

#ifndef JSON_SINK_H
#define JSON_SINK_H

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define JSON_SOCKET_ON                    0 // Output to a socket (1) or file (0)
#define JSON_GZ_COMPRESS                  0 // Compress the output (gzip)
#define JSON_SPLIT                        1 // Split output file (-W option)
#define JSON_ROOT_NODE                    0 // Surround the output with a root node (array)
#define JSON_SUPPRESS_EMPTY_ARRAY         1 // Output empty fields
#define JSON_NO_SPACES                    1 // Suppress unnecessary spaces (1)
#define JSON_SELECT                       0 // Use JSON_SELECT_FILE to only output specific fields

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define JSON_BUFFER_SIZE            1048576 // Size of output buffer
#define JSON_SOCKET_ADDR        "127.0.0.1" // Address of the socket (require JSON_SOCKET_ON=1)
#define JSON_SOCKET_PORT               5000 // Port of the socket (require JSON_SOCKET_ON=1)
#define JSON_SUFFIX           "_flows.json" // Suffix for output file (require JSON_SOCKET_ON=0)
#define JSON_SELECT_FILE "json-columns.txt" // Filename of the field selector (require JSON_SELECT=1)
                                            // (one column name per line)

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_JSON_BUFFER_SIZE,
    ENV_JSON_SOCKET_ADDR,
    ENV_JSON_SOCKET_PORT,
    ENV_JSON_SUFFIX,
    ENV_JSON_SELECT_FILE,
    ENV_JSON_N
};

#endif // JSON_SINK_H
