/*
 * socketSink.h
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

#ifndef SOCKET_SINK_H_
#define SOCKET_SINK_H_


#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define SKS_SOCKTYPE               1 // 0: UDP; 1: TCP
#define SKS_CONTENT_TYPE           1 // 0: binary; 1: text; 2: JSON
#define SKS_HOST_INFO              0 // 0: no info; 1: all info about host
                                     // (only if SKS_CONTENT_TYPE == 0)

#if SKS_SOCKTYPE == 1
#define SKS_GZ_COMPRESS            0 // compress the output (gzip) [TCP ONLY]
#endif // SKS_SOCKTYPE == 1

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define SKS_SERVADD      "127.0.0.1" // destination address
#define SKS_DPORT               6666 // destination port (host order)

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_SKS_SERVADD,
    ENV_SKS_DPORT,
    ENV_SKS_N
};


// Local plugin defines

#define SOCK_BUFSHFT (BUF_DATA_SHFT * 4)
#define MAXBHBUF     2047

#if SOCK_BUFSHFT >= MAXBHBUF
#error "SOCK_BUFSHFT cannot be >= MAXBHBUF"
#endif

#endif // SOCKET_SINK_H_
