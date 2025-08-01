/*
 * nDPI.h
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

#ifndef __NDPI_PLUGIN_H__
#define __NDPI_PLUGIN_H__

// Global includes
#include <stdbool.h>

// Local includes
#include "ndpi_main.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define NDPI_OUTPUT_NUM    0 // Output a numerical classification
#define NDPI_OUTPUT_STR    1 // Output a textual classification
#define NDPI_OUTPUT_STATS  1 // Output nDPI protocol distribution in a separate file
#define NDPI_GUESS_UNKNOWN 1 // Try guessing protocol if not sure on flow terminate

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*          No env / runtime configuration flags available for nDPI           */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// plugin defines
#define NDPI_BUFFER_LEN 256
#define NDPI_STATS_SUFFIX "_nDPI.txt"
#define NDPI_MAX_PKT_LEN 1500


// nDPI plugin structures
typedef struct nDPI_Flow_s {
    struct ndpi_flow_struct *ndpiFlow;
    ndpi_protocol classification;
    uint64_t sent_pkts;
    uint64_t sent_bytes;
    bool done;  // protocol found or gave up
#if NDPI_GUESS_UNKNOWN != 0
    uint8_t ndpi_pkt[NDPI_MAX_PKT_LEN];
#endif // NDPI_GUESS_UNKNOWN != 0
} nDPI_flow_t;

// plugin struct pointer for potential dependencies
extern nDPI_flow_t *nDPI_flow;

#endif // __NDPI_PLUGIN_H__
