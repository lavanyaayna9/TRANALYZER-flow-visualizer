/*
 * kafkaSink.h
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

#ifndef T2_KAFKASINK_H_INCLUDED
#define T2_KAFKASINK_H_INCLUDED

// Local includes

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define KAFKA_DEBUG     0                  // Print debug messages
#define KAFKA_RETRIES   3                  // Max. number of retries when message production failed [0 - 255]

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define KAFKA_BROKERS   "127.0.0.1:9092"   // Broker address(es)
                                           // (comma separated list of host[:port])
#define KAFKA_TOPIC     "tranalyzer.flows" // Topic to produce to

#define KAFKA_PARTITION -1                 // Target partition:
                                           //    - >= 0: fixed partition
                                           //    -   -1: automatic partitioning (unassigned)

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_KAFKA_BROKERS,
    ENV_KAFKA_TOPIC,
    ENV_KAFKA_PARTITION,
    ENV_KAFKA_N
};

#if KAFKA_DEBUG == 1
#define KAFKA_DBG_ERR(format, args...) T2_PERR(plugin_name, format, ##args)
#define KAFKA_DBG_INF(format, args...) T2_PINF(plugin_name, format, ##args)
#else
#define KAFKA_DBG_ERR(format, args...)
#define KAFKA_DBG_INF(format, args...)
#endif

#endif // T2_KAFKASINK_H_INCLUDED
