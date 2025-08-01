/*
 * mongoSink.h
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

#ifndef __MONGO_SINK_H__
#define __MONGO_SINK_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define MONGO_QRY_LEN                    2048 // Max length for query
#define MONGO_NUM_DOCS                      1 // Number of documents (flows) to write in bulk
                                              // (MUST be > 0, i.e., one minimum)
#define MONGO_SELECT                        0 // Use MONGO_SELECT_FILE to only insert specific fields into the DB
#define BSON_SUPPRESS_EMPTY_ARRAY           1 // Whether or not to output empty fields
#define BSON_DEBUG                          0 // Print debug messages

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define MONGO_HOST        "127.0.0.1"         // Address of the database
#define MONGO_PORT        27017               // Port the database is listening to
#define MONGO_DBNAME      "tranalyzer"        // Name of the database
#define MONGO_TABLE_NAME  "flow"              // Name of the database flow table
#define MONGO_SELECT_FILE "mongo-columns.txt" // Filename of the field selector (one column name per line)

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_MONGO_HOST,
    ENV_MONGO_PORT,
    ENV_MONGO_DBNAME,
    ENV_MONGO_TABLE_NAME,
    ENV_MONGO_SELECT_FILE,
    ENV_MONGO_N
};

#endif // __MONGO_SINK_H__
