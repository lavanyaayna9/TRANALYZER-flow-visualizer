/*
 * clickhouseSink.hpp
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

#ifndef T2_CLICKHOUSESINK_HPP_INCLUDED
#define T2_CLICKHOUSESINK_HPP_INCLUDED

// Local includes
#include "t2Plugin.hpp"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define CLICKHOUSE_OVERWRITE_DB    2   // 0: abort if DB already exists
                                       // 1: overwrite DB if it already exists
                                       // 2: reuse DB if it already exists

#define CLICKHOUSE_OVERWRITE_TABLE 2   // 0: abort if table already exists
                                       // 1: overwrite table if it already exists
                                       // 2: append to table if it already exists

#define CLICKHOUSE_TRANSACTION_NFLOWS 10000 //   0: one transaction
                                            // > 0: one transaction every n flows

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define CLICKHOUSE_HOST       "127.0.0.1"  // Address of the database
#define CLICKHOUSE_DBPORT     9000         // Port the database is listening to
#define CLICKHOUSE_USER       "default"    // Username to connect to DB
#define CLICKHOUSE_PASSWORD   ""           // Password to connect to DB
#define CLICKHOUSE_DBNAME     "tranalyzer" // Name of the database
#define CLICKHOUSE_TABLE_NAME "flow"       // Name of the database flow table

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
enum {
    ENV_CLICKHOUSE_HOST,
    ENV_CLICKHOUSE_DBPORT,
    ENV_CLICKHOUSE_USER,
    ENV_CLICKHOUSE_PASSWORD,
    ENV_CLICKHOUSE_DBNAME,
    ENV_CLICKHOUSE_TABLE_NAME,
    ENV_CLICKHOUSE_N
};

#endif // T2_CLICKHOUSESINK_HPP_INCLUDED
