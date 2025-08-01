/*
 * txtSink.h
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

#ifndef __TXT_SINK_H__
#define __TXT_SINK_H__


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define TFS_SPLIT            1 // Split output file (-W option)
#define TFS_PRI_HDR          1 // Print header row at start of flow file
#define TFS_HDR_FILE         1 // Print header file with detailed column information
#define TFS_PRI_HDR_FW       0 // Print header in every output fragment (-W option)
#define TFS_GZ_COMPRESS      0 // Compress the output (gzip)

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define TFS_FLOWS_TXT_SUFFIX "_flows.txt"   // Suffix for the flow file
#define TFS_HEADER_SUFFIX    "_headers.txt" // Suffix for the header file

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_TFS_FLOWS_TXT_SUFFIX,
    ENV_TFS_HEADER_SUFFIX,
    ENV_TFS_N
};

#endif // __TXT_SINK_H__
