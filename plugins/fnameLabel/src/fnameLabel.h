/*
 * fnameLabel.h
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

#ifndef __FNAME_LABEL_H__
#define __FNAME_LABEL_H__

#include <stdint.h>


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define FNL_LBL        1 // 1: Output label derived from input
                         //    (Use fileNum for Tranalyzer -D option, otherwise refer to FNL_IDX)
#define FNL_IDX        0 // Use the 'FNL_IDX' letter of the filename as label
                         // (t2 -R/-i/-r options) [require FNL_LBL=1]
#define FNL_HASH       0 // 1: Output hash of filename
#define FNL_FLNM       1 // 1: Output filename
#define FNL_FREL       1 // Use absolute (0) or relative (1) filenames for fnLabel, fnHash and fnName

#define FNL_NAMELEN 1024 // Max length for filename

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*        No env / runtime configuration flags available for fnameLabel       */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Plugin defines

// Extract the relative filename from 'name'
#define FN_RELNAME(dest, name) { \
    dest = strrchr(name, '/'); \
    if (dest) dest += 1; /* skip '/' */ \
    else dest = name; \
}


// Structs

typedef struct {
#if FNL_HASH == 1
    uint64_t hash;
#endif
#if FNL_LBL == 1
    uint32_t label;
#endif
    char capname[FNL_NAMELEN];
} fnFlow_t;

// plugin struct pointer for potential dependencies
extern fnFlow_t *fnFlows;

#endif // __FNAME_LABEL_H__
