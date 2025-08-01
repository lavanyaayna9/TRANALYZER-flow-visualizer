/*
 * t2PSkel.h
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

#ifndef T2_T2PSKEL_H_INCLUDED
#define T2_T2PSKEL_H_INCLUDED

// Global includes

//#include <stdio.h>
//#include <string.h>

// Local includes

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

/*                No configuration flags available for t2PSkel                */

#define T2PSKEL_SAVE   0 // Save content to T2PSKEL_F_PATH
#define T2PSKEL_STATS  0 // Save statistics to baseFileName "" T2PSKEL_SUFFIX
#define T2PSKEL_LOAD   0 // Load T2PSKEL_FNAME
#define T2PSKEL_VAR1   0 // Output t2PSkelVar1 (var1)
#define T2PSKEL_IP     0 // Output t2PSkelIP (var2)
#define T2PSKEL_VEC    0 // Output t2PSkelVar5_Var6 and t2PSkelVector

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*         No env / runtime configuration flags available for t2PSkel         */

#define T2PSKEL_FNAME  "filename.txt" // File to load from the plugin folder (require T2PSKEL_LOAD=1)
#define T2PSKEL_SUFFIX "_suffix.txt"  // Suffix for output file (require T2PSKEL_STATS=1)

#define T2PSKEL_ENV_STR "str" // Those variables can be overwritten with
                              // 'T2PSKEL_ENV_STR="new_value" t2 -r ...'
#define T2PSKEL_ENV_NUM 0     // or 'export T2PSKEL_ENV_NUM=new_value; t2 -r ...'

#define T2PSKEL_RMDIR   1     // Empty T2PSKEL_F_PATH before starting (require T2PSKEL_SAVE=1)
#define T2PSKEL_F_PATH  "/tmp/t2PSkel_files/" // Path for extracted content

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_T2PSKEL_FNAME,
    ENV_T2PSKEL_SUFFIX,
    ENV_T2PSKEL_ENV_STR,
    ENV_T2PSKEL_ENV_NUM,
    ENV_T2PSKEL_RMDIR,
    ENV_T2PSKEL_F_PATH,
    ENV_T2PSKEL_N,
};


// plugin defines

#define T2PSKEL_NUM     5
#define T2PSKEL_WURST  10
#define T2PSKEL_TXTLEN 16

#define T2PSKEL_PORT 1234

// t2PSkelStat status variable
#define T2PSKEL_STAT_MYPROT 0x01 // use this in t2OnNewFlow() to flag flows of interest


// Plugin structure

typedef struct { // always large variables first to limit memory fragmentation
    file_object_t *file;
#if T2PSKEL_VEC == 1
    double var7[T2PSKEL_NUM][T2PSKEL_WURST];
#endif
#if T2PSKEL_VAR1 == 1
    uint64_t var1;
#endif
#if T2PSKEL_IP == 1
    ip4Addr_t var2;
#endif
    uint32_t numAlarms;
    uint32_t var3;
    uint16_t var4;
#if T2PSKEL_VEC == 1
    uint8_t var5[T2PSKEL_NUM];
    uint8_t var6[T2PSKEL_NUM];
#endif
    uint8_t stat;
    char text[T2PSKEL_TXTLEN+1];
} t2PSkelFlow_t;


// plugin struct pointer for potential dependencies
extern t2PSkelFlow_t *t2PSkelFlows;

#endif // T2_T2PSKEL_H_INCLUDED
