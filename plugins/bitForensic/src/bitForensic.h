/*
 * bitForensic.h
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

#ifndef T2_BITFORENSIC_H_INCLUDED
#define T2_BITFORENSIC_H_INCLUDED

// Global includes

// Local includes
#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define BF_PLEN            0 // 0: Pattern search
                             // 1: Length

#define BF_TOTLEN          0 // 0: Residual length
                             // 1: Total length

#define BF_EXLEN           2 // Length excluded

#define BF_PAT        0x0915 // Pattern: 1,2,4,8 bytes, defines BF_PWDTH
#define BF_MSK        0xffff // Mask: 1,2,4,8 bytes, defines BF_PWDTH

#define BF_NETODR          1 // Search pattern network order
#define BF_NIBBLESWP       0 // Swap nibbles in search pattern (0-1)

#define BF_DNUM           10 // Max bPDPos flow storage

#define BF_SAVE_BCH        0 // Save B/D info
#define BF_BSHIFT          0 // Extract content: start byte shift (require BF_SAVE_BCH=1)

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define BF_RMDIR           1 // Empty BF_V_PATH before starting (require BF_SAVE_BCH=1)
#define BF_V_PATH "/tmp/BF/" // Path for raw content
#define BF_FNAME  "bfnudel"  // Default content file name prefix

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_BF_RMDIR,
    ENV_BF_V_PATH,
    ENV_BF_FNAME,
    ENV_BF_N
};


// plugin defines

#if BF_SAVE_BCH == 1
#define BF_FNLNMX (sizeof(BF_V_PATH) + sizeof(BF_FNAME) + 8 + 16 + 1)
#endif // BF_SAVE_BCH == 1

#if BF_PAT <= 0xff
#define BF_PWDTH 1
#define PATK BF_PAT
#define MSKK BF_MSK
#define NBSWP(pat) (((pat) >> 4) | ((pat) << 4))

#elif BF_PAT <= 0xffff
#define BF_PWDTH 2
#if BF_NETODR == 1
#define PATK ntohs(BF_PAT)
#define MSKK ntohs(BF_MSK)
#else // BF_NETODR == 0
#define PATK BF_PAT
#define MSKK BF_MSK
#endif // BF_NETODR
#define NBSWP(pat) ((((pat) & 0xf0f0) >> 4) | (((pat) & 0x0f0f) << 4))

#elif BF_PAT <= 0xffffffff
#define BF_PWDTH 3
#if BF_NETODR == 1
#define PATK ntohl(BF_PAT)
#define MSKK ntohl(BF_MSK)
#else // BF_NETODR == 0
#define PATK BF_PAT
#define MSKK BF_MSK
#endif // BF_NETODR
#define NBSWP(pat) ((((pat) & 0xf0f0f0f0) >> 4) | (((pat) & 0x0f0f0f0f) << 4))

#elif BF_PAT <= 0xffffffffffffffff
#define BF_PWDTH 4
#if BF_NETODR == 1
#define PATK htobe64(BF_PAT)
#define MSKK htobe64(BF_MSK)
#else // BF_NETODR == 0
#define PATK BF_PAT
#define MSKK BF_MSK
#endif // BF_NETODR
#define NBSWP(pat) ((((pat) & 0xf0f0f0f0f0f0f0f0) >> 4) | (((pat) & 0x0f0f0f0f0f0f0f0f) << 4))

#endif // BF_PAT

#if BF_NIBBLESWP == 1
#define PAT NBSWP(PATK)
#define MSK NBSWP(MSKK)
#else // BF_NIBBLESWP == 0
#define PAT PATK
#define MSK MSKK
#endif // BF_NIBBLESWP

// bFStat status variable
#define BF_DET   0x01
#define BF_PHLEN 0x02
#define BF_WROP  0x08
// bit 4-6 BF_PWDTH


// Plugin structure

typedef struct {
#if BF_SAVE_BCH == 1
   file_object_t *fd;   // file descriptor per flow
#endif // BF_SAVE_BCH == 1
   uint32_t cnt;
   uint16_t bPDPos[BF_DNUM];
   uint8_t stat;
#if BF_SAVE_BCH == 1
   char bfname[BF_FNLNMX+1];
#endif // BF_SAVE_BCH == 1
} bitForFlow_t;


// plugin struct pointer for potential dependencies
extern bitForFlow_t *bitForFlows;

#endif // T2_BITFORENSIC_H_INCLUDED
