/*
 * macLbl.h
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

#ifndef __MACLBL_H__
#define __MACLBL_H__

#include "macRecorder.h"

/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define MAC_SORGLEN 12 // Maximum length for 'who' information (short version)
#define MAC_ORGLEN  44 // Maximum length for 'who' information (long version)

#define MACLBLFILE "macEthlbl_HLP.bin"  // Name of MAC label file

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*       No env / runtime configuration flags available for macRecorder       */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// boundary check
#if MAC_ORGLEN > 512
#undef MAC_ORGLEN
#define MAC_ORGLEN 512
#endif // MAC_ORGLEN > 512


// Structs

typedef struct {
    uint64_t ouiEt;
    //uint64_t mask;
    uint32_t vec;
    uint32_t beF;
#if MR_MACLBL == 2
    char org[MAC_SORGLEN+1];
#endif // MR_MACLBL == 2
#if MR_MACLBL == 3
    char org[MAC_ORGLEN+1];
#endif // MR_MACLBL == 3
} maclbl_t;
//} __attribute__((packed)) maclbl_t;

typedef struct {
    int32_t count;
    maclbl_t *maclbls;
} maclbltable_t;


// function prototypes

maclbltable_t* maclbl_init(const char *dir, const char *filename);
void maclbltable_destroy(maclbltable_t *table);
extern uint32_t maclbl_test(maclbltable_t *table, uint64_t mac, uint16_t ethType);

#endif // __MACLBL_H__
