/*
 * subnetHL6.h
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

#ifndef T2_SUBNETHL6_H_INCLUDED
#define T2_SUBNETHL6_H_INCLUDED

// includes

#include <stdint.h>          // for uint32_t, int32_t

#include "networkHeaders.h"  // for ipAddr_t
#include "subnetHL.h"        // for SUB_MAP, subnet6_t


// plugin defines

#define SUBNETFILE6 "subnets6_HLP.bin" // subnet IPv6 file name


// Structs

typedef struct {
    int32_t count;
    uint32_t ver;
    uint32_t rev;
#if SUB_MAP == 1
    int fdmap;
#endif // SUB_MAP == 1
    subnet6_t *subnets;
} subnettable6_t;


// Function prototypes

subnettable6_t* subnet_init6(const char *dir, const char *filename) __attribute__((__nonnull__(2)));
uint32_t subnet_testHL6(subnettable6_t *table, ipAddr_t net6) __attribute__((__nonnull__(1)));
void subnettable6_destroy(subnettable6_t *table);

#endif // T2_SUBNETHL6_H_INCLUDED
