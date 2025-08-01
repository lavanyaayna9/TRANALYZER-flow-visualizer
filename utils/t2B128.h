/*
 * t2B128.h
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

#ifndef T2_T2B128_H_INCLUDED
#define T2_T2B128_H_INCLUDED

// Includes
#include <inttypes.h>

// Constants
#define BUFLEND 51

// Return codes
#define INPOVRFLW  0
#define OK         1
#define CALOVRFLW -1
#define UNKWCHR   -2

// Structs
typedef union {
    __uint128_t a;
    uint64_t b[2];
} uint128_t;

// Functions
int readU128(uint128_t *g);
int readX128(uint128_t *g);
void writeU128(uint128_t g);

#endif // T2_T2B128_H_INCLUDED
