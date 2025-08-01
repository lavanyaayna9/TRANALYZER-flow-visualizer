/*
 * mpls.h
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

#ifndef T2_MPLS_H_INCLUDED
#define T2_MPLS_H_INCLUDED

#include <stdint.h> // for uint32_t


// MPLS - Multiprotocol Label Switching


#define BTM_MPLS_STKn16 0x0001
#define BTM_MPLS_STKn32 0x00010000

// 'p' MUST be in host order
#define MPLS_LABEL(p)  (uint32_t)(((p) & 0xfffff000) >> 12) // Label
#define MPLS_EXP(p)    (uint8_t) (((p) & 0x00000e00) >>  9) // Experimental bits
#define MPLS_BOTTOM(p) (uint8_t) (((p) & 0x00000100) >>  8) // Bottom of label stack
#define MPLS_TTL(p)    (uint8_t) (((p) & 0x000000ff)      ) // TTL

// 'p' MUST be in network order
#define MPLS_LABEL_N(p)  MPLS_LABEL(ntohl(p))  // Label
#define MPLS_EXP_N(p)    MPLS_EXP(ntohl(p))    // Experimental bits
#define MPLS_BOTTOM_N(p) MPLS_BOTTOM(ntohl(p)) // Bottom of label stack
#define MPLS_TTL_N(p)    MPLS_TTL(ntohl(p))     // TTL


// Structs

typedef struct {
    uint32_t TTL:8;
    uint32_t S:1;
    uint32_t Exp_ToS:3;
    uint32_t label:20;
} mplsHeader_t;

#endif // T2_MPLS_H_INCLUDED
