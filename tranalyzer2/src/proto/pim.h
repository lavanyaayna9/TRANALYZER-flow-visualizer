/*
 * pim.h
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

#ifndef T2_PIM_H_INCLUDED
#define T2_PIM_H_INCLUDED

#include <stdint.h> // for uint8_t, uint16_t


// PIM - Protocol Independent Multicast

#define PIM_REGISTER_LEN 8

// PIM Message Types

#define PIM_TYPE_HELLO     0x00
#define PIM_TYPE_REGISTER  0x01
#define PIM_TYPE_REG_STOP  0x02 // Register-Stop
#define PIM_TYPE_JOIN      0x03 // Join/Prune
#define PIM_TYPE_BOOTSTRAP 0x04
#define PIM_TYPE_ASSERT    0x05
#define PIM_TYPE_GRAFT     0x06 // Graft (used in PIM-DM only)
#define PIM_TYPE_GRAFT_ACK 0x07 // Graft-Ack (used in PIM-DM only)
#define PIM_TYPE_CANDIDATE 0x08 // Candidate-RP-Advertisement


// Structs

typedef struct {
    uint8_t  type:4;
    uint8_t  version:4;
    uint8_t  reserved;
    uint16_t checksum;
} __attribute__((packed)) pimHeader_t;

#endif // T2_PIM_H_INCLUDED
