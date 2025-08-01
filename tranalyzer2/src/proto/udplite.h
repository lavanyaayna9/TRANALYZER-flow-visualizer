/*
 * udplite.h
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

#ifndef T2_UDPLITE_H_INCLUDED
#define T2_UDPLITE_H_INCLUDED

#include <stdint.h> // for uint16_t


// UDP-Lite - Lightweight User Datagram Protocol


// Structs

// UDP-Lite header

typedef struct {
    uint16_t source;
    uint16_t dest;
    uint16_t coverage; // checksum coverage
    uint16_t check;
} __attribute__((packed)) udpliteHeader_t;

#endif // T2_UDPLITE_H_INCLUDED
