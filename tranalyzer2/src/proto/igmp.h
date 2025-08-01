/*
 * igmp.h
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

#ifndef T2_IGMP_H_INCLUDED
#define T2_IGMP_H_INCLUDED

#include <stdint.h>      // for uint8_t, uint16_t
#include <netinet/in.h>  // for struct in_addr


// IGMP - Internet Group Management Protocol


#define IGMP_TYPE_DVMRP      0x13
#define IGMP_TYPE_PIM        0x14


// RGMP - Router-Port Group Management Protocol


// RGMP uses the destination address 224.0.0.25

#define IGMP_RGMP_DADDRn 0x190000e0 // 224.0.0.25

#define IGMP_TYPE_RGMP_LEAVE 0xfc
#define IGMP_TYPE_RGMP_JOIN  0xfd
#define IGMP_TYPE_RGMP_BYE   0xfe
#define IGMP_TYPE_RGMP_HELLO 0xff


// Structs

// IGMP header

typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    struct in_addr group;  // group address
} __attribute__((packed)) igmpHeader_t;

#endif // T2_IGMP_H_INCLUDED
