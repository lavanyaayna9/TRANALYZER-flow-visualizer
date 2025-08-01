/*
 * iputils.c
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

#include "iputils.h"


uint8_t ipv4_to_mask(uint32_t mask) {
    uint32_t temp = mask;
    uint32_t m = 0;
    while (temp) {
        m += (temp & 1);
        temp = temp >> 1;
    }
    return m;
}


uint8_t ipv6_to_mask(ipAddr_t mask) {
    uint8_t m = 0;
    for (uint_fast32_t i = 0; i < 2; i++) {
        uint64_t temp = mask.IPv6L[i];
        while (temp) {
            m += (temp & 1);
            temp = temp >> 1;
        }
    }
    return m;
}


uint32_t mask_to_ipv4(uint8_t mask) {
    return ((1UL << 32) - 1) ^ ((1UL << (32 - mask)) - 1);
}


ipAddr_t mask_to_ipv6(uint8_t mask) {
    ipAddr_t ip = {
        .IPv4x[0] = ntohl(mask_to_ipv4(mask >  32 ? 32 : mask)),
        .IPv4x[1] = ntohl(mask_to_ipv4(mask >  64 ? 32 : (mask > 32 ? (mask - 32) : 0))),
        .IPv4x[2] = ntohl(mask_to_ipv4(mask >  96 ? 32 : (mask > 64 ? (mask - 64) : 0))),
        .IPv4x[3] = ntohl(mask_to_ipv4(mask > 128 ? 32 : (mask > 96 ? (mask - 96) : 0))),
    };
    return ip;
}
