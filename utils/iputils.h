/*
 * iputils.h
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

#ifndef T2_IPUTILS_H_INCLUDED
#define T2_IPUTILS_H_INCLUDED

#include <stdint.h>         // for uint8_t, uint32_t

#include "networkHeaders.h" // for ipAddr_t


uint8_t ipv4_to_mask(uint32_t mask);
uint8_t ipv6_to_mask(ipAddr_t mask);

uint32_t mask_to_ipv4(uint8_t mask);
ipAddr_t mask_to_ipv6(uint8_t mask);

#endif // T2_IPUTILS_H_INCLUDED
