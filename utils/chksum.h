/*
 * chksum.h
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

#ifndef T2_CHKSUM_H_INCLUDED
#define T2_CHKSUM_H_INCLUDED

#include <inttypes.h>  // for uint8_t, uint16_t, uint32_t

uint16_t Checksum(const uint16_t *data, uint32_t chkSum, uint16_t byteLen, uint16_t chkSumWrdPos) __attribute__((__nonnull__(1)));
uint32_t Checksum32(const uint32_t *data, uint32_t byteLen) __attribute__((__nonnull__(1)));
uint32_t sctp_adler32(const uint8_t *data, uint32_t len) __attribute__((__nonnull__(1)));
uint32_t sctp_crc32c(const uint8_t *data, uint32_t len) __attribute__((__nonnull__(1)));

#endif // T2_CHKSUM_H_INCLUDED
