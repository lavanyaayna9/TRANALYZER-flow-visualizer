/*
 * t2base64.h
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

#ifndef T2_T2BASE64_H_INCLUDED
#define T2_T2BASE64_H_INCLUDED

#include <stddef.h> // for size_t

#define T2BASE64_LEN(len) ((((len) + 2) / 3) << 2)

// Returned value MUST be free'd with free().
char* t2_base64_encode_alloc(char const *in, size_t len)
    __attribute__((__malloc__))
    __attribute__((__nonnull__(1)))
    __attribute__((__warn_unused_result__));

void t2_base64_encode(char const *in, size_t len, char *out)
    __attribute__((__nonnull__(1, 3)));

#endif // T2_T2BASE64_H_INCLUDED
