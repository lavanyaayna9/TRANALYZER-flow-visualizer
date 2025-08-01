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

#include "t2base64.h"

#include "t2utils.h"  // for t2_malloc_fatal

#include <stdint.h>   // for uint32_t
#include <string.h>   // for strlen


#define BASE64_PAD '='


static const unsigned char base64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


char* t2_base64_encode_alloc(const char *in, size_t len) {
    const size_t olen = (((len + 2) / 3) << 2);
    char * const out = t2_malloc_fatal(olen + 1);
    t2_base64_encode(in, len, out);
    return out;
}


void t2_base64_encode(const char *in, size_t len, char *out) {
    uint32_t opos = 0;
    for (uint32_t pos = 0; len >= 3; len -= 3, pos += 3) {
        const uint32_t b = ((in[pos] & 0xff) << 16) + ((in[pos + 1] & 0xff) << 8) + ((in[pos + 2] & 0xff));
        out[opos++] = base64_alphabet[(b >> 18)];
        out[opos++] = base64_alphabet[(b >> 12) & 0x3f];
        out[opos++] = base64_alphabet[(b >>  6) & 0x3f];
        out[opos++] = base64_alphabet[b & 0x3f];
    }

    if (len == 1) {
        const uint32_t b = (in[pos] & 0xff);
        out[opos++] = base64_alphabet[(b >> 2)];
        out[opos++] = base64_alphabet[(b << 4) & 0x3f];
        out[opos++] = BASE64_PAD;
        out[opos++] = BASE64_PAD;
    } else if (len == 2) {
        const uint32_t b = ((in[pos] & 0xff) << 8) + ((in[pos + 1] & 0xff));
        out[opos++] = base64_alphabet[(b >> 10)];
        out[opos++] = base64_alphabet[(b >> 4) & 0x3f];
        out[opos++] = base64_alphabet[(b << 2) & 0x3f];
        out[opos++] = BASE64_PAD;
    }

    out[opos] = '\0';
}
