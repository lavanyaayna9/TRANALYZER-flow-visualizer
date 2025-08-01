/*
 * t2crypto.c
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

#include "t2crypto.h"

#include "bin2txt.h"     // for B2T_PRIX8
#include "t2log.h"       // for T2_ERR
#include "t2utils.h"     // for UNLIKELY


bool t2_hash(const char * const buf, size_t buflen, char *dst, size_t dstlen, char sep, const EVP_MD *md) {
    dst[0] = '\0';

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    if (UNLIKELY(!mdctx)) {
        T2_ERR("Failed to create digest context");
        return false;
    }

    if (UNLIKELY(!EVP_DigestInit_ex(mdctx, md, NULL))) {
        T2_ERR("Failed to initialize message digest");
        EVP_MD_CTX_destroy(mdctx);
        return false;
    }

    if (UNLIKELY(!EVP_DigestUpdate(mdctx, buf, buflen))) {
        T2_ERR("Failed to update message digest");
        EVP_MD_CTX_destroy(mdctx);
        return false;
    }

    unsigned int dlen;
    unsigned char digest[EVP_MAX_MD_SIZE + 1];
    if (UNLIKELY(!EVP_DigestFinal_ex(mdctx, digest, &dlen))) {
        T2_ERR("Failed to finalize message digest");
        EVP_MD_CTX_destroy(mdctx);
        return false;
    }

    EVP_MD_CTX_destroy(mdctx);

    const size_t seplen = ((sep == 0) ? 0 : 1);
    if (UNLIKELY(dstlen < (2 + seplen) * dlen)) {
        T2_ERR("Destination buffer for message digest too small... increase to %zu", (2 + seplen) * dlen + 1);
        return false;
    }

    for (size_t i = 0, pos = 0; i < dlen; i++, pos += (2 + seplen)) {
        snprintf(&dst[pos], dstlen - pos, "%02" B2T_PRIX8 "%c", digest[i], sep);
    }

    return true;
}
