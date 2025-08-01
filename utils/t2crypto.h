/*
 * t2crypto.h
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

#ifndef T2_T2CRYPTO_H_INCLUDED
#define T2_T2CRYPTO_H_INCLUDED

#include <openssl/evp.h> // for EVP_md5, EVP_sha1, EVP_sha256
#include <openssl/md5.h> // for MD5_DIGEST_LENGTH
#include <openssl/sha.h> // for SHA1_DIGEST_LENGTH, SHA256_DIGEST_LENGTH
#include <stdbool.h>     // for bool

// Size for message digest buffers (without separators)
#define T2_MD5_STRLEN    (2 * MD5_DIGEST_LENGTH)    // MD5 (32)
#define T2_SHA1_STRLEN   (2 * SHA1_DIGEST_LENGTH)   // SHA1 (40)
#define T2_SHA256_STRLEN (2 * SHA256_DIGEST_LENGTH) // SHA256 (64)

#define t2_md5(buf, buflen, dst, dstlen, sep) t2_hash(buf, buflen, dst, dstlen, sep, EVP_md5())
#define t2_sha1(buf, buflen, dst, dstlen, sep) t2_hash(buf, buflen, dst, dstlen, sep, EVP_sha1())
#define t2_sha256(buf, buflen, dst, dstlen, sep) t2_hash(buf, buflen, dst, dstlen, sep, EVP_sha256())

bool t2_hash(const char * const buf, size_t buflen, char *dst, size_t dstlen, char sep, const EVP_MD *md);

#endif // T2_T2CRYPTO_H_INCLUDED
