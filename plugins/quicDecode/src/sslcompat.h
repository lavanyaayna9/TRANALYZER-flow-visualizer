#ifndef __SSLCOMPAT_H__
#define __SSLCOMPAT_H__

/*
 * https://wiki.openssl.org/index.php/OpenSSL_1.1.0_Changes#Compatibility_Layer
 */

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <openssl/evp.h>
#include <openssl/hmac.h>

EVP_MD_CTX *EVP_MD_CTX_new(void);

void EVP_MD_CTX_free(EVP_MD_CTX *ctx);

HMAC_CTX *HMAC_CTX_new(void);

void HMAC_CTX_free(HMAC_CTX *ctx);

#endif // OPENSSL_VERSION_NUMBER < 0x10100000L

#endif // __SSLCOMPAT_H__
