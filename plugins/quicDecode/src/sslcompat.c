/*
 * https://wiki.openssl.org/index.php/OpenSSL_1.1.0_Changes#Compatibility_Layer
 */

#include "sslcompat.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000L

#include <openssl/crypto.h>
#include <string.h>

static void *OPENSSL_zalloc(size_t num)
{
   void *ret = OPENSSL_malloc(num);

   if (ret != NULL)
       memset(ret, 0, num);
   return ret;
}

EVP_MD_CTX *EVP_MD_CTX_new(void)
{
   return OPENSSL_zalloc(sizeof(EVP_MD_CTX));
}

void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
{
   if (ctx != NULL) {
       EVP_MD_CTX_cleanup(ctx);
       OPENSSL_free(ctx);
    }
}

HMAC_CTX *HMAC_CTX_new(void)
{
   HMAC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
   return ctx;
}

void HMAC_CTX_free(HMAC_CTX *ctx)
{
   if (ctx != NULL) {
       HMAC_CTX_cleanup(ctx);
       OPENSSL_free(ctx);
   }
}

#endif // OPENSSL_VERSION_NUMBER < 0x10100000L
