/* sha.h for openssl */


#ifndef WOLFSSL_SHA_H_
#define WOLFSSL_SHA_H_

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_PREFIX
#include "prefix_sha.h"
#endif

#include <wolfssl/wolfcrypt/compat-wolfcrypt.h>

#ifdef __cplusplus
    extern "C" {
#endif

typedef WOLFCRYPT_SHA_CTX SHA_CTX;

#define SHA_Init    wc_SHA_Init
#define SHA_Update  wc_SHA_Update
#define SHA_Final   wc_SHA_Final

#define SHA1_Init    wc_SHA1_Init
#define SHA1_Update  wc_SHA1_Update
#define SHA1_Final   wc_SHA1_Final

typedef WOLFCRYPT_SHA256_CTX SHA256_CTX;

#define SHA256_Init   wc_SHA256_Init
#define SHA256_Update wc_SHA256_Update
#define SHA256_Final  wc_SHA256_Final


#ifdef WOLFSSL_SHA384
typedef WOLFCRYPT_SHA384_CTX SHA384_CTX;

#define SHA384_Init   wc_SHA384_Init
#define SHA384_Update wc_SHA384_Update
#define SHA384_Final  wc_SHA384_Final
#endif /* WOLFSSL_SHA384 */

#ifdef WOLFSSL_SHA512
typedef WOLFCRYPT_SHA512_CTX SHA512_CTX;

#define SHA512_Init   wc_SHA512_Init
#define SHA512_Update wc_SHA512_Update
#define SHA512_Final  wc_SHA512_Final
#endif /* WOLFSSL_SHA512 */

#ifdef __cplusplus
    }  /* extern "C" */
#endif


#endif /* WOLFSSL_SHA_H_ */
