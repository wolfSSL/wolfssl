/* md5.h for openssl */


#ifndef WOLFSSL_MD5_H_
#define WOLFSSL_MD5_H_

#include <wolfssl/wolfcrypt/settings.h>

#ifndef NO_MD5

#ifdef WOLFSSL_PREFIX
#include "prefix_md5.h"
#endif

#include <wolfssl/wolfcrypt/compat-wolfssl.h>

#ifdef __cplusplus
    extern "C" {
#endif

typedef WOLFCRYPT_MD5_CTX WOLFSSL_MD5_CTX;
typedef WOLFCRYPT_MD5_CTX MD5_CTX;

#define MD5_Init    wc_MD5_Init
#define MD5_Update  wc_MD5_Update
#define MD5_Final   wc_MD5_Final

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* NO_MD5 */

#endif /* WOLFSSL_MD5_H_ */
