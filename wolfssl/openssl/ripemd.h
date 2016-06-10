/* ripemd.h for openssl */


#ifndef WOLFSSL_RIPEMD_H_
#define WOLFSSL_RIPEMD_H_

#include <wolfssl/wolfcrypt/settings.h>

#ifdef __cplusplus
    extern "C" {
#endif

#ifdef WOLFSSL_RIPEMD

typedef WOLFCRYPT_RIPEMD_CTX RIPEMD_CTX;

#define RIPEMD_Init   wc_RIPEMD_Init
#define RIPEMD_Update wc_RIPEMD_Update
#define RIPEMD_Final  wc_RIPEMD_Final
        
#endif /* WOLFSSL_RIPEMD */

#ifdef __cplusplus
    }  /* extern "C" */ 
#endif


#endif /* WOLFSSL_MD5_H_ */

