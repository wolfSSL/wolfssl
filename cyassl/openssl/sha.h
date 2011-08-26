/* sha.h for openssl */


#ifndef CYASSL_SHA_H_
#define CYASSL_SHA_H_

#ifdef YASSL_PREFIX
#include "prefix_sha.h"
#endif

#ifdef __cplusplus
    extern "C" {
#endif


typedef struct CYASSL_SHA_CTX {
    int holder[24];   /* big enough to hold ctaocrypt sha, but check on init */
} CYASSL_SHA_CTX;

CYASSL_API void CyaSSL_SHA_Init(CYASSL_SHA_CTX*);
CYASSL_API void CyaSSL_SHA_Update(CYASSL_SHA_CTX*, const void*, unsigned long);
CYASSL_API void CyaSSL_SHA_Final(unsigned char*, CYASSL_SHA_CTX*);

/* SHA1 points to above, shouldn't use SHA0 ever */
CYASSL_API void CyaSSL_SHA1_Init(CYASSL_SHA_CTX*);
CYASSL_API void CyaSSL_SHA1_Update(CYASSL_SHA_CTX*, const void*, unsigned long);
CYASSL_API void CyaSSL_SHA1_Final(unsigned char*, CYASSL_SHA_CTX*);

enum {
    SHA_DIGEST_LENGTH = 20
};


typedef CYASSL_SHA_CTX SHA_CTX;

#define SHA_Init CyaSSL_SHA_Init
#define SHA_Update CyaSSL_SHA_Update
#define SHA_Final CyaSSL_SHA_Final

#define SHA1_Init CyaSSL_SHA1_Init
#define SHA1_Update CyaSSL_SHA1_Update
#define SHA1_Final CyaSSL_SHA1_Final


#ifdef __cplusplus
    }  /* extern "C" */ 
#endif


#endif /* CYASSL_SHA_H_ */

