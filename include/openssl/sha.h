/* sha.h for openssl */


#ifndef CYASSL_SHA_H_
#define CYASSL_SHA_H_

#ifdef YASSL_PREFIX
#include "prefix_sha.h"
#endif

#ifdef __cplusplus
    extern "C" {
#endif


typedef struct SHA_CTX {
    int holder[24];   /* big enough to hold ctaocrypt sha, but check on init */
} SHA_CTX;

CYASSL_API void SHA_Init(SHA_CTX*);
CYASSL_API void SHA_Update(SHA_CTX*, const void*, unsigned long);
CYASSL_API void SHA_Final(unsigned char*, SHA_CTX*);

/* SHA1 points to above, shouldn't use SHA0 ever */
CYASSL_API void SHA1_Init(SHA_CTX*);
CYASSL_API void SHA1_Update(SHA_CTX*, const void*, unsigned long);
CYASSL_API void SHA1_Final(unsigned char*, SHA_CTX*);

enum {
    SHA_DIGEST_LENGTH = 20
};


#ifdef __cplusplus
    }  /* extern "C" */ 
#endif


#endif /* CYASSL_SHA_H_ */

