/* dh.h for openSSL */


#ifndef CYASSL_DH_H_
#define CYASSL_DH_H_


#include <cyassl/openssl/ssl.h>
#include <cyassl/openssl/bn.h>


#ifdef __cplusplus
    extern "C" {
#endif




typedef struct CYASSL_DH {
	BIGNUM* p;
	BIGNUM* g;
} CYASSL_DH;


typedef CYASSL_DH DH;


#ifdef __cplusplus
    }  /* extern "C" */ 
#endif

#endif /* header */
