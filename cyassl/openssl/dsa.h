/* dsa.h for openSSL */


#ifndef CYASSL_DSA_H_
#define CYASSL_DSA_H_


#include <cyassl/openssl/ssl.h>
#include <cyassl/openssl/bn.h>


#ifdef __cplusplus
    extern "C" {
#endif



struct CYASSL_DSA {
	BIGNUM* p;
	BIGNUM* q;
	BIGNUM* g;
	BIGNUM* pub_key;
	BIGNUM* priv_key;
};





#ifdef __cplusplus
    }  /* extern "C" */ 
#endif

#endif /* header */
