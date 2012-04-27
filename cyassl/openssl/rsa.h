/* rsa.h for openSSL */


#ifndef CYASSL_RSA_H_
#define CYASSL_RSA_H_

#include <cyassl/openssl/ssl.h>
#include <cyassl/openssl/bn.h>


#ifdef __cplusplus
    extern "C" {
#endif


enum  { 
	RSA_PKCS1_PADDING = 1
 };

struct CYASSL_RSA {
	BIGNUM* n;
	BIGNUM* e;
	BIGNUM* d;
	BIGNUM* p;
	BIGNUM* q;
	BIGNUM* dmp1;
	BIGNUM* dmq1;
	BIGNUM* iqmp;
};


CYASSL_API int CyaSSL_RSA_blinding_on(CYASSL_RSA*, CYASSL_BN_CTX*);
CYASSL_API int CyaSSL_RSA_public_encrypt(int len, unsigned char* fr,
	                               unsigned char* to, CYASSL_RSA*, int padding);
CYASSL_API int CyaSSL_RSA_private_decrypt(int len, unsigned char* fr,
	                               unsigned char* to, CYASSL_RSA*, int padding);


#define RSA_blinding_on     CyaSSL_RSA_blinding_on
#define RSA_public_encrypt  CyaSSL_RSA_public_encrypt
#define RSA_private_decrypt CyaSSL_RSA_private_decrypt


#ifdef __cplusplus
    }  /* extern "C" */ 
#endif

#endif /* header */
