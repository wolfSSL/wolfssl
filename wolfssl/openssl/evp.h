/* evp.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */



/*  evp.h defines mini evp openssl compatibility layer
 *
 */


#ifndef WOLFSSL_EVP_H_
#define WOLFSSL_EVP_H_

#include <wolfssl/wolfcrypt/settings.h>

#ifdef __cplusplus
	extern "C" {
#endif

#ifdef WOLFSSL_PREFIX
#include "prefix_evp.h"
#endif

#ifndef NO_MD5
    #include <wolfssl/openssl/md5.h>
#endif
#include <wolfssl/openssl/sha.h>
#include <wolfssl/openssl/ripemd.h>
#include <wolfssl/openssl/rsa.h>
#include <wolfssl/openssl/dsa.h>
#include <wolfssl/openssl/ec.h>

#include <wolfssl/wolfcrypt/compat-wolfssl.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/arc4.h>
#include <wolfssl/wolfcrypt/idea.h>


WOLFSSL_API WOLFSSL_RSA* wolfSSL_EVP_PKEY_get1_RSA(WOLFSSL_EVP_PKEY*);
WOLFSSL_API WOLFSSL_DSA* wolfSSL_EVP_PKEY_get1_DSA(WOLFSSL_EVP_PKEY*);
WOLFSSL_API WOLFSSL_EC_KEY *wolfSSL_EVP_PKEY_get1_EC_KEY(WOLFSSL_EVP_PKEY *key);

/* these next ones don't need real OpenSSL type, for OpenSSH compat only */
WOLFSSL_API void* wolfSSL_EVP_X_STATE(const WOLFCRYPT_EVP_CIPHER_CTX* ctx);
WOLFSSL_API int   wolfSSL_EVP_X_STATE_LEN(const WOLFCRYPT_EVP_CIPHER_CTX* ctx);
WOLFSSL_API void  wolfSSL_3des_iv(WOLFCRYPT_EVP_CIPHER_CTX* ctx, int doset,
                                unsigned char* iv, int len);
WOLFSSL_API void  wolfSSL_aes_ctr_iv(WOLFCRYPT_EVP_CIPHER_CTX* ctx, int doset,
                                unsigned char* iv, int len);
WOLFSSL_API int   wolfSSL_StoreExternalIV(WOLFCRYPT_EVP_CIPHER_CTX* ctx);
WOLFSSL_API int   wolfSSL_SetInternalIV(WOLFCRYPT_EVP_CIPHER_CTX* ctx);
/* end OpenSSH compat */


/* OpenSSL compat */
typedef WOLFCRYPT_EVP_MD            EVP_MD;
typedef WOLFCRYPT_EVP_CIPHER        EVP_CIPHER;
typedef WOLFCRYPT_EVP_MD_CTX        EVP_MD_CTX;
typedef WOLFCRYPT_EVP_CIPHER_CTX    EVP_CIPHER_CTX;

#define EVP_md5             wc_EVP_md5
#define EVP_sha1            wc_EVP_sha1
#define EVP_sha256          wc_EVP_sha256
#define EVP_sha384          wc_EVP_sha384
#define EVP_sha512          wc_EVP_sha512
#define EVP_ripemd160       wc_EVP_ripemd160

#define EVP_aes_128_cbc     wc_EVP_aes_128_cbc
#define EVP_aes_192_cbc     wc_EVP_aes_192_cbc
#define EVP_aes_256_cbc     wc_EVP_aes_256_cbc
#define EVP_aes_128_ctr     wc_EVP_aes_128_ctr
#define EVP_aes_192_ctr     wc_EVP_aes_192_ctr
#define EVP_aes_256_ctr     wc_EVP_aes_256_ctr
#define EVP_des_cbc         wc_EVP_des_cbc
#define EVP_des_ede3_cbc    wc_EVP_des_ede3_cbc
#define EVP_rc4             wc_EVP_rc4
#define EVP_idea_cbc        wc_EVP_idea_cbc
#define EVP_enc_null        wc_EVP_enc_null

#define EVP_MD_CTX_init     wc_EVP_MD_CTX_init
#define EVP_MD_CTX_cleanup  wc_EVP_MD_CTX_cleanup
#define EVP_MD_CTX_copy     wc_EVP_MD_CTX_copy
#define EVP_MD_size         wc_EVP_MD_size

#define EVP_DigestInit      wc_EVP_DigestInit
#define EVP_DigestUpdate    wc_EVP_DigestUpdate
#define EVP_DigestFinal     wc_EVP_DigestFinal
#define EVP_DigestFinal_ex  wc_EVP_DigestFinal_ex

#define EVP_CIPHER_CTX_init             wc_EVP_CIPHER_CTX_init
#define EVP_CIPHER_CTX_cleanup          wc_EVP_CIPHER_CTX_cleanup
#define EVP_CIPHER_CTX_iv_length        wc_EVP_CIPHER_CTX_iv_length
#define EVP_CIPHER_CTX_key_length       wc_EVP_CIPHER_CTX_key_length
#define EVP_CIPHER_CTX_copy             wc_EVP_CIPHER_CTX_copy
#define EVP_CIPHER_CTX_set_key_length   wc_EVP_CIPHER_CTX_set_key_length

#define EVP_CipherInit      wc_EVP_CipherInit
#define EVP_CipherUpdate    wc_EVP_CipherUpdate
#define EVP_CipherFinal     wc_EVP_CipherFinal
#define EVP_Cipher          wc_EVP_Cipher

#define EVP_get_digestbynid wc_EVP_get_digestbynid

#define EVP_PKEY_get1_RSA   wolfSSL_EVP_PKEY_get1_RSA
#define EVP_PKEY_get1_DSA   wolfSSL_EVP_PKEY_get1_DSA
#define EVP_PKEY_get1_EC_KEY wolfSSL_EVP_PKEY_get1_EC_KEY

#ifndef NO_MD5
#define EVP_BytesToKey  wc_EVP_BytesToKey
#endif


#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* WOLFSSL_EVP_H_ */
