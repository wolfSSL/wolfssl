/* evp.h
 *
 * Copyright (C) 2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef WOLF_CRYPT_COMPAT_WOLFSSL_H
#define WOLF_CRYPT_COMPAT_WOLFSSL_H

#include <wolfssl/wolfcrypt/settings.h>

#ifndef NO_MD5
#include <wolfssl/wolfcrypt/md5.h>
#endif
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/des3.h>
#include <wolfssl/wolfcrypt/arc4.h>
#include <wolfssl/wolfcrypt/idea.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>

#ifdef __cplusplus
extern "C" {
#endif

/* EVP digest */
typedef char WOLFCRYPT_EVP_MD;
#ifndef NO_MD5
WOLFSSL_API const WOLFCRYPT_EVP_MD* wc_EVP_md5(void);
#endif
#ifndef NO_SHA
WOLFSSL_API const WOLFCRYPT_EVP_MD* wc_EVP_sha1(void);
#endif
WOLFSSL_API const WOLFCRYPT_EVP_MD* wc_EVP_sha256(void);
#ifdef WOLFSSL_SHA384
WOLFSSL_API const WOLFCRYPT_EVP_MD* wc_EVP_sha384(void);
#endif
#ifdef WOLFSSL_SHA512
WOLFSSL_API const WOLFCRYPT_EVP_MD* wc_EVP_sha512(void);
#endif
#ifdef WOLFSSL_RIPEMD
WOLFSSL_API const WOLFCRYPT_EVP_MD* wc_EVP_ripemd160(void);
#endif

/* EVP Cipher */
typedef char WOLFCRYPT_EVP_CIPHER;
#ifndef NO_AES
WOLFSSL_API const WOLFCRYPT_EVP_CIPHER* wc_EVP_aes_128_cbc(void);
WOLFSSL_API const WOLFCRYPT_EVP_CIPHER* wc_EVP_aes_192_cbc(void);
WOLFSSL_API const WOLFCRYPT_EVP_CIPHER* wc_EVP_aes_256_cbc(void);
#ifdef WOLFSSL_AES_COUNTER
WOLFSSL_API const WOLFCRYPT_EVP_CIPHER* wc_EVP_aes_128_ctr(void);
WOLFSSL_API const WOLFCRYPT_EVP_CIPHER* wc_EVP_aes_192_ctr(void);
WOLFSSL_API const WOLFCRYPT_EVP_CIPHER* wc_EVP_aes_256_ctr(void);
#endif /* WOLFSSL_AES_COUNTER */
#endif /* NO_AES */
#ifndef NO_DES3
WOLFSSL_API const WOLFCRYPT_EVP_CIPHER* wc_EVP_des_cbc(void);
WOLFSSL_API const WOLFCRYPT_EVP_CIPHER* wc_EVP_des_ede3_cbc(void);
#endif
#ifdef HAVE_IDEA
WOLFSSL_API const WOLFCRYPT_EVP_CIPHER* wc_EVP_idea_cbc(void);
#endif
WOLFSSL_API const WOLFCRYPT_EVP_CIPHER* wc_EVP_rc4(void);
WOLFSSL_API const WOLFCRYPT_EVP_CIPHER* wc_EVP_enc_null(void);

enum WC_Digest {
    MD5_DIGEST_LENGTH = 16,
    SHA_DIGEST_LENGTH = 20,
    SHA256_DIGEST_LENGTH = 32,
    SHA384_DIGEST_LENGTH = 48,
    SHA512_DIGEST_LENGTH = 64
};

#ifndef EVP_MAX_MD_SIZE
#define EVP_MAX_MD_SIZE   64     /* sha512 */
#endif

enum WC_Cipher {
    RC4_KEY_SIZE        = 16,  /* always 128bit           */
    DES_KEY_SIZE        =  8,  /* des                     */
    DES3_KEY_SIZE       = 24,  /* 3 des ede               */
    DES_IV_SIZE         =  8,  /* des                     */
    AES_256_KEY_SIZE    = 32,  /* for 256 bit             */
    AES_192_KEY_SIZE    = 24,  /* for 192 bit             */
    AES_IV_SIZE         = 16,  /* always block size       */
    AES_128_KEY_SIZE    = 16,  /* for 128 bit             */
    EVP_SALT_SIZE       =  8,  /* evp salt size 64 bits   */
};

#ifndef NO_MD5
typedef struct {
    int holder[24];   /* big enough, but check on init */
} WOLFCRYPT_MD5_CTX;

WOLFSSL_API void wc_MD5_Init(WOLFCRYPT_MD5_CTX*);
WOLFSSL_API void wc_MD5_Update(WOLFCRYPT_MD5_CTX*, const void*, unsigned long);
WOLFSSL_API void wc_MD5_Final(unsigned char*, WOLFCRYPT_MD5_CTX*);
#endif /* NO_MD5 */

typedef struct {
    int holder[24];   /* big enough, but check on init */
} WOLFCRYPT_SHA_CTX;

WOLFSSL_API void wc_SHA_Init(WOLFCRYPT_SHA_CTX*);
WOLFSSL_API void wc_SHA_Update(WOLFCRYPT_SHA_CTX*, const void*, unsigned long);
WOLFSSL_API void wc_SHA_Final(unsigned char*, WOLFCRYPT_SHA_CTX*);

/* SHA1 points to above, shouldn't use SHA0 ever */
WOLFSSL_API void wc_SHA1_Init(WOLFCRYPT_SHA_CTX*);
WOLFSSL_API void wc_SHA1_Update(WOLFCRYPT_SHA_CTX*, const void*, unsigned long);
WOLFSSL_API void wc_SHA1_Final(unsigned char*, WOLFCRYPT_SHA_CTX*);

typedef struct {
    int holder[28];   /* big enough, but check on init */
} WOLFCRYPT_SHA256_CTX;

WOLFSSL_API void wc_SHA256_Init(WOLFCRYPT_SHA256_CTX*);
WOLFSSL_API void wc_SHA256_Update(WOLFCRYPT_SHA256_CTX*,
                                  const void*, unsigned long);
WOLFSSL_API void wc_SHA256_Final(unsigned char*, WOLFCRYPT_SHA256_CTX*);

#ifdef WOLFSSL_SHA384
typedef struct {
    long long holder[32];   /* big enough, but check on init */
} WOLFCRYPT_SHA384_CTX;

WOLFSSL_API void wc_SHA384_Init(WOLFCRYPT_SHA384_CTX*);
WOLFSSL_API void wc_SHA384_Update(WOLFCRYPT_SHA384_CTX*,
                                  const void*, unsigned long);
WOLFSSL_API void wc_SHA384_Final(unsigned char*, WOLFCRYPT_SHA384_CTX*);
#endif /* WOLFSSL_SHA384 */

#ifdef WOLFSSL_SHA512
typedef struct {
    long long holder[36];   /* big enough, but check on init */
} WOLFCRYPT_SHA512_CTX;

WOLFSSL_API void wc_SHA512_Init(WOLFCRYPT_SHA512_CTX*);
WOLFSSL_API void wc_SHA512_Update(WOLFCRYPT_SHA512_CTX*,
                                  const void*, unsigned long);
WOLFSSL_API void wc_SHA512_Final(unsigned char*, WOLFCRYPT_SHA512_CTX*);
#endif /* WOLFSSL_SHA512 */


#ifdef WOLFSSL_RIPEMD
typedef struct {
    int holder[32];   /* big enough, but check on init */
} WOLFCRYPT_RIPEMD_CTX;

WOLFSSL_API void wc_RIPEMD_Init(WOLFCRYPT_RIPEMD_CTX*);
WOLFSSL_API void wc_RIPEMD_Update(WOLFCRYPT_RIPEMD_CTX*,
                                  const void*, unsigned long);
WOLFSSL_API void wc_RIPEMD_Final(unsigned char*, WOLFCRYPT_RIPEMD_CTX*);
#endif /* WOLFSSL_RIPEMD */

typedef struct {
    Hmac hmac;
    int  type;
} WOLFCRYPT_HMAC_CTX;

WOLFSSL_API void wc_HMAC_Init(WOLFCRYPT_HMAC_CTX* ctx, const void* key,
                              int keylen, const WOLFCRYPT_EVP_MD* type);
WOLFSSL_API void wc_HMAC_Update(WOLFCRYPT_HMAC_CTX* ctx,
                                const unsigned char* data, int len);
WOLFSSL_API void wc_HMAC_Final(WOLFCRYPT_HMAC_CTX* ctx, unsigned char* hash,
                               unsigned int* len);
WOLFSSL_API void wc_HMAC_cleanup(WOLFCRYPT_HMAC_CTX* ctx);

WOLFSSL_API unsigned char* wc_HMAC(const WOLFCRYPT_EVP_MD* evp_md,
                                   const void* key, int key_len,
                                   const unsigned char* d, int n,
                                   unsigned char* md, unsigned int* md_len);

typedef union {
#ifndef NO_MD5
    WOLFCRYPT_MD5_CTX    md5;
#endif
    WOLFCRYPT_SHA_CTX    sha;
    WOLFCRYPT_SHA256_CTX sha256;
#ifdef WOLFSSL_SHA384
    WOLFCRYPT_SHA384_CTX sha384;
#endif
#ifdef WOLFSSL_SHA512
    WOLFCRYPT_SHA512_CTX sha512;
#endif
#ifdef WOLFSSL_RIPEMD
    WOLFCRYPT_RIPEMD_CTX ripemd;
#endif
} WOLFCRYPT_Hasher;

typedef struct WOLFCRYPT_EVP_MD_CTX {
    unsigned char macType;
    int macSize;
    const WOLFCRYPT_EVP_MD *digest;
    WOLFCRYPT_Hasher hash;
} WOLFCRYPT_EVP_MD_CTX;

typedef union {
#ifndef NO_AES
    Aes  aes;
#endif
#ifndef NO_DES3
    Des  des;
    Des3 des3;
#endif
    Arc4 arc4;
#ifdef HAVE_IDEA
    Idea idea;
#endif
} WOLFCRYPT_Cipher;

enum {
    AES_128_CBC_TYPE  = 1,
    AES_192_CBC_TYPE  = 2,
    AES_256_CBC_TYPE  = 3,
    AES_128_CTR_TYPE  = 4,
    AES_192_CTR_TYPE  = 5,
    AES_256_CTR_TYPE  = 6,
    DES_CBC_TYPE      = 7,
    DES_EDE3_CBC_TYPE = 8,
    ARC4_TYPE         = 9,
    NULL_CIPHER_TYPE  = 10,
    EVP_PKEY_RSA      = 11,
    EVP_PKEY_DSA      = 12,
    EVP_PKEY_EC		  = 13,
    IDEA_CBC_TYPE     = 14,
    NID_sha1          = 64,
    NID_md2           = 3,
    NID_md5           =  4
};

typedef struct {
    int            keyLen;         /* user may set for variable */
    int            blockSize;
    int            bufLen;
    unsigned char  enc;            /* if encrypt side, then true */
    unsigned char  cipherType;
    unsigned char  final_used;
    unsigned char  ivUpdate;
    unsigned char  padding;

#ifndef NO_AES
    unsigned char  iv[AES_BLOCK_SIZE];    /* working iv pointer into cipher */
    unsigned char  buf[AES_BLOCK_SIZE];
    unsigned char  final[AES_BLOCK_SIZE];
#elif !defined(NO_DES3) || defined(HAVE_IDEA)
    unsigned char  iv[DES_BLOCK_SIZE];    /* working iv pointer into cipher */
    unsigned char  buf[DES_BLOCK_SIZE];
    unsigned char  final[DES_BLOCK_SIZE];
#endif
    WOLFCRYPT_Cipher  cipher;
} WOLFCRYPT_EVP_CIPHER_CTX;

#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
extern const char *EVP_AES_128_CBC;
extern const char *EVP_AES_192_CBC;
extern const char *EVP_AES_256_CBC;
#if defined(OPENSSL_EXTRA)
extern const char *EVP_AES_128_CTR;
extern const char *EVP_AES_192_CTR;
extern const char *EVP_AES_256_CTR;
#endif
extern const int  EVP_AES_SIZE;

extern const char *EVP_DES_CBC;
extern const int  EVP_DES_SIZE;

extern const char *EVP_DES_EDE3_CBC;
extern const int  EVP_DES_EDE3_SIZE;

#ifdef HAVE_IDEA
extern const char *EVP_IDEA_CBC;
extern const int  EVP_IDEA_SIZE;
#endif
    
#endif /* OPENSSL_EXTRA || HAVE_WEBSERVER */

WOLFSSL_API int  wc_EVP_MD_size(const WOLFCRYPT_EVP_MD* md);
WOLFSSL_API void wc_EVP_MD_CTX_init(WOLFCRYPT_EVP_MD_CTX* ctx);
WOLFSSL_API int  wc_EVP_MD_CTX_cleanup(WOLFCRYPT_EVP_MD_CTX* ctx);
WOLFSSL_API int  wc_EVP_MD_CTX_copy(WOLFCRYPT_EVP_MD_CTX *out,
                                    const WOLFCRYPT_EVP_MD_CTX *in);
WOLFSSL_API const WOLFCRYPT_EVP_MD* wc_EVP_get_digestbynid(int);


WOLFSSL_API int wc_EVP_DigestInit(WOLFCRYPT_EVP_MD_CTX* ctx,
                                  const WOLFCRYPT_EVP_MD* type);
WOLFSSL_API int wc_EVP_DigestUpdate(WOLFCRYPT_EVP_MD_CTX* ctx,
                                    const void* data, unsigned long sz);
WOLFSSL_API int wc_EVP_DigestFinal(WOLFCRYPT_EVP_MD_CTX* ctx,
                                   unsigned char* md, unsigned int* s);
WOLFSSL_API int wc_EVP_DigestFinal_ex(WOLFCRYPT_EVP_MD_CTX* ctx,
                                      unsigned char* md, unsigned int* s);
#ifndef NO_MD5
WOLFSSL_API int wc_EVP_BytesToKey(const WOLFCRYPT_EVP_CIPHER*,
                                  const WOLFCRYPT_EVP_MD*,
                                  const unsigned char*, const unsigned char*,
                                  int, int, unsigned char*, unsigned char*);
#endif

WOLFSSL_API void wc_EVP_CIPHER_CTX_init(WOLFCRYPT_EVP_CIPHER_CTX* ctx);
WOLFSSL_API int wc_EVP_CIPHER_CTX_cleanup(WOLFCRYPT_EVP_CIPHER_CTX* ctx);
WOLFSSL_API int wc_EVP_CIPHER_CTX_iv_length(const WOLFCRYPT_EVP_CIPHER_CTX*);

WOLFSSL_API int wc_EVP_CipherInit(WOLFCRYPT_EVP_CIPHER_CTX* ctx,
                                  const WOLFCRYPT_EVP_CIPHER* type,
                                  unsigned char* key, unsigned char* iv,
                                  int enc);
WOLFSSL_API int wc_EVP_CipherUpdate(WOLFCRYPT_EVP_CIPHER_CTX *ctx,
                                    unsigned char *dst, int *dstLen,
                                    const unsigned char *src, int len);
WOLFSSL_API int wc_EVP_CipherFinal(WOLFCRYPT_EVP_CIPHER_CTX *ctx,
                                   unsigned char *dst, int *dstLen);

WOLFSSL_API int wc_EVP_CIPHER_CTX_key_length(WOLFCRYPT_EVP_CIPHER_CTX*);
WOLFSSL_API int wc_EVP_CIPHER_CTX_set_key_length(WOLFCRYPT_EVP_CIPHER_CTX*,
                                                        int);
WOLFSSL_API int wc_EVP_CIPHER_CTX_copy(WOLFCRYPT_EVP_CIPHER_CTX *out,
                                       const WOLFCRYPT_EVP_CIPHER_CTX *in);


WOLFSSL_API int wc_EVP_Cipher(WOLFCRYPT_EVP_CIPHER_CTX* ctx,
                              unsigned char* dst, unsigned char* src,
                              unsigned int len);

#ifndef EVP_MAX_MD_SIZE
#define EVP_MAX_MD_SIZE   64     /* sha512 */
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* WOLF_CRYPT_COMPAT_WOLFSSL_H */
