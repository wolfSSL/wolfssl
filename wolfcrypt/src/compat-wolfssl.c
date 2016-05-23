/* compat-wolfssl.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
#include <wolfssl/wolfcrypt/misc.h>
#else
#define WOLFSSL_MISC_INCLUDED
#include <wolfcrypt/src/misc.c>
#endif


#include <wolfssl/wolfcrypt/compat-wolfssl.h>


#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)

#ifndef NO_MD5

#ifndef WOLFSSL_HAVE_MIN
#define WOLFSSL_HAVE_MIN

static INLINE word32 min(word32 a, word32 b)
{
    return a > b ? b : a;
}
#endif /* WOLFSSSL_HAVE_MIN */

void wc_MD5_Init(WOLFCRYPT_MD5_CTX* md5)
{
    typedef char md5_test[sizeof(WOLFCRYPT_MD5_CTX) >= sizeof(Md5) ? 1 : -1];
    (void)sizeof(md5_test);

    WOLFSSL_ENTER("MD5_Init");
    wc_InitMd5((Md5*)md5);
}

void wc_MD5_Update(WOLFCRYPT_MD5_CTX* md5, const void* input, unsigned long sz)
{
    WOLFSSL_ENTER("wc_MD5_Update");
    wc_Md5Update((Md5*)md5, (const byte*)input, (word32)sz);
}

void wc_MD5_Final(byte* input, WOLFCRYPT_MD5_CTX* md5)
{
    WOLFSSL_ENTER("MD5_Final");
    wc_Md5Final((Md5*)md5, input);
}
#endif /* NO_MD5 */


#ifndef NO_SHA
void wc_SHA_Init(WOLFCRYPT_SHA_CTX* sha)
{
    typedef char sha_test[sizeof(WOLFCRYPT_SHA_CTX) >= sizeof(Sha) ? 1 : -1];
    (void)sizeof(sha_test);

    WOLFSSL_ENTER("SHA_Init");
    wc_InitSha((Sha*)sha);  /* OpenSSL compat, no ret */
}

void wc_SHA_Update(WOLFCRYPT_SHA_CTX* sha, const void* input, unsigned long sz)
{
    WOLFSSL_ENTER("SHA_Update");
    wc_ShaUpdate((Sha*)sha, (const byte*)input, (word32)sz);
}

void wc_SHA_Final(byte* input, WOLFCRYPT_SHA_CTX* sha)
{
    WOLFSSL_ENTER("SHA_Final");
    wc_ShaFinal((Sha*)sha, input);
}

void wc_SHA1_Init(WOLFCRYPT_SHA_CTX* sha)
{
    WOLFSSL_ENTER("SHA1_Init");
    wc_SHA_Init(sha);
}

void wc_SHA1_Update(WOLFCRYPT_SHA_CTX* sha, const void* input, unsigned long sz)
{
    WOLFSSL_ENTER("SHA1_Update");
    wc_SHA_Update(sha, input, sz);
}

void wc_SHA1_Final(byte* input, WOLFCRYPT_SHA_CTX* sha)
{
    WOLFSSL_ENTER("SHA1_Final");
    wc_SHA_Final(input, sha);
}
#endif /* NO_SHA */


void wc_SHA256_Init(WOLFCRYPT_SHA256_CTX* sha256)
{
    typedef char sha_test[sizeof(WOLFCRYPT_SHA256_CTX)>=sizeof(Sha256) ? 1:-1];
    (void)sizeof(sha_test);

    WOLFSSL_ENTER("SHA256_Init");
    wc_InitSha256((Sha256*)sha256);  /* OpenSSL compat, no error */
}

void wc_SHA256_Update(WOLFCRYPT_SHA256_CTX* sha, const void* input,
                      unsigned long sz)
{
    WOLFSSL_ENTER("SHA256_Update");
    wc_Sha256Update((Sha256*)sha, (const byte*)input, (word32)sz);
    /* OpenSSL compat, no error */
}

void wc_SHA256_Final(byte* input, WOLFCRYPT_SHA256_CTX* sha)
{
    WOLFSSL_ENTER("SHA256_Final");
    wc_Sha256Final((Sha256*)sha, input);
    /* OpenSSL compat, no error */
}


#ifdef WOLFSSL_SHA384
void wc_SHA384_Init(WOLFCRYPT_SHA384_CTX* sha)
{
    typedef char sha_test[sizeof(WOLFCRYPT_SHA384_CTX)>=sizeof(Sha384) ? 1:-1];
    (void)sizeof(sha_test);

    WOLFSSL_ENTER("SHA384_Init");
    wc_InitSha384((Sha384*)sha);   /* OpenSSL compat, no error */
}

void wc_SHA384_Update(WOLFCRYPT_SHA384_CTX* sha, const void* input,
                      unsigned long sz)
{
    WOLFSSL_ENTER("SHA384_Update");
    wc_Sha384Update((Sha384*)sha, (const byte*)input, (word32)sz);
    /* OpenSSL compat, no error */
}

void wc_SHA384_Final(byte* input, WOLFCRYPT_SHA384_CTX* sha)
{
    WOLFSSL_ENTER("SHA384_Final");
    wc_Sha384Final((Sha384*)sha, input);
    /* OpenSSL compat, no error */
}
#endif /* WOLFSSL_SHA384 */


#ifdef WOLFSSL_SHA512
void wc_SHA512_Init(WOLFCRYPT_SHA512_CTX* sha)
{
    typedef char sha_test[sizeof(WOLFCRYPT_SHA512_CTX)>=sizeof(Sha512) ? 1:-1];
    (void)sizeof(sha_test);

    WOLFSSL_ENTER("SHA512_Init");
    wc_InitSha512((Sha512*)sha);  /* OpenSSL compat, no error */
}

void wc_SHA512_Update(WOLFCRYPT_SHA512_CTX* sha, const void* input,
                      unsigned long sz)
{
    WOLFSSL_ENTER("SHA512_Update");
    wc_Sha512Update((Sha512*)sha, (const byte*)input, (word32)sz);
    /* OpenSSL compat, no error */
}

void wc_SHA512_Final(byte* input, WOLFCRYPT_SHA512_CTX* sha)
{
    WOLFSSL_ENTER("SHA512_Final");
    wc_Sha512Final((Sha512*)sha, input);
    /* OpenSSL compat, no error */
}
#endif /* WOLFSSL_SHA512 */

void wc_HMAC_Init(WOLFCRYPT_HMAC_CTX* ctx, const void* key, int keylen,
                  const WOLFCRYPT_EVP_MD* type)
{
    WOLFSSL_MSG("wc_HMAC_Init");

    if (ctx == NULL) {
        WOLFSSL_MSG("no ctx on init");
        return;
    }

    if (type) {
        WOLFSSL_MSG("init has type");

        if (XSTRNCMP(type, "MD5", 3) == 0) {
            WOLFSSL_MSG("md5 hmac");
            ctx->type = MD5;
        }
        else if (XSTRNCMP(type, "SHA256", 6) == 0) {
            WOLFSSL_MSG("sha256 hmac");
            ctx->type = SHA256;
        }

        /* has to be last since would pick or 256, 384, or 512 too */
        else if (XSTRNCMP(type, "SHA", 3) == 0) {
            WOLFSSL_MSG("sha hmac");
            ctx->type = SHA;
        }
        else {
            WOLFSSL_MSG("bad init type");
        }
    }

    if (key && keylen) {
        WOLFSSL_MSG("keying hmac");
        wc_HmacSetKey(&ctx->hmac, ctx->type, (const byte*)key, (word32)keylen);
        /* OpenSSL compat, no error */
    }
}


void wc_HMAC_Update(WOLFCRYPT_HMAC_CTX* ctx, const unsigned char* data, int len)
{
    WOLFSSL_MSG("wc_HMAC_Update");

    if (ctx && data) {
        WOLFSSL_MSG("updating hmac");
        wc_HmacUpdate(&ctx->hmac, data, (word32)len);
        /* OpenSSL compat, no error */
    }
}


void wc_HMAC_Final(WOLFCRYPT_HMAC_CTX* ctx, unsigned char* hash,
                   unsigned int* len)
{
    WOLFSSL_MSG("wc_HMAC_Final");

    if (ctx && hash) {
        WOLFSSL_MSG("final hmac");
        wc_HmacFinal(&ctx->hmac, hash);
        /* OpenSSL compat, no error */

        if (len) {
            WOLFSSL_MSG("setting output len");
            switch (ctx->type) {
#ifndef NO_MD5
                case MD5:
                    *len = MD5_DIGEST_SIZE;
                    break;
#endif
#ifndef NO_SHA
                case SHA:
                    *len = SHA_DIGEST_SIZE;
                    break;
#endif
                case SHA256:
                    *len = SHA256_DIGEST_SIZE;
                    break;

                default:
                    WOLFSSL_MSG("bad hmac type");
            }
        }
    }
}


void wc_HMAC_cleanup(WOLFCRYPT_HMAC_CTX* ctx)
{
    (void)ctx;
    
    WOLFSSL_MSG("wc_HMAC_cleanup");
}

unsigned char* wc_HMAC(const WOLFCRYPT_EVP_MD* evp_md, const void* key,
                       int key_len, const unsigned char* d, int n,
                       unsigned char* md, unsigned int* md_len)
{
    int type = -1;
    unsigned char* ret = NULL;
#ifdef WOLFSSL_SMALL_STACK
    Hmac* hmac = NULL;
#else
    Hmac  hmac[1];
#endif

    WOLFSSL_ENTER("HMAC");
    if (!md)
        return NULL;  /* no static buffer support */

#ifndef NO_MD5
    if (XSTRNCMP(evp_md, "MD5", 3) == 0)
        type = MD5;
#endif
#ifndef NO_SHA
    else if (XSTRNCMP(evp_md, "SHA", 3) == 0)
        type = SHA;
#endif

    if (type == -1)
        return NULL;

#ifdef WOLFSSL_SMALL_STACK
    hmac = (Hmac*)XMALLOC(sizeof(Hmac), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (hmac == NULL)
        return NULL;
#endif

    if (wc_HmacSetKey(hmac, type, (const byte*)key, key_len) == 0)
        if (wc_HmacUpdate(hmac, d, n) == 0)
            if (wc_HmacFinal(hmac, md) == 0) {
                if (md_len) {
#ifndef NO_MD5
                    if (type == MD5)
                        *md_len = (int)MD5_DIGEST_SIZE;
#endif
#ifndef NO_SHA
                    if (type == SHA)
                        *md_len = (int)SHA_DIGEST_SIZE;
#endif
                }
                ret = md;
            }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(hmac, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

const char *EVP_AES_128_CBC = "AES-128-CBC";
const char *EVP_AES_192_CBC = "AES-192-CBC";
const char *EVP_AES_256_CBC = "AES-256-CBC";

#if defined(OPENSSL_EXTRA)
const char *EVP_AES_128_CTR = "AES-128-CTR";
const char *EVP_AES_192_CTR = "AES-192-CTR";
const char *EVP_AES_256_CTR = "AES-256-CTR";
#endif /* OPENSSL_EXTRA */

const int  EVP_AES_SIZE = 11;

const char *EVP_DES_CBC = "DES-CBC";
const int  EVP_DES_SIZE = 7;

const char *EVP_DES_EDE3_CBC = "DES-EDE3-CBC";
const int  EVP_DES_EDE3_SIZE = 12;

#ifdef HAVE_IDEA
const char *EVP_IDEA_CBC = "IDEA-CBC";
const int  EVP_IDEA_SIZE = 8;
#endif /* HAVE_IDEA */

#ifndef NO_AES
const WOLFCRYPT_EVP_CIPHER* wc_EVP_aes_128_cbc(void)
{
    WOLFSSL_ENTER("wc_EVP_aes_128_cbc");
    return EVP_AES_128_CBC;
}

const WOLFCRYPT_EVP_CIPHER* wc_EVP_aes_192_cbc(void)
{
    WOLFSSL_ENTER("wc_EVP_aes_192_cbc");
    return EVP_AES_192_CBC;
}

const WOLFCRYPT_EVP_CIPHER* wc_EVP_aes_256_cbc(void)
{
    WOLFSSL_ENTER("wc_EVP_aes_256_cbc");
    return EVP_AES_256_CBC;
}

#ifdef WOLFSSL_AES_COUNTER
const WOLFCRYPT_EVP_CIPHER* wc_EVP_aes_128_ctr(void)
{
    WOLFSSL_ENTER("wc_EVP_aes_128_ctr");
    return EVP_AES_128_CTR;
}

const WOLFCRYPT_EVP_CIPHER* wc_EVP_aes_192_ctr(void)
{
    WOLFSSL_ENTER("wc_EVP_aes_192_ctr");
    return EVP_AES_192_CTR;
}

const WOLFCRYPT_EVP_CIPHER* wc_EVP_aes_256_ctr(void)
{
    WOLFSSL_ENTER("wc_EVP_aes_256_ctr");
    return EVP_AES_256_CTR;
}
#endif /* WOLFSSL_AES_COUNTER */
#endif /* NO_AES */

#ifndef NO_DES3
const WOLFCRYPT_EVP_CIPHER* wc_EVP_des_cbc(void)
{
    WOLFSSL_ENTER("wc_EVP_des_cbc");
    return EVP_DES_CBC;
}

const WOLFCRYPT_EVP_CIPHER* wc_EVP_des_ede3_cbc(void)
{
    WOLFSSL_ENTER("wc_EVP_des_ede3_cbc");
    return EVP_DES_EDE3_CBC;
}
#endif /* NO_DES3 */

const WOLFCRYPT_EVP_CIPHER* wc_EVP_rc4(void)
{
    static const char* type = "ARC4";
    WOLFSSL_ENTER("wc_EVP_rc4");
    return type;
}

#ifdef HAVE_IDEA
const WOLFCRYPT_EVP_CIPHER* wc_EVP_idea_cbc(void)
{
    WOLFSSL_ENTER("wc_EVP_idea_cbc");
    return EVP_IDEA_CBC;
}
#endif /* HAVE_IDEA */

const WOLFCRYPT_EVP_CIPHER* wc_EVP_enc_null(void)
{
    static const char* type = "NULL";
    WOLFSSL_ENTER("wc_EVP_enc_null");
    return type;
}

#ifndef NO_MD5
int wc_EVP_BytesToKey(const WOLFCRYPT_EVP_CIPHER* type,
                      const WOLFCRYPT_EVP_MD* md, const byte* salt,
                      const byte* data, int sz, int count, byte* key, byte* iv)
{
    int  keyLen = 0;
    int  ivLen  = 0;
    int  j;
    int  keyLeft;
    int  ivLeft;
    int  keyOutput = 0;
    byte digest[MD5_DIGEST_SIZE];
#ifdef WOLFSSL_SMALL_STACK
    Md5* md5 = NULL;
#else
    Md5  md5[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
    md5 = (Md5*)XMALLOC(sizeof(Md5), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (md5 == NULL)
        return 0;
#endif

    WOLFSSL_ENTER("wc_EVP_BytesToKey");
    wc_InitMd5(md5);

    /* only support MD5 for now */
    if (XSTRNCMP(md, "MD5", 3) != 0) return 0;

    /* only support CBC DES and AES for now */
    if (XSTRNCMP(type, EVP_DES_CBC, EVP_DES_SIZE) == 0) {
        keyLen = DES_KEY_SIZE;
        ivLen  = DES_IV_SIZE;
    }
    else if (XSTRNCMP(type, EVP_DES_EDE3_CBC, EVP_DES_EDE3_SIZE) == 0) {
        keyLen = DES3_KEY_SIZE;
        ivLen  = DES_IV_SIZE;
    }
    else if (XSTRNCMP(type, EVP_AES_128_CBC, EVP_AES_SIZE) == 0) {
        keyLen = AES_128_KEY_SIZE;
        ivLen  = AES_IV_SIZE;
    }
    else if (XSTRNCMP(type, EVP_AES_192_CBC, EVP_AES_SIZE) == 0) {
        keyLen = AES_192_KEY_SIZE;
        ivLen  = AES_IV_SIZE;
    }
    else if (XSTRNCMP(type, EVP_AES_256_CBC, EVP_AES_SIZE) == 0) {
        keyLen = AES_256_KEY_SIZE;
        ivLen  = AES_IV_SIZE;
    }
    else {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(md5, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return 0;
    }

    keyLeft   = keyLen;
    ivLeft    = ivLen;

    while (keyOutput < (keyLen + ivLen)) {
        int digestLeft = MD5_DIGEST_SIZE;
        /* D_(i - 1) */
        if (keyOutput)                      /* first time D_0 is empty */
            wc_Md5Update(md5, digest, MD5_DIGEST_SIZE);
        /* data */
        wc_Md5Update(md5, data, sz);
        /* salt */
        if (salt)
            wc_Md5Update(md5, salt, EVP_SALT_SIZE);
        wc_Md5Final(md5, digest);
        /* count */
        for (j = 1; j < count; j++) {
            wc_Md5Update(md5, digest, MD5_DIGEST_SIZE);
            wc_Md5Final(md5, digest);
        }

        if (keyLeft) {
            int store = min(keyLeft, MD5_DIGEST_SIZE);
            XMEMCPY(&key[keyLen - keyLeft], digest, store);

            keyOutput  += store;
            keyLeft    -= store;
            digestLeft -= store;
        }

        if (ivLeft && digestLeft) {
            int store = min(ivLeft, digestLeft);
            if (iv != NULL)
                XMEMCPY(&iv[ivLen - ivLeft],
                        &digest[MD5_DIGEST_SIZE - digestLeft], store);
            keyOutput += store;
            ivLeft    -= store;
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(md5, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return keyOutput == (keyLen + ivLen) ? keyOutput : 0;
}
#endif /* NO_MD5 */

#endif /* OPENSSL_EXTRA || HAVE_WEBSERVER */

#ifdef OPENSSL_EXTRA

#ifndef NO_MD5
const WOLFCRYPT_EVP_MD* wc_EVP_md5(void)
{
    static const char* type = "MD5";
    WOLFSSL_ENTER("EVP_md5");
    return type;
}
#endif /* NO_MD5 */

#ifndef NO_SHA
const WOLFCRYPT_EVP_MD* wc_EVP_sha1(void)
{
    static const char* type = "SHA";
    WOLFSSL_ENTER("EVP_sha1");
    return type;
}
#endif /* NO_SHA */

const WOLFCRYPT_EVP_MD* wc_EVP_sha256(void)
{
    static const char* type = "SHA256";
    WOLFSSL_ENTER("EVP_sha256");
    return type;
}

#ifdef WOLFSSL_SHA384
const WOLFCRYPT_EVP_MD* wc_EVP_sha384(void)
{
    static const char* type = "SHA384";
    WOLFSSL_ENTER("EVP_sha384");
    return type;
}
#endif /* WOLFSSL_SHA384 */

#ifdef WOLFSSL_SHA512
const WOLFCRYPT_EVP_MD* wc_EVP_sha512(void)
{
    static const char* type = "SHA512";
    WOLFSSL_ENTER("EVP_sha512");
    return type;
}
#endif /* WOLFSSL_SHA512 */

void wc_EVP_MD_CTX_init(WOLFCRYPT_EVP_MD_CTX* ctx)
{
    WOLFSSL_ENTER("EVP_CIPHER_MD_CTX_init");
    if (ctx == NULL) {
        WOLFSSL_MSG("Bad function argument");
        return;
    }

    ctx->macSize = 0;
    ctx->macType = 0xff;
}

/* return 1 on ok, 0 on failure to match API compatibility */
int wc_EVP_MD_CTX_copy(WOLFCRYPT_EVP_MD_CTX *out,const WOLFCRYPT_EVP_MD_CTX *in)
{
    WOLFSSL_ENTER("EVP_MD_CTX_copy");

    if (in == NULL || out == NULL) {
        WOLFSSL_MSG("Bad function argument");
        return 0;
    }

    wc_EVP_MD_CTX_init(out);
    XMEMCPY(out, in, sizeof(WOLFCRYPT_EVP_MD_CTX));

    return 1;
}

int wc_EVP_MD_CTX_cleanup(WOLFCRYPT_EVP_MD_CTX* ctx)
{
    WOLFSSL_ENTER("EVP_MD_CTX_cleanup");
    (void)ctx;
    return 0;
}

int wc_EVP_MD_size(const WOLFCRYPT_EVP_MD* type)
{
    WOLFSSL_MSG("wc_EVP_MD_size");

    if (type == NULL) {
        WOLFSSL_MSG("No md type arg");
        return BAD_FUNC_ARG;
    }

    if (XSTRNCMP(type, "SHA256", 6) == 0) {
        return SHA256_DIGEST_SIZE;
    }
#ifndef NO_MD5
    else if (XSTRNCMP(type, "MD5", 3) == 0) {
        return MD5_DIGEST_SIZE;
    }
#endif
#ifdef WOLFSSL_SHA384
    else if (XSTRNCMP(type, "SHA384", 6) == 0) {
        return SHA384_DIGEST_SIZE;
    }
#endif
#ifdef WOLFSSL_SHA512
    else if (XSTRNCMP(type, "SHA512", 6) == 0) {
        return SHA512_DIGEST_SIZE;
    }
#endif
#ifndef NO_SHA
    /* has to be last since would pick or 256, 384, or 512 too */
    else if (XSTRNCMP(type, "SHA", 3) == 0) {
        return SHA_DIGEST_SIZE;
    }
#endif

    return BAD_FUNC_ARG;
}

#ifdef WOLFSSL_RIPEMD
const WOLFCRYPT_EVP_MD* wc_EVP_ripemd160(void)
{
    WOLFSSL_MSG("wc_ripemd160");

    return NULL;
}
#endif

/* 1 on ok */
int wc_EVP_DigestInit(WOLFCRYPT_EVP_MD_CTX* ctx, const WOLFCRYPT_EVP_MD* type)
{
    WOLFSSL_ENTER("EVP_DigestInit");
    if (XSTRNCMP(type, "SHA256", 6) == 0) {
        ctx->macType = SHA256;
        ctx->macSize = SHA256_DIGEST_SIZE;
        wc_SHA256_Init((WOLFCRYPT_SHA256_CTX*)&ctx->hash);
    }
#ifdef WOLFSSL_SHA384
    else if (XSTRNCMP(type, "SHA384", 6) == 0) {
        ctx->macType = SHA384;
        ctx->macSize = SHA384_DIGEST_SIZE;
        wc_SHA384_Init((WOLFCRYPT_SHA384_CTX*)&ctx->hash);
    }
#endif
#ifdef WOLFSSL_SHA512
    else if (XSTRNCMP(type, "SHA512", 6) == 0) {
        ctx->macType = SHA512;
        ctx->macSize = SHA512_DIGEST_SIZE;
        wc_SHA512_Init((WOLFCRYPT_SHA512_CTX*)&ctx->hash);
    }
#endif
#ifndef NO_MD5
    else if (XSTRNCMP(type, "MD5", 3) == 0) {
        ctx->macType = MD5;
        ctx->macSize = MD5_DIGEST_SIZE;
        wc_MD5_Init((WOLFCRYPT_MD5_CTX*)&ctx->hash);
    }
#endif
#ifndef NO_SHA
    /* has to be last since would pick or 256, 384, or 512 too */
    else if (XSTRNCMP(type, "SHA", 3) == 0) {
        ctx->macType = SHA;
        ctx->macSize = SHA_DIGEST_SIZE;
        wc_SHA_Init((WOLFCRYPT_SHA_CTX*)&ctx->hash);
    }
#endif /* NO_SHA */
    else
        return BAD_FUNC_ARG;

    return 1;
}


/* 1 on ok */
int wc_EVP_DigestUpdate(WOLFCRYPT_EVP_MD_CTX* ctx, const void* data,
                        unsigned long sz)
{
    WOLFSSL_ENTER("EVP_DigestUpdate");

    switch (ctx->macType) {
#ifndef NO_MD5
        case MD5:
            wc_MD5_Update((WOLFCRYPT_MD5_CTX*)&ctx->hash, data,
                          (unsigned long)sz);
            break;
#endif
#ifndef NO_SHA
        case SHA:
            wc_SHA_Update((WOLFCRYPT_SHA_CTX*)&ctx->hash, data,
                          (unsigned long)sz);
            break;
#endif
#ifndef NO_SHA256
        case SHA256:
            wc_SHA256_Update((WOLFCRYPT_SHA256_CTX*)&ctx->hash, data,
                             (unsigned long)sz);
            break;
#endif
#ifdef WOLFSSL_SHA384
        case SHA384:
            wc_SHA384_Update((WOLFCRYPT_SHA384_CTX*)&ctx->hash, data,
                             (unsigned long)sz);
            break;
#endif
#ifdef WOLFSSL_SHA512
        case SHA512:
            wc_SHA512_Update((WOLFCRYPT_SHA512_CTX*)&ctx->hash, data,
                             (unsigned long)sz);
            break;
#endif
        default:
            return BAD_FUNC_ARG;
    }

    return 1;
}


/* 1 on ok */
int wc_EVP_DigestFinal(WOLFCRYPT_EVP_MD_CTX* ctx, unsigned char* md,
                       unsigned int* s)
{
    WOLFSSL_ENTER("EVP_DigestFinal");
    switch (ctx->macType) {
#ifndef NO_MD5
        case MD5:
            wc_MD5_Final(md, (WOLFCRYPT_MD5_CTX*)&ctx->hash);
            if (s) *s = MD5_DIGEST_SIZE;
            break;
#endif
#ifndef NO_SHA
        case SHA:
            wc_SHA_Final(md, (WOLFCRYPT_SHA_CTX*)&ctx->hash);
            if (s) *s = SHA_DIGEST_SIZE;
            break;
#endif
#ifndef NO_SHA256
        case SHA256:
            wc_SHA256_Final(md, (WOLFCRYPT_SHA256_CTX*)&ctx->hash);
            if (s) *s = SHA256_DIGEST_SIZE;
            break;
#endif
#ifdef WOLFSSL_SHA384
        case SHA384:
            wc_SHA384_Final(md, (WOLFCRYPT_SHA384_CTX*)&ctx->hash);
            if (s) *s = SHA384_DIGEST_SIZE;
            break;
#endif
#ifdef WOLFSSL_SHA512
        case SHA512:
            wc_SHA512_Final(md, (WOLFCRYPT_SHA512_CTX*)&ctx->hash);
            if (s) *s = SHA512_DIGEST_SIZE;
            break;
#endif
        default:
            return BAD_FUNC_ARG;
    }

    return 1;
}


/* 1 on ok */
int wc_EVP_DigestFinal_ex(WOLFCRYPT_EVP_MD_CTX* ctx, unsigned char* md,
                          unsigned int* s)
{
    WOLFSSL_ENTER("EVP_DigestFinal_ex");
    return wc_EVP_DigestFinal(ctx, md, s);
}

const WOLFCRYPT_EVP_MD* wc_EVP_get_digestbynid(int id)
{
    WOLFSSL_MSG("wc_get_digestbynid");

    switch(id) {
#ifndef NO_MD5
        case NID_md5:
            return wc_EVP_md5();
#endif
#ifndef NO_SHA
        case NID_sha1:
            return wc_EVP_sha1();
#endif
        default:
            WOLFSSL_MSG("Bad digest id value");
    }

    return NULL;
}


void wc_EVP_CIPHER_CTX_init(WOLFCRYPT_EVP_CIPHER_CTX* ctx)
{
    WOLFSSL_ENTER("EVP_CIPHER_CTX_init");
    if (ctx) {
        ctx->cipherType = 0xff;   /* no init */
        ctx->keyLen     = 0;
        ctx->enc        = 1;      /* start in encrypt mode */

        ctx->ivUpdate   = 0;
        ctx->final_used = 0;
        ctx->bufLen     = 0;
        ctx->blockSize  = 0;
        ctx->padding    = 0;

        XMEMSET(ctx->iv, 0, sizeof(ctx->iv));
        XMEMSET(ctx->buf, 0, sizeof(ctx->buf));
        XMEMSET(ctx->final, 0, sizeof(ctx->final));
    }
}

/* 1 on ok */
int wc_EVP_CIPHER_CTX_cleanup(WOLFCRYPT_EVP_CIPHER_CTX* ctx)
{
    WOLFSSL_ENTER("EVP_CIPHER_CTX_cleanup");

    /* reset to initial values */
    wc_EVP_CIPHER_CTX_init(ctx);

    return 1;
}

/* return 1 on ok, 0 on failure to match API compatibility */
int wc_EVP_CipherInit(WOLFCRYPT_EVP_CIPHER_CTX* ctx,
                      const WOLFCRYPT_EVP_CIPHER* type, byte* key,
                      byte* iv, int enc)
{
    int ret = -1;  /* failure local, during function 0 means success
                    because internal functions work that way */
    (void)iv;
    (void)enc;

    WOLFSSL_ENTER("wc_EVP_CipherInit");
    if (ctx == NULL) {
        WOLFSSL_MSG("no ctx");
        return 0;   /* failure */
    }

    if (type == NULL && ctx->cipherType == 0xff) {
        WOLFSSL_MSG("no type set");
        return 0;   /* failure */
    }

#ifndef NO_AES
    if (ctx->cipherType == AES_128_CBC_TYPE ||
        (type && XSTRNCMP(type, EVP_AES_128_CBC, EVP_AES_SIZE) == 0)) {
        WOLFSSL_MSG(EVP_AES_128_CBC);
        ctx->cipherType = AES_128_CBC_TYPE;
        ctx->padding = 1;
        ctx->ivUpdate = 1;
        ctx->blockSize = AES_BLOCK_SIZE;
        ctx->bufLen = 0;
        ctx->final_used = 0;
        ctx->keyLen     = 16;
        if (enc == 0 || enc == 1)
            ctx->enc = enc ? 1 : 0;
        if (key) {
            ret = wc_AesSetKey(&ctx->cipher.aes, key, ctx->keyLen, iv,
                               ctx->enc ? AES_ENCRYPTION : AES_DECRYPTION);
            if (ret != 0)
                return ret;
        }
        if (iv && key == NULL) {
            ret = wc_AesSetIV(&ctx->cipher.aes, iv);
            if (ret != 0)
                return ret;
        }
    }
    else if (ctx->cipherType == AES_192_CBC_TYPE ||
             (type && XSTRNCMP(type, EVP_AES_192_CBC, EVP_AES_SIZE) == 0)) {
        WOLFSSL_MSG(EVP_AES_192_CBC);
        ctx->cipherType = AES_192_CBC_TYPE;
        ctx->padding = 1;
        ctx->ivUpdate = 1;
        ctx->blockSize = AES_BLOCK_SIZE;
        ctx->bufLen = 0;
        ctx->final_used = 0;
        ctx->keyLen     = 24;
        if (enc == 0 || enc == 1)
            ctx->enc = enc ? 1 : 0;
        if (key) {
            ret = wc_AesSetKey(&ctx->cipher.aes, key, ctx->keyLen, iv,
                               ctx->enc ? AES_ENCRYPTION : AES_DECRYPTION);
            if (ret != 0)
                return ret;
        }
        if (iv && key == NULL) {
            ret = wc_AesSetIV(&ctx->cipher.aes, iv);
            if (ret != 0)
                return ret;
        }
    }
    else if (ctx->cipherType == AES_256_CBC_TYPE ||
             (type && XSTRNCMP(type, EVP_AES_256_CBC, EVP_AES_SIZE) == 0)) {
        WOLFSSL_MSG(EVP_AES_256_CBC);
        ctx->cipherType = AES_256_CBC_TYPE;
        ctx->padding = 1;
        ctx->ivUpdate = 1;
        ctx->blockSize = AES_BLOCK_SIZE;
        ctx->bufLen = 0;
        ctx->final_used = 0;
        ctx->keyLen     = 32;
        if (enc == 0 || enc == 1)
            ctx->enc = enc ? 1 : 0;
        if (key) {
            ret = wc_AesSetKey(&ctx->cipher.aes, key, ctx->keyLen, iv,
                               ctx->enc ? AES_ENCRYPTION : AES_DECRYPTION);
            if (ret != 0)
                return ret;
        }
        if (iv && key == NULL) {
            ret = wc_AesSetIV(&ctx->cipher.aes, iv);
            if (ret != 0)
                return ret;
        }
    }
#ifdef WOLFSSL_AES_COUNTER
    else if (ctx->cipherType == AES_128_CTR_TYPE ||
             (type && XSTRNCMP(type, EVP_AES_128_CTR, EVP_AES_SIZE) == 0)) {
        WOLFSSL_MSG(EVP_AES_128_CTR);
        ctx->cipherType = AES_128_CTR_TYPE;
        ctx->padding = 0;
        ctx->ivUpdate = 0;
        ctx->blockSize = AES_BLOCK_SIZE;
        ctx->bufLen = 0;
        ctx->final_used = 0;
        ctx->keyLen     = 16;
        if (enc == 0 || enc == 1)
            ctx->enc = enc ? 1 : 0;
        if (key) {
            ret = wc_AesSetKey(&ctx->cipher.aes, key, ctx->keyLen, iv,
                               AES_ENCRYPTION);
            if (ret != 0)
                return ret;
        }
        if (iv && key == NULL) {
            ret = wc_AesSetIV(&ctx->cipher.aes, iv);
            if (ret != 0)
                return ret;
        }
    }
    else if (ctx->cipherType == AES_192_CTR_TYPE ||
             (type && XSTRNCMP(type, EVP_AES_192_CTR, EVP_AES_SIZE) == 0)) {
        WOLFSSL_MSG(EVP_AES_192_CTR);
        ctx->cipherType = AES_192_CTR_TYPE;
        ctx->padding = 0;
        ctx->ivUpdate = 0;
        ctx->blockSize = AES_BLOCK_SIZE;
        ctx->bufLen = 0;
        ctx->final_used = 0;
        ctx->keyLen     = 24;
        if (enc == 0 || enc == 1)
            ctx->enc = enc ? 1 : 0;
        if (key) {
            ret = wc_AesSetKey(&ctx->cipher.aes, key, ctx->keyLen, iv,
                               AES_ENCRYPTION);
            if (ret != 0)
                return ret;
        }
        if (iv && key == NULL) {
            ret = wc_AesSetIV(&ctx->cipher.aes, iv);
            if (ret != 0)
                return ret;
        }
    }
    else if (ctx->cipherType == AES_256_CTR_TYPE ||
             (type && XSTRNCMP(type, EVP_AES_256_CTR, EVP_AES_SIZE) == 0)) {
        WOLFSSL_MSG(EVP_AES_256_CTR);
        ctx->cipherType = AES_256_CTR_TYPE;
        ctx->padding = 0;
        ctx->ivUpdate = 0;
        ctx->blockSize = AES_BLOCK_SIZE;
        ctx->bufLen = 0;
        ctx->final_used = 0;
        ctx->keyLen     = 32;
        if (enc == 0 || enc == 1)
            ctx->enc = enc ? 1 : 0;
        if (key) {
            ret = wc_AesSetKey(&ctx->cipher.aes, key, ctx->keyLen, iv,
                               AES_ENCRYPTION);
            if (ret != 0)
                return ret;
        }
        if (iv && key == NULL) {
            ret = wc_AesSetIV(&ctx->cipher.aes, iv);
            if (ret != 0)
                return ret;
        }
    }
#endif /* WOLFSSL_AES_CTR */
#endif /* NO_AES */

#ifndef NO_DES3
    if (ctx->cipherType == DES_CBC_TYPE ||
        (type && XSTRNCMP(type, EVP_DES_CBC, EVP_DES_SIZE) == 0)) {
        WOLFSSL_MSG(EVP_DES_CBC);
        ctx->cipherType = DES_CBC_TYPE;
        ctx->padding = 1;
        ctx->ivUpdate = 1;
        ctx->blockSize = DES_BLOCK_SIZE;
        ctx->bufLen = 0;
        ctx->final_used = 0;
        ctx->keyLen     = 8;
        if (enc == 0 || enc == 1)
            ctx->enc = enc ? 1 : 0;
        if (key) {
            ret = wc_Des_SetKey(&ctx->cipher.des, key, iv,
                                ctx->enc ? DES_ENCRYPTION : DES_DECRYPTION);
            if (ret != 0)
                return ret;
        }

        if (iv && key == NULL)
            wc_Des_SetIV(&ctx->cipher.des, iv);
    }
    else if (ctx->cipherType == DES_EDE3_CBC_TYPE ||
             (type &&
              XSTRNCMP(type, EVP_DES_EDE3_CBC, EVP_DES_EDE3_SIZE) == 0)) {
                 WOLFSSL_MSG(EVP_DES_EDE3_CBC);
                 ctx->cipherType = DES_EDE3_CBC_TYPE;
                 ctx->padding = 1;
                 ctx->ivUpdate = 1;
                 ctx->blockSize = DES_BLOCK_SIZE;
                 ctx->bufLen = 0;
                 ctx->final_used = 0;
                 ctx->keyLen     = 24;
                 if (enc == 0 || enc == 1)
                     ctx->enc = enc ? 1 : 0;
                 if (key) {
                     ret = wc_Des3_SetKey(&ctx->cipher.des3, key, iv,
                                          ctx->enc ? DES_ENCRYPTION : DES_DECRYPTION);
                     if (ret != 0)
                         return ret;
                 }

                 if (iv && key == NULL) {
                     ret = wc_Des3_SetIV(&ctx->cipher.des3, iv);
                     if (ret != 0)
                         return ret;
                 }
             }
#endif /* NO_DES3 */
#ifndef NO_RC4
    if (ctx->cipherType == ARC4_TYPE || (type &&
                                         XSTRNCMP(type, "ARC4", 4) == 0)) {
        WOLFSSL_MSG("ARC4");
        ctx->cipherType = ARC4_TYPE;
        ctx->blockSize = 1;
        ctx->bufLen = 0;
        ctx->final_used = 0;
        ctx->padding = 0;
        ctx->ivUpdate = 0;
        if (ctx->keyLen == 0)  /* user may have already set */
            ctx->keyLen = 16;  /* default to 128 */
        if (key)
            wc_Arc4SetKey(&ctx->cipher.arc4, key, ctx->keyLen);
        ret = 0;  /* success */
    }
#endif /* NO_RC4 */
#ifdef HAVE_IDEA
    if (ctx->cipherType == IDEA_CBC_TYPE ||
        (type && XSTRNCMP(type, EVP_IDEA_CBC, EVP_IDEA_SIZE) == 0)) {
        WOLFSSL_MSG(EVP_IDEA_CBC);
        ctx->cipherType = IDEA_CBC_TYPE;
        ctx->padding = 1;
        ctx->ivUpdate = 1;
        ctx->blockSize = IDEA_BLOCK_SIZE;
        ctx->bufLen = 0;
        ctx->final_used = 0;
        ctx->keyLen     = IDEA_KEY_SIZE;
        if (enc == 0 || enc == 1)
            ctx->enc = enc ? 1 : 0;
        if (key) {
            ret = wc_IdeaSetKey(&ctx->cipher.idea, key, (word16)ctx->keyLen,
                                iv, ctx->enc ? IDEA_ENCRYPTION :
                                IDEA_DECRYPTION);
            if (ret != 0)
                return ret;
        }

        if (iv && key == NULL)
            wc_IdeaSetIV(&ctx->cipher.idea, iv);
    }
#endif /* HAVE_IDEA */
    if (ctx->cipherType == NULL_CIPHER_TYPE || (type &&
                                                XSTRNCMP(type, "NULL", 4) == 0)) {
        WOLFSSL_MSG("NULL cipher");
        ctx->cipherType = NULL_CIPHER_TYPE;
        ctx->keyLen = 0;
        ctx->blockSize = 1;
        ctx->bufLen = 0;
        ctx->final_used = 0;
        ctx->padding = 0;
        ctx->ivUpdate = 0;
        ret = 0;  /* success */
    }

    if (ret == 0)
        return 1;
    else
        return 0;  /* overall failure */
}

/* return 1 on ok, 0 on failure to match API compatibility */
int wc_EVP_CipherUpdate(WOLFCRYPT_EVP_CIPHER_CTX *ctx, byte *dst, int *dstLen,
                        const byte *src, int len)
{
    int ret = 0, notEncLen = 0, fixLen = 0;
    WOLFSSL_ENTER("wc_EVP_CipherUpdate");

    *dstLen = 0;

    if (len <= 0)
        return (len == 0);

    /* Push pending data for the decryption case */
    if (!ctx->enc && ctx->final_used) {
        XMEMCPY(dst, ctx->final, ctx->blockSize);
        dst += ctx->blockSize;
        fixLen = 1;
    }

    /* No pending data, src len is a multiple of blocksize */
    if (!ctx->bufLen && !(len & (ctx->blockSize-1))) {
        ret = wc_EVP_Cipher(ctx, &dst[*dstLen], (byte*)src, len);
        if (ret != 1) {
            *dstLen = 0;
            WOLFSSL_MSG("wc_EVP_Cipher failure");
            return 0;
        }
        else {
            *dstLen = len;

            /* save new iv if required */
            if (ctx->ivUpdate) {
                if (ctx->enc)
                    XMEMCPY(ctx->iv, &dst[*dstLen-ctx->blockSize],
                            ctx->blockSize);
                else
                    XMEMCPY(ctx->iv, &src[len-ctx->blockSize],
                            ctx->blockSize);
                ctx->ivUpdate = 2;
            }

            /* extra operation for decrypt case */
            if (!ctx->enc)
                goto decrypt;
            else
                return 1;
        }
    }

    /* Pending data */
    if (ctx->bufLen) {
        /* pending data + src data less than a block
         * keep data and return */
        if (ctx->bufLen + len < ctx->blockSize) {
            XMEMCPY(&ctx->buf[ctx->bufLen], src, len);
            ctx->bufLen += len;
            *dstLen = 0;
            return 1;
        }
        else {
            /* complete pending buffer and encrypt/decrypt it */
            XMEMCPY(&ctx->buf[ctx->bufLen], src,
                    ctx->blockSize - ctx->bufLen);
            ret = wc_EVP_Cipher(ctx, &dst[*dstLen],
                                     ctx->buf, ctx->blockSize);
            if (ret != 1) {
                *dstLen = 0;
                WOLFSSL_MSG("wc_EVP_Cipher failure");
                return 0;
            }

            /* save new iv if required */
            if (ctx->ivUpdate) {
                if (ctx->enc)
                    XMEMCPY(ctx->iv, dst, ctx->blockSize);
                else
                    XMEMCPY(ctx->iv, ctx->buf, ctx->blockSize);
                ctx->ivUpdate = 2;
            }

            len -= (ctx->blockSize - ctx->bufLen);
            src += (ctx->blockSize - ctx->bufLen);
            *dstLen = ctx->blockSize;
        }
    }
    /* src len not a multiple of block size */
    else
        *dstLen = 0;

    /* encrypt/decrypt max blocks as possible */
    notEncLen = len & (ctx->blockSize - 1);
    len -= notEncLen;
    if (len > 0) {
        ret = wc_EVP_Cipher(ctx, &dst[*dstLen], (byte*)src, len);
        if (ret != 1) {
            WOLFSSL_MSG("wc_EVP_Cipher failure");
            return 0;
        }
        *dstLen += len;

        /* save new iv if required */
        if (ctx->ivUpdate) {
            if (ctx->enc)
                XMEMCPY(ctx->iv, &dst[*dstLen-ctx->blockSize],
                        ctx->blockSize);
            else
                XMEMCPY(ctx->iv, &src[len-ctx->blockSize], ctx->blockSize);
            ctx->ivUpdate = 2;
        }
    }

    /* save pending data */
    if (notEncLen)
        XMEMCPY(ctx->buf, src+len, notEncLen);
    ctx->bufLen = notEncLen;

decrypt:
    /* extra operation for decrypt case */
    if (!ctx->enc) {
        /* keep last block for final step when decrypting
         * multiple of block size */
        if (ctx->blockSize > 1 && !ctx->bufLen) {
            *dstLen -= ctx->blockSize;
            ctx->final_used = 1;
            XMEMCPY(ctx->final, &dst[*dstLen], ctx->blockSize);
        }
        else
            ctx->final_used = 0;

        if (fixLen)
            *dstLen += ctx->blockSize;
    }

    return 1;
}

/* return 1 on ok, 0 on failure to match API compatibility */
int wc_EVP_CipherFinal(WOLFCRYPT_EVP_CIPHER_CTX *ctx, byte *dst, int *dstLen)
{
    int ret;

    if (ctx->blockSize == 1) {
        *dstLen = 0;
        WOLFSSL_MSG("wc_EVP_CipherFinal: blocksize 1");
        return 1;
    }

    if (ctx->enc) {
        if (ctx->padding) {
            /* add padding */
            XMEMSET(ctx->buf+ctx->bufLen, (byte)(ctx->blockSize-ctx->bufLen),
                    ctx->blockSize-ctx->bufLen);

            ret = wc_EVP_Cipher(ctx, dst, ctx->buf, ctx->blockSize);
            if (ret != 1) {
                WOLFSSL_MSG("wc_EVP_CipherFinal failure");
                return 0;
            }

            *dstLen = ctx->blockSize;
        }
        else {
            if (ctx->bufLen) {
                ret = wc_EVP_Cipher(ctx, dst, ctx->buf, ctx->bufLen);
                if (ret != 1) {
                    WOLFSSL_MSG("wc_EVP_CipherFinal failure");
                    return 0;
                }

                *dstLen = ctx->bufLen;
            }
            else {
                WOLFSSL_MSG("wc_EVP_CipherFinal: Nothing to do");
                *dstLen = 0;
            }
        }
    }
    else {
        int i, pad;

        /* decrypt pending data, case of stream cipher */
        if (ctx->bufLen && !ctx->final_used) {
            ret = wc_EVP_Cipher(ctx, dst, ctx->buf, ctx->bufLen);
            if (ret != 1) {
                WOLFSSL_MSG("wc_EVP_CipherFinal failure");
                return 0;
            }

            *dstLen = ctx->bufLen;
            ctx->bufLen = 0;

            return 1;
        }
        else if (ctx->bufLen || !ctx->final_used) {
            WOLFSSL_MSG("wc_EVP_CipherFinal: Wrong final block length");
            return 0;
        }

        /* get padding */
        if (ctx->padding) {
            pad = (int)ctx->final[ctx->blockSize-1];
            if (!pad || pad > (int)ctx->blockSize) {
                WOLFSSL_MSG("wc_EVP_CipherFinal: Bad decrypt");
                return 0;
            }

            /* check padding */
            for (i = 0; i < pad; i++) {
                if (ctx->final[ctx->blockSize-1-i] != pad) {
                    WOLFSSL_MSG("wc_EVP_CipherFinal: Bad decrypt");
                    return 0;
                }
            }

            /* return data without padding */
            *dstLen = ctx->blockSize-pad;
            XMEMCPY(dst, ctx->final, *dstLen);
        }
        else {
            /* return data */
            *dstLen = ctx->blockSize;
            XMEMCPY(dst, ctx->final, *dstLen);
        }
    }

    return 1;
}

/* return 1 on ok, 0 on failure to match API compatibility */
int wc_EVP_CIPHER_CTX_copy(WOLFCRYPT_EVP_CIPHER_CTX *out,
                           const WOLFCRYPT_EVP_CIPHER_CTX *in)
{
    WOLFSSL_ENTER("wc_EVP_CIPHER_CTX_copy");

    if (in == NULL || out == NULL) {
        WOLFSSL_MSG("Bad function argument");
        return 0;
    }

    wc_EVP_CIPHER_CTX_cleanup(out);
    XMEMCPY(out, in, sizeof(WOLFCRYPT_EVP_CIPHER_CTX));

    return 1;
}

/* 1 on ok */
int wc_EVP_CIPHER_CTX_key_length(WOLFCRYPT_EVP_CIPHER_CTX* ctx)
{
    WOLFSSL_ENTER("wc_EVP_CIPHER_CTX_key_length");
    if (ctx)
        return ctx->keyLen;

    return 0;   /* failure */
}


/* 1 on ok */
int wc_EVP_CIPHER_CTX_set_key_length(WOLFCRYPT_EVP_CIPHER_CTX* ctx, int keylen)
{
    WOLFSSL_ENTER("wc_EVP_CIPHER_CTX_set_key_length");
    if (ctx)
        ctx->keyLen = keylen;
    else
        return 0;  /* failure */

    return 1;
}


/* 1 on ok */
int wc_EVP_Cipher(WOLFCRYPT_EVP_CIPHER_CTX* ctx, byte* dst, byte* src,
                  word32 len)
{
    int ret = 0;
    WOLFSSL_ENTER("wc_EVP_Cipher");

    if (ctx == NULL || dst == NULL || src == NULL) {
        WOLFSSL_MSG("Bad function argument");
        return 0;  /* failure */
    }

    if (ctx->cipherType == 0xff) {
        WOLFSSL_MSG("no init");
        return 0;  /* failure */
    }

    switch (ctx->cipherType) {

#ifndef NO_AES
        case AES_128_CBC_TYPE :
        case AES_192_CBC_TYPE :
        case AES_256_CBC_TYPE :
            WOLFSSL_MSG("AES CBC");
            if (ctx->ivUpdate > 1) {
                ret = wc_AesSetIV(&ctx->cipher.aes, ctx->iv);
                if (ret != 0) {
                    WOLFSSL_MSG("wc_EVP_Cipher failure");
                    return 0;  /* failure */
                }
            }

            if (ctx->enc)
                ret = wc_AesCbcEncrypt(&ctx->cipher.aes, dst, src, len);
            else
                ret = wc_AesCbcDecrypt(&ctx->cipher.aes, dst, src, len);
            break;

#ifdef WOLFSSL_AES_COUNTER
        case AES_128_CTR_TYPE :
        case AES_192_CTR_TYPE :
        case AES_256_CTR_TYPE :
            WOLFSSL_MSG("AES CTR");
            wc_AesCtrEncrypt(&ctx->cipher.aes, dst, src, len);
            break;
#endif
#endif /* NO_AES */

#ifndef NO_DES3
        case DES_CBC_TYPE :
            if (ctx->ivUpdate > 1)
                wc_Des_SetIV(&ctx->cipher.des, ctx->iv);

            if (ctx->enc)
                wc_Des_CbcEncrypt(&ctx->cipher.des, dst, src, len);
            else
                wc_Des_CbcDecrypt(&ctx->cipher.des, dst, src, len);
            break;

        case DES_EDE3_CBC_TYPE :
            if (ctx->ivUpdate > 1) {
                ret = wc_Des3_SetIV(&ctx->cipher.des3, ctx->iv);
                if (ret != 0) {
                    WOLFSSL_MSG("wc_EVP_Cipher failure");
                    return 0;  /* failure */
                }
            }

            if (ctx->enc)
                ret = wc_Des3_CbcEncrypt(&ctx->cipher.des3, dst, src, len);
            else
                ret = wc_Des3_CbcDecrypt(&ctx->cipher.des3, dst, src, len);
            break;
#endif

#ifndef NO_RC4
        case ARC4_TYPE :
            wc_Arc4Process(&ctx->cipher.arc4, dst, src, len);
            break;
#endif

#ifdef HAVE_IDEA
        case IDEA_CBC_TYPE :
            if (ctx->ivUpdate > 1) {
                ret = wc_IdeaSetIV(&ctx->cipher.idea, ctx->iv);
                if (ret != 0) {
                    WOLFSSL_MSG("wc_EVP_Cipher failure");
                    return 0;  /* failure */
                }
            }

            if (ctx->enc)
                wc_IdeaCbcEncrypt(&ctx->cipher.idea, dst, src, len);
            else
                wc_IdeaCbcDecrypt(&ctx->cipher.idea, dst, src, len);
            break;
#endif
        case NULL_CIPHER_TYPE :
            XMEMCPY(dst, src, len);
            break;

        default: {
            WOLFSSL_MSG("bad type");
            return 0;  /* failure */
        }
    }

    if (ret != 0) {
        WOLFSSL_MSG("wc_EVP_Cipher failure");
        return 0;  /* failuer */
    }

    WOLFSSL_MSG("wc_EVP_Cipher success");
    return 1;  /* success */
}

int wc_EVP_CIPHER_CTX_iv_length(const WOLFCRYPT_EVP_CIPHER_CTX* ctx)
{
    WOLFSSL_MSG("wc_EVP_CIPHER_CTX_iv_length");

    switch (ctx->cipherType) {
#ifndef NO_AES
        case AES_128_CBC_TYPE :
        case AES_192_CBC_TYPE :
        case AES_256_CBC_TYPE :
            WOLFSSL_MSG("AES CBC");
            return AES_BLOCK_SIZE;

#ifdef WOLFSSL_AES_COUNTER
        case AES_128_CTR_TYPE :
        case AES_192_CTR_TYPE :
        case AES_256_CTR_TYPE :
            WOLFSSL_MSG("AES CTR");
            return AES_BLOCK_SIZE;
#endif
#endif /* NO_AES */

#ifndef NO_DES3
        case DES_CBC_TYPE :
            WOLFSSL_MSG("DES CBC");
            return DES_BLOCK_SIZE;

        case DES_EDE3_CBC_TYPE :
            WOLFSSL_MSG("DES EDE3 CBC");
            return DES_BLOCK_SIZE;
#endif

#ifdef HAVE_IDEA
        case IDEA_CBC_TYPE :
            WOLFSSL_MSG("IDEA CBC");
            return IDEA_BLOCK_SIZE;
#endif
        case ARC4_TYPE :
            WOLFSSL_MSG("ARC4");
            return 0;

        case NULL_CIPHER_TYPE :
            WOLFSSL_MSG("NULL");
            return 0;

        default: {
            WOLFSSL_MSG("bad type");
        }
    }
    return 0;
}

#endif /* OPENSSL_EXTRA */
