/* hash.h
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


#ifndef WOLF_CRYPT_HASH_H
#define WOLF_CRYPT_HASH_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Hash types */
enum wc_HashType {
    WC_HASH_TYPE_NONE = 0,
    WC_HASH_TYPE_MD2 = 1,
    WC_HASH_TYPE_MD4 = 2,
    WC_HASH_TYPE_MD5 = 3,
    WC_HASH_TYPE_SHA = 4, /* SHA-1 (not old SHA-0) */
    WC_HASH_TYPE_SHA256 = 5,
    WC_HASH_TYPE_SHA384 = 6,
    WC_HASH_TYPE_SHA512 = 7,
};

/* Find largest possible digest size
   Note if this gets up to the size of 80 or over check smallstack build */
#if defined(WOLFSSL_SHA512)
    #define WC_MAX_DIGEST_SIZE SHA512_DIGEST_SIZE
#elif defined(WOLFSSL_SHA384)
    #define WC_MAX_DIGEST_SIZE SHA384_DIGEST_SIZE
#elif !defined(NO_SHA256)
    #define WC_MAX_DIGEST_SIZE SHA256_DIGEST_SIZE
#elif !defined(NO_SHA)
    #define WC_MAX_DIGEST_SIZE SHA_DIGEST_SIZE
#elif !defined(NO_MD5)
    #define WC_MAX_DIGEST_SIZE MD5_DIGEST_SIZE
#else
    #define WC_MAX_DIGEST_SIZE 64 /* default to max size of 64 */
#endif

#ifndef NO_ASN
WOLFSSL_API int wc_HashGetOID(enum wc_HashType hash_type);
#endif

WOLFSSL_API int wc_HashGetDigestSize(enum wc_HashType hash_type);
WOLFSSL_API int wc_Hash(enum wc_HashType hash_type,
    const byte* data, word32 data_len,
    byte* hash, word32 hash_len);


#ifndef NO_MD5
#include <wolfssl/wolfcrypt/md5.h>
WOLFSSL_API void wc_Md5GetHash(Md5*, byte*);
WOLFSSL_API void wc_Md5RestorePos(Md5*, Md5*);
#if defined(WOLFSSL_TI_HASH)
    WOLFSSL_API void wc_Md5Free(Md5*);
#else
    #define wc_Md5Free(d)
#endif
#endif

#ifndef NO_SHA
#include <wolfssl/wolfcrypt/sha.h>
WOLFSSL_API int wc_ShaGetHash(Sha*, byte*);
WOLFSSL_API void wc_ShaRestorePos(Sha*, Sha*);
WOLFSSL_API int wc_ShaHash(const byte*, word32, byte*);
#if defined(WOLFSSL_TI_HASH)
     WOLFSSL_API void wc_ShaFree(Sha*);
#else
    #define wc_ShaFree(d)
#endif
#endif

#ifndef NO_SHA256
#include <wolfssl/wolfcrypt/sha256.h>
WOLFSSL_API int wc_Sha256GetHash(Sha256*, byte*);
WOLFSSL_API void wc_Sha256RestorePos(Sha256*, Sha256*);
WOLFSSL_API int wc_Sha256Hash(const byte*, word32, byte*);
#if defined(WOLFSSL_TI_HASH)
    WOLFSSL_API void wc_Sha256Free(Sha256*);
#else
    #define wc_Sha256Free(d)
#endif
#endif

#ifdef WOLFSSL_SHA512
#include <wolfssl/wolfcrypt/sha512.h>
WOLFSSL_API int wc_Sha512Hash(const byte*, word32, byte*);
#if defined(WOLFSSL_TI_HASH)
    WOLFSSL_API void wc_Sha512Free(Sha512*);
#else
    #define wc_Sha512Free(d)
#endif
    #if defined(WOLFSSL_SHA384)
        WOLFSSL_API int wc_Sha384Hash(const byte*, word32, byte*);
        #if defined(WOLFSSL_TI_HASH)
            WOLFSSL_API void wc_Sha384Free(Sha384*);
        #else
            #define wc_Sha384Free(d)
        #endif
    #endif /* defined(WOLFSSL_SHA384) */
#endif /* WOLFSSL_SHA512 */


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_HASH_H */
