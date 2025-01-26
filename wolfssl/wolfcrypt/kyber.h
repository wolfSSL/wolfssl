/* kyber.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/*!
    \file wolfssl/wolfcrypt/kyber.h
 */

#ifndef WOLF_CRYPT_KYBER_H
#define WOLF_CRYPT_KYBER_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef WOLFSSL_HAVE_KYBER

/* Define algorithm type when not excluded. */

#ifndef WOLFSSL_NO_KYBER512
#define WOLFSSL_KYBER512
#endif
#ifndef WOLFSSL_NO_KYBER768
#define WOLFSSL_KYBER768
#endif
#ifndef WOLFSSL_NO_KYBER1024
#define WOLFSSL_KYBER1024
#endif


/* Number of co-efficients in polynomial. */
#define KYBER_N             256


/* Size of a polynomial vector based on dimensions. */
#define KYBER_POLY_VEC_SZ(k) ((k) * KYBER_POLY_SIZE)
/* Size of a compressed polynomial based on bits per coefficient. */
#define KYBER_POLY_COMPRESSED_SZ(b) ((b) * (KYBER_N / 8))
/* Size of a compressed vector polynomial based on dimensions and bits per
 * coefficient. */
#define KYBER_POLY_VEC_COMPRESSED_SZ(k, b) ((k) * ((b) * (KYBER_N / 8)))


/* Kyber-512 parameters */
#ifdef WOLFSSL_KYBER512
/* Number of polynomials in a vector and vectors in a matrix. */
#define KYBER512_K          2

/* Size of a polynomial vector. */
#define KYBER512_POLY_VEC_SZ             KYBER_POLY_VEC_SZ(KYBER512_K)
/* Size of a compressed polynomial based on bits per coefficient. */
#define KYBER512_POLY_COMPRESSED_SZ      KYBER_POLY_COMPRESSED_SZ(4)
/* Size of a compressed vector polynomial based on dimensions and bits per
 * coefficient. */
#define KYBER512_POLY_VEC_COMPRESSED_SZ  \
    KYBER_POLY_VEC_COMPRESSED_SZ(KYBER512_K, 10)

/* Public key size. */
#define KYBER512_PUBLIC_KEY_SIZE  \
    (KYBER512_POLY_VEC_SZ + KYBER_SYM_SZ)
/* Private key size. */
#define KYBER512_PRIVATE_KEY_SIZE \
    (KYBER512_POLY_VEC_SZ + KYBER512_PUBLIC_KEY_SIZE + 2 * KYBER_SYM_SZ)
/* Cipher text size. */
#define KYBER512_CIPHER_TEXT_SIZE \
    (KYBER512_POLY_VEC_COMPRESSED_SZ + KYBER512_POLY_COMPRESSED_SZ)
#endif /* WOLFSSL_KYBER512 */

/* Kyber-768 parameters */
#ifdef WOLFSSL_KYBER768
/* Number of polynomials in a vector and vectors in a matrix. */
#define KYBER768_K          3

/* Size of a polynomial vector. */
#define KYBER768_POLY_VEC_SZ             KYBER_POLY_VEC_SZ(KYBER768_K)
/* Size of a compressed polynomial based on bits per coefficient. */
#define KYBER768_POLY_COMPRESSED_SZ      KYBER_POLY_COMPRESSED_SZ(4)
/* Size of a compressed vector polynomial based on dimensions and bits per
 * coefficient. */
#define KYBER768_POLY_VEC_COMPRESSED_SZ  \
    KYBER_POLY_VEC_COMPRESSED_SZ(KYBER768_K, 10)

/* Public key size. */
#define KYBER768_PUBLIC_KEY_SIZE  \
    (KYBER768_POLY_VEC_SZ + KYBER_SYM_SZ)
/* Private key size. */
#define KYBER768_PRIVATE_KEY_SIZE \
    (KYBER768_POLY_VEC_SZ + KYBER768_PUBLIC_KEY_SIZE + 2 * KYBER_SYM_SZ)
/* Cipher text size. */
#define KYBER768_CIPHER_TEXT_SIZE \
    (KYBER768_POLY_VEC_COMPRESSED_SZ + KYBER768_POLY_COMPRESSED_SZ)
#endif /* WOLFSSL_KYBER768 */

/* Kyber-1024 parameters */
#ifdef WOLFSSL_KYBER1024
/* Number of polynomials in a vector and vectors in a matrix. */
#define KYBER1024_K         4

/* Size of a polynomial vector. */
#define KYBER1024_POLY_VEC_SZ             KYBER_POLY_VEC_SZ(KYBER1024_K)
/* Size of a compressed polynomial based on bits per coefficient. */
#define KYBER1024_POLY_COMPRESSED_SZ      KYBER_POLY_COMPRESSED_SZ(5)
/* Size of a compressed vector polynomial based on dimensions and bits per
 * coefficient. */
#define KYBER1024_POLY_VEC_COMPRESSED_SZ \
    KYBER_POLY_VEC_COMPRESSED_SZ(KYBER1024_K, 11)

/* Public key size. */
#define KYBER1024_PUBLIC_KEY_SIZE  \
    (KYBER1024_POLY_VEC_SZ + KYBER_SYM_SZ)
/* Private key size. */
#define KYBER1024_PRIVATE_KEY_SIZE \
    (KYBER1024_POLY_VEC_SZ + KYBER1024_PUBLIC_KEY_SIZE + 2 * KYBER_SYM_SZ)
/* Cipher text size. */
#define KYBER1024_CIPHER_TEXT_SIZE \
    (KYBER1024_POLY_VEC_COMPRESSED_SZ + KYBER1024_POLY_COMPRESSED_SZ)
#endif /* WOLFSSL_KYBER1024 */


/* Maximum dimensions and sizes of supported key types. */
#ifdef WOLFSSL_KYBER1024
#define KYBER_MAX_K                 KYBER1024_K
#define KYBER_MAX_PRIVATE_KEY_SIZE  KYBER1024_PRIVATE_KEY_SIZE
#define KYBER_MAX_PUBLIC_KEY_SIZE   KYBER1024_PUBLIC_KEY_SIZE
#define KYBER_MAX_CIPHER_TEXT_SIZE  KYBER1024_CIPHER_TEXT_SIZE
#elif defined(WOLFSSL_KYBER768)
#define KYBER_MAX_K                 KYBER768_K
#define KYBER_MAX_PRIVATE_KEY_SIZE  KYBER768_PRIVATE_KEY_SIZE
#define KYBER_MAX_PUBLIC_KEY_SIZE   KYBER768_PUBLIC_KEY_SIZE
#define KYBER_MAX_CIPHER_TEXT_SIZE  KYBER768_CIPHER_TEXT_SIZE
#else
#define KYBER_MAX_K                 KYBER512_K
#define KYBER_MAX_PRIVATE_KEY_SIZE  KYBER512_PRIVATE_KEY_SIZE
#define KYBER_MAX_PUBLIC_KEY_SIZE   KYBER512_PUBLIC_KEY_SIZE
#define KYBER_MAX_CIPHER_TEXT_SIZE  KYBER512_CIPHER_TEXT_SIZE
#endif

enum {
    /* Types of Kyber keys. */
    WC_ML_KEM_512  = 0,
    WC_ML_KEM_768  = 1,
    WC_ML_KEM_1024 = 2,

    KYBER_ORIGINAL = 0x10,
    KYBER512  = 0 | KYBER_ORIGINAL,
    KYBER768  = 1 | KYBER_ORIGINAL,
    KYBER1024 = 2 | KYBER_ORIGINAL,

    KYBER_LEVEL1 = KYBER512,
    KYBER_LEVEL3 = KYBER768,
    KYBER_LEVEL5 = KYBER1024,

    /* Symmetric data size. */
    KYBER_SYM_SZ            = 32,
    /* Shared secret size. */
    KYBER_SS_SZ             = 32,
    /* Size of random required for making a key. */
    KYBER_MAKEKEY_RAND_SZ   = 2 * KYBER_SYM_SZ,
    /* Size of random required for encapsulation. */
    KYBER_ENC_RAND_SZ       = KYBER_SYM_SZ,

    /* Encoded polynomial size. */
    KYBER_POLY_SIZE         = 384,
};


/* Different structures for different implementations. */
typedef struct KyberKey KyberKey;


#ifdef __cplusplus
    extern "C" {
#endif

WOLFSSL_API int wc_KyberKey_Init(int type, KyberKey* key, void* heap,
    int devId);
WOLFSSL_API void wc_KyberKey_Free(KyberKey* key);

WOLFSSL_API int wc_KyberKey_MakeKey(KyberKey* key, WC_RNG* rng);
WOLFSSL_API int wc_KyberKey_MakeKeyWithRandom(KyberKey* key,
    const unsigned char* rand, int len);

WOLFSSL_API int wc_KyberKey_CipherTextSize(KyberKey* key, word32* len);
WOLFSSL_API int wc_KyberKey_SharedSecretSize(KyberKey* key, word32* len);

WOLFSSL_API int wc_KyberKey_Encapsulate(KyberKey* key, unsigned char* ct,
    unsigned char* ss, WC_RNG* rng);
WOLFSSL_API int wc_KyberKey_EncapsulateWithRandom(KyberKey* key,
    unsigned char* ct, unsigned char* ss, const unsigned char* rand, int len);
WOLFSSL_API int wc_KyberKey_Decapsulate(KyberKey* key, unsigned char* ss,
    const unsigned char* ct, word32 len);

WOLFSSL_API int wc_KyberKey_DecodePrivateKey(KyberKey* key,
    const unsigned char* in, word32 len);
WOLFSSL_API int wc_KyberKey_DecodePublicKey(KyberKey* key,
    const unsigned char* in, word32 len);

WOLFSSL_API int wc_KyberKey_PrivateKeySize(KyberKey* key, word32* len);
WOLFSSL_API int wc_KyberKey_PublicKeySize(KyberKey* key, word32* len);
WOLFSSL_API int wc_KyberKey_EncodePrivateKey(KyberKey* key, unsigned char* out,
    word32 len);
WOLFSSL_API int wc_KyberKey_EncodePublicKey(KyberKey* key, unsigned char* out,
    word32 len);



#if !defined(WOLFSSL_NO_ML_KEM_512) && !defined(WOLFSSL_NO_ML_KEM)
#define WOLFSSL_WC_ML_KEM_512
#endif
#if !defined(WOLFSSL_NO_ML_KEM_768) && !defined(WOLFSSL_NO_ML_KEM)
#define WOLFSSL_WC_ML_KEM_768
#endif
#if !defined(WOLFSSL_NO_ML_KEM_1024) && !defined(WOLFSSL_NO_ML_KEM)
#define WOLFSSL_WC_ML_KEM_1024
#endif

#ifdef WOLFSSL_WC_ML_KEM_512
#define WC_ML_KEM_512_K                     KYBER512_K
#define WC_ML_KEM_512_PUBLIC_KEY_SIZE       KYBER512_PUBLIC_KEY_SIZE
#define WC_ML_KEM_512_PRIVATE_KEY_SIZE      KYBER512_PRIVATE_KEY_SIZE
#define WC_ML_KEM_512_CIPHER_TEXT_SIZE      KYBER512_CIPHER_TEXT_SIZE
#define WC_ML_KEM_512_POLY_VEC_COMPRESSED_SZ \
        KYBER512_POLY_VEC_COMPRESSED_SZ
#endif

#ifdef WOLFSSL_WC_ML_KEM_768
#define WC_ML_KEM_768_K                     KYBER768_K
#define WC_ML_KEM_768_PUBLIC_KEY_SIZE       KYBER768_PUBLIC_KEY_SIZE
#define WC_ML_KEM_768_PRIVATE_KEY_SIZE      KYBER768_PRIVATE_KEY_SIZE
#define WC_ML_KEM_768_CIPHER_TEXT_SIZE      KYBER768_CIPHER_TEXT_SIZE
#define WC_ML_KEM_768_POLY_VEC_COMPRESSED_SZ \
        KYBER768_POLY_VEC_COMPRESSED_SZ
#endif

#ifdef WOLFSSL_WC_ML_KEM_1024
#define WC_ML_KEM_1024_K                    KYBER1024_K
#define WC_ML_KEM_1024_PUBLIC_KEY_SIZE      KYBER1024_PUBLIC_KEY_SIZE
#define WC_ML_KEM_1024_PRIVATE_KEY_SIZE     KYBER1024_PRIVATE_KEY_SIZE
#define WC_ML_KEM_1024_CIPHER_TEXT_SIZE     KYBER1024_CIPHER_TEXT_SIZE
#define WC_ML_KEM_1024_POLY_VEC_COMPRESSED_SZ \
        KYBER1024_POLY_VEC_COMPRESSED_SZ
#endif

#define WC_ML_KEM_MAX_K                     KYBER_MAX_K
#define WC_ML_KEM_MAX_PRIVATE_KEY_SIZE      KYBER_MAX_PRIVATE_KEY_SIZE
#define WC_ML_KEM_MAX_PUBLIC_KEY_SIZE       KYBER_MAX_PUBLIC_KEY_SIZE
#define WC_ML_KEM_MAX_CIPHER_TEXT_SIZE      KYBER_MAX_CIPHER_TEXT_SIZE

#define WC_ML_KEM_SYM_SZ            KYBER_SYM_SZ
#define WC_ML_KEM_SS_SZ             KYBER_SS_SZ
#define WC_ML_KEM_MAKEKEY_RAND_SZ   KYBER_MAKEKEY_RAND_SZ
#define WC_ML_KEM_ENC_RAND_SZ       KYBER_ENC_RAND_SZ
#define WC_ML_KEM_POLY_SIZE         KYBER_POLY_SIZE

#define MlKemKey            KyberKey

#define wc_MlKemKey_Init(key, type, heap, devId) \
        wc_KyberKey_Init(type, key, heap, devId)
#define wc_MlKemKey_Free                    wc_KyberKey_Free
#define wc_MlKemKey_MakeKey                 wc_KyberKey_MakeKey
#define wc_MlKemKey_MakeKeyWithRandom       wc_KyberKey_MakeKeyWithRandom
#define wc_MlKemKey_CipherTextSize          wc_KyberKey_CipherTextSize
#define wc_MlKemKey_SharedSecretSize        wc_KyberKey_SharedSecretSize
#define wc_MlKemKey_Encapsulate             wc_KyberKey_Encapsulate
#define wc_MlKemKey_EncapsulateWithRandom   wc_KyberKey_EncapsulateWithRandom
#define wc_MlKemKey_Decapsulate             wc_KyberKey_Encapsulate
#define wc_MlKemKey_DecodePrivateKey        wc_KyberKey_DecodePrivateKey
#define wc_MlKemKey_DecodePublicKey         wc_KyberKey_DecodePublicKey
#define wc_MlKemKey_PrivateKeySize          wc_KyberKey_PrivateKeySize
#define wc_MlKemKey_PublicKeySize           wc_KyberKey_PublicKeySize
#define wc_MlKemKey_EncodePrivateKey        wc_KyberKey_EncodePrivateKey
#define wc_MlKemKey_EncodePublicKey         wc_KyberKey_EncodePublicKey


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_HAVE_KYBER */

#endif /* WOLF_CRYPT_KYBER_H */

