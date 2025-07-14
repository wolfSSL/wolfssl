/* mlkem.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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
    \file wolfssl/wolfcrypt/mlkem.h
 */

#ifndef WOLF_CRYPT_MLKEM_H
#define WOLF_CRYPT_MLKEM_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef WOLFSSL_HAVE_MLKEM

/* Number of co-efficients in polynomial. */
#define MLKEM_N             256

/* Define algorithm type when not excluded. */
#ifndef WOLFSSL_NO_ML_KEM
    #if !defined(WOLFSSL_NO_ML_KEM_512)
        #define WOLFSSL_WC_ML_KEM_512
    #endif
    #if !defined(WOLFSSL_NO_ML_KEM_768)
        #define WOLFSSL_WC_ML_KEM_768
    #endif
    #if !defined(WOLFSSL_NO_ML_KEM_1024)
        #define WOLFSSL_WC_ML_KEM_1024
    #endif

    #if !defined(WOLFSSL_WC_ML_KEM_512) && !defined(WOLFSSL_WC_ML_KEM_768) && \
        !defined(WOLFSSL_WC_ML_KEM_1024)
        #error "No ML-KEM key size chosen."
    #endif
#endif

#ifdef WOLFSSL_MLKEM_KYBER
    #ifndef WOLFSSL_NO_KYBER512
        #define WOLFSSL_KYBER512
        #define WOLFSSL_WC_ML_KEM_512
    #endif
    #ifndef WOLFSSL_NO_KYBER768
        #define WOLFSSL_KYBER768
        #define WOLFSSL_WC_ML_KEM_768
    #endif
    #ifndef WOLFSSL_NO_KYBER1024
        #define WOLFSSL_KYBER1024
        #define WOLFSSL_WC_ML_KEM_1024
    #endif

    #if !defined(WOLFSSL_KYBER512) && !defined(WOLFSSL_KYBER768) && \
        !defined(WOLFSSL_KYBER1024)
        #error "No Kyber key size chosen."
    #endif
#endif

/* Size of a polynomial vector based on dimensions. */
#define MLKEM_POLY_VEC_SZ(k) ((k) * WC_ML_KEM_POLY_SIZE)
/* Size of a compressed polynomial based on bits per coefficient. */
#define MLKEM_POLY_COMPRESSED_SZ(b) ((b) * (MLKEM_N / 8))
/* Size of a compressed vector polynomial based on dimensions and bits per
 * coefficient. */
#define MLKEM_POLY_VEC_COMPRESSED_SZ(k, b) ((k) * ((b) * (MLKEM_N / 8)))

#ifdef WOLFSSL_WC_ML_KEM_512
#define WC_ML_KEM_512_K                     2
/* Size of a polynomial vector. */
#define WC_ML_KEM_512_POLY_VEC_SZ           MLKEM_POLY_VEC_SZ(WC_ML_KEM_512_K)
/* Size of a compressed polynomial based on bits per coefficient. */
#define WC_ML_KEM_512_POLY_COMPRESSED_SZ    MLKEM_POLY_COMPRESSED_SZ(4)
/* Size of a compressed vector polynomial based on dimensions and bits per
 * coefficient. */
#define WC_ML_KEM_512_POLY_VEC_COMPRESSED_SZ  \
    MLKEM_POLY_VEC_COMPRESSED_SZ(WC_ML_KEM_512_K, 10)

/* Public key size. */
#define WC_ML_KEM_512_PUBLIC_KEY_SIZE  \
    (WC_ML_KEM_512_POLY_VEC_SZ + WC_ML_KEM_SYM_SZ)
/* Private key size. */
#define WC_ML_KEM_512_PRIVATE_KEY_SIZE \
    (WC_ML_KEM_512_POLY_VEC_SZ + WC_ML_KEM_512_PUBLIC_KEY_SIZE + \
     2 * WC_ML_KEM_SYM_SZ)
/* Cipher text size. */
#define WC_ML_KEM_512_CIPHER_TEXT_SIZE \
    (WC_ML_KEM_512_POLY_VEC_COMPRESSED_SZ + WC_ML_KEM_512_POLY_COMPRESSED_SZ)
#endif

#ifdef WOLFSSL_WC_ML_KEM_768
#define WC_ML_KEM_768_K                     3

/* Size of a polynomial vector. */
#define WC_ML_KEM_768_POLY_VEC_SZ           MLKEM_POLY_VEC_SZ(WC_ML_KEM_768_K)
/* Size of a compressed polynomial based on bits per coefficient. */
#define WC_ML_KEM_768_POLY_COMPRESSED_SZ    MLKEM_POLY_COMPRESSED_SZ(4)
/* Size of a compressed vector polynomial based on dimensions and bits per
 * coefficient. */
#define WC_ML_KEM_768_POLY_VEC_COMPRESSED_SZ  \
    MLKEM_POLY_VEC_COMPRESSED_SZ(WC_ML_KEM_768_K, 10)

/* Public key size. */
#define WC_ML_KEM_768_PUBLIC_KEY_SIZE  \
    (WC_ML_KEM_768_POLY_VEC_SZ + WC_ML_KEM_SYM_SZ)
/* Private key size. */
#define WC_ML_KEM_768_PRIVATE_KEY_SIZE \
    (WC_ML_KEM_768_POLY_VEC_SZ + WC_ML_KEM_768_PUBLIC_KEY_SIZE + \
     2 * WC_ML_KEM_SYM_SZ)
/* Cipher text size. */
#define WC_ML_KEM_768_CIPHER_TEXT_SIZE \
    (WC_ML_KEM_768_POLY_VEC_COMPRESSED_SZ + WC_ML_KEM_768_POLY_COMPRESSED_SZ)
#endif

#ifdef WOLFSSL_WC_ML_KEM_1024
#define WC_ML_KEM_1024_K                    4

/* Size of a polynomial vector. */
#define WC_ML_KEM_1024_POLY_VEC_SZ          MLKEM_POLY_VEC_SZ(WC_ML_KEM_1024_K)
/* Size of a compressed polynomial based on bits per coefficient. */
#define WC_ML_KEM_1024_POLY_COMPRESSED_SZ   MLKEM_POLY_COMPRESSED_SZ(5)
/* Size of a compressed vector polynomial based on dimensions and bits per
 * coefficient. */
#define WC_ML_KEM_1024_POLY_VEC_COMPRESSED_SZ \
    MLKEM_POLY_VEC_COMPRESSED_SZ(WC_ML_KEM_1024_K, 11)

/* Public key size. */
#define WC_ML_KEM_1024_PUBLIC_KEY_SIZE  \
    (WC_ML_KEM_1024_POLY_VEC_SZ + WC_ML_KEM_SYM_SZ)
/* Private key size. */
#define WC_ML_KEM_1024_PRIVATE_KEY_SIZE \
    (WC_ML_KEM_1024_POLY_VEC_SZ + WC_ML_KEM_1024_PUBLIC_KEY_SIZE + \
     2 * WC_ML_KEM_SYM_SZ)
/* Cipher text size. */
#define WC_ML_KEM_1024_CIPHER_TEXT_SIZE \
    (WC_ML_KEM_1024_POLY_VEC_COMPRESSED_SZ + WC_ML_KEM_1024_POLY_COMPRESSED_SZ)
#endif

#ifndef WC_ML_KEM_MAX_K
#ifdef WOLFSSL_WC_ML_KEM_1024
#define WC_ML_KEM_MAX_K                 WC_ML_KEM_1024_K
#define WC_ML_KEM_MAX_PRIVATE_KEY_SIZE  WC_ML_KEM_1024_PRIVATE_KEY_SIZE
#define WC_ML_KEM_MAX_PUBLIC_KEY_SIZE   WC_ML_KEM_1024_PUBLIC_KEY_SIZE
#define WC_ML_KEM_MAX_CIPHER_TEXT_SIZE  WC_ML_KEM_1024_CIPHER_TEXT_SIZE
#elif defined(WOLFSSL_WC_ML_KEM_768)
#define WC_ML_KEM_MAX_K                 WC_ML_KEM_768_K
#define WC_ML_KEM_MAX_PRIVATE_KEY_SIZE  WC_ML_KEM_768_PRIVATE_KEY_SIZE
#define WC_ML_KEM_MAX_PUBLIC_KEY_SIZE   WC_ML_KEM_768_PUBLIC_KEY_SIZE
#define WC_ML_KEM_MAX_CIPHER_TEXT_SIZE  WC_ML_KEM_768_CIPHER_TEXT_SIZE
#elif defined(WOLFSSL_WC_ML_KEM_512)
#define WC_ML_KEM_MAX_K                 WC_ML_KEM_512_K
#define WC_ML_KEM_MAX_PRIVATE_KEY_SIZE  WC_ML_KEM_512_PRIVATE_KEY_SIZE
#define WC_ML_KEM_MAX_PUBLIC_KEY_SIZE   WC_ML_KEM_512_PUBLIC_KEY_SIZE
#define WC_ML_KEM_MAX_CIPHER_TEXT_SIZE  WC_ML_KEM_512_CIPHER_TEXT_SIZE
#endif
#endif /* WC_ML_KEM_MAX_K */

#define KYBER_N             MLKEM_N

/* Size of a polynomial vector based on dimensions. */
#define KYBER_POLY_VEC_SZ(k) ((k) * KYBER_POLY_SIZE)
/* Size of a compressed polynomial based on bits per coefficient. */
#define KYBER_POLY_COMPRESSED_SZ(b) ((b) * (KYBER_N / 8))
/* Size of a compressed vector polynomial based on dimensions and bits per
 * coefficient. */
#define KYBER_POLY_VEC_COMPRESSED_SZ(k, b) ((k) * ((b) * (KYBER_N / 8)))


/* Kyber-512 parameters */
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

/* Kyber-768 parameters */
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

/* Kyber-1024 parameters */
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
#elif defined(WOLFSSL_KYBER512)
#define KYBER_MAX_K                 KYBER512_K
#define KYBER_MAX_PRIVATE_KEY_SIZE  KYBER512_PRIVATE_KEY_SIZE
#define KYBER_MAX_PUBLIC_KEY_SIZE   KYBER512_PUBLIC_KEY_SIZE
#define KYBER_MAX_CIPHER_TEXT_SIZE  KYBER512_CIPHER_TEXT_SIZE
#endif

#define KYBER_SYM_SZ            WC_ML_KEM_SYM_SZ
#define KYBER_SS_SZ             WC_ML_KEM_SS_SZ
#define KYBER_MAKEKEY_RAND_SZ   WC_ML_KEM_MAKEKEY_RAND_SZ
#define KYBER_ENC_RAND_SZ       WC_ML_KEM_ENC_RAND_SZ
#define KYBER_POLY_SIZE         WC_ML_KEM_POLY_SIZE


enum {
    /* Types of Kyber keys. */
    WC_ML_KEM_512  = 0,
    WC_ML_KEM_768  = 1,
    WC_ML_KEM_1024 = 2,

    MLKEM_KYBER = 0x10,
    KYBER512  = 0 | MLKEM_KYBER,
    KYBER768  = 1 | MLKEM_KYBER,
    KYBER1024 = 2 | MLKEM_KYBER,

    KYBER_LEVEL1 = KYBER512,
    KYBER_LEVEL3 = KYBER768,
    KYBER_LEVEL5 = KYBER1024,

    /* Symmetric data size. */
    WC_ML_KEM_SYM_SZ            = 32,
    /* Shared secret size. */
    WC_ML_KEM_SS_SZ             = 32,
    /* Size of random required for making a key. */
    WC_ML_KEM_MAKEKEY_RAND_SZ   = 2 * WC_ML_KEM_SYM_SZ,
    /* Size of random required for encapsulation. */
    WC_ML_KEM_ENC_RAND_SZ       = WC_ML_KEM_SYM_SZ,

    /* Encoded polynomial size. */
    WC_ML_KEM_POLY_SIZE         = 384,
};


/* Different structures for different implementations. */
typedef struct MlKemKey MlKemKey;


#ifdef __cplusplus
    extern "C" {
#endif

WOLFSSL_API int wc_MlKemKey_Init(MlKemKey* key, int type, void* heap,
    int devId);
WOLFSSL_API int wc_MlKemKey_Free(MlKemKey* key);

WOLFSSL_API int wc_MlKemKey_MakeKey(MlKemKey* key, WC_RNG* rng);
WOLFSSL_API int wc_MlKemKey_MakeKeyWithRandom(MlKemKey* key,
    const unsigned char* rand, int len);

WOLFSSL_API int wc_MlKemKey_CipherTextSize(MlKemKey* key, word32* len);
WOLFSSL_API int wc_MlKemKey_SharedSecretSize(MlKemKey* key, word32* len);

WOLFSSL_API int wc_MlKemKey_Encapsulate(MlKemKey* key, unsigned char* ct,
    unsigned char* ss, WC_RNG* rng);
WOLFSSL_API int wc_MlKemKey_EncapsulateWithRandom(MlKemKey* key,
    unsigned char* ct, unsigned char* ss, const unsigned char* rand, int len);
WOLFSSL_API int wc_MlKemKey_Decapsulate(MlKemKey* key, unsigned char* ss,
    const unsigned char* ct, word32 len);

WOLFSSL_API int wc_MlKemKey_DecodePrivateKey(MlKemKey* key,
    const unsigned char* in, word32 len);
WOLFSSL_API int wc_MlKemKey_DecodePublicKey(MlKemKey* key,
    const unsigned char* in, word32 len);

WOLFSSL_API int wc_MlKemKey_PrivateKeySize(MlKemKey* key, word32* len);
WOLFSSL_API int wc_MlKemKey_PublicKeySize(MlKemKey* key, word32* len);
WOLFSSL_API int wc_MlKemKey_EncodePrivateKey(MlKemKey* key, unsigned char* out,
    word32 len);
WOLFSSL_API int wc_MlKemKey_EncodePublicKey(MlKemKey* key, unsigned char* out,
    word32 len);


#define KyberKey            MlKemKey

#define wc_KyberKey_Init(type, key, heap, devId) \
        wc_MlKemKey_Init(key, type, heap, devId)
#define wc_KyberKey_Free                    wc_MlKemKey_Free
#define wc_KyberKey_MakeKey                 wc_MlKemKey_MakeKey
#define wc_KyberKey_MakeKeyWithRandom       wc_MlKemKey_MakeKeyWithRandom
#define wc_KyberKey_CipherTextSize          wc_MlKemKey_CipherTextSize
#define wc_KyberKey_SharedSecretSize        wc_MlKemKey_SharedSecretSize
#define wc_KyberKey_Encapsulate             wc_MlKemKey_Encapsulate
#define wc_KyberKey_EncapsulateWithRandom   wc_MlKemKey_EncapsulateWithRandom
#define wc_KyberKey_Decapsulate             wc_MlKemKey_Decapsulate
#define wc_KyberKey_DecodePrivateKey        wc_MlKemKey_DecodePrivateKey
#define wc_KyberKey_DecodePublicKey         wc_MlKemKey_DecodePublicKey
#define wc_KyberKey_PrivateKeySize          wc_MlKemKey_PrivateKeySize
#define wc_KyberKey_PublicKeySize           wc_MlKemKey_PublicKeySize
#define wc_KyberKey_EncodePrivateKey        wc_MlKemKey_EncodePrivateKey
#define wc_KyberKey_EncodePublicKey         wc_MlKemKey_EncodePublicKey


#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_HAVE_MLKEM */

#endif /* WOLF_CRYPT_MLKEM_H */

