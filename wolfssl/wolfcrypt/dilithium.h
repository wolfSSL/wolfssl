/* dilithium.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
    \file wolfssl/wolfcrypt/dilithium.h
*/

/* Interfaces for Dilithium NIST Level 1 (Dilithium512) and Dilithium NIST Level 5
 * (Dilithium1024). */

#ifndef WOLF_CRYPT_DILITHIUM_H
#define WOLF_CRYPT_DILITHIUM_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#if defined(HAVE_DILITHIUM)

#ifdef HAVE_LIBOQS
#include <oqs/oqs.h>
#include <wolfssl/wolfcrypt/port/liboqs/liboqs.h>
#endif

#if defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) && \
        defined(WOLFSSL_DILITHIUM_NO_SIGN) && \
        !defined(WOLFSSL_DILITHIUM_NO_VERIFY) && \
        !defined(WOLFSSL_DILITHIUM_VERIFY_ONLY)
    #define WOLFSSL_DILITHIUM_VERIFY_ONLY
#endif
#ifdef WOLFSSL_DILITHIUM_VERIFY_ONLY
    #ifndef WOLFSSL_DILITHIUM_NO_MAKE_KEY
        #define WOLFSSL_DILITHIUM_NO_MAKE_KEY
    #endif
    #ifndef WOLFSSL_DILITHIUM_NO_SIGN
        #define WOLFSSL_DILITHIUM_NO_SIGN
    #endif
#endif

#if !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) || \
        !defined(WOLFSSL_DILITHIUM_NO_VERIFY)
    #define WOLFSSL_DILITHIUM_PUBLIC_KEY
#endif
#if !defined(WOLFSSL_DILITHIUM_NO_MAKE_KEY) || \
        !defined(WOLFSSL_DILITHIUM_NO_SIGN)
    #define WOLFSSL_DILITHIUM_PRIVATE_KEY
#endif

#if defined(WOLFSSL_DILITHIUM_PUBLIC_KEY) && \
        defined(WOLFSSL_DILITHIUM_PRIVATE_KEY) && \
        !defined(WOLFSSL_DILITHIUM_NO_CHECK_KEY) && \
        !defined(WOLFSSL_DILITHIUM_CHECK_KEY)
    #define WOLFSSL_DILITHIUM_CHECK_KEY
#endif

#ifdef WOLFSSL_WC_DILITHIUM
    #include <wolfssl/wolfcrypt/sha3.h>
#ifndef WOLFSSL_DILITHIUM_VERIFY_ONLY
    #include <wolfssl/wolfcrypt/random.h>
#endif
#endif

#if defined(WC_DILITHIUM_CACHE_PRIV_VECTORS) && \
        !defined(WC_DILITHIUM_CACHE_MATRIX_A)
    #define WC_DILITHIUM_CACHE_MATRIX_A
#endif
#if defined(WC_DILITHIUM_CACHE_PUB_VECTORS) && \
        !defined(WC_DILITHIUM_CACHE_MATRIX_A)
    #define WC_DILITHIUM_CACHE_MATRIX_A
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* Macros Definitions */

#ifdef WOLFSSL_WC_DILITHIUM

#ifndef WOLFSSL_DILITHIUM_ALIGNMENT
    #if defined(__arch64__)
        #define WOLFSSL_DILITHIUM_ALIGNMENT     8
    #elif defined(__arm__)
        #define WOLFSSL_DILITHIUM_ALIGNMENT     4
    #elif !defined(WOLFSSL_AESNI) && defined(WOLFSSL_GENERAL_ALIGNMENT)
        #define WOLFSSL_DILITHIUM_ALIGNMENT     WOLFSSL_GENERAL_ALIGNMENT
    #else
        #define WOLFSSL_DILITHIUM_ALIGNMENT     8
    #endif
#endif /* WOLFSSL_DILITHIUM_ALIGNMENT */

#define DILITHIUM_LEVEL2_KEY_SIZE       2560
#define DILITHIUM_LEVEL2_SIG_SIZE       2420
#define DILITHIUM_LEVEL2_PUB_KEY_SIZE   1312
#define DILITHIUM_LEVEL2_PRV_KEY_SIZE   \
    (DILITHIUM_LEVEL2_PUB_KEY_SIZE + DILITHIUM_LEVEL2_KEY_SIZE)
/* Buffer sizes large enough to store exported DER encoded keys */
#define DILITHIUM_LEVEL2_PUB_KEY_DER_SIZE 1334
#define DILITHIUM_LEVEL2_PRV_KEY_DER_SIZE 2588

#define DILITHIUM_LEVEL3_KEY_SIZE       4032
#define DILITHIUM_LEVEL3_SIG_SIZE       3309
#define DILITHIUM_LEVEL3_PUB_KEY_SIZE   1952
#define DILITHIUM_LEVEL3_PRV_KEY_SIZE   \
    (DILITHIUM_LEVEL3_PUB_KEY_SIZE + DILITHIUM_LEVEL3_KEY_SIZE)
/* Buffer sizes large enough to store exported DER encoded keys */
#define DILITHIUM_LEVEL3_PUB_KEY_DER_SIZE 1974
#define DILITHIUM_LEVEL3_PRV_KEY_DER_SIZE 4060


#define DILITHIUM_LEVEL5_KEY_SIZE       4896
#define DILITHIUM_LEVEL5_SIG_SIZE       4627
#define DILITHIUM_LEVEL5_PUB_KEY_SIZE   2592
#define DILITHIUM_LEVEL5_PRV_KEY_SIZE   \
    (DILITHIUM_LEVEL5_PUB_KEY_SIZE + DILITHIUM_LEVEL5_KEY_SIZE)
/* Buffer sizes large enough to store exported DER encoded keys */
#define DILITHIUM_LEVEL5_PUB_KEY_DER_SIZE 2614
#define DILITHIUM_LEVEL5_PRV_KEY_DER_SIZE 4924

#define ML_DSA_LEVEL2_KEY_SIZE          2560
#define ML_DSA_LEVEL2_SIG_SIZE          2420
#define ML_DSA_LEVEL2_PUB_KEY_SIZE      1312
#define ML_DSA_LEVEL2_PRV_KEY_SIZE   \
    (ML_DSA_LEVEL2_PUB_KEY_SIZE + ML_DSA_LEVEL2_KEY_SIZE)
/* Buffer sizes large enough to store exported DER encoded keys */
#define ML_DSA_LEVEL2_PUB_KEY_DER_SIZE DILITHIUM_LEVEL2_PUB_KEY_DER_SIZE
#define ML_DSA_LEVEL2_PRV_KEY_DER_SIZE DILITHIUM_LEVEL2_PRV_KEY_DER_SIZE

#define ML_DSA_LEVEL3_KEY_SIZE          4032
#define ML_DSA_LEVEL3_SIG_SIZE          3309
#define ML_DSA_LEVEL3_PUB_KEY_SIZE      1952
#define ML_DSA_LEVEL3_PRV_KEY_SIZE   \
    (ML_DSA_LEVEL3_PUB_KEY_SIZE + ML_DSA_LEVEL3_KEY_SIZE)
/* Buffer sizes large enough to store exported DER encoded keys */
#define ML_DSA_LEVEL3_PUB_KEY_DER_SIZE DILITHIUM_LEVEL3_PUB_KEY_DER_SIZE
#define ML_DSA_LEVEL3_PRV_KEY_DER_SIZE DILITHIUM_LEVEL3_PRV_KEY_DER_SIZE

#define ML_DSA_LEVEL5_KEY_SIZE          4896
#define ML_DSA_LEVEL5_SIG_SIZE          4627
#define ML_DSA_LEVEL5_PUB_KEY_SIZE      2592
#define ML_DSA_LEVEL5_PRV_KEY_SIZE   \
    (ML_DSA_LEVEL5_PUB_KEY_SIZE + ML_DSA_LEVEL5_KEY_SIZE)
/* Buffer sizes large enough to store exported DER encoded keys */
#define ML_DSA_LEVEL5_PUB_KEY_DER_SIZE DILITHIUM_LEVEL5_PUB_KEY_DER_SIZE
#define ML_DSA_LEVEL5_PRV_KEY_DER_SIZE DILITHIUM_LEVEL5_PRV_KEY_DER_SIZE



/* Modulus. */
#define DILITHIUM_Q                     0x7fe001
/* Number of bits in modulus. */
#define DILITHIUM_Q_BITS                23
/* Number of elements in polynomial. */
#define DILITHIUM_N                     256

/* Number of dropped bits. */
#define DILITHIUM_D                     13
/* Maximum value of dropped bits. */
#define DILITHIUM_D_MAX                 (1 << DILITHIUM_D)
/* Half maximum value. */
#define DILITHIUM_D_MAX_HALF            (1 << (DILITHIUM_D - 1))
/* Number of undropped bits. */
#define DILITHIUM_U                     (DILITHIUM_Q_BITS - DILITHIUM_D)

/* Bits in coefficient range of y, GAMMA1, of 2^17 is 17. */
#define DILITHIUM_GAMMA1_BITS_17        17
/* Coefficient range of y, GAMMA1, of 2^17. */
#define DILITHIUM_GAMMA1_17             (1 << 17)
/* # encoding bits of y is GAMMA1 + 1. */
#define DILITHIUM_GAMMA1_17_ENC_BITS    18
/* Coefficient range of y, GAMMA1, of 2^17. */
/* Bits in coefficient range of y, GAMMA1, of 2^19 is 19. */
#define DILITHIUM_GAMMA1_BITS_19        19
/* Coefficient range of y, GAMMA1, of 2^19. */
#define DILITHIUM_GAMMA1_19             (1 << 19)
/* # encoding bits of y is GAMMA1 + 1. */
#define DILITHIUM_GAMMA1_19_ENC_BITS    20

/* Low-order rounding range, GAMMA2, is Q divided by 88. */
#define DILITHIUM_Q_LOW_88              ((DILITHIUM_Q - 1) / 88)
/* Absolute low-order rounding range, GAMMA2, is Q divided by 88. */
#define DILITHIUM_Q_LOW_88_2            (((DILITHIUM_Q - 1) / 88) * 2)
/* # encoding bits of w1 when range is 88. */
#define DILITHIUM_Q_HI_88_ENC_BITS      6
/* Low-order rounding range, GAMMA2, is Q divided by 32. */
#define DILITHIUM_Q_LOW_32              ((DILITHIUM_Q - 1) / 32)
/* Absolute low-order rounding range, GAMMA2, is Q divided by 32. */
#define DILITHIUM_Q_LOW_32_2            (((DILITHIUM_Q - 1) / 32) * 2)
/* # encoding bits of w1 when range is 32. */
#define DILITHIUM_Q_HI_32_ENC_BITS      4

/* Private key range, eta, of 2. */
#define DILITHIUM_ETA_2                 2
/* Bits needed to encode values in range -2..2 as a positive number. */
#define DILITHIUM_ETA_2_BITS            3
/* Extract count of valid values. */
#define DILITHIUM_ETA_2_MOD             15
/* Private key range, eta, of 4. */
#define DILITHIUM_ETA_4                 4
/* Bits needed to encode values in range -4..4 as a positive number. */
#define DILITHIUM_ETA_4_BITS            4
/* Extract count of valid values. */
#define DILITHIUM_ETA_4_MOD             9

/* Number of bytes in a polynomial in memory. */
#define DILITHIUM_POLY_SIZE             (DILITHIUM_N * sizeof(sword32))

#ifndef WOLFSSL_NO_ML_DSA_44

/* Fist dimension of A, k, for ML-DSA-44. */
#define PARAMS_ML_DSA_44_K              4
/* Second dimension of A, l, for ML-DSA-44. */
#define PARAMS_ML_DSA_44_L              4
/* Private key range, ETA, for ML-DSA-44. */
#define PARAMS_ML_DSA_44_ETA            DILITHIUM_ETA_2
/* Number of bits in private key for ML-DSA-44. */
#define PARAMS_ML_DSA_44_ETA_BITS       DILITHIUM_ETA_2_BITS
/* Collision strength of c-tilde, LAMBDA, in bits for ML-DSA-44. */
#define PARAMS_ML_DSA_44_LAMBDA         128
/* # +/-1's in polynomial c, TAU, for ML-DSA-44. */
#define PARAMS_ML_DSA_44_TAU            39
/* BETA = TAU * ETA for ML-DSA-44. */
#define PARAMS_ML_DSA_44_BETA           \
    (PARAMS_ML_DSA_44_TAU * PARAMS_ML_DSA_44_ETA)
/* Max # 1's in the hint h, OMEGA, for ML-DSA-44. */
#define PARAMS_ML_DSA_44_OMEGA          80
/* Bits in coefficient range of y, GAMMA1, for ML-DSA-44. */
#define PARAMS_ML_DSA_44_GAMMA1_BITS    DILITHIUM_GAMMA1_BITS_17
/* Ccoefficient range of y, GAMMA1, for ML-DSA-44. */
#define PARAMS_ML_DSA_44_GAMMA1         (1 << PARAMS_ML_DSA_44_GAMMA1_BITS)
/* Low-order rounding range, GAMMA2, for ML-DSA-44. */
#define PARAMS_ML_DSA_44_GAMMA2         DILITHIUM_Q_LOW_88
/* Bits in high-order rounding range, GAMMA2, for ML-DSA-44. */
#define PARAMS_ML_DSA_44_GAMMA2_HI_BITS 6
/* Encoding size of w1 in bytes for ML-DSA-44.
 * K * N / 8 * 6 - 6 bits as max value is 43 in high bits. */
#define PARAMS_ML_DSA_44_W1_ENC_SZ      \
    (PARAMS_ML_DSA_44_K * DILITHIUM_N / 8 * PARAMS_ML_DSA_44_GAMMA2_HI_BITS)
/* Size of memory used for matrix a in bytes for ML-DSA-44. */
#define PARAMS_ML_DSA_44_A_SIZE         \
    (PARAMS_ML_DSA_44_K * PARAMS_ML_DSA_44_L * DILITHIUM_POLY_SIZE)
/* Size of memory used for vector s1 in bytes for ML-DSA-44. */
#define PARAMS_ML_DSA_44_S1_SIZE        \
    (PARAMS_ML_DSA_44_L * DILITHIUM_POLY_SIZE)
/* Encoding size of s1 in bytes for ML-DSA-44. */
#define PARAMS_ML_DSA_44_S1_ENC_SIZE    \
    (PARAMS_ML_DSA_44_S1_SIZE / sizeof(sword32) * PARAMS_ML_DSA_44_ETA_BITS / 8)
/* Size of memory used for vector s2 in bytes for ML-DSA-44. */
#define PARAMS_ML_DSA_44_S2_SIZE        \
    (PARAMS_ML_DSA_44_K * DILITHIUM_POLY_SIZE)
/* Encoding size of s2 in bytes for ML-DSA-44. */
#define PARAMS_ML_DSA_44_S2_ENC_SIZE    \
    (PARAMS_ML_DSA_44_S2_SIZE / sizeof(sword32) * PARAMS_ML_DSA_44_ETA_BITS / 8)
/* Encoding size of z in bytes for ML-DSA-44. */
#define PARAMS_ML_DSA_44_Z_ENC_SIZE     \
    (PARAMS_ML_DSA_44_S1_SIZE / sizeof(sword32) / 8 * \
     (PARAMS_ML_DSA_44_GAMMA1_BITS + 1))
/* Encoding size of public key in bytes for ML-DSA-44. */
#define PARAMS_ML_DSA_44_PK_SIZE        \
    (DILITHIUM_PUB_SEED_SZ + PARAMS_ML_DSA_44_K * DILITHIUM_N * DILITHIUM_U / 8)
/* Encoding size of signature in bytes for ML-DSA-44. */
#define PARAMS_ML_DSA_44_SIG_SIZE       \
    ((PARAMS_ML_DSA_44_LAMBDA / 4) +    \
     PARAMS_ML_DSA_44_L * DILITHIUM_N/8 * (PARAMS_ML_DSA_44_GAMMA1_BITS + 1) + \
     PARAMS_ML_DSA_44_OMEGA + PARAMS_ML_DSA_44_K)

#endif /* WOLFSSL_NO_ML_DSA_44 */

#ifndef WOLFSSL_NO_ML_DSA_65

/* Fist dimension of A, k, for ML-DSA-65. */
#define PARAMS_ML_DSA_65_K              6
/* Second dimension of A, l, for ML-DSA-65. */
#define PARAMS_ML_DSA_65_L              5
/* Private key range, ETA, for ML-DSA-65. */
#define PARAMS_ML_DSA_65_ETA            DILITHIUM_ETA_4
/* Number of bits in private key for ML-DSA-65. */
#define PARAMS_ML_DSA_65_ETA_BITS       DILITHIUM_ETA_4_BITS
/* Collision strength of c-tilde, LAMBDA, in bits for ML-DSA-65. */
#define PARAMS_ML_DSA_65_LAMBDA         192
/* # +/-1's in polynomial c, TAU, for ML-DSA-65. */
#define PARAMS_ML_DSA_65_TAU            49
/* BETA = TAU * ETA for ML-DSA-65. */
#define PARAMS_ML_DSA_65_BETA           \
    (PARAMS_ML_DSA_65_TAU * PARAMS_ML_DSA_65_ETA)
/* Max # 1's in the hint h, OMEGA, for ML-DSA-65. */
#define PARAMS_ML_DSA_65_OMEGA          55
/* Bits in coefficient range of y, GAMMA1, for ML-DSA-65. */
#define PARAMS_ML_DSA_65_GAMMA1_BITS    DILITHIUM_GAMMA1_BITS_19
/* Ccoefficient range of y, GAMMA1, for ML-DSA-65. */
#define PARAMS_ML_DSA_65_GAMMA1         (1 << PARAMS_ML_DSA_65_GAMMA1_BITS)
/* Low-order rounding range, GAMMA2, for ML-DSA-65. */
#define PARAMS_ML_DSA_65_GAMMA2         DILITHIUM_Q_LOW_32
/* Bits in high-order rounding range, GAMMA2, for ML-DSA-65. */
#define PARAMS_ML_DSA_65_GAMMA2_HI_BITS 4
/* Encoding size of w1 in bytes for ML-DSA-65.
 * K * N / 8 * 4 - 4 bits as max value is 15 in high bits. */
#define PARAMS_ML_DSA_65_W1_ENC_SZ      \
    (PARAMS_ML_DSA_65_K * DILITHIUM_N / 8 * PARAMS_ML_DSA_65_GAMMA2_HI_BITS)
/* Size of memory used for matrix a in bytes for ML-DSA-65. */
#define PARAMS_ML_DSA_65_A_SIZE         \
    (PARAMS_ML_DSA_65_K * PARAMS_ML_DSA_65_L * DILITHIUM_POLY_SIZE)
/* Size of memory used for vector s1 in bytes for ML-DSA-65. */
#define PARAMS_ML_DSA_65_S1_SIZE        \
    (PARAMS_ML_DSA_65_L * DILITHIUM_POLY_SIZE)
/* Encoding size of s1 in bytes for ML-DSA-65. */
#define PARAMS_ML_DSA_65_S1_ENC_SIZE    \
    (PARAMS_ML_DSA_65_S1_SIZE / sizeof(sword32) * PARAMS_ML_DSA_65_ETA_BITS / 8)
/* Size of memory used for vector s2 in bytes for ML-DSA-65. */
#define PARAMS_ML_DSA_65_S2_SIZE        \
    (PARAMS_ML_DSA_65_K * DILITHIUM_POLY_SIZE)
/* Encoding size of s2 in bytes for ML-DSA-65. */
#define PARAMS_ML_DSA_65_S2_ENC_SIZE    \
    (PARAMS_ML_DSA_65_S2_SIZE / sizeof(sword32) * PARAMS_ML_DSA_65_ETA_BITS / 8)
/* Encoding size of z in bytes for ML-DSA-65. */
#define PARAMS_ML_DSA_65_Z_ENC_SIZE     \
    (PARAMS_ML_DSA_65_S1_SIZE / sizeof(sword32) / 8 * \
     (PARAMS_ML_DSA_65_GAMMA1_BITS + 1))
/* Encoding size of public key in bytes for ML-DSA-65. */
#define PARAMS_ML_DSA_65_PK_SIZE        \
    (DILITHIUM_PUB_SEED_SZ + PARAMS_ML_DSA_65_K * DILITHIUM_N * DILITHIUM_U / 8)
/* Encoding size of signature in bytes for ML-DSA-65. */
#define PARAMS_ML_DSA_65_SIG_SIZE       \
    ((PARAMS_ML_DSA_65_LAMBDA / 4) +    \
     PARAMS_ML_DSA_65_L * DILITHIUM_N/8 * (PARAMS_ML_DSA_65_GAMMA1_BITS + 1) + \
     PARAMS_ML_DSA_65_OMEGA + PARAMS_ML_DSA_65_K)

#endif /* WOLFSSL_NO_ML_DSA_65 */

#ifndef WOLFSSL_NO_ML_DSA_87

/* Fist dimension of A, k, for ML-DSA-87. */
#define PARAMS_ML_DSA_87_K              8
/* Second dimension of A, l, for ML-DSA-87. */
#define PARAMS_ML_DSA_87_L              7
/* Private key range, ETA, for ML-DSA-87. */
#define PARAMS_ML_DSA_87_ETA            DILITHIUM_ETA_2
/* Number of bits in private key for ML-DSA-87. */
#define PARAMS_ML_DSA_87_ETA_BITS       DILITHIUM_ETA_2_BITS
/* Collision strength of c-tilde, LAMBDA, in bits for ML-DSA-87. */
#define PARAMS_ML_DSA_87_LAMBDA         256
/* # +/-1's in polynomial c, TAU, for ML-DSA-87. */
#define PARAMS_ML_DSA_87_TAU            60
/* BETA = TAU * ETA for ML-DSA-87. */
#define PARAMS_ML_DSA_87_BETA           \
    (PARAMS_ML_DSA_87_TAU * PARAMS_ML_DSA_87_ETA)
/* Max # 1's in the hint h, OMEGA, for ML-DSA-87. */
#define PARAMS_ML_DSA_87_OMEGA          75
/* Bits in coefficient range of y, GAMMA1, for ML-DSA-87. */
#define PARAMS_ML_DSA_87_GAMMA1_BITS    DILITHIUM_GAMMA1_BITS_19
/* Ccoefficient range of y, GAMMA1, for ML-DSA-87. */
#define PARAMS_ML_DSA_87_GAMMA1         (1 << PARAMS_ML_DSA_87_GAMMA1_BITS)
/* Low-order rounding range, GAMMA2, for ML-DSA-87. */
#define PARAMS_ML_DSA_87_GAMMA2         DILITHIUM_Q_LOW_32
/* Bits in high-order rounding range, GAMMA2, for ML-DSA-87. */
#define PARAMS_ML_DSA_87_GAMMA2_HI_BITS 4
/* Encoding size of w1 in bytes for ML-DSA-87.
 * K * N / 8 * 4 - 4 bits as max value is 15 in high bits. */
#define PARAMS_ML_DSA_87_W1_ENC_SZ      \
    (PARAMS_ML_DSA_87_K * DILITHIUM_N / 8 * PARAMS_ML_DSA_87_GAMMA2_HI_BITS)
/* Size of memory used for matrix A in bytes for ML-DSA-87. */
#define PARAMS_ML_DSA_87_A_SIZE         \
    (PARAMS_ML_DSA_87_K * PARAMS_ML_DSA_87_L * DILITHIUM_POLY_SIZE)
#define PARAMS_ML_DSA_87_S_SIZE         4
/* Size of memory used for vector s1 in bytes for ML-DSA-87. */
#define PARAMS_ML_DSA_87_S1_SIZE        \
    (PARAMS_ML_DSA_87_L * DILITHIUM_POLY_SIZE)
/* Encoding size of s1 in bytes for ML-DSA-87. */
#define PARAMS_ML_DSA_87_S1_ENC_SIZE    \
    (PARAMS_ML_DSA_87_S1_SIZE / sizeof(sword32) * PARAMS_ML_DSA_87_ETA_BITS / 8)
/* Size of memory used for vector s2 in bytes for ML-DSA-87. */
#define PARAMS_ML_DSA_87_S2_SIZE        \
    (PARAMS_ML_DSA_87_K * DILITHIUM_POLY_SIZE)
/* Encoding size of s2 in bytes for ML-DSA-87. */
#define PARAMS_ML_DSA_87_S2_ENC_SIZE    \
    (PARAMS_ML_DSA_87_S2_SIZE / sizeof(sword32) * PARAMS_ML_DSA_87_ETA_BITS / 8)
/* Encoding size of z in bytes for ML-DSA-87. */
#define PARAMS_ML_DSA_87_Z_ENC_SIZE     \
    (PARAMS_ML_DSA_87_S1_SIZE / sizeof(sword32) / 8 * \
     (PARAMS_ML_DSA_87_GAMMA1_BITS + 1))
/* Encoding size of public key in bytes for ML-DSA-87. */
#define PARAMS_ML_DSA_87_PK_SIZE        \
    (DILITHIUM_PUB_SEED_SZ + PARAMS_ML_DSA_87_K * DILITHIUM_N * DILITHIUM_U / 8)
/* Encoding size of signature in bytes for ML-DSA-87. */
#define PARAMS_ML_DSA_87_SIG_SIZE       \
    ((PARAMS_ML_DSA_87_LAMBDA / 4) +    \
     PARAMS_ML_DSA_87_L * DILITHIUM_N/8 * (PARAMS_ML_DSA_87_GAMMA1_BITS + 1) + \
     PARAMS_ML_DSA_87_OMEGA + PARAMS_ML_DSA_87_K)

#endif /* WOLFSSL_NO_ML_DSA_87 */


#ifndef WOLFSSL_NO_ML_DSA_87

#define DILITHIUM_MAX_W1_ENC_SZ         PARAMS_ML_DSA_87_W1_ENC_SZ
/* Maximum collision strength of c-tilde in bytes. */
#define DILITHIUM_MAX_LAMBDA            PARAMS_ML_DSA_87_LAMBDA

/* Maximum count of elements of a vector with dimension K. */
#define DILITHIUM_MAX_K_VECTOR_COUNT     \
    (PARAMS_ML_DSA_87_K * DILITHIUM_N)
/* Maximum count of elements of a vector with dimension L. */
#define DILITHIUM_MAX_L_VECTOR_COUNT     \
    (PARAMS_ML_DSA_87_L * DILITHIUM_N)
/* Maximum count of elements of a matrix with dimension KxL. */
#define DILITHIUM_MAX_MATRIX_COUNT        \
    (PARAMS_ML_DSA_87_K * PARAMS_ML_DSA_87_L * DILITHIUM_N)

#elif !defined(WOLFSSL_NO_ML_DSA_65)

/* Maximum w1 encoding size in bytes. */
#define DILITHIUM_MAX_W1_ENC_SZ         PARAMS_ML_DSA_65_W1_ENC_SZ
/* Maximum collision strength of c-tilde in bytes. */
#define DILITHIUM_MAX_LAMBDA            PARAMS_ML_DSA_65_LAMBDA

/* Maximum count of elements of a vector with dimension K. */
#define DILITHIUM_MAX_K_VECTOR_COUNT     \
    (PARAMS_ML_DSA_65_K * DILITHIUM_N)
/* Maximum count of elements of a vector with dimension L. */
#define DILITHIUM_MAX_L_VECTOR_COUNT     \
    (PARAMS_ML_DSA_65_L * DILITHIUM_N)
/* Maximum count of elements of a matrix with dimension KxL. */
#define DILITHIUM_MAX_MATRIX_COUNT        \
    (PARAMS_ML_DSA_65_K * PARAMS_ML_DSA_65_L * DILITHIUM_N)

#else

/* Maximum w1 encoding size in bytes. */
#define DILITHIUM_MAX_W1_ENC_SZ         PARAMS_ML_DSA_44_W1_ENC_SZ
/* Maximum collision strength of c-tilde in bytes. */
#define DILITHIUM_MAX_LAMBDA            PARAMS_ML_DSA_44_LAMBDA

/* Maximum count of elements of a vector with dimension K. */
#define DILITHIUM_MAX_K_VECTOR_COUNT     \
    (PARAMS_ML_DSA_44_K * DILITHIUM_N)
/* Maximum count of elements of a vector with dimension L. */
#define DILITHIUM_MAX_L_VECTOR_COUNT     \
    (PARAMS_ML_DSA_44_L * DILITHIUM_N)
/* Maximum count of elements of a matrix with dimension KxL. */
#define DILITHIUM_MAX_MATRIX_COUNT        \
    (PARAMS_ML_DSA_44_K * PARAMS_ML_DSA_44_L * DILITHIUM_N)

#endif

/* Length of K in bytes. */
#define DILITHIUM_K_SZ                  32
/* Length of TR in bytes. */
#define DILITHIUM_TR_SZ                 64
/* Length of public key seed in bytes when expanding a. */
#define DILITHIUM_PUB_SEED_SZ           32
/* Length of private key seed in bytes when generating a key. */
#define DILITHIUM_PRIV_SEED_SZ          64

/* Length of seed when creating vector c. */
#define DILITHIUM_SEED_SZ               32
/* Length of seeds created when making a key. */
#define DILITHIUM_SEEDS_SZ              128

/* Length of MU in bytes. */
#define DILITHIUM_MU_SZ                 64
/* Length of random in bytes when generating a signature. */
#define DILITHIUM_RND_SZ                32
/* Length of private random in bytes when generating a signature. */
#define DILITHIUM_PRIV_RAND_SEED_SZ     64

/* 5 blocks, each block 21 * 8 bytes = 840 bytes.
 * Minimum required is 256 * 3 = 768. */
#define DILITHIUM_GEN_A_NBLOCKS         5
/* Number of bytes to generate with Shake128 when generating A. */
#define DILITHIUM_GEN_A_BYTES           \
    (DILITHIUM_GEN_A_NBLOCKS * WC_SHA3_128_COUNT * 8)
/* Number of bytes to a block of SHAKE-128 when generating A. */
#define DILITHIUM_GEN_A_BLOCK_BYTES     (WC_SHA3_128_COUNT * 8)

/* Number of bytes to a block of SHAKE-256 when generating c. */
#define DILITHIUM_GEN_C_BLOCK_BYTES     (WC_SHA3_256_COUNT * 8)


#ifndef WOLFSSL_DILITHIUM_SMALL
#if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT == 0)
    /* A block SHAKE-128 output plus one for reading 4 bytes at a time. */
    #define DILITHIUM_REJ_NTT_POLY_H_SIZE    (DILITHIUM_GEN_A_BYTES + 1)
#else
    /* A block SHAKE-128 output. */
    #define DILITHIUM_REJ_NTT_POLY_H_SIZE    DILITHIUM_GEN_A_BYTES
#endif /* LITTLE_ENDIAN_ORDER && WOLFSSL_DILITHIUM_ALIGNMENT == 0 */
#else
#if defined(LITTLE_ENDIAN_ORDER) && (WOLFSSL_DILITHIUM_ALIGNMENT == 0)
    /* A block SHAKE-128 output plus one for reading 4 bytes at a time. */
    #define DILITHIUM_REJ_NTT_POLY_H_SIZE    (DILITHIUM_GEN_A_BLOCK_BYTES + 1)
#else
    /* A block SHAKE-128 output. */
    #define DILITHIUM_REJ_NTT_POLY_H_SIZE    DILITHIUM_GEN_A_BLOCK_BYTES
#endif /* LITTLE_ENDIAN_ORDER && WOLFSSL_DILITHIUM_ALIGNMENT == 0 */
#endif

#elif defined(HAVE_LIBOQS)

#define DILITHIUM_LEVEL2_KEY_SIZE     OQS_SIG_ml_dsa_44_ipd_length_secret_key
#define DILITHIUM_LEVEL2_SIG_SIZE     OQS_SIG_ml_dsa_44_ipd_length_signature
#define DILITHIUM_LEVEL2_PUB_KEY_SIZE OQS_SIG_ml_dsa_44_ipd_length_public_key
#define DILITHIUM_LEVEL2_PRV_KEY_SIZE \
    (DILITHIUM_LEVEL2_PUB_KEY_SIZE+DILITHIUM_LEVEL2_KEY_SIZE)
/* Buffer sizes large enough to store exported DER encoded keys */
#define DILITHIUM_LEVEL2_PUB_KEY_DER_SIZE 1334
#define DILITHIUM_LEVEL2_PRV_KEY_DER_SIZE 2588

#define DILITHIUM_LEVEL3_KEY_SIZE     OQS_SIG_ml_dsa_65_ipd_length_secret_key
#define DILITHIUM_LEVEL3_SIG_SIZE     OQS_SIG_ml_dsa_65_ipd_length_signature
#define DILITHIUM_LEVEL3_PUB_KEY_SIZE OQS_SIG_ml_dsa_65_ipd_length_public_key
#define DILITHIUM_LEVEL3_PRV_KEY_SIZE \
    (DILITHIUM_LEVEL3_PUB_KEY_SIZE+DILITHIUM_LEVEL3_KEY_SIZE)
/* Buffer sizes large enough to store exported DER encoded keys */
#define DILITHIUM_LEVEL3_PUB_KEY_DER_SIZE 1974
#define DILITHIUM_LEVEL3_PRV_KEY_DER_SIZE 4060

#define DILITHIUM_LEVEL5_KEY_SIZE     OQS_SIG_ml_dsa_87_ipd_length_secret_key
#define DILITHIUM_LEVEL5_SIG_SIZE     OQS_SIG_ml_dsa_87_ipd_length_signature
#define DILITHIUM_LEVEL5_PUB_KEY_SIZE OQS_SIG_ml_dsa_87_ipd_length_public_key
#define DILITHIUM_LEVEL5_PRV_KEY_SIZE \
    (DILITHIUM_LEVEL5_PUB_KEY_SIZE+DILITHIUM_LEVEL5_KEY_SIZE)
/* Buffer sizes large enough to store exported DER encoded keys */
#define DILITHIUM_LEVEL5_PUB_KEY_DER_SIZE 2614
#define DILITHIUM_LEVEL5_PRV_KEY_DER_SIZE 4924


#define ML_DSA_LEVEL2_KEY_SIZE        OQS_SIG_ml_dsa_44_ipd_length_secret_key
#define ML_DSA_LEVEL2_SIG_SIZE        OQS_SIG_ml_dsa_44_ipd_length_signature
#define ML_DSA_LEVEL2_PUB_KEY_SIZE    OQS_SIG_ml_dsa_44_ipd_length_public_key
#define ML_DSA_LEVEL2_PRV_KEY_SIZE    \
    (ML_DSA_LEVEL2_PUB_KEY_SIZE+ML_DSA_LEVEL2_KEY_SIZE)
/* Buffer sizes large enough to store exported DER encoded keys */
#define ML_DSA_LEVEL2_PUB_KEY_DER_SIZE DILITHIUM_LEVEL2_PUB_KEY_DER_SIZE
#define ML_DSA_LEVEL2_PRV_KEY_DER_SIZE DILITHIUM_LEVEL2_PRV_KEY_DER_SIZE

#define ML_DSA_LEVEL3_KEY_SIZE        OQS_SIG_ml_dsa_65_ipd_length_secret_key
#define ML_DSA_LEVEL3_SIG_SIZE        OQS_SIG_ml_dsa_65_ipd_length_signature
#define ML_DSA_LEVEL3_PUB_KEY_SIZE    OQS_SIG_ml_dsa_65_ipd_length_public_key
#define ML_DSA_LEVEL3_PRV_KEY_SIZE    \
    (ML_DSA_LEVEL3_PUB_KEY_SIZE+ML_DSA_LEVEL3_KEY_SIZE)
/* Buffer sizes large enough to store exported DER encoded keys */
#define ML_DSA_LEVEL3_PUB_KEY_DER_SIZE DILITHIUM_LEVEL3_PUB_KEY_DER_SIZE
#define ML_DSA_LEVEL3_PRV_KEY_DER_SIZE DILITHIUM_LEVEL3_PRV_KEY_DER_SIZE

#define ML_DSA_LEVEL5_KEY_SIZE        OQS_SIG_ml_dsa_87_ipd_length_secret_key
#define ML_DSA_LEVEL5_SIG_SIZE        OQS_SIG_ml_dsa_87_ipd_length_signature
#define ML_DSA_LEVEL5_PUB_KEY_SIZE    OQS_SIG_ml_dsa_87_ipd_length_public_key
#define ML_DSA_LEVEL5_PRV_KEY_SIZE    \
    (ML_DSA_LEVEL5_PUB_KEY_SIZE+ML_DSA_LEVEL5_KEY_SIZE)
/* Buffer sizes large enough to store exported DER encoded keys */
#define ML_DSA_LEVEL5_PUB_KEY_DER_SIZE DILITHIUM_LEVEL5_PUB_KEY_DER_SIZE
#define ML_DSA_LEVEL5_PRV_KEY_DER_SIZE DILITHIUM_LEVEL5_PRV_KEY_DER_SIZE

#endif

#define DILITHIUM_MAX_KEY_SIZE     DILITHIUM_LEVEL5_KEY_SIZE
#define DILITHIUM_MAX_SIG_SIZE     DILITHIUM_LEVEL5_SIG_SIZE
#define DILITHIUM_MAX_PUB_KEY_SIZE DILITHIUM_LEVEL5_PUB_KEY_SIZE
#define DILITHIUM_MAX_PRV_KEY_SIZE DILITHIUM_LEVEL5_PRV_KEY_SIZE
/* Buffer sizes large enough to store exported DER encoded keys */
#define DILITHIUM_MAX_PUB_KEY_DER_SIZE DILITHIUM_LEVEL5_PUB_KEY_DER_SIZE
#define DILITHIUM_MAX_PRV_KEY_DER_SIZE DILITHIUM_LEVEL5_PRV_KEY_DER_SIZE


#ifdef WOLF_PRIVATE_KEY_ID
#define DILITHIUM_MAX_ID_LEN    32
#define DILITHIUM_MAX_LABEL_LEN 32
#endif

/* Structs */

#ifdef WOLFSSL_WC_DILITHIUM
typedef struct wc_dilithium_params {
    byte level;
    byte k;
    byte l;
    byte eta;
    byte eta_bits;
    byte tau;
    byte beta;
    byte omega;
    word16 lambda;
    byte gamma1_bits;
    word32 gamma2;
    word32 w1EncSz;
    word16 aSz;
    word16 s1Sz;
    word16 s1EncSz;
    word16 s2Sz;
    word16 s2EncSz;
    word16 zEncSz;
    word16 pkSz;
    word16 sigSz;
} wc_dilithium_params;
#endif

struct dilithium_key {
    byte pubKeySet;
    byte prvKeySet;
    byte level; /* 2,3 or 5 */

    void* heap; /* heap hint */

#ifdef WOLF_CRYPTO_CB
    void* devCtx;
    int   devId;
#endif
#ifdef WOLF_PRIVATE_KEY_ID
    byte id[DILITHIUM_MAX_ID_LEN];
    int  idLen;
    char label[DILITHIUM_MAX_LABEL_LEN];
    int  labelLen;
#endif

#ifndef WOLFSSL_DILITHIUM_ASSIGN_KEY
    byte p[DILITHIUM_MAX_PUB_KEY_SIZE];
    byte k[DILITHIUM_MAX_KEY_SIZE];
#else
    const byte* p;
    const byte* k;
#endif

#ifdef WOLFSSL_WC_DILITHIUM
    const wc_dilithium_params* params;
    wc_Shake shake;
#ifndef WC_DILITHIUM_FIXED_ARRAY
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
    sword32* a;
    byte aSet;
#endif
#ifdef WC_DILITHIUM_CACHE_PRIV_VECTORS
    sword32* s1;
    sword32* s2;
    sword32* t0;
    byte privVecsSet;
#endif
#ifdef WC_DILITHIUM_CACHE_PUB_VECTORS
    sword32* t1;
    byte pubVecSet;
#endif
#else
#ifdef WC_DILITHIUM_CACHE_MATRIX_A
    sword32 a[DILITHIUM_MAX_MATRIX_COUNT];
    byte aSet;
#endif
#ifdef WC_DILITHIUM_CACHE_PRIV_VECTORS
    sword32 s1[DILITHIUM_MAX_L_VECTOR_COUNT];
    sword32 s2[DILITHIUM_MAX_K_VECTOR_COUNT];
    sword32 t0[DILITHIUM_MAX_K_VECTOR_COUNT];
    byte privVecsSet;
#endif
#ifdef WC_DILITHIUM_CACHE_PUB_VECTORS
    sword32 t1[DILITHIUM_MAX_K_VECTOR_COUNT];
    byte pubVecSet;
#endif
#endif
#if defined(WOLFSSL_DILITHIUM_VERIFY_NO_MALLOC) && \
    defined(WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM)
    sword32 z[DILITHIUM_MAX_L_VECTOR_COUNT];
    sword32 c[DILITHIUM_N];
    sword32 w[DILITHIUM_N];
    sword32 t1[DILITHIUM_N];
    byte w1e[DILITHIUM_MAX_W1_ENC_SZ];
#ifdef WOLFSSL_DILITHIUM_SMALL_MEM_POLY64
    sword64 t64[DILITHIUM_N];
#endif
    byte h[DILITHIUM_REJ_NTT_POLY_H_SIZE];
    byte block[DILITHIUM_GEN_C_BLOCK_BYTES];
#endif /* WOLFSSL_DILITHIUM_VERIFY_NO_MALLOC &&
        * WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM */
#endif /* WOLFSSL_WC_DILITHIUM */
};

#ifndef WC_DILITHIUMKEY_TYPE_DEFINED
    typedef struct dilithium_key dilithium_key;
    #define WC_DILITHIUMKEY_TYPE_DEFINED
#endif

/* Functions */

#ifndef WOLFSSL_DILITHIUM_VERIFY_ONLY
WOLFSSL_API
int wc_dilithium_make_key(dilithium_key* key, WC_RNG* rng);
WOLFSSL_API
int wc_dilithium_make_key_from_seed(dilithium_key* key, const byte* seed);

WOLFSSL_API
int wc_dilithium_sign_msg(const byte* msg, word32 msgLen, byte* sig,
    word32* sigLen, dilithium_key* key, WC_RNG* rng);
WOLFSSL_API
int wc_dilithium_sign_ctx_msg(const byte* ctx, byte ctxLen, const byte* msg,
    word32 msgLen, byte* sig, word32* sigLen, dilithium_key* key, WC_RNG* rng);
WOLFSSL_API
int wc_dilithium_sign_ctx_hash(const byte* ctx, byte ctxLen, int hashAlg,
    const byte* hash, word32 hashLen, byte* sig, word32* sigLen,
    dilithium_key* key, WC_RNG* rng);
WOLFSSL_API
int wc_dilithium_sign_msg_with_seed(const byte* msg, word32 msgLen, byte* sig,
    word32 *sigLen, dilithium_key* key, const byte* seed);
WOLFSSL_API
int wc_dilithium_sign_ctx_msg_with_seed(const byte* ctx, byte ctxLen,
    const byte* msg, word32 msgLen, byte* sig, word32 *sigLen,
    dilithium_key* key, const byte* seed);
WOLFSSL_API
int wc_dilithium_sign_ctx_hash_with_seed(const byte* ctx, byte ctxLen,
    int hashAlg, const byte* hash, word32 hashLen, byte* sig, word32 *sigLen,
    dilithium_key* key, const byte* seed);
#endif
WOLFSSL_API
int wc_dilithium_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
    word32 msgLen, int* res, dilithium_key* key);
WOLFSSL_API
int wc_dilithium_verify_ctx_msg(const byte* sig, word32 sigLen, const byte* ctx,
    word32 ctxLen, const byte* msg, word32 msgLen, int* res,
    dilithium_key* key);
WOLFSSL_API
int wc_dilithium_verify_ctx_hash(const byte* sig, word32 sigLen,
    const byte* ctx, word32 ctxLen, int hashAlg, const byte* hash,
    word32 hashLen, int* res, dilithium_key* key);

WOLFSSL_API
int wc_dilithium_init(dilithium_key* key);

WOLFSSL_API
int wc_dilithium_init_ex(dilithium_key* key, void* heap, int devId);

#ifdef WOLF_PRIVATE_KEY_ID
WOLFSSL_API
int wc_dilithium_init_id(dilithium_key* key, const unsigned char* id, int len,
    void* heap, int devId);
WOLFSSL_API
int wc_dilithium_init_label(dilithium_key* key, const char* label, void* heap,
    int devId);
#endif

WOLFSSL_API
int wc_dilithium_set_level(dilithium_key* key, byte level);
WOLFSSL_API
int wc_dilithium_get_level(dilithium_key* key, byte* level);
WOLFSSL_API
void wc_dilithium_free(dilithium_key* key);

#ifdef WOLFSSL_DILITHIUM_PRIVATE_KEY
WOLFSSL_API
int wc_dilithium_size(dilithium_key* key);
#endif
#if defined(WOLFSSL_DILITHIUM_PRIVATE_KEY) && \
    defined(WOLFSSL_DILITHIUM_PUBLIC_KEY)
WOLFSSL_API
int wc_dilithium_priv_size(dilithium_key* key);
#endif
#ifdef WOLFSSL_DILITHIUM_PUBLIC_KEY
WOLFSSL_API
int wc_dilithium_pub_size(dilithium_key* key);
#endif
#if !defined(WOLFSSL_DILITHIUM_NO_SIGN) || !defined(WOLFSSL_DILITHIUM_NO_VERIFY)
WOLFSSL_API
int wc_dilithium_sig_size(dilithium_key* key);
#endif

#ifdef WOLFSSL_DILITHIUM_CHECK_KEY
WOLFSSL_API
int wc_dilithium_check_key(dilithium_key* key);
#endif

#ifdef WOLFSSL_DILITHIUM_PUBLIC_KEY
WOLFSSL_API
int wc_dilithium_import_public(const byte* in, word32 inLen,
    dilithium_key* key);
#endif
#ifdef WOLFSSL_DILITHIUM_PRIVATE_KEY
WOLFSSL_API
int wc_dilithium_import_private(const byte* priv, word32 privSz,
    dilithium_key* key);
#define wc_dilithium_import_private_only    wc_dilithium_import_private
WOLFSSL_API
int wc_dilithium_import_key(const byte* priv, word32 privSz,
    const byte* pub, word32 pubSz, dilithium_key* key);
#endif

#ifdef WOLFSSL_DILITHIUM_PUBLIC_KEY
WOLFSSL_API
int wc_dilithium_export_public(dilithium_key* key, byte* out, word32* outLen);
#endif
#ifdef WOLFSSL_DILITHIUM_PRIVATE_KEY
WOLFSSL_API
int wc_dilithium_export_private(dilithium_key* key, byte* out, word32* outLen);
#define wc_dilithium_export_private_only    wc_dilithium_export_private
#endif
#ifdef WOLFSSL_DILITHIUM_PRIVATE_KEY
WOLFSSL_API
int wc_dilithium_export_key(dilithium_key* key, byte* priv, word32 *privSz,
    byte* pub, word32 *pubSz);
#endif

#ifndef WOLFSSL_DILITHIUM_NO_ASN1
#if defined(WOLFSSL_DILITHIUM_PRIVATE_KEY)
WOLFSSL_API int wc_Dilithium_PrivateKeyDecode(const byte* input,
    word32* inOutIdx, dilithium_key* key, word32 inSz);
#endif
#endif /* WOLFSSL_DILITHIUM_NO_ASN1 */
#ifdef WOLFSSL_DILITHIUM_PUBLIC_KEY
WOLFSSL_API int wc_Dilithium_PublicKeyDecode(const byte* input,
    word32* inOutIdx, dilithium_key* key, word32 inSz);
#endif

#ifndef WOLFSSL_DILITHIUM_NO_ASN1
#ifdef WC_ENABLE_ASYM_KEY_EXPORT
WOLFSSL_API int wc_Dilithium_PublicKeyToDer(dilithium_key* key, byte* output,
    word32 inLen, int withAlg);
#endif
#if defined(WOLFSSL_DILITHIUM_PRIVATE_KEY)
WOLFSSL_API int wc_Dilithium_KeyToDer(dilithium_key* key, byte* output,
    word32 inLen);
#endif
#ifdef WOLFSSL_DILITHIUM_PRIVATE_KEY
WOLFSSL_API int wc_Dilithium_PrivateKeyToDer(dilithium_key* key, byte* output,
    word32 inLen);
#endif
#endif /* WOLFSSL_DILITHIUM_NO_ASN1 */


#define WC_ML_DSA_DRAFT         10

#define WC_ML_DSA_44            2
#define WC_ML_DSA_65            3
#define WC_ML_DSA_87            5
#define WC_ML_DSA_44_DRAFT      (2 + WC_ML_DSA_DRAFT)
#define WC_ML_DSA_65_DRAFT      (3 + WC_ML_DSA_DRAFT)
#define WC_ML_DSA_87_DRAFT      (5 + WC_ML_DSA_DRAFT)

#define DILITHIUM_ML_DSA_44_KEY_SIZE        2560
#define DILITHIUM_ML_DSA_44_SIG_SIZE        2420
#define DILITHIUM_ML_DSA_44_PUB_KEY_SIZE    1312
#define DILITHIUM_ML_DSA_44_PRV_KEY_SIZE    \
    (DILITHIUM_ML_DSA_44_PUB_KEY_SIZE + DILITHIUM_ML_DSA_44_KEY_SIZE)

#define DILITHIUM_ML_DSA_65_KEY_SIZE        4032
#define DILITHIUM_ML_DSA_65_SIG_SIZE        3309
#define DILITHIUM_ML_DSA_65_PUB_KEY_SIZE    1952
#define DILITHIUM_ML_DSA_65_PRV_KEY_SIZE    \
    (DILITHIUM_ML_DSA_65_PUB_KEY_SIZE + DILITHIUM_ML_DSA_65_KEY_SIZE)

#define DILITHIUM_ML_DSA_87_KEY_SIZE        4896
#define DILITHIUM_ML_DSA_87_SIG_SIZE        4627
#define DILITHIUM_ML_DSA_87_PUB_KEY_SIZE    2592
#define DILITHIUM_ML_DSA_87_PRV_KEY_SIZE    \
    (DILITHIUM_ML_DSA_87_PUB_KEY_SIZE + DILITHIUM_ML_DSA_87_KEY_SIZE)


#define MlDsaKey  dilithium_key


#define wc_MlDsaKey_Init(key, heap, devId)                      \
    wc_dilithium_init_ex(key, heap, devId)
#define wc_MlDsaKey_SetParams(key, id)                          \
    wc_dilithium_set_level(key, id)
#define wc_MlDsaKey_GetParams(key, id)                          \
    wc_dilithium_get_level(key, id)
#define wc_MlDsaKey_MakeKey(key, rng)                           \
    wc_dilithium_make_key(key, rng)
#define wc_MlDsaKey_ExportPrivRaw(key, out, outLen)             \
    wc_dilithium_export_private_only(key, out, outLen)
#define wc_MlDsaKey_ImportPrivRaw(key, in, inLen)               \
    wc_dilithium_import_private_only(in, inLen, key)
#define wc_MlDsaKey_Sign(key, sig, sigSz, msg, msgSz, rng)      \
    wc_dilithium_sign_msg(msg, msgSz, sig, sigSz, key, rng)
#define wc_MlDsaKey_Free(key)                                   \
    wc_dilithium_free(key)
#define wc_MlDsaKey_ExportPubRaw(key, out, outLen)              \
    wc_dilithium_export_public(key, out, outLen)
#define wc_MlDsaKey_ImportPubRaw(key, in, inLen)                \
    wc_dilithium_import_public(in, inLen, key)
#define wc_MlDsaKey_Verify(key, sig, sigSz, msg, msgSz, res)    \
    wc_dilithium_verify_msg(sig, sigSz, msg, msgSz, res, key)

WOLFSSL_API int wc_MlDsaKey_GetPrivLen(MlDsaKey* key, int* len);
WOLFSSL_API int wc_MlDsaKey_GetPubLen(MlDsaKey* key, int* len);
WOLFSSL_API int wc_MlDsaKey_GetSigLen(MlDsaKey* key, int* len);

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_DILITHIUM */
#endif /* WOLF_CRYPT_DILITHIUM_H */
