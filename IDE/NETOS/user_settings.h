/* user_settings.h
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


#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

#undef  HAVE_FIPS
#if 1

    #define HAVE_FIPS

    #undef  HAVE_FIPS_VERSION
    #define HAVE_FIPS_VERSION 5

    #undef HAVE_FIPS_VERSION_MAJOR
    #define HAVE_FIPS_VERSION_MAJOR 5

    #undef HAVE_FIPS_VERSION_MINOR
    #define HAVE_FIPS_VERSION_MINOR 2

    #undef WOLFSSL_WOLFSSH
    #define WOLFSSL_WOLFSSH

    #undef WC_RNG_SEED_CB
    #define WC_RNG_SEED_CB

    #if 1
        #undef NO_ATTRIBUTE_CONSTRUCTOR
        #define NO_ATTRIBUTE_CONSTRUCTOR
    #endif

#endif


/* ------------------------------------------------------------------------- */
/* Platform */
/* ------------------------------------------------------------------------- */
#undef  WOLFSSL_GENERAL_ALIGNMENT
#define WOLFSSL_GENERAL_ALIGNMENT   4

#undef THREADX
#define THREADX

#ifndef TX_TIMER_TICKS_PER_SECOND
    #define TX_TIMER_TICKS_PER_SECOND 100
#endif

#undef NETOS
#define NETOS

#undef BIG_ENDIAN_ORDER
#define BIG_ENDIAN_ORDER

#undef WOLFSSL_USE_ALIGN
#define WOLFSSL_USE_ALIGN

#undef  NO_THREAD_LS
#define NO_THREAD_LS

/* ------------------------------------------------------------------------- */
/* Math Configuration */
/* ------------------------------------------------------------------------- */

    #define WOLFCRYPT_FIPS_CORE_HASH_VALUE \
            F0E3A7F32D8FDE71DA017855072247B27D8C0F5A74CACE89AED272A7CF5EAC0E
#if 0
    #define WOLFSSL_SP_MATH_ALL
    #define WOLFSSL_SP_RSA
    #define WOLFSSL_SP_DH
    #define WOLFSSL_SP_ECC
    #define WOLFSSL_SP_4096
    #define WOLFSSL_SP_384
    #define WOLFSSL_SP_521
    #define WOLFSSL_SP_SMALL
    #define WOLFSSL_SP_NO_MALLOC
    #define SP_INT_BITS 8192
#endif
#if 1
    #undef  USE_FAST_MATH
    #define USE_FAST_MATH
    #if 1
        #define WOLFSSL_SP_RSA
        #define WOLFSSL_SP_DH
        #define WOLFSSL_SP_ECC
        #define WOLFSSL_SP_4096
        #define WOLFSSL_SP_384
        #define WOLFSSL_SP_521
        #define WOLFSSL_SP_SMALL
        #define SP_INT_BITS 8192
    #endif
#endif
#if 0
    #undef USE_INTEGER_HEAP_MATH
    #define USE_INTEGER_HEAP_MATH

    #undef WOLFSSL_SMALL_STACK
    #define WOLFSSL_SMALL_STACK
#endif

#undef  SIZEOF_LONG_LONG
#define SIZEOF_LONG_LONG 8

#ifdef USE_FAST_MATH
    #undef  TFM_TIMING_RESISTANT
    #define TFM_TIMING_RESISTANT

    #undef  FP_MAX_BITS
    #define FP_MAX_BITS 16384

    #define TFM_NO_ASM

    /* Optimizations (on M0 UMULL is not supported, need another assembly
     * solution) */
    //#define TFM_ARM
#endif

/* ------------------------------------------------------------------------- */
/* Crypto */
/* ------------------------------------------------------------------------- */
/* RSA */
#undef NO_RSA
#if 1

    /* half as much memory but twice as slow */
    #undef  RSA_LOW_MEM
    //#define RSA_LOW_MEM

    /* Enables blinding mode, to prevent timing attacks */
    #if 0
        #undef  WC_RSA_BLINDING
        #define WC_RSA_BLINDING
    #else
        #undef  WC_NO_HARDEN
        #define WC_NO_HARDEN
    #endif

    /* RSA PSS Support */
    #if 1
        #undef WC_RSA_PSS
        #define WC_RSA_PSS

        #undef WOLFSSL_PSS_LONG_SALT
        #define WOLFSSL_PSS_LONG_SALT

        #undef WOLFSSL_PSS_SALT_LEN_DISCOVER
        #define WOLFSSL_PSS_SALT_LEN_DISCOVER
    #endif

    #if 1
        #define WC_RSA_NO_PADDING
    #endif
#else
    #define NO_RSA
#endif

/* ECC */
#undef HAVE_ECC
#if 1
    #define HAVE_ECC

    /* Manually define enabled curves */
    #undef  ECC_USER_CURVES
    #define ECC_USER_CURVES

    #ifdef ECC_USER_CURVES
        /* Manual Curve Selection */
        #define HAVE_ECC192
        #define HAVE_ECC224
        #undef NO_ECC256
        #define HAVE_ECC256
        #define HAVE_ECC384
        #define HAVE_ECC521
    #endif

    /* Fixed point cache (speeds repeated operations against same private key)
     */
    #undef  FP_ECC
    //#define FP_ECC
    #ifdef FP_ECC
        /* Bits / Entries */
        #undef  FP_ENTRIES
        #define FP_ENTRIES  2
        #undef  FP_LUT
        #define FP_LUT      4
    #endif

    /* Optional ECC calculation method */
    /* Note: doubles heap usage, but slightly faster */
    #undef  ECC_SHAMIR
    #define ECC_SHAMIR

    /* Reduces heap usage, but slower */
    #undef  ECC_TIMING_RESISTANT
    #define ECC_TIMING_RESISTANT

    #ifdef HAVE_FIPS
        #undef  HAVE_ECC_CDH
        #define HAVE_ECC_CDH /* Enable cofactor support */

        #undef NO_STRICT_ECDSA_LEN
        #define NO_STRICT_ECDSA_LEN /* Do not force fixed len w/ FIPS */

        #undef  WOLFSSL_VALIDATE_ECC_IMPORT
        #define WOLFSSL_VALIDATE_ECC_IMPORT /* Validate import */

        #undef WOLFSSL_VALIDATE_ECC_KEYGEN
        #define WOLFSSL_VALIDATE_ECC_KEYGEN /* Validate generated keys */

        #undef WOLFSSL_ECDSA_SET_K
        #define WOLFSSL_ECDSA_SET_K

        //#define WOLFCRYPT_HAVE_SAKKE

    #endif

    /* Use alternate ECC size for ECC math */
    #ifdef USE_FAST_MATH
        #undef  ALT_ECC_SIZE
        #define ALT_ECC_SIZE

        /* Speedups specific to curve */
        #ifndef NO_ECC256
            #undef  TFM_ECC256
            #define TFM_ECC256
        #endif
    #endif
#endif

/* DH */
#undef  NO_DH
#if 1
    #define HAVE_DH
    /* Use table for DH instead of -lm (math) lib dependency */
    #if 1
        #define HAVE_DH_DEFAULT_PARAMS
        #define WOLFSSL_DH_CONST
        #define HAVE_FFDHE_2048
        #define HAVE_FFDHE_3072
        #define HAVE_FFDHE_4096
        #define HAVE_FFDHE_6144
        #define HAVE_FFDHE_8192
    #endif

    #ifdef HAVE_FIPS
        #define WOLFSSL_VALIDATE_FFC_IMPORT
        #define HAVE_FFDHE_Q
    #endif
#else
    #define NO_DH
#endif


/* AES */
#undef NO_AES
#if 1
    #undef  HAVE_AES_CBC
    #define HAVE_AES_CBC

    #undef  HAVE_AESGCM
    #define HAVE_AESGCM

    /* GCM Method (slowest to fastest): GCM_SMALL, GCM_WORD32, GCM_TABLE or
     *                                  GCM_TABLE_4BIT */
    #define GCM_TABLE_4BIT

    #undef  WOLFSSL_AES_DIRECT
    #define WOLFSSL_AES_DIRECT

    #undef  HAVE_AES_ECB
    #define HAVE_AES_ECB

    #undef  WOLFSSL_AES_COUNTER
    #define WOLFSSL_AES_COUNTER

    #undef  HAVE_AESCCM
    #define HAVE_AESCCM

    #undef WOLFSSL_AES_OFB
    #define WOLFSSL_AES_OFB

#else
    #define NO_AES
#endif


/* DES3 */
#undef NO_DES3
#if 0
    #if 1
        #undef WOLFSSL_DES_ECB
        #define WOLFSSL_DES_ECB
    #endif
#else
    #define NO_DES3
#endif

/* ChaCha20 / Poly1305 */
#undef HAVE_CHACHA
#undef HAVE_POLY1305
#if 0
    #define HAVE_CHACHA
    #define HAVE_POLY1305

    /* Needed for Poly1305 */
    #undef  HAVE_ONE_TIME_AUTH
    #define HAVE_ONE_TIME_AUTH
#endif

/* Curve25519 */
#undef HAVE_CURVE25519
#if 0
    #define HAVE_CURVE25519

    /* Optionally use small math (less flash usage, but much slower) */
    #if 1
        #define CURVE25519_SMALL
    #endif
#endif

/* Ed25519 */
#undef HAVE_ED25519
#if 0
    #define HAVE_ED25519 /* ED25519 Requires SHA512 */

    /* Optionally use small math (less flash usage, but much slower) */
    #if 1
        #define ED25519_SMALL
    #endif
#endif


/* ------------------------------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------------------------------- */
/* Sha */
#undef NO_SHA
#if 1
    /* 1k smaller, but 25% slower */
    #define USE_SLOW_SHA
#else
    #define NO_SHA
#endif

/* Sha256 */
#undef NO_SHA256
#if 1
    /* not unrolled - ~2k smaller and ~25% slower */
    #define USE_SLOW_SHA256

    /* Sha224 */
    #if 1
        #define WOLFSSL_SHA224
    #endif
#else
    #define NO_SHA256
#endif

/* Sha512 */
#undef WOLFSSL_SHA512
#if 1
    #define WOLFSSL_SHA512

    #define  WOLFSSL_NOSHA512_224 /* Not in FIPS mode */
    #define  WOLFSSL_NOSHA512_256 /* Not in FIPS mode */

    /* Sha384 */
    #undef  WOLFSSL_SHA384
    #if 1
        #define WOLFSSL_SHA384
    #endif

    /* over twice as small, but 50% slower */
    #define USE_SLOW_SHA512
#endif

/* Sha3 */
#undef WOLFSSL_SHA3
#if 1
    #define WOLFSSL_SHA3
#endif

/* MD5 */
#undef  NO_MD5
#if 1

#else
    #define NO_MD5
#endif

/* HKDF / PRF */
#undef HAVE_HKDF
#if 1
    #define HAVE_HKDF
    #define WOLFSSL_HAVE_PRF
#endif

/* CMAC */
#undef WOLFSSL_CMAC
#if 1
    #define WOLFSSL_CMAC
#endif

/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */

#undef  DEBUG_WOLFSSL
#define DEBUG_WOLFSSL

/* Use this to measure / print heap usage */
#if 0
    #undef  USE_WOLFSSL_MEMORY
    #define USE_WOLFSSL_MEMORY

    #undef  WOLFSSL_TRACK_MEMORY
    //#define WOLFSSL_TRACK_MEMORY

    #undef  WOLFSSL_DEBUG_MEMORY
    //#define WOLFSSL_DEBUG_MEMORY
#else
    #undef  NO_WOLFSSL_MEMORY
    #define NO_WOLFSSL_MEMORY
#endif

#ifndef DEBUG_WOLFSSL
    #undef  NO_ERROR_STRINGS
    #define NO_ERROR_STRINGS
#endif


/* ------------------------------------------------------------------------- */
/* Port */
/* ------------------------------------------------------------------------- */

/* Override Current Time */
/* Allows custom "custom_time()" function to be used for benchmark */
//#define WOLFSSL_USER_CURRTIME
//#define XTIME time


/* ------------------------------------------------------------------------- */
/* RNG */
/* ------------------------------------------------------------------------- */
/* Size of returned HW RNG value */
//#define CUSTOM_RAND_TYPE      unsigned int

/* Seed Source */
#if 1
    extern int my_rng_generate_seed(unsigned char* output, int sz);
    #undef CUSTOM_RAND_GENERATE_SEED
    #define CUSTOM_RAND_GENERATE_SEED my_rng_generate_seed
#endif

/* NETOS */
#if 0
    extern unsigned char get_byte_from_pool(void);
    #define CUSTOM_RAND_GENERATE  get_byte_from_pool
    #define CUSTOM_RAND_TYPE      unsigned char
#endif

//#define WOLFSSL_GENSEED_FORTEST
/* Choose RNG method */
#if 1
    /* Use built-in P-RNG (SHA256 based) with HW RNG */
    /* P-RNG + HW RNG (P-RNG is ~8K) */
    #undef  HAVE_HASHDRBG
    #define HAVE_HASHDRBG
#else
    #undef  WC_NO_HASHDRBG
    #define WC_NO_HASHDRBG

    /* Bypass P-RNG and use only HW RNG */
    extern int custom_rand_generate_block(unsigned char* output,
                                          unsigned int sz);
    #undef  CUSTOM_RAND_GENERATE_BLOCK
    #define CUSTOM_RAND_GENERATE_BLOCK  custom_rand_generate_block
#endif

/* ------------------------------------------------------------------------- */
/* Enable Features */
/* ------------------------------------------------------------------------- */
#if 0
    #undef WOLFSSL_TLS13
    #define WOLFSSL_TLS13
#endif

#undef  WOLFSSL_KEY_GEN
#define WOLFSSL_KEY_GEN

#undef  KEEP_PEER_CERT
//#define KEEP_PEER_CERT

#undef  HAVE_COMP_KEY
//#define HAVE_COMP_KEY

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_SUPPORTED_CURVES
#define HAVE_SUPPORTED_CURVES

#undef  WOLFSSL_BASE64_ENCODE
#define WOLFSSL_BASE64_ENCODE

#undef WOLFSSL_BASE16
#define WOLFSSL_BASE16

/* TLS Session Cache */
#if 1
    #define SMALL_SESSION_CACHE
#else
    #define NO_SESSION_CACHE
#endif

#define BENCH_EMBEDDED

/* ------------------------------------------------------------------------- */
/* Disable Features */
/* ------------------------------------------------------------------------- */
#undef  NO_WOLFSSL_SERVER
//#define NO_WOLFSSL_SERVER

#undef  NO_WOLFSSL_CLIENT
//#define NO_WOLFSSL_CLIENT

#undef  NO_CRYPT_TEST
//#define NO_CRYPT_TEST

#undef  NO_CRYPT_BENCHMARK
//#define NO_CRYPT_BENCHMARK

#undef  WOLFCRYPT_ONLY
//#define WOLFCRYPT_ONLY

/* In-lining of misc.c functions */
/* If defined, must include wolfcrypt/src/misc.c in build */
/* Slower, but about 1k smaller */
#undef  NO_INLINE
//#define NO_INLINE

#undef  NO_FILESYSTEM
#define NO_FILESYSTEM

#undef NO_WOLFSSL_DIR
#define NO_WOLFSSL_DIR

#undef  NO_WRITEV
#define NO_WRITEV

#undef  NO_MAIN_DRIVER
#define NO_MAIN_DRIVER

#undef  NO_DEV_RANDOM
#define NO_DEV_RANDOM

#undef  NO_DSA
#define NO_DSA

#undef  NO_DES3
#define NO_DES3

#undef  NO_RC4
#define NO_RC4

#undef  NO_OLD_TLS
#define NO_OLD_TLS

#undef  NO_PSK
#define NO_PSK

#undef  NO_MD4
#define NO_MD4

#undef  NO_PWDBASED
//#define NO_PWDBASED

#undef  NO_CODING
//#define NO_CODING

#undef  NO_ASN_TIME
//#define NO_ASN_TIME

#undef  NO_CERTS
//#define NO_CERTS

#undef  NO_SIG_WRAPPER
//#define NO_SIG_WRAPPER

/* FIPS optesting for wolfSSL Engineering only, disable in production */
#if 0
    #define DEBUG_FIPS_VERBOSE
    #define NO_CAVP_TDES
    #define USE_UART_READ_LINE
    #define USE_NORMAL_PRINTF
    #define WOLFSSL_PUBLIC_MP

    #define NO_MAIN_OPTEST_DRIVER
    #define OPTEST_LOGGING_ENABLED
    #define DEBUG_FIPS_VERBOSE
    #define OPTEST_INVALID_LOGGING_ENABLED
    #define OPTEST_RUNNING_ORGANIC
    #define HAVE_FORCE_FIPS_FAILURE

    #define USE_CERT_BUFFERS_2048
    #define USE_CERT_BUFFERS_256
    #define FORCE_BUFFER_TEST
    #define NO_MAIN_OPTEST_DRIVER
    #define DEEPLY_EMBEDDED

#endif
/* End optesting only section */

/* START Customer specified options */
#if 1
    #undef  HAVE_SECRET_CALLBACK
    #define HAVE_SECRET_CALLBACK

    #undef  ATOMIC_USER
    #define ATOMIC_USER

    #undef  HAVE_EX_DATA
    #define HAVE_EX_DATA

    #undef  NO_WOLFSSL_STUB
    #define NO_WOLFSSL_STUB

    #undef  OPENSSL_EXTRA
    #define OPENSSL_EXTRA

    #undef  OPENSSL_ALL
    #define OPENSSL_ALL

    #undef  HAVE_EXTENDED_MASTER
    #define HAVE_EXTENDED_MASTER

    #undef  WC_NO_ASYNC_THREADING
    #define WC_NO_ASYNC_THREADING

    #undef  NO_TESTSUITE_MAIN_DRIVER
    #define NO_TESTSUITE_MAIN_DRIVER

    #undef WOLFSSL_NO_ASN_STRICT
    #define WOLFSSL_NO_ASN_STRICT
#endif
/* END Customer specified options */
#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */

