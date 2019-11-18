/* user_settings.h
 *
 * Copyright (C) 2006-2019 wolfSSL Inc.
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

/* Example wolfSSL user settings for STM32F4 with CubeMX */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Platform */
/* ------------------------------------------------------------------------- */
#undef  WOLFSSL_GENERAL_ALIGNMENT
#define WOLFSSL_GENERAL_ALIGNMENT   4

#undef  SINGLE_THREADED
//#define SINGLE_THREADED

#undef  WOLFSSL_SMALL_STACK
#define WOLFSSL_SMALL_STACK

#undef  WOLFSSL_STM32F4
#define WOLFSSL_STM32F4

#undef  WOLFSSL_STM32_CUBEMX
#define WOLFSSL_STM32_CUBEMX

#undef  FREERTOS
#define FREERTOS

#undef  WOLFSSL_USER_IO
#define WOLFSSL_USER_IO

#undef  WOLFSSL_NO_SOCK
#define WOLFSSL_NO_SOCK


/* ------------------------------------------------------------------------- */
/* HW Crypto Acceleration */
/* ------------------------------------------------------------------------- */
// See settings.h STM32F4 section
/* Optionally Disable Hardware Hashing Support */
//#define NO_STM32_HASH
//#define NO_STM32_RNG
//#define NO_STM32_CRYPTO


/* ------------------------------------------------------------------------- */
/* Math Configuration */
/* ------------------------------------------------------------------------- */
#undef  USE_FAST_MATH
#define USE_FAST_MATH

#ifdef USE_FAST_MATH
    #undef  TFM_TIMING_RESISTANT
    #define TFM_TIMING_RESISTANT

    #undef  TFM_NO_ASM
    //#define TFM_NO_ASM

    /* Optimizations (TFM_ARM, TFM_ASM or none) */
    //#define TFM_ASM
#endif

/* Wolf Single Precision Math */
#undef WOLFSSL_SP
#if 0
    #define WOLFSSL_SP
    #define WOLFSSL_SP_SMALL      /* use smaller version of code */
    #define WOLFSSL_HAVE_SP_RSA
    //#define WOLFSSL_HAVE_SP_DH
    #define WOLFSSL_HAVE_SP_ECC
    #define WOLFSSL_SP_CACHE_RESISTANT
    #define WOLFSSL_SP_MATH     /* only SP math - eliminates fast math code */

    //#define WOLFSSL_SP_ASM      /* required if using the ASM versions */
    //#define WOLFSSL_SP_ARM_CORTEX_M_ASM
#endif


/* ------------------------------------------------------------------------- */
/* Crypto */
/* ------------------------------------------------------------------------- */
/* RSA */
#undef NO_RSA
#if 1
    #ifdef USE_FAST_MATH
        /* Maximum math bits (Max RSA key bits * 2) */
        #undef  FP_MAX_BITS
        #define FP_MAX_BITS     4096
    #endif

    /* half as much memory but twice as slow */
    #undef  RSA_LOW_MEM
    //#define RSA_LOW_MEM

    /* Enables blinding mode, to prevent timing attacks */
    #undef  WC_RSA_BLINDING
    #define WC_RSA_BLINDING

    /* RSA PSS Support (required for TLS v1.3)*/
    #if 0
        #define WC_RSA_PSS
    #endif
#else
    #define NO_RSA
#endif

/* ECC */
#if 1
    #undef  HAVE_ECC
    #define HAVE_ECC

    /* Manually define enabled curves */
    #undef  ECC_USER_CURVES
    #define ECC_USER_CURVES

    //#define HAVE_ECC192
    //#define HAVE_ECC224
    #undef NO_ECC256
    //#define HAVE_ECC384
    //#define HAVE_ECC521

    /* Fixed point cache (speeds repeated operations against same private key) */
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

    #ifdef USE_FAST_MATH
        #ifdef NO_RSA
            /* Custom fastmath size if not using RSA */
            /* MAX = ROUND32(ECC BITS 256) + SIZE_OF_MP_DIGIT(32) */
            #undef  FP_MAX_BITS
            #define FP_MAX_BITS     (256 + 32)
        #else
            #undef  ALT_ECC_SIZE
            #define ALT_ECC_SIZE
        #endif

        /* Enable TFM optimizations for ECC */
        //#define TFM_ECC192
        //#define TFM_ECC224
        #define TFM_ECC256
        //#define TFM_ECC384
        //#define TFM_ECC521
    #endif
#endif

/* DH */
#undef  NO_DH
#if 0
    #define HAVE_DH /* freeRTOS settings.h requires this */
#else
    //#define NO_DH
#endif

/* AES */
#undef NO_AES
#if 1
    #undef  HAVE_AESGCM
    #define HAVE_AESGCM

	/* GCM Method: GCM_SMALL, GCM_WORD32 or GCM_TABLE */
    #undef  GCM_SMALL
    #define GCM_SMALL

	#undef  WOLFSSL_AES_COUNTER
	#define WOLFSSL_AES_COUNTER

	#undef  WOLFSSL_AES_DIRECT
	#define WOLFSSL_AES_DIRECT

	#undef  HAVE_AES_ECB
	#define HAVE_AES_ECB
#else
    #define NO_AES
#endif

/* DES */
#undef  NO_DES3
#if 1

#else
    #define NO_DES3
#endif

/* ChaCha20 / Poly1305 */
#undef HAVE_CHACHA
#undef HAVE_POLY1305
#if 1
    #define HAVE_CHACHA
    #define HAVE_POLY1305

    /* Needed for Poly1305 */
    #undef  HAVE_ONE_TIME_AUTH
    #define HAVE_ONE_TIME_AUTH
#endif

/* Ed25519 / Curve25519 */
#undef HAVE_CURVE25519
#undef HAVE_ED25519
#if 0
    #define HAVE_CURVE25519
    #define HAVE_ED25519

    /* Optionally use small math (less flash usage, but much slower) */
    #if 0
        #define CURVED25519_SMALL
    #endif
#endif


/* ------------------------------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------------------------------- */
/* Sha */
#undef NO_SHA
#if 1
    /* 1k smaller, but 25% slower */
    //#define USE_SLOW_SHA
#else
    #define NO_SHA
#endif

/* Sha256 */
#undef NO_SHA256
#if 1
    /* not unrolled - ~2k smaller and ~25% slower */
    //#define USE_SLOW_SHA256

    /* Sha224 */
    #if 0
        #define WOLFSSL_SHA224
    #endif
#else
    #define NO_SHA256
#endif

/* Sha512 */
#undef WOLFSSL_SHA512
#if 1
    /* over twice as small, but 50% slower */
    //#define USE_SLOW_SHA512

    #define WOLFSSL_SHA512
    #define HAVE_SHA512 /* freeRTOS settings.h requires this */

    /* Sha384 */
    #undef  WOLFSSL_SHA384
    #if 1
        #define WOLFSSL_SHA384
    #endif
#endif

/* MD5 */
#if 1
	/* enabled */
#else
    #define NO_MD5
#endif


/* ------------------------------------------------------------------------- */
/* Benchmark / Test */
/* ------------------------------------------------------------------------- */
/* Use reduced benchmark / test sizes */
#undef  BENCH_EMBEDDED
#define BENCH_EMBEDDED

#undef  USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_2048

#undef  USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_256


/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */
#undef  DEBUG_WOLFSSL
//#define DEBUG_WOLFSSL

#ifdef DEBUG_WOLFSSL
    /* Use this to measure / print heap usage */
    #if 0
        #undef  USE_WOLFSSL_MEMORY
        #define USE_WOLFSSL_MEMORY

        #undef  WOLFSSL_TRACK_MEMORY
        #define WOLFSSL_TRACK_MEMORY

		#define WOLFSSL_DEBUG_MEMORY
		#define WOLFSSL_DEBUG_MEMORY_PRINT
    #endif
#else
    #undef  NO_WOLFSSL_MEMORY
    //#define NO_WOLFSSL_MEMORY

    #undef  NO_ERROR_STRINGS
    //#define NO_ERROR_STRINGS
#endif


/* ------------------------------------------------------------------------- */
/* Port */
/* ------------------------------------------------------------------------- */

/* Override Current Time */
/* Allows custom "custom_time()" function to be used for benchmark */
#define WOLFSSL_USER_CURRTIME


/* ------------------------------------------------------------------------- */
/* RNG */
/* ------------------------------------------------------------------------- */
/* Size of returned HW RNG value */
#define NO_OLD_RNGNAME

/* Choose RNG method */
#if 1
	#ifndef STM32_RNG
		#define WOLFSSL_GENSEED_FORTEST
	#endif

    /* Use built-in P-RNG (SHA256 based) with HW RNG */
    /* P-RNG + HW RNG (P-RNG is ~8K) */
    #undef  HAVE_HASHDRBG
    #define HAVE_HASHDRBG
#else
    /* Bypass P-RNG and use only HW RNG */
    extern int custom_rand_generate_block(unsigned char* output, unsigned int sz);
    #undef  CUSTOM_RAND_GENERATE_BLOCK
    #define CUSTOM_RAND_GENERATE_BLOCK  custom_rand_generate_block
#endif


/* ------------------------------------------------------------------------- */
/* Enable Features */
/* ------------------------------------------------------------------------- */
#undef WOLFSSL_TLS13
#if 0
    #define WOLFSSL_TLS13
#endif

#undef  KEEP_PEER_CERT
//#define KEEP_PEER_CERT

#undef  HAVE_COMP_KEY
//#define HAVE_COMP_KEY

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#undef  HAVE_SUPPORTED_CURVES
#define HAVE_SUPPORTED_CURVES

#undef  WOLFSSL_BASE64_ENCODE
//#define WOLFSSL_BASE64_ENCODE

/* TLS Session Cache */
#if 0
    #define SMALL_SESSION_CACHE
#else
    #define NO_SESSION_CACHE
#endif


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

/* In-lining of misc.c functions */
/* If defined, must include wolfcrypt/src/misc.c in build */
/* Slower, but about 1k smaller */
#undef  NO_INLINE
//#define NO_INLINE

#undef  NO_FILESYSTEM
#define NO_FILESYSTEM

#undef  NO_WRITEV
#define NO_WRITEV

#undef  NO_MAIN_DRIVER
#define NO_MAIN_DRIVER

#undef  NO_DEV_RANDOM
#define NO_DEV_RANDOM

#undef  NO_DSA
#define NO_DSA

#undef  NO_RC4
#define NO_RC4

#undef  NO_OLD_TLS
#define NO_OLD_TLS

#undef  NO_HC128
#define NO_HC128

#undef  NO_RABBIT
#define NO_RABBIT

#undef  NO_PSK
#define NO_PSK

#undef  NO_MD4
#define NO_MD4

#undef  NO_PWDBASED
#define NO_PWDBASED

#undef  NO_CODING
//#define NO_CODING

/* bypass certificate date checking, due to lack of properly configured RTC source */
#undef  NO_ASN_TIME
#define NO_ASN_TIME


#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
