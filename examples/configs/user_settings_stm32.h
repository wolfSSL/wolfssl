/* wolfSSL_conf.h (example of generated wolfSSL.I-CUBE-wolfSSL_conf.h using
 * default_conf.ftl and STM32CubeIDE or STM32CubeMX tool)
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

/* STM32 Cube Sample Configuration File
 * Generated automatically using `default_conf.ftl` template
 *
 * Included automatically when USE_HAL_DRIVER is defined
 * (and not WOLFSSL_USER_SETTINGS or HAVE_CONFIG_H).
 */

#ifndef __WOLFSSL_I_CUBE_WOLFSSL_CONF_H__
#define __WOLFSSL_I_CUBE_WOLFSSL_CONF_H__

#ifdef __cplusplus
extern "C" {
#endif


/*---------- WOLF_CONF_DEBUG -----------*/
#define WOLF_CONF_DEBUG      0

/*---------- WOLF_CONF_WOLFCRYPT_ONLY -----------*/
#define WOLF_CONF_WOLFCRYPT_ONLY      0

/*---------- WOLF_CONF_TLS13 -----------*/
#define WOLF_CONF_TLS13      1

/*---------- WOLF_CONF_TLS12 -----------*/
#define WOLF_CONF_TLS12      1

/*---------- WOLF_CONF_DTLS -----------*/
#define WOLF_CONF_DTLS      0

/*---------- WOLF_CONF_MATH -----------*/
#define WOLF_CONF_MATH      4

/*---------- WOLF_CONF_RTOS -----------*/
#define WOLF_CONF_RTOS      2

/*---------- WOLF_CONF_RNG -----------*/
#define WOLF_CONF_RNG      1

/*---------- WOLF_CONF_RSA -----------*/
#define WOLF_CONF_RSA      1

/*---------- WOLF_CONF_ECC -----------*/
#define WOLF_CONF_ECC      1

/*---------- WOLF_CONF_DH -----------*/
#define WOLF_CONF_DH      1

/*---------- WOLF_CONF_AESGCM -----------*/
#define WOLF_CONF_AESGCM      1

/*---------- WOLF_CONF_AESCBC -----------*/
#define WOLF_CONF_AESCBC      0

/*---------- WOLF_CONF_CHAPOLY -----------*/
#define WOLF_CONF_CHAPOLY      1

/*---------- WOLF_CONF_EDCURVE25519 -----------*/
#define WOLF_CONF_EDCURVE25519      1

/*---------- WOLF_CONF_MD5 -----------*/
#define WOLF_CONF_MD5      0

/*---------- WOLF_CONF_SHA1 -----------*/
#define WOLF_CONF_SHA1      0

/*---------- WOLF_CONF_SHA2_224 -----------*/
#define WOLF_CONF_SHA2_224      0

/*---------- WOLF_CONF_SHA2_256 -----------*/
#define WOLF_CONF_SHA2_256      1

/*---------- WOLF_CONF_SHA2_384 -----------*/
#define WOLF_CONF_SHA2_384      1

/*---------- WOLF_CONF_SHA2_512 -----------*/
#define WOLF_CONF_SHA2_512      1

/*---------- WOLF_CONF_SHA3 -----------*/
#define WOLF_CONF_SHA3      0

/*---------- WOLF_CONF_PSK -----------*/
#define WOLF_CONF_PSK      0

/*---------- WOLF_CONF_PWDBASED -----------*/
#define WOLF_CONF_PWDBASED      0

/*---------- WOLF_CONF_KEEP_PEER_CERT -----------*/
#define WOLF_CONF_KEEP_PEER_CERT      0

/*---------- WOLF_CONF_BASE64_ENCODE -----------*/
#define WOLF_CONF_BASE64_ENCODE      0

/*---------- WOLF_CONF_OPENSSL_EXTRA -----------*/
#define WOLF_CONF_OPENSSL_EXTRA      0

/*---------- WOLF_CONF_TEST -----------*/
#define WOLF_CONF_TEST      1

/*---------- WOLF_CONF_PQM4 -----------*/
#define WOLF_CONF_PQM4      0

/*---------- WOLF_CONF_ARMASM -----------*/
#define WOLF_CONF_ARMASM      1

/* ------------------------------------------------------------------------- */
/* Hardware platform */
/* ------------------------------------------------------------------------- */
/* Setup default (No crypto hardware acceleration or TLS UART test).
 * Use undef in platform section to enable it.
 */
#define NO_STM32_HASH
#define NO_STM32_CRYPTO
#define NO_TLS_UART_TEST

#if defined(STM32WB55xx)
    #define WOLFSSL_STM32WB
    #define WOLFSSL_STM32_PKA
    #undef  NO_STM32_CRYPTO
    #define HAL_CONSOLE_UART huart1
#elif defined(STM32WL55xx)
    #define WOLFSSL_STM32WL
    #define WOLFSSL_STM32_PKA
    #undef  NO_STM32_CRYPTO
    #define HAL_CONSOLE_UART huart2
#elif defined(STM32F407xx)
    #define WOLFSSL_STM32F4
    #define HAL_CONSOLE_UART huart2
#elif defined(STM32F437xx)
    #define WOLFSSL_STM32F4
    #undef  NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #define STM32_HAL_V2
    #define HAL_CONSOLE_UART huart4
#elif defined(STM32F777xx)
    #define WOLFSSL_STM32F7
    #undef  NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #define STM32_HAL_V2
    #define HAL_CONSOLE_UART huart2
#elif defined(STM32F756xx)
    #define WOLFSSL_STM32F7
    #undef  NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #define STM32_HAL_V2
    #define HAL_CONSOLE_UART huart3
#elif defined(STM32H753xx)
    #define WOLFSSL_STM32H7
    #undef  NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #define HAL_CONSOLE_UART huart3
#elif defined(STM32H723xx) || defined(STM32H725xx) || defined(STM32H743xx)
    #define WOLFSSL_STM32H7
    #define HAL_CONSOLE_UART huart3
#elif defined(STM32L4A6xx)
    #define WOLFSSL_STM32L4
    #undef  NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #define HAL_CONSOLE_UART hlpuart1
#elif defined(STM32L475xx)
    #define WOLFSSL_STM32L4
    #define HAL_CONSOLE_UART huart1
#elif defined(STM32L562xx)
    #define WOLFSSL_STM32L5
    #define WOLFSSL_STM32_PKA
    #undef  NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #define HAL_CONSOLE_UART huart1
#elif defined(STM32L552xx)
    #define WOLFSSL_STM32L5
    #undef  NO_STM32_HASH
    #define HAL_CONSOLE_UART hlpuart1
#elif defined(STM32F207xx)
    #define WOLFSSL_STM32F2
    #define HAL_CONSOLE_UART huart3
#elif defined(STM32F217xx)
    #define WOLFSSL_STM32F2
    #define HAL_CONSOLE_UART huart2
#elif defined(STM32F107xC)
    #define WOLFSSL_STM32F1
    #define HAL_CONSOLE_UART huart4
    #define NO_STM32_RNG
#elif defined(STM32F401xE)
    #define WOLFSSL_STM32F4
    #define HAL_CONSOLE_UART huart2
    #define NO_STM32_RNG
    #define WOLFSSL_GENSEED_FORTEST /* no HW RNG is available use test seed */
#elif defined(STM32G071xx)
    #define WOLFSSL_STM32G0
    #define HAL_CONSOLE_UART huart2
    #define NO_STM32_RNG
    #define WOLFSSL_GENSEED_FORTEST /* no HW RNG is available use test seed */
#elif defined(STM32G491xx)
    #define WOLFSSL_STM32G4
    #define HAL_CONSOLE_UART hlpuart1
#elif defined(STM32U575xx) || defined(STM32U585xx) || defined(STM32U5A9xx)
    #define HAL_CONSOLE_UART huart1
    #define WOLFSSL_STM32U5
    #define STM32_HAL_V2
    #if defined(STM32U585xx) || defined(STM32U5A9xx)
        #undef  NO_STM32_HASH
        #undef  NO_STM32_CRYPTO
        #define WOLFSSL_STM32_PKA
    #endif
#elif defined(STM32H563xx)
    #define WOLFSSL_STM32H5
    #define HAL_CONSOLE_UART huart3
    #define STM32_HAL_V2
    #undef  NO_STM32_HASH

#else
    #warning Please define a hardware platform!
    /* This means there is not a pre-defined platform for your board/CPU */
    /* You need to define a CPU type, HW crypto and debug UART */
    /* CPU Type: WOLFSSL_STM32F1, WOLFSSL_STM32F2, WOLFSSL_STM32F4,
        WOLFSSL_STM32F7, WOLFSSL_STM32H7, WOLFSSL_STM32L4, WOLFSSL_STM32L5,
        WOLFSSL_STM32G0, WOLFSSL_STM32WB and WOLFSSL_STM32U5 */
    #define WOLFSSL_STM32F4

    /* Debug UART used for printf */
    /* The UART interface number varies for each board/CPU */
    /* Typically this is the UART attached to the ST-Link USB CDC UART port */
    #define HAL_CONSOLE_UART huart4

    /* Hardware Crypto - uncomment as available on hardware */
    //#define WOLFSSL_STM32_PKA
    //#define NO_STM32_RNG
    //#undef  NO_STM32_HASH
    //#undef  NO_STM32_CRYPTO
    /* if no HW RNG is available use test seed */
    //#define WOLFSSL_GENSEED_FORTEST
    //#define STM32_HAL_V2
#endif


/* ------------------------------------------------------------------------- */
/* Platform */
/* ------------------------------------------------------------------------- */
#define SIZEOF_LONG_LONG 8
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define WOLFSSL_STM32_CUBEMX
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_IGNORE_FILE_WARN

/* ------------------------------------------------------------------------- */
/* Network stack: 1=User IO (custom), 2=LWIP (posix), 3=LWIP (native) */
/* ------------------------------------------------------------------------- */
#if defined(WOLF_CONF_IO) && WOLF_CONF_IO == 2
    #define WOLFSSL_LWIP
#elif defined(WOLF_CONF_IO) && WOLF_CONF_IO == 3
    #define WOLFSSL_LWIP_NATIVE
#else /* custom */
    #define WOLFSSL_USER_IO
    #define WOLFSSL_NO_SOCK
#endif


/* ------------------------------------------------------------------------- */
/* Operating System: 1=Bare-metal/Single threaded, 2=FREERTOS */
/* ------------------------------------------------------------------------- */
#if defined(WOLF_CONF_RTOS) && WOLF_CONF_RTOS == 2
    #define FREERTOS
#else
    #define SINGLE_THREADED
#endif


/* ------------------------------------------------------------------------- */
/* Math Configuration */
/* ------------------------------------------------------------------------- */
/* 1=Fast (stack)                      (tfm.c)
 * 2=Normal (heap)                     (integer.c)
 * 3-5=Single Precision: only common curves/key sizes:
 *                   (ECC 256/384/521 and RSA/DH 2048/3072/4096)
 *   3=Single Precision C              (sp_c32.c)
 *   4=Single Precision ASM Cortex-M3+ (sp_cortexm.c)
 *   5=Single Precision ASM Cortex-M0  (sp_armthumb.c)
 * 6=Wolf multi-precision C small      (sp_int.c)
 * 7=Wolf multi-precision C big        (sp_int.c)
 */

#if defined(WOLF_CONF_MATH) && WOLF_CONF_MATH == 1
    /* fast (stack) math - tfm.c */
    #define USE_FAST_MATH
    #define TFM_TIMING_RESISTANT

    #if !defined(NO_RSA) || !defined(NO_DH)
        /* Maximum math bits (Max DH/RSA key bits * 2) */
        #undef  FP_MAX_BITS
        #define FP_MAX_BITS     4096
    #endif

    /* Optimizations (TFM_ARM, TFM_ASM or none) */
    //#define TFM_NO_ASM
    //#define TFM_ASM
#elif defined(WOLF_CONF_MATH) && WOLF_CONF_MATH == 2
    /* heap math - integer.c */
    #define USE_INTEGER_HEAP_MATH
#elif defined(WOLF_CONF_MATH) && (WOLF_CONF_MATH >= 3)
    /* single precision only */
    #define WOLFSSL_SP
    #if WOLF_CONF_MATH != 7
        #define WOLFSSL_SP_SMALL      /* use smaller version of code */
    #endif
    #if defined(WOLF_CONF_RSA) && WOLF_CONF_RSA == 1
        #define WOLFSSL_HAVE_SP_RSA
        //#define WOLFSSL_SP_NO_2048
        //#define WOLFSSL_SP_NO_3072
        //#define WOLFSSL_SP_4096
    #endif
    #if defined(WOLF_CONF_DH) && WOLF_CONF_DH == 1
        #define WOLFSSL_HAVE_SP_DH
    #endif
    #if defined(WOLF_CONF_ECC) && WOLF_CONF_ECC == 1
        #define WOLFSSL_HAVE_SP_ECC
        //#define WOLFSSL_SP_NO_256
        #define WOLFSSL_SP_384
        //#define WOLFSSL_SP_521
    #endif
    #if WOLF_CONF_MATH == 6 || WOLF_CONF_MATH == 7
        #define WOLFSSL_SP_MATH_ALL /* use sp_int.c multi precision math */
        //#define WOLFSSL_SP_ARM_THUMB /* enable ARM Thumb ASM speedups */
    #else
        #define WOLFSSL_SP_MATH    /* disable non-standard curves / key sizes */
    #endif
    #define SP_WORD_SIZE 32 /* force 32-bit mode */

    /* Enable to put all math on stack (no heap) */
    //#define WOLFSSL_SP_NO_MALLOC

    #if WOLF_CONF_MATH == 4 || WOLF_CONF_MATH == 5
        #define WOLFSSL_SP_ASM /* required if using the ASM versions */
        #if WOLF_CONF_MATH == 4
            /* ARM Cortex-M3+ */
            #define WOLFSSL_SP_ARM_CORTEX_M_ASM
        #endif
        #if WOLF_CONF_MATH == 5
            /* Generic ARM Thumb (Cortex-M0) Assembly */
            #define WOLFSSL_SP_ARM_THUMB_ASM
        #endif
    #endif
#endif


/* ------------------------------------------------------------------------- */
/* Enable Features */
/* ------------------------------------------------------------------------- */
/* Required for TLS */
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_EXTENDED_MASTER
#define WOLFSSL_ASN_TEMPLATE
#define HAVE_SNI

#if defined(WOLF_CONF_TLS13) && WOLF_CONF_TLS13 == 1
    #define WOLFSSL_TLS13
    #define HAVE_HKDF
#endif
#if defined(WOLF_CONF_DTLS) && WOLF_CONF_DTLS == 1
    #define WOLFSSL_DTLS
#endif
#if defined(WOLF_CONF_PSK) && WOLF_CONF_PSK == 0
    #define NO_PSK
#endif
#if defined(WOLF_CONF_PWDBASED) && WOLF_CONF_PWDBASED == 0
    #define NO_PWDBASED
#endif
#if defined(WOLF_CONF_KEEP_PEER_CERT) && WOLF_CONF_KEEP_PEER_CERT == 1
    #define KEEP_PEER_CERT
#endif
#if defined(WOLF_CONF_BASE64_ENCODE) && WOLF_CONF_BASE64_ENCODE == 1
    #define WOLFSSL_BASE64_ENCODE
#endif
#if defined(WOLF_CONF_OPENSSL_EXTRA) && WOLF_CONF_OPENSSL_EXTRA >= 1
    #define OPENSSL_EXTRA
    #if !defined(INT_MAX)
        #include <limits.h>
    #endif
#endif
#if defined(WOLF_CONF_OPENSSL_EXTRA) && WOLF_CONF_OPENSSL_EXTRA >= 2
    #define OPENSSL_ALL
#endif

/* TLS Session Cache */
#if defined(WOLF_CONF_RESUMPTION) && WOLF_CONF_RESUMPTION == 1
    #define SMALL_SESSION_CACHE
    #define HAVE_SESSION_TICKET
#else
    #define NO_SESSION_CACHE
#endif

/* TPM support */
#if defined(WOLF_CONF_TPM) && WOLF_CONF_TPM == 1
    #define WOLF_CRYPTO_CB
    #define WOLFSSL_PUBLIC_MP
    /* also AES CFB - enabled below */
#endif

/* TLS key callbacks */
#if defined(WOLF_CONF_PK) && WOLF_CONF_PK == 1
    #define HAVE_PK_CALLBACKS
#endif

/* ------------------------------------------------------------------------- */
/* Crypto */
/* ------------------------------------------------------------------------- */
/* RSA */
#undef NO_RSA
#if defined(WOLF_CONF_RSA) && WOLF_CONF_RSA == 1
    /* half as much memory but twice as slow */
    #undef  RSA_LOW_MEM
    //#define RSA_LOW_MEM

    /* Enables blinding mode, to prevent timing attacks */
    #undef  WC_RSA_BLINDING
    #define WC_RSA_BLINDING

    /* RSA PSS Support (required for TLS v1.3) */
    #ifdef WOLFSSL_TLS13
        #define WC_RSA_PSS
    #endif
#else
    #define NO_RSA
#endif

/* ECC */
#undef HAVE_ECC
#if defined(WOLF_CONF_ECC) && WOLF_CONF_ECC == 1
    #define HAVE_ECC

    /* Manually define enabled curves */
    #define ECC_USER_CURVES

    //#define HAVE_ECC192
    //#define HAVE_ECC224
    #undef NO_ECC256
    #define HAVE_ECC384
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
    #define ECC_TIMING_RESISTANT

    /* Compressed ECC key support */
    //#define HAVE_COMP_KEY

    #ifdef USE_FAST_MATH
        #if defined(NO_RSA) && defined(NO_DH)
            /* Custom fastmath size if not using RSA/DH */
            /* MAX = ROUND32(ECC BITS) * 2 */
            #define FP_MAX_BITS     (256 * 2)
        #else
            #define ALT_ECC_SIZE
        #endif

        /* Enable TFM optimizations for ECC */
        //#define TFM_ECC192
        //#define TFM_ECC224
        //#define TFM_ECC256
        //#define TFM_ECC384
        //#define TFM_ECC521
    #endif
#endif

/* DH */
#undef NO_DH
#if defined(WOLF_CONF_DH) && WOLF_CONF_DH == 1
    #define HAVE_DH /* freeRTOS settings.h requires this */
    #define HAVE_FFDHE_2048
    #define HAVE_DH_DEFAULT_PARAMS
#else
    #define NO_DH
#endif

/* AES */
#if defined(WOLF_CONF_AESGCM) && WOLF_CONF_AESGCM >= 1
    #define HAVE_AESGCM
    #define HAVE_AES_DECRYPT

    /* GCM Method: GCM_SMALL, GCM_WORD32, GCM_TABLE or GCM_TABLE_4BIT */
    /* GCM_TABLE is about 4K larger and 3x faster for GHASH */
    #if WOLF_CONF_AESGCM == 2
        #define GCM_TABLE_4BIT
    #else
        #define GCM_SMALL
    #endif
#endif

#if defined(WOLF_CONF_AESCBC) && WOLF_CONF_AESCBC == 1
    #define HAVE_AES_CBC
    #define HAVE_AES_DECRYPT
#else
    #define NO_AES_CBC
#endif

/* Other possible AES modes */
#if defined(WOLF_CONF_TPM) && WOLF_CONF_TPM == 1
    #define WOLFSSL_AES_CFB /* Used by TPM parameter encryption */
#endif

//#define WOLFSSL_AES_COUNTER
//#define HAVE_AESCCM
//#define WOLFSSL_AES_XTS
//#define WOLFSSL_AES_DIRECT
//#define HAVE_AES_ECB
//#define HAVE_AES_KEYWRAP
//#define AES_MAX_KEY_SIZE 256

/* ChaCha20 / Poly1305 */
#undef HAVE_CHACHA
#undef HAVE_POLY1305
#if defined(WOLF_CONF_CHAPOLY) && WOLF_CONF_CHAPOLY == 1
    #define HAVE_CHACHA
    #define HAVE_POLY1305

    /* Needed for Poly1305 */
    #undef  HAVE_ONE_TIME_AUTH
    #define HAVE_ONE_TIME_AUTH
#endif

/* Ed25519 / Curve25519 */
#undef HAVE_CURVE25519
#undef HAVE_ED25519
#if defined(WOLF_CONF_EDCURVE25519) && WOLF_CONF_EDCURVE25519 == 1
    #define HAVE_CURVE25519
    #define HAVE_ED25519

    /* Optionally use small math (less flash usage, but much slower) */
    //#define CURVED25519_SMALL
#endif

/* ------------------------------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------------------------------- */
/* Sha1 */
#undef NO_SHA
#if defined(WOLF_CONF_SHA1) && WOLF_CONF_SHA1 == 1
    /* 1k smaller, but 25% slower */
    //#define USE_SLOW_SHA
#else
    #define NO_SHA
#endif

/* Sha2-256 */
#undef NO_SHA256
#if defined(WOLF_CONF_SHA2_256) && WOLF_CONF_SHA2_256 == 1
    /* not unrolled - ~2k smaller and ~25% slower */
    //#define USE_SLOW_SHA256

    //#define WOLFSSL_SHAKE256

    /* Sha2-224 */
    #if defined(WOLF_CONF_SHA2_224) && WOLF_CONF_SHA2_224 == 1
        #define WOLFSSL_SHA224
    #endif
#else
    #define NO_SHA256
#endif

/* Sha2-512 */
#undef WOLFSSL_SHA512
#if defined(WOLF_CONF_SHA2_512) && WOLF_CONF_SHA2_512 == 1
    /* over twice as small, but 50% slower */
    //#define USE_SLOW_SHA512

    #define WOLFSSL_SHA512
    #define HAVE_SHA512 /* old freeRTOS settings.h requires this */
#endif

/* Sha2-384 */
#undef WOLFSSL_SHA384
#if defined(WOLF_CONF_SHA2_384) && WOLF_CONF_SHA2_384 == 1
    #define WOLFSSL_SHA384
#endif

/* Sha3 */
#undef WOLFSSL_SHA3
#if defined(WOLF_CONF_SHA3) && WOLF_CONF_SHA3 == 1
    #define WOLFSSL_SHA3
#endif

/* MD5 */
#if defined(WOLF_CONF_MD5) && WOLF_CONF_MD5 == 1
    /* enabled */
#else
    #define NO_MD5
#endif

/* ------------------------------------------------------------------------- */
/* Post-Quantum Crypto */
/* ------------------------------------------------------------------------- */
/* NOTE: this is after the hashing section to override the potential SHA3 undef
 * above. */
#if defined(WOLF_CONF_KYBER) && WOLF_CONF_KYBER == 1
#undef  WOLFSSL_EXPERIMENTAL_SETTINGS
#define WOLFSSL_EXPERIMENTAL_SETTINGS

#undef  WOLFSSL_HAVE_KYBER
#define WOLFSSL_HAVE_KYBER

#undef  WOLFSSL_WC_KYBER
#define WOLFSSL_WC_KYBER

#undef  WOLFSSL_NO_SHAKE128
#undef  WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE128

#undef  WOLFSSL_NO_SHAKE256
#undef  WOLFSSL_SHAKE256
#define WOLFSSL_SHAKE256

#undef  WOLFSSL_SHA3
#define WOLFSSL_SHA3
#endif /* WOLF_CONF_KYBER */

/* ------------------------------------------------------------------------- */
/* Crypto Acceleration */
/* ------------------------------------------------------------------------- */
/* This enables inline assembly speedups for SHA2, SHA3, AES,
 * ChaCha20/Poly1305 and Ed/Curve25519. These settings work for Cortex M4/M7
 * and the source code is located in wolfcrypt/src/port/arm/
 */
#if defined(WOLF_CONF_ARMASM) && WOLF_CONF_ARMASM == 1
    #define WOLFSSL_ARMASM
    #define WOLFSSL_ARMASM_INLINE
    #define WOLFSSL_ARMASM_NO_HW_CRYPTO
    #define WOLFSSL_ARMASM_NO_NEON
    #define WOLFSSL_ARM_ARCH 7
    /* Disable H/W offloading if accelerating S/W crypto */
    #undef  NO_STM32_HASH
    #define NO_STM32_HASH
    #undef  NO_STM32_CRYPTO
    #define NO_STM32_CRYPTO
#endif

/* ------------------------------------------------------------------------- */
/* Benchmark / Test */
/* ------------------------------------------------------------------------- */
/* Use reduced benchmark / test sizes */
#define BENCH_EMBEDDED
#define USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_256


/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */
#if defined(WOLF_CONF_DEBUG) && WOLF_CONF_DEBUG == 1
    #define DEBUG_WOLFSSL

    /* Use this to measure / print heap usage */
    #if 0
        #define USE_WOLFSSL_MEMORY
        #define WOLFSSL_TRACK_MEMORY
        #define WOLFSSL_DEBUG_MEMORY
        #define WOLFSSL_DEBUG_MEMORY_PRINT
    #endif
#else
    //#define NO_WOLFSSL_MEMORY
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
#define NO_OLD_RNGNAME /* conflicts with STM RNG macro */
#if !defined(WOLF_CONF_RNG) || WOLF_CONF_RNG == 1
    /* default is enabled */
    #define HAVE_HASHDRBG
#else /* WOLF_CONF_RNG == 0 */
    #define WC_NO_HASHDRBG
    #define WC_NO_RNG
#endif


/* ------------------------------------------------------------------------- */
/* Disable Features */
/* ------------------------------------------------------------------------- */
#if defined(WOLF_CONF_TLS12) && WOLF_CONF_TLS12 == 0
    #define WOLFSSL_NO_TLS12
#endif
#if defined(WOLF_CONF_WOLFCRYPT_ONLY) && WOLF_CONF_WOLFCRYPT_ONLY == 1
    #define WOLFCRYPT_ONLY
#endif
//#define NO_WOLFSSL_SERVER
//#define NO_WOLFSSL_CLIENT

#if defined(WOLF_CONF_TEST) && WOLF_CONF_TEST == 0
    #define NO_CRYPT_TEST
    #define NO_CRYPT_BENCHMARK
#endif

#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define NO_DEV_RANDOM
#define NO_OLD_TLS
#define WOLFSSL_NO_CLIENT_AUTH /* disable client auth for Ed25519/Ed448 */

#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_DES3
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256

/* In-lining of misc.c functions */
/* If defined, must include wolfcrypt/src/misc.c in build */
/* Slower, but about 1k smaller */
//#define NO_INLINE

/* Base16 / Base64 encoding */
//#define NO_CODING

/* bypass certificate date checking, due to lack of properly configured RTC source */
#ifndef HAL_RTC_MODULE_ENABLED
    #define NO_ASN_TIME
#endif


#ifdef __cplusplus
}
#endif

#endif /* __WOLFSSL_I_CUBE_WOLFSSL_CONF_H__ */
