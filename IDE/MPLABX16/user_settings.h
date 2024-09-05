/* Example custom user settings for wolfSSL */

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
#define SINGLE_THREADED

#undef  WOLFSSL_SMALL_STACK
#define WOLFSSL_SMALL_STACK

#define MICROCHIP_PIC24

/* Define for older versions of xc16 */
#if 0
    #define WOLFSSL_HAVE_MIN
    #define WOLFSSL_HAVE_MAX
#endif

#ifdef MICROCHIP_PIC24
    #define SIZEOF_LONG_LONG 8
    #define SIZEOF_LONG 4
    #define SINGLE_THREADED
    #define WOLFSSL_USER_IO
    #define NO_WRITEV
    #define NO_DEV_RANDOM
    #define NO_FILESYSTEM
    #define BENCH_EMBEDDED
    #define WC_16BIT_CPU
    #define WORD64_AVAILABLE
    #define WOLFSSL_GENSEED_FORTEST
#endif

/* ------------------------------------------------------------------------- */
/* Math Configuration */
/* ------------------------------------------------------------------------- */
#if 1
    #undef  USE_FAST_MATH
    #define USE_FAST_MATH

    #undef  FP_MAX_BITS
    #define FP_MAX_BITS     2048
#else
    #define WOLFSSL_SP_MATH
    #define WOLFSSL_SP_SMALL
    #define WOLFSSL_SP_MATH_ALL
    #define SP_INT_BITS 256
#endif


#ifdef USE_FAST_MATH
    #undef  TFM_TIMING_RESISTANT
    #define TFM_TIMING_RESISTANT

    /* Optimizations */
    //#define TFM_MIPS
#endif

/* ------------------------------------------------------------------------- */
/* Crypto */
/* ------------------------------------------------------------------------- */
/* ECC */
#if 1
    #undef  HAVE_ECC
    #define HAVE_ECC

    /* Manually define enabled curves */
    #undef  ECC_USER_CURVES
    #define ECC_USER_CURVES

    /* Reduces heap usage, but slower */
    #undef  ECC_TIMING_RESISTANT
    #define ECC_TIMING_RESISTANT

    //#define HAVE_ECC192
    //#define HAVE_ECC224
    //#define HAVE_ECC384
    /* Fixed point cache (speeds repeated operations against same private key) */
#if 1
    #undef  FP_ECC
    #define FP_ECC
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


    #ifdef USE_FAST_MATH
        /* use reduced size math buffers for ecc points */
        #undef  ALT_ECC_SIZE
        #define ALT_ECC_SIZE

        /* Enable TFM optimizations for ECC */
        #if defined(HAVE_ECC192) || defined(HAVE_ALL_CURVES)
            #define TFM_ECC192
        #endif
        #if defined(HAVE_ECC224) || defined(HAVE_ALL_CURVES)
            #define TFM_ECC224
        #endif
        #if !defined(NO_ECC256) || defined(HAVE_ALL_CURVES)
            #define TFM_ECC256
        #endif
        #if defined(HAVE_ECC384) || defined(HAVE_ALL_CURVES)
            #define TFM_ECC384
        #endif
        #if defined(HAVE_ECC521) || defined(HAVE_ALL_CURVES)
            #define TFM_ECC521
        #endif
    #endif
#endif
#endif

/* RSA */
#undef NO_RSA
#if 0
    /* half as much memory but twice as slow */
    #undef  RSA_LOW_MEM
#define RSA_LOW_MEM

    #undef WC_RSA_PSS
    #define WC_RSA_PSS

    /* timing resistance */
    #undef  WC_RSA_BLINDING
    #define WC_RSA_BLINDING
#else
    #define NO_RSA
#endif

/* AES */
#undef NO_AES
#if 1
    #undef  HAVE_AES_DECRYPT
    #define HAVE_AES_DECRYPT

    #undef  HAVE_AESGCM
    #define HAVE_AESGCM

    /* GCM Method: GCM_SMALL, GCM_WORD32 or GCM_TABLE */
    #undef  GCM_SMALL
    #define GCM_SMALL

 /* #undef  HAVE_AESCCM
    #define HAVE_AESCCM */

 /* #undef  WOLFSSL_AES_DIRECT
    #define WOLFSSL_AES_DIRECT */

    #undef  NO_AES_CBC
    #define NO_AES_CBC
#else
    #define NO_AES
#endif

/* DES3 */
#undef NO_DES3
#if 0
    #undef  WOLFSSL_DES_ECB
    #define WOLFSSL_DES_ECB
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
#if 0
    /* 1k smaller, but 25% slower */
    #define USE_SLOW_SHA
#else
    #define NO_SHA
#endif

/* Sha256 */
#undef NO_SHA256
#if 1
#else
    #define NO_SHA256
#endif

/* Sha512 */
#undef WOLFSSL_SHA512
#if 0
    #define WOLFSSL_SHA512

    /* Sha384 */
    #undef  WOLFSSL_SHA384
    #if 0
        #define WOLFSSL_SHA384
    #endif

    /* over twice as small, but 50% slower */
    #define USE_SLOW_SHA2
#endif


/* ------------------------------------------------------------------------- */
/* Benchmark / Test */
/* ------------------------------------------------------------------------- */
/* Use reduced benchmark / test sizes */
#undef  BENCH_EMBEDDED
#define BENCH_EMBEDDED

//#undef  USE_CERT_BUFFERS_2048
//#define USE_CERT_BUFFERS_2048

#undef  USE_CERT_BUFFERS_1024
#define USE_CERT_BUFFERS_1024

#undef  USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_256


/* ------------------------------------------------------------------------- */
/* Time */
/* ------------------------------------------------------------------------- */
#if 0
    /* Override Current Time */
    /* Allows custom "custom_time()" function to be used for benchmark */
    #define WOLFSSL_USER_CURRTIME
    #define USER_TICKS
    extern unsigned long custom_time(unsigned long* timer);
    #define XTIME custom_time
#else
    //#warning Time/RTC disabled
    #undef  NO_ASN_TIME
    #define NO_ASN_TIME
#endif

/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */
#undef  DEBUG_WOLFSSL

#if 0
    #define DEBUG_WOLFSSL
    #define WOLFSSL_DEBUG_TLS
    /* Use this to measure / print heap usage */
        #undef  USE_WOLFSSL_MEMORY
        #define USE_WOLFSSL_MEMORY
        #undef  WOLFSSL_TRACK_MEMORY
        #define WOLFSSL_TRACK_MEMORY
#else
    #undef  NO_WOLFSSL_MEMORY
    #define NO_WOLFSSL_MEMORY
#endif

/* ------------------------------------------------------------------------- */
/* Misc */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_ASN_TEMPLATE
#define NO_ERROR_STRINGS
#define NO_LARGE_HASH_TEST
#define NO_PKCS12
#define NO_PKCS8
#define WOLFSSL_NO_PEM


/* ------------------------------------------------------------------------- */
/* Enable Features */
/* ------------------------------------------------------------------------- */
#undef  KEEP_PEER_CERT
#define KEEP_PEER_CERT

#undef  HAVE_COMP_KEY
#define HAVE_COMP_KEY

#undef  WOLFSSL_TLS13
#define WOLFSSL_TLS13

#undef  HAVE_HKDF
#define HAVE_HKDF

#undef  HAVE_TLS_EXTENSIONS
#define HAVE_TLS_EXTENSIONS

#ifdef HAVE_ECC
#undef  HAVE_SUPPORTED_CURVES
#define HAVE_SUPPORTED_CURVES
#endif

#undef  WOLFSSL_BASE64_ENCODE
#define WOLFSSL_BASE64_ENCODE

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
#define NO_WOLFSSL_CLIENT

#undef  NO_CRYPT_TEST
//#define NO_CRYPT_TEST

#undef  NO_CRYPT_BENCHMARK
//#define NO_CRYPT_BENCHMARK

/* In-lining of misc.c functions */
/* If defined, must include wolfcrypt/src/misc.c in build */
/* Slower, but about 1k smaller */
#undef  NO_INLINE
#define NO_INLINE

#undef  NO_FILESYSTEM
#define NO_FILESYSTEM

#undef  NO_WRITEV
#define NO_WRITEV

#undef  NO_MAIN_DRIVER
#define NO_MAIN_DRIVER

#undef  NO_DEV_RANDOM
#define NO_DEV_RANDOM

#undef  NO_PSK
#define NO_PSK

#undef  NO_DSA
#define NO_DSA

#undef  NO_DH
#define NO_DH

#undef  NO_RC4
#define NO_RC4

#undef  NO_OLD_TLS
#define NO_OLD_TLS

#undef  WOLFSSL_NO_TLS12
#define WOLFSSL_NO_TLS12

#undef  NO_PSK
//#define NO_PSK
#define WOLFSSL_STATIC_PSK

#undef  NO_MD4
#define NO_MD4

#undef  NO_PWDBASED
#define NO_PWDBASED

#undef  NO_MD5
#define NO_MD5

#undef  NO_DES3
#define NO_DES3

#undef  NO_CODING
//#define NO_CODING


#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
