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

#undef  NO_BIG_INT
#define NO_BIG_INT

/* remove code around sockets and use IO callbacks instead */
#undef  WOLFSSL_NO_SOCK
#define WOLFSSL_NO_SOCK

#undef  WOLFSSL_USER_IO
#define WOLFSSL_USER_IO

/* Build settings specific for use with MCC18 */
#ifdef __18CXX

    /* 8 bit Micro, reusing some of the setting from 16 bit Micro */
    #undef  WC_16BIT_CPU
    #define WC_16BIT_CPU

    #define SIZEOF_LONG_LONG 4
    #define SIZEOF_LONG 4

    /* pushing some large buffers to 'rom' */
    #undef  WOLFSSL_USE_FLASHMEM
    #define WOLFSSL_USE_FLASHMEM
#endif

#define NO_WOLFSSL_DIR

/* ------------------------------------------------------------------------- */
/* Crypto */
/* ------------------------------------------------------------------------- */

/* AES Configuration */
#undef NO_AES
#if 1
    #undef  WOLFSSL_AES_SMALL_TABLES
    #define WOLFSSL_AES_SMALL_TABLES

    #undef  AES_MAX_KEY_SIZE
    #define AES_MAX_KEY_SIZE 128

    #undef  NO_AES_192
    #define NO_AES_192

    #undef  NO_AES_256
    #define NO_AES_256

    #undef  HAVE_AES_DECRYPT
    #define HAVE_AES_DECRYPT

    #undef  HAVE_AESGCM
    #undef  HAVE_AESCCM
    #undef  WOLFSSL_AES_COUNTER
    #undef  WOLFSSL_AES_DIRECT
#else
    #define NO_AES
#endif

/* No public/private key support, just static PSK */
#undef  WOLFSSL_STATIC_PSK
#define WOLFSSL_STATIC_PSK

#undef  NO_DES3
#define NO_DES3

#undef HAVE_CURVE25519
#undef HAVE_ED25519
#undef HAVE_ECC

#undef  NO_RSA
#define NO_RSA

#undef  NO_DSA
#define NO_DSA

#undef  NO_DH
#define NO_DH

/* ------------------------------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------------------------------- */

/* use Sha256, disable all other hashing */
#undef NO_SHA256

/* Uses about 10 bytes less "DATA" memory */
#undef  USE_SLOW_SHA256
#define USE_SLOW_SHA256

#undef  NO_SHA
#define NO_SHA

#undef  WOLFSSL_SHA512

#undef  NO_RC4
#define NO_RC4

#undef  NO_MD5
#define NO_MD5

#undef  NO_MD4
#define NO_MD4

#undef  NO_HASH_WRAPPER
#define NO_HASH_WRAPPER

#undef  WOLFSSL_NOSHA512_256
#define WOLFSSL_NOSHA512_256

#undef  WOLFSSL_NOSHA512_224
#define WOLFSSL_NOSHA512_224

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
    #endif
#else
    #undef  NO_WOLFSSL_MEMORY
    //#define NO_WOLFSSL_MEMORY

    #undef  NO_ERROR_STRINGS
    #define NO_ERROR_STRINGS
#endif

#undef  WOLFSSL_DEBUG_ERRORS_ONLY
#define WOLFSSL_DEBUG_ERRORS_ONLY

/* removes ability to get human readable alert strings */
#undef  NO_ALERT_STRINGS
#define NO_ALERT_STRINGS

/* ------------------------------------------------------------------------- */
/* Disable Features */
/* ------------------------------------------------------------------------- */
#undef  KEEP_PEER_CERT
#undef  HAVE_COMP_KEY
#undef  HAVE_TLS_EXTENSIONS
#undef  HAVE_SUPPORTED_CURVES
#undef  WOLFSSL_BASE64_ENCODE
#undef  NO_WOLFSSL_CLIENT
#undef  NO_CRYPT_TEST
#undef  NO_CRYPT_BENCHMARK

#undef  NO_SESSION_CACHE
#define NO_SESSION_CACHE

#undef  NO_WOLFSSL_SERVER
#define NO_WOLFSSL_SERVER

#undef  WOLFSSL_NO_CLIENT_AUTH
#define WOLFSSL_NO_CLIENT_AUTH

#undef  NO_ASN_TIME
#define NO_ASN_TIME

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

#undef  NO_OLD_TLS
#define NO_OLD_TLS

#undef  NO_PWDBASED
#define NO_PWDBASED

#undef  NO_CODING
#define NO_CODING

#undef  NO_SESSION_CACHE
#define NO_SESSION_CACHE

#undef  NO_CERTS
#define NO_CERTS

#undef  NO_ASN
#define NO_ASN

#undef  NO_CLIENT_CACHE
#define NO_CLIENT_CACHE

#undef  NO_WOLFSSL_CM_VERIFY
#define NO_WOLFSSL_CM_VERIFY

/* ------------------------------------------------------------------------- */
/* Fine Tuned Size Reduction */
/* ------------------------------------------------------------------------- */

#undef  WC_NO_CACHE_RESISTANT
#define WC_NO_CACHE_RESISTANT

/* pre calculated sizes */
#define MAX_PSK_ID_LEN  10
#define MAX_PSK_KEY_LEN 16u

#undef  WOLFSSL_MAX_SUITE_SZ
#define WOLFSSL_MAX_SUITE_SZ 1

#undef  WOLFSSL_MAX_SIGALGO
#define WOLFSSL_MAX_SIGALGO 1

#undef  MAX_PRF_DIG
#define MAX_PRF_DIG 128

#undef  MAX_PRF_LABSEED
#define MAX_PRF_LABSEED 77

/* remove code with cipher suites, have a hard set PSK suite */
#undef  NO_CIPHER_SUITE_ALIASES
#define NO_CIPHER_SUITE_ALIASES

#undef  NO_FORCE_SCR_SAME_SUITE
#define NO_FORCE_SCR_SAME_SUITE

/* remove extra check that server hello did use matching cihper suite */
#undef  WOLFSSL_NO_STRICT_CIPHER_SUITE
#define WOLFSSL_NO_STRICT_CIPHER_SUITE

/* Remove additional sanity checks to make sure no duplicates, no fast forward ...
 * ~1k of code size */
#undef  WOLFSSL_NO_SANITY_CHECK_HANDSHAKE
//#define WOLFSSL_NO_SANITY_CHECK_HANDSHAKE

/* remove async support */
#undef  WOLFSSL_NO_ASYNC_IO
#define WOLFSSL_NO_ASYNC_IO

/* trim down misc.c file */
#define WOLFSSL_NO_FORCE_ZERO
#define WOLFSSL_NO_STRING_CONV

/* lean PSK to compile additional code */
#define WOLFSSL_LEANPSK
#define WOLFSSL_LEANPSK_STATIC
#ifdef __18CXX
    #define WOLFSSL_LEANPSK_STATIC_IO
#endif

/* disables some early sanity checks on the handshake */
#undef  WOLFSSL_DISABLE_EARLY_SANITY_CHECKS
#define WOLFSSL_DISABLE_EARLY_SANITY_CHECKS

/* removing session resumption support, each connection
 * does a full handshake */
#undef  WOLFSSL_NO_SESSION_RESUMPTION
#define WOLFSSL_NO_SESSION_RESUMPTION

/* cutting out TLS downgrade handling code */
#undef  WOLFSSL_NO_DOWNGRADE
#define WOLFSSL_NO_DOWNGRADE

#undef  NO_HANDSHAKE_DONE_CB
#define NO_HANDSHAKE_DONE_CB

/* ------------------------------------------------------------------------- */
/* Memory config */
/* ------------------------------------------------------------------------- */

#undef  WOLFSSL_SMALL_STACK
#define WOLFSSL_SMALL_STACK

#undef  WOLFSSL_NO_REALLOC
#define WOLFSSL_NO_REALLOC

//#define WOLFSSL_STATIC_MEMORY
#ifndef WOLFSSL_STATIC_MEMORY
    #ifdef __18CXX
        /* use custom malloc on target */
        #define XMALLOC_USER
    #else
        #define NO_WOLFSSL_MEMORY
    #endif
#else
    #define WOLFSSL_STATIC_MEMORY_LEAN
    #define USE_WOLFSSL_MEMORY
    #define WOLFSSL_NO_MALLOC

    /* AES_CBC tunning */
    #if !defined(HAVE_AESGCM) && !defined(HAVE_CHACHA)
      #define WOLFMEM_MAX_BUCKETS 12
      #define WOLFMEM_DEF_BUCKETS 12
      #define WOLFMEM_BUCKETS 4,32,36,80,107,139,154,166,172,195,205,256
      #define WOLFMEM_DIST    3,2,2,1,2,1,1,1,1,1,1,1
    #endif

    #define WOLFSSL_STATIC_ALIGN 1

    /* Send debugging messages about memory allocation */
    //#define WOLFSSL_STATIC_MEMORY_DEBUG_CALLBACK
#endif

/* ------------------------------------------------------------------------- */
/* RNG config */
/* ------------------------------------------------------------------------- */
#ifndef WOLFSSL_GENSEED_FORTEST
    #if 0
        /* Gains about 30 bytes of heap and ~6k of code space but is not a secure
         * RNG. RNG is used with client random in ClientHello and with AES-CBC IV's
         * when usng static PSK cipher suite.
         */
        #define CUSTOM_RAND_GENERATE_BLOCK myRng

        #undef  NO_DEV_RANDOM
        #define NO_DEV_RANDOM
    #else
        #define CUSTOM_RAND_GENERATE_SEED myGenSeed
    #endif
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
