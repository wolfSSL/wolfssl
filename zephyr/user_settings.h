/* user_settings.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#ifdef CONFIG_WOLFSSL

/* The wolfCrypt feature configuration comes from the user's own settings file
 * if one was supplied (CONFIG_WOLFSSL_SETTINGS_FILE), otherwise from the module
 * default below. CONFIG_WOLFSSL_SETTINGS_FILE is always defined; when it is not
 * set in prj.conf it is auto-defined to "", so WOLFSSL_SETTINGS_FILE is only
 * defined (in CMakeLists.txt) when a real path was given. A user-supplied
 * settings file is authoritative: the build-profile Kconfig knobs
 * (WOLFSSL_CRYPTO_ONLY, WOLFSSL_SINGLE_THREADED) shape ONLY the module default
 * below and are NOT applied on top of a settings file, so the two config
 * interfaces never mix. A consumer like wolfPSA that needs specific wolfCrypt
 * options checks for them itself and fails the build if a settings file omits
 * them, rather than injecting them here. */
#ifdef WOLFSSL_SETTINGS_FILE
#include WOLFSSL_SETTINGS_FILE
#else

#ifdef __cplusplus
extern "C" {
#endif


/* ------------------------------------------------------------------------- */
/* Platform */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_GENERAL_ALIGNMENT 4 /* platform requires 32-bit alignment on uint32_t */
#define SIZEOF_LONG_LONG 8          /* long long is 8 bytes / 64-bit */
//#define WOLFSSL_NO_ASM /* optionally disable inline assembly support */
#define WOLFSSL_IGNORE_FILE_WARN /* ignore file includes not required */
//#define WOLFSSL_SMALL_STACK /* option to reduce stack size, offload to heap */
#define BENCH_EMBEDDED /* use smaller buffers in benchmark / tests */

/* Network stack */
/* Default is POSIX sockets */
//#define WOLFSSL_USER_IO /* Use the SetIO callbacks, not the internal wolfio.c socket code */
//#define WOLFSSL_LWIP
//#define WOLFSSL_LWIP_NATIVE
//#define FREERTOS_TCP

/* RTOS */
/* Default is POSIX mutex and pthreads*/
//#define SINGLE_THREADED
//#define FREERTOS
#define NO_FILESYSTEM
#define NO_WRITEV

/* ------------------------------------------------------------------------- */
/* Hardware */
/* ------------------------------------------------------------------------- */
/* CryptoCell support */
#if 0
    //#define WOLFSSL_CRYPTOCELL
    //#define WOLFSSL_CRYPTOCELL_AES
#endif
/* PSA support */
#ifdef CONFIG_MBEDTLS_PSA_CRYPTO_C
    #define WOLFSSL_HAVE_PSA
    #ifndef SINGLE_THREADED
        #define WOLFSSL_PSA_GLOBAL_LOCK
    #endif
    #define WC_NO_HASHDRBG /* use PSA RNG directly via wc_psa_get_random */
#endif

/* ------------------------------------------------------------------------- */
/* FIPS */
/* ------------------------------------------------------------------------- */
#ifdef CONFIG_WOLFCRYPT_FIPS
    /* HAVE_FIPS is the master switch that routes the wolfCrypt algorithms
     * through the FIPS module boundary. The version macros below must match the
     * dropped-in FIPS bundle (see the CMake FIPS-boundary block); settings.h
     * folds them into WOLFSSL_FIPS_VERSION_CODE for the in-boundary gating. */
    #define HAVE_FIPS
    /* Version triples mirror configure.ac's --enable-fips=VERSION mapping. */
    #if defined(CONFIG_WOLFCRYPT_FIPS_READY)
        /* FIPS Ready: in-tree, feature locked, one ahead of the latest. */
        #define HAVE_FIPS_VERSION       8
        #define HAVE_FIPS_VERSION_MINOR 0
        #define HAVE_FIPS_VERSION_PATCH 0
    #elif defined(CONFIG_WOLFCRYPT_FIPS_V7)
        /* FIPS 140-3 v7 full submission. */
        #define HAVE_FIPS_VERSION       7
        #define HAVE_FIPS_VERSION_MINOR 0
        #define HAVE_FIPS_VERSION_PATCH 0
    #elif defined(CONFIG_WOLFCRYPT_FIPS_V6)
        /* FIPS 140-3 SRTP-KDF full submission. */
        #define HAVE_FIPS_VERSION       6
        #define HAVE_FIPS_VERSION_MINOR 0
        #define HAVE_FIPS_VERSION_PATCH 0
    #elif defined(CONFIG_WOLFCRYPT_FIPS_V5)
        /* FIPS 140-3 Cert #4718 (wolfCrypt 5.2.1). */
        #define HAVE_FIPS_VERSION       5
        #define HAVE_FIPS_VERSION_MINOR 2
        #define HAVE_FIPS_VERSION_PATCH 1
    #elif defined(CONFIG_WOLFCRYPT_FIPS_V2)
        /* FIPS 140-2 Cert #3389. */
        #define HAVE_FIPS_VERSION       2
        #define HAVE_FIPS_VERSION_MINOR 0
        #define HAVE_FIPS_VERSION_PATCH 0
    #endif
#endif


/* ------------------------------------------------------------------------- */
/* TLS */
/* ------------------------------------------------------------------------- */
/* TLS v1.2 (on by default) */
#ifdef CONFIG_WOLFSSL_TLS_VERSION_1_2
    #undef  WOLFSSL_NO_TLS12
#else
    #define WOLFSSL_NO_TLS12
#endif
//#define NO_WOLFSSL_SERVER /* Optionally disable TLS server code */
//#define NO_WOLFSSL_CLIENT /* Optionally disable TLS client code */

/* TLS v1.3 */
#if defined(CONFIG_WOLFSSL_TLS_VERSION_1_3) || defined(CONFIG_WOLFSSL_TLS13_ENABLED)
    #define WOLFSSL_TLS13
#endif

/* Disable older TLS version prior to 1.2 */
#define NO_OLD_TLS

/* Enable default TLS extensions */
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_EXTENDED_MASTER
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_SERVER_RENEGOTIATION_INFO
#if defined(CONFIG_WOLFSSL_SNI)
    #define HAVE_SNI /* optional Server Name Indication (SNI) */
#endif

/* ASN */
#define WOLFSSL_ASN_TEMPLATE /* use newer ASN template asn.c code (default) */
#if 0 /* optional space reductions */
    #define WOLFSSL_NO_ASN_STRICT
    #define IGNORE_NAME_CONSTRAINTS
#endif

/* Session Cache */
#if defined(CONFIG_WOLFSSL_SESSION_CACHE)
    #define SMALL_SESSION_CACHE
#else
    #define NO_SESSION_CACHE /* disable session resumption */
#endif
/* TLS 1.3 stateless session tickets -- independent of the internal cache. */
#if defined(CONFIG_WOLFSSL_SESSION_TICKET) && defined(WOLFSSL_TLS13)
    #define HAVE_SESSION_TICKET
#endif

/* Session export (external session cache) */
#if defined(CONFIG_WOLFSSL_SESSION_EXPORT)
    #define HAVE_EXT_CACHE
#endif

/* Keep peer certificate after handshake */
#if defined(CONFIG_WOLFSSL_KEEP_PEER_CERT)
    #define KEEP_PEER_CERT
#endif

/* Always invoke verify callback (on success as well as failure) */
#if defined(CONFIG_WOLFSSL_ALWAYS_VERIFY_CB)
    #define WOLFSSL_ALWAYS_VERIFY_CB
#endif

/* Lightweight X509 helpers (wolfSSL_X509_free, wolfSSL_get_verify_result,
 * wolfSSL_X509_load_certificate_buffer) without pulling in the full
 * OPENSSL_EXTRA surface. Apps needing full OpenSSL compat can override
 * user_settings.h via CONFIG_WOLFSSL_SETTINGS_FILE.
 */
#if defined(CONFIG_WOLFSSL_OPENSSL_EXTRA_X509_SMALL)
    #define OPENSSL_EXTRA_X509_SMALL
#endif

/* DTLS */
#if defined(CONFIG_WOLFSSL_DTLS)
    #define WOLFSSL_DTLS
    #define HAVE_SOCKADDR
#endif

/* PSK */
#if defined(CONFIG_WOLFSSL_PSK)
    #undef NO_PSK
    #define WOLFSSL_STATIC_PSK
#else
    #define NO_PSK /* disable pre-shared-key support */
#endif

/* ALPN */
#if defined(CONFIG_WOLFSSL_ALPN)
    #define HAVE_ALPN
#endif

#if defined(CONFIG_WOLFSSL_MAX_FRAGMENT_LEN)
    #define HAVE_MAX_FRAGMENT
#endif

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
    #define WOLFSSL_SET_CIPHER_BYTES
#endif

/* wolfTPM Zephyr */
#if defined(CONFIG_WOLFTPM)
    #define WOLF_CRYPTO_CB
    #define WOLFSSL_AES_CFB
#endif

/* ------------------------------------------------------------------------- */
/* Algorithms */
/* ------------------------------------------------------------------------- */
/* RNG */
/* wolfCrypt Hash-DRBG (SHA2-256). On Zephyr its seed comes from wc_GenerateSeed()
 * (wolfcrypt/src/random.c), which draws from the hardware entropy driver when one
 * is present and falls back to sys_rand_get() otherwise -- so no seed callback is
 * registered. Guarded by WC_NO_HASHDRBG so a PSA-RNG build
 * (CONFIG_MBEDTLS_PSA_CRYPTO_C above) can still disable the internal DRBG and
 * route randomness through the PSA provider. */
#ifndef WC_NO_HASHDRBG
    #define HAVE_HASHDRBG
#endif

/* Build-profile knobs for the module-default config only (a user-supplied
 * settings file sets these itself). */
#ifdef CONFIG_WOLFSSL_CRYPTO_ONLY
    #define WOLFCRYPT_ONLY
#endif
#ifdef CONFIG_WOLFSSL_SINGLE_THREADED
    #define SINGLE_THREADED
#endif

/* ECC */
#if defined(CONFIG_WOLFSSL_ECC)
    #define HAVE_ECC
    #define ECC_USER_CURVES      /* Enable only ECC curves specific */
    #undef  NO_ECC256            /* Enable SECP256R1 only (on by default) */
    #define ECC_TIMING_RESISTANT /* Enable Timing Resistance */

    //#define ECC_SHAMIR         /* Optional ECC calculation speed improvement if not using SP implementation */
    //#define WOLFSSL_CUSTOM_CURVES /* enable other curves (not just prime) */
    //#define HAVE_ECC_SECPR2
    //#define HAVE_ECC_SECPR3
    //#define HAVE_ECC_BRAINPOOL
    //#define HAVE_ECC_KOBLITZ
    //#define HAVE_ECC_CDH /* Co-factor */
    //#define HAVE_COMP_KEY /* Compressed key support */
    //#define FP_ECC /* Fixed point caching - speed repeated operations against same key */
    //#define HAVE_ECC_ENCRYPT
    //#define WOLFCRYPT_HAVE_ECCSI
    //#define WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT
#endif

#define WOLFSSL_OLD_PRIME_CHECK /* Use faster DH prime checking */

/* RSA */
#if defined(CONFIG_WOLFSSL_RSA)
    #undef NO_RSA
    #define WC_RSA_BLINDING
    //#define WC_RSA_NO_PADDING
    //#define RSA_LOW_MEM

    #if 0
        #define WOLFSSL_KEY_GEN /* For RSA Key gen only */
    #endif
    #if defined(WOLFSSL_TLS13) || defined(CONFIG_WOLFSSL_RSA_PSS)
        /* TLS v1.3 requires RSA PSS padding */
        #define WC_RSA_PSS
        //#define WOLFSSL_PSS_LONG_SALT
    #endif
#else
    #define NO_RSA
#endif

/* DH */
#if 0
    #undef NO_DH /* on by default */
    #define WOLFSSL_DH_CONST /* don't rely on pow/log */
    #define HAVE_FFDHE_2048
    #define HAVE_FFDHE_3072
    #define HAVE_DH_DEFAULT_PARAMS
    //#define WOLFSSL_DH_EXTRA /* Enable additional DH key import/export */
#else
    #define NO_DH
#endif

/* ChaCha20 / Poly1305 */
#if defined(CONFIG_WOLFSSL_CHACHA_POLY)
    #define HAVE_CHACHA
    #define HAVE_POLY1305

    /* Needed for Poly1305 */
    #define HAVE_ONE_TIME_AUTH
#endif

/* Ed25519 / Curve25519 */
#if defined(CONFIG_WOLFSSL_CURVE25519)
    #define HAVE_CURVE25519
    #define HAVE_ED25519 /* ED25519 Requires SHA512 */

    /* Optionally use small math (less flash usage, but much slower) */
    //#define CURVED25519_SMALL
#endif

/* SHA-1 */
#if 0
    #undef  NO_SHA /* on by default */
    //#define USE_SLOW_SHA /* 1k smaller, but 25% slower */
#else
    // #define NO_SHA /* Necessary for pkcs12 tests */
#endif

/* SHA2-256 */
#if 1
    #undef NO_SHA256 /* on by default */
    //#define USE_SLOW_SHA256 /* ~2k smaller and about 25% slower */
    #define WOLFSSL_SHA224
#else
    #define NO_SHA256
#endif

/* SHA2-384/512 */
#if 1
    #define WOLFSSL_SHA384
    #define WOLFSSL_SHA512
    //#define USE_SLOW_SHA512 /* Over twice as small, but 50% slower */
#endif

/* SHA-3 */
#if 1
    #define WOLFSSL_SHA3
#endif

/* AES */
#define HAVE_AES_ECB
/* AES-CBC */
#if 1
    #define HAVE_AES_CBC
#else
    #define NO_AES_CBC
#endif
/* AES-GCM */
#if 1
    #define HAVE_AESGCM
    #define GCM_SMALL /* GCM Method: GCM_TABLE_4BIT, GCM_SMALL, GCM_WORD32 or GCM_TABLE */
    //#define WOLFSSL_AESGCM_STREAM
#endif
//#define HAVE_AES_DECRYPT
//#define WOLFSSL_AES_COUNTER
//#define WOLFSSL_AES_CFB
//#define WOLFSSL_AES_OFB
//#define HAVE_AESCCM
//#define WOLFSSL_AES_XTS

//#define NO_AES_128
//#define NO_AES_192
//#define NO_AES_256
//#define WOLFSSL_AES_SMALL_TABLES
//#define WOLFSSL_AES_NO_UNROLL


/* HKDF */
#if defined(WOLFSSL_TLS13) || defined(CONFIG_WOLFSSL_HKDF)
    #define HAVE_HKDF
#endif

/* CMAC - Zephyr nRF BTLE needs CMAC */
#if 1
    #define WOLFSSL_AES_DIRECT
    #define WOLFSSL_CMAC
#endif


/* Optional Features */
#define WOLFSSL_BASE64_ENCODE /* Enable Base64 encoding */
//#define WC_NO_CACHE_RESISTANT /* systems with cache should enable this for AES, ECC, RSA and DH */
//#define WOLFSSL_CERT_GEN
//#define WOLFSSL_CERT_REQ
//#define WOLFSSL_CERT_EXT
//#define NO_PWDBASED


/* Disable Algorithms */
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
//#define NO_DES3 /* Necessary for pkcs12 tests */

/* PQC families -- each independently selectable so a Kconfig-driven build (no
 * user-provided settings file) can include only what a consumer needs and keep
 * the flash footprint down. All default off. */
#if defined(CONFIG_WOLFSSL_MLKEM)
    #define WOLFSSL_HAVE_MLKEM
    #define WOLFSSL_MLKEM_NO_LARGE_CODE
    #define WOLFSSL_MLKEM_SMALL
    #define WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM
    #define WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM
    #define WOLFSSL_MLKEM_DYNAMIC_KEYS
#endif

#if defined(CONFIG_WOLFSSL_MLDSA)
    #define WOLFSSL_HAVE_MLDSA
    #define WOLFSSL_MLDSA_NO_LARGE_CODE
    #define WOLFSSL_MLDSA_SMALL
    #define WOLFSSL_MLDSA_VERIFY_SMALL_MEM
    #define WOLFSSL_MLDSA_DYNAMIC_KEYS
    #define WOLFSSL_MLDSA_SIGN_SMALL_MEM
    #define WOLFSSL_MLDSA_MAKE_KEY_SMALL_MEM
#endif

#if defined(CONFIG_WOLFSSL_LMS)
    #define WOLFSSL_HAVE_LMS
    #define WOLFSSL_LMS_VERIFY_ONLY
#endif

#if defined(CONFIG_WOLFSSL_XMSS)
    #define WOLFSSL_HAVE_XMSS
    #define WOLFSSL_XMSS_VERIFY_ONLY
#endif

#if defined(CONFIG_WOLFSSL_FALCON)
    #define WOLFSSL_EXPERIMENTAL_SETTINGS /* HAVE_FALCON is gated experimental */
    #define HAVE_FALCON
    /* Small-memory dynamic signer instead of the fast tree-signer (keeps full
     * sign+verify); the default portable integer FPR backend needs no ASM. */
    #define WOLFSSL_FALCON_SIGN_SMALL_MEM
#endif

/* SHA-3 / SHAKE are required by ML-KEM, ML-DSA, and Falcon; enable them (small
 * variant) when any is on, and explicitly disable SHAKE otherwise to keep a
 * non-PQC build lean. */
#if defined(CONFIG_WOLFSSL_MLKEM) || defined(CONFIG_WOLFSSL_MLDSA) || \
    defined(CONFIG_WOLFSSL_FALCON)
    #define WOLFSSL_SHA3_SMALL
    #define WOLFSSL_SHAKE128
    #define WOLFSSL_SHAKE256
#else
    #define WOLFSSL_NO_SHAKE128
    #define WOLFSSL_NO_SHAKE256
#endif


/* ------------------------------------------------------------------------- */
/* Math */
/* ------------------------------------------------------------------------- */
/* Math Options */
/* Multi-precision - generic math for all keys sizes and curves */
#if 1
    #define WOLFSSL_SP_MATH /* no multi-precision math, only single */
#elif 1
    /* wolf mp math (sp_int.c) */
    #define WOLFSSL_SP_MATH_ALL /* use SP math for all key sizes and curves */
    //#define WOLFSSL_SP_NO_MALLOC

    /* use smaller version of code */
    #define WOLFSSL_SP_SMALL

    /* Define the maximum math bits used */
    #if !defined(NO_RSA) || !defined(NO_DH)
        #define SP_INT_BITS 2048
    #elif defined(HAVE_ECC)
        #define SP_INT_BITS 256
    #endif

#elif 1
    /* Fast Math (tfm.c) (stack based and timing resistant) */
    #define USE_FAST_MATH
    #define TFM_TIMING_RESISTANT

    /* Define the maximum math bits used (2 * max) */
    #if !defined(NO_RSA) || !defined(NO_DH)
        #define FP_MAX_BITS (2*2048)
        #ifdef HAVE_ECC
            #define ALT_ECC_SIZE /* use heap allocation for ECC point */
        #endif
    #elif defined(HAVE_ECC)
        #define FP_MAX_BITS (2*256)
    #endif
    #ifdef HAVE_ECC
        //#define TFM_ECC256 /* optional speedup for ECC-256 bit */
    #endif
#else
    /* Normal (integer.c) (heap based, not timing resistant) - not recommended */
    #define USE_INTEGER_HEAP_MATH
#endif

/* Single Precision (optional) */
/* Math written for specific curves and key sizes */
#if 1
    #ifdef HAVE_ECC
        #define WOLFSSL_HAVE_SP_ECC
        //#define WOLFSSL_SP_NO_256
        //#define WOLFSSL_SP_384
        //#define WOLFSSL_SP_521
    #endif
    #ifndef NO_RSA
        #define WOLFSSL_HAVE_SP_RSA
        //#define WOLFSSL_SP_NO_2048
        //#define WOLFSSL_SP_NO_3072
        //#define WOLFSSL_SP_4096
    #endif
    #ifndef NO_DH
        #define WOLFSSL_HAVE_SP_DH
    #endif

    #define WOLFSSL_SP_SMALL      /* use smaller version of code */
    //#define WOLFSSL_SP_NO_MALLOC /* disable heap in wolf/SP math */
    //#define SP_DIV_WORD_USE_DIV /* no div64 */

    #if 0
        /* optional speedup with inline assembly */
        //#define WOLFSSL_SP_ARM_CORTEX_M_ASM /* Cortex-M3+ */
        //#define WOLFSSL_SP_ARM_THUMB_ASM    /* Cortex-M0+ thumb */
        //#define WOLFSSL_SP_ARM32_ASM        /* Cortex-R */
        //#define WOLFSSL_SP_ARM64_ASM        /* Cortex-A */
        //#define WOLFSSL_SP_USE_UDIV
    #endif
#endif

/* ------------------------------------------------------------------------- */
/* Assembly Speedups for Symmetric Algorithms */
/* ------------------------------------------------------------------------- */

#ifdef CONFIG_WOLFCRYPT_ARMASM
    #define WOLFSSL_ARMASM
    #define WOLFSSL_NO_HASH_RAW
    #define WOLFSSL_ARMASM_INLINE /* use inline .c versions */
    #define WOLFSSL_ARMASM_NO_NEON

    /* Default is ARMv8 */

    #if 0 /* ARMv7 */
        #define WOLFSSL_ARM_ARCH 7
        #define WOLFSSL_ARMASM_NO_HW_CRYPTO /* enable if processor does not support aes/sha instructions */
    #endif
#endif

#ifdef CONFIG_WOLFCRYPT_INTELASM
    #define USE_INTEL_SPEEDUP
    #define WOLFSSL_X86_64_BUILD /* 64-bit */
    //#define WOLFSSL_X86_BUILD /* 32-bit */

    /* Issues with building AESNI "_mm_aesimc_si128" always_inline */
    //#define WOLFSSL_AESNI
#endif


/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */
#undef DEBUG_WOLFSSL
#undef NO_ERROR_STRINGS
#ifdef CONFIG_WOLFSSL_DEBUG
    #define DEBUG_WOLFSSL
#else
    #if 1
        #define NO_ERROR_STRINGS
    #endif
#endif


#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_SETTINGS_FILE */

#endif /* CONFIG_WOLFSSL */

#endif /* USER_SETTINGS_H */

