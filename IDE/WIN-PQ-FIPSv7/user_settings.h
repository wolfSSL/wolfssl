#ifndef _WIN_USER_SETTINGS_H_
#define _WIN_USER_SETTINGS_H_

/* For FIPS 140-2 3389 build set to "#if 1" */
#if 0
#undef HAVE_FIPS
#define HAVE_FIPS
#undef HAVE_FIPS_VERSION
#define HAVE_FIPS_VERSION 2
#undef HAVE_FIPS_VERSION_MINOR
#define HAVE_FIPS_VERSION_MINOR 0
#endif

/* Set the following to 1 for WCv5.0-RC12 build. */
#if 1   /* wolfSSL FIPS 140-3 v7.0.0 PQ module (Windows MSVC) */
#undef  HAVE_FIPS
#define HAVE_FIPS
#undef  HAVE_FIPS_VERSION
#define HAVE_FIPS_VERSION 7
#undef  HAVE_FIPS_VERSION_MAJOR
#define HAVE_FIPS_VERSION_MAJOR 7
#undef  HAVE_FIPS_VERSION_MINOR
#define HAVE_FIPS_VERSION_MINOR 0
#undef  HAVE_FIPS_VERSION_PATCH
#define HAVE_FIPS_VERSION_PATCH 0
/* FIPS Ready, matching the Linux validated options.h: settings.h then forces
 * HAVE_FIPS_VERSION 7 and selects FIPS 186-4, as the Linux module does. */
#define WOLFSSL_FIPS_READY
#endif

/* ===== Operational test (optest) build toggle =====
 * Define OPTEST_BUILD for the optest variant (MD5 + force-failure injection +
 * verbose FIPS logging).  Leave UNDEFINED for production. */
/* #define OPTEST_BUILD */  /* OFF */
#ifdef OPTEST_BUILD
    #define HAVE_FORCE_FIPS_FAILURE
    #define DEBUG_FIPS_VERBOSE
    /* MSVC C has no C99 VLAs; the optest test.c sizes buffers with `const`
     * variables -> route them to the heap (XMALLOC) via WOLFSSL_SMALL_STACK. */
    #define WOLFSSL_SMALL_STACK
    #define NO_MAIN_DRIVER
    #define USE_CERT_BUFFERS_2048
    #define USE_CERT_BUFFERS_256
    #define OPTEST_LOGGING_ENABLED
    #define OPTEST_INVALID_LOGGING_ENABLED
    #define OPTEST_LOG_TE_MAPPING
#endif

/* ===== wolfACVP harness build toggle =====
 * The harness needs heap-routed buffers and the embedded cert/key buffers, but
 * not the optest force-failure/verbose logs.  Exclusive with OPTEST_BUILD. */
#define HARNESS_BUILD  /* ON (OPTEST_BUILD must stay OFF) */
#ifdef HARNESS_BUILD
    #define WOLFSSL_SMALL_STACK
    #define USE_CERT_BUFFERS_2048
    #define USE_CERT_BUFFERS_256
#endif

/* x86_64 AES-NI PAA toggle.  Default OFF = pure-C AES, matching the Linux
 * validated options.h; x64 only, Win32 stays pure-C. */
/* #define WOLFSSL_USE_AESNI_PAA */


/* Verify this is Windows */
#ifndef _WIN32
#error This user_settings.h header is only designed for Windows
#endif

/* Configurations */
#if defined(HAVE_FIPS)
    /* FIPS */
    #define OPENSSL_EXTRA
    #define HAVE_THREAD_LS
    #define WOLFSSL_KEY_GEN
    #define HAVE_AESGCM
    #define HAVE_HASHDRBG
    #define WOLFSSL_SHA384
    #define WOLFSSL_SHA512
    #define NO_PSK
    #define NO_RC4
    #define NO_DSA
    #define NO_MD4

    #if defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)
        #define WOLFSSL_SHA224
        #define WOLFSSL_SHA3
        #define WC_RSA_PSS
        #define WC_RSA_NO_PADDING
        #define HAVE_ECC
        #define HAVE_ECC384
        #define HAVE_ECC521
        #define HAVE_SUPPORTED_CURVES
        #define HAVE_TLS_EXTENSIONS
        #define ECC_SHAMIR
        #define HAVE_ECC_CDH
        #define ECC_TIMING_RESISTANT
        #define TFM_TIMING_RESISTANT
        #define WOLFSSL_AES_COUNTER
        #define WOLFSSL_AES_DIRECT
        #define HAVE_AES_ECB
        #define HAVE_AESCCM
        #define WOLFSSL_CMAC
        #define HAVE_HKDF
        #define WOLFSSL_VALIDATE_ECC_IMPORT
        #define WOLFSSL_VALIDATE_FFC_IMPORT
        #define HAVE_FFDHE_Q
    #ifdef _WIN64
        #define WOLFSSL_AESNI
    #endif
    #endif /* FIPS v2 */
    #if defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 5)
        #define NO_DES
        #define NO_DES3
        /* MD5 stays disabled for production; the optest build enables it to
         * prove module isolation.  MD5 is outside the in-core boundary. */
        #ifndef OPTEST_BUILD
        #define NO_MD5
        #endif
        #define NO_OLD_TLS
        #define WOLFSSL_TLS13
        #define HAVE_TLS_EXTENSIONS
        #define HAVE_SUPPORTED_CURVES
        #define GCM_TABLE_4BIT
        #define WOLFSSL_NO_SHAKE256
        #define WOLFSSL_VALIDATE_ECC_KEYGEN
        #define WOLFSSL_ECDSA_SET_K
        /* Match Linux options.h: limits the all-zero digest rejection to
         * deterministic-K signing, so random-k ECDSA over it still succeeds. */
        #define WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT
        #define WOLFSSL_WOLFSSH
        #define WOLFSSL_PUBLIC_MP
        #define WC_RNG_SEED_CB
        /* v7 uses SP math instead of TFM/fast-math, matching the Linux
         * validated options.h.  settings.h auto-#undefs USE_FAST_MATH. */
        #define WOLFSSL_SP_MATH_ALL
        #define WOLFSSL_SP_INT_NEGATIVE
        #define SP_INT_BITS 8192
        #define ECC_USER_CURVES
        /* Allow P-192/P-224 in FIPS mode (matches Linux options.h); without
         * this the FIPS default min key size rejects P-224 -> ECC test -170. */
        #define ECC_MIN_KEY_SZ 192
        #define HAVE_ECC192
        #define HAVE_ECC224
        #define HAVE_ECC256
        #define HAVE_ECC384
        #define HAVE_ECC521
        #define HAVE_FFDHE_2048
        #define HAVE_FFDHE_3072
        #define HAVE_FFDHE_4096
        #define HAVE_FFDHE_6144
        #define HAVE_FFDHE_8192
        #define WOLFSSL_AES_OFB
        #define FP_MAX_BITS 16384
    #endif /* FIPS v5 */
    #if defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 6)
    #ifndef WOLFSSL_USE_AESNI_PAA
        #undef WOLFSSL_AESNI /* default OFF (pure-C, match Linux) */
    #endif
        #define HAVE_ED25519
        /* Curve25519/Curve448 (X25519/X448) are NOT in the v7 module: Linux
         * options.h defines only Ed25519/Ed448. */
        #define WOLFSSL_ED25519_STREAMING_VERIFY
        #define HAVE_ED25519_KEY_IMPORT
        #define HAVE_ED448
        #define HAVE_ED448_KEY_IMPORT
        #define WOLFSSL_ED448_STREAMING_VERIFY
        #undef  WOLFSSL_NO_SHAKE256
        #define WOLFSSL_SHAKE256
        #define WOLFSSL_SHAKE128
        #define WOLFSSL_AES_CFB
        #define WOLFSSL_AES_XTS
        #define WOLFSSL_AESXTS_STREAM
        #define WOLFSSL_AESGCM_STREAM
        #define HAVE_AES_KEYWRAP
        #define WC_SRTP_KDF
        #define HAVE_PBKDF2
        #define WOLFCRYPT_FIPS_CORE_HASH_VALUE \
      AE8F969C072FB4A87B5C594F96162002F3CCEB6026BDB2553C8621AE197F7059 //woPAA
      //E257E8C21764333E4710316D208A90D4ECA0682D6F40DC3F4A6E259D4752E306 //wPAA
        /* SHA-512/224 and SHA-512/256 are approved v7 algorithms and the
         * wolfACVP harness references them, so they must NOT be disabled. */
        /* #define WOLFSSL_NOSHA512_224 */
        /* #define WOLFSSL_NOSHA512_256 */

        /* uncomment for FIPS debugging */
        /* #define DEBUG_FIPS_VERBOSE */

        /* uncomment for whole library debugging */
        /* #define DEBUG_WOLFSSL */
    #endif /* FIPS v6 */
    #if defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 7)
        /* v7.0.0 adds the post-quantum algorithms (FIPS 203/204/205,
         * SP 800-208) + the SHA-512 Hash_DRBG (SP 800-90A). */
        /* Classic finite-field DH is retired in the v7 module: the DH FIPS
         * wrappers and the DH CAST are gone. */
        #define NO_DH
        #define WOLFSSL_HAVE_MLKEM           /* ML-KEM  (FIPS 203) */
        #define WOLFSSL_TLS_NO_MLKEM_STANDALONE
        #define WOLFSSL_PQC_HYBRIDS
        #define WOLFSSL_HAVE_MLDSA           /* ML-DSA  (FIPS 204) */
        #define WOLFSSL_HAVE_LMS            /* LMS     (SP 800-208) */
        #define WOLFSSL_LMS_SHA256_192
        #define WOLFSSL_LMS_SHAKE256
        #define WOLFSSL_HAVE_XMSS           /* XMSS    (SP 800-208) */
        #define WOLFSSL_HAVE_SLHDSA         /* SLH-DSA (FIPS 205) */
        #define WOLFSSL_WC_SLHDSA
        #define WOLFSSL_SLHDSA_PARAM_128S
        #define WOLFSSL_SLHDSA_PARAM_128F
        #define WOLFSSL_SLHDSA_PARAM_192S
        #define WOLFSSL_SLHDSA_PARAM_192F
        #define WOLFSSL_SLHDSA_PARAM_256S
        #define WOLFSSL_SLHDSA_PARAM_256F
        #define WOLFSSL_SLHDSA_SHA2
        #define WOLFSSL_SLHDSA_PARAM_SHA2_128S
        #define WOLFSSL_SLHDSA_PARAM_SHA2_128F
        #define WOLFSSL_SLHDSA_PARAM_SHA2_192S
        #define WOLFSSL_SLHDSA_PARAM_SHA2_192F
        #define WOLFSSL_SLHDSA_PARAM_SHA2_256S
        #define WOLFSSL_SLHDSA_PARAM_SHA2_256F
        #define WOLFSSL_DRBG_SHA512        /* SHA-512 Hash_DRBG (SP 800-90A) */

        /* Leave WOLFCRYPT_FIPS_CORE_HASH_VALUE undefined for v7 (undo the v6
         * block above) so fips_test.c uses its verifyCore[] placeholder. */
        #undef WOLFCRYPT_FIPS_CORE_HASH_VALUE
    #endif /* FIPS v7 */
#else
    /* Enables blinding mode, to prevent timing attacks */
    #define WC_RSA_BLINDING

    #if defined(WOLFSSL_LIB)
        /* The lib */
        #define OPENSSL_EXTRA
        #define WOLFSSL_RIPEMD
        #define NO_PSK
        #define HAVE_EXTENDED_MASTER
        #define WOLFSSL_SNIFFER
        #define HAVE_SECURE_RENEGOTIATION

        #define HAVE_AESGCM
        #define WOLFSSL_SHA384
        #define WOLFSSL_SHA512

        #define HAVE_SUPPORTED_CURVES
        #define HAVE_TLS_EXTENSIONS

        #define HAVE_ECC
        #define ECC_SHAMIR
        #define ECC_TIMING_RESISTANT
    #else
        /* The servers and clients */
        #define OPENSSL_EXTRA
        #define NO_PSK
    #endif
#endif /* HAVE_FIPS */

/* For optesting and code review and harness/vector processing */
#if 0
    #undef USE_CERT_BUFFERS_2048
    #define USE_CERT_BUFFERS_2048

    #undef USE_CERT_BUFFERS_256
    #define USE_CERT_BUFFERS_256

    #define NO_MAIN_DRIVER
    #define HAVE_FORCE_FIPS_FAILURE
    #define OPTEST_LOGGING_ENABLED
    #define OPTEST_INVALID_LOGGING_ENABLED
    #define DEBUG_FIPS_VERBOSE
    #define OPTEST_RUNNING_ORGANIC
    #define DEBUG_WOLFSSL
    #define OPTEST_LOG_TE_MAPPING
    #define DEEPLY_EMBEDDED
    #define WORKING_WITH_AEGISOLVE
#endif /* 1 || 0 */

#endif /* _WIN_USER_SETTINGS_H_ */
