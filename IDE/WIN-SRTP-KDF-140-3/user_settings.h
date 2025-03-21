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
#if 1
#undef  HAVE_FIPS
#define HAVE_FIPS
#undef  HAVE_FIPS_VERSION
#define HAVE_FIPS_VERSION 6
#undef  HAVE_FIPS_VERSION_MAJOR
#define HAVE_FIPS_VERSION_MAJOR 6
#undef  HAVE_FIPS_VERSION_MINOR
#define HAVE_FIPS_VERSION_MINOR 0
#undef  HAVE_FIPS_VERSION_PATCH
#define HAVE_FIPS_VERSION_PATCH 0
#endif

/* For FIPS Ready, uncomment the following: */
/* #define WOLFSSL_FIPS_READY */
#ifdef WOLFSSL_FIPS_READY
    #undef HAVE_FIPS
    #define HAVE_FIPS
    #undef HAVE_FIPS_VERSION
    #define HAVE_FIPS_VERSION 5
    #undef HAVE_FIPS_VERSION_MINOR
    #define HAVE_FIPS_VERSION_MINOR 3
#endif


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
        #define NO_MD5
        #define NO_OLD_TLS
        #define WOLFSSL_TLS13
        #define HAVE_TLS_EXTENSIONS
        #define HAVE_SUPPORTED_CURVES
        #define GCM_TABLE_4BIT
        #define WOLFSSL_NO_SHAKE256
        #define WOLFSSL_VALIDATE_ECC_KEYGEN
        #define WOLFSSL_ECDSA_SET_K
        #define WOLFSSL_WOLFSSH
        #define WOLFSSL_PUBLIC_MP
        #define WC_RNG_SEED_CB
        #define TFM_ECC256
        #define ECC_USER_CURVES
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
        #undef WOLFSSL_AESNI /* Comment out if using PAA */
        #define HAVE_ED25519
        #define HAVE_CURVE25519
        #define WOLFSSL_ED25519_STREAMING_VERIFY
        #define HAVE_ED25519_KEY_IMPORT
        #define HAVE_ED448
        #define HAVE_CURVE448
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
        #define WOLFSSL_NOSHA512_224
        #define WOLFSSL_NOSHA512_256

        /* uncomment for FIPS debugging */
        /* #define DEBUG_FIPS_VERBOSE */

        /* uncomment for whole library debugging */
        /* #define DEBUG_WOLFSSL */
    #endif /* FIPS v6 */
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
