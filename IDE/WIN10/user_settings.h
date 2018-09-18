#ifndef _WIN_USER_SETTINGS_H_
#define _WIN_USER_SETTINGS_H_

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
    #define NO_HC128
    #define NO_RC4
    #define NO_RABBIT
    #define NO_DSA
    #define NO_MD4

    #if defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)
        #define WOLFSSL_SHA224
        #define WOLFSSL_SHA3
        #define WC_RSA_PSS
        #define WC_RSA_NO_PADDING
        #define HAVE_ECC
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
        #define WOLFSSL_AESNI
        #define HAVE_INTEL_RDSEED
        #define FORCE_FAILURE_RDSEED
    #endif /* FIPS v2 */
#else
    /* Enables blinding mode, to prevent timing attacks */
    #define WC_RSA_BLINDING

    #if defined(WOLFSSL_LIB)
        /* The lib */
        #define OPENSSL_EXTRA
        #define WOLFSSL_RIPEMD
        #define WOLFSSL_SHA512
        #define NO_PSK
        #define HAVE_EXTENDED_MASTER
        #define WOLFSSL_SNIFFER
        #define HAVE_TLS_EXTENSIONS
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

#endif /* _WIN_USER_SETTINGS_H_ */
