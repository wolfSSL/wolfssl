#ifndef _WIN_USER_SETTINGS_H_
#define _WIN_USER_SETTINGS_H_

/* Verify this is Windows */
#ifndef _WIN32
#error This user_settings.h header is only designed for Windows
#endif

#define USE_WOLFSSL_IO
#define HAVE_AESGCM
#define WOLFSSL_TLS13
#define HAVE_HKDF
#define HAVE_FFDHE_4096
#define WC_RSA_PSS
#define WOLFSSL_DTLS
#define WOLFSSL_DTLS13
#define WOLFSSL_SEND_HRR_COOKIE
#define WOLFSSL_DTLS_CID

/* Configurations */
#if defined(HAVE_FIPS)
    /* FIPS */
    #define OPENSSL_EXTRA
    #define HAVE_THREAD_LS
    #define WOLFSSL_KEY_GEN
    #define HAVE_HASHDRBG
    #define WOLFSSL_SHA384
    #define WOLFSSL_SHA512
    #define NO_PSK
    #define NO_RC4
    #define NO_DSA
    #define NO_MD4

    #define GCM_NONCE_MID_SZ 12
#else
    /* Enables blinding mode, to prevent timing attacks */
    #define WC_RSA_BLINDING
    #define NO_MULTIBYTE_PRINT

    #define HAVE_CRL
    #define HAVE_CRL_MONITOR

    #define HAVE_OCSP
    #define HAVE_OCSP_RESPONDER
    #define WOLFSSL_CERT_GEN
    #define HAVE_CERTIFICATE_STATUS_REQUEST

    #if defined(WOLFSSL_LIB)
        /* The lib */
        #define OPENSSL_EXTRA
        #define WOLFSSL_RIPEMD
        #define NO_PSK
        #define HAVE_EXTENDED_MASTER
        #define WOLFSSL_SNIFFER
        #define HAVE_SECURE_RENEGOTIATION

        #define HAVE_AESGCM
        #define WOLFSSL_AESGCM_STREAM
        #define WOLFSSL_SHA384
        #define WOLFSSL_SHA512

        #define HAVE_SUPPORTED_CURVES
        #define HAVE_TLS_EXTENSIONS

        #define HAVE_ECC
        #define ECC_SHAMIR
        #define ECC_TIMING_RESISTANT

        #define WOLFSSL_SP_X86_64
        #define SP_INT_BITS  4096

        /* Optional Performance Speedups */
        #if 0
            /* AESNI on x64 */
            #ifdef _WIN64
                #define HAVE_INTEL_RDSEED
                #define WOLFSSL_AESNI
                #define HAVE_INTEL_AVX1
                #if 0
                    #define HAVE_INTEL_AVX2
                #endif

                #define USE_INTEL_CHACHA_SPEEDUP
                #define USE_INTEL_POLY1305_SPEEDUP
            #endif

            /* Single Precision Support.  Sizes assembled by default are
             * RSA/DH 2048 and 3072 and ECC P-256. */
            #define WOLFSSL_SP
            #define WOLFSSL_HAVE_SP_ECC
            #define WOLFSSL_HAVE_SP_DH
            #define WOLFSSL_HAVE_SP_RSA

            /* Opt in Single Precision sizes.  ml64.exe cannot read this
             * header, so each of these that is enabled for the C build must
             * also be passed to the assembler as /DWOLFSSL_SP_xxx or the link
             * fails with LNK2001 on sp_384_*, sp_521_*, sp_4096_* or
             * sp_1024_*.  wolfssl.vcxproj and wolfssl-VS2022.vcxproj already
             * assemble all of them - see the WolfSSLSpAsmDefs property in
             * those files - so nothing extra is needed there.  Note that
             * WOLFSSL_SP_4096 is also defined automatically when SP DH is
             * used with FFDHE 4096. */
            #if 0
                #define WOLFSSL_SP_384
                #define WOLFSSL_SP_521
                #define WOLFSSL_SP_4096
            #endif

            #ifdef _WIN64
                /* Old versions of MASM compiler do not recognize newer
                 * instructions. */
                #if 0
                    #define NO_AVX2_SUPPORT
                    #define NO_MOVBE_SUPPORT
                #endif
                #define WOLFSSL_SP_ASM
                #define WOLFSSL_SP_X86_64_ASM
            #endif
        #endif
    #else
        /* The servers and clients */
        #define OPENSSL_EXTRA
        #define NO_PSK
    #endif
#endif /* HAVE_FIPS */

#endif /* _WIN_USER_SETTINGS_H_ */
