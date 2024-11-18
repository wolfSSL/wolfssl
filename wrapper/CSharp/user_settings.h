/* user_settings.h
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

/* These are the build settings used by the Visual Studio CSharp wrapper */

#ifndef _WIN_CSHARP_USER_SETTINGS_H_
#define _WIN_CSHARP_USER_SETTINGS_H_

/* Features */
#define NO_OLD_TLS
#define WOLFSSL_TLS13
#define WOLFSSL_DTLS
#define WOLFSSL_DTLS13
#define WOLFSSL_SEND_HRR_COOKIE
#define WOLFSSL_DTLS_CID
#define HAVE_EXTENDED_MASTER
#define HAVE_SECURE_RENEGOTIATION
#define HAVE_SUPPORTED_CURVES
#define HAVE_TLS_EXTENSIONS
#define WOLFSSL_CERT_EXT
#define WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_GEN
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_ECC_ENCRYPT
#define WOLFSSL_PUBLIC_MP
#define NO_MULTIBYTE_PRINT
#define WOLFSSL_KEY_GEN /* RSA key gen */
#define WOLFSSL_ASN_TEMPLATE /* default */
#define WOLFSSL_SHA3

#if 0
    #define OPENSSL_EXTRA
#endif

#define HAVE_CRL
#if 0
    /* start thread that can monitor CRL directory */
    #define HAVE_CRL_MONITOR
#endif

/* Algorithms */
#define HAVE_ED25519
#define HAVE_CURVE25519

#define HAVE_AESGCM
#define WOLFSSL_AESGCM_STREAM
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

#define HAVE_HKDF

#undef  NO_DH
#define HAVE_PUBLIC_FFDHE
#define HAVE_FFDHE_2048
#define HAVE_FFDHE_4096

#undef  NO_RSA
#define WC_RSA_PSS
#define WOLFSSL_PSS_LONG_SALT
#define WC_RSA_BLINDING

#define HAVE_ECC
#define ECC_SHAMIR
#define ECC_TIMING_RESISTANT
#define HAVE_COMP_KEY

/* Disable features */
#define NO_PSK

/* Disable Algorithms */
#define NO_DES3
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_SHA

/* Math */

/* Single Precision Support for RSA/DH 1024/2048/3072 and
 * ECC P-256/P-384 */
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_HAVE_SP_DH
#define WOLFSSL_HAVE_SP_RSA

/* Optional Performance Speedups */
#if 0
    #ifdef _WIN64
        /* Assembly speedups for SP math */
        #define WOLFSSL_SP_X86_64_ASM

        /* Support for RDSEED instruction */
        #define HAVE_INTEL_RDSEED

        /* AESNI on x64 */
        #define WOLFSSL_AESNI

        /* Intel ASM */
        #define USE_INTEL_SPEEDUP
        #define WOLFSSL_X86_64_BUILD

        /* Old versions of MASM compiler do not recognize newer
         * instructions. */
        #if 0
            #define NO_AVX2_SUPPORT
            #define NO_MOVBE_SUPPORT
        #endif
    #endif
#endif

/* Debug logging */
#if 1
    #define DEBUG_WOLFSSL
#else
    /* #define NO_ERROR_STRINGS */
#endif

#endif /* !_WIN_CSHARP_USER_SETTINGS_H_ */
