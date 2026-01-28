/* user_settings_pq.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/* Post-Quantum TLS 1.3 with ML-KEM (Kyber) and ML-DSA (Dilithium).
 * Provides quantum-resistant key exchange and signatures.
 * Based on NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) standards.
 *
 * Build and test:
 * cp ./examples/configs/user_settings_pq.h user_settings.h
 * ./configure --enable-usersettings --disable-examples
 * make
 * ./wolfcrypt/test/testwolfcrypt
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------- */
/* Platform */
/* ------------------------------------------------- */
#define WOLFSSL_IGNORE_FILE_WARN

/* ------------------------------------------------- */
/* Math */
/* ------------------------------------------------- */
#define WOLFSSL_SP_MATH_ALL

/* ------------------------------------------------- */
/* TLS 1.3 (required for PQ) */
/* ------------------------------------------------- */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_HKDF
#define WC_RSA_PSS

/* Disable older TLS versions */
#define WOLFSSL_NO_TLS12
#define NO_OLD_TLS

#if 1 /* Session tickets */
    #define HAVE_SESSION_TICKET
#endif
#if 1 /* Server Name Indication */
    #define HAVE_SNI
#endif

/* ------------------------------------------------- */
/* Experimental Settings (required for PQ) */
/* ------------------------------------------------- */
#define WOLFSSL_EXPERIMENTAL_SETTINGS

/* ------------------------------------------------- */
/* ML-KEM / Kyber (Key Encapsulation) */
/* ------------------------------------------------- */
#if 1 /* ML-KEM (FIPS 203) */
    #define WOLFSSL_HAVE_KYBER
    #define WOLFSSL_WC_KYBER
    #define WOLFSSL_KYBER512   /* Level 1: 128-bit security */
    #define WOLFSSL_KYBER768   /* Level 3: 192-bit security */
    #define WOLFSSL_KYBER1024  /* Level 5: 256-bit security */
#endif

/* ------------------------------------------------- */
/* ML-DSA / Dilithium (Signatures) */
/* ------------------------------------------------- */
#if 1 /* ML-DSA (FIPS 204) */
    #define HAVE_DILITHIUM
    #define WOLFSSL_WC_DILITHIUM
    #define DILITHIUM_LEVEL2   /* Level 2: ~128-bit security */
    #define DILITHIUM_LEVEL3   /* Level 3: ~192-bit security */
    #define DILITHIUM_LEVEL5   /* Level 5: ~256-bit security */
    /* Uses FIPS 204 final standard by default */
    #if 0 /* FIPS 204 Draft version */
        #define WOLFSSL_DILITHIUM_FIPS204_DRAFT
    #endif
    #define WOLFSSL_SHAKE128
    #define WOLFSSL_SHAKE256
#endif

/* ------------------------------------------------- */
/* LMS (Stateful Hash-Based Signatures) */
/* ------------------------------------------------- */
#if 0 /* LMS signatures */
    #define WOLFSSL_HAVE_LMS
    #define WOLFSSL_WC_LMS
    #ifndef LMS_LEVELS
        #define LMS_LEVELS 2
    #endif
    #ifndef LMS_HEIGHT
        #define LMS_HEIGHT 10
    #endif
    #ifndef LMS_WINTERNITZ
        #define LMS_WINTERNITZ 8
    #endif
#endif

/* ------------------------------------------------- */
/* XMSS (Stateful Hash-Based Signatures) */
/* ------------------------------------------------- */
#if 0 /* XMSS signatures */
    #define WOLFSSL_HAVE_XMSS
    #define WOLFSSL_WC_XMSS
    #ifndef WOLFSSL_XMSS_MAX_HEIGHT
        #define WOLFSSL_XMSS_MAX_HEIGHT 20
    #endif
#endif

/* ------------------------------------------------- */
/* Timing Resistance */
/* ------------------------------------------------- */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* ------------------------------------------------- */
/* Classical ECC (hybrid with PQ) */
/* ------------------------------------------------- */
#if 1 /* ECC for hybrid key exchange */
    #define HAVE_ECC
    #define ECC_USER_CURVES
    #undef  NO_ECC256
    #define HAVE_ECC384
    #define ECC_SHAMIR
#endif

/* ------------------------------------------------- */
/* Curve25519 (hybrid with PQ) */
/* ------------------------------------------------- */
#if 1 /* X25519 for hybrid key exchange */
    #define HAVE_CURVE25519
#endif

/* ------------------------------------------------- */
/* RSA (for legacy compatibility) */
/* ------------------------------------------------- */
#if 1 /* RSA support */
    #undef NO_RSA
    #define WOLFSSL_KEY_GEN
#else
    #define NO_RSA
#endif

/* ------------------------------------------------- */
/* DH */
/* ------------------------------------------------- */
#define NO_DH

/* ------------------------------------------------- */
/* Symmetric Ciphers */
/* ------------------------------------------------- */
#define HAVE_AESGCM
#define GCM_TABLE_4BIT

#if 1 /* ChaCha20-Poly1305 */
    #define HAVE_CHACHA
    #define HAVE_POLY1305
    #define HAVE_ONE_TIME_AUTH
#endif

/* ------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------- */
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3

/* ------------------------------------------------- */
/* RNG */
/* ------------------------------------------------- */
#define HAVE_HASHDRBG

/* ------------------------------------------------- */
/* ASN / Certificates */
/* ------------------------------------------------- */
#define WOLFSSL_ASN_TEMPLATE

#if 1 /* Certificate generation with PQ algorithms */
    #define WOLFSSL_CERT_GEN
    #define WOLFSSL_CERT_REQ
    #define WOLFSSL_CERT_EXT
#endif

/* ------------------------------------------------- */
/* Disabled Algorithms */
/* ------------------------------------------------- */
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_DES3_TLS_SUITES
#define NO_PSK
#define NO_PWDBASED

/* ------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------- */
#if 0 /* Enable debug logging */
    #define DEBUG_WOLFSSL
#endif
#if 0 /* Disable error strings */
    #define NO_ERROR_STRINGS
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
