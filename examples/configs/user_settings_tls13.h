/* user_settings_tls13.h
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

/* TLS 1.3 only (no TLS 1.2 or older) with modern algorithms.
 * Supports both client and server.
 *
 * Build and test:
 * cp ./examples/configs/user_settings_tls13.h user_settings.h
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
#if 0 /* Single threaded */
    #define SINGLE_THREADED
#endif
#if 0 /* Disable filesystem */
    #define NO_FILESYSTEM
#endif
#define WOLFSSL_IGNORE_FILE_WARN

/* ------------------------------------------------- */
/* Math */
/* ------------------------------------------------- */
#define WOLFSSL_SP_MATH_ALL
#if 0 /* Small code size */
    #define WOLFSSL_SP_SMALL
#endif

/* ------------------------------------------------- */
/* TLS 1.3 */
/* ------------------------------------------------- */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_HKDF
#define WC_RSA_PSS

/* Disable older TLS versions */
#define WOLFSSL_NO_TLS12
#define NO_OLD_TLS

/* TLS 1.3 Extensions */
#if 1 /* Session tickets */
    #define HAVE_SESSION_TICKET
#endif
#if 0 /* Early data (0-RTT) */
    #define WOLFSSL_EARLY_DATA
#endif
#if 0 /* Post-handshake authentication */
    #define WOLFSSL_POST_HANDSHAKE_AUTH
#endif
#if 1 /* Server Name Indication */
    #define HAVE_SNI
#endif

/* Client/Server */
#if 0 /* Client only */
    #define NO_WOLFSSL_SERVER
#endif
#if 0 /* Server only */
    #define NO_WOLFSSL_CLIENT
#endif

/* ------------------------------------------------- */
/* Timing Resistance */
/* ------------------------------------------------- */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* ------------------------------------------------- */
/* ECC */
/* ------------------------------------------------- */
#if 1 /* ECC support */
    #define HAVE_ECC
    #define ECC_USER_CURVES
    #undef  NO_ECC256
    #if 1 /* P-384 */
        #define HAVE_ECC384
    #endif
    #if 0 /* P-521 */
        #define HAVE_ECC521
    #endif
    #define ECC_SHAMIR
#endif

/* ------------------------------------------------- */
/* Curve25519 / Ed25519 */
/* ------------------------------------------------- */
#if 1 /* X25519 key exchange */
    #define HAVE_CURVE25519
#endif
#if 0 /* Ed25519 signatures */
    #define HAVE_ED25519
#endif

/* ------------------------------------------------- */
/* RSA */
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
#if 0 /* DH key exchange (FFDHE) */
    #undef NO_DH
    #define HAVE_FFDHE_2048
    #define HAVE_FFDHE_3072
    #define HAVE_DH_DEFAULT_PARAMS
#else
    #define NO_DH
#endif

/* ------------------------------------------------- */
/* Symmetric Ciphers */
/* ------------------------------------------------- */
/* AES-GCM (required for TLS 1.3) */
#define HAVE_AESGCM
#define GCM_TABLE_4BIT

#if 1 /* ChaCha20-Poly1305 */
    #define HAVE_CHACHA
    #define HAVE_POLY1305
    #define HAVE_ONE_TIME_AUTH
#endif

#if 0 /* AES-CCM */
    #define HAVE_AESCCM
#endif

/* ------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------- */
/* SHA-256 required */
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

/* ------------------------------------------------- */
/* RNG */
/* ------------------------------------------------- */
#define HAVE_HASHDRBG

/* ------------------------------------------------- */
/* ASN / Certificates */
/* ------------------------------------------------- */
#define WOLFSSL_ASN_TEMPLATE

#if 0 /* Certificate generation */
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
#if 0 /* Disable error strings to save flash */
    #define NO_ERROR_STRINGS
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
