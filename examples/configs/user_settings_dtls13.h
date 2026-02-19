/* user_settings_dtls13.h
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

/* DTLS 1.3 for IoT and UDP applications.
 * Suitable for constrained devices with unreliable networks.
 *
 * Build and test:
 * cp ./examples/configs/user_settings_dtls13.h user_settings.h
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
#if 1 /* Single threaded (typical for IoT) */
    #define SINGLE_THREADED
#endif
#if 0 /* Disable filesystem */
    #define NO_FILESYSTEM
#endif
#define WOLFSSL_USER_IO
#define WOLFSSL_IGNORE_FILE_WARN

/* ------------------------------------------------- */
/* Math */
/* ------------------------------------------------- */
#define WOLFSSL_SP_MATH_ALL
#if 1 /* Small code size for IoT */
    #define WOLFSSL_SP_SMALL
#endif

/* ------------------------------------------------- */
/* DTLS 1.3 */
/* ------------------------------------------------- */
#define WOLFSSL_DTLS
#define WOLFSSL_DTLS13
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_HKDF
#define WC_RSA_PSS

/* Disable older versions */
#define WOLFSSL_NO_TLS12
#define NO_OLD_TLS

/* DTLS-specific features */
#if 1 /* HelloRetryRequest cookie (DoS protection) */
    #define WOLFSSL_SEND_HRR_COOKIE
#endif
#if 0 /* Connection ID (NAT traversal) - requires TLS 1.2 code paths */
    #define WOLFSSL_DTLS_CID
#endif
#if 0 /* Fragmented ClientHello */
    #define WOLFSSL_DTLS_CH_FRAG
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
/* ECC (preferred for IoT) */
/* ------------------------------------------------- */
#define HAVE_ECC
#define ECC_USER_CURVES
#undef  NO_ECC256
#if 0 /* P-384 */
    #define HAVE_ECC384
#endif
#define ECC_SHAMIR

/* ------------------------------------------------- */
/* Curve25519 / Ed25519 */
/* ------------------------------------------------- */
#if 1 /* X25519 key exchange (efficient for IoT) */
    #define HAVE_CURVE25519
    #define CURVE25519_SMALL
#endif

/* ------------------------------------------------- */
/* RSA */
/* ------------------------------------------------- */
#if 0 /* RSA support (larger, disable for constrained devices) */
    #undef NO_RSA
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
/* AES-GCM */
#define HAVE_AESGCM
#if 1 /* Small GCM tables for IoT */
    #define GCM_SMALL
#else
    #define GCM_TABLE_4BIT
#endif

#if 1 /* ChaCha20-Poly1305 (efficient in software) */
    #define HAVE_CHACHA
    #define HAVE_POLY1305
    #define HAVE_ONE_TIME_AUTH
#endif

#if 1 /* AES-CCM (common in IoT) */
    #define HAVE_AESCCM
#endif

/* ------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------- */
/* SHA-256 required */
#if 1 /* Smaller/slower SHA */
    #define USE_SLOW_SHA256
#endif

/* ------------------------------------------------- */
/* RNG */
/* ------------------------------------------------- */
#define HAVE_HASHDRBG

/* ------------------------------------------------- */
/* ASN / Certificates */
/* ------------------------------------------------- */
#define WOLFSSL_ASN_TEMPLATE

/* ------------------------------------------------- */
/* Disabled Algorithms */
/* ------------------------------------------------- */
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_SHA
#define NO_DES3
#define NO_DES3_TLS_SUITES
#define NO_PSK
#define NO_PWDBASED

/* ------------------------------------------------- */
/* Memory Optimization */
/* ------------------------------------------------- */
#if 1 /* Small stack for embedded */
    #define WOLFSSL_SMALL_STACK
#endif
#if 0 /* Static memory (no malloc) */
    #define WOLFSSL_STATIC_MEMORY
    #define WOLFSSL_NO_MALLOC
#endif
#define NO_SESSION_CACHE

/* ------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------- */
#if 0 /* Enable debug logging */
    #define DEBUG_WOLFSSL
#endif
#if 1 /* Disable error strings to save flash */
    #define NO_ERROR_STRINGS
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
