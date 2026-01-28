/* user_settings_rsa_only.h
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

/* RSA-only configuration (no ECC).
 * For legacy systems that require RSA-only cipher suites.
 * Supports TLS 1.2 and 1.3 with RSA certificates.
 *
 * Build and test:
 * cp ./examples/configs/user_settings_rsa_only.h user_settings.h
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
#define WOLFSSL_IGNORE_FILE_WARN

/* ------------------------------------------------- */
/* Math */
/* ------------------------------------------------- */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_SP_4096

#if 0 /* Small code size */
    #define WOLFSSL_SP_SMALL
#endif

/* ------------------------------------------------- */
/* TLS */
/* ------------------------------------------------- */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_EXTENDED_MASTER
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_HKDF
#define WC_RSA_PSS

/* TLS 1.2 for legacy compatibility */
#if 1 /* Enable TLS 1.2 */
    #undef WOLFSSL_NO_TLS12
#else
    #define WOLFSSL_NO_TLS12
#endif
#define NO_OLD_TLS

/* TLS Extensions */
#if 1 /* Session tickets */
    #define HAVE_SESSION_TICKET
#endif
#if 1 /* Server Name Indication */
    #define HAVE_SNI
#endif
#if 1 /* Secure renegotiation */
    #define HAVE_SECURE_RENEGOTIATION
    #define HAVE_SERVER_RENEGOTIATION_INFO
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
#define WC_RSA_BLINDING

/* ------------------------------------------------- */
/* RSA */
/* ------------------------------------------------- */
#undef NO_RSA

/* RSA key sizes */
#if 1 /* 2048-bit (minimum recommended) */
    /* Always enabled */
#endif
#if 1 /* 3072-bit */
    /* Enabled via WOLFSSL_SP_MATH_ALL */
#endif
#if 1 /* 4096-bit */
    #define WOLFSSL_SP_4096
#endif

/* RSA features */
#define WOLFSSL_KEY_GEN
#define WC_RSA_NO_PADDING

#if 0 /* RSA-PSS only (no PKCS#1 v1.5) */
    #define WC_RSA_PSS_ONLY
#endif

#if 0 /* Low memory RSA */
    #define RSA_LOW_MEM
#endif

/* ------------------------------------------------- */
/* DH (for TLS 1.2 key exchange) */
/* ------------------------------------------------- */
#if 1 /* DH key exchange */
    #undef NO_DH
    #define HAVE_FFDHE_2048
    #define HAVE_FFDHE_3072
    #define HAVE_FFDHE_4096
    #define HAVE_DH_DEFAULT_PARAMS
    #define WOLFSSL_HAVE_SP_DH
#else
    #define NO_DH
#endif

/* ------------------------------------------------- */
/* ECC - Disabled */
/* ------------------------------------------------- */
#define NO_ECC
/* Note: TLS 1.3 typically requires ECDHE, but can work with
 * FFDHE (DH) key exchange with RSA certificates */

/* ------------------------------------------------- */
/* Symmetric Ciphers */
/* ------------------------------------------------- */
/* AES-GCM (required for TLS 1.3) */
#define HAVE_AESGCM
#define GCM_TABLE_4BIT

/* AES-CBC (for TLS 1.2) */
#define HAVE_AES_CBC
#define HAVE_AES_DECRYPT

#if 1 /* ChaCha20-Poly1305 */
    #define HAVE_CHACHA
    #define HAVE_POLY1305
    #define HAVE_ONE_TIME_AUTH
#endif

#if 0 /* AES-CCM */
    #define HAVE_AESCCM
#endif

#if 0 /* Additional AES modes */
    #define WOLFSSL_AES_COUNTER
    #define WOLFSSL_AES_DIRECT
#endif

/* ------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------- */
/* SHA-256 required */
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

#if 1 /* SHA-1 (for TLS 1.2 compatibility) */
    #undef NO_SHA
#else
    #define NO_SHA
#endif

/* ------------------------------------------------- */
/* RNG */
/* ------------------------------------------------- */
#define HAVE_HASHDRBG

/* ------------------------------------------------- */
/* ASN / Certificates */
/* ------------------------------------------------- */
#define WOLFSSL_ASN_TEMPLATE

#if 1 /* Certificate generation */
    #define WOLFSSL_CERT_GEN
    #define WOLFSSL_CERT_REQ
    #define WOLFSSL_CERT_EXT
#endif

#if 1 /* CRL/OCSP */
    #define HAVE_CRL
    #define HAVE_OCSP
#endif

/* ------------------------------------------------- */
/* Disabled Algorithms */
/* ------------------------------------------------- */
#define NO_DSA
#define NO_RC4
#define NO_MD4
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
