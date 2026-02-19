/* user_settings_pkcs7.h
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

/* PKCS#7 / CMS configuration for signing and encryption.
 * Suitable for S/MIME, firmware signing, secure messaging.
 * No TLS - cryptographic operations only.
 *
 * Build and test:
 * cp ./examples/configs/user_settings_pkcs7.h user_settings.h
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
#define WOLFCRYPT_ONLY
#if 0 /* Single threaded */
    #define SINGLE_THREADED
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
/* PKCS#7 / CMS */
/* ------------------------------------------------- */
#define HAVE_PKCS7

/* PKCS#7 Content Types */
#if 1 /* Signed Data */
    /* Default enabled with HAVE_PKCS7 */
#endif
#if 1 /* Enveloped Data (encryption) */
    /* Default enabled with HAVE_PKCS7 */
#endif
#if 0 /* Compressed Data (requires libz) */
    #define HAVE_LIBZ
#endif
#if 1 /* Authenticated Enveloped Data (AES-GCM) */
    /* Requires HAVE_AESGCM */
#endif

/* PKCS#7 Features */
#define HAVE_X963_KDF
#define HAVE_HKDF

/* ------------------------------------------------- */
/* S/MIME */
/* ------------------------------------------------- */
#if 1 /* S/MIME support */
    #define HAVE_SMIME
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
    #define HAVE_ECC_ENCRYPT  /* ECIES for PKCS#7 */
#endif

/* ------------------------------------------------- */
/* RSA */
/* ------------------------------------------------- */
#if 1 /* RSA support */
    #undef NO_RSA
    #define WOLFSSL_KEY_GEN
    #define WC_RSA_NO_PADDING
#else
    #define NO_RSA
#endif

/* ------------------------------------------------- */
/* Symmetric Ciphers */
/* ------------------------------------------------- */
/* AES (required for PKCS#7) */
#define HAVE_AES_CBC
#define HAVE_AES_DECRYPT
#define HAVE_AES_KEYWRAP
#define WOLFSSL_AES_DIRECT

#if 1 /* AES-GCM (AuthEnvelopedData) */
    #define HAVE_AESGCM
    #define GCM_TABLE_4BIT
#endif

#if 1 /* AES-CCM */
    #define HAVE_AESCCM
#endif

#if 0 /* 3DES (legacy, not recommended) */
    #undef NO_DES3
#else
    #define NO_DES3
#endif

/* ------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------- */
/* SHA-256 required */

#if 1 /* SHA-1 (for legacy compatibility) */
    #undef NO_SHA
#else
    #define NO_SHA
#endif

#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

#if 1 /* SHA-3 */
    #define WOLFSSL_SHA3
#endif

/* ------------------------------------------------- */
/* RNG */
/* ------------------------------------------------- */
#define HAVE_HASHDRBG

/* ------------------------------------------------- */
/* ASN / Certificates */
/* ------------------------------------------------- */
#define WOLFSSL_ASN_TEMPLATE

/* Certificate generation for signing */
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_EXT
#define WOLFSSL_MULTI_ATTRIB

/* Certificate parsing */
#define WOLFSSL_PEM_TO_DER
#define WOLFSSL_DER_TO_PEM
#define WOLFSSL_DER_LOAD

/* ------------------------------------------------- */
/* Encoding */
/* ------------------------------------------------- */
#define WOLFSSL_BASE64_ENCODE

/* ------------------------------------------------- */
/* Disabled Algorithms */
/* ------------------------------------------------- */
#define NO_DH
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
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
