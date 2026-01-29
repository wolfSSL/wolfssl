/* user_settings_openssl_compat.h
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

/* OpenSSL compatibility layer for drop-in replacement.
 * Provides OpenSSL API compatibility for applications migrating from OpenSSL.
 *
 * Build and test:
 * cp ./examples/configs/user_settings_openssl_compat.h user_settings.h
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
/* OpenSSL Compatibility */
/* ------------------------------------------------- */
#define OPENSSL_EXTRA
#if 1 /* Full OpenSSL API compatibility */
    #define OPENSSL_ALL
#endif

/* OpenSSL-compatible names and behavior */
#define WOLFSSL_VERBOSE_ERRORS
#define ERROR_QUEUE_PER_THREAD
#define WOLFSSL_ERROR_CODE_OPENSSL
#define HAVE_WOLFSSL_SSL_H
#define OPENSSL_COMPATIBLE_DEFAULTS

/* Avoid old name conflicts */
#define NO_OLD_RNGNAME
#define NO_OLD_WC_NAMES
#define NO_OLD_SSL_NAMES
#define NO_OLD_SHA_NAMES
#define NO_OLD_MD5_NAME

/* Extra data support (SSL_CTX_set_ex_data, etc.) */
#define HAVE_EX_DATA

/* ------------------------------------------------- */
/* Application Compatibility */
/* ------------------------------------------------- */
#if 0 /* nginx */
    #define WOLFSSL_NGINX
#endif
#if 0 /* HAProxy */
    #define WOLFSSL_HAPROXY
#endif
#if 0 /* Apache httpd */
    #define HAVE_LIGHTY
#endif
#if 0 /* stunnel */
    #define HAVE_STUNNEL
#endif
#if 0 /* OpenVPN */
    #define WOLFSSL_OPENVPN
#endif
#if 0 /* Qt */
    #define WOLFSSL_QT
#endif
#if 0 /* cURL */
    #define WOLFSSL_LIBCURL
#endif
#if 0 /* OpenSSH */
    #define WOLFSSL_OPENSSH
#endif

/* ------------------------------------------------- */
/* Math */
/* ------------------------------------------------- */
#define WOLFSSL_SP_MATH_ALL

/* ------------------------------------------------- */
/* TLS Versions */
/* ------------------------------------------------- */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_EXTENDED_MASTER
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_HKDF
#define WC_RSA_PSS

#if 1 /* TLS 1.2 (for compatibility) */
    #undef WOLFSSL_NO_TLS12
#endif
#if 0 /* Allow older TLS (not recommended) */
    #undef NO_OLD_TLS
#else
    #define NO_OLD_TLS
#endif

/* TLS Extensions */
#define HAVE_SESSION_TICKET
#define HAVE_SNI
#define HAVE_ALPN
#define HAVE_MAX_FRAGMENT
#define HAVE_TRUNCATED_HMAC
#define HAVE_SECURE_RENEGOTIATION
#define HAVE_SERVER_RENEGOTIATION_INFO

/* ------------------------------------------------- */
/* Timing Resistance */
/* ------------------------------------------------- */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* ------------------------------------------------- */
/* ECC */
/* ------------------------------------------------- */
#define HAVE_ECC
#define TFM_ECC256
#define ECC_SHAMIR
#define HAVE_ECC_CDH
#define HAVE_COMP_KEY

/* ------------------------------------------------- */
/* Curve25519 / Ed25519 */
/* ------------------------------------------------- */
#define HAVE_CURVE25519
#define HAVE_ED25519

/* ------------------------------------------------- */
/* Curve448 / Ed448 */
/* ------------------------------------------------- */
#if 1 /* Ed448/X448 */
    #define HAVE_CURVE448
    #define HAVE_ED448
#endif

/* ------------------------------------------------- */
/* RSA */
/* ------------------------------------------------- */
#undef NO_RSA
#define WC_RSA_NO_PADDING
#define WOLFSSL_KEY_GEN

/* ------------------------------------------------- */
/* DH */
/* ------------------------------------------------- */
#undef NO_DH
#define HAVE_FFDHE_2048
#define HAVE_FFDHE_3072
#define HAVE_FFDHE_4096
#define HAVE_DH_DEFAULT_PARAMS
#define WOLFSSL_DH_EXTRA

/* ------------------------------------------------- */
/* Symmetric Ciphers */
/* ------------------------------------------------- */
#define HAVE_AESGCM
#define GCM_TABLE_4BIT
#define WOLFSSL_AESGCM_STREAM
#define HAVE_AESCCM
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_OFB
#define WOLFSSL_AES_CFB
#define HAVE_AES_ECB
#define HAVE_AES_KEYWRAP
#define HAVE_AES_DECRYPT

#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_ONE_TIME_AUTH
#define HAVE_XCHACHA

/* ------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------- */
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE256

#define HAVE_BLAKE2
#define HAVE_BLAKE2B
#define HAVE_BLAKE2S

/* ------------------------------------------------- */
/* Additional Features */
/* ------------------------------------------------- */
#define HAVE_HASHDRBG
#define WOLFSSL_CMAC
#define WOLFSSL_DES_ECB
#define HAVE_CTS
#define HAVE_HKDF
#define HAVE_X963_KDF
#define HAVE_KEYING_MATERIAL
#define WOLFSSL_HAVE_PRF

/* ------------------------------------------------- */
/* Certificates */
/* ------------------------------------------------- */
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_EXT
#define WOLFSSL_MULTI_ATTRIB
#define WOLFSSL_DER_LOAD
#define WOLFSSL_PEM_TO_DER
#define WOLFSSL_DER_TO_PEM
#define WOLFSSL_ALT_NAMES

#define HAVE_CRL
#define HAVE_OCSP
#define HAVE_CERTIFICATE_STATUS_REQUEST
#define HAVE_CERTIFICATE_STATUS_REQUEST_V2

/* ------------------------------------------------- */
/* Encoding */
/* ------------------------------------------------- */
#define WOLFSSL_BASE16
#define WOLFSSL_BASE64_ENCODE

/* ------------------------------------------------- */
/* Session Cache */
/* ------------------------------------------------- */
#define HAVE_EXT_CACHE
#define SESSION_CERTS
#define PERSIST_SESSION_CACHE
#define PERSIST_CERT_CACHE

/* ------------------------------------------------- */
/* PKCS */
/* ------------------------------------------------- */
#define HAVE_PKCS8

/* ------------------------------------------------- */
/* Disabled Algorithms */
/* ------------------------------------------------- */
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_PSK

/* ------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------- */
#if 0 /* Enable debug logging */
    #define DEBUG_WOLFSSL
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
