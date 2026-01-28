/* user_settings_ca.h
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

/* Certificate Authority (CA) / PKI configuration.
 * For certificate generation, signing, CRL, OCSP, and CertificateManager.
 * No TLS - certificate operations only.
 *
 * Build and test:
 * cp ./examples/configs/user_settings_ca.h user_settings.h
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
#define NO_TLS  /* Enables CertificateManager without TLS */
#if 0 /* Single threaded */
    #define SINGLE_THREADED
#endif
#define WOLFSSL_IGNORE_FILE_WARN

/* ------------------------------------------------- */
/* Math */
/* ------------------------------------------------- */
#define WOLFSSL_SP_MATH_ALL
#define SP_INT_BITS 4096

/* ------------------------------------------------- */
/* Timing Resistance */
/* ------------------------------------------------- */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* ------------------------------------------------- */
/* Certificate Generation */
/* ------------------------------------------------- */
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_EXT
#define WOLFSSL_MULTI_ATTRIB
#define WOLFSSL_ALT_NAMES
#define WOLFSSL_CUSTOM_OID
#define HAVE_OID_ENCODING

/* Additional certificate features */
#define WOLFSSL_CERT_NAME_ALL
#define WOLFSSL_HAVE_ISSUER_NAMES
#define WOLFSSL_AKID_NAME
#define WOLFSSL_SUBJ_DIR_ATTR
#define WOLFSSL_SUBJ_INFO_ACC

/* ------------------------------------------------- */
/* ASN.1 */
/* ------------------------------------------------- */
#define WOLFSSL_ASN_TEMPLATE
#define WOLFSSL_PEM_TO_DER
#define WOLFSSL_DER_TO_PEM
#define WOLFSSL_DER_LOAD
#define ASN_BER_TO_DER

/* ------------------------------------------------- */
/* CRL (Certificate Revocation List) */
/* ------------------------------------------------- */
#define HAVE_CRL
#if 0 /* CRL file monitoring */
    #define HAVE_CRL_MONITOR
#endif
#define HAVE_CRL_IO
#define HAVE_IO_TIMEOUT

/* ------------------------------------------------- */
/* OCSP (Online Certificate Status Protocol) */
/* ------------------------------------------------- */
#define HAVE_OCSP
#define HAVE_CERTIFICATE_STATUS_REQUEST
#define HAVE_CERTIFICATE_STATUS_REQUEST_V2
#define HAVE_TLS_EXTENSIONS

/* ------------------------------------------------- */
/* ECC */
/* ------------------------------------------------- */
#if 1 /* ECC support */
    #define HAVE_ECC
    #define ECC_USER_CURVES
    #undef  NO_ECC256
    #define HAVE_ECC384
    #define HAVE_ECC521
    #define ECC_SHAMIR
    #define HAVE_COMP_KEY
    #define WOLFSSL_ECDSA_DETERMINISTIC_K_VARIANT
#endif

/* ------------------------------------------------- */
/* Ed25519 / Ed448 */
/* ------------------------------------------------- */
#if 1 /* Ed25519 certificates */
    #define HAVE_ED25519
    #define HAVE_CURVE25519
#endif
#if 1 /* Ed448 certificates */
    #define HAVE_ED448
    #define HAVE_CURVE448
    #define WOLFSSL_SHAKE256
#endif

/* ------------------------------------------------- */
/* RSA */
/* ------------------------------------------------- */
#if 1 /* RSA support */
    #undef NO_RSA
    #define WOLFSSL_KEY_GEN
    #define WC_RSA_PSS
    #define WC_RSA_NO_PADDING
#else
    #define NO_RSA
#endif

/* ------------------------------------------------- */
/* Post-Quantum Certificates */
/* ------------------------------------------------- */
#if 0 /* ML-DSA / Dilithium certificates */
    #define WOLFSSL_EXPERIMENTAL_SETTINGS
    #define HAVE_DILITHIUM
    #define WOLFSSL_WC_DILITHIUM
    #define WOLFSSL_SHAKE128
    #define WOLFSSL_SHAKE256
#endif

/* ------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------- */
/* SHA-256 required */
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3

#if 1 /* SHA-1 (for legacy certificate compatibility) */
    #undef NO_SHA
#else
    #define NO_SHA
#endif

/* ------------------------------------------------- */
/* RNG */
/* ------------------------------------------------- */
#define HAVE_HASHDRBG

/* ------------------------------------------------- */
/* Encoding */
/* ------------------------------------------------- */
#define WOLFSSL_BASE64_ENCODE
#define WOLFSSL_BASE16

/* ------------------------------------------------- */
/* Disabled Algorithms */
/* ------------------------------------------------- */
#define NO_DH
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_PSK
#define NO_PWDBASED
#define NO_OLD_TLS

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
