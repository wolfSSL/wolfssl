/* user_settings_wolftpm.h
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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


/* should be renamed to user_settings.h for customer use
 * generated from configure and wolfssl/options.h using:
 * ./configure --enable-wolftpm --disable-dh --disable-oldtls \
 *    --disable-sha3 --disable-sha512 --disable-sha384 --disable-sha224 \
 *    --disable-pkcs12 --disable-chacha --disable-poly1305 \
 *    --disable-sys-ca-certs --disable-examples
 *
 * Cleaned up by David Garske
 */


#ifndef WOLF_USER_SETTINGS_TPM_H
#define WOLF_USER_SETTINGS_TPM_H

#ifdef __cplusplus
extern "C" {
#endif

#if 1
    /* wolfTPM with TLS example (v1.3 only) */
    #define WOLFSSL_TLS13
    #define WOLFSSL_NO_TLS12
    #define NO_OLD_TLS

    #define HAVE_TLS_EXTENSIONS
    #define HAVE_SUPPORTED_CURVES
    #define HAVE_SERVER_RENEGOTIATION_INFO
    #define HAVE_ENCRYPT_THEN_MAC

    #define HAVE_HKDF
    #define WC_RSA_PSS
    #define WOLFSSL_PSS_LONG_SALT
#else
    /* wolfCrypt only (no SSL/TLS) */
    #define WOLFCRYPT_ONLY
#endif

/* No threading or file system */
#define SINGLE_THREADED
/* File system disable */
#if 0
    #define NO_FILESYSTEM
#endif

/* Enable crypto callbacks */
#define WOLF_CRYPTO_CB

/* Enable PRNG (SHA2-256) */
#define HAVE_HASHDRBG

/* Enable SP math all (sp_int.c) with multi-precision support */
#define WOLFSSL_SP_MATH_ALL

/* Enable hardening (timing resistance) */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* Asymmetric */
#define HAVE_ECC
#undef NO_RSA
#define NO_DH
#ifndef NO_DH
    #define HAVE_FFDHE_2048
    #define HAVE_DH_DEFAULT_PARAMS
#endif

/* Symmetric Hash */
#undef NO_SHA
#undef NO_SHA256
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384

/* Symmetric Cipher */
#define HAVE_AES_KEYWRAP
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_CFB
#define HAVE_AESGCM
#define GCM_TABLE_4BIT

#if 0
    #define HAVE_POLY1305
    #define HAVE_CHACHA
#endif

/* Features */
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_EXT

#define HAVE_PKCS7
#define HAVE_X963_KDF
#define WOLFSSL_BASE64_ENCODE


/* Disables */
#define NO_DSA
#define NO_DES3
#define NO_RC4
#define NO_PSK
#define NO_MD4
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256


#ifdef __cplusplus
}
#endif

#endif /* WOLF_USER_SETTINGS_TPM_H */
