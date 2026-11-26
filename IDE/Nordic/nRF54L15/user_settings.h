/* user_settings.h
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

/* wolfCrypt configuration for the CRACEN test on the nRF54L15 DK: the hash,
 * cipher, MAC and RNG set the Cryptomaster and TRNG accelerate, and the public
 * key algorithms the PK engine accelerates. */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* the port */
#define WOLFSSL_NRF54L_CRACEN

/* platform: bare metal, one thread, no OS services */
#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define WOLFSSL_NO_SOCK
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SIZEOF_LONG      4
#define SIZEOF_LONG_LONG 8
#define WOLFSSL_IGNORE_FILE_WARN
#define NO_ASN_TIME

/* hashes */
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define NO_MD5
#define NO_MD4

/* AES modes and MACs */
#define HAVE_AES_CBC
#define HAVE_AES_ECB
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_COUNTER
#define HAVE_AESGCM
#define HAVE_AESCCM
#define WOLFSSL_CMAC

/* RNG: Hash-DRBG seeded from the TRNG */
#define HAVE_HASHDRBG

/* public key: ECC on the NIST curves the engine accelerates plus two it
 * takes as generic parameter sets, RSA, DH, X25519 and Ed25519 */
#define HAVE_ECC
#define ECC_USER_CURVES
#define ECC_MIN_KEY_SZ 192
#define HAVE_ECC192
#define HAVE_ECC224
#define HAVE_ECC384
#define HAVE_ECC521
#define WOLFSSL_CUSTOM_CURVES
#define HAVE_ECC_BRAINPOOL
#define WC_RSA_BLINDING
#define WOLFSSL_DH_CONST
#define HAVE_CURVE25519
#define HAVE_ED25519
#define USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_256

/* not needed by the test */
#define NO_DSA
#define NO_CERTS
#define NO_PWDBASED
#define NO_PKCS12
#define NO_PKCS8
#define NO_SIG_WRAPPER
#define NO_DES3
#define NO_RC4
#define NO_PSK
#define NO_SESSION_CACHE
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256

/* hardening */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
