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

/* wolfCrypt configuration for the nRF54L15 CRACEN test: the symmetric and
 * hash algorithms the port offloads, no public key, no TLS. */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* The port under test. WC_USE_DEVID and the TRNG seed source follow. */
#define WOLFSSL_NRF54L_CRACEN

/* Platform */
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

/* Hashes */
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define NO_MD5
#define NO_MD4

/* AES */
#define HAVE_AES_CBC
#define HAVE_AES_ECB
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_COUNTER
#define HAVE_AESGCM
#define HAVE_AESCCM
#define WOLFSSL_CMAC

/* RNG: Hash-DRBG seeded from the CRACEN TRNG */
#define HAVE_HASHDRBG

/* Nothing asymmetric, no certificates */
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_ASN
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

/* Hardening flags expected by settings.h even without public key */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
