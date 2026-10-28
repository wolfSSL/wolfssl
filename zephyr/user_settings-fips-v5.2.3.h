/* user_settings-fips-v5.2.3.h
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

/* Algorithm set of ./configure --enable-fips=v5.2.3, included by
 * user_settings.h under CONFIG_WOLFCRYPT_FIPS_V5_2_3, which also selects the
 * RSA, ECC and P-256 options so that file cannot disable them afterwards.
 * TLS, certificate, platform and DRBG seeding options stay with
 * user_settings.h and its Kconfig mapping. */

#ifndef WOLFSSL_ZEPHYR_FIPS_V5_H
#define WOLFSSL_ZEPHYR_FIPS_V5_H

#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING
#define WOLFSSL_USE_ALIGN

/* Hashes and KDFs */
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_NOSHA512_224
#define WOLFSSL_NOSHA512_256
#define WOLFSSL_SHA3
#define HAVE_HKDF
#define WOLFSSL_WOLFSSH

/* AES. The GHASH method follows the Kconfig choice. */
#define HAVE_AESGCM
#define HAVE_AESCCM
#define HAVE_AES_ECB
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_OFB
#define WOLFSSL_CMAC

/* RSA */
#define WOLFSSL_KEY_GEN
#define WC_RSA_PSS
#define WC_RSA_NO_PADDING

/* ECC */
#define HAVE_ECC
#define ECC_SHAMIR
#define ECC_USER_CURVES
#define HAVE_ECC192
#define HAVE_ECC224
#define HAVE_ECC256
#define HAVE_ECC384
#define HAVE_ECC521
#define HAVE_ECC_CDH
#define WOLFSSL_VALIDATE_ECC_IMPORT
#define WOLFSSL_VALIDATE_ECC_KEYGEN

/* DH */
#undef  NO_DH
#define HAVE_FFDHE_Q
#define HAVE_FFDHE_2048
#define HAVE_FFDHE_3072
#define HAVE_FFDHE_4096
#define HAVE_FFDHE_6144
#define HAVE_FFDHE_8192
#define HAVE_DH_DEFAULT_PARAMS
#define HAVE_PUBLIC_FFDHE
#define WOLFSSL_DH_EXTRA
#define WOLFSSL_VALIDATE_FFC_IMPORT

/* Outside the module */
#define NO_DSA
#define NO_MD4
#define NO_MD5
#define NO_RC4
#define NO_DES3
#define NO_DES3_TLS_SUITES

/* Math. SP_SMALL_STACK moves the 4096-bit mod-exp temporaries (11-23 KB of
 * stack on Cortex-M4) to the heap; it touches only the sp_*.c files, which
 * sit outside the v5 boundary. */
#define WOLFSSL_SP_MATH_ALL
#define SP_INT_BITS 8192
#define WOLFSSL_SP_4096
#define WOLFSSL_SP_SMALL_STACK

#endif /* WOLFSSL_ZEPHYR_FIPS_V5_H */
