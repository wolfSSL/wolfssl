/* user_settings-fips-v7.h
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

/* Algorithm set of ./configure --enable-fips=v7, included by user_settings.h.
 * Platform, TLS and assembly options stay with user_settings.h and Kconfig. */
#ifndef WOLFSSL_ZEPHYR_FIPS_V7_H
#define WOLFSSL_ZEPHYR_FIPS_V7_H

/* fips.c keys its CAST owner on k_current_get() with this set. */
#define HAVE_THREAD_LS

#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING
#define WOLFSSL_USE_ALIGN

/* RNG */
#define HAVE_HASHDRBG
#define WOLFSSL_DRBG_SHA512
#define WC_RNG_EXTRAS
#define WC_RNG_SEED_CB

/* Hashes and KDFs */
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#define HAVE_HKDF
#define HAVE_PBKDF2
#define WC_SRTP_KDF
#define WOLFSSL_WOLFSSH

/* AES */
#define HAVE_AESGCM
#define WOLFSSL_AESGCM_STREAM
#define HAVE_AESCCM
#define HAVE_AES_ECB
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_CFB
#define WOLFSSL_AES_OFB
#define WOLFSSL_AES_XTS
#define WOLFSSL_AESXTS_STREAM
#define HAVE_AES_KEYWRAP
#define WOLFSSL_CMAC

/* RSA */
#define WOLFSSL_KEY_GEN
#define WC_RSA_PSS
#define WOLFSSL_PSS_LONG_SALT
#define WC_RSA_NO_PADDING

/* ECC */
#define HAVE_ECC
#define ECC_SHAMIR
#define ECC_USER_CURVES
#define ECC_MIN_KEY_SZ 192
#define HAVE_ECC192
#define HAVE_ECC224
#define HAVE_ECC256
#define HAVE_ECC384
#define HAVE_ECC521
#define HAVE_ECC_CDH
#define WOLFSSL_ECDSA_SET_K
#define WOLFSSL_VALIDATE_ECC_IMPORT
#define WOLFSSL_VALIDATE_ECC_KEYGEN
#define WOLFSSL_VALIDATE_FFC_IMPORT

/* EdDSA */
#define HAVE_ED25519
#define HAVE_ED25519_KEY_IMPORT
#define WOLFSSL_ED25519_STREAMING_VERIFY
#define HAVE_ED448
#define HAVE_ED448_KEY_IMPORT
#define WOLFSSL_ED448_STREAMING_VERIFY

/* ML-KEM, ML-DSA, LMS, XMSS, SLH-DSA */
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_HAVE_MLDSA
#define WOLFSSL_HAVE_LMS
#define WOLFSSL_LMS_SHA256_192
#define WOLFSSL_LMS_SHAKE256
#define WOLFSSL_HAVE_XMSS
#define WOLFSSL_HAVE_SLHDSA
#define WOLFSSL_WC_SLHDSA
#define WOLFSSL_SLHDSA_PARAM_128S
#define WOLFSSL_SLHDSA_PARAM_128F
#define WOLFSSL_SLHDSA_PARAM_192S
#define WOLFSSL_SLHDSA_PARAM_192F
#define WOLFSSL_SLHDSA_PARAM_256S
#define WOLFSSL_SLHDSA_PARAM_256F
#define WOLFSSL_SLHDSA_SHA2
#define WOLFSSL_SLHDSA_PARAM_SHA2_128S
#define WOLFSSL_SLHDSA_PARAM_SHA2_128F
#define WOLFSSL_SLHDSA_PARAM_SHA2_192S
#define WOLFSSL_SLHDSA_PARAM_SHA2_192F
#define WOLFSSL_SLHDSA_PARAM_SHA2_256S
#define WOLFSSL_SLHDSA_PARAM_SHA2_256F

/* Outside the module */
#define NO_DSA
#define NO_DH
#define NO_MD4
#define NO_MD5
#define NO_RC4
#define NO_DES3

/* Math */
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_SP_INT_NEGATIVE
#define SP_INT_BITS 8192

#endif /* WOLFSSL_ZEPHYR_FIPS_V7_H */
