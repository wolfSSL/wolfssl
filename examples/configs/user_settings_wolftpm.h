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

#undef  WOLFSSL_AES_NO_UNROLL
#define WOLFSSL_AES_NO_UNROLL

#undef  WOLFSSL_AES_SMALL_TABLES
#define WOLFSSL_AES_SMALL_TABLES

#undef  HAVE_C___ATOMIC
#define HAVE_C___ATOMIC 1

#undef  HAVE_THREAD_LS
#define HAVE_THREAD_LS

#undef  NO_DO178
#define NO_DO178

#undef  TFM_NO_ASM
#define TFM_NO_ASM

#undef  WOLFSSL_NO_ASM
#define WOLFSSL_NO_ASM

#undef  WOLFSSL_X86_64_BUILD
#define WOLFSSL_X86_64_BUILD

#undef  SINGLE_THREADED
#define SINGLE_THREADED

#undef  WC_NO_RNG
#define WC_NO_RNG

#undef  ERROR_QUEUE_PER_THREAD
#define ERROR_QUEUE_PER_THREAD

#undef  TFM_TIMING_RESISTANT
#define TFM_TIMING_RESISTANT

#undef  ECC_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT

#undef  NO_SESSION_CACHE
#define NO_SESSION_CACHE

#undef  RSA_LOW_MEM
#define RSA_LOW_MEM

#undef  GCM_SMALL
#define GCM_SMALL

#undef  CURVE25519_SMALL
#define CURVE25519_SMALL

#undef  ED25519_SMALL
#define ED25519_SMALL

#undef  WOLFSSL_SMALL_CERT_VERIFY
#define WOLFSSL_SMALL_CERT_VERIFY

#undef  WOLFSSL_NO_ASYNC_IO
#define WOLFSSL_NO_ASYNC_IO

#undef  USE_SLOW_SHA
#define USE_SLOW_SHA

#undef  USE_SLOW_SHA256
#define USE_SLOW_SHA256

#undef  USE_SLOW_SHA512
#define USE_SLOW_SHA512

#undef  WOLFSSL_AES_CFB
#define WOLFSSL_AES_CFB

#undef  WOLFSSL_USE_ALIGN
#define WOLFSSL_USE_ALIGN

#undef  NO_DSA
#define NO_DSA

#undef  NO_ERROR_STRINGS
#define NO_ERROR_STRINGS

#undef  NO_OLD_TLS
#define NO_OLD_TLS

#undef  WOLFSSL_NO_TLS12
#define WOLFSSL_NO_TLS12

#undef  NO_OLD_TLS
#define NO_OLD_TLS

#undef  NO_WOLFSSL_MEMORY
#define NO_WOLFSSL_MEMORY

#undef  NO_RSA
#define NO_RSA

#undef  NO_DH
#define NO_DH

#undef  NO_ASN
#define NO_ASN

#undef  NO_ASN_CRYPT
#define NO_ASN_CRYPT

#undef  NO_BIG_INT
#define NO_BIG_INT

#undef  NO_CODING
#define NO_CODING

#undef  WOLFSSL_BASE64_ENCODE
#define WOLFSSL_BASE64_ENCODE

#undef  NO_SHA
#define NO_SHA

#undef  NO_OLD_TLS
#define NO_OLD_TLS

#undef  WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE128

#undef  WOLFSSL_NO_SHAKE256
#define WOLFSSL_NO_SHAKE256

#undef  NO_CHACHA_ASM
#define NO_CHACHA_ASM

#undef  WC_NO_HASHDRBG
#define WC_NO_HASHDRBG

#undef  NO_FILESYSTEM
#define NO_FILESYSTEM

#undef  NO_INLINE
#define NO_INLINE

#undef  NO_RC4
#define NO_RC4

#undef  HAVE_ENCRYPT_THEN_MAC
#define HAVE_ENCRYPT_THEN_MAC

#undef  NO_PSK
#define NO_PSK

#undef  NO_MD4
#define NO_MD4

#undef  NO_PKCS12
#define NO_PKCS12

#undef  NO_PWDBASED
#define NO_PWDBASED

#undef  WOLFCRYPT_ONLY
#define WOLFCRYPT_ONLY

#undef  NO_PKCS8
#define NO_PKCS8

#undef  WC_NO_ASYNC_THREADING
#define WC_NO_ASYNC_THREADING

#undef  NO_OLD_RNGNAME
#define NO_OLD_RNGNAME

#undef  NO_OLD_WC_NAMES
#define NO_OLD_WC_NAMES

#undef  NO_OLD_SSL_NAMES
#define NO_OLD_SSL_NAMES

#undef  NO_OLD_SHA_NAMES
#define NO_OLD_SHA_NAMES

#undef  NO_OLD_MD5_NAME
#define NO_OLD_MD5_NAME

#undef  HAVE_DH_DEFAULT_PARAMS
#define HAVE_DH_DEFAULT_PARAMS

#undef  NO_CERTS
#define NO_CERTS

#undef  NO_ASN
#define NO_ASN

#undef  NO_MD5
#define NO_MD5

#undef  NO_OLD_TLS
#define NO_OLD_TLS

#undef  NO_DES3
#define NO_DES3

#undef  HAVE___UINT128_T
#define HAVE___UINT128_T 1


#ifdef __cplusplus
}
#endif

#endif /* WOLF_USER_SETTINGS_TPM_H */
