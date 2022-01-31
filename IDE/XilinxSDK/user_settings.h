/* user_settings.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

/*
 * user_settings.h
 *
 *  Created on: Mar 20, 2020
 *  Generated using: 
 * ./configure --enable-cryptonly --enable-armasm --enable-ecc --enable-aesgcm --enable-pwdbased --enable-sp --enable-sp-asm \
 *     --disable-dh --disable-sha --disable-md5 --disable-sha224 --disable-aescbc --disable-shake256 
 *  Result: wolfssl/options.h
 */

#ifndef SRC_USER_SETTINGS_H_
#define SRC_USER_SETTINGS_H_

/* Disable all TLS support, only wolfCrypt features */
#define WOLFCRYPT_ONLY

/* Xilinx SDK */
#define WOLFSSL_XILINX
#define SINGLE_THREADED
#define NO_FILESYSTEM

/* Platform - remap printf */
#include "xil_printf.h"
#define XPRINTF xil_printf

/* Enable ARMv8 (Aarch64) assembly speedups - SHA256 / AESGCM */
/* Note: Requires CFLAGS="-mcpu=generic+crypto -mstrict-align" */
#define WOLFSSL_ARMASM

/* Math */
#define USE_FAST_MATH
#define FP_MAX_BITS (4096 * 2) /* Max RSA 4096-bit */

/* Use Single Precision assembly math speedups for ECC */
#define WOLFSSL_SP
#define WOLFSSL_SP_ASM
#define WOLFSSL_SP_ARM64_ASM
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_HAVE_SP_RSA

/* Random: HashDRGB / P-RNG (SHA256) */
#define HAVE_HASHDRBG
extern unsigned char my_rng_seed_gen(void);
#define CUSTOM_RAND_GENERATE  my_rng_seed_gen

/* Timing Resistance */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* ECC */
#define HAVE_ECC
#define TFM_ECC256
#define ECC_SHAMIR

/* DH */
#undef NO_DH
#define WOLFSSL_DH_CONST
#define HAVE_FFDHE_2048
#define HAVE_FFDHE_4096

/* Curve25519 / Ed25519 */
#define HAVE_CURVE25519
#define HAVE_ED25519 /* ED25519 Requires SHA512 */
/* 25519 assumes UINT128_T is available for Aarch64 */
#ifndef HAVE___UINT128_T
#define HAVE___UINT128_T
#endif

/* ChaCha20 / Poly1305 */
#define HAVE_CHACHA
#define HAVE_POLY1305

/* AES-GCM Only */
#define NO_AES_CBC
#define HAVE_AESGCM

/* Hashing */
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384
#define WOLFSSL_SHA3
#define WOLFSSL_NO_HASH_RAW /* not supported with ARMASM */

/* HKDF */
#define HAVE_HKDF

/* Disable Algorithms */
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_SHA
#define NO_PSK
#define NO_DES3

/* Other */
#define WOLFSSL_IGNORE_FILE_WARN /* Ignore file include warnings */
#define NO_MAIN_DRIVER /* User supplied "main" entry point */
#define BENCH_EMBEDDED /* Use smaller buffers for benchmarking */

/* Test with "wolfssl/certs_test.h" buffers - no file system */
#define USE_CERT_BUFFERS_256
#define USE_CERT_BUFFERS_2048

/* Debugging */
#if 0
	#define DEBUG_WOLFSSL
#endif

#endif /* SRC_USER_SETTINGS_H_ */
