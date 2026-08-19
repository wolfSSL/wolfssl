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

/* Starter wolfSSL settings for this BSP, created on the first build.
 * Edit it for your project and rebuild the platform; it is never
 * overwritten. It applies to the library and every app on the domain. */

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

/* Bare metal: no OS, no filesystem, no sockets. For TLS, provide I/O
 * callbacks with wolfSSL_SSLSetIORecv/wolfSSL_SSLSetIOSend. */
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define WOLFSSL_NO_SOCK
#define WOLFSSL_USER_IO
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define WOLFSSL_IGNORE_FILE_WARN

/* No wall clock: certificate date checks are skipped. For production,
 * remove this and provide XTIME and XGMTIME instead. */
#define NO_ASN_TIME

/* WARNING: test-only seed so builds work out of the box. For production
 * use real entropy: the ASU offload below or CUSTOM_RAND_GENERATE_SEED. */
#define WOLFSSL_GENSEED_FORTEST

/* Math backend */
#define WOLFSSL_SP_MATH_ALL

/* Hardening */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING
#define WC_RSA_PSS /* required for TLS 1.3 with RSA */

/* Algorithms */
#define HAVE_ECC
#define HAVE_AESGCM
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
#define HAVE_HKDF
#define HAVE_HASHDRBG

/* TLS 1.3 */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define NO_DH /* ECDHE only; use HAVE_FFDHE_2048 instead for DH */

/* For the wolfCrypt self-test and benchmark. Define NO_CRYPT_TEST and
 * NO_CRYPT_BENCHMARK to leave them out instead. */
#define USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_256
#define BENCH_EMBEDDED

/* Uncomment for a build with only wolfCrypt (no TLS layer). */
/* #define WOLFCRYPT_ONLY */

/* Uncomment on Cortex-A domains for ARM assembly acceleration. */
/* #define WOLFSSL_ARMASM */
/* #define WOLFSSL_ARMASM_INLINE */

/* Uncomment for Versal Gen 2 ASU hardware crypto offload. Also enable
 * the xilasu library in this BSP, then register in the app with
 * wc_AsuCryptoCb_RegisterDevice(devId). */
/* #define WOLFSSL_VERSAL_GEN2_ASU */

#endif /* USER_SETTINGS_H */
