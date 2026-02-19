
#ifndef USER_SETTINGS_H
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
#define USER_SETTINGS_H

/*#define DEBUG_WOLFSSL*/

#define NO_MAIN_DRIVER
#define USE_CERT_BUFFERS_2048
#define USE_CERT_BUFFERS_256

/* print out cycles per byte with benchmark
 * when component r_wdt WDT is enabled
 */
#define SYNERGY_CYCLE_COUNT
#define BENCH_EMBEDDED

/* Use turn on all SCE acceleration */
#define WOLFSSL_SCE

/* Used to turn off TRNG */
/* #define WOLFSSL_SCE_NO_TRNG */

/* Used to turn off AES hardware acc. */
/* #define WOLFSSL_SCE_NO_AES */

/* Used to turn off HASH hardware acc. */
/* #define WOLFSSL_SCE_NO_HASH */

#if defined(WOLFSSL_SCE_NO_TRNG)
    /* use unsafe test seed if TRNG not used (not for production) */
    #define WOLFSSL_GENSEED_FORTEST
#endif

#define HAVE_ECC
#define ALT_ECC_SIZE

#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_ONE_TIME_AUTH
#define HAVE_AESGCM

#define HAVE_AES_ECB
#define WOLFSSL_AES_DIRECT

#define TFM_TIMING_RESISTANT
#define WC_RSA_BLINDING
#define ECC_TIMING_RESISTANT

#define NO_WOLFSSL_DIR

#define HAVE_NETX
#define THREADX
#define THREADX_NO_DC_PRINTF
#define NO_WRITEV
#define SIZEOF_LONG 4
#define SIZEOF_LONG_LONG 8

#define SP_WORD_SIZE 32
#define WOLFSSL_SP_NO_DYN_STACK
#define WOLFSSL_SP_NO_3072
#define WOLFSSL_SP_MATH
#define WOLFSSL_SP_SMALL
#define WOLFSSL_SP_NO_MALLOC
/*#define WOLFSSL_SP_NONBLOCK*/
#define WOLFSSL_HAVE_SP_DH
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_SP_ARM_CORTEX_M_ASM

/* TLS 1.3 */
#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_FFDHE_2048
#define HAVE_HKDF
#define WC_RSA_PSS

#define HAVE_CURVE25519
#define HAVE_ED25519
#define WOLFSSL_SHA512

/* NETX Duo BSD manual lists the socket len type as an INT */
#undef  XSOCKLENT
#define XSOCKLENT int

#define USE_WOLF_TIMEVAL_T

#endif
