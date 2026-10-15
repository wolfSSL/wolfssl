/* user_settings.h
 *
 * Copyright (C) 2026 wolfSSL Inc.
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#define WOLFCRYPT_ONLY
#define WC_16BIT_CPU
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_DEV_RANDOM
#define WC_NO_RNG
#define NO_BIG_INT
#define NO_ASN
#define NO_RSA
#define NO_DH
#define NO_DSA
#define NO_MD4
#define NO_MD5
#define NO_SHA
#define NO_SHA512
#define NO_DES3
#define NO_RC4
#define NO_PWDBASED
#define NO_PKCS8
#define NO_PKCS12
#define WOLFSSL_SHA224
#define HAVE_CHACHA
#define HAVE_POLY1305
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT
#define HAVE_AESGCM
#define USE_SLOW_SHA256
#define BENCH_EMBEDDED
#define SIZEOF_LONG 4
#define SIZEOF_LONG_LONG 8

#ifdef MSP430_TEST_ECC
    #undef WC_NO_RNG
    #undef NO_BIG_INT
    #define HAVE_ECC
    #define ECC_USER_CURVES
    #define ECC_TIMING_RESISTANT
    #define WOLFSSL_SP_MATH
    #define WOLFSSL_HAVE_SP_ECC
    #define WOLFSSL_SP_ALLOW_16BIT_CPU
    #define SP_WORD_SIZE 32
    /* Deterministic fixture for the simulator only. */
    int msp430_test_seed(unsigned char* output, unsigned long size);
    #define CUSTOM_RAND_GENERATE_SEED msp430_test_seed
#endif

#endif
