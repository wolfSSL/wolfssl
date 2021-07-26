/* user_settings.h
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Example 'user-settings.h' for IoT-Safe demo */

#ifndef IOTSAFE_EXAMPLE_USER_SETTINGS_H
#define IOTSAFE_EXAMPLE_USER_SETTINGS_H
#include <stdint.h>

#define WOLFSSL_IOTSAFE
#define HAVE_IOTSAFE_HWRNG
#define HAVE_HASHDRBG
#define WOLFSSL_SMALL_STACK

#define WOLFSSL_GENERAL_ALIGNMENT 4
#define DEBUG_WOLFSSL
#define WOLFSSL_LOG_PRINTF
#define DEBUG_WOLFSSL_VERBOSE
#define SINGLE_THREADED
#define WOLFSSL_USER_IO

#define TIME_OVERRIDES

extern volatile unsigned long jiffies;
static inline long XTIME(long *x) { return jiffies;}
#define NO_ASN_TIME
#define WOLFSSL_USER_CURRTIME
#define NO_OLD_RNGNAME
#define SMALL_SESSION_CACHE
#define WOLFSSL_SMALL_STACK
#define TFM_ARM
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT


/* Connect IoT-safe with PK_CALLBACKS */
#define HAVE_PK_CALLBACKS

/* ECC definitions */
#   define HAVE_ECC
#   define ECC_ALT_SIZE
#   define WOLFSSL_HAVE_SP_ECC
#   define USE_CERT_BUFFERS_256

/* SP math */
#define WOLFSSL_SP_MATH
#define WOLFSSL_SP_MATH_ALL
#define WOLFSSL_SP_SMALL
#define WOLFSSL_HAVE_SP_DH
#define SP_WORD_SIZE 32

/* RSA */
#define RSA_LOW_MEM
#define WC_RSA_BLINDING

#define WOLFSSL_DH_CONST

/* TLS settings */
#define NO_OLD_TLS
#define HAVE_TLS_EXTENSIONS
#define HAVE_AES_DECRYPT
#define HAVE_AESGCM
#define GCM_SMALL
#define HAVE_AESCCM
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT

/* TLS 1.3 */
#define WOLFSSL_TLS13
#define HAVE_SUPPORTED_CURVES
#define HAVE_HKDF
#define HAVE_AEAD
#define WC_RSA_PSS
#define HAVE_FFDHE_2048
#define HAVE_SHA384
#define HAVE_SHA512
#define NO_WRITEV
#define NO_FILESYSTEM
#define NO_MAIN_DRIVER

#define NO_RC4
#define NO_DES3

#define htons(x) __builtin_bswap16(x)
#define ntohs(x) __builtin_bswap16(x)
#define ntohl(x) __builtin_bswap32(x)
#define htonl(x) __builtin_bswap32(x)

#endif /* IOTSAFE_EXAMPLE_USER_SETTINGS_H */
