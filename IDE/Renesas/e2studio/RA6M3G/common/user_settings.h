/* user_settings.h
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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
#ifndef USER_SETTINGS_H_
#define USER_SETTINGS_H_

/* Hardware Acceleration:  Renesas Secure Cryptography Engine (SCE) */
#define WOLFSSL_SCE

/* Temporary defines. Not suitable for production. */
#ifndef WOLFSSL_SCE
    #define WOLFSSL_GENSEED_FORTEST /* Warning: define your own seed gen */
    #define NO_DEV_RANDOM
#endif
/* End temporary defines */

/* Operating Environment and Threading */
#define FREERTOS
#define FREERTOS_TCP
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define BENCH_EMBEDDED

/* Filesystem and IO */
#define WOLFSSL_NO_CURRDIR
#define NO_WOLFSSL_DIR
#define NO_FILESYSTEM

/* Cryptography Enable Options */
#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_RSA
#define HAVE_SHA256
#define HAVE_TLS_EXTENSIONS
#define HAVE_TRUNCATED_HMAC
#define HAVE_EXTENDED_MASTER
#define HAVE_ALPN
#define HAVE_SNI
#define HAVE_OCSP
#define HAVE_ONE_TIME_AUTH

/* Cryptography Disable options */
#define NO_PWDBASED
#define NO_DSA
#define NO_DES3
#define NO_RABBIT
#define NO_RC4
#define NO_MD4

/* AES */
#define WOLFSSL_AES_DIRECT
#define HAVE_AES_DECRYPT
/* Cipher Modes */
#define HAVE_AESGCM
#define HAVE_AES_ECB
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_XTS
/* No AES 192 hardware support */
#ifdef WOLFSSL_SCE
    #define NO_AES_192
    #ifdef WOLFSSL_AES_192
        #undef WOLFSSL_AES_192
    #endif
#endif

/* ECC */
#define HAVE_ECC
#ifdef WOLFSSL_SCE
    /* Set 256 and 384 curves only */
    #define ECC_USER_CURVES
    #define HAVE_ECC384
    /* VALIDATE_ECC_IMPORT can be removed. This is for extra tests. */
    #define WOLFSSL_VALIDATE_ECC_IMPORT
    /* ECC_KEY_EXPORT can be removed. This is for extra tests. */
    #define HAVE_ECC_KEY_EXPORT
    /* These tests have hard-coded vector parameters that aren't supported
     * by the hardware. These would need to be changed to have the message
     * digest exactly the size of the ECC key.
     */
    #define NO_ECC_VECTOR_TEST
#endif

/* RSA */
#define WOLFSSL_KEY_GEN
#if defined(WOLFSSL_SCE)
    #define WC_NO_RSA_OAEP
#endif
#define NO_INLINE /* Used for ByteReverseWords */

/* wolfSSL/wolfCrypt Software Optimizations */
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_ARM_CORTEX_M_ASM

/* Non-Fast Math may call realloc.
 * This project uses Amazon FreeRTOS and has no realloc support
 */
#define USE_FAST_MATH
#define ALT_ECC_SIZE
#define WOLFSSL_SMALL_STACK
#define WOLFSSL_DH_CONST

/* Hardening */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING /* SCE has TRNG, silence warning for now */


void wolfssl_thread_entry(void *pvParameters);
extern void initialise_monitor_handles(void);

#endif /* USER_SETTINGS_H_ */
