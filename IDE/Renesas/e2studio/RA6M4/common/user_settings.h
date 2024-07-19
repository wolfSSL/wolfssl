/* user_settings.h
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
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
#if defined(WOLFSSL_RENESAS_SCEPROTECT)
    /* FSP SM stands for Flexible Software Package Security Module
    *  WOLFSSL_RENESAS_FSPSM enables fundamental code when it uses.
    *    e.g. Open/Close/Random generator
    *  WOLFSSL_RENESAS_FSPSPM_TLS enables TLS related code for FSP SM
    *    e.g. Certificate verification, Master Secret Generation
    *  WOLFSSL_RENESAS_SCEPROTECT enables specific code for SCE if needed
    */
    #define WOLFSSL_RENESAS_FSPSM
    #define WOLFSSL_RENESAS_FSPSM_TLS
#endif

    /* XXX_CRYPTONLY definition enables FSP SM module for Crypto only use.
    *  Therefore, it disables TLS related API use
    */
/* #define WOLFSSL_RENESAS_SCEPROTECT_CRYPTONLY */

#if defined(WOLFSSL_RENESAS_SCEPROTECT_CRYPTONLY)
    #undef  WOLFSSL_RENESAS_FSPSM_TLS
    #define WOLFSSL_RENESAS_FSPSM_CRYPTONLY

    #if !defined(WOLFSSL_RENESAS_SCEPROTECT)
        #define WOLFSSL_RENESAS_SCEPROTECT
    #endif
#endif

/* Operating Environment and Threading */
#define FREERTOS
#define FREERTOS_TCP

#define NO_MAIN_DRIVER
#define BENCH_EMBEDDED
#define NO_WRITEV
#define WOLFSSL_NO_FLOAT_FMT

#define NO_DEV_RANDOM
#define SIZEOF_LONG_LONG 8
#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_CURRDIR
#define NO_WOLF_C99
#define NO_MULTIBYTE_PRINT
#define NO_FILESYSTEM

#define XVALIDATEDATE(d, f,t) (0)

#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

#define HAVE_AESGCM
#define WOLFSSL_SHA512
#define HAVE_ECC
#define HAVE_CURVE25519
#define CURVE25519_SMALL

#define WOLFSSL_SMALL_STACK
#define USE_FAST_MATH

/* static RSA */
#define WOLFSSL_STATIC_RSA

/* SEGGER printf */
#define USE_SEGGER_RTT_PRINTF

#ifdef USE_SEGGER_RTT_PRINTF
    int myprintf(const char * sFormat, ...);
    #undef printf
    #define printf myprintf
#endif

/* Enable the following definition to use TLS 1.3
 * For TLS1.3 use "extended-master" needs to turn on
 */
/* #define WOLFSSL_TLS13 */

#if defined(WOLFSSL_TLS13)
    #include <sys/time.h>
    #define HAVE_FFDHE_2048
    #define HAVE_HKDF
    #define WC_RSA_PSS
    #define HAVE_TLS_EXTENSIONS
    #define HAVE_SUPPORTED_CURVES
#endif

#define WOLF_CRYPTO_CB
#if defined(WOLFSSL_RENESAS_SCEPROTECT_CRYPTONLY)
    #define HAVE_RENESAS_SYNC
    #define WC_USE_DEVID 7890
    #define NO_AES_192
    #define NO_SW_BENCH
#endif

#if defined(WOLFSSL_RENESAS_SCEPROTECT_CRYPTONLY)
    #define WOLFSSL_KEY_GEN
#endif

#define CUSTOM_RAND_GENERATE_BLOCK wc_fspsm_GenerateRandBlock
/* use original asn parsing */
#define WOLFSSL_ASN_ORIGINAL
