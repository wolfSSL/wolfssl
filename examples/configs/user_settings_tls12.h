/* user_settings_tls12.h
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

/* Example for TLS v1.2 client only, ECC only, AES GCM only, SHA2-256 only */
/* Derived using:
 * ./configure --disable-rsa --disable-dh --disable-tls13 --disable-chacha \
 *     --disable-poly1305 --disable-sha224 --disable-sha --disable-md5
 * From generated wolfssl/options.h
 * Build and Test using:
 * ./configure --enable-usersettings --disable-examples
 * make
 * ./wolfcrypt/test/testwolfcrypt
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- */
/* Platform */
/* ------------------------------------------------------------------------- */
/* Use the SetIO callbacks, not the internal wolfio.c socket code */
#define WOLFSSL_USER_IO
#define WOLFSSL_IGNORE_FILE_WARN /* ignore file includes not required */
//#define WOLFSSL_SMALL_STACK /* option to reduce stack size, offload to heap */
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_SIG_WRAPPER

/* ------------------------------------------------------------------------- */
/* Math */
/* ------------------------------------------------------------------------- */
/* Math Options */
#if 1 /* Single-precision (SP) wolf math - ECC only */
    #define WOLFSSL_HAVE_SP_ECC   /* use sp_c32.c for math */
    #define WOLFSSL_SP_SMALL      /* use smaller version of code */
    #define WOLFSSL_SP_MATH       /* only SP math - eliminates fast math code */
    /* optional Cortex-M3+ speedup with inline assembly */
    //#define WOLFSSL_SP_ARM_CORTEX_M_ASM
#elif 1
    /* Multi-precision wolf math */
    #define WOLFSSL_SP_MATH_ALL   /* use sp_int.c generic math */
    #define WOLFSSL_SP_SMALL      /* use smaller version of code */
#else
    /* Fast Math - tfm.c */
    #define USE_FAST_MATH
    #define TFM_TIMING_RESISTANT
    #define WOLFSSL_NO_ASM
#endif

/* ------------------------------------------------------------------------- */
/* TLS */
/* ------------------------------------------------------------------------- */
/* Enable TLS v1.2 (on by default) */
#undef  WOLFSSL_NO_TLS12
/* Disable TLS server code */
#define NO_WOLFSSL_SERVER
//#define NO_WOLFSSL_CLIENT
/* Disable TLS v1.3 code */
#undef  WOLFSSL_TLS13
/* Disable older TLS version prior to 1.2 */
#define NO_OLD_TLS

/* Enable default TLS extensions */
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_EXTENDED_MASTER
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_SERVER_RENEGOTIATION_INFO
//#define HAVE_SNI /* optional Server Name Indicator (SNI) */

/* ASN */
#define WOLFSSL_ASN_TEMPLATE /* use newer ASN template asn.c code (default) */

/* Disable Features */
#define NO_SESSION_CACHE /* disable session resumption */
#define NO_PSK /* pre-shared-key support */

/* ------------------------------------------------------------------------- */
/* Algorithms */
/* ------------------------------------------------------------------------- */
/* RNG */
#define HAVE_HASHDRBG /* Use DRBG SHA2-256 and seed */

/* Enable ECC */
#define HAVE_ECC
#define ECC_USER_CURVES      /* Enable only ECC curves specific */
#undef  NO_ECC256            /* Enable SECP256R1 only (on by default) */
#define ECC_TIMING_RESISTANT /* Enable Timing Resistance */
/* Optional ECC calculation speed improvement if not using SP implementation */
//#define ECC_SHAMIR

/* Enable SHA2-256 only (on by default) */
#undef NO_SHA256
//#define USE_SLOW_SHA256 /* Reduces code size by not partially unrolling */

/* Enable AES GCM only */
#define HAVE_AESGCM
#define GCM_SMALL /* use small GHASH table */
#define NO_AES_CBC /* Disable AES CBC */

/* Optional Features */
//#define WOLFSSL_BASE64_ENCODE /* Enable Base64 encoding */


/* Disable Algorithms */
#define NO_RSA
#define NO_DH
#define NO_SHA
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_PWDBASED
#define WOLFSSL_NO_SHAKE128
#define WOLFSSL_NO_SHAKE256

/* ------------------------------------------------------------------------- */
/* Debugging */
/* ------------------------------------------------------------------------- */
#undef DEBUG_WOLFSSL
#undef NO_ERROR_STRINGS
#if 0
    #define DEBUG_WOLFSSL
#else
    #if 1
        #define NO_ERROR_STRINGS
    #endif
#endif

#ifdef __cplusplus
}
#endif


#endif /* WOLFSSL_USER_SETTINGS_H */
