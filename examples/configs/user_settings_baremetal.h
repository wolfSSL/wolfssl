/* user_settings_baremetal.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/* Bare metal configuration for systems without an OS.
 * No filesystem, no malloc, static memory, minimal footprint.
 * Suitable for deeply embedded systems and bootloaders.
 *
 * Build and test:
 * cp ./examples/configs/user_settings_baremetal.h user_settings.h
 * ./configure --enable-usersettings --disable-examples
 * make
 * ./wolfcrypt/test/testwolfcrypt
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------- */
/* Platform - Bare Metal */
/* ------------------------------------------------- */
#define SINGLE_THREADED
#define NO_FILESYSTEM
#define NO_WRITEV
#define WOLFSSL_NO_SOCK
#define WOLFSSL_IGNORE_FILE_WARN
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SIZEOF_LONG_LONG 8

/* TLS transport requires setting IO callbacks */
#define WOLFSSL_USER_IO

/* ------------------------------------------------- */
/* Memory */
/* ------------------------------------------------- */
#if 1 /* stack memory */

#elif 1 /* small stack */
    /* Small stack - allocate large variables from static pool */
    #define WOLFSSL_SMALL_STACK
#else /* static memory */
    #define WOLFSSL_STATIC_MEMORY
    #define WOLFSSL_NO_MALLOC
    #define WOLFSSL_SP_NO_MALLOC
    #define WOLFSSL_MALLOC_CHECK
    #define NO_WOLFSSL_MEMORY
#endif

/* ------------------------------------------------- */
/* Math - Single Precision (smallest) */
/* ------------------------------------------------- */
#define WOLFSSL_SP_MATH
#define WOLFSSL_SP_SMALL
#define TFM_TIMING_RESISTANT

/* ------------------------------------------------- */
/* TLS (optional - disable for crypto-only) */
/* ------------------------------------------------- */
#if 0 /* TLS support */
    #define WOLFSSL_TLS13
    #define WOLFSSL_NO_TLS12
    #define NO_OLD_TLS
    #define HAVE_TLS_EXTENSIONS
    #define HAVE_SUPPORTED_CURVES
    #define HAVE_HKDF
#else
    #define WOLFCRYPT_ONLY
#endif

/* ------------------------------------------------- */
/* ECC (smallest asymmetric option) */
/* ------------------------------------------------- */
#if 1 /* ECC support */
    #define HAVE_ECC
    #define WOLFSSL_HAVE_SP_ECC

    #define ECC_USER_CURVES    /* P-256 only */
    #undef  NO_ECC256
    #define ECC_TIMING_RESISTANT
    /* Disable for smaller size */
    #if 0 /* ECC Shamir (faster, more code) */
        #define ECC_SHAMIR
    #endif
#endif

/* ECC Feature Reduction */
#if 0 /* Verify only (no signing/keygen) */
    #define NO_ECC_SIGN
    #define NO_ECC_DHE
    #define NO_ECC_KEY_EXPORT
#endif

/* ------------------------------------------------- */
/* RSA (disable for smallest size) */
/* ------------------------------------------------- */
#if 0 /* RSA support */
    #undef NO_RSA
    #define WOLFSSL_HAVE_SP_RSA
    #define WC_RSA_BLINDING
    #define RSA_LOW_MEM
    #if 0 /* Verify only */
        #define WOLFSSL_RSA_PUBLIC_ONLY
        #define WOLFSSL_RSA_VERIFY_INLINE
        #define NO_CHECK_PRIVATE_KEY
    #endif
#else
    #define NO_RSA
#endif

/* ------------------------------------------------- */
/* Symmetric Ciphers */
/* ------------------------------------------------- */
#if 1 /* AES */
    #define HAVE_AESGCM
    #define GCM_SMALL
    #define WOLFSSL_AES_SMALL_TABLES
    #define WOLFSSL_AES_NO_UNROLL
    #define NO_AES_192
    #define NO_AES_256
    #if 0 /* AES-CBC */
        #undef NO_AES_CBC
    #else
        #define NO_AES_CBC
    #endif
#else
    #define NO_AES
#endif

#if 0 /* ChaCha20-Poly1305 */
    #define HAVE_CHACHA
    #define HAVE_POLY1305
#endif

/* ------------------------------------------------- */
/* Hashing */
/* ------------------------------------------------- */
/* SHA-256 only (required) */
#define USE_SLOW_SHA256

#if 0 /* SHA-1 (legacy) */
    #undef NO_SHA
#else
    #define NO_SHA
#endif

/* ------------------------------------------------- */
/* RNG */
/* ------------------------------------------------- */
#if 1 /* Hash-based DRBG */
    #define HAVE_HASHDRBG
#else
    /* Use hardware RNG directly */
    #define WC_NO_HASHDRBG
    extern int my_rng_gen_block(unsigned char* output, unsigned int sz);
    #define CUSTOM_RAND_GENERATE_BLOCK my_rng_gen_block
#endif

/* ------------------------------------------------- */
/* ASN / Certificates */
/* ------------------------------------------------- */
#define WOLFSSL_ASN_TEMPLATE

#if 0 /* Disable certificates for smallest size */
    #define NO_ASN
    #define NO_CERTS
    #define NO_CODING
#endif

/* ------------------------------------------------- */
/* Disabled Algorithms */
/* ------------------------------------------------- */
#define NO_DH
#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_DES3_TLS_SUITES
#define NO_PSK
#define NO_PWDBASED
#define NO_PKCS8
#define NO_PKCS12

/* ------------------------------------------------- */
/* Disabled Features */
/* ------------------------------------------------- */
#define NO_SIG_WRAPPER
#define NO_SESSION_CACHE
#define NO_ERROR_STRINGS
#define NO_OLD_RNGNAME
#define NO_WOLFSSL_DIR
#define BENCH_EMBEDDED

/* ------------------------------------------------- */
/* Custom Time (bare metal has no RTC typically) */
/* ------------------------------------------------- */
#if 1 /* Custom time function */
    #define NO_ASN_TIME
    /* Or provide custom time:
     * #define USER_TIME
     * extern unsigned long my_time(unsigned long* timer);
     * #define XTIME my_time
     */
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
