/* user_settings-fips-v5.2.3.h
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

/* wolfCrypt FIPS v5.2.3 settings for Zephyr.
 *
 * A drop-in replacement for zephyr/user_settings.h: copy it over that file in
 * a tree holding the v5.2.3 bundle. It cannot go through
 * CONFIG_WOLFSSL_SETTINGS_FILE, because CONFIG_WOLFCRYPT_FIPS depends on no
 * settings file being set and without it CMake never compiles fips.c. Select
 * in prj.conf:
 *
 *   CONFIG_WOLFCRYPT_FIPS=y
 *   CONFIG_WOLFCRYPT_FIPS_V5=y
 *
 * The algorithm set follows ./configure --enable-fips=v5.2.3, trimmed for
 * flash: OPENSSL_EXTRA and error strings are off. It is fixed, so the
 * algorithm Kconfig options (ECC curves, RSA, ChaCha20/Poly1305, PQC, ...) are
 * not read; the TLS, session and GHASH options are. WC_RNG_SEED_CB is set;
 * register a seed callback with wc_SetSeed_Cb() that reads the hardware
 * entropy driver, since the v5.2.3 wc_GenerateSeed() uses sys_rand_get(). */

#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

#if defined(CONFIG_WOLFSSL) && !defined(CONFIG_WOLFCRYPT_FIPS_V5)
    #error "user_settings-fips-v5.2.3.h needs CONFIG_WOLFCRYPT_FIPS=y and CONFIG_WOLFCRYPT_FIPS_V5=y"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* FIPS Version 5.2.3 (v5.2.1 base with ARM/Thumb2 acceleration in boundary) */
#define HAVE_FIPS
#define HAVE_FIPS_VERSION 5
#define HAVE_FIPS_VERSION_MAJOR 5
#define HAVE_FIPS_VERSION_MINOR 2
#define HAVE_FIPS_VERSION_PATCH 3

#define HAVE_HASHDRBG /* NIST Certified DRBG - SHA256 based */
/* fips.c needs a thread-local choice made. Not HAVE_THREAD_LS: THREAD_LS_T is
 * empty on Zephyr, so it would only drop the ECC/SP cache locks and arm the
 * shared wolfCrypt_Init() recursion guard. */
#define NO_THREAD_LS
#ifdef CONFIG_WOLFSSL_SINGLE_THREADED
    #define SINGLE_THREADED
#endif
#ifdef CONFIG_WOLFSSL_CRYPTO_ONLY
    #define WOLFCRYPT_ONLY
#endif

/* Platform (Zephyr) */
#define WOLFSSL_GENERAL_ALIGNMENT 4 /* platform requires 32-bit alignment on uint32_t */
#define SIZEOF_LONG_LONG 8          /* long long is 8 bytes / 64-bit */
#define WOLFSSL_IGNORE_FILE_WARN    /* ignore file includes not required */
#define BENCH_EMBEDDED              /* use smaller buffers in benchmark / tests */
#if defined(CONFIG_WOLFSSL_USER_IO)
    #define WOLFSSL_USER_IO /* Use the SetIO callbacks, not the internal wolfio.c socket code */
#endif
#define NO_FILESYSTEM
#define NO_WRITEV

/* Hardware (Zephyr)
 * The v5.2.3 boundary owns the ARMv8, ARMv8-32 and Thumb2 AES and SHA-2/SHA-3
 * assembly (armv8-aes.c, armv8-sha256.c in place of sha256.c, and so on) and
 * the Intel SHA assembly. The Zephyr module does not yet place that layout
 * inside the boundary, so symmetric assembly stays off here. The SP math
 * below sits outside the v5 boundary and is safe to accelerate. Left out on
 * purpose: PSA (port/psa, and WC_NO_HASHDRBG bypasses the approved DRBG),
 * CryptoCell, WOLFSSL_AES_TOUCH_LINES / WC_AES_BITSLICED (not in the v5.2.3
 * aes.c) and WOLFSSL_SP_521 (no Cortex-M support at v5.2.3). */
#ifdef CONFIG_WOLFCRYPT_ASM
    /* 64-bit SP backends work in 128-bit intermediates */
    #if defined(__SIZEOF_INT128__) && !defined(HAVE___UINT128_T)
        #define HAVE___UINT128_T 1
    #endif
#endif

/* Math */
#define WOLFSSL_SP_MATH_ALL /* v5.2.3 default (configure DEF_SP_MATH_ALL) */
#define SP_INT_BITS 8192
#define WOLFSSL_PUBLIC_MP /* expose the mp_ math API's */

/* Single Precision math for specific curves and key sizes */
#define WOLFSSL_HAVE_SP_RSA
#define WOLFSSL_HAVE_SP_DH
#define WOLFSSL_HAVE_SP_ECC
#define WOLFSSL_SP_384
#define WOLFSSL_SP_4096
#ifdef CONFIG_WOLFCRYPT_SP_SMALL
    #define WOLFSSL_SP_SMALL /* use smaller version of code */
#endif
#ifdef CONFIG_WOLFCRYPT_ASM
    #if defined(CONFIG_ARMV6_M_ARMV8_M_BASELINE)
        #define WOLFSSL_SP_ARM_THUMB_ASM
        #define WOLFSSL_SP_ARM_THUMB
    #elif defined(CONFIG_ARMV7_M_ARMV8_M_MAINLINE)
        #define WOLFSSL_SP_ARM_CORTEX_M_ASM
        #define WOLFSSL_SP_ARM_CORTEX_M
    #elif defined(CONFIG_ARM64)
        #define WOLFSSL_SP_ARM64_ASM
        #define WOLFSSL_SP_ARM64
    #elif defined(CONFIG_CPU_AARCH32_CORTEX_R) || \
          defined(CONFIG_CPU_AARCH32_CORTEX_A)
        #define WOLFSSL_SP_ARM32_ASM
        #define WOLFSSL_SP_ARM32
    #endif
#endif

/* Timing Resistance */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* FIPS Features */
#define WC_RNG_SEED_CB
#define WOLFSSL_VALIDATE_ECC_IMPORT
#define WOLFSSL_VALIDATE_ECC_KEYGEN
#define WOLFSSL_VALIDATE_FFC_IMPORT

/* TLS
 * Outside the boundary, so it follows the same Kconfig options as
 * zephyr/user_settings.h. */
#ifdef CONFIG_WOLFSSL_TLS_VERSION_1_2
    #undef  WOLFSSL_NO_TLS12
#else
    #define WOLFSSL_NO_TLS12
#endif
#ifdef CONFIG_WOLFSSL_TLS_VERSION_1_3
    #define WOLFSSL_TLS13
#endif
#define NO_OLD_TLS
#define HAVE_TLS_EXTENSIONS
#define HAVE_ENCRYPT_THEN_MAC
#define HAVE_SUPPORTED_CURVES
#define HAVE_EXTENDED_MASTER
#define HAVE_ONE_TIME_AUTH /* TLS extension used with Poly1305 */
#define HAVE_SECURE_RENEGOTIATION
#define HAVE_SERVER_RENEGOTIATION_INFO
#if defined(CONFIG_WOLFSSL_SNI)
    #define HAVE_SNI
#endif
#if defined(CONFIG_WOLFSSL_POST_HANDSHAKE_AUTH)
    #define WOLFSSL_POST_HANDSHAKE_AUTH
#endif
#if defined(CONFIG_WOLFSSL_ALPN)
    #define HAVE_ALPN
#endif
#if defined(CONFIG_WOLFSSL_MAX_FRAGMENT)
    #define HAVE_MAX_FRAGMENT
#endif
#if defined(CONFIG_WOLFSSL_DTLS)
    #define WOLFSSL_DTLS
    #define HAVE_SOCKADDR
#endif
#if defined(CONFIG_WOLFSSL_PSK)
    #undef  NO_PSK
    #define WOLFSSL_STATIC_PSK
#else
    #define NO_PSK
#endif
#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
    #define WOLFSSL_SET_CIPHER_BYTES
#endif

/* OCSP */
#if defined(CONFIG_WOLFSSL_OCSP)
    #define HAVE_OCSP
#endif
#if defined(CONFIG_WOLFSSL_OCSP_STAPLING)
    #define HAVE_CERTIFICATE_STATUS_REQUEST
#endif

/* Sessions */
#if defined(CONFIG_WOLFSSL_SESSION_CACHE)
    #define SMALL_SESSION_CACHE
#else
    #define NO_SESSION_CACHE
#endif
#if defined(CONFIG_WOLFSSL_SESSION_TICKET) && defined(WOLFSSL_TLS13)
    #define HAVE_SESSION_TICKET
#endif
#if defined(CONFIG_WOLFSSL_SESSION_EXPORT)
    #define HAVE_EXT_CACHE
#endif
#if defined(CONFIG_WOLFSSL_KEEP_PEER_CERT)
    #define KEEP_PEER_CERT
#endif
#if defined(CONFIG_WOLFSSL_ALWAYS_VERIFY_CB)
    #define WOLFSSL_ALWAYS_VERIFY_CB
#endif

/* Crypto callbacks. ELS PKC is refused: it registers its offload itself, and
 * that moves approved algorithms out of the module. */
#if defined(CONFIG_WOLFSSL_CRYPTO_CB)
    #define WOLF_CRYPTO_CB
#endif
#if defined(CONFIG_WOLFTPM)
    #ifndef WOLF_CRYPTO_CB
        #define WOLF_CRYPTO_CB
    #endif
    #define WOLFSSL_AES_CFB
#endif
#if defined(CONFIG_WOLFSSL_ELS_PKC)
    #error "CONFIG_WOLFSSL_ELS_PKC offloads approved algorithms outside the FIPS v5.2.3 boundary"
#endif

/* Other Features */
#define WOLFSSL_USE_ALIGN
#define WOLFSSL_BASE64_ENCODE
#if 0 /* optionally enable CRL (Certificate Revocation List) */
    #define HAVE_CRL
#endif
#define WOLFSSL_VERIFY_CB_ALL_CERTS
#define WOLFSSL_DH_EXTRA /* DHE ASN.1 key import/export support */

#ifndef WOLFSSL_WOLFSSH /* ifndef check required due to configure already generating flag */
#define WOLFSSL_WOLFSSH
#endif

/* Compatibility Layer
 * Off by default: OPENSSL_EXTRA adds roughly 30% to the library image. For the
 * few X509 helpers (wolfSSL_X509_free, wolfSSL_get_verify_result, ...) enable
 * OPENSSL_EXTRA_X509_SMALL instead. */
#if 0
    #define OPENSSL_EXTRA
    #if 0 /* if full suite of compatibility API's are needed */
        #define OPENSSL_ALL
    #endif
#endif
#if defined(CONFIG_WOLFSSL_OPENSSL_EXTRA_X509_SMALL)
    #define OPENSSL_EXTRA_X509_SMALL
#endif

/* DH */
#undef  NO_DH
#define HAVE_FFDHE_Q
#define HAVE_FFDHE_2048
#define HAVE_FFDHE_3072
#define HAVE_FFDHE_4096
#define HAVE_FFDHE_6144
#define HAVE_FFDHE_8192
#define HAVE_DH_DEFAULT_PARAMS
#define HAVE_PUBLIC_FFDHE

/* ECC */
#define HAVE_ECC
#define TFM_ECC256
#define ECC_SHAMIR
#define HAVE_ECC_CDH
#define ECC_USER_CURVES
#define HAVE_ECC192
#define HAVE_ECC224
#define HAVE_ECC256
#define HAVE_ECC384
#define HAVE_ECC521
#define WOLFSSL_ECDSA_SET_K

/* RSA */
#undef  NO_RSA
#define WC_RSA_PSS
#define WOLFSSL_KEY_GEN
#define WC_RSA_NO_PADDING

/* AES */
#undef  NO_AES
#define WOLFSSL_AES_COUNTER
#define HAVE_AESCCM
#define HAVE_AES_ECB
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_OFB
#define HAVE_AESGCM
/* GHASH method sits inside the boundary; follow the Kconfig choice. */
#if defined(CONFIG_WOLFSSL_GHASH_TABLE_4BIT)
    #define GCM_TABLE_4BIT
#elif defined(CONFIG_WOLFSSL_GHASH_TABLE_8BIT)
    #define GCM_TABLE
#elif defined(CONFIG_WOLFSSL_GHASH_SMALL)
    #define GCM_SMALL
#else
    #define AES_GCM_GMULT_CT
#endif
#define WOLFSSL_CMAC

/* ChaCha/Poly */
#define HAVE_CHACHA
#define HAVE_POLY1305

/* Hashing */
#undef  NO_SHA
#undef  NO_SHA256
#define WOLFSSL_SHA224
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384
#define WOLFSSL_NOSHA512_224
#define WOLFSSL_NOSHA512_256
#define WOLFSSL_SHA3
#define HAVE_HKDF

/* Disabled Algorithms */
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_DES3_TLS_SUITES
#define NO_DSA
#define NO_RABBIT
#define NO_HC128
#define WOLFSSL_NO_SHAKE256

/* Debugging */
#undef DEBUG_WOLFSSL
#undef NO_ERROR_STRINGS
#ifdef CONFIG_WOLFSSL_DEBUG
    #define DEBUG_WOLFSSL
#else
    #define NO_ERROR_STRINGS
#endif

#ifdef __cplusplus
}
#endif

#endif /* USER_SETTINGS_H */
