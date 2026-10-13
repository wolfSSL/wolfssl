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

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------- */
/* Platform */
/* ------------------------------------------------- */
#define NO_FILESYSTEM
#define WOLFSSL_IGNORE_FILE_WARN
#define WOLFSSL_PTHREADS

#define CUSTOM_RAND_GENERATE_SEED integrity_rand_generate_seed
int integrity_rand_generate_seed(unsigned char* output, unsigned int sz);

#define WOLFSSL_SP_MATH_ALL

#define WOLFSSL_AARCH64_BUILD
#define WOLFSSL_ARMASM
#define WOLFSSL_ARMASM_INLINE
#define WOLFSSL_SP_ASM
#define WOLFSSL_SP_ARM64
#define WOLFSSL_SP_ARM64_ASM

/* remove this line once the ".arch_extension crypto" issue is resolved */
#define WOLFSSL_ARMASM_NO_HW_CRYPTO

#define WOLFSSL_TLS13
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_HKDF
#define WC_RSA_PSS
#define WOLFSSL_NO_TLS12
#define NO_OLD_TLS

#define HAVE_SESSION_TICKET
#define HAVE_SNI

#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

#if 1
    #define HAVE_ECC
    #define ECC_USER_CURVES
    #undef  NO_ECC256
    #if 1
        #define HAVE_ECC384
    #endif
    #if 0
        #define HAVE_ECC521
    #endif
    #define ECC_SHAMIR
#endif

#if 0
    #define HAVE_CURVE25519
#endif
#if 0
    #define HAVE_ED25519
#endif

#if 0
    #undef NO_RSA
    #define WOLFSSL_KEY_GEN
#else
    #define NO_RSA
#endif

#if 0
    #undef NO_DH
    #define HAVE_FFDHE_2048
    #define HAVE_FFDHE_3072
    #define HAVE_DH_DEFAULT_PARAMS
#else
    #define NO_DH
#endif

#define HAVE_AESGCM
#define GCM_TABLE_4BIT

#if 1
    #define HAVE_CHACHA
#endif

#if 0
    #define HAVE_AESCCM
#endif

#define WOLFSSL_CMAC
#define WOLFSSL_AES_DIRECT

#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

#define HAVE_HASHDRBG

#define WOLFSSL_ASN_TEMPLATE

#if 0
    #define WOLFSSL_CERT_GEN
    #define WOLFSSL_CERT_REQ
    #define WOLFSSL_CERT_EXT
#endif

#define NO_DSA
#define NO_RC4
#define NO_MD4
#define NO_MD5
#define NO_DES3
#define NO_DES3_TLS_SUITES
#define NO_PSK
#define NO_PWDBASED

#define HAVE_AES_ECB

/* The benchmark's AArch64 cycle count reads the per-core virtual timer,
 * which differs widely between this board's two A53 cores; derive it from
 * the system clock instead (wolfcrypt/benchmark/benchmark.c). */
#define WC_BENCH_CYCLES_FROM_CLOCK

/* SA2UL hardware offload: the crypto callback device and everything it
 * needs. Without WOLFSSL_SA2UL_DRIVER the build is pure software, with no
 * crypto callbacks at all. */
#ifdef WOLFSSL_SA2UL_DRIVER
    #define WOLFSSL_TI_AM64X_A53_INTEGRITY
    #ifndef WOLF_CRYPTO_CB
        #define WOLF_CRYPTO_CB
    #endif
    #define WOLF_CRYPTO_CB_FREE
    #define WOLF_CRYPTO_CB_AES_SETKEY
    #define WOLF_CRYPTO_CB_COPY
    /* Smallest AES-ECB request sent to SA2UL.  Single blocks (wc_AesEncrypt
     * from software GCM/CTR/CMAC and GCM key setup) stay in software, as an
     * IODevice round trip costs far more than one ARMv8 AES block.  Set this to
     * 16 to push every ECB call through the sa2ul hardware. */
    #ifndef WOLFSSL_SA2UL_ECB_MIN_SZ
        #define WOLFSSL_SA2UL_ECB_MIN_SZ 32
    #endif
    /* Smallest SHA-224/256/384/512 message hashed by SA2UL.  Each SA2UL hash costs
     * an IODevice round trip (~60 us measured), so small hashes -- notably
     * Hash_DRBG's, which made the RNG ~15x slower -- stay in software.
     * Decided at the first Update (a message whose first update is
     * smaller runs entirely in software, without touching the port's
     * lock) and re-checked at Final. Set this to 1 to send every hash to the
     * sa2ul hardware. */
    #ifndef WOLFSSL_SA2UL_HASH_MIN_SZ
        #define WOLFSSL_SA2UL_HASH_MIN_SZ 1024
    #endif
#endif

#define WOLFSSL_STATIC_MEMORY
#define WOLFSSL_STATIC_MEMORY_TEST_SZ (256 * 1024)
#define BENCH_EMBEDDED

#if 0
    #define DEBUG_WOLFSSL
#endif
#if 0
    #define NO_ERROR_STRINGS
#endif

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_USER_SETTINGS_H */
