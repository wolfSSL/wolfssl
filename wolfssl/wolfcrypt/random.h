/* random.h
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

/*!
    \file wolfssl/wolfcrypt/random.h
*/



#ifndef WOLF_CRYPT_RANDOM_H
#define WOLF_CRYPT_RANDOM_H

#include <wolfssl/wolfcrypt/types.h>

#if FIPS_VERSION3_GE(2,0,0)
    #include <wolfssl/wolfcrypt/fips.h>
#endif /* HAVE_FIPS_VERSION >= 2 */

#ifdef __cplusplus
    extern "C" {
#endif

#if FIPS_VERSION3_GE(6,0,0)
    extern const unsigned int wolfCrypt_FIPS_drbg_ro_sanity[2];
    WOLFSSL_LOCAL int wolfCrypt_FIPS_DRBG_sanity(void);
#endif

 /* Maximum generate block length */
#ifndef RNG_MAX_BLOCK_LEN
    #ifdef HAVE_INTEL_QA
        #define RNG_MAX_BLOCK_LEN (0xFFFFl)
    #else
        #define RNG_MAX_BLOCK_LEN (0x10000l)
    #endif
#endif

/* Size of the BRBG seed */
#ifndef DRBG_SEED_LEN
    #define DRBG_SEED_LEN (440/8)
#endif


#if !defined(CUSTOM_RAND_TYPE)
    /* To maintain compatibility the default is byte */
    #define CUSTOM_RAND_TYPE    byte
#endif

/* make sure Hash DRBG is enabled, unless WC_NO_HASHDRBG is defined
    or CUSTOM_RAND_GENERATE_BLOCK is defined */
#if !defined(WC_NO_HASHDRBG) && !defined(CUSTOM_RAND_GENERATE_BLOCK)
    #undef  HAVE_HASHDRBG
    #define HAVE_HASHDRBG
    #ifndef WC_RESEED_INTERVAL
        #define WC_RESEED_INTERVAL (1000000)
    #endif
#endif


/* avoid redefinition of structs */
#if !defined(HAVE_FIPS) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2))

/* RNG supports the following sources (in order):
 * 1. CUSTOM_RAND_GENERATE_BLOCK: Defines name of function as RNG source and
 *     bypasses the options below.
 * 2. HAVE_INTEL_RDRAND: Uses the Intel RDRAND if supported by CPU.
 * 3. HAVE_HASHDRBG (requires SHA256 enabled): Uses SHA256 based P-RNG
 *     seeded via wc_GenerateSeed. This is the default source.
 */

 /* Seed source can be overridden by defining one of these:
      CUSTOM_RAND_GENERATE_SEED
      CUSTOM_RAND_GENERATE_SEED_OS
      CUSTOM_RAND_GENERATE */


#if defined(CUSTOM_RAND_GENERATE_BLOCK)
    /* To use define the following:
     * #define CUSTOM_RAND_GENERATE_BLOCK myRngFunc
     * extern int myRngFunc(byte* output, word32 sz);
     */
    #if defined(CUSTOM_RAND_GENERATE_BLOCK) && defined(WOLFSSL_KCAPI)
        #undef  CUSTOM_RAND_GENERATE_BLOCK
        #define CUSTOM_RAND_GENERATE_BLOCK wc_hwrng_generate_block
        WOLFSSL_LOCAL int wc_hwrng_generate_block(byte *output, word32 sz);
    #endif
#elif defined(HAVE_HASHDRBG)
    #ifdef NO_SHA256
        #error "Hash DRBG requires SHA-256."
    #endif /* NO_SHA256 */
    #include <wolfssl/wolfcrypt/sha256.h>
#elif defined(HAVE_WNR)
     /* allow whitewood as direct RNG source using wc_GenerateSeed directly */
#elif defined(HAVE_INTEL_RDRAND)
    /* Intel RDRAND or RDSEED */
#elif defined(WOLF_CRYPTO_CB)
    /* Requires registered Crypto Callback to service RNG, with devId set */
#elif !defined(WC_NO_RNG)
    #error No RNG source defined!
#endif

#ifdef HAVE_WNR
    #include <wnr.h>
#endif

#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif


#if defined(USE_WINDOWS_API)
    #if defined(_WIN64)
        typedef unsigned __int64 ProviderHandle;
        /* type HCRYPTPROV, avoid #include <windows.h> */
    #else
        typedef unsigned long ProviderHandle;
    #endif

    #ifdef WIN_REUSE_CRYPT_HANDLE
        /* called from wolfCrypt_Init() and wolfCrypt_Cleanup() */
        WOLFSSL_LOCAL int  wc_WinCryptHandleInit(void);
        WOLFSSL_LOCAL void wc_WinCryptHandleCleanup(void);
    #endif
#endif

#ifndef WC_RNG_TYPE_DEFINED /* guard on redeclaration */
    typedef struct OS_Seed OS_Seed;
    typedef struct WC_RNG WC_RNG;
    #ifdef WC_RNG_SEED_CB
        typedef int (*wc_RngSeed_Cb)(OS_Seed* os, byte* seed, word32 sz);
    #endif
    #define WC_RNG_TYPE_DEFINED
#endif

/* OS specific seeder */
struct OS_Seed {
    #if defined(USE_WINDOWS_API)
        ProviderHandle handle;
    #else
        int fd;
    #if defined(WOLFSSL_KEEP_RNG_SEED_FD_OPEN)
        byte seedFdOpen:1;
        byte keepSeedFdOpen:1;
    #endif
    #endif
    #if defined(WOLF_CRYPTO_CB)
        int devId;
    #endif
};

#ifdef HAVE_HASHDRBG

/* The security strength for the RNG is the target number of bits of
 * entropy you are looking for in a seed. */
/* RNG_SECURITY_STRENGTH is unprefixed for backward compat. */
#ifndef RNG_SECURITY_STRENGTH
    /* SHA-256 requires a minimum of 256-bits of entropy. */
    #define RNG_SECURITY_STRENGTH (256)
#endif

/* wolfentropy.h will define for HAVE_ENTROPY_MEMUSE */
#ifdef HAVE_ENTROPY_MEMUSE
    #include <wolfssl/wolfcrypt/wolfentropy.h>
#endif

/* ENTROPY_SCALE_FACTOR is unprefixed for backward compat. */
#ifndef ENTROPY_SCALE_FACTOR
    /* The entropy scale factor should be the whole number inverse of the
     * minimum bits of entropy per bit of NDRNG output. */
    #if defined(HAVE_AMD_RDSEED)
        /* This will yield a SEED_SZ of 16kb. Since nonceSz will be 0,
         * we'll add an additional 8kb on top.
         *
         * See "AMD RNG ESV Public Use Document".  Version 0.7 of October 24,
         * 2024 specifies 0.656 to 1.312 bits of entropy per 128 bit block of
         * RDSEED output, depending on CPU family.
         */
        #define ENTROPY_SCALE_FACTOR  (512)
    #elif defined(HAVE_INTEL_RDSEED) || defined(HAVE_INTEL_RDRAND)
        /* The value of 2 applies to Intel's RDSEED which provides about
         * 0.5 bits minimum of entropy per bit. The value of 4 gives a
         * conservative margin for FIPS. */
        #if defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && \
            (HAVE_FIPS_VERSION >= 2)
            #define ENTROPY_SCALE_FACTOR (2*4)
        #else
            /* Not FIPS, but Intel RDSEED, only double. */
            #define ENTROPY_SCALE_FACTOR (2)
        #endif
    #elif defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && \
        (HAVE_FIPS_VERSION >= 2)
        /* If doing a FIPS build without a specific scale factor, default
         * to 4. This will give 1024 bits of entropy. More is better, but
         * more is also slower. */
        #define ENTROPY_SCALE_FACTOR (4)
    #else
        /* Setting the default to 1. */
        #define ENTROPY_SCALE_FACTOR (1)
    #endif
#endif /* !ENTROPY_SCALE_FACTOR */

/* SEED_BLOCK_SZ is unprefixed for backward compat. */
#ifndef SEED_BLOCK_SZ
    /* The seed block size, is the size of the output of the underlying NDRNG.
     * This value is used for testing the output of the NDRNG. */
    #if defined(HAVE_AMD_RDSEED)
        /* AMD's RDSEED instruction works in 128-bit blocks read 64-bits
        * at a time. */
        #define SEED_BLOCK_SZ (sizeof(word64)*2)
    #elif defined(HAVE_INTEL_RDSEED) || defined(HAVE_INTEL_RDRAND)
        /* RDSEED outputs in blocks of 64-bits. */
        #define SEED_BLOCK_SZ sizeof(word64)
    #else
        /* Setting the default to 4. */
        #define SEED_BLOCK_SZ 4
    #endif
#endif

#define WC_DRBG_SEED_BLOCK_SZ SEED_BLOCK_SZ

#define WC_DRBG_SEED_SZ        (RNG_SECURITY_STRENGTH*ENTROPY_SCALE_FACTOR/8)

/* The maximum seed size will be the seed size plus a seed block for the
 * test, and an additional half of the seed size. This additional half
 * is in case the user does not supply a nonce. A nonce will be obtained
 * from the NDRNG. */
#define WC_DRBG_MAX_SEED_SZ    (WC_DRBG_SEED_SZ + WC_DRBG_SEED_SZ/2 + \
                                SEED_BLOCK_SZ)

#define RNG_HEALTH_TEST_CHECK_SIZE (WC_SHA256_DIGEST_SIZE * 4)

/* RNG health states */
#define WC_DRBG_NOT_INIT     0
#define WC_DRBG_OK           1
#define WC_DRBG_FAILED       2
#define WC_DRBG_CONT_FAILED  3

struct DRBG_internal {
    #ifdef WORD64_AVAILABLE
    word64 reseedCtr;
    #else
    word32 reseedCtr;
    #endif
    byte V[DRBG_SEED_LEN];
    byte C[DRBG_SEED_LEN];
    void* heap;
#if defined(WOLFSSL_ASYNC_CRYPT) || defined(WOLF_CRYPTO_CB)
    int devId;
#endif
#ifdef WOLFSSL_SMALL_STACK_CACHE
    wc_Sha256 sha256;
    byte seed_scratch[DRBG_SEED_LEN];
    byte digest_scratch[WC_SHA256_DIGEST_SIZE];
#endif
};
#endif

/* RNG context */
struct WC_RNG {
    struct OS_Seed seed;
    void* heap;
#ifdef HAVE_HASHDRBG
    /* Hash-based Deterministic Random Bit Generator */
    struct DRBG* drbg;
#if defined(WOLFSSL_NO_MALLOC) && !defined(WOLFSSL_STATIC_MEMORY)
    struct DRBG_internal drbg_data;
#endif
#ifdef WOLFSSL_SMALL_STACK_CACHE
    /* Scratch buffer slots -- everything is preallocated by _InitRng(). */
    struct DRBG_internal *drbg_scratch;
    byte *health_check_scratch;
    byte *newSeed_buf;
#endif
    byte status;
#endif /* HAVE_HASHDRBG */
#if defined(HAVE_GETPID) && !defined(WOLFSSL_NO_GETPID)
    pid_t pid;
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
    WC_ASYNC_DEV asyncDev;
#endif
#if defined(WOLFSSL_ASYNC_CRYPT) || defined(WOLF_CRYPTO_CB)
    int devId;
#endif
};

#endif /* NO FIPS or have FIPS v2*/

/* NO_OLD_RNGNAME removes RNG struct name to prevent possible type conflicts,
 * can't be used with CTaoCrypt FIPS */
#if !defined(NO_OLD_RNGNAME) && !defined(HAVE_FIPS)
    #define RNG WC_RNG
#endif

WOLFSSL_API int wc_GenerateSeed(OS_Seed* os, byte* output, word32 sz);


#ifdef HAVE_WNR
    /* Whitewood netRandom client library */
    WOLFSSL_API int  wc_InitNetRandom(const char*, wnr_hmac_key, int);
    WOLFSSL_API int  wc_FreeNetRandom(void);
#endif /* HAVE_WNR */


WOLFSSL_ABI WOLFSSL_API WC_RNG* wc_rng_new(byte* nonce, word32 nonceSz,
                                           void* heap);
WOLFSSL_API int wc_rng_new_ex(WC_RNG **rng, byte* nonce, word32 nonceSz,
                              void* heap, int devId);
WOLFSSL_ABI WOLFSSL_API void wc_rng_free(WC_RNG* rng);


#ifndef WC_NO_RNG
WOLFSSL_ABI WOLFSSL_API int  wc_InitRng(WC_RNG* rng);
WOLFSSL_API int  wc_InitRng_ex(WC_RNG* rng, void* heap, int devId);
WOLFSSL_API int  wc_InitRngNonce(WC_RNG* rng, byte* nonce, word32 nonceSz);
WOLFSSL_API int  wc_InitRngNonce_ex(WC_RNG* rng, byte* nonce, word32 nonceSz,
                                    void* heap, int devId);
WOLFSSL_ABI WOLFSSL_API int wc_RNG_GenerateBlock(WC_RNG* rng, byte* output, word32 sz);
WOLFSSL_API int  wc_RNG_GenerateByte(WC_RNG* rng, byte* b);
WOLFSSL_API int  wc_FreeRng(WC_RNG* rng);
#else
#include <wolfssl/wolfcrypt/error-crypt.h>
#define wc_InitRng(rng) NOT_COMPILED_IN
#define wc_InitRng_ex(rng, h, d) NOT_COMPILED_IN
#define wc_InitRngNonce(rng, n, s) NOT_COMPILED_IN
#define wc_InitRngNonce_ex(rng, n, s, h, d) NOT_COMPILED_IN
#if defined(__ghs__) || defined(WC_NO_RNG_SIMPLE)
/* some older compilers do not like macro function in expression */
#define wc_RNG_GenerateBlock(rng, b, s) NOT_COMPILED_IN
#else
#ifdef _MSC_VER
#define wc_RNG_GenerateBlock(rng, b, s) (int)(NOT_COMPILED_IN)
#else
#define wc_RNG_GenerateBlock(rng, b, s) \
        ({(void)rng; (void)b; (void)s; NOT_COMPILED_IN;})
#endif
#endif
#define wc_RNG_GenerateByte(rng, b) NOT_COMPILED_IN
#define wc_FreeRng(rng) (void)NOT_COMPILED_IN
#endif

#ifdef WC_RNG_SEED_CB
    WOLFSSL_API int wc_SetSeed_Cb(wc_RngSeed_Cb cb);
#endif

#ifdef HAVE_HASHDRBG
    WOLFSSL_API int wc_RNG_DRBG_Reseed(WC_RNG* rng, const byte* seed,
                                       word32 seedSz);
    WOLFSSL_API int wc_RNG_TestSeed(const byte* seed, word32 seedSz);
    WOLFSSL_API int wc_RNG_HealthTest(int reseed,
                                        const byte* seedA, word32 seedASz,
                                        const byte* seedB, word32 seedBSz,
                                        byte* output, word32 outputSz);
    WOLFSSL_API int wc_RNG_HealthTest_ex(int reseed,
                                        const byte* nonce, word32 nonceSz,
                                        const byte* seedA, word32 seedASz,
                                        const byte* seedB, word32 seedBSz,
                                        byte* output, word32 outputSz,
                                        void* heap, int devId);
#endif /* HAVE_HASHDRBG */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_RANDOM_H */

