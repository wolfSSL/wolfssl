/* random.h
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

#ifndef WC_RNG_NO_POOL
    #ifndef WC_RNG_HAVE_POOL
        #define WC_RNG_HAVE_POOL
    #endif
    #ifdef WOLFSSL_NO_ATOMICS
        typedef word32 WC_RNG_pool_state_t;
    #else
        typedef wolfSSL_Atomic_Uint WC_RNG_pool_state_t;
    #endif
#else
    #undef WC_RNG_HAVE_POOL
#endif

#ifndef WC_RNG_NO_RBGC
    #if !defined(WC_RNG_HAVE_RBGC) && \
        defined(HAVE_HASHDRBG) && \
        !defined(CUSTOM_RAND_GENERATE_BLOCK)
        #define WC_RNG_HAVE_RBGC
    #endif
#else
    #undef WC_RNG_HAVE_RBGC
#endif

/* _FULL_MUTEX is opt-in, and depends on WC_RNG_HAVE_LOCK. */
#ifdef WC_RNG_NO_LOCK_FULL_MUTEX
    #undef WC_RNG_HAVE_LOCK_FULL_MUTEX
#elif defined(WC_RNG_HAVE_LOCK_FULL_MUTEX)
    #ifdef WC_RNG_NO_LOCK
        #error FULL_MUTEX depends on WC_RNG_HAVE_LOCK.
    #endif
#endif

#ifndef WC_RNG_NO_FREE_HOOK
    #define WC_RNG_HAVE_FREE_HOOK
#endif
#ifdef WC_RNG_HAVE_FREE_HOOK
    struct WC_RNG; /* tag forward-declaration for the callback signature */
    typedef int (*wc_RNG_free_hook_cb_t)(const struct WC_RNG *rng, void *arg);
#endif

#ifndef WC_RNG_NO_LOCK
    #ifndef WC_RNG_HAVE_LOCK
        #define WC_RNG_HAVE_LOCK
    #endif
    #ifdef WOLFSSL_NO_ATOMICS
        typedef word32 WC_RNG_lock_t;
        typedef word32 WC_RNG_lock_arg_t;
    #else
        typedef wolfSSL_Atomic_Uint WC_RNG_lock_t;
        typedef WC_ATOMIC_UINT_ARG WC_RNG_lock_arg_t;
    #endif
#else
    #undef WC_RNG_HAVE_LOCK
#endif

#if !defined(HAVE_HASHDRBG) || defined(CUSTOM_RAND_GENERATE_BLOCK) && \
    !defined(WC_RNG_NO_NEXT_SEED)
    #define WC_RNG_NO_NEXT_SEED
#endif
#ifndef WC_RNG_NO_NEXT_SEED
    #ifndef WC_RNG_HAVE_NEXT_SEED
        #define WC_RNG_HAVE_NEXT_SEED
    #endif
    #ifdef WOLFSSL_NO_ATOMICS
        typedef sword32 WC_DRBG_nextSeedLen_t;
    #else
        typedef wolfSSL_Atomic_Int WC_DRBG_nextSeedLen_t;
    #endif
#else
    #undef WC_RNG_HAVE_NEXT_SEED
#endif

 /* Maximum generate block length */
#ifndef RNG_MAX_BLOCK_LEN
    #ifdef HAVE_INTEL_QA
        #define RNG_MAX_BLOCK_LEN (0xFFFFl)
    #else
        #define RNG_MAX_BLOCK_LEN (0x10000l)
    #endif
#endif

/* Size of the DRBG seed (SHA-256) */
#ifndef DRBG_SEED_LEN
    #define DRBG_SEED_LEN (440/8)
#endif

#ifdef WOLFSSL_DRBG_SHA512
    #define DRBG_SHA512_SEED_LEN (888/8)  /* 111 bytes per SP 800-90A Table 2 */
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
        #define WC_RESEED_INTERVAL 1000000
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
        #ifndef WOLFSSL_DRBG_SHA512
            #error "Hash DRBG requires SHA-256 or SHA-512."
        #endif
    #endif /* NO_SHA256 */
    #ifndef NO_SHA256
        #include <wolfssl/wolfcrypt/sha256.h>
    #endif
    #ifdef WOLFSSL_DRBG_SHA512
        #include <wolfssl/wolfcrypt/sha512.h>
    #endif
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

#ifndef WC_OS_SEED_TYPE_DEFINED
    typedef struct OS_Seed OS_Seed;
    #define WC_OS_SEED_TYPE_DEFINED
#endif
#ifndef WC_RNG_TYPE_DEFINED /* guard on redeclaration */
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
        WC_BITFIELD seedFdOpen:1;
        WC_BITFIELD keepSeedFdOpen:1;
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
#else
    /* Maximum entropy bits that can be produced. */
    #define MAX_ENTROPY_BITS    256
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

/* WC_DRBG_SEED_SZ is the number of bytes of raw entropy gathered from the
 * NDRNG at instantiation and reseed. We deliberately "overseed" beyond the
 * NIST minimum (security_strength bits) to account for entropy sources that
 * may deliver fewer than 1 bit of real entropy per bit of output.  With the
 * default FIPS ENTROPY_SCALE_FACTOR of 4 this yields 256*4/8 = 128 bytes =
 * 1024 bits of raw seed material, guaranteeing at least 256 bits of real
 * entropy even if the source provides only 1 good bit per 4.
 *
 * Hash_df then compresses this seed material into the internal V and C state
 * vectors (seedlen = 440 bits for SHA-256, 888 bits for SHA-512 per
 * SP 800-90A Table 2).
 *
 * In FIPS mode (ENTROPY_SCALE_FACTOR >= 4) the base is already >= 128 bytes
 * which exceeds DRBG_SHA512_SEED_LEN (111), so both DRBGs use the same
 * seed size.  In non-FIPS mode we use the base for both DRBGs so that
 * enabling SHA-512 DRBG does not inflate the per-init entropy cost.
 * SP 800-90A requires only security_strength bits (256 = 32 bytes) of
 * entropy regardless of hash size; hash_df compresses the seed material
 * into the internal V/C state vectors. */
#define WC_DRBG_SEED_SZ_BASE  (RNG_SECURITY_STRENGTH*ENTROPY_SCALE_FACTOR/8)

#if defined(HAVE_FIPS) && defined(WOLFSSL_DRBG_SHA512) && \
    (WC_DRBG_SEED_SZ_BASE < DRBG_SHA512_SEED_LEN)
    #define WC_DRBG_SEED_SZ    DRBG_SHA512_SEED_LEN
#else
    #define WC_DRBG_SEED_SZ    WC_DRBG_SEED_SZ_BASE
#endif

/* The maximum seed size will be the seed size plus a seed block for the
 * test, and an additional half of the seed size. This additional half
 * is in case the user does not supply a nonce. A nonce will be obtained
 * from the NDRNG. */
#define WC_DRBG_MAX_SEED_SZ    (WC_DRBG_SEED_SZ + WC_DRBG_SEED_SZ/2 + \
                                SEED_BLOCK_SZ)

#ifndef NO_SHA256
    #define RNG_HEALTH_TEST_CHECK_SIZE (WC_SHA256_DIGEST_SIZE * 4)
#endif
#ifdef WOLFSSL_DRBG_SHA512
    #define RNG_HEALTH_TEST_CHECK_SIZE_SHA512 (WC_SHA512_DIGEST_SIZE * 4)
#endif

#ifndef NO_SHA256

#ifdef WC_RNG_HAVE_NEXT_SEED
    /* Length of the banked next seed: identical byte accounting to other
     * source-fed (re)seeds in the module (gather SEED_SZ + SEED_BLOCK_SZ, apply
     * the block-offset remainder). */
    #define WC_DRBG_NEXT_SEED_LEN (WC_DRBG_SEED_SZ + WC_DRBG_SEED_BLOCK_SZ)
    #define WC_DRBG_NEXT_UNCREDITED_SEED_LEN 64
#endif

struct DRBG_internal {
    #ifdef WORD64_AVAILABLE
    word64 reseedCtr;
    #else
    word32 reseedCtr;
    #endif
    byte V[DRBG_SEED_LEN];
    byte C[DRBG_SEED_LEN];
#ifdef WC_RNG_HAVE_NEXT_SEED
    byte nextSeed[WC_DRBG_NEXT_SEED_LEN];
    WC_DRBG_nextSeedLen_t nextSeedLen;
    #ifdef WC_RNG_HAVE_RBGC
    int nextSeedRBGCStratum;
    #endif
    byte nextUncreditedSeed[WC_DRBG_NEXT_UNCREDITED_SEED_LEN];
    WC_DRBG_nextSeedLen_t nextUncreditedSeedLen;
#endif
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
#endif /* !NO_SHA256 */

#ifdef WOLFSSL_DRBG_SHA512
struct DRBG_SHA512_internal {
    #ifdef WORD64_AVAILABLE
    word64 reseedCtr;
    #else
    word32 reseedCtr;
    #endif
    byte V[DRBG_SHA512_SEED_LEN];
    byte C[DRBG_SHA512_SEED_LEN];
#ifdef WC_RNG_HAVE_NEXT_SEED
    byte nextSeed[WC_DRBG_NEXT_SEED_LEN];
    WC_DRBG_nextSeedLen_t nextSeedLen;
    #ifdef WC_RNG_HAVE_RBGC
    int nextSeedRBGCStratum;
    #endif
    byte nextUncreditedSeed[WC_DRBG_NEXT_UNCREDITED_SEED_LEN];
    WC_DRBG_nextSeedLen_t nextUncreditedSeedLen;
#endif
    void* heap;
#if defined(WOLFSSL_ASYNC_CRYPT) || defined(WOLF_CRYPTO_CB)
    int devId;
#endif
#ifdef WOLFSSL_SMALL_STACK_CACHE
    wc_Sha512 sha512;
    byte seed_scratch[DRBG_SHA512_SEED_LEN];
    byte digest_scratch[WC_SHA512_DIGEST_SIZE];
#endif
};
#endif /* WOLFSSL_DRBG_SHA512 */
#endif /* HAVE_HASHDRBG */

/* DRBG type enum */
#ifdef HAVE_HASHDRBG
enum wc_DrbgType {
    WC_DRBG_SHA256 = 0,
    WC_DRBG_SHA512 = 1
};
#endif

/* RNG health states */
enum wc_RngHealthState {
    WC_DRBG_NOT_INIT =    0,
    WC_DRBG_OK =          1,
    WC_DRBG_FAILED =      2,
    WC_DRBG_CONT_FAILED = 3
};

#define WC_RNG_FLAG_NONE           0
#define WC_RNG_FLAG_RBGC_NEXT_SEED (1U << 0)
#define WC_RNG_FLAG_FULL_MUTEX     (1U << 1)
#define WC_RNG_FLAG_BANKREF        (1U << 2)
#define WC_RNG_FLAG_RECOVER_AND_PROMOTE_FROM_NEXT_SEED (1U << 3)

#ifdef WC_RNG_DEBUG_STATS
    #ifdef WORD64_AVAILABLE
        typedef word64 wc_rng_debug_counter_t;
    #else
        typedef word32 wc_rng_debug_counter_t;
    #endif
#endif

/* RNG context */
struct WC_RNG {
    struct OS_Seed seed;
    void* heap;
    byte status;
    word32 flags;
    #ifdef WC_RNG_DEBUG_STATS
        wc_rng_debug_counter_t _stats_total_bytes_requested;
        wc_rng_debug_counter_t _stats_total_bytes_produced;
        wc_rng_debug_counter_t _stats_total_requests;
        wc_rng_debug_counter_t _stats_credited_reseeds;
        wc_rng_debug_counter_t _stats_uncredited_reseeds;
        wc_rng_debug_counter_t _stats_seed_failures;
    #endif
#ifdef WC_RNG_HAVE_RBGC
    int RBGCStratum;
    #ifdef WC_RNG_DEBUG_STATS
        wc_rng_debug_counter_t _stats_RBGC_bytes_produced;
        wc_rng_debug_counter_t _stats_RBGC_reseeds;
    #endif
#endif
#ifdef WC_RNG_HAVE_LOCK
    WC_RNG_lock_t lock;
    #ifdef WC_RNG_HAVE_LOCK_FULL_MUTEX
    wolfSSL_Mutex mutex;
    #endif
    #ifdef WC_RNG_DEBUG_STATS
        wc_rng_debug_counter_t _stats_locks_taken;
        wc_rng_debug_counter_t _stats_locks_released;
        wc_rng_debug_counter_t _stats_locks_refused; /* racy */
    #endif
#endif
#ifdef WC_RNG_HAVE_FREE_HOOK
    /* fired by wc_FreeRng() before state destruction (one-shot);
     * see wc_RNG_register_free_hook(). */
    wc_RNG_free_hook_cb_t free_hook;
    void *free_hook_arg;
#endif
#ifdef WC_RNG_HAVE_POOL
    byte* pool;
    word16 poolSize;
    WC_RNG_pool_state_t poolState;
    #ifdef WC_RNG_DEBUG_STATS
        wc_rng_debug_counter_t _stats_pool_bytes_produced;
        wc_rng_debug_counter_t _stats_pool_bytes_missed;
    #endif
#endif

#ifdef WC_RNG_DEBUG_STATS
    #ifdef WC_RNG_HAVE_NEXT_SEED
        wc_rng_debug_counter_t _stats_n_nextseed_primary_redeemed;
        wc_rng_debug_counter_t _stats_n_nextseed_RBGC_redeemed;
        wc_rng_debug_counter_t _stats_n_nextuncreditedseed_redeemed;
        /* production-side twins of the consumption counters above; plain
         * increments, racy if there are competing seed bankers (usually
         * there aren't). */
        wc_rng_debug_counter_t _stats_n_nextseed_banked;
        wc_rng_debug_counter_t _stats_n_nextuncreditedseed_banked;
    #endif
#endif

#if defined(HAVE_HASHDRBG) || defined(WC_HAVE_RNG_BANKREF)

#ifdef HAVE_ANONYMOUS_INLINE_AGGREGATES
    union {
#endif

    #ifdef WC_HAVE_RNG_BANKREF
        struct wc_rng_bank *bankref;
    #endif

    #ifdef HAVE_HASHDRBG
        #ifdef HAVE_ANONYMOUS_INLINE_AGGREGATES
        struct {
        #endif
        #ifndef NO_SHA256
            /* SHA-256 Hash-based Deterministic Random Bit Generator */
            struct DRBG* drbg;
        #if defined(WOLFSSL_NO_MALLOC) && !defined(WOLFSSL_STATIC_MEMORY)
            struct DRBG_internal drbg_data;
        #endif
        #ifdef WOLFSSL_SMALL_STACK_CACHE
            /* SHA-256 scratch buffers -- preallocated by _InitRng(). */
            struct DRBG_internal *drbg_scratch;
            byte *health_check_scratch;
        #endif
        #endif /* !NO_SHA256 */
        #ifdef WOLFSSL_SMALL_STACK_CACHE
            /* Seed buffer for PollAndReSeed -- shared by both DRBG types */
            byte *newSeed_buf;
        #endif
        #ifdef WOLFSSL_DRBG_SHA512
            /* SHA-512 Hash-based Deterministic Random Bit Generator */
            struct DRBG_SHA512* drbg512;
        #if defined(WOLFSSL_NO_MALLOC) && !defined(WOLFSSL_STATIC_MEMORY)
            struct DRBG_SHA512_internal drbg512_data;
        #endif
        #ifdef WOLFSSL_SMALL_STACK_CACHE
            /* SHA-512 scratch buffers -- preallocated by _InitRng(). */
            struct DRBG_SHA512_internal *drbg512_scratch;
            byte *health_check_scratch_512;
        #endif
        #endif /* WOLFSSL_DRBG_SHA512 */
            byte drbgType; /* WC_DRBG_SHA256 or WC_DRBG_SHA512 */
        #ifdef HAVE_ANONYMOUS_INLINE_AGGREGATES
        };
        #endif
    #endif /* HAVE_HASHDRBG */

#ifdef HAVE_ANONYMOUS_INLINE_AGGREGATES
    };
#endif

#endif /* HAVE_HASHDRBG || WC_HAVE_RNG_BANKREF */

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

/* Ports layered on the generic noise source turn it on implicitly, so a
 * user_settings.h only has to name the port. */
#if defined(WOLFSSL_C2000_ENTROPY) && !defined(WOLFSSL_NOISE_SRC)
    #define WOLFSSL_NOISE_SRC
#endif

#ifdef WOLFSSL_NOISE_SRC

/* Generic SP800-90B noise source, for parts with a raw physical noise source
 * but no TRNG.  The port supplies one callback returning an unconditioned
 * octet; this layer adds the 4.3 startup test, the 4.4.1 RCT and 4.4.2 APT
 * continuous tests, a latched fail-closed state, entropy-budget oversampling
 * and a SHA-256 conditioner suitable for feeding wc_GenerateSeed().
 * Implementation and entropy model: wolfcrypt/src/random.c.  Worked example:
 * wolfcrypt/src/port/ti/ti-c2000-entropy.c. */

/* Noise sources one instance can combine. */
#ifndef WC_NOISE_SRC_MAX
    #define WC_NOISE_SRC_MAX 2
#endif
#if (WC_NOISE_SRC_MAX) < 1 || (WC_NOISE_SRC_MAX) > 16
    /* wc_NoiseSrc.degraded is a word16 bitmask of dropped sources. */
    #error "WC_NOISE_SRC_MAX must be 1..16"
#endif

/* Conditioner output per chunk in octets (SHA-256).  random.c asserts this
 * against WC_SHA256_DIGEST_SIZE so the two cannot drift; kept as a literal
 * here to avoid pulling sha256.h into random.h. */
#define WC_NOISE_CHUNK_SZ 32

/* Raw octets drawn per source per chunk, from the assumed min-entropy hmin
 * (hundredths of a bit per raw bit) and the oversample factor margin, rounded
 * up so an hmin that does not divide evenly never under-gathers.  Sizes the
 * gather of the credited source (index 0); any further source is extra hash
 * input and is not budgeted.  Exposed so a port can size its work buffer
 * without duplicating the formula. */
#define WC_NOISE_RAW_PER_SRC(hmin, margin)                                    \
    ((word32)((WC_NOISE_CHUNK_SZ *                                            \
        (((8UL * 100UL * (unsigned long)(margin)) +                           \
          ((unsigned long)(hmin) - 1UL)) / (unsigned long)(hmin))) / 8U))

/* Fill *octet with one raw, unconditioned noise octet from source srcIdx.
 * Returns 0 on success, negative on hardware failure. */
typedef int (*wc_NoiseSampleCb)(void* ctx, int srcIdx, byte* octet);

/* SP800-90B 4.4 state, one per source.  Persists across calls by design: the
 * tests are continuous, not per-request. */
typedef struct wc_NoiseHealth {
    word16 rctCount;
    word16 rctLast;
    word16 aptCount;
    word16 aptRef;
    word16 aptPos;
    byte   started;
} wc_NoiseHealth;

/* Caller-owned instance.  Fill the configuration members, then call
 * wc_NoiseSrc_Init(); it derives rawPerSrc and owns everything after it. */
typedef struct wc_NoiseSrc {
    wc_NoiseSampleCb sampleCb;      /* required */
    void*            ctx;           /* opaque, passed to sampleCb */
    const char*      tag;           /* domain separation string, required */
    byte*            work;          /* caller owned, >= numSrc * rawPerSrc */
    word32           workSz;
    word32           startupOctets; /* SP800-90B 4.3, per source */
    word32           chunkCtr;      /* hashed in so chunks cannot repeat */
    word32           rawPerSrc;     /* derived by wc_NoiseSrc_Init */
    wc_NoiseHealth   health[WC_NOISE_SRC_MAX];
    int              failed;        /* latched, cleared only by _Free */
    word16           rctCutoff;     /* SP800-90B 4.4.1 */
    word16           aptWindow;     /* SP800-90B 4.4.2 */
    word16           aptCutoff;
    word16           degraded;      /* bitmask of uncredited sources dropped */
    byte             numSrc;        /* 1 .. WC_NOISE_SRC_MAX */
    byte             hmin;          /* 1..100, hundredths of a bit per raw bit */
    byte             margin;        /* oversample factor, >= 1 */
    byte             inited;
} wc_NoiseSrc;

WOLFSSL_API int  wc_NoiseSrc_Init(wc_NoiseSrc* src);
WOLFSSL_API void wc_NoiseSrc_Free(wc_NoiseSrc* src);
WOLFSSL_API int  wc_NoiseSrc_GenerateSeed(wc_NoiseSrc* src, byte* output,
                                          word32 sz);
/* Raw, unconditioned octets for characterization and self-test only: these run
 * no health tests, so the output is not fit for keying material.
 *
 * They also do not advance the continuous-test state, which has a consequence
 * worth knowing: SP800-90B 4.4 scores a repetition run across consecutive
 * samples, and the octets drawn here are invisible to that accounting.  A run
 * that straddles one of these calls is therefore under-counted.  Draw
 * characterization data before seeding starts, or accept that a stuck source
 * spanning the call may take longer to be caught. */
WOLFSSL_API int  wc_NoiseSrc_GetRaw(wc_NoiseSrc* src, byte* output, word32 len,
                                    int srcIdx);
WOLFSSL_API int  wc_NoiseSrc_SelfTest(wc_NoiseSrc* src);

#endif /* WOLFSSL_NOISE_SRC */


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
WOLFSSL_API int  wc_InitRngNonce(WC_RNG* rng, const byte* nonce, word32 nonceSz);

#define WC_RNG_INIT_FLAGS_NONE            0
#define WC_RNG_INIT_FLAGS_LOCK_REQUIRED   (1U << 0)
#define WC_RNG_INIT_FLAGS_LOCK_INITIALLY  (1U << 1)
#define WC_RNG_INIT_FLAGS_USE_FULL_MUTEX  (1U << 2)
/* At each generate, if a banked next seed is READY, consume it when the
 * instance is flagged _ENTROPY_INVALIDATED (recovery; any provenance), or
 * when the instance is chain-backed and the banked seed is primary
 * (promotion).  For externally-refreshed long-lived RNGs, e.g. the kernel
 * module's registered RBGC leaves. */
#define WC_RNG_INIT_FLAGS_RECOVER_AND_PROMOTE_FROM_NEXT_SEED (1U << 3)

WOLFSSL_API int  wc_InitRng_ex2(WC_RNG* rng, void* heap, int devId,
                                word32 flags);
WOLFSSL_API int  wc_InitRngNonce_ex2(WC_RNG* rng, const byte* nonce, word32 nonceSz,
                                     void* heap, int devId, word32 flags);
WOLFSSL_API int  wc_InitRngNonce_ex(WC_RNG* rng, const byte* nonce, word32 nonceSz,
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
#define wc_InitRng_ex2(rng, h, d, f) NOT_COMPILED_IN
#define wc_InitRngNonce_ex2(rng, n, s, h, d, f) NOT_COMPILED_IN
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

WOLFSSL_API int wc_RNG_GetStatus(const WC_RNG* rng);
WOLFSSL_API int wc_RNG_DRBG_Present(const WC_RNG* rng);

#ifdef HAVE_HASHDRBG
    WOLFSSL_API int wc_RNG_DRBG_Reseed(WC_RNG* rng, const byte* seed,
                                       word32 seedSz);
    WOLFSSL_API int wc_RNG_DRBG_Reseed_Nonce(WC_RNG* rng, const byte* seed,
                                             word32 seedSz, const byte *nonce,
                                             word32 nonceSz);
    WOLFSSL_API int wc_RNG_DRBG_Reseed_Uncredited(WC_RNG* rng,
                                                  const byte* seed,
                                                  word32 seedSz);
    WOLFSSL_API int wc_RNG_DRBG_Reseed_Nonce_Uncredited(
                                 WC_RNG* rng, const byte* seed, word32 seedSz,
                                 const byte *nonce, word32 nonceSz);
    WOLFSSL_API int wc_RNG_DRBG_Reseed_Now(WC_RNG* rng, const byte* nonce,
                                           word32 nonceSz);
    WOLFSSL_API int wc_RNG_TestSeed(const byte* seed, word32 seedSz);

    /* Reseed-counter width tracks struct DRBG_internal above.  The sentinel
     * lets wolfssl/wolfcrypt/rng_bank.h supply the same typedef when building
     * against a legacy FIPS random.h that predates it. */
    #ifndef WC_DRBG_RESEED_CTR_TYPE_DEFINED
    #define WC_DRBG_RESEED_CTR_TYPE_DEFINED
        #ifdef WORD64_AVAILABLE
        typedef word64 wc_drbg_reseed_ctr_t;
        #else
        typedef word32 wc_drbg_reseed_ctr_t;
        #endif
    #endif

#ifdef WC_RNG_HAVE_RBGC
    WOLFSSL_API int wc_RNG_DRBG_GetRBGCStratum(const WC_RNG* rng);
    #ifdef WC_RNG_HAVE_NEXT_SEED
    WOLFSSL_API int wc_RNG_DRBG_GetNextSeedRBGCStratum(const WC_RNG* rng);
    #endif
#endif /* WC_RNG_HAVE_RBGC */
    WOLFSSL_API int wc_RNG_DRBG_GetReseedCtr(const WC_RNG* rng,
                                             wc_drbg_reseed_ctr_t* reseedCtr);
    WOLFSSL_API int wc_RNG_DRBG_ScheduleReseed(WC_RNG* rng);

#ifndef NO_SHA256
    /* SHA-256 Hash_DRBG health test entry points. SHA-512-only builds
     * (NO_SHA256 + WOLFSSL_DRBG_SHA512) use wc_RNG_HealthTest_SHA512_ex
     * declared below. */
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
#endif /* !NO_SHA256 */
#if !defined(NO_SHA256) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))
    /* Extended SHA-256 Hash_DRBG health test per SP 800-90A.
     * Flexible output size, prediction resistance, personalization
     * strings, and additional input support. */
    WOLFSSL_API int wc_RNG_HealthTest_SHA256_ex(
                                        int predResistance,
                                        const byte* nonce, word32 nonceSz,
                                        const byte* persoString,
                                            word32 persoStringSz,
                                        const byte* entropyA,
                                            word32 entropyASz,
                                        const byte* entropyB,
                                            word32 entropyBSz,
                                        const byte* entropyC,
                                            word32 entropyCsz,
                                        const byte* additionalA,
                                            word32 additionalASz,
                                        const byte* additionalB,
                                            word32 additionalBSz,
                                        const byte* additionalReseed,
                                            word32 additionalReseedSz,
                                        byte* output, word32 outputSz,
                                        void* heap, int devId);
#endif /* !NO_SHA256 && !HAVE_SELFTEST && FIPS v7+ */
#if defined(WOLFSSL_DRBG_SHA512) && !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))
    WOLFSSL_API int wc_RNG_HealthTest_SHA512(int reseed,
                                        const byte* seedA, word32 seedASz,
                                        const byte* seedB, word32 seedBSz,
                                        byte* output, word32 outputSz);
    WOLFSSL_API int wc_RNG_HealthTest_SHA512_ex(int reseed,
                                        const byte* nonce, word32 nonceSz,
                                        const byte* persoString,
                                            word32 persoStringSz,
                                        const byte* seedA, word32 seedASz,
                                        const byte* seedB, word32 seedBSz,
                                        const byte* additionalA,
                                            word32 additionalASz,
                                        const byte* additionalB,
                                            word32 additionalBSz,
                                        byte* output, word32 outputSz,
                                        void* heap, int devId);
    /* Extended SHA-512 Hash_DRBG health test per SP 800-90A.
     * Flexible output size, prediction resistance support.
     * predResistance=1: additionalA/B go to Reseed per SP 800-90A 9.3.1,
     *                   Generate gets NULL additional input.
     * predResistance=0: additionalReseed goes to Reseed, additionalA/B go
     *                   to Generate calls 1 and 2 respectively. */
    WOLFSSL_API int wc_RNG_HealthTest_SHA512_ex2(
                                        int predResistance,
                                        const byte* nonce, word32 nonceSz,
                                        const byte* persoString,
                                            word32 persoStringSz,
                                        const byte* entropyA,
                                            word32 entropyASz,
                                        const byte* entropyB,
                                            word32 entropyBSz,
                                        const byte* entropyC,
                                            word32 entropyCsz,
                                        const byte* additionalA,
                                            word32 additionalASz,
                                        const byte* additionalB,
                                            word32 additionalBSz,
                                        const byte* additionalReseed,
                                            word32 additionalReseedSz,
                                        byte* output, word32 outputSz,
                                        void* heap, int devId);
#endif /* WOLFSSL_DRBG_SHA512 && !HAVE_SELFTEST && FIPS v7+ */

    /* Runtime DRBG disable/enable API */
#if !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))
    WOLFSSL_API int wc_Sha256Drbg_Disable(void);
    WOLFSSL_API int wc_Sha256Drbg_Enable(void);
    WOLFSSL_API int wc_Sha256Drbg_IsDisabled(void);
#ifdef WOLFSSL_DRBG_SHA512
    WOLFSSL_API int wc_Sha512Drbg_Disable(void);
    WOLFSSL_API int wc_Sha512Drbg_Enable(void);
    WOLFSSL_API int wc_Sha512Drbg_IsDisabled(void);
#endif
#endif /* !HAVE_SELFTEST && (!HAVE_FIPS || FIPS v7+) */

    /* DRBG state mutex init/free, called from wolfCrypt_Init/Cleanup.
     * Only in v7+ or non-FIPS/non-selftest; older modules lack these. */
#if !defined(HAVE_SELFTEST) && \
    (!defined(HAVE_FIPS) || FIPS_VERSION3_GE(7,0,0))
    WOLFSSL_LOCAL int wc_DrbgState_MutexInit(void);
    WOLFSSL_LOCAL int wc_DrbgState_MutexFree(void);
#endif

#endif /* HAVE_HASHDRBG */

#ifdef WC_RNG_HAVE_RBGC
    /* SP 800-90C RBG-chain spawn: instantiate child as a subordinate DRBG
     * seeded from parent's generate output.  The _New variants allocate the
     * child from parent's heap; release them with ordinary wc_rng_free(). */
    WOLFSSL_API int wc_InitRngRBGC(WC_RNG* child, WC_RNG* parent, word32 flags);
    WOLFSSL_API int wc_InitRngNonceRBGC(WC_RNG* child, WC_RNG* parent,
                                        const byte* nonce, word32 nonceSz,
                                        word32 flags);
    #ifndef WC_NO_CONSTRUCTORS
    /* flags are per-object (WC_RNG_INIT_FLAGS_*), deliberately NOT
     * inherited from the parent: a child's lock policy is its own. */
    WOLFSSL_API int wc_InitRngRBGC_New(WC_RNG** child, WC_RNG* parent,
                                       word32 flags);
    WOLFSSL_API int wc_InitRngNonceRBGC_New(WC_RNG** child, WC_RNG* parent,
                                            const byte* nonce, word32 nonceSz,
                                            word32 flags);
    #endif /* !WC_NO_CONSTRUCTORS */
    /* Note, only a root RNG -- stratum 0, i.e. primary-seeded -- is permitted
     * to generate reseed bytes (wolfCrypt policy; stricter than SP 800-90C
     * 7.1.2.2, which also permits parent reseed). */
    WOLFSSL_API int wc_RNG_DRBG_ReseedRBGC(WC_RNG* rng, WC_RNG* root,
                                           const byte* nonce, word32 nonceSz);
    WOLFSSL_API int wc_RNG_DRBG_ReseedRBGC_Uncredited(WC_RNG* rng,
                                                      WC_RNG* root,
                                                      const byte* nonce,
                                                      word32 nonceSz);
#endif /* WC_RNG_HAVE_RBGC */

#ifdef WC_RNG_HAVE_NEXT_SEED
    #define WC_DRBG_NEXT_SEED_EMPTY 0
    /* All sentinel states are negative; non-negative values are banked byte
     * counts. */
    #define WC_DRBG_NEXT_SEED_READY ((WC_ATOMIC_INT_ARG)(-2))
    #define WC_DRBG_NEXT_SEED_CONSUMING ((WC_ATOMIC_INT_ARG)(-1))

    WOLFSSL_API int wc_RNG_DRBG_NextSeedGenerate(WC_RNG* rng, word32 n);
#ifdef WC_RNG_HAVE_RBGC
    WOLFSSL_API int wc_RNG_DRBG_NextSeedGenerate_RBGC(WC_RNG* rng,
                                                      WC_RNG *root,
                                                      word32 n);
#endif
    WOLFSSL_API int wc_RNG_DRBG_NextSeedCurrent(WC_RNG* rng,
                                                WC_ATOMIC_INT_ARG* n);
    WOLFSSL_API int wc_RNG_DRBG_NextSeedNow_Nonce(WC_RNG* rng,
                                                   const byte* nonce,
                                                   word32 nonceSz);
    WOLFSSL_API int wc_RNG_DRBG_NextSeedNow(WC_RNG* rng);
    WOLFSSL_API int wc_RNG_DRBG_NextUncreditedSeedStore(WC_RNG* rng,
                                                        const byte *nonce,
                                                        word32 nonceSz);
    WOLFSSL_API int wc_RNG_DRBG_NextUncreditedSeedNow(WC_RNG* rng);

#endif /* WC_RNG_HAVE_NEXT_SEED */

#ifdef WC_RNG_HAVE_LOCK
    #define WC_RNG_LOCK_FREE 0
    #define WC_RNG_LOCK_HELD (1U<<0)
    #define WC_RNG_LOCK_REQUIRED (1U<<1)
    #define WC_RNG_LOCK_ENTROPY_INVALIDATED (1U<<2)
    /* consumers' annotation bits start here (see e.g. rng_bank.h) */
    #define WC_RNG_LOCK_EXTRA_SHIFT 3U

    WOLFSSL_API int wc_RNG_lock_get(WC_RNG* rng, WC_RNG_lock_arg_t extra_bits);
    WOLFSSL_API int wc_RNG_lock_get_conditional(WC_RNG* rng,
                                                WC_RNG_lock_arg_t expected_extra_bits,
                                                WC_RNG_lock_arg_t want_extra_bits);
    WOLFSSL_API int wc_RNG_lock_put(WC_RNG* rng, WC_RNG_lock_arg_t extra_bits);
    WOLFSSL_API int wc_RNG_lock_put_conditional(WC_RNG* rng,
                                                WC_RNG_lock_arg_t expected_extra_bits,
                                                WC_RNG_lock_arg_t want_extra_bits);
    WOLFSSL_API int wc_RNG_lock_read(WC_RNG* rng, WC_RNG_lock_arg_t* state);
    WOLFSSL_API int wc_RNG_lock_set_extra(WC_RNG* rng,
                                          WC_RNG_lock_arg_t extra_bits);
    WOLFSSL_API int wc_RNG_lock_add_extra(WC_RNG* rng,
                                          WC_RNG_lock_arg_t extra_bits);
    WOLFSSL_API int wc_RNG_lock_clear_extra(WC_RNG* rng,
                                            WC_RNG_lock_arg_t extra_bits);
    WOLFSSL_API int wc_RNG_invalidate_entropy(WC_RNG* rng);
#endif /* WC_RNG_HAVE_LOCK */

#ifdef WC_RNG_HAVE_FREE_HOOK
/* Register a callback fired by wc_FreeRng() immediately before state
 * destruction, e.g. to unlink the object from an external registry.
 * One-shot: cleared before firing.  A NULL free_hook unregisters.
 * Reinitialization (wc_InitRng*() on a live object) clears any
 * registered hook without firing it: hooks are per-lifetime. */
WOLFSSL_API int wc_RNG_register_free_hook(WC_RNG* rng,
                                          wc_RNG_free_hook_cb_t free_hook,
                                          void *arg);
#endif

#ifdef WC_RNG_HAVE_POOL
    WOLFSSL_API int wc_RNG_Pool_Alloc(WC_RNG* rng, word32 size);
    WOLFSSL_API int wc_RNG_Pool_Collect(WC_RNG* rng, word32 n);
    WOLFSSL_API int wc_RNG_Pool_Collect2(WC_RNG* rng_dest, WC_RNG* rng_src,
                                         word32 n);
    WOLFSSL_API int wc_RNG_Pool_Extract(WC_RNG* rng, byte* out, word32* n);
    WOLFSSL_API int wc_RNG_Pool_Current(WC_RNG* rng, word32* n);
#endif /* WC_RNG_HAVE_POOL */

#ifdef WC_RNG_DEBUG_STATS
struct wc_rng_debug_stats_snapshot {
    wc_rng_debug_counter_t _stats_total_bytes_requested;
    wc_rng_debug_counter_t _stats_total_bytes_produced;
    wc_rng_debug_counter_t _stats_total_requests;
    wc_rng_debug_counter_t _stats_credited_reseeds;
    wc_rng_debug_counter_t _stats_uncredited_reseeds;
    wc_rng_debug_counter_t _stats_seed_failures;
    wc_rng_debug_counter_t _stats_locks_taken;
    wc_rng_debug_counter_t _stats_locks_released;
    wc_rng_debug_counter_t _stats_locks_refused;
#ifdef WC_RNG_HAVE_RBGC
    wc_rng_debug_counter_t _stats_RBGC_bytes_produced;
    wc_rng_debug_counter_t _stats_RBGC_reseeds;
#endif
#ifdef WC_RNG_HAVE_POOL
    wc_rng_debug_counter_t _stats_pool_bytes_produced;
    wc_rng_debug_counter_t _stats_pool_bytes_missed;
#endif
#ifdef WC_RNG_HAVE_NEXT_SEED
    wc_rng_debug_counter_t _stats_n_nextseed_primary_redeemed;
    wc_rng_debug_counter_t _stats_n_nextseed_RBGC_redeemed;
    wc_rng_debug_counter_t _stats_n_nextuncreditedseed_redeemed;
    wc_rng_debug_counter_t _stats_n_nextseed_banked;
    wc_rng_debug_counter_t _stats_n_nextuncreditedseed_banked;
#endif
};

WOLFSSL_API int wc_rng_debug_stats_snap(struct wc_rng_debug_stats_snapshot *s,
                                        const WC_RNG *rng);
WOLFSSL_API int wc_rng_debug_stats_restore(
    const struct wc_rng_debug_stats_snapshot *s,
    WC_RNG *rng);
WOLFSSL_API int wc_rng_debug_stats_sum(struct wc_rng_debug_stats_snapshot *s,
                                       const WC_RNG *rng);
#endif /* WC_RNG_DEBUG_STATS */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_RANDOM_H */

