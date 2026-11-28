/* rng_noisesrc.h
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
    \file wolfssl/wolfcrypt/rng_noisesrc.h
*/

/* Generic SP800-90B noise source, for parts with a raw physical noise source
 * but no TRNG.  The port supplies one callback returning an unconditioned
 * octet; this layer adds the 4.3 startup test, the 4.4.1 RCT and 4.4.2 APT
 * continuous tests, entropy-budget oversampling and a SHA3-256 conditioner
 * suitable for feeding wc_GenerateSeed().  Implementation and entropy model:
 * wolfcrypt/src/rng_noisesrc.c.  Worked example:
 * wolfcrypt/src/port/ti/ti-c2000-entropy.c. */

#ifndef WOLF_CRYPT_RNG_NOISESRC_H
#define WOLF_CRYPT_RNG_NOISESRC_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_NOISE_SRC

#ifdef __cplusplus
    extern "C" {
#endif

/* Noise sources one instance can combine.  Each costs one wc_NoiseHealth,
 * about 1.5 KB. */
#ifndef WC_NOISE_SRC_MAX
    #define WC_NOISE_SRC_MAX 2
#endif
#if (WC_NOISE_SRC_MAX) < 1 || (WC_NOISE_SRC_MAX) > 16
    #error "WC_NOISE_SRC_MAX must be 1..16"
#endif

/* SP800-90B 4.4 defaults, the wolfEntropy values for H = 1 bit of
 * min-entropy per octet at alpha = 2^-30 (derivation in
 * wolfcrypt/src/rng_noisesrc.c).  A zero cutoff, window or startupOctets in
 * a wc_NoiseSrc selects these. */
#define WC_NOISE_RCT_CUTOFF_DEF     31
#define WC_NOISE_APT_WINDOW_DEF     512
#define WC_NOISE_APT_CUTOFF_DEF     325
/* SP800-90B 4.3: 1024 samples through the continuous tests, plus one APT
 * window to fill it. */
#define WC_NOISE_STARTUP_DEF        (1024 + WC_NOISE_APT_WINDOW_DEF)

/* Conditioner output per chunk in octets (SHA3-256).  rng_noisesrc.c asserts
 * this against WC_SHA3_256_DIGEST_SIZE so the two cannot drift; kept as a
 * literal here to avoid pulling sha3.h into this header. */
#define WC_NOISE_CHUNK_SZ 32

/* Defaults for a zero hmin / margin: wolfEntropy's 0.1 bits per raw bit, no
 * extra oversampling, which gathers 320 raw octets per 32-octet chunk. */
#define WC_NOISE_HMIN_DEF   10
#define WC_NOISE_MARGIN_DEF 1

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

/* SP800-90B 4.4.1 Repetition Count Test and 4.4.2 Adaptive Proportion Test
 * state, one per source.  Persists across calls by design: the tests are
 * continuous, not per-request. */
typedef struct wc_NoiseHealth {
    word16 aptSamples[WC_NOISE_APT_WINDOW_DEF];  /* APT circular queue */
    word16 aptCnt[256];         /* per-value count in queue */
    word16 rctCnt;              /* run length of rctPrev */
    word16 aptTotal;            /* samples in queue */
    word16 aptFirst;
    word16 aptLast;
    byte   rctHavePrev;
    byte   rctPrev;
} wc_NoiseHealth;

/* Caller-owned instance.  Fill the configuration members, then call
 * wc_NoiseSrc_Init().  A zero hmin, margin, cutoff, window or startupOctets
 * selects the default.  Init derives rawPerSrc and owns everything else. */
typedef struct wc_NoiseSrc {
    wc_NoiseHealth   health[WC_NOISE_SRC_MAX];
    wc_NoiseSampleCb sampleCb;      /* required */
    void*            ctx;           /* opaque, passed to sampleCb */
    const char*      tag;           /* domain separation string, required */
    byte*            work;          /* caller owned, >= numSrc * rawPerSrc */
    word32           workSz;
    word32           startupOctets; /* SP800-90B 4.3, per source */
    word32           chunkCtr;      /* hashed in so chunks cannot repeat */
    word32           rawPerSrc;     /* derived by wc_NoiseSrc_Init */
    word16           rctCutoff;     /* SP800-90B 4.4.1 */
    word16           aptWindow;     /* SP800-90B 4.4.2, <= 512 */
    word16           aptCutoff;
    byte             numSrc;        /* 1 .. WC_NOISE_SRC_MAX */
    byte             hmin;          /* 1..100, 1/100 bits per raw bit */
    byte             margin;        /* oversample factor, >= 1 */
    byte             inited;
} wc_NoiseSrc;

/* Validates the configuration once, then runs the SP800-90B 4.3 startup test
 * for every source whose health-test state is empty: all of them on the first
 * call, and on later calls any source a test verdict has reset.  The other
 * entry points call it first, so a failed startup is retried by the next
 * call. */
WOLFSSL_API int  wc_NoiseSrc_Init(wc_NoiseSrc* src);
WOLFSSL_API void wc_NoiseSrc_Free(wc_NoiseSrc* src);
/* A health-test failure on any source returns ENTROPY_RT_E or ENTROPY_APT_E,
 * wipes output, and resets that source's test state; the next call reruns the
 * 4.3 startup test for it.  A sampler error propagates as returned by the
 * callback, also with output wiped. */
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
/* Liveness check on the raw noise.  A source that fails it has its test state
 * reset, so the next call reruns its startup test. */
WOLFSSL_API int  wc_NoiseSrc_SelfTest(wc_NoiseSrc* src);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_NOISE_SRC */
#endif /* WOLF_CRYPT_RNG_NOISESRC_H */
