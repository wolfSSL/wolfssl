/* wc_falcon_sampler.h
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
    \file wolfssl/wolfcrypt/wc_falcon_sampler.h
*/

/* Discrete Gaussian sampler for Falcon signing (SamplerZ).
 *
 * This is a faithful port of the constant-time reference sampler by Thomas
 * Pornin (MIT-licensed Falcon reference implementation; the same code ships in
 * PQClean as PQCLEAN_FALCONxxx_CLEAN_gaussian0_sampler / BerExp / sampler).
 * The floating-point work is done exclusively through the abstract fpr_* seam
 * (wolfssl/wolfcrypt/wc_falcon_fpr.h), so the sampler inherits the deterministic
 * bit-exact, branch-free IEEE-754 behaviour of whatever fpr backend is active.
 *
 * SECURITY: the sampler is constant-time with respect to the secret center
 * (mu) and the secret inverse standard deviation (isigma). There are no
 * secret-dependent branches or memory accesses; see the notes in
 * wc_falcon_sampler.c. Randomness is drawn from a SHAKE256 stream seeded from a
 * WC_RNG instance. This file is compiled only on the signing side. */

#ifndef WOLF_CRYPT_WC_FALCON_SAMPLER_H
#define WOLF_CRYPT_WC_FALCON_SAMPLER_H

#include <wolfssl/wolfcrypt/types.h>

#if defined(HAVE_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY)

#include <wolfssl/wolfcrypt/wc_falcon_fpr.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* PRNG buffer: an integral number of SHAKE256 squeeze blocks (rate = 136
 * bytes). 136 is divisible by 8, so 8-byte reads never straddle the boundary
 * that triggers a refill. */
#define FALCON_PRNG_BLOCKS   8
#define FALCON_PRNG_BUFLEN   (FALCON_PRNG_BLOCKS * WC_SHA3_256_BLOCK_SIZE)

/* SHAKE256-backed pseudo-random byte stream.
 *
 * Construction: the SHAKE256 sponge absorbs a seed obtained from WC_RNG
 * (FALCON_PRNG_SEED_LEN fresh random bytes), then is squeezed in fixed-size
 * blocks. get_u8 returns the next stream byte; get_u64 returns the next 8
 * stream bytes interpreted little-endian. */
typedef struct falcon_prng {
    wc_Shake shake;                 /* SHAKE256 sponge state          */
    byte     buf[FALCON_PRNG_BUFLEN];/* squeezed stream buffer         */
    word32   ptr;                   /* index of next byte to consume  */
    word32   len;                   /* number of valid bytes in buf   */
} falcon_prng;

/* Sampler context: the PRNG plus the parameter-set-dependent sigma_min. */
typedef struct falcon_sampler_ctx {
    falcon_prng p;
    fpr        sigma_min;           /* sigma_min for the active logn  */
} falcon_sampler_ctx;

/* Seed length (bytes) drawn from WC_RNG to key the SHAKE256 stream. */
#define FALCON_PRNG_SEED_LEN 56

/* PRNG primitives. */
WOLFSSL_LOCAL int    falcon_prng_init(falcon_prng* p, WC_RNG* rng);
WOLFSSL_LOCAL byte   falcon_prng_get_u8(falcon_prng* p);
WOLFSSL_LOCAL word64 falcon_prng_get_u64(falcon_prng* p);

/* Initialise a sampler context for the given degree (logn = 9 or 10), seeding
 * the PRNG from rng. Returns 0 on success or a negative wolfCrypt error. */
WOLFSSL_LOCAL int falcon_sampler_init(falcon_sampler_ctx* spc, int logn,
    WC_RNG* rng);

/* The base half-Gaussian sampler (z >= 0, sigma0 = 1.8205). Exposed for test
 * harnesses; consumes 9 PRNG bytes. */
WOLFSSL_LOCAL int falcon_gaussian0(falcon_prng* p);

/* SamplerZ: return an integer sampled from the discrete Gaussian of center mu
 * and standard deviation 1/isigma. ctx is a (falcon_sampler_ctx*). */
WOLFSSL_LOCAL int falcon_sampler_z(void* ctx, fpr mu, fpr isigma);

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY */
#endif /* WOLF_CRYPT_WC_FALCON_SAMPLER_H */
