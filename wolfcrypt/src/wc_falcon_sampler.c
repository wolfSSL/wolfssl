/* wc_falcon_sampler.c
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

/* Discrete Gaussian sampler (SamplerZ) for FN-DSA / Falcon signing.
 *
 * This is a faithful port of the constant-time reference sampler written by
 * Thomas Pornin for the Falcon submission (MIT licensed). The identical code
 * is distributed in PQClean as the gaussian0_sampler / BerExp / sampler trio
 * (e.g. crypto_sign/falcon-512/clean/sign.c). It has been adapted to wolfSSL
 * house style (word32/word64/sword64, WOLFSSL_LOCAL linkage) and re-targeted
 * onto two wolfSSL seams:
 *
 *   1. The floating-point seam wolfssl/wolfcrypt/wc_falcon_fpr.h. All real
 *      arithmetic goes through fpr_* (round-to-nearest-even IEEE-754 binary64,
 *      bit-exact and branch-free in the default integer-emulated backend), and
 *      the Bernoulli test uses fpr_expm_p63().
 *   2. A SHAKE256 randomness stream (wolfssl/wolfcrypt/sha3.h) seeded from a
 *      WC_RNG (wolfssl/wolfcrypt/random.h), replacing the reference's ChaCha20
 *      PRNG. The sampler algorithm is agnostic to the byte source; only the
 *      uniform-byte contract matters for correctness and security.
 *
 * CONSTANT TIME / SIDE CHANNELS
 *   - gaussian0() consumes a fixed 9 random bytes and runs a fixed-length,
 *     branch-free table scan (comparison via borrow bits), so its running time
 *     and PRNG consumption are independent of the sampled value.
 *   - BerExp() and sampler() perform no branch or memory access that depends
 *     on the secret center (mu) or secret inverse-sigma (isigma): the only
 *     data-dependent control flow is the rejection-sampling retry loop and
 *     BerExp's lazy byte comparison, both of which depend solely on fresh
 *     uniform random bytes (the rejection probability is deliberately
 *     decorrelated from mu/sigma by the sigma_min scaling factor ccs). This is
 *     the standard Falcon argument; see the reference comments reproduced
 *     below.
 *   - The fpr backend supplies constant-time, value-independent arithmetic, so
 *     no floating-point operation leaks operand values through timing.
 *
 * This translation unit is the signing-only sampler and is therefore excluded
 * from verify-only builds. */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(HAVE_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY) && !defined(WOLF_CRYPTO_CB_ONLY_FALCON)

#include <wolfssl/wolfcrypt/wc_falcon_sampler.h>
#include <wolfssl/wolfcrypt/wc_falcon_fpr.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* ------------------------------------------------------------------------ */
/* fpr constants needed by the sampler that are not exported by the seam.    */
/*                                                                           */
/* These are IEEE-754 binary64 bit patterns, identical to the values used by */
/* the Falcon reference (fpr.h). Each has been verified by decoding the bit  */
/* pattern back to the documented decimal value (shown in the comment).      */
/* ------------------------------------------------------------------------ */

/* log(2) = 0.6931471805599453 */
static const fpr falcon_fpr_log2          = (fpr)4604418534313441775U;
/* 1/log(2) = 1.4426950408889634 */
static const fpr falcon_fpr_inv_log2      = (fpr)4609176140021203710U;
/* 1/(2*sigma0^2) with sigma0 = 1.8205  ->  0.15086504887537272 */
static const fpr falcon_fpr_inv_2sqrsigma0 = (fpr)4594603506513722306U;

/* sigma_min, indexed by logn (degree = 2^logn). These match the Falcon
 * specification's sigma_min(n) table; entries decode to a smooth monotonic
 * curve from 1.1165 (n=2) to 1.2983 (n=1024). FN-DSA uses logn 9 and 10:
 *   logn = 9  (FN-DSA-512 / Falcon-512 ) : 1.2778336969128337
 *   logn = 10 (FN-DSA-1024 / Falcon-1024) : 1.298280334344292            */
static const fpr falcon_fpr_sigma_min[11] = {
    (fpr)0U,                      /* logn 0 : unused        */
    (fpr)4607707126469777035U,    /* logn 1 : 1.1165085072  */
    (fpr)4607777455861499430U,    /* logn 2 : 1.1321247692  */
    (fpr)4607846828256951418U,    /* logn 3 : 1.1475285354  */
    (fpr)4607949175006100261U,    /* logn 4 : 1.1702540789  */
    (fpr)4608049571757433526U,    /* logn 5 : 1.1925466358  */
    (fpr)4608148125896792003U,    /* logn 6 : 1.2144300508  */
    (fpr)4608244935301382692U,    /* logn 7 : 1.2359260568  */
    (fpr)4608340089478362016U,    /* logn 8 : 1.2570545284  */
    (fpr)4608433670533905013U,    /* logn 9 : 1.2778336969  */
    (fpr)4608525754002622308U     /* logn 10: 1.2982803343  */
};

/* ------------------------------------------------------------------------ */
/* SHAKE256 pseudo-random byte stream.                                       */
/*                                                                           */
/* Construction: absorb FALCON_PRNG_SEED_LEN fresh bytes from WC_RNG into a   */
/* SHAKE256 sponge, then squeeze the output in fixed FALCON_PRNG_BLOCKS-block  */
/* batches. get_u64 reads 8 stream bytes little-endian; get_u8 reads one.    */
/* The refill is a fixed-size squeeze, hence constant-time; consumption order */
/* (and thus how many bytes are discarded at a refill boundary) never        */
/* depends on a secret.                                                      */
/* ------------------------------------------------------------------------ */

/* Squeeze a fresh batch of blocks into the buffer. Constant-time. */
static int falcon_prng_refill(falcon_prng* p)
{
    int ret = wc_Shake256_SqueezeBlocks(&p->shake, p->buf, FALCON_PRNG_BLOCKS);
    p->ptr = 0;
    p->len = (ret == 0) ? (word32)FALCON_PRNG_BUFLEN : 0;
    return ret;
}

int falcon_prng_init(falcon_prng* p, WC_RNG* rng)
{
    byte seed[FALCON_PRNG_SEED_LEN];
    int  ret;

    if (p == NULL || rng == NULL)
        return BAD_FUNC_ARG;

    ret = wc_RNG_GenerateBlock(rng, seed, (word32)sizeof(seed));
    if (ret == 0)
        ret = wc_InitShake256(&p->shake, NULL, INVALID_DEVID);
    if (ret == 0)
        ret = wc_Shake256_Absorb(&p->shake, seed, (word32)sizeof(seed));

    p->ptr = 0;
    p->len = 0;
    ForceZero(seed, (word32)sizeof(seed));

    if (ret == 0)
        ret = falcon_prng_refill(p);

    return ret;
}

byte falcon_prng_get_u8(falcon_prng* p)
{
    byte v;

    if (p->ptr + 1U > p->len)
        (void)falcon_prng_refill(p);
    v = p->buf[p->ptr];
    p->ptr += 1U;
    return v;
}

word64 falcon_prng_get_u64(falcon_prng* p)
{
    word64 v;
    word32 i;

    if (p->ptr + 8U > p->len)
        (void)falcon_prng_refill(p);
    i = p->ptr;
    v =  (word64)p->buf[i + 0]
      | ((word64)p->buf[i + 1] << 8)
      | ((word64)p->buf[i + 2] << 16)
      | ((word64)p->buf[i + 3] << 24)
      | ((word64)p->buf[i + 4] << 32)
      | ((word64)p->buf[i + 5] << 40)
      | ((word64)p->buf[i + 6] << 48)
      | ((word64)p->buf[i + 7] << 56);
    p->ptr += 8U;
    return v;
}

/* ------------------------------------------------------------------------ */
/* gaussian0: base half-Gaussian sampler (centered on 0, sigma0 = 1.8205).   */
/*                                                                           */
/* Faithful port of Pornin's reference gaussian0_sampler. The RCDT (reverse  */
/* cumulative distribution table) "dist[]" below is copied VERBATIM from the */
/* Falcon reference implementation (18 rows; each row is a 72-bit threshold  */
/* stored as three 24-bit limbs, most significant limb first). It is the     */
/* same table that appears in PQClean's                                      */
/*   crypto_sign/falcon-512/clean/sign.c                                     */
/* and in the original Falcon round-3 reference. Do not edit these numbers.  */
/* ------------------------------------------------------------------------ */
int falcon_gaussian0(falcon_prng* p)
{
    /* RCDT for the half-Gaussian of standard deviation sigma0 = 1.8205,
     * verbatim from the Falcon reference (Thomas Pornin). Each row holds a
     * 72-bit value as (hi24, mid24, lo24). */
    static const word32 dist[] = {
        10745844u,  3068844u,  3741698u,
         5559083u,  1580863u,  8248194u,
         2260429u, 13669192u,  2736639u,
          708981u,  4421575u, 10046180u,
          169348u,  7122675u,  4136815u,
           30538u, 13063405u,  7650655u,
            4132u, 14505003u,  7826148u,
             417u, 16768101u, 11363290u,
              31u,  8444042u,  8086568u,
               1u, 12844466u,   265321u,
               0u,  1232676u, 13644283u,
               0u,    38047u,  9111839u,
               0u,      870u,  6138264u,
               0u,       14u, 12545723u,
               0u,        0u,  3104126u,
               0u,        0u,    28824u,
               0u,        0u,      198u,
               0u,        0u,        1u
    };

    word32 v0, v1, v2, hi;
    word64 lo;
    word32 u;
    int z;

    /* Get a random 72-bit value, into three 24-bit limbs v0..v2. */
    lo = falcon_prng_get_u64(p);
    hi = (word32)falcon_prng_get_u8(p);
    v0 = (word32)lo & 0xFFFFFFu;
    v1 = (word32)(lo >> 24) & 0xFFFFFFu;
    v2 = (word32)(lo >> 48) | (hi << 16);

    /* Sampled value is z, the number of leading table thresholds that the
     * uniform 72-bit value (v0..v2) is strictly less than. Done with borrow
     * bits, fully branch-free. */
    z = 0;
    for (u = 0; u < (word32)((sizeof dist) / sizeof(dist[0])); u += 3) {
        word32 w0, w1, w2, cc;

        w0 = dist[u + 2];
        w1 = dist[u + 1];
        w2 = dist[u + 0];
        cc = (v0 - w0) >> 31;
        cc = (v1 - w1 - cc) >> 31;
        cc = (v2 - w2 - cc) >> 31;
        z += (int)cc;
    }
    return z;
}

/* ------------------------------------------------------------------------ */
/* BerExp: Bernoulli test, returns 1 with probability ccs * exp(-x).         */
/*                                                                           */
/* Faithful port of Pornin's reference BerExp. x >= 0 is guaranteed by the   */
/* caller. The only data-dependent loop is the lazy 8-bit comparison, whose  */
/* iteration count depends on fresh random bytes, not on secrets.            */
/* ------------------------------------------------------------------------ */
static int falcon_berexp(falcon_prng* p, fpr x, fpr ccs)
{
    int s, i;
    fpr r;
    word32 sw, w;
    word64 z;

    /* Reduce x modulo log(2): x = s*log(2) + r, with s an integer and
     * 0 <= r < log(2). Since x >= 0 we can use fpr_trunc (toward zero). */
    s = (int)fpr_trunc(fpr_mul(x, falcon_fpr_inv_log2));
    r = fpr_sub(x, fpr_mul(fpr_of((sword64)s), falcon_fpr_log2));

    /* It may happen (rarely) that s >= 64; if so, BerExp would be non-zero
     * with probability below 2^-64, so we simply saturate s at 63. */
    sw = (word32)s;
    sw ^= (sw ^ 63u) & (word32)(0U - ((63u - sw) >> 31));
    s = (int)sw;

    /* exp(-r), scaled to 2^63, scaled up to 2^64, then >> s to obtain
     * exp(-x) = 2^-s * exp(-r). The "-1" keeps the value on 64 bits. */
    z = ((fpr_expm_p63(r, ccs) << 1) - 1) >> s;

    /* Compare exp(-x) against fresh random bytes, 8 bits at a time; the sign
     * of the difference yields the sampled bit. */
    i = 64;
    do {
        i -= 8;
        w = (word32)falcon_prng_get_u8(p) - ((word32)(z >> i) & 0xFFu);
    } while ((w == 0) && (i > 0));

    return (int)(w >> 31);
}

/* ------------------------------------------------------------------------ */
/* sampler (SamplerZ): discrete Gaussian of center mu, std dev 1/isigma.     */
/*                                                                           */
/* Faithful port of Pornin's reference sampler. ctx is an falcon_sampler_ctx. */
/* ------------------------------------------------------------------------ */
int falcon_sampler_z(void* ctx, fpr mu, fpr isigma)
{
    falcon_sampler_ctx* spc = (falcon_sampler_ctx*)ctx;
    int s;
    fpr r, dss, ccs;

    /* Center is mu = s + r, with s an integer and 0 <= r < 1. */
    s = (int)fpr_floor(mu);
    r = fpr_sub(mu, fpr_of((sword64)s));

    /* dss = 1/(2*sigma^2) = 0.5 * isigma^2. */
    dss = fpr_half(fpr_sqr(isigma));

    /* ccs = sigma_min / sigma = sigma_min * isigma. */
    ccs = fpr_mul(isigma, spc->sigma_min);

    /* Sample on center r. */
    for (;;) {
        int z0, z, b;
        fpr x;

        /* Half-Gaussian sample, plus a random bit b turning it bimodal:
         * b = 1 -> use z0+1 (centered on 1), b = 0 -> use -z0 (centered 0). */
        z0 = falcon_gaussian0(&spc->p);
        b = (int)falcon_prng_get_u8(&spc->p) & 1;
        z = b + ((b << 1) - 1) * z0;

        /* Rejection sampling. Keep z with probability exp(-x), where
         *   x = ((z-r)^2)/(2*sigma^2) - (z0^2)/(2*sigma0^2).
         * The sigma_min scaling in ccs decorrelates the rejection rate from
         * mu/sigma, keeping the whole sampler constant-time. */
        x = fpr_mul(fpr_sqr(fpr_sub(fpr_of((sword64)z), r)), dss);
        x = fpr_sub(x, fpr_mul(fpr_of((sword64)(z0 * z0)),
            falcon_fpr_inv_2sqrsigma0));
        if (falcon_berexp(&spc->p, x, ccs)) {
            /* Rejection was centered on r; the actual center is mu = s + r. */
            return s + z;
        }
    }
}

/* ------------------------------------------------------------------------ */
/* Context initialisation.                                                   */
/* ------------------------------------------------------------------------ */
int falcon_sampler_init(falcon_sampler_ctx* spc, int logn, WC_RNG* rng)
{
    int ret;

    if (spc == NULL || rng == NULL)
        return BAD_FUNC_ARG;
    if (logn < 1 || logn > 10)
        return BAD_FUNC_ARG;

    spc->sigma_min = falcon_fpr_sigma_min[logn];
    ret = falcon_prng_init(&spc->p, rng);
    return ret;
}

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY */
