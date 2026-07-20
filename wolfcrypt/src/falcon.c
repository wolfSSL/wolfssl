/* falcon.c
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(HAVE_FALCON)

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/random.h>
/* fpr / FFT / poly seam declarations, folded in from the former internal
 * wc_falcon_{fpr,fft,poly}.h so the native Falcon implementation is a single
 * translation unit (the AVX2/NEON FFT backends at the end of this file
 * reference these directly, as the SHA-2 / ChaCha SIMD backends do). */
#ifndef WOLF_CRYPT_WC_FALCON_FPR_H
#define WOLF_CRYPT_WC_FALCON_FPR_H

#include <wolfssl/wolfcrypt/types.h>

#if defined(HAVE_FALCON)

#ifdef __cplusplus
    extern "C" {
#endif

/* Backend selection. The emulated backend is the default; the native/asm
 * backend is opt-in and currently still carries the fpr value as a bit
 * pattern in a word64 so the seam type is uniform across translation units. */
typedef word64 fpr;

/* -- Constructors / conversions / arithmetic / predicates --------------- */

/* Guard against selecting the native-double backend on a 32-bit ARM target that
 * has no double-precision FPU (Cortex-M0/M3/M4/M23/M33 are single-precision or
 * FPU-less). There, C double maps onto slow libgcc soft-double, so FPR_DOUBLE is
 * a pessimization -- the default emulated integer backend is faster. __ARM_FP
 * bit 3 (0x08) marks a hardware double FPU; AArch64 (which always has one) does
 * not define __arm__, so it is unaffected. */
#if defined(WOLFSSL_FALCON_FPR_DOUBLE) && defined(__arm__) && \
    (!defined(__ARM_FP) || (((__ARM_FP) & 0x08) == 0))
    #warning "WOLFSSL_FALCON_FPR_DOUBLE on a target without a double-precision FPU falls back to slow soft-double; the default integer fpr backend is faster on Cortex-M."
#endif

#if defined(WOLFSSL_FALCON_FPR_DOUBLE)
/* Inline native-double backend (opt-in). Maps the fpr seam onto the C double
 * type so the FFT/poly/sampler INLINE these scalar ops and keep values in FP
 * registers -- eliminating the per-op function call + GPR<->XMM shuffle that
 * dominate the out-of-line emulated/asm backends (~8x faster FP math, the bulk
 * of signing). Correctly-rounded IEEE-754 like the asm backend, with the same
 * constant-time-on-normals caveat: Falcon stays within normal range and the
 * caller must keep round-to-nearest-even (no FTZ/DAZ). fpr_expm_p63 and the fpr
 * constants still come from wc_falcon_fpr.c (which sees these inlines). */
#include <math.h>
static WC_INLINE double fpr__getd(fpr x) { double d; XMEMCPY(&d, &x, sizeof(d)); return d; }
static WC_INLINE fpr fpr__setd(double d) { fpr x; XMEMCPY(&x, &d, sizeof(x)); return x; }
static WC_INLINE fpr fpr_of(sword64 i)          { return fpr__setd((double)i); }
static WC_INLINE fpr fpr_scaled(sword64 i, int sc) { return fpr__setd(ldexp((double)i, sc)); }
static WC_INLINE sword64 fpr_rint(fpr x)        { double d = fpr__getd(x); return (sword64)llrint(d); }
static WC_INLINE sword64 fpr_floor(fpr x)       { double d = floor(fpr__getd(x)); return (sword64)d; }
static WC_INLINE sword64 fpr_trunc(fpr x)       { double d = trunc(fpr__getd(x)); return (sword64)d; }
static WC_INLINE fpr fpr_add(fpr x, fpr y)      { return fpr__setd(fpr__getd(x) + fpr__getd(y)); }
static WC_INLINE fpr fpr_sub(fpr x, fpr y)      { return fpr__setd(fpr__getd(x) - fpr__getd(y)); }
static WC_INLINE fpr fpr_neg(fpr x)             { return fpr__setd(-fpr__getd(x)); }
static WC_INLINE fpr fpr_half(fpr x)            { return fpr__setd(fpr__getd(x) * 0.5); }
static WC_INLINE fpr fpr_double(fpr x)          { return fpr__setd(fpr__getd(x) + fpr__getd(x)); }
static WC_INLINE fpr fpr_mul(fpr x, fpr y)      { return fpr__setd(fpr__getd(x) * fpr__getd(y)); }
static WC_INLINE fpr fpr_sqr(fpr x)             { double d = fpr__getd(x); return fpr__setd(d * d); }
static WC_INLINE fpr fpr_inv(fpr x)             { return fpr__setd(1.0 / fpr__getd(x)); }
static WC_INLINE fpr fpr_div(fpr x, fpr y)      { return fpr__setd(fpr__getd(x) / fpr__getd(y)); }
static WC_INLINE fpr fpr_sqrt(fpr x)            { return fpr__setd(sqrt(fpr__getd(x))); }
static WC_INLINE int fpr_lt(fpr x, fpr y)       { return fpr__getd(x) < fpr__getd(y); }
#else
/* Convert a signed integer to fpr (exact for |i| < 2^53). */
WOLFSSL_LOCAL fpr fpr_of(sword64 i);
/* Convert i*2^sc to fpr. */
WOLFSSL_LOCAL fpr fpr_scaled(sword64 i, int sc);
/* Round to nearest integer (ties to even); toward -inf; toward zero. */
WOLFSSL_LOCAL sword64 fpr_rint(fpr x);
WOLFSSL_LOCAL sword64 fpr_floor(fpr x);
WOLFSSL_LOCAL sword64 fpr_trunc(fpr x);
WOLFSSL_LOCAL fpr fpr_add(fpr x, fpr y);
WOLFSSL_LOCAL fpr fpr_sub(fpr x, fpr y);
WOLFSSL_LOCAL fpr fpr_neg(fpr x);
WOLFSSL_LOCAL fpr fpr_half(fpr x);
WOLFSSL_LOCAL fpr fpr_double(fpr x);
WOLFSSL_LOCAL fpr fpr_mul(fpr x, fpr y);
WOLFSSL_LOCAL fpr fpr_sqr(fpr x);
WOLFSSL_LOCAL fpr fpr_inv(fpr x);
WOLFSSL_LOCAL fpr fpr_div(fpr x, fpr y);
WOLFSSL_LOCAL fpr fpr_sqrt(fpr x);
/* Returns 1 if x < y, else 0. Must be constant-time w.r.t. operand values. */
WOLFSSL_LOCAL int fpr_lt(fpr x, fpr y);
#endif /* WOLFSSL_FALCON_FPR_DOUBLE */

/* -- Sampler support ---------------------------------------------------- */

/* Compute, in fixed point (scaled by 2^63), ccs * exp(-x), for the
 * Gaussian-sampler Bernoulli test (BerExp). x and ccs are non-negative and
 * x stays in a bounded range guaranteed by the caller. */
WOLFSSL_LOCAL word64 fpr_expm_p63(fpr x, fpr ccs);

/* -- Named constants (defined by the active backend) -------------------- */

extern const fpr fpr_zero;
extern const fpr fpr_one;
extern const fpr fpr_two;
extern const fpr fpr_onehalf;
extern const fpr fpr_invsqrt2;
extern const fpr fpr_invsqrt8;
extern const fpr fpr_ptwo31;       /*  2^31            */
extern const fpr fpr_ptwo31m1;     /*  2^31 - 1        */
extern const fpr fpr_mtwo31m1;     /* -(2^31 - 1)      */
extern const fpr fpr_ptwo63m1;     /*  2^63 - 1        */
extern const fpr fpr_mtwo63m1;     /* -(2^63 - 1)      */
extern const fpr fpr_ptwo63;       /*  2^63            */

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_FALCON */
#endif /* WOLF_CRYPT_WC_FALCON_FPR_H */
#ifndef WOLF_CRYPT_WC_FALCON_FFT_H
#define WOLF_CRYPT_WC_FALCON_FFT_H

#include <wolfssl/wolfcrypt/types.h>

#if defined(HAVE_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY)


#ifdef __cplusplus
    extern "C" {
#endif

/* Twiddle-factor table (correctly-rounded IEEE-754), shared with the poly_*
 * split/merge operations. falcon_gm_tab[2p+0]=cos, [2p+1]=sin. */
WOLFSSL_LOCAL extern const fpr falcon_gm_tab[2048];

/* In-place forward FFT: coefficient representation -> FFT representation. */
WOLFSSL_LOCAL void falcon_FFT(fpr* f, unsigned logn);
/* In-place inverse FFT: FFT representation -> coefficient representation. */
WOLFSSL_LOCAL void falcon_iFFT(fpr* f, unsigned logn);

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY */
#endif /* WOLF_CRYPT_WC_FALCON_FFT_H */
#ifndef WOLF_CRYPT_WC_FALCON_POLY_H
#define WOLF_CRYPT_WC_FALCON_POLY_H

#include <wolfssl/wolfcrypt/types.h>

#if defined(HAVE_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY)


#ifdef __cplusplus
    extern "C" {
#endif

/* a <- a + b (coefficient-wise; valid in both coefficient and FFT domain). */
WOLFSSL_LOCAL void falcon_poly_add(fpr* a, const fpr* b, unsigned logn);
/* a <- a - b. */
WOLFSSL_LOCAL void falcon_poly_sub(fpr* a, const fpr* b, unsigned logn);
/* a <- -a. */
WOLFSSL_LOCAL void falcon_poly_neg(fpr* a, unsigned logn);
/* a <- adj(a): Hermitian adjoint (complex conjugate) in FFT representation. */
WOLFSSL_LOCAL void falcon_poly_adj_fft(fpr* a, unsigned logn);
/* a <- a * b (pointwise complex product) in FFT representation. */
WOLFSSL_LOCAL void falcon_poly_mul_fft(fpr* a, const fpr* b, unsigned logn);
/* a <- a * adj(b) (pointwise a * conj(b)) in FFT representation. */
WOLFSSL_LOCAL void falcon_poly_muladj_fft(fpr* a, const fpr* b, unsigned logn);
/* a <- a * adj(a) (real-valued result) in FFT representation. */
WOLFSSL_LOCAL void falcon_poly_mulselfadj_fft(fpr* a, unsigned logn);
/* a <- a * x (scalar multiply by fpr constant). */
WOLFSSL_LOCAL void falcon_poly_mulconst(fpr* a, fpr x, unsigned logn);
/* a <- a / b (pointwise complex divide) in FFT representation. */
WOLFSSL_LOCAL void falcon_poly_div_fft(fpr* a, const fpr* b, unsigned logn);
/* d <- 1 / (|a|^2 + |b|^2) (real-valued) in FFT representation. */
WOLFSSL_LOCAL void falcon_poly_invnorm2_fft(fpr* d, const fpr* a, const fpr* b,
    unsigned logn);
/* d <- F*adj(f) + G*adj(g) in FFT representation. */
WOLFSSL_LOCAL void falcon_poly_add_muladj_fft(fpr* d, const fpr* F,
    const fpr* G, const fpr* f, const fpr* g, unsigned logn);
/* a <- a * b where b is a self-adjoint (real) polynomial in FFT
 * representation; b is stored with only its real (lower) half meaningful. */
WOLFSSL_LOCAL void falcon_poly_mul_autoadj_fft(fpr* a, const fpr* b,
    unsigned logn);
/* a <- a / b where b is a self-adjoint (real) polynomial in FFT
 * representation; b is stored with only its real (lower) half meaningful. */
WOLFSSL_LOCAL void falcon_poly_div_autoadj_fft(fpr* a, const fpr* b,
    unsigned logn);
/* In-place LDL decomposition of the 2x2 Hermitian Gram matrix
 * [[g00, adj(g01)], [g01, g11]]: on output g11 holds D[1][1] and g01 holds
 * L[1][0]; g00 (= D[0][0]) is left unchanged. */
WOLFSSL_LOCAL void falcon_poly_LDL_fft(const fpr* g00, fpr* g01, fpr* g11,
    unsigned logn);
/* Same factorization as falcon_poly_LDL_fft but writing the results to
 * separate output buffers (d11, l10), leaving the inputs untouched. */
WOLFSSL_LOCAL void falcon_poly_LDLmv_fft(fpr* d11, fpr* l10, const fpr* g00,
    const fpr* g01, const fpr* g11, unsigned logn);
/* Split f (degree n) into the two half-degree polynomials f0, f1 (degree n/2)
 * in FFT representation. */
WOLFSSL_LOCAL void falcon_poly_split_fft(fpr* f0, fpr* f1, const fpr* f,
    unsigned logn);
/* Inverse of falcon_poly_split_fft: merge f0, f1 (degree n/2) into f (degree n)
 * in FFT representation. */
WOLFSSL_LOCAL void falcon_poly_merge_fft(fpr* f, const fpr* f0, const fpr* f1,
    unsigned logn);

#if defined(WOLFSSL_FALCON_FFT_AVX2)
/* AVX2 (__m256d + FMA) variants of the hot pointwise ops, defined in the
 * folded AVX2 backend at the end of this file. The generic functions above
 * delegate to these when the AVX2 backend is selected. Semantically identical
 * to their scalar twins (FMA rounding differences are acceptable on the
 * signing FFT path). */
WOLFSSL_LOCAL void falcon_poly_mul_fft_avx2(fpr* a, const fpr* b, unsigned logn);
WOLFSSL_LOCAL void falcon_poly_add_avx2(fpr* a, const fpr* b, unsigned logn);
WOLFSSL_LOCAL void falcon_poly_sub_avx2(fpr* a, const fpr* b, unsigned logn);
WOLFSSL_LOCAL void falcon_poly_mulconst_avx2(fpr* a, fpr x, unsigned logn);
WOLFSSL_LOCAL void falcon_poly_muladj_fft_avx2(fpr* a, const fpr* b,
    unsigned logn);
WOLFSSL_LOCAL void falcon_poly_mulselfadj_fft_avx2(fpr* a, unsigned logn);
WOLFSSL_LOCAL void falcon_poly_invnorm2_fft_avx2(fpr* d, const fpr* a,
    const fpr* b, unsigned logn);
WOLFSSL_LOCAL void falcon_poly_add_muladj_fft_avx2(fpr* d, const fpr* F,
    const fpr* G, const fpr* f, const fpr* g, unsigned logn);
WOLFSSL_LOCAL void falcon_poly_LDLmv_fft_avx2(fpr* d11, fpr* l10,
    const fpr* g00, const fpr* g01, const fpr* g11, unsigned logn);
WOLFSSL_LOCAL void falcon_poly_split_fft_avx2(fpr* f0, fpr* f1, const fpr* f,
    unsigned logn);
WOLFSSL_LOCAL void falcon_poly_merge_fft_avx2(fpr* f, const fpr* f0,
    const fpr* f1, unsigned logn);
#endif /* WOLFSSL_FALCON_FFT_AVX2 */

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY */
#endif /* WOLF_CRYPT_WC_FALCON_POLY_H */
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* ==== Native Falcon core (merged from the former wc_falcon_*.c). The AVX2 and
   NEON FFT backends are folded in at the end of this file (gated by
   WOLFSSL_FALCON_FFT_AVX2 / _NEON); only the generated fpr x86-64 asm
   (wc_falcon_fpr_x86_64_asm.S) stays a separate file. ==== */
#if defined(HAVE_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY) && !defined(WOLF_CRYPTO_CB_ONLY_FALCON)
#ifndef WOLF_CRYPT_WC_FALCON_BIGINT_H
#define WOLF_CRYPT_WC_FALCON_BIGINT_H

#include <wolfssl/wolfcrypt/types.h>

#if defined(HAVE_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY)

#ifdef __cplusplus
    extern "C" {
#endif

/* One entry of the RNS small-prime table. Fields mirror the Falcon
 * reference small_prime structure:
 *   p   A prime modulus, with 2^30 < p < 2^31 and p = 1 mod 2048.
 *   g   A primitive root of phi = X^N+1 in the field Z_p.
 *   s   The inverse of the product of all previous primes in the table,
 *       computed modulo p and in Montgomery representation.
 * The table is sorted in decreasing order of p and terminated with a
 * { 0, 0, 0 } sentinel. */
typedef struct falcon_small_prime {
    word32 p;
    word32 g;
    word32 s;
} falcon_small_prime;

/* RNS prime table (terminated with a { 0, 0, 0 } sentinel). */
static const falcon_small_prime FALCON_PRIMES[];

/* ---- modular small-integer helpers (single 31-bit prime modulus) ---- */
static word32 modp_set(sword32 x, word32 p);
static sword32 modp_norm(word32 x, word32 p);
static word32 modp_ninv31(word32 p);
static word32 modp_R(word32 p);
static word32 modp_add(word32 a, word32 b, word32 p);
static word32 modp_sub(word32 a, word32 b, word32 p);
static word32 modp_montymul(word32 a, word32 b, word32 p, word32 p0i);
static word32 modp_R2(word32 p, word32 p0i);
static word32 modp_Rx(unsigned int x, word32 p, word32 p0i, word32 R2);
/* Modular division a/b mod p (returns 0 when b == 0). This is the
 * reference's modular-inverse helper (the canonical Falcon keygen.c has no
 * separately named "modp_get_inv"; modp_div(R,b,...) yields 1/b). */
static word32 modp_div(word32 a, word32 b, word32 p, word32 p0i,
        word32 R);

/* ---- small-modulus NTT used in the RNS ---- */
static void modp_mkgm2(word32* gm, word32* igm, unsigned int logn,
        word32 g, word32 p, word32 p0i);
static void modp_NTT2_ext(word32* a, size_t stride, const word32* gm,
        unsigned int logn, word32 p, word32 p0i);
static void modp_iNTT2_ext(word32* a, size_t stride, const word32* igm,
        unsigned int logn, word32 p, word32 p0i);

/* Convenience wrappers for unit-stride polynomials. */
#define modp_NTT2(a, gm, logn, p, p0i) \
    modp_NTT2_ext(a, 1, gm, logn, p, p0i)
#define modp_iNTT2(a, igm, logn, p, p0i) \
    modp_iNTT2_ext(a, 1, igm, logn, p, p0i)

/* ---- big-integer (zint) helpers ---- */
static word32 zint_sub(word32* a, const word32* b, size_t len,
        word32 ctl);
static word32 zint_mul_small(word32* m, size_t mlen, word32 x);
static word32 zint_mod_small_unsigned(const word32* d, size_t dlen,
        word32 p, word32 p0i, word32 R2);
static word32 zint_mod_small_signed(const word32* d, size_t dlen,
        word32 p, word32 p0i, word32 R2, word32 Rx);
static void zint_add_mul_small(word32* x, const word32* y, size_t len,
        word32 s);
static void zint_norm_zero(word32* x, const word32* p, size_t len);
static void zint_rebuild_CRT(word32* xx, size_t xlen, size_t xstride,
        size_t num, const falcon_small_prime* primes, int normalize_signed,
        word32* tmp);
static void zint_negate(word32* a, size_t len, word32 ctl);
static word32 zint_co_reduce(word32* a, word32* b, size_t len,
        sword64 xa, sword64 xb, sword64 ya, sword64 yb);
static void zint_finish_mod(word32* a, size_t len, const word32* m,
        word32 neg);
static void zint_co_reduce_mod(word32* a, word32* b, const word32* m,
        size_t len, word32 m0i, sword64 xa, sword64 xb, sword64 ya,
        sword64 yb);
static int zint_bezout(word32* u, word32* v, const word32* x,
        const word32* y, size_t len, word32* tmp);
static void zint_add_scaled_mul_small(word32* x, size_t xlen,
        const word32* y, size_t ylen, sword32 k, word32 sch, word32 scl);
static void zint_sub_scaled(word32* x, size_t xlen, const word32* y,
        size_t ylen, word32 sch, word32 scl);
static sword32 zint_one_to_plain(const word32* x);

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY */
#endif /* WOLF_CRYPT_WC_FALCON_BIGINT_H */
#ifndef WOLF_CRYPT_WC_FALCON_CODEC_H
#define WOLF_CRYPT_WC_FALCON_CODEC_H

#include <wolfssl/wolfcrypt/types.h>

#if defined(HAVE_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY)

#ifdef __cplusplus
    extern "C" {
#endif

/* Golomb-Rice (k=7) compress of the signature polynomial s2. Exact inverse of
 * the reference comp_decode. Rejects any |x[i]| > 2047. Returns the number of
 * bytes written, or 0 on range violation / output overflow. */
static size_t falcon_comp_encode(byte* out, size_t max_out,
        const sword16* x, unsigned logn);

/* 14-bit big-endian pack of the public-key polynomial h. Each coefficient must
 * be < q (12289). Returns the number of bytes written, or 0 on range violation
 * / output overflow. */
static size_t falcon_modq_encode(byte* out, size_t max_out,
        const word16* x, unsigned logn);

/* Signed 8-bit polynomial pack/unpack using a fixed per-coefficient bit width.
 * The most-negative value -2^(bits-1) is forbidden (matching the reference). */
static size_t falcon_trim_i8_encode(byte* out, size_t max_out,
        const sword8* x, unsigned logn, unsigned bits);
static size_t falcon_trim_i8_decode(sword8* x, unsigned logn,
        unsigned bits, const byte* in, size_t max_in);

/* Decode a Falcon secret key: header byte (0x50 | logn), then trim_i8 encoded
 * f, g (max_fg_bits[logn]) and F (max_FG_bits[logn]). Validates the header and
 * that the input length is exactly consumed. Returns 0 on success or a negative
 * wolfCrypt error. */
static int falcon_privkey_decode(const byte* sk, size_t sklen,
        sword8* f, sword8* g, sword8* F, unsigned logn);

/* Encode a Falcon secret key from (f, g, F). Inverse of falcon_privkey_decode.
 * Returns bytes written, or 0 on failure. */
static size_t falcon_privkey_encode(byte* sk, size_t max_sk,
        const sword8* f, const sword8* g, const sword8* F, unsigned logn);

#ifdef __cplusplus
    }
#endif

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY */

#endif /* WOLF_CRYPT_WC_FALCON_CODEC_H */
#ifndef WOLF_CRYPT_WC_FALCON_SAMPLER_H
#define WOLF_CRYPT_WC_FALCON_SAMPLER_H

#include <wolfssl/wolfcrypt/types.h>

#if defined(HAVE_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY)

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
    int      err;                   /* sticky: first refill error, or 0 */
} falcon_prng;

/* Sampler context: the PRNG plus the parameter-set-dependent sigma_min. */
typedef struct falcon_sampler_ctx {
    falcon_prng p;
    fpr        sigma_min;           /* sigma_min for the active logn  */
} falcon_sampler_ctx;

/* Seed length (bytes) drawn from WC_RNG to key the SHAKE256 stream. */
#define FALCON_PRNG_SEED_LEN 56

/* PRNG primitives. */
static int    falcon_prng_init(falcon_prng* p, WC_RNG* rng);
static byte   falcon_prng_get_u8(falcon_prng* p);
static word64 falcon_prng_get_u64(falcon_prng* p);

/* Initialise a sampler context for the given degree (logn = 9 or 10), seeding
 * the PRNG from rng. Returns 0 on success or a negative wolfCrypt error. */
static int falcon_sampler_init(falcon_sampler_ctx* spc, int logn,
    WC_RNG* rng);

/* The base half-Gaussian sampler (z >= 0, sigma0 = 1.8205). Exposed for test
 * harnesses; consumes 9 PRNG bytes. */
static int falcon_gaussian0(falcon_prng* p);

/* SamplerZ: return an integer sampled from the discrete Gaussian of center mu
 * and standard deviation 1/isigma. ctx is a (falcon_sampler_ctx*). */
static int falcon_sampler_z(void* ctx, fpr mu, fpr isigma);

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY */
#endif /* WOLF_CRYPT_WC_FALCON_SAMPLER_H */
#ifndef WOLF_CRYPT_WC_FALCON_KEYGEN_H
#define WOLF_CRYPT_WC_FALCON_KEYGEN_H

#include <wolfssl/wolfcrypt/types.h>

#if defined(HAVE_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY)

#include <wolfssl/wolfcrypt/random.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Generate a complete Falcon key pair of degree n = 2^logn.
 *
 *   rng   initialized WC_RNG used to seed the SHAKE256 sampler stream.
 *   f,g   output secret polynomials (n signed coefficients each).
 *   F,G   output NTRU completion polynomials (n signed coefficients each);
 *         G may be reconstructed internally but is always written out here.
 *   h     output public key polynomial (n coefficients in [0, q)); may be
 *         NULL if only the (f,g,F,G) basis is required.
 *   logn  base-2 logarithm of the ring degree (1..10; 9 and 10 are the
 *         Falcon-512 and Falcon-1024 levels).
 *
 * The routine loops, drawing fresh (f,g) until every acceptance test passes
 * and the NTRU equation is solved, exactly as the reference does. Returns 0
 * on success or a negative wolfCrypt error code. */
static int falcon_keygen(WC_RNG* rng, sword8* f, sword8* g,
        sword8* F, sword8* G, word16* h, unsigned logn);

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY */
#endif /* WOLF_CRYPT_WC_FALCON_KEYGEN_H */
#ifndef WOLF_CRYPT_WC_FALCON_SIGN_H
#define WOLF_CRYPT_WC_FALCON_SIGN_H

#include <wolfssl/wolfcrypt/types.h>

#if defined(HAVE_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY)


#ifdef __cplusplus
    extern "C" {
#endif

/* Number of fpr elements in an expanded private key for degree n = 2^logn.
 * Layout: the four B0 matrix polynomials (b00, b01, b10, b11), each of n
 * elements, followed by the ffLDL tree of (logn+1)*2^logn elements. The total
 * is therefore (logn+5)*2^logn fpr (matching the reference's (8*logn+40)*2^logn
 * bytes). */
#define FALCON_EXPANDED_KEY_FPR(logn)    (((size_t)((logn) + 5)) << (logn))

/* Number of fpr elements of scratch required by falcon_do_sign_tree /
 * falcon_sign_core (six polynomials of degree n), matching the reference's
 * 48*2^logn bytes. */
#define FALCON_SIGN_TMP_FPR(logn)        ((size_t)6 << (logn))

/* The discrete-Gaussian sampler callback type used by ffSampling. The second
 * argument is the center mu, the third the inverse standard deviation isigma.
 * falcon_sampler_z (wc_falcon_sampler.h) implements this contract. */
typedef int (*falcon_samplerZ)(void* ctx, fpr mu, fpr isigma);

/* Recompute the NTRU completion polynomial G from (f, g, F) such that
 * f*G - g*F = q (G = (g*F + q)/f), computed over the FFT seam and rounded to
 * integers. G receives n signed coefficients. For a well-formed key the
 * quotient is exact; a rounded coefficient outside the [-127, 127] range is
 * rejected (this also catches a grossly inconsistent/corrupt key). Returns 0 on
 * success, or a negative wolfCrypt error on out-of-range coefficient or memory
 * allocation failure. */
static int falcon_complete_private(sword8* G, const sword8* f,
        const sword8* g, const sword8* F, unsigned logn, void* heap);

#ifndef WOLFSSL_FALCON_SIGN_SMALL_MEM
/* Expand the private basis (f, g, F, G) into 'expanded' (which must hold
 * FALCON_EXPANDED_KEY_FPR(logn) fpr elements): the B0 matrix in FFT
 * representation and the normalized ffLDL tree. Allocates an internal scratch
 * of FALCON_SIGN_TMP_FPR(logn) fpr. Returns 0 on success or a negative
 * wolfCrypt error. */
static int falcon_expand_privkey(fpr* expanded, const sword8* f,
        const sword8* g, const sword8* F, const sword8* G, unsigned logn,
        void* heap);

/* Fast Fourier sampling: sample the target (t0, t1) against the ffLDL 'tree',
 * writing the sampled lattice coordinates into (z0, z1). 'tmp' needs room for
 * at least two polynomials of degree 2^logn. Iterative (explicit-stack)
 * equivalent of the reference ffSampling_fft recursion; sampler invocation
 * order is identical to the reference. */
static void falcon_ffSampling_fft(falcon_samplerZ samp, void* samp_ctx,
        fpr* z0, fpr* z1, const fpr* tree, const fpr* t0, const fpr* t1,
        unsigned logn, fpr* tmp);

/* Produce the signature short vector s2 (n sword16 values) from the expanded
 * key and hashed point hm (n word16 values in [0, q)). Loops over the sampler
 * until the (s1, s2) squared l2-norm is within the Falcon bound. 'tmp' must
 * hold FALCON_SIGN_TMP_FPR(logn) fpr. 'samplerErr', if non-NULL, points at the
 * sampler's sticky error flag; the loop bails out as soon as it becomes
 * non-zero (a wedged PRNG) instead of running to the restart bound. Returns 0
 * on success. */
static int falcon_do_sign_tree(falcon_samplerZ samp, void* samp_ctx,
        sword16* s2, const fpr* expanded, const word16* hm, unsigned logn,
        fpr* tmp, const int* samplerErr);

/* Convenience top-level: sign hashed point c with the expanded key, using the
 * provided (already initialized) sampler context, writing s2. 'tmp' must hold
 * FALCON_SIGN_TMP_FPR(logn) fpr. Returns 0 on success. */
static int falcon_sign_core(falcon_sampler_ctx* spc, const fpr* expanded,
        const word16* c, sword16* s2, fpr* tmp, unsigned logn);
#endif /* !WOLFSSL_FALCON_SIGN_SMALL_MEM (tree-signer forward decls) */

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY */
#endif /* WOLF_CRYPT_WC_FALCON_SIGN_H */



/* ------------------------------------------------------------------------ */
/* Low-level helpers.                                                        */
/*                                                                           */
/* These shift helpers tolerate a (possibly secret) shift count in 0..63 in  */
/* constant time: a variable shift is split into a fixed conditional 32-bit  */
/* part plus a 0..31 part, avoiding both undefined behaviour and any         */
/* operand-dependent timing on platforms whose shift is data dependent.      */
/* ------------------------------------------------------------------------ */

/* Right-shift a 64-bit unsigned value by n (0..63), constant-time. */
static WC_INLINE fpr fpr_ursh(word64 x, int n)
{
    x ^= (x ^ (x >> 32)) & ((word64)0 - (word64)(n >> 5));
    return x >> (n & 31);
}

/* Right-shift a 64-bit signed value by n (0..63), constant-time. */
static WC_INLINE sword64 fpr_irsh(sword64 x, int n)
{
    x ^= (x ^ (x >> 32)) & ((sword64)0 - (sword64)(n >> 5));
    return x >> (n & 31);
}

/* Left-shift a 64-bit unsigned value by n (0..63), constant-time. */
static WC_INLINE word64 fpr_ulsh(word64 x, int n)
{
    x ^= (x ^ (x << 32)) & ((word64)0 - (word64)(n >> 5));
    return x << (n & 31);
}

/* Pack a sign s (0/1), unbiased exponent e and mantissa m (2^54 <= m < 2^55,
 * with the low 3 bits carrying guard/round/sticky information) into the
 * IEEE-754 binary64 bit pattern, applying round-to-nearest-even.
 *
 * If m == 0 a (signed) zero is produced. If e < -1076 the value underflows to
 * a (signed) zero. */
static WC_INLINE fpr FPR(int s, int e, word64 m)
{
    fpr x;
    word32 t;
    unsigned int f;

    /* If e >= -1076 the value is "normal"; otherwise it would be subnormal,
     * which we clamp down to zero. */
    e += 1076;
    t = (word32)e >> 31;
    m &= (word64)t - 1;

    /* If m == 0 we want a zero: force e to 0 too (the sign is conserved). */
    t = (word32)(m >> 54);
    e &= -(int)t;

    /* The 52 stored mantissa bits come from m. Its top set bit (bit 54)
     * increments the exponent field by one when added, which is what we want
     * (and produces 0 for m == 0). */
    x = (((word64)s << 63) | (m >> 2)) + ((word64)(word32)e << 52);

    /* Round to nearest, ties to even: increment when the low 3 bits of m are
     * 011, 110 or 111. A carry spilling into the exponent field is the desired
     * behaviour. */
    f = (unsigned int)m & 7U;
    x += (0xC8U >> f) & 1U;
    return x;
}

/* Normalize mantissa m so its top bit (bit 63) is set, adjusting exponent e so
 * that m * 2^e is preserved. A zero m is left unchanged. Constant-time. */
#define FPR_NORM64(m, e)   do {                                  \
        word32 nt_;                                              \
                                                                \
        (e) -= 63;                                              \
                                                                \
        nt_ = (word32)((m) >> 32);                               \
        nt_ = (nt_ | (word32)(0U - nt_)) >> 31;                  \
        (m) ^= ((m) ^ ((m) << 32)) & ((word64)nt_ - 1);         \
        (e) += (int)(nt_ << 5);                                  \
                                                                \
        nt_ = (word32)((m) >> 48);                               \
        nt_ = (nt_ | (word32)(0U - nt_)) >> 31;                  \
        (m) ^= ((m) ^ ((m) << 16)) & ((word64)nt_ - 1);         \
        (e) += (int)(nt_ << 4);                                  \
                                                                \
        nt_ = (word32)((m) >> 56);                               \
        nt_ = (nt_ | (word32)(0U - nt_)) >> 31;                  \
        (m) ^= ((m) ^ ((m) <<  8)) & ((word64)nt_ - 1);         \
        (e) += (int)(nt_ << 3);                                  \
                                                                \
        nt_ = (word32)((m) >> 60);                               \
        nt_ = (nt_ | (word32)(0U - nt_)) >> 31;                  \
        (m) ^= ((m) ^ ((m) <<  4)) & ((word64)nt_ - 1);         \
        (e) += (int)(nt_ << 2);                                  \
                                                                \
        nt_ = (word32)((m) >> 62);                               \
        nt_ = (nt_ | (word32)(0U - nt_)) >> 31;                  \
        (m) ^= ((m) ^ ((m) <<  2)) & ((word64)nt_ - 1);         \
        (e) += (int)(nt_ << 1);                                  \
                                                                \
        nt_ = (word32)((m) >> 63);                               \
        (m) ^= ((m) ^ ((m) <<  1)) & ((word64)nt_ - 1);         \
        (e) += (int)(nt_);                                       \
    } while (0)

/* ------------------------------------------------------------------------ */
/* Constructors / conversions.                                               */
/* ------------------------------------------------------------------------ */

#ifndef WOLFSSL_FALCON_FPR_DOUBLE   /* inline backend provides fpr_scaled */
fpr fpr_scaled(sword64 i, int sc)
{
    /* Convert i * 2^sc to fpr: take the sign and absolute value, normalize the
     * magnitude so the top bit is set, round down to a 55-bit mantissa (with a
     * sticky low bit) and pack. The source integer is assumed not to be
     * -2^63. */
    int s, e;
    word32 t;
    word64 m;

    /* Sign and absolute value (-i == 1 + ~i). */
    s = (int)((word64)i >> 63);
    i ^= -(sword64)s;
    i += s;

    /* Suppose i != 0 for now: normalize it so the top bit is set. */
    m = (word64)i;
    e = 9 + sc;
    FPR_NORM64(m, e);

    /* m is now in 2^63..2^64-1; divide by 512 into the 2^54..2^55-1 range,
     * folding any dropped bit into the sticky low bit. */
    m |= ((word32)m & 0x1FF) + 0x1FF;
    m >>= 9;

    /* Corrective action for i == 0: clamp e and m to zero. */
    t = (word32)((word64)((word64)i | (word64)(0 - (word64)i)) >> 63);
    m &= (word64)0 - (word64)t;
    e &= -(int)t;

    /* FPR() handles exponents that are too low. */
    return FPR(s, e, m);
}
#endif /* !WOLFSSL_FALCON_FPR_DOUBLE */

#if !defined(WOLFSSL_FALCON_FPR_ASM) && !defined(WOLFSSL_FALCON_FPR_DOUBLE)
/* The scalar fpr operations below are supplied by the per-architecture assembly
 * backend (wc_falcon_fpr_x86_64_asm.S, WOLFSSL_FALCON_FPR_ASM) or by the inline
 * native-double backend (WOLFSSL_FALCON_FPR_DOUBLE) when either is set;
 * otherwise this constant-time integer emulation is used. fpr_expm_p63 and the
 * fpr constants (below) always come from this file. */
fpr fpr_of(sword64 i)
{
    return fpr_scaled(i, 0);
}

sword64 fpr_rint(fpr x)
{
    word64 m, d;
    int e;
    word32 s, dd, f;

    /* Assuming the value fits in -(2^63-1)..+(2^63-1), extract the mantissa as
     * a 63-bit integer and right-shift it as needed. */
    m = ((x << 10) | ((word64)1 << 62)) & (((word64)1 << 63) - 1);
    e = 1085 - ((int)(x >> 52) & 0x7FF);

    /* A shift of more than 63 bits sets m to zero (also covers x == 0). */
    m &= (word64)0 - (word64)((word32)(e - 64) >> 31);
    e &= 63;

    /* Right-shift m by e, rounding to nearest with ties to even. We build a
     * word holding all dropped bits plus the lowest kept bit, then shrink it
     * to three bits, the lowest being sticky. */
    d = fpr_ulsh(m, 63 - e);
    dd = (word32)d | ((word32)(d >> 32) & 0x1FFFFFFF);
    f = (word32)(d >> 61) | ((dd | (word32)(0U - dd)) >> 31);
    m = fpr_ursh(m, e) + (word64)((0xC8U >> f) & 1U);

    /* Apply the sign bit. */
    s = (word32)(x >> 63);
    return ((sword64)m ^ -(sword64)s) + (sword64)s;
}

sword64 fpr_floor(fpr x)
{
    word64 t;
    sword64 xi;
    int e, cc;

    /* Extract the value as a signed scaled integer in the 2^62..2^63-1 range
     * (absolute value), so only a right-shift is needed afterwards. */
    e = (int)(x >> 52) & 0x7FF;
    t = x >> 63;
    xi = (sword64)(((x << 10) | ((word64)1 << 62)) & (((word64)1 << 63) - 1));
    xi = (xi ^ -(sword64)t) + (sword64)t;
    cc = 1085 - e;

    /* An arithmetic right-shift implements floor() (round toward -inf) for
     * both positive and negative values. */
    xi = fpr_irsh(xi, cc & 63);

    /* If the true shift count was 64 or more, replace xi with 0 (nonnegative)
     * or -1 (negative). This also fixes the bogus implicit-bit assumption for
     * a zero input. */
    xi ^= (xi ^ -(sword64)t) & -(sword64)((word32)(63 - cc) >> 31);
    return xi;
}

sword64 fpr_trunc(fpr x)
{
    word64 t, xu;
    int e, cc;

    /* Extract the absolute value as a scaled integer in the 2^62..2^63-1
     * range, then right-shift. */
    e = (int)(x >> 52) & 0x7FF;
    xu = ((x << 10) | ((word64)1 << 62)) & (((word64)1 << 63) - 1);
    cc = 1085 - e;
    xu = fpr_ursh(xu, cc & 63);

    /* If the exponent is too low (cc > 63), clamp to zero (also covers
     * x == 0). */
    xu &= (word64)0 - (word64)((word32)(cc - 64) >> 31);

    /* Apply the sign. */
    t = x >> 63;
    xu = (xu ^ ((word64)0 - t)) + t;
    return (sword64)xu;
}

/* ------------------------------------------------------------------------ */
/* Arithmetic.                                                               */
/* ------------------------------------------------------------------------ */

fpr fpr_add(fpr x, fpr y)
{
    word64 m, xu, yu, za;
    word32 cs;
    int ex, ey, sx, sy, cc;

    /* Ensure x has the larger absolute value, so the exponent of y is no
     * greater than that of x. We also conditionally swap when abs(x) == abs(y)
     * and the sign of x is 1, which guarantees the result keeps the sign of x
     * (and is +0 in the exact-cancellation case). */
    m = ((word64)1 << 63) - 1;
    za = (x & m) - (y & m);
    cs = (word32)(za >> 63)
         | ((1U - (word32)(((word64)0 - za) >> 63)) & (word32)(x >> 63));
    m = (x ^ y) & ((word64)0 - (word64)cs);
    x ^= m;
    y ^= m;

    /* Extract sign bits, biased exponents and mantissas. The mantissas are
     * scaled up to the 2^55..2^56-1 range. A zero operand gets mantissa 0 and
     * exponent -1078. */
    ex = (int)(x >> 52);
    sx = ex >> 11;
    ex &= 0x7FF;
    m = (word64)(word32)((ex + 0x7FF) >> 11) << 52;
    xu = ((x & (((word64)1 << 52) - 1)) | m) << 3;
    ex -= 1078;
    ey = (int)(y >> 52);
    sy = ey >> 11;
    ey &= 0x7FF;
    m = (word64)(word32)((ey + 0x7FF) >> 11) << 52;
    yu = ((y & (((word64)1 << 52) - 1)) | m) << 3;
    ey -= 1078;

    /* x has the larger exponent; right-shift y to align. A shift of 60 bits or
     * more clamps y to zero. */
    cc = ex - ey;
    yu &= (word64)0 - (word64)((word32)(cc - 60) >> 31);
    cc &= 63;

    /* The lowest bit of yu becomes sticky over the shifted-out bits. */
    m = fpr_ulsh(1, cc) - 1;
    yu |= (yu & m) + m;
    yu = fpr_ursh(yu, cc);

    /* Same sign: add mantissas; differing signs: subtract. */
    xu += yu - ((yu << 1) & ((word64)0 - (word64)(sx ^ sy)));

    /* Renormalize the (possibly cancelled or carried) result. */
    FPR_NORM64(xu, ex);

    /* Scale down to the 2^54..2^55-1 range, keeping a sticky low bit. */
    xu |= ((word32)xu & 0x1FF) + 0x1FF;
    xu >>= 9;
    ex += 9;

    /* The result keeps the sign of x (the swap above made the -0 corner cases
     * impossible); FPR() clamps a too-low exponent to zero without altering
     * the sign. */
    return FPR(sx, ex, xu);
}

fpr fpr_sub(fpr x, fpr y)
{
    y ^= (word64)1 << 63;
    return fpr_add(x, y);
}

fpr fpr_neg(fpr x)
{
    x ^= (word64)1 << 63;
    return x;
}

fpr fpr_half(fpr x)
{
    /* Halving subtracts 1 from the exponent; handle zero specially. */
    word32 t;

    x -= (word64)1 << 52;
    t = (((word32)(x >> 52) & 0x7FF) + 1) >> 11;
    x &= (word64)t - 1;
    return x;
}

fpr fpr_double(fpr x)
{
    /* Doubling increments the exponent; handle zero specially. Infinities and
     * NaNs are not a concern for this backend. */
    x += (word64)((((unsigned int)(x >> 52) & 0x7FFU) + 0x7FFU) >> 11) << 52;
    return x;
}

fpr fpr_mul(fpr x, fpr y)
{
    word64 xu, yu, w, zu, zv;
    word32 x0, x1, y0, y1, z0, z1, z2;
    int ex, ey, d, e, s;

    /* Extract mantissas (with implicit bit) as 53-bit integers. */
    xu = (x & (((word64)1 << 52) - 1)) | ((word64)1 << 52);
    yu = (y & (((word64)1 << 52) - 1)) | ((word64)1 << 52);

    /* Multiply the two 53-bit integers using 25-bit low halves so the low
     * limbs (z0, z1) only ever matter for the sticky bit. */
    x0 = (word32)xu & 0x01FFFFFF;
    x1 = (word32)(xu >> 25);
    y0 = (word32)yu & 0x01FFFFFF;
    y1 = (word32)(yu >> 25);
    w = (word64)x0 * (word64)y0;
    z0 = (word32)w & 0x01FFFFFF;
    z1 = (word32)(w >> 25);
    w = (word64)x0 * (word64)y1;
    z1 += (word32)w & 0x01FFFFFF;
    z2 = (word32)(w >> 25);
    w = (word64)x1 * (word64)y0;
    z1 += (word32)w & 0x01FFFFFF;
    z2 += (word32)(w >> 25);
    zu = (word64)x1 * (word64)y1;
    z2 += (z1 >> 25);
    z1 &= 0x01FFFFFF;
    zu += z2;

    /* The product is in 2^104..2^106-1. Keep the top part (zu); fold the low
     * limbs into a sticky bit. */
    zu |= ((z0 | z1) + 0x01FFFFFF) >> 25;

    /* Normalize zu to 2^54..2^55-1; it may be one bit too large. The
     * conditional right-shift preserves the sticky bit. */
    zv = (zu >> 1) | (zu & 1);
    w = zu >> 55;
    zu ^= (zu ^ zv) & ((word64)0 - w);

    /* Aggregate scaling factor: sum the exponents, remove 2*(1023+52), then
     * add 50 + w (the right-shift amounts applied above). */
    ex = (int)((x >> 52) & 0x7FF);
    ey = (int)((y >> 52) & 0x7FF);
    e = ex + ey - 2100 + (int)w;

    /* Result sign is the XOR of the operand signs. */
    s = (int)((x ^ y) >> 63);

    /* Corrective action: if either operand is zero, clamp the mantissa. */
    d = ((ex + 0x7FF) & (ey + 0x7FF)) >> 11;
    zu &= (word64)0 - (word64)d;

    return FPR(s, e, zu);
}

fpr fpr_sqr(fpr x)
{
    return fpr_mul(x, x);
}

fpr fpr_div(fpr x, fpr y)
{
    word64 xu, yu, q, q2, w;
    int i, ex, ey, e, d, s;

    /* Extract mantissas (with implicit bit). */
    xu = (x & (((word64)1 << 52) - 1)) | ((word64)1 << 52);
    yu = (y & (((word64)1 << 52) - 1)) | ((word64)1 << 52);

    /* Bit-by-bit long division of xu by yu, for 55 bits. */
    q = 0;
    for (i = 0; i < 55; i++) {
        word64 b;

        b = ((xu - yu) >> 63) - 1;
        xu -= b & yu;
        q |= b & 1;
        xu <<= 1;
        q <<= 1;
    }

    /* Make the 56th (extra) bit sticky: set it iff the remainder is nonzero. */
    q |= (xu | ((word64)0 - xu)) >> 63;

    /* Normalize q to the 2^54..2^55-1 range (conditional shift, sticky-aware);
     * the top bit may be zero but then the next bit is one. */
    q2 = (q >> 1) | (q & 1);
    w = q >> 55;
    q ^= (q ^ q2) & ((word64)0 - w);

    /* Scaling: exponent biases cancel; remove 55 (division shift) and add w. */
    ex = (int)((x >> 52) & 0x7FF);
    ey = (int)((y >> 52) & 0x7FF);
    e = ex - ey - 55 + (int)w;

    /* Result sign is the XOR of the operand signs. */
    s = (int)((x ^ y) >> 63);

    /* Corrective action for x == 0 (division by zero is excluded by the
     * caller's contract). */
    d = (ex + 0x7FF) >> 11;
    s &= d;
    e &= -d;
    q &= (word64)0 - (word64)d;

    return FPR(s, e, q);
}

fpr fpr_inv(fpr x)
{
    /* 1.0 / x: fpr_one is the bit pattern of the double 1.0. */
    return fpr_div(fpr_one, x);
}

fpr fpr_sqrt(fpr x)
{
    word64 xu, q, s, r;
    int i, ex, e;

    /* Extract the mantissa and the true exponent (mantissa in 1..2). The sign
     * is ignored: the operand is assumed nonnegative. */
    xu = (x & (((word64)1 << 52) - 1)) | ((word64)1 << 52);
    ex = (int)((x >> 52) & 0x7FF);
    e = ex - 1023;

    /* If the exponent is odd, double the mantissa and decrement the exponent,
     * then halve the exponent for the square root. */
    xu += xu & ((word64)0 - (word64)(e & 1));
    e >>= 1;

    /* Double the mantissa: now in 2^53..2^55-1, representing a value in
     * [1, 4) with 53 fractional bits. */
    xu <<= 1;

    /* Compute the square root bit by bit. */
    q = 0;
    s = 0;
    r = (word64)1 << 53;
    for (i = 0; i < 54; i++) {
        word64 t, b;

        t = s + r;
        b = ((xu - t) >> 63) - 1;
        s += (r << 1) & b;
        xu -= t & b;
        q += r & b;
        xu <<= 1;
        r >>= 1;
    }

    /* q is a rounded-low 54-bit value (leading 1, 52 fractional digits and a
     * guard bit); add a sticky bit for the remaining operand. */
    q <<= 1;
    q |= (xu | ((word64)0 - xu)) >> 63;

    /* q is now an integer in 2^54..2^55-1; bias the exponent by 54. */
    e -= 54;

    /* Corrective action for an operand of value zero. */
    q &= (word64)0 - (word64)((ex + 0x7FF) >> 11);

    return FPR(0, e, q);
}

/* ------------------------------------------------------------------------ */
/* Predicates.                                                               */
/* ------------------------------------------------------------------------ */

int fpr_lt(fpr x, fpr y)
{
    /* For equal signs a signed comparison of the bit patterns yields the
     * correct order (and x - y does not overflow). For differing signs the
     * sign of x decides. For two negatives the order is reversed, so we
     * combine sgn(x-y) and sgn(y-x). */
    int cc0, cc1;
    sword64 sx;
    sword64 sy;

    sx = (sword64)x;
    sy = (sword64)y;
    sy &= ~((sx ^ sy) >> 63); /* sy = 0 if the signs differ */

    cc0 = (int)((sx - sy) >> 63) & 1; /* neither subtraction overflows when */
    cc1 = (int)((sy - sx) >> 63) & 1; /* the signs are the same             */

    return cc0 ^ ((cc0 ^ cc1) & (int)((x & y) >> 63));
}
#endif /* !WOLFSSL_FALCON_FPR_ASM */

/* ------------------------------------------------------------------------ */
/* Sampler support: ccs * exp(-x) in fixed point scaled by 2^63.            */
/* ------------------------------------------------------------------------ */

/* Top 64 bits of the 128-bit product z*y. This is the inner operation of the
 * Bernoulli-exp polynomial and the hottest scalar op in signing. On 64-bit
 * targets it is a single multiply instruction; the portable 32x32 fallback
 * (one MUL becomes four) is kept for platforms without a 128-bit integer type
 * (e.g. Cortex-M). Both paths are constant-time and bit-identical. */
#if defined(__SIZEOF_INT128__)
#define FALCON_MULHI(z, y) \
    ((word64)(((unsigned __int128)(word64)(z) * (unsigned __int128)(word64)(y)) >> 64))
#else
static WC_INLINE word64 falcon_mulhi(word64 z, word64 y)
{
    word32 z0 = (word32)z, z1 = (word32)(z >> 32);
    word32 y0 = (word32)y, y1 = (word32)(y >> 32);
    word64 a = ((word64)z0 * (word64)y1) + (((word64)z0 * (word64)y0) >> 32);
    word64 b = ((word64)z1 * (word64)y0);
    word64 c = (a >> 32) + (b >> 32);
    c += (((word64)(word32)a + (word64)(word32)b) >> 32);
    c += (word64)z1 * (word64)y1;
    return c;
}
#define FALCON_MULHI(z, y) falcon_mulhi((z), (y))
#endif

word64 fpr_expm_p63(fpr x, fpr ccs)
{
    /* Polynomial approximation of exp(-x), coefficients from FACCT
     * (https://eprint.iacr.org/2018/1234, https://github.com/raykzhao/gaussian)
     * scaled up by 2^63 and converted to integers. The maximum observed
     * deviation from the true value over the 0..log(2) range is below
     * 2^(-50). */
    static const word64 C[] = {
        0x00000004741183A3u,
        0x00000036548CFC06u,
        0x0000024FDCBF140Au,
        0x0000171D939DE045u,
        0x0000D00CF58F6F84u,
        0x000680681CF796E3u,
        0x002D82D8305B0FEAu,
        0x011111110E066FD0u,
        0x0555555555070F00u,
        0x155555555581FF00u,
        0x400000000002B400u,
        0x7FFFFFFFFFFF4800u,
        0x8000000000000000u
    };

    word64 z, y;

    /* Horner evaluation of the degree-12 polynomial; each step keeps the top
     * 64 bits of z*y. Fully unrolled (the loop bound is a compile-time 13). */
    y = C[0];
    z = (word64)fpr_trunc(fpr_mul(x, fpr_ptwo63)) << 1;
    y = C[1]  - FALCON_MULHI(z, y);
    y = C[2]  - FALCON_MULHI(z, y);
    y = C[3]  - FALCON_MULHI(z, y);
    y = C[4]  - FALCON_MULHI(z, y);
    y = C[5]  - FALCON_MULHI(z, y);
    y = C[6]  - FALCON_MULHI(z, y);
    y = C[7]  - FALCON_MULHI(z, y);
    y = C[8]  - FALCON_MULHI(z, y);
    y = C[9]  - FALCON_MULHI(z, y);
    y = C[10] - FALCON_MULHI(z, y);
    y = C[11] - FALCON_MULHI(z, y);
    y = C[12] - FALCON_MULHI(z, y);

    /* Apply the scaling factor ccs (converted to the same fixed-point format)
     * with a final 64x64->high-64 multiplication. */
    z = (word64)fpr_trunc(fpr_mul(ccs, fpr_ptwo63)) << 1;
    y = FALCON_MULHI(z, y);

    return y;
}

/* ------------------------------------------------------------------------ */
/* Named constants: IEEE-754 binary64 bit patterns.                          */
/* ------------------------------------------------------------------------ */

const fpr fpr_zero      = 0;
const fpr fpr_one       = 4607182418800017408U;   /*  1.0            */
const fpr fpr_two       = 4611686018427387904U;   /*  2.0            */
const fpr fpr_onehalf   = 4602678819172646912U;   /*  0.5            */
const fpr fpr_invsqrt2  = 4604544271217802189U;   /*  1/sqrt(2)      */
const fpr fpr_invsqrt8  = 4600040671590431693U;   /*  1/sqrt(8)      */
const fpr fpr_ptwo31    = 4746794007248502784U;   /*  2^31           */
const fpr fpr_ptwo31m1  = 4746794007244308480U;   /*  2^31 - 1       */
const fpr fpr_mtwo31m1  = 13970166044099084288U;  /* -(2^31 - 1)     */
const fpr fpr_ptwo63m1  = 4890909195324358656U;   /*  2^63 - 1       */
const fpr fpr_mtwo63m1  = 14114281232179134464U;  /* -(2^63 - 1)     */
const fpr fpr_ptwo63    = 4890909195324358656U;   /*  2^63           */




/* Complex helpers over the fpr seam. d may alias a/b inputs only via temps. */
#define FPC_ADD(d_re, d_im, a_re, a_im, b_re, b_im) do { \
        fpr _ar = (a_re), _ai = (a_im), _br = (b_re), _bi = (b_im); \
        (d_re) = fpr_add(_ar, _br); \
        (d_im) = fpr_add(_ai, _bi); \
    } while (0)
#define FPC_SUB(d_re, d_im, a_re, a_im, b_re, b_im) do { \
        fpr _ar = (a_re), _ai = (a_im), _br = (b_re), _bi = (b_im); \
        (d_re) = fpr_sub(_ar, _br); \
        (d_im) = fpr_sub(_ai, _bi); \
    } while (0)
/* (a_re + i a_im) * (b_re + i b_im) */
#define FPC_MUL(d_re, d_im, a_re, a_im, b_re, b_im) do { \
        fpr _ar = (a_re), _ai = (a_im), _br = (b_re), _bi = (b_im); \
        (d_re) = fpr_sub(fpr_mul(_ar, _br), fpr_mul(_ai, _bi)); \
        (d_im) = fpr_add(fpr_mul(_ar, _bi), fpr_mul(_ai, _br)); \
    } while (0)

/* falcon_gm_tab[2*p+0]=cos, [2*p+1]=sin; angle=pi*(2*brev_u(i)+1)/(2m).
 * Generated table of correctly-rounded IEEE-754 twiddle factors, n<=1024.
 * Shared with the poly_split/merge ops (fpr/FFT seam declared above). */
const fpr falcon_gm_tab[2048] = {
    0x0000000000000000ULL, 0x0000000000000000ULL,     0x0000000000000000ULL, 0x0000000000000000ULL,
    0x3FE6A09E667F3BCDULL, 0x3FE6A09E667F3BCCULL,     0xBFE6A09E667F3BCCULL, 0x3FE6A09E667F3BCDULL,
    0x3FED906BCF328D46ULL, 0x3FD87DE2A6AEA963ULL,     0xBFD87DE2A6AEA962ULL, 0x3FED906BCF328D46ULL,
    0x3FD87DE2A6AEA964ULL, 0x3FED906BCF328D46ULL,     0xBFED906BCF328D46ULL, 0x3FD87DE2A6AEA965ULL,
    0x3FEF6297CFF75CB0ULL, 0x3FC8F8B83C69A60AULL,     0xBFC8F8B83C69A608ULL, 0x3FEF6297CFF75CB0ULL,
    0x3FE1C73B39AE68C9ULL, 0x3FEA9B66290EA1A3ULL,     0xBFEA9B66290EA1A4ULL, 0x3FE1C73B39AE68C8ULL,
    0x3FEA9B66290EA1A3ULL, 0x3FE1C73B39AE68C8ULL,     0xBFE1C73B39AE68C6ULL, 0x3FEA9B66290EA1A5ULL,
    0x3FC8F8B83C69A60DULL, 0x3FEF6297CFF75CB0ULL,     0xBFEF6297CFF75CB0ULL, 0x3FC8F8B83C69A617ULL,
    0x3FEFD88DA3D12526ULL, 0x3FB917A6BC29B42CULL,     0xBFB917A6BC29B42FULL, 0x3FEFD88DA3D12526ULL,
    0x3FE44CF325091DD6ULL, 0x3FE8BC806B151741ULL,     0xBFE8BC806B151741ULL, 0x3FE44CF325091DD6ULL,
    0x3FEC38B2F180BDB1ULL, 0x3FDE2B5D3806F63BULL,     0xBFDE2B5D3806F63CULL, 0x3FEC38B2F180BDB1ULL,
    0x3FD294062ED59F05ULL, 0x3FEE9F4156C62DDBULL,     0xBFEE9F4156C62DDAULL, 0x3FD294062ED59F06ULL,
    0x3FEE9F4156C62DDAULL, 0x3FD294062ED59F05ULL,     0xBFD294062ED59F02ULL, 0x3FEE9F4156C62DDBULL,
    0x3FDE2B5D3806F63EULL, 0x3FEC38B2F180BDB0ULL,     0xBFEC38B2F180BDB0ULL, 0x3FDE2B5D3806F63FULL,
    0x3FE8BC806B151741ULL, 0x3FE44CF325091DD6ULL,     0xBFE44CF325091DD5ULL, 0x3FE8BC806B151742ULL,
    0x3FB917A6BC29B438ULL, 0x3FEFD88DA3D12525ULL,     0xBFEFD88DA3D12525ULL, 0x3FB917A6BC29B43CULL,
    0x3FEFF621E3796D7EULL, 0x3FA91F65F10DD814ULL,     0xBFA91F65F10DD813ULL, 0x3FEFF621E3796D7EULL,
    0x3FE57D69348CEC9FULL, 0x3FE7B5DF226AAFAFULL,     0xBFE7B5DF226AAFADULL, 0x3FE57D69348CECA1ULL,
    0x3FECED7AF43CC773ULL, 0x3FDB5D1009E15CC0ULL,     0xBFDB5D1009E15CBCULL, 0x3FECED7AF43CC774ULL,
    0x3FD58F9A75AB1FDDULL, 0x3FEE212104F686E5ULL,     0xBFEE212104F686E4ULL, 0x3FD58F9A75AB1FE2ULL,
    0x3FEF0A7EFB9230D7ULL, 0x3FCF19F97B215F1AULL,     0xBFCF19F97B215F1AULL, 0x3FEF0A7EFB9230D7ULL,
    0x3FE073879922FFEDULL, 0x3FEB728345196E3EULL,     0xBFEB728345196E3DULL, 0x3FE073879922FFEEULL,
    0x3FE9B3E047F38741ULL, 0x3FE30FF7FCE17035ULL,     0xBFE30FF7FCE17035ULL, 0x3FE9B3E047F38741ULL,
    0x3FC2C8106E8E613AULL, 0x3FEFA7557F08A517ULL,     0xBFEFA7557F08A517ULL, 0x3FC2C8106E8E613CULL,
    0x3FEFA7557F08A517ULL, 0x3FC2C8106E8E613AULL,     0xBFC2C8106E8E6136ULL, 0x3FEFA7557F08A517ULL,
    0x3FE30FF7FCE17036ULL, 0x3FE9B3E047F38740ULL,     0xBFE9B3E047F38740ULL, 0x3FE30FF7FCE17036ULL,
    0x3FEB728345196E3EULL, 0x3FE073879922FFEDULL,     0xBFE073879922FFEDULL, 0x3FEB728345196E3EULL,
    0x3FCF19F97B215F1EULL, 0x3FEF0A7EFB9230D7ULL,     0xBFEF0A7EFB9230D7ULL, 0x3FCF19F97B215F21ULL,
    0x3FEE212104F686E5ULL, 0x3FD58F9A75AB1FDDULL,     0xBFD58F9A75AB1FDBULL, 0x3FEE212104F686E5ULL,
    0x3FDB5D1009E15CC2ULL, 0x3FECED7AF43CC773ULL,     0xBFECED7AF43CC773ULL, 0x3FDB5D1009E15CBFULL,
    0x3FE7B5DF226AAFAFULL, 0x3FE57D69348CEC9FULL,     0xBFE57D69348CECA0ULL, 0x3FE7B5DF226AAFAEULL,
    0x3FA91F65F10DD824ULL, 0x3FEFF621E3796D7EULL,     0xBFEFF621E3796D7EULL, 0x3FA91F65F10DD80DULL,
    0x3FEFFD886084CD0DULL, 0x3F992155F7A3667EULL,     0xBF992155F7A36654ULL, 0x3FEFFD886084CD0DULL,
    0x3FE610B7551D2CDFULL, 0x3FE72D0837EFFF96ULL,     0xBFE72D0837EFFF95ULL, 0x3FE610B7551D2CE0ULL,
    0x3FED4134D14DC93AULL, 0x3FD9EF7943A8ED8AULL,     0xBFD9EF7943A8ED88ULL, 0x3FED4134D14DC93AULL,
    0x3FD7088530FA45A1ULL, 0x3FEDDB13B6CCC23CULL,     0xBFEDDB13B6CCC23CULL, 0x3FD7088530FA45A2ULL,
    0x3FEF38F3AC64E589ULL, 0x3FCC0B826A7E4F63ULL,     0xBFCC0B826A7E4F5EULL, 0x3FEF38F3AC64E589ULL,
    0x3FE11EB3541B4B23ULL, 0x3FEB090A581501FFULL,     0xBFEB090A58150200ULL, 0x3FE11EB3541B4B22ULL,
    0x3FEA29A7A0462782ULL, 0x3FE26D054CDD12DFULL,     0xBFE26D054CDD12DFULL, 0x3FEA29A7A0462782ULL,
    0x3FC5E214448B3FCBULL, 0x3FEF8764FA714BA9ULL,     0xBFEF8764FA714BA9ULL, 0x3FC5E214448B3FC6ULL,
    0x3FEFC26470E19FD3ULL, 0x3FBF564E56A9730EULL,     0xBFBF564E56A9730BULL, 0x3FEFC26470E19FD3ULL,
    0x3FE3AFFA292050B9ULL, 0x3FE93A22499263FBULL,     0xBFE93A22499263FBULL, 0x3FE3AFFA292050BAULL,
    0x3FEBD7C0AC6F952AULL, 0x3FDF8BA4DBF89ABAULL,     0xBFDF8BA4DBF89AB9ULL, 0x3FEBD7C0AC6F952AULL,
    0x3FD111D262B1F678ULL, 0x3FEED740E7684963ULL,     0xBFEED740E7684963ULL, 0x3FD111D262B1F679ULL,
    0x3FEE6288EC48E112ULL, 0x3FD4135C94176602ULL,     0xBFD4135C94176600ULL, 0x3FEE6288EC48E112ULL,
    0x3FDCC66E9931C45EULL, 0x3FEC954B213411F5ULL,     0xBFEC954B213411F4ULL, 0x3FDCC66E9931C463ULL,
    0x3FE83B0E0BFF976EULL, 0x3FE4E6CABBE3E5E9ULL,     0xBFE4E6CABBE3E5E7ULL, 0x3FE83B0E0BFF976FULL,
    0x3FB2D52092CE19F8ULL, 0x3FEFE9CDAD01883AULL,     0xBFEFE9CDAD01883AULL, 0x3FB2D52092CE1A0CULL,
    0x3FEFE9CDAD01883AULL, 0x3FB2D52092CE19F6ULL,     0xBFB2D52092CE19EFULL, 0x3FEFE9CDAD01883AULL,
    0x3FE4E6CABBE3E5E9ULL, 0x3FE83B0E0BFF976DULL,     0xBFE83B0E0BFF976EULL, 0x3FE4E6CABBE3E5E8ULL,
    0x3FEC954B213411F5ULL, 0x3FDCC66E9931C45DULL,     0xBFDCC66E9931C460ULL, 0x3FEC954B213411F4ULL,
    0x3FD4135C94176603ULL, 0x3FEE6288EC48E112ULL,     0xBFEE6288EC48E112ULL, 0x3FD4135C94176600ULL,
    0x3FEED740E7684963ULL, 0x3FD111D262B1F677ULL,     0xBFD111D262B1F676ULL, 0x3FEED740E7684963ULL,
    0x3FDF8BA4DBF89ABBULL, 0x3FEBD7C0AC6F9529ULL,     0xBFEBD7C0AC6F9529ULL, 0x3FDF8BA4DBF89ABCULL,
    0x3FE93A22499263FCULL, 0x3FE3AFFA292050B9ULL,     0xBFE3AFFA292050B8ULL, 0x3FE93A22499263FCULL,
    0x3FBF564E56A97314ULL, 0x3FEFC26470E19FD3ULL,     0xBFEFC26470E19FD3ULL, 0x3FBF564E56A97319ULL,
    0x3FEF8764FA714BA9ULL, 0x3FC5E214448B3FC6ULL,     0xBFC5E214448B3FC7ULL, 0x3FEF8764FA714BA9ULL,
    0x3FE26D054CDD12DFULL, 0x3FEA29A7A0462782ULL,     0xBFEA29A7A0462781ULL, 0x3FE26D054CDD12E0ULL,
    0x3FEB090A58150200ULL, 0x3FE11EB3541B4B22ULL,     0xBFE11EB3541B4B21ULL, 0x3FEB090A58150201ULL,
    0x3FCC0B826A7E4F62ULL, 0x3FEF38F3AC64E589ULL,     0xBFEF38F3AC64E588ULL, 0x3FCC0B826A7E4F6CULL,
    0x3FEDDB13B6CCC23DULL, 0x3FD7088530FA459EULL,     0xBFD7088530FA459FULL, 0x3FEDDB13B6CCC23CULL,
    0x3FD9EF7943A8ED8AULL, 0x3FED4134D14DC93AULL,     0xBFED4134D14DC93AULL, 0x3FD9EF7943A8ED8BULL,
    0x3FE72D0837EFFF97ULL, 0x3FE610B7551D2CDEULL,     0xBFE610B7551D2CDFULL, 0x3FE72D0837EFFF96ULL,
    0x3F992155F7A36677ULL, 0x3FEFFD886084CD0DULL,     0xBFEFFD886084CD0DULL, 0x3F992155F7A36689ULL,
    0x3FEFFF62169B92DBULL, 0x3F8921D1FCDEC784ULL,     0xBF8921D1FCDEC749ULL, 0x3FEFFF62169B92DBULL,
    0x3FE6591925F0783EULL, 0x3FE6E74454EAA8AEULL,     0xBFE6E74454EAA8AEULL, 0x3FE6591925F0783EULL,
    0x3FED696173C9E68BULL, 0x3FD9372A63BC93D7ULL,     0xBFD9372A63BC93D5ULL, 0x3FED696173C9E68BULL,
    0x3FD7C3A9311DCCE8ULL, 0x3FEDB6526238A09AULL,     0xBFEDB6526238A09AULL, 0x3FD7C3A9311DCCEAULL,
    0x3FEF4E603B0B2F2DULL, 0x3FCA82A025B00451ULL,     0xBFCA82A025B0044DULL, 0x3FEF4E603B0B2F2DULL,
    0x3FE1734D63DEDB49ULL, 0x3FEAD2BC9E21D510ULL,     0xBFEAD2BC9E21D511ULL, 0x3FE1734D63DEDB48ULL,
    0x3FEA63091B02FAE2ULL, 0x3FE21A799933EB58ULL,     0xBFE21A799933EB59ULL, 0x3FEA63091B02FAE1ULL,
    0x3FC76DD9DE50BF35ULL, 0x3FEF7599A3A12077ULL,     0xBFEF7599A3A12077ULL, 0x3FC76DD9DE50BF2FULL,
    0x3FEFCE15FD6DA67BULL, 0x3FBC3785C79EC2D5ULL,     0xBFBC3785C79EC2D5ULL, 0x3FEFCE15FD6DA67BULL,
    0x3FE3FED9534556D5ULL, 0x3FE8FBCCA3EF940CULL,     0xBFE8FBCCA3EF940DULL, 0x3FE3FED9534556D4ULL,
    0x3FEC08C426725549ULL, 0x3FDEDC1952EF78D5ULL,     0xBFDEDC1952EF78D5ULL, 0x3FEC08C426725549ULL,
    0x3FD1D3443F4CDB3DULL, 0x3FEEBBD8C8DF0B74ULL,     0xBFEEBBD8C8DF0B74ULL, 0x3FD1D3443F4CDB3FULL,
    0x3FEE817BAB4CD10DULL, 0x3FD35410C2E18152ULL,     0xBFD35410C2E18152ULL, 0x3FEE817BAB4CD10DULL,
    0x3FDD79775B86E389ULL, 0x3FEC678B3488739BULL,     0xBFEC678B3488739AULL, 0x3FDD79775B86E38DULL,
    0x3FE87C400FBA2EBFULL, 0x3FE49A449B9B0938ULL,     0xBFE49A449B9B0937ULL, 0x3FE87C400FBA2EC0ULL,
    0x3FB5F6D00A9AA418ULL, 0x3FEFE1CAFCBD5B09ULL,     0xBFEFE1CAFCBD5B09ULL, 0x3FB5F6D00A9AA42CULL,
    0x3FEFF095658E71ADULL, 0x3FAF656E79F820E0ULL,     0xBFAF656E79F820D9ULL, 0x3FEFF095658E71ADULL,
    0x3FE5328292A35596ULL, 0x3FE7F8ECE3571770ULL,     0xBFE7F8ECE357176FULL, 0x3FE5328292A35598ULL,
    0x3FECC1F0F3FCFC5CULL, 0x3FDC1249D8011EE7ULL,     0xBFDC1249D8011EE2ULL, 0x3FECC1F0F3FCFC5DULL,
    0x3FD4D1E24278E76BULL, 0x3FEE426A4B2BC17EULL,     0xBFEE426A4B2BC17DULL, 0x3FD4D1E24278E770ULL,
    0x3FEEF178A3E473C2ULL, 0x3FD04FB80E37FDAEULL,     0xBFD04FB80E37FDADULL, 0x3FEEF178A3E473C2ULL,
    0x3FE01CFC874C3EB7ULL, 0x3FEBA5AA673590D2ULL,     0xBFEBA5AA673590D2ULL, 0x3FE01CFC874C3EB8ULL,
    0x3FE9777EF4C7D742ULL, 0x3FE36058B10659F3ULL,     0xBFE36058B10659F2ULL, 0x3FE9777EF4C7D742ULL,
    0x3FC139F0CEDAF578ULL, 0x3FEFB5797195D741ULL,     0xBFEFB5797195D741ULL, 0x3FC139F0CEDAF57AULL,
    0x3FEF97F924C9099BULL, 0x3FC45576B1293E5AULL,     0xBFC45576B1293E54ULL, 0x3FEF97F924C9099BULL,
    0x3FE2BEDB25FAF3EAULL, 0x3FE9EF43EF29AF94ULL,     0xBFE9EF43EF29AF93ULL, 0x3FE2BEDB25FAF3EBULL,
    0x3FEB3E4D3EF55712ULL, 0x3FE0C9704D5D898FULL,     0xBFE0C9704D5D898DULL, 0x3FEB3E4D3EF55712ULL,
    0x3FCD934FE5454317ULL, 0x3FEF2252F7763AD9ULL,     0xBFEF2252F7763AD9ULL, 0x3FCD934FE5454319ULL,
    0x3FEDFEAE622DBE2BULL, 0x3FD64C7DDD3F27C6ULL,     0xBFD64C7DDD3F27C3ULL, 0x3FEDFEAE622DBE2BULL,
    0x3FDAA6C82B6D3FCCULL, 0x3FED17E7743E35DBULL,     0xBFED17E7743E35DCULL, 0x3FDAA6C82B6D3FC9ULL,
    0x3FE771E75F037261ULL, 0x3FE5C77BBE65018CULL,     0xBFE5C77BBE65018CULL, 0x3FE771E75F037261ULL,
    0x3FA2D865759455E4ULL, 0x3FEFFA72EFFEF75DULL,     0xBFEFFA72EFFEF75DULL, 0x3FA2D865759455CDULL,
    0x3FEFFA72EFFEF75DULL, 0x3FA2D865759455CDULL,     0xBFA2D865759455D2ULL, 0x3FEFFA72EFFEF75DULL,
    0x3FE5C77BBE65018DULL, 0x3FE771E75F037261ULL,     0xBFE771E75F037260ULL, 0x3FE5C77BBE65018EULL,
    0x3FED17E7743E35DCULL, 0x3FDAA6C82B6D3FC9ULL,     0xBFDAA6C82B6D3FC6ULL, 0x3FED17E7743E35DDULL,
    0x3FD64C7DDD3F27C5ULL, 0x3FEDFEAE622DBE2BULL,     0xBFEDFEAE622DBE2AULL, 0x3FD64C7DDD3F27CAULL,
    0x3FEF2252F7763ADAULL, 0x3FCD934FE5454311ULL,     0xBFCD934FE5454312ULL, 0x3FEF2252F7763ADAULL,
    0x3FE0C9704D5D898EULL, 0x3FEB3E4D3EF55712ULL,     0xBFEB3E4D3EF55712ULL, 0x3FE0C9704D5D898FULL,
    0x3FE9EF43EF29AF94ULL, 0x3FE2BEDB25FAF3EAULL,     0xBFE2BEDB25FAF3EAULL, 0x3FE9EF43EF29AF94ULL,
    0x3FC45576B1293E58ULL, 0x3FEF97F924C9099BULL,     0xBFEF97F924C9099BULL, 0x3FC45576B1293E5BULL,
    0x3FEFB5797195D741ULL, 0x3FC139F0CEDAF576ULL,     0xBFC139F0CEDAF574ULL, 0x3FEFB5797195D741ULL,
    0x3FE36058B10659F3ULL, 0x3FE9777EF4C7D741ULL,     0xBFE9777EF4C7D741ULL, 0x3FE36058B10659F4ULL,
    0x3FEBA5AA673590D3ULL, 0x3FE01CFC874C3EB7ULL,     0xBFE01CFC874C3EB6ULL, 0x3FEBA5AA673590D3ULL,
    0x3FD04FB80E37FDAFULL, 0x3FEEF178A3E473C2ULL,     0xBFEEF178A3E473C2ULL, 0x3FD04FB80E37FDB0ULL,
    0x3FEE426A4B2BC17EULL, 0x3FD4D1E24278E76AULL,     0xBFD4D1E24278E769ULL, 0x3FEE426A4B2BC17FULL,
    0x3FDC1249D8011EE8ULL, 0x3FECC1F0F3FCFC5CULL,     0xBFECC1F0F3FCFC5DULL, 0x3FDC1249D8011EE5ULL,
    0x3FE7F8ECE3571771ULL, 0x3FE5328292A35596ULL,     0xBFE5328292A35597ULL, 0x3FE7F8ECE3571770ULL,
    0x3FAF656E79F820EAULL, 0x3FEFF095658E71ADULL,     0xBFEFF095658E71ADULL, 0x3FAF656E79F820D3ULL,
    0x3FEFE1CAFCBD5B09ULL, 0x3FB5F6D00A9AA419ULL,     0xBFB5F6D00A9AA40FULL, 0x3FEFE1CAFCBD5B09ULL,
    0x3FE49A449B9B0939ULL, 0x3FE87C400FBA2EBFULL,     0xBFE87C400FBA2EBFULL, 0x3FE49A449B9B0938ULL,
    0x3FEC678B3488739BULL, 0x3FDD79775B86E389ULL,     0xBFDD79775B86E38AULL, 0x3FEC678B3488739BULL,
    0x3FD35410C2E18154ULL, 0x3FEE817BAB4CD10CULL,     0xBFEE817BAB4CD10DULL, 0x3FD35410C2E18151ULL,
    0x3FEEBBD8C8DF0B74ULL, 0x3FD1D3443F4CDB3DULL,     0xBFD1D3443F4CDB3BULL, 0x3FEEBBD8C8DF0B75ULL,
    0x3FDEDC1952EF78D7ULL, 0x3FEC08C426725549ULL,     0xBFEC08C426725548ULL, 0x3FDEDC1952EF78D8ULL,
    0x3FE8FBCCA3EF940DULL, 0x3FE3FED9534556D4ULL,     0xBFE3FED9534556D3ULL, 0x3FE8FBCCA3EF940EULL,
    0x3FBC3785C79EC2DEULL, 0x3FEFCE15FD6DA67BULL,     0xBFEFCE15FD6DA67BULL, 0x3FBC3785C79EC2E2ULL,
    0x3FEF7599A3A12077ULL, 0x3FC76DD9DE50BF31ULL,     0xBFC76DD9DE50BF30ULL, 0x3FEF7599A3A12077ULL,
    0x3FE21A799933EB59ULL, 0x3FEA63091B02FAE2ULL,     0xBFEA63091B02FAE0ULL, 0x3FE21A799933EB5BULL,
    0x3FEAD2BC9E21D511ULL, 0x3FE1734D63DEDB49ULL,     0xBFE1734D63DEDB47ULL, 0x3FEAD2BC9E21D512ULL,
    0x3FCA82A025B00451ULL, 0x3FEF4E603B0B2F2DULL,     0xBFEF4E603B0B2F2CULL, 0x3FCA82A025B0045BULL,
    0x3FEDB6526238A09BULL, 0x3FD7C3A9311DCCE7ULL,     0xBFD7C3A9311DCCE6ULL, 0x3FEDB6526238A09BULL,
    0x3FD9372A63BC93D7ULL, 0x3FED696173C9E68BULL,     0xBFED696173C9E68BULL, 0x3FD9372A63BC93D8ULL,
    0x3FE6E74454EAA8AEULL, 0x3FE6591925F0783EULL,     0xBFE6591925F0783DULL, 0x3FE6E74454EAA8AFULL,
    0x3F8921D1FCDEC78FULL, 0x3FEFFF62169B92DBULL,     0xBFEFFF62169B92DBULL, 0x3F8921D1FCDEC7B3ULL,
    0x3FEFFFD8858E8A92ULL, 0x3F7921F0FE670071ULL,     0xBF7921F0FE670012ULL, 0x3FEFFFD8858E8A92ULL,
    0x3FE67CF78491AF10ULL, 0x3FE6C40D73C18275ULL,     0xBFE6C40D73C18276ULL, 0x3FE67CF78491AF0FULL,
    0x3FED7D0B02B8ECFAULL, 0x3FD8DAA52EC8A4AFULL,     0xBFD8DAA52EC8A4AEULL, 0x3FED7D0B02B8ECFAULL,
    0x3FD820E3B04EAAC5ULL, 0x3FEDA383A9668987ULL,     0xBFEDA383A9668988ULL, 0x3FD820E3B04EAAC2ULL,
    0x3FEF58A2B1789E84ULL, 0x3FC9BDCBF2DC4366ULL,     0xBFC9BDCBF2DC4363ULL, 0x3FEF58A2B1789E84ULL,
    0x3FE19D5A09F2B9B8ULL, 0x3FEAB7325916C0D4ULL,     0xBFEAB7325916C0D4ULL, 0x3FE19D5A09F2B9B9ULL,
    0x3FEA7F58529FE69DULL, 0x3FE1F0F08BBC861BULL,     0xBFE1F0F08BBC861AULL, 0x3FEA7F58529FE69DULL,
    0x3FC83366E89C64C8ULL, 0x3FEF6C3F7DF5BBB7ULL,     0xBFEF6C3F7DF5BBB7ULL, 0x3FC83366E89C64CBULL,
    0x3FEFD37914220B84ULL, 0x3FBAA7B724495C04ULL,     0xBFBAA7B724495C05ULL, 0x3FEFD37914220B84ULL,
    0x3FE425FF178E6BB2ULL, 0x3FE8DC45331698CCULL,     0xBFE8DC45331698CBULL, 0x3FE425FF178E6BB3ULL,
    0x3FEC20DE3FA971B0ULL, 0x3FDE83E0EAF85113ULL,     0xBFDE83E0EAF85110ULL, 0x3FEC20DE3FA971B0ULL,
    0x3FD233BBABC3BB71ULL, 0x3FEEADB2E8E7A88EULL,     0xBFEEADB2E8E7A88DULL, 0x3FD233BBABC3BB76ULL,
    0x3FEE9084361DF7F3ULL, 0x3FD2F422DAEC0386ULL,     0xBFD2F422DAEC0387ULL, 0x3FEE9084361DF7F2ULL,
    0x3FDDD28F1481CC57ULL, 0x3FEC5042012B6907ULL,     0xBFEC5042012B6907ULL, 0x3FDDD28F1481CC58ULL,
    0x3FE89C7E9A4DD4ABULL, 0x3FE473B51B987347ULL,     0xBFE473B51B987347ULL, 0x3FE89C7E9A4DD4AAULL,
    0x3FB787586A5D5B1FULL, 0x3FEFDD539FF1F456ULL,     0xBFEFDD539FF1F456ULL, 0x3FB787586A5D5B23ULL,
    0x3FEFF3830F8D575CULL, 0x3FAC428D12C0D7E2ULL,     0xBFAC428D12C0D7DFULL, 0x3FEFF3830F8D575CULL,
    0x3FE5581038975137ULL, 0x3FE7D7836CC33DB2ULL,     0xBFE7D7836CC33DB2ULL, 0x3FE5581038975138ULL,
    0x3FECD7D9898B32F6ULL, 0x3FDBB7CF2304BD01ULL,     0xBFDBB7CF2304BD00ULL, 0x3FECD7D9898B32F6ULL,
    0x3FD530D880AF3C24ULL, 0x3FEE31EAE870CE25ULL,     0xBFEE31EAE870CE25ULL, 0x3FD530D880AF3C25ULL,
    0x3FEEFE220C0B95EDULL, 0x3FCFDCDC1ADFEDF8ULL,     0xBFCFDCDC1ADFEDF7ULL, 0x3FEEFE220C0B95EDULL,
    0x3FE0485626AE221AULL, 0x3FEB8C38D27504E9ULL,     0xBFEB8C38D27504E7ULL, 0x3FE0485626AE221DULL,
    0x3FE995CF2ED80D22ULL, 0x3FE338400D0C8E57ULL,     0xBFE338400D0C8E55ULL, 0x3FE995CF2ED80D24ULL,
    0x3FC20116D4EC7BCFULL, 0x3FEFAE8E8E46CFBBULL,     0xBFEFAE8E8E46CFBAULL, 0x3FC20116D4EC7BDAULL,
    0x3FEF9FCE55ADB2C8ULL, 0x3FC38EDBB0CD8D14ULL,     0xBFC38EDBB0CD8D0FULL, 0x3FEF9FCE55ADB2C8ULL,
    0x3FE2E780E3E8EA17ULL, 0x3FE9D1B1F5EA80D5ULL,     0xBFE9D1B1F5EA80D6ULL, 0x3FE2E780E3E8EA16ULL,
    0x3FEB5889FE921405ULL, 0x3FE09E907417C5E1ULL,     0xBFE09E907417C5E1ULL, 0x3FEB5889FE921405ULL,
    0x3FCE56CA1E101A20ULL, 0x3FEF168F53F7205DULL,     0xBFEF168F53F7205DULL, 0x3FCE56CA1E101A1AULL,
    0x3FEE100CCA2980ACULL, 0x3FD5EE27379EA693ULL,     0xBFD5EE27379EA691ULL, 0x3FEE100CCA2980ACULL,
    0x3FDB020D6C7F400BULL, 0x3FED02D4FEB2BD92ULL,     0xBFED02D4FEB2BD92ULL, 0x3FDB020D6C7F400CULL,
    0x3FE79400574F55E5ULL, 0x3FE5A28D2A5D7250ULL,     0xBFE5A28D2A5D724FULL, 0x3FE79400574F55E6ULL,
    0x3FA5FC00D290CD57ULL, 0x3FEFF871DADB81DFULL,     0xBFEFF871DADB81DFULL, 0x3FA5FC00D290CD60ULL,
    0x3FEFFC251DF1D3F8ULL, 0x3F9F693731D1CF01ULL,     0xBF9F693731D1CED1ULL, 0x3FEFFC251DF1D3F8ULL,
    0x3FE5EC3495837074ULL, 0x3FE74F948DA8D28DULL,     0xBFE74F948DA8D28DULL, 0x3FE5EC3495837074ULL,
    0x3FED2CB220E0EF9FULL, 0x3FDA4B4127DEA1E4ULL,     0xBFDA4B4127DEA1E2ULL, 0x3FED2CB220E0EF9FULL,
    0x3FD6AA9D7DC77E19ULL, 0x3FEDED05F7DE47D9ULL,     0xBFEDED05F7DE47DAULL, 0x3FD6AA9D7DC77E17ULL,
    0x3FEF2DC9C9089A9DULL, 0x3FCCCF8CB312B286ULL,     0xBFCCCF8CB312B280ULL, 0x3FEF2DC9C9089A9DULL,
    0x3FE0F426BB2A8E7FULL, 0x3FEB23CD470013B3ULL,     0xBFEB23CD470013B3ULL, 0x3FE0F426BB2A8E7FULL,
    0x3FEA0C95EABAF937ULL, 0x3FE2960727629CA8ULL,     0xBFE2960727629CA7ULL, 0x3FEA0C95EABAF938ULL,
    0x3FC51BDF8597C5F8ULL, 0x3FEF8FD5FFAE41DBULL,     0xBFEF8FD5FFAE41DAULL, 0x3FC51BDF8597C5FAULL,
    0x3FEFBC1617E44186ULL, 0x3FC072A047BA831DULL,     0xBFC072A047BA831BULL, 0x3FEFBC1617E44186ULL,
    0x3FE3884185DFEB22ULL, 0x3FE958EFE48E6DD7ULL,     0xBFE958EFE48E6DD5ULL, 0x3FE3884185DFEB24ULL,
    0x3FEBBED7C49380EAULL, 0x3FDFE2F64BE71210ULL,     0xBFDFE2F64BE7120BULL, 0x3FEBBED7C49380EBULL,
    0x3FD0B0D9CFDBDB91ULL, 0x3FEEE482E25A9DBCULL,     0xBFEEE482E25A9DBBULL, 0x3FD0B0D9CFDBDB96ULL,
    0x3FEE529F04729FFCULL, 0x3FD472B8A5571054ULL,     0xBFD472B8A5571053ULL, 0x3FEE529F04729FFDULL,
    0x3FDC6C7F4997000BULL, 0x3FECABC169A0B900ULL,     0xBFECABC169A0B900ULL, 0x3FDC6C7F4997000CULL,
    0x3FE81A1B33B57ACCULL, 0x3FE50CC09F59A09BULL,     0xBFE50CC09F59A09BULL, 0x3FE81A1B33B57ACCULL,
    0x3FB1440134D709B6ULL, 0x3FEFED58ECB673C4ULL,     0xBFEFED58ECB673C4ULL, 0x3FB1440134D709BBULL,
    0x3FEFE5F3AF2E3940ULL, 0x3FB4661179272096ULL,     0xBFB466117927208EULL, 0x3FEFE5F3AF2E3941ULL,
    0x3FE4C0A145EC0005ULL, 0x3FE85BC51AE958CCULL,     0xBFE85BC51AE958CBULL, 0x3FE4C0A145EC0005ULL,
    0x3FEC7E8E52233CF3ULL, 0x3FDD2016E8E9DB5BULL,     0xBFDD2016E8E9DB59ULL, 0x3FEC7E8E52233CF4ULL,
    0x3FD3B3CEFA0414B9ULL, 0x3FEE7227DB6A9744ULL,     0xBFEE7227DB6A9744ULL, 0x3FD3B3CEFA0414BAULL,
    0x3FEEC9B2D3C3BF84ULL, 0x3FD172A0D7765177ULL,     0xBFD172A0D7765175ULL, 0x3FEEC9B2D3C3BF84ULL,
    0x3FDF3405963FD069ULL, 0x3FEBF064E15377DDULL,     0xBFEBF064E15377DDULL, 0x3FDF3405963FD066ULL,
    0x3FE91B166FD49DA2ULL, 0x3FE3D78238C58343ULL,     0xBFE3D78238C58344ULL, 0x3FE91B166FD49DA1ULL,
    0x3FBDC70ECBAE9FD1ULL, 0x3FEFC8646CFEB721ULL,     0xBFEFC8646CFEB721ULL, 0x3FBDC70ECBAE9FC5ULL,
    0x3FEF7EA629E63D6EULL, 0x3FC6A81304F64AB2ULL,     0xBFC6A81304F64AB2ULL, 0x3FEF7EA629E63D6EULL,
    0x3FE243D5FB98AC20ULL, 0x3FEA4678C8119AC8ULL,     0xBFEA4678C8119AC8ULL, 0x3FE243D5FB98AC1FULL,
    0x3FEAEE04B43C1474ULL, 0x3FE14915AF336CEBULL,     0xBFE14915AF336CEBULL, 0x3FEAEE04B43C1474ULL,
    0x3FCB4732EF3D6722ULL, 0x3FEF43D085FF92DDULL,     0xBFEF43D085FF92DDULL, 0x3FCB4732EF3D6724ULL,
    0x3FEDC8D7CB410260ULL, 0x3FD766340F2418F6ULL,     0xBFD766340F2418F6ULL, 0x3FEDC8D7CB410260ULL,
    0x3FD993716141BDFEULL, 0x3FED556F52E93EB1ULL,     0xBFED556F52E93EB0ULL, 0x3FD993716141BE03ULL,
    0x3FE70A42B3176D7AULL, 0x3FE63503A31C1BE9ULL,     0xBFE63503A31C1BE7ULL, 0x3FE70A42B3176D7BULL,
    0x3F92D936BBE30EFDULL, 0x3FEFFE9CB44B51A1ULL,     0xBFEFFE9CB44B51A1ULL, 0x3F92D936BBE30F4EULL,
    0x3FEFFE9CB44B51A1ULL, 0x3F92D936BBE30EFDULL,     0xBF92D936BBE30ED9ULL, 0x3FEFFE9CB44B51A1ULL,
    0x3FE63503A31C1BE9ULL, 0x3FE70A42B3176D7AULL,     0xBFE70A42B3176D7AULL, 0x3FE63503A31C1BE9ULL,
    0x3FED556F52E93EB1ULL, 0x3FD993716141BDFEULL,     0xBFD993716141BDFCULL, 0x3FED556F52E93EB1ULL,
    0x3FD766340F2418F8ULL, 0x3FEDC8D7CB410260ULL,     0xBFEDC8D7CB410260ULL, 0x3FD766340F2418F5ULL,
    0x3FEF43D085FF92DDULL, 0x3FCB4732EF3D6722ULL,     0xBFCB4732EF3D671EULL, 0x3FEF43D085FF92DDULL,
    0x3FE14915AF336CECULL, 0x3FEAEE04B43C1473ULL,     0xBFEAEE04B43C1473ULL, 0x3FE14915AF336CECULL,
    0x3FEA4678C8119AC8ULL, 0x3FE243D5FB98AC1FULL,     0xBFE243D5FB98AC1EULL, 0x3FEA4678C8119AC9ULL,
    0x3FC6A81304F64AB6ULL, 0x3FEF7EA629E63D6EULL,     0xBFEF7EA629E63D6EULL, 0x3FC6A81304F64AB9ULL,
    0x3FEFC8646CFEB721ULL, 0x3FBDC70ECBAE9FC8ULL,     0xBFBDC70ECBAE9FC8ULL, 0x3FEFC8646CFEB721ULL,
    0x3FE3D78238C58344ULL, 0x3FE91B166FD49DA2ULL,     0xBFE91B166FD49DA0ULL, 0x3FE3D78238C58346ULL,
    0x3FEBF064E15377DDULL, 0x3FDF3405963FD068ULL,     0xBFDF3405963FD063ULL, 0x3FEBF064E15377DEULL,
    0x3FD172A0D7765177ULL, 0x3FEEC9B2D3C3BF84ULL,     0xBFEEC9B2D3C3BF83ULL, 0x3FD172A0D776517CULL,
    0x3FEE7227DB6A9744ULL, 0x3FD3B3CEFA0414B7ULL,     0xBFD3B3CEFA0414B7ULL, 0x3FEE7227DB6A9744ULL,
    0x3FDD2016E8E9DB5BULL, 0x3FEC7E8E52233CF3ULL,     0xBFEC7E8E52233CF3ULL, 0x3FDD2016E8E9DB5CULL,
    0x3FE85BC51AE958CCULL, 0x3FE4C0A145EC0004ULL,     0xBFE4C0A145EC0004ULL, 0x3FE85BC51AE958CDULL,
    0x3FB4661179272096ULL, 0x3FEFE5F3AF2E3940ULL,     0xBFEFE5F3AF2E3940ULL, 0x3FB466117927209BULL,
    0x3FEFED58ECB673C4ULL, 0x3FB1440134D709B2ULL,     0xBFB1440134D709ADULL, 0x3FEFED58ECB673C4ULL,
    0x3FE50CC09F59A09BULL, 0x3FE81A1B33B57ACBULL,     0xBFE81A1B33B57ACBULL, 0x3FE50CC09F59A09CULL,
    0x3FECABC169A0B901ULL, 0x3FDC6C7F4997000AULL,     0xBFDC6C7F49970009ULL, 0x3FECABC169A0B901ULL,
    0x3FD472B8A5571055ULL, 0x3FEE529F04729FFCULL,     0xBFEE529F04729FFCULL, 0x3FD472B8A5571056ULL,
    0x3FEEE482E25A9DBCULL, 0x3FD0B0D9CFDBDB90ULL,     0xBFD0B0D9CFDBDB8FULL, 0x3FEEE482E25A9DBCULL,
    0x3FDFE2F64BE71210ULL, 0x3FEBBED7C49380EAULL,     0xBFEBBED7C49380EBULL, 0x3FDFE2F64BE7120EULL,
    0x3FE958EFE48E6DD7ULL, 0x3FE3884185DFEB22ULL,     0xBFE3884185DFEB23ULL, 0x3FE958EFE48E6DD6ULL,
    0x3FC072A047BA831FULL, 0x3FEFBC1617E44186ULL,     0xBFEFBC1617E44186ULL, 0x3FC072A047BA831AULL,
    0x3FEF8FD5FFAE41DBULL, 0x3FC51BDF8597C5F2ULL,     0xBFC51BDF8597C5F3ULL, 0x3FEF8FD5FFAE41DBULL,
    0x3FE2960727629CA8ULL, 0x3FEA0C95EABAF936ULL,     0xBFEA0C95EABAF937ULL, 0x3FE2960727629CA8ULL,
    0x3FEB23CD470013B4ULL, 0x3FE0F426BB2A8E7DULL,     0xBFE0F426BB2A8E7EULL, 0x3FEB23CD470013B4ULL,
    0x3FCCCF8CB312B284ULL, 0x3FEF2DC9C9089A9DULL,     0xBFEF2DC9C9089A9DULL, 0x3FCCCF8CB312B286ULL,
    0x3FEDED05F7DE47DAULL, 0x3FD6AA9D7DC77E16ULL,     0xBFD6AA9D7DC77E17ULL, 0x3FEDED05F7DE47DAULL,
    0x3FDA4B4127DEA1E4ULL, 0x3FED2CB220E0EF9FULL,     0xBFED2CB220E0EF9EULL, 0x3FDA4B4127DEA1E8ULL,
    0x3FE74F948DA8D28DULL, 0x3FE5EC3495837074ULL,     0xBFE5EC3495837073ULL, 0x3FE74F948DA8D28EULL,
    0x3F9F693731D1CEF4ULL, 0x3FEFFC251DF1D3F8ULL,     0xBFEFFC251DF1D3F8ULL, 0x3F9F693731D1CF46ULL,
    0x3FEFF871DADB81DFULL, 0x3FA5FC00D290CD43ULL,     0xBFA5FC00D290CD45ULL, 0x3FEFF871DADB81DFULL,
    0x3FE5A28D2A5D7251ULL, 0x3FE79400574F55E4ULL,     0xBFE79400574F55E5ULL, 0x3FE5A28D2A5D7250ULL,
    0x3FED02D4FEB2BD92ULL, 0x3FDB020D6C7F4009ULL,     0xBFDB020D6C7F4009ULL, 0x3FED02D4FEB2BD92ULL,
    0x3FD5EE27379EA693ULL, 0x3FEE100CCA2980ACULL,     0xBFEE100CCA2980ACULL, 0x3FD5EE27379EA694ULL,
    0x3FEF168F53F7205DULL, 0x3FCE56CA1E101A1BULL,     0xBFCE56CA1E101A1CULL, 0x3FEF168F53F7205DULL,
    0x3FE09E907417C5E0ULL, 0x3FEB5889FE921405ULL,     0xBFEB5889FE921404ULL, 0x3FE09E907417C5E2ULL,
    0x3FE9D1B1F5EA80D6ULL, 0x3FE2E780E3E8EA16ULL,     0xBFE2E780E3E8EA15ULL, 0x3FE9D1B1F5EA80D7ULL,
    0x3FC38EDBB0CD8D13ULL, 0x3FEF9FCE55ADB2C8ULL,     0xBFEF9FCE55ADB2C8ULL, 0x3FC38EDBB0CD8D1DULL,
    0x3FEFAE8E8E46CFBBULL, 0x3FC20116D4EC7BCEULL,     0xBFC20116D4EC7BCBULL, 0x3FEFAE8E8E46CFBBULL,
    0x3FE338400D0C8E57ULL, 0x3FE995CF2ED80D22ULL,     0xBFE995CF2ED80D23ULL, 0x3FE338400D0C8E56ULL,
    0x3FEB8C38D27504E9ULL, 0x3FE0485626AE221AULL,     0xBFE0485626AE221BULL, 0x3FEB8C38D27504E8ULL,
    0x3FCFDCDC1ADFEDFCULL, 0x3FEEFE220C0B95ECULL,     0xBFEEFE220C0B95EDULL, 0x3FCFDCDC1ADFEDF6ULL,
    0x3FEE31EAE870CE25ULL, 0x3FD530D880AF3C24ULL,     0xBFD530D880AF3C22ULL, 0x3FEE31EAE870CE25ULL,
    0x3FDBB7CF2304BD02ULL, 0x3FECD7D9898B32F6ULL,     0xBFECD7D9898B32F5ULL, 0x3FDBB7CF2304BD03ULL,
    0x3FE7D7836CC33DB3ULL, 0x3FE5581038975137ULL,     0xBFE5581038975136ULL, 0x3FE7D7836CC33DB3ULL,
    0x3FAC428D12C0D7F0ULL, 0x3FEFF3830F8D575CULL,     0xBFEFF3830F8D575CULL, 0x3FAC428D12C0D7F9ULL,
    0x3FEFDD539FF1F456ULL, 0x3FB787586A5D5B21ULL,     0xBFB787586A5D5B16ULL, 0x3FEFDD539FF1F456ULL,
    0x3FE473B51B987347ULL, 0x3FE89C7E9A4DD4AAULL,     0xBFE89C7E9A4DD4A9ULL, 0x3FE473B51B987348ULL,
    0x3FEC5042012B6907ULL, 0x3FDDD28F1481CC58ULL,     0xBFDDD28F1481CC55ULL, 0x3FEC5042012B6908ULL,
    0x3FD2F422DAEC0389ULL, 0x3FEE9084361DF7F2ULL,     0xBFEE9084361DF7F2ULL, 0x3FD2F422DAEC038AULL,
    0x3FEEADB2E8E7A88EULL, 0x3FD233BBABC3BB72ULL,     0xBFD233BBABC3BB6FULL, 0x3FEEADB2E8E7A88EULL,
    0x3FDE83E0EAF85116ULL, 0x3FEC20DE3FA971AFULL,     0xBFEC20DE3FA971B0ULL, 0x3FDE83E0EAF85113ULL,
    0x3FE8DC45331698CCULL, 0x3FE425FF178E6BB1ULL,     0xBFE425FF178E6BB2ULL, 0x3FE8DC45331698CCULL,
    0x3FBAA7B724495C0EULL, 0x3FEFD37914220B84ULL,     0xBFEFD37914220B84ULL, 0x3FBAA7B724495C03ULL,
    0x3FEF6C3F7DF5BBB7ULL, 0x3FC83366E89C64C5ULL,     0xBFC83366E89C64C4ULL, 0x3FEF6C3F7DF5BBB7ULL,
    0x3FE1F0F08BBC861BULL, 0x3FEA7F58529FE69DULL,     0xBFEA7F58529FE69CULL, 0x3FE1F0F08BBC861CULL,
    0x3FEAB7325916C0D4ULL, 0x3FE19D5A09F2B9B8ULL,     0xBFE19D5A09F2B9B7ULL, 0x3FEAB7325916C0D5ULL,
    0x3FC9BDCBF2DC4368ULL, 0x3FEF58A2B1789E84ULL,     0xBFEF58A2B1789E84ULL, 0x3FC9BDCBF2DC436AULL,
    0x3FEDA383A9668988ULL, 0x3FD820E3B04EAAC4ULL,     0xBFD820E3B04EAAC3ULL, 0x3FEDA383A9668988ULL,
    0x3FD8DAA52EC8A4B0ULL, 0x3FED7D0B02B8ECF9ULL,     0xBFED7D0B02B8ECF8ULL, 0x3FD8DAA52EC8A4B5ULL,
    0x3FE6C40D73C18275ULL, 0x3FE67CF78491AF10ULL,     0xBFE67CF78491AF0EULL, 0x3FE6C40D73C18277ULL,
    0x3F7921F0FE67009FULL, 0x3FEFFFD8858E8A92ULL,     0xBFEFFFD8858E8A92ULL, 0x3F7921F0FE6701E6ULL,
    0x3FEFFFF621621D02ULL, 0x3F6921F8BECCA4BAULL,     0xBF6921F8BECCA515ULL, 0x3FEFFFF621621D02ULL,
    0x3FE68ED1EAA19C72ULL, 0x3FE6B25CED2FE29BULL,     0xBFE6B25CED2FE29AULL, 0x3FE68ED1EAA19C73ULL,
    0x3FED86C48445A450ULL, 0x3FD8AC4B86D5ED44ULL,     0xBFD8AC4B86D5ED45ULL, 0x3FED86C48445A44FULL,
    0x3FD84F6AAAF3903EULL, 0x3FED9A00DD8B3D46ULL,     0xBFED9A00DD8B3D45ULL, 0x3FD84F6AAAF39043ULL,
    0x3FEF5DA6ED43685DULL, 0x3FC95B49E9B62AF9ULL,     0xBFC95B49E9B62AFBULL, 0x3FEF5DA6ED43685DULL,
    0x3FE1B250171373BFULL, 0x3FEAA9547A2CB98EULL,     0xBFEAA9547A2CB98EULL, 0x3FE1B250171373BFULL,
    0x3FEA8D676E545AD2ULL, 0x3FE1DC1B64DC4872ULL,     0xBFE1DC1B64DC4872ULL, 0x3FEA8D676E545AD2ULL,
    0x3FC8961727C41802ULL, 0x3FEF677556883CEEULL,     0xBFEF677556883CEEULL, 0x3FC8961727C41805ULL,
    0x3FEFD60D2DA75C9EULL, 0x3FB9DFB6EB24A85CULL,     0xBFB9DFB6EB24A857ULL, 0x3FEFD60D2DA75C9EULL,
    0x3FE4397F5B2A4380ULL, 0x3FE8CC6A75184654ULL,     0xBFE8CC6A75184654ULL, 0x3FE4397F5B2A4380ULL,
    0x3FEC2CD14931E3F1ULL, 0x3FDE57A86D3CD824ULL,     0xBFDE57A86D3CD823ULL, 0x3FEC2CD14931E3F2ULL,
    0x3FD263E6995554BBULL, 0x3FEEA68393E65800ULL,     0xBFEEA68393E65800ULL, 0x3FD263E6995554BCULL,
    0x3FEE97EC36016B30ULL, 0x3FD2C41A4E954520ULL,     0xBFD2C41A4E95451FULL, 0x3FEE97EC36016B31ULL,
    0x3FDDFEFF66A941DEULL, 0x3FEC44833141C004ULL,     0xBFEC44833141C005ULL, 0x3FDDFEFF66A941DCULL,
    0x3FE8AC871EDE1D88ULL, 0x3FE4605A692B32A2ULL,     0xBFE4605A692B32A3ULL, 0x3FE8AC871EDE1D87ULL,
    0x3FB84F8712C130A5ULL, 0x3FEFDAFA7514538CULL,     0xBFEFDAFA7514538CULL, 0x3FB84F8712C1309AULL,
    0x3FEFF4DC54B1BED3ULL, 0x3FAAB101BD5F8317ULL,     0xBFAAB101BD5F8304ULL, 0x3FEFF4DC54B1BED3ULL,
    0x3FE56AC35197649EULL, 0x3FE7C6B89CE2D333ULL,     0xBFE7C6B89CE2D333ULL, 0x3FE56AC35197649EULL,
    0x3FECE2B32799A060ULL, 0x3FDB8A7814FD5693ULL,     0xBFDB8A7814FD5695ULL, 0x3FECE2B32799A060ULL,
    0x3FD5604012F467B6ULL, 0x3FEE298F4439197AULL,     0xBFEE298F4439197AULL, 0x3FD5604012F467B4ULL,
    0x3FEF045A14CF738CULL, 0x3FCF7B7480BD3801ULL,     0xBFCF7B7480BD37FDULL, 0x3FEF045A14CF738CULL,
    0x3FE05DF3EC31B8B8ULL, 0x3FEB7F6686E792E9ULL,     0xBFEB7F6686E792E9ULL, 0x3FE05DF3EC31B8B8ULL,
    0x3FE9A4DFA42B06B2ULL, 0x3FE32421EC49A61FULL,     0xBFE32421EC49A61EULL, 0x3FE9A4DFA42B06B3ULL,
    0x3FC264994DFD340EULL, 0x3FEFAAFBCB0CFDDBULL,     0xBFEFAAFBCB0CFDDBULL, 0x3FC264994DFD3410ULL,
    0x3FEFA39BAC7A1791ULL, 0x3FC32B7BF94516A7ULL,     0xBFC32B7BF94516A7ULL, 0x3FEFA39BAC7A1791ULL,
    0x3FE2FBC24B441015ULL, 0x3FE9C2D110F075C3ULL,     0xBFE9C2D110F075C1ULL, 0x3FE2FBC24B441017ULL,
    0x3FEB658F14FDBC47ULL, 0x3FE089112032B08CULL,     0xBFE089112032B08AULL, 0x3FEB658F14FDBC48ULL,
    0x3FCEB86B462DE348ULL, 0x3FEF1090BC898F5FULL,     0xBFEF1090BC898F5EULL, 0x3FCEB86B462DE352ULL,
    0x3FEE18A02FDC66D9ULL, 0x3FD5BEE78B9DB3B6ULL,     0xBFD5BEE78B9DB3B6ULL, 0x3FEE18A02FDC66D9ULL,
    0x3FDB2F971DB31972ULL, 0x3FECF830E8CE467BULL,     0xBFECF830E8CE467AULL, 0x3FDB2F971DB31973ULL,
    0x3FE7A4F707BF97D2ULL, 0x3FE59001D5F723DFULL,     0xBFE59001D5F723DFULL, 0x3FE7A4F707BF97D3ULL,
    0x3FA78DBAA5874688ULL, 0x3FEFF753BB1B9164ULL,     0xBFEFF753BB1B9164ULL, 0x3FA78DBAA5874691ULL,
    0x3FEFFCE09CE2A679ULL, 0x3F9C454F4CE53B1CULL,     0xBF9C454F4CE53B10ULL, 0x3FEFFCE09CE2A679ULL,
    0x3FE5FE7CBDE56A10ULL, 0x3FE73E558E079942ULL,     0xBFE73E558E079940ULL, 0x3FE5FE7CBDE56A11ULL,
    0x3FED36FC7BCBFBDCULL, 0x3FDA1D6543B50AC0ULL,     0xBFDA1D6543B50ABFULL, 0x3FED36FC7BCBFBDCULL,
    0x3FD6D998638A0CB6ULL, 0x3FEDE4160F6D8D81ULL,     0xBFEDE4160F6D8D80ULL, 0x3FD6D998638A0CBBULL,
    0x3FEF33685A3AAEF0ULL, 0x3FCC6D90535D74DCULL,     0xBFCC6D90535D74DBULL, 0x3FEF33685A3AAEF0ULL,
    0x3FE1097248D0A957ULL, 0x3FEB16742A4CA2F4ULL,     0xBFEB16742A4CA2F4ULL, 0x3FE1097248D0A957ULL,
    0x3FEA1B26D2C0A75EULL, 0x3FE2818BEF4D3CBAULL,     0xBFE2818BEF4D3CB9ULL, 0x3FEA1B26D2C0A75EULL,
    0x3FC57F008654CBE0ULL, 0x3FEF8BA737CB4B77ULL,     0xBFEF8BA737CB4B77ULL, 0x3FC57F008654CBE2ULL,
    0x3FEFBF470F0A8D88ULL, 0x3FC00EE8AD6FB85BULL,     0xBFC00EE8AD6FB855ULL, 0x3FEFBF470F0A8D88ULL,
    0x3FE39C23E3D63029ULL, 0x3FE94990E3AC4A6CULL,     0xBFE94990E3AC4A6BULL, 0x3FE39C23E3D6302AULL,
    0x3FEBCB54CB0D2327ULL, 0x3FDFB7575C24D2DEULL,     0xBFDFB7575C24D2DBULL, 0x3FEBCB54CB0D2328ULL,
    0x3FD0E15B4E1749D0ULL, 0x3FEEDDEB6A078650ULL,     0xBFEEDDEB6A078650ULL, 0x3FD0E15B4E1749D1ULL,
    0x3FEE5A9D550467D3ULL, 0x3FD44310DC8936F0ULL,     0xBFD44310DC8936EEULL, 0x3FEE5A9D550467D4ULL,
    0x3FDC997FC386538BULL, 0x3FECA08F19B9C448ULL,     0xBFECA08F19B9C449ULL, 0x3FDC997FC3865388ULL,
    0x3FE82A9C13F545FFULL, 0x3FE4F9CC25CCA486ULL,     0xBFE4F9CC25CCA487ULL, 0x3FE82A9C13F545FFULL,
    0x3FB20C9674ED4457ULL, 0x3FEFEB9D2530410FULL,     0xBFEFEB9D2530410FULL, 0x3FB20C9674ED444CULL,
    0x3FEFE7EA85482D60ULL, 0x3FB39D9F12C5A299ULL,     0xBFB39D9F12C5A29AULL, 0x3FEFE7EA85482D60ULL,
    0x3FE4D3BC6D589F80ULL, 0x3FE84B7111AF83F9ULL,     0xBFE84B7111AF83FAULL, 0x3FE4D3BC6D589F80ULL,
    0x3FEC89F587029C13ULL, 0x3FDCF34BAEE1CD21ULL,     0xBFDCF34BAEE1CD21ULL, 0x3FEC89F587029C13ULL,
    0x3FD3E39BE96EC271ULL, 0x3FEE6A61C55D53A7ULL,     0xBFEE6A61C55D53A7ULL, 0x3FD3E39BE96EC272ULL,
    0x3FEED0835E999009ULL, 0x3FD1423EEFC69378ULL,     0xBFD1423EEFC69378ULL, 0x3FEED0835E999009ULL,
    0x3FDF5FDEE656CDA2ULL, 0x3FEBE41B611154C1ULL,     0xBFEBE41B611154BFULL, 0x3FDF5FDEE656CDA7ULL,
    0x3FE92AA41FC5A815ULL, 0x3FE3C3C44981C517ULL,     0xBFE3C3C44981C516ULL, 0x3FE92AA41FC5A816ULL,
    0x3FBE8EB7FDE4AA3EULL, 0x3FEFC56E3B7D9AF6ULL,     0xBFEFC56E3B7D9AF6ULL, 0x3FBE8EB7FDE4AA52ULL,
    0x3FEF830F4A40C60CULL, 0x3FC6451A831D830DULL,     0xBFC6451A831D8309ULL, 0x3FEF830F4A40C60CULL,
    0x3FE258734CBB7111ULL, 0x3FEA38184A593BC5ULL,     0xBFEA38184A593BC6ULL, 0x3FE258734CBB710FULL,
    0x3FEAFB8FD89F57B6ULL, 0x3FE133E9CFEE254EULL,     0xBFE133E9CFEE2550ULL, 0x3FEAFB8FD89F57B6ULL,
    0x3FCBA96334F15DB0ULL, 0x3FEF3E6BBC1BBC65ULL,     0xBFEF3E6BBC1BBC65ULL, 0x3FCBA96334F15DAAULL,
    0x3FEDD1FEF38A915AULL, 0x3FD73763C9261092ULL,     0xBFD73763C9261090ULL, 0x3FEDD1FEF38A915AULL,
    0x3FD9C17D440DF9F4ULL, 0x3FED4B5B1B187524ULL,     0xBFED4B5B1B187523ULL, 0x3FD9C17D440DF9F5ULL,
    0x3FE71BAC960E41BFULL, 0x3FE622E44FEC22FFULL,     0xBFE622E44FEC22FEULL, 0x3FE71BAC960E41C0ULL,
    0x3F95FD4D21FAB242ULL, 0x3FEFFE1C6870CB77ULL,     0xBFEFFE1C6870CB77ULL, 0x3F95FD4D21FAB254ULL,
    0x3FEFFF0943C53BD1ULL, 0x3F8F6A296AB997CAULL,     0xBF8F6A296AB997C9ULL, 0x3FEFFF0943C53BD1ULL,
    0x3FE64715437F535BULL, 0x3FE6F8CA99C95B75ULL,     0xBFE6F8CA99C95B74ULL, 0x3FE64715437F535CULL,
    0x3FED5F7172888A7FULL, 0x3FD96555B7AB948FULL,     0xBFD96555B7AB948FULL, 0x3FED5F7172888A7FULL,
    0x3FD794F5E613DFAEULL, 0x3FEDBF9E4395759BULL,     0xBFEDBF9E4395759AULL, 0x3FD794F5E613DFB3ULL,
    0x3FEF492206BCABB4ULL, 0x3FCAE4F1D5F3B9ABULL,     0xBFCAE4F1D5F3B9ABULL, 0x3FEF492206BCABB4ULL,
    0x3FE15E36E4DBE2BDULL, 0x3FEAE068F345ECEEULL,     0xBFEAE068F345ECEFULL, 0x3FE15E36E4DBE2BCULL,
    0x3FEA54C91090F524ULL, 0x3FE22F2D662C13E1ULL,     0xBFE22F2D662C13E1ULL, 0x3FEA54C91090F523ULL,
    0x3FC70AFD8D08C4FFULL, 0x3FEF7A299C1A322AULL,     0xBFEF7A299C1A322AULL, 0x3FC70AFD8D08C501ULL,
    0x3FEFCB4703914354ULL, 0x3FBCFF533B307DC1ULL,     0xBFBCFF533B307DB9ULL, 0x3FEFCB4703914354ULL,
    0x3FE3EB33EABE0681ULL, 0x3FE90B7943575EFEULL,     0xBFE90B7943575EFDULL, 0x3FE3EB33EABE0681ULL,
    0x3FEBFC9D25A1B147ULL, 0x3FDF081906BFF7FDULL,     0xBFDF081906BFF7FCULL, 0x3FEBFC9D25A1B148ULL,
    0x3FD1A2F7FBE8F245ULL, 0x3FEEC2CF4B1AF6B2ULL,     0xBFEEC2CF4B1AF6B2ULL, 0x3FD1A2F7FBE8F246ULL,
    0x3FEE79DB29A5165AULL, 0x3FD383F5E353B6AAULL,     0xBFD383F5E353B6A8ULL, 0x3FEE79DB29A5165AULL,
    0x3FDD4CD02BA8609EULL, 0x3FEC7315899EAAD7ULL,     0xBFEC7315899EAAD7ULL, 0x3FDD4CD02BA8609CULL,
    0x3FE86C0A1D9AA195ULL, 0x3FE4AD79516722F0ULL,     0xBFE4AD79516722F1ULL, 0x3FE86C0A1D9AA195ULL,
    0x3FB52E774A4D4D12ULL, 0x3FEFE3E92BE9D886ULL,     0xBFEFE3E92BE9D886ULL, 0x3FB52E774A4D4D06ULL,
    0x3FEFEF0102826191ULL, 0x3FB07B614E463064ULL,     0xBFB07B614E463057ULL, 0x3FEFEF0102826191ULL,
    0x3FE51FA81CD99AA6ULL, 0x3FE8098B756E52FAULL,     0xBFE8098B756E52FBULL, 0x3FE51FA81CD99AA6ULL,
    0x3FECB6E20A00DA99ULL, 0x3FDC3F6D47263129ULL,     0xBFDC3F6D4726312AULL, 0x3FECB6E20A00DA99ULL,
    0x3FD4A253D11B82F6ULL, 0x3FEE4A8DFF81CE5EULL,     0xBFEE4A8DFF81CE5EULL, 0x3FD4A253D11B82F3ULL,
    0x3FEEEB074C50A544ULL, 0x3FD0804E05EB661EULL,     0xBFD0804E05EB661BULL, 0x3FEEEB074C50A545ULL,
    0x3FE00740C82B82E2ULL, 0x3FEBB249A0B6C40CULL,     0xBFEBB249A0B6C40CULL, 0x3FE00740C82B82E2ULL,
    0x3FE9683F42BD7FE1ULL, 0x3FE374531B817F8DULL,     0xBFE374531B817F8CULL, 0x3FE9683F42BD7FE2ULL,
    0x3FC0D64DBCB2678CULL, 0x3FEFB8D18D66ADB7ULL,     0xBFEFB8D18D66ADB7ULL, 0x3FC0D64DBCB2678EULL,
    0x3FEF93F14F85AC08ULL, 0x3FC4B8B17F79FA88ULL,     0xBFC4B8B17F79FA86ULL, 0x3FEF93F14F85AC08ULL,
    0x3FE2AA76E87AEB58ULL, 0x3FE9FDF4F13149DEULL,     0xBFE9FDF4F13149DDULL, 0x3FE2AA76E87AEB5AULL,
    0x3FEB3115A5F37BF4ULL, 0x3FE0DED0B84BC4B5ULL,     0xBFE0DED0B84BC4B3ULL, 0x3FEB3115A5F37BF5ULL,
    0x3FCD31774D2CBDF0ULL, 0x3FEF2817FC4609CDULL,     0xBFEF2817FC4609CDULL, 0x3FCD31774D2CBDFAULL,
    0x3FEDF5E36A9BA59CULL, 0x3FD67B949CAD63CAULL,     0xBFD67B949CAD63C9ULL, 0x3FEDF5E36A9BA59CULL,
    0x3FDA790CD3DBF31BULL, 0x3FED2255C6E5A4E0ULL,     0xBFED2255C6E5A4E0ULL, 0x3FDA790CD3DBF31CULL,
    0x3FE760C52C304764ULL, 0x3FE5D9DEE73E345CULL,     0xBFE5D9DEE73E345BULL, 0x3FE760C52C304764ULL,
    0x3FA14685DB42C187ULL, 0x3FEFFB55E425FDAEULL,     0xBFEFFB55E425FDAEULL, 0x3FA14685DB42C190ULL,
    0x3FEFF97C4208C014ULL, 0x3FA46A396FF86179ULL,     0xBFA46A396FF8616DULL, 0x3FEFF97C4208C014ULL,
    0x3FE5B50B264F7449ULL, 0x3FE782FB1B90B35AULL,     0xBFE782FB1B90B35BULL, 0x3FE5B50B264F7447ULL,
    0x3FED0D672F59D2B9ULL, 0x3FDAD473125CDC08ULL,     0xBFDAD473125CDC0BULL, 0x3FED0D672F59D2B8ULL,
    0x3FD61D595C88C204ULL, 0x3FEE0766D9280F54ULL,     0xBFEE0766D9280F55ULL, 0x3FD61D595C88C201ULL,
    0x3FEF1C7ABE284708ULL, 0x3FCDF5163F01099AULL,     0xBFCDF5163F010996ULL, 0x3FEF1C7ABE284709ULL,
    0x3FE0B405878F85ECULL, 0x3FEB4B7409DE7925ULL,     0xBFEB4B7409DE7925ULL, 0x3FE0B405878F85EDULL,
    0x3FE9E082EDB42472ULL, 0x3FE2D333D34E9BB7ULL,     0xBFE2D333D34E9BB7ULL, 0x3FE9E082EDB42473ULL,
    0x3FC3F22F57DB4896ULL, 0x3FEF9BED7CFBDE29ULL,     0xBFEF9BED7CFBDE29ULL, 0x3FC3F22F57DB4898ULL,
    0x3FEFB20DC681D54DULL, 0x3FC19D8940BE24E7ULL,     0xBFC19D8940BE24E8ULL, 0x3FEFB20DC681D54CULL,
    0x3FE34C5252C14DE2ULL, 0x3FE986AEF1457593ULL,     0xBFE986AEF1457592ULL, 0x3FE34C5252C14DE3ULL,
    0x3FEB98FA1FD9155FULL, 0x3FE032AE55EDBD95ULL,     0xBFE032AE55EDBD94ULL, 0x3FEB98FA1FD9155FULL,
    0x3FD01F1806B9FDD1ULL, 0x3FEEF7D6E51CA3C0ULL,     0xBFEEF7D6E51CA3BFULL, 0x3FD01F1806B9FDD6ULL,
    0x3FEE3A33EC75CE85ULL, 0x3FD50163DC197047ULL,     0xBFD50163DC197048ULL, 0x3FEE3A33EC75CE85ULL,
    0x3FDBE51517FFC0D9ULL, 0x3FECCCEE20C2DEA0ULL,     0xBFECCCEE20C2DE9FULL, 0x3FDBE51517FFC0DAULL,
    0x3FE7E83F87B03686ULL, 0x3FE5454FF5159DFBULL,     0xBFE5454FF5159DFCULL, 0x3FE7E83F87B03686ULL,
    0x3FADD406F9808EC5ULL, 0x3FEFF21614E131EDULL,     0xBFEFF21614E131EDULL, 0x3FADD406F9808ECEULL,
    0x3FEFDF9922F73307ULL, 0x3FB6BF1B3E79B129ULL,     0xBFB6BF1B3E79B126ULL, 0x3FEFDF9922F73307ULL,
    0x3FE48703306091FFULL, 0x3FE88C66E7481BA1ULL,     0xBFE88C66E7481BA0ULL, 0x3FE48703306091FFULL,
    0x3FEC5BEF59FEF85AULL, 0x3FDDA60C5CFA10D8ULL,     0xBFDDA60C5CFA10D8ULL, 0x3FEC5BEF59FEF85AULL,
    0x3FD3241FB638BAAFULL, 0x3FEE89095BAD6025ULL,     0xBFEE89095BAD6024ULL, 0x3FD3241FB638BAB0ULL,
    0x3FEEB4CF515B8811ULL, 0x3FD2038583D727BDULL,     0xBFD2038583D727BDULL, 0x3FEEB4CF515B8811ULL,
    0x3FDEB00695F25620ULL, 0x3FEC14D9DC465E57ULL,     0xBFEC14D9DC465E56ULL, 0x3FDEB00695F25625ULL,
    0x3FE8EC109B486C49ULL, 0x3FE41272663D108CULL,     0xBFE41272663D108AULL, 0x3FE8EC109B486C4AULL,
    0x3FBB6FA6EC38F64EULL, 0x3FEFD0D158D86087ULL,     0xBFEFD0D158D86087ULL, 0x3FBB6FA6EC38F663ULL,
    0x3FEF70F6434B7EB7ULL, 0x3FC7D0A7BBD2CB1BULL,     0xBFC7D0A7BBD2CB16ULL, 0x3FEF70F6434B7EB7ULL,
    0x3FE205BAA17560D6ULL, 0x3FEA7138DE9D60F4ULL,     0xBFEA7138DE9D60F5ULL, 0x3FE205BAA17560D6ULL,
    0x3FEAC4FFBD3EFAC8ULL, 0x3FE188591F3A46E5ULL,     0xBFE188591F3A46E5ULL, 0x3FEAC4FFBD3EFAC8ULL,
    0x3FCA203E1B1831DFULL, 0x3FEF538B1FAF2D07ULL,     0xBFEF538B1FAF2D07ULL, 0x3FCA203E1B1831D9ULL,
    0x3FEDACF42CE68AB9ULL, 0x3FD7F24DD37341E3ULL,     0xBFD7F24DD37341E2ULL, 0x3FEDACF42CE68AB9ULL,
    0x3FD908EF81EF7BD3ULL, 0x3FED733F508C0DFEULL,     0xBFED733F508C0DFEULL, 0x3FD908EF81EF7BD4ULL,
    0x3FE6D5AFEF4AAFCDULL, 0x3FE66B0F3F52B386ULL,     0xBFE66B0F3F52B385ULL, 0x3FE6D5AFEF4AAFCEULL,
    0x3F82D96B0E509754ULL, 0x3FEFFFA72C978C4FULL,     0xBFEFFFA72C978C4FULL, 0x3F82D96B0E509777ULL,
    0x3FEFFFA72C978C4FULL, 0x3F82D96B0E509703ULL,     0xBF82D96B0E50970DULL, 0x3FEFFFA72C978C4FULL,
    0x3FE66B0F3F52B387ULL, 0x3FE6D5AFEF4AAFCCULL,     0xBFE6D5AFEF4AAFCDULL, 0x3FE66B0F3F52B386ULL,
    0x3FED733F508C0DFFULL, 0x3FD908EF81EF7BD1ULL,     0xBFD908EF81EF7BD1ULL, 0x3FED733F508C0DFFULL,
    0x3FD7F24DD37341E4ULL, 0x3FEDACF42CE68AB9ULL,     0xBFEDACF42CE68AB9ULL, 0x3FD7F24DD37341E5ULL,
    0x3FEF538B1FAF2D07ULL, 0x3FCA203E1B1831DAULL,     0xBFCA203E1B1831DBULL, 0x3FEF538B1FAF2D07ULL,
    0x3FE188591F3A46E5ULL, 0x3FEAC4FFBD3EFAC7ULL,     0xBFEAC4FFBD3EFAC7ULL, 0x3FE188591F3A46E7ULL,
    0x3FEA7138DE9D60F5ULL, 0x3FE205BAA17560D6ULL,     0xBFE205BAA17560D5ULL, 0x3FEA7138DE9D60F6ULL,
    0x3FC7D0A7BBD2CB1BULL, 0x3FEF70F6434B7EB7ULL,     0xBFEF70F6434B7EB7ULL, 0x3FC7D0A7BBD2CB25ULL,
    0x3FEFD0D158D86087ULL, 0x3FBB6FA6EC38F64CULL,     0xBFBB6FA6EC38F646ULL, 0x3FEFD0D158D86087ULL,
    0x3FE41272663D108DULL, 0x3FE8EC109B486C48ULL,     0xBFE8EC109B486C49ULL, 0x3FE41272663D108CULL,
    0x3FEC14D9DC465E58ULL, 0x3FDEB00695F25620ULL,     0xBFDEB00695F25622ULL, 0x3FEC14D9DC465E57ULL,
    0x3FD2038583D727BFULL, 0x3FEEB4CF515B8811ULL,     0xBFEEB4CF515B8811ULL, 0x3FD2038583D727BCULL,
    0x3FEE89095BAD6025ULL, 0x3FD3241FB638BAAFULL,     0xBFD3241FB638BAADULL, 0x3FEE89095BAD6025ULL,
    0x3FDDA60C5CFA10DAULL, 0x3FEC5BEF59FEF85AULL,     0xBFEC5BEF59FEF859ULL, 0x3FDDA60C5CFA10DBULL,
    0x3FE88C66E7481BA1ULL, 0x3FE48703306091FFULL,     0xBFE48703306091FEULL, 0x3FE88C66E7481BA2ULL,
    0x3FB6BF1B3E79B12FULL, 0x3FEFDF9922F73307ULL,     0xBFEFDF9922F73307ULL, 0x3FB6BF1B3E79B134ULL,
    0x3FEFF21614E131EDULL, 0x3FADD406F9808EC8ULL,     0xBFADD406F9808EB3ULL, 0x3FEFF21614E131EDULL,
    0x3FE5454FF5159DFCULL, 0x3FE7E83F87B03686ULL,     0xBFE7E83F87B03685ULL, 0x3FE5454FF5159DFDULL,
    0x3FECCCEE20C2DEA0ULL, 0x3FDBE51517FFC0D9ULL,     0xBFDBE51517FFC0D7ULL, 0x3FECCCEE20C2DEA0ULL,
    0x3FD50163DC19704AULL, 0x3FEE3A33EC75CE85ULL,     0xBFEE3A33EC75CE84ULL, 0x3FD50163DC19704BULL,
    0x3FEEF7D6E51CA3C0ULL, 0x3FD01F1806B9FDD2ULL,     0xBFD01F1806B9FDCFULL, 0x3FEEF7D6E51CA3C0ULL,
    0x3FE032AE55EDBD97ULL, 0x3FEB98FA1FD9155EULL,     0xBFEB98FA1FD9155EULL, 0x3FE032AE55EDBD95ULL,
    0x3FE986AEF1457594ULL, 0x3FE34C5252C14DE1ULL,     0xBFE34C5252C14DE2ULL, 0x3FE986AEF1457593ULL,
    0x3FC19D8940BE24ECULL, 0x3FEFB20DC681D54CULL,     0xBFEFB20DC681D54DULL, 0x3FC19D8940BE24E7ULL,
    0x3FEF9BED7CFBDE29ULL, 0x3FC3F22F57DB4893ULL,     0xBFC3F22F57DB4892ULL, 0x3FEF9BED7CFBDE29ULL,
    0x3FE2D333D34E9BB8ULL, 0x3FE9E082EDB42472ULL,     0xBFE9E082EDB42472ULL, 0x3FE2D333D34E9BB8ULL,
    0x3FEB4B7409DE7925ULL, 0x3FE0B405878F85ECULL,     0xBFE0B405878F85EBULL, 0x3FEB4B7409DE7926ULL,
    0x3FCDF5163F01099BULL, 0x3FEF1C7ABE284708ULL,     0xBFEF1C7ABE284708ULL, 0x3FCDF5163F01099DULL,
    0x3FEE0766D9280F54ULL, 0x3FD61D595C88C203ULL,     0xBFD61D595C88C202ULL, 0x3FEE0766D9280F55ULL,
    0x3FDAD473125CDC09ULL, 0x3FED0D672F59D2B8ULL,     0xBFED0D672F59D2B7ULL, 0x3FDAD473125CDC0EULL,
    0x3FE782FB1B90B35BULL, 0x3FE5B50B264F7448ULL,     0xBFE5B50B264F7446ULL, 0x3FE782FB1B90B35CULL,
    0x3FA46A396FF8617EULL, 0x3FEFF97C4208C014ULL,     0xBFEFF97C4208C014ULL, 0x3FA46A396FF861A7ULL,
    0x3FEFFB55E425FDAEULL, 0x3FA14685DB42C17EULL,     0xBFA14685DB42C175ULL, 0x3FEFFB55E425FDAEULL,
    0x3FE5D9DEE73E345CULL, 0x3FE760C52C304764ULL,     0xBFE760C52C304763ULL, 0x3FE5D9DEE73E345DULL,
    0x3FED2255C6E5A4E1ULL, 0x3FDA790CD3DBF31AULL,     0xBFDA790CD3DBF319ULL, 0x3FED2255C6E5A4E1ULL,
    0x3FD67B949CAD63CBULL, 0x3FEDF5E36A9BA59CULL,     0xBFEDF5E36A9BA59CULL, 0x3FD67B949CAD63CCULL,
    0x3FEF2817FC4609CEULL, 0x3FCD31774D2CBDEEULL,     0xBFCD31774D2CBDECULL, 0x3FEF2817FC4609CEULL,
    0x3FE0DED0B84BC4B6ULL, 0x3FEB3115A5F37BF3ULL,     0xBFEB3115A5F37BF4ULL, 0x3FE0DED0B84BC4B5ULL,
    0x3FE9FDF4F13149DEULL, 0x3FE2AA76E87AEB58ULL,     0xBFE2AA76E87AEB59ULL, 0x3FE9FDF4F13149DEULL,
    0x3FC4B8B17F79FA8AULL, 0x3FEF93F14F85AC07ULL,     0xBFEF93F14F85AC08ULL, 0x3FC4B8B17F79FA85ULL,
    0x3FEFB8D18D66ADB7ULL, 0x3FC0D64DBCB26786ULL,     0xBFC0D64DBCB26787ULL, 0x3FEFB8D18D66ADB7ULL,
    0x3FE374531B817F8EULL, 0x3FE9683F42BD7FE1ULL,     0xBFE9683F42BD7FE1ULL, 0x3FE374531B817F8DULL,
    0x3FEBB249A0B6C40DULL, 0x3FE00740C82B82E0ULL,     0xBFE00740C82B82E1ULL, 0x3FEBB249A0B6C40DULL,
    0x3FD0804E05EB661DULL, 0x3FEEEB074C50A545ULL,     0xBFEEEB074C50A544ULL, 0x3FD0804E05EB661EULL,
    0x3FEE4A8DFF81CE5EULL, 0x3FD4A253D11B82F3ULL,     0xBFD4A253D11B82F3ULL, 0x3FEE4A8DFF81CE5EULL,
    0x3FDC3F6D47263128ULL, 0x3FECB6E20A00DA99ULL,     0xBFECB6E20A00DA98ULL, 0x3FDC3F6D4726312DULL,
    0x3FE8098B756E52FBULL, 0x3FE51FA81CD99AA6ULL,     0xBFE51FA81CD99AA5ULL, 0x3FE8098B756E52FCULL,
    0x3FB07B614E463060ULL, 0x3FEFEF0102826191ULL,     0xBFEFEF0102826191ULL, 0x3FB07B614E463075ULL,
    0x3FEFE3E92BE9D886ULL, 0x3FB52E774A4D4D0AULL,     0xBFB52E774A4D4D09ULL, 0x3FEFE3E92BE9D886ULL,
    0x3FE4AD79516722F1ULL, 0x3FE86C0A1D9AA195ULL,     0xBFE86C0A1D9AA193ULL, 0x3FE4AD79516722F3ULL,
    0x3FEC7315899EAAD7ULL, 0x3FDD4CD02BA8609CULL,     0xBFDD4CD02BA86099ULL, 0x3FEC7315899EAAD8ULL,
    0x3FD383F5E353B6ABULL, 0x3FEE79DB29A5165AULL,     0xBFEE79DB29A51659ULL, 0x3FD383F5E353B6AFULL,
    0x3FEEC2CF4B1AF6B2ULL, 0x3FD1A2F7FBE8F243ULL,     0xBFD1A2F7FBE8F243ULL, 0x3FEEC2CF4B1AF6B2ULL,
    0x3FDF081906BFF7FEULL, 0x3FEBFC9D25A1B147ULL,     0xBFEBFC9D25A1B147ULL, 0x3FDF081906BFF7FEULL,
    0x3FE90B7943575EFEULL, 0x3FE3EB33EABE0680ULL,     0xBFE3EB33EABE0680ULL, 0x3FE90B7943575EFEULL,
    0x3FBCFF533B307DC2ULL, 0x3FEFCB4703914354ULL,     0xBFEFCB4703914354ULL, 0x3FBCFF533B307DC6ULL,
    0x3FEF7A299C1A322AULL, 0x3FC70AFD8D08C4FFULL,     0xBFC70AFD8D08C4FBULL, 0x3FEF7A299C1A322AULL,
    0x3FE22F2D662C13E1ULL, 0x3FEA54C91090F523ULL,     0xBFEA54C91090F522ULL, 0x3FE22F2D662C13E3ULL,
    0x3FEAE068F345ECEFULL, 0x3FE15E36E4DBE2BCULL,     0xBFE15E36E4DBE2BBULL, 0x3FEAE068F345ECF0ULL,
    0x3FCAE4F1D5F3B9AFULL, 0x3FEF492206BCABB4ULL,     0xBFEF492206BCABB4ULL, 0x3FCAE4F1D5F3B9B2ULL,
    0x3FEDBF9E4395759BULL, 0x3FD794F5E613DFAEULL,     0xBFD794F5E613DFACULL, 0x3FEDBF9E4395759BULL,
    0x3FD96555B7AB9491ULL, 0x3FED5F7172888A7EULL,     0xBFED5F7172888A7FULL, 0x3FD96555B7AB948EULL,
    0x3FE6F8CA99C95B75ULL, 0x3FE64715437F535BULL,     0xBFE64715437F535BULL, 0x3FE6F8CA99C95B75ULL,
    0x3F8F6A296AB9980FULL, 0x3FEFFF0943C53BD1ULL,     0xBFEFFF0943C53BD1ULL, 0x3F8F6A296AB997B3ULL,
    0x3FEFFE1C6870CB77ULL, 0x3F95FD4D21FAB226ULL,     0xBF95FD4D21FAB21FULL, 0x3FEFFE1C6870CB77ULL,
    0x3FE622E44FEC22FFULL, 0x3FE71BAC960E41BFULL,     0xBFE71BAC960E41BEULL, 0x3FE622E44FEC2300ULL,
    0x3FED4B5B1B187524ULL, 0x3FD9C17D440DF9F2ULL,     0xBFD9C17D440DF9F2ULL, 0x3FED4B5B1B187524ULL,
    0x3FD73763C9261092ULL, 0x3FEDD1FEF38A915AULL,     0xBFEDD1FEF38A9159ULL, 0x3FD73763C9261093ULL,
    0x3FEF3E6BBC1BBC65ULL, 0x3FCBA96334F15DADULL,     0xBFCBA96334F15DACULL, 0x3FEF3E6BBC1BBC65ULL,
    0x3FE133E9CFEE254FULL, 0x3FEAFB8FD89F57B6ULL,     0xBFEAFB8FD89F57B5ULL, 0x3FE133E9CFEE2551ULL,
    0x3FEA38184A593BC5ULL, 0x3FE258734CBB7110ULL,     0xBFE258734CBB710EULL, 0x3FEA38184A593BC7ULL,
    0x3FC6451A831D830EULL, 0x3FEF830F4A40C60CULL,     0xBFEF830F4A40C60CULL, 0x3FC6451A831D8318ULL,
    0x3FEFC56E3B7D9AF6ULL, 0x3FBE8EB7FDE4AA3EULL,     0xBFBE8EB7FDE4AA35ULL, 0x3FEFC56E3B7D9AF6ULL,
    0x3FE3C3C44981C518ULL, 0x3FE92AA41FC5A815ULL,     0xBFE92AA41FC5A815ULL, 0x3FE3C3C44981C517ULL,
    0x3FEBE41B611154C0ULL, 0x3FDF5FDEE656CDA3ULL,     0xBFDF5FDEE656CDA4ULL, 0x3FEBE41B611154C0ULL,
    0x3FD1423EEFC6937AULL, 0x3FEED0835E999009ULL,     0xBFEED0835E999009ULL, 0x3FD1423EEFC69378ULL,
    0x3FEE6A61C55D53A7ULL, 0x3FD3E39BE96EC271ULL,     0xBFD3E39BE96EC26FULL, 0x3FEE6A61C55D53A8ULL,
    0x3FDCF34BAEE1CD23ULL, 0x3FEC89F587029C13ULL,     0xBFEC89F587029C12ULL, 0x3FDCF34BAEE1CD24ULL,
    0x3FE84B7111AF83FAULL, 0x3FE4D3BC6D589F7FULL,     0xBFE4D3BC6D589F7EULL, 0x3FE84B7111AF83FBULL,
    0x3FB39D9F12C5A2A2ULL, 0x3FEFE7EA85482D60ULL,     0xBFEFE7EA85482D60ULL, 0x3FB39D9F12C5A2A7ULL,
    0x3FEFEB9D2530410FULL, 0x3FB20C9674ED444CULL,     0xBFB20C9674ED444FULL, 0x3FEFEB9D2530410FULL,
    0x3FE4F9CC25CCA487ULL, 0x3FE82A9C13F545FFULL,     0xBFE82A9C13F545FEULL, 0x3FE4F9CC25CCA488ULL,
    0x3FECA08F19B9C449ULL, 0x3FDC997FC3865388ULL,     0xBFDC997FC3865385ULL, 0x3FECA08F19B9C44AULL,
    0x3FD44310DC8936F0ULL, 0x3FEE5A9D550467D3ULL,     0xBFEE5A9D550467D3ULL, 0x3FD44310DC8936F4ULL,
    0x3FEEDDEB6A078651ULL, 0x3FD0E15B4E1749CDULL,     0xBFD0E15B4E1749CEULL, 0x3FEEDDEB6A078651ULL,
    0x3FDFB7575C24D2DDULL, 0x3FEBCB54CB0D2327ULL,     0xBFEBCB54CB0D2327ULL, 0x3FDFB7575C24D2DEULL,
    0x3FE94990E3AC4A6CULL, 0x3FE39C23E3D63029ULL,     0xBFE39C23E3D63029ULL, 0x3FE94990E3AC4A6CULL,
    0x3FC00EE8AD6FB85AULL, 0x3FEFBF470F0A8D88ULL,     0xBFEFBF470F0A8D88ULL, 0x3FC00EE8AD6FB85CULL,
    0x3FEF8BA737CB4B78ULL, 0x3FC57F008654CBDEULL,     0xBFC57F008654CBDBULL, 0x3FEF8BA737CB4B78ULL,
    0x3FE2818BEF4D3CBAULL, 0x3FEA1B26D2C0A75EULL,     0xBFEA1B26D2C0A75DULL, 0x3FE2818BEF4D3CBBULL,
    0x3FEB16742A4CA2F5ULL, 0x3FE1097248D0A956ULL,     0xBFE1097248D0A956ULL, 0x3FEB16742A4CA2F5ULL,
    0x3FCC6D90535D74DFULL, 0x3FEF33685A3AAEF0ULL,     0xBFEF33685A3AAEF0ULL, 0x3FCC6D90535D74E1ULL,
    0x3FEDE4160F6D8D82ULL, 0x3FD6D998638A0CB5ULL,     0xBFD6D998638A0CB4ULL, 0x3FEDE4160F6D8D82ULL,
    0x3FDA1D6543B50AC1ULL, 0x3FED36FC7BCBFBDBULL,     0xBFED36FC7BCBFBDCULL, 0x3FDA1D6543B50ABEULL,
    0x3FE73E558E079942ULL, 0x3FE5FE7CBDE56A0FULL,     0xBFE5FE7CBDE56A10ULL, 0x3FE73E558E079941ULL,
    0x3F9C454F4CE53B33ULL, 0x3FEFFCE09CE2A679ULL,     0xBFEFFCE09CE2A679ULL, 0x3F9C454F4CE53B05ULL,
    0x3FEFF753BB1B9164ULL, 0x3FA78DBAA5874685ULL,     0xBFA78DBAA5874676ULL, 0x3FEFF753BB1B9164ULL,
    0x3FE59001D5F723E0ULL, 0x3FE7A4F707BF97D2ULL,     0xBFE7A4F707BF97D1ULL, 0x3FE59001D5F723E0ULL,
    0x3FECF830E8CE467BULL, 0x3FDB2F971DB31972ULL,     0xBFDB2F971DB31970ULL, 0x3FECF830E8CE467BULL,
    0x3FD5BEE78B9DB3B8ULL, 0x3FEE18A02FDC66D9ULL,     0xBFEE18A02FDC66D9ULL, 0x3FD5BEE78B9DB3B9ULL,
    0x3FEF1090BC898F5FULL, 0x3FCEB86B462DE348ULL,     0xBFCEB86B462DE344ULL, 0x3FEF1090BC898F5FULL,
    0x3FE089112032B08DULL, 0x3FEB658F14FDBC47ULL,     0xBFEB658F14FDBC47ULL, 0x3FE089112032B08BULL,
    0x3FE9C2D110F075C3ULL, 0x3FE2FBC24B441015ULL,     0xBFE2FBC24B441016ULL, 0x3FE9C2D110F075C2ULL,
    0x3FC32B7BF94516ABULL, 0x3FEFA39BAC7A1791ULL,     0xBFEFA39BAC7A1791ULL, 0x3FC32B7BF94516A5ULL,
    0x3FEFAAFBCB0CFDDCULL, 0x3FC264994DFD340AULL,     0xBFC264994DFD3409ULL, 0x3FEFAAFBCB0CFDDCULL,
    0x3FE32421EC49A620ULL, 0x3FE9A4DFA42B06B1ULL,     0xBFE9A4DFA42B06B2ULL, 0x3FE32421EC49A620ULL,
    0x3FEB7F6686E792EAULL, 0x3FE05DF3EC31B8B6ULL,     0xBFE05DF3EC31B8B7ULL, 0x3FEB7F6686E792E9ULL,
    0x3FCF7B7480BD3801ULL, 0x3FEF045A14CF738CULL,     0xBFEF045A14CF738BULL, 0x3FCF7B7480BD3803ULL,
    0x3FEE298F4439197AULL, 0x3FD5604012F467B4ULL,     0xBFD5604012F467B4ULL, 0x3FEE298F4439197AULL,
    0x3FDB8A7814FD5693ULL, 0x3FECE2B32799A060ULL,     0xBFECE2B32799A05FULL, 0x3FDB8A7814FD5698ULL,
    0x3FE7C6B89CE2D333ULL, 0x3FE56AC35197649EULL,     0xBFE56AC35197649DULL, 0x3FE7C6B89CE2D334ULL,
    0x3FAAB101BD5F8316ULL, 0x3FEFF4DC54B1BED3ULL,     0xBFEFF4DC54B1BED2ULL, 0x3FAAB101BD5F833EULL,
    0x3FEFDAFA7514538CULL, 0x3FB84F8712C130A0ULL,     0xBFB84F8712C1309DULL, 0x3FEFDAFA7514538CULL,
    0x3FE4605A692B32A2ULL, 0x3FE8AC871EDE1D87ULL,     0xBFE8AC871EDE1D86ULL, 0x3FE4605A692B32A4ULL,
    0x3FEC44833141C004ULL, 0x3FDDFEFF66A941DDULL,     0xBFDDFEFF66A941D9ULL, 0x3FEC44833141C005ULL,
    0x3FD2C41A4E954521ULL, 0x3FEE97EC36016B30ULL,     0xBFEE97EC36016B2FULL, 0x3FD2C41A4E954526ULL,
    0x3FEEA68393E65800ULL, 0x3FD263E6995554BAULL,     0xBFD263E6995554B9ULL, 0x3FEEA68393E65800ULL,
    0x3FDE57A86D3CD825ULL, 0x3FEC2CD14931E3F1ULL,     0xBFEC2CD14931E3F1ULL, 0x3FDE57A86D3CD826ULL,
    0x3FE8CC6A75184655ULL, 0x3FE4397F5B2A4380ULL,     0xBFE4397F5B2A437FULL, 0x3FE8CC6A75184655ULL,
    0x3FB9DFB6EB24A860ULL, 0x3FEFD60D2DA75C9EULL,     0xBFEFD60D2DA75C9EULL, 0x3FB9DFB6EB24A864ULL,
    0x3FEF677556883CEEULL, 0x3FC8961727C41804ULL,     0xBFC8961727C417FEULL, 0x3FEF677556883CEEULL,
    0x3FE1DC1B64DC4872ULL, 0x3FEA8D676E545AD2ULL,     0xBFEA8D676E545AD1ULL, 0x3FE1DC1B64DC4874ULL,
    0x3FEAA9547A2CB98EULL, 0x3FE1B250171373BEULL,     0xBFE1B250171373BDULL, 0x3FEAA9547A2CB98FULL,
    0x3FC95B49E9B62AFFULL, 0x3FEF5DA6ED43685CULL,     0xBFEF5DA6ED43685CULL, 0x3FC95B49E9B62B02ULL,
    0x3FED9A00DD8B3D46ULL, 0x3FD84F6AAAF3903FULL,     0xBFD84F6AAAF3903CULL, 0x3FED9A00DD8B3D47ULL,
    0x3FD8AC4B86D5ED47ULL, 0x3FED86C48445A44FULL,     0xBFED86C48445A450ULL, 0x3FD8AC4B86D5ED44ULL,
    0x3FE6B25CED2FE29CULL, 0x3FE68ED1EAA19C71ULL,     0xBFE68ED1EAA19C71ULL, 0x3FE6B25CED2FE29BULL,
    0x3F6921F8BECCA62FULL, 0x3FEFFFF621621D02ULL,     0xBFEFFFF621621D02ULL, 0x3F6921F8BECCA4BCULL,
};

#if !defined(WOLFSSL_FALCON_FFT_AVX2) && !defined(WOLFSSL_FALCON_FFT_NEON)
/* When the AVX2 or NEON backend is selected, falcon_FFT/falcon_iFFT are
 * provided by the folded SIMD block at the end of this file instead; the
 * twiddle table above is still shared. */

/* In-place forward FFT: coefficient representation -> FFT representation. */
void falcon_FFT(fpr* f, unsigned logn)
{
    unsigned u;
    size_t t, n, hn, m;

    n = (size_t)1 << logn;
    hn = n >> 1;
    t = hn;
    for (u = 1, m = 2; u < logn; u++, m <<= 1) {
        size_t ht = t >> 1, hm = m >> 1, i1, j1;
        for (i1 = 0, j1 = 0; i1 < hm; i1++, j1 += t) {
            size_t j, j2 = j1 + ht;
            fpr s_re = falcon_gm_tab[((m + i1) << 1) + 0];
            fpr s_im = falcon_gm_tab[((m + i1) << 1) + 1];
            for (j = j1; j < j2; j++) {
                fpr x_re = f[j], x_im = f[j + hn];
                fpr y_re = f[j + ht], y_im = f[j + ht + hn];
                FPC_MUL(y_re, y_im, y_re, y_im, s_re, s_im);
                FPC_ADD(f[j], f[j + hn], x_re, x_im, y_re, y_im);
                FPC_SUB(f[j + ht], f[j + ht + hn], x_re, x_im, y_re, y_im);
            }
        }
        t = ht;
    }
}

/* In-place inverse FFT: exact reversal of falcon_FFT, then scale by 2^-(logn-1).
 * Each inverse butterfly is (a+b) and (a-b)*conj(s). */
void falcon_iFFT(fpr* f, unsigned logn)
{
    int u;
    size_t n = (size_t)1 << logn, hn = n >> 1;

    for (u = (int)logn - 1; u >= 1; u--) {
        size_t m = (size_t)1 << u, hm = m >> 1;
        size_t t = hn >> u;             /* butterfly stride */
        size_t i1, j1;
        for (i1 = 0, j1 = 0; i1 < hm; i1++, j1 += (t << 1)) {
            size_t j, j2 = j1 + t;
            fpr s_re = falcon_gm_tab[((m + i1) << 1) + 0];
            fpr s_im = fpr_neg(falcon_gm_tab[((m + i1) << 1) + 1]);
            for (j = j1; j < j2; j++) {
                fpr a_re = f[j], a_im = f[j + hn];
                fpr b_re = f[j + t], b_im = f[j + t + hn];
                fpr d_re, d_im;
                FPC_ADD(f[j], f[j + hn], a_re, a_im, b_re, b_im);
                FPC_SUB(d_re, d_im, a_re, a_im, b_re, b_im);
                FPC_MUL(f[j + t], f[j + t + hn], d_re, d_im, s_re, s_im);
            }
        }
    }
    {
        fpr ni = fpr_inv(fpr_of((sword64)hn));   /* 1 / 2^(logn-1) (exact) */
        size_t j;
        for (j = 0; j < n; j++) {
            f[j] = fpr_mul(f[j], ni);
        }
    }
}

#endif /* !WOLFSSL_FALCON_FFT_AVX2 */




/* Complex helpers (temps make the macros alias-safe). */
#define FPC_ADD(d_re, d_im, a_re, a_im, b_re, b_im) do { \
        fpr _ar = (a_re), _ai = (a_im), _br = (b_re), _bi = (b_im); \
        (d_re) = fpr_add(_ar, _br); \
        (d_im) = fpr_add(_ai, _bi); \
    } while (0)
#define FPC_SUB(d_re, d_im, a_re, a_im, b_re, b_im) do { \
        fpr _ar = (a_re), _ai = (a_im), _br = (b_re), _bi = (b_im); \
        (d_re) = fpr_sub(_ar, _br); \
        (d_im) = fpr_sub(_ai, _bi); \
    } while (0)
#define FPC_MUL(d_re, d_im, a_re, a_im, b_re, b_im) do { \
        fpr _ar = (a_re), _ai = (a_im), _br = (b_re), _bi = (b_im); \
        (d_re) = fpr_sub(fpr_mul(_ar, _br), fpr_mul(_ai, _bi)); \
        (d_im) = fpr_add(fpr_mul(_ar, _bi), fpr_mul(_ai, _br)); \
    } while (0)
/* (a) / (b) for complex a,b. */
#define FPC_DIV(d_re, d_im, a_re, a_im, b_re, b_im) do { \
        fpr _ar = (a_re), _ai = (a_im), _br = (b_re), _bi = (b_im); \
        fpr _m = fpr_inv(fpr_add(fpr_mul(_br, _br), fpr_mul(_bi, _bi))); \
        _br = fpr_mul(_br, _m); \
        _bi = fpr_neg(fpr_mul(_bi, _m)); \
        (d_re) = fpr_sub(fpr_mul(_ar, _br), fpr_mul(_ai, _bi)); \
        (d_im) = fpr_add(fpr_mul(_ar, _bi), fpr_mul(_ai, _br)); \
    } while (0)

void falcon_poly_add(fpr* a, const fpr* b, unsigned logn)
{
#if defined(WOLFSSL_FALCON_FFT_AVX2)
    falcon_poly_add_avx2(a, b, logn);
#else
    size_t n = (size_t)1 << logn, u;
    for (u = 0; u < n; u++) {
        a[u] = fpr_add(a[u], b[u]);
    }
#endif
}

void falcon_poly_sub(fpr* a, const fpr* b, unsigned logn)
{
#if defined(WOLFSSL_FALCON_FFT_AVX2)
    falcon_poly_sub_avx2(a, b, logn);
#else
    size_t n = (size_t)1 << logn, u;
    for (u = 0; u < n; u++) {
        a[u] = fpr_sub(a[u], b[u]);
    }
#endif
}

void falcon_poly_neg(fpr* a, unsigned logn)
{
    size_t n = (size_t)1 << logn, u;
    for (u = 0; u < n; u++) {
        a[u] = fpr_neg(a[u]);
    }
}

void falcon_poly_adj_fft(fpr* a, unsigned logn)
{
    size_t n = (size_t)1 << logn, hn = n >> 1, u;
    for (u = hn; u < n; u++) {
        a[u] = fpr_neg(a[u]);
    }
}

void falcon_poly_mul_fft(fpr* a, const fpr* b, unsigned logn)
{
#if defined(WOLFSSL_FALCON_FFT_AVX2)
    falcon_poly_mul_fft_avx2(a, b, logn);
#else
    size_t n = (size_t)1 << logn, hn = n >> 1, u;
    for (u = 0; u < hn; u++) {
        fpr a_re = a[u], a_im = a[u + hn];
        fpr b_re = b[u], b_im = b[u + hn];
        FPC_MUL(a[u], a[u + hn], a_re, a_im, b_re, b_im);
    }
#endif
}

void falcon_poly_muladj_fft(fpr* a, const fpr* b, unsigned logn)
{
#if defined(WOLFSSL_FALCON_FFT_AVX2)
    falcon_poly_muladj_fft_avx2(a, b, logn);
#else
    size_t n = (size_t)1 << logn, hn = n >> 1, u;
    for (u = 0; u < hn; u++) {
        fpr a_re = a[u], a_im = a[u + hn];
        fpr b_re = b[u], b_im = fpr_neg(b[u + hn]);
        FPC_MUL(a[u], a[u + hn], a_re, a_im, b_re, b_im);
    }
#endif
}

void falcon_poly_mulselfadj_fft(fpr* a, unsigned logn)
{
#if defined(WOLFSSL_FALCON_FFT_AVX2)
    falcon_poly_mulselfadj_fft_avx2(a, logn);
#else
    /* a * adj(a) = |a|^2 (real). */
    size_t n = (size_t)1 << logn, hn = n >> 1, u;
    for (u = 0; u < hn; u++) {
        fpr a_re = a[u], a_im = a[u + hn];
        a[u] = fpr_add(fpr_mul(a_re, a_re), fpr_mul(a_im, a_im));
        a[u + hn] = fpr_zero;
    }
#endif
}

void falcon_poly_mulconst(fpr* a, fpr x, unsigned logn)
{
#if defined(WOLFSSL_FALCON_FFT_AVX2)
    falcon_poly_mulconst_avx2(a, x, logn);
#else
    size_t n = (size_t)1 << logn, u;
    for (u = 0; u < n; u++) {
        a[u] = fpr_mul(a[u], x);
    }
#endif
}

void falcon_poly_div_fft(fpr* a, const fpr* b, unsigned logn)
{
    size_t n = (size_t)1 << logn, hn = n >> 1, u;
    for (u = 0; u < hn; u++) {
        fpr a_re = a[u], a_im = a[u + hn];
        fpr b_re = b[u], b_im = b[u + hn];
        FPC_DIV(a[u], a[u + hn], a_re, a_im, b_re, b_im);
    }
}

void falcon_poly_invnorm2_fft(fpr* d, const fpr* a, const fpr* b, unsigned logn)
{
#if defined(WOLFSSL_FALCON_FFT_AVX2)
    falcon_poly_invnorm2_fft_avx2(d, a, b, logn);
#else
    size_t n = (size_t)1 << logn, hn = n >> 1, u;
    for (u = 0; u < hn; u++) {
        fpr a_re = a[u], a_im = a[u + hn];
        fpr b_re = b[u], b_im = b[u + hn];
        d[u] = fpr_inv(fpr_add(
            fpr_add(fpr_mul(a_re, a_re), fpr_mul(a_im, a_im)),
            fpr_add(fpr_mul(b_re, b_re), fpr_mul(b_im, b_im))));
    }
#endif
}

void falcon_poly_add_muladj_fft(fpr* d, const fpr* F, const fpr* G,
        const fpr* f, const fpr* g, unsigned logn)
{
#if defined(WOLFSSL_FALCON_FFT_AVX2)
    falcon_poly_add_muladj_fft_avx2(d, F, G, f, g, logn);
#else
    /* d = F*adj(f) + G*adj(g). */
    size_t n = (size_t)1 << logn, hn = n >> 1, u;
    for (u = 0; u < hn; u++) {
        fpr F_re = F[u], F_im = F[u + hn];
        fpr G_re = G[u], G_im = G[u + hn];
        fpr f_re = f[u], f_im = f[u + hn];
        fpr g_re = g[u], g_im = g[u + hn];
        fpr a_re, a_im, b_re, b_im;
        FPC_MUL(a_re, a_im, F_re, F_im, f_re, fpr_neg(f_im));
        FPC_MUL(b_re, b_im, G_re, G_im, g_re, fpr_neg(g_im));
        d[u] = fpr_add(a_re, b_re);
        d[u + hn] = fpr_add(a_im, b_im);
    }
#endif
}

void falcon_poly_mul_autoadj_fft(fpr* a, const fpr* b, unsigned logn)
{
    /* b is self-adjoint (real); only its lower half is meaningful. */
    size_t n = (size_t)1 << logn, hn = n >> 1, u;
    for (u = 0; u < hn; u++) {
        a[u] = fpr_mul(a[u], b[u]);
        a[u + hn] = fpr_mul(a[u + hn], b[u]);
    }
}

void falcon_poly_div_autoadj_fft(fpr* a, const fpr* b, unsigned logn)
{
    size_t n = (size_t)1 << logn, hn = n >> 1, u;
    for (u = 0; u < hn; u++) {
        fpr ib = fpr_inv(b[u]);
        a[u] = fpr_mul(a[u], ib);
        a[u + hn] = fpr_mul(a[u + hn], ib);
    }
}

void falcon_poly_LDL_fft(const fpr* g00, fpr* g01, fpr* g11, unsigned logn)
{
    size_t n = (size_t)1 << logn, hn = n >> 1, u;
    for (u = 0; u < hn; u++) {
        fpr g00_re = g00[u], g00_im = g00[u + hn];
        fpr g01_re = g01[u], g01_im = g01[u + hn];
        fpr g11_re = g11[u], g11_im = g11[u + hn];
        fpr mu_re, mu_im, xx_re, xx_im;
        FPC_DIV(mu_re, mu_im, g01_re, g01_im, g00_re, g00_im);
        FPC_MUL(xx_re, xx_im, mu_re, mu_im, g01_re, fpr_neg(g01_im));
        FPC_SUB(g11[u], g11[u + hn], g11_re, g11_im, xx_re, xx_im);
        g01[u] = mu_re;
        g01[u + hn] = fpr_neg(mu_im);
    }
}

void falcon_poly_LDLmv_fft(fpr* d11, fpr* l10, const fpr* g00, const fpr* g01,
        const fpr* g11, unsigned logn)
{
#if defined(WOLFSSL_FALCON_FFT_AVX2)
    falcon_poly_LDLmv_fft_avx2(d11, l10, g00, g01, g11, logn);
#else
    size_t n = (size_t)1 << logn, hn = n >> 1, u;
    for (u = 0; u < hn; u++) {
        fpr g00_re = g00[u], g00_im = g00[u + hn];
        fpr g01_re = g01[u], g01_im = g01[u + hn];
        fpr g11_re = g11[u], g11_im = g11[u + hn];
        fpr mu_re, mu_im, xx_re, xx_im;
        FPC_DIV(mu_re, mu_im, g01_re, g01_im, g00_re, g00_im);
        FPC_MUL(xx_re, xx_im, mu_re, mu_im, g01_re, fpr_neg(g01_im));
        FPC_SUB(d11[u], d11[u + hn], g11_re, g11_im, xx_re, xx_im);
        l10[u] = mu_re;
        l10[u + hn] = fpr_neg(mu_im);
    }
#endif
}

void falcon_poly_split_fft(fpr* f0, fpr* f1, const fpr* f, unsigned logn)
{
#if defined(WOLFSSL_FALCON_FFT_AVX2)
    falcon_poly_split_fft_avx2(f0, f1, f, logn);
#else
    size_t n = (size_t)1 << logn, hn = n >> 1, qn = hn >> 1, u;
    /* Base case (logn==1, qn==0): single coefficient halves. */
    f0[0] = f[0];
    f1[0] = f[hn];
    for (u = 0; u < qn; u++) {
        fpr a_re = f[(u << 1) + 0], a_im = f[(u << 1) + 0 + hn];
        fpr b_re = f[(u << 1) + 1], b_im = f[(u << 1) + 1 + hn];
        fpr t_re, t_im;
        FPC_ADD(t_re, t_im, a_re, a_im, b_re, b_im);
        f0[u] = fpr_half(t_re);
        f0[u + qn] = fpr_half(t_im);
        FPC_SUB(t_re, t_im, a_re, a_im, b_re, b_im);
        FPC_MUL(t_re, t_im, t_re, t_im,
            falcon_gm_tab[((u + hn) << 1) + 0],
            fpr_neg(falcon_gm_tab[((u + hn) << 1) + 1]));
        f1[u] = fpr_half(t_re);
        f1[u + qn] = fpr_half(t_im);
    }
#endif
}

void falcon_poly_merge_fft(fpr* f, const fpr* f0, const fpr* f1, unsigned logn)
{
#if defined(WOLFSSL_FALCON_FFT_AVX2)
    falcon_poly_merge_fft_avx2(f, f0, f1, logn);
#else
    size_t n = (size_t)1 << logn, hn = n >> 1, qn = hn >> 1, u;
    /* Base case (logn==1, qn==0). */
    f[0] = f0[0];
    f[hn] = f1[0];
    for (u = 0; u < qn; u++) {
        fpr a_re = f0[u], a_im = f0[u + qn];
        fpr b_re, b_im, t_re, t_im;
        FPC_MUL(b_re, b_im, f1[u], f1[u + qn],
            falcon_gm_tab[((u + hn) << 1) + 0],
            falcon_gm_tab[((u + hn) << 1) + 1]);
        FPC_ADD(t_re, t_im, a_re, a_im, b_re, b_im);
        f[(u << 1) + 0] = t_re;
        f[(u << 1) + 0 + hn] = t_im;
        FPC_SUB(t_re, t_im, a_re, a_im, b_re, b_im);
        f[(u << 1) + 1] = t_re;
        f[(u << 1) + 1 + hn] = t_im;
    }
#endif
}




/*
 * Small RNS primes. Each entry is a prime p (2^30 < p < 2^31, p = 1 mod
 * 2048), a primitive root g of X^N+1 in Z_p, and s = the inverse of the
 * product of all previous primes modulo p, in Montgomery representation.
 * The table is listed in decreasing order of p and terminated with a
 * { 0, 0, 0 } sentinel.
 */
static const falcon_small_prime FALCON_PRIMES[] = {
    { 2147473409,  383167813,      10239 },
    { 2147389441,  211808905,  471403745 },
    { 2147387393,   37672282, 1329335065 },
    { 2147377153, 1977035326,  968223422 },
    { 2147358721, 1067163706,  132460015 },
    { 2147352577, 1606082042,  598693809 },
    { 2147346433, 2033915641, 1056257184 },
    { 2147338241, 1653770625,  421286710 },
    { 2147309569,  631200819, 1111201074 },
    { 2147297281, 2038364663, 1042003613 },
    { 2147295233, 1962540515,   19440033 },
    { 2147239937, 2100082663,  353296760 },
    { 2147235841, 1991153006, 1703918027 },
    { 2147217409,  516405114, 1258919613 },
    { 2147205121,  409347988, 1089726929 },
    { 2147196929,  927788991, 1946238668 },
    { 2147178497, 1136922411, 1347028164 },
    { 2147100673,  868626236,  701164723 },
    { 2147082241, 1897279176,  617820870 },
    { 2147074049, 1888819123,  158382189 },
    { 2147051521,   25006327,  522758543 },
    { 2147043329,  327546255,   37227845 },
    { 2147039233,  766324424, 1133356428 },
    { 2146988033, 1862817362,   73861329 },
    { 2146963457,  404622040,  653019435 },
    { 2146959361, 1936581214,  995143093 },
    { 2146938881, 1559770096,  634921513 },
    { 2146908161,  422623708, 1985060172 },
    { 2146885633, 1751189170,  298238186 },
    { 2146871297,  578919515,  291810829 },
    { 2146846721, 1114060353,  915902322 },
    { 2146834433, 2069565474,   47859524 },
    { 2146818049, 1552824584,  646281055 },
    { 2146775041, 1906267847, 1597832891 },
    { 2146756609, 1847414714, 1228090888 },
    { 2146744321, 1818792070, 1176377637 },
    { 2146738177, 1118066398, 1054971214 },
    { 2146736129,   52057278,  933422153 },
    { 2146713601,  592259376, 1406621510 },
    { 2146695169,  263161877, 1514178701 },
    { 2146656257,  685363115,  384505091 },
    { 2146650113,  927727032,  537575289 },
    { 2146646017,   52575506, 1799464037 },
    { 2146643969, 1276803876, 1348954416 },
    { 2146603009,  814028633, 1521547704 },
    { 2146572289, 1846678872, 1310832121 },
    { 2146547713,  919368090, 1019041349 },
    { 2146508801,  671847612,   38582496 },
    { 2146492417,  283911680,  532424562 },
    { 2146490369, 1780044827,  896447978 },
    { 2146459649,  327980850, 1327906900 },
    { 2146447361, 1310561493,  958645253 },
    { 2146441217,  412148926,  287271128 },
    { 2146437121,  293186449, 2009822534 },
    { 2146430977,  179034356, 1359155584 },
    { 2146418689, 1517345488, 1790248672 },
    { 2146406401, 1615820390, 1584833571 },
    { 2146404353,  826651445,  607120498 },
    { 2146379777,    3816988, 1897049071 },
    { 2146363393, 1221409784, 1986921567 },
    { 2146355201, 1388081168,  849968120 },
    { 2146336769, 1803473237, 1655544036 },
    { 2146312193, 1023484977,  273671831 },
    { 2146293761, 1074591448,  467406983 },
    { 2146283521,  831604668, 1523950494 },
    { 2146203649,  712865423, 1170834574 },
    { 2146154497, 1764991362, 1064856763 },
    { 2146142209,  627386213, 1406840151 },
    { 2146127873, 1638674429, 2088393537 },
    { 2146099201, 1516001018,  690673370 },
    { 2146093057, 1294931393,  315136610 },
    { 2146091009, 1942399533,  973539425 },
    { 2146078721, 1843461814, 2132275436 },
    { 2146060289, 1098740778,  360423481 },
    { 2146048001, 1617213232, 1951981294 },
    { 2146041857, 1805783169, 2075683489 },
    { 2146019329,  272027909, 1753219918 },
    { 2145986561, 1206530344, 2034028118 },
    { 2145976321, 1243769360, 1173377644 },
    { 2145964033,  887200839, 1281344586 },
    { 2145906689, 1651026455,  906178216 },
    { 2145875969, 1673238256, 1043521212 },
    { 2145871873, 1226591210, 1399796492 },
    { 2145841153, 1465353397, 1324527802 },
    { 2145832961, 1150638905,  554084759 },
    { 2145816577,  221601706,  427340863 },
    { 2145785857,  608896761,  316590738 },
    { 2145755137, 1712054942, 1684294304 },
    { 2145742849, 1302302867,  724873116 },
    { 2145728513,  516717693,  431671476 },
    { 2145699841,  524575579, 1619722537 },
    { 2145691649, 1925625239,  982974435 },
    { 2145687553,  463795662, 1293154300 },
    { 2145673217,  771716636,  881778029 },
    { 2145630209, 1509556977,  837364988 },
    { 2145595393,  229091856,  851648427 },
    { 2145587201, 1796903241,  635342424 },
    { 2145525761,  715310882, 1677228081 },
    { 2145495041, 1040930522,  200685896 },
    { 2145466369,  949804237, 1809146322 },
    { 2145445889, 1673903706,   95316881 },
    { 2145390593,  806941852, 1428671135 },
    { 2145372161, 1402525292,  159350694 },
    { 2145361921, 2124760298, 1589134749 },
    { 2145359873, 1217503067, 1561543010 },
    { 2145355777,  338341402,   83865711 },
    { 2145343489, 1381532164,  641430002 },
    { 2145325057, 1883895478, 1528469895 },
    { 2145318913, 1335370424,   65809740 },
    { 2145312769, 2000008042, 1919775760 },
    { 2145300481,  961450962, 1229540578 },
    { 2145282049,  910466767, 1964062701 },
    { 2145232897,  816527501,  450152063 },
    { 2145218561, 1435128058, 1794509700 },
    { 2145187841,   33505311, 1272467582 },
    { 2145181697,  269767433, 1380363849 },
    { 2145175553,   56386299, 1316870546 },
    { 2145079297, 2106880293, 1391797340 },
    { 2145021953, 1347906152,  720510798 },
    { 2145015809,  206769262, 1651459955 },
    { 2145003521, 1885513236, 1393381284 },
    { 2144960513, 1810381315,   31937275 },
    { 2144944129, 1306487838, 2019419520 },
    { 2144935937,   37304730, 1841489054 },
    { 2144894977, 1601434616,  157985831 },
    { 2144888833,   98749330, 2128592228 },
    { 2144880641, 1772327002, 2076128344 },
    { 2144864257, 1404514762, 2029969964 },
    { 2144827393,  801236594,  406627220 },
    { 2144806913,  349217443, 1501080290 },
    { 2144796673, 1542656776, 2084736519 },
    { 2144778241, 1210734884, 1746416203 },
    { 2144759809, 1146598851,  716464489 },
    { 2144757761,  286328400, 1823728177 },
    { 2144729089, 1347555695, 1836644881 },
    { 2144727041, 1795703790,  520296412 },
    { 2144696321, 1302475157,  852964281 },
    { 2144667649, 1075877614,  504992927 },
    { 2144573441,  198765808, 1617144982 },
    { 2144555009,  321528767,  155821259 },
    { 2144550913,  814139516, 1819937644 },
    { 2144536577,  571143206,  962942255 },
    { 2144524289, 1746733766,    2471321 },
    { 2144512001, 1821415077,  124190939 },
    { 2144468993,  917871546, 1260072806 },
    { 2144458753,  378417981, 1569240563 },
    { 2144421889,  175229668, 1825620763 },
    { 2144409601, 1699216963,  351648117 },
    { 2144370689, 1071885991,  958186029 },
    { 2144348161, 1763151227,  540353574 },
    { 2144335873, 1060214804,  919598847 },
    { 2144329729,  663515846, 1448552668 },
    { 2144327681, 1057776305,  590222840 },
    { 2144309249, 1705149168, 1459294624 },
    { 2144296961,  325823721, 1649016934 },
    { 2144290817,  738775789,  447427206 },
    { 2144243713,  962347618,  893050215 },
    { 2144237569, 1655257077,  900860862 },
    { 2144161793,  242206694, 1567868672 },
    { 2144155649,  769415308, 1247993134 },
    { 2144137217,  320492023,  515841070 },
    { 2144120833, 1639388522,  770877302 },
    { 2144071681, 1761785233,  964296120 },
    { 2144065537,  419817825,  204564472 },
    { 2144028673,  666050597, 2091019760 },
    { 2144010241, 1413657615, 1518702610 },
    { 2143952897, 1238327946,  475672271 },
    { 2143940609,  307063413, 1176750846 },
    { 2143918081, 2062905559,  786785803 },
    { 2143899649, 1338112849, 1562292083 },
    { 2143891457,   68149545,   87166451 },
    { 2143885313,  921750778,  394460854 },
    { 2143854593,  719766593,  133877196 },
    { 2143836161, 1149399850, 1861591875 },
    { 2143762433, 1848739366, 1335934145 },
    { 2143756289, 1326674710,  102999236 },
    { 2143713281,  808061791, 1156900308 },
    { 2143690753,  388399459, 1926468019 },
    { 2143670273, 1427891374, 1756689401 },
    { 2143666177, 1912173949,  986629565 },
    { 2143645697, 2041160111,  371842865 },
    { 2143641601, 1279906897, 2023974350 },
    { 2143635457,  720473174, 1389027526 },
    { 2143621121, 1298309455, 1732632006 },
    { 2143598593, 1548762216, 1825417506 },
    { 2143567873,  620475784, 1073787233 },
    { 2143561729, 1932954575,  949167309 },
    { 2143553537,  354315656, 1652037534 },
    { 2143541249,  577424288, 1097027618 },
    { 2143531009,  357862822,  478640055 },
    { 2143522817, 2017706025, 1550531668 },
    { 2143506433, 2078127419, 1824320165 },
    { 2143488001,  613475285, 1604011510 },
    { 2143469569, 1466594987,  502095196 },
    { 2143426561, 1115430331, 1044637111 },
    { 2143383553,    9778045, 1902463734 },
    { 2143377409, 1557401276, 2056861771 },
    { 2143363073,  652036455, 1965915971 },
    { 2143260673, 1464581171, 1523257541 },
    { 2143246337, 1876119649,  764541916 },
    { 2143209473, 1614992673, 1920672844 },
    { 2143203329,  981052047, 2049774209 },
    { 2143160321, 1847355533,  728535665 },
    { 2143129601,  965558457,  603052992 },
    { 2143123457, 2140817191,    8348679 },
    { 2143100929, 1547263683,  694209023 },
    { 2143092737,  643459066, 1979934533 },
    { 2143082497,  188603778, 2026175670 },
    { 2143062017, 1657329695,  377451099 },
    { 2143051777,  114967950,  979255473 },
    { 2143025153, 1698431342, 1449196896 },
    { 2143006721, 1862741675, 1739650365 },
    { 2142996481,  756660457,  996160050 },
    { 2142976001,  927864010, 1166847574 },
    { 2142965761,  905070557,  661974566 },
    { 2142916609,   40932754, 1787161127 },
    { 2142892033, 1987985648,  675335382 },
    { 2142885889,  797497211, 1323096997 },
    { 2142871553, 2068025830, 1411877159 },
    { 2142861313, 1217177090, 1438410687 },
    { 2142830593,  409906375, 1767860634 },
    { 2142803969, 1197788993,  359782919 },
    { 2142785537,  643817365,  513932862 },
    { 2142779393, 1717046338,  218943121 },
    { 2142724097,   89336830,  416687049 },
    { 2142707713,    5944581, 1356813523 },
    { 2142658561,  887942135, 2074011722 },
    { 2142638081,  151851972, 1647339939 },
    { 2142564353, 1691505537, 1483107336 },
    { 2142533633, 1989920200, 1135938817 },
    { 2142529537,  959263126, 1531961857 },
    { 2142527489,  453251129, 1725566162 },
    { 2142502913, 1536028102,  182053257 },
    { 2142498817,  570138730,  701443447 },
    { 2142416897,  326965800,  411931819 },
    { 2142363649, 1675665410, 1517191733 },
    { 2142351361,  968529566, 1575712703 },
    { 2142330881, 1384953238, 1769087884 },
    { 2142314497, 1977173242, 1833745524 },
    { 2142289921,   95082313, 1714775493 },
    { 2142283777,  109377615, 1070584533 },
    { 2142277633,   16960510,  702157145 },
    { 2142263297,  553850819,  431364395 },
    { 2142208001,  241466367, 2053967982 },
    { 2142164993, 1795661326, 1031836848 },
    { 2142097409, 1212530046,  712772031 },
    { 2142087169, 1763869720,  822276067 },
    { 2142078977,  644065713, 1765268066 },
    { 2142074881,  112671944,  643204925 },
    { 2142044161, 1387785471, 1297890174 },
    { 2142025729,  783885537, 1000425730 },
    { 2142011393,  905662232, 1679401033 },
    { 2141974529,  799788433,  468119557 },
    { 2141943809, 1932544124,  449305555 },
    { 2141933569, 1527403256,  841867925 },
    { 2141931521, 1247076451,  743823916 },
    { 2141902849, 1199660531,  401687910 },
    { 2141890561,  150132350, 1720336972 },
    { 2141857793, 1287438162,  663880489 },
    { 2141833217,  618017731, 1819208266 },
    { 2141820929,  999578638, 1403090096 },
    { 2141786113,   81834325, 1523542501 },
    { 2141771777,  120001928,  463556492 },
    { 2141759489,  122455485, 2124928282 },
    { 2141749249,  141986041,  940339153 },
    { 2141685761,  889088734,  477141499 },
    { 2141673473,  324212681, 1122558298 },
    { 2141669377, 1175806187, 1373818177 },
    { 2141655041, 1113654822,  296887082 },
    { 2141587457,  991103258, 1585913875 },
    { 2141583361, 1401451409, 1802457360 },
    { 2141575169, 1571977166,  712760980 },
    { 2141546497, 1107849376, 1250270109 },
    { 2141515777,  196544219,  356001130 },
    { 2141495297, 1733571506, 1060744866 },
    { 2141483009,  321552363, 1168297026 },
    { 2141458433,  505818251,  733225819 },
    { 2141360129, 1026840098,  948342276 },
    { 2141325313,  945133744, 2129965998 },
    { 2141317121, 1871100260, 1843844634 },
    { 2141286401, 1790639498, 1750465696 },
    { 2141267969, 1376858592,  186160720 },
    { 2141255681, 2129698296, 1876677959 },
    { 2141243393, 2138900688, 1340009628 },
    { 2141214721, 1933049835, 1087819477 },
    { 2141212673, 1898664939, 1786328049 },
    { 2141202433,  990234828,  940682169 },
    { 2141175809, 1406392421,  993089586 },
    { 2141165569, 1263518371,  289019479 },
    { 2141073409, 1485624211,  507864514 },
    { 2141052929, 1885134788,  311252465 },
    { 2141040641, 1285021247,  280941862 },
    { 2141028353, 1527610374,  375035110 },
    { 2141011969, 1400626168,  164696620 },
    { 2140999681,  632959608,  966175067 },
    { 2140997633, 2045628978, 1290889438 },
    { 2140993537, 1412755491,  375366253 },
    { 2140942337,  719477232,  785367828 },
    { 2140925953,   45224252,  836552317 },
    { 2140917761, 1157376588, 1001839569 },
    { 2140887041,  278480752, 2098732796 },
    { 2140837889, 1663139953,  924094810 },
    { 2140788737,  802501511, 2045368990 },
    { 2140766209, 1820083885, 1800295504 },
    { 2140764161, 1169561905, 2106792035 },
    { 2140696577,  127781498, 1885987531 },
    { 2140684289,   16014477, 1098116827 },
    { 2140653569,  665960598, 1796728247 },
    { 2140594177, 1043085491,  377310938 },
    { 2140579841, 1732838211, 1504505945 },
    { 2140569601,  302071939,  358291016 },
    { 2140567553,  192393733, 1909137143 },
    { 2140557313,  406595731, 1175330270 },
    { 2140549121, 1748850918,  525007007 },
    { 2140477441,  499436566, 1031159814 },
    { 2140469249, 1886004401, 1029951320 },
    { 2140426241, 1483168100, 1676273461 },
    { 2140420097, 1779917297,  846024476 },
    { 2140413953,  522948893, 1816354149 },
    { 2140383233, 1931364473, 1296921241 },
    { 2140366849, 1917356555,  147196204 },
    { 2140354561,   16466177, 1349052107 },
    { 2140348417, 1875366972, 1860485634 },
    { 2140323841,  456498717, 1790256483 },
    { 2140321793, 1629493973,  150031888 },
    { 2140315649, 1904063898,  395510935 },
    { 2140280833, 1784104328,  831417909 },
    { 2140250113,  256087139,  697349101 },
    { 2140229633,  388553070,  243875754 },
    { 2140223489,  747459608, 1396270850 },
    { 2140200961,  507423743, 1895572209 },
    { 2140162049,  580106016, 2045297469 },
    { 2140149761,  712426444,  785217995 },
    { 2140137473, 1441607584,  536866543 },
    { 2140119041,  346538902, 1740434653 },
    { 2140090369,  282642885,   21051094 },
    { 2140076033, 1407456228,  319910029 },
    { 2140047361, 1619330500, 1488632070 },
    { 2140041217, 2089408064, 2012026134 },
    { 2140008449, 1705524800, 1613440760 },
    { 2139924481, 1846208233, 1280649481 },
    { 2139906049,  989438755, 1185646076 },
    { 2139867137, 1522314850,  372783595 },
    { 2139842561, 1681587377,  216848235 },
    { 2139826177, 2066284988, 1784999464 },
    { 2139824129,  480888214, 1513323027 },
    { 2139789313,  847937200,  858192859 },
    { 2139783169, 1642000434, 1583261448 },
    { 2139770881,  940699589,  179702100 },
    { 2139768833,  315623242,  964612676 },
    { 2139666433,  331649203,  764666914 },
    { 2139641857, 2118730799, 1313764644 },
    { 2139635713,  519149027,  519212449 },
    { 2139598849, 1526413634, 1769667104 },
    { 2139574273,  551148610,  820739925 },
    { 2139568129, 1386800242,  472447405 },
    { 2139549697,  813760130, 1412328531 },
    { 2139537409, 1615286260, 1609362979 },
    { 2139475969, 1352559299, 1696720421 },
    { 2139455489, 1048691649, 1584935400 },
    { 2139432961,  836025845,  950121150 },
    { 2139424769, 1558281165, 1635486858 },
    { 2139406337, 1728402143, 1674423301 },
    { 2139396097, 1727715782, 1483470544 },
    { 2139383809, 1092853491, 1741699084 },
    { 2139369473,  690776899, 1242798709 },
    { 2139351041, 1768782380, 2120712049 },
    { 2139334657, 1739968247, 1427249225 },
    { 2139332609, 1547189119,  623011170 },
    { 2139310081, 1346827917, 1605466350 },
    { 2139303937,  369317948,  828392831 },
    { 2139301889, 1560417239, 1788073219 },
    { 2139283457, 1303121623,  595079358 },
    { 2139248641, 1354555286,  573424177 },
    { 2139240449,   60974056,  885781403 },
    { 2139222017,  355573421, 1221054839 },
    { 2139215873,  566477826, 1724006500 },
    { 2139150337,  871437673, 1609133294 },
    { 2139144193, 1478130914, 1137491905 },
    { 2139117569, 1854880922,  964728507 },
    { 2139076609,  202405335,  756508944 },
    { 2139062273, 1399715741,  884826059 },
    { 2139045889, 1051045798, 1202295476 },
    { 2139033601, 1707715206,  632234634 },
    { 2139006977, 2035853139,  231626690 },
    { 2138951681,  183867876,  838350879 },
    { 2138945537, 1403254661,  404460202 },
    { 2138920961,  310865011, 1282911681 },
    { 2138910721, 1328496553,  103472415 },
    { 2138904577,   78831681,  993513549 },
    { 2138902529, 1319697451, 1055904361 },
    { 2138816513,  384338872, 1706202469 },
    { 2138810369, 1084868275,  405677177 },
    { 2138787841,  401181788, 1964773901 },
    { 2138775553, 1850532988, 1247087473 },
    { 2138767361,  874261901, 1576073565 },
    { 2138757121, 1187474742,  993541415 },
    { 2138748929, 1782458888, 1043206483 },
    { 2138744833, 1221500487,  800141243 },
    { 2138738689,  413465368, 1450660558 },
    { 2138695681,  739045140,  342611472 },
    { 2138658817, 1355845756,  672674190 },
    { 2138644481,  608379162, 1538874380 },
    { 2138632193, 1444914034,  686911254 },
    { 2138607617,  484707818, 1435142134 },
    { 2138591233,  539460669, 1290458549 },
    { 2138572801, 2093538990, 2011138646 },
    { 2138552321, 1149786988, 1076414907 },
    { 2138546177,  840688206, 2108985273 },
    { 2138533889,  209669619,  198172413 },
    { 2138523649, 1975879426, 1277003968 },
    { 2138490881, 1351891144, 1976858109 },
    { 2138460161, 1817321013, 1979278293 },
    { 2138429441, 1950077177,  203441928 },
    { 2138400769,  908970113,  628395069 },
    { 2138398721,  219890864,  758486760 },
    { 2138376193, 1306654379,  977554090 },
    { 2138351617,  298822498, 2004708503 },
    { 2138337281,  441457816, 1049002108 },
    { 2138320897, 1517731724, 1442269609 },
    { 2138290177, 1355911197, 1647139103 },
    { 2138234881,  531313247, 1746591962 },
    { 2138214401, 1899410930,  781416444 },
    { 2138202113, 1813477173, 1622508515 },
    { 2138191873, 1086458299, 1025408615 },
    { 2138183681, 1998800427,  827063290 },
    { 2138173441, 1921308898,  749670117 },
    { 2138103809, 1620902804, 2126787647 },
    { 2138099713,  828647069, 1892961817 },
    { 2138085377,  179405355, 1525506535 },
    { 2138060801,  615683235, 1259580138 },
    { 2138044417, 2030277840, 1731266562 },
    { 2138042369, 2087222316, 1627902259 },
    { 2138032129,  126388712, 1108640984 },
    { 2138011649,  715026550, 1017980050 },
    { 2137993217, 1693714349, 1351778704 },
    { 2137888769, 1289762259, 1053090405 },
    { 2137853953,  199991890, 1254192789 },
    { 2137833473,  941421685,  896995556 },
    { 2137817089,  750416446, 1251031181 },
    { 2137792513,  798075119,  368077456 },
    { 2137786369,  878543495, 1035375025 },
    { 2137767937,    9351178, 1156563902 },
    { 2137755649, 1382297614, 1686559583 },
    { 2137724929, 1345472850, 1681096331 },
    { 2137704449,  834666929,  630551727 },
    { 2137673729, 1646165729, 1892091571 },
    { 2137620481,  778943821,   48456461 },
    { 2137618433, 1730837875, 1713336725 },
    { 2137581569,  805610339, 1378891359 },
    { 2137538561,  204342388, 1950165220 },
    { 2137526273, 1947629754, 1500789441 },
    { 2137516033,  719902645, 1499525372 },
    { 2137491457,  230451261,  556382829 },
    { 2137440257,  979573541,  412760291 },
    { 2137374721,  927841248, 1954137185 },
    { 2137362433, 1243778559,  861024672 },
    { 2137313281, 1341338501,  980638386 },
    { 2137311233,  937415182, 1793212117 },
    { 2137255937,  795331324, 1410253405 },
    { 2137243649,  150756339, 1966999887 },
    { 2137182209,  163346914, 1939301431 },
    { 2137171969, 1952552395,  758913141 },
    { 2137159681,  570788721,  218668666 },
    { 2137147393, 1896656810, 2045670345 },
    { 2137141249,  358493842,  518199643 },
    { 2137139201, 1505023029,  674695848 },
    { 2137133057,   27911103,  830956306 },
    { 2137122817,  439771337, 1555268614 },
    { 2137116673,  790988579, 1871449599 },
    { 2137110529,  432109234,  811805080 },
    { 2137102337, 1357900653, 1184997641 },
    { 2137098241,  515119035, 1715693095 },
    { 2137090049,  408575203, 2085660657 },
    { 2137085953, 2097793407, 1349626963 },
    { 2137055233, 1556739954, 1449960883 },
    { 2137030657, 1545758650, 1369303716 },
    { 2136987649,  332602570,  103875114 },
    { 2136969217, 1499989506, 1662964115 },
    { 2136924161,  857040753,    4738842 },
    { 2136895489, 1948872712,  570436091 },
    { 2136893441,   58969960, 1568349634 },
    { 2136887297, 2127193379,  273612548 },
    { 2136850433,  111208983, 1181257116 },
    { 2136809473, 1627275942, 1680317971 },
    { 2136764417, 1574888217,   14011331 },
    { 2136741889,   14011055, 1129154251 },
    { 2136727553,   35862563, 1838555253 },
    { 2136721409,  310235666, 1363928244 },
    { 2136698881, 1612429202, 1560383828 },
    { 2136649729, 1138540131,  800014364 },
    { 2136606721,  602323503, 1433096652 },
    { 2136563713,  182209265, 1919611038 },
    { 2136555521,  324156477,  165591039 },
    { 2136549377,  195513113,  217165345 },
    { 2136526849, 1050768046,  939647887 },
    { 2136508417, 1886286237, 1619926572 },
    { 2136477697,  609647664,   35065157 },
    { 2136471553,  679352216, 1452259468 },
    { 2136457217,  128630031,  824816521 },
    { 2136422401,   19787464, 1526049830 },
    { 2136420353,  698316836, 1530623527 },
    { 2136371201, 1651862373, 1804812805 },
    { 2136334337,  326596005,  336977082 },
    { 2136322049,   63253370, 1904972151 },
    { 2136297473,  312176076,  172182411 },
    { 2136248321,  381261841,  369032670 },
    { 2136242177,  358688773, 1640007994 },
    { 2136229889,  512677188,   75585225 },
    { 2136219649, 2095003250, 1970086149 },
    { 2136207361, 1909650722,  537760675 },
    { 2136176641, 1334616195, 1533487619 },
    { 2136158209, 2096285632, 1793285210 },
    { 2136143873, 1897347517,  293843959 },
    { 2136133633,  923586222, 1022655978 },
    { 2136096769, 1464868191, 1515074410 },
    { 2136094721, 2020679520, 2061636104 },
    { 2136076289,  290798503, 1814726809 },
    { 2136041473,  156415894, 1250757633 },
    { 2135996417,  297459940, 1132158924 },
    { 2135955457,  538755304, 1688831340 },
    { 0, 0, 0 }
};

/*
 * Bit-reversal index table (10 bits).
 */
static const word16 REV10[] = {
       0,  512,  256,  768,  128,  640,  384,  896,   64,  576,  320,  832,
     192,  704,  448,  960,   32,  544,  288,  800,  160,  672,  416,  928,
      96,  608,  352,  864,  224,  736,  480,  992,   16,  528,  272,  784,
     144,  656,  400,  912,   80,  592,  336,  848,  208,  720,  464,  976,
      48,  560,  304,  816,  176,  688,  432,  944,  112,  624,  368,  880,
     240,  752,  496, 1008,    8,  520,  264,  776,  136,  648,  392,  904,
      72,  584,  328,  840,  200,  712,  456,  968,   40,  552,  296,  808,
     168,  680,  424,  936,  104,  616,  360,  872,  232,  744,  488, 1000,
      24,  536,  280,  792,  152,  664,  408,  920,   88,  600,  344,  856,
     216,  728,  472,  984,   56,  568,  312,  824,  184,  696,  440,  952,
     120,  632,  376,  888,  248,  760,  504, 1016,    4,  516,  260,  772,
     132,  644,  388,  900,   68,  580,  324,  836,  196,  708,  452,  964,
      36,  548,  292,  804,  164,  676,  420,  932,  100,  612,  356,  868,
     228,  740,  484,  996,   20,  532,  276,  788,  148,  660,  404,  916,
      84,  596,  340,  852,  212,  724,  468,  980,   52,  564,  308,  820,
     180,  692,  436,  948,  116,  628,  372,  884,  244,  756,  500, 1012,
      12,  524,  268,  780,  140,  652,  396,  908,   76,  588,  332,  844,
     204,  716,  460,  972,   44,  556,  300,  812,  172,  684,  428,  940,
     108,  620,  364,  876,  236,  748,  492, 1004,   28,  540,  284,  796,
     156,  668,  412,  924,   92,  604,  348,  860,  220,  732,  476,  988,
      60,  572,  316,  828,  188,  700,  444,  956,  124,  636,  380,  892,
     252,  764,  508, 1020,    2,  514,  258,  770,  130,  642,  386,  898,
      66,  578,  322,  834,  194,  706,  450,  962,   34,  546,  290,  802,
     162,  674,  418,  930,   98,  610,  354,  866,  226,  738,  482,  994,
      18,  530,  274,  786,  146,  658,  402,  914,   82,  594,  338,  850,
     210,  722,  466,  978,   50,  562,  306,  818,  178,  690,  434,  946,
     114,  626,  370,  882,  242,  754,  498, 1010,   10,  522,  266,  778,
     138,  650,  394,  906,   74,  586,  330,  842,  202,  714,  458,  970,
      42,  554,  298,  810,  170,  682,  426,  938,  106,  618,  362,  874,
     234,  746,  490, 1002,   26,  538,  282,  794,  154,  666,  410,  922,
      90,  602,  346,  858,  218,  730,  474,  986,   58,  570,  314,  826,
     186,  698,  442,  954,  122,  634,  378,  890,  250,  762,  506, 1018,
       6,  518,  262,  774,  134,  646,  390,  902,   70,  582,  326,  838,
     198,  710,  454,  966,   38,  550,  294,  806,  166,  678,  422,  934,
     102,  614,  358,  870,  230,  742,  486,  998,   22,  534,  278,  790,
     150,  662,  406,  918,   86,  598,  342,  854,  214,  726,  470,  982,
      54,  566,  310,  822,  182,  694,  438,  950,  118,  630,  374,  886,
     246,  758,  502, 1014,   14,  526,  270,  782,  142,  654,  398,  910,
      78,  590,  334,  846,  206,  718,  462,  974,   46,  558,  302,  814,
     174,  686,  430,  942,  110,  622,  366,  878,  238,  750,  494, 1006,
      30,  542,  286,  798,  158,  670,  414,  926,   94,  606,  350,  862,
     222,  734,  478,  990,   62,  574,  318,  830,  190,  702,  446,  958,
     126,  638,  382,  894,  254,  766,  510, 1022,    1,  513,  257,  769,
     129,  641,  385,  897,   65,  577,  321,  833,  193,  705,  449,  961,
      33,  545,  289,  801,  161,  673,  417,  929,   97,  609,  353,  865,
     225,  737,  481,  993,   17,  529,  273,  785,  145,  657,  401,  913,
      81,  593,  337,  849,  209,  721,  465,  977,   49,  561,  305,  817,
     177,  689,  433,  945,  113,  625,  369,  881,  241,  753,  497, 1009,
       9,  521,  265,  777,  137,  649,  393,  905,   73,  585,  329,  841,
     201,  713,  457,  969,   41,  553,  297,  809,  169,  681,  425,  937,
     105,  617,  361,  873,  233,  745,  489, 1001,   25,  537,  281,  793,
     153,  665,  409,  921,   89,  601,  345,  857,  217,  729,  473,  985,
      57,  569,  313,  825,  185,  697,  441,  953,  121,  633,  377,  889,
     249,  761,  505, 1017,    5,  517,  261,  773,  133,  645,  389,  901,
      69,  581,  325,  837,  197,  709,  453,  965,   37,  549,  293,  805,
     165,  677,  421,  933,  101,  613,  357,  869,  229,  741,  485,  997,
      21,  533,  277,  789,  149,  661,  405,  917,   85,  597,  341,  853,
     213,  725,  469,  981,   53,  565,  309,  821,  181,  693,  437,  949,
     117,  629,  373,  885,  245,  757,  501, 1013,   13,  525,  269,  781,
     141,  653,  397,  909,   77,  589,  333,  845,  205,  717,  461,  973,
      45,  557,  301,  813,  173,  685,  429,  941,  109,  621,  365,  877,
     237,  749,  493, 1005,   29,  541,  285,  797,  157,  669,  413,  925,
      93,  605,  349,  861,  221,  733,  477,  989,   61,  573,  317,  829,
     189,  701,  445,  957,  125,  637,  381,  893,  253,  765,  509, 1021,
       3,  515,  259,  771,  131,  643,  387,  899,   67,  579,  323,  835,
     195,  707,  451,  963,   35,  547,  291,  803,  163,  675,  419,  931,
      99,  611,  355,  867,  227,  739,  483,  995,   19,  531,  275,  787,
     147,  659,  403,  915,   83,  595,  339,  851,  211,  723,  467,  979,
      51,  563,  307,  819,  179,  691,  435,  947,  115,  627,  371,  883,
     243,  755,  499, 1011,   11,  523,  267,  779,  139,  651,  395,  907,
      75,  587,  331,  843,  203,  715,  459,  971,   43,  555,  299,  811,
     171,  683,  427,  939,  107,  619,  363,  875,  235,  747,  491, 1003,
      27,  539,  283,  795,  155,  667,  411,  923,   91,  603,  347,  859,
     219,  731,  475,  987,   59,  571,  315,  827,  187,  699,  443,  955,
     123,  635,  379,  891,  251,  763,  507, 1019,    7,  519,  263,  775,
     135,  647,  391,  903,   71,  583,  327,  839,  199,  711,  455,  967,
      39,  551,  295,  807,  167,  679,  423,  935,  103,  615,  359,  871,
     231,  743,  487,  999,   23,  535,  279,  791,  151,  663,  407,  919,
      87,  599,  343,  855,  215,  727,  471,  983,   55,  567,  311,  823,
     183,  695,  439,  951,  119,  631,  375,  887,  247,  759,  503, 1015,
      15,  527,  271,  783,  143,  655,  399,  911,   79,  591,  335,  847,
     207,  719,  463,  975,   47,  559,  303,  815,  175,  687,  431,  943,
     111,  623,  367,  879,  239,  751,  495, 1007,   31,  543,  287,  799,
     159,  671,  415,  927,   95,  607,  351,  863,  223,  735,  479,  991,
      63,  575,  319,  831,  191,  703,  447,  959,  127,  639,  383,  895,
     255,  767,  511, 1023,
};

/*
 * Reduce a small signed integer modulo a small prime. The source
 * value x MUST be such that -p < x < p.
 */
word32 modp_set(sword32 x, word32 p)
{
    word32 w;

    w = (word32)x;
    w += p & -(w >> 31);
    return w;
}

/*
 * Normalize a modular integer around 0.
 */
sword32 modp_norm(word32 x, word32 p)
{
    return (sword32)(x - (p & (((x - ((p + 1) >> 1)) >> 31) - 1)));
}

/*
 * Compute -1/p mod 2^31. This works for all odd integers p that fit
 * on 31 bits.
 */
word32 modp_ninv31(word32 p)
{
    word32 y;

    y = 2 - p;
    y *= 2 - p * y;
    y *= 2 - p * y;
    y *= 2 - p * y;
    y *= 2 - p * y;
    return (word32)0x7FFFFFFF & -y;
}

/*
 * Compute R = 2^31 mod p.
 */
word32 modp_R(word32 p)
{
    /*
     * Since 2^30 < p < 2^31, we know that 2^31 mod p is simply
     * 2^31 - p.
     */
    return ((word32)1 << 31) - p;
}

/*
 * Addition modulo p.
 */
word32 modp_add(word32 a, word32 b, word32 p)
{
    word32 d;

    d = a + b - p;
    d += p & -(d >> 31);
    return d;
}

/*
 * Subtraction modulo p.
 */
word32 modp_sub(word32 a, word32 b, word32 p)
{
    word32 d;

    d = a - b;
    d += p & -(d >> 31);
    return d;
}

/*
 * Montgomery multiplication modulo p. The 'p0i' value is -1/p mod 2^31.
 * It is required that p is an odd integer.
 */
word32 modp_montymul(word32 a, word32 b, word32 p, word32 p0i)
{
    word64 z, w;
    word32 d;

    z = (word64)a * (word64)b;
    w = ((z * p0i) & (word64)0x7FFFFFFF) * p;
    d = (word32)((z + w) >> 31) - p;
    d += p & -(d >> 31);
    return d;
}

/*
 * Compute R2 = 2^62 mod p.
 */
word32 modp_R2(word32 p, word32 p0i)
{
    word32 z;

    /*
     * Compute z = 2^31 mod p (this is the value 1 in Montgomery
     * representation), then double it with an addition.
     */
    z = modp_R(p);
    z = modp_add(z, z, p);

    /*
     * Square it five times to obtain 2^32 in Montgomery representation
     * (i.e. 2^63 mod p).
     */
    z = modp_montymul(z, z, p, p0i);
    z = modp_montymul(z, z, p, p0i);
    z = modp_montymul(z, z, p, p0i);
    z = modp_montymul(z, z, p, p0i);
    z = modp_montymul(z, z, p, p0i);

    /*
     * Halve the value mod p to get 2^62.
     */
    z = (z + (p & -(z & 1))) >> 1;
    return z;
}

/*
 * Compute 2^(31*x) modulo p. This works for integers x up to 2^11.
 * p must be prime such that 2^30 < p < 2^31; p0i must be equal to
 * -1/p mod 2^31; R2 must be equal to 2^62 mod p.
 */
word32 modp_Rx(unsigned int x, word32 p, word32 p0i, word32 R2)
{
    int i;
    word32 r, z;

    /*
     * 2^(31*x) = (2^31)*(2^(31*(x-1))); i.e. we want the Montgomery
     * representation of (2^31)^e mod p, where e = x-1.
     * R2 is 2^31 in Montgomery representation.
     */
    x --;
    r = R2;
    z = modp_R(p);
    for (i = 0; (1U << i) <= x; i ++) {
        if ((x & (1U << i)) != 0) {
            z = modp_montymul(z, r, p, p0i);
        }
        r = modp_montymul(r, r, p, p0i);
    }
    return z;
}

/*
 * Division modulo p. If the divisor (b) is 0, then 0 is returned.
 * This function computes proper results only when p is prime.
 * Parameters:
 *   a     dividend
 *   b     divisor
 *   p     odd prime modulus
 *   p0i   -1/p mod 2^31
 *   R     2^31 mod p
 */
word32 modp_div(word32 a, word32 b, word32 p, word32 p0i, word32 R)
{
    word32 z, e;
    int i;

    e = p - 2;
    z = R;
    for (i = 30; i >= 0; i --) {
        word32 z2;

        z = modp_montymul(z, z, p, p0i);
        z2 = modp_montymul(z, b, p, p0i);
        z ^= (z ^ z2) & -(word32)((e >> i) & 1);
    }

    /*
     * The loop above just assumed that b was in Montgomery
     * representation, i.e. really contained b*R; under that
     * assumption, it returns 1/b in Montgomery representation,
     * which is R/b. But we gave it b in normal representation,
     * so the loop really returned R/(b/R) = R^2/b.
     *
     * We want a/b, so we need one Montgomery multiplication with a,
     * which also remove one of the R factors, and another such
     * multiplication to remove the second R factor.
     */
    z = modp_montymul(z, 1, p, p0i);
    return modp_montymul(a, z, p, p0i);
}

/*
 * Compute the roots for NTT and inverse NTT (binary case). Input
 * parameter g is a primitive 2048-th root of 1 modulo p (i.e. g^1024 =
 * -1 mod p). This fills gm[] and igm[] with powers of g and 1/g:
 *   gm[rev(i)] = g^i mod p
 *   igm[rev(i)] = (1/g)^i mod p
 * where rev() is the "bit reversal" function over 10 bits. It fills
 * the arrays only up to N = 2^logn values.
 *
 * The values stored in gm[] and igm[] are in Montgomery representation.
 *
 * p must be a prime such that p = 1 mod 2048.
 */
void modp_mkgm2(word32* gm, word32* igm, unsigned int logn,
    word32 g, word32 p, word32 p0i)
{
    size_t u, n;
    unsigned int k;
    word32 ig, x1, x2, R2;

    n = (size_t)1 << logn;

    /*
     * We want g such that g^(2N) = 1 mod p, but the provided
     * generator has order 2048. We must square it a few times.
     */
    R2 = modp_R2(p, p0i);
    g = modp_montymul(g, R2, p, p0i);
    for (k = logn; k < 10; k ++) {
        g = modp_montymul(g, g, p, p0i);
    }

    ig = modp_div(R2, g, p, p0i, modp_R(p));
    k = 10 - logn;
    x1 = x2 = modp_R(p);
    for (u = 0; u < n; u ++) {
        size_t v;

        v = REV10[u << k];
        gm[v] = x1;
        igm[v] = x2;
        x1 = modp_montymul(x1, g, p, p0i);
        x2 = modp_montymul(x2, ig, p, p0i);
    }
}

/*
 * Compute the NTT over a polynomial (binary case). Polynomial elements
 * are a[0], a[stride], a[2 * stride]...
 */
void modp_NTT2_ext(word32* a, size_t stride, const word32* gm,
    unsigned int logn, word32 p, word32 p0i)
{
    size_t t, m, n;

    if (logn == 0) {
        return;
    }
    n = (size_t)1 << logn;
    t = n;
    for (m = 1; m < n; m <<= 1) {
        size_t ht, u, v1;

        ht = t >> 1;
        for (u = 0, v1 = 0; u < m; u ++, v1 += t) {
            word32 s;
            size_t v;
            word32 *r1, *r2;

            s = gm[m + u];
            r1 = a + v1 * stride;
            r2 = r1 + ht * stride;
            for (v = 0; v < ht; v ++, r1 += stride, r2 += stride) {
                word32 x, y;

                x = *r1;
                y = modp_montymul(*r2, s, p, p0i);
                *r1 = modp_add(x, y, p);
                *r2 = modp_sub(x, y, p);
            }
        }
        t = ht;
    }
}

/*
 * Compute the inverse NTT over a polynomial (binary case).
 */
void modp_iNTT2_ext(word32* a, size_t stride, const word32* igm,
    unsigned int logn, word32 p, word32 p0i)
{
    size_t t, m, n, k;
    word32 ni;
    word32* r;

    if (logn == 0) {
        return;
    }
    n = (size_t)1 << logn;
    t = 1;
    for (m = n; m > 1; m >>= 1) {
        size_t hm, dt, u, v1;

        hm = m >> 1;
        dt = t << 1;
        for (u = 0, v1 = 0; u < hm; u ++, v1 += dt) {
            word32 s;
            size_t v;
            word32 *r1, *r2;

            s = igm[hm + u];
            r1 = a + v1 * stride;
            r2 = r1 + t * stride;
            for (v = 0; v < t; v ++, r1 += stride, r2 += stride) {
                word32 x, y;

                x = *r1;
                y = *r2;
                *r1 = modp_add(x, y, p);
                *r2 = modp_montymul(
                          modp_sub(x, y, p), s, p, p0i);
            }
        }
        t = dt;
    }

    /*
     * We need 1/n in Montgomery representation, i.e. R/n. Since
     * 1 <= logn <= 10, R/n is an integer; moreover, R/n <= 2^30 < p,
     * thus a simple shift will do.
     */
    ni = (word32)1 << (31 - logn);
    for (k = 0, r = a; k < n; k ++, r += stride) {
        *r = modp_montymul(*r, ni, p, p0i);
    }
}

/*
 * Subtract integer b from integer a. Both integers are supposed to have
 * the same size. The carry (0 or 1) is returned. Source arrays a and b
 * MUST be distinct.
 *
 * The operation is performed as described above if ctl = 1. If
 * ctl = 0, the value a[] is unmodified, but all memory accesses are
 * still performed, and the carry is computed and returned.
 */
word32 zint_sub(word32* a, const word32* b, size_t len, word32 ctl)
{
    size_t u;
    word32 cc, m;

    cc = 0;
    m = -ctl;
    for (u = 0; u < len; u ++) {
        word32 aw, w;

        aw = a[u];
        w = aw - b[u] - cc;
        cc = w >> 31;
        aw ^= ((w & 0x7FFFFFFF) ^ aw) & m;
        a[u] = aw;
    }
    return cc;
}

/*
 * Multiply the provided big integer m with a small value x.
 * This function assumes that x < 2^31. The carry word is returned.
 */
word32 zint_mul_small(word32* m, size_t mlen, word32 x)
{
    size_t u;
    word32 cc;

    cc = 0;
    for (u = 0; u < mlen; u ++) {
        word64 z;

        z = (word64)m[u] * (word64)x + cc;
        m[u] = (word32)z & 0x7FFFFFFF;
        cc = (word32)(z >> 31);
    }
    return cc;
}

/*
 * Reduce a big integer d modulo a small integer p.
 * Rules:
 *  d is unsigned
 *  p is prime
 *  2^30 < p < 2^31
 *  p0i = -(1/p) mod 2^31
 *  R2 = 2^62 mod p
 */
word32 zint_mod_small_unsigned(const word32* d, size_t dlen,
    word32 p, word32 p0i, word32 R2)
{
    word32 x;
    size_t u;

    /*
     * Algorithm: we inject words one by one, starting with the high
     * word. Each step is:
     *  - multiply x by 2^31
     *  - add new word
     */
    x = 0;
    u = dlen;
    while (u -- > 0) {
        word32 w;

        x = modp_montymul(x, R2, p, p0i);
        w = d[u] - p;
        w += p & -(w >> 31);
        x = modp_add(x, w, p);
    }
    return x;
}

/*
 * Similar to zint_mod_small_unsigned(), except that d may be signed.
 * Extra parameter is Rx = 2^(31*dlen) mod p.
 */
word32 zint_mod_small_signed(const word32* d, size_t dlen,
    word32 p, word32 p0i, word32 R2, word32 Rx)
{
    word32 z;

    if (dlen == 0) {
        return 0;
    }
    z = zint_mod_small_unsigned(d, dlen, p, p0i, R2);
    z = modp_sub(z, Rx & -(d[dlen - 1] >> 30), p);
    return z;
}

/*
 * Add y*s to x. x and y initially have length 'len' words; the new x
 * has length 'len+1' words. 's' must fit on 31 bits. x[] and y[] must
 * not overlap.
 */
void zint_add_mul_small(word32* x, const word32* y, size_t len, word32 s)
{
    size_t u;
    word32 cc;

    cc = 0;
    for (u = 0; u < len; u ++) {
        word32 xw, yw;
        word64 z;

        xw = x[u];
        yw = y[u];
        z = (word64)yw * (word64)s + (word64)xw + (word64)cc;
        x[u] = (word32)z & 0x7FFFFFFF;
        cc = (word32)(z >> 31);
    }
    x[len] = cc;
}

/*
 * Normalize a modular integer around 0: if x > p/2, then x is replaced
 * with x - p (signed encoding with two's complement); otherwise, x is
 * untouched. The two integers x and p are encoded over the same length.
 */
void zint_norm_zero(word32* x, const word32* p, size_t len)
{
    size_t u;
    word32 r, bb;

    /*
     * Compare x with p/2. We use the shifted version of p, and p
     * is odd, so we really compare with (p-1)/2; we want to perform
     * the subtraction if and only if x > (p-1)/2.
     */
    r = 0;
    bb = 0;
    u = len;
    while (u -- > 0) {
        word32 wx, wp, cc;

        /*
         * Get the two words to compare in wx and wp (both over
         * 31 bits exactly).
         */
        wx = x[u];
        wp = (p[u] >> 1) | (bb << 30);
        bb = p[u] & 1;

        /*
         * We set cc to -1, 0 or 1, depending on whether wp is
         * lower than, equal to, or greater than wx.
         */
        cc = wp - wx;
        cc = ((-cc) >> 31) | -(cc >> 31);

        /*
         * If r != 0 then it is either 1 or -1, and we keep its
         * value. Otherwise, if r = 0, then we replace it with cc.
         */
        r |= cc & ((r & 1) - 1);
    }

    /*
     * At this point, r = -1, 0 or 1, depending on whether (p-1)/2
     * is lower than, equal to, or greater than x. We thus want to
     * do the subtraction only if r = -1.
     */
    zint_sub(x, p, len, r >> 31);
}

/*
 * Rebuild integers from their RNS representation. There are 'num'
 * integers, and each consists in 'xlen' words. 'xx' points at the
 * first word of the first integer; subsequent integers are accessed
 * by adding 'xstride' repeatedly.
 *
 * The words of an integer are the RNS representation of that integer,
 * using the provided 'primes' as moduli. This function replaces
 * each integer with its multi-word value (little-endian order).
 *
 * If "normalize_signed" is non-zero, then the returned value is
 * normalized to the -m/2..m/2 interval (where m is the product of all
 * small prime moduli); two's complement is used for negative values.
 */
void zint_rebuild_CRT(word32* xx, size_t xlen, size_t xstride,
    size_t num, const falcon_small_prime* primes, int normalize_signed,
    word32* tmp)
{
    size_t u;
    word32* x;

    tmp[0] = primes[0].p;
    for (u = 1; u < xlen; u ++) {
        /*
         * At the entry of each loop iteration:
         *  - the first u words of each array have been
         *    reassembled;
         *  - the first u words of tmp[] contains the
         * product of the prime moduli processed so far.
         *
         * We call 'q' the product of all previous primes.
         */
        word32 p, p0i, s, R2;
        size_t v;

        p = primes[u].p;
        s = primes[u].s;
        p0i = modp_ninv31(p);
        R2 = modp_R2(p, p0i);

        for (v = 0, x = xx; v < num; v ++, x += xstride) {
            word32 xp, xq, xr;
            /*
             * xp = the integer x modulo the prime p for this
             *      iteration
             * xq = (x mod q) mod p
             */
            xp = x[u];
            xq = zint_mod_small_unsigned(x, u, p, p0i, R2);

            /*
             * New value is (x mod q) + q * (s * (xp - xq) mod p)
             */
            xr = modp_montymul(s, modp_sub(xp, xq, p), p, p0i);
            zint_add_mul_small(x, tmp, u, xr);
        }

        /*
         * Update product of primes in tmp[].
         */
        tmp[u] = zint_mul_small(tmp, u, p);
    }

    /*
     * Normalize the reconstructed values around 0.
     */
    if (normalize_signed) {
        for (u = 0, x = xx; u < num; u ++, x += xstride) {
            zint_norm_zero(x, tmp, xlen);
        }
    }
}

/*
 * Negate a big integer conditionally: value a is replaced with -a if
 * and only if ctl = 1. Control value ctl must be 0 or 1.
 */
void zint_negate(word32* a, size_t len, word32 ctl)
{
    size_t u;
    word32 cc, m;

    /*
     * If ctl = 1 then we flip the bits of a by XORing with
     * 0x7FFFFFFF, and we add 1 to the value. If ctl = 0 then we XOR
     * with 0 and add 0, which leaves the value unchanged.
     */
    cc = ctl;
    m = -ctl >> 1;
    for (u = 0; u < len; u ++) {
        word32 aw;

        aw = a[u];
        aw = (aw ^ m) + cc;
        a[u] = aw & 0x7FFFFFFF;
        cc = aw >> 31;
    }
}

/*
 * Replace a with (a*xa+b*xb)/(2^31) and b with (a*ya+b*yb)/(2^31).
 * The low bits are dropped (the caller should compute the coefficients
 * such that these dropped bits are all zeros). If either or both
 * yields a negative value, then the value is negated.
 *
 * Returned value is:
 *  0  both values were positive
 *  1  new a had to be negated
 *  2  new b had to be negated
 *  3  both new a and new b had to be negated
 *
 * Coefficients xa, xb, ya and yb may use the full signed 32-bit range.
 */
word32 zint_co_reduce(word32* a, word32* b, size_t len,
    sword64 xa, sword64 xb, sword64 ya, sword64 yb)
{
    size_t u;
    sword64 cca, ccb;
    word32 nega, negb;

    cca = 0;
    ccb = 0;
    for (u = 0; u < len; u ++) {
        word32 wa, wb;
        word64 za, zb;

        wa = a[u];
        wb = b[u];
        za = wa * (word64)xa + wb * (word64)xb + (word64)cca;
        zb = wa * (word64)ya + wb * (word64)yb + (word64)ccb;
        if (u > 0) {
            a[u - 1] = (word32)za & 0x7FFFFFFF;
            b[u - 1] = (word32)zb & 0x7FFFFFFF;
        }
        cca = (sword64)za >> 31;
        ccb = (sword64)zb >> 31;
    }
    a[len - 1] = (word32)cca;
    b[len - 1] = (word32)ccb;

    nega = (word32)((word64)cca >> 63);
    negb = (word32)((word64)ccb >> 63);
    zint_negate(a, len, nega);
    zint_negate(b, len, negb);
    return nega | (negb << 1);
}

/*
 * Finish modular reduction. Rules on input parameters:
 *
 *   if neg = 1, then -m <= a < 0
 *   if neg = 0, then 0 <= a < 2*m
 *
 * If neg = 0, then the top word of a[] is allowed to use 32 bits.
 *
 * Modulus m must be odd.
 */
void zint_finish_mod(word32* a, size_t len, const word32* m, word32 neg)
{
    size_t u;
    word32 cc, xm, ym;

    /*
     * First pass: compare a (assumed nonnegative) with m. Note that
     * if the top word uses 32 bits, subtracting m must yield a
     * value less than 2^31 since a < 2*m.
     */
    cc = 0;
    for (u = 0; u < len; u ++) {
        cc = (a[u] - m[u] - cc) >> 31;
    }

    /*
     * If neg = 1 then we must add m (regardless of cc)
     * If neg = 0 and cc = 0 then we must subtract m
     * If neg = 0 and cc = 1 then we must do nothing
     *
     * In the loop below, we conditionally subtract either m or -m
     * from a. Word xm is a word of m (if neg = 0) or -m (if neg = 1);
     * but if neg = 0 and cc = 1, then ym = 0 and it forces mw to 0.
     */
    xm = -neg >> 1;
    ym = -(neg | (1 - cc));
    cc = neg;
    for (u = 0; u < len; u ++) {
        word32 aw, mw;

        aw = a[u];
        mw = (m[u] ^ xm) & ym;
        aw = aw - mw - cc;
        a[u] = aw & 0x7FFFFFFF;
        cc = aw >> 31;
    }
}

/*
 * Replace a with (a*xa+b*xb)/(2^31) mod m, and b with
 * (a*ya+b*yb)/(2^31) mod m. Modulus m must be odd; m0i = -1/m[0] mod 2^31.
 */
void zint_co_reduce_mod(word32* a, word32* b, const word32* m, size_t len,
    word32 m0i, sword64 xa, sword64 xb, sword64 ya, sword64 yb)
{
    size_t u;
    sword64 cca, ccb;
    word32 fa, fb;

    /*
     * These are actually four combined Montgomery multiplications.
     */
    cca = 0;
    ccb = 0;
    fa = ((a[0] * (word32)xa + b[0] * (word32)xb) * m0i) & 0x7FFFFFFF;
    fb = ((a[0] * (word32)ya + b[0] * (word32)yb) * m0i) & 0x7FFFFFFF;
    for (u = 0; u < len; u ++) {
        word32 wa, wb;
        word64 za, zb;

        wa = a[u];
        wb = b[u];
        za = wa * (word64)xa + wb * (word64)xb
             + m[u] * (word64)fa + (word64)cca;
        zb = wa * (word64)ya + wb * (word64)yb
             + m[u] * (word64)fb + (word64)ccb;
        if (u > 0) {
            a[u - 1] = (word32)za & 0x7FFFFFFF;
            b[u - 1] = (word32)zb & 0x7FFFFFFF;
        }
        cca = (sword64)za >> 31;
        ccb = (sword64)zb >> 31;
    }
    a[len - 1] = (word32)cca;
    b[len - 1] = (word32)ccb;

    /*
     * At this point:
     *   -m <= a < 2*m
     *   -m <= b < 2*m
     * (this is a case of Montgomery reduction)
     * The top words of 'a' and 'b' may have a 32-th bit set.
     * We want to add or subtract the modulus, as required.
     */
    zint_finish_mod(a, len, m, (word32)((word64)cca >> 63));
    zint_finish_mod(b, len, m, (word32)((word64)ccb >> 63));
}

/*
 * Compute a GCD between two positive big integers x and y. The two
 * integers must be odd. Returned value is 1 if the GCD is 1, 0
 * otherwise. When 1 is returned, arrays u and v are filled with values
 * such that:
 *   0 <= u <= y
 *   0 <= v <= x
 *   x*u - y*v = 1
 * x[] and y[] are unmodified. Both input values must have the same
 * encoded length. Temporary array must be large enough to accommodate 4
 * extra values of that length. Arrays u, v and tmp may not overlap with
 * each other, or with either x or y.
 *
 * This is a binary GCD, but it runs in CONSTANT TIME: x and y are derived from
 * the secret polynomials during key generation, so the control flow and memory
 * access pattern must not depend on their values. That is why the loops are
 * fixed-count and every conditional is expressed with bit masks / sign bits
 * rather than data-dependent branches or early exits -- the structure that can
 * look "inefficient" is exactly what keeps the private key off the timing side
 * channel. It is still fast: the top words drive per-iteration reduction factors
 * that shrink the operands by ~31 bits at a time (word-wise, not bit-by-bit).
 */
int zint_bezout(word32* u, word32* v, const word32* x, const word32* y,
    size_t len, word32* tmp)
{
    /*
     * Algorithm is an extended binary GCD. We maintain 6 values
     * a, b, u0, u1, v0 and v1 with the following invariants:
     *
     *  a = x*u0 - y*v0
     *  b = x*u1 - y*v1
     *  0 <= a <= x
     *  0 <= b <= y
     *  0 <= u0 < y
     *  0 <= v0 < x
     *  0 <= u1 <= y
     *  0 <= v1 < x
     *
     * Initial values are:
     *  a = x   u0 = 1   v0 = 0
     *  b = y   u1 = y   v1 = x-1
     *
     * Each iteration reduces either a or b, and maintains the
     * invariants. Algorithm stops when a = b, at which point their
     * common value is GCD(a,b) and (u0,v0) (or (u1,v1)) contains
     * the values (u,v) we want to return.
     *
     * The presentation is bit-by-bit, but can be sped up by working
     * on the top words and low word of a and b, computing reduction
     * parameters pa, pb, qa and qb such that the new values for a and
     * b are:
     *    a' = (a*pa + b*pb) / (2^31)
     *    b' = (a*qa + b*qb) / (2^31)
     * the two divisions being exact. Each such step reduces the total
     * length (sum of lengths of a and b) by at least 30 bits.
     */
    word32 *u0, *u1, *v0, *v1, *a, *b;
    word32 x0i, y0i;
    word32 num, rc;
    size_t j;

    if (len == 0) {
        return 0;
    }

    /*
     * u0 and v0 are the u and v result buffers; the four other
     * values (u1, v1, a and b) are taken from tmp[].
     */
    u0 = u;
    v0 = v;
    u1 = tmp;
    v1 = u1 + len;
    a = v1 + len;
    b = a + len;

    /*
     * We'll need the Montgomery reduction coefficients.
     */
    x0i = modp_ninv31(x[0]);
    y0i = modp_ninv31(y[0]);

    /*
     * Initialize a, b, u0, u1, v0 and v1.
     *  a = x   u0 = 1   v0 = 0
     *  b = y   u1 = y   v1 = x-1
     * Note that x is odd, so computing x-1 is easy.
     */
    XMEMCPY(a, x, len * sizeof *x);
    XMEMCPY(b, y, len * sizeof *y);
    u0[0] = 1;
    XMEMSET(u0 + 1, 0, (len - 1) * sizeof *u0);
    XMEMSET(v0, 0, len * sizeof *v0);
    XMEMCPY(u1, y, len * sizeof *u1);
    XMEMCPY(v1, x, len * sizeof *v1);
    v1[0] --;

    /*
     * Each input operand may be as large as 31*len bits, and we
     * reduce the total length by at least 30 bits at each iteration.
     */
    for (num = 62 * (word32)len + 30; num >= 30; num -= 30) {
        word32 c0, c1;
        word32 a0, a1, b0, b1;
        word64 a_hi, b_hi;
        word32 a_lo, b_lo;
        sword64 pa, pb, qa, qb;
        int i;
        word32 r;

        /*
         * Extract the top words of a and b. If j is the highest
         * index >= 1 such that a[j] != 0 or b[j] != 0, then we
         * want (a[j] << 31) + a[j-1] and (b[j] << 31) + b[j-1].
         * If a and b are down to one word each, then we use
         * a[0] and b[0].
         */
        c0 = (word32) -1;
        c1 = (word32) -1;
        a0 = 0;
        a1 = 0;
        b0 = 0;
        b1 = 0;
        j = len;
        while (j -- > 0) {
            word32 aw, bw;

            aw = a[j];
            bw = b[j];
            a0 ^= (a0 ^ aw) & c0;
            a1 ^= (a1 ^ aw) & c1;
            b0 ^= (b0 ^ bw) & c0;
            b1 ^= (b1 ^ bw) & c1;
            c1 = c0;
            c0 &= (((aw | bw) + 0x7FFFFFFF) >> 31) - (word32)1;
        }

        /*
         * If c1 = 0, then we grabbed two words for a and b.
         * If c1 != 0 but c0 = 0, then we grabbed one word. It
         * is not possible that c1 != 0 and c0 != 0, because that
         * would mean that both integers are zero.
         */
        a1 |= a0 & c1;
        a0 &= ~c1;
        b1 |= b0 & c1;
        b0 &= ~c1;
        a_hi = ((word64)a0 << 31) + a1;
        b_hi = ((word64)b0 << 31) + b1;
        a_lo = a[0];
        b_lo = b[0];

        /*
         * Compute reduction factors:
         *
         *   a' = a*pa + b*pb
         *   b' = a*qa + b*qb
         *
         * such that a' and b' are both multiple of 2^31, but are
         * only marginally larger than a and b.
         */
        pa = 1;
        pb = 0;
        qa = 0;
        qb = 1;
        for (i = 0; i < 31; i ++) {
            /*
             * At each iteration:
             *
             *   a <- (a-b)/2 if: a is odd, b is odd, a_hi > b_hi
             *   b <- (b-a)/2 if: a is odd, b is odd, a_hi <= b_hi
             *   a <- a/2 if: a is even
             *   b <- b/2 if: a is odd, b is even
             *
             * We multiply a_lo and b_lo by 2 at each
             * iteration, thus a division by 2 really is a
             * non-multiplication by 2.
             */
            word32 rt, oa, ob, cAB, cBA, cA;
            word64 rz;

            /*
             * rt = 1 if a_hi > b_hi, 0 otherwise.
             */
            rz = b_hi - a_hi;
            rt = (word32)((rz ^ ((a_hi ^ b_hi)
                                   & (a_hi ^ rz))) >> 63);

            /*
             * cAB = 1 if b must be subtracted from a
             * cBA = 1 if a must be subtracted from b
             * cA = 1 if a must be divided by 2
             *
             * Rules:
             *
             *   cAB and cBA cannot both be 1.
             *   If a is not divided by 2, b is.
             */
            oa = (a_lo >> i) & 1;
            ob = (b_lo >> i) & 1;
            cAB = oa & ob & rt;
            cBA = oa & ob & ~rt;
            cA = cAB | (oa ^ 1);

            /*
             * Conditional subtractions.
             */
            a_lo -= b_lo & -cAB;
            a_hi -= b_hi & -(word64)cAB;
            pa -= qa & -(sword64)cAB;
            pb -= qb & -(sword64)cAB;
            b_lo -= a_lo & -cBA;
            b_hi -= a_hi & -(word64)cBA;
            qa -= pa & -(sword64)cBA;
            qb -= pb & -(sword64)cBA;

            /*
             * Shifting.
             */
            a_lo += a_lo & (cA - 1);
            pa += pa & ((sword64)cA - 1);
            pb += pb & ((sword64)cA - 1);
            a_hi ^= (a_hi ^ (a_hi >> 1)) & -(word64)cA;
            b_lo += b_lo & -cA;
            qa += qa & -(sword64)cA;
            qb += qb & -(sword64)cA;
            b_hi ^= (b_hi ^ (b_hi >> 1)) & ((word64)cA - 1);
        }

        /*
         * Apply the computed parameters to our values. We
         * may have to correct pa and pb depending on the
         * returned value of zint_co_reduce() (when a and/or b
         * had to be negated).
         */
        r = zint_co_reduce(a, b, len, pa, pb, qa, qb);
        pa -= (pa + pa) & -(sword64)(r & 1);
        pb -= (pb + pb) & -(sword64)(r & 1);
        qa -= (qa + qa) & -(sword64)(r >> 1);
        qb -= (qb + qb) & -(sword64)(r >> 1);
        zint_co_reduce_mod(u0, u1, y, len, y0i, pa, pb, qa, qb);
        zint_co_reduce_mod(v0, v1, x, len, x0i, pa, pb, qa, qb);
    }

    /*
     * At that point, array a[] should contain the GCD, and the
     * results (u,v) should already be set. We check that the GCD
     * is indeed 1. We also check that the two operands x and y
     * are odd.
     */
    rc = a[0] ^ 1;
    for (j = 1; j < len; j ++) {
        rc |= a[j];
    }
    return (int)((1 - ((rc | -rc) >> 31)) & x[0] & y[0]);
}

/*
 * Add k*y*2^sc to x. The result is assumed to fit in the array of
 * size xlen (truncation is applied if necessary).
 * Scale factor 'sc' is provided as sch and scl, such that:
 *   sch = sc / 31
 *   scl = sc % 31
 * xlen MUST NOT be lower than ylen.
 *
 * x[] and y[] are both signed integers, using two's complement for
 * negative values.
 */
void zint_add_scaled_mul_small(word32* x, size_t xlen,
    const word32* y, size_t ylen, sword32 k, word32 sch, word32 scl)
{
    size_t u;
    word32 ysign, tw;
    sword32 cc;

    if (ylen == 0) {
        return;
    }

    ysign = -(y[ylen - 1] >> 30) >> 1;
    tw = 0;
    cc = 0;
    for (u = sch; u < xlen; u ++) {
        size_t v;
        word32 wy, wys, ccu;
        word64 z;

        /*
         * Get the next word of y (scaled).
         */
        v = u - sch;
        if (v < ylen) {
            wy = y[v];
        } else {
            wy = ysign;
        }
        wys = ((wy << scl) & 0x7FFFFFFF) | tw;
        tw = wy >> (31 - scl);

        /*
         * The expression below does not overflow.
         */
        z = (word64)((sword64)wys * (sword64)k + (sword64)x[u] + cc);
        x[u] = (word32)z & 0x7FFFFFFF;

        /*
         * Right-shifting the signed value z would yield
         * implementation-defined results (arithmetic shift is
         * not guaranteed). However, we can cast to unsigned,
         * and get the next carry as an unsigned word. We can
         * then convert it back to signed.
         */
        ccu = (word32)(z >> 31);
        cc = (sword32)ccu;
    }
}

/*
 * Subtract y*2^sc from x. The result is assumed to fit in the array of
 * size xlen (truncation is applied if necessary).
 * Scale factor 'sc' is provided as sch and scl, such that:
 *   sch = sc / 31
 *   scl = sc % 31
 * xlen MUST NOT be lower than ylen.
 *
 * x[] and y[] are both signed integers, using two's complement for
 * negative values.
 */
void zint_sub_scaled(word32* x, size_t xlen,
    const word32* y, size_t ylen, word32 sch, word32 scl)
{
    size_t u;
    word32 ysign, tw;
    word32 cc;

    if (ylen == 0) {
        return;
    }

    ysign = -(y[ylen - 1] >> 30) >> 1;
    tw = 0;
    cc = 0;
    for (u = sch; u < xlen; u ++) {
        size_t v;
        word32 w, wy, wys;

        /*
         * Get the next word of y (scaled).
         */
        v = u - sch;
        if (v < ylen) {
            wy = y[v];
        } else {
            wy = ysign;
        }
        wys = ((wy << scl) & 0x7FFFFFFF) | tw;
        tw = wy >> (31 - scl);

        w = x[u] - wys - cc;
        x[u] = w & 0x7FFFFFFF;
        cc = w >> 31;
    }
}

/*
 * Convert a one-word signed big integer into a signed value.
 */
sword32 zint_one_to_plain(const word32* x)
{
    word32 w;

    w = x[0];
    w |= (w & 0x40000000) << 1;
    return (sword32)w;
}




/* Maximum bit width used to encode f and g, indexed by logn (0..10).
 * From the Falcon reference (codec.c). */
static const byte falcon_max_fg_bits[] = {
    /* logn: 0  1  2  3  4  5  6  7  8  9 10 */
             0, 8, 8, 8, 8, 8, 7, 7, 6, 6, 5
};

/* Maximum bit width used to encode F (and G): a constant 8 for every degree in
 * the Falcon reference (codec.c), so no per-logn table is needed (unlike
 * falcon_max_fg_bits, which varies with logn). */
#define FALCON_MAX_FG_BITS 8

/* ------------------------------------------------------------------------ */

/* Pack the public key polynomial h: n coefficients, 14 bits each, packed
 * most-significant bit first. Inverse of falcon_modq_decode. Returns the number
 * of bytes written, or 0 on a coefficient >= q or output overflow. */
size_t falcon_modq_encode(byte* out, size_t max_out, const word16* x,
        unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t out_len = ((n * 14) + 7) >> 3;
    size_t u, v;
    word32 acc = 0;
    int acc_len = 0;

    for (u = 0; u < n; u++) {
        if (x[u] >= FALCON_Q) {
            return 0;
        }
    }
    if (out_len > max_out) {
        return 0;
    }

    v = 0;
    for (u = 0; u < n; u++) {
        acc = (acc << 14) | (word32)x[u];
        acc_len += 14;
        while (acc_len >= 8) {
            acc_len -= 8;
            out[v++] = (byte)(acc >> acc_len);
        }
    }
    if (acc_len > 0) {
        out[v++] = (byte)(acc << (8 - acc_len));
    }
    return out_len;
}

/* ------------------------------------------------------------------------ */

/* Compress the signature polynomial s2 with Golomb-Rice coding (k=7). Exact
 * inverse of the reference comp_decode. Returns the number of bytes written, or
 * 0 if any |x[i]| > 2047 or the output buffer overflows. */
size_t falcon_comp_encode(byte* out, size_t max_out, const sword16* x,
        unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t u, v;
    word32 acc = 0;
    unsigned acc_len = 0;

    /* All coefficients must fit in the -2047..+2047 range. */
    for (u = 0; u < n; u++) {
        if (x[u] < -2047 || x[u] > 2047) {
            return 0;
        }
    }

    v = 0;
    for (u = 0; u < n; u++) {
        int t;
        unsigned w;

        /* Sign bit (1 for negative), then the low 7 bits of |x|. */
        acc <<= 1;
        t = (int)x[u];
        if (t < 0) {
            t = -t;
            acc |= 1;
        }
        w = (unsigned)t;

        acc <<= 7;
        acc |= w & 127u;
        w >>= 7;
        acc_len += 8;

        /* Unary high part: w zero bits then a terminating one. The absolute
         * value is at most 2047, so w <= 15 here and at most 16 bits are added;
         * combined with the 8 bits above and up to 7 carried bits, the 32-bit
         * accumulator never overflows. */
        acc <<= (w + 1);
        acc |= 1;
        acc_len += w + 1;

        while (acc_len >= 8) {
            acc_len -= 8;
            if (v >= max_out) {
                return 0;
            }
            out[v++] = (byte)(acc >> acc_len);
        }
    }

    /* Flush any remaining bits, left-aligned in the final byte. */
    if (acc_len > 0) {
        if (v >= max_out) {
            return 0;
        }
        out[v++] = (byte)(acc << (8 - acc_len));
    }
    return v;
}

/* ------------------------------------------------------------------------ */

/* Pack n signed 8-bit coefficients, each in 'bits' bits, MSB first. The valid
 * range is -(2^(bits-1)-1) .. +(2^(bits-1)-1); the most-negative value is not
 * representable. Returns bytes written, or 0 on range violation / overflow. */
size_t falcon_trim_i8_encode(byte* out, size_t max_out, const sword8* x,
        unsigned logn, unsigned bits)
{
    size_t n = (size_t)1 << logn;
    size_t out_len = ((n * bits) + 7) >> 3;
    size_t u, v;
    int minv, maxv;
    word32 acc = 0, mask;
    unsigned acc_len = 0;

    /* Callers only pass falcon_max_fg_bits / FALCON_MAX_FG_BITS values (5..8);
     * guard the shifts below against out-of-range widths anyway. */
    if (bits < 2 || bits > 8) {
        return 0;
    }

    maxv = (1 << (bits - 1)) - 1;
    minv = -maxv;
    for (u = 0; u < n; u++) {
        if (x[u] < minv || x[u] > maxv) {
            return 0;
        }
    }
    if (out_len > max_out) {
        return 0;
    }

    mask = ((word32)1 << bits) - 1;
    v = 0;
    for (u = 0; u < n; u++) {
        acc = (acc << bits) | ((word32)(byte)x[u] & mask);
        acc_len += bits;
        while (acc_len >= 8) {
            acc_len -= 8;
            out[v++] = (byte)(acc >> acc_len);
        }
    }
    if (acc_len > 0) {
        out[v++] = (byte)(acc << (8 - acc_len));
    }
    return out_len;
}

/* Unpack n signed 8-bit coefficients packed at 'bits' bits each (MSB first).
 * The most-negative value -2^(bits-1) is rejected. Trailing pad bits in the
 * final byte must be zero. Returns bytes consumed, or 0 on any violation. */
size_t falcon_trim_i8_decode(sword8* x, unsigned logn, unsigned bits,
        const byte* in, size_t max_in)
{
    size_t n = (size_t)1 << logn;
    size_t in_len = ((n * bits) + 7) >> 3;
    size_t u, v;
    word32 acc = 0, mask1, mask2;
    unsigned acc_len = 0;

    /* Same defensive width guard as falcon_trim_i8_encode. */
    if (bits < 2 || bits > 8) {
        return 0;
    }

    if (in_len > max_in) {
        return 0;
    }

    mask1 = ((word32)1 << bits) - 1;
    mask2 = (word32)1 << (bits - 1);
    u = 0;
    v = 0;
    while (u < n) {
        acc = (acc << 8) | (word32)in[v++];
        acc_len += 8;
        while (acc_len >= bits && u < n) {
            word32 w;

            acc_len -= bits;
            w = (acc >> acc_len) & mask1;
            /* Sign-extend from the high bit. */
            w |= (word32)(-(sword32)(w & mask2));
            if (w == (word32)(-(sword32)mask2)) {
                /* The -2^(bits-1) value is forbidden. */
                return 0;
            }
            x[u++] = (sword8)(sword32)w;
        }
    }
    /* Extra bits in the last consumed byte must be zero. */
    if ((acc & (((word32)1 << acc_len) - 1)) != 0) {
        return 0;
    }
    return in_len;
}

/* ------------------------------------------------------------------------ */

/* Decode a Falcon secret key into its (f, g, F) basis polynomials. The encoding
 * is: header byte (0x50 | logn), then trim_i8(f, max_fg_bits[logn]),
 * trim_i8(g, max_fg_bits[logn]), trim_i8(F, max_FG_bits[logn]). G is not stored
 * (it is recomputed from f, g, F at use time). The header and an exact length
 * match are both validated. */
int falcon_privkey_decode(const byte* sk, size_t sklen, sword8* f, sword8* g,
        sword8* F, unsigned logn)
{
    size_t u, v;

    if (sk == NULL || f == NULL || g == NULL || F == NULL) {
        return BAD_FUNC_ARG;
    }
    if (logn < 1 || logn > 10) {
        return BAD_FUNC_ARG;
    }
    if (sklen < 1) {
        return BUFFER_E;
    }
    if (sk[0] != (byte)(0x50 | logn)) {
        return ASN_PARSE_E;
    }

    u = 1;
    v = falcon_trim_i8_decode(f, logn, falcon_max_fg_bits[logn],
            sk + u, sklen - u);
    if (v == 0) {
        return ASN_PARSE_E;
    }
    u += v;

    v = falcon_trim_i8_decode(g, logn, falcon_max_fg_bits[logn],
            sk + u, sklen - u);
    if (v == 0) {
        return ASN_PARSE_E;
    }
    u += v;

    v = falcon_trim_i8_decode(F, logn, FALCON_MAX_FG_BITS,
            sk + u, sklen - u);
    if (v == 0) {
        return ASN_PARSE_E;
    }
    u += v;

    /* The whole secret key must be consumed exactly. */
    if (u != sklen) {
        return ASN_PARSE_E;
    }
    return 0;
}

/* Encode a Falcon secret key from its (f, g, F) basis: header byte
 * (0x50 | logn), then trim_i8(f), trim_i8(g) at max_fg_bits[logn] and
 * trim_i8(F) at max_FG_bits[logn]. Returns the number of bytes written, or 0 on
 * range violation / output overflow. */
size_t falcon_privkey_encode(byte* sk, size_t max_sk, const sword8* f,
        const sword8* g, const sword8* F, unsigned logn)
{
    size_t u, v;

    if (sk == NULL || f == NULL || g == NULL || F == NULL) {
        return 0;
    }
    if (logn < 1 || logn > 10) {
        return 0;
    }
    if (max_sk < 1) {
        return 0;
    }
    sk[0] = (byte)(0x50 | logn);
    u = 1;

    v = falcon_trim_i8_encode(sk + u, max_sk - u, f, logn,
            falcon_max_fg_bits[logn]);
    if (v == 0) {
        return 0;
    }
    u += v;

    v = falcon_trim_i8_encode(sk + u, max_sk - u, g, logn,
            falcon_max_fg_bits[logn]);
    if (v == 0) {
        return 0;
    }
    u += v;

    v = falcon_trim_i8_encode(sk + u, max_sk - u, F, logn,
            FALCON_MAX_FG_BITS);
    if (v == 0) {
        return 0;
    }
    u += v;

    return u;
}





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
 * curve from 1.1165 (n=2) to 1.2983 (n=1024). Falcon uses logn 9 and 10:
 *   logn = 9  (Falcon-512 ) : 1.2778336969128337
 *   logn = 10 (Falcon-1024) : 1.298280334344292            */
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
    int ret;

    /* Once the sticky error is latched the stream is already invalid and the
     * result will be rejected; don't keep re-issuing failing squeezes. */
    if (p->err != 0) {
        p->ptr = 0;
        p->len = 0;
        return p->err;
    }
    ret = wc_Shake256_SqueezeBlocks(&p->shake, p->buf, FALCON_PRNG_BLOCKS);
    p->ptr = 0;
    p->len = (ret == 0) ? (word32)FALCON_PRNG_BUFLEN : 0;
    /* Latch the first failure. get_u8/get_u64 have no error return, so a squeeze
     * failure is made sticky here and checked by the signer (falcon_sign_core),
     * which rejects any signature produced from an invalid PRNG state instead of
     * consuming stale buffer bytes. */
    if (ret != 0)
        p->err = ret;
    return ret;
}

int falcon_prng_init(falcon_prng* p, WC_RNG* rng)
{
    byte seed[FALCON_PRNG_SEED_LEN];
    int  ret;

    if (p == NULL || rng == NULL)
        return BAD_FUNC_ARG;

    p->ptr = 0;
    p->len = 0;
    p->err = 0;

    ret = wc_RNG_GenerateBlock(rng, seed, (word32)sizeof(seed));
    if (ret == 0) {
        ret = wc_InitShake256(&p->shake, NULL, INVALID_DEVID);
        if (ret == 0) {
            ret = wc_Shake256_Absorb(&p->shake, seed, (word32)sizeof(seed));
            if (ret == 0)
                ret = falcon_prng_refill(p);
            /* On failure past a successful init the caller never sees a live
             * context (falcon_native_sign_msg only frees the sponge when this
             * function succeeded), so release it here. This matters in
             * WOLFSSL_ASYNC_CRYPT builds where wc_InitShake256 allocates a
             * device context. */
            if (ret != 0)
                wc_Shake256_Free(&p->shake);
        }
    }
    ForceZero(seed, (word32)sizeof(seed));

    return ret;
}

byte falcon_prng_get_u8(falcon_prng* p)
{
    byte v;

    /* On a refill failure len becomes 0 and p->err is latched; the buffer read
     * below stays in bounds (ptr reset to 0) but yields a discarded value --
     * falcon_sign_core checks p->err and rejects the resulting signature. */
    if (p->ptr + 1U > p->len)
        (void)falcon_prng_refill(p);
    v = p->buf[p->ptr];
    p->ptr += 1U;
    return v;
}

/* Read a little-endian word64 from a (possibly unaligned) byte buffer. Falcon's
 * PRNG output is consumed little-endian on every platform, so this is a single
 * load on a little-endian CPU and a load plus byte-swap on a big-endian one --
 * one endian-aware helper instead of the explicit 8-byte assembly (which some
 * compilers do not coalesce into a word load). */
static WC_INLINE word64 falcon_load_le64(const byte* b)
{
    word64 v = readUnalignedWord64(b);
#ifdef BIG_ENDIAN_ORDER
    v = ByteReverseWord64(v);
#endif
    return v;
}

word64 falcon_prng_get_u64(falcon_prng* p)
{
    word64 v;
    word32 i;

    if (p->ptr + 8U > p->len)
        (void)falcon_prng_refill(p);
    i = p->ptr;
    v = falcon_load_le64(&p->buf[i]);
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

        /* A wedged PRNG (latched sticky error) turns every squeezed byte into
         * a constant, which can make the rejection test below deterministic --
         * and, if it rejects, this loop endless. Bail out instead: the value
         * returned is discarded, as falcon_sign_core rejects the entire
         * signature whenever p.err is set. */
        if (spc->p.err != 0) {
            return s;
        }

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




#define MKN(logn)   ((size_t)1 << (logn))

#define FALCON_Q     12289

/* IEEE-754 binary64 bit patterns (the fpr seam carries doubles as word64).
 * These mirror the named constants in the reference fpr.h that are not part of
 * the fpr seam declared above. */
static const fpr fpr_q         = 4667981563525332992ULL; /* (double)12289      */
static const fpr fpr_bnorm_max = 4670353323383631276ULL; /* 1.17^2 * q bound   */

/* Per-level coefficient bounds, indexed by logn (1..10). Ported from the
 * reference codec.c (max_fg_bits / max_FG_bits). */

/* Required temporary buffer size, in bytes, indexed by logn (1..10). This is
 * 28*2^logn bytes, except for the smallest degrees. Ported from the reference
 * inner.h FALCON_KEYGEN_TEMP_* macros. */
static const size_t FALCON_KEYGEN_TEMP[] = {
    0, 136, 272, 224, 448, 896, 1792, 3584, 7168, 14336, 28672
};

/* ==================================================================== */
/* modp helper local to keygen (not part of the shared bigint API).      */

/*
 * Given polynomial f in NTT representation modulo p, compute f' of degree
 * less than N/2 such that f' = f0^2 - X*f1^2 (the resultant recursion step
 * used in the binary depth-1 solver).
 */
static void modp_poly_rec_res(word32* f, unsigned logn,
        word32 p, word32 p0i, word32 R2)
{
    size_t hn, u;

    hn = (size_t)1 << (logn - 1);
    for (u = 0; u < hn; u++) {
        word32 w0, w1;

        w0 = f[(u << 1) + 0];
        w1 = f[(u << 1) + 1];
        f[u] = modp_montymul(modp_montymul(w0, w1, p, p0i), R2, p, p0i);
    }
}

/* ==================================================================== */
/* SHAKE256 stream RNG (seeded from WC_RNG).                             */

typedef struct {
    wc_Shake shake;
    byte buf[WC_SHA3_256_BLOCK_SIZE];   /* 136-byte SHAKE256 rate block */
    size_t ptr;                          /* next unread byte in buf      */
    int err;                             /* sticky squeeze error         */
} falcon_rng;

static int falcon_rng_init(falcon_rng* r, WC_RNG* rng, void* heap)
{
    byte seed[48];
    int ret;

    XMEMSET(r, 0, sizeof(*r));
    ret = wc_RNG_GenerateBlock(rng, seed, (word32)sizeof(seed));
    if (ret != 0) {
        return ret;
    }
    ret = wc_InitShake256(&r->shake, heap, INVALID_DEVID);
    if (ret != 0) {
        return ret;
    }
    ret = wc_Shake256_Absorb(&r->shake, seed, (word32)sizeof(seed));
    if (ret != 0) {
        wc_Shake256_Free(&r->shake);
        return ret;
    }
    /* Force a squeeze on the first extraction. */
    r->ptr = sizeof(r->buf);
    wc_ForceZero(seed, sizeof(seed));   /* seed determines the secret key */
    return 0;
}

static void falcon_rng_free(falcon_rng* r)
{
    wc_Shake256_Free(&r->shake);
    /* The SHAKE sponge state and buffer derive the secret key. */
    wc_ForceZero(r, sizeof(*r));
}

/*
 * Get a random 8-byte integer from the SHAKE256 stream, in little-endian
 * order (consistent interpretation across platforms). The rate block is
 * 136 bytes = 17 * 8, so 8 always divides evenly into a fresh block.
 */
static word64 get_rng_u64(falcon_rng* r)
{
    const byte* p;
    word64 v;

    if (r->ptr >= sizeof(r->buf)) {
        int ret = wc_Shake256_SqueezeBlocks(&r->shake, r->buf, 1);
        if (ret != 0) {
            r->err = ret;
        }
        r->ptr = 0;
    }
    p = r->buf + r->ptr;
    r->ptr += 8;
    v = falcon_load_le64(p);
    return v;
}

/* ==================================================================== */
/* Self-contained mod-q (q = 12289) negacyclic NTT used only to compute  */
/* the public key h = g/f mod q. (modp_* targets 31-bit primes, so a     */
/* dedicated small-modulus transform is used for q here.)                */

static word32 mq_modpow(word32 b, word32 e)
{
    word64 r = 1, bb = b % FALCON_Q;
    while (e != 0) {
        if ((e & 1) != 0) {
            r = (r * bb) % FALCON_Q;
        }
        bb = (bb * bb) % FALCON_Q;
        e >>= 1;
    }
    return (word32)r;
}

static word32 mq_modinv(word32 a)
{
    return mq_modpow(a, FALCON_Q - 2);
}

static unsigned int mq_brv(unsigned int x, int bits)
{
    unsigned int r = 0;
    int i;
    for (i = 0; i < bits; i++) {
        r = (r << 1) | (x & 1);
        x >>= 1;
    }
    return r;
}

static void mq_build_tables(int logn, word32 psi, word16* zetas,
        word16* izetas)
{
    int n = 1 << logn;
    word32 ipsi = mq_modinv(psi);
    int i;
    for (i = 0; i < n; i++) {
        unsigned int e = mq_brv((unsigned int)i, logn);
        zetas[i]  = (word16)mq_modpow(psi,  e);
        izetas[i] = (word16)mq_modpow(ipsi, e);
    }
}

/* Forward negacyclic NTT, Cooley-Tukey: natural -> bit-reversed order. */
static void mq_ntt(word16* a, int n, const word16* zetas)
{
    int t = n, m, i, j;
    for (m = 1; m < n; m <<= 1) {
        t >>= 1;
        for (i = 0; i < m; i++) {
            word32 z = zetas[m + i];
            int start = 2 * i * t;
            for (j = start; j < start + t; j++) {
                word32 u = a[j];
                word32 v = (word32)(((word64)a[j + t] * z) % FALCON_Q);
                a[j]     = (word16)((u + v) % FALCON_Q);
                a[j + t] = (word16)((u + FALCON_Q - v) % FALCON_Q);
            }
        }
    }
}

/* Inverse negacyclic NTT, Gentleman-Sande: bit-reversed -> natural order. */
static void mq_intt(word16* a, int n, const word16* izetas)
{
    int t = 1, m, i, j;
    word32 ninv;
    for (m = n; m > 1; m >>= 1) {
        int h = m >> 1;
        int j1 = 0;
        for (i = 0; i < h; i++) {
            word32 z = izetas[h + i];
            int start = j1;
            for (j = start; j < start + t; j++) {
                word32 u = a[j];
                word32 v = a[j + t];
                a[j]     = (word16)((u + v) % FALCON_Q);
                a[j + t] = (word16)(((word64)((u + FALCON_Q - v) % FALCON_Q)
                                * z) % FALCON_Q);
            }
            j1 += 2 * t;
        }
        t <<= 1;
    }
    ninv = mq_modinv((word32)n);
    for (j = 0; j < n; j++) {
        a[j] = (word16)(((word64)a[j] * ninv) % FALCON_Q);
    }
}

/*
 * Compute the public key h = g/f mod (X^n+1) mod q. Returns 1 on success, or
 * 0 if f is not invertible modulo q (i.e. some NTT coefficient of f is zero),
 * in which case the (f,g) pair is rejected. -1 is returned on allocation
 * failure.
 */
static int falcon_compute_public(word16* h, const sword8* f, const sword8* g,
        unsigned logn, void* heap)
{
    int n = 1 << logn;
    int u;
    word32 psi;
    word16* zetas;
    word16* izetas;
    word16* ff;

    zetas = (word16*)XMALLOC((size_t)3 * (size_t)n * sizeof(word16), heap,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (zetas == NULL) {
        return -1;
    }
    izetas = zetas + n;
    ff = izetas + n;

    psi = mq_modpow(11 /* generator of Z_q^* */,
            (FALCON_Q - 1) / (word32)(2 * n));
    mq_build_tables((int)logn, psi, zetas, izetas);

    for (u = 0; u < n; u++) {
        int xf = f[u], xg = g[u];
        if (xf < 0) {
            xf += FALCON_Q;
        }
        if (xg < 0) {
            xg += FALCON_Q;
        }
        ff[u] = (word16)xf;
        h[u]  = (word16)xg;
    }
    mq_ntt(ff, n, zetas);
    mq_ntt(h, n, zetas);
    for (u = 0; u < n; u++) {
        if (ff[u] == 0) {
            /* The tail of the buffer (ff) holds NTT(f) -- secret material. */
            wc_ForceZero(zetas, (word32)((size_t)3 * (size_t)n
                    * sizeof(word16)));
            XFREE(zetas, heap, DYNAMIC_TYPE_TMP_BUFFER);
            return 0;
        }
        h[u] = (word16)(((word64)h[u] * mq_modinv(ff[u])) % FALCON_Q);
    }
    mq_intt(h, n, izetas);

    /* The tail of the buffer (ff) holds NTT(f) -- secret material. */
    wc_ForceZero(zetas, (word32)((size_t)3 * (size_t)n * sizeof(word16)));
    XFREE(zetas, heap, DYNAMIC_TYPE_TMP_BUFFER);
    return 1;
}

/* ==================================================================== */
/* Polynomial <-> floating-point conversions (port of keygen.c).         */

/*
 * Convert a big-integer polynomial to floating-point. Each coefficient has
 * length flen words, and starts fstride words after the previous.
 */
static void poly_big_to_fp(fpr* d, const word32* f, size_t flen, size_t fstride,
        unsigned logn)
{
    size_t n, u;

    n = MKN(logn);
    if (flen == 0) {
        for (u = 0; u < n; u++) {
            d[u] = fpr_zero;
        }
        return;
    }
    for (u = 0; u < n; u++, f += fstride) {
        size_t v;
        word32 neg, cc, xm;
        fpr x, fsc;

        neg = -(f[flen - 1] >> 30);
        xm = neg >> 1;
        cc = neg & 1;
        x = fpr_zero;
        fsc = fpr_one;
        for (v = 0; v < flen; v++, fsc = fpr_mul(fsc, fpr_ptwo31)) {
            word32 w;

            w = (f[v] ^ xm) + cc;
            cc = w >> 31;
            w &= 0x7FFFFFFF;
            w -= (w << 1) & neg;
            x = fpr_add(x, fpr_mul(fpr_of(*(sword32*)&w), fsc));
        }
        d[u] = x;
    }
}

/*
 * Convert a polynomial to small integers. Source values are one-word signed
 * integers (31 bits). Returns 0 if any coefficient exceeds lim in absolute
 * value, 1 on success. Not constant-time (a failure discards the key).
 */
static int poly_big_to_small(sword8* d, const word32* s, int lim, unsigned logn)
{
    size_t n, u;

    n = MKN(logn);
    for (u = 0; u < n; u++) {
        sword32 z;

        z = zint_one_to_plain(s + u);
        if (z < -lim || z > lim) {
            return 0;
        }
        d[u] = (sword8)z;
    }
    return 1;
}

/*
 * Subtract k*f from F, where F, f and k are polynomials modulo X^N+1.
 * Coefficients of k are scaled by 2^sc, with sch = sc/31 and scl = sc%31.
 * Quadratic-time, space-efficient variant.
 */
static void poly_sub_scaled(word32* F, size_t Flen, size_t Fstride,
        const word32* f, size_t flen, size_t fstride,
        const sword32* k, word32 sch, word32 scl, unsigned logn)
{
    size_t n, u;

    n = MKN(logn);
    for (u = 0; u < n; u++) {
        sword32 kf;
        size_t v;
        word32* x;
        const word32* y;

        kf = -k[u];
        x = F + u * Fstride;
        y = f;
        for (v = 0; v < n; v++) {
            zint_add_scaled_mul_small(x, Flen, y, flen, kf, sch, scl);
            if (u + v == n - 1) {
                x = F;
                kf = -kf;
            }
            else {
                x += Fstride;
            }
            y += fstride;
        }
    }
}

/*
 * Subtract k*f from F using the NTT (for large degree / small integers).
 */
static void poly_sub_scaled_ntt(word32* F, size_t Flen, size_t Fstride,
        const word32* f, size_t flen, size_t fstride,
        const sword32* k, word32 sch, word32 scl, unsigned logn,
        word32* tmp)
{
    word32* gm;
    word32* igm;
    word32* fk;
    word32* t1;
    word32* x;
    const word32* y;
    size_t n, u, tlen;
    const falcon_small_prime* primes;

    n = MKN(logn);
    tlen = flen + 1;
    gm = tmp;
    igm = gm + MKN(logn);
    fk = igm + MKN(logn);
    t1 = fk + n * tlen;

    primes = FALCON_PRIMES;

    /* Compute k*f in fk[], in RNS notation. */
    for (u = 0; u < tlen; u++) {
        word32 p, p0i, R2, Rx;
        size_t v;

        p = primes[u].p;
        p0i = modp_ninv31(p);
        R2 = modp_R2(p, p0i);
        Rx = modp_Rx((unsigned)flen, p, p0i, R2);
        modp_mkgm2(gm, igm, logn, primes[u].g, p, p0i);

        for (v = 0; v < n; v++) {
            t1[v] = modp_set(k[v], p);
        }
        modp_NTT2(t1, gm, logn, p, p0i);
        for (v = 0, y = f, x = fk + u;
                v < n; v++, y += fstride, x += tlen) {
            *x = zint_mod_small_signed(y, flen, p, p0i, R2, Rx);
        }
        modp_NTT2_ext(fk + u, tlen, gm, logn, p, p0i);
        for (v = 0, x = fk + u; v < n; v++, x += tlen) {
            *x = modp_montymul(
                    modp_montymul(t1[v], *x, p, p0i), R2, p, p0i);
        }
        modp_iNTT2_ext(fk + u, tlen, igm, logn, p, p0i);
    }

    /* Rebuild k*f. */
    zint_rebuild_CRT(fk, tlen, tlen, n, primes, 1, t1);

    /* Subtract k*f, scaled, from F. */
    for (u = 0, x = F, y = fk; u < n; u++, x += Fstride, y += tlen) {
        zint_sub_scaled(x, Flen, y, tlen, sch, scl);
    }
}

/* ==================================================================== */
/* Discrete Gaussian sampler (port of keygen.c).                         */

/*
 * Discrete Gaussian distribution table for sigma = 1.17*sqrt(q/(2*N)),
 * q = 12289, N = 1024. Element 0 is P(x = 0); for k > 0 element k is
 * P(x >= k+1 | x > 0). Probabilities scaled by 2^63.
 */
static const word64 gauss_1024_12289[] = {
    1283868770400643928ULL,  6416574995475331444ULL,  4078260278032692663ULL,
    2353523259288686585ULL,  1227179971273316331ULL,   575931623374121527ULL,
    242543240509105209ULL,    91437049221049666ULL,    30799446349977173ULL,
    9255276791179340ULL,     2478152334826140ULL,      590642893610164ULL,
    125206034929641ULL,       23590435911403ULL,        3948334035941ULL,
    586753615614ULL,          77391054539ULL,           9056793210ULL,
    940121950ULL,             86539696ULL,              7062824ULL,
    510971ULL,                32764ULL,                 1862ULL,
    94ULL,                    4ULL,                    0ULL
};

/*
 * Generate one value with a Gaussian distribution centered on 0. Standard
 * deviation is 1.17*sqrt(q/(2*N)); the table is for N = 1024, and lower
 * dimensions sum several samples (sigma scales by sqrt(2)).
 */
static int mkgauss(falcon_rng* rng, unsigned logn)
{
    unsigned u, g;
    int val;

    g = 1U << (10 - logn);
    val = 0;
    for (u = 0; u < g; u++) {
        word64 r;
        word32 f, v, k, neg;

        /*
         * First value: 'neg' is a random sign; 'f' is set to 1 if the
         * generated value is zero.
         */
        r = get_rng_u64(rng);
        neg = (word32)(r >> 63);
        r &= ~((word64)1 << 63);
        f = (word32)((r - gauss_1024_12289[0]) >> 63);

        /*
         * Second value: locate the first table element not greater than
         * r (full table read for constant-time behaviour).
         */
        v = 0;
        r = get_rng_u64(rng);
        r &= ~((word64)1 << 63);
        for (k = 1; k < (word32)((sizeof gauss_1024_12289)
                / (sizeof gauss_1024_12289[0])); k++) {
            word32 t;

            t = (word32)((r - gauss_1024_12289[k]) >> 63) ^ 1;
            v |= k & -(t & (f ^ 1));
            f |= t;
        }

        /* Apply the sign (no effect when the value is zero). */
        v = (v ^ -neg) + neg;

        val += *(sword32*)&v;
    }
    return val;
}

/* ==================================================================== */
/* Length / bit-length parameter tables for the NTRU solver.             */

/*
 * MAX_BL_SMALL[depth]: word length of input f,g at that depth.
 * MAX_BL_LARGE[depth]: word length of the unreduced F,G at that depth.
 */
static const size_t MAX_BL_SMALL[] = {
    1, 1, 2, 2, 4, 7, 14, 27, 53, 106, 209
};
static const size_t MAX_BL_LARGE[] = {
    2, 2, 5, 7, 12, 21, 40, 78, 157, 308
};

/* Average / standard deviation (in bits) of the max coefficient size of
 * (f,g) per depth, used to compute Babai-reduction bounds. */
static const struct {
    int avg;
    int std;
} BITLENGTH[] = {
    {    4,  0 },
    {   11,  1 },
    {   24,  1 },
    {   50,  1 },
    {  102,  1 },
    {  202,  2 },
    {  401,  4 },
    {  794,  5 },
    { 1577,  8 },
    { 3138, 13 },
    { 6308, 25 }
};

/* Minimal recursion depth at which intermediate f,g are rebuilt. */
#define DEPTH_INT_FG   4

/*
 * Squared norm of a short vector, saturated to 2^32-1 if it reaches 2^31.
 */
static word32 poly_small_sqnorm(const sword8* f, unsigned logn)
{
    size_t n, u;
    word32 s, ng;

    n = MKN(logn);
    s = 0;
    ng = 0;
    for (u = 0; u < n; u++) {
        sword32 z;

        z = f[u];
        s += (word32)(z * z);
        ng |= s;
    }
    return s | -(ng >> 31);
}

/* Align 'data' upwards relative to 'base' to a multiple of sizeof(fpr). */
static fpr* align_fpr(void* base, void* data)
{
    byte* cb;
    byte* cd;
    size_t k, km;

    cb = (byte*)base;
    cd = (byte*)data;
    k = (size_t)(cd - cb);
    km = k % sizeof(fpr);
    if (km) {
        k += sizeof(fpr) - km;
    }
    return (fpr*)(cb + k);
}

/* Align 'data' upwards relative to 'base' to a multiple of sizeof(word32). */
static word32* align_u32(void* base, void* data)
{
    byte* cb;
    byte* cd;
    size_t k, km;

    cb = (byte*)base;
    cd = (byte*)data;
    k = (size_t)(cd - cb);
    km = k % sizeof(word32);
    if (km) {
        k += sizeof(word32) - km;
    }
    return (word32*)(cb + k);
}

/* Convert a small vector to floating point. */
static void poly_small_to_fp(fpr* x, const sword8* f, unsigned logn)
{
    size_t n, u;

    n = MKN(logn);
    for (u = 0; u < n; u++) {
        x[u] = fpr_of(f[u]);
    }
}

/*
 * Input: f,g of degree N = 2^logn ('depth' is used only for their lengths).
 * Output: f',g' of degree N/2 with the length for 'depth+1'. Values are in
 * RNS; input and/or output may also be in NTT.
 */
static void make_fg_step(word32* data, unsigned logn, unsigned depth,
        int in_ntt, int out_ntt)
{
    size_t n, hn, u;
    size_t slen, tlen;
    word32* fd;
    word32* gd;
    word32* fs;
    word32* gs;
    word32* gm;
    word32* igm;
    word32* t1;
    const falcon_small_prime* primes;

    n = (size_t)1 << logn;
    hn = n >> 1;
    slen = MAX_BL_SMALL[depth];
    tlen = MAX_BL_SMALL[depth + 1];
    primes = FALCON_PRIMES;

    fd = data;
    gd = fd + hn * tlen;
    fs = gd + hn * tlen;
    gs = fs + n * slen;
    gm = gs + n * slen;
    igm = gm + n;
    t1 = igm + n;
    XMEMMOVE(fs, data, 2 * n * slen * sizeof(*data));

    /* First slen words: use input values directly, applying inverse NTT. */
    for (u = 0; u < slen; u++) {
        word32 p, p0i, R2;
        size_t v;
        word32* x;

        p = primes[u].p;
        p0i = modp_ninv31(p);
        R2 = modp_R2(p, p0i);
        modp_mkgm2(gm, igm, logn, primes[u].g, p, p0i);

        for (v = 0, x = fs + u; v < n; v++, x += slen) {
            t1[v] = *x;
        }
        if (!in_ntt) {
            modp_NTT2(t1, gm, logn, p, p0i);
        }
        for (v = 0, x = fd + u; v < hn; v++, x += tlen) {
            word32 w0, w1;

            w0 = t1[(v << 1) + 0];
            w1 = t1[(v << 1) + 1];
            *x = modp_montymul(modp_montymul(w0, w1, p, p0i), R2, p, p0i);
        }
        if (in_ntt) {
            modp_iNTT2_ext(fs + u, slen, igm, logn, p, p0i);
        }

        for (v = 0, x = gs + u; v < n; v++, x += slen) {
            t1[v] = *x;
        }
        if (!in_ntt) {
            modp_NTT2(t1, gm, logn, p, p0i);
        }
        for (v = 0, x = gd + u; v < hn; v++, x += tlen) {
            word32 w0, w1;

            w0 = t1[(v << 1) + 0];
            w1 = t1[(v << 1) + 1];
            *x = modp_montymul(modp_montymul(w0, w1, p, p0i), R2, p, p0i);
        }
        if (in_ntt) {
            modp_iNTT2_ext(gs + u, slen, igm, logn, p, p0i);
        }

        if (!out_ntt) {
            modp_iNTT2_ext(fd + u, tlen, igm, logn - 1, p, p0i);
            modp_iNTT2_ext(gd + u, tlen, igm, logn - 1, p, p0i);
        }
    }

    /* fs and gs have been de-NTTized; rebuild via CRT. */
    zint_rebuild_CRT(fs, slen, slen, n, primes, 1, gm);
    zint_rebuild_CRT(gs, slen, slen, n, primes, 1, gm);

    /* Remaining words: modular reductions. */
    for (u = slen; u < tlen; u++) {
        word32 p, p0i, R2, Rx;
        size_t v;
        word32* x;

        p = primes[u].p;
        p0i = modp_ninv31(p);
        R2 = modp_R2(p, p0i);
        Rx = modp_Rx((unsigned)slen, p, p0i, R2);
        modp_mkgm2(gm, igm, logn, primes[u].g, p, p0i);
        for (v = 0, x = fs; v < n; v++, x += slen) {
            t1[v] = zint_mod_small_signed(x, slen, p, p0i, R2, Rx);
        }
        modp_NTT2(t1, gm, logn, p, p0i);
        for (v = 0, x = fd + u; v < hn; v++, x += tlen) {
            word32 w0, w1;

            w0 = t1[(v << 1) + 0];
            w1 = t1[(v << 1) + 1];
            *x = modp_montymul(modp_montymul(w0, w1, p, p0i), R2, p, p0i);
        }
        for (v = 0, x = gs; v < n; v++, x += slen) {
            t1[v] = zint_mod_small_signed(x, slen, p, p0i, R2, Rx);
        }
        modp_NTT2(t1, gm, logn, p, p0i);
        for (v = 0, x = gd + u; v < hn; v++, x += tlen) {
            word32 w0, w1;

            w0 = t1[(v << 1) + 0];
            w1 = t1[(v << 1) + 1];
            *x = modp_montymul(modp_montymul(w0, w1, p, p0i), R2, p, p0i);
        }

        if (!out_ntt) {
            modp_iNTT2_ext(fd + u, tlen, igm, logn - 1, p, p0i);
            modp_iNTT2_ext(gd + u, tlen, igm, logn - 1, p, p0i);
        }
    }
}

/*
 * Compute f and g at a specific depth, in RNS notation, stored at slen words
 * per integer. 0 <= depth <= logn.
 */
static void make_fg(word32* data, const sword8* f, const sword8* g,
        unsigned logn, unsigned depth, int out_ntt)
{
    size_t n, u;
    word32* ft;
    word32* gt;
    word32 p0;
    unsigned d;
    const falcon_small_prime* primes;

    n = MKN(logn);
    ft = data;
    gt = ft + n;
    primes = FALCON_PRIMES;
    p0 = primes[0].p;
    for (u = 0; u < n; u++) {
        ft[u] = modp_set(f[u], p0);
        gt[u] = modp_set(g[u], p0);
    }

    if (depth == 0 && out_ntt) {
        word32* gm;
        word32* igm;
        word32 p, p0i;

        p = primes[0].p;
        p0i = modp_ninv31(p);
        gm = gt + n;
        igm = gm + MKN(logn);
        modp_mkgm2(gm, igm, logn, primes[0].g, p, p0i);
        modp_NTT2(ft, gm, logn, p, p0i);
        modp_NTT2(gt, gm, logn, p, p0i);
        return;
    }

    if (depth == 0) {
        return;
    }

    if (depth == 1) {
        make_fg_step(data, logn, 0, 0, out_ntt);
        return;
    }

    make_fg_step(data, logn, 0, 0, 1);
    for (d = 1; d + 1 < depth; d++) {
        make_fg_step(data, logn - d, d, 1, 1);
    }
    make_fg_step(data, logn - depth + 1, depth - 1, 1, out_ntt);
}

/* ==================================================================== */
/* NTRU equation solver (recursive ntru_solve, port of keygen.c).        */

/*
 * Deepest level: compute the resultants of f and g with X^N+1, then apply
 * binary GCD. F and G are returned in tmp[]. Returns 1 on success.
 */
static int solve_NTRU_deepest(unsigned logn_top,
        const sword8* f, const sword8* g, word32* tmp)
{
    size_t len;
    word32* Fp;
    word32* Gp;
    word32* fp;
    word32* gp;
    word32* t1;
    word32 q;
    const falcon_small_prime* primes;

    len = MAX_BL_SMALL[logn_top];
    primes = FALCON_PRIMES;

    Fp = tmp;
    Gp = Fp + len;
    fp = Gp + len;
    gp = fp + len;
    t1 = gp + len;

    make_fg(fp, f, g, logn_top, logn_top, 0);

    /* Rebuild the (always nonnegative) resultants as big integers. */
    zint_rebuild_CRT(fp, len, len, 2, primes, 0, t1);

    /* Binary GCD (requires both inputs odd). */
    if (!zint_bezout(Gp, Fp, fp, gp, len, t1)) {
        return 0;
    }

    /* Multiply by q; a nonzero carry means overflow -> reject. */
    q = 12289;
    if (zint_mul_small(Fp, len, q) != 0
            || zint_mul_small(Gp, len, q) != 0) {
        return 0;
    }

    return 1;
}

/*
 * Intermediate level. On entry the F,G from the previous (deeper) level are
 * in tmp[]. May be invoked at the top level (depth = 0). Returns 1 on success.
 */
static int solve_NTRU_intermediate(unsigned logn_top,
        const sword8* f, const sword8* g, unsigned depth, word32* tmp)
{
    unsigned logn;
    size_t n, hn, slen, dlen, llen, rlen, FGlen, u;
    word32* Fd;
    word32* Gd;
    word32* Ft;
    word32* Gt;
    word32* ft;
    word32* gt;
    word32* t1;
    fpr* rt1;
    fpr* rt2;
    fpr* rt3;
    fpr* rt4;
    fpr* rt5;
    int scale_fg, minbl_fg, maxbl_fg, maxbl_FG, scale_k;
    word32* x;
    word32* y;
    sword32* k;
    const falcon_small_prime* primes;

    logn = logn_top - depth;
    n = (size_t)1 << logn;
    hn = n >> 1;

    slen = MAX_BL_SMALL[depth];
    dlen = MAX_BL_SMALL[depth + 1];
    llen = MAX_BL_LARGE[depth];
    primes = FALCON_PRIMES;

    /* Fd, Gd are the F,G from the deeper level. */
    Fd = tmp;
    Gd = Fd + dlen * hn;

    /* Compute input f,g for this level (RNS + NTT representation). */
    ft = Gd + dlen * hn;
    make_fg(ft, f, g, logn_top, depth, 1);

    /* Move f,g to make room for our unreduced candidate F,G. */
    Ft = tmp;
    Gt = Ft + n * llen;
    t1 = Gt + n * llen;
    XMEMMOVE(t1, ft, 2 * n * slen * sizeof(*ft));
    ft = t1;
    gt = ft + slen * n;
    t1 = gt + slen * n;

    /* Move Fd, Gd after f,g. */
    XMEMMOVE(t1, Fd, 2 * hn * dlen * sizeof(*Fd));
    Fd = t1;
    Gd = Fd + hn * dlen;

    /* Reduce Fd,Gd modulo all needed primes into Ft,Gt (n/2 values each). */
    for (u = 0; u < llen; u++) {
        word32 p, p0i, R2, Rx;
        size_t v;
        word32* xs;
        word32* ys;
        word32* xd;
        word32* yd;

        p = primes[u].p;
        p0i = modp_ninv31(p);
        R2 = modp_R2(p, p0i);
        Rx = modp_Rx((unsigned)dlen, p, p0i, R2);
        for (v = 0, xs = Fd, ys = Gd, xd = Ft + u, yd = Gt + u;
                v < hn;
                v++, xs += dlen, ys += dlen, xd += llen, yd += llen) {
            *xd = zint_mod_small_signed(xs, dlen, p, p0i, R2, Rx);
            *yd = zint_mod_small_signed(ys, dlen, p, p0i, R2, Rx);
        }
    }

    /* Compute F,G modulo sufficiently many small primes. */
    for (u = 0; u < llen; u++) {
        word32 p, p0i, R2;
        word32* gm;
        word32* igm;
        word32* fx;
        word32* gx;
        word32* Fp;
        word32* Gp;
        size_t v;

        p = primes[u].p;
        p0i = modp_ninv31(p);
        R2 = modp_R2(p, p0i);

        /* Once slen words are processed, f,g are de-NTTized -> rebuild. */
        if (u == slen) {
            zint_rebuild_CRT(ft, slen, slen, n, primes, 1, t1);
            zint_rebuild_CRT(gt, slen, slen, n, primes, 1, t1);
        }

        gm = t1;
        igm = gm + n;
        fx = igm + n;
        gx = fx + n;

        modp_mkgm2(gm, igm, logn, primes[u].g, p, p0i);

        if (u < slen) {
            for (v = 0, x = ft + u, y = gt + u;
                    v < n; v++, x += slen, y += slen) {
                fx[v] = *x;
                gx[v] = *y;
            }
            modp_iNTT2_ext(ft + u, slen, igm, logn, p, p0i);
            modp_iNTT2_ext(gt + u, slen, igm, logn, p, p0i);
        }
        else {
            word32 Rx;

            Rx = modp_Rx((unsigned)slen, p, p0i, R2);
            for (v = 0, x = ft, y = gt;
                    v < n; v++, x += slen, y += slen) {
                fx[v] = zint_mod_small_signed(x, slen, p, p0i, R2, Rx);
                gx[v] = zint_mod_small_signed(y, slen, p, p0i, R2, Rx);
            }
            modp_NTT2(fx, gm, logn, p, p0i);
            modp_NTT2(gx, gm, logn, p, p0i);
        }

        /* Get F',G' modulo p in NTT representation (degree n/2). */
        Fp = gx + n;
        Gp = Fp + hn;
        for (v = 0, x = Ft + u, y = Gt + u;
                v < hn; v++, x += llen, y += llen) {
            Fp[v] = *x;
            Gp[v] = *y;
        }
        modp_NTT2(Fp, gm, logn - 1, p, p0i);
        modp_NTT2(Gp, gm, logn - 1, p, p0i);

        for (v = 0, x = Ft + u, y = Gt + u; v < hn;
                v++, x += (llen << 1), y += (llen << 1)) {
            word32 ftA, ftB, gtA, gtB;
            word32 mFp, mGp;

            ftA = fx[(v << 1) + 0];
            ftB = fx[(v << 1) + 1];
            gtA = gx[(v << 1) + 0];
            gtB = gx[(v << 1) + 1];
            mFp = modp_montymul(Fp[v], R2, p, p0i);
            mGp = modp_montymul(Gp[v], R2, p, p0i);
            x[0] = modp_montymul(gtB, mFp, p, p0i);
            x[llen] = modp_montymul(gtA, mFp, p, p0i);
            y[0] = modp_montymul(ftB, mGp, p, p0i);
            y[llen] = modp_montymul(ftA, mGp, p, p0i);
        }
        modp_iNTT2_ext(Ft + u, llen, igm, logn, p, p0i);
        modp_iNTT2_ext(Gt + u, llen, igm, logn, p, p0i);
    }

    /* Rebuild F,G with the CRT. */
    zint_rebuild_CRT(Ft, llen, llen, n, primes, 1, t1);
    zint_rebuild_CRT(Gt, llen, llen, n, primes, 1, t1);

    /* Babai reduction (FFT-based) to bring F,G back to size slen. */
    rt3 = align_fpr(tmp, t1);
    rt4 = rt3 + n;
    rt5 = rt4 + n;
    rt1 = rt5 + (n >> 1);
    k = (sword32*)align_u32(tmp, rt1);
    rt2 = align_fpr(tmp, k + n);
    if (rt2 < (rt1 + n)) {
        rt2 = rt1 + n;
    }
    t1 = (word32*)k + n;

    if (slen > 10) {
        rlen = 10;
    }
    else {
        rlen = slen;
    }
    poly_big_to_fp(rt3, ft + slen - rlen, rlen, slen, logn);
    poly_big_to_fp(rt4, gt + slen - rlen, rlen, slen, logn);

    scale_fg = 31 * (int)(slen - rlen);

    minbl_fg = BITLENGTH[depth].avg - 6 * BITLENGTH[depth].std;
    maxbl_fg = BITLENGTH[depth].avg + 6 * BITLENGTH[depth].std;

    /* Compute 1/(f*adj(f)+g*adj(g)) in rt5; keep adj(f),adj(g) in rt3,rt4. */
    falcon_FFT(rt3, logn);
    falcon_FFT(rt4, logn);
    falcon_poly_invnorm2_fft(rt5, rt3, rt4, logn);
    falcon_poly_adj_fft(rt3, logn);
    falcon_poly_adj_fft(rt4, logn);

    FGlen = llen;
    maxbl_FG = 31 * (int)llen;
    scale_k = maxbl_FG - minbl_fg;

    for (;;) {
        int scale_FG, dc, new_maxbl_FG;
        word32 scl, sch;
        fpr pdc, pt;

        if (FGlen > 10) {
            rlen = 10;
        }
        else {
            rlen = FGlen;
        }
        scale_FG = 31 * (int)(FGlen - rlen);
        poly_big_to_fp(rt1, Ft + FGlen - rlen, rlen, llen, logn);
        poly_big_to_fp(rt2, Gt + FGlen - rlen, rlen, llen, logn);

        /* (F*adj(f)+G*adj(g))/(f*adj(f)+g*adj(g)) in rt2. */
        falcon_FFT(rt1, logn);
        falcon_FFT(rt2, logn);
        falcon_poly_mul_fft(rt1, rt3, logn);
        falcon_poly_mul_fft(rt2, rt4, logn);
        falcon_poly_add(rt2, rt1, logn);
        falcon_poly_mul_autoadj_fft(rt2, rt5, logn);
        falcon_iFFT(rt2, logn);

        dc = scale_k - scale_FG + scale_fg;

        if (dc < 0) {
            dc = -dc;
            pt = fpr_two;
        }
        else {
            pt = fpr_onehalf;
        }
        pdc = fpr_one;
        while (dc != 0) {
            if ((dc & 1) != 0) {
                pdc = fpr_mul(pdc, pt);
            }
            dc >>= 1;
            pt = fpr_sqr(pt);
        }

        for (u = 0; u < n; u++) {
            fpr xv;

            xv = fpr_mul(rt2[u], pdc);

            if (!fpr_lt(fpr_mtwo31m1, xv) || !fpr_lt(xv, fpr_ptwo31m1)) {
                return 0;
            }
            k[u] = (sword32)fpr_rint(xv);
        }

        sch = (word32)(scale_k / 31);
        scl = (word32)(scale_k % 31);
        if (depth <= DEPTH_INT_FG) {
            poly_sub_scaled_ntt(Ft, FGlen, llen, ft, slen, slen,
                    k, sch, scl, logn, t1);
            poly_sub_scaled_ntt(Gt, FGlen, llen, gt, slen, slen,
                    k, sch, scl, logn, t1);
        }
        else {
            poly_sub_scaled(Ft, FGlen, llen, ft, slen, slen,
                    k, sch, scl, logn);
            poly_sub_scaled(Gt, FGlen, llen, gt, slen, slen,
                    k, sch, scl, logn);
        }

        new_maxbl_FG = scale_k + maxbl_fg + 10;
        if (new_maxbl_FG < maxbl_FG) {
            maxbl_FG = new_maxbl_FG;
            if ((int)FGlen * 31 >= maxbl_FG + 31) {
                FGlen--;
            }
        }

        if (scale_k <= 0) {
            break;
        }
        scale_k -= 25;
        if (scale_k < 0) {
            scale_k = 0;
        }
    }

    /* Re-extend the sign if (F,G) length dropped below slen. */
    if (FGlen < slen) {
        for (u = 0; u < n; u++, Ft += llen, Gt += llen) {
            size_t v;
            word32 sw;

            sw = -(Ft[FGlen - 1] >> 30) >> 1;
            for (v = FGlen; v < slen; v++) {
                Ft[v] = sw;
            }
            sw = -(Gt[FGlen - 1] >> 30) >> 1;
            for (v = FGlen; v < slen; v++) {
                Gt[v] = sw;
            }
        }
    }

    /* Compress all values to slen words (expected output format). */
    for (u = 0, x = tmp, y = tmp;
            u < (n << 1); u++, x += slen, y += llen) {
        XMEMMOVE(x, y, slen * sizeof(*y));
    }
    return 1;
}

/*
 * Binary case, depth = 1. On entry F,G from the deeper level are in tmp[].
 * Returns 1 on success.
 */
static int solve_NTRU_binary_depth1(unsigned logn_top,
        const sword8* f, const sword8* g, word32* tmp)
{
    unsigned depth, logn;
    size_t n_top, n, hn, slen, dlen, llen, u;
    word32* Fd;
    word32* Gd;
    word32* Ft;
    word32* Gt;
    word32* ft;
    word32* gt;
    word32* t1;
    fpr* rt1;
    fpr* rt2;
    fpr* rt3;
    fpr* rt4;
    fpr* rt5;
    fpr* rt6;
    word32* x;
    word32* y;

    depth = 1;
    n_top = (size_t)1 << logn_top;
    logn = logn_top - depth;
    n = (size_t)1 << logn;
    hn = n >> 1;

    slen = MAX_BL_SMALL[depth];
    dlen = MAX_BL_SMALL[depth + 1];
    llen = MAX_BL_LARGE[depth];

    Fd = tmp;
    Gd = Fd + dlen * hn;
    Ft = Gd + dlen * hn;
    Gt = Ft + llen * n;

    /* Reduce Fd,Gd modulo all needed primes into Ft,Gt. */
    for (u = 0; u < llen; u++) {
        word32 p, p0i, R2, Rx;
        size_t v;
        word32* xs;
        word32* ys;
        word32* xd;
        word32* yd;

        p = FALCON_PRIMES[u].p;
        p0i = modp_ninv31(p);
        R2 = modp_R2(p, p0i);
        Rx = modp_Rx((unsigned)dlen, p, p0i, R2);
        for (v = 0, xs = Fd, ys = Gd, xd = Ft + u, yd = Gt + u;
                v < hn;
                v++, xs += dlen, ys += dlen, xd += llen, yd += llen) {
            *xd = zint_mod_small_signed(xs, dlen, p, p0i, R2, Rx);
            *yd = zint_mod_small_signed(ys, dlen, p, p0i, R2, Rx);
        }
    }

    /* Squeeze out Fd,Gd. */
    XMEMMOVE(tmp, Ft, llen * n * sizeof(word32));
    Ft = tmp;
    XMEMMOVE(Ft + llen * n, Gt, llen * n * sizeof(word32));
    Gt = Ft + llen * n;
    ft = Gt + llen * n;
    gt = ft + slen * n;
    t1 = gt + slen * n;

    /* Compute F,G modulo sufficiently many small primes. */
    for (u = 0; u < llen; u++) {
        word32 p, p0i, R2;
        word32* gm;
        word32* igm;
        word32* fx;
        word32* gx;
        word32* Fp;
        word32* Gp;
        unsigned e;
        size_t v;

        p = FALCON_PRIMES[u].p;
        p0i = modp_ninv31(p);
        R2 = modp_R2(p, p0i);

        gm = t1;
        igm = gm + n_top;
        fx = igm + n;
        gx = fx + n_top;
        modp_mkgm2(gm, igm, logn_top, FALCON_PRIMES[u].g, p, p0i);

        for (v = 0; v < n_top; v++) {
            fx[v] = modp_set(f[v], p);
            gx[v] = modp_set(g[v], p);
        }

        modp_NTT2(fx, gm, logn_top, p, p0i);
        modp_NTT2(gx, gm, logn_top, p, p0i);
        for (e = logn_top; e > logn; e--) {
            modp_poly_rec_res(fx, e, p, p0i, R2);
            modp_poly_rec_res(gx, e, p, p0i, R2);
        }

        /* Save space: from here we only need degree-n tables. */
        XMEMMOVE(gm + n, igm, n * sizeof(*igm));
        igm = gm + n;
        XMEMMOVE(igm + n, fx, n * sizeof(*ft));
        fx = igm + n;
        XMEMMOVE(fx + n, gx, n * sizeof(*gt));
        gx = fx + n;

        /* F',G' modulo p in NTT representation (degree n/2). */
        Fp = gx + n;
        Gp = Fp + hn;
        for (v = 0, x = Ft + u, y = Gt + u;
                v < hn; v++, x += llen, y += llen) {
            Fp[v] = *x;
            Gp[v] = *y;
        }
        modp_NTT2(Fp, gm, logn - 1, p, p0i);
        modp_NTT2(Gp, gm, logn - 1, p, p0i);

        for (v = 0, x = Ft + u, y = Gt + u;
                v < hn; v++, x += (llen << 1), y += (llen << 1)) {
            word32 ftA, ftB, gtA, gtB;
            word32 mFp, mGp;

            ftA = fx[(v << 1) + 0];
            ftB = fx[(v << 1) + 1];
            gtA = gx[(v << 1) + 0];
            gtB = gx[(v << 1) + 1];
            mFp = modp_montymul(Fp[v], R2, p, p0i);
            mGp = modp_montymul(Gp[v], R2, p, p0i);
            x[0] = modp_montymul(gtB, mFp, p, p0i);
            x[llen] = modp_montymul(gtA, mFp, p, p0i);
            y[0] = modp_montymul(ftB, mGp, p, p0i);
            y[llen] = modp_montymul(ftA, mGp, p, p0i);
        }
        modp_iNTT2_ext(Ft + u, llen, igm, logn, p, p0i);
        modp_iNTT2_ext(Gt + u, llen, igm, logn, p, p0i);

        /* Also save ft,gt up to size slen. */
        if (u < slen) {
            modp_iNTT2(fx, igm, logn, p, p0i);
            modp_iNTT2(gx, igm, logn, p, p0i);
            for (v = 0, x = ft + u, y = gt + u;
                    v < n; v++, x += slen, y += slen) {
                *x = fx[v];
                *y = gx[v];
            }
        }
    }

    /* Rebuild f,g,F,G with the CRT (consecutive in RAM). */
    zint_rebuild_CRT(Ft, llen, llen, n << 1, FALCON_PRIMES, 1, t1);
    zint_rebuild_CRT(ft, slen, slen, n << 1, FALCON_PRIMES, 1, t1);

    /* Babai reduction, specialized for depth 1 (single pass, no scaling). */
    rt1 = align_fpr(tmp, gt + slen * n);
    rt2 = rt1 + n;
    poly_big_to_fp(rt1, Ft, llen, llen, logn);
    poly_big_to_fp(rt2, Gt, llen, llen, logn);

    XMEMMOVE(tmp, ft, 2 * slen * n * sizeof(*ft));
    ft = tmp;
    gt = ft + slen * n;
    rt3 = align_fpr(tmp, gt + slen * n);
    XMEMMOVE(rt3, rt1, 2 * n * sizeof(*rt1));
    rt1 = rt3;
    rt2 = rt1 + n;
    rt3 = rt2 + n;
    rt4 = rt3 + n;

    poly_big_to_fp(rt3, ft, slen, slen, logn);
    poly_big_to_fp(rt4, gt, slen, slen, logn);

    XMEMMOVE(tmp, rt1, 4 * n * sizeof(*rt1));
    rt1 = (fpr*)tmp;
    rt2 = rt1 + n;
    rt3 = rt2 + n;
    rt4 = rt3 + n;

    /* rt1=F rt2=G rt3=f rt4=g; convert all to FFT. */
    falcon_FFT(rt1, logn);
    falcon_FFT(rt2, logn);
    falcon_FFT(rt3, logn);
    falcon_FFT(rt4, logn);

    rt5 = rt4 + n;
    rt6 = rt5 + n;
    falcon_poly_add_muladj_fft(rt5, rt1, rt2, rt3, rt4, logn);
    falcon_poly_invnorm2_fft(rt6, rt3, rt4, logn);
    falcon_poly_mul_autoadj_fft(rt5, rt6, logn);

    falcon_iFFT(rt5, logn);
    for (u = 0; u < n; u++) {
        fpr z;

        z = rt5[u];
        if (!fpr_lt(z, fpr_ptwo63m1) || !fpr_lt(fpr_mtwo63m1, z)) {
            return 0;
        }
        rt5[u] = fpr_of(fpr_rint(z));
    }
    falcon_FFT(rt5, logn);

    /* Subtract k*f from F, k*g from G. */
    falcon_poly_mul_fft(rt3, rt5, logn);
    falcon_poly_mul_fft(rt4, rt5, logn);
    falcon_poly_sub(rt1, rt3, logn);
    falcon_poly_sub(rt2, rt4, logn);
    falcon_iFFT(rt1, logn);
    falcon_iFFT(rt2, logn);

    /* Convert back F,G to integers. */
    Ft = tmp;
    Gt = Ft + n;
    rt3 = align_fpr(tmp, Gt + n);
    XMEMMOVE(rt3, rt1, 2 * n * sizeof(*rt1));
    rt1 = rt3;
    rt2 = rt1 + n;
    for (u = 0; u < n; u++) {
        Ft[u] = (word32)fpr_rint(rt1[u]);
        Gt[u] = (word32)fpr_rint(rt2[u]);
    }

    return 1;
}

/*
 * Binary case, depth = 0 (top level). On entry F,G from the deeper level are
 * in tmp[]. Returns 1 on success.
 */
static int solve_NTRU_binary_depth0(unsigned logn,
        const sword8* f, const sword8* g, word32* tmp)
{
    size_t n, hn, u;
    word32 p, p0i, R2;
    word32* Fp;
    word32* Gp;
    word32* t1;
    word32* t2;
    word32* t3;
    word32* t4;
    word32* t5;
    word32* gm;
    word32* igm;
    word32* ft;
    word32* gt;
    fpr* rt2;
    fpr* rt3;

    n = (size_t)1 << logn;
    hn = n >> 1;

    p = FALCON_PRIMES[0].p;
    p0i = modp_ninv31(p);
    R2 = modp_R2(p, p0i);

    Fp = tmp;
    Gp = Fp + hn;
    ft = Gp + hn;
    gt = ft + n;
    gm = gt + n;
    igm = gm + n;

    modp_mkgm2(gm, igm, logn, FALCON_PRIMES[0].g, p, p0i);

    /* Convert F',G' to NTT representation. */
    for (u = 0; u < hn; u++) {
        Fp[u] = modp_set(zint_one_to_plain(Fp + u), p);
        Gp[u] = modp_set(zint_one_to_plain(Gp + u), p);
    }
    modp_NTT2(Fp, gm, logn - 1, p, p0i);
    modp_NTT2(Gp, gm, logn - 1, p, p0i);

    /* Load f,g and convert to NTT. */
    for (u = 0; u < n; u++) {
        ft[u] = modp_set(f[u], p);
        gt[u] = modp_set(g[u], p);
    }
    modp_NTT2(ft, gm, logn, p, p0i);
    modp_NTT2(gt, gm, logn, p, p0i);

    /* Build the unreduced F,G in ft,gt. */
    for (u = 0; u < n; u += 2) {
        word32 ftA, ftB, gtA, gtB;
        word32 mFp, mGp;

        ftA = ft[u + 0];
        ftB = ft[u + 1];
        gtA = gt[u + 0];
        gtB = gt[u + 1];
        mFp = modp_montymul(Fp[u >> 1], R2, p, p0i);
        mGp = modp_montymul(Gp[u >> 1], R2, p, p0i);
        ft[u + 0] = modp_montymul(gtB, mFp, p, p0i);
        ft[u + 1] = modp_montymul(gtA, mFp, p, p0i);
        gt[u + 0] = modp_montymul(ftB, mGp, p, p0i);
        gt[u + 1] = modp_montymul(ftA, mGp, p, p0i);
    }
    modp_iNTT2(ft, igm, logn, p, p0i);
    modp_iNTT2(gt, igm, logn, p, p0i);

    Gp = Fp + n;
    t1 = Gp + n;
    XMEMMOVE(Fp, ft, 2 * n * sizeof(*ft));

    /* Babai reduction. */
    t2 = t1 + n;
    t3 = t2 + n;
    t4 = t3 + n;
    t5 = t4 + n;

    modp_mkgm2(t1, t2, logn, FALCON_PRIMES[0].g, p, p0i);

    modp_NTT2(Fp, t1, logn, p, p0i);
    modp_NTT2(Gp, t1, logn, p, p0i);

    /* Load f and adj(f) in t4,t5, convert to NTT. */
    t4[0] = t5[0] = modp_set(f[0], p);
    for (u = 1; u < n; u++) {
        t4[u] = modp_set(f[u], p);
        t5[n - u] = modp_set(-f[u], p);
    }
    modp_NTT2(t4, t1, logn, p, p0i);
    modp_NTT2(t5, t1, logn, p, p0i);

    /* F*adj(f) in t2, f*adj(f) in t3. */
    for (u = 0; u < n; u++) {
        word32 w;

        w = modp_montymul(t5[u], R2, p, p0i);
        t2[u] = modp_montymul(w, Fp[u], p, p0i);
        t3[u] = modp_montymul(w, t4[u], p, p0i);
    }

    /* Load g and adj(g) in t4,t5, convert to NTT. */
    t4[0] = t5[0] = modp_set(g[0], p);
    for (u = 1; u < n; u++) {
        t4[u] = modp_set(g[u], p);
        t5[n - u] = modp_set(-g[u], p);
    }
    modp_NTT2(t4, t1, logn, p, p0i);
    modp_NTT2(t5, t1, logn, p, p0i);

    /* Add G*adj(g) to t2, g*adj(g) to t3. */
    for (u = 0; u < n; u++) {
        word32 w;

        w = modp_montymul(t5[u], R2, p, p0i);
        t2[u] = modp_add(t2[u], modp_montymul(w, Gp[u], p, p0i), p);
        t3[u] = modp_add(t3[u], modp_montymul(w, t4[u], p, p0i), p);
    }

    /* Convert t2,t3 back to normal representation (normalized around 0). */
    modp_mkgm2(t1, t4, logn, FALCON_PRIMES[0].g, p, p0i);
    modp_iNTT2(t2, t4, logn, p, p0i);
    modp_iNTT2(t3, t4, logn, p, p0i);
    for (u = 0; u < n; u++) {
        t1[u] = (word32)modp_norm(t2[u], p);
        t2[u] = (word32)modp_norm(t3[u], p);
    }

    /* Divide t1 by t2 via the FFT (auto-adjoint denominator). */
    rt3 = align_fpr(tmp, t3);
    for (u = 0; u < n; u++) {
        rt3[u] = fpr_of(((sword32*)t2)[u]);
    }
    falcon_FFT(rt3, logn);
    rt2 = align_fpr(tmp, t2);
    XMEMMOVE(rt2, rt3, hn * sizeof(*rt3));

    rt3 = rt2 + hn;
    for (u = 0; u < n; u++) {
        rt3[u] = fpr_of(((sword32*)t1)[u]);
    }
    falcon_FFT(rt3, logn);

    falcon_poly_div_autoadj_fft(rt3, rt2, logn);
    falcon_iFFT(rt3, logn);
    for (u = 0; u < n; u++) {
        t1[u] = modp_set((sword32)fpr_rint(rt3[u]), p);
    }

    /* Compute F-k*f, G-k*g. */
    t2 = t1 + n;
    t3 = t2 + n;
    t4 = t3 + n;
    t5 = t4 + n;
    modp_mkgm2(t2, t3, logn, FALCON_PRIMES[0].g, p, p0i);
    for (u = 0; u < n; u++) {
        t4[u] = modp_set(f[u], p);
        t5[u] = modp_set(g[u], p);
    }
    modp_NTT2(t1, t2, logn, p, p0i);
    modp_NTT2(t4, t2, logn, p, p0i);
    modp_NTT2(t5, t2, logn, p, p0i);
    for (u = 0; u < n; u++) {
        word32 kw;

        kw = modp_montymul(t1[u], R2, p, p0i);
        Fp[u] = modp_sub(Fp[u], modp_montymul(kw, t4[u], p, p0i), p);
        Gp[u] = modp_sub(Gp[u], modp_montymul(kw, t5[u], p, p0i), p);
    }
    modp_iNTT2(Fp, t3, logn, p, p0i);
    modp_iNTT2(Gp, t3, logn, p, p0i);
    for (u = 0; u < n; u++) {
        Fp[u] = (word32)modp_norm(Fp[u], p);
        Gp[u] = (word32)modp_norm(Gp[u], p);
    }

    return 1;
}

/*
 * Solve the NTRU equation. Returns 1 on success, 0 on failure. G may be NULL
 * (then computed internally but not returned). If any coefficient of F or G
 * exceeds lim in absolute value, 0 is returned.
 */
static int solve_NTRU(unsigned logn, sword8* F, sword8* G,
        const sword8* f, const sword8* g, int lim, word32* tmp)
{
    size_t n, u;
    word32* ft;
    word32* gt;
    word32* Ft;
    word32* Gt;
    word32* gm;
    word32 p, p0i, r;
    const falcon_small_prime* primes;

    n = MKN(logn);

    if (!solve_NTRU_deepest(logn, f, g, tmp)) {
        return 0;
    }

    if (logn <= 2) {
        unsigned depth;

        depth = logn;
        while (depth-- > 0) {
            if (!solve_NTRU_intermediate(logn, f, g, depth, tmp)) {
                return 0;
            }
        }
    }
    else {
        unsigned depth;

        depth = logn;
        while (depth-- > 2) {
            if (!solve_NTRU_intermediate(logn, f, g, depth, tmp)) {
                return 0;
            }
        }
        if (!solve_NTRU_binary_depth1(logn, f, g, tmp)) {
            return 0;
        }
        if (!solve_NTRU_binary_depth0(logn, f, g, tmp)) {
            return 0;
        }
    }

    /* Use a temporary buffer for G if none provided. */
    if (G == NULL) {
        G = (sword8*)(tmp + 2 * n);
    }

    /* Final F,G are in tmp[], one word per coefficient (signed 31 bits). */
    if (!poly_big_to_small(F, tmp, lim, logn)
            || !poly_big_to_small(G, tmp + n, lim, logn)) {
        return 0;
    }

    /* Verify g*F - f*G = q modulo a small prime, using the NTT. */
    Gt = tmp;
    ft = Gt + n;
    gt = ft + n;
    Ft = gt + n;
    gm = Ft + n;

    primes = FALCON_PRIMES;
    p = primes[0].p;
    p0i = modp_ninv31(p);
    modp_mkgm2(gm, tmp, logn, primes[0].g, p, p0i);
    for (u = 0; u < n; u++) {
        Gt[u] = modp_set(G[u], p);
    }
    for (u = 0; u < n; u++) {
        ft[u] = modp_set(f[u], p);
        gt[u] = modp_set(g[u], p);
        Ft[u] = modp_set(F[u], p);
    }
    modp_NTT2(ft, gm, logn, p, p0i);
    modp_NTT2(gt, gm, logn, p, p0i);
    modp_NTT2(Ft, gm, logn, p, p0i);
    modp_NTT2(Gt, gm, logn, p, p0i);
    r = modp_montymul(12289, 1, p, p0i);
    for (u = 0; u < n; u++) {
        word32 z;

        z = modp_sub(modp_montymul(ft[u], Gt[u], p, p0i),
                modp_montymul(gt[u], Ft[u], p, p0i), p);
        if (z != r) {
            return 0;
        }
    }

    return 1;
}

/*
 * Generate a Gaussian-distributed polynomial whose resultant with phi is odd
 * (sum of coefficients is 1 mod 2).
 */
static void poly_small_mkgauss(falcon_rng* rng, sword8* f, unsigned logn)
{
    size_t n, u;
    unsigned mod2;

    n = MKN(logn);
    mod2 = 0;
    for (u = 0; u < n; u++) {
        int s;

        for (;;) {
            s = mkgauss(rng, logn);

            /* Abort on a PRNG failure: stale bytes would otherwise make the
             * parity constraint below unsatisfiable and spin forever. */
            if (rng->err != 0) {
                f[u] = 0;
                break;
            }

            /* Coefficient must fit in -127..+127. */
            if (s < -127 || s > 127) {
                continue;
            }

            /* The sum of all coefficients must be odd. */
            if (u == n - 1) {
                if ((mod2 ^ (unsigned)(s & 1)) == 0) {
                    continue;
                }
            }
            else {
                mod2 ^= (unsigned)(s & 1);
            }
            f[u] = (sword8)s;
            break;
        }
    }
}

/* ==================================================================== */
/* Public entry point.                                                   */

int falcon_keygen(WC_RNG* rng, sword8* f, sword8* g, sword8* F, sword8* G,
        word16* h, unsigned logn)
{
    size_t n;
    falcon_rng rc;
    byte* tmpbuf = NULL;
    word16* hwork = NULL;
    void* heap = NULL;
    size_t tmpSz;
    int ret;

    if (rng == NULL || f == NULL || g == NULL || F == NULL || G == NULL) {
        return BAD_FUNC_ARG;
    }
    if (logn < 1 || logn > 10) {
        return BAD_FUNC_ARG;
    }
    n = MKN(logn);

    /* Temporary buffer (sized per the reference; padded for fpr alignment). */
    tmpSz = FALCON_KEYGEN_TEMP[logn] + sizeof(fpr);
    tmpbuf = (byte*)XMALLOC(tmpSz, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (tmpbuf == NULL) {
        return MEMORY_E;
    }

    /* We always need h to test invertibility; allocate scratch if caller
     * did not supply one. */
    if (h == NULL) {
        hwork = (word16*)XMALLOC(n * sizeof(word16), heap,
                DYNAMIC_TYPE_TMP_BUFFER);
        if (hwork == NULL) {
            XFREE(tmpbuf, heap, DYNAMIC_TYPE_TMP_BUFFER);
            return MEMORY_E;
        }
    }
    else {
        hwork = h;
    }

    ret = falcon_rng_init(&rc, rng, heap);
    if (ret != 0) {
        if (h == NULL) {
            XFREE(hwork, heap, DYNAMIC_TYPE_TMP_BUFFER);
        }
        XFREE(tmpbuf, heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    /*
     * Sample (f,g) until: coefficients are in bounds, (g,-f) norm and the
     * orthogonalized vector norm are under the 1.17*sqrt(q) bound, f is
     * invertible mod q, and the NTRU equation can be solved.
     */
    for (;;) {
        fpr* rt1;
        fpr* rt2;
        fpr* rt3;
        fpr bnorm;
        word32 normf, normg, norm;
        int lim;
        size_t u;
        int cp;

        poly_small_mkgauss(&rc, f, logn);
        poly_small_mkgauss(&rc, g, logn);
        if (rc.err != 0) {
            ret = rc.err;
            goto out;
        }

        /* Coefficient bound check (FALCON_COMP_TRIM encodability). */
        lim = 1 << (falcon_max_fg_bits[logn] - 1);
        for (u = 0; u < n; u++) {
            if (f[u] >= lim || f[u] <= -lim
                    || g[u] >= lim || g[u] <= -lim) {
                lim = -1;
                break;
            }
        }
        if (lim < 0) {
            continue;
        }

        /* Squared norm of (g,-f); bound is (1.17^2)*q = 16822.41 -> 16823. */
        normf = poly_small_sqnorm(f, logn);
        normg = poly_small_sqnorm(g, logn);
        norm = (normf + normg) | -((normf | normg) >> 31);
        if (norm >= 16823) {
            continue;
        }

        /* Orthogonalized vector norm. */
        rt1 = (fpr*)tmpbuf;
        rt2 = rt1 + n;
        rt3 = rt2 + n;
        poly_small_to_fp(rt1, f, logn);
        poly_small_to_fp(rt2, g, logn);
        falcon_FFT(rt1, logn);
        falcon_FFT(rt2, logn);
        falcon_poly_invnorm2_fft(rt3, rt1, rt2, logn);
        falcon_poly_adj_fft(rt1, logn);
        falcon_poly_adj_fft(rt2, logn);
        falcon_poly_mulconst(rt1, fpr_q, logn);
        falcon_poly_mulconst(rt2, fpr_q, logn);
        falcon_poly_mul_autoadj_fft(rt1, rt3, logn);
        falcon_poly_mul_autoadj_fft(rt2, rt3, logn);
        falcon_iFFT(rt1, logn);
        falcon_iFFT(rt2, logn);
        bnorm = fpr_zero;
        for (u = 0; u < n; u++) {
            bnorm = fpr_add(bnorm, fpr_sqr(rt1[u]));
            bnorm = fpr_add(bnorm, fpr_sqr(rt2[u]));
        }
        if (!fpr_lt(bnorm, fpr_bnorm_max)) {
            continue;
        }

        /* Public key h = g/f mod q; restart if f not invertible. */
        cp = falcon_compute_public(hwork, f, g, logn, heap);
        if (cp < 0) {
            ret = MEMORY_E;
            goto out;
        }
        if (cp == 0) {
            continue;
        }

        /* Solve the NTRU equation to get F,G. */
        lim = (1 << (FALCON_MAX_FG_BITS - 1)) - 1;
        if (!solve_NTRU(logn, F, G, f, g, lim, (word32*)tmpbuf)) {
            continue;
        }

        /* Success. */
        break;
    }

    ret = 0;

out:
    falcon_rng_free(&rc);
    if (h == NULL) {
        /* hwork holds the public key h by now (g was overwritten in place);
         * zeroized anyway for consistency with the tmpbuf hardening. */
        if (hwork != NULL) {
            wc_ForceZero(hwork, (word32)(n * sizeof(word16)));
        }
        XFREE(hwork, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    /* tmpbuf held the full secret-key expansion (f,g in RNS/NTT, F,G, FFT
     * images, Babai reduction vectors). */
    if (tmpbuf != NULL) {
        wc_ForceZero(tmpbuf, (word32)tmpSz);
    }
    XFREE(tmpbuf, heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}




#define MKN(logn)   ((size_t)1 << (logn))

#define FALCON_Q     12289

/* Safety bound on the sign-tree restart loop. The per-iteration restart
 * probability is well below 1 (expected iteration count ~1), so the chance of
 * legitimately reaching even a few dozen restarts is astronomically small; this
 * bound is never approached in normal operation. It only guarantees termination
 * if the sampler can no longer produce accepting candidates (e.g. a failed PRNG
 * squeeze), in which case falcon_sign_core additionally rejects the result via
 * the PRNG's sticky error. */
#define FALCON_SIGN_MAX_RESTARTS  4096UL

#ifdef WOLFSSL_FALCON_SIGN_STATS
/* Optional instrumentation: counts the (rare) ffSampling restarts, for test
 * harnesses. Defined here so it links; external linkage so a harness can read
 * it. Not compiled into production builds. */
unsigned long falcon_sign_restart_count = 0;
#endif

/* IEEE-754 binary64 bit patterns (the fpr seam carries doubles as word64).
 * These mirror named constants from the reference fpr.h that are not part of
 * the fpr seam declared above. fpr_invsqrt2 / fpr_invsqrt8 ARE part of the seam
 * and are used directly. */ /* (double)12289   */
static const fpr fpr_inverse_of_q  = 4545632735260551042ULL; /* 1/12289         */

/* 1/sigma, indexed by logn (1..10). Ported from the reference fpr.h. */
static const fpr fpr_inv_sigma[] = {
    0,  /* unused */
    4574611497772390042ULL,
    4574501679055810265ULL,
    4574396282908341804ULL,
    4574245855758572086ULL,
    4574103865040221165ULL,
    4573969550563515544ULL,
    4573842244705920822ULL,
    4573721358406441454ULL,
    4573606369665796042ULL,
    4573496814039276259ULL
};

/* Acceptance bound for the (squared) l2-norm of the signature, indexed by logn
 * (1..10). Inclusive bounds (= floor(beta^2)). Ported from the reference
 * common.c l2bound[]. */
static const word32 l2bound[] = {
    0,        /* unused */
    101498u,
    208714u,
    428865u,
    892039u,
    1852696u,
    3842630u,
    7959734u,
    16468416u,
    34034726u,
    70265242u
};

/* ==================================================================== */
/* complete_private: recompute G from (f, g, F).                         */

/* The keygen NTRU solver produces (F, G) such that f*G - g*F = q, hence
 * G = (g*F + q) / f. We recompute it over the FFT seam, add the constant q to
 * the real (lower) half of the FFT representation, divide by f, inverse-FFT and
 * round to integers. */
int falcon_complete_private(sword8* G, const sword8* f, const sword8* g,
        const sword8* F, unsigned logn, void* heap)
{
    size_t n, hn, u;
    fpr* t1;
    fpr* t2;
    fpr* t3;
    int ret = 0;

    if (G == NULL || f == NULL || g == NULL || F == NULL
            || logn < 1 || logn > 10) {
        return BAD_FUNC_ARG;
    }

    n = MKN(logn);
    hn = n >> 1;

    /* Three working polynomials. */
    t1 = (fpr*)XMALLOC((size_t)3 * n * sizeof(fpr), heap,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (t1 == NULL) {
        return MEMORY_E;
    }
    t2 = t1 + n;
    t3 = t2 + n;

    for (u = 0; u < n; u++) {
        t1[u] = fpr_of(g[u]);   /* g */
        t2[u] = fpr_of(F[u]);   /* F */
        t3[u] = fpr_of(f[u]);   /* f */
    }
    falcon_FFT(t1, logn);
    falcon_FFT(t2, logn);
    falcon_FFT(t3, logn);

    /* t1 <- g*F. */
    falcon_poly_mul_fft(t1, t2, logn);

    /* t1 <- g*F + q. The constant polynomial q evaluates to q (a real value) at
     * every FFT point, so only the real (lower) half is incremented. */
    for (u = 0; u < hn; u++) {
        t1[u] = fpr_add(t1[u], fpr_q);
    }

    /* t1 <- (g*F + q) / f. */
    falcon_poly_div_fft(t1, t3, logn);

    falcon_iFFT(t1, logn);

    for (u = 0; u < n; u++) {
        sword64 z;

        z = fpr_rint(t1[u]);
        if (z < -127 || z > 127) {
            ret = BAD_FUNC_ARG;
            break;
        }
        G[u] = (sword8)z;
    }

    /* t1 held the FFT images of the secret basis (g, F, f) and the derived G. */
    wc_ForceZero(t1, (word32)((size_t)3 * n * sizeof(fpr)));
    XFREE(t1, heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* ==================================================================== */
/* ffLDL tree construction (expand_privkey).                             */

/* The eager ffLDL tree + tree-based signer are compiled only for the default
 * (fast) path. WOLFSSL_FALCON_SIGN_SMALL_MEM builds the dynamic signer instead,
 * which rebuilds the tree inside the sampler and so does not use any of this. */
#ifndef WOLFSSL_FALCON_SIGN_SMALL_MEM

/* Size of the ffLDL tree (number of fpr elements) for polynomials of degree
 * 2^logn:  s(0) = 1,  s(logn) = 2^logn + 2*s(logn-1)  =>  (logn+1)*2^logn. */
static WC_INLINE unsigned ffLDL_treesize(unsigned logn)
{
    return (logn + 1) << logn;
}

/* The reference implementation expresses ffLDL construction, tree
 * normalization and Fast Fourier sampling as self-recursions on logn. wolfSSL
 * forbids recursion, so each is flattened here into an iteration over an
 * explicit stack of frames; depth is bounded by logn <= 10, so the stacks are
 * small fixed arrays. Sub-invocations run in exactly the reference order --
 * for ffSampling this is a hard requirement, since the discrete Gaussian
 * sampler consumes a PRNG stream and only the reference order reproduces the
 * reference signatures. */

/* One pending ffLDL_fft_inner sub-invocation. */
typedef struct ffLDL_job {
    fpr* tree;
    fpr* g0;
    fpr* g1;
    unsigned logn;
} ffLDL_job;

/* Iterative equivalent of the reference ffLDL_fft_inner recursion. All work of
 * an invocation happens before its two half-degree sub-invocations, so a LIFO
 * list of pending jobs suffices. Expects the (auto-adjoint, quasicyclic)
 * matrix in (g0, g1), which are used as modifiable temporaries. tmp[] needs
 * room for at least one polynomial; it is only used within a single job, never
 * across jobs. */
static void ffLDL_fft_inner(fpr* tree, fpr* g0, fpr* g1, unsigned logn,
        fpr* tmp)
{
    /* A job at logn > 0 replaces itself with two jobs at logn - 1, leaving at
     * most one pending sibling per level plus the current job: logn + 1
     * frames, <= 11 for logn <= 10. */
    ffLDL_job stk[11];
    int sp;

    stk[0].tree = tree;
    stk[0].g0 = g0;
    stk[0].g1 = g1;
    stk[0].logn = logn;
    sp = 0;

    while (sp >= 0) {
        ffLDL_job job;
        size_t n, hn;

        job = stk[sp];
        sp--;

        n = MKN(job.logn);
        if (n == 1) {
            job.tree[0] = job.g0[0];
            continue;
        }
        hn = n >> 1;

        /* d00 = g0; d11 -> tmp; L[1][0] -> tree. */
        falcon_poly_LDLmv_fft(tmp, job.tree, job.g0, job.g1, job.g0, job.logn);

        /* Split d00 (in g0) and d11 (in tmp), reusing g0/g1 as scratch:
         *   d00 -> g1, g1+hn ; d11 -> g0, g0+hn. */
        falcon_poly_split_fft(job.g1, job.g1 + hn, job.g0, job.logn);
        falcon_poly_split_fft(job.g0, job.g0 + hn, tmp, job.logn);

        /* Queue both half-degree sub-invocations; their buffers are disjoint.
         * The d11 half (in g0) is pushed first so that the d00 half (in g1)
         * runs first, matching the reference order. */
        sp++;
        stk[sp].tree = job.tree + n + ffLDL_treesize(job.logn - 1);
        stk[sp].g0 = job.g0;
        stk[sp].g1 = job.g0 + hn;
        stk[sp].logn = job.logn - 1;
        sp++;
        stk[sp].tree = job.tree + n;
        stk[sp].g0 = job.g1;
        stk[sp].g1 = job.g1 + hn;
        stk[sp].logn = job.logn - 1;
    }
}

/* Compute the ffLDL tree of the auto-adjoint matrix [[g00, adj(g01)],
 * [g01, g11]] (FFT representation). tmp[] needs room for at least three
 * polynomials. */
static void ffLDL_fft(fpr* tree, const fpr* g00, const fpr* g01,
        const fpr* g11, unsigned logn, fpr* tmp)
{
    size_t n, hn;
    fpr* d00;
    fpr* d11;

    n = MKN(logn);
    if (n == 1) {
        tree[0] = g00[0];
        return;
    }
    hn = n >> 1;
    d00 = tmp;
    d11 = tmp + n;
    tmp += n << 1;

    XMEMCPY(d00, g00, n * sizeof(*g00));
    falcon_poly_LDLmv_fft(d11, tree, g00, g01, g11, logn);

    falcon_poly_split_fft(tmp, tmp + hn, d00, logn);
    falcon_poly_split_fft(d00, d00 + hn, d11, logn);
    XMEMCPY(d11, tmp, n * sizeof(*tmp));
    ffLDL_fft_inner(tree + n, d11, d11 + hn, logn - 1, tmp);
    ffLDL_fft_inner(tree + n + ffLDL_treesize(logn - 1),
            d00, d00 + hn, logn - 1, tmp);
}

/* Normalize an ffLDL tree: each leaf x is replaced with sigma/sqrt(x). The leaf
 * stores the inverse of the spec value, saving a division here and in the
 * sampler. Iterative equivalent of the reference recursion: internal nodes do
 * no work of their own, so a LIFO list of pending subtrees replaces the two
 * tail calls (see ffLDL_fft_inner for the occupancy bound). */
static void ffLDL_binary_normalize(fpr* tree, unsigned orig_logn, unsigned logn)
{
    struct {
        fpr* tree;
        unsigned logn;
    } stk[11];
    int sp;

    stk[0].tree = tree;
    stk[0].logn = logn;
    sp = 0;

    while (sp >= 0) {
        fpr* t;
        unsigned l;
        size_t n;

        t = stk[sp].tree;
        l = stk[sp].logn;
        sp--;

        n = MKN(l);
        if (n == 1) {
            t[0] = fpr_mul(fpr_sqrt(t[0]), fpr_inv_sigma[orig_logn]);
            continue;
        }

        sp++;
        stk[sp].tree = t + n + ffLDL_treesize(l - 1);
        stk[sp].logn = l - 1;
        sp++;
        stk[sp].tree = t + n;
        stk[sp].logn = l - 1;
    }
}

#endif /* !WOLFSSL_FALCON_SIGN_SMALL_MEM (ffLDL tree construction) */

/* Convert a small-integer polynomial into the fpr representation. Shared by the
 * eager expand_privkey and the dynamic signer. */
static void smallints_to_fpr(fpr* r, const sword8* t, unsigned logn)
{
    size_t n, u;

    n = MKN(logn);
    for (u = 0; u < n; u++) {
        r[u] = fpr_of(t[u]);
    }
}

#ifndef WOLFSSL_FALCON_SIGN_SMALL_MEM
/* Expanded-key layout offsets (in fpr elements). */
static WC_INLINE size_t skoff_b00(unsigned logn) { (void)logn; return 0; }
static WC_INLINE size_t skoff_b01(unsigned logn) { return MKN(logn); }
static WC_INLINE size_t skoff_b10(unsigned logn) { return 2 * MKN(logn); }
static WC_INLINE size_t skoff_b11(unsigned logn) { return 3 * MKN(logn); }
static WC_INLINE size_t skoff_tree(unsigned logn) { return 4 * MKN(logn); }

int falcon_expand_privkey(fpr* expanded, const sword8* f, const sword8* g,
        const sword8* F, const sword8* G, unsigned logn, void* heap)
{
    size_t n;
    fpr* rf;
    fpr* rg;
    fpr* rF;
    fpr* rG;
    fpr* b00;
    fpr* b01;
    fpr* b10;
    fpr* b11;
    fpr* g00;
    fpr* g01;
    fpr* g11;
    fpr* gxx;
    fpr* tree;
    fpr* tmp;

    if (expanded == NULL || f == NULL || g == NULL || F == NULL || G == NULL
            || logn < 1 || logn > 10) {
        return BAD_FUNC_ARG;
    }

    n = MKN(logn);

    /* Internal scratch: six polynomials (matches the reference 48*2^logn). */
    tmp = (fpr*)XMALLOC((size_t)6 * n * sizeof(fpr), heap,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (tmp == NULL) {
        return MEMORY_E;
    }

    b00 = expanded + skoff_b00(logn);
    b01 = expanded + skoff_b01(logn);
    b10 = expanded + skoff_b10(logn);
    b11 = expanded + skoff_b11(logn);
    tree = expanded + skoff_tree(logn);

    /* B0 = [[g, -f], [G, -F]]. */
    rf = b01;
    rg = b00;
    rF = b11;
    rG = b10;

    smallints_to_fpr(rf, f, logn);
    smallints_to_fpr(rg, g, logn);
    smallints_to_fpr(rF, F, logn);
    smallints_to_fpr(rG, G, logn);

    falcon_FFT(rf, logn);
    falcon_FFT(rg, logn);
    falcon_FFT(rF, logn);
    falcon_FFT(rG, logn);
    falcon_poly_neg(rf, logn);
    falcon_poly_neg(rF, logn);

    /* Gram matrix G = B*B^* (upper triangle: g00, g01, g11). */
    g00 = tmp;
    g01 = g00 + n;
    g11 = g01 + n;
    gxx = g11 + n;

    XMEMCPY(g00, b00, n * sizeof(*b00));
    falcon_poly_mulselfadj_fft(g00, logn);
    XMEMCPY(gxx, b01, n * sizeof(*b01));
    falcon_poly_mulselfadj_fft(gxx, logn);
    falcon_poly_add(g00, gxx, logn);

    XMEMCPY(g01, b00, n * sizeof(*b00));
    falcon_poly_muladj_fft(g01, b10, logn);
    XMEMCPY(gxx, b01, n * sizeof(*b01));
    falcon_poly_muladj_fft(gxx, b11, logn);
    falcon_poly_add(g01, gxx, logn);

    XMEMCPY(g11, b10, n * sizeof(*b10));
    falcon_poly_mulselfadj_fft(g11, logn);
    XMEMCPY(gxx, b11, n * sizeof(*b11));
    falcon_poly_mulselfadj_fft(gxx, logn);
    falcon_poly_add(g11, gxx, logn);

    /* Falcon tree, then normalization. */
    ffLDL_fft(tree, g00, g01, g11, logn, gxx);
    ffLDL_binary_normalize(tree, logn, logn);

    /* tmp held the secret-derived Gram matrix and ffLDL intermediates. */
    wc_ForceZero(tmp, (word32)((size_t)6 * n * sizeof(fpr)));
    XFREE(tmp, heap, DYNAMIC_TYPE_TMP_BUFFER);
    return 0;
}

/* ==================================================================== */
/* Fast Fourier sampling.                                                */

/* Base case at logn == 2 (n = 4): the two bottom levels of the sampling
 * walk, fully unrolled over the four coefficients (as in the reference). */
static WC_INLINE void ffSampling_fft_deg4(falcon_samplerZ samp, void* samp_ctx,
        fpr* z0, fpr* z1, const fpr* tree, const fpr* t0, const fpr* t1)
{
    const fpr* tree0;
    const fpr* tree1;
    fpr x0, x1, y0, y1, w0, w1, w2, w3, sigma;
    fpr a_re, a_im, b_re, b_im, c_re, c_im;

    tree0 = tree + 4;
    tree1 = tree + 8;

    a_re = t1[0];
    a_im = t1[2];
    b_re = t1[1];
    b_im = t1[3];
    c_re = fpr_add(a_re, b_re);
    c_im = fpr_add(a_im, b_im);
    w0 = fpr_half(c_re);
    w1 = fpr_half(c_im);
    c_re = fpr_sub(a_re, b_re);
    c_im = fpr_sub(a_im, b_im);
    w2 = fpr_mul(fpr_add(c_re, c_im), fpr_invsqrt8);
    w3 = fpr_mul(fpr_sub(c_im, c_re), fpr_invsqrt8);

    x0 = w2;
    x1 = w3;
    sigma = tree1[3];
    w2 = fpr_of(samp(samp_ctx, x0, sigma));
    w3 = fpr_of(samp(samp_ctx, x1, sigma));
    a_re = fpr_sub(x0, w2);
    a_im = fpr_sub(x1, w3);
    b_re = tree1[0];
    b_im = tree1[1];
    c_re = fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im));
    c_im = fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re));
    x0 = fpr_add(c_re, w0);
    x1 = fpr_add(c_im, w1);
    sigma = tree1[2];
    w0 = fpr_of(samp(samp_ctx, x0, sigma));
    w1 = fpr_of(samp(samp_ctx, x1, sigma));

    a_re = w0;
    a_im = w1;
    b_re = w2;
    b_im = w3;
    c_re = fpr_mul(fpr_sub(b_re, b_im), fpr_invsqrt2);
    c_im = fpr_mul(fpr_add(b_re, b_im), fpr_invsqrt2);
    z1[0] = w0 = fpr_add(a_re, c_re);
    z1[2] = w2 = fpr_add(a_im, c_im);
    z1[1] = w1 = fpr_sub(a_re, c_re);
    z1[3] = w3 = fpr_sub(a_im, c_im);

    w0 = fpr_sub(t1[0], w0);
    w1 = fpr_sub(t1[1], w1);
    w2 = fpr_sub(t1[2], w2);
    w3 = fpr_sub(t1[3], w3);

    a_re = w0;
    a_im = w2;
    b_re = tree[0];
    b_im = tree[2];
    w0 = fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im));
    w2 = fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re));
    a_re = w1;
    a_im = w3;
    b_re = tree[1];
    b_im = tree[3];
    w1 = fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im));
    w3 = fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re));

    w0 = fpr_add(w0, t0[0]);
    w1 = fpr_add(w1, t0[1]);
    w2 = fpr_add(w2, t0[2]);
    w3 = fpr_add(w3, t0[3]);

    a_re = w0;
    a_im = w2;
    b_re = w1;
    b_im = w3;
    c_re = fpr_add(a_re, b_re);
    c_im = fpr_add(a_im, b_im);
    w0 = fpr_half(c_re);
    w1 = fpr_half(c_im);
    c_re = fpr_sub(a_re, b_re);
    c_im = fpr_sub(a_im, b_im);
    w2 = fpr_mul(fpr_add(c_re, c_im), fpr_invsqrt8);
    w3 = fpr_mul(fpr_sub(c_im, c_re), fpr_invsqrt8);

    x0 = w2;
    x1 = w3;
    sigma = tree0[3];
    w2 = y0 = fpr_of(samp(samp_ctx, x0, sigma));
    w3 = y1 = fpr_of(samp(samp_ctx, x1, sigma));
    a_re = fpr_sub(x0, y0);
    a_im = fpr_sub(x1, y1);
    b_re = tree0[0];
    b_im = tree0[1];
    c_re = fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im));
    c_im = fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re));
    x0 = fpr_add(c_re, w0);
    x1 = fpr_add(c_im, w1);
    sigma = tree0[2];
    w0 = fpr_of(samp(samp_ctx, x0, sigma));
    w1 = fpr_of(samp(samp_ctx, x1, sigma));

    a_re = w0;
    a_im = w1;
    b_re = w2;
    b_im = w3;
    c_re = fpr_mul(fpr_sub(b_re, b_im), fpr_invsqrt2);
    c_im = fpr_mul(fpr_add(b_re, b_im), fpr_invsqrt2);
    z0[0] = fpr_add(a_re, c_re);
    z0[2] = fpr_add(a_im, c_im);
    z0[1] = fpr_sub(a_re, c_re);
    z0[3] = fpr_sub(a_im, c_im);
}

/* Base case at logn == 1 (n = 2): reachable only for the (insecure) smallest
 * degree. */
static WC_INLINE void ffSampling_fft_deg2(falcon_samplerZ samp, void* samp_ctx,
        fpr* z0, fpr* z1, const fpr* tree, const fpr* t0, const fpr* t1)
{
    fpr x0, x1, y0, y1, sigma;
    fpr a_re, a_im, b_re, b_im, c_re, c_im;

    x0 = t1[0];
    x1 = t1[1];
    sigma = tree[3];
    z1[0] = y0 = fpr_of(samp(samp_ctx, x0, sigma));
    z1[1] = y1 = fpr_of(samp(samp_ctx, x1, sigma));
    a_re = fpr_sub(x0, y0);
    a_im = fpr_sub(x1, y1);
    b_re = tree[0];
    b_im = tree[1];
    c_re = fpr_sub(fpr_mul(a_re, b_re), fpr_mul(a_im, b_im));
    c_im = fpr_add(fpr_mul(a_re, b_im), fpr_mul(a_im, b_re));
    x0 = fpr_add(c_re, t0[0]);
    x1 = fpr_add(c_im, t0[1]);
    sigma = tree[2];
    z0[0] = fpr_of(samp(samp_ctx, x0, sigma));
    z0[1] = fpr_of(samp(samp_ctx, x1, sigma));
}

/* One flattened falcon_ffSampling_fft invocation at logn >= 3. Each frame is
 * visited three times, tracked by 'stage':
 *   FF_SAMP_STAGE_T1:   split t1 and descend into the tree1 subtree;
 *   FF_SAMP_STAGE_T0:   merge z1, build tb0 = t0 + (t1 - z1)*L in tmp, split
 *                       it and descend into the tree0 subtree;
 *   FF_SAMP_STAGE_DONE: merge z0 and pop back to the parent frame. */
typedef struct ffSampling_frame {
    fpr* z0;
    fpr* z1;
    const fpr* tree;
    const fpr* t0;
    const fpr* t1;
    fpr* tmp;
    unsigned logn;
    unsigned stage;
} ffSampling_frame;

#define FF_SAMP_STAGE_T1     0U
#define FF_SAMP_STAGE_T0     1U
#define FF_SAMP_STAGE_DONE   2U

/* Maximum frame-stack depth: one frame per level from the top logn down to 3
 * (levels 2 and 1 run as the inlined base cases above), so at most logn - 2
 * <= 8 frames for logn <= 10. */
#define FF_SAMP_MAX_FRAMES   8

/* Descend into a sub-invocation at 'logn': run the base case directly when
 * the walk bottoms out (logn == 2), otherwise push a frame for the state
 * machine in falcon_ffSampling_fft. Returns the new top-of-stack index. */
static WC_INLINE int ffSampling_descend(ffSampling_frame* stk, int sp,
        falcon_samplerZ samp, void* samp_ctx, fpr* z0, fpr* z1,
        const fpr* tree, const fpr* t0, const fpr* t1, unsigned logn, fpr* tmp)
{
    if (logn == 2) {
        ffSampling_fft_deg4(samp, samp_ctx, z0, z1, tree, t0, t1);
    }
    else {
        sp++;
        stk[sp].z0 = z0;
        stk[sp].z1 = z1;
        stk[sp].tree = tree;
        stk[sp].t0 = t0;
        stk[sp].t1 = t1;
        stk[sp].tmp = tmp;
        stk[sp].logn = logn;
        stk[sp].stage = FF_SAMP_STAGE_T1;
    }
    return sp;
}

/* Iterative equivalent of the reference ffSampling_fft recursion. The frames
 * are visited -- and hence the sampler is invoked -- in exactly the reference
 * recursion order; the sampler consumes a PRNG stream, so preserving that
 * order is what keeps the produced signatures identical to the reference. */
void falcon_ffSampling_fft(falcon_samplerZ samp, void* samp_ctx,
        fpr* z0, fpr* z1, const fpr* tree, const fpr* t0, const fpr* t1,
        unsigned logn, fpr* tmp)
{
    ffSampling_frame stk[FF_SAMP_MAX_FRAMES];
    int sp;

    /* Degrees handled entirely by the inlined base cases. */
    if (logn == 2) {
        ffSampling_fft_deg4(samp, samp_ctx, z0, z1, tree, t0, t1);
        return;
    }
    if (logn == 1) {
        ffSampling_fft_deg2(samp, samp_ctx, z0, z1, tree, t0, t1);
        return;
    }
    /* Callers validate 1 <= logn <= 10 (falcon_do_sign_tree); this keeps the
     * frame stack in bounds regardless. */
    if (logn < 1 || logn > 10) {
        return;
    }

    sp = ffSampling_descend(stk, -1, samp, samp_ctx, z0, z1, tree, t0, t1,
            logn, tmp);

    while (sp >= 0) {
        ffSampling_frame* f;
        size_t n, hn;

        f = &stk[sp];
        n = (size_t)1 << f->logn;
        hn = n >> 1;

        switch (f->stage) {
        case FF_SAMP_STAGE_T1:
            f->stage = FF_SAMP_STAGE_T0;
            /* Split t1 into z1, then sample the halves against the tree1
             * subtree; the sampled halves land in tmp, tmp + hn. */
            falcon_poly_split_fft(f->z1, f->z1 + hn, f->t1, f->logn);
            sp = ffSampling_descend(stk, sp, samp, samp_ctx,
                    f->tmp, f->tmp + hn,
                    f->tree + n + ffLDL_treesize(f->logn - 1),
                    f->z1, f->z1 + hn, f->logn - 1, f->tmp + n);
            break;

        case FF_SAMP_STAGE_T0:
            f->stage = FF_SAMP_STAGE_DONE;
            /* Merge the sampled halves back into z1. */
            falcon_poly_merge_fft(f->z1, f->tmp, f->tmp + hn, f->logn);

            /* tb0 = t0 + (t1 - z1) * L, built in tmp[]. */
            XMEMCPY(f->tmp, f->t1, n * sizeof(*f->t1));
            falcon_poly_sub(f->tmp, f->z1, f->logn);
            falcon_poly_mul_fft(f->tmp, f->tree, f->logn);
            falcon_poly_add(f->tmp, f->t0, f->logn);

            /* Split tb0 into z0, then sample the halves against the tree0
             * subtree. */
            falcon_poly_split_fft(f->z0, f->z0 + hn, f->tmp, f->logn);
            sp = ffSampling_descend(stk, sp, samp, samp_ctx,
                    f->tmp, f->tmp + hn, f->tree + n,
                    f->z0, f->z0 + hn, f->logn - 1, f->tmp + n);
            break;

        default:
            /* FF_SAMP_STAGE_DONE: merge the sampled halves back into z0;
             * this invocation is complete. */
            falcon_poly_merge_fft(f->z0, f->tmp, f->tmp + hn, f->logn);
            sp--;
            break;
        }
    }
}

/* ==================================================================== */
/* do_sign_tree / sign_core.                                             */

#endif /* !WOLFSSL_FALCON_SIGN_SMALL_MEM (expand_privkey + tree sampler) */

/* is_short_half: squared l2-norm of (s1, s2) where the s1 partial sum (sqn) is
 * already accumulated and saturates to 2^32-1. Returns 1 if within bound.
 * Shared by the tree-based and dynamic signers. */
static int is_short_half(word32 sqn, const sword16* s2, unsigned logn)
{
    size_t n, u;
    word32 ng;

    n = (size_t)1 << logn;
    ng = (word32)(0 - (sqn >> 31));
    for (u = 0; u < n; u++) {
        sword32 z;

        z = s2[u];
        sqn += (word32)(z * z);
        ng |= sqn;
    }
    sqn |= (word32)(0 - (ng >> 31));

    return sqn <= l2bound[logn];
}

#ifndef WOLFSSL_FALCON_SIGN_SMALL_MEM
/* Single signing attempt over the expanded key. Returns 1 if the produced
 * (s1, s2) is short enough (s2 written), 0 if the caller should retry. tmp[]
 * needs room for six polynomials. */
static int do_sign_tree_once(falcon_samplerZ samp, void* samp_ctx, sword16* s2,
        const fpr* expanded, const word16* hm, unsigned logn, fpr* tmp)
{
    size_t n, u;
    fpr* t0;
    fpr* t1;
    fpr* tx;
    fpr* ty;
    const fpr* b00;
    const fpr* b01;
    const fpr* b10;
    const fpr* b11;
    const fpr* tree;
    fpr ni;
    word32 sqn, ng;
    sword16* s1tmp;
    sword16* s2tmp;

    n = MKN(logn);
    t0 = tmp;
    t1 = t0 + n;
    b00 = expanded + skoff_b00(logn);
    b01 = expanded + skoff_b01(logn);
    b10 = expanded + skoff_b10(logn);
    b11 = expanded + skoff_b11(logn);
    tree = expanded + skoff_tree(logn);

    /* Target vector [hm, 0]. */
    for (u = 0; u < n; u++) {
        t0[u] = fpr_of(hm[u]);
    }

    /* Apply the basis to obtain the real target (after q-normalization). */
    falcon_FFT(t0, logn);
    ni = fpr_inverse_of_q;
    XMEMCPY(t1, t0, n * sizeof(*t0));
    falcon_poly_mul_fft(t1, b01, logn);
    falcon_poly_mulconst(t1, fpr_neg(ni), logn);
    falcon_poly_mul_fft(t0, b11, logn);
    falcon_poly_mulconst(t0, ni, logn);

    tx = t1 + n;
    ty = tx + n;

    /* Sampling; output written to [tx, ty]. */
    falcon_ffSampling_fft(samp, samp_ctx, tx, ty, tree, t0, t1, logn, ty + n);

    /* Lattice point corresponding to that short vector. */
    XMEMCPY(t0, tx, n * sizeof(*tx));
    XMEMCPY(t1, ty, n * sizeof(*ty));
    falcon_poly_mul_fft(tx, b00, logn);
    falcon_poly_mul_fft(ty, b10, logn);
    falcon_poly_add(tx, ty, logn);
    XMEMCPY(ty, t0, n * sizeof(*t0));
    falcon_poly_mul_fft(ty, b01, logn);

    XMEMCPY(t0, tx, n * sizeof(*tx));
    falcon_poly_mul_fft(t1, b11, logn);
    falcon_poly_add(t1, ty, logn);

    falcon_iFFT(t0, logn);
    falcon_iFFT(t1, logn);

    /* s1 = hm - round(t0); accumulate squared norm with saturation. */
    s1tmp = (sword16*)tx;
    sqn = 0;
    ng = 0;
    for (u = 0; u < n; u++) {
        sword32 z;

        z = (sword32)hm[u] - (sword32)fpr_rint(t0[u]);
        sqn += (word32)(z * z);
        ng |= sqn;
        s1tmp[u] = (sword16)z;
    }
    sqn |= (word32)(0 - (ng >> 31));

    /* s2 = -round(t1) (written into tmp; never into s2[] until accepted, so a
     * retry preserves hm[]). */
    s2tmp = (sword16*)tmp;
    for (u = 0; u < n; u++) {
        s2tmp[u] = (sword16)(0 - fpr_rint(t1[u]));
    }
    if (is_short_half(sqn, s2tmp, logn)) {
        XMEMCPY(s2, s2tmp, n * sizeof(*s2));
        XMEMCPY(tmp, s1tmp, n * sizeof(*s1tmp));
        return 1;
    }
    return 0;
}

int falcon_do_sign_tree(falcon_samplerZ samp, void* samp_ctx, sword16* s2,
        const fpr* expanded, const word16* hm, unsigned logn, fpr* tmp,
        const int* samplerErr)
{
    if (samp == NULL || s2 == NULL || expanded == NULL || hm == NULL
            || tmp == NULL || logn < 1 || logn > 10) {
        return BAD_FUNC_ARG;
    }

    /* Loop until the candidate (s1, s2) is short enough. With degrees 512 and
     * 1024 a restart is very rare (expected iteration count is ~1), so the
     * bound below is astronomically beyond any legitimate run; it exists only
     * so a wedged sampler -- e.g. a PRNG whose SHAKE256 squeeze started failing,
     * yielding candidates that never pass the norm bound -- terminates instead
     * of spinning forever. */
    {
        unsigned long iter;
        for (iter = 0; iter < FALCON_SIGN_MAX_RESTARTS; iter++) {
            if (do_sign_tree_once(samp, samp_ctx, s2, expanded, hm, logn, tmp)) {
                return 0;
            }
            /* Fail fast on a sampler PRNG error (non-secret, already latched):
             * no point burning restarts on candidates built from invalid
             * randomness. */
            if (samplerErr != NULL && *samplerErr != 0) {
                return *samplerErr;
            }
#ifdef WOLFSSL_FALCON_SIGN_STATS
            /* Count this restart (counter defined at file scope). */
            falcon_sign_restart_count++;
#endif
        }
    }
    /* Exhausted the restart bound: treat as an operational failure. */
    return WC_FAILURE;
}

int falcon_sign_core(falcon_sampler_ctx* spc, const fpr* expanded,
        const word16* c, sword16* s2, fpr* tmp, unsigned logn)
{
    int ret;

    if (spc == NULL) {
        return BAD_FUNC_ARG;
    }
    ret = falcon_do_sign_tree(falcon_sampler_z, spc, s2, expanded, c, logn, tmp,
            &spc->p.err);
    /* Reject the signature if the sampler's PRNG failed at any point: the
     * squeezed bytes it consumed would be invalid, so the result is unsafe. */
    if (ret == 0 && spc->p.err != 0) {
        ret = spc->p.err;
    }
    return ret;
}

#endif /* !WOLFSSL_FALCON_SIGN_SMALL_MEM (eager tree-based signer) */

#ifdef WOLFSSL_FALCON_SIGN_SMALL_MEM
/* Low-memory ("dynamic") signing. Instead of precomputing and storing the whole
 * expanded key (the ffLDL tree, ~120KB at Falcon-1024), it rebuilds the tree on
 * the fly *inside* the sampling recursion, so only one scratch buffer of
 * FALCON_SIGN_DYN_TMP_FPR(logn) fpr is ever live -- roughly half the memory of
 * the expand+tree path, at the cost of redoing the tree work on every signing
 * attempt. Faithful port of the Falcon reference sign_dyn / ffSampling_fft_dyntree
 * (so the sampler is invoked in exactly the reference order and the signatures
 * are identical to the default path), with the reference recursion flattened to
 * an explicit stack per the wolfSSL no-recursion rule. */

/* Scratch, in fpr, for falcon_do_sign_dyn (reference TMPSIZE_SIGNDYN = 78*2^logn
 * bytes; 10*2^logn fpr = 80*2^logn bytes covers it for the supported logn). */
#define FALCON_SIGN_DYN_TMP_FPR(logn)    ((size_t)10 << (logn))

/* One pending ffSampling_fft_dyntree node (the reference recursion, flattened).
 * Each internal node LDL-decomposes its Gram block in place, then descends first
 * into the right sub-tree (stage 1) and then the left (stage 2). */
typedef struct falcon_dyn_frame {
    fpr* t0;
    fpr* t1;
    fpr* g00;
    fpr* g01;
    fpr* g11;
    fpr* tmp;
    unsigned logn;
    unsigned stage;
} falcon_dyn_frame;

#define FALCON_DYN_STAGE_ENTER  0U
#define FALCON_DYN_STAGE_RIGHT  1U   /* right child done, do middle work + left */
#define FALCON_DYN_STAGE_LEFT   2U   /* left child done, merge and pop          */
/* logn <= 10, so the deepest chain is 11 frames (logn..0). */
#define FALCON_DYN_MAX_FRAMES   12

/* Fast Fourier sampling that builds the LDL tree lazily. Iterative equivalent of
 * the reference ffSampling_fft_dyntree; the sampler call order is identical. */
static void falcon_ffSampling_fft_dyntree(falcon_samplerZ samp, void* samp_ctx,
        fpr* t0, fpr* t1, fpr* g00, fpr* g01, fpr* g11,
        unsigned orig_logn, unsigned logn, fpr* tmp)
{
    falcon_dyn_frame stk[FALCON_DYN_MAX_FRAMES];
    int sp;

    if (logn > 10) {
        return;
    }
    stk[0].t0 = t0; stk[0].t1 = t1;
    stk[0].g00 = g00; stk[0].g01 = g01; stk[0].g11 = g11;
    stk[0].tmp = tmp; stk[0].logn = logn; stk[0].stage = FALCON_DYN_STAGE_ENTER;
    sp = 1;

    while (sp > 0) {
        falcon_dyn_frame* f = &stk[sp - 1];
        size_t n, hn;
        fpr* z0;
        fpr* z1;

        /* Deepest level: the leaf value is g00[0]; normalize by sigma and
         * sample the two coordinates. */
        if (f->logn == 0) {
            fpr leaf = fpr_mul(fpr_sqrt(f->g00[0]), fpr_inv_sigma[orig_logn]);
            f->t0[0] = fpr_of(samp(samp_ctx, f->t0[0], leaf));
            f->t1[0] = fpr_of(samp(samp_ctx, f->t1[0], leaf));
            sp--;
            continue;
        }

        n = (size_t)1 << f->logn;
        hn = n >> 1;

        if (f->stage == FALCON_DYN_STAGE_ENTER) {
            /* Decompose G into LDL (in place): keep d00 (== g00), d11 and l10. */
            falcon_poly_LDL_fft(f->g00, f->g01, f->g11, f->logn);
            /* Split d00 and d11 into half-size Gram matrices; save l10 in tmp. */
            falcon_poly_split_fft(f->tmp, f->tmp + hn, f->g00, f->logn);
            XMEMCPY(f->g00, f->tmp, n * sizeof(fpr));
            falcon_poly_split_fft(f->tmp, f->tmp + hn, f->g11, f->logn);
            XMEMCPY(f->g11, f->tmp, n * sizeof(fpr));
            XMEMCPY(f->tmp, f->g01, n * sizeof(fpr));
            XMEMCPY(f->g01, f->g00, hn * sizeof(fpr));
            XMEMCPY(f->g01 + hn, f->g11, hn * sizeof(fpr));

            /* Split t1 and descend into the right sub-tree. */
            z1 = f->tmp + n;
            falcon_poly_split_fft(z1, z1 + hn, f->t1, f->logn);
            f->stage = FALCON_DYN_STAGE_RIGHT;
            stk[sp].t0  = z1;          stk[sp].t1  = z1 + hn;
            stk[sp].g00 = f->g11;      stk[sp].g01 = f->g11 + hn;
            stk[sp].g11 = f->g01 + hn; stk[sp].tmp = z1 + n;
            stk[sp].logn = f->logn - 1; stk[sp].stage = FALCON_DYN_STAGE_ENTER;
            sp++;
            continue;
        }
        else if (f->stage == FALCON_DYN_STAGE_RIGHT) {
            /* Merge the right-subtree result, then tb0 = t0 + (t1 - z1)*l10. */
            z1 = f->tmp + n;
            falcon_poly_merge_fft(f->tmp + (n << 1), z1, z1 + hn, f->logn);
            XMEMCPY(z1, f->t1, n * sizeof(fpr));
            falcon_poly_sub(z1, f->tmp + (n << 1), f->logn);
            XMEMCPY(f->t1, f->tmp + (n << 1), n * sizeof(fpr));
            falcon_poly_mul_fft(f->tmp, z1, f->logn);
            falcon_poly_add(f->t0, f->tmp, f->logn);

            /* Split tb0 (in t0) and descend into the left sub-tree. */
            z0 = f->tmp;
            falcon_poly_split_fft(z0, z0 + hn, f->t0, f->logn);
            f->stage = FALCON_DYN_STAGE_LEFT;
            stk[sp].t0  = z0;      stk[sp].t1  = z0 + hn;
            stk[sp].g00 = f->g00;  stk[sp].g01 = f->g00 + hn;
            stk[sp].g11 = f->g01;  stk[sp].tmp = z0 + n;
            stk[sp].logn = f->logn - 1; stk[sp].stage = FALCON_DYN_STAGE_ENTER;
            sp++;
            continue;
        }
        else {  /* FALCON_DYN_STAGE_LEFT */
            z0 = f->tmp;
            falcon_poly_merge_fft(f->t0, z0, z0 + hn, f->logn);
            sp--;
            continue;
        }
    }
}

/* One dynamic signing attempt. Returns 1 if the produced (s1, s2) is short
 * enough (s2 written), 0 to retry with a fresh nonce. Faithful port of the
 * reference do_sign_dyn. 'tmp' must hold FALCON_SIGN_DYN_TMP_FPR(logn) fpr. */
static int falcon_do_sign_dyn_once(falcon_samplerZ samp, void* samp_ctx,
        sword16* s2, const sword8* f, const sword8* g, const sword8* F,
        const sword8* G, const word16* hm, unsigned logn, fpr* tmp)
{
    size_t n, u;
    fpr *t0, *t1, *tx, *ty;
    fpr *b00, *b01, *b10, *b11, *g00, *g01, *g11;
    fpr ni;
    word32 sqn, ng;
    sword16 *s1tmp, *s2tmp;

    n = MKN(logn);

    /* Basis B = [[g, -f], [G, -F]] in FFT. */
    b00 = tmp; b01 = b00 + n; b10 = b01 + n; b11 = b10 + n;
    smallints_to_fpr(b01, f, logn);
    smallints_to_fpr(b00, g, logn);
    smallints_to_fpr(b11, F, logn);
    smallints_to_fpr(b10, G, logn);
    falcon_FFT(b01, logn); falcon_FFT(b00, logn);
    falcon_FFT(b11, logn); falcon_FFT(b10, logn);
    falcon_poly_neg(b01, logn);
    falcon_poly_neg(b11, logn);

    /* Gram matrix G = B*adj(B), upper triangle; keep b01, b11 for the target. */
    t0 = b11 + n; t1 = t0 + n;
    XMEMCPY(t0, b01, n * sizeof(fpr)); falcon_poly_mulselfadj_fft(t0, logn);
    XMEMCPY(t1, b00, n * sizeof(fpr)); falcon_poly_muladj_fft(t1, b10, logn);
    falcon_poly_mulselfadj_fft(b00, logn); falcon_poly_add(b00, t0, logn); /* g00 */
    XMEMCPY(t0, b01, n * sizeof(fpr));
    falcon_poly_muladj_fft(b01, b11, logn); falcon_poly_add(b01, t1, logn); /* g01 */
    falcon_poly_mulselfadj_fft(b10, logn);
    XMEMCPY(t1, b11, n * sizeof(fpr)); falcon_poly_mulselfadj_fft(t1, logn);
    falcon_poly_add(b10, t1, logn);                                        /* g11 */

    /* Layout now: g00 g01 g11 b11 b01 t0 t1. */
    g00 = b00; g01 = b01; g11 = b10;
    b01 = t0; t0 = b01 + n; t1 = t0 + n;

    /* Target [hm, 0], then apply the basis. */
    for (u = 0; u < n; u++) {
        t0[u] = fpr_of(hm[u]);
    }
    falcon_FFT(t0, logn);
    ni = fpr_inverse_of_q;
    XMEMCPY(t1, t0, n * sizeof(fpr));
    falcon_poly_mul_fft(t1, b01, logn); falcon_poly_mulconst(t1, fpr_neg(ni), logn);
    falcon_poly_mul_fft(t0, b11, logn); falcon_poly_mulconst(t0, ni, logn);

    /* Discard b01, b11: move (t0,t1) down. Layout: g00 g01 g11 t0 t1. */
    XMEMMOVE(b11, t0, n * 2 * sizeof(fpr));
    t0 = g11 + n; t1 = t0 + n;

    /* Sample; result over (t0,t1). */
    falcon_ffSampling_fft_dyntree(samp, samp_ctx, t0, t1, g00, g01, g11,
            logn, logn, t1 + n);

    /* Recompute the basis (it was overwritten) and get the lattice point. */
    b00 = tmp; b01 = b00 + n; b10 = b01 + n; b11 = b10 + n;
    XMEMMOVE(b11 + n, t0, n * 2 * sizeof(fpr));
    t0 = b11 + n; t1 = t0 + n;
    smallints_to_fpr(b01, f, logn); smallints_to_fpr(b00, g, logn);
    smallints_to_fpr(b11, F, logn); smallints_to_fpr(b10, G, logn);
    falcon_FFT(b01, logn); falcon_FFT(b00, logn);
    falcon_FFT(b11, logn); falcon_FFT(b10, logn);
    falcon_poly_neg(b01, logn); falcon_poly_neg(b11, logn);
    tx = t1 + n; ty = tx + n;

    XMEMCPY(tx, t0, n * sizeof(fpr)); XMEMCPY(ty, t1, n * sizeof(fpr));
    falcon_poly_mul_fft(tx, b00, logn); falcon_poly_mul_fft(ty, b10, logn);
    falcon_poly_add(tx, ty, logn);
    XMEMCPY(ty, t0, n * sizeof(fpr)); falcon_poly_mul_fft(ty, b01, logn);
    XMEMCPY(t0, tx, n * sizeof(fpr));
    falcon_poly_mul_fft(t1, b11, logn); falcon_poly_add(t1, ty, logn);
    falcon_iFFT(t0, logn); falcon_iFFT(t1, logn);

    /* s1 = hm - round(t0); accumulate squared norm with saturation. */
    s1tmp = (sword16*)tx;
    sqn = 0; ng = 0;
    for (u = 0; u < n; u++) {
        sword32 z = (sword32)hm[u] - (sword32)fpr_rint(t0[u]);
        sqn += (word32)(z * z);
        ng |= sqn;
        s1tmp[u] = (sword16)z;
    }
    sqn |= (word32)(0 - (ng >> 31));

    /* s2 = -round(t1); only committed if the pair is short (hm must survive a
     * retry, and s2[] may alias hm[]). */
    s2tmp = (sword16*)tmp;
    for (u = 0; u < n; u++) {
        s2tmp[u] = (sword16)(0 - fpr_rint(t1[u]));
    }
    if (is_short_half(sqn, s2tmp, logn)) {
        XMEMCPY(s2, s2tmp, n * sizeof(sword16));
        XMEMCPY(tmp, s1tmp, n * sizeof(sword16));
        return 1;
    }
    return 0;
}

/* Dynamic signing with restart, mirroring falcon_do_sign_tree. */
static int falcon_do_sign_dyn(falcon_samplerZ samp, void* samp_ctx, sword16* s2,
        const sword8* f, const sword8* g, const sword8* F, const sword8* G,
        const word16* hm, unsigned logn, fpr* tmp, const int* samplerErr)
{
    unsigned long iter;

    if (samp == NULL || s2 == NULL || f == NULL || g == NULL || F == NULL
            || G == NULL || hm == NULL || tmp == NULL || logn < 1 || logn > 10) {
        return BAD_FUNC_ARG;
    }
    for (iter = 0; iter < FALCON_SIGN_MAX_RESTARTS; iter++) {
        if (falcon_do_sign_dyn_once(samp, samp_ctx, s2, f, g, F, G, hm, logn,
                tmp)) {
            return 0;
        }
        if (samplerErr != NULL && *samplerErr != 0) {
            return *samplerErr;
        }
    }
    return WC_FAILURE;
}

/* Top-level low-memory sign: like falcon_sign_core but from the raw basis
 * (f, g, F, G) instead of a precomputed expanded key. */
static int falcon_sign_dyn_core(falcon_sampler_ctx* spc, const sword8* f,
        const sword8* g, const sword8* F, const sword8* G, const word16* c,
        sword16* s2, fpr* tmp, unsigned logn)
{
    int ret;

    if (spc == NULL) {
        return BAD_FUNC_ARG;
    }
    ret = falcon_do_sign_dyn(falcon_sampler_z, spc, s2, f, g, F, G, c, logn, tmp,
            &spc->p.err);
    if (ret == 0 && spc->p.err != 0) {
        ret = spc->p.err;
    }
    return ret;
}
#endif /* WOLFSSL_FALCON_SIGN_SMALL_MEM */

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY && !WOLF_CRYPTO_CB_ONLY_FALCON */

#if defined(HAVE_FALCON) && !defined(WOLF_CRYPTO_CB_ONLY_FALCON)


#ifndef WOLFSSL_FALCON_VERIFY_ONLY
#endif


/* A completed sign attempt whose compressed signature overruns the level's
 * fixed length is rejected and re-sampled with a fresh nonce. Over-length
 * compression is rare (well under 1% per attempt), so this bound is only ever
 * approached by a wedged RNG feeding constant nonces -- in which case the loop
 * exits with BUFFER_E rather than spinning forever. Mirrors the named restart
 * bound (FALCON_SIGN_MAX_RESTARTS) on the sign-tree loop in wc_falcon_sign.c. */
#define FALCON_SIGN_MAX_ENCODE_RETRIES 32

/* Squared L2-norm acceptance bounds, indexed by logn. Values from the Falcon
 * specification / reference implementation (l2bound table). */
static const word32 falcon_l2bound[] = {
    /* 0..8 unused */ 0, 0, 0, 0, 0, 0, 0, 0, 0,
    34034726u,   /* logn = 9  (Falcon-512)  */
    70265242u    /* logn = 10 (Falcon-1024) */
};

/* ------------------------------------------------------------------------ */
/* Small modular helpers (correctness-first; hot paths are accelerated by the
 * generated per-arch backends in a later phase).                            */
/* ------------------------------------------------------------------------ */

static word32 falcon_modpow(word32 b, word32 e)
{
    word64 r = 1, bb = b % FALCON_Q;
    while (e != 0) {
        if ((e & 1) != 0) {
            r = (r * bb) % FALCON_Q;
        }
        bb = (bb * bb) % FALCON_Q;
        e >>= 1;
    }
    return (word32)r;
}

/* q is prime, so a^(q-2) == a^-1 (mod q). */
static word32 falcon_modinv(word32 a)
{
    return falcon_modpow(a, FALCON_Q - 2);
}

/* Bit-reversed twiddle tables for the degree-n negacyclic verify NTT, keyed by
 * level. psi is a primitive 2n-th root of unity (psi^n == -1 mod q); these were
 * generated once with falcon_modpow/falcon_modinv over the bit-reversal
 * permutation and embedded as read-only constants. Precomputing them avoids
 * both the per-verify O(n) modular-exponentiation cost of rebuilding them and
 * any lazy-initialisation data race on a shared mutable cache. */
static const word16 falcon_zetas_l1[512] = {
        1,  1479,  8246,  5146,  4134,  6553, 11567,  1305,  5860,  3195,  1212, 10643,
     3621,  9744,  8785,  3542,  7311, 10938,  8961,  5777,  5023,  6461,  5728,  4591,
     3006,  9545,   563,  9314,  2625, 11340,  4821,  2639, 12149,  1853,   726,  4611,
    11112,  4255,  2768,  1635,  2963,  7393,  2366,  9238,  9198, 12208, 11289,  7969,
     8736,  4805, 11227,  2294,  9542,  4846,  9154,  8577,  9275,  3201,  7203, 10963,
     1170,  9970,   955, 11499,  8340,  8993,  2396,  4452,  6915,  2837,   130,  7935,
    11336,  3748,  6522, 11462,  5067, 10092, 12171,  9813,  8011,  1673,  5331,  7300,
    10908,  9764,  4177,  8705,   480,  9447,  1022, 12280,  5791, 11745,  9821, 11950,
    12144,  6747,  8652,  3459,  2731,  8357,  6378,  7399, 10530,  3707,  8595,  5179,
     3382,   355,  4231,  2548,  9048, 11560,  3289, 10276,  9005,  9408,  5092, 10200,
     6534,  4632,  4388,  1260,   334,  2426,  1428, 10593,  3400,  2399,  5191,  9153,
     9273,   243,  3000,   671,  3531, 11813,  3985,  7384, 10111, 10745,  6730, 11869,
     9042,  2686,  2969,  3978,  8779,  6957,  9424,  2370,  8241, 10040,  9405, 11136,
     3186,  5407, 10163,  1630,  3271,  8232, 10600,  8925,  4414,  2847, 10115,  4372,
     9509,  5195,  7394, 10805,  9984,  7247,  4053,  9644, 12176,  4919,  2166,  8374,
    12129,  9140,  7852,     3,  1426,  7635, 10512,  1663,  8653,  4938,  2704,  5291,
     5277,  1168, 11082,  9041,  2143, 11224, 11885,  4645,  4096, 11796,  5444,  2381,
    10911,  1912,  4337, 11854,  4976, 10682, 11414,  8509, 11287,  5011,  8005,  5088,
     9852,  8643,  9302,  6267,  2422,  6039,  2187,  2566, 10849,  8526,  9223,    27,
     7205,  1632,  7404,  1017,  4143,  7575, 12047, 10752,  8585,  2678,  7270, 11744,
     3833,  3778, 11899,   773,  5101, 11222,  9888,   442,  9377,  6591,   354,  7428,
     5012,  2481,  1045,  9430, 10302, 10587,  8724, 11635,  7083,  5529,  9090, 12233,
     6152,  4948,   400,  1728,  6427,  6136,  6874,  3643, 10930,  5435,  1254, 11316,
    10256,  3998, 10367,  8410, 11821,  8301, 11907,   316,  6950,  5446,  6093,  3710,
     7822,  4789,  7540,  5537,  3789,   147,  5456,  7840, 11239,  7753,  5445,  3860,
     9606,  1190,  8471,  6118,  5925,  1018,  8775,  1041,  1973,  5574, 11011,  2344,
     4075,  5315,  4324,  4916, 10120, 11767,  7210,  9027,  6281, 11404,  7280,  1956,
    11286,  3532, 12048, 12231,  1105, 12147,  5681,  8812,  8851,  2844,   975,  4212,
     8687,  6068,   421,  8209,  3600,  3263,  7665,  6077,  4782,  6403,  9260,  5594,
     8076, 11785,   605,  9987,  5468,  1010,   787,  8807,  5241,  9369,  9162,  8120,
     5057,  7591,  3445,  7509,  2049,  7377, 10968,   192,   431, 10710,  2505,  5906,
    12138, 10162,  8332,  9450,  6415,   677,  6234,  3336, 12237,  9115,  1323,  2766,
     3150,  1319,  8243,   709,  8049,  8719, 11454,  6224,   922, 11848,  8210,  1058,
     1958,  7967, 10211, 11177,    64,  8633, 11606,  9830,  6507,  1566,  2948,  9786,
     6370,  7856,  3834,  5257, 10542,  9166,  9235,  5486,  1404, 11964,  1146, 11341,
     3728,  8240,  6299,  1159,  6099,   295,  5766, 11637,  8527,  2919,  8273,  8212,
     3329,  7991,  9597,   168, 10695,  1962,  5106,  6328,  5297,  6170,  3956,  1360,
    11089,  7105,  9734,  6167,  9407,  1805,  1954,  2051,  6142,  2447,  3963, 11713,
     8855,  8760,  9381,   218,  9928, 10446,  9259,  4115,  5333, 10258,  5876,  2281,
      156,  9522,  8320,  3991,   453,  6381, 11871,  8517,  4774,  6860,  4737,  1293,
    10232,  5369,  9087,  7796,   350,  1512, 10474,  6906,  1489,  2500,  1583,  6347,
    11026, 12240,  6374,  1483,  3009,  1693,   723,   174,  2738,  6421,  2655,  6554,
    10314,  3757,  9364, 11942,  7535, 10431,   426,  3315,
};
static const word16 falcon_izetas_l1[512] = {
        1, 10810,  7143,  4043, 10984,   722,  5736,  8155,  8747,  3504,  2545,  8668,
     1646, 11077,  9094,  6429,  9650,  7468,   949,  9664,  2975, 11726,  2744,  9283,
     7698,  6561,  5828,  7266,  6512,  3328,  1351,  4978,   790, 11334,  2319, 11119,
     1326,  5086,  9088,  3014,  3712,  3135,  7443,  2747,  9995,  1062,  7484,  3553,
     4320,  1000,    81,  3091,  3051,  9923,  4896,  9326, 10654,  9521,  8034,  1177,
     7678, 11563, 10436,   140,  1696, 10861,  9863, 11955, 11029,  7901,  7657,  5755,
     2089,  7197,  2881,  3284,  2013,  9000,   729,  3241,  9741,  8058, 11934,  8907,
     7110,  3694,  8582,  1759,  4890,  5911,  3932,  9558,  8830,  3637,  5542,   145,
      339,  2468,   544,  6498,     9, 11267,  2842, 11809,  3584,  8112,  2525,  1381,
     4989,  6958, 10616,  4278,  2476,   118,  2197,  7222,   827,  5767,  8541,   953,
     4354, 12159,  9452,  5374,  7837,  9893,  3296,  3949,  2859, 11244,  9808,  7277,
     4861, 11935,  5698,  2912, 11847,  2401,  1067,  7188, 11516,   390,  8511,  8456,
      545,  5019,  9611,  3704,  1537,   242,  4714,  8146, 11272,  4885, 10657,  5084,
    12262,  3066,  3763,  1440,  9723, 10102,  6250,  9867,  6022,  2987,  3646,  2437,
     7201,  4284,  7278,  1002,  3780,   875,  1607,  7313,   435,  7952, 10377,  1378,
     9908,  6845,   493,  8193,  7644,   404,  1065, 10146,  3248,  1207, 11121,  7012,
     6998,  9585,  7351,  3636, 10626,  1777,  4654, 10863, 12286,  4437,  3149,   160,
     3915, 10123,  7370,   113,  2645,  8236,  5042,  2305,  1484,  4895,  7094,  2780,
     7917,  2174,  9442,  7875,  3364,  1689,  4057,  9018, 10659,  2126,  6882,  9103,
     1153,  2884,  2249,  4048,  9919,  2865,  5332,  3510,  8311,  9320,  9603,  3247,
      420,  5559,  1544,  2178,  4905,  8304,   476,  8758, 11618,  9289, 12046,  3016,
     3136,  7098,  9890,  8889,  8974, 11863,  1858,  4754,   347,  2925,  8532,  1975,
     5735,  9634,  5868,  9551, 12115, 11566, 10596,  9280, 10806,  5915,    49,  1263,
     5942, 10706,  9789, 10800,  5383,  1815, 10777, 11939,  4493,  3202,  6920,  2057,
    10996,  7552,  5429,  7515,  3772,   418,  5908, 11836,  8298,  3969,  2767, 12133,
    10008,  6413,  2031,  6956,  8174,  3030,  1843,  2361, 12071,  2908,  3529,  3434,
      576,  8326,  9842,  6147, 10238, 10335, 10484,  2882,  6122,  2555,  5184,  1200,
    10929,  8333,  6119,  6992,  5961,  7183, 10327,  1594, 12121,  2692,  4298,  8960,
     4077,  4016,  9370,  3762,   652,  6523, 11994,  6190, 11130,  5990,  4049,  8561,
      948, 11143,   325, 10885,  6803,  3054,  3123,  1747,  7032,  8455,  4433,  5919,
     2503,  9341, 10723,  5782,  2459,   683,  3656, 12225,  1112,  2078,  4322, 10331,
    11231,  4079,   441, 11367,  6065,   835,  3570,  4240, 11580,  4046, 10970,  9139,
     9523, 10966,  3174,    52,  8953,  6055, 11612,  5874,  2839,  3957,  2127,   151,
     6383,  9784,  1579, 11858, 12097,  1321,  4912, 10240,  4780,  8844,  4698,  7232,
     4169,  3127,  2920,  7048,  3482, 11502, 11279,  6821,  2302, 11684,   504,  4213,
     6695,  3029,  5886,  7507,  6212,  4624,  9026,  8689,  4080, 11868,  6221,  3602,
     8077, 11314,  9445,  3438,  3477,  6608,   142, 11184,    58,   241,  8757,  1003,
    10333,  5009,   885,  6008,  3262,  5079,   522,  2169,  7373,  7965,  6974,  8214,
     9945,  1278,  6715, 10316, 11248,  3514, 11271,  6364,  6171,  3818, 11099,  2683,
     8429,  6844,  4536,  1050,  4449,  6833, 12142,  8500,  6752,  4749,  7500,  4467,
     8579,  6196,  6843,  5339, 11973,   382,  3988,   468,  3879,  1922,  8291,  2033,
      973, 11035,  6854,  1359,  8646,  5415,  6153,  5862, 10561, 11889,  7341,  6137,
       56,  3199,  6760,  5206,   654,  3565,  1702,  1987,
};
static const word16 falcon_zetas_l5[1024] = {
        1,  1479,  8246,  5146,  4134,  6553, 11567,  1305,  5860,  3195,  1212, 10643,
     3621,  9744,  8785,  3542,  7311, 10938,  8961,  5777,  5023,  6461,  5728,  4591,
     3006,  9545,   563,  9314,  2625, 11340,  4821,  2639, 12149,  1853,   726,  4611,
    11112,  4255,  2768,  1635,  2963,  7393,  2366,  9238,  9198, 12208, 11289,  7969,
     8736,  4805, 11227,  2294,  9542,  4846,  9154,  8577,  9275,  3201,  7203, 10963,
     1170,  9970,   955, 11499,  8340,  8993,  2396,  4452,  6915,  2837,   130,  7935,
    11336,  3748,  6522, 11462,  5067, 10092, 12171,  9813,  8011,  1673,  5331,  7300,
    10908,  9764,  4177,  8705,   480,  9447,  1022, 12280,  5791, 11745,  9821, 11950,
    12144,  6747,  8652,  3459,  2731,  8357,  6378,  7399, 10530,  3707,  8595,  5179,
     3382,   355,  4231,  2548,  9048, 11560,  3289, 10276,  9005,  9408,  5092, 10200,
     6534,  4632,  4388,  1260,   334,  2426,  1428, 10593,  3400,  2399,  5191,  9153,
     9273,   243,  3000,   671,  3531, 11813,  3985,  7384, 10111, 10745,  6730, 11869,
     9042,  2686,  2969,  3978,  8779,  6957,  9424,  2370,  8241, 10040,  9405, 11136,
     3186,  5407, 10163,  1630,  3271,  8232, 10600,  8925,  4414,  2847, 10115,  4372,
     9509,  5195,  7394, 10805,  9984,  7247,  4053,  9644, 12176,  4919,  2166,  8374,
    12129,  9140,  7852,     3,  1426,  7635, 10512,  1663,  8653,  4938,  2704,  5291,
     5277,  1168, 11082,  9041,  2143, 11224, 11885,  4645,  4096, 11796,  5444,  2381,
    10911,  1912,  4337, 11854,  4976, 10682, 11414,  8509, 11287,  5011,  8005,  5088,
     9852,  8643,  9302,  6267,  2422,  6039,  2187,  2566, 10849,  8526,  9223,    27,
     7205,  1632,  7404,  1017,  4143,  7575, 12047, 10752,  8585,  2678,  7270, 11744,
     3833,  3778, 11899,   773,  5101, 11222,  9888,   442,  9377,  6591,   354,  7428,
     5012,  2481,  1045,  9430, 10302, 10587,  8724, 11635,  7083,  5529,  9090, 12233,
     6152,  4948,   400,  1728,  6427,  6136,  6874,  3643, 10930,  5435,  1254, 11316,
    10256,  3998, 10367,  8410, 11821,  8301, 11907,   316,  6950,  5446,  6093,  3710,
     7822,  4789,  7540,  5537,  3789,   147,  5456,  7840, 11239,  7753,  5445,  3860,
     9606,  1190,  8471,  6118,  5925,  1018,  8775,  1041,  1973,  5574, 11011,  2344,
     4075,  5315,  4324,  4916, 10120, 11767,  7210,  9027,  6281, 11404,  7280,  1956,
    11286,  3532, 12048, 12231,  1105, 12147,  5681,  8812,  8851,  2844,   975,  4212,
     8687,  6068,   421,  8209,  3600,  3263,  7665,  6077,  4782,  6403,  9260,  5594,
     8076, 11785,   605,  9987,  5468,  1010,   787,  8807,  5241,  9369,  9162,  8120,
     5057,  7591,  3445,  7509,  2049,  7377, 10968,   192,   431, 10710,  2505,  5906,
    12138, 10162,  8332,  9450,  6415,   677,  6234,  3336, 12237,  9115,  1323,  2766,
     3150,  1319,  8243,   709,  8049,  8719, 11454,  6224,   922, 11848,  8210,  1058,
     1958,  7967, 10211, 11177,    64,  8633, 11606,  9830,  6507,  1566,  2948,  9786,
     6370,  7856,  3834,  5257, 10542,  9166,  9235,  5486,  1404, 11964,  1146, 11341,
     3728,  8240,  6299,  1159,  6099,   295,  5766, 11637,  8527,  2919,  8273,  8212,
     3329,  7991,  9597,   168, 10695,  1962,  5106,  6328,  5297,  6170,  3956,  1360,
    11089,  7105,  9734,  6167,  9407,  1805,  1954,  2051,  6142,  2447,  3963, 11713,
     8855,  8760,  9381,   218,  9928, 10446,  9259,  4115,  5333, 10258,  5876,  2281,
      156,  9522,  8320,  3991,   453,  6381, 11871,  8517,  4774,  6860,  4737,  1293,
    10232,  5369,  9087,  7796,   350,  1512, 10474,  6906,  1489,  2500,  1583,  6347,
    11026, 12240,  6374,  1483,  3009,  1693,   723,   174,  2738,  6421,  2655,  6554,
    10314,  3757,  9364, 11942,  7535, 10431,   426,  3315,  1945,  1029,  1325,  5724,
     3624,  1892,  8945,  6691,  5797,  8330, 10141,  5959,  1248,  2442,  5115,  7350,
     1522,  2151,  3343,  4119, 12269,  7287,  7126,  7681,  9395,  8635,  1314,  1744,
     5690,  9834,   338,  8342, 10347,  3408, 11124,  9714,  8778,  5478,  1178,  9513,
    11783,  1255,  5784,  1392,  9615,  2212,  8951,  3276,  8122,  6085, 11251,   923,
     2800, 12096, 10058,  6092, 11912,  7711,   375,  1620,  2185, 11897,  1836, 11864,
    12109,  4138,  2689,  7684,  5509,   204,  7070, 10880,  2054,  2483,  3042,  1344,
    11826,  3407,  3981,  1468, 11232,  9689,  9168,  4705,  5246,  4475,  1236,  9272,
    11925,  2360,  9261,  7073,  6771, 11063,  4739,  4251,   622, 10552,  4499,  5672,
     2947,  8307,  5609,   636,  7376,  8761,  4235,  8464,  3375,  2291,  7954,  3393,
      512,  7619,  6825,  4906,  2900,   239, 11295,  4554,  1804,  1403,  6094,  5189,
    10602, 11883,   146,  7021,  1518,  8524,  7226,  8113,  8022,  5653, 10014,  2461,
    10533,  8144,  8755,  8328,  3495,  7725,  2065,  6463,  1131,  1445, 11164,  7429,
     5734,  1176,  6781,  1275,  3889,   579,  6693,  6302,  3114,  9520,  6323, 12077,
     8682, 10962,  8347,  7057,  7508,  7365, 11275, 11841,    60,  2717,  3200,  1535,
     2260, 12221,  5836,  4566,  1417,  6613, 10032,  4505,  8314,  7406,  9202,  5835,
     8545,  4963,  9233,  2528,  6444,  6701, 11877,  5102,  2450, 10584, 11873, 11475,
     2164,  5416,   716,  2110,  3448, 11946,  7751, 10381, 11081,  7562,  5211,  1866,
     6877,  8080,  6296,  9011,  5061,  1218, 11851,  3515,  3589, 11572,  2982, 10916,
     4103,  9860,  1721,  1536,  1092,  5209,  9084,  3359,  4265,  3678, 10361, 11825,
     8840, 11153,  8581,  9051,  9363, 10463,  7800,  9118,  8051, 11677,  3368,  4227,
     4222,  1526, 12164, 11749,  1389,  2068,   346,  7885,  3163,  8257,  4840,  6162,
     6320,  7640,  9360,  6026,   466,  1030,  8468,  1681,  8443,  1573,  3793,  6063,
     2602,  1901, 11787,  7171, 11169,  2535,  5808,    21,  2873,  9462,  9855,   791,
    11415,  9988,  6639,   170, 12139, 11641,  4289,  2307,     8, 11832,  4523,  4301,
     8494,  3268,  6513, 10440, 10013,   982,  9696, 11410,  4390,  4218,  8835,  3758,
     9332,  1481, 10243,  9349,  3317,  2532,  8957, 12150, 11759,  2626,  4504,   778,
     8711,  4697,  1701,  8823,  1279, 11424,  2672,  7119,  3116,   189, 10526, 10080,
    10939,  6457,  1734,  8474, 10595,  1530,  3869,  7866, 11129,  4820,  7771,  3094,
     9559,  5411,  1868, 10036, 10506,  5078,  7315,  4565,  2478,  2840,  9270,  8095,
     5275, 10499,  6879, 11038,  6164, 10407,  1040,  2035,  4665,  5406,  3020,  5673,
     3669,  7002, 11345,  4770,  2643,  1095,  5781,  9244,  1241,  4378,  8838,  8195,
     3840,  1842,  8176, 12217,  9461,  7937,  4834,  9577,  6828,  9343,  7779,  2637,
    11408, 11924, 10362,  1015, 11385,  2485,  5039,  5547, 11009, 11675,  1371,    24,
     1590,  4411, 11066,  9955, 10734, 10487,  7186, 10398,  2338,  4693,  9996,   417,
     6138,  8820,  7846,  3418,  2622,  6903,  4661, 11779,   450,  1944, 11711,  5368,
     3670,  8481,  7302,  9916,  7154, 12226,  4684,  8929, 10891,  9199, 11463,  7246,
     8787,  6500,  1658,  6671,  4483,  6586,  1506,  3065,   910,  6389,  7570,   751,
    10583,  8360,  3229,  7559,  1282,  3572,  2832, 10268,  6086,  5646,  9169,  6184,
     3941,  3753,  5370,  3536,   769,  6763,    50,   216,  8484,   767, 10076,  8136,
     8566, 11444, 10353, 12282,  7235,  9135,  9004,  7929,  5349,  9344,  2633, 10883,
     4855,  3769,  9057,   293,  8190,  8345,  6685,  6759,  1265,  3007, 10118,  8809,
     2941, 11722,  5289,  6627,  4273,  3221,  2595,  3837,  5082,  7699,   682,   980,
     7087, 11445,  5207,  8239,
};
static const word16 falcon_izetas_l5[1024] = {
        1, 10810,  7143,  4043, 10984,   722,  5736,  8155,  8747,  3504,  2545,  8668,
     1646, 11077,  9094,  6429,  9650,  7468,   949,  9664,  2975, 11726,  2744,  9283,
     7698,  6561,  5828,  7266,  6512,  3328,  1351,  4978,   790, 11334,  2319, 11119,
     1326,  5086,  9088,  3014,  3712,  3135,  7443,  2747,  9995,  1062,  7484,  3553,
     4320,  1000,    81,  3091,  3051,  9923,  4896,  9326, 10654,  9521,  8034,  1177,
     7678, 11563, 10436,   140,  1696, 10861,  9863, 11955, 11029,  7901,  7657,  5755,
     2089,  7197,  2881,  3284,  2013,  9000,   729,  3241,  9741,  8058, 11934,  8907,
     7110,  3694,  8582,  1759,  4890,  5911,  3932,  9558,  8830,  3637,  5542,   145,
      339,  2468,   544,  6498,     9, 11267,  2842, 11809,  3584,  8112,  2525,  1381,
     4989,  6958, 10616,  4278,  2476,   118,  2197,  7222,   827,  5767,  8541,   953,
     4354, 12159,  9452,  5374,  7837,  9893,  3296,  3949,  2859, 11244,  9808,  7277,
     4861, 11935,  5698,  2912, 11847,  2401,  1067,  7188, 11516,   390,  8511,  8456,
      545,  5019,  9611,  3704,  1537,   242,  4714,  8146, 11272,  4885, 10657,  5084,
    12262,  3066,  3763,  1440,  9723, 10102,  6250,  9867,  6022,  2987,  3646,  2437,
     7201,  4284,  7278,  1002,  3780,   875,  1607,  7313,   435,  7952, 10377,  1378,
     9908,  6845,   493,  8193,  7644,   404,  1065, 10146,  3248,  1207, 11121,  7012,
     6998,  9585,  7351,  3636, 10626,  1777,  4654, 10863, 12286,  4437,  3149,   160,
     3915, 10123,  7370,   113,  2645,  8236,  5042,  2305,  1484,  4895,  7094,  2780,
     7917,  2174,  9442,  7875,  3364,  1689,  4057,  9018, 10659,  2126,  6882,  9103,
     1153,  2884,  2249,  4048,  9919,  2865,  5332,  3510,  8311,  9320,  9603,  3247,
      420,  5559,  1544,  2178,  4905,  8304,   476,  8758, 11618,  9289, 12046,  3016,
     3136,  7098,  9890,  8889,  8974, 11863,  1858,  4754,   347,  2925,  8532,  1975,
     5735,  9634,  5868,  9551, 12115, 11566, 10596,  9280, 10806,  5915,    49,  1263,
     5942, 10706,  9789, 10800,  5383,  1815, 10777, 11939,  4493,  3202,  6920,  2057,
    10996,  7552,  5429,  7515,  3772,   418,  5908, 11836,  8298,  3969,  2767, 12133,
    10008,  6413,  2031,  6956,  8174,  3030,  1843,  2361, 12071,  2908,  3529,  3434,
      576,  8326,  9842,  6147, 10238, 10335, 10484,  2882,  6122,  2555,  5184,  1200,
    10929,  8333,  6119,  6992,  5961,  7183, 10327,  1594, 12121,  2692,  4298,  8960,
     4077,  4016,  9370,  3762,   652,  6523, 11994,  6190, 11130,  5990,  4049,  8561,
      948, 11143,   325, 10885,  6803,  3054,  3123,  1747,  7032,  8455,  4433,  5919,
     2503,  9341, 10723,  5782,  2459,   683,  3656, 12225,  1112,  2078,  4322, 10331,
    11231,  4079,   441, 11367,  6065,   835,  3570,  4240, 11580,  4046, 10970,  9139,
     9523, 10966,  3174,    52,  8953,  6055, 11612,  5874,  2839,  3957,  2127,   151,
     6383,  9784,  1579, 11858, 12097,  1321,  4912, 10240,  4780,  8844,  4698,  7232,
     4169,  3127,  2920,  7048,  3482, 11502, 11279,  6821,  2302, 11684,   504,  4213,
     6695,  3029,  5886,  7507,  6212,  4624,  9026,  8689,  4080, 11868,  6221,  3602,
     8077, 11314,  9445,  3438,  3477,  6608,   142, 11184,    58,   241,  8757,  1003,
    10333,  5009,   885,  6008,  3262,  5079,   522,  2169,  7373,  7965,  6974,  8214,
     9945,  1278,  6715, 10316, 11248,  3514, 11271,  6364,  6171,  3818, 11099,  2683,
     8429,  6844,  4536,  1050,  4449,  6833, 12142,  8500,  6752,  4749,  7500,  4467,
     8579,  6196,  6843,  5339, 11973,   382,  3988,   468,  3879,  1922,  8291,  2033,
      973, 11035,  6854,  1359,  8646,  5415,  6153,  5862, 10561, 11889,  7341,  6137,
       56,  3199,  6760,  5206,   654,  3565,  1702,  1987,  4050,  7082,   844,  5202,
    11309, 11607,  4590,  7207,  8452,  9694,  9068,  8016,  5662,  7000,   567,  9348,
     3480,  2171,  9282, 11024,  5530,  5604,  3944,  4099, 11996,  3232,  8520,  7434,
     1406,  9656,  2945,  6940,  4360,  3285,  3154,  5054,     7,  1936,   845,  3723,
     4153,  2213, 11522,  3805, 12073, 12239,  5526, 11520,  8753,  6919,  8536,  8348,
     6105,  3120,  6643,  6203,  2021,  9457,  8717, 11007,  4730,  9060,  3929,  1706,
    11538,  4719,  5900, 11379,  9224, 10783,  5703,  7806,  5618, 10631,  5789,  3502,
     5043,   826,  3090,  1398,  3360,  7605,    63,  5135,  2373,  4987,  3808,  8619,
     6921,   578, 10345, 11839,   510,  7628,  5386,  9667,  8871,  4443,  3469,  6151,
    11872,  2293,  7596,  9951,  1891,  5103,  1802,  1555,  2334,  1223,  7878, 10699,
    12265, 10918,   614,  1280,  6742,  7250,  9804,   904, 11274,  1927,   365,   881,
     9652,  4510,  2946,  5461,  2712,  7455,  4352,  2828,    72,  4113, 10447,  8449,
     4094,  3451,  7911, 11048,  3045,  6508, 11194,  9646,  7519,   944,  5287,  8620,
     6616,  9269,  6883,  7624, 10254, 11249,  1882,  6125,  1251,  5410,  1790,  7014,
     4194,  3019,  9449,  9811,  7724,  4974,  7211,  1783,  2253, 10421,  6878,  2730,
     9195,  4518,  7469,  1160,  4423,  8420, 10759,  1694,  3815, 10555,  5832,  1350,
     2209,  1763, 12100,  9173,  5170,  9617,   865, 11010,  3466, 10588,  7592,  3578,
    11511,  7785,  9663,   530,   139,  3332,  9757,  8972,  2940,  2046, 10808,  2957,
     8531,  3454,  8071,  7899,   879,  2593, 11307,  2276,  1849,  5776,  9021,  3795,
     7988,  7766,   457, 12281,  9982,  8000,   648,   150, 12119,  5650,  2301,   874,
    11498,  2434,  2827,  9416, 12268,  6481,  9754,  1120,  5118,   502, 10388,  9687,
     6226,  8496, 10716,  3846, 10608,  3821, 11259, 11823,  6263,  2929,  4649,  5969,
     6127,  7449,  4032,  9126,  4404, 11943, 10221, 10900,   540,   125, 10763,  8067,
     8062,  8921,   612,  4238,  3171,  4489,  1826,  2926,  3238,  3708,  1136,  3449,
      464,  1928,  8611,  8024,  8930,  3205,  7080, 11197, 10753, 10568,  2429,  8186,
     1373,  9307,   717,  8700,  8774,   438, 11071,  7228,  3278,  5993,  4209,  5412,
    10423,  7078,  4727,  1208,  1908,  4538,   343,  8841, 10179, 11573,  6873, 10125,
      814,   416,  1705,  9839,  7187,   412,  5588,  5845,  9761,  3056,  7326,  3744,
     6454,  3087,  4883,  3975,  7784,  2257,  5676, 10872,  7723,  6453,    68, 10029,
    10754,  9089,  9572, 12229,   448,  1014,  4924,  4781,  5232,  3942,  1327,  3607,
      212,  5966,  2769,  9175,  5987,  5596, 11710,  8400, 11014,  5508, 11113,  6555,
     4860,  1125, 10844, 11158,  5826, 10224,  4564,  8794,  3961,  3534,  4145,  1756,
     9828,  2275,  6636,  4267,  4176,  5063,  3765, 10771,  5268, 12143,   406,  1687,
     7100,  6195, 10886, 10485,  7735,   994, 12050,  9389,  7383,  5464,  4670, 11777,
     8896,  4335,  9998,  8914,  3825,  8054,  3528,  4913, 11653,  6680,  3982,  9342,
     6617,  7790,  1737, 11667,  8038,  7550,  1226,  5518,  5216,  3028,  9929,   364,
     3017, 11053,  7814,  7043,  7584,  3121,  2600,  1057, 10821,  8308,  8882,   463,
    10945,  9247,  9806, 10235,  1409,  5219, 12085,  6780,  4605,  9600,  8151,   180,
      425, 10453,   392, 10104, 10669, 11914,  4578,   377,  6197,  2231,   193,  9489,
    11366,  1038,  6204,  4167,  9013,  3338, 10077,  2674, 10897,  6505, 11034,   506,
     2776, 11111,  6811,  3511,  2575,  1165,  8881,  1942,  3947, 11951,  2455,  6599,
    10545, 10975,  3654,  2894,  4608,  5163,  5002,    20,  8170,  8946, 10138, 10767,
     4939,  7174,  9847, 11041,  6330,  2148,  3959,  6492,  5598,  3344, 10397,  8665,
     6565, 10964, 11260, 10344,
};

static void falcon_get_tables(unsigned logn, const word16** zetas,
        const word16** izetas)
{
    if (logn == FALCON_LEVEL1_LOGN) {
        *zetas  = falcon_zetas_l1;
        *izetas = falcon_izetas_l1;
    }
    else {
        *zetas  = falcon_zetas_l5;
        *izetas = falcon_izetas_l5;
    }
}

/* Division-free modular reductions for the NTT. Hardware integer division is
 * absent on Cortex-M0/M3 (a slow library call) and multi-cycle elsewhere, so
 * the inner loops use a Barrett multiply + a conditional subtract instead of
 * '%'. Both are bit-identical to a mod q and constant-time.
 *   falcon_barrett: a in [0, q^2) -> [0, q)  (349496 = floor(2^32 / q)).
 *   falcon_csub:    a in [0, 2q)  -> [0, q). */
static WC_INLINE word32 falcon_barrett(word32 a)
{
    word32 t = (word32)(((word64)a * 349496u) >> 32);
    a -= t * FALCON_Q;
    a -= FALCON_Q & (word32)((sword32)(FALCON_Q - 1 - a) >> 31);
    return a;
}
static WC_INLINE word32 falcon_csub(word32 a)
{
    a -= FALCON_Q & (word32)((sword32)(FALCON_Q - 1 - a) >> 31);
    return a;
}

/* Optional ARM DSP acceleration for the verify path (NTT/iNTT/pointwise/norm).
 * On cores with the DSP extension (__ARM_FEATURE_DSP: Cortex-M4/M7/M33, ...) the
 * butterflies process two packed 16-bit coefficients per iteration using the
 * SMLA* 16x16 multiplies, SADD16/SSUB16 packed adds, and a USUB16+SEL packed
 * conditional subtract; the squared-norm accumulates two lanes per SMUAD. Every
 * result is bit-identical to the scalar Barrett path below. Define
 * WOLFSSL_FALCON_NO_NTT_DSP to force the portable C path. */
#if !defined(WOLFSSL_FALCON_NTT_DSP) && defined(__ARM_FEATURE_DSP) && \
    !defined(WOLFSSL_FALCON_NO_NTT_DSP)
    #define WOLFSSL_FALCON_NTT_DSP
#endif

#ifdef WOLFSSL_FALCON_NTT_DSP
#include <arm_acle.h>
/* q replicated into both halfword lanes. */
#define FALCON_QPK (((word32)FALCON_Q << 16) | (word32)FALCON_Q)
/* Signed 16x16 -> 32 products (coefficients are < q < 2^14, so they fit s16). */
static WC_INLINE word32 falcon_smulbb(word32 a, word32 b) /* a.lo * b.lo */
    { return (word32)__smlabb(a, b, 0); }
static WC_INLINE word32 falcon_smultb(word32 a, word32 b) /* a.hi * b.lo */
    { return (word32)__smlatb(a, b, 0); }
static WC_INLINE word32 falcon_smultt(word32 a, word32 b) /* a.hi * b.hi */
    { return (word32)__smlatt(a, b, 0); }
static WC_INLINE word32 falcon_pack(word32 lo, word32 hi)
    { return (lo & 0xffffu) | (hi << 16); }
/* Two packed halfword lanes, each in [0, 2q) -> [0, q): USUB16 sets APSR.GE per
 * lane (set where x >= q), SEL then selects (x - q) on those lanes. */
static WC_INLINE word32 falcon_pcsub(word32 x)
    { word32 d = __usub16(x, FALCON_QPK); return __sel(d, x); }
/* Aliasing-safe packed load/store of a coefficient pair (lowers to LDR/STR). */
static WC_INLINE word32 falcon_ld2(const word16* p)
    { word32 v; XMEMCPY(&v, p, sizeof(v)); return v; }
static WC_INLINE void falcon_st2(word16* p, word32 v)
    { XMEMCPY(p, &v, sizeof(v)); }
#endif /* WOLFSSL_FALCON_NTT_DSP */

/* Forward negacyclic NTT, Cooley-Tukey: natural -> bit-reversed order. */
static void falcon_ntt(word16* a, int n, const word16* zetas)
{
    int t = n, m, i, j;
    for (m = 1; m < n; m <<= 1) {
        t >>= 1;
        for (i = 0; i < m; i++) {
            word32 z = zetas[m + i];
            int start = 2 * i * t;
#ifdef WOLFSSL_FALCON_NTT_DSP
            if (t >= 2) {
                for (j = start; j < start + t; j += 2) {
                    word32 A = falcon_ld2(a + j);       /* [a[j]   | a[j+1]]   */
                    word32 B = falcon_ld2(a + j + t);   /* [a[j+t] | a[j+1+t]] */
                    word32 v0 = falcon_barrett(falcon_smulbb(B, z));
                    word32 v1 = falcon_barrett(falcon_smultb(B, z));
                    word32 V = falcon_pack(v0, v1);
                    falcon_st2(a + j,     falcon_pcsub(__sadd16(A, V)));
                    falcon_st2(a + j + t,
                        falcon_pcsub(__ssub16(__sadd16(A, FALCON_QPK), V)));
                }
                continue;
            }
#endif
            for (j = start; j < start + t; j++) {
                word32 u = a[j];
                word32 v = falcon_barrett((word32)a[j + t] * z);
                a[j]     = (word16)falcon_csub(u + v);
                a[j + t] = (word16)falcon_csub(u + FALCON_Q - v);
            }
        }
    }
}

/* Inverse negacyclic NTT, Gentleman-Sande: bit-reversed -> natural order. */
static void falcon_intt(word16* a, int n, const word16* izetas)
{
    int t = 1, m, i, j;
    word32 ninv;
    for (m = n; m > 1; m >>= 1) {
        int h = m >> 1;
        int j1 = 0;
        for (i = 0; i < h; i++) {
            word32 z = izetas[h + i];
            int start = j1;
#ifdef WOLFSSL_FALCON_NTT_DSP
            if (t >= 2) {
                for (j = start; j < start + t; j += 2) {
                    word32 A = falcon_ld2(a + j);
                    word32 B = falcon_ld2(a + j + t);
                    word32 W = falcon_pcsub(
                        __ssub16(__sadd16(A, FALCON_QPK), B)); /* csub(u+q-v) */
                    word32 w0 = falcon_barrett(falcon_smulbb(W, z));
                    word32 w1 = falcon_barrett(falcon_smultb(W, z));
                    falcon_st2(a + j,     falcon_pcsub(__sadd16(A, B)));
                    falcon_st2(a + j + t, falcon_pack(w0, w1));
                }
                j1 += 2 * t;
                continue;
            }
#endif
            for (j = start; j < start + t; j++) {
                word32 u = a[j];
                word32 v = a[j + t];
                word32 w = falcon_csub(u + FALCON_Q - v);
                a[j]     = (word16)falcon_csub(u + v);
                a[j + t] = (word16)falcon_barrett(w * z);
            }
            j1 += 2 * t;
        }
        t <<= 1;
    }
    ninv = falcon_modinv((word32)n);
    for (j = 0; j < n; j++) {
        a[j] = (word16)falcon_barrett((word32)a[j] * ninv);
    }
}

/* ------------------------------------------------------------------------ */
/* Codec                                                                     */
/* ------------------------------------------------------------------------ */

/* Decode the public key polynomial h: n coefficients packed 14 bits each,
 * most-significant bit first. Each coefficient must be < q. Returns the number
 * of input bytes consumed, or a negative wolfCrypt error. */
static int falcon_modq_decode(const byte* in, word32 inLen, word16* x,
        unsigned logn)
{
    size_t n = (size_t)1 << logn;
    size_t need = ((n * 14) + 7) >> 3;
    word32 acc = 0;
    int acc_bits = 0;
    size_t in_i = 0, out_i = 0;

    if (inLen < need) {
        return BUFFER_E;
    }
    while (out_i < n) {
        acc = (acc << 8) | in[in_i++];
        acc_bits += 8;
        if (acc_bits >= 14) {
            word32 w;
            acc_bits -= 14;
            w = (acc >> acc_bits) & 0x3FFF;
            if (w >= FALCON_Q) {
                return ASN_PARSE_E;
            }
            x[out_i++] = (word16)w;
        }
    }
    /* Unused trailing bits in the final byte must be zero. */
    if ((acc & (((word32)1 << acc_bits) - 1)) != 0) {
        return ASN_PARSE_E;
    }
    return (int)need;
}

/* Decode the compressed signature polynomial s2 (Golomb-Rice, k=7). Returns
 * the number of input bytes consumed, or a negative wolfCrypt error. Ported
 * from the Falcon reference comp_decode. */
static int falcon_comp_decode(const byte* in, word32 inLen, sword16* x,
        unsigned logn)
{
    size_t n = (size_t)1 << logn;
    word32 acc = 0;
    unsigned int acc_len = 0;
    size_t v = 0, u;

    for (u = 0; u < n; u++) {
        unsigned int b, s, mag;

        if (v >= inLen) {
            return BUFFER_E;
        }
        acc = (acc << 8) | (word32)in[v++];
        b = acc >> acc_len;
        s = b & 128;
        mag = b & 127;

        /* High bits: unary-coded run of zeros terminated by a one bit. */
        for (;;) {
            if (acc_len == 0) {
                if (v >= inLen) {
                    return BUFFER_E;
                }
                acc = (acc << 8) | (word32)in[v++];
                acc_len = 8;
            }
            acc_len--;
            if (((acc >> acc_len) & 1) != 0) {
                break;
            }
            mag += 128;
            if (mag > 2047) {
                return ASN_PARSE_E;
            }
        }
        /* Negative zero is not a valid encoding. */
        if (s != 0 && mag == 0) {
            return ASN_PARSE_E;
        }
        x[u] = (sword16)(s != 0 ? -(int)mag : (int)mag);
    }
    /* Unused trailing bits must be zero. */
    if ((acc & (((word32)1 << acc_len) - 1)) != 0) {
        return ASN_PARSE_E;
    }
    return (int)v;
}

/* hash-to-point (variable time; inputs are public). Absorbs nonce||msg into a
 * fresh SHAKE256 context and samples n coefficients in [0,q) by rejection. */
static int falcon_hash_to_point(const byte* nonce, const byte* msg,
        word32 msgLen, word16* c, unsigned logn, void* heap)
{
    wc_Shake shake;
    byte block[WC_SHA3_256_BLOCK_SIZE];
    size_t n = (size_t)1 << logn;
    size_t i = 0;
    int bi = WC_SHA3_256_BLOCK_SIZE;   /* force an initial squeeze */
    int ret;
    int shakeInit = 0;

    /* Absorb nonce || msg incrementally, avoiding a temporary concatenation
     * buffer: wc_Shake256_Absorb() is an Update() followed by the SHAKE finalize
     * on the same sponge, so feeding the nonce with wc_Shake256_Update() first
     * and the message with wc_Shake256_Absorb() second absorbs their
     * concatenation and pads the state for squeezing. */
    ret = wc_InitShake256(&shake, heap, INVALID_DEVID);
    if (ret == 0) {
        shakeInit = 1;
        ret = wc_Shake256_Update(&shake, nonce, FALCON_NONCE_SIZE);
    }
    if (ret == 0) {
        ret = wc_Shake256_Absorb(&shake, msg, msgLen);
    }

    while (ret == 0 && i < n) {
        word32 w;
        if (bi >= WC_SHA3_256_BLOCK_SIZE) {
            ret = wc_Shake256_SqueezeBlocks(&shake, block, 1);
            if (ret != 0) {
                break;
            }
            bi = 0;
        }
        w = ((word32)block[bi] << 8) | (word32)block[bi + 1];
        bi += 2;
        /* 61445 == 5 * q: keeps the distribution uniform mod q. */
        if (w < 61445u) {
            while (w >= FALCON_Q) {
                w -= FALCON_Q;
            }
            c[i++] = (word16)w;
        }
    }

    /* Only free the SHAKE context if it was successfully initialized
     * (wc_Shake256_Free touches device state in async builds). */
    if (shakeInit) {
        wc_Shake256_Free(&shake);
    }
    return ret;
}

/* Center x (given in [0,q)) into (-q/2, q/2]. */
static WC_INLINE sword32 falcon_center(word32 x)
{
    sword32 r = (sword32)x;
    if (r > (FALCON_Q >> 1)) {
        r -= FALCON_Q;
    }
    return r;
}

/* ------------------------------------------------------------------------ */
/* Public API                                                                */
/* ------------------------------------------------------------------------ */

static int falcon_level_params(byte level, unsigned* logn, int* n, word32* pubSz)
{
    switch (level) {
        case FALCON_LEVEL1:
            *logn = FALCON_LEVEL1_LOGN;
            *n = FALCON_LEVEL1_N;
            *pubSz = FALCON_LEVEL1_PUB_KEY_SIZE;
            return 0;
        case FALCON_LEVEL5:
            *logn = FALCON_LEVEL5_LOGN;
            *n = FALCON_LEVEL5_N;
            *pubSz = FALCON_LEVEL5_PUB_KEY_SIZE;
            return 0;
        default:
            return BAD_FUNC_ARG;
    }
}

#ifndef WOLFSSL_FALCON_VERIFY_ONLY
int falcon_native_make_key(falcon_key* key, WC_RNG* rng)
{
    int ret = 0;
    unsigned logn = 0;
    int n = 0;
    word32 pubSz = 0, keySz = 0;
    sword8 *f = NULL, *g = NULL, *F = NULL, *G = NULL;
    word16* h = NULL;
    byte* arena = NULL;
    size_t arenaSz = 0;
    void* heap;

    if (key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }
    if (falcon_level_params(key->level, &logn, &n, &pubSz) != 0) {
        return BAD_FUNC_ARG;
    }
    keySz = (key->level == FALCON_LEVEL1) ? FALCON_LEVEL1_KEY_SIZE
                                            : FALCON_LEVEL5_KEY_SIZE;
    heap = key->heap;

    /* One allocation for h (word16, public) then f/g/F/G (sword8, secret),
     * ordered so each is naturally aligned. */
    {
        size_t hSz = sizeof(word16) * (size_t)n;
        arenaSz = hSz + 4 * (size_t)n;
        arena = (byte*)XMALLOC(arenaSz, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (arena != NULL) {
            h = (word16*)arena;
            f = (sword8*)(arena + hSz);
            g = f + n;
            F = g + n;
            G = F + n;
        }
    }
    if (arena == NULL) {
        ret = MEMORY_E;
        goto out;
    }

    ret = falcon_keygen(rng, f, g, F, G, h, logn);
    if (ret != 0) {
        goto out;
    }

    /* Encode the public key: header byte then 14-bit packed h. */
    key->p[0] = (byte)(FALCON_PUB_HEAD | logn);
    if (falcon_modq_encode(key->p + 1, (size_t)(pubSz - 1), h, logn) == 0) {
        ret = BAD_FUNC_ARG;
        goto out;
    }

    /* Encode the secret key (header | f | g | F) into key->k. */
    if (falcon_privkey_encode(key->k, keySz, f, g, F, logn) != (size_t)keySz) {
        ret = BAD_FUNC_ARG;
        goto out;
    }

    key->pubKeySet = 1;
    key->prvKeySet = 1;

out:
    /* One ForceZero + free; covers the secret f/g/F/G (h is public but zeroing
     * it too is harmless). */
    if (arena != NULL) {
        ForceZero(arena, (word32)arenaSz);
        XFREE(arena, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}

int falcon_native_sign_msg(const byte* in, word32 inLen, byte* out, word32* outLen,
        falcon_key* key, WC_RNG* rng)
{
    int ret = 0;
    unsigned logn = 0;
    int n = 0;
    word32 pubSz = 0, keySz = 0, sigMax = 0;
    sword8 *f = NULL, *g = NULL, *F = NULL, *G = NULL;
    word16* c = NULL;
    sword16* s2 = NULL;
#ifndef WOLFSSL_FALCON_SIGN_SMALL_MEM
    fpr* expanded = NULL;
#endif
    fpr* tmp = NULL;
    byte* arena = NULL;             /* single allocation backing all buffers */
    size_t arenaSz = 0;
    falcon_sampler_ctx spc;
    byte nonce[FALCON_NONCE_SIZE];
    void* heap;
    int attempt, haveSpc = 0;
    size_t compLen = 0;

    if ((in == NULL && inLen != 0) || out == NULL || outLen == NULL ||
            key == NULL || rng == NULL) {
        return BAD_FUNC_ARG;
    }
    if (!key->prvKeySet) {
        return BAD_FUNC_ARG;
    }
    if (falcon_level_params(key->level, &logn, &n, &pubSz) != 0) {
        return BAD_FUNC_ARG;
    }
    keySz  = (key->level == FALCON_LEVEL1) ? FALCON_LEVEL1_KEY_SIZE
                                             : FALCON_LEVEL5_KEY_SIZE;
    sigMax = (key->level == FALCON_LEVEL1) ? FALCON_LEVEL1_SIG_SIZE
                                             : FALCON_LEVEL5_SIG_SIZE;
    if (*outLen < sigMax) {
        *outLen = sigMax;
        return BUFFER_E;
    }
    heap = key->heap;

    /* One allocation backs every sign buffer (the working set is >100KB at
     * Falcon-1024, so it stays on the heap in all builds). Ordered by decreasing
     * alignment -- fpr (expanded, tmp), then word16 (c, s2), then sword8
     * (f, g, F, G) -- so each sub-buffer is naturally aligned from the
     * max-aligned base. */
    {
#ifdef WOLFSSL_FALCON_SIGN_SMALL_MEM
        /* Dynamic signing needs only one fpr scratch (the tree is rebuilt inside
         * the sampler), so the arena is far smaller than the expand+tree path. */
        size_t dSz = sizeof(fpr) * FALCON_SIGN_DYN_TMP_FPR(logn);
        arenaSz = dSz + (size_t)8 * (size_t)n;   /* c+s2 = 4n, f+g+F+G = 4n */
        arena = (byte*)XMALLOC(arenaSz, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (arena != NULL) {
            tmp = (fpr*)arena;
            c   = (word16*)(arena + dSz);
            s2  = (sword16*)(arena + dSz + 2 * (size_t)n);
            f   = (sword8*)(arena + dSz + 4 * (size_t)n);
            g   = f + n;
            F   = g + n;
            G   = F + n;
        }
#else
        size_t eSz = sizeof(fpr) * FALCON_EXPANDED_KEY_FPR(logn);
        size_t tSz = sizeof(fpr) * FALCON_SIGN_TMP_FPR(logn);
        arenaSz = eSz + tSz + (size_t)8 * (size_t)n;  /* c+s2 = 4n, f+g+F+G = 4n */
        arena = (byte*)XMALLOC(arenaSz, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (arena != NULL) {
            expanded = (fpr*)arena;
            tmp      = (fpr*)(arena + eSz);
            c        = (word16*)(arena + eSz + tSz);
            s2       = (sword16*)(arena + eSz + tSz + 2 * (size_t)n);
            f        = (sword8*)(arena + eSz + tSz + 4 * (size_t)n);
            g        = f + n;
            F        = g + n;
            G        = F + n;
        }
#endif
    }
    if (arena == NULL) {
        ret = MEMORY_E;
        goto out;
    }

    /* Decode the secret basis, recompute G, expand to the ffLDL tree. */
    ret = falcon_privkey_decode(key->k, keySz, f, g, F, logn);
    if (ret != 0) {
        goto out;
    }
    ret = falcon_complete_private(G, f, g, F, logn, heap);
    if (ret != 0) {
        goto out;
    }
#ifndef WOLFSSL_FALCON_SIGN_SMALL_MEM
    /* Precompute the expanded key (skipped in small-mem mode: the dynamic signer
     * rebuilds the tree on the fly for each attempt). */
    ret = falcon_expand_privkey(expanded, f, g, F, G, logn, heap);
    if (ret != 0) {
        goto out;
    }
#endif
    ret = falcon_sampler_init(&spc, (int)logn, rng);
    if (ret != 0) {
        goto out;
    }
    haveSpc = 1;

    /* Each attempt draws a fresh nonce and samples a signature; retry if the
     * compressed form does not fit the level's maximum length. */
    for (attempt = 0; attempt < FALCON_SIGN_MAX_ENCODE_RETRIES; attempt++) {
        ret = wc_RNG_GenerateBlock(rng, nonce, FALCON_NONCE_SIZE);
        if (ret != 0) {
            goto out;
        }
        ret = falcon_hash_to_point(nonce, in, inLen, c, logn, heap);
        if (ret != 0) {
            goto out;
        }
#ifdef WOLFSSL_FALCON_SIGN_SMALL_MEM
        ret = falcon_sign_dyn_core(&spc, f, g, F, G, c, s2, tmp, logn);
#else
        ret = falcon_sign_core(&spc, expanded, c, s2, tmp, logn);
#endif
        if (ret != 0) {
            goto out;
        }
        out[0] = (byte)(FALCON_SIG_HEAD_COMPRESSED | logn);
        XMEMCPY(out + 1, nonce, FALCON_NONCE_SIZE);
        /* Bound the compressed signature by the level's fixed maximum length
         * (sigMax), NOT by the caller-supplied buffer size (*outLen): a caller
         * may pass a buffer larger than sigMax, and a candidate whose encoding
         * exceeds the level budget must be rejected and re-sampled with a fresh
         * nonce -- otherwise an over-length (e.g. 667-byte Falcon-512)
         * signature is emitted that no verifier will accept. *outLen >= sigMax
         * is guaranteed above, so capping at sigMax never overruns the buffer. */
        compLen = falcon_comp_encode(out + 1 + FALCON_NONCE_SIZE,
                (size_t)(sigMax - 1 - FALCON_NONCE_SIZE), s2, logn);
        if (compLen != 0) {
            break;
        }
    }
    if (compLen == 0) {
        ret = BUFFER_E;
        goto out;
    }
    *outLen = (word32)(1 + FALCON_NONCE_SIZE + compLen);

out:
    /* Free the sampler's SHAKE256 context before zeroizing. wc_Shake256_Free
     * releases the async device context allocated by wc_InitShake256 in
     * WOLFSSL_ASYNC_CRYPT builds; without it that context leaks on every sign.
     * Only when falcon_sampler_init succeeded (haveSpc) is the context live. */
    if (haveSpc) {
        wc_Shake256_Free(&spc.p.shake);
    }
    /* Always zeroize: the SHAKE sponge may hold seed-derived state even if
     * falcon_sampler_init failed after absorbing the seed. */
    ForceZero(&spc, sizeof(spc));
    /* One ForceZero + free covers every secret in the arena (f/g/F/G, the
     * expanded basis, and the sign scratch). */
    if (arena != NULL) {
        ForceZero(arena, (word32)arenaSz);
        XFREE(arena, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}

/* Cryptographic private/public consistency check. Decodes (f, g) from the
 * private key and h from the public key, and verifies the defining relation
 * h = g/f (mod q, mod X^n + 1) as h*f == g slot-wise in the NTT domain
 * (falcon_ntt keeps every value canonical in [0, q), so direct comparison is
 * exact). A slot with NTT(f) == 0 is rejected as well: keygen only emits f
 * invertible mod q, and a non-invertible f does not determine h.
 *
 * Returns 0 when the pair is consistent, PUBLIC_KEY_E on mismatch, or a
 * negative wolfCrypt error on decode/allocation failure. */
int falcon_native_check_key(falcon_key* key)
{
    int ret = 0;
    unsigned logn = 0;
    int n = 0, i;
    word32 pubSz = 0, keySz;
    sword8 *f = NULL, *g = NULL, *F = NULL;
    word16 *h = NULL, *ft = NULL, *gt = NULL;
    const word16* zetas = NULL;
    const word16* izetas = NULL;
    byte* arena = NULL;
    size_t arenaSz = 0;
    void* heap;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }
    if (falcon_level_params(key->level, &logn, &n, &pubSz) != 0) {
        return BAD_FUNC_ARG;
    }
    keySz = (key->level == FALCON_LEVEL1) ? FALCON_LEVEL1_KEY_SIZE
                                          : FALCON_LEVEL5_KEY_SIZE;
    heap = key->heap;

    /* One allocation: h/ft/gt (word16) then f/g/F (sword8), alignment-ordered. */
    {
        size_t wSz = sizeof(word16) * (size_t)n;
        arenaSz = 3 * wSz + 3 * (size_t)n;
        arena = (byte*)XMALLOC(arenaSz, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (arena != NULL) {
            h  = (word16*)arena;
            ft = (word16*)(arena + wSz);
            gt = (word16*)(arena + 2 * wSz);
            f  = (sword8*)(arena + 3 * wSz);
            g  = f + n;
            F  = g + n;
        }
    }
    if (arena == NULL) {
        ret = MEMORY_E;
        goto out;
    }

    ret = falcon_privkey_decode(key->k, keySz, f, g, F, logn);
    if (ret != 0) {
        goto out;
    }
    if (key->p[0] != (byte)(FALCON_PUB_HEAD | logn)) {
        ret = ASN_PARSE_E;
        goto out;
    }
    {
        int rc = falcon_modq_decode(key->p + 1, pubSz - 1, h, logn);
        if (rc < 0) {
            ret = rc;
            goto out;
        }
    }

    for (i = 0; i < n; i++) {
        int x = f[i];
        if (x < 0) {
            x += FALCON_Q;
        }
        ft[i] = (word16)x;
        x = g[i];
        if (x < 0) {
            x += FALCON_Q;
        }
        gt[i] = (word16)x;
    }
    falcon_get_tables(logn, &zetas, &izetas);
    falcon_ntt(ft, n, zetas);
    falcon_ntt(gt, n, zetas);
    falcon_ntt(h, n, zetas);
    for (i = 0; i < n; i++) {
        /* Barrett reduction (division-free, constant-time) instead of '%': ft[i]
         * is the NTT image of the secret polynomial f, and both h[i] and ft[i]
         * are in [0, q) so the product is in [0, q^2) -- falcon_barrett's domain
         * -- matching the verify path's pointwise multiply. */
        if (ft[i] == 0 ||
                (word16)falcon_barrett((word32)h[i] * ft[i]) != gt[i]) {
            ret = PUBLIC_KEY_E;
            break;
        }
    }

out:
    /* One ForceZero + free (covers the secret f/g/F and the NTT images ft/gt). */
    if (arena != NULL) {
        ForceZero(arena, (word32)arenaSz);
        XFREE(arena, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    return ret;
}
#endif /* !WOLFSSL_FALCON_VERIFY_ONLY */

int falcon_native_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
        word32 msgLen, int* res, falcon_key* key)
{
    int ret = 0;
    unsigned logn = 0;
    int n = 0;
    word32 pubSz = 0;
    const byte* sigData;
    word32 sigDataLen;
    word16* h = NULL;
    word16* c = NULL;
    word16* t = NULL;
    const word16* zetas = NULL;
    const word16* izetas = NULL;
    sword16* s2 = NULL;
    void* heap;
    /* h, c, t (word16) and s2 (sword16) are all n elements of 2 bytes: carve
     * them from one arena. The verify working set is public and small (<=8KB at
     * Falcon-1024), so it lives on the stack unless WOLFSSL_SMALL_STACK asks for
     * the heap. */
#ifdef WOLFSSL_SMALL_STACK
    word16* arena = NULL;
#else
    word16 arena[4 * FALCON_MAX_N];
#endif

    if (sig == NULL || res == NULL || key == NULL ||
            (msg == NULL && msgLen != 0)) {
        return BAD_FUNC_ARG;
    }
    *res = 0;
    if (!key->pubKeySet) {
        return BAD_FUNC_ARG;
    }
    if (falcon_level_params(key->level, &logn, &n, &pubSz) != 0) {
        return BAD_FUNC_ARG;
    }
    heap = key->heap;

    /* Signature framing: 1 header byte | 40-byte nonce | compressed s2. The
     * compressed encoding is variable length but bounded by the level's max. */
    if (sigLen < (word32)(1 + FALCON_NONCE_SIZE + 1)) {
        return BUFFER_E;
    }
    if (sigLen > (word32)(key->level == FALCON_LEVEL1 ?
            FALCON_LEVEL1_SIG_SIZE : FALCON_LEVEL5_SIG_SIZE)) {
        return BUFFER_E;
    }
    if (sig[0] != (byte)(FALCON_SIG_HEAD_COMPRESSED | logn)) {
        return ASN_PARSE_E;
    }
    sigData = sig + 1 + FALCON_NONCE_SIZE;
    sigDataLen = sigLen - 1 - FALCON_NONCE_SIZE;

#ifdef WOLFSSL_SMALL_STACK
    arena = (word16*)XMALLOC(sizeof(word16) * 4 * (size_t)n, heap,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (arena == NULL) {
        ret = MEMORY_E;
        goto out;
    }
#endif
    h  = arena;
    c  = arena + n;
    t  = arena + 2 * n;
    s2 = (sword16*)(arena + 3 * n);

    /* Decode public key h (skip the 0x0n header byte). */
    if (key->p[0] != (byte)(FALCON_PUB_HEAD | logn)) {
        ret = ASN_PARSE_E;
        goto out;
    }
    {
        int rc = falcon_modq_decode(key->p + 1, pubSz - 1, h, logn);
        if (rc < 0) {
            ret = rc;
            goto out;
        }
    }

    /* Decode compressed s2; the encoding must consume the whole buffer. */
    {
        int rc = falcon_comp_decode(sigData, sigDataLen, s2, logn);
        if (rc < 0) {
            ret = rc;
            goto out;
        }
        if ((word32)rc != sigDataLen) {
            ret = ASN_PARSE_E;
            goto out;
        }
    }

    /* c = HashToPoint(nonce || msg). */
    ret = falcon_hash_to_point(sig + 1, msg, msgLen, c, logn, heap);
    if (ret != 0) {
        goto out;
    }

    /* t = s2 * h mod (x^n + 1) mod q, via NTT. Twiddle tables are cached. */
    falcon_get_tables(logn, &zetas, &izetas);
    {
        int i;
        for (i = 0; i < n; i++) {
            sword32 v = s2[i];
            if (v < 0) {
                v += FALCON_Q;
            }
            t[i] = (word16)v;
        }
    }
    falcon_ntt(t, n, zetas);
    falcon_ntt(h, n, zetas);
    {
        int i = 0;
#ifdef WOLFSSL_FALCON_NTT_DSP
        for (; i + 1 < n; i += 2) {
            word32 T = falcon_ld2(t + i);
            word32 H = falcon_ld2(h + i);
            word32 p0 = falcon_barrett(falcon_smulbb(T, H));
            word32 p1 = falcon_barrett(falcon_smultt(T, H));
            falcon_st2(t + i, falcon_pack(p0, p1));
        }
#endif
        for (; i < n; i++) {
            t[i] = (word16)falcon_barrett((word32)t[i] * h[i]);
        }
    }
    falcon_intt(t, n, izetas);

    /* s1 = c - s2*h mod q (centered); accept iff ||(s1,s2)||^2 <= bound. */
    {
        word64 norm = 0;
        int i = 0;
#ifdef WOLFSSL_FALCON_NTT_DSP
        /* Accumulate two squared coefficients per SMUAD (a.lo^2 + a.hi^2).
         * |centered| <= q/2 < 2^13, so each SMUAD result < 2^27 (no overflow);
         * the running total is 64-bit. */
        for (; i + 1 < n; i += 2) {
            word32 d0 = falcon_csub(c[i]     + FALCON_Q - t[i]);
            word32 d1 = falcon_csub(c[i + 1] + FALCON_Q - t[i + 1]);
            word32 s1p = falcon_pack((word32)(sword16)falcon_center(d0),
                                     (word32)(sword16)falcon_center(d1));
            word32 s2p = falcon_pack((word32)(sword16)s2[i],
                                     (word32)(sword16)s2[i + 1]);
            norm += (word64)(word32)__smuad(s1p, s1p);
            norm += (word64)(word32)__smuad(s2p, s2p);
        }
#endif
        for (; i < n; i++) {
            word32 d = falcon_csub(c[i] + FALCON_Q - t[i]);
            sword32 s1c = falcon_center(d);
            sword32 s2c = s2[i];
            norm += (word64)((sword64)s1c * s1c);
            norm += (word64)((sword64)s2c * s2c);
        }
        if (norm <= (word64)falcon_l2bound[logn]) {
            *res = 1;
        }
    }

out:
    /* h/c/t/s2 share one arena; zetas/izetas point at static caches. */
#ifdef WOLFSSL_SMALL_STACK
    if (arena != NULL) XFREE(arena, heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return ret;
}


#endif /* HAVE_FALCON && !WOLF_CRYPTO_CB_ONLY_FALCON */

/* ==== Public wc_falcon_* API (cryptocb dispatch + arg checks) ==== */

#ifndef WOLFSSL_FALCON_VERIFY_ONLY
/* Generate a new Falcon key pair into key (key->level must be set first).
 *
 * key  [in/out]  Falcon key to populate.
 * rng  [in]      Random number generator.
 * returns BAD_FUNC_ARG when a parameter is NULL or level is unset,
 *         0 on success, other -ve value on failure.
 */
int wc_falcon_make_key(falcon_key* key, WC_RNG* rng)
{
    int ret = 0;

    if ((key == NULL) || (rng == NULL)) {
        return BAD_FUNC_ARG;
    }
    if ((key->level != 1) && (key->level != 5)) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (key->devId != INVALID_DEVID)
    #endif
    {
        ret = wc_CryptoCb_MakePqcSignatureKey(rng, WC_PQC_SIG_TYPE_FALCON,
                key->level, key);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
        ret = 0;
    }
#endif /* WOLF_CRYPTO_CB */

#ifdef WOLF_CRYPTO_CB_ONLY_FALCON
    /* No software fallback: only a crypto callback can service the request. */
    ret = NO_VALID_DEVID;
#else
    ret = falcon_native_make_key(key, rng);
#endif
    return ret;
}
#endif /* !WOLFSSL_FALCON_VERIFY_ONLY */

/* Sign the message using the falcon private key.
 *
 *  in          [in]      Message to sign.
 *  inLen       [in]      Length of the message in bytes.
 *  out         [in]      Buffer to write signature into.
 *  outLen      [in/out]  On in, size of buffer.
 *                        On out, the length of the signature in bytes.
 *  key         [in]      Falcon key to use when signing
 *  rng         [in]      Random number generator (required by the software
 *                        signer).
 *  returns BAD_FUNC_ARG when a parameter is NULL, the private key is not set,
 *          or (software path) rng is NULL,
 *          BUFFER_E when outLen is less than the active level's signature size
 *          (FALCON_LEVEL1_SIG_SIZE or FALCON_LEVEL5_SIG_SIZE),
 *          0 otherwise.
 */
int wc_falcon_sign_msg(const byte* in, word32 inLen,
                              byte* out, word32 *outLen,
                              falcon_key* key, WC_RNG* rng)
{
    int ret = 0;

    /* sanity check on arguments */
    if ((in == NULL) || (out == NULL) || (outLen == NULL) || (key == NULL)) {
        return  BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (key->devId != INVALID_DEVID)
    #endif
    {
        ret = wc_CryptoCb_PqcSign(in, inLen, out, outLen, NULL, 0,
                WC_HASH_TYPE_NONE, rng, WC_PQC_SIG_TYPE_FALCON, key);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
        ret = 0;
    }
#endif /* WOLF_CRYPTO_CB */

#ifdef WOLF_CRYPTO_CB_ONLY_FALCON
    /* No software fallback: only a crypto callback can service the request. */
    ret = NO_VALID_DEVID;
#elif defined(WOLFSSL_FALCON_VERIFY_ONLY)
    /* inLen/rng are only consumed by the (absent) software or cryptocb paths. */
    (void)inLen;
    (void)rng;
    ret = NOT_COMPILED_IN;
#else
    /* Software signer needs a private key and an RNG; validate both here so the
     * failure is reported at the API boundary rather than deep in the native
     * signer. */
    if ((ret == 0) && (!key->prvKeySet)) {
        ret = BAD_FUNC_ARG;
    }
    if ((ret == 0) && (rng == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = falcon_native_sign_msg(in, inLen, out, outLen, key, rng);
    }
#endif
    return ret;
}

/* Verify the message using the falcon public key.
 *
 *  sig         [in]  Signature to verify.
 *  sigLen      [in]  Size of signature in bytes.
 *  msg         [in]  Message to verify.
 *  msgLen      [in]  Length of the message in bytes.
 *  res         [out] *res is set to 1 on successful verification.
 *  key         [in]  Falcon key to use to verify.
 *  returns BAD_FUNC_ARG when a parameter is NULL or the public key is not set,
 *          BUFFER_E when sigLen is out of range for the key's level,
 *          0 on a completed verification (inspect *res for the result).
 */
int wc_falcon_verify_msg(const byte* sig, word32 sigLen, const byte* msg,
                        word32 msgLen, int* res, falcon_key* key)
{
    int ret = 0;

    if (key == NULL || sig == NULL || msg == NULL || res == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (key->devId != INVALID_DEVID)
    #endif
    {
        ret = wc_CryptoCb_PqcVerify(sig, sigLen, msg, msgLen, NULL, 0,
                WC_HASH_TYPE_NONE, res, WC_PQC_SIG_TYPE_FALCON, key);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
        ret = 0;
    }
#endif /* WOLF_CRYPTO_CB */

#ifdef WOLF_CRYPTO_CB_ONLY_FALCON
    /* No software fallback: only a crypto callback can service the request. */
    ret = NO_VALID_DEVID;
#else
    if ((ret == 0) && (!key->pubKeySet)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = falcon_native_verify_msg(sig, sigLen, msg, msgLen, res, key);
    }
#endif

    return ret;
}

/* Initialize the falcon private/public key.
 *
 * key  [in]  Falcon key.
 * returns BAD_FUNC_ARG when key is NULL
 */
int wc_falcon_init(falcon_key* key)
{
    return wc_falcon_init_ex(key, NULL, INVALID_DEVID);
}

/* Initialize the falcon private/public key.
 *
 * key  [in]  Falcon key.
 * heap [in]  Heap hint.
 * devId[in]  Device ID.
 * returns BAD_FUNC_ARG when key is NULL
 */
int wc_falcon_init_ex(falcon_key* key, void* heap, int devId)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    ForceZero(key, sizeof(*key));

    key->heap = heap;

#ifdef WOLF_CRYPTO_CB
    key->devCtx = NULL;
    key->devId = devId;
#endif
#ifdef WOLF_PRIVATE_KEY_ID
    key->idLen = 0;
    key->labelLen = 0;
#endif

    (void) heap;
    (void) devId;

    return 0;
}

#ifdef WOLF_PRIVATE_KEY_ID
int wc_falcon_init_id(falcon_key* key, const unsigned char* id, int len,
                         void* heap, int devId)
{
    int ret = 0;

    if (key == NULL)
        ret = BAD_FUNC_ARG;
    if (ret == 0 && (len < 0 || len > FALCON_MAX_ID_LEN))
        ret = BUFFER_E;

    if (ret == 0)
        ret = wc_falcon_init_ex(key, heap, devId);
    if (ret == 0 && id != NULL && len != 0) {
        XMEMCPY(key->id, id, (size_t)len);
        key->idLen = len;
    }

    /* Set the maximum level here */
    wc_falcon_set_level(key, 5);

    return ret;
}

int wc_falcon_init_label(falcon_key* key, const char* label, void* heap,
                            int devId)
{
    int ret = 0;
    int labelLen = 0;

    if (key == NULL || label == NULL)
        ret = BAD_FUNC_ARG;
    if (ret == 0) {
        labelLen = (int)XSTRLEN(label);
        if (labelLen == 0 || labelLen > FALCON_MAX_LABEL_LEN)
            ret = BUFFER_E;
    }

    if (ret == 0)
        ret = wc_falcon_init_ex(key, heap, devId);
    if (ret == 0) {
        XMEMCPY(key->label, label, (size_t)labelLen);
        key->labelLen = labelLen;
    }

    /* Set the maximum level here */
    wc_falcon_set_level(key, 5);

    return ret;
}
#endif

/* Set the level of the falcon private/public key.
 *
 * key   [out]  Falcon key.
 * level [in]   Either 1 or 5.
 * returns BAD_FUNC_ARG when key is NULL or level is not 1 and not 5.
 */
int wc_falcon_set_level(falcon_key* key, byte level)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (level != 1 && level != 5) {
        return BAD_FUNC_ARG;
    }

    key->level = level;
    key->pubKeySet = 0;
    key->prvKeySet = 0;
    return 0;
}

/* Get the level of the falcon private/public key.
 *
 * key   [in]  Falcon key.
 * level [out] The level.
 * returns BAD_FUNC_ARG when key is NULL or level has not been set.
 */
int wc_falcon_get_level(falcon_key* key, byte* level)
{
    if (key == NULL || level == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->level != 1 && key->level != 5) {
        return BAD_FUNC_ARG;
    }

    *level = key->level;
    return 0;
}

/* Clears the falcon key data
 *
 * key  [in]  Falcon key.
 */
void wc_falcon_free(falcon_key* key)
{
    if (key != NULL) {
        ForceZero(key, sizeof(*key));
    }
}

/* Export the falcon public key.
 *
 * key     [in]      Falcon public key.
 * out     [in]      Array to hold public key.
 * outLen  [in/out]  On in, the number of bytes in array.
 *                   On out, the number bytes put into array.
 * returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when outLen is less than FALCON_LEVEL1_PUB_KEY_SIZE,
 *         0 otherwise.
 */
int wc_falcon_export_public(falcon_key* key,
                            byte* out, word32* outLen)
{
    /* sanity check on arguments */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        return BAD_FUNC_ARG;
    }

    if ((key->level != 1) && (key->level != 5)) {
        return BAD_FUNC_ARG;
    }

    if (!key->pubKeySet) {
        return BAD_FUNC_ARG;
    }

    /* check and set up out length */
    if ((key->level == 1) && (*outLen < FALCON_LEVEL1_PUB_KEY_SIZE)) {
        *outLen = FALCON_LEVEL1_PUB_KEY_SIZE;
        return BUFFER_E;
    }
    else if ((key->level == 5) && (*outLen < FALCON_LEVEL5_PUB_KEY_SIZE)) {
        *outLen = FALCON_LEVEL5_PUB_KEY_SIZE;
        return BUFFER_E;
    }

    if (key->level == 1) {
        *outLen = FALCON_LEVEL1_PUB_KEY_SIZE;
        XMEMCPY(out, key->p, FALCON_LEVEL1_PUB_KEY_SIZE);
    }
    else if (key->level == 5) {
        *outLen = FALCON_LEVEL5_PUB_KEY_SIZE;
        XMEMCPY(out, key->p, FALCON_LEVEL5_PUB_KEY_SIZE);
    }

    return 0;
}

/* Import a falcon public key from a byte array.
 * Public key encoded in big-endian.
 *
 * in      [in]  Array holding public key.
 * inLen   [in]  Number of bytes of data in array.
 * key     [in]  Falcon public key.
 * returns BAD_FUNC_ARG when a parameter is NULL or key format is not supported,
 *         0 otherwise.
 */
int wc_falcon_import_public(const byte* in, word32 inLen,
                                   falcon_key* key)
{
    /* sanity check on arguments */
    if ((in == NULL) || (key == NULL)) {
        return BAD_FUNC_ARG;
    }

    if ((key->level != 1) && (key->level != 5)) {
        return BAD_FUNC_ARG;
    }

    if ((key->level == 1) && (inLen != FALCON_LEVEL1_PUB_KEY_SIZE)) {
        return BAD_FUNC_ARG;
    }
    else if ((key->level == 5) && (inLen != FALCON_LEVEL5_PUB_KEY_SIZE)) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(key->p, in, inLen);
    key->pubKeySet = 1;

    return 0;
}

/* Import a raw Falcon private key.
 *
 * Accepts either the raw secret key (FALCON_LEVELx_KEY_SIZE) or the legacy
 * concat(priv, pub) layout (FALCON_LEVELx_PRV_KEY_SIZE) produced by older
 * wolfSSL releases. In the concat case, the trailing public-key bytes are
 * imported as well so verify works on round-tripped keys.
 *
 * priv    [in]  Raw private-key bytes.
 * privSz  [in]  Length of priv in bytes.
 * key     [in]  Falcon key. key->level must already be set.
 * returns BAD_FUNC_ARG when a parameter is NULL or privSz doesn't match
 *         either accepted size, 0 otherwise.
 *
 * This is the raw-bytes import. To decode a DER/PKCS8 Falcon private key,
 * use wc_Falcon_PrivateKeyDecode instead.
 */
int wc_falcon_import_private_only(const byte* priv, word32 privSz,
                                 falcon_key* key)
{
    word32 keySz;
    word32 concatSz;

    if ((priv == NULL) || (key == NULL)) {
        return BAD_FUNC_ARG;
    }

    if (key->level == 1) {
        keySz = FALCON_LEVEL1_KEY_SIZE;
        concatSz = FALCON_LEVEL1_PRV_KEY_SIZE;
    }
    else if (key->level == 5) {
        keySz = FALCON_LEVEL5_KEY_SIZE;
        concatSz = FALCON_LEVEL5_PRV_KEY_SIZE;
    }
    else {
        return BAD_FUNC_ARG;
    }

    if ((privSz != keySz) && (privSz != concatSz)) {
        return BAD_FUNC_ARG;
    }

    XMEMCPY(key->k, priv, keySz);
    key->prvKeySet = 1;

    /* Legacy concat layout carries the public key after the private key. */
    if (privSz == concatSz) {
        XMEMCPY(key->p, priv + keySz, concatSz - keySz);
        key->pubKeySet = 1;
    }

    return 0;
}

/* Import a raw Falcon private (and optionally public) key.
 *
 * If pub is NULL (and pubSz is 0), only the private key is imported. The
 * private buffer may be in the legacy concat(priv,pub) layout, in which case
 * the public part is recovered from it.
 *
 * priv    [in]  Raw private-key bytes (FALCON_LEVELx_KEY_SIZE or the legacy
 *               FALCON_LEVELx_PRV_KEY_SIZE concat layout).
 * privSz  [in]  Length of priv in bytes.
 * pub     [in]  Raw public-key bytes (FALCON_LEVELx_PUB_KEY_SIZE), or NULL.
 * pubSz   [in]  Length of pub in bytes (0 if pub is NULL).
 * key     [in]  Falcon key. key->level must already be set.
 * returns BAD_FUNC_ARG when a required parameter is NULL or a length doesn't
 *         match an expected size, 0 otherwise.
 *
 * This is the raw-bytes import. To decode a DER/PKCS8 Falcon private key,
 * use wc_Falcon_PrivateKeyDecode instead.
 */
int wc_falcon_import_private_key(const byte* priv, word32 privSz,
                                        const byte* pub, word32 pubSz,
                                        falcon_key* key)
{
    int ret;

    if ((priv == NULL) || (key == NULL)) {
        return BAD_FUNC_ARG;
    }
    if ((pub == NULL) && (pubSz != 0)) {
        return BAD_FUNC_ARG;
    }

    ret = wc_falcon_import_private_only(priv, privSz, key);
    if ((ret == 0) && (pub != NULL)) {
        ret = wc_falcon_import_public(pub, pubSz, key);
    }
    return ret;
}

/* Export the falcon private key.
 *
 * key     [in]      Falcon private key.
 * out     [in]      Array to hold private key.
 * outLen  [in/out]  On in, the number of bytes in array.
 *                   On out, the number bytes put into array.
 * returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when outLen is less than FALCON_LEVEL1_KEY_SIZE,
 *         0 otherwise.
 */
int wc_falcon_export_private_only(falcon_key* key, byte* out, word32* outLen)
{
    /* sanity checks on arguments */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        return BAD_FUNC_ARG;
    }

    if ((key->level != 1) && (key->level != 5)) {
        return BAD_FUNC_ARG;
    }

    /* check and set up out length */
    if ((key->level == 1) && (*outLen < FALCON_LEVEL1_KEY_SIZE)) {
        *outLen = FALCON_LEVEL1_KEY_SIZE;
        return BUFFER_E;
    }
    else if ((key->level == 5) && (*outLen < FALCON_LEVEL5_KEY_SIZE)) {
        *outLen = FALCON_LEVEL5_KEY_SIZE;
        return BUFFER_E;
    }

    if (key->level == 1) {
        *outLen = FALCON_LEVEL1_KEY_SIZE;
    }
    else if (key->level == 5) {
        *outLen = FALCON_LEVEL5_KEY_SIZE;
    }

    XMEMCPY(out, key->k, *outLen);

    return 0;
}

/* Export the falcon private and public key.
 *
 * key     [in]      Falcon private/public key.
 * out     [in]      Array to hold private and public key.
 * outLen  [in/out]  On in, the number of bytes in array.
 *                   On out, the number bytes put into array.
 * returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when outLen is less than FALCON_LEVEL1_PRV_KEY_SIZE,
 *         0 otherwise.
 */
int wc_falcon_export_private(falcon_key* key, byte* out, word32* outLen)
{
    /* sanity checks on arguments */
    if ((key == NULL) || (out == NULL) || (outLen == NULL)) {
        return BAD_FUNC_ARG;
    }

    if ((key->level != 1) && (key->level != 5)) {
        return BAD_FUNC_ARG;
    }

    if ((key->level == 1) && (*outLen < FALCON_LEVEL1_PRV_KEY_SIZE)) {
        *outLen = FALCON_LEVEL1_PRV_KEY_SIZE;
        return BUFFER_E;
    }
    else if ((key->level == 5) && (*outLen < FALCON_LEVEL5_PRV_KEY_SIZE)) {
        *outLen = FALCON_LEVEL5_PRV_KEY_SIZE;
        return BUFFER_E;
    }


    if (key->level == 1) {
        *outLen = FALCON_LEVEL1_PRV_KEY_SIZE;
        XMEMCPY(out, key->k, FALCON_LEVEL1_KEY_SIZE);
        XMEMCPY(out + FALCON_LEVEL1_KEY_SIZE, key->p,
                FALCON_LEVEL1_PUB_KEY_SIZE);
    }
    else if (key->level == 5) {
        *outLen = FALCON_LEVEL5_PRV_KEY_SIZE;
        XMEMCPY(out, key->k, FALCON_LEVEL5_KEY_SIZE);
        XMEMCPY(out + FALCON_LEVEL5_KEY_SIZE, key->p,
                FALCON_LEVEL5_PUB_KEY_SIZE);
    }

    return 0;
}

/* Export the falcon private and public key.
 *
 * key     [in]      Falcon private/public key.
 * priv    [in]      Array to hold private key.
 * privSz  [in/out]  On in, the number of bytes in private key array.
 * pub     [in]      Array to hold  public key.
 * pubSz   [in/out]  On in, the number of bytes in public key array.
 *                   On out, the number bytes put into array.
 * returns BAD_FUNC_ARG when a parameter is NULL,
 *         BUFFER_E when privSz is less than FALCON_LEVEL1_PRV_KEY_SIZE or pubSz is less
 *         than FALCON_LEVEL1_PUB_KEY_SIZE,
 *         0 otherwise.
 */
int wc_falcon_export_key(falcon_key* key, byte* priv, word32 *privSz,
                        byte* pub, word32 *pubSz)
{
    int ret = 0;

    /* export private part */
    ret = wc_falcon_export_private(key, priv, privSz);
    if (ret == 0) {
        /* export public part */
        ret = wc_falcon_export_public(key, pub, pubSz);
    }

    return ret;
}

/* Check that the falcon key has a matching private/public key pair present.
 *
 * key     [in]      Falcon private/public key.
 * returns BAD_FUNC_ARG when key is NULL or the level is unset,
 *         PUBLIC_KEY_E when either half is not set, or when the stored public
 *         key h does not satisfy the defining relation h = g/f (mod q) for the
 *         private (f, g),
 *         0 otherwise.
 *
 * When the native signing core is compiled in, both halves are decoded and the
 * relation h*f == g (mod q, mod X^n + 1) is verified in the NTT domain, so a
 * mismatched pair is detected cryptographically. In verify-only or
 * callback-only builds (no private-key codec available) only the presence of
 * both halves is checked. The pre-native implementation compared the stored
 * public key against a duplicate copy kept behind the private key, which was
 * always a copy of the same bytes and so could never detect a mismatch. */
int wc_falcon_check_key(falcon_key* key)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if ((key->level != 1) && (key->level != 5)) {
        return BAD_FUNC_ARG;
    }

    if (!key->pubKeySet || !key->prvKeySet) {
        return PUBLIC_KEY_E;
    }

#ifdef WC_FALCON_HAVE_NATIVE_SIGN
    return falcon_native_check_key(key);
#else
    return 0;
#endif
}

/* Returns the size of a falcon private key.
 *
 * key     [in]      Falcon private/public key.
 * returns BAD_FUNC_ARG when key is NULL,
 *         FALCON_LEVEL1_KEY_SIZE otherwise.
 */
int wc_falcon_size(falcon_key* key)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->level == 1) {
        return FALCON_LEVEL1_KEY_SIZE;
    }
    else if (key->level == 5) {
        return FALCON_LEVEL5_KEY_SIZE;
    }

    return BAD_FUNC_ARG;
}

/* Returns the size of a falcon private plus public key.
 *
 * key     [in]      Falcon private/public key.
 * returns BAD_FUNC_ARG when key is NULL,
 *         FALCON_LEVEL1_PRV_KEY_SIZE otherwise.
 */
int wc_falcon_priv_size(falcon_key* key)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->level == 1) {
        return FALCON_LEVEL1_PRV_KEY_SIZE;
    }
    else if (key->level == 5) {
        return FALCON_LEVEL5_PRV_KEY_SIZE;
    }

    return BAD_FUNC_ARG;
}

/* Returns the size of a falcon public key.
 *
 * key     [in]      Falcon private/public key.
 * returns BAD_FUNC_ARG when key is NULL,
 *         FALCON_LEVEL1_PUB_KEY_SIZE otherwise.
 */
int wc_falcon_pub_size(falcon_key* key)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->level == 1) {
        return FALCON_LEVEL1_PUB_KEY_SIZE;
    }
    else if (key->level == 5) {
        return FALCON_LEVEL5_PUB_KEY_SIZE;
    }

    return BAD_FUNC_ARG;
}

/* Returns the size of a falcon signature.
 *
 * key     [in]      Falcon private/public key.
 * returns BAD_FUNC_ARG when key is NULL,
 *         FALCON_LEVEL1_SIG_SIZE otherwise.
 */
int wc_falcon_sig_size(falcon_key* key)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->level == 1) {
        return FALCON_LEVEL1_SIG_SIZE;
    }
    else if (key->level == 5) {
        return FALCON_LEVEL5_SIG_SIZE;
    }

    return BAD_FUNC_ARG;
}

int wc_Falcon_PrivateKeyDecode(const byte* input, word32* inOutIdx,
                                     falcon_key* key, word32 inSz)
{
    int ret = 0;
    byte* privKey = NULL;
    byte* pubKey = NULL;
    word32 privKeyLen = FALCON_MAX_PRV_KEY_SIZE;
    word32 pubKeyLen = FALCON_MAX_PUB_KEY_SIZE;
    int keytype = 0;

    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0) {
        return BAD_FUNC_ARG;
    }

    if (key->level == 1) {
        keytype = FALCON_LEVEL1k;
    }
    else if (key->level == 5) {
        keytype = FALCON_LEVEL5k;
    }
    else {
        return BAD_FUNC_ARG;
    }

    privKey = (byte*)XMALLOC(FALCON_MAX_PRV_KEY_SIZE, NULL,
                             DYNAMIC_TYPE_TMP_BUFFER);
    if (privKey == NULL)
        return MEMORY_E;
    pubKey = (byte*)XMALLOC(FALCON_MAX_PUB_KEY_SIZE, NULL,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (pubKey == NULL) {
        XFREE(privKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }

    ret = DecodeAsymKey(input, inOutIdx, inSz, privKey, &privKeyLen,
                        pubKey, &pubKeyLen, keytype);
    if (ret == 0) {
        /* PKCS8 may carry only the private key; pass NULL/0 in that case
         * so import_private_key can recover the public part from the legacy
         * concat layout (or leave pubKeySet = 0 for a strict raw private). */
        if (pubKeyLen == 0) {
            ret = wc_falcon_import_private_key(privKey, privKeyLen,
                                               NULL, 0, key);
        }
        else {
            ret = wc_falcon_import_private_key(privKey, privKeyLen,
                                               pubKey, pubKeyLen, key);
        }
    }

    XFREE(privKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

int wc_Falcon_PublicKeyDecode(const byte* input, word32* inOutIdx,
                                    falcon_key* key, word32 inSz)
{
    int ret = 0;
    WC_DECLARE_VAR(pubKey, byte, FALCON_MAX_PUB_KEY_SIZE, NULL);
    word32 pubKeyLen = FALCON_MAX_PUB_KEY_SIZE;
    int keytype = 0;

    if (input == NULL || inOutIdx == NULL || key == NULL || inSz == 0) {
        return BAD_FUNC_ARG;
    }

    ret = wc_falcon_import_public(input, inSz, key);
    if (ret == 0) {
        return 0;
    }

    if (key->level == 1) {
        keytype = FALCON_LEVEL1k;
    }
    else if (key->level == 5) {
        keytype = FALCON_LEVEL5k;
    }
    else {
        return BAD_FUNC_ARG;
    }

    WC_ALLOC_VAR_EX(pubKey, byte, FALCON_MAX_PUB_KEY_SIZE, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER, return MEMORY_E);

    ret = DecodeAsymKeyPublic(input, inOutIdx, inSz, pubKey, &pubKeyLen,
                              keytype);
    if (ret == 0) {
        ret = wc_falcon_import_public(pubKey, pubKeyLen, key);
    }

    WC_FREE_VAR_EX(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

#ifdef WC_ENABLE_ASYM_KEY_EXPORT
/* Encode the public part of an Falcon key in DER.
 *
 * Pass NULL for output to get the size of the encoding.
 *
 * @param [in]  key       Falcon key object.
 * @param [out] output    Buffer to put encoded data in.
 * @param [in]  outLen    Size of buffer in bytes.
 * @param [in]  withAlg   Whether to use SubjectPublicKeyInfo format.
 * @return  Size of encoded data in bytes on success.
 * @return  BAD_FUNC_ARG when key is NULL.
 * @return  MEMORY_E when dynamic memory allocation failed.
 */
int wc_Falcon_PublicKeyToDer(falcon_key* key, byte* output, word32 inLen,
                             int withAlg)
{
    int    ret;
    WC_DECLARE_VAR(pubKey, byte, FALCON_MAX_PUB_KEY_SIZE, NULL);
    word32 pubKeyLen = FALCON_MAX_PUB_KEY_SIZE;
    int    keytype = 0;

    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->level == 1) {
        keytype = FALCON_LEVEL1k;
    }
    else if (key->level == 5) {
        keytype = FALCON_LEVEL5k;
    }
    else {
        return BAD_FUNC_ARG;
    }

    WC_ALLOC_VAR_EX(pubKey, byte, FALCON_MAX_PUB_KEY_SIZE, NULL,
                    DYNAMIC_TYPE_TMP_BUFFER, return MEMORY_E);

    ret = wc_falcon_export_public(key, pubKey, &pubKeyLen);
    if (ret == 0) {
        ret = SetAsymKeyDerPublic(pubKey, pubKeyLen, output, inLen, keytype,
                                  withAlg);
    }

    WC_FREE_VAR_EX(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#endif

int wc_Falcon_KeyToDer(falcon_key* key, byte* output, word32 inLen)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->level == 1) {
        return SetAsymKeyDer(key->k, FALCON_LEVEL1_KEY_SIZE, key->p,
                             FALCON_LEVEL1_PUB_KEY_SIZE, output, inLen,
                             FALCON_LEVEL1k);
    }
    else if (key->level == 5) {
        return SetAsymKeyDer(key->k, FALCON_LEVEL5_KEY_SIZE, key->p,
                             FALCON_LEVEL5_PUB_KEY_SIZE, output, inLen,
                             FALCON_LEVEL5k);
    }

    return BAD_FUNC_ARG;
}

int wc_Falcon_PrivateKeyToDer(falcon_key* key, byte* output, word32 inLen)
{
    if (key == NULL) {
        return BAD_FUNC_ARG;
    }

    if (key->level == 1) {
        return SetAsymKeyDer(key->k, FALCON_LEVEL1_KEY_SIZE, NULL, 0, output,
                             inLen, FALCON_LEVEL1k);
    }
    else if (key->level == 5) {
        return SetAsymKeyDer(key->k, FALCON_LEVEL5_KEY_SIZE, NULL, 0, output,
                             inLen, FALCON_LEVEL5k);
    }

    return BAD_FUNC_ARG;
}

/* ==== AVX2 (__m256d + FMA) FFT/poly backend, folded from the former
   wc_falcon_fft_avx2.c. Self-guarded and self-scheduled via per-function
   target attributes, so it needs no special per-file CFLAGS. ==== */
/* AVX2 (__m256d + FMA) FFT backend for the native Falcon signing path.
 *
 * This is a vectorization of the scalar FFT in wc_falcon_fft.c and the hot
 * FFT-domain pointwise polynomial operations in wc_falcon_poly.c. It processes
 * 4 doubles per 256-bit vector and uses fused multiply-add for the complex
 * butterflies. The algorithm and twiddle-table (falcon_gm_tab) layout are
 * unchanged from the scalar backend; only the butterfly inner loops (and the
 * pointwise poly ops) are widened.
 *
 * Representation (see the fpr/FFT seam above): a degree-n real polynomial is carried as
 * n fpr (= IEEE-754 bit patterns in a word64) = n/2 complex evaluations; real
 * parts live in [0, n/2), imaginary parts in [n/2, n). Because an fpr IS the
 * bit pattern of a double, the fpr arrays are loaded directly with
 * _mm256_loadu_pd((const double*)ptr).
 *
 * CORRECTNESS NOTE: unlike the rest of the fpr seam, this backend does NOT
 * promise bit-identical (round-to-nearest-even, no-FMA) results. FMA fuses the
 * multiply-add with a single rounding, so the FFT output differs in the last
 * ULPs from the scalar backend. This is intentional and safe: the signing FFT
 * only needs to produce a short vector that passes the norm bound and verifies;
 * it is never required to be reproducible against the scalar path. The Gaussian
 * sampler's determinism depends only on the fpr_* scalar ops (unchanged), and
 * verification is integer-only and unaffected.
 *
 * TARGET ISA: every externally-visible function and every intrinsic helper is
 * annotated with __attribute__((target("avx2,fma"))) on GCC/Clang, so the TU
 * compiles and runs correctly even when the surrounding build uses only a
 * baseline (e.g. SSE2) -march. The annotation is harmless if the build ALSO
 * passes -mavx2 -mfma per file. On compilers without the target attribute
 * (e.g. MSVC) the TU must be compiled with the appropriate /arch:AVX2 flag.
 */


#if defined(HAVE_FALCON) && !defined(WOLF_CRYPTO_CB_ONLY_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY) && \
    defined(WOLFSSL_FALCON_FFT_AVX2)


#include <immintrin.h>

#if defined(__GNUC__) || defined(__clang__)
    #define FALCON_AVX2_TARGET __attribute__((target("avx2,fma")))
#else
    #define FALCON_AVX2_TARGET
#endif

/* Reinterpret an fpr (word64 bit pattern) as a double without aliasing UB:
 * the fpr arrays are word64 but hold IEEE-754 doubles, so a value-preserving
 * load through (const double*) is what the SIMD path needs. */
static WC_INLINE double falcon_avx2_d(fpr x)
{
    double d;
    XMEMCPY(&d, &x, sizeof(d));
    return d;
}

/* Scalar (inline-double) complex helpers for the small-stride tail levels.
 * These match the scalar backend exactly (no FMA) for the few coefficients
 * where SIMD would not pay off. The scalar core defined FPC_* earlier in this
 * file with a different (alias-safe) form, so undef before redefining -- the
 * same per-backend macro discipline as sha512.c's SHA_METHOD. */
#undef FPC_MUL
#undef FPC_ADD
#undef FPC_SUB
#define FPC_MUL(d_re, d_im, a_re, a_im, b_re, b_im) do { \
        fpr _ar = (a_re), _ai = (a_im), _br = (b_re), _bi = (b_im); \
        (d_re) = fpr_sub(fpr_mul(_ar, _br), fpr_mul(_ai, _bi)); \
        (d_im) = fpr_add(fpr_mul(_ar, _bi), fpr_mul(_ai, _br)); \
    } while (0)
#define FPC_ADD(d_re, d_im, a_re, a_im, b_re, b_im) do { \
        (d_re) = fpr_add((a_re), (b_re)); \
        (d_im) = fpr_add((a_im), (b_im)); \
    } while (0)
#define FPC_SUB(d_re, d_im, a_re, a_im, b_re, b_im) do { \
        (d_re) = fpr_sub((a_re), (b_re)); \
        (d_im) = fpr_sub((a_im), (b_im)); \
    } while (0)

/* Vector complex multiply: (yr + i yi) <- (yr + i yi) * (sr + i si).
 * Uses FMA: re = yr*sr - yi*si, im = yr*si + yi*sr. */
#define FALCON_VCMUL(out_re, out_im, yr, yi, sr, si) do { \
        __m256d _t0 = _mm256_mul_pd((yi), (si)); \
        __m256d _t1 = _mm256_mul_pd((yi), (sr)); \
        (out_re) = _mm256_fmsub_pd((yr), (sr), _t0); \
        (out_im) = _mm256_fmadd_pd((yr), (si), _t1); \
    } while (0)

/* ------------------------------------------------------------------------- */
/* Forward FFT                                                               */
/* ------------------------------------------------------------------------- */

FALCON_AVX2_TARGET
void falcon_FFT(fpr* f, unsigned logn)
{
    double* fd = (double*)f;
    unsigned u;
    size_t t, n, hn, m;

    n = (size_t)1 << logn;
    hn = n >> 1;
    t = hn;
    for (u = 1, m = 2; u < logn; u++, m <<= 1) {
        size_t ht = t >> 1, hm = m >> 1, i1, j1;
        for (i1 = 0, j1 = 0; i1 < hm; i1++, j1 += t) {
            size_t j, j2 = j1 + ht;
            fpr s_re = falcon_gm_tab[((m + i1) << 1) + 0];
            fpr s_im = falcon_gm_tab[((m + i1) << 1) + 1];
            if (ht >= 4) {
                __m256d vsr = _mm256_set1_pd(falcon_avx2_d(s_re));
                __m256d vsi = _mm256_set1_pd(falcon_avx2_d(s_im));
                for (j = j1; j < j2; j += 4) {
                    __m256d xr = _mm256_loadu_pd(fd + j);
                    __m256d xi = _mm256_loadu_pd(fd + j + hn);
                    __m256d yr = _mm256_loadu_pd(fd + j + ht);
                    __m256d yi = _mm256_loadu_pd(fd + j + ht + hn);
                    __m256d tr, ti;
                    FALCON_VCMUL(tr, ti, yr, yi, vsr, vsi);
                    _mm256_storeu_pd(fd + j,           _mm256_add_pd(xr, tr));
                    _mm256_storeu_pd(fd + j + hn,      _mm256_add_pd(xi, ti));
                    _mm256_storeu_pd(fd + j + ht,      _mm256_sub_pd(xr, tr));
                    _mm256_storeu_pd(fd + j + ht + hn, _mm256_sub_pd(xi, ti));
                }
            }
            else {
                /* small-stride tail (ht == 1 or 2): scalar inline-double */
                for (j = j1; j < j2; j++) {
                    fpr x_re = f[j], x_im = f[j + hn];
                    fpr y_re = f[j + ht], y_im = f[j + ht + hn];
                    FPC_MUL(y_re, y_im, y_re, y_im, s_re, s_im);
                    FPC_ADD(f[j], f[j + hn], x_re, x_im, y_re, y_im);
                    FPC_SUB(f[j + ht], f[j + ht + hn], x_re, x_im, y_re, y_im);
                }
            }
        }
        t = ht;
    }
}

/* ------------------------------------------------------------------------- */
/* Inverse FFT                                                               */
/* ------------------------------------------------------------------------- */

FALCON_AVX2_TARGET
void falcon_iFFT(fpr* f, unsigned logn)
{
    double* fd = (double*)f;
    int u;
    size_t n = (size_t)1 << logn, hn = n >> 1;

    for (u = (int)logn - 1; u >= 1; u--) {
        size_t m = (size_t)1 << u, hm = m >> 1;
        size_t t = hn >> u;             /* butterfly stride */
        size_t i1, j1;
        for (i1 = 0, j1 = 0; i1 < hm; i1++, j1 += (t << 1)) {
            size_t j, j2 = j1 + t;
            fpr s_re = falcon_gm_tab[((m + i1) << 1) + 0];
            fpr s_im = fpr_neg(falcon_gm_tab[((m + i1) << 1) + 1]);
            if (t >= 4) {
                __m256d vsr = _mm256_set1_pd(falcon_avx2_d(s_re));
                __m256d vsi = _mm256_set1_pd(falcon_avx2_d(s_im));
                for (j = j1; j < j2; j += 4) {
                    __m256d ar = _mm256_loadu_pd(fd + j);
                    __m256d ai = _mm256_loadu_pd(fd + j + hn);
                    __m256d br = _mm256_loadu_pd(fd + j + t);
                    __m256d bi = _mm256_loadu_pd(fd + j + t + hn);
                    __m256d dr = _mm256_sub_pd(ar, br);
                    __m256d di = _mm256_sub_pd(ai, bi);
                    __m256d pr, pi;
                    _mm256_storeu_pd(fd + j,      _mm256_add_pd(ar, br));
                    _mm256_storeu_pd(fd + j + hn, _mm256_add_pd(ai, bi));
                    FALCON_VCMUL(pr, pi, dr, di, vsr, vsi);
                    _mm256_storeu_pd(fd + j + t,      pr);
                    _mm256_storeu_pd(fd + j + t + hn, pi);
                }
            }
            else {
                for (j = j1; j < j2; j++) {
                    fpr a_re = f[j], a_im = f[j + hn];
                    fpr b_re = f[j + t], b_im = f[j + t + hn];
                    fpr d_re, d_im;
                    FPC_ADD(f[j], f[j + hn], a_re, a_im, b_re, b_im);
                    FPC_SUB(d_re, d_im, a_re, a_im, b_re, b_im);
                    FPC_MUL(f[j + t], f[j + t + hn], d_re, d_im, s_re, s_im);
                }
            }
        }
    }
    /* final scale by 1 / 2^(logn-1) */
    {
        fpr ni = fpr_inv(fpr_of((sword64)hn));
        if (n >= 4) {
            __m256d vni = _mm256_set1_pd(falcon_avx2_d(ni));
            size_t j;
            for (j = 0; j < n; j += 4) {
                _mm256_storeu_pd(fd + j,
                    _mm256_mul_pd(_mm256_loadu_pd(fd + j), vni));
            }
        }
        else {
            size_t j;
            for (j = 0; j < n; j++) {
                f[j] = fpr_mul(f[j], ni);
            }
        }
    }
}

/* ------------------------------------------------------------------------- */
/* FFT-domain pointwise polynomial operations (hot in signing)               */
/* ------------------------------------------------------------------------- */

/* a <- a * b (pointwise complex product) over [0, hn). */
FALCON_AVX2_TARGET
void falcon_poly_mul_fft_avx2(fpr* a, const fpr* b, unsigned logn)
{
    double* ad = (double*)a;
    const double* bd = (const double*)b;
    size_t n = (size_t)1 << logn, hn = n >> 1, u;

    if (hn >= 4) {
        for (u = 0; u < hn; u += 4) {
            __m256d ar = _mm256_loadu_pd(ad + u);
            __m256d ai = _mm256_loadu_pd(ad + u + hn);
            __m256d br = _mm256_loadu_pd(bd + u);
            __m256d bi = _mm256_loadu_pd(bd + u + hn);
            __m256d t0 = _mm256_mul_pd(ai, bi);
            __m256d t1 = _mm256_mul_pd(ai, br);
            __m256d re = _mm256_fmsub_pd(ar, br, t0); /* ar*br - ai*bi */
            __m256d im = _mm256_fmadd_pd(ar, bi, t1); /* ar*bi + ai*br */
            _mm256_storeu_pd(ad + u,      re);
            _mm256_storeu_pd(ad + u + hn, im);
        }
    }
    else {
        for (u = 0; u < hn; u++) {
            fpr a_re = a[u], a_im = a[u + hn];
            fpr b_re = b[u], b_im = b[u + hn];
            FPC_MUL(a[u], a[u + hn], a_re, a_im, b_re, b_im);
        }
    }
}

/* a <- a + b over [0, n). */
FALCON_AVX2_TARGET
void falcon_poly_add_avx2(fpr* a, const fpr* b, unsigned logn)
{
    double* ad = (double*)a;
    const double* bd = (const double*)b;
    size_t n = (size_t)1 << logn, u;

    if (n >= 4) {
        for (u = 0; u < n; u += 4) {
            _mm256_storeu_pd(ad + u,
                _mm256_add_pd(_mm256_loadu_pd(ad + u), _mm256_loadu_pd(bd + u)));
        }
    }
    else {
        for (u = 0; u < n; u++) {
            a[u] = fpr_add(a[u], b[u]);
        }
    }
}

/* a <- a - b over [0, n). */
FALCON_AVX2_TARGET
void falcon_poly_sub_avx2(fpr* a, const fpr* b, unsigned logn)
{
    double* ad = (double*)a;
    const double* bd = (const double*)b;
    size_t n = (size_t)1 << logn, u;

    if (n >= 4) {
        for (u = 0; u < n; u += 4) {
            _mm256_storeu_pd(ad + u,
                _mm256_sub_pd(_mm256_loadu_pd(ad + u), _mm256_loadu_pd(bd + u)));
        }
    }
    else {
        for (u = 0; u < n; u++) {
            a[u] = fpr_sub(a[u], b[u]);
        }
    }
}

/* a <- a * x (scalar fpr constant) over [0, n). */
FALCON_AVX2_TARGET
void falcon_poly_mulconst_avx2(fpr* a, fpr x, unsigned logn)
{
    double* ad = (double*)a;
    size_t n = (size_t)1 << logn, u;

    if (n >= 4) {
        __m256d vx = _mm256_set1_pd(falcon_avx2_d(x));
        for (u = 0; u < n; u += 4) {
            _mm256_storeu_pd(ad + u, _mm256_mul_pd(_mm256_loadu_pd(ad + u), vx));
        }
    }
    else {
        for (u = 0; u < n; u++) {
            a[u] = fpr_mul(a[u], x);
        }
    }
}

/* a <- a * adj(b): pointwise a * conj(b) over [0, hn). */
FALCON_AVX2_TARGET
void falcon_poly_muladj_fft_avx2(fpr* a, const fpr* b, unsigned logn)
{
    double* ad = (double*)a;
    const double* bd = (const double*)b;
    size_t n = (size_t)1 << logn, hn = n >> 1, u;

    if (hn >= 4) {
        for (u = 0; u < hn; u += 4) {
            __m256d ar = _mm256_loadu_pd(ad + u);
            __m256d ai = _mm256_loadu_pd(ad + u + hn);
            __m256d br = _mm256_loadu_pd(bd + u);
            __m256d bi = _mm256_loadu_pd(bd + u + hn);
            /* re = ar*br + ai*bi ; im = ai*br - ar*bi */
            __m256d re = _mm256_fmadd_pd(ar, br, _mm256_mul_pd(ai, bi));
            __m256d im = _mm256_fmsub_pd(ai, br, _mm256_mul_pd(ar, bi));
            _mm256_storeu_pd(ad + u,      re);
            _mm256_storeu_pd(ad + u + hn, im);
        }
    }
    else {
        for (u = 0; u < hn; u++) {
            fpr a_re = a[u], a_im = a[u + hn];
            fpr b_re = b[u], b_im = fpr_neg(b[u + hn]);
            FPC_MUL(a[u], a[u + hn], a_re, a_im, b_re, b_im);
        }
    }
}

/* a <- a * adj(a) = |a|^2 (real) over [0, hn); imag half set to zero. */
FALCON_AVX2_TARGET
void falcon_poly_mulselfadj_fft_avx2(fpr* a, unsigned logn)
{
    double* ad = (double*)a;
    size_t n = (size_t)1 << logn, hn = n >> 1, u;

    if (hn >= 4) {
        __m256d zero = _mm256_setzero_pd();
        for (u = 0; u < hn; u += 4) {
            __m256d ar = _mm256_loadu_pd(ad + u);
            __m256d ai = _mm256_loadu_pd(ad + u + hn);
            __m256d re = _mm256_fmadd_pd(ar, ar, _mm256_mul_pd(ai, ai));
            _mm256_storeu_pd(ad + u,      re);
            _mm256_storeu_pd(ad + u + hn, zero);
        }
    }
    else {
        for (u = 0; u < hn; u++) {
            fpr a_re = a[u], a_im = a[u + hn];
            a[u] = fpr_add(fpr_mul(a_re, a_re), fpr_mul(a_im, a_im));
            a[u + hn] = fpr_zero;
        }
    }
}

/* d <- 1 / (|a|^2 + |b|^2) (real) over [0, hn). */
FALCON_AVX2_TARGET
void falcon_poly_invnorm2_fft_avx2(fpr* d, const fpr* a, const fpr* b,
        unsigned logn)
{
    double* dd = (double*)d;
    const double* ad = (const double*)a;
    const double* bd = (const double*)b;
    size_t n = (size_t)1 << logn, hn = n >> 1, u;

    if (hn >= 4) {
        __m256d one = _mm256_set1_pd(1.0);
        for (u = 0; u < hn; u += 4) {
            __m256d ar = _mm256_loadu_pd(ad + u);
            __m256d ai = _mm256_loadu_pd(ad + u + hn);
            __m256d br = _mm256_loadu_pd(bd + u);
            __m256d bi = _mm256_loadu_pd(bd + u + hn);
            __m256d s = _mm256_fmadd_pd(ar, ar, _mm256_mul_pd(ai, ai));
            s = _mm256_fmadd_pd(br, br, s);
            s = _mm256_fmadd_pd(bi, bi, s);
            _mm256_storeu_pd(dd + u, _mm256_div_pd(one, s));
        }
    }
    else {
        for (u = 0; u < hn; u++) {
            fpr a_re = a[u], a_im = a[u + hn];
            fpr b_re = b[u], b_im = b[u + hn];
            d[u] = fpr_inv(fpr_add(
                fpr_add(fpr_mul(a_re, a_re), fpr_mul(a_im, a_im)),
                fpr_add(fpr_mul(b_re, b_re), fpr_mul(b_im, b_im))));
        }
    }
}

/* d <- F*adj(f) + G*adj(g) over [0, hn). */
FALCON_AVX2_TARGET
void falcon_poly_add_muladj_fft_avx2(fpr* d, const fpr* F, const fpr* G,
        const fpr* f, const fpr* g, unsigned logn)
{
    double* dd = (double*)d;
    const double* Fd = (const double*)F;
    const double* Gd = (const double*)G;
    const double* fd = (const double*)f;
    const double* gd = (const double*)g;
    size_t n = (size_t)1 << logn, hn = n >> 1, u;

    if (hn >= 4) {
        for (u = 0; u < hn; u += 4) {
            __m256d Fr = _mm256_loadu_pd(Fd + u), Fi = _mm256_loadu_pd(Fd + u + hn);
            __m256d Gr = _mm256_loadu_pd(Gd + u), Gi = _mm256_loadu_pd(Gd + u + hn);
            __m256d fr = _mm256_loadu_pd(fd + u), fi = _mm256_loadu_pd(fd + u + hn);
            __m256d gr = _mm256_loadu_pd(gd + u), gi = _mm256_loadu_pd(gd + u + hn);
            /* F*conj(f): re=Fr*fr+Fi*fi, im=Fi*fr-Fr*fi */
            __m256d are = _mm256_fmadd_pd(Fr, fr, _mm256_mul_pd(Fi, fi));
            __m256d aim = _mm256_fmsub_pd(Fi, fr, _mm256_mul_pd(Fr, fi));
            __m256d bre = _mm256_fmadd_pd(Gr, gr, _mm256_mul_pd(Gi, gi));
            __m256d bim = _mm256_fmsub_pd(Gi, gr, _mm256_mul_pd(Gr, gi));
            _mm256_storeu_pd(dd + u,      _mm256_add_pd(are, bre));
            _mm256_storeu_pd(dd + u + hn, _mm256_add_pd(aim, bim));
        }
    }
    else {
        for (u = 0; u < hn; u++) {
            fpr F_re = F[u], F_im = F[u + hn];
            fpr G_re = G[u], G_im = G[u + hn];
            fpr f_re = f[u], f_im = f[u + hn];
            fpr g_re = g[u], g_im = g[u + hn];
            fpr a_re, a_im, b_re, b_im;
            FPC_MUL(a_re, a_im, F_re, F_im, f_re, fpr_neg(f_im));
            FPC_MUL(b_re, b_im, G_re, G_im, g_re, fpr_neg(g_im));
            d[u] = fpr_add(a_re, b_re);
            d[u + hn] = fpr_add(a_im, b_im);
        }
    }
}

/* LDL of the 2x2 Hermitian Gram matrix, results to d11/l10 (inputs untouched).
 *   mu = g01 / g00 ; d11 = g11 - mu*adj(g01) ; l10 = adj(mu) */
FALCON_AVX2_TARGET
void falcon_poly_LDLmv_fft_avx2(fpr* d11, fpr* l10, const fpr* g00,
        const fpr* g01, const fpr* g11, unsigned logn)
{
    double* d11d = (double*)d11;
    double* l10d = (double*)l10;
    const double* g00d = (const double*)g00;
    const double* g01d = (const double*)g01;
    const double* g11d = (const double*)g11;
    size_t n = (size_t)1 << logn, hn = n >> 1, u;

    if (hn >= 4) {
        __m256d one = _mm256_set1_pd(1.0);
        __m256d neg = _mm256_set1_pd(-0.0);
        for (u = 0; u < hn; u += 4) {
            __m256d ar = _mm256_loadu_pd(g01d + u),  ai = _mm256_loadu_pd(g01d + u + hn);
            __m256d br = _mm256_loadu_pd(g00d + u),  bi = _mm256_loadu_pd(g00d + u + hn);
            __m256d c11r = _mm256_loadu_pd(g11d + u), c11i = _mm256_loadu_pd(g11d + u + hn);
            /* mu = g01 / g00 */
            __m256d den = _mm256_fmadd_pd(br, br, _mm256_mul_pd(bi, bi));
            __m256d m = _mm256_div_pd(one, den);
            __m256d mur = _mm256_mul_pd(_mm256_fmadd_pd(ar, br, _mm256_mul_pd(ai, bi)), m);
            __m256d mui = _mm256_mul_pd(_mm256_fmsub_pd(ai, br, _mm256_mul_pd(ar, bi)), m);
            /* xx = mu * adj(g01) : adj(g01) = (ar, -ai)
             *   re = mur*ar + mui*ai ; im = mui*ar - mur*ai */
            __m256d xxr = _mm256_fmadd_pd(mur, ar, _mm256_mul_pd(mui, ai));
            __m256d xxi = _mm256_fmsub_pd(mui, ar, _mm256_mul_pd(mur, ai));
            _mm256_storeu_pd(d11d + u,      _mm256_sub_pd(c11r, xxr));
            _mm256_storeu_pd(d11d + u + hn, _mm256_sub_pd(c11i, xxi));
            _mm256_storeu_pd(l10d + u,      mur);
            _mm256_storeu_pd(l10d + u + hn, _mm256_xor_pd(mui, neg)); /* -mu_im */
        }
    }
    else {
        for (u = 0; u < hn; u++) {
            fpr g00_re = g00[u], g00_im = g00[u + hn];
            fpr g01_re = g01[u], g01_im = g01[u + hn];
            fpr g11_re = g11[u], g11_im = g11[u + hn];
            fpr mu_re, mu_im, xx_re, xx_im, m;
            m = fpr_inv(fpr_add(fpr_mul(g00_re, g00_re), fpr_mul(g00_im, g00_im)));
            mu_re = fpr_mul(fpr_add(fpr_mul(g01_re, g00_re),
                fpr_mul(g01_im, g00_im)), m);
            mu_im = fpr_mul(fpr_sub(fpr_mul(g01_im, g00_re),
                fpr_mul(g01_re, g00_im)), m);
            FPC_MUL(xx_re, xx_im, mu_re, mu_im, g01_re, fpr_neg(g01_im));
            d11[u] = fpr_sub(g11_re, xx_re);
            d11[u + hn] = fpr_sub(g11_im, xx_im);
            l10[u] = mu_re;
            l10[u + hn] = fpr_neg(mu_im);
        }
    }
}

/* Deinterleave two contiguous vectors v0=[x0..x3], v1=[x4..x7] into
 * evens=[x0,x2,x4,x6] and odds=[x1,x3,x5,x7]. */
FALCON_AVX2_TARGET
static WC_INLINE void falcon_deint(__m256d v0, __m256d v1,
        __m256d* evens, __m256d* odds)
{
    __m256d lo = _mm256_unpacklo_pd(v0, v1); /* [x0,x4,x2,x6] */
    __m256d hi = _mm256_unpackhi_pd(v0, v1); /* [x1,x5,x3,x7] */
    *evens = _mm256_permute4x64_pd(lo, _MM_SHUFFLE(3, 1, 2, 0));
    *odds  = _mm256_permute4x64_pd(hi, _MM_SHUFFLE(3, 1, 2, 0));
}

/* Interleave evens=[x0,x2,x4,x6], odds=[x1,x3,x5,x7] back into
 * v0=[x0,x1,x2,x3], v1=[x4,x5,x6,x7]. */
FALCON_AVX2_TARGET
static WC_INLINE void falcon_int(__m256d evens, __m256d odds,
        __m256d* v0, __m256d* v1)
{
    __m256d e = _mm256_permute4x64_pd(evens, _MM_SHUFFLE(3, 1, 2, 0));
    __m256d o = _mm256_permute4x64_pd(odds,  _MM_SHUFFLE(3, 1, 2, 0));
    *v0 = _mm256_unpacklo_pd(e, o);
    *v1 = _mm256_unpackhi_pd(e, o);
}

/* Split f (degree n) into half-degree f0, f1 in FFT representation. */
FALCON_AVX2_TARGET
void falcon_poly_split_fft_avx2(fpr* f0, fpr* f1, const fpr* f, unsigned logn)
{
    size_t n = (size_t)1 << logn, hn = n >> 1, qn = hn >> 1, u;
    const double* fd = (const double*)f;
    double* f0d = (double*)f0;
    double* f1d = (double*)f1;
    const double* gm = (const double*)falcon_gm_tab;

    f0[0] = f[0];
    f1[0] = f[hn];
    if (qn >= 4) {
        __m256d half = _mm256_set1_pd(0.5);
        for (u = 0; u < qn; u += 4) {
            __m256d ar, ai, br, bi, gcos, gsin, tr, ti, sr, si, xr, xi;
            /* deinterleave real parts: f[2u..2u+7] -> a_re(even), b_re(odd) */
            falcon_deint(_mm256_loadu_pd(fd + 2*u),
                        _mm256_loadu_pd(fd + 2*u + 4), &ar, &br);
            falcon_deint(_mm256_loadu_pd(fd + 2*u + hn),
                        _mm256_loadu_pd(fd + 2*u + hn + 4), &ai, &bi);
            /* twiddles gm[2*(hn+u) ..] -> cos(even), sin(odd) */
            falcon_deint(_mm256_loadu_pd(gm + 2*(hn + u)),
                        _mm256_loadu_pd(gm + 2*(hn + u) + 4), &gcos, &gsin);
            /* f0 = half(a + b) */
            _mm256_storeu_pd(f0d + u,      _mm256_mul_pd(_mm256_add_pd(ar, br), half));
            _mm256_storeu_pd(f0d + u + qn, _mm256_mul_pd(_mm256_add_pd(ai, bi), half));
            /* t = a - b ; s = t * conj(gm) ; f1 = half(s) */
            tr = _mm256_sub_pd(ar, br);
            ti = _mm256_sub_pd(ai, bi);
            /* conj: (gcos, -gsin): sr=tr*gcos+ti*gsin, si=ti*gcos-tr*gsin */
            sr = _mm256_fmadd_pd(tr, gcos, _mm256_mul_pd(ti, gsin));
            si = _mm256_fmsub_pd(ti, gcos, _mm256_mul_pd(tr, gsin));
            xr = _mm256_mul_pd(sr, half);
            xi = _mm256_mul_pd(si, half);
            _mm256_storeu_pd(f1d + u,      xr);
            _mm256_storeu_pd(f1d + u + qn, xi);
        }
    }
    else {
        for (u = 0; u < qn; u++) {
            fpr a_re = f[(u << 1) + 0], a_im = f[(u << 1) + 0 + hn];
            fpr b_re = f[(u << 1) + 1], b_im = f[(u << 1) + 1 + hn];
            fpr t_re, t_im;
            FPC_ADD(t_re, t_im, a_re, a_im, b_re, b_im);
            f0[u] = fpr_half(t_re);
            f0[u + qn] = fpr_half(t_im);
            FPC_SUB(t_re, t_im, a_re, a_im, b_re, b_im);
            FPC_MUL(t_re, t_im, t_re, t_im,
                falcon_gm_tab[((u + hn) << 1) + 0],
                fpr_neg(falcon_gm_tab[((u + hn) << 1) + 1]));
            f1[u] = fpr_half(t_re);
            f1[u + qn] = fpr_half(t_im);
        }
    }
}

/* Merge f0, f1 (degree n/2) into f (degree n) in FFT representation. */
FALCON_AVX2_TARGET
void falcon_poly_merge_fft_avx2(fpr* f, const fpr* f0, const fpr* f1,
        unsigned logn)
{
    size_t n = (size_t)1 << logn, hn = n >> 1, qn = hn >> 1, u;
    double* fd = (double*)f;
    const double* f0d = (const double*)f0;
    const double* f1d = (const double*)f1;
    const double* gm = (const double*)falcon_gm_tab;

    f[0] = f0[0];
    f[hn] = f1[0];
    if (qn >= 4) {
        for (u = 0; u < qn; u += 4) {
            __m256d ar, ai, c1r, c1i, gcos, gsin, br, bi, tr, ti, v0, v1;
            ar = _mm256_loadu_pd(f0d + u);
            ai = _mm256_loadu_pd(f0d + u + qn);
            c1r = _mm256_loadu_pd(f1d + u);
            c1i = _mm256_loadu_pd(f1d + u + qn);
            falcon_deint(_mm256_loadu_pd(gm + 2*(hn + u)),
                        _mm256_loadu_pd(gm + 2*(hn + u) + 4), &gcos, &gsin);
            /* b = f1 * gm : br=c1r*gcos-c1i*gsin, bi=c1r*gsin+c1i*gcos */
            br = _mm256_fmsub_pd(c1r, gcos, _mm256_mul_pd(c1i, gsin));
            bi = _mm256_fmadd_pd(c1r, gsin, _mm256_mul_pd(c1i, gcos));
            /* even (index 2u) = a + b ; odd (index 2u+1) = a - b */
            tr = _mm256_add_pd(ar, br);   /* even real */
            ti = _mm256_sub_pd(ar, br);   /* odd real  */
            falcon_int(tr, ti, &v0, &v1);
            _mm256_storeu_pd(fd + 2*u,     v0);
            _mm256_storeu_pd(fd + 2*u + 4, v1);
            tr = _mm256_add_pd(ai, bi);   /* even imag */
            ti = _mm256_sub_pd(ai, bi);   /* odd imag  */
            falcon_int(tr, ti, &v0, &v1);
            _mm256_storeu_pd(fd + 2*u + hn,     v0);
            _mm256_storeu_pd(fd + 2*u + hn + 4, v1);
        }
    }
    else {
        for (u = 0; u < qn; u++) {
            fpr a_re = f0[u], a_im = f0[u + qn];
            fpr b_re, b_im, t_re, t_im;
            FPC_MUL(b_re, b_im, f1[u], f1[u + qn],
                falcon_gm_tab[((u + hn) << 1) + 0],
                falcon_gm_tab[((u + hn) << 1) + 1]);
            FPC_ADD(t_re, t_im, a_re, a_im, b_re, b_im);
            f[(u << 1) + 0] = t_re;
            f[(u << 1) + 0 + hn] = t_im;
            FPC_SUB(t_re, t_im, a_re, a_im, b_re, b_im);
            f[(u << 1) + 1] = t_re;
            f[(u << 1) + 1 + hn] = t_im;
        }
    }
}

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY &&
        * WOLFSSL_FALCON_FFT_AVX2 */

/* ==== AArch64 NEON (float64x2_t + FMA) FFT backend, folded from the former
   wc_falcon_fft_neon.c. AdvSIMD is AArch64 baseline, so no per-file
   CFLAGS are needed. ==== */
/* AArch64 NEON (float64x2_t + FMA) FFT backend for the native Falcon
 * signing path. This is the 2-wide-double counterpart of the AVX2 backend
 * above: it processes two doubles per 128-bit vector and uses
 * fused multiply-add for the complex butterflies. The algorithm and the
 * twiddle-table (falcon_gm_tab) layout are unchanged from the scalar backend
 * (wc_falcon_fft.c); only the butterfly inner loops are widened.
 *
 * On ARMv8-A, Advanced SIMD (including float64x2_t) is part of the baseline, so
 * no per-function target attribute is required. NEON double is only available
 * on AArch64, so this backend is gated on __aarch64__.
 *
 * CORRECTNESS NOTE: like the AVX2 backend, this does NOT promise bit-identical
 * (no-FMA) results versus the scalar fpr path -- FMA fuses the multiply-add with
 * a single rounding, so the FFT output differs in the last ULPs. This is safe:
 * the signing FFT only needs to produce a short vector that passes the norm
 * bound and verifies. The Gaussian sampler's determinism depends only on the
 * scalar fpr_* ops (unchanged), and verification is integer-only.
 */


#if defined(HAVE_FALCON) && !defined(WOLF_CRYPTO_CB_ONLY_FALCON) && \
    !defined(WOLFSSL_FALCON_VERIFY_ONLY) && \
    defined(WOLFSSL_FALCON_FFT_NEON) && defined(__aarch64__)


#include <arm_neon.h>

/* Reinterpret an fpr (word64 bit pattern) as a double without aliasing UB. */
static WC_INLINE double falcon_neon_d(fpr x)
{
    double d;
    XMEMCPY(&d, &x, sizeof(d));
    return d;
}

/* Scalar (inline-double) complex helpers for the small-stride tail level
 * (ht == 1), matching the scalar backend exactly. Undef before redefining, as
 * in the AVX2 block above. */
#undef FPC_MUL
#undef FPC_ADD
#undef FPC_SUB
#define FPC_MUL(d_re, d_im, a_re, a_im, b_re, b_im) do { \
        fpr _ar = (a_re), _ai = (a_im), _br = (b_re), _bi = (b_im); \
        (d_re) = fpr_sub(fpr_mul(_ar, _br), fpr_mul(_ai, _bi)); \
        (d_im) = fpr_add(fpr_mul(_ar, _bi), fpr_mul(_ai, _br)); \
    } while (0)
#define FPC_ADD(d_re, d_im, a_re, a_im, b_re, b_im) do { \
        (d_re) = fpr_add((a_re), (b_re)); \
        (d_im) = fpr_add((a_im), (b_im)); \
    } while (0)
#define FPC_SUB(d_re, d_im, a_re, a_im, b_re, b_im) do { \
        (d_re) = fpr_sub((a_re), (b_re)); \
        (d_im) = fpr_sub((a_im), (b_im)); \
    } while (0)

/* Vector complex multiply: (yr + i yi) <- (yr + i yi) * (sr + i si).
 * re = yr*sr - yi*si, im = yr*si + yi*sr. vfmsq(a,b,c)=a-b*c, vfmaq(a,b,c)=a+b*c. */
#define FALCON_VCMUL(out_re, out_im, yr, yi, sr, si) do { \
        (out_re) = vfmsq_f64(vmulq_f64((yr), (sr)), (yi), (si)); \
        (out_im) = vfmaq_f64(vmulq_f64((yr), (si)), (yi), (sr)); \
    } while (0)

/* Aliasing-safe vector load/store.  fpr is a word64 IEEE-754 bit pattern, so
 * the backing store's real object type is the 64-bit integer, not double.
 * Load/store through uint64_t (the actual type) and reinterpret the vector
 * register to/from f64 -- casting fpr* to double* and using vld1q_f64/vst1q_f64
 * would be a strict-aliasing violation that can miscompile at -O2/-O3. */
#define FALCON_VLD(pf) \
    vreinterpretq_f64_u64(vld1q_u64((const uint64_t*)(const void*)(pf)))
#define FALCON_VST(pf, v) \
    vst1q_u64((uint64_t*)(void*)(pf), vreinterpretq_u64_f64(v))

/* ------------------------------------------------------------------------- */
/* Forward FFT                                                               */
/* ------------------------------------------------------------------------- */

void falcon_FFT(fpr* f, unsigned logn)
{
    unsigned u;
    size_t t, n, hn, m;

    n = (size_t)1 << logn;
    hn = n >> 1;
    t = hn;
    for (u = 1, m = 2; u < logn; u++, m <<= 1) {
        size_t ht = t >> 1, hm = m >> 1, i1, j1;
        for (i1 = 0, j1 = 0; i1 < hm; i1++, j1 += t) {
            size_t j, j2 = j1 + ht;
            fpr s_re = falcon_gm_tab[((m + i1) << 1) + 0];
            fpr s_im = falcon_gm_tab[((m + i1) << 1) + 1];
            if (ht >= 2) {
                float64x2_t vsr = vdupq_n_f64(falcon_neon_d(s_re));
                float64x2_t vsi = vdupq_n_f64(falcon_neon_d(s_im));
                for (j = j1; j < j2; j += 2) {
                    float64x2_t xr = FALCON_VLD(f + j);
                    float64x2_t xi = FALCON_VLD(f + j + hn);
                    float64x2_t yr = FALCON_VLD(f + j + ht);
                    float64x2_t yi = FALCON_VLD(f + j + ht + hn);
                    float64x2_t tr, ti;
                    FALCON_VCMUL(tr, ti, yr, yi, vsr, vsi);
                    FALCON_VST(f + j, vaddq_f64(xr, tr));
                    FALCON_VST(f + j + hn, vaddq_f64(xi, ti));
                    FALCON_VST(f + j + ht, vsubq_f64(xr, tr));
                    FALCON_VST(f + j + ht + hn, vsubq_f64(xi, ti));
                }
            }
            else {
                /* small-stride tail (ht == 1): scalar inline-double */
                for (j = j1; j < j2; j++) {
                    fpr x_re = f[j], x_im = f[j + hn];
                    fpr y_re = f[j + ht], y_im = f[j + ht + hn];
                    FPC_MUL(y_re, y_im, y_re, y_im, s_re, s_im);
                    FPC_ADD(f[j], f[j + hn], x_re, x_im, y_re, y_im);
                    FPC_SUB(f[j + ht], f[j + ht + hn], x_re, x_im, y_re, y_im);
                }
            }
        }
        t = ht;
    }
}

/* ------------------------------------------------------------------------- */
/* Inverse FFT                                                               */
/* ------------------------------------------------------------------------- */

void falcon_iFFT(fpr* f, unsigned logn)
{
    int u;
    size_t n = (size_t)1 << logn, hn = n >> 1;

    for (u = (int)logn - 1; u >= 1; u--) {
        size_t m = (size_t)1 << u, hm = m >> 1;
        size_t t = hn >> u;             /* butterfly stride */
        size_t i1, j1;
        for (i1 = 0, j1 = 0; i1 < hm; i1++, j1 += (t << 1)) {
            size_t j, j2 = j1 + t;
            fpr s_re = falcon_gm_tab[((m + i1) << 1) + 0];
            fpr s_im = fpr_neg(falcon_gm_tab[((m + i1) << 1) + 1]);
            if (t >= 2) {
                float64x2_t vsr = vdupq_n_f64(falcon_neon_d(s_re));
                float64x2_t vsi = vdupq_n_f64(falcon_neon_d(s_im));
                for (j = j1; j < j2; j += 2) {
                    float64x2_t ar = FALCON_VLD(f + j);
                    float64x2_t ai = FALCON_VLD(f + j + hn);
                    float64x2_t br = FALCON_VLD(f + j + t);
                    float64x2_t bi = FALCON_VLD(f + j + t + hn);
                    float64x2_t dr = vsubq_f64(ar, br);
                    float64x2_t di = vsubq_f64(ai, bi);
                    float64x2_t pr, pi;
                    FALCON_VST(f + j, vaddq_f64(ar, br));
                    FALCON_VST(f + j + hn, vaddq_f64(ai, bi));
                    FALCON_VCMUL(pr, pi, dr, di, vsr, vsi);
                    FALCON_VST(f + j + t, pr);
                    FALCON_VST(f + j + t + hn, pi);
                }
            }
            else {
                for (j = j1; j < j2; j++) {
                    fpr a_re = f[j], a_im = f[j + hn];
                    fpr b_re = f[j + t], b_im = f[j + t + hn];
                    fpr d_re, d_im;
                    FPC_ADD(f[j], f[j + hn], a_re, a_im, b_re, b_im);
                    FPC_SUB(d_re, d_im, a_re, a_im, b_re, b_im);
                    FPC_MUL(f[j + t], f[j + t + hn], d_re, d_im, s_re, s_im);
                }
            }
        }
    }
    /* final scale by 1 / 2^(logn-1) */
    {
        fpr ni = fpr_inv(fpr_of((sword64)hn));
        if (n >= 2) {
            float64x2_t vni = vdupq_n_f64(falcon_neon_d(ni));
            size_t j;
            for (j = 0; j < n; j += 2) {
                FALCON_VST(f + j, vmulq_f64(FALCON_VLD(f + j), vni));
            }
        }
        else {
            f[0] = fpr_mul(f[0], ni);
        }
    }
}

#endif /* HAVE_FALCON && !WOLF_CRYPTO_CB_ONLY_FALCON &&
        * !WOLFSSL_FALCON_VERIFY_ONLY && WOLFSSL_FALCON_FFT_NEON && __aarch64__ */

#endif /* HAVE_FALCON */
