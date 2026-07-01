/* wc_falcon_sign.c
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

/* Falcon signing orchestration. See wolfssl/wolfcrypt/wc_falcon_sign.h.
 *
 * Faithful port of the signature-generation core of the MIT-licensed Falcon
 * reference implementation sign.c (Thomas Pornin, Falcon Project, 2017-2019):
 * expand_privkey (B0 basis in FFT + ffLDL tree), ffSampling_fft and
 * do_sign_tree. The big-integer NTRU completion of G (complete_private) is done
 * here over the FFT seam. All floating-point work flows through the abstract
 * fpr_* seam (wc_falcon_fpr / fft / poly); the discrete Gaussian sampler and its
 * SHAKE256-backed randomness come from wc_falcon_sampler. */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(HAVE_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY) && !defined(WOLF_CRYPTO_CB_ONLY_FALCON)

#include <wolfssl/wolfcrypt/wc_falcon_sign.h>
#include <wolfssl/wolfcrypt/wc_falcon_fpr.h>
#include <wolfssl/wolfcrypt/wc_falcon_fft.h>
#include <wolfssl/wolfcrypt/wc_falcon_poly.h>
#include <wolfssl/wolfcrypt/wc_falcon_sampler.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

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

/* IEEE-754 binary64 bit patterns (the fpr seam carries doubles as word64).
 * These mirror named constants from the reference fpr.h that are not part of
 * the public wc_falcon_fpr.h API. fpr_invsqrt2 / fpr_invsqrt8 ARE exported by
 * the seam and are used directly. */
static const fpr fpr_q             = 4667981563525332992ULL; /* (double)12289   */
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

/* Size of the ffLDL tree (number of fpr elements) for polynomials of degree
 * 2^logn:  s(0) = 1,  s(logn) = 2^logn + 2*s(logn-1)  =>  (logn+1)*2^logn. */
static WC_INLINE unsigned ffLDL_treesize(unsigned logn)
{
    return (logn + 1) << logn;
}

/* Inner ffLDL recursion. Expects the (auto-adjoint, quasicyclic) matrix in
 * (g0, g1), which are used as modifiable temporaries. tmp[] needs room for at
 * least one polynomial. */
static void ffLDL_fft_inner(fpr* tree, fpr* g0, fpr* g1, unsigned logn,
        fpr* tmp)
{
    size_t n, hn;

    n = MKN(logn);
    if (n == 1) {
        tree[0] = g0[0];
        return;
    }
    hn = n >> 1;

    /* d00 = g0; d11 -> tmp; L[1][0] -> tree. */
    falcon_poly_LDLmv_fft(tmp, tree, g0, g1, g0, logn);

    /* Split d00 (in g0) and d11 (in tmp), reusing g0/g1 as scratch:
     *   d00 -> g1, g1+hn ; d11 -> g0, g0+hn. */
    falcon_poly_split_fft(g1, g1 + hn, g0, logn);
    falcon_poly_split_fft(g0, g0 + hn, tmp, logn);

    ffLDL_fft_inner(tree + n, g1, g1 + hn, logn - 1, tmp);
    ffLDL_fft_inner(tree + n + ffLDL_treesize(logn - 1),
            g0, g0 + hn, logn - 1, tmp);
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
 * sampler. */
static void ffLDL_binary_normalize(fpr* tree, unsigned orig_logn, unsigned logn)
{
    size_t n;

    n = MKN(logn);
    if (n == 1) {
        tree[0] = fpr_mul(fpr_sqrt(tree[0]), fpr_inv_sigma[orig_logn]);
    }
    else {
        ffLDL_binary_normalize(tree + n, orig_logn, logn - 1);
        ffLDL_binary_normalize(tree + n + ffLDL_treesize(logn - 1),
                orig_logn, logn - 1);
    }
}

/* Convert a small-integer polynomial into the fpr representation. */
static void smallints_to_fpr(fpr* r, const sword8* t, unsigned logn)
{
    size_t n, u;

    n = MKN(logn);
    for (u = 0; u < n; u++) {
        r[u] = fpr_of(t[u]);
    }
}

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

void falcon_ffSampling_fft(falcon_samplerZ samp, void* samp_ctx,
        fpr* z0, fpr* z1, const fpr* tree, const fpr* t0, const fpr* t1,
        unsigned logn, fpr* tmp)
{
    size_t n, hn;
    const fpr* tree0;
    const fpr* tree1;

    /* logn == 2: inline the last two recursion levels. */
    if (logn == 2) {
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

        return;
    }

    /* logn == 1: reachable only for the (insecure) smallest degree. */
    if (logn == 1) {
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

        return;
    }

    /* General recursive case (logn >= 3). */
    n = (size_t)1 << logn;
    hn = n >> 1;
    tree0 = tree + n;
    tree1 = tree + n + ffLDL_treesize(logn - 1);

    /* Split t1, recurse (output in tmp), merge back into z1. */
    falcon_poly_split_fft(z1, z1 + hn, t1, logn);
    falcon_ffSampling_fft(samp, samp_ctx, tmp, tmp + hn,
            tree1, z1, z1 + hn, logn - 1, tmp + n);
    falcon_poly_merge_fft(z1, tmp, tmp + hn, logn);

    /* tb0 = t0 + (t1 - z1) * L, ending up in tmp[]. */
    XMEMCPY(tmp, t1, n * sizeof(*t1));
    falcon_poly_sub(tmp, z1, logn);
    falcon_poly_mul_fft(tmp, tree, logn);
    falcon_poly_add(tmp, t0, logn);

    /* Second recursion. */
    falcon_poly_split_fft(z0, z0 + hn, tmp, logn);
    falcon_ffSampling_fft(samp, samp_ctx, tmp, tmp + hn,
            tree0, z0, z0 + hn, logn - 1, tmp + n);
    falcon_poly_merge_fft(z0, tmp, tmp + hn, logn);
}

/* ==================================================================== */
/* do_sign_tree / sign_core.                                             */

/* is_short_half: squared l2-norm of (s1, s2) where the s1 partial sum (sqn) is
 * already accumulated and saturates to 2^32-1. Returns 1 if within bound. */
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
            /* Optional instrumentation for test harnesses: counts the rare
             * ffSampling restarts. Not compiled into production builds. */
            extern unsigned long falcon_sign_restart_count;
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

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY */
