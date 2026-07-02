/* wc_falcon_fft_avx2.c
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

/* AVX2 (__m256d + FMA) FFT backend for the native Falcon signing path.
 *
 * This is a vectorization of the scalar FFT in wc_falcon_fft.c and the hot
 * FFT-domain pointwise polynomial operations in wc_falcon_poly.c. It processes
 * 4 doubles per 256-bit vector and uses fused multiply-add for the complex
 * butterflies. The algorithm and twiddle-table (falcon_gm_tab) layout are
 * unchanged from the scalar backend; only the butterfly inner loops (and the
 * pointwise poly ops) are widened.
 *
 * Representation (see wc_falcon_fft.h): a degree-n real polynomial is carried as
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(HAVE_FALCON) && !defined(WOLF_CRYPTO_CB_ONLY_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY) && \
    defined(WOLFSSL_FALCON_FFT_AVX2)

#include <wolfssl/wolfcrypt/wc_falcon_fft.h>
#include <wolfssl/wolfcrypt/wc_falcon_poly.h>

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
 * where SIMD would not pay off. */
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
