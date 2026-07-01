/* wc_falcon_fft_neon.c
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

/* AArch64 NEON (float64x2_t + FMA) FFT backend for the native Falcon
 * signing path. This is the 2-wide-double counterpart of the AVX2 backend in
 * wc_falcon_fft_avx2.c: it processes two doubles per 128-bit vector and uses
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(HAVE_FALCON) && !defined(WOLF_CRYPTO_CB_ONLY_FALCON) && \
    !defined(WOLFSSL_FALCON_VERIFY_ONLY) && \
    defined(WOLFSSL_FALCON_FFT_NEON) && defined(__aarch64__)

#include <wolfssl/wolfcrypt/wc_falcon_fft.h>

#include <arm_neon.h>

/* Reinterpret an fpr (word64 bit pattern) as a double without aliasing UB. */
static WC_INLINE double falcon_neon_d(fpr x)
{
    double d;
    XMEMCPY(&d, &x, sizeof(d));
    return d;
}

/* Scalar (inline-double) complex helpers for the small-stride tail level
 * (ht == 1), matching the scalar backend exactly. */
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

/* ------------------------------------------------------------------------- */
/* Forward FFT                                                               */
/* ------------------------------------------------------------------------- */

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
            if (ht >= 2) {
                float64x2_t vsr = vdupq_n_f64(falcon_neon_d(s_re));
                float64x2_t vsi = vdupq_n_f64(falcon_neon_d(s_im));
                for (j = j1; j < j2; j += 2) {
                    float64x2_t xr = vld1q_f64(fd + j);
                    float64x2_t xi = vld1q_f64(fd + j + hn);
                    float64x2_t yr = vld1q_f64(fd + j + ht);
                    float64x2_t yi = vld1q_f64(fd + j + ht + hn);
                    float64x2_t tr, ti;
                    FALCON_VCMUL(tr, ti, yr, yi, vsr, vsi);
                    vst1q_f64(fd + j,           vaddq_f64(xr, tr));
                    vst1q_f64(fd + j + hn,      vaddq_f64(xi, ti));
                    vst1q_f64(fd + j + ht,      vsubq_f64(xr, tr));
                    vst1q_f64(fd + j + ht + hn, vsubq_f64(xi, ti));
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
            if (t >= 2) {
                float64x2_t vsr = vdupq_n_f64(falcon_neon_d(s_re));
                float64x2_t vsi = vdupq_n_f64(falcon_neon_d(s_im));
                for (j = j1; j < j2; j += 2) {
                    float64x2_t ar = vld1q_f64(fd + j);
                    float64x2_t ai = vld1q_f64(fd + j + hn);
                    float64x2_t br = vld1q_f64(fd + j + t);
                    float64x2_t bi = vld1q_f64(fd + j + t + hn);
                    float64x2_t dr = vsubq_f64(ar, br);
                    float64x2_t di = vsubq_f64(ai, bi);
                    float64x2_t pr, pi;
                    vst1q_f64(fd + j,      vaddq_f64(ar, br));
                    vst1q_f64(fd + j + hn, vaddq_f64(ai, bi));
                    FALCON_VCMUL(pr, pi, dr, di, vsr, vsi);
                    vst1q_f64(fd + j + t,      pr);
                    vst1q_f64(fd + j + t + hn, pi);
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
                vst1q_f64(fd + j, vmulq_f64(vld1q_f64(fd + j), vni));
            }
        }
        else {
            f[0] = fpr_mul(f[0], ni);
        }
    }
}

#endif /* HAVE_FALCON && !WOLF_CRYPTO_CB_ONLY_FALCON &&
        * !WOLFSSL_FALCON_VERIFY_ONLY && WOLFSSL_FALCON_FFT_NEON && __aarch64__ */
