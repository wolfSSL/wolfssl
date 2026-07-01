/* wc_falcon_poly.c
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

/* Falcon FFT-domain polynomial operations over the fpr seam. Faithful
 * port of the poly_* functions from the MIT-licensed Falcon reference (fft.c,
 * Thomas Pornin). See wolfssl/wolfcrypt/wc_falcon_poly.h. */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(HAVE_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY) && !defined(WOLF_CRYPTO_CB_ONLY_FALCON)

#include <wolfssl/wolfcrypt/wc_falcon_poly.h>
#include <wolfssl/wolfcrypt/wc_falcon_fft.h>   /* falcon_gm_tab */

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

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY */
