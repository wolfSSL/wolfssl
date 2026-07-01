/* wc_falcon_poly.h
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
    \file wolfssl/wolfcrypt/wc_falcon_poly.h
*/

/* FN-DSA / Falcon FFT-domain polynomial operations over the fpr seam. A real
 * polynomial of n coefficients is carried as n fpr values: the n/2 complex
 * evaluations at the roots of x^n+1, real parts in [0, n/2), imaginary parts in
 * [n/2, n) (see wc_falcon_fft.h). These primitives feed ffSampling and signing;
 * they are a faithful port of the poly_* functions from the MIT-licensed Falcon
 * reference implementation (fft.c, by Thomas Pornin). Not needed for
 * verification. */

#ifndef WOLF_CRYPT_WC_FALCON_POLY_H
#define WOLF_CRYPT_WC_FALCON_POLY_H

#include <wolfssl/wolfcrypt/types.h>

#if defined(HAVE_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY)

#include <wolfssl/wolfcrypt/wc_falcon_fpr.h>

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
/* AVX2 (__m256d + FMA) variants of the hot pointwise ops, provided by
 * wc_falcon_fft_avx2.c. The generic functions above delegate to these when the
 * AVX2 backend is selected. Semantically identical to their scalar twins
 * (FMA rounding differences are acceptable on the signing FFT path). */
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
