/* wc_falcon_fft.h
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
    \file wolfssl/wolfcrypt/wc_falcon_fft.h
*/

/* FN-DSA / Falcon FFT over the fpr seam. A real polynomial of n coefficients is
 * carried as n fpr values: the n/2 complex evaluations at the roots of x^n+1,
 * real parts in [0, n/2), imaginary parts in [n/2, n). Used by the Gaussian
 * sampler and signing; not needed for verification. */

#ifndef WOLF_CRYPT_WC_FALCON_FFT_H
#define WOLF_CRYPT_WC_FALCON_FFT_H

#include <wolfssl/wolfcrypt/types.h>

#if defined(HAVE_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY)

#include <wolfssl/wolfcrypt/wc_falcon_fpr.h>

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
