/* wc_falcon_sign.h
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
    \file wolfssl/wolfcrypt/wc_falcon_sign.h
*/

/* Falcon signing orchestration (the "tree" signer).
 *
 * Faithful port of the signature-generation core of the MIT-licensed Falcon
 * reference implementation sign.c (Thomas Pornin, Falcon Project, 2017-2019):
 *
 *   - falcon_complete_private: recompute G from (f, g, F) using the NTRU
 *     relation f*G - g*F = q (so G = (g*F + q)/f), via the FFT seam.
 *   - falcon_expand_privkey: build the B0 = [[g, -f], [G, -F]] basis in FFT
 *     representation, the Gram matrix G = B*B^*, and the normalized ffLDL
 *     tree (the "expanded private key").
 *   - falcon_ffSampling_fft: the Fast Fourier sampling recursion driving the
 *     discrete Gaussian sampler over the ffLDL tree.
 *   - falcon_do_sign_tree / falcon_sign_core: produce the signature short
 *     vector s2, looping over the sampler until the (s1, s2) squared l2-norm
 *     is within the Falcon acceptance bound.
 *
 * The floating-point work flows exclusively through the abstract fpr_* seam
 * (wc_falcon_fpr.h), the FFT (wc_falcon_fft.h) and the FFT-domain polynomial
 * primitives (wc_falcon_poly.h); randomness for the sampler comes from the
 * SHAKE256-backed sampler context (wc_falcon_sampler.h). This module is
 * compiled only on the signing side. */

#ifndef WOLF_CRYPT_WC_FALCON_SIGN_H
#define WOLF_CRYPT_WC_FALCON_SIGN_H

#include <wolfssl/wolfcrypt/types.h>

#if defined(HAVE_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY)

#include <wolfssl/wolfcrypt/wc_falcon_fpr.h>
#include <wolfssl/wolfcrypt/wc_falcon_sampler.h>

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
WOLFSSL_LOCAL int falcon_complete_private(sword8* G, const sword8* f,
        const sword8* g, const sword8* F, unsigned logn);

/* Expand the private basis (f, g, F, G) into 'expanded' (which must hold
 * FALCON_EXPANDED_KEY_FPR(logn) fpr elements): the B0 matrix in FFT
 * representation and the normalized ffLDL tree. Allocates an internal scratch
 * of FALCON_SIGN_TMP_FPR(logn) fpr. Returns 0 on success or a negative
 * wolfCrypt error. */
WOLFSSL_LOCAL int falcon_expand_privkey(fpr* expanded, const sword8* f,
        const sword8* g, const sword8* F, const sword8* G, unsigned logn);

/* Fast Fourier sampling: sample the target (t0, t1) against the ffLDL 'tree',
 * writing the sampled lattice coordinates into (z0, z1). 'tmp' needs room for
 * at least two polynomials of degree 2^logn. Faithful port of the reference
 * ffSampling_fft. */
WOLFSSL_LOCAL void falcon_ffSampling_fft(falcon_samplerZ samp, void* samp_ctx,
        fpr* z0, fpr* z1, const fpr* tree, const fpr* t0, const fpr* t1,
        unsigned logn, fpr* tmp);

/* Produce the signature short vector s2 (n sword16 values) from the expanded
 * key and hashed point hm (n word16 values in [0, q)). Loops over the sampler
 * until the (s1, s2) squared l2-norm is within the Falcon bound. 'tmp' must
 * hold FALCON_SIGN_TMP_FPR(logn) fpr. Returns 0 on success. */
WOLFSSL_LOCAL int falcon_do_sign_tree(falcon_samplerZ samp, void* samp_ctx,
        sword16* s2, const fpr* expanded, const word16* hm, unsigned logn,
        fpr* tmp);

/* Convenience top-level: sign hashed point c with the expanded key, using the
 * provided (already initialized) sampler context, writing s2. 'tmp' must hold
 * FALCON_SIGN_TMP_FPR(logn) fpr. Returns 0 on success. */
WOLFSSL_LOCAL int falcon_sign_core(falcon_sampler_ctx* spc, const fpr* expanded,
        const word16* c, sword16* s2, fpr* tmp, unsigned logn);

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY */
#endif /* WOLF_CRYPT_WC_FALCON_SIGN_H */
