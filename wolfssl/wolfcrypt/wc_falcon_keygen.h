/* wc_falcon_keygen.h
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
    \file wolfssl/wolfcrypt/wc_falcon_keygen.h
*/

/* Falcon key-pair generation.
 *
 * Generates an (f, g, F, G) NTRU lattice basis together with the public key
 * h = g/f mod q. The procedure is a faithful port of the key-generation half
 * of the MIT-licensed Falcon reference implementation keygen.c (Thomas
 * Pornin):
 *
 *   - sample f, g from a discrete Gaussian of standard deviation
 *     1.17*sqrt(q/(2n)), driven by a SHAKE256 stream seeded from a WC_RNG;
 *   - reject (f, g) until the resultant with X^n+1 is odd, the (g,-f) norm
 *     and the orthogonalized vector norm are below the 1.17*sqrt(q) bound,
 *     and f is invertible modulo q;
 *   - solve the NTRU equation f*G - g*F = q with the recursive "ntru_solve"
 *     built on the validated big-integer / RNS layer (wc_falcon_bigint);
 *   - return the basis and the public polynomial h.
 *
 * This module is excluded from verify-only builds (keygen is not needed
 * there) and depends on the floating-point seam (wc_falcon_fpr / fft / poly). */

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
WOLFSSL_LOCAL int falcon_keygen(WC_RNG* rng, sword8* f, sword8* g,
        sword8* F, sword8* G, word16* h, unsigned logn);

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY */
#endif /* WOLF_CRYPT_WC_FALCON_KEYGEN_H */
