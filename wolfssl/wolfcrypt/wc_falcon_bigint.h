/* wc_falcon_bigint.h
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
    \file wolfssl/wolfcrypt/wc_falcon_bigint.h
*/

/* Self-contained big-integer / RNS arithmetic for native Falcon
 * key generation.
 *
 * Falcon key generation solves the NTRU equation g*F - f*G = q, which is
 * performed by the Falcon "ntru_solve" routine. That routine relies on a
 * specialized integer-only big-number layer using a residue number system
 * (RNS) of 31-bit prime moduli, with a small-modulus NTT for fast
 * polynomial arithmetic and an extended-binary-GCD (Bezout) solver.
 *
 * The algorithms and limb conventions here are ported faithfully from the
 * Falcon reference implementation keygen.c by Thomas Pornin (MIT licensed):
 *   - big integers are little-endian arrays of word32 "limbs", each limb
 *     holding 31 bits of value (the top bit is unused for carry handling);
 *   - products use word64; signed reductions use sword32 / sword64;
 *   - the RNS primes p satisfy 2^30 < p < 2^31 and p = 1 mod 2048.
 *
 * This module is INTEGER-ONLY and independent of the floating-point seam.
 * It is excluded from verify-only builds (keygen is not needed there). */

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
WOLFSSL_LOCAL extern const falcon_small_prime FALCON_PRIMES[];

/* ---- modular small-integer helpers (single 31-bit prime modulus) ---- */
WOLFSSL_LOCAL word32 modp_set(sword32 x, word32 p);
WOLFSSL_LOCAL sword32 modp_norm(word32 x, word32 p);
WOLFSSL_LOCAL word32 modp_ninv31(word32 p);
WOLFSSL_LOCAL word32 modp_R(word32 p);
WOLFSSL_LOCAL word32 modp_add(word32 a, word32 b, word32 p);
WOLFSSL_LOCAL word32 modp_sub(word32 a, word32 b, word32 p);
WOLFSSL_LOCAL word32 modp_montymul(word32 a, word32 b, word32 p, word32 p0i);
WOLFSSL_LOCAL word32 modp_R2(word32 p, word32 p0i);
WOLFSSL_LOCAL word32 modp_Rx(unsigned int x, word32 p, word32 p0i, word32 R2);
/* Modular division a/b mod p (returns 0 when b == 0). This is the
 * reference's modular-inverse helper (the canonical Falcon keygen.c has no
 * separately named "modp_get_inv"; modp_div(R,b,...) yields 1/b). */
WOLFSSL_LOCAL word32 modp_div(word32 a, word32 b, word32 p, word32 p0i,
        word32 R);

/* ---- small-modulus NTT used in the RNS ---- */
WOLFSSL_LOCAL void modp_mkgm2(word32* gm, word32* igm, unsigned int logn,
        word32 g, word32 p, word32 p0i);
WOLFSSL_LOCAL void modp_NTT2_ext(word32* a, size_t stride, const word32* gm,
        unsigned int logn, word32 p, word32 p0i);
WOLFSSL_LOCAL void modp_iNTT2_ext(word32* a, size_t stride, const word32* igm,
        unsigned int logn, word32 p, word32 p0i);

/* Convenience wrappers for unit-stride polynomials. */
#define modp_NTT2(a, gm, logn, p, p0i) \
    modp_NTT2_ext(a, 1, gm, logn, p, p0i)
#define modp_iNTT2(a, igm, logn, p, p0i) \
    modp_iNTT2_ext(a, 1, igm, logn, p, p0i)

/* ---- big-integer (zint) helpers ---- */
WOLFSSL_LOCAL word32 zint_sub(word32* a, const word32* b, size_t len,
        word32 ctl);
WOLFSSL_LOCAL word32 zint_mul_small(word32* m, size_t mlen, word32 x);
WOLFSSL_LOCAL word32 zint_mod_small_unsigned(const word32* d, size_t dlen,
        word32 p, word32 p0i, word32 R2);
WOLFSSL_LOCAL word32 zint_mod_small_signed(const word32* d, size_t dlen,
        word32 p, word32 p0i, word32 R2, word32 Rx);
WOLFSSL_LOCAL void zint_add_mul_small(word32* x, const word32* y, size_t len,
        word32 s);
WOLFSSL_LOCAL void zint_norm_zero(word32* x, const word32* p, size_t len);
WOLFSSL_LOCAL void zint_rebuild_CRT(word32* xx, size_t xlen, size_t xstride,
        size_t num, const falcon_small_prime* primes, int normalize_signed,
        word32* tmp);
WOLFSSL_LOCAL void zint_negate(word32* a, size_t len, word32 ctl);
WOLFSSL_LOCAL word32 zint_co_reduce(word32* a, word32* b, size_t len,
        sword64 xa, sword64 xb, sword64 ya, sword64 yb);
WOLFSSL_LOCAL void zint_finish_mod(word32* a, size_t len, const word32* m,
        word32 neg);
WOLFSSL_LOCAL void zint_co_reduce_mod(word32* a, word32* b, const word32* m,
        size_t len, word32 m0i, sword64 xa, sword64 xb, sword64 ya,
        sword64 yb);
WOLFSSL_LOCAL int zint_bezout(word32* u, word32* v, const word32* x,
        const word32* y, size_t len, word32* tmp);
WOLFSSL_LOCAL void zint_add_scaled_mul_small(word32* x, size_t xlen,
        const word32* y, size_t ylen, sword32 k, word32 sch, word32 scl);
WOLFSSL_LOCAL void zint_sub_scaled(word32* x, size_t xlen, const word32* y,
        size_t ylen, word32 sch, word32 scl);
WOLFSSL_LOCAL sword32 zint_one_to_plain(const word32* x);

#ifdef __cplusplus
    }    /* extern "C" */
#endif

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY */
#endif /* WOLF_CRYPT_WC_FALCON_BIGINT_H */
