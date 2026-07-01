/* wc_falcon_codec.c
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

/* Falcon encode/decode routines for the signing and
 * key-generation paths. These are faithful ports of the Falcon reference
 * implementation (codec.c): modq_encode, comp_encode, trim_i8_encode and
 * trim_i8_decode, plus the secret-key decoder that drives them.
 *
 * The verification-side decoders (modq_decode, comp_decode) are statics in
 * wc_falcon.c and are deliberately not duplicated here. */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(HAVE_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY) && !defined(WOLF_CRYPTO_CB_ONLY_FALCON)

#include <wolfssl/wolfcrypt/falcon.h>
#include <wolfssl/wolfcrypt/wc_falcon_codec.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* Maximum bit width used to encode f and g, indexed by logn (0..10).
 * From the Falcon reference (codec.c). */
static const byte falcon_max_fg_bits[] = {
    0, /* unused */
    8,
    8,
    8,
    8,
    8,
    7,
    7,
    6,
    6,
    5
};

/* Maximum bit width used to encode F (and G), indexed by logn (0..10).
 * From the Falcon reference (codec.c). */
static const byte falcon_max_FG_bits[] = {
    0, /* unused */
    8,
    8,
    8,
    8,
    8,
    8,
    8,
    8,
    8,
    8
};

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

    v = falcon_trim_i8_decode(F, logn, falcon_max_FG_bits[logn],
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
            falcon_max_FG_bits[logn]);
    if (v == 0) {
        return 0;
    }
    u += v;

    return u;
}

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY */
