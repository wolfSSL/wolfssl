/* wc_falcon_codec.h
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

/* Falcon encode/decode routines for the
 * signing and key-generation paths. The verification-side decoders
 * (modq_decode, comp_decode) live as static functions in wc_falcon.c and are
 * not referenced here. */

#ifndef FALCON_CODEC_H
#define FALCON_CODEC_H

#include <wolfssl/wolfcrypt/types.h>

#if defined(HAVE_FALCON) && !defined(WOLFSSL_FALCON_VERIFY_ONLY)

#ifdef __cplusplus
    extern "C" {
#endif

/* Golomb-Rice (k=7) compress of the signature polynomial s2. Exact inverse of
 * the reference comp_decode. Rejects any |x[i]| > 2047. Returns the number of
 * bytes written, or 0 on range violation / output overflow. */
WOLFSSL_LOCAL size_t falcon_comp_encode(byte* out, size_t max_out,
        const sword16* x, unsigned logn);

/* 14-bit big-endian pack of the public-key polynomial h. Each coefficient must
 * be < q (12289). Returns the number of bytes written, or 0 on range violation
 * / output overflow. */
WOLFSSL_LOCAL size_t falcon_modq_encode(byte* out, size_t max_out,
        const word16* x, unsigned logn);

/* Signed 8-bit polynomial pack/unpack using a fixed per-coefficient bit width.
 * The most-negative value -2^(bits-1) is forbidden (matching the reference). */
WOLFSSL_LOCAL size_t falcon_trim_i8_encode(byte* out, size_t max_out,
        const sword8* x, unsigned logn, unsigned bits);
WOLFSSL_LOCAL size_t falcon_trim_i8_decode(sword8* x, unsigned logn,
        unsigned bits, const byte* in, size_t max_in);

/* Decode a Falcon secret key: header byte (0x50 | logn), then trim_i8 encoded
 * f, g (max_fg_bits[logn]) and F (max_FG_bits[logn]). Validates the header and
 * that the input length is exactly consumed. Returns 0 on success or a negative
 * wolfCrypt error. */
WOLFSSL_LOCAL int falcon_privkey_decode(const byte* sk, size_t sklen,
        sword8* f, sword8* g, sword8* F, unsigned logn);

/* Encode a Falcon secret key from (f, g, F). Inverse of falcon_privkey_decode.
 * Returns bytes written, or 0 on failure. */
WOLFSSL_LOCAL size_t falcon_privkey_encode(byte* sk, size_t max_sk,
        const sword8* f, const sword8* g, const sword8* F, unsigned logn);

#ifdef __cplusplus
    }
#endif

#endif /* HAVE_FALCON && !WOLFSSL_FALCON_VERIFY_ONLY */

#endif /* FALCON_CODEC_H */
