/* chacha.c
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
/*

DESCRIPTION
This library contains implementation for the ChaCha20 stream cipher and
the Poly1305 authenticator, both as as combined-mode,
or Authenticated Encryption with Additional Data (AEAD) algorithm.

*/

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)

#include <wolfssl/wolfcrypt/chacha20_poly1305.h>
#include <wolfssl/wolfcrypt/cpuid.h>

#ifdef NO_INLINE
#include <wolfssl/wolfcrypt/misc.h>
#else
#define WOLFSSL_MISC_INCLUDED
#include <wolfcrypt/src/misc.c>
#endif

#define CHACHA20_POLY1305_AEAD_INITIAL_COUNTER  0

#ifdef WOLFSSL_CHACHA20_POLY1305_FUSED
/* Fused single-pass encrypt kernel (in chacha_asm.S) and the 4-way power
 * precompute it depends on. */
#ifdef __cplusplus
extern "C" {
#endif
WOLFSSL_LOCAL void chacha20_poly1305_avx512(ChaCha* chacha, Poly1305* poly,
    const byte* m, byte* c, word32 bytes);
WOLFSSL_LOCAL void poly1305_calc_powers_avx2(Poly1305* ctx);
#ifdef __cplusplus
}
#endif

/* The fused kernel uses 4-block ChaCha (256-bit) + 4-way Poly1305, which beats
 * the wide two-pass only where 512-bit code is throttled - Intel Ice Lake and
 * later, under the AVX-512 frequency license.  On AMD (no throttle, very fast
 * wide primitives) the two-pass wins, so gate on an Intel vendor.  Override:
 * WOLFSSL_CHACHA20_POLY1305_FUSED_ALWAYS / _NEVER. */
static WC_INLINE int chacha20_poly1305_use_fused(void)
{
#if defined(WOLFSSL_CHACHA20_POLY1305_FUSED_NEVER)
    return 0;
#elif defined(WOLFSSL_CHACHA20_POLY1305_FUSED_ALWAYS)
    return 1;
#else
    cpuid_flags_t f = cpuid_get_flags();
    return (IS_CPU_INTEL(f) != 0) && (IS_INTEL_AVX512(f) != 0);
#endif
}

/* Encrypt with the fused kernel: no AAD, so Poly1305 starts clean and 256-byte
 * aligned.  Drive Poly1305 4-way (forceAvx2) so the kernel and the tail/final
 * share the layout; the kernel does the aligned bulk, the tail and length
 * framing go through the normal 4-way path. */
static int chacha20_poly1305_encrypt_fused(ChaChaPoly_Aead* aead,
    const byte* pt, word32 ptLen, byte* ct, byte* tag)
{
    word32 bulk = ptLen & ~(word32)0xff;
    int ret;

    aead->poly.forceAvx2 = 1;
    /* The cpuid setkey may have zeroed a different accumulator; ready the 4-way
     * hash and let the kernel initialise the lanes. */
    XMEMSET(aead->poly.hh, 0, sizeof(aead->poly.hh));
    aead->poly.started = 0;
    aead->poly.leftover = 0;
    aead->state = CHACHA20_POLY1305_STATE_DATA;

    SAVE_VECTOR_REGISTERS(return _svr_ret;);
    poly1305_calc_powers_avx2(&aead->poly);
    aead->poly.started = 1;
    chacha20_poly1305_avx512(&aead->chacha, &aead->poly, pt, ct, bulk);
    RESTORE_VECTOR_REGISTERS();

    aead->dataLen = bulk;
    ret = 0;
    if (ptLen > bulk)
        ret = wc_ChaCha20Poly1305_UpdateData(aead, pt + bulk, ct + bulk,
                                             ptLen - bulk);
    if (ret == 0)
        ret = wc_ChaCha20Poly1305_Final(aead, tag);

    return ret;
}
#endif /* WOLFSSL_CHACHA20_POLY1305_FUSED */

#ifdef WOLFSSL_CHACHA20_POLY1305_FUSED_IFMA
/* IFMA stitched single-pass encrypt kernel (in chacha_asm.S): full 512-bit
 * 16-block ChaCha interleaved with an 8-way IFMA (vpmadd52) Poly1305 that
 * collapses to the scalar hash.  Processes 1024-byte units.  Depends on the
 * radix-2^44 powers. */
#ifdef __cplusplus
extern "C" {
#endif
WOLFSSL_LOCAL void chacha20_poly1305_ifma(ChaCha* chacha, Poly1305* poly,
    const byte* m, byte* c, word32 bytes);
/* Decrypt counterpart: hashes the ciphertext INPUT (m) as it decrypts to c
 * (in-place safe - m is hashed before it is overwritten).  Same 1024-byte
 * units and radix-2^44 powers. */
WOLFSSL_LOCAL void chacha20_poly1305_ifma_decrypt(ChaCha* chacha,
    Poly1305* poly, const byte* m, byte* c, word32 bytes);
WOLFSSL_LOCAL void poly1305_calc_powers_avx512ifma(Poly1305* ctx);
/* ctx->h = ctx->hh * r^nBlocks + ctx->h - advances the running hash (saved by
 * the kernel to ctx->hh) past a chunk the kernel hashed from zero into ctx->h.
 * Radix-2^64 scalar, so no 26<->64 conversions. */
WOLFSSL_LOCAL void poly1305_fold_avx512ifma(Poly1305* ctx, word32 nBlocks);
#ifdef __cplusplus
}
#endif

/* Minimum length to stitch.  The kernel processes 1024-byte units and a
 * once-per-op power precompute, and any sub-1024 remainder is authenticated by
 * the slower scalar Poly1305; below this the two-pass wins (measured crossover
 * on Zen5).  Above it the stitch wins 1.1-1.4x, growing with size. */
#ifndef CHACHA20_POLY1305_STITCH_MIN
#define CHACHA20_POLY1305_STITCH_MIN 4096
#endif

/* Short-message fused path: for messages this small the Poly1305 key block
 * (ChaCha counter 0) and the whole ciphertext (counter 1+) fit in a single
 * ChaCha keystream generation - one pass instead of two - and a scalar
 * Poly1305 avoids the vector power-precompute cost.  Needs the forceScalar
 * flag (same builds as the fused kernels).  Measured 1.1-1.5x on Zen5 for
 * 64-192 byte records; above SHORT_MAX the poly key spills to a second ChaCha
 * chunk and the saving is gone. */
#if defined(WOLFSSL_CHACHA20_POLY1305_FUSED_IFMA) && \
    !defined(WOLFSSL_NO_CHACHA20_POLY1305_SHORT)
    #define WOLFSSL_CHACHA20_POLY1305_SHORT
    #ifndef CHACHA20_POLY1305_SHORT_MAX
        /* 64 (poly-key block) + 192 = 256 = one AVX-512VL 4-block chunk */
        #define CHACHA20_POLY1305_SHORT_MAX 192
    #endif
#endif

/* The IFMA stitch runs a full-width 512-bit 16-block ChaCha interleaved with an
 * 8-way IFMA Poly1305: ChaCha is the bottleneck and Poly hides under it, so it
 * beats the two-pass (which runs the two passes back to back) by ~1.3-1.4x at
 * >=16KB - measured on AMD Zen5, and expected wherever AVX-512 + IFMA exist
 * (both use 512-bit ChaCha, so any frequency throttle hits both equally).  Gate
 * on AVX-512 + IFMA, any vendor.  Override: ..._FUSED_IFMA_ALWAYS / _NEVER. */
static WC_INLINE int chacha20_poly1305_use_fused_ifma(void)
{
#if defined(WOLFSSL_CHACHA20_POLY1305_FUSED_IFMA_NEVER)
    return 0;
#elif defined(WOLFSSL_CHACHA20_POLY1305_FUSED_IFMA_ALWAYS)
    return 1;
#else
    cpuid_flags_t f = cpuid_get_flags();
    return (IS_INTEL_AVX512(f) != 0) && (IS_INTEL_AVX512_IFMA(f) != 0);
#endif
}

/* Stitch one 1024-byte-aligned bulk.  (IFMA path) The kernel hashes this
 * chunk's ciphertext from zero (leaving ctx->h = H_chunk) and advances the
 * ChaCha counter, saving the running hash (the AAD, or previous chunks) to
 * ctx->hh; poly1305_fold_avx512ifma then advances that hash past this chunk
 * (ctx->h = ctx->hh * r^nBlocks + H_chunk).  Powers are computed once (started
 * flag).  Caller must have ctx->h = running hash, leftover == 0, forceScalar
 * and finished set, and the ChaCha counter placed for this chunk.  decrypt: in
 * is ciphertext, out is plaintext (in-place safe - the kernel hashes in before
 * overwriting it); the hash math is identical. */
static int chacha20_poly1305_stitch_chunk(ChaCha* chacha, Poly1305* poly,
    const byte* in, byte* out, word32 bulk, int decrypt)
{
    int fold;

    /* A running hash (AAD or previous chunks) must be folded past this chunk;
     * detect it before the kernel overwrites poly->h with this chunk's hash. */
    fold = (poly->h[0] | poly->h[1] | poly->h[2]) != 0;

    SAVE_VECTOR_REGISTERS(return _svr_ret;);
    if (!poly->started) {
        poly1305_calc_powers_avx512ifma(poly);
        poly->started = 1;
    }
    if (decrypt)
        chacha20_poly1305_ifma_decrypt(chacha, poly, in, out, bulk);
    else
        chacha20_poly1305_ifma(chacha, poly, in, out, bulk);
    RESTORE_VECTOR_REGISTERS();

    /* poly->h = H_chunk, poly->hh = running hash (scalar fold, no vectors). */
    if (fold)
        poly1305_fold_avx512ifma(poly, bulk / 16);
    return 0;
}

/* Encrypt the whole message with the IFMA stitch (one-shot path).  AAD is
 * hashed scalar into ctx->h, the 1024-aligned bulk is stitched (folding AAD
 * through it), the tail + length framing go through the scalar path.
 * forceScalar/finished: see the AVX2 fused note (setkey_avx2 leaves finished
 * clear).  Both this and the streaming UpdateData path share stitch_chunk(). */
static int chacha20_poly1305_encrypt_fused_ifma(ChaChaPoly_Aead* aead,
    const byte* aad, word32 aadLen, const byte* pt, word32 ptLen, byte* ct,
    byte* tag)
{
    word32 bulk = ptLen & ~(word32)0x3ff;
    int ret = 0;

    aead->poly.forceScalar = 1;
    XMEMSET(aead->poly.h, 0, sizeof(aead->poly.h));
    aead->poly.finished = 1;
    aead->poly.leftover = 0;
    aead->poly.started = 0;

    /* Hash AAD + pad1 (scalar) -> H_aad in ctx->h. */
    if (aadLen > 0) {
        ret = wc_Poly1305Update(&aead->poly, aad, aadLen);
        if (ret == 0)
            ret = wc_Poly1305_Pad(&aead->poly, aadLen);
    }
    aead->aadLen = aadLen;
    aead->state = CHACHA20_POLY1305_STATE_DATA;

    if (ret == 0)
        ret = chacha20_poly1305_stitch_chunk(&aead->chacha, &aead->poly, pt,
                                             ct, bulk, 0);
    if (ret == 0) {
        aead->dataLen = bulk;
        if (ptLen > bulk)
            ret = wc_ChaCha20Poly1305_UpdateData(aead, pt + bulk, ct + bulk,
                                                 ptLen - bulk);
        if (ret == 0)
            ret = wc_ChaCha20Poly1305_Final(aead, tag);
    }
    return ret;
}
#endif /* WOLFSSL_CHACHA20_POLY1305_FUSED_IFMA */

#ifdef WOLFSSL_CHACHA20_POLY1305_SHORT

#if defined(USE_INTEL_SPEEDUP) && defined(WOLFSSL_X86_64_BUILD) && \
    !defined(WOLFSSL_NO_CHACHA20_POLY1305_SMALL_ASM)
#define WOLFSSL_CP_SMALL_ASM

/* Fused single-call ChaCha20-Poly1305 encrypt for a one-block (<=64 byte)
 * record (in chacha_asm.S): SSSE3 crypt2 produces the Poly1305 key block and
 * the single data block together; the scalar poly1305_*_avx do the MAC. */
#ifdef __cplusplus
extern "C" {
#endif
WOLFSSL_LOCAL void chacha20_poly1305_small_enc(ChaCha* chacha, Poly1305* poly,
    const byte* m, byte* c, word32 mLen, const byte* aad, word32 aadLen,
    byte* tag);
/* Decrypt twin: decrypts in->out AND verifies the tag in one pass (decrypt-
 * then-verify).  Constant-time-compares the computed tag against the received
 * tag internally and returns 0 on match, 1 on mismatch; the caller ForceZeros
 * the output on mismatch, so no plaintext is released on a bad tag. */
WOLFSSL_LOCAL int chacha20_poly1305_small_dec(ChaCha* chacha, Poly1305* poly,
    const byte* in, byte* out, word32 ctLen, const byte* aad, word32 aadLen,
    const byte* tag);
#ifdef __cplusplus
}
#endif

static WC_INLINE int chacha20_poly1305_use_small(void)
{
    return IS_INTEL_AVX2(cpuid_get_flags()) != 0;
}
#endif

/* Fused short-message (sz <= CHACHA20_POLY1305_SHORT_MAX) encrypt for the
 * pre-keyed contexts: derive the Poly1305 key (counter 0) and the encryption
 * keystream (counter 1+) in a SINGLE ChaCha pass, then scalar-hash.  Saves the
 * second ChaCha invocation the two-pass path would make. */
static int chacha20_poly1305_encrypt_short(ChaCha* chacha, Poly1305* poly,
    byte* out, const byte* in, word32 sz, const byte* nonce, byte* tag,
    const byte* aad, word32 aadSz)
{
    byte ks[64 + CHACHA20_POLY1305_SHORT_MAX];
    int  ret;

#ifdef WOLFSSL_CP_SMALL_ASM
    /* One block or less of data: the fused single-call kernel. */
    if (sz <= 64 && chacha20_poly1305_use_small()) {
        ret = wc_Chacha_SetIV(chacha, nonce,
                              CHACHA20_POLY1305_AEAD_INITIAL_COUNTER);
        if (ret == 0) {
            SAVE_VECTOR_REGISTERS(return _svr_ret;);
            chacha20_poly1305_small_enc(chacha, poly, in, out, sz, aad, aadSz,
                                        tag);
            RESTORE_VECTOR_REGISTERS();
        }
        return ret;
    }
#endif

    XMEMSET(ks, 0, 64 + sz);
    ret = wc_Chacha_SetIV(chacha, nonce,
                          CHACHA20_POLY1305_AEAD_INITIAL_COUNTER);
    if (ret == 0)                       /* ctr0 (poly key) .. ctrN, one pass */
        ret = wc_Chacha_Process(chacha, ks, ks, 64 + sz);
    if (ret == 0)
        ret = wc_Poly1305SetKey(poly, ks, CHACHA20_POLY1305_AEAD_KEYSIZE);
    if (ret == 0) {
        xorbufout(out, in, ks + 64, sz);   /* ct = pt ^ keystream (ctr1+) */
        poly->forceScalar = 1;
        poly->finished = 1;
        ret = wc_Poly1305_MAC(poly, aad, aadSz, out, sz, tag,
                              CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);
    }
    ForceZero(ks, 64 + sz);                /* ks[0:32] was the poly key */
    return ret;
}

/* Fused short-message decrypt twin: derive key + keystream in one ChaCha pass,
 * MAC the ciphertext INPUT and verify the tag BEFORE decrypting, so no
 * plaintext is produced on a bad tag (stronger than the stitch, cheap here
 * because the message is small).  In-place safe. */
static int chacha20_poly1305_decrypt_short(ChaCha* chacha, Poly1305* poly,
    byte* out, const byte* in, word32 sz, const byte* nonce, const byte* tag,
    const byte* aad, word32 aadSz)
{
    byte ks[64 + CHACHA20_POLY1305_SHORT_MAX];
    byte calcTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    int  ret;

#ifdef WOLFSSL_CP_SMALL_ASM
    /* One block or less of data: the fused single-call kernel decrypts in->out
     * and computes calcTag in one pass (decrypt-then-verify).  Zero the output
     * if the tag is bad, so no plaintext is released. */
    if (sz <= 64 && chacha20_poly1305_use_small()) {
        ret = wc_Chacha_SetIV(chacha, nonce,
                              CHACHA20_POLY1305_AEAD_INITIAL_COUNTER);
        if (ret == 0) {
            int bad;
            SAVE_VECTOR_REGISTERS(return _svr_ret;);
            bad = chacha20_poly1305_small_dec(chacha, poly, in, out, sz, aad,
                                              aadSz, tag);
            RESTORE_VECTOR_REGISTERS();
            if (bad) {                         /* bad tag: no plaintext */
                if (sz > 0)
                    ForceZero(out, sz);
                ret = MAC_CMP_FAILED_E;
            }
        }
        (void)calcTag;
        return ret;
    }
#endif

    XMEMSET(ks, 0, 64 + sz);
    ret = wc_Chacha_SetIV(chacha, nonce,
                          CHACHA20_POLY1305_AEAD_INITIAL_COUNTER);
    if (ret == 0)
        ret = wc_Chacha_Process(chacha, ks, ks, 64 + sz);
    if (ret == 0)
        ret = wc_Poly1305SetKey(poly, ks, CHACHA20_POLY1305_AEAD_KEYSIZE);
    if (ret == 0) {
        poly->forceScalar = 1;
        poly->finished = 1;
        ret = wc_Poly1305_MAC(poly, aad, aadSz, in, sz, calcTag,
                              CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);
    }
    if (ret == 0)
        ret = wc_ChaCha20Poly1305_CheckTag(tag, calcTag);
    if (ret == 0)                          /* tag good: decrypt pt = ct ^ ks */
        xorbufout(out, in, ks + 64, sz);
    else if (sz > 0)                       /* bad tag/error: no stale output */
        ForceZero(out, sz);
    ForceZero(ks, 64 + sz);
    return ret;
}
#endif /* WOLFSSL_CHACHA20_POLY1305_SHORT */

/* Encrypt + authenticate one message with PRE-KEYED ChaCha20 and Poly1305
 * contexts - the ChaCha20-Poly1305 analogue of wc_AesGcmEncrypt on a keyed Aes.
 * Intended for the TLS record layer, which keeps the ChaCha context keyed once
 * (per traffic key) and only varies the nonce per record.  The per-record
 * Poly1305 key is derived here from the ChaCha keystream.  Uses the single-pass
 * IFMA stitch when beneficial, else the two-pass; identical output either way.
 *
 *   chacha  ChaCha20 context with the key already set (wc_Chacha_SetKey)
 *   poly    Poly1305 scratch context (re-keyed here every call)
 *   out     ciphertext out (may alias in)
 *   in/sz   plaintext / length
 *   nonce   CHACHA20_POLY1305_AEAD_IV_SIZE (12) byte record nonce
 *   tag     CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE (16) byte tag out
 *   aad/aadSz  additional authenticated data
 * returns 0 on success, negative on error.
 */
WOLFSSL_API int wc_ChaCha20Poly1305_Encrypt_ex(ChaCha* chacha, Poly1305* poly,
    byte* out, const byte* in, word32 sz, const byte* nonce, byte* tag,
    const byte* aad, word32 aadSz)
{
    byte polyKey[CHACHA20_POLY1305_AEAD_KEYSIZE];
    int  ret;

    if (chacha == NULL || poly == NULL || nonce == NULL || tag == NULL ||
            (sz > 0 && (in == NULL || out == NULL)) ||
            (aadSz > 0 && aad == NULL)) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_CHACHA20_POLY1305_SHORT
    if (sz <= CHACHA20_POLY1305_SHORT_MAX)
        return chacha20_poly1305_encrypt_short(chacha, poly, out, in, sz,
                                               nonce, tag, aad, aadSz);
#endif

    /* Per-record Poly1305 key = first 32 bytes of ChaCha20(nonce, ctr 0). */
    XMEMSET(polyKey, 0, sizeof(polyKey));
    ret = wc_Chacha_SetIV(chacha, nonce,
                          CHACHA20_POLY1305_AEAD_INITIAL_COUNTER);
    if (ret == 0)
        ret = wc_Chacha_Process(chacha, polyKey, polyKey, sizeof(polyKey));
    if (ret == 0)   /* message data starts at counter 1 */
        ret = wc_Chacha_SetIV(chacha, nonce,
            CHACHA20_POLY1305_AEAD_INITIAL_COUNTER + 1);
    if (ret == 0)
        ret = wc_Poly1305SetKey(poly, polyKey, sizeof(polyKey));
    ForceZero(polyKey, sizeof(polyKey));
    if (ret != 0)
        return ret;

#ifdef WOLFSSL_CHACHA20_POLY1305_FUSED_IFMA
    if (sz >= CHACHA20_POLY1305_STITCH_MIN &&
            chacha20_poly1305_use_fused_ifma()) {
        word32 bulk = sz & ~(word32)0x3ff;
        /* Scalar running hash (in poly->h) so stitch and tail chain; poly->h,
         * leftover and started are all zeroed by wc_Poly1305SetKey. */
        poly->forceScalar = 1;
        poly->finished = 1;
        if (aadSz > 0) {                             /* H_aad + pad1 (scalar) */
            ret = wc_Poly1305Update(poly, aad, aadSz);
            if (ret == 0)
                ret = wc_Poly1305_Pad(poly, aadSz);
        }
        if (ret == 0)                            /* stitch bulk + fold AAD */
            ret = chacha20_poly1305_stitch_chunk(chacha, poly, in, out, bulk,
                                                 0);
        if (ret == 0 && sz > bulk) {                 /* scalar tail */
            ret = wc_Chacha_Process(chacha, out + bulk, in + bulk, sz - bulk);
            if (ret == 0)
                ret = wc_Poly1305Update(poly, out + bulk, sz - bulk);
        }
        if (ret == 0)                                /* pad2 + lengths + tag */
            ret = wc_Poly1305_Pad(poly, sz);
        if (ret == 0)
            ret = wc_Poly1305_EncodeSizes(poly, aadSz, sz);
        if (ret == 0)
            ret = wc_Poly1305Final(poly, tag);
        return ret;
    }
#endif

    /* Two-pass: fast vector Poly1305 (small msgs, or stitch not beneficial). */
    ret = wc_Chacha_Process(chacha, out, in, sz);
    if (ret == 0)
        ret = wc_Poly1305_MAC(poly, aad, aadSz, out, sz, tag,
                              CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);
    return ret;
}

/* Verify+decrypt one message with pre-keyed ChaCha20 and Poly1305 contexts -
 * the decrypt counterpart of wc_ChaCha20Poly1305_Encrypt_ex, for the TLS record
 * layer.  Verifies the Poly1305 tag over AAD+ciphertext and decrypts to out
 * (in-place safe).  Uses the single-pass IFMA decrypt stitch when beneficial.
 * The plaintext is produced while the tag is computed, so on tag mismatch out
 * is zeroed and MAC_CMP_FAILED_E returned - callers must check the result.
 *
 *   chacha  ChaCha20 context with the key already set (wc_Chacha_SetKey)
 *   poly    Poly1305 scratch context (re-keyed here every call)
 *   out     plaintext out (may alias in)
 *   in/sz   ciphertext / length
 *   nonce   CHACHA20_POLY1305_AEAD_IV_SIZE (12) byte record nonce
 *   tag     CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE (16) byte tag to verify
 *   aad/aadSz  additional authenticated data
 * returns 0 on success, MAC_CMP_FAILED_E on tag mismatch, else negative.
 */
WOLFSSL_API int wc_ChaCha20Poly1305_Decrypt_ex(ChaCha* chacha, Poly1305* poly,
    byte* out, const byte* in, word32 sz, const byte* nonce, const byte* tag,
    const byte* aad, word32 aadSz)
{
    byte polyKey[CHACHA20_POLY1305_AEAD_KEYSIZE];
    byte calcTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];
    int  ret;

    if (chacha == NULL || poly == NULL || nonce == NULL || tag == NULL ||
            (sz > 0 && (in == NULL || out == NULL)) ||
            (aadSz > 0 && aad == NULL)) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_CHACHA20_POLY1305_SHORT
    if (sz <= CHACHA20_POLY1305_SHORT_MAX)
        return chacha20_poly1305_decrypt_short(chacha, poly, out, in, sz,
                                               nonce, tag, aad, aadSz);
#endif

    /* Per-record Poly1305 key = first 32 bytes of ChaCha20(nonce, ctr 0). */
    XMEMSET(polyKey, 0, sizeof(polyKey));
    ret = wc_Chacha_SetIV(chacha, nonce,
                          CHACHA20_POLY1305_AEAD_INITIAL_COUNTER);
    if (ret == 0)
        ret = wc_Chacha_Process(chacha, polyKey, polyKey, sizeof(polyKey));
    if (ret == 0)   /* message data starts at counter 1 */
        ret = wc_Chacha_SetIV(chacha, nonce,
            CHACHA20_POLY1305_AEAD_INITIAL_COUNTER + 1);
    if (ret == 0)
        ret = wc_Poly1305SetKey(poly, polyKey, sizeof(polyKey));
    ForceZero(polyKey, sizeof(polyKey));
    if (ret != 0)
        return ret;

#ifdef WOLFSSL_CHACHA20_POLY1305_FUSED_IFMA
    if (sz >= CHACHA20_POLY1305_STITCH_MIN &&
            chacha20_poly1305_use_fused_ifma()) {
        word32 bulk = sz & ~(word32)0x3ff;
        /* Scalar running hash (in poly->h) so stitch and tail chain; poly->h,
         * leftover and started are all zeroed by wc_Poly1305SetKey. */
        poly->forceScalar = 1;
        poly->finished = 1;
        if (aadSz > 0) {                             /* H_aad + pad1 (scalar) */
            ret = wc_Poly1305Update(poly, aad, aadSz);
            if (ret == 0)
                ret = wc_Poly1305_Pad(poly, aadSz);
        }
        if (ret == 0)                        /* stitch: hash CT + decrypt */
            ret = chacha20_poly1305_stitch_chunk(chacha, poly, in, out, bulk,
                                                 1);
        if (ret == 0 && sz > bulk) {                 /* scalar tail */
            /* hash the ciphertext tail before decrypt overwrites it */
            ret = wc_Poly1305Update(poly, in + bulk, sz - bulk);
            if (ret == 0)
                ret = wc_Chacha_Process(chacha, out + bulk, in + bulk,
                                        sz - bulk);
        }
        if (ret == 0)                                /* pad2 + lengths + tag */
            ret = wc_Poly1305_Pad(poly, sz);
        if (ret == 0)
            ret = wc_Poly1305_EncodeSizes(poly, aadSz, sz);
        if (ret == 0)
            ret = wc_Poly1305Final(poly, calcTag);
    }
    else
#endif
    {
        /* Two-pass: MAC the ciphertext (in), then decrypt in -> out. */
        ret = wc_Poly1305_MAC(poly, aad, aadSz, in, sz, calcTag,
                              CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);
        if (ret == 0)
            ret = wc_Chacha_Process(chacha, out, in, sz);
    }

    if (ret == 0)
        ret = wc_ChaCha20Poly1305_CheckTag(tag, calcTag);
    if (ret != 0 && sz > 0)
        ForceZero(out, sz);
    return ret;
}

/* Clear a temporary ChaChaPoly_Aead.  On an AVX-512/IFMA build the Poly1305
 * state carries ~320 extra bytes (r5..r8 for the 16-way poly, ifma_h for the
 * IFMA stitch) that are only ever written on AVX-512-capable CPUs; on a CPU
 * without AVX-512 they are never touched, so zeroing them on every call is pure
 * overhead - a large fraction of a small AEAD op.  Skip them there (they hold
 * no key material from this call), and clear the full struct otherwise. */
static WC_INLINE void chacha20_poly1305_aead_zero(ChaChaPoly_Aead* aead)
{
#ifdef WOLFSSL_POLY1305_AVX512
    if (IS_INTEL_AVX512(cpuid_get_flags()) != 0)
        ForceZero(aead, sizeof(ChaChaPoly_Aead));
    else
        ForceZero(aead, (word32)((const byte*)&aead->poly.r5
                                 - (const byte*)aead));
#else
    ForceZero(aead, sizeof(ChaChaPoly_Aead));
#endif
}

WOLFSSL_ABI
int wc_ChaCha20Poly1305_Encrypt(
                const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
                const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
                const byte* inAAD, const word32 inAADLen,
                const byte* inPlaintext, const word32 inPlaintextLen,
                byte* outCiphertext,
                byte outAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE])
{
    int ret;
    WC_DECLARE_VAR(aead, ChaChaPoly_Aead, 1, 0);

    /* Validate function arguments */
    if (!inKey || !inIV ||
        (inPlaintextLen > 0 && inPlaintext == NULL) ||
        (inAADLen > 0 && inAAD == NULL) ||
        !outCiphertext ||
        !outAuthTag)
    {
        return BAD_FUNC_ARG;
    }

    WC_ALLOC_VAR_EX(aead, ChaChaPoly_Aead, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        return MEMORY_E);

#ifdef WOLFSSL_CHACHA20_POLY1305_SHORT
    /* Small record: derive the Poly1305 key and the keystream in a SINGLE
     * ChaCha pass (SSSE3), then scalar-hash - the same short path Encrypt_ex
     * uses.  Avoids wc_ChaCha20Poly1305_Init's separate scalar poly-key block
     * and the second scalar data block the two-pass fallback would run. */
    if (inPlaintextLen <= CHACHA20_POLY1305_SHORT_MAX) {
        ret = wc_Chacha_SetKey(&aead->chacha, inKey,
            CHACHA20_POLY1305_AEAD_KEYSIZE);
        if (ret == 0)
            ret = chacha20_poly1305_encrypt_short(&aead->chacha, &aead->poly,
                outCiphertext, inPlaintext, inPlaintextLen, inIV, outAuthTag,
                inAAD, inAADLen);
    }
    else
#endif
    {
    ret = wc_ChaCha20Poly1305_Init(aead, inKey, inIV,
        CHACHA20_POLY1305_AEAD_ENCRYPT);
    /* Prefer the IFMA stitch - full 512-bit ChaCha, beats the others where
     * AVX-512 + IFMA exist. */
#ifdef WOLFSSL_CHACHA20_POLY1305_FUSED_IFMA
    if (ret == 0 && inPlaintextLen >= CHACHA20_POLY1305_STITCH_MIN &&
            chacha20_poly1305_use_fused_ifma()) {
        ret = chacha20_poly1305_encrypt_fused_ifma(aead, inAAD, inAADLen,
                  inPlaintext, inPlaintextLen, outCiphertext, outAuthTag);
    }
    else
#endif
#ifdef WOLFSSL_CHACHA20_POLY1305_FUSED
    if (ret == 0 && inAADLen == 0 && inPlaintextLen >= 256 &&
            chacha20_poly1305_use_fused()) {
        ret = chacha20_poly1305_encrypt_fused(aead, inPlaintext,
                  inPlaintextLen, outCiphertext, outAuthTag);
    }
    else
#endif
    {
        /* Direct two-pass on the contexts Init already keyed (ChaCha counter is
         * at 1, Poly1305 keyed).  Faster than the UpdateAad/UpdateData/Final
         * state machine for the common non-stitched case - in particular
         * wc_Poly1305_MAC hashes the AAD inline instead of buffering it through
         * UpdateAad, which is where the small-message-with-AAD cost was. */
        if (ret == 0)
            ret = wc_Chacha_Process(&aead->chacha, outCiphertext, inPlaintext,
                                    inPlaintextLen);
        if (ret == 0)
            ret = wc_Poly1305_MAC(&aead->poly, inAAD, inAADLen, outCiphertext,
                      inPlaintextLen, outAuthTag,
                      CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);
    }
    }
    #ifdef WOLFSSL_SMALL_STACK
    if (aead != NULL)
    #endif
        chacha20_poly1305_aead_zero(aead);
    WC_FREE_VAR_EX(aead, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

WOLFSSL_ABI
int wc_ChaCha20Poly1305_Decrypt(
                const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
                const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
                const byte* inAAD, const word32 inAADLen,
                const byte* inCiphertext, const word32 inCiphertextLen,
                const byte inAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE],
                byte* outPlaintext)
{
    int ret;
    WC_DECLARE_VAR(aead, ChaChaPoly_Aead, 1, 0);
    byte calculatedAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE];

    /* Validate function arguments */
    if (!inKey || !inIV ||
        (inCiphertextLen > 0 && inCiphertext == NULL) ||
        (inAADLen > 0 && inAAD == NULL) ||
        !inAuthTag ||
        !outPlaintext)
    {
        return BAD_FUNC_ARG;
    }

    WC_ALLOC_VAR_EX(aead, ChaChaPoly_Aead, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        return MEMORY_E);

    XMEMSET(calculatedAuthTag, 0, sizeof(calculatedAuthTag));

#ifdef WOLFSSL_CHACHA20_POLY1305_SHORT
    /* Small record: single ChaCha pass for poly key + keystream, MAC the
     * ciphertext and verify BEFORE decrypting (no plaintext on bad tag).  Same
     * short path Decrypt_ex uses; avoids Init's extra scalar poly-key block. */
    if (inCiphertextLen <= CHACHA20_POLY1305_SHORT_MAX) {
        ret = wc_Chacha_SetKey(&aead->chacha, inKey,
            CHACHA20_POLY1305_AEAD_KEYSIZE);
        if (ret == 0)
            ret = chacha20_poly1305_decrypt_short(&aead->chacha, &aead->poly,
                outPlaintext, inCiphertext, inCiphertextLen, inIV, inAuthTag,
                inAAD, inAADLen);
    }
    else
#endif
    {
    ret = wc_ChaCha20Poly1305_Init(aead, inKey, inIV,
        CHACHA20_POLY1305_AEAD_DECRYPT);
    /* Direct two-pass on the contexts Init already keyed: MAC the ciphertext,
     * verify the tag, then decrypt - verify-then-decrypt, so no plaintext is
     * produced on a bad tag.  Faster than the UpdateAad/UpdateData/Final state
     * machine (wc_Poly1305_MAC hashes the AAD inline).  In-place safe: the MAC
     * reads inCiphertext before the decrypt overwrites it. */
    if (ret == 0)
        ret = wc_Poly1305_MAC(&aead->poly, inAAD, inAADLen, inCiphertext,
                  inCiphertextLen, calculatedAuthTag,
                  CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE);
    if (ret == 0)
        ret = wc_ChaCha20Poly1305_CheckTag(inAuthTag, calculatedAuthTag);
    if (ret == 0)
        ret = wc_Chacha_Process(&aead->chacha, outPlaintext, inCiphertext,
                                inCiphertextLen);
    }

    if (ret != 0) {
        /* zero plaintext on error */
        ForceZero(outPlaintext, inCiphertextLen);
    }
    #ifdef WOLFSSL_SMALL_STACK
    if (aead != NULL)
    #endif
        chacha20_poly1305_aead_zero(aead);
    WC_FREE_VAR_EX(aead, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

int wc_ChaCha20Poly1305_CheckTag(
    const byte authTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE],
    const byte authTagChk[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE])
{
    int ret = 0;
    if (authTag == NULL || authTagChk == NULL) {
        return BAD_FUNC_ARG;
    }
    if (ConstantCompare(authTag, authTagChk,
            CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE) != 0) {
        ret = MAC_CMP_FAILED_E;
    }
    return ret;
}

int wc_ChaCha20Poly1305_Init(ChaChaPoly_Aead* aead,
    const byte inKey[CHACHA20_POLY1305_AEAD_KEYSIZE],
    const byte inIV[CHACHA20_POLY1305_AEAD_IV_SIZE],
    int isEncrypt)
{
    int ret;
    byte authKey[CHACHA20_POLY1305_AEAD_KEYSIZE];

    /* check arguments */
    if (aead == NULL || inKey == NULL || inIV == NULL) {
        return BAD_FUNC_ARG;
    }

    /* setup aead context (full clear: the aadLen/dataLen/state wrapper fields
     * live after the Poly1305 member and must be initialized) */
    XMEMSET(aead, 0, sizeof(ChaChaPoly_Aead));
    XMEMSET(authKey, 0, sizeof(authKey));
    aead->isEncrypt = isEncrypt ? 1 : 0;

    /* Initialize the ChaCha20 context (key and iv) */
    ret = wc_Chacha_SetKey(&aead->chacha, inKey,
        CHACHA20_POLY1305_AEAD_KEYSIZE);
    if (ret == 0) {
        ret = wc_Chacha_SetIV(&aead->chacha, inIV,
            CHACHA20_POLY1305_AEAD_INITIAL_COUNTER);
    }

    /* Create the Poly1305 key */
    if (ret == 0) {
        ret = wc_Chacha_Process(&aead->chacha, authKey, authKey,
            CHACHA20_POLY1305_AEAD_KEYSIZE);
    }

    /* Initialize Poly1305 context */
    if (ret == 0) {
        ret = wc_Poly1305SetKey(&aead->poly, authKey,
            CHACHA20_POLY1305_AEAD_KEYSIZE);
    }

    /* advance counter by 1 after creating Poly1305 key */
    if (ret == 0) {
        ret = wc_Chacha_SetIV(&aead->chacha, inIV,
            CHACHA20_POLY1305_AEAD_INITIAL_COUNTER + 1);
    }

    if (ret == 0) {
        aead->state = CHACHA20_POLY1305_STATE_READY;
    }

    ForceZero(authKey, sizeof(authKey));

    return ret;
}

/* optional additional authentication data */
int wc_ChaCha20Poly1305_UpdateAad(ChaChaPoly_Aead* aead,
    const byte* inAAD, word32 inAADLen)
{
    int ret = 0;

    if (aead == NULL || (inAAD == NULL && inAADLen > 0)) {
        return BAD_FUNC_ARG;
    }
    if (aead->state != CHACHA20_POLY1305_STATE_READY &&
        aead->state != CHACHA20_POLY1305_STATE_AAD) {
        return BAD_STATE_E;
    }
    if (inAADLen > CHACHA20_POLY1305_MAX - aead->aadLen)
        return CHACHA_POLY_OVERFLOW;

    if (inAAD && inAADLen > 0) {
        ret = wc_Poly1305Update(&aead->poly, inAAD, inAADLen);
        if (ret == 0) {
            aead->aadLen += inAADLen;
            aead->state = CHACHA20_POLY1305_STATE_AAD;
        }
    }

    return ret;
}

/* inData and outData can be same pointer (inline) */
int wc_ChaCha20Poly1305_UpdateData(ChaChaPoly_Aead* aead,
    const byte* inData, byte* outData, word32 dataLen)
{
    int ret = 0;

    if (aead == NULL || inData == NULL || outData == NULL) {
        return BAD_FUNC_ARG;
    }
    if (aead->state != CHACHA20_POLY1305_STATE_READY &&
        aead->state != CHACHA20_POLY1305_STATE_AAD &&
        aead->state != CHACHA20_POLY1305_STATE_DATA) {
        return BAD_STATE_E;
    }
    if (dataLen > CHACHA20_POLY1305_MAX - aead->dataLen)
        return CHACHA_POLY_OVERFLOW;

#ifdef WOLFSSL_CHACHA20_POLY1305_FUSED_IFMA
    /* Enter scalar-stitch mode at the first data chunk when it is large enough
     * to benefit and no vector Poly1305 state exists yet (started==0): any AAD
     * so far is then fully buffered by the vector path.  The vector buffer can
     * hold >16 bytes, which the scalar path cannot resume, so re-hash the
     * buffered AAD cleanly through the scalar path; the pad below finishes it.
     * If the AAD was large enough to be processed by the vector path
     * (started==1) we cannot switch, so it stays two-pass - no regression.
     * The IFMA stitch handles both directions (decrypt hashes the ciphertext
     * input). */
    if (!aead->poly.forceScalar && aead->poly.started == 0 &&
            aead->dataLen == 0 && dataLen >= CHACHA20_POLY1305_STITCH_MIN &&
            chacha20_poly1305_use_fused_ifma()) {
        word32 aadN = (word32)aead->poly.leftover;
        byte   aadBuf[8 * POLY1305_BLOCK_SIZE];
        if (aadN > 0)
            XMEMCPY(aadBuf, aead->poly.buffer, aadN);
        aead->poly.forceScalar = 1;
        aead->poly.finished = 1;
        aead->poly.leftover = 0;
        if (aadN > 0)
            ret = wc_Poly1305Update(&aead->poly, aadBuf, aadN);
    }
#endif

    /* Pad the AAD */
    if (ret == 0 && aead->state == CHACHA20_POLY1305_STATE_AAD) {
        ret = wc_Poly1305_Pad(&aead->poly, aead->aadLen);
    }

    /* advance state */
    aead->state = CHACHA20_POLY1305_STATE_DATA;

    /* Perform ChaCha20 encrypt/decrypt and Poly1305 auth calc */
    if (ret == 0) {
        if (aead->isEncrypt) {
            const byte* in = inData;
            byte* out = outData;
            word32 len = dataLen;
#ifdef WOLFSSL_CHACHA20_POLY1305_FUSED_IFMA
            /* Stitch the 1024-aligned bulk (encrypt + auth in one pass) when
             * the data so far is 64-byte aligned - so BOTH ChaCha (no buffered
             * partial keystream) and Poly1305 (leftover==0, running hash in
             * ctx->h) are at a block boundary - and we are in scalar-hash mode
             * (set at Init for AVX-512+IFMA encrypt).  The kernel processes
             * whole blocks from the ChaCha counter, so a mid-block position
             * would make it skip the buffered keystream; the 64-alignment check
             * prevents that.  The remainder falls through to the path below. */
            if (aead->poly.forceScalar && (aead->dataLen & 63) == 0 &&
                    len >= CHACHA20_POLY1305_STITCH_MIN) {
                word32 bulk = len & ~(word32)0x3ff;
                ret = chacha20_poly1305_stitch_chunk(&aead->chacha, &aead->poly,
                                                     in, out, bulk, 0);
                in += bulk;
                out += bulk;
                len -= bulk;
            }
#endif
            if (ret == 0 && len > 0) {
                ret = wc_Chacha_Process(&aead->chacha, out, in, len);
                if (ret == 0)
                    ret = wc_Poly1305Update(&aead->poly, out, len);
            }
        }
        else {
            const byte* in = inData;
            byte* out = outData;
            word32 len = dataLen;
#ifdef WOLFSSL_CHACHA20_POLY1305_FUSED_IFMA
            /* Stitch the 1024-aligned bulk (auth + decrypt in one pass) under
             * the same conditions as encrypt.  The kernel hashes the ciphertext
             * (in) before overwriting it, so in-place decrypt is safe. */
            if (aead->poly.forceScalar && (aead->dataLen & 63) == 0 &&
                    len >= CHACHA20_POLY1305_STITCH_MIN) {
                word32 bulk = len & ~(word32)0x3ff;
                ret = chacha20_poly1305_stitch_chunk(&aead->chacha, &aead->poly,
                                                     in, out, bulk, 1);
                in += bulk;
                out += bulk;
                len -= bulk;
            }
#endif
            if (ret == 0 && len > 0) {
                /* hash the ciphertext before decrypt overwrites it */
                ret = wc_Poly1305Update(&aead->poly, in, len);
                if (ret == 0)
                    ret = wc_Chacha_Process(&aead->chacha, out, in, len);
            }
        }
    }
    if (ret == 0) {
        aead->dataLen += dataLen;
    }
    return ret;
}

int wc_ChaCha20Poly1305_Final(ChaChaPoly_Aead* aead,
    byte outAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE])
{
    int ret = 0;

    if (aead == NULL || outAuthTag == NULL) {
        return BAD_FUNC_ARG;
    }
    if (aead->state != CHACHA20_POLY1305_STATE_AAD &&
        aead->state != CHACHA20_POLY1305_STATE_DATA) {
        return BAD_STATE_E;
    }

    /* Pad the AAD - Make sure it is done */
    if (aead->state == CHACHA20_POLY1305_STATE_AAD) {
        ret = wc_Poly1305_Pad(&aead->poly, aead->aadLen);
    }

    /* Pad the plaintext/ciphertext to 16 bytes */
    if (ret == 0) {
        ret = wc_Poly1305_Pad(&aead->poly, aead->dataLen);
    }

    /* Add the aad length and plaintext/ciphertext length */
    if (ret == 0) {
        ret = wc_Poly1305_EncodeSizes(&aead->poly, aead->aadLen,
            aead->dataLen);
    }

    /* Finalize the auth tag */
    if (ret == 0) {
        ret = wc_Poly1305Final(&aead->poly, outAuthTag);
    }

    /* reset and cleanup sensitive context */
    ForceZero(aead, sizeof(ChaChaPoly_Aead));

    return ret;
}

#ifdef HAVE_XCHACHA

int wc_XChaCha20Poly1305_Init(
    ChaChaPoly_Aead *aead,
    const byte *ad, word32 ad_len,
    const byte *nonce, word32 nonce_len,
    const byte *key, word32 key_len,
    int isEncrypt)
{
    byte authKey[CHACHA20_POLY1305_AEAD_KEYSIZE];
    int ret;

    if ((aead == NULL) || (ad == NULL && ad_len > 0) || (nonce == NULL) ||
        (key == NULL))
        return BAD_FUNC_ARG;

    if ((key_len != CHACHA20_POLY1305_AEAD_KEYSIZE) ||
        (nonce_len != XCHACHA20_POLY1305_AEAD_NONCE_SIZE))
        return BAD_FUNC_ARG;

    if ((ret = wc_XChacha_SetKey(&aead->chacha,
                                 key, key_len,
                                 nonce, nonce_len,
                                 0 /* counter */)) < 0)
        return ret;

    XMEMSET(authKey, 0, sizeof authKey);

    /* Create the Poly1305 key */
    if ((ret = wc_Chacha_Process(&aead->chacha, authKey, authKey,
                                 (word32)sizeof authKey)) < 0)
        goto out;
    /* advance to start of the next ChaCha block. */
    wc_Chacha_purge_current_block(&aead->chacha);

    /* Initialize Poly1305 context */
    if ((ret = wc_Poly1305SetKey(&aead->poly, authKey,
                                 (word32)sizeof authKey)) < 0)
        goto out;

    if ((ret = wc_Poly1305Update(&aead->poly, ad, (word32)ad_len)) < 0)
        goto out;

    if ((ret = wc_Poly1305_Pad(&aead->poly, (word32)ad_len)) < 0)
        goto out;

    aead->isEncrypt = isEncrypt ? 1 : 0;
    aead->state = CHACHA20_POLY1305_STATE_AAD;

    ret = 0;

out:
    ForceZero(authKey, sizeof(authKey));

    return ret;
}

static WC_INLINE int wc_XChaCha20Poly1305_crypt_oneshot(
    byte *dst, const size_t dst_space,
    const byte *src, const size_t src_len,
    const byte *ad, const size_t ad_len,
    const byte *nonce, const size_t nonce_len,
    const byte *key, const size_t key_len,
    int isEncrypt)
{
    int ret;
    size_t dst_len;
    const byte *src_i;
    byte *dst_i;
    size_t src_len_rem;
#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    ChaChaPoly_Aead *aead = (ChaChaPoly_Aead *)XMALLOC(sizeof *aead, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (aead == NULL)
        return MEMORY_E;
#else
    ChaChaPoly_Aead aead_buf, *aead = &aead_buf;
#endif

    if (isEncrypt) {
        if (src_len > (size_t)(CHACHA20_POLY1305_MAX - POLY1305_DIGEST_SIZE)) {
            ret = BAD_FUNC_ARG;
            goto out;
        }
        dst_len = src_len + (size_t)POLY1305_DIGEST_SIZE;
    }
    else {
        if (src_len < POLY1305_DIGEST_SIZE) {
            ret = BAD_FUNC_ARG;
            goto out;
        }
        dst_len = src_len - (size_t)POLY1305_DIGEST_SIZE;
    }

    if ((dst == NULL) || (src == NULL)) {
        ret = BAD_FUNC_ARG;
        goto out;
    }

    if (dst_space < dst_len) {
        ret = BUFFER_E;
        goto out;
    }

    /* Sanity check lengths to prevent truncation when cast to word32. */
    if ((ad_len > WOLFSSL_MAX_32BIT) ||
        (nonce_len > WOLFSSL_MAX_32BIT) ||
        (key_len > WOLFSSL_MAX_32BIT)) {
        ret = BAD_FUNC_ARG;
        goto out;
    }

    if ((ret = wc_XChaCha20Poly1305_Init(aead, ad, (word32)ad_len,
                                         nonce, (word32)nonce_len,
                                         key, (word32)key_len, 1)) < 0)
        goto out;

#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Add("wc_XChaCha20Poly1305_crypt_oneshot aead", aead,
        sizeof(ChaChaPoly_Aead));
#endif

    /* process the input in 16k pieces to accommodate src_lens that don't fit in a word32,
     * and to exploit hot cache for the input data.
     */
    src_i = src;
    src_len_rem = isEncrypt ? src_len : dst_len;
    dst_i = dst;
    while (src_len_rem > 0) {
        word32 this_src_len =
            (src_len_rem > 16384) ?
            16384 :
            (word32)src_len_rem;

        if ((ret = wc_Chacha_Process(&aead->chacha, dst_i, src_i, this_src_len)) < 0)
            goto out;

        if ((ret = wc_Poly1305Update(&aead->poly, isEncrypt ? dst_i : src_i, this_src_len)) < 0)
            goto out;

        src_len_rem -= (size_t)this_src_len;
        src_i += this_src_len;
        dst_i += this_src_len;
    }

    if (aead->poly.leftover) {
        if ((ret = wc_Poly1305_Pad(&aead->poly, (word32)aead->poly.leftover)) < 0)
            goto out;
    }

#ifdef WORD64_AVAILABLE
    ret = wc_Poly1305_EncodeSizes64(&aead->poly, ad_len, isEncrypt ? src_len : dst_len);
#else
    ret = wc_Poly1305_EncodeSizes(&aead->poly, ad_len, isEncrypt ? src_len : dst_len);
#endif
    if (ret < 0)
        goto out;

    if (isEncrypt)
        ret = wc_Poly1305Final(&aead->poly, dst + src_len);
    else {
        byte outAuthTag[POLY1305_DIGEST_SIZE];

        if ((ret = wc_Poly1305Final(&aead->poly, outAuthTag)) < 0)
            goto out;

        if (ConstantCompare(outAuthTag, src + dst_len, POLY1305_DIGEST_SIZE)
            != 0) {
            ForceZero(dst, dst_space);
            ret = MAC_CMP_FAILED_E;
            goto out;
        }
    }

  out:

    ForceZero(aead, sizeof *aead);

#if defined(WOLFSSL_SMALL_STACK) && !defined(WOLFSSL_NO_MALLOC)
    XFREE(aead, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#elif defined(WOLFSSL_CHECK_MEM_ZERO)
    wc_MemZero_Check(aead, sizeof(ChaChaPoly_Aead));
#endif

    return ret;
}

int wc_XChaCha20Poly1305_Encrypt(
    byte *dst, const size_t dst_space,
    const byte *src, const size_t src_len,
    const byte *ad, const size_t ad_len,
    const byte *nonce, const size_t nonce_len,
    const byte *key, const size_t key_len)
{
    return wc_XChaCha20Poly1305_crypt_oneshot(dst, dst_space, src, src_len, ad, ad_len, nonce, nonce_len, key, key_len, 1);
}

int wc_XChaCha20Poly1305_Decrypt(
    byte *dst, const size_t dst_space,
    const byte *src, const size_t src_len,
    const byte *ad, const size_t ad_len,
    const byte *nonce, const size_t nonce_len,
    const byte *key, const size_t key_len)
{
    return wc_XChaCha20Poly1305_crypt_oneshot(dst, dst_space, src, src_len, ad, ad_len, nonce, nonce_len, key, key_len, 0);
}

#endif /* HAVE_XCHACHA */

#endif /* HAVE_CHACHA && HAVE_POLY1305 */
