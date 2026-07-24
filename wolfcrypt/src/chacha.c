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
This library contains implementation for the ChaCha20 stream cipher.

Based from chacha-ref.c version 20080118
D. J. Bernstein
Public domain.

*/

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef HAVE_CHACHA
    #include <wolfssl/wolfcrypt/chacha.h>

    #ifdef NO_INLINE
        #include <wolfssl/wolfcrypt/misc.h>
    #else
        #define WOLFSSL_MISC_INCLUDED
        #include <wolfcrypt/src/misc.c>
    #endif

    #ifdef BIG_ENDIAN_ORDER
        #define LITTLE32(x) ByteReverseWord32(x)
    #else
        #define LITTLE32(x) (x)
    #endif

    /* Number of rounds */
    #define ROUNDS  20

    #define U32C(v) (v##U)
    #define U32V(v) ((word32)(v) & U32C(0xFFFFFFFF))
    #define U8TO32_LITTLE(p) LITTLE32(readUnalignedWord32(p))

    #define ROTATE(v,c) rotlFixed(v, c)
    #define XOR(v,w)    ((v) ^ (w))
    #define PLUS(v,w)   (U32V((v) + (w)))
    #define PLUSONE(v)  (PLUS((v),1))

    #define QUARTERROUND(a,b,c,d) \
        x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
        x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
        x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
        x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);
#endif /* HAVE_CHACHA */


/* BEGIN ChaCha C implementation */
#if defined(HAVE_CHACHA)

#include <wolfssl/wolfcrypt/cpuid.h>

#ifdef CHACHA_AEAD_TEST
    #include <stdio.h>
#endif

#ifdef USE_INTEL_CHACHA_SPEEDUP
    #include <emmintrin.h>
    #include <immintrin.h>

    #if defined(__GNUC__) && ((__GNUC__ < 4) || \
                              (__GNUC__ == 4 && __GNUC_MINOR__ <= 8))
        #undef  NO_AVX2_SUPPORT
        #define NO_AVX2_SUPPORT
    #endif
    #if defined(__clang__) && ((__clang_major__ < 3) || \
                               (__clang_major__ == 3 && __clang_minor__ <= 5))
        #undef  NO_AVX2_SUPPORT
        #define NO_AVX2_SUPPORT
    #elif defined(__clang__) && defined(NO_AVX2_SUPPORT)
        #undef NO_AVX2_SUPPORT
    #endif
    #if defined(_MSC_VER) && (_MSC_VER <= 1900)
        #undef  NO_AVX2_SUPPORT
        #define NO_AVX2_SUPPORT
    #endif

    #ifndef NO_AVX2_SUPPORT
        #define HAVE_INTEL_AVX2
    #endif
    #if !defined(NO_AVX512_SUPPORT) && !defined(HAVE_INTEL_AVX512)
        #define HAVE_INTEL_AVX512
    #endif
    /* SSSE3 is the baseline SIMD path, used on CPUs that lack AVX. */
    #ifndef HAVE_INTEL_SSSE3
        #define HAVE_INTEL_SSSE3
    #endif

    static cpuid_flags_t cpuidFlags = WC_CPUID_INITIALIZER;
#endif

/* The aarch64 ChaCha assembly is NEON-only. When NEON might be absent, also
 * build the C implementation: dispatch on ASIMD at runtime when NEON is
 * compiled in, or use only the C path when NEON is disabled at build time. */
#if defined(USE_ARM_CHACHA_SPEEDUP) && defined(__aarch64__)
    #ifdef WOLFSSL_ARMASM_NO_NEON
        #define WOLFSSL_ARM_CHACHA_C_ONLY
    #else
        #define WOLFSSL_ARM_CHACHA_NEON_FALLBACK
    #endif
#endif
#if defined(WOLFSSL_ARM_CHACHA_NEON_FALLBACK) || \
    defined(WOLFSSL_ARM_CHACHA_C_ONLY)
    #define WOLFSSL_ARM_CHACHA_NEED_C
#endif

#ifdef WOLFSSL_ARM_CHACHA_NEON_FALLBACK
    static cpuid_flags_t chacha_cpuid_flags = WC_CPUID_INITIALIZER;
    /* Return non-zero when NEON/ASIMD is present and the asm path should run. */
    static WC_INLINE int chacha_use_neon(void)
    {
        cpuid_get_flags_ex(&chacha_cpuid_flags);
        return IS_AARCH64_ASIMD(chacha_cpuid_flags);
    }
#endif

/**
  * Set up iv(nonce). Earlier versions used 64 bits instead of 96, this version
  * uses the typical AEAD 96 bit nonce and can do record sizes of 256 GB.
  */
int wc_Chacha_SetIV(ChaCha* ctx, const byte* inIv, word32 counter)
{
#if (!defined(USE_ARM_CHACHA_SPEEDUP) || defined(WOLFSSL_ARM_CHACHA_NEED_C)) && \
    !defined(USE_RISCV_CHACHA_SPEEDUP)
    word32 temp[CHACHA_IV_WORDS];/* used for alignment of memory */
#endif

    if (ctx == NULL || inIv == NULL)
        return BAD_FUNC_ARG;

    ctx->left = 0; /* resets state */

#ifdef WOLFSSL_ARM_CHACHA_NEON_FALLBACK
    if (chacha_use_neon())
        wc_chacha_setiv(ctx->X, inIv, counter);
    else
#elif (defined(USE_ARM_CHACHA_SPEEDUP) && !defined(WOLFSSL_ARM_CHACHA_C_ONLY)) || \
    defined(USE_RISCV_CHACHA_SPEEDUP)
    wc_chacha_setiv(ctx->X, inIv, counter);
#endif
#if (!defined(USE_ARM_CHACHA_SPEEDUP) || defined(WOLFSSL_ARM_CHACHA_NEED_C)) && \
    !defined(USE_RISCV_CHACHA_SPEEDUP)
    {
        XMEMCPY(temp, inIv, CHACHA_IV_BYTES);
        /* block counter */
        ctx->X[CHACHA_MATRIX_CNT_IV+0] = counter;
        /* fixed variable from nonce */
        ctx->X[CHACHA_MATRIX_CNT_IV+1] = LITTLE32(temp[0]);
        /* counter from nonce */
        ctx->X[CHACHA_MATRIX_CNT_IV+2] = LITTLE32(temp[1]);
        /* counter from nonce */
        ctx->X[CHACHA_MATRIX_CNT_IV+3] = LITTLE32(temp[2]);
    }
#endif

    return 0;
}

#if (!defined(USE_ARM_CHACHA_SPEEDUP) || defined(WOLFSSL_ARM_CHACHA_NEED_C)) && \
    !defined(USE_RISCV_CHACHA_SPEEDUP)
/* "expand 32-byte k" as unsigned 32 byte */
static const word32 sigma[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
/* "expand 16-byte k" as unsigned 16 byte */
static const word32 tau[4] = {0x61707865, 0x3120646e, 0x79622d36, 0x6b206574};
#endif

/**
  * Key setup. 8 word iv (nonce)
  */
int wc_Chacha_SetKey(ChaCha* ctx, const byte* key, word32 keySz)
{
#if (!defined(USE_ARM_CHACHA_SPEEDUP) || defined(WOLFSSL_ARM_CHACHA_NEED_C)) && \
    !defined(USE_RISCV_CHACHA_SPEEDUP)
    const word32* constants;
    const byte*   k;
#ifdef XSTREAM_ALIGN
    word32 alignKey[8];
#endif
#endif

    if (ctx == NULL || key == NULL)
        return BAD_FUNC_ARG;

    if (keySz != (CHACHA_MAX_KEY_SZ/2) && keySz != CHACHA_MAX_KEY_SZ)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_ARM_CHACHA_NEON_FALLBACK
    if (chacha_use_neon())
        wc_chacha_setkey(ctx->X, key, keySz);
    else
#elif (defined(USE_ARM_CHACHA_SPEEDUP) && !defined(WOLFSSL_ARM_CHACHA_C_ONLY)) || \
    defined(USE_RISCV_CHACHA_SPEEDUP)
    wc_chacha_setkey(ctx->X, key, keySz);
#endif
#if (!defined(USE_ARM_CHACHA_SPEEDUP) || defined(WOLFSSL_ARM_CHACHA_NEED_C)) && \
    !defined(USE_RISCV_CHACHA_SPEEDUP)
    {
#ifdef XSTREAM_ALIGN
    if ((wc_ptr_t)key % 4) {
        WOLFSSL_MSG("wc_ChachaSetKey unaligned key");
        XMEMCPY(alignKey, key, keySz);
        k = (byte*)alignKey;
    }
    else {
        k = key;
    }
#else
    k = key;
#endif /* XSTREAM_ALIGN */

#ifdef CHACHA_AEAD_TEST
    word32 i;
    printf("ChaCha key used :\n");
    for (i = 0; i < keySz; i++) {
        printf("%02x", key[i]);
        if ((i + 1) % 8 == 0)
           printf("\n");
    }
    printf("\n\n");
#endif

    ctx->X[4] = U8TO32_LITTLE(k +  0);
    ctx->X[5] = U8TO32_LITTLE(k +  4);
    ctx->X[6] = U8TO32_LITTLE(k +  8);
    ctx->X[7] = U8TO32_LITTLE(k + 12);
    if (keySz == CHACHA_MAX_KEY_SZ) {
        k += 16;
        constants = sigma;
    }
    else {
        constants = tau;
    }
    ctx->X[ 8] = U8TO32_LITTLE(k +  0);
    ctx->X[ 9] = U8TO32_LITTLE(k +  4);
    ctx->X[10] = U8TO32_LITTLE(k +  8);
    ctx->X[11] = U8TO32_LITTLE(k + 12);
    ctx->X[ 0] = constants[0];
    ctx->X[ 1] = constants[1];
    ctx->X[ 2] = constants[2];
    ctx->X[ 3] = constants[3];
    }
#endif

    ctx->left = 0; /* resets state */

    return 0;
}

#if (!defined(USE_INTEL_CHACHA_SPEEDUP) && !defined(USE_ARM_CHACHA_SPEEDUP) && \
    !defined(USE_RISCV_CHACHA_SPEEDUP)) || defined(WOLFSSL_ARM_CHACHA_NEED_C)
/**
  * Converts word into bytes with rotations having been done.
  */
static WC_INLINE void wc_Chacha_wordtobyte(word32 x[CHACHA_CHUNK_WORDS],
        word32 state[CHACHA_CHUNK_WORDS])
{
    word32 i;

    XMEMCPY(x, state, CHACHA_CHUNK_BYTES);

    for (i = (ROUNDS); i > 0; i -= 2) {
        QUARTERROUND(0, 4,  8, 12)
        QUARTERROUND(1, 5,  9, 13)
        QUARTERROUND(2, 6, 10, 14)
        QUARTERROUND(3, 7, 11, 15)
        QUARTERROUND(0, 5, 10, 15)
        QUARTERROUND(1, 6, 11, 12)
        QUARTERROUND(2, 7,  8, 13)
        QUARTERROUND(3, 4,  9, 14)
    }

    for (i = 0; i < CHACHA_CHUNK_WORDS; i++) {
        x[i] = PLUS(x[i], state[i]);
#ifdef BIG_ENDIAN_ORDER
        x[i] = LITTLE32(x[i]);
#endif
    }
}
#endif /* !USE_INTEL_CHACHA_SPEEDUP */

#ifdef __cplusplus
    extern "C" {
#endif

extern void chacha_encrypt_x64(ChaCha* ctx, const byte* m, byte* c,
                               word32 bytes);
extern void chacha_encrypt_avx1(ChaCha* ctx, const byte* m, byte* c,
                                word32 bytes);
extern void chacha_encrypt_avx2(ChaCha* ctx, const byte* m, byte* c,
                                word32 bytes);
extern void chacha_encrypt_avx512(ChaCha* ctx, const byte* m, byte* c,
                                  word32 bytes);
extern void chacha_encrypt_avx512vl(ChaCha* ctx, const byte* m, byte* c,
                                    word32 bytes);
/* Not exported (WOLFSSL_LOCAL/hidden): its _sse3 (SSSE3) suffix is not in the
 * symbol-prefix allowlist, and internal asm helpers should not be exported. */
WOLFSSL_LOCAL void chacha_encrypt_sse3(ChaCha* ctx, const byte* m, byte* c,
                                word32 bytes);

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#if defined(USE_INTEL_CHACHA_SPEEDUP) && defined(HAVE_INTEL_AVX512)
/* Decide whether to use the 512-bit (zmm) ChaCha path for this CPU.
 *
 * The zmm path processes 16 blocks at a time and is the fastest option on
 * microarchitectures that run 512-bit code at full clock: AMD Zen 4/5 (no
 * AVX-512 license) and Intel Ice Lake and later.  On Intel Skylake-SP /
 * Cascade Lake-class parts, sustained 512-bit instructions trip the AVX-512
 * frequency license and downclock the core - enough that the 256-bit AVX2 path
 * is faster in practice (this matches OpenSSL, which suppresses its 16x zmm
 * ChaCha there, and the Linux kernel, which uses only 256-bit AVX-512VL).
 *
 * There is no direct "does this core downclock" CPUID bit, so VAES presence is
 * used as a generational proxy: the throttling parts (Skylake-SP / Skylake-X /
 * Cascade Lake) predate VAES, whereas every microarchitecture that runs 512-bit
 * without penalty (AMD Zen 4/5, Intel Ice Lake+) implements it.  A missing VAES
 * only costs a little throughput (fall back to AVX2), never correctness.
 *
 * Override the heuristic with:
 *   WOLFSSL_CHACHA20_AVX512_ALWAYS - use zmm whenever AVX-512 is present
 *   WOLFSSL_CHACHA20_AVX512_NEVER  - never use zmm (always AVX2 or below)
 */
static WC_INLINE int chacha_avx512_beneficial(cpuid_flags_t flags)
{
#if defined(WOLFSSL_CHACHA20_AVX512_NEVER)
    (void)flags;
    return 0;
#elif defined(WOLFSSL_CHACHA20_AVX512_ALWAYS)
    return IS_INTEL_AVX512(flags) != 0;
#else
    return (IS_INTEL_AVX512(flags) != 0) && (IS_INTEL_VAES(flags) != 0);
#endif
}
#endif /* USE_INTEL_CHACHA_SPEEDUP && HAVE_INTEL_AVX512 */


#if (!defined(USE_INTEL_CHACHA_SPEEDUP) && !defined(USE_ARM_CHACHA_SPEEDUP) && \
    !defined(USE_RISCV_CHACHA_SPEEDUP)) || defined(WOLFSSL_ARM_CHACHA_NEED_C)
/**
  * Encrypt a stream of bytes
  */
static void wc_Chacha_encrypt_bytes(ChaCha* ctx, const byte* m, byte* c,
                                    word32 bytes)
{
    union {
        byte state[CHACHA_CHUNK_BYTES];
        word32 state32[CHACHA_CHUNK_WORDS];
        wolfssl_word align_word; /* align for xorbufout */
    } tmp;

    /* handle left overs */
    if (bytes > 0 && ctx->left > 0) {
        word32 processed = min(bytes, ctx->left);
        wc_Chacha_wordtobyte(tmp.state32, ctx->X); /* recreate the stream */
        xorbufout(c, m, tmp.state + CHACHA_CHUNK_BYTES - ctx->left, processed);
        ctx->left -= processed;

        /* Used up all of the stream that was left, increment the counter */
        if (ctx->left == 0) {
            ctx->X[CHACHA_MATRIX_CNT_IV] =
                                          PLUSONE(ctx->X[CHACHA_MATRIX_CNT_IV]);
        }
        bytes -= processed;
        c += processed;
        m += processed;
    }

    while (bytes >= CHACHA_CHUNK_BYTES) {
        wc_Chacha_wordtobyte(tmp.state32, ctx->X);
        ctx->X[CHACHA_MATRIX_CNT_IV] = PLUSONE(ctx->X[CHACHA_MATRIX_CNT_IV]);
        xorbufout(c, m, tmp.state, CHACHA_CHUNK_BYTES);
        bytes -= CHACHA_CHUNK_BYTES;
        c += CHACHA_CHUNK_BYTES;
        m += CHACHA_CHUNK_BYTES;
    }

    if (bytes) {
        /* in this case there will always be some left over since bytes is less
         * than CHACHA_CHUNK_BYTES, so do not increment counter after getting
         * stream in order for the stream to be recreated on next call */
        wc_Chacha_wordtobyte(tmp.state32, ctx->X);
        xorbufout(c, m, tmp.state, bytes);
        ctx->left = CHACHA_CHUNK_BYTES - bytes;
    }
}
#endif /* !USE_INTEL_CHACHA_SPEEDUP */


/**
  * API to encrypt/decrypt a message of any size.
  */
int wc_Chacha_Process(ChaCha* ctx, byte* output, const byte* input,
                      word32 msglen)
{
    if (ctx == NULL || input == NULL || output == NULL)
        return BAD_FUNC_ARG;

#ifdef USE_INTEL_CHACHA_SPEEDUP
    /* handle left overs */
    if (msglen > 0 && ctx->left > 0) {
        byte*  out;
        word32 processed = min(msglen, ctx->left);

        out = (byte*)ctx->over + CHACHA_CHUNK_BYTES - ctx->left;
        xorbufout(output, input, out, processed);
        ctx->left -= processed;
        msglen -= processed;
        output += processed;
        input += processed;
    }

    if (msglen == 0) {
        return 0;
    }

    cpuid_get_flags_ex(&cpuidFlags);

    /* One block or less. */
#if defined(HAVE_INTEL_AVX1) && !defined(WOLFSSL_LINUXKM)
    /* In userspace SAVE_VECTOR_REGISTERS is free, so a single AVX block (~285
     * cyc) beats the scalar block (~435) - e.g. the per-record Poly1305 key
     * derivation (a 32-byte ChaCha) in the ChaCha20-Poly1305 two-pass path.
     * The AVX-512VL path already uses SIMD for one block; match that here. */
    if (msglen <= CHACHA_CHUNK_BYTES && IS_INTEL_AVX512VL(cpuidFlags) == 0 &&
            IS_INTEL_AVX1(cpuidFlags)) {
        SAVE_VECTOR_REGISTERS(return _svr_ret;);
        chacha_encrypt_avx1(ctx, input, output, msglen);
        RESTORE_VECTOR_REGISTERS();
        return 0;
    }
#endif
    /* At most one block: the scalar path avoids the SIMD broadcast/transpose
     * setup and (in the Linux kernel module) the costly vector-register
     * save/restore. */
    if (msglen <= CHACHA_CHUNK_BYTES) {
        chacha_encrypt_x64(ctx, input, output, msglen);
        return 0;
    }

    /* 65..255 bytes without AVX-512VL: use the SSSE3 128-bit exact-block path.
     * It is ~1.8x the scalar path and beats the 8-block AVX2 kernel (which
     * always emits a full 512-byte key stream) below 256 bytes - e.g. a
     * 192-byte key stream is 735 vs 1335 (scalar) vs 836 (AVX2) cycles on
     * Coffee Lake.  This is the ChaCha20-Poly1305 short-record hot path (poly
     * key + <=2 data blocks).  At >=256 bytes the four-block AVX2/AVX1 kernels
     * take over below. */
#ifdef HAVE_INTEL_SSSE3
    if (IS_INTEL_AVX512VL(cpuidFlags) == 0 &&
            msglen < 4 * CHACHA_CHUNK_BYTES &&
            IS_INTEL_SSSE3(cpuidFlags)) {
        SAVE_VECTOR_REGISTERS(return _svr_ret;);
        chacha_encrypt_sse3(ctx, input, output, msglen);
        RESTORE_VECTOR_REGISTERS();
        return 0;
    }
#endif
    if (IS_INTEL_AVX512VL(cpuidFlags) == 0 &&
            msglen < 4 * CHACHA_CHUNK_BYTES) {
        chacha_encrypt_x64(ctx, input, output, msglen);
        return 0;
    }

    #ifdef HAVE_INTEL_AVX512
    /* Below one 16-block chunk (1024 bytes) the zmm path does no work and
     * just tail-calls AVX2, so dispatch straight to AVX2 for smaller input. */
    if (chacha_avx512_beneficial(cpuidFlags) &&
            msglen >= 16 * CHACHA_CHUNK_BYTES) {
        SAVE_VECTOR_REGISTERS(return _svr_ret;);
        chacha_encrypt_avx512(ctx, input, output, msglen);
        RESTORE_VECTOR_REGISTERS();
        return 0;
    }
    /* Everything below the AVX2 512-byte minimum (1..511 bytes) is handled by
     * the AVX-512VL path itself - whole 256-byte four-block chunks plus a
     * partial four-block tail - using single-instruction vprold rotations on
     * 128-bit registers (no AVX-512 frequency penalty).  It does not fall back
     * to any other implementation. */
    if (IS_INTEL_AVX512VL(cpuidFlags) && msglen < 8 * CHACHA_CHUNK_BYTES) {
        SAVE_VECTOR_REGISTERS(return _svr_ret;);
        chacha_encrypt_avx512vl(ctx, input, output, msglen);
        RESTORE_VECTOR_REGISTERS();
        return 0;
    }
    #endif
    #ifdef HAVE_INTEL_AVX2
    if (IS_INTEL_AVX2(cpuidFlags)) {
        SAVE_VECTOR_REGISTERS(return _svr_ret;);
        chacha_encrypt_avx2(ctx, input, output, msglen);
        RESTORE_VECTOR_REGISTERS();
        return 0;
    }
    #endif
    if (IS_INTEL_AVX1(cpuidFlags)) {
        SAVE_VECTOR_REGISTERS(return _svr_ret;);
        chacha_encrypt_avx1(ctx, input, output, msglen);
        RESTORE_VECTOR_REGISTERS();
        return 0;
    }
    #ifdef HAVE_INTEL_SSSE3
    else if (IS_INTEL_SSSE3(cpuidFlags)) {
        SAVE_VECTOR_REGISTERS(return _svr_ret;);
        chacha_encrypt_sse3(ctx, input, output, msglen);
        RESTORE_VECTOR_REGISTERS();
        return 0;
    }
    #endif
    else {
        chacha_encrypt_x64(ctx, input, output, msglen);
        return 0;
    }
#elif defined(USE_ARM_CHACHA_SPEEDUP) || defined(USE_RISCV_CHACHA_SPEEDUP)
#ifdef WOLFSSL_ARM_CHACHA_NEON_FALLBACK
    if (chacha_use_neon())
#endif
#ifndef WOLFSSL_ARM_CHACHA_C_ONLY
    {
        /* Handle left over bytes from last block. */
        if ((msglen > 0) && (ctx->left > 0)) {
            byte* over = ((byte*)ctx->over) + CHACHA_CHUNK_BYTES - ctx->left;
            word32 l = min(msglen, ctx->left);

            wc_chacha_use_over(over, output, input, l);

            ctx->left -= l;
            input += l;
            output += l;
            msglen -= l;
        }

        if (msglen != 0) {
            wc_chacha_crypt_bytes(ctx, output, input, msglen);
        }
        return 0;
    }
#endif
#ifdef WOLFSSL_ARM_CHACHA_NEED_C
#ifdef WOLFSSL_ARM_CHACHA_NEON_FALLBACK
    else
#endif
    {
        wc_Chacha_encrypt_bytes(ctx, input, output, msglen);
        return 0;
    }
#endif
#else
    wc_Chacha_encrypt_bytes(ctx, input, output, msglen);
    return 0;
#endif
}
#endif /* HAVE_CHACHA */
/* END ChaCha C implementation */

#if defined(HAVE_CHACHA) && defined(HAVE_XCHACHA)

void wc_Chacha_purge_current_block(ChaCha* ctx)
{
    if (ctx->left > 0) {
        byte scratch[CHACHA_CHUNK_BYTES];
        XMEMSET(scratch, 0, sizeof(scratch));
        (void)wc_Chacha_Process(ctx, scratch, scratch, CHACHA_CHUNK_BYTES - ctx->left);
    }
}

/*
 * wc_HChacha_block - half a ChaCha block, for XChaCha
 *
 * see https://tools.ietf.org/html/draft-arciszewski-xchacha-03
 */
static WC_INLINE void wc_HChacha_block(ChaCha* ctx,
    word32 stream[CHACHA_CHUNK_WORDS/2], word32 nrounds)
{
    word32 x[CHACHA_CHUNK_WORDS];
    word32 i;

    for (i = 0; i < CHACHA_CHUNK_WORDS; i++) {
        x[i] = ctx->X[i];
    }

    for (i = nrounds; i > 0; i -= 2) {
        QUARTERROUND(0, 4,  8, 12)
        QUARTERROUND(1, 5,  9, 13)
        QUARTERROUND(2, 6, 10, 14)
        QUARTERROUND(3, 7, 11, 15)
        QUARTERROUND(0, 5, 10, 15)
        QUARTERROUND(1, 6, 11, 12)
        QUARTERROUND(2, 7,  8, 13)
        QUARTERROUND(3, 4,  9, 14)
    }

    for (i = 0; i < CHACHA_CHUNK_WORDS/4; ++i)
        stream[i] = x[i];
    for (i = CHACHA_CHUNK_WORDS/4; i < CHACHA_CHUNK_WORDS/2; ++i)
        stream[i] = x[i + CHACHA_CHUNK_WORDS/2];
}

/* XChaCha -- https://tools.ietf.org/html/draft-arciszewski-xchacha-03 */
int wc_XChacha_SetKey(ChaCha *ctx,
                      const byte *key, word32 keySz,
                      const byte *nonce, word32 nonceSz,
                      word32 counter)
{
    int ret;
    word32 k[CHACHA_MAX_KEY_SZ];
    byte   iv[CHACHA_IV_BYTES];

    if (nonceSz != XCHACHA_NONCE_BYTES)
        return BAD_FUNC_ARG;

    if ((ret = wc_Chacha_SetKey(ctx, key, keySz)) < 0)
        return ret;

    /* form a first chacha IV from the first 16 bytes of the nonce.
     * the first word is supplied in the "counter" arg, and
     * the result is a full 128 bit nonceful IV for the one-time block
     * crypto op that follows.
     */
    if ((ret = wc_Chacha_SetIV(ctx, nonce + 4, U8TO32_LITTLE(nonce))) < 0)
        return ret;

    wc_HChacha_block(ctx, k, 20); /* 20 rounds, but keeping half the output. */

    /* the HChacha output is used as a 256 bit key for the main cipher. */
    XMEMCPY(&ctx->X[4], k, 8 * sizeof(word32));

    /* use 8 bytes from the end of the 24 byte nonce, padded up to 12 bytes,
     * to form the IV for the main cipher.
     */
    XMEMSET(iv, 0, 4);
    XMEMCPY(iv + 4, nonce + 16, 8);

    if ((ret = wc_Chacha_SetIV(ctx, iv, counter)) < 0)
        return ret;

    ForceZero(k, sizeof k);
    ForceZero(iv, sizeof iv);

    return 0;
}

#endif /* HAVE_CHACHA && HAVE_XCHACHA */
