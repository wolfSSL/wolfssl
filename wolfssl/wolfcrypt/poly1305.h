/* poly1305.h
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
    \file wolfssl/wolfcrypt/poly1305.h
*/

#ifndef WOLF_CRYPT_POLY1305_H
#define WOLF_CRYPT_POLY1305_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_POLY1305

#ifdef __cplusplus
    extern "C" {
#endif

/* auto detect between 32bit / 64bit */
#if defined(__SIZEOF_INT128__) && defined(__LP64__)
#define WC_HAS_SIZEOF_INT128_64BIT
#endif

#if defined(_MSC_VER) && defined(_M_X64)
#define WC_HAS_MSVC_64BIT
#endif

#if (defined(__GNUC__) && defined(__LP64__) && \
        ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 4))))
#define WC_HAS_GCC_4_4_64BIT
#endif

#ifdef WOLFSSL_X86_64_BUILD
#if defined(USE_INTEL_SPEEDUP) && !defined(NO_POLY1305_ASM)
    #define USE_INTEL_POLY1305_SPEEDUP
    #define HAVE_INTEL_AVX1
    /* 8-way AVX-512 path.  Enabling it appends r^5..r^8 to the state (see the
     * struct below); define WOLFSSL_POLY1305_NO_AVX512 to keep the smaller
     * state and drop the path. */
    #if !defined(WOLFSSL_POLY1305_NO_AVX512)
        #define WOLFSSL_POLY1305_AVX512
    #endif
    /* Fused single-pass ChaCha20-Poly1305 (encrypt).  It drives Poly1305 in the
     * 4-way layout, so the ctx carries a flag forcing that path. */
    #if !defined(WOLFSSL_NO_CHACHA20_POLY1305_FUSED)
        #define WOLFSSL_CHACHA20_POLY1305_FUSED
    #endif
    /* IFMA stitched single-pass ChaCha20-Poly1305 (AVX-512 + IFMA): a full
     * 512-bit 16-block ChaCha interleaved with an 8-way IFMA (vpmadd52)
     * Poly1305 that collapses to the scalar hash.  It BEATS the two-pass by
     * ~1.3-1.4x (>=16KB) - ChaCha is the bottleneck and Poly hides under it -
     * so it is ON by default and runtime-gated on the AVX-512 + IFMA flags.
     * Needs the AVX-512 IFMA state (r^1..r^8, ifma_h), so it follows
     * WOLFSSL_POLY1305_AVX512.  Define WOLFSSL_NO_CHACHA20_POLY1305_FUSED_IFMA
     * to drop it; it drives Poly1305 scalar via the forceScalar flag. */
    #if defined(WOLFSSL_POLY1305_AVX512) && \
        !defined(WOLFSSL_NO_CHACHA20_POLY1305_FUSED_IFMA)
        #define WOLFSSL_CHACHA20_POLY1305_FUSED_IFMA
    #endif
#endif
#endif

#if defined(USE_INTEL_POLY1305_SPEEDUP)
#elif (defined(WC_HAS_SIZEOF_INT128_64BIT) || defined(WC_HAS_MSVC_64BIT) ||  \
       defined(WC_HAS_GCC_4_4_64BIT)) && !defined(WOLFSSL_W64_WRAPPER_TEST)
#define POLY130564
#else
#define POLY130532
#endif

/* The aarch64 Poly1305 assembly is NEON-only. Provide a software fallback:
 * dispatch on ASIMD at runtime when NEON is built in, or use only the C path
 * when NEON is disabled at build time. */
#if defined(WOLFSSL_ARMASM) && defined(__aarch64__)
    #ifdef WOLFSSL_ARMASM_NO_NEON
        #define WOLFSSL_ARM_POLY1305_C_ONLY
    #else
        #define WOLFSSL_ARM_POLY1305_NEON_FALLBACK
    #endif
    #define WOLFSSL_ARM_POLY1305_NEED_C
#endif

enum {
    POLY1305 = 7,
    POLY1305_BLOCK_SIZE = 16,
    POLY1305_DIGEST_SIZE = 16
};

#define WC_POLY1305_PAD_SZ 16
#define WC_POLY1305_MAC_SZ 16

/* Poly1305 state */
typedef struct Poly1305 {
#ifdef USE_INTEL_POLY1305_SPEEDUP
    word64 r[3];
    word64 h[3];
    word64 pad[2];
    word64 hh[20];
    word32 r1[8];
    word32 r2[8];
    word32 r3[8];
    word32 r4[8];
    word64 hm[16];
    unsigned char buffer[8*POLY1305_BLOCK_SIZE];
    size_t leftover;
    unsigned char finished;
    unsigned char started;
#ifdef WOLFSSL_POLY1305_AVX512
    /* r^5..r^8 for the 8-way path, appended so the AVX1/AVX2 field offsets are
     * unchanged.  ALIGN8 keeps each power 8-byte aligned (26-bit limb packing
     * matches r1..r4). */
    ALIGN8 word32 r5[8];
    word32 r6[8];
    word32 r7[8];
    word32 r8[8];
    /* IFMA path (radix 2^44) keeps r^1..r^8 in the r1..r8 fields above (three
     * 44-bit limbs each) and its eight-lane running hash here: three limbs x
     * eight lanes x 64-bit.  hh (32-bit packed) is too small for 44-bit lanes.
     */
    ALIGN8 word64 ifma_h[24];
#endif
#ifdef WOLFSSL_CHACHA20_POLY1305_FUSED
    /* When set, wc_Poly1305Update/Final use the 4-way path so the fused
     * ChaCha20-Poly1305 kernel (also 4-way) stays layout-consistent. */
    unsigned char forceAvx2;
#endif
#ifdef WOLFSSL_CHACHA20_POLY1305_FUSED_IFMA
    /* When set, wc_Poly1305Update/Final use the scalar path so the fused IFMA
     * ChaCha20-Poly1305 stitch (which finishes in the scalar hash) stays
     * layout-consistent. */
    unsigned char forceScalar;
#endif
#elif defined(WOLFSSL_ARMASM) && defined(__aarch64__)
    ALIGN8 word64 r64[2];
    ALIGN8 word32 r4[4];
    ALIGN8 word32 r3[4];
    ALIGN8 word32 r2[4];
    ALIGN8 word32 r1[4];
    ALIGN8 word32 r4321[4];
    ALIGN8 word32 h[6];
    ALIGN8 word32 pad[4];
    word64 leftover;
    unsigned char buffer[POLY1305_BLOCK_SIZE];
    unsigned char finished;
#ifdef WOLFSSL_ARM_POLY1305_NEED_C
    /* Software fallback state (radix 2^44), used when NEON is unavailable.
     * Appended after the assembly state so the asm field offsets are unchanged.
     */
    word64 c_r[3];
    word64 c_h[3];
    word64 c_pad[2];
#endif
#elif defined(WOLFSSL_ARMASM) && !defined(WOLFSSL_ARMASM_THUMB2) && \
    !defined(WOLFSSL_ARMASM_NO_NEON)
    /* NEON implementation for ARM32 */
    word32 r[4];
    word32 h[6];
    word32 pad[4];
    word32 leftover;
    unsigned char buffer[4*POLY1305_BLOCK_SIZE];
    word32 r_21[10];
    word32 r_43[10];
    unsigned char finished;
#elif defined(WOLFSSL_ARMASM)
    /* ARM32 (non-NEON) and Thumb2 */
    word32 r[4];
    word32 h[5];
    word32 pad[4];
    word32 leftover;
    unsigned char buffer[POLY1305_BLOCK_SIZE];
    unsigned char finished;
#elif defined(WOLFSSL_RISCV_ASM)
    /* Same layout/offsets as the generic POLY130564 struct (the scalar/base
     * asm and common C depend on these offsets: r=0, h=24, pad=48, leftover=64,
     * buffer=72, finished=88). */
    word64 r[3];
    word64 h[3];
    word64 pad[2];
    size_t leftover;
    unsigned char buffer[POLY1305_BLOCK_SIZE];
    unsigned char finished;
#ifdef WOLFSSL_RISCV_VECTOR
    /* Powers of r for the vector blocks path (44/44/42-bit limbs), stored as eight
     * contiguous power-arrays so a single strided vector load gathers one limb's
     * [r^4|r^3|r^2|r^1] (4-block, at r2[0]) or [r^8|r^7|r^6|r^5] (8-block pass A, at
     * r2[12]) or [r^2|r^1] (2-block tail).  Layout (word64):
     *   r2[0..2]=r^4, r2[3..5]=r^3, r2[6..8]=r^2, r2[9..11]=r^1,
     *   r2[12..14]=r^8, r2[15..17]=r^7, r2[18..20]=r^6, r2[21..23]=r^5.
     * Placed AFTER finished so the offsets above are unchanged. */
    word64 r2[24];
    /* Lazily-computed-powers level (offset 288): 0=none, 1=r^2 ready, 2=r^2..r^4
     * ready, 3=r^2..r^8 ready.  SetKey clears it; the blocks path computes only the
     * powers a given message size needs, so small messages skip the power setup. */
    unsigned char r2_level;
#endif
#else
#if defined(POLY130564)
    word64 r[3];
    word64 h[3];
    word64 pad[2];
#else
    word32 r[5];
    word32 h[5];
    word32 pad[4];
#endif
    size_t leftover;
    unsigned char buffer[POLY1305_BLOCK_SIZE];
    unsigned char finished;
#endif /* USE_INTEL_POLY1305_SPEEDUP */
} Poly1305;

/* does init */

WOLFSSL_API int wc_Poly1305SetKey(Poly1305* poly1305, const byte* key,
    word32 kySz);
WOLFSSL_API int wc_Poly1305Update(Poly1305* poly1305, const byte* m, word32 bytes);
WOLFSSL_API int wc_Poly1305Final(Poly1305* poly1305, byte* tag);

/* AEAD Functions */
WOLFSSL_API int wc_Poly1305_Pad(Poly1305* ctx, word32 lenToPad);
WOLFSSL_API int wc_Poly1305_EncodeSizes(Poly1305* ctx, word32 aadSz,
    word32 dataSz);
#ifdef WORD64_AVAILABLE
WOLFSSL_API int wc_Poly1305_EncodeSizes64(Poly1305* ctx, word64 aadSz,
     word64 dataSz);
#endif
WOLFSSL_API int wc_Poly1305_MAC(Poly1305* ctx, const byte* additional,
    word32 addSz, const byte* input, word32 sz, byte* tag, word32 tagSz);

#if defined(WOLFSSL_ARMASM)
#if defined(__aarch64__ )
void poly1305_arm64_block_16(Poly1305* ctx, const unsigned char* m);
void poly1305_arm64_blocks(Poly1305* ctx, const unsigned char* m, size_t bytes);
#elif defined(WOLFSSL_ARMASM_THUMB2)
void poly1305_blocks_thumb2(Poly1305* ctx, const unsigned char *m,
    size_t bytes);
void poly1305_block_thumb2(Poly1305* ctx, const unsigned char *m);

void poly1305_blocks_thumb2_16(Poly1305* ctx, const unsigned char* m,
    word32 len, int notLast);
#else
void poly1305_blocks_arm32(Poly1305* ctx, const unsigned char *m, size_t bytes);
void poly1305_block_arm32(Poly1305* ctx, const unsigned char *m);

void poly1305_arm32_blocks(Poly1305* ctx, const unsigned char* m, word32 len);
void poly1305_arm32_blocks_16(Poly1305* ctx, const unsigned char* m, word32 len,
    int notLast);
#endif

void poly1305_set_key(Poly1305* ctx, const byte* key);
void poly1305_final(Poly1305* ctx, byte* mac);
#endif /* WOLFSSL_ARMASM */

#if defined(WOLFSSL_RISCV_ASM)
#define poly1305_blocks     poly1305_blocks_riscv64

void poly1305_blocks_riscv64(Poly1305* ctx, const unsigned char *m,
    size_t bytes);
void poly1305_block_16_riscv64(Poly1305* ctx, const unsigned char *m);
void poly1305_set_key_riscv64(Poly1305* ctx, const byte* key);
void poly1305_final_riscv64(Poly1305* ctx, byte* mac);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_POLY1305 */
#endif /* WOLF_CRYPT_POLY1305_H */
