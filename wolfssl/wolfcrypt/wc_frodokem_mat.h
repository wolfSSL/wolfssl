/* wc_frodokem_mat.h
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
    \file wolfssl/wolfcrypt/wc_frodokem_mat.h
*/

/* Internal-only declarations for the FrodoKEM reference implementation: the
 * run-time parameter set, the assembly dispatch configuration and the low-level
 * matrix / encoding operations shared by wc_frodokem.c and wc_frodokem_mat.c
 * (and the generated inline-assembly _c.c files). The public API and the
 * FrodoKemKey object live in wc_frodokem.h. */

#ifndef WOLF_CRYPT_WC_FRODOKEM_MAT_H
#define WOLF_CRYPT_WC_FRODOKEM_MAT_H

#include <wolfssl/wolfcrypt/wc_frodokem.h>

#ifdef WOLFSSL_HAVE_FRODOKEM

#ifdef __cplusplus
    extern "C" {
#endif

/* When the multi-way AVX2/AVX512 Keccak squeeze routines are compiled in,
 * matrix-A rows for the SHAKE method are generated several at a time: four with
 * AVX2 (sha3_blocksx4_out_avx2), eight with AVX512 (sha3_blocksx8_out_avx512).
 * The one-A-row scratch buffer is widened to hold FRODOKEM_ROW_MULT rows (the
 * widest path compiled in); the runtime path is chosen by CPU features. */
#if defined(WOLFSSL_FRODOKEM_SHAKE) && defined(USE_INTEL_SPEEDUP) && \
    !defined(WC_SHA3_NO_ASM)
    #define FRODOKEM_HAVE_SHAKE_X4
    #ifndef NO_AVX512_SUPPORT
        #define FRODOKEM_HAVE_SHAKE_X8
    #endif
#endif

/* AVX2/AVX512 assembly for the matrix operations: the fused S*A / A*S row
 * accumulates, the small nbar x nbar ops (mul_bs, mul_add_sb_plus_e, add) and
 * the CDF sampler. Available whenever the Intel assembly is built, independent
 * of the matrix-A generation method (AES or SHAKE). */
#if defined(USE_INTEL_SPEEDUP)
    #define FRODOKEM_HAVE_MATRIX_ASM
    #ifndef NO_AVX512_SUPPORT
        #define FRODOKEM_HAVE_MATRIX_ASM_AVX512
    #endif
    /* VAES (vector AES over YMM/ZMM) matrix-A generation. Follows aes.c: the
     * VAES asm is compiled and dispatched unless the build opts out with
     * NO_VAES_SUPPORT, in which case the AES-NI kernel is the widest path. */
    #ifndef NO_VAES_SUPPORT
        #define FRODOKEM_HAVE_MATRIX_ASM_VAES
    #endif
#endif

/* AArch64 NEON assembly: a 2-way SHAKE (two matrix-A rows at once) and NEON
 * matrix ops. NEON is baseline on AArch64, so no runtime feature check. */
#if defined(WOLFSSL_ARMASM) && defined(__aarch64__)
    #define FRODOKEM_HAVE_NEON_ASM
    #ifdef WOLFSSL_FRODOKEM_SHAKE
        #define FRODOKEM_HAVE_SHAKE_NEON
    #endif
/* AArch32 NEON assembly: NEON matrix ops only. There is no 2-way NEON Keccak on
 * AArch32 (the single-stream permutation already uses all 32 d-registers), so
 * matrix A rows are generated one at a time (FRODOKEM_ROW_MULT is 1). Requires
 * NEON (-mfpu=neon) - excludes Thumb2, ARMv6 and other non-NEON ARM targets. */
#elif defined(WOLFSSL_ARMASM) && !defined(WOLFSSL_ARMASM_THUMB2) && \
      !defined(WOLFSSL_ARMASM_NO_NEON) && \
      (defined(__ARM_NEON) || defined(__ARM_NEON__))
    #define FRODOKEM_HAVE_NEON_ASM
/* ARMv7 Thumb2 assembly: matrix ops using the packed dual-16-bit DSP
 * instructions (no NEON). Two coefficients per 32-bit register. Requires the
 * DSP extension (__ARM_FEATURE_DSP, e.g. Cortex-M4/M7/R) - the CDF sampler
 * stays on the C path. Matrix A rows are generated one at a time. */
#elif defined(WOLFSSL_ARMASM) && defined(WOLFSSL_ARMASM_THUMB2) && \
      defined(__ARM_FEATURE_DSP)
    #define FRODOKEM_HAVE_THUMB2_ASM
/* AArch32 (A32) scalar assembly: the same packed dual-16-bit matrix ops as the
 * Thumb2 path, in A32 encoding, for ARMv7-A without NEON (reached only when the
 * NEON branch above did not match, i.e. NEON is absent or disabled via
 * WOLFSSL_ARMASM_NO_NEON) when the 32-bit SIMD instructions (SMLAD/SADD16/PKHBT)
 * are present. The CDF sampler stays on the C path. Matrix A rows are generated
 * one at a time. */
#elif defined(WOLFSSL_ARMASM) && !defined(__aarch64__) && \
      !defined(WOLFSSL_ARMASM_THUMB2) && defined(__ARM_FEATURE_SIMD32)
    #define FRODOKEM_HAVE_ARM32_SIMD32_ASM
#endif

/* The ARM asm variants (AArch64 NEON, AArch32 NEON/Thumb2/SIMD32) present the
 * same matrix-op interface. Alias them to arch-neutral names so the dispatch
 * has a single ARM path; each call generates FRODOKEM_ROW_MULT A rows (four on
 * AArch64 NEON, one on AArch32). The CDF sampler is NEON-only. */
#if defined(FRODOKEM_HAVE_NEON_ASM)
    #define FRODOKEM_HAVE_ARM_ASM
    #define frodokem_add_arm                frodokem_add_neon
    #define frodokem_sa_accum_arm           frodokem_sa_accum_neon
    #define frodokem_as_accum_arm           frodokem_as_accum_neon
    #define frodokem_mul_bs_arm             frodokem_mul_bs_neon
    #define frodokem_mul_add_sb_plus_e_arm  frodokem_mul_add_sb_plus_e_neon
#elif defined(FRODOKEM_HAVE_THUMB2_ASM)
    #define FRODOKEM_HAVE_ARM_ASM
    #define frodokem_add_arm                frodokem_add_thumb2
    #define frodokem_sa_accum_arm           frodokem_sa_accum_thumb2
    #define frodokem_as_accum_arm           frodokem_as_accum_thumb2
    #define frodokem_mul_bs_arm             frodokem_mul_bs_thumb2
    #define frodokem_mul_add_sb_plus_e_arm  frodokem_mul_add_sb_plus_e_thumb2
#elif defined(FRODOKEM_HAVE_ARM32_SIMD32_ASM)
    #define FRODOKEM_HAVE_ARM_ASM
    #define frodokem_add_arm                frodokem_add_simd32
    #define frodokem_sa_accum_arm           frodokem_sa_accum_simd32
    #define frodokem_as_accum_arm           frodokem_as_accum_simd32
    #define frodokem_mul_bs_arm             frodokem_mul_bs_simd32
    #define frodokem_mul_add_sb_plus_e_arm  frodokem_mul_add_sb_plus_e_simd32
#endif

/* AArch64 SVE: a length-agnostic scalable-vector S * A accumulate, emitted
 * into armv8-frodokem-asm.S alongside NEON. Compiled only when explicitly
 * enabled (WOLFSSL_FRODOKEM_SVE) and selected at run time by an AT_HWCAP
 * check, since SVE is optional per CPU (NEON is the always-present fallback).
 * Not available under inline assembly (WOLFSSL_ARMASM_INLINE): the SVE
 * routines are only emitted into the .S file, not the inline C twin, so inline
 * builds fall back to NEON. */
#if defined(FRODOKEM_HAVE_NEON_ASM) && defined(__aarch64__) && \
    defined(WOLFSSL_FRODOKEM_SVE) && !defined(WOLFSSL_ARMASM_INLINE)
    #define FRODOKEM_HAVE_SVE
#endif

/* AArch64 SME: the B * S product via the ZA-tile integer outer product (UMOPA),
 * emitted into armv8-frodokem-asm.S alongside NEON. Compiled only when
 * explicitly enabled (WOLFSSL_FRODOKEM_SME) and selected at run time by an
 * AT_HWCAP2 check. The MOPA needs the B/S matrices in an interleaved layout, so
 * the wrapper transposes into a scratch buffer first. Not available under
 * inline assembly (see FRODOKEM_HAVE_SVE): the SME routines are only in the .S
 * file. */
#if defined(FRODOKEM_HAVE_NEON_ASM) && defined(__aarch64__) && \
    defined(WOLFSSL_FRODOKEM_SME) && !defined(WOLFSSL_ARMASM_INLINE)
    #define FRODOKEM_HAVE_SME
#endif

/* ARMv8 AES matrix-A generation via the crypto extension (AESE/AESMC), emitted
 * into armv8-frodokem-asm.S (AArch64) or armv8-32-frodokem-asm.S (AArch32).
 * Available whenever the ARMv8 AES hardware crypto is present and the NEON
 * matrix path is compiled (AArch32 also requires NEON) - the crypto condition
 * wc_AesEcbEncrypt uses. A single frodokem_gen_a_rows_aes_arm name aliases the
 * arch-specific routine so the dispatch has one AES A-gen call. Not available
 * under inline assembly (WOLFSSL_ARMASM_INLINE): the generator is only in the
 * .S file, not the inline C twin, so inline builds fall back to the per-row C
 * AES A-generator (frodokem_gen_a_rows_aes). */
#if defined(FRODOKEM_HAVE_NEON_ASM) && defined(__aarch64__) && \
    defined(WOLFSSL_FRODOKEM_AES) && !defined(WOLFSSL_ARMASM_NO_HW_CRYPTO) && \
    !defined(WOLFSSL_ARMASM_INLINE)
    #define FRODOKEM_HAVE_ARM64_AES_ASM
    #define FRODOKEM_HAVE_ARM_AES_ASM
    #define frodokem_gen_a_rows_aes_arm  frodokem_gen_a_rows_aes_arm64
#elif defined(FRODOKEM_HAVE_NEON_ASM) && !defined(__aarch64__) && \
    !defined(WOLFSSL_ARMASM_THUMB2) && defined(WOLFSSL_FRODOKEM_AES) && \
    !defined(WOLFSSL_ARMASM_NO_HW_CRYPTO) && !defined(WOLFSSL_ARMASM_INLINE)
    #define FRODOKEM_HAVE_ARM32_AES_ASM
    #define FRODOKEM_HAVE_ARM_AES_ASM
    #define frodokem_gen_a_rows_aes_arm  frodokem_gen_a_rows_aes_arm32
#endif

/* The A-row scratch buffer holds this many rows: the number of A rows generated
 * per generator call (also the outer accumulate loop's row step), used by both
 * the SHAKE and AES paths; the runtime path is chosen by CPU features. On x86
 * this matches the fused accumulate width (8 with AVX512, 4 with AVX2). On
 * AArch64 the AES generator batches four rows so its AES-ECB loop keeps enough
 * blocks in flight to saturate the crypto unit; the driver then accumulates them
 * FRODOKEM_AS_ACCUM_ROWS (two) at a time. */
#if defined(FRODOKEM_HAVE_MATRIX_ASM_AVX512)
    #define FRODOKEM_ROW_MULT   8
#elif defined(USE_INTEL_SPEEDUP)
    #define FRODOKEM_ROW_MULT   4
#elif defined(FRODOKEM_HAVE_NEON_ASM) && defined(__aarch64__)
    #define FRODOKEM_ROW_MULT   4
#else
    /* AArch32 NEON and the portable C path both consume one A row per call. */
    #define FRODOKEM_ROW_MULT   1
#endif

/* Number of A rows a single fused A * S / S * A accumulate call consumes on the
 * ARM paths. The AArch64 accumulate (NEON, and the runtime-interchangeable
 * SVE/SME variants) fuses two rows; AArch32 and the portable C path do one.
 * FRODOKEM_ROW_MULT is a multiple of this, so a generated batch of rows is
 * accumulated this many at a time. */
#if defined(FRODOKEM_HAVE_NEON_ASM) && defined(__aarch64__)
    #define FRODOKEM_AS_ACCUM_ROWS  2
#else
    #define FRODOKEM_AS_ACCUM_ROWS  1
#endif


/* Run-time parameters for a FrodoKEM parameter set. */
struct FrodoKemParams {
    /* Number of rows/columns in the big matrix A. */
    int n;
    /* Number of bits per coefficient - log2 of the modulus q. */
    int d;
    /* Mask to reduce a value modulo q (q - 1). */
    word16 qMask;
    /* Number of bits extracted per coefficient in Encode/Decode. */
    int b;
    /* Cumulative distribution table for error sampling. */
    const word16* cdf;
    /* Number of entries in the CDF table. */
    int cdfLen;
    /* Length of s / pkh / shared secret / message in bytes (lensec / 8). */
    int lenSec;
    /* Use SHAKE256 (1) or SHAKE128 (0) for the hashing function SHAKE. */
    int useShake256;
    /* Encoded public key size in bytes (base parameter set only). */
    int pkSize;
    /* Encoded private key size in bytes (base parameter set only). */
    int skSize;
    /* Length of seedSE in bytes (lenSE / 8). */
    int lenSE;
    /* Length of salt in bytes (lensalt / 8). 0 for eFrodoKEM (ephemeral). */
    int lenSalt;
    /* Ciphertext size in bytes (depends on salt length). */
    int ctSize;
    /* Generate matrix A with AES-128 (1) or SHAKE-128 (0). */
    int useAes;
};


/* Low-level matrix and encoding operations (wc_frodokem_mat.c). */

WOLFSSL_LOCAL void frodokem_init(void);

WOLFSSL_LOCAL void frodokem_pack(byte* out, const word16* in, int nElem, int d);
WOLFSSL_LOCAL void frodokem_unpack(word16* out, const byte* in, int nElem,
    int d);
WOLFSSL_LOCAL void frodokem_store_matrix(byte* out, const word16* mat, int cnt);
WOLFSSL_LOCAL void frodokem_load_matrix(word16* mat, const byte* in, int cnt);

WOLFSSL_LOCAL void frodokem_key_encode(word16* c, const byte* msg, int d,
    int bits);
WOLFSSL_LOCAL void frodokem_key_decode(byte* msg, const word16* c,
    const FrodoKemParams* p);

WOLFSSL_LOCAL int frodokem_shake(const FrodoKemParams* p, wc_Shake* shake,
    const byte* in0, word32 len0, const byte* in1, word32 len1, byte* out,
    word32 outLen);
WOLFSSL_LOCAL int frodokem_shake_oneshot(const FrodoKemParams* p,
    wc_Shake* shake, const byte* in, word32 inLen, byte* out, word32 outLen);
/* seedA = SHAKE(z); z and seedA are both FRODOKEM_SEEDA_SZ bytes, so this is
 * just the one-shot path with those fixed lengths. */
#define frodokem_shake_seeda(p, shake, in, out)                     \
    frodokem_shake_oneshot(p, shake, in, FRODOKEM_SEEDA_SZ, out,     \
        FRODOKEM_SEEDA_SZ)
/* seedSE || k = SHAKE(pkh || u || salt, lenSE + lensec). pkh is lensec bytes;
 * uSalt is u (lensec) followed by salt (lensalt). */
#define frodokem_gen_seedse_k(p, shake, pkh, uSalt, out)            \
    frodokem_shake(p, shake, pkh, (word32)(p)->lenSec, uSalt,       \
        (word32)((p)->lenSec + (p)->lenSalt), out,                  \
        (word32)((p)->lenSE + (p)->lenSec))

WOLFSSL_LOCAL int frodokem_gen_noise(const FrodoKemParams* p, wc_Shake* shake,
    const byte* seInput, byte* tmp, word16* mat0, int cnt0, word16* mat1,
    int cnt1);

/* Compute out += A * S + E (keygen) and out += S * A + E (encaps/decaps),
 * generating matrix A a row (batch) at a time. seedA, the parameters and the
 * SHAKE / AES objects for matrix-A generation are taken from key. */
WOLFSSL_LOCAL int frodokem_mul_add_as_plus_e(FrodoKemKey* key, word16* out,
    const word16* s, word16* row);
WOLFSSL_LOCAL int frodokem_mul_add_sa_plus_e(FrodoKemKey* key, word16* out,
    const word16* s, word16* row);
WOLFSSL_LOCAL void frodokem_mul_add_sb_plus_e(word16* out, const word16* b,
    const word16* s, int n, int qmask);
WOLFSSL_LOCAL void frodokem_mul_bs(word16* out, const word16* b,
    const word16* s, int n, int qmask);
WOLFSSL_LOCAL void frodokem_add(word16* a, const word16* b, int qmask);

#ifdef FRODOKEM_HAVE_MATRIX_ASM
/* Mask cnt contiguous matrix-A coefficients with qmask in one AVX2 pass - the
 * mod-q reduction for the 640 SHAKE path (q == 2^15). cnt is a coefficient
 * count; any leftover after the 16-wide loop is masked one word at a time. */
WOLFSSL_LOCAL void frodokem_a_rows_reduce_avx2(word16* rows, word32 cnt,
    int qmask);
/* Assembly S*A / A*S accumulate for four generated A rows at once (AVX2). */
WOLFSSL_LOCAL void frodokem_sa_accum_avx2(word16* out, const word16* s,
    const word16* row, int j, int n);
WOLFSSL_LOCAL void frodokem_as_accum_avx2(word16* out, const word16* s,
    const word16* row, int i, int n);
#ifdef FRODOKEM_HAVE_MATRIX_ASM_VAES
/* Assembly AES-128-ECB matrix-A row generation + mod-q reduction for cnt rows
 * (AVX2 + VAES). Builds the counter blocks in registers, ECB-encrypts and
 * masks; in is unused. ks is the eleven expanded AES-128 round keys (Aes.key).
 * n must be a multiple of 8 (cnt need not be). */
WOLFSSL_LOCAL void frodokem_gen_a_rows_aes_avx2(byte* in, word16* out,
    const byte* ks, int i, int cnt, int n, int qmask);
#endif
/* Assembly AES-128-ECB matrix-A row generation + mod-q reduction for cnt rows
 * (AVX + AES-NI, no VAES). Builds the AES-ECB counter blocks in registers (no
 * memory build pass), encrypts eight at a time and folds the mask into the
 * store. Used when AVX2 is present but VAES is not (pre-Ice-Lake Intel,
 * pre-Zen4 AMD). in is unused (kept for signature parity); out receives the
 * cnt*n coefficients. ks is the eleven expanded AES-128 round keys (Aes.key).
 * Handles any n that is a multiple of 8 (cnt and n need not be 8-aligned). */
WOLFSSL_LOCAL void frodokem_gen_a_rows_aes_aesni(byte* in, word16* out,
    const byte* ks, int i, int cnt, int n, int qmask);
#endif
#ifdef FRODOKEM_HAVE_MATRIX_ASM_AVX512
/* Assembly S * A / A * S accumulate for eight generated A rows at once
 * (AVX512). */
WOLFSSL_LOCAL void frodokem_sa_accum_avx512(word16* out, const word16* s,
    const word16* row, int j, int n);
WOLFSSL_LOCAL void frodokem_as_accum_avx512(word16* out, const word16* s,
    const word16* row, int i, int n);
#ifdef FRODOKEM_HAVE_MATRIX_ASM_VAES
/* Assembly AES-128-ECB matrix-A row generation + mod-q reduction for cnt rows
 * (AVX512 + VAES). Builds the input blocks, ECB-encrypts and masks; in may
 * alias out. ks is the eleven expanded AES-128 round keys (Aes.key). cnt*2*n
 * must be a multiple of 256 (holds for cnt == 8). */
WOLFSSL_LOCAL void frodokem_gen_a_rows_aes_avx512(byte* in, word16* out,
    const byte* ks, int i, int cnt, int n, int qmask);
#endif
#endif
#ifdef FRODOKEM_HAVE_MATRIX_ASM
/* AVX2 nbar x nbar matrix ops (B*S, S*B+E, add). */
WOLFSSL_LOCAL void frodokem_mul_bs_avx2(word16* out, const word16* b,
    const word16* s, int n, int qmask);
WOLFSSL_LOCAL void frodokem_mul_add_sb_plus_e_avx2(word16* out, const word16* b,
    const word16* s, int n, int qmask);
WOLFSSL_LOCAL void frodokem_add_avx2(word16* a, const word16* b, int qmask);
WOLFSSL_LOCAL void frodokem_sample_avx2(word16* mat, int cnt,
    const word16* cdf, int cdflen);
#endif
#ifdef FRODOKEM_HAVE_MATRIX_ASM_AVX512
/* AVX512 nbar x nbar matrix ops (B*S, S*B+E, add). */
WOLFSSL_LOCAL void frodokem_mul_bs_avx512(word16* out, const word16* b,
    const word16* s, int n, int qmask);
WOLFSSL_LOCAL void frodokem_mul_add_sb_plus_e_avx512(word16* out,
    const word16* b, const word16* s, int n, int qmask);
WOLFSSL_LOCAL void frodokem_add_avx512(word16* a, const word16* b, int qmask);
WOLFSSL_LOCAL void frodokem_sample_avx512(word16* mat, int cnt,
    const word16* cdf, int cdflen);
#endif
#ifdef FRODOKEM_HAVE_SHAKE_NEON
/* AArch64 NEON Keccak-f[1600] permutation on two interleaved states at once
 * (state[0..24] and state[25..49]) - matrix-A SHAKE generates two rows at a
 * time. */
WOLFSSL_LOCAL void frodokem_sha3_x2_neon(word64* state);
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
/* SHA3-crypto-extension twin of frodokem_sha3_x2_neon (EOR3/RAX1/XAR/BCAX),
 * used at run time when the CPU reports FEAT_SHA3. */
WOLFSSL_LOCAL void frodokem_sha3_x2_crypto(word64* state);
#endif
#endif
#ifdef FRODOKEM_HAVE_NEON_ASM
/* AArch64/AArch32 NEON matrix operations. sa/as accumulate FRODOKEM_ROW_MULT
 * generated A rows per call (two on AArch64, one on AArch32); the rest match the
 * Intel routines. */
WOLFSSL_LOCAL void frodokem_sa_accum_neon(word16* out, const word16* s,
    const word16* row, int j, int n);
WOLFSSL_LOCAL void frodokem_sa_accum_x4_neon(word16* out, const word16* s,
    const word16* row, int j, int n);
WOLFSSL_LOCAL void frodokem_as_accum_neon(word16* out, const word16* s,
    const word16* row, int i, int n);
WOLFSSL_LOCAL void frodokem_as_accum_x4_neon(word16* out, const word16* s,
    const word16* row, int i, int n);
WOLFSSL_LOCAL void frodokem_mul_bs_neon(word16* out, const word16* b,
    const word16* s, int n, int qmask);
WOLFSSL_LOCAL void frodokem_mul_add_sb_plus_e_neon(word16* out,
    const word16* b, const word16* s, int n, int qmask);
WOLFSSL_LOCAL void frodokem_add_neon(word16* a, const word16* b, int qmask);
WOLFSSL_LOCAL void frodokem_sample_neon(word16* mat, int cnt,
    const word16* cdf, int cdflen);
#endif
#ifdef FRODOKEM_HAVE_ARM64_AES_ASM
/* AArch64 AES-128-ECB matrix-A row generation + mod-q reduction for cnt rows
 * (ARMv8 crypto extension). Builds the input blocks, ECB-encrypts and masks; in
 * may alias out. ks is the eleven expanded AES-128 round keys (Aes.key). cnt*2*n
 * must be a multiple of 64 (holds for cnt == 2). */
WOLFSSL_LOCAL void frodokem_gen_a_rows_aes_arm64(byte* in, word16* out,
    const byte* ks, int i, int cnt, int n, int qmask);
#endif
#ifdef FRODOKEM_HAVE_ARM32_AES_ASM
/* AArch32 AES-128-ECB matrix-A row generation + mod-q reduction for cnt rows
 * (ARMv8 crypto extension). Builds the input blocks, ECB-encrypts and masks; in
 * may alias out. ks is the eleven expanded AES-128 round keys (Aes.key). cnt*2*n
 * must be a multiple of 32 (holds for cnt == 1). */
WOLFSSL_LOCAL void frodokem_gen_a_rows_aes_arm32(byte* in, word16* out,
    const byte* ks, int i, int cnt, int n, int qmask);
#endif
#ifdef FRODOKEM_HAVE_THUMB2_ASM
/* ARMv7 Thumb2 packed dual-16-bit matrix operations (no NEON). sa/as accumulate
 * one A row per call; the CDF sampler stays on the C path. */
WOLFSSL_LOCAL void frodokem_sa_accum_thumb2(word16* out, const word16* s,
    const word16* row, int j, int n);
WOLFSSL_LOCAL void frodokem_as_accum_thumb2(word16* out, const word16* s,
    const word16* row, int i, int n);
WOLFSSL_LOCAL void frodokem_mul_bs_thumb2(word16* out, const word16* b,
    const word16* s, int n, int qmask);
WOLFSSL_LOCAL void frodokem_mul_add_sb_plus_e_thumb2(word16* out,
    const word16* b, const word16* s, int n, int qmask);
WOLFSSL_LOCAL void frodokem_add_thumb2(word16* a, const word16* b, int qmask);
#endif
#ifdef FRODOKEM_HAVE_ARM32_SIMD32_ASM
/* AArch32 (A32) packed dual-16-bit matrix operations (no NEON) using the 32-bit
 * SIMD instructions (SMLAD/SADD16/PKHBT/...), the A32 encoding of the same
 * kernels as the Thumb2 path. sa/as accumulate one A row per call; the CDF
 * sampler stays on the C path. */
WOLFSSL_LOCAL void frodokem_sa_accum_simd32(word16* out, const word16* s,
    const word16* row, int j, int n);
WOLFSSL_LOCAL void frodokem_as_accum_simd32(word16* out, const word16* s,
    const word16* row, int i, int n);
WOLFSSL_LOCAL void frodokem_mul_bs_simd32(word16* out, const word16* b,
    const word16* s, int n, int qmask);
WOLFSSL_LOCAL void frodokem_mul_add_sb_plus_e_simd32(word16* out,
    const word16* b, const word16* s, int n, int qmask);
WOLFSSL_LOCAL void frodokem_add_simd32(word16* a, const word16* b, int qmask);
#endif
#ifdef FRODOKEM_HAVE_SVE
/* AArch64 SVE scalable-vector matrix accumulates (two A rows per call, matching
 * the NEON interface). Length-agnostic: run on any SVE vector length. */
WOLFSSL_LOCAL void frodokem_sa_accum_sve(word16* out, const word16* s,
    const word16* row, int j, int n);
WOLFSSL_LOCAL void frodokem_as_accum_sve(word16* out, const word16* s,
    const word16* row, int i, int n);
WOLFSSL_LOCAL void frodokem_mul_bs_sve(word16* out, const word16* b,
    const word16* s, int n, int qmask);
WOLFSSL_LOCAL void frodokem_add_sve(word16* a, const word16* b, int qmask);
#endif
#ifdef FRODOKEM_HAVE_SME
/* AArch64 SME B * S (nbar x nbar) via the ZA-tile UMOPA. bt/st are B and S in
 * the interleaved MOPA layout (bt[t*nbar*2 + 2*i + e] = b[i*n + 2*t + e]). */
WOLFSSL_LOCAL void frodokem_mul_bs_sme(word16* out, const word16* bt,
    const word16* st, int n, int qmask);
/* AArch64 SME S * A accumulate (two A rows) via the ZA-tile UMOPA tiled over the
 * n columns. sc is the S column pair (sc[2*i + e] = s[i*n + j + e], 2*nbar
 * word16); row is the natural pair of A rows (the interleave is done in-asm). */
WOLFSSL_LOCAL void frodokem_sa_accum_sme(word16* out, const word16* sc,
    const word16* row, int n);
/* AArch64 SME A * S accumulate (two A rows) via the ZA-tile UMOPA. at/st are the
 * A rows and S in the interleaved MOPA layout (at[t*4 + 2*r + e] = row[r*n + 2*t
 * + e], st[t*nbar*2 + 2*k + e] = s[k*n + 2*t + e]). */
WOLFSSL_LOCAL void frodokem_as_accum_sme(word16* out, const word16* at,
    const word16* st, int i, int n);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLFSSL_HAVE_FRODOKEM */

#endif /* WOLF_CRYPT_WC_FRODOKEM_MAT_H */
