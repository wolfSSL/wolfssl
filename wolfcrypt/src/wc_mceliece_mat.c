/* wc_mceliece_mat.c
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

/* Classic McEliece field, polynomial, matrix and code machinery.
 *
 * Implementation based on:
 *   https://www.ietf.org/archive/id/draft-josefsson-mceliece-05.txt
 * and the algorithms of the Classic McEliece NIST submission (public domain).
 *
 * All parameter sets use m = 13, so the field GF(2^13), the Benes network
 * (2m-1 = 25 stages over 2^13 elements) and the control-bit logic are shared;
 * only n and t vary and are taken from the McElieceParams passed in.
 */

#define _WC_BUILDING_WC_MCELIECE_MAT_C

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/wolfcrypt/wc_mceliece_mat.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/memory.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef WOLFSSL_HAVE_MCELIECE

/* Field element type: a value in GF(2^13) held in the low 13 bits. */
typedef word16 mc_gf;

/* Row types for the bitsliced additive-FFT scratch buffers, so the stack /
 * heap switch can go through WC_DECLARE_VAR and friends: WC_DECLARE_VAR(x,
 * mc_bs4, n, heap) is "word64 x[n][4]" on the stack or "word64 (*x)[4]" on the
 * heap (a single contiguous allocation), matching how these buffers are used
 * and passed. */
typedef word64 mc_bs2[2];
typedef word64 mc_bs4[4];
typedef word64 mc_bs28[28];

/* Several hot loops read/write byte buffers a machine word at a time. These
 * unions alias a byte pointer as a word pointer without breaking strict
 * aliasing (the same type-pun idiom as misc.c xorbuf). */
typedef union {
    byte* bp;
    wolfssl_word* wp;
} McWordPtr;
typedef union {
    const byte* bp;
    const wolfssl_word* wp;
} McCWordPtr;
typedef union {
    byte* bp;
    word64* wp;
} McWord64Ptr;

#if defined(WOLFSSL_X86_64_BUILD) && defined(USE_INTEL_SPEEDUP) && \
    !defined(WOLFSSL_NO_ASM)
/* x86_64 AVX2/AVX512 assembly kernels, chosen at runtime from CPU features
 * (AVX512 preferred) and used only when the vector registers can be saved.
 * cpuid.h must be included before testing HAVE_CPUID (it defines it). */
#include <wolfssl/wolfcrypt/cpuid.h>

/* At least one vector ISA must be enabled for the asm to be usable. */
#if defined(HAVE_CPUID) && \
    (!defined(NO_AVX2_SUPPORT) || !defined(NO_AVX512_SUPPORT))
#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
#define MC_HAVE_SORT_ASM
#define MC_HAVE_ELIM_ASM
#define MC_HAVE_TRANSPOSE_ASM
#endif

#if !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) || \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
#define MC_HAVE_MUL_ASM
#endif

/* The x86 one-shot decode drivers (wc_mceliece_decode_drv_gfni/avx512/avx2)
 * need the Intel asm helpers + AVX2. Defined up here (not just before the
 * drivers) so wc_mceliece_dec_layout can size their driver scratch. */
#if defined(MC_HAVE_MUL_ASM) && !defined(WOLFSSL_MCELIECE_SMALL) && \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE) && \
    !defined(WOLFSSL_MCELIECE_DECAPSULATE_SMALL_MEM) && \
    !defined(NO_AVX2_SUPPORT)
    #define MC_HAVE_DECODE_ASM
#endif
#if defined(MC_HAVE_DECODE_ASM)
    #define MC_HAVE_DECODE_BS_ASM
#endif

#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
#ifndef NO_AVX2_SUPPORT
/* Keygen AVX2 asm kernels (defined in the generated asm, declared here for the
 * AVX2 keygen driver): control bits, bitslice_poly, radix_conv, and the forward
 * FFT butterflies. */
WOLFSSL_LOCAL int wc_mceliece_controlbits_avx2(byte* out, const sword16* pi,
    int w, int n, sword32* temp, sword16* pitest, void* frames);
WOLFSSL_LOCAL void wc_mceliece_bitslice_poly_avx2(word64* in, const mc_gf* c);
WOLFSSL_LOCAL void wc_mceliece_radix_conv_avx2(word64* in);
WOLFSSL_LOCAL void wc_mceliece_fft_fwd_butterflies_avx2(word64* out, word64* in,
    int monic, word64* scratch);
#define MC_HAVE_BS_FFT_ASM
/* The AVX2 bitsliced-keygen driver kernel (wc_mceliece_bs_pk_gen_avx2) is
 * emitted in the HAVE_INTEL_AVX512 asm block, so it exists only when AVX512
 * build support is present. On an AVX2-only build (NO_AVX512_SUPPORT) fall
 * back to the C keygen rather than referencing an absent symbol. */
#ifndef NO_AVX512_SUPPORT
#define MC_HAVE_BS_KEYGEN_AVX2
#endif
#endif
#ifndef NO_AVX512_SUPPORT
/* Keygen AVX512 asm kernels (declared for the AVX512 keygen driver): control
 * bits and the bitsliced systematic-form pk_gen. */
WOLFSSL_LOCAL int wc_mceliece_controlbits_avx512(byte* out, const sword16* pi,
    int w, int n, sword32* temp, sword16* pitest, void* frames);
WOLFSSL_LOCAL int wc_mceliece_bs_pk_gen_avx512(const void* ctx);
#define MC_HAVE_BS_PKGEN_AVX512
#define MC_HAVE_BS_KEYGEN_AVX512
#endif
#endif

#ifndef WOLFSSL_MCELIECE_NO_ENCAPSULATE
#if !defined(WOLFSSL_MCELIECE_SMALL) && \
    (!defined(NO_AVX2_SUPPORT) || !defined(NO_AVX512_SUPPORT))
#define MC_HAVE_ENCAP_ASM
#endif
#endif

#endif
#endif

#if defined(__aarch64__) && defined(WOLFSSL_ARMASM) && \
    !defined(WOLFSSL_ARMASM_NO_NEON) && !defined(WOLFSSL_NO_ASM)
/* AArch64 NEON assembly kernels, chosen at runtime from CPU features (ASIMD).
 * cpuid.h must be included before testing HAVE_CPUID_AARCH64 (defines it). */
#include <wolfssl/wolfcrypt/cpuid.h>

#ifdef HAVE_CPUID_AARCH64
#if !defined(WOLFSSL_MCELIECE_SMALL)
/* AArch64 NEON is usable for this build (runtime-gated on ASIMD). Op-specific
 * flags below and MC_HAVE_AFF_FFT_NEON (shared FFT, defined with the FFT). */
#define MC_HAVE_AARCH64_NEON
#endif
/* Encapsulate: the syndrome C0 = He is the compute-bound step and has a NEON
 * kernel; the FixedWeight draw and bit-scatter stay in C. */
#ifndef WOLFSSL_MCELIECE_NO_ENCAPSULATE
#if !defined(WOLFSSL_MCELIECE_SMALL)
#define MC_HAVE_ENCAP_NEON
#endif
#endif
/* Decapsulate: the C decode calls the NEON leaf kernels (Benes network,
 * additive-FFT/GF) as raw entry points under the one vector-register window
 * wc_mceliece_decode opens around the whole driver. */
#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
#if !defined(WOLFSSL_MCELIECE_SMALL)
#define MC_HAVE_DECODE_NEON
#endif
#endif
/* Make-key: the systematic MatGen (cswap-LU) row elimination is the O(mt^3)
 * hot loop; its inner masked row XOR runs on NEON. */
#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
#if !defined(WOLFSSL_MCELIECE_SMALL)
#define MC_HAVE_PKGEN_NEON
#endif
#endif
#endif /* HAVE_CPUID_AARCH64 */

/* Runtime selector read directly by wc_mceliece_gf_mul_scalar_neon (in the
 * generated asm): nonzero selects the AArch64 PMULL (crypto-extension) path,
 * zero the portable bitsliced path. Defined unconditionally in the NEON build
 * (the asm always references it); defaults to the safe bitsliced path and is
 * set from CPU features by mc_set_gf_pmull() before the ops that use it. */
unsigned int wc_mceliece_gf_pmull = 0;

#ifdef HAVE_CPUID_AARCH64
/* Detect the PMULL (carryless-multiply) feature and select the scalar GF path.
 * Idempotent and cheap; called at the entry of the ops that reach the scalar
 * multiply (genpoly for make-key, berlekamp_massey for decap). */
static WC_INLINE void mc_set_gf_pmull(void)
{
    /* cpuid_get_flags() returns the (lazily initialized) feature flags; unlike
     * cpuid_get_flags_atomic() it needs no caller-initialized storage. */
    wc_mceliece_gf_pmull = IS_AARCH64_PMULL(cpuid_get_flags()) ? 1u : 0u;
}
#else
#define mc_set_gf_pmull() WC_DO_NOTHING
#endif
#endif /* __aarch64__ && WOLFSSL_ARMASM && !NO_NEON && !NO_ASM */

#if !defined(__aarch64__) && defined(WOLFSSL_ARMASM) && \
    !defined(WOLFSSL_ARMASM_NO_NEON) && !defined(WOLFSSL_ARMASM_THUMB2) && \
    !defined(WOLFSSL_NO_ASM)
/* AArch32 NEON assembly kernels.  Unlike AArch64 there is no runtime CPU-
 * feature gate: the AArch32 McEliece asm is only built into a NEON build
 * (BUILD_ARMASM_NEON, non-Thumb), so NEON is guaranteed present and the op
 * flags are unconditional.  There is no PMULL path on AArch32 - the scalar GF
 * multiply is always the portable bitsliced kernel, so mc_set_gf_pmull() is a
 * no-op and the wc_mceliece_gf_pmull selector (an AArch64-only symbol) is
 * never referenced. */
#if !defined(WOLFSSL_MCELIECE_SMALL)
#define MC_HAVE_ARM32_NEON
#endif
#ifndef WOLFSSL_MCELIECE_NO_ENCAPSULATE
#if !defined(WOLFSSL_MCELIECE_SMALL)
#define MC_HAVE_ENCAP_NEON
#endif
#endif
#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
#if !defined(WOLFSSL_MCELIECE_SMALL)
#define MC_HAVE_DECODE_NEON
#endif
#endif
#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
#if !defined(WOLFSSL_MCELIECE_SMALL)
#define MC_HAVE_PKGEN_NEON
#endif
#endif
#define mc_set_gf_pmull() WC_DO_NOTHING
#endif /* AArch32 NEON */

/* Runtime gate for the NEON driver dispatch: AArch64 checks ASIMD at run time;
 * AArch32 NEON is compile-time (always available in this build). */
#if defined(MC_HAVE_ENCAP_NEON) || defined(MC_HAVE_DECODE_NEON) || \
    defined(MC_HAVE_PKGEN_NEON)
#if defined(__aarch64__)
#define MC_NEON_RUNTIME_OK   IS_AARCH64_ASIMD(mc_cpuid_flags)
#else
#define MC_NEON_RUNTIME_OK   1
#endif
#endif

/* Number of field elements q = 2^m. */
#define MC_Q        (1 << MCELIECE_M)
/* Low-m-bit mask for a field element. */
#define MC_GFMASK   MCELIECE_GF_MASK

#if defined(HAVE_CPUID) || defined(HAVE_CPUID_AARCH64)
/* CPU feature flags, retrieved once by mceliece_init() and read by the runtime
 * assembly dispatch (x86 keygen/encap/decap AVX2/AVX512, AArch64 NEON). */
static cpuid_flags_t mc_cpuid_flags = WC_CPUID_INITIALIZER;
#endif
#ifdef HAVE_CPUID
/* The generated AVX512 kernels use 256-bit EVEX ops (AVX512VL) and 128-bit
 * qword insert/extract (AVX512DQ) in addition to foundation (F) and byte/word
 * (BW) instructions, so require all four before dispatching to them. */
#define MC_HAVE_AVX512_HW(f)                                             \
    (IS_INTEL_AVX512(f) && IS_INTEL_AVX512_BW(f) &&                      \
     IS_INTEL_AVX512_DQ(f) && IS_INTEL_AVX512_VL(f))
/* The GFNI decode monolith additionally needs GFNI (gf2p8affineqb) and
 * AVX512VBMI (vpermb) for the fast 64x64 bit transpose. */
#define MC_HAVE_GFNI_HW(f)                                               \
    (MC_HAVE_AVX512_HW(f) && IS_INTEL_GFNI(f) && IS_INTEL_AVX512_VBMI(f))
#endif

/* Initialize the Classic McEliece implementation.
 *
 * Retrieves the CPU feature flags once so operations dispatch to assembly
 * without re-querying CPUID on every call. Called from wc_McElieceKey_Init.
 */
void mceliece_init(void)
{
#if defined(HAVE_CPUID) || defined(HAVE_CPUID_AARCH64)
    cpuid_get_flags_ex(&mc_cpuid_flags);
#endif
}

/******************************************************************************/
/* GF(2^13) arithmetic. Field polynomial z^13 + z^4 + z^3 + z + 1 (0x201B).   */
/******************************************************************************/

#if !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) || \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
/* Return an all-ones mask when a is zero, else 0. Constant time: a - 1 borrows
 * (setting bit 31 of the 32-bit intermediate) only when a is zero; that bit is
 * then broadcast to a full 16-bit mask. Branchless, with no data-dependent
 * control flow or memory access.
 *
 * @param  [in]  a  Field element to test.
 * @return  0xFFFF when a == 0.
 * @return  0x0000 otherwise.
 */
static WC_INLINE mc_gf wc_mceliece_gf_iszero(mc_gf a)
{
    return (mc_gf)(0U - (((word32)a - 1) >> 31));
}

/* Multiply two field elements, reducing modulo the field polynomial
 * z^13 + z^4 + z^3 + z + 1.
 *
 * @param  [in]  in0  First field element.
 * @param  [in]  in1  Second field element.
 * @return  in0 * in1 in GF(2^13).
 */
static mc_gf wc_mceliece_gf_mul(mc_gf in0, mc_gf in1)
{
    /* Carryless product by shift-and-mask: for each set bit i of in1, XOR in
     * in0 << i (selected with a 0/all-ones mask, so it is constant time and
     * needs no multiply). The 13-bit inputs give a <= 25-bit product and the
     * reduction stays below 2^25, so 32-bit words are sufficient. Small builds
     * keep the compact bit loop; otherwise it is fully unrolled. */
    word32 r;
    word32 sh = in0;
    word32 t;

#ifdef WOLFSSL_MCELIECE_SMALL
    word32 b = in1;
    int i;

    r = 0;
    for (i = 0; i < MCELIECE_M; i++) {
        r ^= sh & (word32)(0 - (b & 1));
        sh <<= 1;
        b >>= 1;
    }
#else
    r  = sh & (word32)(0 - (in1 & 1));
    r ^= (sh <<  1) & (word32)(0 - ((in1 >>  1) & 1));
    r ^= (sh <<  2) & (word32)(0 - ((in1 >>  2) & 1));
    r ^= (sh <<  3) & (word32)(0 - ((in1 >>  3) & 1));
    r ^= (sh <<  4) & (word32)(0 - ((in1 >>  4) & 1));
    r ^= (sh <<  5) & (word32)(0 - ((in1 >>  5) & 1));
    r ^= (sh <<  6) & (word32)(0 - ((in1 >>  6) & 1));
    r ^= (sh <<  7) & (word32)(0 - ((in1 >>  7) & 1));
    r ^= (sh <<  8) & (word32)(0 - ((in1 >>  8) & 1));
    r ^= (sh <<  9) & (word32)(0 - ((in1 >>  9) & 1));
    r ^= (sh << 10) & (word32)(0 - ((in1 >> 10) & 1));
    r ^= (sh << 11) & (word32)(0 - ((in1 >> 11) & 1));
    r ^= (sh << 12) & (word32)(0 - ((in1 >> 12) & 1));
#endif

    t = r & 0x1FF0000;
    r ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

    t = r & 0x000E000;
    r ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

    return (mc_gf)(r & MC_GFMASK);
}

/* Square a field element. Squaring is linear over GF(2), so a^2 is just the
 * input bits placed at even positions and reduced. The low 7 input bits land
 * at positions 0..12 and need no reduction; the top 6 bits contribute the
 * precomputed reductions of x^14, x^16, ..., x^24. Everything stays within
 * 16-bit values and the routine is branch-free and constant time.
 *
 * @param  [in]  in  Field element.
 * @return  in^2 in GF(2^13).
 */
static mc_gf wc_mceliece_gf_sq(mc_gf in)
{
    static const word16 hi[6] = {
        0x0036, 0x00D8, 0x0360, 0x0D80, 0x161B, 0x185A
    };
    word16 x;
#ifdef WOLFSSL_MCELIECE_SMALL
    word16 m;
    int i;
#else
    word16 m0 = (word16)(0 - (word16)((in >>  7) & 1));
    word16 m1 = (word16)(0 - (word16)((in >>  8) & 1));
    word16 m2 = (word16)(0 - (word16)((in >>  9) & 1));
    word16 m3 = (word16)(0 - (word16)((in >> 10) & 1));
    word16 m4 = (word16)(0 - (word16)((in >> 11) & 1));
    word16 m5 = (word16)(0 - (word16)((in >> 12) & 1));
#endif

    /* Spread the low 7 bits to even positions 0, 2, ..., 12. */
    x = (word16)(in & 0x7F);
    x = (word16)((x | (x << 4)) & 0x0F0F);
    x = (word16)((x | (x << 2)) & 0x3333);
    x = (word16)((x | (x << 1)) & 0x5555);

    /* Fold in the reduced contribution of each of the top 6 bits. */
#ifdef WOLFSSL_MCELIECE_SMALL
    for (i = 0; i < 6; i++) {
        m = (word16)(0 - (word16)((in >> (7 + i)) & 1));
        x ^= (word16)(hi[i] & m);
    }
#else
    x = (word16)(x ^
        (word16)(hi[0] & m0) ^ (word16)(hi[1] & m1) ^
        (word16)(hi[2] & m2) ^ (word16)(hi[3] & m3) ^
        (word16)(hi[4] & m4) ^ (word16)(hi[5] & m5));
#endif

    return (mc_gf)(x & MC_GFMASK);
}

/* Raise a field element to the fourth power. Like wc_mceliece_gf_sq this is a
 * linear map:
 * the low 4 input bits land at positions 0, 4, 8, 12 (no reduction) and bits
 * 4..12 fold in the precomputed reductions of x^16, x^20, ..., x^48. Stays
 * within 16-bit values, branch-free, and cheaper than
 * wc_mceliece_gf_sq(wc_mceliece_gf_sq(in)).
 *
 * @param  [in]  in  Field element.
 * @return  (in^2)^2 in GF(2^13).
 */
static mc_gf wc_mceliece_gf_sq2(mc_gf in)
{
    static const word16 hi[9] = {
        0x00D8, 0x0D80, 0x185A, 0x0514, 0x1176, 0x17B8, 0x1B75, 0x17FF,
        0x1F05
    };
    word16 x;
#ifdef WOLFSSL_MCELIECE_SMALL
    word16 m;
    int i;
#else
    word16 m0 = (word16)(0 - (word16)((in >>  4) & 1));
    word16 m1 = (word16)(0 - (word16)((in >>  5) & 1));
    word16 m2 = (word16)(0 - (word16)((in >>  6) & 1));
    word16 m3 = (word16)(0 - (word16)((in >>  7) & 1));
    word16 m4 = (word16)(0 - (word16)((in >>  8) & 1));
    word16 m5 = (word16)(0 - (word16)((in >>  9) & 1));
    word16 m6 = (word16)(0 - (word16)((in >> 10) & 1));
    word16 m7 = (word16)(0 - (word16)((in >> 11) & 1));
    word16 m8 = (word16)(0 - (word16)((in >> 12) & 1));
#endif

    x = (word16)((in & 1) | ((in & 2) << 3) | ((in & 4) << 6) |
        ((in & 8) << 9));
#ifdef WOLFSSL_MCELIECE_SMALL
    for (i = 0; i < 9; i++) {
        m = (word16)(0 - (word16)((in >> (4 + i)) & 1));
        x ^= (word16)(hi[i] & m);
    }
#else
    x = (word16)(x ^
        (word16)(hi[0] & m0) ^ (word16)(hi[1] & m1) ^
        (word16)(hi[2] & m2) ^ (word16)(hi[3] & m3) ^
        (word16)(hi[4] & m4) ^ (word16)(hi[5] & m5) ^
        (word16)(hi[6] & m6) ^ (word16)(hi[7] & m7) ^
        (word16)(hi[8] & m8));
#endif

    return (mc_gf)(x & MC_GFMASK);
}

/* Compute the multiplicative inverse of a field element.
 *
 * den^-1 = den^(2^13 - 2), via an addition chain using squaring
 * (wc_mceliece_gf_sq), fourth power (wc_mceliece_gf_sq2) and multiplication
 * (wc_mceliece_gf_mul). This is the num / den division specialised to num = 1,
 * so the trailing multiply by num drops to a final square.
 *
 * @param  [in]  den  Field element.
 * @return  den^-1 in GF(2^13).
 */
static mc_gf wc_mceliece_gf_inv(mc_gf den)
{
    mc_gf den3;
    mc_gf den15;
    mc_gf out;

    den3 = wc_mceliece_gf_mul(wc_mceliece_gf_sq(den), den);
    den15 = wc_mceliece_gf_mul(wc_mceliece_gf_sq2(den3), den3);
    out = wc_mceliece_gf_sq2(den15);
    out = wc_mceliece_gf_mul(wc_mceliece_gf_sq2(out), den15);
    out = wc_mceliece_gf_sq2(out);
    out = wc_mceliece_gf_mul(wc_mceliece_gf_sq2(out), den15);

    return wc_mceliece_gf_sq(out);
}
#endif

#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
/* Multiply two degree-(t-1) polynomials over GF(2^13), reducing modulo the
 * field polynomial of GF((2^13)^t) (the taps depend on t).
 *
 * @param  [out]  out  Product (t coefficients); also used as 2t-1 scratch.
 * @param  [in]   in0  First polynomial (t coefficients).
 * @param  [in]   in1  Second polynomial (t coefficients).
 * @param  [in]   t    Number of coefficients (error weight).
 */
static void wc_mceliece_gf_poly_mul(mc_gf* out, const mc_gf* in0,
    const mc_gf* in1, int t)
{
    int i;
    int j;
    mc_gf* prod;

    prod = out;
    /* Caller supplies out with room for 2t-1 coefficients during the
     * accumulation; the reduction folds it back to t. */
    for (i = 0; i < t * 2 - 1; i++) {
        prod[i] = 0;
    }
    for (i = 0; i < t; i++) {
        for (j = 0; j < t; j++) {
            prod[i + j] ^= wc_mceliece_gf_mul(in0[i], in1[j]);
        }
    }

    /* Reduce modulo the field polynomial of GF((2^13)^t). The polynomial, and
     * hence the reduction taps, depend on t: t = 119 uses x^119 + x^8 + 1;
     * t = 128 uses x^128 + x^7 + x^2 + x + 1. */
    if (t == WC_MCELIECE_6960119_T) {
        for (i = (t - 1) * 2; i >= t; i--) {
            prod[i - t + 8] ^= prod[i];
            prod[i - t + 0] ^= prod[i];
        }
    }
    else {
        for (i = (t - 1) * 2; i >= t; i--) {
            prod[i - t + 7] ^= prod[i];
            prod[i - t + 2] ^= prod[i];
            prod[i - t + 1] ^= prod[i];
            prod[i - t + 0] ^= prod[i];
        }
    }
}
#endif

/******************************************************************************/
/* Little-endian load / store helpers.                                        */
/******************************************************************************/

/* Load a field element from two little-endian bytes, masked to MCELIECE_M
 * bits.
 *
 * @param  [in]  src  Buffer holding the 2-byte little-endian value.
 * @return  The field element (low MCELIECE_M bits).
 */
static mc_gf wc_mceliece_load_gf(const byte* src)
{
    word16 a;

#ifdef LITTLE_ENDIAN_ORDER
    XMEMCPY(&a, src, sizeof(a));
#else
    a = src[1];
    a = (word16)(a << 8);
    a |= src[0];
#endif

    return (mc_gf)(a & MC_GFMASK);
}

#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
/* Store a field element as two little-endian bytes.
 *
 * @param  [out]  dest  Buffer to write the 2-byte little-endian value to.
 * @param  [in]   a     Field element to store.
 */
static void wc_mceliece_store_gf(byte* dest, mc_gf a)
{
#ifdef LITTLE_ENDIAN_ORDER
    word16 v = (word16)a;

    XMEMCPY(dest, &v, sizeof(v));
#else
    dest[0] = (byte)(a & 0xFF);
    dest[1] = (byte)(a >> 8);
#endif
}

/* Load four bytes as a little-endian 32-bit word.
 *
 * @param  [in]  in  Buffer holding the 4 bytes.
 * @return  The 32-bit value.
 */
static word32 wc_mceliece_load4(const byte* in)
{
    word32 ret;
#ifdef LITTLE_ENDIAN_ORDER
    XMEMCPY(&ret, in, sizeof(ret));
#else
    int i;

    ret = in[3];
    for (i = 2; i >= 0; i--) {
        ret <<= 8;
        ret |= in[i];
    }
#endif

    return ret;
}
#endif

#if !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) || \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
/* Load eight bytes as a little-endian 64-bit word. Used only by the decode
 * path (Benes apply), so it is not compiled into a make-key-only build.
 *
 * @param  [in]  in  Buffer holding the 8 bytes.
 * @return  The 64-bit value.
 */
static word64 wc_mceliece_load8(const byte* in)
{
    word64 ret;
#ifdef LITTLE_ENDIAN_ORDER
    XMEMCPY(&ret, in, sizeof(ret));
#else
    int i;

    ret = in[7];
    for (i = 6; i >= 0; i--) {
        ret <<= 8;
        ret |= in[i];
    }
#endif

    return ret;
}
#endif /* !WOLFSSL_MCELIECE_NO_DECAPSULATE */

/* Store a 64-bit word as eight little-endian bytes.
 *
 * @param  [out]  out  Buffer to write the 8 bytes to.
 * @param  [in]   in   Value to store.
 */
static void wc_mceliece_store8(byte* out, word64 in)
{
#ifdef LITTLE_ENDIAN_ORDER
    XMEMCPY(out, &in, sizeof(in));
#else
    out[0] = (byte)((in >> 0x00) & 0xFF);
    out[1] = (byte)((in >> 0x08) & 0xFF);
    out[2] = (byte)((in >> 0x10) & 0xFF);
    out[3] = (byte)((in >> 0x18) & 0xFF);
    out[4] = (byte)((in >> 0x20) & 0xFF);
    out[5] = (byte)((in >> 0x28) & 0xFF);
    out[6] = (byte)((in >> 0x30) & 0xFF);
    out[7] = (byte)((in >> 0x38) & 0xFF);
#endif
}

#ifdef WOLFSSL_MCELIECE_GEN_TABLES
/* Reverse the low MCELIECE_M (13) bits of a field element. Used only when
 * generating the FFT constant tables.
 *
 * @param  [in]  a  Field element.
 * @return  The 13-bit reversal of a.
 */
static mc_gf wc_mceliece_bitrev(mc_gf a)
{
    a = (mc_gf)(((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8));
    a = (mc_gf)(((a & 0x0F0F) << 4) | ((a & 0xF0F0) >> 4));
    a = (mc_gf)(((a & 0x3333) << 2) | ((a & 0xCCCC) >> 2));
    a = (mc_gf)(((a & 0x5555) << 1) | ((a & 0xAAAA) >> 1));

    return (mc_gf)(a >> 3);
}
#endif /* WOLFSSL_MCELIECE_GEN_TABLES */
#endif

/******************************************************************************/
/* Constant-time sorting (djbsort networks) used by field ordering / Benes.   */
/******************************************************************************/

#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
/* Constant-time signed minimum of two 32-bit values.
 *
 * @param  [in]  a  First value.
 * @param  [in]  b  Second value.
 * @return  The smaller of a and b.
 */
static sword32 wc_mceliece_i32_min(sword32 a, sword32 b)
{
    sword32 ab = b ^ a;
    sword32 c = (sword32)((sword64)b - (sword64)a);

    c ^= ab & (c ^ b);
    c >>= 31;
    c &= ab;

    return a ^ c;
}

/* Constant-time signed compare-and-swap so that *a <= *b.
 *
 * Branchless AND vectorisable: the compiler lowers this to NEON add/sub/shift
 * (unlike the general xor-mask form, which does not auto-vectorise), which is
 * the main lever for the C sort. PRECONDITION: both values are in [0, 2^31).
 * Every wc_mceliece_i32_sort caller satisfies this - all its keys are Benes
 * control-bit values that pack a field index < 2^13 shifted by <= 16 bits, so
 * < 2^29 (the full-range field-ordering permutation uses wc_mceliece_u64_sort).
 * The bound guarantees x - y does not overflow, so the arithmetic-shift sign of
 * the difference is the exact comparison without the wider-type correction the
 * general signed form needs. The subtraction is done unsigned to avoid UB.
 *
 * @param  [in, out]  a  On return, the smaller of the two values.
 * @param  [in, out]  b  On return, the larger of the two values.
 */
static void wc_mceliece_i32_minmax(sword32* a, sword32* b)
{
    sword32 x = *a;
    sword32 y = *b;
    sword32 d = (sword32)((word32)x - (word32)y);
    sword32 m = d >> 31;             /* all ones iff x < y (keys >= 0) */
    sword32 dm = d & m;

    *a = y + dm;                     /* min(x, y) */
    *b = x - dm;                     /* max(x, y) */
}

/* Constant-time unsigned compare-and-swap so that *a <= *b.
 *
 * Keys are known to be below 2^63, so the borrow of (b - a) reliably yields
 * the ordering.
 *
 * @param  [in, out]  a  On return, the smaller of the two values.
 * @param  [in, out]  b  On return, the larger of the two values.
 */
static void wc_mceliece_u64_minmax(word64* a, word64* b)
{
    word64 x = *a;
    word64 y = *b;
    word64 c = y - x;

    c >>= 63;
    c = (word64)0 - c;
    c &= x ^ y;

    *a = x ^ c;
    *b = y ^ c;
}

/* Sort n signed 32-bit values ascending in constant time.
 *
 * Uses a Batcher/djbsort merge network. The whole network runs in assembly
 * when available; the scalar network here is the portable fallback.
 *
 * @param  [in, out]  x  Values to sort in place.
 * @param  [in]       n  Number of values.
 */
static void wc_mceliece_i32_sort(sword32* x, int n)
{
    int top;
    int p;
    int q;
    int r;
    int i;

    if (n < 2) {
        return;
    }
    top = 1;
    while (top < n - top) {
        top += top;
    }
    for (p = top; p > 0; p >>= 1) {
        int base;
        /* The valid indices {i : (i & p) == 0} form contiguous blocks
         * [2kp, 2kp+p); iterating them as blocks removes the per-element
         * (i & p) branch so the compiler auto-vectorises this compare-exchange
         * sweep (x[i] vs x[i+p], which do not overlap within a block). */
        for (base = 0; base < n - p; base += 2 * p) {
            int lim = base + p;
            if (lim > n - p) {
                lim = n - p;
            }
            for (i = base; i < lim; i++) {
                wc_mceliece_i32_minmax(&x[i], &x[i + p]);
            }
        }
        i = 0;
        for (q = top; q > p; q >>= 1) {
            for (; i < n - q; i++) {
                if (!(i & p)) {
                    /* Threaded compare-exchange done in place: x[i+p] holds the
                     * running minimum against each x[i+r]. */
                    for (r = q; r > p; r >>= 1) {
                        wc_mceliece_i32_minmax(&x[i + p], &x[i + r]);
                    }
                }
            }
        }
    }
}

/* Compare-exchange count disjoint 64-bit pairs into (min, max).
 *
 * For k in [0, count): a[k] <- min(a[k], b[k]); b[k] <- max(a[k], b[k]).
 * Scalar constant-time compare-exchange. a and b must not overlap.
 *
 * @param  [in, out]  a        On return, element-wise minimums.
 * @param  [in, out]  b        On return, element-wise maximums.
 * @param  [in]       count    Number of pairs to process.
 */
static void wc_mceliece_u64_minmax_vec(word64* a, word64* b, int count)
{
    int k;

    for (k = 0; k < count; k++) {
        wc_mceliece_u64_minmax(&a[k], &b[k]);
    }
}

/* Sort n unsigned 64-bit values ascending in constant time.
 *
 * The compare-exchange network mirrors wc_mceliece_i32_sort but processes runs
 * of disjoint pairs with wc_mceliece_u64_minmax_vec.
 *
 * @param  [in, out]  x       Values to sort in place.
 * @param  [in]       n       Number of values.
 */
/* Portable C merge-exchange sort; the asm paths use their own
 * wc_mceliece_u64_sort_neon / _avx2 kernels. */
static void wc_mceliece_u64_sort(word64* x, int n)
{
    int top;
    int p;
    int q;
    int r;
    int i;

    if (n < 2) {
        return;
    }

    top = 1;
    while (top < n - top) {
        top += top;
    }
    for (p = top; p > 0; p >>= 1) {
        /* The selected indices ((i & p) == 0) of the first pass form contiguous
         * runs [bs, bs + p); do each run as one (vectorised) compare-exchange
         * against [bs + p, ...). The pairs in a run are disjoint, so order
         * within the run does not matter. */
        int bs;
        for (bs = 0; bs < n - p; bs += p + p) {
            int len = n - p - bs;
            if (len > p) {
                len = p;
            }
            wc_mceliece_u64_minmax_vec(&x[bs], &x[bs + p], len);
        }
        /* Merge passes: the threaded compare-exchange a = x[i+p] is done in
         * place, and a run of consecutive selected indices [i, blk) (which
         * touch disjoint cells) is one vectorised compare-exchange per r. */
        i = 0;
        for (q = top; q > p; q >>= 1) {
            while (i < n - q) {
                int blk;
                int len;

                if (i & p) {
                    /* Skip an unselected p-block. */
                    i = (i | (p - 1)) + 1;
                    continue;
                }
                blk = (i & ~(p - 1)) + p;
                len = blk - i;
                if (i + len > n - q) {
                    len = n - q - i;
                }
                for (r = q; r > p; r >>= 1) {
                    wc_mceliece_u64_minmax_vec(&x[i + p], &x[i + r], len);
                }
                i += len;
            }
        }
    }
}
#endif

/******************************************************************************/
/* Matrix transpose and Benes network (all m = 13).                           */
/******************************************************************************/

/* transpose_64x64 is used by the Benes network (decap) AND the shared
 * additive-FFT transpose (make-key), so it lives outside the decap-only guard.
 */
#if !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) || \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
/* Transpose a 64x64 bit matrix.
 *
 * @param  [out]  out      Transposed matrix (64 word64 rows).
 * @param  [in]   in       Source matrix (64 word64 rows).
 */
static void wc_mceliece_transpose_64x64(word64* out, const word64* in)
{
    int i;
    int j;
    int s;
#if defined(WOLFSSL_MCELIECE_SMALL)
    int d;
#endif
    word64 x;
    word64 y;
#if defined(WOLFSSL_MCELIECE_SMALL)
    static const word64 masks[6][2] = {
        { W64LIT(0x5555555555555555), W64LIT(0xAAAAAAAAAAAAAAAA) },
        { W64LIT(0x3333333333333333), W64LIT(0xCCCCCCCCCCCCCCCC) },
        { W64LIT(0x0F0F0F0F0F0F0F0F), W64LIT(0xF0F0F0F0F0F0F0F0) },
        { W64LIT(0x00FF00FF00FF00FF), W64LIT(0xFF00FF00FF00FF00) },
        { W64LIT(0x0000FFFF0000FFFF), W64LIT(0xFFFF0000FFFF0000) },
        { W64LIT(0x00000000FFFFFFFF), W64LIT(0xFFFFFFFF00000000) }
    };
#endif

    for (i = 0; i < 64; i++) {
        out[i] = in[i];
    }
#if defined(WOLFSSL_MCELIECE_SMALL)
    for (d = 5; d >= 0; d--) {
        s = 1 << d;
        for (i = 0; i < 64; i += s * 2) {
            for (j = i; j < i + s; j++) {
                x = (out[j] & masks[d][0]) | ((out[j + s] & masks[d][0]) << s);
                y = ((out[j] & masks[d][1]) >> s) | (out[j + s] & masks[d][1]);
                out[j + 0] = x;
                out[j + s] = y;
            }
        }
    }
#else
    /* Unrolled swap levels d = 5..0 with the shift and both masks passed as
     * literals: no table lookup, each level's masks and shift s = 1 << d are
     * compile-time constants. */
    #define MC_TRANSPOSE64_LEVEL(D, M0, M1)                               \
        s = 1 << (D);                                                     \
        for (i = 0; i < 64; i += s * 2) {                                 \
            for (j = i; j < i + s; j++) {                                 \
                x = (out[j] & (M0)) | ((out[j + s] & (M0)) << s);         \
                y = ((out[j] & (M1)) >> s) | (out[j + s] & (M1));         \
                out[j + 0] = x;                                           \
                out[j + s] = y;                                           \
            }                                                             \
        }
    MC_TRANSPOSE64_LEVEL(5, W64LIT(0x00000000FFFFFFFF),
                            W64LIT(0xFFFFFFFF00000000))
    MC_TRANSPOSE64_LEVEL(4, W64LIT(0x0000FFFF0000FFFF),
                            W64LIT(0xFFFF0000FFFF0000))
    MC_TRANSPOSE64_LEVEL(3, W64LIT(0x00FF00FF00FF00FF),
                            W64LIT(0xFF00FF00FF00FF00))
    MC_TRANSPOSE64_LEVEL(2, W64LIT(0x0F0F0F0F0F0F0F0F),
                            W64LIT(0xF0F0F0F0F0F0F0F0))
    MC_TRANSPOSE64_LEVEL(1, W64LIT(0x3333333333333333),
                            W64LIT(0xCCCCCCCCCCCCCCCC))
    MC_TRANSPOSE64_LEVEL(0, W64LIT(0x5555555555555555),
                            W64LIT(0xAAAAAAAAAAAAAAAA))
    #undef MC_TRANSPOSE64_LEVEL
#endif
}
#endif /* transpose_64x64: make-key || decap */

#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
/* Apply the middle (in-place) layers of the Benes network.
 *
 * Operates on 128 rows of 64 bits, conditionally swapping bit positions
 * according to the control bits.
 *
 * @param  [in, out]  data     128 rows of 64 bits, permuted in place.
 * @param  [in]       bits     Control bits for this layer.
 * @param  [in]       lgs      Log2 of the swap stride.
 */
static void wc_mceliece_layer_in(word64* data, const word64* bits, int lgs)
{
    int i;
    int j;
    int s;
    word64 d;
    const word64* bp = bits;

    s = 1 << lgs;
    for (i = 0; i < 64; i += s * 2) {
        for (j = i; j < i + s; j++) {
            d = data[j] ^ data[j + s];
            d &= *bp++;
            data[j] ^= d;
            data[j + s] ^= d;

            d = data[64 + j] ^ data[64 + j + s];
            d &= *bp++;
            data[64 + j] ^= d;
            data[64 + j + s] ^= d;
        }
    }
}

/* Apply the first and last (external) layers of the Benes network.
 *
 * Operates on the full array of 128 rows of 64 bits, conditionally swapping
 * bit positions according to the control bits.
 *
 * @param  [in, out]  data     128 rows of 64 bits, permuted in place.
 * @param  [in]       bits     Control bits for this layer.
 * @param  [in]       lgs      Log2 of the swap stride.
 */
static void wc_mceliece_layer_ex(word64* data, const word64* bits, int lgs)
{
    int i;
    int j;
    int s;
    word64 d;
    const word64* bp = bits;

    s = 1 << lgs;
    for (i = 0; i < 128; i += s * 2) {
        for (j = i; j < i + s; j++) {
            d = data[j] ^ data[j + s];
            d &= *bp++;
            data[j] ^= d;
            data[j + s] ^= d;
        }
    }
}

#ifdef MC_HAVE_DECODE_NEON
/* NEON Benes permutation network (asm entry); the portable C equivalent is
 * wc_mceliece_apply_benes below. */
WOLFSSL_LOCAL void wc_mceliece_apply_benes_neon(byte* r, const byte* bits,
    int rev, word64* work);
#endif

/* Apply the Benes network defined by the control bits to the 2^13-bit array r.
 *
 * @param  [in, out]  r     The 2^13 bits (MC_Q / 8 bytes) to permute in place.
 * @param  [in]       bits  Control bits of the Benes network.
 * @param  [in]       rev   0 for forward application; non-zero for inverse.
 * @param  [in]       work  Scratch of 384 word64 (128+128+64+64) so no large
 *                          buffer is placed on the stack.
 */
static void wc_mceliece_apply_benes(byte* r, const byte* bits, int rev,
    word64* work)
{
    int i;
    int iter;
    int inc;
    byte* rp = r;
    const byte* bits_ptr;
    word64* r_int_v = work;
    word64* r_int_h = work + 128;
    word64* b_int_v = work + 256;
    word64* b_int_h = work + 320;


    if (rev) {
        bits_ptr = bits + 12288;
        inc = -1024;
    }
    else {
        bits_ptr = bits;
        inc = 0;
    }

    for (i = 0; i < 64; i++) {
        r_int_v[i] = wc_mceliece_load8(rp + i * 16 + 0);
        r_int_v[64 + i] = wc_mceliece_load8(rp + i * 16 + 8);
    }
    wc_mceliece_transpose_64x64(r_int_h, r_int_v);
    wc_mceliece_transpose_64x64(r_int_h + 64, r_int_v + 64);

    for (iter = 0; iter <= 6; iter++) {
        for (i = 0; i < 64; i++) {
            b_int_v[i] = wc_mceliece_load8(bits_ptr);
            bits_ptr += 8;
        }
        bits_ptr += inc;
        wc_mceliece_transpose_64x64(b_int_h, b_int_v);
        wc_mceliece_layer_ex(r_int_h, b_int_h, iter);
    }

    wc_mceliece_transpose_64x64(r_int_v, r_int_h);
    wc_mceliece_transpose_64x64(r_int_v + 64, r_int_h + 64);

    for (iter = 0; iter <= 5; iter++) {
        for (i = 0; i < 64; i++) {
            b_int_v[i] = wc_mceliece_load8(bits_ptr);
            bits_ptr += 8;
        }
        bits_ptr += inc;
        wc_mceliece_layer_in(r_int_v, b_int_v, iter);
    }
    for (iter = 4; iter >= 0; iter--) {
        for (i = 0; i < 64; i++) {
            b_int_v[i] = wc_mceliece_load8(bits_ptr);
            bits_ptr += 8;
        }
        bits_ptr += inc;
        wc_mceliece_layer_in(r_int_v, b_int_v, iter);
    }

    wc_mceliece_transpose_64x64(r_int_h, r_int_v);
    wc_mceliece_transpose_64x64(r_int_h + 64, r_int_v + 64);

    for (iter = 6; iter >= 0; iter--) {
        for (i = 0; i < 64; i++) {
            b_int_v[i] = wc_mceliece_load8(bits_ptr);
            bits_ptr += 8;
        }
        bits_ptr += inc;
        wc_mceliece_transpose_64x64(b_int_h, b_int_v);
        wc_mceliece_layer_ex(r_int_h, b_int_h, iter);
    }

    wc_mceliece_transpose_64x64(r_int_v, r_int_h);
    wc_mceliece_transpose_64x64(r_int_v + 64, r_int_h + 64);

    for (i = 0; i < 64; i++) {
        wc_mceliece_store8(rp + i * 16 + 0, r_int_v[i]);
        wc_mceliece_store8(rp + i * 16 + 8, r_int_v[64 + i]);
    }
}
#endif

/******************************************************************************/
/* Control bits from a permutation (Nassimi-Sahni; see cr.yp.to/controlbits). */
/******************************************************************************/

/* Explicit-stack frame for the iterative control-bit computation. */
typedef struct McCbFrame {
    long pos;
    long step;
    const sword16* pi;
    long w;
    long n;
} McCbFrame;

#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
/* Compose the middle-layer control values for the small-w case (w <= 10).
 * The index fits in 10 bits, so a and b pack two fields per 32-bit word using
 * 10-bit sub-fields. Runs the sorting-network composition w-2 times.
 *
 * @param  [in, out]  a  Shared n-element scratch; sorted then overwritten.
 * @param  [in, out]  b  Control values; composed in place, masked to 10 bits.
 * @param  [in]       n  Permutation size for this node.
 * @param  [in]       w  log2(n) for this node (<= 10).
 */
static void wc_mceliece_cb_compose10(sword32* a, sword32* b, long n, long w)
{
    long i;
    long x;

    for (x = 0; x < n; x++) {
        b[x] = ((a[x] & 0xffff) << 10) | (b[x] & 0x3ff);
    }
    for (i = 1; i < w - 1; i++) {
        for (x = 0; x < n; x++) {
            a[x] = (sword32)(((word32)(b[x] & ~0x3ff) << 6) | (word32)x);
        }
        wc_mceliece_i32_sort(a, (int)n);
        for (x = 0; x < n; x++) {
            a[x] = (sword32)(((word32)a[x] << 20) | (word32)b[x]);
        }
        wc_mceliece_i32_sort(a, (int)n);
        for (x = 0; x < n; x++) {
            sword32 ppcpx = a[x] & 0xfffff;
            sword32 ppcx = (a[x] & 0xffc00) | (b[x] & 0x3ff);
            b[x] = wc_mceliece_i32_min(ppcx, ppcpx);
        }
    }
    for (x = 0; x < n; x++) {
        b[x] &= 0x3ff;
    }
}

/* Compose the middle-layer control values for the large-w case (w > 10).
 * The top-level w = GFBITS = 13; fields need up to 16 bits, so a and b pack
 * them as 16-bit sub-fields. Same composition as cb_compose10 but 16-bit wide.
 *
 * @param  [in, out]  a  Shared n-element scratch; sorted then overwritten.
 * @param  [in, out]  b  Control values; composed in place, masked to 16 bits.
 * @param  [in]       n  Permutation size for this node.
 * @param  [in]       w  log2(n) for this node (> 10).
 */
static void wc_mceliece_cb_compose16(sword32* a, sword32* b, long n, long w)
{
    long i;
    long x;

    for (x = 0; x < n; x++) {
        b[x] = (sword32)((((word32)a[x]) << 16) | (word32)(b[x] & 0xffff));
    }
    for (i = 1; i < w - 1; i++) {
        for (x = 0; x < n; x++) {
            a[x] = (sword32)((b[x] & ~0xffff) | (word32)x);
        }
        wc_mceliece_i32_sort(a, (int)n);
        for (x = 0; x < n; x++) {
            a[x] = (sword32)((((word32)a[x]) << 16) | (word32)(b[x] & 0xffff));
        }
        if (i < w - 2) {
            for (x = 0; x < n; x++) {
                b[x] = (sword32)((a[x] & ~0xffff) | (word32)(b[x] >> 16));
            }
            wc_mceliece_i32_sort(b, (int)n);
            for (x = 0; x < n; x++) {
                b[x] = (sword32)((((word32)b[x]) << 16) |
                    (word32)(a[x] & 0xffff));
            }
        }
        wc_mceliece_i32_sort(a, (int)n);
        for (x = 0; x < n; x++) {
            sword32 cpx = (b[x] & ~0xffff) | (a[x] & 0xffff);
            b[x] = wc_mceliece_i32_min(b[x], cpx);
        }
    }
    for (x = 0; x < n; x++) {
        b[x] &= 0xffff;
    }
}

/* Build the Benes control bits of a permutation. The underlying algorithm is a
 * balanced binary recursion whose two child calls are its last statements; it
 * is realised here as an explicit-stack depth-first worklist (process a node,
 * then push its two children, second half first so the first half runs first,
 * matching the recursion's order and its shared-temp lifetimes).
 *
 * @param  [out]  out    Control bits, XORed at strided positions.
 * @param  [in]   pos0   Starting output bit position.
 * @param  [in]   step0  Output bit position stride.
 * @param  [in]   pi0    Root permutation.
 * @param  [in]   w0     Root log2(n).
 * @param  [in]   n0     Root permutation size.
 * @param  [in]   temp   Scratch of 2*n sword32.
 * @param  [in]   stack  Worklist of up to 2*GFBITS+2 McCbFrame.
 */
static void wc_mceliece_cb_build(byte* out, long pos0, long step0,
    const sword16* pi0, long w0, long n0, sword32* temp, McCbFrame* stack)
{
    int sp;

    stack[0].pos = pos0;
    stack[0].step = step0;
    stack[0].pi = pi0;
    stack[0].w = w0;
    stack[0].n = n0;
    sp = 1;

    while (sp > 0) {
        long pos;
        long step;
        long w;
        long n;
        long x;
        long y;
        long j;
        long k;
        const sword16* pi;
        sword32* a;
        sword32* b;
        sword16* q;

        sp--;
        pos = stack[sp].pos;
        step = stack[sp].step;
        pi = stack[sp].pi;
        w = stack[sp].w;
        n = stack[sp].n;

        if (w == 1) {
            out[pos >> 3] ^= (byte)(pi[0] << (pos & 7));
            continue;
        }

        a = temp;
        b = temp + n;
        q = (sword16*)(temp + n + n / 4);

        for (x = 0; x < n; x++) {
            a[x] = (sword32)(((word32)(pi[x] ^ 1) << 16) | (word16)pi[x ^ 1]);
        }
        wc_mceliece_i32_sort(a, (int)n);

        for (x = 0; x < n; x++) {
            sword32 ax = a[x];
            sword32 px = ax & 0xffff;
            sword32 cx = wc_mceliece_i32_min(px, (sword32)x);
            b[x] = (px << 16) | cx;
        }

        for (x = 0; x < n; x++) {
            a[x] = (sword32)((((word32)a[x]) << 16) | (word32)x);
        }
        wc_mceliece_i32_sort(a, (int)n);

        for (x = 0; x < n; x++) {
            a[x] = (sword32)((((word32)a[x]) << 16) + (word32)(b[x] >> 16));
        }
        wc_mceliece_i32_sort(a, (int)n);

        /* w = GFBITS = 13 at the top level, so the w > 10 path is taken. */
        if (w <= 10) {
            wc_mceliece_cb_compose10(a, b, n, w);
        }
        else {
            wc_mceliece_cb_compose16(a, b, n, w);
        }

        for (x = 0; x < n; x++) {
            a[x] = (sword32)((((word32)(word16)pi[x]) << 16) + (word32)x);
        }
        wc_mceliece_i32_sort(a, (int)n);

        for (j = 0; j < n / 2; j++) {
            sword32 fj;
            sword32 fx;
            sword32 fx1;

            x = 2 * j;
            fj = b[x] & 1;
            fx = (sword32)(x + fj);
            fx1 = fx ^ 1;
            out[pos >> 3] ^= (byte)(fj << (pos & 7));
            pos += step;
            b[x] = (sword32)(((word32)a[x] << 16) | (word32)fx);
            b[x + 1] = (sword32)(((word32)a[x + 1] << 16) | (word32)fx1);
        }
        wc_mceliece_i32_sort(b, (int)n);

        pos += (2 * w - 3) * step * (n / 2);

        for (k = 0; k < n / 2; k++) {
            sword32 lk;
            sword32 ly;
            sword32 ly1;

            y = 2 * k;
            lk = b[y] & 1;
            ly = (sword32)(y + lk);
            ly1 = ly ^ 1;
            out[pos >> 3] ^= (byte)(lk << (pos & 7));
            pos += step;
            a[y] = (sword32)((ly << 16) | (b[y] & 0xffff));
            a[y + 1] = (sword32)((ly1 << 16) | (b[y + 1] & 0xffff));
        }
        wc_mceliece_i32_sort(a, (int)n);

        pos -= (2 * w - 2) * step * (n / 2);

        for (j = 0; j < n / 2; j++) {
            q[j] = (sword16)((a[2 * j] & 0xffff) >> 1);
            q[j + n / 2] = (sword16)((a[2 * j + 1] & 0xffff) >> 1);
        }

        /* Push the second half first so the first half runs first. The first
         * half overwrites temp[0..n); the second half's pi lives in temp[n..2n)
         * (this node's q) and so survives it. */
        stack[sp].pos = pos + step;
        stack[sp].step = step * 2;
        stack[sp].pi = q + n / 2;
        stack[sp].w = w - 1;
        stack[sp].n = n / 2;
        sp++;
        stack[sp].pos = pos;
        stack[sp].step = step * 2;
        stack[sp].pi = q;
        stack[sp].w = w - 1;
        stack[sp].n = n / 2;
        sp++;
    }
}

/* Apply one Benes control-bit layer to a permutation (self-verification).
 * Conditionally swaps elements paired at stride 1 << s using the layer's
 * control bits.
 *
 * @param  [in, out]  p   Permutation, swapped in place.
 * @param  [in]       cb  Control bits for this layer.
 * @param  [in]       s   Layer index; swap stride is 1 << s.
 * @param  [in]       n   Permutation size.
 */
static void wc_mceliece_cb_layer(sword16* p, const byte* cb, int s, int n)
{
    int i;
    int j;
    int stride = 1 << s;
    int index = 0;
    sword16 d;
    sword16 m;

    for (i = 0; i < n; i += stride * 2) {
        for (j = 0; j < stride; j++) {
            d = (sword16)(p[i + j] ^ p[i + j + stride]);
            m = (sword16)((cb[index >> 3] >> (index & 7)) & 1);
            m = (sword16)(-m);
            d = (sword16)(d & m);
            p[i + j] ^= d;
            p[i + j + stride] ^= d;
            index++;
        }
    }
}

/* Compute the (2w-1)*n/2 Benes control bits of a permutation, verifying the
 * result by applying them to the identity.
 *
 * @param  [out]  out      Control bits.
 * @param  [in]   pi       Permutation of {0, ..., n-1}.
 * @param  [in]   w        log2(n) (GFBITS at the top level).
 * @param  [in]   n        Permutation size (a power of two).
 * @param  [in]   temp     Scratch of 2*n sword32.
 * @param  [in]   pi_test  Scratch of n sword16 (self-check).
 * @param  [in]   frames   Scratch of 2*GFBITS+2 McCbFrame (recursion stack).
 * @return  0 on success.
 * @return  -1 if the self-check never matches.
 */
static int wc_mceliece_gen_controlbits(byte* out, const sword16* pi, long w,
    long n, sword32* temp, sword16* pi_test, McCbFrame* frames)
{
    sword16 diff;
    int i;
    byte* ptr;
    int loop;
    int ret = -1;

    for (loop = 0; loop < 2; loop++) {
        XMEMSET(out, 0, (size_t)(((2 * w - 1) * n / 2 + 7) >> 3));
        wc_mceliece_cb_build(out, 0, 1, pi, w, n, temp, frames);

        for (i = 0; i < n; i++) {
            pi_test[i] = (sword16)i;
        }
        ptr = out;
        for (i = 0; i < w; i++) {
            wc_mceliece_cb_layer(pi_test, ptr, i, (int)n);
            ptr += n >> 4;
        }
        for (i = (int)(w - 2); i >= 0; i--) {
            wc_mceliece_cb_layer(pi_test, ptr, i, (int)n);
            ptr += n >> 4;
        }

        diff = 0;
        for (i = 0; i < n; i++) {
            diff = (sword16)(diff | (pi[i] ^ pi_test[i]));
        }
        if (diff == 0) {
            ret = 0;
            break;
        }
    }

    return ret;
}
#endif

/******************************************************************************/
/* Goppa polynomial generation (minimal polynomial of t field elements).      */
/******************************************************************************/

#if !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) || \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
/* dst[i] ^= wc_mceliece_gf_mul(scalar, src[i]), for count elements.
 * The genpoly reduction multiply-accumulate, and the Berlekamp-Massey locator
 * update.
 *
 * @param  [in, out]  dst      Accumulator, count field elements.
 * @param  [in]       scalar   Field-element multiplier.
 * @param  [in]       src      Source elements.
 * @param  [in]       count    Number of elements.
 */
static void wc_mceliece_gf_mulc_mac(mc_gf* dst, mc_gf scalar, const mc_gf* src,
    int count)
{
    int i;
    int k;
    /* For a fixed scalar, gf_mul(scalar, x) is GF(2)-linear in x, so precompute
     * the reduced basis products basis[k] = scalar * x^k mod g (<= 13 bits)
     * once, then each element is the XOR of the basis[k] selected by src[i]'s
     * bits - with no per-element reduction (~1.7x fewer ops than a gf_mul per
     * element). Constant time: mask-select only, no secret-indexed access.
     * The modulus is g = x^13 + x^4 + x^3 + x + 1, so x^13 reduces to 0x1B. */
    word32 basis[MCELIECE_M];
    word32 m = scalar;

    for (k = 0; k < MCELIECE_M; k++) {
        word32 hi;

        basis[k] = m;
        m <<= 1;
        hi = (m >> MCELIECE_M) & 1;
        m &= MC_GFMASK;
        m ^= (word32)0x1B & (word32)(0 - hi);
    }
    for (i = 0; i < count; i++) {
        word32 s = src[i];
        word32 r = 0;

        for (k = 0; k < MCELIECE_M; k++) {
            r ^= basis[k] & (word32)(0 - ((s >> k) & 1));
        }
        dst[i] ^= (mc_gf)r;
    }
}
#endif

#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
/* Compute the monic minimal (Goppa) polynomial of t field elements by
 * Gaussian elimination over GF(2^13).
 *
 * @param  [out]  out   Goppa polynomial (t coefficients).
 * @param  [in]   f     The t field elements.
 * @param  [in]   t     Error weight / polynomial degree.
 * @param  [in]   mat   Scratch of (t+1)*t mc_gf.
 * @param  [in]   prod  Scratch of 2t-1 mc_gf.
 * @return  0 on success.
 * @return  -1 if the system is singular.
 */
static int wc_mceliece_genpoly_gen(mc_gf* out, const mc_gf* f, int t,
    mc_gf* mat, mc_gf* prod)
{
    int i;
    int j;
    int k;
    int c;
    mc_gf mask;
    mc_gf inv;
    int ret = 0;

    /* This is the pure-C fallback. When SIMD is available, genpoly runs inside
     * the monolithic asm keygen driver (wc_mceliece_keygen_*), not here. */

    /* mat is used as mat[col][row] with col in [0, t], row in [0, t). */
    mat[0 * t + 0] = 1;
    for (i = 1; i < t; i++) {
        mat[0 * t + i] = 0;
    }
    for (i = 0; i < t; i++) {
        mat[1 * t + i] = f[i];
    }
    for (j = 2; j <= t; j++) {
        wc_mceliece_gf_poly_mul(prod, &mat[(j - 1) * t], f, t);
        for (i = 0; i < t; i++) {
            mat[j * t + i] = prod[i];
        }
    }

    for (j = 0; j < t; j++) {
        for (k = j + 1; k < t; k++) {
            mask = wc_mceliece_gf_iszero(mat[j * t + j]);
            for (c = j; c < t + 1; c++) {
                mat[c * t + j] ^= mat[c * t + k] & mask;
            }
        }
        if (mat[j * t + j] == 0) {
            ret = -1;
            break;
        }
        inv = wc_mceliece_gf_inv(mat[j * t + j]);
        for (c = j; c < t + 1; c++) {
            mat[c * t + j] = wc_mceliece_gf_mul(mat[c * t + j], inv);
        }
        /* Reduce every other column: mat[c][k] ^= mat[c][j] * mat[j][k] for
         * k != j. Save row j and zero its diagonal so the pivot column j is
         * left untouched, then multiply-accumulate each row c into place. */
        for (k = 0; k < t; k++) {
            prod[k] = mat[j * t + k];
        }
        prod[j] = 0;
        for (c = j; c < t + 1; c++) {
            wc_mceliece_gf_mulc_mac(&mat[c * t], mat[c * t + j], prod, t);
        }
    }
    if (ret == 0) {
        for (i = 0; i < t; i++) {
            out[i] = mat[t * t + i];
        }
    }

    return ret;
}
#endif

/******************************************************************************/
/* Polynomial evaluation, syndrome and Berlekamp-Massey (decoding).           */
/******************************************************************************/

#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE

/* Berlekamp-Massey: the minimal polynomial (error locator) of a syndrome,
 * computed in constant time. The asm decode path uses its own monolithic
 * wc_mceliece_berlekamp_massey_neon instead; this stays pure C.
 *
 * @param  [out]  out  Error-locator polynomial (t+1 coefficients).
 * @param  [in]   s    Syndrome (2t field elements).
 * @param  [in]   t    Error weight.
 * @param  [in]   tmp  Scratch of t+1 mc_gf.
 * @param  [in]   c    Scratch of t+1 mc_gf.
 * @param  [in]   bp   Scratch of t+1 mc_gf.
 */
static void wc_mceliece_bm(mc_gf* out, const mc_gf* s, int t, mc_gf* tmp,
    mc_gf* c, mc_gf* bp)
{
    int i;
    word16 n;
    word16 len = 0;
    word16 mle;
    word16 mne;
    mc_gf b = 1;
    mc_gf d;
    mc_gf lead;
    word32 acc;
    word32 rt;
    int k;

    for (i = 0; i < t + 1; i++) {
        c[i] = bp[i] = 0;
    }
    bp[1] = c[0] = 1;

    for (n = 0; n < 2 * t; n++) {
        int m = (n < (word16)t) ? (int)n : t;

        d = 0;
        /* Discrepancy dot-product with DEFERRED reduction: accumulate the
         * raw carryless products (<= 25 bits) UNREDUCED, fold once at the
         * end. Reduction is GF(2)-linear so reduce(sum) == sum(reduce),
         * saving the per-term reduction. Constant time. */
        acc = 0;

        for (i = 0; i <= m; i++) {
            word32 a = c[i];
            word32 sb = s[n - i];

            for (k = 0; k < MCELIECE_M; k++) {
                acc ^= (a << k) & (word32)(0 - ((sb >> k) & 1));
            }
        }
        rt = acc & 0x1FF0000;
        acc ^= (rt >> 9) ^ (rt >> 10) ^ (rt >> 12) ^ (rt >> 13);
        rt = acc & 0x000E000;
        acc ^= (rt >> 9) ^ (rt >> 10) ^ (rt >> 12) ^ (rt >> 13);
        d ^= (mc_gf)(acc & MC_GFMASK);

        mne = (word16)~wc_mceliece_gf_iszero(d);
        mle = (word16)(ctMask16GTE((int)n, 2 * (int)len) & mne);

        for (i = 0; i <= t; i++) {
            tmp[i] = c[i];
        }
        /* Inversion-free update: c = b*c ^ d*bp (no per-iteration field
         * division). c[0] accumulates a nonzero scalar (b never 0); the result
         * is normalised to monic after the loop, so callers get the true
         * locator - identical to the division form but without 2t field
         * inversions (wc_mceliece_gf_inv). */
        XMEMSET(c, 0, (size_t)(t + 1) * sizeof(mc_gf));
        wc_mceliece_gf_mulc_mac(c, b, tmp, t + 1);
        wc_mceliece_gf_mulc_mac(c, d, bp, t + 1);
        len = (word16)((len & ~mle) | ((n + 1 - len) & mle));
        /* Fused bp <- x * (mle ? tmp : bp): the conditional B <- C swap and the
         * B <- x*B shift in one downward pass (each bp[i] takes the masked
         * bp[i-1]/tmp[i-1]; the top select the plain shift would drop is never
         * computed). Constant time. */
        for (i = t; i >= 1; i--) {
            bp[i] = (mc_gf)((bp[i - 1] & ~mle) | (tmp[i - 1] & mle));
        }
        bp[0] = 0;
        b = (mc_gf)((b & ~mle) | (d & mle));
    }
    /* Normalise to monic: the inversion-free loop left c scaled by c[0] (the
     * degree-t / out[t] coefficient); divide it out so out is the true monic
     * locator. c[0] != 0 for a weight-t error (locator degree exactly t). */
    lead = wc_mceliece_gf_inv(c[0]);
    for (i = 0; i <= t; i++) {
        out[i] = (mc_gf)wc_mceliece_gf_mul(c[t - i], lead);
    }
}
#endif

/******************************************************************************/
/* Public-key generation (MatGen: systematic and semi-systematic).            */
/******************************************************************************/

#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
/* Count the trailing zero bits of a 64-bit value, in constant time.
 *
 * @param  [in]  in  Value to examine.
 * @return  Number of trailing zero bits (64 when in is zero).
 */
static int wc_mceliece_ctz(word64 in)
{
    int i;
    int b;
    int m = 0;
    int r = 0;

    for (i = 0; i < 64; i++) {
        b = (int)((in >> i) & 1);
        m |= b;
        r += (m ^ 1) & (b ^ 1);
    }

    return r;
}

#endif

/******************************************************************************/
/* Single-allocation scratch arenas: one buffer per operation, sized by
 * wc_mceliece_*_scratch_sz() and carved here. mat.c never allocates. */
/******************************************************************************/

/* Reserve sz bytes from scratch s at the next 8-byte boundary, advancing *off.
 * When s is NULL only the running size is accumulated (used for sizing).
 *
 * @param  [in]      s    Scratch base address, or NULL to only accumulate the
 *                        size.
 * @param  [in,out]  off  Running offset, advanced past the reservation.
 * @param  [in]      sz   Number of bytes to reserve.
 * @return  Pointer to the reserved 8-byte-aligned block.
 * @return  NULL when s is NULL.
 */
static void* mc_carve(byte* s, word32* off, word32 sz)
{
    void* p;

    *off = (*off + 7u) & ~(word32)7u;
    p = (s == NULL) ? NULL : (void*)(s + *off);
    *off += sz;

    return p;
}

/* Keygen scratch buffers. buf (wc_mceliece_pk_gen sort) and cbtmp (control
 * bits) are used at different times and share one region. */
typedef struct McKgBufs {
    byte* r;
    word32* perm;
    sword16* pi;
    sword16* pitest;
    sword32* cbtmp;
    word64* buf;
    McCbFrame* frames;
    mc_gf* f;
    mc_gf* irr;
    mc_gf* gmat;
    mc_gf* gprod;
    byte* mat;
    mc_gf* g;
    mc_gf* sup;
    mc_gf* inv;
    word64* mcbuf;
    byte* ctzlist;
} McKgBufs;

/* Decapsulation scratch buffers. */
typedef struct McDecBufs {
    byte* r;
    mc_gf* einv;
    mc_gf* fftw;
    mc_gf* mulbuf;
    mc_gf* fftt;
    mc_gf* s;
    mc_gf* locator;
    mc_gf* tmp;
    mc_gf* c;
    mc_gf* bp;
    byte* bwork;
    word64* benes;
    word64* scratch;
} McDecBufs;

#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
/* Number of 256-column blocks spanned by an mt-row bitsliced band. */
#define MC_BS_NBI(mt) (((mt) + 255) / 256)
/* Widest par_width the build can select: the AVX2 MatGen monolith picks
 * 7/11/13 per variant, every other path uses 7. The shared par workspace is
 * sized for this maximum so any path fits within it. */
#if defined(MC_HAVE_BS_KEYGEN_AVX2)
#define MC_BS_MAX_PARW 13
#else
#define MC_BS_MAX_PARW 7
#endif

/* Bitsliced MatGen workspaces, carved from the keygen scratch by
 * wc_mceliece_bs_layout and shared (never concurrently) by the portable-C
 * MatGen driver and the assembly keygen. */
typedef struct McBsBufs {
    word64 (*prod)[MCELIECE_M][4];
    word64 (*consts)[MCELIECE_M][4];
    word64 (*eval)[MCELIECE_M][4];
    word64 (*par)[7][4];
    word64* mat;
    word64* scratch;
    word64* fftinv;
    sword16* ind;
    sword16* indInv;
    byte* tmat;
} McBsBufs;

/* Carve the bitsliced MatGen workspaces from s starting at *off, advancing
 * *off past them (size-only when s is NULL). par is sized for MC_BS_MAX_PARW;
 * each keygen path addresses it with its own stride, so the region is a safe
 * upper bound shared across them.
 *
 * @param  [in]      p    Parameter set (defines mt, n and buffer sizes).
 * @param  [in]      s    Scratch base address, or NULL to only advance *off.
 * @param  [in, out] off  Running offset into s, advanced past the buffers.
 * @param  [out]     b    Buffer pointers set to their offsets within s.
 */
static void wc_mceliece_bs_layout(const McElieceParams* p, byte* s,
    word32* off, McBsBufs* b)
{
    const int mt = p->mt;
    const int nbiW = MC_BS_NBI(mt) * 4;
    const int numBlocks = (p->n + 255) / 256;
    const int tmatStride = numBlocks * 32;
    const word32 planes = (word32)(32 * sizeof(word64[MCELIECE_M][4]));

    b->prod    = (word64(*)[MCELIECE_M][4])mc_carve(s, off, planes);
    b->consts  = (word64(*)[MCELIECE_M][4])mc_carve(s, off, planes);
    b->eval    = (word64(*)[MCELIECE_M][4])mc_carve(s, off, planes);
    b->par     = (word64(*)[7][4])mc_carve(s, off,
        (word32)((size_t)mt * MC_BS_MAX_PARW * 4 * sizeof(word64)));
    b->mat     = (word64*) mc_carve(s, off,
        (word32)((size_t)mt * nbiW * sizeof(word64)));
    b->scratch = (word64*) mc_carve(s, off, (word32)(mt * sizeof(word64)));
    b->fftinv  = (word64*) mc_carve(s, off, (word32)(MC_Q * sizeof(word64)));
    b->ind     = (sword16*)mc_carve(s, off, (word32)(mt * sizeof(sword16)));
    b->indInv  = (sword16*)mc_carve(s, off, (word32)(mt * sizeof(sword16)));
    b->tmat    = (byte*)   mc_carve(s, off, (word32)(mt * tmatStride));
}

/* Lay out the key-generation scratch buffers within s, or size them when
 * s is NULL. Assigns each McKgBufs pointer an offset into s; overlaps
 * buffers with disjoint lifetimes and builds the matrix in the public-key
 * buffer, minimising the scratch for both the C and assembly keygen.
 *
 * @param  [in]   p   Parameter set (defines t, n and buffer sizes).
 * @param  [in]   s   Scratch base address, or NULL to only compute the size.
 * @param  [out]  b   McKgBufs pointers set to their offsets within s.
 * @param  [out]  bb  McBsBufs (bitsliced MatGen) pointers, also within s.
 * @return  Total scratch size in bytes.
 */
static word32 wc_mceliece_kg_layout(const McElieceParams* p, byte* s,
    McKgBufs* b, McBsBufs* bb)
{
    const int t = p->t;
    const int n = p->n;
    const word32 rlen = p->sBytes + (word32)MC_Q * 4 + (word32)(t * 2) +
        MCELIECE_SEED_SZ;
    word32 off = 0;
    byte* regA;
    byte* bufR;

    /* Buffers with disjoint lifetimes are overlapped, and MatGen runs in the
     * (enlarged) public-key buffer itself (keypair sets b->mat = pk), so the
     * ~1.3-1.7 MB matrix is not carved here - the biggest saving. This layout
     * is used by both the C and the assembly keygen (both run the same
     * genpoly -> pk_gen -> controlbits pipeline with the same buffer
     * lifetimes).
     *
     * regA is reused across three non-overlapping phases:
     *   perm (field ordering, until the sort)
     *   -> sup + inv (matrix build)
     *   -> pitest + frames (control bits).
     * perm = MC_Q word32 is the largest user; sup+inv = 4n and pitest+frames
     * both fit within it. bufR carries buf/cbtmp (sort + control bits) with
     * gmat (genpoly) overlaid - genpoly finishes before the sort. */
    b->r      = (byte*)   mc_carve(s, &off, rlen);
    regA      = (byte*)   mc_carve(s, &off, (word32)sizeof(word32) * MC_Q);
    bufR      = (byte*)   mc_carve(s, &off, (word32)sizeof(word64) * MC_Q);
    b->pi     = (sword16*)mc_carve(s, &off, (word32)sizeof(sword16) * MC_Q);
    b->f      = (mc_gf*)  mc_carve(s, &off, (word32)sizeof(mc_gf) * t);
    b->irr    = (mc_gf*)  mc_carve(s, &off, (word32)sizeof(mc_gf) * t);
    b->gprod  = (mc_gf*)  mc_carve(s, &off,
        (word32)sizeof(mc_gf) * (2 * t - 1));
    b->g      = (mc_gf*)  mc_carve(s, &off, (word32)sizeof(mc_gf) * (t + 1));
    b->mcbuf  = (word64*) mc_carve(s, &off, (word32)sizeof(word64) * 64);
    b->ctzlist= (byte*)   mc_carve(s, &off, 32);
    b->perm   = (word32*)   regA;
    b->sup    = (mc_gf*)    regA;
    b->inv    = (mc_gf*)   (regA + (word32)sizeof(mc_gf) * n);
    b->pitest = (sword16*)  regA;
    b->frames = (McCbFrame*)(regA + (word32)sizeof(sword16) * MC_Q);
    b->buf    = (word64*)   bufR;
    b->cbtmp  = (sword32*)  bufR;
    b->gmat   = (mc_gf*)    bufR;
    b->mat    = NULL;

    /* The bitsliced MatGen workspaces live in the same scratch (disjoint from
     * the McKgBufs regions above; used simultaneously during MatGen). */
    wc_mceliece_bs_layout(p, s, &off, bb);

    return off;
}
#endif

#ifndef WOLFSSL_MCELIECE_NO_ENCAPSULATE
/* Lay out the encapsulation scratch buffers within s, or size them when s is
 * NULL. Sets each output pointer (nums/ind/row, plus val for the small build)
 * to an offset into s; overlaps buffers with disjoint lifetimes (nums/ind onto
 * row) for both the C and assembly encode.
 *
 * @param  [in]   p  Parameter set (defines t and buffer sizes).
 * @param  [in]   s  Scratch base address, or NULL to only compute the size.
 * @param  [out]  b  Buffer pointers set to their offsets within s.
 * @return  Total scratch size in bytes.
 */
static word32 wc_mceliece_enc_layout(const McElieceParams* p, byte* s,
    word16** nums, word16** ind, byte** row
#ifdef WOLFSSL_MCELIECE_SMALL
    , byte** val
#endif
    )
{
    const int t = p->t;
    word32 off = 0;

    /* nums (FixedWeight) and ind (scatter) are both dead before row (the
     * syndrome working buffer) in both the C and assembly encode, so overlay
     * them onto row: 2t + t = 3t word16 = 6t bytes <= p->sBytes for every set.
     * The assembly encode reads only ind and row (not nums), with the same
     * lifetimes, so the overlap is safe there too. */
    *row  = (byte*)  mc_carve(s, &off, p->sBytes);
    *nums = (word16*)*row;
    *ind  = (word16*)(*row + (word32)sizeof(word16) * 2 * t);
#ifdef WOLFSSL_MCELIECE_SMALL
    *val  = (byte*)  mc_carve(s, &off, (word32)t);
#endif

    return off;
}
#endif

#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
/* Driver + shared FFT-callee scratch (word64) handed to the asm decode kernels
 * instead of large stack frames. Not secret-cleared (see
 * wc_mceliece_dec_layout). */
#define MC_DEC_DRIVER_SCRATCH_WORDS (1748 + 808)

/* NEON C driver scratch (word64), replacing its large stack frame: ksc (the
 * shared goppa-eval / syndrome / Berlekamp-Massey / FFT scratch, used strictly
 * sequentially) plus srecv/sreenc (mc_bs4) and poly (mc_bs2). Unlike the x86
 * monolithic scratch this holds decode secrets, so it stays inside the
 * ForceZero'd region. */
#define MC_DEC_NEON_KSC_WORDS   640
#define MC_DEC_NEON_SCRATCH_WORDS \
    (MC_DEC_NEON_KSC_WORDS + MCELIECE_M * 4 + MCELIECE_M * 4 + MCELIECE_M * 2)

/* Bitsliced einv/FFT footprint: the MC_Q field elements pack 256 to a group
 * (4 word64) across MCELIECE_M planes, so the C-path FFT buffers actually
 * touch only this many bytes - far less than the loose sizeof(mc_gf) * MC_Q. */
#define MC_DEC_BS_BYTES \
    ((word32)(MC_Q / 256) * MCELIECE_M * 4 * (word32)sizeof(word64))

/* Lay out the decapsulation scratch buffers within s, or size them when s is
 * NULL. Assigns each McDecBufs pointer an offset into s; overlaps buffers with
 * disjoint lifetimes (mulbuf and the bm scratch onto fftt) and sizes the
 * bitsliced buffers exactly, for both the C and assembly decode. The asm
 * driver scratch is carved last so the caller can exclude it from the secret
 * ForceZero, and is omitted entirely when
 * the asm decode is disabled (WOLFSSL_MCELIECE_DECAPSULATE_SMALL_MEM).
 *
 * @param  [in]   p  Parameter set (defines t and buffer sizes).
 * @param  [in]   s  Scratch base address, or NULL to only compute the size.
 * @param  [out]  b  Buffer pointers set to their offsets within s.
 * @return  Total scratch size in bytes.
 */
static word32 wc_mceliece_dec_layout(const McElieceParams* p, byte* s,
    McDecBufs* b)
{
    const int t = p->t;
    word32 off = 0;

    b->r       = (byte*)mc_carve(s, &off, (word32)(MC_Q >> 3));
    /* einv and the FFT work buffer are bitsliced, so they need exactly
     * MC_DEC_BS_BYTES (not sizeof(mc_gf) * MC_Q); fftw uses just 128 elements.
     * fftt and mulbuf are never live at the same time (the C decode alternates
     * roles; the asm decode uses fftt but never mulbuf), so mulbuf aliases
     * fftt. These reductions hold for both the C and assembly decode. */
    b->einv    = (mc_gf*)mc_carve(s, &off, MC_DEC_BS_BYTES);
    b->fftw    = (mc_gf*)mc_carve(s, &off, (word32)sizeof(mc_gf) * 128);
    b->fftt    = (mc_gf*)mc_carve(s, &off, MC_DEC_BS_BYTES);
    b->mulbuf  = b->fftt;
    /* Berlekamp-Massey scratch overlays fftt: the C bm() runs between the two
     * FFTs, when fftt holds nothing live (aff_fft rewrites it right after);
     * the asm decode never touches tmp/c/bp (its bm scratch is the driver
     * scratch below). 3(t+1) mc_gf, far less than MC_DEC_BS_BYTES. s and
     * locator stay separate - both are live across the bm() call. */
    b->tmp     = b->fftt;
    b->c       = b->fftt + (t + 1);
    b->bp      = b->fftt + 2 * (t + 1);
    b->s       = (mc_gf*)mc_carve(s, &off, (word32)sizeof(mc_gf) * 2 * t);
    b->locator = (mc_gf*)mc_carve(s, &off, (word32)sizeof(mc_gf) * (t + 1));
    b->bwork   = (byte*)mc_carve(s, &off, (word32)(MC_Q >> 3));
    b->benes   = (word64*)mc_carve(s, &off, (word32)sizeof(word64) * 384);
#if defined(MC_HAVE_DECODE_BS_ASM)
    /* Driver scratch for the x86 monolithic asm decode: 148 slots + 1600 word64
     * shared benes bits = 1748 word64 (was a ~14KB stack frame), plus a shared
     * FFT-callee region (einv/fft_tr/btr_fwd/wc_mceliece_bm scratch, 808
     * word64) the driver hands down to those kernels. Carved LAST so the caller
     * can leave it out of the secret ForceZero (it held no clearing when it was
     * a stack frame; its secret content also lives in the cleared db.* bufs).
     * Only asm-touched. */
    b->scratch = (word64*)mc_carve(s, &off,
        (word32)sizeof(word64) * MC_DEC_DRIVER_SCRATCH_WORDS);
#elif defined(MC_HAVE_DECODE_NEON)
    /* NEON C driver scratch (ksc + srecv/sreenc/poly), replacing its stack
     * frame. Carved in the secret region. */
    b->scratch = (word64*)mc_carve(s, &off,
        (word32)sizeof(word64) * MC_DEC_NEON_SCRATCH_WORDS);
#else
    /* No asm/NEON decode driver in this build (pure C uses its own buffers). */
    b->scratch = NULL;
#endif

    return off;
}
#endif

#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
/* Total scratch size needed by key generation for the parameter set.
 *
 * @param  [in]  p  Parameter set.
 * @return  Scratch size in bytes.
 * @return  0 on allocation failure.
 */
word32 wc_mceliece_keygen_scratch_sz(const McElieceParams* p)
{
    WC_DECLARE_VAR(b, McKgBufs, 1, NULL);
    WC_DECLARE_VAR(bb, McBsBufs, 1, NULL);
    word32 sz = 0;

    WC_ALLOC_VAR(b, McKgBufs, 1, NULL);
    WC_ALLOC_VAR(bb, McBsBufs, 1, NULL);
    if (WC_VAR_OK(b) && WC_VAR_OK(bb)) {
        sz = wc_mceliece_kg_layout(p, NULL, b, bb);
    }
    WC_FREE_VAR(bb, NULL);
    WC_FREE_VAR(b, NULL);
    return sz;
}

/* Size of the public-key buffer during key generation. The systematic MatGen
 * matrix is built in place there (mt rows, each padded to an 8-byte multiple),
 * so it must hold the full mt x n matrix rather than just the packed public
 * key; wc_mceliece_make_key shrinks it back to p->pubSz afterwards.
 *
 * @param  [in]  p  Parameter set.
 * @return  Public-key buffer size in bytes for key generation.
 */
word32 wc_mceliece_keygen_pk_sz(const McElieceParams* p)
{
    return (word32)p->mt * (((p->sBytes + 7) >> 3) * 8);
}
#endif

#ifndef WOLFSSL_MCELIECE_NO_ENCAPSULATE
/* Total scratch size needed by encapsulation for the parameter set.
 *
 * @param  [in]  p  Parameter set.
 * @return  Scratch size in bytes.
 * @return  0 on allocation failure.
 */
word32 wc_mceliece_encap_scratch_sz(const McElieceParams* p)
{
    word16* nums;
    word16* ind;
    byte* row;
    word32 sz;
#ifdef WOLFSSL_MCELIECE_SMALL
    byte* val;

    sz = wc_mceliece_enc_layout(p, NULL, &nums, &ind, &row, &val);
#else
    sz = wc_mceliece_enc_layout(p, NULL, &nums, &ind, &row);
#endif
    return sz;
}
#endif

#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
/* Total scratch size needed by decapsulation decode for the parameter set.
 *
 * @param  [in]  p  Parameter set.
 * @return  Scratch size in bytes.
 * @return  0 on allocation failure.
 */
word32 wc_mceliece_decode_scratch_sz(const McElieceParams* p)
{
    WC_DECLARE_VAR(b, McDecBufs, 1, NULL);
    word32 sz = 0;

    WC_ALLOC_VAR(b, McDecBufs, 1, NULL);
    if (WC_VAR_OK(b)) {
        sz = wc_mceliece_dec_layout(p, NULL, b);
    }
    WC_FREE_VAR(b, NULL);
    return sz;
}
#endif

/* The whole wc_mceliece_pk_gen (MatGen) has a self-contained per-ISA asm
 * driver when the keygen kernels are built in; the C wc_mceliece_pk_gen below
 * is the runtime fallback (used when no asm driver is available). */

/* Reused decode kernels (defined later in this file), non-static so the asm
 * fftbuild monolith (wc_mceliece_bs_fftbuild_neon) can call them. Declared
 * unconditionally: they are defined in both the decode and make-key paths, so
 * their prototype must be visible wherever the definition compiles. */
WOLFSSL_LOCAL void wc_mceliece_aff_bs_poly(word64 in[MCELIECE_M][2],
    const mc_gf* c);
WOLFSSL_LOCAL int wc_mceliece_aff_fft(word64 out[32][MCELIECE_M][4],
    word64 in[MCELIECE_M][2], int monic);

#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
/* Bitsliced structured keygen (libmceliece avx/pk_gen.c port). A vec256 is a
 * word64[4]; the heavy kernels (wc_mceliece_aff_bs_poly / aff_fft /
 * aff_v256_mul / aff_inv256) are the existing decode asm, reused here. */
static int wc_mceliece_aff_v256_mul(word64 h[MCELIECE_M][4],
    word64 f[MCELIECE_M][4], const word64 g[MCELIECE_M][4]);
static int wc_mceliece_aff_inv256(word64 out[MCELIECE_M][4],
    word64 in[MCELIECE_M][4]);
WOLFSSL_LOCAL void wc_mceliece_aff_tables(void);
/* FFT-build vec256 GF multiply (C fallback; SIMD via the pk_gen monolith).
 *
 * @param  [out]  r  Product r = a * b (bitsliced vec256 GF).
 * @param  [in]   a  First operand.
 * @param  [in]   b  Second operand.
 * @return  0 on success.
 * @return  A field-op error code on failure.
 */
static int wc_mceliece_bs_v256_mul(word64 r[MCELIECE_M][4],
    word64 a[MCELIECE_M][4], word64 b[MCELIECE_M][4])
{
    return wc_mceliece_aff_v256_mul(r, a, b);
}
/* FFT-build vec256 GF inverse (C fallback; SIMD via the pk_gen monolith).
 *
 * @param  [out]  out  Inverse of in (bitsliced vec256 GF).
 * @param  [in]   in   Element to invert.
 * @return  0 on success.
 * @return  A field-op error code on failure.
 */
static int wc_mceliece_bs_inv256(word64 out[MCELIECE_M][4],
    word64 in[MCELIECE_M][4])
{
    return wc_mceliece_aff_inv256(out, in);
}

/* de-bitslice: 32 blocks x GFBITS planes of vec256 -> 8192 field elements.
 *
 * @param  [out]  out  8192 de-bitsliced field elements.
 * @param  [in]   in   32 blocks x GFBITS planes of vec256.
 */
static void wc_mceliece_bs_debitslice(word64* out, word64 in[32][MCELIECE_M][4])
{
    int i;
    int j;
    int r;
    int lane;

    for (i = 0; i < (1 << MCELIECE_M); i++) {
        out[i] = 0;
    }
    for (i = 0; i < 32; i++) {
        for (j = MCELIECE_M - 1; j >= 0; j--) {
            for (lane = 0; lane < 4; lane++) {
                word64 u = in[i][j][lane];

                for (r = 0; r < 64; r++) {
                    out[i * 256 + lane * 64 + r] <<= 1;
                    out[i * 256 + lane * 64 + r] |= (u >> r) & 1;
                }
            }
        }
    }
}

/* Fused inverse of de-bitslice (libmceliece to_bitslicing_2x): reads the packed
 * sorted keys and emits two bitsliced sets in one pass. out0 plane j takes bit
 * (GFBITS-1-j) of each key - the low GFBITS index bits read in reversed plane
 * order, i.e. support element bitrev(idx). out1 plane j takes bit (j+GFBITS)
 * - the packed inverse. Both land in the sorted (support) order, so this
 * replaces the scalar de/re-bitslice round-trip when building consts + prod.
 *
 * @param  [out]  out0  First bitsliced set (consts), in reversed plane order.
 * @param  [out]  out1  Second bitsliced set (prod), the packed inverse.
 * @param  [in]   in    Packed sorted keys.
 */
static void wc_mceliece_bs_tobitslice2x(
    word64 out0[32][MCELIECE_M][4],
    word64 out1[32][MCELIECE_M][4], const word64* in)
{
    int i;
    int j;
    int k;
    int r;

    for (i = 0; i < 32; i++) {
        for (j = MCELIECE_M - 1; j >= 0; j--) {
            word64 u0[4];
            word64 u1[4];

            for (k = 0; k < 4; k++) {
                u0[k] = 0;
                u1[k] = 0;
                for (r = 63; r >= 0; r--) {
                    word64 v = in[i * 256 + k * 64 + r];

                    u0[k] = (u0[k] << 1) | ((v >> (MCELIECE_M - 1 - j)) & 1);
                    u1[k] = (u1[k] << 1) | ((v >> (j + MCELIECE_M)) & 1);
                }
                out0[i][j][k] = u0[k];
                out1[i][j][k] = u1[k];
            }
        }
    }
}


/* Broadcast bit i of a bitsliced row word array to all 256 lanes of out.
 *
 * @param  [out]  out  Vec256 with bit i broadcast to all 256 lanes.
 * @param  [in]   w    Bitsliced row word array.
 * @param  [in]   i    Bit index to broadcast.
 */
static WC_INLINE void wc_mceliece_v256_bitmask(word64* out, const word64* w,
    int i)
{
    word64 m = (word64)0 - ((w[i >> 6] >> (i & 63)) & 1);

    out[0] = m;
    out[1] = m;
    out[2] = m;
    out[3] = m;
}

/* composeinv: y = x o pi^-1, done by stable-sorting (pi[i] << 16 | x[i]) and
 * taking the low 16 bits (libmceliece composeinv, uint16 values so the packed
 * key is non-negative and a u64 sort matches the int32 sort).
 *
 * @param  [in]   n        Number of elements.
 * @param  [out]  y        Composed permutation y = x o pi^-1.
 * @param  [in]   x        Input values.
 * @param  [in]   pi       Permutation.
 * @param  [in]   scratch  Sort scratch.
 */
static void wc_mceliece_bs_composeinv(int n, sword16* y,
    const sword16* x, const sword16* pi, word64* scratch)
{
    int i;

    for (i = 0; i < n; i++) {
        scratch[i] = ((word64)(word16)pi[i] << 16) | (word16)x[i];
    }
    wc_mceliece_u64_sort(scratch, n);
    for (i = 0; i < n; i++) {
        y[i] = (sword16)(scratch[i] & 0xFFFF);
    }
}

/* Swap rows i0,i1 of the par matrix (and their keys x) when x[i1] < x[i0].
 *
 * @param  [in,out]  x         Row sort keys.
 * @param  [in,out]  mat       Par matrix rows.
 * @param  [in]      parWidth  Par-phase batch width.
 * @param  [in]      i0        First row index.
 * @param  [in]      i1        Second row index.
 */
static void wc_mceliece_bs_minmax_rows(sword16* x, word64 (*mat)[7][4],
    int parWidth, int i0, int i1)
{
    word64 m = (word64)0 - (word64)(((word16)x[i1] < (word16)x[i0]) & 1);
    sword16 d = (sword16)((word16)(x[i0] ^ x[i1]) & (word16)m);
    int b;

    x[i0] ^= d;
    x[i1] ^= d;
    /* Constant-time swap of the two rows' vec256 (word64[4]) when m is all
     * ones: each lane XORs in the masked difference (no swap when m == 0). */
    for (b = 0; b < parWidth; b++) {
        word64* r0 = mat[i0][b];
        word64* r1 = mat[i1][b];
#if defined(WOLFSSL_MCELIECE_SMALL)
        int k;

        for (k = 0; k < 4; k++) {
            word64 s = (r0[k] ^ r1[k]) & m;

            r0[k] ^= s;
            r1[k] ^= s;
        }
#else
        word64 s0 = (r0[0] ^ r1[0]) & m;
        word64 s1 = (r0[1] ^ r1[1]) & m;
        word64 s2 = (r0[2] ^ r1[2]) & m;
        word64 s3 = (r0[3] ^ r1[3]) & m;

        r0[0] ^= s0;
        r1[0] ^= s0;
        r0[1] ^= s1;
        r1[1] ^= s1;
        r0[2] ^= s2;
        r1[2] ^= s2;
        r0[3] ^= s3;
        r1[3] ^= s3;
#endif
    }
}

/* Sort the par matrix rows by key x with a merge-exchange network (applies the
 * recorded permutation P to the regenerated right-hand columns).
 *
 * @param  [in]      n         Number of rows.
 * @param  [in,out]  x         Row sort keys.
 * @param  [in,out]  mat       Par matrix rows, permuted to key order.
 * @param  [in]      parWidth  Par-phase batch width.
 */
static void wc_mceliece_bs_sort_rows(int n, sword16* x, word64 (*mat)[7][4],
    int parWidth)
{
    int t = 1;
    int j;

    /* t = ceil(log2(n)): the least t with 2^t >= n (Knuth 5.2.2M). The first
     * pass then uses stride 2^(t-1), matching wc_mceliece_u64_sort's top. */
    while ((1 << t) < n) {
        t++;
    }
    for (j = t - 1; j >= 0; j--) {
        int p = 1 << j;
        int q = 1 << (t - 1);
        int r = 0;
        int d = p;

        for (;;) {
            int i;

            for (i = 0; i < n - d; i++) {
                if ((i & p) == r) {
                    wc_mceliece_bs_minmax_rows(x, mat, parWidth, i, i + d);
                }
            }
            if (q != p) {
                d = q - p;
                q = q / 2;
                r = p;
            }
            else {
                break;
            }
        }
    }
}

/* Bitsliced mov_columns on the vec256 LU block viewed as words
 * mat[PK_NROWS][nbiW] (nbiW = nBlocks_I*4). Swaps columns in the 32x64 window
 * at row mt-32 to reach semi-systematic form, updates pi and pivots. Port of
 * libmceliece mov_columns.
 *
 * @param  [in,out]  mat     Vec256 LU block; columns swapped toward
 *                           semi-systematic form.
 * @param  [in]      nbiW    Row width in word64 (nBlocks_I * 4).
 * @param  [in]      nRows   Number of rows.
 * @param  [in,out]  pi      Support permutation, updated by the column swaps.
 * @param  [in,out]  pivots  Pivot bits.
 * @return  0 on success.
 * @return  -1 when the 32x64 window is singular.
 */
static int wc_mceliece_bs_mov_columns(word64* mat, int nbiW,
    int nRows, sword16* pi, word64* pivots)
{
    int i;
    int j;
    int ret = 0;
    int pivotCol[32];
    word64 buf[32];
    word64 t;
    word64 d;
    const word64 one = 1;
    const int row = nRows - 32;
    const int blockIdx = row / 64;
    const int s = row & 63;

    for (i = 0; i < 32; i++) {
        buf[i] = (mat[(size_t)(row + i) * nbiW + blockIdx] >> s) |
                 (mat[(size_t)(row + i) * nbiW + blockIdx + 1] << (64 - s));
    }

    *pivots = 0;
    for (i = 0; i < 32; i++) {
        t = buf[i];
        for (j = i + 1; j < 32; j++) {
            t |= buf[j];
        }
        if (t == 0) {
            ret = -1;
            break;
        }
        pivotCol[i] = wc_mceliece_ctz(t);
        *pivots |= one << pivotCol[i];
        for (j = i + 1; j < 32; j++) {
            word64 mask = (buf[i] >> pivotCol[i]) & 1;

            mask -= 1;
            buf[i] ^= buf[j] & mask;
        }
        for (j = i + 1; j < 32; j++) {
            word64 mask = (buf[j] >> pivotCol[i]) & 1;

            mask = (word64)0 - mask;
            buf[j] ^= buf[i] & mask;
        }
    }

    for (i = 0; (i < 32) && (ret == 0); i++) {
        for (j = i + 1; j < 64; j++) {
            d = (word64)(pi[row + i] ^ pi[row + j]);
            /* Mask is all-ones only when j == pivotCol[i] (constant time). */
            d &= ctMask16Eq((int)j, pivotCol[i]);
            pi[row + i] ^= (sword16)d;
            pi[row + j] ^= (sword16)d;
        }
    }

    for (i = 0; (i < nRows) && (ret == 0); i++) {
        word64* mrow = &mat[(size_t)i * nbiW + blockIdx];

        t = (mrow[0] >> s) | (mrow[1] << (64 - s));
        for (j = 0; j < 32; j++) {
            d = t >> j;
            d ^= t >> pivotCol[j];
            d &= 1;
            t ^= d << pivotCol[j];
            t ^= d << j;
        }
        mrow[0] = (mrow[0] & (((word64)1 << s) - 1)) | (t << s);
        mrow[1] = (mrow[1] & ~(((word64)1 << s) - 1)) | (t >> (64 - s));
    }

    return ret;
}

/* FFT-build setup: load the Goppa polynomial from gbytes, initialise the
 * additive-FFT tables, and expand to the 128-coefficient bitslice input.
 *
 * @param  [out]  g       Goppa polynomial coefficients.
 * @param  [out]  fftw    Additive-FFT working coefficients (128 entries).
 * @param  [in]   gbytes  Serialised Goppa polynomial.
 * @param  [in]   t       Error weight.
 */
static void wc_mceliece_bs_gload(mc_gf* g, mc_gf* fftw, const byte* gbytes,
    int t)
{
    int i;

    g[t] = 1;
    for (i = 0; i < t; i++) {
        g[i] = wc_mceliece_load_gf(gbytes + i * 2);
    }
    wc_mceliece_aff_tables();
    for (i = 0; i < 128; i++) {
        fftw[i] = (mc_gf)((i <= t) ? g[i] : 0);
    }
}
/* Pack the field-ordering sort key: perm (sort field + duplicate detector) in
 * the top bits, the 13-bit inverse next, the 13-bit field index low.
 *
 * @param  [out]  buf     Packed field-ordering sort keys.
 * @param  [in]   perm    Field-ordering permutation values.
 * @param  [in]   fftinv  Batch-inverted FFT evaluations.
 */
static void wc_mceliece_bs_packbuf(word64* buf, const word32* perm,
    const word64* fftinv)
{
    int i;

    for (i = 0; i < MC_Q; i++) {
        buf[i] = (word64)perm[i] << 31;
        buf[i] |= ((word64)(fftinv[i] & MC_GFMASK)) << 13;
        buf[i] |= (word64)i;
    }
}
/* Duplicate-support check on the sorted keys, then extract pi. Returns -1 if
 * any two support elements collide (perm values must be distinct).
 *
 * @param  [out]  pi   Extracted support permutation.
 * @param  [in]   buf  Sorted packed keys.
 * @return  0 on success.
 * @return  -1 if any two support elements collide.
 */
static int wc_mceliece_bs_dup_pi(sword16* pi, const word64* buf)
{
    int i;
    int ret = 0;

    for (i = 1; (i < MC_Q) && (ret == 0); i++) {
        if ((buf[i - 1] >> 31) == (buf[i] >> 31)) {
            ret = -1;
        }
    }
    if (ret == 0) {
        for (i = 0; i < MC_Q; i++) {
            pi[i] = (sword16)(buf[i] & MC_GFMASK);
        }
    }
    return ret;
}
/* Seed the overlap block (first batch, b=0) from mat's last block: its L^-1 and
 * the mov_columns permutation were already applied during the LU.
 *
 * @param  [out]  par   Overlap block, seeded from mat's last block.
 * @param  [in]   mat   LU-reduced left block.
 * @param  [in]   mt    Number of parity rows.
 * @param  [in]   nbiW  Block width in word64.
 * @param  [in]   nbi   Number of I blocks.
 */
static void wc_mceliece_bs_overlap(word64* par, const word64* mat, int mt,
    int nbiW, int nbi)
{
    int row;
    int c;

    for (row = 0; row < mt; row++) {
        for (c = 0; c < 4; c++) {
            par[(size_t)row * 28 + c] =
                mat[(size_t)row * nbiW + (nbi - 1) * 4 + c];
        }
    }
}
/* Raw inputs for the bitsliced pk_gen asm driver (and the C phase helpers that
 * mirror it). Every field is 8 bytes so the asm addresses field i at base + i*8
 * (keep in sync with the k_* offsets in the generator). All buffers are
 * pre-carved by the C caller; the driver owns no allocation. */
typedef struct McBsKgCtx {
    const byte* gbytes;         /*   0 */
    const word32* perm;         /*   8 */
    sword16* pi;                /*  16 */
    word64* buf;                /*  24 */
    word64* mat;                /*  32 */
    word64* prod;               /*  40 */
    word64* consts;             /*  48 */
    word64* eval;               /*  56 */
    word64* fftinv;             /*  64 */
    word64* par;                /*  72 */
    sword16* ind;               /*  80 */
    sword16* indInv;            /*  88 */
    byte* tmat;                 /*  96 */
    word64* scratch;            /* 104 */
    word64* pivots;             /* 112 */
    byte* pk;                   /* 120 */
    mc_gf* g;                   /* 128 */
    word64 t;                   /* 136 */
    word64 mt;                  /* 144 */
    word64 mono;                /* 152 */
    word64 isF;                 /* 160 */
    word64 numBlocks;           /* 168 */
    word64 firstBlock;          /* 176 */
    word64 tmatStride;          /* 184 */
    word64 nBytes;              /* 192 */
    word64 parW;                /* 200  par-phase batch width (AVX2 dispatch) */
} McBsKgCtx;

WOLFSSL_LOCAL int wc_mceliece_bs_phase10(const McBsKgCtx* c);
/* FFT-build (phases 1-6): evaluate the Goppa polynomial at every field element
 * via the additive FFT, batch-invert, fold the inverses into the field-ordering
 * sort key, and lay the inverse and support down (prod / consts) in support
 * order. Returns 0, -1 on a duplicate support, or a field-op error.
 *
 * Steps:
 *  1. Load g and expand it to the 128-coefficient FFT input, then build the
 *     bitsliced polynomial.
 *  2. Evaluate g at every field element via the additive FFT.
 *  3. Prefix products: prod[i] = eval[0] * ... * eval[i] per band.
 *  4. Batch-invert the final product and fold back so every evaluation is
 *     inverted.
 *  5. De-bitslice the inverses, pack the field-ordering sort key, sort, and
 *     reject a duplicate support.
 *  6. Lay the inverse (prod) and support (consts) down in support order.
 *
 * @param  [in]  c  Key-generation context.
 * @return  0 on success.
 * @return  -1 on a duplicate support.
 * @return  A field-op error code otherwise.
 */
static int wc_mceliece_bs_fftbuild(const McBsKgCtx* c)
{
    const int t = (int)c->t;
    const int mono = (int)c->mono;
    word64 (*prod)[MCELIECE_M][4] = (word64(*)[MCELIECE_M][4])c->prod;
    word64 (*consts)[MCELIECE_M][4] = (word64(*)[MCELIECE_M][4])c->consts;
    word64 (*eval)[MCELIECE_M][4] = (word64(*)[MCELIECE_M][4])c->eval;
    word64* fftinv = c->fftinv;
    word64* buf = c->buf;
    sword16* pi = c->pi;
    const word32* perm = c->perm;
    mc_gf* g = c->g;
    const byte* gbytes = c->gbytes;
    int i;
    int k;
    int ret = 0;
    /* Heap-backed under WOLFSSL_SMALL_STACK (~1.3 KB off the stack). */
    WC_DECLARE_VAR(fftw, mc_gf, 128, NULL);
    WC_DECLARE_VAR(poly, mc_bs2, MCELIECE_M, NULL);
    WC_DECLARE_VAR(u, mc_bs4, MCELIECE_M, NULL);
    WC_DECLARE_VAR(tmpg, mc_bs4, MCELIECE_M, NULL);

    WC_ALLOC_VAR(fftw, mc_gf, 128, NULL);
    WC_ALLOC_VAR(poly, mc_bs2, MCELIECE_M, NULL);
    WC_ALLOC_VAR(u, mc_bs4, MCELIECE_M, NULL);
    WC_ALLOC_VAR(tmpg, mc_bs4, MCELIECE_M, NULL);
    if (!WC_VAR_OK(fftw) || !WC_VAR_OK(poly) || !WC_VAR_OK(u) ||
            !WC_VAR_OK(tmpg)) {
        ret = MEMORY_E;
        goto cleanup;
    }

    /* 1. Load g, expand to the FFT input and build the bitsliced polynomial. */
    wc_mceliece_bs_gload(g, fftw, gbytes, t);
    wc_mceliece_aff_bs_poly(poly, fftw);
    /* 2. Evaluate g at every field element via the additive FFT. */
    ret = wc_mceliece_aff_fft(eval, poly, mono);
    if (ret == 0) {
        /* 3. Prefix products: prod[i] = eval[0] * ... * eval[i] per band. */
        for (k = 0; k < MCELIECE_M; k++) {
            prod[0][k][0] = eval[0][k][0];
            prod[0][k][1] = eval[0][k][1];
            prod[0][k][2] = eval[0][k][2];
            prod[0][k][3] = eval[0][k][3];
        }
        for (i = 1; (i < 32) && (ret == 0); i++) {
            ret = wc_mceliece_bs_v256_mul(prod[i], prod[i - 1], eval[i]);
        }
        /* 4. Batch-invert the final product and fold back to invert every
         * evaluation. */
        if (ret == 0) {
            ret = wc_mceliece_bs_inv256(u, prod[31]);
        }
        for (i = 31; (i >= 1) && (ret == 0); i--) {
            ret = wc_mceliece_bs_v256_mul(tmpg, u, prod[i - 1]);
            if (ret == 0) {
                ret = wc_mceliece_bs_v256_mul(u, u, eval[i]);
            }
            if (ret == 0) {
                for (k = 0; k < MCELIECE_M; k++) {
                    prod[i][k][0] = tmpg[k][0];
                    prod[i][k][1] = tmpg[k][1];
                    prod[i][k][2] = tmpg[k][2];
                    prod[i][k][3] = tmpg[k][3];
                }
            }
        }
        if (ret == 0) {
            for (k = 0; k < MCELIECE_M; k++) {
                prod[0][k][0] = u[k][0];
                prod[0][k][1] = u[k][1];
                prod[0][k][2] = u[k][2];
                prod[0][k][3] = u[k][3];
            }
        }
    }
    if (ret == 0) {
        /* 5. De-bitslice, pack the sort key, sort, reject dup support. */
        wc_mceliece_bs_debitslice(fftinv, prod);
        wc_mceliece_bs_packbuf(buf, perm, fftinv);
        wc_mceliece_u64_sort(buf, MC_Q);
        if (wc_mceliece_bs_dup_pi(pi, buf) != 0) {
            ret = -1;
        }
    }
    if (ret == 0) {
        /* 6. Emit the inverse (prod) and support (consts) in support order. */
        wc_mceliece_bs_tobitslice2x(consts, prod, buf);
    }

cleanup:
    WC_FREE_VAR(fftw, NULL);
    WC_FREE_VAR(poly, NULL);
    WC_FREE_VAR(u, NULL);
    WC_FREE_VAR(tmpg, NULL);
    return ret;
}

/* Phase 10: regenerate the right columns in par_width blocks and apply P
 * (sort_rows), L^-1 and U^-1 to obtain T in the scratch byte-matrix tmat.
 *
 * @param  [in]  c  Key-generation context.
 * @return  0 on success.
 * @return  MEMORY_E if a bitsliced-multiply scratch allocation fails.
 */
int wc_mceliece_bs_phase10(const McBsKgCtx* c)
{
    const int t = (int)c->t;
    const int mt = (int)c->mt;
    const int numBlocks = (int)c->numBlocks;
    const int firstBlock = (int)c->firstBlock;
    const int tmatStride = (int)c->tmatStride;
    const int m = MCELIECE_M;
    const int nbi = MC_BS_NBI(mt);
    const int nbiW = nbi * 4;
    const int parW = 7;
    word64 (*prod)[MCELIECE_M][4] = (word64(*)[MCELIECE_M][4])c->prod;
    word64 (*consts)[MCELIECE_M][4] = (word64(*)[MCELIECE_M][4])c->consts;
    word64 (*par)[7][4] = (word64(*)[7][4])c->par;
    word64* mat = c->mat;
    sword16* ind = c->ind;
    sword16* indInv = c->indInv;
    byte* tmat = c->tmat;
    int i;
    int j;
    int kk;
    int b;
    int row;
    int cc;
    int ret = 0;

    XMEMSET(tmat, 0, (size_t)mt * tmatStride);
    for (j = firstBlock; (ret == 0) && (j < numBlocks); j += parW) {
        for (kk = 0; kk < m; kk++) {
            for (b = 0; b < parW; b++) {
                if (j + b < numBlocks) {
                    for (cc = 0; cc < 4; cc++) {
                        par[kk][b][cc] = prod[j + b][kk][cc];
                    }
                }
            }
        }
        for (i = 1; (ret == 0) && (i < t); i++) {
            for (b = 0; b < parW; b++) {
                if ((j + b < numBlocks) && (ret == 0)) {
                    ret = wc_mceliece_aff_v256_mul(prod[j + b], prod[j + b],
                        consts[j + b]);
                }
            }
            for (kk = 0; kk < m; kk++) {
                for (b = 0; b < parW; b++) {
                    if (j + b < numBlocks) {
                        for (cc = 0; cc < 4; cc++) {
                            par[i * m + kk][b][cc] = prod[j + b][kk][cc];
                        }
                    }
                }
            }
        }
        /* Copy the inverse permutation into the working index for the par
         * phase. */
        for (i = 0; i < mt; i++) {
            ind[i] = indInv[i];
        }
        wc_mceliece_bs_sort_rows(mt, ind, par, parW);
        for (row = mt - 1; row >= 0; row--) {
            for (i = 0; i < row; i++) {
                word64 mm[4];

                wc_mceliece_v256_bitmask(mm, mat + (size_t)row * nbiW, i);
                for (b = 0; b < parW; b++) {
                    for (cc = 0; cc < 4; cc++) {
                        par[row][b][cc] ^= par[i][b][cc] & mm[cc];
                    }
                }
            }
        }
        /* The overlap block (first batch, b=0) is part of the LU block: its
         * L^-1 and the mov_columns permutation were already applied there, so
         * take it from mat's last block and apply only U^-1 below. */
        if (j == firstBlock) {
            wc_mceliece_bs_overlap((word64*)par, mat, mt, nbiW, nbi);
        }
        for (row = mt - 1; row >= 0; row--) {
            for (i = mt - 1; i > row; i--) {
                word64 mm[4];

                wc_mceliece_v256_bitmask(mm, mat + (size_t)row * nbiW, i);
                for (b = 0; b < parW; b++) {
                    for (cc = 0; cc < 4; cc++) {
                        par[row][b][cc] ^= par[i][b][cc] & mm[cc];
                    }
                }
            }
        }
        for (b = 0; b < parW; b++) {
            const int blk = j + b;

            if (blk < numBlocks) {
                for (row = 0; row < mt; row++) {
                    /* Serialise the 4 vec256 words little-endian: par is
                     * bitsliced (numeric bit order) and pk/tmat are byte
                     * packed, so a raw copy would byte-swap the columns on
                     * big-endian hosts. */
                    byte* dst = tmat + (size_t)row * tmatStride + blk * 32;
                    wc_mceliece_store8(dst +  0, par[row][b][0]);
                    wc_mceliece_store8(dst +  8, par[row][b][1]);
                    wc_mceliece_store8(dst + 16, par[row][b][2]);
                    wc_mceliece_store8(dst + 24, par[row][b][3]);
                }
            }
        }
    }

    return ret;
}

/* Populate the McBsKgCtx read by the bitsliced pk_gen asm from pre-carved
 * buffers and the parameter set.
 *
 * @param  [in]   p       Parameter set.
 * @param  [in]   pk      Public-key buffer.
 * @param  [in]   gbytes  Serialised Goppa polynomial.
 * @param  [in]   kb      Key-generation buffers.
 * @param  [in]   pivots  Pivot bits.
 * @param  [in]   b       Bitsliced workspaces.
 * @param  [out]  kc      Context populated for the bitsliced pk_gen asm.
 * @param  [in]   parW    Par-phase batch width.
 */
static void wc_mceliece_bs_ctx_fill(const McElieceParams* p, byte* pk,
    const byte* gbytes, McKgBufs* kb, word64* pivots, const McBsBufs* b,
    McBsKgCtx* kc, int parW)
{
    const int mt = p->mt;
    const int numBlocks = (p->n + 255) / 256;

    kc->gbytes = gbytes;
    kc->perm = kb->perm;
    kc->pi = kb->pi;
    kc->buf = kb->buf;
    kc->mat = b->mat;
    kc->prod = (word64*)b->prod;
    kc->consts = (word64*)b->consts;
    kc->eval = (word64*)b->eval;
    kc->fftinv = b->fftinv;
    kc->par = (word64*)b->par;
    kc->ind = b->ind;
    kc->indInv = b->indInv;
    kc->tmat = b->tmat;
    kc->scratch = b->scratch;
    kc->pivots = pivots;
    kc->pk = pk;
    kc->g = kb->g;
    kc->t = (word64)p->t;
    kc->mt = (word64)mt;
    kc->mono = (word64)(p->t == 128);
    kc->isF = (word64)p->f;
    kc->numBlocks = (word64)numBlocks;
    kc->firstBlock = (word64)(mt / 256);
    kc->tmatStride = (word64)(numBlocks * 32);
    kc->nBytes = (word64)p->sBytes;
    kc->parW = (word64)parW;
}

#if defined(MC_HAVE_BS_KEYGEN_AVX512) || defined(MC_HAVE_BS_KEYGEN_AVX2)
/* AVX2 par-phase batch width: a fixed value per parameter set - the largest of
 * {7, 11, 13} that evenly divides the par-block count (numBlocks - firstBlock)
 * so the batched par apply wastes no slots. Matches libmceliece's per-variant
 * par_width. (The AVX512 driver always uses 7.)
 *
 * @param  [in]  p  Parameter set.
 * @return  The selected par-phase batch width.
 */
static int wc_mceliece_bs_parwidth(const McElieceParams* p)
{
    switch (p->n) {
    case WC_MCELIECE_8192128_N:                /* 26 par blocks */
        return 13;
    case WC_MCELIECE_6960119_N:                /* 22 par blocks */
        return 11;
    default:                                   /* 6688128: 21 par blocks */
        return 7;
    }
}
#endif /* MC_HAVE_BS_KEYGEN_AVX512 || MC_HAVE_BS_KEYGEN_AVX2 */

/* Bitsliced structured MatGen (libmceliece-style): build the parity-check
 * matrix left block via the additive-FFT + prod/consts recurrence, cswap-LU it
 * (storing L^-1 and U in place, P in ind), then regenerate the right columns
 * in par_width blocks and apply P (sort_rows), L^-1 and U^-1 to obtain T. Byte-
 * identical pk/pi/pivots to the reference; the cache-local vector ops are the
 * keygen speed-up. The large workspaces (bufs) are carved from the keygen
 * scratch by the caller.
 *
 * Steps:
 *  1-6. FFT build (in wc_mceliece_bs_fftbuild): evaluate g over the field,
 *       batch-invert, sort into support order.
 *  7. Fill the LU block from prod, advancing prod by consts per band.
 *  8. cswap-LU: P M = L U, storing L^-1 and U in mat, P in ind.
 *  9. indInv = P^-1.
 *  10. Regenerate the right columns per par block, apply P, L^-1 and U^-1 into
 *      the scratch byte-matrix tmat.
 *  11. Extract T (columns >= mt) from tmat into pk.
 *
 * @param  [in]      p       Parameter set.
 * @param  [in,out]  pk      Public-key buffer; the mt x n matrix is built and
 *                           reduced in place.
 * @param  [in]      gbytes  Serialised Goppa polynomial.
 * @param  [in]      kb      Key-generation buffers.
 * @param  [in,out]  pivots  Pivot bits recorded during the LU.
 * @param  [in]      bufs    Bitsliced MatGen workspaces (carved from the keygen
 *                           scratch).
 * @return  0 on success.
 * @return  1 to retry (singular matrix).
 * @return  A negative error code otherwise.
 */
static int wc_mceliece_pk_gen(const McElieceParams* p, byte* pk,
    const byte* gbytes, McKgBufs* kb, word64* pivots, McBsBufs* bufs)
{
    const int t = p->t;
    const int mt = p->mt;
    const int n = p->n;
    const int m = MCELIECE_M;
    const int nbi = MC_BS_NBI(mt);
    const int nbiW = nbi * 4;
    const int numBlocks = (n + 255) / 256;
    const int tmatStride = numBlocks * 32;
    const int nBytes = (int)p->sBytes;
    const int rowBytes = (int)((p->k + 7) >> 3);
    const int skip = mt >> 3;
    const int tail = mt & 0x7;
    sword16* pi = kb->pi;
    int ret = 0;
    int i;
    int j;
    int kk;
    int row;
    int c;
    word64 (*prod)[MCELIECE_M][4];
    word64 (*consts)[MCELIECE_M][4];
    word64* mat;
    word64* scratch;
    sword16* ind;
    sword16* indInv;
    byte* tmat;
    McBsKgCtx kc;

    prod = bufs->prod;
    consts = bufs->consts;
    mat = bufs->mat;
    scratch = bufs->scratch;
    ind = bufs->ind;
    indInv = bufs->indInv;
    tmat = bufs->tmat;
    wc_mceliece_bs_ctx_fill(p, pk, gbytes, kb, pivots, bufs, &kc, 7);

    /* 1-6. FFT build: evaluate g over the field, batch-invert, sort into
     * support order and lay down prod (inverses) and consts (support). */
    ret = wc_mceliece_bs_fftbuild(&kc);
    if (ret == 0) {
        /* 7. Fill LU block from prod, advancing prod by consts per band. */
        for (kk = 0; kk < m; kk++) {
            for (j = 0; j < nbi; j++) {
                for (c = 0; c < 4; c++) {
                    mat[(size_t)kk * nbiW + j * 4 + c] = prod[j][kk][c];
                }
            }
        }
        for (i = 1; (ret == 0) && (i < t); i++) {
            for (j = 0; (ret == 0) && (j < nbi); j++) {
                ret = wc_mceliece_aff_v256_mul(prod[j], prod[j], consts[j]);
                for (kk = 0; (ret == 0) && (kk < m); kk++) {
                    for (c = 0; c < 4; c++) {
                        mat[((size_t)(i * m + kk)) * nbiW + j * 4 + c] =
                            prod[j][kk][c];
                    }
                }
            }
        }

        /* 8. cswap-LU: P M = L U, storing L^-1 and U in mat, P in ind. */
        for (i = 0; i < mt; i++) {
            ind[i] = (sword16)i;
            indInv[i] = (sword16)i;
        }
        for (row = 0; (row < mt) && (ret == 0); row++) {
            const int iBlk = row >> 6;
            const int jBit = row & 63;

            if (p->f && (row == mt - 32)) {
                if (wc_mceliece_bs_mov_columns(mat, nbiW, mt, pi,
                        pivots) != 0) {
                    ret = -1;
                    break;
                }
            }
            for (kk = row + 1; kk < mt; kk++) {
                word64 xb = (mat[(size_t)row * nbiW + iBlk] >> jBit) & 1;
                word64 yb = (mat[(size_t)kk * nbiW + iBlk] >> jBit) & 1;
                word64 mask = (word64)0 - (yb & (xb ^ 1));
                sword16 di = (sword16)((word16)(ind[row] ^ ind[kk]) &
                    (word16)mask);

                ind[row] ^= di;
                ind[kk] ^= di;
                for (c = 0; c < nbiW; c++) {
                    word64 d = (mat[(size_t)row * nbiW + c] ^
                        mat[(size_t)kk * nbiW + c]) & mask;

                    mat[(size_t)row * nbiW + c] ^= d;
                    mat[(size_t)kk * nbiW + c] ^= d;
                }
            }
            if (((mat[(size_t)row * nbiW + iBlk] >> jBit) & 1) == 0) {
                ret = -1;
                break;
            }
            for (kk = row + 1; kk < mt; kk++) {
                word64 bit = (mat[(size_t)kk * nbiW + iBlk] >> jBit) & 1;
                word64 saved = mat[(size_t)kk * nbiW + iBlk] &
                    ((word64)1 << jBit);
                word64 mm = (word64)0 - bit;

                for (c = 0; c < nbiW; c++) {
                    mat[(size_t)kk * nbiW + c] ^=
                        mat[(size_t)row * nbiW + c] & mm;
                }
                mat[(size_t)kk * nbiW + iBlk] |= saved;
            }
        }
    }
    if (ret == 0) {
        /* 9. indInv = P^-1. */
        wc_mceliece_bs_composeinv(mt, indInv, indInv, ind, scratch);

        /* 10. Regenerate right columns per par block, apply P, L^-1, U^-1
         * into the scratch byte-matrix tmat. */
        ret = wc_mceliece_bs_phase10(&kc);

        /* 11. Extract T (columns >= mt) from tmat into pk. */
        if ((ret == 0) && (tail == 0)) {
            for (i = 0; i < mt; i++) {
                XMEMCPY(pk + (size_t)i * rowBytes,
                    tmat + (size_t)i * tmatStride + skip, (size_t)rowBytes);
            }
        }
        else if (ret == 0) {
            byte* pkp = pk;

            for (i = 0; i < mt; i++) {
                const byte* mrow = tmat + (size_t)i * tmatStride;

                for (j = skip; j < nBytes - 1; j++) {
                    *pkp++ = (byte)((mrow[j] >> tail) |
                        (mrow[j + 1] << (8 - tail)));
                }
                *pkp++ = (byte)(mrow[nBytes - 1] >> tail);
            }
        }
    }
    return ret;
}
#endif

/******************************************************************************/
/* Key generation (SeededKeyGen).                                             */
/******************************************************************************/

#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
/* One-shot SHAKE256: out[0..outLen) = SHAKE256(in[0..inLen)).
 *
 * @param  [in]   shake   SHAKE-256 object to (re)initialise and run.
 * @param  [in]   in      Input bytes.
 * @param  [in]   inLen   Input length.
 * @param  [out]  out     Output bytes.
 * @param  [in]   outLen  Output length.
 * @return  0 on success.
 * @return  A hash error otherwise.
 */
static int wc_mceliece_shake256(wc_Shake* shake, const byte* in, word32 inLen,
    byte* out, word32 outLen)
{
    int ret;
    int devId = INVALID_DEVID;
#ifdef WOLF_CRYPTO_CB
    devId = shake->devId;
#endif

    /* Reset the reusable sponge but preserve its heap and devId so a configured
     * heap hint / crypto callback survives (do not stomp them with NULL). */
    ret = wc_InitShake256(shake, shake->heap, devId);
    if (ret == 0) {
        ret = wc_Shake256_Update(shake, in, inLen);
    }
    if (ret == 0) {
        ret = wc_Shake256_Final(shake, out, outLen);
    }

    return ret;
}

/* Pure-C key generation core - the portable-C equivalent of the per-ISA asm
 * keygen drivers (wc_mceliece_keygen_drv_avx2/avx512): genpoly -> serialise the
 * irreducible polynomial into the private key at skp -> wc_mceliece_pk_gen
 * (systematic MatGen) -> control bits at skp + irrBytes. pivots is updated by
 * wc_mceliece_pk_gen. Returns 0 on success, 1 to request a retry (genpoly
 * rejection / singular MatGen), or BAD_STATE_E on a control-bit failure - the
 * same return convention as the asm drivers, so the caller handles both paths
 * identically.
 *
 * Steps:
 *  1. genpoly: build the irreducible Goppa polynomial from f.
 *  2. Serialise the polynomial into the private key.
 *  3. Systematic MatGen (wc_mceliece_pk_gen), producing pk and the pivots.
 *  4. Control bits for the support permutation.
 *
 * @param  [in]      p       Parameter set.
 * @param  [out]     pk      Public-key buffer; the parity matrix is built and
 *                           reduced in place.
 * @param  [out]     skp     Private-key body: irreducible polynomial then, at
 *                           +irrBytes, the control bits.
 * @param  [in]      kb      Pre-carved key-generation buffers.
 * @param  [in,out]  pivots  MatGen pivot bits, updated by pk_gen.
 * @param  [in]      bsbufs  Bitsliced pk_gen workspaces.
 * @return  0 on success.
 * @return  1 to request a retry.
 * @return  A negative hard error code otherwise.
 */
static WC_NO_INLINE int wc_mceliece_keygen_c(const McElieceParams* p, byte* pk,
    byte* skp, McKgBufs* kb, word64* pivots, McBsBufs* bsbufs)
{
    int i;
    const int t = p->t;
    int ret = 0;

    /* 1. genpoly: build the irreducible Goppa polynomial from f. */
    if (wc_mceliece_genpoly_gen(kb->irr, kb->f, t, kb->gmat, kb->gprod) != 0) {
        ret = 1;
    }
    else {
        int pret;

        /* 2. Serialise the polynomial into the private key. */
        for (i = 0; i < t; i++) {
            wc_mceliece_store_gf(skp + i * 2, kb->irr[i]);
        }
        /* 3. Systematic MatGen (produces pk and the pivots). */
        pret = wc_mceliece_pk_gen(p, pk, skp, kb, pivots, bsbufs);
        /* pk_gen: 0 = success; +/-1 = non-systematic MatGen (retry); any other
         * nonzero (e.g. MEMORY_E) is a hard error - propagate, do not retry
         * (else a persistent allocation failure would loop forever). */
        if ((pret != 0) && (pret != 1) && (pret != -1)) {
            ret = pret;
        }
        else if (pret != 0) {
            ret = 1;
        }
        /* 4. Control bits for the support permutation. */
        else if (wc_mceliece_gen_controlbits(skp + p->irrBytes,
                kb->pi, MCELIECE_M, MC_Q, kb->cbtmp, kb->pitest,
                kb->frames) != 0) {
            ret = BAD_STATE_E;
        }
    }
    return ret;
}

/* Generate a key pair from a 32-byte delta seed (SeededKeyGen, draft 8.3).
 * Field ordering / irreducible / MatGen failures retry internally (SHAKE
 * derived, so no further external randomness is consumed).
 *
 * @param  [in]   p        Parameter set.
 * @param  [in]   shake    Reusable SHAKE-256 object for the PRG.
 * @param  [in]   delta    32-byte seed.
 * @param  [out]  pk       Encoded public key (p->pubSz bytes).
 * @param  [out]  sk       Encoded private key (p->privSz bytes).
 * @param  [in]   scratch  Buffer of wc_mceliece_keygen_scratch_sz(p) bytes.
 * @return  0 on success.
 * @return  BAD_STATE_E otherwise.
 * @return  A hash error otherwise.
 */


#if defined(MC_HAVE_BS_KEYGEN_AVX512) || defined(MC_HAVE_BS_KEYGEN_AVX2)
/* Bitsliced keygen sub-kernels (asm) the C keygen drivers orchestrate
 * (genpoly -> serialize -> pk_gen -> controlbits), one driver per ISA in
 * place of a single monolithic asm keygen entry. */
WOLFSSL_LOCAL int wc_mceliece_genpoly_avx512(mc_gf* out, mc_gf* f, int t,
    mc_gf* mat, mc_gf* prod);
WOLFSSL_LOCAL int wc_mceliece_genpoly_avx2(mc_gf* out, mc_gf* f, int t,
    mc_gf* mat, mc_gf* prod);
WOLFSSL_LOCAL int wc_mceliece_bs_pk_gen_avx2(const void* ctx);
#endif

#ifdef MC_HAVE_BS_KEYGEN_AVX512
/* C keygen driver (AVX512): the three phase asm kernels (genpoly,
 * bitsliced pk_gen, controlbits) in sequence, irr serialise glue in C.
 * Returns 0 / 1 (retry) / negative error (hard).
 *
 * @param  [in]      p       Parameter set.
 * @param  [out]     pk      Public-key buffer; the parity matrix is built and
 *                           reduced in place.
 * @param  [out]     skp     Private-key body: irreducible polynomial then, at
 *                           +irrBytes, the control bits.
 * @param  [in]      kb      Pre-carved key-generation buffers.
 * @param  [in,out]  pivots  MatGen pivot bits, updated by pk_gen.
 * @param  [in]      bsbufs  Bitsliced pk_gen workspaces.
 * @param  [in]      bsParW  Par-phase batch width.
 * @param  [in]      f       Goppa polynomial coefficients (genpoly output).
 * @param  [in]      t       Error weight.
 * @return  0 on success.
 * @return  1 to request a retry.
 * @return  A negative hard error code otherwise.
 */
static int wc_mceliece_keygen_drv_avx512(const McElieceParams* p, byte* pk,
    byte* skp, McKgBufs* kb, word64* pivots, McBsBufs* bsbufs, int bsParW,
    mc_gf* f, int t)
{
    McBsKgCtx kc;
    int ret;
    int i;

    wc_mceliece_bs_ctx_fill(p, pk, skp, kb, pivots, bsbufs, &kc, bsParW);
    ret = wc_mceliece_genpoly_avx512(kb->irr, f, t, kb->gmat, kb->gprod);
    if (ret != 0) {
        ret = 1;
    }
    else {
        for (i = 0; i < t; i++) {
            wc_mceliece_store_gf(skp + i * 2, kb->irr[i]);
        }
        ret = wc_mceliece_bs_pk_gen_avx512(&kc);
        if (ret != 0) {
            ret = 1;
        }
        else if (wc_mceliece_controlbits_avx512(skp + p->irrBytes, kb->pi,
                MCELIECE_M, MC_Q, kb->cbtmp, kb->pitest, kb->frames) != 0) {
            /* Hard failure: return a negative error (matching the C path),
             * not the positive retry-convention code. */
            ret = BAD_STATE_E;
        }
    }
    return ret;
}
#endif

#ifdef MC_HAVE_BS_KEYGEN_AVX2
/* C keygen driver (AVX2): the three AVX2 phase asm kernels in sequence.
 *
 * @param  [in]      p       Parameter set.
 * @param  [out]     pk      Public-key buffer; the parity matrix is built and
 *                           reduced in place.
 * @param  [out]     skp     Private-key body: irreducible polynomial then, at
 *                           +irrBytes, the control bits.
 * @param  [in]      kb      Pre-carved key-generation buffers.
 * @param  [in,out]  pivots  MatGen pivot bits, updated by pk_gen.
 * @param  [in]      bsbufs  Bitsliced pk_gen workspaces.
 * @param  [in]      bsParW  Par-phase batch width.
 * @param  [in]      f       Goppa polynomial coefficients (genpoly output).
 * @param  [in]      t       Error weight.
 * @return  0 on success.
 * @return  1 to request a retry.
 * @return  A negative hard error code otherwise.
 */
static int wc_mceliece_keygen_drv_avx2(const McElieceParams* p, byte* pk,
    byte* skp, McKgBufs* kb, word64* pivots, McBsBufs* bsbufs, int bsParW,
    mc_gf* f, int t)
{
    McBsKgCtx kc;
    int ret;
    int i;

    wc_mceliece_bs_ctx_fill(p, pk, skp, kb, pivots, bsbufs, &kc, bsParW);
    ret = wc_mceliece_genpoly_avx2(kb->irr, f, t, kb->gmat, kb->gprod);
    if (ret != 0) {
        ret = 1;
    }
    else {
        for (i = 0; i < t; i++) {
            wc_mceliece_store_gf(skp + i * 2, kb->irr[i]);
        }
        ret = wc_mceliece_bs_pk_gen_avx2(&kc);
        if (ret != 0) {
            ret = 1;
        }
        else if (wc_mceliece_controlbits_avx2(skp + p->irrBytes, kb->pi,
                MCELIECE_M, MC_Q, kb->cbtmp, kb->pitest, kb->frames) != 0) {
            /* Hard failure: return a negative error (matching the C path),
             * not the positive retry-convention code. */
            ret = BAD_STATE_E;
        }
    }
    return ret;
}
#endif

#ifdef MC_HAVE_PKGEN_NEON
/* Coarse Goppa minimal-polynomial kernel (keygen phase 1; x86 genpoly_avx2
 * analogue). Computes the poly into out, stores it to skp (store_gf), then
 * chains directly into wc_mceliece_pk_gen_neon (phase 2). Returns 0, -1 if the
 * poly matrix is singular (reseed), or a pk_gen error. */
WOLFSSL_LOCAL int wc_mceliece_genpoly_neon(mc_gf* out, const mc_gf* f, int t,
    mc_gf* mat, mc_gf* prod, byte* skp, McBsKgCtx* ctx);
/* Benes control bits (keygen phase 3; x86 controlbits_avx2 analogue). */
WOLFSSL_LOCAL int wc_mceliece_controlbits_neon(byte* out, const sword16* pi,
    int w, int n, sword32* temp, sword16* pi_test, void* frames);

/* AArch64 NEON keygen driver. Symmetric with the x86 wc_mceliece_keygen_drv_*
 * entry points: the caller (wc_mceliece_keygen) holds one vector-register
 * window across the whole driver, so each phase calls its NEON implementation
 * directly. The inner MatGen kernels re-enter the (ref-counted) window as
 * no-ops.
 *
 * @param  [in]      p       Parameter set.
 * @param  [out]     pk      Public-key buffer; the parity matrix is built and
 *                           reduced in place.
 * @param  [out]     skp     Private-key body: irreducible polynomial then, at
 *                           +irrBytes, the control bits.
 * @param  [in]      kb      Pre-carved key-generation buffers.
 * @param  [in,out]  pivots  MatGen pivot bits, updated by pk_gen.
 * @param  [in]      bsbufs  Bitsliced pk_gen workspaces.
 * @return  0 on success.
 * @return  1 to request a retry.
 * @return  A negative hard error code otherwise.
 */
static int wc_mceliece_keygen_drv_neon(const McElieceParams* p, byte* pk,
    byte* skp, McKgBufs* kb, word64* pivots, McBsBufs* bsbufs)
{
    const int t = p->t;
    int ret = 0;
    int gret;
    McBsKgCtx kc;

    /* Build the ctx, then run phase 1 (genpoly): it stores the Goppa poly to
     * skp and chains directly into pk_gen_neon (phase 2). */
    wc_mceliece_bs_ctx_fill(p, pk, skp, kb, pivots, bsbufs, &kc, 7);
    /* Build the additive-FFT constant tables here (op level) so the asm path
     * never has to call into C: gload_neon no longer initialises them. */
    wc_mceliece_aff_tables();
    mc_set_gf_pmull();  /* pick PMULL vs bitsliced GF from CPU features */
    gret = wc_mceliece_genpoly_neon(kb->irr, kb->f, t, kb->gmat, kb->gprod,
        skp, &kc);
    if ((gret != 0) && (gret != 1) && (gret != -1)) {
        ret = gret;             /* hard error (e.g. fftbuild MEMORY_E) */
    }
    else if (gret != 0) {
        ret = 1;                /* singular poly or MatGen -> reseed */
    }
    /* Phase 3: Benes control bits (asm orchestrator over cb_build/cb_layer). */
    else if (wc_mceliece_controlbits_neon(skp + p->irrBytes, kb->pi,
            MCELIECE_M, MC_Q, kb->cbtmp, kb->pitest, kb->frames) != 0) {
        ret = BAD_STATE_E;
    }
    return ret;
}
#endif /* MC_HAVE_PKGEN_NEON */

/* Key-generation dispatcher: run one attempt with the best available
 * implementation - the bitsliced AVX512/AVX2 driver when its ISA is available
 * at run time (using the caller's pre-allocated bitsliced workspaces), the NEON
 * driver on AArch64, else the portable C keygen. One vector-register window
 * wraps the x86 asm path. Returns 0 on success, 1 to retry with a fresh seed,
 * or a hard error.
 *
 * @param  [in]      p       Parameter set.
 * @param  [out]     pk      Public-key buffer.
 * @param  [out]     skp     Private-key body.
 * @param  [in]      kb      Pre-carved key-generation buffers.
 * @param  [in,out]  pivots  MatGen pivot bits, updated by pk_gen.
 * @param  [in]      bsbufs  Bitsliced pk_gen workspaces.
 * @return  0 on success.
 * @return  1 to retry with a fresh seed.
 * @return  A negative hard error code otherwise.
 */
static int wc_mceliece_keygen(const McElieceParams* p, byte* pk, byte* skp,
    McKgBufs* kb, word64* pivots, McBsBufs* bsbufs)
{
    int kret = 0;
    int done = 0;

#if defined(MC_HAVE_BS_KEYGEN_AVX512) || defined(MC_HAVE_BS_KEYGEN_AVX2)
    /* Select the monolithic asm keygen (genpoly -> pk_gen -> controlbits over
     * one context) when its ISA is available at run time: prefer AVX512, else
     * AVX2. The AVX2 monolith picks par_width per variant (7/11/13); AVX512
     * uses 7 (its apply_block3 register-blocking needs 3*parW <= 32). */
    int useMono = 0;
#ifdef MC_HAVE_BS_KEYGEN_AVX512
    useMono = useMono || MC_HAVE_AVX512_HW(mc_cpuid_flags);
#endif
#ifdef MC_HAVE_BS_KEYGEN_AVX2
    useMono = useMono || IS_INTEL_AVX2(mc_cpuid_flags);
#endif
    if (useMono && (SAVE_VECTOR_REGISTERS2() == 0)) {
#ifdef MC_HAVE_BS_KEYGEN_AVX512
        if ((!done) && MC_HAVE_AVX512_HW(mc_cpuid_flags)) {
            kret = wc_mceliece_keygen_drv_avx512(p, pk, skp, kb, pivots,
                bsbufs, 7, kb->f, p->t);
            done = 1;
        }
#endif
#ifdef MC_HAVE_BS_KEYGEN_AVX2
        if ((!done) && IS_INTEL_AVX2(mc_cpuid_flags)) {
            kret = wc_mceliece_keygen_drv_avx2(p, pk, skp, kb, pivots,
                bsbufs, wc_mceliece_bs_parwidth(p), kb->f, p->t);
            done = 1;
        }
#endif
        RESTORE_VECTOR_REGISTERS();
    }
#endif
#ifdef MC_HAVE_PKGEN_NEON
    if ((!done) && MC_NEON_RUNTIME_OK && (SAVE_VECTOR_REGISTERS2() == 0)) {
        /* One vector-register window over the whole NEON driver (symmetric with
         * the x86 asm path above); the driver calls the NEON kernels directly.
         * If the window can't be taken, fall through to the portable keygen. */
        kret = wc_mceliece_keygen_drv_neon(p, pk, skp, kb, pivots, bsbufs);
        RESTORE_VECTOR_REGISTERS();
        done = 1;
    }
#endif
    if (!done) {
        kret = wc_mceliece_keygen_c(p, pk, skp, kb, pivots, bsbufs);
    }
    return kret;
}

#endif

/******************************************************************************/
/* Encapsulation code path: FixedWeight error and syndrome Encode.            */
/******************************************************************************/

#ifndef WOLFSSL_MCELIECE_NO_ENCAPSULATE
/* Parity of the bitwise AND of two len-byte vectors, accumulated a machine
 * word at a time (a and b need not be word aligned). Constant time.
 *
 * @param  [in]  a    First vector.
 * @param  [in]  b    Second vector.
 * @param  [in]  len  Length in bytes.
 * @return  The single parity bit (0 or 1).
 */
static byte wc_mceliece_and_parity(const byte* a, const byte* b, int len)
{
    wolfssl_word acc = 0;
    wolfssl_word aw;
    wolfssl_word bw;
    const int wsz = (int)sizeof(wolfssl_word);
    int i = 0;
    byte r = 0;
    /* Type-pun helpers so word reads of the byte buffers do not break strict
     * aliasing (same idiom as misc.c xorbuf). */
    McCWordPtr pa;
    McCWordPtr pb;


    /* When the length is a whole number of words and both inputs are
     * word-aligned, read whole words directly instead of copying each one with
     * XMEMCPY. That is the tail-free case the compiler can vectorise; the tests
     * are on the (public) length and addresses, not the data, so the parity
     * stays constant time. It fires for every row of 8192128 (row stride a
     * word multiple); the other sets' packed stride is not, so they stay on the
     * XMEMCPY path (already optimal where unaligned access is cheap). */
    if (((len & (wsz - 1)) == 0) &&
            ((((wc_ptr_t)a | (wc_ptr_t)b) & (wc_ptr_t)(wsz - 1)) == 0)) {
        const int nw = len / wsz;

        pa.bp = a;
        pb.bp = b;
        for (; i < nw; i++) {
            acc ^= pa.wp[i] & pb.wp[i];
        }
        i *= wsz;
    }
    else {
        for (; i + wsz <= len; i += wsz) {
            XMEMCPY(&aw, a + i, (size_t)wsz);
            XMEMCPY(&bw, b + i, (size_t)wsz);
            acc ^= aw & bw;
        }
    }
    for (; i < len; i++) {
        r ^= (byte)(a[i] & b[i]);
    }
    for (i = 0; i < wsz; i++) {
        r ^= (byte)(acc >> (8 * i));
    }

    r ^= (byte)(r >> 4);
    r ^= (byte)(r >> 2);
    r ^= (byte)(r >> 1);

    return (byte)(r & 1);
}

/* Encode: compute the syndrome C0 = He of an error vector using the public
 * key. Each syndrome bit i is <H_row_i, e> = e_i XOR <T_row_i, e >> mt>, where
 * H = [I | T]. Aligning e to the T columns once (eT = e >> mt) turns the body
 * into one word-wise AND-parity per row, avoiding a per-row matrix rebuild. The
 * eT shift handles sets whose mt is not a multiple of 8 (6960119).
 *
 * @param  [in]   p    Parameter set.
 * @param  [out]  s    Syndrome / ciphertext body (CEILING(mt/8) bytes).
 * @param  [in]   pk   Public key T.
 * @param  [in]   e    Error vector (CEILING(n/8) bytes).
 * @param  [in]   row  Scratch of CEILING(k/8) bytes (used only when mt is not
 *                     byte-aligned; holds the shifted eT).
 */
static void wc_mceliece_syndrome(const McElieceParams* p, byte* s,
    const byte* pk, const byte* e, byte* row)
{
    int i;
    int j;
    const int nBytes = (int)p->sBytes;
    const int rowBytes = (int)((p->k + 7) >> 3);
    const int tail = p->mt & 0x7;
    const int mtBytes = p->mt >> 3;
    const byte* pk_ptr = pk;
    const byte* eT;
    byte hi;
    byte t;
    byte id;
#ifdef WOLFSSL_MCELIECE_SMALL
    const int nRows = p->mt;
#else
    const int wsz = (int)sizeof(wolfssl_word);
    byte sv;
#endif

    /* Align e to the T columns: eT = e >> mt. Byte-aligned mt needs only a
     * pointer; otherwise shift the tail bits into the scratch row. */
    if (tail == 0) {
        eT = e + mtBytes;
    }
    else {
        for (j = 0; j < rowBytes; j++) {
            hi = 0;
            if (mtBytes + j + 1 < nBytes) {
                hi = e[mtBytes + j + 1];
            }
            row[j] = (byte)((e[mtBytes + j] >> tail) | (hi << (8 - tail)));
        }
        eT = row;
    }

#ifdef WOLFSSL_MCELIECE_SMALL
    /* Compact: zero the syndrome, then OR each row's bit into place. */
    XMEMSET(s, 0, p->syndBytes);
    for (i = 0; i < nRows; i++) {
        t = wc_mceliece_and_parity(pk_ptr, eT, rowBytes);
        id = (byte)((e[i >> 3] >> (i & 0x7)) & 1);
        s[i >> 3] |= (byte)((t ^ id) << (i & 0x7));
        pk_ptr += rowBytes;
    }
#else
    /* Build each syndrome byte from its 8 rows at once. s = T.eT XOR e: within
     * byte i, bit j is that row's identity bit e[i]>>j, so no separate zeroing
     * pass or read-modify-write of s is needed. Processing all 8 rows of the
     * byte in one loop (vs 8 separate wc_mceliece_and_parity calls) lets the
     * shared eT word be read once for all 8 rows and gives the compiler 8
     * independent AND-XOR accumulator chains to schedule - C analogue of the
     * SIMD row-interleave. Data-oblivious: bounds are the public rowBytes/mt
     * only. The 8 rows 8i..8i+7 all exist since 8*mtBytes <= mt. */
    for (i = 0; i < mtBytes; i++) {
        wolfssl_word acc[8];
        byte rt[8];
        int r;
        int k = 0;

        for (r = 0; r < 8; r++) {
            acc[r] = 0;
            rt[r] = 0;
        }
        for (; k + wsz <= rowBytes; k += wsz) {
            wolfssl_word ew;

            XMEMCPY(&ew, eT + k, (size_t)wsz);
            for (r = 0; r < 8; r++) {
                wolfssl_word xw;

                XMEMCPY(&xw, pk_ptr + (size_t)r * rowBytes + k, (size_t)wsz);
                acc[r] ^= xw & ew;
            }
        }
        for (; k < rowBytes; k++) {
            byte eb = eT[k];

            for (r = 0; r < 8; r++) {
                rt[r] ^= (byte)(pk_ptr[(size_t)r * rowBytes + k] & eb);
            }
        }
        sv = 0;
        for (r = 0; r < 8; r++) {
            byte pr = rt[r];
            int w;

            for (w = 0; w < wsz; w++) {
                pr ^= (byte)(acc[r] >> (8 * w));
            }
            pr ^= (byte)(pr >> 4);
            pr ^= (byte)(pr >> 2);
            pr ^= (byte)(pr >> 1);
            id = (byte)((e[i] >> r) & 1);
            sv |= (byte)(((pr ^ id) & 1) << r);
        }
        s[i] = sv;
        pk_ptr += (size_t)8 * rowBytes;
    }
    /* Partial final byte when mt is not a multiple of 8 (6960119). */
    if (tail != 0) {
        sv = 0;
        for (j = 0; j < tail; j++) {
            t = wc_mceliece_and_parity(pk_ptr, eT, rowBytes);
            id = (byte)((e[mtBytes] >> j) & 1);
            sv |= (byte)((t ^ id) << j);
            pk_ptr += rowBytes;
        }
        s[mtBytes] = sv;
    }
#endif
}
#endif

#ifndef WOLFSSL_MCELIECE_NO_ENCAPSULATE
/* Encapsulation Encode path (draft section 8.5): draw a fixed-weight-t error
 * vector from rand (FixedWeight) and compute the syndrome C0 = He.
 * wc_mceliece_encap runs the per-ISA C driver (orchestrating the asm
 * FixedWeight/scatter/syndrome sub-kernels) when the CPU supports it, else the
 * portable C below. wc_mceliece_encap_c is non-inlined so its working set is a
 * distinct frame from the thin dispatcher; each function is documented at its
 * own definition. */
/* FixedWeight-t rejection draw (draft SeededKeyGen): read tau field elements
 * from rand, keep the first t that are < n, and reject the attempt (redraw the
 * next 2*tau bytes) if fewer than t survive or any two are equal. On success
 * ind[0..t) holds t distinct positions < n. Returns 0 or RAND_DEPLETED. Shared
 * by the C encode and the asm encode drivers. */
static int wc_mceliece_encap_fixedweight_c(const McElieceParams* p,
    const byte* rand, word32 randLen, word16* nums, word16* ind)
{
    int ret = 0;
    int i;
    int j;
    int count;
    int eq;
    const int n = p->n;
    const int t = p->t;
    const int tau = p->tau;
    const word32 attempt = (word32)MCELIECE_FIXEDWEIGHT_ATTEMPT_SZ(tau);
    word32 off = 0;
    int done = 0;

    while ((ret == 0) && (!done)) {
        if (off + attempt > randLen) {
            ret = MCELIECE_RAND_DEPLETED;
            break;
        }
        for (i = 0; i < tau; i++) {
            nums[i] = wc_mceliece_load_gf(rand + off + i * 2);
        }
        off += attempt;
        count = 0;
        for (i = 0; (i < tau) && (count < t); i++) {
            if (nums[i] < n) {
                ind[count++] = nums[i];
            }
        }
        if (count < t) {
            continue;
        }
        eq = 0;
        for (i = 1; i < t; i++) {
            for (j = 0; j < i; j++) {
                if (ind[i] == ind[j]) {
                    eq = 1;
                }
            }
        }
        if (eq == 0) {
            done = 1;
        }
    }

    return ret;
}

/* Scatter the t error bits into e in constant time: compare every output
 * position against each index with a mask (no data-dependent addressing).
 * Small builds work a byte at a time; otherwise a 64-bit word at a time (8x
 * fewer mask operations). Shared by the C encode and the asm encode drivers. */
static void wc_mceliece_encap_scatter_c(const McElieceParams* p,
    const word16* ind, byte* e
#ifdef WOLFSSL_MCELIECE_SMALL
    , byte* val
#endif
    )
{
    int j;
    const int t = p->t;
#ifdef WOLFSSL_MCELIECE_SMALL
    int i;

    for (j = 0; j < t; j++) {
        val[j] = (byte)(1 << (ind[j] & 7));
    }
    for (i = 0; i < (int)p->sBytes; i++) {
        e[i] = 0;
        for (j = 0; j < t; j++) {
            /* Mask is all-ones only when i == ind[j] >> 3 (constant time). */
            byte m = ctMaskEq((int)i, (int)(ind[j] >> 3));

            e[i] |= val[j] & m;
        }
    }
#else
    int w;
    int nwords = ((int)p->sBytes + 7) / 8;
#ifdef LITTLE_ENDIAN_ORDER
    /* e is the malloc'd scratch: aligned and padded to a multiple of 8 bytes
     * (eSz), so each word is a single aligned store; the last word's unused
     * high bytes land in the padding. */
    McWord64Ptr ep;

    ep.bp = e;
#endif
    for (w = 0; w < nwords; w++) {
        word64 ex = 0;
#ifndef LITTLE_ENDIAN_ORDER
        int k;
#endif

        for (j = 0; j < t; j++) {
            /* Set bit (ind[j] & 63) of ex only when this index lands in word w:
             * the equality is a single 1/0 bit shifted into place. The shift
             * count is the same secret ind[j] the masked form used, so the
             * timing is unchanged and constant. */
            ex |= (word64)(ctMask16Eq((int)w, (int)(ind[j] >> 6)) & 1)
                << (ind[j] & 63);
        }
#ifdef LITTLE_ENDIAN_ORDER
        ep.wp[w] = ex;
#else
        for (k = 0; (k < 8) && (w * 8 + k < (int)p->sBytes); k++) {
            e[w * 8 + k] = (byte)(ex >> (k * 8));
        }
#endif
    }
#endif
}

/* Portable C encapsulation: the fallback taken when no asm/NEON encode driver
 * is available. Lays out the scratch buffers, draws the fixed-weight-t error
 * vector from rand (FixedWeight) and computes the syndrome C0 = He entirely in
 * C. See wc_mceliece_encap for the dispatch and the e/c0 outputs. Returns 0 or
 * MCELIECE_RAND_DEPLETED. Kept non-inlined so its working set is a distinct
 * frame from the thin dispatcher.
 *
 * Steps:
 *  1. Lay out the scratch buffers.
 *  2. FixedWeight-t rejection sample of the error positions from rand.
 *  3. Scatter the t positions into the error vector e.
 *  4. Syndrome C0 = He.
 *
 * @param  [in]   p        Parameter set.
 * @param  [in]   pk       Public key.
 * @param  [in]   rand     Randomness for FixedWeight sampling.
 * @param  [in]   randLen  Length of rand in bytes.
 * @param  [out]  e        Weight-t error vector (params->sBytes bytes).
 * @param  [out]  c0       Syndrome C0 = He (params->syndBytes bytes).
 * @param  [in]   scratch  Encapsulation scratch buffer.
 * @return  0 on success.
 * @return  MCELIECE_RAND_DEPLETED if rand is exhausted.
 */
static WC_NO_INLINE int wc_mceliece_encap_c(const McElieceParams* p,
    const byte* pk, const byte* rand, word32 randLen, byte* e, byte* c0,
    byte* scratch)
{
    int ret;
    word16* nums;
    word16* ind;
    byte* row;
#ifdef WOLFSSL_MCELIECE_SMALL
    byte* val;

    /* 1. Lay out the scratch buffers. */
    wc_mceliece_enc_layout(p, scratch, &nums, &ind, &row, &val);
#else
    /* 1. Lay out the scratch buffers. */
    wc_mceliece_enc_layout(p, scratch, &nums, &ind, &row);
#endif

    /* 2. FixedWeight-t rejection sample of the error positions from rand. */
    ret = wc_mceliece_encap_fixedweight_c(p, rand, randLen, nums, ind);
    if (ret == 0) {
        /* 3. Scatter the t positions into the error vector e. */
#ifdef WOLFSSL_MCELIECE_SMALL
        wc_mceliece_encap_scatter_c(p, ind, e, val);
#else
        wc_mceliece_encap_scatter_c(p, ind, e);
#endif
        /* 4. Syndrome C0 = He. */
        wc_mceliece_syndrome(p, c0, pk, e, row);
    }

    return ret;
}

/* Encapsulation Encode dispatcher.
 *
 * Runs the per-ISA asm encode driver (FixedWeight/scatter/syndrome sub-kernels)
 * when the CPU supports it, otherwise falls back to the portable C
 * wc_mceliece_encap_c.
 *
 * @param  [in]   p        Parameter set.
 * @param  [in]   pk       Public key T.
 * @param  [in]   rand     Randomness for FixedWeight.
 * @param  [in]   randLen  Length of rand in bytes.
 * @param  [out]  e        Weight-t error vector (CEILING(n/8) bytes).
 * @param  [out]  c0       Syndrome ciphertext body (CEILING(mt/8) bytes).
 * @param  [in]   scratch  Buffer of wc_mceliece_encap_scratch_sz(p) bytes.
 * @return  0 on success.
 * @return  MCELIECE_RAND_DEPLETED if rand is exhausted first.
 */
#ifdef MC_HAVE_ENCAP_ASM
#ifndef NO_AVX512_SUPPORT
/* Encode sub-kernels (asm) the C encap driver orchestrates: FixedWeight draw ->
 * const-time bit-scatter into e -> syndrome C0 = He. One driver per ISA in
 * place of a single monolithic asm entry. */
WOLFSSL_LOCAL int wc_mceliece_encap_fixedweight_avx512(const byte* rand,
    word16* ind, int randLen, int n, int t, int tau);
WOLFSSL_LOCAL void wc_mceliece_encap_scatter_avx512(byte* e, const word16* ind,
    int t, int nwords);
WOLFSSL_LOCAL void wc_mceliece_encap_syndrome_avx512(const byte* pk,
    const byte* e, byte* c0, byte* row, int mt, int rowBytes);

/* C driver (AVX512): FixedWeight (rejection sampling) then, on success, the
 * bit-scatter and syndrome sub-kernels, each taking the fields it needs
 * directly. Returns 0 or MCELIECE_RAND_DEPLETED.
 *
 * @param  [in]   p        Parameter set.
 * @param  [in]   pk       Public key.
 * @param  [in]   rand     Randomness for FixedWeight sampling.
 * @param  [in]   randLen  Length of rand in bytes.
 * @param  [out]  e        Weight-t error vector (params->sBytes bytes).
 * @param  [out]  c0       Syndrome C0 = He (params->syndBytes bytes).
 * @param  [in]   scratch  Encapsulation scratch buffer.
 * @return  0 on success.
 * @return  MCELIECE_RAND_DEPLETED if rand is exhausted.
 */
static int wc_mceliece_encap_drv_avx512(const McElieceParams* p, const byte* pk,
    const byte* rand, word32 randLen, byte* e, byte* c0, byte* scratch)
{
    word16* nums;
    word16* ind;
    byte* row;
    int ret;
    int nwords = ((int)p->sBytes + 7) / 8;
    int rowBytes = (int)((p->k + 7) >> 3);

    wc_mceliece_enc_layout(p, scratch, &nums, &ind, &row);
    ret = wc_mceliece_encap_fixedweight_avx512(rand, ind, (int)randLen, p->n,
        p->t, p->tau);
    if (ret == 0) {
        wc_mceliece_encap_scatter_avx512(e, ind, p->t, nwords);
        wc_mceliece_encap_syndrome_avx512(pk, e, c0, row, p->mt, rowBytes);
    }
    return ret;
}
#endif
#ifndef NO_AVX2_SUPPORT
/* Encap AVX2 asm kernels (declared for the AVX2 encap driver): fixed-weight
 * error draw, bit-scatter, and the syndrome C0 = He. */
WOLFSSL_LOCAL int wc_mceliece_encap_fixedweight_avx2(const byte* rand,
    word16* ind, int randLen, int n, int t, int tau);
WOLFSSL_LOCAL void wc_mceliece_encap_scatter_avx2(byte* e, const word16* ind,
    int t, int nwords);
WOLFSSL_LOCAL void wc_mceliece_encap_syndrome_avx2(const byte* pk,
    const byte* e, byte* c0, byte* row, int mt, int rowBytes);

/* C driver (AVX2): the AVX2 Encode sub-kernels in sequence, each taking the
 * fields it needs directly.
 *
 * @param  [in]   p        Parameter set.
 * @param  [in]   pk       Public key.
 * @param  [in]   rand     Randomness for FixedWeight sampling.
 * @param  [in]   randLen  Length of rand in bytes.
 * @param  [out]  e        Weight-t error vector (params->sBytes bytes).
 * @param  [out]  c0       Syndrome C0 = He (params->syndBytes bytes).
 * @param  [in]   scratch  Encapsulation scratch buffer.
 * @return  0 on success.
 * @return  MCELIECE_RAND_DEPLETED if rand is exhausted.
 */
static int wc_mceliece_encap_drv_avx2(const McElieceParams* p, const byte* pk,
    const byte* rand, word32 randLen, byte* e, byte* c0, byte* scratch)
{
    word16* nums;
    word16* ind;
    byte* row;
    int ret;
    int nwords = ((int)p->sBytes + 7) / 8;
    int rowBytes = (int)((p->k + 7) >> 3);

    wc_mceliece_enc_layout(p, scratch, &nums, &ind, &row);
    ret = wc_mceliece_encap_fixedweight_avx2(rand, ind, (int)randLen, p->n,
        p->t, p->tau);
    if (ret == 0) {
        wc_mceliece_encap_scatter_avx2(e, ind, p->t, nwords);
        wc_mceliece_encap_syndrome_avx2(pk, e, c0, row, p->mt, rowBytes);
    }
    return ret;
}
#endif
#endif /* MC_HAVE_ENCAP_ASM */

#ifdef MC_HAVE_ENCAP_NEON
/* AArch64 NEON encode sub-kernels: FixedWeight draw -> constant-time bit-
 * scatter into e -> compute-bound syndrome C0 = He. One driver per ISA in
 * place of a single monolithic asm entry. */
WOLFSSL_LOCAL int wc_mceliece_encap_fixedweight_neon(const byte* rand,
    word16* ind, int randLen, int n, int t, int tau);
WOLFSSL_LOCAL void wc_mceliece_encap_scatter_neon(byte* e, const word16* ind,
    int t, int nwords);
WOLFSSL_LOCAL void wc_mceliece_encap_syndrome_neon(const byte* pk,
    const byte* e, byte* c0, byte* row, int mt, int rowBytes);

/* C driver (NEON): the NEON Encode sub-kernels in sequence.
 *
 * @param  [in]   p        Parameter set.
 * @param  [in]   pk       Public key.
 * @param  [in]   rand     Randomness for FixedWeight sampling.
 * @param  [in]   randLen  Length of rand in bytes.
 * @param  [out]  e        Weight-t error vector (params->sBytes bytes).
 * @param  [out]  c0       Syndrome C0 = He (params->syndBytes bytes).
 * @param  [in]   scratch  Encapsulation scratch buffer.
 * @return  0 on success.
 * @return  MCELIECE_RAND_DEPLETED if rand is exhausted.
 */
static int wc_mceliece_encap_drv_neon(const McElieceParams* p, const byte* pk,
    const byte* rand, word32 randLen, byte* e, byte* c0, byte* scratch)
{
    word16* nums;
    word16* ind;
    byte* row;
    int ret;
    int nwords = ((int)p->sBytes + 7) / 8;
    int rowBytes = (int)((p->k + 7) >> 3);

    wc_mceliece_enc_layout(p, scratch, &nums, &ind, &row);

    ret = wc_mceliece_encap_fixedweight_neon(rand, ind, (int)randLen, p->n,
        p->t, p->tau);
    if (ret == 0) {
        wc_mceliece_encap_scatter_neon(e, ind, p->t, nwords);
        wc_mceliece_encap_syndrome_neon(pk, e, c0, row, p->mt, rowBytes);
    }
    return ret;
}
#endif /* MC_HAVE_ENCAP_NEON */

#endif

/******************************************************************************/
/* Decapsulation code path: syndrome decode.                                  */
/*                                                                            */
/* The additive-FFT field/poly primitives at the top of this section are also */
/* used by the bitsliced key generation (forward FFT for MatGen), so they are */
/* compiled whenever make-key OR decapsulate is enabled (MC_HAVE_AFF_FFT).    */
/* The decode-only parts (transpose FFT, syndrome, root-find, drivers) stay   */
/* behind WOLFSSL_MCELIECE_NO_DECAPSULATE.                                    */
/******************************************************************************/

#if !defined(WOLFSSL_MCELIECE_NO_MAKE_KEY) || \
    !defined(WOLFSSL_MCELIECE_NO_DECAPSULATE)
#define MC_HAVE_AFF_FFT
/* The bitsliced GF(2^13) vec256 multiply is the additive-FFT core, shared by
 * both keygen and decode; it has an AArch64/AArch32 NEON kernel. */
#if defined(MC_HAVE_AARCH64_NEON) || defined(MC_HAVE_ARM32_NEON)
#define MC_HAVE_AFF_FFT_NEON
#endif
#endif

#ifdef MC_HAVE_AFF_FFT
/* Additive (Gao-Mateer) FFT over GF(2^13): multipoint evaluation at all 2^13
 * field elements and its transpose (the Goppa syndrome). Replaces the O(n*t)
 * Horner eval and power-chain syndrome with O(n log n) work. Standard basis
 * {1,2,4,..} and offset 0 so eval output is in natural field-element order.
 * See mceliece-implementation notes for the derivation. */

/* Coefficient-bitsliced additive FFT (McBits Revisited / Gao-Mateer),
 * generated from GF(2^13): forward wc_mceliece_aff_fft (multipoint poly eval)
 * and transposed wc_mceliece_aff_fft_tr (the Goppa syndrome), on constants
 * derived from the field (no external data). vec128 = word64[13][2],
 * vec256 = word64[13][4]; output is idx-order (work[idx] =
 * poly(wc_mceliece_bitrev(idx))), matching the element-wise Horner evaluation
 * it replaces in the C decode. */
#ifdef WOLFSSL_MCELIECE_GEN_TABLES
/* --- field arithmetic (constant generation only) --- */
/* Raise a field element to the 128th power: x^128 = x^(2^7).
 *
 * Seven successive Frobenius squarings in GF(2^13). Used only when generating
 * the FFT constant tables.
 *
 * @param  [in]  x  Field element.
 * @return  x raised to the power 128.
 */
static mc_gf wc_mceliece_aff_pow128(mc_gf x)
{
    int i;

    for (i = 0; i < 7; i++) {
        x = wc_mceliece_gf_sq(x);
    }
    return x;
}
/* Normalized linearized subspace polynomial s_d(x) / s_d(2^d).
 *
 * s_d vanishes on the subspace spanned by {1,2,..,2^(d-1)}; the result is
 * normalized so the value at 2^d is 1. Used only when generating the FFT
 * constant tables.
 *
 * @param  [in]  d  Subspace dimension (product runs over 2^d points).
 * @param  [in]  x  Field element to evaluate at.
 * @return  Normalized subspace polynomial value at x.
 */
static mc_gf wc_mceliece_aff_shat(int d, mc_gf x)
{
    mc_gf num = 1;
    mc_gf den = 1;
    mc_gf dn = (mc_gf)(1 << d);
    int w;
    int j;

    for (w = 0; w < (1 << d); w++) {
        mc_gf pt = 0;

        for (j = 0; j < d; j++) {
            if (w & (1 << j)) {
                pt ^= (mc_gf)(1 << j);
            }
        }
        num = wc_mceliece_gf_mul(num, (mc_gf)(x ^ pt));
        den = wc_mceliece_gf_mul(den, (mc_gf)(dn ^ pt));
    }
    return wc_mceliece_gf_mul(num, wc_mceliece_gf_inv(den));
}
#endif /* WOLFSSL_MCELIECE_GEN_TABLES */

/* --- bitsliced constant tables (idx-order, alpha[idx]=brev13(idx)) --- */
/* A bitsliced vec256 lane group = 13 planes x 4 word64; vec128 = 13 x 2. */
#ifdef WOLFSSL_MCELIECE_GEN_TABLES
static word64 mc_aff_powers[32][MCELIECE_M][4];
static word64 mc_aff_consts[33][MCELIECE_M][4];
static word64 mc_aff_scal2x[5][MCELIECE_M][2];
static word64 mc_aff_scal4x[6][MCELIECE_M][4];
#else
#include <wolfssl/wolfcrypt/wc_mceliece_aff_consts.h>
#endif

#ifdef WOLFSSL_MCELIECE_GEN_TABLES
/* Scatter a field element into a bitsliced vec256 lane group at position l.
 *
 * Bit k of val is written to plane k, word l>>6, bit l&63. Used only when
 * generating the FFT constant tables.
 *
 * @param  [in, out]  v    Bitsliced group of MCELIECE_M planes x 4 word64.
 * @param  [in]       l    Lane position (0..255).
 * @param  [in]       val  Field element supplying one bit per plane.
 */
static void wc_mceliece_aff_put256(word64 v[MCELIECE_M][4], int l, mc_gf val)
{
    int k;
    int wd = l >> 6;
    int bit = l & 63;

    for (k = 0; k < MCELIECE_M; k++) {
        if ((val >> k) & 1) {
            v[k][wd] |= (word64)1 << bit;
        }
    }
}
/* Scatter a field element into a bitsliced vec128 lane group at position l.
 *
 * Bit k of val is written to plane k, word l>>6, bit l&63. Used only when
 * generating the FFT constant tables.
 *
 * @param  [in, out]  v    Bitsliced group of MCELIECE_M planes x 2 word64.
 * @param  [in]       l    Lane position (0..127).
 * @param  [in]       val  Field element supplying one bit per plane.
 */
static void wc_mceliece_aff_put128(word64 v[MCELIECE_M][2], int l, mc_gf val)
{
    int k;
    int wd = l >> 6;
    int bit = l & 63;

    for (k = 0; k < MCELIECE_M; k++) {
        if ((val >> k) & 1) {
            v[k][wd] |= (word64)1 << bit;
        }
    }
}
/* Generate the bitsliced constant tables for the additive FFT.
 *
 * Fills mc_aff_powers (the x^128 leading-term correction), mc_aff_consts (the
 * s-hat twist constants) and mc_aff_scal2x / mc_aff_scal4x (radix-conversion
 * scale factors), all in idx-order derived from the field. Call once before
 * any FFT.
 */
static void wc_mceliece_aff_gen_tables(void)
{
    int i;
    int l;
    int m;
    int cptr;
    int j;
    int b;
    mc_gf g[6];
    mc_gf beta = 0;
    mc_gf two = 2;

    XMEMSET(mc_aff_powers, 0, sizeof(mc_aff_powers));
    XMEMSET(mc_aff_consts, 0, sizeof(mc_aff_consts));
    XMEMSET(mc_aff_scal2x, 0, sizeof(mc_aff_scal2x));
    XMEMSET(mc_aff_scal4x, 0, sizeof(mc_aff_scal4x));
    for (i = 0; i < 32; i++) {
        for (l = 0; l < 256; l++) {
            wc_mceliece_aff_put256(mc_aff_powers[i], l,
                wc_mceliece_aff_pow128(
                    wc_mceliece_bitrev((mc_gf)(i * 256 + l))));
        }
    }
    for (l = 0; l < 256; l++) {
        wc_mceliece_aff_put256(mc_aff_consts[0], l,
            wc_mceliece_aff_shat(6, wc_mceliece_bitrev((mc_gf)(l & 0x3F))));
        wc_mceliece_aff_put256(mc_aff_consts[1], l,
            wc_mceliece_aff_shat(5, wc_mceliece_bitrev((mc_gf)(l & 0x7F))));
    }
    cptr = 2;
    for (i = 0; i <= 4; i++) {
        int s = 1 << i;
        int d = 4 - i;

        for (m = 0; m < s; m++) {
            mc_gf rr = 0;

            for (b = 0; b < i; b++) {
                if (m & (1 << b)) {
                    rr ^= (mc_gf)(1 << (4 - b));
                }
            }
            for (l = 0; l < 256; l++) {
                wc_mceliece_aff_put256(mc_aff_consts[cptr + m], l,
                    wc_mceliece_aff_shat(d,
                        (mc_gf)(wc_mceliece_bitrev((mc_gf)l) ^ rr)));
            }
        }
        cptr += s;
    }
    for (j = 0; j < 6; j++) {
        beta ^= two;
        g[j] = (mc_gf)(wc_mceliece_gf_mul(beta, beta) ^ beta);
        two = wc_mceliece_gf_mul(two, two);
    }
    for (j = 0; j < 5; j++) {
        int gr = 1 << (j + 1);
        int nb = 6 - j;
        mc_gf gg[8];

        gg[0] = g[j];
        for (b = 1; b < nb; b++) {
            gg[b] = wc_mceliece_gf_mul(gg[b - 1], gg[b - 1]);
        }
        for (l = 0; l < 128; l++) {
            int h = l / gr;
            mc_gf v = 1;

            for (b = 0; b < nb; b++) {
                if (h & (1 << b)) {
                    v = wc_mceliece_gf_mul(v, gg[b]);
                }
            }
            wc_mceliece_aff_put128(mc_aff_scal2x[j], l, v);
        }
    }
    for (j = 0; j < 6; j++) {
        int gr = 1 << (j + 1);
        int nb = 7 - j;
        mc_gf gg[8];

        gg[0] = g[j];
        for (b = 1; b < nb; b++) {
            gg[b] = wc_mceliece_gf_mul(gg[b - 1], gg[b - 1]);
        }
        for (l = 0; l < 256; l++) {
            int h = l / gr;
            mc_gf v = 1;

            for (b = 0; b < nb; b++) {
                if (h & (1 << b)) {
                    v = wc_mceliece_gf_mul(v, gg[b]);
                }
            }
            wc_mceliece_aff_put256(mc_aff_scal4x[j], l, v);
        }
    }
}
#endif /* WOLFSSL_MCELIECE_GEN_TABLES */

/* --- bitsliced vector helpers (word64 planes) --- */
/* Unpack-high of two vec128 lanes: r = { a[1], b[1] }.
 *
 * @param  [out]  r  Result vec128 lane (2 word64).
 * @param  [in]   a  First source vec128 lane.
 * @param  [in]   b  Second source vec128 lane.
 */
static void wc_mceliece_aff_v128_uh(word64* r, const word64* a, const word64* b)
{
    r[0] = a[1];
    r[1] = b[1];
}
/* XOR two vec256 lanes: r = a ^ b (4 word64 each).
 *
 * @param  [out]  r  Result vec256 lane.
 * @param  [in]   a  First source vec256 lane.
 * @param  [in]   b  Second source vec256 lane.
 */
static void wc_mceliece_aff_v256_xor(word64* r, const word64* a,
    const word64* b)
{
    int w;

    for (w = 0; w < 4; w++) {
        r[w] = a[w] ^ b[w];
    }
}

/* XOR all 13 vec256 planes: r[k] = a[k] ^ b[k]. The additive-FFT butterfly
 * combine; dispatches to NEON (128-bit wide) when available.
 *
 * @param  [out]  r  Result r[k] = a[k] ^ b[k] across all 13 planes.
 * @param  [in]   a  First operand planes.
 * @param  [in]   b  Second operand planes.
 */
static void wc_mceliece_aff_v256_xor13(word64 r[MCELIECE_M][4],
    const word64 a[MCELIECE_M][4], const word64 b[MCELIECE_M][4])
{
    int k;

    for (k = 0; k < MCELIECE_M; k++) {
        r[k][0] = a[k][0] ^ b[k][0];
        r[k][1] = a[k][1] ^ b[k][1];
        r[k][2] = a[k][2] ^ b[k][2];
        r[k][3] = a[k][3] ^ b[k][3];
    }
}
/* Unpack-low 128-bit halves of two vec256 lanes: r = { a[0..1], b[0..1] }.
 *
 * @param  [out]  r  Result vec256 lane.
 * @param  [in]   a  First source vec256 lane.
 * @param  [in]   b  Second source vec256 lane.
 */
static void wc_mceliece_aff_v256_ul(word64* r, const word64* a, const word64* b)
{
    r[0] = a[0];
    r[1] = a[1];
    r[2] = b[0];
    r[3] = b[1];
}
/* Unpack-high 128-bit halves of two vec256 lanes: r = { a[2..3], b[2..3] }.
 *
 * @param  [out]  r  Result vec256 lane.
 * @param  [in]   a  First source vec256 lane.
 * @param  [in]   b  Second source vec256 lane.
 */
static void wc_mceliece_aff_v256_uh(word64* r, const word64* a, const word64* b)
{
    r[0] = a[2];
    r[1] = a[3];
    r[2] = b[2];
    r[3] = b[3];
}
/* Unpack-low 64-bit words of two vec256 lanes: r = { a0, b0, a2, b2 }.
 *
 * @param  [out]  r  Result vec256 lane.
 * @param  [in]   a  First source vec256 lane.
 * @param  [in]   b  Second source vec256 lane.
 */
#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
static void wc_mceliece_aff_v256_ul2(word64* r, const word64* a,
    const word64* b)
{
    r[0] = a[0];
    r[1] = b[0];
    r[2] = a[2];
    r[3] = b[2];
}
/* Unpack-high 64-bit words of two vec256 lanes: r = { a1, b1, a3, b3 }.
 *
 * @param  [out]  r  Result vec256 lane.
 * @param  [in]   a  First source vec256 lane.
 * @param  [in]   b  Second source vec256 lane.
 */
static void wc_mceliece_aff_v256_uh2(word64* r, const word64* a,
    const word64* b)
{
    r[0] = a[1];
    r[1] = b[1];
    r[2] = a[3];
    r[3] = b[3];
}
/* Extract one 128-bit half of a vec256 lane into a vec128 result.
 *
 * @param  [out]  r  Result vec128 lane (2 word64).
 * @param  [in]   a  Source vec256 lane.
 * @param  [in]   i  Half selector: 0 for low half, non-zero for high half.
 */
static void wc_mceliece_aff_v256_ex2(word64* r, const word64* a, int i)
{
    if (i) {
        r[0] = a[2];
        r[1] = a[3];
    }
    else {
        r[0] = a[0];
        r[1] = a[1];
    }
}
#endif /* WOLFSSL_MCELIECE_NO_DECAPSULATE */

/* Bitsliced GF(2^13) multiply over vec128 lanes: h = f * g.
 *
 * Schoolbook multiply of the 13-bit bitsliced planes with reduction by the
 * field polynomial, applied to all 128 lanes in parallel.
 *
 * @param  [out]  h     Product, MCELIECE_M planes x 2 word64.
 * @param  [in]   f     First operand (may alias h).
 * @param  [in]   g     Second operand.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic scratch allocation fails.
 */
static int wc_mceliece_aff_v128_mul(word64 h[MCELIECE_M][2],
    word64 f[MCELIECE_M][2], const word64 g[MCELIECE_M][2])
{
    int i;
    int j;
    int w;
    int k;
    int ret = 0;
    WC_DECLARE_VAR(c, mc_bs2, 25, NULL);

    WC_ALLOC_VAR(c, mc_bs2, 25, NULL);
    if (!WC_VAR_OK(c)) {
        ret = MEMORY_E;
    }
    else {
        for (k = 0; k < 25; k++) {
            c[k][0] = 0;
            c[k][1] = 0;
        }
        for (i = 0; i < 13; i++) {
            for (j = 0; j < 13; j++) {
                for (w = 0; w < 2; w++) {
                    c[i + j][w] ^= f[i][w] & g[j][w];
                }
            }
        }
        for (k = 24; k >= 13; k--) {
            for (w = 0; w < 2; w++) {
                c[k - 9][w] ^= c[k][w];
                c[k - 10][w] ^= c[k][w];
                c[k - 12][w] ^= c[k][w];
                c[k - 13][w] ^= c[k][w];
            }
        }
        for (k = 0; k < 13; k++) {
            h[k][0] = c[k][0];
            h[k][1] = c[k][1];
        }
        WC_FREE_VAR(c, NULL);
    }
    return ret;
}
/* Bitsliced GF(2^13) multiply over vec256 lanes: h = f * g.
 *
 * Schoolbook multiply of the 13-bit bitsliced planes with reduction by the
 * field polynomial, applied to all 256 lanes in parallel.
 *
 * @param  [out]  h     Product, MCELIECE_M planes x 4 word64.
 * @param  [in]   f     First operand (may alias h).
 * @param  [in]   g     Second operand.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic scratch allocation fails.
 */
static int wc_mceliece_aff_v256_mul(word64 h[MCELIECE_M][4],
    word64 f[MCELIECE_M][4], const word64 g[MCELIECE_M][4])
{
    int i;
    int j;
    int w;
    int k;
    int ret = 0;
    WC_DECLARE_VAR(c, mc_bs4, 25, NULL);

    WC_ALLOC_VAR(c, mc_bs4, 25, NULL);
    if (!WC_VAR_OK(c)) {
        ret = MEMORY_E;
    }
    else {
        /* Output-stationary schoolbook: accumulate each product coefficient
         * c[k] = XOR_{i+j=k} f[i] & g[j] in registers, store once, instead
         * of 169 read-modify-writes scattered across the c[] array. */
        for (k = 0; k < 25; k++) {
            word64 a0 = 0, a1 = 0, a2 = 0, a3 = 0;
            int lo = (k - 12 < 0) ? 0 : (k - 12);
            int hi = (k < 12) ? k : 12;

            for (i = lo; i <= hi; i++) {
                j = k - i;
                a0 ^= f[i][0] & g[j][0];
                a1 ^= f[i][1] & g[j][1];
                a2 ^= f[i][2] & g[j][2];
                a3 ^= f[i][3] & g[j][3];
            }
            c[k][0] = a0;
            c[k][1] = a1;
            c[k][2] = a2;
            c[k][3] = a3;
        }
        for (k = 24; k >= 13; k--) {
            for (w = 0; w < 4; w++) {
                c[k - 9][w] ^= c[k][w];
                c[k - 10][w] ^= c[k][w];
                c[k - 12][w] ^= c[k][w];
                c[k - 13][w] ^= c[k][w];
            }
        }
        for (k = 0; k < 13; k++) {
            for (w = 0; w < 4; w++) {
                h[k][w] = c[k][w];
            }
        }
        WC_FREE_VAR(c, NULL);
    }
    return ret;
}
/* Multiply-add-add butterfly: a ^= mul(b, c); b ^= a.
 *
 * The forward-FFT butterfly on two vec256 operands with twist constant c.
 *
 * @param  [in, out]  a     First operand; gets a ^= b*c.
 * @param  [in, out]  b     Second operand; gets b ^= a afterwards.
 * @param  [in]       c     Twist constant (bitsliced planes).
 * @return  0 on success.
 * @return  MEMORY_E when dynamic scratch allocation fails.
 */
static int wc_mceliece_aff_maa(word64 a[MCELIECE_M][4], word64 b[MCELIECE_M][4],
    const word64 c[MCELIECE_M][4])
{
    int ret;
    WC_DECLARE_VAR(p, mc_bs4, MCELIECE_M, NULL);

    WC_ALLOC_VAR(p, mc_bs4, MCELIECE_M, NULL);
    if (!WC_VAR_OK(p)) {
        ret = MEMORY_E;
    }
    else {
        ret = wc_mceliece_aff_v256_mul(p, b, c);
        if (ret == 0) {
            wc_mceliece_aff_v256_xor13(a, a, p);
            wc_mceliece_aff_v256_xor13(b, b, a);
        }
        WC_FREE_VAR(p, NULL);
    }
    return ret;
}
/* Add-multiply-add butterfly (transpose of maa): a ^= b; b ^= mul(a, c).
 *
 * The transposed-FFT butterfly on two vec256 operands with twist constant c.
 *
 * @param  [in, out]  a     First operand; gets a ^= b.
 * @param  [in, out]  b     Second operand; gets b ^= a*c afterwards.
 * @param  [in]       c     Twist constant (bitsliced planes).
 * @return  0 on success.
 * @return  MEMORY_E when dynamic scratch allocation fails.
 */
#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
static int wc_mceliece_aff_ama(word64 a[MCELIECE_M][4], word64 b[MCELIECE_M][4],
    const word64 c[MCELIECE_M][4])
{
    int ret;
    WC_DECLARE_VAR(p, mc_bs4, MCELIECE_M, NULL);

    WC_ALLOC_VAR(p, mc_bs4, MCELIECE_M, NULL);
    if (!WC_VAR_OK(p)) {
        ret = MEMORY_E;
    }
    else {
        /* a ^= b in place: a becomes the multiplicand (a and b are always
         * distinct buffers at the call sites), so no separate scratch is
         * needed. */
        wc_mceliece_aff_v256_xor13(a, a, b);
        ret = wc_mceliece_aff_v256_mul(p, a, c);
        if (ret == 0) {
            wc_mceliece_aff_v256_xor13(b, b, p);
        }
        WC_FREE_VAR(p, NULL);
    }
    return ret;
}
#endif /* WOLFSSL_MCELIECE_NO_DECAPSULATE */
/* Pack 13 planes by 128-bit lane: lo = unpack-low, hi = unpack-high.
 *
 * For each plane p: lo[p] = v256_ul(a[p], b[p]), hi[p] = v256_uh(a[p], b[p]).
 * The AVX512 asm does this with single vshufi64x2 ops.
 *
 * @param  [out]  lo    Low 128-bit lanes of each plane.
 * @param  [out]  hi    High 128-bit lanes of each plane.
 * @param  [in]   a     First source, MCELIECE_M planes x 4 word64.
 * @param  [in]   b     Second source, MCELIECE_M planes x 4 word64.
 */
static void wc_mceliece_aff_pack_lh(word64 lo[MCELIECE_M][4],
    word64 hi[MCELIECE_M][4], const word64 a[MCELIECE_M][4],
    const word64 b[MCELIECE_M][4])
{
    int p;

    for (p = 0; p < MCELIECE_M; p++) {
        wc_mceliece_aff_v256_ul(lo[p], a[p], b[p]);
        wc_mceliece_aff_v256_uh(hi[p], a[p], b[p]);
    }
}
/* Pack 13 planes by 64-bit word: lo = unpack-low, hi = unpack-high.
 *
 * For each plane p: lo[p] = v256_ul2(a[p], b[p]),
 * hi[p] = v256_uh2(a[p], b[p]).
 *
 * @param  [out]  lo    Low 64-bit words of each plane.
 * @param  [out]  hi    High 64-bit words of each plane.
 * @param  [in]   a     First source, MCELIECE_M planes x 4 word64.
 * @param  [in]   b     Second source, MCELIECE_M planes x 4 word64.
 */
#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
static void wc_mceliece_aff_pack_lh2(word64 lo[MCELIECE_M][4],
    word64 hi[MCELIECE_M][4], const word64 a[MCELIECE_M][4],
    const word64 b[MCELIECE_M][4])
{
    int p;

    for (p = 0; p < MCELIECE_M; p++) {
        wc_mceliece_aff_v256_ul2(lo[p], a[p], b[p]);
        wc_mceliece_aff_v256_uh2(hi[p], a[p], b[p]);
    }
}
#endif /* WOLFSSL_MCELIECE_NO_DECAPSULATE */
static const byte mc_aff_reversal[64];
/* Forward-FFT output assembly for plane i.
 *
 * For each of 32 groups j: out[j][i] = v256_ul(buf[r0], buf[r1]) and, when
 * i != 12, out[j][i+1] = v256_uh(buf[r0], buf[r1]); r0/r1 come from the
 * bit-reversal table. The AVX512 asm does the 32 j's as 256-bit shuffles.
 *
 * @param  [out]  out   FFT output groups (written for plane i, and i+1).
 * @param  [in]   buf   Transposed butterfly buffer (64 vec256 lanes).
 * @param  [in]   i     Plane index (0..12).
 */
static void wc_mceliece_aff_fwd_out(word64 out[32][MCELIECE_M][4],
    word64 buf[64][4], int i)
{
    int j;

    for (j = 0; j < 32; j++) {
        int r0 = mc_aff_reversal[2 * j + 0];
        int r1 = mc_aff_reversal[2 * j + 1];

        if (i != 12) {
            wc_mceliece_aff_v256_uh(out[j][i + 1], buf[r0], buf[r1]);
        }
        wc_mceliece_aff_v256_ul(out[j][i + 0], buf[r0], buf[r1]);
    }
}
/* Transposed-FFT input gather for plane i.
 *
 * For each of 32 groups k: buf[r0] = v256_ul(in[k][i], in[k][i+1]),
 * buf[r1] = v256_uh(in[k][i], in[k][i+1]); r0/r1 come from the bit-reversal
 * table. When i == 12 there is no plane i+1, so only the low 128 bits of
 * buf[r0]/buf[r1] are written. The AVX512 asm does the 32 k's vectorised.
 *
 * @param  [out]  buf   Butterfly input buffer (64 vec256 lanes).
 * @param  [in]   in    Transposed-FFT input groups.
 * @param  [in]   i     Plane index (0..12).
 */
#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
static void wc_mceliece_aff_btr_in(word64 buf[64][4],
    word64 in[32][MCELIECE_M][4], int i)
{
    int k;

    for (k = 0; k < 32; k++) {
        int r0 = mc_aff_reversal[2 * k + 0];
        int r1 = mc_aff_reversal[2 * k + 1];

        if (i != 12) {
            wc_mceliece_aff_v256_ex2(buf[r0] + 2, in[k][i + 1], 0);
            wc_mceliece_aff_v256_ex2(buf[r1] + 2, in[k][i + 1], 1);
        }
        wc_mceliece_aff_v256_ex2(buf[r0] + 0, in[k][i + 0], 0);
        wc_mceliece_aff_v256_ex2(buf[r1] + 0, in[k][i + 0], 1);
    }
}
#endif /* WOLFSSL_MCELIECE_NO_DECAPSULATE */
/* Transpose the 64x64 bit-matrix in each of the 4 lane-words in place.
 *
 * Runs four independent 64x64 bit-transposes, one per word column.
 *
 * @param  [in, out]  in    64 vec256 lanes; each lane-word bit-transposed.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic scratch allocation fails.
 */
static int wc_mceliece_aff_transpose(word64 in[64][4])
{
    int ret = 0;

    int L;
    int c;
    WC_DECLARE_VAR(col, word64, 64, NULL);

    WC_ALLOC_VAR(col, word64, 64, NULL);
    if (!WC_VAR_OK(col)) {
        ret = MEMORY_E;
    }
    else {
        /* Each of the 4 planes (in[r][L], r = 0..63) is an independent
         * 64x64 bit matrix. Gather the plane into a contiguous buffer, run
         * the fast recursive delta-swap transpose (O(64 log 64) vs naive
         * O(64*64) bit-scan), then scatter back. The transpose is in-place
         * safe (its initial copy is a no-op when out == in). */
        for (L = 0; L < 4; L++) {
            for (c = 0; c < 64; c++) {
                col[c] = in[c][L];
            }
            wc_mceliece_transpose_64x64(col, col);
            for (c = 0; c < 64; c++) {
                in[c][L] = col[c];
            }
        }
        WC_FREE_VAR(col, NULL);
    }
    return ret;
}

static const byte mc_aff_reversal[64] = {
    0, 32, 16, 48, 8, 40, 24, 56, 4, 36, 20, 52, 12, 44, 28, 60,
    2, 34, 18, 50, 10, 42, 26, 58, 6, 38, 22, 54, 14, 46, 30, 62,
    1, 33, 17, 49, 9, 41, 25, 57, 5, 37, 21, 53, 13, 45, 29, 61,
    3, 35, 19, 51, 11, 43, 27, 59, 7, 39, 23, 55, 15, 47, 31, 63
};

/* --- forward fft: radix conversions + butterflies --- */
static const word64 mc_aff_rmask0[5] = {
    W64LIT(0x8888888888888888), W64LIT(0xC0C0C0C0C0C0C0C0),
    W64LIT(0xF000F000F000F000), W64LIT(0xFF000000FF000000),
    W64LIT(0xFFFF000000000000)
};
static const word64 mc_aff_rmask1[5] = {
    W64LIT(0x4444444444444444), W64LIT(0x3030303030303030),
    W64LIT(0x0F000F000F000F00), W64LIT(0x00FF000000FF0000),
    W64LIT(0x0000FFFF00000000)
};
/* One step of the forward additive-FFT radix conversion for a given j: the
 * per-plane twist then the masked right-shift passes (kk = 4..j).
 *
 * @param  [in,out]  in  Bitsliced coefficients, transformed in place.
 * @param  [in]      j   Forward radix-conversion step index.
 */
static void wc_mceliece_aff_radix_step(word64 in[MCELIECE_M][2], int j)
{
    int i;
    int kk;
    word64 t0;
    word64 t1;
    word64 v0;
    word64 v1;

    for (i = 0; i < 13; i++) {
        v1 = in[i][1];
        v1 ^= v1 >> 32;
        v0 = in[i][0];
        v0 ^= v1 << 32;
        in[i][0] = v0;
        in[i][1] = v1;
    }
    for (i = 0; i < 13; i++) {
        for (kk = 4; kk >= j; kk--) {
            int sh = 1 << kk;

            t0 = (in[i][0] & mc_aff_rmask0[kk]) >> sh;
            t1 = (in[i][1] & mc_aff_rmask0[kk]) >> sh;
            in[i][0] ^= t0;
            in[i][1] ^= t1;
            t0 = (in[i][0] & mc_aff_rmask1[kk]) >> sh;
            t1 = (in[i][1] & mc_aff_rmask1[kk]) >> sh;
            in[i][0] ^= t0;
            in[i][1] ^= t1;
        }
    }
}
/* Radix conversion (forward): convert to the additive-FFT basis, in place.
 *
 * Six rounds of bit-shuffle masking and scale multiplies (mc_aff_scal2x) that
 * map the input polynomial into the Gao-Mateer FFT basis over vec128 lanes.
 *
 * @param  [in, out]  in    Polynomial planes (MCELIECE_M x 2 word64).
 * @return  0 on success.
 * @return  MEMORY_E when a scale multiply's scratch allocation fails.
 */
static int wc_mceliece_aff_radix_conv(word64 in[MCELIECE_M][2])
{
    int j;
    int ret = 0;

    for (j = 0; (j <= 5) && (ret == 0); j++) {
        wc_mceliece_aff_radix_step(in, j);
        if (j < 5) {
            ret = wc_mceliece_aff_v128_mul(in, in, mc_aff_scal2x[j]);
        }
    }
    return ret;
}
static const word16 mc_aff_beta_f[8] = {
    2522, 7827, 7801, 8035, 6897, 8167, 3476, 0
};
#ifdef MC_HAVE_AFF_FFT_NEON
/* Coarse forward-FFT butterfly network: mirrors x86 fft_fwd_butterflies_avx2,
 * a C-driver-style asm orchestrator that CALLS the fine FFT leaves. Needs a
 * 532-word64 scratch (tmp/t/pre/buf) and the const twist/reversal tables. */
WOLFSSL_LOCAL void wc_mceliece_fft_fwd_butterflies_neon(word64* out,
    word64* in, int monic, word64* scratch);
#endif

/* Butterfly stages of the forward additive FFT.
 *
 * Consumes the radix-converted input, precomputes the beta twists, runs the
 * bit-reversal butterfly network with per-level twist constants, and (when
 * monic) adds the implicit x^128 leading term. Produces the 32 vec256 output
 * groups, each holding one evaluation block in idx-order.
 *
 * @param  [out]  out    32 groups of MCELIECE_M planes x 4 word64.
 * @param  [in]   in     Radix-converted polynomial (MCELIECE_M x 2 word64).
 * @param  [in]   monic  Non-zero to add the implicit x^128 term (degree-128
 *                       monic locator); zero when the leading term fits.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic scratch allocation fails.
 */
static int wc_mceliece_aff_butterflies(word64 out[32][MCELIECE_M][4],
    word64 in[MCELIECE_M][2], int monic)
{
    int i;
    int j;
    int k;
    int s;
    int b;
    int i2;
    int ret = 0;
    word64 cptr = 2;
#if defined(WOLFSSL_MCELIECE_SMALL)
    int n;
    /* (dst, src, pre) triple for each of the 63 unrolled radix-round XORs; the
     * SMALL path walks these in order instead of emitting 63 fixed calls. */
    static const byte xops[63][3] = {
        { 1,  0, 0}, {16,  0, 4}, { 3,  1, 1}, {48, 16, 5}, {49, 48, 0},
        { 2,  0, 1}, {51, 49, 1}, { 6,  2, 2}, {50, 51, 0}, { 7,  6, 0},
        {54, 50, 2}, { 5,  7, 1}, {55, 54, 0}, {53, 55, 1}, { 4,  0, 2},
        {52, 53, 0}, {12,  4, 3}, {60, 52, 3}, {13, 12, 0}, {61, 60, 0},
        {15, 13, 1}, {63, 61, 1}, {14, 15, 0}, {62, 63, 0}, {10, 14, 2},
        {58, 62, 2}, {11, 10, 0}, {59, 58, 0}, { 9, 11, 1}, {57, 59, 1},
        {56, 57, 0}, { 8,  0, 3}, {40, 56, 4}, {24,  8, 4}, {41, 40, 0},
        {25, 24, 0}, {43, 41, 1}, {27, 25, 1}, {42, 43, 0}, {26, 27, 0},
        {46, 42, 2}, {30, 26, 2}, {47, 46, 0}, {31, 30, 0}, {45, 47, 1},
        {29, 31, 1}, {44, 45, 0}, {28, 29, 0}, {36, 44, 3}, {20, 28, 3},
        {37, 36, 0}, {21, 20, 0}, {39, 37, 1}, {23, 21, 1}, {38, 39, 0},
        {22, 23, 0}, {34, 38, 2}, {18, 22, 2}, {35, 34, 0}, {19, 18, 0},
        {33, 35, 1}, {17, 19, 1}, {32, 33, 0}
    };
#endif
    /* tmp0, tmp1 are live only in the final pack/maa loop, after buf's last use
     * (fwd_out), so they reuse buf's storage: 2 * MCELIECE_M rows fit in 64. */
    mc_bs4* tmp0;
    mc_bs4* tmp1;
    WC_DECLARE_VAR(tmp, mc_bs2, MCELIECE_M, NULL);
    WC_DECLARE_VAR(t, mc_bs2, MCELIECE_M, NULL);
    WC_DECLARE_VAR(pre, mc_bs28, 8, NULL);
    WC_DECLARE_VAR(buf, mc_bs4, 64, NULL);

    WC_ALLOC_VAR(tmp, mc_bs2, MCELIECE_M, NULL);
    WC_ALLOC_VAR(t, mc_bs2, MCELIECE_M, NULL);
    WC_ALLOC_VAR(pre, mc_bs28, 8, NULL);
    WC_ALLOC_VAR(buf, mc_bs4, 64, NULL);
    if (!WC_VAR_OK(tmp) || !WC_VAR_OK(t) || !WC_VAR_OK(pre) ||
            !WC_VAR_OK(buf)) {
        ret = MEMORY_E;
        goto cleanup;
    }
    tmp0 = buf;
    tmp1 = buf + MCELIECE_M;

    XMEMSET(pre, 0, sizeof(word64) * 8 * 28);
    for (j = 0; j < 13; j++) {
        wc_mceliece_aff_v128_uh(t[j], in[j], in[j]);
    }
    for (i = 0; i < 8; i += 2) {
        for (j = 0; j < 13; j++) {
            tmp[j][0] = (word64)0 - (word64)((mc_aff_beta_f[i] >> j) & 1);
            tmp[j][1] = (word64)0 - (word64)((mc_aff_beta_f[i + 1] >> j) & 1);
        }
        ret = wc_mceliece_aff_v128_mul(tmp, t, tmp);
        if (ret != 0) {
            goto cleanup;
        }
        for (j = 0; j < 13; j++) {
            pre[i + 0][j * 2 + 0] = tmp[j][0];
            pre[i + 0][j * 2 + 1] = tmp[j][0];
            pre[i + 1][j * 2 + 0] = tmp[j][1];
            pre[i + 1][j * 2 + 1] = tmp[j][1];
        }
    }
    for (i = 0; i < 13; i += 2) {
        i2 = i >> 1;
        buf[0][0] = in[i][0];
        buf[0][1] = in[i][0] ^ pre[6][i * 2];
        if (i != 12) {
            buf[0][2] = in[i + 1][0];
            buf[0][3] = in[i + 1][0] ^ pre[6][(i + 1) * 2];
        }
#if defined(WOLFSSL_MCELIECE_SMALL)
        for (n = 0; n < 63; n++) {
            wc_mceliece_aff_v256_xor(buf[xops[n][0]], buf[xops[n][1]],
                pre[xops[n][2]] + i2 * 4);
        }
#else
#define X(d, a, p) wc_mceliece_aff_v256_xor(buf[d], buf[a], pre[p] + i2 * 4)
        X(1, 0, 0);
        X(16, 0, 4);
        X(3, 1, 1);
        X(48, 16, 5);
        X(49, 48, 0);
        X(2, 0, 1);
        X(51, 49, 1);
        X(6, 2, 2);
        X(50, 51, 0);
        X(7, 6, 0);
        X(54, 50, 2);
        X(5, 7, 1);
        X(55, 54, 0);
        X(53, 55, 1);
        X(4, 0, 2);
        X(52, 53, 0);
        X(12, 4, 3);
        X(60, 52, 3);
        X(13, 12, 0);
        X(61, 60, 0);
        X(15, 13, 1);
        X(63, 61, 1);
        X(14, 15, 0);
        X(62, 63, 0);
        X(10, 14, 2);
        X(58, 62, 2);
        X(11, 10, 0);
        X(59, 58, 0);
        X(9, 11, 1);
        X(57, 59, 1);
        X(56, 57, 0);
        X(8, 0, 3);
        X(40, 56, 4);
        X(24, 8, 4);
        X(41, 40, 0);
        X(25, 24, 0);
        X(43, 41, 1);
        X(27, 25, 1);
        X(42, 43, 0);
        X(26, 27, 0);
        X(46, 42, 2);
        X(30, 26, 2);
        X(47, 46, 0);
        X(31, 30, 0);
        X(45, 47, 1);
        X(29, 31, 1);
        X(44, 45, 0);
        X(28, 29, 0);
        X(36, 44, 3);
        X(20, 28, 3);
        X(37, 36, 0);
        X(21, 20, 0);
        X(39, 37, 1);
        X(23, 21, 1);
        X(38, 39, 0);
        X(22, 23, 0);
        X(34, 38, 2);
        X(18, 22, 2);
        X(35, 34, 0);
        X(19, 18, 0);
        X(33, 35, 1);
        X(17, 19, 1);
        X(32, 33, 0);
#undef X
#endif
        ret = wc_mceliece_aff_transpose(buf);
        if (ret != 0) {
            goto cleanup;
        }
        wc_mceliece_aff_fwd_out(out, buf, i);
    }
    for (k = 0; k < 32; k += 2) {
        wc_mceliece_aff_pack_lh(tmp0, tmp1, out[k], out[k + 1]);
        ret = wc_mceliece_aff_maa(tmp0, tmp1, mc_aff_consts[1]);
        if (ret != 0) {
            goto cleanup;
        }
        wc_mceliece_aff_pack_lh(out[k], out[k + 1], tmp0, tmp1);
    }
    for (i = 0; i <= 4; i++) {
        s = 1 << i;
        for (j = 0; j < 32; j += 2 * s) {
            for (k = j; k < j + s; k++) {
                ret = wc_mceliece_aff_maa(out[k], out[k + s],
                    mc_aff_consts[cptr + (k - j)]);
                if (ret != 0) {
                    goto cleanup;
                }
            }
        }
        cptr += (1 << i);
    }
    /* Add the implicit x^128 term only when the poly is a monic degree-128
     * (t == 128). For t == 119 the leading term fits in the 128 bitsliced
     * coefficients, so no powers correction is applied. */
    if (monic) {
        for (i = 0; i < 32; i++) {
            for (b = 0; b < 13; b++) {
                wc_mceliece_aff_v256_xor(out[i][b], out[i][b],
                    mc_aff_powers[i][b]);
            }
        }
    }

cleanup:
    WC_FREE_VAR(tmp, NULL);
    WC_FREE_VAR(t, NULL);
    WC_FREE_VAR(pre, NULL);
    WC_FREE_VAR(buf, NULL);
    return ret;
}
/* Forward bitsliced additive FFT (Gao-Mateer): evaluate a 128-coefficient
 * polynomial at all MC_Q field points. Radix conversion then butterflies.
 *
 * @param  [out]  out    Point evaluations: 32 vec256 groups of 13 planes.
 * @param  [in]   in     Bitsliced polynomial: 13 planes x 2 word64 (vec128).
 * @param  [in]   monic  Nonzero adds the implicit x^128 term (degree-128 g).
 * @return  0 on success.
 * @return  A negative error code on failure.
 */
WOLFSSL_LOCAL int wc_mceliece_aff_fft(word64 out[32][MCELIECE_M][4],
    word64 in[MCELIECE_M][2], int monic)
{
    int ret;

    ret = wc_mceliece_aff_radix_conv(in);
    if (ret == 0) {
        ret = wc_mceliece_aff_butterflies(out, in, monic);
    }
    return ret;
}

/* --- transpose fft_tr: butterflies_tr + radix conversions tr --- */
/* Copy a 256-bit vector: r = a.
 *
 * @param  [out]  r  Destination 4 word64 lanes.
 * @param  [in]   a  Source 4 word64 lanes.
 */
#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
static void wc_mceliece_aff_v256_set(word64* r, const word64* a)
{
    r[0] = a[0];
    r[1] = a[1];
    r[2] = a[2];
    r[3] = a[3];
}
static const word64 mc_aff_tmask0[6] = {
    W64LIT(0x2222222222222222), W64LIT(0x0C0C0C0C0C0C0C0C),
    W64LIT(0x00F000F000F000F0), W64LIT(0x0000FF000000FF00),
    W64LIT(0x00000000FFFF0000), W64LIT(0xFFFFFFFF00000000)
};
static const word64 mc_aff_tmask1[6] = {
    W64LIT(0x4444444444444444), W64LIT(0x3030303030303030),
    W64LIT(0x0F000F000F000F00), W64LIT(0x00FF000000FF0000),
    W64LIT(0x0000FFFF00000000), W64LIT(0x00000000FFFFFFFF)
};
/* One step of the transposed-FFT radix conversion for a given j: the masked
 * left-shift passes (k = j..4), the twist (j <= 5) and the combine.
 *
 * @param  [in,out]  in  Bitsliced coefficients, transformed in place.
 * @param  [in]      j   Transposed radix-conversion step index.
 */
static void wc_mceliece_aff_radix_tr_step(word64 in[MCELIECE_M][4], int j)
{
    int i;
    int k;
    int w;
    word64 t[4];
    word64 v[4];

    for (k = j; k <= 4; k++) {
        for (i = 0; i < 13; i++) {
            int sh = 1 << k;

            for (w = 0; w < 4; w++) {
                t[w] = (in[i][w] & mc_aff_tmask0[k]) << sh;
            }
            for (w = 0; w < 4; w++) {
                in[i][w] ^= t[w];
            }
            for (w = 0; w < 4; w++) {
                t[w] = (in[i][w] & mc_aff_tmask1[k]) << sh;
            }
            for (w = 0; w < 4; w++) {
                in[i][w] ^= t[w];
            }
        }
    }
    if (j <= 5) {
        for (i = 0; i < 13; i++) {
            v[0] = in[i][0];
            v[1] = in[i][1];
            v[2] = in[i][2];
            v[3] = in[i][3];
            v[1] ^= v[0] >> 32;
            v[1] ^= v[1] << 32;
            v[3] ^= v[2] >> 32;
            v[3] ^= v[3] << 32;
            in[i][0] = v[0];
            in[i][1] = v[1];
            in[i][2] = v[2];
            in[i][3] = v[3];
        }
    }
    for (i = 0; i < 13; i++) {
        v[0] = in[i][0];
        v[1] = in[i][1];
        v[2] = in[i][2];
        v[3] = in[i][3];
        v[2] ^= v[1];
        v[3] ^= v[2];
        in[i][0] = v[0];
        in[i][1] = v[1];
        in[i][2] = v[2];
        in[i][3] = v[3];
    }
}
/* Transpose (adjoint) of the additive-FFT radix conversion, in place. Applies
 * the twisted-basis steps of wc_mceliece_aff_radix_conv in reverse order.
 *
 * @param  [in, out]  in    Bitsliced data, 13 planes x 4 word64 (vec256).
 * @return  0 on success.
 * @return  A negative error code on failure.
 */
static int wc_mceliece_aff_radix_conv_tr(word64 in[MCELIECE_M][4])
{
    int j;
    int ret = 0;

    for (j = 6; (j >= 0) && (ret == 0); j--) {
        if (j < 6) {
            ret = wc_mceliece_aff_v256_mul(in, in, mc_aff_scal4x[j]);
            if (ret != 0) {
                break;
            }
        }
        wc_mceliece_aff_radix_tr_step(in, j);
    }
    return ret;
}
static const word16 mc_aff_beta_t[6] = {
    5246, 5306, 6039, 6685, 4905, 6755
};
/* Transpose-FFT broadcast network for one plane-pair (C fallback of the asm
 * wc_mceliece_fft_tr_network): fold buf[64] into the pre[6] column-i2 slice,
 * then extract the out128 evaluations from buf[0]^buf[1].
 *
 * @param  [in, out]  pre     6 accumulator columns; column i2 is written here.
 * @param  [in, out]  buf     64-lane transposed scratch, consumed in place.
 * @param  [out]      out128  Evaluation pairs for planes i and i+1.
 * @param  [in]       i       Even plane index being processed.
 * @param  [in]       i2      Column slice index (i >> 1) within pre.
 */
static void wc_mceliece_aff_btr_net(word64 pre[6][28], word64 buf[64][4],
    word64 out128[MCELIECE_M][2][2], int i, int i2)
{
    word64 tv[4];
#if defined(WOLFSSL_MCELIECE_SMALL)
    int n;
    /* (op, dst, src) for the transpose-network step: op 0 = set pre[dst],
     * 1 = xor buf[src] into pre[dst], 2 = xor buf[src] into buf[dst]. The SMALL
     * path walks these instead of emitting the 125 fixed calls below. */
    static const byte bops[125][3] = {
        {0,  0, 32}, {2, 33, 32}, {0,  1, 33}, {2, 35, 33}, {1,  0, 35},
        {2, 34, 35}, {0,  2, 34}, {2, 38, 34}, {1,  0, 38}, {2, 39, 38},
        {1,  1, 39}, {2, 37, 39}, {1,  0, 37}, {2, 36, 37}, {0,  3, 36},
        {2, 44, 36}, {1,  0, 44}, {2, 45, 44}, {1,  1, 45}, {2, 47, 45},
        {1,  0, 47}, {2, 46, 47}, {1,  2, 46}, {2, 42, 46}, {1,  0, 42},
        {2, 43, 42}, {1,  1, 43}, {2, 41, 43}, {1,  0, 41}, {2, 40, 41},
        {0,  4, 40}, {2, 56, 40}, {1,  0, 56}, {2, 57, 56}, {1,  1, 57},
        {2, 59, 57}, {1,  0, 59}, {2, 58, 59}, {1,  2, 58}, {2, 62, 58},
        {1,  0, 62}, {2, 63, 62}, {1,  1, 63}, {2, 61, 63}, {1,  0, 61},
        {2, 60, 61}, {1,  3, 60}, {2, 52, 60}, {1,  0, 52}, {2, 53, 52},
        {1,  1, 53}, {2, 55, 53}, {1,  0, 55}, {2, 54, 55}, {1,  2, 54},
        {2, 50, 54}, {1,  0, 50}, {2, 51, 50}, {1,  1, 51}, {2, 49, 51},
        {1,  0, 49}, {2, 48, 49}, {0,  5, 48}, {2, 16, 48}, {1,  0, 16},
        {2, 17, 16}, {1,  1, 17}, {2, 19, 17}, {1,  0, 19}, {2, 18, 19},
        {1,  2, 18}, {2, 22, 18}, {1,  0, 22}, {2, 23, 22}, {1,  1, 23},
        {2, 21, 23}, {1,  0, 21}, {2, 20, 21}, {1,  3, 20}, {2, 28, 20},
        {1,  0, 28}, {2, 29, 28}, {1,  1, 29}, {2, 31, 29}, {1,  0, 31},
        {2, 30, 31}, {1,  2, 30}, {2, 26, 30}, {1,  0, 26}, {2, 27, 26},
        {1,  1, 27}, {2, 25, 27}, {1,  0, 25}, {2, 24, 25}, {1,  4, 24},
        {2,  8, 24}, {1,  0,  8}, {2,  9,  8}, {1,  1,  9}, {2, 11,  9},
        {1,  0, 11}, {2, 10, 11}, {1,  2, 10}, {2, 14, 10}, {1,  0, 14},
        {2, 15, 14}, {1,  1, 15}, {2, 13, 15}, {1,  0, 13}, {2, 12, 13},
        {1,  3, 12}, {2,  4, 12}, {1,  0,  4}, {2,  5,  4}, {1,  1,  5},
        {2,  7,  5}, {1,  0,  7}, {2,  6,  7}, {1,  2,  6}, {2,  2,  6},
        {1,  0,  2}, {2,  3,  2}, {1,  1,  3}, {2,  1,  3}, {1,  0,  1}
    };

    for (n = 0; n < 125; n++) {
        if (bops[n][0] == 0) {
            wc_mceliece_aff_v256_set(pre[bops[n][1]] + i2 * 4, buf[bops[n][2]]);
        }
        else if (bops[n][0] == 1) {
            wc_mceliece_aff_v256_xor(pre[bops[n][1]] + i2 * 4,
                pre[bops[n][1]] + i2 * 4, buf[bops[n][2]]);
        }
        else {
            wc_mceliece_aff_v256_xor(buf[bops[n][1]], buf[bops[n][1]],
                buf[bops[n][2]]);
        }
    }
#else
#define PS(p, m) wc_mceliece_aff_v256_set(pre[p] + i2 * 4, buf[m])
#define PA(p, m) \
    wc_mceliece_aff_v256_xor(pre[p] + i2 * 4, pre[p] + i2 * 4, buf[m])
#define BX(n, m) wc_mceliece_aff_v256_xor(buf[n], buf[n], buf[m])
        PS(0, 32);
        BX(33, 32);
        PS(1, 33);
        BX(35, 33);
        PA(0, 35);
        BX(34, 35);
        PS(2, 34);
        BX(38, 34);
        PA(0, 38);
        BX(39, 38);
        PA(1, 39);
        BX(37, 39);
        PA(0, 37);
        BX(36, 37);
        PS(3, 36);
        BX(44, 36);
        PA(0, 44);
        BX(45, 44);
        PA(1, 45);
        BX(47, 45);
        PA(0, 47);
        BX(46, 47);
        PA(2, 46);
        BX(42, 46);
        PA(0, 42);
        BX(43, 42);
        PA(1, 43);
        BX(41, 43);
        PA(0, 41);
        BX(40, 41);
        PS(4, 40);
        BX(56, 40);
        PA(0, 56);
        BX(57, 56);
        PA(1, 57);
        BX(59, 57);
        PA(0, 59);
        BX(58, 59);
        PA(2, 58);
        BX(62, 58);
        PA(0, 62);
        BX(63, 62);
        PA(1, 63);
        BX(61, 63);
        PA(0, 61);
        BX(60, 61);
        PA(3, 60);
        BX(52, 60);
        PA(0, 52);
        BX(53, 52);
        PA(1, 53);
        BX(55, 53);
        PA(0, 55);
        BX(54, 55);
        PA(2, 54);
        BX(50, 54);
        PA(0, 50);
        BX(51, 50);
        PA(1, 51);
        BX(49, 51);
        PA(0, 49);
        BX(48, 49);
        PS(5, 48);
        BX(16, 48);
        PA(0, 16);
        BX(17, 16);
        PA(1, 17);
        BX(19, 17);
        PA(0, 19);
        BX(18, 19);
        PA(2, 18);
        BX(22, 18);
        PA(0, 22);
        BX(23, 22);
        PA(1, 23);
        BX(21, 23);
        PA(0, 21);
        BX(20, 21);
        PA(3, 20);
        BX(28, 20);
        PA(0, 28);
        BX(29, 28);
        PA(1, 29);
        BX(31, 29);
        PA(0, 31);
        BX(30, 31);
        PA(2, 30);
        BX(26, 30);
        PA(0, 26);
        BX(27, 26);
        PA(1, 27);
        BX(25, 27);
        PA(0, 25);
        BX(24, 25);
        PA(4, 24);
        BX(8, 24);
        PA(0, 8);
        BX(9, 8);
        PA(1, 9);
        BX(11, 9);
        PA(0, 11);
        BX(10, 11);
        PA(2, 10);
        BX(14, 10);
        PA(0, 14);
        BX(15, 14);
        PA(1, 15);
        BX(13, 15);
        PA(0, 13);
        BX(12, 13);
        PA(3, 12);
        BX(4, 12);
        PA(0, 4);
        BX(5, 4);
        PA(1, 5);
        BX(7, 5);
        PA(0, 7);
        BX(6, 7);
        PA(2, 6);
        BX(2, 6);
        PA(0, 2);
        BX(3, 2);
        PA(1, 3);
        BX(1, 3);
        PA(0, 1);
#undef PS
#undef PA
#undef BX
#endif
        wc_mceliece_aff_v256_xor(tv, buf[0], buf[1]);
        if (i != 12) {
            wc_mceliece_aff_v256_ex2(out128[i + 1][0], tv, 1);
        }
        wc_mceliece_aff_v256_ex2(out128[i + 0][0], tv, 0);

}
/* Transpose (adjoint) of the additive-FFT butterfly network: fold the 32
 * evaluation groups back down into a single bitsliced result plane set.
 *
 * @param  [out]      out   Folded result, 13 planes x 4 word64 (vec256).
 * @param  [in, out]  in    32 evaluation groups; used as scratch in place.
 * @return  0 on success.
 * @return  A negative error code on failure.
 */
static int wc_mceliece_aff_butterflies_tr(word64 out[MCELIECE_M][4],
    word64 in[32][MCELIECE_M][4])
{
    int i;
    int j;
    int k;
    int s;
    int b;
    int i2;
    int ret = 0;
    word64 cptr = 33;
    /* t0, t1 are live only in the pack/ama loop below, where buf is not yet in
     * use (btr_in first writes it afterwards), so they reuse buf's storage:
     * 2 * MCELIECE_M rows fit in its 64. */
    mc_bs4* t0;
    mc_bs4* t1;
    WC_DECLARE_VAR(tmp, mc_bs2, MCELIECE_M, NULL);
    WC_DECLARE_VAR(pre, mc_bs28, 6, NULL);
    WC_DECLARE_VAR(buf, mc_bs4, 64, NULL);

    WC_ALLOC_VAR(tmp, mc_bs2, MCELIECE_M, NULL);
    WC_ALLOC_VAR(pre, mc_bs28, 6, NULL);
    WC_ALLOC_VAR(buf, mc_bs4, 64, NULL);
    if (!WC_VAR_OK(tmp) || !WC_VAR_OK(pre) || !WC_VAR_OK(buf)) {
        ret = MEMORY_E;
        goto cleanup;
    }
    t0 = buf;
    t1 = buf + MCELIECE_M;

    for (i = 4; i >= 0; i--) {
        s = 1 << i;
        cptr -= s;
        for (j = 0; j < 32; j += 2 * s) {
            for (k = j; k < j + s; k++) {
                ret = wc_mceliece_aff_ama(in[k], in[k + s],
                    mc_aff_consts[cptr + (k - j)]);
                if (ret != 0) {
                    goto cleanup;
                }
            }
        }
    }
    for (k = 0; k < 32; k += 2) {
        wc_mceliece_aff_pack_lh(t0, t1, in[k], in[k + 1]);
        ret = wc_mceliece_aff_ama(t0, t1, mc_aff_consts[1]);
        if (ret != 0) {
            goto cleanup;
        }
        wc_mceliece_aff_pack_lh(in[k], in[k + 1], t0, t1);
        wc_mceliece_aff_pack_lh2(t0, t1, in[k], in[k + 1]);
        ret = wc_mceliece_aff_ama(t0, t1, mc_aff_consts[0]);
        if (ret != 0) {
            goto cleanup;
        }
        wc_mceliece_aff_pack_lh2(in[k], in[k + 1], t0, t1);
    }
    for (i = 0; i < 13; i += 2) {
        i2 = i >> 1;
        wc_mceliece_aff_btr_in(buf, in, i);
        ret = wc_mceliece_aff_transpose(buf);
        if (ret != 0) {
            goto cleanup;
        }
        /* Writes out[b][0..1] (the low/high 128-lane pair) directly; out and
         * the [2][2] view alias the same MCELIECE_M x 4 word64. */
        wc_mceliece_aff_btr_net(pre, buf, (word64(*)[2][2])out, i, i2);
    }
    for (j = 0; j < 13; j++) {
        tmp[j][0] = (word64)0 - (word64)((mc_aff_beta_t[0] >> j) & 1);
        tmp[j][1] = tmp[j][0];
    }
    ret = wc_mceliece_aff_v128_mul(tmp, (word64(*)[2])pre[0], tmp);
    if (ret != 0) {
        goto cleanup;
    }
    for (b = 0; b < 13; b++) {
        out[b][2] = tmp[b][0];
        out[b][3] = tmp[b][1];
    }
    for (i = 1; i < 6; i++) {
        for (j = 0; j < 13; j++) {
            tmp[j][0] = (word64)0 - (word64)((mc_aff_beta_t[i] >> j) & 1);
            tmp[j][1] = tmp[j][0];
        }
        ret = wc_mceliece_aff_v128_mul(tmp, (word64(*)[2])pre[i], tmp);
        if (ret != 0) {
            goto cleanup;
        }
        for (b = 0; b < 13; b++) {
            out[b][2] ^= tmp[b][0];
            out[b][3] ^= tmp[b][1];
        }
    }

cleanup:
    WC_FREE_VAR(tmp, NULL);
    WC_FREE_VAR(pre, NULL);
    WC_FREE_VAR(buf, NULL);
    return ret;
}
/* Transpose (adjoint) additive FFT: the butterfly transpose followed by the
 * radix-conversion transpose. Maps point moments back to coefficient space.
 *
 * @param  [out]      out   Result, 13 planes x 4 word64 (vec256).
 * @param  [in, out]  in    32 point-moment groups; used as scratch in place.
 * @return  0 on success.
 * @return  A negative error code on failure.
 */
static int wc_mceliece_aff_fft_tr(word64 out[MCELIECE_M][4],
    word64 in[32][MCELIECE_M][4])
{
    int ret;

    ret = wc_mceliece_aff_butterflies_tr(out, in);
    if (ret == 0) {
        ret = wc_mceliece_aff_radix_conv_tr(out);
    }
    return ret;
}
#endif /* WOLFSSL_MCELIECE_NO_DECAPSULATE */

#ifdef WOLFSSL_MCELIECE_GEN_TABLES
/* The additive-FFT constants depend only on the fixed field, so build them once
 * and cache, guarded by the same three-state atomic as wc_mceliece_fft_tables.
 * */
static wolfSSL_Atomic_Uint mc_aff_state = 0;
#endif

/* Prototype kept next to the definition so a make-key-disabled (decap-only)
 * build - where the make-key forward-decl block is compiled out - still has a
 * visible prototype for this non-static function. */
WOLFSSL_LOCAL void wc_mceliece_aff_tables(void);

#ifdef WOLFSSL_MCELIECE_GEN_TABLES
/* Build the bitsliced additive-FFT constant tables once and cache them, using
 * a three-state atomic so concurrent callers build exactly once. */
void wc_mceliece_aff_tables(void)
{
    if (WOLFSSL_ATOMIC_LOAD(mc_aff_state) != 2) {
        unsigned int expected;

        for (;;) {
            expected = 0;
            if (wolfSSL_Atomic_Uint_CompareExchange(&mc_aff_state, &expected,
                    1) == 1) {
                wc_mceliece_aff_gen_tables();
                WOLFSSL_ATOMIC_STORE(mc_aff_state, 2U);
                break;
            }
            if (expected == 2) {
                break;
            }
            WC_RELAX_LONG_LOOP();
        }
    }
}
#else
/* The additive-FFT constant tables are compile-time fixed (the default, from
 * wc_mceliece_aff_consts.h), so nothing needs building at runtime - this is a
 * no-op kept so callers need not be conditionalised. Define
 * WOLFSSL_MCELIECE_GEN_TABLES to generate them in C at startup instead. */
void wc_mceliece_aff_tables(void)
{
}
#endif

/* Bitsliced GF(2^13) squaring r = a^2 (vec256). Squaring is GF(2)-linear:
 * a(z)^2 = sum a_i z^(2i) reduced mod z^13+z^4+z^3+z+1, so each output plane is
 * a fixed XOR of input planes - far cheaper than a full multiply. All input
 * planes are read into t before any output is written, so r == a is safe.
 *
 * @param  [out]  r  Result, a^2, 13 planes x 4 word64.
 * @param  [in]   a  Input, 13 planes x 4 word64.
 */
static void wc_mceliece_aff_v256_sqr(word64 r[MCELIECE_M][4],
    const word64 a[MCELIECE_M][4])
{
    int w;
    int k;
    word64 t[MCELIECE_M][4];

    for (w = 0; w < 4; w++) {
        t[0][w]  = a[0][w] ^ a[11][w];
        t[1][w]  = a[7][w] ^ a[11][w] ^ a[12][w];
        t[2][w]  = a[1][w] ^ a[7][w];
        t[3][w]  = a[8][w] ^ a[11][w] ^ a[12][w];
        t[4][w]  = a[2][w] ^ a[7][w] ^ a[8][w] ^ a[11][w] ^ a[12][w];
        t[5][w]  = a[7][w] ^ a[9][w];
        t[6][w]  = a[3][w] ^ a[8][w] ^ a[9][w] ^ a[12][w];
        t[7][w]  = a[8][w] ^ a[10][w];
        t[8][w]  = a[4][w] ^ a[9][w] ^ a[10][w];
        t[9][w]  = a[9][w] ^ a[11][w];
        t[10][w] = a[5][w] ^ a[10][w] ^ a[11][w];
        t[11][w] = a[10][w] ^ a[12][w];
        t[12][w] = a[6][w] ^ a[11][w] ^ a[12][w];
    }
    for (k = 0; k < MCELIECE_M; k++) {
        r[k][0] = t[k][0];
        r[k][1] = t[k][1];
        r[k][2] = t[k][2];
        r[k][3] = t[k][3];
    }
}
/* Bitsliced GF(2^13) inverse of a 256-lane group: out = 1/in = in^(2^13-2).
 * Itoh-Tsujii: in^(2^13-2) = product of in^(2^i) for i = 1..12. All lanes
 * inverted in parallel; 0 maps to 0.
 *
 * @param  [out]  out   Inverses, 13 planes x 4 word64 (vec256).
 * @param  [in]   in    Input lanes, 13 planes x 4 word64 (vec256).
 * @return  0 on success.
 * @return  A negative error code on failure.
 */
static int wc_mceliece_aff_inv256(word64 out[MCELIECE_M][4],
    word64 in[MCELIECE_M][4])
{
    int i;
    int k;
    int ret;
    WC_DECLARE_VAR(sq, mc_bs4, MCELIECE_M, NULL);

    WC_ALLOC_VAR(sq, mc_bs4, MCELIECE_M, NULL);
    if (!WC_VAR_OK(sq)) {
        ret = MEMORY_E;
    }
    else {
        wc_mceliece_aff_v256_sqr(sq, in);
        for (k = 0; k < MCELIECE_M; k++) {
            out[k][0] = sq[k][0];
            out[k][1] = sq[k][1];
            out[k][2] = sq[k][2];
            out[k][3] = sq[k][3];
        }
        ret = 0;
        for (i = 2; (ret == 0) && (i <= 12); i++) {
            wc_mceliece_aff_v256_sqr(sq, sq);
            ret = wc_mceliece_aff_v256_mul(out, out, sq);
        }
        WC_FREE_VAR(sq, NULL);
    }
    return ret;
}

#ifdef MC_HAVE_AFF_FFT_NEON
WOLFSSL_LOCAL void wc_mceliece_bs_poly_neon(word64* in, const mc_gf* c);
#endif

/* Bitslice 128 polynomial coefficients c[0..127] into a vec128: 13 planes x 2
 * word64, with coefficients 0..63 in word 0 and 64..127 in word 1.
 *
 * @param  [out]  in  Bitsliced polynomial, 13 planes x 2 word64 (vec128).
 * @param  [in]   c   The 128 mc_gf coefficients to bitslice.
 */
WOLFSSL_LOCAL void wc_mceliece_aff_bs_poly(word64 in[MCELIECE_M][2],
    const mc_gf* c)
{
    int k;
    int d;

    for (k = 0; k < MCELIECE_M; k++) {
        word64 w0 = 0;
        word64 w1 = 0;

        for (d = 0; d < 64; d++) {
            w0 |= (word64)((c[d] >> k) & 1) << d;
            w1 |= (word64)((c[d + 64] >> k) & 1) << d;
        }
        in[k][0] = w0;
        in[k][1] = w1;
    }
}

/* Scale the bitsliced einv (= 1/g^2) by a field-order bitmask and transpose-FFT
 * it, leaving the syndrome moments bitsliced in synd (moment j = bit j across
 * the 13 planes). No Benes here (the caller supplies field order) and no mc_gf
 * unpack (callers that need coefficients do so separately).
 *
 * @param  [out]  synd       Bitsliced syndrome moments, 13 planes x 4 word64.
 * @param  [in]   fieldmask  Field-order MC_Q-bit mask (MC_Q/8 bytes).
 * @param  [in]   einvbs     Bitsliced 1/g^2, 32 groups of 13 planes (vec256).
 * @param  [out]  scaled     Scratch, 32 groups of 13 planes (vec256).
 * @return  0 on success.
 * @return  A negative error code on failure.
 */
#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
static int wc_mceliece_aff_synd_bits(word64 synd[MCELIECE_M][4],
    const byte* fieldmask, word64 einvbs[32][MCELIECE_M][4],
    word64 scaled[32][MCELIECE_M][4])
{
    word64 mask[4];
    int i;
    int k;

    for (i = 0; i < 32; i++) {
        /* Load the 4 field-order mask words little-endian: einvbs is bitsliced
         * with numeric bit order (bit d = element d), so a raw byte copy would
         * misalign the AND on big-endian hosts. */
        mask[0] = wc_mceliece_load8(fieldmask + i * 32);
        mask[1] = wc_mceliece_load8(fieldmask + i * 32 + 8);
        mask[2] = wc_mceliece_load8(fieldmask + i * 32 + 16);
        mask[3] = wc_mceliece_load8(fieldmask + i * 32 + 24);
        for (k = 0; k < MCELIECE_M; k++) {
            scaled[i][k][0] = einvbs[i][k][0] & mask[0];
            scaled[i][k][1] = einvbs[i][k][1] & mask[1];
            scaled[i][k][2] = einvbs[i][k][2] & mask[2];
            scaled[i][k][3] = einvbs[i][k][3] & mask[3];
        }
    }
    return wc_mceliece_aff_fft_tr(synd, scaled);
}

#ifdef MC_HAVE_DECODE_NEON
/* NEON bitsliced-syndrome moment unpack (asm entry); the portable C equivalent
 * is wc_mceliece_aff_synd_unpack below. */
WOLFSSL_LOCAL void wc_mceliece_synd_unpack_neon(mc_gf* s, word64* synd,
    int count);
#endif

/* Unpack the first 2t bitsliced syndrome moments into mc_gf coefficients.
 *
 * @param  [out]  s     Syndrome, 2t mc_gf coefficients.
 * @param  [in]   synd  Bitsliced syndrome moments, 13 planes x 4 word64.
 * @param  [in]   t     Error weight (2t moments unpacked).
 */
static void wc_mceliece_aff_synd_unpack(mc_gf* s, word64 synd[MCELIECE_M][4],
    int t)
{
    int j = 0;
    int k;

    for (; j < 2 * t; j++) {
        mc_gf x = 0;
        int w = j >> 6;
        int b = j & 63;

        for (k = 0; k < MCELIECE_M; k++) {
            x |= (mc_gf)(((synd[k][w] >> b) & 1) << k);
        }
        s[j] = x;
    }
}

/* Bitsliced Goppa syndrome of a support-order word: inverse-Benes to field
 * order, scale the bitsliced einv, transpose-FFT, then unpack the first 2t
 * moments into s. The bitsliced moments are also left in synd for a bitsliced
 * re-encode compare.
 *
 * @param  [out]  s         Syndrome, 2t mc_gf coefficients.
 * @param  [out]  synd      Bitsliced syndrome moments, 13 planes x 4 word64.
 * @param  [in]   wordbits  Support-order bit array (MC_Q bits).
 * @param  [in]   einvbs    Bitsliced 1/g^2, 32 groups of 13 planes (vec256).
 * @param  [in]   condp     Benes condition bits from the private key.
 * @param  [in]   benes     Benes network scratch.
 * @param  [out]  bwork     Scratch of MC_Q/8 bytes (holds the field mask).
 * @param  [in]   t         Error weight.
 * @param  [out]  scaled    Scratch, 32 groups of 13 planes (vec256).
 * @return  0 on success.
 * @return  A negative error code on failure.
 */
static int wc_mceliece_aff_syndrome_bs(mc_gf* s, word64 synd[MCELIECE_M][4],
    const byte* wordbits, word64 einvbs[32][MCELIECE_M][4], const byte* condp,
    word64* benes, byte* bwork, int t, word64 scaled[32][MCELIECE_M][4])
{
    int ret;

    XMEMCPY(bwork, wordbits, (size_t)(MC_Q >> 3));
    wc_mceliece_apply_benes(bwork, condp, 1, benes);
    ret = wc_mceliece_aff_synd_bits(synd, bwork, einvbs, scaled);
    if (ret == 0) {
        wc_mceliece_aff_synd_unpack(s, synd, t);
    }
    return ret;
}

/* The one-shot decode driver lives in the AVX2 object and calls the FFT/BM/
 * Benes helpers, so it needs the Intel asm helpers (MC_HAVE_MUL_ASM) and AVX2
 * to be built in; at run time the helpers dispatch on the CPU features. The
 * driver replicates the whole decode compute; it runs entirely inside the
 * SAVE_VECTOR_REGISTERS2 window that wc_mceliece_decode opens around it. */
/* Decapsulation is driven from C (wc_mceliece_decode_drv_*): the driver calls
 * the additive-FFT decode asm sub-kernels (einv, syndrome, bitsliced BM,
 * root-find, re-encode) in sequence, one copy per ISA.  MC_HAVE_DECODE_ASM /
 * MC_HAVE_DECODE_BS_ASM are defined near the top of this file (before
 * wc_mceliece_dec_layout, which sizes the driver scratch). */

/* Bitsliced-decode phase context: the pure-C decode (wc_mceliece_decode_c)
 * builds this once (buffer pointers, key, runtime const tables, sizes) and each
 * phase (wc_mceliece_aff_einv) reads from it. */
typedef struct McAffDec {
    word64* einvbs;         /*   0 */
    word64 (*ffts)[MCELIECE_M][4]; /*   8 */
    const byte* gp;         /*  16 */
    int t;                  /*  24 */
    int mono;               /*  28 */
} McAffDec;

/* einv phase (pure C): einvbs[e] = 1/g(e)^2 bitsliced, via fft(g), squaring,
 * and a 32-group Montgomery batch inverse.
 *
 * @param  [in]  ctx   Decode phase context: buffers, key and const tables.
 * @return  0 on success.
 * @return  A negative error code on failure.
 */
static int wc_mceliece_aff_einv(const McAffDec* ctx)
{
    word64 (*einvbs)[MCELIECE_M][4] = (word64 (*)[MCELIECE_M][4])(void*)
        ctx->einvbs;
    word64 (*ffts)[MCELIECE_M][4] = ctx->ffts;
    const byte* gp = ctx->gp;
    int t = ctx->t;
    int mono = ctx->mono;
    int i;
    int k;
    int ret = 0;
    WC_DECLARE_VAR(fftw, mc_gf, 128, NULL);
    WC_DECLARE_VAR(poly, mc_bs2, MCELIECE_M, NULL);
    WC_DECLARE_VAR(u, mc_bs4, MCELIECE_M, NULL);
    WC_DECLARE_VAR(tmpg, mc_bs4, MCELIECE_M, NULL);

    WC_ALLOC_VAR(fftw, mc_gf, 128, NULL);
    WC_ALLOC_VAR(poly, mc_bs2, MCELIECE_M, NULL);
    WC_ALLOC_VAR(u, mc_bs4, MCELIECE_M, NULL);
    WC_ALLOC_VAR(tmpg, mc_bs4, MCELIECE_M, NULL);
    if (!WC_VAR_OK(fftw) || !WC_VAR_OK(poly) || !WC_VAR_OK(u) ||
            !WC_VAR_OK(tmpg)) {
        ret = MEMORY_E;
        goto cleanup;
    }

    for (i = 0; i < 128; i++) {
        if (i < t) {
            fftw[i] = wc_mceliece_load_gf(gp + i * 2);
        }
        else if (i == t) {
            fftw[i] = 1;
        }
        else {
            fftw[i] = 0;
        }
    }
    wc_mceliece_aff_bs_poly(poly, fftw);
    ret = wc_mceliece_aff_fft(ffts, poly, mono);
    if (ret != 0) {
        goto cleanup;
    }
    for (i = 0; i < 32; i++) {
        ret = wc_mceliece_aff_v256_mul(ffts[i], ffts[i], ffts[i]);
        if (ret != 0) {
            goto cleanup;
        }
    }
    for (k = 0; k < MCELIECE_M; k++) {
        einvbs[0][k][0] = ffts[0][k][0];
        einvbs[0][k][1] = ffts[0][k][1];
        einvbs[0][k][2] = ffts[0][k][2];
        einvbs[0][k][3] = ffts[0][k][3];
    }
    for (i = 1; i < 32; i++) {
        ret = wc_mceliece_aff_v256_mul(einvbs[i], einvbs[i - 1], ffts[i]);
        if (ret != 0) {
            goto cleanup;
        }
    }
    ret = wc_mceliece_aff_inv256(u, einvbs[31]);
    if (ret != 0) {
        goto cleanup;
    }
    for (i = 31; i >= 1; i--) {
        ret = wc_mceliece_aff_v256_mul(tmpg, u, einvbs[i - 1]);
        if (ret != 0) {
            goto cleanup;
        }
        ret = wc_mceliece_aff_v256_mul(u, u, ffts[i]);
        if (ret != 0) {
            goto cleanup;
        }
        for (k = 0; k < MCELIECE_M; k++) {
            einvbs[i][k][0] = tmpg[k][0];
            einvbs[i][k][1] = tmpg[k][1];
            einvbs[i][k][2] = tmpg[k][2];
            einvbs[i][k][3] = tmpg[k][3];
        }
    }
    for (k = 0; k < MCELIECE_M; k++) {
        einvbs[0][k][0] = u[k][0];
        einvbs[0][k][1] = u[k][1];
        einvbs[0][k][2] = u[k][2];
        einvbs[0][k][3] = u[k][3];
    }

cleanup:
    WC_FREE_VAR(fftw, NULL);
    WC_FREE_VAR(poly, NULL);
    WC_FREE_VAR(u, NULL);
    WC_FREE_VAR(tmpg, NULL);
    return ret;
}

/* Decapsulation Decode path (pure-C, no monolithic asm entry): recover the
 * weight-t error vector from the syndrome using the private key (FFT-based:
 * einv=fft(g), syndrome=fft_tr, wc_mceliece_bm, error=fft(locator), re-encode
 * check). This is the coefficient-bitsliced Goppa decode; wc_mceliece_decode
 * dispatches to the asm driver when available and calls this otherwise. Kept
 * non-inlined so its (allocated) working set is a distinct frame from the thin
 * dispatcher.
 *
 * Steps:
 *  1. einv[e] = 1 / g(e)^2 bitsliced, via fft(g).
 *  2. Syndrome of the received word (padded): Benes to field order, scale by
 *     einv, unpack.
 *  3. Berlekamp-Massey.
 *  4. Locator as the FFT input polynomial; bitslice and forward-FFT it.
 *  5. Roots = all-zero FFT lanes, marked into bwork.
 *  6. Re-encode check syndrome (bitsliced).
 *  7. Roots -> support-order error via Benes (rev=0), copied to e.
 *  8. Weight and moment-mask compare, built into the success mask.
 *
 * @param  [in]   p        Parameter set.
 * @param  [in]   sk       Encoded private key.
 * @param  [in]   c0       Syndrome ciphertext body.
 * @param  [out]  e        Decoded error vector (CEILING(n/8) bytes).
 * @param  [in]   scratch  Buffer of wc_mceliece_decode_scratch_sz(p) bytes.
 * @return  0 on success.
 * @return  MCELIECE_DECODE_FAIL on a decoding failure (caller applies
 *          implicit rejection).
 * @return  A negative hard error otherwise.
 */
static WC_NO_INLINE int wc_mceliece_decode_c(const McElieceParams* p,
    const byte* sk, const byte* c0, byte* e, byte* scratch)
{
    int ret = 0;
    int i;
    int w = 0;
    word16 check;
    word16 sfail = 0;
    const int n = p->n;
    const int t = p->t;
    const byte* gp = sk + MCELIECE_SEED_SZ + MCELIECE_C_SZ;
    const byte* condp = gp + p->irrBytes;
    const int qBytes = MC_Q >> 3;
    McDecBufs db;
    byte* r;
    mc_gf* einv;
    mc_gf* fftw;
    mc_gf* mulbuf;
    mc_gf* fftt;
    mc_gf* s;
    mc_gf* locator;
    mc_gf* tmp;
    mc_gf* c;
    mc_gf* bp;
    byte* bwork;
    word64* benes;
    word64 (*einvbs)[MCELIECE_M][4];
    word64 (*ffts)[MCELIECE_M][4];
    word64 (*scaled)[MCELIECE_M][4];
    McAffDec adc;
    word64 mmask[4];
    word64 chk;
    int tt;
    int k;
    int mono = (t == 128);
    WC_DECLARE_VAR(poly, mc_bs2, MCELIECE_M, NULL);
    WC_DECLARE_VAR(srecv, mc_bs4, MCELIECE_M, NULL);
    WC_DECLARE_VAR(sreenc, mc_bs4, MCELIECE_M, NULL);

    /* The coefficient-bitsliced decode body runs entirely in portable C. */
    wc_mceliece_dec_layout(p, scratch, &db);
    r = db.r;
    einv = db.einv;
    fftw = db.fftw;
    mulbuf = db.mulbuf;
    fftt = db.fftt;
    s = db.s;
    locator = db.locator;
    tmp = db.tmp;
    c = db.c;
    bp = db.bp;
    bwork = db.bwork;
    benes = db.benes;
    /* Bitsliced additive-FFT constants (built once, cached). */
    wc_mceliece_aff_tables();

    WC_ALLOC_VAR(poly, mc_bs2, MCELIECE_M, NULL);
    WC_ALLOC_VAR(srecv, mc_bs4, MCELIECE_M, NULL);
    WC_ALLOC_VAR(sreenc, mc_bs4, MCELIECE_M, NULL);
    if (!WC_VAR_OK(poly) || !WC_VAR_OK(srecv) || !WC_VAR_OK(sreenc)) {
        ret = MEMORY_E;
        goto decode_cleanup;
    }

    /* Bitsliced-throughout decode: the FFT data stays bitsliced between
     * stages (no per-element mc_gf<->bitslice pack/unpack, no scalar
     * transpose), so the whole compute is a handful of SIMD FFTs. */
    einvbs = (word64 (*)[MCELIECE_M][4])einv;
    ffts = (word64 (*)[MCELIECE_M][4])fftt;
    scaled = (word64 (*)[MCELIECE_M][4])mulbuf;

    /* 1. einv[e] = 1 / g(e)^2 bitsliced, via fft(g). g is monic degree t
     * with the leading coefficient implicit (mono adds x^128). */
    adc.einvbs = &einvbs[0][0][0];
    adc.ffts = ffts;
    adc.gp = gp;
    adc.t = t;
    adc.mono = mono;
    ret = wc_mceliece_aff_einv(&adc);
    if (ret != 0) {
        goto decode_cleanup;
    }

    /* 2. Syndrome of the received word (padded to 2^m bits): Benes to field
     *    order, scale by einv, unpack. */
    XMEMCPY(r, c0, p->syndBytes);
    XMEMSET(r + p->syndBytes, 0, (size_t)qBytes - p->syndBytes);
    ret = wc_mceliece_aff_syndrome_bs(s, srecv, r, einvbs, condp, benes,
        bwork, t, scaled);
    if (ret != 0) {
        goto decode_cleanup;
    }

    /* 3. Berlekamp-Massey. */
    wc_mceliece_bm(locator, s, t, tmp, c, bp);

    /* 4. Error support = roots of the locator, found bitsliced: eval it,
     * mark the all-zero lanes (roots) straight into bwork in idx-order
     * (bwork[idx] = root at the field element for bitsliced index idx),
     * then Benes-permute to support order. */
    for (i = 0; i < 128; i++) {
        fftw[i] = (i <= t) ? (mc_gf)locator[i] : 0;
    }
    wc_mceliece_aff_bs_poly(poly, fftw);
    ret = wc_mceliece_aff_fft(ffts, poly, mono);
    if (ret != 0) {
        goto decode_cleanup;
    }
    /* 5. Roots = all-zero FFT lanes, marked into bwork. */
    for (i = 0; i < 32; i++) {
        word64 orv[4];

        orv[0] = 0;
        orv[1] = 0;
        orv[2] = 0;
        orv[3] = 0;
        for (k = 0; k < MCELIECE_M; k++) {
            orv[0] |= ffts[i][k][0];
            orv[1] |= ffts[i][k][1];
            orv[2] |= ffts[i][k][2];
            orv[3] |= ffts[i][k][3];
        }
        orv[0] = ~orv[0];
        orv[1] = ~orv[1];
        orv[2] = ~orv[2];
        orv[3] = ~orv[3];
        /* Store the root field-mask little-endian: it is re-read via load8 by
         * aff_synd_bits and apply_benes below, so a raw copy would byte-swap it
         * on big-endian hosts. */
        wc_mceliece_store8(bwork + i * 32 +  0, orv[0]);
        wc_mceliece_store8(bwork + i * 32 +  8, orv[1]);
        wc_mceliece_store8(bwork + i * 32 + 16, orv[2]);
        wc_mceliece_store8(bwork + i * 32 + 24, orv[3]);
    }

    /* 6. Re-encode check syndrome. bwork now holds the roots in field
     * order; the recovered error e = benes(bwork, rev=0), and its
     * syndrome would benes it straight back to this same field mask, so
     * take the compare syndrome from bwork now and skip that Benes
     * round trip. Safe:
     * the weight term of the final check already rejects unless all t
     * locator roots lie in the support (then field mask == e exactly).
     * Kept bitsliced: the check compares moments bitsliced, so the
     * mc_gf unpack (per-decode ~4K cycles) is skipped here. */
    ret = wc_mceliece_aff_synd_bits(sreenc, bwork, einvbs, scaled);
    if (ret != 0) {
        goto decode_cleanup;
    }

    /* 7. Roots -> support-order error via the Benes network. The
     * error e is exactly the first n bits of bwork (same bit layout),
     * so copy the bytes, clear any bits past n in the last byte, and
     * popcount for the weight - no per-bit loop. */
    wc_mceliece_apply_benes(bwork, condp, 0, benes);
    XMEMCPY(e, bwork, (size_t)p->sBytes);
    if (n & 0x7) {
        e[p->sBytes - 1] &= (byte)((1 << (n & 0x7)) - 1);
    }
    for (i = 0; i < (int)p->sBytes; i++) {
        byte v = e[i];

        v = (byte)(v - ((v >> 1) & 0x55));
        v = (byte)((v & 0x33) + ((v >> 2) & 0x33));
        v = (byte)((v + (v >> 4)) & 0x0F);
        w += v;
    }

    /* 8. Weight and moment-mask compare: the recovered syndrome (sreenc)
     * must equal the received syndrome (srecv) over the first 2t
     * moments. Compare the bitsliced planes directly (moment j = bit
     * j of each plane), masking any bits past 2t in the last word.
     * Fully data-independent - no per-moment mc_gf unpack, no
     * branch. */
    chk = 0;
    tt = 2 * t;
    for (i = 0; i < 4; i++) {
        int bits = tt - i * 64;

        if (bits >= 64) {
            mmask[i] = ~(word64)0;
        }
        else if (bits <= 0) {
            mmask[i] = 0;
        }
        else {
            mmask[i] = ((word64)1 << bits) - 1;
        }
    }
    for (k = 0; k < MCELIECE_M; k++) {
        chk |= (srecv[k][0] ^ sreenc[k][0]) & mmask[0];
        chk |= (srecv[k][1] ^ sreenc[k][1]) & mmask[1];
        chk |= (srecv[k][2] ^ sreenc[k][2]) & mmask[2];
        chk |= (srecv[k][3] ^ sreenc[k][3]) & mmask[3];
    }
    /* Reduce the 64-bit mismatch accumulator to 0 or 1 in bit 0. A plain
     * 16-bit fold could leave a mismatch in bit 15, which would defeat the
     * (check - 1) >> 15 zero-test below and report a failed decode as success,
     * bypassing implicit rejection. */
    chk |= chk >> 32;
    chk |= chk >> 16;
    chk |= chk >> 8;
    chk |= chk >> 4;
    chk |= chk >> 2;
    chk |= chk >> 1;
    sfail |= (word16)(chk & 1);

    check = (word16)w;
    check ^= (word16)t;
    check |= sfail;
    check = (word16)(check - 1);
    check >>= 15;

    /* check == 1 on success, 0 on failure. Build a mask that is all-zero
     * on success and all-ones on failure, then select the fail code. */
    ret = ((int)check - 1) & MCELIECE_DECODE_FAIL;

decode_cleanup:
    WC_FREE_VAR(poly, NULL);
    WC_FREE_VAR(srecv, NULL);
    WC_FREE_VAR(sreenc, NULL);

    return ret;
}

/* Decapsulation Decode dispatcher: run the per-ISA decode driver (a C
 * orchestrator over asm sub-kernels) when the CPU supports it, otherwise fall
 * back to the portable C implementation (wc_mceliece_decode_c).
 *
 * @param  [in]   p        Parameter set.
 * @param  [in]   sk       Encoded private key.
 * @param  [in]   c0       Syndrome ciphertext body.
 * @param  [out]  e        Decoded error vector (CEILING(n/8) bytes).
 * @param  [in]   scratch  Buffer of wc_mceliece_decode_scratch_sz(p) bytes.
 * @return  0 on success.
 * @return  MCELIECE_DECODE_FAIL on a decoding failure (caller applies
 *          implicit rejection).
 * @return  A negative hard error otherwise.
 */

#ifdef MC_HAVE_DECODE_BS_ASM
#ifndef NO_AVX512_SUPPORT
/* Decode sub-kernels (asm) the C decode drivers orchestrate, one driver per
 * ISA (wc_mceliece_decode_drv_*) in place of a single monolithic asm entry. */
WOLFSSL_LOCAL void wc_mceliece_goppa_eval_inv_avx512(word64* einvbs,
    word64* ffts, const byte* gp, int t, int mono, word64* scratch);
WOLFSSL_LOCAL void wc_mceliece_syndrome_avx512(word64* synd, const byte* fm,
    word64* einv, word64* scaled, word64* scratch);
WOLFSSL_LOCAL void wc_mceliece_syndrome_unpack_avx512(mc_gf* s, word64* synd,
    int t);
WOLFSSL_LOCAL void wc_mceliece_berlekamp_massey_avx512(mc_gf* out,
    const mc_gf* s, int t, word64* scratch);
WOLFSSL_LOCAL void wc_mceliece_bitslice_poly_avx512(word64* in, const mc_gf* c);
WOLFSSL_LOCAL void wc_mceliece_radix_conv_avx512(word64* in);
WOLFSSL_LOCAL void wc_mceliece_fft_fwd_butterflies_avx512(word64* out,
    word64* in, int monic, word64* scratch);
WOLFSSL_LOCAL void wc_mceliece_apply_benes_avx2(byte* r, const byte* bits,
    int rev, word64* work);
WOLFSSL_LOCAL void wc_mceliece_benes_prep_avx2(const byte* condp,
    byte* bits_int);

/* C decode driver (AVX512): AVX512 kernels for the heavy stages, AVX2 for
 * the Benes permute, and the glue (bwork copy, root OR-reduce, weight,
 * moment check) in C. One driver per ISA.
 *
 * Steps:
 *  1. einv[e] = 1 / g(e)^2 bitsliced.
 *  2. bwork = received syndrome padded to 2^m bits.
 *  3. Benes prep, permute (rev=1), syndrome and unpack.
 *  4. Berlekamp-Massey.
 *  5. Locator as the FFT input polynomial.
 *  6-7. Bitslice, radix-convert and forward-FFT the locator.
 *  8. Roots = all-zero FFT lanes, marked into bwork in idx order.
 *  9. Re-encode check syndrome (bitsliced).
 *  10. Roots -> support-order error via Benes (rev=0).
 *  11. Moment-mask compare of received vs re-encoded syndromes.
 *
 * @param  [in]   p        Parameter set.
 * @param  [in]   sk       Private key.
 * @param  [in]   c0       Received syndrome (ciphertext).
 * @param  [out]  e        Decoded weight-t error vector (params->sBytes bytes).
 * @param  [in]   scratch  Decode scratch buffer.
 * @return  0 on success.
 * @return  MCELIECE_DECODE_FAIL on a decoding failure.
 * @return  A negative hard error otherwise.
 */
static int wc_mceliece_decode_drv_avx512(const McElieceParams* p,
    const byte* sk, const byte* c0, byte* e, byte* scratch)
{
    const byte* gp = sk + MCELIECE_SEED_SZ + MCELIECE_C_SZ;
    const byte* condp = gp + p->irrBytes;
    const int t = p->t;
    const int mono = (t == 128);
    const int qBytes = MC_Q >> 3;
    McDecBufs db;
    word64 (*ffts)[MCELIECE_M][4];
    word64* einvbs;
    word64* scaled;
    byte* bitsInt;
    word64* callee;
    word64 srecv[MCELIECE_M][4];
    word64 sreenc[MCELIECE_M][4];
    word64 poly[MCELIECE_M][2];
    word64 mmask[4];
    word64 chk = 0;
    int tt = 2 * t;
    int w = 0;
    word16 sfail = 0;
    word16 check;
    int i;
    int k;

    wc_mceliece_dec_layout(p, scratch, &db);
    wc_mceliece_aff_tables();
    einvbs = (word64*)db.einv;
    ffts = (word64 (*)[MCELIECE_M][4])db.fftt;
    scaled = (word64*)db.mulbuf;
    bitsInt = (byte*)(db.scratch + 148);
    callee = db.scratch + 1748;

    /* 1. einv[e] = 1 / g(e)^2 bitsliced. */
    wc_mceliece_goppa_eval_inv_avx512(einvbs, (word64*)ffts, gp, t, mono,
        callee);

    /* 2. bwork = received syndrome padded to 2^m bits. */
    XMEMCPY(db.bwork, c0, p->syndBytes);
    XMEMSET(db.bwork + p->syndBytes, 0, (size_t)qBytes - p->syndBytes);

    /* 3. Benes prep, permute (rev=1), syndrome and unpack. */
    wc_mceliece_benes_prep_avx2(condp, bitsInt);
    wc_mceliece_apply_benes_avx2(db.bwork, bitsInt, 1, db.benes);
    wc_mceliece_syndrome_avx512((word64*)srecv, db.bwork, einvbs, scaled,
        callee);
    wc_mceliece_syndrome_unpack_avx512(db.s, (word64*)srecv, t);

    /* 4. Berlekamp-Massey. */
    wc_mceliece_berlekamp_massey_avx512(db.locator, db.s, t, callee);

    /* 5. Locator as the FFT input polynomial. */
    for (i = 0; i < 128; i++) {
        db.fftw[i] = (i <= t) ? (mc_gf)db.locator[i] : 0;
    }

    /* 6-7. Bitslice, radix-convert, forward-FFT the locator. */
    wc_mceliece_bitslice_poly_avx512((word64*)poly, db.fftw);
    wc_mceliece_radix_conv_avx512((word64*)poly);
    wc_mceliece_fft_fwd_butterflies_avx512((word64*)ffts, (word64*)poly, mono,
        callee);

    /* 8. Roots = all-zero FFT lanes, marked into bwork in idx order. */
    for (i = 0; i < 32; i++) {
        word64 orv[4];

        orv[0] = 0;
        orv[1] = 0;
        orv[2] = 0;
        orv[3] = 0;
        for (k = 0; k < MCELIECE_M; k++) {
            orv[0] |= ffts[i][k][0];
            orv[1] |= ffts[i][k][1];
            orv[2] |= ffts[i][k][2];
            orv[3] |= ffts[i][k][3];
        }
        orv[0] = ~orv[0];
        orv[1] = ~orv[1];
        orv[2] = ~orv[2];
        orv[3] = ~orv[3];
        wc_mceliece_store8(db.bwork + i * 32 +  0, orv[0]);
        wc_mceliece_store8(db.bwork + i * 32 +  8, orv[1]);
        wc_mceliece_store8(db.bwork + i * 32 + 16, orv[2]);
        wc_mceliece_store8(db.bwork + i * 32 + 24, orv[3]);
    }

    /* 9. Re-encode check syndrome (bitsliced). */
    wc_mceliece_syndrome_avx512((word64*)sreenc, db.bwork, einvbs, scaled,
        callee);

    /* 10. Roots -> support-order error via Benes (rev=0). */
    wc_mceliece_apply_benes_avx2(db.bwork, bitsInt, 0, db.benes);
    XMEMCPY(e, db.bwork, (size_t)p->sBytes);
    if (p->n & 0x7) {
        e[p->sBytes - 1] &= (byte)((1 << (p->n & 0x7)) - 1);
    }
    for (i = 0; i < (int)p->sBytes; i++) {
        byte v = e[i];

        v = (byte)(v - ((v >> 1) & 0x55));
        v = (byte)((v & 0x33) + ((v >> 2) & 0x33));
        v = (byte)((v + (v >> 4)) & 0x0F);
        w += v;
    }

    /* 11. Moment-mask compare of received vs re-encoded syndromes. */
    for (i = 0; i < 4; i++) {
        int bits = tt - i * 64;

        if (bits >= 64) {
            mmask[i] = ~(word64)0;
        }
        else if (bits <= 0) {
            mmask[i] = 0;
        }
        else {
            mmask[i] = ((word64)1 << bits) - 1;
        }
    }
    for (k = 0; k < MCELIECE_M; k++) {
        chk |= (srecv[k][0] ^ sreenc[k][0]) & mmask[0];
        chk |= (srecv[k][1] ^ sreenc[k][1]) & mmask[1];
        chk |= (srecv[k][2] ^ sreenc[k][2]) & mmask[2];
        chk |= (srecv[k][3] ^ sreenc[k][3]) & mmask[3];
    }
    /* Reduce the 64-bit mismatch accumulator to 0 or 1 in bit 0. A plain
     * 16-bit fold could leave a mismatch in bit 15, which would defeat the
     * (check - 1) >> 15 zero-test below and report a failed decode as success,
     * bypassing implicit rejection. */
    chk |= chk >> 32;
    chk |= chk >> 16;
    chk |= chk >> 8;
    chk |= chk >> 4;
    chk |= chk >> 2;
    chk |= chk >> 1;
    sfail |= (word16)(chk & 1);

    check = (word16)w;
    check ^= (word16)t;
    check |= sfail;
    check = (word16)(check - 1);
    check >>= 15;
    return ((int)check - 1) & MCELIECE_DECODE_FAIL;
}
#endif /* !NO_AVX512_SUPPORT */

/* AVX2 decode driver: uses only AVX2 sub-kernels, so it is available on an
 * AVX2-only build (independent of NO_AVX512_SUPPORT). */
#ifndef NO_AVX2_SUPPORT
WOLFSSL_LOCAL void wc_mceliece_goppa_eval_inv_avx2(word64* einvbs, word64* ffts,
    const byte* gp, int t, int mono, word64* scratch);
WOLFSSL_LOCAL void wc_mceliece_syndrome_avx2(word64* synd, const byte* fm,
    word64* einv, word64* scaled, word64* scratch);
WOLFSSL_LOCAL void wc_mceliece_syndrome_unpack_avx2(mc_gf* s, word64* synd,
    int t);
WOLFSSL_LOCAL void wc_mceliece_berlekamp_massey_avx2(mc_gf* out, const mc_gf* s,
    int t, word64* scratch);
/* AVX2 Benes kernels (also declared in the AVX512 driver block above; both
 * drivers use them and the blocks are now guard-independent). */
WOLFSSL_LOCAL void wc_mceliece_apply_benes_avx2(byte* r, const byte* bits,
    int rev, word64* work);
WOLFSSL_LOCAL void wc_mceliece_benes_prep_avx2(const byte* condp,
    byte* bitsInt);
/* Shared AVX2 FFT kernels (also declared under the make-key guard for keygen);
 * decode needs them even when make-key is compiled out. */
WOLFSSL_LOCAL void wc_mceliece_bitslice_poly_avx2(word64* in, const mc_gf* c);
WOLFSSL_LOCAL void wc_mceliece_radix_conv_avx2(word64* in);
WOLFSSL_LOCAL void wc_mceliece_fft_fwd_butterflies_avx2(word64* out, word64* in,
    int monic, word64* scratch);

/* C decode driver (AVX2): AVX2 kernels for the heavy stages and the Benes
 * permute, with the glue (bwork copy, root OR-reduce, weight, moment check) in
 * C. One driver per ISA.
 *
 * Steps:
 *  1. einv[e] = 1 / g(e)^2 bitsliced.
 *  2. bwork = received syndrome padded to 2^m bits.
 *  3. Benes prep, permute (rev=1), syndrome and unpack.
 *  4. Berlekamp-Massey.
 *  5. Locator as the FFT input polynomial.
 *  6-7. Bitslice, radix-convert and forward-FFT the locator.
 *  8. Roots = all-zero FFT lanes, marked into bwork in idx order.
 *  9. Re-encode check syndrome (bitsliced).
 *  10. Roots -> support-order error via Benes (rev=0).
 *  11. Moment-mask compare of received vs re-encoded syndromes.
 *
 * @param  [in]   p        Parameter set.
 * @param  [in]   sk       Private key.
 * @param  [in]   c0       Received syndrome (ciphertext).
 * @param  [out]  e        Decoded weight-t error vector (params->sBytes bytes).
 * @param  [in]   scratch  Decode scratch buffer.
 * @return  0 on success.
 * @return  MCELIECE_DECODE_FAIL on a decoding failure.
 * @return  A negative hard error otherwise.
 */
static int wc_mceliece_decode_drv_avx2(const McElieceParams* p, const byte* sk,
    const byte* c0, byte* e, byte* scratch)
{
    const byte* gp = sk + MCELIECE_SEED_SZ + MCELIECE_C_SZ;
    const byte* condp = gp + p->irrBytes;
    const int t = p->t;
    const int mono = (t == 128);
    const int qBytes = MC_Q >> 3;
    McDecBufs db;
    word64 (*ffts)[MCELIECE_M][4];
    word64* einvbs;
    word64* scaled;
    byte* bitsInt;
    word64* callee;
    word64 srecv[MCELIECE_M][4];
    word64 sreenc[MCELIECE_M][4];
    word64 poly[MCELIECE_M][2];
    word64 mmask[4];
    word64 chk = 0;
    int tt = 2 * t;
    int w = 0;
    word16 sfail = 0;
    word16 check;
    int i;
    int k;

    wc_mceliece_dec_layout(p, scratch, &db);
    wc_mceliece_aff_tables();
    einvbs = (word64*)db.einv;
    ffts = (word64 (*)[MCELIECE_M][4])db.fftt;
    scaled = (word64*)db.mulbuf;
    bitsInt = (byte*)(db.scratch + 148);
    callee = db.scratch + 1748;

    /* 1. einv[e] = 1 / g(e)^2 bitsliced. */
    wc_mceliece_goppa_eval_inv_avx2(einvbs, (word64*)ffts, gp, t, mono, callee);

    /* 2. bwork = received syndrome padded to 2^m bits. */
    XMEMCPY(db.bwork, c0, p->syndBytes);
    XMEMSET(db.bwork + p->syndBytes, 0, (size_t)qBytes - p->syndBytes);

    /* 3. Benes prep, permute (rev=1), syndrome and unpack. */
    wc_mceliece_benes_prep_avx2(condp, bitsInt);
    wc_mceliece_apply_benes_avx2(db.bwork, bitsInt, 1, db.benes);
    wc_mceliece_syndrome_avx2((word64*)srecv, db.bwork, einvbs, scaled, callee);
    wc_mceliece_syndrome_unpack_avx2(db.s, (word64*)srecv, t);

    /* 4. Berlekamp-Massey. */
    wc_mceliece_berlekamp_massey_avx2(db.locator, db.s, t, callee);

    /* 5. Locator as the FFT input polynomial. */
    for (i = 0; i < 128; i++) {
        db.fftw[i] = (i <= t) ? (mc_gf)db.locator[i] : 0;
    }

    /* 6-7. Bitslice, radix-convert, forward-FFT the locator. */
    wc_mceliece_bitslice_poly_avx2((word64*)poly, db.fftw);
    wc_mceliece_radix_conv_avx2((word64*)poly);
    wc_mceliece_fft_fwd_butterflies_avx2((word64*)ffts, (word64*)poly, mono,
        callee);

    /* 8. Roots = all-zero FFT lanes, marked into bwork in idx order. */
    for (i = 0; i < 32; i++) {
        word64 orv[4];

        orv[0] = 0;
        orv[1] = 0;
        orv[2] = 0;
        orv[3] = 0;
        for (k = 0; k < MCELIECE_M; k++) {
            orv[0] |= ffts[i][k][0];
            orv[1] |= ffts[i][k][1];
            orv[2] |= ffts[i][k][2];
            orv[3] |= ffts[i][k][3];
        }
        orv[0] = ~orv[0];
        orv[1] = ~orv[1];
        orv[2] = ~orv[2];
        orv[3] = ~orv[3];
        wc_mceliece_store8(db.bwork + i * 32 +  0, orv[0]);
        wc_mceliece_store8(db.bwork + i * 32 +  8, orv[1]);
        wc_mceliece_store8(db.bwork + i * 32 + 16, orv[2]);
        wc_mceliece_store8(db.bwork + i * 32 + 24, orv[3]);
    }

    /* 9. Re-encode check syndrome (bitsliced). */
    wc_mceliece_syndrome_avx2((word64*)sreenc, db.bwork, einvbs, scaled,
        callee);

    /* 10. Roots -> support-order error via Benes (rev=0). */
    wc_mceliece_apply_benes_avx2(db.bwork, bitsInt, 0, db.benes);
    XMEMCPY(e, db.bwork, (size_t)p->sBytes);
    if (p->n & 0x7) {
        e[p->sBytes - 1] &= (byte)((1 << (p->n & 0x7)) - 1);
    }
    for (i = 0; i < (int)p->sBytes; i++) {
        byte v = e[i];

        v = (byte)(v - ((v >> 1) & 0x55));
        v = (byte)((v & 0x33) + ((v >> 2) & 0x33));
        v = (byte)((v + (v >> 4)) & 0x0F);
        w += v;
    }

    /* 11. Moment-mask compare of received vs re-encoded syndromes. */
    for (i = 0; i < 4; i++) {
        int bits = tt - i * 64;

        if (bits >= 64) {
            mmask[i] = ~(word64)0;
        }
        else if (bits <= 0) {
            mmask[i] = 0;
        }
        else {
            mmask[i] = ((word64)1 << bits) - 1;
        }
    }
    for (k = 0; k < MCELIECE_M; k++) {
        chk |= (srecv[k][0] ^ sreenc[k][0]) & mmask[0];
        chk |= (srecv[k][1] ^ sreenc[k][1]) & mmask[1];
        chk |= (srecv[k][2] ^ sreenc[k][2]) & mmask[2];
        chk |= (srecv[k][3] ^ sreenc[k][3]) & mmask[3];
    }
    /* Reduce the 64-bit mismatch accumulator to 0 or 1 in bit 0. A plain
     * 16-bit fold could leave a mismatch in bit 15, which would defeat the
     * (check - 1) >> 15 zero-test below and report a failed decode as success,
     * bypassing implicit rejection. */
    chk |= chk >> 32;
    chk |= chk >> 16;
    chk |= chk >> 8;
    chk |= chk >> 4;
    chk |= chk >> 2;
    chk |= chk >> 1;
    sfail |= (word16)(chk & 1);

    check = (word16)w;
    check ^= (word16)t;
    check |= sfail;
    check = (word16)(check - 1);
    check >>= 15;
    return ((int)check - 1) & MCELIECE_DECODE_FAIL;
}

#endif /* !NO_AVX2_SUPPORT */

#ifndef NO_AVX512_SUPPORT
/* GFNI Benes network (asm entries): wc_mceliece_benes_prep_gfni expands the
 * private-key condition bits, wc_mceliece_apply_benes_gfni applies the
 * permutation. Used by the GFNI decode driver below. */
WOLFSSL_LOCAL void wc_mceliece_apply_benes_gfni(byte* r, const byte* bits,
    int rev, word64* work);
WOLFSSL_LOCAL void wc_mceliece_benes_prep_gfni(const byte* condp,
    byte* bits_int);

/* C decode driver (GFNI): AVX512 kernels for the heavy stages and the GFNI
 * (vgf2p8affineqb) Benes permute, with the glue (bwork copy, root OR-reduce,
 * weight, moment check) in C. One driver per ISA.
 *
 * Steps:
 *  1. einv[e] = 1 / g(e)^2 bitsliced.
 *  2. bwork = received syndrome padded to 2^m bits.
 *  3. Benes prep, permute (rev=1), syndrome and unpack.
 *  4. Berlekamp-Massey.
 *  5. Locator as the FFT input polynomial.
 *  6-7. Bitslice, radix-convert and forward-FFT the locator.
 *  8. Roots = all-zero FFT lanes, marked into bwork in idx order.
 *  9. Re-encode check syndrome (bitsliced).
 *  10. Roots -> support-order error via Benes (rev=0).
 *  11. Moment-mask compare of received vs re-encoded syndromes.
 *
 * @param  [in]   p        Parameter set.
 * @param  [in]   sk       Private key.
 * @param  [in]   c0       Received syndrome (ciphertext).
 * @param  [out]  e        Decoded weight-t error vector (params->sBytes bytes).
 * @param  [in]   scratch  Decode scratch buffer.
 * @return  0 on success.
 * @return  MCELIECE_DECODE_FAIL on a decoding failure.
 * @return  A negative hard error otherwise.
 */


static int wc_mceliece_decode_drv_gfni(const McElieceParams* p, const byte* sk,
    const byte* c0, byte* e, byte* scratch)
{
    const byte* gp = sk + MCELIECE_SEED_SZ + MCELIECE_C_SZ;
    const byte* condp = gp + p->irrBytes;
    const int t = p->t;
    const int mono = (t == 128);
    const int qBytes = MC_Q >> 3;
    McDecBufs db;
    word64 (*ffts)[MCELIECE_M][4];
    word64* einvbs;
    word64* scaled;
    byte* bitsInt;
    word64* callee;
    word64 srecv[MCELIECE_M][4];
    word64 sreenc[MCELIECE_M][4];
    word64 poly[MCELIECE_M][2];
    word64 mmask[4];
    word64 chk = 0;
    int tt = 2 * t;
    int w = 0;
    word16 sfail = 0;
    word16 check;
    int i;
    int k;

    wc_mceliece_dec_layout(p, scratch, &db);
    wc_mceliece_aff_tables();
    einvbs = (word64*)db.einv;
    ffts = (word64 (*)[MCELIECE_M][4])db.fftt;
    scaled = (word64*)db.mulbuf;
    bitsInt = (byte*)(db.scratch + 148);
    callee = db.scratch + 1748;

    /* 1. einv[e] = 1 / g(e)^2 bitsliced. */
    wc_mceliece_goppa_eval_inv_avx512(einvbs, (word64*)ffts, gp, t, mono,
        callee);

    /* 2. bwork = received syndrome padded to 2^m bits. */
    XMEMCPY(db.bwork, c0, p->syndBytes);
    XMEMSET(db.bwork + p->syndBytes, 0, (size_t)qBytes - p->syndBytes);

    /* 3. Benes prep, permute (rev=1), syndrome and unpack. */
    wc_mceliece_benes_prep_gfni(condp, bitsInt);
    wc_mceliece_apply_benes_gfni(db.bwork, bitsInt, 1, db.benes);
    wc_mceliece_syndrome_avx512((word64*)srecv, db.bwork, einvbs, scaled,
        callee);
    wc_mceliece_syndrome_unpack_avx512(db.s, (word64*)srecv, t);

    /* 4. Berlekamp-Massey. */
    wc_mceliece_berlekamp_massey_avx512(db.locator, db.s, t, callee);

    /* 5. Locator as the FFT input polynomial. */
    for (i = 0; i < 128; i++) {
        db.fftw[i] = (i <= t) ? (mc_gf)db.locator[i] : 0;
    }

    /* 6-7. Bitslice, radix-convert, forward-FFT the locator. */
    wc_mceliece_bitslice_poly_avx512((word64*)poly, db.fftw);
    wc_mceliece_radix_conv_avx512((word64*)poly);
    wc_mceliece_fft_fwd_butterflies_avx512((word64*)ffts, (word64*)poly, mono,
        callee);

    /* 8. Roots = all-zero FFT lanes, marked into bwork in idx order. */
    for (i = 0; i < 32; i++) {
        word64 orv[4];

        orv[0] = 0;
        orv[1] = 0;
        orv[2] = 0;
        orv[3] = 0;
        for (k = 0; k < MCELIECE_M; k++) {
            orv[0] |= ffts[i][k][0];
            orv[1] |= ffts[i][k][1];
            orv[2] |= ffts[i][k][2];
            orv[3] |= ffts[i][k][3];
        }
        orv[0] = ~orv[0];
        orv[1] = ~orv[1];
        orv[2] = ~orv[2];
        orv[3] = ~orv[3];
        wc_mceliece_store8(db.bwork + i * 32 +  0, orv[0]);
        wc_mceliece_store8(db.bwork + i * 32 +  8, orv[1]);
        wc_mceliece_store8(db.bwork + i * 32 + 16, orv[2]);
        wc_mceliece_store8(db.bwork + i * 32 + 24, orv[3]);
    }

    /* 9. Re-encode check syndrome (bitsliced). */
    wc_mceliece_syndrome_avx512((word64*)sreenc, db.bwork, einvbs, scaled,
        callee);

    /* 10. Roots -> support-order error via Benes (rev=0). */
    wc_mceliece_apply_benes_gfni(db.bwork, bitsInt, 0, db.benes);
    XMEMCPY(e, db.bwork, (size_t)p->sBytes);
    if (p->n & 0x7) {
        e[p->sBytes - 1] &= (byte)((1 << (p->n & 0x7)) - 1);
    }
    for (i = 0; i < (int)p->sBytes; i++) {
        byte v = e[i];

        v = (byte)(v - ((v >> 1) & 0x55));
        v = (byte)((v & 0x33) + ((v >> 2) & 0x33));
        v = (byte)((v + (v >> 4)) & 0x0F);
        w += v;
    }

    /* 11. Moment-mask compare of received vs re-encoded syndromes. */
    for (i = 0; i < 4; i++) {
        int bits = tt - i * 64;

        if (bits >= 64) {
            mmask[i] = ~(word64)0;
        }
        else if (bits <= 0) {
            mmask[i] = 0;
        }
        else {
            mmask[i] = ((word64)1 << bits) - 1;
        }
    }
    for (k = 0; k < MCELIECE_M; k++) {
        chk |= (srecv[k][0] ^ sreenc[k][0]) & mmask[0];
        chk |= (srecv[k][1] ^ sreenc[k][1]) & mmask[1];
        chk |= (srecv[k][2] ^ sreenc[k][2]) & mmask[2];
        chk |= (srecv[k][3] ^ sreenc[k][3]) & mmask[3];
    }
    /* Reduce the 64-bit mismatch accumulator to 0 or 1 in bit 0. A plain
     * 16-bit fold could leave a mismatch in bit 15, which would defeat the
     * (check - 1) >> 15 zero-test below and report a failed decode as success,
     * bypassing implicit rejection. */
    chk |= chk >> 32;
    chk |= chk >> 16;
    chk |= chk >> 8;
    chk |= chk >> 4;
    chk |= chk >> 2;
    chk |= chk >> 1;
    sfail |= (word16)(chk & 1);

    check = (word16)w;
    check ^= (word16)t;
    check |= sfail;
    check = (word16)(check - 1);
    check >>= 15;
    return ((int)check - 1) & MCELIECE_DECODE_FAIL;
}

#endif /* !NO_AVX512_SUPPORT (gfni) */

#endif /* MC_HAVE_DECODE_BS_ASM */

#ifdef MC_HAVE_DECODE_NEON
/* AArch64 NEON decode driver. Symmetric with the x86 wc_mceliece_decode_drv_*
 * entry points: a C orchestrator that calls the raw NEON leaf kernels (Benes
 * layers, additive-FFT/GF kernels) directly inside the single vector-register
 * window that wc_mceliece_decode opens around the whole driver - so the kernels
 * do no per-call save/restore. All scratch is allocated by the caller before
 * that window opens (wc_McElieceKey_Decapsulate does one allocation up front),
 * so nothing sleeps while the window is held - safe even where holding a window
 * disables preemption (kernel_neon_begin). */
/* Coarse forward radix-conversion kernel (built + validated, wired live here).
 * Tables: rm0/rm1 = rmask0/1, scal = scal2x; c is a 25-plane mul scratch.
 * AArch32 has no spare argument register for c (the kernel already uses the
 * full GP file), so it keeps that scratch on its own stack and takes no c -
 * declare and call it per architecture to match each kernel's real signature. */
#if defined(__aarch64__)
WOLFSSL_LOCAL void wc_mceliece_radix_conv_neon(word64* in, word64* c);
#else
WOLFSSL_LOCAL void wc_mceliece_radix_conv_neon(word64* in);
#endif
/* Coarse single entry points (x86 goppa_eval_inv/syndrome analogues): bl-
 * orchestrators over the leaves, which read the global const tables populated
 * by wc_mceliece_aff_tables(). */
WOLFSSL_LOCAL void wc_mceliece_goppa_eval_inv_neon(word64* einvbs, word64* ffts,
    const byte* gp, int t, int mono, word64* poly, word64* scratch);
WOLFSSL_LOCAL void wc_mceliece_syndrome_neon(word64* synd,
    const byte* fieldmask, word64* einvbs, word64* scaled, word64* scratch);
/* Full Berlekamp-Massey in asm (x86 berlekamp_massey_avx2 analogue). scratch is
 * a word64 buffer carving tmp/c/bp (>= 192 word64). */
WOLFSSL_LOCAL void wc_mceliece_berlekamp_massey_neon(word16* out,
    const word16* s, int t, word64* scratch);

/* Flat NEON decode driver, mirroring wc_mceliece_decode_drv_avx512/avx2: a C
 * orchestrator calling the NEON assembly kernels explicitly at each step. The
 * caller (wc_mceliece_decode) holds one vector-register window, so the kernels
 * are the raw _neon entry points (no per-call save/restore). The x86 coarse
 * goppa_eval_inv/syndrome/berlekamp_massey entry points expand here into their
 * NEON constituents (bs_poly + radix_conv + butterflies + Montgomery; synd_mask
 * + butterflies_tr + radix_conv_tr + unpack; the BM body). ksc (640 word64) is
 * the shared kernel scratch, reused sequentially.
 *
 * Steps:
 *  1. einv = 1/g(e)^2 bitsliced (fft(g) + Montgomery batch inverse).
 *  2. Received syndrome, padded to 2^m bits.
 *  3. Benes(rev=1) to field order, scale einv, transpose-FFT, unpack.
 *  4. Berlekamp-Massey (full asm; carves tmp/c/bp from ksc).
 *  5. Roots = all-zero FFT lanes of the locator, marked into bwork.
 *  6. Re-encode check syndrome (bitsliced) from the root field-mask.
 *  7. Roots -> support-order error via Benes(rev=0); popcount the weight.
 *  8. Moment-mask compare of received vs re-encoded syndromes.
 *
 * @param  [in]   p        Parameter set.
 * @param  [in]   sk       Private key.
 * @param  [in]   c0       Received syndrome (ciphertext).
 * @param  [out]  e        Decoded weight-t error vector (params->sBytes bytes).
 * @param  [in]   scratch  Decode scratch buffer.
 * @return  0 on success.
 * @return  MCELIECE_DECODE_FAIL on a decoding failure.
 * @return  A negative hard error otherwise.
 */
static int wc_mceliece_decode_drv_neon(const McElieceParams* p, const byte* sk,
    const byte* c0, byte* e, byte* scratch)
{
    int ret = 0;
    int i;
    int k;
    int nv;
    int w = 0;
    int tt = 2 * p->t;
    word16 check;
    word16 sfail = 0;
    const int n = p->n;
    const int t = p->t;
    const int mono = (t == 128);
    const byte* gp = sk + MCELIECE_SEED_SZ + MCELIECE_C_SZ;
    const byte* condp = gp + p->irrBytes;
    const int qBytes = MC_Q >> 3;
    McDecBufs db;
    mc_gf* fftw;
    mc_gf* s;
    mc_gf* locator;
    byte* r;
    byte* bwork;
    word64* benes;
    word64 (*einvbs)[MCELIECE_M][4];
    word64 (*ffts)[MCELIECE_M][4];
    word64 (*scaled)[MCELIECE_M][4];
    word64 mmask[4];
    word64 chk = 0;
    /* ksc/srecv/sreenc/poly are carved from the arena scratch (db.scratch),
     * not the stack - see wc_mceliece_dec_layout/MC_DEC_NEON_SCRATCH_WORDS. */
    mc_bs2* poly;
    mc_bs4* srecv;
    mc_bs4* sreenc;
    word64* ksc;

    wc_mceliece_dec_layout(p, scratch, &db);
    wc_mceliece_aff_tables();
    r = db.r;
    fftw = db.fftw;
    s = db.s;
    locator = db.locator;
    bwork = db.bwork;
    benes = db.benes;
    einvbs = (word64 (*)[MCELIECE_M][4])db.einv;
    ffts = (word64 (*)[MCELIECE_M][4])db.fftt;
    scaled = (word64 (*)[MCELIECE_M][4])db.mulbuf;
    /* Carve ksc + srecv/sreenc/poly from the arena driver scratch. */
    ksc    = db.scratch;
    srecv  = (mc_bs4*)(db.scratch + MC_DEC_NEON_KSC_WORDS);
    sreenc = (mc_bs4*)(db.scratch + MC_DEC_NEON_KSC_WORDS + MCELIECE_M * 4);
    poly   = (mc_bs2*)(db.scratch + MC_DEC_NEON_KSC_WORDS + MCELIECE_M * 8);

    /* 1. einv = 1/g(e)^2 bitsliced (fft(g) + Montgomery batch inverse). */
    wc_mceliece_goppa_eval_inv_neon((word64*)einvbs, (word64*)ffts, gp, t, mono,
        (word64*)poly, ksc);

    /* 2. Received syndrome, padded to 2^m bits. */
    XMEMCPY(r, c0, p->syndBytes);
    XMEMSET(r + p->syndBytes, 0, (size_t)qBytes - p->syndBytes);

    /* 3. Benes(rev=1) to field order, scale einv, transpose-FFT, unpack. */
    XMEMCPY(bwork, r, (size_t)qBytes);
    wc_mceliece_apply_benes_neon(bwork, condp, 1, benes);
    wc_mceliece_syndrome_neon((word64*)srecv, bwork, (word64*)einvbs,
        (word64*)scaled, ksc);
    nv = tt & ~7;
    if (nv > 0) {
        wc_mceliece_synd_unpack_neon(s, (word64*)srecv, nv);
    }
    for (i = nv; i < tt; i++) {
        mc_gf x = 0;
        int wr = i >> 6;
        int br = i & 63;

        for (k = 0; k < MCELIECE_M; k++) {
            x |= (mc_gf)(((srecv[k][wr] >> br) & 1) << k);
        }
        s[i] = x;
    }

    /* 4. Berlekamp-Massey (full asm; carves tmp/c/bp from ksc). */
    mc_set_gf_pmull();  /* pick PMULL vs bitsliced GF from CPU features */
    wc_mceliece_berlekamp_massey_neon(locator, s, t, ksc);

    /* 5. Roots = all-zero FFT lanes of the locator, marked into bwork. */
    for (i = 0; i < 128; i++) {
        fftw[i] = (i <= t) ? (mc_gf)locator[i] : 0;
    }
    wc_mceliece_bs_poly_neon((word64*)poly, fftw);
#if defined(__aarch64__)
    wc_mceliece_radix_conv_neon((word64*)poly, ksc);
#else
    wc_mceliece_radix_conv_neon((word64*)poly);
#endif
    wc_mceliece_fft_fwd_butterflies_neon((word64*)ffts, (word64*)poly, mono,
        ksc);
    for (i = 0; i < 32; i++) {
        word64 orv[4];

        orv[0] = 0;
        orv[1] = 0;
        orv[2] = 0;
        orv[3] = 0;
        for (k = 0; k < MCELIECE_M; k++) {
            orv[0] |= ffts[i][k][0];
            orv[1] |= ffts[i][k][1];
            orv[2] |= ffts[i][k][2];
            orv[3] |= ffts[i][k][3];
        }
        orv[0] = ~orv[0];
        orv[1] = ~orv[1];
        orv[2] = ~orv[2];
        orv[3] = ~orv[3];
        wc_mceliece_store8(bwork + i * 32 +  0, orv[0]);
        wc_mceliece_store8(bwork + i * 32 +  8, orv[1]);
        wc_mceliece_store8(bwork + i * 32 + 16, orv[2]);
        wc_mceliece_store8(bwork + i * 32 + 24, orv[3]);
    }

    /* 6. Re-encode check syndrome (bitsliced) from the root field-mask. */
    wc_mceliece_syndrome_neon((word64*)sreenc, bwork, (word64*)einvbs,
        (word64*)scaled, ksc);

    /* 7. Roots -> support-order error via Benes(rev=0); popcount the weight. */
    wc_mceliece_apply_benes_neon(bwork, condp, 0, benes);
    XMEMCPY(e, bwork, (size_t)p->sBytes);
    if (n & 0x7) {
        e[p->sBytes - 1] &= (byte)((1 << (n & 0x7)) - 1);
    }
    for (i = 0; i < (int)p->sBytes; i++) {
        byte v = e[i];

        v = (byte)(v - ((v >> 1) & 0x55));
        v = (byte)((v & 0x33) + ((v >> 2) & 0x33));
        v = (byte)((v + (v >> 4)) & 0x0F);
        w += v;
    }

    /* 8. Moment-mask compare of received vs re-encoded syndromes. */
    for (i = 0; i < 4; i++) {
        int bits = tt - i * 64;

        if (bits >= 64) {
            mmask[i] = ~(word64)0;
        }
        else if (bits <= 0) {
            mmask[i] = 0;
        }
        else {
            mmask[i] = ((word64)1 << bits) - 1;
        }
    }
    for (k = 0; k < MCELIECE_M; k++) {
        chk |= (srecv[k][0] ^ sreenc[k][0]) & mmask[0];
        chk |= (srecv[k][1] ^ sreenc[k][1]) & mmask[1];
        chk |= (srecv[k][2] ^ sreenc[k][2]) & mmask[2];
        chk |= (srecv[k][3] ^ sreenc[k][3]) & mmask[3];
    }
    /* Reduce the 64-bit mismatch accumulator to 0 or 1 in bit 0. A plain
     * 16-bit fold could leave a mismatch in bit 15, which would defeat the
     * (check - 1) >> 15 zero-test below and report a failed decode as success,
     * bypassing implicit rejection. */
    chk |= chk >> 32;
    chk |= chk >> 16;
    chk |= chk >> 8;
    chk |= chk >> 4;
    chk |= chk >> 2;
    chk |= chk >> 1;
    sfail |= (word16)(chk & 1);

    check = (word16)w;
    check ^= (word16)t;
    check |= sfail;
    check = (word16)(check - 1);
    check >>= 15;
    ret = ((int)check - 1) & MCELIECE_DECODE_FAIL;

    return ret;
}
#endif /* MC_HAVE_DECODE_NEON */

#endif /* WOLFSSL_MCELIECE_NO_DECAPSULATE */
#endif /* MC_HAVE_AFF_FFT */


#ifndef WOLFSSL_MCELIECE_NO_MAKE_KEY
/* Generate a Classic McEliece key pair (draft section 8.3, SeededKeyGen):
 * expand the seed delta with SHAKE256 into the field ordering, the irreducible
 * Goppa polynomial and the rejection-sampling randomness, then run one key
 * generation attempt, deriving a fresh seed and retrying on rejection until a
 * valid key is produced. The public key is written to pk and the private key
 * (delta, s, the control bits and g) to sk. Returns 0 on success or a negative
 * error code.
 *
 * Steps:
 *  1. Select the key-generation implementation (SIMD level, else portable C).
 *  2. SeededKeyGen: derive r = SHAKE256(seed), parse the polynomial and field
 *     ordering, run keygen, and retry with a fresh seed on rejection.
 *  3. Append the implicit-rejection string s and the pivot positions to sk.
 *
 * @param  [in]   p        Parameter set.
 * @param  [in]   shake    SHAKE256 object used to expand delta.
 * @param  [in]   delta    Key seed (MCELIECE_SEED_SZ bytes).
 * @param  [out]  pk       Public key (params->pubSz bytes).
 * @param  [out]  sk       Private key (params->privSz bytes).
 * @param  [in]   scratch  Keygen scratch (wc_mceliece_keygen_scratch_sz()
 *                         bytes).
 * @return  0 on success.
 * @return  A negative error code otherwise.
 */
int wc_mceliece_keypair(const McElieceParams* p, wc_Shake* shake,
    const byte* delta, byte* pk, byte* sk, byte* scratch)
{
    int ret = 0;
    int i;
    const int t = p->t;
    const word32 permBytes = (word32)MC_Q * 4;
    const word32 rlen = p->sBytes + permBytes + (word32)(t * 2) +
        MCELIECE_SEED_SZ;
    byte seed[1 + MCELIECE_SEED_SZ];
    McKgBufs kb;
    byte* r;
    word32* perm;
    mc_gf* f;
    word64 pivots = 0;
    byte* rp;
    byte* skp;
    int done = 0;
    McBsBufs bsbufs;

    wc_mceliece_kg_layout(p, scratch, &kb, &bsbufs);
    /* Build the systematic matrix directly in the (enlarged) pk buffer;
     * wc_mceliece_pk_gen compacts T to the front of pk in place at the end.
     * Used by both the C and assembly keygen paths. */
    kb.mat = pk;
    r = kb.r;
    perm = kb.perm;
    f = kb.f;

    seed[0] = 64;
    XMEMCPY(seed + 1, delta, MCELIECE_SEED_SZ);

    /* 1. SeededKeyGen: derive r = SHAKE256(seed), parse the polynomial and
     *    field ordering, run keygen, retry with a fresh seed on rejection. */
    while ((ret == 0) && (!done)) {
        int kret = 2;

        /* E = PRG(seed) has layout (draft SeededKeyGen):
         *   s (first n bits) || field-ordering (Sigma2*q) || g (Sigma1*t) ||
         *   delta' (last MCELIECE_SEED_SZ bytes).
         * delta' is the trailing seed (read separately below); the irr poly,
         * field ordering and s are read by walking rp DOWN from the start of
         * delta' (r + rlen - MCELIECE_SEED_SZ), so s lands at offset 0 - the
         * first n bits, as required. */
        rp = r + rlen - MCELIECE_SEED_SZ;
        skp = sk;

        /* r = PRG(seed) = SHAKE256(64 || delta). */
        ret = wc_mceliece_shake256(shake, seed, sizeof(seed), r, rlen);
        if (ret != 0) {
            break;
        }

        /* Store current delta and reserve the 8-byte pivot field. */
        XMEMCPY(skp, seed + 1, MCELIECE_SEED_SZ);
        skp += MCELIECE_SEED_SZ + MCELIECE_C_SZ;
        /* Next seed is the trailing 32 bytes of r (used only on retry). */
        XMEMCPY(seed + 1, r + rlen - MCELIECE_SEED_SZ, MCELIECE_SEED_SZ);

        /* Irreducible polynomial input from the next block of r. */
        rp -= (word32)(t * 2);
        for (i = 0; i < t; i++) {
            f[i] = wc_mceliece_load_gf(rp + i * 2);
        }

        /* Field ordering from the next block of r. */
        rp -= permBytes;
        for (i = 0; i < MC_Q; i++) {
            perm[i] = wc_mceliece_load4(rp + i * 4);
        }

        pivots = 0xFFFFFFFF;
        kret = wc_mceliece_keygen(p, pk, skp, &kb, &pivots, &bsbufs);

        /* All keygen implementations share one return convention: 1 = retry
         * with a fresh SHAKE-derived seed, 0 = success, else a hard error. */
        if (kret == 1) {
            continue;
        }
        if (kret != 0) {
            /* Propagate the real hard-error code (e.g. MEMORY_E) rather than
             * masking every failure as BAD_STATE_E. */
            ret = kret;
            break;
        }
        skp += p->irrBytes + MCELIECE_COND_BYTES;

        /* 3. Append the implicit-rejection string s and the pivots to sk. */
        rp -= p->sBytes;
        XMEMCPY(skp, rp, p->sBytes);

        wc_mceliece_store8(sk + MCELIECE_SEED_SZ, pivots);

        done = 1;
    }

    ForceZero(seed, sizeof(seed));

    return ret;
}
#endif /* WOLFSSL_MCELIECE_NO_MAKE_KEY */

#ifndef WOLFSSL_MCELIECE_NO_ENCAPSULATE
/* Encapsulation dispatcher (draft section 8.5, Encode): run the syndrome
 * encode with the best available implementation - the AVX512/AVX2 asm or the
 * NEON encode driver under one vector-register window, else the portable C
 * encode. Draws the fixed-weight-t error vector e from rand and computes the
 * syndrome C0 = He (see the header for the e/c0 outputs). Returns 0 on success,
 * MCELIECE_RAND_DEPLETED when rand is exhausted, or a negative error code.
 *
 * @param  [in]   p        Parameter set.
 * @param  [in]   pk       Public key.
 * @param  [in]   rand     Randomness for FixedWeight sampling.
 * @param  [in]   randLen  Length of rand in bytes.
 * @param  [out]  e        Weight-t error vector (params->sBytes bytes).
 * @param  [out]  c0       Syndrome C0 = He (params->syndBytes bytes).
 * @param  [in]   scratch  Encapsulation scratch buffer.
 * @return  0 on success.
 * @return  MCELIECE_RAND_DEPLETED if rand is exhausted.
 * @return  A negative error code otherwise.
 */
int wc_mceliece_encap(const McElieceParams* p, const byte* pk, const byte* rand,
    word32 randLen, byte* e, byte* c0, byte* scratch)
{
    int ret = 0;
    int done = 0;

#if defined(MC_HAVE_ENCAP_ASM) || defined(MC_HAVE_ENCAP_NEON)
    if (SAVE_VECTOR_REGISTERS2() == 0) {
#endif
#ifdef MC_HAVE_ENCAP_ASM
#ifndef NO_AVX512_SUPPORT
        if (MC_HAVE_AVX512_HW(mc_cpuid_flags)) {
            ret = wc_mceliece_encap_drv_avx512(p, pk, rand, randLen, e, c0,
                scratch);
            done = 1;
        }
        else
#endif
#ifndef NO_AVX2_SUPPORT
        if (IS_INTEL_AVX2(mc_cpuid_flags)) {
            ret = wc_mceliece_encap_drv_avx2(p, pk, rand, randLen, e, c0,
                scratch);
            done = 1;
        }
#endif
#endif /* MC_HAVE_ENCAP_ASM */
#ifdef MC_HAVE_ENCAP_NEON
        if (MC_NEON_RUNTIME_OK) {
            ret = wc_mceliece_encap_drv_neon(p, pk, rand, randLen, e, c0,
                scratch);
            done = 1;
        }
#endif
#if defined(MC_HAVE_ENCAP_ASM) || defined(MC_HAVE_ENCAP_NEON)
        RESTORE_VECTOR_REGISTERS();
    }
#endif
    if (!done) {
        ret = wc_mceliece_encap_c(p, pk, rand, randLen, e, c0, scratch);
    }

    return ret;
}
#endif /* WOLFSSL_MCELIECE_NO_ENCAPSULATE */

#ifndef WOLFSSL_MCELIECE_NO_DECAPSULATE
/* Decapsulation dispatcher (draft section 8.6, Decode): recover the weight-t
 * error vector e from the syndrome C0 with the best available implementation -
 * the GFNI/AVX512/AVX2 asm driver or the NEON driver under one vector-register
 * window, else the portable C decode. Returns 0 on success (e holds the decoded
 * error), MCELIECE_DECODE_FAIL on a genuine decoding failure (caller applies
 * implicit rejection), or a negative hard error.
 *
 * @param  [in]   p        Parameter set.
 * @param  [in]   sk       Private key.
 * @param  [in]   c0       Received syndrome (ciphertext).
 * @param  [out]  e        Decoded weight-t error vector (params->sBytes bytes).
 * @param  [in]   scratch  Decode scratch buffer.
 * @return  0 on success.
 * @return  MCELIECE_DECODE_FAIL on a genuine decoding failure.
 * @return  A negative hard error otherwise.
 */
int wc_mceliece_decode(const McElieceParams* p, const byte* sk, const byte* c0,
    byte* e, byte* scratch)
{
    int ret = 0;
    int done = 0;

#ifdef MC_HAVE_DECODE_BS_ASM
    if (SAVE_VECTOR_REGISTERS2() == 0) {
#ifndef NO_AVX512_SUPPORT
        if (MC_HAVE_GFNI_HW(mc_cpuid_flags)) {
            ret = wc_mceliece_decode_drv_gfni(p, sk, c0, e, scratch);
            done = 1;
        }
        else if (MC_HAVE_AVX512_HW(mc_cpuid_flags)) {
            ret = wc_mceliece_decode_drv_avx512(p, sk, c0, e, scratch);
            done = 1;
        }
#endif
        if ((!done) && IS_INTEL_AVX2(mc_cpuid_flags)) {
            ret = wc_mceliece_decode_drv_avx2(p, sk, c0, e, scratch);
            done = 1;
        }
        RESTORE_VECTOR_REGISTERS();
    }
#endif
#ifdef MC_HAVE_DECODE_NEON
    if ((!done) && MC_NEON_RUNTIME_OK) {
        /* One vector-register window over the whole decode; the driver calls
         * the raw NEON kernels inside it (matches x86 dispatch above). */
        if (SAVE_VECTOR_REGISTERS2() == 0) {
            ret = wc_mceliece_decode_drv_neon(p, sk, c0, e, scratch);
            RESTORE_VECTOR_REGISTERS();
            done = 1;
        }
    }
#endif
    if (!done) {
        ret = wc_mceliece_decode_c(p, sk, c0, e, scratch);
    }

    return ret;
}
#endif /* WOLFSSL_MCELIECE_NO_DECAPSULATE */
#endif /* WOLFSSL_HAVE_MCELIECE */
