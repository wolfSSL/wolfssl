/* wc_frodokem_intrin.c */
/*
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

#define _WC_BUILDING_WC_FRODOKEM_INTRIN_C

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef WOLFSSL_X86_64_BUILD

#ifdef _MSC_VER
    /* _umul128, __popcnt and _BitScanReverse64 live here. */
    #include <intrin.h>
#endif
#include <immintrin.h>
#include <wolfssl/wolfcrypt/wc_frodokem.h>

#if !defined(__GNUC__) && !defined(__clang__) && !defined(_MSC_VER)
    #error "Generated intrinsics need GCC, Clang or MSVC."
#endif

#ifdef _MSC_VER
    /* MSVC has no per-function ISA attribute and needs none: it accepts
     * any intrinsic whatever /arch says and emits the instruction, so
     * the SSE2, AVX2 and AVX-512 variants below all compile from one
     * translation unit built at the default /arch.  That is the same
     * property the target attribute buys on GCC, arrived at from the
     * other direction - which is why the wide-ISA guard further down
     * still applies: /arch:AVX2 lets MSVC promote the SSE2 variants to
     * VEX encodings, and one picked for a pre-AVX CPU would trap. */
    #define WC_X64I_TARGET(isa) /* null expansion */
    #define WC_X64I_UNUSED
#else
/* Select the ISA for one function only, so variants for different ISAs
 * can live in one translation unit compiled at baseline -march and
 * still be picked at run time by the cpuid dispatch. */
#define WC_X64I_TARGET(isa)     __attribute__((target(isa)))
#define WC_X64I_UNUSED          __attribute__((unused))
#endif

/* 64x64 -> 128 multiply.  GCC and Clang have a 128-bit integer type;
 * MSVC has an intrinsic that returns the halves separately.  Written as
 * one macro so the generator emits the same statement either way.  The
 * destination may name the same variable as an operand - MUL writes
 * RDX:RAX and reads RAX - so both forms read the operands before
 * assigning. */
#ifdef _MSC_VER
    #define WC_X64I_MUL128(lo, hi, a, b)                               \
        do {                                                           \
            word64 wc_h_;                                              \
            word64 wc_l_ = (word64)_umul128((a), (b), &wc_h_);         \
            (lo) = wc_l_; (hi) = wc_h_;                                \
        } while (0)
#else
    #define WC_X64I_MUL128(lo, hi, a, b)                               \
        do {                                                           \
            __uint128_t wc_p_ = (__uint128_t)(a) * (b);                \
            (lo) = (word64)wc_p_;                                      \
            (hi) = (word64)(wc_p_ >> 64);                              \
        } while (0)
#endif

/* Byte reversal, and the 128/64 unsigned divide SP's division step
 * needs.  The divide has no portable spelling at all: GCC and Clang
 * take it through __uint128_t, MSVC has _udiv128.  Neither traps the
 * quotient overflow that DIV raises - the callers keep the divisor
 * above the high half, which is what makes the instruction safe there
 * too. */
#ifdef _MSC_VER
    #define WC_X64I_BSWAP64(x)   ((word64)_byteswap_uint64((x)))
    #define WC_X64I_DIV128(q, r, hi, lo, d)                            \
        do {                                                           \
            word64 wc_r_;                                              \
            word64 wc_q_ = _udiv128((hi), (lo), (d), &wc_r_);          \
            (q) = wc_q_; (r) = wc_r_;                                  \
        } while (0)
#else
    #define WC_X64I_BSWAP64(x)   ((word64)__builtin_bswap64((x)))
    #define WC_X64I_DIV128(q, r, hi, lo, d)                            \
        do {                                                           \
            __uint128_t wc_n_ = ((__uint128_t)(hi) << 64) | (lo);      \
            word64 wc_d_ = (d);                                        \
            word64 wc_q_ = (word64)(wc_n_ / wc_d_);                    \
            word64 wc_r_ = (word64)(wc_n_ % wc_d_);                    \
            (q) = wc_q_; (r) = wc_r_;                                  \
        } while (0)
#endif

/* Bit counting: the two compilers spell these differently and MSVC's
 * scan intrinsics report through an out-parameter.  BSR is only reached
 * with a non-zero source (the generator says so where it emits it), so
 * the zero case need not be defined here either. */
#ifdef _MSC_VER
    #define WC_X64I_POPCNT32(x)  ((word32)__popcnt((unsigned int)(x)))
    #define WC_X64I_POPCNT64(x)  ((word64)__popcnt64((unsigned __int64)(x)))
    #define WC_X64I_BSR64(x)     wc_x64i_bsr64(x)
    static WC_X64I_UNUSED word64 wc_x64i_bsr64(word64 x)
    {
        unsigned long i;
        _BitScanReverse64(&i, (unsigned __int64)x);
        return (word64)i;
    }
#else
    #define WC_X64I_POPCNT32(x)                                        \
        ((word32)__builtin_popcount((unsigned int)(x)))
    #define WC_X64I_POPCNT64(x)                                        \
        ((word64)__builtin_popcountll((unsigned long long)(x)))
    #define WC_X64I_BSR64(x)                                           \
        ((word64)(63 - __builtin_clzll((unsigned long long)(x))))
#endif

/* The attribute ADDS to the command line rather than replacing it, so a
 * build that enables a wider ISA globally lets EVERY routine here use
 * it - and one the cpuid dispatch picked for, say, an AVX2 CPU would
 * then execute AVX-512 encodings and trap.  The assembly this replaces
 * cannot be promoted that way, so refuse rather than silently build it.
 * Narrowing the attributes instead is not possible: an attribute set
 * smaller than the command line stops the always_inline intrinsics in
 * the headers from inlining at all.  Define the escape hatch only for a
 * build that will run on the machine it was compiled for. */
#if (defined(__AVX2__) || defined(__AVX512F__)) && \
    !defined(WOLFSSL_X86_64_INTRIN_ALLOW_WIDE_ISA)
    /* Override with WOLFSSL_X86_64_INTRIN_ALLOW_WIDE_ISA only for a
     * binary that will run on the machine it was built on. */
    #error "wide -march breaks the cpuid dispatch - see above"
#endif

/* GCC gained _mm256_zextsi128_si256 in 10.x; earlier releases express the
 * same "128-bit VEX write zeroes the upper lanes" rule this way. */
#if defined(__GNUC__) && !defined(__clang__) && (__GNUC__ < 10)
    #define _mm256_zextsi128_si256(a)   \
        _mm256_insertf128_si256(_mm256_setzero_si256(), (a), 0)
#endif

/* A register holding an address is modelled as a word64, so a memory
 * operand is that value cast back to a byte pointer plus the
 * displacement.  Loads go through the const forms; the element type of
 * every object addressed this way matches the access width, which is
 * what keeps the accesses free of aliasing violations. */
#define WC_PR(b, o)     ((const byte*)(size_t)(b) + (o))
#define WC_PW(b, o)     ((byte*)(size_t)(b) + (o))
#define WC_L8(b, o)     (*(const byte*)WC_PR(b, o))
#define WC_L16(b, o)    (*(const word16*)WC_PR(b, o))
#define WC_L32(b, o)    (*(const word32*)WC_PR(b, o))
#define WC_L64(b, o)    (*(const word64*)WC_PR(b, o))
#define WC_S8(b, o)     (*(byte*)WC_PW(b, o))
#define WC_S16(b, o)    (*(word16*)WC_PW(b, o))
#define WC_S32(b, o)    (*(word32*)WC_PW(b, o))
#define WC_S64(b, o)    (*(word64*)WC_PW(b, o))

/* A stack frame slot is written at one width and read at another, so
 * the storage's declared type has to admit both: a union member is the
 * access the aliasing rules allow. */
typedef union {
    byte   b[8];
    word16 w16[4];
    word32 w32[2];
    word64 w64;
} WC_X64I_SLOT;

#ifndef HAVE_INTEL_AVX1
#define HAVE_INTEL_AVX1
#endif /* HAVE_INTEL_AVX1 */
#ifndef NO_AVX2_SUPPORT
#ifndef HAVE_INTEL_AVX2
#define HAVE_INTEL_AVX2
#endif /* HAVE_INTEL_AVX2 */
#endif /* NO_AVX2_SUPPORT */
#ifndef NO_VAES_SUPPORT
#ifndef HAVE_INTEL_VAES
#define HAVE_INTEL_VAES
#endif /* HAVE_INTEL_VAES */
#endif /* NO_VAES_SUPPORT */
#ifndef NO_AVX512_SUPPORT
#ifndef HAVE_INTEL_AVX512
#define HAVE_INTEL_AVX512
#endif /* HAVE_INTEL_AVX512 */
#endif /* NO_AVX512_SUPPORT */
#ifndef HAVE_INTEL_SSSE3
#define HAVE_INTEL_SSSE3
#endif /* HAVE_INTEL_SSSE3 */
#ifndef NO_AVX512_SUPPORT
#ifndef NO_AVX512_IFMA_SUPPORT
#ifndef HAVE_INTEL_AVX512_IFMA
#define HAVE_INTEL_AVX512_IFMA
#endif /* HAVE_INTEL_AVX512_IFMA */
#endif /* NO_AVX512_IFMA_SUPPORT */
#ifndef NO_AVX512_VBMI_SUPPORT
#ifndef HAVE_INTEL_AVX512_VBMI
#define HAVE_INTEL_AVX512_VBMI
#endif /* HAVE_INTEL_AVX512_VBMI */
#endif /* NO_AVX512_VBMI_SUPPORT */
#ifndef NO_AVX512_VBMI2_SUPPORT
#ifndef HAVE_INTEL_AVX512_VBMI2
#define HAVE_INTEL_AVX512_VBMI2
#endif /* HAVE_INTEL_AVX512_VBMI2 */
#endif /* NO_AVX512_VBMI2_SUPPORT */
#endif /* NO_AVX512_SUPPORT */

#ifdef WOLFSSL_HAVE_FRODOKEM
#ifdef HAVE_INTEL_AVX2
extern WOLFSSL_LOCAL void frodokem_sa_accum_avx2(word16* out, const word16* s,
    const word16* row, int j, int n);
extern WOLFSSL_LOCAL void frodokem_as_accum_avx2(word16* out, const word16* s,
    const word16* row, int i, int n);
extern WOLFSSL_LOCAL void frodokem_mul_bs_avx2(word16* out, const word16* b,
    const word16* s, int n, int qmask);
extern WOLFSSL_LOCAL void frodokem_mul_add_sb_plus_e_avx2(word16* out,
    const word16* b, const word16* s, int n, int qmask);
extern WOLFSSL_LOCAL void frodokem_add_avx2(word16* a, const word16* b,
    int qmask);
extern WOLFSSL_LOCAL void frodokem_a_rows_reduce_avx2(word16* rows, word32 cnt,
    int qmask);
extern WOLFSSL_LOCAL void frodokem_sample_avx2(word16* mat, int cnt,
    const word16* cdf, int cdflen);
extern WOLFSSL_LOCAL void frodokem_gen_a_rows_aes_avx2(byte* in, word16* out,
    const byte* ks, int i, int cnt, int n, int qmask);
extern WOLFSSL_LOCAL void frodokem_gen_a_rows_aes_aesni(byte* in, word16* out,
    const byte* ks, int i, int cnt, int n, int qmask);
#endif
#ifdef HAVE_INTEL_AVX512
extern WOLFSSL_LOCAL void frodokem_sa_accum_avx512(word16* out, const word16* s,
    const word16* row, int j, int n);
extern WOLFSSL_LOCAL void frodokem_as_accum_avx512(word16* out, const word16* s,
    const word16* row, int i, int n);
extern WOLFSSL_LOCAL void frodokem_mul_bs_avx512(word16* out, const word16* b,
    const word16* s, int n, int qmask);
extern WOLFSSL_LOCAL void frodokem_mul_add_sb_plus_e_avx512(word16* out,
    const word16* b, const word16* s, int n, int qmask);
extern WOLFSSL_LOCAL void frodokem_add_avx512(word16* a, const word16* b,
    int qmask);
extern WOLFSSL_LOCAL void frodokem_sample_avx512(word16* mat, int cnt,
    const word16* cdf, int cdflen);
extern WOLFSSL_LOCAL void frodokem_gen_a_rows_aes_avx512(byte* in, word16* out,
    const byte* ks, int i, int cnt, int n, int qmask);

#endif
#endif
#ifdef WOLFSSL_HAVE_FRODOKEM
#ifdef HAVE_INTEL_AVX2
WC_X64I_TARGET("avx2")
WOLFSSL_LOCAL void frodokem_sa_accum_avx2(word16* out, const word16* s,
    const word16* row, int j, int n)
{
    word64 rdi, rsi, rdx, rcx, r8, rax, r9, r10, r11, r13, r12 = 0;
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y4 = _mm256_setzero_si256(), y5 = _mm256_setzero_si256();

    rdi = (word64)(size_t)out;
    rsi = (word64)(size_t)s;
    rdx = (word64)(size_t)row;
    rcx = (word64)(word32)j;
    r8 = (word64)(word32)n;

    rcx = (word64)((word64)(sword64)(sword32)(word32)rcx);
    rcx = (word64)(rcx << 1);
    rsi = (word64)(rsi + rcx);
    rax = (word64)((word64)(sword64)(sword32)(word32)r8);
    rax = (word64)(rax << 1);
    r9 = (word64)(rdx);
    r9 = (word64)(r9 + rax);
    r10 = (word64)(r9);
    r10 = (word64)(r10 + rax);
    r11 = (word64)(r10);
    r11 = (word64)(r11 + rax);
    r13 = (word64)(8);
L_frodokem_sa_accum_avx2_i:
    y0 = _mm256_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(rsi,
        0)));
    y1 = _mm256_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(rsi,
        2)));
    y2 = _mm256_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(rsi,
        4)));
    y3 = _mm256_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(rsi,
        6)));
    r12 = (word64)(0);
L_frodokem_sa_accum_avx2_k:
    y4 = _mm256_loadu_si256((const __m256i*)WC_PR(rdi, r12));
    y5 = _mm256_mullo_epi16(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rdx,
        r12)));
    y4 = _mm256_add_epi16(y4, y5);
    y5 = _mm256_mullo_epi16(y1, _mm256_loadu_si256((const __m256i*)WC_PR(r9,
        r12)));
    y4 = _mm256_add_epi16(y4, y5);
    y5 = _mm256_mullo_epi16(y2, _mm256_loadu_si256((const __m256i*)WC_PR(r10,
        r12)));
    y4 = _mm256_add_epi16(y4, y5);
    y5 = _mm256_mullo_epi16(y3, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        r12)));
    y4 = _mm256_add_epi16(y4, y5);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, r12), y4);
    r12 = (word64)(r12 + 0x20);
    if ((sword64)(r12) < (sword64)(rax)) {
        goto L_frodokem_sa_accum_avx2_k;
    }
    rdi = (word64)(rdi + rax);
    rsi = (word64)(rsi + rax);
    r13 = (word64)(r13 - 1);
    if ((r13) != (0)) {
        goto L_frodokem_sa_accum_avx2_i;
    }
}

WC_X64I_TARGET("avx2")
WOLFSSL_LOCAL void frodokem_as_accum_avx2(word16* out, const word16* s,
    const word16* row, int i, int n)
{
    word64 rdi, rsi, rdx, rcx, r8, rax, r9, r10, r11, r12, r13, r14, r15, rbp,
           rbx = 0;
    __m128i x9 = _mm_setzero_si128(), x11 = _mm_setzero_si128(),
            x12 = _mm_setzero_si128();
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y4 = _mm256_setzero_si256(), y5 = _mm256_setzero_si256(),
            y6 = _mm256_setzero_si256(), y7 = _mm256_setzero_si256(),
            y8 = _mm256_setzero_si256(), y10 = _mm256_setzero_si256();

    rdi = (word64)(size_t)out;
    rsi = (word64)(size_t)s;
    rdx = (word64)(size_t)row;
    rcx = (word64)(word32)i;
    r8 = (word64)(word32)n;

    rcx = (word64)((word64)(sword64)(sword32)(word32)rcx);
    rcx = (word64)(rcx << 4);
    rdi = (word64)(rdi + rcx);
    rax = (word64)((word64)(sword64)(sword32)(word32)r8);
    rax = (word64)(rax << 1);
    r9 = (word64)(rsi);
    r9 = (word64)(r9 + rax);
    r10 = (word64)(r9);
    r10 = (word64)(r10 + rax);
    r11 = (word64)(r10);
    r11 = (word64)(r11 + rax);
    r12 = (word64)(r11);
    r12 = (word64)(r12 + rax);
    r13 = (word64)(r12);
    r13 = (word64)(r13 + rax);
    r14 = (word64)(r13);
    r14 = (word64)(r14 + rax);
    r15 = (word64)(r14);
    r15 = (word64)(r15 + rax);
    rbp = (word64)(4);
    x12 = _mm_cmpeq_epi32(x12, x12);
    x12 = _mm_srli_epi32(x12, 16);
L_frodokem_as_accum_avx2_r:
    y0 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    rbx = (word64)(0);
L_frodokem_as_accum_avx2_j:
    y8 = _mm256_loadu_si256((const __m256i*)WC_PR(rdx, rbx));
    y10 = _mm256_madd_epi16(y8, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        rbx)));
    y0 = _mm256_add_epi32(y0, y10);
    y10 = _mm256_madd_epi16(y8, _mm256_loadu_si256((const __m256i*)WC_PR(r9,
        rbx)));
    y1 = _mm256_add_epi32(y1, y10);
    y10 = _mm256_madd_epi16(y8, _mm256_loadu_si256((const __m256i*)WC_PR(r10,
        rbx)));
    y2 = _mm256_add_epi32(y2, y10);
    y10 = _mm256_madd_epi16(y8, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        rbx)));
    y3 = _mm256_add_epi32(y3, y10);
    y10 = _mm256_madd_epi16(y8, _mm256_loadu_si256((const __m256i*)WC_PR(r12,
        rbx)));
    y4 = _mm256_add_epi32(y4, y10);
    y10 = _mm256_madd_epi16(y8, _mm256_loadu_si256((const __m256i*)WC_PR(r13,
        rbx)));
    y5 = _mm256_add_epi32(y5, y10);
    y10 = _mm256_madd_epi16(y8, _mm256_loadu_si256((const __m256i*)WC_PR(r14,
        rbx)));
    y6 = _mm256_add_epi32(y6, y10);
    y10 = _mm256_madd_epi16(y8, _mm256_loadu_si256((const __m256i*)WC_PR(r15,
        rbx)));
    y7 = _mm256_add_epi32(y7, y10);
    rbx = (word64)(rbx + 0x20);
    if ((sword64)(rbx) < (sword64)(rax)) {
        goto L_frodokem_as_accum_avx2_j;
    }
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y0, 1));
    y0 = _mm256_zextsi128_si256(_mm_add_epi32(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y1, 1));
    y1 = _mm256_zextsi128_si256(_mm_add_epi32(_mm256_castsi256_si128(y1),
        _mm256_castsi256_si128(y8)));
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y2, 1));
    y2 = _mm256_zextsi128_si256(_mm_add_epi32(_mm256_castsi256_si128(y2),
        _mm256_castsi256_si128(y8)));
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y3, 1));
    y3 = _mm256_zextsi128_si256(_mm_add_epi32(_mm256_castsi256_si128(y3),
        _mm256_castsi256_si128(y8)));
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y4, 1));
    y4 = _mm256_zextsi128_si256(_mm_add_epi32(_mm256_castsi256_si128(y4),
        _mm256_castsi256_si128(y8)));
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y5, 1));
    y5 = _mm256_zextsi128_si256(_mm_add_epi32(_mm256_castsi256_si128(y5),
        _mm256_castsi256_si128(y8)));
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y6, 1));
    y6 = _mm256_zextsi128_si256(_mm_add_epi32(_mm256_castsi256_si128(y6),
        _mm256_castsi256_si128(y8)));
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y7, 1));
    y7 = _mm256_zextsi128_si256(_mm_add_epi32(_mm256_castsi256_si128(y7),
        _mm256_castsi256_si128(y8)));
    y10 = _mm256_zextsi128_si256(_mm_hadd_epi32(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y1)));
    x11 = _mm_hadd_epi32(_mm256_castsi256_si128(y2), _mm256_castsi256_si128(
        y3));
    x9 = _mm_hadd_epi32(_mm256_castsi256_si128(y10), x11);
    y10 = _mm256_zextsi128_si256(_mm_hadd_epi32(_mm256_castsi256_si128(y4),
        _mm256_castsi256_si128(y5)));
    x11 = _mm_hadd_epi32(_mm256_castsi256_si128(y6), _mm256_castsi256_si128(
        y7));
    y10 = _mm256_zextsi128_si256(_mm_hadd_epi32(_mm256_castsi256_si128(y10),
        x11));
    x9 = _mm_and_si128(x9, x12);
    y10 = _mm256_zextsi128_si256(_mm_and_si128(_mm256_castsi256_si128(y10),
        x12));
    x9 = _mm_packus_epi32(x9, _mm256_castsi256_si128(y10));
    x9 = _mm_add_epi16(x9, _mm_loadu_si128((const __m128i*)WC_PR(rdi, 0)));
    _mm_storeu_si128((__m128i*)WC_PW(rdi, 0), x9);
    rdx = (word64)(rdx + rax);
    rdi = (word64)(rdi + 0x10);
    rbp = (word64)(rbp - 1);
    if ((rbp) != (0)) {
        goto L_frodokem_as_accum_avx2_r;
    }
}

WC_X64I_TARGET("avx2")
WOLFSSL_LOCAL void frodokem_mul_bs_avx2(word16* out, const word16* b,
    const word16* s, int n, int qmask)
{
    word64 rdi, rsi, rdx, rcx, r8, rax, r9, r10, r11, r12, r13, r14, r15, rbp,
           rbx = 0;
    __m128i x9 = _mm_setzero_si128(), x11 = _mm_setzero_si128(), x12;
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y4 = _mm256_setzero_si256(), y5 = _mm256_setzero_si256(),
            y6 = _mm256_setzero_si256(), y7 = _mm256_setzero_si256(),
            y8 = _mm256_setzero_si256(), y10 = _mm256_setzero_si256();

    rdi = (word64)(size_t)out;
    rsi = (word64)(size_t)b;
    rdx = (word64)(size_t)s;
    rcx = (word64)(word32)n;
    r8 = (word64)(word32)qmask;

    rax = (word64)((word64)(sword64)(sword32)(word32)rcx);
    rax = (word64)(rax << 1);
    r9 = (word64)(rdx);
    r9 = (word64)(r9 + rax);
    r10 = (word64)(r9);
    r10 = (word64)(r10 + rax);
    r11 = (word64)(r10);
    r11 = (word64)(r11 + rax);
    r12 = (word64)(r11);
    r12 = (word64)(r12 + rax);
    r13 = (word64)(r12);
    r13 = (word64)(r13 + rax);
    r14 = (word64)(r13);
    r14 = (word64)(r14 + rax);
    r15 = (word64)(r14);
    r15 = (word64)(r15 + rax);
    rbp = (word64)(8);
    x12 = _mm_cvtsi32_si128((int)(word32)r8);
    x12 = _mm_broadcastd_epi32(x12);
L_frodokem_mul_bs_avx2_r:
    y0 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    rbx = (word64)(0);
L_frodokem_mul_bs_avx2_j:
    y8 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, rbx));
    y10 = _mm256_madd_epi16(y8, _mm256_loadu_si256((const __m256i*)WC_PR(rdx,
        rbx)));
    y0 = _mm256_add_epi32(y0, y10);
    y10 = _mm256_madd_epi16(y8, _mm256_loadu_si256((const __m256i*)WC_PR(r9,
        rbx)));
    y1 = _mm256_add_epi32(y1, y10);
    y10 = _mm256_madd_epi16(y8, _mm256_loadu_si256((const __m256i*)WC_PR(r10,
        rbx)));
    y2 = _mm256_add_epi32(y2, y10);
    y10 = _mm256_madd_epi16(y8, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        rbx)));
    y3 = _mm256_add_epi32(y3, y10);
    y10 = _mm256_madd_epi16(y8, _mm256_loadu_si256((const __m256i*)WC_PR(r12,
        rbx)));
    y4 = _mm256_add_epi32(y4, y10);
    y10 = _mm256_madd_epi16(y8, _mm256_loadu_si256((const __m256i*)WC_PR(r13,
        rbx)));
    y5 = _mm256_add_epi32(y5, y10);
    y10 = _mm256_madd_epi16(y8, _mm256_loadu_si256((const __m256i*)WC_PR(r14,
        rbx)));
    y6 = _mm256_add_epi32(y6, y10);
    y10 = _mm256_madd_epi16(y8, _mm256_loadu_si256((const __m256i*)WC_PR(r15,
        rbx)));
    y7 = _mm256_add_epi32(y7, y10);
    rbx = (word64)(rbx + 0x20);
    if ((sword64)(rbx) < (sword64)(rax)) {
        goto L_frodokem_mul_bs_avx2_j;
    }
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y0, 1));
    y0 = _mm256_zextsi128_si256(_mm_add_epi32(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y1, 1));
    y1 = _mm256_zextsi128_si256(_mm_add_epi32(_mm256_castsi256_si128(y1),
        _mm256_castsi256_si128(y8)));
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y2, 1));
    y2 = _mm256_zextsi128_si256(_mm_add_epi32(_mm256_castsi256_si128(y2),
        _mm256_castsi256_si128(y8)));
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y3, 1));
    y3 = _mm256_zextsi128_si256(_mm_add_epi32(_mm256_castsi256_si128(y3),
        _mm256_castsi256_si128(y8)));
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y4, 1));
    y4 = _mm256_zextsi128_si256(_mm_add_epi32(_mm256_castsi256_si128(y4),
        _mm256_castsi256_si128(y8)));
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y5, 1));
    y5 = _mm256_zextsi128_si256(_mm_add_epi32(_mm256_castsi256_si128(y5),
        _mm256_castsi256_si128(y8)));
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y6, 1));
    y6 = _mm256_zextsi128_si256(_mm_add_epi32(_mm256_castsi256_si128(y6),
        _mm256_castsi256_si128(y8)));
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y7, 1));
    y7 = _mm256_zextsi128_si256(_mm_add_epi32(_mm256_castsi256_si128(y7),
        _mm256_castsi256_si128(y8)));
    y10 = _mm256_zextsi128_si256(_mm_hadd_epi32(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y1)));
    x11 = _mm_hadd_epi32(_mm256_castsi256_si128(y2), _mm256_castsi256_si128(
        y3));
    x9 = _mm_hadd_epi32(_mm256_castsi256_si128(y10), x11);
    y10 = _mm256_zextsi128_si256(_mm_hadd_epi32(_mm256_castsi256_si128(y4),
        _mm256_castsi256_si128(y5)));
    x11 = _mm_hadd_epi32(_mm256_castsi256_si128(y6), _mm256_castsi256_si128(
        y7));
    y10 = _mm256_zextsi128_si256(_mm_hadd_epi32(_mm256_castsi256_si128(y10),
        x11));
    x9 = _mm_and_si128(x9, x12);
    y10 = _mm256_zextsi128_si256(_mm_and_si128(_mm256_castsi256_si128(y10),
        x12));
    x9 = _mm_packus_epi32(x9, _mm256_castsi256_si128(y10));
    _mm_storeu_si128((__m128i*)WC_PW(rdi, 0), x9);
    rsi = (word64)(rsi + rax);
    rdi = (word64)(rdi + 0x10);
    rbp = (word64)(rbp - 1);
    if ((rbp) != (0)) {
        goto L_frodokem_mul_bs_avx2_r;
    }
}

WC_X64I_TARGET("avx2")
WOLFSSL_LOCAL void frodokem_mul_add_sb_plus_e_avx2(word16* out, const word16* b,
    const word16* s, int n, int qmask)
{
    word64 rdi, rsi, rdx, rcx, r8, rax, r9, r10, r11, r12, r13, r14, r15, rbx;
    __m256i y0, y1, y2, y3, y4 = _mm256_setzero_si256(),
            y5 = _mm256_setzero_si256(), y6 = _mm256_setzero_si256(), y7;

    rdi = (word64)(size_t)out;
    rsi = (word64)(size_t)b;
    rdx = (word64)(size_t)s;
    rcx = (word64)(word32)n;
    r8 = (word64)(word32)qmask;

    rax = (word64)((word64)(sword64)(sword32)(word32)rcx);
    rax = (word64)(rax << 1);
    r9 = (word64)(rdx);
    r9 = (word64)(r9 + rax);
    r10 = (word64)(r9);
    r10 = (word64)(r10 + rax);
    r11 = (word64)(r10);
    r11 = (word64)(r11 + rax);
    r12 = (word64)(r11);
    r12 = (word64)(r12 + rax);
    r13 = (word64)(r12);
    r13 = (word64)(r13 + rax);
    r14 = (word64)(r13);
    r14 = (word64)(r14 + rax);
    r15 = (word64)(r14);
    r15 = (word64)(r15 + rax);
    y7 = _mm256_zextsi128_si256(_mm_cvtsi32_si128((int)(word32)r8));
    y7 = _mm256_broadcastw_epi16(_mm256_castsi256_si128(y7));
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rdi, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rdi, 32));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rdi, 64));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(rdi, 96));
    rbx = (word64)(0);
L_frodokem_mul_add_sb_plus_e_avx2_j:
    y4 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rsi,
        0)));
    y5 = _mm256_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        rbx)));
    y6 = _mm256_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        rbx)));
    y5 = _mm256_inserti128_si256(y5, _mm256_castsi256_si128(y6), 1);
    y6 = _mm256_mullo_epi16(y5, y4);
    y0 = _mm256_add_epi16(y0, y6);
    y5 = _mm256_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        rbx)));
    y6 = _mm256_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(r11,
        rbx)));
    y5 = _mm256_inserti128_si256(y5, _mm256_castsi256_si128(y6), 1);
    y6 = _mm256_mullo_epi16(y5, y4);
    y1 = _mm256_add_epi16(y1, y6);
    y5 = _mm256_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(r12,
        rbx)));
    y6 = _mm256_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(r13,
        rbx)));
    y5 = _mm256_inserti128_si256(y5, _mm256_castsi256_si128(y6), 1);
    y6 = _mm256_mullo_epi16(y5, y4);
    y2 = _mm256_add_epi16(y2, y6);
    y5 = _mm256_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(r14,
        rbx)));
    y6 = _mm256_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(r15,
        rbx)));
    y5 = _mm256_inserti128_si256(y5, _mm256_castsi256_si128(y6), 1);
    y6 = _mm256_mullo_epi16(y5, y4);
    y3 = _mm256_add_epi16(y3, y6);
    rsi = (word64)(rsi + 0x10);
    rbx = (word64)(rbx + 2);
    if ((sword64)(rbx) < (sword64)(rax)) {
        goto L_frodokem_mul_add_sb_plus_e_avx2_j;
    }
    y0 = _mm256_and_si256(y0, y7);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 0), y0);
    y1 = _mm256_and_si256(y1, y7);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 32), y1);
    y2 = _mm256_and_si256(y2, y7);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 64), y2);
    y3 = _mm256_and_si256(y3, y7);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 96), y3);
}

WC_X64I_TARGET("avx2")
WOLFSSL_LOCAL void frodokem_add_avx2(word16* a, const word16* b, int qmask)
{
    word64 rdi, rsi, rdx;
    __m256i y0, y1, y2, y3, y4;

    rdi = (word64)(size_t)a;
    rsi = (word64)(size_t)b;
    rdx = (word64)(word32)qmask;

    y0 = _mm256_zextsi128_si256(_mm_cvtsi32_si128((int)(word32)rdx));
    y0 = _mm256_broadcastw_epi16(_mm256_castsi256_si128(y0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rdi, 0));
    y1 = _mm256_add_epi16(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        0)));
    y1 = _mm256_and_si256(y1, y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 0), y1);
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rdi, 32));
    y2 = _mm256_add_epi16(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        32)));
    y2 = _mm256_and_si256(y2, y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 32), y2);
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(rdi, 64));
    y3 = _mm256_add_epi16(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        64)));
    y3 = _mm256_and_si256(y3, y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 64), y3);
    y4 = _mm256_loadu_si256((const __m256i*)WC_PR(rdi, 96));
    y4 = _mm256_add_epi16(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        96)));
    y4 = _mm256_and_si256(y4, y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 96), y4);
}

WC_X64I_TARGET("avx2")
WOLFSSL_LOCAL void frodokem_a_rows_reduce_avx2(word16* rows, word32 cnt,
    int qmask)
{
    word64 rdi, rsi, rdx, rax, rcx = 0;
    __m256i y0, y1 = _mm256_setzero_si256();

    rdi = (word64)(size_t)rows;
    rsi = (word64)(word32)cnt;
    rdx = (word64)(word32)qmask;

    y0 = _mm256_zextsi128_si256(_mm_cvtsi32_si128((int)(word32)rdx));
    y0 = _mm256_broadcastw_epi16(_mm256_castsi256_si128(y0));
    rax = (word32)((word32)rsi);
L_frodokem_a_rows_reduce_avx2_blk:
    if ((sword64)(rax) < (sword64)(0x10)) {
        goto L_frodokem_a_rows_reduce_avx2_tail;
    }
    y1 = _mm256_and_si256(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rdi,
        0)));
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 0), y1);
    rdi = (word64)(rdi + 0x20);
    rax = (word64)(rax - 0x10);
    goto L_frodokem_a_rows_reduce_avx2_blk;
L_frodokem_a_rows_reduce_avx2_tail:
    if ((sword64)(rax) <= (sword64)(0)) {
        goto L_frodokem_a_rows_reduce_avx2_done;
    }
L_frodokem_a_rows_reduce_avx2_word:
    rcx = (word32)((word32)WC_L16(rdi, 0));
    rcx = (word32)((word32)rcx & (word32)rdx);
    WC_S16(rdi, 0) = (word16)((word16)rcx);
    rdi = (word64)(rdi + 2);
    rax = (word64)(rax - 1);
    if ((sword64)(rax) > (sword64)(0)) {
        goto L_frodokem_a_rows_reduce_avx2_word;
    }
L_frodokem_a_rows_reduce_avx2_done:
    ;
}

WC_X64I_TARGET("avx2")
WOLFSSL_LOCAL void frodokem_sample_avx2(word16* mat, int cnt, const word16* cdf,
    int cdflen)
{
    word64 rdi, rsi, rdx, rcx, rax, r8, r9 = 0, r10 = 0;
    __m256i y0 = _mm256_setzero_si256(), y1, y2 = _mm256_setzero_si256(),
            y3 = _mm256_setzero_si256(), y4 = _mm256_setzero_si256(),
            y5 = _mm256_setzero_si256(), y6 = _mm256_setzero_si256(),
            y7 = _mm256_setzero_si256();

    rdi = (word64)(size_t)mat;
    rsi = (word64)(word32)cnt;
    rdx = (word64)(size_t)cdf;
    rcx = (word64)(word32)cdflen;

    rax = (word64)((word64)(sword64)(sword32)(word32)rsi);
    rax = (word64)(rax << 1);
    y0 = _mm256_cmpeq_epi16(y0, y0);
    y0 = _mm256_srli_epi16(y0, 15);
    y1 = _mm256_setzero_si256();
    r8 = (word64)(0);
L_frodokem_sample_avx2_blk:
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rdi, r8));
    y3 = _mm256_srli_epi16(y2, 1);
    y4 = _mm256_and_si256(y2, y0);
    y5 = _mm256_setzero_si256();
    r9 = (word64)(rdx);
    r10 = (word32)((word32)rcx);
L_frodokem_sample_avx2_cdf:
    y6 = _mm256_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(r9, 0)));
    y6 = _mm256_sub_epi16(y6, y3);
    y6 = _mm256_srli_epi16(y6, 15);
    y5 = _mm256_add_epi16(y5, y6);
    r9 = (word64)(r9 + 2);
    r10 = (word64)(r10 - 1);
    if ((r10) != (0)) {
        goto L_frodokem_sample_avx2_cdf;
    }
    y7 = _mm256_sub_epi16(y1, y4);
    y5 = _mm256_xor_si256(y5, y7);
    y5 = _mm256_add_epi16(y5, y4);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, r8), y5);
    r8 = (word64)(r8 + 0x20);
    if ((sword64)(r8) < (sword64)(rax)) {
        goto L_frodokem_sample_avx2_blk;
    }
}

WC_X64I_TARGET("aes,vaes,avx2")
WOLFSSL_LOCAL void frodokem_gen_a_rows_aes_avx2(byte* in, word16* out,
    const byte* ks, int i, int cnt, int n, int qmask)
{
    word64 rdi, rsi, rdx, rcx, r8, r9, rax, r10, r11, r12, r14 = 0, r13 = 0,
           r15 = 0;
    __m256i y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10,
            y11 = _mm256_setzero_si256(), y12 = _mm256_setzero_si256(),
            y13 = _mm256_setzero_si256(), y14 = _mm256_setzero_si256(), y15;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(size_t)ks;
    rcx = (word64)(word32)i;
    r8 = (word64)(word32)cnt;
    r9 = (word64)(word32)n;
    rax = (word64)(word32)qmask;

    y0 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        0)));
    y1 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        16)));
    y2 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        32)));
    y3 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        48)));
    y4 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        64)));
    y5 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        80)));
    y6 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        96)));
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        112)));
    y8 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        128)));
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        144)));
    y10 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        160)));
    y15 = _mm256_zextsi128_si256(_mm_cvtsi32_si128((int)(word32)rax));
    y15 = _mm256_broadcastw_epi16(_mm256_castsi256_si128(y15));
    r10 = (word64)((word64)(sword64)(sword32)(word32)r9);
    r10 = (word64)(r10 >> 3);
    r11 = (word64)((word64)(sword64)(sword32)(word32)r8);
    rcx = (word64)((word64)(sword64)(sword32)(word32)rcx);
    r12 = (word64)(0);
L_frodokem_gen_a_rows_aes_avx2_row:
    r14 = (word64)(rcx);
    r14 = (word64)(r14 + r12);
    r13 = (word64)(0);
L_frodokem_gen_a_rows_aes_avx2_blk:
    r15 = (word64)(r13 + 8);
    if ((sword64)(r15) > (sword64)(r10)) {
        goto L_frodokem_gen_a_rows_aes_avx2_tail;
    }
    y11 = _mm256_zextsi128_si256(_mm_cvtsi32_si128((int)(word32)r14));
    r14 = (word64)(r14 + 0x80000);
    y0 = _mm256_zextsi128_si256(_mm_cvtsi32_si128((int)(word32)r14));
    r14 = (word64)(r14 + 0x80000);
    y11 = _mm256_inserti128_si256(y11, _mm256_castsi256_si128(y0), 1);
    y12 = _mm256_zextsi128_si256(_mm_cvtsi32_si128((int)(word32)r14));
    r14 = (word64)(r14 + 0x80000);
    y0 = _mm256_zextsi128_si256(_mm_cvtsi32_si128((int)(word32)r14));
    r14 = (word64)(r14 + 0x80000);
    y12 = _mm256_inserti128_si256(y12, _mm256_castsi256_si128(y0), 1);
    y13 = _mm256_zextsi128_si256(_mm_cvtsi32_si128((int)(word32)r14));
    r14 = (word64)(r14 + 0x80000);
    y0 = _mm256_zextsi128_si256(_mm_cvtsi32_si128((int)(word32)r14));
    r14 = (word64)(r14 + 0x80000);
    y13 = _mm256_inserti128_si256(y13, _mm256_castsi256_si128(y0), 1);
    y14 = _mm256_zextsi128_si256(_mm_cvtsi32_si128((int)(word32)r14));
    r14 = (word64)(r14 + 0x80000);
    y0 = _mm256_zextsi128_si256(_mm_cvtsi32_si128((int)(word32)r14));
    r14 = (word64)(r14 + 0x80000);
    y14 = _mm256_inserti128_si256(y14, _mm256_castsi256_si128(y0), 1);
    y0 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        0)));
    y11 = _mm256_xor_si256(y11, y0);
    y12 = _mm256_xor_si256(y12, y0);
    y13 = _mm256_xor_si256(y13, y0);
    y14 = _mm256_xor_si256(y14, y0);
    y11 = _mm256_aesenc_epi128(y11, y1);
    y12 = _mm256_aesenc_epi128(y12, y1);
    y13 = _mm256_aesenc_epi128(y13, y1);
    y14 = _mm256_aesenc_epi128(y14, y1);
    y11 = _mm256_aesenc_epi128(y11, y2);
    y12 = _mm256_aesenc_epi128(y12, y2);
    y13 = _mm256_aesenc_epi128(y13, y2);
    y14 = _mm256_aesenc_epi128(y14, y2);
    y11 = _mm256_aesenc_epi128(y11, y3);
    y12 = _mm256_aesenc_epi128(y12, y3);
    y13 = _mm256_aesenc_epi128(y13, y3);
    y14 = _mm256_aesenc_epi128(y14, y3);
    y11 = _mm256_aesenc_epi128(y11, y4);
    y12 = _mm256_aesenc_epi128(y12, y4);
    y13 = _mm256_aesenc_epi128(y13, y4);
    y14 = _mm256_aesenc_epi128(y14, y4);
    y11 = _mm256_aesenc_epi128(y11, y5);
    y12 = _mm256_aesenc_epi128(y12, y5);
    y13 = _mm256_aesenc_epi128(y13, y5);
    y14 = _mm256_aesenc_epi128(y14, y5);
    y11 = _mm256_aesenc_epi128(y11, y6);
    y12 = _mm256_aesenc_epi128(y12, y6);
    y13 = _mm256_aesenc_epi128(y13, y6);
    y14 = _mm256_aesenc_epi128(y14, y6);
    y11 = _mm256_aesenc_epi128(y11, y7);
    y12 = _mm256_aesenc_epi128(y12, y7);
    y13 = _mm256_aesenc_epi128(y13, y7);
    y14 = _mm256_aesenc_epi128(y14, y7);
    y11 = _mm256_aesenc_epi128(y11, y8);
    y12 = _mm256_aesenc_epi128(y12, y8);
    y13 = _mm256_aesenc_epi128(y13, y8);
    y14 = _mm256_aesenc_epi128(y14, y8);
    y11 = _mm256_aesenc_epi128(y11, y9);
    y12 = _mm256_aesenc_epi128(y12, y9);
    y13 = _mm256_aesenc_epi128(y13, y9);
    y14 = _mm256_aesenc_epi128(y14, y9);
    y11 = _mm256_aesenclast_epi128(y11, y10);
    y12 = _mm256_aesenclast_epi128(y12, y10);
    y13 = _mm256_aesenclast_epi128(y13, y10);
    y14 = _mm256_aesenclast_epi128(y14, y10);
    y11 = _mm256_and_si256(y11, y15);
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 0), y11);
    y12 = _mm256_and_si256(y12, y15);
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 32), y12);
    y13 = _mm256_and_si256(y13, y15);
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 64), y13);
    y14 = _mm256_and_si256(y14, y15);
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 96), y14);
    rsi = (word64)(rsi + 0x80);
    r13 = (word64)(r13 + 8);
    goto L_frodokem_gen_a_rows_aes_avx2_blk;
L_frodokem_gen_a_rows_aes_avx2_tail:
    if ((sword64)(r13) >= (sword64)(r10)) {
        goto L_frodokem_gen_a_rows_aes_avx2_next;
    }
    y11 = _mm256_zextsi128_si256(_mm_cvtsi32_si128((int)(word32)r14));
    r14 = (word64)(r14 + 0x80000);
    y11 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y11),
        _mm256_castsi256_si128(y0)));
    y11 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y11),
        _mm256_castsi256_si128(y1)));
    y11 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y11),
        _mm256_castsi256_si128(y2)));
    y11 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y11),
        _mm256_castsi256_si128(y3)));
    y11 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y11),
        _mm256_castsi256_si128(y4)));
    y11 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y11),
        _mm256_castsi256_si128(y5)));
    y11 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y11),
        _mm256_castsi256_si128(y6)));
    y11 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y11),
        _mm256_castsi256_si128(y7)));
    y11 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y11),
        _mm256_castsi256_si128(y8)));
    y11 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y11),
        _mm256_castsi256_si128(y9)));
    y11 = _mm256_zextsi128_si256(_mm_aesenclast_si128(_mm256_castsi256_si128(
        y11), _mm256_castsi256_si128(y10)));
    y11 = _mm256_zextsi128_si256(_mm_and_si128(_mm256_castsi256_si128(y11),
        _mm256_castsi256_si128(y15)));
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 0), _mm256_castsi256_si128(y11));
    rsi = (word64)(rsi + 0x10);
    r13 = (word64)(r13 + 1);
    goto L_frodokem_gen_a_rows_aes_avx2_tail;
L_frodokem_gen_a_rows_aes_avx2_next:
    r12 = (word64)(r12 + 1);
    if ((sword64)(r12) < (sword64)(r11)) {
        goto L_frodokem_gen_a_rows_aes_avx2_row;
    }
    (void)rdi;
}

WC_X64I_TARGET("aes,avx2")
WOLFSSL_LOCAL void frodokem_gen_a_rows_aes_aesni(byte* in, word16* out,
    const byte* ks, int i, int cnt, int n, int qmask)
{
    word64 rdi, rsi, rdx, rcx, r8, r9, rax, r10, r11, r12, r14 = 0, r13 = 0,
           r15 = 0;
    __m128i x0 = _mm_setzero_si128(), x1 = _mm_setzero_si128(),
            x2 = _mm_setzero_si128(), x3 = _mm_setzero_si128(),
            x4 = _mm_setzero_si128(), x5 = _mm_setzero_si128(),
            x6 = _mm_setzero_si128(), x7 = _mm_setzero_si128(), x8;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(size_t)ks;
    rcx = (word64)(word32)i;
    r8 = (word64)(word32)cnt;
    r9 = (word64)(word32)n;
    rax = (word64)(word32)qmask;

    x8 = _mm_cvtsi32_si128((int)(word32)rax);
    x8 = _mm_broadcastw_epi16(x8);
    r10 = (word64)((word64)(sword64)(sword32)(word32)r9);
    r10 = (word64)(r10 >> 3);
    r11 = (word64)((word64)(sword64)(sword32)(word32)r8);
    rcx = (word64)((word64)(sword64)(sword32)(word32)rcx);
    r12 = (word64)(0);
L_frodokem_gen_a_rows_aes_aesni_row:
    r14 = (word64)(rcx);
    r14 = (word64)(r14 + r12);
    r13 = (word64)(0);
L_frodokem_gen_a_rows_aes_aesni_blk:
    r15 = (word64)(r13 + 8);
    if ((sword64)(r15) > (sword64)(r10)) {
        goto L_frodokem_gen_a_rows_aes_aesni_tail;
    }
    x0 = _mm_cvtsi32_si128((int)(word32)r14);
    r14 = (word64)(r14 + 0x80000);
    x1 = _mm_cvtsi32_si128((int)(word32)r14);
    r14 = (word64)(r14 + 0x80000);
    x2 = _mm_cvtsi32_si128((int)(word32)r14);
    r14 = (word64)(r14 + 0x80000);
    x3 = _mm_cvtsi32_si128((int)(word32)r14);
    r14 = (word64)(r14 + 0x80000);
    x4 = _mm_cvtsi32_si128((int)(word32)r14);
    r14 = (word64)(r14 + 0x80000);
    x5 = _mm_cvtsi32_si128((int)(word32)r14);
    r14 = (word64)(r14 + 0x80000);
    x6 = _mm_cvtsi32_si128((int)(word32)r14);
    r14 = (word64)(r14 + 0x80000);
    x7 = _mm_cvtsi32_si128((int)(word32)r14);
    r14 = (word64)(r14 + 0x80000);
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0)));
    x1 = _mm_xor_si128(x1, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0)));
    x2 = _mm_xor_si128(x2, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0)));
    x3 = _mm_xor_si128(x3, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0)));
    x4 = _mm_xor_si128(x4, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0)));
    x5 = _mm_xor_si128(x5, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0)));
    x6 = _mm_xor_si128(x6, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0)));
    x7 = _mm_xor_si128(x7, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0)));
    x0 = _mm_aesenc_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 16)));
    x1 = _mm_aesenc_si128(x1, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 16)));
    x2 = _mm_aesenc_si128(x2, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 16)));
    x3 = _mm_aesenc_si128(x3, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 16)));
    x4 = _mm_aesenc_si128(x4, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 16)));
    x5 = _mm_aesenc_si128(x5, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 16)));
    x6 = _mm_aesenc_si128(x6, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 16)));
    x7 = _mm_aesenc_si128(x7, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 16)));
    x0 = _mm_aesenc_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 32)));
    x1 = _mm_aesenc_si128(x1, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 32)));
    x2 = _mm_aesenc_si128(x2, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 32)));
    x3 = _mm_aesenc_si128(x3, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 32)));
    x4 = _mm_aesenc_si128(x4, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 32)));
    x5 = _mm_aesenc_si128(x5, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 32)));
    x6 = _mm_aesenc_si128(x6, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 32)));
    x7 = _mm_aesenc_si128(x7, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 32)));
    x0 = _mm_aesenc_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 48)));
    x1 = _mm_aesenc_si128(x1, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 48)));
    x2 = _mm_aesenc_si128(x2, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 48)));
    x3 = _mm_aesenc_si128(x3, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 48)));
    x4 = _mm_aesenc_si128(x4, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 48)));
    x5 = _mm_aesenc_si128(x5, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 48)));
    x6 = _mm_aesenc_si128(x6, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 48)));
    x7 = _mm_aesenc_si128(x7, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 48)));
    x0 = _mm_aesenc_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 64)));
    x1 = _mm_aesenc_si128(x1, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 64)));
    x2 = _mm_aesenc_si128(x2, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 64)));
    x3 = _mm_aesenc_si128(x3, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 64)));
    x4 = _mm_aesenc_si128(x4, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 64)));
    x5 = _mm_aesenc_si128(x5, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 64)));
    x6 = _mm_aesenc_si128(x6, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 64)));
    x7 = _mm_aesenc_si128(x7, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 64)));
    x0 = _mm_aesenc_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 80)));
    x1 = _mm_aesenc_si128(x1, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 80)));
    x2 = _mm_aesenc_si128(x2, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 80)));
    x3 = _mm_aesenc_si128(x3, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 80)));
    x4 = _mm_aesenc_si128(x4, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 80)));
    x5 = _mm_aesenc_si128(x5, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 80)));
    x6 = _mm_aesenc_si128(x6, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 80)));
    x7 = _mm_aesenc_si128(x7, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 80)));
    x0 = _mm_aesenc_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 96)));
    x1 = _mm_aesenc_si128(x1, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 96)));
    x2 = _mm_aesenc_si128(x2, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 96)));
    x3 = _mm_aesenc_si128(x3, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 96)));
    x4 = _mm_aesenc_si128(x4, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 96)));
    x5 = _mm_aesenc_si128(x5, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 96)));
    x6 = _mm_aesenc_si128(x6, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 96)));
    x7 = _mm_aesenc_si128(x7, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 96)));
    x0 = _mm_aesenc_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 112)));
    x1 = _mm_aesenc_si128(x1, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 112)));
    x2 = _mm_aesenc_si128(x2, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 112)));
    x3 = _mm_aesenc_si128(x3, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 112)));
    x4 = _mm_aesenc_si128(x4, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 112)));
    x5 = _mm_aesenc_si128(x5, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 112)));
    x6 = _mm_aesenc_si128(x6, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 112)));
    x7 = _mm_aesenc_si128(x7, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 112)));
    x0 = _mm_aesenc_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 128)));
    x1 = _mm_aesenc_si128(x1, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 128)));
    x2 = _mm_aesenc_si128(x2, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 128)));
    x3 = _mm_aesenc_si128(x3, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 128)));
    x4 = _mm_aesenc_si128(x4, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 128)));
    x5 = _mm_aesenc_si128(x5, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 128)));
    x6 = _mm_aesenc_si128(x6, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 128)));
    x7 = _mm_aesenc_si128(x7, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 128)));
    x0 = _mm_aesenc_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 144)));
    x1 = _mm_aesenc_si128(x1, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 144)));
    x2 = _mm_aesenc_si128(x2, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 144)));
    x3 = _mm_aesenc_si128(x3, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 144)));
    x4 = _mm_aesenc_si128(x4, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 144)));
    x5 = _mm_aesenc_si128(x5, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 144)));
    x6 = _mm_aesenc_si128(x6, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 144)));
    x7 = _mm_aesenc_si128(x7, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 144)));
    x0 = _mm_aesenclast_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx,
        160)));
    x1 = _mm_aesenclast_si128(x1, _mm_loadu_si128((const __m128i*)WC_PR(rdx,
        160)));
    x2 = _mm_aesenclast_si128(x2, _mm_loadu_si128((const __m128i*)WC_PR(rdx,
        160)));
    x3 = _mm_aesenclast_si128(x3, _mm_loadu_si128((const __m128i*)WC_PR(rdx,
        160)));
    x4 = _mm_aesenclast_si128(x4, _mm_loadu_si128((const __m128i*)WC_PR(rdx,
        160)));
    x5 = _mm_aesenclast_si128(x5, _mm_loadu_si128((const __m128i*)WC_PR(rdx,
        160)));
    x6 = _mm_aesenclast_si128(x6, _mm_loadu_si128((const __m128i*)WC_PR(rdx,
        160)));
    x7 = _mm_aesenclast_si128(x7, _mm_loadu_si128((const __m128i*)WC_PR(rdx,
        160)));
    x0 = _mm_and_si128(x0, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 0), x0);
    x1 = _mm_and_si128(x1, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 16), x1);
    x2 = _mm_and_si128(x2, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 32), x2);
    x3 = _mm_and_si128(x3, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 48), x3);
    x4 = _mm_and_si128(x4, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 64), x4);
    x5 = _mm_and_si128(x5, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 80), x5);
    x6 = _mm_and_si128(x6, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 96), x6);
    x7 = _mm_and_si128(x7, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 112), x7);
    rsi = (word64)(rsi + 0x80);
    r13 = (word64)(r13 + 8);
    goto L_frodokem_gen_a_rows_aes_aesni_blk;
L_frodokem_gen_a_rows_aes_aesni_tail:
    if ((sword64)(r13) >= (sword64)(r10)) {
        goto L_frodokem_gen_a_rows_aes_aesni_next;
    }
    x0 = _mm_cvtsi32_si128((int)(word32)r14);
    r14 = (word64)(r14 + 0x80000);
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0)));
    x0 = _mm_aesenc_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 16)));
    x0 = _mm_aesenc_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 32)));
    x0 = _mm_aesenc_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 48)));
    x0 = _mm_aesenc_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 64)));
    x0 = _mm_aesenc_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 80)));
    x0 = _mm_aesenc_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 96)));
    x0 = _mm_aesenc_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 112)));
    x0 = _mm_aesenc_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 128)));
    x0 = _mm_aesenc_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 144)));
    x0 = _mm_aesenclast_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx,
        160)));
    x0 = _mm_and_si128(x0, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 0), x0);
    rsi = (word64)(rsi + 0x10);
    r13 = (word64)(r13 + 1);
    goto L_frodokem_gen_a_rows_aes_aesni_tail;
L_frodokem_gen_a_rows_aes_aesni_next:
    r12 = (word64)(r12 + 1);
    if ((sword64)(r12) < (sword64)(r11)) {
        goto L_frodokem_gen_a_rows_aes_aesni_row;
    }
    (void)rdi;
}

#endif /* HAVE_INTEL_AVX2 */
#endif /* WOLFSSL_HAVE_FRODOKEM */
#ifdef WOLFSSL_HAVE_FRODOKEM
#ifdef HAVE_INTEL_AVX512
WC_X64I_TARGET("avx512f,avx512bw")
WOLFSSL_LOCAL void frodokem_sa_accum_avx512(word16* out, const word16* s,
    const word16* row, int j, int n)
{
    word64 rdi, rsi, rdx, rcx, r8, rax, r9, r10, r11, r12, r13, r14, r15, rbp,
           rbx = 0;
    __m512i z0 = _mm512_setzero_si512(), z1 = _mm512_setzero_si512(),
            z2 = _mm512_setzero_si512(), z3 = _mm512_setzero_si512(),
            z4 = _mm512_setzero_si512(), z5 = _mm512_setzero_si512(),
            z6 = _mm512_setzero_si512(), z7 = _mm512_setzero_si512(),
            z8 = _mm512_setzero_si512(), z9 = _mm512_setzero_si512();

    rdi = (word64)(size_t)out;
    rsi = (word64)(size_t)s;
    rdx = (word64)(size_t)row;
    rcx = (word64)(word32)j;
    r8 = (word64)(word32)n;

    rcx = (word64)((word64)(sword64)(sword32)(word32)rcx);
    rcx = (word64)(rcx << 1);
    rsi = (word64)(rsi + rcx);
    rax = (word64)((word64)(sword64)(sword32)(word32)r8);
    rax = (word64)(rax << 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & -64);
    r9 = (word64)(rdx);
    r9 = (word64)(r9 + rax);
    r10 = (word64)(r9);
    r10 = (word64)(r10 + rax);
    r11 = (word64)(r10);
    r11 = (word64)(r11 + rax);
    r12 = (word64)(r11);
    r12 = (word64)(r12 + rax);
    r13 = (word64)(r12);
    r13 = (word64)(r13 + rax);
    r14 = (word64)(r13);
    r14 = (word64)(r14 + rax);
    r15 = (word64)(r14);
    r15 = (word64)(r15 + rax);
    rbp = (word64)(8);
L_frodokem_sa_accum_avx512_i:
    z0 = _mm512_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(rsi,
        0)));
    z1 = _mm512_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(rsi,
        2)));
    z2 = _mm512_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(rsi,
        4)));
    z3 = _mm512_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(rsi,
        6)));
    z4 = _mm512_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(rsi,
        8)));
    z5 = _mm512_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(rsi,
        10)));
    z6 = _mm512_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(rsi,
        12)));
    z7 = _mm512_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(rsi,
        14)));
    rbx = (word64)(0);
L_frodokem_sa_accum_avx512_k:
    z8 = _mm512_loadu_si512((const void*)WC_PR(rdi, rbx));
    z9 = _mm512_mullo_epi16(z0, _mm512_loadu_si512((const void*)WC_PR(rdx,
        rbx)));
    z8 = _mm512_add_epi16(z8, z9);
    z9 = _mm512_mullo_epi16(z1, _mm512_loadu_si512((const void*)WC_PR(r9,
        rbx)));
    z8 = _mm512_add_epi16(z8, z9);
    z9 = _mm512_mullo_epi16(z2, _mm512_loadu_si512((const void*)WC_PR(r10,
        rbx)));
    z8 = _mm512_add_epi16(z8, z9);
    z9 = _mm512_mullo_epi16(z3, _mm512_loadu_si512((const void*)WC_PR(r11,
        rbx)));
    z8 = _mm512_add_epi16(z8, z9);
    z9 = _mm512_mullo_epi16(z4, _mm512_loadu_si512((const void*)WC_PR(r12,
        rbx)));
    z8 = _mm512_add_epi16(z8, z9);
    z9 = _mm512_mullo_epi16(z5, _mm512_loadu_si512((const void*)WC_PR(r13,
        rbx)));
    z8 = _mm512_add_epi16(z8, z9);
    z9 = _mm512_mullo_epi16(z6, _mm512_loadu_si512((const void*)WC_PR(r14,
        rbx)));
    z8 = _mm512_add_epi16(z8, z9);
    z9 = _mm512_mullo_epi16(z7, _mm512_loadu_si512((const void*)WC_PR(r15,
        rbx)));
    z8 = _mm512_add_epi16(z8, z9);
    _mm512_storeu_si512((void*)WC_PW(rdi, rbx), z8);
    rbx = (word64)(rbx + 0x40);
    if ((sword64)(rbx) < (sword64)(rcx)) {
        goto L_frodokem_sa_accum_avx512_k;
    }
    if ((sword64)(rbx) >= (sword64)(rax)) {
        goto L_frodokem_sa_accum_avx512_tail;
    }
    z8 = _mm512_zextsi256_si512(_mm256_loadu_si256((const __m256i*)WC_PR(rdi,
        rbx)));
    z9 = _mm512_zextsi256_si512(_mm256_mullo_epi16(_mm512_castsi512_si256(z0),
        _mm256_loadu_si256((const __m256i*)WC_PR(rdx, rbx))));
    z8 = _mm512_zextsi256_si512(_mm256_add_epi16(_mm512_castsi512_si256(z8),
        _mm512_castsi512_si256(z9)));
    z9 = _mm512_zextsi256_si512(_mm256_mullo_epi16(_mm512_castsi512_si256(z1),
        _mm256_loadu_si256((const __m256i*)WC_PR(r9, rbx))));
    z8 = _mm512_zextsi256_si512(_mm256_add_epi16(_mm512_castsi512_si256(z8),
        _mm512_castsi512_si256(z9)));
    z9 = _mm512_zextsi256_si512(_mm256_mullo_epi16(_mm512_castsi512_si256(z2),
        _mm256_loadu_si256((const __m256i*)WC_PR(r10, rbx))));
    z8 = _mm512_zextsi256_si512(_mm256_add_epi16(_mm512_castsi512_si256(z8),
        _mm512_castsi512_si256(z9)));
    z9 = _mm512_zextsi256_si512(_mm256_mullo_epi16(_mm512_castsi512_si256(z3),
        _mm256_loadu_si256((const __m256i*)WC_PR(r11, rbx))));
    z8 = _mm512_zextsi256_si512(_mm256_add_epi16(_mm512_castsi512_si256(z8),
        _mm512_castsi512_si256(z9)));
    z9 = _mm512_zextsi256_si512(_mm256_mullo_epi16(_mm512_castsi512_si256(z4),
        _mm256_loadu_si256((const __m256i*)WC_PR(r12, rbx))));
    z8 = _mm512_zextsi256_si512(_mm256_add_epi16(_mm512_castsi512_si256(z8),
        _mm512_castsi512_si256(z9)));
    z9 = _mm512_zextsi256_si512(_mm256_mullo_epi16(_mm512_castsi512_si256(z5),
        _mm256_loadu_si256((const __m256i*)WC_PR(r13, rbx))));
    z8 = _mm512_zextsi256_si512(_mm256_add_epi16(_mm512_castsi512_si256(z8),
        _mm512_castsi512_si256(z9)));
    z9 = _mm512_zextsi256_si512(_mm256_mullo_epi16(_mm512_castsi512_si256(z6),
        _mm256_loadu_si256((const __m256i*)WC_PR(r14, rbx))));
    z8 = _mm512_zextsi256_si512(_mm256_add_epi16(_mm512_castsi512_si256(z8),
        _mm512_castsi512_si256(z9)));
    z9 = _mm512_zextsi256_si512(_mm256_mullo_epi16(_mm512_castsi512_si256(z7),
        _mm256_loadu_si256((const __m256i*)WC_PR(r15, rbx))));
    z8 = _mm512_zextsi256_si512(_mm256_add_epi16(_mm512_castsi512_si256(z8),
        _mm512_castsi512_si256(z9)));
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, rbx), _mm512_castsi512_si256(z8));
L_frodokem_sa_accum_avx512_tail:
    rdi = (word64)(rdi + rax);
    rsi = (word64)(rsi + rax);
    rbp = (word64)(rbp - 1);
    if ((rbp) != (0)) {
        goto L_frodokem_sa_accum_avx512_i;
    }
}

WC_X64I_TARGET("avx512f,avx512vl,avx512bw")
WOLFSSL_LOCAL void frodokem_as_accum_avx512(word16* out, const word16* s,
    const word16* row, int i, int n)
{
    word64 rdi, rsi, rdx, rcx, r8, rax, r9, r10, r11, r12, r13, r14, r15, rbp,
           rbx = 0;
    __m128i x2 = _mm_setzero_si128(), x3 = _mm_setzero_si128(),
            x4 = _mm_setzero_si128(), x5 = _mm_setzero_si128(),
            x6 = _mm_setzero_si128(), x7 = _mm_setzero_si128(),
            x8 = _mm_setzero_si128(), x9 = _mm_setzero_si128(),
            x10 = _mm_setzero_si128(), x11 = _mm_setzero_si128(),
            x12 = _mm_setzero_si128(), x13 = _mm_setzero_si128();
    __m256i y22 = _mm256_setzero_si256(), y23 = _mm256_setzero_si256(),
            y24 = _mm256_setzero_si256(), y25 = _mm256_setzero_si256(),
            y26 = _mm256_setzero_si256(), y27 = _mm256_setzero_si256(),
            y28 = _mm256_setzero_si256(), y29 = _mm256_setzero_si256();
    __m512i z0 = _mm512_setzero_si512(), z1 = _mm512_setzero_si512(),
            z14 = _mm512_setzero_si512(), z15 = _mm512_setzero_si512(),
            z16 = _mm512_setzero_si512(), z17 = _mm512_setzero_si512(),
            z18 = _mm512_setzero_si512(), z19 = _mm512_setzero_si512(),
            z20 = _mm512_setzero_si512(), z21 = _mm512_setzero_si512();

    rdi = (word64)(size_t)out;
    rsi = (word64)(size_t)s;
    rdx = (word64)(size_t)row;
    rcx = (word64)(word32)i;
    r8 = (word64)(word32)n;

    rcx = (word64)((word64)(sword64)(sword32)(word32)rcx);
    rcx = (word64)(rcx << 4);
    rdi = (word64)(rdi + rcx);
    rax = (word64)((word64)(sword64)(sword32)(word32)r8);
    rax = (word64)(rax << 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & -64);
    r9 = (word64)(rsi);
    r9 = (word64)(r9 + rax);
    r10 = (word64)(r9);
    r10 = (word64)(r10 + rax);
    r11 = (word64)(r10);
    r11 = (word64)(r11 + rax);
    r12 = (word64)(r11);
    r12 = (word64)(r12 + rax);
    r13 = (word64)(r12);
    r13 = (word64)(r13 + rax);
    r14 = (word64)(r13);
    r14 = (word64)(r14 + rax);
    r15 = (word64)(r14);
    r15 = (word64)(r15 + rax);
    rbp = (word64)(8);
    x13 = _mm_cmpeq_epi32(x13, x13);
    x13 = _mm_srli_epi32(x13, 16);
L_frodokem_as_accum_avx512_r:
    z14 = _mm512_setzero_si512();
    y22 = _mm256_setzero_si256();
    z15 = _mm512_setzero_si512();
    y23 = _mm256_setzero_si256();
    z16 = _mm512_setzero_si512();
    y24 = _mm256_setzero_si256();
    z17 = _mm512_setzero_si512();
    y25 = _mm256_setzero_si256();
    z18 = _mm512_setzero_si512();
    y26 = _mm256_setzero_si256();
    z19 = _mm512_setzero_si512();
    y27 = _mm256_setzero_si256();
    z20 = _mm512_setzero_si512();
    y28 = _mm256_setzero_si256();
    z21 = _mm512_setzero_si512();
    y29 = _mm256_setzero_si256();
    rbx = (word64)(0);
L_frodokem_as_accum_avx512_j:
    z0 = _mm512_loadu_si512((const void*)WC_PR(rdx, rbx));
    z1 = _mm512_madd_epi16(z0, _mm512_loadu_si512((const void*)WC_PR(rsi,
        rbx)));
    z14 = _mm512_add_epi32(z14, z1);
    z1 = _mm512_madd_epi16(z0, _mm512_loadu_si512((const void*)WC_PR(r9, rbx)));
    z15 = _mm512_add_epi32(z15, z1);
    z1 = _mm512_madd_epi16(z0, _mm512_loadu_si512((const void*)WC_PR(r10,
        rbx)));
    z16 = _mm512_add_epi32(z16, z1);
    z1 = _mm512_madd_epi16(z0, _mm512_loadu_si512((const void*)WC_PR(r11,
        rbx)));
    z17 = _mm512_add_epi32(z17, z1);
    z1 = _mm512_madd_epi16(z0, _mm512_loadu_si512((const void*)WC_PR(r12,
        rbx)));
    z18 = _mm512_add_epi32(z18, z1);
    z1 = _mm512_madd_epi16(z0, _mm512_loadu_si512((const void*)WC_PR(r13,
        rbx)));
    z19 = _mm512_add_epi32(z19, z1);
    z1 = _mm512_madd_epi16(z0, _mm512_loadu_si512((const void*)WC_PR(r14,
        rbx)));
    z20 = _mm512_add_epi32(z20, z1);
    z1 = _mm512_madd_epi16(z0, _mm512_loadu_si512((const void*)WC_PR(r15,
        rbx)));
    z21 = _mm512_add_epi32(z21, z1);
    rbx = (word64)(rbx + 0x40);
    if ((sword64)(rbx) < (sword64)(rcx)) {
        goto L_frodokem_as_accum_avx512_j;
    }
    if ((sword64)(rbx) >= (sword64)(rax)) {
        goto L_frodokem_as_accum_avx512_tail;
    }
    z0 = _mm512_zextsi256_si512(_mm256_loadu_si256((const __m256i*)WC_PR(rdx,
        rbx)));
    y22 = _mm256_madd_epi16(_mm512_castsi512_si256(z0), _mm256_loadu_si256((
        const __m256i*)WC_PR(rsi, rbx)));
    y23 = _mm256_madd_epi16(_mm512_castsi512_si256(z0), _mm256_loadu_si256((
        const __m256i*)WC_PR(r9, rbx)));
    y24 = _mm256_madd_epi16(_mm512_castsi512_si256(z0), _mm256_loadu_si256((
        const __m256i*)WC_PR(r10, rbx)));
    y25 = _mm256_madd_epi16(_mm512_castsi512_si256(z0), _mm256_loadu_si256((
        const __m256i*)WC_PR(r11, rbx)));
    y26 = _mm256_madd_epi16(_mm512_castsi512_si256(z0), _mm256_loadu_si256((
        const __m256i*)WC_PR(r12, rbx)));
    y27 = _mm256_madd_epi16(_mm512_castsi512_si256(z0), _mm256_loadu_si256((
        const __m256i*)WC_PR(r13, rbx)));
    y28 = _mm256_madd_epi16(_mm512_castsi512_si256(z0), _mm256_loadu_si256((
        const __m256i*)WC_PR(r14, rbx)));
    y29 = _mm256_madd_epi16(_mm512_castsi512_si256(z0), _mm256_loadu_si256((
        const __m256i*)WC_PR(r15, rbx)));
L_frodokem_as_accum_avx512_tail:
    z1 = _mm512_zextsi256_si512(_mm512_extracti64x4_epi64(z14, 1));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z14),
        _mm512_castsi512_si256(z1)));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z1),
        y22));
    z0 = _mm512_zextsi128_si512(_mm256_extracti128_si256(_mm512_castsi512_si256(
        z1), 1));
    x2 = _mm_add_epi32(_mm512_castsi512_si128(z1), _mm512_castsi512_si128(z0));
    z1 = _mm512_zextsi256_si512(_mm512_extracti64x4_epi64(z15, 1));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z15),
        _mm512_castsi512_si256(z1)));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z1),
        y23));
    z0 = _mm512_zextsi128_si512(_mm256_extracti128_si256(_mm512_castsi512_si256(
        z1), 1));
    x3 = _mm_add_epi32(_mm512_castsi512_si128(z1), _mm512_castsi512_si128(z0));
    z1 = _mm512_zextsi256_si512(_mm512_extracti64x4_epi64(z16, 1));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z16),
        _mm512_castsi512_si256(z1)));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z1),
        y24));
    z0 = _mm512_zextsi128_si512(_mm256_extracti128_si256(_mm512_castsi512_si256(
        z1), 1));
    x4 = _mm_add_epi32(_mm512_castsi512_si128(z1), _mm512_castsi512_si128(z0));
    z1 = _mm512_zextsi256_si512(_mm512_extracti64x4_epi64(z17, 1));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z17),
        _mm512_castsi512_si256(z1)));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z1),
        y25));
    z0 = _mm512_zextsi128_si512(_mm256_extracti128_si256(_mm512_castsi512_si256(
        z1), 1));
    x5 = _mm_add_epi32(_mm512_castsi512_si128(z1), _mm512_castsi512_si128(z0));
    z1 = _mm512_zextsi256_si512(_mm512_extracti64x4_epi64(z18, 1));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z18),
        _mm512_castsi512_si256(z1)));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z1),
        y26));
    z0 = _mm512_zextsi128_si512(_mm256_extracti128_si256(_mm512_castsi512_si256(
        z1), 1));
    x6 = _mm_add_epi32(_mm512_castsi512_si128(z1), _mm512_castsi512_si128(z0));
    z1 = _mm512_zextsi256_si512(_mm512_extracti64x4_epi64(z19, 1));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z19),
        _mm512_castsi512_si256(z1)));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z1),
        y27));
    z0 = _mm512_zextsi128_si512(_mm256_extracti128_si256(_mm512_castsi512_si256(
        z1), 1));
    x7 = _mm_add_epi32(_mm512_castsi512_si128(z1), _mm512_castsi512_si128(z0));
    z1 = _mm512_zextsi256_si512(_mm512_extracti64x4_epi64(z20, 1));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z20),
        _mm512_castsi512_si256(z1)));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z1),
        y28));
    z0 = _mm512_zextsi128_si512(_mm256_extracti128_si256(_mm512_castsi512_si256(
        z1), 1));
    x8 = _mm_add_epi32(_mm512_castsi512_si128(z1), _mm512_castsi512_si128(z0));
    z1 = _mm512_zextsi256_si512(_mm512_extracti64x4_epi64(z21, 1));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z21),
        _mm512_castsi512_si256(z1)));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z1),
        y29));
    z0 = _mm512_zextsi128_si512(_mm256_extracti128_si256(_mm512_castsi512_si256(
        z1), 1));
    x9 = _mm_add_epi32(_mm512_castsi512_si128(z1), _mm512_castsi512_si128(z0));
    x11 = _mm_hadd_epi32(x2, x3);
    x12 = _mm_hadd_epi32(x4, x5);
    x10 = _mm_hadd_epi32(x11, x12);
    x11 = _mm_hadd_epi32(x6, x7);
    x12 = _mm_hadd_epi32(x8, x9);
    x11 = _mm_hadd_epi32(x11, x12);
    x10 = _mm_and_si128(x10, x13);
    x11 = _mm_and_si128(x11, x13);
    x10 = _mm_packus_epi32(x10, x11);
    x10 = _mm_add_epi16(x10, _mm_loadu_si128((const __m128i*)WC_PR(rdi, 0)));
    _mm_storeu_si128((__m128i*)WC_PW(rdi, 0), x10);
    rdx = (word64)(rdx + rax);
    rdi = (word64)(rdi + 0x10);
    rbp = (word64)(rbp - 1);
    if ((rbp) != (0)) {
        goto L_frodokem_as_accum_avx512_r;
    }
}

WC_X64I_TARGET("avx512f,avx512vl,avx512bw")
WOLFSSL_LOCAL void frodokem_mul_bs_avx512(word16* out, const word16* b,
    const word16* s, int n, int qmask)
{
    word64 rdi, rsi, rdx, rcx, r8, rax, r9, r10, r11, r12, r13, r14, r15, rbp,
           rbx = 0;
    __m128i x2 = _mm_setzero_si128(), x3 = _mm_setzero_si128(),
            x4 = _mm_setzero_si128(), x5 = _mm_setzero_si128(),
            x6 = _mm_setzero_si128(), x7 = _mm_setzero_si128(),
            x8 = _mm_setzero_si128(), x9 = _mm_setzero_si128(),
            x10 = _mm_setzero_si128(), x11 = _mm_setzero_si128(),
            x12 = _mm_setzero_si128(), x13;
    __m256i y22 = _mm256_setzero_si256(), y23 = _mm256_setzero_si256(),
            y24 = _mm256_setzero_si256(), y25 = _mm256_setzero_si256(),
            y26 = _mm256_setzero_si256(), y27 = _mm256_setzero_si256(),
            y28 = _mm256_setzero_si256(), y29 = _mm256_setzero_si256();
    __m512i z0 = _mm512_setzero_si512(), z1 = _mm512_setzero_si512(),
            z14 = _mm512_setzero_si512(), z15 = _mm512_setzero_si512(),
            z16 = _mm512_setzero_si512(), z17 = _mm512_setzero_si512(),
            z18 = _mm512_setzero_si512(), z19 = _mm512_setzero_si512(),
            z20 = _mm512_setzero_si512(), z21 = _mm512_setzero_si512();

    rdi = (word64)(size_t)out;
    rsi = (word64)(size_t)b;
    rdx = (word64)(size_t)s;
    rcx = (word64)(word32)n;
    r8 = (word64)(word32)qmask;

    rax = (word64)((word64)(sword64)(sword32)(word32)rcx);
    rax = (word64)(rax << 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & -64);
    r9 = (word64)(rdx);
    r9 = (word64)(r9 + rax);
    r10 = (word64)(r9);
    r10 = (word64)(r10 + rax);
    r11 = (word64)(r10);
    r11 = (word64)(r11 + rax);
    r12 = (word64)(r11);
    r12 = (word64)(r12 + rax);
    r13 = (word64)(r12);
    r13 = (word64)(r13 + rax);
    r14 = (word64)(r13);
    r14 = (word64)(r14 + rax);
    r15 = (word64)(r14);
    r15 = (word64)(r15 + rax);
    rbp = (word64)(8);
    x13 = _mm_cvtsi32_si128((int)(word32)r8);
    x13 = _mm_broadcastd_epi32(x13);
L_frodokem_mul_bs_avx512_r:
    z14 = _mm512_setzero_si512();
    y22 = _mm256_setzero_si256();
    z15 = _mm512_setzero_si512();
    y23 = _mm256_setzero_si256();
    z16 = _mm512_setzero_si512();
    y24 = _mm256_setzero_si256();
    z17 = _mm512_setzero_si512();
    y25 = _mm256_setzero_si256();
    z18 = _mm512_setzero_si512();
    y26 = _mm256_setzero_si256();
    z19 = _mm512_setzero_si512();
    y27 = _mm256_setzero_si256();
    z20 = _mm512_setzero_si512();
    y28 = _mm256_setzero_si256();
    z21 = _mm512_setzero_si512();
    y29 = _mm256_setzero_si256();
    rbx = (word64)(0);
L_frodokem_mul_bs_avx512_j:
    z0 = _mm512_loadu_si512((const void*)WC_PR(rsi, rbx));
    z1 = _mm512_madd_epi16(z0, _mm512_loadu_si512((const void*)WC_PR(rdx,
        rbx)));
    z14 = _mm512_add_epi32(z14, z1);
    z1 = _mm512_madd_epi16(z0, _mm512_loadu_si512((const void*)WC_PR(r9, rbx)));
    z15 = _mm512_add_epi32(z15, z1);
    z1 = _mm512_madd_epi16(z0, _mm512_loadu_si512((const void*)WC_PR(r10,
        rbx)));
    z16 = _mm512_add_epi32(z16, z1);
    z1 = _mm512_madd_epi16(z0, _mm512_loadu_si512((const void*)WC_PR(r11,
        rbx)));
    z17 = _mm512_add_epi32(z17, z1);
    z1 = _mm512_madd_epi16(z0, _mm512_loadu_si512((const void*)WC_PR(r12,
        rbx)));
    z18 = _mm512_add_epi32(z18, z1);
    z1 = _mm512_madd_epi16(z0, _mm512_loadu_si512((const void*)WC_PR(r13,
        rbx)));
    z19 = _mm512_add_epi32(z19, z1);
    z1 = _mm512_madd_epi16(z0, _mm512_loadu_si512((const void*)WC_PR(r14,
        rbx)));
    z20 = _mm512_add_epi32(z20, z1);
    z1 = _mm512_madd_epi16(z0, _mm512_loadu_si512((const void*)WC_PR(r15,
        rbx)));
    z21 = _mm512_add_epi32(z21, z1);
    rbx = (word64)(rbx + 0x40);
    if ((sword64)(rbx) < (sword64)(rcx)) {
        goto L_frodokem_mul_bs_avx512_j;
    }
    if ((sword64)(rbx) >= (sword64)(rax)) {
        goto L_frodokem_mul_bs_avx512_tail;
    }
    z0 = _mm512_zextsi256_si512(_mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        rbx)));
    y22 = _mm256_madd_epi16(_mm512_castsi512_si256(z0), _mm256_loadu_si256((
        const __m256i*)WC_PR(rdx, rbx)));
    y23 = _mm256_madd_epi16(_mm512_castsi512_si256(z0), _mm256_loadu_si256((
        const __m256i*)WC_PR(r9, rbx)));
    y24 = _mm256_madd_epi16(_mm512_castsi512_si256(z0), _mm256_loadu_si256((
        const __m256i*)WC_PR(r10, rbx)));
    y25 = _mm256_madd_epi16(_mm512_castsi512_si256(z0), _mm256_loadu_si256((
        const __m256i*)WC_PR(r11, rbx)));
    y26 = _mm256_madd_epi16(_mm512_castsi512_si256(z0), _mm256_loadu_si256((
        const __m256i*)WC_PR(r12, rbx)));
    y27 = _mm256_madd_epi16(_mm512_castsi512_si256(z0), _mm256_loadu_si256((
        const __m256i*)WC_PR(r13, rbx)));
    y28 = _mm256_madd_epi16(_mm512_castsi512_si256(z0), _mm256_loadu_si256((
        const __m256i*)WC_PR(r14, rbx)));
    y29 = _mm256_madd_epi16(_mm512_castsi512_si256(z0), _mm256_loadu_si256((
        const __m256i*)WC_PR(r15, rbx)));
L_frodokem_mul_bs_avx512_tail:
    z1 = _mm512_zextsi256_si512(_mm512_extracti64x4_epi64(z14, 1));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z14),
        _mm512_castsi512_si256(z1)));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z1),
        y22));
    z0 = _mm512_zextsi128_si512(_mm256_extracti128_si256(_mm512_castsi512_si256(
        z1), 1));
    x2 = _mm_add_epi32(_mm512_castsi512_si128(z1), _mm512_castsi512_si128(z0));
    z1 = _mm512_zextsi256_si512(_mm512_extracti64x4_epi64(z15, 1));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z15),
        _mm512_castsi512_si256(z1)));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z1),
        y23));
    z0 = _mm512_zextsi128_si512(_mm256_extracti128_si256(_mm512_castsi512_si256(
        z1), 1));
    x3 = _mm_add_epi32(_mm512_castsi512_si128(z1), _mm512_castsi512_si128(z0));
    z1 = _mm512_zextsi256_si512(_mm512_extracti64x4_epi64(z16, 1));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z16),
        _mm512_castsi512_si256(z1)));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z1),
        y24));
    z0 = _mm512_zextsi128_si512(_mm256_extracti128_si256(_mm512_castsi512_si256(
        z1), 1));
    x4 = _mm_add_epi32(_mm512_castsi512_si128(z1), _mm512_castsi512_si128(z0));
    z1 = _mm512_zextsi256_si512(_mm512_extracti64x4_epi64(z17, 1));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z17),
        _mm512_castsi512_si256(z1)));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z1),
        y25));
    z0 = _mm512_zextsi128_si512(_mm256_extracti128_si256(_mm512_castsi512_si256(
        z1), 1));
    x5 = _mm_add_epi32(_mm512_castsi512_si128(z1), _mm512_castsi512_si128(z0));
    z1 = _mm512_zextsi256_si512(_mm512_extracti64x4_epi64(z18, 1));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z18),
        _mm512_castsi512_si256(z1)));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z1),
        y26));
    z0 = _mm512_zextsi128_si512(_mm256_extracti128_si256(_mm512_castsi512_si256(
        z1), 1));
    x6 = _mm_add_epi32(_mm512_castsi512_si128(z1), _mm512_castsi512_si128(z0));
    z1 = _mm512_zextsi256_si512(_mm512_extracti64x4_epi64(z19, 1));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z19),
        _mm512_castsi512_si256(z1)));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z1),
        y27));
    z0 = _mm512_zextsi128_si512(_mm256_extracti128_si256(_mm512_castsi512_si256(
        z1), 1));
    x7 = _mm_add_epi32(_mm512_castsi512_si128(z1), _mm512_castsi512_si128(z0));
    z1 = _mm512_zextsi256_si512(_mm512_extracti64x4_epi64(z20, 1));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z20),
        _mm512_castsi512_si256(z1)));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z1),
        y28));
    z0 = _mm512_zextsi128_si512(_mm256_extracti128_si256(_mm512_castsi512_si256(
        z1), 1));
    x8 = _mm_add_epi32(_mm512_castsi512_si128(z1), _mm512_castsi512_si128(z0));
    z1 = _mm512_zextsi256_si512(_mm512_extracti64x4_epi64(z21, 1));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z21),
        _mm512_castsi512_si256(z1)));
    z1 = _mm512_zextsi256_si512(_mm256_add_epi32(_mm512_castsi512_si256(z1),
        y29));
    z0 = _mm512_zextsi128_si512(_mm256_extracti128_si256(_mm512_castsi512_si256(
        z1), 1));
    x9 = _mm_add_epi32(_mm512_castsi512_si128(z1), _mm512_castsi512_si128(z0));
    x11 = _mm_hadd_epi32(x2, x3);
    x12 = _mm_hadd_epi32(x4, x5);
    x10 = _mm_hadd_epi32(x11, x12);
    x11 = _mm_hadd_epi32(x6, x7);
    x12 = _mm_hadd_epi32(x8, x9);
    x11 = _mm_hadd_epi32(x11, x12);
    x10 = _mm_and_si128(x10, x13);
    x11 = _mm_and_si128(x11, x13);
    x10 = _mm_packus_epi32(x10, x11);
    _mm_storeu_si128((__m128i*)WC_PW(rdi, 0), x10);
    rsi = (word64)(rsi + rax);
    rdi = (word64)(rdi + 0x10);
    rbp = (word64)(rbp - 1);
    if ((rbp) != (0)) {
        goto L_frodokem_mul_bs_avx512_r;
    }
}

WC_X64I_TARGET("avx512f,avx512bw")
WOLFSSL_LOCAL void frodokem_mul_add_sb_plus_e_avx512(word16* out,
    const word16* b, const word16* s, int n, int qmask)
{
    word64 rdi, rsi, rdx, rcx, r8, rax, r9, r10, r11, r12, r13, r14, r15, rbx;
    __m512i z0, z1, z2 = _mm512_setzero_si512(), z3 = _mm512_setzero_si512(),
            z4 = _mm512_setzero_si512(), z5;

    rdi = (word64)(size_t)out;
    rsi = (word64)(size_t)b;
    rdx = (word64)(size_t)s;
    rcx = (word64)(word32)n;
    r8 = (word64)(word32)qmask;

    rax = (word64)((word64)(sword64)(sword32)(word32)rcx);
    rax = (word64)(rax << 1);
    r9 = (word64)(rdx);
    r9 = (word64)(r9 + rax);
    r10 = (word64)(r9);
    r10 = (word64)(r10 + rax);
    r11 = (word64)(r10);
    r11 = (word64)(r11 + rax);
    r12 = (word64)(r11);
    r12 = (word64)(r12 + rax);
    r13 = (word64)(r12);
    r13 = (word64)(r13 + rax);
    r14 = (word64)(r13);
    r14 = (word64)(r14 + rax);
    r15 = (word64)(r14);
    r15 = (word64)(r15 + rax);
    z5 = _mm512_zextsi128_si512(_mm_cvtsi32_si128((int)(word32)r8));
    z5 = _mm512_broadcastw_epi16(_mm512_castsi512_si128(z5));
    z0 = _mm512_loadu_si512((const void*)WC_PR(rdi, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(rdi, 64));
    rbx = (word64)(0);
L_frodokem_mul_add_sb_plus_e_avx512_j:
    z2 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rsi, 0)));
    z3 = _mm512_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        rbx)));
    z4 = _mm512_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        rbx)));
    z3 = _mm512_inserti32x4(z3, _mm512_castsi512_si128(z4), 1);
    z4 = _mm512_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        rbx)));
    z3 = _mm512_inserti32x4(z3, _mm512_castsi512_si128(z4), 2);
    z4 = _mm512_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(r11,
        rbx)));
    z3 = _mm512_inserti32x4(z3, _mm512_castsi512_si128(z4), 3);
    z4 = _mm512_mullo_epi16(z3, z2);
    z0 = _mm512_add_epi16(z0, z4);
    z3 = _mm512_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(r12,
        rbx)));
    z4 = _mm512_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(r13,
        rbx)));
    z3 = _mm512_inserti32x4(z3, _mm512_castsi512_si128(z4), 1);
    z4 = _mm512_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(r14,
        rbx)));
    z3 = _mm512_inserti32x4(z3, _mm512_castsi512_si128(z4), 2);
    z4 = _mm512_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(r15,
        rbx)));
    z3 = _mm512_inserti32x4(z3, _mm512_castsi512_si128(z4), 3);
    z4 = _mm512_mullo_epi16(z3, z2);
    z1 = _mm512_add_epi16(z1, z4);
    rsi = (word64)(rsi + 0x10);
    rbx = (word64)(rbx + 2);
    if ((sword64)(rbx) < (sword64)(rax)) {
        goto L_frodokem_mul_add_sb_plus_e_avx512_j;
    }
    z0 = _mm512_and_si512(z0, z5);
    _mm512_storeu_si512((void*)WC_PW(rdi, 0), z0);
    z1 = _mm512_and_si512(z1, z5);
    _mm512_storeu_si512((void*)WC_PW(rdi, 64), z1);
}

WC_X64I_TARGET("avx512f,avx512bw")
WOLFSSL_LOCAL void frodokem_add_avx512(word16* a, const word16* b, int qmask)
{
    word64 rdi, rsi, rdx;
    __m512i z0, z1, z2;

    rdi = (word64)(size_t)a;
    rsi = (word64)(size_t)b;
    rdx = (word64)(word32)qmask;

    z0 = _mm512_zextsi128_si512(_mm_cvtsi32_si128((int)(word32)rdx));
    z0 = _mm512_broadcastw_epi16(_mm512_castsi512_si128(z0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(rdi, 0));
    z1 = _mm512_add_epi16(z1, _mm512_loadu_si512((const void*)WC_PR(rsi, 0)));
    z1 = _mm512_and_si512(z1, z0);
    _mm512_storeu_si512((void*)WC_PW(rdi, 0), z1);
    z2 = _mm512_loadu_si512((const void*)WC_PR(rdi, 64));
    z2 = _mm512_add_epi16(z2, _mm512_loadu_si512((const void*)WC_PR(rsi, 64)));
    z2 = _mm512_and_si512(z2, z0);
    _mm512_storeu_si512((void*)WC_PW(rdi, 64), z2);
}

WC_X64I_TARGET("avx512f,avx512bw")
WOLFSSL_LOCAL void frodokem_sample_avx512(word16* mat, int cnt,
    const word16* cdf, int cdflen)
{
    word64 rdi, rsi, rdx, rcx, rax, r8, r9 = 0, r10 = 0;
    __m512i z0 = _mm512_setzero_si512(), z1, z2 = _mm512_setzero_si512(),
            z3 = _mm512_setzero_si512(), z4 = _mm512_setzero_si512(),
            z5 = _mm512_setzero_si512(), z6 = _mm512_setzero_si512(),
            z7 = _mm512_setzero_si512();

    rdi = (word64)(size_t)mat;
    rsi = (word64)(word32)cnt;
    rdx = (word64)(size_t)cdf;
    rcx = (word64)(word32)cdflen;

    rax = (word64)((word64)(sword64)(sword32)(word32)rsi);
    rax = (word64)(rax << 1);
    z0 = _mm512_ternarylogic_epi32(z0, z0, z0, 0xff);
    z0 = _mm512_srli_epi16(z0, 15);
    z1 = _mm512_setzero_si512();
    r8 = (word64)(0);
L_frodokem_sample_avx512_blk:
    z2 = _mm512_loadu_si512((const void*)WC_PR(rdi, r8));
    z3 = _mm512_srli_epi16(z2, 1);
    z4 = _mm512_and_si512(z2, z0);
    z5 = _mm512_setzero_si512();
    r9 = (word64)(rdx);
    r10 = (word32)((word32)rcx);
L_frodokem_sample_avx512_cdf:
    z6 = _mm512_broadcastw_epi16(_mm_loadu_si128((const __m128i*)WC_PR(r9, 0)));
    z6 = _mm512_sub_epi16(z6, z3);
    z6 = _mm512_srli_epi16(z6, 15);
    z5 = _mm512_add_epi16(z5, z6);
    r9 = (word64)(r9 + 2);
    r10 = (word64)(r10 - 1);
    if ((r10) != (0)) {
        goto L_frodokem_sample_avx512_cdf;
    }
    z7 = _mm512_sub_epi16(z1, z4);
    z5 = _mm512_xor_si512(z5, z7);
    z5 = _mm512_add_epi16(z5, z4);
    _mm512_storeu_si512((void*)WC_PW(rdi, r8), z5);
    r8 = (word64)(r8 + 0x40);
    if ((sword64)(r8) < (sword64)(rax)) {
        goto L_frodokem_sample_avx512_blk;
    }
}

WC_X64I_TARGET("vaes,avx512f,avx512bw")
WOLFSSL_LOCAL void frodokem_gen_a_rows_aes_avx512(byte* in, word16* out,
    const byte* ks, int i, int cnt, int n, int qmask)
{
    word64 rdi, rsi, rdx, rcx, r8, r9, rax, r10, r11, r15, r12, r14 = 0,
           r13 = 0;
    __m512i z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10,
            z11 = _mm512_setzero_si512(), z12 = _mm512_setzero_si512(),
            z13 = _mm512_setzero_si512(), z14 = _mm512_setzero_si512(), z15;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(size_t)ks;
    rcx = (word64)(word32)i;
    r8 = (word64)(word32)cnt;
    r9 = (word64)(word32)n;
    rax = (word64)(word32)qmask;

    z0 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rdx, 0)));
    z1 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        16)));
    z2 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        32)));
    z3 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        48)));
    z4 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        64)));
    z5 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        80)));
    z6 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        96)));
    z7 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        112)));
    z8 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        128)));
    z9 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        144)));
    z10 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rdx,
        160)));
    z15 = _mm512_zextsi128_si512(_mm_cvtsi32_si128((int)(word32)rax));
    z15 = _mm512_broadcastw_epi16(_mm512_castsi512_si128(z15));
    r10 = (word64)((word64)(sword64)(sword32)(word32)r9);
    r10 = (word64)(r10 << 1);
    r11 = (word64)((word64)(sword64)(sword32)(word32)r8);
    r11 = (word64)(r11 * r10);
    rcx = (word64)((word64)(sword64)(sword32)(word32)rcx);
    r15 = (word64)(0);
    r12 = (word64)(rdi);
L_frodokem_gen_a_rows_aes_avx512_row:
    r14 = (word32)((word32)rcx);
    r13 = (word64)(r12);
    r13 = (word64)(r13 + r10);
L_frodokem_gen_a_rows_aes_avx512_blk:
    WC_S64(r12, 0) = (word64)(r14);
    WC_S64(r12, 8) = (word64)(r15);
    r14 = (word64)(r14 + 0x80000);
    r12 = (word64)(r12 + 0x10);
    if ((sword64)(r12) < (sword64)(r13)) {
        goto L_frodokem_gen_a_rows_aes_avx512_blk;
    }
    rcx = (word64)(rcx + 1);
    r13 = (word64)(rdi);
    r13 = (word64)(r13 + r11);
    if ((sword64)(r12) < (sword64)(r13)) {
        goto L_frodokem_gen_a_rows_aes_avx512_row;
    }
    r14 = (word64)(0);
L_frodokem_gen_a_rows_aes_avx512_aes:
    z11 = _mm512_loadu_si512((const void*)WC_PR(rdi, 0));
    z12 = _mm512_loadu_si512((const void*)WC_PR(rdi, 64));
    z13 = _mm512_loadu_si512((const void*)WC_PR(rdi, 128));
    z14 = _mm512_loadu_si512((const void*)WC_PR(rdi, 192));
    z11 = _mm512_xor_si512(z11, z0);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z0);
    z14 = _mm512_xor_si512(z14, z0);
    z11 = _mm512_aesenc_epi128(z11, z1);
    z12 = _mm512_aesenc_epi128(z12, z1);
    z13 = _mm512_aesenc_epi128(z13, z1);
    z14 = _mm512_aesenc_epi128(z14, z1);
    z11 = _mm512_aesenc_epi128(z11, z2);
    z12 = _mm512_aesenc_epi128(z12, z2);
    z13 = _mm512_aesenc_epi128(z13, z2);
    z14 = _mm512_aesenc_epi128(z14, z2);
    z11 = _mm512_aesenc_epi128(z11, z3);
    z12 = _mm512_aesenc_epi128(z12, z3);
    z13 = _mm512_aesenc_epi128(z13, z3);
    z14 = _mm512_aesenc_epi128(z14, z3);
    z11 = _mm512_aesenc_epi128(z11, z4);
    z12 = _mm512_aesenc_epi128(z12, z4);
    z13 = _mm512_aesenc_epi128(z13, z4);
    z14 = _mm512_aesenc_epi128(z14, z4);
    z11 = _mm512_aesenc_epi128(z11, z5);
    z12 = _mm512_aesenc_epi128(z12, z5);
    z13 = _mm512_aesenc_epi128(z13, z5);
    z14 = _mm512_aesenc_epi128(z14, z5);
    z11 = _mm512_aesenc_epi128(z11, z6);
    z12 = _mm512_aesenc_epi128(z12, z6);
    z13 = _mm512_aesenc_epi128(z13, z6);
    z14 = _mm512_aesenc_epi128(z14, z6);
    z11 = _mm512_aesenc_epi128(z11, z7);
    z12 = _mm512_aesenc_epi128(z12, z7);
    z13 = _mm512_aesenc_epi128(z13, z7);
    z14 = _mm512_aesenc_epi128(z14, z7);
    z11 = _mm512_aesenc_epi128(z11, z8);
    z12 = _mm512_aesenc_epi128(z12, z8);
    z13 = _mm512_aesenc_epi128(z13, z8);
    z14 = _mm512_aesenc_epi128(z14, z8);
    z11 = _mm512_aesenc_epi128(z11, z9);
    z12 = _mm512_aesenc_epi128(z12, z9);
    z13 = _mm512_aesenc_epi128(z13, z9);
    z14 = _mm512_aesenc_epi128(z14, z9);
    z11 = _mm512_aesenclast_epi128(z11, z10);
    z12 = _mm512_aesenclast_epi128(z12, z10);
    z13 = _mm512_aesenclast_epi128(z13, z10);
    z14 = _mm512_aesenclast_epi128(z14, z10);
    z11 = _mm512_and_si512(z11, z15);
    z12 = _mm512_and_si512(z12, z15);
    z13 = _mm512_and_si512(z13, z15);
    z14 = _mm512_and_si512(z14, z15);
    _mm512_storeu_si512((void*)WC_PW(rsi, 0), z11);
    _mm512_storeu_si512((void*)WC_PW(rsi, 64), z12);
    _mm512_storeu_si512((void*)WC_PW(rsi, 128), z13);
    _mm512_storeu_si512((void*)WC_PW(rsi, 192), z14);
    rdi = (word64)(rdi + 0x100);
    rsi = (word64)(rsi + 0x100);
    r14 = (word64)(r14 + 0x100);
    if ((sword64)(r14) < (sword64)(r11)) {
        goto L_frodokem_gen_a_rows_aes_avx512_aes;
    }
}

#endif /* HAVE_INTEL_AVX512 */
#endif /* WOLFSSL_HAVE_FRODOKEM */

#undef WC_PR
#undef WC_PW
#undef WC_L8
#undef WC_L16
#undef WC_L32
#undef WC_L64
#undef WC_S8
#undef WC_S16
#undef WC_S32
#undef WC_S64
#undef WC_X64I_TARGET
#undef WC_X64I_UNUSED
#undef WC_X64I_MUL128
#undef WC_X64I_POPCNT32
#undef WC_X64I_POPCNT64
#undef WC_X64I_BSR64
#undef WC_X64I_BSWAP64
#undef WC_X64I_DIV128

#endif /* WOLFSSL_X86_64_BUILD */
