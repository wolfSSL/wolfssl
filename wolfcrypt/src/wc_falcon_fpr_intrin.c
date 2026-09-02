/* wc_falcon_fpr_intrin.c */
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

#define _WC_BUILDING_WC_FALCON_FPR_INTRIN_C

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef WOLFSSL_X86_64_BUILD

#ifdef _MSC_VER
    /* _umul128, __popcnt and _BitScanReverse64 live here. */
    #include <intrin.h>
#endif
#include <immintrin.h>
#include <wolfssl/wolfcrypt/falcon.h>

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

#if defined(HAVE_FALCON) && defined(WOLFSSL_FALCON_FPR_ASM)
extern WOLFSSL_LOCAL word64 fpr_add(word64 x, word64 y);
extern WOLFSSL_LOCAL word64 fpr_sub(word64 x, word64 y);
extern WOLFSSL_LOCAL word64 fpr_neg(word64 x);
extern WOLFSSL_LOCAL word64 fpr_half(word64 x);
extern WOLFSSL_LOCAL word64 fpr_double(word64 x);
extern WOLFSSL_LOCAL word64 fpr_mul(word64 x, word64 y);
extern WOLFSSL_LOCAL word64 fpr_sqr(word64 x);
extern WOLFSSL_LOCAL word64 fpr_div(word64 x, word64 y);
extern WOLFSSL_LOCAL word64 fpr_inv(word64 x);
extern WOLFSSL_LOCAL word64 fpr_sqrt(word64 x);
extern WOLFSSL_LOCAL word64 fpr_of(sword64 i);
extern WOLFSSL_LOCAL sword64 fpr_rint(word64 x);
extern WOLFSSL_LOCAL sword64 fpr_floor(word64 x);
extern WOLFSSL_LOCAL sword64 fpr_trunc(word64 x);
extern WOLFSSL_LOCAL int fpr_lt(word64 x, word64 y);

#endif
#if defined(HAVE_FALCON) && defined(WOLFSSL_FALCON_FPR_ASM)
/* Native x86_64 (SSE2 scalar-double) backend for the Falcon fpr
 * seam.  Generated by wolfssl-scripts: falcon/x86_64/falcon.rb.
 * Each routine is bit-exact with the round-to-nearest-even
 * IEEE-754 emulation in wolfcrypt/src/wc_falcon_fpr.c on all values
 * Falcon exercises (no subnormals, no NaN/Inf).
 *
 * SysV AMD64 ABI only (operands in RDI/RSI, result in RAX); not
 * MSVC/Win64.  Requires the default MXCSR (round-to-nearest-even, FP
 * exceptions masked, FTZ/DAZ off) -- the standard C runtime state.
 * DO NOT EDIT. */

WC_X64I_TARGET("sse2")
WOLFSSL_LOCAL word64 fpr_add(word64 x, word64 y)
{
    word64 rdi, rsi, rax;
    __m128i x0, x1;

    rsi = (word64)(word64)y;
    rdi = (word64)(word64)x;
    /* r = x + y */
    x0 = _mm_cvtsi64_si128((long long)rdi);
    x1 = _mm_cvtsi64_si128((long long)rsi);
    x0 = _mm_castpd_si128(_mm_add_sd(_mm_castsi128_pd(x0), _mm_castsi128_pd(
        x1)));
    rax = (word64)((word64)_mm_cvtsi128_si64(x0));
    return (word64)(word64)rax;
}

WC_X64I_TARGET("sse2")
WOLFSSL_LOCAL word64 fpr_sub(word64 x, word64 y)
{
    word64 rdi, rsi, rax;
    __m128i x0, x1;

    rsi = (word64)(word64)y;
    rdi = (word64)(word64)x;
    /* r = x - y */
    x0 = _mm_cvtsi64_si128((long long)rdi);
    x1 = _mm_cvtsi64_si128((long long)rsi);
    x0 = _mm_castpd_si128(_mm_sub_sd(_mm_castsi128_pd(x0), _mm_castsi128_pd(
        x1)));
    rax = (word64)((word64)_mm_cvtsi128_si64(x0));
    return (word64)(word64)rax;
}

WC_X64I_TARGET("sse2")
WOLFSSL_LOCAL word64 fpr_neg(word64 x)
{
    word64 rdi, rax;
    __m128i x0, x1;

    rdi = (word64)(word64)x;
    /* r = -x  (flip the sign bit) */
    x0 = _mm_cvtsi64_si128((long long)rdi);
    rax = (word64)(0x8000000000000000ULL);
    x1 = _mm_cvtsi64_si128((long long)rax);
    x0 = _mm_xor_si128(x0, x1);
    rax = (word64)((word64)_mm_cvtsi128_si64(x0));
    return (word64)(word64)rax;
}

WC_X64I_TARGET("sse2")
WOLFSSL_LOCAL word64 fpr_half(word64 x)
{
    word64 rdi, rax;
    __m128i x0, x1;

    rdi = (word64)(word64)x;
    /* r = x * 0.5 */
    x0 = _mm_cvtsi64_si128((long long)rdi);
    rax = (word64)(0x3fe0000000000000ULL);
    x1 = _mm_cvtsi64_si128((long long)rax);
    x0 = _mm_castpd_si128(_mm_mul_sd(_mm_castsi128_pd(x0), _mm_castsi128_pd(
        x1)));
    rax = (word64)((word64)_mm_cvtsi128_si64(x0));
    return (word64)(word64)rax;
}

WC_X64I_TARGET("sse2")
WOLFSSL_LOCAL word64 fpr_double(word64 x)
{
    word64 rdi, rax;
    __m128i x0;

    rdi = (word64)(word64)x;
    /* r = x + x */
    x0 = _mm_cvtsi64_si128((long long)rdi);
    x0 = _mm_castpd_si128(_mm_add_sd(_mm_castsi128_pd(x0), _mm_castsi128_pd(
        x0)));
    rax = (word64)((word64)_mm_cvtsi128_si64(x0));
    return (word64)(word64)rax;
}

WC_X64I_TARGET("sse2")
WOLFSSL_LOCAL word64 fpr_mul(word64 x, word64 y)
{
    word64 rdi, rsi, rax;
    __m128i x0, x1;

    rsi = (word64)(word64)y;
    rdi = (word64)(word64)x;
    /* r = x * y */
    x0 = _mm_cvtsi64_si128((long long)rdi);
    x1 = _mm_cvtsi64_si128((long long)rsi);
    x0 = _mm_castpd_si128(_mm_mul_sd(_mm_castsi128_pd(x0), _mm_castsi128_pd(
        x1)));
    rax = (word64)((word64)_mm_cvtsi128_si64(x0));
    return (word64)(word64)rax;
}

WC_X64I_TARGET("sse2")
WOLFSSL_LOCAL word64 fpr_sqr(word64 x)
{
    word64 rdi, rax;
    __m128i x0;

    rdi = (word64)(word64)x;
    /* r = x * x */
    x0 = _mm_cvtsi64_si128((long long)rdi);
    x0 = _mm_castpd_si128(_mm_mul_sd(_mm_castsi128_pd(x0), _mm_castsi128_pd(
        x0)));
    rax = (word64)((word64)_mm_cvtsi128_si64(x0));
    return (word64)(word64)rax;
}

WC_X64I_TARGET("sse2")
WOLFSSL_LOCAL word64 fpr_div(word64 x, word64 y)
{
    word64 rdi, rsi, rax;
    __m128i x0, x1;

    rsi = (word64)(word64)y;
    rdi = (word64)(word64)x;
    /* r = x / y */
    x0 = _mm_cvtsi64_si128((long long)rdi);
    x1 = _mm_cvtsi64_si128((long long)rsi);
    x0 = _mm_castpd_si128(_mm_div_sd(_mm_castsi128_pd(x0), _mm_castsi128_pd(
        x1)));
    rax = (word64)((word64)_mm_cvtsi128_si64(x0));
    return (word64)(word64)rax;
}

WC_X64I_TARGET("sse2")
WOLFSSL_LOCAL word64 fpr_inv(word64 x)
{
    word64 rax, rdi;
    __m128i x0, x1;

    rdi = (word64)(word64)x;
    /* r = 1.0 / x */
    rax = (word64)(0x3ff0000000000000ULL);
    x1 = _mm_cvtsi64_si128((long long)rax);
    x0 = _mm_cvtsi64_si128((long long)rdi);
    x1 = _mm_castpd_si128(_mm_div_sd(_mm_castsi128_pd(x1), _mm_castsi128_pd(
        x0)));
    rax = (word64)((word64)_mm_cvtsi128_si64(x1));
    return (word64)(word64)rax;
}

WC_X64I_TARGET("sse2")
WOLFSSL_LOCAL word64 fpr_sqrt(word64 x)
{
    word64 rdi, rax;
    __m128i x0;

    rdi = (word64)(word64)x;
    /* r = sqrt(x)  (operand assumed non-negative) */
    x0 = _mm_cvtsi64_si128((long long)rdi);
    x0 = _mm_castpd_si128(_mm_sqrt_sd(_mm_castsi128_pd(x0), _mm_castsi128_pd(
        x0)));
    rax = (word64)((word64)_mm_cvtsi128_si64(x0));
    return (word64)(word64)rax;
}

WC_X64I_TARGET("sse2")
WOLFSSL_LOCAL word64 fpr_of(sword64 i)
{
    word64 rdi, rax;
    __m128i x0 = _mm_setzero_si128();

    rdi = (word64)(word64)i;
    /* r = (double)i  (round-to-nearest-even) */
    x0 = _mm_castpd_si128(_mm_cvtsi64_sd(_mm_castsi128_pd(x0), (long long)rdi));
    rax = (word64)((word64)_mm_cvtsi128_si64(x0));
    return (word64)(word64)rax;
}

WC_X64I_TARGET("sse2")
WOLFSSL_LOCAL sword64 fpr_rint(word64 x)
{
    word64 rdi, rax;
    __m128i x0;

    rdi = (word64)(word64)x;
    /* return = lrint(x)  (round-to-nearest, ties to even) */
    x0 = _mm_cvtsi64_si128((long long)rdi);
    rax = (word64)((word64)_mm_cvtsd_si64(_mm_castsi128_pd(x0)));
    return (sword64)(word64)rax;
}

WC_X64I_TARGET("sse2")
WOLFSSL_LOCAL sword64 fpr_floor(word64 x)
{
    word64 rdi, rax;
    __m128i x0, x1 = _mm_setzero_si128();
    unsigned char cf;

    rdi = (word64)(word64)x;
    /* return = floor(x)  (round toward -inf), pure SSE2 */
    x0 = _mm_cvtsi64_si128((long long)rdi);
    /* t = trunc(x) toward zero */
    rax = (word64)((word64)_mm_cvttsd_si64(_mm_castsi128_pd(x0)));
    /* tf = (double)t */
    x1 = _mm_castpd_si128(_mm_cvtsi64_sd(_mm_castsi128_pd(x1), (long long)rax));
    /* when x < tf, subtract 1 from t (negative non-integers only) */
    cf = _subborrow_u64((unsigned char)(!(_mm_cvtsd_f64(_mm_castsi128_pd(
        x0)) >= _mm_cvtsd_f64(_mm_castsi128_pd(x1)))), rax, 0, (
        unsigned long long*)&rax);
    return (sword64)(word64)rax;
    (void)cf;
}

WC_X64I_TARGET("sse2")
WOLFSSL_LOCAL sword64 fpr_trunc(word64 x)
{
    word64 rdi, rax;
    __m128i x0;

    rdi = (word64)(word64)x;
    /* return = trunc(x)  (round toward zero) */
    x0 = _mm_cvtsi64_si128((long long)rdi);
    rax = (word64)((word64)_mm_cvttsd_si64(_mm_castsi128_pd(x0)));
    return (sword64)(word64)rax;
}

WC_X64I_TARGET("sse2")
WOLFSSL_LOCAL int fpr_lt(word64 x, word64 y)
{
    word64 rdi, rsi, rax;
    __m128i x0, x1;

    rsi = (word64)(word64)y;
    rdi = (word64)(word64)x;
    /* return = (x < y) ? 1 : 0 */
    x0 = _mm_cvtsi64_si128((long long)rdi);
    x1 = _mm_cvtsi64_si128((long long)rsi);
    /* clear eax (and flags) before the ordered compare */
    rax = (word32)(0);
    /* CF is set iff x < y */
    rax = (rax & ~(word64)0xff) | ((word64)(byte)((byte)((unsigned char)(!(
        _mm_cvtsd_f64(_mm_castsi128_pd(x0)) >= _mm_cvtsd_f64(_mm_castsi128_pd(
        x1)))))) & 0xff);
    return (int)(word32)rax;
}

#endif /* HAVE_FALCON && WOLFSSL_FALCON_FPR_ASM */

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
