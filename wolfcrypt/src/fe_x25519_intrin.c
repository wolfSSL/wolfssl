/* fe_x25519_intrin.c */
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

#define WC_FIPS_LL_CRYPTO
#define _WC_BUILDING_FE_X25519_INTRIN_C

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef WOLFSSL_X86_64_BUILD

#ifdef _MSC_VER
    /* _umul128, __popcnt and _BitScanReverse64 live here. */
    #include <intrin.h>
#endif
#include <immintrin.h>
#include <wolfssl/wolfcrypt/fe_operations.h>
#include <wolfssl/wolfcrypt/ge_operations.h>
#include <wolfssl/wolfcrypt/cpuid.h>

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

extern WOLFSSL_LOCAL void fe_init(void);
extern WOLFSSL_LOCAL void fe_frombytes(fe out, const unsigned char* in);
extern WOLFSSL_LOCAL void fe_tobytes(unsigned char* out, const fe n);
extern WOLFSSL_LOCAL void fe_1(fe n);
extern WOLFSSL_LOCAL void fe_0(fe n);
extern WOLFSSL_LOCAL void fe_copy(fe r, const fe a);
extern WOLFSSL_LOCAL void fe_sub(fe r, const fe a, const fe b);
extern WOLFSSL_LOCAL void fe_add(fe r, const fe a, const fe b);
extern WOLFSSL_LOCAL void fe_neg(fe r, const fe a);
extern WOLFSSL_LOCAL void fe_cmov(fe a, const fe b, int c);
extern WOLFSSL_LOCAL int fe_isnonzero(const fe a);
extern WOLFSSL_LOCAL int fe_isnegative(const fe a);
extern WOLFSSL_LOCAL void fe_cmov_table(fe* r, const fe* base, signed char b);
extern WOLFSSL_LOCAL void fe_mul(fe r, const fe a, const fe b);
extern WOLFSSL_LOCAL void fe_sq(fe r, const fe a);
extern WOLFSSL_LOCAL void fe_mul121666(fe r, fe a);
extern WOLFSSL_LOCAL void fe_invert(fe r, const fe a);
extern WOLFSSL_LOCAL int curve25519(byte* r, const byte* n, const byte* a);
extern WOLFSSL_LOCAL void fe_pow22523(fe r, const fe a);
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
extern WOLFSSL_LOCAL void ge_p1p1_to_p2(ge_p2* r, const ge_p1p1* p);
extern WOLFSSL_LOCAL void ge_p1p1_to_p3(ge_p3* r, const ge_p1p1* p);
extern WOLFSSL_LOCAL void ge_p2_dbl(ge_p1p1* r, const ge_p2* p);
extern WOLFSSL_LOCAL void ge_madd(ge_p1p1* r, const ge_p3* p,
    const ge_precomp* q);
extern WOLFSSL_LOCAL void ge_msub(ge_p1p1* r, const ge_p3* p,
    const ge_precomp* q);
extern WOLFSSL_LOCAL void ge_add(ge_p1p1* r, const ge_p3* p,
    const ge_cached* q);
extern WOLFSSL_LOCAL void ge_sub(ge_p1p1* r, const ge_p3* p,
    const ge_cached* q);
#endif
#if defined(WOLFSSL_CURVE25519_NOT_USE_ED25519)
#if defined(WOLFSSL_CURVE25519_NOT_USE_ED25519)
extern WOLFSSL_LOCAL int curve25519_base(byte* r, const byte* n);
#endif
#endif
#ifdef HAVE_ED25519
#ifdef HAVE_ED25519
extern WOLFSSL_LOCAL void fe_sq2(fe r, const fe a);
extern WOLFSSL_LOCAL void fe_invert_nct(fe r, const fe a);
extern WOLFSSL_LOCAL void sc_reduce(byte* s);
extern WOLFSSL_LOCAL void sc_muladd(byte* s, const byte* a, const byte* b,
    const byte* c);
#endif
#endif
extern WOLFSSL_LOCAL void fe_cmov_table_x64(fe* r, const fe* base,
    signed char b);
extern WOLFSSL_LOCAL void fe_mul_x64(fe r, fe a, fe b);
extern WOLFSSL_LOCAL void fe_sq_x64(fe r, fe a);
extern WOLFSSL_LOCAL void fe_sq_n_x64(fe r, const fe a, word64 n);
extern WOLFSSL_LOCAL void fe_mul121666_x64(fe r, fe a);
extern WOLFSSL_LOCAL void fe_invert_x64(fe r, const fe a);
#if defined(WOLFSSL_CURVE25519_NOT_USE_ED25519)
extern WOLFSSL_LOCAL int curve25519_base_x64(byte* r, byte* n);
#endif
extern WOLFSSL_LOCAL int curve25519_x64(byte* r, byte* n, byte* a);
extern WOLFSSL_LOCAL void fe_pow22523_x64(fe r, const fe a);
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
extern WOLFSSL_LOCAL void ge_p1p1_to_p2_x64(ge_p2* r, const ge_p1p1* p);
extern WOLFSSL_LOCAL void ge_p1p1_to_p3_x64(ge_p3* r, const ge_p1p1* p);
extern WOLFSSL_LOCAL void ge_p2_dbl_x64(ge_p1p1* r, const ge_p2* p);
extern WOLFSSL_LOCAL void ge_madd_x64(ge_p1p1* r, const ge_p3* p,
    const ge_precomp* q);
extern WOLFSSL_LOCAL void ge_msub_x64(ge_p1p1* r, const ge_p3* p,
    const ge_precomp* q);
extern WOLFSSL_LOCAL void ge_add_x64(ge_p1p1* r, const ge_p3* p,
    const fe qe_cached);
extern WOLFSSL_LOCAL void ge_sub_x64(ge_p1p1* r, const ge_p3* p,
    const fe qe_cached);
#endif
#ifdef HAVE_ED25519
extern WOLFSSL_LOCAL void fe_sq2_x64(fe r, fe a);
extern WOLFSSL_LOCAL void sc_reduce_x64(byte* s);
extern WOLFSSL_LOCAL void sc_muladd_x64(byte* s, byte* a, byte* b, byte* c);
extern WOLFSSL_LOCAL void fe_invert_nct_x64(word64* r, const word64* a);
#endif
#ifdef HAVE_INTEL_AVX2
extern WOLFSSL_LOCAL void fe_cmov_table_avx2(fe* r, const fe* base,
    signed char b);
extern WOLFSSL_LOCAL void fe_mul_avx2(fe r, fe a, fe b);
extern WOLFSSL_LOCAL void fe_sq_avx2(fe r, fe a);
extern WOLFSSL_LOCAL void fe_sq_n_avx2(fe r, const fe a, word64 n);
extern WOLFSSL_LOCAL void fe_mul121666_avx2(fe r, fe a);
extern WOLFSSL_LOCAL void fe_invert_avx2(fe r, const fe a);
#if defined(WOLFSSL_CURVE25519_NOT_USE_ED25519)
extern WOLFSSL_LOCAL int curve25519_base_avx2(byte* r, byte* n);
#endif
extern WOLFSSL_LOCAL int curve25519_avx2(byte* r, byte* n, byte* a);
extern WOLFSSL_LOCAL void fe_pow22523_avx2(fe r, const fe a);
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
extern WOLFSSL_LOCAL void ge_p1p1_to_p2_avx2(ge_p2* r, const ge_p1p1* p);
extern WOLFSSL_LOCAL void ge_p1p1_to_p3_avx2(ge_p3* r, const ge_p1p1* p);
extern WOLFSSL_LOCAL void ge_p2_dbl_avx2(ge_p1p1* r, const ge_p2* p);
extern WOLFSSL_LOCAL void ge_madd_avx2(ge_p1p1* r, const ge_p3* p,
    const ge_precomp* q);
extern WOLFSSL_LOCAL void ge_msub_avx2(ge_p1p1* r, const ge_p3* p,
    const ge_precomp* q);
extern WOLFSSL_LOCAL void ge_add_avx2(ge_p1p1* r, const ge_p3* p,
    const fe qe_cached);
extern WOLFSSL_LOCAL void ge_sub_avx2(ge_p1p1* r, const ge_p3* p,
    const fe qe_cached);
#endif
#ifdef HAVE_ED25519
extern WOLFSSL_LOCAL void fe_sq2_avx2(fe r, fe a);
extern WOLFSSL_LOCAL void sc_reduce_avx2(byte* s);
extern WOLFSSL_LOCAL void sc_muladd_avx2(byte* s, byte* a, byte* b, byte* c);
extern WOLFSSL_LOCAL void fe_invert_nct_avx2(word64* r, const word64* a);
#endif
#ifdef HAVE_INTEL_AVX512_IFMA
#if defined(WOLFSSL_CURVE25519_NOT_USE_ED25519)
extern WOLFSSL_LOCAL int curve25519_base_avx512_ifma(byte* r, byte* n);
#endif
extern WOLFSSL_LOCAL int curve25519_avx512_ifma(byte* r, byte* n, byte* a);
#if defined(WOLFSSL_CURVE25519_NOT_USE_ED25519)
extern WOLFSSL_LOCAL int curve25519_base_avx512_ifma_dq(byte* r, byte* n);
#endif
extern WOLFSSL_LOCAL int curve25519_avx512_ifma_dq(byte* r, byte* n, byte* a);
#ifdef HAVE_ED25519
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
extern WOLFSSL_LOCAL int ge_double_scalarmult_vartime_avx512_ifma(ge_p2* r,
    const byte* a, const ge_p3* A, const byte* b, const ge_precomp* bi,
    byte* buf);
extern WOLFSSL_LOCAL int ge_double_scalarmult_vartime_avx512_ifma_dq(ge_p2* r,
    const byte* a, const ge_p3* A, const byte* b, const ge_precomp* bi,
    byte* buf);

#endif
#endif
#endif
#endif
static word32 cpuFlagsSet = 0;
static word32 intelFlags = 0;
static word64 fe_cmov_table_p = (word64)(size_t)fe_cmov_table_x64;
static word64 fe_mul_p = (word64)(size_t)fe_mul_x64;
static word64 fe_sq_p = (word64)(size_t)fe_sq_x64;
static word64 fe_mul121666_p = (word64)(size_t)fe_mul121666_x64;
static word64 fe_invert_p = (word64)(size_t)fe_invert_x64;
static word64 curve25519_p = (word64)(size_t)curve25519_x64;
static word64 fe_pow22523_p = (word64)(size_t)fe_pow22523_x64;
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
static word64 ge_p1p1_to_p2_p = (word64)(size_t)ge_p1p1_to_p2_x64;
static word64 ge_p1p1_to_p3_p = (word64)(size_t)ge_p1p1_to_p3_x64;
static word64 ge_p2_dbl_p = (word64)(size_t)ge_p2_dbl_x64;
static word64 ge_madd_p = (word64)(size_t)ge_madd_x64;
static word64 ge_msub_p = (word64)(size_t)ge_msub_x64;
static word64 ge_add_p = (word64)(size_t)ge_add_x64;
static word64 ge_sub_p = (word64)(size_t)ge_sub_x64;
#endif
#if defined(WOLFSSL_CURVE25519_NOT_USE_ED25519)
static word64 curve25519_base_p = (word64)(size_t)curve25519_base_x64;
#endif
#ifdef HAVE_ED25519
static word64 fe_sq2_p = (word64)(size_t)fe_sq2_x64;
static word64 fe_invert_nct_p = (word64)(size_t)fe_invert_nct_x64;
static word64 sc_reduce_p = (word64)(size_t)sc_reduce_x64;
static word64 sc_muladd_p = (word64)(size_t)sc_muladd_x64;

#endif
#ifndef NO_AVX512_SUPPORT
#ifndef NO_AVX512_IFMA_SUPPORT
#ifndef HAVE_INTEL_AVX512_IFMA
#define HAVE_INTEL_AVX512_IFMA
#endif /* HAVE_INTEL_AVX512_IFMA */
#endif /* NO_AVX512_IFMA_SUPPORT */
#endif /* NO_AVX512_SUPPORT */
WOLFSSL_LOCAL void fe_init(void)
{
    word64 rax;

#ifdef HAVE_INTEL_AVX2
    rax = (word32)((word32)cpuFlagsSet);
    if ((((word32)rax & (word32)rax)) == (0)) {
        goto L_fe_init_get_flags;
    }
    return;
L_fe_init_get_flags:
    rax = (word64)cpuid_get_flags();
    intelFlags = (word32)(word32)rax;
    rax = (word32)((word32)rax & 0x50);
    if (((word32)rax) != (0x50)) {
        goto L_fe_init_flags_done;
    }
    rax = (word64)((word64)(size_t)fe_cmov_table_avx2);
    fe_cmov_table_p = (word64)(size_t)rax;
    rax = (word64)((word64)(size_t)fe_mul_avx2);
    fe_mul_p = (word64)(size_t)rax;
    rax = (word64)((word64)(size_t)fe_sq_avx2);
    fe_sq_p = (word64)(size_t)rax;
    rax = (word64)((word64)(size_t)fe_mul121666_avx2);
    fe_mul121666_p = (word64)(size_t)rax;
    rax = (word64)((word64)(size_t)fe_invert_avx2);
    fe_invert_p = (word64)(size_t)rax;
    rax = (word64)((word64)(size_t)curve25519_avx2);
    curve25519_p = (word64)(size_t)rax;
    rax = (word64)((word64)(size_t)fe_pow22523_avx2);
    fe_pow22523_p = (word64)(size_t)rax;
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
    rax = (word64)((word64)(size_t)ge_p1p1_to_p2_avx2);
    ge_p1p1_to_p2_p = (word64)(size_t)rax;
    rax = (word64)((word64)(size_t)ge_p1p1_to_p3_avx2);
    ge_p1p1_to_p3_p = (word64)(size_t)rax;
    rax = (word64)((word64)(size_t)ge_p2_dbl_avx2);
    ge_p2_dbl_p = (word64)(size_t)rax;
    rax = (word64)((word64)(size_t)ge_madd_avx2);
    ge_madd_p = (word64)(size_t)rax;
    rax = (word64)((word64)(size_t)ge_msub_avx2);
    ge_msub_p = (word64)(size_t)rax;
    rax = (word64)((word64)(size_t)ge_add_avx2);
    ge_add_p = (word64)(size_t)rax;
    rax = (word64)((word64)(size_t)ge_sub_avx2);
    ge_sub_p = (word64)(size_t)rax;
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
#if defined(WOLFSSL_CURVE25519_NOT_USE_ED25519)
    rax = (word64)((word64)(size_t)curve25519_base_avx2);
    curve25519_base_p = (word64)(size_t)rax;
#endif /* WOLFSSL_CURVE25519_NOT_USE_ED25519 */
#ifdef HAVE_ED25519
    rax = (word64)((word64)(size_t)fe_sq2_avx2);
    fe_sq2_p = (word64)(size_t)rax;
    rax = (word64)((word64)(size_t)fe_invert_nct_avx2);
    fe_invert_nct_p = (word64)(size_t)rax;
    rax = (word64)((word64)(size_t)sc_reduce_avx2);
    sc_reduce_p = (word64)(size_t)rax;
    rax = (word64)((word64)(size_t)sc_muladd_avx2);
    sc_muladd_p = (word64)(size_t)rax;
#endif /* HAVE_ED25519 */
#ifdef HAVE_INTEL_AVX512_IFMA
    rax = (word32)((word32)intelFlags);
    rax = (word32)((word32)rax & 0x30800);
    if (((word32)rax) != (0x30800)) {
        goto L_fe_init_flags_done;
    }
    rax = (word64)((word64)(size_t)curve25519_avx512_ifma);
    curve25519_p = (word64)(size_t)rax;
#if defined(WOLFSSL_CURVE25519_NOT_USE_ED25519)
    rax = (word64)((word64)(size_t)curve25519_base_avx512_ifma);
    curve25519_base_p = (word64)(size_t)rax;
#endif /* WOLFSSL_CURVE25519_NOT_USE_ED25519 */
    rax = (word32)((word32)intelFlags);
    rax = (word32)((word32)rax & 0x72800);
    if (((word32)rax) != (0x72800)) {
        goto L_fe_init_flags_done;
    }
    rax = (word64)((word64)(size_t)curve25519_avx512_ifma_dq);
    curve25519_p = (word64)(size_t)rax;
#if defined(WOLFSSL_CURVE25519_NOT_USE_ED25519)
    rax = (word64)((word64)(size_t)curve25519_base_avx512_ifma_dq);
    curve25519_base_p = (word64)(size_t)rax;
#endif /* WOLFSSL_CURVE25519_NOT_USE_ED25519 */
#endif /* HAVE_INTEL_AVX512_IFMA */
L_fe_init_flags_done:
    cpuFlagsSet = (word32)1;
#endif /* HAVE_INTEL_AVX2 */
}

WOLFSSL_LOCAL void fe_frombytes(fe out, const unsigned char* in)
{
    word64 rdi, rsi, r9, rdx, rax, rcx, r8;

    rdi = (word64)(size_t)out;
    rsi = (word64)(size_t)in;

    r9 = (word64)(0x7fffffffffffffff);
    rdx = (word64)(WC_L64(rsi, 0));
    rax = (word64)(WC_L64(rsi, 8));
    rcx = (word64)(WC_L64(rsi, 16));
    r8 = (word64)(WC_L64(rsi, 24));
    r8 = (word64)(r8 & r9);
    WC_S64(rdi, 0) = (word64)(rdx);
    WC_S64(rdi, 8) = (word64)(rax);
    WC_S64(rdi, 16) = (word64)(rcx);
    WC_S64(rdi, 24) = (word64)(r8);
}

WOLFSSL_LOCAL void fe_tobytes(unsigned char* out, const fe n)
{
    word64 rdi, rsi, r10, rdx, rax, rcx, r8, r9;
    unsigned char cf;

    rdi = (word64)(size_t)out;
    rsi = (word64)(size_t)n;

    r10 = (word64)(0x7fffffffffffffff);
    rdx = (word64)(WC_L64(rsi, 0));
    rax = (word64)(WC_L64(rsi, 8));
    rcx = (word64)(WC_L64(rsi, 16));
    r8 = (word64)(WC_L64(rsi, 24));
    cf = _addcarry_u64(0, rdx, 0x13, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, rax, 0, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, rcx, 0, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    r8 = (word64)(r8 >> 63);
    r9 = (word64)(r8 * 19);
    rdx = (word64)(WC_L64(rsi, 0));
    rax = (word64)(WC_L64(rsi, 8));
    rcx = (word64)(WC_L64(rsi, 16));
    r8 = (word64)(WC_L64(rsi, 24));
    cf = _addcarry_u64(0, rdx, r9, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, rax, 0, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, rcx, 0, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    r8 = (word64)(r8 & r10);
    WC_S64(rdi, 0) = (word64)(rdx);
    WC_S64(rdi, 8) = (word64)(rax);
    WC_S64(rdi, 16) = (word64)(rcx);
    WC_S64(rdi, 24) = (word64)(r8);
}

WOLFSSL_LOCAL void fe_1(fe n)
{
    word64 rdi;

    rdi = (word64)(size_t)n;

    /* Set one */
    WC_S64(rdi, 0) = (word64)(1);
    WC_S64(rdi, 8) = (word64)(0);
    WC_S64(rdi, 16) = (word64)(0);
    WC_S64(rdi, 24) = (word64)(0);
}

WOLFSSL_LOCAL void fe_0(fe n)
{
    word64 rdi;

    rdi = (word64)(size_t)n;

    /* Set zero */
    WC_S64(rdi, 0) = (word64)(0);
    WC_S64(rdi, 8) = (word64)(0);
    WC_S64(rdi, 16) = (word64)(0);
    WC_S64(rdi, 24) = (word64)(0);
}

WOLFSSL_LOCAL void fe_copy(fe r, const fe a)
{
    word64 rdi, rsi, rdx, rax, rcx, r8;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)a;

    /* Copy */
    rdx = (word64)(WC_L64(rsi, 0));
    rax = (word64)(WC_L64(rsi, 8));
    rcx = (word64)(WC_L64(rsi, 16));
    r8 = (word64)(WC_L64(rsi, 24));
    WC_S64(rdi, 0) = (word64)(rdx);
    WC_S64(rdi, 8) = (word64)(rax);
    WC_S64(rdi, 16) = (word64)(rcx);
    WC_S64(rdi, 24) = (word64)(r8);
}

WOLFSSL_LOCAL void fe_sub(fe r, const fe a, const fe b)
{
    word64 rdi, rsi, rdx, rax, rcx, r8, r9, r10 = 0;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)a;
    rdx = (word64)(size_t)b;

    /* Sub */
    rax = (word64)(WC_L64(rsi, 0));
    rcx = (word64)(WC_L64(rsi, 8));
    r8 = (word64)(WC_L64(rsi, 16));
    r9 = (word64)(WC_L64(rsi, 24));
    cf = _subborrow_u64(0, rax, WC_L64(rdx, 0), (unsigned long long*)&rax);
    cf = _subborrow_u64(cf, rcx, WC_L64(rdx, 8), (unsigned long long*)&rcx);
    cf = _subborrow_u64(cf, r8, WC_L64(rdx, 16), (unsigned long long*)&r8);
    cf = _subborrow_u64(cf, r9, WC_L64(rdx, 24), (unsigned long long*)&r9);
    cf = _subborrow_u64(cf, r10, r10, (unsigned long long*)&r10);
    r10 = (word64)((r10 << 1) | (r9 >> 63));
    r10 = (word64)(r10 * -19);
    r9 = (word64)(r9 & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, rax, r10, (unsigned long long*)&rax);
    cf = _subborrow_u64(cf, rcx, 0, (unsigned long long*)&rcx);
    cf = _subborrow_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _subborrow_u64(cf, r9, 0, (unsigned long long*)&r9);
    WC_S64(rdi, 0) = (word64)(rax);
    WC_S64(rdi, 8) = (word64)(rcx);
    WC_S64(rdi, 16) = (word64)(r8);
    WC_S64(rdi, 24) = (word64)(r9);
}

WOLFSSL_LOCAL void fe_add(fe r, const fe a, const fe b)
{
    word64 rdi, rsi, rdx, rax, rcx, r8, r9, r10;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)a;
    rdx = (word64)(size_t)b;

    /* Add */
    rax = (word64)(WC_L64(rsi, 0));
    rcx = (word64)(WC_L64(rsi, 8));
    cf = _addcarry_u64(0, rax, WC_L64(rdx, 0), (unsigned long long*)&rax);
    r8 = (word64)(WC_L64(rsi, 16));
    cf = _addcarry_u64(cf, rcx, WC_L64(rdx, 8), (unsigned long long*)&rcx);
    r9 = (word64)(WC_L64(rsi, 24));
    cf = _addcarry_u64(cf, r8, WC_L64(rdx, 16), (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, WC_L64(rdx, 24), (unsigned long long*)&r9);
    r10 = (word64)(0);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    r10 = (word64)((r10 << 1) | (r9 >> 63));
    r10 = (word64)(r10 * 0x13);
    r9 = (word64)(r9 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, rax, r10, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, rcx, 0, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    WC_S64(rdi, 0) = (word64)(rax);
    WC_S64(rdi, 8) = (word64)(rcx);
    WC_S64(rdi, 16) = (word64)(r8);
    WC_S64(rdi, 24) = (word64)(r9);
}

WOLFSSL_LOCAL void fe_neg(fe r, const fe a)
{
    word64 rdi, rsi, rdx, rax, rcx, r8;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)a;

    rdx = (word64)(-19);
    rax = (word64)(-1);
    rcx = (word64)(-1);
    r8 = (word64)(0x7fffffffffffffff);
    cf = _subborrow_u64(0, rdx, WC_L64(rsi, 0), (unsigned long long*)&rdx);
    cf = _subborrow_u64(cf, rax, WC_L64(rsi, 8), (unsigned long long*)&rax);
    cf = _subborrow_u64(cf, rcx, WC_L64(rsi, 16), (unsigned long long*)&rcx);
    cf = _subborrow_u64(cf, r8, WC_L64(rsi, 24), (unsigned long long*)&r8);
    WC_S64(rdi, 0) = (word64)(rdx);
    WC_S64(rdi, 8) = (word64)(rax);
    WC_S64(rdi, 16) = (word64)(rcx);
    WC_S64(rdi, 24) = (word64)(r8);
}

WOLFSSL_LOCAL void fe_cmov(fe a, const fe b, int c)
{
    word64 rdi, rsi, rdx, rcx, r8, r9, r10;
    word32 zf1;
    word32 zf2;

    rdi = (word64)(size_t)a;
    rsi = (word64)(size_t)b;
    rdx = (word64)(word64)c;

    zf1 = (word32)rdx;
    zf2 = 1;
    rcx = (word64)(WC_L64(rdi, 0));
    r8 = (word64)(WC_L64(rdi, 8));
    r9 = (word64)(WC_L64(rdi, 16));
    r10 = (word64)(WC_L64(rdi, 24));
    rcx = (zf1) == (zf2) ? WC_L64(rsi, 0) : rcx;
    r8 = (zf1) == (zf2) ? WC_L64(rsi, 8) : r8;
    r9 = (zf1) == (zf2) ? WC_L64(rsi, 16) : r9;
    r10 = (zf1) == (zf2) ? WC_L64(rsi, 24) : r10;
    WC_S64(rdi, 0) = (word64)(rcx);
    WC_S64(rdi, 8) = (word64)(r8);
    WC_S64(rdi, 16) = (word64)(r9);
    WC_S64(rdi, 24) = (word64)(r10);
}

WOLFSSL_LOCAL int fe_isnonzero(const fe a)
{
    word64 rdi, r10, rax, rdx, rcx, r8, r9;
    unsigned char cf;

    rdi = (word64)(size_t)a;

    r10 = (word64)(0x7fffffffffffffff);
    rax = (word64)(WC_L64(rdi, 0));
    rdx = (word64)(WC_L64(rdi, 8));
    rcx = (word64)(WC_L64(rdi, 16));
    r8 = (word64)(WC_L64(rdi, 24));
    cf = _addcarry_u64(0, rax, 0x13, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, rcx, 0, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    r8 = (word64)(r8 >> 63);
    r9 = (word64)(r8 * 19);
    rax = (word64)(WC_L64(rdi, 0));
    rdx = (word64)(WC_L64(rdi, 8));
    rcx = (word64)(WC_L64(rdi, 16));
    r8 = (word64)(WC_L64(rdi, 24));
    cf = _addcarry_u64(0, rax, r9, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, rcx, 0, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    r8 = (word64)(r8 & r10);
    rax = (word64)(rax | rdx);
    rax = (word64)(rax | rcx);
    rax = (word64)(rax | r8);
    return (int)(word32)rax;
}

WOLFSSL_LOCAL int fe_isnegative(const fe a)
{
    word64 rdi, r11, rdx, rcx, r8, r9, rax, r10;
    unsigned char cf;

    rdi = (word64)(size_t)a;

    r11 = (word64)(0x7fffffffffffffff);
    rdx = (word64)(WC_L64(rdi, 0));
    rcx = (word64)(WC_L64(rdi, 8));
    r8 = (word64)(WC_L64(rdi, 16));
    r9 = (word64)(WC_L64(rdi, 24));
    rax = (word64)(rdx);
    cf = _addcarry_u64(0, rdx, 0x13, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, rcx, 0, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    r9 = (word64)(r9 >> 63);
    r10 = (word64)(r9 * 19);
    rax = (word64)(rax + r10);
    rax = (word64)(rax & 1);
    return (int)(word32)rax;
    (void)r11;
}

WOLFSSL_LOCAL void fe_cmov_table(fe* r, const fe* base, signed char b)
{
    ((void(*)(fe*, const fe*, signed char))(size_t)fe_cmov_table_p)(r, base, b);
    return;
    (void)r;
    (void)base;
    (void)b;
}

WOLFSSL_LOCAL void fe_mul(fe r, const fe a, const fe b)
{
    ((void(*)(fe, const fe, const fe))(size_t)fe_mul_p)(r, a, b);
    return;
    (void)r;
    (void)a;
    (void)b;
}

WOLFSSL_LOCAL void fe_sq(fe r, const fe a)
{
    ((void(*)(fe, const fe))(size_t)fe_sq_p)(r, a);
    return;
    (void)r;
    (void)a;
}

WOLFSSL_LOCAL void fe_mul121666(fe r, fe a)
{
    ((void(*)(fe, fe))(size_t)fe_mul121666_p)(r, a);
    return;
    (void)r;
    (void)a;
}

WOLFSSL_LOCAL void fe_invert(fe r, const fe a)
{
    ((void(*)(fe, const fe))(size_t)fe_invert_p)(r, a);
    return;
    (void)r;
    (void)a;
}

WOLFSSL_LOCAL int curve25519(byte* r, const byte* n, const byte* a)
{
    return ((int(*)(byte*, const byte*, const byte*))(size_t)curve25519_p)(r, n,
        a);
    (void)r;
    (void)n;
    (void)a;
}

WOLFSSL_LOCAL void fe_pow22523(fe r, const fe a)
{
    ((void(*)(fe, const fe))(size_t)fe_pow22523_p)(r, a);
    return;
    (void)r;
    (void)a;
}

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_p1p1_to_p2(ge_p2* r, const ge_p1p1* p)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
    ((void(*)(ge_p2*, const ge_p1p1*))(size_t)ge_p1p1_to_p2_p)(r, p);
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
    return;
    (void)r;
    (void)p;
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_p1p1_to_p3(ge_p3* r, const ge_p1p1* p)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
    ((void(*)(ge_p3*, const ge_p1p1*))(size_t)ge_p1p1_to_p3_p)(r, p);
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
    return;
    (void)r;
    (void)p;
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_p2_dbl(ge_p1p1* r, const ge_p2* p)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
    ((void(*)(ge_p1p1*, const ge_p2*))(size_t)ge_p2_dbl_p)(r, p);
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
    return;
    (void)r;
    (void)p;
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_madd(ge_p1p1* r, const ge_p3* p, const ge_precomp* q)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
    ((void(*)(ge_p1p1*, const ge_p3*, const ge_precomp*))(size_t)ge_madd_p)(r,
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
        p, q);
    return;
    (void)r;
    (void)p;
    (void)q;
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_msub(ge_p1p1* r, const ge_p3* p, const ge_precomp* q)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
    ((void(*)(ge_p1p1*, const ge_p3*, const ge_precomp*))(size_t)ge_msub_p)(r,
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
        p, q);
    return;
    (void)r;
    (void)p;
    (void)q;
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_add(ge_p1p1* r, const ge_p3* p, const ge_cached* q)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
    ((void(*)(ge_p1p1*, const ge_p3*, const ge_cached*))(size_t)ge_add_p)(r, p,
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
        q);
    return;
    (void)r;
    (void)p;
    (void)q;
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_sub(ge_p1p1* r, const ge_p3* p, const ge_cached* q)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
    ((void(*)(ge_p1p1*, const ge_p3*, const ge_cached*))(size_t)ge_sub_p)(r, p,
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
        q);
    return;
    (void)r;
    (void)p;
    (void)q;
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(WOLFSSL_CURVE25519_NOT_USE_ED25519)
#if defined(WOLFSSL_CURVE25519_NOT_USE_ED25519)
WOLFSSL_LOCAL int curve25519_base(byte* r, const byte* n)
{
    return ((int(*)(byte*, const byte*))(size_t)curve25519_base_p)(r, n);
    (void)r;
    (void)n;
}

#endif /* WOLFSSL_CURVE25519_NOT_USE_ED25519 */
#endif /* WOLFSSL_CURVE25519_NOT_USE_ED25519 */
#ifdef HAVE_ED25519
#ifdef HAVE_ED25519
WOLFSSL_LOCAL void fe_sq2(fe r, const fe a)
{
    ((void(*)(fe, const fe))(size_t)fe_sq2_p)(r, a);
    return;
    (void)r;
    (void)a;
}

#endif /* HAVE_ED25519 */
#ifdef HAVE_ED25519
WOLFSSL_LOCAL void fe_invert_nct(fe r, const fe a)
{
    ((void(*)(fe, const fe))(size_t)fe_invert_nct_p)(r, a);
    return;
    (void)r;
    (void)a;
}

#endif /* HAVE_ED25519 */
#ifdef HAVE_ED25519
WOLFSSL_LOCAL void sc_reduce(byte* s)
{
    ((void(*)(byte*))(size_t)sc_reduce_p)(s);
    return;
    (void)s;
}

#endif /* HAVE_ED25519 */
#ifdef HAVE_ED25519
WOLFSSL_LOCAL void sc_muladd(byte* s, const byte* a, const byte* b,
    const byte* c)
{
    ((void(*)(byte*, const byte*, const byte*, const byte*))(
        size_t)sc_muladd_p)(s, a, b, c);
    return;
    (void)s;
    (void)a;
    (void)b;
    (void)c;
}

#endif /* HAVE_ED25519 */
#endif /* HAVE_ED25519 */
#if defined(WOLFSSL_CURVE25519_NOT_USE_ED25519)
#endif /* WOLFSSL_CURVE25519_NOT_USE_ED25519 */
#ifdef HAVE_ED25519
#endif /* HAVE_ED25519 */
WOLFSSL_LOCAL void fe_cmov_table_x64(fe* r, const fe* base, signed char b)
{
    word64 rdi, rsi, rcx, rax, rdx, r15 = 0, r8, r9, r10, r11, r12, r13, r14;
    byte zf1;
    byte zf2;
    byte zf3;
    byte zf4;
    byte zf5;
    byte zf6;
    byte zf7;
    byte zf8;
    byte zf9;
    byte zf10;
    byte zf11;
    byte zf12;
    byte zf13;
    byte zf14;
    byte zf15;
    byte zf16;
    byte zf17;
    byte zf18;
    byte zf19;
    byte zf20;
    byte zf21;
    byte zf22;
    byte zf23;
    byte zf24;
    byte zf25;
    byte zf26;
    byte zf27;
    byte zf28;
    byte zf29;
    byte zf30;
    byte zf31;
    byte zf32;
    byte zf33;
    byte zf34;
    byte zf35;
    byte zf36;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)base;
    rcx = (word64)(byte)b;

    rax = (word64)((word64)(sword64)(signed char)(byte)rcx);
    rdx = (word64)(word32)((sword32)(word32)rax >> 31);
    rax = (rax & ~(word64)0xff) | ((word64)(byte)((byte)rax ^ (
        byte)rdx) & 0xff);
    rax = (rax & ~(word64)0xff) | ((word64)(byte)((byte)rax - (
        byte)rdx) & 0xff);
    r15 = (r15 & ~(word64)0xff) | ((word64)(byte)((byte)rax) & 0xff);
    rax = (word64)(1);
    rdx = (word64)(0);
    r8 = (word64)(0);
    r9 = (word64)(0);
    r10 = (word64)(1);
    r11 = (word64)(0);
    r12 = (word64)(0);
    r13 = (word64)(0);
    zf1 = (byte)r15;
    zf2 = 1;
    r14 = (word64)(WC_L64(rsi, 0));
    rax = (zf1) == (zf2) ? r14 : rax;
    r14 = (word64)(WC_L64(rsi, 8));
    rdx = (zf1) == (zf2) ? r14 : rdx;
    r14 = (word64)(WC_L64(rsi, 16));
    r8 = (zf1) == (zf2) ? r14 : r8;
    r14 = (word64)(WC_L64(rsi, 24));
    r9 = (zf1) == (zf2) ? r14 : r9;
    r14 = (word64)(WC_L64(rsi, 32));
    r10 = (zf1) == (zf2) ? r14 : r10;
    r14 = (word64)(WC_L64(rsi, 40));
    r11 = (zf1) == (zf2) ? r14 : r11;
    r14 = (word64)(WC_L64(rsi, 48));
    r12 = (zf1) == (zf2) ? r14 : r12;
    r14 = (word64)(WC_L64(rsi, 56));
    r13 = (zf1) == (zf2) ? r14 : r13;
    zf3 = (byte)r15;
    zf4 = 2;
    r14 = (word64)(WC_L64(rsi, 96));
    rax = (zf3) == (zf4) ? r14 : rax;
    r14 = (word64)(WC_L64(rsi, 104));
    rdx = (zf3) == (zf4) ? r14 : rdx;
    r14 = (word64)(WC_L64(rsi, 112));
    r8 = (zf3) == (zf4) ? r14 : r8;
    r14 = (word64)(WC_L64(rsi, 120));
    r9 = (zf3) == (zf4) ? r14 : r9;
    r14 = (word64)(WC_L64(rsi, 128));
    r10 = (zf3) == (zf4) ? r14 : r10;
    r14 = (word64)(WC_L64(rsi, 136));
    r11 = (zf3) == (zf4) ? r14 : r11;
    r14 = (word64)(WC_L64(rsi, 144));
    r12 = (zf3) == (zf4) ? r14 : r12;
    r14 = (word64)(WC_L64(rsi, 152));
    r13 = (zf3) == (zf4) ? r14 : r13;
    zf5 = (byte)r15;
    zf6 = 3;
    r14 = (word64)(WC_L64(rsi, 192));
    rax = (zf5) == (zf6) ? r14 : rax;
    r14 = (word64)(WC_L64(rsi, 200));
    rdx = (zf5) == (zf6) ? r14 : rdx;
    r14 = (word64)(WC_L64(rsi, 208));
    r8 = (zf5) == (zf6) ? r14 : r8;
    r14 = (word64)(WC_L64(rsi, 216));
    r9 = (zf5) == (zf6) ? r14 : r9;
    r14 = (word64)(WC_L64(rsi, 224));
    r10 = (zf5) == (zf6) ? r14 : r10;
    r14 = (word64)(WC_L64(rsi, 232));
    r11 = (zf5) == (zf6) ? r14 : r11;
    r14 = (word64)(WC_L64(rsi, 240));
    r12 = (zf5) == (zf6) ? r14 : r12;
    r14 = (word64)(WC_L64(rsi, 248));
    r13 = (zf5) == (zf6) ? r14 : r13;
    zf7 = (byte)r15;
    zf8 = 4;
    r14 = (word64)(WC_L64(rsi, 288));
    rax = (zf7) == (zf8) ? r14 : rax;
    r14 = (word64)(WC_L64(rsi, 296));
    rdx = (zf7) == (zf8) ? r14 : rdx;
    r14 = (word64)(WC_L64(rsi, 304));
    r8 = (zf7) == (zf8) ? r14 : r8;
    r14 = (word64)(WC_L64(rsi, 312));
    r9 = (zf7) == (zf8) ? r14 : r9;
    r14 = (word64)(WC_L64(rsi, 320));
    r10 = (zf7) == (zf8) ? r14 : r10;
    r14 = (word64)(WC_L64(rsi, 328));
    r11 = (zf7) == (zf8) ? r14 : r11;
    r14 = (word64)(WC_L64(rsi, 336));
    r12 = (zf7) == (zf8) ? r14 : r12;
    r14 = (word64)(WC_L64(rsi, 344));
    r13 = (zf7) == (zf8) ? r14 : r13;
    zf9 = (byte)r15;
    zf10 = 5;
    r14 = (word64)(WC_L64(rsi, 384));
    rax = (zf9) == (zf10) ? r14 : rax;
    r14 = (word64)(WC_L64(rsi, 392));
    rdx = (zf9) == (zf10) ? r14 : rdx;
    r14 = (word64)(WC_L64(rsi, 400));
    r8 = (zf9) == (zf10) ? r14 : r8;
    r14 = (word64)(WC_L64(rsi, 408));
    r9 = (zf9) == (zf10) ? r14 : r9;
    r14 = (word64)(WC_L64(rsi, 416));
    r10 = (zf9) == (zf10) ? r14 : r10;
    r14 = (word64)(WC_L64(rsi, 424));
    r11 = (zf9) == (zf10) ? r14 : r11;
    r14 = (word64)(WC_L64(rsi, 432));
    r12 = (zf9) == (zf10) ? r14 : r12;
    r14 = (word64)(WC_L64(rsi, 440));
    r13 = (zf9) == (zf10) ? r14 : r13;
    zf11 = (byte)r15;
    zf12 = 6;
    r14 = (word64)(WC_L64(rsi, 480));
    rax = (zf11) == (zf12) ? r14 : rax;
    r14 = (word64)(WC_L64(rsi, 488));
    rdx = (zf11) == (zf12) ? r14 : rdx;
    r14 = (word64)(WC_L64(rsi, 496));
    r8 = (zf11) == (zf12) ? r14 : r8;
    r14 = (word64)(WC_L64(rsi, 504));
    r9 = (zf11) == (zf12) ? r14 : r9;
    r14 = (word64)(WC_L64(rsi, 512));
    r10 = (zf11) == (zf12) ? r14 : r10;
    r14 = (word64)(WC_L64(rsi, 520));
    r11 = (zf11) == (zf12) ? r14 : r11;
    r14 = (word64)(WC_L64(rsi, 528));
    r12 = (zf11) == (zf12) ? r14 : r12;
    r14 = (word64)(WC_L64(rsi, 536));
    r13 = (zf11) == (zf12) ? r14 : r13;
    zf13 = (byte)r15;
    zf14 = 7;
    r14 = (word64)(WC_L64(rsi, 576));
    rax = (zf13) == (zf14) ? r14 : rax;
    r14 = (word64)(WC_L64(rsi, 584));
    rdx = (zf13) == (zf14) ? r14 : rdx;
    r14 = (word64)(WC_L64(rsi, 592));
    r8 = (zf13) == (zf14) ? r14 : r8;
    r14 = (word64)(WC_L64(rsi, 600));
    r9 = (zf13) == (zf14) ? r14 : r9;
    r14 = (word64)(WC_L64(rsi, 608));
    r10 = (zf13) == (zf14) ? r14 : r10;
    r14 = (word64)(WC_L64(rsi, 616));
    r11 = (zf13) == (zf14) ? r14 : r11;
    r14 = (word64)(WC_L64(rsi, 624));
    r12 = (zf13) == (zf14) ? r14 : r12;
    r14 = (word64)(WC_L64(rsi, 632));
    r13 = (zf13) == (zf14) ? r14 : r13;
    zf15 = (byte)r15;
    zf16 = 8;
    r14 = (word64)(WC_L64(rsi, 672));
    rax = (zf15) == (zf16) ? r14 : rax;
    r14 = (word64)(WC_L64(rsi, 680));
    rdx = (zf15) == (zf16) ? r14 : rdx;
    r14 = (word64)(WC_L64(rsi, 688));
    r8 = (zf15) == (zf16) ? r14 : r8;
    r14 = (word64)(WC_L64(rsi, 696));
    r9 = (zf15) == (zf16) ? r14 : r9;
    r14 = (word64)(WC_L64(rsi, 704));
    r10 = (zf15) == (zf16) ? r14 : r10;
    r14 = (word64)(WC_L64(rsi, 712));
    r11 = (zf15) == (zf16) ? r14 : r11;
    r14 = (word64)(WC_L64(rsi, 720));
    r12 = (zf15) == (zf16) ? r14 : r12;
    r14 = (word64)(WC_L64(rsi, 728));
    r13 = (zf15) == (zf16) ? r14 : r13;
    zf17 = (byte)rcx;
    zf18 = 0;
    r14 = (word64)(rax);
    rax = (sword8)(zf17) < (sword8)(zf18) ? r10 : rax;
    r10 = (sword8)(zf17) < (sword8)(zf18) ? r14 : r10;
    r14 = (word64)(rdx);
    rdx = (sword8)(zf17) < (sword8)(zf18) ? r11 : rdx;
    r11 = (sword8)(zf17) < (sword8)(zf18) ? r14 : r11;
    r14 = (word64)(r8);
    r8 = (sword8)(zf17) < (sword8)(zf18) ? r12 : r8;
    r12 = (sword8)(zf17) < (sword8)(zf18) ? r14 : r12;
    r14 = (word64)(r9);
    r9 = (sword8)(zf17) < (sword8)(zf18) ? r13 : r9;
    r13 = (sword8)(zf17) < (sword8)(zf18) ? r14 : r13;
    WC_S64(rdi, 0) = (word64)(rax);
    WC_S64(rdi, 8) = (word64)(rdx);
    WC_S64(rdi, 16) = (word64)(r8);
    WC_S64(rdi, 24) = (word64)(r9);
    WC_S64(rdi, 32) = (word64)(r10);
    WC_S64(rdi, 40) = (word64)(r11);
    WC_S64(rdi, 48) = (word64)(r12);
    WC_S64(rdi, 56) = (word64)(r13);
    rax = (word64)(0);
    rdx = (word64)(0);
    r8 = (word64)(0);
    r9 = (word64)(0);
    zf19 = (byte)r15;
    zf20 = 1;
    r14 = (word64)(WC_L64(rsi, 64));
    rax = (zf19) == (zf20) ? r14 : rax;
    r14 = (word64)(WC_L64(rsi, 72));
    rdx = (zf19) == (zf20) ? r14 : rdx;
    r14 = (word64)(WC_L64(rsi, 80));
    r8 = (zf19) == (zf20) ? r14 : r8;
    r14 = (word64)(WC_L64(rsi, 88));
    r9 = (zf19) == (zf20) ? r14 : r9;
    zf21 = (byte)r15;
    zf22 = 2;
    r14 = (word64)(WC_L64(rsi, 160));
    rax = (zf21) == (zf22) ? r14 : rax;
    r14 = (word64)(WC_L64(rsi, 168));
    rdx = (zf21) == (zf22) ? r14 : rdx;
    r14 = (word64)(WC_L64(rsi, 176));
    r8 = (zf21) == (zf22) ? r14 : r8;
    r14 = (word64)(WC_L64(rsi, 184));
    r9 = (zf21) == (zf22) ? r14 : r9;
    zf23 = (byte)r15;
    zf24 = 3;
    r14 = (word64)(WC_L64(rsi, 256));
    rax = (zf23) == (zf24) ? r14 : rax;
    r14 = (word64)(WC_L64(rsi, 264));
    rdx = (zf23) == (zf24) ? r14 : rdx;
    r14 = (word64)(WC_L64(rsi, 272));
    r8 = (zf23) == (zf24) ? r14 : r8;
    r14 = (word64)(WC_L64(rsi, 280));
    r9 = (zf23) == (zf24) ? r14 : r9;
    zf25 = (byte)r15;
    zf26 = 4;
    r14 = (word64)(WC_L64(rsi, 352));
    rax = (zf25) == (zf26) ? r14 : rax;
    r14 = (word64)(WC_L64(rsi, 360));
    rdx = (zf25) == (zf26) ? r14 : rdx;
    r14 = (word64)(WC_L64(rsi, 368));
    r8 = (zf25) == (zf26) ? r14 : r8;
    r14 = (word64)(WC_L64(rsi, 376));
    r9 = (zf25) == (zf26) ? r14 : r9;
    zf27 = (byte)r15;
    zf28 = 5;
    r14 = (word64)(WC_L64(rsi, 448));
    rax = (zf27) == (zf28) ? r14 : rax;
    r14 = (word64)(WC_L64(rsi, 456));
    rdx = (zf27) == (zf28) ? r14 : rdx;
    r14 = (word64)(WC_L64(rsi, 464));
    r8 = (zf27) == (zf28) ? r14 : r8;
    r14 = (word64)(WC_L64(rsi, 472));
    r9 = (zf27) == (zf28) ? r14 : r9;
    zf29 = (byte)r15;
    zf30 = 6;
    r14 = (word64)(WC_L64(rsi, 544));
    rax = (zf29) == (zf30) ? r14 : rax;
    r14 = (word64)(WC_L64(rsi, 552));
    rdx = (zf29) == (zf30) ? r14 : rdx;
    r14 = (word64)(WC_L64(rsi, 560));
    r8 = (zf29) == (zf30) ? r14 : r8;
    r14 = (word64)(WC_L64(rsi, 568));
    r9 = (zf29) == (zf30) ? r14 : r9;
    zf31 = (byte)r15;
    zf32 = 7;
    r14 = (word64)(WC_L64(rsi, 640));
    rax = (zf31) == (zf32) ? r14 : rax;
    r14 = (word64)(WC_L64(rsi, 648));
    rdx = (zf31) == (zf32) ? r14 : rdx;
    r14 = (word64)(WC_L64(rsi, 656));
    r8 = (zf31) == (zf32) ? r14 : r8;
    r14 = (word64)(WC_L64(rsi, 664));
    r9 = (zf31) == (zf32) ? r14 : r9;
    zf33 = (byte)r15;
    zf34 = 8;
    r14 = (word64)(WC_L64(rsi, 736));
    rax = (zf33) == (zf34) ? r14 : rax;
    r14 = (word64)(WC_L64(rsi, 744));
    rdx = (zf33) == (zf34) ? r14 : rdx;
    r14 = (word64)(WC_L64(rsi, 752));
    r8 = (zf33) == (zf34) ? r14 : r8;
    r14 = (word64)(WC_L64(rsi, 760));
    r9 = (zf33) == (zf34) ? r14 : r9;
    r10 = (word64)(-19);
    r11 = (word64)(-1);
    r12 = (word64)(-1);
    r13 = (word64)(0x7fffffffffffffff);
    cf = _subborrow_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _subborrow_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, r12, r8, (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, r9, (unsigned long long*)&r13);
    zf35 = (byte)rcx;
    zf36 = 0;
    rax = (sword8)((byte)rcx) < (sword8)(0) ? r10 : rax;
    rdx = (sword8)(zf35) < (sword8)(zf36) ? r11 : rdx;
    r8 = (sword8)(zf35) < (sword8)(zf36) ? r12 : r8;
    r9 = (sword8)(zf35) < (sword8)(zf36) ? r13 : r9;
    WC_S64(rdi, 64) = (word64)(rax);
    WC_S64(rdi, 72) = (word64)(rdx);
    WC_S64(rdi, 80) = (word64)(r8);
    WC_S64(rdi, 88) = (word64)(r9);
}

WOLFSSL_LOCAL void fe_mul_x64(fe r, fe a, fe b)
{
    word64 rdi, rsi, rcx, rax, rdx = 0, r8, r9, r10, r11, r12, r13, r14, r15,
           rbx;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)a;
    rcx = (word64)(size_t)b;

    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r8 = (word64)(rax);
    r9 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r11 >> 63));
    rdx = (word64)(rdx * 19);
    r11 = (word64)(r11 & rbx);
    rbx = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r8, rbx, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    rbx = (word64)(0x7fffffffffffffff);
    rax = (word64)(r11);
    rax = (word64)((word64)((sword64)rax >> 63));
    rax = (word64)(rax & 0x13);
    r11 = (word64)(r11 & rbx);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /* Store */
    WC_S64(rdi, 0) = (word64)(r8);
    WC_S64(rdi, 8) = (word64)(r9);
    WC_S64(rdi, 16) = (word64)(r10);
    WC_S64(rdi, 24) = (word64)(r11);
}

WOLFSSL_LOCAL void fe_sq_x64(fe r, fe a)
{
    word64 rdi, rsi, rax, rdx = 0, r8, r9, r10, r11, r12, r13, r14, rcx, r15;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)a;

    /* Square */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r8 = (word64)(rax);
    r9 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rsi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rsi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rsi, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /* Double */
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r8, r8, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r9, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    rcx = (word64)(rax);
    r15 = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rsi, 8));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r8, r15, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r15 = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rsi, 16));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r10, r15, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r15 = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rsi, 24));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r12, r15, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r15 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r10 >> 63));
    rdx = (word64)(rdx * 19);
    r10 = (word64)(r10 & r15);
    r15 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r11 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(0, rcx, r15, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    r15 = (word64)(0x7fffffffffffffff);
    rax = (word64)(r10);
    rax = (word64)((word64)((sword64)rax >> 63));
    rax = (word64)(rax & 0x13);
    r10 = (word64)(r10 & r15);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    /* Store */
    WC_S64(rdi, 0) = (word64)(rcx);
    WC_S64(rdi, 8) = (word64)(r8);
    WC_S64(rdi, 16) = (word64)(r9);
    WC_S64(rdi, 24) = (word64)(r10);
}

WOLFSSL_LOCAL void fe_sq_n_x64(fe r, const fe a, word64 n)
{
    word64 rdi, rsi, rcx, rax = 0, rdx = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0,
           r13 = 0, r14 = 0, r15 = 0, r8 = 0, rbx = 0;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)a;
    rcx = (word64)(word64)n;

L_fe_sq_n_x64:
    /* Square */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r9 = (word64)(rax);
    r10 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rsi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rsi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rsi, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /* Double */
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r9, r9, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, r14, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r8 = (word64)(rax);
    rbx = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rsi, 8));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r9, rbx, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rsi, 16));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r11, rbx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rsi, 24));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(0, r13, rbx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r11 >> 63));
    rdx = (word64)(rdx * 19);
    r11 = (word64)(r11 & rbx);
    rbx = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r8, rbx, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    /* Store */
    WC_S64(rdi, 0) = (word64)(r8);
    WC_S64(rdi, 8) = (word64)(r9);
    WC_S64(rdi, 16) = (word64)(r10);
    WC_S64(rdi, 24) = (word64)(r11);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)((byte)rcx - 1) & 0xff);
    if (((byte)rcx) != (0)) {
        goto L_fe_sq_n_x64;
    }
}

WOLFSSL_LOCAL void fe_mul121666_x64(fe r, fe a)
{
    word64 rdi, rsi, rax, rdx = 0, r10, r8, r9, r11, r12, rcx;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)a;

    /* Multiply by 121666 */
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r10 = (word64)(0);
    r8 = (word64)(rax);
    r9 = (word64)(rdx);
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    rcx = (word64)(0x7fffffffffffffff);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    r12 = (word64)((r12 << 1) | (r11 >> 63));
    r11 = (word64)(r11 & rcx);
    rax = (word64)(0x13);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    WC_S64(rdi, 0) = (word64)(r8);
    WC_S64(rdi, 8) = (word64)(r9);
    WC_S64(rdi, 16) = (word64)(r10);
    WC_S64(rdi, 24) = (word64)(r11);
}

WOLFSSL_LOCAL void fe_invert_x64(fe r, const fe a)
{
    word64 rdi, rsi, rsp, rdx;
    XALIGNED(32) WC_X64I_SLOT stk[20];

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)a;

    rsp = (word64)(size_t)stk + 160;
    rsp = (word64)(rsp - 144);
    /* Invert */
    WC_S64(rsp, 128) = (word64)(rdi);
    WC_S64(rsp, 136) = (word64)(rsi);
    rdi = (word64)(rsp);
    rsi = (word64)(WC_L64(rsp, 136));
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(WC_L64(rsp, 136));
    rdx = (word64)(rsp + 32);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(4);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(9);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 64);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(0x13);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(9);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(0x31);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 64);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(0x63);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(0x31);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(4);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(WC_L64(rsp, 128));
    rsi = (word64)(rsp + 32);
    rdx = (word64)(rsp);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rsi = (word64)(WC_L64(rsp, 136));
    rdi = (word64)(WC_L64(rsp, 128));
}

#if defined(WOLFSSL_CURVE25519_NOT_USE_ED25519)
XALIGNED(32) static const word64 L_curve25519_base_x64_x2[] WC_X64I_UNUSED = {
    0x5cae469cdd684efbULL, 0x8f3f5ced1e350b5cULL,
    0xd9750c687d157114ULL, 0x20d342d51873f1b7ULL,
};

WOLFSSL_LOCAL int curve25519_base_x64(byte* r, byte* n)
{
    word64 rdi, rsi, rsp, r15, rcx, r8, r9, r10, rbp, rbx = 0, r11 = 0,
           r12 = 0, r13 = 0, r14 = 0, rax = 0, rdx = 0;
    XALIGNED(32) WC_X64I_SLOT stk[24];
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)n;

    rsp = (word64)(size_t)stk + 192;
    rsp = (word64)(rsp - 168);
    r15 = (word64)(0);
    WC_S64(rsp, 160) = (word64)(rdi);
    /* Set base point x */
    WC_S64(rdi, 0) = (word64)(9);
    WC_S64(rdi, 8) = (word64)(0);
    WC_S64(rdi, 16) = (word64)(0);
    WC_S64(rdi, 24) = (word64)(0);
    /* Set one */
    WC_S64(rsp, 0) = (word64)(1);
    WC_S64(rsp, 8) = (word64)(0);
    WC_S64(rsp, 16) = (word64)(0);
    WC_S64(rsp, 24) = (word64)(0);
    rcx = (word64)(WC_L64(L_curve25519_base_x64_x2, 0));
    r8 = (word64)(WC_L64(L_curve25519_base_x64_x2, 8));
    r9 = (word64)(WC_L64(L_curve25519_base_x64_x2, 16));
    r10 = (word64)(WC_L64(L_curve25519_base_x64_x2, 24));
    /* Set one */
    WC_S64(rsp, 32) = (word64)(1);
    WC_S64(rsp, 40) = (word64)(0);
    WC_S64(rsp, 48) = (word64)(0);
    WC_S64(rsp, 56) = (word64)(0);
    WC_S64(rsp, 64) = (word64)(rcx);
    WC_S64(rsp, 72) = (word64)(r8);
    WC_S64(rsp, 80) = (word64)(r9);
    WC_S64(rsp, 88) = (word64)(r10);
    rbp = (word64)(0xfd);
L_curve25519_base_x64_bits:
    r8 = (word64)(rbp);
    rcx = (word64)(rbp);
    rcx = (word64)(rcx & 0x3f);
    r8 = (word64)(r8 >> 6);
    rbx = (word64)(WC_L64(rsi, r8 * 8));
    rbx = (word64)(rbx >> ((byte)rcx & 63));
    rbx = (word64)(rbx & 1);
    r15 = (word64)(r15 ^ rbx);
    r15 = (word64)(0 - r15);
    /* Conditional Swap */
    rcx = (word64)(WC_L64(rdi, 0));
    r8 = (word64)(WC_L64(rdi, 8));
    r9 = (word64)(WC_L64(rdi, 16));
    r10 = (word64)(WC_L64(rdi, 24));
    r11 = (word64)(WC_L64(rsp, 0));
    r12 = (word64)(WC_L64(rsp, 8));
    r13 = (word64)(WC_L64(rsp, 16));
    r14 = (word64)(WC_L64(rsp, 24));
    rcx = (word64)(rcx ^ WC_L64(rsp, 64));
    r8 = (word64)(r8 ^ WC_L64(rsp, 72));
    r9 = (word64)(r9 ^ WC_L64(rsp, 80));
    r10 = (word64)(r10 ^ WC_L64(rsp, 88));
    r11 = (word64)(r11 ^ WC_L64(rsp, 32));
    r12 = (word64)(r12 ^ WC_L64(rsp, 40));
    r13 = (word64)(r13 ^ WC_L64(rsp, 48));
    r14 = (word64)(r14 ^ WC_L64(rsp, 56));
    rcx = (word64)(rcx & r15);
    r8 = (word64)(r8 & r15);
    r9 = (word64)(r9 & r15);
    r10 = (word64)(r10 & r15);
    r11 = (word64)(r11 & r15);
    r12 = (word64)(r12 & r15);
    r13 = (word64)(r13 & r15);
    r14 = (word64)(r14 & r15);
    WC_S64(rdi, 0) = (word64)(WC_L64(rdi, 0) ^ rcx);
    WC_S64(rdi, 8) = (word64)(WC_L64(rdi, 8) ^ r8);
    WC_S64(rdi, 16) = (word64)(WC_L64(rdi, 16) ^ r9);
    WC_S64(rdi, 24) = (word64)(WC_L64(rdi, 24) ^ r10);
    WC_S64(rsp, 0) = (word64)(WC_L64(rsp, 0) ^ r11);
    WC_S64(rsp, 8) = (word64)(WC_L64(rsp, 8) ^ r12);
    WC_S64(rsp, 16) = (word64)(WC_L64(rsp, 16) ^ r13);
    WC_S64(rsp, 24) = (word64)(WC_L64(rsp, 24) ^ r14);
    WC_S64(rsp, 64) = (word64)(WC_L64(rsp, 64) ^ rcx);
    WC_S64(rsp, 72) = (word64)(WC_L64(rsp, 72) ^ r8);
    WC_S64(rsp, 80) = (word64)(WC_L64(rsp, 80) ^ r9);
    WC_S64(rsp, 88) = (word64)(WC_L64(rsp, 88) ^ r10);
    WC_S64(rsp, 32) = (word64)(WC_L64(rsp, 32) ^ r11);
    WC_S64(rsp, 40) = (word64)(WC_L64(rsp, 40) ^ r12);
    WC_S64(rsp, 48) = (word64)(WC_L64(rsp, 48) ^ r13);
    WC_S64(rsp, 56) = (word64)(WC_L64(rsp, 56) ^ r14);
    r15 = (word64)(rbx);
    /* Add-Sub */
    /* Add */
    rcx = (word64)(WC_L64(rdi, 0));
    r8 = (word64)(WC_L64(rdi, 8));
    r9 = (word64)(WC_L64(rdi, 16));
    r10 = (word64)(WC_L64(rdi, 24));
    r11 = (word64)(rcx);
    cf = _addcarry_u64(0, rcx, WC_L64(rsp, 0), (unsigned long long*)&rcx);
    r12 = (word64)(r8);
    cf = _addcarry_u64(cf, r8, WC_L64(rsp, 8), (unsigned long long*)&r8);
    r13 = (word64)(r9);
    cf = _addcarry_u64(cf, r9, WC_L64(rsp, 16), (unsigned long long*)&r9);
    r14 = (word64)(r10);
    cf = _addcarry_u64(cf, r10, WC_L64(rsp, 24), (unsigned long long*)&r10);
    rbx = (word64)(0);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    rbx = (word64)((rbx << 1) | (r10 >> 63));
    rbx = (word64)(rbx * 0x13);
    r10 = (word64)(r10 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    /* Sub */
    cf = _subborrow_u64(0, r11, WC_L64(rsp, 0), (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, r12, WC_L64(rsp, 8), (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, WC_L64(rsp, 16), (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, WC_L64(rsp, 24), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, rbx, rbx, (unsigned long long*)&rbx);
    rbx = (word64)((rbx << 1) | (r14 >> 63));
    rbx = (word64)(rbx * -19);
    r14 = (word64)(r14 & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r11, rbx, (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, 0, (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, 0, (unsigned long long*)&r14);
    WC_S64(rdi, 0) = (word64)(rcx);
    WC_S64(rdi, 8) = (word64)(r8);
    WC_S64(rdi, 16) = (word64)(r9);
    WC_S64(rdi, 24) = (word64)(r10);
    WC_S64(rsp, 128) = (word64)(r11);
    WC_S64(rsp, 136) = (word64)(r12);
    WC_S64(rsp, 144) = (word64)(r13);
    WC_S64(rsp, 152) = (word64)(r14);
    /* Add-Sub */
    /* Add */
    rcx = (word64)(WC_L64(rsp, 64));
    r8 = (word64)(WC_L64(rsp, 72));
    r9 = (word64)(WC_L64(rsp, 80));
    r10 = (word64)(WC_L64(rsp, 88));
    r11 = (word64)(rcx);
    cf = _addcarry_u64(0, rcx, WC_L64(rsp, 32), (unsigned long long*)&rcx);
    r12 = (word64)(r8);
    cf = _addcarry_u64(cf, r8, WC_L64(rsp, 40), (unsigned long long*)&r8);
    r13 = (word64)(r9);
    cf = _addcarry_u64(cf, r9, WC_L64(rsp, 48), (unsigned long long*)&r9);
    r14 = (word64)(r10);
    cf = _addcarry_u64(cf, r10, WC_L64(rsp, 56), (unsigned long long*)&r10);
    rbx = (word64)(0);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    rbx = (word64)((rbx << 1) | (r10 >> 63));
    rbx = (word64)(rbx * 0x13);
    r10 = (word64)(r10 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    /* Sub */
    cf = _subborrow_u64(0, r11, WC_L64(rsp, 32), (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, r12, WC_L64(rsp, 40), (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, WC_L64(rsp, 48), (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, WC_L64(rsp, 56), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, rbx, rbx, (unsigned long long*)&rbx);
    rbx = (word64)((rbx << 1) | (r14 >> 63));
    rbx = (word64)(rbx * -19);
    r14 = (word64)(r14 & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r11, rbx, (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, 0, (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, 0, (unsigned long long*)&r14);
    WC_S64(rsp, 32) = (word64)(rcx);
    WC_S64(rsp, 40) = (word64)(r8);
    WC_S64(rsp, 48) = (word64)(r9);
    WC_S64(rsp, 56) = (word64)(r10);
    WC_S64(rsp, 96) = (word64)(r11);
    WC_S64(rsp, 104) = (word64)(r12);
    WC_S64(rsp, 112) = (word64)(r13);
    WC_S64(rsp, 120) = (word64)(r14);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 32));
    rcx = (word64)(rax);
    r8 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 32));
    r9 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 40));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rsp, 144));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 32));
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 40));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 48));
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rsp, 152));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 32));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rsp, 144));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 40));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 48));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 56));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rsp, 152));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 40));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rsp, 144));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 48));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 56));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rsp, 152));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 48));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rsp, 144));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 56));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rsp, 152));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 56));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r10 >> 63));
    rdx = (word64)(rdx * 19);
    r10 = (word64)(r10 & rbx);
    rbx = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r11 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    /* Store */
    WC_S64(rsp, 32) = (word64)(rcx);
    WC_S64(rsp, 40) = (word64)(r8);
    WC_S64(rsp, 48) = (word64)(r9);
    WC_S64(rsp, 56) = (word64)(r10);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 96));
    rcx = (word64)(rax);
    r8 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 96));
    r9 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 104));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rdi, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 96));
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 104));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 112));
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rdi, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 96));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rdi, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 104));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 112));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 120));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rdi, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 104));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rdi, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 112));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 120));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rdi, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 112));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rdi, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 120));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rdi, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 120));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r10 >> 63));
    rdx = (word64)(rdx * 19);
    r10 = (word64)(r10 & rbx);
    rbx = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r11 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    /* Store */
    WC_S64(rsp, 0) = (word64)(rcx);
    WC_S64(rsp, 8) = (word64)(r8);
    WC_S64(rsp, 16) = (word64)(r9);
    WC_S64(rsp, 24) = (word64)(r10);
    /* Square */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r8 = (word64)(rax);
    r9 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rsp, 144));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /* Double */
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r8, r8, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r9, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    rcx = (word64)(rax);
    rbx = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r8, rbx, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rsp, 144));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r10, rbx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rsp, 152));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r12, rbx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r10 >> 63));
    rdx = (word64)(rdx * 19);
    r10 = (word64)(r10 & rbx);
    rbx = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r11 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    /* Store */
    WC_S64(rsp, 96) = (word64)(rcx);
    WC_S64(rsp, 104) = (word64)(r8);
    WC_S64(rsp, 112) = (word64)(r9);
    WC_S64(rsp, 120) = (word64)(r10);
    /* Square */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r8 = (word64)(rax);
    r9 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rdi, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /* Double */
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r8, r8, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r9, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    rcx = (word64)(rax);
    rbx = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r8, rbx, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rdi, 16));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r10, rbx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rdi, 24));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r12, rbx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r10 >> 63));
    rdx = (word64)(rdx * 19);
    r10 = (word64)(r10 & rbx);
    rbx = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r11 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    /* Store */
    WC_S64(rsp, 128) = (word64)(rcx);
    WC_S64(rsp, 136) = (word64)(r8);
    WC_S64(rsp, 144) = (word64)(r9);
    WC_S64(rsp, 152) = (word64)(r10);
    /* Add-Sub */
    /* Add */
    rcx = (word64)(WC_L64(rsp, 0));
    r8 = (word64)(WC_L64(rsp, 8));
    r9 = (word64)(WC_L64(rsp, 16));
    r10 = (word64)(WC_L64(rsp, 24));
    r11 = (word64)(rcx);
    cf = _addcarry_u64(0, rcx, WC_L64(rsp, 32), (unsigned long long*)&rcx);
    r12 = (word64)(r8);
    cf = _addcarry_u64(cf, r8, WC_L64(rsp, 40), (unsigned long long*)&r8);
    r13 = (word64)(r9);
    cf = _addcarry_u64(cf, r9, WC_L64(rsp, 48), (unsigned long long*)&r9);
    r14 = (word64)(r10);
    cf = _addcarry_u64(cf, r10, WC_L64(rsp, 56), (unsigned long long*)&r10);
    rbx = (word64)(0);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    rbx = (word64)((rbx << 1) | (r10 >> 63));
    rbx = (word64)(rbx * 0x13);
    r10 = (word64)(r10 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    /* Sub */
    cf = _subborrow_u64(0, r11, WC_L64(rsp, 32), (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, r12, WC_L64(rsp, 40), (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, WC_L64(rsp, 48), (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, WC_L64(rsp, 56), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, rbx, rbx, (unsigned long long*)&rbx);
    rbx = (word64)((rbx << 1) | (r14 >> 63));
    rbx = (word64)(rbx * -19);
    r14 = (word64)(r14 & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r11, rbx, (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, 0, (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, 0, (unsigned long long*)&r14);
    WC_S64(rsp, 64) = (word64)(rcx);
    WC_S64(rsp, 72) = (word64)(r8);
    WC_S64(rsp, 80) = (word64)(r9);
    WC_S64(rsp, 88) = (word64)(r10);
    WC_S64(rsp, 32) = (word64)(r11);
    WC_S64(rsp, 40) = (word64)(r12);
    WC_S64(rsp, 48) = (word64)(r13);
    WC_S64(rsp, 56) = (word64)(r14);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    rcx = (word64)(rax);
    r8 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r9 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r10 >> 63));
    rdx = (word64)(rdx * 19);
    r10 = (word64)(r10 & rbx);
    rbx = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r11 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    /* Store */
    WC_S64(rdi, 0) = (word64)(rcx);
    WC_S64(rdi, 8) = (word64)(r8);
    WC_S64(rdi, 16) = (word64)(r9);
    WC_S64(rdi, 24) = (word64)(r10);
    /* Sub */
    rcx = (word64)(WC_L64(rsp, 128));
    r8 = (word64)(WC_L64(rsp, 136));
    r9 = (word64)(WC_L64(rsp, 144));
    r10 = (word64)(WC_L64(rsp, 152));
    cf = _subborrow_u64(0, rcx, WC_L64(rsp, 96), (unsigned long long*)&rcx);
    cf = _subborrow_u64(cf, r8, WC_L64(rsp, 104), (unsigned long long*)&r8);
    cf = _subborrow_u64(cf, r9, WC_L64(rsp, 112), (unsigned long long*)&r9);
    cf = _subborrow_u64(cf, r10, WC_L64(rsp, 120), (unsigned long long*)&r10);
    cf = _subborrow_u64(cf, rbx, rbx, (unsigned long long*)&rbx);
    rbx = (word64)((rbx << 1) | (r10 >> 63));
    rbx = (word64)(rbx * -19);
    r10 = (word64)(r10 & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _subborrow_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _subborrow_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _subborrow_u64(cf, r10, 0, (unsigned long long*)&r10);
    WC_S64(rsp, 128) = (word64)(rcx);
    WC_S64(rsp, 136) = (word64)(r8);
    WC_S64(rsp, 144) = (word64)(r9);
    WC_S64(rsp, 152) = (word64)(r10);
    /* Square */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rsp, 32));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 40));
    r8 = (word64)(rax);
    r9 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rsp, 32));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 48));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rsp, 32));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 56));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rsp, 40));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 48));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rsp, 40));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 56));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rsp, 48));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 56));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /* Double */
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r8, r8, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r9, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rsp, 32));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    rcx = (word64)(rax);
    rbx = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rsp, 40));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r8, rbx, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rsp, 48));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r10, rbx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rsp, 56));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r12, rbx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r10 >> 63));
    rdx = (word64)(rdx * 19);
    r10 = (word64)(r10 & rbx);
    rbx = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r11 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    /* Store */
    WC_S64(rsp, 32) = (word64)(rcx);
    WC_S64(rsp, 40) = (word64)(r8);
    WC_S64(rsp, 48) = (word64)(r9);
    WC_S64(rsp, 56) = (word64)(r10);
    /* Square */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rsp, 64));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 72));
    r8 = (word64)(rax);
    r9 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rsp, 64));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 80));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rsp, 64));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 88));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rsp, 72));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 80));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rsp, 72));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 88));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rsp, 80));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 88));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /* Double */
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r8, r8, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r9, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rsp, 64));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    rcx = (word64)(rax);
    rbx = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rsp, 72));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r8, rbx, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rsp, 80));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r10, rbx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rsp, 88));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r12, rbx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r10 >> 63));
    rdx = (word64)(rdx * 19);
    r10 = (word64)(r10 & rbx);
    rbx = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r11 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    /* Store */
    WC_S64(rsp, 64) = (word64)(rcx);
    WC_S64(rsp, 72) = (word64)(r8);
    WC_S64(rsp, 80) = (word64)(r9);
    WC_S64(rsp, 88) = (word64)(r10);
    /* Multiply by 121666 */
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r9 = (word64)(0);
    rcx = (word64)(rax);
    r8 = (word64)(rdx);
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    r11 = (word64)(0x7fffffffffffffff);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(0, rcx, WC_L64(rsp, 96), (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, WC_L64(rsp, 104), (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, WC_L64(rsp, 112), (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, WC_L64(rsp, 120), (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    r12 = (word64)((r12 << 1) | (r10 >> 63));
    r10 = (word64)(r10 & r11);
    rax = (word64)(0x13);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    WC_S64(rsp, 96) = (word64)(rcx);
    WC_S64(rsp, 104) = (word64)(r8);
    WC_S64(rsp, 112) = (word64)(r9);
    WC_S64(rsp, 120) = (word64)(r10);
    /* Multiply by 9 */
    rax = (word64)(9);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 32));
    r9 = (word64)(0);
    rcx = (word64)(rax);
    r8 = (word64)(rdx);
    rax = (word64)(9);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 40));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    rax = (word64)(9);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 48));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    rax = (word64)(9);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 56));
    r11 = (word64)(0x7fffffffffffffff);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    r12 = (word64)((r12 << 1) | (r10 >> 63));
    r10 = (word64)(r10 & r11);
    rax = (word64)(0x13);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    WC_S64(rsp, 32) = (word64)(rcx);
    WC_S64(rsp, 40) = (word64)(r8);
    WC_S64(rsp, 48) = (word64)(r9);
    WC_S64(rsp, 56) = (word64)(r10);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    rcx = (word64)(rax);
    r8 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r9 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r10 >> 63));
    rdx = (word64)(rdx * 19);
    r10 = (word64)(r10 & rbx);
    rbx = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r11 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    /* Store */
    WC_S64(rsp, 0) = (word64)(rcx);
    WC_S64(rsp, 8) = (word64)(r8);
    WC_S64(rsp, 16) = (word64)(r9);
    WC_S64(rsp, 24) = (word64)(r10);
    rbp = (word64)(rbp - 1);
    if ((sword64)(rbp) >= (sword64)(3)) {
        goto L_curve25519_base_x64_bits;
    }
    r15 = (word64)(0 - r15);
    /* Conditional Swap */
    rcx = (word64)(WC_L64(rdi, 0));
    r8 = (word64)(WC_L64(rdi, 8));
    r9 = (word64)(WC_L64(rdi, 16));
    r10 = (word64)(WC_L64(rdi, 24));
    r11 = (word64)(WC_L64(rsp, 0));
    r12 = (word64)(WC_L64(rsp, 8));
    r13 = (word64)(WC_L64(rsp, 16));
    r14 = (word64)(WC_L64(rsp, 24));
    rcx = (word64)(rcx ^ WC_L64(rsp, 64));
    r8 = (word64)(r8 ^ WC_L64(rsp, 72));
    r9 = (word64)(r9 ^ WC_L64(rsp, 80));
    r10 = (word64)(r10 ^ WC_L64(rsp, 88));
    r11 = (word64)(r11 ^ WC_L64(rsp, 32));
    r12 = (word64)(r12 ^ WC_L64(rsp, 40));
    r13 = (word64)(r13 ^ WC_L64(rsp, 48));
    r14 = (word64)(r14 ^ WC_L64(rsp, 56));
    rcx = (word64)(rcx & r15);
    r8 = (word64)(r8 & r15);
    r9 = (word64)(r9 & r15);
    r10 = (word64)(r10 & r15);
    r11 = (word64)(r11 & r15);
    r12 = (word64)(r12 & r15);
    r13 = (word64)(r13 & r15);
    r14 = (word64)(r14 & r15);
    WC_S64(rdi, 0) = (word64)(WC_L64(rdi, 0) ^ rcx);
    WC_S64(rdi, 8) = (word64)(WC_L64(rdi, 8) ^ r8);
    WC_S64(rdi, 16) = (word64)(WC_L64(rdi, 16) ^ r9);
    WC_S64(rdi, 24) = (word64)(WC_L64(rdi, 24) ^ r10);
    WC_S64(rsp, 0) = (word64)(WC_L64(rsp, 0) ^ r11);
    WC_S64(rsp, 8) = (word64)(WC_L64(rsp, 8) ^ r12);
    WC_S64(rsp, 16) = (word64)(WC_L64(rsp, 16) ^ r13);
    WC_S64(rsp, 24) = (word64)(WC_L64(rsp, 24) ^ r14);
    WC_S64(rsp, 64) = (word64)(WC_L64(rsp, 64) ^ rcx);
    WC_S64(rsp, 72) = (word64)(WC_L64(rsp, 72) ^ r8);
    WC_S64(rsp, 80) = (word64)(WC_L64(rsp, 80) ^ r9);
    WC_S64(rsp, 88) = (word64)(WC_L64(rsp, 88) ^ r10);
    WC_S64(rsp, 32) = (word64)(WC_L64(rsp, 32) ^ r11);
    WC_S64(rsp, 40) = (word64)(WC_L64(rsp, 40) ^ r12);
    WC_S64(rsp, 48) = (word64)(WC_L64(rsp, 48) ^ r13);
    WC_S64(rsp, 56) = (word64)(WC_L64(rsp, 56) ^ r14);
L_curve25519_base_x64_3:
    /* Add-Sub */
    /* Add */
    rcx = (word64)(WC_L64(rdi, 0));
    r8 = (word64)(WC_L64(rdi, 8));
    r9 = (word64)(WC_L64(rdi, 16));
    r10 = (word64)(WC_L64(rdi, 24));
    r11 = (word64)(rcx);
    cf = _addcarry_u64(0, rcx, WC_L64(rsp, 0), (unsigned long long*)&rcx);
    r12 = (word64)(r8);
    cf = _addcarry_u64(cf, r8, WC_L64(rsp, 8), (unsigned long long*)&r8);
    r13 = (word64)(r9);
    cf = _addcarry_u64(cf, r9, WC_L64(rsp, 16), (unsigned long long*)&r9);
    r14 = (word64)(r10);
    cf = _addcarry_u64(cf, r10, WC_L64(rsp, 24), (unsigned long long*)&r10);
    rbx = (word64)(0);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    rbx = (word64)((rbx << 1) | (r10 >> 63));
    rbx = (word64)(rbx * 0x13);
    r10 = (word64)(r10 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    /* Sub */
    cf = _subborrow_u64(0, r11, WC_L64(rsp, 0), (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, r12, WC_L64(rsp, 8), (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, WC_L64(rsp, 16), (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, WC_L64(rsp, 24), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, rbx, rbx, (unsigned long long*)&rbx);
    rbx = (word64)((rbx << 1) | (r14 >> 63));
    rbx = (word64)(rbx * -19);
    r14 = (word64)(r14 & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r11, rbx, (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, 0, (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, 0, (unsigned long long*)&r14);
    WC_S64(rdi, 0) = (word64)(rcx);
    WC_S64(rdi, 8) = (word64)(r8);
    WC_S64(rdi, 16) = (word64)(r9);
    WC_S64(rdi, 24) = (word64)(r10);
    WC_S64(rsp, 128) = (word64)(r11);
    WC_S64(rsp, 136) = (word64)(r12);
    WC_S64(rsp, 144) = (word64)(r13);
    WC_S64(rsp, 152) = (word64)(r14);
    /* Square */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r8 = (word64)(rax);
    r9 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rsp, 144));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /* Double */
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r8, r8, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r9, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    rcx = (word64)(rax);
    rbx = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r8, rbx, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rsp, 144));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r10, rbx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rsp, 152));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r12, rbx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r10 >> 63));
    rdx = (word64)(rdx * 19);
    r10 = (word64)(r10 & rbx);
    rbx = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r11 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    /* Store */
    WC_S64(rsp, 96) = (word64)(rcx);
    WC_S64(rsp, 104) = (word64)(r8);
    WC_S64(rsp, 112) = (word64)(r9);
    WC_S64(rsp, 120) = (word64)(r10);
    /* Square */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r8 = (word64)(rax);
    r9 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rdi, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /* Double */
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r8, r8, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r9, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    rcx = (word64)(rax);
    rbx = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r8, rbx, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rdi, 16));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r10, rbx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rdi, 24));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r12, rbx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r10 >> 63));
    rdx = (word64)(rdx * 19);
    r10 = (word64)(r10 & rbx);
    rbx = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r11 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    /* Store */
    WC_S64(rsp, 128) = (word64)(rcx);
    WC_S64(rsp, 136) = (word64)(r8);
    WC_S64(rsp, 144) = (word64)(r9);
    WC_S64(rsp, 152) = (word64)(r10);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    rcx = (word64)(rax);
    r8 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r9 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r10 >> 63));
    rdx = (word64)(rdx * 19);
    r10 = (word64)(r10 & rbx);
    rbx = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r11 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    /* Store */
    WC_S64(rdi, 0) = (word64)(rcx);
    WC_S64(rdi, 8) = (word64)(r8);
    WC_S64(rdi, 16) = (word64)(r9);
    WC_S64(rdi, 24) = (word64)(r10);
    /* Sub */
    rcx = (word64)(WC_L64(rsp, 128));
    r8 = (word64)(WC_L64(rsp, 136));
    r9 = (word64)(WC_L64(rsp, 144));
    r10 = (word64)(WC_L64(rsp, 152));
    cf = _subborrow_u64(0, rcx, WC_L64(rsp, 96), (unsigned long long*)&rcx);
    cf = _subborrow_u64(cf, r8, WC_L64(rsp, 104), (unsigned long long*)&r8);
    cf = _subborrow_u64(cf, r9, WC_L64(rsp, 112), (unsigned long long*)&r9);
    cf = _subborrow_u64(cf, r10, WC_L64(rsp, 120), (unsigned long long*)&r10);
    cf = _subborrow_u64(cf, rbx, rbx, (unsigned long long*)&rbx);
    rbx = (word64)((rbx << 1) | (r10 >> 63));
    rbx = (word64)(rbx * -19);
    r10 = (word64)(r10 & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _subborrow_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _subborrow_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _subborrow_u64(cf, r10, 0, (unsigned long long*)&r10);
    WC_S64(rsp, 128) = (word64)(rcx);
    WC_S64(rsp, 136) = (word64)(r8);
    WC_S64(rsp, 144) = (word64)(r9);
    WC_S64(rsp, 152) = (word64)(r10);
    /* Multiply by 121666 */
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r9 = (word64)(0);
    rcx = (word64)(rax);
    r8 = (word64)(rdx);
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    r11 = (word64)(0x7fffffffffffffff);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(0, rcx, WC_L64(rsp, 96), (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, WC_L64(rsp, 104), (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, WC_L64(rsp, 112), (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, WC_L64(rsp, 120), (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    r12 = (word64)((r12 << 1) | (r10 >> 63));
    r10 = (word64)(r10 & r11);
    rax = (word64)(0x13);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    WC_S64(rsp, 96) = (word64)(rcx);
    WC_S64(rsp, 104) = (word64)(r8);
    WC_S64(rsp, 112) = (word64)(r9);
    WC_S64(rsp, 120) = (word64)(r10);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    rcx = (word64)(rax);
    r8 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r9 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r10 >> 63));
    rdx = (word64)(rdx * 19);
    r10 = (word64)(r10 & rbx);
    rbx = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r11 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    /* Store */
    WC_S64(rsp, 0) = (word64)(rcx);
    WC_S64(rsp, 8) = (word64)(r8);
    WC_S64(rsp, 16) = (word64)(r9);
    WC_S64(rsp, 24) = (word64)(r10);
    rbp = (word64)(rbp - 1);
    if ((sword64)(rbp) >= (sword64)(0)) {
        goto L_curve25519_base_x64_3;
    }
    /* Invert */
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(rsp + 96);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 64);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(4);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 64);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(9);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 128);
    rsi = (word64)(rsp + 96);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 128);
    rsi = (word64)(rsp + 128);
    rdx = (word64)(0x13);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 128);
    rdx = (word64)(rsp + 96);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(9);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 64);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(0x31);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 128);
    rsi = (word64)(rsp + 96);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 128);
    rsi = (word64)(rsp + 128);
    rdx = (word64)(0x63);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 128);
    rdx = (word64)(rsp + 96);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(0x31);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(4);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(WC_L64(rsp, 160));
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rsp, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    rcx = (word64)(rax);
    r8 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rsp, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r9 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rsp, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rsp, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rsp, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rsp, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rsp, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rsp, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rsp, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rsp, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rsp, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rsp, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rsp, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rsp, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rsp, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rsp, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbx = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r10 >> 63));
    rdx = (word64)(rdx * 19);
    r10 = (word64)(r10 & rbx);
    rbx = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r11 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(0, rcx, rbx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    rbx = (word64)(0x7fffffffffffffff);
    rax = (word64)(r10);
    rax = (word64)((word64)((sword64)rax >> 63));
    rax = (word64)(rax & 0x13);
    r10 = (word64)(r10 & rbx);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    rax = (word64)(0x7fffffffffffffff);
    rdx = (word64)(rcx);
    cf = _addcarry_u64(0, rdx, 0x13, (unsigned long long*)&rdx);
    rdx = (word64)(r8);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rdx = (word64)(r9);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rdx = (word64)(r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rdx = (word64)((word64)((sword64)rdx >> 63));
    rdx = (word64)(rdx & 0x13);
    r10 = (word64)(r10 & rax);
    cf = _addcarry_u64(0, rcx, rdx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    r10 = (word64)(r10 & rax);
    /* Store */
    WC_S64(rdi, 0) = (word64)(rcx);
    WC_S64(rdi, 8) = (word64)(r8);
    WC_S64(rdi, 16) = (word64)(r9);
    WC_S64(rdi, 24) = (word64)(r10);
    rax = (word64)(0);
    return (int)(word32)rax;
}

#endif /* WOLFSSL_CURVE25519_NOT_USE_ED25519 */
WOLFSSL_LOCAL int curve25519_x64(byte* r, byte* n, byte* a)
{
    word64 rdi, rsi, r8, rsp, rbx, rcx, r9, r10, r11, rbp = 0, r12 = 0,
           r13 = 0, r14 = 0, r15 = 0, rax = 0, rdx = 0;
    XALIGNED(32) WC_X64I_SLOT stk[24];
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)n;
    r8 = (word64)(size_t)a;

    rsp = (word64)(size_t)stk + 192;
    rsp = (word64)(rsp - 176);
    rbx = (word64)(0);
    WC_S64(rsp, 168) = (word64)(rdi);
    /* Set one */
    WC_S64(rdi, 0) = (word64)(1);
    WC_S64(rdi, 8) = (word64)(0);
    WC_S64(rdi, 16) = (word64)(0);
    WC_S64(rdi, 24) = (word64)(0);
    /* Set zero */
    WC_S64(rsp, 0) = (word64)(0);
    WC_S64(rsp, 8) = (word64)(0);
    WC_S64(rsp, 16) = (word64)(0);
    WC_S64(rsp, 24) = (word64)(0);
    /* Set one */
    WC_S64(rsp, 32) = (word64)(1);
    WC_S64(rsp, 40) = (word64)(0);
    WC_S64(rsp, 48) = (word64)(0);
    WC_S64(rsp, 56) = (word64)(0);
    /* Copy */
    rcx = (word64)(WC_L64(r8, 0));
    r9 = (word64)(WC_L64(r8, 8));
    r10 = (word64)(WC_L64(r8, 16));
    r11 = (word64)(WC_L64(r8, 24));
    WC_S64(rsp, 64) = (word64)(rcx);
    WC_S64(rsp, 72) = (word64)(r9);
    WC_S64(rsp, 80) = (word64)(r10);
    WC_S64(rsp, 88) = (word64)(r11);
    r9 = (word64)(0xfe);
L_curve25519_x64_bits:
    WC_S64(rsp, 160) = (word64)(r9);
    rcx = (word64)(r9);
    rcx = (word64)(rcx & 0x3f);
    r9 = (word64)(r9 >> 6);
    rbp = (word64)(WC_L64(rsi, r9 * 8));
    rbp = (word64)(rbp >> ((byte)rcx & 63));
    rbp = (word64)(rbp & 1);
    rbx = (word64)(rbx ^ rbp);
    rbx = (word64)(0 - rbx);
    /* Conditional Swap */
    rcx = (word64)(WC_L64(rdi, 0));
    r9 = (word64)(WC_L64(rdi, 8));
    r10 = (word64)(WC_L64(rdi, 16));
    r11 = (word64)(WC_L64(rdi, 24));
    r12 = (word64)(WC_L64(rsp, 0));
    r13 = (word64)(WC_L64(rsp, 8));
    r14 = (word64)(WC_L64(rsp, 16));
    r15 = (word64)(WC_L64(rsp, 24));
    rcx = (word64)(rcx ^ WC_L64(rsp, 64));
    r9 = (word64)(r9 ^ WC_L64(rsp, 72));
    r10 = (word64)(r10 ^ WC_L64(rsp, 80));
    r11 = (word64)(r11 ^ WC_L64(rsp, 88));
    r12 = (word64)(r12 ^ WC_L64(rsp, 32));
    r13 = (word64)(r13 ^ WC_L64(rsp, 40));
    r14 = (word64)(r14 ^ WC_L64(rsp, 48));
    r15 = (word64)(r15 ^ WC_L64(rsp, 56));
    rcx = (word64)(rcx & rbx);
    r9 = (word64)(r9 & rbx);
    r10 = (word64)(r10 & rbx);
    r11 = (word64)(r11 & rbx);
    r12 = (word64)(r12 & rbx);
    r13 = (word64)(r13 & rbx);
    r14 = (word64)(r14 & rbx);
    r15 = (word64)(r15 & rbx);
    WC_S64(rdi, 0) = (word64)(WC_L64(rdi, 0) ^ rcx);
    WC_S64(rdi, 8) = (word64)(WC_L64(rdi, 8) ^ r9);
    WC_S64(rdi, 16) = (word64)(WC_L64(rdi, 16) ^ r10);
    WC_S64(rdi, 24) = (word64)(WC_L64(rdi, 24) ^ r11);
    WC_S64(rsp, 0) = (word64)(WC_L64(rsp, 0) ^ r12);
    WC_S64(rsp, 8) = (word64)(WC_L64(rsp, 8) ^ r13);
    WC_S64(rsp, 16) = (word64)(WC_L64(rsp, 16) ^ r14);
    WC_S64(rsp, 24) = (word64)(WC_L64(rsp, 24) ^ r15);
    WC_S64(rsp, 64) = (word64)(WC_L64(rsp, 64) ^ rcx);
    WC_S64(rsp, 72) = (word64)(WC_L64(rsp, 72) ^ r9);
    WC_S64(rsp, 80) = (word64)(WC_L64(rsp, 80) ^ r10);
    WC_S64(rsp, 88) = (word64)(WC_L64(rsp, 88) ^ r11);
    WC_S64(rsp, 32) = (word64)(WC_L64(rsp, 32) ^ r12);
    WC_S64(rsp, 40) = (word64)(WC_L64(rsp, 40) ^ r13);
    WC_S64(rsp, 48) = (word64)(WC_L64(rsp, 48) ^ r14);
    WC_S64(rsp, 56) = (word64)(WC_L64(rsp, 56) ^ r15);
    rbx = (word64)(rbp);
    /* Add-Sub */
    /* Add */
    rcx = (word64)(WC_L64(rdi, 0));
    r9 = (word64)(WC_L64(rdi, 8));
    r10 = (word64)(WC_L64(rdi, 16));
    r11 = (word64)(WC_L64(rdi, 24));
    r12 = (word64)(rcx);
    cf = _addcarry_u64(0, rcx, WC_L64(rsp, 0), (unsigned long long*)&rcx);
    r13 = (word64)(r9);
    cf = _addcarry_u64(cf, r9, WC_L64(rsp, 8), (unsigned long long*)&r9);
    r14 = (word64)(r10);
    cf = _addcarry_u64(cf, r10, WC_L64(rsp, 16), (unsigned long long*)&r10);
    r15 = (word64)(r11);
    cf = _addcarry_u64(cf, r11, WC_L64(rsp, 24), (unsigned long long*)&r11);
    rbp = (word64)(0);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    rbp = (word64)((rbp << 1) | (r11 >> 63));
    rbp = (word64)(rbp * 0x13);
    r11 = (word64)(r11 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /* Sub */
    cf = _subborrow_u64(0, r12, WC_L64(rsp, 0), (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, WC_L64(rsp, 8), (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, WC_L64(rsp, 16), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, WC_L64(rsp, 24), (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbp, rbp, (unsigned long long*)&rbp);
    rbp = (word64)((rbp << 1) | (r15 >> 63));
    rbp = (word64)(rbp * -19);
    r15 = (word64)(r15 & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r12, rbp, (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, 0, (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    WC_S64(rdi, 0) = (word64)(rcx);
    WC_S64(rdi, 8) = (word64)(r9);
    WC_S64(rdi, 16) = (word64)(r10);
    WC_S64(rdi, 24) = (word64)(r11);
    WC_S64(rsp, 128) = (word64)(r12);
    WC_S64(rsp, 136) = (word64)(r13);
    WC_S64(rsp, 144) = (word64)(r14);
    WC_S64(rsp, 152) = (word64)(r15);
    /* Add-Sub */
    /* Add */
    rcx = (word64)(WC_L64(rsp, 64));
    r9 = (word64)(WC_L64(rsp, 72));
    r10 = (word64)(WC_L64(rsp, 80));
    r11 = (word64)(WC_L64(rsp, 88));
    r12 = (word64)(rcx);
    cf = _addcarry_u64(0, rcx, WC_L64(rsp, 32), (unsigned long long*)&rcx);
    r13 = (word64)(r9);
    cf = _addcarry_u64(cf, r9, WC_L64(rsp, 40), (unsigned long long*)&r9);
    r14 = (word64)(r10);
    cf = _addcarry_u64(cf, r10, WC_L64(rsp, 48), (unsigned long long*)&r10);
    r15 = (word64)(r11);
    cf = _addcarry_u64(cf, r11, WC_L64(rsp, 56), (unsigned long long*)&r11);
    rbp = (word64)(0);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    rbp = (word64)((rbp << 1) | (r11 >> 63));
    rbp = (word64)(rbp * 0x13);
    r11 = (word64)(r11 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /* Sub */
    cf = _subborrow_u64(0, r12, WC_L64(rsp, 32), (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, WC_L64(rsp, 40), (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, WC_L64(rsp, 48), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, WC_L64(rsp, 56), (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbp, rbp, (unsigned long long*)&rbp);
    rbp = (word64)((rbp << 1) | (r15 >> 63));
    rbp = (word64)(rbp * -19);
    r15 = (word64)(r15 & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r12, rbp, (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, 0, (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    WC_S64(rsp, 32) = (word64)(rcx);
    WC_S64(rsp, 40) = (word64)(r9);
    WC_S64(rsp, 48) = (word64)(r10);
    WC_S64(rsp, 56) = (word64)(r11);
    WC_S64(rsp, 96) = (word64)(r12);
    WC_S64(rsp, 104) = (word64)(r13);
    WC_S64(rsp, 112) = (word64)(r14);
    WC_S64(rsp, 120) = (word64)(r15);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 32));
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 32));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 40));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rsp, 144));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 32));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 40));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 48));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rsp, 152));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 32));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rsp, 144));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 40));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 48));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 56));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rsp, 152));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 40));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rsp, 144));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 48));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 56));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rsp, 152));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 48));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rsp, 144));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 56));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rsp, 152));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 56));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r11 >> 63));
    rdx = (word64)(rdx * 19);
    r11 = (word64)(r11 & rbp);
    rbp = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    /* Store */
    WC_S64(rsp, 32) = (word64)(rcx);
    WC_S64(rsp, 40) = (word64)(r9);
    WC_S64(rsp, 48) = (word64)(r10);
    WC_S64(rsp, 56) = (word64)(r11);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 96));
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 96));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 104));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rdi, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 96));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 104));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 112));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rdi, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 96));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rdi, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 104));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 112));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 120));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rdi, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 104));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rdi, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 112));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 120));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rdi, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 112));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rdi, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 120));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rdi, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 120));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r11 >> 63));
    rdx = (word64)(rdx * 19);
    r11 = (word64)(r11 & rbp);
    rbp = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    /* Store */
    WC_S64(rsp, 0) = (word64)(rcx);
    WC_S64(rsp, 8) = (word64)(r9);
    WC_S64(rsp, 16) = (word64)(r10);
    WC_S64(rsp, 24) = (word64)(r11);
    /* Square */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r9 = (word64)(rax);
    r10 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rsp, 144));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /* Double */
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r9, r9, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, r14, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    rcx = (word64)(rax);
    rbp = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r9, rbp, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rsp, 144));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r11, rbp, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rsp, 152));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(0, r13, rbp, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r11 >> 63));
    rdx = (word64)(rdx * 19);
    r11 = (word64)(r11 & rbp);
    rbp = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    /* Store */
    WC_S64(rsp, 96) = (word64)(rcx);
    WC_S64(rsp, 104) = (word64)(r9);
    WC_S64(rsp, 112) = (word64)(r10);
    WC_S64(rsp, 120) = (word64)(r11);
    /* Square */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r9 = (word64)(rax);
    r10 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rdi, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /* Double */
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r9, r9, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, r14, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    rcx = (word64)(rax);
    rbp = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r9, rbp, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rdi, 16));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r11, rbp, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rdi, 24));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(0, r13, rbp, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r11 >> 63));
    rdx = (word64)(rdx * 19);
    r11 = (word64)(r11 & rbp);
    rbp = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    /* Store */
    WC_S64(rsp, 128) = (word64)(rcx);
    WC_S64(rsp, 136) = (word64)(r9);
    WC_S64(rsp, 144) = (word64)(r10);
    WC_S64(rsp, 152) = (word64)(r11);
    /* Add-Sub */
    /* Add */
    rcx = (word64)(WC_L64(rsp, 0));
    r9 = (word64)(WC_L64(rsp, 8));
    r10 = (word64)(WC_L64(rsp, 16));
    r11 = (word64)(WC_L64(rsp, 24));
    r12 = (word64)(rcx);
    cf = _addcarry_u64(0, rcx, WC_L64(rsp, 32), (unsigned long long*)&rcx);
    r13 = (word64)(r9);
    cf = _addcarry_u64(cf, r9, WC_L64(rsp, 40), (unsigned long long*)&r9);
    r14 = (word64)(r10);
    cf = _addcarry_u64(cf, r10, WC_L64(rsp, 48), (unsigned long long*)&r10);
    r15 = (word64)(r11);
    cf = _addcarry_u64(cf, r11, WC_L64(rsp, 56), (unsigned long long*)&r11);
    rbp = (word64)(0);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    rbp = (word64)((rbp << 1) | (r11 >> 63));
    rbp = (word64)(rbp * 0x13);
    r11 = (word64)(r11 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /* Sub */
    cf = _subborrow_u64(0, r12, WC_L64(rsp, 32), (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, WC_L64(rsp, 40), (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, WC_L64(rsp, 48), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, WC_L64(rsp, 56), (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbp, rbp, (unsigned long long*)&rbp);
    rbp = (word64)((rbp << 1) | (r15 >> 63));
    rbp = (word64)(rbp * -19);
    r15 = (word64)(r15 & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r12, rbp, (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, 0, (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    WC_S64(rsp, 64) = (word64)(rcx);
    WC_S64(rsp, 72) = (word64)(r9);
    WC_S64(rsp, 80) = (word64)(r10);
    WC_S64(rsp, 88) = (word64)(r11);
    WC_S64(rsp, 32) = (word64)(r12);
    WC_S64(rsp, 40) = (word64)(r13);
    WC_S64(rsp, 48) = (word64)(r14);
    WC_S64(rsp, 56) = (word64)(r15);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r11 >> 63));
    rdx = (word64)(rdx * 19);
    r11 = (word64)(r11 & rbp);
    rbp = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    /* Store */
    WC_S64(rdi, 0) = (word64)(rcx);
    WC_S64(rdi, 8) = (word64)(r9);
    WC_S64(rdi, 16) = (word64)(r10);
    WC_S64(rdi, 24) = (word64)(r11);
    /* Sub */
    rcx = (word64)(WC_L64(rsp, 128));
    r9 = (word64)(WC_L64(rsp, 136));
    r10 = (word64)(WC_L64(rsp, 144));
    r11 = (word64)(WC_L64(rsp, 152));
    cf = _subborrow_u64(0, rcx, WC_L64(rsp, 96), (unsigned long long*)&rcx);
    cf = _subborrow_u64(cf, r9, WC_L64(rsp, 104), (unsigned long long*)&r9);
    cf = _subborrow_u64(cf, r10, WC_L64(rsp, 112), (unsigned long long*)&r10);
    cf = _subborrow_u64(cf, r11, WC_L64(rsp, 120), (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, rbp, rbp, (unsigned long long*)&rbp);
    rbp = (word64)((rbp << 1) | (r11 >> 63));
    rbp = (word64)(rbp * -19);
    r11 = (word64)(r11 & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _subborrow_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _subborrow_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _subborrow_u64(cf, r11, 0, (unsigned long long*)&r11);
    WC_S64(rsp, 128) = (word64)(rcx);
    WC_S64(rsp, 136) = (word64)(r9);
    WC_S64(rsp, 144) = (word64)(r10);
    WC_S64(rsp, 152) = (word64)(r11);
    /* Square */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rsp, 32));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 40));
    r9 = (word64)(rax);
    r10 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rsp, 32));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 48));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rsp, 32));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 56));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rsp, 40));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 48));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rsp, 40));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 56));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rsp, 48));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 56));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /* Double */
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r9, r9, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, r14, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rsp, 32));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    rcx = (word64)(rax);
    rbp = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rsp, 40));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r9, rbp, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rsp, 48));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r11, rbp, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rsp, 56));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(0, r13, rbp, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r11 >> 63));
    rdx = (word64)(rdx * 19);
    r11 = (word64)(r11 & rbp);
    rbp = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    /* Store */
    WC_S64(rsp, 32) = (word64)(rcx);
    WC_S64(rsp, 40) = (word64)(r9);
    WC_S64(rsp, 48) = (word64)(r10);
    WC_S64(rsp, 56) = (word64)(r11);
    /* Square */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rsp, 64));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 72));
    r9 = (word64)(rax);
    r10 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rsp, 64));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 80));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rsp, 64));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 88));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rsp, 72));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 80));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rsp, 72));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 88));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rsp, 80));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 88));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /* Double */
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r9, r9, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, r14, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rsp, 64));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    rcx = (word64)(rax);
    rbp = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rsp, 72));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r9, rbp, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rsp, 80));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r11, rbp, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rsp, 88));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(0, r13, rbp, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r11 >> 63));
    rdx = (word64)(rdx * 19);
    r11 = (word64)(r11 & rbp);
    rbp = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    rbp = (word64)(0x7fffffffffffffff);
    rax = (word64)(r11);
    rax = (word64)((word64)((sword64)rax >> 63));
    rax = (word64)(rax & 0x13);
    r11 = (word64)(r11 & rbp);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /* Store */
    WC_S64(rsp, 64) = (word64)(rcx);
    WC_S64(rsp, 72) = (word64)(r9);
    WC_S64(rsp, 80) = (word64)(r10);
    WC_S64(rsp, 88) = (word64)(r11);
    /* Multiply by 121666 */
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r10 = (word64)(0);
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    r12 = (word64)(0x7fffffffffffffff);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(0, rcx, WC_L64(rsp, 96), (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, WC_L64(rsp, 104), (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, WC_L64(rsp, 112), (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, WC_L64(rsp, 120), (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    r13 = (word64)((r13 << 1) | (r11 >> 63));
    r11 = (word64)(r11 & r12);
    rax = (word64)(0x13);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    WC_S64(rsp, 96) = (word64)(rcx);
    WC_S64(rsp, 104) = (word64)(r9);
    WC_S64(rsp, 112) = (word64)(r10);
    WC_S64(rsp, 120) = (word64)(r11);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rsp, 32));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rsp, 40));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rsp, 32));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rsp, 48));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rsp, 40));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rsp, 32));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rsp, 56));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rsp, 48));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rsp, 40));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rsp, 32));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rsp, 56));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rsp, 48));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rsp, 40));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rsp, 56));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rsp, 48));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rsp, 56));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r11 >> 63));
    rdx = (word64)(rdx * 19);
    r11 = (word64)(r11 & rbp);
    rbp = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    /* Store */
    WC_S64(rsp, 32) = (word64)(rcx);
    WC_S64(rsp, 40) = (word64)(r9);
    WC_S64(rsp, 48) = (word64)(r10);
    WC_S64(rsp, 56) = (word64)(r11);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r11 >> 63));
    rdx = (word64)(rdx * 19);
    r11 = (word64)(r11 & rbp);
    rbp = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    /* Store */
    WC_S64(rsp, 0) = (word64)(rcx);
    WC_S64(rsp, 8) = (word64)(r9);
    WC_S64(rsp, 16) = (word64)(r10);
    WC_S64(rsp, 24) = (word64)(r11);
    r9 = (word64)(WC_L64(rsp, 160));
    r9 = (word64)(r9 - 1);
    if ((sword64)(r9) >= (sword64)(3)) {
        goto L_curve25519_x64_bits;
    }
    WC_S64(rsp, 160) = (word64)(2);
    rbx = (word64)(0 - rbx);
    /* Conditional Swap */
    rcx = (word64)(WC_L64(rdi, 0));
    r9 = (word64)(WC_L64(rdi, 8));
    r10 = (word64)(WC_L64(rdi, 16));
    r11 = (word64)(WC_L64(rdi, 24));
    r12 = (word64)(WC_L64(rsp, 0));
    r13 = (word64)(WC_L64(rsp, 8));
    r14 = (word64)(WC_L64(rsp, 16));
    r15 = (word64)(WC_L64(rsp, 24));
    rcx = (word64)(rcx ^ WC_L64(rsp, 64));
    r9 = (word64)(r9 ^ WC_L64(rsp, 72));
    r10 = (word64)(r10 ^ WC_L64(rsp, 80));
    r11 = (word64)(r11 ^ WC_L64(rsp, 88));
    r12 = (word64)(r12 ^ WC_L64(rsp, 32));
    r13 = (word64)(r13 ^ WC_L64(rsp, 40));
    r14 = (word64)(r14 ^ WC_L64(rsp, 48));
    r15 = (word64)(r15 ^ WC_L64(rsp, 56));
    rcx = (word64)(rcx & rbx);
    r9 = (word64)(r9 & rbx);
    r10 = (word64)(r10 & rbx);
    r11 = (word64)(r11 & rbx);
    r12 = (word64)(r12 & rbx);
    r13 = (word64)(r13 & rbx);
    r14 = (word64)(r14 & rbx);
    r15 = (word64)(r15 & rbx);
    WC_S64(rdi, 0) = (word64)(WC_L64(rdi, 0) ^ rcx);
    WC_S64(rdi, 8) = (word64)(WC_L64(rdi, 8) ^ r9);
    WC_S64(rdi, 16) = (word64)(WC_L64(rdi, 16) ^ r10);
    WC_S64(rdi, 24) = (word64)(WC_L64(rdi, 24) ^ r11);
    WC_S64(rsp, 0) = (word64)(WC_L64(rsp, 0) ^ r12);
    WC_S64(rsp, 8) = (word64)(WC_L64(rsp, 8) ^ r13);
    WC_S64(rsp, 16) = (word64)(WC_L64(rsp, 16) ^ r14);
    WC_S64(rsp, 24) = (word64)(WC_L64(rsp, 24) ^ r15);
    WC_S64(rsp, 64) = (word64)(WC_L64(rsp, 64) ^ rcx);
    WC_S64(rsp, 72) = (word64)(WC_L64(rsp, 72) ^ r9);
    WC_S64(rsp, 80) = (word64)(WC_L64(rsp, 80) ^ r10);
    WC_S64(rsp, 88) = (word64)(WC_L64(rsp, 88) ^ r11);
    WC_S64(rsp, 32) = (word64)(WC_L64(rsp, 32) ^ r12);
    WC_S64(rsp, 40) = (word64)(WC_L64(rsp, 40) ^ r13);
    WC_S64(rsp, 48) = (word64)(WC_L64(rsp, 48) ^ r14);
    WC_S64(rsp, 56) = (word64)(WC_L64(rsp, 56) ^ r15);
L_curve25519_x64_3:
    /* Add-Sub */
    /* Add */
    rcx = (word64)(WC_L64(rdi, 0));
    r9 = (word64)(WC_L64(rdi, 8));
    r10 = (word64)(WC_L64(rdi, 16));
    r11 = (word64)(WC_L64(rdi, 24));
    r12 = (word64)(rcx);
    cf = _addcarry_u64(0, rcx, WC_L64(rsp, 0), (unsigned long long*)&rcx);
    r13 = (word64)(r9);
    cf = _addcarry_u64(cf, r9, WC_L64(rsp, 8), (unsigned long long*)&r9);
    r14 = (word64)(r10);
    cf = _addcarry_u64(cf, r10, WC_L64(rsp, 16), (unsigned long long*)&r10);
    r15 = (word64)(r11);
    cf = _addcarry_u64(cf, r11, WC_L64(rsp, 24), (unsigned long long*)&r11);
    rbp = (word64)(0);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    rbp = (word64)((rbp << 1) | (r11 >> 63));
    rbp = (word64)(rbp * 0x13);
    r11 = (word64)(r11 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /* Sub */
    cf = _subborrow_u64(0, r12, WC_L64(rsp, 0), (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, WC_L64(rsp, 8), (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, WC_L64(rsp, 16), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, WC_L64(rsp, 24), (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbp, rbp, (unsigned long long*)&rbp);
    rbp = (word64)((rbp << 1) | (r15 >> 63));
    rbp = (word64)(rbp * -19);
    r15 = (word64)(r15 & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r12, rbp, (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, 0, (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    WC_S64(rdi, 0) = (word64)(rcx);
    WC_S64(rdi, 8) = (word64)(r9);
    WC_S64(rdi, 16) = (word64)(r10);
    WC_S64(rdi, 24) = (word64)(r11);
    WC_S64(rsp, 128) = (word64)(r12);
    WC_S64(rsp, 136) = (word64)(r13);
    WC_S64(rsp, 144) = (word64)(r14);
    WC_S64(rsp, 152) = (word64)(r15);
    /* Square */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r9 = (word64)(rax);
    r10 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rsp, 144));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /* Double */
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r9, r9, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, r14, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rsp, 128));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    rcx = (word64)(rax);
    rbp = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rsp, 136));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r9, rbp, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rsp, 144));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r11, rbp, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rsp, 152));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(0, r13, rbp, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r11 >> 63));
    rdx = (word64)(rdx * 19);
    r11 = (word64)(r11 & rbp);
    rbp = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    /* Store */
    WC_S64(rsp, 96) = (word64)(rcx);
    WC_S64(rsp, 104) = (word64)(r9);
    WC_S64(rsp, 112) = (word64)(r10);
    WC_S64(rsp, 120) = (word64)(r11);
    /* Square */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r9 = (word64)(rax);
    r10 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rdi, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /* Double */
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r9, r9, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, r14, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    rcx = (word64)(rax);
    rbp = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r9, rbp, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rdi, 16));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r11, rbp, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rdi, 24));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(0, r13, rbp, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r11 >> 63));
    rdx = (word64)(rdx * 19);
    r11 = (word64)(r11 & rbp);
    rbp = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    /* Store */
    WC_S64(rsp, 128) = (word64)(rcx);
    WC_S64(rsp, 136) = (word64)(r9);
    WC_S64(rsp, 144) = (word64)(r10);
    WC_S64(rsp, 152) = (word64)(r11);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r11 >> 63));
    rdx = (word64)(rdx * 19);
    r11 = (word64)(r11 & rbp);
    rbp = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    /* Store */
    WC_S64(rdi, 0) = (word64)(rcx);
    WC_S64(rdi, 8) = (word64)(r9);
    WC_S64(rdi, 16) = (word64)(r10);
    WC_S64(rdi, 24) = (word64)(r11);
    /* Sub */
    rcx = (word64)(WC_L64(rsp, 128));
    r9 = (word64)(WC_L64(rsp, 136));
    r10 = (word64)(WC_L64(rsp, 144));
    r11 = (word64)(WC_L64(rsp, 152));
    cf = _subborrow_u64(0, rcx, WC_L64(rsp, 96), (unsigned long long*)&rcx);
    cf = _subborrow_u64(cf, r9, WC_L64(rsp, 104), (unsigned long long*)&r9);
    cf = _subborrow_u64(cf, r10, WC_L64(rsp, 112), (unsigned long long*)&r10);
    cf = _subborrow_u64(cf, r11, WC_L64(rsp, 120), (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, rbp, rbp, (unsigned long long*)&rbp);
    rbp = (word64)((rbp << 1) | (r11 >> 63));
    rbp = (word64)(rbp * -19);
    r11 = (word64)(r11 & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _subborrow_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _subborrow_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _subborrow_u64(cf, r11, 0, (unsigned long long*)&r11);
    WC_S64(rsp, 128) = (word64)(rcx);
    WC_S64(rsp, 136) = (word64)(r9);
    WC_S64(rsp, 144) = (word64)(r10);
    WC_S64(rsp, 152) = (word64)(r11);
    /* Multiply by 121666 */
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r10 = (word64)(0);
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    rax = (word64)(0x1db42);
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    r12 = (word64)(0x7fffffffffffffff);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(0, rcx, WC_L64(rsp, 96), (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, WC_L64(rsp, 104), (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, WC_L64(rsp, 112), (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, WC_L64(rsp, 120), (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    r13 = (word64)((r13 << 1) | (r11 >> 63));
    r11 = (word64)(r11 & r12);
    rax = (word64)(0x13);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    WC_S64(rsp, 96) = (word64)(rcx);
    WC_S64(rsp, 104) = (word64)(r9);
    WC_S64(rsp, 112) = (word64)(r10);
    WC_S64(rsp, 120) = (word64)(r11);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 128));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rsp, 96));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 136));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rsp, 104));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 144));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rsp, 112));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rsp, 120));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsp, 152));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r11 >> 63));
    rdx = (word64)(rdx * 19);
    r11 = (word64)(r11 & rbp);
    rbp = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    /* Store */
    WC_S64(rsp, 0) = (word64)(rcx);
    WC_S64(rsp, 8) = (word64)(r9);
    WC_S64(rsp, 16) = (word64)(r10);
    WC_S64(rsp, 24) = (word64)(r11);
    WC_S64(rsp, 160) = (word64)(WC_L64(rsp, 160) - 1);
    if ((sword64)(WC_S64(rsp, 160)) >= (sword64)(0)) {
        goto L_curve25519_x64_3;
    }
    /* Invert */
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(rsp + 96);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 64);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(4);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 64);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(9);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 128);
    rsi = (word64)(rsp + 96);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 128);
    rsi = (word64)(rsp + 128);
    rdx = (word64)(0x13);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 128);
    rdx = (word64)(rsp + 96);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(9);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 64);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(0x31);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 128);
    rsi = (word64)(rsp + 96);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 128);
    rsi = (word64)(rsp + 128);
    rdx = (word64)(0x63);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 128);
    rdx = (word64)(rsp + 96);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(0x31);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(4);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(WC_L64(rsp, 168));
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rsp, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rsp, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rsp, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rsp, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rsp, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rsp, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rsp, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rsp, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rsp, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rsp, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rsp, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rsp, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rsp, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rsp, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rsp, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rsp, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rbp = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r11 >> 63));
    rdx = (word64)(rdx * 19);
    r11 = (word64)(r11 & rbp);
    rbp = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, rcx, rbp, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    rbp = (word64)(0x7fffffffffffffff);
    rax = (word64)(r11);
    rax = (word64)((word64)((sword64)rax >> 63));
    rax = (word64)(rax & 0x13);
    r11 = (word64)(r11 & rbp);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    rax = (word64)(0x7fffffffffffffff);
    rdx = (word64)(rcx);
    cf = _addcarry_u64(0, rdx, 0x13, (unsigned long long*)&rdx);
    rdx = (word64)(r9);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rdx = (word64)(r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rdx = (word64)(r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    rdx = (word64)((word64)((sword64)rdx >> 63));
    rdx = (word64)(rdx & 0x13);
    r11 = (word64)(r11 & rax);
    cf = _addcarry_u64(0, rcx, rdx, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    r11 = (word64)(r11 & rax);
    /* Store */
    WC_S64(rdi, 0) = (word64)(rcx);
    WC_S64(rdi, 8) = (word64)(r9);
    WC_S64(rdi, 16) = (word64)(r10);
    WC_S64(rdi, 24) = (word64)(r11);
    rax = (word64)(0);
    return (int)(word32)rax;
}

WOLFSSL_LOCAL void fe_pow22523_x64(fe r, const fe a)
{
    word64 rdi, rsi, rsp, rdx;
    XALIGNED(32) WC_X64I_SLOT stk[16];

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)a;

    rsp = (word64)(size_t)stk + 128;
    rsp = (word64)(rsp - 112);
    /* pow22523 */
    WC_S64(rsp, 96) = (word64)(rdi);
    WC_S64(rsp, 104) = (word64)(rsi);
    rdi = (word64)(rsp);
    rsi = (word64)(WC_L64(rsp, 104));
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(WC_L64(rsp, 104));
    rdx = (word64)(rsp + 32);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(rsp);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(4);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(rsp);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(9);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(rsp);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(0x13);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(9);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(rsp);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(0x31);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(rsp);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(0x63);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(0x31);
    (void)fe_sq_n_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(rsp);
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp);
    (void)fe_sq_x64((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(WC_L64(rsp, 96));
    rsi = (word64)(rsp);
    rdx = (word64)(WC_L64(rsp, 104));
    (void)fe_mul_x64((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rsi = (word64)(WC_L64(rsp, 104));
    rdi = (word64)(WC_L64(rsp, 96));
}

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_p1p1_to_p2_x64(ge_p2* r, const ge_p1p1* p)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
    word64 rdi, rsi, rsp, rcx, rax, rdx = 0, r9, r10, r11, r12, r13, r14, r15,
           rbx, r8;
    XALIGNED(32) WC_X64I_SLOT stk[4];
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)p;

    rsp = (word64)(size_t)stk + 32;
    rsp = (word64)(rsp - 16);
    WC_S64(rsp, 0) = (word64)(rdi);
    WC_S64(rsp, 8) = (word64)(rsi);
    rcx = (word64)(rsi);
    rcx = (word64)(rcx + 0x60);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r9 = (word64)(rax);
    r10 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r12 >> 63));
    rdx = (word64)(rdx * 19);
    r12 = (word64)(r12 & r8);
    r8 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(0, r9, r8, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    /* Store */
    WC_S64(rdi, 0) = (word64)(r9);
    WC_S64(rdi, 8) = (word64)(r10);
    WC_S64(rdi, 16) = (word64)(r11);
    WC_S64(rdi, 24) = (word64)(r12);
    rsi = (word64)(rsi + 0x40);
    rdi = (word64)(rdi + 0x40);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r9 = (word64)(rax);
    r10 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r12 >> 63));
    rdx = (word64)(rdx * 19);
    r12 = (word64)(r12 & r8);
    r8 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(0, r9, r8, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    /* Store */
    WC_S64(rdi, 0) = (word64)(r9);
    WC_S64(rdi, 8) = (word64)(r10);
    WC_S64(rdi, 16) = (word64)(r11);
    WC_S64(rdi, 24) = (word64)(r12);
    rcx = (word64)(rsi);
    rcx = (word64)(rcx - 0x20);
    rdi = (word64)(rdi - 0x20);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r9 = (word64)(rax);
    r10 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r12 >> 63));
    rdx = (word64)(rdx * 19);
    r12 = (word64)(r12 & r8);
    r8 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(0, r9, r8, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    /* Store */
    WC_S64(rdi, 0) = (word64)(r9);
    WC_S64(rdi, 8) = (word64)(r10);
    WC_S64(rdi, 16) = (word64)(r11);
    WC_S64(rdi, 24) = (word64)(r12);
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_p1p1_to_p3_x64(ge_p3* r, const ge_p1p1* p)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
    word64 rdi, rsi, rsp, rcx, rax, rdx = 0, r9, r10, r11, r12, r13, r14, r15,
           rbx, r8;
    XALIGNED(32) WC_X64I_SLOT stk[4];
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)p;

    rsp = (word64)(size_t)stk + 32;
    rsp = (word64)(rsp - 16);
    WC_S64(rsp, 0) = (word64)(rdi);
    WC_S64(rsp, 8) = (word64)(rsi);
    rcx = (word64)(rsi);
    rcx = (word64)(rcx + 0x60);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r9 = (word64)(rax);
    r10 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r12 >> 63));
    rdx = (word64)(rdx * 19);
    r12 = (word64)(r12 & r8);
    r8 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(0, r9, r8, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    /* Store */
    WC_S64(rdi, 0) = (word64)(r9);
    WC_S64(rdi, 8) = (word64)(r10);
    WC_S64(rdi, 16) = (word64)(r11);
    WC_S64(rdi, 24) = (word64)(r12);
    rcx = (word64)(rsi);
    rcx = (word64)(rcx + 0x20);
    rdi = (word64)(rdi + 0x60);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r9 = (word64)(rax);
    r10 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r12 >> 63));
    rdx = (word64)(rdx * 19);
    r12 = (word64)(r12 & r8);
    r8 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(0, r9, r8, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    /* Store */
    WC_S64(rdi, 0) = (word64)(r9);
    WC_S64(rdi, 8) = (word64)(r10);
    WC_S64(rdi, 16) = (word64)(r11);
    WC_S64(rdi, 24) = (word64)(r12);
    rsi = (word64)(rsi + 0x40);
    rdi = (word64)(rdi - 0x40);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r9 = (word64)(rax);
    r10 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r12 >> 63));
    rdx = (word64)(rdx * 19);
    r12 = (word64)(r12 & r8);
    r8 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(0, r9, r8, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    /* Store */
    WC_S64(rdi, 0) = (word64)(r9);
    WC_S64(rdi, 8) = (word64)(r10);
    WC_S64(rdi, 16) = (word64)(r11);
    WC_S64(rdi, 24) = (word64)(r12);
    rcx = (word64)(rsi);
    rcx = (word64)(rcx + 0x20);
    rdi = (word64)(rdi + 0x20);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r9 = (word64)(rax);
    r10 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r12 >> 63));
    rdx = (word64)(rdx * 19);
    r12 = (word64)(r12 & r8);
    r8 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(0, r9, r8, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    /* Store */
    WC_S64(rdi, 0) = (word64)(r9);
    WC_S64(rdi, 8) = (word64)(r10);
    WC_S64(rdi, 16) = (word64)(r11);
    WC_S64(rdi, 24) = (word64)(r12);
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_p2_dbl_x64(ge_p1p1* r, const ge_p2* p)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
    word64 rdi, rsi, rsp, rax, rdx = 0, r10, r11, r12, r13, r14, r15, rbx, r9,
           r8, rcx;
    XALIGNED(32) WC_X64I_SLOT stk[4];
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)p;

    rsp = (word64)(size_t)stk + 32;
    rsp = (word64)(rsp - 16);
    WC_S64(rsp, 0) = (word64)(rdi);
    WC_S64(rsp, 8) = (word64)(rsi);
    rdi = (word64)(rdi + 0x40);
    /* Square */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r10 = (word64)(rax);
    r11 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rsi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rsi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rsi, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    /* Double */
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, r14, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, r15, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r9 = (word64)(rax);
    r8 = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rsi, 8));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r10, r8, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rsi, 16));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r12, r8, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rsi, 24));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r14, r8, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r12 >> 63));
    rdx = (word64)(rdx * 19);
    r12 = (word64)(r12 & r8);
    r8 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(0, r9, r8, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    /* Store */
    WC_S64(rdi, 0) = (word64)(r9);
    WC_S64(rdi, 8) = (word64)(r10);
    WC_S64(rdi, 16) = (word64)(r11);
    WC_S64(rdi, 24) = (word64)(r12);
    rsi = (word64)(rsi + 0x20);
    /* Square */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r10 = (word64)(rax);
    r11 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rsi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rsi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rsi, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    /* Double */
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, r14, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, r15, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r9 = (word64)(rax);
    r8 = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rsi, 8));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r10, r8, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rsi, 16));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r12, r8, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rsi, 24));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r14, r8, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r12 >> 63));
    rdx = (word64)(rdx * 19);
    r12 = (word64)(r12 & r8);
    r8 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(0, r9, r8, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    /* Store */
    rsi = (word64)(rdi);
    rdi = (word64)(rdi - 0x20);
    /* Add-Sub */
    /* Add */
    r13 = (word64)(r9);
    cf = _addcarry_u64(0, r9, WC_L64(rsi, 0), (unsigned long long*)&r9);
    r14 = (word64)(r10);
    cf = _addcarry_u64(cf, r10, WC_L64(rsi, 8), (unsigned long long*)&r10);
    r15 = (word64)(r11);
    cf = _addcarry_u64(cf, r11, WC_L64(rsi, 16), (unsigned long long*)&r11);
    rbx = (word64)(r12);
    cf = _addcarry_u64(cf, r12, WC_L64(rsi, 24), (unsigned long long*)&r12);
    r8 = (word64)(0);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    r8 = (word64)((r8 << 1) | (r12 >> 63));
    r8 = (word64)(r8 * 0x13);
    r12 = (word64)(r12 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, r9, r8, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /* Sub */
    cf = _subborrow_u64(0, r13, WC_L64(rsi, 0), (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, WC_L64(rsi, 8), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, WC_L64(rsi, 16), (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, WC_L64(rsi, 24), (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, r8, r8, (unsigned long long*)&r8);
    r8 = (word64)((r8 << 1) | (rbx >> 63));
    r8 = (word64)(r8 * -19);
    rbx = (word64)(rbx & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r13, r8, (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    WC_S64(rdi, 0) = (word64)(r9);
    WC_S64(rdi, 8) = (word64)(r10);
    WC_S64(rdi, 16) = (word64)(r11);
    WC_S64(rdi, 24) = (word64)(r12);
    WC_S64(rsi, 0) = (word64)(r13);
    WC_S64(rsi, 8) = (word64)(r14);
    WC_S64(rsi, 16) = (word64)(r15);
    WC_S64(rsi, 24) = (word64)(rbx);
    rcx = (word64)(WC_L64(rsp, 8));
    rsi = (word64)(rcx);
    rsi = (word64)(rsi + 0x20);
    rdi = (word64)(rdi - 0x20);
    /* Add */
    r9 = (word64)(WC_L64(rsi, 0));
    r10 = (word64)(WC_L64(rsi, 8));
    cf = _addcarry_u64(0, r9, WC_L64(rcx, 0), (unsigned long long*)&r9);
    r11 = (word64)(WC_L64(rsi, 16));
    cf = _addcarry_u64(cf, r10, WC_L64(rcx, 8), (unsigned long long*)&r10);
    r12 = (word64)(WC_L64(rsi, 24));
    cf = _addcarry_u64(cf, r11, WC_L64(rcx, 16), (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, WC_L64(rcx, 24), (unsigned long long*)&r12);
    r8 = (word64)(0);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    r8 = (word64)((r8 << 1) | (r12 >> 63));
    r8 = (word64)(r8 * 0x13);
    r12 = (word64)(r12 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, r9, r8, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rdi, 0) = (word64)(r9);
    WC_S64(rdi, 8) = (word64)(r10);
    WC_S64(rdi, 16) = (word64)(r11);
    WC_S64(rdi, 24) = (word64)(r12);
    /* Square */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r10 = (word64)(rax);
    r11 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rdi, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    /* Double */
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, r14, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, r15, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rdi, 0));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r9 = (word64)(rax);
    r8 = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rdi, 8));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r10, r8, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rdi, 16));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r12, r8, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rdi, 24));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r14, r8, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r12 >> 63));
    rdx = (word64)(rdx * 19);
    r12 = (word64)(r12 & r8);
    r8 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(0, r9, r8, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    /* Store */
    rsi = (word64)(rdi);
    rsi = (word64)(rsi + 0x20);
    /* Sub */
    cf = _subborrow_u64(0, r9, WC_L64(rsi, 0), (unsigned long long*)&r9);
    cf = _subborrow_u64(cf, r10, WC_L64(rsi, 8), (unsigned long long*)&r10);
    cf = _subborrow_u64(cf, r11, WC_L64(rsi, 16), (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, r12, WC_L64(rsi, 24), (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r8, r8, (unsigned long long*)&r8);
    r8 = (word64)((r8 << 1) | (r12 >> 63));
    r8 = (word64)(r8 * -19);
    r12 = (word64)(r12 & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r9, r8, (unsigned long long*)&r9);
    cf = _subborrow_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _subborrow_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rdi, 0) = (word64)(r9);
    WC_S64(rdi, 8) = (word64)(r10);
    WC_S64(rdi, 16) = (word64)(r11);
    WC_S64(rdi, 24) = (word64)(r12);
    rcx = (word64)(rcx + 0x40);
    /* Square * 2 */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rcx, 8));
    r10 = (word64)(rax);
    r11 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rcx, 16));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rcx, 24));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rcx, 16));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rcx, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rcx, 24));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    /* Double */
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, r14, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, r15, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r9 = (word64)(rax);
    r8 = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r10, r8, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r12, r8, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r14, r8, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r8 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r12 >> 63));
    rdx = (word64)(rdx * 19);
    r12 = (word64)(r12 & r8);
    r8 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(0, r9, r8, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    rax = (word64)(r12);
    r12 = (word64)((r12 << 1) | (r11 >> 63));
    r11 = (word64)((r11 << 1) | (r10 >> 63));
    r10 = (word64)((r10 << 1) | (r9 >> 63));
    r9 = (word64)(r9 << 1);
    r8 = (word64)(0x7fffffffffffffff);
    rax = (word64)(rax >> 62);
    r12 = (word64)(r12 & r8);
    rax = (word64)(rax * 19);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /* Store */
    rsi = (word64)(rdi);
    rsi = (word64)(rsi + 0x40);
    rdi = (word64)(rdi + 0x60);
    /* Sub */
    cf = _subborrow_u64(0, r9, WC_L64(rsi, 0), (unsigned long long*)&r9);
    cf = _subborrow_u64(cf, r10, WC_L64(rsi, 8), (unsigned long long*)&r10);
    cf = _subborrow_u64(cf, r11, WC_L64(rsi, 16), (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, r12, WC_L64(rsi, 24), (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r8, r8, (unsigned long long*)&r8);
    r8 = (word64)((r8 << 1) | (r12 >> 63));
    r8 = (word64)(r8 * -19);
    r12 = (word64)(r12 & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r9, r8, (unsigned long long*)&r9);
    cf = _subborrow_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _subborrow_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rdi, 0) = (word64)(r9);
    WC_S64(rdi, 8) = (word64)(r10);
    WC_S64(rdi, 16) = (word64)(r11);
    WC_S64(rdi, 24) = (word64)(r12);
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_madd_x64(ge_p1p1* r, const ge_p3* p, const ge_precomp* q)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
    word64 rdi, rsi, rcx, rsp, r8, r10, r11, r12, r13, r14, r15, rbx, rbp, r9,
           rax, rdx = 0;
    XALIGNED(32) WC_X64I_SLOT stk[4];
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)p;
    rcx = (word64)(size_t)q;

    rsp = (word64)(size_t)stk + 32;
    rsp = (word64)(rsp - 24);
    WC_S64(rsp, 0) = (word64)(rdi);
    WC_S64(rsp, 8) = (word64)(rsi);
    WC_S64(rsp, 16) = (word64)(rcx);
    r8 = (word64)(rsi);
    rcx = (word64)(rsi);
    rcx = (word64)(rcx + 0x20);
    rsi = (word64)(rdi);
    rsi = (word64)(rsi + 0x20);
    /* Add-Sub */
    /* Add */
    r10 = (word64)(WC_L64(rcx, 0));
    r11 = (word64)(WC_L64(rcx, 8));
    r12 = (word64)(WC_L64(rcx, 16));
    r13 = (word64)(WC_L64(rcx, 24));
    r14 = (word64)(r10);
    cf = _addcarry_u64(0, r10, WC_L64(r8, 0), (unsigned long long*)&r10);
    r15 = (word64)(r11);
    cf = _addcarry_u64(cf, r11, WC_L64(r8, 8), (unsigned long long*)&r11);
    rbx = (word64)(r12);
    cf = _addcarry_u64(cf, r12, WC_L64(r8, 16), (unsigned long long*)&r12);
    rbp = (word64)(r13);
    cf = _addcarry_u64(cf, r13, WC_L64(r8, 24), (unsigned long long*)&r13);
    r9 = (word64)(0);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (r13 >> 63));
    r9 = (word64)(r9 * 0x13);
    r13 = (word64)(r13 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /* Sub */
    cf = _subborrow_u64(0, r14, WC_L64(r8, 0), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, WC_L64(r8, 8), (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, WC_L64(r8, 16), (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, WC_L64(r8, 24), (unsigned long long*)&rbp);
    cf = _subborrow_u64(cf, r9, r9, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (rbp >> 63));
    r9 = (word64)(r9 * -19);
    rbp = (word64)(rbp & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r14, r9, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    WC_S64(rdi, 0) = (word64)(r10);
    WC_S64(rdi, 8) = (word64)(r11);
    WC_S64(rdi, 16) = (word64)(r12);
    WC_S64(rdi, 24) = (word64)(r13);
    WC_S64(rsi, 0) = (word64)(r14);
    WC_S64(rsi, 8) = (word64)(r15);
    WC_S64(rsi, 16) = (word64)(rbx);
    WC_S64(rsi, 24) = (word64)(rbp);
    rcx = (word64)(WC_L64(rsp, 16));
    rcx = (word64)(rcx + 0x20);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r10 = (word64)(rax);
    r11 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, rbx, rax, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbp);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r9 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r13 >> 63));
    rdx = (word64)(rdx * 19);
    r13 = (word64)(r13 & r9);
    r9 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rbx, (unsigned long long*)&r13);
    /* Store */
    WC_S64(rsi, 0) = (word64)(r10);
    WC_S64(rsi, 8) = (word64)(r11);
    WC_S64(rsi, 16) = (word64)(r12);
    WC_S64(rsi, 24) = (word64)(r13);
    r8 = (word64)(r8 + 0x60);
    rcx = (word64)(rcx + 0x20);
    rdi = (word64)(rdi + 0x60);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r10 = (word64)(rax);
    r11 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, rbx, rax, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbp);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r9 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r13 >> 63));
    rdx = (word64)(rdx * 19);
    r13 = (word64)(r13 & r9);
    r9 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rbx, (unsigned long long*)&r13);
    /* Store */
    WC_S64(rdi, 0) = (word64)(r10);
    WC_S64(rdi, 8) = (word64)(r11);
    WC_S64(rdi, 16) = (word64)(r12);
    WC_S64(rdi, 24) = (word64)(r13);
    rcx = (word64)(rcx - 0x40);
    rdi = (word64)(rdi - 0x60);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r10 = (word64)(rax);
    r11 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, rbx, rax, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbp);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r9 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r13 >> 63));
    rdx = (word64)(rdx * 19);
    r13 = (word64)(r13 & r9);
    r9 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rbx, (unsigned long long*)&r13);
    /* Store */
    /* Add-Sub */
    /* Add */
    r14 = (word64)(r10);
    cf = _addcarry_u64(0, r10, WC_L64(rsi, 0), (unsigned long long*)&r10);
    r15 = (word64)(r11);
    cf = _addcarry_u64(cf, r11, WC_L64(rsi, 8), (unsigned long long*)&r11);
    rbx = (word64)(r12);
    cf = _addcarry_u64(cf, r12, WC_L64(rsi, 16), (unsigned long long*)&r12);
    rbp = (word64)(r13);
    cf = _addcarry_u64(cf, r13, WC_L64(rsi, 24), (unsigned long long*)&r13);
    r9 = (word64)(0);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (r13 >> 63));
    r9 = (word64)(r9 * 0x13);
    r13 = (word64)(r13 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /* Sub */
    cf = _subborrow_u64(0, r14, WC_L64(rsi, 0), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, WC_L64(rsi, 8), (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, WC_L64(rsi, 16), (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, WC_L64(rsi, 24), (unsigned long long*)&rbp);
    cf = _subborrow_u64(cf, r9, r9, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (rbp >> 63));
    r9 = (word64)(r9 * -19);
    rbp = (word64)(rbp & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r14, r9, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    WC_S64(rsi, 0) = (word64)(r10);
    WC_S64(rsi, 8) = (word64)(r11);
    WC_S64(rsi, 16) = (word64)(r12);
    WC_S64(rsi, 24) = (word64)(r13);
    WC_S64(rdi, 0) = (word64)(r14);
    WC_S64(rdi, 8) = (word64)(r15);
    WC_S64(rdi, 16) = (word64)(rbx);
    WC_S64(rdi, 24) = (word64)(rbp);
    r8 = (word64)(r8 - 0x20);
    /* Double */
    r10 = (word64)(WC_L64(r8, 0));
    r11 = (word64)(WC_L64(r8, 8));
    cf = _addcarry_u64(0, r10, r10, (unsigned long long*)&r10);
    r12 = (word64)(WC_L64(r8, 16));
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    r13 = (word64)(WC_L64(r8, 24));
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    r9 = (word64)(0);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (r13 >> 63));
    r9 = (word64)(r9 * 0x13);
    r13 = (word64)(r13 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    rsi = (word64)(rdi);
    rsi = (word64)(rsi + 0x60);
    rdi = (word64)(rdi + 0x40);
    /* Add-Sub */
    /* Add */
    r14 = (word64)(r10);
    cf = _addcarry_u64(0, r10, WC_L64(rsi, 0), (unsigned long long*)&r10);
    r15 = (word64)(r11);
    cf = _addcarry_u64(cf, r11, WC_L64(rsi, 8), (unsigned long long*)&r11);
    rbx = (word64)(r12);
    cf = _addcarry_u64(cf, r12, WC_L64(rsi, 16), (unsigned long long*)&r12);
    rbp = (word64)(r13);
    cf = _addcarry_u64(cf, r13, WC_L64(rsi, 24), (unsigned long long*)&r13);
    r9 = (word64)(0);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (r13 >> 63));
    r9 = (word64)(r9 * 0x13);
    r13 = (word64)(r13 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /* Sub */
    cf = _subborrow_u64(0, r14, WC_L64(rsi, 0), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, WC_L64(rsi, 8), (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, WC_L64(rsi, 16), (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, WC_L64(rsi, 24), (unsigned long long*)&rbp);
    cf = _subborrow_u64(cf, r9, r9, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (rbp >> 63));
    r9 = (word64)(r9 * -19);
    rbp = (word64)(rbp & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r14, r9, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    WC_S64(rdi, 0) = (word64)(r10);
    WC_S64(rdi, 8) = (word64)(r11);
    WC_S64(rdi, 16) = (word64)(r12);
    WC_S64(rdi, 24) = (word64)(r13);
    WC_S64(rsi, 0) = (word64)(r14);
    WC_S64(rsi, 8) = (word64)(r15);
    WC_S64(rsi, 16) = (word64)(rbx);
    WC_S64(rsi, 24) = (word64)(rbp);
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_msub_x64(ge_p1p1* r, const ge_p3* p, const ge_precomp* q)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
    word64 rdi, rsi, rcx, rsp, r8, r10, r11, r12, r13, r14, r15, rbx, rbp, r9,
           rax, rdx = 0;
    XALIGNED(32) WC_X64I_SLOT stk[4];
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)p;
    rcx = (word64)(size_t)q;

    rsp = (word64)(size_t)stk + 32;
    rsp = (word64)(rsp - 24);
    WC_S64(rsp, 0) = (word64)(rdi);
    WC_S64(rsp, 8) = (word64)(rsi);
    WC_S64(rsp, 16) = (word64)(rcx);
    r8 = (word64)(rsi);
    rcx = (word64)(rsi);
    rcx = (word64)(rcx + 0x20);
    rsi = (word64)(rdi);
    rsi = (word64)(rsi + 0x20);
    /* Add-Sub */
    /* Add */
    r10 = (word64)(WC_L64(rcx, 0));
    r11 = (word64)(WC_L64(rcx, 8));
    r12 = (word64)(WC_L64(rcx, 16));
    r13 = (word64)(WC_L64(rcx, 24));
    r14 = (word64)(r10);
    cf = _addcarry_u64(0, r10, WC_L64(r8, 0), (unsigned long long*)&r10);
    r15 = (word64)(r11);
    cf = _addcarry_u64(cf, r11, WC_L64(r8, 8), (unsigned long long*)&r11);
    rbx = (word64)(r12);
    cf = _addcarry_u64(cf, r12, WC_L64(r8, 16), (unsigned long long*)&r12);
    rbp = (word64)(r13);
    cf = _addcarry_u64(cf, r13, WC_L64(r8, 24), (unsigned long long*)&r13);
    r9 = (word64)(0);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (r13 >> 63));
    r9 = (word64)(r9 * 0x13);
    r13 = (word64)(r13 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /* Sub */
    cf = _subborrow_u64(0, r14, WC_L64(r8, 0), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, WC_L64(r8, 8), (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, WC_L64(r8, 16), (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, WC_L64(r8, 24), (unsigned long long*)&rbp);
    cf = _subborrow_u64(cf, r9, r9, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (rbp >> 63));
    r9 = (word64)(r9 * -19);
    rbp = (word64)(rbp & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r14, r9, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    WC_S64(rdi, 0) = (word64)(r10);
    WC_S64(rdi, 8) = (word64)(r11);
    WC_S64(rdi, 16) = (word64)(r12);
    WC_S64(rdi, 24) = (word64)(r13);
    WC_S64(rsi, 0) = (word64)(r14);
    WC_S64(rsi, 8) = (word64)(r15);
    WC_S64(rsi, 16) = (word64)(rbx);
    WC_S64(rsi, 24) = (word64)(rbp);
    rcx = (word64)(WC_L64(rsp, 16));
    rdi = (word64)(rdi + 0x20);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r10 = (word64)(rax);
    r11 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, rbx, rax, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbp);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r9 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r13 >> 63));
    rdx = (word64)(rdx * 19);
    r13 = (word64)(r13 & r9);
    r9 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rbx, (unsigned long long*)&r13);
    /* Store */
    WC_S64(rdi, 0) = (word64)(r10);
    WC_S64(rdi, 8) = (word64)(r11);
    WC_S64(rdi, 16) = (word64)(r12);
    WC_S64(rdi, 24) = (word64)(r13);
    r8 = (word64)(r8 + 0x60);
    rcx = (word64)(rcx + 0x40);
    rdi = (word64)(rdi + 0x40);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r10 = (word64)(rax);
    r11 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, rbx, rax, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbp);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r9 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r13 >> 63));
    rdx = (word64)(rdx * 19);
    r13 = (word64)(r13 & r9);
    r9 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rbx, (unsigned long long*)&r13);
    /* Store */
    WC_S64(rdi, 0) = (word64)(r10);
    WC_S64(rdi, 8) = (word64)(r11);
    WC_S64(rdi, 16) = (word64)(r12);
    WC_S64(rdi, 24) = (word64)(r13);
    rcx = (word64)(rcx - 0x20);
    rdi = (word64)(rdi - 0x60);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r10 = (word64)(rax);
    r11 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, rbx, rax, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbp);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r9 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r13 >> 63));
    rdx = (word64)(rdx * 19);
    r13 = (word64)(r13 & r9);
    r9 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rbx, (unsigned long long*)&r13);
    /* Store */
    /* Add-Sub */
    /* Add */
    r14 = (word64)(r10);
    cf = _addcarry_u64(0, r10, WC_L64(rsi, 0), (unsigned long long*)&r10);
    r15 = (word64)(r11);
    cf = _addcarry_u64(cf, r11, WC_L64(rsi, 8), (unsigned long long*)&r11);
    rbx = (word64)(r12);
    cf = _addcarry_u64(cf, r12, WC_L64(rsi, 16), (unsigned long long*)&r12);
    rbp = (word64)(r13);
    cf = _addcarry_u64(cf, r13, WC_L64(rsi, 24), (unsigned long long*)&r13);
    r9 = (word64)(0);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (r13 >> 63));
    r9 = (word64)(r9 * 0x13);
    r13 = (word64)(r13 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /* Sub */
    cf = _subborrow_u64(0, r14, WC_L64(rsi, 0), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, WC_L64(rsi, 8), (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, WC_L64(rsi, 16), (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, WC_L64(rsi, 24), (unsigned long long*)&rbp);
    cf = _subborrow_u64(cf, r9, r9, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (rbp >> 63));
    r9 = (word64)(r9 * -19);
    rbp = (word64)(rbp & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r14, r9, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    WC_S64(rsi, 0) = (word64)(r10);
    WC_S64(rsi, 8) = (word64)(r11);
    WC_S64(rsi, 16) = (word64)(r12);
    WC_S64(rsi, 24) = (word64)(r13);
    WC_S64(rdi, 0) = (word64)(r14);
    WC_S64(rdi, 8) = (word64)(r15);
    WC_S64(rdi, 16) = (word64)(rbx);
    WC_S64(rdi, 24) = (word64)(rbp);
    r8 = (word64)(r8 - 0x20);
    rdi = (word64)(rdi + 0x40);
    /* Double */
    r10 = (word64)(WC_L64(r8, 0));
    r11 = (word64)(WC_L64(r8, 8));
    cf = _addcarry_u64(0, r10, r10, (unsigned long long*)&r10);
    r12 = (word64)(WC_L64(r8, 16));
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    r13 = (word64)(WC_L64(r8, 24));
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    r9 = (word64)(0);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (r13 >> 63));
    r9 = (word64)(r9 * 0x13);
    r13 = (word64)(r13 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    rsi = (word64)(rdi);
    rsi = (word64)(rsi + 0x20);
    /* Add-Sub */
    /* Add */
    r14 = (word64)(r10);
    cf = _addcarry_u64(0, r10, WC_L64(rsi, 0), (unsigned long long*)&r10);
    r15 = (word64)(r11);
    cf = _addcarry_u64(cf, r11, WC_L64(rsi, 8), (unsigned long long*)&r11);
    rbx = (word64)(r12);
    cf = _addcarry_u64(cf, r12, WC_L64(rsi, 16), (unsigned long long*)&r12);
    rbp = (word64)(r13);
    cf = _addcarry_u64(cf, r13, WC_L64(rsi, 24), (unsigned long long*)&r13);
    r9 = (word64)(0);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (r13 >> 63));
    r9 = (word64)(r9 * 0x13);
    r13 = (word64)(r13 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /* Sub */
    cf = _subborrow_u64(0, r14, WC_L64(rsi, 0), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, WC_L64(rsi, 8), (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, WC_L64(rsi, 16), (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, WC_L64(rsi, 24), (unsigned long long*)&rbp);
    cf = _subborrow_u64(cf, r9, r9, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (rbp >> 63));
    r9 = (word64)(r9 * -19);
    rbp = (word64)(rbp & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r14, r9, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    WC_S64(rsi, 0) = (word64)(r10);
    WC_S64(rsi, 8) = (word64)(r11);
    WC_S64(rsi, 16) = (word64)(r12);
    WC_S64(rsi, 24) = (word64)(r13);
    WC_S64(rdi, 0) = (word64)(r14);
    WC_S64(rdi, 8) = (word64)(r15);
    WC_S64(rdi, 16) = (word64)(rbx);
    WC_S64(rdi, 24) = (word64)(rbp);
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_add_x64(ge_p1p1* r, const ge_p3* p, const fe qe_cached)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
    word64 rdi, rsi, rcx, rsp, r8, r10, r11, r12, r13, r14, r15, rbx, rbp, r9,
           rax, rdx = 0;
    XALIGNED(32) WC_X64I_SLOT stk[4];
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)p;
    rcx = (word64)(size_t)qe_cached;

    rsp = (word64)(size_t)stk + 32;
    rsp = (word64)(rsp - 24);
    WC_S64(rsp, 0) = (word64)(rdi);
    WC_S64(rsp, 8) = (word64)(rsi);
    WC_S64(rsp, 16) = (word64)(rcx);
    r8 = (word64)(rsi);
    rcx = (word64)(rsi);
    rcx = (word64)(rcx + 0x20);
    rsi = (word64)(rdi);
    rsi = (word64)(rsi + 0x20);
    /* Add-Sub */
    /* Add */
    r10 = (word64)(WC_L64(rcx, 0));
    r11 = (word64)(WC_L64(rcx, 8));
    r12 = (word64)(WC_L64(rcx, 16));
    r13 = (word64)(WC_L64(rcx, 24));
    r14 = (word64)(r10);
    cf = _addcarry_u64(0, r10, WC_L64(r8, 0), (unsigned long long*)&r10);
    r15 = (word64)(r11);
    cf = _addcarry_u64(cf, r11, WC_L64(r8, 8), (unsigned long long*)&r11);
    rbx = (word64)(r12);
    cf = _addcarry_u64(cf, r12, WC_L64(r8, 16), (unsigned long long*)&r12);
    rbp = (word64)(r13);
    cf = _addcarry_u64(cf, r13, WC_L64(r8, 24), (unsigned long long*)&r13);
    r9 = (word64)(0);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (r13 >> 63));
    r9 = (word64)(r9 * 0x13);
    r13 = (word64)(r13 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /* Sub */
    cf = _subborrow_u64(0, r14, WC_L64(r8, 0), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, WC_L64(r8, 8), (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, WC_L64(r8, 16), (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, WC_L64(r8, 24), (unsigned long long*)&rbp);
    cf = _subborrow_u64(cf, r9, r9, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (rbp >> 63));
    r9 = (word64)(r9 * -19);
    rbp = (word64)(rbp & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r14, r9, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    WC_S64(rdi, 0) = (word64)(r10);
    WC_S64(rdi, 8) = (word64)(r11);
    WC_S64(rdi, 16) = (word64)(r12);
    WC_S64(rdi, 24) = (word64)(r13);
    WC_S64(rsi, 0) = (word64)(r14);
    WC_S64(rsi, 8) = (word64)(r15);
    WC_S64(rsi, 16) = (word64)(rbx);
    WC_S64(rsi, 24) = (word64)(rbp);
    rcx = (word64)(WC_L64(rsp, 16));
    rcx = (word64)(rcx + 0x20);
    rdi = (word64)(rdi + 0x20);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r10 = (word64)(rax);
    r11 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, rbx, rax, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbp);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r9 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r13 >> 63));
    rdx = (word64)(rdx * 19);
    r13 = (word64)(r13 & r9);
    r9 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rbx, (unsigned long long*)&r13);
    /* Store */
    WC_S64(rdi, 0) = (word64)(r10);
    WC_S64(rdi, 8) = (word64)(r11);
    WC_S64(rdi, 16) = (word64)(r12);
    WC_S64(rdi, 24) = (word64)(r13);
    r8 = (word64)(r8 + 0x60);
    rcx = (word64)(rcx + 0x40);
    rdi = (word64)(rdi + 0x40);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r10 = (word64)(rax);
    r11 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, rbx, rax, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbp);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r9 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r13 >> 63));
    rdx = (word64)(rdx * 19);
    r13 = (word64)(r13 & r9);
    r9 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rbx, (unsigned long long*)&r13);
    /* Store */
    WC_S64(rdi, 0) = (word64)(r10);
    WC_S64(rdi, 8) = (word64)(r11);
    WC_S64(rdi, 16) = (word64)(r12);
    WC_S64(rdi, 24) = (word64)(r13);
    rcx = (word64)(rcx - 0x60);
    rdi = (word64)(rdi - 0x60);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r10 = (word64)(rax);
    r11 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, rbx, rax, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbp);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r9 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r13 >> 63));
    rdx = (word64)(rdx * 19);
    r13 = (word64)(r13 & r9);
    r9 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rbx, (unsigned long long*)&r13);
    /* Store */
    /* Add-Sub */
    /* Add */
    r14 = (word64)(r10);
    cf = _addcarry_u64(0, r10, WC_L64(rsi, 0), (unsigned long long*)&r10);
    r15 = (word64)(r11);
    cf = _addcarry_u64(cf, r11, WC_L64(rsi, 8), (unsigned long long*)&r11);
    rbx = (word64)(r12);
    cf = _addcarry_u64(cf, r12, WC_L64(rsi, 16), (unsigned long long*)&r12);
    rbp = (word64)(r13);
    cf = _addcarry_u64(cf, r13, WC_L64(rsi, 24), (unsigned long long*)&r13);
    r9 = (word64)(0);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (r13 >> 63));
    r9 = (word64)(r9 * 0x13);
    r13 = (word64)(r13 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /* Sub */
    cf = _subborrow_u64(0, r14, WC_L64(rsi, 0), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, WC_L64(rsi, 8), (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, WC_L64(rsi, 16), (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, WC_L64(rsi, 24), (unsigned long long*)&rbp);
    cf = _subborrow_u64(cf, r9, r9, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (rbp >> 63));
    r9 = (word64)(r9 * -19);
    rbp = (word64)(rbp & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r14, r9, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    WC_S64(rsi, 0) = (word64)(r10);
    WC_S64(rsi, 8) = (word64)(r11);
    WC_S64(rsi, 16) = (word64)(r12);
    WC_S64(rsi, 24) = (word64)(r13);
    WC_S64(rdi, 0) = (word64)(r14);
    WC_S64(rdi, 8) = (word64)(r15);
    WC_S64(rdi, 16) = (word64)(rbx);
    WC_S64(rdi, 24) = (word64)(rbp);
    r8 = (word64)(r8 - 0x20);
    rcx = (word64)(rcx + 0x40);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r10 = (word64)(rax);
    r11 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, rbx, rax, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbp);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r9 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r13 >> 63));
    rdx = (word64)(rdx * 19);
    r13 = (word64)(r13 & r9);
    r9 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rbx, (unsigned long long*)&r13);
    /* Store */
    rdi = (word64)(rdi + 0x40);
    /* Double */
    cf = _addcarry_u64(0, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    r9 = (word64)(0);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (r13 >> 63));
    r9 = (word64)(r9 * 0x13);
    r13 = (word64)(r13 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    rsi = (word64)(rdi);
    rsi = (word64)(rsi + 0x20);
    /* Add-Sub */
    /* Add */
    r14 = (word64)(r10);
    cf = _addcarry_u64(0, r10, WC_L64(rsi, 0), (unsigned long long*)&r10);
    r15 = (word64)(r11);
    cf = _addcarry_u64(cf, r11, WC_L64(rsi, 8), (unsigned long long*)&r11);
    rbx = (word64)(r12);
    cf = _addcarry_u64(cf, r12, WC_L64(rsi, 16), (unsigned long long*)&r12);
    rbp = (word64)(r13);
    cf = _addcarry_u64(cf, r13, WC_L64(rsi, 24), (unsigned long long*)&r13);
    r9 = (word64)(0);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (r13 >> 63));
    r9 = (word64)(r9 * 0x13);
    r13 = (word64)(r13 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /* Sub */
    cf = _subborrow_u64(0, r14, WC_L64(rsi, 0), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, WC_L64(rsi, 8), (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, WC_L64(rsi, 16), (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, WC_L64(rsi, 24), (unsigned long long*)&rbp);
    cf = _subborrow_u64(cf, r9, r9, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (rbp >> 63));
    r9 = (word64)(r9 * -19);
    rbp = (word64)(rbp & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r14, r9, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    WC_S64(rdi, 0) = (word64)(r10);
    WC_S64(rdi, 8) = (word64)(r11);
    WC_S64(rdi, 16) = (word64)(r12);
    WC_S64(rdi, 24) = (word64)(r13);
    WC_S64(rsi, 0) = (word64)(r14);
    WC_S64(rsi, 8) = (word64)(r15);
    WC_S64(rsi, 16) = (word64)(rbx);
    WC_S64(rsi, 24) = (word64)(rbp);
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_sub_x64(ge_p1p1* r, const ge_p3* p, const fe qe_cached)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
    word64 rdi, rsi, rcx, rsp, r8, r10, r11, r12, r13, r14, r15, rbx, rbp, r9,
           rax, rdx = 0;
    XALIGNED(32) WC_X64I_SLOT stk[4];
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)p;
    rcx = (word64)(size_t)qe_cached;

    rsp = (word64)(size_t)stk + 32;
    rsp = (word64)(rsp - 24);
    WC_S64(rsp, 0) = (word64)(rdi);
    WC_S64(rsp, 8) = (word64)(rsi);
    WC_S64(rsp, 16) = (word64)(rcx);
    r8 = (word64)(rsi);
    rcx = (word64)(rsi);
    rcx = (word64)(rcx + 0x20);
    rsi = (word64)(rdi);
    rsi = (word64)(rsi + 0x20);
    /* Add-Sub */
    /* Add */
    r10 = (word64)(WC_L64(rcx, 0));
    r11 = (word64)(WC_L64(rcx, 8));
    r12 = (word64)(WC_L64(rcx, 16));
    r13 = (word64)(WC_L64(rcx, 24));
    r14 = (word64)(r10);
    cf = _addcarry_u64(0, r10, WC_L64(r8, 0), (unsigned long long*)&r10);
    r15 = (word64)(r11);
    cf = _addcarry_u64(cf, r11, WC_L64(r8, 8), (unsigned long long*)&r11);
    rbx = (word64)(r12);
    cf = _addcarry_u64(cf, r12, WC_L64(r8, 16), (unsigned long long*)&r12);
    rbp = (word64)(r13);
    cf = _addcarry_u64(cf, r13, WC_L64(r8, 24), (unsigned long long*)&r13);
    r9 = (word64)(0);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (r13 >> 63));
    r9 = (word64)(r9 * 0x13);
    r13 = (word64)(r13 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /* Sub */
    cf = _subborrow_u64(0, r14, WC_L64(r8, 0), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, WC_L64(r8, 8), (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, WC_L64(r8, 16), (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, WC_L64(r8, 24), (unsigned long long*)&rbp);
    cf = _subborrow_u64(cf, r9, r9, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (rbp >> 63));
    r9 = (word64)(r9 * -19);
    rbp = (word64)(rbp & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r14, r9, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    WC_S64(rdi, 0) = (word64)(r10);
    WC_S64(rdi, 8) = (word64)(r11);
    WC_S64(rdi, 16) = (word64)(r12);
    WC_S64(rdi, 24) = (word64)(r13);
    WC_S64(rsi, 0) = (word64)(r14);
    WC_S64(rsi, 8) = (word64)(r15);
    WC_S64(rsi, 16) = (word64)(rbx);
    WC_S64(rsi, 24) = (word64)(rbp);
    rcx = (word64)(WC_L64(rsp, 16));
    rdi = (word64)(rdi + 0x20);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r10 = (word64)(rax);
    r11 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, rbx, rax, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbp);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r9 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r13 >> 63));
    rdx = (word64)(rdx * 19);
    r13 = (word64)(r13 & r9);
    r9 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rbx, (unsigned long long*)&r13);
    /* Store */
    WC_S64(rdi, 0) = (word64)(r10);
    WC_S64(rdi, 8) = (word64)(r11);
    WC_S64(rdi, 16) = (word64)(r12);
    WC_S64(rdi, 24) = (word64)(r13);
    r8 = (word64)(r8 + 0x60);
    rcx = (word64)(rcx + 0x60);
    rdi = (word64)(rdi + 0x40);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r10 = (word64)(rax);
    r11 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, rbx, rax, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbp);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r9 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r13 >> 63));
    rdx = (word64)(rdx * 19);
    r13 = (word64)(r13 & r9);
    r9 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rbx, (unsigned long long*)&r13);
    /* Store */
    WC_S64(rdi, 0) = (word64)(r10);
    WC_S64(rdi, 8) = (word64)(r11);
    WC_S64(rdi, 16) = (word64)(r12);
    WC_S64(rdi, 24) = (word64)(r13);
    rcx = (word64)(rcx - 0x40);
    rdi = (word64)(rdi - 0x60);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r10 = (word64)(rax);
    r11 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 0));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 8));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 16));
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rdi, 24));
    cf = _addcarry_u64(0, rbx, rax, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbp);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r9 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r13 >> 63));
    rdx = (word64)(rdx * 19);
    r13 = (word64)(r13 & r9);
    r9 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rbx, (unsigned long long*)&r13);
    /* Store */
    /* Add-Sub */
    /* Add */
    r14 = (word64)(r10);
    cf = _addcarry_u64(0, r10, WC_L64(rsi, 0), (unsigned long long*)&r10);
    r15 = (word64)(r11);
    cf = _addcarry_u64(cf, r11, WC_L64(rsi, 8), (unsigned long long*)&r11);
    rbx = (word64)(r12);
    cf = _addcarry_u64(cf, r12, WC_L64(rsi, 16), (unsigned long long*)&r12);
    rbp = (word64)(r13);
    cf = _addcarry_u64(cf, r13, WC_L64(rsi, 24), (unsigned long long*)&r13);
    r9 = (word64)(0);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (r13 >> 63));
    r9 = (word64)(r9 * 0x13);
    r13 = (word64)(r13 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /* Sub */
    cf = _subborrow_u64(0, r14, WC_L64(rsi, 0), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, WC_L64(rsi, 8), (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, WC_L64(rsi, 16), (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, WC_L64(rsi, 24), (unsigned long long*)&rbp);
    cf = _subborrow_u64(cf, r9, r9, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (rbp >> 63));
    r9 = (word64)(r9 * -19);
    rbp = (word64)(rbp & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r14, r9, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    WC_S64(rsi, 0) = (word64)(r10);
    WC_S64(rsi, 8) = (word64)(r11);
    WC_S64(rsi, 16) = (word64)(r12);
    WC_S64(rsi, 24) = (word64)(r13);
    WC_S64(rdi, 0) = (word64)(r14);
    WC_S64(rdi, 8) = (word64)(r15);
    WC_S64(rdi, 16) = (word64)(rbx);
    WC_S64(rdi, 24) = (word64)(rbp);
    r8 = (word64)(r8 - 0x20);
    rcx = (word64)(rcx + 0x20);
    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r10 = (word64)(rax);
    r11 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 0));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rcx, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 8));
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rcx, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 16));
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rcx, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rcx, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(r8, 24));
    cf = _addcarry_u64(0, rbx, rax, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, rbp);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r9 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r13 >> 63));
    rdx = (word64)(rdx * 19);
    r13 = (word64)(r13 & r9);
    r9 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    WC_X64I_MUL128(rax, rdx, rax, r15);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r14, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rbx, (unsigned long long*)&r13);
    /* Store */
    /* Double */
    cf = _addcarry_u64(0, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    r9 = (word64)(0);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (r13 >> 63));
    r9 = (word64)(r9 * 0x13);
    r13 = (word64)(r13 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    rsi = (word64)(rdi);
    rsi = (word64)(rsi + 0x40);
    rdi = (word64)(rdi + 0x60);
    /* Add-Sub */
    /* Add */
    r14 = (word64)(r10);
    cf = _addcarry_u64(0, r10, WC_L64(rdi, 0), (unsigned long long*)&r10);
    r15 = (word64)(r11);
    cf = _addcarry_u64(cf, r11, WC_L64(rdi, 8), (unsigned long long*)&r11);
    rbx = (word64)(r12);
    cf = _addcarry_u64(cf, r12, WC_L64(rdi, 16), (unsigned long long*)&r12);
    rbp = (word64)(r13);
    cf = _addcarry_u64(cf, r13, WC_L64(rdi, 24), (unsigned long long*)&r13);
    r9 = (word64)(0);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (r13 >> 63));
    r9 = (word64)(r9 * 0x13);
    r13 = (word64)(r13 & ~(word64)((word64)1 << 63));
    /*   Sub modulus (if overflow) */
    cf = _addcarry_u64(0, r10, r9, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /* Sub */
    cf = _subborrow_u64(0, r14, WC_L64(rdi, 0), (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, WC_L64(rdi, 8), (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, WC_L64(rdi, 16), (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, WC_L64(rdi, 24), (unsigned long long*)&rbp);
    cf = _subborrow_u64(cf, r9, r9, (unsigned long long*)&r9);
    r9 = (word64)((r9 << 1) | (rbp >> 63));
    r9 = (word64)(r9 * -19);
    rbp = (word64)(rbp & ~(word64)((word64)1 << 63));
    /*   Add modulus (if underflow) */
    cf = _subborrow_u64(0, r14, r9, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    cf = _subborrow_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    cf = _subborrow_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    WC_S64(rdi, 0) = (word64)(r10);
    WC_S64(rdi, 8) = (word64)(r11);
    WC_S64(rdi, 16) = (word64)(r12);
    WC_S64(rdi, 24) = (word64)(r13);
    WC_S64(rsi, 0) = (word64)(r14);
    WC_S64(rsi, 8) = (word64)(r15);
    WC_S64(rsi, 16) = (word64)(rbx);
    WC_S64(rsi, 24) = (word64)(rbp);
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#ifdef HAVE_ED25519
WOLFSSL_LOCAL void fe_sq2_x64(fe r, fe a)
{
    word64 rdi, rsi, rax, rdx = 0, r8, r9, r10, r11, r12, r13, r14, rcx, r15;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)a;

    /* Square * 2 */
    /*  A[0] * A[1] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r8 = (word64)(rax);
    r9 = (word64)(rdx);
    /*  A[0] * A[2] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[0] * A[3] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * A[2] */
    rax = (word64)(WC_L64(rsi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[1] * A[3] */
    rax = (word64)(WC_L64(rsi, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    /*  A[2] * A[3] */
    rax = (word64)(WC_L64(rsi, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /* Double */
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r8, r8, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r9, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r10, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, r11, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r12, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, r13, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[0] * A[0] */
    rax = (word64)(WC_L64(rsi, 0));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    rcx = (word64)(rax);
    r15 = (word64)(rdx);
    /*  A[1] * A[1] */
    rax = (word64)(WC_L64(rsi, 8));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r8, r15, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r15 = (word64)(rdx);
    /*  A[2] * A[2] */
    rax = (word64)(WC_L64(rsi, 16));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r10, r15, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r15 = (word64)(rdx);
    /*  A[3] * A[3] */
    rax = (word64)(WC_L64(rsi, 24));
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r12, r15, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    r15 = (word64)(0x7fffffffffffffff);
    rdx = (word64)((rdx << 1) | (r10 >> 63));
    rdx = (word64)(rdx * 19);
    r10 = (word64)(r10 & r15);
    r15 = (word64)(rdx);
    rax = (word64)(0x26);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r11 = (word64)(0);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0x26);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(0, rcx, r15, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, r13, (unsigned long long*)&r10);
    rax = (word64)(r10);
    r10 = (word64)((r10 << 1) | (r9 >> 63));
    r9 = (word64)((r9 << 1) | (r8 >> 63));
    r8 = (word64)((r8 << 1) | (rcx >> 63));
    rcx = (word64)(rcx << 1);
    r15 = (word64)(0x7fffffffffffffff);
    rax = (word64)(rax >> 62);
    r10 = (word64)(r10 & r15);
    rax = (word64)(rax * 19);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    /* Store */
    WC_S64(rdi, 0) = (word64)(rcx);
    WC_S64(rdi, 8) = (word64)(r8);
    WC_S64(rdi, 16) = (word64)(r9);
    WC_S64(rdi, 24) = (word64)(r10);
}

WOLFSSL_LOCAL void sc_reduce_x64(byte* s)
{
    word64 rdi, r8, r9, r10, r11, r12, r13, r14, r15, rcx, rsi, rax, rdx = 0,
           rbp, rbx;
    unsigned char cf;

    rdi = (word64)(size_t)s;

    r8 = (word64)(WC_L64(rdi, 0));
    r9 = (word64)(WC_L64(rdi, 8));
    r10 = (word64)(WC_L64(rdi, 16));
    r11 = (word64)(WC_L64(rdi, 24));
    r12 = (word64)(WC_L64(rdi, 32));
    r13 = (word64)(WC_L64(rdi, 40));
    r14 = (word64)(WC_L64(rdi, 48));
    r15 = (word64)(WC_L64(rdi, 56));
    rcx = (word64)(r15);
    rsi = (word64)(0xfffffffffffffff);
    rcx = (word64)(rcx >> 56);
    r15 = (word64)((r15 << 4) | (r14 >> 60));
    r14 = (word64)((r14 << 4) | (r13 >> 60));
    r13 = (word64)((r13 << 4) | (r12 >> 60));
    r12 = (word64)((r12 << 4) | (r11 >> 60));
    r11 = (word64)(r11 & rsi);
    r15 = (word64)(r15 & rsi);
    /* Add order times bits 504..511 */
    cf = _subborrow_u64(0, r14, rcx, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    rax = (word64)(0xeb2106215d086329);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    rsi = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    rax = (word64)(0xa7ed9ce5a30a2c13);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rsi, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /* Sub product of top 4 words and order */
    rcx = (word64)(0xa7ed9ce5a30a2c13);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    rax = (word64)(r13);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    rsi = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    rax = (word64)(r14);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    cf = _addcarry_u64(0, r9, rbp, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    rbx = (word64)(0);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    rax = (word64)(r15);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    cf = _addcarry_u64(0, r10, rsi, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    rcx = (word64)(0xeb2106215d086329);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    rax = (word64)(r13);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    rsi = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    rax = (word64)(r14);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    cf = _addcarry_u64(0, r10, rbp, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    rbp = (word64)(0);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    rax = (word64)(r15);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    cf = _addcarry_u64(0, r11, rsi, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rbx, rax, (unsigned long long*)&rbx);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    cf = _subborrow_u64(0, r10, r12, (unsigned long long*)&r10);
    r12 = (word64)(rbx);
    cf = _subborrow_u64(cf, r11, r13, (unsigned long long*)&r11);
    r13 = (word64)(rbp);
    cf = _subborrow_u64(cf, r12, r14, (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, r15, (unsigned long long*)&r13);
    rcx = (word64)(r13);
    rcx = (word64)((word64)((sword64)rcx >> 57));
    /*   Conditionally subtract order starting at bit 125 */
    rax = (word64)(0xa000000000000000);
    rdx = (word64)(0xcb024c634b9eba7d);
    rbx = (word64)(0x29bdf3bd45ef39a);
    rbp = (word64)(0x200000000000000);
    rax = (word64)(rax & rcx);
    rdx = (word64)(rdx & rcx);
    rbx = (word64)(rbx & rcx);
    rbp = (word64)(rbp & rcx);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rbx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rbp, (unsigned long long*)&r13);
    /*   Move bits 252-376 to own registers */
    rcx = (word64)(0xfffffffffffffff);
    r13 = (word64)((r13 << 4) | (r12 >> 60));
    r12 = (word64)((r12 << 4) | (r11 >> 60));
    r11 = (word64)(r11 & rcx);
    /* Sub product of top 2 words and order */
    /*   * -5812631a5cf5d3ed */
    rcx = (word64)(0xa7ed9ce5a30a2c13);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    rax = (word64)(r13);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    /*   * -14def9dea2f79cd7 */
    rcx = (word64)(0xeb2106215d086329);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    rax = (word64)(r13);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    /*   Add overflows at 2 * 64 */
    rsi = (word64)(0xfffffffffffffff);
    r11 = (word64)(r11 & rsi);
    cf = _addcarry_u64(0, r10, rbx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rbp, (unsigned long long*)&r11);
    /*   Subtract top at 2 * 64 */
    cf = _subborrow_u64(0, r10, r12, (unsigned long long*)&r10);
    cf = _subborrow_u64(cf, r11, r13, (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, rsi, rsi, (unsigned long long*)&rsi);
    /*   Conditional sub order */
    rax = (word64)(0x5812631a5cf5d3ed);
    rdx = (word64)(0x14def9dea2f79cd6);
    rbx = (word64)(0x1000000000000000);
    rax = (word64)(rax & rsi);
    rdx = (word64)(rdx & rsi);
    rbx = (word64)(rbx & rsi);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0xfffffffffffffff);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rbx, (unsigned long long*)&r11);
    r11 = (word64)(r11 & rax);
    /* Store result */
    WC_S64(rdi, 0) = (word64)(r8);
    WC_S64(rdi, 8) = (word64)(r9);
    WC_S64(rdi, 16) = (word64)(r10);
    WC_S64(rdi, 24) = (word64)(r11);
}

WOLFSSL_LOCAL void sc_muladd_x64(byte* s, byte* a, byte* b, byte* c)
{
    word64 rdi, rsi, rbp, rcx, rax, rdx = 0, r8, r9, r10, r11, r12, r13, r14,
           r15, rbx;
    unsigned char cf;

    rdi = (word64)(size_t)s;
    rsi = (word64)(size_t)a;
    rbp = (word64)(size_t)b;
    rcx = (word64)(size_t)c;

    /* Multiply */
    /*  A[0] * B[0] */
    rax = (word64)(WC_L64(rbp, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r8 = (word64)(rax);
    r9 = (word64)(rdx);
    /*  A[0] * B[1] */
    rax = (word64)(WC_L64(rbp, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r10 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    /*  A[1] * B[0] */
    rax = (word64)(WC_L64(rbp, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r11 = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    /*  A[0] * B[2] */
    rax = (word64)(WC_L64(rbp, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    /*  A[1] * B[1] */
    rax = (word64)(WC_L64(rbp, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r12 = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[2] * B[0] */
    rax = (word64)(WC_L64(rbp, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /*  A[0] * B[3] */
    rax = (word64)(WC_L64(rbp, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 0));
    r13 = (word64)(0);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[2] */
    rax = (word64)(WC_L64(rbp, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[2] * B[1] */
    rax = (word64)(WC_L64(rbp, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[3] * B[0] */
    rax = (word64)(WC_L64(rbp, 0));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    /*  A[1] * B[3] */
    rax = (word64)(WC_L64(rbp, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 8));
    r14 = (word64)(0);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[2] */
    rax = (word64)(WC_L64(rbp, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[3] * B[1] */
    rax = (word64)(WC_L64(rbp, 8));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    /*  A[2] * B[3] */
    rax = (word64)(WC_L64(rbp, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 16));
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[2] */
    rax = (word64)(WC_L64(rbp, 16));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /*  A[3] * B[3] */
    rax = (word64)(WC_L64(rbp, 24));
    WC_X64I_MUL128(rax, rdx, rax, WC_L64(rsi, 24));
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    /* Add c to a * b */
    cf = _addcarry_u64(0, r8, WC_L64(rcx, 0), (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, WC_L64(rcx, 8), (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, WC_L64(rcx, 16), (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, WC_L64(rcx, 24), (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    rbx = (word64)(r15);
    rcx = (word64)(0xfffffffffffffff);
    rbx = (word64)(rbx >> 56);
    r15 = (word64)((r15 << 4) | (r14 >> 60));
    r14 = (word64)((r14 << 4) | (r13 >> 60));
    r13 = (word64)((r13 << 4) | (r12 >> 60));
    r12 = (word64)((r12 << 4) | (r11 >> 60));
    r11 = (word64)(r11 & rcx);
    r15 = (word64)(r15 & rcx);
    /* Add order times bits 504..507 */
    cf = _subborrow_u64(0, r14, rbx, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    rax = (word64)(0xeb2106215d086329);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rcx = (word64)(0);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    rax = (word64)(0xa7ed9ce5a30a2c13);
    cf = _addcarry_u64(cf, rcx, rdx, (unsigned long long*)&rcx);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rcx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /* Sub product of top 4 words and order */
    rbx = (word64)(0xa7ed9ce5a30a2c13);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    rax = (word64)(r13);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rcx = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, rcx, rdx, (unsigned long long*)&rcx);
    rax = (word64)(r14);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    cf = _addcarry_u64(0, r9, rbp, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    rsi = (word64)(0);
    cf = _addcarry_u64(cf, rsi, 0, (unsigned long long*)&rsi);
    rax = (word64)(r15);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    cf = _addcarry_u64(0, r10, rcx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    rbx = (word64)(0xeb2106215d086329);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    rax = (word64)(r13);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rcx = (word64)(0);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rcx, rdx, (unsigned long long*)&rcx);
    rax = (word64)(r14);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    cf = _addcarry_u64(0, r10, rbp, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    rbp = (word64)(0);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    rax = (word64)(r15);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    cf = _addcarry_u64(0, r11, rcx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rsi, rax, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    cf = _subborrow_u64(0, r10, r12, (unsigned long long*)&r10);
    r12 = (word64)(rsi);
    cf = _subborrow_u64(cf, r11, r13, (unsigned long long*)&r11);
    r13 = (word64)(rbp);
    cf = _subborrow_u64(cf, r12, r14, (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, r15, (unsigned long long*)&r13);
    rbx = (word64)(r13);
    rbx = (word64)((word64)((sword64)rbx >> 57));
    /*   Conditionally subtract order starting at bit 125 */
    rax = (word64)(0xa000000000000000);
    rdx = (word64)(0xcb024c634b9eba7d);
    rsi = (word64)(0x29bdf3bd45ef39a);
    rbp = (word64)(0x200000000000000);
    rax = (word64)(rax & rbx);
    rdx = (word64)(rdx & rbx);
    rsi = (word64)(rsi & rbx);
    rbp = (word64)(rbp & rbx);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rsi, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rbp, (unsigned long long*)&r13);
    /*   Move bits 252-376 to own registers */
    rbx = (word64)(0xfffffffffffffff);
    r13 = (word64)((r13 << 4) | (r12 >> 60));
    r12 = (word64)((r12 << 4) | (r11 >> 60));
    r11 = (word64)(r11 & rbx);
    /* Sub product of top 2 words and order */
    /*   * -5812631a5cf5d3ed */
    rbx = (word64)(0xa7ed9ce5a30a2c13);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rsi = (word64)(0);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, rsi, 0, (unsigned long long*)&rsi);
    rax = (word64)(r13);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    /*   * -14def9dea2f79cd7 */
    rbx = (word64)(0xeb2106215d086329);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    rbp = (word64)(0);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rbp, 0, (unsigned long long*)&rbp);
    rax = (word64)(r13);
    WC_X64I_MUL128(rax, rdx, rax, rbx);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rbp, rdx, (unsigned long long*)&rbp);
    /*   Add overflows at 2 * 64 */
    rcx = (word64)(0xfffffffffffffff);
    r11 = (word64)(r11 & rcx);
    cf = _addcarry_u64(0, r10, rsi, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rbp, (unsigned long long*)&r11);
    /*   Subtract top at 2 * 64 */
    cf = _subborrow_u64(0, r10, r12, (unsigned long long*)&r10);
    cf = _subborrow_u64(cf, r11, r13, (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, rcx, rcx, (unsigned long long*)&rcx);
    /*   Conditional sub order */
    rax = (word64)(0x5812631a5cf5d3ed);
    rdx = (word64)(0x14def9dea2f79cd6);
    rsi = (word64)(0x1000000000000000);
    rax = (word64)(rax & rcx);
    rdx = (word64)(rdx & rcx);
    rsi = (word64)(rsi & rcx);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    rax = (word64)(0xfffffffffffffff);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rsi, (unsigned long long*)&r11);
    r11 = (word64)(r11 & rax);
    /* Store result */
    WC_S64(rdi, 0) = (word64)(r8);
    WC_S64(rdi, 8) = (word64)(r9);
    WC_S64(rdi, 16) = (word64)(r10);
    WC_S64(rdi, 24) = (word64)(r11);
}

/* Non-constant time modular inversion.
 *
 * @param  [out]  r   Resulting number.
 * @param  [in]   a   Number to invert.
 * @return  MP_OKAY on success.
 */
WOLFSSL_LOCAL void fe_invert_nct_x64(word64* r, const word64* a)
{
    word64 rdi, rsi, rsp, rcx, r8, r9, r10, r11, r12, r13, r14, r15, rdx = 0,
           rax = 0;
    XALIGNED(32) WC_X64I_SLOT stk[68];
    word64 zf1;
    word64 zf2;
    word64 zf3;
    word64 zf4;
    word64 zf5;
    word64 zf6;
    byte zf7;
    byte zf8;
    byte zf9;
    byte zf10;
    byte zf11;
    byte zf12;
    byte zf13;
    byte zf14;
    byte zf15;
    byte zf16;
    byte zf17;
    byte zf18;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)a;

    rsp = (word64)(size_t)stk + 544;
    rsp = (word64)(rsp - 513);
    rcx = (word64)(-19);
    r8 = (word64)(-1);
    r9 = (word64)(-1);
    r10 = (word64)(0x7fffffffffffffff);
    r11 = (word64)(WC_L64(rsi, 0));
    r12 = (word64)(WC_L64(rsi, 8));
    r13 = (word64)(WC_L64(rsi, 16));
    r14 = (word64)(WC_L64(rsi, 24));
    r15 = (word64)(0);
    if ((((byte)r11 & 1)) != (0)) {
        goto fe_invert_nct_v_even_end;
    }
fe_invert_nct_v_even_start:
    r11 = (word64)((r11 >> 1) | (r12 << 63));
    r12 = (word64)((r12 >> 1) | (r13 << 63));
    r13 = (word64)((r13 >> 1) | (r14 << 63));
    r14 = (word64)(r14 >> 1);
    WC_S8(rsp, r15) = (byte)(1);
    r15 = (word64)(r15 + 1);
    if ((((byte)r11 & 1)) == (0)) {
        goto fe_invert_nct_v_even_start;
    }
fe_invert_nct_v_even_end:
L_fe_invert_nct_uv_start:
    zf1 = r10;
    zf2 = r14;
    if ((r10) < (r14)) {
        goto L_fe_invert_nct_uv_v;
    }
    if ((zf1) > (zf2)) {
        goto L_fe_invert_nct_uv_u;
    }
    zf3 = r9;
    zf4 = r13;
    if ((r9) < (r13)) {
        goto L_fe_invert_nct_uv_v;
    }
    if ((zf3) > (zf4)) {
        goto L_fe_invert_nct_uv_u;
    }
    zf5 = r8;
    zf6 = r12;
    if ((r8) < (r12)) {
        goto L_fe_invert_nct_uv_v;
    }
    if ((zf5) > (zf6)) {
        goto L_fe_invert_nct_uv_u;
    }
    if ((rcx) < (r11)) {
        goto L_fe_invert_nct_uv_v;
    }
L_fe_invert_nct_uv_u:
    WC_S8(rsp, r15) = (byte)(2);
    r15 = (word64)(r15 + 1);
    cf = _subborrow_u64(0, rcx, r11, (unsigned long long*)&rcx);
    cf = _subborrow_u64(cf, r8, r12, (unsigned long long*)&r8);
    cf = _subborrow_u64(cf, r9, r13, (unsigned long long*)&r9);
    cf = _subborrow_u64(cf, r10, r14, (unsigned long long*)&r10);
    rcx = (word64)((rcx >> 1) | (r8 << 63));
    r8 = (word64)((r8 >> 1) | (r9 << 63));
    r9 = (word64)((r9 >> 1) | (r10 << 63));
    r10 = (word64)(r10 >> 1);
    if ((((byte)rcx & 1)) != (0)) {
        goto fe_invert_nct_usubv_even_end;
    }
fe_invert_nct_usubv_even_start:
    rcx = (word64)((rcx >> 1) | (r8 << 63));
    r8 = (word64)((r8 >> 1) | (r9 << 63));
    r9 = (word64)((r9 >> 1) | (r10 << 63));
    r10 = (word64)(r10 >> 1);
    WC_S8(rsp, r15) = (byte)(0);
    r15 = (word64)(r15 + 1);
    if ((((byte)rcx & 1)) == (0)) {
        goto fe_invert_nct_usubv_even_start;
    }
fe_invert_nct_usubv_even_end:
    if ((rcx) != (1)) {
        goto L_fe_invert_nct_uv_start;
    }
    rdx = (word64)(r8);
    rdx = (word64)(rdx | r9);
    if ((rdx) != (0)) {
        goto L_fe_invert_nct_uv_start;
    }
    rdx = (word64)(rdx | r10);
    if ((rdx) != (0)) {
        goto L_fe_invert_nct_uv_start;
    }
    rax = (rax & ~(word64)0xff) | ((word64)(byte)(1) & 0xff);
    goto L_fe_invert_nct_uv_end;
L_fe_invert_nct_uv_v:
    WC_S8(rsp, r15) = (byte)(3);
    r15 = (word64)(r15 + 1);
    cf = _subborrow_u64(0, r11, rcx, (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, r12, r8, (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, r9, (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, r10, (unsigned long long*)&r14);
    r11 = (word64)((r11 >> 1) | (r12 << 63));
    r12 = (word64)((r12 >> 1) | (r13 << 63));
    r13 = (word64)((r13 >> 1) | (r14 << 63));
    r14 = (word64)(r14 >> 1);
    if ((((byte)r11 & 1)) != (0)) {
        goto fe_invert_nct_vsubu_even_end;
    }
fe_invert_nct_vsubu_even_start:
    r11 = (word64)((r11 >> 1) | (r12 << 63));
    r12 = (word64)((r12 >> 1) | (r13 << 63));
    r13 = (word64)((r13 >> 1) | (r14 << 63));
    r14 = (word64)(r14 >> 1);
    WC_S8(rsp, r15) = (byte)(1);
    r15 = (word64)(r15 + 1);
    if ((((byte)r11 & 1)) == (0)) {
        goto fe_invert_nct_vsubu_even_start;
    }
fe_invert_nct_vsubu_even_end:
    if ((r11) != (1)) {
        goto L_fe_invert_nct_uv_start;
    }
    rdx = (word64)(r12);
    rdx = (word64)(rdx | r13);
    if ((rdx) != (0)) {
        goto L_fe_invert_nct_uv_start;
    }
    rdx = (word64)(rdx | r14);
    if ((rdx) != (0)) {
        goto L_fe_invert_nct_uv_start;
    }
    rax = (rax & ~(word64)0xff) | ((word64)(byte)(0) & 0xff);
L_fe_invert_nct_uv_end:
    rcx = (word64)(-19);
    r8 = (word64)(-1);
    r9 = (word64)(-1);
    r10 = (word64)(0x7fffffffffffffff);
    r11 = (word64)(1);
    r12 = (word64)(0);
    r13 = (word64)(0);
    r14 = (word64)(0);
    WC_S8(rsp, r15) = (byte)(7);
    rdx = (rdx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, 0)) & 0xff);
    r15 = (word64)(1);
    zf7 = (byte)rdx;
    zf8 = 1;
    if (((byte)rdx) == (1)) {
        goto L_fe_invert_nct_op_div2_d;
    }
    if ((sword8)(zf7) < (sword8)(zf8)) {
        goto L_fe_invert_nct_op_div2_b;
    }
    zf9 = (byte)rdx;
    zf10 = 3;
    if (((byte)rdx) == (3)) {
        goto L_fe_invert_nct_op_d_sub_b;
    }
    if ((sword8)(zf9) < (sword8)(zf10)) {
        goto L_fe_invert_nct_op_b_sub_d;
    }
    goto L_fe_invert_nct_op_end;
L_fe_invert_nct_op_b_sub_d:
    cf = _subborrow_u64(0, rcx, r11, (unsigned long long*)&rcx);
    cf = _subborrow_u64(cf, r8, r12, (unsigned long long*)&r8);
    cf = _subborrow_u64(cf, r9, r13, (unsigned long long*)&r9);
    cf = _subborrow_u64(cf, r10, r14, (unsigned long long*)&r10);
    if ((cf) == 0) {
        goto L_fe_invert_nct_op_div2_b;
    }
    rdx = (word64)(-1);
    cf = _addcarry_u64(0, rcx, -19, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, rdx, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    rdx = (word64)(0x7fffffffffffffff);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
L_fe_invert_nct_op_div2_b:
    if ((((byte)rcx & 1)) == (0)) {
        goto L_fe_invert_nct_op_div2_b_mod;
    }
    cf = _addcarry_u64(0, rcx, -19, (unsigned long long*)&rcx);
    rdx = (word64)(-1);
    cf = _addcarry_u64(cf, r8, rdx, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    rdx = (word64)(0x7fffffffffffffff);
    cf = _addcarry_u64(cf, r10, rdx, (unsigned long long*)&r10);
L_fe_invert_nct_op_div2_b_mod:
    rcx = (word64)((rcx >> 1) | (r8 << 63));
    r8 = (word64)((r8 >> 1) | (r9 << 63));
    r9 = (word64)((r9 >> 1) | (r10 << 63));
    r10 = (word64)(r10 >> 1);
    rdx = (rdx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, r15)) & 0xff);
    r15 = (word64)(r15 + 1);
    zf11 = (byte)rdx;
    zf12 = 1;
    if (((byte)rdx) == (1)) {
        goto L_fe_invert_nct_op_div2_d;
    }
    if ((sword8)(zf11) < (sword8)(zf12)) {
        goto L_fe_invert_nct_op_div2_b;
    }
    zf13 = (byte)rdx;
    zf14 = 3;
    if (((byte)rdx) == (3)) {
        goto L_fe_invert_nct_op_d_sub_b;
    }
    if ((sword8)(zf13) < (sword8)(zf14)) {
        goto L_fe_invert_nct_op_b_sub_d;
    }
    goto L_fe_invert_nct_op_end;
L_fe_invert_nct_op_d_sub_b:
    cf = _subborrow_u64(0, r11, rcx, (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, r12, r8, (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, r9, (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, r10, (unsigned long long*)&r14);
    if ((cf) == 0) {
        goto L_fe_invert_nct_op_div2_d;
    }
    rdx = (word64)(-1);
    cf = _addcarry_u64(0, r11, -19, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    rdx = (word64)(0x7fffffffffffffff);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
L_fe_invert_nct_op_div2_d:
    if ((((byte)r11 & 1)) == (0)) {
        goto L_fe_invert_nct_op_div2_d_mod;
    }
    cf = _addcarry_u64(0, r11, -19, (unsigned long long*)&r11);
    rdx = (word64)(-1);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    rdx = (word64)(0x7fffffffffffffff);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
L_fe_invert_nct_op_div2_d_mod:
    r11 = (word64)((r11 >> 1) | (r12 << 63));
    r12 = (word64)((r12 >> 1) | (r13 << 63));
    r13 = (word64)((r13 >> 1) | (r14 << 63));
    r14 = (word64)(r14 >> 1);
    rdx = (rdx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, r15)) & 0xff);
    r15 = (word64)(r15 + 1);
    zf15 = (byte)rdx;
    zf16 = 1;
    if (((byte)rdx) == (1)) {
        goto L_fe_invert_nct_op_div2_d;
    }
    if ((sword8)(zf15) < (sword8)(zf16)) {
        goto L_fe_invert_nct_op_div2_b;
    }
    zf17 = (byte)rdx;
    zf18 = 3;
    if (((byte)rdx) == (3)) {
        goto L_fe_invert_nct_op_d_sub_b;
    }
    if ((sword8)(zf17) < (sword8)(zf18)) {
        goto L_fe_invert_nct_op_b_sub_d;
    }
L_fe_invert_nct_op_end:
    if (((byte)rax) != (1)) {
        goto L_fe_invert_nct_store_d;
    }
    WC_S64(rdi, 0) = (word64)(rcx);
    WC_S64(rdi, 8) = (word64)(r8);
    WC_S64(rdi, 16) = (word64)(r9);
    WC_S64(rdi, 24) = (word64)(r10);
    goto L_fe_invert_nct_store_end;
L_fe_invert_nct_store_d:
    WC_S64(rdi, 0) = (word64)(r11);
    WC_S64(rdi, 8) = (word64)(r12);
    WC_S64(rdi, 16) = (word64)(r13);
    WC_S64(rdi, 24) = (word64)(r14);
L_fe_invert_nct_store_end:
    ;
}

#endif /* HAVE_ED25519 */
#ifdef HAVE_INTEL_AVX2
WC_X64I_TARGET("avx2")
WOLFSSL_LOCAL void fe_cmov_table_avx2(fe* r, const fe* base, signed char b)
{
    word64 rdi, rsi, rcx, rbx, rax, rdx, r8, r9, r10, r11, r12, r13, r14, r15;
    __m256i y0, y1, y2, y3, y4, y5, y6, y7, y8, y9;
    byte zf1;
    byte zf2;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)base;
    rcx = (word64)(byte)b;

    rbx = (word64)(0);
    rax = (word64)((word64)(sword64)(signed char)(byte)rcx);
    rdx = (word64)(word32)((sword32)(word32)rax >> 31);
    rax = (rax & ~(word64)0xff) | ((word64)(byte)((byte)rax ^ (
        byte)rdx) & 0xff);
    rax = (rax & ~(word64)0xff) | ((word64)(byte)((byte)rax - (
        byte)rdx) & 0xff);
    rbx = (rbx & ~(word64)0xff) | ((word64)(byte)((byte)rax) & 0xff);
    y7 = _mm256_zextsi128_si256(_mm_cvtsi32_si128((int)(word32)rbx));
    rbx = (word64)(1);
    y9 = _mm256_zextsi128_si256(_mm_cvtsi64_si128((long long)rbx));
    y3 = y9;
    y4 = y9;
    y8 = _mm256_setzero_si256();
    y7 = _mm256_permutevar8x32_epi32(y7, y8);
    y9 = _mm256_permutevar8x32_epi32(y9, y8);
    y0 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y6 = _mm256_cmpeq_epi32(y8, y7);
    y5 = _mm256_setzero_si256();
    y3 = _mm256_and_si256(y3, y6);
    y4 = _mm256_and_si256(y4, y6);
    y8 = y9;
    y6 = _mm256_cmpeq_epi32(y8, y7);
    y8 = _mm256_add_epi32(y8, y9);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 32));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 64));
    y0 = _mm256_and_si256(y0, y6);
    y1 = _mm256_and_si256(y1, y6);
    y2 = _mm256_and_si256(y2, y6);
    y3 = _mm256_or_si256(y3, y0);
    y4 = _mm256_or_si256(y4, y1);
    y5 = _mm256_or_si256(y5, y2);
    y6 = _mm256_cmpeq_epi32(y8, y7);
    y8 = _mm256_add_epi32(y8, y9);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 96));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 128));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 160));
    y0 = _mm256_and_si256(y0, y6);
    y1 = _mm256_and_si256(y1, y6);
    y2 = _mm256_and_si256(y2, y6);
    y3 = _mm256_or_si256(y3, y0);
    y4 = _mm256_or_si256(y4, y1);
    y5 = _mm256_or_si256(y5, y2);
    y6 = _mm256_cmpeq_epi32(y8, y7);
    y8 = _mm256_add_epi32(y8, y9);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 192));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 224));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 256));
    y0 = _mm256_and_si256(y0, y6);
    y1 = _mm256_and_si256(y1, y6);
    y2 = _mm256_and_si256(y2, y6);
    y3 = _mm256_or_si256(y3, y0);
    y4 = _mm256_or_si256(y4, y1);
    y5 = _mm256_or_si256(y5, y2);
    y6 = _mm256_cmpeq_epi32(y8, y7);
    y8 = _mm256_add_epi32(y8, y9);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 288));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 320));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 352));
    y0 = _mm256_and_si256(y0, y6);
    y1 = _mm256_and_si256(y1, y6);
    y2 = _mm256_and_si256(y2, y6);
    y3 = _mm256_or_si256(y3, y0);
    y4 = _mm256_or_si256(y4, y1);
    y5 = _mm256_or_si256(y5, y2);
    y6 = _mm256_cmpeq_epi32(y8, y7);
    y8 = _mm256_add_epi32(y8, y9);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 384));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 416));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 448));
    y0 = _mm256_and_si256(y0, y6);
    y1 = _mm256_and_si256(y1, y6);
    y2 = _mm256_and_si256(y2, y6);
    y3 = _mm256_or_si256(y3, y0);
    y4 = _mm256_or_si256(y4, y1);
    y5 = _mm256_or_si256(y5, y2);
    y6 = _mm256_cmpeq_epi32(y8, y7);
    y8 = _mm256_add_epi32(y8, y9);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 480));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 512));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 544));
    y0 = _mm256_and_si256(y0, y6);
    y1 = _mm256_and_si256(y1, y6);
    y2 = _mm256_and_si256(y2, y6);
    y3 = _mm256_or_si256(y3, y0);
    y4 = _mm256_or_si256(y4, y1);
    y5 = _mm256_or_si256(y5, y2);
    y6 = _mm256_cmpeq_epi32(y8, y7);
    y8 = _mm256_add_epi32(y8, y9);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 576));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 608));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 640));
    y0 = _mm256_and_si256(y0, y6);
    y1 = _mm256_and_si256(y1, y6);
    y2 = _mm256_and_si256(y2, y6);
    y3 = _mm256_or_si256(y3, y0);
    y4 = _mm256_or_si256(y4, y1);
    y5 = _mm256_or_si256(y5, y2);
    y6 = _mm256_cmpeq_epi32(y8, y7);
    y8 = _mm256_add_epi32(y8, y9);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 672));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 704));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 736));
    y0 = _mm256_and_si256(y0, y6);
    y1 = _mm256_and_si256(y1, y6);
    y2 = _mm256_and_si256(y2, y6);
    y3 = _mm256_or_si256(y3, y0);
    y4 = _mm256_or_si256(y4, y1);
    y5 = _mm256_or_si256(y5, y2);
    rax = (word64)((word64)(sword64)(signed char)(byte)rcx);
    rax = (word64)((word64)((sword64)rax >> 63));
    y6 = _mm256_zextsi128_si256(_mm_cvtsi32_si128((int)(word32)rax));
    y8 = _mm256_setzero_si256();
    y6 = _mm256_permutevar8x32_epi32(y6, y8);
    y8 = _mm256_xor_si256(y3, y4);
    y8 = _mm256_and_si256(y8, y6);
    y3 = _mm256_xor_si256(y3, y8);
    y4 = _mm256_xor_si256(y4, y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 0), y3);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 32), y4);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 64), y5);
    r8 = (word64)(WC_L64(rdi, 64));
    r9 = (word64)(WC_L64(rdi, 72));
    r10 = (word64)(WC_L64(rdi, 80));
    r11 = (word64)(WC_L64(rdi, 88));
    r12 = (word64)(-19);
    r13 = (word64)(-1);
    r14 = (word64)(-1);
    r15 = (word64)(0x7fffffffffffffff);
    cf = _subborrow_u64(0, r12, r8, (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, r9, (unsigned long long*)&r13);
    cf = _subborrow_u64(cf, r14, r10, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, r11, (unsigned long long*)&r15);
    zf1 = (byte)rcx;
    zf2 = 0;
    r8 = (sword8)((byte)rcx) < (sword8)(0) ? r12 : r8;
    r9 = (sword8)(zf1) < (sword8)(zf2) ? r13 : r9;
    r10 = (sword8)(zf1) < (sword8)(zf2) ? r14 : r10;
    r11 = (sword8)(zf1) < (sword8)(zf2) ? r15 : r11;
    WC_S64(rdi, 64) = (word64)(r8);
    WC_S64(rdi, 72) = (word64)(r9);
    WC_S64(rdi, 80) = (word64)(r10);
    WC_S64(rdi, 88) = (word64)(r11);
}

WOLFSSL_LOCAL void fe_mul_avx2(fe r, fe a, fe b)
{
    fe_mul_x64(r, a, b);
}

WOLFSSL_LOCAL void fe_sq_avx2(fe r, fe a)
{
    fe_sq_x64(r, a);
}

WOLFSSL_LOCAL void fe_sq_n_avx2(fe r, const fe a, word64 n)
{
    fe_sq_n_x64(r, a, n);
}

WC_X64I_TARGET("bmi2")
WOLFSSL_LOCAL void fe_mul121666_avx2(fe r, fe a)
{
    word64 rdi, rsi, rdx, rax = 0, r13 = 0, rcx = 0, r12 = 0, r8 = 0, r11 = 0,
           r9 = 0, r10 = 0;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)a;

    rdx = (word64)(0x1db42);
    WC_X64I_MUL128(rax, r13, rdx, WC_L64(rsi, 0));
    WC_X64I_MUL128(rcx, r12, rdx, WC_L64(rsi, 8));
    WC_X64I_MUL128(r8, r11, rdx, WC_L64(rsi, 16));
    cf = _addcarry_u64(0, rcx, r13, (unsigned long long*)&rcx);
    WC_X64I_MUL128(r9, r10, rdx, WC_L64(rsi, 24));
    cf = _addcarry_u64(cf, r8, r12, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r11, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    r10 = (word64)((r10 << 1) | (r9 >> 63));
    r9 = (word64)(r9 & ~(word64)((word64)1 << 63));
    r10 = (word64)(r10 * 19);
    cf = _addcarry_u64(0, rax, r10, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, rcx, 0, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    WC_S64(rdi, 0) = (word64)(rax);
    WC_S64(rdi, 8) = (word64)(rcx);
    WC_S64(rdi, 16) = (word64)(r8);
    WC_S64(rdi, 24) = (word64)(r9);
}

WOLFSSL_LOCAL void fe_invert_avx2(fe r, const fe a)
{
    word64 rdi, rsi, rsp, rdx;
    XALIGNED(32) WC_X64I_SLOT stk[20];

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)a;

    rsp = (word64)(size_t)stk + 160;
    rsp = (word64)(rsp - 144);
    /* Invert */
    WC_S64(rsp, 128) = (word64)(rdi);
    WC_S64(rsp, 136) = (word64)(rsi);
    rdi = (word64)(rsp);
    rsi = (word64)(WC_L64(rsp, 136));
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(WC_L64(rsp, 136));
    rdx = (word64)(rsp + 32);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(4);
    (void)fe_sq_n_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(9);
    (void)fe_sq_n_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 64);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(0x13);
    (void)fe_sq_n_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(9);
    (void)fe_sq_n_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(0x31);
    (void)fe_sq_n_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 64);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 96);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(0x63);
    (void)fe_sq_n_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 96);
    rdx = (word64)(rsp + 64);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(0x31);
    (void)fe_sq_n_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(4);
    (void)fe_sq_n_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(WC_L64(rsp, 128));
    rsi = (word64)(rsp + 32);
    rdx = (word64)(rsp);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rsi = (word64)(WC_L64(rsp, 136));
    rdi = (word64)(WC_L64(rsp, 128));
}

#if defined(WOLFSSL_CURVE25519_NOT_USE_ED25519)
XALIGNED(32) static const word64 L_curve25519_base_avx2_x2[] WC_X64I_UNUSED = {
    0x5cae469cdd684efbULL, 0x8f3f5ced1e350b5cULL,
    0xd9750c687d157114ULL, 0x20d342d51873f1b7ULL,
};

WOLFSSL_LOCAL int curve25519_base_avx2(byte* r, byte* n)
{
    return curve25519_base_x64(r, n);
}

#endif /* WOLFSSL_CURVE25519_NOT_USE_ED25519 */
WOLFSSL_LOCAL int curve25519_avx2(byte* r, byte* n, byte* a)
{
    return curve25519_x64(r, n, a);
}

WOLFSSL_LOCAL void fe_pow22523_avx2(fe r, const fe a)
{
    word64 rdi, rsi, rsp, rdx;
    XALIGNED(32) WC_X64I_SLOT stk[16];

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)a;

    rsp = (word64)(size_t)stk + 128;
    rsp = (word64)(rsp - 112);
    /* pow22523 */
    WC_S64(rsp, 96) = (word64)(rdi);
    WC_S64(rsp, 104) = (word64)(rsi);
    rdi = (word64)(rsp);
    rsi = (word64)(WC_L64(rsp, 104));
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(WC_L64(rsp, 104));
    rdx = (word64)(rsp + 32);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(rsp);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(4);
    (void)fe_sq_n_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(rsp);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(9);
    (void)fe_sq_n_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(rsp);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(0x13);
    (void)fe_sq_n_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(9);
    (void)fe_sq_n_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(rsp);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(0x31);
    (void)fe_sq_n_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(rsp);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 64);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(0x63);
    (void)fe_sq_n_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 64);
    rdx = (word64)(rsp + 32);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp + 32);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(0x31);
    (void)fe_sq_n_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (word64)rdx);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp + 32);
    rdx = (word64)(rsp);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(rsp);
    rsi = (word64)(rsp);
    (void)fe_sq_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    rdi = (word64)(WC_L64(rsp, 96));
    rsi = (word64)(rsp);
    rdx = (word64)(WC_L64(rsp, 104));
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    rsi = (word64)(WC_L64(rsp, 104));
    rdi = (word64)(WC_L64(rsp, 96));
}

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_p1p1_to_p2_avx2(ge_p2* r, const ge_p1p1* p)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
    ge_p1p1_to_p2_x64(r, p);
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_p1p1_to_p3_avx2(ge_p3* r, const ge_p1p1* p)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
    ge_p1p1_to_p3_x64(r, p);
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_p2_dbl_avx2(ge_p1p1* r, const ge_p2* p)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
    ge_p2_dbl_x64(r, p);
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_madd_avx2(ge_p1p1* r, const ge_p3* p, const ge_precomp* q)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
    ge_madd_x64(r, p, q);
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_msub_avx2(ge_p1p1* r, const ge_p3* p, const ge_precomp* q)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
    ge_msub_x64(r, p, q);
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_add_avx2(ge_p1p1* r, const ge_p3* p, const fe qe_cached)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
    ge_add_x64(r, p, qe_cached);
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL void ge_sub_avx2(ge_p1p1* r, const ge_p3* p, const fe qe_cached)
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
{
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
    ge_sub_x64(r, p, qe_cached);
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#ifdef HAVE_ED25519
WOLFSSL_LOCAL void fe_sq2_avx2(fe r, fe a)
{
    fe_sq2_x64(r, a);
}

WC_X64I_TARGET("bmi2")
WOLFSSL_LOCAL void sc_reduce_avx2(byte* s)
{
    word64 rdi, r8, r9, r10, r11, r12, r13, r14, r15, rax, rcx, rdx, rsi = 0,
           rbx = 0, rbp;
    unsigned char cf;

    rdi = (word64)(size_t)s;

    r8 = (word64)(WC_L64(rdi, 0));
    r9 = (word64)(WC_L64(rdi, 8));
    r10 = (word64)(WC_L64(rdi, 16));
    r11 = (word64)(WC_L64(rdi, 24));
    r12 = (word64)(WC_L64(rdi, 32));
    r13 = (word64)(WC_L64(rdi, 40));
    r14 = (word64)(WC_L64(rdi, 48));
    r15 = (word64)(WC_L64(rdi, 56));
    rax = (word64)(r15);
    rcx = (word64)(0xfffffffffffffff);
    rax = (word64)(rax >> 56);
    r15 = (word64)((r15 << 4) | (r14 >> 60));
    r14 = (word64)((r14 << 4) | (r13 >> 60));
    r13 = (word64)((r13 << 4) | (r12 >> 60));
    r12 = (word64)((r12 << 4) | (r11 >> 60));
    r11 = (word64)(r11 & rcx);
    r15 = (word64)(r15 & rcx);
    /* Add order times bits 504..511 */
    cf = _subborrow_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _subborrow_u64(cf, r15, 0, (unsigned long long*)&r15);
    rdx = (word64)(0xeb2106215d086329);
    WC_X64I_MUL128(rsi, rcx, rdx, rax);
    rdx = (word64)(0xa7ed9ce5a30a2c13);
    cf = _addcarry_u64(0, r13, rsi, (unsigned long long*)&r13);
    WC_X64I_MUL128(rsi, rbx, rdx, rax);
    cf = _addcarry_u64(cf, rcx, 0, (unsigned long long*)&rcx);
    cf = _addcarry_u64(0, r12, rsi, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rbx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rcx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /* Sub product of top 4 words and order */
    rdx = (word64)(0xa7ed9ce5a30a2c13);
    WC_X64I_MUL128(rcx, rax, rdx, r12);
    cf = _addcarry_u64(0, r8, rcx, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rax, (unsigned long long*)&r9);
    WC_X64I_MUL128(rcx, rax, rdx, r14);
    cf = _addcarry_u64(cf, r10, rcx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rax, (unsigned long long*)&r11);
    rsi = (word64)(0);
    cf = _addcarry_u64(cf, rsi, 0, (unsigned long long*)&rsi);
    WC_X64I_MUL128(rcx, rax, rdx, r13);
    cf = _addcarry_u64(0, r9, rcx, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rax, (unsigned long long*)&r10);
    WC_X64I_MUL128(rcx, rax, rdx, r15);
    cf = _addcarry_u64(cf, r11, rcx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rsi, rax, (unsigned long long*)&rsi);
    rdx = (word64)(0xeb2106215d086329);
    WC_X64I_MUL128(rcx, rax, rdx, r12);
    cf = _addcarry_u64(0, r9, rcx, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rax, (unsigned long long*)&r10);
    WC_X64I_MUL128(rcx, rax, rdx, r14);
    cf = _addcarry_u64(cf, r11, rcx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, rsi, rax, (unsigned long long*)&rsi);
    rbx = (word64)(0);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    WC_X64I_MUL128(rcx, rax, rdx, r13);
    cf = _addcarry_u64(0, r10, rcx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rax, (unsigned long long*)&r11);
    WC_X64I_MUL128(rcx, rax, rdx, r15);
    cf = _addcarry_u64(cf, rsi, rcx, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, rax, (unsigned long long*)&rbx);
    cf = _subborrow_u64(0, r10, r12, (unsigned long long*)&r10);
    r12 = (word64)(rsi);
    cf = _subborrow_u64(cf, r11, r13, (unsigned long long*)&r11);
    r13 = (word64)(rbx);
    cf = _subborrow_u64(cf, r12, r14, (unsigned long long*)&r12);
    cf = _subborrow_u64(cf, r13, r15, (unsigned long long*)&r13);
    rax = (word64)(r13);
    rax = (word64)((word64)((sword64)rax >> 57));
    /*   Conditionally subtract order starting at bit 125 */
    rsi = (word64)(0xa000000000000000);
    rbx = (word64)(0xcb024c634b9eba7d);
    rbp = (word64)(0x29bdf3bd45ef39a);
    rcx = (word64)(0x200000000000000);
    rsi = (word64)(rsi & rax);
    rbx = (word64)(rbx & rax);
    rbp = (word64)(rbp & rax);
    rcx = (word64)(rcx & rax);
    cf = _addcarry_u64(0, r9, rsi, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rbx, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rbp, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rcx, (unsigned long long*)&r13);
    /*   Move bits 252-376 to own registers */
    rax = (word64)(0xfffffffffffffff);
    r13 = (word64)((r13 << 4) | (r12 >> 60));
    r12 = (word64)((r12 << 4) | (r11 >> 60));
    r11 = (word64)(r11 & rax);
    /* Sub product of top 2 words and order */
    /*   * -5812631a5cf5d3ed */
    rdx = (word64)(0xa7ed9ce5a30a2c13);
    WC_X64I_MUL128(rbp, rax, rdx, r12);
    rsi = (word64)(0);
    cf = _addcarry_u64(0, r8, rbp, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rax, (unsigned long long*)&r9);
    WC_X64I_MUL128(rbp, rax, rdx, r13);
    cf = _addcarry_u64(cf, rsi, 0, (unsigned long long*)&rsi);
    cf = _addcarry_u64(0, r9, rbp, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, rsi, rax, (unsigned long long*)&rsi);
    /*   * -14def9dea2f79cd7 */
    rdx = (word64)(0xeb2106215d086329);
    WC_X64I_MUL128(rbp, rax, rdx, r12);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r9, rbp, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, rax, (unsigned long long*)&r10);
    WC_X64I_MUL128(rbp, rax, rdx, r13);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    cf = _addcarry_u64(0, r10, rbp, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, rbx, rax, (unsigned long long*)&rbx);
    /*   Add overflows at 2 * 64 */
    rcx = (word64)(0xfffffffffffffff);
    r11 = (word64)(r11 & rcx);
    cf = _addcarry_u64(0, r10, rsi, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rbx, (unsigned long long*)&r11);
    /*   Subtract top at 2 * 64 */
    cf = _subborrow_u64(0, r10, r12, (unsigned long long*)&r10);
    cf = _subborrow_u64(cf, r11, r13, (unsigned long long*)&r11);
    cf = _subborrow_u64(cf, rcx, rcx, (unsigned long long*)&rcx);
    /*   Conditional sub order */
    rsi = (word64)(0x5812631a5cf5d3ed);
    rbx = (word64)(0x14def9dea2f79cd6);
    rbp = (word64)(0x1000000000000000);
    rsi = (word64)(rsi & rcx);
    rbx = (word64)(rbx & rcx);
    rbp = (word64)(rbp & rcx);
    cf = _addcarry_u64(0, r8, rsi, (unsigned long long*)&r8);
    rsi = (word64)(0xfffffffffffffff);
    cf = _addcarry_u64(cf, r9, rbx, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rbp, (unsigned long long*)&r11);
    r11 = (word64)(r11 & rsi);
    /* Store result */
    WC_S64(rdi, 0) = (word64)(r8);
    WC_S64(rdi, 8) = (word64)(r9);
    WC_S64(rdi, 16) = (word64)(r10);
    WC_S64(rdi, 24) = (word64)(r11);
}

WOLFSSL_LOCAL void sc_muladd_avx2(byte* s, byte* a, byte* b, byte* c)
{
    sc_muladd_x64(s, a, b, c);
}

XALIGNED(16) static const word32 L_fe_invert_nct_avx2_prime[] WC_X64I_UNUSED = {
    0x03ffffed, 0x03ffffff, 0x03ffffff, 0x03ffffff,
    0x03ffffff, 0x00000000, 0x00000000, 0x00000000,
    0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff,
    0x001fffff, 0x00000000, 0x00000000, 0x00000000,
};

XALIGNED(32) static const word64 L_fe_invert_nct_avx2_one[] WC_X64I_UNUSED = {
    0x0000000000000001ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
};

XALIGNED(16) static const word32 L_fe_invert_nct_avx2_all_one[]
    WC_X64I_UNUSED = {
    0x00000001, 0x00000001, 0x00000001, 0x00000001,
    0x00000001, 0x00000001, 0x00000001, 0x00000001,
};

XALIGNED(16) static const word32 L_fe_invert_nct_avx2_mask01111[]
    WC_X64I_UNUSED = {
    0x00000000, 0x00000001, 0x00000001, 0x00000001,
    0x00000001, 0x00000000, 0x00000000, 0x00000000,
};

XALIGNED(16) static const word32 L_fe_invert_nct_avx2_down_one_dword[]
    WC_X64I_UNUSED = {
    0x00000001, 0x00000002, 0x00000003, 0x00000004,
    0x00000005, 0x00000006, 0x00000007, 0x00000007,
};

XALIGNED(16) static const word32 L_fe_invert_nct_avx2_neg[] WC_X64I_UNUSED = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x80000000, 0x00000000, 0x00000000, 0x00000000,
};

XALIGNED(16) static const word32 L_fe_invert_nct_avx2_up_one_dword[]
    WC_X64I_UNUSED = {
    0x00000007, 0x00000000, 0x00000001, 0x00000002,
    0x00000003, 0x00000007, 0x00000007, 0x00000007,
};

XALIGNED(16) static const word32 L_fe_invert_nct_avx2_mask26[]
    WC_X64I_UNUSED = {
    0x03ffffff, 0x03ffffff, 0x03ffffff, 0x03ffffff,
    0x03ffffff, 0x00000000, 0x00000000, 0x00000000,
};

/* Non-constant time modular inversion.
 *
 * @param  [out]  r   Resulting number.
 * @param  [in]   a   Number to invert.
 * @param  [in]   m   Modulus.
 * @return  MP_OKAY on success.
 */
WC_X64I_TARGET("avx2")
WOLFSSL_LOCAL void fe_invert_nct_avx2(word64* r, const word64* a)
{
    word64 rdi, rsi, rax, rcx, r8, r9, r10, r11, r12, r13, rbx, rdx = 0,
           r14 = 0, r15 = 0;
    __m256i y0, y1, y2, y3, y4 = _mm256_setzero_si256(),
            y5 = _mm256_setzero_si256(), y6, y7, y8, y9, y10, y11, y12, y13,
            y14;
    word64 zf1;
    word64 zf2;
    word64 zf3;
    word64 zf4;
    word64 zf5;
    word64 zf6;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)a;

    rax = (word64)(-19);
    rcx = (word64)(-1);
    r8 = (word64)(-1);
    r9 = (word64)(0x7fffffffffffffff);
    r10 = (word64)(WC_L64(rsi, 0));
    r11 = (word64)(WC_L64(rsi, 8));
    r12 = (word64)(WC_L64(rsi, 16));
    r13 = (word64)(WC_L64(rsi, 24));
    rbx = (word64)((word64)(size_t)L_fe_invert_nct_avx2_prime);
    y6 = _mm256_loadu_si256((const __m256i*)WC_PR(rbx, 0));
    y7 = _mm256_loadu_si256((const __m256i*)WC_PR(rbx, 32));
    rbx = (word64)((word64)(size_t)L_fe_invert_nct_avx2_one);
    y8 = _mm256_loadu_si256((const __m256i*)WC_PR(rbx, 0));
    rbx = (word64)((word64)(size_t)L_fe_invert_nct_avx2_mask01111);
    y9 = _mm256_loadu_si256((const __m256i*)WC_PR(rbx, 0));
    rbx = (word64)((word64)(size_t)L_fe_invert_nct_avx2_all_one);
    y10 = _mm256_loadu_si256((const __m256i*)WC_PR(rbx, 0));
    rbx = (word64)((word64)(size_t)L_fe_invert_nct_avx2_down_one_dword);
    y11 = _mm256_loadu_si256((const __m256i*)WC_PR(rbx, 0));
    rbx = (word64)((word64)(size_t)L_fe_invert_nct_avx2_neg);
    y12 = _mm256_loadu_si256((const __m256i*)WC_PR(rbx, 0));
    rbx = (word64)((word64)(size_t)L_fe_invert_nct_avx2_up_one_dword);
    y13 = _mm256_loadu_si256((const __m256i*)WC_PR(rbx, 0));
    rbx = (word64)((word64)(size_t)L_fe_invert_nct_avx2_mask26);
    y14 = _mm256_loadu_si256((const __m256i*)WC_PR(rbx, 0));
    y0 = _mm256_zextsi128_si256(_mm_setzero_si128());
    y1 = _mm256_zextsi128_si256(_mm_setzero_si128());
    y2 = y8;
    y3 = _mm256_zextsi128_si256(_mm_setzero_si128());
    if ((((byte)r10 & 1)) != (0)) {
        goto L_fe_invert_nct_avx2_v_even_end;
    }
L_fe_invert_nct_avx2_v_even_start:
    r10 = (word64)((r10 >> 1) | (r11 << 63));
    r11 = (word64)((r11 >> 1) | (r12 << 63));
    r12 = (word64)((r12 >> 1) | (r13 << 63));
    r13 = (word64)(r13 >> 1);
    if ((_mm256_testz_si256(y2, y8)) == (1)) {
        goto L_fe_invert_nct_avx2_v_even_shr1;
    }
    y2 = _mm256_add_epi32(y2, y6);
    y3 = _mm256_add_epi32(y3, y7);
L_fe_invert_nct_avx2_v_even_shr1:
    y4 = _mm256_and_si256(y2, y9);
    y5 = _mm256_and_si256(y3, y10);
    y4 = _mm256_permutevar8x32_epi32(y4, y11);
    y2 = _mm256_srai_epi32(y2, 1);
    y3 = _mm256_srai_epi32(y3, 1);
    y5 = _mm256_slli_epi32(y5, 25);
    y4 = _mm256_zextsi128_si256(_mm_slli_epi32(_mm256_castsi256_si128(y4), 25));
    y2 = _mm256_add_epi32(y2, y5);
    y3 = _mm256_add_epi32(y3, y4);
    if ((((byte)r10 & 1)) == (0)) {
        goto L_fe_invert_nct_avx2_v_even_start;
    }
L_fe_invert_nct_avx2_v_even_end:
L_fe_invert_nct_avx2_uv_start:
    zf1 = r9;
    zf2 = r13;
    if ((r9) < (r13)) {
        goto L_fe_invert_nct_avx2_uv_v;
    }
    if ((zf1) > (zf2)) {
        goto L_fe_invert_nct_avx2_uv_u;
    }
    zf3 = r8;
    zf4 = r12;
    if ((r8) < (r12)) {
        goto L_fe_invert_nct_avx2_uv_v;
    }
    if ((zf3) > (zf4)) {
        goto L_fe_invert_nct_avx2_uv_u;
    }
    zf5 = rcx;
    zf6 = r11;
    if ((rcx) < (r11)) {
        goto L_fe_invert_nct_avx2_uv_v;
    }
    if ((zf5) > (zf6)) {
        goto L_fe_invert_nct_avx2_uv_u;
    }
    if ((rax) < (r10)) {
        goto L_fe_invert_nct_avx2_uv_v;
    }
L_fe_invert_nct_avx2_uv_u:
    cf = _subborrow_u64(0, rax, r10, (unsigned long long*)&rax);
    cf = _subborrow_u64(cf, rcx, r11, (unsigned long long*)&rcx);
    y0 = _mm256_sub_epi32(y0, y2);
    cf = _subborrow_u64(cf, r8, r12, (unsigned long long*)&r8);
    y1 = _mm256_sub_epi32(y1, y3);
    cf = _subborrow_u64(cf, r9, r13, (unsigned long long*)&r9);
    if ((_mm256_testz_si256(y1, y12)) == (1)) {
        goto L_fe_invert_nct_avx2_usubv_done_neg;
    }
    y0 = _mm256_add_epi32(y0, y6);
    y1 = _mm256_add_epi32(y1, y7);
L_fe_invert_nct_avx2_usubv_done_neg:
L_fe_invert_nct_avx2_usubv_shr1:
    rax = (word64)((rax >> 1) | (rcx << 63));
    rcx = (word64)((rcx >> 1) | (r8 << 63));
    r8 = (word64)((r8 >> 1) | (r9 << 63));
    r9 = (word64)(r9 >> 1);
    if ((_mm256_testz_si256(y0, y8)) == (1)) {
        goto L_fe_invert_nct_avx2_usubv_sub_shr1;
    }
    y0 = _mm256_add_epi32(y0, y6);
    y1 = _mm256_add_epi32(y1, y7);
L_fe_invert_nct_avx2_usubv_sub_shr1:
    y4 = _mm256_and_si256(y0, y9);
    y5 = _mm256_and_si256(y1, y10);
    y4 = _mm256_permutevar8x32_epi32(y4, y11);
    y0 = _mm256_srai_epi32(y0, 1);
    y1 = _mm256_srai_epi32(y1, 1);
    y5 = _mm256_slli_epi32(y5, 25);
    y4 = _mm256_zextsi128_si256(_mm_slli_epi32(_mm256_castsi256_si128(y4), 25));
    y0 = _mm256_add_epi32(y0, y5);
    y1 = _mm256_add_epi32(y1, y4);
    if ((((byte)rax & 1)) == (0)) {
        goto L_fe_invert_nct_avx2_usubv_shr1;
    }
    if ((rax) != (1)) {
        goto L_fe_invert_nct_avx2_uv_start;
    }
    rdx = (word64)(rcx);
    rdx = (word64)(rdx | r8);
    if ((rdx) != (0)) {
        goto L_fe_invert_nct_avx2_uv_start;
    }
    rdx = (word64)(rdx | r9);
    if ((rdx) != (0)) {
        goto L_fe_invert_nct_avx2_uv_start;
    }
    rax = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y0), 0));
    r8 = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y0), 1));
    r10 = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y0), 2));
    r12 = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y0), 3));
    rcx = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y1), 0));
    r9 = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y1), 1));
    r11 = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y1), 2));
    r13 = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y1), 3));
    y0 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y0, 1));
    y1 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y1, 1));
    r14 = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y0), 0));
    r15 = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y1), 0));
    goto L_fe_invert_nct_avx2_store_done;
L_fe_invert_nct_avx2_uv_v:
    cf = _subborrow_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _subborrow_u64(cf, r11, rcx, (unsigned long long*)&r11);
    y2 = _mm256_sub_epi32(y2, y0);
    cf = _subborrow_u64(cf, r12, r8, (unsigned long long*)&r12);
    y3 = _mm256_sub_epi32(y3, y1);
    cf = _subborrow_u64(cf, r13, r9, (unsigned long long*)&r13);
    if ((_mm256_testz_si256(y3, y12)) == (1)) {
        goto L_fe_invert_nct_avx2_vsubu_done_neg;
    }
    y2 = _mm256_add_epi32(y2, y6);
    y3 = _mm256_add_epi32(y3, y7);
L_fe_invert_nct_avx2_vsubu_done_neg:
L_fe_invert_nct_avx2_vsubu_shr1:
    r10 = (word64)((r10 >> 1) | (r11 << 63));
    r11 = (word64)((r11 >> 1) | (r12 << 63));
    r12 = (word64)((r12 >> 1) | (r13 << 63));
    r13 = (word64)(r13 >> 1);
    if ((_mm256_testz_si256(y2, y8)) == (1)) {
        goto L_fe_invert_nct_avx2_vsubu_sub_shr1;
    }
    y2 = _mm256_add_epi32(y2, y6);
    y3 = _mm256_add_epi32(y3, y7);
L_fe_invert_nct_avx2_vsubu_sub_shr1:
    y4 = _mm256_and_si256(y2, y9);
    y5 = _mm256_and_si256(y3, y10);
    y4 = _mm256_permutevar8x32_epi32(y4, y11);
    y2 = _mm256_srai_epi32(y2, 1);
    y3 = _mm256_srai_epi32(y3, 1);
    y5 = _mm256_slli_epi32(y5, 25);
    y4 = _mm256_zextsi128_si256(_mm_slli_epi32(_mm256_castsi256_si128(y4), 25));
    y2 = _mm256_add_epi32(y2, y5);
    y3 = _mm256_add_epi32(y3, y4);
    if ((((byte)r10 & 1)) == (0)) {
        goto L_fe_invert_nct_avx2_vsubu_shr1;
    }
    if ((r10) != (1)) {
        goto L_fe_invert_nct_avx2_uv_start;
    }
    rdx = (word64)(r11);
    rdx = (word64)(rdx | r12);
    if ((rdx) != (0)) {
        goto L_fe_invert_nct_avx2_uv_start;
    }
    rdx = (word64)(rdx | r13);
    if ((rdx) != (0)) {
        goto L_fe_invert_nct_avx2_uv_start;
    }
    rax = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y2), 0));
    r8 = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y2), 1));
    r10 = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y2), 2));
    r12 = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y2), 3));
    rcx = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y3), 0));
    r9 = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y3), 1));
    r11 = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y3), 2));
    r13 = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y3), 3));
    y2 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y2, 1));
    y3 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y3, 1));
    r14 = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y2), 0));
    r15 = (word32)((word32)_mm_extract_epi32(_mm256_castsi256_si128(y3), 0));
L_fe_invert_nct_avx2_store_done:
    rdx = (word32)((word32)rax);
    rax = (word32)((word32)rax & 0x3ffffff);
    rdx = (word32)((word32)((sword32)(word32)rdx >> 26));
    rcx = (word32)((word32)rcx + (word32)rdx);
    rdx = (word32)((word32)rcx);
    rcx = (word32)((word32)rcx & 0x3ffffff);
    rdx = (word32)((word32)((sword32)(word32)rdx >> 26));
    r8 = (word32)((word32)r8 + (word32)rdx);
    rdx = (word32)((word32)r8);
    r8 = (word32)((word32)r8 & 0x3ffffff);
    rdx = (word32)((word32)((sword32)(word32)rdx >> 26));
    r9 = (word32)((word32)r9 + (word32)rdx);
    rdx = (word32)((word32)r9);
    r9 = (word32)((word32)r9 & 0x3ffffff);
    rdx = (word32)((word32)((sword32)(word32)rdx >> 26));
    r10 = (word32)((word32)r10 + (word32)rdx);
    rdx = (word32)((word32)r10);
    r10 = (word32)((word32)r10 & 0x3ffffff);
    rdx = (word32)((word32)((sword32)(word32)rdx >> 26));
    r11 = (word32)((word32)r11 + (word32)rdx);
    rdx = (word32)((word32)r11);
    r11 = (word32)((word32)r11 & 0x3ffffff);
    rdx = (word32)((word32)((sword32)(word32)rdx >> 26));
    r12 = (word32)((word32)r12 + (word32)rdx);
    rdx = (word32)((word32)r12);
    r12 = (word32)((word32)r12 & 0x3ffffff);
    rdx = (word32)((word32)((sword32)(word32)rdx >> 26));
    r13 = (word32)((word32)r13 + (word32)rdx);
    rdx = (word32)((word32)r13);
    r13 = (word32)((word32)r13 & 0x3ffffff);
    rdx = (word32)((word32)((sword32)(word32)rdx >> 26));
    r14 = (word32)((word32)r14 + (word32)rdx);
    rdx = (word32)((word32)r14);
    r14 = (word32)((word32)r14 & 0x3ffffff);
    rdx = (word32)((word32)((sword32)(word32)rdx >> 26));
    r15 = (word32)((word32)r15 + (word32)rdx);
    rcx = (word64)((word64)(sword64)(sword32)(word32)rcx);
    r9 = (word64)((word64)(sword64)(sword32)(word32)r9);
    r11 = (word64)((word64)(sword64)(sword32)(word32)r11);
    r13 = (word64)((word64)(sword64)(sword32)(word32)r13);
    r15 = (word64)((word64)(sword64)(sword32)(word32)r15);
    rcx = (word64)(rcx << 26);
    r9 = (word64)(r9 << 26);
    r11 = (word64)(r11 << 26);
    r13 = (word64)(r13 << 26);
    r15 = (word64)(r15 << 26);
    rax = (word64)((word64)(sword64)(sword32)(word32)rax);
    cf = _addcarry_u64(0, rax, rcx, (unsigned long long*)&rax);
    r8 = (word64)((word64)(sword64)(sword32)(word32)r8);
    cf = _addcarry_u64(cf, r8, r9, (unsigned long long*)&r8);
    r10 = (word64)((word64)(sword64)(sword32)(word32)r10);
    cf = _addcarry_u64(cf, r10, r11, (unsigned long long*)&r10);
    r12 = (word64)((word64)(sword64)(sword32)(word32)r12);
    cf = _addcarry_u64(cf, r12, r13, (unsigned long long*)&r12);
    r14 = (word64)((word64)(sword64)(sword32)(word32)r14);
    cf = _addcarry_u64(cf, r14, r15, (unsigned long long*)&r14);
    if ((sword64)(r14) >= (sword64)(0)) {
        goto L_fe_invert_nct_avx2_uv_start_no_add_prime;
    }
    rcx = (word64)(0xfffffffffffed);
    r9 = (word64)(0xfffffffffffff);
    r11 = (word64)(0xfffffffffffff);
    r13 = (word64)(0xfffffffffffff);
    r15 = (word64)(0x7fffffffffff);
    rax = (word64)(rax + rcx);
    r8 = (word64)(r8 + r9);
    r10 = (word64)(r10 + r11);
    r12 = (word64)(r12 + r13);
    r14 = (word64)(r14 + r15);
    rdx = (word64)(0xfffffffffffff);
    rcx = (word64)(rax);
    rax = (word64)(rax & rdx);
    rcx = (word64)((word64)((sword64)rcx >> 52));
    r8 = (word64)(r8 + rcx);
    r9 = (word64)(r8);
    r8 = (word64)(r8 & rdx);
    r9 = (word64)((word64)((sword64)r9 >> 52));
    r10 = (word64)(r10 + r9);
    r11 = (word64)(r10);
    r10 = (word64)(r10 & rdx);
    r11 = (word64)((word64)((sword64)r11 >> 52));
    r12 = (word64)(r12 + r11);
    r13 = (word64)(r12);
    r12 = (word64)(r12 & rdx);
    r13 = (word64)((word64)((sword64)r13 >> 52));
    r14 = (word64)(r14 + r13);
L_fe_invert_nct_avx2_uv_start_no_add_prime:
    rcx = (word64)(r8);
    r9 = (word64)(r10);
    r11 = (word64)(r12);
    rcx = (word64)(rcx << 52);
    r8 = (word64)((word64)((sword64)r8 >> 12));
    r9 = (word64)(r9 << 40);
    r10 = (word64)((word64)((sword64)r10 >> 24));
    r11 = (word64)(r11 << 28);
    r12 = (word64)((word64)((sword64)r12 >> 36));
    r14 = (word64)(r14 << 16);
    cf = _addcarry_u64(0, rax, rcx, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, r8, r9, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r10, r11, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r12, r14, (unsigned long long*)&r12);
    WC_S64(rdi, 0) = (word64)(rax);
    WC_S64(rdi, 8) = (word64)(r8);
    WC_S64(rdi, 16) = (word64)(r10);
    WC_S64(rdi, 24) = (word64)(r12);
    (void)y13;
    (void)y14;
}

#endif /* HAVE_ED25519 */
#ifdef HAVE_INTEL_AVX512_IFMA
XALIGNED(32) static const word64 L_x25519_ifma_consts[] WC_X64I_UNUSED = {
    0x0007ffffffffffffULL, 0x000fffffffffffdaULL,
    0x000ffffffffffffeULL, 0x0000000000000013ULL,
    0x000000000001db41ULL,
};

#if defined(WOLFSSL_CURVE25519_NOT_USE_ED25519)
WC_X64I_TARGET("avx512f,avx512vl,avx512ifma")
WOLFSSL_LOCAL int curve25519_base_avx512_ifma(byte* r, byte* n)
{
    word64 rdi, rsi, rsp, r13, r10, r11, r8, rdx, rcx = 0, rax = 0, r9 = 0,
           r12 = 0;
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y4 = _mm256_setzero_si256(), y5 = _mm256_setzero_si256(),
            y6 = _mm256_setzero_si256(), y7 = _mm256_setzero_si256(),
            y8 = _mm256_setzero_si256(), y9 = _mm256_setzero_si256(),
            y10 = _mm256_setzero_si256(), y11 = _mm256_setzero_si256(),
            y12 = _mm256_setzero_si256(), y13 = _mm256_setzero_si256(),
            y14 = _mm256_setzero_si256(), y15 = _mm256_setzero_si256(),
            y16 = _mm256_setzero_si256(), y17 = _mm256_setzero_si256(), y18,
            y19, y20, y21, y22, y23 = _mm256_setzero_si256(),
            y24 = _mm256_setzero_si256(), y25 = _mm256_setzero_si256(),
            y26 = _mm256_setzero_si256(), y27 = _mm256_setzero_si256(), y28,
            y29, y30, y31;
    XALIGNED(32) WC_X64I_SLOT stk[92];
    __mmask16 k1, k2, k3, k4, k5, k7, k6;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)n;

    rsp = (word64)(size_t)stk + 736;
    rsp = (word64)(rsp - 736);
    WC_S64(rsp, 712) = (word64)(rdi);
    r13 = (word64)(0x7ffffffffffff);
    r10 = (word64)(9);
    WC_S64(rsp, 0) = (word64)(r10);
    WC_S64(rsp, 8) = (word64)(r10);
    WC_S64(rsp, 16) = (word64)(r10);
    WC_S64(rsp, 24) = (word64)(r10);
    WC_S64(rsp, 480) = (word64)(1);
    WC_S64(rsp, 488) = (word64)(0);
    WC_S64(rsp, 496) = (word64)(r10);
    WC_S64(rsp, 504) = (word64)(1);
    r10 = (word64)(0);
    WC_S64(rsp, 32) = (word64)(r10);
    WC_S64(rsp, 40) = (word64)(r10);
    WC_S64(rsp, 48) = (word64)(r10);
    WC_S64(rsp, 56) = (word64)(r10);
    WC_S64(rsp, 512) = (word64)(0);
    WC_S64(rsp, 520) = (word64)(0);
    WC_S64(rsp, 528) = (word64)(r10);
    WC_S64(rsp, 536) = (word64)(0);
    WC_S64(rsp, 64) = (word64)(r10);
    WC_S64(rsp, 72) = (word64)(r10);
    WC_S64(rsp, 80) = (word64)(r10);
    WC_S64(rsp, 88) = (word64)(r10);
    WC_S64(rsp, 544) = (word64)(0);
    WC_S64(rsp, 552) = (word64)(0);
    WC_S64(rsp, 560) = (word64)(r10);
    WC_S64(rsp, 568) = (word64)(0);
    WC_S64(rsp, 96) = (word64)(r10);
    WC_S64(rsp, 104) = (word64)(r10);
    WC_S64(rsp, 112) = (word64)(r10);
    WC_S64(rsp, 120) = (word64)(r10);
    WC_S64(rsp, 576) = (word64)(0);
    WC_S64(rsp, 584) = (word64)(0);
    WC_S64(rsp, 592) = (word64)(r10);
    WC_S64(rsp, 600) = (word64)(0);
    WC_S64(rsp, 128) = (word64)(r10);
    WC_S64(rsp, 136) = (word64)(r10);
    WC_S64(rsp, 144) = (word64)(r10);
    WC_S64(rsp, 152) = (word64)(r10);
    WC_S64(rsp, 608) = (word64)(0);
    WC_S64(rsp, 616) = (word64)(0);
    WC_S64(rsp, 624) = (word64)(r10);
    WC_S64(rsp, 632) = (word64)(0);
    r11 = (word64)((word64)(size_t)L_x25519_ifma_consts);
    y28 = _mm256_set1_epi64x((long long)WC_L64(r11, 0));
    y29 = _mm256_set1_epi64x((long long)WC_L64(r11, 8));
    y30 = _mm256_set1_epi64x((long long)WC_L64(r11, 16));
    y31 = _mm256_set1_epi64x((long long)WC_L64(r11, 24));
    r10 = (word32)(0xa);
    k1 = (__mmask16)(word32)r10;
    r10 = (word32)(5);
    k2 = (__mmask16)(word32)r10;
    r10 = (word32)(4);
    k3 = (__mmask16)(word32)r10;
    r10 = (word32)(8);
    k4 = (__mmask16)(word32)r10;
    r10 = (word32)(2);
    k5 = (__mmask16)(word32)r10;
    r10 = (word32)(6);
    k7 = (__mmask16)(word32)r10;
    y18 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 480));
    y19 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 512));
    y20 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 544));
    y21 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 576));
    y22 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 608));
    r8 = (word64)(0);
    rdx = (word64)(0xfe);
L_curve25519_base_avx512_ifma_bits:
    /* Conditionally swap (x2, z2) with (x3, z3) */
    WC_S64(rsp, 704) = (word64)(rdx);
    rcx = (word64)(rdx);
    rcx = (word64)(rcx & 0x3f);
    rdx = (word64)(rdx >> 6);
    rax = (word64)(WC_L64(rsi, rdx * 8));
    rax = (word64)(rax >> ((byte)rcx & 63));
    rax = (word64)(rax & 1);
    r9 = (word64)(rax);
    r8 = (word64)(r8 ^ rax);
    r8 = (word64)(0 - r8);
    r8 = (word64)(r8 & 0xf);
    k6 = (__mmask16)(word32)r8;
    r8 = (word64)(r9);
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_permute4x64_epi64(y18, 0x4e));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_permute4x64_epi64(y19, 0x4e));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_permute4x64_epi64(y20, 0x4e));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_permute4x64_epi64(y21, 0x4e));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_permute4x64_epi64(y22, 0x4e));
    /* A = x2 + z2, B = x2 - z2, C = x3 + z3, D = x3 - z3 */
    y0 = _mm256_permute4x64_epi64(y18, 0xb1);
    y1 = _mm256_permute4x64_epi64(y19, 0xb1);
    y2 = _mm256_permute4x64_epi64(y20, 0xb1);
    y3 = _mm256_permute4x64_epi64(y21, 0xb1);
    y4 = _mm256_permute4x64_epi64(y22, 0xb1);
    y23 = _mm256_add_epi64(y0, y18);
    y24 = _mm256_add_epi64(y1, y19);
    y25 = _mm256_add_epi64(y2, y20);
    y26 = _mm256_add_epi64(y3, y21);
    y27 = _mm256_add_epi64(y4, y22);
    y0 = _mm256_mask_blend_epi64(k1, y0, _mm256_add_epi64(y0, y29));
    y1 = _mm256_mask_blend_epi64(k1, y1, _mm256_add_epi64(y1, y30));
    y2 = _mm256_mask_blend_epi64(k1, y2, _mm256_add_epi64(y2, y30));
    y3 = _mm256_mask_blend_epi64(k1, y3, _mm256_add_epi64(y3, y30));
    y4 = _mm256_mask_blend_epi64(k1, y4, _mm256_add_epi64(y4, y30));
    y23 = _mm256_mask_blend_epi64(k1, y23, _mm256_sub_epi64(y0, y18));
    y24 = _mm256_mask_blend_epi64(k1, y24, _mm256_sub_epi64(y1, y19));
    y25 = _mm256_mask_blend_epi64(k1, y25, _mm256_sub_epi64(y2, y20));
    y26 = _mm256_mask_blend_epi64(k1, y26, _mm256_sub_epi64(y3, y21));
    y27 = _mm256_mask_blend_epi64(k1, y27, _mm256_sub_epi64(y4, y22));
    y5 = _mm256_srli_epi64(y23, 51);
    y23 = _mm256_and_si256(y23, y28);
    y6 = _mm256_srli_epi64(y24, 51);
    y24 = _mm256_and_si256(y24, y28);
    y7 = _mm256_srli_epi64(y25, 51);
    y25 = _mm256_and_si256(y25, y28);
    y8 = _mm256_srli_epi64(y26, 51);
    y26 = _mm256_and_si256(y26, y28);
    y9 = _mm256_srli_epi64(y27, 51);
    y27 = _mm256_and_si256(y27, y28);
    y23 = _mm256_madd52lo_epu64(y23, y9, y31);
    y24 = _mm256_add_epi64(y24, y5);
    y25 = _mm256_add_epi64(y25, y6);
    y26 = _mm256_add_epi64(y26, y7);
    y27 = _mm256_add_epi64(y27, y8);
    /* [AA, BB, CB, DA] = [A, B, C, D] * [A, B, B, A] */
    y18 = _mm256_permute4x64_epi64(y23, 0x14);
    y19 = _mm256_permute4x64_epi64(y24, 0x14);
    y20 = _mm256_permute4x64_epi64(y25, 0x14);
    y21 = _mm256_permute4x64_epi64(y26, 0x14);
    y22 = _mm256_permute4x64_epi64(y27, 0x14);
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_slli_epi64(y5, 4);
    y10 = _mm256_slli_epi64(y5, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y5);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_slli_epi64(y6, 4);
    y10 = _mm256_slli_epi64(y6, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y6);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_slli_epi64(y7, 4);
    y10 = _mm256_slli_epi64(y7, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y7);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_slli_epi64(y8, 4);
    y10 = _mm256_slli_epi64(y8, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y8);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_slli_epi64(y17, 4);
    y10 = _mm256_slli_epi64(y17, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y17);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* U = [AA, DA-CB, DA+CB, AA-BB], V = [BB, DA-CB, DA+CB, a24] */
    y23 = _mm256_permute4x64_epi64(y18, 0x69);
    y24 = _mm256_permute4x64_epi64(y19, 0x69);
    y25 = _mm256_permute4x64_epi64(y20, 0x69);
    y26 = _mm256_permute4x64_epi64(y21, 0x69);
    y27 = _mm256_permute4x64_epi64(y22, 0x69);
    y18 = _mm256_permute4x64_epi64(y18, 0x3c);
    y19 = _mm256_permute4x64_epi64(y19, 0x3c);
    y20 = _mm256_permute4x64_epi64(y20, 0x3c);
    y21 = _mm256_permute4x64_epi64(y21, 0x3c);
    y22 = _mm256_permute4x64_epi64(y22, 0x3c);
    y18 = _mm256_mask_blend_epi64(k3, y18, _mm256_add_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k3, y19, _mm256_add_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k3, y20, _mm256_add_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k3, y21, _mm256_add_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k3, y22, _mm256_add_epi64(y22, y27));
    y18 = _mm256_mask_blend_epi64(k1, y18, _mm256_add_epi64(y18, y29));
    y19 = _mm256_mask_blend_epi64(k1, y19, _mm256_add_epi64(y19, y30));
    y20 = _mm256_mask_blend_epi64(k1, y20, _mm256_add_epi64(y20, y30));
    y21 = _mm256_mask_blend_epi64(k1, y21, _mm256_add_epi64(y21, y30));
    y22 = _mm256_mask_blend_epi64(k1, y22, _mm256_add_epi64(y22, y30));
    y18 = _mm256_mask_blend_epi64(k1, y18, _mm256_sub_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k1, y19, _mm256_sub_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k1, y20, _mm256_sub_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k1, y21, _mm256_sub_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k1, y22, _mm256_sub_epi64(y22, y27));
    y0 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y1 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y2 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y3 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y4 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y4, y31);
    y19 = _mm256_add_epi64(y19, y0);
    y20 = _mm256_add_epi64(y20, y1);
    y21 = _mm256_add_epi64(y21, y2);
    y22 = _mm256_add_epi64(y22, y3);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 160), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 192), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 224), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 256), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 288), y22);
    y23 = _mm256_mask_blend_epi64(k7, y23, y18);
    y24 = _mm256_mask_blend_epi64(k7, y24, y19);
    y25 = _mm256_mask_blend_epi64(k7, y25, y20);
    y26 = _mm256_mask_blend_epi64(k7, y26, y21);
    y27 = _mm256_mask_blend_epi64(k7, y27, y22);
    y23 = _mm256_mask_blend_epi64(k4, y23, _mm256_set1_epi64x((long long)WC_L64(
        r11, 32)));
    y24 = _mm256_mask_blend_epi64(k4, y24, _mm256_setzero_si256());
    y25 = _mm256_mask_blend_epi64(k4, y25, _mm256_setzero_si256());
    y26 = _mm256_mask_blend_epi64(k4, y26, _mm256_setzero_si256());
    y27 = _mm256_mask_blend_epi64(k4, y27, _mm256_setzero_si256());
    /* [AA.BB, GG, FF, a24.E] = U * V */
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_slli_epi64(y5, 4);
    y10 = _mm256_slli_epi64(y5, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y5);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_slli_epi64(y6, 4);
    y10 = _mm256_slli_epi64(y6, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y6);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_slli_epi64(y7, 4);
    y10 = _mm256_slli_epi64(y7, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y7);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_slli_epi64(y8, 4);
    y10 = _mm256_slli_epi64(y8, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y8);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_slli_epi64(y17, 4);
    y10 = _mm256_slli_epi64(y17, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y17);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* U3 = [E, E, E, x1], V3 = [aE, AA + a24.E, T, T] */
    y23 = _mm256_permute4x64_epi64(y18, 0x5f);
    y24 = _mm256_permute4x64_epi64(y19, 0x5f);
    y25 = _mm256_permute4x64_epi64(y20, 0x5f);
    y26 = _mm256_permute4x64_epi64(y21, 0x5f);
    y27 = _mm256_permute4x64_epi64(y22, 0x5f);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 320), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 352), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 384), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 416), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 448), y22);
    y5 = _mm256_set1_epi64x((long long)WC_L64(rsp, 160));
    y6 = _mm256_set1_epi64x((long long)WC_L64(rsp, 192));
    y7 = _mm256_set1_epi64x((long long)WC_L64(rsp, 224));
    y8 = _mm256_set1_epi64x((long long)WC_L64(rsp, 256));
    y9 = _mm256_set1_epi64x((long long)WC_L64(rsp, 288));
    y23 = _mm256_mask_blend_epi64(k5, y23, _mm256_add_epi64(y23, y5));
    y24 = _mm256_mask_blend_epi64(k5, y24, _mm256_add_epi64(y24, y6));
    y25 = _mm256_mask_blend_epi64(k5, y25, _mm256_add_epi64(y25, y7));
    y26 = _mm256_mask_blend_epi64(k5, y26, _mm256_add_epi64(y26, y8));
    y27 = _mm256_mask_blend_epi64(k5, y27, _mm256_add_epi64(y27, y9));
    y10 = _mm256_srli_epi64(y23, 51);
    y23 = _mm256_and_si256(y23, y28);
    y11 = _mm256_srli_epi64(y24, 51);
    y24 = _mm256_and_si256(y24, y28);
    y12 = _mm256_srli_epi64(y25, 51);
    y25 = _mm256_and_si256(y25, y28);
    y13 = _mm256_srli_epi64(y26, 51);
    y26 = _mm256_and_si256(y26, y28);
    y14 = _mm256_srli_epi64(y27, 51);
    y27 = _mm256_and_si256(y27, y28);
    y23 = _mm256_madd52lo_epu64(y23, y14, y31);
    y24 = _mm256_add_epi64(y24, y10);
    y25 = _mm256_add_epi64(y25, y11);
    y26 = _mm256_add_epi64(y26, y12);
    y27 = _mm256_add_epi64(y27, y13);
    y18 = _mm256_set1_epi64x((long long)WC_L64(rsp, 184));
    y19 = _mm256_set1_epi64x((long long)WC_L64(rsp, 216));
    y20 = _mm256_set1_epi64x((long long)WC_L64(rsp, 248));
    y21 = _mm256_set1_epi64x((long long)WC_L64(rsp, 280));
    y22 = _mm256_set1_epi64x((long long)WC_L64(rsp, 312));
    y18 = _mm256_mask_blend_epi64(k4, y18, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 0)));
    y19 = _mm256_mask_blend_epi64(k4, y19, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 32)));
    y20 = _mm256_mask_blend_epi64(k4, y20, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 64)));
    y21 = _mm256_mask_blend_epi64(k4, y21, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 96)));
    y22 = _mm256_mask_blend_epi64(k4, y22, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 128)));
    /* [-, E.H, -, x1.T] = U3 * V3 */
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_slli_epi64(y5, 4);
    y10 = _mm256_slli_epi64(y5, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y5);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_slli_epi64(y6, 4);
    y10 = _mm256_slli_epi64(y6, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y6);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_slli_epi64(y7, 4);
    y10 = _mm256_slli_epi64(y7, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y7);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_slli_epi64(y8, 4);
    y10 = _mm256_slli_epi64(y8, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y8);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_slli_epi64(y17, 4);
    y10 = _mm256_slli_epi64(y17, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y17);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* [x2, z2, x3, z3] = [AA.BB, E.H, FF, x1.T] */
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 320));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 352));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 384));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 416));
    y4 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 448));
    y18 = _mm256_mask_blend_epi64(k2, y18, y0);
    y19 = _mm256_mask_blend_epi64(k2, y19, y1);
    y20 = _mm256_mask_blend_epi64(k2, y20, y2);
    y21 = _mm256_mask_blend_epi64(k2, y21, y3);
    y22 = _mm256_mask_blend_epi64(k2, y22, y4);
    rdx = (word64)(WC_L64(rsp, 704));
    rdx = (word64)(rdx - 1);
    if ((sword64)(rdx) >= (sword64)(0)) {
        goto L_curve25519_base_avx512_ifma_bits;
    }
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 480), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 512), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 544), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 576), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 608), y22);
    /* Convert to 4 x 64-bit field elements */
    r13 = (word64)(0x7ffffffffffff);
    rdx = (word64)(WC_L64(rsp, 480));
    rax = (word64)(WC_L64(rsp, 512));
    r8 = (word64)(WC_L64(rsp, 544));
    r9 = (word64)(WC_L64(rsp, 576));
    r10 = (word64)(WC_L64(rsp, 608));
    r11 = (word64)(rdx);
    r11 = (word64)(r11 >> 51);
    rdx = (word64)(rdx & r13);
    rax = (word64)(rax + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 >> 51);
    rax = (word64)(rax & r13);
    r8 = (word64)(r8 + r11);
    r11 = (word64)(r8);
    r11 = (word64)(r11 >> 51);
    r8 = (word64)(r8 & r13);
    r9 = (word64)(r9 + r11);
    r11 = (word64)(r9);
    r11 = (word64)(r11 >> 51);
    r9 = (word64)(r9 & r13);
    r10 = (word64)(r10 + r11);
    r11 = (word64)(r10);
    r11 = (word64)(r11 >> 51);
    r10 = (word64)(r10 & r13);
    r11 = (word64)(r11 * 19);
    rdx = (word64)(rdx + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 << 51);
    r12 = (word64)(rax);
    r12 = (word64)(r12 >> 13);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rsp, 640) = (word64)(rdx);
    r11 = (word64)(r8);
    r11 = (word64)(r11 << 38);
    rdx = (word64)(r8);
    rdx = (word64)(rdx >> 26);
    cf = _addcarry_u64(0, r12, r11, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    WC_S64(rsp, 648) = (word64)(r12);
    r11 = (word64)(r9);
    r11 = (word64)(r11 << 25);
    r12 = (word64)(r9);
    r12 = (word64)(r12 >> 39);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rsp, 656) = (word64)(rdx);
    r11 = (word64)(r10);
    r11 = (word64)(r11 << 12);
    r12 = (word64)(r12 + r11);
    WC_S64(rsp, 664) = (word64)(r12);
    rdx = (word64)(WC_L64(rsp, 488));
    rax = (word64)(WC_L64(rsp, 520));
    r8 = (word64)(WC_L64(rsp, 552));
    r9 = (word64)(WC_L64(rsp, 584));
    r10 = (word64)(WC_L64(rsp, 616));
    r11 = (word64)(rdx);
    r11 = (word64)(r11 >> 51);
    rdx = (word64)(rdx & r13);
    rax = (word64)(rax + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 >> 51);
    rax = (word64)(rax & r13);
    r8 = (word64)(r8 + r11);
    r11 = (word64)(r8);
    r11 = (word64)(r11 >> 51);
    r8 = (word64)(r8 & r13);
    r9 = (word64)(r9 + r11);
    r11 = (word64)(r9);
    r11 = (word64)(r11 >> 51);
    r9 = (word64)(r9 & r13);
    r10 = (word64)(r10 + r11);
    r11 = (word64)(r10);
    r11 = (word64)(r11 >> 51);
    r10 = (word64)(r10 & r13);
    r11 = (word64)(r11 * 19);
    rdx = (word64)(rdx + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 << 51);
    r12 = (word64)(rax);
    r12 = (word64)(r12 >> 13);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rsp, 672) = (word64)(rdx);
    r11 = (word64)(r8);
    r11 = (word64)(r11 << 38);
    rdx = (word64)(r8);
    rdx = (word64)(rdx >> 26);
    cf = _addcarry_u64(0, r12, r11, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    WC_S64(rsp, 680) = (word64)(r12);
    r11 = (word64)(r9);
    r11 = (word64)(r11 << 25);
    r12 = (word64)(r9);
    r12 = (word64)(r12 >> 39);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rsp, 688) = (word64)(rdx);
    r11 = (word64)(r10);
    r11 = (word64)(r11 << 12);
    r12 = (word64)(r12 + r11);
    WC_S64(rsp, 696) = (word64)(r12);
    /* z2 = 1 / z2 */
    rdi = (word64)(rsp + 672);
    rsi = (word64)(rsp + 672);
    (void)fe_invert_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    /* x2 = x2 * z2 */
    rdi = (word64)(rsp + 640);
    rsi = (word64)(rsp + 640);
    rdx = (word64)(rsp + 672);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    /* Store fully reduced result */
    rdi = (word64)(WC_L64(rsp, 712));
    rsi = (word64)(rsp + 640);
    (void)fe_tobytes((unsigned char*)(size_t)rdi, (void*)(size_t)rsi);
    rax = (word64)(0);
    return (int)(word32)rax;
}

#endif /* WOLFSSL_CURVE25519_NOT_USE_ED25519 */
WC_X64I_TARGET("avx512f,avx512vl,avx512ifma")
WOLFSSL_LOCAL int curve25519_avx512_ifma(byte* r, byte* n, byte* a)
{
    word64 rdi, rsi, r15, rsp, r13, rdx, rax, r8, r9, r10, r12, r11, rcx = 0;
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y4 = _mm256_setzero_si256(), y5 = _mm256_setzero_si256(),
            y6 = _mm256_setzero_si256(), y7 = _mm256_setzero_si256(),
            y8 = _mm256_setzero_si256(), y9 = _mm256_setzero_si256(),
            y10 = _mm256_setzero_si256(), y11 = _mm256_setzero_si256(),
            y12 = _mm256_setzero_si256(), y13 = _mm256_setzero_si256(),
            y14 = _mm256_setzero_si256(), y15 = _mm256_setzero_si256(),
            y16 = _mm256_setzero_si256(), y17 = _mm256_setzero_si256(), y18,
            y19, y20, y21, y22, y23 = _mm256_setzero_si256(),
            y24 = _mm256_setzero_si256(), y25 = _mm256_setzero_si256(),
            y26 = _mm256_setzero_si256(), y27 = _mm256_setzero_si256(), y28,
            y29, y30, y31;
    XALIGNED(32) WC_X64I_SLOT stk[92];
    __mmask16 k1, k2, k3, k4, k5, k7, k6;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)n;
    r15 = (word64)(size_t)a;

    rsp = (word64)(size_t)stk + 736;
    rsp = (word64)(rsp - 736);
    WC_S64(rsp, 712) = (word64)(rdi);
    r13 = (word64)(0x7ffffffffffff);
    rdx = (word64)(WC_L64(r15, 0));
    rax = (word64)(WC_L64(r15, 8));
    r8 = (word64)(WC_L64(r15, 16));
    r9 = (word64)(WC_L64(r15, 24));
    r10 = (word64)(r9);
    r10 = (word64)(r10 >> 63);
    r10 = (word64)(r10 * 19);
    r9 = (word64)(r9 << 1);
    r9 = (word64)(r9 >> 1);
    r12 = (word64)(rdx);
    r12 = (word64)(r12 & r13);
    r12 = (word64)(r12 + r10);
    WC_S64(rsp, 0) = (word64)(r12);
    WC_S64(rsp, 8) = (word64)(r12);
    WC_S64(rsp, 16) = (word64)(r12);
    WC_S64(rsp, 24) = (word64)(r12);
    WC_S64(rsp, 480) = (word64)(1);
    WC_S64(rsp, 488) = (word64)(0);
    WC_S64(rsp, 496) = (word64)(r12);
    WC_S64(rsp, 504) = (word64)(1);
    rdx = (word64)((rdx >> 51) | (rax << 13));
    r10 = (word64)(rdx);
    r10 = (word64)(r10 & r13);
    WC_S64(rsp, 32) = (word64)(r10);
    WC_S64(rsp, 40) = (word64)(r10);
    WC_S64(rsp, 48) = (word64)(r10);
    WC_S64(rsp, 56) = (word64)(r10);
    WC_S64(rsp, 512) = (word64)(0);
    WC_S64(rsp, 520) = (word64)(0);
    WC_S64(rsp, 528) = (word64)(r10);
    WC_S64(rsp, 536) = (word64)(0);
    rax = (word64)((rax >> 38) | (r8 << 26));
    r10 = (word64)(rax);
    r10 = (word64)(r10 & r13);
    WC_S64(rsp, 64) = (word64)(r10);
    WC_S64(rsp, 72) = (word64)(r10);
    WC_S64(rsp, 80) = (word64)(r10);
    WC_S64(rsp, 88) = (word64)(r10);
    WC_S64(rsp, 544) = (word64)(0);
    WC_S64(rsp, 552) = (word64)(0);
    WC_S64(rsp, 560) = (word64)(r10);
    WC_S64(rsp, 568) = (word64)(0);
    r8 = (word64)((r8 >> 25) | (r9 << 39));
    r10 = (word64)(r8);
    r10 = (word64)(r10 & r13);
    WC_S64(rsp, 96) = (word64)(r10);
    WC_S64(rsp, 104) = (word64)(r10);
    WC_S64(rsp, 112) = (word64)(r10);
    WC_S64(rsp, 120) = (word64)(r10);
    WC_S64(rsp, 576) = (word64)(0);
    WC_S64(rsp, 584) = (word64)(0);
    WC_S64(rsp, 592) = (word64)(r10);
    WC_S64(rsp, 600) = (word64)(0);
    r9 = (word64)(r9 >> 12);
    WC_S64(rsp, 128) = (word64)(r9);
    WC_S64(rsp, 136) = (word64)(r9);
    WC_S64(rsp, 144) = (word64)(r9);
    WC_S64(rsp, 152) = (word64)(r9);
    WC_S64(rsp, 608) = (word64)(0);
    WC_S64(rsp, 616) = (word64)(0);
    WC_S64(rsp, 624) = (word64)(r9);
    WC_S64(rsp, 632) = (word64)(0);
    r11 = (word64)((word64)(size_t)L_x25519_ifma_consts);
    y28 = _mm256_set1_epi64x((long long)WC_L64(r11, 0));
    y29 = _mm256_set1_epi64x((long long)WC_L64(r11, 8));
    y30 = _mm256_set1_epi64x((long long)WC_L64(r11, 16));
    y31 = _mm256_set1_epi64x((long long)WC_L64(r11, 24));
    r10 = (word32)(0xa);
    k1 = (__mmask16)(word32)r10;
    r10 = (word32)(5);
    k2 = (__mmask16)(word32)r10;
    r10 = (word32)(4);
    k3 = (__mmask16)(word32)r10;
    r10 = (word32)(8);
    k4 = (__mmask16)(word32)r10;
    r10 = (word32)(2);
    k5 = (__mmask16)(word32)r10;
    r10 = (word32)(6);
    k7 = (__mmask16)(word32)r10;
    y18 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 480));
    y19 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 512));
    y20 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 544));
    y21 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 576));
    y22 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 608));
    r8 = (word64)(0);
    rdx = (word64)(0xfe);
L_curve25519_avx512_ifma_bits:
    /* Conditionally swap (x2, z2) with (x3, z3) */
    WC_S64(rsp, 704) = (word64)(rdx);
    rcx = (word64)(rdx);
    rcx = (word64)(rcx & 0x3f);
    rdx = (word64)(rdx >> 6);
    rax = (word64)(WC_L64(rsi, rdx * 8));
    rax = (word64)(rax >> ((byte)rcx & 63));
    rax = (word64)(rax & 1);
    r9 = (word64)(rax);
    r8 = (word64)(r8 ^ rax);
    r8 = (word64)(0 - r8);
    r8 = (word64)(r8 & 0xf);
    k6 = (__mmask16)(word32)r8;
    r8 = (word64)(r9);
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_permute4x64_epi64(y18, 0x4e));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_permute4x64_epi64(y19, 0x4e));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_permute4x64_epi64(y20, 0x4e));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_permute4x64_epi64(y21, 0x4e));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_permute4x64_epi64(y22, 0x4e));
    /* A = x2 + z2, B = x2 - z2, C = x3 + z3, D = x3 - z3 */
    y0 = _mm256_permute4x64_epi64(y18, 0xb1);
    y1 = _mm256_permute4x64_epi64(y19, 0xb1);
    y2 = _mm256_permute4x64_epi64(y20, 0xb1);
    y3 = _mm256_permute4x64_epi64(y21, 0xb1);
    y4 = _mm256_permute4x64_epi64(y22, 0xb1);
    y23 = _mm256_add_epi64(y0, y18);
    y24 = _mm256_add_epi64(y1, y19);
    y25 = _mm256_add_epi64(y2, y20);
    y26 = _mm256_add_epi64(y3, y21);
    y27 = _mm256_add_epi64(y4, y22);
    y0 = _mm256_mask_blend_epi64(k1, y0, _mm256_add_epi64(y0, y29));
    y1 = _mm256_mask_blend_epi64(k1, y1, _mm256_add_epi64(y1, y30));
    y2 = _mm256_mask_blend_epi64(k1, y2, _mm256_add_epi64(y2, y30));
    y3 = _mm256_mask_blend_epi64(k1, y3, _mm256_add_epi64(y3, y30));
    y4 = _mm256_mask_blend_epi64(k1, y4, _mm256_add_epi64(y4, y30));
    y23 = _mm256_mask_blend_epi64(k1, y23, _mm256_sub_epi64(y0, y18));
    y24 = _mm256_mask_blend_epi64(k1, y24, _mm256_sub_epi64(y1, y19));
    y25 = _mm256_mask_blend_epi64(k1, y25, _mm256_sub_epi64(y2, y20));
    y26 = _mm256_mask_blend_epi64(k1, y26, _mm256_sub_epi64(y3, y21));
    y27 = _mm256_mask_blend_epi64(k1, y27, _mm256_sub_epi64(y4, y22));
    y5 = _mm256_srli_epi64(y23, 51);
    y23 = _mm256_and_si256(y23, y28);
    y6 = _mm256_srli_epi64(y24, 51);
    y24 = _mm256_and_si256(y24, y28);
    y7 = _mm256_srli_epi64(y25, 51);
    y25 = _mm256_and_si256(y25, y28);
    y8 = _mm256_srli_epi64(y26, 51);
    y26 = _mm256_and_si256(y26, y28);
    y9 = _mm256_srli_epi64(y27, 51);
    y27 = _mm256_and_si256(y27, y28);
    y23 = _mm256_madd52lo_epu64(y23, y9, y31);
    y24 = _mm256_add_epi64(y24, y5);
    y25 = _mm256_add_epi64(y25, y6);
    y26 = _mm256_add_epi64(y26, y7);
    y27 = _mm256_add_epi64(y27, y8);
    /* [AA, BB, CB, DA] = [A, B, C, D] * [A, B, B, A] */
    y18 = _mm256_permute4x64_epi64(y23, 0x14);
    y19 = _mm256_permute4x64_epi64(y24, 0x14);
    y20 = _mm256_permute4x64_epi64(y25, 0x14);
    y21 = _mm256_permute4x64_epi64(y26, 0x14);
    y22 = _mm256_permute4x64_epi64(y27, 0x14);
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_slli_epi64(y5, 4);
    y10 = _mm256_slli_epi64(y5, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y5);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_slli_epi64(y6, 4);
    y10 = _mm256_slli_epi64(y6, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y6);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_slli_epi64(y7, 4);
    y10 = _mm256_slli_epi64(y7, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y7);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_slli_epi64(y8, 4);
    y10 = _mm256_slli_epi64(y8, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y8);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_slli_epi64(y17, 4);
    y10 = _mm256_slli_epi64(y17, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y17);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* U = [AA, DA-CB, DA+CB, AA-BB], V = [BB, DA-CB, DA+CB, a24] */
    y23 = _mm256_permute4x64_epi64(y18, 0x69);
    y24 = _mm256_permute4x64_epi64(y19, 0x69);
    y25 = _mm256_permute4x64_epi64(y20, 0x69);
    y26 = _mm256_permute4x64_epi64(y21, 0x69);
    y27 = _mm256_permute4x64_epi64(y22, 0x69);
    y18 = _mm256_permute4x64_epi64(y18, 0x3c);
    y19 = _mm256_permute4x64_epi64(y19, 0x3c);
    y20 = _mm256_permute4x64_epi64(y20, 0x3c);
    y21 = _mm256_permute4x64_epi64(y21, 0x3c);
    y22 = _mm256_permute4x64_epi64(y22, 0x3c);
    y18 = _mm256_mask_blend_epi64(k3, y18, _mm256_add_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k3, y19, _mm256_add_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k3, y20, _mm256_add_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k3, y21, _mm256_add_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k3, y22, _mm256_add_epi64(y22, y27));
    y18 = _mm256_mask_blend_epi64(k1, y18, _mm256_add_epi64(y18, y29));
    y19 = _mm256_mask_blend_epi64(k1, y19, _mm256_add_epi64(y19, y30));
    y20 = _mm256_mask_blend_epi64(k1, y20, _mm256_add_epi64(y20, y30));
    y21 = _mm256_mask_blend_epi64(k1, y21, _mm256_add_epi64(y21, y30));
    y22 = _mm256_mask_blend_epi64(k1, y22, _mm256_add_epi64(y22, y30));
    y18 = _mm256_mask_blend_epi64(k1, y18, _mm256_sub_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k1, y19, _mm256_sub_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k1, y20, _mm256_sub_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k1, y21, _mm256_sub_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k1, y22, _mm256_sub_epi64(y22, y27));
    y0 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y1 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y2 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y3 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y4 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y4, y31);
    y19 = _mm256_add_epi64(y19, y0);
    y20 = _mm256_add_epi64(y20, y1);
    y21 = _mm256_add_epi64(y21, y2);
    y22 = _mm256_add_epi64(y22, y3);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 160), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 192), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 224), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 256), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 288), y22);
    y23 = _mm256_mask_blend_epi64(k7, y23, y18);
    y24 = _mm256_mask_blend_epi64(k7, y24, y19);
    y25 = _mm256_mask_blend_epi64(k7, y25, y20);
    y26 = _mm256_mask_blend_epi64(k7, y26, y21);
    y27 = _mm256_mask_blend_epi64(k7, y27, y22);
    y23 = _mm256_mask_blend_epi64(k4, y23, _mm256_set1_epi64x((long long)WC_L64(
        r11, 32)));
    y24 = _mm256_mask_blend_epi64(k4, y24, _mm256_setzero_si256());
    y25 = _mm256_mask_blend_epi64(k4, y25, _mm256_setzero_si256());
    y26 = _mm256_mask_blend_epi64(k4, y26, _mm256_setzero_si256());
    y27 = _mm256_mask_blend_epi64(k4, y27, _mm256_setzero_si256());
    /* [AA.BB, GG, FF, a24.E] = U * V */
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_slli_epi64(y5, 4);
    y10 = _mm256_slli_epi64(y5, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y5);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_slli_epi64(y6, 4);
    y10 = _mm256_slli_epi64(y6, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y6);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_slli_epi64(y7, 4);
    y10 = _mm256_slli_epi64(y7, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y7);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_slli_epi64(y8, 4);
    y10 = _mm256_slli_epi64(y8, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y8);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_slli_epi64(y17, 4);
    y10 = _mm256_slli_epi64(y17, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y17);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* U3 = [E, E, E, x1], V3 = [aE, AA + a24.E, T, T] */
    y23 = _mm256_permute4x64_epi64(y18, 0x5f);
    y24 = _mm256_permute4x64_epi64(y19, 0x5f);
    y25 = _mm256_permute4x64_epi64(y20, 0x5f);
    y26 = _mm256_permute4x64_epi64(y21, 0x5f);
    y27 = _mm256_permute4x64_epi64(y22, 0x5f);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 320), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 352), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 384), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 416), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 448), y22);
    y5 = _mm256_set1_epi64x((long long)WC_L64(rsp, 160));
    y6 = _mm256_set1_epi64x((long long)WC_L64(rsp, 192));
    y7 = _mm256_set1_epi64x((long long)WC_L64(rsp, 224));
    y8 = _mm256_set1_epi64x((long long)WC_L64(rsp, 256));
    y9 = _mm256_set1_epi64x((long long)WC_L64(rsp, 288));
    y23 = _mm256_mask_blend_epi64(k5, y23, _mm256_add_epi64(y23, y5));
    y24 = _mm256_mask_blend_epi64(k5, y24, _mm256_add_epi64(y24, y6));
    y25 = _mm256_mask_blend_epi64(k5, y25, _mm256_add_epi64(y25, y7));
    y26 = _mm256_mask_blend_epi64(k5, y26, _mm256_add_epi64(y26, y8));
    y27 = _mm256_mask_blend_epi64(k5, y27, _mm256_add_epi64(y27, y9));
    y10 = _mm256_srli_epi64(y23, 51);
    y23 = _mm256_and_si256(y23, y28);
    y11 = _mm256_srli_epi64(y24, 51);
    y24 = _mm256_and_si256(y24, y28);
    y12 = _mm256_srli_epi64(y25, 51);
    y25 = _mm256_and_si256(y25, y28);
    y13 = _mm256_srli_epi64(y26, 51);
    y26 = _mm256_and_si256(y26, y28);
    y14 = _mm256_srli_epi64(y27, 51);
    y27 = _mm256_and_si256(y27, y28);
    y23 = _mm256_madd52lo_epu64(y23, y14, y31);
    y24 = _mm256_add_epi64(y24, y10);
    y25 = _mm256_add_epi64(y25, y11);
    y26 = _mm256_add_epi64(y26, y12);
    y27 = _mm256_add_epi64(y27, y13);
    y18 = _mm256_set1_epi64x((long long)WC_L64(rsp, 184));
    y19 = _mm256_set1_epi64x((long long)WC_L64(rsp, 216));
    y20 = _mm256_set1_epi64x((long long)WC_L64(rsp, 248));
    y21 = _mm256_set1_epi64x((long long)WC_L64(rsp, 280));
    y22 = _mm256_set1_epi64x((long long)WC_L64(rsp, 312));
    y18 = _mm256_mask_blend_epi64(k4, y18, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 0)));
    y19 = _mm256_mask_blend_epi64(k4, y19, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 32)));
    y20 = _mm256_mask_blend_epi64(k4, y20, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 64)));
    y21 = _mm256_mask_blend_epi64(k4, y21, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 96)));
    y22 = _mm256_mask_blend_epi64(k4, y22, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 128)));
    /* [-, E.H, -, x1.T] = U3 * V3 */
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_slli_epi64(y5, 4);
    y10 = _mm256_slli_epi64(y5, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y5);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_slli_epi64(y6, 4);
    y10 = _mm256_slli_epi64(y6, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y6);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_slli_epi64(y7, 4);
    y10 = _mm256_slli_epi64(y7, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y7);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_slli_epi64(y8, 4);
    y10 = _mm256_slli_epi64(y8, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y8);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_slli_epi64(y17, 4);
    y10 = _mm256_slli_epi64(y17, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y17);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* [x2, z2, x3, z3] = [AA.BB, E.H, FF, x1.T] */
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 320));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 352));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 384));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 416));
    y4 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 448));
    y18 = _mm256_mask_blend_epi64(k2, y18, y0);
    y19 = _mm256_mask_blend_epi64(k2, y19, y1);
    y20 = _mm256_mask_blend_epi64(k2, y20, y2);
    y21 = _mm256_mask_blend_epi64(k2, y21, y3);
    y22 = _mm256_mask_blend_epi64(k2, y22, y4);
    rdx = (word64)(WC_L64(rsp, 704));
    rdx = (word64)(rdx - 1);
    if ((sword64)(rdx) >= (sword64)(0)) {
        goto L_curve25519_avx512_ifma_bits;
    }
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 480), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 512), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 544), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 576), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 608), y22);
    /* Convert to 4 x 64-bit field elements */
    r13 = (word64)(0x7ffffffffffff);
    rdx = (word64)(WC_L64(rsp, 480));
    rax = (word64)(WC_L64(rsp, 512));
    r8 = (word64)(WC_L64(rsp, 544));
    r9 = (word64)(WC_L64(rsp, 576));
    r10 = (word64)(WC_L64(rsp, 608));
    r11 = (word64)(rdx);
    r11 = (word64)(r11 >> 51);
    rdx = (word64)(rdx & r13);
    rax = (word64)(rax + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 >> 51);
    rax = (word64)(rax & r13);
    r8 = (word64)(r8 + r11);
    r11 = (word64)(r8);
    r11 = (word64)(r11 >> 51);
    r8 = (word64)(r8 & r13);
    r9 = (word64)(r9 + r11);
    r11 = (word64)(r9);
    r11 = (word64)(r11 >> 51);
    r9 = (word64)(r9 & r13);
    r10 = (word64)(r10 + r11);
    r11 = (word64)(r10);
    r11 = (word64)(r11 >> 51);
    r10 = (word64)(r10 & r13);
    r11 = (word64)(r11 * 19);
    rdx = (word64)(rdx + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 << 51);
    r12 = (word64)(rax);
    r12 = (word64)(r12 >> 13);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rsp, 640) = (word64)(rdx);
    r11 = (word64)(r8);
    r11 = (word64)(r11 << 38);
    rdx = (word64)(r8);
    rdx = (word64)(rdx >> 26);
    cf = _addcarry_u64(0, r12, r11, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    WC_S64(rsp, 648) = (word64)(r12);
    r11 = (word64)(r9);
    r11 = (word64)(r11 << 25);
    r12 = (word64)(r9);
    r12 = (word64)(r12 >> 39);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rsp, 656) = (word64)(rdx);
    r11 = (word64)(r10);
    r11 = (word64)(r11 << 12);
    r12 = (word64)(r12 + r11);
    WC_S64(rsp, 664) = (word64)(r12);
    rdx = (word64)(WC_L64(rsp, 488));
    rax = (word64)(WC_L64(rsp, 520));
    r8 = (word64)(WC_L64(rsp, 552));
    r9 = (word64)(WC_L64(rsp, 584));
    r10 = (word64)(WC_L64(rsp, 616));
    r11 = (word64)(rdx);
    r11 = (word64)(r11 >> 51);
    rdx = (word64)(rdx & r13);
    rax = (word64)(rax + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 >> 51);
    rax = (word64)(rax & r13);
    r8 = (word64)(r8 + r11);
    r11 = (word64)(r8);
    r11 = (word64)(r11 >> 51);
    r8 = (word64)(r8 & r13);
    r9 = (word64)(r9 + r11);
    r11 = (word64)(r9);
    r11 = (word64)(r11 >> 51);
    r9 = (word64)(r9 & r13);
    r10 = (word64)(r10 + r11);
    r11 = (word64)(r10);
    r11 = (word64)(r11 >> 51);
    r10 = (word64)(r10 & r13);
    r11 = (word64)(r11 * 19);
    rdx = (word64)(rdx + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 << 51);
    r12 = (word64)(rax);
    r12 = (word64)(r12 >> 13);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rsp, 672) = (word64)(rdx);
    r11 = (word64)(r8);
    r11 = (word64)(r11 << 38);
    rdx = (word64)(r8);
    rdx = (word64)(rdx >> 26);
    cf = _addcarry_u64(0, r12, r11, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    WC_S64(rsp, 680) = (word64)(r12);
    r11 = (word64)(r9);
    r11 = (word64)(r11 << 25);
    r12 = (word64)(r9);
    r12 = (word64)(r12 >> 39);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rsp, 688) = (word64)(rdx);
    r11 = (word64)(r10);
    r11 = (word64)(r11 << 12);
    r12 = (word64)(r12 + r11);
    WC_S64(rsp, 696) = (word64)(r12);
    /* z2 = 1 / z2 */
    rdi = (word64)(rsp + 672);
    rsi = (word64)(rsp + 672);
    (void)fe_invert_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    /* x2 = x2 * z2 */
    rdi = (word64)(rsp + 640);
    rsi = (word64)(rsp + 640);
    rdx = (word64)(rsp + 672);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    /* Store fully reduced result */
    rdi = (word64)(WC_L64(rsp, 712));
    rsi = (word64)(rsp + 640);
    (void)fe_tobytes((unsigned char*)(size_t)rdi, (void*)(size_t)rsi);
    rax = (word64)(0);
    return (int)(word32)rax;
}

#if defined(WOLFSSL_CURVE25519_NOT_USE_ED25519)
WC_X64I_TARGET("avx512f,avx512vl,avx512ifma,avx512dq")
WOLFSSL_LOCAL int curve25519_base_avx512_ifma_dq(byte* r, byte* n)
{
    word64 rdi, rsi, rsp, r13, r10, r11, r8, rdx, rcx = 0, rax = 0, r9 = 0,
           r12 = 0;
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y4 = _mm256_setzero_si256(), y5 = _mm256_setzero_si256(),
            y6 = _mm256_setzero_si256(), y7 = _mm256_setzero_si256(),
            y8 = _mm256_setzero_si256(), y9 = _mm256_setzero_si256(),
            y10 = _mm256_setzero_si256(), y11 = _mm256_setzero_si256(),
            y12 = _mm256_setzero_si256(), y13 = _mm256_setzero_si256(),
            y14 = _mm256_setzero_si256(), y15 = _mm256_setzero_si256(),
            y16 = _mm256_setzero_si256(), y17 = _mm256_setzero_si256(), y18,
            y19, y20, y21, y22, y23 = _mm256_setzero_si256(),
            y24 = _mm256_setzero_si256(), y25 = _mm256_setzero_si256(),
            y26 = _mm256_setzero_si256(), y27 = _mm256_setzero_si256(), y28,
            y29, y30, y31;
    XALIGNED(32) WC_X64I_SLOT stk[92];
    __mmask16 k1, k2, k3, k4, k5, k7, k6;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)n;

    rsp = (word64)(size_t)stk + 736;
    rsp = (word64)(rsp - 736);
    WC_S64(rsp, 712) = (word64)(rdi);
    r13 = (word64)(0x7ffffffffffff);
    r10 = (word64)(9);
    WC_S64(rsp, 0) = (word64)(r10);
    WC_S64(rsp, 8) = (word64)(r10);
    WC_S64(rsp, 16) = (word64)(r10);
    WC_S64(rsp, 24) = (word64)(r10);
    WC_S64(rsp, 480) = (word64)(1);
    WC_S64(rsp, 488) = (word64)(0);
    WC_S64(rsp, 496) = (word64)(r10);
    WC_S64(rsp, 504) = (word64)(1);
    r10 = (word64)(0);
    WC_S64(rsp, 32) = (word64)(r10);
    WC_S64(rsp, 40) = (word64)(r10);
    WC_S64(rsp, 48) = (word64)(r10);
    WC_S64(rsp, 56) = (word64)(r10);
    WC_S64(rsp, 512) = (word64)(0);
    WC_S64(rsp, 520) = (word64)(0);
    WC_S64(rsp, 528) = (word64)(r10);
    WC_S64(rsp, 536) = (word64)(0);
    WC_S64(rsp, 64) = (word64)(r10);
    WC_S64(rsp, 72) = (word64)(r10);
    WC_S64(rsp, 80) = (word64)(r10);
    WC_S64(rsp, 88) = (word64)(r10);
    WC_S64(rsp, 544) = (word64)(0);
    WC_S64(rsp, 552) = (word64)(0);
    WC_S64(rsp, 560) = (word64)(r10);
    WC_S64(rsp, 568) = (word64)(0);
    WC_S64(rsp, 96) = (word64)(r10);
    WC_S64(rsp, 104) = (word64)(r10);
    WC_S64(rsp, 112) = (word64)(r10);
    WC_S64(rsp, 120) = (word64)(r10);
    WC_S64(rsp, 576) = (word64)(0);
    WC_S64(rsp, 584) = (word64)(0);
    WC_S64(rsp, 592) = (word64)(r10);
    WC_S64(rsp, 600) = (word64)(0);
    WC_S64(rsp, 128) = (word64)(r10);
    WC_S64(rsp, 136) = (word64)(r10);
    WC_S64(rsp, 144) = (word64)(r10);
    WC_S64(rsp, 152) = (word64)(r10);
    WC_S64(rsp, 608) = (word64)(0);
    WC_S64(rsp, 616) = (word64)(0);
    WC_S64(rsp, 624) = (word64)(r10);
    WC_S64(rsp, 632) = (word64)(0);
    r11 = (word64)((word64)(size_t)L_x25519_ifma_consts);
    y28 = _mm256_set1_epi64x((long long)WC_L64(r11, 0));
    y29 = _mm256_set1_epi64x((long long)WC_L64(r11, 8));
    y30 = _mm256_set1_epi64x((long long)WC_L64(r11, 16));
    y31 = _mm256_set1_epi64x((long long)WC_L64(r11, 24));
    r10 = (word32)(0xa);
    k1 = (__mmask16)(word32)r10;
    r10 = (word32)(5);
    k2 = (__mmask16)(word32)r10;
    r10 = (word32)(4);
    k3 = (__mmask16)(word32)r10;
    r10 = (word32)(8);
    k4 = (__mmask16)(word32)r10;
    r10 = (word32)(2);
    k5 = (__mmask16)(word32)r10;
    r10 = (word32)(6);
    k7 = (__mmask16)(word32)r10;
    y18 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 480));
    y19 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 512));
    y20 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 544));
    y21 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 576));
    y22 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 608));
    r8 = (word64)(0);
    rdx = (word64)(0xfe);
L_curve25519_base_avx512_ifma_dq_bits:
    /* Conditionally swap (x2, z2) with (x3, z3) */
    WC_S64(rsp, 704) = (word64)(rdx);
    rcx = (word64)(rdx);
    rcx = (word64)(rcx & 0x3f);
    rdx = (word64)(rdx >> 6);
    rax = (word64)(WC_L64(rsi, rdx * 8));
    rax = (word64)(rax >> ((byte)rcx & 63));
    rax = (word64)(rax & 1);
    r9 = (word64)(rax);
    r8 = (word64)(r8 ^ rax);
    r8 = (word64)(0 - r8);
    r8 = (word64)(r8 & 0xf);
    k6 = (__mmask16)(word32)r8;
    r8 = (word64)(r9);
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_permute4x64_epi64(y18, 0x4e));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_permute4x64_epi64(y19, 0x4e));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_permute4x64_epi64(y20, 0x4e));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_permute4x64_epi64(y21, 0x4e));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_permute4x64_epi64(y22, 0x4e));
    /* A = x2 + z2, B = x2 - z2, C = x3 + z3, D = x3 - z3 */
    y0 = _mm256_permute4x64_epi64(y18, 0xb1);
    y1 = _mm256_permute4x64_epi64(y19, 0xb1);
    y2 = _mm256_permute4x64_epi64(y20, 0xb1);
    y3 = _mm256_permute4x64_epi64(y21, 0xb1);
    y4 = _mm256_permute4x64_epi64(y22, 0xb1);
    y23 = _mm256_add_epi64(y0, y18);
    y24 = _mm256_add_epi64(y1, y19);
    y25 = _mm256_add_epi64(y2, y20);
    y26 = _mm256_add_epi64(y3, y21);
    y27 = _mm256_add_epi64(y4, y22);
    y0 = _mm256_mask_blend_epi64(k1, y0, _mm256_add_epi64(y0, y29));
    y1 = _mm256_mask_blend_epi64(k1, y1, _mm256_add_epi64(y1, y30));
    y2 = _mm256_mask_blend_epi64(k1, y2, _mm256_add_epi64(y2, y30));
    y3 = _mm256_mask_blend_epi64(k1, y3, _mm256_add_epi64(y3, y30));
    y4 = _mm256_mask_blend_epi64(k1, y4, _mm256_add_epi64(y4, y30));
    y23 = _mm256_mask_blend_epi64(k1, y23, _mm256_sub_epi64(y0, y18));
    y24 = _mm256_mask_blend_epi64(k1, y24, _mm256_sub_epi64(y1, y19));
    y25 = _mm256_mask_blend_epi64(k1, y25, _mm256_sub_epi64(y2, y20));
    y26 = _mm256_mask_blend_epi64(k1, y26, _mm256_sub_epi64(y3, y21));
    y27 = _mm256_mask_blend_epi64(k1, y27, _mm256_sub_epi64(y4, y22));
    y5 = _mm256_srli_epi64(y23, 51);
    y23 = _mm256_and_si256(y23, y28);
    y6 = _mm256_srli_epi64(y24, 51);
    y24 = _mm256_and_si256(y24, y28);
    y7 = _mm256_srli_epi64(y25, 51);
    y25 = _mm256_and_si256(y25, y28);
    y8 = _mm256_srli_epi64(y26, 51);
    y26 = _mm256_and_si256(y26, y28);
    y9 = _mm256_srli_epi64(y27, 51);
    y27 = _mm256_and_si256(y27, y28);
    y23 = _mm256_madd52lo_epu64(y23, y9, y31);
    y24 = _mm256_add_epi64(y24, y5);
    y25 = _mm256_add_epi64(y25, y6);
    y26 = _mm256_add_epi64(y26, y7);
    y27 = _mm256_add_epi64(y27, y8);
    /* [AA, BB, CB, DA] = [A, B, C, D] * [A, B, B, A] */
    y18 = _mm256_permute4x64_epi64(y23, 0x14);
    y19 = _mm256_permute4x64_epi64(y24, 0x14);
    y20 = _mm256_permute4x64_epi64(y25, 0x14);
    y21 = _mm256_permute4x64_epi64(y26, 0x14);
    y22 = _mm256_permute4x64_epi64(y27, 0x14);
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_mullo_epi64(y5, y31);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_mullo_epi64(y6, y31);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_mullo_epi64(y7, y31);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_mullo_epi64(y8, y31);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_mullo_epi64(y17, y31);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* U = [AA, DA-CB, DA+CB, AA-BB], V = [BB, DA-CB, DA+CB, a24] */
    y23 = _mm256_permute4x64_epi64(y18, 0x69);
    y24 = _mm256_permute4x64_epi64(y19, 0x69);
    y25 = _mm256_permute4x64_epi64(y20, 0x69);
    y26 = _mm256_permute4x64_epi64(y21, 0x69);
    y27 = _mm256_permute4x64_epi64(y22, 0x69);
    y18 = _mm256_permute4x64_epi64(y18, 0x3c);
    y19 = _mm256_permute4x64_epi64(y19, 0x3c);
    y20 = _mm256_permute4x64_epi64(y20, 0x3c);
    y21 = _mm256_permute4x64_epi64(y21, 0x3c);
    y22 = _mm256_permute4x64_epi64(y22, 0x3c);
    y18 = _mm256_mask_blend_epi64(k3, y18, _mm256_add_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k3, y19, _mm256_add_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k3, y20, _mm256_add_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k3, y21, _mm256_add_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k3, y22, _mm256_add_epi64(y22, y27));
    y18 = _mm256_mask_blend_epi64(k1, y18, _mm256_add_epi64(y18, y29));
    y19 = _mm256_mask_blend_epi64(k1, y19, _mm256_add_epi64(y19, y30));
    y20 = _mm256_mask_blend_epi64(k1, y20, _mm256_add_epi64(y20, y30));
    y21 = _mm256_mask_blend_epi64(k1, y21, _mm256_add_epi64(y21, y30));
    y22 = _mm256_mask_blend_epi64(k1, y22, _mm256_add_epi64(y22, y30));
    y18 = _mm256_mask_blend_epi64(k1, y18, _mm256_sub_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k1, y19, _mm256_sub_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k1, y20, _mm256_sub_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k1, y21, _mm256_sub_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k1, y22, _mm256_sub_epi64(y22, y27));
    y0 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y1 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y2 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y3 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y4 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y4, y31);
    y19 = _mm256_add_epi64(y19, y0);
    y20 = _mm256_add_epi64(y20, y1);
    y21 = _mm256_add_epi64(y21, y2);
    y22 = _mm256_add_epi64(y22, y3);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 160), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 192), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 224), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 256), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 288), y22);
    y23 = _mm256_mask_blend_epi64(k7, y23, y18);
    y24 = _mm256_mask_blend_epi64(k7, y24, y19);
    y25 = _mm256_mask_blend_epi64(k7, y25, y20);
    y26 = _mm256_mask_blend_epi64(k7, y26, y21);
    y27 = _mm256_mask_blend_epi64(k7, y27, y22);
    y23 = _mm256_mask_blend_epi64(k4, y23, _mm256_set1_epi64x((long long)WC_L64(
        r11, 32)));
    y24 = _mm256_mask_blend_epi64(k4, y24, _mm256_setzero_si256());
    y25 = _mm256_mask_blend_epi64(k4, y25, _mm256_setzero_si256());
    y26 = _mm256_mask_blend_epi64(k4, y26, _mm256_setzero_si256());
    y27 = _mm256_mask_blend_epi64(k4, y27, _mm256_setzero_si256());
    /* [AA.BB, GG, FF, a24.E] = U * V */
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_mullo_epi64(y5, y31);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_mullo_epi64(y6, y31);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_mullo_epi64(y7, y31);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_mullo_epi64(y8, y31);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_mullo_epi64(y17, y31);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* U3 = [E, E, E, x1], V3 = [aE, AA + a24.E, T, T] */
    y23 = _mm256_permute4x64_epi64(y18, 0x5f);
    y24 = _mm256_permute4x64_epi64(y19, 0x5f);
    y25 = _mm256_permute4x64_epi64(y20, 0x5f);
    y26 = _mm256_permute4x64_epi64(y21, 0x5f);
    y27 = _mm256_permute4x64_epi64(y22, 0x5f);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 320), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 352), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 384), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 416), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 448), y22);
    y5 = _mm256_set1_epi64x((long long)WC_L64(rsp, 160));
    y6 = _mm256_set1_epi64x((long long)WC_L64(rsp, 192));
    y7 = _mm256_set1_epi64x((long long)WC_L64(rsp, 224));
    y8 = _mm256_set1_epi64x((long long)WC_L64(rsp, 256));
    y9 = _mm256_set1_epi64x((long long)WC_L64(rsp, 288));
    y23 = _mm256_mask_blend_epi64(k5, y23, _mm256_add_epi64(y23, y5));
    y24 = _mm256_mask_blend_epi64(k5, y24, _mm256_add_epi64(y24, y6));
    y25 = _mm256_mask_blend_epi64(k5, y25, _mm256_add_epi64(y25, y7));
    y26 = _mm256_mask_blend_epi64(k5, y26, _mm256_add_epi64(y26, y8));
    y27 = _mm256_mask_blend_epi64(k5, y27, _mm256_add_epi64(y27, y9));
    y10 = _mm256_srli_epi64(y23, 51);
    y23 = _mm256_and_si256(y23, y28);
    y11 = _mm256_srli_epi64(y24, 51);
    y24 = _mm256_and_si256(y24, y28);
    y12 = _mm256_srli_epi64(y25, 51);
    y25 = _mm256_and_si256(y25, y28);
    y13 = _mm256_srli_epi64(y26, 51);
    y26 = _mm256_and_si256(y26, y28);
    y14 = _mm256_srli_epi64(y27, 51);
    y27 = _mm256_and_si256(y27, y28);
    y23 = _mm256_madd52lo_epu64(y23, y14, y31);
    y24 = _mm256_add_epi64(y24, y10);
    y25 = _mm256_add_epi64(y25, y11);
    y26 = _mm256_add_epi64(y26, y12);
    y27 = _mm256_add_epi64(y27, y13);
    y18 = _mm256_set1_epi64x((long long)WC_L64(rsp, 184));
    y19 = _mm256_set1_epi64x((long long)WC_L64(rsp, 216));
    y20 = _mm256_set1_epi64x((long long)WC_L64(rsp, 248));
    y21 = _mm256_set1_epi64x((long long)WC_L64(rsp, 280));
    y22 = _mm256_set1_epi64x((long long)WC_L64(rsp, 312));
    y18 = _mm256_mask_blend_epi64(k4, y18, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 0)));
    y19 = _mm256_mask_blend_epi64(k4, y19, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 32)));
    y20 = _mm256_mask_blend_epi64(k4, y20, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 64)));
    y21 = _mm256_mask_blend_epi64(k4, y21, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 96)));
    y22 = _mm256_mask_blend_epi64(k4, y22, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 128)));
    /* [-, E.H, -, x1.T] = U3 * V3 */
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_mullo_epi64(y5, y31);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_mullo_epi64(y6, y31);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_mullo_epi64(y7, y31);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_mullo_epi64(y8, y31);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_mullo_epi64(y17, y31);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* [x2, z2, x3, z3] = [AA.BB, E.H, FF, x1.T] */
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 320));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 352));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 384));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 416));
    y4 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 448));
    y18 = _mm256_mask_blend_epi64(k2, y18, y0);
    y19 = _mm256_mask_blend_epi64(k2, y19, y1);
    y20 = _mm256_mask_blend_epi64(k2, y20, y2);
    y21 = _mm256_mask_blend_epi64(k2, y21, y3);
    y22 = _mm256_mask_blend_epi64(k2, y22, y4);
    rdx = (word64)(WC_L64(rsp, 704));
    rdx = (word64)(rdx - 1);
    if ((sword64)(rdx) >= (sword64)(0)) {
        goto L_curve25519_base_avx512_ifma_dq_bits;
    }
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 480), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 512), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 544), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 576), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 608), y22);
    /* Convert to 4 x 64-bit field elements */
    r13 = (word64)(0x7ffffffffffff);
    rdx = (word64)(WC_L64(rsp, 480));
    rax = (word64)(WC_L64(rsp, 512));
    r8 = (word64)(WC_L64(rsp, 544));
    r9 = (word64)(WC_L64(rsp, 576));
    r10 = (word64)(WC_L64(rsp, 608));
    r11 = (word64)(rdx);
    r11 = (word64)(r11 >> 51);
    rdx = (word64)(rdx & r13);
    rax = (word64)(rax + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 >> 51);
    rax = (word64)(rax & r13);
    r8 = (word64)(r8 + r11);
    r11 = (word64)(r8);
    r11 = (word64)(r11 >> 51);
    r8 = (word64)(r8 & r13);
    r9 = (word64)(r9 + r11);
    r11 = (word64)(r9);
    r11 = (word64)(r11 >> 51);
    r9 = (word64)(r9 & r13);
    r10 = (word64)(r10 + r11);
    r11 = (word64)(r10);
    r11 = (word64)(r11 >> 51);
    r10 = (word64)(r10 & r13);
    r11 = (word64)(r11 * 19);
    rdx = (word64)(rdx + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 << 51);
    r12 = (word64)(rax);
    r12 = (word64)(r12 >> 13);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rsp, 640) = (word64)(rdx);
    r11 = (word64)(r8);
    r11 = (word64)(r11 << 38);
    rdx = (word64)(r8);
    rdx = (word64)(rdx >> 26);
    cf = _addcarry_u64(0, r12, r11, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    WC_S64(rsp, 648) = (word64)(r12);
    r11 = (word64)(r9);
    r11 = (word64)(r11 << 25);
    r12 = (word64)(r9);
    r12 = (word64)(r12 >> 39);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rsp, 656) = (word64)(rdx);
    r11 = (word64)(r10);
    r11 = (word64)(r11 << 12);
    r12 = (word64)(r12 + r11);
    WC_S64(rsp, 664) = (word64)(r12);
    rdx = (word64)(WC_L64(rsp, 488));
    rax = (word64)(WC_L64(rsp, 520));
    r8 = (word64)(WC_L64(rsp, 552));
    r9 = (word64)(WC_L64(rsp, 584));
    r10 = (word64)(WC_L64(rsp, 616));
    r11 = (word64)(rdx);
    r11 = (word64)(r11 >> 51);
    rdx = (word64)(rdx & r13);
    rax = (word64)(rax + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 >> 51);
    rax = (word64)(rax & r13);
    r8 = (word64)(r8 + r11);
    r11 = (word64)(r8);
    r11 = (word64)(r11 >> 51);
    r8 = (word64)(r8 & r13);
    r9 = (word64)(r9 + r11);
    r11 = (word64)(r9);
    r11 = (word64)(r11 >> 51);
    r9 = (word64)(r9 & r13);
    r10 = (word64)(r10 + r11);
    r11 = (word64)(r10);
    r11 = (word64)(r11 >> 51);
    r10 = (word64)(r10 & r13);
    r11 = (word64)(r11 * 19);
    rdx = (word64)(rdx + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 << 51);
    r12 = (word64)(rax);
    r12 = (word64)(r12 >> 13);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rsp, 672) = (word64)(rdx);
    r11 = (word64)(r8);
    r11 = (word64)(r11 << 38);
    rdx = (word64)(r8);
    rdx = (word64)(rdx >> 26);
    cf = _addcarry_u64(0, r12, r11, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    WC_S64(rsp, 680) = (word64)(r12);
    r11 = (word64)(r9);
    r11 = (word64)(r11 << 25);
    r12 = (word64)(r9);
    r12 = (word64)(r12 >> 39);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rsp, 688) = (word64)(rdx);
    r11 = (word64)(r10);
    r11 = (word64)(r11 << 12);
    r12 = (word64)(r12 + r11);
    WC_S64(rsp, 696) = (word64)(r12);
    /* z2 = 1 / z2 */
    rdi = (word64)(rsp + 672);
    rsi = (word64)(rsp + 672);
    (void)fe_invert_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    /* x2 = x2 * z2 */
    rdi = (word64)(rsp + 640);
    rsi = (word64)(rsp + 640);
    rdx = (word64)(rsp + 672);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    /* Store fully reduced result */
    rdi = (word64)(WC_L64(rsp, 712));
    rsi = (word64)(rsp + 640);
    (void)fe_tobytes((unsigned char*)(size_t)rdi, (void*)(size_t)rsi);
    rax = (word64)(0);
    return (int)(word32)rax;
}

#endif /* WOLFSSL_CURVE25519_NOT_USE_ED25519 */
WC_X64I_TARGET("avx512f,avx512vl,avx512ifma,avx512dq")
WOLFSSL_LOCAL int curve25519_avx512_ifma_dq(byte* r, byte* n, byte* a)
{
    word64 rdi, rsi, r15, rsp, r13, rdx, rax, r8, r9, r10, r12, r11, rcx = 0;
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y4 = _mm256_setzero_si256(), y5 = _mm256_setzero_si256(),
            y6 = _mm256_setzero_si256(), y7 = _mm256_setzero_si256(),
            y8 = _mm256_setzero_si256(), y9 = _mm256_setzero_si256(),
            y10 = _mm256_setzero_si256(), y11 = _mm256_setzero_si256(),
            y12 = _mm256_setzero_si256(), y13 = _mm256_setzero_si256(),
            y14 = _mm256_setzero_si256(), y15 = _mm256_setzero_si256(),
            y16 = _mm256_setzero_si256(), y17 = _mm256_setzero_si256(), y18,
            y19, y20, y21, y22, y23 = _mm256_setzero_si256(),
            y24 = _mm256_setzero_si256(), y25 = _mm256_setzero_si256(),
            y26 = _mm256_setzero_si256(), y27 = _mm256_setzero_si256(), y28,
            y29, y30, y31;
    XALIGNED(32) WC_X64I_SLOT stk[92];
    __mmask16 k1, k2, k3, k4, k5, k7, k6;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)n;
    r15 = (word64)(size_t)a;

    rsp = (word64)(size_t)stk + 736;
    rsp = (word64)(rsp - 736);
    WC_S64(rsp, 712) = (word64)(rdi);
    r13 = (word64)(0x7ffffffffffff);
    rdx = (word64)(WC_L64(r15, 0));
    rax = (word64)(WC_L64(r15, 8));
    r8 = (word64)(WC_L64(r15, 16));
    r9 = (word64)(WC_L64(r15, 24));
    r10 = (word64)(r9);
    r10 = (word64)(r10 >> 63);
    r10 = (word64)(r10 * 19);
    r9 = (word64)(r9 << 1);
    r9 = (word64)(r9 >> 1);
    r12 = (word64)(rdx);
    r12 = (word64)(r12 & r13);
    r12 = (word64)(r12 + r10);
    WC_S64(rsp, 0) = (word64)(r12);
    WC_S64(rsp, 8) = (word64)(r12);
    WC_S64(rsp, 16) = (word64)(r12);
    WC_S64(rsp, 24) = (word64)(r12);
    WC_S64(rsp, 480) = (word64)(1);
    WC_S64(rsp, 488) = (word64)(0);
    WC_S64(rsp, 496) = (word64)(r12);
    WC_S64(rsp, 504) = (word64)(1);
    rdx = (word64)((rdx >> 51) | (rax << 13));
    r10 = (word64)(rdx);
    r10 = (word64)(r10 & r13);
    WC_S64(rsp, 32) = (word64)(r10);
    WC_S64(rsp, 40) = (word64)(r10);
    WC_S64(rsp, 48) = (word64)(r10);
    WC_S64(rsp, 56) = (word64)(r10);
    WC_S64(rsp, 512) = (word64)(0);
    WC_S64(rsp, 520) = (word64)(0);
    WC_S64(rsp, 528) = (word64)(r10);
    WC_S64(rsp, 536) = (word64)(0);
    rax = (word64)((rax >> 38) | (r8 << 26));
    r10 = (word64)(rax);
    r10 = (word64)(r10 & r13);
    WC_S64(rsp, 64) = (word64)(r10);
    WC_S64(rsp, 72) = (word64)(r10);
    WC_S64(rsp, 80) = (word64)(r10);
    WC_S64(rsp, 88) = (word64)(r10);
    WC_S64(rsp, 544) = (word64)(0);
    WC_S64(rsp, 552) = (word64)(0);
    WC_S64(rsp, 560) = (word64)(r10);
    WC_S64(rsp, 568) = (word64)(0);
    r8 = (word64)((r8 >> 25) | (r9 << 39));
    r10 = (word64)(r8);
    r10 = (word64)(r10 & r13);
    WC_S64(rsp, 96) = (word64)(r10);
    WC_S64(rsp, 104) = (word64)(r10);
    WC_S64(rsp, 112) = (word64)(r10);
    WC_S64(rsp, 120) = (word64)(r10);
    WC_S64(rsp, 576) = (word64)(0);
    WC_S64(rsp, 584) = (word64)(0);
    WC_S64(rsp, 592) = (word64)(r10);
    WC_S64(rsp, 600) = (word64)(0);
    r9 = (word64)(r9 >> 12);
    WC_S64(rsp, 128) = (word64)(r9);
    WC_S64(rsp, 136) = (word64)(r9);
    WC_S64(rsp, 144) = (word64)(r9);
    WC_S64(rsp, 152) = (word64)(r9);
    WC_S64(rsp, 608) = (word64)(0);
    WC_S64(rsp, 616) = (word64)(0);
    WC_S64(rsp, 624) = (word64)(r9);
    WC_S64(rsp, 632) = (word64)(0);
    r11 = (word64)((word64)(size_t)L_x25519_ifma_consts);
    y28 = _mm256_set1_epi64x((long long)WC_L64(r11, 0));
    y29 = _mm256_set1_epi64x((long long)WC_L64(r11, 8));
    y30 = _mm256_set1_epi64x((long long)WC_L64(r11, 16));
    y31 = _mm256_set1_epi64x((long long)WC_L64(r11, 24));
    r10 = (word32)(0xa);
    k1 = (__mmask16)(word32)r10;
    r10 = (word32)(5);
    k2 = (__mmask16)(word32)r10;
    r10 = (word32)(4);
    k3 = (__mmask16)(word32)r10;
    r10 = (word32)(8);
    k4 = (__mmask16)(word32)r10;
    r10 = (word32)(2);
    k5 = (__mmask16)(word32)r10;
    r10 = (word32)(6);
    k7 = (__mmask16)(word32)r10;
    y18 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 480));
    y19 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 512));
    y20 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 544));
    y21 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 576));
    y22 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 608));
    r8 = (word64)(0);
    rdx = (word64)(0xfe);
L_curve25519_avx512_ifma_dq_bits:
    /* Conditionally swap (x2, z2) with (x3, z3) */
    WC_S64(rsp, 704) = (word64)(rdx);
    rcx = (word64)(rdx);
    rcx = (word64)(rcx & 0x3f);
    rdx = (word64)(rdx >> 6);
    rax = (word64)(WC_L64(rsi, rdx * 8));
    rax = (word64)(rax >> ((byte)rcx & 63));
    rax = (word64)(rax & 1);
    r9 = (word64)(rax);
    r8 = (word64)(r8 ^ rax);
    r8 = (word64)(0 - r8);
    r8 = (word64)(r8 & 0xf);
    k6 = (__mmask16)(word32)r8;
    r8 = (word64)(r9);
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_permute4x64_epi64(y18, 0x4e));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_permute4x64_epi64(y19, 0x4e));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_permute4x64_epi64(y20, 0x4e));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_permute4x64_epi64(y21, 0x4e));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_permute4x64_epi64(y22, 0x4e));
    /* A = x2 + z2, B = x2 - z2, C = x3 + z3, D = x3 - z3 */
    y0 = _mm256_permute4x64_epi64(y18, 0xb1);
    y1 = _mm256_permute4x64_epi64(y19, 0xb1);
    y2 = _mm256_permute4x64_epi64(y20, 0xb1);
    y3 = _mm256_permute4x64_epi64(y21, 0xb1);
    y4 = _mm256_permute4x64_epi64(y22, 0xb1);
    y23 = _mm256_add_epi64(y0, y18);
    y24 = _mm256_add_epi64(y1, y19);
    y25 = _mm256_add_epi64(y2, y20);
    y26 = _mm256_add_epi64(y3, y21);
    y27 = _mm256_add_epi64(y4, y22);
    y0 = _mm256_mask_blend_epi64(k1, y0, _mm256_add_epi64(y0, y29));
    y1 = _mm256_mask_blend_epi64(k1, y1, _mm256_add_epi64(y1, y30));
    y2 = _mm256_mask_blend_epi64(k1, y2, _mm256_add_epi64(y2, y30));
    y3 = _mm256_mask_blend_epi64(k1, y3, _mm256_add_epi64(y3, y30));
    y4 = _mm256_mask_blend_epi64(k1, y4, _mm256_add_epi64(y4, y30));
    y23 = _mm256_mask_blend_epi64(k1, y23, _mm256_sub_epi64(y0, y18));
    y24 = _mm256_mask_blend_epi64(k1, y24, _mm256_sub_epi64(y1, y19));
    y25 = _mm256_mask_blend_epi64(k1, y25, _mm256_sub_epi64(y2, y20));
    y26 = _mm256_mask_blend_epi64(k1, y26, _mm256_sub_epi64(y3, y21));
    y27 = _mm256_mask_blend_epi64(k1, y27, _mm256_sub_epi64(y4, y22));
    y5 = _mm256_srli_epi64(y23, 51);
    y23 = _mm256_and_si256(y23, y28);
    y6 = _mm256_srli_epi64(y24, 51);
    y24 = _mm256_and_si256(y24, y28);
    y7 = _mm256_srli_epi64(y25, 51);
    y25 = _mm256_and_si256(y25, y28);
    y8 = _mm256_srli_epi64(y26, 51);
    y26 = _mm256_and_si256(y26, y28);
    y9 = _mm256_srli_epi64(y27, 51);
    y27 = _mm256_and_si256(y27, y28);
    y23 = _mm256_madd52lo_epu64(y23, y9, y31);
    y24 = _mm256_add_epi64(y24, y5);
    y25 = _mm256_add_epi64(y25, y6);
    y26 = _mm256_add_epi64(y26, y7);
    y27 = _mm256_add_epi64(y27, y8);
    /* [AA, BB, CB, DA] = [A, B, C, D] * [A, B, B, A] */
    y18 = _mm256_permute4x64_epi64(y23, 0x14);
    y19 = _mm256_permute4x64_epi64(y24, 0x14);
    y20 = _mm256_permute4x64_epi64(y25, 0x14);
    y21 = _mm256_permute4x64_epi64(y26, 0x14);
    y22 = _mm256_permute4x64_epi64(y27, 0x14);
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_mullo_epi64(y5, y31);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_mullo_epi64(y6, y31);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_mullo_epi64(y7, y31);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_mullo_epi64(y8, y31);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_mullo_epi64(y17, y31);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* U = [AA, DA-CB, DA+CB, AA-BB], V = [BB, DA-CB, DA+CB, a24] */
    y23 = _mm256_permute4x64_epi64(y18, 0x69);
    y24 = _mm256_permute4x64_epi64(y19, 0x69);
    y25 = _mm256_permute4x64_epi64(y20, 0x69);
    y26 = _mm256_permute4x64_epi64(y21, 0x69);
    y27 = _mm256_permute4x64_epi64(y22, 0x69);
    y18 = _mm256_permute4x64_epi64(y18, 0x3c);
    y19 = _mm256_permute4x64_epi64(y19, 0x3c);
    y20 = _mm256_permute4x64_epi64(y20, 0x3c);
    y21 = _mm256_permute4x64_epi64(y21, 0x3c);
    y22 = _mm256_permute4x64_epi64(y22, 0x3c);
    y18 = _mm256_mask_blend_epi64(k3, y18, _mm256_add_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k3, y19, _mm256_add_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k3, y20, _mm256_add_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k3, y21, _mm256_add_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k3, y22, _mm256_add_epi64(y22, y27));
    y18 = _mm256_mask_blend_epi64(k1, y18, _mm256_add_epi64(y18, y29));
    y19 = _mm256_mask_blend_epi64(k1, y19, _mm256_add_epi64(y19, y30));
    y20 = _mm256_mask_blend_epi64(k1, y20, _mm256_add_epi64(y20, y30));
    y21 = _mm256_mask_blend_epi64(k1, y21, _mm256_add_epi64(y21, y30));
    y22 = _mm256_mask_blend_epi64(k1, y22, _mm256_add_epi64(y22, y30));
    y18 = _mm256_mask_blend_epi64(k1, y18, _mm256_sub_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k1, y19, _mm256_sub_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k1, y20, _mm256_sub_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k1, y21, _mm256_sub_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k1, y22, _mm256_sub_epi64(y22, y27));
    y0 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y1 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y2 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y3 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y4 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y4, y31);
    y19 = _mm256_add_epi64(y19, y0);
    y20 = _mm256_add_epi64(y20, y1);
    y21 = _mm256_add_epi64(y21, y2);
    y22 = _mm256_add_epi64(y22, y3);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 160), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 192), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 224), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 256), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 288), y22);
    y23 = _mm256_mask_blend_epi64(k7, y23, y18);
    y24 = _mm256_mask_blend_epi64(k7, y24, y19);
    y25 = _mm256_mask_blend_epi64(k7, y25, y20);
    y26 = _mm256_mask_blend_epi64(k7, y26, y21);
    y27 = _mm256_mask_blend_epi64(k7, y27, y22);
    y23 = _mm256_mask_blend_epi64(k4, y23, _mm256_set1_epi64x((long long)WC_L64(
        r11, 32)));
    y24 = _mm256_mask_blend_epi64(k4, y24, _mm256_setzero_si256());
    y25 = _mm256_mask_blend_epi64(k4, y25, _mm256_setzero_si256());
    y26 = _mm256_mask_blend_epi64(k4, y26, _mm256_setzero_si256());
    y27 = _mm256_mask_blend_epi64(k4, y27, _mm256_setzero_si256());
    /* [AA.BB, GG, FF, a24.E] = U * V */
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_mullo_epi64(y5, y31);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_mullo_epi64(y6, y31);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_mullo_epi64(y7, y31);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_mullo_epi64(y8, y31);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_mullo_epi64(y17, y31);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* U3 = [E, E, E, x1], V3 = [aE, AA + a24.E, T, T] */
    y23 = _mm256_permute4x64_epi64(y18, 0x5f);
    y24 = _mm256_permute4x64_epi64(y19, 0x5f);
    y25 = _mm256_permute4x64_epi64(y20, 0x5f);
    y26 = _mm256_permute4x64_epi64(y21, 0x5f);
    y27 = _mm256_permute4x64_epi64(y22, 0x5f);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 320), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 352), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 384), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 416), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 448), y22);
    y5 = _mm256_set1_epi64x((long long)WC_L64(rsp, 160));
    y6 = _mm256_set1_epi64x((long long)WC_L64(rsp, 192));
    y7 = _mm256_set1_epi64x((long long)WC_L64(rsp, 224));
    y8 = _mm256_set1_epi64x((long long)WC_L64(rsp, 256));
    y9 = _mm256_set1_epi64x((long long)WC_L64(rsp, 288));
    y23 = _mm256_mask_blend_epi64(k5, y23, _mm256_add_epi64(y23, y5));
    y24 = _mm256_mask_blend_epi64(k5, y24, _mm256_add_epi64(y24, y6));
    y25 = _mm256_mask_blend_epi64(k5, y25, _mm256_add_epi64(y25, y7));
    y26 = _mm256_mask_blend_epi64(k5, y26, _mm256_add_epi64(y26, y8));
    y27 = _mm256_mask_blend_epi64(k5, y27, _mm256_add_epi64(y27, y9));
    y10 = _mm256_srli_epi64(y23, 51);
    y23 = _mm256_and_si256(y23, y28);
    y11 = _mm256_srli_epi64(y24, 51);
    y24 = _mm256_and_si256(y24, y28);
    y12 = _mm256_srli_epi64(y25, 51);
    y25 = _mm256_and_si256(y25, y28);
    y13 = _mm256_srli_epi64(y26, 51);
    y26 = _mm256_and_si256(y26, y28);
    y14 = _mm256_srli_epi64(y27, 51);
    y27 = _mm256_and_si256(y27, y28);
    y23 = _mm256_madd52lo_epu64(y23, y14, y31);
    y24 = _mm256_add_epi64(y24, y10);
    y25 = _mm256_add_epi64(y25, y11);
    y26 = _mm256_add_epi64(y26, y12);
    y27 = _mm256_add_epi64(y27, y13);
    y18 = _mm256_set1_epi64x((long long)WC_L64(rsp, 184));
    y19 = _mm256_set1_epi64x((long long)WC_L64(rsp, 216));
    y20 = _mm256_set1_epi64x((long long)WC_L64(rsp, 248));
    y21 = _mm256_set1_epi64x((long long)WC_L64(rsp, 280));
    y22 = _mm256_set1_epi64x((long long)WC_L64(rsp, 312));
    y18 = _mm256_mask_blend_epi64(k4, y18, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 0)));
    y19 = _mm256_mask_blend_epi64(k4, y19, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 32)));
    y20 = _mm256_mask_blend_epi64(k4, y20, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 64)));
    y21 = _mm256_mask_blend_epi64(k4, y21, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 96)));
    y22 = _mm256_mask_blend_epi64(k4, y22, _mm256_loadu_si256((
        const __m256i*)WC_PR(rsp, 128)));
    /* [-, E.H, -, x1.T] = U3 * V3 */
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_mullo_epi64(y5, y31);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_mullo_epi64(y6, y31);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_mullo_epi64(y7, y31);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_mullo_epi64(y8, y31);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_mullo_epi64(y17, y31);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* [x2, z2, x3, z3] = [AA.BB, E.H, FF, x1.T] */
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 320));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 352));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 384));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 416));
    y4 = _mm256_loadu_si256((const __m256i*)WC_PR(rsp, 448));
    y18 = _mm256_mask_blend_epi64(k2, y18, y0);
    y19 = _mm256_mask_blend_epi64(k2, y19, y1);
    y20 = _mm256_mask_blend_epi64(k2, y20, y2);
    y21 = _mm256_mask_blend_epi64(k2, y21, y3);
    y22 = _mm256_mask_blend_epi64(k2, y22, y4);
    rdx = (word64)(WC_L64(rsp, 704));
    rdx = (word64)(rdx - 1);
    if ((sword64)(rdx) >= (sword64)(0)) {
        goto L_curve25519_avx512_ifma_dq_bits;
    }
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 480), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 512), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 544), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 576), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 608), y22);
    /* Convert to 4 x 64-bit field elements */
    r13 = (word64)(0x7ffffffffffff);
    rdx = (word64)(WC_L64(rsp, 480));
    rax = (word64)(WC_L64(rsp, 512));
    r8 = (word64)(WC_L64(rsp, 544));
    r9 = (word64)(WC_L64(rsp, 576));
    r10 = (word64)(WC_L64(rsp, 608));
    r11 = (word64)(rdx);
    r11 = (word64)(r11 >> 51);
    rdx = (word64)(rdx & r13);
    rax = (word64)(rax + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 >> 51);
    rax = (word64)(rax & r13);
    r8 = (word64)(r8 + r11);
    r11 = (word64)(r8);
    r11 = (word64)(r11 >> 51);
    r8 = (word64)(r8 & r13);
    r9 = (word64)(r9 + r11);
    r11 = (word64)(r9);
    r11 = (word64)(r11 >> 51);
    r9 = (word64)(r9 & r13);
    r10 = (word64)(r10 + r11);
    r11 = (word64)(r10);
    r11 = (word64)(r11 >> 51);
    r10 = (word64)(r10 & r13);
    r11 = (word64)(r11 * 19);
    rdx = (word64)(rdx + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 << 51);
    r12 = (word64)(rax);
    r12 = (word64)(r12 >> 13);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rsp, 640) = (word64)(rdx);
    r11 = (word64)(r8);
    r11 = (word64)(r11 << 38);
    rdx = (word64)(r8);
    rdx = (word64)(rdx >> 26);
    cf = _addcarry_u64(0, r12, r11, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    WC_S64(rsp, 648) = (word64)(r12);
    r11 = (word64)(r9);
    r11 = (word64)(r11 << 25);
    r12 = (word64)(r9);
    r12 = (word64)(r12 >> 39);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rsp, 656) = (word64)(rdx);
    r11 = (word64)(r10);
    r11 = (word64)(r11 << 12);
    r12 = (word64)(r12 + r11);
    WC_S64(rsp, 664) = (word64)(r12);
    rdx = (word64)(WC_L64(rsp, 488));
    rax = (word64)(WC_L64(rsp, 520));
    r8 = (word64)(WC_L64(rsp, 552));
    r9 = (word64)(WC_L64(rsp, 584));
    r10 = (word64)(WC_L64(rsp, 616));
    r11 = (word64)(rdx);
    r11 = (word64)(r11 >> 51);
    rdx = (word64)(rdx & r13);
    rax = (word64)(rax + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 >> 51);
    rax = (word64)(rax & r13);
    r8 = (word64)(r8 + r11);
    r11 = (word64)(r8);
    r11 = (word64)(r11 >> 51);
    r8 = (word64)(r8 & r13);
    r9 = (word64)(r9 + r11);
    r11 = (word64)(r9);
    r11 = (word64)(r11 >> 51);
    r9 = (word64)(r9 & r13);
    r10 = (word64)(r10 + r11);
    r11 = (word64)(r10);
    r11 = (word64)(r11 >> 51);
    r10 = (word64)(r10 & r13);
    r11 = (word64)(r11 * 19);
    rdx = (word64)(rdx + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 << 51);
    r12 = (word64)(rax);
    r12 = (word64)(r12 >> 13);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rsp, 672) = (word64)(rdx);
    r11 = (word64)(r8);
    r11 = (word64)(r11 << 38);
    rdx = (word64)(r8);
    rdx = (word64)(rdx >> 26);
    cf = _addcarry_u64(0, r12, r11, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    WC_S64(rsp, 680) = (word64)(r12);
    r11 = (word64)(r9);
    r11 = (word64)(r11 << 25);
    r12 = (word64)(r9);
    r12 = (word64)(r12 >> 39);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rsp, 688) = (word64)(rdx);
    r11 = (word64)(r10);
    r11 = (word64)(r11 << 12);
    r12 = (word64)(r12 + r11);
    WC_S64(rsp, 696) = (word64)(r12);
    /* z2 = 1 / z2 */
    rdi = (word64)(rsp + 672);
    rsi = (word64)(rsp + 672);
    (void)fe_invert_avx2((void*)(size_t)rdi, (void*)(size_t)rsi);
    /* x2 = x2 * z2 */
    rdi = (word64)(rsp + 640);
    rsi = (word64)(rsp + 640);
    rdx = (word64)(rsp + 672);
    (void)fe_mul_avx2((void*)(size_t)rdi, (void*)(size_t)rsi, (void*)(
        size_t)rdx);
    /* Store fully reduced result */
    rdi = (word64)(WC_L64(rsp, 712));
    rsi = (word64)(rsp + 640);
    (void)fe_tobytes((unsigned char*)(size_t)rdi, (void*)(size_t)rsi);
    rax = (word64)(0);
    return (int)(word32)rax;
}

#ifdef HAVE_ED25519
XALIGNED(32) static const word64 L_ge_ifma_consts[] WC_X64I_UNUSED = {
    0x0007ffffffffffffULL, 0x000fffffffffffdaULL,
    0x000ffffffffffffeULL, 0x0000000000000013ULL,
    0x0000000000000001ULL, 0x0000000000000001ULL,
    0x00069b9426b2f159ULL, 0x0000000000000001ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x00035050762add7aULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0003cf44c0038052ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0006738cc7407977ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0002406d9dc56dffULL, 0x0000000000000000ULL,
};

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WC_X64I_TARGET("avx512f,avx512vl,avx512ifma")
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL int ge_double_scalarmult_vartime_avx512_ifma(ge_p2* r,
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
    const byte* a, const ge_p3* A, const byte* b, const ge_precomp* bi,
    byte* buf)
{
    word64 rdi, rsi, r14, r15, rbx, rbp, rdx, r11, rax = 0, rcx = 0, r12 = 0,
           r8 = 0, r9 = 0, r10 = 0, r13 = 0;
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y4 = _mm256_setzero_si256(), y5 = _mm256_setzero_si256(),
            y6 = _mm256_setzero_si256(), y7 = _mm256_setzero_si256(),
            y8 = _mm256_setzero_si256(), y9 = _mm256_setzero_si256(),
            y10 = _mm256_setzero_si256(), y11 = _mm256_setzero_si256(),
            y12 = _mm256_setzero_si256(), y13 = _mm256_setzero_si256(),
            y14 = _mm256_setzero_si256(), y15 = _mm256_setzero_si256(),
            y16 = _mm256_setzero_si256(), y17 = _mm256_setzero_si256(),
            y18 = _mm256_setzero_si256(), y19 = _mm256_setzero_si256(),
            y20 = _mm256_setzero_si256(), y21 = _mm256_setzero_si256(),
            y22 = _mm256_setzero_si256(), y23 = _mm256_setzero_si256(),
            y24 = _mm256_setzero_si256(), y25 = _mm256_setzero_si256(),
            y26 = _mm256_setzero_si256(), y27 = _mm256_setzero_si256(),
            y28 = _mm256_setzero_si256(), y29 = _mm256_setzero_si256(),
            y30 = _mm256_setzero_si256(), y31 = _mm256_setzero_si256();
    __mmask16 k1, k2, k3, k4, k5, k6, k7;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)a;
    r14 = (word64)(size_t)A;
    r15 = (word64)(size_t)b;
    rbx = (word64)(size_t)bi;
    rbp = (word64)(size_t)buf;

    /* Window digits of the scalar multiplying A */
    /* One digit per bit of the scalar */
    rdx = (word64)(0);
    r11 = (word64)(0);
L_ge_dsm_a_avx512_ifma_slide_bytes:
    rax = (word64)((word64)WC_L8(rsi, r11));
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 1920) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 1920) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 1920) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 1920) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 1920) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 1920) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 1920) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 1920) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    r11 = (word64)(r11 + 1);
    if ((r11) != (0x20)) {
        goto L_ge_dsm_a_avx512_ifma_slide_bytes;
    }
    /* Fold each run of digits down to one odd digit */
    r11 = (word64)(0);
L_ge_dsm_a_avx512_ifma_slide_digit:
    rcx = (word64)((word64)(sword64)(signed char)WC_L8(rbp, r11 + 1920));
    if (((rcx & rcx)) == (0)) {
        goto L_ge_dsm_a_avx512_ifma_slide_next_digit;
    }
    r12 = (word64)(1);
L_ge_dsm_a_avx512_ifma_slide_window:
    rdx = (word64)(r11);
    rdx = (word64)(rdx + r12);
    if ((sword64)(rdx) >= (sword64)(0x100)) {
        goto L_ge_dsm_a_avx512_ifma_slide_next_digit;
    }
    r8 = (word64)((word64)(sword64)(signed char)WC_L8(rbp, rdx + 1920));
    if (((r8 & r8)) == (0)) {
        goto L_ge_dsm_a_avx512_ifma_slide_next_window;
    }
    /* Weight of the digit at i + b, relative to the one at i */
    r9 = (word64)(r8);
    r8 = (word64)(r12);
L_ge_dsm_a_avx512_ifma_slide_shift:
    r9 = (word64)(r9 + r9);
    r8 = (word64)(r8 - 1);
    if ((r8) != (0)) {
        goto L_ge_dsm_a_avx512_ifma_slide_shift;
    }
    r9 = (word64)((word64)(sword64)(signed char)(byte)r9);
    /* Fold it in if the digit at i stays within range */
    r10 = (word64)(rcx);
    r10 = (word64)(r10 + r9);
    if ((sword64)(r10) > (sword64)(0xf)) {
        goto L_ge_dsm_a_avx512_ifma_slide_sub;
    }
    rcx = (word64)(r10);
    WC_S8(rbp, r11 + 1920) = (byte)((byte)rcx);
    WC_S8(rbp, rdx + 1920) = (byte)(0);
    goto L_ge_dsm_a_avx512_ifma_slide_next_window;
L_ge_dsm_a_avx512_ifma_slide_sub:
    r10 = (word64)(rcx);
    r10 = (word64)(r10 - r9);
    if ((sword64)(r10) < (sword64)(-15)) {
        goto L_ge_dsm_a_avx512_ifma_slide_next_digit;
    }
    rcx = (word64)(r10);
    WC_S8(rbp, r11 + 1920) = (byte)((byte)rcx);
    /* Subtracting it borrows from the digits above */
L_ge_dsm_a_avx512_ifma_slide_carry:
    if ((sword64)(rdx) >= (sword64)(0x100)) {
        goto L_ge_dsm_a_avx512_ifma_slide_next_window;
    }
    r10 = (word64)((word64)(sword64)(signed char)WC_L8(rbp, rdx + 1920));
    if (((r10 & r10)) == (0)) {
        goto L_ge_dsm_a_avx512_ifma_slide_set;
    }
    WC_S8(rbp, rdx + 1920) = (byte)(0);
    rdx = (word64)(rdx + 1);
    goto L_ge_dsm_a_avx512_ifma_slide_carry;
L_ge_dsm_a_avx512_ifma_slide_set:
    WC_S8(rbp, rdx + 1920) = (byte)(1);
L_ge_dsm_a_avx512_ifma_slide_next_window:
    r12 = (word64)(r12 + 1);
    if ((sword64)(r12) <= (sword64)(6)) {
        goto L_ge_dsm_a_avx512_ifma_slide_window;
    }
L_ge_dsm_a_avx512_ifma_slide_next_digit:
    r11 = (word64)(r11 + 1);
    if ((sword64)(r11) < (sword64)(0x100)) {
        goto L_ge_dsm_a_avx512_ifma_slide_digit;
    }
    /* Window digits of the base point scalar */
    /* One digit per bit of the scalar */
    rdx = (word64)(0);
    r11 = (word64)(0);
L_ge_dsm_b_avx512_ifma_slide_bytes:
    rax = (word64)((word64)WC_L8(r15, r11));
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 2176) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 2176) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 2176) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 2176) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 2176) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 2176) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 2176) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 2176) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    r11 = (word64)(r11 + 1);
    if ((r11) != (0x20)) {
        goto L_ge_dsm_b_avx512_ifma_slide_bytes;
    }
    /* Fold each run of digits down to one odd digit */
    r11 = (word64)(0);
L_ge_dsm_b_avx512_ifma_slide_digit:
    rcx = (word64)((word64)(sword64)(signed char)WC_L8(rbp, r11 + 2176));
    if (((rcx & rcx)) == (0)) {
        goto L_ge_dsm_b_avx512_ifma_slide_next_digit;
    }
    r12 = (word64)(1);
L_ge_dsm_b_avx512_ifma_slide_window:
    rdx = (word64)(r11);
    rdx = (word64)(rdx + r12);
    if ((sword64)(rdx) >= (sword64)(0x100)) {
        goto L_ge_dsm_b_avx512_ifma_slide_next_digit;
    }
    r8 = (word64)((word64)(sword64)(signed char)WC_L8(rbp, rdx + 2176));
    if (((r8 & r8)) == (0)) {
        goto L_ge_dsm_b_avx512_ifma_slide_next_window;
    }
    /* Weight of the digit at i + b, relative to the one at i */
    r9 = (word64)(r8);
    r8 = (word64)(r12);
L_ge_dsm_b_avx512_ifma_slide_shift:
    r9 = (word64)(r9 + r9);
    r8 = (word64)(r8 - 1);
    if ((r8) != (0)) {
        goto L_ge_dsm_b_avx512_ifma_slide_shift;
    }
    r9 = (word64)((word64)(sword64)(signed char)(byte)r9);
    /* Fold it in if the digit at i stays within range */
    r10 = (word64)(rcx);
    r10 = (word64)(r10 + r9);
    if ((sword64)(r10) > (sword64)(0x3f)) {
        goto L_ge_dsm_b_avx512_ifma_slide_sub;
    }
    rcx = (word64)(r10);
    WC_S8(rbp, r11 + 2176) = (byte)((byte)rcx);
    WC_S8(rbp, rdx + 2176) = (byte)(0);
    goto L_ge_dsm_b_avx512_ifma_slide_next_window;
L_ge_dsm_b_avx512_ifma_slide_sub:
    r10 = (word64)(rcx);
    r10 = (word64)(r10 - r9);
    if ((sword64)(r10) < (sword64)(-63)) {
        goto L_ge_dsm_b_avx512_ifma_slide_next_digit;
    }
    rcx = (word64)(r10);
    WC_S8(rbp, r11 + 2176) = (byte)((byte)rcx);
    /* Subtracting it borrows from the digits above */
L_ge_dsm_b_avx512_ifma_slide_carry:
    if ((sword64)(rdx) >= (sword64)(0x100)) {
        goto L_ge_dsm_b_avx512_ifma_slide_next_window;
    }
    r10 = (word64)((word64)(sword64)(signed char)WC_L8(rbp, rdx + 2176));
    if (((r10 & r10)) == (0)) {
        goto L_ge_dsm_b_avx512_ifma_slide_set;
    }
    WC_S8(rbp, rdx + 2176) = (byte)(0);
    rdx = (word64)(rdx + 1);
    goto L_ge_dsm_b_avx512_ifma_slide_carry;
L_ge_dsm_b_avx512_ifma_slide_set:
    WC_S8(rbp, rdx + 2176) = (byte)(1);
L_ge_dsm_b_avx512_ifma_slide_next_window:
    r12 = (word64)(r12 + 1);
    if ((sword64)(r12) <= (sword64)(6)) {
        goto L_ge_dsm_b_avx512_ifma_slide_window;
    }
L_ge_dsm_b_avx512_ifma_slide_next_digit:
    r11 = (word64)(r11 + 1);
    if ((sword64)(r11) < (sword64)(0x100)) {
        goto L_ge_dsm_b_avx512_ifma_slide_digit;
    }
    r15 = (word64)((word64)(size_t)L_ge_ifma_consts);
    y28 = _mm256_set1_epi64x((long long)WC_L64(r15, 0));
    y29 = _mm256_set1_epi64x((long long)WC_L64(r15, 8));
    y30 = _mm256_set1_epi64x((long long)WC_L64(r15, 16));
    y31 = _mm256_set1_epi64x((long long)WC_L64(r15, 24));
    r9 = (word32)(8);
    k1 = (__mmask16)(word32)r9;
    r9 = (word32)(0xc);
    k2 = (__mmask16)(word32)r9;
    r9 = (word32)(9);
    k3 = (__mmask16)(word32)r9;
    r9 = (word32)(6);
    k4 = (__mmask16)(word32)r9;
    r9 = (word32)(1);
    k5 = (__mmask16)(word32)r9;
    r9 = (word32)(2);
    k6 = (__mmask16)(word32)r9;
    r9 = (word32)(4);
    k7 = (__mmask16)(word32)r9;
    /* Odd multiples of A, cached and in limb form */
    r10 = (word64)(0x7ffffffffffff);
    /* A in limb form: [X, Y, Z, T] */
    rdx = (word64)(WC_L64(r14, 0));
    rax = (word64)(WC_L64(r14, 8));
    rcx = (word64)(WC_L64(r14, 16));
    r8 = (word64)(WC_L64(r14, 24));
    r9 = (word64)(r8);
    r9 = (word64)(r9 >> 63);
    r9 = (word64)(r9 * 19);
    r8 = (word64)(r8 << 1);
    r8 = (word64)(r8 >> 1);
    r13 = (word64)(rdx);
    r13 = (word64)(r13 & r10);
    r13 = (word64)(r13 + r9);
    WC_S64(rbp, 1440) = (word64)(r13);
    rdx = (word64)((rdx >> 51) | (rax << 13));
    r9 = (word64)(rdx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1472) = (word64)(r9);
    rax = (word64)((rax >> 38) | (rcx << 26));
    r9 = (word64)(rax);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1504) = (word64)(r9);
    rcx = (word64)((rcx >> 25) | (r8 << 39));
    r9 = (word64)(rcx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1536) = (word64)(r9);
    r8 = (word64)(r8 >> 12);
    WC_S64(rbp, 1568) = (word64)(r8);
    rdx = (word64)(WC_L64(r14, 32));
    rax = (word64)(WC_L64(r14, 40));
    rcx = (word64)(WC_L64(r14, 48));
    r8 = (word64)(WC_L64(r14, 56));
    r9 = (word64)(r8);
    r9 = (word64)(r9 >> 63);
    r9 = (word64)(r9 * 19);
    r8 = (word64)(r8 << 1);
    r8 = (word64)(r8 >> 1);
    r13 = (word64)(rdx);
    r13 = (word64)(r13 & r10);
    r13 = (word64)(r13 + r9);
    WC_S64(rbp, 1448) = (word64)(r13);
    rdx = (word64)((rdx >> 51) | (rax << 13));
    r9 = (word64)(rdx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1480) = (word64)(r9);
    rax = (word64)((rax >> 38) | (rcx << 26));
    r9 = (word64)(rax);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1512) = (word64)(r9);
    rcx = (word64)((rcx >> 25) | (r8 << 39));
    r9 = (word64)(rcx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1544) = (word64)(r9);
    r8 = (word64)(r8 >> 12);
    WC_S64(rbp, 1576) = (word64)(r8);
    rdx = (word64)(WC_L64(r14, 64));
    rax = (word64)(WC_L64(r14, 72));
    rcx = (word64)(WC_L64(r14, 80));
    r8 = (word64)(WC_L64(r14, 88));
    r9 = (word64)(r8);
    r9 = (word64)(r9 >> 63);
    r9 = (word64)(r9 * 19);
    r8 = (word64)(r8 << 1);
    r8 = (word64)(r8 >> 1);
    r13 = (word64)(rdx);
    r13 = (word64)(r13 & r10);
    r13 = (word64)(r13 + r9);
    WC_S64(rbp, 1456) = (word64)(r13);
    rdx = (word64)((rdx >> 51) | (rax << 13));
    r9 = (word64)(rdx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1488) = (word64)(r9);
    rax = (word64)((rax >> 38) | (rcx << 26));
    r9 = (word64)(rax);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1520) = (word64)(r9);
    rcx = (word64)((rcx >> 25) | (r8 << 39));
    r9 = (word64)(rcx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1552) = (word64)(r9);
    r8 = (word64)(r8 >> 12);
    WC_S64(rbp, 1584) = (word64)(r8);
    rdx = (word64)(WC_L64(r14, 96));
    rax = (word64)(WC_L64(r14, 104));
    rcx = (word64)(WC_L64(r14, 112));
    r8 = (word64)(WC_L64(r14, 120));
    r9 = (word64)(r8);
    r9 = (word64)(r9 >> 63);
    r9 = (word64)(r9 * 19);
    r8 = (word64)(r8 << 1);
    r8 = (word64)(r8 >> 1);
    r13 = (word64)(rdx);
    r13 = (word64)(r13 & r10);
    r13 = (word64)(r13 + r9);
    WC_S64(rbp, 1464) = (word64)(r13);
    rdx = (word64)((rdx >> 51) | (rax << 13));
    r9 = (word64)(rdx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1496) = (word64)(r9);
    rax = (word64)((rax >> 38) | (rcx << 26));
    r9 = (word64)(rax);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1528) = (word64)(r9);
    rcx = (word64)((rcx >> 25) | (r8 << 39));
    r9 = (word64)(rcx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1560) = (word64)(r9);
    r8 = (word64)(r8 >> 12);
    WC_S64(rbp, 1592) = (word64)(r8);
    /* Ai[0] = A */
    y18 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1440));
    y19 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1472));
    y20 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1504));
    y21 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1536));
    y22 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1568));
    /* To cached */
    y23 = _mm256_permute4x64_epi64(y18, 0xb0);
    y24 = _mm256_permute4x64_epi64(y19, 0xb0);
    y25 = _mm256_permute4x64_epi64(y20, 0xb0);
    y26 = _mm256_permute4x64_epi64(y21, 0xb0);
    y27 = _mm256_permute4x64_epi64(y22, 0xb0);
    y18 = _mm256_permute4x64_epi64(y18, 0xb5);
    y19 = _mm256_permute4x64_epi64(y19, 0xb5);
    y20 = _mm256_permute4x64_epi64(y20, 0xb5);
    y21 = _mm256_permute4x64_epi64(y21, 0xb5);
    y22 = _mm256_permute4x64_epi64(y22, 0xb5);
    y18 = _mm256_mask_blend_epi64(k5, y18, _mm256_add_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k5, y19, _mm256_add_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k5, y20, _mm256_add_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k5, y21, _mm256_add_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k5, y22, _mm256_add_epi64(y22, y27));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_add_epi64(y18, y29));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_add_epi64(y19, y30));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_add_epi64(y20, y30));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_add_epi64(y21, y30));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_add_epi64(y22, y30));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_sub_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_sub_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_sub_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_sub_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_sub_epi64(y22, y27));
    y0 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y1 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y2 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y3 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y4 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y4, y31);
    y19 = _mm256_add_epi64(y19, y0);
    y20 = _mm256_add_epi64(y20, y1);
    y21 = _mm256_add_epi64(y21, y2);
    y22 = _mm256_add_epi64(y22, y3);
    y23 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 32));
    y24 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 64));
    y25 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 96));
    y26 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 128));
    y27 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 160));
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_slli_epi64(y5, 4);
    y10 = _mm256_slli_epi64(y5, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y5);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_slli_epi64(y6, 4);
    y10 = _mm256_slli_epi64(y6, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y6);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_slli_epi64(y7, 4);
    y10 = _mm256_slli_epi64(y7, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y7);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_slli_epi64(y8, 4);
    y10 = _mm256_slli_epi64(y8, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y8);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_slli_epi64(y17, 4);
    y10 = _mm256_slli_epi64(y17, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y17);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 0), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 32), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 64), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 96), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 128), y22);
    /* A2 = 2.A */
    y18 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1440));
    y19 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1472));
    y20 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1504));
    y21 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1536));
    y22 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1568));
    /* Double */
    y23 = _mm256_permute4x64_epi64(y18, 0x64);
    y24 = _mm256_permute4x64_epi64(y19, 0x64);
    y25 = _mm256_permute4x64_epi64(y20, 0x64);
    y26 = _mm256_permute4x64_epi64(y21, 0x64);
    y27 = _mm256_permute4x64_epi64(y22, 0x64);
    y18 = _mm256_permute4x64_epi64(y18, 0x24);
    y19 = _mm256_permute4x64_epi64(y19, 0x24);
    y20 = _mm256_permute4x64_epi64(y20, 0x24);
    y21 = _mm256_permute4x64_epi64(y21, 0x24);
    y22 = _mm256_permute4x64_epi64(y22, 0x24);
    y18 = _mm256_mask_blend_epi64(k1, y18, _mm256_add_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k1, y19, _mm256_add_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k1, y20, _mm256_add_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k1, y21, _mm256_add_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k1, y22, _mm256_add_epi64(y22, y27));
    y0 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y1 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y2 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y3 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y4 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y4, y31);
    y19 = _mm256_add_epi64(y19, y0);
    y20 = _mm256_add_epi64(y20, y1);
    y21 = _mm256_add_epi64(y21, y2);
    y22 = _mm256_add_epi64(y22, y3);
    y23 = y18;
    y24 = y19;
    y25 = y20;
    y26 = y21;
    y27 = y22;
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_slli_epi64(y5, 4);
    y10 = _mm256_slli_epi64(y5, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y5);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_slli_epi64(y6, 4);
    y10 = _mm256_slli_epi64(y6, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y6);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_slli_epi64(y7, 4);
    y10 = _mm256_slli_epi64(y7, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y7);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_slli_epi64(y8, 4);
    y10 = _mm256_slli_epi64(y8, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y8);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_slli_epi64(y17, 4);
    y10 = _mm256_slli_epi64(y17, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y17);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* Y3 = YY + XX, Z3 = YY - XX */
    y23 = _mm256_permute4x64_epi64(y18, 0x55);
    y24 = _mm256_permute4x64_epi64(y19, 0x55);
    y25 = _mm256_permute4x64_epi64(y20, 0x55);
    y26 = _mm256_permute4x64_epi64(y21, 0x55);
    y27 = _mm256_permute4x64_epi64(y22, 0x55);
    y0 = _mm256_permute4x64_epi64(y18, 0);
    y1 = _mm256_permute4x64_epi64(y19, 0);
    y2 = _mm256_permute4x64_epi64(y20, 0);
    y3 = _mm256_permute4x64_epi64(y21, 0);
    y4 = _mm256_permute4x64_epi64(y22, 0);
    y5 = _mm256_add_epi64(y23, y0);
    y6 = _mm256_add_epi64(y24, y1);
    y7 = _mm256_add_epi64(y25, y2);
    y8 = _mm256_add_epi64(y26, y3);
    y9 = _mm256_add_epi64(y27, y4);
    y23 = _mm256_mask_blend_epi64(k2, y23, _mm256_add_epi64(y23, y29));
    y24 = _mm256_mask_blend_epi64(k2, y24, _mm256_add_epi64(y24, y30));
    y25 = _mm256_mask_blend_epi64(k2, y25, _mm256_add_epi64(y25, y30));
    y26 = _mm256_mask_blend_epi64(k2, y26, _mm256_add_epi64(y26, y30));
    y27 = _mm256_mask_blend_epi64(k2, y27, _mm256_add_epi64(y27, y30));
    y5 = _mm256_mask_blend_epi64(k2, y5, _mm256_sub_epi64(y23, y0));
    y6 = _mm256_mask_blend_epi64(k2, y6, _mm256_sub_epi64(y24, y1));
    y7 = _mm256_mask_blend_epi64(k2, y7, _mm256_sub_epi64(y25, y2));
    y8 = _mm256_mask_blend_epi64(k2, y8, _mm256_sub_epi64(y26, y3));
    y9 = _mm256_mask_blend_epi64(k2, y9, _mm256_sub_epi64(y27, y4));
    y23 = _mm256_srli_epi64(y5, 51);
    y5 = _mm256_and_si256(y5, y28);
    y24 = _mm256_srli_epi64(y6, 51);
    y6 = _mm256_and_si256(y6, y28);
    y25 = _mm256_srli_epi64(y7, 51);
    y7 = _mm256_and_si256(y7, y28);
    y26 = _mm256_srli_epi64(y8, 51);
    y8 = _mm256_and_si256(y8, y28);
    y27 = _mm256_srli_epi64(y9, 51);
    y9 = _mm256_and_si256(y9, y28);
    y5 = _mm256_madd52lo_epu64(y5, y27, y31);
    y6 = _mm256_add_epi64(y6, y23);
    y7 = _mm256_add_epi64(y7, y24);
    y8 = _mm256_add_epi64(y8, y25);
    y9 = _mm256_add_epi64(y9, y26);
    /* X3 = AA - Y3, T3 = 2.ZZ - Z3 */
    y23 = _mm256_permute4x64_epi64(y18, 0xaf);
    y24 = _mm256_permute4x64_epi64(y19, 0xaf);
    y25 = _mm256_permute4x64_epi64(y20, 0xaf);
    y26 = _mm256_permute4x64_epi64(y21, 0xaf);
    y27 = _mm256_permute4x64_epi64(y22, 0xaf);
    y23 = _mm256_mask_blend_epi64(k2, y23, _mm256_add_epi64(y23, y23));
    y24 = _mm256_mask_blend_epi64(k2, y24, _mm256_add_epi64(y24, y24));
    y25 = _mm256_mask_blend_epi64(k2, y25, _mm256_add_epi64(y25, y25));
    y26 = _mm256_mask_blend_epi64(k2, y26, _mm256_add_epi64(y26, y26));
    y27 = _mm256_mask_blend_epi64(k2, y27, _mm256_add_epi64(y27, y27));
    y23 = _mm256_mask_blend_epi64(k3, y23, _mm256_add_epi64(y23, y29));
    y24 = _mm256_mask_blend_epi64(k3, y24, _mm256_add_epi64(y24, y30));
    y25 = _mm256_mask_blend_epi64(k3, y25, _mm256_add_epi64(y25, y30));
    y26 = _mm256_mask_blend_epi64(k3, y26, _mm256_add_epi64(y26, y30));
    y27 = _mm256_mask_blend_epi64(k3, y27, _mm256_add_epi64(y27, y30));
    y23 = _mm256_mask_blend_epi64(k3, y23, _mm256_sub_epi64(y23, y5));
    y24 = _mm256_mask_blend_epi64(k3, y24, _mm256_sub_epi64(y24, y6));
    y25 = _mm256_mask_blend_epi64(k3, y25, _mm256_sub_epi64(y25, y7));
    y26 = _mm256_mask_blend_epi64(k3, y26, _mm256_sub_epi64(y26, y8));
    y27 = _mm256_mask_blend_epi64(k3, y27, _mm256_sub_epi64(y27, y9));
    y0 = _mm256_srli_epi64(y23, 51);
    y23 = _mm256_and_si256(y23, y28);
    y1 = _mm256_srli_epi64(y24, 51);
    y24 = _mm256_and_si256(y24, y28);
    y2 = _mm256_srli_epi64(y25, 51);
    y25 = _mm256_and_si256(y25, y28);
    y3 = _mm256_srli_epi64(y26, 51);
    y26 = _mm256_and_si256(y26, y28);
    y4 = _mm256_srli_epi64(y27, 51);
    y27 = _mm256_and_si256(y27, y28);
    y23 = _mm256_madd52lo_epu64(y23, y4, y31);
    y24 = _mm256_add_epi64(y24, y0);
    y25 = _mm256_add_epi64(y25, y1);
    y26 = _mm256_add_epi64(y26, y2);
    y27 = _mm256_add_epi64(y27, y3);
    y23 = _mm256_mask_blend_epi64(k4, y23, y5);
    y24 = _mm256_mask_blend_epi64(k4, y24, y6);
    y25 = _mm256_mask_blend_epi64(k4, y25, y7);
    y26 = _mm256_mask_blend_epi64(k4, y26, y8);
    y27 = _mm256_mask_blend_epi64(k4, y27, y9);
    /* To p3 */
    y18 = _mm256_permute4x64_epi64(y23, 0x24);
    y19 = _mm256_permute4x64_epi64(y24, 0x24);
    y20 = _mm256_permute4x64_epi64(y25, 0x24);
    y21 = _mm256_permute4x64_epi64(y26, 0x24);
    y22 = _mm256_permute4x64_epi64(y27, 0x24);
    y23 = _mm256_permute4x64_epi64(y23, 0x7b);
    y24 = _mm256_permute4x64_epi64(y24, 0x7b);
    y25 = _mm256_permute4x64_epi64(y25, 0x7b);
    y26 = _mm256_permute4x64_epi64(y26, 0x7b);
    y27 = _mm256_permute4x64_epi64(y27, 0x7b);
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_slli_epi64(y5, 4);
    y10 = _mm256_slli_epi64(y5, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y5);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_slli_epi64(y6, 4);
    y10 = _mm256_slli_epi64(y6, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y6);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_slli_epi64(y7, 4);
    y10 = _mm256_slli_epi64(y7, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y7);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_slli_epi64(y8, 4);
    y10 = _mm256_slli_epi64(y8, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y8);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_slli_epi64(y17, 4);
    y10 = _mm256_slli_epi64(y17, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y17);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1280), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1312), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1344), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1376), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1408), y22);
    /* Ai[j] = A2 + Ai[j-1] */
    r12 = (word64)(rbp);
    r11 = (word64)(7);
L_ge_dsm_avx512_ifma_table:
    y18 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1280));
    y19 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1312));
    y20 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1344));
    y21 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1376));
    y22 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1408));
    /* Add */
    y23 = _mm256_permute4x64_epi64(y18, 0xb0);
    y24 = _mm256_permute4x64_epi64(y19, 0xb0);
    y25 = _mm256_permute4x64_epi64(y20, 0xb0);
    y26 = _mm256_permute4x64_epi64(y21, 0xb0);
    y27 = _mm256_permute4x64_epi64(y22, 0xb0);
    y18 = _mm256_permute4x64_epi64(y18, 0xb5);
    y19 = _mm256_permute4x64_epi64(y19, 0xb5);
    y20 = _mm256_permute4x64_epi64(y20, 0xb5);
    y21 = _mm256_permute4x64_epi64(y21, 0xb5);
    y22 = _mm256_permute4x64_epi64(y22, 0xb5);
    y18 = _mm256_mask_blend_epi64(k5, y18, _mm256_add_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k5, y19, _mm256_add_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k5, y20, _mm256_add_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k5, y21, _mm256_add_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k5, y22, _mm256_add_epi64(y22, y27));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_add_epi64(y18, y29));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_add_epi64(y19, y30));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_add_epi64(y20, y30));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_add_epi64(y21, y30));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_add_epi64(y22, y30));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_sub_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_sub_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_sub_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_sub_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_sub_epi64(y22, y27));
    y0 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y1 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y2 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y3 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y4 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y4, y31);
    y19 = _mm256_add_epi64(y19, y0);
    y20 = _mm256_add_epi64(y20, y1);
    y21 = _mm256_add_epi64(y21, y2);
    y22 = _mm256_add_epi64(y22, y3);
    y23 = _mm256_loadu_si256((const __m256i*)WC_PR(r12, 0));
    y24 = _mm256_loadu_si256((const __m256i*)WC_PR(r12, 32));
    y25 = _mm256_loadu_si256((const __m256i*)WC_PR(r12, 64));
    y26 = _mm256_loadu_si256((const __m256i*)WC_PR(r12, 96));
    y27 = _mm256_loadu_si256((const __m256i*)WC_PR(r12, 128));
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_slli_epi64(y5, 4);
    y10 = _mm256_slli_epi64(y5, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y5);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_slli_epi64(y6, 4);
    y10 = _mm256_slli_epi64(y6, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y6);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_slli_epi64(y7, 4);
    y10 = _mm256_slli_epi64(y7, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y7);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_slli_epi64(y8, 4);
    y10 = _mm256_slli_epi64(y8, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y8);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_slli_epi64(y17, 4);
    y10 = _mm256_slli_epi64(y17, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y17);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* X3 = B - A, Y3 = B + A, Z3 = D + C, T3 = D - C */
    y23 = _mm256_permute4x64_epi64(y18, 0xf0);
    y24 = _mm256_permute4x64_epi64(y19, 0xf0);
    y25 = _mm256_permute4x64_epi64(y20, 0xf0);
    y26 = _mm256_permute4x64_epi64(y21, 0xf0);
    y27 = _mm256_permute4x64_epi64(y22, 0xf0);
    y23 = _mm256_mask_blend_epi64(k2, y23, _mm256_add_epi64(y23, y23));
    y24 = _mm256_mask_blend_epi64(k2, y24, _mm256_add_epi64(y24, y24));
    y25 = _mm256_mask_blend_epi64(k2, y25, _mm256_add_epi64(y25, y25));
    y26 = _mm256_mask_blend_epi64(k2, y26, _mm256_add_epi64(y26, y26));
    y27 = _mm256_mask_blend_epi64(k2, y27, _mm256_add_epi64(y27, y27));
    y0 = _mm256_permute4x64_epi64(y18, 0xa5);
    y1 = _mm256_permute4x64_epi64(y19, 0xa5);
    y2 = _mm256_permute4x64_epi64(y20, 0xa5);
    y3 = _mm256_permute4x64_epi64(y21, 0xa5);
    y4 = _mm256_permute4x64_epi64(y22, 0xa5);
    y18 = _mm256_add_epi64(y23, y0);
    y19 = _mm256_add_epi64(y24, y1);
    y20 = _mm256_add_epi64(y25, y2);
    y21 = _mm256_add_epi64(y26, y3);
    y22 = _mm256_add_epi64(y27, y4);
    y23 = _mm256_mask_blend_epi64(k3, y23, _mm256_add_epi64(y23, y29));
    y24 = _mm256_mask_blend_epi64(k3, y24, _mm256_add_epi64(y24, y30));
    y25 = _mm256_mask_blend_epi64(k3, y25, _mm256_add_epi64(y25, y30));
    y26 = _mm256_mask_blend_epi64(k3, y26, _mm256_add_epi64(y26, y30));
    y27 = _mm256_mask_blend_epi64(k3, y27, _mm256_add_epi64(y27, y30));
    y18 = _mm256_mask_blend_epi64(k3, y18, _mm256_sub_epi64(y23, y0));
    y19 = _mm256_mask_blend_epi64(k3, y19, _mm256_sub_epi64(y24, y1));
    y20 = _mm256_mask_blend_epi64(k3, y20, _mm256_sub_epi64(y25, y2));
    y21 = _mm256_mask_blend_epi64(k3, y21, _mm256_sub_epi64(y26, y3));
    y22 = _mm256_mask_blend_epi64(k3, y22, _mm256_sub_epi64(y27, y4));
    y5 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y6 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y7 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y8 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y9 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y9, y31);
    y19 = _mm256_add_epi64(y19, y5);
    y20 = _mm256_add_epi64(y20, y6);
    y21 = _mm256_add_epi64(y21, y7);
    y22 = _mm256_add_epi64(y22, y8);
    y23 = y18;
    y24 = y19;
    y25 = y20;
    y26 = y21;
    y27 = y22;
    /* To p3 */
    y18 = _mm256_permute4x64_epi64(y23, 0x24);
    y19 = _mm256_permute4x64_epi64(y24, 0x24);
    y20 = _mm256_permute4x64_epi64(y25, 0x24);
    y21 = _mm256_permute4x64_epi64(y26, 0x24);
    y22 = _mm256_permute4x64_epi64(y27, 0x24);
    y23 = _mm256_permute4x64_epi64(y23, 0x7b);
    y24 = _mm256_permute4x64_epi64(y24, 0x7b);
    y25 = _mm256_permute4x64_epi64(y25, 0x7b);
    y26 = _mm256_permute4x64_epi64(y26, 0x7b);
    y27 = _mm256_permute4x64_epi64(y27, 0x7b);
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_slli_epi64(y5, 4);
    y10 = _mm256_slli_epi64(y5, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y5);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_slli_epi64(y6, 4);
    y10 = _mm256_slli_epi64(y6, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y6);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_slli_epi64(y7, 4);
    y10 = _mm256_slli_epi64(y7, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y7);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_slli_epi64(y8, 4);
    y10 = _mm256_slli_epi64(y8, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y8);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_slli_epi64(y17, 4);
    y10 = _mm256_slli_epi64(y17, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y17);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    r12 = (word64)(r12 + 0xa0);
    /* To cached */
    y23 = _mm256_permute4x64_epi64(y18, 0xb0);
    y24 = _mm256_permute4x64_epi64(y19, 0xb0);
    y25 = _mm256_permute4x64_epi64(y20, 0xb0);
    y26 = _mm256_permute4x64_epi64(y21, 0xb0);
    y27 = _mm256_permute4x64_epi64(y22, 0xb0);
    y18 = _mm256_permute4x64_epi64(y18, 0xb5);
    y19 = _mm256_permute4x64_epi64(y19, 0xb5);
    y20 = _mm256_permute4x64_epi64(y20, 0xb5);
    y21 = _mm256_permute4x64_epi64(y21, 0xb5);
    y22 = _mm256_permute4x64_epi64(y22, 0xb5);
    y18 = _mm256_mask_blend_epi64(k5, y18, _mm256_add_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k5, y19, _mm256_add_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k5, y20, _mm256_add_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k5, y21, _mm256_add_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k5, y22, _mm256_add_epi64(y22, y27));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_add_epi64(y18, y29));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_add_epi64(y19, y30));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_add_epi64(y20, y30));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_add_epi64(y21, y30));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_add_epi64(y22, y30));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_sub_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_sub_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_sub_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_sub_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_sub_epi64(y22, y27));
    y0 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y1 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y2 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y3 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y4 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y4, y31);
    y19 = _mm256_add_epi64(y19, y0);
    y20 = _mm256_add_epi64(y20, y1);
    y21 = _mm256_add_epi64(y21, y2);
    y22 = _mm256_add_epi64(y22, y3);
    y23 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 32));
    y24 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 64));
    y25 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 96));
    y26 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 128));
    y27 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 160));
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_slli_epi64(y5, 4);
    y10 = _mm256_slli_epi64(y5, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y5);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_slli_epi64(y6, 4);
    y10 = _mm256_slli_epi64(y6, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y6);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_slli_epi64(y7, 4);
    y10 = _mm256_slli_epi64(y7, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y7);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_slli_epi64(y8, 4);
    y10 = _mm256_slli_epi64(y8, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y8);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_slli_epi64(y17, 4);
    y10 = _mm256_slli_epi64(y17, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y17);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 0), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 32), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 64), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 96), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 128), y22);
    r11 = (word64)(r11 - 1);
    if ((r11) != (0)) {
        goto L_ge_dsm_avx512_ifma_table;
    }
    /* R = identity: X = 0, Y = 1, Z = 1, T = 0 */
    r9 = (word64)(1);
    WC_S64(rbp, 1608) = (word64)(r9);
    r9 = (word64)(0);
    WC_S64(rbp, 1640) = (word64)(r9);
    WC_S64(rbp, 1672) = (word64)(r9);
    WC_S64(rbp, 1704) = (word64)(r9);
    WC_S64(rbp, 1736) = (word64)(r9);
    r9 = (word64)(1);
    WC_S64(rbp, 1616) = (word64)(r9);
    r9 = (word64)(0);
    WC_S64(rbp, 1648) = (word64)(r9);
    WC_S64(rbp, 1680) = (word64)(r9);
    WC_S64(rbp, 1712) = (word64)(r9);
    WC_S64(rbp, 1744) = (word64)(r9);
    r9 = (word64)(0);
    WC_S64(rbp, 1600) = (word64)(r9);
    WC_S64(rbp, 1624) = (word64)(r9);
    WC_S64(rbp, 1632) = (word64)(r9);
    WC_S64(rbp, 1656) = (word64)(r9);
    WC_S64(rbp, 1664) = (word64)(r9);
    WC_S64(rbp, 1688) = (word64)(r9);
    WC_S64(rbp, 1696) = (word64)(r9);
    WC_S64(rbp, 1720) = (word64)(r9);
    WC_S64(rbp, 1728) = (word64)(r9);
    WC_S64(rbp, 1752) = (word64)(r9);
    r10 = (word64)(0x7ffffffffffff);
    y18 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1600));
    y19 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1632));
    y20 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1664));
    y21 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1696));
    y22 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1728));
    r11 = (word64)(0xff);
L_ge_dsm_avx512_ifma_bits:
    /* Double */
    y23 = _mm256_permute4x64_epi64(y18, 0x64);
    y24 = _mm256_permute4x64_epi64(y19, 0x64);
    y25 = _mm256_permute4x64_epi64(y20, 0x64);
    y26 = _mm256_permute4x64_epi64(y21, 0x64);
    y27 = _mm256_permute4x64_epi64(y22, 0x64);
    y18 = _mm256_permute4x64_epi64(y18, 0x24);
    y19 = _mm256_permute4x64_epi64(y19, 0x24);
    y20 = _mm256_permute4x64_epi64(y20, 0x24);
    y21 = _mm256_permute4x64_epi64(y21, 0x24);
    y22 = _mm256_permute4x64_epi64(y22, 0x24);
    y18 = _mm256_mask_blend_epi64(k1, y18, _mm256_add_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k1, y19, _mm256_add_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k1, y20, _mm256_add_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k1, y21, _mm256_add_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k1, y22, _mm256_add_epi64(y22, y27));
    y0 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y1 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y2 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y3 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y4 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y4, y31);
    y19 = _mm256_add_epi64(y19, y0);
    y20 = _mm256_add_epi64(y20, y1);
    y21 = _mm256_add_epi64(y21, y2);
    y22 = _mm256_add_epi64(y22, y3);
    y23 = y18;
    y24 = y19;
    y25 = y20;
    y26 = y21;
    y27 = y22;
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_slli_epi64(y5, 4);
    y10 = _mm256_slli_epi64(y5, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y5);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_slli_epi64(y6, 4);
    y10 = _mm256_slli_epi64(y6, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y6);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_slli_epi64(y7, 4);
    y10 = _mm256_slli_epi64(y7, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y7);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_slli_epi64(y8, 4);
    y10 = _mm256_slli_epi64(y8, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y8);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_slli_epi64(y17, 4);
    y10 = _mm256_slli_epi64(y17, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y17);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* Y3 = YY + XX, Z3 = YY - XX */
    y23 = _mm256_permute4x64_epi64(y18, 0x55);
    y24 = _mm256_permute4x64_epi64(y19, 0x55);
    y25 = _mm256_permute4x64_epi64(y20, 0x55);
    y26 = _mm256_permute4x64_epi64(y21, 0x55);
    y27 = _mm256_permute4x64_epi64(y22, 0x55);
    y0 = _mm256_permute4x64_epi64(y18, 0);
    y1 = _mm256_permute4x64_epi64(y19, 0);
    y2 = _mm256_permute4x64_epi64(y20, 0);
    y3 = _mm256_permute4x64_epi64(y21, 0);
    y4 = _mm256_permute4x64_epi64(y22, 0);
    y5 = _mm256_add_epi64(y23, y0);
    y6 = _mm256_add_epi64(y24, y1);
    y7 = _mm256_add_epi64(y25, y2);
    y8 = _mm256_add_epi64(y26, y3);
    y9 = _mm256_add_epi64(y27, y4);
    y23 = _mm256_mask_blend_epi64(k2, y23, _mm256_add_epi64(y23, y29));
    y24 = _mm256_mask_blend_epi64(k2, y24, _mm256_add_epi64(y24, y30));
    y25 = _mm256_mask_blend_epi64(k2, y25, _mm256_add_epi64(y25, y30));
    y26 = _mm256_mask_blend_epi64(k2, y26, _mm256_add_epi64(y26, y30));
    y27 = _mm256_mask_blend_epi64(k2, y27, _mm256_add_epi64(y27, y30));
    y5 = _mm256_mask_blend_epi64(k2, y5, _mm256_sub_epi64(y23, y0));
    y6 = _mm256_mask_blend_epi64(k2, y6, _mm256_sub_epi64(y24, y1));
    y7 = _mm256_mask_blend_epi64(k2, y7, _mm256_sub_epi64(y25, y2));
    y8 = _mm256_mask_blend_epi64(k2, y8, _mm256_sub_epi64(y26, y3));
    y9 = _mm256_mask_blend_epi64(k2, y9, _mm256_sub_epi64(y27, y4));
    y23 = _mm256_srli_epi64(y5, 51);
    y5 = _mm256_and_si256(y5, y28);
    y24 = _mm256_srli_epi64(y6, 51);
    y6 = _mm256_and_si256(y6, y28);
    y25 = _mm256_srli_epi64(y7, 51);
    y7 = _mm256_and_si256(y7, y28);
    y26 = _mm256_srli_epi64(y8, 51);
    y8 = _mm256_and_si256(y8, y28);
    y27 = _mm256_srli_epi64(y9, 51);
    y9 = _mm256_and_si256(y9, y28);
    y5 = _mm256_madd52lo_epu64(y5, y27, y31);
    y6 = _mm256_add_epi64(y6, y23);
    y7 = _mm256_add_epi64(y7, y24);
    y8 = _mm256_add_epi64(y8, y25);
    y9 = _mm256_add_epi64(y9, y26);
    /* X3 = AA - Y3, T3 = 2.ZZ - Z3 */
    y23 = _mm256_permute4x64_epi64(y18, 0xaf);
    y24 = _mm256_permute4x64_epi64(y19, 0xaf);
    y25 = _mm256_permute4x64_epi64(y20, 0xaf);
    y26 = _mm256_permute4x64_epi64(y21, 0xaf);
    y27 = _mm256_permute4x64_epi64(y22, 0xaf);
    y23 = _mm256_mask_blend_epi64(k2, y23, _mm256_add_epi64(y23, y23));
    y24 = _mm256_mask_blend_epi64(k2, y24, _mm256_add_epi64(y24, y24));
    y25 = _mm256_mask_blend_epi64(k2, y25, _mm256_add_epi64(y25, y25));
    y26 = _mm256_mask_blend_epi64(k2, y26, _mm256_add_epi64(y26, y26));
    y27 = _mm256_mask_blend_epi64(k2, y27, _mm256_add_epi64(y27, y27));
    y23 = _mm256_mask_blend_epi64(k3, y23, _mm256_add_epi64(y23, y29));
    y24 = _mm256_mask_blend_epi64(k3, y24, _mm256_add_epi64(y24, y30));
    y25 = _mm256_mask_blend_epi64(k3, y25, _mm256_add_epi64(y25, y30));
    y26 = _mm256_mask_blend_epi64(k3, y26, _mm256_add_epi64(y26, y30));
    y27 = _mm256_mask_blend_epi64(k3, y27, _mm256_add_epi64(y27, y30));
    y23 = _mm256_mask_blend_epi64(k3, y23, _mm256_sub_epi64(y23, y5));
    y24 = _mm256_mask_blend_epi64(k3, y24, _mm256_sub_epi64(y24, y6));
    y25 = _mm256_mask_blend_epi64(k3, y25, _mm256_sub_epi64(y25, y7));
    y26 = _mm256_mask_blend_epi64(k3, y26, _mm256_sub_epi64(y26, y8));
    y27 = _mm256_mask_blend_epi64(k3, y27, _mm256_sub_epi64(y27, y9));
    y0 = _mm256_srli_epi64(y23, 51);
    y23 = _mm256_and_si256(y23, y28);
    y1 = _mm256_srli_epi64(y24, 51);
    y24 = _mm256_and_si256(y24, y28);
    y2 = _mm256_srli_epi64(y25, 51);
    y25 = _mm256_and_si256(y25, y28);
    y3 = _mm256_srli_epi64(y26, 51);
    y26 = _mm256_and_si256(y26, y28);
    y4 = _mm256_srli_epi64(y27, 51);
    y27 = _mm256_and_si256(y27, y28);
    y23 = _mm256_madd52lo_epu64(y23, y4, y31);
    y24 = _mm256_add_epi64(y24, y0);
    y25 = _mm256_add_epi64(y25, y1);
    y26 = _mm256_add_epi64(y26, y2);
    y27 = _mm256_add_epi64(y27, y3);
    y23 = _mm256_mask_blend_epi64(k4, y23, y5);
    y24 = _mm256_mask_blend_epi64(k4, y24, y6);
    y25 = _mm256_mask_blend_epi64(k4, y25, y7);
    y26 = _mm256_mask_blend_epi64(k4, y26, y8);
    y27 = _mm256_mask_blend_epi64(k4, y27, y9);
    /* Add the multiple of A selected by this window digit */
    r12 = (word64)((word64)(sword64)(signed char)WC_L8(rbp, r11 + 1920));
    if (((r12 & r12)) == (0)) {
        goto L_ge_dsm_avx512_ifma_skip_a;
    }
    rsi = (word64)(r12);
    rsi = (word64)((word64)((sword64)rsi >> 63));
    r12 = (word64)(r12);
    r12 = (word64)(r12 ^ rsi);
    r12 = (word64)(r12 - rsi);
    r12 = (word64)(r12 >> 1);
    r12 = (word64)(r12 * 160);
    r14 = (word64)(rbp);
    r14 = (word64)(r14 + r12);
    y18 = _mm256_loadu_si256((const __m256i*)WC_PR(r14, 0));
    y19 = _mm256_loadu_si256((const __m256i*)WC_PR(r14, 32));
    y20 = _mm256_loadu_si256((const __m256i*)WC_PR(r14, 64));
    y21 = _mm256_loadu_si256((const __m256i*)WC_PR(r14, 96));
    y22 = _mm256_loadu_si256((const __m256i*)WC_PR(r14, 128));
    if (((rsi & rsi)) == (0)) {
        goto L_ge_dsm_avx512_ifma_noswap_a;
    }
    y18 = _mm256_permute4x64_epi64(y18, 0xe1);
    y19 = _mm256_permute4x64_epi64(y19, 0xe1);
    y20 = _mm256_permute4x64_epi64(y20, 0xe1);
    y21 = _mm256_permute4x64_epi64(y21, 0xe1);
    y22 = _mm256_permute4x64_epi64(y22, 0xe1);
L_ge_dsm_avx512_ifma_noswap_a:
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1760), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1792), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1824), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1856), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1888), y22);
    /* To p3 */
    y18 = _mm256_permute4x64_epi64(y23, 0x24);
    y19 = _mm256_permute4x64_epi64(y24, 0x24);
    y20 = _mm256_permute4x64_epi64(y25, 0x24);
    y21 = _mm256_permute4x64_epi64(y26, 0x24);
    y22 = _mm256_permute4x64_epi64(y27, 0x24);
    y23 = _mm256_permute4x64_epi64(y23, 0x7b);
    y24 = _mm256_permute4x64_epi64(y24, 0x7b);
    y25 = _mm256_permute4x64_epi64(y25, 0x7b);
    y26 = _mm256_permute4x64_epi64(y26, 0x7b);
    y27 = _mm256_permute4x64_epi64(y27, 0x7b);
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_slli_epi64(y5, 4);
    y10 = _mm256_slli_epi64(y5, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y5);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_slli_epi64(y6, 4);
    y10 = _mm256_slli_epi64(y6, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y6);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_slli_epi64(y7, 4);
    y10 = _mm256_slli_epi64(y7, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y7);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_slli_epi64(y8, 4);
    y10 = _mm256_slli_epi64(y8, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y8);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_slli_epi64(y17, 4);
    y10 = _mm256_slli_epi64(y17, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y17);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* Add */
    y23 = _mm256_permute4x64_epi64(y18, 0xb0);
    y24 = _mm256_permute4x64_epi64(y19, 0xb0);
    y25 = _mm256_permute4x64_epi64(y20, 0xb0);
    y26 = _mm256_permute4x64_epi64(y21, 0xb0);
    y27 = _mm256_permute4x64_epi64(y22, 0xb0);
    y18 = _mm256_permute4x64_epi64(y18, 0xb5);
    y19 = _mm256_permute4x64_epi64(y19, 0xb5);
    y20 = _mm256_permute4x64_epi64(y20, 0xb5);
    y21 = _mm256_permute4x64_epi64(y21, 0xb5);
    y22 = _mm256_permute4x64_epi64(y22, 0xb5);
    y18 = _mm256_mask_blend_epi64(k5, y18, _mm256_add_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k5, y19, _mm256_add_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k5, y20, _mm256_add_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k5, y21, _mm256_add_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k5, y22, _mm256_add_epi64(y22, y27));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_add_epi64(y18, y29));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_add_epi64(y19, y30));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_add_epi64(y20, y30));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_add_epi64(y21, y30));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_add_epi64(y22, y30));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_sub_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_sub_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_sub_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_sub_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_sub_epi64(y22, y27));
    y0 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y1 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y2 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y3 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y4 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y4, y31);
    y19 = _mm256_add_epi64(y19, y0);
    y20 = _mm256_add_epi64(y20, y1);
    y21 = _mm256_add_epi64(y21, y2);
    y22 = _mm256_add_epi64(y22, y3);
    y23 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1760));
    y24 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1792));
    y25 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1824));
    y26 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1856));
    y27 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1888));
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_slli_epi64(y5, 4);
    y10 = _mm256_slli_epi64(y5, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y5);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_slli_epi64(y6, 4);
    y10 = _mm256_slli_epi64(y6, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y6);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_slli_epi64(y7, 4);
    y10 = _mm256_slli_epi64(y7, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y7);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_slli_epi64(y8, 4);
    y10 = _mm256_slli_epi64(y8, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y8);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_slli_epi64(y17, 4);
    y10 = _mm256_slli_epi64(y17, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y17);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* X3 = B - A, Y3 = B + A, Z3 = D + C, T3 = D - C */
    y23 = _mm256_permute4x64_epi64(y18, 0xf0);
    y24 = _mm256_permute4x64_epi64(y19, 0xf0);
    y25 = _mm256_permute4x64_epi64(y20, 0xf0);
    y26 = _mm256_permute4x64_epi64(y21, 0xf0);
    y27 = _mm256_permute4x64_epi64(y22, 0xf0);
    y23 = _mm256_mask_blend_epi64(k2, y23, _mm256_add_epi64(y23, y23));
    y24 = _mm256_mask_blend_epi64(k2, y24, _mm256_add_epi64(y24, y24));
    y25 = _mm256_mask_blend_epi64(k2, y25, _mm256_add_epi64(y25, y25));
    y26 = _mm256_mask_blend_epi64(k2, y26, _mm256_add_epi64(y26, y26));
    y27 = _mm256_mask_blend_epi64(k2, y27, _mm256_add_epi64(y27, y27));
    y0 = _mm256_permute4x64_epi64(y18, 0xa5);
    y1 = _mm256_permute4x64_epi64(y19, 0xa5);
    y2 = _mm256_permute4x64_epi64(y20, 0xa5);
    y3 = _mm256_permute4x64_epi64(y21, 0xa5);
    y4 = _mm256_permute4x64_epi64(y22, 0xa5);
    y18 = _mm256_add_epi64(y23, y0);
    y19 = _mm256_add_epi64(y24, y1);
    y20 = _mm256_add_epi64(y25, y2);
    y21 = _mm256_add_epi64(y26, y3);
    y22 = _mm256_add_epi64(y27, y4);
    y23 = _mm256_mask_blend_epi64(k3, y23, _mm256_add_epi64(y23, y29));
    y24 = _mm256_mask_blend_epi64(k3, y24, _mm256_add_epi64(y24, y30));
    y25 = _mm256_mask_blend_epi64(k3, y25, _mm256_add_epi64(y25, y30));
    y26 = _mm256_mask_blend_epi64(k3, y26, _mm256_add_epi64(y26, y30));
    y27 = _mm256_mask_blend_epi64(k3, y27, _mm256_add_epi64(y27, y30));
    y18 = _mm256_mask_blend_epi64(k3, y18, _mm256_sub_epi64(y23, y0));
    y19 = _mm256_mask_blend_epi64(k3, y19, _mm256_sub_epi64(y24, y1));
    y20 = _mm256_mask_blend_epi64(k3, y20, _mm256_sub_epi64(y25, y2));
    y21 = _mm256_mask_blend_epi64(k3, y21, _mm256_sub_epi64(y26, y3));
    y22 = _mm256_mask_blend_epi64(k3, y22, _mm256_sub_epi64(y27, y4));
    y5 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y6 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y7 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y8 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y9 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y9, y31);
    y19 = _mm256_add_epi64(y19, y5);
    y20 = _mm256_add_epi64(y20, y6);
    y21 = _mm256_add_epi64(y21, y7);
    y22 = _mm256_add_epi64(y22, y8);
    if (((rsi & rsi)) == (0)) {
        goto L_ge_dsm_avx512_ifma_nores_a;
    }
    y18 = _mm256_permute4x64_epi64(y18, 0xb4);
    y19 = _mm256_permute4x64_epi64(y19, 0xb4);
    y20 = _mm256_permute4x64_epi64(y20, 0xb4);
    y21 = _mm256_permute4x64_epi64(y21, 0xb4);
    y22 = _mm256_permute4x64_epi64(y22, 0xb4);
L_ge_dsm_avx512_ifma_nores_a:
    y23 = y18;
    y24 = y19;
    y25 = y20;
    y26 = y21;
    y27 = y22;
L_ge_dsm_avx512_ifma_skip_a:
    /* Add the multiple of the base point */
    r12 = (word64)((word64)(sword64)(signed char)WC_L8(rbp, r11 + 2176));
    if (((r12 & r12)) == (0)) {
        goto L_ge_dsm_avx512_ifma_skip_b;
    }
    rsi = (word64)(r12);
    rsi = (word64)((word64)((sword64)rsi >> 63));
    r12 = (word64)(r12);
    r12 = (word64)(r12 ^ rsi);
    r12 = (word64)(r12 - rsi);
    r12 = (word64)(r12 >> 1);
    r12 = (word64)(r12 * 96);
    r14 = (word64)(rbx);
    r14 = (word64)(r14 + r12);
    rdx = (word64)(WC_L64(r14, 0));
    rax = (word64)(WC_L64(r14, 8));
    rcx = (word64)(WC_L64(r14, 16));
    r8 = (word64)(WC_L64(r14, 24));
    r9 = (word64)(r8);
    r9 = (word64)(r9 >> 63);
    r9 = (word64)(r9 * 19);
    r8 = (word64)(r8 << 1);
    r8 = (word64)(r8 >> 1);
    r13 = (word64)(rdx);
    r13 = (word64)(r13 & r10);
    r13 = (word64)(r13 + r9);
    WC_S64(rbp, 1760) = (word64)(r13);
    rdx = (word64)((rdx >> 51) | (rax << 13));
    r9 = (word64)(rdx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1792) = (word64)(r9);
    rax = (word64)((rax >> 38) | (rcx << 26));
    r9 = (word64)(rax);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1824) = (word64)(r9);
    rcx = (word64)((rcx >> 25) | (r8 << 39));
    r9 = (word64)(rcx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1856) = (word64)(r9);
    r8 = (word64)(r8 >> 12);
    WC_S64(rbp, 1888) = (word64)(r8);
    rdx = (word64)(WC_L64(r14, 32));
    rax = (word64)(WC_L64(r14, 40));
    rcx = (word64)(WC_L64(r14, 48));
    r8 = (word64)(WC_L64(r14, 56));
    r9 = (word64)(r8);
    r9 = (word64)(r9 >> 63);
    r9 = (word64)(r9 * 19);
    r8 = (word64)(r8 << 1);
    r8 = (word64)(r8 >> 1);
    r13 = (word64)(rdx);
    r13 = (word64)(r13 & r10);
    r13 = (word64)(r13 + r9);
    WC_S64(rbp, 1768) = (word64)(r13);
    rdx = (word64)((rdx >> 51) | (rax << 13));
    r9 = (word64)(rdx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1800) = (word64)(r9);
    rax = (word64)((rax >> 38) | (rcx << 26));
    r9 = (word64)(rax);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1832) = (word64)(r9);
    rcx = (word64)((rcx >> 25) | (r8 << 39));
    r9 = (word64)(rcx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1864) = (word64)(r9);
    r8 = (word64)(r8 >> 12);
    WC_S64(rbp, 1896) = (word64)(r8);
    rdx = (word64)(WC_L64(r14, 64));
    rax = (word64)(WC_L64(r14, 72));
    rcx = (word64)(WC_L64(r14, 80));
    r8 = (word64)(WC_L64(r14, 88));
    r9 = (word64)(r8);
    r9 = (word64)(r9 >> 63);
    r9 = (word64)(r9 * 19);
    r8 = (word64)(r8 << 1);
    r8 = (word64)(r8 >> 1);
    r13 = (word64)(rdx);
    r13 = (word64)(r13 & r10);
    r13 = (word64)(r13 + r9);
    WC_S64(rbp, 1776) = (word64)(r13);
    rdx = (word64)((rdx >> 51) | (rax << 13));
    r9 = (word64)(rdx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1808) = (word64)(r9);
    rax = (word64)((rax >> 38) | (rcx << 26));
    r9 = (word64)(rax);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1840) = (word64)(r9);
    rcx = (word64)((rcx >> 25) | (r8 << 39));
    r9 = (word64)(rcx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1872) = (word64)(r9);
    r8 = (word64)(r8 >> 12);
    WC_S64(rbp, 1904) = (word64)(r8);
    rdx = (word64)(1);
    WC_S64(rbp, 1784) = (word64)(rdx);
    rdx = (word64)(0);
    WC_S64(rbp, 1816) = (word64)(rdx);
    WC_S64(rbp, 1848) = (word64)(rdx);
    WC_S64(rbp, 1880) = (word64)(rdx);
    WC_S64(rbp, 1912) = (word64)(rdx);
    if (((rsi & rsi)) == (0)) {
        goto L_ge_dsm_avx512_ifma_noswap_b;
    }
    y18 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1760));
    y19 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1792));
    y20 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1824));
    y21 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1856));
    y22 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1888));
    y18 = _mm256_permute4x64_epi64(y18, 0xe1);
    y19 = _mm256_permute4x64_epi64(y19, 0xe1);
    y20 = _mm256_permute4x64_epi64(y20, 0xe1);
    y21 = _mm256_permute4x64_epi64(y21, 0xe1);
    y22 = _mm256_permute4x64_epi64(y22, 0xe1);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1760), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1792), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1824), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1856), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1888), y22);
L_ge_dsm_avx512_ifma_noswap_b:
    /* To p3 */
    y18 = _mm256_permute4x64_epi64(y23, 0x24);
    y19 = _mm256_permute4x64_epi64(y24, 0x24);
    y20 = _mm256_permute4x64_epi64(y25, 0x24);
    y21 = _mm256_permute4x64_epi64(y26, 0x24);
    y22 = _mm256_permute4x64_epi64(y27, 0x24);
    y23 = _mm256_permute4x64_epi64(y23, 0x7b);
    y24 = _mm256_permute4x64_epi64(y24, 0x7b);
    y25 = _mm256_permute4x64_epi64(y25, 0x7b);
    y26 = _mm256_permute4x64_epi64(y26, 0x7b);
    y27 = _mm256_permute4x64_epi64(y27, 0x7b);
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_slli_epi64(y5, 4);
    y10 = _mm256_slli_epi64(y5, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y5);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_slli_epi64(y6, 4);
    y10 = _mm256_slli_epi64(y6, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y6);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_slli_epi64(y7, 4);
    y10 = _mm256_slli_epi64(y7, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y7);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_slli_epi64(y8, 4);
    y10 = _mm256_slli_epi64(y8, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y8);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_slli_epi64(y17, 4);
    y10 = _mm256_slli_epi64(y17, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y17);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* Add */
    y23 = _mm256_permute4x64_epi64(y18, 0xb0);
    y24 = _mm256_permute4x64_epi64(y19, 0xb0);
    y25 = _mm256_permute4x64_epi64(y20, 0xb0);
    y26 = _mm256_permute4x64_epi64(y21, 0xb0);
    y27 = _mm256_permute4x64_epi64(y22, 0xb0);
    y18 = _mm256_permute4x64_epi64(y18, 0xb5);
    y19 = _mm256_permute4x64_epi64(y19, 0xb5);
    y20 = _mm256_permute4x64_epi64(y20, 0xb5);
    y21 = _mm256_permute4x64_epi64(y21, 0xb5);
    y22 = _mm256_permute4x64_epi64(y22, 0xb5);
    y18 = _mm256_mask_blend_epi64(k5, y18, _mm256_add_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k5, y19, _mm256_add_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k5, y20, _mm256_add_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k5, y21, _mm256_add_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k5, y22, _mm256_add_epi64(y22, y27));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_add_epi64(y18, y29));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_add_epi64(y19, y30));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_add_epi64(y20, y30));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_add_epi64(y21, y30));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_add_epi64(y22, y30));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_sub_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_sub_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_sub_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_sub_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_sub_epi64(y22, y27));
    y0 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y1 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y2 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y3 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y4 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y4, y31);
    y19 = _mm256_add_epi64(y19, y0);
    y20 = _mm256_add_epi64(y20, y1);
    y21 = _mm256_add_epi64(y21, y2);
    y22 = _mm256_add_epi64(y22, y3);
    y23 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1760));
    y24 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1792));
    y25 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1824));
    y26 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1856));
    y27 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1888));
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_slli_epi64(y5, 4);
    y10 = _mm256_slli_epi64(y5, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y5);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_slli_epi64(y6, 4);
    y10 = _mm256_slli_epi64(y6, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y6);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_slli_epi64(y7, 4);
    y10 = _mm256_slli_epi64(y7, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y7);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_slli_epi64(y8, 4);
    y10 = _mm256_slli_epi64(y8, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y8);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_slli_epi64(y17, 4);
    y10 = _mm256_slli_epi64(y17, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y17);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* X3 = B - A, Y3 = B + A, Z3 = D + C, T3 = D - C */
    y23 = _mm256_permute4x64_epi64(y18, 0xf0);
    y24 = _mm256_permute4x64_epi64(y19, 0xf0);
    y25 = _mm256_permute4x64_epi64(y20, 0xf0);
    y26 = _mm256_permute4x64_epi64(y21, 0xf0);
    y27 = _mm256_permute4x64_epi64(y22, 0xf0);
    y23 = _mm256_mask_blend_epi64(k2, y23, _mm256_add_epi64(y23, y23));
    y24 = _mm256_mask_blend_epi64(k2, y24, _mm256_add_epi64(y24, y24));
    y25 = _mm256_mask_blend_epi64(k2, y25, _mm256_add_epi64(y25, y25));
    y26 = _mm256_mask_blend_epi64(k2, y26, _mm256_add_epi64(y26, y26));
    y27 = _mm256_mask_blend_epi64(k2, y27, _mm256_add_epi64(y27, y27));
    y0 = _mm256_permute4x64_epi64(y18, 0xa5);
    y1 = _mm256_permute4x64_epi64(y19, 0xa5);
    y2 = _mm256_permute4x64_epi64(y20, 0xa5);
    y3 = _mm256_permute4x64_epi64(y21, 0xa5);
    y4 = _mm256_permute4x64_epi64(y22, 0xa5);
    y18 = _mm256_add_epi64(y23, y0);
    y19 = _mm256_add_epi64(y24, y1);
    y20 = _mm256_add_epi64(y25, y2);
    y21 = _mm256_add_epi64(y26, y3);
    y22 = _mm256_add_epi64(y27, y4);
    y23 = _mm256_mask_blend_epi64(k3, y23, _mm256_add_epi64(y23, y29));
    y24 = _mm256_mask_blend_epi64(k3, y24, _mm256_add_epi64(y24, y30));
    y25 = _mm256_mask_blend_epi64(k3, y25, _mm256_add_epi64(y25, y30));
    y26 = _mm256_mask_blend_epi64(k3, y26, _mm256_add_epi64(y26, y30));
    y27 = _mm256_mask_blend_epi64(k3, y27, _mm256_add_epi64(y27, y30));
    y18 = _mm256_mask_blend_epi64(k3, y18, _mm256_sub_epi64(y23, y0));
    y19 = _mm256_mask_blend_epi64(k3, y19, _mm256_sub_epi64(y24, y1));
    y20 = _mm256_mask_blend_epi64(k3, y20, _mm256_sub_epi64(y25, y2));
    y21 = _mm256_mask_blend_epi64(k3, y21, _mm256_sub_epi64(y26, y3));
    y22 = _mm256_mask_blend_epi64(k3, y22, _mm256_sub_epi64(y27, y4));
    y5 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y6 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y7 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y8 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y9 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y9, y31);
    y19 = _mm256_add_epi64(y19, y5);
    y20 = _mm256_add_epi64(y20, y6);
    y21 = _mm256_add_epi64(y21, y7);
    y22 = _mm256_add_epi64(y22, y8);
    if (((rsi & rsi)) == (0)) {
        goto L_ge_dsm_avx512_ifma_nores_b;
    }
    y18 = _mm256_permute4x64_epi64(y18, 0xb4);
    y19 = _mm256_permute4x64_epi64(y19, 0xb4);
    y20 = _mm256_permute4x64_epi64(y20, 0xb4);
    y21 = _mm256_permute4x64_epi64(y21, 0xb4);
    y22 = _mm256_permute4x64_epi64(y22, 0xb4);
L_ge_dsm_avx512_ifma_nores_b:
    y23 = y18;
    y24 = y19;
    y25 = y20;
    y26 = y21;
    y27 = y22;
L_ge_dsm_avx512_ifma_skip_b:
    /* To p3 */
    y18 = _mm256_permute4x64_epi64(y23, 0x24);
    y19 = _mm256_permute4x64_epi64(y24, 0x24);
    y20 = _mm256_permute4x64_epi64(y25, 0x24);
    y21 = _mm256_permute4x64_epi64(y26, 0x24);
    y22 = _mm256_permute4x64_epi64(y27, 0x24);
    y23 = _mm256_permute4x64_epi64(y23, 0x7b);
    y24 = _mm256_permute4x64_epi64(y24, 0x7b);
    y25 = _mm256_permute4x64_epi64(y25, 0x7b);
    y26 = _mm256_permute4x64_epi64(y26, 0x7b);
    y27 = _mm256_permute4x64_epi64(y27, 0x7b);
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_slli_epi64(y5, 4);
    y10 = _mm256_slli_epi64(y5, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y5);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_slli_epi64(y6, 4);
    y10 = _mm256_slli_epi64(y6, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y6);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_slli_epi64(y7, 4);
    y10 = _mm256_slli_epi64(y7, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y7);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_slli_epi64(y8, 4);
    y10 = _mm256_slli_epi64(y8, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y8);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_slli_epi64(y17, 4);
    y10 = _mm256_slli_epi64(y17, 1);
    y9 = _mm256_add_epi64(y9, y10);
    y9 = _mm256_add_epi64(y9, y17);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    r11 = (word64)(r11 - 1);
    if ((sword64)(r11) >= (sword64)(0)) {
        goto L_ge_dsm_avx512_ifma_bits;
    }
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1600), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1632), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1664), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1696), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1728), y22);
    /* Convert X, Y and Z back to 4 x 64-bit field elements */
    r10 = (word64)(0x7ffffffffffff);
    rdx = (word64)(WC_L64(rbp, 1600));
    rax = (word64)(WC_L64(rbp, 1632));
    rcx = (word64)(WC_L64(rbp, 1664));
    r8 = (word64)(WC_L64(rbp, 1696));
    r9 = (word64)(WC_L64(rbp, 1728));
    r11 = (word64)(rdx);
    r11 = (word64)(r11 >> 51);
    rdx = (word64)(rdx & r10);
    rax = (word64)(rax + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 >> 51);
    rax = (word64)(rax & r10);
    rcx = (word64)(rcx + r11);
    r11 = (word64)(rcx);
    r11 = (word64)(r11 >> 51);
    rcx = (word64)(rcx & r10);
    r8 = (word64)(r8 + r11);
    r11 = (word64)(r8);
    r11 = (word64)(r11 >> 51);
    r8 = (word64)(r8 & r10);
    r9 = (word64)(r9 + r11);
    r11 = (word64)(r9);
    r11 = (word64)(r11 >> 51);
    r9 = (word64)(r9 & r10);
    r11 = (word64)(r11 * 19);
    rdx = (word64)(rdx + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 << 51);
    r12 = (word64)(rax);
    r12 = (word64)(r12 >> 13);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rdi, 0) = (word64)(rdx);
    r11 = (word64)(rcx);
    r11 = (word64)(r11 << 38);
    rdx = (word64)(rcx);
    rdx = (word64)(rdx >> 26);
    cf = _addcarry_u64(0, r12, r11, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    WC_S64(rdi, 8) = (word64)(r12);
    r11 = (word64)(r8);
    r11 = (word64)(r11 << 25);
    r12 = (word64)(r8);
    r12 = (word64)(r12 >> 39);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rdi, 16) = (word64)(rdx);
    r11 = (word64)(r9);
    r11 = (word64)(r11 << 12);
    r12 = (word64)(r12 + r11);
    WC_S64(rdi, 24) = (word64)(r12);
    rdx = (word64)(WC_L64(rbp, 1608));
    rax = (word64)(WC_L64(rbp, 1640));
    rcx = (word64)(WC_L64(rbp, 1672));
    r8 = (word64)(WC_L64(rbp, 1704));
    r9 = (word64)(WC_L64(rbp, 1736));
    r11 = (word64)(rdx);
    r11 = (word64)(r11 >> 51);
    rdx = (word64)(rdx & r10);
    rax = (word64)(rax + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 >> 51);
    rax = (word64)(rax & r10);
    rcx = (word64)(rcx + r11);
    r11 = (word64)(rcx);
    r11 = (word64)(r11 >> 51);
    rcx = (word64)(rcx & r10);
    r8 = (word64)(r8 + r11);
    r11 = (word64)(r8);
    r11 = (word64)(r11 >> 51);
    r8 = (word64)(r8 & r10);
    r9 = (word64)(r9 + r11);
    r11 = (word64)(r9);
    r11 = (word64)(r11 >> 51);
    r9 = (word64)(r9 & r10);
    r11 = (word64)(r11 * 19);
    rdx = (word64)(rdx + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 << 51);
    r12 = (word64)(rax);
    r12 = (word64)(r12 >> 13);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rdi, 32) = (word64)(rdx);
    r11 = (word64)(rcx);
    r11 = (word64)(r11 << 38);
    rdx = (word64)(rcx);
    rdx = (word64)(rdx >> 26);
    cf = _addcarry_u64(0, r12, r11, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    WC_S64(rdi, 40) = (word64)(r12);
    r11 = (word64)(r8);
    r11 = (word64)(r11 << 25);
    r12 = (word64)(r8);
    r12 = (word64)(r12 >> 39);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rdi, 48) = (word64)(rdx);
    r11 = (word64)(r9);
    r11 = (word64)(r11 << 12);
    r12 = (word64)(r12 + r11);
    WC_S64(rdi, 56) = (word64)(r12);
    rdx = (word64)(WC_L64(rbp, 1616));
    rax = (word64)(WC_L64(rbp, 1648));
    rcx = (word64)(WC_L64(rbp, 1680));
    r8 = (word64)(WC_L64(rbp, 1712));
    r9 = (word64)(WC_L64(rbp, 1744));
    r11 = (word64)(rdx);
    r11 = (word64)(r11 >> 51);
    rdx = (word64)(rdx & r10);
    rax = (word64)(rax + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 >> 51);
    rax = (word64)(rax & r10);
    rcx = (word64)(rcx + r11);
    r11 = (word64)(rcx);
    r11 = (word64)(r11 >> 51);
    rcx = (word64)(rcx & r10);
    r8 = (word64)(r8 + r11);
    r11 = (word64)(r8);
    r11 = (word64)(r11 >> 51);
    r8 = (word64)(r8 & r10);
    r9 = (word64)(r9 + r11);
    r11 = (word64)(r9);
    r11 = (word64)(r11 >> 51);
    r9 = (word64)(r9 & r10);
    r11 = (word64)(r11 * 19);
    rdx = (word64)(rdx + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 << 51);
    r12 = (word64)(rax);
    r12 = (word64)(r12 >> 13);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rdi, 64) = (word64)(rdx);
    r11 = (word64)(rcx);
    r11 = (word64)(r11 << 38);
    rdx = (word64)(rcx);
    rdx = (word64)(rdx >> 26);
    cf = _addcarry_u64(0, r12, r11, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    WC_S64(rdi, 72) = (word64)(r12);
    r11 = (word64)(r8);
    r11 = (word64)(r11 << 25);
    r12 = (word64)(r8);
    r12 = (word64)(r12 >> 39);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rdi, 80) = (word64)(rdx);
    r11 = (word64)(r9);
    r11 = (word64)(r11 << 12);
    r12 = (word64)(r12 + r11);
    WC_S64(rdi, 88) = (word64)(r12);
    rax = (word64)(0);
    return (int)(word32)rax;
    (void)k7;
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WC_X64I_TARGET("avx512f,avx512vl,avx512ifma,avx512dq")
#if defined(HAVE_ED25519) || defined(WOLFSSL_CURVE25519_USE_ED25519)
WOLFSSL_LOCAL int ge_double_scalarmult_vartime_avx512_ifma_dq(ge_p2* r,
#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */
    const byte* a, const ge_p3* A, const byte* b, const ge_precomp* bi,
    byte* buf)
{
    word64 rdi, rsi, r14, r15, rbx, rbp, rdx, r11, rax = 0, rcx = 0, r12 = 0,
           r8 = 0, r9 = 0, r10 = 0, r13 = 0;
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y4 = _mm256_setzero_si256(), y5 = _mm256_setzero_si256(),
            y6 = _mm256_setzero_si256(), y7 = _mm256_setzero_si256(),
            y8 = _mm256_setzero_si256(), y9 = _mm256_setzero_si256(),
            y10 = _mm256_setzero_si256(), y11 = _mm256_setzero_si256(),
            y12 = _mm256_setzero_si256(), y13 = _mm256_setzero_si256(),
            y14 = _mm256_setzero_si256(), y15 = _mm256_setzero_si256(),
            y16 = _mm256_setzero_si256(), y17 = _mm256_setzero_si256(),
            y18 = _mm256_setzero_si256(), y19 = _mm256_setzero_si256(),
            y20 = _mm256_setzero_si256(), y21 = _mm256_setzero_si256(),
            y22 = _mm256_setzero_si256(), y23 = _mm256_setzero_si256(),
            y24 = _mm256_setzero_si256(), y25 = _mm256_setzero_si256(),
            y26 = _mm256_setzero_si256(), y27 = _mm256_setzero_si256(),
            y28 = _mm256_setzero_si256(), y29 = _mm256_setzero_si256(),
            y30 = _mm256_setzero_si256(), y31 = _mm256_setzero_si256();
    __mmask16 k1, k2, k3, k4, k5, k6, k7;
    unsigned char cf;

    rdi = (word64)(size_t)r;
    rsi = (word64)(size_t)a;
    r14 = (word64)(size_t)A;
    r15 = (word64)(size_t)b;
    rbx = (word64)(size_t)bi;
    rbp = (word64)(size_t)buf;

    /* Window digits of the scalar multiplying A */
    /* One digit per bit of the scalar */
    rdx = (word64)(0);
    r11 = (word64)(0);
L_ge_dsm_dq_a_avx512_ifma_slide_bytes:
    rax = (word64)((word64)WC_L8(rsi, r11));
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 1920) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 1920) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 1920) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 1920) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 1920) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 1920) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 1920) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 1920) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    r11 = (word64)(r11 + 1);
    if ((r11) != (0x20)) {
        goto L_ge_dsm_dq_a_avx512_ifma_slide_bytes;
    }
    /* Fold each run of digits down to one odd digit */
    r11 = (word64)(0);
L_ge_dsm_dq_a_avx512_ifma_slide_digit:
    rcx = (word64)((word64)(sword64)(signed char)WC_L8(rbp, r11 + 1920));
    if (((rcx & rcx)) == (0)) {
        goto L_ge_dsm_dq_a_avx512_ifma_slide_next_digit;
    }
    r12 = (word64)(1);
L_ge_dsm_dq_a_avx512_ifma_slide_window:
    rdx = (word64)(r11);
    rdx = (word64)(rdx + r12);
    if ((sword64)(rdx) >= (sword64)(0x100)) {
        goto L_ge_dsm_dq_a_avx512_ifma_slide_next_digit;
    }
    r8 = (word64)((word64)(sword64)(signed char)WC_L8(rbp, rdx + 1920));
    if (((r8 & r8)) == (0)) {
        goto L_ge_dsm_dq_a_avx512_ifma_slide_next_window;
    }
    /* Weight of the digit at i + b, relative to the one at i */
    r9 = (word64)(r8);
    r8 = (word64)(r12);
L_ge_dsm_dq_a_avx512_ifma_slide_shift:
    r9 = (word64)(r9 + r9);
    r8 = (word64)(r8 - 1);
    if ((r8) != (0)) {
        goto L_ge_dsm_dq_a_avx512_ifma_slide_shift;
    }
    r9 = (word64)((word64)(sword64)(signed char)(byte)r9);
    /* Fold it in if the digit at i stays within range */
    r10 = (word64)(rcx);
    r10 = (word64)(r10 + r9);
    if ((sword64)(r10) > (sword64)(0xf)) {
        goto L_ge_dsm_dq_a_avx512_ifma_slide_sub;
    }
    rcx = (word64)(r10);
    WC_S8(rbp, r11 + 1920) = (byte)((byte)rcx);
    WC_S8(rbp, rdx + 1920) = (byte)(0);
    goto L_ge_dsm_dq_a_avx512_ifma_slide_next_window;
L_ge_dsm_dq_a_avx512_ifma_slide_sub:
    r10 = (word64)(rcx);
    r10 = (word64)(r10 - r9);
    if ((sword64)(r10) < (sword64)(-15)) {
        goto L_ge_dsm_dq_a_avx512_ifma_slide_next_digit;
    }
    rcx = (word64)(r10);
    WC_S8(rbp, r11 + 1920) = (byte)((byte)rcx);
    /* Subtracting it borrows from the digits above */
L_ge_dsm_dq_a_avx512_ifma_slide_carry:
    if ((sword64)(rdx) >= (sword64)(0x100)) {
        goto L_ge_dsm_dq_a_avx512_ifma_slide_next_window;
    }
    r10 = (word64)((word64)(sword64)(signed char)WC_L8(rbp, rdx + 1920));
    if (((r10 & r10)) == (0)) {
        goto L_ge_dsm_dq_a_avx512_ifma_slide_set;
    }
    WC_S8(rbp, rdx + 1920) = (byte)(0);
    rdx = (word64)(rdx + 1);
    goto L_ge_dsm_dq_a_avx512_ifma_slide_carry;
L_ge_dsm_dq_a_avx512_ifma_slide_set:
    WC_S8(rbp, rdx + 1920) = (byte)(1);
L_ge_dsm_dq_a_avx512_ifma_slide_next_window:
    r12 = (word64)(r12 + 1);
    if ((sword64)(r12) <= (sword64)(6)) {
        goto L_ge_dsm_dq_a_avx512_ifma_slide_window;
    }
L_ge_dsm_dq_a_avx512_ifma_slide_next_digit:
    r11 = (word64)(r11 + 1);
    if ((sword64)(r11) < (sword64)(0x100)) {
        goto L_ge_dsm_dq_a_avx512_ifma_slide_digit;
    }
    /* Window digits of the base point scalar */
    /* One digit per bit of the scalar */
    rdx = (word64)(0);
    r11 = (word64)(0);
L_ge_dsm_dq_b_avx512_ifma_slide_bytes:
    rax = (word64)((word64)WC_L8(r15, r11));
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 2176) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 2176) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 2176) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 2176) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 2176) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 2176) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 2176) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    rcx = (word64)(rax);
    rcx = (word64)(rcx & 1);
    WC_S8(rbp, rdx + 2176) = (byte)((byte)rcx);
    rax = (word64)(rax >> 1);
    rdx = (word64)(rdx + 1);
    r11 = (word64)(r11 + 1);
    if ((r11) != (0x20)) {
        goto L_ge_dsm_dq_b_avx512_ifma_slide_bytes;
    }
    /* Fold each run of digits down to one odd digit */
    r11 = (word64)(0);
L_ge_dsm_dq_b_avx512_ifma_slide_digit:
    rcx = (word64)((word64)(sword64)(signed char)WC_L8(rbp, r11 + 2176));
    if (((rcx & rcx)) == (0)) {
        goto L_ge_dsm_dq_b_avx512_ifma_slide_next_digit;
    }
    r12 = (word64)(1);
L_ge_dsm_dq_b_avx512_ifma_slide_window:
    rdx = (word64)(r11);
    rdx = (word64)(rdx + r12);
    if ((sword64)(rdx) >= (sword64)(0x100)) {
        goto L_ge_dsm_dq_b_avx512_ifma_slide_next_digit;
    }
    r8 = (word64)((word64)(sword64)(signed char)WC_L8(rbp, rdx + 2176));
    if (((r8 & r8)) == (0)) {
        goto L_ge_dsm_dq_b_avx512_ifma_slide_next_window;
    }
    /* Weight of the digit at i + b, relative to the one at i */
    r9 = (word64)(r8);
    r8 = (word64)(r12);
L_ge_dsm_dq_b_avx512_ifma_slide_shift:
    r9 = (word64)(r9 + r9);
    r8 = (word64)(r8 - 1);
    if ((r8) != (0)) {
        goto L_ge_dsm_dq_b_avx512_ifma_slide_shift;
    }
    r9 = (word64)((word64)(sword64)(signed char)(byte)r9);
    /* Fold it in if the digit at i stays within range */
    r10 = (word64)(rcx);
    r10 = (word64)(r10 + r9);
    if ((sword64)(r10) > (sword64)(0x3f)) {
        goto L_ge_dsm_dq_b_avx512_ifma_slide_sub;
    }
    rcx = (word64)(r10);
    WC_S8(rbp, r11 + 2176) = (byte)((byte)rcx);
    WC_S8(rbp, rdx + 2176) = (byte)(0);
    goto L_ge_dsm_dq_b_avx512_ifma_slide_next_window;
L_ge_dsm_dq_b_avx512_ifma_slide_sub:
    r10 = (word64)(rcx);
    r10 = (word64)(r10 - r9);
    if ((sword64)(r10) < (sword64)(-63)) {
        goto L_ge_dsm_dq_b_avx512_ifma_slide_next_digit;
    }
    rcx = (word64)(r10);
    WC_S8(rbp, r11 + 2176) = (byte)((byte)rcx);
    /* Subtracting it borrows from the digits above */
L_ge_dsm_dq_b_avx512_ifma_slide_carry:
    if ((sword64)(rdx) >= (sword64)(0x100)) {
        goto L_ge_dsm_dq_b_avx512_ifma_slide_next_window;
    }
    r10 = (word64)((word64)(sword64)(signed char)WC_L8(rbp, rdx + 2176));
    if (((r10 & r10)) == (0)) {
        goto L_ge_dsm_dq_b_avx512_ifma_slide_set;
    }
    WC_S8(rbp, rdx + 2176) = (byte)(0);
    rdx = (word64)(rdx + 1);
    goto L_ge_dsm_dq_b_avx512_ifma_slide_carry;
L_ge_dsm_dq_b_avx512_ifma_slide_set:
    WC_S8(rbp, rdx + 2176) = (byte)(1);
L_ge_dsm_dq_b_avx512_ifma_slide_next_window:
    r12 = (word64)(r12 + 1);
    if ((sword64)(r12) <= (sword64)(6)) {
        goto L_ge_dsm_dq_b_avx512_ifma_slide_window;
    }
L_ge_dsm_dq_b_avx512_ifma_slide_next_digit:
    r11 = (word64)(r11 + 1);
    if ((sword64)(r11) < (sword64)(0x100)) {
        goto L_ge_dsm_dq_b_avx512_ifma_slide_digit;
    }
    r15 = (word64)((word64)(size_t)L_ge_ifma_consts);
    y28 = _mm256_set1_epi64x((long long)WC_L64(r15, 0));
    y29 = _mm256_set1_epi64x((long long)WC_L64(r15, 8));
    y30 = _mm256_set1_epi64x((long long)WC_L64(r15, 16));
    y31 = _mm256_set1_epi64x((long long)WC_L64(r15, 24));
    r9 = (word32)(8);
    k1 = (__mmask16)(word32)r9;
    r9 = (word32)(0xc);
    k2 = (__mmask16)(word32)r9;
    r9 = (word32)(9);
    k3 = (__mmask16)(word32)r9;
    r9 = (word32)(6);
    k4 = (__mmask16)(word32)r9;
    r9 = (word32)(1);
    k5 = (__mmask16)(word32)r9;
    r9 = (word32)(2);
    k6 = (__mmask16)(word32)r9;
    r9 = (word32)(4);
    k7 = (__mmask16)(word32)r9;
    /* Odd multiples of A, cached and in limb form */
    r10 = (word64)(0x7ffffffffffff);
    /* A in limb form: [X, Y, Z, T] */
    rdx = (word64)(WC_L64(r14, 0));
    rax = (word64)(WC_L64(r14, 8));
    rcx = (word64)(WC_L64(r14, 16));
    r8 = (word64)(WC_L64(r14, 24));
    r9 = (word64)(r8);
    r9 = (word64)(r9 >> 63);
    r9 = (word64)(r9 * 19);
    r8 = (word64)(r8 << 1);
    r8 = (word64)(r8 >> 1);
    r13 = (word64)(rdx);
    r13 = (word64)(r13 & r10);
    r13 = (word64)(r13 + r9);
    WC_S64(rbp, 1440) = (word64)(r13);
    rdx = (word64)((rdx >> 51) | (rax << 13));
    r9 = (word64)(rdx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1472) = (word64)(r9);
    rax = (word64)((rax >> 38) | (rcx << 26));
    r9 = (word64)(rax);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1504) = (word64)(r9);
    rcx = (word64)((rcx >> 25) | (r8 << 39));
    r9 = (word64)(rcx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1536) = (word64)(r9);
    r8 = (word64)(r8 >> 12);
    WC_S64(rbp, 1568) = (word64)(r8);
    rdx = (word64)(WC_L64(r14, 32));
    rax = (word64)(WC_L64(r14, 40));
    rcx = (word64)(WC_L64(r14, 48));
    r8 = (word64)(WC_L64(r14, 56));
    r9 = (word64)(r8);
    r9 = (word64)(r9 >> 63);
    r9 = (word64)(r9 * 19);
    r8 = (word64)(r8 << 1);
    r8 = (word64)(r8 >> 1);
    r13 = (word64)(rdx);
    r13 = (word64)(r13 & r10);
    r13 = (word64)(r13 + r9);
    WC_S64(rbp, 1448) = (word64)(r13);
    rdx = (word64)((rdx >> 51) | (rax << 13));
    r9 = (word64)(rdx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1480) = (word64)(r9);
    rax = (word64)((rax >> 38) | (rcx << 26));
    r9 = (word64)(rax);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1512) = (word64)(r9);
    rcx = (word64)((rcx >> 25) | (r8 << 39));
    r9 = (word64)(rcx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1544) = (word64)(r9);
    r8 = (word64)(r8 >> 12);
    WC_S64(rbp, 1576) = (word64)(r8);
    rdx = (word64)(WC_L64(r14, 64));
    rax = (word64)(WC_L64(r14, 72));
    rcx = (word64)(WC_L64(r14, 80));
    r8 = (word64)(WC_L64(r14, 88));
    r9 = (word64)(r8);
    r9 = (word64)(r9 >> 63);
    r9 = (word64)(r9 * 19);
    r8 = (word64)(r8 << 1);
    r8 = (word64)(r8 >> 1);
    r13 = (word64)(rdx);
    r13 = (word64)(r13 & r10);
    r13 = (word64)(r13 + r9);
    WC_S64(rbp, 1456) = (word64)(r13);
    rdx = (word64)((rdx >> 51) | (rax << 13));
    r9 = (word64)(rdx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1488) = (word64)(r9);
    rax = (word64)((rax >> 38) | (rcx << 26));
    r9 = (word64)(rax);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1520) = (word64)(r9);
    rcx = (word64)((rcx >> 25) | (r8 << 39));
    r9 = (word64)(rcx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1552) = (word64)(r9);
    r8 = (word64)(r8 >> 12);
    WC_S64(rbp, 1584) = (word64)(r8);
    rdx = (word64)(WC_L64(r14, 96));
    rax = (word64)(WC_L64(r14, 104));
    rcx = (word64)(WC_L64(r14, 112));
    r8 = (word64)(WC_L64(r14, 120));
    r9 = (word64)(r8);
    r9 = (word64)(r9 >> 63);
    r9 = (word64)(r9 * 19);
    r8 = (word64)(r8 << 1);
    r8 = (word64)(r8 >> 1);
    r13 = (word64)(rdx);
    r13 = (word64)(r13 & r10);
    r13 = (word64)(r13 + r9);
    WC_S64(rbp, 1464) = (word64)(r13);
    rdx = (word64)((rdx >> 51) | (rax << 13));
    r9 = (word64)(rdx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1496) = (word64)(r9);
    rax = (word64)((rax >> 38) | (rcx << 26));
    r9 = (word64)(rax);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1528) = (word64)(r9);
    rcx = (word64)((rcx >> 25) | (r8 << 39));
    r9 = (word64)(rcx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1560) = (word64)(r9);
    r8 = (word64)(r8 >> 12);
    WC_S64(rbp, 1592) = (word64)(r8);
    /* Ai[0] = A */
    y18 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1440));
    y19 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1472));
    y20 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1504));
    y21 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1536));
    y22 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1568));
    /* To cached */
    y23 = _mm256_permute4x64_epi64(y18, 0xb0);
    y24 = _mm256_permute4x64_epi64(y19, 0xb0);
    y25 = _mm256_permute4x64_epi64(y20, 0xb0);
    y26 = _mm256_permute4x64_epi64(y21, 0xb0);
    y27 = _mm256_permute4x64_epi64(y22, 0xb0);
    y18 = _mm256_permute4x64_epi64(y18, 0xb5);
    y19 = _mm256_permute4x64_epi64(y19, 0xb5);
    y20 = _mm256_permute4x64_epi64(y20, 0xb5);
    y21 = _mm256_permute4x64_epi64(y21, 0xb5);
    y22 = _mm256_permute4x64_epi64(y22, 0xb5);
    y18 = _mm256_mask_blend_epi64(k5, y18, _mm256_add_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k5, y19, _mm256_add_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k5, y20, _mm256_add_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k5, y21, _mm256_add_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k5, y22, _mm256_add_epi64(y22, y27));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_add_epi64(y18, y29));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_add_epi64(y19, y30));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_add_epi64(y20, y30));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_add_epi64(y21, y30));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_add_epi64(y22, y30));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_sub_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_sub_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_sub_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_sub_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_sub_epi64(y22, y27));
    y0 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y1 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y2 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y3 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y4 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y4, y31);
    y19 = _mm256_add_epi64(y19, y0);
    y20 = _mm256_add_epi64(y20, y1);
    y21 = _mm256_add_epi64(y21, y2);
    y22 = _mm256_add_epi64(y22, y3);
    y23 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 32));
    y24 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 64));
    y25 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 96));
    y26 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 128));
    y27 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 160));
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_mullo_epi64(y5, y31);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_mullo_epi64(y6, y31);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_mullo_epi64(y7, y31);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_mullo_epi64(y8, y31);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_mullo_epi64(y17, y31);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 0), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 32), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 64), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 96), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 128), y22);
    /* A2 = 2.A */
    y18 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1440));
    y19 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1472));
    y20 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1504));
    y21 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1536));
    y22 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1568));
    /* Double */
    y23 = _mm256_permute4x64_epi64(y18, 0x64);
    y24 = _mm256_permute4x64_epi64(y19, 0x64);
    y25 = _mm256_permute4x64_epi64(y20, 0x64);
    y26 = _mm256_permute4x64_epi64(y21, 0x64);
    y27 = _mm256_permute4x64_epi64(y22, 0x64);
    y18 = _mm256_permute4x64_epi64(y18, 0x24);
    y19 = _mm256_permute4x64_epi64(y19, 0x24);
    y20 = _mm256_permute4x64_epi64(y20, 0x24);
    y21 = _mm256_permute4x64_epi64(y21, 0x24);
    y22 = _mm256_permute4x64_epi64(y22, 0x24);
    y18 = _mm256_mask_blend_epi64(k1, y18, _mm256_add_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k1, y19, _mm256_add_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k1, y20, _mm256_add_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k1, y21, _mm256_add_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k1, y22, _mm256_add_epi64(y22, y27));
    y0 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y1 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y2 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y3 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y4 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y4, y31);
    y19 = _mm256_add_epi64(y19, y0);
    y20 = _mm256_add_epi64(y20, y1);
    y21 = _mm256_add_epi64(y21, y2);
    y22 = _mm256_add_epi64(y22, y3);
    y23 = y18;
    y24 = y19;
    y25 = y20;
    y26 = y21;
    y27 = y22;
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_mullo_epi64(y5, y31);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_mullo_epi64(y6, y31);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_mullo_epi64(y7, y31);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_mullo_epi64(y8, y31);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_mullo_epi64(y17, y31);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* Y3 = YY + XX, Z3 = YY - XX */
    y23 = _mm256_permute4x64_epi64(y18, 0x55);
    y24 = _mm256_permute4x64_epi64(y19, 0x55);
    y25 = _mm256_permute4x64_epi64(y20, 0x55);
    y26 = _mm256_permute4x64_epi64(y21, 0x55);
    y27 = _mm256_permute4x64_epi64(y22, 0x55);
    y0 = _mm256_permute4x64_epi64(y18, 0);
    y1 = _mm256_permute4x64_epi64(y19, 0);
    y2 = _mm256_permute4x64_epi64(y20, 0);
    y3 = _mm256_permute4x64_epi64(y21, 0);
    y4 = _mm256_permute4x64_epi64(y22, 0);
    y5 = _mm256_add_epi64(y23, y0);
    y6 = _mm256_add_epi64(y24, y1);
    y7 = _mm256_add_epi64(y25, y2);
    y8 = _mm256_add_epi64(y26, y3);
    y9 = _mm256_add_epi64(y27, y4);
    y23 = _mm256_mask_blend_epi64(k2, y23, _mm256_add_epi64(y23, y29));
    y24 = _mm256_mask_blend_epi64(k2, y24, _mm256_add_epi64(y24, y30));
    y25 = _mm256_mask_blend_epi64(k2, y25, _mm256_add_epi64(y25, y30));
    y26 = _mm256_mask_blend_epi64(k2, y26, _mm256_add_epi64(y26, y30));
    y27 = _mm256_mask_blend_epi64(k2, y27, _mm256_add_epi64(y27, y30));
    y5 = _mm256_mask_blend_epi64(k2, y5, _mm256_sub_epi64(y23, y0));
    y6 = _mm256_mask_blend_epi64(k2, y6, _mm256_sub_epi64(y24, y1));
    y7 = _mm256_mask_blend_epi64(k2, y7, _mm256_sub_epi64(y25, y2));
    y8 = _mm256_mask_blend_epi64(k2, y8, _mm256_sub_epi64(y26, y3));
    y9 = _mm256_mask_blend_epi64(k2, y9, _mm256_sub_epi64(y27, y4));
    y23 = _mm256_srli_epi64(y5, 51);
    y5 = _mm256_and_si256(y5, y28);
    y24 = _mm256_srli_epi64(y6, 51);
    y6 = _mm256_and_si256(y6, y28);
    y25 = _mm256_srli_epi64(y7, 51);
    y7 = _mm256_and_si256(y7, y28);
    y26 = _mm256_srli_epi64(y8, 51);
    y8 = _mm256_and_si256(y8, y28);
    y27 = _mm256_srli_epi64(y9, 51);
    y9 = _mm256_and_si256(y9, y28);
    y5 = _mm256_madd52lo_epu64(y5, y27, y31);
    y6 = _mm256_add_epi64(y6, y23);
    y7 = _mm256_add_epi64(y7, y24);
    y8 = _mm256_add_epi64(y8, y25);
    y9 = _mm256_add_epi64(y9, y26);
    /* X3 = AA - Y3, T3 = 2.ZZ - Z3 */
    y23 = _mm256_permute4x64_epi64(y18, 0xaf);
    y24 = _mm256_permute4x64_epi64(y19, 0xaf);
    y25 = _mm256_permute4x64_epi64(y20, 0xaf);
    y26 = _mm256_permute4x64_epi64(y21, 0xaf);
    y27 = _mm256_permute4x64_epi64(y22, 0xaf);
    y23 = _mm256_mask_blend_epi64(k2, y23, _mm256_add_epi64(y23, y23));
    y24 = _mm256_mask_blend_epi64(k2, y24, _mm256_add_epi64(y24, y24));
    y25 = _mm256_mask_blend_epi64(k2, y25, _mm256_add_epi64(y25, y25));
    y26 = _mm256_mask_blend_epi64(k2, y26, _mm256_add_epi64(y26, y26));
    y27 = _mm256_mask_blend_epi64(k2, y27, _mm256_add_epi64(y27, y27));
    y23 = _mm256_mask_blend_epi64(k3, y23, _mm256_add_epi64(y23, y29));
    y24 = _mm256_mask_blend_epi64(k3, y24, _mm256_add_epi64(y24, y30));
    y25 = _mm256_mask_blend_epi64(k3, y25, _mm256_add_epi64(y25, y30));
    y26 = _mm256_mask_blend_epi64(k3, y26, _mm256_add_epi64(y26, y30));
    y27 = _mm256_mask_blend_epi64(k3, y27, _mm256_add_epi64(y27, y30));
    y23 = _mm256_mask_blend_epi64(k3, y23, _mm256_sub_epi64(y23, y5));
    y24 = _mm256_mask_blend_epi64(k3, y24, _mm256_sub_epi64(y24, y6));
    y25 = _mm256_mask_blend_epi64(k3, y25, _mm256_sub_epi64(y25, y7));
    y26 = _mm256_mask_blend_epi64(k3, y26, _mm256_sub_epi64(y26, y8));
    y27 = _mm256_mask_blend_epi64(k3, y27, _mm256_sub_epi64(y27, y9));
    y0 = _mm256_srli_epi64(y23, 51);
    y23 = _mm256_and_si256(y23, y28);
    y1 = _mm256_srli_epi64(y24, 51);
    y24 = _mm256_and_si256(y24, y28);
    y2 = _mm256_srli_epi64(y25, 51);
    y25 = _mm256_and_si256(y25, y28);
    y3 = _mm256_srli_epi64(y26, 51);
    y26 = _mm256_and_si256(y26, y28);
    y4 = _mm256_srli_epi64(y27, 51);
    y27 = _mm256_and_si256(y27, y28);
    y23 = _mm256_madd52lo_epu64(y23, y4, y31);
    y24 = _mm256_add_epi64(y24, y0);
    y25 = _mm256_add_epi64(y25, y1);
    y26 = _mm256_add_epi64(y26, y2);
    y27 = _mm256_add_epi64(y27, y3);
    y23 = _mm256_mask_blend_epi64(k4, y23, y5);
    y24 = _mm256_mask_blend_epi64(k4, y24, y6);
    y25 = _mm256_mask_blend_epi64(k4, y25, y7);
    y26 = _mm256_mask_blend_epi64(k4, y26, y8);
    y27 = _mm256_mask_blend_epi64(k4, y27, y9);
    /* To p3 */
    y18 = _mm256_permute4x64_epi64(y23, 0x24);
    y19 = _mm256_permute4x64_epi64(y24, 0x24);
    y20 = _mm256_permute4x64_epi64(y25, 0x24);
    y21 = _mm256_permute4x64_epi64(y26, 0x24);
    y22 = _mm256_permute4x64_epi64(y27, 0x24);
    y23 = _mm256_permute4x64_epi64(y23, 0x7b);
    y24 = _mm256_permute4x64_epi64(y24, 0x7b);
    y25 = _mm256_permute4x64_epi64(y25, 0x7b);
    y26 = _mm256_permute4x64_epi64(y26, 0x7b);
    y27 = _mm256_permute4x64_epi64(y27, 0x7b);
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_mullo_epi64(y5, y31);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_mullo_epi64(y6, y31);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_mullo_epi64(y7, y31);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_mullo_epi64(y8, y31);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_mullo_epi64(y17, y31);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1280), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1312), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1344), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1376), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1408), y22);
    /* Ai[j] = A2 + Ai[j-1] */
    r12 = (word64)(rbp);
    r11 = (word64)(7);
L_ge_dsm_dq_avx512_ifma_table:
    y18 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1280));
    y19 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1312));
    y20 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1344));
    y21 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1376));
    y22 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1408));
    /* Add */
    y23 = _mm256_permute4x64_epi64(y18, 0xb0);
    y24 = _mm256_permute4x64_epi64(y19, 0xb0);
    y25 = _mm256_permute4x64_epi64(y20, 0xb0);
    y26 = _mm256_permute4x64_epi64(y21, 0xb0);
    y27 = _mm256_permute4x64_epi64(y22, 0xb0);
    y18 = _mm256_permute4x64_epi64(y18, 0xb5);
    y19 = _mm256_permute4x64_epi64(y19, 0xb5);
    y20 = _mm256_permute4x64_epi64(y20, 0xb5);
    y21 = _mm256_permute4x64_epi64(y21, 0xb5);
    y22 = _mm256_permute4x64_epi64(y22, 0xb5);
    y18 = _mm256_mask_blend_epi64(k5, y18, _mm256_add_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k5, y19, _mm256_add_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k5, y20, _mm256_add_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k5, y21, _mm256_add_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k5, y22, _mm256_add_epi64(y22, y27));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_add_epi64(y18, y29));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_add_epi64(y19, y30));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_add_epi64(y20, y30));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_add_epi64(y21, y30));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_add_epi64(y22, y30));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_sub_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_sub_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_sub_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_sub_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_sub_epi64(y22, y27));
    y0 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y1 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y2 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y3 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y4 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y4, y31);
    y19 = _mm256_add_epi64(y19, y0);
    y20 = _mm256_add_epi64(y20, y1);
    y21 = _mm256_add_epi64(y21, y2);
    y22 = _mm256_add_epi64(y22, y3);
    y23 = _mm256_loadu_si256((const __m256i*)WC_PR(r12, 0));
    y24 = _mm256_loadu_si256((const __m256i*)WC_PR(r12, 32));
    y25 = _mm256_loadu_si256((const __m256i*)WC_PR(r12, 64));
    y26 = _mm256_loadu_si256((const __m256i*)WC_PR(r12, 96));
    y27 = _mm256_loadu_si256((const __m256i*)WC_PR(r12, 128));
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_mullo_epi64(y5, y31);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_mullo_epi64(y6, y31);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_mullo_epi64(y7, y31);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_mullo_epi64(y8, y31);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_mullo_epi64(y17, y31);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* X3 = B - A, Y3 = B + A, Z3 = D + C, T3 = D - C */
    y23 = _mm256_permute4x64_epi64(y18, 0xf0);
    y24 = _mm256_permute4x64_epi64(y19, 0xf0);
    y25 = _mm256_permute4x64_epi64(y20, 0xf0);
    y26 = _mm256_permute4x64_epi64(y21, 0xf0);
    y27 = _mm256_permute4x64_epi64(y22, 0xf0);
    y23 = _mm256_mask_blend_epi64(k2, y23, _mm256_add_epi64(y23, y23));
    y24 = _mm256_mask_blend_epi64(k2, y24, _mm256_add_epi64(y24, y24));
    y25 = _mm256_mask_blend_epi64(k2, y25, _mm256_add_epi64(y25, y25));
    y26 = _mm256_mask_blend_epi64(k2, y26, _mm256_add_epi64(y26, y26));
    y27 = _mm256_mask_blend_epi64(k2, y27, _mm256_add_epi64(y27, y27));
    y0 = _mm256_permute4x64_epi64(y18, 0xa5);
    y1 = _mm256_permute4x64_epi64(y19, 0xa5);
    y2 = _mm256_permute4x64_epi64(y20, 0xa5);
    y3 = _mm256_permute4x64_epi64(y21, 0xa5);
    y4 = _mm256_permute4x64_epi64(y22, 0xa5);
    y18 = _mm256_add_epi64(y23, y0);
    y19 = _mm256_add_epi64(y24, y1);
    y20 = _mm256_add_epi64(y25, y2);
    y21 = _mm256_add_epi64(y26, y3);
    y22 = _mm256_add_epi64(y27, y4);
    y23 = _mm256_mask_blend_epi64(k3, y23, _mm256_add_epi64(y23, y29));
    y24 = _mm256_mask_blend_epi64(k3, y24, _mm256_add_epi64(y24, y30));
    y25 = _mm256_mask_blend_epi64(k3, y25, _mm256_add_epi64(y25, y30));
    y26 = _mm256_mask_blend_epi64(k3, y26, _mm256_add_epi64(y26, y30));
    y27 = _mm256_mask_blend_epi64(k3, y27, _mm256_add_epi64(y27, y30));
    y18 = _mm256_mask_blend_epi64(k3, y18, _mm256_sub_epi64(y23, y0));
    y19 = _mm256_mask_blend_epi64(k3, y19, _mm256_sub_epi64(y24, y1));
    y20 = _mm256_mask_blend_epi64(k3, y20, _mm256_sub_epi64(y25, y2));
    y21 = _mm256_mask_blend_epi64(k3, y21, _mm256_sub_epi64(y26, y3));
    y22 = _mm256_mask_blend_epi64(k3, y22, _mm256_sub_epi64(y27, y4));
    y5 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y6 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y7 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y8 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y9 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y9, y31);
    y19 = _mm256_add_epi64(y19, y5);
    y20 = _mm256_add_epi64(y20, y6);
    y21 = _mm256_add_epi64(y21, y7);
    y22 = _mm256_add_epi64(y22, y8);
    y23 = y18;
    y24 = y19;
    y25 = y20;
    y26 = y21;
    y27 = y22;
    /* To p3 */
    y18 = _mm256_permute4x64_epi64(y23, 0x24);
    y19 = _mm256_permute4x64_epi64(y24, 0x24);
    y20 = _mm256_permute4x64_epi64(y25, 0x24);
    y21 = _mm256_permute4x64_epi64(y26, 0x24);
    y22 = _mm256_permute4x64_epi64(y27, 0x24);
    y23 = _mm256_permute4x64_epi64(y23, 0x7b);
    y24 = _mm256_permute4x64_epi64(y24, 0x7b);
    y25 = _mm256_permute4x64_epi64(y25, 0x7b);
    y26 = _mm256_permute4x64_epi64(y26, 0x7b);
    y27 = _mm256_permute4x64_epi64(y27, 0x7b);
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_mullo_epi64(y5, y31);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_mullo_epi64(y6, y31);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_mullo_epi64(y7, y31);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_mullo_epi64(y8, y31);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_mullo_epi64(y17, y31);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    r12 = (word64)(r12 + 0xa0);
    /* To cached */
    y23 = _mm256_permute4x64_epi64(y18, 0xb0);
    y24 = _mm256_permute4x64_epi64(y19, 0xb0);
    y25 = _mm256_permute4x64_epi64(y20, 0xb0);
    y26 = _mm256_permute4x64_epi64(y21, 0xb0);
    y27 = _mm256_permute4x64_epi64(y22, 0xb0);
    y18 = _mm256_permute4x64_epi64(y18, 0xb5);
    y19 = _mm256_permute4x64_epi64(y19, 0xb5);
    y20 = _mm256_permute4x64_epi64(y20, 0xb5);
    y21 = _mm256_permute4x64_epi64(y21, 0xb5);
    y22 = _mm256_permute4x64_epi64(y22, 0xb5);
    y18 = _mm256_mask_blend_epi64(k5, y18, _mm256_add_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k5, y19, _mm256_add_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k5, y20, _mm256_add_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k5, y21, _mm256_add_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k5, y22, _mm256_add_epi64(y22, y27));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_add_epi64(y18, y29));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_add_epi64(y19, y30));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_add_epi64(y20, y30));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_add_epi64(y21, y30));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_add_epi64(y22, y30));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_sub_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_sub_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_sub_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_sub_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_sub_epi64(y22, y27));
    y0 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y1 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y2 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y3 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y4 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y4, y31);
    y19 = _mm256_add_epi64(y19, y0);
    y20 = _mm256_add_epi64(y20, y1);
    y21 = _mm256_add_epi64(y21, y2);
    y22 = _mm256_add_epi64(y22, y3);
    y23 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 32));
    y24 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 64));
    y25 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 96));
    y26 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 128));
    y27 = _mm256_loadu_si256((const __m256i*)WC_PR(r15, 160));
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_mullo_epi64(y5, y31);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_mullo_epi64(y6, y31);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_mullo_epi64(y7, y31);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_mullo_epi64(y8, y31);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_mullo_epi64(y17, y31);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 0), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 32), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 64), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 96), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 128), y22);
    r11 = (word64)(r11 - 1);
    if ((r11) != (0)) {
        goto L_ge_dsm_dq_avx512_ifma_table;
    }
    /* R = identity: X = 0, Y = 1, Z = 1, T = 0 */
    r9 = (word64)(1);
    WC_S64(rbp, 1608) = (word64)(r9);
    r9 = (word64)(0);
    WC_S64(rbp, 1640) = (word64)(r9);
    WC_S64(rbp, 1672) = (word64)(r9);
    WC_S64(rbp, 1704) = (word64)(r9);
    WC_S64(rbp, 1736) = (word64)(r9);
    r9 = (word64)(1);
    WC_S64(rbp, 1616) = (word64)(r9);
    r9 = (word64)(0);
    WC_S64(rbp, 1648) = (word64)(r9);
    WC_S64(rbp, 1680) = (word64)(r9);
    WC_S64(rbp, 1712) = (word64)(r9);
    WC_S64(rbp, 1744) = (word64)(r9);
    r9 = (word64)(0);
    WC_S64(rbp, 1600) = (word64)(r9);
    WC_S64(rbp, 1624) = (word64)(r9);
    WC_S64(rbp, 1632) = (word64)(r9);
    WC_S64(rbp, 1656) = (word64)(r9);
    WC_S64(rbp, 1664) = (word64)(r9);
    WC_S64(rbp, 1688) = (word64)(r9);
    WC_S64(rbp, 1696) = (word64)(r9);
    WC_S64(rbp, 1720) = (word64)(r9);
    WC_S64(rbp, 1728) = (word64)(r9);
    WC_S64(rbp, 1752) = (word64)(r9);
    r10 = (word64)(0x7ffffffffffff);
    y18 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1600));
    y19 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1632));
    y20 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1664));
    y21 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1696));
    y22 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1728));
    r11 = (word64)(0xff);
L_ge_dsm_dq_avx512_ifma_bits:
    /* Double */
    y23 = _mm256_permute4x64_epi64(y18, 0x64);
    y24 = _mm256_permute4x64_epi64(y19, 0x64);
    y25 = _mm256_permute4x64_epi64(y20, 0x64);
    y26 = _mm256_permute4x64_epi64(y21, 0x64);
    y27 = _mm256_permute4x64_epi64(y22, 0x64);
    y18 = _mm256_permute4x64_epi64(y18, 0x24);
    y19 = _mm256_permute4x64_epi64(y19, 0x24);
    y20 = _mm256_permute4x64_epi64(y20, 0x24);
    y21 = _mm256_permute4x64_epi64(y21, 0x24);
    y22 = _mm256_permute4x64_epi64(y22, 0x24);
    y18 = _mm256_mask_blend_epi64(k1, y18, _mm256_add_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k1, y19, _mm256_add_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k1, y20, _mm256_add_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k1, y21, _mm256_add_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k1, y22, _mm256_add_epi64(y22, y27));
    y0 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y1 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y2 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y3 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y4 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y4, y31);
    y19 = _mm256_add_epi64(y19, y0);
    y20 = _mm256_add_epi64(y20, y1);
    y21 = _mm256_add_epi64(y21, y2);
    y22 = _mm256_add_epi64(y22, y3);
    y23 = y18;
    y24 = y19;
    y25 = y20;
    y26 = y21;
    y27 = y22;
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_mullo_epi64(y5, y31);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_mullo_epi64(y6, y31);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_mullo_epi64(y7, y31);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_mullo_epi64(y8, y31);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_mullo_epi64(y17, y31);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* Y3 = YY + XX, Z3 = YY - XX */
    y23 = _mm256_permute4x64_epi64(y18, 0x55);
    y24 = _mm256_permute4x64_epi64(y19, 0x55);
    y25 = _mm256_permute4x64_epi64(y20, 0x55);
    y26 = _mm256_permute4x64_epi64(y21, 0x55);
    y27 = _mm256_permute4x64_epi64(y22, 0x55);
    y0 = _mm256_permute4x64_epi64(y18, 0);
    y1 = _mm256_permute4x64_epi64(y19, 0);
    y2 = _mm256_permute4x64_epi64(y20, 0);
    y3 = _mm256_permute4x64_epi64(y21, 0);
    y4 = _mm256_permute4x64_epi64(y22, 0);
    y5 = _mm256_add_epi64(y23, y0);
    y6 = _mm256_add_epi64(y24, y1);
    y7 = _mm256_add_epi64(y25, y2);
    y8 = _mm256_add_epi64(y26, y3);
    y9 = _mm256_add_epi64(y27, y4);
    y23 = _mm256_mask_blend_epi64(k2, y23, _mm256_add_epi64(y23, y29));
    y24 = _mm256_mask_blend_epi64(k2, y24, _mm256_add_epi64(y24, y30));
    y25 = _mm256_mask_blend_epi64(k2, y25, _mm256_add_epi64(y25, y30));
    y26 = _mm256_mask_blend_epi64(k2, y26, _mm256_add_epi64(y26, y30));
    y27 = _mm256_mask_blend_epi64(k2, y27, _mm256_add_epi64(y27, y30));
    y5 = _mm256_mask_blend_epi64(k2, y5, _mm256_sub_epi64(y23, y0));
    y6 = _mm256_mask_blend_epi64(k2, y6, _mm256_sub_epi64(y24, y1));
    y7 = _mm256_mask_blend_epi64(k2, y7, _mm256_sub_epi64(y25, y2));
    y8 = _mm256_mask_blend_epi64(k2, y8, _mm256_sub_epi64(y26, y3));
    y9 = _mm256_mask_blend_epi64(k2, y9, _mm256_sub_epi64(y27, y4));
    y23 = _mm256_srli_epi64(y5, 51);
    y5 = _mm256_and_si256(y5, y28);
    y24 = _mm256_srli_epi64(y6, 51);
    y6 = _mm256_and_si256(y6, y28);
    y25 = _mm256_srli_epi64(y7, 51);
    y7 = _mm256_and_si256(y7, y28);
    y26 = _mm256_srli_epi64(y8, 51);
    y8 = _mm256_and_si256(y8, y28);
    y27 = _mm256_srli_epi64(y9, 51);
    y9 = _mm256_and_si256(y9, y28);
    y5 = _mm256_madd52lo_epu64(y5, y27, y31);
    y6 = _mm256_add_epi64(y6, y23);
    y7 = _mm256_add_epi64(y7, y24);
    y8 = _mm256_add_epi64(y8, y25);
    y9 = _mm256_add_epi64(y9, y26);
    /* X3 = AA - Y3, T3 = 2.ZZ - Z3 */
    y23 = _mm256_permute4x64_epi64(y18, 0xaf);
    y24 = _mm256_permute4x64_epi64(y19, 0xaf);
    y25 = _mm256_permute4x64_epi64(y20, 0xaf);
    y26 = _mm256_permute4x64_epi64(y21, 0xaf);
    y27 = _mm256_permute4x64_epi64(y22, 0xaf);
    y23 = _mm256_mask_blend_epi64(k2, y23, _mm256_add_epi64(y23, y23));
    y24 = _mm256_mask_blend_epi64(k2, y24, _mm256_add_epi64(y24, y24));
    y25 = _mm256_mask_blend_epi64(k2, y25, _mm256_add_epi64(y25, y25));
    y26 = _mm256_mask_blend_epi64(k2, y26, _mm256_add_epi64(y26, y26));
    y27 = _mm256_mask_blend_epi64(k2, y27, _mm256_add_epi64(y27, y27));
    y23 = _mm256_mask_blend_epi64(k3, y23, _mm256_add_epi64(y23, y29));
    y24 = _mm256_mask_blend_epi64(k3, y24, _mm256_add_epi64(y24, y30));
    y25 = _mm256_mask_blend_epi64(k3, y25, _mm256_add_epi64(y25, y30));
    y26 = _mm256_mask_blend_epi64(k3, y26, _mm256_add_epi64(y26, y30));
    y27 = _mm256_mask_blend_epi64(k3, y27, _mm256_add_epi64(y27, y30));
    y23 = _mm256_mask_blend_epi64(k3, y23, _mm256_sub_epi64(y23, y5));
    y24 = _mm256_mask_blend_epi64(k3, y24, _mm256_sub_epi64(y24, y6));
    y25 = _mm256_mask_blend_epi64(k3, y25, _mm256_sub_epi64(y25, y7));
    y26 = _mm256_mask_blend_epi64(k3, y26, _mm256_sub_epi64(y26, y8));
    y27 = _mm256_mask_blend_epi64(k3, y27, _mm256_sub_epi64(y27, y9));
    y0 = _mm256_srli_epi64(y23, 51);
    y23 = _mm256_and_si256(y23, y28);
    y1 = _mm256_srli_epi64(y24, 51);
    y24 = _mm256_and_si256(y24, y28);
    y2 = _mm256_srli_epi64(y25, 51);
    y25 = _mm256_and_si256(y25, y28);
    y3 = _mm256_srli_epi64(y26, 51);
    y26 = _mm256_and_si256(y26, y28);
    y4 = _mm256_srli_epi64(y27, 51);
    y27 = _mm256_and_si256(y27, y28);
    y23 = _mm256_madd52lo_epu64(y23, y4, y31);
    y24 = _mm256_add_epi64(y24, y0);
    y25 = _mm256_add_epi64(y25, y1);
    y26 = _mm256_add_epi64(y26, y2);
    y27 = _mm256_add_epi64(y27, y3);
    y23 = _mm256_mask_blend_epi64(k4, y23, y5);
    y24 = _mm256_mask_blend_epi64(k4, y24, y6);
    y25 = _mm256_mask_blend_epi64(k4, y25, y7);
    y26 = _mm256_mask_blend_epi64(k4, y26, y8);
    y27 = _mm256_mask_blend_epi64(k4, y27, y9);
    /* Add the multiple of A selected by this window digit */
    r12 = (word64)((word64)(sword64)(signed char)WC_L8(rbp, r11 + 1920));
    if (((r12 & r12)) == (0)) {
        goto L_ge_dsm_dq_avx512_ifma_skip_a;
    }
    rsi = (word64)(r12);
    rsi = (word64)((word64)((sword64)rsi >> 63));
    r12 = (word64)(r12);
    r12 = (word64)(r12 ^ rsi);
    r12 = (word64)(r12 - rsi);
    r12 = (word64)(r12 >> 1);
    r12 = (word64)(r12 * 160);
    r14 = (word64)(rbp);
    r14 = (word64)(r14 + r12);
    y18 = _mm256_loadu_si256((const __m256i*)WC_PR(r14, 0));
    y19 = _mm256_loadu_si256((const __m256i*)WC_PR(r14, 32));
    y20 = _mm256_loadu_si256((const __m256i*)WC_PR(r14, 64));
    y21 = _mm256_loadu_si256((const __m256i*)WC_PR(r14, 96));
    y22 = _mm256_loadu_si256((const __m256i*)WC_PR(r14, 128));
    if (((rsi & rsi)) == (0)) {
        goto L_ge_dsm_dq_avx512_ifma_noswap_a;
    }
    y18 = _mm256_permute4x64_epi64(y18, 0xe1);
    y19 = _mm256_permute4x64_epi64(y19, 0xe1);
    y20 = _mm256_permute4x64_epi64(y20, 0xe1);
    y21 = _mm256_permute4x64_epi64(y21, 0xe1);
    y22 = _mm256_permute4x64_epi64(y22, 0xe1);
L_ge_dsm_dq_avx512_ifma_noswap_a:
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1760), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1792), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1824), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1856), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1888), y22);
    /* To p3 */
    y18 = _mm256_permute4x64_epi64(y23, 0x24);
    y19 = _mm256_permute4x64_epi64(y24, 0x24);
    y20 = _mm256_permute4x64_epi64(y25, 0x24);
    y21 = _mm256_permute4x64_epi64(y26, 0x24);
    y22 = _mm256_permute4x64_epi64(y27, 0x24);
    y23 = _mm256_permute4x64_epi64(y23, 0x7b);
    y24 = _mm256_permute4x64_epi64(y24, 0x7b);
    y25 = _mm256_permute4x64_epi64(y25, 0x7b);
    y26 = _mm256_permute4x64_epi64(y26, 0x7b);
    y27 = _mm256_permute4x64_epi64(y27, 0x7b);
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_mullo_epi64(y5, y31);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_mullo_epi64(y6, y31);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_mullo_epi64(y7, y31);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_mullo_epi64(y8, y31);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_mullo_epi64(y17, y31);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* Add */
    y23 = _mm256_permute4x64_epi64(y18, 0xb0);
    y24 = _mm256_permute4x64_epi64(y19, 0xb0);
    y25 = _mm256_permute4x64_epi64(y20, 0xb0);
    y26 = _mm256_permute4x64_epi64(y21, 0xb0);
    y27 = _mm256_permute4x64_epi64(y22, 0xb0);
    y18 = _mm256_permute4x64_epi64(y18, 0xb5);
    y19 = _mm256_permute4x64_epi64(y19, 0xb5);
    y20 = _mm256_permute4x64_epi64(y20, 0xb5);
    y21 = _mm256_permute4x64_epi64(y21, 0xb5);
    y22 = _mm256_permute4x64_epi64(y22, 0xb5);
    y18 = _mm256_mask_blend_epi64(k5, y18, _mm256_add_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k5, y19, _mm256_add_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k5, y20, _mm256_add_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k5, y21, _mm256_add_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k5, y22, _mm256_add_epi64(y22, y27));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_add_epi64(y18, y29));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_add_epi64(y19, y30));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_add_epi64(y20, y30));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_add_epi64(y21, y30));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_add_epi64(y22, y30));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_sub_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_sub_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_sub_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_sub_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_sub_epi64(y22, y27));
    y0 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y1 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y2 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y3 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y4 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y4, y31);
    y19 = _mm256_add_epi64(y19, y0);
    y20 = _mm256_add_epi64(y20, y1);
    y21 = _mm256_add_epi64(y21, y2);
    y22 = _mm256_add_epi64(y22, y3);
    y23 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1760));
    y24 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1792));
    y25 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1824));
    y26 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1856));
    y27 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1888));
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_mullo_epi64(y5, y31);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_mullo_epi64(y6, y31);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_mullo_epi64(y7, y31);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_mullo_epi64(y8, y31);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_mullo_epi64(y17, y31);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* X3 = B - A, Y3 = B + A, Z3 = D + C, T3 = D - C */
    y23 = _mm256_permute4x64_epi64(y18, 0xf0);
    y24 = _mm256_permute4x64_epi64(y19, 0xf0);
    y25 = _mm256_permute4x64_epi64(y20, 0xf0);
    y26 = _mm256_permute4x64_epi64(y21, 0xf0);
    y27 = _mm256_permute4x64_epi64(y22, 0xf0);
    y23 = _mm256_mask_blend_epi64(k2, y23, _mm256_add_epi64(y23, y23));
    y24 = _mm256_mask_blend_epi64(k2, y24, _mm256_add_epi64(y24, y24));
    y25 = _mm256_mask_blend_epi64(k2, y25, _mm256_add_epi64(y25, y25));
    y26 = _mm256_mask_blend_epi64(k2, y26, _mm256_add_epi64(y26, y26));
    y27 = _mm256_mask_blend_epi64(k2, y27, _mm256_add_epi64(y27, y27));
    y0 = _mm256_permute4x64_epi64(y18, 0xa5);
    y1 = _mm256_permute4x64_epi64(y19, 0xa5);
    y2 = _mm256_permute4x64_epi64(y20, 0xa5);
    y3 = _mm256_permute4x64_epi64(y21, 0xa5);
    y4 = _mm256_permute4x64_epi64(y22, 0xa5);
    y18 = _mm256_add_epi64(y23, y0);
    y19 = _mm256_add_epi64(y24, y1);
    y20 = _mm256_add_epi64(y25, y2);
    y21 = _mm256_add_epi64(y26, y3);
    y22 = _mm256_add_epi64(y27, y4);
    y23 = _mm256_mask_blend_epi64(k3, y23, _mm256_add_epi64(y23, y29));
    y24 = _mm256_mask_blend_epi64(k3, y24, _mm256_add_epi64(y24, y30));
    y25 = _mm256_mask_blend_epi64(k3, y25, _mm256_add_epi64(y25, y30));
    y26 = _mm256_mask_blend_epi64(k3, y26, _mm256_add_epi64(y26, y30));
    y27 = _mm256_mask_blend_epi64(k3, y27, _mm256_add_epi64(y27, y30));
    y18 = _mm256_mask_blend_epi64(k3, y18, _mm256_sub_epi64(y23, y0));
    y19 = _mm256_mask_blend_epi64(k3, y19, _mm256_sub_epi64(y24, y1));
    y20 = _mm256_mask_blend_epi64(k3, y20, _mm256_sub_epi64(y25, y2));
    y21 = _mm256_mask_blend_epi64(k3, y21, _mm256_sub_epi64(y26, y3));
    y22 = _mm256_mask_blend_epi64(k3, y22, _mm256_sub_epi64(y27, y4));
    y5 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y6 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y7 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y8 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y9 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y9, y31);
    y19 = _mm256_add_epi64(y19, y5);
    y20 = _mm256_add_epi64(y20, y6);
    y21 = _mm256_add_epi64(y21, y7);
    y22 = _mm256_add_epi64(y22, y8);
    if (((rsi & rsi)) == (0)) {
        goto L_ge_dsm_dq_avx512_ifma_nores_a;
    }
    y18 = _mm256_permute4x64_epi64(y18, 0xb4);
    y19 = _mm256_permute4x64_epi64(y19, 0xb4);
    y20 = _mm256_permute4x64_epi64(y20, 0xb4);
    y21 = _mm256_permute4x64_epi64(y21, 0xb4);
    y22 = _mm256_permute4x64_epi64(y22, 0xb4);
L_ge_dsm_dq_avx512_ifma_nores_a:
    y23 = y18;
    y24 = y19;
    y25 = y20;
    y26 = y21;
    y27 = y22;
L_ge_dsm_dq_avx512_ifma_skip_a:
    /* Add the multiple of the base point */
    r12 = (word64)((word64)(sword64)(signed char)WC_L8(rbp, r11 + 2176));
    if (((r12 & r12)) == (0)) {
        goto L_ge_dsm_dq_avx512_ifma_skip_b;
    }
    rsi = (word64)(r12);
    rsi = (word64)((word64)((sword64)rsi >> 63));
    r12 = (word64)(r12);
    r12 = (word64)(r12 ^ rsi);
    r12 = (word64)(r12 - rsi);
    r12 = (word64)(r12 >> 1);
    r12 = (word64)(r12 * 96);
    r14 = (word64)(rbx);
    r14 = (word64)(r14 + r12);
    rdx = (word64)(WC_L64(r14, 0));
    rax = (word64)(WC_L64(r14, 8));
    rcx = (word64)(WC_L64(r14, 16));
    r8 = (word64)(WC_L64(r14, 24));
    r9 = (word64)(r8);
    r9 = (word64)(r9 >> 63);
    r9 = (word64)(r9 * 19);
    r8 = (word64)(r8 << 1);
    r8 = (word64)(r8 >> 1);
    r13 = (word64)(rdx);
    r13 = (word64)(r13 & r10);
    r13 = (word64)(r13 + r9);
    WC_S64(rbp, 1760) = (word64)(r13);
    rdx = (word64)((rdx >> 51) | (rax << 13));
    r9 = (word64)(rdx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1792) = (word64)(r9);
    rax = (word64)((rax >> 38) | (rcx << 26));
    r9 = (word64)(rax);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1824) = (word64)(r9);
    rcx = (word64)((rcx >> 25) | (r8 << 39));
    r9 = (word64)(rcx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1856) = (word64)(r9);
    r8 = (word64)(r8 >> 12);
    WC_S64(rbp, 1888) = (word64)(r8);
    rdx = (word64)(WC_L64(r14, 32));
    rax = (word64)(WC_L64(r14, 40));
    rcx = (word64)(WC_L64(r14, 48));
    r8 = (word64)(WC_L64(r14, 56));
    r9 = (word64)(r8);
    r9 = (word64)(r9 >> 63);
    r9 = (word64)(r9 * 19);
    r8 = (word64)(r8 << 1);
    r8 = (word64)(r8 >> 1);
    r13 = (word64)(rdx);
    r13 = (word64)(r13 & r10);
    r13 = (word64)(r13 + r9);
    WC_S64(rbp, 1768) = (word64)(r13);
    rdx = (word64)((rdx >> 51) | (rax << 13));
    r9 = (word64)(rdx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1800) = (word64)(r9);
    rax = (word64)((rax >> 38) | (rcx << 26));
    r9 = (word64)(rax);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1832) = (word64)(r9);
    rcx = (word64)((rcx >> 25) | (r8 << 39));
    r9 = (word64)(rcx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1864) = (word64)(r9);
    r8 = (word64)(r8 >> 12);
    WC_S64(rbp, 1896) = (word64)(r8);
    rdx = (word64)(WC_L64(r14, 64));
    rax = (word64)(WC_L64(r14, 72));
    rcx = (word64)(WC_L64(r14, 80));
    r8 = (word64)(WC_L64(r14, 88));
    r9 = (word64)(r8);
    r9 = (word64)(r9 >> 63);
    r9 = (word64)(r9 * 19);
    r8 = (word64)(r8 << 1);
    r8 = (word64)(r8 >> 1);
    r13 = (word64)(rdx);
    r13 = (word64)(r13 & r10);
    r13 = (word64)(r13 + r9);
    WC_S64(rbp, 1776) = (word64)(r13);
    rdx = (word64)((rdx >> 51) | (rax << 13));
    r9 = (word64)(rdx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1808) = (word64)(r9);
    rax = (word64)((rax >> 38) | (rcx << 26));
    r9 = (word64)(rax);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1840) = (word64)(r9);
    rcx = (word64)((rcx >> 25) | (r8 << 39));
    r9 = (word64)(rcx);
    r9 = (word64)(r9 & r10);
    WC_S64(rbp, 1872) = (word64)(r9);
    r8 = (word64)(r8 >> 12);
    WC_S64(rbp, 1904) = (word64)(r8);
    rdx = (word64)(1);
    WC_S64(rbp, 1784) = (word64)(rdx);
    rdx = (word64)(0);
    WC_S64(rbp, 1816) = (word64)(rdx);
    WC_S64(rbp, 1848) = (word64)(rdx);
    WC_S64(rbp, 1880) = (word64)(rdx);
    WC_S64(rbp, 1912) = (word64)(rdx);
    if (((rsi & rsi)) == (0)) {
        goto L_ge_dsm_dq_avx512_ifma_noswap_b;
    }
    y18 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1760));
    y19 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1792));
    y20 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1824));
    y21 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1856));
    y22 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1888));
    y18 = _mm256_permute4x64_epi64(y18, 0xe1);
    y19 = _mm256_permute4x64_epi64(y19, 0xe1);
    y20 = _mm256_permute4x64_epi64(y20, 0xe1);
    y21 = _mm256_permute4x64_epi64(y21, 0xe1);
    y22 = _mm256_permute4x64_epi64(y22, 0xe1);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1760), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1792), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1824), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1856), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1888), y22);
L_ge_dsm_dq_avx512_ifma_noswap_b:
    /* To p3 */
    y18 = _mm256_permute4x64_epi64(y23, 0x24);
    y19 = _mm256_permute4x64_epi64(y24, 0x24);
    y20 = _mm256_permute4x64_epi64(y25, 0x24);
    y21 = _mm256_permute4x64_epi64(y26, 0x24);
    y22 = _mm256_permute4x64_epi64(y27, 0x24);
    y23 = _mm256_permute4x64_epi64(y23, 0x7b);
    y24 = _mm256_permute4x64_epi64(y24, 0x7b);
    y25 = _mm256_permute4x64_epi64(y25, 0x7b);
    y26 = _mm256_permute4x64_epi64(y26, 0x7b);
    y27 = _mm256_permute4x64_epi64(y27, 0x7b);
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_mullo_epi64(y5, y31);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_mullo_epi64(y6, y31);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_mullo_epi64(y7, y31);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_mullo_epi64(y8, y31);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_mullo_epi64(y17, y31);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* Add */
    y23 = _mm256_permute4x64_epi64(y18, 0xb0);
    y24 = _mm256_permute4x64_epi64(y19, 0xb0);
    y25 = _mm256_permute4x64_epi64(y20, 0xb0);
    y26 = _mm256_permute4x64_epi64(y21, 0xb0);
    y27 = _mm256_permute4x64_epi64(y22, 0xb0);
    y18 = _mm256_permute4x64_epi64(y18, 0xb5);
    y19 = _mm256_permute4x64_epi64(y19, 0xb5);
    y20 = _mm256_permute4x64_epi64(y20, 0xb5);
    y21 = _mm256_permute4x64_epi64(y21, 0xb5);
    y22 = _mm256_permute4x64_epi64(y22, 0xb5);
    y18 = _mm256_mask_blend_epi64(k5, y18, _mm256_add_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k5, y19, _mm256_add_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k5, y20, _mm256_add_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k5, y21, _mm256_add_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k5, y22, _mm256_add_epi64(y22, y27));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_add_epi64(y18, y29));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_add_epi64(y19, y30));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_add_epi64(y20, y30));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_add_epi64(y21, y30));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_add_epi64(y22, y30));
    y18 = _mm256_mask_blend_epi64(k6, y18, _mm256_sub_epi64(y18, y23));
    y19 = _mm256_mask_blend_epi64(k6, y19, _mm256_sub_epi64(y19, y24));
    y20 = _mm256_mask_blend_epi64(k6, y20, _mm256_sub_epi64(y20, y25));
    y21 = _mm256_mask_blend_epi64(k6, y21, _mm256_sub_epi64(y21, y26));
    y22 = _mm256_mask_blend_epi64(k6, y22, _mm256_sub_epi64(y22, y27));
    y0 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y1 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y2 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y3 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y4 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y4, y31);
    y19 = _mm256_add_epi64(y19, y0);
    y20 = _mm256_add_epi64(y20, y1);
    y21 = _mm256_add_epi64(y21, y2);
    y22 = _mm256_add_epi64(y22, y3);
    y23 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1760));
    y24 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1792));
    y25 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1824));
    y26 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1856));
    y27 = _mm256_loadu_si256((const __m256i*)WC_PR(rbp, 1888));
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_mullo_epi64(y5, y31);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_mullo_epi64(y6, y31);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_mullo_epi64(y7, y31);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_mullo_epi64(y8, y31);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_mullo_epi64(y17, y31);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    /* X3 = B - A, Y3 = B + A, Z3 = D + C, T3 = D - C */
    y23 = _mm256_permute4x64_epi64(y18, 0xf0);
    y24 = _mm256_permute4x64_epi64(y19, 0xf0);
    y25 = _mm256_permute4x64_epi64(y20, 0xf0);
    y26 = _mm256_permute4x64_epi64(y21, 0xf0);
    y27 = _mm256_permute4x64_epi64(y22, 0xf0);
    y23 = _mm256_mask_blend_epi64(k2, y23, _mm256_add_epi64(y23, y23));
    y24 = _mm256_mask_blend_epi64(k2, y24, _mm256_add_epi64(y24, y24));
    y25 = _mm256_mask_blend_epi64(k2, y25, _mm256_add_epi64(y25, y25));
    y26 = _mm256_mask_blend_epi64(k2, y26, _mm256_add_epi64(y26, y26));
    y27 = _mm256_mask_blend_epi64(k2, y27, _mm256_add_epi64(y27, y27));
    y0 = _mm256_permute4x64_epi64(y18, 0xa5);
    y1 = _mm256_permute4x64_epi64(y19, 0xa5);
    y2 = _mm256_permute4x64_epi64(y20, 0xa5);
    y3 = _mm256_permute4x64_epi64(y21, 0xa5);
    y4 = _mm256_permute4x64_epi64(y22, 0xa5);
    y18 = _mm256_add_epi64(y23, y0);
    y19 = _mm256_add_epi64(y24, y1);
    y20 = _mm256_add_epi64(y25, y2);
    y21 = _mm256_add_epi64(y26, y3);
    y22 = _mm256_add_epi64(y27, y4);
    y23 = _mm256_mask_blend_epi64(k3, y23, _mm256_add_epi64(y23, y29));
    y24 = _mm256_mask_blend_epi64(k3, y24, _mm256_add_epi64(y24, y30));
    y25 = _mm256_mask_blend_epi64(k3, y25, _mm256_add_epi64(y25, y30));
    y26 = _mm256_mask_blend_epi64(k3, y26, _mm256_add_epi64(y26, y30));
    y27 = _mm256_mask_blend_epi64(k3, y27, _mm256_add_epi64(y27, y30));
    y18 = _mm256_mask_blend_epi64(k3, y18, _mm256_sub_epi64(y23, y0));
    y19 = _mm256_mask_blend_epi64(k3, y19, _mm256_sub_epi64(y24, y1));
    y20 = _mm256_mask_blend_epi64(k3, y20, _mm256_sub_epi64(y25, y2));
    y21 = _mm256_mask_blend_epi64(k3, y21, _mm256_sub_epi64(y26, y3));
    y22 = _mm256_mask_blend_epi64(k3, y22, _mm256_sub_epi64(y27, y4));
    y5 = _mm256_srli_epi64(y18, 51);
    y18 = _mm256_and_si256(y18, y28);
    y6 = _mm256_srli_epi64(y19, 51);
    y19 = _mm256_and_si256(y19, y28);
    y7 = _mm256_srli_epi64(y20, 51);
    y20 = _mm256_and_si256(y20, y28);
    y8 = _mm256_srli_epi64(y21, 51);
    y21 = _mm256_and_si256(y21, y28);
    y9 = _mm256_srli_epi64(y22, 51);
    y22 = _mm256_and_si256(y22, y28);
    y18 = _mm256_madd52lo_epu64(y18, y9, y31);
    y19 = _mm256_add_epi64(y19, y5);
    y20 = _mm256_add_epi64(y20, y6);
    y21 = _mm256_add_epi64(y21, y7);
    y22 = _mm256_add_epi64(y22, y8);
    if (((rsi & rsi)) == (0)) {
        goto L_ge_dsm_dq_avx512_ifma_nores_b;
    }
    y18 = _mm256_permute4x64_epi64(y18, 0xb4);
    y19 = _mm256_permute4x64_epi64(y19, 0xb4);
    y20 = _mm256_permute4x64_epi64(y20, 0xb4);
    y21 = _mm256_permute4x64_epi64(y21, 0xb4);
    y22 = _mm256_permute4x64_epi64(y22, 0xb4);
L_ge_dsm_dq_avx512_ifma_nores_b:
    y23 = y18;
    y24 = y19;
    y25 = y20;
    y26 = y21;
    y27 = y22;
L_ge_dsm_dq_avx512_ifma_skip_b:
    /* To p3 */
    y18 = _mm256_permute4x64_epi64(y23, 0x24);
    y19 = _mm256_permute4x64_epi64(y24, 0x24);
    y20 = _mm256_permute4x64_epi64(y25, 0x24);
    y21 = _mm256_permute4x64_epi64(y26, 0x24);
    y22 = _mm256_permute4x64_epi64(y27, 0x24);
    y23 = _mm256_permute4x64_epi64(y23, 0x7b);
    y24 = _mm256_permute4x64_epi64(y24, 0x7b);
    y25 = _mm256_permute4x64_epi64(y25, 0x7b);
    y26 = _mm256_permute4x64_epi64(y26, 0x7b);
    y27 = _mm256_permute4x64_epi64(y27, 0x7b);
    /* Multiply 4 field elements */
    y0 = _mm256_setzero_si256();
    y9 = _mm256_setzero_si256();
    y1 = _mm256_setzero_si256();
    y10 = _mm256_setzero_si256();
    y2 = _mm256_setzero_si256();
    y11 = _mm256_setzero_si256();
    y3 = _mm256_setzero_si256();
    y12 = _mm256_setzero_si256();
    y4 = _mm256_setzero_si256();
    y13 = _mm256_setzero_si256();
    y5 = _mm256_setzero_si256();
    y14 = _mm256_setzero_si256();
    y6 = _mm256_setzero_si256();
    y15 = _mm256_setzero_si256();
    y7 = _mm256_setzero_si256();
    y16 = _mm256_setzero_si256();
    y8 = _mm256_setzero_si256();
    y17 = _mm256_setzero_si256();
    y0 = _mm256_madd52lo_epu64(y0, y18, y23);
    y9 = _mm256_madd52hi_epu64(y9, y18, y23);
    y1 = _mm256_madd52lo_epu64(y1, y18, y24);
    y10 = _mm256_madd52hi_epu64(y10, y18, y24);
    y2 = _mm256_madd52lo_epu64(y2, y18, y25);
    y11 = _mm256_madd52hi_epu64(y11, y18, y25);
    y3 = _mm256_madd52lo_epu64(y3, y18, y26);
    y12 = _mm256_madd52hi_epu64(y12, y18, y26);
    y4 = _mm256_madd52lo_epu64(y4, y18, y27);
    y13 = _mm256_madd52hi_epu64(y13, y18, y27);
    y1 = _mm256_madd52lo_epu64(y1, y19, y23);
    y10 = _mm256_madd52hi_epu64(y10, y19, y23);
    y2 = _mm256_madd52lo_epu64(y2, y19, y24);
    y11 = _mm256_madd52hi_epu64(y11, y19, y24);
    y3 = _mm256_madd52lo_epu64(y3, y19, y25);
    y12 = _mm256_madd52hi_epu64(y12, y19, y25);
    y4 = _mm256_madd52lo_epu64(y4, y19, y26);
    y13 = _mm256_madd52hi_epu64(y13, y19, y26);
    y5 = _mm256_madd52lo_epu64(y5, y19, y27);
    y14 = _mm256_madd52hi_epu64(y14, y19, y27);
    y2 = _mm256_madd52lo_epu64(y2, y20, y23);
    y11 = _mm256_madd52hi_epu64(y11, y20, y23);
    y3 = _mm256_madd52lo_epu64(y3, y20, y24);
    y12 = _mm256_madd52hi_epu64(y12, y20, y24);
    y4 = _mm256_madd52lo_epu64(y4, y20, y25);
    y13 = _mm256_madd52hi_epu64(y13, y20, y25);
    y5 = _mm256_madd52lo_epu64(y5, y20, y26);
    y14 = _mm256_madd52hi_epu64(y14, y20, y26);
    y6 = _mm256_madd52lo_epu64(y6, y20, y27);
    y15 = _mm256_madd52hi_epu64(y15, y20, y27);
    y3 = _mm256_madd52lo_epu64(y3, y21, y23);
    y12 = _mm256_madd52hi_epu64(y12, y21, y23);
    y4 = _mm256_madd52lo_epu64(y4, y21, y24);
    y13 = _mm256_madd52hi_epu64(y13, y21, y24);
    y5 = _mm256_madd52lo_epu64(y5, y21, y25);
    y14 = _mm256_madd52hi_epu64(y14, y21, y25);
    y6 = _mm256_madd52lo_epu64(y6, y21, y26);
    y15 = _mm256_madd52hi_epu64(y15, y21, y26);
    y7 = _mm256_madd52lo_epu64(y7, y21, y27);
    y16 = _mm256_madd52hi_epu64(y16, y21, y27);
    y4 = _mm256_madd52lo_epu64(y4, y22, y23);
    y13 = _mm256_madd52hi_epu64(y13, y22, y23);
    y5 = _mm256_madd52lo_epu64(y5, y22, y24);
    y14 = _mm256_madd52hi_epu64(y14, y22, y24);
    y6 = _mm256_madd52lo_epu64(y6, y22, y25);
    y15 = _mm256_madd52hi_epu64(y15, y22, y25);
    y7 = _mm256_madd52lo_epu64(y7, y22, y26);
    y16 = _mm256_madd52hi_epu64(y16, y22, y26);
    y8 = _mm256_madd52lo_epu64(y8, y22, y27);
    y17 = _mm256_madd52hi_epu64(y17, y22, y27);
    y9 = _mm256_add_epi64(y9, y9);
    y1 = _mm256_add_epi64(y1, y9);
    y10 = _mm256_add_epi64(y10, y10);
    y2 = _mm256_add_epi64(y2, y10);
    y11 = _mm256_add_epi64(y11, y11);
    y3 = _mm256_add_epi64(y3, y11);
    y12 = _mm256_add_epi64(y12, y12);
    y4 = _mm256_add_epi64(y4, y12);
    y13 = _mm256_add_epi64(y13, y13);
    y5 = _mm256_add_epi64(y5, y13);
    y14 = _mm256_add_epi64(y14, y14);
    y6 = _mm256_add_epi64(y6, y14);
    y15 = _mm256_add_epi64(y15, y15);
    y7 = _mm256_add_epi64(y7, y15);
    y16 = _mm256_add_epi64(y16, y16);
    y8 = _mm256_add_epi64(y8, y16);
    y17 = _mm256_add_epi64(y17, y17);
    /* Reduce */
    y9 = _mm256_mullo_epi64(y5, y31);
    y0 = _mm256_add_epi64(y0, y9);
    y9 = _mm256_mullo_epi64(y6, y31);
    y1 = _mm256_add_epi64(y1, y9);
    y9 = _mm256_mullo_epi64(y7, y31);
    y2 = _mm256_add_epi64(y2, y9);
    y9 = _mm256_mullo_epi64(y8, y31);
    y3 = _mm256_add_epi64(y3, y9);
    y9 = _mm256_mullo_epi64(y17, y31);
    y4 = _mm256_add_epi64(y4, y9);
    y23 = _mm256_srli_epi64(y0, 51);
    y0 = _mm256_and_si256(y0, y28);
    y24 = _mm256_srli_epi64(y1, 51);
    y1 = _mm256_and_si256(y1, y28);
    y25 = _mm256_srli_epi64(y2, 51);
    y2 = _mm256_and_si256(y2, y28);
    y26 = _mm256_srli_epi64(y3, 51);
    y3 = _mm256_and_si256(y3, y28);
    y27 = _mm256_srli_epi64(y4, 51);
    y4 = _mm256_and_si256(y4, y28);
    y18 = y0;
    y18 = _mm256_madd52lo_epu64(y18, y27, y31);
    y19 = _mm256_add_epi64(y1, y23);
    y20 = _mm256_add_epi64(y2, y24);
    y21 = _mm256_add_epi64(y3, y25);
    y22 = _mm256_add_epi64(y4, y26);
    r11 = (word64)(r11 - 1);
    if ((sword64)(r11) >= (sword64)(0)) {
        goto L_ge_dsm_dq_avx512_ifma_bits;
    }
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1600), y18);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1632), y19);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1664), y20);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1696), y21);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 1728), y22);
    /* Convert X, Y and Z back to 4 x 64-bit field elements */
    r10 = (word64)(0x7ffffffffffff);
    rdx = (word64)(WC_L64(rbp, 1600));
    rax = (word64)(WC_L64(rbp, 1632));
    rcx = (word64)(WC_L64(rbp, 1664));
    r8 = (word64)(WC_L64(rbp, 1696));
    r9 = (word64)(WC_L64(rbp, 1728));
    r11 = (word64)(rdx);
    r11 = (word64)(r11 >> 51);
    rdx = (word64)(rdx & r10);
    rax = (word64)(rax + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 >> 51);
    rax = (word64)(rax & r10);
    rcx = (word64)(rcx + r11);
    r11 = (word64)(rcx);
    r11 = (word64)(r11 >> 51);
    rcx = (word64)(rcx & r10);
    r8 = (word64)(r8 + r11);
    r11 = (word64)(r8);
    r11 = (word64)(r11 >> 51);
    r8 = (word64)(r8 & r10);
    r9 = (word64)(r9 + r11);
    r11 = (word64)(r9);
    r11 = (word64)(r11 >> 51);
    r9 = (word64)(r9 & r10);
    r11 = (word64)(r11 * 19);
    rdx = (word64)(rdx + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 << 51);
    r12 = (word64)(rax);
    r12 = (word64)(r12 >> 13);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rdi, 0) = (word64)(rdx);
    r11 = (word64)(rcx);
    r11 = (word64)(r11 << 38);
    rdx = (word64)(rcx);
    rdx = (word64)(rdx >> 26);
    cf = _addcarry_u64(0, r12, r11, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    WC_S64(rdi, 8) = (word64)(r12);
    r11 = (word64)(r8);
    r11 = (word64)(r11 << 25);
    r12 = (word64)(r8);
    r12 = (word64)(r12 >> 39);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rdi, 16) = (word64)(rdx);
    r11 = (word64)(r9);
    r11 = (word64)(r11 << 12);
    r12 = (word64)(r12 + r11);
    WC_S64(rdi, 24) = (word64)(r12);
    rdx = (word64)(WC_L64(rbp, 1608));
    rax = (word64)(WC_L64(rbp, 1640));
    rcx = (word64)(WC_L64(rbp, 1672));
    r8 = (word64)(WC_L64(rbp, 1704));
    r9 = (word64)(WC_L64(rbp, 1736));
    r11 = (word64)(rdx);
    r11 = (word64)(r11 >> 51);
    rdx = (word64)(rdx & r10);
    rax = (word64)(rax + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 >> 51);
    rax = (word64)(rax & r10);
    rcx = (word64)(rcx + r11);
    r11 = (word64)(rcx);
    r11 = (word64)(r11 >> 51);
    rcx = (word64)(rcx & r10);
    r8 = (word64)(r8 + r11);
    r11 = (word64)(r8);
    r11 = (word64)(r11 >> 51);
    r8 = (word64)(r8 & r10);
    r9 = (word64)(r9 + r11);
    r11 = (word64)(r9);
    r11 = (word64)(r11 >> 51);
    r9 = (word64)(r9 & r10);
    r11 = (word64)(r11 * 19);
    rdx = (word64)(rdx + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 << 51);
    r12 = (word64)(rax);
    r12 = (word64)(r12 >> 13);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rdi, 32) = (word64)(rdx);
    r11 = (word64)(rcx);
    r11 = (word64)(r11 << 38);
    rdx = (word64)(rcx);
    rdx = (word64)(rdx >> 26);
    cf = _addcarry_u64(0, r12, r11, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    WC_S64(rdi, 40) = (word64)(r12);
    r11 = (word64)(r8);
    r11 = (word64)(r11 << 25);
    r12 = (word64)(r8);
    r12 = (word64)(r12 >> 39);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rdi, 48) = (word64)(rdx);
    r11 = (word64)(r9);
    r11 = (word64)(r11 << 12);
    r12 = (word64)(r12 + r11);
    WC_S64(rdi, 56) = (word64)(r12);
    rdx = (word64)(WC_L64(rbp, 1616));
    rax = (word64)(WC_L64(rbp, 1648));
    rcx = (word64)(WC_L64(rbp, 1680));
    r8 = (word64)(WC_L64(rbp, 1712));
    r9 = (word64)(WC_L64(rbp, 1744));
    r11 = (word64)(rdx);
    r11 = (word64)(r11 >> 51);
    rdx = (word64)(rdx & r10);
    rax = (word64)(rax + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 >> 51);
    rax = (word64)(rax & r10);
    rcx = (word64)(rcx + r11);
    r11 = (word64)(rcx);
    r11 = (word64)(r11 >> 51);
    rcx = (word64)(rcx & r10);
    r8 = (word64)(r8 + r11);
    r11 = (word64)(r8);
    r11 = (word64)(r11 >> 51);
    r8 = (word64)(r8 & r10);
    r9 = (word64)(r9 + r11);
    r11 = (word64)(r9);
    r11 = (word64)(r11 >> 51);
    r9 = (word64)(r9 & r10);
    r11 = (word64)(r11 * 19);
    rdx = (word64)(rdx + r11);
    r11 = (word64)(rax);
    r11 = (word64)(r11 << 51);
    r12 = (word64)(rax);
    r12 = (word64)(r12 >> 13);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rdi, 64) = (word64)(rdx);
    r11 = (word64)(rcx);
    r11 = (word64)(r11 << 38);
    rdx = (word64)(rcx);
    rdx = (word64)(rdx >> 26);
    cf = _addcarry_u64(0, r12, r11, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    WC_S64(rdi, 72) = (word64)(r12);
    r11 = (word64)(r8);
    r11 = (word64)(r11 << 25);
    r12 = (word64)(r8);
    r12 = (word64)(r12 >> 39);
    cf = _addcarry_u64(0, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rdi, 80) = (word64)(rdx);
    r11 = (word64)(r9);
    r11 = (word64)(r11 << 12);
    r12 = (word64)(r12 + r11);
    WC_S64(rdi, 88) = (word64)(r12);
    rax = (word64)(0);
    return (int)(word32)rax;
    (void)k7;
}

#endif /* HAVE_ED25519 || WOLFSSL_CURVE25519_USE_ED25519 */

#endif /* HAVE_ED25519 */
#endif /* HAVE_INTEL_AVX512_IFMA */
#endif /* HAVE_INTEL_AVX2 */

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
