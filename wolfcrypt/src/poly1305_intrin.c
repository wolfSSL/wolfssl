/* poly1305_intrin.c */
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

#define _WC_BUILDING_POLY1305_INTRIN_C

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef WOLFSSL_X86_64_BUILD

#ifdef _MSC_VER
    /* _umul128, __popcnt and _BitScanReverse64 live here. */
    #include <intrin.h>
#endif
#include <immintrin.h>
#include <wolfssl/wolfcrypt/poly1305.h>

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

#ifdef WOLFSSL_X86_64_BUILD
#ifdef HAVE_INTEL_AVX1
extern WOLFSSL_LOCAL void poly1305_setkey_avx(Poly1305* ctx, const byte* key);
extern WOLFSSL_LOCAL void poly1305_block_avx(Poly1305* ctx,
    const unsigned char* m);
extern WOLFSSL_LOCAL void poly1305_blocks_avx(Poly1305* ctx,
    const unsigned char* m, size_t bytes);
extern WOLFSSL_LOCAL void poly1305_final_avx(Poly1305* ctx, byte* mac);
#endif
#ifdef HAVE_INTEL_AVX2
extern WOLFSSL_LOCAL void poly1305_calc_powers_avx2(Poly1305* ctx);
extern WOLFSSL_LOCAL void poly1305_setkey_avx2(Poly1305* ctx, const byte* key);
extern WOLFSSL_LOCAL void poly1305_blocks_avx2(Poly1305* ctx,
    const unsigned char* m, size_t bytes);
extern WOLFSSL_LOCAL void poly1305_final_avx2(Poly1305* ctx, byte* mac);
#endif
#ifdef HAVE_INTEL_AVX512
extern WOLFSSL_LOCAL void poly1305_calc_powers_avx512(Poly1305* ctx);
extern WOLFSSL_LOCAL void poly1305_blocks_avx512(Poly1305* ctx,
    const unsigned char* m, size_t bytes);
extern WOLFSSL_LOCAL void poly1305_final_avx512(Poly1305* ctx, byte* mac);
extern WOLFSSL_LOCAL void poly1305_calc_powers_avx512ifma(Poly1305* ctx);
extern WOLFSSL_LOCAL void poly1305_setkey_avx512ifma(Poly1305* ctx,
    const byte* key);
extern WOLFSSL_LOCAL void poly1305_blocks_avx512ifma(Poly1305* ctx,
    const unsigned char* m, size_t bytes);
extern WOLFSSL_LOCAL void poly1305_final_avx512ifma(Poly1305* ctx, byte* mac);
extern WOLFSSL_LOCAL void poly1305_fold_avx512ifma(Poly1305* ctx,
    word32 nBlocks);

#endif
#endif
#ifdef WOLFSSL_X86_64_BUILD
#ifdef HAVE_INTEL_AVX1
WOLFSSL_LOCAL void poly1305_setkey_avx(Poly1305* ctx, const byte* key)
{
    word64 rdi, rsi, r10, r11, rdx, rax, rcx, r8, r9;

    rdi = (word64)(size_t)ctx;
    rsi = (word64)(size_t)key;

    r10 = (word64)(0xffffffc0fffffffULL);
    r11 = (word64)(0xffffffc0ffffffcULL);
    rdx = (word64)(WC_L64(rsi, 0));
    rax = (word64)(WC_L64(rsi, 8));
    rcx = (word64)(WC_L64(rsi, 16));
    r8 = (word64)(WC_L64(rsi, 24));
    rdx = (word64)(rdx & r10);
    rax = (word64)(rax & r11);
    r10 = (word64)(rdx);
    r11 = (word64)(rax);
    r9 = (word64)(0);
    WC_S64(rdi, 0) = (word64)(rdx);
    WC_S64(rdi, 8) = (word64)(rax);
    WC_S64(rdi, 24) = (word64)(r9);
    WC_S64(rdi, 32) = (word64)(r9);
    WC_S64(rdi, 40) = (word64)(r9);
    WC_S64(rdi, 48) = (word64)(rcx);
    WC_S64(rdi, 56) = (word64)(r8);
    WC_S64(rdi, 352) = (word64)(r9);
    WC_S64(rdi, 408) = (word64)(r9);
    WC_S64(rdi, 360) = (word64)(rdx);
    WC_S64(rdi, 416) = (word64)(rax);
    r10 = (word64)(r10 + rdx);
    r11 = (word64)(r11 + rax);
    WC_S64(rdi, 368) = (word64)(r10);
    WC_S64(rdi, 424) = (word64)(r11);
    r10 = (word64)(r10 + rdx);
    r11 = (word64)(r11 + rax);
    WC_S64(rdi, 376) = (word64)(r10);
    WC_S64(rdi, 432) = (word64)(r11);
    r10 = (word64)(r10 + rdx);
    r11 = (word64)(r11 + rax);
    WC_S64(rdi, 384) = (word64)(r10);
    WC_S64(rdi, 440) = (word64)(r11);
    r10 = (word64)(r10 + rdx);
    r11 = (word64)(r11 + rax);
    WC_S64(rdi, 392) = (word64)(r10);
    WC_S64(rdi, 448) = (word64)(r11);
    r10 = (word64)(r10 + rdx);
    r11 = (word64)(r11 + rax);
    WC_S64(rdi, 400) = (word64)(r10);
    WC_S64(rdi, 456) = (word64)(r11);
    WC_S64(rdi, 608) = (word64)(r9);
    WC_S8(rdi, 616) = (byte)(1);
}

WOLFSSL_LOCAL void poly1305_block_avx(Poly1305* ctx, const unsigned char* m)
{
    word64 rdi, rsi, r15, rbx, r8, r9, r10, r14, r11, r12, rax, rdx = 0, r13;
    unsigned char cf;

    rdi = (word64)(size_t)ctx;
    rsi = (word64)(size_t)m;

    r15 = (word64)(WC_L64(rdi, 0));
    rbx = (word64)(WC_L64(rdi, 8));
    r8 = (word64)(WC_L64(rdi, 24));
    r9 = (word64)(WC_L64(rdi, 32));
    r10 = (word64)(WC_L64(rdi, 40));
    r14 = (word64)(0);
    r14 = (r14 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, 616)) & 0xff);
    /* h += m */
    r11 = (word64)(WC_L64(rsi, 0));
    r12 = (word64)(WC_L64(rsi, 8));
    cf = _addcarry_u64(0, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    rax = (word64)(rbx);
    cf = _addcarry_u64(cf, r10, r14, (unsigned long long*)&r10);
    /* r[1] * h[0] => rdx, rax ==> t2, t1 */
    WC_X64I_MUL128(rax, rdx, rax, r8);
    r12 = (word64)(rax);
    r13 = (word64)(rdx);
    /* r[0] * h[1] => rdx, rax ++> t2, t1 */
    rax = (word64)(r15);
    WC_X64I_MUL128(rax, rdx, rax, r9);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    rax = (word64)(r15);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /* r[0] * h[0] => rdx, rax ==> t4, t0 */
    WC_X64I_MUL128(rax, rdx, rax, r8);
    r11 = (word64)(rax);
    r8 = (word64)(rdx);
    /* r[1] * h[1] => rdx, rax =+> t3, t2 */
    rax = (word64)(rbx);
    WC_X64I_MUL128(rax, rdx, rax, r9);
    /*   r[0] * h[2] +> t2 */
    r13 = (word64)(r13 + WC_L64(rdi, r10 * 8 + 352));
    r14 = (word64)(rdx);
    cf = _addcarry_u64(0, r12, r8, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rax, (unsigned long long*)&r13);
    /*   r[1] * h[2] +> t3 */
    cf = _addcarry_u64(cf, r14, WC_L64(rdi, r10 * 8 + 408), (
        unsigned long long*)&r14);
    /* r * h in r14, r13, r12, r11 */
    /* h = (r * h) mod 2^130 - 5 */
    r10 = (word64)(r13);
    r13 = (word64)(r13 & -4);
    r10 = (word64)(r10 & 3);
    cf = _addcarry_u64(0, r11, r13, (unsigned long long*)&r11);
    r8 = (word64)(r13);
    cf = _addcarry_u64(cf, r12, r14, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    r8 = (word64)((r8 >> 2) | (r14 << 62));
    r14 = (word64)(r14 >> 2);
    cf = _addcarry_u64(0, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r12, r14, (unsigned long long*)&r12);
    r9 = (word64)(r12);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    /* h in r10, r9, r8 */
    /* Store h to ctx */
    WC_S64(rdi, 24) = (word64)(r8);
    WC_S64(rdi, 32) = (word64)(r9);
    WC_S64(rdi, 40) = (word64)(r10);
}

WOLFSSL_LOCAL void poly1305_blocks_avx(Poly1305* ctx, const unsigned char* m,
    size_t bytes)
{
    word64 rdi, rsi, rcx, r15, rbx, r8, r9, r10, r11 = 0, r12 = 0, rax = 0,
           rdx = 0, r13 = 0, r14 = 0;
    unsigned char cf;

    rdi = (word64)(size_t)ctx;
    rsi = (word64)(size_t)m;
    rcx = (word64)(word64)bytes;

    r15 = (word64)(WC_L64(rdi, 0));
    rbx = (word64)(WC_L64(rdi, 8));
    r8 = (word64)(WC_L64(rdi, 24));
    r9 = (word64)(WC_L64(rdi, 32));
    r10 = (word64)(WC_L64(rdi, 40));
L_poly1305_avx_blocks_start:
    /* h += m */
    r11 = (word64)(WC_L64(rsi, 0));
    r12 = (word64)(WC_L64(rsi, 8));
    cf = _addcarry_u64(0, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r12, (unsigned long long*)&r9);
    rax = (word64)(rbx);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    /* r[1] * h[0] => rdx, rax ==> t2, t1 */
    WC_X64I_MUL128(rax, rdx, rax, r8);
    r12 = (word64)(rax);
    r13 = (word64)(rdx);
    /* r[0] * h[1] => rdx, rax ++> t2, t1 */
    rax = (word64)(r15);
    WC_X64I_MUL128(rax, rdx, rax, r9);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    rax = (word64)(r15);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /* r[0] * h[0] => rdx, rax ==> t4, t0 */
    WC_X64I_MUL128(rax, rdx, rax, r8);
    r11 = (word64)(rax);
    r8 = (word64)(rdx);
    /* r[1] * h[1] => rdx, rax =+> t3, t2 */
    rax = (word64)(rbx);
    WC_X64I_MUL128(rax, rdx, rax, r9);
    /*   r[0] * h[2] +> t2 */
    r13 = (word64)(r13 + WC_L64(rdi, r10 * 8 + 360));
    r14 = (word64)(rdx);
    cf = _addcarry_u64(0, r12, r8, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rax, (unsigned long long*)&r13);
    /*   r[1] * h[2] +> t3 */
    cf = _addcarry_u64(cf, r14, WC_L64(rdi, r10 * 8 + 416), (
        unsigned long long*)&r14);
    /* r * h in r14, r13, r12, r11 */
    /* h = (r * h) mod 2^130 - 5 */
    r10 = (word64)(r13);
    r13 = (word64)(r13 & -4);
    r10 = (word64)(r10 & 3);
    cf = _addcarry_u64(0, r11, r13, (unsigned long long*)&r11);
    r8 = (word64)(r13);
    cf = _addcarry_u64(cf, r12, r14, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    r8 = (word64)((r8 >> 2) | (r14 << 62));
    r14 = (word64)(r14 >> 2);
    cf = _addcarry_u64(0, r8, r11, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r12, r14, (unsigned long long*)&r12);
    r9 = (word64)(r12);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    /* h in r10, r9, r8 */
    /* Next block from message */
    rsi = (word64)(rsi + 0x10);
    rcx = (word64)(rcx - 0x10);
    if ((sword64)(rcx) > (sword64)(0)) {
        goto L_poly1305_avx_blocks_start;
    }
    /* Store h to ctx */
    WC_S64(rdi, 24) = (word64)(r8);
    WC_S64(rdi, 32) = (word64)(r9);
    WC_S64(rdi, 40) = (word64)(r10);
}

WOLFSSL_LOCAL void poly1305_final_avx(Poly1305* ctx, byte* mac)
{
    word64 rdi, rbx, rax, rsi = 0, rdx = 0, rcx = 0, r11 = 0, r12 = 0, r8 = 0,
           r9 = 0, r10 = 0;
    word64 zf1;
    word64 zf2;
    unsigned char cf;

    rdi = (word64)(size_t)ctx;
    rbx = (word64)(size_t)mac;

    rax = (word64)(WC_L64(rdi, 608));
    if (((rax & rax)) == (0)) {
        goto L_poly1305_avx_final_no_more;
    }
    WC_S8(rdi, rax + 480) = (byte)(1);
    goto L_poly1305_avx_final_cmp_rem;
L_poly1305_avx_final_zero_rem:
    WC_S8(rdi, rax + 480) = (byte)(0);
L_poly1305_avx_final_cmp_rem:
    rax = (rax & ~(word64)0xff) | ((word64)(byte)((byte)rax + 1) & 0xff);
    if ((sword64)(rax) < (sword64)(0x10)) {
        goto L_poly1305_avx_final_zero_rem;
    }
    WC_S8(rdi, 616) = (byte)(0);
    rsi = (word64)(rdi + 480);
    (void)poly1305_block_avx((Poly1305*)(size_t)rdi, (const unsigned char*)(
        size_t)rsi);
L_poly1305_avx_final_no_more:
    rax = (word64)(WC_L64(rdi, 24));
    rdx = (word64)(WC_L64(rdi, 32));
    rcx = (word64)(WC_L64(rdi, 40));
    r11 = (word64)(WC_L64(rdi, 48));
    r12 = (word64)(WC_L64(rdi, 56));
    /* h %= p */
    /* h = (h + pad) */
    /* mod 2^130 - 5 */
    r8 = (word64)(rcx);
    rcx = (word64)(rcx & 3);
    r8 = (word64)(r8 >> 2);
    /*   Multiply by 5 */
    r8 = (word64)(r8 + r8 * 4);
    cf = _addcarry_u64(0, rax, r8, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, rcx, 0, (unsigned long long*)&rcx);
    /* Fixup when between (1 << 130) - 1 and (1 << 130) - 5 */
    r8 = (word64)(rax);
    r9 = (word64)(rdx);
    r10 = (word64)(rcx);
    cf = _addcarry_u64(0, r8, 5, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    zf1 = r10;
    zf2 = 4;
    rax = (r10) == (4) ? r8 : rax;
    rdx = (zf1) == (zf2) ? r9 : rdx;
    /* h += pad */
    cf = _addcarry_u64(0, rax, r11, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, rdx, r12, (unsigned long long*)&rdx);
    WC_S64(rbx, 0) = (word64)(rax);
    WC_S64(rbx, 8) = (word64)(rdx);
    /* Zero out r */
    WC_S64(rdi, 0) = (word64)(0);
    WC_S64(rdi, 8) = (word64)(0);
    /* Zero out h */
    WC_S64(rdi, 24) = (word64)(0);
    WC_S64(rdi, 32) = (word64)(0);
    WC_S64(rdi, 40) = (word64)(0);
    /* Zero out pad */
    WC_S64(rdi, 48) = (word64)(0);
    WC_S64(rdi, 56) = (word64)(0);
}

#endif /* HAVE_INTEL_AVX1 */
#ifdef HAVE_INTEL_AVX2
WOLFSSL_LOCAL void poly1305_calc_powers_avx2(Poly1305* ctx)
{
    word64 rdi, rcx, r8, r9, rax, rdx, rsi, rbx, rbp, r13, r11, r12, r10, r15,
           r14;
    unsigned char cf;

    rdi = (word64)(size_t)ctx;

    rcx = (word64)(WC_L64(rdi, 0));
    r8 = (word64)(WC_L64(rdi, 8));
    r9 = (word64)(0);
    /* Convert to 26 bits in 32 */
    rax = (word64)(rcx);
    rdx = (word64)(rcx);
    rsi = (word64)(rcx);
    rbx = (word64)(r8);
    rbp = (word64)(r8);
    rdx = (word64)(rdx >> 26);
    rsi = (word64)((rsi >> 52) | (r8 << 12));
    rbx = (word64)(rbx >> 14);
    rbp = (word64)((rbp >> 40) | (r9 << 24));
    rax = (word64)(rax & 0x3ffffff);
    rdx = (word64)(rdx & 0x3ffffff);
    rsi = (word64)(rsi & 0x3ffffff);
    rbx = (word64)(rbx & 0x3ffffff);
    rbp = (word64)(rbp & 0x3ffffff);
    WC_S32(rdi, 224) = (word32)((word32)rax);
    WC_S32(rdi, 228) = (word32)((word32)rdx);
    WC_S32(rdi, 232) = (word32)((word32)rsi);
    WC_S32(rdi, 236) = (word32)((word32)rbx);
    WC_S32(rdi, 240) = (word32)((word32)rbp);
    WC_S32(rdi, 244) = (word32)(0);
    /* Square 128-bit */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    r13 = (word64)(0);
    r11 = (word64)(rax);
    r12 = (word64)(rdx);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r10 = (word64)(rax);
    r15 = (word64)(rdx);
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r11, r15, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /* Reduce 256-bit to 130-bit */
    rax = (word64)(r12);
    rdx = (word64)(r13);
    rax = (word64)(rax & -4);
    r12 = (word64)(r12 & 3);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)(rdx >> 2);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    rax = (word64)(r12);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    r12 = (word64)(r12 & 3);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /* Convert to 26 bits in 32 */
    rax = (word64)(r10);
    rdx = (word64)(r10);
    rsi = (word64)(r10);
    rbx = (word64)(r11);
    rbp = (word64)(r11);
    rdx = (word64)(rdx >> 26);
    rsi = (word64)((rsi >> 52) | (r11 << 12));
    rbx = (word64)(rbx >> 14);
    rbp = (word64)((rbp >> 40) | (r12 << 24));
    rax = (word64)(rax & 0x3ffffff);
    rdx = (word64)(rdx & 0x3ffffff);
    rsi = (word64)(rsi & 0x3ffffff);
    rbx = (word64)(rbx & 0x3ffffff);
    rbp = (word64)(rbp & 0x3ffffff);
    WC_S32(rdi, 256) = (word32)((word32)rax);
    WC_S32(rdi, 260) = (word32)((word32)rdx);
    WC_S32(rdi, 264) = (word32)((word32)rsi);
    WC_S32(rdi, 268) = (word32)((word32)rbx);
    WC_S32(rdi, 272) = (word32)((word32)rbp);
    WC_S32(rdi, 276) = (word32)(0);
    /* Multiply 128-bit by 130-bit */
    /*   r1[0] * r2[0] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    r13 = (word64)(rax);
    r14 = (word64)(rdx);
    /*   r1[0] * r2[1] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    /*   r1[1] * r2[0] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    rsi = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, 0, (unsigned long long*)&rsi);
    /*   r1[0] * r2[2] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    /*   r1[1] * r2[1] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*   r1[1] * r2[2] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    /* Reduce 260-bit to 130-bit */
    rax = (word64)(r15);
    rdx = (word64)(rsi);
    rbx = (word64)(rbx);
    rax = (word64)(rax & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rbx, (unsigned long long*)&r15);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)((rdx >> 2) | (rbx << 62));
    rbx = (word64)(rbx >> 2);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rbx, (unsigned long long*)&r15);
    rax = (word64)(r15);
    r15 = (word64)(r15 & 3);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /* Convert to 26 bits in 32 */
    rax = (word64)(r13);
    rdx = (word64)(r13);
    rsi = (word64)(r13);
    rbx = (word64)(r14);
    rbp = (word64)(r14);
    rdx = (word64)(rdx >> 26);
    rsi = (word64)((rsi >> 52) | (r14 << 12));
    rbx = (word64)(rbx >> 14);
    rbp = (word64)((rbp >> 40) | (r15 << 24));
    rax = (word64)(rax & 0x3ffffff);
    rdx = (word64)(rdx & 0x3ffffff);
    rsi = (word64)(rsi & 0x3ffffff);
    rbx = (word64)(rbx & 0x3ffffff);
    rbp = (word64)(rbp & 0x3ffffff);
    WC_S32(rdi, 288) = (word32)((word32)rax);
    WC_S32(rdi, 292) = (word32)((word32)rdx);
    WC_S32(rdi, 296) = (word32)((word32)rsi);
    WC_S32(rdi, 300) = (word32)((word32)rbx);
    WC_S32(rdi, 304) = (word32)((word32)rbp);
    WC_S32(rdi, 308) = (word32)(0);
    /* Square 130-bit */
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    r13 = (word64)(0);
    r8 = (word64)(rax);
    r9 = (word64)(rdx);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    rax = (word64)(r10);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    rcx = (word64)(rax);
    r15 = (word64)(rdx);
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r8, r15, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r14 = (word64)(rax);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /* Reduce 260-bit to 130-bit */
    rax = (word64)(r9);
    rdx = (word64)(r13);
    r15 = (word64)(r14);
    rax = (word64)(rax & -4);
    r9 = (word64)(r9 & 3);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, rdx, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r15, (unsigned long long*)&r9);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)((rdx >> 2) | (r15 << 62));
    r15 = (word64)(r15 >> 2);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, rdx, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r15, (unsigned long long*)&r9);
    rax = (word64)(r9);
    r9 = (word64)(r9 & 3);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    /* Convert to 26 bits in 32 */
    rax = (word64)(rcx);
    rdx = (word64)(rcx);
    rsi = (word64)(rcx);
    rbx = (word64)(r8);
    rbp = (word64)(r8);
    rdx = (word64)(rdx >> 26);
    rsi = (word64)((rsi >> 52) | (r8 << 12));
    rbx = (word64)(rbx >> 14);
    rbp = (word64)((rbp >> 40) | (r9 << 24));
    rax = (word64)(rax & 0x3ffffff);
    rdx = (word64)(rdx & 0x3ffffff);
    rsi = (word64)(rsi & 0x3ffffff);
    rbx = (word64)(rbx & 0x3ffffff);
    rbp = (word64)(rbp & 0x3ffffff);
    WC_S32(rdi, 320) = (word32)((word32)rax);
    WC_S32(rdi, 324) = (word32)((word32)rdx);
    WC_S32(rdi, 328) = (word32)((word32)rsi);
    WC_S32(rdi, 332) = (word32)((word32)rbx);
    WC_S32(rdi, 336) = (word32)((word32)rbp);
    WC_S32(rdi, 340) = (word32)(0);
}

WC_X64I_TARGET("avx2")
WOLFSSL_LOCAL void poly1305_setkey_avx2(Poly1305* ctx, const byte* key)
{
    word64 rdi, rsi;
    __m256i y0;

    rdi = (word64)(size_t)ctx;
    rsi = (word64)(size_t)key;

    (void)poly1305_setkey_avx((Poly1305*)(size_t)rdi, (const byte*)(size_t)rsi);
    y0 = _mm256_setzero_si256();
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 64), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 96), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 128), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 160), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 192), y0);
    WC_S64(rdi, 608) = (word64)(0);
    WC_S16(rdi, 616) = (word16)(0);
}

XALIGNED(32) static const word64 L_poly1305_avx2_blocks_mask[]
    WC_X64I_UNUSED = {
    0x0000000003ffffffULL, 0x0000000003ffffffULL,
    0x0000000003ffffffULL, 0x0000000003ffffffULL,
};

XALIGNED(32) static const word64 L_poly1305_avx2_blocks_hibit[]
    WC_X64I_UNUSED = {
    0x0000000001000000ULL, 0x0000000001000000ULL,
    0x0000000001000000ULL, 0x0000000001000000ULL,
};

WC_X64I_TARGET("avx2")
WOLFSSL_LOCAL void poly1305_blocks_avx2(Poly1305* ctx, const unsigned char* m,
    size_t bytes)
{
    word64 rdi, rsi, rdx, rsp, r13, r14, rcx, rbx, rax, r8 = 0, r9 = 0,
           r10 = 0, r11 = 0, r12 = 0;
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y4 = _mm256_setzero_si256(), y5 = _mm256_setzero_si256(),
            y6 = _mm256_setzero_si256(), y7 = _mm256_setzero_si256(),
            y8 = _mm256_setzero_si256(), y9 = _mm256_setzero_si256(),
            y10 = _mm256_setzero_si256(), y11 = _mm256_setzero_si256(),
            y12 = _mm256_setzero_si256(), y13 = _mm256_setzero_si256(),
            y14 = _mm256_setzero_si256(), y15;
    XALIGNED(32) WC_X64I_SLOT stk[40];
    unsigned char cf;

    rdi = (word64)(size_t)ctx;
    rsi = (word64)(size_t)m;
    rdx = (word64)(word64)bytes;

    rsp = (word64)(size_t)stk + 320;
    rsp = (word64)(rsp - 320);
    r13 = (word64)((word64)(size_t)L_poly1305_avx2_blocks_mask);
    r14 = (word64)((word64)(size_t)L_poly1305_avx2_blocks_hibit);
    rcx = (word64)(rsp);
    rcx = (word64)(rcx & -32);
    rcx = (word64)(rcx + 0x20);
    y15 = _mm256_setzero_si256();
    rbx = (word64)(rcx);
    rax = (word64)(rdi + 64);
    rbx = (word64)(rbx + 0xa0);
    if ((WC_L16(rdi, 616)) != (0)) {
        goto L_poly1305_avx2_blocks_begin_h;
    }
    /* Load the message data */
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 32));
    y2 = _mm256_permute2x128_si256(y0, y1, 0x20);
    y0 = _mm256_permute2x128_si256(y0, y1, 0x31);
    y1 = _mm256_unpacklo_epi32(y2, y0);
    y3 = _mm256_unpackhi_epi32(y2, y0);
    y0 = _mm256_unpacklo_epi32(y1, y15);
    y1 = _mm256_unpackhi_epi32(y1, y15);
    y2 = _mm256_unpacklo_epi32(y3, y15);
    y3 = _mm256_unpackhi_epi32(y3, y15);
    y4 = _mm256_loadu_si256((const __m256i*)WC_PR(r14, 0));
    y1 = _mm256_slli_epi64(y1, 6);
    y2 = _mm256_slli_epi64(y2, 12);
    y3 = _mm256_slli_epi64(y3, 18);
    y14 = _mm256_loadu_si256((const __m256i*)WC_PR(r13, 0));
    /* Reduce, in place, the message data */
    y10 = _mm256_srli_epi64(y0, 26);
    y11 = _mm256_srli_epi64(y3, 26);
    y0 = _mm256_and_si256(y0, y14);
    y3 = _mm256_and_si256(y3, y14);
    y1 = _mm256_add_epi64(y10, y1);
    y4 = _mm256_add_epi64(y11, y4);
    y10 = _mm256_srli_epi64(y1, 26);
    y11 = _mm256_srli_epi64(y4, 26);
    y1 = _mm256_and_si256(y1, y14);
    y4 = _mm256_and_si256(y4, y14);
    y2 = _mm256_add_epi64(y10, y2);
    y12 = _mm256_slli_epi32(y11, 2);
    y12 = _mm256_add_epi32(y11, y12);
    y10 = _mm256_srli_epi64(y2, 26);
    y0 = _mm256_add_epi64(y12, y0);
    y11 = _mm256_srli_epi64(y0, 26);
    y2 = _mm256_and_si256(y2, y14);
    y0 = _mm256_and_si256(y0, y14);
    y3 = _mm256_add_epi64(y10, y3);
    y1 = _mm256_add_epi64(y11, y1);
    y10 = _mm256_srli_epi64(y3, 26);
    y3 = _mm256_and_si256(y3, y14);
    y4 = _mm256_add_epi64(y10, y4);
    rsi = (word64)(rsi + 0x40);
    rdx = (word64)(rdx - 0x40);
    if ((rdx) == (0)) {
        goto L_poly1305_avx2_blocks_store;
    }
    goto L_poly1305_avx2_blocks_load_r4;
L_poly1305_avx2_blocks_begin_h:
    /* Load the H values. */
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rax, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rax, 32));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rax, 64));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(rax, 96));
    y4 = _mm256_loadu_si256((const __m256i*)WC_PR(rax, 128));
    /* Check if there is a power of r to load - otherwise use r^4. */
    if ((WC_L8(rdi, 616)) == (0)) {
        goto L_poly1305_avx2_blocks_load_r4;
    }
    /* Load the 4 powers of r - r^4, r^3, r^2, r^1. */
    y8 = _mm256_loadu_si256((const __m256i*)WC_PR(rdi, 224));
    y7 = _mm256_loadu_si256((const __m256i*)WC_PR(rdi, 256));
    y6 = _mm256_loadu_si256((const __m256i*)WC_PR(rdi, 288));
    y5 = _mm256_loadu_si256((const __m256i*)WC_PR(rdi, 320));
    y5 = _mm256_permute4x64_epi64(y5, 0xd8);
    y6 = _mm256_permute4x64_epi64(y6, 0xd8);
    y7 = _mm256_permute4x64_epi64(y7, 0xd8);
    y8 = _mm256_permute4x64_epi64(y8, 0xd8);
    y10 = _mm256_unpacklo_epi64(y5, y6);
    y11 = _mm256_unpackhi_epi64(y5, y6);
    y12 = _mm256_unpacklo_epi64(y7, y8);
    y13 = _mm256_unpackhi_epi64(y7, y8);
    y5 = _mm256_permute2x128_si256(y10, y12, 0x20);
    y7 = _mm256_permute2x128_si256(y10, y12, 0x31);
    y9 = _mm256_permute2x128_si256(y11, y13, 0x20);
    y6 = _mm256_srli_epi64(y5, 32);
    y8 = _mm256_srli_epi64(y7, 32);
    goto L_poly1305_avx2_blocks_mul_5;
L_poly1305_avx2_blocks_load_r4:
    /* Load r^4 into all four positions. */
    y13 = _mm256_loadu_si256((const __m256i*)WC_PR(rdi, 320));
    y5 = _mm256_permute4x64_epi64(y13, 0);
    y14 = _mm256_srli_epi64(y13, 32);
    y7 = _mm256_permute4x64_epi64(y13, 0x55);
    y9 = _mm256_permute4x64_epi64(y13, 0xaa);
    y6 = _mm256_permute4x64_epi64(y14, 0);
    y8 = _mm256_permute4x64_epi64(y14, 0x55);
L_poly1305_avx2_blocks_mul_5:
    /* Multiply top 4 26-bit values of all four H by 5 */
    y10 = _mm256_slli_epi32(y6, 2);
    y11 = _mm256_slli_epi32(y7, 2);
    y12 = _mm256_slli_epi32(y8, 2);
    y13 = _mm256_slli_epi32(y9, 2);
    y10 = _mm256_add_epi64(y6, y10);
    y11 = _mm256_add_epi64(y7, y11);
    y12 = _mm256_add_epi64(y8, y12);
    y13 = _mm256_add_epi64(y9, y13);
    /* Store powers of r and multiple of 5 for use in multiply. */
    _mm256_storeu_si256((__m256i*)WC_PW(rbx, 0), y10);
    _mm256_storeu_si256((__m256i*)WC_PW(rbx, 32), y11);
    _mm256_storeu_si256((__m256i*)WC_PW(rbx, 64), y12);
    _mm256_storeu_si256((__m256i*)WC_PW(rbx, 96), y13);
    _mm256_storeu_si256((__m256i*)WC_PW(rcx, 0), y5);
    _mm256_storeu_si256((__m256i*)WC_PW(rcx, 32), y6);
    _mm256_storeu_si256((__m256i*)WC_PW(rcx, 64), y7);
    _mm256_storeu_si256((__m256i*)WC_PW(rcx, 96), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rcx, 128), y9);
    y14 = _mm256_loadu_si256((const __m256i*)WC_PR(r13, 0));
    /* If not finished then loop over data */
    if ((WC_L8(rdi, 616)) != (1)) {
        goto L_poly1305_avx2_blocks_start;
    }
    /* Do last multiply, reduce, add the four H together and move to */
    /* 32-bit registers */
    y5 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y10 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y6 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y7 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y5 = _mm256_add_epi64(y10, y5);
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y8 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y6 = _mm256_add_epi64(y11, y6);
    y13 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y10 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y5 = _mm256_add_epi64(y12, y5);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y12 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        0)));
    y5 = _mm256_add_epi64(y13, y5);
    y9 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        0)));
    y6 = _mm256_add_epi64(y10, y6);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        0)));
    y7 = _mm256_add_epi64(y11, y7);
    y10 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        0)));
    y8 = _mm256_add_epi64(y12, y8);
    y11 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        0)));
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        32)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        32)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        32)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        32)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        64)));
    y9 = _mm256_add_epi64(y13, y9);
    y13 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        64)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        64)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        96)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        96)));
    y9 = _mm256_add_epi64(y13, y9);
    y7 = _mm256_add_epi64(y10, y7);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        128)));
    y8 = _mm256_add_epi64(y11, y8);
    y9 = _mm256_add_epi64(y12, y9);
    y9 = _mm256_add_epi64(y13, y9);
    y10 = _mm256_srli_epi64(y5, 26);
    y11 = _mm256_srli_epi64(y8, 26);
    y5 = _mm256_and_si256(y5, y14);
    y8 = _mm256_and_si256(y8, y14);
    y6 = _mm256_add_epi64(y10, y6);
    y9 = _mm256_add_epi64(y11, y9);
    y10 = _mm256_srli_epi64(y6, 26);
    y11 = _mm256_srli_epi64(y9, 26);
    y1 = _mm256_and_si256(y6, y14);
    y4 = _mm256_and_si256(y9, y14);
    y7 = _mm256_add_epi64(y10, y7);
    y12 = _mm256_slli_epi32(y11, 2);
    y12 = _mm256_add_epi32(y11, y12);
    y10 = _mm256_srli_epi64(y7, 26);
    y5 = _mm256_add_epi64(y12, y5);
    y11 = _mm256_srli_epi64(y5, 26);
    y2 = _mm256_and_si256(y7, y14);
    y0 = _mm256_and_si256(y5, y14);
    y8 = _mm256_add_epi64(y10, y8);
    y1 = _mm256_add_epi64(y11, y1);
    y10 = _mm256_srli_epi64(y8, 26);
    y3 = _mm256_and_si256(y8, y14);
    y4 = _mm256_add_epi64(y10, y4);
    y5 = _mm256_bsrli_epi128(y0, 8);
    y6 = _mm256_bsrli_epi128(y1, 8);
    y7 = _mm256_bsrli_epi128(y2, 8);
    y8 = _mm256_bsrli_epi128(y3, 8);
    y9 = _mm256_bsrli_epi128(y4, 8);
    y0 = _mm256_add_epi64(y5, y0);
    y1 = _mm256_add_epi64(y6, y1);
    y2 = _mm256_add_epi64(y7, y2);
    y3 = _mm256_add_epi64(y8, y3);
    y4 = _mm256_add_epi64(y9, y4);
    y5 = _mm256_permute4x64_epi64(y0, 2);
    y6 = _mm256_permute4x64_epi64(y1, 2);
    y7 = _mm256_permute4x64_epi64(y2, 2);
    y8 = _mm256_permute4x64_epi64(y3, 2);
    y9 = _mm256_permute4x64_epi64(y4, 2);
    y0 = _mm256_add_epi64(y5, y0);
    y1 = _mm256_add_epi64(y6, y1);
    y2 = _mm256_add_epi64(y7, y2);
    y3 = _mm256_add_epi64(y8, y3);
    y4 = _mm256_add_epi64(y9, y4);
    r8 = (word32)((word32)_mm_cvtsi128_si32(_mm256_castsi256_si128(y0)));
    r9 = (word32)((word32)_mm_cvtsi128_si32(_mm256_castsi256_si128(y1)));
    r10 = (word32)((word32)_mm_cvtsi128_si32(_mm256_castsi256_si128(y2)));
    r11 = (word32)((word32)_mm_cvtsi128_si32(_mm256_castsi256_si128(y3)));
    r12 = (word32)((word32)_mm_cvtsi128_si32(_mm256_castsi256_si128(y4)));
    goto L_poly1305_avx2_blocks_end_calc;
L_poly1305_avx2_blocks_start:
    y5 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 0));
    y6 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 32));
    y7 = _mm256_permute2x128_si256(y5, y6, 0x20);
    y5 = _mm256_permute2x128_si256(y5, y6, 0x31);
    y6 = _mm256_unpacklo_epi32(y7, y5);
    y8 = _mm256_unpackhi_epi32(y7, y5);
    y5 = _mm256_unpacklo_epi32(y6, y15);
    y6 = _mm256_unpackhi_epi32(y6, y15);
    y7 = _mm256_unpacklo_epi32(y8, y15);
    y8 = _mm256_unpackhi_epi32(y8, y15);
    y9 = _mm256_loadu_si256((const __m256i*)WC_PR(r14, 0));
    y6 = _mm256_slli_epi64(y6, 6);
    y7 = _mm256_slli_epi64(y7, 12);
    y8 = _mm256_slli_epi64(y8, 18);
    y10 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y5 = _mm256_add_epi64(y10, y5);
    y10 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y11 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y6 = _mm256_add_epi64(y11, y6);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y12 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y7 = _mm256_add_epi64(y12, y7);
    y5 = _mm256_add_epi64(y10, y5);
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y13 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y8 = _mm256_add_epi64(y13, y8);
    y6 = _mm256_add_epi64(y11, y6);
    y13 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y10 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y5 = _mm256_add_epi64(y12, y5);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y12 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        0)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        0)));
    y9 = _mm256_add_epi64(y13, y9);
    y6 = _mm256_add_epi64(y10, y6);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        0)));
    y7 = _mm256_add_epi64(y11, y7);
    y10 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        0)));
    y8 = _mm256_add_epi64(y12, y8);
    y11 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        0)));
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        32)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        32)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        32)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        32)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        64)));
    y9 = _mm256_add_epi64(y13, y9);
    y13 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        64)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        64)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        96)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        96)));
    y9 = _mm256_add_epi64(y13, y9);
    y7 = _mm256_add_epi64(y10, y7);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        128)));
    y8 = _mm256_add_epi64(y11, y8);
    y9 = _mm256_add_epi64(y12, y9);
    y9 = _mm256_add_epi64(y13, y9);
    y10 = _mm256_srli_epi64(y5, 26);
    y11 = _mm256_srli_epi64(y8, 26);
    y5 = _mm256_and_si256(y5, y14);
    y8 = _mm256_and_si256(y8, y14);
    y6 = _mm256_add_epi64(y10, y6);
    y9 = _mm256_add_epi64(y11, y9);
    y10 = _mm256_srli_epi64(y6, 26);
    y11 = _mm256_srli_epi64(y9, 26);
    y1 = _mm256_and_si256(y6, y14);
    y4 = _mm256_and_si256(y9, y14);
    y7 = _mm256_add_epi64(y10, y7);
    y12 = _mm256_slli_epi32(y11, 2);
    y12 = _mm256_add_epi32(y11, y12);
    y10 = _mm256_srli_epi64(y7, 26);
    y5 = _mm256_add_epi64(y12, y5);
    y11 = _mm256_srli_epi64(y5, 26);
    y2 = _mm256_and_si256(y7, y14);
    y0 = _mm256_and_si256(y5, y14);
    y8 = _mm256_add_epi64(y10, y8);
    y1 = _mm256_add_epi64(y11, y1);
    y10 = _mm256_srli_epi64(y8, 26);
    y3 = _mm256_and_si256(y8, y14);
    y4 = _mm256_add_epi64(y10, y4);
    rsi = (word64)(rsi + 0x40);
    rdx = (word64)(rdx - 0x40);
    if ((rdx) != (0)) {
        goto L_poly1305_avx2_blocks_start;
    }
L_poly1305_avx2_blocks_store:
    /* Store four H values - state */
    _mm256_storeu_si256((__m256i*)WC_PW(rax, 0), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rax, 32), y1);
    _mm256_storeu_si256((__m256i*)WC_PW(rax, 64), y2);
    _mm256_storeu_si256((__m256i*)WC_PW(rax, 96), y3);
    _mm256_storeu_si256((__m256i*)WC_PW(rax, 128), y4);
L_poly1305_avx2_blocks_end_calc:
    if ((WC_L8(rdi, 616)) == (0)) {
        goto L_poly1305_avx2_blocks_complete;
    }
    rax = (word64)(r8);
    rdx = (word64)(r10);
    rcx = (word64)(r12);
    rdx = (word64)(rdx >> 12);
    rcx = (word64)(rcx >> 24);
    r9 = (word64)(r9 << 26);
    r10 = (word64)(r10 << 52);
    r11 = (word64)(r11 << 14);
    r12 = (word64)(r12 << 40);
    cf = _addcarry_u64(0, rax, r9, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, rax, r10, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, rdx, r12, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, rcx, 0, (unsigned long long*)&rcx);
    r8 = (word64)(rcx);
    rcx = (word64)(rcx & 3);
    r8 = (word64)(r8 >> 2);
    r8 = (word64)(r8 + r8 * 4);
    cf = _addcarry_u64(0, rax, r8, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, rcx, 0, (unsigned long long*)&rcx);
    WC_S64(rdi, 24) = (word64)(rax);
    WC_S64(rdi, 32) = (word64)(rdx);
    WC_S64(rdi, 40) = (word64)(rcx);
L_poly1305_avx2_blocks_complete:
    WC_S8(rdi, 617) = (byte)(1);
}

WC_X64I_TARGET("avx2")
WOLFSSL_LOCAL void poly1305_final_avx2(Poly1305* ctx, byte* mac)
{
    word64 rdi, rsi, rcx = 0, rsp, rdx = 0, rax = 0, r8 = 0;
    __m256i y0 = _mm256_setzero_si256();
    XALIGNED(32) WC_X64I_SLOT stk[4];

    rdi = (word64)(size_t)ctx;
    rsi = (word64)(size_t)mac;

    rsp = (word64)(size_t)stk + 32;
    WC_S8(rdi, 616) = (byte)(1);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, 617)) & 0xff);
    if (((byte)rcx) == (0)) {
        goto L_poly1305_avx2_final_done_blocks_X4;
    }
    rsp = (word64)(rsp - 8);
    WC_S64(rsp, 0) = rsi;
    rdx = (word64)(0x40);
    rsi = (word64)(0);
    (void)poly1305_blocks_avx2((Poly1305*)(size_t)rdi, (const unsigned char*)(
        size_t)rsi, (size_t)rdx);
    rsi = WC_L64(rsp, 0);
    rsp = (word64)(rsp + 8);
L_poly1305_avx2_final_done_blocks_X4:
    rax = (word64)(WC_L64(rdi, 608));
    rcx = (word64)(rax);
    rcx = (word64)(rcx & -16);
    if (((byte)rcx) == (0)) {
        goto L_poly1305_avx2_final_done_blocks;
    }
    rsp = (word64)(rsp - 8);
    WC_S64(rsp, 0) = rcx;
    rsp = (word64)(rsp - 8);
    WC_S64(rsp, 0) = rax;
    rsp = (word64)(rsp - 8);
    WC_S64(rsp, 0) = rsi;
    rdx = (word64)(rcx);
    rsi = (word64)(rdi + 480);
    (void)poly1305_blocks_avx((Poly1305*)(size_t)rdi, (const unsigned char*)(
        size_t)rsi, (size_t)rdx);
    rsi = WC_L64(rsp, 0);
    rsp = (word64)(rsp + 8);
    rax = WC_L64(rsp, 0);
    rsp = (word64)(rsp + 8);
    rcx = WC_L64(rsp, 0);
    rsp = (word64)(rsp + 8);
L_poly1305_avx2_final_done_blocks:
    WC_S64(rdi, 608) = (word64)(WC_L64(rdi, 608) - rcx);
    rdx = (word64)(0);
    goto L_poly1305_avx2_final_cmp_copy;
L_poly1305_avx2_final_start_copy:
    r8 = (r8 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, rcx + 480)) & 0xff);
    WC_S8(rdi, rdx + 480) = (byte)((byte)r8);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)((byte)rcx + 1) & 0xff);
    rdx = (rdx & ~(word64)0xff) | ((word64)(byte)((byte)rdx + 1) & 0xff);
L_poly1305_avx2_final_cmp_copy:
    if (((byte)rax) != ((byte)rcx)) {
        goto L_poly1305_avx2_final_start_copy;
    }
    (void)poly1305_final_avx((Poly1305*)(size_t)rdi, (byte*)(size_t)rsi);
    y0 = _mm256_setzero_si256();
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 64), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 96), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 128), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 160), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 192), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 224), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 256), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 288), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 320), y0);
    WC_S64(rdi, 608) = (word64)(0);
    WC_S16(rdi, 616) = (word16)(0);
}

#endif /* HAVE_INTEL_AVX2 */
#ifdef HAVE_INTEL_AVX512
WOLFSSL_LOCAL void poly1305_calc_powers_avx512(Poly1305* ctx)
{
    word64 rdi, rsp, rcx, r8, r9, rax, rdx, rsi, rbx, rbp, r13, r11, r12, r10,
           r15, r14;
    XALIGNED(32) WC_X64I_SLOT stk[12];
    unsigned char cf;

    rdi = (word64)(size_t)ctx;

    rsp = (word64)(size_t)stk + 96;
    rsp = (word64)(rsp - 96);
    rcx = (word64)(WC_L64(rdi, 0));
    r8 = (word64)(WC_L64(rdi, 8));
    r9 = (word64)(0);
    /* Convert to 26 bits in 32 */
    rax = (word64)(rcx);
    rdx = (word64)(rcx);
    rsi = (word64)(rcx);
    rbx = (word64)(r8);
    rbp = (word64)(r8);
    rdx = (word64)(rdx >> 26);
    rsi = (word64)((rsi >> 52) | (r8 << 12));
    rbx = (word64)(rbx >> 14);
    rbp = (word64)((rbp >> 40) | (r9 << 24));
    rax = (word64)(rax & 0x3ffffff);
    rdx = (word64)(rdx & 0x3ffffff);
    rsi = (word64)(rsi & 0x3ffffff);
    rbx = (word64)(rbx & 0x3ffffff);
    rbp = (word64)(rbp & 0x3ffffff);
    WC_S32(rdi, 224) = (word32)((word32)rax);
    WC_S32(rdi, 228) = (word32)((word32)rdx);
    WC_S32(rdi, 232) = (word32)((word32)rsi);
    WC_S32(rdi, 236) = (word32)((word32)rbx);
    WC_S32(rdi, 240) = (word32)((word32)rbp);
    WC_S32(rdi, 244) = (word32)(0);
    WC_S64(rsp, 0) = (word64)(rcx);
    WC_S64(rsp, 8) = (word64)(r8);
    WC_S64(rsp, 16) = (word64)(r9);
    /* Square 128-bit */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    r13 = (word64)(0);
    r11 = (word64)(rax);
    r12 = (word64)(rdx);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r10 = (word64)(rax);
    r15 = (word64)(rdx);
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r11, r15, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /* Reduce 256-bit to 130-bit */
    rax = (word64)(r12);
    rdx = (word64)(r13);
    rax = (word64)(rax & -4);
    r12 = (word64)(r12 & 3);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)(rdx >> 2);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    rax = (word64)(r12);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    r12 = (word64)(r12 & 3);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /* Convert to 26 bits in 32 */
    rax = (word64)(r10);
    rdx = (word64)(r10);
    rsi = (word64)(r10);
    rbx = (word64)(r11);
    rbp = (word64)(r11);
    rdx = (word64)(rdx >> 26);
    rsi = (word64)((rsi >> 52) | (r11 << 12));
    rbx = (word64)(rbx >> 14);
    rbp = (word64)((rbp >> 40) | (r12 << 24));
    rax = (word64)(rax & 0x3ffffff);
    rdx = (word64)(rdx & 0x3ffffff);
    rsi = (word64)(rsi & 0x3ffffff);
    rbx = (word64)(rbx & 0x3ffffff);
    rbp = (word64)(rbp & 0x3ffffff);
    WC_S32(rdi, 256) = (word32)((word32)rax);
    WC_S32(rdi, 260) = (word32)((word32)rdx);
    WC_S32(rdi, 264) = (word32)((word32)rsi);
    WC_S32(rdi, 268) = (word32)((word32)rbx);
    WC_S32(rdi, 272) = (word32)((word32)rbp);
    WC_S32(rdi, 276) = (word32)(0);
    WC_S64(rsp, 24) = (word64)(r10);
    WC_S64(rsp, 32) = (word64)(r11);
    WC_S64(rsp, 40) = (word64)(r12);
    /* Multiply 128-bit by 130-bit */
    /*   r1[0] * r2[0] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    r13 = (word64)(rax);
    r14 = (word64)(rdx);
    /*   r1[0] * r2[1] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    /*   r1[1] * r2[0] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    rsi = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, 0, (unsigned long long*)&rsi);
    /*   r1[0] * r2[2] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    /*   r1[1] * r2[1] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*   r1[1] * r2[2] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    /* Reduce 260-bit to 130-bit */
    rax = (word64)(r15);
    rdx = (word64)(rsi);
    rbx = (word64)(rbx);
    rax = (word64)(rax & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rbx, (unsigned long long*)&r15);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)((rdx >> 2) | (rbx << 62));
    rbx = (word64)(rbx >> 2);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rbx, (unsigned long long*)&r15);
    rax = (word64)(r15);
    r15 = (word64)(r15 & 3);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /* Convert to 26 bits in 32 */
    rax = (word64)(r13);
    rdx = (word64)(r13);
    rsi = (word64)(r13);
    rbx = (word64)(r14);
    rbp = (word64)(r14);
    rdx = (word64)(rdx >> 26);
    rsi = (word64)((rsi >> 52) | (r14 << 12));
    rbx = (word64)(rbx >> 14);
    rbp = (word64)((rbp >> 40) | (r15 << 24));
    rax = (word64)(rax & 0x3ffffff);
    rdx = (word64)(rdx & 0x3ffffff);
    rsi = (word64)(rsi & 0x3ffffff);
    rbx = (word64)(rbx & 0x3ffffff);
    rbp = (word64)(rbp & 0x3ffffff);
    WC_S32(rdi, 288) = (word32)((word32)rax);
    WC_S32(rdi, 292) = (word32)((word32)rdx);
    WC_S32(rdi, 296) = (word32)((word32)rsi);
    WC_S32(rdi, 300) = (word32)((word32)rbx);
    WC_S32(rdi, 304) = (word32)((word32)rbp);
    WC_S32(rdi, 308) = (word32)(0);
    WC_S64(rsp, 48) = (word64)(r13);
    WC_S64(rsp, 56) = (word64)(r14);
    WC_S64(rsp, 64) = (word64)(r15);
    /* Square 130-bit */
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    r13 = (word64)(0);
    r8 = (word64)(rax);
    r9 = (word64)(rdx);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    rax = (word64)(r10);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    rcx = (word64)(rax);
    r15 = (word64)(rdx);
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r8, r15, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r14 = (word64)(rax);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /* Reduce 260-bit to 130-bit */
    rax = (word64)(r9);
    rdx = (word64)(r13);
    r15 = (word64)(r14);
    rax = (word64)(rax & -4);
    r9 = (word64)(r9 & 3);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, rdx, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r15, (unsigned long long*)&r9);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)((rdx >> 2) | (r15 << 62));
    r15 = (word64)(r15 >> 2);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, rdx, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r15, (unsigned long long*)&r9);
    rax = (word64)(r9);
    r9 = (word64)(r9 & 3);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    /* Convert to 26 bits in 32 */
    rax = (word64)(rcx);
    rdx = (word64)(rcx);
    rsi = (word64)(rcx);
    rbx = (word64)(r8);
    rbp = (word64)(r8);
    rdx = (word64)(rdx >> 26);
    rsi = (word64)((rsi >> 52) | (r8 << 12));
    rbx = (word64)(rbx >> 14);
    rbp = (word64)((rbp >> 40) | (r9 << 24));
    rax = (word64)(rax & 0x3ffffff);
    rdx = (word64)(rdx & 0x3ffffff);
    rsi = (word64)(rsi & 0x3ffffff);
    rbx = (word64)(rbx & 0x3ffffff);
    rbp = (word64)(rbp & 0x3ffffff);
    WC_S32(rdi, 320) = (word32)((word32)rax);
    WC_S32(rdi, 324) = (word32)((word32)rdx);
    WC_S32(rdi, 328) = (word32)((word32)rsi);
    WC_S32(rdi, 332) = (word32)((word32)rbx);
    WC_S32(rdi, 336) = (word32)((word32)rbp);
    WC_S32(rdi, 340) = (word32)(0);
    WC_S64(rsp, 72) = (word64)(rcx);
    WC_S64(rsp, 80) = (word64)(r8);
    WC_S64(rsp, 88) = (word64)(r9);
    r10 = (word64)(WC_L64(rsp, 0));
    r11 = (word64)(WC_L64(rsp, 8));
    r12 = (word64)(WC_L64(rsp, 16));
    /* Multiply 128-bit by 130-bit */
    /*   r1[0] * r2[0] */
    rax = (word64)(r10);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    r13 = (word64)(rax);
    r14 = (word64)(rdx);
    /*   r1[0] * r2[1] */
    rax = (word64)(r10);
    WC_X64I_MUL128(rax, rdx, rax, r8);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    /*   r1[1] * r2[0] */
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    rsi = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, 0, (unsigned long long*)&rsi);
    /*   r1[0] * r2[2] */
    rax = (word64)(r10);
    WC_X64I_MUL128(rax, rdx, rax, r9);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    /*   r1[1] * r2[1] */
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, r8);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*   r1[1] * r2[2] */
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, r9);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    /* Reduce 260-bit to 130-bit */
    rax = (word64)(r15);
    rdx = (word64)(rsi);
    rbx = (word64)(rbx);
    rax = (word64)(rax & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rbx, (unsigned long long*)&r15);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)((rdx >> 2) | (rbx << 62));
    rbx = (word64)(rbx >> 2);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rbx, (unsigned long long*)&r15);
    rax = (word64)(r15);
    r15 = (word64)(r15 & 3);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /* Convert to 26 bits in 32 */
    rax = (word64)(r13);
    rdx = (word64)(r13);
    rsi = (word64)(r13);
    rbx = (word64)(r14);
    rbp = (word64)(r14);
    rdx = (word64)(rdx >> 26);
    rsi = (word64)((rsi >> 52) | (r14 << 12));
    rbx = (word64)(rbx >> 14);
    rbp = (word64)((rbp >> 40) | (r15 << 24));
    rax = (word64)(rax & 0x3ffffff);
    rdx = (word64)(rdx & 0x3ffffff);
    rsi = (word64)(rsi & 0x3ffffff);
    rbx = (word64)(rbx & 0x3ffffff);
    rbp = (word64)(rbp & 0x3ffffff);
    WC_S32(rdi, 624) = (word32)((word32)rax);
    WC_S32(rdi, 628) = (word32)((word32)rdx);
    WC_S32(rdi, 632) = (word32)((word32)rsi);
    WC_S32(rdi, 636) = (word32)((word32)rbx);
    WC_S32(rdi, 640) = (word32)((word32)rbp);
    WC_S32(rdi, 644) = (word32)(0);
    /* Square 130-bit */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    r13 = (word64)(0);
    r11 = (word64)(rax);
    r12 = (word64)(rdx);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r10 = (word64)(rax);
    r15 = (word64)(rdx);
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r11, r15, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    rax = (word64)(r9);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r14 = (word64)(rax);
    rax = (word64)(r9);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    rax = (word64)(r9);
    WC_X64I_MUL128(rax, rdx, rax, r8);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /* Reduce 260-bit to 130-bit */
    rax = (word64)(r12);
    rdx = (word64)(r13);
    r15 = (word64)(r14);
    rax = (word64)(rax & -4);
    r12 = (word64)(r12 & 3);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)((rdx >> 2) | (r15 << 62));
    r15 = (word64)(r15 >> 2);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    rax = (word64)(r12);
    r12 = (word64)(r12 & 3);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /* Convert to 26 bits in 32 */
    rax = (word64)(r10);
    rdx = (word64)(r10);
    rsi = (word64)(r10);
    rbx = (word64)(r11);
    rbp = (word64)(r11);
    rdx = (word64)(rdx >> 26);
    rsi = (word64)((rsi >> 52) | (r11 << 12));
    rbx = (word64)(rbx >> 14);
    rbp = (word64)((rbp >> 40) | (r12 << 24));
    rax = (word64)(rax & 0x3ffffff);
    rdx = (word64)(rdx & 0x3ffffff);
    rsi = (word64)(rsi & 0x3ffffff);
    rbx = (word64)(rbx & 0x3ffffff);
    rbp = (word64)(rbp & 0x3ffffff);
    WC_S32(rdi, 720) = (word32)((word32)rax);
    WC_S32(rdi, 724) = (word32)((word32)rdx);
    WC_S32(rdi, 728) = (word32)((word32)rsi);
    WC_S32(rdi, 732) = (word32)((word32)rbx);
    WC_S32(rdi, 736) = (word32)((word32)rbp);
    WC_S32(rdi, 740) = (word32)(0);
    rcx = (word64)(WC_L64(rsp, 48));
    r8 = (word64)(WC_L64(rsp, 56));
    r9 = (word64)(WC_L64(rsp, 64));
    /* Square 130-bit */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    r13 = (word64)(0);
    r11 = (word64)(rax);
    r12 = (word64)(rdx);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r10 = (word64)(rax);
    r15 = (word64)(rdx);
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r11, r15, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    rax = (word64)(r9);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r14 = (word64)(rax);
    rax = (word64)(r9);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    rax = (word64)(r9);
    WC_X64I_MUL128(rax, rdx, rax, r8);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /* Reduce 260-bit to 130-bit */
    rax = (word64)(r12);
    rdx = (word64)(r13);
    r15 = (word64)(r14);
    rax = (word64)(rax & -4);
    r12 = (word64)(r12 & 3);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)((rdx >> 2) | (r15 << 62));
    r15 = (word64)(r15 >> 2);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    rax = (word64)(r12);
    r12 = (word64)(r12 & 3);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /* Convert to 26 bits in 32 */
    rax = (word64)(r10);
    rdx = (word64)(r10);
    rsi = (word64)(r10);
    rbx = (word64)(r11);
    rbp = (word64)(r11);
    rdx = (word64)(rdx >> 26);
    rsi = (word64)((rsi >> 52) | (r11 << 12));
    rbx = (word64)(rbx >> 14);
    rbp = (word64)((rbp >> 40) | (r12 << 24));
    rax = (word64)(rax & 0x3ffffff);
    rdx = (word64)(rdx & 0x3ffffff);
    rsi = (word64)(rsi & 0x3ffffff);
    rbx = (word64)(rbx & 0x3ffffff);
    rbp = (word64)(rbp & 0x3ffffff);
    WC_S32(rdi, 656) = (word32)((word32)rax);
    WC_S32(rdi, 660) = (word32)((word32)rdx);
    WC_S32(rdi, 664) = (word32)((word32)rsi);
    WC_S32(rdi, 668) = (word32)((word32)rbx);
    WC_S32(rdi, 672) = (word32)((word32)rbp);
    WC_S32(rdi, 676) = (word32)(0);
    rcx = (word64)(WC_L64(rsp, 0));
    r8 = (word64)(WC_L64(rsp, 8));
    r9 = (word64)(WC_L64(rsp, 16));
    /* Multiply 128-bit by 130-bit */
    /*   r1[0] * r2[0] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    r13 = (word64)(rax);
    r14 = (word64)(rdx);
    /*   r1[0] * r2[1] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    /*   r1[1] * r2[0] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    rsi = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, 0, (unsigned long long*)&rsi);
    /*   r1[0] * r2[2] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    /*   r1[1] * r2[1] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*   r1[1] * r2[2] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    /* Reduce 260-bit to 130-bit */
    rax = (word64)(r15);
    rdx = (word64)(rsi);
    rbx = (word64)(rbx);
    rax = (word64)(rax & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rbx, (unsigned long long*)&r15);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)((rdx >> 2) | (rbx << 62));
    rbx = (word64)(rbx >> 2);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rbx, (unsigned long long*)&r15);
    rax = (word64)(r15);
    r15 = (word64)(r15 & 3);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /* Convert to 26 bits in 32 */
    rax = (word64)(r13);
    rdx = (word64)(r13);
    rsi = (word64)(r13);
    rbx = (word64)(r14);
    rbp = (word64)(r14);
    rdx = (word64)(rdx >> 26);
    rsi = (word64)((rsi >> 52) | (r14 << 12));
    rbx = (word64)(rbx >> 14);
    rbp = (word64)((rbp >> 40) | (r15 << 24));
    rax = (word64)(rax & 0x3ffffff);
    rdx = (word64)(rdx & 0x3ffffff);
    rsi = (word64)(rsi & 0x3ffffff);
    rbx = (word64)(rbx & 0x3ffffff);
    rbp = (word64)(rbp & 0x3ffffff);
    WC_S32(rdi, 688) = (word32)((word32)rax);
    WC_S32(rdi, 692) = (word32)((word32)rdx);
    WC_S32(rdi, 696) = (word32)((word32)rsi);
    WC_S32(rdi, 700) = (word32)((word32)rbx);
    WC_S32(rdi, 704) = (word32)((word32)rbp);
    WC_S32(rdi, 708) = (word32)(0);
}

XALIGNED(32) static const word64 L_poly1305_avx512_blocks_mask[]
    WC_X64I_UNUSED = {
    0x0000000003ffffffULL, 0x0000000003ffffffULL,
    0x0000000003ffffffULL, 0x0000000003ffffffULL,
    0x0000000003ffffffULL, 0x0000000003ffffffULL,
    0x0000000003ffffffULL, 0x0000000003ffffffULL,
};

XALIGNED(32) static const word64 L_poly1305_avx512_blocks_hibit[]
    WC_X64I_UNUSED = {
    0x0000000001000000ULL, 0x0000000001000000ULL,
    0x0000000001000000ULL, 0x0000000001000000ULL,
    0x0000000001000000ULL, 0x0000000001000000ULL,
    0x0000000001000000ULL, 0x0000000001000000ULL,
};

XALIGNED(32) static const word64 L_poly1305_avx512_blocks_permidx[]
    WC_X64I_UNUSED = {
    0x0000000400000000ULL, 0x0000000c00000008ULL,
    0x0000001400000010ULL, 0x0000001c00000018ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000500000001ULL, 0x0000000d00000009ULL,
    0x0000001500000011ULL, 0x0000001d00000019ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000600000002ULL, 0x0000000e0000000aULL,
    0x0000001600000012ULL, 0x0000001e0000001aULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000700000003ULL, 0x0000000f0000000bULL,
    0x0000001700000013ULL, 0x0000001f0000001bULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
};

XALIGNED(32) static const word64 L_poly1305_avx512_blocks_rxidx[]
    WC_X64I_UNUSED = {
    0x0000001000000018ULL, 0x0000000000000008ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000001100000019ULL, 0x0000000100000009ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x000000120000001aULL, 0x000000020000000aULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x000000130000001bULL, 0x000000030000000bULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x000000140000001cULL, 0x000000040000000cULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
};

WC_X64I_TARGET("avx512f,avx512vl,avx512bw")
WOLFSSL_LOCAL void poly1305_blocks_avx512(Poly1305* ctx, const unsigned char* m,
    size_t bytes)
{
    word64 rdi, rsi, rdx, rcx, r13, r14, r15, rax, r8 = 0, r9 = 0, r10 = 0,
           r11 = 0, r12 = 0;
    __m512i z0 = _mm512_setzero_si512(), z1 = _mm512_setzero_si512(),
            z2 = _mm512_setzero_si512(), z3 = _mm512_setzero_si512(),
            z4 = _mm512_setzero_si512(), z5 = _mm512_setzero_si512(),
            z6 = _mm512_setzero_si512(), z7 = _mm512_setzero_si512(),
            z8 = _mm512_setzero_si512(), z9 = _mm512_setzero_si512(),
            z10 = _mm512_setzero_si512(), z11 = _mm512_setzero_si512(),
            z12 = _mm512_setzero_si512(), z13 = _mm512_setzero_si512(),
            z14 = _mm512_setzero_si512(), z15 = _mm512_setzero_si512(),
            z16 = _mm512_setzero_si512(), z17 = _mm512_setzero_si512(),
            z18 = _mm512_setzero_si512(), z19 = _mm512_setzero_si512(),
            z20 = _mm512_setzero_si512(), z21 = _mm512_setzero_si512(),
            z22 = _mm512_setzero_si512(), z23 = _mm512_setzero_si512(), z24,
            z25 = _mm512_setzero_si512(), z26 = _mm512_setzero_si512(),
            z27 = _mm512_setzero_si512();
    unsigned char cf;

    rdi = (word64)(size_t)ctx;
    rsi = (word64)(size_t)m;
    rdx = (word64)(word64)bytes;

    rcx = (word64)((word64)(size_t)L_poly1305_avx512_blocks_mask);
    r13 = (word64)((word64)(size_t)L_poly1305_avx512_blocks_hibit);
    r14 = (word64)((word64)(size_t)L_poly1305_avx512_blocks_permidx);
    r15 = (word64)((word64)(size_t)L_poly1305_avx512_blocks_rxidx);
    z24 = _mm512_setzero_si512();
    rax = (word64)(rdi + 64);
    if ((WC_L16(rdi, 616)) != (0)) {
        goto L_poly1305_avx512_blocks_begin_h;
    }
    /* Load the message data */
    z25 = _mm512_loadu_si512((const void*)WC_PR(rsi, 0));
    z26 = _mm512_loadu_si512((const void*)WC_PR(rsi, 64));
    z27 = _mm512_loadu_si512((const void*)WC_PR(r14, 0));
    z27 = _mm512_permutex2var_epi32(z25, z27, z26);
    z0 = _mm512_cvtepu32_epi64(_mm512_castsi512_si256(z27));
    z27 = _mm512_loadu_si512((const void*)WC_PR(r14, 64));
    z27 = _mm512_permutex2var_epi32(z25, z27, z26);
    z1 = _mm512_cvtepu32_epi64(_mm512_castsi512_si256(z27));
    z27 = _mm512_loadu_si512((const void*)WC_PR(r14, 128));
    z27 = _mm512_permutex2var_epi32(z25, z27, z26);
    z2 = _mm512_cvtepu32_epi64(_mm512_castsi512_si256(z27));
    z27 = _mm512_loadu_si512((const void*)WC_PR(r14, 192));
    z27 = _mm512_permutex2var_epi32(z25, z27, z26);
    z3 = _mm512_cvtepu32_epi64(_mm512_castsi512_si256(z27));
    z4 = _mm512_loadu_si512((const void*)WC_PR(r13, 0));
    z1 = _mm512_slli_epi64(z1, 6);
    z2 = _mm512_slli_epi64(z2, 12);
    z3 = _mm512_slli_epi64(z3, 18);
    z23 = _mm512_loadu_si512((const void*)WC_PR(rcx, 0));
    /* Reduce, in place, the message data */
    z19 = _mm512_srli_epi64(z0, 26);
    z20 = _mm512_srli_epi64(z3, 26);
    z0 = _mm512_and_si512(z0, z23);
    z3 = _mm512_and_si512(z3, z23);
    z1 = _mm512_add_epi64(z19, z1);
    z4 = _mm512_add_epi64(z20, z4);
    z19 = _mm512_srli_epi64(z1, 26);
    z20 = _mm512_srli_epi64(z4, 26);
    z1 = _mm512_and_si512(z1, z23);
    z4 = _mm512_and_si512(z4, z23);
    z2 = _mm512_add_epi64(z19, z2);
    z21 = _mm512_slli_epi32(z20, 2);
    z21 = _mm512_add_epi32(z20, z21);
    z19 = _mm512_srli_epi64(z2, 26);
    z0 = _mm512_add_epi64(z21, z0);
    z20 = _mm512_srli_epi64(z0, 26);
    z2 = _mm512_and_si512(z2, z23);
    z0 = _mm512_and_si512(z0, z23);
    z3 = _mm512_add_epi64(z19, z3);
    z1 = _mm512_add_epi64(z20, z1);
    z19 = _mm512_srli_epi64(z3, 26);
    z3 = _mm512_and_si512(z3, z23);
    z4 = _mm512_add_epi64(z19, z4);
    rsi = (word64)(rsi + 0x80);
    rdx = (word64)(rdx - 0x80);
    if ((rdx) == (0)) {
        goto L_poly1305_avx512_blocks_store;
    }
    goto L_poly1305_avx512_blocks_load_r8;
L_poly1305_avx512_blocks_begin_h:
    /* Load the H values. */
    z0 = _mm512_cvtepu32_epi64(_mm256_loadu_si256((const __m256i*)WC_PR(rax,
        0)));
    z1 = _mm512_cvtepu32_epi64(_mm256_loadu_si256((const __m256i*)WC_PR(rax,
        32)));
    z2 = _mm512_cvtepu32_epi64(_mm256_loadu_si256((const __m256i*)WC_PR(rax,
        64)));
    z3 = _mm512_cvtepu32_epi64(_mm256_loadu_si256((const __m256i*)WC_PR(rax,
        96)));
    z4 = _mm512_cvtepu32_epi64(_mm256_loadu_si256((const __m256i*)WC_PR(rax,
        128)));
    /* Check if there is a power of r to load - otherwise use r^8. */
    if ((WC_L8(rdi, 616)) == (0)) {
        goto L_poly1305_avx512_blocks_load_r8;
    }
    /* Load the 8 powers of r - r^8 .. r^1. */
    z14 = _mm512_loadu_si512((const void*)WC_PR(rdi, 224));
    z15 = _mm512_loadu_si512((const void*)WC_PR(rdi, 288));
    z16 = _mm512_loadu_si512((const void*)WC_PR(rdi, 624));
    z17 = _mm512_loadu_si512((const void*)WC_PR(rdi, 688));
    z18 = _mm512_loadu_si512((const void*)WC_PR(r15, 0));
    z18 = _mm512_permutex2var_epi32(z16, z18, z17);
    z20 = _mm512_zextsi256_si512(_mm256_cvtepu32_epi64(_mm512_castsi512_si128(
        z18)));
    z19 = _mm512_loadu_si512((const void*)WC_PR(r15, 0));
    z19 = _mm512_permutex2var_epi32(z14, z19, z15);
    z21 = _mm512_zextsi256_si512(_mm256_cvtepu32_epi64(_mm512_castsi512_si128(
        z19)));
    z5 = _mm512_inserti64x4(z20, _mm512_castsi512_si256(z21), 1);
    z18 = _mm512_loadu_si512((const void*)WC_PR(r15, 64));
    z18 = _mm512_permutex2var_epi32(z16, z18, z17);
    z20 = _mm512_zextsi256_si512(_mm256_cvtepu32_epi64(_mm512_castsi512_si128(
        z18)));
    z19 = _mm512_loadu_si512((const void*)WC_PR(r15, 64));
    z19 = _mm512_permutex2var_epi32(z14, z19, z15);
    z21 = _mm512_zextsi256_si512(_mm256_cvtepu32_epi64(_mm512_castsi512_si128(
        z19)));
    z6 = _mm512_inserti64x4(z20, _mm512_castsi512_si256(z21), 1);
    z18 = _mm512_loadu_si512((const void*)WC_PR(r15, 128));
    z18 = _mm512_permutex2var_epi32(z16, z18, z17);
    z20 = _mm512_zextsi256_si512(_mm256_cvtepu32_epi64(_mm512_castsi512_si128(
        z18)));
    z19 = _mm512_loadu_si512((const void*)WC_PR(r15, 128));
    z19 = _mm512_permutex2var_epi32(z14, z19, z15);
    z21 = _mm512_zextsi256_si512(_mm256_cvtepu32_epi64(_mm512_castsi512_si128(
        z19)));
    z7 = _mm512_inserti64x4(z20, _mm512_castsi512_si256(z21), 1);
    z18 = _mm512_loadu_si512((const void*)WC_PR(r15, 192));
    z18 = _mm512_permutex2var_epi32(z16, z18, z17);
    z20 = _mm512_zextsi256_si512(_mm256_cvtepu32_epi64(_mm512_castsi512_si128(
        z18)));
    z19 = _mm512_loadu_si512((const void*)WC_PR(r15, 192));
    z19 = _mm512_permutex2var_epi32(z14, z19, z15);
    z21 = _mm512_zextsi256_si512(_mm256_cvtepu32_epi64(_mm512_castsi512_si128(
        z19)));
    z8 = _mm512_inserti64x4(z20, _mm512_castsi512_si256(z21), 1);
    z18 = _mm512_loadu_si512((const void*)WC_PR(r15, 256));
    z18 = _mm512_permutex2var_epi32(z16, z18, z17);
    z20 = _mm512_zextsi256_si512(_mm256_cvtepu32_epi64(_mm512_castsi512_si128(
        z18)));
    z19 = _mm512_loadu_si512((const void*)WC_PR(r15, 256));
    z19 = _mm512_permutex2var_epi32(z14, z19, z15);
    z21 = _mm512_zextsi256_si512(_mm256_cvtepu32_epi64(_mm512_castsi512_si128(
        z19)));
    z9 = _mm512_inserti64x4(z20, _mm512_castsi512_si256(z21), 1);
    goto L_poly1305_avx512_blocks_mul_5;
L_poly1305_avx512_blocks_load_r8:
    /* Load r^8 into all eight lanes. */
    z5 = _mm512_set1_epi32((int)WC_L32(rdi, 720));
    z6 = _mm512_set1_epi32((int)WC_L32(rdi, 724));
    z7 = _mm512_set1_epi32((int)WC_L32(rdi, 728));
    z8 = _mm512_set1_epi32((int)WC_L32(rdi, 732));
    z9 = _mm512_set1_epi32((int)WC_L32(rdi, 736));
L_poly1305_avx512_blocks_mul_5:
    /* Multiply top 4 26-bit values of all eight powers by 5 */
    z10 = _mm512_slli_epi32(z6, 2);
    z11 = _mm512_slli_epi32(z7, 2);
    z12 = _mm512_slli_epi32(z8, 2);
    z13 = _mm512_slli_epi32(z9, 2);
    z10 = _mm512_add_epi64(z6, z10);
    z11 = _mm512_add_epi64(z7, z11);
    z12 = _mm512_add_epi64(z8, z12);
    z13 = _mm512_add_epi64(z9, z13);
    z23 = _mm512_loadu_si512((const void*)WC_PR(rcx, 0));
    /* If not finished then loop over data */
    if ((WC_L8(rdi, 616)) != (1)) {
        goto L_poly1305_avx512_blocks_start;
    }
    /* Do last multiply, reduce, add the eight H together and move to */
    /* 32-bit registers */
    z14 = _mm512_mul_epu32(z4, z10);
    z19 = _mm512_mul_epu32(z3, z11);
    z15 = _mm512_mul_epu32(z4, z11);
    z20 = _mm512_mul_epu32(z3, z12);
    z16 = _mm512_mul_epu32(z4, z12);
    z14 = _mm512_add_epi64(z19, z14);
    z21 = _mm512_mul_epu32(z2, z12);
    z17 = _mm512_mul_epu32(z4, z13);
    z15 = _mm512_add_epi64(z20, z15);
    z22 = _mm512_mul_epu32(z1, z13);
    z19 = _mm512_mul_epu32(z2, z13);
    z14 = _mm512_add_epi64(z21, z14);
    z20 = _mm512_mul_epu32(z3, z13);
    z21 = _mm512_mul_epu32(z3, z5);
    z14 = _mm512_add_epi64(z22, z14);
    z18 = _mm512_mul_epu32(z4, z5);
    z15 = _mm512_add_epi64(z19, z15);
    z22 = _mm512_mul_epu32(z0, z5);
    z16 = _mm512_add_epi64(z20, z16);
    z19 = _mm512_mul_epu32(z1, z5);
    z17 = _mm512_add_epi64(z21, z17);
    z20 = _mm512_mul_epu32(z2, z5);
    z21 = _mm512_mul_epu32(z2, z6);
    z14 = _mm512_add_epi64(z22, z14);
    z22 = _mm512_mul_epu32(z3, z6);
    z15 = _mm512_add_epi64(z19, z15);
    z19 = _mm512_mul_epu32(z0, z6);
    z16 = _mm512_add_epi64(z20, z16);
    z20 = _mm512_mul_epu32(z1, z6);
    z17 = _mm512_add_epi64(z21, z17);
    z21 = _mm512_mul_epu32(z1, z7);
    z18 = _mm512_add_epi64(z22, z18);
    z22 = _mm512_mul_epu32(z2, z7);
    z15 = _mm512_add_epi64(z19, z15);
    z19 = _mm512_mul_epu32(z0, z7);
    z16 = _mm512_add_epi64(z20, z16);
    z20 = _mm512_mul_epu32(z0, z8);
    z17 = _mm512_add_epi64(z21, z17);
    z21 = _mm512_mul_epu32(z1, z8);
    z18 = _mm512_add_epi64(z22, z18);
    z16 = _mm512_add_epi64(z19, z16);
    z22 = _mm512_mul_epu32(z0, z9);
    z17 = _mm512_add_epi64(z20, z17);
    z18 = _mm512_add_epi64(z21, z18);
    z18 = _mm512_add_epi64(z22, z18);
    z19 = _mm512_srli_epi64(z14, 26);
    z20 = _mm512_srli_epi64(z17, 26);
    z14 = _mm512_and_si512(z14, z23);
    z17 = _mm512_and_si512(z17, z23);
    z15 = _mm512_add_epi64(z19, z15);
    z18 = _mm512_add_epi64(z20, z18);
    z19 = _mm512_srli_epi64(z15, 26);
    z20 = _mm512_srli_epi64(z18, 26);
    z1 = _mm512_and_si512(z15, z23);
    z4 = _mm512_and_si512(z18, z23);
    z16 = _mm512_add_epi64(z19, z16);
    z21 = _mm512_slli_epi32(z20, 2);
    z21 = _mm512_add_epi32(z20, z21);
    z19 = _mm512_srli_epi64(z16, 26);
    z14 = _mm512_add_epi64(z21, z14);
    z20 = _mm512_srli_epi64(z14, 26);
    z2 = _mm512_and_si512(z16, z23);
    z0 = _mm512_and_si512(z14, z23);
    z17 = _mm512_add_epi64(z19, z17);
    z1 = _mm512_add_epi64(z20, z1);
    z19 = _mm512_srli_epi64(z17, 26);
    z3 = _mm512_and_si512(z17, z23);
    z4 = _mm512_add_epi64(z19, z4);
    z14 = _mm512_shuffle_i64x2(z0, z0, 0x4e);
    z15 = _mm512_shuffle_i64x2(z1, z1, 0x4e);
    z16 = _mm512_shuffle_i64x2(z2, z2, 0x4e);
    z17 = _mm512_shuffle_i64x2(z3, z3, 0x4e);
    z18 = _mm512_shuffle_i64x2(z4, z4, 0x4e);
    z0 = _mm512_add_epi64(z14, z0);
    z1 = _mm512_add_epi64(z15, z1);
    z2 = _mm512_add_epi64(z16, z2);
    z3 = _mm512_add_epi64(z17, z3);
    z4 = _mm512_add_epi64(z18, z4);
    z14 = _mm512_bsrli_epi128(z0, 8);
    z15 = _mm512_bsrli_epi128(z1, 8);
    z16 = _mm512_bsrli_epi128(z2, 8);
    z17 = _mm512_bsrli_epi128(z3, 8);
    z18 = _mm512_bsrli_epi128(z4, 8);
    z0 = _mm512_add_epi64(z14, z0);
    z1 = _mm512_add_epi64(z15, z1);
    z2 = _mm512_add_epi64(z16, z2);
    z3 = _mm512_add_epi64(z17, z3);
    z4 = _mm512_add_epi64(z18, z4);
    z14 = _mm512_permutex_epi64(z0, 2);
    z15 = _mm512_permutex_epi64(z1, 2);
    z16 = _mm512_permutex_epi64(z2, 2);
    z17 = _mm512_permutex_epi64(z3, 2);
    z18 = _mm512_permutex_epi64(z4, 2);
    z0 = _mm512_add_epi64(z14, z0);
    z1 = _mm512_add_epi64(z15, z1);
    z2 = _mm512_add_epi64(z16, z2);
    z3 = _mm512_add_epi64(z17, z3);
    z4 = _mm512_add_epi64(z18, z4);
    r8 = (word32)((word32)_mm_cvtsi128_si32(_mm512_castsi512_si128(z0)));
    r9 = (word32)((word32)_mm_cvtsi128_si32(_mm512_castsi512_si128(z1)));
    r10 = (word32)((word32)_mm_cvtsi128_si32(_mm512_castsi512_si128(z2)));
    r11 = (word32)((word32)_mm_cvtsi128_si32(_mm512_castsi512_si128(z3)));
    r12 = (word32)((word32)_mm_cvtsi128_si32(_mm512_castsi512_si128(z4)));
    goto L_poly1305_avx512_blocks_end_calc;
L_poly1305_avx512_blocks_start:
    z25 = _mm512_loadu_si512((const void*)WC_PR(rsi, 0));
    z26 = _mm512_loadu_si512((const void*)WC_PR(rsi, 64));
    z27 = _mm512_loadu_si512((const void*)WC_PR(r14, 0));
    z27 = _mm512_permutex2var_epi32(z25, z27, z26);
    z14 = _mm512_cvtepu32_epi64(_mm512_castsi512_si256(z27));
    z27 = _mm512_loadu_si512((const void*)WC_PR(r14, 64));
    z27 = _mm512_permutex2var_epi32(z25, z27, z26);
    z15 = _mm512_cvtepu32_epi64(_mm512_castsi512_si256(z27));
    z27 = _mm512_loadu_si512((const void*)WC_PR(r14, 128));
    z27 = _mm512_permutex2var_epi32(z25, z27, z26);
    z16 = _mm512_cvtepu32_epi64(_mm512_castsi512_si256(z27));
    z27 = _mm512_loadu_si512((const void*)WC_PR(r14, 192));
    z27 = _mm512_permutex2var_epi32(z25, z27, z26);
    z17 = _mm512_cvtepu32_epi64(_mm512_castsi512_si256(z27));
    z18 = _mm512_loadu_si512((const void*)WC_PR(r13, 0));
    z15 = _mm512_slli_epi64(z15, 6);
    z16 = _mm512_slli_epi64(z16, 12);
    z17 = _mm512_slli_epi64(z17, 18);
    z19 = _mm512_mul_epu32(z4, z10);
    z14 = _mm512_add_epi64(z19, z14);
    z19 = _mm512_mul_epu32(z3, z11);
    z20 = _mm512_mul_epu32(z4, z11);
    z15 = _mm512_add_epi64(z20, z15);
    z20 = _mm512_mul_epu32(z3, z12);
    z21 = _mm512_mul_epu32(z4, z12);
    z16 = _mm512_add_epi64(z21, z16);
    z14 = _mm512_add_epi64(z19, z14);
    z21 = _mm512_mul_epu32(z2, z12);
    z22 = _mm512_mul_epu32(z4, z13);
    z17 = _mm512_add_epi64(z22, z17);
    z15 = _mm512_add_epi64(z20, z15);
    z22 = _mm512_mul_epu32(z1, z13);
    z19 = _mm512_mul_epu32(z2, z13);
    z14 = _mm512_add_epi64(z21, z14);
    z20 = _mm512_mul_epu32(z3, z13);
    z21 = _mm512_mul_epu32(z3, z5);
    z14 = _mm512_add_epi64(z22, z14);
    z22 = _mm512_mul_epu32(z4, z5);
    z18 = _mm512_add_epi64(z22, z18);
    z15 = _mm512_add_epi64(z19, z15);
    z22 = _mm512_mul_epu32(z0, z5);
    z16 = _mm512_add_epi64(z20, z16);
    z19 = _mm512_mul_epu32(z1, z5);
    z17 = _mm512_add_epi64(z21, z17);
    z20 = _mm512_mul_epu32(z2, z5);
    z21 = _mm512_mul_epu32(z2, z6);
    z14 = _mm512_add_epi64(z22, z14);
    z22 = _mm512_mul_epu32(z3, z6);
    z15 = _mm512_add_epi64(z19, z15);
    z19 = _mm512_mul_epu32(z0, z6);
    z16 = _mm512_add_epi64(z20, z16);
    z20 = _mm512_mul_epu32(z1, z6);
    z17 = _mm512_add_epi64(z21, z17);
    z21 = _mm512_mul_epu32(z1, z7);
    z18 = _mm512_add_epi64(z22, z18);
    z22 = _mm512_mul_epu32(z2, z7);
    z15 = _mm512_add_epi64(z19, z15);
    z19 = _mm512_mul_epu32(z0, z7);
    z16 = _mm512_add_epi64(z20, z16);
    z20 = _mm512_mul_epu32(z0, z8);
    z17 = _mm512_add_epi64(z21, z17);
    z21 = _mm512_mul_epu32(z1, z8);
    z18 = _mm512_add_epi64(z22, z18);
    z16 = _mm512_add_epi64(z19, z16);
    z22 = _mm512_mul_epu32(z0, z9);
    z17 = _mm512_add_epi64(z20, z17);
    z18 = _mm512_add_epi64(z21, z18);
    z18 = _mm512_add_epi64(z22, z18);
    z19 = _mm512_srli_epi64(z14, 26);
    z20 = _mm512_srli_epi64(z17, 26);
    z14 = _mm512_and_si512(z14, z23);
    z17 = _mm512_and_si512(z17, z23);
    z15 = _mm512_add_epi64(z19, z15);
    z18 = _mm512_add_epi64(z20, z18);
    z19 = _mm512_srli_epi64(z15, 26);
    z20 = _mm512_srli_epi64(z18, 26);
    z1 = _mm512_and_si512(z15, z23);
    z4 = _mm512_and_si512(z18, z23);
    z16 = _mm512_add_epi64(z19, z16);
    z21 = _mm512_slli_epi32(z20, 2);
    z21 = _mm512_add_epi32(z20, z21);
    z19 = _mm512_srli_epi64(z16, 26);
    z14 = _mm512_add_epi64(z21, z14);
    z20 = _mm512_srli_epi64(z14, 26);
    z2 = _mm512_and_si512(z16, z23);
    z0 = _mm512_and_si512(z14, z23);
    z17 = _mm512_add_epi64(z19, z17);
    z1 = _mm512_add_epi64(z20, z1);
    z19 = _mm512_srli_epi64(z17, 26);
    z3 = _mm512_and_si512(z17, z23);
    z4 = _mm512_add_epi64(z19, z4);
    rsi = (word64)(rsi + 0x80);
    rdx = (word64)(rdx - 0x80);
    if ((rdx) != (0)) {
        goto L_poly1305_avx512_blocks_start;
    }
L_poly1305_avx512_blocks_store:
    /* Store eight H values - state */
    _mm256_storeu_si256((__m256i*)WC_PW(rax, 0), _mm512_cvtepi64_epi32(z0));
    _mm256_storeu_si256((__m256i*)WC_PW(rax, 32), _mm512_cvtepi64_epi32(z1));
    _mm256_storeu_si256((__m256i*)WC_PW(rax, 64), _mm512_cvtepi64_epi32(z2));
    _mm256_storeu_si256((__m256i*)WC_PW(rax, 96), _mm512_cvtepi64_epi32(z3));
    _mm256_storeu_si256((__m256i*)WC_PW(rax, 128), _mm512_cvtepi64_epi32(z4));
L_poly1305_avx512_blocks_end_calc:
    if ((WC_L8(rdi, 616)) == (0)) {
        goto L_poly1305_avx512_blocks_complete;
    }
    rax = (word64)(r8);
    rdx = (word64)(r10);
    rcx = (word64)(r12);
    rdx = (word64)(rdx >> 12);
    rcx = (word64)(rcx >> 24);
    r9 = (word64)(r9 << 26);
    r10 = (word64)(r10 << 52);
    r11 = (word64)(r11 << 14);
    r12 = (word64)(r12 << 40);
    cf = _addcarry_u64(0, rax, r9, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, rax, r10, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, rdx, r11, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, rdx, r12, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, rcx, 0, (unsigned long long*)&rcx);
    r8 = (word64)(rcx);
    rcx = (word64)(rcx & 3);
    r8 = (word64)(r8 >> 2);
    r8 = (word64)(r8 + r8 * 4);
    cf = _addcarry_u64(0, rax, r8, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, rdx, 0, (unsigned long long*)&rdx);
    cf = _addcarry_u64(cf, rcx, 0, (unsigned long long*)&rcx);
    WC_S64(rdi, 24) = (word64)(rax);
    WC_S64(rdi, 32) = (word64)(rdx);
    WC_S64(rdi, 40) = (word64)(rcx);
L_poly1305_avx512_blocks_complete:
    WC_S8(rdi, 617) = (byte)(1);
    (void)z24;
}

WC_X64I_TARGET("avx2")
WOLFSSL_LOCAL void poly1305_final_avx512(Poly1305* ctx, byte* mac)
{
    word64 rdi, rsi, rcx = 0, rsp, rdx = 0, rax = 0, r8 = 0;
    __m256i y0 = _mm256_setzero_si256();
    XALIGNED(32) WC_X64I_SLOT stk[4];

    rdi = (word64)(size_t)ctx;
    rsi = (word64)(size_t)mac;

    rsp = (word64)(size_t)stk + 32;
    WC_S8(rdi, 616) = (byte)(1);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, 617)) & 0xff);
    if (((byte)rcx) == (0)) {
        goto L_poly1305_avx512_final_done_blocks_X8;
    }
    rsp = (word64)(rsp - 8);
    WC_S64(rsp, 0) = rsi;
    rdx = (word64)(0x80);
    rsi = (word64)(0);
    (void)poly1305_blocks_avx512((Poly1305*)(size_t)rdi, (const unsigned char*)(
        size_t)rsi, (size_t)rdx);
    rsi = WC_L64(rsp, 0);
    rsp = (word64)(rsp + 8);
L_poly1305_avx512_final_done_blocks_X8:
    rax = (word64)(WC_L64(rdi, 608));
    rcx = (word64)(rax);
    rcx = (word64)(rcx & -16);
    if (((byte)rcx) == (0)) {
        goto L_poly1305_avx512_final_done_blocks;
    }
    rsp = (word64)(rsp - 8);
    WC_S64(rsp, 0) = rcx;
    rsp = (word64)(rsp - 8);
    WC_S64(rsp, 0) = rax;
    rsp = (word64)(rsp - 8);
    WC_S64(rsp, 0) = rsi;
    rdx = (word64)(rcx);
    rsi = (word64)(rdi + 480);
    (void)poly1305_blocks_avx((Poly1305*)(size_t)rdi, (const unsigned char*)(
        size_t)rsi, (size_t)rdx);
    rsi = WC_L64(rsp, 0);
    rsp = (word64)(rsp + 8);
    rax = WC_L64(rsp, 0);
    rsp = (word64)(rsp + 8);
    rcx = WC_L64(rsp, 0);
    rsp = (word64)(rsp + 8);
L_poly1305_avx512_final_done_blocks:
    WC_S64(rdi, 608) = (word64)(WC_L64(rdi, 608) - rcx);
    rdx = (word64)(0);
    goto L_poly1305_avx512_final_cmp_copy;
L_poly1305_avx512_final_start_copy:
    r8 = (r8 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, rcx + 480)) & 0xff);
    WC_S8(rdi, rdx + 480) = (byte)((byte)r8);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)((byte)rcx + 1) & 0xff);
    rdx = (rdx & ~(word64)0xff) | ((word64)(byte)((byte)rdx + 1) & 0xff);
L_poly1305_avx512_final_cmp_copy:
    if (((byte)rax) != ((byte)rcx)) {
        goto L_poly1305_avx512_final_start_copy;
    }
    (void)poly1305_final_avx((Poly1305*)(size_t)rdi, (byte*)(size_t)rsi);
    y0 = _mm256_zextsi128_si256(_mm_setzero_si128());
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 64), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 96), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 128), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 160), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 192), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 224), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 256), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 288), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 320), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 624), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 656), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 688), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 720), y0);
    WC_S64(rdi, 608) = (word64)(0);
    WC_S16(rdi, 616) = (word16)(0);
}

#endif /* HAVE_INTEL_AVX512 */
#ifdef HAVE_INTEL_AVX512
WOLFSSL_LOCAL void poly1305_calc_powers_avx512ifma(Poly1305* ctx)
{
    word64 rdi, rsp, rcx, r8, r9, rax, rdx, rsi, r13, r11, r12, r10, r15, r14,
           rbx;
    XALIGNED(32) WC_X64I_SLOT stk[12];
    unsigned char cf;

    rdi = (word64)(size_t)ctx;

    rsp = (word64)(size_t)stk + 96;
    rsp = (word64)(rsp - 96);
    rcx = (word64)(WC_L64(rdi, 0));
    r8 = (word64)(WC_L64(rdi, 8));
    r9 = (word64)(0);
    /* Convert to 44 bits in 64 */
    rax = (word64)(rcx);
    rax = (word64)(rax << 20);
    rax = (word64)(rax >> 20);
    rdx = (word64)(rcx);
    rdx = (word64)((rdx >> 44) | (r8 << 20));
    rdx = (word64)(rdx << 20);
    rdx = (word64)(rdx >> 20);
    rsi = (word64)(r8);
    rsi = (word64)((rsi >> 24) | (r9 << 40));
    WC_S64(rdi, 224) = (word64)(rax);
    WC_S64(rdi, 232) = (word64)(rdx);
    WC_S64(rdi, 240) = (word64)(rsi);
    WC_S64(rsp, 0) = (word64)(rcx);
    WC_S64(rsp, 8) = (word64)(r8);
    WC_S64(rsp, 16) = (word64)(r9);
    /* Square 128-bit */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    r13 = (word64)(0);
    r11 = (word64)(rax);
    r12 = (word64)(rdx);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r10 = (word64)(rax);
    r15 = (word64)(rdx);
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r11, r15, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    /* Reduce 256-bit to 130-bit */
    rax = (word64)(r12);
    rdx = (word64)(r13);
    rax = (word64)(rax & -4);
    r12 = (word64)(r12 & 3);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)(rdx >> 2);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    rax = (word64)(r12);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    r12 = (word64)(r12 & 3);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /* Convert to 44 bits in 64 */
    rax = (word64)(r10);
    rax = (word64)(rax << 20);
    rax = (word64)(rax >> 20);
    rdx = (word64)(r10);
    rdx = (word64)((rdx >> 44) | (r11 << 20));
    rdx = (word64)(rdx << 20);
    rdx = (word64)(rdx >> 20);
    rsi = (word64)(r11);
    rsi = (word64)((rsi >> 24) | (r12 << 40));
    WC_S64(rdi, 256) = (word64)(rax);
    WC_S64(rdi, 264) = (word64)(rdx);
    WC_S64(rdi, 272) = (word64)(rsi);
    WC_S64(rsp, 24) = (word64)(r10);
    WC_S64(rsp, 32) = (word64)(r11);
    WC_S64(rsp, 40) = (word64)(r12);
    /* Multiply 128-bit by 130-bit */
    /*   r1[0] * r2[0] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    r13 = (word64)(rax);
    r14 = (word64)(rdx);
    /*   r1[0] * r2[1] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    /*   r1[1] * r2[0] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    rsi = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, 0, (unsigned long long*)&rsi);
    /*   r1[0] * r2[2] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    /*   r1[1] * r2[1] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*   r1[1] * r2[2] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    /* Reduce 260-bit to 130-bit */
    rax = (word64)(r15);
    rdx = (word64)(rsi);
    rbx = (word64)(rbx);
    rax = (word64)(rax & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rbx, (unsigned long long*)&r15);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)((rdx >> 2) | (rbx << 62));
    rbx = (word64)(rbx >> 2);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rbx, (unsigned long long*)&r15);
    rax = (word64)(r15);
    r15 = (word64)(r15 & 3);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /* Convert to 44 bits in 64 */
    rax = (word64)(r13);
    rax = (word64)(rax << 20);
    rax = (word64)(rax >> 20);
    rdx = (word64)(r13);
    rdx = (word64)((rdx >> 44) | (r14 << 20));
    rdx = (word64)(rdx << 20);
    rdx = (word64)(rdx >> 20);
    rsi = (word64)(r14);
    rsi = (word64)((rsi >> 24) | (r15 << 40));
    WC_S64(rdi, 288) = (word64)(rax);
    WC_S64(rdi, 296) = (word64)(rdx);
    WC_S64(rdi, 304) = (word64)(rsi);
    WC_S64(rsp, 48) = (word64)(r13);
    WC_S64(rsp, 56) = (word64)(r14);
    WC_S64(rsp, 64) = (word64)(r15);
    /* Square 130-bit */
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    r13 = (word64)(0);
    r8 = (word64)(rax);
    r9 = (word64)(rdx);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rdx, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    rax = (word64)(r10);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    rcx = (word64)(rax);
    r15 = (word64)(rdx);
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r8, r15, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r14 = (word64)(rax);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /* Reduce 260-bit to 130-bit */
    rax = (word64)(r9);
    rdx = (word64)(r13);
    r15 = (word64)(r14);
    rax = (word64)(rax & -4);
    r9 = (word64)(r9 & 3);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, rdx, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r15, (unsigned long long*)&r9);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)((rdx >> 2) | (r15 << 62));
    r15 = (word64)(r15 >> 2);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, rdx, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, r15, (unsigned long long*)&r9);
    rax = (word64)(r9);
    r9 = (word64)(r9 & 3);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    cf = _addcarry_u64(0, rcx, rax, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, r8, 0, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    /* Convert to 44 bits in 64 */
    rax = (word64)(rcx);
    rax = (word64)(rax << 20);
    rax = (word64)(rax >> 20);
    rdx = (word64)(rcx);
    rdx = (word64)((rdx >> 44) | (r8 << 20));
    rdx = (word64)(rdx << 20);
    rdx = (word64)(rdx >> 20);
    rsi = (word64)(r8);
    rsi = (word64)((rsi >> 24) | (r9 << 40));
    WC_S64(rdi, 320) = (word64)(rax);
    WC_S64(rdi, 328) = (word64)(rdx);
    WC_S64(rdi, 336) = (word64)(rsi);
    WC_S64(rsp, 72) = (word64)(rcx);
    WC_S64(rsp, 80) = (word64)(r8);
    WC_S64(rsp, 88) = (word64)(r9);
    r10 = (word64)(WC_L64(rsp, 0));
    r11 = (word64)(WC_L64(rsp, 8));
    r12 = (word64)(WC_L64(rsp, 16));
    /* Multiply 128-bit by 130-bit */
    /*   r1[0] * r2[0] */
    rax = (word64)(r10);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    r13 = (word64)(rax);
    r14 = (word64)(rdx);
    /*   r1[0] * r2[1] */
    rax = (word64)(r10);
    WC_X64I_MUL128(rax, rdx, rax, r8);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    /*   r1[1] * r2[0] */
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    rsi = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, 0, (unsigned long long*)&rsi);
    /*   r1[0] * r2[2] */
    rax = (word64)(r10);
    WC_X64I_MUL128(rax, rdx, rax, r9);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    /*   r1[1] * r2[1] */
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, r8);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*   r1[1] * r2[2] */
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, r9);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    /* Reduce 260-bit to 130-bit */
    rax = (word64)(r15);
    rdx = (word64)(rsi);
    rbx = (word64)(rbx);
    rax = (word64)(rax & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rbx, (unsigned long long*)&r15);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)((rdx >> 2) | (rbx << 62));
    rbx = (word64)(rbx >> 2);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rbx, (unsigned long long*)&r15);
    rax = (word64)(r15);
    r15 = (word64)(r15 & 3);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /* Convert to 44 bits in 64 */
    rax = (word64)(r13);
    rax = (word64)(rax << 20);
    rax = (word64)(rax >> 20);
    rdx = (word64)(r13);
    rdx = (word64)((rdx >> 44) | (r14 << 20));
    rdx = (word64)(rdx << 20);
    rdx = (word64)(rdx >> 20);
    rsi = (word64)(r14);
    rsi = (word64)((rsi >> 24) | (r15 << 40));
    WC_S64(rdi, 624) = (word64)(rax);
    WC_S64(rdi, 632) = (word64)(rdx);
    WC_S64(rdi, 640) = (word64)(rsi);
    /* Square 130-bit */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    r13 = (word64)(0);
    r11 = (word64)(rax);
    r12 = (word64)(rdx);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r10 = (word64)(rax);
    r15 = (word64)(rdx);
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r11, r15, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    rax = (word64)(r9);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r14 = (word64)(rax);
    rax = (word64)(r9);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    rax = (word64)(r9);
    WC_X64I_MUL128(rax, rdx, rax, r8);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /* Reduce 260-bit to 130-bit */
    rax = (word64)(r12);
    rdx = (word64)(r13);
    r15 = (word64)(r14);
    rax = (word64)(rax & -4);
    r12 = (word64)(r12 & 3);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)((rdx >> 2) | (r15 << 62));
    r15 = (word64)(r15 >> 2);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    rax = (word64)(r12);
    r12 = (word64)(r12 & 3);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /* Convert to 44 bits in 64 */
    rax = (word64)(r10);
    rax = (word64)(rax << 20);
    rax = (word64)(rax >> 20);
    rdx = (word64)(r10);
    rdx = (word64)((rdx >> 44) | (r11 << 20));
    rdx = (word64)(rdx << 20);
    rdx = (word64)(rdx >> 20);
    rsi = (word64)(r11);
    rsi = (word64)((rsi >> 24) | (r12 << 40));
    WC_S64(rdi, 720) = (word64)(rax);
    WC_S64(rdi, 728) = (word64)(rdx);
    WC_S64(rdi, 736) = (word64)(rsi);
    rcx = (word64)(WC_L64(rsp, 48));
    r8 = (word64)(WC_L64(rsp, 56));
    r9 = (word64)(WC_L64(rsp, 64));
    /* Square 130-bit */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    r13 = (word64)(0);
    r11 = (word64)(rax);
    r12 = (word64)(rdx);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r10 = (word64)(rax);
    r15 = (word64)(rdx);
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r11, r15, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    rax = (word64)(r9);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r14 = (word64)(rax);
    rax = (word64)(r9);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    rax = (word64)(r9);
    WC_X64I_MUL128(rax, rdx, rax, r8);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /* Reduce 260-bit to 130-bit */
    rax = (word64)(r12);
    rdx = (word64)(r13);
    r15 = (word64)(r14);
    rax = (word64)(rax & -4);
    r12 = (word64)(r12 & 3);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)((rdx >> 2) | (r15 << 62));
    r15 = (word64)(r15 >> 2);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    rax = (word64)(r12);
    r12 = (word64)(r12 & 3);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    /* Convert to 44 bits in 64 */
    rax = (word64)(r10);
    rax = (word64)(rax << 20);
    rax = (word64)(rax >> 20);
    rdx = (word64)(r10);
    rdx = (word64)((rdx >> 44) | (r11 << 20));
    rdx = (word64)(rdx << 20);
    rdx = (word64)(rdx >> 20);
    rsi = (word64)(r11);
    rsi = (word64)((rsi >> 24) | (r12 << 40));
    WC_S64(rdi, 656) = (word64)(rax);
    WC_S64(rdi, 664) = (word64)(rdx);
    WC_S64(rdi, 672) = (word64)(rsi);
    rcx = (word64)(WC_L64(rsp, 0));
    r8 = (word64)(WC_L64(rsp, 8));
    r9 = (word64)(WC_L64(rsp, 16));
    /* Multiply 128-bit by 130-bit */
    /*   r1[0] * r2[0] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    r13 = (word64)(rax);
    r14 = (word64)(rdx);
    /*   r1[0] * r2[1] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    /*   r1[1] * r2[0] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    rsi = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, 0, (unsigned long long*)&rsi);
    /*   r1[0] * r2[2] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    /*   r1[1] * r2[1] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*   r1[1] * r2[2] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    /* Reduce 260-bit to 130-bit */
    rax = (word64)(r15);
    rdx = (word64)(rsi);
    rbx = (word64)(rbx);
    rax = (word64)(rax & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rbx, (unsigned long long*)&r15);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)((rdx >> 2) | (rbx << 62));
    rbx = (word64)(rbx >> 2);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rbx, (unsigned long long*)&r15);
    rax = (word64)(r15);
    r15 = (word64)(r15 & 3);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    /* Convert to 44 bits in 64 */
    rax = (word64)(r13);
    rax = (word64)(rax << 20);
    rax = (word64)(rax >> 20);
    rdx = (word64)(r13);
    rdx = (word64)((rdx >> 44) | (r14 << 20));
    rdx = (word64)(rdx << 20);
    rdx = (word64)(rdx >> 20);
    rsi = (word64)(r14);
    rsi = (word64)((rsi >> 24) | (r15 << 40));
    WC_S64(rdi, 688) = (word64)(rax);
    WC_S64(rdi, 696) = (word64)(rdx);
    WC_S64(rdi, 704) = (word64)(rsi);
}

WC_X64I_TARGET("avx512f")
WOLFSSL_LOCAL void poly1305_setkey_avx512ifma(Poly1305* ctx, const byte* key)
{
    word64 rdi, rsi;
    __m512i z0;

    rdi = (word64)(size_t)ctx;
    rsi = (word64)(size_t)key;

    (void)poly1305_setkey_avx((Poly1305*)(size_t)rdi, (const byte*)(size_t)rsi);
    z0 = _mm512_setzero_si512();
    _mm512_storeu_si512((void*)WC_PW(rdi, 752), z0);
    _mm512_storeu_si512((void*)WC_PW(rdi, 816), z0);
    _mm512_storeu_si512((void*)WC_PW(rdi, 880), z0);
    WC_S64(rdi, 608) = (word64)(0);
    WC_S16(rdi, 616) = (word16)(0);
}

XALIGNED(32) static const word64 L_poly1305_avx512ifma_blocks_mask44[]
    WC_X64I_UNUSED = {
    0x00000fffffffffffULL, 0x00000fffffffffffULL,
    0x00000fffffffffffULL, 0x00000fffffffffffULL,
    0x00000fffffffffffULL, 0x00000fffffffffffULL,
    0x00000fffffffffffULL, 0x00000fffffffffffULL,
};

XALIGNED(32) static const word64 L_poly1305_avx512ifma_blocks_mask24[]
    WC_X64I_UNUSED = {
    0x0000000000ffffffULL, 0x0000000000ffffffULL,
    0x0000000000ffffffULL, 0x0000000000ffffffULL,
    0x0000000000ffffffULL, 0x0000000000ffffffULL,
    0x0000000000ffffffULL, 0x0000000000ffffffULL,
};

XALIGNED(32) static const word64 L_poly1305_avx512ifma_blocks_pad[]
    WC_X64I_UNUSED = {
    0x0000010000000000ULL, 0x0000010000000000ULL,
    0x0000010000000000ULL, 0x0000010000000000ULL,
    0x0000010000000000ULL, 0x0000010000000000ULL,
    0x0000010000000000ULL, 0x0000010000000000ULL,
};

XALIGNED(32) static const word64 L_poly1305_avx512ifma_blocks_idxeven[]
    WC_X64I_UNUSED = {
    0x0000000000000000ULL, 0x0000000000000002ULL,
    0x0000000000000004ULL, 0x0000000000000006ULL,
    0x0000000000000008ULL, 0x000000000000000aULL,
    0x000000000000000cULL, 0x000000000000000eULL,
};

XALIGNED(32) static const word64 L_poly1305_avx512ifma_blocks_idxodd[]
    WC_X64I_UNUSED = {
    0x0000000000000001ULL, 0x0000000000000003ULL,
    0x0000000000000005ULL, 0x0000000000000007ULL,
    0x0000000000000009ULL, 0x000000000000000bULL,
    0x000000000000000dULL, 0x000000000000000fULL,
};

XALIGNED(32) static const word64 L_poly1305_avx512ifma_blocks_rxidx[]
    WC_X64I_UNUSED = {
    0x000000000000000cULL, 0x0000000000000008ULL,
    0x0000000000000004ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x000000000000000dULL, 0x0000000000000009ULL,
    0x0000000000000005ULL, 0x0000000000000001ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x000000000000000eULL, 0x000000000000000aULL,
    0x0000000000000006ULL, 0x0000000000000002ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000000ULL, 0x0000000000000000ULL,
};

WC_X64I_TARGET("avx512f,avx512bw,avx512ifma")
WOLFSSL_LOCAL void poly1305_blocks_avx512ifma(Poly1305* ctx,
    const unsigned char* m, size_t bytes)
{
    word64 rdi, rsi, rdx, r8, r9, r10, r11, r12, r13, rax = 0, rcx = 0,
           r14 = 0;
    __m512i z0 = _mm512_setzero_si512(), z1 = _mm512_setzero_si512(),
            z2 = _mm512_setzero_si512(), z3 = _mm512_setzero_si512(),
            z4 = _mm512_setzero_si512(), z5 = _mm512_setzero_si512(),
            z6 = _mm512_setzero_si512(), z7 = _mm512_setzero_si512(),
            z8 = _mm512_setzero_si512(), z9 = _mm512_setzero_si512(),
            z10 = _mm512_setzero_si512(), z11 = _mm512_setzero_si512(),
            z12 = _mm512_setzero_si512(), z13 = _mm512_setzero_si512(),
            z14 = _mm512_setzero_si512(), z15 = _mm512_setzero_si512(),
            z16 = _mm512_setzero_si512(), z17 = _mm512_setzero_si512(), z18;
    unsigned char cf;

    rdi = (word64)(size_t)ctx;
    rsi = (word64)(size_t)m;
    rdx = (word64)(word64)bytes;

    r8 = (word64)((word64)(size_t)L_poly1305_avx512ifma_blocks_mask44);
    r9 = (word64)((word64)(size_t)L_poly1305_avx512ifma_blocks_mask24);
    r10 = (word64)((word64)(size_t)L_poly1305_avx512ifma_blocks_pad);
    r11 = (word64)((word64)(size_t)L_poly1305_avx512ifma_blocks_idxeven);
    r12 = (word64)((word64)(size_t)L_poly1305_avx512ifma_blocks_idxodd);
    r13 = (word64)((word64)(size_t)L_poly1305_avx512ifma_blocks_rxidx);
    z18 = _mm512_loadu_si512((const void*)WC_PR(r8, 0));
    if ((WC_L16(rdi, 616)) != (0)) {
        goto L_poly1305_avx512ifma_blocks_begin_h;
    }
    /* First 8 blocks initialise the lanes directly. */
    z14 = _mm512_loadu_si512((const void*)WC_PR(rsi, 0));
    z15 = _mm512_loadu_si512((const void*)WC_PR(rsi, 64));
    z16 = _mm512_loadu_si512((const void*)WC_PR(r11, 0));
    z16 = _mm512_permutex2var_epi64(z14, z16, z15);
    z17 = _mm512_loadu_si512((const void*)WC_PR(r12, 0));
    z17 = _mm512_permutex2var_epi64(z14, z17, z15);
    z0 = _mm512_and_si512(z16, _mm512_loadu_si512((const void*)WC_PR(r8, 0)));
    z14 = _mm512_srli_epi64(z16, 44);
    z15 = _mm512_and_si512(z17, _mm512_loadu_si512((const void*)WC_PR(r9, 0)));
    z15 = _mm512_slli_epi64(z15, 20);
    z1 = _mm512_or_si512(z15, z14);
    z2 = _mm512_srli_epi64(z17, 24);
    z2 = _mm512_or_si512(z2, _mm512_loadu_si512((const void*)WC_PR(r10, 0)));
    rsi = (word64)(rsi + 0x80);
    rdx = (word64)(rdx - 0x80);
    if ((rdx) == (0)) {
        goto L_poly1305_avx512ifma_blocks_store;
    }
    goto L_poly1305_avx512ifma_blocks_load_r8;
L_poly1305_avx512ifma_blocks_begin_h:
    z0 = _mm512_loadu_si512((const void*)WC_PR(rdi, 752));
    z1 = _mm512_loadu_si512((const void*)WC_PR(rdi, 816));
    z2 = _mm512_loadu_si512((const void*)WC_PR(rdi, 880));
    if ((WC_L8(rdi, 616)) == (0)) {
        goto L_poly1305_avx512ifma_blocks_load_r8;
    }
    /* Finished: load the 8 distinct powers r^8..r^1. */
    z8 = _mm512_loadu_si512((const void*)WC_PR(rdi, 224));
    z9 = _mm512_loadu_si512((const void*)WC_PR(rdi, 288));
    z10 = _mm512_loadu_si512((const void*)WC_PR(rdi, 624));
    z11 = _mm512_loadu_si512((const void*)WC_PR(rdi, 688));
    z12 = _mm512_loadu_si512((const void*)WC_PR(r13, 0));
    z12 = _mm512_permutex2var_epi64(z10, z12, z11);
    z13 = _mm512_loadu_si512((const void*)WC_PR(r13, 0));
    z13 = _mm512_permutex2var_epi64(z8, z13, z9);
    z3 = _mm512_inserti64x4(z12, _mm512_castsi512_si256(z13), 1);
    z12 = _mm512_loadu_si512((const void*)WC_PR(r13, 64));
    z12 = _mm512_permutex2var_epi64(z10, z12, z11);
    z13 = _mm512_loadu_si512((const void*)WC_PR(r13, 64));
    z13 = _mm512_permutex2var_epi64(z8, z13, z9);
    z4 = _mm512_inserti64x4(z12, _mm512_castsi512_si256(z13), 1);
    z12 = _mm512_loadu_si512((const void*)WC_PR(r13, 128));
    z12 = _mm512_permutex2var_epi64(z10, z12, z11);
    z13 = _mm512_loadu_si512((const void*)WC_PR(r13, 128));
    z13 = _mm512_permutex2var_epi64(z8, z13, z9);
    z5 = _mm512_inserti64x4(z12, _mm512_castsi512_si256(z13), 1);
    goto L_poly1305_avx512ifma_blocks_do_mul;
L_poly1305_avx512ifma_blocks_load_r8:
    z3 = _mm512_set1_epi64((long long)WC_L64(rdi, 720));
    z4 = _mm512_set1_epi64((long long)WC_L64(rdi, 728));
    z5 = _mm512_set1_epi64((long long)WC_L64(rdi, 736));
L_poly1305_avx512ifma_blocks_do_mul:
    z14 = _mm512_slli_epi64(z4, 2);
    z6 = _mm512_slli_epi64(z4, 4);
    z6 = _mm512_add_epi64(z6, z14);
    z14 = _mm512_slli_epi64(z5, 2);
    z7 = _mm512_slli_epi64(z5, 4);
    z7 = _mm512_add_epi64(z7, z14);
    if ((WC_L8(rdi, 616)) != (1)) {
        goto L_poly1305_avx512ifma_blocks_start;
    }
    /* Finished: final multiply, collapse lanes, reduce to ctx->h. */
    z8 = _mm512_setzero_si512();
    z9 = _mm512_setzero_si512();
    z10 = _mm512_setzero_si512();
    z11 = _mm512_setzero_si512();
    z12 = _mm512_setzero_si512();
    z13 = _mm512_setzero_si512();
    z8 = _mm512_madd52lo_epu64(z8, z0, z3);
    z8 = _mm512_madd52lo_epu64(z8, z1, z7);
    z8 = _mm512_madd52lo_epu64(z8, z2, z6);
    z11 = _mm512_madd52hi_epu64(z11, z0, z3);
    z11 = _mm512_madd52hi_epu64(z11, z1, z7);
    z11 = _mm512_madd52hi_epu64(z11, z2, z6);
    z9 = _mm512_madd52lo_epu64(z9, z0, z4);
    z9 = _mm512_madd52lo_epu64(z9, z1, z3);
    z9 = _mm512_madd52lo_epu64(z9, z2, z7);
    z12 = _mm512_madd52hi_epu64(z12, z0, z4);
    z12 = _mm512_madd52hi_epu64(z12, z1, z3);
    z12 = _mm512_madd52hi_epu64(z12, z2, z7);
    z10 = _mm512_madd52lo_epu64(z10, z0, z5);
    z10 = _mm512_madd52lo_epu64(z10, z1, z4);
    z10 = _mm512_madd52lo_epu64(z10, z2, z3);
    z13 = _mm512_madd52hi_epu64(z13, z0, z5);
    z13 = _mm512_madd52hi_epu64(z13, z1, z4);
    z13 = _mm512_madd52hi_epu64(z13, z2, z3);
    z14 = _mm512_slli_epi64(z11, 8);
    z9 = _mm512_add_epi64(z14, z9);
    z14 = _mm512_slli_epi64(z12, 8);
    z10 = _mm512_add_epi64(z14, z10);
    z15 = _mm512_slli_epi64(z13, 8);
    z14 = _mm512_slli_epi64(z15, 2);
    z15 = _mm512_slli_epi64(z15, 4);
    z15 = _mm512_add_epi64(z15, z14);
    z8 = _mm512_add_epi64(z15, z8);
    z14 = _mm512_srli_epi64(z8, 44);
    z0 = _mm512_and_si512(z8, z18);
    z9 = _mm512_add_epi64(z14, z9);
    z14 = _mm512_srli_epi64(z9, 44);
    z1 = _mm512_and_si512(z9, z18);
    z10 = _mm512_add_epi64(z14, z10);
    z14 = _mm512_srli_epi64(z10, 44);
    z2 = _mm512_and_si512(z10, z18);
    z15 = _mm512_slli_epi64(z14, 2);
    z14 = _mm512_slli_epi64(z14, 4);
    z14 = _mm512_add_epi64(z14, z15);
    z0 = _mm512_add_epi64(z14, z0);
    z14 = _mm512_shuffle_i64x2(z0, z0, 0x4e);
    z15 = _mm512_shuffle_i64x2(z1, z1, 0x4e);
    z16 = _mm512_shuffle_i64x2(z2, z2, 0x4e);
    z0 = _mm512_add_epi64(z14, z0);
    z1 = _mm512_add_epi64(z15, z1);
    z2 = _mm512_add_epi64(z16, z2);
    z14 = _mm512_bsrli_epi128(z0, 8);
    z15 = _mm512_bsrli_epi128(z1, 8);
    z16 = _mm512_bsrli_epi128(z2, 8);
    z0 = _mm512_add_epi64(z14, z0);
    z1 = _mm512_add_epi64(z15, z1);
    z2 = _mm512_add_epi64(z16, z2);
    z14 = _mm512_permutex_epi64(z0, 2);
    z15 = _mm512_permutex_epi64(z1, 2);
    z16 = _mm512_permutex_epi64(z2, 2);
    z0 = _mm512_add_epi64(z14, z0);
    z1 = _mm512_add_epi64(z15, z1);
    z2 = _mm512_add_epi64(z16, z2);
    rax = (word64)((word64)_mm_cvtsi128_si64(_mm512_castsi512_si128(z0)));
    rcx = (word64)((word64)_mm_cvtsi128_si64(_mm512_castsi512_si128(z1)));
    rdx = (word64)((word64)_mm_cvtsi128_si64(_mm512_castsi512_si128(z2)));
    r9 = (word64)(rcx);
    r9 = (word64)(r9 >> 20);
    r10 = (word64)(rdx);
    r10 = (word64)(r10 >> 40);
    r8 = (word64)(rax);
    rax = (word64)(rcx);
    rax = (word64)(rax << 44);
    cf = _addcarry_u64(0, r8, rax, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    rax = (word64)(rdx);
    rax = (word64)(rax << 24);
    cf = _addcarry_u64(0, r9, rax, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    r14 = (word64)(r10);
    r10 = (word64)(r10 & 3);
    r14 = (word64)(r14 >> 2);
    r14 = (word64)(r14 + r14 * 4);
    cf = _addcarry_u64(0, r8, r14, (unsigned long long*)&r8);
    cf = _addcarry_u64(cf, r9, 0, (unsigned long long*)&r9);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    WC_S64(rdi, 24) = (word64)(r8);
    WC_S64(rdi, 32) = (word64)(r9);
    WC_S64(rdi, 40) = (word64)(r10);
    goto L_poly1305_avx512ifma_blocks_end_calc;
L_poly1305_avx512ifma_blocks_start:
    z14 = _mm512_loadu_si512((const void*)WC_PR(rsi, 0));
    z15 = _mm512_loadu_si512((const void*)WC_PR(rsi, 64));
    z16 = _mm512_loadu_si512((const void*)WC_PR(r11, 0));
    z16 = _mm512_permutex2var_epi64(z14, z16, z15);
    z17 = _mm512_loadu_si512((const void*)WC_PR(r12, 0));
    z17 = _mm512_permutex2var_epi64(z14, z17, z15);
    z8 = _mm512_and_si512(z16, _mm512_loadu_si512((const void*)WC_PR(r8, 0)));
    z14 = _mm512_srli_epi64(z16, 44);
    z15 = _mm512_and_si512(z17, _mm512_loadu_si512((const void*)WC_PR(r9, 0)));
    z15 = _mm512_slli_epi64(z15, 20);
    z9 = _mm512_or_si512(z15, z14);
    z10 = _mm512_srli_epi64(z17, 24);
    z10 = _mm512_or_si512(z10, _mm512_loadu_si512((const void*)WC_PR(r10, 0)));
    z11 = _mm512_setzero_si512();
    z12 = _mm512_setzero_si512();
    z13 = _mm512_setzero_si512();
    z8 = _mm512_madd52lo_epu64(z8, z0, z3);
    z8 = _mm512_madd52lo_epu64(z8, z1, z7);
    z8 = _mm512_madd52lo_epu64(z8, z2, z6);
    z11 = _mm512_madd52hi_epu64(z11, z0, z3);
    z11 = _mm512_madd52hi_epu64(z11, z1, z7);
    z11 = _mm512_madd52hi_epu64(z11, z2, z6);
    z9 = _mm512_madd52lo_epu64(z9, z0, z4);
    z9 = _mm512_madd52lo_epu64(z9, z1, z3);
    z9 = _mm512_madd52lo_epu64(z9, z2, z7);
    z12 = _mm512_madd52hi_epu64(z12, z0, z4);
    z12 = _mm512_madd52hi_epu64(z12, z1, z3);
    z12 = _mm512_madd52hi_epu64(z12, z2, z7);
    z10 = _mm512_madd52lo_epu64(z10, z0, z5);
    z10 = _mm512_madd52lo_epu64(z10, z1, z4);
    z10 = _mm512_madd52lo_epu64(z10, z2, z3);
    z13 = _mm512_madd52hi_epu64(z13, z0, z5);
    z13 = _mm512_madd52hi_epu64(z13, z1, z4);
    z13 = _mm512_madd52hi_epu64(z13, z2, z3);
    z14 = _mm512_slli_epi64(z11, 8);
    z9 = _mm512_add_epi64(z14, z9);
    z14 = _mm512_slli_epi64(z12, 8);
    z10 = _mm512_add_epi64(z14, z10);
    z15 = _mm512_slli_epi64(z13, 8);
    z14 = _mm512_slli_epi64(z15, 2);
    z15 = _mm512_slli_epi64(z15, 4);
    z15 = _mm512_add_epi64(z15, z14);
    z8 = _mm512_add_epi64(z15, z8);
    z14 = _mm512_srli_epi64(z8, 44);
    z0 = _mm512_and_si512(z8, z18);
    z9 = _mm512_add_epi64(z14, z9);
    z14 = _mm512_srli_epi64(z9, 44);
    z1 = _mm512_and_si512(z9, z18);
    z10 = _mm512_add_epi64(z14, z10);
    z14 = _mm512_srli_epi64(z10, 44);
    z2 = _mm512_and_si512(z10, z18);
    z15 = _mm512_slli_epi64(z14, 2);
    z14 = _mm512_slli_epi64(z14, 4);
    z14 = _mm512_add_epi64(z14, z15);
    z0 = _mm512_add_epi64(z14, z0);
    rsi = (word64)(rsi + 0x80);
    rdx = (word64)(rdx - 0x80);
    if ((rdx) != (0)) {
        goto L_poly1305_avx512ifma_blocks_start;
    }
L_poly1305_avx512ifma_blocks_store:
    _mm512_storeu_si512((void*)WC_PW(rdi, 752), z0);
    _mm512_storeu_si512((void*)WC_PW(rdi, 816), z1);
    _mm512_storeu_si512((void*)WC_PW(rdi, 880), z2);
L_poly1305_avx512ifma_blocks_end_calc:
    WC_S8(rdi, 617) = (byte)(1);
}

WC_X64I_TARGET("avx512f")
WOLFSSL_LOCAL void poly1305_final_avx512ifma(Poly1305* ctx, byte* mac)
{
    word64 rdi, rsi, rcx = 0, rsp, rdx = 0, rax = 0, r8 = 0;
    __m512i z0 = _mm512_setzero_si512();
    XALIGNED(32) WC_X64I_SLOT stk[4];

    rdi = (word64)(size_t)ctx;
    rsi = (word64)(size_t)mac;

    rsp = (word64)(size_t)stk + 32;
    WC_S8(rdi, 616) = (byte)(1);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, 617)) & 0xff);
    if (((byte)rcx) == (0)) {
        goto L_poly1305_avx512ifma_final_done_blocks_8;
    }
    rsp = (word64)(rsp - 8);
    WC_S64(rsp, 0) = rsi;
    rdx = (word64)(0x80);
    rsi = (word64)(0);
    (void)poly1305_blocks_avx512ifma((Poly1305*)(size_t)rdi, (
        const unsigned char*)(size_t)rsi, (size_t)rdx);
    rsi = WC_L64(rsp, 0);
    rsp = (word64)(rsp + 8);
L_poly1305_avx512ifma_final_done_blocks_8:
    rax = (word64)(WC_L64(rdi, 608));
    rcx = (word64)(rax);
    rcx = (word64)(rcx & -16);
    if (((byte)rcx) == (0)) {
        goto L_poly1305_avx512ifma_final_done_blocks;
    }
    rsp = (word64)(rsp - 8);
    WC_S64(rsp, 0) = rcx;
    rsp = (word64)(rsp - 8);
    WC_S64(rsp, 0) = rax;
    rsp = (word64)(rsp - 8);
    WC_S64(rsp, 0) = rsi;
    rdx = (word64)(rcx);
    rsi = (word64)(rdi + 480);
    (void)poly1305_blocks_avx((Poly1305*)(size_t)rdi, (const unsigned char*)(
        size_t)rsi, (size_t)rdx);
    rsi = WC_L64(rsp, 0);
    rsp = (word64)(rsp + 8);
    rax = WC_L64(rsp, 0);
    rsp = (word64)(rsp + 8);
    rcx = WC_L64(rsp, 0);
    rsp = (word64)(rsp + 8);
L_poly1305_avx512ifma_final_done_blocks:
    WC_S64(rdi, 608) = (word64)(WC_L64(rdi, 608) - rcx);
    rdx = (word64)(0);
    goto L_poly1305_avx512ifma_final_cmp_copy;
L_poly1305_avx512ifma_final_start_copy:
    r8 = (r8 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, rcx + 480)) & 0xff);
    WC_S8(rdi, rdx + 480) = (byte)((byte)r8);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)((byte)rcx + 1) & 0xff);
    rdx = (rdx & ~(word64)0xff) | ((word64)(byte)((byte)rdx + 1) & 0xff);
L_poly1305_avx512ifma_final_cmp_copy:
    if (((byte)rax) != ((byte)rcx)) {
        goto L_poly1305_avx512ifma_final_start_copy;
    }
    (void)poly1305_final_avx((Poly1305*)(size_t)rdi, (byte*)(size_t)rsi);
    z0 = _mm512_setzero_si512();
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 224), _mm512_castsi512_si256(z0));
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 256), _mm512_castsi512_si256(z0));
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 288), _mm512_castsi512_si256(z0));
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 320), _mm512_castsi512_si256(z0));
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 624), _mm512_castsi512_si256(z0));
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 656), _mm512_castsi512_si256(z0));
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 688), _mm512_castsi512_si256(z0));
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 720), _mm512_castsi512_si256(z0));
    _mm512_storeu_si512((void*)WC_PW(rdi, 752), z0);
    _mm512_storeu_si512((void*)WC_PW(rdi, 816), z0);
    _mm512_storeu_si512((void*)WC_PW(rdi, 880), z0);
    WC_S64(rdi, 608) = (word64)(0);
    WC_S16(rdi, 616) = (word16)(0);
}

WOLFSSL_LOCAL void poly1305_fold_avx512ifma(Poly1305* ctx, word32 nBlocks)
{
    word64 rdi, rsp, rsi, rcx, r8, r9, rax, rdx = 0, r13 = 0, r11 = 0,
           r12 = 0, r10 = 0, r15 = 0, r14 = 0, rbx = 0, rbp = 0;
    XALIGNED(32) WC_X64I_SLOT stk[8];
    unsigned char cf;

    rdi = (word64)(size_t)ctx;

    rsp = (word64)(size_t)stk + 64;
    rsi = (word64)(word32)nBlocks;
    rsp = (word64)(rsp - 64);
    WC_S32(rsp, 24) = (word32)((word32)rsi);
    rcx = (word64)(WC_L64(rdi, 0));
    r8 = (word64)(WC_L64(rdi, 8));
    r9 = (word64)(0);
    WC_S64(rsp, 0) = (word64)(rcx);
    WC_S64(rsp, 8) = (word64)(r8);
    WC_S64(rsp, 16) = (word64)(r9);
    rax = (word64)(WC_X64I_BSR64(rsi));
    /* BSR: source is non-zero at this point; a zero source would
       leave the destination unchanged rather than land here. */
    WC_S64(rsp, 32) = (word64)(rax);
L_poly1305_fold_loop:
    rax = (word64)(WC_L64(rsp, 32));
    if (((rax & rax)) == (0)) {
        goto L_poly1305_fold_done;
    }
    rax = (word64)(rax - 1);
    WC_S64(rsp, 32) = (word64)(rax);
    rcx = (word64)(WC_L64(rsp, 0));
    r8 = (word64)(WC_L64(rsp, 8));
    r9 = (word64)(WC_L64(rsp, 16));
    /* Square 130-bit */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    r13 = (word64)(0);
    r11 = (word64)(rax);
    r12 = (word64)(rdx);
    cf = _addcarry_u64(0, r11, rax, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rdx, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, 0, (unsigned long long*)&r13);
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r10 = (word64)(rax);
    r15 = (word64)(rdx);
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    cf = _addcarry_u64(0, r11, r15, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    rax = (word64)(r9);
    WC_X64I_MUL128(rax, rdx, rax, rax);
    r14 = (word64)(rax);
    rax = (word64)(r9);
    WC_X64I_MUL128(rax, rdx, rax, rcx);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r12, rax, (unsigned long long*)&r12);
    cf = _addcarry_u64(cf, r13, rdx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    rax = (word64)(r9);
    WC_X64I_MUL128(rax, rdx, rax, r8);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    /* Reduce 260-bit to 130-bit */
    rax = (word64)(r12);
    rdx = (word64)(r13);
    r15 = (word64)(r14);
    rax = (word64)(rax & -4);
    r12 = (word64)(r12 & 3);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)((rdx >> 2) | (r15 << 62));
    r15 = (word64)(r15 >> 2);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, rdx, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, r15, (unsigned long long*)&r12);
    rax = (word64)(r12);
    r12 = (word64)(r12 & 3);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    cf = _addcarry_u64(0, r10, rax, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    cf = _addcarry_u64(cf, r12, 0, (unsigned long long*)&r12);
    WC_S64(rsp, 0) = (word64)(r10);
    WC_S64(rsp, 8) = (word64)(r11);
    WC_S64(rsp, 16) = (word64)(r12);
    rax = (word32)(WC_L32(rsp, 24));
    rdx = (word64)(WC_L64(rsp, 32));
    if (((unsigned char)((rax >> (rdx & 63)) & 1)) == 0) {
        goto L_poly1305_fold_skip;
    }
    rcx = (word64)(WC_L64(rdi, 0));
    r8 = (word64)(WC_L64(rdi, 8));
    r9 = (word64)(0);
    r10 = (word64)(WC_L64(rsp, 0));
    r11 = (word64)(WC_L64(rsp, 8));
    r12 = (word64)(WC_L64(rsp, 16));
    /* Multiply 128-bit by 130-bit */
    /*   r1[0] * r2[0] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    r13 = (word64)(rax);
    r14 = (word64)(rdx);
    /*   r1[0] * r2[1] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    r15 = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    /*   r1[1] * r2[0] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    rsi = (word64)(0);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, 0, (unsigned long long*)&rsi);
    /*   r1[0] * r2[2] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    /*   r1[1] * r2[1] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    rbx = (word64)(0);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*   r1[1] * r2[2] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    /* Reduce 260-bit to 130-bit */
    rax = (word64)(r15);
    rdx = (word64)(rsi);
    rbx = (word64)(rbx);
    rax = (word64)(rax & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rbx, (unsigned long long*)&r15);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)((rdx >> 2) | (rbx << 62));
    rbx = (word64)(rbx >> 2);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rbx, (unsigned long long*)&r15);
    rax = (word64)(r15);
    r15 = (word64)(r15 & 3);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    WC_S64(rsp, 0) = (word64)(r13);
    WC_S64(rsp, 8) = (word64)(r14);
    WC_S64(rsp, 16) = (word64)(r15);
L_poly1305_fold_skip:
    goto L_poly1305_fold_loop;
L_poly1305_fold_done:
    rcx = (word64)(WC_L64(rdi, 64));
    r8 = (word64)(WC_L64(rdi, 72));
    r9 = (word64)(WC_L64(rdi, 80));
    r10 = (word64)(WC_L64(rsp, 0));
    r11 = (word64)(WC_L64(rsp, 8));
    r12 = (word64)(WC_L64(rsp, 16));
    /* Multiply 130-bit by 130-bit */
    r13 = (word64)(0);
    r14 = (word64)(0);
    r15 = (word64)(0);
    rsi = (word64)(0);
    rbx = (word64)(0);
    /*   r1[0] * r2[0] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, 0, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*   r1[0] * r2[1] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, 0, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*   r1[0] * r2[2] */
    rax = (word64)(rcx);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*   r1[1] * r2[0] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    cf = _addcarry_u64(0, r14, rax, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rdx, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, 0, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*   r1[1] * r2[1] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*   r1[1] * r2[2] */
    rax = (word64)(r8);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    /*   r1[2] * r2[0] */
    rax = (word64)(r9);
    WC_X64I_MUL128(rax, rdx, rax, r10);
    cf = _addcarry_u64(0, r15, rax, (unsigned long long*)&r15);
    cf = _addcarry_u64(cf, rsi, rdx, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, 0, (unsigned long long*)&rbx);
    /*   r1[2] * r2[1] */
    rax = (word64)(r9);
    WC_X64I_MUL128(rax, rdx, rax, r11);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rbx, rdx, (unsigned long long*)&rbx);
    /*   r1[2] * r2[2] */
    rax = (word64)(r9);
    WC_X64I_MUL128(rax, rdx, rax, r12);
    rbx = (word64)(rbx + rax);
    /* Reduce 260-bit to 130-bit */
    rax = (word64)(r15);
    rdx = (word64)(rsi);
    rbp = (word64)(rbx);
    rax = (word64)(rax & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rbp, (unsigned long long*)&r15);
    rax = (word64)((rax >> 2) | (rdx << 62));
    rdx = (word64)((rdx >> 2) | (rbp << 62));
    rbp = (word64)(rbp >> 2);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rdx, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, rbp, (unsigned long long*)&r15);
    rax = (word64)(r15);
    r15 = (word64)(r15 & 3);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    rax = (word64)(WC_L64(rdi, 24));
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    rax = (word64)(WC_L64(rdi, 32));
    cf = _addcarry_u64(cf, r14, rax, (unsigned long long*)&r14);
    rax = (word64)(WC_L64(rdi, 40));
    cf = _addcarry_u64(cf, r15, rax, (unsigned long long*)&r15);
    rax = (word64)(r15);
    r15 = (word64)(r15 & 3);
    rax = (word64)(rax >> 2);
    rax = (word64)(rax + rax * 4);
    cf = _addcarry_u64(0, r13, rax, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    WC_S64(rdi, 24) = (word64)(r13);
    WC_S64(rdi, 32) = (word64)(r14);
    WC_S64(rdi, 40) = (word64)(r15);
}

#endif /* HAVE_INTEL_AVX512 */
#endif /* WOLFSSL_X86_64_BUILD */

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
