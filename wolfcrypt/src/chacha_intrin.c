/* chacha_intrin.c */
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

#define _WC_BUILDING_CHACHA_INTRIN_C

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef WOLFSSL_X86_64_BUILD

#ifdef _MSC_VER
    /* _umul128, __popcnt and _BitScanReverse64 live here. */
    #include <intrin.h>
#endif
#include <immintrin.h>
#include <wolfssl/wolfcrypt/chacha.h>
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
extern WOLFSSL_LOCAL void chacha_encrypt_x64(ChaCha* ctx, const byte* m,
    byte* c, word32 bytes);
#ifdef HAVE_INTEL_SSSE3
extern WOLFSSL_LOCAL void chacha_encrypt_sse3(ChaCha* ctx, const byte* m,
    byte* c, word32 bytes);
#endif
#ifdef HAVE_INTEL_AVX1
extern WOLFSSL_LOCAL void chacha_encrypt_avx1(ChaCha* ctx, const byte* m,
    byte* c, word32 bytes);
#endif
#ifdef HAVE_INTEL_AVX2
extern WOLFSSL_LOCAL void chacha_encrypt_avx2(ChaCha* ctx, const byte* m,
    byte* c, word32 bytes);
#endif
#ifdef HAVE_INTEL_AVX512
extern WOLFSSL_LOCAL void chacha_encrypt_avx512vl(ChaCha* ctx, const byte* m,
    byte* c, word32 bytes);
extern WOLFSSL_LOCAL void chacha_encrypt_avx512(ChaCha* ctx, const byte* m,
    byte* c, word32 bytes);
extern WOLFSSL_LOCAL void chacha20_poly1305_avx512(ChaCha* chacha,
    Poly1305* poly, const byte* m, byte* c, word32 bytes);
extern WOLFSSL_LOCAL void chacha20_poly1305_ifma(ChaCha* chacha, Poly1305* poly,
    const byte* m, byte* c, word32 bytes);
extern WOLFSSL_LOCAL void chacha20_poly1305_ifma_decrypt(ChaCha* chacha,
    Poly1305* poly, const byte* m, byte* c, word32 bytes);
#endif
#ifdef HAVE_INTEL_AVX2
extern WOLFSSL_LOCAL void chacha20_poly1305_small_enc(ChaCha* chacha,
    Poly1305* poly, const byte* m, byte* c, word32 mLen, const byte* aad,
    word32 aadLen, byte* tag);
extern WOLFSSL_LOCAL int chacha20_poly1305_small_dec(ChaCha* chacha,
    Poly1305* poly, const byte* in, byte* out, word32 ctLen, const byte* aad,
    word32 aadLen, const byte* tag);

#endif
#endif
#ifdef WOLFSSL_X86_64_BUILD
WOLFSSL_LOCAL void chacha_encrypt_x64(ChaCha* ctx, const byte* m, byte* c,
    word32 bytes)
{
    word64 rdi, rsi, rdx, rcx, rsp, rax = 0, rbx = 0, r8 = 0, r9 = 0, r10 = 0,
           r11 = 0, r12 = 0, r13 = 0, r14 = 0, r15 = 0, rbp = 0;
    XALIGNED(32) WC_X64I_SLOT stk[16];
    word32 zf1;
    word32 zf2;

    rdi = (word64)(size_t)ctx;
    rsi = (word64)(size_t)m;
    rdx = (word64)(size_t)c;
    rcx = (word64)(word32)bytes;

    rsp = (word64)(size_t)stk + 128;
    rsp = (word64)(rsp - 64);
    if (((word32)rcx) < (0x40)) {
        goto L_chacha_x64_small;
    }
L_chacha_x64_start:
    rsp = (word64)(rsp - 48);
    WC_S64(rsp, 24) = (word64)(rdx);
    WC_S64(rsp, 32) = (word64)(rsi);
    WC_S64(rsp, 40) = (word64)(rcx);
    rax = (word64)(WC_L64(rdi, 32));
    rbx = (word64)(WC_L64(rdi, 40));
    WC_S64(rsp, 8) = (word64)(rax);
    WC_S64(rsp, 16) = (word64)(rbx);
    rax = (word32)(WC_L32(rdi, 0));
    rbx = (word32)(WC_L32(rdi, 4));
    rcx = (word32)(WC_L32(rdi, 8));
    rdx = (word32)(WC_L32(rdi, 12));
    r8 = (word32)(WC_L32(rdi, 16));
    r9 = (word32)(WC_L32(rdi, 20));
    r10 = (word32)(WC_L32(rdi, 24));
    r11 = (word32)(WC_L32(rdi, 28));
    r12 = (word32)(WC_L32(rdi, 48));
    r13 = (word32)(WC_L32(rdi, 52));
    r14 = (word32)(WC_L32(rdi, 56));
    r15 = (word32)(WC_L32(rdi, 60));
    WC_S8(rsp, 0) = (byte)(0xa);
L_chacha_x64_block_crypt_start:
    rax = (word32)((word32)rax + (word32)r8);
    rbx = (word32)((word32)rbx + (word32)r9);
    rcx = (word32)((word32)rcx + (word32)r10);
    rdx = (word32)((word32)rdx + (word32)r11);
    r12 = (word32)((word32)r12 ^ (word32)rax);
    r13 = (word32)((word32)r13 ^ (word32)rbx);
    r14 = (word32)((word32)r14 ^ (word32)rcx);
    r15 = (word32)((word32)r15 ^ (word32)rdx);
    r12 = (word32)((((word32)r12) << 16) | (((word32)r12) >> 16));
    r13 = (word32)((((word32)r13) << 16) | (((word32)r13) >> 16));
    r14 = (word32)((((word32)r14) << 16) | (((word32)r14) >> 16));
    r15 = (word32)((((word32)r15) << 16) | (((word32)r15) >> 16));
    WC_S32(rsp, 8) = (word32)(WC_L32(rsp, 8) + (word32)r12);
    WC_S32(rsp, 12) = (word32)(WC_L32(rsp, 12) + (word32)r13);
    WC_S32(rsp, 16) = (word32)(WC_L32(rsp, 16) + (word32)r14);
    WC_S32(rsp, 20) = (word32)(WC_L32(rsp, 20) + (word32)r15);
    r8 = (word32)((word32)r8 ^ WC_L32(rsp, 8));
    r9 = (word32)((word32)r9 ^ WC_L32(rsp, 12));
    r10 = (word32)((word32)r10 ^ WC_L32(rsp, 16));
    r11 = (word32)((word32)r11 ^ WC_L32(rsp, 20));
    r8 = (word32)((((word32)r8) << 12) | (((word32)r8) >> 20));
    r9 = (word32)((((word32)r9) << 12) | (((word32)r9) >> 20));
    r10 = (word32)((((word32)r10) << 12) | (((word32)r10) >> 20));
    r11 = (word32)((((word32)r11) << 12) | (((word32)r11) >> 20));
    rax = (word32)((word32)rax + (word32)r8);
    rbx = (word32)((word32)rbx + (word32)r9);
    rcx = (word32)((word32)rcx + (word32)r10);
    rdx = (word32)((word32)rdx + (word32)r11);
    r12 = (word32)((word32)r12 ^ (word32)rax);
    r13 = (word32)((word32)r13 ^ (word32)rbx);
    r14 = (word32)((word32)r14 ^ (word32)rcx);
    r15 = (word32)((word32)r15 ^ (word32)rdx);
    r12 = (word32)((((word32)r12) << 8) | (((word32)r12) >> 24));
    r13 = (word32)((((word32)r13) << 8) | (((word32)r13) >> 24));
    r14 = (word32)((((word32)r14) << 8) | (((word32)r14) >> 24));
    r15 = (word32)((((word32)r15) << 8) | (((word32)r15) >> 24));
    WC_S32(rsp, 8) = (word32)(WC_L32(rsp, 8) + (word32)r12);
    WC_S32(rsp, 12) = (word32)(WC_L32(rsp, 12) + (word32)r13);
    WC_S32(rsp, 16) = (word32)(WC_L32(rsp, 16) + (word32)r14);
    WC_S32(rsp, 20) = (word32)(WC_L32(rsp, 20) + (word32)r15);
    r8 = (word32)((word32)r8 ^ WC_L32(rsp, 8));
    r9 = (word32)((word32)r9 ^ WC_L32(rsp, 12));
    r10 = (word32)((word32)r10 ^ WC_L32(rsp, 16));
    r11 = (word32)((word32)r11 ^ WC_L32(rsp, 20));
    r8 = (word32)((((word32)r8) << 7) | (((word32)r8) >> 25));
    r9 = (word32)((((word32)r9) << 7) | (((word32)r9) >> 25));
    r10 = (word32)((((word32)r10) << 7) | (((word32)r10) >> 25));
    r11 = (word32)((((word32)r11) << 7) | (((word32)r11) >> 25));
    rax = (word32)((word32)rax + (word32)r9);
    rbx = (word32)((word32)rbx + (word32)r10);
    rcx = (word32)((word32)rcx + (word32)r11);
    rdx = (word32)((word32)rdx + (word32)r8);
    r15 = (word32)((word32)r15 ^ (word32)rax);
    r12 = (word32)((word32)r12 ^ (word32)rbx);
    r13 = (word32)((word32)r13 ^ (word32)rcx);
    r14 = (word32)((word32)r14 ^ (word32)rdx);
    r15 = (word32)((((word32)r15) << 16) | (((word32)r15) >> 16));
    r12 = (word32)((((word32)r12) << 16) | (((word32)r12) >> 16));
    r13 = (word32)((((word32)r13) << 16) | (((word32)r13) >> 16));
    r14 = (word32)((((word32)r14) << 16) | (((word32)r14) >> 16));
    WC_S32(rsp, 16) = (word32)(WC_L32(rsp, 16) + (word32)r15);
    WC_S32(rsp, 20) = (word32)(WC_L32(rsp, 20) + (word32)r12);
    WC_S32(rsp, 8) = (word32)(WC_L32(rsp, 8) + (word32)r13);
    WC_S32(rsp, 12) = (word32)(WC_L32(rsp, 12) + (word32)r14);
    r9 = (word32)((word32)r9 ^ WC_L32(rsp, 16));
    r10 = (word32)((word32)r10 ^ WC_L32(rsp, 20));
    r11 = (word32)((word32)r11 ^ WC_L32(rsp, 8));
    r8 = (word32)((word32)r8 ^ WC_L32(rsp, 12));
    r9 = (word32)((((word32)r9) << 12) | (((word32)r9) >> 20));
    r10 = (word32)((((word32)r10) << 12) | (((word32)r10) >> 20));
    r11 = (word32)((((word32)r11) << 12) | (((word32)r11) >> 20));
    r8 = (word32)((((word32)r8) << 12) | (((word32)r8) >> 20));
    rax = (word32)((word32)rax + (word32)r9);
    rbx = (word32)((word32)rbx + (word32)r10);
    rcx = (word32)((word32)rcx + (word32)r11);
    rdx = (word32)((word32)rdx + (word32)r8);
    r15 = (word32)((word32)r15 ^ (word32)rax);
    r12 = (word32)((word32)r12 ^ (word32)rbx);
    r13 = (word32)((word32)r13 ^ (word32)rcx);
    r14 = (word32)((word32)r14 ^ (word32)rdx);
    r15 = (word32)((((word32)r15) << 8) | (((word32)r15) >> 24));
    r12 = (word32)((((word32)r12) << 8) | (((word32)r12) >> 24));
    r13 = (word32)((((word32)r13) << 8) | (((word32)r13) >> 24));
    r14 = (word32)((((word32)r14) << 8) | (((word32)r14) >> 24));
    WC_S32(rsp, 16) = (word32)(WC_L32(rsp, 16) + (word32)r15);
    WC_S32(rsp, 20) = (word32)(WC_L32(rsp, 20) + (word32)r12);
    WC_S32(rsp, 8) = (word32)(WC_L32(rsp, 8) + (word32)r13);
    WC_S32(rsp, 12) = (word32)(WC_L32(rsp, 12) + (word32)r14);
    r9 = (word32)((word32)r9 ^ WC_L32(rsp, 16));
    r10 = (word32)((word32)r10 ^ WC_L32(rsp, 20));
    r11 = (word32)((word32)r11 ^ WC_L32(rsp, 8));
    r8 = (word32)((word32)r8 ^ WC_L32(rsp, 12));
    r9 = (word32)((((word32)r9) << 7) | (((word32)r9) >> 25));
    r10 = (word32)((((word32)r10) << 7) | (((word32)r10) >> 25));
    r11 = (word32)((((word32)r11) << 7) | (((word32)r11) >> 25));
    r8 = (word32)((((word32)r8) << 7) | (((word32)r8) >> 25));
    WC_S8(rsp, 0) = (byte)(WC_L8(rsp, 0) - 1);
    if (((byte)WC_S8(rsp, 0)) != (0)) {
        goto L_chacha_x64_block_crypt_start;
    }
    rsi = (word64)(WC_L64(rsp, 32));
    rbp = (word64)(WC_L64(rsp, 24));
    rax = (word32)((word32)rax + WC_L32(rdi, 0));
    rbx = (word32)((word32)rbx + WC_L32(rdi, 4));
    rcx = (word32)((word32)rcx + WC_L32(rdi, 8));
    rdx = (word32)((word32)rdx + WC_L32(rdi, 12));
    r8 = (word32)((word32)r8 + WC_L32(rdi, 16));
    r9 = (word32)((word32)r9 + WC_L32(rdi, 20));
    r10 = (word32)((word32)r10 + WC_L32(rdi, 24));
    r11 = (word32)((word32)r11 + WC_L32(rdi, 28));
    r12 = (word32)((word32)r12 + WC_L32(rdi, 48));
    r13 = (word32)((word32)r13 + WC_L32(rdi, 52));
    r14 = (word32)((word32)r14 + WC_L32(rdi, 56));
    r15 = (word32)((word32)r15 + WC_L32(rdi, 60));
    rax = (word32)((word32)rax ^ WC_L32(rsi, 0));
    rbx = (word32)((word32)rbx ^ WC_L32(rsi, 4));
    rcx = (word32)((word32)rcx ^ WC_L32(rsi, 8));
    rdx = (word32)((word32)rdx ^ WC_L32(rsi, 12));
    r8 = (word32)((word32)r8 ^ WC_L32(rsi, 16));
    r9 = (word32)((word32)r9 ^ WC_L32(rsi, 20));
    r10 = (word32)((word32)r10 ^ WC_L32(rsi, 24));
    r11 = (word32)((word32)r11 ^ WC_L32(rsi, 28));
    r12 = (word32)((word32)r12 ^ WC_L32(rsi, 48));
    r13 = (word32)((word32)r13 ^ WC_L32(rsi, 52));
    r14 = (word32)((word32)r14 ^ WC_L32(rsi, 56));
    r15 = (word32)((word32)r15 ^ WC_L32(rsi, 60));
    WC_S32(rbp, 0) = (word32)((word32)rax);
    WC_S32(rbp, 4) = (word32)((word32)rbx);
    WC_S32(rbp, 8) = (word32)((word32)rcx);
    WC_S32(rbp, 12) = (word32)((word32)rdx);
    WC_S32(rbp, 16) = (word32)((word32)r8);
    WC_S32(rbp, 20) = (word32)((word32)r9);
    WC_S32(rbp, 24) = (word32)((word32)r10);
    WC_S32(rbp, 28) = (word32)((word32)r11);
    WC_S32(rbp, 48) = (word32)((word32)r12);
    WC_S32(rbp, 52) = (word32)((word32)r13);
    WC_S32(rbp, 56) = (word32)((word32)r14);
    WC_S32(rbp, 60) = (word32)((word32)r15);
    rax = (word32)(WC_L32(rsp, 8));
    rbx = (word32)(WC_L32(rsp, 12));
    rcx = (word32)(WC_L32(rsp, 16));
    rdx = (word32)(WC_L32(rsp, 20));
    rax = (word32)((word32)rax + WC_L32(rdi, 32));
    rbx = (word32)((word32)rbx + WC_L32(rdi, 36));
    rcx = (word32)((word32)rcx + WC_L32(rdi, 40));
    rdx = (word32)((word32)rdx + WC_L32(rdi, 44));
    rax = (word32)((word32)rax ^ WC_L32(rsi, 32));
    rbx = (word32)((word32)rbx ^ WC_L32(rsi, 36));
    rcx = (word32)((word32)rcx ^ WC_L32(rsi, 40));
    rdx = (word32)((word32)rdx ^ WC_L32(rsi, 44));
    WC_S32(rbp, 32) = (word32)((word32)rax);
    WC_S32(rbp, 36) = (word32)((word32)rbx);
    WC_S32(rbp, 40) = (word32)((word32)rcx);
    WC_S32(rbp, 44) = (word32)((word32)rdx);
    rdx = (word64)(WC_L64(rsp, 24));
    rcx = (word64)(WC_L64(rsp, 40));
    WC_S32(rdi, 48) = (word32)(WC_L32(rdi, 48) + 1);
    rsp = (word64)(rsp + 48);
    rcx = (word32)((word32)rcx - 0x40);
    rsi = (word64)(rsi + 0x40);
    rdx = (word64)(rdx + 0x40);
    if (((word32)rcx) >= (0x40)) {
        goto L_chacha_x64_start;
    }
L_chacha_x64_small:
    if (((word32)rcx) == (0)) {
        goto L_chacha_x64_done;
    }
    rsp = (word64)(rsp - 48);
    WC_S64(rsp, 24) = (word64)(rdx);
    WC_S64(rsp, 32) = (word64)(rsi);
    WC_S64(rsp, 40) = (word64)(rcx);
    rax = (word64)(WC_L64(rdi, 32));
    rbx = (word64)(WC_L64(rdi, 40));
    WC_S64(rsp, 8) = (word64)(rax);
    WC_S64(rsp, 16) = (word64)(rbx);
    rax = (word32)(WC_L32(rdi, 0));
    rbx = (word32)(WC_L32(rdi, 4));
    rcx = (word32)(WC_L32(rdi, 8));
    rdx = (word32)(WC_L32(rdi, 12));
    r8 = (word32)(WC_L32(rdi, 16));
    r9 = (word32)(WC_L32(rdi, 20));
    r10 = (word32)(WC_L32(rdi, 24));
    r11 = (word32)(WC_L32(rdi, 28));
    r12 = (word32)(WC_L32(rdi, 48));
    r13 = (word32)(WC_L32(rdi, 52));
    r14 = (word32)(WC_L32(rdi, 56));
    r15 = (word32)(WC_L32(rdi, 60));
    WC_S8(rsp, 0) = (byte)(0xa);
L_chacha_x64_partial_crypt_start:
    rax = (word32)((word32)rax + (word32)r8);
    rbx = (word32)((word32)rbx + (word32)r9);
    rcx = (word32)((word32)rcx + (word32)r10);
    rdx = (word32)((word32)rdx + (word32)r11);
    r12 = (word32)((word32)r12 ^ (word32)rax);
    r13 = (word32)((word32)r13 ^ (word32)rbx);
    r14 = (word32)((word32)r14 ^ (word32)rcx);
    r15 = (word32)((word32)r15 ^ (word32)rdx);
    r12 = (word32)((((word32)r12) << 16) | (((word32)r12) >> 16));
    r13 = (word32)((((word32)r13) << 16) | (((word32)r13) >> 16));
    r14 = (word32)((((word32)r14) << 16) | (((word32)r14) >> 16));
    r15 = (word32)((((word32)r15) << 16) | (((word32)r15) >> 16));
    WC_S32(rsp, 8) = (word32)(WC_L32(rsp, 8) + (word32)r12);
    WC_S32(rsp, 12) = (word32)(WC_L32(rsp, 12) + (word32)r13);
    WC_S32(rsp, 16) = (word32)(WC_L32(rsp, 16) + (word32)r14);
    WC_S32(rsp, 20) = (word32)(WC_L32(rsp, 20) + (word32)r15);
    r8 = (word32)((word32)r8 ^ WC_L32(rsp, 8));
    r9 = (word32)((word32)r9 ^ WC_L32(rsp, 12));
    r10 = (word32)((word32)r10 ^ WC_L32(rsp, 16));
    r11 = (word32)((word32)r11 ^ WC_L32(rsp, 20));
    r8 = (word32)((((word32)r8) << 12) | (((word32)r8) >> 20));
    r9 = (word32)((((word32)r9) << 12) | (((word32)r9) >> 20));
    r10 = (word32)((((word32)r10) << 12) | (((word32)r10) >> 20));
    r11 = (word32)((((word32)r11) << 12) | (((word32)r11) >> 20));
    rax = (word32)((word32)rax + (word32)r8);
    rbx = (word32)((word32)rbx + (word32)r9);
    rcx = (word32)((word32)rcx + (word32)r10);
    rdx = (word32)((word32)rdx + (word32)r11);
    r12 = (word32)((word32)r12 ^ (word32)rax);
    r13 = (word32)((word32)r13 ^ (word32)rbx);
    r14 = (word32)((word32)r14 ^ (word32)rcx);
    r15 = (word32)((word32)r15 ^ (word32)rdx);
    r12 = (word32)((((word32)r12) << 8) | (((word32)r12) >> 24));
    r13 = (word32)((((word32)r13) << 8) | (((word32)r13) >> 24));
    r14 = (word32)((((word32)r14) << 8) | (((word32)r14) >> 24));
    r15 = (word32)((((word32)r15) << 8) | (((word32)r15) >> 24));
    WC_S32(rsp, 8) = (word32)(WC_L32(rsp, 8) + (word32)r12);
    WC_S32(rsp, 12) = (word32)(WC_L32(rsp, 12) + (word32)r13);
    WC_S32(rsp, 16) = (word32)(WC_L32(rsp, 16) + (word32)r14);
    WC_S32(rsp, 20) = (word32)(WC_L32(rsp, 20) + (word32)r15);
    r8 = (word32)((word32)r8 ^ WC_L32(rsp, 8));
    r9 = (word32)((word32)r9 ^ WC_L32(rsp, 12));
    r10 = (word32)((word32)r10 ^ WC_L32(rsp, 16));
    r11 = (word32)((word32)r11 ^ WC_L32(rsp, 20));
    r8 = (word32)((((word32)r8) << 7) | (((word32)r8) >> 25));
    r9 = (word32)((((word32)r9) << 7) | (((word32)r9) >> 25));
    r10 = (word32)((((word32)r10) << 7) | (((word32)r10) >> 25));
    r11 = (word32)((((word32)r11) << 7) | (((word32)r11) >> 25));
    rax = (word32)((word32)rax + (word32)r9);
    rbx = (word32)((word32)rbx + (word32)r10);
    rcx = (word32)((word32)rcx + (word32)r11);
    rdx = (word32)((word32)rdx + (word32)r8);
    r15 = (word32)((word32)r15 ^ (word32)rax);
    r12 = (word32)((word32)r12 ^ (word32)rbx);
    r13 = (word32)((word32)r13 ^ (word32)rcx);
    r14 = (word32)((word32)r14 ^ (word32)rdx);
    r15 = (word32)((((word32)r15) << 16) | (((word32)r15) >> 16));
    r12 = (word32)((((word32)r12) << 16) | (((word32)r12) >> 16));
    r13 = (word32)((((word32)r13) << 16) | (((word32)r13) >> 16));
    r14 = (word32)((((word32)r14) << 16) | (((word32)r14) >> 16));
    WC_S32(rsp, 16) = (word32)(WC_L32(rsp, 16) + (word32)r15);
    WC_S32(rsp, 20) = (word32)(WC_L32(rsp, 20) + (word32)r12);
    WC_S32(rsp, 8) = (word32)(WC_L32(rsp, 8) + (word32)r13);
    WC_S32(rsp, 12) = (word32)(WC_L32(rsp, 12) + (word32)r14);
    r9 = (word32)((word32)r9 ^ WC_L32(rsp, 16));
    r10 = (word32)((word32)r10 ^ WC_L32(rsp, 20));
    r11 = (word32)((word32)r11 ^ WC_L32(rsp, 8));
    r8 = (word32)((word32)r8 ^ WC_L32(rsp, 12));
    r9 = (word32)((((word32)r9) << 12) | (((word32)r9) >> 20));
    r10 = (word32)((((word32)r10) << 12) | (((word32)r10) >> 20));
    r11 = (word32)((((word32)r11) << 12) | (((word32)r11) >> 20));
    r8 = (word32)((((word32)r8) << 12) | (((word32)r8) >> 20));
    rax = (word32)((word32)rax + (word32)r9);
    rbx = (word32)((word32)rbx + (word32)r10);
    rcx = (word32)((word32)rcx + (word32)r11);
    rdx = (word32)((word32)rdx + (word32)r8);
    r15 = (word32)((word32)r15 ^ (word32)rax);
    r12 = (word32)((word32)r12 ^ (word32)rbx);
    r13 = (word32)((word32)r13 ^ (word32)rcx);
    r14 = (word32)((word32)r14 ^ (word32)rdx);
    r15 = (word32)((((word32)r15) << 8) | (((word32)r15) >> 24));
    r12 = (word32)((((word32)r12) << 8) | (((word32)r12) >> 24));
    r13 = (word32)((((word32)r13) << 8) | (((word32)r13) >> 24));
    r14 = (word32)((((word32)r14) << 8) | (((word32)r14) >> 24));
    WC_S32(rsp, 16) = (word32)(WC_L32(rsp, 16) + (word32)r15);
    WC_S32(rsp, 20) = (word32)(WC_L32(rsp, 20) + (word32)r12);
    WC_S32(rsp, 8) = (word32)(WC_L32(rsp, 8) + (word32)r13);
    WC_S32(rsp, 12) = (word32)(WC_L32(rsp, 12) + (word32)r14);
    r9 = (word32)((word32)r9 ^ WC_L32(rsp, 16));
    r10 = (word32)((word32)r10 ^ WC_L32(rsp, 20));
    r11 = (word32)((word32)r11 ^ WC_L32(rsp, 8));
    r8 = (word32)((word32)r8 ^ WC_L32(rsp, 12));
    r9 = (word32)((((word32)r9) << 7) | (((word32)r9) >> 25));
    r10 = (word32)((((word32)r10) << 7) | (((word32)r10) >> 25));
    r11 = (word32)((((word32)r11) << 7) | (((word32)r11) >> 25));
    r8 = (word32)((((word32)r8) << 7) | (((word32)r8) >> 25));
    WC_S8(rsp, 0) = (byte)(WC_L8(rsp, 0) - 1);
    if (((byte)WC_S8(rsp, 0)) != (0)) {
        goto L_chacha_x64_partial_crypt_start;
    }
    rsi = (word64)(WC_L64(rsp, 32));
    rax = (word32)((word32)rax + WC_L32(rdi, 0));
    rbx = (word32)((word32)rbx + WC_L32(rdi, 4));
    rcx = (word32)((word32)rcx + WC_L32(rdi, 8));
    rdx = (word32)((word32)rdx + WC_L32(rdi, 12));
    r8 = (word32)((word32)r8 + WC_L32(rdi, 16));
    r9 = (word32)((word32)r9 + WC_L32(rdi, 20));
    r10 = (word32)((word32)r10 + WC_L32(rdi, 24));
    r11 = (word32)((word32)r11 + WC_L32(rdi, 28));
    r12 = (word32)((word32)r12 + WC_L32(rdi, 48));
    r13 = (word32)((word32)r13 + WC_L32(rdi, 52));
    r14 = (word32)((word32)r14 + WC_L32(rdi, 56));
    r15 = (word32)((word32)r15 + WC_L32(rdi, 60));
    rbp = (word64)(rdi + 80);
    WC_S32(rbp, 0) = (word32)((word32)rax);
    WC_S32(rbp, 4) = (word32)((word32)rbx);
    WC_S32(rbp, 8) = (word32)((word32)rcx);
    WC_S32(rbp, 12) = (word32)((word32)rdx);
    WC_S32(rbp, 16) = (word32)((word32)r8);
    WC_S32(rbp, 20) = (word32)((word32)r9);
    WC_S32(rbp, 24) = (word32)((word32)r10);
    WC_S32(rbp, 28) = (word32)((word32)r11);
    WC_S32(rbp, 48) = (word32)((word32)r12);
    WC_S32(rbp, 52) = (word32)((word32)r13);
    WC_S32(rbp, 56) = (word32)((word32)r14);
    WC_S32(rbp, 60) = (word32)((word32)r15);
    rax = (word32)(WC_L32(rsp, 8));
    rbx = (word32)(WC_L32(rsp, 12));
    rcx = (word32)(WC_L32(rsp, 16));
    rdx = (word32)(WC_L32(rsp, 20));
    rax = (word32)((word32)rax + WC_L32(rdi, 32));
    rbx = (word32)((word32)rbx + WC_L32(rdi, 36));
    rcx = (word32)((word32)rcx + WC_L32(rdi, 40));
    rdx = (word32)((word32)rdx + WC_L32(rdi, 44));
    WC_S32(rbp, 32) = (word32)((word32)rax);
    WC_S32(rbp, 36) = (word32)((word32)rbx);
    WC_S32(rbp, 40) = (word32)((word32)rcx);
    WC_S32(rbp, 44) = (word32)((word32)rdx);
    rdx = (word64)(WC_L64(rsp, 24));
    rcx = (word64)(WC_L64(rsp, 40));
    WC_S32(rdi, 48) = (word32)(WC_L32(rdi, 48) + 1);
    rsp = (word64)(rsp + 48);
    r8 = (word32)((word32)rcx);
    rbx = (word64)(0);
    r8 = (word32)((word32)r8 & 7);
    if (((word32)r8) == (0)) {
        goto L_chacha_x64_partial_start64;
    }
L_chacha_x64_partial_start8:
    rax = (word32)((word32)WC_L8(rbp, rbx));
    rax = (rax & ~(word64)0xff) | ((word64)(byte)((byte)rax ^ WC_L8(rsi,
        rbx)) & 0xff);
    WC_S8(rdx, rbx) = (byte)((byte)rax);
    rbx = (word32)((word32)rbx + 1);
    zf1 = (word32)rbx;
    zf2 = (word32)r8;
    if (((word32)rbx) != ((word32)r8)) {
        goto L_chacha_x64_partial_start8;
    }
    if ((zf1) == (zf2)) {
        goto L_chacha_x64_partial_end64;
    }
L_chacha_x64_partial_start64:
    rax = (word64)(WC_L64(rbp, rbx));
    rax = (word64)(rax ^ WC_L64(rsi, rbx));
    WC_S64(rdx, rbx) = (word64)(rax);
    rbx = (word32)((word32)rbx + 8);
L_chacha_x64_partial_end64:
    if (((word32)rbx) != ((word32)rcx)) {
        goto L_chacha_x64_partial_start64;
    }
    rcx = (word32)(0x40);
    rcx = (word32)((word32)rcx - (word32)rbx);
    WC_S32(rdi, 76) = (word32)((word32)rcx);
L_chacha_x64_done:
    ;
}

#ifndef HAVE_INTEL_SSSE3
#define HAVE_INTEL_SSSE3
#endif /* HAVE_INTEL_SSSE3 */
#ifdef HAVE_INTEL_SSSE3
XALIGNED(16) static const word64 L_chacha20_sse3_rotl8[] WC_X64I_UNUSED = {
    0x0605040702010003ULL, 0x0e0d0c0f0a09080bULL,
};

XALIGNED(16) static const word64 L_chacha20_sse3_rotl16[] WC_X64I_UNUSED = {
    0x0504070601000302ULL, 0x0d0c0f0e09080b0aULL,
};

XALIGNED(16) static const word64 L_chacha20_sse3_one[] WC_X64I_UNUSED = {
    0x0000000000000001ULL, 0x0000000000000000ULL,
};

WC_X64I_TARGET("sse2,ssse3")
WOLFSSL_LOCAL void chacha_encrypt_sse3(ChaCha* ctx, const byte* m, byte* c,
    word32 bytes)
{
    word64 rdi, rsi, rdx, rcx, r11, r12, r13, rax = 0, r8 = 0, r9 = 0,
           r10 = 0;
    __m128i x0 = _mm_setzero_si128(), x1 = _mm_setzero_si128(),
            x2 = _mm_setzero_si128(), x3 = _mm_setzero_si128(),
            x4 = _mm_setzero_si128(), x5 = _mm_setzero_si128(),
            x6 = _mm_setzero_si128(), x7 = _mm_setzero_si128(),
            x8 = _mm_setzero_si128(), x9 = _mm_setzero_si128(),
            x10 = _mm_setzero_si128(), x11 = _mm_setzero_si128(),
            x12 = _mm_setzero_si128(), x13 = _mm_setzero_si128();
    word32 zf1;
    word32 zf2;

    rdi = (word64)(size_t)ctx;
    rsi = (word64)(size_t)m;
    rdx = (word64)(size_t)c;
    rcx = (word64)(word32)bytes;

    r11 = (word64)((word64)(size_t)L_chacha20_sse3_rotl8);
    r12 = (word64)((word64)(size_t)L_chacha20_sse3_rotl16);
    r13 = (word64)((word64)(size_t)L_chacha20_sse3_one);
    if (((word32)rcx) < (0x80)) {
        goto L_chacha20_sse3_128_done;
    }
L_chacha20_sse3_128_start:
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 16));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 48));
    x10 = x0;
    x11 = x1;
    x12 = x2;
    x13 = x3;
    x4 = x0;
    x5 = x1;
    x6 = x2;
    x7 = x3;
    x7 = _mm_add_epi32(x7, _mm_loadu_si128((const __m128i*)WC_PR(r13, 0)));
    rax = (rax & ~(word64)0xff) | ((word64)(byte)(0xa) & 0xff);
L_chacha20_sse3_128_crypt2_start:
    x0 = _mm_add_epi32(x0, x1);
    x4 = _mm_add_epi32(x4, x5);
    x3 = _mm_xor_si128(x3, x0);
    x7 = _mm_xor_si128(x7, x4);
    x3 = _mm_shuffle_epi8(x3, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x7 = _mm_shuffle_epi8(x7, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x2 = _mm_add_epi32(x2, x3);
    x6 = _mm_add_epi32(x6, x7);
    x1 = _mm_xor_si128(x1, x2);
    x5 = _mm_xor_si128(x5, x6);
    x8 = x1;
    x9 = x5;
    x8 = _mm_srli_epi32(x8, 20);
    x9 = _mm_srli_epi32(x9, 20);
    x1 = _mm_slli_epi32(x1, 12);
    x5 = _mm_slli_epi32(x5, 12);
    x1 = _mm_xor_si128(x1, x8);
    x5 = _mm_xor_si128(x5, x9);
    x0 = _mm_add_epi32(x0, x1);
    x4 = _mm_add_epi32(x4, x5);
    x3 = _mm_xor_si128(x3, x0);
    x7 = _mm_xor_si128(x7, x4);
    x3 = _mm_shuffle_epi8(x3, _mm_loadu_si128((const __m128i*)WC_PR(r11, 0)));
    x7 = _mm_shuffle_epi8(x7, _mm_loadu_si128((const __m128i*)WC_PR(r11, 0)));
    x2 = _mm_add_epi32(x2, x3);
    x6 = _mm_add_epi32(x6, x7);
    x1 = _mm_xor_si128(x1, x2);
    x5 = _mm_xor_si128(x5, x6);
    x8 = x1;
    x9 = x5;
    x8 = _mm_srli_epi32(x8, 25);
    x9 = _mm_srli_epi32(x9, 25);
    x1 = _mm_slli_epi32(x1, 7);
    x5 = _mm_slli_epi32(x5, 7);
    x1 = _mm_xor_si128(x1, x8);
    x5 = _mm_xor_si128(x5, x9);
    x1 = _mm_shuffle_epi32(x1, 0x39);
    x2 = _mm_shuffle_epi32(x2, 0x4e);
    x3 = _mm_shuffle_epi32(x3, 0x93);
    x5 = _mm_shuffle_epi32(x5, 0x39);
    x6 = _mm_shuffle_epi32(x6, 0x4e);
    x7 = _mm_shuffle_epi32(x7, 0x93);
    x0 = _mm_add_epi32(x0, x1);
    x4 = _mm_add_epi32(x4, x5);
    x3 = _mm_xor_si128(x3, x0);
    x7 = _mm_xor_si128(x7, x4);
    x3 = _mm_shuffle_epi8(x3, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x7 = _mm_shuffle_epi8(x7, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x2 = _mm_add_epi32(x2, x3);
    x6 = _mm_add_epi32(x6, x7);
    x1 = _mm_xor_si128(x1, x2);
    x5 = _mm_xor_si128(x5, x6);
    x8 = x1;
    x9 = x5;
    x8 = _mm_srli_epi32(x8, 20);
    x9 = _mm_srli_epi32(x9, 20);
    x1 = _mm_slli_epi32(x1, 12);
    x5 = _mm_slli_epi32(x5, 12);
    x1 = _mm_xor_si128(x1, x8);
    x5 = _mm_xor_si128(x5, x9);
    x0 = _mm_add_epi32(x0, x1);
    x4 = _mm_add_epi32(x4, x5);
    x3 = _mm_xor_si128(x3, x0);
    x7 = _mm_xor_si128(x7, x4);
    x3 = _mm_shuffle_epi8(x3, _mm_loadu_si128((const __m128i*)WC_PR(r11, 0)));
    x7 = _mm_shuffle_epi8(x7, _mm_loadu_si128((const __m128i*)WC_PR(r11, 0)));
    x2 = _mm_add_epi32(x2, x3);
    x6 = _mm_add_epi32(x6, x7);
    x1 = _mm_xor_si128(x1, x2);
    x5 = _mm_xor_si128(x5, x6);
    x8 = x1;
    x9 = x5;
    x8 = _mm_srli_epi32(x8, 25);
    x9 = _mm_srli_epi32(x9, 25);
    x1 = _mm_slli_epi32(x1, 7);
    x5 = _mm_slli_epi32(x5, 7);
    x1 = _mm_xor_si128(x1, x8);
    x5 = _mm_xor_si128(x5, x9);
    x1 = _mm_shuffle_epi32(x1, 0x93);
    x2 = _mm_shuffle_epi32(x2, 0x4e);
    x3 = _mm_shuffle_epi32(x3, 0x39);
    x5 = _mm_shuffle_epi32(x5, 0x93);
    x6 = _mm_shuffle_epi32(x6, 0x4e);
    x7 = _mm_shuffle_epi32(x7, 0x39);
    rax = (rax & ~(word64)0xff) | ((word64)(byte)((byte)rax - 1) & 0xff);
    if (((byte)rax) != (0)) {
        goto L_chacha20_sse3_128_crypt2_start;
    }
    x0 = _mm_add_epi32(x0, x10);
    x1 = _mm_add_epi32(x1, x11);
    x2 = _mm_add_epi32(x2, x12);
    x3 = _mm_add_epi32(x3, x13);
    x4 = _mm_add_epi32(x4, x10);
    x5 = _mm_add_epi32(x5, x11);
    x6 = _mm_add_epi32(x6, x12);
    x7 = _mm_add_epi32(x7, x13);
    x7 = _mm_add_epi32(x7, _mm_loadu_si128((const __m128i*)WC_PR(r13, 0)));
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 0));
    x0 = _mm_xor_si128(x0, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x0);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 16));
    x1 = _mm_xor_si128(x1, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 16), x1);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 32));
    x2 = _mm_xor_si128(x2, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 32), x2);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 48));
    x3 = _mm_xor_si128(x3, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 48), x3);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 64));
    x4 = _mm_xor_si128(x4, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 64), x4);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 80));
    x5 = _mm_xor_si128(x5, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 80), x5);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 96));
    x6 = _mm_xor_si128(x6, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 96), x6);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 112));
    x7 = _mm_xor_si128(x7, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 112), x7);
    WC_S32(rdi, 48) = (word32)(WC_L32(rdi, 48) + 2);
    rcx = (word32)((word32)rcx - 0x80);
    rsi = (word64)(rsi + 0x80);
    rdx = (word64)(rdx + 0x80);
    if (((word32)rcx) >= (0x80)) {
        goto L_chacha20_sse3_128_start;
    }
L_chacha20_sse3_128_done:
    if (((word32)rcx) == (0)) {
        goto L_chacha20_sse3_last_done;
    }
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 16));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 48));
    x10 = x0;
    x11 = x1;
    x12 = x2;
    x13 = x3;
    x4 = x0;
    x5 = x1;
    x6 = x2;
    x7 = x3;
    x7 = _mm_add_epi32(x7, _mm_loadu_si128((const __m128i*)WC_PR(r13, 0)));
    rax = (rax & ~(word64)0xff) | ((word64)(byte)(0xa) & 0xff);
L_chacha20_sse3_last_crypt2_start:
    x0 = _mm_add_epi32(x0, x1);
    x4 = _mm_add_epi32(x4, x5);
    x3 = _mm_xor_si128(x3, x0);
    x7 = _mm_xor_si128(x7, x4);
    x3 = _mm_shuffle_epi8(x3, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x7 = _mm_shuffle_epi8(x7, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x2 = _mm_add_epi32(x2, x3);
    x6 = _mm_add_epi32(x6, x7);
    x1 = _mm_xor_si128(x1, x2);
    x5 = _mm_xor_si128(x5, x6);
    x8 = x1;
    x9 = x5;
    x8 = _mm_srli_epi32(x8, 20);
    x9 = _mm_srli_epi32(x9, 20);
    x1 = _mm_slli_epi32(x1, 12);
    x5 = _mm_slli_epi32(x5, 12);
    x1 = _mm_xor_si128(x1, x8);
    x5 = _mm_xor_si128(x5, x9);
    x0 = _mm_add_epi32(x0, x1);
    x4 = _mm_add_epi32(x4, x5);
    x3 = _mm_xor_si128(x3, x0);
    x7 = _mm_xor_si128(x7, x4);
    x3 = _mm_shuffle_epi8(x3, _mm_loadu_si128((const __m128i*)WC_PR(r11, 0)));
    x7 = _mm_shuffle_epi8(x7, _mm_loadu_si128((const __m128i*)WC_PR(r11, 0)));
    x2 = _mm_add_epi32(x2, x3);
    x6 = _mm_add_epi32(x6, x7);
    x1 = _mm_xor_si128(x1, x2);
    x5 = _mm_xor_si128(x5, x6);
    x8 = x1;
    x9 = x5;
    x8 = _mm_srli_epi32(x8, 25);
    x9 = _mm_srli_epi32(x9, 25);
    x1 = _mm_slli_epi32(x1, 7);
    x5 = _mm_slli_epi32(x5, 7);
    x1 = _mm_xor_si128(x1, x8);
    x5 = _mm_xor_si128(x5, x9);
    x1 = _mm_shuffle_epi32(x1, 0x39);
    x2 = _mm_shuffle_epi32(x2, 0x4e);
    x3 = _mm_shuffle_epi32(x3, 0x93);
    x5 = _mm_shuffle_epi32(x5, 0x39);
    x6 = _mm_shuffle_epi32(x6, 0x4e);
    x7 = _mm_shuffle_epi32(x7, 0x93);
    x0 = _mm_add_epi32(x0, x1);
    x4 = _mm_add_epi32(x4, x5);
    x3 = _mm_xor_si128(x3, x0);
    x7 = _mm_xor_si128(x7, x4);
    x3 = _mm_shuffle_epi8(x3, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x7 = _mm_shuffle_epi8(x7, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x2 = _mm_add_epi32(x2, x3);
    x6 = _mm_add_epi32(x6, x7);
    x1 = _mm_xor_si128(x1, x2);
    x5 = _mm_xor_si128(x5, x6);
    x8 = x1;
    x9 = x5;
    x8 = _mm_srli_epi32(x8, 20);
    x9 = _mm_srli_epi32(x9, 20);
    x1 = _mm_slli_epi32(x1, 12);
    x5 = _mm_slli_epi32(x5, 12);
    x1 = _mm_xor_si128(x1, x8);
    x5 = _mm_xor_si128(x5, x9);
    x0 = _mm_add_epi32(x0, x1);
    x4 = _mm_add_epi32(x4, x5);
    x3 = _mm_xor_si128(x3, x0);
    x7 = _mm_xor_si128(x7, x4);
    x3 = _mm_shuffle_epi8(x3, _mm_loadu_si128((const __m128i*)WC_PR(r11, 0)));
    x7 = _mm_shuffle_epi8(x7, _mm_loadu_si128((const __m128i*)WC_PR(r11, 0)));
    x2 = _mm_add_epi32(x2, x3);
    x6 = _mm_add_epi32(x6, x7);
    x1 = _mm_xor_si128(x1, x2);
    x5 = _mm_xor_si128(x5, x6);
    x8 = x1;
    x9 = x5;
    x8 = _mm_srli_epi32(x8, 25);
    x9 = _mm_srli_epi32(x9, 25);
    x1 = _mm_slli_epi32(x1, 7);
    x5 = _mm_slli_epi32(x5, 7);
    x1 = _mm_xor_si128(x1, x8);
    x5 = _mm_xor_si128(x5, x9);
    x1 = _mm_shuffle_epi32(x1, 0x93);
    x2 = _mm_shuffle_epi32(x2, 0x4e);
    x3 = _mm_shuffle_epi32(x3, 0x39);
    x5 = _mm_shuffle_epi32(x5, 0x93);
    x6 = _mm_shuffle_epi32(x6, 0x4e);
    x7 = _mm_shuffle_epi32(x7, 0x39);
    rax = (rax & ~(word64)0xff) | ((word64)(byte)((byte)rax - 1) & 0xff);
    if (((byte)rax) != (0)) {
        goto L_chacha20_sse3_last_crypt2_start;
    }
    x0 = _mm_add_epi32(x0, x10);
    x1 = _mm_add_epi32(x1, x11);
    x2 = _mm_add_epi32(x2, x12);
    x3 = _mm_add_epi32(x3, x13);
    x4 = _mm_add_epi32(x4, x10);
    x5 = _mm_add_epi32(x5, x11);
    x6 = _mm_add_epi32(x6, x12);
    x7 = _mm_add_epi32(x7, x13);
    x7 = _mm_add_epi32(x7, _mm_loadu_si128((const __m128i*)WC_PR(r13, 0)));
    if (((word32)rcx) <= (0x40)) {
        goto L_chacha20_sse3_last_lt64;
    }
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 0));
    x0 = _mm_xor_si128(x0, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x0);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 16));
    x1 = _mm_xor_si128(x1, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 16), x1);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 32));
    x2 = _mm_xor_si128(x2, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 32), x2);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 48));
    x3 = _mm_xor_si128(x3, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 48), x3);
    x0 = x4;
    x1 = x5;
    x2 = x6;
    x3 = x7;
    WC_S32(rdi, 48) = (word32)(WC_L32(rdi, 48) + 1);
    rcx = (word32)((word32)rcx - 0x40);
    rsi = (word64)(rsi + 0x40);
    rdx = (word64)(rdx + 0x40);
L_chacha20_sse3_last_lt64:
    r8 = (word64)(rdi + 80);
    _mm_storeu_si128((__m128i*)WC_PW(r8, 0), x0);
    _mm_storeu_si128((__m128i*)WC_PW(r8, 16), x1);
    _mm_storeu_si128((__m128i*)WC_PW(r8, 32), x2);
    _mm_storeu_si128((__m128i*)WC_PW(r8, 48), x3);
    WC_S32(rdi, 48) = (word32)(WC_L32(rdi, 48) + 1);
    rax = (word32)((word32)rcx);
    r9 = (word64)(0);
    rax = (word32)((word32)rax & 7);
    if (((word32)rax) == (0)) {
        goto L_chacha20_sse3_last_start64;
    }
L_chacha20_sse3_last_start8:
    r10 = (word32)((word32)WC_L8(r8, r9));
    r10 = (r10 & ~(word64)0xff) | ((word64)(byte)((byte)r10 ^ WC_L8(rsi,
        r9)) & 0xff);
    WC_S8(rdx, r9) = (byte)((byte)r10);
    r9 = (word32)((word32)r9 + 1);
    zf1 = (word32)r9;
    zf2 = (word32)rax;
    if (((word32)r9) != ((word32)rax)) {
        goto L_chacha20_sse3_last_start8;
    }
    if ((zf1) == (zf2)) {
        goto L_chacha20_sse3_last_end64;
    }
L_chacha20_sse3_last_start64:
    r10 = (word64)(WC_L64(r8, r9));
    r10 = (word64)(r10 ^ WC_L64(rsi, r9));
    WC_S64(rdx, r9) = (word64)(r10);
    r9 = (word32)((word32)r9 + 8);
L_chacha20_sse3_last_end64:
    if (((word32)r9) != ((word32)rcx)) {
        goto L_chacha20_sse3_last_start64;
    }
    rax = (word32)(0x40);
    rax = (word32)((word32)rax - (word32)r9);
    WC_S32(rdi, 76) = (word32)((word32)rax);
L_chacha20_sse3_last_done:
    ;
}

#endif /* HAVE_INTEL_SSSE3 */
#ifdef HAVE_INTEL_AVX1
XALIGNED(16) static const word64 L_chacha20_avx1_rotl8[] WC_X64I_UNUSED = {
    0x0605040702010003ULL, 0x0e0d0c0f0a09080bULL,
};

XALIGNED(16) static const word64 L_chacha20_avx1_rotl16[] WC_X64I_UNUSED = {
    0x0504070601000302ULL, 0x0d0c0f0e09080b0aULL,
};

XALIGNED(16) static const word64 L_chacha20_avx1_add[] WC_X64I_UNUSED = {
    0x0000000100000000ULL, 0x0000000300000002ULL,
};

XALIGNED(16) static const word64 L_chacha20_avx1_four[] WC_X64I_UNUSED = {
    0x0000000400000004ULL, 0x0000000400000004ULL,
};

WC_X64I_TARGET("avx")
WOLFSSL_LOCAL void chacha_encrypt_avx1(ChaCha* ctx, const byte* m, byte* c,
    word32 bytes)
{
    word64 rdi, rsi, rdx, rcx, rsp, r9, r10, r12, r13, r14, r15, rax, r8 = 0,
           r11 = 0;
    __m128i x0 = _mm_setzero_si128(), x1 = _mm_setzero_si128(),
            x2 = _mm_setzero_si128(), x3 = _mm_setzero_si128(),
            x4 = _mm_setzero_si128(), x5 = _mm_setzero_si128(),
            x6 = _mm_setzero_si128(), x7 = _mm_setzero_si128(),
            x8 = _mm_setzero_si128(), x9 = _mm_setzero_si128(),
            x10 = _mm_setzero_si128(), x11 = _mm_setzero_si128(),
            x12 = _mm_setzero_si128(), x13 = _mm_setzero_si128(),
            x14 = _mm_setzero_si128(), x15 = _mm_setzero_si128();
    XALIGNED(32) WC_X64I_SLOT stk[52];
    word32 zf1;
    word32 zf2;

    rdi = (word64)(size_t)ctx;
    rsi = (word64)(size_t)m;
    rdx = (word64)(size_t)c;
    rcx = (word64)(word32)bytes;

    rsp = (word64)(size_t)stk + 416;
    rsp = (word64)(rsp - 400);
    r9 = (word64)(rsp);
    r10 = (word64)(rsp + 256);
    r12 = (word64)((word64)(size_t)L_chacha20_avx1_rotl8);
    r13 = (word64)((word64)(size_t)L_chacha20_avx1_rotl16);
    r14 = (word64)((word64)(size_t)L_chacha20_avx1_add);
    r15 = (word64)((word64)(size_t)L_chacha20_avx1_four);
    r9 = (word64)(r9 + 0xf);
    r10 = (word64)(r10 + 0xf);
    r9 = (word64)(r9 & -16);
    r10 = (word64)(r10 & -16);
    rax = (word32)((word32)rcx);
    rax = (word32)((word32)rax >> 8);
    if (((word32)rax) == (0)) {
        goto L_chacha20_avx1_end128;
    }
    x0 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)WC_PR(rdi, 0)), 0);
    x1 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)WC_PR(rdi, 4)), 0);
    x2 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)WC_PR(rdi, 8)), 0);
    x3 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)WC_PR(rdi, 12)), 0);
    x4 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)WC_PR(rdi, 16)), 0);
    x5 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)WC_PR(rdi, 20)), 0);
    x6 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)WC_PR(rdi, 24)), 0);
    x7 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)WC_PR(rdi, 28)), 0);
    x8 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)WC_PR(rdi, 32)), 0);
    x9 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)WC_PR(rdi, 36)), 0);
    x10 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)WC_PR(rdi, 40)), 0);
    x11 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)WC_PR(rdi, 44)), 0);
    x12 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)WC_PR(rdi, 48)), 0);
    x13 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)WC_PR(rdi, 52)), 0);
    x14 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)WC_PR(rdi, 56)), 0);
    x15 = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)WC_PR(rdi, 60)), 0);
    x12 = _mm_add_epi32(x12, _mm_loadu_si128((const __m128i*)WC_PR(r14, 0)));
    _mm_storeu_si128((__m128i*)WC_PW(r9, 0), x0);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 16), x1);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 32), x2);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 48), x3);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 64), x4);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 80), x5);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 96), x6);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 112), x7);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 128), x8);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 144), x9);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 160), x10);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 176), x11);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 192), x12);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 208), x13);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 224), x14);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 240), x15);
L_chacha20_avx1_start128:
    _mm_storeu_si128((__m128i*)WC_PW(r10, 48), x11);
    r8 = (r8 & ~(word64)0xff) | ((word64)(byte)(0xa) & 0xff);
L_chacha20_avx1_loop128:
    x0 = _mm_add_epi32(x0, x4);
    x12 = _mm_xor_si128(x12, x0);
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x12 = _mm_shuffle_epi8(x12, _mm_loadu_si128((const __m128i*)WC_PR(r13, 0)));
    x8 = _mm_add_epi32(x8, x12);
    x4 = _mm_xor_si128(x4, x8);
    x1 = _mm_add_epi32(x1, x5);
    x13 = _mm_xor_si128(x13, x1);
    x13 = _mm_shuffle_epi8(x13, _mm_loadu_si128((const __m128i*)WC_PR(r13, 0)));
    x9 = _mm_add_epi32(x9, x13);
    x5 = _mm_xor_si128(x5, x9);
    x2 = _mm_add_epi32(x2, x6);
    x14 = _mm_xor_si128(x14, x2);
    x14 = _mm_shuffle_epi8(x14, _mm_loadu_si128((const __m128i*)WC_PR(r13, 0)));
    x10 = _mm_add_epi32(x10, x14);
    x6 = _mm_xor_si128(x6, x10);
    x3 = _mm_add_epi32(x3, x7);
    x15 = _mm_xor_si128(x15, x3);
    x15 = _mm_shuffle_epi8(x15, _mm_loadu_si128((const __m128i*)WC_PR(r13, 0)));
    x11 = _mm_add_epi32(x11, x15);
    x7 = _mm_xor_si128(x7, x11);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 48), x11);
    x11 = _mm_srli_epi32(x4, 20);
    x4 = _mm_slli_epi32(x4, 12);
    x4 = _mm_xor_si128(x4, x11);
    x11 = _mm_srli_epi32(x5, 20);
    x5 = _mm_slli_epi32(x5, 12);
    x5 = _mm_xor_si128(x5, x11);
    x11 = _mm_srli_epi32(x6, 20);
    x6 = _mm_slli_epi32(x6, 12);
    x6 = _mm_xor_si128(x6, x11);
    x11 = _mm_srli_epi32(x7, 20);
    x7 = _mm_slli_epi32(x7, 12);
    x7 = _mm_xor_si128(x7, x11);
    x0 = _mm_add_epi32(x0, x4);
    x12 = _mm_xor_si128(x12, x0);
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x12 = _mm_shuffle_epi8(x12, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x8 = _mm_add_epi32(x8, x12);
    x4 = _mm_xor_si128(x4, x8);
    x1 = _mm_add_epi32(x1, x5);
    x13 = _mm_xor_si128(x13, x1);
    x13 = _mm_shuffle_epi8(x13, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x9 = _mm_add_epi32(x9, x13);
    x5 = _mm_xor_si128(x5, x9);
    x2 = _mm_add_epi32(x2, x6);
    x14 = _mm_xor_si128(x14, x2);
    x14 = _mm_shuffle_epi8(x14, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x10 = _mm_add_epi32(x10, x14);
    x6 = _mm_xor_si128(x6, x10);
    x3 = _mm_add_epi32(x3, x7);
    x15 = _mm_xor_si128(x15, x3);
    x15 = _mm_shuffle_epi8(x15, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x11 = _mm_add_epi32(x11, x15);
    x7 = _mm_xor_si128(x7, x11);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 48), x11);
    x11 = _mm_srli_epi32(x4, 25);
    x4 = _mm_slli_epi32(x4, 7);
    x4 = _mm_xor_si128(x4, x11);
    x11 = _mm_srli_epi32(x5, 25);
    x5 = _mm_slli_epi32(x5, 7);
    x5 = _mm_xor_si128(x5, x11);
    x11 = _mm_srli_epi32(x6, 25);
    x6 = _mm_slli_epi32(x6, 7);
    x6 = _mm_xor_si128(x6, x11);
    x11 = _mm_srli_epi32(x7, 25);
    x7 = _mm_slli_epi32(x7, 7);
    x7 = _mm_xor_si128(x7, x11);
    x0 = _mm_add_epi32(x0, x5);
    x15 = _mm_xor_si128(x15, x0);
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x15 = _mm_shuffle_epi8(x15, _mm_loadu_si128((const __m128i*)WC_PR(r13, 0)));
    x10 = _mm_add_epi32(x10, x15);
    x5 = _mm_xor_si128(x5, x10);
    x1 = _mm_add_epi32(x1, x6);
    x12 = _mm_xor_si128(x12, x1);
    x12 = _mm_shuffle_epi8(x12, _mm_loadu_si128((const __m128i*)WC_PR(r13, 0)));
    x11 = _mm_add_epi32(x11, x12);
    x6 = _mm_xor_si128(x6, x11);
    x2 = _mm_add_epi32(x2, x7);
    x13 = _mm_xor_si128(x13, x2);
    x13 = _mm_shuffle_epi8(x13, _mm_loadu_si128((const __m128i*)WC_PR(r13, 0)));
    x8 = _mm_add_epi32(x8, x13);
    x7 = _mm_xor_si128(x7, x8);
    x3 = _mm_add_epi32(x3, x4);
    x14 = _mm_xor_si128(x14, x3);
    x14 = _mm_shuffle_epi8(x14, _mm_loadu_si128((const __m128i*)WC_PR(r13, 0)));
    x9 = _mm_add_epi32(x9, x14);
    x4 = _mm_xor_si128(x4, x9);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 48), x11);
    x11 = _mm_srli_epi32(x5, 20);
    x5 = _mm_slli_epi32(x5, 12);
    x5 = _mm_xor_si128(x5, x11);
    x11 = _mm_srli_epi32(x6, 20);
    x6 = _mm_slli_epi32(x6, 12);
    x6 = _mm_xor_si128(x6, x11);
    x11 = _mm_srli_epi32(x7, 20);
    x7 = _mm_slli_epi32(x7, 12);
    x7 = _mm_xor_si128(x7, x11);
    x11 = _mm_srli_epi32(x4, 20);
    x4 = _mm_slli_epi32(x4, 12);
    x4 = _mm_xor_si128(x4, x11);
    x0 = _mm_add_epi32(x0, x5);
    x15 = _mm_xor_si128(x15, x0);
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x15 = _mm_shuffle_epi8(x15, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x10 = _mm_add_epi32(x10, x15);
    x5 = _mm_xor_si128(x5, x10);
    x1 = _mm_add_epi32(x1, x6);
    x12 = _mm_xor_si128(x12, x1);
    x12 = _mm_shuffle_epi8(x12, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x11 = _mm_add_epi32(x11, x12);
    x6 = _mm_xor_si128(x6, x11);
    x2 = _mm_add_epi32(x2, x7);
    x13 = _mm_xor_si128(x13, x2);
    x13 = _mm_shuffle_epi8(x13, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x8 = _mm_add_epi32(x8, x13);
    x7 = _mm_xor_si128(x7, x8);
    x3 = _mm_add_epi32(x3, x4);
    x14 = _mm_xor_si128(x14, x3);
    x14 = _mm_shuffle_epi8(x14, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x9 = _mm_add_epi32(x9, x14);
    x4 = _mm_xor_si128(x4, x9);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 48), x11);
    x11 = _mm_srli_epi32(x5, 25);
    x5 = _mm_slli_epi32(x5, 7);
    x5 = _mm_xor_si128(x5, x11);
    x11 = _mm_srli_epi32(x6, 25);
    x6 = _mm_slli_epi32(x6, 7);
    x6 = _mm_xor_si128(x6, x11);
    x11 = _mm_srli_epi32(x7, 25);
    x7 = _mm_slli_epi32(x7, 7);
    x7 = _mm_xor_si128(x7, x11);
    x11 = _mm_srli_epi32(x4, 25);
    x4 = _mm_slli_epi32(x4, 7);
    x4 = _mm_xor_si128(x4, x11);
    r8 = (r8 & ~(word64)0xff) | ((word64)(byte)((byte)r8 - 1) & 0xff);
    if (((byte)r8) != (0)) {
        goto L_chacha20_avx1_loop128;
    }
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x0 = _mm_add_epi32(x0, _mm_loadu_si128((const __m128i*)WC_PR(r9, 0)));
    x1 = _mm_add_epi32(x1, _mm_loadu_si128((const __m128i*)WC_PR(r9, 16)));
    x2 = _mm_add_epi32(x2, _mm_loadu_si128((const __m128i*)WC_PR(r9, 32)));
    x3 = _mm_add_epi32(x3, _mm_loadu_si128((const __m128i*)WC_PR(r9, 48)));
    x4 = _mm_add_epi32(x4, _mm_loadu_si128((const __m128i*)WC_PR(r9, 64)));
    x5 = _mm_add_epi32(x5, _mm_loadu_si128((const __m128i*)WC_PR(r9, 80)));
    x6 = _mm_add_epi32(x6, _mm_loadu_si128((const __m128i*)WC_PR(r9, 96)));
    x7 = _mm_add_epi32(x7, _mm_loadu_si128((const __m128i*)WC_PR(r9, 112)));
    x8 = _mm_add_epi32(x8, _mm_loadu_si128((const __m128i*)WC_PR(r9, 128)));
    x9 = _mm_add_epi32(x9, _mm_loadu_si128((const __m128i*)WC_PR(r9, 144)));
    x10 = _mm_add_epi32(x10, _mm_loadu_si128((const __m128i*)WC_PR(r9, 160)));
    x11 = _mm_add_epi32(x11, _mm_loadu_si128((const __m128i*)WC_PR(r9, 176)));
    x12 = _mm_add_epi32(x12, _mm_loadu_si128((const __m128i*)WC_PR(r9, 192)));
    x13 = _mm_add_epi32(x13, _mm_loadu_si128((const __m128i*)WC_PR(r9, 208)));
    x14 = _mm_add_epi32(x14, _mm_loadu_si128((const __m128i*)WC_PR(r9, 224)));
    x15 = _mm_add_epi32(x15, _mm_loadu_si128((const __m128i*)WC_PR(r9, 240)));
    _mm_storeu_si128((__m128i*)WC_PW(r10, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 16), x9);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 32), x10);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 48), x11);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 64), x12);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 80), x13);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 96), x14);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 112), x15);
    x8 = _mm_unpacklo_epi32(x0, x1);
    x9 = _mm_unpacklo_epi32(x2, x3);
    x12 = _mm_unpackhi_epi32(x0, x1);
    x13 = _mm_unpackhi_epi32(x2, x3);
    x10 = _mm_unpacklo_epi32(x4, x5);
    x11 = _mm_unpacklo_epi32(x6, x7);
    x14 = _mm_unpackhi_epi32(x4, x5);
    x15 = _mm_unpackhi_epi32(x6, x7);
    x0 = _mm_unpacklo_epi64(x8, x9);
    x1 = _mm_unpacklo_epi64(x10, x11);
    x2 = _mm_unpackhi_epi64(x8, x9);
    x3 = _mm_unpackhi_epi64(x10, x11);
    x4 = _mm_unpacklo_epi64(x12, x13);
    x5 = _mm_unpacklo_epi64(x14, x15);
    x6 = _mm_unpackhi_epi64(x12, x13);
    x7 = _mm_unpackhi_epi64(x14, x15);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 0));
    x9 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 16));
    x10 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 64));
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 80));
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 128));
    x13 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 144));
    x14 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 192));
    x15 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 208));
    x0 = _mm_xor_si128(x0, x8);
    x1 = _mm_xor_si128(x1, x9);
    x2 = _mm_xor_si128(x2, x10);
    x3 = _mm_xor_si128(x3, x11);
    x4 = _mm_xor_si128(x4, x12);
    x5 = _mm_xor_si128(x5, x13);
    x6 = _mm_xor_si128(x6, x14);
    x7 = _mm_xor_si128(x7, x15);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x0);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 16), x1);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 64), x2);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 80), x3);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 128), x4);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 144), x5);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 192), x6);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 208), x7);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 64));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 80));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 96));
    x7 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 112));
    x8 = _mm_unpacklo_epi32(x0, x1);
    x9 = _mm_unpacklo_epi32(x2, x3);
    x12 = _mm_unpackhi_epi32(x0, x1);
    x13 = _mm_unpackhi_epi32(x2, x3);
    x10 = _mm_unpacklo_epi32(x4, x5);
    x11 = _mm_unpacklo_epi32(x6, x7);
    x14 = _mm_unpackhi_epi32(x4, x5);
    x15 = _mm_unpackhi_epi32(x6, x7);
    x0 = _mm_unpacklo_epi64(x8, x9);
    x1 = _mm_unpacklo_epi64(x10, x11);
    x2 = _mm_unpackhi_epi64(x8, x9);
    x3 = _mm_unpackhi_epi64(x10, x11);
    x4 = _mm_unpacklo_epi64(x12, x13);
    x5 = _mm_unpacklo_epi64(x14, x15);
    x6 = _mm_unpackhi_epi64(x12, x13);
    x7 = _mm_unpackhi_epi64(x14, x15);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 32));
    x9 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 48));
    x10 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 96));
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 112));
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 160));
    x13 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 176));
    x14 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 224));
    x15 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 240));
    x0 = _mm_xor_si128(x0, x8);
    x1 = _mm_xor_si128(x1, x9);
    x2 = _mm_xor_si128(x2, x10);
    x3 = _mm_xor_si128(x3, x11);
    x4 = _mm_xor_si128(x4, x12);
    x5 = _mm_xor_si128(x5, x13);
    x6 = _mm_xor_si128(x6, x14);
    x7 = _mm_xor_si128(x7, x15);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 32), x0);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 48), x1);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 96), x2);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 112), x3);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 160), x4);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 176), x5);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 224), x6);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 240), x7);
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 192));
    rsi = (word64)(rsi + 0x100);
    rdx = (word64)(rdx + 0x100);
    x12 = _mm_add_epi32(x12, _mm_loadu_si128((const __m128i*)WC_PR(r15, 0)));
    rcx = (word32)((word32)rcx - 0x100);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 192), x12);
    if (((word32)rcx) < (0x100)) {
        goto L_chacha20_avx1_done128;
    }
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 16));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 48));
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 64));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 80));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 96));
    x7 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 112));
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 128));
    x9 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 144));
    x10 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 160));
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 176));
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 192));
    x13 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 208));
    x14 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 224));
    x15 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 240));
    goto L_chacha20_avx1_start128;
L_chacha20_avx1_done128:
    rax = (word32)((word32)rax << 2);
    WC_S32(rdi, 48) = (word32)(WC_L32(rdi, 48) + (word32)rax);
L_chacha20_avx1_end128:
    if (((word32)rcx) < (0x40)) {
        goto L_chacha20_avx1_block_done;
    }
L_chacha20_avx1_block_start:
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 16));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 48));
    x5 = x0;
    x6 = x1;
    x7 = x2;
    x8 = x3;
    rax = (rax & ~(word64)0xff) | ((word64)(byte)(0xa) & 0xff);
L_chacha20_avx1_block_crypt_start:
    x0 = _mm_add_epi32(x0, x1);
    x3 = _mm_xor_si128(x3, x0);
    x3 = _mm_shuffle_epi8(x3, _mm_loadu_si128((const __m128i*)WC_PR(r13, 0)));
    x2 = _mm_add_epi32(x2, x3);
    x1 = _mm_xor_si128(x1, x2);
    x4 = _mm_srli_epi32(x1, 20);
    x1 = _mm_slli_epi32(x1, 12);
    x1 = _mm_xor_si128(x1, x4);
    x0 = _mm_add_epi32(x0, x1);
    x3 = _mm_xor_si128(x3, x0);
    x3 = _mm_shuffle_epi8(x3, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x2 = _mm_add_epi32(x2, x3);
    x1 = _mm_xor_si128(x1, x2);
    x4 = _mm_srli_epi32(x1, 25);
    x1 = _mm_slli_epi32(x1, 7);
    x1 = _mm_xor_si128(x1, x4);
    x1 = _mm_shuffle_epi32(x1, 0x39);
    x2 = _mm_shuffle_epi32(x2, 0x4e);
    x3 = _mm_shuffle_epi32(x3, 0x93);
    x0 = _mm_add_epi32(x0, x1);
    x3 = _mm_xor_si128(x3, x0);
    x3 = _mm_shuffle_epi8(x3, _mm_loadu_si128((const __m128i*)WC_PR(r13, 0)));
    x2 = _mm_add_epi32(x2, x3);
    x1 = _mm_xor_si128(x1, x2);
    x4 = _mm_srli_epi32(x1, 20);
    x1 = _mm_slli_epi32(x1, 12);
    x1 = _mm_xor_si128(x1, x4);
    x0 = _mm_add_epi32(x0, x1);
    x3 = _mm_xor_si128(x3, x0);
    x3 = _mm_shuffle_epi8(x3, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x2 = _mm_add_epi32(x2, x3);
    x1 = _mm_xor_si128(x1, x2);
    x4 = _mm_srli_epi32(x1, 25);
    x1 = _mm_slli_epi32(x1, 7);
    x1 = _mm_xor_si128(x1, x4);
    x1 = _mm_shuffle_epi32(x1, 0x93);
    x2 = _mm_shuffle_epi32(x2, 0x4e);
    x3 = _mm_shuffle_epi32(x3, 0x39);
    rax = (rax & ~(word64)0xff) | ((word64)(byte)((byte)rax - 1) & 0xff);
    if (((byte)rax) != (0)) {
        goto L_chacha20_avx1_block_crypt_start;
    }
    x0 = _mm_add_epi32(x0, x5);
    x1 = _mm_add_epi32(x1, x6);
    x2 = _mm_add_epi32(x2, x7);
    x3 = _mm_add_epi32(x3, x8);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 0));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 16));
    x7 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 32));
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 48));
    x0 = _mm_xor_si128(x0, x5);
    x1 = _mm_xor_si128(x1, x6);
    x2 = _mm_xor_si128(x2, x7);
    x3 = _mm_xor_si128(x3, x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x0);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 16), x1);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 32), x2);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 48), x3);
    WC_S32(rdi, 48) = (word32)(WC_L32(rdi, 48) + 1);
    rcx = (word32)((word32)rcx - 0x40);
    rsi = (word64)(rsi + 0x40);
    rdx = (word64)(rdx + 0x40);
    if (((word32)rcx) >= (0x40)) {
        goto L_chacha20_avx1_block_start;
    }
L_chacha20_avx1_block_done:
    if (((word32)rcx) == (0)) {
        goto L_chacha20_avx1_partial_done;
    }
    r10 = (word64)(rdi + 80);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 16));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 48));
    x5 = x0;
    x6 = x1;
    x7 = x2;
    x8 = x3;
    rax = (rax & ~(word64)0xff) | ((word64)(byte)(0xa) & 0xff);
L_chacha20_avx1_partial_crypt_start:
    x0 = _mm_add_epi32(x0, x1);
    x3 = _mm_xor_si128(x3, x0);
    x3 = _mm_shuffle_epi8(x3, _mm_loadu_si128((const __m128i*)WC_PR(r13, 0)));
    x2 = _mm_add_epi32(x2, x3);
    x1 = _mm_xor_si128(x1, x2);
    x4 = _mm_srli_epi32(x1, 20);
    x1 = _mm_slli_epi32(x1, 12);
    x1 = _mm_xor_si128(x1, x4);
    x0 = _mm_add_epi32(x0, x1);
    x3 = _mm_xor_si128(x3, x0);
    x3 = _mm_shuffle_epi8(x3, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x2 = _mm_add_epi32(x2, x3);
    x1 = _mm_xor_si128(x1, x2);
    x4 = _mm_srli_epi32(x1, 25);
    x1 = _mm_slli_epi32(x1, 7);
    x1 = _mm_xor_si128(x1, x4);
    x1 = _mm_shuffle_epi32(x1, 0x39);
    x2 = _mm_shuffle_epi32(x2, 0x4e);
    x3 = _mm_shuffle_epi32(x3, 0x93);
    x0 = _mm_add_epi32(x0, x1);
    x3 = _mm_xor_si128(x3, x0);
    x3 = _mm_shuffle_epi8(x3, _mm_loadu_si128((const __m128i*)WC_PR(r13, 0)));
    x2 = _mm_add_epi32(x2, x3);
    x1 = _mm_xor_si128(x1, x2);
    x4 = _mm_srli_epi32(x1, 20);
    x1 = _mm_slli_epi32(x1, 12);
    x1 = _mm_xor_si128(x1, x4);
    x0 = _mm_add_epi32(x0, x1);
    x3 = _mm_xor_si128(x3, x0);
    x3 = _mm_shuffle_epi8(x3, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    x2 = _mm_add_epi32(x2, x3);
    x1 = _mm_xor_si128(x1, x2);
    x4 = _mm_srli_epi32(x1, 25);
    x1 = _mm_slli_epi32(x1, 7);
    x1 = _mm_xor_si128(x1, x4);
    x1 = _mm_shuffle_epi32(x1, 0x93);
    x2 = _mm_shuffle_epi32(x2, 0x4e);
    x3 = _mm_shuffle_epi32(x3, 0x39);
    rax = (rax & ~(word64)0xff) | ((word64)(byte)((byte)rax - 1) & 0xff);
    if (((byte)rax) != (0)) {
        goto L_chacha20_avx1_partial_crypt_start;
    }
    x0 = _mm_add_epi32(x0, x5);
    x1 = _mm_add_epi32(x1, x6);
    x2 = _mm_add_epi32(x2, x7);
    x3 = _mm_add_epi32(x3, x8);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 0), x0);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 16), x1);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 32), x2);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 48), x3);
    WC_S32(rdi, 48) = (word32)(WC_L32(rdi, 48) + 1);
    r8 = (word32)((word32)rcx);
    r11 = (word64)(0);
    r8 = (word32)((word32)r8 & 7);
    if (((word32)r8) == (0)) {
        goto L_chacha20_avx1_partial_start64;
    }
L_chacha20_avx1_partial_start8:
    rax = (word32)((word32)WC_L8(r10, r11));
    rax = (rax & ~(word64)0xff) | ((word64)(byte)((byte)rax ^ WC_L8(rsi,
        r11)) & 0xff);
    WC_S8(rdx, r11) = (byte)((byte)rax);
    r11 = (word32)((word32)r11 + 1);
    zf1 = (word32)r11;
    zf2 = (word32)r8;
    if (((word32)r11) != ((word32)r8)) {
        goto L_chacha20_avx1_partial_start8;
    }
    if ((zf1) == (zf2)) {
        goto L_chacha20_avx1_partial_end64;
    }
L_chacha20_avx1_partial_start64:
    rax = (word64)(WC_L64(r10, r11));
    rax = (word64)(rax ^ WC_L64(rsi, r11));
    WC_S64(rdx, r11) = (word64)(rax);
    r11 = (word32)((word32)r11 + 8);
L_chacha20_avx1_partial_end64:
    if (((word32)r11) != ((word32)rcx)) {
        goto L_chacha20_avx1_partial_start64;
    }
    r8 = (word32)(0x40);
    r8 = (word32)((word32)r8 - (word32)r11);
    WC_S32(rdi, 76) = (word32)((word32)r8);
L_chacha20_avx1_partial_done:
    ;
}

#endif /* HAVE_INTEL_AVX1 */
#ifdef HAVE_INTEL_AVX2
XALIGNED(32) static const word64 L_chacha20_avx2_rotl8[] WC_X64I_UNUSED = {
    0x0605040702010003ULL, 0x0e0d0c0f0a09080bULL,
    0x0605040702010003ULL, 0x0e0d0c0f0a09080bULL,
};

XALIGNED(32) static const word64 L_chacha20_avx2_rotl16[] WC_X64I_UNUSED = {
    0x0504070601000302ULL, 0x0d0c0f0e09080b0aULL,
    0x0504070601000302ULL, 0x0d0c0f0e09080b0aULL,
};

XALIGNED(32) static const word64 L_chacha20_avx2_add[] WC_X64I_UNUSED = {
    0x0000000100000000ULL, 0x0000000300000002ULL,
    0x0000000500000004ULL, 0x0000000700000006ULL,
};

XALIGNED(32) static const word64 L_chacha20_avx2_eight[] WC_X64I_UNUSED = {
    0x0000000800000008ULL, 0x0000000800000008ULL,
    0x0000000800000008ULL, 0x0000000800000008ULL,
};

WC_X64I_TARGET("avx2")
WOLFSSL_LOCAL void chacha_encrypt_avx2(ChaCha* ctx, const byte* m, byte* c,
    word32 bytes)
{
    word64 rdi, rsi, rdx, rcx, rsp, r9, r11, r12, r13, r14, r10, rax, r8 = 0;
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y4 = _mm256_setzero_si256(), y5 = _mm256_setzero_si256(),
            y6 = _mm256_setzero_si256(), y7 = _mm256_setzero_si256(),
            y8 = _mm256_setzero_si256(), y9 = _mm256_setzero_si256(),
            y10 = _mm256_setzero_si256(), y11 = _mm256_setzero_si256(),
            y12 = _mm256_setzero_si256(), y13 = _mm256_setzero_si256(),
            y14 = _mm256_setzero_si256(), y15 = _mm256_setzero_si256();
    XALIGNED(32) WC_X64I_SLOT stk[100];

    rdi = (word64)(size_t)ctx;
    rsi = (word64)(size_t)m;
    rdx = (word64)(size_t)c;
    rcx = (word64)(word32)bytes;

    rsp = (word64)(size_t)stk + 800;
    rsp = (word64)(rsp - 800);
    r9 = (word64)(rsp);
    r11 = (word64)((word64)(size_t)L_chacha20_avx2_rotl8);
    r12 = (word64)((word64)(size_t)L_chacha20_avx2_rotl16);
    r13 = (word64)((word64)(size_t)L_chacha20_avx2_add);
    r14 = (word64)((word64)(size_t)L_chacha20_avx2_eight);
    r10 = (word64)(rsp + 512);
    r9 = (word64)(r9 + 0x1f);
    r10 = (word64)(r10 + 0x1f);
    r9 = (word64)(r9 & -32);
    r10 = (word64)(r10 & -32);
    rax = (word32)((word32)rcx);
    rax = (word32)((word32)rax >> 9);
    if (((word32)rax) == (0)) {
        goto L_chacha20_avx2_end256;
    }
    y0 = _mm256_set1_epi32((int)WC_L32(rdi, 0));
    y1 = _mm256_set1_epi32((int)WC_L32(rdi, 4));
    y2 = _mm256_set1_epi32((int)WC_L32(rdi, 8));
    y3 = _mm256_set1_epi32((int)WC_L32(rdi, 12));
    y4 = _mm256_set1_epi32((int)WC_L32(rdi, 16));
    y5 = _mm256_set1_epi32((int)WC_L32(rdi, 20));
    y6 = _mm256_set1_epi32((int)WC_L32(rdi, 24));
    y7 = _mm256_set1_epi32((int)WC_L32(rdi, 28));
    y8 = _mm256_set1_epi32((int)WC_L32(rdi, 32));
    y9 = _mm256_set1_epi32((int)WC_L32(rdi, 36));
    y10 = _mm256_set1_epi32((int)WC_L32(rdi, 40));
    y11 = _mm256_set1_epi32((int)WC_L32(rdi, 44));
    y12 = _mm256_set1_epi32((int)WC_L32(rdi, 48));
    y13 = _mm256_set1_epi32((int)WC_L32(rdi, 52));
    y14 = _mm256_set1_epi32((int)WC_L32(rdi, 56));
    y15 = _mm256_set1_epi32((int)WC_L32(rdi, 60));
    y12 = _mm256_add_epi32(y12, _mm256_loadu_si256((const __m256i*)WC_PR(r13,
        0)));
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 0), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 32), y1);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 64), y2);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 96), y3);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 128), y4);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 160), y5);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 192), y6);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 224), y7);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 256), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 288), y9);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 320), y10);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 352), y11);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 384), y12);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 416), y13);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 448), y14);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 480), y15);
L_chacha20_avx2_start256:
    r8 = (r8 & ~(word64)0xff) | ((word64)(byte)(0xa) & 0xff);
    _mm256_storeu_si256((__m256i*)WC_PW(r10, 96), y11);
L_chacha20_avx2_loop256:
    y0 = _mm256_add_epi32(y0, y4);
    y12 = _mm256_xor_si256(y12, y0);
    y11 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 96));
    y12 = _mm256_shuffle_epi8(y12, _mm256_loadu_si256((const __m256i*)WC_PR(r12,
        0)));
    y8 = _mm256_add_epi32(y8, y12);
    y4 = _mm256_xor_si256(y4, y8);
    y1 = _mm256_add_epi32(y1, y5);
    y13 = _mm256_xor_si256(y13, y1);
    y13 = _mm256_shuffle_epi8(y13, _mm256_loadu_si256((const __m256i*)WC_PR(r12,
        0)));
    y9 = _mm256_add_epi32(y9, y13);
    y5 = _mm256_xor_si256(y5, y9);
    y2 = _mm256_add_epi32(y2, y6);
    y14 = _mm256_xor_si256(y14, y2);
    y14 = _mm256_shuffle_epi8(y14, _mm256_loadu_si256((const __m256i*)WC_PR(r12,
        0)));
    y10 = _mm256_add_epi32(y10, y14);
    y6 = _mm256_xor_si256(y6, y10);
    y3 = _mm256_add_epi32(y3, y7);
    y15 = _mm256_xor_si256(y15, y3);
    y15 = _mm256_shuffle_epi8(y15, _mm256_loadu_si256((const __m256i*)WC_PR(r12,
        0)));
    y11 = _mm256_add_epi32(y11, y15);
    y7 = _mm256_xor_si256(y7, y11);
    _mm256_storeu_si256((__m256i*)WC_PW(r10, 96), y11);
    y11 = _mm256_srli_epi32(y4, 20);
    y4 = _mm256_slli_epi32(y4, 12);
    y4 = _mm256_xor_si256(y4, y11);
    y11 = _mm256_srli_epi32(y5, 20);
    y5 = _mm256_slli_epi32(y5, 12);
    y5 = _mm256_xor_si256(y5, y11);
    y11 = _mm256_srli_epi32(y6, 20);
    y6 = _mm256_slli_epi32(y6, 12);
    y6 = _mm256_xor_si256(y6, y11);
    y11 = _mm256_srli_epi32(y7, 20);
    y7 = _mm256_slli_epi32(y7, 12);
    y7 = _mm256_xor_si256(y7, y11);
    y0 = _mm256_add_epi32(y0, y4);
    y12 = _mm256_xor_si256(y12, y0);
    y11 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 96));
    y12 = _mm256_shuffle_epi8(y12, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        0)));
    y8 = _mm256_add_epi32(y8, y12);
    y4 = _mm256_xor_si256(y4, y8);
    y1 = _mm256_add_epi32(y1, y5);
    y13 = _mm256_xor_si256(y13, y1);
    y13 = _mm256_shuffle_epi8(y13, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        0)));
    y9 = _mm256_add_epi32(y9, y13);
    y5 = _mm256_xor_si256(y5, y9);
    y2 = _mm256_add_epi32(y2, y6);
    y14 = _mm256_xor_si256(y14, y2);
    y14 = _mm256_shuffle_epi8(y14, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        0)));
    y10 = _mm256_add_epi32(y10, y14);
    y6 = _mm256_xor_si256(y6, y10);
    y3 = _mm256_add_epi32(y3, y7);
    y15 = _mm256_xor_si256(y15, y3);
    y15 = _mm256_shuffle_epi8(y15, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        0)));
    y11 = _mm256_add_epi32(y11, y15);
    y7 = _mm256_xor_si256(y7, y11);
    _mm256_storeu_si256((__m256i*)WC_PW(r10, 96), y11);
    y11 = _mm256_srli_epi32(y4, 25);
    y4 = _mm256_slli_epi32(y4, 7);
    y4 = _mm256_xor_si256(y4, y11);
    y11 = _mm256_srli_epi32(y5, 25);
    y5 = _mm256_slli_epi32(y5, 7);
    y5 = _mm256_xor_si256(y5, y11);
    y11 = _mm256_srli_epi32(y6, 25);
    y6 = _mm256_slli_epi32(y6, 7);
    y6 = _mm256_xor_si256(y6, y11);
    y11 = _mm256_srli_epi32(y7, 25);
    y7 = _mm256_slli_epi32(y7, 7);
    y7 = _mm256_xor_si256(y7, y11);
    y0 = _mm256_add_epi32(y0, y5);
    y15 = _mm256_xor_si256(y15, y0);
    y11 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 96));
    y15 = _mm256_shuffle_epi8(y15, _mm256_loadu_si256((const __m256i*)WC_PR(r12,
        0)));
    y10 = _mm256_add_epi32(y10, y15);
    y5 = _mm256_xor_si256(y5, y10);
    y1 = _mm256_add_epi32(y1, y6);
    y12 = _mm256_xor_si256(y12, y1);
    y12 = _mm256_shuffle_epi8(y12, _mm256_loadu_si256((const __m256i*)WC_PR(r12,
        0)));
    y11 = _mm256_add_epi32(y11, y12);
    y6 = _mm256_xor_si256(y6, y11);
    y2 = _mm256_add_epi32(y2, y7);
    y13 = _mm256_xor_si256(y13, y2);
    y13 = _mm256_shuffle_epi8(y13, _mm256_loadu_si256((const __m256i*)WC_PR(r12,
        0)));
    y8 = _mm256_add_epi32(y8, y13);
    y7 = _mm256_xor_si256(y7, y8);
    y3 = _mm256_add_epi32(y3, y4);
    y14 = _mm256_xor_si256(y14, y3);
    y14 = _mm256_shuffle_epi8(y14, _mm256_loadu_si256((const __m256i*)WC_PR(r12,
        0)));
    y9 = _mm256_add_epi32(y9, y14);
    y4 = _mm256_xor_si256(y4, y9);
    _mm256_storeu_si256((__m256i*)WC_PW(r10, 96), y11);
    y11 = _mm256_srli_epi32(y5, 20);
    y5 = _mm256_slli_epi32(y5, 12);
    y5 = _mm256_xor_si256(y5, y11);
    y11 = _mm256_srli_epi32(y6, 20);
    y6 = _mm256_slli_epi32(y6, 12);
    y6 = _mm256_xor_si256(y6, y11);
    y11 = _mm256_srli_epi32(y7, 20);
    y7 = _mm256_slli_epi32(y7, 12);
    y7 = _mm256_xor_si256(y7, y11);
    y11 = _mm256_srli_epi32(y4, 20);
    y4 = _mm256_slli_epi32(y4, 12);
    y4 = _mm256_xor_si256(y4, y11);
    y0 = _mm256_add_epi32(y0, y5);
    y15 = _mm256_xor_si256(y15, y0);
    y11 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 96));
    y15 = _mm256_shuffle_epi8(y15, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        0)));
    y10 = _mm256_add_epi32(y10, y15);
    y5 = _mm256_xor_si256(y5, y10);
    y1 = _mm256_add_epi32(y1, y6);
    y12 = _mm256_xor_si256(y12, y1);
    y12 = _mm256_shuffle_epi8(y12, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        0)));
    y11 = _mm256_add_epi32(y11, y12);
    y6 = _mm256_xor_si256(y6, y11);
    y2 = _mm256_add_epi32(y2, y7);
    y13 = _mm256_xor_si256(y13, y2);
    y13 = _mm256_shuffle_epi8(y13, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        0)));
    y8 = _mm256_add_epi32(y8, y13);
    y7 = _mm256_xor_si256(y7, y8);
    y3 = _mm256_add_epi32(y3, y4);
    y14 = _mm256_xor_si256(y14, y3);
    y14 = _mm256_shuffle_epi8(y14, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        0)));
    y9 = _mm256_add_epi32(y9, y14);
    y4 = _mm256_xor_si256(y4, y9);
    _mm256_storeu_si256((__m256i*)WC_PW(r10, 96), y11);
    y11 = _mm256_srli_epi32(y5, 25);
    y5 = _mm256_slli_epi32(y5, 7);
    y5 = _mm256_xor_si256(y5, y11);
    y11 = _mm256_srli_epi32(y6, 25);
    y6 = _mm256_slli_epi32(y6, 7);
    y6 = _mm256_xor_si256(y6, y11);
    y11 = _mm256_srli_epi32(y7, 25);
    y7 = _mm256_slli_epi32(y7, 7);
    y7 = _mm256_xor_si256(y7, y11);
    y11 = _mm256_srli_epi32(y4, 25);
    y4 = _mm256_slli_epi32(y4, 7);
    y4 = _mm256_xor_si256(y4, y11);
    r8 = (r8 & ~(word64)0xff) | ((word64)(byte)((byte)r8 - 1) & 0xff);
    if (((byte)r8) != (0)) {
        goto L_chacha20_avx2_loop256;
    }
    y11 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 96));
    y0 = _mm256_add_epi32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(r9, 0)));
    y1 = _mm256_add_epi32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(r9,
        32)));
    y2 = _mm256_add_epi32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(r9,
        64)));
    y3 = _mm256_add_epi32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(r9,
        96)));
    y4 = _mm256_add_epi32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(r9,
        128)));
    y5 = _mm256_add_epi32(y5, _mm256_loadu_si256((const __m256i*)WC_PR(r9,
        160)));
    y6 = _mm256_add_epi32(y6, _mm256_loadu_si256((const __m256i*)WC_PR(r9,
        192)));
    y7 = _mm256_add_epi32(y7, _mm256_loadu_si256((const __m256i*)WC_PR(r9,
        224)));
    y8 = _mm256_add_epi32(y8, _mm256_loadu_si256((const __m256i*)WC_PR(r9,
        256)));
    y9 = _mm256_add_epi32(y9, _mm256_loadu_si256((const __m256i*)WC_PR(r9,
        288)));
    y10 = _mm256_add_epi32(y10, _mm256_loadu_si256((const __m256i*)WC_PR(r9,
        320)));
    y11 = _mm256_add_epi32(y11, _mm256_loadu_si256((const __m256i*)WC_PR(r9,
        352)));
    y12 = _mm256_add_epi32(y12, _mm256_loadu_si256((const __m256i*)WC_PR(r9,
        384)));
    y13 = _mm256_add_epi32(y13, _mm256_loadu_si256((const __m256i*)WC_PR(r9,
        416)));
    y14 = _mm256_add_epi32(y14, _mm256_loadu_si256((const __m256i*)WC_PR(r9,
        448)));
    y15 = _mm256_add_epi32(y15, _mm256_loadu_si256((const __m256i*)WC_PR(r9,
        480)));
    _mm256_storeu_si256((__m256i*)WC_PW(r10, 0), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(r10, 32), y9);
    _mm256_storeu_si256((__m256i*)WC_PW(r10, 64), y10);
    _mm256_storeu_si256((__m256i*)WC_PW(r10, 96), y11);
    _mm256_storeu_si256((__m256i*)WC_PW(r10, 128), y12);
    _mm256_storeu_si256((__m256i*)WC_PW(r10, 160), y13);
    _mm256_storeu_si256((__m256i*)WC_PW(r10, 192), y14);
    _mm256_storeu_si256((__m256i*)WC_PW(r10, 224), y15);
    y8 = _mm256_unpacklo_epi32(y0, y1);
    y9 = _mm256_unpacklo_epi32(y2, y3);
    y12 = _mm256_unpackhi_epi32(y0, y1);
    y13 = _mm256_unpackhi_epi32(y2, y3);
    y10 = _mm256_unpacklo_epi32(y4, y5);
    y11 = _mm256_unpacklo_epi32(y6, y7);
    y14 = _mm256_unpackhi_epi32(y4, y5);
    y15 = _mm256_unpackhi_epi32(y6, y7);
    y0 = _mm256_unpacklo_epi64(y8, y9);
    y1 = _mm256_unpacklo_epi64(y10, y11);
    y2 = _mm256_unpackhi_epi64(y8, y9);
    y3 = _mm256_unpackhi_epi64(y10, y11);
    y4 = _mm256_unpacklo_epi64(y12, y13);
    y5 = _mm256_unpacklo_epi64(y14, y15);
    y6 = _mm256_unpackhi_epi64(y12, y13);
    y7 = _mm256_unpackhi_epi64(y14, y15);
    y8 = _mm256_permute2x128_si256(y0, y1, 0x20);
    y9 = _mm256_permute2x128_si256(y2, y3, 0x20);
    y12 = _mm256_permute2x128_si256(y0, y1, 0x31);
    y13 = _mm256_permute2x128_si256(y2, y3, 0x31);
    y10 = _mm256_permute2x128_si256(y4, y5, 0x20);
    y11 = _mm256_permute2x128_si256(y6, y7, 0x20);
    y14 = _mm256_permute2x128_si256(y4, y5, 0x31);
    y15 = _mm256_permute2x128_si256(y6, y7, 0x31);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 64));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 128));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 192));
    y4 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 256));
    y5 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 320));
    y6 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 384));
    y7 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 448));
    y8 = _mm256_xor_si256(y8, y0);
    y9 = _mm256_xor_si256(y9, y1);
    y10 = _mm256_xor_si256(y10, y2);
    y11 = _mm256_xor_si256(y11, y3);
    y12 = _mm256_xor_si256(y12, y4);
    y13 = _mm256_xor_si256(y13, y5);
    y14 = _mm256_xor_si256(y14, y6);
    y15 = _mm256_xor_si256(y15, y7);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 0), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 64), y9);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 128), y10);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 192), y11);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 256), y12);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 320), y13);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 384), y14);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 448), y15);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 32));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 64));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 96));
    y4 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 128));
    y5 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 160));
    y6 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 192));
    y7 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 224));
    y8 = _mm256_unpacklo_epi32(y0, y1);
    y9 = _mm256_unpacklo_epi32(y2, y3);
    y12 = _mm256_unpackhi_epi32(y0, y1);
    y13 = _mm256_unpackhi_epi32(y2, y3);
    y10 = _mm256_unpacklo_epi32(y4, y5);
    y11 = _mm256_unpacklo_epi32(y6, y7);
    y14 = _mm256_unpackhi_epi32(y4, y5);
    y15 = _mm256_unpackhi_epi32(y6, y7);
    y0 = _mm256_unpacklo_epi64(y8, y9);
    y1 = _mm256_unpacklo_epi64(y10, y11);
    y2 = _mm256_unpackhi_epi64(y8, y9);
    y3 = _mm256_unpackhi_epi64(y10, y11);
    y4 = _mm256_unpacklo_epi64(y12, y13);
    y5 = _mm256_unpacklo_epi64(y14, y15);
    y6 = _mm256_unpackhi_epi64(y12, y13);
    y7 = _mm256_unpackhi_epi64(y14, y15);
    y8 = _mm256_permute2x128_si256(y0, y1, 0x20);
    y9 = _mm256_permute2x128_si256(y2, y3, 0x20);
    y12 = _mm256_permute2x128_si256(y0, y1, 0x31);
    y13 = _mm256_permute2x128_si256(y2, y3, 0x31);
    y10 = _mm256_permute2x128_si256(y4, y5, 0x20);
    y11 = _mm256_permute2x128_si256(y6, y7, 0x20);
    y14 = _mm256_permute2x128_si256(y4, y5, 0x31);
    y15 = _mm256_permute2x128_si256(y6, y7, 0x31);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 32));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 96));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 160));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 224));
    y4 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 288));
    y5 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 352));
    y6 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 416));
    y7 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 480));
    y8 = _mm256_xor_si256(y8, y0);
    y9 = _mm256_xor_si256(y9, y1);
    y10 = _mm256_xor_si256(y10, y2);
    y11 = _mm256_xor_si256(y11, y3);
    y12 = _mm256_xor_si256(y12, y4);
    y13 = _mm256_xor_si256(y13, y5);
    y14 = _mm256_xor_si256(y14, y6);
    y15 = _mm256_xor_si256(y15, y7);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 32), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 96), y9);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 160), y10);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 224), y11);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 288), y12);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 352), y13);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 416), y14);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 480), y15);
    y12 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 384));
    rsi = (word64)(rsi + 0x200);
    rdx = (word64)(rdx + 0x200);
    y12 = _mm256_add_epi32(y12, _mm256_loadu_si256((const __m256i*)WC_PR(r14,
        0)));
    rcx = (word32)((word32)rcx - 0x200);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 384), y12);
    if (((word32)rcx) < (0x200)) {
        goto L_chacha20_avx2_done256;
    }
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 32));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 64));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 96));
    y4 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 128));
    y5 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 160));
    y6 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 192));
    y7 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 224));
    y8 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 256));
    y9 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 288));
    y10 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 320));
    y11 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 352));
    y12 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 384));
    y13 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 416));
    y14 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 448));
    y15 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 480));
    goto L_chacha20_avx2_start256;
L_chacha20_avx2_done256:
    rax = (word32)((word32)rax << 3);
    WC_S32(rdi, 48) = (word32)(WC_L32(rdi, 48) + (word32)rax);
L_chacha20_avx2_end256:
    (void)chacha_encrypt_avx1((ChaCha*)(size_t)rdi, (const byte*)(size_t)rsi, (
        byte*)(size_t)rdx, (word32)rcx);
}

#endif /* HAVE_INTEL_AVX2 */
#ifdef HAVE_INTEL_AVX512
XALIGNED(16) static const word64 L_chacha20_avx512vl_add[] WC_X64I_UNUSED = {
    0x0000000100000000ULL, 0x0000000300000002ULL,
};

XALIGNED(16) static const word64 L_chacha20_avx512vl_four[] WC_X64I_UNUSED = {
    0x0000000400000004ULL, 0x0000000400000004ULL,
};

WC_X64I_TARGET("avx512f,avx512vl")
WOLFSSL_LOCAL void chacha_encrypt_avx512vl(ChaCha* ctx, const byte* m, byte* c,
    word32 bytes)
{
    word64 rdi, rsi, rdx, rcx, rsp, r9, r10, r12, r13, rax, r8 = 0, r11 = 0;
    __m128i x0 = _mm_setzero_si128(), x1 = _mm_setzero_si128(),
            x2 = _mm_setzero_si128(), x3 = _mm_setzero_si128(),
            x4 = _mm_setzero_si128(), x5 = _mm_setzero_si128(),
            x6 = _mm_setzero_si128(), x7 = _mm_setzero_si128(),
            x8 = _mm_setzero_si128(), x9 = _mm_setzero_si128(),
            x10 = _mm_setzero_si128(), x11 = _mm_setzero_si128(),
            x12 = _mm_setzero_si128(), x13 = _mm_setzero_si128(),
            x14 = _mm_setzero_si128(), x15 = _mm_setzero_si128();
    XALIGNED(32) WC_X64I_SLOT stk[52];
    word32 zf1;
    word32 zf2;

    rdi = (word64)(size_t)ctx;
    rsi = (word64)(size_t)m;
    rdx = (word64)(size_t)c;
    rcx = (word64)(word32)bytes;

    rsp = (word64)(size_t)stk + 416;
    rsp = (word64)(rsp - 400);
    r9 = (word64)(rsp);
    r10 = (word64)(rsp + 256);
    r12 = (word64)((word64)(size_t)L_chacha20_avx512vl_add);
    r13 = (word64)((word64)(size_t)L_chacha20_avx512vl_four);
    r9 = (word64)(r9 + 0xf);
    r10 = (word64)(r10 + 0xf);
    r9 = (word64)(r9 & -16);
    r10 = (word64)(r10 & -16);
    rax = (word32)((word32)rcx);
    rax = (word32)((word32)rax >> 8);
    if (((word32)rax) == (0)) {
        goto L_chacha20_avx512vl_end128;
    }
    x0 = _mm_set1_epi32((int)WC_L32(rdi, 0));
    x1 = _mm_set1_epi32((int)WC_L32(rdi, 4));
    x2 = _mm_set1_epi32((int)WC_L32(rdi, 8));
    x3 = _mm_set1_epi32((int)WC_L32(rdi, 12));
    x4 = _mm_set1_epi32((int)WC_L32(rdi, 16));
    x5 = _mm_set1_epi32((int)WC_L32(rdi, 20));
    x6 = _mm_set1_epi32((int)WC_L32(rdi, 24));
    x7 = _mm_set1_epi32((int)WC_L32(rdi, 28));
    x8 = _mm_set1_epi32((int)WC_L32(rdi, 32));
    x9 = _mm_set1_epi32((int)WC_L32(rdi, 36));
    x10 = _mm_set1_epi32((int)WC_L32(rdi, 40));
    x11 = _mm_set1_epi32((int)WC_L32(rdi, 44));
    x12 = _mm_set1_epi32((int)WC_L32(rdi, 48));
    x13 = _mm_set1_epi32((int)WC_L32(rdi, 52));
    x14 = _mm_set1_epi32((int)WC_L32(rdi, 56));
    x15 = _mm_set1_epi32((int)WC_L32(rdi, 60));
    x12 = _mm_add_epi32(x12, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    _mm_storeu_si128((__m128i*)WC_PW(r9, 0), x0);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 16), x1);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 32), x2);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 48), x3);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 64), x4);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 80), x5);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 96), x6);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 112), x7);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 128), x8);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 144), x9);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 160), x10);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 176), x11);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 192), x12);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 208), x13);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 224), x14);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 240), x15);
L_chacha20_avx512vl_start128:
    r8 = (r8 & ~(word64)0xff) | ((word64)(byte)(0xa) & 0xff);
L_chacha20_avx512vl_loop128:
    x0 = _mm_add_epi32(x0, x4);
    x1 = _mm_add_epi32(x1, x5);
    x2 = _mm_add_epi32(x2, x6);
    x3 = _mm_add_epi32(x3, x7);
    x12 = _mm_xor_si128(x12, x0);
    x13 = _mm_xor_si128(x13, x1);
    x14 = _mm_xor_si128(x14, x2);
    x15 = _mm_xor_si128(x15, x3);
    x12 = _mm_rol_epi32(x12, 16);
    x13 = _mm_rol_epi32(x13, 16);
    x14 = _mm_rol_epi32(x14, 16);
    x15 = _mm_rol_epi32(x15, 16);
    x8 = _mm_add_epi32(x8, x12);
    x9 = _mm_add_epi32(x9, x13);
    x10 = _mm_add_epi32(x10, x14);
    x11 = _mm_add_epi32(x11, x15);
    x4 = _mm_xor_si128(x4, x8);
    x5 = _mm_xor_si128(x5, x9);
    x6 = _mm_xor_si128(x6, x10);
    x7 = _mm_xor_si128(x7, x11);
    x4 = _mm_rol_epi32(x4, 12);
    x5 = _mm_rol_epi32(x5, 12);
    x6 = _mm_rol_epi32(x6, 12);
    x7 = _mm_rol_epi32(x7, 12);
    x0 = _mm_add_epi32(x0, x4);
    x1 = _mm_add_epi32(x1, x5);
    x2 = _mm_add_epi32(x2, x6);
    x3 = _mm_add_epi32(x3, x7);
    x12 = _mm_xor_si128(x12, x0);
    x13 = _mm_xor_si128(x13, x1);
    x14 = _mm_xor_si128(x14, x2);
    x15 = _mm_xor_si128(x15, x3);
    x12 = _mm_rol_epi32(x12, 8);
    x13 = _mm_rol_epi32(x13, 8);
    x14 = _mm_rol_epi32(x14, 8);
    x15 = _mm_rol_epi32(x15, 8);
    x8 = _mm_add_epi32(x8, x12);
    x9 = _mm_add_epi32(x9, x13);
    x10 = _mm_add_epi32(x10, x14);
    x11 = _mm_add_epi32(x11, x15);
    x4 = _mm_xor_si128(x4, x8);
    x5 = _mm_xor_si128(x5, x9);
    x6 = _mm_xor_si128(x6, x10);
    x7 = _mm_xor_si128(x7, x11);
    x4 = _mm_rol_epi32(x4, 7);
    x5 = _mm_rol_epi32(x5, 7);
    x6 = _mm_rol_epi32(x6, 7);
    x7 = _mm_rol_epi32(x7, 7);
    x0 = _mm_add_epi32(x0, x5);
    x1 = _mm_add_epi32(x1, x6);
    x2 = _mm_add_epi32(x2, x7);
    x3 = _mm_add_epi32(x3, x4);
    x15 = _mm_xor_si128(x15, x0);
    x12 = _mm_xor_si128(x12, x1);
    x13 = _mm_xor_si128(x13, x2);
    x14 = _mm_xor_si128(x14, x3);
    x15 = _mm_rol_epi32(x15, 16);
    x12 = _mm_rol_epi32(x12, 16);
    x13 = _mm_rol_epi32(x13, 16);
    x14 = _mm_rol_epi32(x14, 16);
    x10 = _mm_add_epi32(x10, x15);
    x11 = _mm_add_epi32(x11, x12);
    x8 = _mm_add_epi32(x8, x13);
    x9 = _mm_add_epi32(x9, x14);
    x5 = _mm_xor_si128(x5, x10);
    x6 = _mm_xor_si128(x6, x11);
    x7 = _mm_xor_si128(x7, x8);
    x4 = _mm_xor_si128(x4, x9);
    x5 = _mm_rol_epi32(x5, 12);
    x6 = _mm_rol_epi32(x6, 12);
    x7 = _mm_rol_epi32(x7, 12);
    x4 = _mm_rol_epi32(x4, 12);
    x0 = _mm_add_epi32(x0, x5);
    x1 = _mm_add_epi32(x1, x6);
    x2 = _mm_add_epi32(x2, x7);
    x3 = _mm_add_epi32(x3, x4);
    x15 = _mm_xor_si128(x15, x0);
    x12 = _mm_xor_si128(x12, x1);
    x13 = _mm_xor_si128(x13, x2);
    x14 = _mm_xor_si128(x14, x3);
    x15 = _mm_rol_epi32(x15, 8);
    x12 = _mm_rol_epi32(x12, 8);
    x13 = _mm_rol_epi32(x13, 8);
    x14 = _mm_rol_epi32(x14, 8);
    x10 = _mm_add_epi32(x10, x15);
    x11 = _mm_add_epi32(x11, x12);
    x8 = _mm_add_epi32(x8, x13);
    x9 = _mm_add_epi32(x9, x14);
    x5 = _mm_xor_si128(x5, x10);
    x6 = _mm_xor_si128(x6, x11);
    x7 = _mm_xor_si128(x7, x8);
    x4 = _mm_xor_si128(x4, x9);
    x5 = _mm_rol_epi32(x5, 7);
    x6 = _mm_rol_epi32(x6, 7);
    x7 = _mm_rol_epi32(x7, 7);
    x4 = _mm_rol_epi32(x4, 7);
    r8 = (r8 & ~(word64)0xff) | ((word64)(byte)((byte)r8 - 1) & 0xff);
    if (((byte)r8) != (0)) {
        goto L_chacha20_avx512vl_loop128;
    }
    x0 = _mm_add_epi32(x0, _mm_loadu_si128((const __m128i*)WC_PR(r9, 0)));
    x1 = _mm_add_epi32(x1, _mm_loadu_si128((const __m128i*)WC_PR(r9, 16)));
    x2 = _mm_add_epi32(x2, _mm_loadu_si128((const __m128i*)WC_PR(r9, 32)));
    x3 = _mm_add_epi32(x3, _mm_loadu_si128((const __m128i*)WC_PR(r9, 48)));
    x4 = _mm_add_epi32(x4, _mm_loadu_si128((const __m128i*)WC_PR(r9, 64)));
    x5 = _mm_add_epi32(x5, _mm_loadu_si128((const __m128i*)WC_PR(r9, 80)));
    x6 = _mm_add_epi32(x6, _mm_loadu_si128((const __m128i*)WC_PR(r9, 96)));
    x7 = _mm_add_epi32(x7, _mm_loadu_si128((const __m128i*)WC_PR(r9, 112)));
    x8 = _mm_add_epi32(x8, _mm_loadu_si128((const __m128i*)WC_PR(r9, 128)));
    x9 = _mm_add_epi32(x9, _mm_loadu_si128((const __m128i*)WC_PR(r9, 144)));
    x10 = _mm_add_epi32(x10, _mm_loadu_si128((const __m128i*)WC_PR(r9, 160)));
    x11 = _mm_add_epi32(x11, _mm_loadu_si128((const __m128i*)WC_PR(r9, 176)));
    x12 = _mm_add_epi32(x12, _mm_loadu_si128((const __m128i*)WC_PR(r9, 192)));
    x13 = _mm_add_epi32(x13, _mm_loadu_si128((const __m128i*)WC_PR(r9, 208)));
    x14 = _mm_add_epi32(x14, _mm_loadu_si128((const __m128i*)WC_PR(r9, 224)));
    x15 = _mm_add_epi32(x15, _mm_loadu_si128((const __m128i*)WC_PR(r9, 240)));
    _mm_storeu_si128((__m128i*)WC_PW(r10, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 16), x9);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 32), x10);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 48), x11);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 64), x12);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 80), x13);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 96), x14);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 112), x15);
    x8 = _mm_unpacklo_epi32(x0, x1);
    x9 = _mm_unpacklo_epi32(x2, x3);
    x12 = _mm_unpackhi_epi32(x0, x1);
    x13 = _mm_unpackhi_epi32(x2, x3);
    x10 = _mm_unpacklo_epi32(x4, x5);
    x11 = _mm_unpacklo_epi32(x6, x7);
    x14 = _mm_unpackhi_epi32(x4, x5);
    x15 = _mm_unpackhi_epi32(x6, x7);
    x0 = _mm_unpacklo_epi64(x8, x9);
    x1 = _mm_unpacklo_epi64(x10, x11);
    x2 = _mm_unpackhi_epi64(x8, x9);
    x3 = _mm_unpackhi_epi64(x10, x11);
    x4 = _mm_unpacklo_epi64(x12, x13);
    x5 = _mm_unpacklo_epi64(x14, x15);
    x6 = _mm_unpackhi_epi64(x12, x13);
    x7 = _mm_unpackhi_epi64(x14, x15);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 0));
    x9 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 16));
    x10 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 64));
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 80));
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 128));
    x13 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 144));
    x14 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 192));
    x15 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 208));
    x0 = _mm_xor_si128(x0, x8);
    x1 = _mm_xor_si128(x1, x9);
    x2 = _mm_xor_si128(x2, x10);
    x3 = _mm_xor_si128(x3, x11);
    x4 = _mm_xor_si128(x4, x12);
    x5 = _mm_xor_si128(x5, x13);
    x6 = _mm_xor_si128(x6, x14);
    x7 = _mm_xor_si128(x7, x15);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x0);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 16), x1);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 64), x2);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 80), x3);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 128), x4);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 144), x5);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 192), x6);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 208), x7);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 64));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 80));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 96));
    x7 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 112));
    x8 = _mm_unpacklo_epi32(x0, x1);
    x9 = _mm_unpacklo_epi32(x2, x3);
    x12 = _mm_unpackhi_epi32(x0, x1);
    x13 = _mm_unpackhi_epi32(x2, x3);
    x10 = _mm_unpacklo_epi32(x4, x5);
    x11 = _mm_unpacklo_epi32(x6, x7);
    x14 = _mm_unpackhi_epi32(x4, x5);
    x15 = _mm_unpackhi_epi32(x6, x7);
    x0 = _mm_unpacklo_epi64(x8, x9);
    x1 = _mm_unpacklo_epi64(x10, x11);
    x2 = _mm_unpackhi_epi64(x8, x9);
    x3 = _mm_unpackhi_epi64(x10, x11);
    x4 = _mm_unpacklo_epi64(x12, x13);
    x5 = _mm_unpacklo_epi64(x14, x15);
    x6 = _mm_unpackhi_epi64(x12, x13);
    x7 = _mm_unpackhi_epi64(x14, x15);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 32));
    x9 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 48));
    x10 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 96));
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 112));
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 160));
    x13 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 176));
    x14 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 224));
    x15 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 240));
    x0 = _mm_xor_si128(x0, x8);
    x1 = _mm_xor_si128(x1, x9);
    x2 = _mm_xor_si128(x2, x10);
    x3 = _mm_xor_si128(x3, x11);
    x4 = _mm_xor_si128(x4, x12);
    x5 = _mm_xor_si128(x5, x13);
    x6 = _mm_xor_si128(x6, x14);
    x7 = _mm_xor_si128(x7, x15);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 32), x0);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 48), x1);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 96), x2);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 112), x3);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 160), x4);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 176), x5);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 224), x6);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 240), x7);
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 192));
    rsi = (word64)(rsi + 0x100);
    rdx = (word64)(rdx + 0x100);
    x12 = _mm_add_epi32(x12, _mm_loadu_si128((const __m128i*)WC_PR(r13, 0)));
    rcx = (word32)((word32)rcx - 0x100);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 192), x12);
    if (((word32)rcx) < (0x100)) {
        goto L_chacha20_avx512vl_done128;
    }
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 16));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 48));
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 64));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 80));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 96));
    x7 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 112));
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 128));
    x9 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 144));
    x10 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 160));
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 176));
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 192));
    x13 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 208));
    x14 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 224));
    x15 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 240));
    goto L_chacha20_avx512vl_start128;
L_chacha20_avx512vl_done128:
    rax = (word32)((word32)rax << 2);
    WC_S32(rdi, 48) = (word32)(WC_L32(rdi, 48) + (word32)rax);
L_chacha20_avx512vl_end128:
    if (((word32)rcx) == (0)) {
        goto L_chacha20_avx512vl_last_done;
    }
    x0 = _mm_set1_epi32((int)WC_L32(rdi, 0));
    x1 = _mm_set1_epi32((int)WC_L32(rdi, 4));
    x2 = _mm_set1_epi32((int)WC_L32(rdi, 8));
    x3 = _mm_set1_epi32((int)WC_L32(rdi, 12));
    x4 = _mm_set1_epi32((int)WC_L32(rdi, 16));
    x5 = _mm_set1_epi32((int)WC_L32(rdi, 20));
    x6 = _mm_set1_epi32((int)WC_L32(rdi, 24));
    x7 = _mm_set1_epi32((int)WC_L32(rdi, 28));
    x8 = _mm_set1_epi32((int)WC_L32(rdi, 32));
    x9 = _mm_set1_epi32((int)WC_L32(rdi, 36));
    x10 = _mm_set1_epi32((int)WC_L32(rdi, 40));
    x11 = _mm_set1_epi32((int)WC_L32(rdi, 44));
    x12 = _mm_set1_epi32((int)WC_L32(rdi, 48));
    x13 = _mm_set1_epi32((int)WC_L32(rdi, 52));
    x14 = _mm_set1_epi32((int)WC_L32(rdi, 56));
    x15 = _mm_set1_epi32((int)WC_L32(rdi, 60));
    x12 = _mm_add_epi32(x12, _mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    _mm_storeu_si128((__m128i*)WC_PW(r9, 0), x0);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 16), x1);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 32), x2);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 48), x3);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 64), x4);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 80), x5);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 96), x6);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 112), x7);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 128), x8);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 144), x9);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 160), x10);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 176), x11);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 192), x12);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 208), x13);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 224), x14);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 240), x15);
    r8 = (r8 & ~(word64)0xff) | ((word64)(byte)(0xa) & 0xff);
L_chacha20_avx512vl_last_round:
    x0 = _mm_add_epi32(x0, x4);
    x1 = _mm_add_epi32(x1, x5);
    x2 = _mm_add_epi32(x2, x6);
    x3 = _mm_add_epi32(x3, x7);
    x12 = _mm_xor_si128(x12, x0);
    x13 = _mm_xor_si128(x13, x1);
    x14 = _mm_xor_si128(x14, x2);
    x15 = _mm_xor_si128(x15, x3);
    x12 = _mm_rol_epi32(x12, 16);
    x13 = _mm_rol_epi32(x13, 16);
    x14 = _mm_rol_epi32(x14, 16);
    x15 = _mm_rol_epi32(x15, 16);
    x8 = _mm_add_epi32(x8, x12);
    x9 = _mm_add_epi32(x9, x13);
    x10 = _mm_add_epi32(x10, x14);
    x11 = _mm_add_epi32(x11, x15);
    x4 = _mm_xor_si128(x4, x8);
    x5 = _mm_xor_si128(x5, x9);
    x6 = _mm_xor_si128(x6, x10);
    x7 = _mm_xor_si128(x7, x11);
    x4 = _mm_rol_epi32(x4, 12);
    x5 = _mm_rol_epi32(x5, 12);
    x6 = _mm_rol_epi32(x6, 12);
    x7 = _mm_rol_epi32(x7, 12);
    x0 = _mm_add_epi32(x0, x4);
    x1 = _mm_add_epi32(x1, x5);
    x2 = _mm_add_epi32(x2, x6);
    x3 = _mm_add_epi32(x3, x7);
    x12 = _mm_xor_si128(x12, x0);
    x13 = _mm_xor_si128(x13, x1);
    x14 = _mm_xor_si128(x14, x2);
    x15 = _mm_xor_si128(x15, x3);
    x12 = _mm_rol_epi32(x12, 8);
    x13 = _mm_rol_epi32(x13, 8);
    x14 = _mm_rol_epi32(x14, 8);
    x15 = _mm_rol_epi32(x15, 8);
    x8 = _mm_add_epi32(x8, x12);
    x9 = _mm_add_epi32(x9, x13);
    x10 = _mm_add_epi32(x10, x14);
    x11 = _mm_add_epi32(x11, x15);
    x4 = _mm_xor_si128(x4, x8);
    x5 = _mm_xor_si128(x5, x9);
    x6 = _mm_xor_si128(x6, x10);
    x7 = _mm_xor_si128(x7, x11);
    x4 = _mm_rol_epi32(x4, 7);
    x5 = _mm_rol_epi32(x5, 7);
    x6 = _mm_rol_epi32(x6, 7);
    x7 = _mm_rol_epi32(x7, 7);
    x0 = _mm_add_epi32(x0, x5);
    x1 = _mm_add_epi32(x1, x6);
    x2 = _mm_add_epi32(x2, x7);
    x3 = _mm_add_epi32(x3, x4);
    x15 = _mm_xor_si128(x15, x0);
    x12 = _mm_xor_si128(x12, x1);
    x13 = _mm_xor_si128(x13, x2);
    x14 = _mm_xor_si128(x14, x3);
    x15 = _mm_rol_epi32(x15, 16);
    x12 = _mm_rol_epi32(x12, 16);
    x13 = _mm_rol_epi32(x13, 16);
    x14 = _mm_rol_epi32(x14, 16);
    x10 = _mm_add_epi32(x10, x15);
    x11 = _mm_add_epi32(x11, x12);
    x8 = _mm_add_epi32(x8, x13);
    x9 = _mm_add_epi32(x9, x14);
    x5 = _mm_xor_si128(x5, x10);
    x6 = _mm_xor_si128(x6, x11);
    x7 = _mm_xor_si128(x7, x8);
    x4 = _mm_xor_si128(x4, x9);
    x5 = _mm_rol_epi32(x5, 12);
    x6 = _mm_rol_epi32(x6, 12);
    x7 = _mm_rol_epi32(x7, 12);
    x4 = _mm_rol_epi32(x4, 12);
    x0 = _mm_add_epi32(x0, x5);
    x1 = _mm_add_epi32(x1, x6);
    x2 = _mm_add_epi32(x2, x7);
    x3 = _mm_add_epi32(x3, x4);
    x15 = _mm_xor_si128(x15, x0);
    x12 = _mm_xor_si128(x12, x1);
    x13 = _mm_xor_si128(x13, x2);
    x14 = _mm_xor_si128(x14, x3);
    x15 = _mm_rol_epi32(x15, 8);
    x12 = _mm_rol_epi32(x12, 8);
    x13 = _mm_rol_epi32(x13, 8);
    x14 = _mm_rol_epi32(x14, 8);
    x10 = _mm_add_epi32(x10, x15);
    x11 = _mm_add_epi32(x11, x12);
    x8 = _mm_add_epi32(x8, x13);
    x9 = _mm_add_epi32(x9, x14);
    x5 = _mm_xor_si128(x5, x10);
    x6 = _mm_xor_si128(x6, x11);
    x7 = _mm_xor_si128(x7, x8);
    x4 = _mm_xor_si128(x4, x9);
    x5 = _mm_rol_epi32(x5, 7);
    x6 = _mm_rol_epi32(x6, 7);
    x7 = _mm_rol_epi32(x7, 7);
    x4 = _mm_rol_epi32(x4, 7);
    r8 = (r8 & ~(word64)0xff) | ((word64)(byte)((byte)r8 - 1) & 0xff);
    if (((byte)r8) != (0)) {
        goto L_chacha20_avx512vl_last_round;
    }
    x0 = _mm_add_epi32(x0, _mm_loadu_si128((const __m128i*)WC_PR(r9, 0)));
    x1 = _mm_add_epi32(x1, _mm_loadu_si128((const __m128i*)WC_PR(r9, 16)));
    x2 = _mm_add_epi32(x2, _mm_loadu_si128((const __m128i*)WC_PR(r9, 32)));
    x3 = _mm_add_epi32(x3, _mm_loadu_si128((const __m128i*)WC_PR(r9, 48)));
    x4 = _mm_add_epi32(x4, _mm_loadu_si128((const __m128i*)WC_PR(r9, 64)));
    x5 = _mm_add_epi32(x5, _mm_loadu_si128((const __m128i*)WC_PR(r9, 80)));
    x6 = _mm_add_epi32(x6, _mm_loadu_si128((const __m128i*)WC_PR(r9, 96)));
    x7 = _mm_add_epi32(x7, _mm_loadu_si128((const __m128i*)WC_PR(r9, 112)));
    x8 = _mm_add_epi32(x8, _mm_loadu_si128((const __m128i*)WC_PR(r9, 128)));
    x9 = _mm_add_epi32(x9, _mm_loadu_si128((const __m128i*)WC_PR(r9, 144)));
    x10 = _mm_add_epi32(x10, _mm_loadu_si128((const __m128i*)WC_PR(r9, 160)));
    x11 = _mm_add_epi32(x11, _mm_loadu_si128((const __m128i*)WC_PR(r9, 176)));
    x12 = _mm_add_epi32(x12, _mm_loadu_si128((const __m128i*)WC_PR(r9, 192)));
    x13 = _mm_add_epi32(x13, _mm_loadu_si128((const __m128i*)WC_PR(r9, 208)));
    x14 = _mm_add_epi32(x14, _mm_loadu_si128((const __m128i*)WC_PR(r9, 224)));
    x15 = _mm_add_epi32(x15, _mm_loadu_si128((const __m128i*)WC_PR(r9, 240)));
    _mm_storeu_si128((__m128i*)WC_PW(r10, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 16), x9);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 32), x10);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 48), x11);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 64), x12);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 80), x13);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 96), x14);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 112), x15);
    x8 = _mm_unpacklo_epi32(x0, x1);
    x9 = _mm_unpacklo_epi32(x2, x3);
    x12 = _mm_unpackhi_epi32(x0, x1);
    x13 = _mm_unpackhi_epi32(x2, x3);
    x10 = _mm_unpacklo_epi32(x4, x5);
    x11 = _mm_unpacklo_epi32(x6, x7);
    x14 = _mm_unpackhi_epi32(x4, x5);
    x15 = _mm_unpackhi_epi32(x6, x7);
    x0 = _mm_unpacklo_epi64(x8, x9);
    x1 = _mm_unpacklo_epi64(x10, x11);
    x2 = _mm_unpackhi_epi64(x8, x9);
    x3 = _mm_unpackhi_epi64(x10, x11);
    x4 = _mm_unpacklo_epi64(x12, x13);
    x5 = _mm_unpacklo_epi64(x14, x15);
    x6 = _mm_unpackhi_epi64(x12, x13);
    x7 = _mm_unpackhi_epi64(x14, x15);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 0), x0);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 16), x1);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 64), x2);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 80), x3);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 128), x4);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 144), x5);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 192), x6);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 208), x7);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 64));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 80));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 96));
    x7 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 112));
    x8 = _mm_unpacklo_epi32(x0, x1);
    x9 = _mm_unpacklo_epi32(x2, x3);
    x12 = _mm_unpackhi_epi32(x0, x1);
    x13 = _mm_unpackhi_epi32(x2, x3);
    x10 = _mm_unpacklo_epi32(x4, x5);
    x11 = _mm_unpacklo_epi32(x6, x7);
    x14 = _mm_unpackhi_epi32(x4, x5);
    x15 = _mm_unpackhi_epi32(x6, x7);
    x0 = _mm_unpacklo_epi64(x8, x9);
    x1 = _mm_unpacklo_epi64(x10, x11);
    x2 = _mm_unpackhi_epi64(x8, x9);
    x3 = _mm_unpackhi_epi64(x10, x11);
    x4 = _mm_unpacklo_epi64(x12, x13);
    x5 = _mm_unpacklo_epi64(x14, x15);
    x6 = _mm_unpackhi_epi64(x12, x13);
    x7 = _mm_unpackhi_epi64(x14, x15);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 32), x0);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 48), x1);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 96), x2);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 112), x3);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 160), x4);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 176), x5);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 224), x6);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 240), x7);
    if (((word32)rcx) < (0x40)) {
        goto L_chacha20_avx512vl_last_fdone;
    }
L_chacha20_avx512vl_last_fstart:
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 0));
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(r9, 0)));
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x0);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 16));
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(r9, 16)));
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 16), x0);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 32));
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(r9, 32)));
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 32), x0);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 48));
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(r9, 48)));
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 48), x0);
    WC_S32(rdi, 48) = (word32)(WC_L32(rdi, 48) + 1);
    rcx = (word32)((word32)rcx - 0x40);
    rsi = (word64)(rsi + 0x40);
    rdx = (word64)(rdx + 0x40);
    r9 = (word64)(r9 + 0x40);
    if (((word32)rcx) >= (0x40)) {
        goto L_chacha20_avx512vl_last_fstart;
    }
L_chacha20_avx512vl_last_fdone:
    if (((word32)rcx) == (0)) {
        goto L_chacha20_avx512vl_last_done;
    }
    r10 = (word64)(rdi + 80);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 0));
    _mm_storeu_si128((__m128i*)WC_PW(r10, 0), x0);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 16));
    _mm_storeu_si128((__m128i*)WC_PW(r10, 16), x0);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 32));
    _mm_storeu_si128((__m128i*)WC_PW(r10, 32), x0);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 48));
    _mm_storeu_si128((__m128i*)WC_PW(r10, 48), x0);
    WC_S32(rdi, 48) = (word32)(WC_L32(rdi, 48) + 1);
    r8 = (word32)((word32)rcx);
    r11 = (word64)(0);
    r8 = (word32)((word32)r8 & 7);
    if (((word32)r8) == (0)) {
        goto L_chacha20_avx512vl_last_start64;
    }
L_chacha20_avx512vl_last_start8:
    rax = (word32)((word32)WC_L8(r10, r11));
    rax = (rax & ~(word64)0xff) | ((word64)(byte)((byte)rax ^ WC_L8(rsi,
        r11)) & 0xff);
    WC_S8(rdx, r11) = (byte)((byte)rax);
    r11 = (word32)((word32)r11 + 1);
    zf1 = (word32)r11;
    zf2 = (word32)r8;
    if (((word32)r11) != ((word32)r8)) {
        goto L_chacha20_avx512vl_last_start8;
    }
    if ((zf1) == (zf2)) {
        goto L_chacha20_avx512vl_last_end64;
    }
L_chacha20_avx512vl_last_start64:
    rax = (word64)(WC_L64(r10, r11));
    rax = (word64)(rax ^ WC_L64(rsi, r11));
    WC_S64(rdx, r11) = (word64)(rax);
    r11 = (word32)((word32)r11 + 8);
L_chacha20_avx512vl_last_end64:
    if (((word32)r11) != ((word32)rcx)) {
        goto L_chacha20_avx512vl_last_start64;
    }
    r8 = (word32)(0x40);
    r8 = (word32)((word32)r8 - (word32)r11);
    WC_S32(rdi, 76) = (word32)((word32)r8);
L_chacha20_avx512vl_last_done:
    ;
}

#endif /* HAVE_INTEL_AVX512 */
#ifdef HAVE_INTEL_AVX512
XALIGNED(32) static const word64 L_chacha20_avx512_add[] WC_X64I_UNUSED = {
    0x0000000100000000ULL, 0x0000000300000002ULL,
    0x0000000500000004ULL, 0x0000000700000006ULL,
    0x0000000900000008ULL, 0x0000000b0000000aULL,
    0x0000000d0000000cULL, 0x0000000f0000000eULL,
};

WC_X64I_TARGET("avx512f")
WOLFSSL_LOCAL void chacha_encrypt_avx512(ChaCha* ctx, const byte* m, byte* c,
    word32 bytes)
{
    word64 rdi, rsi, rdx, rcx, rsp, r8, rax = 0;
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
            z22 = _mm512_setzero_si512(), z23 = _mm512_setzero_si512(),
            z24 = _mm512_setzero_si512(), z25 = _mm512_setzero_si512(),
            z26 = _mm512_setzero_si512(), z27 = _mm512_setzero_si512(),
            z28 = _mm512_setzero_si512(), z29 = _mm512_setzero_si512(),
            z30 = _mm512_setzero_si512(), z31 = _mm512_setzero_si512();
    XALIGNED(32) WC_X64I_SLOT stk[4];

    rdi = (word64)(size_t)ctx;
    rsi = (word64)(size_t)m;
    rdx = (word64)(size_t)c;
    rcx = (word64)(word32)bytes;

    rsp = (word64)(size_t)stk + 32;
    rsp = (word64)(rsp - 8);
    r8 = (word64)((word64)(size_t)L_chacha20_avx512_add);
    if (((word32)rcx) < (0x400)) {
        goto L_chacha20_avx512_end512;
    }
L_chacha20_avx512_start512:
    z0 = _mm512_set1_epi32((int)WC_L32(rdi, 0));
    z1 = _mm512_set1_epi32((int)WC_L32(rdi, 4));
    z2 = _mm512_set1_epi32((int)WC_L32(rdi, 8));
    z3 = _mm512_set1_epi32((int)WC_L32(rdi, 12));
    z4 = _mm512_set1_epi32((int)WC_L32(rdi, 16));
    z5 = _mm512_set1_epi32((int)WC_L32(rdi, 20));
    z6 = _mm512_set1_epi32((int)WC_L32(rdi, 24));
    z7 = _mm512_set1_epi32((int)WC_L32(rdi, 28));
    z8 = _mm512_set1_epi32((int)WC_L32(rdi, 32));
    z9 = _mm512_set1_epi32((int)WC_L32(rdi, 36));
    z10 = _mm512_set1_epi32((int)WC_L32(rdi, 40));
    z11 = _mm512_set1_epi32((int)WC_L32(rdi, 44));
    z13 = _mm512_set1_epi32((int)WC_L32(rdi, 52));
    z14 = _mm512_set1_epi32((int)WC_L32(rdi, 56));
    z15 = _mm512_set1_epi32((int)WC_L32(rdi, 60));
    z12 = _mm512_set1_epi32((int)WC_L32(rdi, 48));
    z12 = _mm512_add_epi32(z12, _mm512_loadu_si512((const void*)WC_PR(r8, 0)));
    rax = (rax & ~(word64)0xff) | ((word64)(byte)(0xa) & 0xff);
L_chacha20_avx512_loop512:
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    rax = (rax & ~(word64)0xff) | ((word64)(byte)((byte)rax - 1) & 0xff);
    if (((byte)rax) != (0)) {
        goto L_chacha20_avx512_loop512;
    }
    z0 = _mm512_add_epi32(z0, _mm512_set1_epi32((int)WC_L32(rdi, 0)));
    z1 = _mm512_add_epi32(z1, _mm512_set1_epi32((int)WC_L32(rdi, 4)));
    z2 = _mm512_add_epi32(z2, _mm512_set1_epi32((int)WC_L32(rdi, 8)));
    z3 = _mm512_add_epi32(z3, _mm512_set1_epi32((int)WC_L32(rdi, 12)));
    z4 = _mm512_add_epi32(z4, _mm512_set1_epi32((int)WC_L32(rdi, 16)));
    z5 = _mm512_add_epi32(z5, _mm512_set1_epi32((int)WC_L32(rdi, 20)));
    z6 = _mm512_add_epi32(z6, _mm512_set1_epi32((int)WC_L32(rdi, 24)));
    z7 = _mm512_add_epi32(z7, _mm512_set1_epi32((int)WC_L32(rdi, 28)));
    z8 = _mm512_add_epi32(z8, _mm512_set1_epi32((int)WC_L32(rdi, 32)));
    z9 = _mm512_add_epi32(z9, _mm512_set1_epi32((int)WC_L32(rdi, 36)));
    z10 = _mm512_add_epi32(z10, _mm512_set1_epi32((int)WC_L32(rdi, 40)));
    z11 = _mm512_add_epi32(z11, _mm512_set1_epi32((int)WC_L32(rdi, 44)));
    z13 = _mm512_add_epi32(z13, _mm512_set1_epi32((int)WC_L32(rdi, 52)));
    z14 = _mm512_add_epi32(z14, _mm512_set1_epi32((int)WC_L32(rdi, 56)));
    z15 = _mm512_add_epi32(z15, _mm512_set1_epi32((int)WC_L32(rdi, 60)));
    z16 = _mm512_set1_epi32((int)WC_L32(rdi, 48));
    z16 = _mm512_add_epi32(z16, _mm512_loadu_si512((const void*)WC_PR(r8, 0)));
    z12 = _mm512_add_epi32(z12, z16);
    z16 = _mm512_unpacklo_epi32(z0, z1);
    z17 = _mm512_unpackhi_epi32(z0, z1);
    z18 = _mm512_unpacklo_epi32(z2, z3);
    z19 = _mm512_unpackhi_epi32(z2, z3);
    z20 = _mm512_unpacklo_epi32(z4, z5);
    z21 = _mm512_unpackhi_epi32(z4, z5);
    z22 = _mm512_unpacklo_epi32(z6, z7);
    z23 = _mm512_unpackhi_epi32(z6, z7);
    z24 = _mm512_unpacklo_epi32(z8, z9);
    z25 = _mm512_unpackhi_epi32(z8, z9);
    z26 = _mm512_unpacklo_epi32(z10, z11);
    z27 = _mm512_unpackhi_epi32(z10, z11);
    z28 = _mm512_unpacklo_epi32(z12, z13);
    z29 = _mm512_unpackhi_epi32(z12, z13);
    z30 = _mm512_unpacklo_epi32(z14, z15);
    z31 = _mm512_unpackhi_epi32(z14, z15);
    z0 = _mm512_unpacklo_epi64(z16, z18);
    z1 = _mm512_unpackhi_epi64(z16, z18);
    z2 = _mm512_unpacklo_epi64(z17, z19);
    z3 = _mm512_unpackhi_epi64(z17, z19);
    z4 = _mm512_unpacklo_epi64(z20, z22);
    z5 = _mm512_unpackhi_epi64(z20, z22);
    z6 = _mm512_unpacklo_epi64(z21, z23);
    z7 = _mm512_unpackhi_epi64(z21, z23);
    z8 = _mm512_unpacklo_epi64(z24, z26);
    z9 = _mm512_unpackhi_epi64(z24, z26);
    z10 = _mm512_unpacklo_epi64(z25, z27);
    z11 = _mm512_unpackhi_epi64(z25, z27);
    z12 = _mm512_unpacklo_epi64(z28, z30);
    z13 = _mm512_unpackhi_epi64(z28, z30);
    z14 = _mm512_unpacklo_epi64(z29, z31);
    z15 = _mm512_unpackhi_epi64(z29, z31);
    z16 = _mm512_shuffle_i32x4(z0, z4, 0x44);
    z17 = _mm512_shuffle_i32x4(z0, z4, 0xee);
    z18 = _mm512_shuffle_i32x4(z8, z12, 0x44);
    z19 = _mm512_shuffle_i32x4(z8, z12, 0xee);
    z20 = _mm512_shuffle_i32x4(z16, z18, 0x88);
    z21 = _mm512_shuffle_i32x4(z16, z18, 0xdd);
    z22 = _mm512_shuffle_i32x4(z17, z19, 0x88);
    z23 = _mm512_shuffle_i32x4(z17, z19, 0xdd);
    z20 = _mm512_xor_si512(z20, _mm512_loadu_si512((const void*)WC_PR(rsi, 0)));
    _mm512_storeu_si512((void*)WC_PW(rdx, 0), z20);
    z21 = _mm512_xor_si512(z21, _mm512_loadu_si512((const void*)WC_PR(rsi,
        256)));
    _mm512_storeu_si512((void*)WC_PW(rdx, 256), z21);
    z22 = _mm512_xor_si512(z22, _mm512_loadu_si512((const void*)WC_PR(rsi,
        512)));
    _mm512_storeu_si512((void*)WC_PW(rdx, 512), z22);
    z23 = _mm512_xor_si512(z23, _mm512_loadu_si512((const void*)WC_PR(rsi,
        768)));
    _mm512_storeu_si512((void*)WC_PW(rdx, 768), z23);
    z16 = _mm512_shuffle_i32x4(z1, z5, 0x44);
    z17 = _mm512_shuffle_i32x4(z1, z5, 0xee);
    z18 = _mm512_shuffle_i32x4(z9, z13, 0x44);
    z19 = _mm512_shuffle_i32x4(z9, z13, 0xee);
    z20 = _mm512_shuffle_i32x4(z16, z18, 0x88);
    z21 = _mm512_shuffle_i32x4(z16, z18, 0xdd);
    z22 = _mm512_shuffle_i32x4(z17, z19, 0x88);
    z23 = _mm512_shuffle_i32x4(z17, z19, 0xdd);
    z20 = _mm512_xor_si512(z20, _mm512_loadu_si512((const void*)WC_PR(rsi,
        64)));
    _mm512_storeu_si512((void*)WC_PW(rdx, 64), z20);
    z21 = _mm512_xor_si512(z21, _mm512_loadu_si512((const void*)WC_PR(rsi,
        320)));
    _mm512_storeu_si512((void*)WC_PW(rdx, 320), z21);
    z22 = _mm512_xor_si512(z22, _mm512_loadu_si512((const void*)WC_PR(rsi,
        576)));
    _mm512_storeu_si512((void*)WC_PW(rdx, 576), z22);
    z23 = _mm512_xor_si512(z23, _mm512_loadu_si512((const void*)WC_PR(rsi,
        832)));
    _mm512_storeu_si512((void*)WC_PW(rdx, 832), z23);
    z16 = _mm512_shuffle_i32x4(z2, z6, 0x44);
    z17 = _mm512_shuffle_i32x4(z2, z6, 0xee);
    z18 = _mm512_shuffle_i32x4(z10, z14, 0x44);
    z19 = _mm512_shuffle_i32x4(z10, z14, 0xee);
    z20 = _mm512_shuffle_i32x4(z16, z18, 0x88);
    z21 = _mm512_shuffle_i32x4(z16, z18, 0xdd);
    z22 = _mm512_shuffle_i32x4(z17, z19, 0x88);
    z23 = _mm512_shuffle_i32x4(z17, z19, 0xdd);
    z20 = _mm512_xor_si512(z20, _mm512_loadu_si512((const void*)WC_PR(rsi,
        128)));
    _mm512_storeu_si512((void*)WC_PW(rdx, 128), z20);
    z21 = _mm512_xor_si512(z21, _mm512_loadu_si512((const void*)WC_PR(rsi,
        384)));
    _mm512_storeu_si512((void*)WC_PW(rdx, 384), z21);
    z22 = _mm512_xor_si512(z22, _mm512_loadu_si512((const void*)WC_PR(rsi,
        640)));
    _mm512_storeu_si512((void*)WC_PW(rdx, 640), z22);
    z23 = _mm512_xor_si512(z23, _mm512_loadu_si512((const void*)WC_PR(rsi,
        896)));
    _mm512_storeu_si512((void*)WC_PW(rdx, 896), z23);
    z16 = _mm512_shuffle_i32x4(z3, z7, 0x44);
    z17 = _mm512_shuffle_i32x4(z3, z7, 0xee);
    z18 = _mm512_shuffle_i32x4(z11, z15, 0x44);
    z19 = _mm512_shuffle_i32x4(z11, z15, 0xee);
    z20 = _mm512_shuffle_i32x4(z16, z18, 0x88);
    z21 = _mm512_shuffle_i32x4(z16, z18, 0xdd);
    z22 = _mm512_shuffle_i32x4(z17, z19, 0x88);
    z23 = _mm512_shuffle_i32x4(z17, z19, 0xdd);
    z20 = _mm512_xor_si512(z20, _mm512_loadu_si512((const void*)WC_PR(rsi,
        192)));
    _mm512_storeu_si512((void*)WC_PW(rdx, 192), z20);
    z21 = _mm512_xor_si512(z21, _mm512_loadu_si512((const void*)WC_PR(rsi,
        448)));
    _mm512_storeu_si512((void*)WC_PW(rdx, 448), z21);
    z22 = _mm512_xor_si512(z22, _mm512_loadu_si512((const void*)WC_PR(rsi,
        704)));
    _mm512_storeu_si512((void*)WC_PW(rdx, 704), z22);
    z23 = _mm512_xor_si512(z23, _mm512_loadu_si512((const void*)WC_PR(rsi,
        960)));
    _mm512_storeu_si512((void*)WC_PW(rdx, 960), z23);
    rsi = (word64)(rsi + 0x400);
    rdx = (word64)(rdx + 0x400);
    WC_S32(rdi, 48) = (word32)(WC_L32(rdi, 48) + 0x10);
    rcx = (word32)((word32)rcx - 0x400);
    if (((word32)rcx) >= (0x400)) {
        goto L_chacha20_avx512_start512;
    }
L_chacha20_avx512_end512:
    (void)chacha_encrypt_avx2((ChaCha*)(size_t)rdi, (const byte*)(size_t)rsi, (
        byte*)(size_t)rdx, (word32)rcx);
}

#endif /* HAVE_INTEL_AVX512 */
#ifdef HAVE_INTEL_AVX512
XALIGNED(16) static const word64 L_chacha20_poly1305_add[] WC_X64I_UNUSED = {
    0x0000000100000000ULL, 0x0000000300000002ULL,
};

XALIGNED(16) static const word64 L_chacha20_poly1305_four[] WC_X64I_UNUSED = {
    0x0000000400000004ULL, 0x0000000400000004ULL,
};

XALIGNED(32) static const word64 L_chacha20_poly1305_mask[] WC_X64I_UNUSED = {
    0x0000000003ffffffULL, 0x0000000003ffffffULL,
    0x0000000003ffffffULL, 0x0000000003ffffffULL,
};

XALIGNED(32) static const word64 L_chacha20_poly1305_hibit[] WC_X64I_UNUSED = {
    0x0000000001000000ULL, 0x0000000001000000ULL,
    0x0000000001000000ULL, 0x0000000001000000ULL,
};

WC_X64I_TARGET("avx512f,avx512vl")
WOLFSSL_LOCAL void chacha20_poly1305_avx512(ChaCha* chacha, Poly1305* poly,
    const byte* m, byte* c, word32 bytes)
{
    word64 rdi, rsi, rdx, rcx, r8, rsp, r10, r11, r12, r13, r14, r15, rbx,
           rbp, r9, rax = 0;
    __m128i x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28,
            x29, x30, x31;
    __m256i y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14,
            y15;
    XALIGNED(32) WC_X64I_SLOT stk[92];

    rdi = (word64)(size_t)chacha;
    rsi = (word64)(size_t)poly;
    rdx = (word64)(size_t)m;
    rcx = (word64)(size_t)c;
    r8 = (word64)(word32)bytes;

    rsp = (word64)(size_t)stk + 736;
    rsp = (word64)(rsp - 720);
    r10 = (word64)((word64)(size_t)L_chacha20_poly1305_add);
    r11 = (word64)((word64)(size_t)L_chacha20_poly1305_four);
    r12 = (word64)((word64)(size_t)L_chacha20_poly1305_mask);
    r13 = (word64)((word64)(size_t)L_chacha20_poly1305_hibit);
    r14 = (word64)(rsp);
    r14 = (word64)(r14 + 0xf);
    r14 = (word64)(r14 & -16);
    r15 = (word64)(rsp + 272);
    r15 = (word64)(r15 + 0xf);
    r15 = (word64)(r15 & -16);
    rbx = (word64)(rsp + 416);
    rbp = (word64)(rsp + 576);
    y15 = _mm256_zextsi128_si256(_mm_setzero_si128());
    r9 = (word64)(rsi + 64);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 32));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 64));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 96));
    y4 = _mm256_loadu_si256((const __m256i*)WC_PR(r9, 128));
    y13 = _mm256_loadu_si256((const __m256i*)WC_PR(rsi, 320));
    y5 = _mm256_permute4x64_epi64(y13, 0);
    y14 = _mm256_srli_epi64(y13, 32);
    y7 = _mm256_permute4x64_epi64(y13, 0x55);
    y9 = _mm256_permute4x64_epi64(y13, 0xaa);
    y6 = _mm256_permute4x64_epi64(y14, 0);
    y8 = _mm256_permute4x64_epi64(y14, 0x55);
    y10 = _mm256_slli_epi32(y6, 2);
    y11 = _mm256_slli_epi32(y7, 2);
    y12 = _mm256_slli_epi32(y8, 2);
    y13 = _mm256_slli_epi32(y9, 2);
    y10 = _mm256_add_epi64(y6, y10);
    y11 = _mm256_add_epi64(y7, y11);
    y12 = _mm256_add_epi64(y8, y12);
    y13 = _mm256_add_epi64(y9, y13);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 0), y10);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 32), y11);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 64), y12);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 96), y13);
    _mm256_storeu_si256((__m256i*)WC_PW(rbx, 0), y5);
    _mm256_storeu_si256((__m256i*)WC_PW(rbx, 32), y6);
    _mm256_storeu_si256((__m256i*)WC_PW(rbx, 64), y7);
    _mm256_storeu_si256((__m256i*)WC_PW(rbx, 96), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rbx, 128), y9);
    y14 = _mm256_loadu_si256((const __m256i*)WC_PR(r12, 0));
    x16 = _mm_set1_epi32((int)WC_L32(rdi, 0));
    x17 = _mm_set1_epi32((int)WC_L32(rdi, 4));
    x18 = _mm_set1_epi32((int)WC_L32(rdi, 8));
    x19 = _mm_set1_epi32((int)WC_L32(rdi, 12));
    x20 = _mm_set1_epi32((int)WC_L32(rdi, 16));
    x21 = _mm_set1_epi32((int)WC_L32(rdi, 20));
    x22 = _mm_set1_epi32((int)WC_L32(rdi, 24));
    x23 = _mm_set1_epi32((int)WC_L32(rdi, 28));
    x24 = _mm_set1_epi32((int)WC_L32(rdi, 32));
    x25 = _mm_set1_epi32((int)WC_L32(rdi, 36));
    x26 = _mm_set1_epi32((int)WC_L32(rdi, 40));
    x27 = _mm_set1_epi32((int)WC_L32(rdi, 44));
    x28 = _mm_set1_epi32((int)WC_L32(rdi, 48));
    x29 = _mm_set1_epi32((int)WC_L32(rdi, 52));
    x30 = _mm_set1_epi32((int)WC_L32(rdi, 56));
    x31 = _mm_set1_epi32((int)WC_L32(rdi, 60));
    x28 = _mm_add_epi32(x28, _mm_loadu_si128((const __m128i*)WC_PR(r10, 0)));
    _mm_storeu_si128((__m128i*)WC_PW(r14, 0), x16);
    _mm_storeu_si128((__m128i*)WC_PW(r14, 16), x17);
    _mm_storeu_si128((__m128i*)WC_PW(r14, 32), x18);
    _mm_storeu_si128((__m128i*)WC_PW(r14, 48), x19);
    _mm_storeu_si128((__m128i*)WC_PW(r14, 64), x20);
    _mm_storeu_si128((__m128i*)WC_PW(r14, 80), x21);
    _mm_storeu_si128((__m128i*)WC_PW(r14, 96), x22);
    _mm_storeu_si128((__m128i*)WC_PW(r14, 112), x23);
    _mm_storeu_si128((__m128i*)WC_PW(r14, 128), x24);
    _mm_storeu_si128((__m128i*)WC_PW(r14, 144), x25);
    _mm_storeu_si128((__m128i*)WC_PW(r14, 160), x26);
    _mm_storeu_si128((__m128i*)WC_PW(r14, 176), x27);
    _mm_storeu_si128((__m128i*)WC_PW(r14, 192), x28);
    _mm_storeu_si128((__m128i*)WC_PW(r14, 208), x29);
    _mm_storeu_si128((__m128i*)WC_PW(r14, 224), x30);
    _mm_storeu_si128((__m128i*)WC_PW(r14, 240), x31);
    rax = (rax & ~(word64)0xff) | ((word64)(byte)(0xa) & 0xff);
L_chacha20_poly1305_rounds:
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x31 = _mm_rol_epi32(x31, 16);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 12);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x31 = _mm_rol_epi32(x31, 8);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 7);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 16);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x20 = _mm_rol_epi32(x20, 12);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 8);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x20 = _mm_rol_epi32(x20, 7);
    rax = (rax & ~(word64)0xff) | ((word64)(byte)((byte)rax - 1) & 0xff);
    if (((byte)rax) != (0)) {
        goto L_chacha20_poly1305_rounds;
    }
    x16 = _mm_add_epi32(x16, _mm_loadu_si128((const __m128i*)WC_PR(r14, 0)));
    x17 = _mm_add_epi32(x17, _mm_loadu_si128((const __m128i*)WC_PR(r14, 16)));
    x18 = _mm_add_epi32(x18, _mm_loadu_si128((const __m128i*)WC_PR(r14, 32)));
    x19 = _mm_add_epi32(x19, _mm_loadu_si128((const __m128i*)WC_PR(r14, 48)));
    x20 = _mm_add_epi32(x20, _mm_loadu_si128((const __m128i*)WC_PR(r14, 64)));
    x21 = _mm_add_epi32(x21, _mm_loadu_si128((const __m128i*)WC_PR(r14, 80)));
    x22 = _mm_add_epi32(x22, _mm_loadu_si128((const __m128i*)WC_PR(r14, 96)));
    x23 = _mm_add_epi32(x23, _mm_loadu_si128((const __m128i*)WC_PR(r14, 112)));
    x24 = _mm_add_epi32(x24, _mm_loadu_si128((const __m128i*)WC_PR(r14, 128)));
    x25 = _mm_add_epi32(x25, _mm_loadu_si128((const __m128i*)WC_PR(r14, 144)));
    x26 = _mm_add_epi32(x26, _mm_loadu_si128((const __m128i*)WC_PR(r14, 160)));
    x27 = _mm_add_epi32(x27, _mm_loadu_si128((const __m128i*)WC_PR(r14, 176)));
    x28 = _mm_add_epi32(x28, _mm_loadu_si128((const __m128i*)WC_PR(r14, 192)));
    x29 = _mm_add_epi32(x29, _mm_loadu_si128((const __m128i*)WC_PR(r14, 208)));
    x30 = _mm_add_epi32(x30, _mm_loadu_si128((const __m128i*)WC_PR(r14, 224)));
    x31 = _mm_add_epi32(x31, _mm_loadu_si128((const __m128i*)WC_PR(r14, 240)));
    _mm_storeu_si128((__m128i*)WC_PW(r15, 0), x24);
    _mm_storeu_si128((__m128i*)WC_PW(r15, 16), x25);
    _mm_storeu_si128((__m128i*)WC_PW(r15, 32), x26);
    _mm_storeu_si128((__m128i*)WC_PW(r15, 48), x27);
    _mm_storeu_si128((__m128i*)WC_PW(r15, 64), x28);
    _mm_storeu_si128((__m128i*)WC_PW(r15, 80), x29);
    _mm_storeu_si128((__m128i*)WC_PW(r15, 96), x30);
    _mm_storeu_si128((__m128i*)WC_PW(r15, 112), x31);
    x24 = _mm_unpacklo_epi32(x16, x17);
    x25 = _mm_unpacklo_epi32(x18, x19);
    x28 = _mm_unpackhi_epi32(x16, x17);
    x29 = _mm_unpackhi_epi32(x18, x19);
    x26 = _mm_unpacklo_epi32(x20, x21);
    x27 = _mm_unpacklo_epi32(x22, x23);
    x30 = _mm_unpackhi_epi32(x20, x21);
    x31 = _mm_unpackhi_epi32(x22, x23);
    x16 = _mm_unpacklo_epi64(x24, x25);
    x17 = _mm_unpacklo_epi64(x26, x27);
    x18 = _mm_unpackhi_epi64(x24, x25);
    x19 = _mm_unpackhi_epi64(x26, x27);
    x20 = _mm_unpacklo_epi64(x28, x29);
    x21 = _mm_unpacklo_epi64(x30, x31);
    x22 = _mm_unpackhi_epi64(x28, x29);
    x23 = _mm_unpackhi_epi64(x30, x31);
    x24 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0));
    x25 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 16));
    x26 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 64));
    x27 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 80));
    x28 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 128));
    x29 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 144));
    x30 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 192));
    x31 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 208));
    x16 = _mm_xor_si128(x16, x24);
    x17 = _mm_xor_si128(x17, x25);
    x18 = _mm_xor_si128(x18, x26);
    x19 = _mm_xor_si128(x19, x27);
    x20 = _mm_xor_si128(x20, x28);
    x21 = _mm_xor_si128(x21, x29);
    x22 = _mm_xor_si128(x22, x30);
    x23 = _mm_xor_si128(x23, x31);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), x16);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 16), x17);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 64), x18);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 80), x19);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 128), x20);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 144), x21);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 192), x22);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 208), x23);
    x16 = _mm_loadu_si128((const __m128i*)WC_PR(r15, 0));
    x17 = _mm_loadu_si128((const __m128i*)WC_PR(r15, 16));
    x18 = _mm_loadu_si128((const __m128i*)WC_PR(r15, 32));
    x19 = _mm_loadu_si128((const __m128i*)WC_PR(r15, 48));
    x20 = _mm_loadu_si128((const __m128i*)WC_PR(r15, 64));
    x21 = _mm_loadu_si128((const __m128i*)WC_PR(r15, 80));
    x22 = _mm_loadu_si128((const __m128i*)WC_PR(r15, 96));
    x23 = _mm_loadu_si128((const __m128i*)WC_PR(r15, 112));
    x24 = _mm_unpacklo_epi32(x16, x17);
    x25 = _mm_unpacklo_epi32(x18, x19);
    x28 = _mm_unpackhi_epi32(x16, x17);
    x29 = _mm_unpackhi_epi32(x18, x19);
    x26 = _mm_unpacklo_epi32(x20, x21);
    x27 = _mm_unpacklo_epi32(x22, x23);
    x30 = _mm_unpackhi_epi32(x20, x21);
    x31 = _mm_unpackhi_epi32(x22, x23);
    x16 = _mm_unpacklo_epi64(x24, x25);
    x17 = _mm_unpacklo_epi64(x26, x27);
    x18 = _mm_unpackhi_epi64(x24, x25);
    x19 = _mm_unpackhi_epi64(x26, x27);
    x20 = _mm_unpacklo_epi64(x28, x29);
    x21 = _mm_unpacklo_epi64(x30, x31);
    x22 = _mm_unpackhi_epi64(x28, x29);
    x23 = _mm_unpackhi_epi64(x30, x31);
    x24 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 32));
    x25 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 48));
    x26 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 96));
    x27 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 112));
    x28 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 160));
    x29 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 176));
    x30 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 224));
    x31 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 240));
    x16 = _mm_xor_si128(x16, x24);
    x17 = _mm_xor_si128(x17, x25);
    x18 = _mm_xor_si128(x18, x26);
    x19 = _mm_xor_si128(x19, x27);
    x20 = _mm_xor_si128(x20, x28);
    x21 = _mm_xor_si128(x21, x29);
    x22 = _mm_xor_si128(x22, x30);
    x23 = _mm_xor_si128(x23, x31);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 32), x16);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 48), x17);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 96), x18);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 112), x19);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 160), x20);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 176), x21);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 224), x22);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 240), x23);
    x28 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 192));
    x28 = _mm_add_epi32(x28, _mm_loadu_si128((const __m128i*)WC_PR(r11, 0)));
    _mm_storeu_si128((__m128i*)WC_PW(r14, 192), x28);
    x16 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 0));
    x17 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 16));
    x18 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 32));
    x19 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 48));
    x20 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 64));
    x21 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 80));
    x22 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 96));
    x23 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 112));
    x24 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 128));
    x25 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 144));
    x26 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 160));
    x27 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 176));
    x28 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 192));
    x29 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 208));
    x30 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 224));
    x31 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 240));
    rdx = (word64)(rdx + 0x100);
    rcx = (word64)(rcx + 0x100);
    r8 = (word32)((word32)r8 - 0x100);
    if (((word32)r8) == (0)) {
        goto L_chacha20_poly1305_epilogue;
    }
L_chacha20_poly1305_start:
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x31 = _mm_rol_epi32(x31, 16);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 12);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x31 = _mm_rol_epi32(x31, 8);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 7);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 16);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x20 = _mm_rol_epi32(x20, 12);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 8);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x20 = _mm_rol_epi32(x20, 7);
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x31 = _mm_rol_epi32(x31, 16);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 12);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x31 = _mm_rol_epi32(x31, 8);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 7);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 16);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x20 = _mm_rol_epi32(x20, 12);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 8);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x20 = _mm_rol_epi32(x20, 7);
    y5 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, -256));
    y6 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, -224));
    y7 = _mm256_permute2x128_si256(y5, y6, 0x20);
    y5 = _mm256_permute2x128_si256(y5, y6, 0x31);
    y6 = _mm256_unpacklo_epi32(y7, y5);
    y8 = _mm256_unpackhi_epi32(y7, y5);
    y5 = _mm256_unpacklo_epi32(y6, y15);
    y6 = _mm256_unpackhi_epi32(y6, y15);
    y7 = _mm256_unpacklo_epi32(y8, y15);
    y8 = _mm256_unpackhi_epi32(y8, y15);
    y9 = _mm256_loadu_si256((const __m256i*)WC_PR(r13, 0));
    y6 = _mm256_slli_epi64(y6, 6);
    y7 = _mm256_slli_epi64(y7, 12);
    y8 = _mm256_slli_epi64(y8, 18);
    y10 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        0)));
    y5 = _mm256_add_epi64(y10, y5);
    y10 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        32)));
    y11 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        32)));
    y6 = _mm256_add_epi64(y11, y6);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y12 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y7 = _mm256_add_epi64(y12, y7);
    y5 = _mm256_add_epi64(y10, y5);
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y13 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y8 = _mm256_add_epi64(y13, y8);
    y6 = _mm256_add_epi64(y11, y6);
    y13 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y10 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y5 = _mm256_add_epi64(y12, y5);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y12 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y9 = _mm256_add_epi64(y13, y9);
    y6 = _mm256_add_epi64(y10, y6);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y7 = _mm256_add_epi64(y11, y7);
    y10 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y8 = _mm256_add_epi64(y12, y8);
    y11 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y9 = _mm256_add_epi64(y13, y9);
    y13 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y9 = _mm256_add_epi64(y13, y9);
    y7 = _mm256_add_epi64(y10, y7);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
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
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x31 = _mm_rol_epi32(x31, 16);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 12);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x31 = _mm_rol_epi32(x31, 8);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 7);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 16);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x20 = _mm_rol_epi32(x20, 12);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 8);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x20 = _mm_rol_epi32(x20, 7);
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x31 = _mm_rol_epi32(x31, 16);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 12);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x31 = _mm_rol_epi32(x31, 8);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 7);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 16);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x20 = _mm_rol_epi32(x20, 12);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 8);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x20 = _mm_rol_epi32(x20, 7);
    y5 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, -192));
    y6 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, -160));
    y7 = _mm256_permute2x128_si256(y5, y6, 0x20);
    y5 = _mm256_permute2x128_si256(y5, y6, 0x31);
    y6 = _mm256_unpacklo_epi32(y7, y5);
    y8 = _mm256_unpackhi_epi32(y7, y5);
    y5 = _mm256_unpacklo_epi32(y6, y15);
    y6 = _mm256_unpackhi_epi32(y6, y15);
    y7 = _mm256_unpacklo_epi32(y8, y15);
    y8 = _mm256_unpackhi_epi32(y8, y15);
    y9 = _mm256_loadu_si256((const __m256i*)WC_PR(r13, 0));
    y6 = _mm256_slli_epi64(y6, 6);
    y7 = _mm256_slli_epi64(y7, 12);
    y8 = _mm256_slli_epi64(y8, 18);
    y10 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        0)));
    y5 = _mm256_add_epi64(y10, y5);
    y10 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        32)));
    y11 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        32)));
    y6 = _mm256_add_epi64(y11, y6);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y12 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y7 = _mm256_add_epi64(y12, y7);
    y5 = _mm256_add_epi64(y10, y5);
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y13 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y8 = _mm256_add_epi64(y13, y8);
    y6 = _mm256_add_epi64(y11, y6);
    y13 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y10 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y5 = _mm256_add_epi64(y12, y5);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y12 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y9 = _mm256_add_epi64(y13, y9);
    y6 = _mm256_add_epi64(y10, y6);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y7 = _mm256_add_epi64(y11, y7);
    y10 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y8 = _mm256_add_epi64(y12, y8);
    y11 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y9 = _mm256_add_epi64(y13, y9);
    y13 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y9 = _mm256_add_epi64(y13, y9);
    y7 = _mm256_add_epi64(y10, y7);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
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
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x31 = _mm_rol_epi32(x31, 16);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 12);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x31 = _mm_rol_epi32(x31, 8);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 7);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 16);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x20 = _mm_rol_epi32(x20, 12);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 8);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x20 = _mm_rol_epi32(x20, 7);
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x31 = _mm_rol_epi32(x31, 16);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 12);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x31 = _mm_rol_epi32(x31, 8);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 7);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 16);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x20 = _mm_rol_epi32(x20, 12);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 8);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x20 = _mm_rol_epi32(x20, 7);
    y5 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, -128));
    y6 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, -96));
    y7 = _mm256_permute2x128_si256(y5, y6, 0x20);
    y5 = _mm256_permute2x128_si256(y5, y6, 0x31);
    y6 = _mm256_unpacklo_epi32(y7, y5);
    y8 = _mm256_unpackhi_epi32(y7, y5);
    y5 = _mm256_unpacklo_epi32(y6, y15);
    y6 = _mm256_unpackhi_epi32(y6, y15);
    y7 = _mm256_unpacklo_epi32(y8, y15);
    y8 = _mm256_unpackhi_epi32(y8, y15);
    y9 = _mm256_loadu_si256((const __m256i*)WC_PR(r13, 0));
    y6 = _mm256_slli_epi64(y6, 6);
    y7 = _mm256_slli_epi64(y7, 12);
    y8 = _mm256_slli_epi64(y8, 18);
    y10 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        0)));
    y5 = _mm256_add_epi64(y10, y5);
    y10 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        32)));
    y11 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        32)));
    y6 = _mm256_add_epi64(y11, y6);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y12 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y7 = _mm256_add_epi64(y12, y7);
    y5 = _mm256_add_epi64(y10, y5);
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y13 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y8 = _mm256_add_epi64(y13, y8);
    y6 = _mm256_add_epi64(y11, y6);
    y13 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y10 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y5 = _mm256_add_epi64(y12, y5);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y12 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y9 = _mm256_add_epi64(y13, y9);
    y6 = _mm256_add_epi64(y10, y6);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y7 = _mm256_add_epi64(y11, y7);
    y10 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y8 = _mm256_add_epi64(y12, y8);
    y11 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y9 = _mm256_add_epi64(y13, y9);
    y13 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y9 = _mm256_add_epi64(y13, y9);
    y7 = _mm256_add_epi64(y10, y7);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
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
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x31 = _mm_rol_epi32(x31, 16);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 12);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x31 = _mm_rol_epi32(x31, 8);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 7);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 16);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x20 = _mm_rol_epi32(x20, 12);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 8);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x20 = _mm_rol_epi32(x20, 7);
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x31 = _mm_rol_epi32(x31, 16);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 12);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x31 = _mm_rol_epi32(x31, 8);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 7);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 16);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x20 = _mm_rol_epi32(x20, 12);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 8);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x20 = _mm_rol_epi32(x20, 7);
    y5 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, -64));
    y6 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, -32));
    y7 = _mm256_permute2x128_si256(y5, y6, 0x20);
    y5 = _mm256_permute2x128_si256(y5, y6, 0x31);
    y6 = _mm256_unpacklo_epi32(y7, y5);
    y8 = _mm256_unpackhi_epi32(y7, y5);
    y5 = _mm256_unpacklo_epi32(y6, y15);
    y6 = _mm256_unpackhi_epi32(y6, y15);
    y7 = _mm256_unpacklo_epi32(y8, y15);
    y8 = _mm256_unpackhi_epi32(y8, y15);
    y9 = _mm256_loadu_si256((const __m256i*)WC_PR(r13, 0));
    y6 = _mm256_slli_epi64(y6, 6);
    y7 = _mm256_slli_epi64(y7, 12);
    y8 = _mm256_slli_epi64(y8, 18);
    y10 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        0)));
    y5 = _mm256_add_epi64(y10, y5);
    y10 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        32)));
    y11 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        32)));
    y6 = _mm256_add_epi64(y11, y6);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y12 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y7 = _mm256_add_epi64(y12, y7);
    y5 = _mm256_add_epi64(y10, y5);
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y13 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y8 = _mm256_add_epi64(y13, y8);
    y6 = _mm256_add_epi64(y11, y6);
    y13 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y10 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y5 = _mm256_add_epi64(y12, y5);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y12 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y9 = _mm256_add_epi64(y13, y9);
    y6 = _mm256_add_epi64(y10, y6);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y7 = _mm256_add_epi64(y11, y7);
    y10 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y8 = _mm256_add_epi64(y12, y8);
    y11 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y9 = _mm256_add_epi64(y13, y9);
    y13 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y9 = _mm256_add_epi64(y13, y9);
    y7 = _mm256_add_epi64(y10, y7);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
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
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x31 = _mm_rol_epi32(x31, 16);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 12);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x31 = _mm_rol_epi32(x31, 8);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 7);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 16);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x20 = _mm_rol_epi32(x20, 12);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 8);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x20 = _mm_rol_epi32(x20, 7);
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x31 = _mm_rol_epi32(x31, 16);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 12);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x16 = _mm_add_epi32(x16, x20);
    x17 = _mm_add_epi32(x17, x21);
    x18 = _mm_add_epi32(x18, x22);
    x19 = _mm_add_epi32(x19, x23);
    x28 = _mm_xor_si128(x28, x16);
    x29 = _mm_xor_si128(x29, x17);
    x30 = _mm_xor_si128(x30, x18);
    x31 = _mm_xor_si128(x31, x19);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x31 = _mm_rol_epi32(x31, 8);
    x24 = _mm_add_epi32(x24, x28);
    x25 = _mm_add_epi32(x25, x29);
    x26 = _mm_add_epi32(x26, x30);
    x27 = _mm_add_epi32(x27, x31);
    x20 = _mm_xor_si128(x20, x24);
    x21 = _mm_xor_si128(x21, x25);
    x22 = _mm_xor_si128(x22, x26);
    x23 = _mm_xor_si128(x23, x27);
    x20 = _mm_rol_epi32(x20, 7);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 16);
    x28 = _mm_rol_epi32(x28, 16);
    x29 = _mm_rol_epi32(x29, 16);
    x30 = _mm_rol_epi32(x30, 16);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 12);
    x22 = _mm_rol_epi32(x22, 12);
    x23 = _mm_rol_epi32(x23, 12);
    x20 = _mm_rol_epi32(x20, 12);
    x16 = _mm_add_epi32(x16, x21);
    x17 = _mm_add_epi32(x17, x22);
    x18 = _mm_add_epi32(x18, x23);
    x19 = _mm_add_epi32(x19, x20);
    x31 = _mm_xor_si128(x31, x16);
    x28 = _mm_xor_si128(x28, x17);
    x29 = _mm_xor_si128(x29, x18);
    x30 = _mm_xor_si128(x30, x19);
    x31 = _mm_rol_epi32(x31, 8);
    x28 = _mm_rol_epi32(x28, 8);
    x29 = _mm_rol_epi32(x29, 8);
    x30 = _mm_rol_epi32(x30, 8);
    x26 = _mm_add_epi32(x26, x31);
    x27 = _mm_add_epi32(x27, x28);
    x24 = _mm_add_epi32(x24, x29);
    x25 = _mm_add_epi32(x25, x30);
    x21 = _mm_xor_si128(x21, x26);
    x22 = _mm_xor_si128(x22, x27);
    x23 = _mm_xor_si128(x23, x24);
    x20 = _mm_xor_si128(x20, x25);
    x21 = _mm_rol_epi32(x21, 7);
    x22 = _mm_rol_epi32(x22, 7);
    x23 = _mm_rol_epi32(x23, 7);
    x20 = _mm_rol_epi32(x20, 7);
    x16 = _mm_add_epi32(x16, _mm_loadu_si128((const __m128i*)WC_PR(r14, 0)));
    x17 = _mm_add_epi32(x17, _mm_loadu_si128((const __m128i*)WC_PR(r14, 16)));
    x18 = _mm_add_epi32(x18, _mm_loadu_si128((const __m128i*)WC_PR(r14, 32)));
    x19 = _mm_add_epi32(x19, _mm_loadu_si128((const __m128i*)WC_PR(r14, 48)));
    x20 = _mm_add_epi32(x20, _mm_loadu_si128((const __m128i*)WC_PR(r14, 64)));
    x21 = _mm_add_epi32(x21, _mm_loadu_si128((const __m128i*)WC_PR(r14, 80)));
    x22 = _mm_add_epi32(x22, _mm_loadu_si128((const __m128i*)WC_PR(r14, 96)));
    x23 = _mm_add_epi32(x23, _mm_loadu_si128((const __m128i*)WC_PR(r14, 112)));
    x24 = _mm_add_epi32(x24, _mm_loadu_si128((const __m128i*)WC_PR(r14, 128)));
    x25 = _mm_add_epi32(x25, _mm_loadu_si128((const __m128i*)WC_PR(r14, 144)));
    x26 = _mm_add_epi32(x26, _mm_loadu_si128((const __m128i*)WC_PR(r14, 160)));
    x27 = _mm_add_epi32(x27, _mm_loadu_si128((const __m128i*)WC_PR(r14, 176)));
    x28 = _mm_add_epi32(x28, _mm_loadu_si128((const __m128i*)WC_PR(r14, 192)));
    x29 = _mm_add_epi32(x29, _mm_loadu_si128((const __m128i*)WC_PR(r14, 208)));
    x30 = _mm_add_epi32(x30, _mm_loadu_si128((const __m128i*)WC_PR(r14, 224)));
    x31 = _mm_add_epi32(x31, _mm_loadu_si128((const __m128i*)WC_PR(r14, 240)));
    _mm_storeu_si128((__m128i*)WC_PW(r15, 0), x24);
    _mm_storeu_si128((__m128i*)WC_PW(r15, 16), x25);
    _mm_storeu_si128((__m128i*)WC_PW(r15, 32), x26);
    _mm_storeu_si128((__m128i*)WC_PW(r15, 48), x27);
    _mm_storeu_si128((__m128i*)WC_PW(r15, 64), x28);
    _mm_storeu_si128((__m128i*)WC_PW(r15, 80), x29);
    _mm_storeu_si128((__m128i*)WC_PW(r15, 96), x30);
    _mm_storeu_si128((__m128i*)WC_PW(r15, 112), x31);
    x24 = _mm_unpacklo_epi32(x16, x17);
    x25 = _mm_unpacklo_epi32(x18, x19);
    x28 = _mm_unpackhi_epi32(x16, x17);
    x29 = _mm_unpackhi_epi32(x18, x19);
    x26 = _mm_unpacklo_epi32(x20, x21);
    x27 = _mm_unpacklo_epi32(x22, x23);
    x30 = _mm_unpackhi_epi32(x20, x21);
    x31 = _mm_unpackhi_epi32(x22, x23);
    x16 = _mm_unpacklo_epi64(x24, x25);
    x17 = _mm_unpacklo_epi64(x26, x27);
    x18 = _mm_unpackhi_epi64(x24, x25);
    x19 = _mm_unpackhi_epi64(x26, x27);
    x20 = _mm_unpacklo_epi64(x28, x29);
    x21 = _mm_unpacklo_epi64(x30, x31);
    x22 = _mm_unpackhi_epi64(x28, x29);
    x23 = _mm_unpackhi_epi64(x30, x31);
    x24 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0));
    x25 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 16));
    x26 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 64));
    x27 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 80));
    x28 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 128));
    x29 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 144));
    x30 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 192));
    x31 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 208));
    x16 = _mm_xor_si128(x16, x24);
    x17 = _mm_xor_si128(x17, x25);
    x18 = _mm_xor_si128(x18, x26);
    x19 = _mm_xor_si128(x19, x27);
    x20 = _mm_xor_si128(x20, x28);
    x21 = _mm_xor_si128(x21, x29);
    x22 = _mm_xor_si128(x22, x30);
    x23 = _mm_xor_si128(x23, x31);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), x16);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 16), x17);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 64), x18);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 80), x19);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 128), x20);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 144), x21);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 192), x22);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 208), x23);
    x16 = _mm_loadu_si128((const __m128i*)WC_PR(r15, 0));
    x17 = _mm_loadu_si128((const __m128i*)WC_PR(r15, 16));
    x18 = _mm_loadu_si128((const __m128i*)WC_PR(r15, 32));
    x19 = _mm_loadu_si128((const __m128i*)WC_PR(r15, 48));
    x20 = _mm_loadu_si128((const __m128i*)WC_PR(r15, 64));
    x21 = _mm_loadu_si128((const __m128i*)WC_PR(r15, 80));
    x22 = _mm_loadu_si128((const __m128i*)WC_PR(r15, 96));
    x23 = _mm_loadu_si128((const __m128i*)WC_PR(r15, 112));
    x24 = _mm_unpacklo_epi32(x16, x17);
    x25 = _mm_unpacklo_epi32(x18, x19);
    x28 = _mm_unpackhi_epi32(x16, x17);
    x29 = _mm_unpackhi_epi32(x18, x19);
    x26 = _mm_unpacklo_epi32(x20, x21);
    x27 = _mm_unpacklo_epi32(x22, x23);
    x30 = _mm_unpackhi_epi32(x20, x21);
    x31 = _mm_unpackhi_epi32(x22, x23);
    x16 = _mm_unpacklo_epi64(x24, x25);
    x17 = _mm_unpacklo_epi64(x26, x27);
    x18 = _mm_unpackhi_epi64(x24, x25);
    x19 = _mm_unpackhi_epi64(x26, x27);
    x20 = _mm_unpacklo_epi64(x28, x29);
    x21 = _mm_unpacklo_epi64(x30, x31);
    x22 = _mm_unpackhi_epi64(x28, x29);
    x23 = _mm_unpackhi_epi64(x30, x31);
    x24 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 32));
    x25 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 48));
    x26 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 96));
    x27 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 112));
    x28 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 160));
    x29 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 176));
    x30 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 224));
    x31 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 240));
    x16 = _mm_xor_si128(x16, x24);
    x17 = _mm_xor_si128(x17, x25);
    x18 = _mm_xor_si128(x18, x26);
    x19 = _mm_xor_si128(x19, x27);
    x20 = _mm_xor_si128(x20, x28);
    x21 = _mm_xor_si128(x21, x29);
    x22 = _mm_xor_si128(x22, x30);
    x23 = _mm_xor_si128(x23, x31);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 32), x16);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 48), x17);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 96), x18);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 112), x19);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 160), x20);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 176), x21);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 224), x22);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 240), x23);
    x28 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 192));
    x28 = _mm_add_epi32(x28, _mm_loadu_si128((const __m128i*)WC_PR(r11, 0)));
    _mm_storeu_si128((__m128i*)WC_PW(r14, 192), x28);
    x16 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 0));
    x17 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 16));
    x18 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 32));
    x19 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 48));
    x20 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 64));
    x21 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 80));
    x22 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 96));
    x23 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 112));
    x24 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 128));
    x25 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 144));
    x26 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 160));
    x27 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 176));
    x28 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 192));
    x29 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 208));
    x30 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 224));
    x31 = _mm_loadu_si128((const __m128i*)WC_PR(r14, 240));
    rdx = (word64)(rdx + 0x100);
    rcx = (word64)(rcx + 0x100);
    r8 = (word32)((word32)r8 - 0x100);
    if (((word32)r8) != (0)) {
        goto L_chacha20_poly1305_start;
    }
L_chacha20_poly1305_epilogue:
    y5 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, -256));
    y6 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, -224));
    y7 = _mm256_permute2x128_si256(y5, y6, 0x20);
    y5 = _mm256_permute2x128_si256(y5, y6, 0x31);
    y6 = _mm256_unpacklo_epi32(y7, y5);
    y8 = _mm256_unpackhi_epi32(y7, y5);
    y5 = _mm256_unpacklo_epi32(y6, y15);
    y6 = _mm256_unpackhi_epi32(y6, y15);
    y7 = _mm256_unpacklo_epi32(y8, y15);
    y8 = _mm256_unpackhi_epi32(y8, y15);
    y9 = _mm256_loadu_si256((const __m256i*)WC_PR(r13, 0));
    y6 = _mm256_slli_epi64(y6, 6);
    y7 = _mm256_slli_epi64(y7, 12);
    y8 = _mm256_slli_epi64(y8, 18);
    y10 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        0)));
    y5 = _mm256_add_epi64(y10, y5);
    y10 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        32)));
    y11 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        32)));
    y6 = _mm256_add_epi64(y11, y6);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y12 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y7 = _mm256_add_epi64(y12, y7);
    y5 = _mm256_add_epi64(y10, y5);
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y13 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y8 = _mm256_add_epi64(y13, y8);
    y6 = _mm256_add_epi64(y11, y6);
    y13 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y10 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y5 = _mm256_add_epi64(y12, y5);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y12 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y9 = _mm256_add_epi64(y13, y9);
    y6 = _mm256_add_epi64(y10, y6);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y7 = _mm256_add_epi64(y11, y7);
    y10 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y8 = _mm256_add_epi64(y12, y8);
    y11 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y9 = _mm256_add_epi64(y13, y9);
    y13 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y9 = _mm256_add_epi64(y13, y9);
    y7 = _mm256_add_epi64(y10, y7);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
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
    y5 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, -192));
    y6 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, -160));
    y7 = _mm256_permute2x128_si256(y5, y6, 0x20);
    y5 = _mm256_permute2x128_si256(y5, y6, 0x31);
    y6 = _mm256_unpacklo_epi32(y7, y5);
    y8 = _mm256_unpackhi_epi32(y7, y5);
    y5 = _mm256_unpacklo_epi32(y6, y15);
    y6 = _mm256_unpackhi_epi32(y6, y15);
    y7 = _mm256_unpacklo_epi32(y8, y15);
    y8 = _mm256_unpackhi_epi32(y8, y15);
    y9 = _mm256_loadu_si256((const __m256i*)WC_PR(r13, 0));
    y6 = _mm256_slli_epi64(y6, 6);
    y7 = _mm256_slli_epi64(y7, 12);
    y8 = _mm256_slli_epi64(y8, 18);
    y10 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        0)));
    y5 = _mm256_add_epi64(y10, y5);
    y10 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        32)));
    y11 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        32)));
    y6 = _mm256_add_epi64(y11, y6);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y12 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y7 = _mm256_add_epi64(y12, y7);
    y5 = _mm256_add_epi64(y10, y5);
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y13 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y8 = _mm256_add_epi64(y13, y8);
    y6 = _mm256_add_epi64(y11, y6);
    y13 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y10 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y5 = _mm256_add_epi64(y12, y5);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y12 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y9 = _mm256_add_epi64(y13, y9);
    y6 = _mm256_add_epi64(y10, y6);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y7 = _mm256_add_epi64(y11, y7);
    y10 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y8 = _mm256_add_epi64(y12, y8);
    y11 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y9 = _mm256_add_epi64(y13, y9);
    y13 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y9 = _mm256_add_epi64(y13, y9);
    y7 = _mm256_add_epi64(y10, y7);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
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
    y5 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, -128));
    y6 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, -96));
    y7 = _mm256_permute2x128_si256(y5, y6, 0x20);
    y5 = _mm256_permute2x128_si256(y5, y6, 0x31);
    y6 = _mm256_unpacklo_epi32(y7, y5);
    y8 = _mm256_unpackhi_epi32(y7, y5);
    y5 = _mm256_unpacklo_epi32(y6, y15);
    y6 = _mm256_unpackhi_epi32(y6, y15);
    y7 = _mm256_unpacklo_epi32(y8, y15);
    y8 = _mm256_unpackhi_epi32(y8, y15);
    y9 = _mm256_loadu_si256((const __m256i*)WC_PR(r13, 0));
    y6 = _mm256_slli_epi64(y6, 6);
    y7 = _mm256_slli_epi64(y7, 12);
    y8 = _mm256_slli_epi64(y8, 18);
    y10 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        0)));
    y5 = _mm256_add_epi64(y10, y5);
    y10 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        32)));
    y11 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        32)));
    y6 = _mm256_add_epi64(y11, y6);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y12 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y7 = _mm256_add_epi64(y12, y7);
    y5 = _mm256_add_epi64(y10, y5);
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y13 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y8 = _mm256_add_epi64(y13, y8);
    y6 = _mm256_add_epi64(y11, y6);
    y13 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y10 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y5 = _mm256_add_epi64(y12, y5);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y12 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y9 = _mm256_add_epi64(y13, y9);
    y6 = _mm256_add_epi64(y10, y6);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y7 = _mm256_add_epi64(y11, y7);
    y10 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y8 = _mm256_add_epi64(y12, y8);
    y11 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y9 = _mm256_add_epi64(y13, y9);
    y13 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y9 = _mm256_add_epi64(y13, y9);
    y7 = _mm256_add_epi64(y10, y7);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
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
    y5 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, -64));
    y6 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, -32));
    y7 = _mm256_permute2x128_si256(y5, y6, 0x20);
    y5 = _mm256_permute2x128_si256(y5, y6, 0x31);
    y6 = _mm256_unpacklo_epi32(y7, y5);
    y8 = _mm256_unpackhi_epi32(y7, y5);
    y5 = _mm256_unpacklo_epi32(y6, y15);
    y6 = _mm256_unpackhi_epi32(y6, y15);
    y7 = _mm256_unpacklo_epi32(y8, y15);
    y8 = _mm256_unpackhi_epi32(y8, y15);
    y9 = _mm256_loadu_si256((const __m256i*)WC_PR(r13, 0));
    y6 = _mm256_slli_epi64(y6, 6);
    y7 = _mm256_slli_epi64(y7, 12);
    y8 = _mm256_slli_epi64(y8, 18);
    y10 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        0)));
    y5 = _mm256_add_epi64(y10, y5);
    y10 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        32)));
    y11 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        32)));
    y6 = _mm256_add_epi64(y11, y6);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y12 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y7 = _mm256_add_epi64(y12, y7);
    y5 = _mm256_add_epi64(y10, y5);
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y13 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y8 = _mm256_add_epi64(y13, y8);
    y6 = _mm256_add_epi64(y11, y6);
    y13 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y10 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y5 = _mm256_add_epi64(y12, y5);
    y11 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    y12 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y9 = _mm256_add_epi64(y13, y9);
    y6 = _mm256_add_epi64(y10, y6);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y7 = _mm256_add_epi64(y11, y7);
    y10 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y8 = _mm256_add_epi64(y12, y8);
    y11 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        0)));
    y12 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y5 = _mm256_add_epi64(y13, y5);
    y13 = _mm256_mul_epu32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        32)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y9 = _mm256_add_epi64(y13, y9);
    y13 = _mm256_mul_epu32(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y6 = _mm256_add_epi64(y10, y6);
    y10 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        64)));
    y7 = _mm256_add_epi64(y11, y7);
    y11 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y8 = _mm256_add_epi64(y12, y8);
    y12 = _mm256_mul_epu32(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
        96)));
    y9 = _mm256_add_epi64(y13, y9);
    y7 = _mm256_add_epi64(y10, y7);
    y13 = _mm256_mul_epu32(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbx,
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
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 0), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 32), y1);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 64), y2);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 96), y3);
    _mm256_storeu_si256((__m256i*)WC_PW(r9, 128), y4);
    WC_S32(rdi, 48) = (word32)_mm_cvtsi128_si32(x28);
}

#endif /* HAVE_INTEL_AVX512 */
#ifdef HAVE_INTEL_AVX512
XALIGNED(32) static const word64 L_cp512_add[] WC_X64I_UNUSED = {
    0x0000000100000000ULL, 0x0000000300000002ULL,
    0x0000000500000004ULL, 0x0000000700000006ULL,
    0x0000000900000008ULL, 0x0000000b0000000aULL,
    0x0000000d0000000cULL, 0x0000000f0000000eULL,
};

XALIGNED(32) static const word64 L_cp512_pc[] WC_X64I_UNUSED = {
    0x00000fffffffffffULL, 0x00000fffffffffffULL,
    0x00000fffffffffffULL, 0x00000fffffffffffULL,
    0x00000fffffffffffULL, 0x00000fffffffffffULL,
    0x00000fffffffffffULL, 0x00000fffffffffffULL,
    0x0000000000ffffffULL, 0x0000000000ffffffULL,
    0x0000000000ffffffULL, 0x0000000000ffffffULL,
    0x0000000000ffffffULL, 0x0000000000ffffffULL,
    0x0000000000ffffffULL, 0x0000000000ffffffULL,
    0x0000010000000000ULL, 0x0000010000000000ULL,
    0x0000010000000000ULL, 0x0000010000000000ULL,
    0x0000010000000000ULL, 0x0000010000000000ULL,
    0x0000010000000000ULL, 0x0000010000000000ULL,
    0x0000000000000000ULL, 0x0000000000000002ULL,
    0x0000000000000004ULL, 0x0000000000000006ULL,
    0x0000000000000008ULL, 0x000000000000000aULL,
    0x000000000000000cULL, 0x000000000000000eULL,
    0x0000000000000001ULL, 0x0000000000000003ULL,
    0x0000000000000005ULL, 0x0000000000000007ULL,
    0x0000000000000009ULL, 0x000000000000000bULL,
    0x000000000000000dULL, 0x000000000000000fULL,
    0x0000001000000010ULL, 0x0000001000000010ULL,
    0x0000001000000010ULL, 0x0000001000000010ULL,
    0x0000001000000010ULL, 0x0000001000000010ULL,
    0x0000001000000010ULL, 0x0000001000000010ULL,
};

XALIGNED(32) static const word64 L_cp512_rx[] WC_X64I_UNUSED = {
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
WOLFSSL_LOCAL void chacha20_poly1305_ifma(ChaCha* chacha, Poly1305* poly,
    const byte* m, byte* c, word32 bytes)
{
    word64 rdi, rsi, rdx, rcx, r8, rsp, rax, r10, r9, r11, r12 = 0, r13 = 0,
           r14 = 0;
    __m512i z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14,
            z15, z16, z17, z18, z19, z20, z21, z22, z23, z24, z25, z26, z27,
            z28, z29, z30, z31;
    XALIGNED(32) WC_X64I_SLOT stk[152];
    unsigned char cf;

    rdi = (word64)(size_t)chacha;
    rsi = (word64)(size_t)poly;
    rdx = (word64)(size_t)m;
    rcx = (word64)(size_t)c;
    r8 = (word64)(word32)bytes;

    rsp = (word64)(size_t)stk + 1216;
    rsp = (word64)(rsp - 1200);
    rax = (word64)((word64)(size_t)L_cp512_pc);
    r10 = (word64)((word64)(size_t)L_cp512_rx);
    r9 = (word64)((word64)(size_t)L_cp512_add);
    r11 = (word64)(rsp + 32);
    r11 = (word64)(r11 + 0x3f);
    r11 = (word64)(r11 & -64);
    z16 = _mm512_setzero_si512();
    z17 = _mm512_setzero_si512();
    z18 = _mm512_setzero_si512();
    _mm512_storeu_si512((void*)WC_PW(rsi, 752), z16);
    _mm512_storeu_si512((void*)WC_PW(rsi, 816), z17);
    _mm512_storeu_si512((void*)WC_PW(rsi, 880), z18);
    z19 = _mm512_set1_epi64((long long)WC_L64(rsi, 720));
    z20 = _mm512_set1_epi64((long long)WC_L64(rsi, 728));
    z21 = _mm512_set1_epi64((long long)WC_L64(rsi, 736));
    z30 = _mm512_slli_epi64(z20, 2);
    z22 = _mm512_slli_epi64(z20, 4);
    z22 = _mm512_add_epi64(z22, z30);
    z30 = _mm512_slli_epi64(z21, 2);
    z23 = _mm512_slli_epi64(z21, 4);
    z23 = _mm512_add_epi64(z23, z30);
    z0 = _mm512_set1_epi32((int)WC_L32(rdi, 0));
    z1 = _mm512_set1_epi32((int)WC_L32(rdi, 4));
    z2 = _mm512_set1_epi32((int)WC_L32(rdi, 8));
    z3 = _mm512_set1_epi32((int)WC_L32(rdi, 12));
    z4 = _mm512_set1_epi32((int)WC_L32(rdi, 16));
    z5 = _mm512_set1_epi32((int)WC_L32(rdi, 20));
    z6 = _mm512_set1_epi32((int)WC_L32(rdi, 24));
    z7 = _mm512_set1_epi32((int)WC_L32(rdi, 28));
    z8 = _mm512_set1_epi32((int)WC_L32(rdi, 32));
    z9 = _mm512_set1_epi32((int)WC_L32(rdi, 36));
    z10 = _mm512_set1_epi32((int)WC_L32(rdi, 40));
    z11 = _mm512_set1_epi32((int)WC_L32(rdi, 44));
    z12 = _mm512_set1_epi32((int)WC_L32(rdi, 48));
    z13 = _mm512_set1_epi32((int)WC_L32(rdi, 52));
    z14 = _mm512_set1_epi32((int)WC_L32(rdi, 56));
    z15 = _mm512_set1_epi32((int)WC_L32(rdi, 60));
    z12 = _mm512_add_epi32(z12, _mm512_loadu_si512((const void*)WC_PR(r9, 0)));
    _mm512_storeu_si512((void*)WC_PW(r11, 0), z0);
    _mm512_storeu_si512((void*)WC_PW(r11, 64), z1);
    _mm512_storeu_si512((void*)WC_PW(r11, 128), z2);
    _mm512_storeu_si512((void*)WC_PW(r11, 192), z3);
    _mm512_storeu_si512((void*)WC_PW(r11, 256), z4);
    _mm512_storeu_si512((void*)WC_PW(r11, 320), z5);
    _mm512_storeu_si512((void*)WC_PW(r11, 384), z6);
    _mm512_storeu_si512((void*)WC_PW(r11, 448), z7);
    _mm512_storeu_si512((void*)WC_PW(r11, 512), z8);
    _mm512_storeu_si512((void*)WC_PW(r11, 576), z9);
    _mm512_storeu_si512((void*)WC_PW(r11, 640), z10);
    _mm512_storeu_si512((void*)WC_PW(r11, 704), z11);
    _mm512_storeu_si512((void*)WC_PW(r11, 768), z12);
    _mm512_storeu_si512((void*)WC_PW(r11, 832), z13);
    _mm512_storeu_si512((void*)WC_PW(r11, 896), z14);
    _mm512_storeu_si512((void*)WC_PW(r11, 960), z15);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z0 = _mm512_add_epi32(z0, _mm512_loadu_si512((const void*)WC_PR(r11, 0)));
    z1 = _mm512_add_epi32(z1, _mm512_loadu_si512((const void*)WC_PR(r11, 64)));
    z2 = _mm512_add_epi32(z2, _mm512_loadu_si512((const void*)WC_PR(r11, 128)));
    z3 = _mm512_add_epi32(z3, _mm512_loadu_si512((const void*)WC_PR(r11, 192)));
    z4 = _mm512_add_epi32(z4, _mm512_loadu_si512((const void*)WC_PR(r11, 256)));
    z5 = _mm512_add_epi32(z5, _mm512_loadu_si512((const void*)WC_PR(r11, 320)));
    z6 = _mm512_add_epi32(z6, _mm512_loadu_si512((const void*)WC_PR(r11, 384)));
    z7 = _mm512_add_epi32(z7, _mm512_loadu_si512((const void*)WC_PR(r11, 448)));
    z8 = _mm512_add_epi32(z8, _mm512_loadu_si512((const void*)WC_PR(r11, 512)));
    z9 = _mm512_add_epi32(z9, _mm512_loadu_si512((const void*)WC_PR(r11, 576)));
    z10 = _mm512_add_epi32(z10, _mm512_loadu_si512((const void*)WC_PR(r11,
        640)));
    z11 = _mm512_add_epi32(z11, _mm512_loadu_si512((const void*)WC_PR(r11,
        704)));
    z12 = _mm512_add_epi32(z12, _mm512_loadu_si512((const void*)WC_PR(r11,
        768)));
    z13 = _mm512_add_epi32(z13, _mm512_loadu_si512((const void*)WC_PR(r11,
        832)));
    z14 = _mm512_add_epi32(z14, _mm512_loadu_si512((const void*)WC_PR(r11,
        896)));
    z15 = _mm512_add_epi32(z15, _mm512_loadu_si512((const void*)WC_PR(r11,
        960)));
    z16 = _mm512_unpacklo_epi32(z0, z1);
    z17 = _mm512_unpackhi_epi32(z0, z1);
    z18 = _mm512_unpacklo_epi32(z2, z3);
    z19 = _mm512_unpackhi_epi32(z2, z3);
    z20 = _mm512_unpacklo_epi32(z4, z5);
    z21 = _mm512_unpackhi_epi32(z4, z5);
    z22 = _mm512_unpacklo_epi32(z6, z7);
    z23 = _mm512_unpackhi_epi32(z6, z7);
    z24 = _mm512_unpacklo_epi32(z8, z9);
    z25 = _mm512_unpackhi_epi32(z8, z9);
    z26 = _mm512_unpacklo_epi32(z10, z11);
    z27 = _mm512_unpackhi_epi32(z10, z11);
    z28 = _mm512_unpacklo_epi32(z12, z13);
    z29 = _mm512_unpackhi_epi32(z12, z13);
    z30 = _mm512_unpacklo_epi32(z14, z15);
    z31 = _mm512_unpackhi_epi32(z14, z15);
    z0 = _mm512_unpacklo_epi64(z16, z18);
    z1 = _mm512_unpackhi_epi64(z16, z18);
    z2 = _mm512_unpacklo_epi64(z17, z19);
    z3 = _mm512_unpackhi_epi64(z17, z19);
    z4 = _mm512_unpacklo_epi64(z20, z22);
    z5 = _mm512_unpackhi_epi64(z20, z22);
    z6 = _mm512_unpacklo_epi64(z21, z23);
    z7 = _mm512_unpackhi_epi64(z21, z23);
    z8 = _mm512_unpacklo_epi64(z24, z26);
    z9 = _mm512_unpackhi_epi64(z24, z26);
    z10 = _mm512_unpacklo_epi64(z25, z27);
    z11 = _mm512_unpackhi_epi64(z25, z27);
    z12 = _mm512_unpacklo_epi64(z28, z30);
    z13 = _mm512_unpackhi_epi64(z28, z30);
    z14 = _mm512_unpacklo_epi64(z29, z31);
    z15 = _mm512_unpackhi_epi64(z29, z31);
    z16 = _mm512_shuffle_i32x4(z0, z4, 0x44);
    z17 = _mm512_shuffle_i32x4(z0, z4, 0xee);
    z18 = _mm512_shuffle_i32x4(z8, z12, 0x44);
    z19 = _mm512_shuffle_i32x4(z8, z12, 0xee);
    z20 = _mm512_shuffle_i32x4(z16, z18, 0x88);
    z21 = _mm512_shuffle_i32x4(z16, z18, 0xdd);
    z22 = _mm512_shuffle_i32x4(z17, z19, 0x88);
    z23 = _mm512_shuffle_i32x4(z17, z19, 0xdd);
    z20 = _mm512_xor_si512(z20, _mm512_loadu_si512((const void*)WC_PR(rdx, 0)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 0), z20);
    z21 = _mm512_xor_si512(z21, _mm512_loadu_si512((const void*)WC_PR(rdx,
        256)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 256), z21);
    z22 = _mm512_xor_si512(z22, _mm512_loadu_si512((const void*)WC_PR(rdx,
        512)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 512), z22);
    z23 = _mm512_xor_si512(z23, _mm512_loadu_si512((const void*)WC_PR(rdx,
        768)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 768), z23);
    z16 = _mm512_shuffle_i32x4(z1, z5, 0x44);
    z17 = _mm512_shuffle_i32x4(z1, z5, 0xee);
    z18 = _mm512_shuffle_i32x4(z9, z13, 0x44);
    z19 = _mm512_shuffle_i32x4(z9, z13, 0xee);
    z20 = _mm512_shuffle_i32x4(z16, z18, 0x88);
    z21 = _mm512_shuffle_i32x4(z16, z18, 0xdd);
    z22 = _mm512_shuffle_i32x4(z17, z19, 0x88);
    z23 = _mm512_shuffle_i32x4(z17, z19, 0xdd);
    z20 = _mm512_xor_si512(z20, _mm512_loadu_si512((const void*)WC_PR(rdx,
        64)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 64), z20);
    z21 = _mm512_xor_si512(z21, _mm512_loadu_si512((const void*)WC_PR(rdx,
        320)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 320), z21);
    z22 = _mm512_xor_si512(z22, _mm512_loadu_si512((const void*)WC_PR(rdx,
        576)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 576), z22);
    z23 = _mm512_xor_si512(z23, _mm512_loadu_si512((const void*)WC_PR(rdx,
        832)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 832), z23);
    z16 = _mm512_shuffle_i32x4(z2, z6, 0x44);
    z17 = _mm512_shuffle_i32x4(z2, z6, 0xee);
    z18 = _mm512_shuffle_i32x4(z10, z14, 0x44);
    z19 = _mm512_shuffle_i32x4(z10, z14, 0xee);
    z20 = _mm512_shuffle_i32x4(z16, z18, 0x88);
    z21 = _mm512_shuffle_i32x4(z16, z18, 0xdd);
    z22 = _mm512_shuffle_i32x4(z17, z19, 0x88);
    z23 = _mm512_shuffle_i32x4(z17, z19, 0xdd);
    z20 = _mm512_xor_si512(z20, _mm512_loadu_si512((const void*)WC_PR(rdx,
        128)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 128), z20);
    z21 = _mm512_xor_si512(z21, _mm512_loadu_si512((const void*)WC_PR(rdx,
        384)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 384), z21);
    z22 = _mm512_xor_si512(z22, _mm512_loadu_si512((const void*)WC_PR(rdx,
        640)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 640), z22);
    z23 = _mm512_xor_si512(z23, _mm512_loadu_si512((const void*)WC_PR(rdx,
        896)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 896), z23);
    z16 = _mm512_shuffle_i32x4(z3, z7, 0x44);
    z17 = _mm512_shuffle_i32x4(z3, z7, 0xee);
    z18 = _mm512_shuffle_i32x4(z11, z15, 0x44);
    z19 = _mm512_shuffle_i32x4(z11, z15, 0xee);
    z20 = _mm512_shuffle_i32x4(z16, z18, 0x88);
    z21 = _mm512_shuffle_i32x4(z16, z18, 0xdd);
    z22 = _mm512_shuffle_i32x4(z17, z19, 0x88);
    z23 = _mm512_shuffle_i32x4(z17, z19, 0xdd);
    z20 = _mm512_xor_si512(z20, _mm512_loadu_si512((const void*)WC_PR(rdx,
        192)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 192), z20);
    z21 = _mm512_xor_si512(z21, _mm512_loadu_si512((const void*)WC_PR(rdx,
        448)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 448), z21);
    z22 = _mm512_xor_si512(z22, _mm512_loadu_si512((const void*)WC_PR(rdx,
        704)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 704), z22);
    z23 = _mm512_xor_si512(z23, _mm512_loadu_si512((const void*)WC_PR(rdx,
        960)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 960), z23);
    z12 = _mm512_loadu_si512((const void*)WC_PR(r11, 768));
    z12 = _mm512_add_epi32(z12, _mm512_loadu_si512((const void*)WC_PR(rax,
        320)));
    _mm512_storeu_si512((void*)WC_PW(r11, 768), z12);
    z0 = _mm512_loadu_si512((const void*)WC_PR(r11, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(r11, 64));
    z2 = _mm512_loadu_si512((const void*)WC_PR(r11, 128));
    z3 = _mm512_loadu_si512((const void*)WC_PR(r11, 192));
    z4 = _mm512_loadu_si512((const void*)WC_PR(r11, 256));
    z5 = _mm512_loadu_si512((const void*)WC_PR(r11, 320));
    z6 = _mm512_loadu_si512((const void*)WC_PR(r11, 384));
    z7 = _mm512_loadu_si512((const void*)WC_PR(r11, 448));
    z8 = _mm512_loadu_si512((const void*)WC_PR(r11, 512));
    z9 = _mm512_loadu_si512((const void*)WC_PR(r11, 576));
    z10 = _mm512_loadu_si512((const void*)WC_PR(r11, 640));
    z11 = _mm512_loadu_si512((const void*)WC_PR(r11, 704));
    z12 = _mm512_loadu_si512((const void*)WC_PR(r11, 768));
    z13 = _mm512_loadu_si512((const void*)WC_PR(r11, 832));
    z14 = _mm512_loadu_si512((const void*)WC_PR(r11, 896));
    z15 = _mm512_loadu_si512((const void*)WC_PR(r11, 960));
    rdx = (word64)(rdx + 0x400);
    rcx = (word64)(rcx + 0x400);
    r8 = (word32)((word32)r8 - 0x400);
    if (((word32)r8) == (0)) {
        goto L_cp512_epi;
    }
L_cp512_start:
    z16 = _mm512_loadu_si512((const void*)WC_PR(rsi, 752));
    z17 = _mm512_loadu_si512((const void*)WC_PR(rsi, 816));
    z18 = _mm512_loadu_si512((const void*)WC_PR(rsi, 880));
    z19 = _mm512_set1_epi64((long long)WC_L64(rsi, 720));
    z20 = _mm512_set1_epi64((long long)WC_L64(rsi, 728));
    z21 = _mm512_set1_epi64((long long)WC_L64(rsi, 736));
    z30 = _mm512_slli_epi64(z20, 2);
    z22 = _mm512_slli_epi64(z20, 4);
    z22 = _mm512_add_epi64(z22, z30);
    z30 = _mm512_slli_epi64(z21, 2);
    z23 = _mm512_slli_epi64(z21, 4);
    z23 = _mm512_add_epi64(z23, z30);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rcx, -1024));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rcx, -960));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rcx, -896));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rcx, -832));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rcx, -768));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rcx, -704));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rcx, -640));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rcx, -576));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rcx, -512));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rcx, -448));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rcx, -384));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rcx, -320));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rcx, -256));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rcx, -192));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rcx, -128));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rcx, -64));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z0 = _mm512_add_epi32(z0, _mm512_loadu_si512((const void*)WC_PR(r11, 0)));
    z1 = _mm512_add_epi32(z1, _mm512_loadu_si512((const void*)WC_PR(r11, 64)));
    z2 = _mm512_add_epi32(z2, _mm512_loadu_si512((const void*)WC_PR(r11, 128)));
    z3 = _mm512_add_epi32(z3, _mm512_loadu_si512((const void*)WC_PR(r11, 192)));
    z4 = _mm512_add_epi32(z4, _mm512_loadu_si512((const void*)WC_PR(r11, 256)));
    z5 = _mm512_add_epi32(z5, _mm512_loadu_si512((const void*)WC_PR(r11, 320)));
    z6 = _mm512_add_epi32(z6, _mm512_loadu_si512((const void*)WC_PR(r11, 384)));
    z7 = _mm512_add_epi32(z7, _mm512_loadu_si512((const void*)WC_PR(r11, 448)));
    z8 = _mm512_add_epi32(z8, _mm512_loadu_si512((const void*)WC_PR(r11, 512)));
    z9 = _mm512_add_epi32(z9, _mm512_loadu_si512((const void*)WC_PR(r11, 576)));
    z10 = _mm512_add_epi32(z10, _mm512_loadu_si512((const void*)WC_PR(r11,
        640)));
    z11 = _mm512_add_epi32(z11, _mm512_loadu_si512((const void*)WC_PR(r11,
        704)));
    z12 = _mm512_add_epi32(z12, _mm512_loadu_si512((const void*)WC_PR(r11,
        768)));
    z13 = _mm512_add_epi32(z13, _mm512_loadu_si512((const void*)WC_PR(r11,
        832)));
    z14 = _mm512_add_epi32(z14, _mm512_loadu_si512((const void*)WC_PR(r11,
        896)));
    z15 = _mm512_add_epi32(z15, _mm512_loadu_si512((const void*)WC_PR(r11,
        960)));
    _mm512_storeu_si512((void*)WC_PW(rsi, 752), z16);
    _mm512_storeu_si512((void*)WC_PW(rsi, 816), z17);
    _mm512_storeu_si512((void*)WC_PW(rsi, 880), z18);
    z16 = _mm512_unpacklo_epi32(z0, z1);
    z17 = _mm512_unpackhi_epi32(z0, z1);
    z18 = _mm512_unpacklo_epi32(z2, z3);
    z19 = _mm512_unpackhi_epi32(z2, z3);
    z20 = _mm512_unpacklo_epi32(z4, z5);
    z21 = _mm512_unpackhi_epi32(z4, z5);
    z22 = _mm512_unpacklo_epi32(z6, z7);
    z23 = _mm512_unpackhi_epi32(z6, z7);
    z24 = _mm512_unpacklo_epi32(z8, z9);
    z25 = _mm512_unpackhi_epi32(z8, z9);
    z26 = _mm512_unpacklo_epi32(z10, z11);
    z27 = _mm512_unpackhi_epi32(z10, z11);
    z28 = _mm512_unpacklo_epi32(z12, z13);
    z29 = _mm512_unpackhi_epi32(z12, z13);
    z30 = _mm512_unpacklo_epi32(z14, z15);
    z31 = _mm512_unpackhi_epi32(z14, z15);
    z0 = _mm512_unpacklo_epi64(z16, z18);
    z1 = _mm512_unpackhi_epi64(z16, z18);
    z2 = _mm512_unpacklo_epi64(z17, z19);
    z3 = _mm512_unpackhi_epi64(z17, z19);
    z4 = _mm512_unpacklo_epi64(z20, z22);
    z5 = _mm512_unpackhi_epi64(z20, z22);
    z6 = _mm512_unpacklo_epi64(z21, z23);
    z7 = _mm512_unpackhi_epi64(z21, z23);
    z8 = _mm512_unpacklo_epi64(z24, z26);
    z9 = _mm512_unpackhi_epi64(z24, z26);
    z10 = _mm512_unpacklo_epi64(z25, z27);
    z11 = _mm512_unpackhi_epi64(z25, z27);
    z12 = _mm512_unpacklo_epi64(z28, z30);
    z13 = _mm512_unpackhi_epi64(z28, z30);
    z14 = _mm512_unpacklo_epi64(z29, z31);
    z15 = _mm512_unpackhi_epi64(z29, z31);
    z16 = _mm512_shuffle_i32x4(z0, z4, 0x44);
    z17 = _mm512_shuffle_i32x4(z0, z4, 0xee);
    z18 = _mm512_shuffle_i32x4(z8, z12, 0x44);
    z19 = _mm512_shuffle_i32x4(z8, z12, 0xee);
    z20 = _mm512_shuffle_i32x4(z16, z18, 0x88);
    z21 = _mm512_shuffle_i32x4(z16, z18, 0xdd);
    z22 = _mm512_shuffle_i32x4(z17, z19, 0x88);
    z23 = _mm512_shuffle_i32x4(z17, z19, 0xdd);
    z20 = _mm512_xor_si512(z20, _mm512_loadu_si512((const void*)WC_PR(rdx, 0)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 0), z20);
    z21 = _mm512_xor_si512(z21, _mm512_loadu_si512((const void*)WC_PR(rdx,
        256)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 256), z21);
    z22 = _mm512_xor_si512(z22, _mm512_loadu_si512((const void*)WC_PR(rdx,
        512)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 512), z22);
    z23 = _mm512_xor_si512(z23, _mm512_loadu_si512((const void*)WC_PR(rdx,
        768)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 768), z23);
    z16 = _mm512_shuffle_i32x4(z1, z5, 0x44);
    z17 = _mm512_shuffle_i32x4(z1, z5, 0xee);
    z18 = _mm512_shuffle_i32x4(z9, z13, 0x44);
    z19 = _mm512_shuffle_i32x4(z9, z13, 0xee);
    z20 = _mm512_shuffle_i32x4(z16, z18, 0x88);
    z21 = _mm512_shuffle_i32x4(z16, z18, 0xdd);
    z22 = _mm512_shuffle_i32x4(z17, z19, 0x88);
    z23 = _mm512_shuffle_i32x4(z17, z19, 0xdd);
    z20 = _mm512_xor_si512(z20, _mm512_loadu_si512((const void*)WC_PR(rdx,
        64)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 64), z20);
    z21 = _mm512_xor_si512(z21, _mm512_loadu_si512((const void*)WC_PR(rdx,
        320)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 320), z21);
    z22 = _mm512_xor_si512(z22, _mm512_loadu_si512((const void*)WC_PR(rdx,
        576)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 576), z22);
    z23 = _mm512_xor_si512(z23, _mm512_loadu_si512((const void*)WC_PR(rdx,
        832)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 832), z23);
    z16 = _mm512_shuffle_i32x4(z2, z6, 0x44);
    z17 = _mm512_shuffle_i32x4(z2, z6, 0xee);
    z18 = _mm512_shuffle_i32x4(z10, z14, 0x44);
    z19 = _mm512_shuffle_i32x4(z10, z14, 0xee);
    z20 = _mm512_shuffle_i32x4(z16, z18, 0x88);
    z21 = _mm512_shuffle_i32x4(z16, z18, 0xdd);
    z22 = _mm512_shuffle_i32x4(z17, z19, 0x88);
    z23 = _mm512_shuffle_i32x4(z17, z19, 0xdd);
    z20 = _mm512_xor_si512(z20, _mm512_loadu_si512((const void*)WC_PR(rdx,
        128)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 128), z20);
    z21 = _mm512_xor_si512(z21, _mm512_loadu_si512((const void*)WC_PR(rdx,
        384)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 384), z21);
    z22 = _mm512_xor_si512(z22, _mm512_loadu_si512((const void*)WC_PR(rdx,
        640)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 640), z22);
    z23 = _mm512_xor_si512(z23, _mm512_loadu_si512((const void*)WC_PR(rdx,
        896)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 896), z23);
    z16 = _mm512_shuffle_i32x4(z3, z7, 0x44);
    z17 = _mm512_shuffle_i32x4(z3, z7, 0xee);
    z18 = _mm512_shuffle_i32x4(z11, z15, 0x44);
    z19 = _mm512_shuffle_i32x4(z11, z15, 0xee);
    z20 = _mm512_shuffle_i32x4(z16, z18, 0x88);
    z21 = _mm512_shuffle_i32x4(z16, z18, 0xdd);
    z22 = _mm512_shuffle_i32x4(z17, z19, 0x88);
    z23 = _mm512_shuffle_i32x4(z17, z19, 0xdd);
    z20 = _mm512_xor_si512(z20, _mm512_loadu_si512((const void*)WC_PR(rdx,
        192)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 192), z20);
    z21 = _mm512_xor_si512(z21, _mm512_loadu_si512((const void*)WC_PR(rdx,
        448)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 448), z21);
    z22 = _mm512_xor_si512(z22, _mm512_loadu_si512((const void*)WC_PR(rdx,
        704)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 704), z22);
    z23 = _mm512_xor_si512(z23, _mm512_loadu_si512((const void*)WC_PR(rdx,
        960)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 960), z23);
    z12 = _mm512_loadu_si512((const void*)WC_PR(r11, 768));
    z12 = _mm512_add_epi32(z12, _mm512_loadu_si512((const void*)WC_PR(rax,
        320)));
    _mm512_storeu_si512((void*)WC_PW(r11, 768), z12);
    z0 = _mm512_loadu_si512((const void*)WC_PR(r11, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(r11, 64));
    z2 = _mm512_loadu_si512((const void*)WC_PR(r11, 128));
    z3 = _mm512_loadu_si512((const void*)WC_PR(r11, 192));
    z4 = _mm512_loadu_si512((const void*)WC_PR(r11, 256));
    z5 = _mm512_loadu_si512((const void*)WC_PR(r11, 320));
    z6 = _mm512_loadu_si512((const void*)WC_PR(r11, 384));
    z7 = _mm512_loadu_si512((const void*)WC_PR(r11, 448));
    z8 = _mm512_loadu_si512((const void*)WC_PR(r11, 512));
    z9 = _mm512_loadu_si512((const void*)WC_PR(r11, 576));
    z10 = _mm512_loadu_si512((const void*)WC_PR(r11, 640));
    z11 = _mm512_loadu_si512((const void*)WC_PR(r11, 704));
    z12 = _mm512_loadu_si512((const void*)WC_PR(r11, 768));
    z13 = _mm512_loadu_si512((const void*)WC_PR(r11, 832));
    z14 = _mm512_loadu_si512((const void*)WC_PR(r11, 896));
    z15 = _mm512_loadu_si512((const void*)WC_PR(r11, 960));
    rdx = (word64)(rdx + 0x400);
    rcx = (word64)(rcx + 0x400);
    r8 = (word32)((word32)r8 - 0x400);
    if (((word32)r8) != (0)) {
        goto L_cp512_start;
    }
L_cp512_epi:
    z16 = _mm512_loadu_si512((const void*)WC_PR(rsi, 752));
    z17 = _mm512_loadu_si512((const void*)WC_PR(rsi, 816));
    z18 = _mm512_loadu_si512((const void*)WC_PR(rsi, 880));
    z19 = _mm512_set1_epi64((long long)WC_L64(rsi, 720));
    z20 = _mm512_set1_epi64((long long)WC_L64(rsi, 728));
    z21 = _mm512_set1_epi64((long long)WC_L64(rsi, 736));
    z30 = _mm512_slli_epi64(z20, 2);
    z22 = _mm512_slli_epi64(z20, 4);
    z22 = _mm512_add_epi64(z22, z30);
    z30 = _mm512_slli_epi64(z21, 2);
    z23 = _mm512_slli_epi64(z21, 4);
    z23 = _mm512_add_epi64(z23, z30);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rcx, -1024));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rcx, -960));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rcx, -896));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rcx, -832));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rcx, -768));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rcx, -704));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rcx, -640));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rcx, -576));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rcx, -512));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rcx, -448));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rcx, -384));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rcx, -320));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rcx, -256));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rcx, -192));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rcx, -128));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rcx, -64));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z24 = _mm512_loadu_si512((const void*)WC_PR(rsi, 224));
    z25 = _mm512_loadu_si512((const void*)WC_PR(rsi, 288));
    z26 = _mm512_loadu_si512((const void*)WC_PR(rsi, 624));
    z27 = _mm512_loadu_si512((const void*)WC_PR(rsi, 688));
    z28 = _mm512_loadu_si512((const void*)WC_PR(r10, 0));
    z28 = _mm512_permutex2var_epi64(z26, z28, z27);
    z29 = _mm512_loadu_si512((const void*)WC_PR(r10, 0));
    z29 = _mm512_permutex2var_epi64(z24, z29, z25);
    z19 = _mm512_inserti64x4(z28, _mm512_castsi512_si256(z29), 1);
    z28 = _mm512_loadu_si512((const void*)WC_PR(r10, 64));
    z28 = _mm512_permutex2var_epi64(z26, z28, z27);
    z29 = _mm512_loadu_si512((const void*)WC_PR(r10, 64));
    z29 = _mm512_permutex2var_epi64(z24, z29, z25);
    z20 = _mm512_inserti64x4(z28, _mm512_castsi512_si256(z29), 1);
    z28 = _mm512_loadu_si512((const void*)WC_PR(r10, 128));
    z28 = _mm512_permutex2var_epi64(z26, z28, z27);
    z29 = _mm512_loadu_si512((const void*)WC_PR(r10, 128));
    z29 = _mm512_permutex2var_epi64(z24, z29, z25);
    z21 = _mm512_inserti64x4(z28, _mm512_castsi512_si256(z29), 1);
    z30 = _mm512_slli_epi64(z20, 2);
    z22 = _mm512_slli_epi64(z20, 4);
    z22 = _mm512_add_epi64(z22, z30);
    z30 = _mm512_slli_epi64(z21, 2);
    z23 = _mm512_slli_epi64(z21, 4);
    z23 = _mm512_add_epi64(z23, z30);
    z24 = _mm512_setzero_si512();
    z25 = _mm512_setzero_si512();
    z26 = _mm512_setzero_si512();
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z24 = _mm512_shuffle_i64x2(z16, z16, 0x4e);
    z25 = _mm512_shuffle_i64x2(z17, z17, 0x4e);
    z26 = _mm512_shuffle_i64x2(z18, z18, 0x4e);
    z16 = _mm512_add_epi64(z24, z16);
    z17 = _mm512_add_epi64(z25, z17);
    z18 = _mm512_add_epi64(z26, z18);
    z24 = _mm512_bsrli_epi128(z16, 8);
    z25 = _mm512_bsrli_epi128(z17, 8);
    z26 = _mm512_bsrli_epi128(z18, 8);
    z16 = _mm512_add_epi64(z24, z16);
    z17 = _mm512_add_epi64(z25, z17);
    z18 = _mm512_add_epi64(z26, z18);
    z24 = _mm512_permutex_epi64(z16, 2);
    z25 = _mm512_permutex_epi64(z17, 2);
    z26 = _mm512_permutex_epi64(z18, 2);
    z16 = _mm512_add_epi64(z24, z16);
    z17 = _mm512_add_epi64(z25, z17);
    z18 = _mm512_add_epi64(z26, z18);
    r12 = (word64)((word64)_mm_cvtsi128_si64(_mm512_castsi512_si128(z16)));
    r13 = (word64)((word64)_mm_cvtsi128_si64(_mm512_castsi512_si128(z17)));
    r14 = (word64)((word64)_mm_cvtsi128_si64(_mm512_castsi512_si128(z18)));
    r10 = (word64)(r13);
    r10 = (word64)(r10 >> 20);
    r11 = (word64)(r14);
    r11 = (word64)(r11 >> 40);
    rax = (word64)(r12);
    r12 = (word64)(r13);
    r12 = (word64)(r12 << 44);
    cf = _addcarry_u64(0, rax, r12, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    r12 = (word64)(r14);
    r12 = (word64)(r12 << 24);
    cf = _addcarry_u64(0, r10, r12, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    r9 = (word64)(r11);
    r11 = (word64)(r11 & 3);
    r9 = (word64)(r9 >> 2);
    r9 = (word64)(r9 + r9 * 4);
    cf = _addcarry_u64(0, rax, r9, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    r12 = (word64)(WC_L64(rsi, 24));
    WC_S64(rsi, 64) = (word64)(r12);
    r12 = (word64)(WC_L64(rsi, 32));
    WC_S64(rsi, 72) = (word64)(r12);
    r12 = (word64)(WC_L64(rsi, 40));
    WC_S64(rsi, 80) = (word64)(r12);
    WC_S64(rsi, 24) = (word64)(rax);
    WC_S64(rsi, 32) = (word64)(r10);
    WC_S64(rsi, 40) = (word64)(r11);
    WC_S32(rdi, 48) = (word32)_mm_cvtsi128_si32(_mm512_castsi512_si128(z12));
}

WC_X64I_TARGET("avx512f,avx512bw,avx512ifma")
WOLFSSL_LOCAL void chacha20_poly1305_ifma_decrypt(ChaCha* chacha,
    Poly1305* poly, const byte* m, byte* c, word32 bytes)
{
    word64 rdi, rsi, rdx, rcx, r8, rsp, rax, r10, r9, r11, r12 = 0, r13 = 0,
           r14 = 0;
    __m512i z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14,
            z15, z16, z17, z18, z19 = _mm512_setzero_si512(),
            z20 = _mm512_setzero_si512(), z21 = _mm512_setzero_si512(),
            z22 = _mm512_setzero_si512(), z23 = _mm512_setzero_si512(),
            z24 = _mm512_setzero_si512(), z25 = _mm512_setzero_si512(),
            z26 = _mm512_setzero_si512(), z27 = _mm512_setzero_si512(),
            z28 = _mm512_setzero_si512(), z29 = _mm512_setzero_si512(),
            z30 = _mm512_setzero_si512(), z31 = _mm512_setzero_si512();
    XALIGNED(32) WC_X64I_SLOT stk[152];
    unsigned char cf;

    rdi = (word64)(size_t)chacha;
    rsi = (word64)(size_t)poly;
    rdx = (word64)(size_t)m;
    rcx = (word64)(size_t)c;
    r8 = (word64)(word32)bytes;

    rsp = (word64)(size_t)stk + 1216;
    rsp = (word64)(rsp - 1200);
    rax = (word64)((word64)(size_t)L_cp512_pc);
    r10 = (word64)((word64)(size_t)L_cp512_rx);
    r9 = (word64)((word64)(size_t)L_cp512_add);
    r11 = (word64)(rsp + 32);
    r11 = (word64)(r11 + 0x3f);
    r11 = (word64)(r11 & -64);
    z16 = _mm512_setzero_si512();
    z17 = _mm512_setzero_si512();
    z18 = _mm512_setzero_si512();
    _mm512_storeu_si512((void*)WC_PW(rsi, 752), z16);
    _mm512_storeu_si512((void*)WC_PW(rsi, 816), z17);
    _mm512_storeu_si512((void*)WC_PW(rsi, 880), z18);
    z0 = _mm512_set1_epi32((int)WC_L32(rdi, 0));
    z1 = _mm512_set1_epi32((int)WC_L32(rdi, 4));
    z2 = _mm512_set1_epi32((int)WC_L32(rdi, 8));
    z3 = _mm512_set1_epi32((int)WC_L32(rdi, 12));
    z4 = _mm512_set1_epi32((int)WC_L32(rdi, 16));
    z5 = _mm512_set1_epi32((int)WC_L32(rdi, 20));
    z6 = _mm512_set1_epi32((int)WC_L32(rdi, 24));
    z7 = _mm512_set1_epi32((int)WC_L32(rdi, 28));
    z8 = _mm512_set1_epi32((int)WC_L32(rdi, 32));
    z9 = _mm512_set1_epi32((int)WC_L32(rdi, 36));
    z10 = _mm512_set1_epi32((int)WC_L32(rdi, 40));
    z11 = _mm512_set1_epi32((int)WC_L32(rdi, 44));
    z12 = _mm512_set1_epi32((int)WC_L32(rdi, 48));
    z13 = _mm512_set1_epi32((int)WC_L32(rdi, 52));
    z14 = _mm512_set1_epi32((int)WC_L32(rdi, 56));
    z15 = _mm512_set1_epi32((int)WC_L32(rdi, 60));
    z12 = _mm512_add_epi32(z12, _mm512_loadu_si512((const void*)WC_PR(r9, 0)));
    _mm512_storeu_si512((void*)WC_PW(r11, 0), z0);
    _mm512_storeu_si512((void*)WC_PW(r11, 64), z1);
    _mm512_storeu_si512((void*)WC_PW(r11, 128), z2);
    _mm512_storeu_si512((void*)WC_PW(r11, 192), z3);
    _mm512_storeu_si512((void*)WC_PW(r11, 256), z4);
    _mm512_storeu_si512((void*)WC_PW(r11, 320), z5);
    _mm512_storeu_si512((void*)WC_PW(r11, 384), z6);
    _mm512_storeu_si512((void*)WC_PW(r11, 448), z7);
    _mm512_storeu_si512((void*)WC_PW(r11, 512), z8);
    _mm512_storeu_si512((void*)WC_PW(r11, 576), z9);
    _mm512_storeu_si512((void*)WC_PW(r11, 640), z10);
    _mm512_storeu_si512((void*)WC_PW(r11, 704), z11);
    _mm512_storeu_si512((void*)WC_PW(r11, 768), z12);
    _mm512_storeu_si512((void*)WC_PW(r11, 832), z13);
    _mm512_storeu_si512((void*)WC_PW(r11, 896), z14);
    _mm512_storeu_si512((void*)WC_PW(r11, 960), z15);
L_cp512_dstart:
    z16 = _mm512_loadu_si512((const void*)WC_PR(rsi, 752));
    z17 = _mm512_loadu_si512((const void*)WC_PR(rsi, 816));
    z18 = _mm512_loadu_si512((const void*)WC_PR(rsi, 880));
    z19 = _mm512_set1_epi64((long long)WC_L64(rsi, 720));
    z20 = _mm512_set1_epi64((long long)WC_L64(rsi, 728));
    z21 = _mm512_set1_epi64((long long)WC_L64(rsi, 736));
    z30 = _mm512_slli_epi64(z20, 2);
    z22 = _mm512_slli_epi64(z20, 4);
    z22 = _mm512_add_epi64(z22, z30);
    z30 = _mm512_slli_epi64(z21, 2);
    z23 = _mm512_slli_epi64(z21, 4);
    z23 = _mm512_add_epi64(z23, z30);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rdx, 0));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rdx, 64));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rdx, 128));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rdx, 192));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rdx, 256));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rdx, 320));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rdx, 384));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rdx, 448));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rdx, 512));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rdx, 576));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rdx, 640));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rdx, 704));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rdx, 768));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rdx, 832));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z27 = _mm512_loadu_si512((const void*)WC_PR(rdx, 896));
    z28 = _mm512_loadu_si512((const void*)WC_PR(rdx, 960));
    z29 = _mm512_loadu_si512((const void*)WC_PR(rax, 192));
    z29 = _mm512_permutex2var_epi64(z27, z29, z28);
    z30 = _mm512_loadu_si512((const void*)WC_PR(rax, 256));
    z30 = _mm512_permutex2var_epi64(z27, z30, z28);
    z24 = _mm512_and_si512(z29, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z27 = _mm512_srli_epi64(z29, 44);
    z28 = _mm512_and_si512(z30, _mm512_loadu_si512((const void*)WC_PR(rax,
        64)));
    z28 = _mm512_slli_epi64(z28, 20);
    z25 = _mm512_or_si512(z28, z27);
    z26 = _mm512_srli_epi64(z30, 24);
    z26 = _mm512_or_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax,
        128)));
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z15 = _mm512_rol_epi32(z15, 16);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 12);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z0 = _mm512_add_epi32(z0, z4);
    z1 = _mm512_add_epi32(z1, z5);
    z2 = _mm512_add_epi32(z2, z6);
    z3 = _mm512_add_epi32(z3, z7);
    z12 = _mm512_xor_si512(z12, z0);
    z13 = _mm512_xor_si512(z13, z1);
    z14 = _mm512_xor_si512(z14, z2);
    z15 = _mm512_xor_si512(z15, z3);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z8 = _mm512_add_epi32(z8, z12);
    z9 = _mm512_add_epi32(z9, z13);
    z10 = _mm512_add_epi32(z10, z14);
    z11 = _mm512_add_epi32(z11, z15);
    z4 = _mm512_xor_si512(z4, z8);
    z5 = _mm512_xor_si512(z5, z9);
    z6 = _mm512_xor_si512(z6, z10);
    z7 = _mm512_xor_si512(z7, z11);
    z4 = _mm512_rol_epi32(z4, 7);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 16);
    z12 = _mm512_rol_epi32(z12, 16);
    z13 = _mm512_rol_epi32(z13, 16);
    z14 = _mm512_rol_epi32(z14, 16);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 12);
    z6 = _mm512_rol_epi32(z6, 12);
    z7 = _mm512_rol_epi32(z7, 12);
    z4 = _mm512_rol_epi32(z4, 12);
    z0 = _mm512_add_epi32(z0, z5);
    z1 = _mm512_add_epi32(z1, z6);
    z2 = _mm512_add_epi32(z2, z7);
    z3 = _mm512_add_epi32(z3, z4);
    z15 = _mm512_xor_si512(z15, z0);
    z12 = _mm512_xor_si512(z12, z1);
    z13 = _mm512_xor_si512(z13, z2);
    z14 = _mm512_xor_si512(z14, z3);
    z15 = _mm512_rol_epi32(z15, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z10 = _mm512_add_epi32(z10, z15);
    z11 = _mm512_add_epi32(z11, z12);
    z8 = _mm512_add_epi32(z8, z13);
    z9 = _mm512_add_epi32(z9, z14);
    z5 = _mm512_xor_si512(z5, z10);
    z6 = _mm512_xor_si512(z6, z11);
    z7 = _mm512_xor_si512(z7, z8);
    z4 = _mm512_xor_si512(z4, z9);
    z5 = _mm512_rol_epi32(z5, 7);
    z6 = _mm512_rol_epi32(z6, 7);
    z7 = _mm512_rol_epi32(z7, 7);
    z4 = _mm512_rol_epi32(z4, 7);
    z0 = _mm512_add_epi32(z0, _mm512_loadu_si512((const void*)WC_PR(r11, 0)));
    z1 = _mm512_add_epi32(z1, _mm512_loadu_si512((const void*)WC_PR(r11, 64)));
    z2 = _mm512_add_epi32(z2, _mm512_loadu_si512((const void*)WC_PR(r11, 128)));
    z3 = _mm512_add_epi32(z3, _mm512_loadu_si512((const void*)WC_PR(r11, 192)));
    z4 = _mm512_add_epi32(z4, _mm512_loadu_si512((const void*)WC_PR(r11, 256)));
    z5 = _mm512_add_epi32(z5, _mm512_loadu_si512((const void*)WC_PR(r11, 320)));
    z6 = _mm512_add_epi32(z6, _mm512_loadu_si512((const void*)WC_PR(r11, 384)));
    z7 = _mm512_add_epi32(z7, _mm512_loadu_si512((const void*)WC_PR(r11, 448)));
    z8 = _mm512_add_epi32(z8, _mm512_loadu_si512((const void*)WC_PR(r11, 512)));
    z9 = _mm512_add_epi32(z9, _mm512_loadu_si512((const void*)WC_PR(r11, 576)));
    z10 = _mm512_add_epi32(z10, _mm512_loadu_si512((const void*)WC_PR(r11,
        640)));
    z11 = _mm512_add_epi32(z11, _mm512_loadu_si512((const void*)WC_PR(r11,
        704)));
    z12 = _mm512_add_epi32(z12, _mm512_loadu_si512((const void*)WC_PR(r11,
        768)));
    z13 = _mm512_add_epi32(z13, _mm512_loadu_si512((const void*)WC_PR(r11,
        832)));
    z14 = _mm512_add_epi32(z14, _mm512_loadu_si512((const void*)WC_PR(r11,
        896)));
    z15 = _mm512_add_epi32(z15, _mm512_loadu_si512((const void*)WC_PR(r11,
        960)));
    _mm512_storeu_si512((void*)WC_PW(rsi, 752), z16);
    _mm512_storeu_si512((void*)WC_PW(rsi, 816), z17);
    _mm512_storeu_si512((void*)WC_PW(rsi, 880), z18);
    z16 = _mm512_unpacklo_epi32(z0, z1);
    z17 = _mm512_unpackhi_epi32(z0, z1);
    z18 = _mm512_unpacklo_epi32(z2, z3);
    z19 = _mm512_unpackhi_epi32(z2, z3);
    z20 = _mm512_unpacklo_epi32(z4, z5);
    z21 = _mm512_unpackhi_epi32(z4, z5);
    z22 = _mm512_unpacklo_epi32(z6, z7);
    z23 = _mm512_unpackhi_epi32(z6, z7);
    z24 = _mm512_unpacklo_epi32(z8, z9);
    z25 = _mm512_unpackhi_epi32(z8, z9);
    z26 = _mm512_unpacklo_epi32(z10, z11);
    z27 = _mm512_unpackhi_epi32(z10, z11);
    z28 = _mm512_unpacklo_epi32(z12, z13);
    z29 = _mm512_unpackhi_epi32(z12, z13);
    z30 = _mm512_unpacklo_epi32(z14, z15);
    z31 = _mm512_unpackhi_epi32(z14, z15);
    z0 = _mm512_unpacklo_epi64(z16, z18);
    z1 = _mm512_unpackhi_epi64(z16, z18);
    z2 = _mm512_unpacklo_epi64(z17, z19);
    z3 = _mm512_unpackhi_epi64(z17, z19);
    z4 = _mm512_unpacklo_epi64(z20, z22);
    z5 = _mm512_unpackhi_epi64(z20, z22);
    z6 = _mm512_unpacklo_epi64(z21, z23);
    z7 = _mm512_unpackhi_epi64(z21, z23);
    z8 = _mm512_unpacklo_epi64(z24, z26);
    z9 = _mm512_unpackhi_epi64(z24, z26);
    z10 = _mm512_unpacklo_epi64(z25, z27);
    z11 = _mm512_unpackhi_epi64(z25, z27);
    z12 = _mm512_unpacklo_epi64(z28, z30);
    z13 = _mm512_unpackhi_epi64(z28, z30);
    z14 = _mm512_unpacklo_epi64(z29, z31);
    z15 = _mm512_unpackhi_epi64(z29, z31);
    z16 = _mm512_shuffle_i32x4(z0, z4, 0x44);
    z17 = _mm512_shuffle_i32x4(z0, z4, 0xee);
    z18 = _mm512_shuffle_i32x4(z8, z12, 0x44);
    z19 = _mm512_shuffle_i32x4(z8, z12, 0xee);
    z20 = _mm512_shuffle_i32x4(z16, z18, 0x88);
    z21 = _mm512_shuffle_i32x4(z16, z18, 0xdd);
    z22 = _mm512_shuffle_i32x4(z17, z19, 0x88);
    z23 = _mm512_shuffle_i32x4(z17, z19, 0xdd);
    z20 = _mm512_xor_si512(z20, _mm512_loadu_si512((const void*)WC_PR(rdx, 0)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 0), z20);
    z21 = _mm512_xor_si512(z21, _mm512_loadu_si512((const void*)WC_PR(rdx,
        256)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 256), z21);
    z22 = _mm512_xor_si512(z22, _mm512_loadu_si512((const void*)WC_PR(rdx,
        512)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 512), z22);
    z23 = _mm512_xor_si512(z23, _mm512_loadu_si512((const void*)WC_PR(rdx,
        768)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 768), z23);
    z16 = _mm512_shuffle_i32x4(z1, z5, 0x44);
    z17 = _mm512_shuffle_i32x4(z1, z5, 0xee);
    z18 = _mm512_shuffle_i32x4(z9, z13, 0x44);
    z19 = _mm512_shuffle_i32x4(z9, z13, 0xee);
    z20 = _mm512_shuffle_i32x4(z16, z18, 0x88);
    z21 = _mm512_shuffle_i32x4(z16, z18, 0xdd);
    z22 = _mm512_shuffle_i32x4(z17, z19, 0x88);
    z23 = _mm512_shuffle_i32x4(z17, z19, 0xdd);
    z20 = _mm512_xor_si512(z20, _mm512_loadu_si512((const void*)WC_PR(rdx,
        64)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 64), z20);
    z21 = _mm512_xor_si512(z21, _mm512_loadu_si512((const void*)WC_PR(rdx,
        320)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 320), z21);
    z22 = _mm512_xor_si512(z22, _mm512_loadu_si512((const void*)WC_PR(rdx,
        576)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 576), z22);
    z23 = _mm512_xor_si512(z23, _mm512_loadu_si512((const void*)WC_PR(rdx,
        832)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 832), z23);
    z16 = _mm512_shuffle_i32x4(z2, z6, 0x44);
    z17 = _mm512_shuffle_i32x4(z2, z6, 0xee);
    z18 = _mm512_shuffle_i32x4(z10, z14, 0x44);
    z19 = _mm512_shuffle_i32x4(z10, z14, 0xee);
    z20 = _mm512_shuffle_i32x4(z16, z18, 0x88);
    z21 = _mm512_shuffle_i32x4(z16, z18, 0xdd);
    z22 = _mm512_shuffle_i32x4(z17, z19, 0x88);
    z23 = _mm512_shuffle_i32x4(z17, z19, 0xdd);
    z20 = _mm512_xor_si512(z20, _mm512_loadu_si512((const void*)WC_PR(rdx,
        128)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 128), z20);
    z21 = _mm512_xor_si512(z21, _mm512_loadu_si512((const void*)WC_PR(rdx,
        384)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 384), z21);
    z22 = _mm512_xor_si512(z22, _mm512_loadu_si512((const void*)WC_PR(rdx,
        640)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 640), z22);
    z23 = _mm512_xor_si512(z23, _mm512_loadu_si512((const void*)WC_PR(rdx,
        896)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 896), z23);
    z16 = _mm512_shuffle_i32x4(z3, z7, 0x44);
    z17 = _mm512_shuffle_i32x4(z3, z7, 0xee);
    z18 = _mm512_shuffle_i32x4(z11, z15, 0x44);
    z19 = _mm512_shuffle_i32x4(z11, z15, 0xee);
    z20 = _mm512_shuffle_i32x4(z16, z18, 0x88);
    z21 = _mm512_shuffle_i32x4(z16, z18, 0xdd);
    z22 = _mm512_shuffle_i32x4(z17, z19, 0x88);
    z23 = _mm512_shuffle_i32x4(z17, z19, 0xdd);
    z20 = _mm512_xor_si512(z20, _mm512_loadu_si512((const void*)WC_PR(rdx,
        192)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 192), z20);
    z21 = _mm512_xor_si512(z21, _mm512_loadu_si512((const void*)WC_PR(rdx,
        448)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 448), z21);
    z22 = _mm512_xor_si512(z22, _mm512_loadu_si512((const void*)WC_PR(rdx,
        704)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 704), z22);
    z23 = _mm512_xor_si512(z23, _mm512_loadu_si512((const void*)WC_PR(rdx,
        960)));
    _mm512_storeu_si512((void*)WC_PW(rcx, 960), z23);
    z12 = _mm512_loadu_si512((const void*)WC_PR(r11, 768));
    z12 = _mm512_add_epi32(z12, _mm512_loadu_si512((const void*)WC_PR(rax,
        320)));
    _mm512_storeu_si512((void*)WC_PW(r11, 768), z12);
    z0 = _mm512_loadu_si512((const void*)WC_PR(r11, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(r11, 64));
    z2 = _mm512_loadu_si512((const void*)WC_PR(r11, 128));
    z3 = _mm512_loadu_si512((const void*)WC_PR(r11, 192));
    z4 = _mm512_loadu_si512((const void*)WC_PR(r11, 256));
    z5 = _mm512_loadu_si512((const void*)WC_PR(r11, 320));
    z6 = _mm512_loadu_si512((const void*)WC_PR(r11, 384));
    z7 = _mm512_loadu_si512((const void*)WC_PR(r11, 448));
    z8 = _mm512_loadu_si512((const void*)WC_PR(r11, 512));
    z9 = _mm512_loadu_si512((const void*)WC_PR(r11, 576));
    z10 = _mm512_loadu_si512((const void*)WC_PR(r11, 640));
    z11 = _mm512_loadu_si512((const void*)WC_PR(r11, 704));
    z12 = _mm512_loadu_si512((const void*)WC_PR(r11, 768));
    z13 = _mm512_loadu_si512((const void*)WC_PR(r11, 832));
    z14 = _mm512_loadu_si512((const void*)WC_PR(r11, 896));
    z15 = _mm512_loadu_si512((const void*)WC_PR(r11, 960));
    rdx = (word64)(rdx + 0x400);
    rcx = (word64)(rcx + 0x400);
    r8 = (word32)((word32)r8 - 0x400);
    if (((word32)r8) != (0)) {
        goto L_cp512_dstart;
    }
    z16 = _mm512_loadu_si512((const void*)WC_PR(rsi, 752));
    z17 = _mm512_loadu_si512((const void*)WC_PR(rsi, 816));
    z18 = _mm512_loadu_si512((const void*)WC_PR(rsi, 880));
    z24 = _mm512_loadu_si512((const void*)WC_PR(rsi, 224));
    z25 = _mm512_loadu_si512((const void*)WC_PR(rsi, 288));
    z26 = _mm512_loadu_si512((const void*)WC_PR(rsi, 624));
    z27 = _mm512_loadu_si512((const void*)WC_PR(rsi, 688));
    z28 = _mm512_loadu_si512((const void*)WC_PR(r10, 0));
    z28 = _mm512_permutex2var_epi64(z26, z28, z27);
    z29 = _mm512_loadu_si512((const void*)WC_PR(r10, 0));
    z29 = _mm512_permutex2var_epi64(z24, z29, z25);
    z19 = _mm512_inserti64x4(z28, _mm512_castsi512_si256(z29), 1);
    z28 = _mm512_loadu_si512((const void*)WC_PR(r10, 64));
    z28 = _mm512_permutex2var_epi64(z26, z28, z27);
    z29 = _mm512_loadu_si512((const void*)WC_PR(r10, 64));
    z29 = _mm512_permutex2var_epi64(z24, z29, z25);
    z20 = _mm512_inserti64x4(z28, _mm512_castsi512_si256(z29), 1);
    z28 = _mm512_loadu_si512((const void*)WC_PR(r10, 128));
    z28 = _mm512_permutex2var_epi64(z26, z28, z27);
    z29 = _mm512_loadu_si512((const void*)WC_PR(r10, 128));
    z29 = _mm512_permutex2var_epi64(z24, z29, z25);
    z21 = _mm512_inserti64x4(z28, _mm512_castsi512_si256(z29), 1);
    z30 = _mm512_slli_epi64(z20, 2);
    z22 = _mm512_slli_epi64(z20, 4);
    z22 = _mm512_add_epi64(z22, z30);
    z30 = _mm512_slli_epi64(z21, 2);
    z23 = _mm512_slli_epi64(z21, 4);
    z23 = _mm512_add_epi64(z23, z30);
    z24 = _mm512_setzero_si512();
    z25 = _mm512_setzero_si512();
    z26 = _mm512_setzero_si512();
    z27 = _mm512_setzero_si512();
    z28 = _mm512_setzero_si512();
    z29 = _mm512_setzero_si512();
    z24 = _mm512_madd52lo_epu64(z24, z16, z19);
    z24 = _mm512_madd52lo_epu64(z24, z17, z23);
    z24 = _mm512_madd52lo_epu64(z24, z18, z22);
    z27 = _mm512_madd52hi_epu64(z27, z16, z19);
    z27 = _mm512_madd52hi_epu64(z27, z17, z23);
    z27 = _mm512_madd52hi_epu64(z27, z18, z22);
    z25 = _mm512_madd52lo_epu64(z25, z16, z20);
    z25 = _mm512_madd52lo_epu64(z25, z17, z19);
    z25 = _mm512_madd52lo_epu64(z25, z18, z23);
    z28 = _mm512_madd52hi_epu64(z28, z16, z20);
    z28 = _mm512_madd52hi_epu64(z28, z17, z19);
    z28 = _mm512_madd52hi_epu64(z28, z18, z23);
    z26 = _mm512_madd52lo_epu64(z26, z16, z21);
    z26 = _mm512_madd52lo_epu64(z26, z17, z20);
    z26 = _mm512_madd52lo_epu64(z26, z18, z19);
    z29 = _mm512_madd52hi_epu64(z29, z16, z21);
    z29 = _mm512_madd52hi_epu64(z29, z17, z20);
    z29 = _mm512_madd52hi_epu64(z29, z18, z19);
    z30 = _mm512_slli_epi64(z27, 8);
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_slli_epi64(z28, 8);
    z26 = _mm512_add_epi64(z30, z26);
    z31 = _mm512_slli_epi64(z29, 8);
    z30 = _mm512_slli_epi64(z31, 2);
    z31 = _mm512_slli_epi64(z31, 4);
    z31 = _mm512_add_epi64(z31, z30);
    z24 = _mm512_add_epi64(z31, z24);
    z30 = _mm512_srli_epi64(z24, 44);
    z16 = _mm512_and_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z25 = _mm512_add_epi64(z30, z25);
    z30 = _mm512_srli_epi64(z25, 44);
    z17 = _mm512_and_si512(z25, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z26 = _mm512_add_epi64(z30, z26);
    z30 = _mm512_srli_epi64(z26, 44);
    z18 = _mm512_and_si512(z26, _mm512_loadu_si512((const void*)WC_PR(rax, 0)));
    z31 = _mm512_slli_epi64(z30, 2);
    z30 = _mm512_slli_epi64(z30, 4);
    z30 = _mm512_add_epi64(z30, z31);
    z16 = _mm512_add_epi64(z30, z16);
    z24 = _mm512_shuffle_i64x2(z16, z16, 0x4e);
    z25 = _mm512_shuffle_i64x2(z17, z17, 0x4e);
    z26 = _mm512_shuffle_i64x2(z18, z18, 0x4e);
    z16 = _mm512_add_epi64(z24, z16);
    z17 = _mm512_add_epi64(z25, z17);
    z18 = _mm512_add_epi64(z26, z18);
    z24 = _mm512_bsrli_epi128(z16, 8);
    z25 = _mm512_bsrli_epi128(z17, 8);
    z26 = _mm512_bsrli_epi128(z18, 8);
    z16 = _mm512_add_epi64(z24, z16);
    z17 = _mm512_add_epi64(z25, z17);
    z18 = _mm512_add_epi64(z26, z18);
    z24 = _mm512_permutex_epi64(z16, 2);
    z25 = _mm512_permutex_epi64(z17, 2);
    z26 = _mm512_permutex_epi64(z18, 2);
    z16 = _mm512_add_epi64(z24, z16);
    z17 = _mm512_add_epi64(z25, z17);
    z18 = _mm512_add_epi64(z26, z18);
    r12 = (word64)((word64)_mm_cvtsi128_si64(_mm512_castsi512_si128(z16)));
    r13 = (word64)((word64)_mm_cvtsi128_si64(_mm512_castsi512_si128(z17)));
    r14 = (word64)((word64)_mm_cvtsi128_si64(_mm512_castsi512_si128(z18)));
    r10 = (word64)(r13);
    r10 = (word64)(r10 >> 20);
    r11 = (word64)(r14);
    r11 = (word64)(r11 >> 40);
    rax = (word64)(r12);
    r12 = (word64)(r13);
    r12 = (word64)(r12 << 44);
    cf = _addcarry_u64(0, rax, r12, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    r12 = (word64)(r14);
    r12 = (word64)(r12 << 24);
    cf = _addcarry_u64(0, r10, r12, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    r9 = (word64)(r11);
    r11 = (word64)(r11 & 3);
    r9 = (word64)(r9 >> 2);
    r9 = (word64)(r9 + r9 * 4);
    cf = _addcarry_u64(0, rax, r9, (unsigned long long*)&rax);
    cf = _addcarry_u64(cf, r10, 0, (unsigned long long*)&r10);
    cf = _addcarry_u64(cf, r11, 0, (unsigned long long*)&r11);
    r12 = (word64)(WC_L64(rsi, 24));
    WC_S64(rsi, 64) = (word64)(r12);
    r12 = (word64)(WC_L64(rsi, 32));
    WC_S64(rsi, 72) = (word64)(r12);
    r12 = (word64)(WC_L64(rsi, 40));
    WC_S64(rsi, 80) = (word64)(r12);
    WC_S64(rsi, 24) = (word64)(rax);
    WC_S64(rsi, 32) = (word64)(r10);
    WC_S64(rsi, 40) = (word64)(r11);
    WC_S32(rdi, 48) = (word32)_mm_cvtsi128_si32(_mm512_castsi512_si128(z12));
}

#endif /* HAVE_INTEL_AVX512 */
#ifdef HAVE_INTEL_AVX2
XALIGNED(32) static const word64 L_chacha20_poly1305_small_enc_rotl8[]
    WC_X64I_UNUSED = {
    0x0605040702010003ULL, 0x0e0d0c0f0a09080bULL,
    0x0605040702010003ULL, 0x0e0d0c0f0a09080bULL,
};

XALIGNED(32) static const word64 L_chacha20_poly1305_small_enc_rotl16[]
    WC_X64I_UNUSED = {
    0x0504070601000302ULL, 0x0d0c0f0e09080b0aULL,
    0x0504070601000302ULL, 0x0d0c0f0e09080b0aULL,
};

XALIGNED(32) static const word64 L_chacha20_poly1305_small_enc_ymm_inc[]
    WC_X64I_UNUSED = {
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000001ULL, 0x0000000000000000ULL,
};

WC_X64I_TARGET("avx2")
WOLFSSL_LOCAL void chacha20_poly1305_small_enc(ChaCha* chacha, Poly1305* poly,
    const byte* m, byte* c, word32 mLen, const byte* aad, word32 aadLen,
    byte* tag)
{
    word64 rdi, rsi, rdx, rcx, r8, r9, rsp, rax, r11, r12, r13, rbp = 0,
           rbx = 0, r10 = 0, r14 = 0, r15 = 0;
    __m128i x4 = _mm_setzero_si128(), x5 = _mm_setzero_si128(),
            x6 = _mm_setzero_si128(), x7 = _mm_setzero_si128();
    __m256i y0, y1, y2, y3, y8 = _mm256_setzero_si256(), y10, y11, y12, y13;
    XALIGNED(32) WC_X64I_SLOT stk[24];
    word64 zf1;
    word64 zf2;
    unsigned char cf;

    rdi = (word64)(size_t)chacha;
    rsi = (word64)(size_t)poly;
    rdx = (word64)(size_t)m;
    rcx = (word64)(size_t)c;
    r8 = (word64)(word32)mLen;
    r9 = (word64)(size_t)aad;

    rsp = (word64)(size_t)stk + 192;
    rsp = (word64)(rsp - 192);
    rax = (word32)((word32)aadLen);
    WC_S64(rsp, 128) = (word64)(rax);
    rax = (word64)(tag);
    WC_S64(rsp, 152) = (word64)(rax);
    WC_S64(rsp, 136) = (word64)(rcx);
    rax = (word64)(r8);
    WC_S64(rsp, 144) = (word64)(rax);
    r11 = (word64)((word64)(size_t)L_chacha20_poly1305_small_enc_rotl8);
    r12 = (word64)((word64)(size_t)L_chacha20_poly1305_small_enc_rotl16);
    r13 = (word64)((word64)(size_t)L_chacha20_poly1305_small_enc_ymm_inc);
    y0 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdi,
        0)));
    y1 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdi,
        16)));
    y2 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdi,
        32)));
    y3 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdi,
        48)));
    y3 = _mm256_add_epi32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(r13,
        0)));
    y10 = y0;
    y11 = y1;
    y12 = y2;
    y13 = y3;
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(0xa) & 0xff);
L_c20p1305_small_enc_crypt2_start:
    y0 = _mm256_add_epi32(y0, y1);
    y3 = _mm256_xor_si256(y3, y0);
    y3 = _mm256_shuffle_epi8(y3, _mm256_loadu_si256((const __m256i*)WC_PR(r12,
        0)));
    y2 = _mm256_add_epi32(y2, y3);
    y1 = _mm256_xor_si256(y1, y2);
    y8 = _mm256_srli_epi32(y1, 20);
    y1 = _mm256_slli_epi32(y1, 12);
    y1 = _mm256_xor_si256(y1, y8);
    y0 = _mm256_add_epi32(y0, y1);
    y3 = _mm256_xor_si256(y3, y0);
    y3 = _mm256_shuffle_epi8(y3, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        0)));
    y2 = _mm256_add_epi32(y2, y3);
    y1 = _mm256_xor_si256(y1, y2);
    y8 = _mm256_srli_epi32(y1, 25);
    y1 = _mm256_slli_epi32(y1, 7);
    y1 = _mm256_xor_si256(y1, y8);
    y1 = _mm256_shuffle_epi32(y1, 0x39);
    y2 = _mm256_shuffle_epi32(y2, 0x4e);
    y3 = _mm256_shuffle_epi32(y3, 0x93);
    y0 = _mm256_add_epi32(y0, y1);
    y3 = _mm256_xor_si256(y3, y0);
    y3 = _mm256_shuffle_epi8(y3, _mm256_loadu_si256((const __m256i*)WC_PR(r12,
        0)));
    y2 = _mm256_add_epi32(y2, y3);
    y1 = _mm256_xor_si256(y1, y2);
    y8 = _mm256_srli_epi32(y1, 20);
    y1 = _mm256_slli_epi32(y1, 12);
    y1 = _mm256_xor_si256(y1, y8);
    y0 = _mm256_add_epi32(y0, y1);
    y3 = _mm256_xor_si256(y3, y0);
    y3 = _mm256_shuffle_epi8(y3, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        0)));
    y2 = _mm256_add_epi32(y2, y3);
    y1 = _mm256_xor_si256(y1, y2);
    y8 = _mm256_srli_epi32(y1, 25);
    y1 = _mm256_slli_epi32(y1, 7);
    y1 = _mm256_xor_si256(y1, y8);
    y1 = _mm256_shuffle_epi32(y1, 0x93);
    y2 = _mm256_shuffle_epi32(y2, 0x4e);
    y3 = _mm256_shuffle_epi32(y3, 0x39);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)((byte)rcx - 1) & 0xff);
    if (((byte)rcx) != (0)) {
        goto L_c20p1305_small_enc_crypt2_start;
    }
    y0 = _mm256_add_epi32(y0, y10);
    y1 = _mm256_add_epi32(y1, y11);
    y2 = _mm256_add_epi32(y2, y12);
    y3 = _mm256_add_epi32(y3, y13);
    x4 = _mm256_extracti128_si256(y0, 1);
    x5 = _mm256_extracti128_si256(y1, 1);
    x6 = _mm256_extracti128_si256(y2, 1);
    x7 = _mm256_extracti128_si256(y3, 1);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), _mm256_castsi256_si128(y0));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 16), _mm256_castsi256_si128(y1));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 32), x4);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 48), x5);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 64), x6);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 80), x7);
    rcx = (word64)(WC_L64(rsp, 136));
    rbp = (word64)(WC_L64(rsp, 144));
    rbx = (word64)(rsp + 32);
L_chacha20_poly1305_small_enc_x16:
    if ((sword64)(rbp) < (sword64)(0x10)) {
        goto L_chacha20_poly1305_small_enc_xtail;
    }
    y8 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdx, 0)));
    y8 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y8),
        _mm_loadu_si128((const __m128i*)WC_PR(rbx, 0))));
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), _mm256_castsi256_si128(y8));
    rdx = (word64)(rdx + 0x10);
    rcx = (word64)(rcx + 0x10);
    rbx = (word64)(rbx + 0x10);
    rbp = (word64)(rbp - 0x10);
    goto L_chacha20_poly1305_small_enc_x16;
L_chacha20_poly1305_small_enc_xtail:
    if (((rbp & rbp)) == (0)) {
        goto L_chacha20_poly1305_small_enc_xdone;
    }
    rdi = (word64)(0);
L_chacha20_poly1305_small_enc_xbyte:
    if ((sword64)(rdi) >= (sword64)(rbp)) {
        goto L_chacha20_poly1305_small_enc_xdone;
    }
    rax = (word32)((word32)WC_L8(rdx, rdi));
    rax = (rax & ~(word64)0xff) | ((word64)(byte)((byte)rax ^ WC_L8(rbx,
        rdi)) & 0xff);
    WC_S8(rcx, rdi) = (byte)((byte)rax);
    rdi = (word64)(rdi + 1);
    goto L_chacha20_poly1305_small_enc_xbyte;
L_chacha20_poly1305_small_enc_xdone:
    r10 = (word64)(rsi);
    rax = (word64)(0xffffffc0fffffffULL);
    rdx = (word64)(0xffffffc0ffffffcULL);
    r11 = (word64)(WC_L64(rsp, 0));
    r11 = (word64)(r11 & rax);
    r12 = (word64)(WC_L64(rsp, 8));
    r12 = (word64)(r12 & rdx);
    rax = (word64)(WC_L64(rsp, 16));
    WC_S64(r10, 48) = (word64)(rax);
    rax = (word64)(WC_L64(rsp, 24));
    WC_S64(r10, 56) = (word64)(rax);
    rax = (word64)(0);
    WC_S64(r10, 352) = (word64)(rax);
    WC_S64(r10, 408) = (word64)(rax);
    WC_S64(r10, 360) = (word64)(r11);
    WC_S64(r10, 416) = (word64)(r12);
    rcx = (word64)(r11);
    rsi = (word64)(r12);
    rcx = (word64)(rcx + r11);
    rsi = (word64)(rsi + r12);
    WC_S64(r10, 368) = (word64)(rcx);
    WC_S64(r10, 424) = (word64)(rsi);
    rcx = (word64)(rcx + r11);
    rsi = (word64)(rsi + r12);
    WC_S64(r10, 376) = (word64)(rcx);
    WC_S64(r10, 432) = (word64)(rsi);
    rcx = (word64)(rcx + r11);
    rsi = (word64)(rsi + r12);
    WC_S64(r10, 384) = (word64)(rcx);
    WC_S64(r10, 440) = (word64)(rsi);
    rcx = (word64)(rcx + r11);
    rsi = (word64)(rsi + r12);
    WC_S64(r10, 392) = (word64)(rcx);
    WC_S64(r10, 448) = (word64)(rsi);
    rcx = (word64)(rcx + r11);
    rsi = (word64)(rsi + r12);
    WC_S64(r10, 400) = (word64)(rcx);
    WC_S64(r10, 456) = (word64)(rsi);
    r13 = (word64)(0);
    r14 = (word64)(0);
    r15 = (word64)(0);
    rbx = (word64)(r9);
    rbp = (word64)(WC_L64(rsp, 128));
L_c20p1305_small_aad_full:
    if ((sword64)(rbp) < (sword64)(0x10)) {
        goto L_c20p1305_small_aad_part;
    }
    rcx = (word64)(WC_L64(rbx, 0));
    rsi = (word64)(WC_L64(rbx, 8));
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rsi, (unsigned long long*)&r14);
    rax = (word64)(r12);
    cf = _addcarry_u64(cf, r15, 1, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rsi = (word64)(rax);
    rdi = (word64)(rdx);
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    rax = (word64)(r11);
    cf = _addcarry_u64(cf, rdi, rdx, (unsigned long long*)&rdi);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    rdi = (word64)(rdi + WC_L64(r10, r15 * 8 + 352));
    r8 = (word64)(rdx);
    cf = _addcarry_u64(0, rsi, r9, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rdi, rax, (unsigned long long*)&rdi);
    cf = _addcarry_u64(cf, r8, WC_L64(r10, r15 * 8 + 408), (
        unsigned long long*)&r8);
    r15 = (word64)(rdi);
    rdi = (word64)(rdi & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, rcx, rdi, (unsigned long long*)&rcx);
    r13 = (word64)(rdi);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    r13 = (word64)((r13 >> 2) | (r8 << 62));
    r8 = (word64)(r8 >> 2);
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    r14 = (word64)(rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    rbx = (word64)(rbx + 0x10);
    rbp = (word64)(rbp - 0x10);
    goto L_c20p1305_small_aad_full;
L_c20p1305_small_aad_part:
    if (((rbp & rbp)) == (0)) {
        goto L_c20p1305_small_aad_done;
    }
    rax = (word64)(0);
    WC_S64(rsp, 96) = (word64)(rax);
    WC_S64(rsp, 104) = (word64)(rax);
    r9 = (word64)(rsp + 96);
    if ((sword64)(rbp) < (sword64)(8)) {
        goto L_c20p1305_small_aad_c4;
    }
    rax = (word64)(WC_L64(rbx, 0));
    WC_S64(r9, 0) = (word64)(rax);
    rbx = (word64)(rbx + 8);
    r9 = (word64)(r9 + 8);
    rbp = (word64)(rbp - 8);
L_c20p1305_small_aad_c4:
    if ((sword64)(rbp) < (sword64)(4)) {
        goto L_c20p1305_small_aad_cby;
    }
    rax = (word32)(WC_L32(rbx, 0));
    WC_S32(r9, 0) = (word32)((word32)rax);
    rbx = (word64)(rbx + 4);
    r9 = (word64)(r9 + 4);
    rbp = (word64)(rbp - 4);
L_c20p1305_small_aad_cby:
    if (((rbp & rbp)) == (0)) {
        goto L_c20p1305_small_aad_cpyd;
    }
L_c20p1305_small_aad_cbyl:
    rax = (word32)((word32)WC_L8(rbx, 0));
    WC_S8(r9, 0) = (byte)((byte)rax);
    rbx = (word64)(rbx + 1);
    r9 = (word64)(r9 + 1);
    rbp = (word64)(rbp - 1);
    if ((rbp) != (0)) {
        goto L_c20p1305_small_aad_cbyl;
    }
L_c20p1305_small_aad_cpyd:
    rbx = (word64)(rsp + 96);
    rcx = (word64)(WC_L64(rbx, 0));
    rsi = (word64)(WC_L64(rbx, 8));
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rsi, (unsigned long long*)&r14);
    rax = (word64)(r12);
    cf = _addcarry_u64(cf, r15, 1, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rsi = (word64)(rax);
    rdi = (word64)(rdx);
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    rax = (word64)(r11);
    cf = _addcarry_u64(cf, rdi, rdx, (unsigned long long*)&rdi);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    rdi = (word64)(rdi + WC_L64(r10, r15 * 8 + 352));
    r8 = (word64)(rdx);
    cf = _addcarry_u64(0, rsi, r9, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rdi, rax, (unsigned long long*)&rdi);
    cf = _addcarry_u64(cf, r8, WC_L64(r10, r15 * 8 + 408), (
        unsigned long long*)&r8);
    r15 = (word64)(rdi);
    rdi = (word64)(rdi & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, rcx, rdi, (unsigned long long*)&rcx);
    r13 = (word64)(rdi);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    r13 = (word64)((r13 >> 2) | (r8 << 62));
    r8 = (word64)(r8 >> 2);
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    r14 = (word64)(rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
L_c20p1305_small_aad_done:
    rbx = (word64)(WC_L64(rsp, 136));
    rbp = (word64)(WC_L64(rsp, 144));
L_c20p1305_small_ct_full:
    if ((sword64)(rbp) < (sword64)(0x10)) {
        goto L_c20p1305_small_ct_part;
    }
    rcx = (word64)(WC_L64(rbx, 0));
    rsi = (word64)(WC_L64(rbx, 8));
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rsi, (unsigned long long*)&r14);
    rax = (word64)(r12);
    cf = _addcarry_u64(cf, r15, 1, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rsi = (word64)(rax);
    rdi = (word64)(rdx);
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    rax = (word64)(r11);
    cf = _addcarry_u64(cf, rdi, rdx, (unsigned long long*)&rdi);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    rdi = (word64)(rdi + WC_L64(r10, r15 * 8 + 352));
    r8 = (word64)(rdx);
    cf = _addcarry_u64(0, rsi, r9, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rdi, rax, (unsigned long long*)&rdi);
    cf = _addcarry_u64(cf, r8, WC_L64(r10, r15 * 8 + 408), (
        unsigned long long*)&r8);
    r15 = (word64)(rdi);
    rdi = (word64)(rdi & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, rcx, rdi, (unsigned long long*)&rcx);
    r13 = (word64)(rdi);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    r13 = (word64)((r13 >> 2) | (r8 << 62));
    r8 = (word64)(r8 >> 2);
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    r14 = (word64)(rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    rbx = (word64)(rbx + 0x10);
    rbp = (word64)(rbp - 0x10);
    goto L_c20p1305_small_ct_full;
L_c20p1305_small_ct_part:
    if (((rbp & rbp)) == (0)) {
        goto L_c20p1305_small_ct_done;
    }
    rax = (word64)(0);
    WC_S64(rsp, 96) = (word64)(rax);
    WC_S64(rsp, 104) = (word64)(rax);
    r9 = (word64)(rsp + 96);
    if ((sword64)(rbp) < (sword64)(8)) {
        goto L_c20p1305_small_ct_c4;
    }
    rax = (word64)(WC_L64(rbx, 0));
    WC_S64(r9, 0) = (word64)(rax);
    rbx = (word64)(rbx + 8);
    r9 = (word64)(r9 + 8);
    rbp = (word64)(rbp - 8);
L_c20p1305_small_ct_c4:
    if ((sword64)(rbp) < (sword64)(4)) {
        goto L_c20p1305_small_ct_cby;
    }
    rax = (word32)(WC_L32(rbx, 0));
    WC_S32(r9, 0) = (word32)((word32)rax);
    rbx = (word64)(rbx + 4);
    r9 = (word64)(r9 + 4);
    rbp = (word64)(rbp - 4);
L_c20p1305_small_ct_cby:
    if (((rbp & rbp)) == (0)) {
        goto L_c20p1305_small_ct_cpyd;
    }
L_c20p1305_small_ct_cbyl:
    rax = (word32)((word32)WC_L8(rbx, 0));
    WC_S8(r9, 0) = (byte)((byte)rax);
    rbx = (word64)(rbx + 1);
    r9 = (word64)(r9 + 1);
    rbp = (word64)(rbp - 1);
    if ((rbp) != (0)) {
        goto L_c20p1305_small_ct_cbyl;
    }
L_c20p1305_small_ct_cpyd:
    rbx = (word64)(rsp + 96);
    rcx = (word64)(WC_L64(rbx, 0));
    rsi = (word64)(WC_L64(rbx, 8));
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rsi, (unsigned long long*)&r14);
    rax = (word64)(r12);
    cf = _addcarry_u64(cf, r15, 1, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rsi = (word64)(rax);
    rdi = (word64)(rdx);
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    rax = (word64)(r11);
    cf = _addcarry_u64(cf, rdi, rdx, (unsigned long long*)&rdi);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    rdi = (word64)(rdi + WC_L64(r10, r15 * 8 + 352));
    r8 = (word64)(rdx);
    cf = _addcarry_u64(0, rsi, r9, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rdi, rax, (unsigned long long*)&rdi);
    cf = _addcarry_u64(cf, r8, WC_L64(r10, r15 * 8 + 408), (
        unsigned long long*)&r8);
    r15 = (word64)(rdi);
    rdi = (word64)(rdi & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, rcx, rdi, (unsigned long long*)&rcx);
    r13 = (word64)(rdi);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    r13 = (word64)((r13 >> 2) | (r8 << 62));
    r8 = (word64)(r8 >> 2);
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    r14 = (word64)(rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
L_c20p1305_small_ct_done:
    rax = (word64)(WC_L64(rsp, 128));
    WC_S64(rsp, 112) = (word64)(rax);
    rax = (word64)(WC_L64(rsp, 144));
    WC_S64(rsp, 120) = (word64)(rax);
    rbx = (word64)(rsp + 112);
    rcx = (word64)(WC_L64(rbx, 0));
    rsi = (word64)(WC_L64(rbx, 8));
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rsi, (unsigned long long*)&r14);
    rax = (word64)(r12);
    cf = _addcarry_u64(cf, r15, 1, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rsi = (word64)(rax);
    rdi = (word64)(rdx);
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    rax = (word64)(r11);
    cf = _addcarry_u64(cf, rdi, rdx, (unsigned long long*)&rdi);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    rdi = (word64)(rdi + WC_L64(r10, r15 * 8 + 352));
    r8 = (word64)(rdx);
    cf = _addcarry_u64(0, rsi, r9, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rdi, rax, (unsigned long long*)&rdi);
    cf = _addcarry_u64(cf, r8, WC_L64(r10, r15 * 8 + 408), (
        unsigned long long*)&r8);
    r15 = (word64)(rdi);
    rdi = (word64)(rdi & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, rcx, rdi, (unsigned long long*)&rcx);
    r13 = (word64)(rdi);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    r13 = (word64)((r13 >> 2) | (r8 << 62));
    r8 = (word64)(r8 >> 2);
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    r14 = (word64)(rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    rbx = (word64)(WC_L64(rsp, 152));
    rcx = (word64)(r15);
    r15 = (word64)(r15 & 3);
    rcx = (word64)(rcx >> 2);
    rcx = (word64)(rcx + rcx * 4);
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    rcx = (word64)(r13);
    rsi = (word64)(r14);
    rdi = (word64)(r15);
    cf = _addcarry_u64(0, rcx, 5, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, rsi, 0, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rdi, 0, (unsigned long long*)&rdi);
    zf1 = rdi;
    zf2 = 4;
    r13 = (rdi) == (4) ? rcx : r13;
    r14 = (zf1) == (zf2) ? rsi : r14;
    cf = _addcarry_u64(0, r13, WC_L64(r10, 48), (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, WC_L64(r10, 56), (unsigned long long*)&r14);
    WC_S64(rbx, 0) = (word64)(r13);
    WC_S64(rbx, 8) = (word64)(r14);
    y0 = _mm256_zextsi128_si256(_mm_setzero_si128());
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), _mm256_castsi256_si128(y0));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 16), _mm256_castsi256_si128(y0));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 32), _mm256_castsi256_si128(y0));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 48), _mm256_castsi256_si128(y0));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 64), _mm256_castsi256_si128(y0));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 80), _mm256_castsi256_si128(y0));
    (void)aadLen;
    (void)tag;
}

WC_X64I_TARGET("avx2")
WOLFSSL_LOCAL int chacha20_poly1305_small_dec(ChaCha* chacha, Poly1305* poly,
    const byte* in, byte* out, word32 ctLen, const byte* aad, word32 aadLen,
    const byte* tag)
{
    word64 rdi, rsi, rdx, rcx, r8, r9, rsp, rax, r11, r12, r13, r10 = 0,
           r14 = 0, r15 = 0, rbx = 0, rbp = 0;
    __m128i x4 = _mm_setzero_si128(), x5 = _mm_setzero_si128(),
            x6 = _mm_setzero_si128(), x7 = _mm_setzero_si128();
    __m256i y0, y1, y2, y3, y8 = _mm256_setzero_si256(), y10, y11, y12, y13;
    XALIGNED(32) WC_X64I_SLOT stk[24];
    word64 zf1;
    word64 zf2;
    unsigned char cf;

    rdi = (word64)(size_t)chacha;
    rsi = (word64)(size_t)poly;
    rdx = (word64)(size_t)in;
    rcx = (word64)(size_t)out;
    r8 = (word64)(word32)ctLen;
    r9 = (word64)(size_t)aad;

    rsp = (word64)(size_t)stk + 192;
    rsp = (word64)(rsp - 168);
    rax = (word32)((word32)aadLen);
    WC_S64(rsp, 128) = (word64)(rax);
    rax = (word64)(tag);
    WC_S64(rsp, 144) = (word64)(rax);
    rax = (word64)(r8);
    WC_S64(rsp, 136) = (word64)(rax);
    rax = (word64)(rdx);
    WC_S64(rsp, 152) = (word64)(rax);
    rax = (word64)(rcx);
    WC_S64(rsp, 160) = (word64)(rax);
    r11 = (word64)((word64)(size_t)L_chacha20_poly1305_small_enc_rotl8);
    r12 = (word64)((word64)(size_t)L_chacha20_poly1305_small_enc_rotl16);
    r13 = (word64)((word64)(size_t)L_chacha20_poly1305_small_enc_ymm_inc);
    y0 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdi,
        0)));
    y1 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdi,
        16)));
    y2 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdi,
        32)));
    y3 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdi,
        48)));
    y3 = _mm256_add_epi32(y3, _mm256_loadu_si256((const __m256i*)WC_PR(r13,
        0)));
    y10 = y0;
    y11 = y1;
    y12 = y2;
    y13 = y3;
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(0xa) & 0xff);
L_c20p1305_small_dec_crypt2_start:
    y0 = _mm256_add_epi32(y0, y1);
    y3 = _mm256_xor_si256(y3, y0);
    y3 = _mm256_shuffle_epi8(y3, _mm256_loadu_si256((const __m256i*)WC_PR(r12,
        0)));
    y2 = _mm256_add_epi32(y2, y3);
    y1 = _mm256_xor_si256(y1, y2);
    y8 = _mm256_srli_epi32(y1, 20);
    y1 = _mm256_slli_epi32(y1, 12);
    y1 = _mm256_xor_si256(y1, y8);
    y0 = _mm256_add_epi32(y0, y1);
    y3 = _mm256_xor_si256(y3, y0);
    y3 = _mm256_shuffle_epi8(y3, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        0)));
    y2 = _mm256_add_epi32(y2, y3);
    y1 = _mm256_xor_si256(y1, y2);
    y8 = _mm256_srli_epi32(y1, 25);
    y1 = _mm256_slli_epi32(y1, 7);
    y1 = _mm256_xor_si256(y1, y8);
    y1 = _mm256_shuffle_epi32(y1, 0x39);
    y2 = _mm256_shuffle_epi32(y2, 0x4e);
    y3 = _mm256_shuffle_epi32(y3, 0x93);
    y0 = _mm256_add_epi32(y0, y1);
    y3 = _mm256_xor_si256(y3, y0);
    y3 = _mm256_shuffle_epi8(y3, _mm256_loadu_si256((const __m256i*)WC_PR(r12,
        0)));
    y2 = _mm256_add_epi32(y2, y3);
    y1 = _mm256_xor_si256(y1, y2);
    y8 = _mm256_srli_epi32(y1, 20);
    y1 = _mm256_slli_epi32(y1, 12);
    y1 = _mm256_xor_si256(y1, y8);
    y0 = _mm256_add_epi32(y0, y1);
    y3 = _mm256_xor_si256(y3, y0);
    y3 = _mm256_shuffle_epi8(y3, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        0)));
    y2 = _mm256_add_epi32(y2, y3);
    y1 = _mm256_xor_si256(y1, y2);
    y8 = _mm256_srli_epi32(y1, 25);
    y1 = _mm256_slli_epi32(y1, 7);
    y1 = _mm256_xor_si256(y1, y8);
    y1 = _mm256_shuffle_epi32(y1, 0x93);
    y2 = _mm256_shuffle_epi32(y2, 0x4e);
    y3 = _mm256_shuffle_epi32(y3, 0x39);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)((byte)rcx - 1) & 0xff);
    if (((byte)rcx) != (0)) {
        goto L_c20p1305_small_dec_crypt2_start;
    }
    y0 = _mm256_add_epi32(y0, y10);
    y1 = _mm256_add_epi32(y1, y11);
    y2 = _mm256_add_epi32(y2, y12);
    y3 = _mm256_add_epi32(y3, y13);
    x4 = _mm256_extracti128_si256(y0, 1);
    x5 = _mm256_extracti128_si256(y1, 1);
    x6 = _mm256_extracti128_si256(y2, 1);
    x7 = _mm256_extracti128_si256(y3, 1);
    r10 = (word64)(rsi);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), _mm256_castsi256_si128(y0));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 16), _mm256_castsi256_si128(y1));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 32), x4);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 48), x5);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 64), x6);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 80), x7);
    rax = (word64)(0xffffffc0fffffffULL);
    rdx = (word64)(0xffffffc0ffffffcULL);
    r11 = (word64)(WC_L64(rsp, 0));
    r11 = (word64)(r11 & rax);
    r12 = (word64)(WC_L64(rsp, 8));
    r12 = (word64)(r12 & rdx);
    rax = (word64)(WC_L64(rsp, 16));
    WC_S64(r10, 48) = (word64)(rax);
    rax = (word64)(WC_L64(rsp, 24));
    WC_S64(r10, 56) = (word64)(rax);
    rax = (word64)(0);
    WC_S64(r10, 352) = (word64)(rax);
    WC_S64(r10, 408) = (word64)(rax);
    WC_S64(r10, 360) = (word64)(r11);
    WC_S64(r10, 416) = (word64)(r12);
    rcx = (word64)(r11);
    rsi = (word64)(r12);
    rcx = (word64)(rcx + r11);
    rsi = (word64)(rsi + r12);
    WC_S64(r10, 368) = (word64)(rcx);
    WC_S64(r10, 424) = (word64)(rsi);
    rcx = (word64)(rcx + r11);
    rsi = (word64)(rsi + r12);
    WC_S64(r10, 376) = (word64)(rcx);
    WC_S64(r10, 432) = (word64)(rsi);
    rcx = (word64)(rcx + r11);
    rsi = (word64)(rsi + r12);
    WC_S64(r10, 384) = (word64)(rcx);
    WC_S64(r10, 440) = (word64)(rsi);
    rcx = (word64)(rcx + r11);
    rsi = (word64)(rsi + r12);
    WC_S64(r10, 392) = (word64)(rcx);
    WC_S64(r10, 448) = (word64)(rsi);
    rcx = (word64)(rcx + r11);
    rsi = (word64)(rsi + r12);
    WC_S64(r10, 400) = (word64)(rcx);
    WC_S64(r10, 456) = (word64)(rsi);
    r13 = (word64)(0);
    r14 = (word64)(0);
    r15 = (word64)(0);
    rbx = (word64)(r9);
    rbp = (word64)(WC_L64(rsp, 128));
L_c20p1305_small_dec_aad_full:
    if ((sword64)(rbp) < (sword64)(0x10)) {
        goto L_c20p1305_small_dec_aad_part;
    }
    rcx = (word64)(WC_L64(rbx, 0));
    rsi = (word64)(WC_L64(rbx, 8));
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rsi, (unsigned long long*)&r14);
    rax = (word64)(r12);
    cf = _addcarry_u64(cf, r15, 1, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rsi = (word64)(rax);
    rdi = (word64)(rdx);
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    rax = (word64)(r11);
    cf = _addcarry_u64(cf, rdi, rdx, (unsigned long long*)&rdi);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    rdi = (word64)(rdi + WC_L64(r10, r15 * 8 + 352));
    r8 = (word64)(rdx);
    cf = _addcarry_u64(0, rsi, r9, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rdi, rax, (unsigned long long*)&rdi);
    cf = _addcarry_u64(cf, r8, WC_L64(r10, r15 * 8 + 408), (
        unsigned long long*)&r8);
    r15 = (word64)(rdi);
    rdi = (word64)(rdi & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, rcx, rdi, (unsigned long long*)&rcx);
    r13 = (word64)(rdi);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    r13 = (word64)((r13 >> 2) | (r8 << 62));
    r8 = (word64)(r8 >> 2);
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    r14 = (word64)(rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    rbx = (word64)(rbx + 0x10);
    rbp = (word64)(rbp - 0x10);
    goto L_c20p1305_small_dec_aad_full;
L_c20p1305_small_dec_aad_part:
    if (((rbp & rbp)) == (0)) {
        goto L_c20p1305_small_dec_aad_done;
    }
    rax = (word64)(0);
    WC_S64(rsp, 96) = (word64)(rax);
    WC_S64(rsp, 104) = (word64)(rax);
    r9 = (word64)(rsp + 96);
    if ((sword64)(rbp) < (sword64)(8)) {
        goto L_c20p1305_small_dec_aad_c4;
    }
    rax = (word64)(WC_L64(rbx, 0));
    WC_S64(r9, 0) = (word64)(rax);
    rbx = (word64)(rbx + 8);
    r9 = (word64)(r9 + 8);
    rbp = (word64)(rbp - 8);
L_c20p1305_small_dec_aad_c4:
    if ((sword64)(rbp) < (sword64)(4)) {
        goto L_c20p1305_small_dec_aad_cby;
    }
    rax = (word32)(WC_L32(rbx, 0));
    WC_S32(r9, 0) = (word32)((word32)rax);
    rbx = (word64)(rbx + 4);
    r9 = (word64)(r9 + 4);
    rbp = (word64)(rbp - 4);
L_c20p1305_small_dec_aad_cby:
    if (((rbp & rbp)) == (0)) {
        goto L_c20p1305_small_dec_aad_cpyd;
    }
L_c20p1305_small_dec_aad_cbyl:
    rax = (word32)((word32)WC_L8(rbx, 0));
    WC_S8(r9, 0) = (byte)((byte)rax);
    rbx = (word64)(rbx + 1);
    r9 = (word64)(r9 + 1);
    rbp = (word64)(rbp - 1);
    if ((rbp) != (0)) {
        goto L_c20p1305_small_dec_aad_cbyl;
    }
L_c20p1305_small_dec_aad_cpyd:
    rbx = (word64)(rsp + 96);
    rcx = (word64)(WC_L64(rbx, 0));
    rsi = (word64)(WC_L64(rbx, 8));
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rsi, (unsigned long long*)&r14);
    rax = (word64)(r12);
    cf = _addcarry_u64(cf, r15, 1, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rsi = (word64)(rax);
    rdi = (word64)(rdx);
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    rax = (word64)(r11);
    cf = _addcarry_u64(cf, rdi, rdx, (unsigned long long*)&rdi);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    rdi = (word64)(rdi + WC_L64(r10, r15 * 8 + 352));
    r8 = (word64)(rdx);
    cf = _addcarry_u64(0, rsi, r9, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rdi, rax, (unsigned long long*)&rdi);
    cf = _addcarry_u64(cf, r8, WC_L64(r10, r15 * 8 + 408), (
        unsigned long long*)&r8);
    r15 = (word64)(rdi);
    rdi = (word64)(rdi & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, rcx, rdi, (unsigned long long*)&rcx);
    r13 = (word64)(rdi);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    r13 = (word64)((r13 >> 2) | (r8 << 62));
    r8 = (word64)(r8 >> 2);
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    r14 = (word64)(rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
L_c20p1305_small_dec_aad_done:
    rbx = (word64)(WC_L64(rsp, 152));
    rbp = (word64)(WC_L64(rsp, 136));
L_c20p1305_small_dec_ct_full:
    if ((sword64)(rbp) < (sword64)(0x10)) {
        goto L_c20p1305_small_dec_ct_part;
    }
    rcx = (word64)(WC_L64(rbx, 0));
    rsi = (word64)(WC_L64(rbx, 8));
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rsi, (unsigned long long*)&r14);
    rax = (word64)(r12);
    cf = _addcarry_u64(cf, r15, 1, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rsi = (word64)(rax);
    rdi = (word64)(rdx);
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    rax = (word64)(r11);
    cf = _addcarry_u64(cf, rdi, rdx, (unsigned long long*)&rdi);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    rdi = (word64)(rdi + WC_L64(r10, r15 * 8 + 352));
    r8 = (word64)(rdx);
    cf = _addcarry_u64(0, rsi, r9, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rdi, rax, (unsigned long long*)&rdi);
    cf = _addcarry_u64(cf, r8, WC_L64(r10, r15 * 8 + 408), (
        unsigned long long*)&r8);
    r15 = (word64)(rdi);
    rdi = (word64)(rdi & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, rcx, rdi, (unsigned long long*)&rcx);
    r13 = (word64)(rdi);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    r13 = (word64)((r13 >> 2) | (r8 << 62));
    r8 = (word64)(r8 >> 2);
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    r14 = (word64)(rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    rbx = (word64)(rbx + 0x10);
    rbp = (word64)(rbp - 0x10);
    goto L_c20p1305_small_dec_ct_full;
L_c20p1305_small_dec_ct_part:
    if (((rbp & rbp)) == (0)) {
        goto L_c20p1305_small_dec_ct_done;
    }
    rax = (word64)(0);
    WC_S64(rsp, 96) = (word64)(rax);
    WC_S64(rsp, 104) = (word64)(rax);
    r9 = (word64)(rsp + 96);
    if ((sword64)(rbp) < (sword64)(8)) {
        goto L_c20p1305_small_dec_ct_c4;
    }
    rax = (word64)(WC_L64(rbx, 0));
    WC_S64(r9, 0) = (word64)(rax);
    rbx = (word64)(rbx + 8);
    r9 = (word64)(r9 + 8);
    rbp = (word64)(rbp - 8);
L_c20p1305_small_dec_ct_c4:
    if ((sword64)(rbp) < (sword64)(4)) {
        goto L_c20p1305_small_dec_ct_cby;
    }
    rax = (word32)(WC_L32(rbx, 0));
    WC_S32(r9, 0) = (word32)((word32)rax);
    rbx = (word64)(rbx + 4);
    r9 = (word64)(r9 + 4);
    rbp = (word64)(rbp - 4);
L_c20p1305_small_dec_ct_cby:
    if (((rbp & rbp)) == (0)) {
        goto L_c20p1305_small_dec_ct_cpyd;
    }
L_c20p1305_small_dec_ct_cbyl:
    rax = (word32)((word32)WC_L8(rbx, 0));
    WC_S8(r9, 0) = (byte)((byte)rax);
    rbx = (word64)(rbx + 1);
    r9 = (word64)(r9 + 1);
    rbp = (word64)(rbp - 1);
    if ((rbp) != (0)) {
        goto L_c20p1305_small_dec_ct_cbyl;
    }
L_c20p1305_small_dec_ct_cpyd:
    rbx = (word64)(rsp + 96);
    rcx = (word64)(WC_L64(rbx, 0));
    rsi = (word64)(WC_L64(rbx, 8));
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rsi, (unsigned long long*)&r14);
    rax = (word64)(r12);
    cf = _addcarry_u64(cf, r15, 1, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rsi = (word64)(rax);
    rdi = (word64)(rdx);
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    rax = (word64)(r11);
    cf = _addcarry_u64(cf, rdi, rdx, (unsigned long long*)&rdi);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    rdi = (word64)(rdi + WC_L64(r10, r15 * 8 + 352));
    r8 = (word64)(rdx);
    cf = _addcarry_u64(0, rsi, r9, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rdi, rax, (unsigned long long*)&rdi);
    cf = _addcarry_u64(cf, r8, WC_L64(r10, r15 * 8 + 408), (
        unsigned long long*)&r8);
    r15 = (word64)(rdi);
    rdi = (word64)(rdi & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, rcx, rdi, (unsigned long long*)&rcx);
    r13 = (word64)(rdi);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    r13 = (word64)((r13 >> 2) | (r8 << 62));
    r8 = (word64)(r8 >> 2);
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    r14 = (word64)(rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
L_c20p1305_small_dec_ct_done:
    rax = (word64)(WC_L64(rsp, 128));
    WC_S64(rsp, 112) = (word64)(rax);
    rax = (word64)(WC_L64(rsp, 136));
    WC_S64(rsp, 120) = (word64)(rax);
    rbx = (word64)(rsp + 112);
    rcx = (word64)(WC_L64(rbx, 0));
    rsi = (word64)(WC_L64(rbx, 8));
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, rsi, (unsigned long long*)&r14);
    rax = (word64)(r12);
    cf = _addcarry_u64(cf, r15, 1, (unsigned long long*)&r15);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rsi = (word64)(rax);
    rdi = (word64)(rdx);
    rax = (word64)(r11);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    cf = _addcarry_u64(0, rsi, rax, (unsigned long long*)&rsi);
    rax = (word64)(r11);
    cf = _addcarry_u64(cf, rdi, rdx, (unsigned long long*)&rdi);
    WC_X64I_MUL128(rax, rdx, rax, r13);
    rcx = (word64)(rax);
    r9 = (word64)(rdx);
    rax = (word64)(r12);
    WC_X64I_MUL128(rax, rdx, rax, r14);
    rdi = (word64)(rdi + WC_L64(r10, r15 * 8 + 352));
    r8 = (word64)(rdx);
    cf = _addcarry_u64(0, rsi, r9, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rdi, rax, (unsigned long long*)&rdi);
    cf = _addcarry_u64(cf, r8, WC_L64(r10, r15 * 8 + 408), (
        unsigned long long*)&r8);
    r15 = (word64)(rdi);
    rdi = (word64)(rdi & -4);
    r15 = (word64)(r15 & 3);
    cf = _addcarry_u64(0, rcx, rdi, (unsigned long long*)&rcx);
    r13 = (word64)(rdi);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    r13 = (word64)((r13 >> 2) | (r8 << 62));
    r8 = (word64)(r8 >> 2);
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, rsi, r8, (unsigned long long*)&rsi);
    r14 = (word64)(rsi);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    rdx = (word64)(WC_L64(rsp, 152));
    rcx = (word64)(WC_L64(rsp, 160));
    rbp = (word64)(WC_L64(rsp, 136));
    rbx = (word64)(rsp + 32);
L_chacha20_poly1305_small_dec_x16:
    if ((sword64)(rbp) < (sword64)(0x10)) {
        goto L_chacha20_poly1305_small_dec_xtail;
    }
    y8 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdx, 0)));
    y8 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y8),
        _mm_loadu_si128((const __m128i*)WC_PR(rbx, 0))));
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), _mm256_castsi256_si128(y8));
    rdx = (word64)(rdx + 0x10);
    rcx = (word64)(rcx + 0x10);
    rbx = (word64)(rbx + 0x10);
    rbp = (word64)(rbp - 0x10);
    goto L_chacha20_poly1305_small_dec_x16;
L_chacha20_poly1305_small_dec_xtail:
    if (((rbp & rbp)) == (0)) {
        goto L_chacha20_poly1305_small_dec_xdone;
    }
    rdi = (word64)(0);
L_chacha20_poly1305_small_dec_xbyte:
    if ((sword64)(rdi) >= (sword64)(rbp)) {
        goto L_chacha20_poly1305_small_dec_xdone;
    }
    rax = (word32)((word32)WC_L8(rdx, rdi));
    rax = (rax & ~(word64)0xff) | ((word64)(byte)((byte)rax ^ WC_L8(rbx,
        rdi)) & 0xff);
    WC_S8(rcx, rdi) = (byte)((byte)rax);
    rdi = (word64)(rdi + 1);
    goto L_chacha20_poly1305_small_dec_xbyte;
L_chacha20_poly1305_small_dec_xdone:
    y0 = _mm256_zextsi128_si256(_mm_setzero_si128());
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), _mm256_castsi256_si128(y0));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 16), _mm256_castsi256_si128(y0));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 32), _mm256_castsi256_si128(y0));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 48), _mm256_castsi256_si128(y0));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 64), _mm256_castsi256_si128(y0));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 80), _mm256_castsi256_si128(y0));
    rbx = (word64)(WC_L64(rsp, 144));
    rcx = (word64)(r15);
    r15 = (word64)(r15 & 3);
    rcx = (word64)(rcx >> 2);
    rcx = (word64)(rcx + rcx * 4);
    cf = _addcarry_u64(0, r13, rcx, (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, 0, (unsigned long long*)&r14);
    cf = _addcarry_u64(cf, r15, 0, (unsigned long long*)&r15);
    rcx = (word64)(r13);
    rsi = (word64)(r14);
    rdi = (word64)(r15);
    cf = _addcarry_u64(0, rcx, 5, (unsigned long long*)&rcx);
    cf = _addcarry_u64(cf, rsi, 0, (unsigned long long*)&rsi);
    cf = _addcarry_u64(cf, rdi, 0, (unsigned long long*)&rdi);
    zf1 = rdi;
    zf2 = 4;
    r13 = (rdi) == (4) ? rcx : r13;
    r14 = (zf1) == (zf2) ? rsi : r14;
    cf = _addcarry_u64(0, r13, WC_L64(r10, 48), (unsigned long long*)&r13);
    cf = _addcarry_u64(cf, r14, WC_L64(r10, 56), (unsigned long long*)&r14);
    r13 = (word64)(r13 ^ WC_L64(rbx, 0));
    r14 = (word64)(r14 ^ WC_L64(rbx, 8));
    r13 = (word64)(r13 | r14);
    rax = (word64)(r13);
    rax = (word64)(0 - rax);
    rax = (word64)(rax | r13);
    rax = (word64)(rax >> 63);
    return (int)(word32)rax;
    (void)aadLen;
    (void)tag;
}

#endif /* HAVE_INTEL_AVX2 */
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
