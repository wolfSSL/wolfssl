/* sha512_x86_64_intrin.c */
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
#define _WC_BUILDING_SHA512_X86_64_INTRIN_C

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef WOLFSSL_X86_64_BUILD

#ifdef _MSC_VER
    /* _umul128, __popcnt and _BitScanReverse64 live here. */
    #include <intrin.h>
#endif
#include <immintrin.h>
#include <wolfssl/wolfcrypt/sha512.h>

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

#ifdef HAVE_INTEL_AVX1
extern WOLFSSL_LOCAL int Transform_Sha512_AVX1(wc_Sha512* sha512);
extern WOLFSSL_LOCAL int Transform_Sha512_AVX1_Len(wc_Sha512* sha512,
    word32 len);
extern WOLFSSL_LOCAL int Transform_Sha512_AVX1_RORX(wc_Sha512* sha512);
extern WOLFSSL_LOCAL int Transform_Sha512_AVX1_RORX_Len(wc_Sha512* sha512,
    word32 len);
#endif
#ifdef HAVE_INTEL_AVX2
extern WOLFSSL_LOCAL int Transform_Sha512_AVX2(wc_Sha512* sha512);
extern WOLFSSL_LOCAL int Transform_Sha512_AVX2_Len(wc_Sha512* sha512,
    word32 len);
extern WOLFSSL_LOCAL int Transform_Sha512_AVX2_RORX(wc_Sha512* sha512);
extern WOLFSSL_LOCAL int Transform_Sha512_AVX2_RORX_Len(wc_Sha512* sha512,
    word32 len);
#ifdef WOLFSSL_HAVE_XMSS
#ifdef HAVE_INTEL_AVX512
extern WOLFSSL_LOCAL void Transform_Sha512_x8_AVX512(word64* state,
    const unsigned char* data);
#if !defined(NO_AVX512BW_SUPPORT)
extern WOLFSSL_LOCAL void Transform_Sha512_x8_AVX512_BW(word64* state,
    const unsigned char* data);
#endif
#ifdef WOLFSSL_HAVE_XMSS
extern WOLFSSL_LOCAL void Transform_Sha512_x8_XmssPrf_AVX512(word64* out,
    const word64* mid, const word64* adrs, const word32* chainv,
    const word32* hashv);
extern WOLFSSL_LOCAL void Transform_Sha512_x8_XmssF_AVX512(word64* st,
    const word64* key, const word64* bm);

#endif
#endif
#endif
#endif
#ifdef HAVE_INTEL_AVX1
XALIGNED(32) static const word64 L_avx1_sha512_k[] WC_X64I_UNUSED = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

XALIGNED(16) static const word64 L_avx1_sha512_flip_mask[] WC_X64I_UNUSED = {
    0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL,
};

WC_X64I_TARGET("avx")
WOLFSSL_LOCAL int Transform_Sha512_AVX1(wc_Sha512* sha512)
{
    word64 rdi, rsp, rax, r8, r9, r10, r11, r12, r13, r14, r15, rsi, rbx,
           rdx = 0, rcx = 0;
    __m128i x0, x1, x2, x3, x4, x5, x6, x7, x8 = _mm_setzero_si128(),
            x9 = _mm_setzero_si128(), x10 = _mm_setzero_si128(),
            x11 = _mm_setzero_si128(), x12 = _mm_setzero_si128(),
            x13 = _mm_setzero_si128(), x14;
    XALIGNED(32) WC_X64I_SLOT stk[20];

    rdi = (word64)(size_t)sha512;

    rsp = (word64)(size_t)stk + 160;
    rsp = (word64)(rsp - 136);
    rax = (word64)(rdi + 64);
    x14 = _mm_loadu_si128((const __m128i*)WC_PR(L_avx1_sha512_flip_mask, 0));
    r8 = (word64)(WC_L64(rdi, 0));
    r9 = (word64)(WC_L64(rdi, 8));
    r10 = (word64)(WC_L64(rdi, 16));
    r11 = (word64)(WC_L64(rdi, 24));
    r12 = (word64)(WC_L64(rdi, 32));
    r13 = (word64)(WC_L64(rdi, 40));
    r14 = (word64)(WC_L64(rdi, 48));
    r15 = (word64)(WC_L64(rdi, 56));
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rax, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(rax, 16));
    x0 = _mm_shuffle_epi8(x0, x14);
    x1 = _mm_shuffle_epi8(x1, x14);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rax, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(rax, 48));
    x2 = _mm_shuffle_epi8(x2, x14);
    x3 = _mm_shuffle_epi8(x3, x14);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rax, 64));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rax, 80));
    x4 = _mm_shuffle_epi8(x4, x14);
    x5 = _mm_shuffle_epi8(x5, x14);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rax, 96));
    x7 = _mm_loadu_si128((const __m128i*)WC_PR(rax, 112));
    x6 = _mm_shuffle_epi8(x6, x14);
    x7 = _mm_shuffle_epi8(x7, x14);
    WC_S32(rsp, 128) = (word32)(4);
    rsi = (word64)((word64)(size_t)L_avx1_sha512_k);
    rbx = (word64)(r9);
    rax = (word64)(r12);
    rbx = (word64)(rbx ^ r10);
    /* Start of 16 rounds */
L_transform_sha512_avx1_start:
    x8 = _mm_add_epi64(x0, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 0)));
    x9 = _mm_add_epi64(x1, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 16)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 16), x9);
    x8 = _mm_add_epi64(x2, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 32)));
    x9 = _mm_add_epi64(x3, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 48)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 32), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 48), x9);
    x8 = _mm_add_epi64(x4, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 64)));
    x9 = _mm_add_epi64(x5, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 80)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 64), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 80), x9);
    x8 = _mm_add_epi64(x6, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 96)));
    x9 = _mm_add_epi64(x7, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 112)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 96), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 112), x9);
    rsi = (word64)(rsi + 0x80);
    /* msg_sched: 0-1 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x12 = _mm_alignr_epi8(x1, x0, 8);
    x13 = _mm_alignr_epi8(x5, x4, 8);
    /* rnd_0: 1 - 1 */
    rdx = (word64)(r8);
    rcx = (word64)(r13);
    r15 = (word64)(r15 + WC_L64(rsp, 0));
    rcx = (word64)(rcx ^ r14);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 3 */
    rax = (word64)(rax ^ r12);
    rcx = (word64)(rcx & r12);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r14);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 4 - 5 */
    rax = (word64)(rax ^ r12);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r9);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 6 - 7 */
    r15 = (word64)(r15 + rax);
    rcx = (word64)(r8);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 8 - 9 */
    rcx = (word64)(rcx ^ r8);
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r11 = (word64)(r11 + r15);
    x8 = _mm_xor_si128(x8, x11);
    x0 = _mm_add_epi64(x13, x0);
    /* rnd_0: 10 - 11 */
    rcx = (word64)(rcx ^ r8);
    r15 = (word64)(r15 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r11);
    r15 = (word64)(r15 + rcx);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x0 = _mm_add_epi64(x8, x0);
    /* rnd_1: 1 - 1 */
    rbx = (word64)(r15);
    rcx = (word64)(r12);
    r14 = (word64)(r14 + WC_L64(rsp, 8));
    rcx = (word64)(rcx ^ r13);
    x8 = _mm_srli_epi64(x7, 19);
    x9 = _mm_slli_epi64(x7, 45);
    /* rnd_1: 2 - 3 */
    rax = (word64)(rax ^ r11);
    rcx = (word64)(rcx & r11);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r13);
    x10 = _mm_srli_epi64(x7, 61);
    x11 = _mm_slli_epi64(x7, 3);
    /* rnd_1: 4 - 6 */
    rax = (word64)(rax ^ r11);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r8);
    r14 = (word64)(r14 + rax);
    rcx = (word64)(r15);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 7 - 8 */
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r15);
    rdx = (word64)(rdx ^ r8);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x7, 6);
    /* rnd_1: 9 - 10 */
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r10 = (word64)(r10 + r14);
    rcx = (word64)(rcx ^ r15);
    r14 = (word64)(r14 + rdx);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 11 - 11 */
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r10);
    r14 = (word64)(r14 + rcx);
    x0 = _mm_add_epi64(x8, x0);
    /* msg_sched done: 0-1 */
    /* msg_sched: 2-3 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x12 = _mm_alignr_epi8(x2, x1, 8);
    x13 = _mm_alignr_epi8(x6, x5, 8);
    /* rnd_0: 1 - 1 */
    rdx = (word64)(r14);
    rcx = (word64)(r11);
    r13 = (word64)(r13 + WC_L64(rsp, 16));
    rcx = (word64)(rcx ^ r12);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 3 */
    rax = (word64)(rax ^ r10);
    rcx = (word64)(rcx & r10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r12);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 4 - 5 */
    rax = (word64)(rax ^ r10);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r15);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 6 - 7 */
    r13 = (word64)(r13 + rax);
    rcx = (word64)(r14);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 8 - 9 */
    rcx = (word64)(rcx ^ r14);
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r9 = (word64)(r9 + r13);
    x8 = _mm_xor_si128(x8, x11);
    x1 = _mm_add_epi64(x13, x1);
    /* rnd_0: 10 - 11 */
    rcx = (word64)(rcx ^ r14);
    r13 = (word64)(r13 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r9);
    r13 = (word64)(r13 + rcx);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x1 = _mm_add_epi64(x8, x1);
    /* rnd_1: 1 - 1 */
    rbx = (word64)(r13);
    rcx = (word64)(r10);
    r12 = (word64)(r12 + WC_L64(rsp, 24));
    rcx = (word64)(rcx ^ r11);
    x8 = _mm_srli_epi64(x0, 19);
    x9 = _mm_slli_epi64(x0, 45);
    /* rnd_1: 2 - 3 */
    rax = (word64)(rax ^ r9);
    rcx = (word64)(rcx & r9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r11);
    x10 = _mm_srli_epi64(x0, 61);
    x11 = _mm_slli_epi64(x0, 3);
    /* rnd_1: 4 - 6 */
    rax = (word64)(rax ^ r9);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r14);
    r12 = (word64)(r12 + rax);
    rcx = (word64)(r13);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 7 - 8 */
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r13);
    rdx = (word64)(rdx ^ r14);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x0, 6);
    /* rnd_1: 9 - 10 */
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r8 = (word64)(r8 + r12);
    rcx = (word64)(rcx ^ r13);
    r12 = (word64)(r12 + rdx);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 11 - 11 */
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r8);
    r12 = (word64)(r12 + rcx);
    x1 = _mm_add_epi64(x8, x1);
    /* msg_sched done: 2-3 */
    /* msg_sched: 4-5 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x12 = _mm_alignr_epi8(x3, x2, 8);
    x13 = _mm_alignr_epi8(x7, x6, 8);
    /* rnd_0: 1 - 1 */
    rdx = (word64)(r12);
    rcx = (word64)(r9);
    r11 = (word64)(r11 + WC_L64(rsp, 32));
    rcx = (word64)(rcx ^ r10);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 3 */
    rax = (word64)(rax ^ r8);
    rcx = (word64)(rcx & r8);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r10);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 4 - 5 */
    rax = (word64)(rax ^ r8);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r13);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 6 - 7 */
    r11 = (word64)(r11 + rax);
    rcx = (word64)(r12);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 8 - 9 */
    rcx = (word64)(rcx ^ r12);
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r15 = (word64)(r15 + r11);
    x8 = _mm_xor_si128(x8, x11);
    x2 = _mm_add_epi64(x13, x2);
    /* rnd_0: 10 - 11 */
    rcx = (word64)(rcx ^ r12);
    r11 = (word64)(r11 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r15);
    r11 = (word64)(r11 + rcx);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x2 = _mm_add_epi64(x8, x2);
    /* rnd_1: 1 - 1 */
    rbx = (word64)(r11);
    rcx = (word64)(r8);
    r10 = (word64)(r10 + WC_L64(rsp, 40));
    rcx = (word64)(rcx ^ r9);
    x8 = _mm_srli_epi64(x1, 19);
    x9 = _mm_slli_epi64(x1, 45);
    /* rnd_1: 2 - 3 */
    rax = (word64)(rax ^ r15);
    rcx = (word64)(rcx & r15);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r9);
    x10 = _mm_srli_epi64(x1, 61);
    x11 = _mm_slli_epi64(x1, 3);
    /* rnd_1: 4 - 6 */
    rax = (word64)(rax ^ r15);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r12);
    r10 = (word64)(r10 + rax);
    rcx = (word64)(r11);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 7 - 8 */
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r11);
    rdx = (word64)(rdx ^ r12);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x1, 6);
    /* rnd_1: 9 - 10 */
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r14 = (word64)(r14 + r10);
    rcx = (word64)(rcx ^ r11);
    r10 = (word64)(r10 + rdx);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 11 - 11 */
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r14);
    r10 = (word64)(r10 + rcx);
    x2 = _mm_add_epi64(x8, x2);
    /* msg_sched done: 4-5 */
    /* msg_sched: 6-7 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x12 = _mm_alignr_epi8(x4, x3, 8);
    x13 = _mm_alignr_epi8(x0, x7, 8);
    /* rnd_0: 1 - 1 */
    rdx = (word64)(r10);
    rcx = (word64)(r15);
    r9 = (word64)(r9 + WC_L64(rsp, 48));
    rcx = (word64)(rcx ^ r8);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 3 */
    rax = (word64)(rax ^ r14);
    rcx = (word64)(rcx & r14);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r8);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 4 - 5 */
    rax = (word64)(rax ^ r14);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r11);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 6 - 7 */
    r9 = (word64)(r9 + rax);
    rcx = (word64)(r10);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 8 - 9 */
    rcx = (word64)(rcx ^ r10);
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r13 = (word64)(r13 + r9);
    x8 = _mm_xor_si128(x8, x11);
    x3 = _mm_add_epi64(x13, x3);
    /* rnd_0: 10 - 11 */
    rcx = (word64)(rcx ^ r10);
    r9 = (word64)(r9 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r13);
    r9 = (word64)(r9 + rcx);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x3 = _mm_add_epi64(x8, x3);
    /* rnd_1: 1 - 1 */
    rbx = (word64)(r9);
    rcx = (word64)(r14);
    r8 = (word64)(r8 + WC_L64(rsp, 56));
    rcx = (word64)(rcx ^ r15);
    x8 = _mm_srli_epi64(x2, 19);
    x9 = _mm_slli_epi64(x2, 45);
    /* rnd_1: 2 - 3 */
    rax = (word64)(rax ^ r13);
    rcx = (word64)(rcx & r13);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r15);
    x10 = _mm_srli_epi64(x2, 61);
    x11 = _mm_slli_epi64(x2, 3);
    /* rnd_1: 4 - 6 */
    rax = (word64)(rax ^ r13);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r10);
    r8 = (word64)(r8 + rax);
    rcx = (word64)(r9);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 7 - 8 */
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r9);
    rdx = (word64)(rdx ^ r10);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x2, 6);
    /* rnd_1: 9 - 10 */
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r12 = (word64)(r12 + r8);
    rcx = (word64)(rcx ^ r9);
    r8 = (word64)(r8 + rdx);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 11 - 11 */
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r12);
    r8 = (word64)(r8 + rcx);
    x3 = _mm_add_epi64(x8, x3);
    /* msg_sched done: 6-7 */
    /* msg_sched: 8-9 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x12 = _mm_alignr_epi8(x5, x4, 8);
    x13 = _mm_alignr_epi8(x1, x0, 8);
    /* rnd_0: 1 - 1 */
    rdx = (word64)(r8);
    rcx = (word64)(r13);
    r15 = (word64)(r15 + WC_L64(rsp, 64));
    rcx = (word64)(rcx ^ r14);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 3 */
    rax = (word64)(rax ^ r12);
    rcx = (word64)(rcx & r12);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r14);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 4 - 5 */
    rax = (word64)(rax ^ r12);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r9);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 6 - 7 */
    r15 = (word64)(r15 + rax);
    rcx = (word64)(r8);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 8 - 9 */
    rcx = (word64)(rcx ^ r8);
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r11 = (word64)(r11 + r15);
    x8 = _mm_xor_si128(x8, x11);
    x4 = _mm_add_epi64(x13, x4);
    /* rnd_0: 10 - 11 */
    rcx = (word64)(rcx ^ r8);
    r15 = (word64)(r15 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r11);
    r15 = (word64)(r15 + rcx);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x4 = _mm_add_epi64(x8, x4);
    /* rnd_1: 1 - 1 */
    rbx = (word64)(r15);
    rcx = (word64)(r12);
    r14 = (word64)(r14 + WC_L64(rsp, 72));
    rcx = (word64)(rcx ^ r13);
    x8 = _mm_srli_epi64(x3, 19);
    x9 = _mm_slli_epi64(x3, 45);
    /* rnd_1: 2 - 3 */
    rax = (word64)(rax ^ r11);
    rcx = (word64)(rcx & r11);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r13);
    x10 = _mm_srli_epi64(x3, 61);
    x11 = _mm_slli_epi64(x3, 3);
    /* rnd_1: 4 - 6 */
    rax = (word64)(rax ^ r11);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r8);
    r14 = (word64)(r14 + rax);
    rcx = (word64)(r15);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 7 - 8 */
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r15);
    rdx = (word64)(rdx ^ r8);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x3, 6);
    /* rnd_1: 9 - 10 */
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r10 = (word64)(r10 + r14);
    rcx = (word64)(rcx ^ r15);
    r14 = (word64)(r14 + rdx);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 11 - 11 */
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r10);
    r14 = (word64)(r14 + rcx);
    x4 = _mm_add_epi64(x8, x4);
    /* msg_sched done: 8-9 */
    /* msg_sched: 10-11 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x12 = _mm_alignr_epi8(x6, x5, 8);
    x13 = _mm_alignr_epi8(x2, x1, 8);
    /* rnd_0: 1 - 1 */
    rdx = (word64)(r14);
    rcx = (word64)(r11);
    r13 = (word64)(r13 + WC_L64(rsp, 80));
    rcx = (word64)(rcx ^ r12);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 3 */
    rax = (word64)(rax ^ r10);
    rcx = (word64)(rcx & r10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r12);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 4 - 5 */
    rax = (word64)(rax ^ r10);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r15);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 6 - 7 */
    r13 = (word64)(r13 + rax);
    rcx = (word64)(r14);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 8 - 9 */
    rcx = (word64)(rcx ^ r14);
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r9 = (word64)(r9 + r13);
    x8 = _mm_xor_si128(x8, x11);
    x5 = _mm_add_epi64(x13, x5);
    /* rnd_0: 10 - 11 */
    rcx = (word64)(rcx ^ r14);
    r13 = (word64)(r13 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r9);
    r13 = (word64)(r13 + rcx);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x5 = _mm_add_epi64(x8, x5);
    /* rnd_1: 1 - 1 */
    rbx = (word64)(r13);
    rcx = (word64)(r10);
    r12 = (word64)(r12 + WC_L64(rsp, 88));
    rcx = (word64)(rcx ^ r11);
    x8 = _mm_srli_epi64(x4, 19);
    x9 = _mm_slli_epi64(x4, 45);
    /* rnd_1: 2 - 3 */
    rax = (word64)(rax ^ r9);
    rcx = (word64)(rcx & r9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r11);
    x10 = _mm_srli_epi64(x4, 61);
    x11 = _mm_slli_epi64(x4, 3);
    /* rnd_1: 4 - 6 */
    rax = (word64)(rax ^ r9);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r14);
    r12 = (word64)(r12 + rax);
    rcx = (word64)(r13);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 7 - 8 */
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r13);
    rdx = (word64)(rdx ^ r14);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x4, 6);
    /* rnd_1: 9 - 10 */
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r8 = (word64)(r8 + r12);
    rcx = (word64)(rcx ^ r13);
    r12 = (word64)(r12 + rdx);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 11 - 11 */
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r8);
    r12 = (word64)(r12 + rcx);
    x5 = _mm_add_epi64(x8, x5);
    /* msg_sched done: 10-11 */
    /* msg_sched: 12-13 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x12 = _mm_alignr_epi8(x7, x6, 8);
    x13 = _mm_alignr_epi8(x3, x2, 8);
    /* rnd_0: 1 - 1 */
    rdx = (word64)(r12);
    rcx = (word64)(r9);
    r11 = (word64)(r11 + WC_L64(rsp, 96));
    rcx = (word64)(rcx ^ r10);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 3 */
    rax = (word64)(rax ^ r8);
    rcx = (word64)(rcx & r8);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r10);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 4 - 5 */
    rax = (word64)(rax ^ r8);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r13);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 6 - 7 */
    r11 = (word64)(r11 + rax);
    rcx = (word64)(r12);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 8 - 9 */
    rcx = (word64)(rcx ^ r12);
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r15 = (word64)(r15 + r11);
    x8 = _mm_xor_si128(x8, x11);
    x6 = _mm_add_epi64(x13, x6);
    /* rnd_0: 10 - 11 */
    rcx = (word64)(rcx ^ r12);
    r11 = (word64)(r11 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r15);
    r11 = (word64)(r11 + rcx);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x6 = _mm_add_epi64(x8, x6);
    /* rnd_1: 1 - 1 */
    rbx = (word64)(r11);
    rcx = (word64)(r8);
    r10 = (word64)(r10 + WC_L64(rsp, 104));
    rcx = (word64)(rcx ^ r9);
    x8 = _mm_srli_epi64(x5, 19);
    x9 = _mm_slli_epi64(x5, 45);
    /* rnd_1: 2 - 3 */
    rax = (word64)(rax ^ r15);
    rcx = (word64)(rcx & r15);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r9);
    x10 = _mm_srli_epi64(x5, 61);
    x11 = _mm_slli_epi64(x5, 3);
    /* rnd_1: 4 - 6 */
    rax = (word64)(rax ^ r15);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r12);
    r10 = (word64)(r10 + rax);
    rcx = (word64)(r11);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 7 - 8 */
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r11);
    rdx = (word64)(rdx ^ r12);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x5, 6);
    /* rnd_1: 9 - 10 */
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r14 = (word64)(r14 + r10);
    rcx = (word64)(rcx ^ r11);
    r10 = (word64)(r10 + rdx);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 11 - 11 */
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r14);
    r10 = (word64)(r10 + rcx);
    x6 = _mm_add_epi64(x8, x6);
    /* msg_sched done: 12-13 */
    /* msg_sched: 14-15 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x12 = _mm_alignr_epi8(x0, x7, 8);
    x13 = _mm_alignr_epi8(x4, x3, 8);
    /* rnd_0: 1 - 1 */
    rdx = (word64)(r10);
    rcx = (word64)(r15);
    r9 = (word64)(r9 + WC_L64(rsp, 112));
    rcx = (word64)(rcx ^ r8);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 3 */
    rax = (word64)(rax ^ r14);
    rcx = (word64)(rcx & r14);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r8);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 4 - 5 */
    rax = (word64)(rax ^ r14);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r11);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 6 - 7 */
    r9 = (word64)(r9 + rax);
    rcx = (word64)(r10);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 8 - 9 */
    rcx = (word64)(rcx ^ r10);
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r13 = (word64)(r13 + r9);
    x8 = _mm_xor_si128(x8, x11);
    x7 = _mm_add_epi64(x13, x7);
    /* rnd_0: 10 - 11 */
    rcx = (word64)(rcx ^ r10);
    r9 = (word64)(r9 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r13);
    r9 = (word64)(r9 + rcx);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x7 = _mm_add_epi64(x8, x7);
    /* rnd_1: 1 - 1 */
    rbx = (word64)(r9);
    rcx = (word64)(r14);
    r8 = (word64)(r8 + WC_L64(rsp, 120));
    rcx = (word64)(rcx ^ r15);
    x8 = _mm_srli_epi64(x6, 19);
    x9 = _mm_slli_epi64(x6, 45);
    /* rnd_1: 2 - 3 */
    rax = (word64)(rax ^ r13);
    rcx = (word64)(rcx & r13);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r15);
    x10 = _mm_srli_epi64(x6, 61);
    x11 = _mm_slli_epi64(x6, 3);
    /* rnd_1: 4 - 6 */
    rax = (word64)(rax ^ r13);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r10);
    r8 = (word64)(r8 + rax);
    rcx = (word64)(r9);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 7 - 8 */
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r9);
    rdx = (word64)(rdx ^ r10);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x6, 6);
    /* rnd_1: 9 - 10 */
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r12 = (word64)(r12 + r8);
    rcx = (word64)(rcx ^ r9);
    r8 = (word64)(r8 + rdx);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 11 - 11 */
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r12);
    r8 = (word64)(r8 + rcx);
    x7 = _mm_add_epi64(x8, x7);
    /* msg_sched done: 14-15 */
    WC_S32(rsp, 128) = (word32)(WC_L32(rsp, 128) - 1);
    if (((word32)WC_S32(rsp, 128)) != (0)) {
        goto L_transform_sha512_avx1_start;
    }
    x8 = _mm_add_epi64(x0, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 0)));
    x9 = _mm_add_epi64(x1, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 16)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 16), x9);
    x8 = _mm_add_epi64(x2, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 32)));
    x9 = _mm_add_epi64(x3, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 48)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 32), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 48), x9);
    x8 = _mm_add_epi64(x4, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 64)));
    x9 = _mm_add_epi64(x5, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 80)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 64), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 80), x9);
    x8 = _mm_add_epi64(x6, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 96)));
    x9 = _mm_add_epi64(x7, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 112)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 96), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 112), x9);
    /* rnd_all_2: 0-1 */
    /* rnd_0: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r8);
    rcx = (word64)(r13);
    r15 = (word64)(r15 + WC_L64(rsp, 0));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    rcx = (word64)(rcx & r12);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r9);
    r15 = (word64)(r15 + rax);
    rcx = (word64)(r8);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r8);
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r11 = (word64)(r11 + r15);
    rcx = (word64)(rcx ^ r8);
    r15 = (word64)(r15 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r11);
    r15 = (word64)(r15 + rcx);
    /* rnd_1: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r15);
    rcx = (word64)(r12);
    r14 = (word64)(r14 + WC_L64(rsp, 8));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    rcx = (word64)(rcx & r11);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r8);
    r14 = (word64)(r14 + rax);
    rcx = (word64)(r15);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r15);
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r10 = (word64)(r10 + r14);
    rcx = (word64)(rcx ^ r15);
    r14 = (word64)(r14 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r10);
    r14 = (word64)(r14 + rcx);
    /* rnd_all_2: 2-3 */
    /* rnd_0: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r14);
    rcx = (word64)(r11);
    r13 = (word64)(r13 + WC_L64(rsp, 16));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    rcx = (word64)(rcx & r10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r15);
    r13 = (word64)(r13 + rax);
    rcx = (word64)(r14);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r14);
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r9 = (word64)(r9 + r13);
    rcx = (word64)(rcx ^ r14);
    r13 = (word64)(r13 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r9);
    r13 = (word64)(r13 + rcx);
    /* rnd_1: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r13);
    rcx = (word64)(r10);
    r12 = (word64)(r12 + WC_L64(rsp, 24));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    rcx = (word64)(rcx & r9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r14);
    r12 = (word64)(r12 + rax);
    rcx = (word64)(r13);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r13);
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r8 = (word64)(r8 + r12);
    rcx = (word64)(rcx ^ r13);
    r12 = (word64)(r12 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r8);
    r12 = (word64)(r12 + rcx);
    /* rnd_all_2: 4-5 */
    /* rnd_0: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r12);
    rcx = (word64)(r9);
    r11 = (word64)(r11 + WC_L64(rsp, 32));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    rcx = (word64)(rcx & r8);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r13);
    r11 = (word64)(r11 + rax);
    rcx = (word64)(r12);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r12);
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r15 = (word64)(r15 + r11);
    rcx = (word64)(rcx ^ r12);
    r11 = (word64)(r11 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r15);
    r11 = (word64)(r11 + rcx);
    /* rnd_1: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r11);
    rcx = (word64)(r8);
    r10 = (word64)(r10 + WC_L64(rsp, 40));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    rcx = (word64)(rcx & r15);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r12);
    r10 = (word64)(r10 + rax);
    rcx = (word64)(r11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r11);
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r14 = (word64)(r14 + r10);
    rcx = (word64)(rcx ^ r11);
    r10 = (word64)(r10 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r14);
    r10 = (word64)(r10 + rcx);
    /* rnd_all_2: 6-7 */
    /* rnd_0: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r10);
    rcx = (word64)(r15);
    r9 = (word64)(r9 + WC_L64(rsp, 48));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    rcx = (word64)(rcx & r14);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r11);
    r9 = (word64)(r9 + rax);
    rcx = (word64)(r10);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r10);
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r13 = (word64)(r13 + r9);
    rcx = (word64)(rcx ^ r10);
    r9 = (word64)(r9 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r13);
    r9 = (word64)(r9 + rcx);
    /* rnd_1: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r9);
    rcx = (word64)(r14);
    r8 = (word64)(r8 + WC_L64(rsp, 56));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    rcx = (word64)(rcx & r13);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r10);
    r8 = (word64)(r8 + rax);
    rcx = (word64)(r9);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r9);
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r12 = (word64)(r12 + r8);
    rcx = (word64)(rcx ^ r9);
    r8 = (word64)(r8 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r12);
    r8 = (word64)(r8 + rcx);
    /* rnd_all_2: 8-9 */
    /* rnd_0: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r8);
    rcx = (word64)(r13);
    r15 = (word64)(r15 + WC_L64(rsp, 64));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    rcx = (word64)(rcx & r12);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r9);
    r15 = (word64)(r15 + rax);
    rcx = (word64)(r8);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r8);
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r11 = (word64)(r11 + r15);
    rcx = (word64)(rcx ^ r8);
    r15 = (word64)(r15 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r11);
    r15 = (word64)(r15 + rcx);
    /* rnd_1: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r15);
    rcx = (word64)(r12);
    r14 = (word64)(r14 + WC_L64(rsp, 72));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    rcx = (word64)(rcx & r11);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r8);
    r14 = (word64)(r14 + rax);
    rcx = (word64)(r15);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r15);
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r10 = (word64)(r10 + r14);
    rcx = (word64)(rcx ^ r15);
    r14 = (word64)(r14 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r10);
    r14 = (word64)(r14 + rcx);
    /* rnd_all_2: 10-11 */
    /* rnd_0: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r14);
    rcx = (word64)(r11);
    r13 = (word64)(r13 + WC_L64(rsp, 80));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    rcx = (word64)(rcx & r10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r15);
    r13 = (word64)(r13 + rax);
    rcx = (word64)(r14);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r14);
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r9 = (word64)(r9 + r13);
    rcx = (word64)(rcx ^ r14);
    r13 = (word64)(r13 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r9);
    r13 = (word64)(r13 + rcx);
    /* rnd_1: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r13);
    rcx = (word64)(r10);
    r12 = (word64)(r12 + WC_L64(rsp, 88));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    rcx = (word64)(rcx & r9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r14);
    r12 = (word64)(r12 + rax);
    rcx = (word64)(r13);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r13);
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r8 = (word64)(r8 + r12);
    rcx = (word64)(rcx ^ r13);
    r12 = (word64)(r12 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r8);
    r12 = (word64)(r12 + rcx);
    /* rnd_all_2: 12-13 */
    /* rnd_0: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r12);
    rcx = (word64)(r9);
    r11 = (word64)(r11 + WC_L64(rsp, 96));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    rcx = (word64)(rcx & r8);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r13);
    r11 = (word64)(r11 + rax);
    rcx = (word64)(r12);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r12);
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r15 = (word64)(r15 + r11);
    rcx = (word64)(rcx ^ r12);
    r11 = (word64)(r11 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r15);
    r11 = (word64)(r11 + rcx);
    /* rnd_1: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r11);
    rcx = (word64)(r8);
    r10 = (word64)(r10 + WC_L64(rsp, 104));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    rcx = (word64)(rcx & r15);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r12);
    r10 = (word64)(r10 + rax);
    rcx = (word64)(r11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r11);
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r14 = (word64)(r14 + r10);
    rcx = (word64)(rcx ^ r11);
    r10 = (word64)(r10 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r14);
    r10 = (word64)(r10 + rcx);
    /* rnd_all_2: 14-15 */
    /* rnd_0: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r10);
    rcx = (word64)(r15);
    r9 = (word64)(r9 + WC_L64(rsp, 112));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    rcx = (word64)(rcx & r14);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r11);
    r9 = (word64)(r9 + rax);
    rcx = (word64)(r10);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r10);
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r13 = (word64)(r13 + r9);
    rcx = (word64)(rcx ^ r10);
    r9 = (word64)(r9 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r13);
    r9 = (word64)(r9 + rcx);
    /* rnd_1: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r9);
    rcx = (word64)(r14);
    r8 = (word64)(r8 + WC_L64(rsp, 120));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    rcx = (word64)(rcx & r13);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r10);
    r8 = (word64)(r8 + rax);
    rcx = (word64)(r9);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r9);
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r12 = (word64)(r12 + r8);
    rcx = (word64)(rcx ^ r9);
    r8 = (word64)(r8 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r12);
    r8 = (word64)(r8 + rcx);
    WC_S64(rdi, 0) = (word64)(WC_L64(rdi, 0) + r8);
    WC_S64(rdi, 8) = (word64)(WC_L64(rdi, 8) + r9);
    WC_S64(rdi, 16) = (word64)(WC_L64(rdi, 16) + r10);
    WC_S64(rdi, 24) = (word64)(WC_L64(rdi, 24) + r11);
    WC_S64(rdi, 32) = (word64)(WC_L64(rdi, 32) + r12);
    WC_S64(rdi, 40) = (word64)(WC_L64(rdi, 40) + r13);
    WC_S64(rdi, 48) = (word64)(WC_L64(rdi, 48) + r14);
    WC_S64(rdi, 56) = (word64)(WC_L64(rdi, 56) + r15);
    rax = (word64)(0);
    return (int)(word32)rax;
}

WC_X64I_TARGET("avx")
WOLFSSL_LOCAL int Transform_Sha512_AVX1_Len(wc_Sha512* sha512, word32 len)
{
    word64 rdi, rbp, rsp, rsi, rdx, r8, r9, r10, r11, r12, r13, r14, r15,
           rbx = 0, rax = 0, rcx = 0;
    __m128i x0 = _mm_setzero_si128(), x1 = _mm_setzero_si128(),
            x2 = _mm_setzero_si128(), x3 = _mm_setzero_si128(),
            x4 = _mm_setzero_si128(), x5 = _mm_setzero_si128(),
            x6 = _mm_setzero_si128(), x7 = _mm_setzero_si128(),
            x8 = _mm_setzero_si128(), x9 = _mm_setzero_si128(),
            x10 = _mm_setzero_si128(), x11 = _mm_setzero_si128(),
            x12 = _mm_setzero_si128(), x13 = _mm_setzero_si128(), x14;
    XALIGNED(32) WC_X64I_SLOT stk[20];
    word32 zf1;

    rdi = (word64)(size_t)sha512;
    rbp = (word64)(word32)len;

    rsp = (word64)(size_t)stk + 160;
    rsp = (word64)(rsp - 144);
    rsi = (word64)(WC_L64(rdi, 224));
    rdx = (word64)((word64)(size_t)L_avx1_sha512_k);
    x14 = _mm_loadu_si128((const __m128i*)WC_PR(L_avx1_sha512_flip_mask, 0));
    r8 = (word64)(WC_L64(rdi, 0));
    r9 = (word64)(WC_L64(rdi, 8));
    r10 = (word64)(WC_L64(rdi, 16));
    r11 = (word64)(WC_L64(rdi, 24));
    r12 = (word64)(WC_L64(rdi, 32));
    r13 = (word64)(WC_L64(rdi, 40));
    r14 = (word64)(WC_L64(rdi, 48));
    r15 = (word64)(WC_L64(rdi, 56));
    /* Start of loop processing a block */
L_sha512_len_avx1_begin:
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 16));
    x0 = _mm_shuffle_epi8(x0, x14);
    x1 = _mm_shuffle_epi8(x1, x14);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 48));
    x2 = _mm_shuffle_epi8(x2, x14);
    x3 = _mm_shuffle_epi8(x3, x14);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 64));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 80));
    x4 = _mm_shuffle_epi8(x4, x14);
    x5 = _mm_shuffle_epi8(x5, x14);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 96));
    x7 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 112));
    x6 = _mm_shuffle_epi8(x6, x14);
    x7 = _mm_shuffle_epi8(x7, x14);
    WC_S32(rsp, 128) = (word32)(4);
    rbx = (word64)(r9);
    rax = (word64)(r12);
    rbx = (word64)(rbx ^ r10);
    x8 = _mm_add_epi64(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0)));
    x9 = _mm_add_epi64(x1, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 16)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 16), x9);
    x8 = _mm_add_epi64(x2, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 32)));
    x9 = _mm_add_epi64(x3, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 48)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 32), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 48), x9);
    x8 = _mm_add_epi64(x4, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 64)));
    x9 = _mm_add_epi64(x5, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 80)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 64), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 80), x9);
    x8 = _mm_add_epi64(x6, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 96)));
    x9 = _mm_add_epi64(x7, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 112)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 96), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 112), x9);
    /* Start of 16 rounds */
L_sha512_len_avx1_start:
    rdx = (word64)(rdx + 0x80);
    WC_S64(rsp, 136) = (word64)(rdx);
    /* msg_sched: 0-1 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x12 = _mm_alignr_epi8(x1, x0, 8);
    x13 = _mm_alignr_epi8(x5, x4, 8);
    /* rnd_0: 1 - 1 */
    rdx = (word64)(r8);
    rcx = (word64)(r13);
    r15 = (word64)(r15 + WC_L64(rsp, 0));
    rcx = (word64)(rcx ^ r14);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 3 */
    rax = (word64)(rax ^ r12);
    rcx = (word64)(rcx & r12);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r14);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 4 - 5 */
    rax = (word64)(rax ^ r12);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r9);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 6 - 7 */
    r15 = (word64)(r15 + rax);
    rcx = (word64)(r8);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 8 - 9 */
    rcx = (word64)(rcx ^ r8);
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r11 = (word64)(r11 + r15);
    x8 = _mm_xor_si128(x8, x11);
    x0 = _mm_add_epi64(x13, x0);
    /* rnd_0: 10 - 11 */
    rcx = (word64)(rcx ^ r8);
    r15 = (word64)(r15 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r11);
    r15 = (word64)(r15 + rcx);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x0 = _mm_add_epi64(x8, x0);
    /* rnd_1: 1 - 1 */
    rbx = (word64)(r15);
    rcx = (word64)(r12);
    r14 = (word64)(r14 + WC_L64(rsp, 8));
    rcx = (word64)(rcx ^ r13);
    x8 = _mm_srli_epi64(x7, 19);
    x9 = _mm_slli_epi64(x7, 45);
    /* rnd_1: 2 - 3 */
    rax = (word64)(rax ^ r11);
    rcx = (word64)(rcx & r11);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r13);
    x10 = _mm_srli_epi64(x7, 61);
    x11 = _mm_slli_epi64(x7, 3);
    /* rnd_1: 4 - 6 */
    rax = (word64)(rax ^ r11);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r8);
    r14 = (word64)(r14 + rax);
    rcx = (word64)(r15);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 7 - 8 */
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r15);
    rdx = (word64)(rdx ^ r8);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x7, 6);
    /* rnd_1: 9 - 10 */
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r10 = (word64)(r10 + r14);
    rcx = (word64)(rcx ^ r15);
    r14 = (word64)(r14 + rdx);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 11 - 11 */
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r10);
    r14 = (word64)(r14 + rcx);
    x0 = _mm_add_epi64(x8, x0);
    /* msg_sched done: 0-1 */
    /* msg_sched: 2-3 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x12 = _mm_alignr_epi8(x2, x1, 8);
    x13 = _mm_alignr_epi8(x6, x5, 8);
    /* rnd_0: 1 - 1 */
    rdx = (word64)(r14);
    rcx = (word64)(r11);
    r13 = (word64)(r13 + WC_L64(rsp, 16));
    rcx = (word64)(rcx ^ r12);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 3 */
    rax = (word64)(rax ^ r10);
    rcx = (word64)(rcx & r10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r12);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 4 - 5 */
    rax = (word64)(rax ^ r10);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r15);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 6 - 7 */
    r13 = (word64)(r13 + rax);
    rcx = (word64)(r14);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 8 - 9 */
    rcx = (word64)(rcx ^ r14);
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r9 = (word64)(r9 + r13);
    x8 = _mm_xor_si128(x8, x11);
    x1 = _mm_add_epi64(x13, x1);
    /* rnd_0: 10 - 11 */
    rcx = (word64)(rcx ^ r14);
    r13 = (word64)(r13 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r9);
    r13 = (word64)(r13 + rcx);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x1 = _mm_add_epi64(x8, x1);
    /* rnd_1: 1 - 1 */
    rbx = (word64)(r13);
    rcx = (word64)(r10);
    r12 = (word64)(r12 + WC_L64(rsp, 24));
    rcx = (word64)(rcx ^ r11);
    x8 = _mm_srli_epi64(x0, 19);
    x9 = _mm_slli_epi64(x0, 45);
    /* rnd_1: 2 - 3 */
    rax = (word64)(rax ^ r9);
    rcx = (word64)(rcx & r9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r11);
    x10 = _mm_srli_epi64(x0, 61);
    x11 = _mm_slli_epi64(x0, 3);
    /* rnd_1: 4 - 6 */
    rax = (word64)(rax ^ r9);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r14);
    r12 = (word64)(r12 + rax);
    rcx = (word64)(r13);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 7 - 8 */
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r13);
    rdx = (word64)(rdx ^ r14);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x0, 6);
    /* rnd_1: 9 - 10 */
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r8 = (word64)(r8 + r12);
    rcx = (word64)(rcx ^ r13);
    r12 = (word64)(r12 + rdx);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 11 - 11 */
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r8);
    r12 = (word64)(r12 + rcx);
    x1 = _mm_add_epi64(x8, x1);
    /* msg_sched done: 2-3 */
    /* msg_sched: 4-5 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x12 = _mm_alignr_epi8(x3, x2, 8);
    x13 = _mm_alignr_epi8(x7, x6, 8);
    /* rnd_0: 1 - 1 */
    rdx = (word64)(r12);
    rcx = (word64)(r9);
    r11 = (word64)(r11 + WC_L64(rsp, 32));
    rcx = (word64)(rcx ^ r10);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 3 */
    rax = (word64)(rax ^ r8);
    rcx = (word64)(rcx & r8);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r10);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 4 - 5 */
    rax = (word64)(rax ^ r8);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r13);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 6 - 7 */
    r11 = (word64)(r11 + rax);
    rcx = (word64)(r12);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 8 - 9 */
    rcx = (word64)(rcx ^ r12);
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r15 = (word64)(r15 + r11);
    x8 = _mm_xor_si128(x8, x11);
    x2 = _mm_add_epi64(x13, x2);
    /* rnd_0: 10 - 11 */
    rcx = (word64)(rcx ^ r12);
    r11 = (word64)(r11 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r15);
    r11 = (word64)(r11 + rcx);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x2 = _mm_add_epi64(x8, x2);
    /* rnd_1: 1 - 1 */
    rbx = (word64)(r11);
    rcx = (word64)(r8);
    r10 = (word64)(r10 + WC_L64(rsp, 40));
    rcx = (word64)(rcx ^ r9);
    x8 = _mm_srli_epi64(x1, 19);
    x9 = _mm_slli_epi64(x1, 45);
    /* rnd_1: 2 - 3 */
    rax = (word64)(rax ^ r15);
    rcx = (word64)(rcx & r15);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r9);
    x10 = _mm_srli_epi64(x1, 61);
    x11 = _mm_slli_epi64(x1, 3);
    /* rnd_1: 4 - 6 */
    rax = (word64)(rax ^ r15);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r12);
    r10 = (word64)(r10 + rax);
    rcx = (word64)(r11);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 7 - 8 */
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r11);
    rdx = (word64)(rdx ^ r12);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x1, 6);
    /* rnd_1: 9 - 10 */
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r14 = (word64)(r14 + r10);
    rcx = (word64)(rcx ^ r11);
    r10 = (word64)(r10 + rdx);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 11 - 11 */
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r14);
    r10 = (word64)(r10 + rcx);
    x2 = _mm_add_epi64(x8, x2);
    /* msg_sched done: 4-5 */
    /* msg_sched: 6-7 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x12 = _mm_alignr_epi8(x4, x3, 8);
    x13 = _mm_alignr_epi8(x0, x7, 8);
    /* rnd_0: 1 - 1 */
    rdx = (word64)(r10);
    rcx = (word64)(r15);
    r9 = (word64)(r9 + WC_L64(rsp, 48));
    rcx = (word64)(rcx ^ r8);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 3 */
    rax = (word64)(rax ^ r14);
    rcx = (word64)(rcx & r14);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r8);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 4 - 5 */
    rax = (word64)(rax ^ r14);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r11);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 6 - 7 */
    r9 = (word64)(r9 + rax);
    rcx = (word64)(r10);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 8 - 9 */
    rcx = (word64)(rcx ^ r10);
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r13 = (word64)(r13 + r9);
    x8 = _mm_xor_si128(x8, x11);
    x3 = _mm_add_epi64(x13, x3);
    /* rnd_0: 10 - 11 */
    rcx = (word64)(rcx ^ r10);
    r9 = (word64)(r9 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r13);
    r9 = (word64)(r9 + rcx);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x3 = _mm_add_epi64(x8, x3);
    /* rnd_1: 1 - 1 */
    rbx = (word64)(r9);
    rcx = (word64)(r14);
    r8 = (word64)(r8 + WC_L64(rsp, 56));
    rcx = (word64)(rcx ^ r15);
    x8 = _mm_srli_epi64(x2, 19);
    x9 = _mm_slli_epi64(x2, 45);
    /* rnd_1: 2 - 3 */
    rax = (word64)(rax ^ r13);
    rcx = (word64)(rcx & r13);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r15);
    x10 = _mm_srli_epi64(x2, 61);
    x11 = _mm_slli_epi64(x2, 3);
    /* rnd_1: 4 - 6 */
    rax = (word64)(rax ^ r13);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r10);
    r8 = (word64)(r8 + rax);
    rcx = (word64)(r9);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 7 - 8 */
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r9);
    rdx = (word64)(rdx ^ r10);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x2, 6);
    /* rnd_1: 9 - 10 */
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r12 = (word64)(r12 + r8);
    rcx = (word64)(rcx ^ r9);
    r8 = (word64)(r8 + rdx);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 11 - 11 */
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r12);
    r8 = (word64)(r8 + rcx);
    x3 = _mm_add_epi64(x8, x3);
    /* msg_sched done: 6-7 */
    /* msg_sched: 8-9 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x12 = _mm_alignr_epi8(x5, x4, 8);
    x13 = _mm_alignr_epi8(x1, x0, 8);
    /* rnd_0: 1 - 1 */
    rdx = (word64)(r8);
    rcx = (word64)(r13);
    r15 = (word64)(r15 + WC_L64(rsp, 64));
    rcx = (word64)(rcx ^ r14);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 3 */
    rax = (word64)(rax ^ r12);
    rcx = (word64)(rcx & r12);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r14);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 4 - 5 */
    rax = (word64)(rax ^ r12);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r9);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 6 - 7 */
    r15 = (word64)(r15 + rax);
    rcx = (word64)(r8);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 8 - 9 */
    rcx = (word64)(rcx ^ r8);
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r11 = (word64)(r11 + r15);
    x8 = _mm_xor_si128(x8, x11);
    x4 = _mm_add_epi64(x13, x4);
    /* rnd_0: 10 - 11 */
    rcx = (word64)(rcx ^ r8);
    r15 = (word64)(r15 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r11);
    r15 = (word64)(r15 + rcx);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x4 = _mm_add_epi64(x8, x4);
    /* rnd_1: 1 - 1 */
    rbx = (word64)(r15);
    rcx = (word64)(r12);
    r14 = (word64)(r14 + WC_L64(rsp, 72));
    rcx = (word64)(rcx ^ r13);
    x8 = _mm_srli_epi64(x3, 19);
    x9 = _mm_slli_epi64(x3, 45);
    /* rnd_1: 2 - 3 */
    rax = (word64)(rax ^ r11);
    rcx = (word64)(rcx & r11);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r13);
    x10 = _mm_srli_epi64(x3, 61);
    x11 = _mm_slli_epi64(x3, 3);
    /* rnd_1: 4 - 6 */
    rax = (word64)(rax ^ r11);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r8);
    r14 = (word64)(r14 + rax);
    rcx = (word64)(r15);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 7 - 8 */
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r15);
    rdx = (word64)(rdx ^ r8);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x3, 6);
    /* rnd_1: 9 - 10 */
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r10 = (word64)(r10 + r14);
    rcx = (word64)(rcx ^ r15);
    r14 = (word64)(r14 + rdx);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 11 - 11 */
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r10);
    r14 = (word64)(r14 + rcx);
    x4 = _mm_add_epi64(x8, x4);
    /* msg_sched done: 8-9 */
    /* msg_sched: 10-11 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x12 = _mm_alignr_epi8(x6, x5, 8);
    x13 = _mm_alignr_epi8(x2, x1, 8);
    /* rnd_0: 1 - 1 */
    rdx = (word64)(r14);
    rcx = (word64)(r11);
    r13 = (word64)(r13 + WC_L64(rsp, 80));
    rcx = (word64)(rcx ^ r12);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 3 */
    rax = (word64)(rax ^ r10);
    rcx = (word64)(rcx & r10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r12);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 4 - 5 */
    rax = (word64)(rax ^ r10);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r15);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 6 - 7 */
    r13 = (word64)(r13 + rax);
    rcx = (word64)(r14);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 8 - 9 */
    rcx = (word64)(rcx ^ r14);
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r9 = (word64)(r9 + r13);
    x8 = _mm_xor_si128(x8, x11);
    x5 = _mm_add_epi64(x13, x5);
    /* rnd_0: 10 - 11 */
    rcx = (word64)(rcx ^ r14);
    r13 = (word64)(r13 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r9);
    r13 = (word64)(r13 + rcx);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x5 = _mm_add_epi64(x8, x5);
    /* rnd_1: 1 - 1 */
    rbx = (word64)(r13);
    rcx = (word64)(r10);
    r12 = (word64)(r12 + WC_L64(rsp, 88));
    rcx = (word64)(rcx ^ r11);
    x8 = _mm_srli_epi64(x4, 19);
    x9 = _mm_slli_epi64(x4, 45);
    /* rnd_1: 2 - 3 */
    rax = (word64)(rax ^ r9);
    rcx = (word64)(rcx & r9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r11);
    x10 = _mm_srli_epi64(x4, 61);
    x11 = _mm_slli_epi64(x4, 3);
    /* rnd_1: 4 - 6 */
    rax = (word64)(rax ^ r9);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r14);
    r12 = (word64)(r12 + rax);
    rcx = (word64)(r13);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 7 - 8 */
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r13);
    rdx = (word64)(rdx ^ r14);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x4, 6);
    /* rnd_1: 9 - 10 */
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r8 = (word64)(r8 + r12);
    rcx = (word64)(rcx ^ r13);
    r12 = (word64)(r12 + rdx);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 11 - 11 */
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r8);
    r12 = (word64)(r12 + rcx);
    x5 = _mm_add_epi64(x8, x5);
    /* msg_sched done: 10-11 */
    /* msg_sched: 12-13 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x12 = _mm_alignr_epi8(x7, x6, 8);
    x13 = _mm_alignr_epi8(x3, x2, 8);
    /* rnd_0: 1 - 1 */
    rdx = (word64)(r12);
    rcx = (word64)(r9);
    r11 = (word64)(r11 + WC_L64(rsp, 96));
    rcx = (word64)(rcx ^ r10);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 3 */
    rax = (word64)(rax ^ r8);
    rcx = (word64)(rcx & r8);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r10);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 4 - 5 */
    rax = (word64)(rax ^ r8);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r13);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 6 - 7 */
    r11 = (word64)(r11 + rax);
    rcx = (word64)(r12);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 8 - 9 */
    rcx = (word64)(rcx ^ r12);
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r15 = (word64)(r15 + r11);
    x8 = _mm_xor_si128(x8, x11);
    x6 = _mm_add_epi64(x13, x6);
    /* rnd_0: 10 - 11 */
    rcx = (word64)(rcx ^ r12);
    r11 = (word64)(r11 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r15);
    r11 = (word64)(r11 + rcx);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x6 = _mm_add_epi64(x8, x6);
    /* rnd_1: 1 - 1 */
    rbx = (word64)(r11);
    rcx = (word64)(r8);
    r10 = (word64)(r10 + WC_L64(rsp, 104));
    rcx = (word64)(rcx ^ r9);
    x8 = _mm_srli_epi64(x5, 19);
    x9 = _mm_slli_epi64(x5, 45);
    /* rnd_1: 2 - 3 */
    rax = (word64)(rax ^ r15);
    rcx = (word64)(rcx & r15);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r9);
    x10 = _mm_srli_epi64(x5, 61);
    x11 = _mm_slli_epi64(x5, 3);
    /* rnd_1: 4 - 6 */
    rax = (word64)(rax ^ r15);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r12);
    r10 = (word64)(r10 + rax);
    rcx = (word64)(r11);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 7 - 8 */
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r11);
    rdx = (word64)(rdx ^ r12);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x5, 6);
    /* rnd_1: 9 - 10 */
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r14 = (word64)(r14 + r10);
    rcx = (word64)(rcx ^ r11);
    r10 = (word64)(r10 + rdx);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 11 - 11 */
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r14);
    r10 = (word64)(r10 + rcx);
    x6 = _mm_add_epi64(x8, x6);
    /* msg_sched done: 12-13 */
    /* msg_sched: 14-15 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x12 = _mm_alignr_epi8(x0, x7, 8);
    x13 = _mm_alignr_epi8(x4, x3, 8);
    /* rnd_0: 1 - 1 */
    rdx = (word64)(r10);
    rcx = (word64)(r15);
    r9 = (word64)(r9 + WC_L64(rsp, 112));
    rcx = (word64)(rcx ^ r8);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 3 */
    rax = (word64)(rax ^ r14);
    rcx = (word64)(rcx & r14);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r8);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 4 - 5 */
    rax = (word64)(rax ^ r14);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r11);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 6 - 7 */
    r9 = (word64)(r9 + rax);
    rcx = (word64)(r10);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 8 - 9 */
    rcx = (word64)(rcx ^ r10);
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r13 = (word64)(r13 + r9);
    x8 = _mm_xor_si128(x8, x11);
    x7 = _mm_add_epi64(x13, x7);
    /* rnd_0: 10 - 11 */
    rcx = (word64)(rcx ^ r10);
    r9 = (word64)(r9 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r13);
    r9 = (word64)(r9 + rcx);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    x7 = _mm_add_epi64(x8, x7);
    /* rnd_1: 1 - 1 */
    rbx = (word64)(r9);
    rcx = (word64)(r14);
    r8 = (word64)(r8 + WC_L64(rsp, 120));
    rcx = (word64)(rcx ^ r15);
    x8 = _mm_srli_epi64(x6, 19);
    x9 = _mm_slli_epi64(x6, 45);
    /* rnd_1: 2 - 3 */
    rax = (word64)(rax ^ r13);
    rcx = (word64)(rcx & r13);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r15);
    x10 = _mm_srli_epi64(x6, 61);
    x11 = _mm_slli_epi64(x6, 3);
    /* rnd_1: 4 - 6 */
    rax = (word64)(rax ^ r13);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r10);
    r8 = (word64)(r8 + rax);
    rcx = (word64)(r9);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 7 - 8 */
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r9);
    rdx = (word64)(rdx ^ r10);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x6, 6);
    /* rnd_1: 9 - 10 */
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r12 = (word64)(r12 + r8);
    rcx = (word64)(rcx ^ r9);
    r8 = (word64)(r8 + rdx);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 11 - 11 */
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r12);
    r8 = (word64)(r8 + rcx);
    x7 = _mm_add_epi64(x8, x7);
    /* msg_sched done: 14-15 */
    rdx = (word64)(WC_L64(rsp, 136));
    x8 = _mm_add_epi64(x0, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0)));
    x9 = _mm_add_epi64(x1, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 16)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 16), x9);
    x8 = _mm_add_epi64(x2, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 32)));
    x9 = _mm_add_epi64(x3, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 48)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 32), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 48), x9);
    x8 = _mm_add_epi64(x4, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 64)));
    x9 = _mm_add_epi64(x5, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 80)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 64), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 80), x9);
    x8 = _mm_add_epi64(x6, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 96)));
    x9 = _mm_add_epi64(x7, _mm_loadu_si128((const __m128i*)WC_PR(rdx, 112)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 96), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 112), x9);
    WC_S32(rsp, 128) = (word32)(WC_L32(rsp, 128) - 1);
    if (((word32)WC_S32(rsp, 128)) != (0)) {
        goto L_sha512_len_avx1_start;
    }
    /* rnd_all_2: 0-1 */
    /* rnd_0: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r8);
    rcx = (word64)(r13);
    r15 = (word64)(r15 + WC_L64(rsp, 0));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    rcx = (word64)(rcx & r12);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r9);
    r15 = (word64)(r15 + rax);
    rcx = (word64)(r8);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r8);
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r11 = (word64)(r11 + r15);
    rcx = (word64)(rcx ^ r8);
    r15 = (word64)(r15 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r11);
    r15 = (word64)(r15 + rcx);
    /* rnd_1: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r15);
    rcx = (word64)(r12);
    r14 = (word64)(r14 + WC_L64(rsp, 8));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    rcx = (word64)(rcx & r11);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r8);
    r14 = (word64)(r14 + rax);
    rcx = (word64)(r15);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r15);
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r10 = (word64)(r10 + r14);
    rcx = (word64)(rcx ^ r15);
    r14 = (word64)(r14 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r10);
    r14 = (word64)(r14 + rcx);
    /* rnd_all_2: 2-3 */
    /* rnd_0: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r14);
    rcx = (word64)(r11);
    r13 = (word64)(r13 + WC_L64(rsp, 16));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    rcx = (word64)(rcx & r10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r15);
    r13 = (word64)(r13 + rax);
    rcx = (word64)(r14);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r14);
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r9 = (word64)(r9 + r13);
    rcx = (word64)(rcx ^ r14);
    r13 = (word64)(r13 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r9);
    r13 = (word64)(r13 + rcx);
    /* rnd_1: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r13);
    rcx = (word64)(r10);
    r12 = (word64)(r12 + WC_L64(rsp, 24));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    rcx = (word64)(rcx & r9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r14);
    r12 = (word64)(r12 + rax);
    rcx = (word64)(r13);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r13);
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r8 = (word64)(r8 + r12);
    rcx = (word64)(rcx ^ r13);
    r12 = (word64)(r12 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r8);
    r12 = (word64)(r12 + rcx);
    /* rnd_all_2: 4-5 */
    /* rnd_0: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r12);
    rcx = (word64)(r9);
    r11 = (word64)(r11 + WC_L64(rsp, 32));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    rcx = (word64)(rcx & r8);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r13);
    r11 = (word64)(r11 + rax);
    rcx = (word64)(r12);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r12);
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r15 = (word64)(r15 + r11);
    rcx = (word64)(rcx ^ r12);
    r11 = (word64)(r11 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r15);
    r11 = (word64)(r11 + rcx);
    /* rnd_1: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r11);
    rcx = (word64)(r8);
    r10 = (word64)(r10 + WC_L64(rsp, 40));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    rcx = (word64)(rcx & r15);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r12);
    r10 = (word64)(r10 + rax);
    rcx = (word64)(r11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r11);
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r14 = (word64)(r14 + r10);
    rcx = (word64)(rcx ^ r11);
    r10 = (word64)(r10 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r14);
    r10 = (word64)(r10 + rcx);
    /* rnd_all_2: 6-7 */
    /* rnd_0: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r10);
    rcx = (word64)(r15);
    r9 = (word64)(r9 + WC_L64(rsp, 48));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    rcx = (word64)(rcx & r14);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r11);
    r9 = (word64)(r9 + rax);
    rcx = (word64)(r10);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r10);
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r13 = (word64)(r13 + r9);
    rcx = (word64)(rcx ^ r10);
    r9 = (word64)(r9 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r13);
    r9 = (word64)(r9 + rcx);
    /* rnd_1: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r9);
    rcx = (word64)(r14);
    r8 = (word64)(r8 + WC_L64(rsp, 56));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    rcx = (word64)(rcx & r13);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r10);
    r8 = (word64)(r8 + rax);
    rcx = (word64)(r9);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r9);
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r12 = (word64)(r12 + r8);
    rcx = (word64)(rcx ^ r9);
    r8 = (word64)(r8 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r12);
    r8 = (word64)(r8 + rcx);
    /* rnd_all_2: 8-9 */
    /* rnd_0: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r8);
    rcx = (word64)(r13);
    r15 = (word64)(r15 + WC_L64(rsp, 64));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    rcx = (word64)(rcx & r12);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r9);
    r15 = (word64)(r15 + rax);
    rcx = (word64)(r8);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r8);
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r11 = (word64)(r11 + r15);
    rcx = (word64)(rcx ^ r8);
    r15 = (word64)(r15 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r11);
    r15 = (word64)(r15 + rcx);
    /* rnd_1: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r15);
    rcx = (word64)(r12);
    r14 = (word64)(r14 + WC_L64(rsp, 72));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    rcx = (word64)(rcx & r11);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r8);
    r14 = (word64)(r14 + rax);
    rcx = (word64)(r15);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r15);
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r10 = (word64)(r10 + r14);
    rcx = (word64)(rcx ^ r15);
    r14 = (word64)(r14 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r10);
    r14 = (word64)(r14 + rcx);
    /* rnd_all_2: 10-11 */
    /* rnd_0: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r14);
    rcx = (word64)(r11);
    r13 = (word64)(r13 + WC_L64(rsp, 80));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    rcx = (word64)(rcx & r10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r15);
    r13 = (word64)(r13 + rax);
    rcx = (word64)(r14);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r14);
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r9 = (word64)(r9 + r13);
    rcx = (word64)(rcx ^ r14);
    r13 = (word64)(r13 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r9);
    r13 = (word64)(r13 + rcx);
    /* rnd_1: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r13);
    rcx = (word64)(r10);
    r12 = (word64)(r12 + WC_L64(rsp, 88));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    rcx = (word64)(rcx & r9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r14);
    r12 = (word64)(r12 + rax);
    rcx = (word64)(r13);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r13);
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r8 = (word64)(r8 + r12);
    rcx = (word64)(rcx ^ r13);
    r12 = (word64)(r12 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r8);
    r12 = (word64)(r12 + rcx);
    /* rnd_all_2: 12-13 */
    /* rnd_0: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r12);
    rcx = (word64)(r9);
    r11 = (word64)(r11 + WC_L64(rsp, 96));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    rcx = (word64)(rcx & r8);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r13);
    r11 = (word64)(r11 + rax);
    rcx = (word64)(r12);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r12);
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r15 = (word64)(r15 + r11);
    rcx = (word64)(rcx ^ r12);
    r11 = (word64)(r11 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r15);
    r11 = (word64)(r11 + rcx);
    /* rnd_1: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r11);
    rcx = (word64)(r8);
    r10 = (word64)(r10 + WC_L64(rsp, 104));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    rcx = (word64)(rcx & r15);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r12);
    r10 = (word64)(r10 + rax);
    rcx = (word64)(r11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r11);
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r14 = (word64)(r14 + r10);
    rcx = (word64)(rcx ^ r11);
    r10 = (word64)(r10 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r14);
    r10 = (word64)(r10 + rcx);
    /* rnd_all_2: 14-15 */
    /* rnd_0: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r10);
    rcx = (word64)(r15);
    r9 = (word64)(r9 + WC_L64(rsp, 112));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    rcx = (word64)(rcx & r14);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r11);
    r9 = (word64)(r9 + rax);
    rcx = (word64)(r10);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r10);
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r13 = (word64)(r13 + r9);
    rcx = (word64)(rcx ^ r10);
    r9 = (word64)(r9 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r13);
    r9 = (word64)(r9 + rcx);
    /* rnd_1: 0 - 11 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r9);
    rcx = (word64)(r14);
    r8 = (word64)(r8 + WC_L64(rsp, 120));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    rcx = (word64)(rcx & r13);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r10);
    r8 = (word64)(r8 + rax);
    rcx = (word64)(r9);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r9);
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r12 = (word64)(r12 + r8);
    rcx = (word64)(rcx ^ r9);
    r8 = (word64)(r8 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r12);
    r8 = (word64)(r8 + rcx);
    r8 = (word64)(r8 + WC_L64(rdi, 0));
    r9 = (word64)(r9 + WC_L64(rdi, 8));
    r10 = (word64)(r10 + WC_L64(rdi, 16));
    r11 = (word64)(r11 + WC_L64(rdi, 24));
    r12 = (word64)(r12 + WC_L64(rdi, 32));
    r13 = (word64)(r13 + WC_L64(rdi, 40));
    r14 = (word64)(r14 + WC_L64(rdi, 48));
    r15 = (word64)(r15 + WC_L64(rdi, 56));
    rdx = (word64)((word64)(size_t)L_avx1_sha512_k);
    rsi = (word64)(rsi + 0x80);
    rbp = (word32)((word32)rbp - 0x80);
    zf1 = (word32)rbp;
    WC_S64(rdi, 0) = (word64)(r8);
    WC_S64(rdi, 8) = (word64)(r9);
    WC_S64(rdi, 16) = (word64)(r10);
    WC_S64(rdi, 24) = (word64)(r11);
    WC_S64(rdi, 32) = (word64)(r12);
    WC_S64(rdi, 40) = (word64)(r13);
    WC_S64(rdi, 48) = (word64)(r14);
    WC_S64(rdi, 56) = (word64)(r15);
    if ((zf1) != (0)) {
        goto L_sha512_len_avx1_begin;
    }
    rax = (word64)(0);
    return (int)(word32)rax;
}

XALIGNED(32) static const word64 L_avx1_rorx_sha512_k[] WC_X64I_UNUSED = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

XALIGNED(16) static const word64 L_avx1_rorx_sha512_flip_mask[]
    WC_X64I_UNUSED = {
    0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL,
};

WC_X64I_TARGET("avx,bmi2")
WOLFSSL_LOCAL int Transform_Sha512_AVX1_RORX(wc_Sha512* sha512)
{
    word64 rdi, rsp, rax, r8, r9, r10, r11, r12, r13, r14, r15, rsi, rbx, rdx,
           rcx = 0;
    __m128i x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10 = _mm_setzero_si128(),
            x11 = _mm_setzero_si128(), x12 = _mm_setzero_si128(),
            x13 = _mm_setzero_si128(), x14;
    XALIGNED(32) WC_X64I_SLOT stk[20];

    rdi = (word64)(size_t)sha512;

    rsp = (word64)(size_t)stk + 160;
    rsp = (word64)(rsp - 136);
    rax = (word64)(rdi + 64);
    x14 = _mm_loadu_si128((const __m128i*)WC_PR(L_avx1_rorx_sha512_flip_mask,
        0));
    r8 = (word64)(WC_L64(rdi, 0));
    r9 = (word64)(WC_L64(rdi, 8));
    r10 = (word64)(WC_L64(rdi, 16));
    r11 = (word64)(WC_L64(rdi, 24));
    r12 = (word64)(WC_L64(rdi, 32));
    r13 = (word64)(WC_L64(rdi, 40));
    r14 = (word64)(WC_L64(rdi, 48));
    r15 = (word64)(WC_L64(rdi, 56));
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rax, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(rax, 16));
    x0 = _mm_shuffle_epi8(x0, x14);
    x1 = _mm_shuffle_epi8(x1, x14);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rax, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(rax, 48));
    x2 = _mm_shuffle_epi8(x2, x14);
    x3 = _mm_shuffle_epi8(x3, x14);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rax, 64));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rax, 80));
    x4 = _mm_shuffle_epi8(x4, x14);
    x5 = _mm_shuffle_epi8(x5, x14);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rax, 96));
    x7 = _mm_loadu_si128((const __m128i*)WC_PR(rax, 112));
    x6 = _mm_shuffle_epi8(x6, x14);
    x7 = _mm_shuffle_epi8(x7, x14);
    WC_S32(rsp, 128) = (word32)(4);
    rsi = (word64)((word64)(size_t)L_avx1_rorx_sha512_k);
    rbx = (word64)(r9);
    rdx = (word64)(0);
    rbx = (word64)(rbx ^ r10);
    x8 = _mm_add_epi64(x0, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 0)));
    x9 = _mm_add_epi64(x1, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 16)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 16), x9);
    x8 = _mm_add_epi64(x2, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 32)));
    x9 = _mm_add_epi64(x3, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 48)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 32), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 48), x9);
    x8 = _mm_add_epi64(x4, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 64)));
    x9 = _mm_add_epi64(x5, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 80)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 64), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 80), x9);
    x8 = _mm_add_epi64(x6, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 96)));
    x9 = _mm_add_epi64(x7, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 112)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 96), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 112), x9);
    /* Start of 16 rounds */
L_transform_sha512_avx1_rorx_start:
    rsi = (word64)(rsi + 0x80);
    /* msg_sched: 0-1 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((r12) >> 14) | ((r12) << 50));
    rcx = (word64)(((r12) >> 18) | ((r12) << 46));
    r8 = (word64)(r8 + rdx);
    x12 = _mm_alignr_epi8(x1, x0, 8);
    x13 = _mm_alignr_epi8(x5, x4, 8);
    /* rnd_0: 1 - 1 */
    r15 = (word64)(r15 + WC_L64(rsp, 0));
    rdx = (word64)(r13);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 2 */
    rdx = (word64)(rdx ^ r14);
    rax = (word64)(((r12) >> 41) | ((r12) << 23));
    rax = (word64)(rax ^ rcx);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 3 - 3 */
    rdx = (word64)(rdx & r12);
    r15 = (word64)(r15 + rax);
    rax = (word64)(((r8) >> 28) | ((r8) << 36));
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 4 - 4 */
    rcx = (word64)(((r8) >> 34) | ((r8) << 30));
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(rcx ^ rax);
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 5 - 5 */
    rax = (word64)(((r8) >> 39) | ((r8) << 25));
    r15 = (word64)(r15 + rdx);
    rax = (word64)(rax ^ rcx);
    x8 = _mm_xor_si128(x8, x11);
    x0 = _mm_add_epi64(x13, x0);
    /* rnd_0: 6 - 7 */
    rdx = (word64)(r9);
    r11 = (word64)(r11 + r15);
    rdx = (word64)(rdx ^ r8);
    rbx = (word64)(rbx & rdx);
    r15 = (word64)(r15 + rax);
    rbx = (word64)(rbx ^ r9);
    x0 = _mm_add_epi64(x8, x0);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((r11) >> 14) | ((r11) << 50));
    rcx = (word64)(((r11) >> 18) | ((r11) << 46));
    r15 = (word64)(r15 + rbx);
    x8 = _mm_srli_epi64(x7, 19);
    x9 = _mm_slli_epi64(x7, 45);
    /* rnd_1: 1 - 1 */
    r14 = (word64)(r14 + WC_L64(rsp, 8));
    rbx = (word64)(r12);
    rcx = (word64)(rcx ^ rax);
    x10 = _mm_srli_epi64(x7, 61);
    x11 = _mm_slli_epi64(x7, 3);
    /* rnd_1: 2 - 2 */
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r11) >> 41) | ((r11) << 23));
    rax = (word64)(rax ^ rcx);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 3 - 4 */
    rbx = (word64)(rbx & r11);
    r14 = (word64)(r14 + rax);
    rax = (word64)(((r15) >> 28) | ((r15) << 36));
    rcx = (word64)(((r15) >> 34) | ((r15) << 30));
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x7, 6);
    /* rnd_1: 5 - 6 */
    rax = (word64)(((r15) >> 39) | ((r15) << 25));
    r14 = (word64)(r14 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r8);
    r10 = (word64)(r10 + r14);
    rbx = (word64)(rbx ^ r15);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 7 - 7 */
    rdx = (word64)(rdx & rbx);
    r14 = (word64)(r14 + rax);
    rdx = (word64)(rdx ^ r8);
    x0 = _mm_add_epi64(x8, x0);
    /* msg_sched done: 0-1 */
    /* msg_sched: 2-3 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((r10) >> 14) | ((r10) << 50));
    rcx = (word64)(((r10) >> 18) | ((r10) << 46));
    r14 = (word64)(r14 + rdx);
    x12 = _mm_alignr_epi8(x2, x1, 8);
    x13 = _mm_alignr_epi8(x6, x5, 8);
    /* rnd_0: 1 - 1 */
    r13 = (word64)(r13 + WC_L64(rsp, 16));
    rdx = (word64)(r11);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 2 */
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r10) >> 41) | ((r10) << 23));
    rax = (word64)(rax ^ rcx);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 3 - 3 */
    rdx = (word64)(rdx & r10);
    r13 = (word64)(r13 + rax);
    rax = (word64)(((r14) >> 28) | ((r14) << 36));
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 4 - 4 */
    rcx = (word64)(((r14) >> 34) | ((r14) << 30));
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(rcx ^ rax);
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 5 - 5 */
    rax = (word64)(((r14) >> 39) | ((r14) << 25));
    r13 = (word64)(r13 + rdx);
    rax = (word64)(rax ^ rcx);
    x8 = _mm_xor_si128(x8, x11);
    x1 = _mm_add_epi64(x13, x1);
    /* rnd_0: 6 - 7 */
    rdx = (word64)(r15);
    r9 = (word64)(r9 + r13);
    rdx = (word64)(rdx ^ r14);
    rbx = (word64)(rbx & rdx);
    r13 = (word64)(r13 + rax);
    rbx = (word64)(rbx ^ r15);
    x1 = _mm_add_epi64(x8, x1);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((r9) >> 14) | ((r9) << 50));
    rcx = (word64)(((r9) >> 18) | ((r9) << 46));
    r13 = (word64)(r13 + rbx);
    x8 = _mm_srli_epi64(x0, 19);
    x9 = _mm_slli_epi64(x0, 45);
    /* rnd_1: 1 - 1 */
    r12 = (word64)(r12 + WC_L64(rsp, 24));
    rbx = (word64)(r10);
    rcx = (word64)(rcx ^ rax);
    x10 = _mm_srli_epi64(x0, 61);
    x11 = _mm_slli_epi64(x0, 3);
    /* rnd_1: 2 - 2 */
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r9) >> 41) | ((r9) << 23));
    rax = (word64)(rax ^ rcx);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 3 - 4 */
    rbx = (word64)(rbx & r9);
    r12 = (word64)(r12 + rax);
    rax = (word64)(((r13) >> 28) | ((r13) << 36));
    rcx = (word64)(((r13) >> 34) | ((r13) << 30));
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x0, 6);
    /* rnd_1: 5 - 6 */
    rax = (word64)(((r13) >> 39) | ((r13) << 25));
    r12 = (word64)(r12 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r14);
    r8 = (word64)(r8 + r12);
    rbx = (word64)(rbx ^ r13);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 7 - 7 */
    rdx = (word64)(rdx & rbx);
    r12 = (word64)(r12 + rax);
    rdx = (word64)(rdx ^ r14);
    x1 = _mm_add_epi64(x8, x1);
    /* msg_sched done: 2-3 */
    /* msg_sched: 4-5 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((r8) >> 14) | ((r8) << 50));
    rcx = (word64)(((r8) >> 18) | ((r8) << 46));
    r12 = (word64)(r12 + rdx);
    x12 = _mm_alignr_epi8(x3, x2, 8);
    x13 = _mm_alignr_epi8(x7, x6, 8);
    /* rnd_0: 1 - 1 */
    r11 = (word64)(r11 + WC_L64(rsp, 32));
    rdx = (word64)(r9);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 2 */
    rdx = (word64)(rdx ^ r10);
    rax = (word64)(((r8) >> 41) | ((r8) << 23));
    rax = (word64)(rax ^ rcx);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 3 - 3 */
    rdx = (word64)(rdx & r8);
    r11 = (word64)(r11 + rax);
    rax = (word64)(((r12) >> 28) | ((r12) << 36));
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 4 - 4 */
    rcx = (word64)(((r12) >> 34) | ((r12) << 30));
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(rcx ^ rax);
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 5 - 5 */
    rax = (word64)(((r12) >> 39) | ((r12) << 25));
    r11 = (word64)(r11 + rdx);
    rax = (word64)(rax ^ rcx);
    x8 = _mm_xor_si128(x8, x11);
    x2 = _mm_add_epi64(x13, x2);
    /* rnd_0: 6 - 7 */
    rdx = (word64)(r13);
    r15 = (word64)(r15 + r11);
    rdx = (word64)(rdx ^ r12);
    rbx = (word64)(rbx & rdx);
    r11 = (word64)(r11 + rax);
    rbx = (word64)(rbx ^ r13);
    x2 = _mm_add_epi64(x8, x2);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((r15) >> 14) | ((r15) << 50));
    rcx = (word64)(((r15) >> 18) | ((r15) << 46));
    r11 = (word64)(r11 + rbx);
    x8 = _mm_srli_epi64(x1, 19);
    x9 = _mm_slli_epi64(x1, 45);
    /* rnd_1: 1 - 1 */
    r10 = (word64)(r10 + WC_L64(rsp, 40));
    rbx = (word64)(r8);
    rcx = (word64)(rcx ^ rax);
    x10 = _mm_srli_epi64(x1, 61);
    x11 = _mm_slli_epi64(x1, 3);
    /* rnd_1: 2 - 2 */
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r15) >> 41) | ((r15) << 23));
    rax = (word64)(rax ^ rcx);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 3 - 4 */
    rbx = (word64)(rbx & r15);
    r10 = (word64)(r10 + rax);
    rax = (word64)(((r11) >> 28) | ((r11) << 36));
    rcx = (word64)(((r11) >> 34) | ((r11) << 30));
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x1, 6);
    /* rnd_1: 5 - 6 */
    rax = (word64)(((r11) >> 39) | ((r11) << 25));
    r10 = (word64)(r10 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r12);
    r14 = (word64)(r14 + r10);
    rbx = (word64)(rbx ^ r11);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 7 - 7 */
    rdx = (word64)(rdx & rbx);
    r10 = (word64)(r10 + rax);
    rdx = (word64)(rdx ^ r12);
    x2 = _mm_add_epi64(x8, x2);
    /* msg_sched done: 4-5 */
    /* msg_sched: 6-7 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((r14) >> 14) | ((r14) << 50));
    rcx = (word64)(((r14) >> 18) | ((r14) << 46));
    r10 = (word64)(r10 + rdx);
    x12 = _mm_alignr_epi8(x4, x3, 8);
    x13 = _mm_alignr_epi8(x0, x7, 8);
    /* rnd_0: 1 - 1 */
    r9 = (word64)(r9 + WC_L64(rsp, 48));
    rdx = (word64)(r15);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 2 */
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r14) >> 41) | ((r14) << 23));
    rax = (word64)(rax ^ rcx);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 3 - 3 */
    rdx = (word64)(rdx & r14);
    r9 = (word64)(r9 + rax);
    rax = (word64)(((r10) >> 28) | ((r10) << 36));
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 4 - 4 */
    rcx = (word64)(((r10) >> 34) | ((r10) << 30));
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(rcx ^ rax);
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 5 - 5 */
    rax = (word64)(((r10) >> 39) | ((r10) << 25));
    r9 = (word64)(r9 + rdx);
    rax = (word64)(rax ^ rcx);
    x8 = _mm_xor_si128(x8, x11);
    x3 = _mm_add_epi64(x13, x3);
    /* rnd_0: 6 - 7 */
    rdx = (word64)(r11);
    r13 = (word64)(r13 + r9);
    rdx = (word64)(rdx ^ r10);
    rbx = (word64)(rbx & rdx);
    r9 = (word64)(r9 + rax);
    rbx = (word64)(rbx ^ r11);
    x3 = _mm_add_epi64(x8, x3);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((r13) >> 14) | ((r13) << 50));
    rcx = (word64)(((r13) >> 18) | ((r13) << 46));
    r9 = (word64)(r9 + rbx);
    x8 = _mm_srli_epi64(x2, 19);
    x9 = _mm_slli_epi64(x2, 45);
    /* rnd_1: 1 - 1 */
    r8 = (word64)(r8 + WC_L64(rsp, 56));
    rbx = (word64)(r14);
    rcx = (word64)(rcx ^ rax);
    x10 = _mm_srli_epi64(x2, 61);
    x11 = _mm_slli_epi64(x2, 3);
    /* rnd_1: 2 - 2 */
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r13) >> 41) | ((r13) << 23));
    rax = (word64)(rax ^ rcx);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 3 - 4 */
    rbx = (word64)(rbx & r13);
    r8 = (word64)(r8 + rax);
    rax = (word64)(((r9) >> 28) | ((r9) << 36));
    rcx = (word64)(((r9) >> 34) | ((r9) << 30));
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x2, 6);
    /* rnd_1: 5 - 6 */
    rax = (word64)(((r9) >> 39) | ((r9) << 25));
    r8 = (word64)(r8 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r10);
    r12 = (word64)(r12 + r8);
    rbx = (word64)(rbx ^ r9);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 7 - 7 */
    rdx = (word64)(rdx & rbx);
    r8 = (word64)(r8 + rax);
    rdx = (word64)(rdx ^ r10);
    x3 = _mm_add_epi64(x8, x3);
    /* msg_sched done: 6-7 */
    /* msg_sched: 8-9 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((r12) >> 14) | ((r12) << 50));
    rcx = (word64)(((r12) >> 18) | ((r12) << 46));
    r8 = (word64)(r8 + rdx);
    x12 = _mm_alignr_epi8(x5, x4, 8);
    x13 = _mm_alignr_epi8(x1, x0, 8);
    /* rnd_0: 1 - 1 */
    r15 = (word64)(r15 + WC_L64(rsp, 64));
    rdx = (word64)(r13);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 2 */
    rdx = (word64)(rdx ^ r14);
    rax = (word64)(((r12) >> 41) | ((r12) << 23));
    rax = (word64)(rax ^ rcx);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 3 - 3 */
    rdx = (word64)(rdx & r12);
    r15 = (word64)(r15 + rax);
    rax = (word64)(((r8) >> 28) | ((r8) << 36));
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 4 - 4 */
    rcx = (word64)(((r8) >> 34) | ((r8) << 30));
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(rcx ^ rax);
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 5 - 5 */
    rax = (word64)(((r8) >> 39) | ((r8) << 25));
    r15 = (word64)(r15 + rdx);
    rax = (word64)(rax ^ rcx);
    x8 = _mm_xor_si128(x8, x11);
    x4 = _mm_add_epi64(x13, x4);
    /* rnd_0: 6 - 7 */
    rdx = (word64)(r9);
    r11 = (word64)(r11 + r15);
    rdx = (word64)(rdx ^ r8);
    rbx = (word64)(rbx & rdx);
    r15 = (word64)(r15 + rax);
    rbx = (word64)(rbx ^ r9);
    x4 = _mm_add_epi64(x8, x4);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((r11) >> 14) | ((r11) << 50));
    rcx = (word64)(((r11) >> 18) | ((r11) << 46));
    r15 = (word64)(r15 + rbx);
    x8 = _mm_srli_epi64(x3, 19);
    x9 = _mm_slli_epi64(x3, 45);
    /* rnd_1: 1 - 1 */
    r14 = (word64)(r14 + WC_L64(rsp, 72));
    rbx = (word64)(r12);
    rcx = (word64)(rcx ^ rax);
    x10 = _mm_srli_epi64(x3, 61);
    x11 = _mm_slli_epi64(x3, 3);
    /* rnd_1: 2 - 2 */
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r11) >> 41) | ((r11) << 23));
    rax = (word64)(rax ^ rcx);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 3 - 4 */
    rbx = (word64)(rbx & r11);
    r14 = (word64)(r14 + rax);
    rax = (word64)(((r15) >> 28) | ((r15) << 36));
    rcx = (word64)(((r15) >> 34) | ((r15) << 30));
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x3, 6);
    /* rnd_1: 5 - 6 */
    rax = (word64)(((r15) >> 39) | ((r15) << 25));
    r14 = (word64)(r14 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r8);
    r10 = (word64)(r10 + r14);
    rbx = (word64)(rbx ^ r15);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 7 - 7 */
    rdx = (word64)(rdx & rbx);
    r14 = (word64)(r14 + rax);
    rdx = (word64)(rdx ^ r8);
    x4 = _mm_add_epi64(x8, x4);
    /* msg_sched done: 8-9 */
    /* msg_sched: 10-11 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((r10) >> 14) | ((r10) << 50));
    rcx = (word64)(((r10) >> 18) | ((r10) << 46));
    r14 = (word64)(r14 + rdx);
    x12 = _mm_alignr_epi8(x6, x5, 8);
    x13 = _mm_alignr_epi8(x2, x1, 8);
    /* rnd_0: 1 - 1 */
    r13 = (word64)(r13 + WC_L64(rsp, 80));
    rdx = (word64)(r11);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 2 */
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r10) >> 41) | ((r10) << 23));
    rax = (word64)(rax ^ rcx);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 3 - 3 */
    rdx = (word64)(rdx & r10);
    r13 = (word64)(r13 + rax);
    rax = (word64)(((r14) >> 28) | ((r14) << 36));
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 4 - 4 */
    rcx = (word64)(((r14) >> 34) | ((r14) << 30));
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(rcx ^ rax);
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 5 - 5 */
    rax = (word64)(((r14) >> 39) | ((r14) << 25));
    r13 = (word64)(r13 + rdx);
    rax = (word64)(rax ^ rcx);
    x8 = _mm_xor_si128(x8, x11);
    x5 = _mm_add_epi64(x13, x5);
    /* rnd_0: 6 - 7 */
    rdx = (word64)(r15);
    r9 = (word64)(r9 + r13);
    rdx = (word64)(rdx ^ r14);
    rbx = (word64)(rbx & rdx);
    r13 = (word64)(r13 + rax);
    rbx = (word64)(rbx ^ r15);
    x5 = _mm_add_epi64(x8, x5);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((r9) >> 14) | ((r9) << 50));
    rcx = (word64)(((r9) >> 18) | ((r9) << 46));
    r13 = (word64)(r13 + rbx);
    x8 = _mm_srli_epi64(x4, 19);
    x9 = _mm_slli_epi64(x4, 45);
    /* rnd_1: 1 - 1 */
    r12 = (word64)(r12 + WC_L64(rsp, 88));
    rbx = (word64)(r10);
    rcx = (word64)(rcx ^ rax);
    x10 = _mm_srli_epi64(x4, 61);
    x11 = _mm_slli_epi64(x4, 3);
    /* rnd_1: 2 - 2 */
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r9) >> 41) | ((r9) << 23));
    rax = (word64)(rax ^ rcx);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 3 - 4 */
    rbx = (word64)(rbx & r9);
    r12 = (word64)(r12 + rax);
    rax = (word64)(((r13) >> 28) | ((r13) << 36));
    rcx = (word64)(((r13) >> 34) | ((r13) << 30));
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x4, 6);
    /* rnd_1: 5 - 6 */
    rax = (word64)(((r13) >> 39) | ((r13) << 25));
    r12 = (word64)(r12 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r14);
    r8 = (word64)(r8 + r12);
    rbx = (word64)(rbx ^ r13);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 7 - 7 */
    rdx = (word64)(rdx & rbx);
    r12 = (word64)(r12 + rax);
    rdx = (word64)(rdx ^ r14);
    x5 = _mm_add_epi64(x8, x5);
    /* msg_sched done: 10-11 */
    /* msg_sched: 12-13 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((r8) >> 14) | ((r8) << 50));
    rcx = (word64)(((r8) >> 18) | ((r8) << 46));
    r12 = (word64)(r12 + rdx);
    x12 = _mm_alignr_epi8(x7, x6, 8);
    x13 = _mm_alignr_epi8(x3, x2, 8);
    /* rnd_0: 1 - 1 */
    r11 = (word64)(r11 + WC_L64(rsp, 96));
    rdx = (word64)(r9);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 2 */
    rdx = (word64)(rdx ^ r10);
    rax = (word64)(((r8) >> 41) | ((r8) << 23));
    rax = (word64)(rax ^ rcx);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 3 - 3 */
    rdx = (word64)(rdx & r8);
    r11 = (word64)(r11 + rax);
    rax = (word64)(((r12) >> 28) | ((r12) << 36));
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 4 - 4 */
    rcx = (word64)(((r12) >> 34) | ((r12) << 30));
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(rcx ^ rax);
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 5 - 5 */
    rax = (word64)(((r12) >> 39) | ((r12) << 25));
    r11 = (word64)(r11 + rdx);
    rax = (word64)(rax ^ rcx);
    x8 = _mm_xor_si128(x8, x11);
    x6 = _mm_add_epi64(x13, x6);
    /* rnd_0: 6 - 7 */
    rdx = (word64)(r13);
    r15 = (word64)(r15 + r11);
    rdx = (word64)(rdx ^ r12);
    rbx = (word64)(rbx & rdx);
    r11 = (word64)(r11 + rax);
    rbx = (word64)(rbx ^ r13);
    x6 = _mm_add_epi64(x8, x6);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((r15) >> 14) | ((r15) << 50));
    rcx = (word64)(((r15) >> 18) | ((r15) << 46));
    r11 = (word64)(r11 + rbx);
    x8 = _mm_srli_epi64(x5, 19);
    x9 = _mm_slli_epi64(x5, 45);
    /* rnd_1: 1 - 1 */
    r10 = (word64)(r10 + WC_L64(rsp, 104));
    rbx = (word64)(r8);
    rcx = (word64)(rcx ^ rax);
    x10 = _mm_srli_epi64(x5, 61);
    x11 = _mm_slli_epi64(x5, 3);
    /* rnd_1: 2 - 2 */
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r15) >> 41) | ((r15) << 23));
    rax = (word64)(rax ^ rcx);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 3 - 4 */
    rbx = (word64)(rbx & r15);
    r10 = (word64)(r10 + rax);
    rax = (word64)(((r11) >> 28) | ((r11) << 36));
    rcx = (word64)(((r11) >> 34) | ((r11) << 30));
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x5, 6);
    /* rnd_1: 5 - 6 */
    rax = (word64)(((r11) >> 39) | ((r11) << 25));
    r10 = (word64)(r10 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r12);
    r14 = (word64)(r14 + r10);
    rbx = (word64)(rbx ^ r11);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 7 - 7 */
    rdx = (word64)(rdx & rbx);
    r10 = (word64)(r10 + rax);
    rdx = (word64)(rdx ^ r12);
    x6 = _mm_add_epi64(x8, x6);
    /* msg_sched done: 12-13 */
    /* msg_sched: 14-15 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((r14) >> 14) | ((r14) << 50));
    rcx = (word64)(((r14) >> 18) | ((r14) << 46));
    r10 = (word64)(r10 + rdx);
    x12 = _mm_alignr_epi8(x0, x7, 8);
    x13 = _mm_alignr_epi8(x4, x3, 8);
    /* rnd_0: 1 - 1 */
    r9 = (word64)(r9 + WC_L64(rsp, 112));
    rdx = (word64)(r15);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 2 */
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r14) >> 41) | ((r14) << 23));
    rax = (word64)(rax ^ rcx);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 3 - 3 */
    rdx = (word64)(rdx & r14);
    r9 = (word64)(r9 + rax);
    rax = (word64)(((r10) >> 28) | ((r10) << 36));
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 4 - 4 */
    rcx = (word64)(((r10) >> 34) | ((r10) << 30));
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(rcx ^ rax);
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 5 - 5 */
    rax = (word64)(((r10) >> 39) | ((r10) << 25));
    r9 = (word64)(r9 + rdx);
    rax = (word64)(rax ^ rcx);
    x8 = _mm_xor_si128(x8, x11);
    x7 = _mm_add_epi64(x13, x7);
    /* rnd_0: 6 - 7 */
    rdx = (word64)(r11);
    r13 = (word64)(r13 + r9);
    rdx = (word64)(rdx ^ r10);
    rbx = (word64)(rbx & rdx);
    r9 = (word64)(r9 + rax);
    rbx = (word64)(rbx ^ r11);
    x7 = _mm_add_epi64(x8, x7);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((r13) >> 14) | ((r13) << 50));
    rcx = (word64)(((r13) >> 18) | ((r13) << 46));
    r9 = (word64)(r9 + rbx);
    x8 = _mm_srli_epi64(x6, 19);
    x9 = _mm_slli_epi64(x6, 45);
    /* rnd_1: 1 - 1 */
    r8 = (word64)(r8 + WC_L64(rsp, 120));
    rbx = (word64)(r14);
    rcx = (word64)(rcx ^ rax);
    x10 = _mm_srli_epi64(x6, 61);
    x11 = _mm_slli_epi64(x6, 3);
    /* rnd_1: 2 - 2 */
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r13) >> 41) | ((r13) << 23));
    rax = (word64)(rax ^ rcx);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 3 - 4 */
    rbx = (word64)(rbx & r13);
    r8 = (word64)(r8 + rax);
    rax = (word64)(((r9) >> 28) | ((r9) << 36));
    rcx = (word64)(((r9) >> 34) | ((r9) << 30));
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x6, 6);
    /* rnd_1: 5 - 6 */
    rax = (word64)(((r9) >> 39) | ((r9) << 25));
    r8 = (word64)(r8 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r10);
    r12 = (word64)(r12 + r8);
    rbx = (word64)(rbx ^ r9);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 7 - 7 */
    rdx = (word64)(rdx & rbx);
    r8 = (word64)(r8 + rax);
    rdx = (word64)(rdx ^ r10);
    x7 = _mm_add_epi64(x8, x7);
    /* msg_sched done: 14-15 */
    x8 = _mm_add_epi64(x0, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 0)));
    x9 = _mm_add_epi64(x1, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 16)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 16), x9);
    x8 = _mm_add_epi64(x2, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 32)));
    x9 = _mm_add_epi64(x3, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 48)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 32), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 48), x9);
    x8 = _mm_add_epi64(x4, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 64)));
    x9 = _mm_add_epi64(x5, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 80)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 64), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 80), x9);
    x8 = _mm_add_epi64(x6, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 96)));
    x9 = _mm_add_epi64(x7, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 112)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 96), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 112), x9);
    WC_S32(rsp, 128) = (word32)(WC_L32(rsp, 128) - 1);
    if (((word32)WC_S32(rsp, 128)) != (0)) {
        goto L_transform_sha512_avx1_rorx_start;
    }
    /* rnd_all_2: 0-1 */
    /* rnd_0: 0 - 7 */
    rax = (word64)(((r12) >> 14) | ((r12) << 50));
    rcx = (word64)(((r12) >> 18) | ((r12) << 46));
    r8 = (word64)(r8 + rdx);
    r15 = (word64)(r15 + WC_L64(rsp, 0));
    rdx = (word64)(r13);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r14);
    rax = (word64)(((r12) >> 41) | ((r12) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r12);
    r15 = (word64)(r15 + rax);
    rax = (word64)(((r8) >> 28) | ((r8) << 36));
    rcx = (word64)(((r8) >> 34) | ((r8) << 30));
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r8) >> 39) | ((r8) << 25));
    r15 = (word64)(r15 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r9);
    r11 = (word64)(r11 + r15);
    rdx = (word64)(rdx ^ r8);
    rbx = (word64)(rbx & rdx);
    r15 = (word64)(r15 + rax);
    rbx = (word64)(rbx ^ r9);
    /* rnd_1: 0 - 7 */
    rax = (word64)(((r11) >> 14) | ((r11) << 50));
    rcx = (word64)(((r11) >> 18) | ((r11) << 46));
    r15 = (word64)(r15 + rbx);
    r14 = (word64)(r14 + WC_L64(rsp, 8));
    rbx = (word64)(r12);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r11) >> 41) | ((r11) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r11);
    r14 = (word64)(r14 + rax);
    rax = (word64)(((r15) >> 28) | ((r15) << 36));
    rcx = (word64)(((r15) >> 34) | ((r15) << 30));
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r15) >> 39) | ((r15) << 25));
    r14 = (word64)(r14 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r8);
    r10 = (word64)(r10 + r14);
    rbx = (word64)(rbx ^ r15);
    rdx = (word64)(rdx & rbx);
    r14 = (word64)(r14 + rax);
    rdx = (word64)(rdx ^ r8);
    /* rnd_all_2: 2-3 */
    /* rnd_0: 0 - 7 */
    rax = (word64)(((r10) >> 14) | ((r10) << 50));
    rcx = (word64)(((r10) >> 18) | ((r10) << 46));
    r14 = (word64)(r14 + rdx);
    r13 = (word64)(r13 + WC_L64(rsp, 16));
    rdx = (word64)(r11);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r10) >> 41) | ((r10) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r10);
    r13 = (word64)(r13 + rax);
    rax = (word64)(((r14) >> 28) | ((r14) << 36));
    rcx = (word64)(((r14) >> 34) | ((r14) << 30));
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r14) >> 39) | ((r14) << 25));
    r13 = (word64)(r13 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r15);
    r9 = (word64)(r9 + r13);
    rdx = (word64)(rdx ^ r14);
    rbx = (word64)(rbx & rdx);
    r13 = (word64)(r13 + rax);
    rbx = (word64)(rbx ^ r15);
    /* rnd_1: 0 - 7 */
    rax = (word64)(((r9) >> 14) | ((r9) << 50));
    rcx = (word64)(((r9) >> 18) | ((r9) << 46));
    r13 = (word64)(r13 + rbx);
    r12 = (word64)(r12 + WC_L64(rsp, 24));
    rbx = (word64)(r10);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r9) >> 41) | ((r9) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r9);
    r12 = (word64)(r12 + rax);
    rax = (word64)(((r13) >> 28) | ((r13) << 36));
    rcx = (word64)(((r13) >> 34) | ((r13) << 30));
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r13) >> 39) | ((r13) << 25));
    r12 = (word64)(r12 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r14);
    r8 = (word64)(r8 + r12);
    rbx = (word64)(rbx ^ r13);
    rdx = (word64)(rdx & rbx);
    r12 = (word64)(r12 + rax);
    rdx = (word64)(rdx ^ r14);
    /* rnd_all_2: 4-5 */
    /* rnd_0: 0 - 7 */
    rax = (word64)(((r8) >> 14) | ((r8) << 50));
    rcx = (word64)(((r8) >> 18) | ((r8) << 46));
    r12 = (word64)(r12 + rdx);
    r11 = (word64)(r11 + WC_L64(rsp, 32));
    rdx = (word64)(r9);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r10);
    rax = (word64)(((r8) >> 41) | ((r8) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r8);
    r11 = (word64)(r11 + rax);
    rax = (word64)(((r12) >> 28) | ((r12) << 36));
    rcx = (word64)(((r12) >> 34) | ((r12) << 30));
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r12) >> 39) | ((r12) << 25));
    r11 = (word64)(r11 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r13);
    r15 = (word64)(r15 + r11);
    rdx = (word64)(rdx ^ r12);
    rbx = (word64)(rbx & rdx);
    r11 = (word64)(r11 + rax);
    rbx = (word64)(rbx ^ r13);
    /* rnd_1: 0 - 7 */
    rax = (word64)(((r15) >> 14) | ((r15) << 50));
    rcx = (word64)(((r15) >> 18) | ((r15) << 46));
    r11 = (word64)(r11 + rbx);
    r10 = (word64)(r10 + WC_L64(rsp, 40));
    rbx = (word64)(r8);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r15) >> 41) | ((r15) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r15);
    r10 = (word64)(r10 + rax);
    rax = (word64)(((r11) >> 28) | ((r11) << 36));
    rcx = (word64)(((r11) >> 34) | ((r11) << 30));
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r11) >> 39) | ((r11) << 25));
    r10 = (word64)(r10 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r12);
    r14 = (word64)(r14 + r10);
    rbx = (word64)(rbx ^ r11);
    rdx = (word64)(rdx & rbx);
    r10 = (word64)(r10 + rax);
    rdx = (word64)(rdx ^ r12);
    /* rnd_all_2: 6-7 */
    /* rnd_0: 0 - 7 */
    rax = (word64)(((r14) >> 14) | ((r14) << 50));
    rcx = (word64)(((r14) >> 18) | ((r14) << 46));
    r10 = (word64)(r10 + rdx);
    r9 = (word64)(r9 + WC_L64(rsp, 48));
    rdx = (word64)(r15);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r14) >> 41) | ((r14) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r14);
    r9 = (word64)(r9 + rax);
    rax = (word64)(((r10) >> 28) | ((r10) << 36));
    rcx = (word64)(((r10) >> 34) | ((r10) << 30));
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r10) >> 39) | ((r10) << 25));
    r9 = (word64)(r9 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r11);
    r13 = (word64)(r13 + r9);
    rdx = (word64)(rdx ^ r10);
    rbx = (word64)(rbx & rdx);
    r9 = (word64)(r9 + rax);
    rbx = (word64)(rbx ^ r11);
    /* rnd_1: 0 - 7 */
    rax = (word64)(((r13) >> 14) | ((r13) << 50));
    rcx = (word64)(((r13) >> 18) | ((r13) << 46));
    r9 = (word64)(r9 + rbx);
    r8 = (word64)(r8 + WC_L64(rsp, 56));
    rbx = (word64)(r14);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r13) >> 41) | ((r13) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r13);
    r8 = (word64)(r8 + rax);
    rax = (word64)(((r9) >> 28) | ((r9) << 36));
    rcx = (word64)(((r9) >> 34) | ((r9) << 30));
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r9) >> 39) | ((r9) << 25));
    r8 = (word64)(r8 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r10);
    r12 = (word64)(r12 + r8);
    rbx = (word64)(rbx ^ r9);
    rdx = (word64)(rdx & rbx);
    r8 = (word64)(r8 + rax);
    rdx = (word64)(rdx ^ r10);
    /* rnd_all_2: 8-9 */
    /* rnd_0: 0 - 7 */
    rax = (word64)(((r12) >> 14) | ((r12) << 50));
    rcx = (word64)(((r12) >> 18) | ((r12) << 46));
    r8 = (word64)(r8 + rdx);
    r15 = (word64)(r15 + WC_L64(rsp, 64));
    rdx = (word64)(r13);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r14);
    rax = (word64)(((r12) >> 41) | ((r12) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r12);
    r15 = (word64)(r15 + rax);
    rax = (word64)(((r8) >> 28) | ((r8) << 36));
    rcx = (word64)(((r8) >> 34) | ((r8) << 30));
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r8) >> 39) | ((r8) << 25));
    r15 = (word64)(r15 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r9);
    r11 = (word64)(r11 + r15);
    rdx = (word64)(rdx ^ r8);
    rbx = (word64)(rbx & rdx);
    r15 = (word64)(r15 + rax);
    rbx = (word64)(rbx ^ r9);
    /* rnd_1: 0 - 7 */
    rax = (word64)(((r11) >> 14) | ((r11) << 50));
    rcx = (word64)(((r11) >> 18) | ((r11) << 46));
    r15 = (word64)(r15 + rbx);
    r14 = (word64)(r14 + WC_L64(rsp, 72));
    rbx = (word64)(r12);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r11) >> 41) | ((r11) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r11);
    r14 = (word64)(r14 + rax);
    rax = (word64)(((r15) >> 28) | ((r15) << 36));
    rcx = (word64)(((r15) >> 34) | ((r15) << 30));
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r15) >> 39) | ((r15) << 25));
    r14 = (word64)(r14 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r8);
    r10 = (word64)(r10 + r14);
    rbx = (word64)(rbx ^ r15);
    rdx = (word64)(rdx & rbx);
    r14 = (word64)(r14 + rax);
    rdx = (word64)(rdx ^ r8);
    /* rnd_all_2: 10-11 */
    /* rnd_0: 0 - 7 */
    rax = (word64)(((r10) >> 14) | ((r10) << 50));
    rcx = (word64)(((r10) >> 18) | ((r10) << 46));
    r14 = (word64)(r14 + rdx);
    r13 = (word64)(r13 + WC_L64(rsp, 80));
    rdx = (word64)(r11);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r10) >> 41) | ((r10) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r10);
    r13 = (word64)(r13 + rax);
    rax = (word64)(((r14) >> 28) | ((r14) << 36));
    rcx = (word64)(((r14) >> 34) | ((r14) << 30));
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r14) >> 39) | ((r14) << 25));
    r13 = (word64)(r13 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r15);
    r9 = (word64)(r9 + r13);
    rdx = (word64)(rdx ^ r14);
    rbx = (word64)(rbx & rdx);
    r13 = (word64)(r13 + rax);
    rbx = (word64)(rbx ^ r15);
    /* rnd_1: 0 - 7 */
    rax = (word64)(((r9) >> 14) | ((r9) << 50));
    rcx = (word64)(((r9) >> 18) | ((r9) << 46));
    r13 = (word64)(r13 + rbx);
    r12 = (word64)(r12 + WC_L64(rsp, 88));
    rbx = (word64)(r10);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r9) >> 41) | ((r9) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r9);
    r12 = (word64)(r12 + rax);
    rax = (word64)(((r13) >> 28) | ((r13) << 36));
    rcx = (word64)(((r13) >> 34) | ((r13) << 30));
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r13) >> 39) | ((r13) << 25));
    r12 = (word64)(r12 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r14);
    r8 = (word64)(r8 + r12);
    rbx = (word64)(rbx ^ r13);
    rdx = (word64)(rdx & rbx);
    r12 = (word64)(r12 + rax);
    rdx = (word64)(rdx ^ r14);
    /* rnd_all_2: 12-13 */
    /* rnd_0: 0 - 7 */
    rax = (word64)(((r8) >> 14) | ((r8) << 50));
    rcx = (word64)(((r8) >> 18) | ((r8) << 46));
    r12 = (word64)(r12 + rdx);
    r11 = (word64)(r11 + WC_L64(rsp, 96));
    rdx = (word64)(r9);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r10);
    rax = (word64)(((r8) >> 41) | ((r8) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r8);
    r11 = (word64)(r11 + rax);
    rax = (word64)(((r12) >> 28) | ((r12) << 36));
    rcx = (word64)(((r12) >> 34) | ((r12) << 30));
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r12) >> 39) | ((r12) << 25));
    r11 = (word64)(r11 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r13);
    r15 = (word64)(r15 + r11);
    rdx = (word64)(rdx ^ r12);
    rbx = (word64)(rbx & rdx);
    r11 = (word64)(r11 + rax);
    rbx = (word64)(rbx ^ r13);
    /* rnd_1: 0 - 7 */
    rax = (word64)(((r15) >> 14) | ((r15) << 50));
    rcx = (word64)(((r15) >> 18) | ((r15) << 46));
    r11 = (word64)(r11 + rbx);
    r10 = (word64)(r10 + WC_L64(rsp, 104));
    rbx = (word64)(r8);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r15) >> 41) | ((r15) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r15);
    r10 = (word64)(r10 + rax);
    rax = (word64)(((r11) >> 28) | ((r11) << 36));
    rcx = (word64)(((r11) >> 34) | ((r11) << 30));
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r11) >> 39) | ((r11) << 25));
    r10 = (word64)(r10 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r12);
    r14 = (word64)(r14 + r10);
    rbx = (word64)(rbx ^ r11);
    rdx = (word64)(rdx & rbx);
    r10 = (word64)(r10 + rax);
    rdx = (word64)(rdx ^ r12);
    /* rnd_all_2: 14-15 */
    /* rnd_0: 0 - 7 */
    rax = (word64)(((r14) >> 14) | ((r14) << 50));
    rcx = (word64)(((r14) >> 18) | ((r14) << 46));
    r10 = (word64)(r10 + rdx);
    r9 = (word64)(r9 + WC_L64(rsp, 112));
    rdx = (word64)(r15);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r14) >> 41) | ((r14) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r14);
    r9 = (word64)(r9 + rax);
    rax = (word64)(((r10) >> 28) | ((r10) << 36));
    rcx = (word64)(((r10) >> 34) | ((r10) << 30));
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r10) >> 39) | ((r10) << 25));
    r9 = (word64)(r9 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r11);
    r13 = (word64)(r13 + r9);
    rdx = (word64)(rdx ^ r10);
    rbx = (word64)(rbx & rdx);
    r9 = (word64)(r9 + rax);
    rbx = (word64)(rbx ^ r11);
    /* rnd_1: 0 - 7 */
    rax = (word64)(((r13) >> 14) | ((r13) << 50));
    rcx = (word64)(((r13) >> 18) | ((r13) << 46));
    r9 = (word64)(r9 + rbx);
    r8 = (word64)(r8 + WC_L64(rsp, 120));
    rbx = (word64)(r14);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r13) >> 41) | ((r13) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r13);
    r8 = (word64)(r8 + rax);
    rax = (word64)(((r9) >> 28) | ((r9) << 36));
    rcx = (word64)(((r9) >> 34) | ((r9) << 30));
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r9) >> 39) | ((r9) << 25));
    r8 = (word64)(r8 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r10);
    r12 = (word64)(r12 + r8);
    rbx = (word64)(rbx ^ r9);
    rdx = (word64)(rdx & rbx);
    r8 = (word64)(r8 + rax);
    rdx = (word64)(rdx ^ r10);
    r8 = (word64)(r8 + rdx);
    WC_S64(rdi, 0) = (word64)(WC_L64(rdi, 0) + r8);
    WC_S64(rdi, 8) = (word64)(WC_L64(rdi, 8) + r9);
    WC_S64(rdi, 16) = (word64)(WC_L64(rdi, 16) + r10);
    WC_S64(rdi, 24) = (word64)(WC_L64(rdi, 24) + r11);
    WC_S64(rdi, 32) = (word64)(WC_L64(rdi, 32) + r12);
    WC_S64(rdi, 40) = (word64)(WC_L64(rdi, 40) + r13);
    WC_S64(rdi, 48) = (word64)(WC_L64(rdi, 48) + r14);
    WC_S64(rdi, 56) = (word64)(WC_L64(rdi, 56) + r15);
    rax = (word64)(0);
    return (int)(word32)rax;
}

WC_X64I_TARGET("avx,bmi2")
WOLFSSL_LOCAL int Transform_Sha512_AVX1_RORX_Len(wc_Sha512* sha512, word32 len)
{
    word64 rdi, rbp, rsp, rsi, rcx, r8, r9, r10, r11, r12, r13, r14, r15,
           rbx = 0, rdx = 0, rax = 0;
    __m128i x0 = _mm_setzero_si128(), x1 = _mm_setzero_si128(),
            x2 = _mm_setzero_si128(), x3 = _mm_setzero_si128(),
            x4 = _mm_setzero_si128(), x5 = _mm_setzero_si128(),
            x6 = _mm_setzero_si128(), x7 = _mm_setzero_si128(),
            x8 = _mm_setzero_si128(), x9 = _mm_setzero_si128(),
            x10 = _mm_setzero_si128(), x11 = _mm_setzero_si128(),
            x12 = _mm_setzero_si128(), x13 = _mm_setzero_si128(), x14;
    XALIGNED(32) WC_X64I_SLOT stk[20];
    word32 zf1;

    rdi = (word64)(size_t)sha512;
    rbp = (word64)(word32)len;

    rsp = (word64)(size_t)stk + 160;
    rsp = (word64)(rsp - 144);
    rsi = (word64)(WC_L64(rdi, 224));
    rcx = (word64)((word64)(size_t)L_avx1_rorx_sha512_k);
    x14 = _mm_loadu_si128((const __m128i*)WC_PR(L_avx1_rorx_sha512_flip_mask,
        0));
    r8 = (word64)(WC_L64(rdi, 0));
    r9 = (word64)(WC_L64(rdi, 8));
    r10 = (word64)(WC_L64(rdi, 16));
    r11 = (word64)(WC_L64(rdi, 24));
    r12 = (word64)(WC_L64(rdi, 32));
    r13 = (word64)(WC_L64(rdi, 40));
    r14 = (word64)(WC_L64(rdi, 48));
    r15 = (word64)(WC_L64(rdi, 56));
    /* Start of loop processing a block */
L_sha512_len_avx1_rorx_begin:
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 16));
    x0 = _mm_shuffle_epi8(x0, x14);
    x1 = _mm_shuffle_epi8(x1, x14);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 48));
    x2 = _mm_shuffle_epi8(x2, x14);
    x3 = _mm_shuffle_epi8(x3, x14);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 64));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 80));
    x4 = _mm_shuffle_epi8(x4, x14);
    x5 = _mm_shuffle_epi8(x5, x14);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 96));
    x7 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 112));
    x6 = _mm_shuffle_epi8(x6, x14);
    x7 = _mm_shuffle_epi8(x7, x14);
    WC_S32(rsp, 128) = (word32)(4);
    rbx = (word64)(r9);
    rdx = (word64)(0);
    rbx = (word64)(rbx ^ r10);
    x8 = _mm_add_epi64(x0, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    x9 = _mm_add_epi64(x1, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 16), x9);
    x8 = _mm_add_epi64(x2, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32)));
    x9 = _mm_add_epi64(x3, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 32), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 48), x9);
    x8 = _mm_add_epi64(x4, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64)));
    x9 = _mm_add_epi64(x5, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 64), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 80), x9);
    x8 = _mm_add_epi64(x6, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96)));
    x9 = _mm_add_epi64(x7, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 96), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 112), x9);
    /* Start of 16 rounds */
L_sha512_len_avx1_rorx_start:
    rcx = (word64)(rcx + 0x80);
    WC_S64(rsp, 136) = (word64)(rcx);
    /* msg_sched: 0-1 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((r12) >> 14) | ((r12) << 50));
    rcx = (word64)(((r12) >> 18) | ((r12) << 46));
    r8 = (word64)(r8 + rdx);
    x12 = _mm_alignr_epi8(x1, x0, 8);
    x13 = _mm_alignr_epi8(x5, x4, 8);
    /* rnd_0: 1 - 1 */
    r15 = (word64)(r15 + WC_L64(rsp, 0));
    rdx = (word64)(r13);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 2 */
    rdx = (word64)(rdx ^ r14);
    rax = (word64)(((r12) >> 41) | ((r12) << 23));
    rax = (word64)(rax ^ rcx);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 3 - 3 */
    rdx = (word64)(rdx & r12);
    r15 = (word64)(r15 + rax);
    rax = (word64)(((r8) >> 28) | ((r8) << 36));
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 4 - 4 */
    rcx = (word64)(((r8) >> 34) | ((r8) << 30));
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(rcx ^ rax);
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 5 - 5 */
    rax = (word64)(((r8) >> 39) | ((r8) << 25));
    r15 = (word64)(r15 + rdx);
    rax = (word64)(rax ^ rcx);
    x8 = _mm_xor_si128(x8, x11);
    x0 = _mm_add_epi64(x13, x0);
    /* rnd_0: 6 - 7 */
    rdx = (word64)(r9);
    r11 = (word64)(r11 + r15);
    rdx = (word64)(rdx ^ r8);
    rbx = (word64)(rbx & rdx);
    r15 = (word64)(r15 + rax);
    rbx = (word64)(rbx ^ r9);
    x0 = _mm_add_epi64(x8, x0);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((r11) >> 14) | ((r11) << 50));
    rcx = (word64)(((r11) >> 18) | ((r11) << 46));
    r15 = (word64)(r15 + rbx);
    x8 = _mm_srli_epi64(x7, 19);
    x9 = _mm_slli_epi64(x7, 45);
    /* rnd_1: 1 - 1 */
    r14 = (word64)(r14 + WC_L64(rsp, 8));
    rbx = (word64)(r12);
    rcx = (word64)(rcx ^ rax);
    x10 = _mm_srli_epi64(x7, 61);
    x11 = _mm_slli_epi64(x7, 3);
    /* rnd_1: 2 - 2 */
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r11) >> 41) | ((r11) << 23));
    rax = (word64)(rax ^ rcx);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 3 - 4 */
    rbx = (word64)(rbx & r11);
    r14 = (word64)(r14 + rax);
    rax = (word64)(((r15) >> 28) | ((r15) << 36));
    rcx = (word64)(((r15) >> 34) | ((r15) << 30));
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x7, 6);
    /* rnd_1: 5 - 6 */
    rax = (word64)(((r15) >> 39) | ((r15) << 25));
    r14 = (word64)(r14 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r8);
    r10 = (word64)(r10 + r14);
    rbx = (word64)(rbx ^ r15);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 7 - 7 */
    rdx = (word64)(rdx & rbx);
    r14 = (word64)(r14 + rax);
    rdx = (word64)(rdx ^ r8);
    x0 = _mm_add_epi64(x8, x0);
    /* msg_sched done: 0-1 */
    /* msg_sched: 2-3 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((r10) >> 14) | ((r10) << 50));
    rcx = (word64)(((r10) >> 18) | ((r10) << 46));
    r14 = (word64)(r14 + rdx);
    x12 = _mm_alignr_epi8(x2, x1, 8);
    x13 = _mm_alignr_epi8(x6, x5, 8);
    /* rnd_0: 1 - 1 */
    r13 = (word64)(r13 + WC_L64(rsp, 16));
    rdx = (word64)(r11);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 2 */
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r10) >> 41) | ((r10) << 23));
    rax = (word64)(rax ^ rcx);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 3 - 3 */
    rdx = (word64)(rdx & r10);
    r13 = (word64)(r13 + rax);
    rax = (word64)(((r14) >> 28) | ((r14) << 36));
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 4 - 4 */
    rcx = (word64)(((r14) >> 34) | ((r14) << 30));
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(rcx ^ rax);
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 5 - 5 */
    rax = (word64)(((r14) >> 39) | ((r14) << 25));
    r13 = (word64)(r13 + rdx);
    rax = (word64)(rax ^ rcx);
    x8 = _mm_xor_si128(x8, x11);
    x1 = _mm_add_epi64(x13, x1);
    /* rnd_0: 6 - 7 */
    rdx = (word64)(r15);
    r9 = (word64)(r9 + r13);
    rdx = (word64)(rdx ^ r14);
    rbx = (word64)(rbx & rdx);
    r13 = (word64)(r13 + rax);
    rbx = (word64)(rbx ^ r15);
    x1 = _mm_add_epi64(x8, x1);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((r9) >> 14) | ((r9) << 50));
    rcx = (word64)(((r9) >> 18) | ((r9) << 46));
    r13 = (word64)(r13 + rbx);
    x8 = _mm_srli_epi64(x0, 19);
    x9 = _mm_slli_epi64(x0, 45);
    /* rnd_1: 1 - 1 */
    r12 = (word64)(r12 + WC_L64(rsp, 24));
    rbx = (word64)(r10);
    rcx = (word64)(rcx ^ rax);
    x10 = _mm_srli_epi64(x0, 61);
    x11 = _mm_slli_epi64(x0, 3);
    /* rnd_1: 2 - 2 */
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r9) >> 41) | ((r9) << 23));
    rax = (word64)(rax ^ rcx);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 3 - 4 */
    rbx = (word64)(rbx & r9);
    r12 = (word64)(r12 + rax);
    rax = (word64)(((r13) >> 28) | ((r13) << 36));
    rcx = (word64)(((r13) >> 34) | ((r13) << 30));
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x0, 6);
    /* rnd_1: 5 - 6 */
    rax = (word64)(((r13) >> 39) | ((r13) << 25));
    r12 = (word64)(r12 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r14);
    r8 = (word64)(r8 + r12);
    rbx = (word64)(rbx ^ r13);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 7 - 7 */
    rdx = (word64)(rdx & rbx);
    r12 = (word64)(r12 + rax);
    rdx = (word64)(rdx ^ r14);
    x1 = _mm_add_epi64(x8, x1);
    /* msg_sched done: 2-3 */
    /* msg_sched: 4-5 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((r8) >> 14) | ((r8) << 50));
    rcx = (word64)(((r8) >> 18) | ((r8) << 46));
    r12 = (word64)(r12 + rdx);
    x12 = _mm_alignr_epi8(x3, x2, 8);
    x13 = _mm_alignr_epi8(x7, x6, 8);
    /* rnd_0: 1 - 1 */
    r11 = (word64)(r11 + WC_L64(rsp, 32));
    rdx = (word64)(r9);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 2 */
    rdx = (word64)(rdx ^ r10);
    rax = (word64)(((r8) >> 41) | ((r8) << 23));
    rax = (word64)(rax ^ rcx);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 3 - 3 */
    rdx = (word64)(rdx & r8);
    r11 = (word64)(r11 + rax);
    rax = (word64)(((r12) >> 28) | ((r12) << 36));
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 4 - 4 */
    rcx = (word64)(((r12) >> 34) | ((r12) << 30));
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(rcx ^ rax);
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 5 - 5 */
    rax = (word64)(((r12) >> 39) | ((r12) << 25));
    r11 = (word64)(r11 + rdx);
    rax = (word64)(rax ^ rcx);
    x8 = _mm_xor_si128(x8, x11);
    x2 = _mm_add_epi64(x13, x2);
    /* rnd_0: 6 - 7 */
    rdx = (word64)(r13);
    r15 = (word64)(r15 + r11);
    rdx = (word64)(rdx ^ r12);
    rbx = (word64)(rbx & rdx);
    r11 = (word64)(r11 + rax);
    rbx = (word64)(rbx ^ r13);
    x2 = _mm_add_epi64(x8, x2);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((r15) >> 14) | ((r15) << 50));
    rcx = (word64)(((r15) >> 18) | ((r15) << 46));
    r11 = (word64)(r11 + rbx);
    x8 = _mm_srli_epi64(x1, 19);
    x9 = _mm_slli_epi64(x1, 45);
    /* rnd_1: 1 - 1 */
    r10 = (word64)(r10 + WC_L64(rsp, 40));
    rbx = (word64)(r8);
    rcx = (word64)(rcx ^ rax);
    x10 = _mm_srli_epi64(x1, 61);
    x11 = _mm_slli_epi64(x1, 3);
    /* rnd_1: 2 - 2 */
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r15) >> 41) | ((r15) << 23));
    rax = (word64)(rax ^ rcx);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 3 - 4 */
    rbx = (word64)(rbx & r15);
    r10 = (word64)(r10 + rax);
    rax = (word64)(((r11) >> 28) | ((r11) << 36));
    rcx = (word64)(((r11) >> 34) | ((r11) << 30));
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x1, 6);
    /* rnd_1: 5 - 6 */
    rax = (word64)(((r11) >> 39) | ((r11) << 25));
    r10 = (word64)(r10 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r12);
    r14 = (word64)(r14 + r10);
    rbx = (word64)(rbx ^ r11);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 7 - 7 */
    rdx = (word64)(rdx & rbx);
    r10 = (word64)(r10 + rax);
    rdx = (word64)(rdx ^ r12);
    x2 = _mm_add_epi64(x8, x2);
    /* msg_sched done: 4-5 */
    /* msg_sched: 6-7 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((r14) >> 14) | ((r14) << 50));
    rcx = (word64)(((r14) >> 18) | ((r14) << 46));
    r10 = (word64)(r10 + rdx);
    x12 = _mm_alignr_epi8(x4, x3, 8);
    x13 = _mm_alignr_epi8(x0, x7, 8);
    /* rnd_0: 1 - 1 */
    r9 = (word64)(r9 + WC_L64(rsp, 48));
    rdx = (word64)(r15);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 2 */
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r14) >> 41) | ((r14) << 23));
    rax = (word64)(rax ^ rcx);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 3 - 3 */
    rdx = (word64)(rdx & r14);
    r9 = (word64)(r9 + rax);
    rax = (word64)(((r10) >> 28) | ((r10) << 36));
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 4 - 4 */
    rcx = (word64)(((r10) >> 34) | ((r10) << 30));
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(rcx ^ rax);
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 5 - 5 */
    rax = (word64)(((r10) >> 39) | ((r10) << 25));
    r9 = (word64)(r9 + rdx);
    rax = (word64)(rax ^ rcx);
    x8 = _mm_xor_si128(x8, x11);
    x3 = _mm_add_epi64(x13, x3);
    /* rnd_0: 6 - 7 */
    rdx = (word64)(r11);
    r13 = (word64)(r13 + r9);
    rdx = (word64)(rdx ^ r10);
    rbx = (word64)(rbx & rdx);
    r9 = (word64)(r9 + rax);
    rbx = (word64)(rbx ^ r11);
    x3 = _mm_add_epi64(x8, x3);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((r13) >> 14) | ((r13) << 50));
    rcx = (word64)(((r13) >> 18) | ((r13) << 46));
    r9 = (word64)(r9 + rbx);
    x8 = _mm_srli_epi64(x2, 19);
    x9 = _mm_slli_epi64(x2, 45);
    /* rnd_1: 1 - 1 */
    r8 = (word64)(r8 + WC_L64(rsp, 56));
    rbx = (word64)(r14);
    rcx = (word64)(rcx ^ rax);
    x10 = _mm_srli_epi64(x2, 61);
    x11 = _mm_slli_epi64(x2, 3);
    /* rnd_1: 2 - 2 */
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r13) >> 41) | ((r13) << 23));
    rax = (word64)(rax ^ rcx);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 3 - 4 */
    rbx = (word64)(rbx & r13);
    r8 = (word64)(r8 + rax);
    rax = (word64)(((r9) >> 28) | ((r9) << 36));
    rcx = (word64)(((r9) >> 34) | ((r9) << 30));
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x2, 6);
    /* rnd_1: 5 - 6 */
    rax = (word64)(((r9) >> 39) | ((r9) << 25));
    r8 = (word64)(r8 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r10);
    r12 = (word64)(r12 + r8);
    rbx = (word64)(rbx ^ r9);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 7 - 7 */
    rdx = (word64)(rdx & rbx);
    r8 = (word64)(r8 + rax);
    rdx = (word64)(rdx ^ r10);
    x3 = _mm_add_epi64(x8, x3);
    /* msg_sched done: 6-7 */
    /* msg_sched: 8-9 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((r12) >> 14) | ((r12) << 50));
    rcx = (word64)(((r12) >> 18) | ((r12) << 46));
    r8 = (word64)(r8 + rdx);
    x12 = _mm_alignr_epi8(x5, x4, 8);
    x13 = _mm_alignr_epi8(x1, x0, 8);
    /* rnd_0: 1 - 1 */
    r15 = (word64)(r15 + WC_L64(rsp, 64));
    rdx = (word64)(r13);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 2 */
    rdx = (word64)(rdx ^ r14);
    rax = (word64)(((r12) >> 41) | ((r12) << 23));
    rax = (word64)(rax ^ rcx);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 3 - 3 */
    rdx = (word64)(rdx & r12);
    r15 = (word64)(r15 + rax);
    rax = (word64)(((r8) >> 28) | ((r8) << 36));
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 4 - 4 */
    rcx = (word64)(((r8) >> 34) | ((r8) << 30));
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(rcx ^ rax);
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 5 - 5 */
    rax = (word64)(((r8) >> 39) | ((r8) << 25));
    r15 = (word64)(r15 + rdx);
    rax = (word64)(rax ^ rcx);
    x8 = _mm_xor_si128(x8, x11);
    x4 = _mm_add_epi64(x13, x4);
    /* rnd_0: 6 - 7 */
    rdx = (word64)(r9);
    r11 = (word64)(r11 + r15);
    rdx = (word64)(rdx ^ r8);
    rbx = (word64)(rbx & rdx);
    r15 = (word64)(r15 + rax);
    rbx = (word64)(rbx ^ r9);
    x4 = _mm_add_epi64(x8, x4);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((r11) >> 14) | ((r11) << 50));
    rcx = (word64)(((r11) >> 18) | ((r11) << 46));
    r15 = (word64)(r15 + rbx);
    x8 = _mm_srli_epi64(x3, 19);
    x9 = _mm_slli_epi64(x3, 45);
    /* rnd_1: 1 - 1 */
    r14 = (word64)(r14 + WC_L64(rsp, 72));
    rbx = (word64)(r12);
    rcx = (word64)(rcx ^ rax);
    x10 = _mm_srli_epi64(x3, 61);
    x11 = _mm_slli_epi64(x3, 3);
    /* rnd_1: 2 - 2 */
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r11) >> 41) | ((r11) << 23));
    rax = (word64)(rax ^ rcx);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 3 - 4 */
    rbx = (word64)(rbx & r11);
    r14 = (word64)(r14 + rax);
    rax = (word64)(((r15) >> 28) | ((r15) << 36));
    rcx = (word64)(((r15) >> 34) | ((r15) << 30));
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x3, 6);
    /* rnd_1: 5 - 6 */
    rax = (word64)(((r15) >> 39) | ((r15) << 25));
    r14 = (word64)(r14 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r8);
    r10 = (word64)(r10 + r14);
    rbx = (word64)(rbx ^ r15);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 7 - 7 */
    rdx = (word64)(rdx & rbx);
    r14 = (word64)(r14 + rax);
    rdx = (word64)(rdx ^ r8);
    x4 = _mm_add_epi64(x8, x4);
    /* msg_sched done: 8-9 */
    /* msg_sched: 10-11 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((r10) >> 14) | ((r10) << 50));
    rcx = (word64)(((r10) >> 18) | ((r10) << 46));
    r14 = (word64)(r14 + rdx);
    x12 = _mm_alignr_epi8(x6, x5, 8);
    x13 = _mm_alignr_epi8(x2, x1, 8);
    /* rnd_0: 1 - 1 */
    r13 = (word64)(r13 + WC_L64(rsp, 80));
    rdx = (word64)(r11);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 2 */
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r10) >> 41) | ((r10) << 23));
    rax = (word64)(rax ^ rcx);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 3 - 3 */
    rdx = (word64)(rdx & r10);
    r13 = (word64)(r13 + rax);
    rax = (word64)(((r14) >> 28) | ((r14) << 36));
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 4 - 4 */
    rcx = (word64)(((r14) >> 34) | ((r14) << 30));
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(rcx ^ rax);
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 5 - 5 */
    rax = (word64)(((r14) >> 39) | ((r14) << 25));
    r13 = (word64)(r13 + rdx);
    rax = (word64)(rax ^ rcx);
    x8 = _mm_xor_si128(x8, x11);
    x5 = _mm_add_epi64(x13, x5);
    /* rnd_0: 6 - 7 */
    rdx = (word64)(r15);
    r9 = (word64)(r9 + r13);
    rdx = (word64)(rdx ^ r14);
    rbx = (word64)(rbx & rdx);
    r13 = (word64)(r13 + rax);
    rbx = (word64)(rbx ^ r15);
    x5 = _mm_add_epi64(x8, x5);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((r9) >> 14) | ((r9) << 50));
    rcx = (word64)(((r9) >> 18) | ((r9) << 46));
    r13 = (word64)(r13 + rbx);
    x8 = _mm_srli_epi64(x4, 19);
    x9 = _mm_slli_epi64(x4, 45);
    /* rnd_1: 1 - 1 */
    r12 = (word64)(r12 + WC_L64(rsp, 88));
    rbx = (word64)(r10);
    rcx = (word64)(rcx ^ rax);
    x10 = _mm_srli_epi64(x4, 61);
    x11 = _mm_slli_epi64(x4, 3);
    /* rnd_1: 2 - 2 */
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r9) >> 41) | ((r9) << 23));
    rax = (word64)(rax ^ rcx);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 3 - 4 */
    rbx = (word64)(rbx & r9);
    r12 = (word64)(r12 + rax);
    rax = (word64)(((r13) >> 28) | ((r13) << 36));
    rcx = (word64)(((r13) >> 34) | ((r13) << 30));
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x4, 6);
    /* rnd_1: 5 - 6 */
    rax = (word64)(((r13) >> 39) | ((r13) << 25));
    r12 = (word64)(r12 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r14);
    r8 = (word64)(r8 + r12);
    rbx = (word64)(rbx ^ r13);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 7 - 7 */
    rdx = (word64)(rdx & rbx);
    r12 = (word64)(r12 + rax);
    rdx = (word64)(rdx ^ r14);
    x5 = _mm_add_epi64(x8, x5);
    /* msg_sched done: 10-11 */
    /* msg_sched: 12-13 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((r8) >> 14) | ((r8) << 50));
    rcx = (word64)(((r8) >> 18) | ((r8) << 46));
    r12 = (word64)(r12 + rdx);
    x12 = _mm_alignr_epi8(x7, x6, 8);
    x13 = _mm_alignr_epi8(x3, x2, 8);
    /* rnd_0: 1 - 1 */
    r11 = (word64)(r11 + WC_L64(rsp, 96));
    rdx = (word64)(r9);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 2 */
    rdx = (word64)(rdx ^ r10);
    rax = (word64)(((r8) >> 41) | ((r8) << 23));
    rax = (word64)(rax ^ rcx);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 3 - 3 */
    rdx = (word64)(rdx & r8);
    r11 = (word64)(r11 + rax);
    rax = (word64)(((r12) >> 28) | ((r12) << 36));
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 4 - 4 */
    rcx = (word64)(((r12) >> 34) | ((r12) << 30));
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(rcx ^ rax);
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 5 - 5 */
    rax = (word64)(((r12) >> 39) | ((r12) << 25));
    r11 = (word64)(r11 + rdx);
    rax = (word64)(rax ^ rcx);
    x8 = _mm_xor_si128(x8, x11);
    x6 = _mm_add_epi64(x13, x6);
    /* rnd_0: 6 - 7 */
    rdx = (word64)(r13);
    r15 = (word64)(r15 + r11);
    rdx = (word64)(rdx ^ r12);
    rbx = (word64)(rbx & rdx);
    r11 = (word64)(r11 + rax);
    rbx = (word64)(rbx ^ r13);
    x6 = _mm_add_epi64(x8, x6);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((r15) >> 14) | ((r15) << 50));
    rcx = (word64)(((r15) >> 18) | ((r15) << 46));
    r11 = (word64)(r11 + rbx);
    x8 = _mm_srli_epi64(x5, 19);
    x9 = _mm_slli_epi64(x5, 45);
    /* rnd_1: 1 - 1 */
    r10 = (word64)(r10 + WC_L64(rsp, 104));
    rbx = (word64)(r8);
    rcx = (word64)(rcx ^ rax);
    x10 = _mm_srli_epi64(x5, 61);
    x11 = _mm_slli_epi64(x5, 3);
    /* rnd_1: 2 - 2 */
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r15) >> 41) | ((r15) << 23));
    rax = (word64)(rax ^ rcx);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 3 - 4 */
    rbx = (word64)(rbx & r15);
    r10 = (word64)(r10 + rax);
    rax = (word64)(((r11) >> 28) | ((r11) << 36));
    rcx = (word64)(((r11) >> 34) | ((r11) << 30));
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x5, 6);
    /* rnd_1: 5 - 6 */
    rax = (word64)(((r11) >> 39) | ((r11) << 25));
    r10 = (word64)(r10 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r12);
    r14 = (word64)(r14 + r10);
    rbx = (word64)(rbx ^ r11);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 7 - 7 */
    rdx = (word64)(rdx & rbx);
    r10 = (word64)(r10 + rax);
    rdx = (word64)(rdx ^ r12);
    x6 = _mm_add_epi64(x8, x6);
    /* msg_sched done: 12-13 */
    /* msg_sched: 14-15 */
    /* rnd_0: 0 - 0 */
    rax = (word64)(((r14) >> 14) | ((r14) << 50));
    rcx = (word64)(((r14) >> 18) | ((r14) << 46));
    r10 = (word64)(r10 + rdx);
    x12 = _mm_alignr_epi8(x0, x7, 8);
    x13 = _mm_alignr_epi8(x4, x3, 8);
    /* rnd_0: 1 - 1 */
    r9 = (word64)(r9 + WC_L64(rsp, 112));
    rdx = (word64)(r15);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_srli_epi64(x12, 1);
    x9 = _mm_slli_epi64(x12, 63);
    /* rnd_0: 2 - 2 */
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r14) >> 41) | ((r14) << 23));
    rax = (word64)(rax ^ rcx);
    x10 = _mm_srli_epi64(x12, 8);
    x11 = _mm_slli_epi64(x12, 56);
    /* rnd_0: 3 - 3 */
    rdx = (word64)(rdx & r14);
    r9 = (word64)(r9 + rax);
    rax = (word64)(((r10) >> 28) | ((r10) << 36));
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_0: 4 - 4 */
    rcx = (word64)(((r10) >> 34) | ((r10) << 30));
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(rcx ^ rax);
    x11 = _mm_srli_epi64(x12, 7);
    x8 = _mm_xor_si128(x8, x10);
    /* rnd_0: 5 - 5 */
    rax = (word64)(((r10) >> 39) | ((r10) << 25));
    r9 = (word64)(r9 + rdx);
    rax = (word64)(rax ^ rcx);
    x8 = _mm_xor_si128(x8, x11);
    x7 = _mm_add_epi64(x13, x7);
    /* rnd_0: 6 - 7 */
    rdx = (word64)(r11);
    r13 = (word64)(r13 + r9);
    rdx = (word64)(rdx ^ r10);
    rbx = (word64)(rbx & rdx);
    r9 = (word64)(r9 + rax);
    rbx = (word64)(rbx ^ r11);
    x7 = _mm_add_epi64(x8, x7);
    /* rnd_1: 0 - 0 */
    rax = (word64)(((r13) >> 14) | ((r13) << 50));
    rcx = (word64)(((r13) >> 18) | ((r13) << 46));
    r9 = (word64)(r9 + rbx);
    x8 = _mm_srli_epi64(x6, 19);
    x9 = _mm_slli_epi64(x6, 45);
    /* rnd_1: 1 - 1 */
    r8 = (word64)(r8 + WC_L64(rsp, 120));
    rbx = (word64)(r14);
    rcx = (word64)(rcx ^ rax);
    x10 = _mm_srli_epi64(x6, 61);
    x11 = _mm_slli_epi64(x6, 3);
    /* rnd_1: 2 - 2 */
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r13) >> 41) | ((r13) << 23));
    rax = (word64)(rax ^ rcx);
    x8 = _mm_or_si128(x8, x9);
    x10 = _mm_or_si128(x10, x11);
    /* rnd_1: 3 - 4 */
    rbx = (word64)(rbx & r13);
    r8 = (word64)(r8 + rax);
    rax = (word64)(((r9) >> 28) | ((r9) << 36));
    rcx = (word64)(((r9) >> 34) | ((r9) << 30));
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(rcx ^ rax);
    x8 = _mm_xor_si128(x8, x10);
    x11 = _mm_srli_epi64(x6, 6);
    /* rnd_1: 5 - 6 */
    rax = (word64)(((r9) >> 39) | ((r9) << 25));
    r8 = (word64)(r8 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r10);
    r12 = (word64)(r12 + r8);
    rbx = (word64)(rbx ^ r9);
    x8 = _mm_xor_si128(x8, x11);
    /* rnd_1: 7 - 7 */
    rdx = (word64)(rdx & rbx);
    r8 = (word64)(r8 + rax);
    rdx = (word64)(rdx ^ r10);
    x7 = _mm_add_epi64(x8, x7);
    /* msg_sched done: 14-15 */
    rcx = (word64)(WC_L64(rsp, 136));
    x8 = _mm_add_epi64(x0, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    x9 = _mm_add_epi64(x1, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 16), x9);
    x8 = _mm_add_epi64(x2, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32)));
    x9 = _mm_add_epi64(x3, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 32), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 48), x9);
    x8 = _mm_add_epi64(x4, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64)));
    x9 = _mm_add_epi64(x5, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 64), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 80), x9);
    x8 = _mm_add_epi64(x6, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96)));
    x9 = _mm_add_epi64(x7, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 96), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 112), x9);
    WC_S32(rsp, 128) = (word32)(WC_L32(rsp, 128) - 1);
    if (((word32)WC_S32(rsp, 128)) != (0)) {
        goto L_sha512_len_avx1_rorx_start;
    }
    x8 = _mm_add_epi64(x0, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    x9 = _mm_add_epi64(x1, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 16), x9);
    x8 = _mm_add_epi64(x2, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32)));
    x9 = _mm_add_epi64(x3, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 32), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 48), x9);
    x8 = _mm_add_epi64(x4, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64)));
    x9 = _mm_add_epi64(x5, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 64), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 80), x9);
    x8 = _mm_add_epi64(x6, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96)));
    x9 = _mm_add_epi64(x7, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 96), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 112), x9);
    /* rnd_all_2: 0-1 */
    /* rnd_0: 0 - 7 */
    rax = (word64)(((r12) >> 14) | ((r12) << 50));
    rcx = (word64)(((r12) >> 18) | ((r12) << 46));
    r8 = (word64)(r8 + rdx);
    r15 = (word64)(r15 + WC_L64(rsp, 0));
    rdx = (word64)(r13);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r14);
    rax = (word64)(((r12) >> 41) | ((r12) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r12);
    r15 = (word64)(r15 + rax);
    rax = (word64)(((r8) >> 28) | ((r8) << 36));
    rcx = (word64)(((r8) >> 34) | ((r8) << 30));
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r8) >> 39) | ((r8) << 25));
    r15 = (word64)(r15 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r9);
    r11 = (word64)(r11 + r15);
    rdx = (word64)(rdx ^ r8);
    rbx = (word64)(rbx & rdx);
    r15 = (word64)(r15 + rax);
    rbx = (word64)(rbx ^ r9);
    /* rnd_1: 0 - 7 */
    rax = (word64)(((r11) >> 14) | ((r11) << 50));
    rcx = (word64)(((r11) >> 18) | ((r11) << 46));
    r15 = (word64)(r15 + rbx);
    r14 = (word64)(r14 + WC_L64(rsp, 8));
    rbx = (word64)(r12);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r11) >> 41) | ((r11) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r11);
    r14 = (word64)(r14 + rax);
    rax = (word64)(((r15) >> 28) | ((r15) << 36));
    rcx = (word64)(((r15) >> 34) | ((r15) << 30));
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r15) >> 39) | ((r15) << 25));
    r14 = (word64)(r14 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r8);
    r10 = (word64)(r10 + r14);
    rbx = (word64)(rbx ^ r15);
    rdx = (word64)(rdx & rbx);
    r14 = (word64)(r14 + rax);
    rdx = (word64)(rdx ^ r8);
    /* rnd_all_2: 2-3 */
    /* rnd_0: 0 - 7 */
    rax = (word64)(((r10) >> 14) | ((r10) << 50));
    rcx = (word64)(((r10) >> 18) | ((r10) << 46));
    r14 = (word64)(r14 + rdx);
    r13 = (word64)(r13 + WC_L64(rsp, 16));
    rdx = (word64)(r11);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r10) >> 41) | ((r10) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r10);
    r13 = (word64)(r13 + rax);
    rax = (word64)(((r14) >> 28) | ((r14) << 36));
    rcx = (word64)(((r14) >> 34) | ((r14) << 30));
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r14) >> 39) | ((r14) << 25));
    r13 = (word64)(r13 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r15);
    r9 = (word64)(r9 + r13);
    rdx = (word64)(rdx ^ r14);
    rbx = (word64)(rbx & rdx);
    r13 = (word64)(r13 + rax);
    rbx = (word64)(rbx ^ r15);
    /* rnd_1: 0 - 7 */
    rax = (word64)(((r9) >> 14) | ((r9) << 50));
    rcx = (word64)(((r9) >> 18) | ((r9) << 46));
    r13 = (word64)(r13 + rbx);
    r12 = (word64)(r12 + WC_L64(rsp, 24));
    rbx = (word64)(r10);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r9) >> 41) | ((r9) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r9);
    r12 = (word64)(r12 + rax);
    rax = (word64)(((r13) >> 28) | ((r13) << 36));
    rcx = (word64)(((r13) >> 34) | ((r13) << 30));
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r13) >> 39) | ((r13) << 25));
    r12 = (word64)(r12 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r14);
    r8 = (word64)(r8 + r12);
    rbx = (word64)(rbx ^ r13);
    rdx = (word64)(rdx & rbx);
    r12 = (word64)(r12 + rax);
    rdx = (word64)(rdx ^ r14);
    /* rnd_all_2: 4-5 */
    /* rnd_0: 0 - 7 */
    rax = (word64)(((r8) >> 14) | ((r8) << 50));
    rcx = (word64)(((r8) >> 18) | ((r8) << 46));
    r12 = (word64)(r12 + rdx);
    r11 = (word64)(r11 + WC_L64(rsp, 32));
    rdx = (word64)(r9);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r10);
    rax = (word64)(((r8) >> 41) | ((r8) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r8);
    r11 = (word64)(r11 + rax);
    rax = (word64)(((r12) >> 28) | ((r12) << 36));
    rcx = (word64)(((r12) >> 34) | ((r12) << 30));
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r12) >> 39) | ((r12) << 25));
    r11 = (word64)(r11 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r13);
    r15 = (word64)(r15 + r11);
    rdx = (word64)(rdx ^ r12);
    rbx = (word64)(rbx & rdx);
    r11 = (word64)(r11 + rax);
    rbx = (word64)(rbx ^ r13);
    /* rnd_1: 0 - 7 */
    rax = (word64)(((r15) >> 14) | ((r15) << 50));
    rcx = (word64)(((r15) >> 18) | ((r15) << 46));
    r11 = (word64)(r11 + rbx);
    r10 = (word64)(r10 + WC_L64(rsp, 40));
    rbx = (word64)(r8);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r15) >> 41) | ((r15) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r15);
    r10 = (word64)(r10 + rax);
    rax = (word64)(((r11) >> 28) | ((r11) << 36));
    rcx = (word64)(((r11) >> 34) | ((r11) << 30));
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r11) >> 39) | ((r11) << 25));
    r10 = (word64)(r10 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r12);
    r14 = (word64)(r14 + r10);
    rbx = (word64)(rbx ^ r11);
    rdx = (word64)(rdx & rbx);
    r10 = (word64)(r10 + rax);
    rdx = (word64)(rdx ^ r12);
    /* rnd_all_2: 6-7 */
    /* rnd_0: 0 - 7 */
    rax = (word64)(((r14) >> 14) | ((r14) << 50));
    rcx = (word64)(((r14) >> 18) | ((r14) << 46));
    r10 = (word64)(r10 + rdx);
    r9 = (word64)(r9 + WC_L64(rsp, 48));
    rdx = (word64)(r15);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r14) >> 41) | ((r14) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r14);
    r9 = (word64)(r9 + rax);
    rax = (word64)(((r10) >> 28) | ((r10) << 36));
    rcx = (word64)(((r10) >> 34) | ((r10) << 30));
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r10) >> 39) | ((r10) << 25));
    r9 = (word64)(r9 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r11);
    r13 = (word64)(r13 + r9);
    rdx = (word64)(rdx ^ r10);
    rbx = (word64)(rbx & rdx);
    r9 = (word64)(r9 + rax);
    rbx = (word64)(rbx ^ r11);
    /* rnd_1: 0 - 7 */
    rax = (word64)(((r13) >> 14) | ((r13) << 50));
    rcx = (word64)(((r13) >> 18) | ((r13) << 46));
    r9 = (word64)(r9 + rbx);
    r8 = (word64)(r8 + WC_L64(rsp, 56));
    rbx = (word64)(r14);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r13) >> 41) | ((r13) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r13);
    r8 = (word64)(r8 + rax);
    rax = (word64)(((r9) >> 28) | ((r9) << 36));
    rcx = (word64)(((r9) >> 34) | ((r9) << 30));
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r9) >> 39) | ((r9) << 25));
    r8 = (word64)(r8 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r10);
    r12 = (word64)(r12 + r8);
    rbx = (word64)(rbx ^ r9);
    rdx = (word64)(rdx & rbx);
    r8 = (word64)(r8 + rax);
    rdx = (word64)(rdx ^ r10);
    /* rnd_all_2: 8-9 */
    /* rnd_0: 0 - 7 */
    rax = (word64)(((r12) >> 14) | ((r12) << 50));
    rcx = (word64)(((r12) >> 18) | ((r12) << 46));
    r8 = (word64)(r8 + rdx);
    r15 = (word64)(r15 + WC_L64(rsp, 64));
    rdx = (word64)(r13);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r14);
    rax = (word64)(((r12) >> 41) | ((r12) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r12);
    r15 = (word64)(r15 + rax);
    rax = (word64)(((r8) >> 28) | ((r8) << 36));
    rcx = (word64)(((r8) >> 34) | ((r8) << 30));
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r8) >> 39) | ((r8) << 25));
    r15 = (word64)(r15 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r9);
    r11 = (word64)(r11 + r15);
    rdx = (word64)(rdx ^ r8);
    rbx = (word64)(rbx & rdx);
    r15 = (word64)(r15 + rax);
    rbx = (word64)(rbx ^ r9);
    /* rnd_1: 0 - 7 */
    rax = (word64)(((r11) >> 14) | ((r11) << 50));
    rcx = (word64)(((r11) >> 18) | ((r11) << 46));
    r15 = (word64)(r15 + rbx);
    r14 = (word64)(r14 + WC_L64(rsp, 72));
    rbx = (word64)(r12);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r11) >> 41) | ((r11) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r11);
    r14 = (word64)(r14 + rax);
    rax = (word64)(((r15) >> 28) | ((r15) << 36));
    rcx = (word64)(((r15) >> 34) | ((r15) << 30));
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r15) >> 39) | ((r15) << 25));
    r14 = (word64)(r14 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r8);
    r10 = (word64)(r10 + r14);
    rbx = (word64)(rbx ^ r15);
    rdx = (word64)(rdx & rbx);
    r14 = (word64)(r14 + rax);
    rdx = (word64)(rdx ^ r8);
    /* rnd_all_2: 10-11 */
    /* rnd_0: 0 - 7 */
    rax = (word64)(((r10) >> 14) | ((r10) << 50));
    rcx = (word64)(((r10) >> 18) | ((r10) << 46));
    r14 = (word64)(r14 + rdx);
    r13 = (word64)(r13 + WC_L64(rsp, 80));
    rdx = (word64)(r11);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r10) >> 41) | ((r10) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r10);
    r13 = (word64)(r13 + rax);
    rax = (word64)(((r14) >> 28) | ((r14) << 36));
    rcx = (word64)(((r14) >> 34) | ((r14) << 30));
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r14) >> 39) | ((r14) << 25));
    r13 = (word64)(r13 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r15);
    r9 = (word64)(r9 + r13);
    rdx = (word64)(rdx ^ r14);
    rbx = (word64)(rbx & rdx);
    r13 = (word64)(r13 + rax);
    rbx = (word64)(rbx ^ r15);
    /* rnd_1: 0 - 7 */
    rax = (word64)(((r9) >> 14) | ((r9) << 50));
    rcx = (word64)(((r9) >> 18) | ((r9) << 46));
    r13 = (word64)(r13 + rbx);
    r12 = (word64)(r12 + WC_L64(rsp, 88));
    rbx = (word64)(r10);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r9) >> 41) | ((r9) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r9);
    r12 = (word64)(r12 + rax);
    rax = (word64)(((r13) >> 28) | ((r13) << 36));
    rcx = (word64)(((r13) >> 34) | ((r13) << 30));
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r13) >> 39) | ((r13) << 25));
    r12 = (word64)(r12 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r14);
    r8 = (word64)(r8 + r12);
    rbx = (word64)(rbx ^ r13);
    rdx = (word64)(rdx & rbx);
    r12 = (word64)(r12 + rax);
    rdx = (word64)(rdx ^ r14);
    /* rnd_all_2: 12-13 */
    /* rnd_0: 0 - 7 */
    rax = (word64)(((r8) >> 14) | ((r8) << 50));
    rcx = (word64)(((r8) >> 18) | ((r8) << 46));
    r12 = (word64)(r12 + rdx);
    r11 = (word64)(r11 + WC_L64(rsp, 96));
    rdx = (word64)(r9);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r10);
    rax = (word64)(((r8) >> 41) | ((r8) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r8);
    r11 = (word64)(r11 + rax);
    rax = (word64)(((r12) >> 28) | ((r12) << 36));
    rcx = (word64)(((r12) >> 34) | ((r12) << 30));
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r12) >> 39) | ((r12) << 25));
    r11 = (word64)(r11 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r13);
    r15 = (word64)(r15 + r11);
    rdx = (word64)(rdx ^ r12);
    rbx = (word64)(rbx & rdx);
    r11 = (word64)(r11 + rax);
    rbx = (word64)(rbx ^ r13);
    /* rnd_1: 0 - 7 */
    rax = (word64)(((r15) >> 14) | ((r15) << 50));
    rcx = (word64)(((r15) >> 18) | ((r15) << 46));
    r11 = (word64)(r11 + rbx);
    r10 = (word64)(r10 + WC_L64(rsp, 104));
    rbx = (word64)(r8);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r15) >> 41) | ((r15) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r15);
    r10 = (word64)(r10 + rax);
    rax = (word64)(((r11) >> 28) | ((r11) << 36));
    rcx = (word64)(((r11) >> 34) | ((r11) << 30));
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r11) >> 39) | ((r11) << 25));
    r10 = (word64)(r10 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r12);
    r14 = (word64)(r14 + r10);
    rbx = (word64)(rbx ^ r11);
    rdx = (word64)(rdx & rbx);
    r10 = (word64)(r10 + rax);
    rdx = (word64)(rdx ^ r12);
    /* rnd_all_2: 14-15 */
    /* rnd_0: 0 - 7 */
    rax = (word64)(((r14) >> 14) | ((r14) << 50));
    rcx = (word64)(((r14) >> 18) | ((r14) << 46));
    r10 = (word64)(r10 + rdx);
    r9 = (word64)(r9 + WC_L64(rsp, 112));
    rdx = (word64)(r15);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r14) >> 41) | ((r14) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r14);
    r9 = (word64)(r9 + rax);
    rax = (word64)(((r10) >> 28) | ((r10) << 36));
    rcx = (word64)(((r10) >> 34) | ((r10) << 30));
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r10) >> 39) | ((r10) << 25));
    r9 = (word64)(r9 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r11);
    r13 = (word64)(r13 + r9);
    rdx = (word64)(rdx ^ r10);
    rbx = (word64)(rbx & rdx);
    r9 = (word64)(r9 + rax);
    rbx = (word64)(rbx ^ r11);
    /* rnd_1: 0 - 7 */
    rax = (word64)(((r13) >> 14) | ((r13) << 50));
    rcx = (word64)(((r13) >> 18) | ((r13) << 46));
    r9 = (word64)(r9 + rbx);
    r8 = (word64)(r8 + WC_L64(rsp, 120));
    rbx = (word64)(r14);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r13) >> 41) | ((r13) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r13);
    r8 = (word64)(r8 + rax);
    rax = (word64)(((r9) >> 28) | ((r9) << 36));
    rcx = (word64)(((r9) >> 34) | ((r9) << 30));
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r9) >> 39) | ((r9) << 25));
    r8 = (word64)(r8 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r10);
    r12 = (word64)(r12 + r8);
    rbx = (word64)(rbx ^ r9);
    rdx = (word64)(rdx & rbx);
    r8 = (word64)(r8 + rax);
    rdx = (word64)(rdx ^ r10);
    r8 = (word64)(r8 + rdx);
    r8 = (word64)(r8 + WC_L64(rdi, 0));
    r9 = (word64)(r9 + WC_L64(rdi, 8));
    r10 = (word64)(r10 + WC_L64(rdi, 16));
    r11 = (word64)(r11 + WC_L64(rdi, 24));
    r12 = (word64)(r12 + WC_L64(rdi, 32));
    r13 = (word64)(r13 + WC_L64(rdi, 40));
    r14 = (word64)(r14 + WC_L64(rdi, 48));
    r15 = (word64)(r15 + WC_L64(rdi, 56));
    rcx = (word64)((word64)(size_t)L_avx1_rorx_sha512_k);
    rsi = (word64)(rsi + 0x80);
    rbp = (word32)((word32)rbp - 0x80);
    zf1 = (word32)rbp;
    WC_S64(rdi, 0) = (word64)(r8);
    WC_S64(rdi, 8) = (word64)(r9);
    WC_S64(rdi, 16) = (word64)(r10);
    WC_S64(rdi, 24) = (word64)(r11);
    WC_S64(rdi, 32) = (word64)(r12);
    WC_S64(rdi, 40) = (word64)(r13);
    WC_S64(rdi, 48) = (word64)(r14);
    WC_S64(rdi, 56) = (word64)(r15);
    if ((zf1) != (0)) {
        goto L_sha512_len_avx1_rorx_begin;
    }
    rax = (word64)(0);
    return (int)(word32)rax;
}

#endif /* HAVE_INTEL_AVX1 */
#ifdef HAVE_INTEL_AVX2
XALIGNED(32) static const word64 L_avx2_sha512_k[] WC_X64I_UNUSED = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

XALIGNED(32) static const word64 L_avx2_sha512_k_2[] WC_X64I_UNUSED = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

XALIGNED(16) static const word64 L_avx2_sha512_k_2_end[] WC_X64I_UNUSED = {
    (word64)(size_t)(L_avx2_sha512_k_2 + 128),
};

XALIGNED(32) static const word64 L_avx2_sha512_flip_mask[] WC_X64I_UNUSED = {
    0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL,
    0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL,
};

WC_X64I_TARGET("avx2")
WOLFSSL_LOCAL int Transform_Sha512_AVX2(wc_Sha512* sha512)
{
    word64 rdi, rsp, rax, r8, r9, r10, r11, r12, r13, r14, r15, rsi, rbx,
           rdx = 0, rcx = 0;
    __m256i y0, y1, y2, y3, y8, y9, y10 = _mm256_setzero_si256(),
            y11 = _mm256_setzero_si256(), y12 = _mm256_setzero_si256(),
            y13 = _mm256_setzero_si256(), y14 = _mm256_setzero_si256(), y15;
    XALIGNED(32) WC_X64I_SLOT stk[20];

    rdi = (word64)(size_t)sha512;

    rsp = (word64)(size_t)stk + 160;
    rsp = (word64)(rsp - 136);
    rax = (word64)(rdi + 64);
    y15 = _mm256_loadu_si256((const __m256i*)WC_PR(L_avx2_sha512_flip_mask, 0));
    r8 = (word64)(WC_L64(rdi, 0));
    r9 = (word64)(WC_L64(rdi, 8));
    r10 = (word64)(WC_L64(rdi, 16));
    r11 = (word64)(WC_L64(rdi, 24));
    r12 = (word64)(WC_L64(rdi, 32));
    r13 = (word64)(WC_L64(rdi, 40));
    r14 = (word64)(WC_L64(rdi, 48));
    r15 = (word64)(WC_L64(rdi, 56));
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rax, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rax, 32));
    y0 = _mm256_shuffle_epi8(y0, y15);
    y1 = _mm256_shuffle_epi8(y1, y15);
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rax, 64));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(rax, 96));
    y2 = _mm256_shuffle_epi8(y2, y15);
    y3 = _mm256_shuffle_epi8(y3, y15);
    WC_S32(rsp, 128) = (word32)(4);
    rsi = (word64)((word64)(size_t)L_avx2_sha512_k);
    rbx = (word64)(r9);
    rax = (word64)(r12);
    rbx = (word64)(rbx ^ r10);
    y8 = _mm256_add_epi64(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        0)));
    y9 = _mm256_add_epi64(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        32)));
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 0), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 32), y9);
    y8 = _mm256_add_epi64(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        64)));
    y9 = _mm256_add_epi64(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        96)));
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 64), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 96), y9);
    /* Start of 16 rounds */
L_sha256_avx2_start:
    rsi = (word64)(rsi + 0x80);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y12 = _mm256_blend_epi32(y0, y1, 3);
    y13 = _mm256_blend_epi32(y2, y3, 3);
    rdx = (word64)(r8);
    rcx = (word64)(r13);
    r15 = (word64)(r15 + WC_L64(rsp, 0));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    rcx = (word64)(rcx & r12);
    y12 = _mm256_permute4x64_epi64(y12, 0x39);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r14);
    y13 = _mm256_permute4x64_epi64(y13, 0x39);
    rax = (word64)(rax ^ r12);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r9);
    y8 = _mm256_srli_epi64(y12, 1);
    r15 = (word64)(r15 + rax);
    rcx = (word64)(r8);
    y9 = _mm256_slli_epi64(y12, 63);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y10 = _mm256_srli_epi64(y12, 8);
    rcx = (word64)(rcx ^ r8);
    rbx = (word64)(rbx ^ r9);
    y11 = _mm256_slli_epi64(y12, 56);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r11 = (word64)(r11 + r15);
    y8 = _mm256_or_si256(y8, y9);
    rcx = (word64)(rcx ^ r8);
    r15 = (word64)(r15 + rbx);
    y10 = _mm256_or_si256(y10, y11);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r11);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y11 = _mm256_srli_epi64(y12, 7);
    rbx = (word64)(r15);
    rcx = (word64)(r12);
    y8 = _mm256_xor_si256(y8, y10);
    r14 = (word64)(r14 + WC_L64(rsp, 8));
    rcx = (word64)(rcx ^ r13);
    y8 = _mm256_xor_si256(y8, y11);
    rax = (word64)(rax ^ r11);
    rcx = (word64)(rcx & r11);
    y0 = _mm256_add_epi64(y13, y0);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r13);
    y0 = _mm256_add_epi64(y8, y0);
    rax = (word64)(rax ^ r11);
    r14 = (word64)(r14 + rcx);
    y14 = _mm256_permute2x128_si256(y3, y3, 0x81);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r8);
    r14 = (word64)(r14 + rax);
    rcx = (word64)(r15);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y8 = _mm256_srli_epi64(y14, 19);
    rcx = (word64)(rcx ^ r15);
    rdx = (word64)(rdx ^ r8);
    y9 = _mm256_slli_epi64(y14, 45);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r10 = (word64)(r10 + r14);
    y10 = _mm256_srli_epi64(y14, 61);
    rcx = (word64)(rcx ^ r15);
    r14 = (word64)(r14 + rdx);
    y11 = _mm256_slli_epi64(y14, 3);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r10);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y8 = _mm256_or_si256(y8, y9);
    rdx = (word64)(r14);
    rcx = (word64)(r11);
    r13 = (word64)(r13 + WC_L64(rsp, 16));
    rcx = (word64)(rcx ^ r12);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(rax ^ r10);
    rcx = (word64)(rcx & r10);
    y8 = _mm256_xor_si256(y8, y10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r12);
    y11 = _mm256_srli_epi64(y14, 6);
    rax = (word64)(rax ^ r10);
    r13 = (word64)(r13 + rcx);
    y8 = _mm256_xor_si256(y8, y11);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r15);
    y0 = _mm256_add_epi64(y8, y0);
    r13 = (word64)(r13 + rax);
    rcx = (word64)(r14);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y14 = _mm256_permute2x128_si256(y0, y0, 8);
    rcx = (word64)(rcx ^ r14);
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r9 = (word64)(r9 + r13);
    y8 = _mm256_srli_epi64(y14, 19);
    rcx = (word64)(rcx ^ r14);
    r13 = (word64)(r13 + rbx);
    y9 = _mm256_slli_epi64(y14, 45);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r9);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y10 = _mm256_srli_epi64(y14, 61);
    rbx = (word64)(r13);
    rcx = (word64)(r10);
    r12 = (word64)(r12 + WC_L64(rsp, 24));
    rcx = (word64)(rcx ^ r11);
    y11 = _mm256_slli_epi64(y14, 3);
    rax = (word64)(rax ^ r9);
    rcx = (word64)(rcx & r9);
    y8 = _mm256_or_si256(y8, y9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r11);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(rax ^ r9);
    r12 = (word64)(r12 + rcx);
    y8 = _mm256_xor_si256(y8, y10);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r14);
    y11 = _mm256_srli_epi64(y14, 6);
    r12 = (word64)(r12 + rax);
    rcx = (word64)(r13);
    y8 = _mm256_xor_si256(y8, y11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y0 = _mm256_add_epi64(y8, y0);
    rcx = (word64)(rcx ^ r13);
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r8 = (word64)(r8 + r12);
    rcx = (word64)(rcx ^ r13);
    r12 = (word64)(r12 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r8);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y12 = _mm256_blend_epi32(y1, y2, 3);
    y13 = _mm256_blend_epi32(y3, y0, 3);
    rdx = (word64)(r12);
    rcx = (word64)(r9);
    r11 = (word64)(r11 + WC_L64(rsp, 32));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    rcx = (word64)(rcx & r8);
    y12 = _mm256_permute4x64_epi64(y12, 0x39);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r10);
    y13 = _mm256_permute4x64_epi64(y13, 0x39);
    rax = (word64)(rax ^ r8);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r13);
    y8 = _mm256_srli_epi64(y12, 1);
    r11 = (word64)(r11 + rax);
    rcx = (word64)(r12);
    y9 = _mm256_slli_epi64(y12, 63);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y10 = _mm256_srli_epi64(y12, 8);
    rcx = (word64)(rcx ^ r12);
    rbx = (word64)(rbx ^ r13);
    y11 = _mm256_slli_epi64(y12, 56);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r15 = (word64)(r15 + r11);
    y8 = _mm256_or_si256(y8, y9);
    rcx = (word64)(rcx ^ r12);
    r11 = (word64)(r11 + rbx);
    y10 = _mm256_or_si256(y10, y11);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r15);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y11 = _mm256_srli_epi64(y12, 7);
    rbx = (word64)(r11);
    rcx = (word64)(r8);
    y8 = _mm256_xor_si256(y8, y10);
    r10 = (word64)(r10 + WC_L64(rsp, 40));
    rcx = (word64)(rcx ^ r9);
    y8 = _mm256_xor_si256(y8, y11);
    rax = (word64)(rax ^ r15);
    rcx = (word64)(rcx & r15);
    y1 = _mm256_add_epi64(y13, y1);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r9);
    y1 = _mm256_add_epi64(y8, y1);
    rax = (word64)(rax ^ r15);
    r10 = (word64)(r10 + rcx);
    y14 = _mm256_permute2x128_si256(y0, y0, 0x81);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r12);
    r10 = (word64)(r10 + rax);
    rcx = (word64)(r11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y8 = _mm256_srli_epi64(y14, 19);
    rcx = (word64)(rcx ^ r11);
    rdx = (word64)(rdx ^ r12);
    y9 = _mm256_slli_epi64(y14, 45);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r14 = (word64)(r14 + r10);
    y10 = _mm256_srli_epi64(y14, 61);
    rcx = (word64)(rcx ^ r11);
    r10 = (word64)(r10 + rdx);
    y11 = _mm256_slli_epi64(y14, 3);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r14);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y8 = _mm256_or_si256(y8, y9);
    rdx = (word64)(r10);
    rcx = (word64)(r15);
    r9 = (word64)(r9 + WC_L64(rsp, 48));
    rcx = (word64)(rcx ^ r8);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(rax ^ r14);
    rcx = (word64)(rcx & r14);
    y8 = _mm256_xor_si256(y8, y10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r8);
    y11 = _mm256_srli_epi64(y14, 6);
    rax = (word64)(rax ^ r14);
    r9 = (word64)(r9 + rcx);
    y8 = _mm256_xor_si256(y8, y11);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r11);
    y1 = _mm256_add_epi64(y8, y1);
    r9 = (word64)(r9 + rax);
    rcx = (word64)(r10);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y14 = _mm256_permute2x128_si256(y1, y1, 8);
    rcx = (word64)(rcx ^ r10);
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r13 = (word64)(r13 + r9);
    y8 = _mm256_srli_epi64(y14, 19);
    rcx = (word64)(rcx ^ r10);
    r9 = (word64)(r9 + rbx);
    y9 = _mm256_slli_epi64(y14, 45);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r13);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y10 = _mm256_srli_epi64(y14, 61);
    rbx = (word64)(r9);
    rcx = (word64)(r14);
    r8 = (word64)(r8 + WC_L64(rsp, 56));
    rcx = (word64)(rcx ^ r15);
    y11 = _mm256_slli_epi64(y14, 3);
    rax = (word64)(rax ^ r13);
    rcx = (word64)(rcx & r13);
    y8 = _mm256_or_si256(y8, y9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r15);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(rax ^ r13);
    r8 = (word64)(r8 + rcx);
    y8 = _mm256_xor_si256(y8, y10);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r10);
    y11 = _mm256_srli_epi64(y14, 6);
    r8 = (word64)(r8 + rax);
    rcx = (word64)(r9);
    y8 = _mm256_xor_si256(y8, y11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y1 = _mm256_add_epi64(y8, y1);
    rcx = (word64)(rcx ^ r9);
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r12 = (word64)(r12 + r8);
    rcx = (word64)(rcx ^ r9);
    r8 = (word64)(r8 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r12);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y12 = _mm256_blend_epi32(y2, y3, 3);
    y13 = _mm256_blend_epi32(y0, y1, 3);
    rdx = (word64)(r8);
    rcx = (word64)(r13);
    r15 = (word64)(r15 + WC_L64(rsp, 64));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    rcx = (word64)(rcx & r12);
    y12 = _mm256_permute4x64_epi64(y12, 0x39);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r14);
    y13 = _mm256_permute4x64_epi64(y13, 0x39);
    rax = (word64)(rax ^ r12);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r9);
    y8 = _mm256_srli_epi64(y12, 1);
    r15 = (word64)(r15 + rax);
    rcx = (word64)(r8);
    y9 = _mm256_slli_epi64(y12, 63);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y10 = _mm256_srli_epi64(y12, 8);
    rcx = (word64)(rcx ^ r8);
    rbx = (word64)(rbx ^ r9);
    y11 = _mm256_slli_epi64(y12, 56);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r11 = (word64)(r11 + r15);
    y8 = _mm256_or_si256(y8, y9);
    rcx = (word64)(rcx ^ r8);
    r15 = (word64)(r15 + rbx);
    y10 = _mm256_or_si256(y10, y11);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r11);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y11 = _mm256_srli_epi64(y12, 7);
    rbx = (word64)(r15);
    rcx = (word64)(r12);
    y8 = _mm256_xor_si256(y8, y10);
    r14 = (word64)(r14 + WC_L64(rsp, 72));
    rcx = (word64)(rcx ^ r13);
    y8 = _mm256_xor_si256(y8, y11);
    rax = (word64)(rax ^ r11);
    rcx = (word64)(rcx & r11);
    y2 = _mm256_add_epi64(y13, y2);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r13);
    y2 = _mm256_add_epi64(y8, y2);
    rax = (word64)(rax ^ r11);
    r14 = (word64)(r14 + rcx);
    y14 = _mm256_permute2x128_si256(y1, y1, 0x81);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r8);
    r14 = (word64)(r14 + rax);
    rcx = (word64)(r15);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y8 = _mm256_srli_epi64(y14, 19);
    rcx = (word64)(rcx ^ r15);
    rdx = (word64)(rdx ^ r8);
    y9 = _mm256_slli_epi64(y14, 45);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r10 = (word64)(r10 + r14);
    y10 = _mm256_srli_epi64(y14, 61);
    rcx = (word64)(rcx ^ r15);
    r14 = (word64)(r14 + rdx);
    y11 = _mm256_slli_epi64(y14, 3);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r10);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y8 = _mm256_or_si256(y8, y9);
    rdx = (word64)(r14);
    rcx = (word64)(r11);
    r13 = (word64)(r13 + WC_L64(rsp, 80));
    rcx = (word64)(rcx ^ r12);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(rax ^ r10);
    rcx = (word64)(rcx & r10);
    y8 = _mm256_xor_si256(y8, y10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r12);
    y11 = _mm256_srli_epi64(y14, 6);
    rax = (word64)(rax ^ r10);
    r13 = (word64)(r13 + rcx);
    y8 = _mm256_xor_si256(y8, y11);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r15);
    y2 = _mm256_add_epi64(y8, y2);
    r13 = (word64)(r13 + rax);
    rcx = (word64)(r14);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y14 = _mm256_permute2x128_si256(y2, y2, 8);
    rcx = (word64)(rcx ^ r14);
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r9 = (word64)(r9 + r13);
    y8 = _mm256_srli_epi64(y14, 19);
    rcx = (word64)(rcx ^ r14);
    r13 = (word64)(r13 + rbx);
    y9 = _mm256_slli_epi64(y14, 45);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r9);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y10 = _mm256_srli_epi64(y14, 61);
    rbx = (word64)(r13);
    rcx = (word64)(r10);
    r12 = (word64)(r12 + WC_L64(rsp, 88));
    rcx = (word64)(rcx ^ r11);
    y11 = _mm256_slli_epi64(y14, 3);
    rax = (word64)(rax ^ r9);
    rcx = (word64)(rcx & r9);
    y8 = _mm256_or_si256(y8, y9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r11);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(rax ^ r9);
    r12 = (word64)(r12 + rcx);
    y8 = _mm256_xor_si256(y8, y10);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r14);
    y11 = _mm256_srli_epi64(y14, 6);
    r12 = (word64)(r12 + rax);
    rcx = (word64)(r13);
    y8 = _mm256_xor_si256(y8, y11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y2 = _mm256_add_epi64(y8, y2);
    rcx = (word64)(rcx ^ r13);
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r8 = (word64)(r8 + r12);
    rcx = (word64)(rcx ^ r13);
    r12 = (word64)(r12 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r8);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y12 = _mm256_blend_epi32(y3, y0, 3);
    y13 = _mm256_blend_epi32(y1, y2, 3);
    rdx = (word64)(r12);
    rcx = (word64)(r9);
    r11 = (word64)(r11 + WC_L64(rsp, 96));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    rcx = (word64)(rcx & r8);
    y12 = _mm256_permute4x64_epi64(y12, 0x39);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r10);
    y13 = _mm256_permute4x64_epi64(y13, 0x39);
    rax = (word64)(rax ^ r8);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r13);
    y8 = _mm256_srli_epi64(y12, 1);
    r11 = (word64)(r11 + rax);
    rcx = (word64)(r12);
    y9 = _mm256_slli_epi64(y12, 63);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y10 = _mm256_srli_epi64(y12, 8);
    rcx = (word64)(rcx ^ r12);
    rbx = (word64)(rbx ^ r13);
    y11 = _mm256_slli_epi64(y12, 56);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r15 = (word64)(r15 + r11);
    y8 = _mm256_or_si256(y8, y9);
    rcx = (word64)(rcx ^ r12);
    r11 = (word64)(r11 + rbx);
    y10 = _mm256_or_si256(y10, y11);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r15);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y11 = _mm256_srli_epi64(y12, 7);
    rbx = (word64)(r11);
    rcx = (word64)(r8);
    y8 = _mm256_xor_si256(y8, y10);
    r10 = (word64)(r10 + WC_L64(rsp, 104));
    rcx = (word64)(rcx ^ r9);
    y8 = _mm256_xor_si256(y8, y11);
    rax = (word64)(rax ^ r15);
    rcx = (word64)(rcx & r15);
    y3 = _mm256_add_epi64(y13, y3);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r9);
    y3 = _mm256_add_epi64(y8, y3);
    rax = (word64)(rax ^ r15);
    r10 = (word64)(r10 + rcx);
    y14 = _mm256_permute2x128_si256(y2, y2, 0x81);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r12);
    r10 = (word64)(r10 + rax);
    rcx = (word64)(r11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y8 = _mm256_srli_epi64(y14, 19);
    rcx = (word64)(rcx ^ r11);
    rdx = (word64)(rdx ^ r12);
    y9 = _mm256_slli_epi64(y14, 45);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r14 = (word64)(r14 + r10);
    y10 = _mm256_srli_epi64(y14, 61);
    rcx = (word64)(rcx ^ r11);
    r10 = (word64)(r10 + rdx);
    y11 = _mm256_slli_epi64(y14, 3);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r14);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y8 = _mm256_or_si256(y8, y9);
    rdx = (word64)(r10);
    rcx = (word64)(r15);
    r9 = (word64)(r9 + WC_L64(rsp, 112));
    rcx = (word64)(rcx ^ r8);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(rax ^ r14);
    rcx = (word64)(rcx & r14);
    y8 = _mm256_xor_si256(y8, y10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r8);
    y11 = _mm256_srli_epi64(y14, 6);
    rax = (word64)(rax ^ r14);
    r9 = (word64)(r9 + rcx);
    y8 = _mm256_xor_si256(y8, y11);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r11);
    y3 = _mm256_add_epi64(y8, y3);
    r9 = (word64)(r9 + rax);
    rcx = (word64)(r10);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y14 = _mm256_permute2x128_si256(y3, y3, 8);
    rcx = (word64)(rcx ^ r10);
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r13 = (word64)(r13 + r9);
    y8 = _mm256_srli_epi64(y14, 19);
    rcx = (word64)(rcx ^ r10);
    r9 = (word64)(r9 + rbx);
    y9 = _mm256_slli_epi64(y14, 45);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r13);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y10 = _mm256_srli_epi64(y14, 61);
    rbx = (word64)(r9);
    rcx = (word64)(r14);
    r8 = (word64)(r8 + WC_L64(rsp, 120));
    rcx = (word64)(rcx ^ r15);
    y11 = _mm256_slli_epi64(y14, 3);
    rax = (word64)(rax ^ r13);
    rcx = (word64)(rcx & r13);
    y8 = _mm256_or_si256(y8, y9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r15);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(rax ^ r13);
    r8 = (word64)(r8 + rcx);
    y8 = _mm256_xor_si256(y8, y10);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r10);
    y11 = _mm256_srli_epi64(y14, 6);
    r8 = (word64)(r8 + rax);
    rcx = (word64)(r9);
    y8 = _mm256_xor_si256(y8, y11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y3 = _mm256_add_epi64(y8, y3);
    rcx = (word64)(rcx ^ r9);
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r12 = (word64)(r12 + r8);
    rcx = (word64)(rcx ^ r9);
    r8 = (word64)(r8 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r12);
    r8 = (word64)(r8 + rcx);
    y8 = _mm256_add_epi64(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        0)));
    y9 = _mm256_add_epi64(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        32)));
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 0), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 32), y9);
    y8 = _mm256_add_epi64(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        64)));
    y9 = _mm256_add_epi64(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        96)));
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 64), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 96), y9);
    WC_S32(rsp, 128) = (word32)(WC_L32(rsp, 128) - 1);
    if (((word32)WC_S32(rsp, 128)) != (0)) {
        goto L_sha256_avx2_start;
    }
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r8);
    rcx = (word64)(r13);
    r15 = (word64)(r15 + WC_L64(rsp, 0));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    rcx = (word64)(rcx & r12);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r9);
    r15 = (word64)(r15 + rax);
    rcx = (word64)(r8);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r8);
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r11 = (word64)(r11 + r15);
    rcx = (word64)(rcx ^ r8);
    r15 = (word64)(r15 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r11);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r15);
    rcx = (word64)(r12);
    r14 = (word64)(r14 + WC_L64(rsp, 8));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    rcx = (word64)(rcx & r11);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r8);
    r14 = (word64)(r14 + rax);
    rcx = (word64)(r15);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r15);
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r10 = (word64)(r10 + r14);
    rcx = (word64)(rcx ^ r15);
    r14 = (word64)(r14 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r10);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r14);
    rcx = (word64)(r11);
    r13 = (word64)(r13 + WC_L64(rsp, 16));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    rcx = (word64)(rcx & r10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r15);
    r13 = (word64)(r13 + rax);
    rcx = (word64)(r14);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r14);
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r9 = (word64)(r9 + r13);
    rcx = (word64)(rcx ^ r14);
    r13 = (word64)(r13 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r9);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r13);
    rcx = (word64)(r10);
    r12 = (word64)(r12 + WC_L64(rsp, 24));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    rcx = (word64)(rcx & r9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r14);
    r12 = (word64)(r12 + rax);
    rcx = (word64)(r13);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r13);
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r8 = (word64)(r8 + r12);
    rcx = (word64)(rcx ^ r13);
    r12 = (word64)(r12 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r8);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r12);
    rcx = (word64)(r9);
    r11 = (word64)(r11 + WC_L64(rsp, 32));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    rcx = (word64)(rcx & r8);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r13);
    r11 = (word64)(r11 + rax);
    rcx = (word64)(r12);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r12);
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r15 = (word64)(r15 + r11);
    rcx = (word64)(rcx ^ r12);
    r11 = (word64)(r11 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r15);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r11);
    rcx = (word64)(r8);
    r10 = (word64)(r10 + WC_L64(rsp, 40));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    rcx = (word64)(rcx & r15);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r12);
    r10 = (word64)(r10 + rax);
    rcx = (word64)(r11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r11);
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r14 = (word64)(r14 + r10);
    rcx = (word64)(rcx ^ r11);
    r10 = (word64)(r10 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r14);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r10);
    rcx = (word64)(r15);
    r9 = (word64)(r9 + WC_L64(rsp, 48));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    rcx = (word64)(rcx & r14);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r11);
    r9 = (word64)(r9 + rax);
    rcx = (word64)(r10);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r10);
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r13 = (word64)(r13 + r9);
    rcx = (word64)(rcx ^ r10);
    r9 = (word64)(r9 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r13);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r9);
    rcx = (word64)(r14);
    r8 = (word64)(r8 + WC_L64(rsp, 56));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    rcx = (word64)(rcx & r13);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r10);
    r8 = (word64)(r8 + rax);
    rcx = (word64)(r9);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r9);
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r12 = (word64)(r12 + r8);
    rcx = (word64)(rcx ^ r9);
    r8 = (word64)(r8 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r12);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r8);
    rcx = (word64)(r13);
    r15 = (word64)(r15 + WC_L64(rsp, 64));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    rcx = (word64)(rcx & r12);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r9);
    r15 = (word64)(r15 + rax);
    rcx = (word64)(r8);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r8);
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r11 = (word64)(r11 + r15);
    rcx = (word64)(rcx ^ r8);
    r15 = (word64)(r15 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r11);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r15);
    rcx = (word64)(r12);
    r14 = (word64)(r14 + WC_L64(rsp, 72));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    rcx = (word64)(rcx & r11);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r8);
    r14 = (word64)(r14 + rax);
    rcx = (word64)(r15);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r15);
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r10 = (word64)(r10 + r14);
    rcx = (word64)(rcx ^ r15);
    r14 = (word64)(r14 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r10);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r14);
    rcx = (word64)(r11);
    r13 = (word64)(r13 + WC_L64(rsp, 80));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    rcx = (word64)(rcx & r10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r15);
    r13 = (word64)(r13 + rax);
    rcx = (word64)(r14);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r14);
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r9 = (word64)(r9 + r13);
    rcx = (word64)(rcx ^ r14);
    r13 = (word64)(r13 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r9);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r13);
    rcx = (word64)(r10);
    r12 = (word64)(r12 + WC_L64(rsp, 88));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    rcx = (word64)(rcx & r9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r14);
    r12 = (word64)(r12 + rax);
    rcx = (word64)(r13);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r13);
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r8 = (word64)(r8 + r12);
    rcx = (word64)(rcx ^ r13);
    r12 = (word64)(r12 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r8);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r12);
    rcx = (word64)(r9);
    r11 = (word64)(r11 + WC_L64(rsp, 96));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    rcx = (word64)(rcx & r8);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r13);
    r11 = (word64)(r11 + rax);
    rcx = (word64)(r12);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r12);
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r15 = (word64)(r15 + r11);
    rcx = (word64)(rcx ^ r12);
    r11 = (word64)(r11 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r15);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r11);
    rcx = (word64)(r8);
    r10 = (word64)(r10 + WC_L64(rsp, 104));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    rcx = (word64)(rcx & r15);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r12);
    r10 = (word64)(r10 + rax);
    rcx = (word64)(r11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r11);
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r14 = (word64)(r14 + r10);
    rcx = (word64)(rcx ^ r11);
    r10 = (word64)(r10 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r14);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r10);
    rcx = (word64)(r15);
    r9 = (word64)(r9 + WC_L64(rsp, 112));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    rcx = (word64)(rcx & r14);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r11);
    r9 = (word64)(r9 + rax);
    rcx = (word64)(r10);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r10);
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r13 = (word64)(r13 + r9);
    rcx = (word64)(rcx ^ r10);
    r9 = (word64)(r9 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r13);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r9);
    rcx = (word64)(r14);
    r8 = (word64)(r8 + WC_L64(rsp, 120));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    rcx = (word64)(rcx & r13);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r10);
    r8 = (word64)(r8 + rax);
    rcx = (word64)(r9);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r9);
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r12 = (word64)(r12 + r8);
    rcx = (word64)(rcx ^ r9);
    r8 = (word64)(r8 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r12);
    r8 = (word64)(r8 + rcx);
    WC_S64(rdi, 0) = (word64)(WC_L64(rdi, 0) + r8);
    WC_S64(rdi, 8) = (word64)(WC_L64(rdi, 8) + r9);
    WC_S64(rdi, 16) = (word64)(WC_L64(rdi, 16) + r10);
    WC_S64(rdi, 24) = (word64)(WC_L64(rdi, 24) + r11);
    WC_S64(rdi, 32) = (word64)(WC_L64(rdi, 32) + r12);
    WC_S64(rdi, 40) = (word64)(WC_L64(rdi, 40) + r13);
    WC_S64(rdi, 48) = (word64)(WC_L64(rdi, 48) + r14);
    WC_S64(rdi, 56) = (word64)(WC_L64(rdi, 56) + r15);
    rax = (word64)(0);
    return (int)(word32)rax;
}

WC_X64I_TARGET("avx2")
WOLFSSL_LOCAL int Transform_Sha512_AVX2_Len(wc_Sha512* sha512, word32 len)
{
    word64 rdi, rbp, rbx = 0, rsp, rcx = 0, r8 = 0, r9 = 0, r10 = 0, r11 = 0,
           r12 = 0, r13 = 0, r14 = 0, r15 = 0, rsi = 0, rax = 0, rdx = 0;
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y4 = _mm256_setzero_si256(), y5 = _mm256_setzero_si256(),
            y6 = _mm256_setzero_si256(), y7 = _mm256_setzero_si256(),
            y8 = _mm256_setzero_si256(), y9 = _mm256_setzero_si256(),
            y10 = _mm256_setzero_si256(), y11 = _mm256_setzero_si256(),
            y12 = _mm256_setzero_si256(), y13 = _mm256_setzero_si256(),
            y15 = _mm256_setzero_si256();
    XALIGNED(32) WC_X64I_SLOT stk[172];
    word32 zf1;

    rdi = (word64)(size_t)sha512;
    rbp = (word64)(word32)len;

    rsp = (word64)(size_t)stk + 1376;
    if ((((byte)rbp & 0x80)) == (0)) {
        goto L_sha512_len_avx2_block;
    }
    rbx = (word64)(WC_L64(rdi, 224));
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rbx, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rbx, 32));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rbx, 64));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(rbx, 96));
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 64), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 96), y1);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 128), y2);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 160), y3);
    (void)Transform_Sha512_AVX2((wc_Sha512*)(size_t)rdi);
    WC_S64(rdi, 224) = (word64)(WC_L64(rdi, 224) + 0x80);
    rbp = (word32)((word32)rbp - 0x80);
    if (((word32)rbp) == (0)) {
        goto L_sha512_len_avx2_done;
    }
L_sha512_len_avx2_block:
    rsp = (word64)(rsp - 1352);
    rcx = (word64)(WC_L64(rdi, 224));
    y15 = _mm256_loadu_si256((const __m256i*)WC_PR(L_avx2_sha512_flip_mask, 0));
    r8 = (word64)(WC_L64(rdi, 0));
    r9 = (word64)(WC_L64(rdi, 8));
    r10 = (word64)(WC_L64(rdi, 16));
    r11 = (word64)(WC_L64(rdi, 24));
    r12 = (word64)(WC_L64(rdi, 32));
    r13 = (word64)(WC_L64(rdi, 40));
    r14 = (word64)(WC_L64(rdi, 48));
    r15 = (word64)(WC_L64(rdi, 56));
    WC_S64(rsp, 1344) = (word64)(rbp);
    /* Start of loop processing two blocks */
L_sha512_len_avx2_begin:
    rbp = (word64)(rsp);
    rsi = (word64)((word64)(size_t)L_avx2_sha512_k_2);
    rbx = (word64)(r9);
    rax = (word64)(r12);
    y0 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    y1 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        16)));
    y0 = _mm256_inserti128_si256(y0, _mm_loadu_si128((const __m128i*)WC_PR(rcx,
        128)), 1);
    y1 = _mm256_inserti128_si256(y1, _mm_loadu_si128((const __m128i*)WC_PR(rcx,
        144)), 1);
    y0 = _mm256_shuffle_epi8(y0, y15);
    y1 = _mm256_shuffle_epi8(y1, y15);
    y2 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        32)));
    y3 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        48)));
    y2 = _mm256_inserti128_si256(y2, _mm_loadu_si128((const __m128i*)WC_PR(rcx,
        160)), 1);
    y3 = _mm256_inserti128_si256(y3, _mm_loadu_si128((const __m128i*)WC_PR(rcx,
        176)), 1);
    y2 = _mm256_shuffle_epi8(y2, y15);
    y3 = _mm256_shuffle_epi8(y3, y15);
    y4 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        64)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        80)));
    y4 = _mm256_inserti128_si256(y4, _mm_loadu_si128((const __m128i*)WC_PR(rcx,
        192)), 1);
    y5 = _mm256_inserti128_si256(y5, _mm_loadu_si128((const __m128i*)WC_PR(rcx,
        208)), 1);
    y4 = _mm256_shuffle_epi8(y4, y15);
    y5 = _mm256_shuffle_epi8(y5, y15);
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        96)));
    y7 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        112)));
    y6 = _mm256_inserti128_si256(y6, _mm_loadu_si128((const __m128i*)WC_PR(rcx,
        224)), 1);
    y7 = _mm256_inserti128_si256(y7, _mm_loadu_si128((const __m128i*)WC_PR(rcx,
        240)), 1);
    y6 = _mm256_shuffle_epi8(y6, y15);
    y7 = _mm256_shuffle_epi8(y7, y15);
    rbx = (word64)(rbx ^ r10);
    /* Start of 16 rounds */
L_sha512_len_avx2_start:
    y8 = _mm256_add_epi64(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        0)));
    y9 = _mm256_add_epi64(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        32)));
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 0), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 32), y9);
    y8 = _mm256_add_epi64(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        64)));
    y9 = _mm256_add_epi64(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        96)));
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 64), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 96), y9);
    y8 = _mm256_add_epi64(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        128)));
    y9 = _mm256_add_epi64(y5, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        160)));
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 128), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 160), y9);
    y8 = _mm256_add_epi64(y6, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        192)));
    y9 = _mm256_add_epi64(y7, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        224)));
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 192), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 224), y9);
    /* msg_sched: 0-1 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y12 = _mm256_alignr_epi8(y1, y0, 8);
    y13 = _mm256_alignr_epi8(y5, y4, 8);
    rdx = (word64)(r8);
    rcx = (word64)(r13);
    r15 = (word64)(r15 + WC_L64(rbp, 0));
    rcx = (word64)(rcx ^ r14);
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rax = (word64)(rax ^ r12);
    rcx = (word64)(rcx & r12);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r14);
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    rax = (word64)(rax ^ r12);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r9);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    r15 = (word64)(r15 + rax);
    rcx = (word64)(r8);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y11 = _mm256_srli_epi64(y12, 7);
    y8 = _mm256_xor_si256(y8, y10);
    rcx = (word64)(rcx ^ r8);
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r11 = (word64)(r11 + r15);
    y8 = _mm256_xor_si256(y8, y11);
    y0 = _mm256_add_epi64(y13, y0);
    rcx = (word64)(rcx ^ r8);
    r15 = (word64)(r15 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r11);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y0 = _mm256_add_epi64(y8, y0);
    rbx = (word64)(r15);
    rcx = (word64)(r12);
    r14 = (word64)(r14 + WC_L64(rbp, 8));
    rcx = (word64)(rcx ^ r13);
    y8 = _mm256_srli_epi64(y7, 19);
    y9 = _mm256_slli_epi64(y7, 45);
    rax = (word64)(rax ^ r11);
    rcx = (word64)(rcx & r11);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r13);
    y10 = _mm256_srli_epi64(y7, 61);
    y11 = _mm256_slli_epi64(y7, 3);
    rax = (word64)(rax ^ r11);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r8);
    r14 = (word64)(r14 + rax);
    rcx = (word64)(r15);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r15);
    rdx = (word64)(rdx ^ r8);
    y8 = _mm256_xor_si256(y8, y10);
    y11 = _mm256_srli_epi64(y7, 6);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r10 = (word64)(r10 + r14);
    rcx = (word64)(rcx ^ r15);
    r14 = (word64)(r14 + rdx);
    y8 = _mm256_xor_si256(y8, y11);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r10);
    r14 = (word64)(r14 + rcx);
    y0 = _mm256_add_epi64(y8, y0);
    /* msg_sched done: 0-1 */
    /* msg_sched: 4-5 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y12 = _mm256_alignr_epi8(y2, y1, 8);
    y13 = _mm256_alignr_epi8(y6, y5, 8);
    rdx = (word64)(r14);
    rcx = (word64)(r11);
    r13 = (word64)(r13 + WC_L64(rbp, 32));
    rcx = (word64)(rcx ^ r12);
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rax = (word64)(rax ^ r10);
    rcx = (word64)(rcx & r10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r12);
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    rax = (word64)(rax ^ r10);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r15);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    r13 = (word64)(r13 + rax);
    rcx = (word64)(r14);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y11 = _mm256_srli_epi64(y12, 7);
    y8 = _mm256_xor_si256(y8, y10);
    rcx = (word64)(rcx ^ r14);
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r9 = (word64)(r9 + r13);
    y8 = _mm256_xor_si256(y8, y11);
    y1 = _mm256_add_epi64(y13, y1);
    rcx = (word64)(rcx ^ r14);
    r13 = (word64)(r13 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r9);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y1 = _mm256_add_epi64(y8, y1);
    rbx = (word64)(r13);
    rcx = (word64)(r10);
    r12 = (word64)(r12 + WC_L64(rbp, 40));
    rcx = (word64)(rcx ^ r11);
    y8 = _mm256_srli_epi64(y0, 19);
    y9 = _mm256_slli_epi64(y0, 45);
    rax = (word64)(rax ^ r9);
    rcx = (word64)(rcx & r9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r11);
    y10 = _mm256_srli_epi64(y0, 61);
    y11 = _mm256_slli_epi64(y0, 3);
    rax = (word64)(rax ^ r9);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r14);
    r12 = (word64)(r12 + rax);
    rcx = (word64)(r13);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r13);
    rdx = (word64)(rdx ^ r14);
    y8 = _mm256_xor_si256(y8, y10);
    y11 = _mm256_srli_epi64(y0, 6);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r8 = (word64)(r8 + r12);
    rcx = (word64)(rcx ^ r13);
    r12 = (word64)(r12 + rdx);
    y8 = _mm256_xor_si256(y8, y11);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r8);
    r12 = (word64)(r12 + rcx);
    y1 = _mm256_add_epi64(y8, y1);
    /* msg_sched done: 4-5 */
    /* msg_sched: 8-9 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y12 = _mm256_alignr_epi8(y3, y2, 8);
    y13 = _mm256_alignr_epi8(y7, y6, 8);
    rdx = (word64)(r12);
    rcx = (word64)(r9);
    r11 = (word64)(r11 + WC_L64(rbp, 64));
    rcx = (word64)(rcx ^ r10);
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rax = (word64)(rax ^ r8);
    rcx = (word64)(rcx & r8);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r10);
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    rax = (word64)(rax ^ r8);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r13);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    r11 = (word64)(r11 + rax);
    rcx = (word64)(r12);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y11 = _mm256_srli_epi64(y12, 7);
    y8 = _mm256_xor_si256(y8, y10);
    rcx = (word64)(rcx ^ r12);
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r15 = (word64)(r15 + r11);
    y8 = _mm256_xor_si256(y8, y11);
    y2 = _mm256_add_epi64(y13, y2);
    rcx = (word64)(rcx ^ r12);
    r11 = (word64)(r11 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r15);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y2 = _mm256_add_epi64(y8, y2);
    rbx = (word64)(r11);
    rcx = (word64)(r8);
    r10 = (word64)(r10 + WC_L64(rbp, 72));
    rcx = (word64)(rcx ^ r9);
    y8 = _mm256_srli_epi64(y1, 19);
    y9 = _mm256_slli_epi64(y1, 45);
    rax = (word64)(rax ^ r15);
    rcx = (word64)(rcx & r15);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r9);
    y10 = _mm256_srli_epi64(y1, 61);
    y11 = _mm256_slli_epi64(y1, 3);
    rax = (word64)(rax ^ r15);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r12);
    r10 = (word64)(r10 + rax);
    rcx = (word64)(r11);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r11);
    rdx = (word64)(rdx ^ r12);
    y8 = _mm256_xor_si256(y8, y10);
    y11 = _mm256_srli_epi64(y1, 6);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r14 = (word64)(r14 + r10);
    rcx = (word64)(rcx ^ r11);
    r10 = (word64)(r10 + rdx);
    y8 = _mm256_xor_si256(y8, y11);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r14);
    r10 = (word64)(r10 + rcx);
    y2 = _mm256_add_epi64(y8, y2);
    /* msg_sched done: 8-9 */
    /* msg_sched: 12-13 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y12 = _mm256_alignr_epi8(y4, y3, 8);
    y13 = _mm256_alignr_epi8(y0, y7, 8);
    rdx = (word64)(r10);
    rcx = (word64)(r15);
    r9 = (word64)(r9 + WC_L64(rbp, 96));
    rcx = (word64)(rcx ^ r8);
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rax = (word64)(rax ^ r14);
    rcx = (word64)(rcx & r14);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r8);
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    rax = (word64)(rax ^ r14);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r11);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    r9 = (word64)(r9 + rax);
    rcx = (word64)(r10);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y11 = _mm256_srli_epi64(y12, 7);
    y8 = _mm256_xor_si256(y8, y10);
    rcx = (word64)(rcx ^ r10);
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r13 = (word64)(r13 + r9);
    y8 = _mm256_xor_si256(y8, y11);
    y3 = _mm256_add_epi64(y13, y3);
    rcx = (word64)(rcx ^ r10);
    r9 = (word64)(r9 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r13);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y3 = _mm256_add_epi64(y8, y3);
    rbx = (word64)(r9);
    rcx = (word64)(r14);
    r8 = (word64)(r8 + WC_L64(rbp, 104));
    rcx = (word64)(rcx ^ r15);
    y8 = _mm256_srli_epi64(y2, 19);
    y9 = _mm256_slli_epi64(y2, 45);
    rax = (word64)(rax ^ r13);
    rcx = (word64)(rcx & r13);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r15);
    y10 = _mm256_srli_epi64(y2, 61);
    y11 = _mm256_slli_epi64(y2, 3);
    rax = (word64)(rax ^ r13);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r10);
    r8 = (word64)(r8 + rax);
    rcx = (word64)(r9);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r9);
    rdx = (word64)(rdx ^ r10);
    y8 = _mm256_xor_si256(y8, y10);
    y11 = _mm256_srli_epi64(y2, 6);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r12 = (word64)(r12 + r8);
    rcx = (word64)(rcx ^ r9);
    r8 = (word64)(r8 + rdx);
    y8 = _mm256_xor_si256(y8, y11);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r12);
    r8 = (word64)(r8 + rcx);
    y3 = _mm256_add_epi64(y8, y3);
    /* msg_sched done: 12-13 */
    /* msg_sched: 16-17 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y12 = _mm256_alignr_epi8(y5, y4, 8);
    y13 = _mm256_alignr_epi8(y1, y0, 8);
    rdx = (word64)(r8);
    rcx = (word64)(r13);
    r15 = (word64)(r15 + WC_L64(rbp, 128));
    rcx = (word64)(rcx ^ r14);
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rax = (word64)(rax ^ r12);
    rcx = (word64)(rcx & r12);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r14);
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    rax = (word64)(rax ^ r12);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r9);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    r15 = (word64)(r15 + rax);
    rcx = (word64)(r8);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y11 = _mm256_srli_epi64(y12, 7);
    y8 = _mm256_xor_si256(y8, y10);
    rcx = (word64)(rcx ^ r8);
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r11 = (word64)(r11 + r15);
    y8 = _mm256_xor_si256(y8, y11);
    y4 = _mm256_add_epi64(y13, y4);
    rcx = (word64)(rcx ^ r8);
    r15 = (word64)(r15 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r11);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y4 = _mm256_add_epi64(y8, y4);
    rbx = (word64)(r15);
    rcx = (word64)(r12);
    r14 = (word64)(r14 + WC_L64(rbp, 136));
    rcx = (word64)(rcx ^ r13);
    y8 = _mm256_srli_epi64(y3, 19);
    y9 = _mm256_slli_epi64(y3, 45);
    rax = (word64)(rax ^ r11);
    rcx = (word64)(rcx & r11);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r13);
    y10 = _mm256_srli_epi64(y3, 61);
    y11 = _mm256_slli_epi64(y3, 3);
    rax = (word64)(rax ^ r11);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r8);
    r14 = (word64)(r14 + rax);
    rcx = (word64)(r15);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r15);
    rdx = (word64)(rdx ^ r8);
    y8 = _mm256_xor_si256(y8, y10);
    y11 = _mm256_srli_epi64(y3, 6);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r10 = (word64)(r10 + r14);
    rcx = (word64)(rcx ^ r15);
    r14 = (word64)(r14 + rdx);
    y8 = _mm256_xor_si256(y8, y11);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r10);
    r14 = (word64)(r14 + rcx);
    y4 = _mm256_add_epi64(y8, y4);
    /* msg_sched done: 16-17 */
    /* msg_sched: 20-21 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y12 = _mm256_alignr_epi8(y6, y5, 8);
    y13 = _mm256_alignr_epi8(y2, y1, 8);
    rdx = (word64)(r14);
    rcx = (word64)(r11);
    r13 = (word64)(r13 + WC_L64(rbp, 160));
    rcx = (word64)(rcx ^ r12);
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rax = (word64)(rax ^ r10);
    rcx = (word64)(rcx & r10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r12);
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    rax = (word64)(rax ^ r10);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r15);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    r13 = (word64)(r13 + rax);
    rcx = (word64)(r14);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y11 = _mm256_srli_epi64(y12, 7);
    y8 = _mm256_xor_si256(y8, y10);
    rcx = (word64)(rcx ^ r14);
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r9 = (word64)(r9 + r13);
    y8 = _mm256_xor_si256(y8, y11);
    y5 = _mm256_add_epi64(y13, y5);
    rcx = (word64)(rcx ^ r14);
    r13 = (word64)(r13 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r9);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y5 = _mm256_add_epi64(y8, y5);
    rbx = (word64)(r13);
    rcx = (word64)(r10);
    r12 = (word64)(r12 + WC_L64(rbp, 168));
    rcx = (word64)(rcx ^ r11);
    y8 = _mm256_srli_epi64(y4, 19);
    y9 = _mm256_slli_epi64(y4, 45);
    rax = (word64)(rax ^ r9);
    rcx = (word64)(rcx & r9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r11);
    y10 = _mm256_srli_epi64(y4, 61);
    y11 = _mm256_slli_epi64(y4, 3);
    rax = (word64)(rax ^ r9);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r14);
    r12 = (word64)(r12 + rax);
    rcx = (word64)(r13);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r13);
    rdx = (word64)(rdx ^ r14);
    y8 = _mm256_xor_si256(y8, y10);
    y11 = _mm256_srli_epi64(y4, 6);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r8 = (word64)(r8 + r12);
    rcx = (word64)(rcx ^ r13);
    r12 = (word64)(r12 + rdx);
    y8 = _mm256_xor_si256(y8, y11);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r8);
    r12 = (word64)(r12 + rcx);
    y5 = _mm256_add_epi64(y8, y5);
    /* msg_sched done: 20-21 */
    /* msg_sched: 24-25 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y12 = _mm256_alignr_epi8(y7, y6, 8);
    y13 = _mm256_alignr_epi8(y3, y2, 8);
    rdx = (word64)(r12);
    rcx = (word64)(r9);
    r11 = (word64)(r11 + WC_L64(rbp, 192));
    rcx = (word64)(rcx ^ r10);
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rax = (word64)(rax ^ r8);
    rcx = (word64)(rcx & r8);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r10);
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    rax = (word64)(rax ^ r8);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r13);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    r11 = (word64)(r11 + rax);
    rcx = (word64)(r12);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y11 = _mm256_srli_epi64(y12, 7);
    y8 = _mm256_xor_si256(y8, y10);
    rcx = (word64)(rcx ^ r12);
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r15 = (word64)(r15 + r11);
    y8 = _mm256_xor_si256(y8, y11);
    y6 = _mm256_add_epi64(y13, y6);
    rcx = (word64)(rcx ^ r12);
    r11 = (word64)(r11 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r15);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y6 = _mm256_add_epi64(y8, y6);
    rbx = (word64)(r11);
    rcx = (word64)(r8);
    r10 = (word64)(r10 + WC_L64(rbp, 200));
    rcx = (word64)(rcx ^ r9);
    y8 = _mm256_srli_epi64(y5, 19);
    y9 = _mm256_slli_epi64(y5, 45);
    rax = (word64)(rax ^ r15);
    rcx = (word64)(rcx & r15);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r9);
    y10 = _mm256_srli_epi64(y5, 61);
    y11 = _mm256_slli_epi64(y5, 3);
    rax = (word64)(rax ^ r15);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r12);
    r10 = (word64)(r10 + rax);
    rcx = (word64)(r11);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r11);
    rdx = (word64)(rdx ^ r12);
    y8 = _mm256_xor_si256(y8, y10);
    y11 = _mm256_srli_epi64(y5, 6);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r14 = (word64)(r14 + r10);
    rcx = (word64)(rcx ^ r11);
    r10 = (word64)(r10 + rdx);
    y8 = _mm256_xor_si256(y8, y11);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r14);
    r10 = (word64)(r10 + rcx);
    y6 = _mm256_add_epi64(y8, y6);
    /* msg_sched done: 24-25 */
    /* msg_sched: 28-29 */
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y12 = _mm256_alignr_epi8(y0, y7, 8);
    y13 = _mm256_alignr_epi8(y4, y3, 8);
    rdx = (word64)(r10);
    rcx = (word64)(r15);
    r9 = (word64)(r9 + WC_L64(rbp, 224));
    rcx = (word64)(rcx ^ r8);
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rax = (word64)(rax ^ r14);
    rcx = (word64)(rcx & r14);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r8);
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    rax = (word64)(rax ^ r14);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r11);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    r9 = (word64)(r9 + rax);
    rcx = (word64)(r10);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    y11 = _mm256_srli_epi64(y12, 7);
    y8 = _mm256_xor_si256(y8, y10);
    rcx = (word64)(rcx ^ r10);
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r13 = (word64)(r13 + r9);
    y8 = _mm256_xor_si256(y8, y11);
    y7 = _mm256_add_epi64(y13, y7);
    rcx = (word64)(rcx ^ r10);
    r9 = (word64)(r9 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r13);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    y7 = _mm256_add_epi64(y8, y7);
    rbx = (word64)(r9);
    rcx = (word64)(r14);
    r8 = (word64)(r8 + WC_L64(rbp, 232));
    rcx = (word64)(rcx ^ r15);
    y8 = _mm256_srli_epi64(y6, 19);
    y9 = _mm256_slli_epi64(y6, 45);
    rax = (word64)(rax ^ r13);
    rcx = (word64)(rcx & r13);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r15);
    y10 = _mm256_srli_epi64(y6, 61);
    y11 = _mm256_slli_epi64(y6, 3);
    rax = (word64)(rax ^ r13);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r10);
    r8 = (word64)(r8 + rax);
    rcx = (word64)(r9);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r9);
    rdx = (word64)(rdx ^ r10);
    y8 = _mm256_xor_si256(y8, y10);
    y11 = _mm256_srli_epi64(y6, 6);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r12 = (word64)(r12 + r8);
    rcx = (word64)(rcx ^ r9);
    r8 = (word64)(r8 + rdx);
    y8 = _mm256_xor_si256(y8, y11);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r12);
    r8 = (word64)(r8 + rcx);
    y7 = _mm256_add_epi64(y8, y7);
    /* msg_sched done: 28-29 */
    rsi = (word64)(rsi + 0x100);
    rbp = (word64)(rbp + 0x100);
    if ((rsi) != (WC_L64(L_avx2_sha512_k_2_end, 0))) {
        goto L_sha512_len_avx2_start;
    }
    y8 = _mm256_add_epi64(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        0)));
    y9 = _mm256_add_epi64(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        32)));
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 0), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 32), y9);
    y8 = _mm256_add_epi64(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        64)));
    y9 = _mm256_add_epi64(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        96)));
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 64), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 96), y9);
    y8 = _mm256_add_epi64(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        128)));
    y9 = _mm256_add_epi64(y5, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        160)));
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 128), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 160), y9);
    y8 = _mm256_add_epi64(y6, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        192)));
    y9 = _mm256_add_epi64(y7, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        224)));
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 192), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rbp, 224), y9);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r8);
    rcx = (word64)(r13);
    r15 = (word64)(r15 + WC_L64(rbp, 0));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    rcx = (word64)(rcx & r12);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r9);
    r15 = (word64)(r15 + rax);
    rcx = (word64)(r8);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r8);
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r11 = (word64)(r11 + r15);
    rcx = (word64)(rcx ^ r8);
    r15 = (word64)(r15 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r11);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r15);
    rcx = (word64)(r12);
    r14 = (word64)(r14 + WC_L64(rbp, 8));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    rcx = (word64)(rcx & r11);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r8);
    r14 = (word64)(r14 + rax);
    rcx = (word64)(r15);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r15);
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r10 = (word64)(r10 + r14);
    rcx = (word64)(rcx ^ r15);
    r14 = (word64)(r14 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r10);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r14);
    rcx = (word64)(r11);
    r13 = (word64)(r13 + WC_L64(rbp, 32));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    rcx = (word64)(rcx & r10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r15);
    r13 = (word64)(r13 + rax);
    rcx = (word64)(r14);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r14);
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r9 = (word64)(r9 + r13);
    rcx = (word64)(rcx ^ r14);
    r13 = (word64)(r13 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r9);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r13);
    rcx = (word64)(r10);
    r12 = (word64)(r12 + WC_L64(rbp, 40));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    rcx = (word64)(rcx & r9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r14);
    r12 = (word64)(r12 + rax);
    rcx = (word64)(r13);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r13);
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r8 = (word64)(r8 + r12);
    rcx = (word64)(rcx ^ r13);
    r12 = (word64)(r12 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r8);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r12);
    rcx = (word64)(r9);
    r11 = (word64)(r11 + WC_L64(rbp, 64));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    rcx = (word64)(rcx & r8);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r13);
    r11 = (word64)(r11 + rax);
    rcx = (word64)(r12);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r12);
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r15 = (word64)(r15 + r11);
    rcx = (word64)(rcx ^ r12);
    r11 = (word64)(r11 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r15);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r11);
    rcx = (word64)(r8);
    r10 = (word64)(r10 + WC_L64(rbp, 72));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    rcx = (word64)(rcx & r15);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r12);
    r10 = (word64)(r10 + rax);
    rcx = (word64)(r11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r11);
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r14 = (word64)(r14 + r10);
    rcx = (word64)(rcx ^ r11);
    r10 = (word64)(r10 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r14);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r10);
    rcx = (word64)(r15);
    r9 = (word64)(r9 + WC_L64(rbp, 96));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    rcx = (word64)(rcx & r14);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r11);
    r9 = (word64)(r9 + rax);
    rcx = (word64)(r10);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r10);
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r13 = (word64)(r13 + r9);
    rcx = (word64)(rcx ^ r10);
    r9 = (word64)(r9 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r13);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r9);
    rcx = (word64)(r14);
    r8 = (word64)(r8 + WC_L64(rbp, 104));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    rcx = (word64)(rcx & r13);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r10);
    r8 = (word64)(r8 + rax);
    rcx = (word64)(r9);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r9);
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r12 = (word64)(r12 + r8);
    rcx = (word64)(rcx ^ r9);
    r8 = (word64)(r8 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r12);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r8);
    rcx = (word64)(r13);
    r15 = (word64)(r15 + WC_L64(rbp, 128));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    rcx = (word64)(rcx & r12);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r9);
    r15 = (word64)(r15 + rax);
    rcx = (word64)(r8);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r8);
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r11 = (word64)(r11 + r15);
    rcx = (word64)(rcx ^ r8);
    r15 = (word64)(r15 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r11);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r15);
    rcx = (word64)(r12);
    r14 = (word64)(r14 + WC_L64(rbp, 136));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    rcx = (word64)(rcx & r11);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r8);
    r14 = (word64)(r14 + rax);
    rcx = (word64)(r15);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r15);
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r10 = (word64)(r10 + r14);
    rcx = (word64)(rcx ^ r15);
    r14 = (word64)(r14 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r10);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r14);
    rcx = (word64)(r11);
    r13 = (word64)(r13 + WC_L64(rbp, 160));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    rcx = (word64)(rcx & r10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r15);
    r13 = (word64)(r13 + rax);
    rcx = (word64)(r14);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r14);
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r9 = (word64)(r9 + r13);
    rcx = (word64)(rcx ^ r14);
    r13 = (word64)(r13 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r9);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r13);
    rcx = (word64)(r10);
    r12 = (word64)(r12 + WC_L64(rbp, 168));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    rcx = (word64)(rcx & r9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r14);
    r12 = (word64)(r12 + rax);
    rcx = (word64)(r13);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r13);
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r8 = (word64)(r8 + r12);
    rcx = (word64)(rcx ^ r13);
    r12 = (word64)(r12 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r8);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r12);
    rcx = (word64)(r9);
    r11 = (word64)(r11 + WC_L64(rbp, 192));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    rcx = (word64)(rcx & r8);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r13);
    r11 = (word64)(r11 + rax);
    rcx = (word64)(r12);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r12);
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r15 = (word64)(r15 + r11);
    rcx = (word64)(rcx ^ r12);
    r11 = (word64)(r11 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r15);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r11);
    rcx = (word64)(r8);
    r10 = (word64)(r10 + WC_L64(rbp, 200));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    rcx = (word64)(rcx & r15);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r12);
    r10 = (word64)(r10 + rax);
    rcx = (word64)(r11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r11);
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r14 = (word64)(r14 + r10);
    rcx = (word64)(rcx ^ r11);
    r10 = (word64)(r10 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r14);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r10);
    rcx = (word64)(r15);
    r9 = (word64)(r9 + WC_L64(rbp, 224));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    rcx = (word64)(rcx & r14);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r11);
    r9 = (word64)(r9 + rax);
    rcx = (word64)(r10);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r10);
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r13 = (word64)(r13 + r9);
    rcx = (word64)(rcx ^ r10);
    r9 = (word64)(r9 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r13);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r9);
    rcx = (word64)(r14);
    r8 = (word64)(r8 + WC_L64(rbp, 232));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    rcx = (word64)(rcx & r13);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r10);
    r8 = (word64)(r8 + rax);
    rcx = (word64)(r9);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r9);
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r12 = (word64)(r12 + r8);
    rcx = (word64)(rcx ^ r9);
    r8 = (word64)(r8 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r12);
    r8 = (word64)(r8 + rcx);
    rbp = (word64)(rbp - 0x400);
    r8 = (word64)(r8 + WC_L64(rdi, 0));
    r9 = (word64)(r9 + WC_L64(rdi, 8));
    r10 = (word64)(r10 + WC_L64(rdi, 16));
    r11 = (word64)(r11 + WC_L64(rdi, 24));
    r12 = (word64)(r12 + WC_L64(rdi, 32));
    r13 = (word64)(r13 + WC_L64(rdi, 40));
    r14 = (word64)(r14 + WC_L64(rdi, 48));
    r15 = (word64)(r15 + WC_L64(rdi, 56));
    WC_S64(rdi, 0) = (word64)(r8);
    WC_S64(rdi, 8) = (word64)(r9);
    WC_S64(rdi, 16) = (word64)(r10);
    WC_S64(rdi, 24) = (word64)(r11);
    WC_S64(rdi, 32) = (word64)(r12);
    WC_S64(rdi, 40) = (word64)(r13);
    WC_S64(rdi, 48) = (word64)(r14);
    WC_S64(rdi, 56) = (word64)(r15);
    rbx = (word64)(r9);
    rax = (word64)(r12);
    rbx = (word64)(rbx ^ r10);
    rsi = (word64)(5);
L_sha512_len_avx2_tail:
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r8);
    rcx = (word64)(r13);
    r15 = (word64)(r15 + WC_L64(rbp, 16));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    rcx = (word64)(rcx & r12);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r9);
    r15 = (word64)(r15 + rax);
    rcx = (word64)(r8);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r8);
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r11 = (word64)(r11 + r15);
    rcx = (word64)(rcx ^ r8);
    r15 = (word64)(r15 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r11);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r15);
    rcx = (word64)(r12);
    r14 = (word64)(r14 + WC_L64(rbp, 24));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    rcx = (word64)(rcx & r11);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r8);
    r14 = (word64)(r14 + rax);
    rcx = (word64)(r15);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r15);
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r10 = (word64)(r10 + r14);
    rcx = (word64)(rcx ^ r15);
    r14 = (word64)(r14 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r10);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r14);
    rcx = (word64)(r11);
    r13 = (word64)(r13 + WC_L64(rbp, 48));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    rcx = (word64)(rcx & r10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r15);
    r13 = (word64)(r13 + rax);
    rcx = (word64)(r14);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r14);
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r9 = (word64)(r9 + r13);
    rcx = (word64)(rcx ^ r14);
    r13 = (word64)(r13 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r9);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r13);
    rcx = (word64)(r10);
    r12 = (word64)(r12 + WC_L64(rbp, 56));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    rcx = (word64)(rcx & r9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r14);
    r12 = (word64)(r12 + rax);
    rcx = (word64)(r13);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r13);
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r8 = (word64)(r8 + r12);
    rcx = (word64)(rcx ^ r13);
    r12 = (word64)(r12 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r8);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r12);
    rcx = (word64)(r9);
    r11 = (word64)(r11 + WC_L64(rbp, 80));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    rcx = (word64)(rcx & r8);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r13);
    r11 = (word64)(r11 + rax);
    rcx = (word64)(r12);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r12);
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r15 = (word64)(r15 + r11);
    rcx = (word64)(rcx ^ r12);
    r11 = (word64)(r11 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r15);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r11);
    rcx = (word64)(r8);
    r10 = (word64)(r10 + WC_L64(rbp, 88));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    rcx = (word64)(rcx & r15);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r12);
    r10 = (word64)(r10 + rax);
    rcx = (word64)(r11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r11);
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r14 = (word64)(r14 + r10);
    rcx = (word64)(rcx ^ r11);
    r10 = (word64)(r10 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r14);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r10);
    rcx = (word64)(r15);
    r9 = (word64)(r9 + WC_L64(rbp, 112));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    rcx = (word64)(rcx & r14);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r11);
    r9 = (word64)(r9 + rax);
    rcx = (word64)(r10);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r10);
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r13 = (word64)(r13 + r9);
    rcx = (word64)(rcx ^ r10);
    r9 = (word64)(r9 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r13);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r9);
    rcx = (word64)(r14);
    r8 = (word64)(r8 + WC_L64(rbp, 120));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    rcx = (word64)(rcx & r13);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r10);
    r8 = (word64)(r8 + rax);
    rcx = (word64)(r9);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r9);
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r12 = (word64)(r12 + r8);
    rcx = (word64)(rcx ^ r9);
    r8 = (word64)(r8 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r12);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r8);
    rcx = (word64)(r13);
    r15 = (word64)(r15 + WC_L64(rbp, 144));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    rcx = (word64)(rcx & r12);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r14);
    rax = (word64)(rax ^ r12);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r9);
    r15 = (word64)(r15 + rax);
    rcx = (word64)(r8);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r8);
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r11 = (word64)(r11 + r15);
    rcx = (word64)(rcx ^ r8);
    r15 = (word64)(r15 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r11);
    r15 = (word64)(r15 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r15);
    rcx = (word64)(r12);
    r14 = (word64)(r14 + WC_L64(rbp, 152));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    rcx = (word64)(rcx & r11);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r13);
    rax = (word64)(rax ^ r11);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r8);
    r14 = (word64)(r14 + rax);
    rcx = (word64)(r15);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r15);
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r10 = (word64)(r10 + r14);
    rcx = (word64)(rcx ^ r15);
    r14 = (word64)(r14 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r10);
    r14 = (word64)(r14 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r14);
    rcx = (word64)(r11);
    r13 = (word64)(r13 + WC_L64(rbp, 176));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    rcx = (word64)(rcx & r10);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r12);
    rax = (word64)(rax ^ r10);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r15);
    r13 = (word64)(r13 + rax);
    rcx = (word64)(r14);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r14);
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r9 = (word64)(r9 + r13);
    rcx = (word64)(rcx ^ r14);
    r13 = (word64)(r13 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r9);
    r13 = (word64)(r13 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r13);
    rcx = (word64)(r10);
    r12 = (word64)(r12 + WC_L64(rbp, 184));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    rcx = (word64)(rcx & r9);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r11);
    rax = (word64)(rax ^ r9);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r14);
    r12 = (word64)(r12 + rax);
    rcx = (word64)(r13);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r13);
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r8 = (word64)(r8 + r12);
    rcx = (word64)(rcx ^ r13);
    r12 = (word64)(r12 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r8);
    r12 = (word64)(r12 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r12);
    rcx = (word64)(r9);
    r11 = (word64)(r11 + WC_L64(rbp, 208));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    rcx = (word64)(rcx & r8);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r10);
    rax = (word64)(rax ^ r8);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r13);
    r11 = (word64)(r11 + rax);
    rcx = (word64)(r12);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r12);
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r15 = (word64)(r15 + r11);
    rcx = (word64)(rcx ^ r12);
    r11 = (word64)(r11 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r15);
    r11 = (word64)(r11 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r11);
    rcx = (word64)(r8);
    r10 = (word64)(r10 + WC_L64(rbp, 216));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    rcx = (word64)(rcx & r15);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r9);
    rax = (word64)(rax ^ r15);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r12);
    r10 = (word64)(r10 + rax);
    rcx = (word64)(r11);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r11);
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r14 = (word64)(r14 + r10);
    rcx = (word64)(rcx ^ r11);
    r10 = (word64)(r10 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r14);
    r10 = (word64)(r10 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rdx = (word64)(r10);
    rcx = (word64)(r15);
    r9 = (word64)(r9 + WC_L64(rbp, 240));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    rcx = (word64)(rcx & r14);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r8);
    rax = (word64)(rax ^ r14);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rdx = (word64)(rdx ^ r11);
    r9 = (word64)(r9 + rax);
    rcx = (word64)(r10);
    rbx = (word64)(rbx & rdx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r10);
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r13 = (word64)(r13 + r9);
    rcx = (word64)(rcx ^ r10);
    r9 = (word64)(r9 + rbx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r13);
    r9 = (word64)(r9 + rcx);
    rax = (word64)(((rax) >> 23) | ((rax) << 41));
    rbx = (word64)(r9);
    rcx = (word64)(r14);
    r8 = (word64)(r8 + WC_L64(rbp, 248));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    rcx = (word64)(rcx & r13);
    rax = (word64)(((rax) >> 4) | ((rax) << 60));
    rcx = (word64)(rcx ^ r15);
    rax = (word64)(rax ^ r13);
    r8 = (word64)(r8 + rcx);
    rax = (word64)(((rax) >> 14) | ((rax) << 50));
    rbx = (word64)(rbx ^ r10);
    r8 = (word64)(r8 + rax);
    rcx = (word64)(r9);
    rdx = (word64)(rdx & rbx);
    rcx = (word64)(((rcx) >> 5) | ((rcx) << 59));
    rcx = (word64)(rcx ^ r9);
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(((rcx) >> 6) | ((rcx) << 58));
    r12 = (word64)(r12 + r8);
    rcx = (word64)(rcx ^ r9);
    r8 = (word64)(r8 + rdx);
    rcx = (word64)(((rcx) >> 28) | ((rcx) << 36));
    rax = (word64)(r12);
    r8 = (word64)(r8 + rcx);
    rbp = (word64)(rbp + 0x100);
    rsi = (word64)(rsi - 1);
    if ((rsi) != (0)) {
        goto L_sha512_len_avx2_tail;
    }
    r8 = (word64)(r8 + WC_L64(rdi, 0));
    r9 = (word64)(r9 + WC_L64(rdi, 8));
    r10 = (word64)(r10 + WC_L64(rdi, 16));
    r11 = (word64)(r11 + WC_L64(rdi, 24));
    r12 = (word64)(r12 + WC_L64(rdi, 32));
    r13 = (word64)(r13 + WC_L64(rdi, 40));
    r14 = (word64)(r14 + WC_L64(rdi, 48));
    r15 = (word64)(r15 + WC_L64(rdi, 56));
    rcx = (word64)(WC_L64(rdi, 224));
    rcx = (word64)(rcx + 0x100);
    WC_S32(rsp, 1344) = (word32)(WC_L32(rsp, 1344) - 0x100);
    zf1 = (word32)WC_S32(rsp, 1344);
    WC_S64(rdi, 224) = (word64)(rcx);
    WC_S64(rdi, 0) = (word64)(r8);
    WC_S64(rdi, 8) = (word64)(r9);
    WC_S64(rdi, 16) = (word64)(r10);
    WC_S64(rdi, 24) = (word64)(r11);
    WC_S64(rdi, 32) = (word64)(r12);
    WC_S64(rdi, 40) = (word64)(r13);
    WC_S64(rdi, 48) = (word64)(r14);
    WC_S64(rdi, 56) = (word64)(r15);
    if ((zf1) != (0)) {
        goto L_sha512_len_avx2_begin;
    }
    rsp = (word64)(rsp + 1352);
L_sha512_len_avx2_done:
    rax = (word64)(0);
    return (int)(word32)rax;
}

XALIGNED(32) static const word64 L_avx2_rorx_sha512_k[] WC_X64I_UNUSED = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

XALIGNED(32) static const word64 L_avx2_rorx_sha512_k_2[] WC_X64I_UNUSED = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

XALIGNED(16) static const word64 L_avx2_rorx_sha512_k_2_end[] WC_X64I_UNUSED = {
    (word64)(size_t)(L_avx2_rorx_sha512_k_2 + 128),
};

XALIGNED(32) static const word64 L_avx2_rorx_sha512_flip_mask[]
    WC_X64I_UNUSED = {
    0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL,
    0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL,
};

WC_X64I_TARGET("avx2,bmi2")
WOLFSSL_LOCAL int Transform_Sha512_AVX2_RORX(wc_Sha512* sha512)
{
    word64 rdi, rsp, rcx, r8, r9, r10, r11, r12, r13, r14, r15, rsi, rbx, rdx,
           rax = 0;
    __m256i y0, y1, y2, y3, y8, y9, y10 = _mm256_setzero_si256(),
            y11 = _mm256_setzero_si256(), y12 = _mm256_setzero_si256(),
            y13 = _mm256_setzero_si256(), y14 = _mm256_setzero_si256(), y15;
    XALIGNED(32) WC_X64I_SLOT stk[20];

    rdi = (word64)(size_t)sha512;

    rsp = (word64)(size_t)stk + 160;
    rsp = (word64)(rsp - 136);
    rcx = (word64)(rdi + 64);
    y15 = _mm256_loadu_si256((const __m256i*)WC_PR(L_avx2_rorx_sha512_flip_mask,
        0));
    r8 = (word64)(WC_L64(rdi, 0));
    r9 = (word64)(WC_L64(rdi, 8));
    r10 = (word64)(WC_L64(rdi, 16));
    r11 = (word64)(WC_L64(rdi, 24));
    r12 = (word64)(WC_L64(rdi, 32));
    r13 = (word64)(WC_L64(rdi, 40));
    r14 = (word64)(WC_L64(rdi, 48));
    r15 = (word64)(WC_L64(rdi, 56));
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 32));
    y0 = _mm256_shuffle_epi8(y0, y15);
    y1 = _mm256_shuffle_epi8(y1, y15);
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 64));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 96));
    y2 = _mm256_shuffle_epi8(y2, y15);
    y3 = _mm256_shuffle_epi8(y3, y15);
    WC_S32(rsp, 128) = (word32)(4);
    rsi = (word64)((word64)(size_t)L_avx2_rorx_sha512_k);
    rbx = (word64)(r9);
    rdx = (word64)(0);
    rbx = (word64)(rbx ^ r10);
    /* set_w_k: 0 */
    y8 = _mm256_add_epi64(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        0)));
    y9 = _mm256_add_epi64(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        32)));
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 0), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 32), y9);
    y8 = _mm256_add_epi64(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        64)));
    y9 = _mm256_add_epi64(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        96)));
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 64), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 96), y9);
    /* Start of 16 rounds */
L_sha256_len_avx2_rorx_start:
    rsi = (word64)(rsi + 0x80);
    rax = (word64)(((r12) >> 14) | ((r12) << 50));
    rcx = (word64)(((r12) >> 18) | ((r12) << 46));
    r8 = (word64)(r8 + rdx);
    y12 = _mm256_blend_epi32(y0, y1, 3);
    y13 = _mm256_blend_epi32(y2, y3, 3);
    r15 = (word64)(r15 + WC_L64(rsp, 0));
    rdx = (word64)(r13);
    rcx = (word64)(rcx ^ rax);
    y12 = _mm256_permute4x64_epi64(y12, 0x39);
    rdx = (word64)(rdx ^ r14);
    rax = (word64)(((r12) >> 41) | ((r12) << 23));
    rax = (word64)(rax ^ rcx);
    y13 = _mm256_permute4x64_epi64(y13, 0x39);
    rdx = (word64)(rdx & r12);
    r15 = (word64)(r15 + rax);
    rax = (word64)(((r8) >> 28) | ((r8) << 36));
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rcx = (word64)(((r8) >> 34) | ((r8) << 30));
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(rcx ^ rax);
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(((r8) >> 39) | ((r8) << 25));
    r15 = (word64)(r15 + rdx);
    rax = (word64)(rax ^ rcx);
    y11 = _mm256_srli_epi64(y12, 7);
    rdx = (word64)(r9);
    r11 = (word64)(r11 + r15);
    rdx = (word64)(rdx ^ r8);
    y14 = _mm256_permute2x128_si256(y3, y3, 0x81);
    rbx = (word64)(rbx & rdx);
    r15 = (word64)(r15 + rax);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r11) >> 14) | ((r11) << 50));
    rcx = (word64)(((r11) >> 18) | ((r11) << 46));
    r15 = (word64)(r15 + rbx);
    y8 = _mm256_xor_si256(y8, y10);
    r14 = (word64)(r14 + WC_L64(rsp, 8));
    rbx = (word64)(r12);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_xor_si256(y8, y11);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r11) >> 41) | ((r11) << 23));
    rax = (word64)(rax ^ rcx);
    y0 = _mm256_add_epi64(y13, y0);
    y0 = _mm256_add_epi64(y8, y0);
    rbx = (word64)(rbx & r11);
    r14 = (word64)(r14 + rax);
    rax = (word64)(((r15) >> 28) | ((r15) << 36));
    y8 = _mm256_srli_epi64(y14, 19);
    y9 = _mm256_slli_epi64(y14, 45);
    rcx = (word64)(((r15) >> 34) | ((r15) << 30));
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(rcx ^ rax);
    y10 = _mm256_srli_epi64(y14, 61);
    y11 = _mm256_slli_epi64(y14, 3);
    y8 = _mm256_or_si256(y8, y9);
    rax = (word64)(((r15) >> 39) | ((r15) << 25));
    r14 = (word64)(r14 + rbx);
    rax = (word64)(rax ^ rcx);
    y10 = _mm256_or_si256(y10, y11);
    rbx = (word64)(r8);
    r10 = (word64)(r10 + r14);
    rbx = (word64)(rbx ^ r15);
    y8 = _mm256_xor_si256(y8, y10);
    rdx = (word64)(rdx & rbx);
    r14 = (word64)(r14 + rax);
    rdx = (word64)(rdx ^ r8);
    y11 = _mm256_srli_epi64(y14, 6);
    rax = (word64)(((r10) >> 14) | ((r10) << 50));
    rcx = (word64)(((r10) >> 18) | ((r10) << 46));
    r14 = (word64)(r14 + rdx);
    y8 = _mm256_xor_si256(y8, y11);
    r13 = (word64)(r13 + WC_L64(rsp, 16));
    rdx = (word64)(r11);
    rcx = (word64)(rcx ^ rax);
    y0 = _mm256_add_epi64(y8, y0);
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r10) >> 41) | ((r10) << 23));
    rax = (word64)(rax ^ rcx);
    y14 = _mm256_permute2x128_si256(y0, y0, 8);
    rdx = (word64)(rdx & r10);
    r13 = (word64)(r13 + rax);
    rax = (word64)(((r14) >> 28) | ((r14) << 36));
    rcx = (word64)(((r14) >> 34) | ((r14) << 30));
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_srli_epi64(y14, 19);
    y9 = _mm256_slli_epi64(y14, 45);
    rax = (word64)(((r14) >> 39) | ((r14) << 25));
    r13 = (word64)(r13 + rdx);
    rax = (word64)(rax ^ rcx);
    y10 = _mm256_srli_epi64(y14, 61);
    y11 = _mm256_slli_epi64(y14, 3);
    y8 = _mm256_or_si256(y8, y9);
    rdx = (word64)(r15);
    r9 = (word64)(r9 + r13);
    rdx = (word64)(rdx ^ r14);
    y10 = _mm256_or_si256(y10, y11);
    rbx = (word64)(rbx & rdx);
    r13 = (word64)(r13 + rax);
    rbx = (word64)(rbx ^ r15);
    y8 = _mm256_xor_si256(y8, y10);
    rax = (word64)(((r9) >> 14) | ((r9) << 50));
    rcx = (word64)(((r9) >> 18) | ((r9) << 46));
    r13 = (word64)(r13 + rbx);
    y11 = _mm256_srli_epi64(y14, 6);
    r12 = (word64)(r12 + WC_L64(rsp, 24));
    rbx = (word64)(r10);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r9) >> 41) | ((r9) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_xor_si256(y8, y11);
    rbx = (word64)(rbx & r9);
    r12 = (word64)(r12 + rax);
    rax = (word64)(((r13) >> 28) | ((r13) << 36));
    rcx = (word64)(((r13) >> 34) | ((r13) << 30));
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(rcx ^ rax);
    y0 = _mm256_add_epi64(y8, y0);
    rax = (word64)(((r13) >> 39) | ((r13) << 25));
    r12 = (word64)(r12 + rbx);
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_add_epi64(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        0)));
    rbx = (word64)(r14);
    r8 = (word64)(r8 + r12);
    rbx = (word64)(rbx ^ r13);
    rdx = (word64)(rdx & rbx);
    r12 = (word64)(r12 + rax);
    rdx = (word64)(rdx ^ r14);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 0), y8);
    rax = (word64)(((r8) >> 14) | ((r8) << 50));
    rcx = (word64)(((r8) >> 18) | ((r8) << 46));
    r12 = (word64)(r12 + rdx);
    y12 = _mm256_blend_epi32(y1, y2, 3);
    y13 = _mm256_blend_epi32(y3, y0, 3);
    r11 = (word64)(r11 + WC_L64(rsp, 32));
    rdx = (word64)(r9);
    rcx = (word64)(rcx ^ rax);
    y12 = _mm256_permute4x64_epi64(y12, 0x39);
    rdx = (word64)(rdx ^ r10);
    rax = (word64)(((r8) >> 41) | ((r8) << 23));
    rax = (word64)(rax ^ rcx);
    y13 = _mm256_permute4x64_epi64(y13, 0x39);
    rdx = (word64)(rdx & r8);
    r11 = (word64)(r11 + rax);
    rax = (word64)(((r12) >> 28) | ((r12) << 36));
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rcx = (word64)(((r12) >> 34) | ((r12) << 30));
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(rcx ^ rax);
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(((r12) >> 39) | ((r12) << 25));
    r11 = (word64)(r11 + rdx);
    rax = (word64)(rax ^ rcx);
    y11 = _mm256_srli_epi64(y12, 7);
    rdx = (word64)(r13);
    r15 = (word64)(r15 + r11);
    rdx = (word64)(rdx ^ r12);
    y14 = _mm256_permute2x128_si256(y0, y0, 0x81);
    rbx = (word64)(rbx & rdx);
    r11 = (word64)(r11 + rax);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r15) >> 14) | ((r15) << 50));
    rcx = (word64)(((r15) >> 18) | ((r15) << 46));
    r11 = (word64)(r11 + rbx);
    y8 = _mm256_xor_si256(y8, y10);
    r10 = (word64)(r10 + WC_L64(rsp, 40));
    rbx = (word64)(r8);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_xor_si256(y8, y11);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r15) >> 41) | ((r15) << 23));
    rax = (word64)(rax ^ rcx);
    y1 = _mm256_add_epi64(y13, y1);
    y1 = _mm256_add_epi64(y8, y1);
    rbx = (word64)(rbx & r15);
    r10 = (word64)(r10 + rax);
    rax = (word64)(((r11) >> 28) | ((r11) << 36));
    y8 = _mm256_srli_epi64(y14, 19);
    y9 = _mm256_slli_epi64(y14, 45);
    rcx = (word64)(((r11) >> 34) | ((r11) << 30));
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(rcx ^ rax);
    y10 = _mm256_srli_epi64(y14, 61);
    y11 = _mm256_slli_epi64(y14, 3);
    y8 = _mm256_or_si256(y8, y9);
    rax = (word64)(((r11) >> 39) | ((r11) << 25));
    r10 = (word64)(r10 + rbx);
    rax = (word64)(rax ^ rcx);
    y10 = _mm256_or_si256(y10, y11);
    rbx = (word64)(r12);
    r14 = (word64)(r14 + r10);
    rbx = (word64)(rbx ^ r11);
    y8 = _mm256_xor_si256(y8, y10);
    rdx = (word64)(rdx & rbx);
    r10 = (word64)(r10 + rax);
    rdx = (word64)(rdx ^ r12);
    y11 = _mm256_srli_epi64(y14, 6);
    rax = (word64)(((r14) >> 14) | ((r14) << 50));
    rcx = (word64)(((r14) >> 18) | ((r14) << 46));
    r10 = (word64)(r10 + rdx);
    y8 = _mm256_xor_si256(y8, y11);
    r9 = (word64)(r9 + WC_L64(rsp, 48));
    rdx = (word64)(r15);
    rcx = (word64)(rcx ^ rax);
    y1 = _mm256_add_epi64(y8, y1);
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r14) >> 41) | ((r14) << 23));
    rax = (word64)(rax ^ rcx);
    y14 = _mm256_permute2x128_si256(y1, y1, 8);
    rdx = (word64)(rdx & r14);
    r9 = (word64)(r9 + rax);
    rax = (word64)(((r10) >> 28) | ((r10) << 36));
    rcx = (word64)(((r10) >> 34) | ((r10) << 30));
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_srli_epi64(y14, 19);
    y9 = _mm256_slli_epi64(y14, 45);
    rax = (word64)(((r10) >> 39) | ((r10) << 25));
    r9 = (word64)(r9 + rdx);
    rax = (word64)(rax ^ rcx);
    y10 = _mm256_srli_epi64(y14, 61);
    y11 = _mm256_slli_epi64(y14, 3);
    y8 = _mm256_or_si256(y8, y9);
    rdx = (word64)(r11);
    r13 = (word64)(r13 + r9);
    rdx = (word64)(rdx ^ r10);
    y10 = _mm256_or_si256(y10, y11);
    rbx = (word64)(rbx & rdx);
    r9 = (word64)(r9 + rax);
    rbx = (word64)(rbx ^ r11);
    y8 = _mm256_xor_si256(y8, y10);
    rax = (word64)(((r13) >> 14) | ((r13) << 50));
    rcx = (word64)(((r13) >> 18) | ((r13) << 46));
    r9 = (word64)(r9 + rbx);
    y11 = _mm256_srli_epi64(y14, 6);
    r8 = (word64)(r8 + WC_L64(rsp, 56));
    rbx = (word64)(r14);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r13) >> 41) | ((r13) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_xor_si256(y8, y11);
    rbx = (word64)(rbx & r13);
    r8 = (word64)(r8 + rax);
    rax = (word64)(((r9) >> 28) | ((r9) << 36));
    rcx = (word64)(((r9) >> 34) | ((r9) << 30));
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(rcx ^ rax);
    y1 = _mm256_add_epi64(y8, y1);
    rax = (word64)(((r9) >> 39) | ((r9) << 25));
    r8 = (word64)(r8 + rbx);
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_add_epi64(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        32)));
    rbx = (word64)(r10);
    r12 = (word64)(r12 + r8);
    rbx = (word64)(rbx ^ r9);
    rdx = (word64)(rdx & rbx);
    r8 = (word64)(r8 + rax);
    rdx = (word64)(rdx ^ r10);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 32), y8);
    rax = (word64)(((r12) >> 14) | ((r12) << 50));
    rcx = (word64)(((r12) >> 18) | ((r12) << 46));
    r8 = (word64)(r8 + rdx);
    y12 = _mm256_blend_epi32(y2, y3, 3);
    y13 = _mm256_blend_epi32(y0, y1, 3);
    r15 = (word64)(r15 + WC_L64(rsp, 64));
    rdx = (word64)(r13);
    rcx = (word64)(rcx ^ rax);
    y12 = _mm256_permute4x64_epi64(y12, 0x39);
    rdx = (word64)(rdx ^ r14);
    rax = (word64)(((r12) >> 41) | ((r12) << 23));
    rax = (word64)(rax ^ rcx);
    y13 = _mm256_permute4x64_epi64(y13, 0x39);
    rdx = (word64)(rdx & r12);
    r15 = (word64)(r15 + rax);
    rax = (word64)(((r8) >> 28) | ((r8) << 36));
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rcx = (word64)(((r8) >> 34) | ((r8) << 30));
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(rcx ^ rax);
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(((r8) >> 39) | ((r8) << 25));
    r15 = (word64)(r15 + rdx);
    rax = (word64)(rax ^ rcx);
    y11 = _mm256_srli_epi64(y12, 7);
    rdx = (word64)(r9);
    r11 = (word64)(r11 + r15);
    rdx = (word64)(rdx ^ r8);
    y14 = _mm256_permute2x128_si256(y1, y1, 0x81);
    rbx = (word64)(rbx & rdx);
    r15 = (word64)(r15 + rax);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r11) >> 14) | ((r11) << 50));
    rcx = (word64)(((r11) >> 18) | ((r11) << 46));
    r15 = (word64)(r15 + rbx);
    y8 = _mm256_xor_si256(y8, y10);
    r14 = (word64)(r14 + WC_L64(rsp, 72));
    rbx = (word64)(r12);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_xor_si256(y8, y11);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r11) >> 41) | ((r11) << 23));
    rax = (word64)(rax ^ rcx);
    y2 = _mm256_add_epi64(y13, y2);
    y2 = _mm256_add_epi64(y8, y2);
    rbx = (word64)(rbx & r11);
    r14 = (word64)(r14 + rax);
    rax = (word64)(((r15) >> 28) | ((r15) << 36));
    y8 = _mm256_srli_epi64(y14, 19);
    y9 = _mm256_slli_epi64(y14, 45);
    rcx = (word64)(((r15) >> 34) | ((r15) << 30));
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(rcx ^ rax);
    y10 = _mm256_srli_epi64(y14, 61);
    y11 = _mm256_slli_epi64(y14, 3);
    y8 = _mm256_or_si256(y8, y9);
    rax = (word64)(((r15) >> 39) | ((r15) << 25));
    r14 = (word64)(r14 + rbx);
    rax = (word64)(rax ^ rcx);
    y10 = _mm256_or_si256(y10, y11);
    rbx = (word64)(r8);
    r10 = (word64)(r10 + r14);
    rbx = (word64)(rbx ^ r15);
    y8 = _mm256_xor_si256(y8, y10);
    rdx = (word64)(rdx & rbx);
    r14 = (word64)(r14 + rax);
    rdx = (word64)(rdx ^ r8);
    y11 = _mm256_srli_epi64(y14, 6);
    rax = (word64)(((r10) >> 14) | ((r10) << 50));
    rcx = (word64)(((r10) >> 18) | ((r10) << 46));
    r14 = (word64)(r14 + rdx);
    y8 = _mm256_xor_si256(y8, y11);
    r13 = (word64)(r13 + WC_L64(rsp, 80));
    rdx = (word64)(r11);
    rcx = (word64)(rcx ^ rax);
    y2 = _mm256_add_epi64(y8, y2);
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r10) >> 41) | ((r10) << 23));
    rax = (word64)(rax ^ rcx);
    y14 = _mm256_permute2x128_si256(y2, y2, 8);
    rdx = (word64)(rdx & r10);
    r13 = (word64)(r13 + rax);
    rax = (word64)(((r14) >> 28) | ((r14) << 36));
    rcx = (word64)(((r14) >> 34) | ((r14) << 30));
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_srli_epi64(y14, 19);
    y9 = _mm256_slli_epi64(y14, 45);
    rax = (word64)(((r14) >> 39) | ((r14) << 25));
    r13 = (word64)(r13 + rdx);
    rax = (word64)(rax ^ rcx);
    y10 = _mm256_srli_epi64(y14, 61);
    y11 = _mm256_slli_epi64(y14, 3);
    y8 = _mm256_or_si256(y8, y9);
    rdx = (word64)(r15);
    r9 = (word64)(r9 + r13);
    rdx = (word64)(rdx ^ r14);
    y10 = _mm256_or_si256(y10, y11);
    rbx = (word64)(rbx & rdx);
    r13 = (word64)(r13 + rax);
    rbx = (word64)(rbx ^ r15);
    y8 = _mm256_xor_si256(y8, y10);
    rax = (word64)(((r9) >> 14) | ((r9) << 50));
    rcx = (word64)(((r9) >> 18) | ((r9) << 46));
    r13 = (word64)(r13 + rbx);
    y11 = _mm256_srli_epi64(y14, 6);
    r12 = (word64)(r12 + WC_L64(rsp, 88));
    rbx = (word64)(r10);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r9) >> 41) | ((r9) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_xor_si256(y8, y11);
    rbx = (word64)(rbx & r9);
    r12 = (word64)(r12 + rax);
    rax = (word64)(((r13) >> 28) | ((r13) << 36));
    rcx = (word64)(((r13) >> 34) | ((r13) << 30));
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(rcx ^ rax);
    y2 = _mm256_add_epi64(y8, y2);
    rax = (word64)(((r13) >> 39) | ((r13) << 25));
    r12 = (word64)(r12 + rbx);
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_add_epi64(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        64)));
    rbx = (word64)(r14);
    r8 = (word64)(r8 + r12);
    rbx = (word64)(rbx ^ r13);
    rdx = (word64)(rdx & rbx);
    r12 = (word64)(r12 + rax);
    rdx = (word64)(rdx ^ r14);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 64), y8);
    rax = (word64)(((r8) >> 14) | ((r8) << 50));
    rcx = (word64)(((r8) >> 18) | ((r8) << 46));
    r12 = (word64)(r12 + rdx);
    y12 = _mm256_blend_epi32(y3, y0, 3);
    y13 = _mm256_blend_epi32(y1, y2, 3);
    r11 = (word64)(r11 + WC_L64(rsp, 96));
    rdx = (word64)(r9);
    rcx = (word64)(rcx ^ rax);
    y12 = _mm256_permute4x64_epi64(y12, 0x39);
    rdx = (word64)(rdx ^ r10);
    rax = (word64)(((r8) >> 41) | ((r8) << 23));
    rax = (word64)(rax ^ rcx);
    y13 = _mm256_permute4x64_epi64(y13, 0x39);
    rdx = (word64)(rdx & r8);
    r11 = (word64)(r11 + rax);
    rax = (word64)(((r12) >> 28) | ((r12) << 36));
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rcx = (word64)(((r12) >> 34) | ((r12) << 30));
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(rcx ^ rax);
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(((r12) >> 39) | ((r12) << 25));
    r11 = (word64)(r11 + rdx);
    rax = (word64)(rax ^ rcx);
    y11 = _mm256_srli_epi64(y12, 7);
    rdx = (word64)(r13);
    r15 = (word64)(r15 + r11);
    rdx = (word64)(rdx ^ r12);
    y14 = _mm256_permute2x128_si256(y2, y2, 0x81);
    rbx = (word64)(rbx & rdx);
    r11 = (word64)(r11 + rax);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r15) >> 14) | ((r15) << 50));
    rcx = (word64)(((r15) >> 18) | ((r15) << 46));
    r11 = (word64)(r11 + rbx);
    y8 = _mm256_xor_si256(y8, y10);
    r10 = (word64)(r10 + WC_L64(rsp, 104));
    rbx = (word64)(r8);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_xor_si256(y8, y11);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r15) >> 41) | ((r15) << 23));
    rax = (word64)(rax ^ rcx);
    y3 = _mm256_add_epi64(y13, y3);
    y3 = _mm256_add_epi64(y8, y3);
    rbx = (word64)(rbx & r15);
    r10 = (word64)(r10 + rax);
    rax = (word64)(((r11) >> 28) | ((r11) << 36));
    y8 = _mm256_srli_epi64(y14, 19);
    y9 = _mm256_slli_epi64(y14, 45);
    rcx = (word64)(((r11) >> 34) | ((r11) << 30));
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(rcx ^ rax);
    y10 = _mm256_srli_epi64(y14, 61);
    y11 = _mm256_slli_epi64(y14, 3);
    y8 = _mm256_or_si256(y8, y9);
    rax = (word64)(((r11) >> 39) | ((r11) << 25));
    r10 = (word64)(r10 + rbx);
    rax = (word64)(rax ^ rcx);
    y10 = _mm256_or_si256(y10, y11);
    rbx = (word64)(r12);
    r14 = (word64)(r14 + r10);
    rbx = (word64)(rbx ^ r11);
    y8 = _mm256_xor_si256(y8, y10);
    rdx = (word64)(rdx & rbx);
    r10 = (word64)(r10 + rax);
    rdx = (word64)(rdx ^ r12);
    y11 = _mm256_srli_epi64(y14, 6);
    rax = (word64)(((r14) >> 14) | ((r14) << 50));
    rcx = (word64)(((r14) >> 18) | ((r14) << 46));
    r10 = (word64)(r10 + rdx);
    y8 = _mm256_xor_si256(y8, y11);
    r9 = (word64)(r9 + WC_L64(rsp, 112));
    rdx = (word64)(r15);
    rcx = (word64)(rcx ^ rax);
    y3 = _mm256_add_epi64(y8, y3);
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r14) >> 41) | ((r14) << 23));
    rax = (word64)(rax ^ rcx);
    y14 = _mm256_permute2x128_si256(y3, y3, 8);
    rdx = (word64)(rdx & r14);
    r9 = (word64)(r9 + rax);
    rax = (word64)(((r10) >> 28) | ((r10) << 36));
    rcx = (word64)(((r10) >> 34) | ((r10) << 30));
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_srli_epi64(y14, 19);
    y9 = _mm256_slli_epi64(y14, 45);
    rax = (word64)(((r10) >> 39) | ((r10) << 25));
    r9 = (word64)(r9 + rdx);
    rax = (word64)(rax ^ rcx);
    y10 = _mm256_srli_epi64(y14, 61);
    y11 = _mm256_slli_epi64(y14, 3);
    y8 = _mm256_or_si256(y8, y9);
    rdx = (word64)(r11);
    r13 = (word64)(r13 + r9);
    rdx = (word64)(rdx ^ r10);
    y10 = _mm256_or_si256(y10, y11);
    rbx = (word64)(rbx & rdx);
    r9 = (word64)(r9 + rax);
    rbx = (word64)(rbx ^ r11);
    y8 = _mm256_xor_si256(y8, y10);
    rax = (word64)(((r13) >> 14) | ((r13) << 50));
    rcx = (word64)(((r13) >> 18) | ((r13) << 46));
    r9 = (word64)(r9 + rbx);
    y11 = _mm256_srli_epi64(y14, 6);
    r8 = (word64)(r8 + WC_L64(rsp, 120));
    rbx = (word64)(r14);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r13) >> 41) | ((r13) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_xor_si256(y8, y11);
    rbx = (word64)(rbx & r13);
    r8 = (word64)(r8 + rax);
    rax = (word64)(((r9) >> 28) | ((r9) << 36));
    rcx = (word64)(((r9) >> 34) | ((r9) << 30));
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(rcx ^ rax);
    y3 = _mm256_add_epi64(y8, y3);
    rax = (word64)(((r9) >> 39) | ((r9) << 25));
    r8 = (word64)(r8 + rbx);
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_add_epi64(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rsi,
        96)));
    rbx = (word64)(r10);
    r12 = (word64)(r12 + r8);
    rbx = (word64)(rbx ^ r9);
    rdx = (word64)(rdx & rbx);
    r8 = (word64)(r8 + rax);
    rdx = (word64)(rdx ^ r10);
    _mm256_storeu_si256((__m256i*)WC_PW(rsp, 96), y8);
    WC_S32(rsp, 128) = (word32)(WC_L32(rsp, 128) - 1);
    if (((word32)WC_S32(rsp, 128)) != (0)) {
        goto L_sha256_len_avx2_rorx_start;
    }
    /* rnd_all_4: 0-3 */
    rax = (word64)(((r12) >> 14) | ((r12) << 50));
    rcx = (word64)(((r12) >> 18) | ((r12) << 46));
    r8 = (word64)(r8 + rdx);
    r15 = (word64)(r15 + WC_L64(rsp, 0));
    rdx = (word64)(r13);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r14);
    rax = (word64)(((r12) >> 41) | ((r12) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r12);
    r15 = (word64)(r15 + rax);
    rax = (word64)(((r8) >> 28) | ((r8) << 36));
    rcx = (word64)(((r8) >> 34) | ((r8) << 30));
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r8) >> 39) | ((r8) << 25));
    r15 = (word64)(r15 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r9);
    r11 = (word64)(r11 + r15);
    rdx = (word64)(rdx ^ r8);
    rbx = (word64)(rbx & rdx);
    r15 = (word64)(r15 + rax);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r11) >> 14) | ((r11) << 50));
    rcx = (word64)(((r11) >> 18) | ((r11) << 46));
    r15 = (word64)(r15 + rbx);
    r14 = (word64)(r14 + WC_L64(rsp, 8));
    rbx = (word64)(r12);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r11) >> 41) | ((r11) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r11);
    r14 = (word64)(r14 + rax);
    rax = (word64)(((r15) >> 28) | ((r15) << 36));
    rcx = (word64)(((r15) >> 34) | ((r15) << 30));
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r15) >> 39) | ((r15) << 25));
    r14 = (word64)(r14 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r8);
    r10 = (word64)(r10 + r14);
    rbx = (word64)(rbx ^ r15);
    rdx = (word64)(rdx & rbx);
    r14 = (word64)(r14 + rax);
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r10) >> 14) | ((r10) << 50));
    rcx = (word64)(((r10) >> 18) | ((r10) << 46));
    r14 = (word64)(r14 + rdx);
    r13 = (word64)(r13 + WC_L64(rsp, 16));
    rdx = (word64)(r11);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r10) >> 41) | ((r10) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r10);
    r13 = (word64)(r13 + rax);
    rax = (word64)(((r14) >> 28) | ((r14) << 36));
    rcx = (word64)(((r14) >> 34) | ((r14) << 30));
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r14) >> 39) | ((r14) << 25));
    r13 = (word64)(r13 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r15);
    r9 = (word64)(r9 + r13);
    rdx = (word64)(rdx ^ r14);
    rbx = (word64)(rbx & rdx);
    r13 = (word64)(r13 + rax);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r9) >> 14) | ((r9) << 50));
    rcx = (word64)(((r9) >> 18) | ((r9) << 46));
    r13 = (word64)(r13 + rbx);
    r12 = (word64)(r12 + WC_L64(rsp, 24));
    rbx = (word64)(r10);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r9) >> 41) | ((r9) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r9);
    r12 = (word64)(r12 + rax);
    rax = (word64)(((r13) >> 28) | ((r13) << 36));
    rcx = (word64)(((r13) >> 34) | ((r13) << 30));
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r13) >> 39) | ((r13) << 25));
    r12 = (word64)(r12 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r14);
    r8 = (word64)(r8 + r12);
    rbx = (word64)(rbx ^ r13);
    rdx = (word64)(rdx & rbx);
    r12 = (word64)(r12 + rax);
    rdx = (word64)(rdx ^ r14);
    /* rnd_all_4: 4-7 */
    rax = (word64)(((r8) >> 14) | ((r8) << 50));
    rcx = (word64)(((r8) >> 18) | ((r8) << 46));
    r12 = (word64)(r12 + rdx);
    r11 = (word64)(r11 + WC_L64(rsp, 32));
    rdx = (word64)(r9);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r10);
    rax = (word64)(((r8) >> 41) | ((r8) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r8);
    r11 = (word64)(r11 + rax);
    rax = (word64)(((r12) >> 28) | ((r12) << 36));
    rcx = (word64)(((r12) >> 34) | ((r12) << 30));
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r12) >> 39) | ((r12) << 25));
    r11 = (word64)(r11 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r13);
    r15 = (word64)(r15 + r11);
    rdx = (word64)(rdx ^ r12);
    rbx = (word64)(rbx & rdx);
    r11 = (word64)(r11 + rax);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r15) >> 14) | ((r15) << 50));
    rcx = (word64)(((r15) >> 18) | ((r15) << 46));
    r11 = (word64)(r11 + rbx);
    r10 = (word64)(r10 + WC_L64(rsp, 40));
    rbx = (word64)(r8);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r15) >> 41) | ((r15) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r15);
    r10 = (word64)(r10 + rax);
    rax = (word64)(((r11) >> 28) | ((r11) << 36));
    rcx = (word64)(((r11) >> 34) | ((r11) << 30));
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r11) >> 39) | ((r11) << 25));
    r10 = (word64)(r10 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r12);
    r14 = (word64)(r14 + r10);
    rbx = (word64)(rbx ^ r11);
    rdx = (word64)(rdx & rbx);
    r10 = (word64)(r10 + rax);
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r14) >> 14) | ((r14) << 50));
    rcx = (word64)(((r14) >> 18) | ((r14) << 46));
    r10 = (word64)(r10 + rdx);
    r9 = (word64)(r9 + WC_L64(rsp, 48));
    rdx = (word64)(r15);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r14) >> 41) | ((r14) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r14);
    r9 = (word64)(r9 + rax);
    rax = (word64)(((r10) >> 28) | ((r10) << 36));
    rcx = (word64)(((r10) >> 34) | ((r10) << 30));
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r10) >> 39) | ((r10) << 25));
    r9 = (word64)(r9 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r11);
    r13 = (word64)(r13 + r9);
    rdx = (word64)(rdx ^ r10);
    rbx = (word64)(rbx & rdx);
    r9 = (word64)(r9 + rax);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r13) >> 14) | ((r13) << 50));
    rcx = (word64)(((r13) >> 18) | ((r13) << 46));
    r9 = (word64)(r9 + rbx);
    r8 = (word64)(r8 + WC_L64(rsp, 56));
    rbx = (word64)(r14);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r13) >> 41) | ((r13) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r13);
    r8 = (word64)(r8 + rax);
    rax = (word64)(((r9) >> 28) | ((r9) << 36));
    rcx = (word64)(((r9) >> 34) | ((r9) << 30));
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r9) >> 39) | ((r9) << 25));
    r8 = (word64)(r8 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r10);
    r12 = (word64)(r12 + r8);
    rbx = (word64)(rbx ^ r9);
    rdx = (word64)(rdx & rbx);
    r8 = (word64)(r8 + rax);
    rdx = (word64)(rdx ^ r10);
    /* rnd_all_4: 8-11 */
    rax = (word64)(((r12) >> 14) | ((r12) << 50));
    rcx = (word64)(((r12) >> 18) | ((r12) << 46));
    r8 = (word64)(r8 + rdx);
    r15 = (word64)(r15 + WC_L64(rsp, 64));
    rdx = (word64)(r13);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r14);
    rax = (word64)(((r12) >> 41) | ((r12) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r12);
    r15 = (word64)(r15 + rax);
    rax = (word64)(((r8) >> 28) | ((r8) << 36));
    rcx = (word64)(((r8) >> 34) | ((r8) << 30));
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r8) >> 39) | ((r8) << 25));
    r15 = (word64)(r15 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r9);
    r11 = (word64)(r11 + r15);
    rdx = (word64)(rdx ^ r8);
    rbx = (word64)(rbx & rdx);
    r15 = (word64)(r15 + rax);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r11) >> 14) | ((r11) << 50));
    rcx = (word64)(((r11) >> 18) | ((r11) << 46));
    r15 = (word64)(r15 + rbx);
    r14 = (word64)(r14 + WC_L64(rsp, 72));
    rbx = (word64)(r12);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r11) >> 41) | ((r11) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r11);
    r14 = (word64)(r14 + rax);
    rax = (word64)(((r15) >> 28) | ((r15) << 36));
    rcx = (word64)(((r15) >> 34) | ((r15) << 30));
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r15) >> 39) | ((r15) << 25));
    r14 = (word64)(r14 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r8);
    r10 = (word64)(r10 + r14);
    rbx = (word64)(rbx ^ r15);
    rdx = (word64)(rdx & rbx);
    r14 = (word64)(r14 + rax);
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r10) >> 14) | ((r10) << 50));
    rcx = (word64)(((r10) >> 18) | ((r10) << 46));
    r14 = (word64)(r14 + rdx);
    r13 = (word64)(r13 + WC_L64(rsp, 80));
    rdx = (word64)(r11);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r10) >> 41) | ((r10) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r10);
    r13 = (word64)(r13 + rax);
    rax = (word64)(((r14) >> 28) | ((r14) << 36));
    rcx = (word64)(((r14) >> 34) | ((r14) << 30));
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r14) >> 39) | ((r14) << 25));
    r13 = (word64)(r13 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r15);
    r9 = (word64)(r9 + r13);
    rdx = (word64)(rdx ^ r14);
    rbx = (word64)(rbx & rdx);
    r13 = (word64)(r13 + rax);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r9) >> 14) | ((r9) << 50));
    rcx = (word64)(((r9) >> 18) | ((r9) << 46));
    r13 = (word64)(r13 + rbx);
    r12 = (word64)(r12 + WC_L64(rsp, 88));
    rbx = (word64)(r10);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r9) >> 41) | ((r9) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r9);
    r12 = (word64)(r12 + rax);
    rax = (word64)(((r13) >> 28) | ((r13) << 36));
    rcx = (word64)(((r13) >> 34) | ((r13) << 30));
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r13) >> 39) | ((r13) << 25));
    r12 = (word64)(r12 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r14);
    r8 = (word64)(r8 + r12);
    rbx = (word64)(rbx ^ r13);
    rdx = (word64)(rdx & rbx);
    r12 = (word64)(r12 + rax);
    rdx = (word64)(rdx ^ r14);
    /* rnd_all_4: 12-15 */
    rax = (word64)(((r8) >> 14) | ((r8) << 50));
    rcx = (word64)(((r8) >> 18) | ((r8) << 46));
    r12 = (word64)(r12 + rdx);
    r11 = (word64)(r11 + WC_L64(rsp, 96));
    rdx = (word64)(r9);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r10);
    rax = (word64)(((r8) >> 41) | ((r8) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r8);
    r11 = (word64)(r11 + rax);
    rax = (word64)(((r12) >> 28) | ((r12) << 36));
    rcx = (word64)(((r12) >> 34) | ((r12) << 30));
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r12) >> 39) | ((r12) << 25));
    r11 = (word64)(r11 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r13);
    r15 = (word64)(r15 + r11);
    rdx = (word64)(rdx ^ r12);
    rbx = (word64)(rbx & rdx);
    r11 = (word64)(r11 + rax);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r15) >> 14) | ((r15) << 50));
    rcx = (word64)(((r15) >> 18) | ((r15) << 46));
    r11 = (word64)(r11 + rbx);
    r10 = (word64)(r10 + WC_L64(rsp, 104));
    rbx = (word64)(r8);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r15) >> 41) | ((r15) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r15);
    r10 = (word64)(r10 + rax);
    rax = (word64)(((r11) >> 28) | ((r11) << 36));
    rcx = (word64)(((r11) >> 34) | ((r11) << 30));
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r11) >> 39) | ((r11) << 25));
    r10 = (word64)(r10 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r12);
    r14 = (word64)(r14 + r10);
    rbx = (word64)(rbx ^ r11);
    rdx = (word64)(rdx & rbx);
    r10 = (word64)(r10 + rax);
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r14) >> 14) | ((r14) << 50));
    rcx = (word64)(((r14) >> 18) | ((r14) << 46));
    r10 = (word64)(r10 + rdx);
    r9 = (word64)(r9 + WC_L64(rsp, 112));
    rdx = (word64)(r15);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r14) >> 41) | ((r14) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r14);
    r9 = (word64)(r9 + rax);
    rax = (word64)(((r10) >> 28) | ((r10) << 36));
    rcx = (word64)(((r10) >> 34) | ((r10) << 30));
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r10) >> 39) | ((r10) << 25));
    r9 = (word64)(r9 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r11);
    r13 = (word64)(r13 + r9);
    rdx = (word64)(rdx ^ r10);
    rbx = (word64)(rbx & rdx);
    r9 = (word64)(r9 + rax);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r13) >> 14) | ((r13) << 50));
    rcx = (word64)(((r13) >> 18) | ((r13) << 46));
    r9 = (word64)(r9 + rbx);
    r8 = (word64)(r8 + WC_L64(rsp, 120));
    rbx = (word64)(r14);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r13) >> 41) | ((r13) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r13);
    r8 = (word64)(r8 + rax);
    rax = (word64)(((r9) >> 28) | ((r9) << 36));
    rcx = (word64)(((r9) >> 34) | ((r9) << 30));
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r9) >> 39) | ((r9) << 25));
    r8 = (word64)(r8 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r10);
    r12 = (word64)(r12 + r8);
    rbx = (word64)(rbx ^ r9);
    rdx = (word64)(rdx & rbx);
    r8 = (word64)(r8 + rax);
    rdx = (word64)(rdx ^ r10);
    r8 = (word64)(r8 + rdx);
    WC_S64(rdi, 0) = (word64)(WC_L64(rdi, 0) + r8);
    WC_S64(rdi, 8) = (word64)(WC_L64(rdi, 8) + r9);
    WC_S64(rdi, 16) = (word64)(WC_L64(rdi, 16) + r10);
    WC_S64(rdi, 24) = (word64)(WC_L64(rdi, 24) + r11);
    WC_S64(rdi, 32) = (word64)(WC_L64(rdi, 32) + r12);
    WC_S64(rdi, 40) = (word64)(WC_L64(rdi, 40) + r13);
    WC_S64(rdi, 48) = (word64)(WC_L64(rdi, 48) + r14);
    WC_S64(rdi, 56) = (word64)(WC_L64(rdi, 56) + r15);
    rax = (word64)(0);
    return (int)(word32)rax;
}

WC_X64I_TARGET("avx2,bmi2")
WOLFSSL_LOCAL int Transform_Sha512_AVX2_RORX_Len(wc_Sha512* sha512, word32 len)
{
    word64 rdi, rsi, rax = 0, rsp, r8 = 0, r9 = 0, r10 = 0, r11 = 0, r12 = 0,
           r13 = 0, r14 = 0, r15 = 0, rbp = 0, rbx = 0, rdx = 0, rcx = 0;
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y4 = _mm256_setzero_si256(), y5 = _mm256_setzero_si256(),
            y6 = _mm256_setzero_si256(), y7 = _mm256_setzero_si256(),
            y8 = _mm256_setzero_si256(), y9 = _mm256_setzero_si256(),
            y10 = _mm256_setzero_si256(), y11 = _mm256_setzero_si256(),
            y12 = _mm256_setzero_si256(), y13 = _mm256_setzero_si256(),
            y15 = _mm256_setzero_si256();
    XALIGNED(32) WC_X64I_SLOT stk[172];
    word32 zf1;

    rdi = (word64)(size_t)sha512;
    rsi = (word64)(word32)len;

    rsp = (word64)(size_t)stk + 1376;
    if ((((byte)rsi & 0x80)) == (0)) {
        goto L_sha512_len_avx2_rorx_block;
    }
    rax = (word64)(WC_L64(rdi, 224));
    rsp = (word64)(rsp - 8);
    WC_S64(rsp, 0) = rsi;
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rax, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rax, 32));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rax, 64));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(rax, 96));
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 64), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 96), y1);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 128), y2);
    _mm256_storeu_si256((__m256i*)WC_PW(rdi, 160), y3);
    (void)Transform_Sha512_AVX2_RORX((wc_Sha512*)(size_t)rdi);
    rsi = WC_L64(rsp, 0);
    rsp = (word64)(rsp + 8);
    WC_S64(rdi, 224) = (word64)(WC_L64(rdi, 224) + 0x80);
    rsi = (word32)((word32)rsi - 0x80);
    if (((word32)rsi) == (0)) {
        goto L_sha512_len_avx2_rorx_done;
    }
L_sha512_len_avx2_rorx_block:
    rsp = (word64)(rsp - 1352);
    rax = (word64)(WC_L64(rdi, 224));
    y15 = _mm256_loadu_si256((const __m256i*)WC_PR(L_avx2_rorx_sha512_flip_mask,
        0));
    r8 = (word64)(WC_L64(rdi, 0));
    r9 = (word64)(WC_L64(rdi, 8));
    r10 = (word64)(WC_L64(rdi, 16));
    r11 = (word64)(WC_L64(rdi, 24));
    r12 = (word64)(WC_L64(rdi, 32));
    r13 = (word64)(WC_L64(rdi, 40));
    r14 = (word64)(WC_L64(rdi, 48));
    r15 = (word64)(WC_L64(rdi, 56));
    WC_S32(rsp, 1344) = (word32)((word32)rsi);
    /* Start of loop processing two blocks */
L_sha512_len_avx2_rorx_begin:
    rsi = (word64)(rsp);
    rbp = (word64)((word64)(size_t)L_avx2_rorx_sha512_k_2);
    rbx = (word64)(r9);
    rdx = (word64)(0);
    y0 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rax, 0)));
    y1 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rax,
        16)));
    y0 = _mm256_inserti128_si256(y0, _mm_loadu_si128((const __m128i*)WC_PR(rax,
        128)), 1);
    y1 = _mm256_inserti128_si256(y1, _mm_loadu_si128((const __m128i*)WC_PR(rax,
        144)), 1);
    y0 = _mm256_shuffle_epi8(y0, y15);
    y1 = _mm256_shuffle_epi8(y1, y15);
    y2 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rax,
        32)));
    y3 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rax,
        48)));
    y2 = _mm256_inserti128_si256(y2, _mm_loadu_si128((const __m128i*)WC_PR(rax,
        160)), 1);
    y3 = _mm256_inserti128_si256(y3, _mm_loadu_si128((const __m128i*)WC_PR(rax,
        176)), 1);
    y2 = _mm256_shuffle_epi8(y2, y15);
    y3 = _mm256_shuffle_epi8(y3, y15);
    y4 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rax,
        64)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rax,
        80)));
    y4 = _mm256_inserti128_si256(y4, _mm_loadu_si128((const __m128i*)WC_PR(rax,
        192)), 1);
    y5 = _mm256_inserti128_si256(y5, _mm_loadu_si128((const __m128i*)WC_PR(rax,
        208)), 1);
    y4 = _mm256_shuffle_epi8(y4, y15);
    y5 = _mm256_shuffle_epi8(y5, y15);
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rax,
        96)));
    y7 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rax,
        112)));
    y6 = _mm256_inserti128_si256(y6, _mm_loadu_si128((const __m128i*)WC_PR(rax,
        224)), 1);
    y7 = _mm256_inserti128_si256(y7, _mm_loadu_si128((const __m128i*)WC_PR(rax,
        240)), 1);
    y6 = _mm256_shuffle_epi8(y6, y15);
    y7 = _mm256_shuffle_epi8(y7, y15);
    rbx = (word64)(rbx ^ r10);
    /* Start of 16 rounds */
L_sha512_len_avx2_rorx_start:
    y8 = _mm256_add_epi64(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        0)));
    y9 = _mm256_add_epi64(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        32)));
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 0), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 32), y9);
    y8 = _mm256_add_epi64(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y9 = _mm256_add_epi64(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 64), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 96), y9);
    y8 = _mm256_add_epi64(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        128)));
    y9 = _mm256_add_epi64(y5, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        160)));
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 128), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 160), y9);
    y8 = _mm256_add_epi64(y6, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        192)));
    y9 = _mm256_add_epi64(y7, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        224)));
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 192), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 224), y9);
    /* msg_sched: 0-1 */
    rax = (word64)(((r12) >> 14) | ((r12) << 50));
    rcx = (word64)(((r12) >> 18) | ((r12) << 46));
    r8 = (word64)(r8 + rdx);
    y12 = _mm256_alignr_epi8(y1, y0, 8);
    r15 = (word64)(r15 + WC_L64(rsi, 0));
    rdx = (word64)(r13);
    rcx = (word64)(rcx ^ rax);
    y13 = _mm256_alignr_epi8(y5, y4, 8);
    rdx = (word64)(rdx ^ r14);
    rax = (word64)(((r12) >> 41) | ((r12) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rdx = (word64)(rdx & r12);
    r15 = (word64)(r15 + rax);
    rax = (word64)(((r8) >> 28) | ((r8) << 36));
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    rcx = (word64)(((r8) >> 34) | ((r8) << 30));
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(((r8) >> 39) | ((r8) << 25));
    r15 = (word64)(r15 + rdx);
    rax = (word64)(rax ^ rcx);
    y11 = _mm256_srli_epi64(y12, 7);
    y8 = _mm256_xor_si256(y8, y10);
    rdx = (word64)(r9);
    r11 = (word64)(r11 + r15);
    rdx = (word64)(rdx ^ r8);
    y8 = _mm256_xor_si256(y8, y11);
    y0 = _mm256_add_epi64(y13, y0);
    rbx = (word64)(rbx & rdx);
    r15 = (word64)(r15 + rax);
    rbx = (word64)(rbx ^ r9);
    y0 = _mm256_add_epi64(y8, y0);
    rax = (word64)(((r11) >> 14) | ((r11) << 50));
    rcx = (word64)(((r11) >> 18) | ((r11) << 46));
    r15 = (word64)(r15 + rbx);
    y8 = _mm256_srli_epi64(y7, 19);
    y9 = _mm256_slli_epi64(y7, 45);
    r14 = (word64)(r14 + WC_L64(rsi, 8));
    rbx = (word64)(r12);
    rcx = (word64)(rcx ^ rax);
    y10 = _mm256_srli_epi64(y7, 61);
    y11 = _mm256_slli_epi64(y7, 3);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r11) >> 41) | ((r11) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rbx = (word64)(rbx & r11);
    r14 = (word64)(r14 + rax);
    rax = (word64)(((r15) >> 28) | ((r15) << 36));
    rcx = (word64)(((r15) >> 34) | ((r15) << 30));
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_xor_si256(y8, y10);
    y11 = _mm256_srli_epi64(y7, 6);
    rax = (word64)(((r15) >> 39) | ((r15) << 25));
    r14 = (word64)(r14 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r8);
    r10 = (word64)(r10 + r14);
    rbx = (word64)(rbx ^ r15);
    y8 = _mm256_xor_si256(y8, y11);
    rdx = (word64)(rdx & rbx);
    r14 = (word64)(r14 + rax);
    rdx = (word64)(rdx ^ r8);
    y0 = _mm256_add_epi64(y8, y0);
    /* msg_sched done: 0-1 */
    /* msg_sched: 4-5 */
    rax = (word64)(((r10) >> 14) | ((r10) << 50));
    rcx = (word64)(((r10) >> 18) | ((r10) << 46));
    r14 = (word64)(r14 + rdx);
    y12 = _mm256_alignr_epi8(y2, y1, 8);
    r13 = (word64)(r13 + WC_L64(rsi, 32));
    rdx = (word64)(r11);
    rcx = (word64)(rcx ^ rax);
    y13 = _mm256_alignr_epi8(y6, y5, 8);
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r10) >> 41) | ((r10) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rdx = (word64)(rdx & r10);
    r13 = (word64)(r13 + rax);
    rax = (word64)(((r14) >> 28) | ((r14) << 36));
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    rcx = (word64)(((r14) >> 34) | ((r14) << 30));
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(((r14) >> 39) | ((r14) << 25));
    r13 = (word64)(r13 + rdx);
    rax = (word64)(rax ^ rcx);
    y11 = _mm256_srli_epi64(y12, 7);
    y8 = _mm256_xor_si256(y8, y10);
    rdx = (word64)(r15);
    r9 = (word64)(r9 + r13);
    rdx = (word64)(rdx ^ r14);
    y8 = _mm256_xor_si256(y8, y11);
    y1 = _mm256_add_epi64(y13, y1);
    rbx = (word64)(rbx & rdx);
    r13 = (word64)(r13 + rax);
    rbx = (word64)(rbx ^ r15);
    y1 = _mm256_add_epi64(y8, y1);
    rax = (word64)(((r9) >> 14) | ((r9) << 50));
    rcx = (word64)(((r9) >> 18) | ((r9) << 46));
    r13 = (word64)(r13 + rbx);
    y8 = _mm256_srli_epi64(y0, 19);
    y9 = _mm256_slli_epi64(y0, 45);
    r12 = (word64)(r12 + WC_L64(rsi, 40));
    rbx = (word64)(r10);
    rcx = (word64)(rcx ^ rax);
    y10 = _mm256_srli_epi64(y0, 61);
    y11 = _mm256_slli_epi64(y0, 3);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r9) >> 41) | ((r9) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rbx = (word64)(rbx & r9);
    r12 = (word64)(r12 + rax);
    rax = (word64)(((r13) >> 28) | ((r13) << 36));
    rcx = (word64)(((r13) >> 34) | ((r13) << 30));
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_xor_si256(y8, y10);
    y11 = _mm256_srli_epi64(y0, 6);
    rax = (word64)(((r13) >> 39) | ((r13) << 25));
    r12 = (word64)(r12 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r14);
    r8 = (word64)(r8 + r12);
    rbx = (word64)(rbx ^ r13);
    y8 = _mm256_xor_si256(y8, y11);
    rdx = (word64)(rdx & rbx);
    r12 = (word64)(r12 + rax);
    rdx = (word64)(rdx ^ r14);
    y1 = _mm256_add_epi64(y8, y1);
    /* msg_sched done: 4-5 */
    /* msg_sched: 8-9 */
    rax = (word64)(((r8) >> 14) | ((r8) << 50));
    rcx = (word64)(((r8) >> 18) | ((r8) << 46));
    r12 = (word64)(r12 + rdx);
    y12 = _mm256_alignr_epi8(y3, y2, 8);
    r11 = (word64)(r11 + WC_L64(rsi, 64));
    rdx = (word64)(r9);
    rcx = (word64)(rcx ^ rax);
    y13 = _mm256_alignr_epi8(y7, y6, 8);
    rdx = (word64)(rdx ^ r10);
    rax = (word64)(((r8) >> 41) | ((r8) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rdx = (word64)(rdx & r8);
    r11 = (word64)(r11 + rax);
    rax = (word64)(((r12) >> 28) | ((r12) << 36));
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    rcx = (word64)(((r12) >> 34) | ((r12) << 30));
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(((r12) >> 39) | ((r12) << 25));
    r11 = (word64)(r11 + rdx);
    rax = (word64)(rax ^ rcx);
    y11 = _mm256_srli_epi64(y12, 7);
    y8 = _mm256_xor_si256(y8, y10);
    rdx = (word64)(r13);
    r15 = (word64)(r15 + r11);
    rdx = (word64)(rdx ^ r12);
    y8 = _mm256_xor_si256(y8, y11);
    y2 = _mm256_add_epi64(y13, y2);
    rbx = (word64)(rbx & rdx);
    r11 = (word64)(r11 + rax);
    rbx = (word64)(rbx ^ r13);
    y2 = _mm256_add_epi64(y8, y2);
    rax = (word64)(((r15) >> 14) | ((r15) << 50));
    rcx = (word64)(((r15) >> 18) | ((r15) << 46));
    r11 = (word64)(r11 + rbx);
    y8 = _mm256_srli_epi64(y1, 19);
    y9 = _mm256_slli_epi64(y1, 45);
    r10 = (word64)(r10 + WC_L64(rsi, 72));
    rbx = (word64)(r8);
    rcx = (word64)(rcx ^ rax);
    y10 = _mm256_srli_epi64(y1, 61);
    y11 = _mm256_slli_epi64(y1, 3);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r15) >> 41) | ((r15) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rbx = (word64)(rbx & r15);
    r10 = (word64)(r10 + rax);
    rax = (word64)(((r11) >> 28) | ((r11) << 36));
    rcx = (word64)(((r11) >> 34) | ((r11) << 30));
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_xor_si256(y8, y10);
    y11 = _mm256_srli_epi64(y1, 6);
    rax = (word64)(((r11) >> 39) | ((r11) << 25));
    r10 = (word64)(r10 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r12);
    r14 = (word64)(r14 + r10);
    rbx = (word64)(rbx ^ r11);
    y8 = _mm256_xor_si256(y8, y11);
    rdx = (word64)(rdx & rbx);
    r10 = (word64)(r10 + rax);
    rdx = (word64)(rdx ^ r12);
    y2 = _mm256_add_epi64(y8, y2);
    /* msg_sched done: 8-9 */
    /* msg_sched: 12-13 */
    rax = (word64)(((r14) >> 14) | ((r14) << 50));
    rcx = (word64)(((r14) >> 18) | ((r14) << 46));
    r10 = (word64)(r10 + rdx);
    y12 = _mm256_alignr_epi8(y4, y3, 8);
    r9 = (word64)(r9 + WC_L64(rsi, 96));
    rdx = (word64)(r15);
    rcx = (word64)(rcx ^ rax);
    y13 = _mm256_alignr_epi8(y0, y7, 8);
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r14) >> 41) | ((r14) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rdx = (word64)(rdx & r14);
    r9 = (word64)(r9 + rax);
    rax = (word64)(((r10) >> 28) | ((r10) << 36));
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    rcx = (word64)(((r10) >> 34) | ((r10) << 30));
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(((r10) >> 39) | ((r10) << 25));
    r9 = (word64)(r9 + rdx);
    rax = (word64)(rax ^ rcx);
    y11 = _mm256_srli_epi64(y12, 7);
    y8 = _mm256_xor_si256(y8, y10);
    rdx = (word64)(r11);
    r13 = (word64)(r13 + r9);
    rdx = (word64)(rdx ^ r10);
    y8 = _mm256_xor_si256(y8, y11);
    y3 = _mm256_add_epi64(y13, y3);
    rbx = (word64)(rbx & rdx);
    r9 = (word64)(r9 + rax);
    rbx = (word64)(rbx ^ r11);
    y3 = _mm256_add_epi64(y8, y3);
    rax = (word64)(((r13) >> 14) | ((r13) << 50));
    rcx = (word64)(((r13) >> 18) | ((r13) << 46));
    r9 = (word64)(r9 + rbx);
    y8 = _mm256_srli_epi64(y2, 19);
    y9 = _mm256_slli_epi64(y2, 45);
    r8 = (word64)(r8 + WC_L64(rsi, 104));
    rbx = (word64)(r14);
    rcx = (word64)(rcx ^ rax);
    y10 = _mm256_srli_epi64(y2, 61);
    y11 = _mm256_slli_epi64(y2, 3);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r13) >> 41) | ((r13) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rbx = (word64)(rbx & r13);
    r8 = (word64)(r8 + rax);
    rax = (word64)(((r9) >> 28) | ((r9) << 36));
    rcx = (word64)(((r9) >> 34) | ((r9) << 30));
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_xor_si256(y8, y10);
    y11 = _mm256_srli_epi64(y2, 6);
    rax = (word64)(((r9) >> 39) | ((r9) << 25));
    r8 = (word64)(r8 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r10);
    r12 = (word64)(r12 + r8);
    rbx = (word64)(rbx ^ r9);
    y8 = _mm256_xor_si256(y8, y11);
    rdx = (word64)(rdx & rbx);
    r8 = (word64)(r8 + rax);
    rdx = (word64)(rdx ^ r10);
    y3 = _mm256_add_epi64(y8, y3);
    /* msg_sched done: 12-13 */
    /* msg_sched: 16-17 */
    rax = (word64)(((r12) >> 14) | ((r12) << 50));
    rcx = (word64)(((r12) >> 18) | ((r12) << 46));
    r8 = (word64)(r8 + rdx);
    y12 = _mm256_alignr_epi8(y5, y4, 8);
    r15 = (word64)(r15 + WC_L64(rsi, 128));
    rdx = (word64)(r13);
    rcx = (word64)(rcx ^ rax);
    y13 = _mm256_alignr_epi8(y1, y0, 8);
    rdx = (word64)(rdx ^ r14);
    rax = (word64)(((r12) >> 41) | ((r12) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rdx = (word64)(rdx & r12);
    r15 = (word64)(r15 + rax);
    rax = (word64)(((r8) >> 28) | ((r8) << 36));
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    rcx = (word64)(((r8) >> 34) | ((r8) << 30));
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(((r8) >> 39) | ((r8) << 25));
    r15 = (word64)(r15 + rdx);
    rax = (word64)(rax ^ rcx);
    y11 = _mm256_srli_epi64(y12, 7);
    y8 = _mm256_xor_si256(y8, y10);
    rdx = (word64)(r9);
    r11 = (word64)(r11 + r15);
    rdx = (word64)(rdx ^ r8);
    y8 = _mm256_xor_si256(y8, y11);
    y4 = _mm256_add_epi64(y13, y4);
    rbx = (word64)(rbx & rdx);
    r15 = (word64)(r15 + rax);
    rbx = (word64)(rbx ^ r9);
    y4 = _mm256_add_epi64(y8, y4);
    rax = (word64)(((r11) >> 14) | ((r11) << 50));
    rcx = (word64)(((r11) >> 18) | ((r11) << 46));
    r15 = (word64)(r15 + rbx);
    y8 = _mm256_srli_epi64(y3, 19);
    y9 = _mm256_slli_epi64(y3, 45);
    r14 = (word64)(r14 + WC_L64(rsi, 136));
    rbx = (word64)(r12);
    rcx = (word64)(rcx ^ rax);
    y10 = _mm256_srli_epi64(y3, 61);
    y11 = _mm256_slli_epi64(y3, 3);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r11) >> 41) | ((r11) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rbx = (word64)(rbx & r11);
    r14 = (word64)(r14 + rax);
    rax = (word64)(((r15) >> 28) | ((r15) << 36));
    rcx = (word64)(((r15) >> 34) | ((r15) << 30));
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_xor_si256(y8, y10);
    y11 = _mm256_srli_epi64(y3, 6);
    rax = (word64)(((r15) >> 39) | ((r15) << 25));
    r14 = (word64)(r14 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r8);
    r10 = (word64)(r10 + r14);
    rbx = (word64)(rbx ^ r15);
    y8 = _mm256_xor_si256(y8, y11);
    rdx = (word64)(rdx & rbx);
    r14 = (word64)(r14 + rax);
    rdx = (word64)(rdx ^ r8);
    y4 = _mm256_add_epi64(y8, y4);
    /* msg_sched done: 16-17 */
    /* msg_sched: 20-21 */
    rax = (word64)(((r10) >> 14) | ((r10) << 50));
    rcx = (word64)(((r10) >> 18) | ((r10) << 46));
    r14 = (word64)(r14 + rdx);
    y12 = _mm256_alignr_epi8(y6, y5, 8);
    r13 = (word64)(r13 + WC_L64(rsi, 160));
    rdx = (word64)(r11);
    rcx = (word64)(rcx ^ rax);
    y13 = _mm256_alignr_epi8(y2, y1, 8);
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r10) >> 41) | ((r10) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rdx = (word64)(rdx & r10);
    r13 = (word64)(r13 + rax);
    rax = (word64)(((r14) >> 28) | ((r14) << 36));
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    rcx = (word64)(((r14) >> 34) | ((r14) << 30));
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(((r14) >> 39) | ((r14) << 25));
    r13 = (word64)(r13 + rdx);
    rax = (word64)(rax ^ rcx);
    y11 = _mm256_srli_epi64(y12, 7);
    y8 = _mm256_xor_si256(y8, y10);
    rdx = (word64)(r15);
    r9 = (word64)(r9 + r13);
    rdx = (word64)(rdx ^ r14);
    y8 = _mm256_xor_si256(y8, y11);
    y5 = _mm256_add_epi64(y13, y5);
    rbx = (word64)(rbx & rdx);
    r13 = (word64)(r13 + rax);
    rbx = (word64)(rbx ^ r15);
    y5 = _mm256_add_epi64(y8, y5);
    rax = (word64)(((r9) >> 14) | ((r9) << 50));
    rcx = (word64)(((r9) >> 18) | ((r9) << 46));
    r13 = (word64)(r13 + rbx);
    y8 = _mm256_srli_epi64(y4, 19);
    y9 = _mm256_slli_epi64(y4, 45);
    r12 = (word64)(r12 + WC_L64(rsi, 168));
    rbx = (word64)(r10);
    rcx = (word64)(rcx ^ rax);
    y10 = _mm256_srli_epi64(y4, 61);
    y11 = _mm256_slli_epi64(y4, 3);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r9) >> 41) | ((r9) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rbx = (word64)(rbx & r9);
    r12 = (word64)(r12 + rax);
    rax = (word64)(((r13) >> 28) | ((r13) << 36));
    rcx = (word64)(((r13) >> 34) | ((r13) << 30));
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_xor_si256(y8, y10);
    y11 = _mm256_srli_epi64(y4, 6);
    rax = (word64)(((r13) >> 39) | ((r13) << 25));
    r12 = (word64)(r12 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r14);
    r8 = (word64)(r8 + r12);
    rbx = (word64)(rbx ^ r13);
    y8 = _mm256_xor_si256(y8, y11);
    rdx = (word64)(rdx & rbx);
    r12 = (word64)(r12 + rax);
    rdx = (word64)(rdx ^ r14);
    y5 = _mm256_add_epi64(y8, y5);
    /* msg_sched done: 20-21 */
    /* msg_sched: 24-25 */
    rax = (word64)(((r8) >> 14) | ((r8) << 50));
    rcx = (word64)(((r8) >> 18) | ((r8) << 46));
    r12 = (word64)(r12 + rdx);
    y12 = _mm256_alignr_epi8(y7, y6, 8);
    r11 = (word64)(r11 + WC_L64(rsi, 192));
    rdx = (word64)(r9);
    rcx = (word64)(rcx ^ rax);
    y13 = _mm256_alignr_epi8(y3, y2, 8);
    rdx = (word64)(rdx ^ r10);
    rax = (word64)(((r8) >> 41) | ((r8) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rdx = (word64)(rdx & r8);
    r11 = (word64)(r11 + rax);
    rax = (word64)(((r12) >> 28) | ((r12) << 36));
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    rcx = (word64)(((r12) >> 34) | ((r12) << 30));
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(((r12) >> 39) | ((r12) << 25));
    r11 = (word64)(r11 + rdx);
    rax = (word64)(rax ^ rcx);
    y11 = _mm256_srli_epi64(y12, 7);
    y8 = _mm256_xor_si256(y8, y10);
    rdx = (word64)(r13);
    r15 = (word64)(r15 + r11);
    rdx = (word64)(rdx ^ r12);
    y8 = _mm256_xor_si256(y8, y11);
    y6 = _mm256_add_epi64(y13, y6);
    rbx = (word64)(rbx & rdx);
    r11 = (word64)(r11 + rax);
    rbx = (word64)(rbx ^ r13);
    y6 = _mm256_add_epi64(y8, y6);
    rax = (word64)(((r15) >> 14) | ((r15) << 50));
    rcx = (word64)(((r15) >> 18) | ((r15) << 46));
    r11 = (word64)(r11 + rbx);
    y8 = _mm256_srli_epi64(y5, 19);
    y9 = _mm256_slli_epi64(y5, 45);
    r10 = (word64)(r10 + WC_L64(rsi, 200));
    rbx = (word64)(r8);
    rcx = (word64)(rcx ^ rax);
    y10 = _mm256_srli_epi64(y5, 61);
    y11 = _mm256_slli_epi64(y5, 3);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r15) >> 41) | ((r15) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rbx = (word64)(rbx & r15);
    r10 = (word64)(r10 + rax);
    rax = (word64)(((r11) >> 28) | ((r11) << 36));
    rcx = (word64)(((r11) >> 34) | ((r11) << 30));
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_xor_si256(y8, y10);
    y11 = _mm256_srli_epi64(y5, 6);
    rax = (word64)(((r11) >> 39) | ((r11) << 25));
    r10 = (word64)(r10 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r12);
    r14 = (word64)(r14 + r10);
    rbx = (word64)(rbx ^ r11);
    y8 = _mm256_xor_si256(y8, y11);
    rdx = (word64)(rdx & rbx);
    r10 = (word64)(r10 + rax);
    rdx = (word64)(rdx ^ r12);
    y6 = _mm256_add_epi64(y8, y6);
    /* msg_sched done: 24-25 */
    /* msg_sched: 28-29 */
    rax = (word64)(((r14) >> 14) | ((r14) << 50));
    rcx = (word64)(((r14) >> 18) | ((r14) << 46));
    r10 = (word64)(r10 + rdx);
    y12 = _mm256_alignr_epi8(y0, y7, 8);
    r9 = (word64)(r9 + WC_L64(rsi, 224));
    rdx = (word64)(r15);
    rcx = (word64)(rcx ^ rax);
    y13 = _mm256_alignr_epi8(y4, y3, 8);
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r14) >> 41) | ((r14) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_srli_epi64(y12, 1);
    y9 = _mm256_slli_epi64(y12, 63);
    rdx = (word64)(rdx & r14);
    r9 = (word64)(r9 + rax);
    rax = (word64)(((r10) >> 28) | ((r10) << 36));
    y10 = _mm256_srli_epi64(y12, 8);
    y11 = _mm256_slli_epi64(y12, 56);
    rcx = (word64)(((r10) >> 34) | ((r10) << 30));
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rax = (word64)(((r10) >> 39) | ((r10) << 25));
    r9 = (word64)(r9 + rdx);
    rax = (word64)(rax ^ rcx);
    y11 = _mm256_srli_epi64(y12, 7);
    y8 = _mm256_xor_si256(y8, y10);
    rdx = (word64)(r11);
    r13 = (word64)(r13 + r9);
    rdx = (word64)(rdx ^ r10);
    y8 = _mm256_xor_si256(y8, y11);
    y7 = _mm256_add_epi64(y13, y7);
    rbx = (word64)(rbx & rdx);
    r9 = (word64)(r9 + rax);
    rbx = (word64)(rbx ^ r11);
    y7 = _mm256_add_epi64(y8, y7);
    rax = (word64)(((r13) >> 14) | ((r13) << 50));
    rcx = (word64)(((r13) >> 18) | ((r13) << 46));
    r9 = (word64)(r9 + rbx);
    y8 = _mm256_srli_epi64(y6, 19);
    y9 = _mm256_slli_epi64(y6, 45);
    r8 = (word64)(r8 + WC_L64(rsi, 232));
    rbx = (word64)(r14);
    rcx = (word64)(rcx ^ rax);
    y10 = _mm256_srli_epi64(y6, 61);
    y11 = _mm256_slli_epi64(y6, 3);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r13) >> 41) | ((r13) << 23));
    rax = (word64)(rax ^ rcx);
    y8 = _mm256_or_si256(y8, y9);
    y10 = _mm256_or_si256(y10, y11);
    rbx = (word64)(rbx & r13);
    r8 = (word64)(r8 + rax);
    rax = (word64)(((r9) >> 28) | ((r9) << 36));
    rcx = (word64)(((r9) >> 34) | ((r9) << 30));
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(rcx ^ rax);
    y8 = _mm256_xor_si256(y8, y10);
    y11 = _mm256_srli_epi64(y6, 6);
    rax = (word64)(((r9) >> 39) | ((r9) << 25));
    r8 = (word64)(r8 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r10);
    r12 = (word64)(r12 + r8);
    rbx = (word64)(rbx ^ r9);
    y8 = _mm256_xor_si256(y8, y11);
    rdx = (word64)(rdx & rbx);
    r8 = (word64)(r8 + rax);
    rdx = (word64)(rdx ^ r10);
    y7 = _mm256_add_epi64(y8, y7);
    /* msg_sched done: 28-29 */
    rbp = (word64)(rbp + 0x100);
    rsi = (word64)(rsi + 0x100);
    if ((rbp) != (WC_L64(L_avx2_rorx_sha512_k_2_end, 0))) {
        goto L_sha512_len_avx2_rorx_start;
    }
    y8 = _mm256_add_epi64(y0, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        0)));
    y9 = _mm256_add_epi64(y1, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        32)));
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 0), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 32), y9);
    y8 = _mm256_add_epi64(y2, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        64)));
    y9 = _mm256_add_epi64(y3, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        96)));
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 64), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 96), y9);
    y8 = _mm256_add_epi64(y4, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        128)));
    y9 = _mm256_add_epi64(y5, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        160)));
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 128), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 160), y9);
    y8 = _mm256_add_epi64(y6, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        192)));
    y9 = _mm256_add_epi64(y7, _mm256_loadu_si256((const __m256i*)WC_PR(rbp,
        224)));
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 192), y8);
    _mm256_storeu_si256((__m256i*)WC_PW(rsi, 224), y9);
    /* rnd_all_2: 0-1 */
    rax = (word64)(((r12) >> 14) | ((r12) << 50));
    rcx = (word64)(((r12) >> 18) | ((r12) << 46));
    r8 = (word64)(r8 + rdx);
    r15 = (word64)(r15 + WC_L64(rsi, 0));
    rdx = (word64)(r13);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r14);
    rax = (word64)(((r12) >> 41) | ((r12) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r12);
    r15 = (word64)(r15 + rax);
    rax = (word64)(((r8) >> 28) | ((r8) << 36));
    rcx = (word64)(((r8) >> 34) | ((r8) << 30));
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r8) >> 39) | ((r8) << 25));
    r15 = (word64)(r15 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r9);
    r11 = (word64)(r11 + r15);
    rdx = (word64)(rdx ^ r8);
    rbx = (word64)(rbx & rdx);
    r15 = (word64)(r15 + rax);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r11) >> 14) | ((r11) << 50));
    rcx = (word64)(((r11) >> 18) | ((r11) << 46));
    r15 = (word64)(r15 + rbx);
    r14 = (word64)(r14 + WC_L64(rsi, 8));
    rbx = (word64)(r12);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r11) >> 41) | ((r11) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r11);
    r14 = (word64)(r14 + rax);
    rax = (word64)(((r15) >> 28) | ((r15) << 36));
    rcx = (word64)(((r15) >> 34) | ((r15) << 30));
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r15) >> 39) | ((r15) << 25));
    r14 = (word64)(r14 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r8);
    r10 = (word64)(r10 + r14);
    rbx = (word64)(rbx ^ r15);
    rdx = (word64)(rdx & rbx);
    r14 = (word64)(r14 + rax);
    rdx = (word64)(rdx ^ r8);
    /* rnd_all_2: 4-5 */
    rax = (word64)(((r10) >> 14) | ((r10) << 50));
    rcx = (word64)(((r10) >> 18) | ((r10) << 46));
    r14 = (word64)(r14 + rdx);
    r13 = (word64)(r13 + WC_L64(rsi, 32));
    rdx = (word64)(r11);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r10) >> 41) | ((r10) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r10);
    r13 = (word64)(r13 + rax);
    rax = (word64)(((r14) >> 28) | ((r14) << 36));
    rcx = (word64)(((r14) >> 34) | ((r14) << 30));
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r14) >> 39) | ((r14) << 25));
    r13 = (word64)(r13 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r15);
    r9 = (word64)(r9 + r13);
    rdx = (word64)(rdx ^ r14);
    rbx = (word64)(rbx & rdx);
    r13 = (word64)(r13 + rax);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r9) >> 14) | ((r9) << 50));
    rcx = (word64)(((r9) >> 18) | ((r9) << 46));
    r13 = (word64)(r13 + rbx);
    r12 = (word64)(r12 + WC_L64(rsi, 40));
    rbx = (word64)(r10);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r9) >> 41) | ((r9) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r9);
    r12 = (word64)(r12 + rax);
    rax = (word64)(((r13) >> 28) | ((r13) << 36));
    rcx = (word64)(((r13) >> 34) | ((r13) << 30));
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r13) >> 39) | ((r13) << 25));
    r12 = (word64)(r12 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r14);
    r8 = (word64)(r8 + r12);
    rbx = (word64)(rbx ^ r13);
    rdx = (word64)(rdx & rbx);
    r12 = (word64)(r12 + rax);
    rdx = (word64)(rdx ^ r14);
    /* rnd_all_2: 8-9 */
    rax = (word64)(((r8) >> 14) | ((r8) << 50));
    rcx = (word64)(((r8) >> 18) | ((r8) << 46));
    r12 = (word64)(r12 + rdx);
    r11 = (word64)(r11 + WC_L64(rsi, 64));
    rdx = (word64)(r9);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r10);
    rax = (word64)(((r8) >> 41) | ((r8) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r8);
    r11 = (word64)(r11 + rax);
    rax = (word64)(((r12) >> 28) | ((r12) << 36));
    rcx = (word64)(((r12) >> 34) | ((r12) << 30));
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r12) >> 39) | ((r12) << 25));
    r11 = (word64)(r11 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r13);
    r15 = (word64)(r15 + r11);
    rdx = (word64)(rdx ^ r12);
    rbx = (word64)(rbx & rdx);
    r11 = (word64)(r11 + rax);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r15) >> 14) | ((r15) << 50));
    rcx = (word64)(((r15) >> 18) | ((r15) << 46));
    r11 = (word64)(r11 + rbx);
    r10 = (word64)(r10 + WC_L64(rsi, 72));
    rbx = (word64)(r8);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r15) >> 41) | ((r15) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r15);
    r10 = (word64)(r10 + rax);
    rax = (word64)(((r11) >> 28) | ((r11) << 36));
    rcx = (word64)(((r11) >> 34) | ((r11) << 30));
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r11) >> 39) | ((r11) << 25));
    r10 = (word64)(r10 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r12);
    r14 = (word64)(r14 + r10);
    rbx = (word64)(rbx ^ r11);
    rdx = (word64)(rdx & rbx);
    r10 = (word64)(r10 + rax);
    rdx = (word64)(rdx ^ r12);
    /* rnd_all_2: 12-13 */
    rax = (word64)(((r14) >> 14) | ((r14) << 50));
    rcx = (word64)(((r14) >> 18) | ((r14) << 46));
    r10 = (word64)(r10 + rdx);
    r9 = (word64)(r9 + WC_L64(rsi, 96));
    rdx = (word64)(r15);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r14) >> 41) | ((r14) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r14);
    r9 = (word64)(r9 + rax);
    rax = (word64)(((r10) >> 28) | ((r10) << 36));
    rcx = (word64)(((r10) >> 34) | ((r10) << 30));
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r10) >> 39) | ((r10) << 25));
    r9 = (word64)(r9 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r11);
    r13 = (word64)(r13 + r9);
    rdx = (word64)(rdx ^ r10);
    rbx = (word64)(rbx & rdx);
    r9 = (word64)(r9 + rax);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r13) >> 14) | ((r13) << 50));
    rcx = (word64)(((r13) >> 18) | ((r13) << 46));
    r9 = (word64)(r9 + rbx);
    r8 = (word64)(r8 + WC_L64(rsi, 104));
    rbx = (word64)(r14);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r13) >> 41) | ((r13) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r13);
    r8 = (word64)(r8 + rax);
    rax = (word64)(((r9) >> 28) | ((r9) << 36));
    rcx = (word64)(((r9) >> 34) | ((r9) << 30));
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r9) >> 39) | ((r9) << 25));
    r8 = (word64)(r8 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r10);
    r12 = (word64)(r12 + r8);
    rbx = (word64)(rbx ^ r9);
    rdx = (word64)(rdx & rbx);
    r8 = (word64)(r8 + rax);
    rdx = (word64)(rdx ^ r10);
    /* rnd_all_2: 16-17 */
    rax = (word64)(((r12) >> 14) | ((r12) << 50));
    rcx = (word64)(((r12) >> 18) | ((r12) << 46));
    r8 = (word64)(r8 + rdx);
    r15 = (word64)(r15 + WC_L64(rsi, 128));
    rdx = (word64)(r13);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r14);
    rax = (word64)(((r12) >> 41) | ((r12) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r12);
    r15 = (word64)(r15 + rax);
    rax = (word64)(((r8) >> 28) | ((r8) << 36));
    rcx = (word64)(((r8) >> 34) | ((r8) << 30));
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r8) >> 39) | ((r8) << 25));
    r15 = (word64)(r15 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r9);
    r11 = (word64)(r11 + r15);
    rdx = (word64)(rdx ^ r8);
    rbx = (word64)(rbx & rdx);
    r15 = (word64)(r15 + rax);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r11) >> 14) | ((r11) << 50));
    rcx = (word64)(((r11) >> 18) | ((r11) << 46));
    r15 = (word64)(r15 + rbx);
    r14 = (word64)(r14 + WC_L64(rsi, 136));
    rbx = (word64)(r12);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r11) >> 41) | ((r11) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r11);
    r14 = (word64)(r14 + rax);
    rax = (word64)(((r15) >> 28) | ((r15) << 36));
    rcx = (word64)(((r15) >> 34) | ((r15) << 30));
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r15) >> 39) | ((r15) << 25));
    r14 = (word64)(r14 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r8);
    r10 = (word64)(r10 + r14);
    rbx = (word64)(rbx ^ r15);
    rdx = (word64)(rdx & rbx);
    r14 = (word64)(r14 + rax);
    rdx = (word64)(rdx ^ r8);
    /* rnd_all_2: 20-21 */
    rax = (word64)(((r10) >> 14) | ((r10) << 50));
    rcx = (word64)(((r10) >> 18) | ((r10) << 46));
    r14 = (word64)(r14 + rdx);
    r13 = (word64)(r13 + WC_L64(rsi, 160));
    rdx = (word64)(r11);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r10) >> 41) | ((r10) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r10);
    r13 = (word64)(r13 + rax);
    rax = (word64)(((r14) >> 28) | ((r14) << 36));
    rcx = (word64)(((r14) >> 34) | ((r14) << 30));
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r14) >> 39) | ((r14) << 25));
    r13 = (word64)(r13 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r15);
    r9 = (word64)(r9 + r13);
    rdx = (word64)(rdx ^ r14);
    rbx = (word64)(rbx & rdx);
    r13 = (word64)(r13 + rax);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r9) >> 14) | ((r9) << 50));
    rcx = (word64)(((r9) >> 18) | ((r9) << 46));
    r13 = (word64)(r13 + rbx);
    r12 = (word64)(r12 + WC_L64(rsi, 168));
    rbx = (word64)(r10);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r9) >> 41) | ((r9) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r9);
    r12 = (word64)(r12 + rax);
    rax = (word64)(((r13) >> 28) | ((r13) << 36));
    rcx = (word64)(((r13) >> 34) | ((r13) << 30));
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r13) >> 39) | ((r13) << 25));
    r12 = (word64)(r12 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r14);
    r8 = (word64)(r8 + r12);
    rbx = (word64)(rbx ^ r13);
    rdx = (word64)(rdx & rbx);
    r12 = (word64)(r12 + rax);
    rdx = (word64)(rdx ^ r14);
    /* rnd_all_2: 24-25 */
    rax = (word64)(((r8) >> 14) | ((r8) << 50));
    rcx = (word64)(((r8) >> 18) | ((r8) << 46));
    r12 = (word64)(r12 + rdx);
    r11 = (word64)(r11 + WC_L64(rsi, 192));
    rdx = (word64)(r9);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r10);
    rax = (word64)(((r8) >> 41) | ((r8) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r8);
    r11 = (word64)(r11 + rax);
    rax = (word64)(((r12) >> 28) | ((r12) << 36));
    rcx = (word64)(((r12) >> 34) | ((r12) << 30));
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r12) >> 39) | ((r12) << 25));
    r11 = (word64)(r11 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r13);
    r15 = (word64)(r15 + r11);
    rdx = (word64)(rdx ^ r12);
    rbx = (word64)(rbx & rdx);
    r11 = (word64)(r11 + rax);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r15) >> 14) | ((r15) << 50));
    rcx = (word64)(((r15) >> 18) | ((r15) << 46));
    r11 = (word64)(r11 + rbx);
    r10 = (word64)(r10 + WC_L64(rsi, 200));
    rbx = (word64)(r8);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r15) >> 41) | ((r15) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r15);
    r10 = (word64)(r10 + rax);
    rax = (word64)(((r11) >> 28) | ((r11) << 36));
    rcx = (word64)(((r11) >> 34) | ((r11) << 30));
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r11) >> 39) | ((r11) << 25));
    r10 = (word64)(r10 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r12);
    r14 = (word64)(r14 + r10);
    rbx = (word64)(rbx ^ r11);
    rdx = (word64)(rdx & rbx);
    r10 = (word64)(r10 + rax);
    rdx = (word64)(rdx ^ r12);
    /* rnd_all_2: 28-29 */
    rax = (word64)(((r14) >> 14) | ((r14) << 50));
    rcx = (word64)(((r14) >> 18) | ((r14) << 46));
    r10 = (word64)(r10 + rdx);
    r9 = (word64)(r9 + WC_L64(rsi, 224));
    rdx = (word64)(r15);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r14) >> 41) | ((r14) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r14);
    r9 = (word64)(r9 + rax);
    rax = (word64)(((r10) >> 28) | ((r10) << 36));
    rcx = (word64)(((r10) >> 34) | ((r10) << 30));
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r10) >> 39) | ((r10) << 25));
    r9 = (word64)(r9 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r11);
    r13 = (word64)(r13 + r9);
    rdx = (word64)(rdx ^ r10);
    rbx = (word64)(rbx & rdx);
    r9 = (word64)(r9 + rax);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r13) >> 14) | ((r13) << 50));
    rcx = (word64)(((r13) >> 18) | ((r13) << 46));
    r9 = (word64)(r9 + rbx);
    r8 = (word64)(r8 + WC_L64(rsi, 232));
    rbx = (word64)(r14);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r13) >> 41) | ((r13) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r13);
    r8 = (word64)(r8 + rax);
    rax = (word64)(((r9) >> 28) | ((r9) << 36));
    rcx = (word64)(((r9) >> 34) | ((r9) << 30));
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r9) >> 39) | ((r9) << 25));
    r8 = (word64)(r8 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r10);
    r12 = (word64)(r12 + r8);
    rbx = (word64)(rbx ^ r9);
    rdx = (word64)(rdx & rbx);
    r8 = (word64)(r8 + rax);
    rdx = (word64)(rdx ^ r10);
    r8 = (word64)(r8 + rdx);
    rsi = (word64)(rsi - 0x400);
    r8 = (word64)(r8 + WC_L64(rdi, 0));
    r9 = (word64)(r9 + WC_L64(rdi, 8));
    r10 = (word64)(r10 + WC_L64(rdi, 16));
    r11 = (word64)(r11 + WC_L64(rdi, 24));
    r12 = (word64)(r12 + WC_L64(rdi, 32));
    r13 = (word64)(r13 + WC_L64(rdi, 40));
    r14 = (word64)(r14 + WC_L64(rdi, 48));
    r15 = (word64)(r15 + WC_L64(rdi, 56));
    WC_S64(rdi, 0) = (word64)(r8);
    WC_S64(rdi, 8) = (word64)(r9);
    WC_S64(rdi, 16) = (word64)(r10);
    WC_S64(rdi, 24) = (word64)(r11);
    WC_S64(rdi, 32) = (word64)(r12);
    WC_S64(rdi, 40) = (word64)(r13);
    WC_S64(rdi, 48) = (word64)(r14);
    WC_S64(rdi, 56) = (word64)(r15);
    rbx = (word64)(r9);
    rdx = (word64)(0);
    rbx = (word64)(rbx ^ r10);
    rbp = (word64)(5);
L_sha512_len_avx2_rorx_tail:
    /* rnd_all_2: 2-3 */
    rax = (word64)(((r12) >> 14) | ((r12) << 50));
    rcx = (word64)(((r12) >> 18) | ((r12) << 46));
    r8 = (word64)(r8 + rdx);
    r15 = (word64)(r15 + WC_L64(rsi, 16));
    rdx = (word64)(r13);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r14);
    rax = (word64)(((r12) >> 41) | ((r12) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r12);
    r15 = (word64)(r15 + rax);
    rax = (word64)(((r8) >> 28) | ((r8) << 36));
    rcx = (word64)(((r8) >> 34) | ((r8) << 30));
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r8) >> 39) | ((r8) << 25));
    r15 = (word64)(r15 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r9);
    r11 = (word64)(r11 + r15);
    rdx = (word64)(rdx ^ r8);
    rbx = (word64)(rbx & rdx);
    r15 = (word64)(r15 + rax);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r11) >> 14) | ((r11) << 50));
    rcx = (word64)(((r11) >> 18) | ((r11) << 46));
    r15 = (word64)(r15 + rbx);
    r14 = (word64)(r14 + WC_L64(rsi, 24));
    rbx = (word64)(r12);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r11) >> 41) | ((r11) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r11);
    r14 = (word64)(r14 + rax);
    rax = (word64)(((r15) >> 28) | ((r15) << 36));
    rcx = (word64)(((r15) >> 34) | ((r15) << 30));
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r15) >> 39) | ((r15) << 25));
    r14 = (word64)(r14 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r8);
    r10 = (word64)(r10 + r14);
    rbx = (word64)(rbx ^ r15);
    rdx = (word64)(rdx & rbx);
    r14 = (word64)(r14 + rax);
    rdx = (word64)(rdx ^ r8);
    /* rnd_all_2: 6-7 */
    rax = (word64)(((r10) >> 14) | ((r10) << 50));
    rcx = (word64)(((r10) >> 18) | ((r10) << 46));
    r14 = (word64)(r14 + rdx);
    r13 = (word64)(r13 + WC_L64(rsi, 48));
    rdx = (word64)(r11);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r10) >> 41) | ((r10) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r10);
    r13 = (word64)(r13 + rax);
    rax = (word64)(((r14) >> 28) | ((r14) << 36));
    rcx = (word64)(((r14) >> 34) | ((r14) << 30));
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r14) >> 39) | ((r14) << 25));
    r13 = (word64)(r13 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r15);
    r9 = (word64)(r9 + r13);
    rdx = (word64)(rdx ^ r14);
    rbx = (word64)(rbx & rdx);
    r13 = (word64)(r13 + rax);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r9) >> 14) | ((r9) << 50));
    rcx = (word64)(((r9) >> 18) | ((r9) << 46));
    r13 = (word64)(r13 + rbx);
    r12 = (word64)(r12 + WC_L64(rsi, 56));
    rbx = (word64)(r10);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r9) >> 41) | ((r9) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r9);
    r12 = (word64)(r12 + rax);
    rax = (word64)(((r13) >> 28) | ((r13) << 36));
    rcx = (word64)(((r13) >> 34) | ((r13) << 30));
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r13) >> 39) | ((r13) << 25));
    r12 = (word64)(r12 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r14);
    r8 = (word64)(r8 + r12);
    rbx = (word64)(rbx ^ r13);
    rdx = (word64)(rdx & rbx);
    r12 = (word64)(r12 + rax);
    rdx = (word64)(rdx ^ r14);
    /* rnd_all_2: 10-11 */
    rax = (word64)(((r8) >> 14) | ((r8) << 50));
    rcx = (word64)(((r8) >> 18) | ((r8) << 46));
    r12 = (word64)(r12 + rdx);
    r11 = (word64)(r11 + WC_L64(rsi, 80));
    rdx = (word64)(r9);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r10);
    rax = (word64)(((r8) >> 41) | ((r8) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r8);
    r11 = (word64)(r11 + rax);
    rax = (word64)(((r12) >> 28) | ((r12) << 36));
    rcx = (word64)(((r12) >> 34) | ((r12) << 30));
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r12) >> 39) | ((r12) << 25));
    r11 = (word64)(r11 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r13);
    r15 = (word64)(r15 + r11);
    rdx = (word64)(rdx ^ r12);
    rbx = (word64)(rbx & rdx);
    r11 = (word64)(r11 + rax);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r15) >> 14) | ((r15) << 50));
    rcx = (word64)(((r15) >> 18) | ((r15) << 46));
    r11 = (word64)(r11 + rbx);
    r10 = (word64)(r10 + WC_L64(rsi, 88));
    rbx = (word64)(r8);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r15) >> 41) | ((r15) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r15);
    r10 = (word64)(r10 + rax);
    rax = (word64)(((r11) >> 28) | ((r11) << 36));
    rcx = (word64)(((r11) >> 34) | ((r11) << 30));
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r11) >> 39) | ((r11) << 25));
    r10 = (word64)(r10 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r12);
    r14 = (word64)(r14 + r10);
    rbx = (word64)(rbx ^ r11);
    rdx = (word64)(rdx & rbx);
    r10 = (word64)(r10 + rax);
    rdx = (word64)(rdx ^ r12);
    /* rnd_all_2: 14-15 */
    rax = (word64)(((r14) >> 14) | ((r14) << 50));
    rcx = (word64)(((r14) >> 18) | ((r14) << 46));
    r10 = (word64)(r10 + rdx);
    r9 = (word64)(r9 + WC_L64(rsi, 112));
    rdx = (word64)(r15);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r14) >> 41) | ((r14) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r14);
    r9 = (word64)(r9 + rax);
    rax = (word64)(((r10) >> 28) | ((r10) << 36));
    rcx = (word64)(((r10) >> 34) | ((r10) << 30));
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r10) >> 39) | ((r10) << 25));
    r9 = (word64)(r9 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r11);
    r13 = (word64)(r13 + r9);
    rdx = (word64)(rdx ^ r10);
    rbx = (word64)(rbx & rdx);
    r9 = (word64)(r9 + rax);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r13) >> 14) | ((r13) << 50));
    rcx = (word64)(((r13) >> 18) | ((r13) << 46));
    r9 = (word64)(r9 + rbx);
    r8 = (word64)(r8 + WC_L64(rsi, 120));
    rbx = (word64)(r14);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r13) >> 41) | ((r13) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r13);
    r8 = (word64)(r8 + rax);
    rax = (word64)(((r9) >> 28) | ((r9) << 36));
    rcx = (word64)(((r9) >> 34) | ((r9) << 30));
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r9) >> 39) | ((r9) << 25));
    r8 = (word64)(r8 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r10);
    r12 = (word64)(r12 + r8);
    rbx = (word64)(rbx ^ r9);
    rdx = (word64)(rdx & rbx);
    r8 = (word64)(r8 + rax);
    rdx = (word64)(rdx ^ r10);
    /* rnd_all_2: 18-19 */
    rax = (word64)(((r12) >> 14) | ((r12) << 50));
    rcx = (word64)(((r12) >> 18) | ((r12) << 46));
    r8 = (word64)(r8 + rdx);
    r15 = (word64)(r15 + WC_L64(rsi, 144));
    rdx = (word64)(r13);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r14);
    rax = (word64)(((r12) >> 41) | ((r12) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r12);
    r15 = (word64)(r15 + rax);
    rax = (word64)(((r8) >> 28) | ((r8) << 36));
    rcx = (word64)(((r8) >> 34) | ((r8) << 30));
    rdx = (word64)(rdx ^ r14);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r8) >> 39) | ((r8) << 25));
    r15 = (word64)(r15 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r9);
    r11 = (word64)(r11 + r15);
    rdx = (word64)(rdx ^ r8);
    rbx = (word64)(rbx & rdx);
    r15 = (word64)(r15 + rax);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r11) >> 14) | ((r11) << 50));
    rcx = (word64)(((r11) >> 18) | ((r11) << 46));
    r15 = (word64)(r15 + rbx);
    r14 = (word64)(r14 + WC_L64(rsi, 152));
    rbx = (word64)(r12);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r11) >> 41) | ((r11) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r11);
    r14 = (word64)(r14 + rax);
    rax = (word64)(((r15) >> 28) | ((r15) << 36));
    rcx = (word64)(((r15) >> 34) | ((r15) << 30));
    rbx = (word64)(rbx ^ r13);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r15) >> 39) | ((r15) << 25));
    r14 = (word64)(r14 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r8);
    r10 = (word64)(r10 + r14);
    rbx = (word64)(rbx ^ r15);
    rdx = (word64)(rdx & rbx);
    r14 = (word64)(r14 + rax);
    rdx = (word64)(rdx ^ r8);
    /* rnd_all_2: 22-23 */
    rax = (word64)(((r10) >> 14) | ((r10) << 50));
    rcx = (word64)(((r10) >> 18) | ((r10) << 46));
    r14 = (word64)(r14 + rdx);
    r13 = (word64)(r13 + WC_L64(rsi, 176));
    rdx = (word64)(r11);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r12);
    rax = (word64)(((r10) >> 41) | ((r10) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r10);
    r13 = (word64)(r13 + rax);
    rax = (word64)(((r14) >> 28) | ((r14) << 36));
    rcx = (word64)(((r14) >> 34) | ((r14) << 30));
    rdx = (word64)(rdx ^ r12);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r14) >> 39) | ((r14) << 25));
    r13 = (word64)(r13 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r15);
    r9 = (word64)(r9 + r13);
    rdx = (word64)(rdx ^ r14);
    rbx = (word64)(rbx & rdx);
    r13 = (word64)(r13 + rax);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r9) >> 14) | ((r9) << 50));
    rcx = (word64)(((r9) >> 18) | ((r9) << 46));
    r13 = (word64)(r13 + rbx);
    r12 = (word64)(r12 + WC_L64(rsi, 184));
    rbx = (word64)(r10);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r9) >> 41) | ((r9) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r9);
    r12 = (word64)(r12 + rax);
    rax = (word64)(((r13) >> 28) | ((r13) << 36));
    rcx = (word64)(((r13) >> 34) | ((r13) << 30));
    rbx = (word64)(rbx ^ r11);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r13) >> 39) | ((r13) << 25));
    r12 = (word64)(r12 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r14);
    r8 = (word64)(r8 + r12);
    rbx = (word64)(rbx ^ r13);
    rdx = (word64)(rdx & rbx);
    r12 = (word64)(r12 + rax);
    rdx = (word64)(rdx ^ r14);
    /* rnd_all_2: 26-27 */
    rax = (word64)(((r8) >> 14) | ((r8) << 50));
    rcx = (word64)(((r8) >> 18) | ((r8) << 46));
    r12 = (word64)(r12 + rdx);
    r11 = (word64)(r11 + WC_L64(rsi, 208));
    rdx = (word64)(r9);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r10);
    rax = (word64)(((r8) >> 41) | ((r8) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r8);
    r11 = (word64)(r11 + rax);
    rax = (word64)(((r12) >> 28) | ((r12) << 36));
    rcx = (word64)(((r12) >> 34) | ((r12) << 30));
    rdx = (word64)(rdx ^ r10);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r12) >> 39) | ((r12) << 25));
    r11 = (word64)(r11 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r13);
    r15 = (word64)(r15 + r11);
    rdx = (word64)(rdx ^ r12);
    rbx = (word64)(rbx & rdx);
    r11 = (word64)(r11 + rax);
    rbx = (word64)(rbx ^ r13);
    rax = (word64)(((r15) >> 14) | ((r15) << 50));
    rcx = (word64)(((r15) >> 18) | ((r15) << 46));
    r11 = (word64)(r11 + rbx);
    r10 = (word64)(r10 + WC_L64(rsi, 216));
    rbx = (word64)(r8);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r9);
    rax = (word64)(((r15) >> 41) | ((r15) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r15);
    r10 = (word64)(r10 + rax);
    rax = (word64)(((r11) >> 28) | ((r11) << 36));
    rcx = (word64)(((r11) >> 34) | ((r11) << 30));
    rbx = (word64)(rbx ^ r9);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r11) >> 39) | ((r11) << 25));
    r10 = (word64)(r10 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r12);
    r14 = (word64)(r14 + r10);
    rbx = (word64)(rbx ^ r11);
    rdx = (word64)(rdx & rbx);
    r10 = (word64)(r10 + rax);
    rdx = (word64)(rdx ^ r12);
    /* rnd_all_2: 30-31 */
    rax = (word64)(((r14) >> 14) | ((r14) << 50));
    rcx = (word64)(((r14) >> 18) | ((r14) << 46));
    r10 = (word64)(r10 + rdx);
    r9 = (word64)(r9 + WC_L64(rsi, 240));
    rdx = (word64)(r15);
    rcx = (word64)(rcx ^ rax);
    rdx = (word64)(rdx ^ r8);
    rax = (word64)(((r14) >> 41) | ((r14) << 23));
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(rdx & r14);
    r9 = (word64)(r9 + rax);
    rax = (word64)(((r10) >> 28) | ((r10) << 36));
    rcx = (word64)(((r10) >> 34) | ((r10) << 30));
    rdx = (word64)(rdx ^ r8);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r10) >> 39) | ((r10) << 25));
    r9 = (word64)(r9 + rdx);
    rax = (word64)(rax ^ rcx);
    rdx = (word64)(r11);
    r13 = (word64)(r13 + r9);
    rdx = (word64)(rdx ^ r10);
    rbx = (word64)(rbx & rdx);
    r9 = (word64)(r9 + rax);
    rbx = (word64)(rbx ^ r11);
    rax = (word64)(((r13) >> 14) | ((r13) << 50));
    rcx = (word64)(((r13) >> 18) | ((r13) << 46));
    r9 = (word64)(r9 + rbx);
    r8 = (word64)(r8 + WC_L64(rsi, 248));
    rbx = (word64)(r14);
    rcx = (word64)(rcx ^ rax);
    rbx = (word64)(rbx ^ r15);
    rax = (word64)(((r13) >> 41) | ((r13) << 23));
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(rbx & r13);
    r8 = (word64)(r8 + rax);
    rax = (word64)(((r9) >> 28) | ((r9) << 36));
    rcx = (word64)(((r9) >> 34) | ((r9) << 30));
    rbx = (word64)(rbx ^ r15);
    rcx = (word64)(rcx ^ rax);
    rax = (word64)(((r9) >> 39) | ((r9) << 25));
    r8 = (word64)(r8 + rbx);
    rax = (word64)(rax ^ rcx);
    rbx = (word64)(r10);
    r12 = (word64)(r12 + r8);
    rbx = (word64)(rbx ^ r9);
    rdx = (word64)(rdx & rbx);
    r8 = (word64)(r8 + rax);
    rdx = (word64)(rdx ^ r10);
    rsi = (word64)(rsi + 0x100);
    rbp = (word64)(rbp - 1);
    if ((rbp) != (0)) {
        goto L_sha512_len_avx2_rorx_tail;
    }
    r8 = (word64)(r8 + rdx);
    r8 = (word64)(r8 + WC_L64(rdi, 0));
    r9 = (word64)(r9 + WC_L64(rdi, 8));
    r10 = (word64)(r10 + WC_L64(rdi, 16));
    r11 = (word64)(r11 + WC_L64(rdi, 24));
    r12 = (word64)(r12 + WC_L64(rdi, 32));
    r13 = (word64)(r13 + WC_L64(rdi, 40));
    r14 = (word64)(r14 + WC_L64(rdi, 48));
    r15 = (word64)(r15 + WC_L64(rdi, 56));
    rax = (word64)(WC_L64(rdi, 224));
    rax = (word64)(rax + 0x100);
    WC_S32(rsp, 1344) = (word32)(WC_L32(rsp, 1344) - 0x100);
    zf1 = (word32)WC_S32(rsp, 1344);
    WC_S64(rdi, 224) = (word64)(rax);
    WC_S64(rdi, 0) = (word64)(r8);
    WC_S64(rdi, 8) = (word64)(r9);
    WC_S64(rdi, 16) = (word64)(r10);
    WC_S64(rdi, 24) = (word64)(r11);
    WC_S64(rdi, 32) = (word64)(r12);
    WC_S64(rdi, 40) = (word64)(r13);
    WC_S64(rdi, 48) = (word64)(r14);
    WC_S64(rdi, 56) = (word64)(r15);
    if ((zf1) != (0)) {
        goto L_sha512_len_avx2_rorx_begin;
    }
    rsp = (word64)(rsp + 1352);
L_sha512_len_avx2_rorx_done:
    rax = (word64)(0);
    return (int)(word32)rax;
}

#ifdef WOLFSSL_HAVE_XMSS
#ifndef NO_AVX512_SUPPORT
#ifndef HAVE_INTEL_AVX512
#define HAVE_INTEL_AVX512
#endif /* HAVE_INTEL_AVX512 */
#endif /* NO_AVX512_SUPPORT */
#ifdef HAVE_INTEL_AVX512
XALIGNED(16) static const word32 L_avx512_sha512_x8_bswap_mask[]
    WC_X64I_UNUSED = {
    0xff00ff00, 0xff00ff00, 0xff00ff00, 0xff00ff00,
    0xff00ff00, 0xff00ff00, 0xff00ff00, 0xff00ff00,
    0xff00ff00, 0xff00ff00, 0xff00ff00, 0xff00ff00,
    0xff00ff00, 0xff00ff00, 0xff00ff00, 0xff00ff00,
};

XALIGNED(32) static const word64 L_avx512_sha512_x8_k[] WC_X64I_UNUSED = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL,
    0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL,
    0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL,
    0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL,
    0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL,
    0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL,
    0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL,
    0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL,
    0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL,
    0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

WC_X64I_TARGET("avx,avx512f")
WOLFSSL_LOCAL void Transform_Sha512_x8_AVX512(word64* state,
    const unsigned char* data)
{
    word64 rdi, rsi, rbp, rax;
    __m512i z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14,
            z15, z16, z17, z18, z19, z20, z21, z22, z23, z24, z25, z26, z27,
            z28, z29;

    rdi = (word64)(size_t)state;
    rsi = (word64)(size_t)data;

    z28 = _mm512_loadu_si512((const void*)WC_PR(L_avx512_sha512_x8_bswap_mask,
        0));
    /* W[0..7] of all eight blocks */
    z8 = _mm512_loadu_si512((const void*)WC_PR(rsi, 0));
    z8 = _mm512_shuffle_epi32(z8, 0xb1);
    z29 = _mm512_ror_epi32(z8, 8);
    z8 = _mm512_rol_epi32(z8, 8);
    z8 = _mm512_ternarylogic_epi32(z8, z29, z28, 0xd8);
    z9 = _mm512_loadu_si512((const void*)WC_PR(rsi, 128));
    z9 = _mm512_shuffle_epi32(z9, 0xb1);
    z29 = _mm512_ror_epi32(z9, 8);
    z9 = _mm512_rol_epi32(z9, 8);
    z9 = _mm512_ternarylogic_epi32(z9, z29, z28, 0xd8);
    z10 = _mm512_loadu_si512((const void*)WC_PR(rsi, 256));
    z10 = _mm512_shuffle_epi32(z10, 0xb1);
    z29 = _mm512_ror_epi32(z10, 8);
    z10 = _mm512_rol_epi32(z10, 8);
    z10 = _mm512_ternarylogic_epi32(z10, z29, z28, 0xd8);
    z11 = _mm512_loadu_si512((const void*)WC_PR(rsi, 384));
    z11 = _mm512_shuffle_epi32(z11, 0xb1);
    z29 = _mm512_ror_epi32(z11, 8);
    z11 = _mm512_rol_epi32(z11, 8);
    z11 = _mm512_ternarylogic_epi32(z11, z29, z28, 0xd8);
    z12 = _mm512_loadu_si512((const void*)WC_PR(rsi, 512));
    z12 = _mm512_shuffle_epi32(z12, 0xb1);
    z29 = _mm512_ror_epi32(z12, 8);
    z12 = _mm512_rol_epi32(z12, 8);
    z12 = _mm512_ternarylogic_epi32(z12, z29, z28, 0xd8);
    z13 = _mm512_loadu_si512((const void*)WC_PR(rsi, 640));
    z13 = _mm512_shuffle_epi32(z13, 0xb1);
    z29 = _mm512_ror_epi32(z13, 8);
    z13 = _mm512_rol_epi32(z13, 8);
    z13 = _mm512_ternarylogic_epi32(z13, z29, z28, 0xd8);
    z14 = _mm512_loadu_si512((const void*)WC_PR(rsi, 768));
    z14 = _mm512_shuffle_epi32(z14, 0xb1);
    z29 = _mm512_ror_epi32(z14, 8);
    z14 = _mm512_rol_epi32(z14, 8);
    z14 = _mm512_ternarylogic_epi32(z14, z29, z28, 0xd8);
    z15 = _mm512_loadu_si512((const void*)WC_PR(rsi, 896));
    z15 = _mm512_shuffle_epi32(z15, 0xb1);
    z29 = _mm512_ror_epi32(z15, 8);
    z15 = _mm512_rol_epi32(z15, 8);
    z15 = _mm512_ternarylogic_epi32(z15, z29, z28, 0xd8);
    z29 = _mm512_unpacklo_epi64(z8, z9);
    z9 = _mm512_unpackhi_epi64(z8, z9);
    z8 = z29;
    z29 = _mm512_unpacklo_epi64(z10, z11);
    z11 = _mm512_unpackhi_epi64(z10, z11);
    z10 = z29;
    z29 = _mm512_unpacklo_epi64(z12, z13);
    z13 = _mm512_unpackhi_epi64(z12, z13);
    z12 = z29;
    z29 = _mm512_unpacklo_epi64(z14, z15);
    z15 = _mm512_unpackhi_epi64(z14, z15);
    z14 = z29;
    z29 = _mm512_shuffle_i64x2(z8, z10, 0x88);
    z10 = _mm512_shuffle_i64x2(z8, z10, 0xdd);
    z8 = z29;
    z29 = _mm512_shuffle_i64x2(z9, z11, 0x88);
    z11 = _mm512_shuffle_i64x2(z9, z11, 0xdd);
    z9 = z29;
    z29 = _mm512_shuffle_i64x2(z12, z14, 0x88);
    z14 = _mm512_shuffle_i64x2(z12, z14, 0xdd);
    z12 = z29;
    z29 = _mm512_shuffle_i64x2(z13, z15, 0x88);
    z15 = _mm512_shuffle_i64x2(z13, z15, 0xdd);
    z13 = z29;
    z29 = _mm512_shuffle_i64x2(z8, z12, 0x88);
    z12 = _mm512_shuffle_i64x2(z8, z12, 0xdd);
    z8 = z29;
    z29 = _mm512_shuffle_i64x2(z9, z13, 0x88);
    z13 = _mm512_shuffle_i64x2(z9, z13, 0xdd);
    z9 = z29;
    z29 = _mm512_shuffle_i64x2(z10, z14, 0x88);
    z14 = _mm512_shuffle_i64x2(z10, z14, 0xdd);
    z10 = z29;
    z29 = _mm512_shuffle_i64x2(z11, z15, 0x88);
    z15 = _mm512_shuffle_i64x2(z11, z15, 0xdd);
    z11 = z29;
    /* W[8..15] of all eight blocks */
    z16 = _mm512_loadu_si512((const void*)WC_PR(rsi, 64));
    z16 = _mm512_shuffle_epi32(z16, 0xb1);
    z29 = _mm512_ror_epi32(z16, 8);
    z16 = _mm512_rol_epi32(z16, 8);
    z16 = _mm512_ternarylogic_epi32(z16, z29, z28, 0xd8);
    z17 = _mm512_loadu_si512((const void*)WC_PR(rsi, 192));
    z17 = _mm512_shuffle_epi32(z17, 0xb1);
    z29 = _mm512_ror_epi32(z17, 8);
    z17 = _mm512_rol_epi32(z17, 8);
    z17 = _mm512_ternarylogic_epi32(z17, z29, z28, 0xd8);
    z18 = _mm512_loadu_si512((const void*)WC_PR(rsi, 320));
    z18 = _mm512_shuffle_epi32(z18, 0xb1);
    z29 = _mm512_ror_epi32(z18, 8);
    z18 = _mm512_rol_epi32(z18, 8);
    z18 = _mm512_ternarylogic_epi32(z18, z29, z28, 0xd8);
    z19 = _mm512_loadu_si512((const void*)WC_PR(rsi, 448));
    z19 = _mm512_shuffle_epi32(z19, 0xb1);
    z29 = _mm512_ror_epi32(z19, 8);
    z19 = _mm512_rol_epi32(z19, 8);
    z19 = _mm512_ternarylogic_epi32(z19, z29, z28, 0xd8);
    z20 = _mm512_loadu_si512((const void*)WC_PR(rsi, 576));
    z20 = _mm512_shuffle_epi32(z20, 0xb1);
    z29 = _mm512_ror_epi32(z20, 8);
    z20 = _mm512_rol_epi32(z20, 8);
    z20 = _mm512_ternarylogic_epi32(z20, z29, z28, 0xd8);
    z21 = _mm512_loadu_si512((const void*)WC_PR(rsi, 704));
    z21 = _mm512_shuffle_epi32(z21, 0xb1);
    z29 = _mm512_ror_epi32(z21, 8);
    z21 = _mm512_rol_epi32(z21, 8);
    z21 = _mm512_ternarylogic_epi32(z21, z29, z28, 0xd8);
    z22 = _mm512_loadu_si512((const void*)WC_PR(rsi, 832));
    z22 = _mm512_shuffle_epi32(z22, 0xb1);
    z29 = _mm512_ror_epi32(z22, 8);
    z22 = _mm512_rol_epi32(z22, 8);
    z22 = _mm512_ternarylogic_epi32(z22, z29, z28, 0xd8);
    z23 = _mm512_loadu_si512((const void*)WC_PR(rsi, 960));
    z23 = _mm512_shuffle_epi32(z23, 0xb1);
    z29 = _mm512_ror_epi32(z23, 8);
    z23 = _mm512_rol_epi32(z23, 8);
    z23 = _mm512_ternarylogic_epi32(z23, z29, z28, 0xd8);
    z29 = _mm512_unpacklo_epi64(z16, z17);
    z17 = _mm512_unpackhi_epi64(z16, z17);
    z16 = z29;
    z29 = _mm512_unpacklo_epi64(z18, z19);
    z19 = _mm512_unpackhi_epi64(z18, z19);
    z18 = z29;
    z29 = _mm512_unpacklo_epi64(z20, z21);
    z21 = _mm512_unpackhi_epi64(z20, z21);
    z20 = z29;
    z29 = _mm512_unpacklo_epi64(z22, z23);
    z23 = _mm512_unpackhi_epi64(z22, z23);
    z22 = z29;
    z29 = _mm512_shuffle_i64x2(z16, z18, 0x88);
    z18 = _mm512_shuffle_i64x2(z16, z18, 0xdd);
    z16 = z29;
    z29 = _mm512_shuffle_i64x2(z17, z19, 0x88);
    z19 = _mm512_shuffle_i64x2(z17, z19, 0xdd);
    z17 = z29;
    z29 = _mm512_shuffle_i64x2(z20, z22, 0x88);
    z22 = _mm512_shuffle_i64x2(z20, z22, 0xdd);
    z20 = z29;
    z29 = _mm512_shuffle_i64x2(z21, z23, 0x88);
    z23 = _mm512_shuffle_i64x2(z21, z23, 0xdd);
    z21 = z29;
    z29 = _mm512_shuffle_i64x2(z16, z20, 0x88);
    z20 = _mm512_shuffle_i64x2(z16, z20, 0xdd);
    z16 = z29;
    z29 = _mm512_shuffle_i64x2(z17, z21, 0x88);
    z21 = _mm512_shuffle_i64x2(z17, z21, 0xdd);
    z17 = z29;
    z29 = _mm512_shuffle_i64x2(z18, z22, 0x88);
    z22 = _mm512_shuffle_i64x2(z18, z22, 0xdd);
    z18 = z29;
    z29 = _mm512_shuffle_i64x2(z19, z23, 0x88);
    z23 = _mm512_shuffle_i64x2(z19, z23, 0xdd);
    z19 = z29;
    /* Load the eight lane-interleaved states */
    z0 = _mm512_loadu_si512((const void*)WC_PR(rdi, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(rdi, 64));
    z2 = _mm512_loadu_si512((const void*)WC_PR(rdi, 128));
    z3 = _mm512_loadu_si512((const void*)WC_PR(rdi, 192));
    z4 = _mm512_loadu_si512((const void*)WC_PR(rdi, 256));
    z5 = _mm512_loadu_si512((const void*)WC_PR(rdi, 320));
    z6 = _mm512_loadu_si512((const void*)WC_PR(rdi, 384));
    z7 = _mm512_loadu_si512((const void*)WC_PR(rdi, 448));
    rbp = (word64)((word64)(size_t)L_avx512_sha512_x8_k);
    /* Rounds 0-15: the schedule is the message block itself */
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 0)));
    z7 = _mm512_add_epi64(z7, z8);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 8)));
    z6 = _mm512_add_epi64(z6, z9);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 16)));
    z5 = _mm512_add_epi64(z5, z10);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 24)));
    z4 = _mm512_add_epi64(z4, z11);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 32)));
    z3 = _mm512_add_epi64(z3, z12);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 40)));
    z2 = _mm512_add_epi64(z2, z13);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 48)));
    z1 = _mm512_add_epi64(z1, z14);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 56)));
    z0 = _mm512_add_epi64(z0, z15);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 64)));
    z7 = _mm512_add_epi64(z7, z16);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 72)));
    z6 = _mm512_add_epi64(z6, z17);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 80)));
    z5 = _mm512_add_epi64(z5, z18);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 88)));
    z4 = _mm512_add_epi64(z4, z19);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 96)));
    z3 = _mm512_add_epi64(z3, z20);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 104)));
    z2 = _mm512_add_epi64(z2, z21);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 112)));
    z1 = _mm512_add_epi64(z1, z22);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 120)));
    z0 = _mm512_add_epi64(z0, z23);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    rbp = (word64)(rbp + 0x80);
    rax = (word32)(4);
L_sha512_x8_avx512_start:
    z24 = _mm512_ror_epi64(z9, 1);
    z25 = _mm512_ror_epi64(z9, 8);
    z26 = _mm512_srli_epi64(z9, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z22, 19);
    z26 = _mm512_ror_epi64(z22, 61);
    z27 = _mm512_srli_epi64(z22, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z8 = _mm512_add_epi64(z8, z24);
    z8 = _mm512_add_epi64(z8, z25);
    z8 = _mm512_add_epi64(z8, z17);
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 0)));
    z7 = _mm512_add_epi64(z7, z8);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z10, 1);
    z25 = _mm512_ror_epi64(z10, 8);
    z26 = _mm512_srli_epi64(z10, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z23, 19);
    z26 = _mm512_ror_epi64(z23, 61);
    z27 = _mm512_srli_epi64(z23, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z9 = _mm512_add_epi64(z9, z24);
    z9 = _mm512_add_epi64(z9, z25);
    z9 = _mm512_add_epi64(z9, z18);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 8)));
    z6 = _mm512_add_epi64(z6, z9);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z11, 1);
    z25 = _mm512_ror_epi64(z11, 8);
    z26 = _mm512_srli_epi64(z11, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z8, 19);
    z26 = _mm512_ror_epi64(z8, 61);
    z27 = _mm512_srli_epi64(z8, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z10 = _mm512_add_epi64(z10, z24);
    z10 = _mm512_add_epi64(z10, z25);
    z10 = _mm512_add_epi64(z10, z19);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 16)));
    z5 = _mm512_add_epi64(z5, z10);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z12, 1);
    z25 = _mm512_ror_epi64(z12, 8);
    z26 = _mm512_srli_epi64(z12, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z9, 19);
    z26 = _mm512_ror_epi64(z9, 61);
    z27 = _mm512_srli_epi64(z9, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z11 = _mm512_add_epi64(z11, z24);
    z11 = _mm512_add_epi64(z11, z25);
    z11 = _mm512_add_epi64(z11, z20);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 24)));
    z4 = _mm512_add_epi64(z4, z11);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z13, 1);
    z25 = _mm512_ror_epi64(z13, 8);
    z26 = _mm512_srli_epi64(z13, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z10, 19);
    z26 = _mm512_ror_epi64(z10, 61);
    z27 = _mm512_srli_epi64(z10, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z12 = _mm512_add_epi64(z12, z24);
    z12 = _mm512_add_epi64(z12, z25);
    z12 = _mm512_add_epi64(z12, z21);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 32)));
    z3 = _mm512_add_epi64(z3, z12);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z14, 1);
    z25 = _mm512_ror_epi64(z14, 8);
    z26 = _mm512_srli_epi64(z14, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z11, 19);
    z26 = _mm512_ror_epi64(z11, 61);
    z27 = _mm512_srli_epi64(z11, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z13 = _mm512_add_epi64(z13, z24);
    z13 = _mm512_add_epi64(z13, z25);
    z13 = _mm512_add_epi64(z13, z22);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 40)));
    z2 = _mm512_add_epi64(z2, z13);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z15, 1);
    z25 = _mm512_ror_epi64(z15, 8);
    z26 = _mm512_srli_epi64(z15, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z12, 19);
    z26 = _mm512_ror_epi64(z12, 61);
    z27 = _mm512_srli_epi64(z12, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z14 = _mm512_add_epi64(z14, z24);
    z14 = _mm512_add_epi64(z14, z25);
    z14 = _mm512_add_epi64(z14, z23);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 48)));
    z1 = _mm512_add_epi64(z1, z14);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z16, 1);
    z25 = _mm512_ror_epi64(z16, 8);
    z26 = _mm512_srli_epi64(z16, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z13, 19);
    z26 = _mm512_ror_epi64(z13, 61);
    z27 = _mm512_srli_epi64(z13, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z15 = _mm512_add_epi64(z15, z24);
    z15 = _mm512_add_epi64(z15, z25);
    z15 = _mm512_add_epi64(z15, z8);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 56)));
    z0 = _mm512_add_epi64(z0, z15);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z17, 1);
    z25 = _mm512_ror_epi64(z17, 8);
    z26 = _mm512_srli_epi64(z17, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z14, 19);
    z26 = _mm512_ror_epi64(z14, 61);
    z27 = _mm512_srli_epi64(z14, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z16 = _mm512_add_epi64(z16, z24);
    z16 = _mm512_add_epi64(z16, z25);
    z16 = _mm512_add_epi64(z16, z9);
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 64)));
    z7 = _mm512_add_epi64(z7, z16);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z18, 1);
    z25 = _mm512_ror_epi64(z18, 8);
    z26 = _mm512_srli_epi64(z18, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z15, 19);
    z26 = _mm512_ror_epi64(z15, 61);
    z27 = _mm512_srli_epi64(z15, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z17 = _mm512_add_epi64(z17, z24);
    z17 = _mm512_add_epi64(z17, z25);
    z17 = _mm512_add_epi64(z17, z10);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 72)));
    z6 = _mm512_add_epi64(z6, z17);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z19, 1);
    z25 = _mm512_ror_epi64(z19, 8);
    z26 = _mm512_srli_epi64(z19, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z16, 19);
    z26 = _mm512_ror_epi64(z16, 61);
    z27 = _mm512_srli_epi64(z16, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z18 = _mm512_add_epi64(z18, z24);
    z18 = _mm512_add_epi64(z18, z25);
    z18 = _mm512_add_epi64(z18, z11);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 80)));
    z5 = _mm512_add_epi64(z5, z18);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z20, 1);
    z25 = _mm512_ror_epi64(z20, 8);
    z26 = _mm512_srli_epi64(z20, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z17, 19);
    z26 = _mm512_ror_epi64(z17, 61);
    z27 = _mm512_srli_epi64(z17, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z19 = _mm512_add_epi64(z19, z24);
    z19 = _mm512_add_epi64(z19, z25);
    z19 = _mm512_add_epi64(z19, z12);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 88)));
    z4 = _mm512_add_epi64(z4, z19);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z21, 1);
    z25 = _mm512_ror_epi64(z21, 8);
    z26 = _mm512_srli_epi64(z21, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z18, 19);
    z26 = _mm512_ror_epi64(z18, 61);
    z27 = _mm512_srli_epi64(z18, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z20 = _mm512_add_epi64(z20, z24);
    z20 = _mm512_add_epi64(z20, z25);
    z20 = _mm512_add_epi64(z20, z13);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 96)));
    z3 = _mm512_add_epi64(z3, z20);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z22, 1);
    z25 = _mm512_ror_epi64(z22, 8);
    z26 = _mm512_srli_epi64(z22, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z19, 19);
    z26 = _mm512_ror_epi64(z19, 61);
    z27 = _mm512_srli_epi64(z19, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z21 = _mm512_add_epi64(z21, z24);
    z21 = _mm512_add_epi64(z21, z25);
    z21 = _mm512_add_epi64(z21, z14);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 104)));
    z2 = _mm512_add_epi64(z2, z21);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z23, 1);
    z25 = _mm512_ror_epi64(z23, 8);
    z26 = _mm512_srli_epi64(z23, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z20, 19);
    z26 = _mm512_ror_epi64(z20, 61);
    z27 = _mm512_srli_epi64(z20, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z22 = _mm512_add_epi64(z22, z24);
    z22 = _mm512_add_epi64(z22, z25);
    z22 = _mm512_add_epi64(z22, z15);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 112)));
    z1 = _mm512_add_epi64(z1, z22);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z8, 1);
    z25 = _mm512_ror_epi64(z8, 8);
    z26 = _mm512_srli_epi64(z8, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z21, 19);
    z26 = _mm512_ror_epi64(z21, 61);
    z27 = _mm512_srli_epi64(z21, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z23 = _mm512_add_epi64(z23, z24);
    z23 = _mm512_add_epi64(z23, z25);
    z23 = _mm512_add_epi64(z23, z16);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 120)));
    z0 = _mm512_add_epi64(z0, z23);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    rbp = (word64)(rbp + 0x80);
    rax = (word32)((word32)rax - 1);
    if (((word32)rax) != (0)) {
        goto L_sha512_x8_avx512_start;
    }
    /* Add the compressed block into the states */
    z0 = _mm512_add_epi64(z0, _mm512_loadu_si512((const void*)WC_PR(rdi, 0)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 0), z0);
    z1 = _mm512_add_epi64(z1, _mm512_loadu_si512((const void*)WC_PR(rdi, 64)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 64), z1);
    z2 = _mm512_add_epi64(z2, _mm512_loadu_si512((const void*)WC_PR(rdi, 128)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 128), z2);
    z3 = _mm512_add_epi64(z3, _mm512_loadu_si512((const void*)WC_PR(rdi, 192)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 192), z3);
    z4 = _mm512_add_epi64(z4, _mm512_loadu_si512((const void*)WC_PR(rdi, 256)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 256), z4);
    z5 = _mm512_add_epi64(z5, _mm512_loadu_si512((const void*)WC_PR(rdi, 320)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 320), z5);
    z6 = _mm512_add_epi64(z6, _mm512_loadu_si512((const void*)WC_PR(rdi, 384)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 384), z6);
    z7 = _mm512_add_epi64(z7, _mm512_loadu_si512((const void*)WC_PR(rdi, 448)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 448), z7);
}

#if !defined(NO_AVX512BW_SUPPORT)
XALIGNED(32) static const word64 L_avx512_sha512_x8_flip_mask[]
    WC_X64I_UNUSED = {
    0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL,
    0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL,
    0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL,
    0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL,
};

WC_X64I_TARGET("avx,avx512f,avx512bw")
WOLFSSL_LOCAL void Transform_Sha512_x8_AVX512_BW(word64* state,
    const unsigned char* data)
{
    word64 rdi, rsi, rbp, rax;
    __m512i z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14,
            z15, z16, z17, z18, z19, z20, z21, z22, z23, z24, z25, z26, z27,
            z28, z29;

    rdi = (word64)(size_t)state;
    rsi = (word64)(size_t)data;

    z28 = _mm512_loadu_si512((const void*)WC_PR(L_avx512_sha512_x8_flip_mask,
        0));
    /* W[0..7] of all eight blocks */
    z8 = _mm512_loadu_si512((const void*)WC_PR(rsi, 0));
    z8 = _mm512_shuffle_epi8(z8, z28);
    z9 = _mm512_loadu_si512((const void*)WC_PR(rsi, 128));
    z9 = _mm512_shuffle_epi8(z9, z28);
    z10 = _mm512_loadu_si512((const void*)WC_PR(rsi, 256));
    z10 = _mm512_shuffle_epi8(z10, z28);
    z11 = _mm512_loadu_si512((const void*)WC_PR(rsi, 384));
    z11 = _mm512_shuffle_epi8(z11, z28);
    z12 = _mm512_loadu_si512((const void*)WC_PR(rsi, 512));
    z12 = _mm512_shuffle_epi8(z12, z28);
    z13 = _mm512_loadu_si512((const void*)WC_PR(rsi, 640));
    z13 = _mm512_shuffle_epi8(z13, z28);
    z14 = _mm512_loadu_si512((const void*)WC_PR(rsi, 768));
    z14 = _mm512_shuffle_epi8(z14, z28);
    z15 = _mm512_loadu_si512((const void*)WC_PR(rsi, 896));
    z15 = _mm512_shuffle_epi8(z15, z28);
    z29 = _mm512_unpacklo_epi64(z8, z9);
    z9 = _mm512_unpackhi_epi64(z8, z9);
    z8 = z29;
    z29 = _mm512_unpacklo_epi64(z10, z11);
    z11 = _mm512_unpackhi_epi64(z10, z11);
    z10 = z29;
    z29 = _mm512_unpacklo_epi64(z12, z13);
    z13 = _mm512_unpackhi_epi64(z12, z13);
    z12 = z29;
    z29 = _mm512_unpacklo_epi64(z14, z15);
    z15 = _mm512_unpackhi_epi64(z14, z15);
    z14 = z29;
    z29 = _mm512_shuffle_i64x2(z8, z10, 0x88);
    z10 = _mm512_shuffle_i64x2(z8, z10, 0xdd);
    z8 = z29;
    z29 = _mm512_shuffle_i64x2(z9, z11, 0x88);
    z11 = _mm512_shuffle_i64x2(z9, z11, 0xdd);
    z9 = z29;
    z29 = _mm512_shuffle_i64x2(z12, z14, 0x88);
    z14 = _mm512_shuffle_i64x2(z12, z14, 0xdd);
    z12 = z29;
    z29 = _mm512_shuffle_i64x2(z13, z15, 0x88);
    z15 = _mm512_shuffle_i64x2(z13, z15, 0xdd);
    z13 = z29;
    z29 = _mm512_shuffle_i64x2(z8, z12, 0x88);
    z12 = _mm512_shuffle_i64x2(z8, z12, 0xdd);
    z8 = z29;
    z29 = _mm512_shuffle_i64x2(z9, z13, 0x88);
    z13 = _mm512_shuffle_i64x2(z9, z13, 0xdd);
    z9 = z29;
    z29 = _mm512_shuffle_i64x2(z10, z14, 0x88);
    z14 = _mm512_shuffle_i64x2(z10, z14, 0xdd);
    z10 = z29;
    z29 = _mm512_shuffle_i64x2(z11, z15, 0x88);
    z15 = _mm512_shuffle_i64x2(z11, z15, 0xdd);
    z11 = z29;
    /* W[8..15] of all eight blocks */
    z16 = _mm512_loadu_si512((const void*)WC_PR(rsi, 64));
    z16 = _mm512_shuffle_epi8(z16, z28);
    z17 = _mm512_loadu_si512((const void*)WC_PR(rsi, 192));
    z17 = _mm512_shuffle_epi8(z17, z28);
    z18 = _mm512_loadu_si512((const void*)WC_PR(rsi, 320));
    z18 = _mm512_shuffle_epi8(z18, z28);
    z19 = _mm512_loadu_si512((const void*)WC_PR(rsi, 448));
    z19 = _mm512_shuffle_epi8(z19, z28);
    z20 = _mm512_loadu_si512((const void*)WC_PR(rsi, 576));
    z20 = _mm512_shuffle_epi8(z20, z28);
    z21 = _mm512_loadu_si512((const void*)WC_PR(rsi, 704));
    z21 = _mm512_shuffle_epi8(z21, z28);
    z22 = _mm512_loadu_si512((const void*)WC_PR(rsi, 832));
    z22 = _mm512_shuffle_epi8(z22, z28);
    z23 = _mm512_loadu_si512((const void*)WC_PR(rsi, 960));
    z23 = _mm512_shuffle_epi8(z23, z28);
    z29 = _mm512_unpacklo_epi64(z16, z17);
    z17 = _mm512_unpackhi_epi64(z16, z17);
    z16 = z29;
    z29 = _mm512_unpacklo_epi64(z18, z19);
    z19 = _mm512_unpackhi_epi64(z18, z19);
    z18 = z29;
    z29 = _mm512_unpacklo_epi64(z20, z21);
    z21 = _mm512_unpackhi_epi64(z20, z21);
    z20 = z29;
    z29 = _mm512_unpacklo_epi64(z22, z23);
    z23 = _mm512_unpackhi_epi64(z22, z23);
    z22 = z29;
    z29 = _mm512_shuffle_i64x2(z16, z18, 0x88);
    z18 = _mm512_shuffle_i64x2(z16, z18, 0xdd);
    z16 = z29;
    z29 = _mm512_shuffle_i64x2(z17, z19, 0x88);
    z19 = _mm512_shuffle_i64x2(z17, z19, 0xdd);
    z17 = z29;
    z29 = _mm512_shuffle_i64x2(z20, z22, 0x88);
    z22 = _mm512_shuffle_i64x2(z20, z22, 0xdd);
    z20 = z29;
    z29 = _mm512_shuffle_i64x2(z21, z23, 0x88);
    z23 = _mm512_shuffle_i64x2(z21, z23, 0xdd);
    z21 = z29;
    z29 = _mm512_shuffle_i64x2(z16, z20, 0x88);
    z20 = _mm512_shuffle_i64x2(z16, z20, 0xdd);
    z16 = z29;
    z29 = _mm512_shuffle_i64x2(z17, z21, 0x88);
    z21 = _mm512_shuffle_i64x2(z17, z21, 0xdd);
    z17 = z29;
    z29 = _mm512_shuffle_i64x2(z18, z22, 0x88);
    z22 = _mm512_shuffle_i64x2(z18, z22, 0xdd);
    z18 = z29;
    z29 = _mm512_shuffle_i64x2(z19, z23, 0x88);
    z23 = _mm512_shuffle_i64x2(z19, z23, 0xdd);
    z19 = z29;
    /* Load the eight lane-interleaved states */
    z0 = _mm512_loadu_si512((const void*)WC_PR(rdi, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(rdi, 64));
    z2 = _mm512_loadu_si512((const void*)WC_PR(rdi, 128));
    z3 = _mm512_loadu_si512((const void*)WC_PR(rdi, 192));
    z4 = _mm512_loadu_si512((const void*)WC_PR(rdi, 256));
    z5 = _mm512_loadu_si512((const void*)WC_PR(rdi, 320));
    z6 = _mm512_loadu_si512((const void*)WC_PR(rdi, 384));
    z7 = _mm512_loadu_si512((const void*)WC_PR(rdi, 448));
    rbp = (word64)((word64)(size_t)L_avx512_sha512_x8_k);
    /* Rounds 0-15: the schedule is the message block itself */
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 0)));
    z7 = _mm512_add_epi64(z7, z8);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 8)));
    z6 = _mm512_add_epi64(z6, z9);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 16)));
    z5 = _mm512_add_epi64(z5, z10);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 24)));
    z4 = _mm512_add_epi64(z4, z11);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 32)));
    z3 = _mm512_add_epi64(z3, z12);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 40)));
    z2 = _mm512_add_epi64(z2, z13);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 48)));
    z1 = _mm512_add_epi64(z1, z14);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 56)));
    z0 = _mm512_add_epi64(z0, z15);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 64)));
    z7 = _mm512_add_epi64(z7, z16);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 72)));
    z6 = _mm512_add_epi64(z6, z17);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 80)));
    z5 = _mm512_add_epi64(z5, z18);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 88)));
    z4 = _mm512_add_epi64(z4, z19);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 96)));
    z3 = _mm512_add_epi64(z3, z20);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 104)));
    z2 = _mm512_add_epi64(z2, z21);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 112)));
    z1 = _mm512_add_epi64(z1, z22);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 120)));
    z0 = _mm512_add_epi64(z0, z23);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    rbp = (word64)(rbp + 0x80);
    rax = (word32)(4);
L_sha512_x8_avx512_bw_start:
    z24 = _mm512_ror_epi64(z9, 1);
    z25 = _mm512_ror_epi64(z9, 8);
    z26 = _mm512_srli_epi64(z9, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z22, 19);
    z26 = _mm512_ror_epi64(z22, 61);
    z27 = _mm512_srli_epi64(z22, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z8 = _mm512_add_epi64(z8, z24);
    z8 = _mm512_add_epi64(z8, z25);
    z8 = _mm512_add_epi64(z8, z17);
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 0)));
    z7 = _mm512_add_epi64(z7, z8);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z10, 1);
    z25 = _mm512_ror_epi64(z10, 8);
    z26 = _mm512_srli_epi64(z10, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z23, 19);
    z26 = _mm512_ror_epi64(z23, 61);
    z27 = _mm512_srli_epi64(z23, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z9 = _mm512_add_epi64(z9, z24);
    z9 = _mm512_add_epi64(z9, z25);
    z9 = _mm512_add_epi64(z9, z18);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 8)));
    z6 = _mm512_add_epi64(z6, z9);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z11, 1);
    z25 = _mm512_ror_epi64(z11, 8);
    z26 = _mm512_srli_epi64(z11, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z8, 19);
    z26 = _mm512_ror_epi64(z8, 61);
    z27 = _mm512_srli_epi64(z8, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z10 = _mm512_add_epi64(z10, z24);
    z10 = _mm512_add_epi64(z10, z25);
    z10 = _mm512_add_epi64(z10, z19);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 16)));
    z5 = _mm512_add_epi64(z5, z10);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z12, 1);
    z25 = _mm512_ror_epi64(z12, 8);
    z26 = _mm512_srli_epi64(z12, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z9, 19);
    z26 = _mm512_ror_epi64(z9, 61);
    z27 = _mm512_srli_epi64(z9, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z11 = _mm512_add_epi64(z11, z24);
    z11 = _mm512_add_epi64(z11, z25);
    z11 = _mm512_add_epi64(z11, z20);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 24)));
    z4 = _mm512_add_epi64(z4, z11);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z13, 1);
    z25 = _mm512_ror_epi64(z13, 8);
    z26 = _mm512_srli_epi64(z13, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z10, 19);
    z26 = _mm512_ror_epi64(z10, 61);
    z27 = _mm512_srli_epi64(z10, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z12 = _mm512_add_epi64(z12, z24);
    z12 = _mm512_add_epi64(z12, z25);
    z12 = _mm512_add_epi64(z12, z21);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 32)));
    z3 = _mm512_add_epi64(z3, z12);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z14, 1);
    z25 = _mm512_ror_epi64(z14, 8);
    z26 = _mm512_srli_epi64(z14, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z11, 19);
    z26 = _mm512_ror_epi64(z11, 61);
    z27 = _mm512_srli_epi64(z11, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z13 = _mm512_add_epi64(z13, z24);
    z13 = _mm512_add_epi64(z13, z25);
    z13 = _mm512_add_epi64(z13, z22);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 40)));
    z2 = _mm512_add_epi64(z2, z13);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z15, 1);
    z25 = _mm512_ror_epi64(z15, 8);
    z26 = _mm512_srli_epi64(z15, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z12, 19);
    z26 = _mm512_ror_epi64(z12, 61);
    z27 = _mm512_srli_epi64(z12, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z14 = _mm512_add_epi64(z14, z24);
    z14 = _mm512_add_epi64(z14, z25);
    z14 = _mm512_add_epi64(z14, z23);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 48)));
    z1 = _mm512_add_epi64(z1, z14);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z16, 1);
    z25 = _mm512_ror_epi64(z16, 8);
    z26 = _mm512_srli_epi64(z16, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z13, 19);
    z26 = _mm512_ror_epi64(z13, 61);
    z27 = _mm512_srli_epi64(z13, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z15 = _mm512_add_epi64(z15, z24);
    z15 = _mm512_add_epi64(z15, z25);
    z15 = _mm512_add_epi64(z15, z8);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 56)));
    z0 = _mm512_add_epi64(z0, z15);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z17, 1);
    z25 = _mm512_ror_epi64(z17, 8);
    z26 = _mm512_srli_epi64(z17, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z14, 19);
    z26 = _mm512_ror_epi64(z14, 61);
    z27 = _mm512_srli_epi64(z14, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z16 = _mm512_add_epi64(z16, z24);
    z16 = _mm512_add_epi64(z16, z25);
    z16 = _mm512_add_epi64(z16, z9);
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 64)));
    z7 = _mm512_add_epi64(z7, z16);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z18, 1);
    z25 = _mm512_ror_epi64(z18, 8);
    z26 = _mm512_srli_epi64(z18, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z15, 19);
    z26 = _mm512_ror_epi64(z15, 61);
    z27 = _mm512_srli_epi64(z15, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z17 = _mm512_add_epi64(z17, z24);
    z17 = _mm512_add_epi64(z17, z25);
    z17 = _mm512_add_epi64(z17, z10);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 72)));
    z6 = _mm512_add_epi64(z6, z17);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z19, 1);
    z25 = _mm512_ror_epi64(z19, 8);
    z26 = _mm512_srli_epi64(z19, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z16, 19);
    z26 = _mm512_ror_epi64(z16, 61);
    z27 = _mm512_srli_epi64(z16, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z18 = _mm512_add_epi64(z18, z24);
    z18 = _mm512_add_epi64(z18, z25);
    z18 = _mm512_add_epi64(z18, z11);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 80)));
    z5 = _mm512_add_epi64(z5, z18);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z20, 1);
    z25 = _mm512_ror_epi64(z20, 8);
    z26 = _mm512_srli_epi64(z20, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z17, 19);
    z26 = _mm512_ror_epi64(z17, 61);
    z27 = _mm512_srli_epi64(z17, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z19 = _mm512_add_epi64(z19, z24);
    z19 = _mm512_add_epi64(z19, z25);
    z19 = _mm512_add_epi64(z19, z12);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 88)));
    z4 = _mm512_add_epi64(z4, z19);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z21, 1);
    z25 = _mm512_ror_epi64(z21, 8);
    z26 = _mm512_srli_epi64(z21, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z18, 19);
    z26 = _mm512_ror_epi64(z18, 61);
    z27 = _mm512_srli_epi64(z18, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z20 = _mm512_add_epi64(z20, z24);
    z20 = _mm512_add_epi64(z20, z25);
    z20 = _mm512_add_epi64(z20, z13);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 96)));
    z3 = _mm512_add_epi64(z3, z20);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z22, 1);
    z25 = _mm512_ror_epi64(z22, 8);
    z26 = _mm512_srli_epi64(z22, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z19, 19);
    z26 = _mm512_ror_epi64(z19, 61);
    z27 = _mm512_srli_epi64(z19, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z21 = _mm512_add_epi64(z21, z24);
    z21 = _mm512_add_epi64(z21, z25);
    z21 = _mm512_add_epi64(z21, z14);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 104)));
    z2 = _mm512_add_epi64(z2, z21);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z23, 1);
    z25 = _mm512_ror_epi64(z23, 8);
    z26 = _mm512_srli_epi64(z23, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z20, 19);
    z26 = _mm512_ror_epi64(z20, 61);
    z27 = _mm512_srli_epi64(z20, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z22 = _mm512_add_epi64(z22, z24);
    z22 = _mm512_add_epi64(z22, z25);
    z22 = _mm512_add_epi64(z22, z15);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 112)));
    z1 = _mm512_add_epi64(z1, z22);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z8, 1);
    z25 = _mm512_ror_epi64(z8, 8);
    z26 = _mm512_srli_epi64(z8, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z21, 19);
    z26 = _mm512_ror_epi64(z21, 61);
    z27 = _mm512_srli_epi64(z21, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z23 = _mm512_add_epi64(z23, z24);
    z23 = _mm512_add_epi64(z23, z25);
    z23 = _mm512_add_epi64(z23, z16);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 120)));
    z0 = _mm512_add_epi64(z0, z23);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    rbp = (word64)(rbp + 0x80);
    rax = (word32)((word32)rax - 1);
    if (((word32)rax) != (0)) {
        goto L_sha512_x8_avx512_bw_start;
    }
    /* Add the compressed block into the states */
    z0 = _mm512_add_epi64(z0, _mm512_loadu_si512((const void*)WC_PR(rdi, 0)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 0), z0);
    z1 = _mm512_add_epi64(z1, _mm512_loadu_si512((const void*)WC_PR(rdi, 64)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 64), z1);
    z2 = _mm512_add_epi64(z2, _mm512_loadu_si512((const void*)WC_PR(rdi, 128)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 128), z2);
    z3 = _mm512_add_epi64(z3, _mm512_loadu_si512((const void*)WC_PR(rdi, 192)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 192), z3);
    z4 = _mm512_add_epi64(z4, _mm512_loadu_si512((const void*)WC_PR(rdi, 256)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 256), z4);
    z5 = _mm512_add_epi64(z5, _mm512_loadu_si512((const void*)WC_PR(rdi, 320)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 320), z5);
    z6 = _mm512_add_epi64(z6, _mm512_loadu_si512((const void*)WC_PR(rdi, 384)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 384), z6);
    z7 = _mm512_add_epi64(z7, _mm512_loadu_si512((const void*)WC_PR(rdi, 448)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 448), z7);
}

#endif /* !defined(NO_AVX512BW_SUPPORT) */
#ifdef WOLFSSL_HAVE_XMSS
XALIGNED(32) static const word64 L_avx512_sha512_x8_iv[] WC_X64I_UNUSED = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

XALIGNED(16) static const word64 L_avx512_sha512_x8_pad80q[] WC_X64I_UNUSED = {
    0x8000000000000000ULL,
};

XALIGNED(16) static const word64 L_avx512_sha512_x8_len1280[] WC_X64I_UNUSED = {
    0x0000000000000500ULL,
};

XALIGNED(16) static const word64 L_avx512_sha512_x8_len1536[] WC_X64I_UNUSED = {
    0x0000000000000600ULL,
};

XALIGNED(16) static const word64 L_avx512_sha512_x8_hi32[] WC_X64I_UNUSED = {
    0xffffffff00000000ULL,
};

XALIGNED(16) static const word64 L_avx512_sha512_x8_lo32[] WC_X64I_UNUSED = {
    0x00000000ffffffffULL,
};

WC_X64I_TARGET("avx512f")
WOLFSSL_LOCAL void Transform_Sha512_x8_XmssPrf_AVX512(word64* out,
    const word64* mid, const word64* adrs, const word32* chainv,
    const word32* hashv)
{
    word64 rdi, rsi, rdx, rcx, r8, rbp, rax;
    __m512i z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14,
            z15, z16, z17, z18, z19, z20, z21, z22, z23, z24, z25, z26, z27;

    rdi = (word64)(size_t)out;
    rsi = (word64)(size_t)mid;
    rdx = (word64)(size_t)adrs;
    rcx = (word64)(size_t)chainv;
    r8 = (word64)(size_t)hashv;

    rbp = (word64)((word64)(size_t)L_avx512_sha512_x8_k);
    z8 = _mm512_set1_epi64((long long)WC_L64(rdx, 0));
    z9 = _mm512_set1_epi64((long long)WC_L64(rdx, 8));
    /* Word 2: the OTS address, then the chain address under it */
    z10 = _mm512_set1_epi64((long long)WC_L64(rdx, 16));
    z25 = _mm512_set1_epi64((long long)WC_L64(L_avx512_sha512_x8_hi32, 0));
    z10 = _mm512_and_si512(z10, z25);
    z24 = _mm512_cvtepu32_epi64(_mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        0)));
    z10 = _mm512_or_si512(z10, z24);
    /* Word 3: the key-and-mask word, then the hash address over it */
    z11 = _mm512_set1_epi64((long long)WC_L64(rdx, 24));
    z25 = _mm512_set1_epi64((long long)WC_L64(L_avx512_sha512_x8_lo32, 0));
    z11 = _mm512_and_si512(z11, z25);
    z24 = _mm512_cvtepu32_epi64(_mm256_loadu_si256((const __m256i*)WC_PR(r8,
        0)));
    z24 = _mm512_slli_epi64(z24, 32);
    z11 = _mm512_or_si512(z11, z24);
    /* Padding for a 160-byte message, the last 128 of it this block */
    z12 = _mm512_set1_epi64((long long)WC_L64(L_avx512_sha512_x8_pad80q, 0));
    z13 = _mm512_setzero_si512();
    z14 = _mm512_setzero_si512();
    z15 = _mm512_setzero_si512();
    z16 = _mm512_setzero_si512();
    z17 = _mm512_setzero_si512();
    z18 = _mm512_setzero_si512();
    z19 = _mm512_setzero_si512();
    z20 = _mm512_setzero_si512();
    z21 = _mm512_setzero_si512();
    z22 = _mm512_setzero_si512();
    z23 = _mm512_set1_epi64((long long)WC_L64(L_avx512_sha512_x8_len1280, 0));
    /* Carry on from the state padding || SEED left behind */
    z0 = _mm512_set1_epi64((long long)WC_L64(rsi, 0));
    z1 = _mm512_set1_epi64((long long)WC_L64(rsi, 8));
    z2 = _mm512_set1_epi64((long long)WC_L64(rsi, 16));
    z3 = _mm512_set1_epi64((long long)WC_L64(rsi, 24));
    z4 = _mm512_set1_epi64((long long)WC_L64(rsi, 32));
    z5 = _mm512_set1_epi64((long long)WC_L64(rsi, 40));
    z6 = _mm512_set1_epi64((long long)WC_L64(rsi, 48));
    z7 = _mm512_set1_epi64((long long)WC_L64(rsi, 56));
    /* Rounds 0-15: the schedule is the message block itself */
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 0)));
    z7 = _mm512_add_epi64(z7, z8);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 8)));
    z6 = _mm512_add_epi64(z6, z9);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 16)));
    z5 = _mm512_add_epi64(z5, z10);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 24)));
    z4 = _mm512_add_epi64(z4, z11);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 32)));
    z3 = _mm512_add_epi64(z3, z12);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 40)));
    z2 = _mm512_add_epi64(z2, z13);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 48)));
    z1 = _mm512_add_epi64(z1, z14);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 56)));
    z0 = _mm512_add_epi64(z0, z15);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 64)));
    z7 = _mm512_add_epi64(z7, z16);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 72)));
    z6 = _mm512_add_epi64(z6, z17);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 80)));
    z5 = _mm512_add_epi64(z5, z18);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 88)));
    z4 = _mm512_add_epi64(z4, z19);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 96)));
    z3 = _mm512_add_epi64(z3, z20);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 104)));
    z2 = _mm512_add_epi64(z2, z21);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 112)));
    z1 = _mm512_add_epi64(z1, z22);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 120)));
    z0 = _mm512_add_epi64(z0, z23);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    rbp = (word64)(rbp + 0x80);
    rax = (word32)(4);
L_sha512_x8_xmss_prf_start:
    z24 = _mm512_ror_epi64(z9, 1);
    z25 = _mm512_ror_epi64(z9, 8);
    z26 = _mm512_srli_epi64(z9, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z22, 19);
    z26 = _mm512_ror_epi64(z22, 61);
    z27 = _mm512_srli_epi64(z22, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z8 = _mm512_add_epi64(z8, z24);
    z8 = _mm512_add_epi64(z8, z25);
    z8 = _mm512_add_epi64(z8, z17);
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 0)));
    z7 = _mm512_add_epi64(z7, z8);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z10, 1);
    z25 = _mm512_ror_epi64(z10, 8);
    z26 = _mm512_srli_epi64(z10, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z23, 19);
    z26 = _mm512_ror_epi64(z23, 61);
    z27 = _mm512_srli_epi64(z23, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z9 = _mm512_add_epi64(z9, z24);
    z9 = _mm512_add_epi64(z9, z25);
    z9 = _mm512_add_epi64(z9, z18);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 8)));
    z6 = _mm512_add_epi64(z6, z9);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z11, 1);
    z25 = _mm512_ror_epi64(z11, 8);
    z26 = _mm512_srli_epi64(z11, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z8, 19);
    z26 = _mm512_ror_epi64(z8, 61);
    z27 = _mm512_srli_epi64(z8, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z10 = _mm512_add_epi64(z10, z24);
    z10 = _mm512_add_epi64(z10, z25);
    z10 = _mm512_add_epi64(z10, z19);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 16)));
    z5 = _mm512_add_epi64(z5, z10);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z12, 1);
    z25 = _mm512_ror_epi64(z12, 8);
    z26 = _mm512_srli_epi64(z12, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z9, 19);
    z26 = _mm512_ror_epi64(z9, 61);
    z27 = _mm512_srli_epi64(z9, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z11 = _mm512_add_epi64(z11, z24);
    z11 = _mm512_add_epi64(z11, z25);
    z11 = _mm512_add_epi64(z11, z20);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 24)));
    z4 = _mm512_add_epi64(z4, z11);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z13, 1);
    z25 = _mm512_ror_epi64(z13, 8);
    z26 = _mm512_srli_epi64(z13, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z10, 19);
    z26 = _mm512_ror_epi64(z10, 61);
    z27 = _mm512_srli_epi64(z10, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z12 = _mm512_add_epi64(z12, z24);
    z12 = _mm512_add_epi64(z12, z25);
    z12 = _mm512_add_epi64(z12, z21);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 32)));
    z3 = _mm512_add_epi64(z3, z12);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z14, 1);
    z25 = _mm512_ror_epi64(z14, 8);
    z26 = _mm512_srli_epi64(z14, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z11, 19);
    z26 = _mm512_ror_epi64(z11, 61);
    z27 = _mm512_srli_epi64(z11, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z13 = _mm512_add_epi64(z13, z24);
    z13 = _mm512_add_epi64(z13, z25);
    z13 = _mm512_add_epi64(z13, z22);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 40)));
    z2 = _mm512_add_epi64(z2, z13);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z15, 1);
    z25 = _mm512_ror_epi64(z15, 8);
    z26 = _mm512_srli_epi64(z15, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z12, 19);
    z26 = _mm512_ror_epi64(z12, 61);
    z27 = _mm512_srli_epi64(z12, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z14 = _mm512_add_epi64(z14, z24);
    z14 = _mm512_add_epi64(z14, z25);
    z14 = _mm512_add_epi64(z14, z23);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 48)));
    z1 = _mm512_add_epi64(z1, z14);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z16, 1);
    z25 = _mm512_ror_epi64(z16, 8);
    z26 = _mm512_srli_epi64(z16, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z13, 19);
    z26 = _mm512_ror_epi64(z13, 61);
    z27 = _mm512_srli_epi64(z13, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z15 = _mm512_add_epi64(z15, z24);
    z15 = _mm512_add_epi64(z15, z25);
    z15 = _mm512_add_epi64(z15, z8);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 56)));
    z0 = _mm512_add_epi64(z0, z15);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z17, 1);
    z25 = _mm512_ror_epi64(z17, 8);
    z26 = _mm512_srli_epi64(z17, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z14, 19);
    z26 = _mm512_ror_epi64(z14, 61);
    z27 = _mm512_srli_epi64(z14, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z16 = _mm512_add_epi64(z16, z24);
    z16 = _mm512_add_epi64(z16, z25);
    z16 = _mm512_add_epi64(z16, z9);
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 64)));
    z7 = _mm512_add_epi64(z7, z16);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z18, 1);
    z25 = _mm512_ror_epi64(z18, 8);
    z26 = _mm512_srli_epi64(z18, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z15, 19);
    z26 = _mm512_ror_epi64(z15, 61);
    z27 = _mm512_srli_epi64(z15, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z17 = _mm512_add_epi64(z17, z24);
    z17 = _mm512_add_epi64(z17, z25);
    z17 = _mm512_add_epi64(z17, z10);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 72)));
    z6 = _mm512_add_epi64(z6, z17);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z19, 1);
    z25 = _mm512_ror_epi64(z19, 8);
    z26 = _mm512_srli_epi64(z19, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z16, 19);
    z26 = _mm512_ror_epi64(z16, 61);
    z27 = _mm512_srli_epi64(z16, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z18 = _mm512_add_epi64(z18, z24);
    z18 = _mm512_add_epi64(z18, z25);
    z18 = _mm512_add_epi64(z18, z11);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 80)));
    z5 = _mm512_add_epi64(z5, z18);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z20, 1);
    z25 = _mm512_ror_epi64(z20, 8);
    z26 = _mm512_srli_epi64(z20, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z17, 19);
    z26 = _mm512_ror_epi64(z17, 61);
    z27 = _mm512_srli_epi64(z17, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z19 = _mm512_add_epi64(z19, z24);
    z19 = _mm512_add_epi64(z19, z25);
    z19 = _mm512_add_epi64(z19, z12);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 88)));
    z4 = _mm512_add_epi64(z4, z19);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z21, 1);
    z25 = _mm512_ror_epi64(z21, 8);
    z26 = _mm512_srli_epi64(z21, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z18, 19);
    z26 = _mm512_ror_epi64(z18, 61);
    z27 = _mm512_srli_epi64(z18, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z20 = _mm512_add_epi64(z20, z24);
    z20 = _mm512_add_epi64(z20, z25);
    z20 = _mm512_add_epi64(z20, z13);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 96)));
    z3 = _mm512_add_epi64(z3, z20);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z22, 1);
    z25 = _mm512_ror_epi64(z22, 8);
    z26 = _mm512_srli_epi64(z22, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z19, 19);
    z26 = _mm512_ror_epi64(z19, 61);
    z27 = _mm512_srli_epi64(z19, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z21 = _mm512_add_epi64(z21, z24);
    z21 = _mm512_add_epi64(z21, z25);
    z21 = _mm512_add_epi64(z21, z14);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 104)));
    z2 = _mm512_add_epi64(z2, z21);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z23, 1);
    z25 = _mm512_ror_epi64(z23, 8);
    z26 = _mm512_srli_epi64(z23, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z20, 19);
    z26 = _mm512_ror_epi64(z20, 61);
    z27 = _mm512_srli_epi64(z20, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z22 = _mm512_add_epi64(z22, z24);
    z22 = _mm512_add_epi64(z22, z25);
    z22 = _mm512_add_epi64(z22, z15);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 112)));
    z1 = _mm512_add_epi64(z1, z22);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z8, 1);
    z25 = _mm512_ror_epi64(z8, 8);
    z26 = _mm512_srli_epi64(z8, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z21, 19);
    z26 = _mm512_ror_epi64(z21, 61);
    z27 = _mm512_srli_epi64(z21, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z23 = _mm512_add_epi64(z23, z24);
    z23 = _mm512_add_epi64(z23, z25);
    z23 = _mm512_add_epi64(z23, z16);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 120)));
    z0 = _mm512_add_epi64(z0, z23);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    rbp = (word64)(rbp + 0x80);
    rax = (word32)((word32)rax - 1);
    if (((word32)rax) != (0)) {
        goto L_sha512_x8_xmss_prf_start;
    }
    /* Add the midstate back; the digest stays interleaved for F */
    z24 = _mm512_set1_epi64((long long)WC_L64(rsi, 0));
    z0 = _mm512_add_epi64(z0, z24);
    _mm512_storeu_si512((void*)WC_PW(rdi, 0), z0);
    z24 = _mm512_set1_epi64((long long)WC_L64(rsi, 8));
    z1 = _mm512_add_epi64(z1, z24);
    _mm512_storeu_si512((void*)WC_PW(rdi, 64), z1);
    z24 = _mm512_set1_epi64((long long)WC_L64(rsi, 16));
    z2 = _mm512_add_epi64(z2, z24);
    _mm512_storeu_si512((void*)WC_PW(rdi, 128), z2);
    z24 = _mm512_set1_epi64((long long)WC_L64(rsi, 24));
    z3 = _mm512_add_epi64(z3, z24);
    _mm512_storeu_si512((void*)WC_PW(rdi, 192), z3);
    z24 = _mm512_set1_epi64((long long)WC_L64(rsi, 32));
    z4 = _mm512_add_epi64(z4, z24);
    _mm512_storeu_si512((void*)WC_PW(rdi, 256), z4);
    z24 = _mm512_set1_epi64((long long)WC_L64(rsi, 40));
    z5 = _mm512_add_epi64(z5, z24);
    _mm512_storeu_si512((void*)WC_PW(rdi, 320), z5);
    z24 = _mm512_set1_epi64((long long)WC_L64(rsi, 48));
    z6 = _mm512_add_epi64(z6, z24);
    _mm512_storeu_si512((void*)WC_PW(rdi, 384), z6);
    z24 = _mm512_set1_epi64((long long)WC_L64(rsi, 56));
    z7 = _mm512_add_epi64(z7, z24);
    _mm512_storeu_si512((void*)WC_PW(rdi, 448), z7);
}

WC_X64I_TARGET("avx512f")
WOLFSSL_LOCAL void Transform_Sha512_x8_XmssF_AVX512(word64* st,
    const word64* key, const word64* bm)
{
    word64 rdi, rsi, rdx, rsp, r9, rbp, rax;
    __m512i z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14,
            z15, z16, z17, z18, z19, z20, z21, z22, z23, z24, z25, z26, z27;
    XALIGNED(32) WC_X64I_SLOT stk[64];

    rdi = (word64)(size_t)st;
    rsi = (word64)(size_t)key;
    rdx = (word64)(size_t)bm;

    rsp = (word64)(size_t)stk + 512;
    rsp = (word64)(rsp - 512);
    r9 = (word64)((word64)(size_t)L_avx512_sha512_x8_iv);
    /* First block: the padding for F is zero, and then KEY */
    z8 = _mm512_setzero_si512();
    z9 = _mm512_setzero_si512();
    z10 = _mm512_setzero_si512();
    z11 = _mm512_setzero_si512();
    z12 = _mm512_setzero_si512();
    z13 = _mm512_setzero_si512();
    z14 = _mm512_setzero_si512();
    z15 = _mm512_setzero_si512();
    z16 = _mm512_loadu_si512((const void*)WC_PR(rsi, 0));
    z17 = _mm512_loadu_si512((const void*)WC_PR(rsi, 64));
    z18 = _mm512_loadu_si512((const void*)WC_PR(rsi, 128));
    z19 = _mm512_loadu_si512((const void*)WC_PR(rsi, 192));
    z20 = _mm512_loadu_si512((const void*)WC_PR(rsi, 256));
    z21 = _mm512_loadu_si512((const void*)WC_PR(rsi, 320));
    z22 = _mm512_loadu_si512((const void*)WC_PR(rsi, 384));
    z23 = _mm512_loadu_si512((const void*)WC_PR(rsi, 448));
    z0 = _mm512_set1_epi64((long long)WC_L64(r9, 0));
    z1 = _mm512_set1_epi64((long long)WC_L64(r9, 8));
    z2 = _mm512_set1_epi64((long long)WC_L64(r9, 16));
    z3 = _mm512_set1_epi64((long long)WC_L64(r9, 24));
    z4 = _mm512_set1_epi64((long long)WC_L64(r9, 32));
    z5 = _mm512_set1_epi64((long long)WC_L64(r9, 40));
    z6 = _mm512_set1_epi64((long long)WC_L64(r9, 48));
    z7 = _mm512_set1_epi64((long long)WC_L64(r9, 56));
    rbp = (word64)((word64)(size_t)L_avx512_sha512_x8_k);
    /* Rounds 0-15: the schedule is the message block itself */
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 0)));
    z7 = _mm512_add_epi64(z7, z8);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 8)));
    z6 = _mm512_add_epi64(z6, z9);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 16)));
    z5 = _mm512_add_epi64(z5, z10);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 24)));
    z4 = _mm512_add_epi64(z4, z11);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 32)));
    z3 = _mm512_add_epi64(z3, z12);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 40)));
    z2 = _mm512_add_epi64(z2, z13);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 48)));
    z1 = _mm512_add_epi64(z1, z14);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 56)));
    z0 = _mm512_add_epi64(z0, z15);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 64)));
    z7 = _mm512_add_epi64(z7, z16);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 72)));
    z6 = _mm512_add_epi64(z6, z17);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 80)));
    z5 = _mm512_add_epi64(z5, z18);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 88)));
    z4 = _mm512_add_epi64(z4, z19);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 96)));
    z3 = _mm512_add_epi64(z3, z20);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 104)));
    z2 = _mm512_add_epi64(z2, z21);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 112)));
    z1 = _mm512_add_epi64(z1, z22);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 120)));
    z0 = _mm512_add_epi64(z0, z23);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    rbp = (word64)(rbp + 0x80);
    rax = (word32)(4);
L_sha512_x8_xmss_f_blk1:
    z24 = _mm512_ror_epi64(z9, 1);
    z25 = _mm512_ror_epi64(z9, 8);
    z26 = _mm512_srli_epi64(z9, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z22, 19);
    z26 = _mm512_ror_epi64(z22, 61);
    z27 = _mm512_srli_epi64(z22, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z8 = _mm512_add_epi64(z8, z24);
    z8 = _mm512_add_epi64(z8, z25);
    z8 = _mm512_add_epi64(z8, z17);
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 0)));
    z7 = _mm512_add_epi64(z7, z8);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z10, 1);
    z25 = _mm512_ror_epi64(z10, 8);
    z26 = _mm512_srli_epi64(z10, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z23, 19);
    z26 = _mm512_ror_epi64(z23, 61);
    z27 = _mm512_srli_epi64(z23, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z9 = _mm512_add_epi64(z9, z24);
    z9 = _mm512_add_epi64(z9, z25);
    z9 = _mm512_add_epi64(z9, z18);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 8)));
    z6 = _mm512_add_epi64(z6, z9);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z11, 1);
    z25 = _mm512_ror_epi64(z11, 8);
    z26 = _mm512_srli_epi64(z11, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z8, 19);
    z26 = _mm512_ror_epi64(z8, 61);
    z27 = _mm512_srli_epi64(z8, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z10 = _mm512_add_epi64(z10, z24);
    z10 = _mm512_add_epi64(z10, z25);
    z10 = _mm512_add_epi64(z10, z19);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 16)));
    z5 = _mm512_add_epi64(z5, z10);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z12, 1);
    z25 = _mm512_ror_epi64(z12, 8);
    z26 = _mm512_srli_epi64(z12, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z9, 19);
    z26 = _mm512_ror_epi64(z9, 61);
    z27 = _mm512_srli_epi64(z9, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z11 = _mm512_add_epi64(z11, z24);
    z11 = _mm512_add_epi64(z11, z25);
    z11 = _mm512_add_epi64(z11, z20);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 24)));
    z4 = _mm512_add_epi64(z4, z11);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z13, 1);
    z25 = _mm512_ror_epi64(z13, 8);
    z26 = _mm512_srli_epi64(z13, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z10, 19);
    z26 = _mm512_ror_epi64(z10, 61);
    z27 = _mm512_srli_epi64(z10, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z12 = _mm512_add_epi64(z12, z24);
    z12 = _mm512_add_epi64(z12, z25);
    z12 = _mm512_add_epi64(z12, z21);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 32)));
    z3 = _mm512_add_epi64(z3, z12);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z14, 1);
    z25 = _mm512_ror_epi64(z14, 8);
    z26 = _mm512_srli_epi64(z14, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z11, 19);
    z26 = _mm512_ror_epi64(z11, 61);
    z27 = _mm512_srli_epi64(z11, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z13 = _mm512_add_epi64(z13, z24);
    z13 = _mm512_add_epi64(z13, z25);
    z13 = _mm512_add_epi64(z13, z22);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 40)));
    z2 = _mm512_add_epi64(z2, z13);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z15, 1);
    z25 = _mm512_ror_epi64(z15, 8);
    z26 = _mm512_srli_epi64(z15, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z12, 19);
    z26 = _mm512_ror_epi64(z12, 61);
    z27 = _mm512_srli_epi64(z12, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z14 = _mm512_add_epi64(z14, z24);
    z14 = _mm512_add_epi64(z14, z25);
    z14 = _mm512_add_epi64(z14, z23);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 48)));
    z1 = _mm512_add_epi64(z1, z14);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z16, 1);
    z25 = _mm512_ror_epi64(z16, 8);
    z26 = _mm512_srli_epi64(z16, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z13, 19);
    z26 = _mm512_ror_epi64(z13, 61);
    z27 = _mm512_srli_epi64(z13, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z15 = _mm512_add_epi64(z15, z24);
    z15 = _mm512_add_epi64(z15, z25);
    z15 = _mm512_add_epi64(z15, z8);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 56)));
    z0 = _mm512_add_epi64(z0, z15);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z17, 1);
    z25 = _mm512_ror_epi64(z17, 8);
    z26 = _mm512_srli_epi64(z17, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z14, 19);
    z26 = _mm512_ror_epi64(z14, 61);
    z27 = _mm512_srli_epi64(z14, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z16 = _mm512_add_epi64(z16, z24);
    z16 = _mm512_add_epi64(z16, z25);
    z16 = _mm512_add_epi64(z16, z9);
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 64)));
    z7 = _mm512_add_epi64(z7, z16);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z18, 1);
    z25 = _mm512_ror_epi64(z18, 8);
    z26 = _mm512_srli_epi64(z18, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z15, 19);
    z26 = _mm512_ror_epi64(z15, 61);
    z27 = _mm512_srli_epi64(z15, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z17 = _mm512_add_epi64(z17, z24);
    z17 = _mm512_add_epi64(z17, z25);
    z17 = _mm512_add_epi64(z17, z10);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 72)));
    z6 = _mm512_add_epi64(z6, z17);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z19, 1);
    z25 = _mm512_ror_epi64(z19, 8);
    z26 = _mm512_srli_epi64(z19, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z16, 19);
    z26 = _mm512_ror_epi64(z16, 61);
    z27 = _mm512_srli_epi64(z16, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z18 = _mm512_add_epi64(z18, z24);
    z18 = _mm512_add_epi64(z18, z25);
    z18 = _mm512_add_epi64(z18, z11);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 80)));
    z5 = _mm512_add_epi64(z5, z18);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z20, 1);
    z25 = _mm512_ror_epi64(z20, 8);
    z26 = _mm512_srli_epi64(z20, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z17, 19);
    z26 = _mm512_ror_epi64(z17, 61);
    z27 = _mm512_srli_epi64(z17, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z19 = _mm512_add_epi64(z19, z24);
    z19 = _mm512_add_epi64(z19, z25);
    z19 = _mm512_add_epi64(z19, z12);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 88)));
    z4 = _mm512_add_epi64(z4, z19);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z21, 1);
    z25 = _mm512_ror_epi64(z21, 8);
    z26 = _mm512_srli_epi64(z21, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z18, 19);
    z26 = _mm512_ror_epi64(z18, 61);
    z27 = _mm512_srli_epi64(z18, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z20 = _mm512_add_epi64(z20, z24);
    z20 = _mm512_add_epi64(z20, z25);
    z20 = _mm512_add_epi64(z20, z13);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 96)));
    z3 = _mm512_add_epi64(z3, z20);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z22, 1);
    z25 = _mm512_ror_epi64(z22, 8);
    z26 = _mm512_srli_epi64(z22, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z19, 19);
    z26 = _mm512_ror_epi64(z19, 61);
    z27 = _mm512_srli_epi64(z19, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z21 = _mm512_add_epi64(z21, z24);
    z21 = _mm512_add_epi64(z21, z25);
    z21 = _mm512_add_epi64(z21, z14);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 104)));
    z2 = _mm512_add_epi64(z2, z21);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z23, 1);
    z25 = _mm512_ror_epi64(z23, 8);
    z26 = _mm512_srli_epi64(z23, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z20, 19);
    z26 = _mm512_ror_epi64(z20, 61);
    z27 = _mm512_srli_epi64(z20, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z22 = _mm512_add_epi64(z22, z24);
    z22 = _mm512_add_epi64(z22, z25);
    z22 = _mm512_add_epi64(z22, z15);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 112)));
    z1 = _mm512_add_epi64(z1, z22);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z8, 1);
    z25 = _mm512_ror_epi64(z8, 8);
    z26 = _mm512_srli_epi64(z8, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z21, 19);
    z26 = _mm512_ror_epi64(z21, 61);
    z27 = _mm512_srli_epi64(z21, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z23 = _mm512_add_epi64(z23, z24);
    z23 = _mm512_add_epi64(z23, z25);
    z23 = _mm512_add_epi64(z23, z16);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 120)));
    z0 = _mm512_add_epi64(z0, z23);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    rbp = (word64)(rbp + 0x80);
    rax = (word32)((word32)rax - 1);
    if (((word32)rax) != (0)) {
        goto L_sha512_x8_xmss_f_blk1;
    }
    /* Hold on to the chaining value: it is needed again at the end */
    z24 = _mm512_set1_epi64((long long)WC_L64(r9, 0));
    z0 = _mm512_add_epi64(z0, z24);
    _mm512_storeu_si512((void*)WC_PW(rsp, 0), z0);
    z24 = _mm512_set1_epi64((long long)WC_L64(r9, 8));
    z1 = _mm512_add_epi64(z1, z24);
    _mm512_storeu_si512((void*)WC_PW(rsp, 64), z1);
    z24 = _mm512_set1_epi64((long long)WC_L64(r9, 16));
    z2 = _mm512_add_epi64(z2, z24);
    _mm512_storeu_si512((void*)WC_PW(rsp, 128), z2);
    z24 = _mm512_set1_epi64((long long)WC_L64(r9, 24));
    z3 = _mm512_add_epi64(z3, z24);
    _mm512_storeu_si512((void*)WC_PW(rsp, 192), z3);
    z24 = _mm512_set1_epi64((long long)WC_L64(r9, 32));
    z4 = _mm512_add_epi64(z4, z24);
    _mm512_storeu_si512((void*)WC_PW(rsp, 256), z4);
    z24 = _mm512_set1_epi64((long long)WC_L64(r9, 40));
    z5 = _mm512_add_epi64(z5, z24);
    _mm512_storeu_si512((void*)WC_PW(rsp, 320), z5);
    z24 = _mm512_set1_epi64((long long)WC_L64(r9, 48));
    z6 = _mm512_add_epi64(z6, z24);
    _mm512_storeu_si512((void*)WC_PW(rsp, 384), z6);
    z24 = _mm512_set1_epi64((long long)WC_L64(r9, 56));
    z7 = _mm512_add_epi64(z7, z24);
    _mm512_storeu_si512((void*)WC_PW(rsp, 448), z7);
    /* Second block: tmp ^ BM, then the padding for 192 bytes */
    z24 = _mm512_loadu_si512((const void*)WC_PR(rdi, 0));
    z8 = _mm512_xor_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rdx, 0)));
    z24 = _mm512_loadu_si512((const void*)WC_PR(rdi, 64));
    z9 = _mm512_xor_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rdx, 64)));
    z24 = _mm512_loadu_si512((const void*)WC_PR(rdi, 128));
    z10 = _mm512_xor_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rdx,
        128)));
    z24 = _mm512_loadu_si512((const void*)WC_PR(rdi, 192));
    z11 = _mm512_xor_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rdx,
        192)));
    z24 = _mm512_loadu_si512((const void*)WC_PR(rdi, 256));
    z12 = _mm512_xor_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rdx,
        256)));
    z24 = _mm512_loadu_si512((const void*)WC_PR(rdi, 320));
    z13 = _mm512_xor_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rdx,
        320)));
    z24 = _mm512_loadu_si512((const void*)WC_PR(rdi, 384));
    z14 = _mm512_xor_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rdx,
        384)));
    z24 = _mm512_loadu_si512((const void*)WC_PR(rdi, 448));
    z15 = _mm512_xor_si512(z24, _mm512_loadu_si512((const void*)WC_PR(rdx,
        448)));
    z16 = _mm512_set1_epi64((long long)WC_L64(L_avx512_sha512_x8_pad80q, 0));
    z17 = _mm512_setzero_si512();
    z18 = _mm512_setzero_si512();
    z19 = _mm512_setzero_si512();
    z20 = _mm512_setzero_si512();
    z21 = _mm512_setzero_si512();
    z22 = _mm512_setzero_si512();
    z23 = _mm512_set1_epi64((long long)WC_L64(L_avx512_sha512_x8_len1536, 0));
    rbp = (word64)((word64)(size_t)L_avx512_sha512_x8_k);
    /* Rounds 0-15: the schedule is the message block itself */
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 0)));
    z7 = _mm512_add_epi64(z7, z8);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 8)));
    z6 = _mm512_add_epi64(z6, z9);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 16)));
    z5 = _mm512_add_epi64(z5, z10);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 24)));
    z4 = _mm512_add_epi64(z4, z11);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 32)));
    z3 = _mm512_add_epi64(z3, z12);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 40)));
    z2 = _mm512_add_epi64(z2, z13);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 48)));
    z1 = _mm512_add_epi64(z1, z14);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 56)));
    z0 = _mm512_add_epi64(z0, z15);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 64)));
    z7 = _mm512_add_epi64(z7, z16);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 72)));
    z6 = _mm512_add_epi64(z6, z17);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 80)));
    z5 = _mm512_add_epi64(z5, z18);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 88)));
    z4 = _mm512_add_epi64(z4, z19);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 96)));
    z3 = _mm512_add_epi64(z3, z20);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 104)));
    z2 = _mm512_add_epi64(z2, z21);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 112)));
    z1 = _mm512_add_epi64(z1, z22);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 120)));
    z0 = _mm512_add_epi64(z0, z23);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    rbp = (word64)(rbp + 0x80);
    rax = (word32)(4);
L_sha512_x8_xmss_f_blk2:
    z24 = _mm512_ror_epi64(z9, 1);
    z25 = _mm512_ror_epi64(z9, 8);
    z26 = _mm512_srli_epi64(z9, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z22, 19);
    z26 = _mm512_ror_epi64(z22, 61);
    z27 = _mm512_srli_epi64(z22, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z8 = _mm512_add_epi64(z8, z24);
    z8 = _mm512_add_epi64(z8, z25);
    z8 = _mm512_add_epi64(z8, z17);
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 0)));
    z7 = _mm512_add_epi64(z7, z8);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z10, 1);
    z25 = _mm512_ror_epi64(z10, 8);
    z26 = _mm512_srli_epi64(z10, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z23, 19);
    z26 = _mm512_ror_epi64(z23, 61);
    z27 = _mm512_srli_epi64(z23, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z9 = _mm512_add_epi64(z9, z24);
    z9 = _mm512_add_epi64(z9, z25);
    z9 = _mm512_add_epi64(z9, z18);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 8)));
    z6 = _mm512_add_epi64(z6, z9);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z11, 1);
    z25 = _mm512_ror_epi64(z11, 8);
    z26 = _mm512_srli_epi64(z11, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z8, 19);
    z26 = _mm512_ror_epi64(z8, 61);
    z27 = _mm512_srli_epi64(z8, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z10 = _mm512_add_epi64(z10, z24);
    z10 = _mm512_add_epi64(z10, z25);
    z10 = _mm512_add_epi64(z10, z19);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 16)));
    z5 = _mm512_add_epi64(z5, z10);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z12, 1);
    z25 = _mm512_ror_epi64(z12, 8);
    z26 = _mm512_srli_epi64(z12, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z9, 19);
    z26 = _mm512_ror_epi64(z9, 61);
    z27 = _mm512_srli_epi64(z9, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z11 = _mm512_add_epi64(z11, z24);
    z11 = _mm512_add_epi64(z11, z25);
    z11 = _mm512_add_epi64(z11, z20);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 24)));
    z4 = _mm512_add_epi64(z4, z11);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z13, 1);
    z25 = _mm512_ror_epi64(z13, 8);
    z26 = _mm512_srli_epi64(z13, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z10, 19);
    z26 = _mm512_ror_epi64(z10, 61);
    z27 = _mm512_srli_epi64(z10, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z12 = _mm512_add_epi64(z12, z24);
    z12 = _mm512_add_epi64(z12, z25);
    z12 = _mm512_add_epi64(z12, z21);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 32)));
    z3 = _mm512_add_epi64(z3, z12);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z14, 1);
    z25 = _mm512_ror_epi64(z14, 8);
    z26 = _mm512_srli_epi64(z14, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z11, 19);
    z26 = _mm512_ror_epi64(z11, 61);
    z27 = _mm512_srli_epi64(z11, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z13 = _mm512_add_epi64(z13, z24);
    z13 = _mm512_add_epi64(z13, z25);
    z13 = _mm512_add_epi64(z13, z22);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 40)));
    z2 = _mm512_add_epi64(z2, z13);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z15, 1);
    z25 = _mm512_ror_epi64(z15, 8);
    z26 = _mm512_srli_epi64(z15, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z12, 19);
    z26 = _mm512_ror_epi64(z12, 61);
    z27 = _mm512_srli_epi64(z12, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z14 = _mm512_add_epi64(z14, z24);
    z14 = _mm512_add_epi64(z14, z25);
    z14 = _mm512_add_epi64(z14, z23);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 48)));
    z1 = _mm512_add_epi64(z1, z14);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z16, 1);
    z25 = _mm512_ror_epi64(z16, 8);
    z26 = _mm512_srli_epi64(z16, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z13, 19);
    z26 = _mm512_ror_epi64(z13, 61);
    z27 = _mm512_srli_epi64(z13, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z15 = _mm512_add_epi64(z15, z24);
    z15 = _mm512_add_epi64(z15, z25);
    z15 = _mm512_add_epi64(z15, z8);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 56)));
    z0 = _mm512_add_epi64(z0, z15);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z17, 1);
    z25 = _mm512_ror_epi64(z17, 8);
    z26 = _mm512_srli_epi64(z17, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z14, 19);
    z26 = _mm512_ror_epi64(z14, 61);
    z27 = _mm512_srli_epi64(z14, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z16 = _mm512_add_epi64(z16, z24);
    z16 = _mm512_add_epi64(z16, z25);
    z16 = _mm512_add_epi64(z16, z9);
    z7 = _mm512_add_epi64(z7, _mm512_set1_epi64((long long)WC_L64(rbp, 64)));
    z7 = _mm512_add_epi64(z7, z16);
    z3 = _mm512_add_epi64(z3, z7);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe2);
    z24 = _mm512_ror_epi64(z4, 14);
    z25 = _mm512_ror_epi64(z4, 18);
    z26 = _mm512_ror_epi64(z4, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z0, 28);
    z25 = _mm512_ror_epi64(z0, 34);
    z26 = _mm512_ror_epi64(z0, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe8);
    z7 = _mm512_add_epi64(z7, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z24 = _mm512_ror_epi64(z18, 1);
    z25 = _mm512_ror_epi64(z18, 8);
    z26 = _mm512_srli_epi64(z18, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z15, 19);
    z26 = _mm512_ror_epi64(z15, 61);
    z27 = _mm512_srli_epi64(z15, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z17 = _mm512_add_epi64(z17, z24);
    z17 = _mm512_add_epi64(z17, z25);
    z17 = _mm512_add_epi64(z17, z10);
    z6 = _mm512_add_epi64(z6, _mm512_set1_epi64((long long)WC_L64(rbp, 72)));
    z6 = _mm512_add_epi64(z6, z17);
    z2 = _mm512_add_epi64(z2, z6);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe2);
    z24 = _mm512_ror_epi64(z3, 14);
    z25 = _mm512_ror_epi64(z3, 18);
    z26 = _mm512_ror_epi64(z3, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z7, 28);
    z25 = _mm512_ror_epi64(z7, 34);
    z26 = _mm512_ror_epi64(z7, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe8);
    z6 = _mm512_add_epi64(z6, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z24 = _mm512_ror_epi64(z19, 1);
    z25 = _mm512_ror_epi64(z19, 8);
    z26 = _mm512_srli_epi64(z19, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z16, 19);
    z26 = _mm512_ror_epi64(z16, 61);
    z27 = _mm512_srli_epi64(z16, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z18 = _mm512_add_epi64(z18, z24);
    z18 = _mm512_add_epi64(z18, z25);
    z18 = _mm512_add_epi64(z18, z11);
    z5 = _mm512_add_epi64(z5, _mm512_set1_epi64((long long)WC_L64(rbp, 80)));
    z5 = _mm512_add_epi64(z5, z18);
    z1 = _mm512_add_epi64(z1, z5);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe2);
    z24 = _mm512_ror_epi64(z2, 14);
    z25 = _mm512_ror_epi64(z2, 18);
    z26 = _mm512_ror_epi64(z2, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z6, 28);
    z25 = _mm512_ror_epi64(z6, 34);
    z26 = _mm512_ror_epi64(z6, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe8);
    z5 = _mm512_add_epi64(z5, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z24 = _mm512_ror_epi64(z20, 1);
    z25 = _mm512_ror_epi64(z20, 8);
    z26 = _mm512_srli_epi64(z20, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z17, 19);
    z26 = _mm512_ror_epi64(z17, 61);
    z27 = _mm512_srli_epi64(z17, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z19 = _mm512_add_epi64(z19, z24);
    z19 = _mm512_add_epi64(z19, z25);
    z19 = _mm512_add_epi64(z19, z12);
    z4 = _mm512_add_epi64(z4, _mm512_set1_epi64((long long)WC_L64(rbp, 88)));
    z4 = _mm512_add_epi64(z4, z19);
    z0 = _mm512_add_epi64(z0, z4);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe2);
    z24 = _mm512_ror_epi64(z1, 14);
    z25 = _mm512_ror_epi64(z1, 18);
    z26 = _mm512_ror_epi64(z1, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z24);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z5, 28);
    z25 = _mm512_ror_epi64(z5, 34);
    z26 = _mm512_ror_epi64(z5, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe8);
    z4 = _mm512_add_epi64(z4, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z24 = _mm512_ror_epi64(z21, 1);
    z25 = _mm512_ror_epi64(z21, 8);
    z26 = _mm512_srli_epi64(z21, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z18, 19);
    z26 = _mm512_ror_epi64(z18, 61);
    z27 = _mm512_srli_epi64(z18, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z20 = _mm512_add_epi64(z20, z24);
    z20 = _mm512_add_epi64(z20, z25);
    z20 = _mm512_add_epi64(z20, z13);
    z3 = _mm512_add_epi64(z3, _mm512_set1_epi64((long long)WC_L64(rbp, 96)));
    z3 = _mm512_add_epi64(z3, z20);
    z7 = _mm512_add_epi64(z7, z3);
    z27 = z1;
    z27 = _mm512_ternarylogic_epi64(z27, z0, z2, 0xe2);
    z24 = _mm512_ror_epi64(z0, 14);
    z25 = _mm512_ror_epi64(z0, 18);
    z26 = _mm512_ror_epi64(z0, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z7 = _mm512_add_epi64(z7, z27);
    z3 = _mm512_add_epi64(z3, z27);
    z7 = _mm512_add_epi64(z7, z24);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z4, 28);
    z25 = _mm512_ror_epi64(z4, 34);
    z26 = _mm512_ror_epi64(z4, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z5;
    z27 = _mm512_ternarylogic_epi64(z27, z4, z6, 0xe8);
    z3 = _mm512_add_epi64(z3, z27);
    z3 = _mm512_add_epi64(z3, z24);
    z24 = _mm512_ror_epi64(z22, 1);
    z25 = _mm512_ror_epi64(z22, 8);
    z26 = _mm512_srli_epi64(z22, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z19, 19);
    z26 = _mm512_ror_epi64(z19, 61);
    z27 = _mm512_srli_epi64(z19, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z21 = _mm512_add_epi64(z21, z24);
    z21 = _mm512_add_epi64(z21, z25);
    z21 = _mm512_add_epi64(z21, z14);
    z2 = _mm512_add_epi64(z2, _mm512_set1_epi64((long long)WC_L64(rbp, 104)));
    z2 = _mm512_add_epi64(z2, z21);
    z6 = _mm512_add_epi64(z6, z2);
    z27 = z0;
    z27 = _mm512_ternarylogic_epi64(z27, z7, z1, 0xe2);
    z24 = _mm512_ror_epi64(z7, 14);
    z25 = _mm512_ror_epi64(z7, 18);
    z26 = _mm512_ror_epi64(z7, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z6 = _mm512_add_epi64(z6, z27);
    z2 = _mm512_add_epi64(z2, z27);
    z6 = _mm512_add_epi64(z6, z24);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z3, 28);
    z25 = _mm512_ror_epi64(z3, 34);
    z26 = _mm512_ror_epi64(z3, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z4;
    z27 = _mm512_ternarylogic_epi64(z27, z3, z5, 0xe8);
    z2 = _mm512_add_epi64(z2, z27);
    z2 = _mm512_add_epi64(z2, z24);
    z24 = _mm512_ror_epi64(z23, 1);
    z25 = _mm512_ror_epi64(z23, 8);
    z26 = _mm512_srli_epi64(z23, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z20, 19);
    z26 = _mm512_ror_epi64(z20, 61);
    z27 = _mm512_srli_epi64(z20, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z22 = _mm512_add_epi64(z22, z24);
    z22 = _mm512_add_epi64(z22, z25);
    z22 = _mm512_add_epi64(z22, z15);
    z1 = _mm512_add_epi64(z1, _mm512_set1_epi64((long long)WC_L64(rbp, 112)));
    z1 = _mm512_add_epi64(z1, z22);
    z5 = _mm512_add_epi64(z5, z1);
    z27 = z7;
    z27 = _mm512_ternarylogic_epi64(z27, z6, z0, 0xe2);
    z24 = _mm512_ror_epi64(z6, 14);
    z25 = _mm512_ror_epi64(z6, 18);
    z26 = _mm512_ror_epi64(z6, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z5 = _mm512_add_epi64(z5, z27);
    z1 = _mm512_add_epi64(z1, z27);
    z5 = _mm512_add_epi64(z5, z24);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z2, 28);
    z25 = _mm512_ror_epi64(z2, 34);
    z26 = _mm512_ror_epi64(z2, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z3;
    z27 = _mm512_ternarylogic_epi64(z27, z2, z4, 0xe8);
    z1 = _mm512_add_epi64(z1, z27);
    z1 = _mm512_add_epi64(z1, z24);
    z24 = _mm512_ror_epi64(z8, 1);
    z25 = _mm512_ror_epi64(z8, 8);
    z26 = _mm512_srli_epi64(z8, 7);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z25 = _mm512_ror_epi64(z21, 19);
    z26 = _mm512_ror_epi64(z21, 61);
    z27 = _mm512_srli_epi64(z21, 6);
    z25 = _mm512_ternarylogic_epi64(z25, z26, z27, 0x96);
    z23 = _mm512_add_epi64(z23, z24);
    z23 = _mm512_add_epi64(z23, z25);
    z23 = _mm512_add_epi64(z23, z16);
    z0 = _mm512_add_epi64(z0, _mm512_set1_epi64((long long)WC_L64(rbp, 120)));
    z0 = _mm512_add_epi64(z0, z23);
    z4 = _mm512_add_epi64(z4, z0);
    z27 = z6;
    z27 = _mm512_ternarylogic_epi64(z27, z5, z7, 0xe2);
    z24 = _mm512_ror_epi64(z5, 14);
    z25 = _mm512_ror_epi64(z5, 18);
    z26 = _mm512_ror_epi64(z5, 41);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z4 = _mm512_add_epi64(z4, z27);
    z0 = _mm512_add_epi64(z0, z27);
    z4 = _mm512_add_epi64(z4, z24);
    z0 = _mm512_add_epi64(z0, z24);
    z24 = _mm512_ror_epi64(z1, 28);
    z25 = _mm512_ror_epi64(z1, 34);
    z26 = _mm512_ror_epi64(z1, 39);
    z24 = _mm512_ternarylogic_epi64(z24, z25, z26, 0x96);
    z27 = z2;
    z27 = _mm512_ternarylogic_epi64(z27, z1, z3, 0xe8);
    z0 = _mm512_add_epi64(z0, z27);
    z0 = _mm512_add_epi64(z0, z24);
    rbp = (word64)(rbp + 0x80);
    rax = (word32)((word32)rax - 1);
    if (((word32)rax) != (0)) {
        goto L_sha512_x8_xmss_f_blk2;
    }
    /* Add the chaining value back, leaving the chain value in place */
    z0 = _mm512_add_epi64(z0, _mm512_loadu_si512((const void*)WC_PR(rsp, 0)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 0), z0);
    z1 = _mm512_add_epi64(z1, _mm512_loadu_si512((const void*)WC_PR(rsp, 64)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 64), z1);
    z2 = _mm512_add_epi64(z2, _mm512_loadu_si512((const void*)WC_PR(rsp, 128)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 128), z2);
    z3 = _mm512_add_epi64(z3, _mm512_loadu_si512((const void*)WC_PR(rsp, 192)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 192), z3);
    z4 = _mm512_add_epi64(z4, _mm512_loadu_si512((const void*)WC_PR(rsp, 256)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 256), z4);
    z5 = _mm512_add_epi64(z5, _mm512_loadu_si512((const void*)WC_PR(rsp, 320)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 320), z5);
    z6 = _mm512_add_epi64(z6, _mm512_loadu_si512((const void*)WC_PR(rsp, 384)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 384), z6);
    z7 = _mm512_add_epi64(z7, _mm512_loadu_si512((const void*)WC_PR(rsp, 448)));
    _mm512_storeu_si512((void*)WC_PW(rdi, 448), z7);
}

#endif /* WOLFSSL_HAVE_XMSS */
#endif /* HAVE_INTEL_AVX512 */
#endif /* WOLFSSL_HAVE_XMSS */
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
