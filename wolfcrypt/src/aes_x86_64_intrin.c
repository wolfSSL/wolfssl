/* aes_x86_64_intrin.c */
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
#define _WC_BUILDING_AES_X86_64_INTRIN_C

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef WOLFSSL_X86_64_BUILD

#ifdef _MSC_VER
    /* _umul128, __popcnt and _BitScanReverse64 live here. */
    #include <intrin.h>
#endif
#include <immintrin.h>
#include <wolfssl/wolfcrypt/aes.h>

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
extern WOLFSSL_LOCAL void AES_128_Key_Expansion_AESNI(
    const unsigned char* userkey, unsigned char* key_schedule);
extern WOLFSSL_LOCAL void AES_192_Key_Expansion_AESNI(
    const unsigned char* userkey, unsigned char* key_schedule);
extern WOLFSSL_LOCAL void AES_256_Key_Expansion_AESNI(
    const unsigned char* userkey, unsigned char* key_schedule);
extern WOLFSSL_LOCAL void AES_ECB_encrypt_AESNI(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr);
extern WOLFSSL_LOCAL void AES_ECB_decrypt_AESNI(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr);
extern WOLFSSL_LOCAL void AES_CBC_encrypt_AESNI(const unsigned char* in,
    unsigned char* out, unsigned char* ivec, unsigned long length,
    const unsigned char* KS, int nr);
extern WOLFSSL_LOCAL void AES_CBC_decrypt_AESNI(const unsigned char* in,
    unsigned char* out, unsigned char* ivec, unsigned long length,
    const unsigned char* KS, int nr);
extern WOLFSSL_LOCAL void AES_CTR_encrypt_AESNI(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr,
    unsigned char* ctr);
#ifdef HAVE_INTEL_AVX1
extern WOLFSSL_LOCAL void AES_ECB_encrypt_avx1(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr);
extern WOLFSSL_LOCAL void AES_ECB_decrypt_avx1(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr);
extern WOLFSSL_LOCAL void AES_CBC_encrypt_avx1(const unsigned char* in,
    unsigned char* out, unsigned char* ivec, unsigned long length,
    const unsigned char* KS, int nr);
extern WOLFSSL_LOCAL void AES_CBC_decrypt_avx1(const unsigned char* in,
    unsigned char* out, unsigned char* ivec, unsigned long length,
    const unsigned char* KS, int nr);
extern WOLFSSL_LOCAL void AES_CTR_encrypt_avx1(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr,
    unsigned char* ctr);
#endif
#ifdef HAVE_INTEL_VAES
extern WOLFSSL_LOCAL void AES_ECB_encrypt_vaes(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr);
extern WOLFSSL_LOCAL void AES_ECB_decrypt_vaes(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr);
extern WOLFSSL_LOCAL void AES_CBC_encrypt_vaes(const unsigned char* in,
    unsigned char* out, unsigned char* ivec, unsigned long length,
    const unsigned char* KS, int nr);
extern WOLFSSL_LOCAL void AES_CBC_decrypt_vaes(const unsigned char* in,
    unsigned char* out, unsigned char* ivec, unsigned long length,
    const unsigned char* KS, int nr);
extern WOLFSSL_LOCAL void AES_CTR_encrypt_vaes(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr,
    unsigned char* ctr);
#endif
#ifdef HAVE_INTEL_AVX512
extern WOLFSSL_LOCAL void AES_ECB_encrypt_avx512(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr);
extern WOLFSSL_LOCAL void AES_ECB_decrypt_avx512(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr);
extern WOLFSSL_LOCAL void AES_CBC_encrypt_avx512(const unsigned char* in,
    unsigned char* out, unsigned char* ivec, unsigned long length,
    const unsigned char* KS, int nr);
extern WOLFSSL_LOCAL void AES_CBC_decrypt_avx512(const unsigned char* in,
    unsigned char* out, unsigned char* ivec, unsigned long length,
    const unsigned char* KS, int nr);
extern WOLFSSL_LOCAL void AES_CTR_encrypt_avx512(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr,
    unsigned char* ctr);

#endif
#endif
#ifdef WOLFSSL_X86_64_BUILD
WC_X64I_TARGET("sse2,aes")
WOLFSSL_LOCAL void AES_128_Key_Expansion_AESNI(const unsigned char* userkey,
    unsigned char* key_schedule)
{
    word64 rdi, rsi;
    __m128i x0, x1, x2;

    rdi = (word64)(size_t)userkey;
    rsi = (word64)(size_t)key_schedule;

    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 0));
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 0), x0);
    x1 = _mm_aeskeygenassist_si128(x0, 1);
    x1 = _mm_shuffle_epi32(x1, 0xff);
    x2 = x0;
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x0 = _mm_xor_si128(x0, x1);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 16), x0);
    x1 = _mm_aeskeygenassist_si128(x0, 2);
    x1 = _mm_shuffle_epi32(x1, 0xff);
    x2 = x0;
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x0 = _mm_xor_si128(x0, x1);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 32), x0);
    x1 = _mm_aeskeygenassist_si128(x0, 4);
    x1 = _mm_shuffle_epi32(x1, 0xff);
    x2 = x0;
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x0 = _mm_xor_si128(x0, x1);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 48), x0);
    x1 = _mm_aeskeygenassist_si128(x0, 8);
    x1 = _mm_shuffle_epi32(x1, 0xff);
    x2 = x0;
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x0 = _mm_xor_si128(x0, x1);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 64), x0);
    x1 = _mm_aeskeygenassist_si128(x0, 0x10);
    x1 = _mm_shuffle_epi32(x1, 0xff);
    x2 = x0;
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x0 = _mm_xor_si128(x0, x1);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 80), x0);
    x1 = _mm_aeskeygenassist_si128(x0, 0x20);
    x1 = _mm_shuffle_epi32(x1, 0xff);
    x2 = x0;
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x0 = _mm_xor_si128(x0, x1);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 96), x0);
    x1 = _mm_aeskeygenassist_si128(x0, 0x40);
    x1 = _mm_shuffle_epi32(x1, 0xff);
    x2 = x0;
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x0 = _mm_xor_si128(x0, x1);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 112), x0);
    x1 = _mm_aeskeygenassist_si128(x0, 0x80);
    x1 = _mm_shuffle_epi32(x1, 0xff);
    x2 = x0;
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x0 = _mm_xor_si128(x0, x1);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 128), x0);
    x1 = _mm_aeskeygenassist_si128(x0, 0x1b);
    x1 = _mm_shuffle_epi32(x1, 0xff);
    x2 = x0;
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x0 = _mm_xor_si128(x0, x1);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 144), x0);
    x1 = _mm_aeskeygenassist_si128(x0, 0x36);
    x1 = _mm_shuffle_epi32(x1, 0xff);
    x2 = x0;
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_bslli_si128(x2, 4);
    x0 = _mm_xor_si128(x0, x2);
    x0 = _mm_xor_si128(x0, x1);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 160), x0);
}

WC_X64I_TARGET("sse2,sse4.1,aes")
WOLFSSL_LOCAL void AES_192_Key_Expansion_AESNI(const unsigned char* userkey,
    unsigned char* key_schedule)
{
    word64 rdi, rsi;
    __m128i x0, x1, x2, x3, x4, x5;

    rdi = (word64)(size_t)userkey;
    rsi = (word64)(size_t)key_schedule;

    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 0));
    x1 = _mm_setzero_si128();
    x1 = _mm_insert_epi64(x1, (long long)WC_L64(rdi, 16), 0);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 0), x0);
    x4 = x1;
    x2 = _mm_aeskeygenassist_si128(x1, 1);
    x2 = _mm_shuffle_epi32(x2, 0x55);
    x3 = x0;
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_shuffle_epi32(x0, 0xff);
    x3 = x1;
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x1 = _mm_xor_si128(x1, x2);
    x4 = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(x4), _mm_castsi128_pd(
        x0), 0));
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 16), x4);
    x5 = x0;
    x5 = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(x5), _mm_castsi128_pd(
        x1), 1));
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 32), x5);
    x2 = _mm_aeskeygenassist_si128(x1, 2);
    x2 = _mm_shuffle_epi32(x2, 0x55);
    x3 = x0;
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_shuffle_epi32(x0, 0xff);
    x3 = x1;
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x1 = _mm_xor_si128(x1, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 48), x0);
    x4 = x1;
    x2 = _mm_aeskeygenassist_si128(x1, 4);
    x2 = _mm_shuffle_epi32(x2, 0x55);
    x3 = x0;
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_shuffle_epi32(x0, 0xff);
    x3 = x1;
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x1 = _mm_xor_si128(x1, x2);
    x4 = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(x4), _mm_castsi128_pd(
        x0), 0));
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 64), x4);
    x5 = x0;
    x5 = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(x5), _mm_castsi128_pd(
        x1), 1));
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 80), x5);
    x2 = _mm_aeskeygenassist_si128(x1, 8);
    x2 = _mm_shuffle_epi32(x2, 0x55);
    x3 = x0;
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_shuffle_epi32(x0, 0xff);
    x3 = x1;
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x1 = _mm_xor_si128(x1, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 96), x0);
    x4 = x1;
    x2 = _mm_aeskeygenassist_si128(x1, 0x10);
    x2 = _mm_shuffle_epi32(x2, 0x55);
    x3 = x0;
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_shuffle_epi32(x0, 0xff);
    x3 = x1;
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x1 = _mm_xor_si128(x1, x2);
    x4 = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(x4), _mm_castsi128_pd(
        x0), 0));
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 112), x4);
    x5 = x0;
    x5 = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(x5), _mm_castsi128_pd(
        x1), 1));
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 128), x5);
    x2 = _mm_aeskeygenassist_si128(x1, 0x20);
    x2 = _mm_shuffle_epi32(x2, 0x55);
    x3 = x0;
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_shuffle_epi32(x0, 0xff);
    x3 = x1;
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x1 = _mm_xor_si128(x1, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 144), x0);
    x4 = x1;
    x2 = _mm_aeskeygenassist_si128(x1, 0x40);
    x2 = _mm_shuffle_epi32(x2, 0x55);
    x3 = x0;
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_shuffle_epi32(x0, 0xff);
    x3 = x1;
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x1 = _mm_xor_si128(x1, x2);
    x4 = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(x4), _mm_castsi128_pd(
        x0), 0));
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 160), x4);
    x5 = x0;
    x5 = _mm_castpd_si128(_mm_shuffle_pd(_mm_castsi128_pd(x5), _mm_castsi128_pd(
        x1), 1));
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 176), x5);
    x2 = _mm_aeskeygenassist_si128(x1, 0x80);
    x2 = _mm_shuffle_epi32(x2, 0x55);
    x3 = x0;
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x0 = _mm_xor_si128(x0, x2);
    x2 = _mm_shuffle_epi32(x0, 0xff);
    x3 = x1;
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x1 = _mm_xor_si128(x1, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 192), x0);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 208), x1);
}

WC_X64I_TARGET("sse2,aes")
WOLFSSL_LOCAL void AES_256_Key_Expansion_AESNI(const unsigned char* userkey,
    unsigned char* key_schedule)
{
    word64 rdi, rsi;
    __m128i x0, x1, x2, x3;

    rdi = (word64)(size_t)userkey;
    rsi = (word64)(size_t)key_schedule;

    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 16));
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 0), x0);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 16), x1);
    x2 = _mm_aeskeygenassist_si128(x1, 1);
    x2 = _mm_shuffle_epi32(x2, 0xff);
    x3 = x0;
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x0 = _mm_xor_si128(x0, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 32), x0);
    x2 = _mm_aeskeygenassist_si128(x0, 0);
    x2 = _mm_shuffle_epi32(x2, 0xaa);
    x3 = x1;
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x1 = _mm_xor_si128(x1, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 48), x1);
    x2 = _mm_aeskeygenassist_si128(x1, 2);
    x2 = _mm_shuffle_epi32(x2, 0xff);
    x3 = x0;
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x0 = _mm_xor_si128(x0, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 64), x0);
    x2 = _mm_aeskeygenassist_si128(x0, 0);
    x2 = _mm_shuffle_epi32(x2, 0xaa);
    x3 = x1;
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x1 = _mm_xor_si128(x1, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 80), x1);
    x2 = _mm_aeskeygenassist_si128(x1, 4);
    x2 = _mm_shuffle_epi32(x2, 0xff);
    x3 = x0;
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x0 = _mm_xor_si128(x0, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 96), x0);
    x2 = _mm_aeskeygenassist_si128(x0, 0);
    x2 = _mm_shuffle_epi32(x2, 0xaa);
    x3 = x1;
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x1 = _mm_xor_si128(x1, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 112), x1);
    x2 = _mm_aeskeygenassist_si128(x1, 8);
    x2 = _mm_shuffle_epi32(x2, 0xff);
    x3 = x0;
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x0 = _mm_xor_si128(x0, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 128), x0);
    x2 = _mm_aeskeygenassist_si128(x0, 0);
    x2 = _mm_shuffle_epi32(x2, 0xaa);
    x3 = x1;
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x1 = _mm_xor_si128(x1, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 144), x1);
    x2 = _mm_aeskeygenassist_si128(x1, 0x10);
    x2 = _mm_shuffle_epi32(x2, 0xff);
    x3 = x0;
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x0 = _mm_xor_si128(x0, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 160), x0);
    x2 = _mm_aeskeygenassist_si128(x0, 0);
    x2 = _mm_shuffle_epi32(x2, 0xaa);
    x3 = x1;
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x1 = _mm_xor_si128(x1, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 176), x1);
    x2 = _mm_aeskeygenassist_si128(x1, 0x20);
    x2 = _mm_shuffle_epi32(x2, 0xff);
    x3 = x0;
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x0 = _mm_xor_si128(x0, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 192), x0);
    x2 = _mm_aeskeygenassist_si128(x0, 0);
    x2 = _mm_shuffle_epi32(x2, 0xaa);
    x3 = x1;
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x1 = _mm_xor_si128(x1, x3);
    x1 = _mm_xor_si128(x1, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 208), x1);
    x2 = _mm_aeskeygenassist_si128(x1, 0x40);
    x2 = _mm_shuffle_epi32(x2, 0xff);
    x3 = x0;
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x3 = _mm_bslli_si128(x3, 4);
    x0 = _mm_xor_si128(x0, x3);
    x0 = _mm_xor_si128(x0, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rsi, 224), x0);
}

WC_X64I_TARGET("sse2,aes")
WOLFSSL_LOCAL void AES_ECB_encrypt_AESNI(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr)
{
    word64 rdi, rsi, rdx, rcx, r8, rax, r9, r10 = 0, r11 = 0;
    __m128i x0 = _mm_setzero_si128(), x1 = _mm_setzero_si128(),
            x2 = _mm_setzero_si128(), x3 = _mm_setzero_si128(),
            x4 = _mm_setzero_si128(), x5 = _mm_setzero_si128(),
            x6 = _mm_setzero_si128();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;
    word32 zf5;
    word32 zf6;
    word32 zf7;
    word32 zf8;
    word32 zf9;
    word32 zf10;
    word32 zf11;
    word32 zf12;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(word64)length;
    rcx = (word64)(size_t)KS;
    r8 = (word64)(word32)nr;

    rax = (word32)(0);
    zf1 = (word32)rdx;
    zf2 = 0x40;
    r9 = (word32)((word32)rdx);
    if ((zf1) < (zf2)) {
        goto L_AES_ECB_encrypt_AESNI_done_64;
    }
    r9 = (word32)((word32)r9 & 0xffffffc0);
L_AES_ECB_encrypt_AESNI_enc_64:
    /* 64 bytes of input */
    /* aes_ecb_enc_64 */
    r10 = (word64)(rdi + rax);
    r11 = (word64)(rsi + rax);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    /* aes_enc_block */
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x0 = _mm_xor_si128(x0, x4);
    x1 = _mm_xor_si128(x1, x4);
    x2 = _mm_xor_si128(x2, x4);
    x3 = _mm_xor_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 128));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 144));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    zf3 = (word32)r8;
    zf4 = 0xb;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 160));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_ECB_encrypt_AESNI_64_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 176));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    zf5 = (word32)r8;
    zf6 = 0xd;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 192));
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_ECB_encrypt_AESNI_64_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 208));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 224));
L_AES_ECB_encrypt_AESNI_64_aes_enc_block_last:
    x0 = _mm_aesenclast_si128(x0, x4);
    x1 = _mm_aesenclast_si128(x1, x4);
    x2 = _mm_aesenclast_si128(x2, x4);
    x3 = _mm_aesenclast_si128(x3, x4);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 0), x0);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 16), x1);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 32), x2);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 48), x3);
    rax = (word32)((word32)rax + 0x40);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_encrypt_AESNI_enc_64;
    }
L_AES_ECB_encrypt_AESNI_done_64:
    zf7 = (word32)rax;
    zf8 = (word32)rdx;
    r9 = (word32)((word32)rdx);
    if ((zf7) == (zf8)) {
        goto L_AES_ECB_encrypt_AESNI_done_enc;
    }
    r9 = (word32)((word32)r9 & 0xfffffff0);
L_AES_ECB_encrypt_AESNI_enc_16:
    /* 16 bytes of input */
    r10 = (word64)(rdi + rax);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    /* aes_enc_block */
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 128));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 144));
    x0 = _mm_aesenc_si128(x0, x5);
    zf9 = (word32)r8;
    zf10 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 160));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_ECB_encrypt_AESNI_16_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 176));
    x0 = _mm_aesenc_si128(x0, x6);
    zf11 = (word32)r8;
    zf12 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 192));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_ECB_encrypt_AESNI_16_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 208));
    x0 = _mm_aesenc_si128(x0, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 224));
L_AES_ECB_encrypt_AESNI_16_aes_enc_block_last:
    x0 = _mm_aesenclast_si128(x0, x5);
    r10 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 0), x0);
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_encrypt_AESNI_enc_16;
    }
L_AES_ECB_encrypt_AESNI_done_enc:
    ;
}

WC_X64I_TARGET("sse2,aes")
WOLFSSL_LOCAL void AES_ECB_decrypt_AESNI(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr)
{
    word64 rdi, rsi, rdx, rcx, r8, rax, r9, r10 = 0, r11 = 0;
    __m128i x0 = _mm_setzero_si128(), x1 = _mm_setzero_si128(),
            x2 = _mm_setzero_si128(), x3 = _mm_setzero_si128(),
            x4 = _mm_setzero_si128(), x5 = _mm_setzero_si128(),
            x6 = _mm_setzero_si128();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;
    word32 zf5;
    word32 zf6;
    word32 zf7;
    word32 zf8;
    word32 zf9;
    word32 zf10;
    word32 zf11;
    word32 zf12;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(word64)length;
    rcx = (word64)(size_t)KS;
    r8 = (word64)(word32)nr;

    rax = (word32)(0);
    zf1 = (word32)rdx;
    zf2 = 0x40;
    r9 = (word32)((word32)rdx);
    if ((zf1) < (zf2)) {
        goto L_AES_ECB_decrypt_AESNI_done_64;
    }
    r9 = (word32)((word32)r9 & 0xffffffc0);
L_AES_ECB_decrypt_AESNI_dec_64:
    /* 64 bytes of input */
    /* aes_ecb_dec_64 */
    r10 = (word64)(rdi + rax);
    r11 = (word64)(rsi + rax);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    /* aes_dec_block */
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x0 = _mm_xor_si128(x0, x4);
    x1 = _mm_xor_si128(x1, x4);
    x2 = _mm_xor_si128(x2, x4);
    x3 = _mm_xor_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 128));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 144));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    zf3 = (word32)r8;
    zf4 = 0xb;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 160));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_ECB_decrypt_AESNI_64_aes_dec_block_last;
    }
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 176));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    zf5 = (word32)r8;
    zf6 = 0xd;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 192));
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_ECB_decrypt_AESNI_64_aes_dec_block_last;
    }
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 208));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 224));
L_AES_ECB_decrypt_AESNI_64_aes_dec_block_last:
    x0 = _mm_aesdeclast_si128(x0, x4);
    x1 = _mm_aesdeclast_si128(x1, x4);
    x2 = _mm_aesdeclast_si128(x2, x4);
    x3 = _mm_aesdeclast_si128(x3, x4);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 0), x0);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 16), x1);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 32), x2);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 48), x3);
    rax = (word32)((word32)rax + 0x40);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_decrypt_AESNI_dec_64;
    }
L_AES_ECB_decrypt_AESNI_done_64:
    zf7 = (word32)rax;
    zf8 = (word32)rdx;
    r9 = (word32)((word32)rdx);
    if ((zf7) == (zf8)) {
        goto L_AES_ECB_decrypt_AESNI_done_dec;
    }
    r9 = (word32)((word32)r9 & 0xfffffff0);
L_AES_ECB_decrypt_AESNI_dec_16:
    /* 16 bytes of input */
    r10 = (word64)(rdi + rax);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    /* aes_dec_block */
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x0 = _mm_aesdec_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x0 = _mm_aesdec_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x0 = _mm_aesdec_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64));
    x0 = _mm_aesdec_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80));
    x0 = _mm_aesdec_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96));
    x0 = _mm_aesdec_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112));
    x0 = _mm_aesdec_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 128));
    x0 = _mm_aesdec_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 144));
    x0 = _mm_aesdec_si128(x0, x5);
    zf9 = (word32)r8;
    zf10 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 160));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_ECB_decrypt_AESNI_16_aes_dec_block_last;
    }
    x0 = _mm_aesdec_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 176));
    x0 = _mm_aesdec_si128(x0, x6);
    zf11 = (word32)r8;
    zf12 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 192));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_ECB_decrypt_AESNI_16_aes_dec_block_last;
    }
    x0 = _mm_aesdec_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 208));
    x0 = _mm_aesdec_si128(x0, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 224));
L_AES_ECB_decrypt_AESNI_16_aes_dec_block_last:
    x0 = _mm_aesdeclast_si128(x0, x5);
    r10 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 0), x0);
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_decrypt_AESNI_dec_16;
    }
L_AES_ECB_decrypt_AESNI_done_dec:
    ;
}

WC_X64I_TARGET("sse2,aes")
WOLFSSL_LOCAL void AES_CBC_encrypt_AESNI(const unsigned char* in,
    unsigned char* out, unsigned char* ivec, unsigned long length,
    const unsigned char* KS, int nr)
{
    word64 rdi, rsi, rdx, rcx, r8, r9, rax, r10 = 0, r11 = 0;
    __m128i x0, x1 = _mm_setzero_si128(), x3 = _mm_setzero_si128(),
            x4 = _mm_setzero_si128();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(size_t)ivec;
    rcx = (word64)(word64)length;
    r8 = (word64)(size_t)KS;
    r9 = (word64)(word32)nr;

    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0));
    rax = (word32)(0);
    if (((word32)rax) == ((word32)rcx)) {
        goto L_AES_CBC_encrypt_AESNI_done;
    }
L_AES_CBC_encrypt_AESNI_loop:
    /* 16 bytes of input */
    r10 = (word64)(rdi + rax);
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    x1 = _mm_xor_si128(x1, x0);
    /* aes_enc_block */
    x1 = _mm_xor_si128(x1, _mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x1 = _mm_aesenc_si128(x1, x3);
    zf1 = (word32)r9;
    zf2 = 0xb;
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_CBC_encrypt_AESNI_aes_enc_block_last;
    }
    x1 = _mm_aesenc_si128(x1, x3);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x1 = _mm_aesenc_si128(x1, x4);
    zf3 = (word32)r9;
    zf4 = 0xd;
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_CBC_encrypt_AESNI_aes_enc_block_last;
    }
    x1 = _mm_aesenc_si128(x1, x3);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x1 = _mm_aesenc_si128(x1, x4);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_CBC_encrypt_AESNI_aes_enc_block_last:
    x1 = _mm_aesenclast_si128(x1, x3);
    r11 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 0), x1);
    x0 = x1;
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)rcx)) {
        goto L_AES_CBC_encrypt_AESNI_loop;
    }
L_AES_CBC_encrypt_AESNI_done:
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x0);
}

WC_X64I_TARGET("sse2,aes")
WOLFSSL_LOCAL void AES_CBC_decrypt_AESNI(const unsigned char* in,
    unsigned char* out, unsigned char* ivec, unsigned long length,
    const unsigned char* KS, int nr)
{
    word64 rdi, rsi, rdx, rcx, r8, r9, rax, r10, r11 = 0, r12 = 0;
    __m128i x0 = _mm_setzero_si128(), x1 = _mm_setzero_si128(),
            x2 = _mm_setzero_si128(), x3 = _mm_setzero_si128(), x4,
            x5 = _mm_setzero_si128(), x6 = _mm_setzero_si128(),
            x7 = _mm_setzero_si128(), x8 = _mm_setzero_si128();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;
    word32 zf5;
    word32 zf6;
    word32 zf7;
    word32 zf8;
    word32 zf9;
    word32 zf10;
    word32 zf11;
    word32 zf12;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(size_t)ivec;
    rcx = (word64)(word64)length;
    r8 = (word64)(size_t)KS;
    r9 = (word64)(word32)nr;

    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0));
    rax = (word32)(0);
    zf1 = (word32)rcx;
    zf2 = 0x40;
    r10 = (word32)((word32)rcx);
    if ((zf1) < (zf2)) {
        goto L_AES_CBC_decrypt_AESNI_done_64;
    }
    r10 = (word32)((word32)r10 & 0xffffffc0);
L_AES_CBC_decrypt_AESNI_dec_64:
    /* 64 bytes of input */
    /* aes_cbc_dec_64 */
    r11 = (word64)(rdi + rax);
    r12 = (word64)(rsi + rax);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 16));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 48));
    /* aes_dec_block */
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 0));
    x0 = _mm_xor_si128(x0, x5);
    x1 = _mm_xor_si128(x1, x5);
    x2 = _mm_xor_si128(x2, x5);
    x3 = _mm_xor_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    zf3 = (word32)r9;
    zf4 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_CBC_decrypt_AESNI_64_aes_dec_block_last;
    }
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    zf5 = (word32)r9;
    zf6 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_CBC_decrypt_AESNI_64_aes_dec_block_last;
    }
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_CBC_decrypt_AESNI_64_aes_dec_block_last:
    x0 = _mm_aesdeclast_si128(x0, x5);
    x1 = _mm_aesdeclast_si128(x1, x5);
    x2 = _mm_aesdeclast_si128(x2, x5);
    x3 = _mm_aesdeclast_si128(x3, x5);
    x0 = _mm_xor_si128(x0, x4);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 0));
    x1 = _mm_xor_si128(x1, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 16));
    x2 = _mm_xor_si128(x2, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 32));
    x3 = _mm_xor_si128(x3, x5);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 48));
    _mm_storeu_si128((__m128i*)WC_PW(r12, 0), x0);
    _mm_storeu_si128((__m128i*)WC_PW(r12, 16), x1);
    _mm_storeu_si128((__m128i*)WC_PW(r12, 32), x2);
    _mm_storeu_si128((__m128i*)WC_PW(r12, 48), x3);
    rax = (word32)((word32)rax + 0x40);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CBC_decrypt_AESNI_dec_64;
    }
L_AES_CBC_decrypt_AESNI_done_64:
    zf7 = (word32)rax;
    zf8 = (word32)rcx;
    r10 = (word32)((word32)rcx);
    if ((zf7) == (zf8)) {
        goto L_AES_CBC_decrypt_AESNI_done_dec;
    }
    r10 = (word32)((word32)r10 & 0xfffffff0);
L_AES_CBC_decrypt_AESNI_dec_16:
    /* 16 bytes of input */
    r11 = (word64)(rdi + rax);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 0));
    x8 = x0;
    /* aes_dec_block */
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x0 = _mm_aesdec_si128(x0, x6);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x0 = _mm_aesdec_si128(x0, x6);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x0 = _mm_aesdec_si128(x0, x6);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x0 = _mm_aesdec_si128(x0, x6);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x0 = _mm_aesdec_si128(x0, x6);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x0 = _mm_aesdec_si128(x0, x6);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x0 = _mm_aesdec_si128(x0, x6);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x0 = _mm_aesdec_si128(x0, x6);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x0 = _mm_aesdec_si128(x0, x6);
    zf9 = (word32)r9;
    zf10 = 0xb;
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_CBC_decrypt_AESNI_16_aes_dec_block_last;
    }
    x0 = _mm_aesdec_si128(x0, x6);
    x7 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x0 = _mm_aesdec_si128(x0, x7);
    zf11 = (word32)r9;
    zf12 = 0xd;
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_CBC_decrypt_AESNI_16_aes_dec_block_last;
    }
    x0 = _mm_aesdec_si128(x0, x6);
    x7 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x0 = _mm_aesdec_si128(x0, x7);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_CBC_decrypt_AESNI_16_aes_dec_block_last:
    x0 = _mm_aesdeclast_si128(x0, x6);
    x0 = _mm_xor_si128(x0, x4);
    x4 = x8;
    r11 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 0), x0);
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CBC_decrypt_AESNI_dec_16;
    }
L_AES_CBC_decrypt_AESNI_done_dec:
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x4);
}

XALIGNED(16) static const word64 L_aes_ctr_aesni_bswap[] WC_X64I_UNUSED = {
    0x08090a0b0c0d0e0fULL, 0x0001020304050607ULL,
};

XALIGNED(16) static const word64 L_aes_ctr_aesni_one[] WC_X64I_UNUSED = {
    0x0000000000000001ULL, 0x0000000000000000ULL,
};

WC_X64I_TARGET("sse2,ssse3,sse4.1,aes")
WOLFSSL_LOCAL void AES_CTR_encrypt_AESNI(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr,
    unsigned char* ctr)
{
    word64 rdi, rsi, rdx, rcx, r8, r9, rax, r10, r11 = 0, r12 = 0;
    __m128i x0 = _mm_setzero_si128(), x1 = _mm_setzero_si128(),
            x2 = _mm_setzero_si128(), x3 = _mm_setzero_si128(),
            x4 = _mm_setzero_si128(), x5 = _mm_setzero_si128(),
            x6 = _mm_setzero_si128(), x7, x8, x9, x10,
            x11 = _mm_setzero_si128();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;
    word32 zf5;
    word32 zf6;
    word32 zf7;
    word32 zf8;
    word32 zf9;
    word32 zf10;
    word32 zf11;
    word32 zf12;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(word64)length;
    rcx = (word64)(size_t)KS;
    r8 = (word64)(word32)nr;
    r9 = (word64)(size_t)ctr;

    x8 = _mm_loadu_si128((const __m128i*)WC_PR(L_aes_ctr_aesni_bswap, 0));
    x9 = _mm_loadu_si128((const __m128i*)WC_PR(L_aes_ctr_aesni_one, 0));
    x10 = _mm_setzero_si128();
    x7 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 0));
    x7 = _mm_shuffle_epi8(x7, x8);
    rax = (word32)(0);
    zf1 = (word32)rdx;
    zf2 = 0x40;
    r10 = (word32)((word32)rdx);
    if ((zf1) < (zf2)) {
        goto L_AES_CTR_encrypt_AESNI_done_64;
    }
    r10 = (word32)((word32)r10 & 0xffffffc0);
L_AES_CTR_encrypt_AESNI_enc_64:
    /* 64 bytes of input */
    /* aes_ctr_enc_64 */
    r11 = (word64)(rdi + rax);
    r12 = (word64)(rsi + rax);
    x0 = x7;
    x0 = _mm_shuffle_epi8(x0, x8);
    x7 = _mm_add_epi64(x7, x9);
    x11 = x7;
    x11 = _mm_cmpeq_epi64(x11, x10);
    x11 = _mm_bslli_si128(x11, 8);
    x11 = _mm_srli_epi64(x11, 63);
    x7 = _mm_add_epi64(x7, x11);
    x1 = x7;
    x1 = _mm_shuffle_epi8(x1, x8);
    x7 = _mm_add_epi64(x7, x9);
    x11 = x7;
    x11 = _mm_cmpeq_epi64(x11, x10);
    x11 = _mm_bslli_si128(x11, 8);
    x11 = _mm_srli_epi64(x11, 63);
    x7 = _mm_add_epi64(x7, x11);
    x2 = x7;
    x2 = _mm_shuffle_epi8(x2, x8);
    x7 = _mm_add_epi64(x7, x9);
    x11 = x7;
    x11 = _mm_cmpeq_epi64(x11, x10);
    x11 = _mm_bslli_si128(x11, 8);
    x11 = _mm_srli_epi64(x11, 63);
    x7 = _mm_add_epi64(x7, x11);
    x3 = x7;
    x3 = _mm_shuffle_epi8(x3, x8);
    x7 = _mm_add_epi64(x7, x9);
    x11 = x7;
    x11 = _mm_cmpeq_epi64(x11, x10);
    x11 = _mm_bslli_si128(x11, 8);
    x11 = _mm_srli_epi64(x11, 63);
    x7 = _mm_add_epi64(x7, x11);
    /* aes_enc_block */
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x0 = _mm_xor_si128(x0, x4);
    x1 = _mm_xor_si128(x1, x4);
    x2 = _mm_xor_si128(x2, x4);
    x3 = _mm_xor_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 128));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 144));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    zf3 = (word32)r8;
    zf4 = 0xb;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 160));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_CTR_encrypt_AESNI_64_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 176));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    zf5 = (word32)r8;
    zf6 = 0xd;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 192));
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_CTR_encrypt_AESNI_64_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 208));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 224));
L_AES_CTR_encrypt_AESNI_64_aes_enc_block_last:
    x0 = _mm_aesenclast_si128(x0, x4);
    x1 = _mm_aesenclast_si128(x1, x4);
    x2 = _mm_aesenclast_si128(x2, x4);
    x3 = _mm_aesenclast_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 0));
    x0 = _mm_xor_si128(x0, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 16));
    x1 = _mm_xor_si128(x1, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 32));
    x2 = _mm_xor_si128(x2, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 48));
    x3 = _mm_xor_si128(x3, x4);
    _mm_storeu_si128((__m128i*)WC_PW(r12, 0), x0);
    _mm_storeu_si128((__m128i*)WC_PW(r12, 16), x1);
    _mm_storeu_si128((__m128i*)WC_PW(r12, 32), x2);
    _mm_storeu_si128((__m128i*)WC_PW(r12, 48), x3);
    rax = (word32)((word32)rax + 0x40);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CTR_encrypt_AESNI_enc_64;
    }
L_AES_CTR_encrypt_AESNI_done_64:
    zf7 = (word32)rax;
    zf8 = (word32)rdx;
    r10 = (word32)((word32)rdx);
    if ((zf7) == (zf8)) {
        goto L_AES_CTR_encrypt_AESNI_done_enc;
    }
    r10 = (word32)((word32)r10 & 0xfffffff0);
L_AES_CTR_encrypt_AESNI_enc_16:
    /* 16 bytes of input */
    x0 = x7;
    x0 = _mm_shuffle_epi8(x0, x8);
    x7 = _mm_add_epi64(x7, x9);
    x11 = x7;
    x11 = _mm_cmpeq_epi64(x11, x10);
    x11 = _mm_bslli_si128(x11, 8);
    x11 = _mm_srli_epi64(x11, 63);
    x7 = _mm_add_epi64(x7, x11);
    /* aes_enc_block */
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 128));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 144));
    x0 = _mm_aesenc_si128(x0, x5);
    zf9 = (word32)r8;
    zf10 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 160));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_CTR_encrypt_AESNI_16_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 176));
    x0 = _mm_aesenc_si128(x0, x6);
    zf11 = (word32)r8;
    zf12 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 192));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_CTR_encrypt_AESNI_16_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 208));
    x0 = _mm_aesenc_si128(x0, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 224));
L_AES_CTR_encrypt_AESNI_16_aes_enc_block_last:
    x0 = _mm_aesenclast_si128(x0, x5);
    r11 = (word64)(rdi + rax);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 0));
    x0 = _mm_xor_si128(x0, x4);
    r11 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 0), x0);
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CTR_encrypt_AESNI_enc_16;
    }
L_AES_CTR_encrypt_AESNI_done_enc:
    x7 = _mm_shuffle_epi8(x7, x8);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 0), x7);
}

#ifdef HAVE_INTEL_AVX1
WC_X64I_TARGET("aes,avx")
WOLFSSL_LOCAL void AES_ECB_encrypt_avx1(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr)
{
    word64 rdi, rsi, rdx, rcx, r8, rax, r9, r10 = 0, r11 = 0;
    __m128i x0 = _mm_setzero_si128(), x1 = _mm_setzero_si128(),
            x2 = _mm_setzero_si128(), x3 = _mm_setzero_si128(),
            x4 = _mm_setzero_si128(), x5 = _mm_setzero_si128(),
            x6 = _mm_setzero_si128();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;
    word32 zf5;
    word32 zf6;
    word32 zf7;
    word32 zf8;
    word32 zf9;
    word32 zf10;
    word32 zf11;
    word32 zf12;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(word64)length;
    rcx = (word64)(size_t)KS;
    r8 = (word64)(word32)nr;

    rax = (word32)(0);
    zf1 = (word32)rdx;
    zf2 = 0x40;
    r9 = (word32)((word32)rdx);
    if ((zf1) < (zf2)) {
        goto L_AES_ECB_encrypt_avx1_done_64;
    }
    r9 = (word32)((word32)r9 & 0xffffffc0);
L_AES_ECB_encrypt_avx1_enc_64:
    /* 64 bytes of input */
    /* aes_ecb_enc_64 */
    r10 = (word64)(rdi + rax);
    r11 = (word64)(rsi + rax);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    /* aes_enc_block */
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x0 = _mm_xor_si128(x0, x4);
    x1 = _mm_xor_si128(x1, x4);
    x2 = _mm_xor_si128(x2, x4);
    x3 = _mm_xor_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 128));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 144));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    zf3 = (word32)r8;
    zf4 = 0xb;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 160));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_ECB_encrypt_avx1_64_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 176));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    zf5 = (word32)r8;
    zf6 = 0xd;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 192));
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_ECB_encrypt_avx1_64_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 208));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 224));
L_AES_ECB_encrypt_avx1_64_aes_enc_block_last:
    x0 = _mm_aesenclast_si128(x0, x4);
    x1 = _mm_aesenclast_si128(x1, x4);
    x2 = _mm_aesenclast_si128(x2, x4);
    x3 = _mm_aesenclast_si128(x3, x4);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 0), x0);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 16), x1);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 32), x2);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 48), x3);
    rax = (word32)((word32)rax + 0x40);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_encrypt_avx1_enc_64;
    }
L_AES_ECB_encrypt_avx1_done_64:
    zf7 = (word32)rax;
    zf8 = (word32)rdx;
    r9 = (word32)((word32)rdx);
    if ((zf7) == (zf8)) {
        goto L_AES_ECB_encrypt_avx1_done_enc;
    }
    r9 = (word32)((word32)r9 & 0xfffffff0);
L_AES_ECB_encrypt_avx1_enc_16:
    /* 16 bytes of input */
    r10 = (word64)(rdi + rax);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    /* aes_enc_block */
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 128));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 144));
    x0 = _mm_aesenc_si128(x0, x5);
    zf9 = (word32)r8;
    zf10 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 160));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_ECB_encrypt_avx1_16_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 176));
    x0 = _mm_aesenc_si128(x0, x6);
    zf11 = (word32)r8;
    zf12 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 192));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_ECB_encrypt_avx1_16_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 208));
    x0 = _mm_aesenc_si128(x0, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 224));
L_AES_ECB_encrypt_avx1_16_aes_enc_block_last:
    x0 = _mm_aesenclast_si128(x0, x5);
    r10 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 0), x0);
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_encrypt_avx1_enc_16;
    }
L_AES_ECB_encrypt_avx1_done_enc:
    ;
}

WC_X64I_TARGET("aes,avx")
WOLFSSL_LOCAL void AES_ECB_decrypt_avx1(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr)
{
    word64 rdi, rsi, rdx, rcx, r8, rax, r9, r10 = 0, r11 = 0;
    __m128i x0 = _mm_setzero_si128(), x1 = _mm_setzero_si128(),
            x2 = _mm_setzero_si128(), x3 = _mm_setzero_si128(),
            x4 = _mm_setzero_si128(), x5 = _mm_setzero_si128(),
            x6 = _mm_setzero_si128();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;
    word32 zf5;
    word32 zf6;
    word32 zf7;
    word32 zf8;
    word32 zf9;
    word32 zf10;
    word32 zf11;
    word32 zf12;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(word64)length;
    rcx = (word64)(size_t)KS;
    r8 = (word64)(word32)nr;

    rax = (word32)(0);
    zf1 = (word32)rdx;
    zf2 = 0x40;
    r9 = (word32)((word32)rdx);
    if ((zf1) < (zf2)) {
        goto L_AES_ECB_decrypt_avx1_done_64;
    }
    r9 = (word32)((word32)r9 & 0xffffffc0);
L_AES_ECB_decrypt_avx1_dec_64:
    /* 64 bytes of input */
    /* aes_ecb_dec_64 */
    r10 = (word64)(rdi + rax);
    r11 = (word64)(rsi + rax);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    /* aes_dec_block */
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x0 = _mm_xor_si128(x0, x4);
    x1 = _mm_xor_si128(x1, x4);
    x2 = _mm_xor_si128(x2, x4);
    x3 = _mm_xor_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 128));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 144));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    zf3 = (word32)r8;
    zf4 = 0xb;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 160));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_ECB_decrypt_avx1_64_aes_dec_block_last;
    }
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 176));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    zf5 = (word32)r8;
    zf6 = 0xd;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 192));
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_ECB_decrypt_avx1_64_aes_dec_block_last;
    }
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 208));
    x0 = _mm_aesdec_si128(x0, x4);
    x1 = _mm_aesdec_si128(x1, x4);
    x2 = _mm_aesdec_si128(x2, x4);
    x3 = _mm_aesdec_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 224));
L_AES_ECB_decrypt_avx1_64_aes_dec_block_last:
    x0 = _mm_aesdeclast_si128(x0, x4);
    x1 = _mm_aesdeclast_si128(x1, x4);
    x2 = _mm_aesdeclast_si128(x2, x4);
    x3 = _mm_aesdeclast_si128(x3, x4);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 0), x0);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 16), x1);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 32), x2);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 48), x3);
    rax = (word32)((word32)rax + 0x40);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_decrypt_avx1_dec_64;
    }
L_AES_ECB_decrypt_avx1_done_64:
    zf7 = (word32)rax;
    zf8 = (word32)rdx;
    r9 = (word32)((word32)rdx);
    if ((zf7) == (zf8)) {
        goto L_AES_ECB_decrypt_avx1_done_dec;
    }
    r9 = (word32)((word32)r9 & 0xfffffff0);
L_AES_ECB_decrypt_avx1_dec_16:
    /* 16 bytes of input */
    r10 = (word64)(rdi + rax);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    /* aes_dec_block */
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x0 = _mm_aesdec_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x0 = _mm_aesdec_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x0 = _mm_aesdec_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64));
    x0 = _mm_aesdec_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80));
    x0 = _mm_aesdec_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96));
    x0 = _mm_aesdec_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112));
    x0 = _mm_aesdec_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 128));
    x0 = _mm_aesdec_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 144));
    x0 = _mm_aesdec_si128(x0, x5);
    zf9 = (word32)r8;
    zf10 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 160));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_ECB_decrypt_avx1_16_aes_dec_block_last;
    }
    x0 = _mm_aesdec_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 176));
    x0 = _mm_aesdec_si128(x0, x6);
    zf11 = (word32)r8;
    zf12 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 192));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_ECB_decrypt_avx1_16_aes_dec_block_last;
    }
    x0 = _mm_aesdec_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 208));
    x0 = _mm_aesdec_si128(x0, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 224));
L_AES_ECB_decrypt_avx1_16_aes_dec_block_last:
    x0 = _mm_aesdeclast_si128(x0, x5);
    r10 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 0), x0);
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_decrypt_avx1_dec_16;
    }
L_AES_ECB_decrypt_avx1_done_dec:
    ;
}

WC_X64I_TARGET("aes,avx")
WOLFSSL_LOCAL void AES_CBC_encrypt_avx1(const unsigned char* in,
    unsigned char* out, unsigned char* ivec, unsigned long length,
    const unsigned char* KS, int nr)
{
    word64 rdi, rsi, rdx, rcx, r8, r9, rax, r10 = 0, r11 = 0;
    __m128i x0, x1 = _mm_setzero_si128(), x3 = _mm_setzero_si128(),
            x4 = _mm_setzero_si128();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(size_t)ivec;
    rcx = (word64)(word64)length;
    r8 = (word64)(size_t)KS;
    r9 = (word64)(word32)nr;

    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0));
    rax = (word32)(0);
    if (((word32)rax) == ((word32)rcx)) {
        goto L_AES_CBC_encrypt_avx1_done;
    }
L_AES_CBC_encrypt_avx1_loop:
    /* 16 bytes of input */
    r10 = (word64)(rdi + rax);
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    x1 = _mm_xor_si128(x1, x0);
    /* aes_enc_block */
    x1 = _mm_xor_si128(x1, _mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x1 = _mm_aesenc_si128(x1, x3);
    zf1 = (word32)r9;
    zf2 = 0xb;
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_CBC_encrypt_avx1_aes_enc_block_last;
    }
    x1 = _mm_aesenc_si128(x1, x3);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x1 = _mm_aesenc_si128(x1, x4);
    zf3 = (word32)r9;
    zf4 = 0xd;
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_CBC_encrypt_avx1_aes_enc_block_last;
    }
    x1 = _mm_aesenc_si128(x1, x3);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x1 = _mm_aesenc_si128(x1, x4);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_CBC_encrypt_avx1_aes_enc_block_last:
    x1 = _mm_aesenclast_si128(x1, x3);
    r11 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 0), x1);
    x0 = x1;
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)rcx)) {
        goto L_AES_CBC_encrypt_avx1_loop;
    }
L_AES_CBC_encrypt_avx1_done:
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x0);
}

WC_X64I_TARGET("aes,avx")
WOLFSSL_LOCAL void AES_CBC_decrypt_avx1(const unsigned char* in,
    unsigned char* out, unsigned char* ivec, unsigned long length,
    const unsigned char* KS, int nr)
{
    word64 rdi, rsi, rdx, rcx, r8, r9, rax, r10, r11 = 0, r12 = 0;
    __m128i x0 = _mm_setzero_si128(), x1 = _mm_setzero_si128(),
            x2 = _mm_setzero_si128(), x3 = _mm_setzero_si128(), x4,
            x5 = _mm_setzero_si128(), x6 = _mm_setzero_si128(),
            x7 = _mm_setzero_si128(), x8 = _mm_setzero_si128();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;
    word32 zf5;
    word32 zf6;
    word32 zf7;
    word32 zf8;
    word32 zf9;
    word32 zf10;
    word32 zf11;
    word32 zf12;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(size_t)ivec;
    rcx = (word64)(word64)length;
    r8 = (word64)(size_t)KS;
    r9 = (word64)(word32)nr;

    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0));
    rax = (word32)(0);
    zf1 = (word32)rcx;
    zf2 = 0x40;
    r10 = (word32)((word32)rcx);
    if ((zf1) < (zf2)) {
        goto L_AES_CBC_decrypt_avx1_done_64;
    }
    r10 = (word32)((word32)r10 & 0xffffffc0);
L_AES_CBC_decrypt_avx1_dec_64:
    /* 64 bytes of input */
    /* aes_cbc_dec_64 */
    r11 = (word64)(rdi + rax);
    r12 = (word64)(rsi + rax);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 0));
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 16));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 32));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 48));
    /* aes_dec_block */
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 0));
    x0 = _mm_xor_si128(x0, x5);
    x1 = _mm_xor_si128(x1, x5);
    x2 = _mm_xor_si128(x2, x5);
    x3 = _mm_xor_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    zf3 = (word32)r9;
    zf4 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_CBC_decrypt_avx1_64_aes_dec_block_last;
    }
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    zf5 = (word32)r9;
    zf6 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_CBC_decrypt_avx1_64_aes_dec_block_last;
    }
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x0 = _mm_aesdec_si128(x0, x5);
    x1 = _mm_aesdec_si128(x1, x5);
    x2 = _mm_aesdec_si128(x2, x5);
    x3 = _mm_aesdec_si128(x3, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_CBC_decrypt_avx1_64_aes_dec_block_last:
    x0 = _mm_aesdeclast_si128(x0, x5);
    x1 = _mm_aesdeclast_si128(x1, x5);
    x2 = _mm_aesdeclast_si128(x2, x5);
    x3 = _mm_aesdeclast_si128(x3, x5);
    x0 = _mm_xor_si128(x0, x4);
    x1 = _mm_xor_si128(x1, _mm_loadu_si128((const __m128i*)WC_PR(r11, 0)));
    x2 = _mm_xor_si128(x2, _mm_loadu_si128((const __m128i*)WC_PR(r11, 16)));
    x3 = _mm_xor_si128(x3, _mm_loadu_si128((const __m128i*)WC_PR(r11, 32)));
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 48));
    _mm_storeu_si128((__m128i*)WC_PW(r12, 0), x0);
    _mm_storeu_si128((__m128i*)WC_PW(r12, 16), x1);
    _mm_storeu_si128((__m128i*)WC_PW(r12, 32), x2);
    _mm_storeu_si128((__m128i*)WC_PW(r12, 48), x3);
    rax = (word32)((word32)rax + 0x40);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CBC_decrypt_avx1_dec_64;
    }
L_AES_CBC_decrypt_avx1_done_64:
    zf7 = (word32)rax;
    zf8 = (word32)rcx;
    r10 = (word32)((word32)rcx);
    if ((zf7) == (zf8)) {
        goto L_AES_CBC_decrypt_avx1_done_dec;
    }
    r10 = (word32)((word32)r10 & 0xfffffff0);
L_AES_CBC_decrypt_avx1_dec_16:
    /* 16 bytes of input */
    r11 = (word64)(rdi + rax);
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r11, 0));
    x8 = x0;
    /* aes_dec_block */
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x0 = _mm_aesdec_si128(x0, x6);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x0 = _mm_aesdec_si128(x0, x6);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x0 = _mm_aesdec_si128(x0, x6);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x0 = _mm_aesdec_si128(x0, x6);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x0 = _mm_aesdec_si128(x0, x6);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x0 = _mm_aesdec_si128(x0, x6);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x0 = _mm_aesdec_si128(x0, x6);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x0 = _mm_aesdec_si128(x0, x6);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x0 = _mm_aesdec_si128(x0, x6);
    zf9 = (word32)r9;
    zf10 = 0xb;
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_CBC_decrypt_avx1_16_aes_dec_block_last;
    }
    x0 = _mm_aesdec_si128(x0, x6);
    x7 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x0 = _mm_aesdec_si128(x0, x7);
    zf11 = (word32)r9;
    zf12 = 0xd;
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_CBC_decrypt_avx1_16_aes_dec_block_last;
    }
    x0 = _mm_aesdec_si128(x0, x6);
    x7 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x0 = _mm_aesdec_si128(x0, x7);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_CBC_decrypt_avx1_16_aes_dec_block_last:
    x0 = _mm_aesdeclast_si128(x0, x6);
    x0 = _mm_xor_si128(x0, x4);
    x4 = x8;
    r11 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 0), x0);
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CBC_decrypt_avx1_dec_16;
    }
L_AES_CBC_decrypt_avx1_done_dec:
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x4);
}

XALIGNED(16) static const word64 L_aes_ctr_avx1_bswap[] WC_X64I_UNUSED = {
    0x08090a0b0c0d0e0fULL, 0x0001020304050607ULL,
};

XALIGNED(16) static const word64 L_aes_ctr_avx1_one[] WC_X64I_UNUSED = {
    0x0000000000000001ULL, 0x0000000000000000ULL,
};

WC_X64I_TARGET("aes,avx")
WOLFSSL_LOCAL void AES_CTR_encrypt_avx1(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr,
    unsigned char* ctr)
{
    word64 rdi, rsi, rdx, rcx, r8, r9, rax, r10, r11 = 0, r12 = 0;
    __m128i x0 = _mm_setzero_si128(), x1 = _mm_setzero_si128(),
            x2 = _mm_setzero_si128(), x3 = _mm_setzero_si128(),
            x4 = _mm_setzero_si128(), x5 = _mm_setzero_si128(),
            x6 = _mm_setzero_si128(), x7, x8, x9, x10,
            x11 = _mm_setzero_si128();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;
    word32 zf5;
    word32 zf6;
    word32 zf7;
    word32 zf8;
    word32 zf9;
    word32 zf10;
    word32 zf11;
    word32 zf12;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(word64)length;
    rcx = (word64)(size_t)KS;
    r8 = (word64)(word32)nr;
    r9 = (word64)(size_t)ctr;

    x8 = _mm_loadu_si128((const __m128i*)WC_PR(L_aes_ctr_avx1_bswap, 0));
    x9 = _mm_loadu_si128((const __m128i*)WC_PR(L_aes_ctr_avx1_one, 0));
    x10 = _mm_setzero_si128();
    x7 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 0));
    x7 = _mm_shuffle_epi8(x7, x8);
    rax = (word32)(0);
    zf1 = (word32)rdx;
    zf2 = 0x40;
    r10 = (word32)((word32)rdx);
    if ((zf1) < (zf2)) {
        goto L_AES_CTR_encrypt_avx1_done_64;
    }
    r10 = (word32)((word32)r10 & 0xffffffc0);
L_AES_CTR_encrypt_avx1_enc_64:
    /* 64 bytes of input */
    /* aes_ctr_enc_64 */
    r11 = (word64)(rdi + rax);
    r12 = (word64)(rsi + rax);
    x0 = _mm_shuffle_epi8(x7, x8);
    x7 = _mm_add_epi64(x7, x9);
    x11 = _mm_cmpeq_epi64(x7, x10);
    x11 = _mm_bslli_si128(x11, 8);
    x11 = _mm_srli_epi64(x11, 63);
    x7 = _mm_add_epi64(x7, x11);
    x1 = _mm_shuffle_epi8(x7, x8);
    x7 = _mm_add_epi64(x7, x9);
    x11 = _mm_cmpeq_epi64(x7, x10);
    x11 = _mm_bslli_si128(x11, 8);
    x11 = _mm_srli_epi64(x11, 63);
    x7 = _mm_add_epi64(x7, x11);
    x2 = _mm_shuffle_epi8(x7, x8);
    x7 = _mm_add_epi64(x7, x9);
    x11 = _mm_cmpeq_epi64(x7, x10);
    x11 = _mm_bslli_si128(x11, 8);
    x11 = _mm_srli_epi64(x11, 63);
    x7 = _mm_add_epi64(x7, x11);
    x3 = _mm_shuffle_epi8(x7, x8);
    x7 = _mm_add_epi64(x7, x9);
    x11 = _mm_cmpeq_epi64(x7, x10);
    x11 = _mm_bslli_si128(x11, 8);
    x11 = _mm_srli_epi64(x11, 63);
    x7 = _mm_add_epi64(x7, x11);
    /* aes_enc_block */
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x0 = _mm_xor_si128(x0, x4);
    x1 = _mm_xor_si128(x1, x4);
    x2 = _mm_xor_si128(x2, x4);
    x3 = _mm_xor_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 128));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 144));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    zf3 = (word32)r8;
    zf4 = 0xb;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 160));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_CTR_encrypt_avx1_64_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 176));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    zf5 = (word32)r8;
    zf6 = 0xd;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 192));
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_CTR_encrypt_avx1_64_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 208));
    x0 = _mm_aesenc_si128(x0, x4);
    x1 = _mm_aesenc_si128(x1, x4);
    x2 = _mm_aesenc_si128(x2, x4);
    x3 = _mm_aesenc_si128(x3, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 224));
L_AES_CTR_encrypt_avx1_64_aes_enc_block_last:
    x0 = _mm_aesenclast_si128(x0, x4);
    x1 = _mm_aesenclast_si128(x1, x4);
    x2 = _mm_aesenclast_si128(x2, x4);
    x3 = _mm_aesenclast_si128(x3, x4);
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(r11, 0)));
    x1 = _mm_xor_si128(x1, _mm_loadu_si128((const __m128i*)WC_PR(r11, 16)));
    x2 = _mm_xor_si128(x2, _mm_loadu_si128((const __m128i*)WC_PR(r11, 32)));
    x3 = _mm_xor_si128(x3, _mm_loadu_si128((const __m128i*)WC_PR(r11, 48)));
    _mm_storeu_si128((__m128i*)WC_PW(r12, 0), x0);
    _mm_storeu_si128((__m128i*)WC_PW(r12, 16), x1);
    _mm_storeu_si128((__m128i*)WC_PW(r12, 32), x2);
    _mm_storeu_si128((__m128i*)WC_PW(r12, 48), x3);
    rax = (word32)((word32)rax + 0x40);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CTR_encrypt_avx1_enc_64;
    }
L_AES_CTR_encrypt_avx1_done_64:
    zf7 = (word32)rax;
    zf8 = (word32)rdx;
    r10 = (word32)((word32)rdx);
    if ((zf7) == (zf8)) {
        goto L_AES_CTR_encrypt_avx1_done_enc;
    }
    r10 = (word32)((word32)r10 & 0xfffffff0);
L_AES_CTR_encrypt_avx1_enc_16:
    /* 16 bytes of input */
    x0 = _mm_shuffle_epi8(x7, x8);
    x7 = _mm_add_epi64(x7, x9);
    x11 = _mm_cmpeq_epi64(x7, x10);
    x11 = _mm_bslli_si128(x11, 8);
    x11 = _mm_srli_epi64(x11, 63);
    x7 = _mm_add_epi64(x7, x11);
    /* aes_enc_block */
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 128));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 144));
    x0 = _mm_aesenc_si128(x0, x5);
    zf9 = (word32)r8;
    zf10 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 160));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_CTR_encrypt_avx1_16_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 176));
    x0 = _mm_aesenc_si128(x0, x6);
    zf11 = (word32)r8;
    zf12 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 192));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_CTR_encrypt_avx1_16_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 208));
    x0 = _mm_aesenc_si128(x0, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 224));
L_AES_CTR_encrypt_avx1_16_aes_enc_block_last:
    x0 = _mm_aesenclast_si128(x0, x5);
    r11 = (word64)(rdi + rax);
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(r11, 0)));
    r11 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 0), x0);
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CTR_encrypt_avx1_enc_16;
    }
L_AES_CTR_encrypt_avx1_done_enc:
    x7 = _mm_shuffle_epi8(x7, x8);
    _mm_storeu_si128((__m128i*)WC_PW(r9, 0), x7);
}

#endif /* HAVE_INTEL_AVX1 */
#ifdef HAVE_INTEL_VAES
WC_X64I_TARGET("aes,vaes,avx2")
WOLFSSL_LOCAL void AES_ECB_encrypt_vaes(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr)
{
    word64 rdi, rsi, rdx, rcx, r8, rax, r9, r10 = 0, r11 = 0;
    __m128i x5 = _mm_setzero_si128(), x6 = _mm_setzero_si128();
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y7 = _mm256_setzero_si256();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;
    word32 zf5;
    word32 zf6;
    word32 zf7;
    word32 zf8;
    word32 zf9;
    word32 zf10;
    word32 zf11;
    word32 zf12;
    word32 zf13;
    word32 zf14;
    word32 zf15;
    word32 zf16;
    word32 zf17;
    word32 zf18;
    word32 zf19;
    word32 zf20;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(word64)length;
    rcx = (word64)(size_t)KS;
    r8 = (word64)(word32)nr;

    rax = (word32)(0);
    zf1 = (word32)rdx;
    zf2 = 0x80;
    r9 = (word32)((word32)rdx);
    if ((zf1) < (zf2)) {
        goto L_AES_ECB_encrypt_vaes_done_128;
    }
    r9 = (word32)((word32)r9 & 0xffffff80);
L_AES_ECB_encrypt_vaes_enc_128:
    /* 128 bytes of input */
    /* aes_ecb_enc_128 */
    r10 = (word64)(rdi + rax);
    r11 = (word64)(rsi + rax);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 32));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 64));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 96));
    /* aes_enc_block */
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        0)));
    y0 = _mm256_xor_si256(y0, y7);
    y1 = _mm256_xor_si256(y1, y7);
    y2 = _mm256_xor_si256(y2, y7);
    y3 = _mm256_xor_si256(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        16)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y2 = _mm256_aesenc_epi128(y2, y7);
    y3 = _mm256_aesenc_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        32)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y2 = _mm256_aesenc_epi128(y2, y7);
    y3 = _mm256_aesenc_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        48)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y2 = _mm256_aesenc_epi128(y2, y7);
    y3 = _mm256_aesenc_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        64)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y2 = _mm256_aesenc_epi128(y2, y7);
    y3 = _mm256_aesenc_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        80)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y2 = _mm256_aesenc_epi128(y2, y7);
    y3 = _mm256_aesenc_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        96)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y2 = _mm256_aesenc_epi128(y2, y7);
    y3 = _mm256_aesenc_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        112)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y2 = _mm256_aesenc_epi128(y2, y7);
    y3 = _mm256_aesenc_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        128)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y2 = _mm256_aesenc_epi128(y2, y7);
    y3 = _mm256_aesenc_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        144)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y2 = _mm256_aesenc_epi128(y2, y7);
    y3 = _mm256_aesenc_epi128(y3, y7);
    zf3 = (word32)r8;
    zf4 = 0xb;
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        160)));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_ECB_encrypt_vaes_128_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y2 = _mm256_aesenc_epi128(y2, y7);
    y3 = _mm256_aesenc_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        176)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y2 = _mm256_aesenc_epi128(y2, y7);
    y3 = _mm256_aesenc_epi128(y3, y7);
    zf5 = (word32)r8;
    zf6 = 0xd;
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        192)));
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_ECB_encrypt_vaes_128_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y2 = _mm256_aesenc_epi128(y2, y7);
    y3 = _mm256_aesenc_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        208)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y2 = _mm256_aesenc_epi128(y2, y7);
    y3 = _mm256_aesenc_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        224)));
L_AES_ECB_encrypt_vaes_128_aes_enc_block_last:
    y0 = _mm256_aesenclast_epi128(y0, y7);
    y1 = _mm256_aesenclast_epi128(y1, y7);
    y2 = _mm256_aesenclast_epi128(y2, y7);
    y3 = _mm256_aesenclast_epi128(y3, y7);
    _mm256_storeu_si256((__m256i*)WC_PW(r11, 0), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(r11, 32), y1);
    _mm256_storeu_si256((__m256i*)WC_PW(r11, 64), y2);
    _mm256_storeu_si256((__m256i*)WC_PW(r11, 96), y3);
    rax = (word32)((word32)rax + 0x80);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_encrypt_vaes_enc_128;
    }
L_AES_ECB_encrypt_vaes_done_128:
    r9 = (word32)((word32)rdx);
    r9 = (word32)((word32)r9 - (word32)rax);
    if (((word32)r9) < (0x40)) {
        goto L_AES_ECB_encrypt_vaes_done_64;
    }
    /* 64 bytes of input */
    /* aes_ecb_enc_64 */
    r10 = (word64)(rdi + rax);
    r11 = (word64)(rsi + rax);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 32));
    /* aes_enc_block */
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        0)));
    y0 = _mm256_xor_si256(y0, y7);
    y1 = _mm256_xor_si256(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        16)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        32)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        48)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        64)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        80)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        96)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        112)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        128)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        144)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    zf7 = (word32)r8;
    zf8 = 0xb;
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        160)));
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_ECB_encrypt_vaes_64_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        176)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    zf9 = (word32)r8;
    zf10 = 0xd;
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        192)));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_ECB_encrypt_vaes_64_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        208)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y1 = _mm256_aesenc_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        224)));
L_AES_ECB_encrypt_vaes_64_aes_enc_block_last:
    y0 = _mm256_aesenclast_epi128(y0, y7);
    y1 = _mm256_aesenclast_epi128(y1, y7);
    _mm256_storeu_si256((__m256i*)WC_PW(r11, 0), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(r11, 32), y1);
    rax = (word32)((word32)rax + 0x40);
L_AES_ECB_encrypt_vaes_done_64:
    r9 = (word32)((word32)rdx);
    r9 = (word32)((word32)r9 & 0xffffffe0);
    if (((word32)rax) == ((word32)r9)) {
        goto L_AES_ECB_encrypt_vaes_done_32;
    }
L_AES_ECB_encrypt_vaes_enc_32:
    /* 32 bytes of input */
    /* aes_ecb_enc_32 */
    r10 = (word64)(rdi + rax);
    r11 = (word64)(rsi + rax);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 0));
    /* aes_enc_block */
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        0)));
    y0 = _mm256_xor_si256(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        16)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        32)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        48)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        64)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        80)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        96)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        112)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        128)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        144)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    zf11 = (word32)r8;
    zf12 = 0xb;
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        160)));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_ECB_encrypt_vaes_32_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        176)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    zf13 = (word32)r8;
    zf14 = 0xd;
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        192)));
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_ECB_encrypt_vaes_32_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        208)));
    y0 = _mm256_aesenc_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        224)));
L_AES_ECB_encrypt_vaes_32_aes_enc_block_last:
    y0 = _mm256_aesenclast_epi128(y0, y7);
    _mm256_storeu_si256((__m256i*)WC_PW(r11, 0), y0);
    rax = (word32)((word32)rax + 0x20);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_encrypt_vaes_enc_32;
    }
L_AES_ECB_encrypt_vaes_done_32:
    zf15 = (word32)rax;
    zf16 = (word32)rdx;
    r9 = (word32)((word32)rdx);
    if ((zf15) == (zf16)) {
        goto L_AES_ECB_encrypt_vaes_done_enc;
    }
    r9 = (word32)((word32)r9 & 0xfffffff0);
L_AES_ECB_encrypt_vaes_enc_16:
    /* 16 bytes of input */
    r10 = (word64)(rdi + rax);
    y0 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10, 0)));
    /* aes_enc_block */
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0))));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 128));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 144));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        x5));
    zf17 = (word32)r8;
    zf18 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 160));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_ECB_encrypt_vaes_16_aes_enc_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        x5));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 176));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        x6));
    zf19 = (word32)r8;
    zf20 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 192));
    if ((sword32)(zf19) < (sword32)(zf20)) {
        goto L_AES_ECB_encrypt_vaes_16_aes_enc_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        x5));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 208));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        x6));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 224));
L_AES_ECB_encrypt_vaes_16_aes_enc_block_last:
    y0 = _mm256_zextsi128_si256(_mm_aesenclast_si128(_mm256_castsi256_si128(y0),
        x5));
    r10 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 0), _mm256_castsi256_si128(y0));
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_encrypt_vaes_enc_16;
    }
L_AES_ECB_encrypt_vaes_done_enc:
    ;
}

WC_X64I_TARGET("aes,vaes,avx2")
WOLFSSL_LOCAL void AES_ECB_decrypt_vaes(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr)
{
    word64 rdi, rsi, rdx, rcx, r8, rax, r9, r10 = 0, r11 = 0;
    __m128i x5 = _mm_setzero_si128(), x6 = _mm_setzero_si128();
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y7 = _mm256_setzero_si256();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;
    word32 zf5;
    word32 zf6;
    word32 zf7;
    word32 zf8;
    word32 zf9;
    word32 zf10;
    word32 zf11;
    word32 zf12;
    word32 zf13;
    word32 zf14;
    word32 zf15;
    word32 zf16;
    word32 zf17;
    word32 zf18;
    word32 zf19;
    word32 zf20;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(word64)length;
    rcx = (word64)(size_t)KS;
    r8 = (word64)(word32)nr;

    rax = (word32)(0);
    zf1 = (word32)rdx;
    zf2 = 0x80;
    r9 = (word32)((word32)rdx);
    if ((zf1) < (zf2)) {
        goto L_AES_ECB_decrypt_vaes_done_128;
    }
    r9 = (word32)((word32)r9 & 0xffffff80);
L_AES_ECB_decrypt_vaes_dec_128:
    /* 128 bytes of input */
    /* aes_ecb_dec_128 */
    r10 = (word64)(rdi + rax);
    r11 = (word64)(rsi + rax);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 32));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 64));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 96));
    /* aes_dec_block */
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        0)));
    y0 = _mm256_xor_si256(y0, y7);
    y1 = _mm256_xor_si256(y1, y7);
    y2 = _mm256_xor_si256(y2, y7);
    y3 = _mm256_xor_si256(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        16)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y2 = _mm256_aesdec_epi128(y2, y7);
    y3 = _mm256_aesdec_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        32)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y2 = _mm256_aesdec_epi128(y2, y7);
    y3 = _mm256_aesdec_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        48)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y2 = _mm256_aesdec_epi128(y2, y7);
    y3 = _mm256_aesdec_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        64)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y2 = _mm256_aesdec_epi128(y2, y7);
    y3 = _mm256_aesdec_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        80)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y2 = _mm256_aesdec_epi128(y2, y7);
    y3 = _mm256_aesdec_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        96)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y2 = _mm256_aesdec_epi128(y2, y7);
    y3 = _mm256_aesdec_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        112)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y2 = _mm256_aesdec_epi128(y2, y7);
    y3 = _mm256_aesdec_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        128)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y2 = _mm256_aesdec_epi128(y2, y7);
    y3 = _mm256_aesdec_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        144)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y2 = _mm256_aesdec_epi128(y2, y7);
    y3 = _mm256_aesdec_epi128(y3, y7);
    zf3 = (word32)r8;
    zf4 = 0xb;
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        160)));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_ECB_decrypt_vaes_128_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y2 = _mm256_aesdec_epi128(y2, y7);
    y3 = _mm256_aesdec_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        176)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y2 = _mm256_aesdec_epi128(y2, y7);
    y3 = _mm256_aesdec_epi128(y3, y7);
    zf5 = (word32)r8;
    zf6 = 0xd;
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        192)));
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_ECB_decrypt_vaes_128_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y2 = _mm256_aesdec_epi128(y2, y7);
    y3 = _mm256_aesdec_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        208)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y2 = _mm256_aesdec_epi128(y2, y7);
    y3 = _mm256_aesdec_epi128(y3, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        224)));
L_AES_ECB_decrypt_vaes_128_aes_dec_block_last:
    y0 = _mm256_aesdeclast_epi128(y0, y7);
    y1 = _mm256_aesdeclast_epi128(y1, y7);
    y2 = _mm256_aesdeclast_epi128(y2, y7);
    y3 = _mm256_aesdeclast_epi128(y3, y7);
    _mm256_storeu_si256((__m256i*)WC_PW(r11, 0), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(r11, 32), y1);
    _mm256_storeu_si256((__m256i*)WC_PW(r11, 64), y2);
    _mm256_storeu_si256((__m256i*)WC_PW(r11, 96), y3);
    rax = (word32)((word32)rax + 0x80);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_decrypt_vaes_dec_128;
    }
L_AES_ECB_decrypt_vaes_done_128:
    r9 = (word32)((word32)rdx);
    r9 = (word32)((word32)r9 - (word32)rax);
    if (((word32)r9) < (0x40)) {
        goto L_AES_ECB_decrypt_vaes_done_64;
    }
    /* 64 bytes of input */
    /* aes_ecb_dec_64 */
    r10 = (word64)(rdi + rax);
    r11 = (word64)(rsi + rax);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 32));
    /* aes_dec_block */
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        0)));
    y0 = _mm256_xor_si256(y0, y7);
    y1 = _mm256_xor_si256(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        16)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        32)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        48)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        64)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        80)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        96)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        112)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        128)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        144)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    zf7 = (word32)r8;
    zf8 = 0xb;
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        160)));
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_ECB_decrypt_vaes_64_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        176)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    zf9 = (word32)r8;
    zf10 = 0xd;
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        192)));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_ECB_decrypt_vaes_64_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        208)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y1 = _mm256_aesdec_epi128(y1, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        224)));
L_AES_ECB_decrypt_vaes_64_aes_dec_block_last:
    y0 = _mm256_aesdeclast_epi128(y0, y7);
    y1 = _mm256_aesdeclast_epi128(y1, y7);
    _mm256_storeu_si256((__m256i*)WC_PW(r11, 0), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(r11, 32), y1);
    rax = (word32)((word32)rax + 0x40);
L_AES_ECB_decrypt_vaes_done_64:
    r9 = (word32)((word32)rdx);
    r9 = (word32)((word32)r9 & 0xffffffe0);
    if (((word32)rax) == ((word32)r9)) {
        goto L_AES_ECB_decrypt_vaes_done_32;
    }
L_AES_ECB_decrypt_vaes_dec_32:
    /* 32 bytes of input */
    /* aes_ecb_dec_32 */
    r10 = (word64)(rdi + rax);
    r11 = (word64)(rsi + rax);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(r10, 0));
    /* aes_dec_block */
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        0)));
    y0 = _mm256_xor_si256(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        16)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        32)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        48)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        64)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        80)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        96)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        112)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        128)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        144)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    zf11 = (word32)r8;
    zf12 = 0xb;
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        160)));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_ECB_decrypt_vaes_32_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        176)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    zf13 = (word32)r8;
    zf14 = 0xd;
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        192)));
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_ECB_decrypt_vaes_32_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        208)));
    y0 = _mm256_aesdec_epi128(y0, y7);
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        224)));
L_AES_ECB_decrypt_vaes_32_aes_dec_block_last:
    y0 = _mm256_aesdeclast_epi128(y0, y7);
    _mm256_storeu_si256((__m256i*)WC_PW(r11, 0), y0);
    rax = (word32)((word32)rax + 0x20);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_decrypt_vaes_dec_32;
    }
L_AES_ECB_decrypt_vaes_done_32:
    zf15 = (word32)rax;
    zf16 = (word32)rdx;
    r9 = (word32)((word32)rdx);
    if ((zf15) == (zf16)) {
        goto L_AES_ECB_decrypt_vaes_done_dec;
    }
    r9 = (word32)((word32)r9 & 0xfffffff0);
L_AES_ECB_decrypt_vaes_dec_16:
    /* 16 bytes of input */
    r10 = (word64)(rdi + rax);
    y0 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10, 0)));
    /* aes_dec_block */
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0))));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 128));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 144));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    zf17 = (word32)r8;
    zf18 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 160));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_ECB_decrypt_vaes_16_aes_dec_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 176));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x6));
    zf19 = (word32)r8;
    zf20 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 192));
    if ((sword32)(zf19) < (sword32)(zf20)) {
        goto L_AES_ECB_decrypt_vaes_16_aes_dec_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 208));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x6));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 224));
L_AES_ECB_decrypt_vaes_16_aes_dec_block_last:
    y0 = _mm256_zextsi128_si256(_mm_aesdeclast_si128(_mm256_castsi256_si128(y0),
        x5));
    r10 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 0), _mm256_castsi256_si128(y0));
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_decrypt_vaes_dec_16;
    }
L_AES_ECB_decrypt_vaes_done_dec:
    ;
}

WC_X64I_TARGET("aes,avx")
WOLFSSL_LOCAL void AES_CBC_encrypt_vaes(const unsigned char* in,
    unsigned char* out, unsigned char* ivec, unsigned long length,
    const unsigned char* KS, int nr)
{
    word64 rdi, rsi, rdx, rcx, r8, r9, rax, r10 = 0, r11 = 0;
    __m128i x0, x1 = _mm_setzero_si128(), x3 = _mm_setzero_si128(),
            x4 = _mm_setzero_si128();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(size_t)ivec;
    rcx = (word64)(word64)length;
    r8 = (word64)(size_t)KS;
    r9 = (word64)(word32)nr;

    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0));
    rax = (word32)(0);
    if (((word32)rax) == ((word32)rcx)) {
        goto L_AES_CBC_encrypt_vaes_done;
    }
L_AES_CBC_encrypt_vaes_loop:
    /* 16 bytes of input */
    r10 = (word64)(rdi + rax);
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    x1 = _mm_xor_si128(x1, x0);
    /* aes_enc_block */
    x1 = _mm_xor_si128(x1, _mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x1 = _mm_aesenc_si128(x1, x3);
    zf1 = (word32)r9;
    zf2 = 0xb;
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_CBC_encrypt_vaes_aes_enc_block_last;
    }
    x1 = _mm_aesenc_si128(x1, x3);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x1 = _mm_aesenc_si128(x1, x4);
    zf3 = (word32)r9;
    zf4 = 0xd;
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_CBC_encrypt_vaes_aes_enc_block_last;
    }
    x1 = _mm_aesenc_si128(x1, x3);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x1 = _mm_aesenc_si128(x1, x4);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_CBC_encrypt_vaes_aes_enc_block_last:
    x1 = _mm_aesenclast_si128(x1, x3);
    r11 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 0), x1);
    x0 = x1;
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)rcx)) {
        goto L_AES_CBC_encrypt_vaes_loop;
    }
L_AES_CBC_encrypt_vaes_done:
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x0);
}

WC_X64I_TARGET("aes,vaes,avx2")
WOLFSSL_LOCAL void AES_CBC_decrypt_vaes(const unsigned char* in,
    unsigned char* out, unsigned char* ivec, unsigned long length,
    const unsigned char* KS, int nr)
{
    word64 rdi, rsi, rdx, rcx, r8, r9, rax, r10, r11 = 0, r12 = 0;
    __m128i x5 = _mm_setzero_si128(), x6 = _mm_setzero_si128(),
            x7 = _mm_setzero_si128();
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(), y8,
            y9 = _mm256_setzero_si256(), y10 = _mm256_setzero_si256(),
            y11 = _mm256_setzero_si256(), y12 = _mm256_setzero_si256(),
            y13 = _mm256_setzero_si256();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;
    word32 zf5;
    word32 zf6;
    word32 zf7;
    word32 zf8;
    word32 zf9;
    word32 zf10;
    word32 zf11;
    word32 zf12;
    word32 zf13;
    word32 zf14;
    word32 zf15;
    word32 zf16;
    word32 zf17;
    word32 zf18;
    word32 zf19;
    word32 zf20;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(size_t)ivec;
    rcx = (word64)(word64)length;
    r8 = (word64)(size_t)KS;
    r9 = (word64)(word32)nr;

    y8 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdx, 0)));
    rax = (word32)(0);
    zf1 = (word32)rcx;
    zf2 = 0x80;
    r10 = (word32)((word32)rcx);
    if ((zf1) < (zf2)) {
        goto L_AES_CBC_decrypt_vaes_done_128;
    }
    r10 = (word32)((word32)r10 & 0xffffff80);
L_AES_CBC_decrypt_vaes_dec_128:
    /* 128 bytes of input */
    /* aes_cbc_dec_128 */
    r11 = (word64)(rdi + rax);
    r12 = (word64)(rsi + rax);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(r11, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(r11, 32));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(r11, 64));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(r11, 96));
    y10 = _mm256_inserti128_si256(y8, _mm256_castsi256_si128(y0), 1);
    y11 = _mm256_loadu_si256((const __m256i*)WC_PR(r11, 16));
    y12 = _mm256_loadu_si256((const __m256i*)WC_PR(r11, 48));
    y13 = _mm256_loadu_si256((const __m256i*)WC_PR(r11, 80));
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y3, 1));
    /* aes_dec_block */
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        0)));
    y0 = _mm256_xor_si256(y0, y9);
    y1 = _mm256_xor_si256(y1, y9);
    y2 = _mm256_xor_si256(y2, y9);
    y3 = _mm256_xor_si256(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        16)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        32)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        48)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        64)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        80)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        96)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    zf3 = (word32)r9;
    zf4 = 0xb;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_CBC_decrypt_vaes_128_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    zf5 = (word32)r9;
    zf6 = 0xd;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_CBC_decrypt_vaes_128_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_CBC_decrypt_vaes_128_aes_dec_block_last:
    y0 = _mm256_aesdeclast_epi128(y0, y9);
    y1 = _mm256_aesdeclast_epi128(y1, y9);
    y2 = _mm256_aesdeclast_epi128(y2, y9);
    y3 = _mm256_aesdeclast_epi128(y3, y9);
    y0 = _mm256_xor_si256(y0, y10);
    y1 = _mm256_xor_si256(y1, y11);
    y2 = _mm256_xor_si256(y2, y12);
    y3 = _mm256_xor_si256(y3, y13);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 0), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 32), y1);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 64), y2);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 96), y3);
    rax = (word32)((word32)rax + 0x80);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CBC_decrypt_vaes_dec_128;
    }
L_AES_CBC_decrypt_vaes_done_128:
    r10 = (word32)((word32)rcx);
    r10 = (word32)((word32)r10 - (word32)rax);
    if (((word32)r10) < (0x40)) {
        goto L_AES_CBC_decrypt_vaes_done_64;
    }
    /* 64 bytes of input */
    /* aes_cbc_dec_64 */
    r11 = (word64)(rdi + rax);
    r12 = (word64)(rsi + rax);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(r11, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(r11, 32));
    y10 = _mm256_inserti128_si256(y8, _mm256_castsi256_si128(y0), 1);
    y11 = _mm256_loadu_si256((const __m256i*)WC_PR(r11, 16));
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y1, 1));
    /* aes_dec_block */
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        0)));
    y0 = _mm256_xor_si256(y0, y9);
    y1 = _mm256_xor_si256(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        16)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        32)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        48)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        64)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        80)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        96)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    zf7 = (word32)r9;
    zf8 = 0xb;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_CBC_decrypt_vaes_64_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    zf9 = (word32)r9;
    zf10 = 0xd;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_CBC_decrypt_vaes_64_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_CBC_decrypt_vaes_64_aes_dec_block_last:
    y0 = _mm256_aesdeclast_epi128(y0, y9);
    y1 = _mm256_aesdeclast_epi128(y1, y9);
    y0 = _mm256_xor_si256(y0, y10);
    y1 = _mm256_xor_si256(y1, y11);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 0), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 32), y1);
    rax = (word32)((word32)rax + 0x40);
L_AES_CBC_decrypt_vaes_done_64:
    r10 = (word32)((word32)rcx);
    r10 = (word32)((word32)r10 & 0xffffffe0);
    if (((word32)rax) == ((word32)r10)) {
        goto L_AES_CBC_decrypt_vaes_done_32;
    }
L_AES_CBC_decrypt_vaes_dec_32:
    /* 32 bytes of input */
    /* aes_cbc_dec_32 */
    r11 = (word64)(rdi + rax);
    r12 = (word64)(rsi + rax);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(r11, 0));
    y10 = _mm256_inserti128_si256(y8, _mm256_castsi256_si128(y0), 1);
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y0, 1));
    /* aes_dec_block */
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        0)));
    y0 = _mm256_xor_si256(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        16)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        32)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        48)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        64)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        80)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        96)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    zf11 = (word32)r9;
    zf12 = 0xb;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_CBC_decrypt_vaes_32_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    zf13 = (word32)r9;
    zf14 = 0xd;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_CBC_decrypt_vaes_32_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_CBC_decrypt_vaes_32_aes_dec_block_last:
    y0 = _mm256_aesdeclast_epi128(y0, y9);
    y0 = _mm256_xor_si256(y0, y10);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 0), y0);
    rax = (word32)((word32)rax + 0x20);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CBC_decrypt_vaes_dec_32;
    }
L_AES_CBC_decrypt_vaes_done_32:
    zf15 = (word32)rax;
    zf16 = (word32)rcx;
    r10 = (word32)((word32)rcx);
    if ((zf15) == (zf16)) {
        goto L_AES_CBC_decrypt_vaes_done_dec;
    }
    r10 = (word32)((word32)r10 & 0xfffffff0);
L_AES_CBC_decrypt_vaes_dec_16:
    /* 16 bytes of input */
    r11 = (word64)(rdi + rax);
    y0 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r11, 0)));
    x7 = _mm256_castsi256_si128(y0);
    /* aes_dec_block */
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm_loadu_si128((const __m128i*)WC_PR(r8, 0))));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    zf17 = (word32)r9;
    zf18 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_CBC_decrypt_vaes_16_aes_dec_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x6));
    zf19 = (word32)r9;
    zf20 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf19) < (sword32)(zf20)) {
        goto L_AES_CBC_decrypt_vaes_16_aes_dec_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x5));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        x6));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_CBC_decrypt_vaes_16_aes_dec_block_last:
    y0 = _mm256_zextsi128_si256(_mm_aesdeclast_si128(_mm256_castsi256_si128(y0),
        x5));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    y8 = _mm256_zextsi128_si256(x7);
    r11 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 0), _mm256_castsi256_si128(y0));
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CBC_decrypt_vaes_dec_16;
    }
L_AES_CBC_decrypt_vaes_done_dec:
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), _mm256_castsi256_si128(y8));
}

XALIGNED(16) static const word64 L_aes_ctr_bswap_vaes[] WC_X64I_UNUSED = {
    0x08090a0b0c0d0e0fULL, 0x0001020304050607ULL,
};

XALIGNED(32) static const word64 L_aes_ctr_inc_vaes[] WC_X64I_UNUSED = {
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000001ULL, 0x0000000000000000ULL,
    0x0000000000000002ULL, 0x0000000000000000ULL,
    0x0000000000000003ULL, 0x0000000000000000ULL,
    0x0000000000000004ULL, 0x0000000000000000ULL,
    0x0000000000000005ULL, 0x0000000000000000ULL,
    0x0000000000000006ULL, 0x0000000000000000ULL,
    0x0000000000000007ULL, 0x0000000000000000ULL,
    0x0000000000000008ULL, 0x0000000000000000ULL,
    0x0000000000000009ULL, 0x0000000000000000ULL,
    0x000000000000000aULL, 0x0000000000000000ULL,
    0x000000000000000bULL, 0x0000000000000000ULL,
    0x000000000000000cULL, 0x0000000000000000ULL,
    0x000000000000000dULL, 0x0000000000000000ULL,
    0x000000000000000eULL, 0x0000000000000000ULL,
    0x000000000000000fULL, 0x0000000000000000ULL,
    0x0000000000000010ULL, 0x0000000000000000ULL,
};

WC_X64I_TARGET("aes,vaes,avx2")
WOLFSSL_LOCAL void AES_CTR_encrypt_vaes(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr,
    unsigned char* ctr)
{
    word64 rdi, rsi, rdx, rcx, r8, r9, rax, r10, r11 = 0, r12 = 0;
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y4 = _mm256_setzero_si256(), y5 = _mm256_setzero_si256(),
            y6 = _mm256_setzero_si256(), y7, y8, y9 = _mm256_setzero_si256(),
            y10 = _mm256_setzero_si256(), y11 = _mm256_setzero_si256(), y12,
            y13, y14 = _mm256_setzero_si256(), y15 = _mm256_setzero_si256();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;
    word32 zf5;
    word32 zf6;
    word32 zf7;
    word32 zf8;
    word32 zf9;
    word32 zf10;
    word32 zf11;
    word32 zf12;
    word32 zf13;
    word32 zf14;
    word32 zf15;
    word32 zf16;
    word32 zf17;
    word32 zf18;
    word32 zf19;
    word32 zf20;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(word64)length;
    rcx = (word64)(size_t)KS;
    r8 = (word64)(word32)nr;
    r9 = (word64)(size_t)ctr;

    y8 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(
        L_aes_ctr_bswap_vaes, 0)));
    y7 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        0)));
    y7 = _mm256_shuffle_epi8(y7, y8);
    y12 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(
        L_aes_ctr_inc_vaes, 32)));
    y13 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(
        L_aes_ctr_inc_vaes, 16)));
    rax = (word32)(0);
    zf1 = (word32)rdx;
    zf2 = 0x80;
    r10 = (word32)((word32)rdx);
    if ((zf1) < (zf2)) {
        goto L_AES_CTR_encrypt_vaes_done_128;
    }
    r10 = (word32)((word32)r10 & 0xffffff80);
    y10 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(
        L_aes_ctr_inc_vaes, 128)));
    y9 = y7;
    y4 = _mm256_add_epi64(y7, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 0)));
    y15 = _mm256_and_si256(y9, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 0)));
    y9 = _mm256_or_si256(y9, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 0)));
    y9 = _mm256_andnot_si256(y4, y9);
    y9 = _mm256_or_si256(y9, y15);
    y9 = _mm256_srli_epi64(y9, 63);
    y9 = _mm256_bslli_epi128(y9, 8);
    y4 = _mm256_add_epi64(y4, y9);
    y9 = y7;
    y5 = _mm256_add_epi64(y7, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 32)));
    y15 = _mm256_and_si256(y9, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 32)));
    y9 = _mm256_or_si256(y9, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 32)));
    y9 = _mm256_andnot_si256(y5, y9);
    y9 = _mm256_or_si256(y9, y15);
    y9 = _mm256_srli_epi64(y9, 63);
    y9 = _mm256_bslli_epi128(y9, 8);
    y5 = _mm256_add_epi64(y5, y9);
    y9 = y7;
    y6 = _mm256_add_epi64(y7, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 64)));
    y15 = _mm256_and_si256(y9, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 64)));
    y9 = _mm256_or_si256(y9, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 64)));
    y9 = _mm256_andnot_si256(y6, y9);
    y9 = _mm256_or_si256(y9, y15);
    y9 = _mm256_srli_epi64(y9, 63);
    y9 = _mm256_bslli_epi128(y9, 8);
    y6 = _mm256_add_epi64(y6, y9);
    y9 = y7;
    y7 = _mm256_add_epi64(y7, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 96)));
    y15 = _mm256_and_si256(y9, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 96)));
    y9 = _mm256_or_si256(y9, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 96)));
    y9 = _mm256_andnot_si256(y7, y9);
    y9 = _mm256_or_si256(y9, y15);
    y9 = _mm256_srli_epi64(y9, 63);
    y9 = _mm256_bslli_epi128(y9, 8);
    y7 = _mm256_add_epi64(y7, y9);
L_AES_CTR_encrypt_vaes_enc_128:
    /* 128 bytes of input */
    r11 = (word64)(rdi + rax);
    r12 = (word64)(rsi + rax);
    y0 = _mm256_shuffle_epi8(y4, y8);
    y1 = _mm256_shuffle_epi8(y5, y8);
    y2 = _mm256_shuffle_epi8(y6, y8);
    y3 = _mm256_shuffle_epi8(y7, y8);
    y9 = y4;
    y4 = _mm256_add_epi64(y4, y10);
    y15 = _mm256_and_si256(y9, y10);
    y9 = _mm256_or_si256(y9, y10);
    y9 = _mm256_andnot_si256(y4, y9);
    y9 = _mm256_or_si256(y9, y15);
    y9 = _mm256_srli_epi64(y9, 63);
    y9 = _mm256_bslli_epi128(y9, 8);
    y4 = _mm256_add_epi64(y4, y9);
    y9 = y5;
    y5 = _mm256_add_epi64(y5, y10);
    y15 = _mm256_and_si256(y9, y10);
    y9 = _mm256_or_si256(y9, y10);
    y9 = _mm256_andnot_si256(y5, y9);
    y9 = _mm256_or_si256(y9, y15);
    y9 = _mm256_srli_epi64(y9, 63);
    y9 = _mm256_bslli_epi128(y9, 8);
    y5 = _mm256_add_epi64(y5, y9);
    y9 = y6;
    y6 = _mm256_add_epi64(y6, y10);
    y15 = _mm256_and_si256(y9, y10);
    y9 = _mm256_or_si256(y9, y10);
    y9 = _mm256_andnot_si256(y6, y9);
    y9 = _mm256_or_si256(y9, y15);
    y9 = _mm256_srli_epi64(y9, 63);
    y9 = _mm256_bslli_epi128(y9, 8);
    y6 = _mm256_add_epi64(y6, y9);
    y9 = y7;
    y7 = _mm256_add_epi64(y7, y10);
    y15 = _mm256_and_si256(y9, y10);
    y9 = _mm256_or_si256(y9, y10);
    y9 = _mm256_andnot_si256(y7, y9);
    y9 = _mm256_or_si256(y9, y15);
    y9 = _mm256_srli_epi64(y9, 63);
    y9 = _mm256_bslli_epi128(y9, 8);
    y7 = _mm256_add_epi64(y7, y9);
    /* aes_enc_block */
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        0)));
    y0 = _mm256_xor_si256(y0, y14);
    y1 = _mm256_xor_si256(y1, y14);
    y2 = _mm256_xor_si256(y2, y14);
    y3 = _mm256_xor_si256(y3, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        16)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y2 = _mm256_aesenc_epi128(y2, y14);
    y3 = _mm256_aesenc_epi128(y3, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        32)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y2 = _mm256_aesenc_epi128(y2, y14);
    y3 = _mm256_aesenc_epi128(y3, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        48)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y2 = _mm256_aesenc_epi128(y2, y14);
    y3 = _mm256_aesenc_epi128(y3, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        64)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y2 = _mm256_aesenc_epi128(y2, y14);
    y3 = _mm256_aesenc_epi128(y3, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        80)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y2 = _mm256_aesenc_epi128(y2, y14);
    y3 = _mm256_aesenc_epi128(y3, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        96)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y2 = _mm256_aesenc_epi128(y2, y14);
    y3 = _mm256_aesenc_epi128(y3, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        112)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y2 = _mm256_aesenc_epi128(y2, y14);
    y3 = _mm256_aesenc_epi128(y3, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        128)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y2 = _mm256_aesenc_epi128(y2, y14);
    y3 = _mm256_aesenc_epi128(y3, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        144)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y2 = _mm256_aesenc_epi128(y2, y14);
    y3 = _mm256_aesenc_epi128(y3, y14);
    zf3 = (word32)r8;
    zf4 = 0xb;
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        160)));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_CTR_encrypt_vaes_128_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y2 = _mm256_aesenc_epi128(y2, y14);
    y3 = _mm256_aesenc_epi128(y3, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        176)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y2 = _mm256_aesenc_epi128(y2, y14);
    y3 = _mm256_aesenc_epi128(y3, y14);
    zf5 = (word32)r8;
    zf6 = 0xd;
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        192)));
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_CTR_encrypt_vaes_128_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y2 = _mm256_aesenc_epi128(y2, y14);
    y3 = _mm256_aesenc_epi128(y3, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        208)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y2 = _mm256_aesenc_epi128(y2, y14);
    y3 = _mm256_aesenc_epi128(y3, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        224)));
L_AES_CTR_encrypt_vaes_128_aes_enc_block_last:
    y0 = _mm256_aesenclast_epi128(y0, y14);
    y1 = _mm256_aesenclast_epi128(y1, y14);
    y2 = _mm256_aesenclast_epi128(y2, y14);
    y3 = _mm256_aesenclast_epi128(y3, y14);
    y0 = _mm256_xor_si256(y0, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        0)));
    y1 = _mm256_xor_si256(y1, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        32)));
    y2 = _mm256_xor_si256(y2, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        64)));
    y3 = _mm256_xor_si256(y3, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        96)));
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 0), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 32), y1);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 64), y2);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 96), y3);
    rax = (word32)((word32)rax + 0x80);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CTR_encrypt_vaes_enc_128;
    }
    y7 = _mm256_permute2x128_si256(y4, y4, 0);
L_AES_CTR_encrypt_vaes_done_128:
    r10 = (word32)((word32)rdx);
    r10 = (word32)((word32)r10 - (word32)rax);
    if (((word32)r10) < (0x40)) {
        goto L_AES_CTR_encrypt_vaes_done_64;
    }
    /* 64 bytes of input */
    y11 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(
        L_aes_ctr_inc_vaes, 64)));
    /* aes_ctr_enc_64 */
    r11 = (word64)(rdi + rax);
    r12 = (word64)(rsi + rax);
    y0 = _mm256_add_epi64(y7, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 0)));
    y9 = y7;
    y15 = _mm256_and_si256(y9, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 0)));
    y9 = _mm256_or_si256(y9, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 0)));
    y9 = _mm256_andnot_si256(y0, y9);
    y9 = _mm256_or_si256(y9, y15);
    y9 = _mm256_srli_epi64(y9, 63);
    y9 = _mm256_bslli_epi128(y9, 8);
    y0 = _mm256_add_epi64(y0, y9);
    y0 = _mm256_shuffle_epi8(y0, y8);
    y1 = _mm256_add_epi64(y7, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 32)));
    y9 = y7;
    y15 = _mm256_and_si256(y9, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 32)));
    y9 = _mm256_or_si256(y9, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 32)));
    y9 = _mm256_andnot_si256(y1, y9);
    y9 = _mm256_or_si256(y9, y15);
    y9 = _mm256_srli_epi64(y9, 63);
    y9 = _mm256_bslli_epi128(y9, 8);
    y1 = _mm256_add_epi64(y1, y9);
    y1 = _mm256_shuffle_epi8(y1, y8);
    y9 = y7;
    y7 = _mm256_add_epi64(y7, y11);
    y15 = _mm256_and_si256(y9, y11);
    y9 = _mm256_or_si256(y9, y11);
    y9 = _mm256_andnot_si256(y7, y9);
    y9 = _mm256_or_si256(y9, y15);
    y9 = _mm256_srli_epi64(y9, 63);
    y9 = _mm256_bslli_epi128(y9, 8);
    y7 = _mm256_add_epi64(y7, y9);
    /* aes_enc_block */
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        0)));
    y0 = _mm256_xor_si256(y0, y14);
    y1 = _mm256_xor_si256(y1, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        16)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        32)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        48)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        64)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        80)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        96)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        112)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        128)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        144)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    zf7 = (word32)r8;
    zf8 = 0xb;
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        160)));
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_CTR_encrypt_vaes_64_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        176)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    zf9 = (word32)r8;
    zf10 = 0xd;
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        192)));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_CTR_encrypt_vaes_64_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        208)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y1 = _mm256_aesenc_epi128(y1, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        224)));
L_AES_CTR_encrypt_vaes_64_aes_enc_block_last:
    y0 = _mm256_aesenclast_epi128(y0, y14);
    y1 = _mm256_aesenclast_epi128(y1, y14);
    y0 = _mm256_xor_si256(y0, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        0)));
    y1 = _mm256_xor_si256(y1, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        32)));
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 0), y0);
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 32), y1);
    rax = (word32)((word32)rax + 0x40);
L_AES_CTR_encrypt_vaes_done_64:
    r10 = (word32)((word32)rdx);
    r10 = (word32)((word32)r10 & 0xffffffe0);
    if (((word32)rax) == ((word32)r10)) {
        goto L_AES_CTR_encrypt_vaes_done_32;
    }
L_AES_CTR_encrypt_vaes_enc_32:
    /* 32 bytes of input */
    /* aes_ctr_enc_32 */
    r11 = (word64)(rdi + rax);
    r12 = (word64)(rsi + rax);
    y0 = _mm256_add_epi64(y7, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 0)));
    y9 = y7;
    y15 = _mm256_and_si256(y9, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 0)));
    y9 = _mm256_or_si256(y9, _mm256_loadu_si256((const __m256i*)WC_PR(
        L_aes_ctr_inc_vaes, 0)));
    y9 = _mm256_andnot_si256(y0, y9);
    y9 = _mm256_or_si256(y9, y15);
    y9 = _mm256_srli_epi64(y9, 63);
    y9 = _mm256_bslli_epi128(y9, 8);
    y0 = _mm256_add_epi64(y0, y9);
    y0 = _mm256_shuffle_epi8(y0, y8);
    y9 = y7;
    y7 = _mm256_add_epi64(y7, y12);
    y15 = _mm256_and_si256(y9, y12);
    y9 = _mm256_or_si256(y9, y12);
    y9 = _mm256_andnot_si256(y7, y9);
    y9 = _mm256_or_si256(y9, y15);
    y9 = _mm256_srli_epi64(y9, 63);
    y9 = _mm256_bslli_epi128(y9, 8);
    y7 = _mm256_add_epi64(y7, y9);
    /* aes_enc_block */
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        0)));
    y0 = _mm256_xor_si256(y0, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        16)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        32)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        48)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        64)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        80)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        96)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        112)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        128)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        144)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    zf11 = (word32)r8;
    zf12 = 0xb;
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        160)));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_CTR_encrypt_vaes_32_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        176)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    zf13 = (word32)r8;
    zf14 = 0xd;
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        192)));
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_CTR_encrypt_vaes_32_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        208)));
    y0 = _mm256_aesenc_epi128(y0, y14);
    y14 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        224)));
L_AES_CTR_encrypt_vaes_32_aes_enc_block_last:
    y0 = _mm256_aesenclast_epi128(y0, y14);
    y0 = _mm256_xor_si256(y0, _mm256_loadu_si256((const __m256i*)WC_PR(r11,
        0)));
    _mm256_storeu_si256((__m256i*)WC_PW(r12, 0), y0);
    rax = (word32)((word32)rax + 0x20);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CTR_encrypt_vaes_enc_32;
    }
L_AES_CTR_encrypt_vaes_done_32:
    zf15 = (word32)rax;
    zf16 = (word32)rdx;
    r10 = (word32)((word32)rdx);
    if ((zf15) == (zf16)) {
        goto L_AES_CTR_encrypt_vaes_done_enc;
    }
    r10 = (word32)((word32)r10 & 0xfffffff0);
L_AES_CTR_encrypt_vaes_enc_16:
    /* 16 bytes of input */
    y0 = _mm256_zextsi128_si256(_mm_shuffle_epi8(_mm256_castsi256_si128(y7),
        _mm256_castsi256_si128(y8)));
    y9 = y7;
    y7 = _mm256_add_epi64(y7, y13);
    y15 = _mm256_and_si256(y9, y13);
    y9 = _mm256_or_si256(y9, y13);
    y9 = _mm256_andnot_si256(y7, y9);
    y9 = _mm256_or_si256(y9, y15);
    y9 = _mm256_srli_epi64(y9, 63);
    y9 = _mm256_bslli_epi128(y9, 8);
    y7 = _mm256_add_epi64(y7, y9);
    /* aes_enc_block */
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0))));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        16)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        32)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        48)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        64)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        80)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        96)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        112)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        128)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        144)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    zf17 = (word32)r8;
    zf18 = 0xb;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        160)));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_CTR_encrypt_vaes_16_aes_enc_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        176)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    zf19 = (word32)r8;
    zf20 = 0xd;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        192)));
    if ((sword32)(zf19) < (sword32)(zf20)) {
        goto L_AES_CTR_encrypt_vaes_16_aes_enc_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        208)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        224)));
L_AES_CTR_encrypt_vaes_16_aes_enc_block_last:
    y0 = _mm256_zextsi128_si256(_mm_aesenclast_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    r11 = (word64)(rdi + rax);
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm_loadu_si128((const __m128i*)WC_PR(r11, 0))));
    r11 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 0), _mm256_castsi256_si128(y0));
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CTR_encrypt_vaes_enc_16;
    }
L_AES_CTR_encrypt_vaes_done_enc:
    y0 = _mm256_zextsi128_si256(_mm_shuffle_epi8(_mm256_castsi256_si128(y7),
        _mm256_castsi256_si128(y8)));
    _mm_storeu_si128((__m128i*)WC_PW(r9, 0), _mm256_castsi256_si128(y0));
}

#endif /* HAVE_INTEL_VAES */
#ifdef HAVE_INTEL_AVX512
WC_X64I_TARGET("aes,vaes,avx512f,avx512vl")
WOLFSSL_LOCAL void AES_ECB_encrypt_avx512(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr)
{
    word64 rdi, rsi, rdx, rcx, r8, rax, r9 = 0, r10 = 0, r11 = 0;
    __m128i x5 = _mm_setzero_si128(), x6 = _mm_setzero_si128();
    __m512i z0 = _mm512_setzero_si512(), z1 = _mm512_setzero_si512(),
            z2 = _mm512_setzero_si512(), z3 = _mm512_setzero_si512(),
            z7 = _mm512_setzero_si512(), z8 = _mm512_setzero_si512(),
            z9 = _mm512_setzero_si512(), z10 = _mm512_setzero_si512(),
            z11 = _mm512_setzero_si512(), z12 = _mm512_setzero_si512(),
            z13 = _mm512_setzero_si512(), z14 = _mm512_setzero_si512(),
            z15 = _mm512_setzero_si512(), z16 = _mm512_setzero_si512(),
            z17 = _mm512_setzero_si512(), z18 = _mm512_setzero_si512(),
            z19 = _mm512_setzero_si512(), z20 = _mm512_setzero_si512(),
            z21 = _mm512_setzero_si512(), z22 = _mm512_setzero_si512();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;
    word32 zf5;
    word32 zf6;
    word32 zf7;
    word32 zf8;
    word32 zf9;
    word32 zf10;
    word32 zf11;
    word32 zf12;
    word32 zf13;
    word32 zf14;
    word32 zf15;
    word32 zf16;
    word32 zf17;
    word32 zf18;
    word32 zf19;
    word32 zf20;
    word32 zf21;
    word32 zf22;
    word32 zf23;
    word32 zf24;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(word64)length;
    rcx = (word64)(size_t)KS;
    r8 = (word64)(word32)nr;

    rax = (word32)(0);
    if (((word32)rdx) < (0x20)) {
        goto L_AES_ECB_encrypt_avx512_done_32;
    }
    z8 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    z9 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        16)));
    z10 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        32)));
    z11 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        48)));
    z12 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        64)));
    z13 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        80)));
    z14 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        96)));
    z15 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        112)));
    z16 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        128)));
    z17 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        144)));
    z18 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        160)));
    if ((sword32)((word32)r8) < (sword32)(0xb)) {
        goto L_AES_ECB_encrypt_avx512_key_cached;
    }
    z19 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        176)));
    z20 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        192)));
    if ((sword32)((word32)r8) < (sword32)(0xd)) {
        goto L_AES_ECB_encrypt_avx512_key_cached;
    }
    z21 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        208)));
    z22 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        224)));
L_AES_ECB_encrypt_avx512_key_cached:
    zf1 = (word32)rdx;
    zf2 = 0x100;
    r9 = (word32)((word32)rdx);
    if ((zf1) < (zf2)) {
        goto L_AES_ECB_encrypt_avx512_done_256;
    }
    r9 = (word32)((word32)r9 & 0xffffff00);
L_AES_ECB_encrypt_avx512_enc_256:
    /* 256 bytes of input */
    /* aes_ecb_enc_256 */
    r10 = (word64)(rdi + rax);
    r11 = (word64)(rsi + rax);
    z0 = _mm512_loadu_si512((const void*)WC_PR(r10, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(r10, 64));
    z2 = _mm512_loadu_si512((const void*)WC_PR(r10, 128));
    z3 = _mm512_loadu_si512((const void*)WC_PR(r10, 192));
    /* aes_enc_block */
    z0 = _mm512_xor_si512(z0, z8);
    z1 = _mm512_xor_si512(z1, z8);
    z2 = _mm512_xor_si512(z2, z8);
    z3 = _mm512_xor_si512(z3, z8);
    z0 = _mm512_aesenc_epi128(z0, z9);
    z1 = _mm512_aesenc_epi128(z1, z9);
    z2 = _mm512_aesenc_epi128(z2, z9);
    z3 = _mm512_aesenc_epi128(z3, z9);
    z0 = _mm512_aesenc_epi128(z0, z10);
    z1 = _mm512_aesenc_epi128(z1, z10);
    z2 = _mm512_aesenc_epi128(z2, z10);
    z3 = _mm512_aesenc_epi128(z3, z10);
    z0 = _mm512_aesenc_epi128(z0, z11);
    z1 = _mm512_aesenc_epi128(z1, z11);
    z2 = _mm512_aesenc_epi128(z2, z11);
    z3 = _mm512_aesenc_epi128(z3, z11);
    z0 = _mm512_aesenc_epi128(z0, z12);
    z1 = _mm512_aesenc_epi128(z1, z12);
    z2 = _mm512_aesenc_epi128(z2, z12);
    z3 = _mm512_aesenc_epi128(z3, z12);
    z0 = _mm512_aesenc_epi128(z0, z13);
    z1 = _mm512_aesenc_epi128(z1, z13);
    z2 = _mm512_aesenc_epi128(z2, z13);
    z3 = _mm512_aesenc_epi128(z3, z13);
    z0 = _mm512_aesenc_epi128(z0, z14);
    z1 = _mm512_aesenc_epi128(z1, z14);
    z2 = _mm512_aesenc_epi128(z2, z14);
    z3 = _mm512_aesenc_epi128(z3, z14);
    z0 = _mm512_aesenc_epi128(z0, z15);
    z1 = _mm512_aesenc_epi128(z1, z15);
    z2 = _mm512_aesenc_epi128(z2, z15);
    z3 = _mm512_aesenc_epi128(z3, z15);
    z0 = _mm512_aesenc_epi128(z0, z16);
    z1 = _mm512_aesenc_epi128(z1, z16);
    z2 = _mm512_aesenc_epi128(z2, z16);
    z3 = _mm512_aesenc_epi128(z3, z16);
    z0 = _mm512_aesenc_epi128(z0, z17);
    z1 = _mm512_aesenc_epi128(z1, z17);
    z2 = _mm512_aesenc_epi128(z2, z17);
    z3 = _mm512_aesenc_epi128(z3, z17);
    zf3 = (word32)r8;
    zf4 = 0xb;
    z7 = z18;
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_ECB_encrypt_avx512_256_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z18);
    z1 = _mm512_aesenc_epi128(z1, z18);
    z2 = _mm512_aesenc_epi128(z2, z18);
    z3 = _mm512_aesenc_epi128(z3, z18);
    z0 = _mm512_aesenc_epi128(z0, z19);
    z1 = _mm512_aesenc_epi128(z1, z19);
    z2 = _mm512_aesenc_epi128(z2, z19);
    z3 = _mm512_aesenc_epi128(z3, z19);
    zf5 = (word32)r8;
    zf6 = 0xd;
    z7 = z20;
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_ECB_encrypt_avx512_256_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z20);
    z1 = _mm512_aesenc_epi128(z1, z20);
    z2 = _mm512_aesenc_epi128(z2, z20);
    z3 = _mm512_aesenc_epi128(z3, z20);
    z0 = _mm512_aesenc_epi128(z0, z21);
    z1 = _mm512_aesenc_epi128(z1, z21);
    z2 = _mm512_aesenc_epi128(z2, z21);
    z3 = _mm512_aesenc_epi128(z3, z21);
    z7 = z22;
L_AES_ECB_encrypt_avx512_256_aes_enc_block_last:
    z0 = _mm512_aesenclast_epi128(z0, z7);
    z1 = _mm512_aesenclast_epi128(z1, z7);
    z2 = _mm512_aesenclast_epi128(z2, z7);
    z3 = _mm512_aesenclast_epi128(z3, z7);
    _mm512_storeu_si512((void*)WC_PW(r11, 0), z0);
    _mm512_storeu_si512((void*)WC_PW(r11, 64), z1);
    _mm512_storeu_si512((void*)WC_PW(r11, 128), z2);
    _mm512_storeu_si512((void*)WC_PW(r11, 192), z3);
    rax = (word32)((word32)rax + 0x100);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_encrypt_avx512_enc_256;
    }
L_AES_ECB_encrypt_avx512_done_256:
    r9 = (word32)((word32)rdx);
    r9 = (word32)((word32)r9 - (word32)rax);
    if (((word32)r9) < (0x80)) {
        goto L_AES_ECB_encrypt_avx512_done_128;
    }
    /* 128 bytes of input */
    /* aes_ecb_enc_128 */
    r10 = (word64)(rdi + rax);
    r11 = (word64)(rsi + rax);
    z0 = _mm512_loadu_si512((const void*)WC_PR(r10, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(r10, 64));
    /* aes_enc_block */
    z0 = _mm512_xor_si512(z0, z8);
    z1 = _mm512_xor_si512(z1, z8);
    z0 = _mm512_aesenc_epi128(z0, z9);
    z1 = _mm512_aesenc_epi128(z1, z9);
    z0 = _mm512_aesenc_epi128(z0, z10);
    z1 = _mm512_aesenc_epi128(z1, z10);
    z0 = _mm512_aesenc_epi128(z0, z11);
    z1 = _mm512_aesenc_epi128(z1, z11);
    z0 = _mm512_aesenc_epi128(z0, z12);
    z1 = _mm512_aesenc_epi128(z1, z12);
    z0 = _mm512_aesenc_epi128(z0, z13);
    z1 = _mm512_aesenc_epi128(z1, z13);
    z0 = _mm512_aesenc_epi128(z0, z14);
    z1 = _mm512_aesenc_epi128(z1, z14);
    z0 = _mm512_aesenc_epi128(z0, z15);
    z1 = _mm512_aesenc_epi128(z1, z15);
    z0 = _mm512_aesenc_epi128(z0, z16);
    z1 = _mm512_aesenc_epi128(z1, z16);
    z0 = _mm512_aesenc_epi128(z0, z17);
    z1 = _mm512_aesenc_epi128(z1, z17);
    zf7 = (word32)r8;
    zf8 = 0xb;
    z7 = z18;
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_ECB_encrypt_avx512_128_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z18);
    z1 = _mm512_aesenc_epi128(z1, z18);
    z0 = _mm512_aesenc_epi128(z0, z19);
    z1 = _mm512_aesenc_epi128(z1, z19);
    zf9 = (word32)r8;
    zf10 = 0xd;
    z7 = z20;
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_ECB_encrypt_avx512_128_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z20);
    z1 = _mm512_aesenc_epi128(z1, z20);
    z0 = _mm512_aesenc_epi128(z0, z21);
    z1 = _mm512_aesenc_epi128(z1, z21);
    z7 = z22;
L_AES_ECB_encrypt_avx512_128_aes_enc_block_last:
    z0 = _mm512_aesenclast_epi128(z0, z7);
    z1 = _mm512_aesenclast_epi128(z1, z7);
    _mm512_storeu_si512((void*)WC_PW(r11, 0), z0);
    _mm512_storeu_si512((void*)WC_PW(r11, 64), z1);
    rax = (word32)((word32)rax + 0x80);
L_AES_ECB_encrypt_avx512_done_128:
    r9 = (word32)((word32)rdx);
    r9 = (word32)((word32)r9 & 0xffffffc0);
    if (((word32)rax) == ((word32)r9)) {
        goto L_AES_ECB_encrypt_avx512_done_64;
    }
L_AES_ECB_encrypt_avx512_enc_64:
    /* 64 bytes of input */
    /* aes_ecb_enc_64 */
    r10 = (word64)(rdi + rax);
    r11 = (word64)(rsi + rax);
    z0 = _mm512_loadu_si512((const void*)WC_PR(r10, 0));
    /* aes_enc_block */
    z0 = _mm512_xor_si512(z0, z8);
    z0 = _mm512_aesenc_epi128(z0, z9);
    z0 = _mm512_aesenc_epi128(z0, z10);
    z0 = _mm512_aesenc_epi128(z0, z11);
    z0 = _mm512_aesenc_epi128(z0, z12);
    z0 = _mm512_aesenc_epi128(z0, z13);
    z0 = _mm512_aesenc_epi128(z0, z14);
    z0 = _mm512_aesenc_epi128(z0, z15);
    z0 = _mm512_aesenc_epi128(z0, z16);
    z0 = _mm512_aesenc_epi128(z0, z17);
    zf11 = (word32)r8;
    zf12 = 0xb;
    z7 = z18;
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_ECB_encrypt_avx512_64_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z18);
    z0 = _mm512_aesenc_epi128(z0, z19);
    zf13 = (word32)r8;
    zf14 = 0xd;
    z7 = z20;
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_ECB_encrypt_avx512_64_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z20);
    z0 = _mm512_aesenc_epi128(z0, z21);
    z7 = z22;
L_AES_ECB_encrypt_avx512_64_aes_enc_block_last:
    z0 = _mm512_aesenclast_epi128(z0, z7);
    _mm512_storeu_si512((void*)WC_PW(r11, 0), z0);
    rax = (word32)((word32)rax + 0x40);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_encrypt_avx512_enc_64;
    }
L_AES_ECB_encrypt_avx512_done_64:
    r9 = (word32)((word32)rdx);
    r9 = (word32)((word32)r9 - (word32)rax);
    if (((word32)r9) < (0x20)) {
        goto L_AES_ECB_encrypt_avx512_done_32;
    }
    /* 32 bytes of input */
    r10 = (word64)(rdi + rax);
    z0 = _mm512_zextsi256_si512(_mm256_loadu_si256((const __m256i*)WC_PR(r10,
        0)));
    /* aes_enc_block */
    z0 = _mm512_zextsi256_si512(_mm256_xor_si256(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z8)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z9)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z10)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z11)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z12)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z13)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z14)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z15)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z16)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z17)));
    zf15 = (word32)r8;
    zf16 = 0xb;
    z7 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z18));
    if ((sword32)(zf15) < (sword32)(zf16)) {
        goto L_AES_ECB_encrypt_avx512_32_aes_enc_block_last;
    }
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z18)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z19)));
    zf17 = (word32)r8;
    zf18 = 0xd;
    z7 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z20));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_ECB_encrypt_avx512_32_aes_enc_block_last;
    }
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z20)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z21)));
    z7 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z22));
L_AES_ECB_encrypt_avx512_32_aes_enc_block_last:
    z0 = _mm512_zextsi256_si512(_mm256_aesenclast_epi128(_mm512_castsi512_si256(
        z0), _mm512_castsi512_si256(z7)));
    r10 = (word64)(rsi + rax);
    _mm256_storeu_si256((__m256i*)WC_PW(r10, 0), _mm512_castsi512_si256(z0));
    rax = (word32)((word32)rax + 0x20);
L_AES_ECB_encrypt_avx512_done_32:
    zf19 = (word32)rax;
    zf20 = (word32)rdx;
    r9 = (word32)((word32)rdx);
    if ((zf19) == (zf20)) {
        goto L_AES_ECB_encrypt_avx512_done_enc;
    }
    r9 = (word32)((word32)r9 & 0xfffffff0);
L_AES_ECB_encrypt_avx512_enc_16:
    /* 16 bytes of input */
    r10 = (word64)(rdi + rax);
    z0 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10, 0)));
    /* aes_enc_block */
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0))));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 128));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 144));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        x5));
    zf21 = (word32)r8;
    zf22 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 160));
    if ((sword32)(zf21) < (sword32)(zf22)) {
        goto L_AES_ECB_encrypt_avx512_16_aes_enc_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        x5));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 176));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        x6));
    zf23 = (word32)r8;
    zf24 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 192));
    if ((sword32)(zf23) < (sword32)(zf24)) {
        goto L_AES_ECB_encrypt_avx512_16_aes_enc_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        x5));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 208));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        x6));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 224));
L_AES_ECB_encrypt_avx512_16_aes_enc_block_last:
    z0 = _mm512_zextsi128_si512(_mm_aesenclast_si128(_mm512_castsi512_si128(z0),
        x5));
    r10 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 0), _mm512_castsi512_si128(z0));
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_encrypt_avx512_enc_16;
    }
L_AES_ECB_encrypt_avx512_done_enc:
    ;
}

WC_X64I_TARGET("aes,vaes,avx512f,avx512vl")
WOLFSSL_LOCAL void AES_ECB_decrypt_avx512(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr)
{
    word64 rdi, rsi, rdx, rcx, r8, rax, r9 = 0, r10 = 0, r11 = 0;
    __m128i x5 = _mm_setzero_si128(), x6 = _mm_setzero_si128();
    __m512i z0 = _mm512_setzero_si512(), z1 = _mm512_setzero_si512(),
            z2 = _mm512_setzero_si512(), z3 = _mm512_setzero_si512(),
            z7 = _mm512_setzero_si512(), z8 = _mm512_setzero_si512(),
            z9 = _mm512_setzero_si512(), z10 = _mm512_setzero_si512(),
            z11 = _mm512_setzero_si512(), z12 = _mm512_setzero_si512(),
            z13 = _mm512_setzero_si512(), z14 = _mm512_setzero_si512(),
            z15 = _mm512_setzero_si512(), z16 = _mm512_setzero_si512(),
            z17 = _mm512_setzero_si512(), z18 = _mm512_setzero_si512(),
            z19 = _mm512_setzero_si512(), z20 = _mm512_setzero_si512(),
            z21 = _mm512_setzero_si512(), z22 = _mm512_setzero_si512();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;
    word32 zf5;
    word32 zf6;
    word32 zf7;
    word32 zf8;
    word32 zf9;
    word32 zf10;
    word32 zf11;
    word32 zf12;
    word32 zf13;
    word32 zf14;
    word32 zf15;
    word32 zf16;
    word32 zf17;
    word32 zf18;
    word32 zf19;
    word32 zf20;
    word32 zf21;
    word32 zf22;
    word32 zf23;
    word32 zf24;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(word64)length;
    rcx = (word64)(size_t)KS;
    r8 = (word64)(word32)nr;

    rax = (word32)(0);
    if (((word32)rdx) < (0x20)) {
        goto L_AES_ECB_decrypt_avx512_done_32;
    }
    z8 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    z9 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        16)));
    z10 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        32)));
    z11 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        48)));
    z12 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        64)));
    z13 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        80)));
    z14 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        96)));
    z15 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        112)));
    z16 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        128)));
    z17 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        144)));
    z18 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        160)));
    if ((sword32)((word32)r8) < (sword32)(0xb)) {
        goto L_AES_ECB_decrypt_avx512_key_cached;
    }
    z19 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        176)));
    z20 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        192)));
    if ((sword32)((word32)r8) < (sword32)(0xd)) {
        goto L_AES_ECB_decrypt_avx512_key_cached;
    }
    z21 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        208)));
    z22 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        224)));
L_AES_ECB_decrypt_avx512_key_cached:
    zf1 = (word32)rdx;
    zf2 = 0x100;
    r9 = (word32)((word32)rdx);
    if ((zf1) < (zf2)) {
        goto L_AES_ECB_decrypt_avx512_done_256;
    }
    r9 = (word32)((word32)r9 & 0xffffff00);
L_AES_ECB_decrypt_avx512_dec_256:
    /* 256 bytes of input */
    /* aes_ecb_dec_256 */
    r10 = (word64)(rdi + rax);
    r11 = (word64)(rsi + rax);
    z0 = _mm512_loadu_si512((const void*)WC_PR(r10, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(r10, 64));
    z2 = _mm512_loadu_si512((const void*)WC_PR(r10, 128));
    z3 = _mm512_loadu_si512((const void*)WC_PR(r10, 192));
    /* aes_dec_block */
    z0 = _mm512_xor_si512(z0, z8);
    z1 = _mm512_xor_si512(z1, z8);
    z2 = _mm512_xor_si512(z2, z8);
    z3 = _mm512_xor_si512(z3, z8);
    z0 = _mm512_aesdec_epi128(z0, z9);
    z1 = _mm512_aesdec_epi128(z1, z9);
    z2 = _mm512_aesdec_epi128(z2, z9);
    z3 = _mm512_aesdec_epi128(z3, z9);
    z0 = _mm512_aesdec_epi128(z0, z10);
    z1 = _mm512_aesdec_epi128(z1, z10);
    z2 = _mm512_aesdec_epi128(z2, z10);
    z3 = _mm512_aesdec_epi128(z3, z10);
    z0 = _mm512_aesdec_epi128(z0, z11);
    z1 = _mm512_aesdec_epi128(z1, z11);
    z2 = _mm512_aesdec_epi128(z2, z11);
    z3 = _mm512_aesdec_epi128(z3, z11);
    z0 = _mm512_aesdec_epi128(z0, z12);
    z1 = _mm512_aesdec_epi128(z1, z12);
    z2 = _mm512_aesdec_epi128(z2, z12);
    z3 = _mm512_aesdec_epi128(z3, z12);
    z0 = _mm512_aesdec_epi128(z0, z13);
    z1 = _mm512_aesdec_epi128(z1, z13);
    z2 = _mm512_aesdec_epi128(z2, z13);
    z3 = _mm512_aesdec_epi128(z3, z13);
    z0 = _mm512_aesdec_epi128(z0, z14);
    z1 = _mm512_aesdec_epi128(z1, z14);
    z2 = _mm512_aesdec_epi128(z2, z14);
    z3 = _mm512_aesdec_epi128(z3, z14);
    z0 = _mm512_aesdec_epi128(z0, z15);
    z1 = _mm512_aesdec_epi128(z1, z15);
    z2 = _mm512_aesdec_epi128(z2, z15);
    z3 = _mm512_aesdec_epi128(z3, z15);
    z0 = _mm512_aesdec_epi128(z0, z16);
    z1 = _mm512_aesdec_epi128(z1, z16);
    z2 = _mm512_aesdec_epi128(z2, z16);
    z3 = _mm512_aesdec_epi128(z3, z16);
    z0 = _mm512_aesdec_epi128(z0, z17);
    z1 = _mm512_aesdec_epi128(z1, z17);
    z2 = _mm512_aesdec_epi128(z2, z17);
    z3 = _mm512_aesdec_epi128(z3, z17);
    zf3 = (word32)r8;
    zf4 = 0xb;
    z7 = z18;
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_ECB_decrypt_avx512_256_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z18);
    z1 = _mm512_aesdec_epi128(z1, z18);
    z2 = _mm512_aesdec_epi128(z2, z18);
    z3 = _mm512_aesdec_epi128(z3, z18);
    z0 = _mm512_aesdec_epi128(z0, z19);
    z1 = _mm512_aesdec_epi128(z1, z19);
    z2 = _mm512_aesdec_epi128(z2, z19);
    z3 = _mm512_aesdec_epi128(z3, z19);
    zf5 = (word32)r8;
    zf6 = 0xd;
    z7 = z20;
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_ECB_decrypt_avx512_256_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z20);
    z1 = _mm512_aesdec_epi128(z1, z20);
    z2 = _mm512_aesdec_epi128(z2, z20);
    z3 = _mm512_aesdec_epi128(z3, z20);
    z0 = _mm512_aesdec_epi128(z0, z21);
    z1 = _mm512_aesdec_epi128(z1, z21);
    z2 = _mm512_aesdec_epi128(z2, z21);
    z3 = _mm512_aesdec_epi128(z3, z21);
    z7 = z22;
L_AES_ECB_decrypt_avx512_256_aes_dec_block_last:
    z0 = _mm512_aesdeclast_epi128(z0, z7);
    z1 = _mm512_aesdeclast_epi128(z1, z7);
    z2 = _mm512_aesdeclast_epi128(z2, z7);
    z3 = _mm512_aesdeclast_epi128(z3, z7);
    _mm512_storeu_si512((void*)WC_PW(r11, 0), z0);
    _mm512_storeu_si512((void*)WC_PW(r11, 64), z1);
    _mm512_storeu_si512((void*)WC_PW(r11, 128), z2);
    _mm512_storeu_si512((void*)WC_PW(r11, 192), z3);
    rax = (word32)((word32)rax + 0x100);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_decrypt_avx512_dec_256;
    }
L_AES_ECB_decrypt_avx512_done_256:
    r9 = (word32)((word32)rdx);
    r9 = (word32)((word32)r9 - (word32)rax);
    if (((word32)r9) < (0x80)) {
        goto L_AES_ECB_decrypt_avx512_done_128;
    }
    /* 128 bytes of input */
    /* aes_ecb_dec_128 */
    r10 = (word64)(rdi + rax);
    r11 = (word64)(rsi + rax);
    z0 = _mm512_loadu_si512((const void*)WC_PR(r10, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(r10, 64));
    /* aes_dec_block */
    z0 = _mm512_xor_si512(z0, z8);
    z1 = _mm512_xor_si512(z1, z8);
    z0 = _mm512_aesdec_epi128(z0, z9);
    z1 = _mm512_aesdec_epi128(z1, z9);
    z0 = _mm512_aesdec_epi128(z0, z10);
    z1 = _mm512_aesdec_epi128(z1, z10);
    z0 = _mm512_aesdec_epi128(z0, z11);
    z1 = _mm512_aesdec_epi128(z1, z11);
    z0 = _mm512_aesdec_epi128(z0, z12);
    z1 = _mm512_aesdec_epi128(z1, z12);
    z0 = _mm512_aesdec_epi128(z0, z13);
    z1 = _mm512_aesdec_epi128(z1, z13);
    z0 = _mm512_aesdec_epi128(z0, z14);
    z1 = _mm512_aesdec_epi128(z1, z14);
    z0 = _mm512_aesdec_epi128(z0, z15);
    z1 = _mm512_aesdec_epi128(z1, z15);
    z0 = _mm512_aesdec_epi128(z0, z16);
    z1 = _mm512_aesdec_epi128(z1, z16);
    z0 = _mm512_aesdec_epi128(z0, z17);
    z1 = _mm512_aesdec_epi128(z1, z17);
    zf7 = (word32)r8;
    zf8 = 0xb;
    z7 = z18;
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_ECB_decrypt_avx512_128_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z18);
    z1 = _mm512_aesdec_epi128(z1, z18);
    z0 = _mm512_aesdec_epi128(z0, z19);
    z1 = _mm512_aesdec_epi128(z1, z19);
    zf9 = (word32)r8;
    zf10 = 0xd;
    z7 = z20;
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_ECB_decrypt_avx512_128_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z20);
    z1 = _mm512_aesdec_epi128(z1, z20);
    z0 = _mm512_aesdec_epi128(z0, z21);
    z1 = _mm512_aesdec_epi128(z1, z21);
    z7 = z22;
L_AES_ECB_decrypt_avx512_128_aes_dec_block_last:
    z0 = _mm512_aesdeclast_epi128(z0, z7);
    z1 = _mm512_aesdeclast_epi128(z1, z7);
    _mm512_storeu_si512((void*)WC_PW(r11, 0), z0);
    _mm512_storeu_si512((void*)WC_PW(r11, 64), z1);
    rax = (word32)((word32)rax + 0x80);
L_AES_ECB_decrypt_avx512_done_128:
    r9 = (word32)((word32)rdx);
    r9 = (word32)((word32)r9 & 0xffffffc0);
    if (((word32)rax) == ((word32)r9)) {
        goto L_AES_ECB_decrypt_avx512_done_64;
    }
L_AES_ECB_decrypt_avx512_dec_64:
    /* 64 bytes of input */
    /* aes_ecb_dec_64 */
    r10 = (word64)(rdi + rax);
    r11 = (word64)(rsi + rax);
    z0 = _mm512_loadu_si512((const void*)WC_PR(r10, 0));
    /* aes_dec_block */
    z0 = _mm512_xor_si512(z0, z8);
    z0 = _mm512_aesdec_epi128(z0, z9);
    z0 = _mm512_aesdec_epi128(z0, z10);
    z0 = _mm512_aesdec_epi128(z0, z11);
    z0 = _mm512_aesdec_epi128(z0, z12);
    z0 = _mm512_aesdec_epi128(z0, z13);
    z0 = _mm512_aesdec_epi128(z0, z14);
    z0 = _mm512_aesdec_epi128(z0, z15);
    z0 = _mm512_aesdec_epi128(z0, z16);
    z0 = _mm512_aesdec_epi128(z0, z17);
    zf11 = (word32)r8;
    zf12 = 0xb;
    z7 = z18;
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_ECB_decrypt_avx512_64_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z18);
    z0 = _mm512_aesdec_epi128(z0, z19);
    zf13 = (word32)r8;
    zf14 = 0xd;
    z7 = z20;
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_ECB_decrypt_avx512_64_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z20);
    z0 = _mm512_aesdec_epi128(z0, z21);
    z7 = z22;
L_AES_ECB_decrypt_avx512_64_aes_dec_block_last:
    z0 = _mm512_aesdeclast_epi128(z0, z7);
    _mm512_storeu_si512((void*)WC_PW(r11, 0), z0);
    rax = (word32)((word32)rax + 0x40);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_decrypt_avx512_dec_64;
    }
L_AES_ECB_decrypt_avx512_done_64:
    r9 = (word32)((word32)rdx);
    r9 = (word32)((word32)r9 - (word32)rax);
    if (((word32)r9) < (0x20)) {
        goto L_AES_ECB_decrypt_avx512_done_32;
    }
    /* 32 bytes of input */
    r10 = (word64)(rdi + rax);
    z0 = _mm512_zextsi256_si512(_mm256_loadu_si256((const __m256i*)WC_PR(r10,
        0)));
    /* aes_dec_block */
    z0 = _mm512_zextsi256_si512(_mm256_xor_si256(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z8)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z9)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z10)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z11)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z12)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z13)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z14)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z15)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z16)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z17)));
    zf15 = (word32)r8;
    zf16 = 0xb;
    z7 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z18));
    if ((sword32)(zf15) < (sword32)(zf16)) {
        goto L_AES_ECB_decrypt_avx512_32_aes_dec_block_last;
    }
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z18)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z19)));
    zf17 = (word32)r8;
    zf18 = 0xd;
    z7 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z20));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_ECB_decrypt_avx512_32_aes_dec_block_last;
    }
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z20)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z21)));
    z7 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z22));
L_AES_ECB_decrypt_avx512_32_aes_dec_block_last:
    z0 = _mm512_zextsi256_si512(_mm256_aesdeclast_epi128(_mm512_castsi512_si256(
        z0), _mm512_castsi512_si256(z7)));
    r10 = (word64)(rsi + rax);
    _mm256_storeu_si256((__m256i*)WC_PW(r10, 0), _mm512_castsi512_si256(z0));
    rax = (word32)((word32)rax + 0x20);
L_AES_ECB_decrypt_avx512_done_32:
    zf19 = (word32)rax;
    zf20 = (word32)rdx;
    r9 = (word32)((word32)rdx);
    if ((zf19) == (zf20)) {
        goto L_AES_ECB_decrypt_avx512_done_dec;
    }
    r9 = (word32)((word32)r9 & 0xfffffff0);
L_AES_ECB_decrypt_avx512_dec_16:
    /* 16 bytes of input */
    r10 = (word64)(rdi + rax);
    z0 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10, 0)));
    /* aes_dec_block */
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0))));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 64));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 80));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 96));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 112));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 128));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 144));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    zf21 = (word32)r8;
    zf22 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 160));
    if ((sword32)(zf21) < (sword32)(zf22)) {
        goto L_AES_ECB_decrypt_avx512_16_aes_dec_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 176));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x6));
    zf23 = (word32)r8;
    zf24 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 192));
    if ((sword32)(zf23) < (sword32)(zf24)) {
        goto L_AES_ECB_decrypt_avx512_16_aes_dec_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 208));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x6));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 224));
L_AES_ECB_decrypt_avx512_16_aes_dec_block_last:
    z0 = _mm512_zextsi128_si512(_mm_aesdeclast_si128(_mm512_castsi512_si128(z0),
        x5));
    r10 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r10, 0), _mm512_castsi512_si128(z0));
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)r9)) {
        goto L_AES_ECB_decrypt_avx512_dec_16;
    }
L_AES_ECB_decrypt_avx512_done_dec:
    ;
}

WC_X64I_TARGET("aes,avx,avx512f,avx512vl")
WOLFSSL_LOCAL void AES_CBC_encrypt_avx512(const unsigned char* in,
    unsigned char* out, unsigned char* ivec, unsigned long length,
    const unsigned char* KS, int nr)
{
    word64 rdi, rsi, rdx, rcx, r8, r9, rax, r10 = 0, r11 = 0;
    __m128i x0, x1 = _mm_setzero_si128(), x3 = _mm_setzero_si128(),
            x4 = _mm_setzero_si128();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(size_t)ivec;
    rcx = (word64)(word64)length;
    r8 = (word64)(size_t)KS;
    r9 = (word64)(word32)nr;

    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rdx, 0));
    rax = (word32)(0);
    if (((word32)rax) == ((word32)rcx)) {
        goto L_AES_CBC_encrypt_avx512_done;
    }
L_AES_CBC_encrypt_avx512_loop:
    /* 16 bytes of input */
    r10 = (word64)(rdi + rax);
    x1 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    x1 = _mm_ternarylogic_epi64(x1, x0, _mm_loadu_si128((const __m128i*)WC_PR(
        r8, 0)), 0x96);
    /* aes_enc_block */
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x1 = _mm_aesenc_si128(x1, x3);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x1 = _mm_aesenc_si128(x1, x3);
    zf1 = (word32)r9;
    zf2 = 0xb;
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_CBC_encrypt_avx512_aes_enc_block_last;
    }
    x1 = _mm_aesenc_si128(x1, x3);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x1 = _mm_aesenc_si128(x1, x4);
    zf3 = (word32)r9;
    zf4 = 0xd;
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_CBC_encrypt_avx512_aes_enc_block_last;
    }
    x1 = _mm_aesenc_si128(x1, x3);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x1 = _mm_aesenc_si128(x1, x4);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_CBC_encrypt_avx512_aes_enc_block_last:
    x1 = _mm_aesenclast_si128(x1, x3);
    r11 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 0), x1);
    x0 = x1;
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)rcx)) {
        goto L_AES_CBC_encrypt_avx512_loop;
    }
L_AES_CBC_encrypt_avx512_done:
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x0);
}

WC_X64I_TARGET("aes,vaes,avx512f,avx512vl")
WOLFSSL_LOCAL void AES_CBC_decrypt_avx512(const unsigned char* in,
    unsigned char* out, unsigned char* ivec, unsigned long length,
    const unsigned char* KS, int nr)
{
    word64 rdi, rsi, rdx, rcx, r8, r9, rax, r10 = 0, r11 = 0, r12 = 0;
    __m128i x5 = _mm_setzero_si128(), x6 = _mm_setzero_si128(),
            x7 = _mm_setzero_si128();
    __m256i y8;
    __m512i z0 = _mm512_setzero_si512(), z1 = _mm512_setzero_si512(),
            z2 = _mm512_setzero_si512(), z3 = _mm512_setzero_si512(),
            z9 = _mm512_setzero_si512(), z10 = _mm512_setzero_si512(),
            z11 = _mm512_setzero_si512(), z12 = _mm512_setzero_si512(),
            z13 = _mm512_setzero_si512(), z14 = _mm512_setzero_si512(),
            z15 = _mm512_setzero_si512(), z16 = _mm512_setzero_si512(),
            z17 = _mm512_setzero_si512(), z18 = _mm512_setzero_si512(),
            z19 = _mm512_setzero_si512(), z20 = _mm512_setzero_si512(),
            z21 = _mm512_setzero_si512(), z22 = _mm512_setzero_si512(),
            z23 = _mm512_setzero_si512(), z24 = _mm512_setzero_si512(),
            z25 = _mm512_setzero_si512(), z26 = _mm512_setzero_si512(),
            z27 = _mm512_setzero_si512(), z28 = _mm512_setzero_si512();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;
    word32 zf5;
    word32 zf6;
    word32 zf7;
    word32 zf8;
    word32 zf9;
    word32 zf10;
    word32 zf11;
    word32 zf12;
    word32 zf13;
    word32 zf14;
    word32 zf15;
    word32 zf16;
    word32 zf17;
    word32 zf18;
    word32 zf19;
    word32 zf20;
    word32 zf21;
    word32 zf22;
    word32 zf23;
    word32 zf24;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(size_t)ivec;
    rcx = (word64)(word64)length;
    r8 = (word64)(size_t)KS;
    r9 = (word64)(word32)nr;

    y8 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rdx, 0)));
    rax = (word32)(0);
    if (((word32)rcx) < (0x20)) {
        goto L_AES_CBC_decrypt_avx512_done_32;
    }
    z14 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    z15 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        16)));
    z16 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        32)));
    z17 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        48)));
    z18 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        64)));
    z19 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        80)));
    z20 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        96)));
    z21 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    z22 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    z23 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    z24 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)((word32)r9) < (sword32)(0xb)) {
        goto L_AES_CBC_decrypt_avx512_key_cached;
    }
    z25 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    z26 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)((word32)r9) < (sword32)(0xd)) {
        goto L_AES_CBC_decrypt_avx512_key_cached;
    }
    z27 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    z28 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_CBC_decrypt_avx512_key_cached:
    zf1 = (word32)rcx;
    zf2 = 0x100;
    r10 = (word32)((word32)rcx);
    if ((zf1) < (zf2)) {
        goto L_AES_CBC_decrypt_avx512_done_256;
    }
    r10 = (word32)((word32)r10 & 0xffffff00);
L_AES_CBC_decrypt_avx512_dec_256:
    /* 256 bytes of input */
    /* aes_cbc_dec_256 */
    r11 = (word64)(rdi + rax);
    r12 = (word64)(rsi + rax);
    z0 = _mm512_loadu_si512((const void*)WC_PR(r11, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(r11, 64));
    z2 = _mm512_loadu_si512((const void*)WC_PR(r11, 128));
    z3 = _mm512_loadu_si512((const void*)WC_PR(r11, 192));
    z10 = _mm512_shuffle_i64x2(z0, z0, 0x90);
    z10 = _mm512_inserti32x4(z10, _mm256_castsi256_si128(y8), 0);
    z11 = _mm512_loadu_si512((const void*)WC_PR(r11, 48));
    z12 = _mm512_loadu_si512((const void*)WC_PR(r11, 112));
    z13 = _mm512_loadu_si512((const void*)WC_PR(r11, 176));
    y8 = _mm256_zextsi128_si256(_mm512_extracti32x4_epi32(z3, 3));
    /* aes_dec_block */
    z0 = _mm512_xor_si512(z0, z14);
    z1 = _mm512_xor_si512(z1, z14);
    z2 = _mm512_xor_si512(z2, z14);
    z3 = _mm512_xor_si512(z3, z14);
    z0 = _mm512_aesdec_epi128(z0, z15);
    z1 = _mm512_aesdec_epi128(z1, z15);
    z2 = _mm512_aesdec_epi128(z2, z15);
    z3 = _mm512_aesdec_epi128(z3, z15);
    z0 = _mm512_aesdec_epi128(z0, z16);
    z1 = _mm512_aesdec_epi128(z1, z16);
    z2 = _mm512_aesdec_epi128(z2, z16);
    z3 = _mm512_aesdec_epi128(z3, z16);
    z0 = _mm512_aesdec_epi128(z0, z17);
    z1 = _mm512_aesdec_epi128(z1, z17);
    z2 = _mm512_aesdec_epi128(z2, z17);
    z3 = _mm512_aesdec_epi128(z3, z17);
    z0 = _mm512_aesdec_epi128(z0, z18);
    z1 = _mm512_aesdec_epi128(z1, z18);
    z2 = _mm512_aesdec_epi128(z2, z18);
    z3 = _mm512_aesdec_epi128(z3, z18);
    z0 = _mm512_aesdec_epi128(z0, z19);
    z1 = _mm512_aesdec_epi128(z1, z19);
    z2 = _mm512_aesdec_epi128(z2, z19);
    z3 = _mm512_aesdec_epi128(z3, z19);
    z0 = _mm512_aesdec_epi128(z0, z20);
    z1 = _mm512_aesdec_epi128(z1, z20);
    z2 = _mm512_aesdec_epi128(z2, z20);
    z3 = _mm512_aesdec_epi128(z3, z20);
    z0 = _mm512_aesdec_epi128(z0, z21);
    z1 = _mm512_aesdec_epi128(z1, z21);
    z2 = _mm512_aesdec_epi128(z2, z21);
    z3 = _mm512_aesdec_epi128(z3, z21);
    z0 = _mm512_aesdec_epi128(z0, z22);
    z1 = _mm512_aesdec_epi128(z1, z22);
    z2 = _mm512_aesdec_epi128(z2, z22);
    z3 = _mm512_aesdec_epi128(z3, z22);
    z0 = _mm512_aesdec_epi128(z0, z23);
    z1 = _mm512_aesdec_epi128(z1, z23);
    z2 = _mm512_aesdec_epi128(z2, z23);
    z3 = _mm512_aesdec_epi128(z3, z23);
    zf3 = (word32)r9;
    zf4 = 0xb;
    z9 = z24;
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_CBC_decrypt_avx512_256_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z24);
    z1 = _mm512_aesdec_epi128(z1, z24);
    z2 = _mm512_aesdec_epi128(z2, z24);
    z3 = _mm512_aesdec_epi128(z3, z24);
    z0 = _mm512_aesdec_epi128(z0, z25);
    z1 = _mm512_aesdec_epi128(z1, z25);
    z2 = _mm512_aesdec_epi128(z2, z25);
    z3 = _mm512_aesdec_epi128(z3, z25);
    zf5 = (word32)r9;
    zf6 = 0xd;
    z9 = z26;
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_CBC_decrypt_avx512_256_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z26);
    z1 = _mm512_aesdec_epi128(z1, z26);
    z2 = _mm512_aesdec_epi128(z2, z26);
    z3 = _mm512_aesdec_epi128(z3, z26);
    z0 = _mm512_aesdec_epi128(z0, z27);
    z1 = _mm512_aesdec_epi128(z1, z27);
    z2 = _mm512_aesdec_epi128(z2, z27);
    z3 = _mm512_aesdec_epi128(z3, z27);
    z9 = z28;
L_AES_CBC_decrypt_avx512_256_aes_dec_block_last:
    z0 = _mm512_aesdeclast_epi128(z0, z9);
    z1 = _mm512_aesdeclast_epi128(z1, z9);
    z2 = _mm512_aesdeclast_epi128(z2, z9);
    z3 = _mm512_aesdeclast_epi128(z3, z9);
    z0 = _mm512_xor_si512(z0, z10);
    z1 = _mm512_xor_si512(z1, z11);
    z2 = _mm512_xor_si512(z2, z12);
    z3 = _mm512_xor_si512(z3, z13);
    _mm512_storeu_si512((void*)WC_PW(r12, 0), z0);
    _mm512_storeu_si512((void*)WC_PW(r12, 64), z1);
    _mm512_storeu_si512((void*)WC_PW(r12, 128), z2);
    _mm512_storeu_si512((void*)WC_PW(r12, 192), z3);
    rax = (word32)((word32)rax + 0x100);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CBC_decrypt_avx512_dec_256;
    }
L_AES_CBC_decrypt_avx512_done_256:
    r10 = (word32)((word32)rcx);
    r10 = (word32)((word32)r10 - (word32)rax);
    if (((word32)r10) < (0x80)) {
        goto L_AES_CBC_decrypt_avx512_done_128;
    }
    /* 128 bytes of input */
    /* aes_cbc_dec_128 */
    r11 = (word64)(rdi + rax);
    r12 = (word64)(rsi + rax);
    z0 = _mm512_loadu_si512((const void*)WC_PR(r11, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(r11, 64));
    z10 = _mm512_shuffle_i64x2(z0, z0, 0x90);
    z10 = _mm512_inserti32x4(z10, _mm256_castsi256_si128(y8), 0);
    z11 = _mm512_loadu_si512((const void*)WC_PR(r11, 48));
    y8 = _mm256_zextsi128_si256(_mm512_extracti32x4_epi32(z1, 3));
    /* aes_dec_block */
    z0 = _mm512_xor_si512(z0, z14);
    z1 = _mm512_xor_si512(z1, z14);
    z0 = _mm512_aesdec_epi128(z0, z15);
    z1 = _mm512_aesdec_epi128(z1, z15);
    z0 = _mm512_aesdec_epi128(z0, z16);
    z1 = _mm512_aesdec_epi128(z1, z16);
    z0 = _mm512_aesdec_epi128(z0, z17);
    z1 = _mm512_aesdec_epi128(z1, z17);
    z0 = _mm512_aesdec_epi128(z0, z18);
    z1 = _mm512_aesdec_epi128(z1, z18);
    z0 = _mm512_aesdec_epi128(z0, z19);
    z1 = _mm512_aesdec_epi128(z1, z19);
    z0 = _mm512_aesdec_epi128(z0, z20);
    z1 = _mm512_aesdec_epi128(z1, z20);
    z0 = _mm512_aesdec_epi128(z0, z21);
    z1 = _mm512_aesdec_epi128(z1, z21);
    z0 = _mm512_aesdec_epi128(z0, z22);
    z1 = _mm512_aesdec_epi128(z1, z22);
    z0 = _mm512_aesdec_epi128(z0, z23);
    z1 = _mm512_aesdec_epi128(z1, z23);
    zf7 = (word32)r9;
    zf8 = 0xb;
    z9 = z24;
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_CBC_decrypt_avx512_128_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z24);
    z1 = _mm512_aesdec_epi128(z1, z24);
    z0 = _mm512_aesdec_epi128(z0, z25);
    z1 = _mm512_aesdec_epi128(z1, z25);
    zf9 = (word32)r9;
    zf10 = 0xd;
    z9 = z26;
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_CBC_decrypt_avx512_128_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z26);
    z1 = _mm512_aesdec_epi128(z1, z26);
    z0 = _mm512_aesdec_epi128(z0, z27);
    z1 = _mm512_aesdec_epi128(z1, z27);
    z9 = z28;
L_AES_CBC_decrypt_avx512_128_aes_dec_block_last:
    z0 = _mm512_aesdeclast_epi128(z0, z9);
    z1 = _mm512_aesdeclast_epi128(z1, z9);
    z0 = _mm512_xor_si512(z0, z10);
    z1 = _mm512_xor_si512(z1, z11);
    _mm512_storeu_si512((void*)WC_PW(r12, 0), z0);
    _mm512_storeu_si512((void*)WC_PW(r12, 64), z1);
    rax = (word32)((word32)rax + 0x80);
L_AES_CBC_decrypt_avx512_done_128:
    r10 = (word32)((word32)rcx);
    r10 = (word32)((word32)r10 & 0xffffffc0);
    if (((word32)rax) == ((word32)r10)) {
        goto L_AES_CBC_decrypt_avx512_done_64;
    }
L_AES_CBC_decrypt_avx512_dec_64:
    /* 64 bytes of input */
    /* aes_cbc_dec_64 */
    r11 = (word64)(rdi + rax);
    r12 = (word64)(rsi + rax);
    z0 = _mm512_loadu_si512((const void*)WC_PR(r11, 0));
    z10 = _mm512_shuffle_i64x2(z0, z0, 0x90);
    z10 = _mm512_inserti32x4(z10, _mm256_castsi256_si128(y8), 0);
    y8 = _mm256_zextsi128_si256(_mm512_extracti32x4_epi32(z0, 3));
    /* aes_dec_block */
    z0 = _mm512_xor_si512(z0, z14);
    z0 = _mm512_aesdec_epi128(z0, z15);
    z0 = _mm512_aesdec_epi128(z0, z16);
    z0 = _mm512_aesdec_epi128(z0, z17);
    z0 = _mm512_aesdec_epi128(z0, z18);
    z0 = _mm512_aesdec_epi128(z0, z19);
    z0 = _mm512_aesdec_epi128(z0, z20);
    z0 = _mm512_aesdec_epi128(z0, z21);
    z0 = _mm512_aesdec_epi128(z0, z22);
    z0 = _mm512_aesdec_epi128(z0, z23);
    zf11 = (word32)r9;
    zf12 = 0xb;
    z9 = z24;
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_CBC_decrypt_avx512_64_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z24);
    z0 = _mm512_aesdec_epi128(z0, z25);
    zf13 = (word32)r9;
    zf14 = 0xd;
    z9 = z26;
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_CBC_decrypt_avx512_64_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z26);
    z0 = _mm512_aesdec_epi128(z0, z27);
    z9 = z28;
L_AES_CBC_decrypt_avx512_64_aes_dec_block_last:
    z0 = _mm512_aesdeclast_epi128(z0, z9);
    z0 = _mm512_xor_si512(z0, z10);
    _mm512_storeu_si512((void*)WC_PW(r12, 0), z0);
    rax = (word32)((word32)rax + 0x40);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CBC_decrypt_avx512_dec_64;
    }
L_AES_CBC_decrypt_avx512_done_64:
    r10 = (word32)((word32)rcx);
    r10 = (word32)((word32)r10 - (word32)rax);
    if (((word32)r10) < (0x20)) {
        goto L_AES_CBC_decrypt_avx512_done_32;
    }
    /* 32 bytes of input */
    r11 = (word64)(rdi + rax);
    z0 = _mm512_zextsi256_si512(_mm256_loadu_si256((const __m256i*)WC_PR(r11,
        0)));
    z10 = _mm512_zextsi256_si512(_mm256_inserti128_si256(y8,
        _mm512_castsi512_si128(z0), 1));
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(_mm512_castsi512_si256(
        z0), 1));
    /* aes_dec_block */
    z0 = _mm512_zextsi256_si512(_mm256_xor_si256(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z14)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z15)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z16)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z17)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z18)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z19)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z20)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z21)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z22)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z23)));
    zf15 = (word32)r9;
    zf16 = 0xb;
    z9 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z24));
    if ((sword32)(zf15) < (sword32)(zf16)) {
        goto L_AES_CBC_decrypt_avx512_32_aes_dec_block_last;
    }
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z24)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z25)));
    zf17 = (word32)r9;
    zf18 = 0xd;
    z9 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z26));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_CBC_decrypt_avx512_32_aes_dec_block_last;
    }
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z26)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z27)));
    z9 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z28));
L_AES_CBC_decrypt_avx512_32_aes_dec_block_last:
    z0 = _mm512_zextsi256_si512(_mm256_aesdeclast_epi128(_mm512_castsi512_si256(
        z0), _mm512_castsi512_si256(z9)));
    z0 = _mm512_zextsi256_si512(_mm256_xor_si256(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z10)));
    r11 = (word64)(rsi + rax);
    _mm256_storeu_si256((__m256i*)WC_PW(r11, 0), _mm512_castsi512_si256(z0));
    rax = (word32)((word32)rax + 0x20);
L_AES_CBC_decrypt_avx512_done_32:
    zf19 = (word32)rax;
    zf20 = (word32)rcx;
    r10 = (word32)((word32)rcx);
    if ((zf19) == (zf20)) {
        goto L_AES_CBC_decrypt_avx512_done_dec;
    }
    r10 = (word32)((word32)r10 & 0xfffffff0);
L_AES_CBC_decrypt_avx512_dec_16:
    /* 16 bytes of input */
    r11 = (word64)(rdi + rax);
    z0 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r11, 0)));
    x7 = _mm512_castsi512_si128(z0);
    /* aes_dec_block */
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm_loadu_si128((const __m128i*)WC_PR(r8, 0))));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    zf21 = (word32)r9;
    zf22 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf21) < (sword32)(zf22)) {
        goto L_AES_CBC_decrypt_avx512_16_aes_dec_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x6));
    zf23 = (word32)r9;
    zf24 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf23) < (sword32)(zf24)) {
        goto L_AES_CBC_decrypt_avx512_16_aes_dec_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x5));
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        x6));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_CBC_decrypt_avx512_16_aes_dec_block_last:
    z0 = _mm512_zextsi128_si512(_mm_aesdeclast_si128(_mm512_castsi512_si128(z0),
        x5));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm256_castsi256_si128(y8)));
    y8 = _mm256_zextsi128_si256(x7);
    r11 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 0), _mm512_castsi512_si128(z0));
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CBC_decrypt_avx512_dec_16;
    }
L_AES_CBC_decrypt_avx512_done_dec:
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), _mm256_castsi256_si128(y8));
}

XALIGNED(16) static const word64 L_aes_ctr_bswap_avx512[] WC_X64I_UNUSED = {
    0x08090a0b0c0d0e0fULL, 0x0001020304050607ULL,
};

XALIGNED(32) static const word64 L_aes_ctr_inc_avx512[] WC_X64I_UNUSED = {
    0x0000000000000000ULL, 0x0000000000000000ULL,
    0x0000000000000001ULL, 0x0000000000000000ULL,
    0x0000000000000002ULL, 0x0000000000000000ULL,
    0x0000000000000003ULL, 0x0000000000000000ULL,
    0x0000000000000004ULL, 0x0000000000000000ULL,
    0x0000000000000005ULL, 0x0000000000000000ULL,
    0x0000000000000006ULL, 0x0000000000000000ULL,
    0x0000000000000007ULL, 0x0000000000000000ULL,
    0x0000000000000008ULL, 0x0000000000000000ULL,
    0x0000000000000009ULL, 0x0000000000000000ULL,
    0x000000000000000aULL, 0x0000000000000000ULL,
    0x000000000000000bULL, 0x0000000000000000ULL,
    0x000000000000000cULL, 0x0000000000000000ULL,
    0x000000000000000dULL, 0x0000000000000000ULL,
    0x000000000000000eULL, 0x0000000000000000ULL,
    0x000000000000000fULL, 0x0000000000000000ULL,
    0x0000000000000010ULL, 0x0000000000000000ULL,
};

WC_X64I_TARGET("aes,vaes,avx512f,avx512vl,avx512bw")
WOLFSSL_LOCAL void AES_CTR_encrypt_avx512(const unsigned char* in,
    unsigned char* out, unsigned long length, const unsigned char* KS, int nr,
    unsigned char* ctr)
{
    word64 rdi, rsi, rdx, rcx, r8, r9, rax, r10 = 0, r11 = 0, r12 = 0;
    __m512i z0 = _mm512_setzero_si512(), z1 = _mm512_setzero_si512(),
            z2 = _mm512_setzero_si512(), z3 = _mm512_setzero_si512(),
            z4 = _mm512_setzero_si512(), z5 = _mm512_setzero_si512(),
            z6 = _mm512_setzero_si512(), z7, z8, z9 = _mm512_setzero_si512(),
            z10 = _mm512_setzero_si512(), z11 = _mm512_setzero_si512(), z12,
            z13, z14 = _mm512_setzero_si512(), z15 = _mm512_setzero_si512(),
            z16 = _mm512_setzero_si512(), z17 = _mm512_setzero_si512(),
            z18 = _mm512_setzero_si512(), z19 = _mm512_setzero_si512(),
            z20 = _mm512_setzero_si512(), z21 = _mm512_setzero_si512(),
            z22 = _mm512_setzero_si512(), z23 = _mm512_setzero_si512(),
            z24 = _mm512_setzero_si512(), z25 = _mm512_setzero_si512(),
            z26 = _mm512_setzero_si512(), z27 = _mm512_setzero_si512(),
            z28 = _mm512_setzero_si512(), z29 = _mm512_setzero_si512();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;
    word32 zf5;
    word32 zf6;
    word32 zf7;
    word32 zf8;
    word32 zf9;
    word32 zf10;
    word32 zf11;
    word32 zf12;
    word32 zf13;
    word32 zf14;
    word32 zf15;
    word32 zf16;
    word32 zf17;
    word32 zf18;
    word32 zf19;
    word32 zf20;
    word32 zf21;
    word32 zf22;
    word32 zf23;
    word32 zf24;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rdx = (word64)(word64)length;
    rcx = (word64)(size_t)KS;
    r8 = (word64)(word32)nr;
    r9 = (word64)(size_t)ctr;

    z8 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(
        L_aes_ctr_bswap_avx512, 0)));
    z7 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r9, 0)));
    z7 = _mm512_shuffle_epi8(z7, z8);
    z12 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(
        L_aes_ctr_inc_avx512, 64)));
    z13 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(
        L_aes_ctr_inc_avx512, 16)));
    rax = (word32)(0);
    if (((word32)rdx) < (0x20)) {
        goto L_AES_CTR_encrypt_avx512_done_32;
    }
    z15 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        0)));
    z16 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        16)));
    z17 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        32)));
    z18 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        48)));
    z19 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        64)));
    z20 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        80)));
    z21 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        96)));
    z22 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        112)));
    z23 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        128)));
    z24 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        144)));
    z25 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        160)));
    if ((sword32)((word32)r8) < (sword32)(0xb)) {
        goto L_AES_CTR_encrypt_avx512_key_cached;
    }
    z26 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        176)));
    z27 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        192)));
    if ((sword32)((word32)r8) < (sword32)(0xd)) {
        goto L_AES_CTR_encrypt_avx512_key_cached;
    }
    z28 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        208)));
    z29 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        224)));
L_AES_CTR_encrypt_avx512_key_cached:
    zf1 = (word32)rdx;
    zf2 = 0x100;
    r10 = (word32)((word32)rdx);
    if ((zf1) < (zf2)) {
        goto L_AES_CTR_encrypt_avx512_done_256;
    }
    r10 = (word32)((word32)r10 & 0xffffff00);
    z10 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(
        L_aes_ctr_inc_avx512, 256)));
    z9 = z7;
    z4 = _mm512_add_epi64(z7, _mm512_loadu_si512((const void*)WC_PR(
        L_aes_ctr_inc_avx512, 0)));
    z9 = _mm512_ternarylogic_epi64(z9, z4, _mm512_loadu_si512((
        const void*)WC_PR(L_aes_ctr_inc_avx512, 0)), 0xb2);
    z9 = _mm512_srli_epi64(z9, 63);
    z9 = _mm512_bslli_epi128(z9, 8);
    z4 = _mm512_add_epi64(z4, z9);
    z9 = z7;
    z5 = _mm512_add_epi64(z7, _mm512_loadu_si512((const void*)WC_PR(
        L_aes_ctr_inc_avx512, 64)));
    z9 = _mm512_ternarylogic_epi64(z9, z5, _mm512_loadu_si512((
        const void*)WC_PR(L_aes_ctr_inc_avx512, 64)), 0xb2);
    z9 = _mm512_srli_epi64(z9, 63);
    z9 = _mm512_bslli_epi128(z9, 8);
    z5 = _mm512_add_epi64(z5, z9);
    z9 = z7;
    z6 = _mm512_add_epi64(z7, _mm512_loadu_si512((const void*)WC_PR(
        L_aes_ctr_inc_avx512, 128)));
    z9 = _mm512_ternarylogic_epi64(z9, z6, _mm512_loadu_si512((
        const void*)WC_PR(L_aes_ctr_inc_avx512, 128)), 0xb2);
    z9 = _mm512_srli_epi64(z9, 63);
    z9 = _mm512_bslli_epi128(z9, 8);
    z6 = _mm512_add_epi64(z6, z9);
    z9 = z7;
    z7 = _mm512_add_epi64(z7, _mm512_loadu_si512((const void*)WC_PR(
        L_aes_ctr_inc_avx512, 192)));
    z9 = _mm512_ternarylogic_epi64(z9, z7, _mm512_loadu_si512((
        const void*)WC_PR(L_aes_ctr_inc_avx512, 192)), 0xb2);
    z9 = _mm512_srli_epi64(z9, 63);
    z9 = _mm512_bslli_epi128(z9, 8);
    z7 = _mm512_add_epi64(z7, z9);
L_AES_CTR_encrypt_avx512_enc_256:
    /* 256 bytes of input */
    r11 = (word64)(rdi + rax);
    r12 = (word64)(rsi + rax);
    z0 = _mm512_shuffle_epi8(z4, z8);
    z1 = _mm512_shuffle_epi8(z5, z8);
    z2 = _mm512_shuffle_epi8(z6, z8);
    z3 = _mm512_shuffle_epi8(z7, z8);
    z9 = z4;
    z4 = _mm512_add_epi64(z4, z10);
    z9 = _mm512_ternarylogic_epi64(z9, z4, z10, 0xb2);
    z9 = _mm512_srli_epi64(z9, 63);
    z9 = _mm512_bslli_epi128(z9, 8);
    z4 = _mm512_add_epi64(z4, z9);
    z9 = z5;
    z5 = _mm512_add_epi64(z5, z10);
    z9 = _mm512_ternarylogic_epi64(z9, z5, z10, 0xb2);
    z9 = _mm512_srli_epi64(z9, 63);
    z9 = _mm512_bslli_epi128(z9, 8);
    z5 = _mm512_add_epi64(z5, z9);
    z9 = z6;
    z6 = _mm512_add_epi64(z6, z10);
    z9 = _mm512_ternarylogic_epi64(z9, z6, z10, 0xb2);
    z9 = _mm512_srli_epi64(z9, 63);
    z9 = _mm512_bslli_epi128(z9, 8);
    z6 = _mm512_add_epi64(z6, z9);
    z9 = z7;
    z7 = _mm512_add_epi64(z7, z10);
    z9 = _mm512_ternarylogic_epi64(z9, z7, z10, 0xb2);
    z9 = _mm512_srli_epi64(z9, 63);
    z9 = _mm512_bslli_epi128(z9, 8);
    z7 = _mm512_add_epi64(z7, z9);
    /* aes_enc_block */
    z0 = _mm512_xor_si512(z0, z15);
    z1 = _mm512_xor_si512(z1, z15);
    z2 = _mm512_xor_si512(z2, z15);
    z3 = _mm512_xor_si512(z3, z15);
    z0 = _mm512_aesenc_epi128(z0, z16);
    z1 = _mm512_aesenc_epi128(z1, z16);
    z2 = _mm512_aesenc_epi128(z2, z16);
    z3 = _mm512_aesenc_epi128(z3, z16);
    z0 = _mm512_aesenc_epi128(z0, z17);
    z1 = _mm512_aesenc_epi128(z1, z17);
    z2 = _mm512_aesenc_epi128(z2, z17);
    z3 = _mm512_aesenc_epi128(z3, z17);
    z0 = _mm512_aesenc_epi128(z0, z18);
    z1 = _mm512_aesenc_epi128(z1, z18);
    z2 = _mm512_aesenc_epi128(z2, z18);
    z3 = _mm512_aesenc_epi128(z3, z18);
    z0 = _mm512_aesenc_epi128(z0, z19);
    z1 = _mm512_aesenc_epi128(z1, z19);
    z2 = _mm512_aesenc_epi128(z2, z19);
    z3 = _mm512_aesenc_epi128(z3, z19);
    z0 = _mm512_aesenc_epi128(z0, z20);
    z1 = _mm512_aesenc_epi128(z1, z20);
    z2 = _mm512_aesenc_epi128(z2, z20);
    z3 = _mm512_aesenc_epi128(z3, z20);
    z0 = _mm512_aesenc_epi128(z0, z21);
    z1 = _mm512_aesenc_epi128(z1, z21);
    z2 = _mm512_aesenc_epi128(z2, z21);
    z3 = _mm512_aesenc_epi128(z3, z21);
    z0 = _mm512_aesenc_epi128(z0, z22);
    z1 = _mm512_aesenc_epi128(z1, z22);
    z2 = _mm512_aesenc_epi128(z2, z22);
    z3 = _mm512_aesenc_epi128(z3, z22);
    z0 = _mm512_aesenc_epi128(z0, z23);
    z1 = _mm512_aesenc_epi128(z1, z23);
    z2 = _mm512_aesenc_epi128(z2, z23);
    z3 = _mm512_aesenc_epi128(z3, z23);
    z0 = _mm512_aesenc_epi128(z0, z24);
    z1 = _mm512_aesenc_epi128(z1, z24);
    z2 = _mm512_aesenc_epi128(z2, z24);
    z3 = _mm512_aesenc_epi128(z3, z24);
    zf3 = (word32)r8;
    zf4 = 0xb;
    z14 = z25;
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_CTR_encrypt_avx512_256_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z25);
    z1 = _mm512_aesenc_epi128(z1, z25);
    z2 = _mm512_aesenc_epi128(z2, z25);
    z3 = _mm512_aesenc_epi128(z3, z25);
    z0 = _mm512_aesenc_epi128(z0, z26);
    z1 = _mm512_aesenc_epi128(z1, z26);
    z2 = _mm512_aesenc_epi128(z2, z26);
    z3 = _mm512_aesenc_epi128(z3, z26);
    zf5 = (word32)r8;
    zf6 = 0xd;
    z14 = z27;
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_CTR_encrypt_avx512_256_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z27);
    z1 = _mm512_aesenc_epi128(z1, z27);
    z2 = _mm512_aesenc_epi128(z2, z27);
    z3 = _mm512_aesenc_epi128(z3, z27);
    z0 = _mm512_aesenc_epi128(z0, z28);
    z1 = _mm512_aesenc_epi128(z1, z28);
    z2 = _mm512_aesenc_epi128(z2, z28);
    z3 = _mm512_aesenc_epi128(z3, z28);
    z14 = z29;
L_AES_CTR_encrypt_avx512_256_aes_enc_block_last:
    z0 = _mm512_aesenclast_epi128(z0, z14);
    z1 = _mm512_aesenclast_epi128(z1, z14);
    z2 = _mm512_aesenclast_epi128(z2, z14);
    z3 = _mm512_aesenclast_epi128(z3, z14);
    z0 = _mm512_xor_si512(z0, _mm512_loadu_si512((const void*)WC_PR(r11, 0)));
    z1 = _mm512_xor_si512(z1, _mm512_loadu_si512((const void*)WC_PR(r11, 64)));
    z2 = _mm512_xor_si512(z2, _mm512_loadu_si512((const void*)WC_PR(r11, 128)));
    z3 = _mm512_xor_si512(z3, _mm512_loadu_si512((const void*)WC_PR(r11, 192)));
    _mm512_storeu_si512((void*)WC_PW(r12, 0), z0);
    _mm512_storeu_si512((void*)WC_PW(r12, 64), z1);
    _mm512_storeu_si512((void*)WC_PW(r12, 128), z2);
    _mm512_storeu_si512((void*)WC_PW(r12, 192), z3);
    rax = (word32)((word32)rax + 0x100);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CTR_encrypt_avx512_enc_256;
    }
    z7 = _mm512_shuffle_i64x2(z4, z4, 0);
L_AES_CTR_encrypt_avx512_done_256:
    r10 = (word32)((word32)rdx);
    r10 = (word32)((word32)r10 - (word32)rax);
    if (((word32)r10) < (0x80)) {
        goto L_AES_CTR_encrypt_avx512_done_128;
    }
    /* 128 bytes of input */
    z11 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(
        L_aes_ctr_inc_avx512, 128)));
    /* aes_ctr_enc_128 */
    r11 = (word64)(rdi + rax);
    r12 = (word64)(rsi + rax);
    z0 = _mm512_add_epi64(z7, _mm512_loadu_si512((const void*)WC_PR(
        L_aes_ctr_inc_avx512, 0)));
    z9 = z7;
    z9 = _mm512_ternarylogic_epi64(z9, z0, _mm512_loadu_si512((
        const void*)WC_PR(L_aes_ctr_inc_avx512, 0)), 0xb2);
    z9 = _mm512_srli_epi64(z9, 63);
    z9 = _mm512_bslli_epi128(z9, 8);
    z0 = _mm512_add_epi64(z0, z9);
    z0 = _mm512_shuffle_epi8(z0, z8);
    z1 = _mm512_add_epi64(z7, _mm512_loadu_si512((const void*)WC_PR(
        L_aes_ctr_inc_avx512, 64)));
    z9 = z7;
    z9 = _mm512_ternarylogic_epi64(z9, z1, _mm512_loadu_si512((
        const void*)WC_PR(L_aes_ctr_inc_avx512, 64)), 0xb2);
    z9 = _mm512_srli_epi64(z9, 63);
    z9 = _mm512_bslli_epi128(z9, 8);
    z1 = _mm512_add_epi64(z1, z9);
    z1 = _mm512_shuffle_epi8(z1, z8);
    z9 = z7;
    z7 = _mm512_add_epi64(z7, z11);
    z9 = _mm512_ternarylogic_epi64(z9, z7, z11, 0xb2);
    z9 = _mm512_srli_epi64(z9, 63);
    z9 = _mm512_bslli_epi128(z9, 8);
    z7 = _mm512_add_epi64(z7, z9);
    /* aes_enc_block */
    z0 = _mm512_xor_si512(z0, z15);
    z1 = _mm512_xor_si512(z1, z15);
    z0 = _mm512_aesenc_epi128(z0, z16);
    z1 = _mm512_aesenc_epi128(z1, z16);
    z0 = _mm512_aesenc_epi128(z0, z17);
    z1 = _mm512_aesenc_epi128(z1, z17);
    z0 = _mm512_aesenc_epi128(z0, z18);
    z1 = _mm512_aesenc_epi128(z1, z18);
    z0 = _mm512_aesenc_epi128(z0, z19);
    z1 = _mm512_aesenc_epi128(z1, z19);
    z0 = _mm512_aesenc_epi128(z0, z20);
    z1 = _mm512_aesenc_epi128(z1, z20);
    z0 = _mm512_aesenc_epi128(z0, z21);
    z1 = _mm512_aesenc_epi128(z1, z21);
    z0 = _mm512_aesenc_epi128(z0, z22);
    z1 = _mm512_aesenc_epi128(z1, z22);
    z0 = _mm512_aesenc_epi128(z0, z23);
    z1 = _mm512_aesenc_epi128(z1, z23);
    z0 = _mm512_aesenc_epi128(z0, z24);
    z1 = _mm512_aesenc_epi128(z1, z24);
    zf7 = (word32)r8;
    zf8 = 0xb;
    z14 = z25;
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_CTR_encrypt_avx512_128_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z25);
    z1 = _mm512_aesenc_epi128(z1, z25);
    z0 = _mm512_aesenc_epi128(z0, z26);
    z1 = _mm512_aesenc_epi128(z1, z26);
    zf9 = (word32)r8;
    zf10 = 0xd;
    z14 = z27;
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_CTR_encrypt_avx512_128_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z27);
    z1 = _mm512_aesenc_epi128(z1, z27);
    z0 = _mm512_aesenc_epi128(z0, z28);
    z1 = _mm512_aesenc_epi128(z1, z28);
    z14 = z29;
L_AES_CTR_encrypt_avx512_128_aes_enc_block_last:
    z0 = _mm512_aesenclast_epi128(z0, z14);
    z1 = _mm512_aesenclast_epi128(z1, z14);
    z0 = _mm512_xor_si512(z0, _mm512_loadu_si512((const void*)WC_PR(r11, 0)));
    z1 = _mm512_xor_si512(z1, _mm512_loadu_si512((const void*)WC_PR(r11, 64)));
    _mm512_storeu_si512((void*)WC_PW(r12, 0), z0);
    _mm512_storeu_si512((void*)WC_PW(r12, 64), z1);
    rax = (word32)((word32)rax + 0x80);
L_AES_CTR_encrypt_avx512_done_128:
    r10 = (word32)((word32)rdx);
    r10 = (word32)((word32)r10 & 0xffffffc0);
    if (((word32)rax) == ((word32)r10)) {
        goto L_AES_CTR_encrypt_avx512_done_64;
    }
L_AES_CTR_encrypt_avx512_enc_64:
    /* 64 bytes of input */
    /* aes_ctr_enc_64 */
    r11 = (word64)(rdi + rax);
    r12 = (word64)(rsi + rax);
    z0 = _mm512_add_epi64(z7, _mm512_loadu_si512((const void*)WC_PR(
        L_aes_ctr_inc_avx512, 0)));
    z9 = z7;
    z9 = _mm512_ternarylogic_epi64(z9, z0, _mm512_loadu_si512((
        const void*)WC_PR(L_aes_ctr_inc_avx512, 0)), 0xb2);
    z9 = _mm512_srli_epi64(z9, 63);
    z9 = _mm512_bslli_epi128(z9, 8);
    z0 = _mm512_add_epi64(z0, z9);
    z0 = _mm512_shuffle_epi8(z0, z8);
    z9 = z7;
    z7 = _mm512_add_epi64(z7, z12);
    z9 = _mm512_ternarylogic_epi64(z9, z7, z12, 0xb2);
    z9 = _mm512_srli_epi64(z9, 63);
    z9 = _mm512_bslli_epi128(z9, 8);
    z7 = _mm512_add_epi64(z7, z9);
    /* aes_enc_block */
    z0 = _mm512_xor_si512(z0, z15);
    z0 = _mm512_aesenc_epi128(z0, z16);
    z0 = _mm512_aesenc_epi128(z0, z17);
    z0 = _mm512_aesenc_epi128(z0, z18);
    z0 = _mm512_aesenc_epi128(z0, z19);
    z0 = _mm512_aesenc_epi128(z0, z20);
    z0 = _mm512_aesenc_epi128(z0, z21);
    z0 = _mm512_aesenc_epi128(z0, z22);
    z0 = _mm512_aesenc_epi128(z0, z23);
    z0 = _mm512_aesenc_epi128(z0, z24);
    zf11 = (word32)r8;
    zf12 = 0xb;
    z14 = z25;
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_CTR_encrypt_avx512_64_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z25);
    z0 = _mm512_aesenc_epi128(z0, z26);
    zf13 = (word32)r8;
    zf14 = 0xd;
    z14 = z27;
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_CTR_encrypt_avx512_64_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z27);
    z0 = _mm512_aesenc_epi128(z0, z28);
    z14 = z29;
L_AES_CTR_encrypt_avx512_64_aes_enc_block_last:
    z0 = _mm512_aesenclast_epi128(z0, z14);
    z0 = _mm512_xor_si512(z0, _mm512_loadu_si512((const void*)WC_PR(r11, 0)));
    _mm512_storeu_si512((void*)WC_PW(r12, 0), z0);
    rax = (word32)((word32)rax + 0x40);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CTR_encrypt_avx512_enc_64;
    }
L_AES_CTR_encrypt_avx512_done_64:
    r10 = (word32)((word32)rdx);
    r10 = (word32)((word32)r10 - (word32)rax);
    if (((word32)r10) < (0x20)) {
        goto L_AES_CTR_encrypt_avx512_done_32;
    }
    /* 32 bytes of input */
    z4 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(
        L_aes_ctr_inc_avx512, 32)));
    z0 = _mm512_zextsi256_si512(_mm256_add_epi64(_mm512_castsi512_si256(z7),
        _mm256_loadu_si256((const __m256i*)WC_PR(L_aes_ctr_inc_avx512, 0))));
    z9 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z7));
    z9 = _mm512_zextsi256_si512(_mm256_ternarylogic_epi64(
        _mm512_castsi512_si256(z9), _mm512_castsi512_si256(z0),
        _mm256_loadu_si256((const __m256i*)WC_PR(L_aes_ctr_inc_avx512, 0)),
        0xb2));
    z9 = _mm512_zextsi256_si512(_mm256_srli_epi64(_mm512_castsi512_si256(z9),
        63));
    z9 = _mm512_zextsi256_si512(_mm256_bslli_epi128(_mm512_castsi512_si256(z9),
        8));
    z0 = _mm512_zextsi256_si512(_mm256_add_epi64(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z9)));
    z0 = _mm512_zextsi256_si512(_mm256_shuffle_epi8(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z8)));
    z9 = z7;
    z7 = _mm512_add_epi64(z7, z4);
    z9 = _mm512_ternarylogic_epi64(z9, z7, z4, 0xb2);
    z9 = _mm512_srli_epi64(z9, 63);
    z9 = _mm512_bslli_epi128(z9, 8);
    z7 = _mm512_add_epi64(z7, z9);
    /* aes_enc_block */
    z0 = _mm512_zextsi256_si512(_mm256_xor_si256(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z15)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z16)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z17)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z18)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z19)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z20)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z21)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z22)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z23)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z24)));
    zf15 = (word32)r8;
    zf16 = 0xb;
    z14 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z25));
    if ((sword32)(zf15) < (sword32)(zf16)) {
        goto L_AES_CTR_encrypt_avx512_32_aes_enc_block_last;
    }
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z25)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z26)));
    zf17 = (word32)r8;
    zf18 = 0xd;
    z14 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z27));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_CTR_encrypt_avx512_32_aes_enc_block_last;
    }
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z27)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z28)));
    z14 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z29));
L_AES_CTR_encrypt_avx512_32_aes_enc_block_last:
    z0 = _mm512_zextsi256_si512(_mm256_aesenclast_epi128(_mm512_castsi512_si256(
        z0), _mm512_castsi512_si256(z14)));
    r11 = (word64)(rdi + rax);
    z0 = _mm512_zextsi256_si512(_mm256_xor_si256(_mm512_castsi512_si256(z0),
        _mm256_loadu_si256((const __m256i*)WC_PR(r11, 0))));
    r11 = (word64)(rsi + rax);
    _mm256_storeu_si256((__m256i*)WC_PW(r11, 0), _mm512_castsi512_si256(z0));
    rax = (word32)((word32)rax + 0x20);
L_AES_CTR_encrypt_avx512_done_32:
    zf19 = (word32)rax;
    zf20 = (word32)rdx;
    r10 = (word32)((word32)rdx);
    if ((zf19) == (zf20)) {
        goto L_AES_CTR_encrypt_avx512_done_enc;
    }
    r10 = (word32)((word32)r10 & 0xfffffff0);
L_AES_CTR_encrypt_avx512_enc_16:
    /* 16 bytes of input */
    z0 = _mm512_zextsi128_si512(_mm_shuffle_epi8(_mm512_castsi512_si128(z7),
        _mm512_castsi512_si128(z8)));
    z9 = z7;
    z7 = _mm512_add_epi64(z7, z13);
    z9 = _mm512_ternarylogic_epi64(z9, z7, z13, 0xb2);
    z9 = _mm512_srli_epi64(z9, 63);
    z9 = _mm512_bslli_epi128(z9, 8);
    z7 = _mm512_add_epi64(z7, z9);
    /* aes_enc_block */
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0))));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        16)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        32)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        48)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        64)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        80)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        96)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        112)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        128)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        144)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    zf21 = (word32)r8;
    zf22 = 0xb;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        160)));
    if ((sword32)(zf21) < (sword32)(zf22)) {
        goto L_AES_CTR_encrypt_avx512_16_aes_enc_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        176)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    zf23 = (word32)r8;
    zf24 = 0xd;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        192)));
    if ((sword32)(zf23) < (sword32)(zf24)) {
        goto L_AES_CTR_encrypt_avx512_16_aes_enc_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        208)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx,
        224)));
L_AES_CTR_encrypt_avx512_16_aes_enc_block_last:
    z0 = _mm512_zextsi128_si512(_mm_aesenclast_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    r11 = (word64)(rdi + rax);
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm_loadu_si128((const __m128i*)WC_PR(r11, 0))));
    r11 = (word64)(rsi + rax);
    _mm_storeu_si128((__m128i*)WC_PW(r11, 0), _mm512_castsi512_si128(z0));
    rax = (word32)((word32)rax + 0x10);
    if (((word32)rax) < ((word32)r10)) {
        goto L_AES_CTR_encrypt_avx512_enc_16;
    }
L_AES_CTR_encrypt_avx512_done_enc:
    z0 = _mm512_zextsi128_si512(_mm_shuffle_epi8(_mm512_castsi512_si128(z7),
        _mm512_castsi512_si128(z8)));
    _mm_storeu_si128((__m128i*)WC_PW(r9, 0), _mm512_castsi512_si128(z0));
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
