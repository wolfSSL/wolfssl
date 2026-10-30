/* aes_xts_intrin.c */
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
#define _WC_BUILDING_AES_XTS_INTRIN_C

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

#ifdef WOLFSSL_AES_XTS
#ifdef WOLFSSL_X86_64_BUILD
extern WOLFSSL_LOCAL void AES_XTS_init_aesni(const unsigned char* i,
    const unsigned char* key, int nr);
extern WOLFSSL_LOCAL void AES_XTS_encrypt_aesni(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* i,
    const unsigned char* key, const unsigned char* key2, int nr);
extern WOLFSSL_LOCAL void AES_XTS_encrypt_update_aesni(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* key,
    unsigned char* tweak_block, int nr);
extern WOLFSSL_LOCAL void AES_XTS_decrypt_aesni(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* i,
    const unsigned char* key, const unsigned char* key2, int nr);
extern WOLFSSL_LOCAL void AES_XTS_decrypt_update_aesni(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* key,
    unsigned char* tweak_block, int nr);
#ifdef HAVE_INTEL_AVX1
extern WOLFSSL_LOCAL void AES_XTS_init_avx1(const unsigned char* i,
    const unsigned char* key, int nr);
extern WOLFSSL_LOCAL void AES_XTS_encrypt_avx1(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* i,
    const unsigned char* key, const unsigned char* key2, int nr);
extern WOLFSSL_LOCAL void AES_XTS_encrypt_update_avx1(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* key,
    unsigned char* tweak_block, int nr);
extern WOLFSSL_LOCAL void AES_XTS_decrypt_avx1(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* i,
    const unsigned char* key, const unsigned char* key2, int nr);
extern WOLFSSL_LOCAL void AES_XTS_decrypt_update_avx1(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* key,
    unsigned char* tweak_block, int nr);
#endif
#ifdef HAVE_INTEL_VAES
extern WOLFSSL_LOCAL void AES_XTS_init_vaes(const unsigned char* i,
    const unsigned char* key, int nr);
extern WOLFSSL_LOCAL void AES_XTS_encrypt_vaes(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* i,
    const unsigned char* key, const unsigned char* key2, int nr);
extern WOLFSSL_LOCAL void AES_XTS_encrypt_update_vaes(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* key,
    unsigned char* tweak_block, int nr);
extern WOLFSSL_LOCAL void AES_XTS_decrypt_vaes(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* i,
    const unsigned char* key, const unsigned char* key2, int nr);
extern WOLFSSL_LOCAL void AES_XTS_decrypt_update_vaes(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* key,
    unsigned char* tweak_block, int nr);
#endif
#ifdef HAVE_INTEL_AVX512
extern WOLFSSL_LOCAL void AES_XTS_init_avx512(const unsigned char* i,
    const unsigned char* key, int nr);
extern WOLFSSL_LOCAL void AES_XTS_encrypt_avx512(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* i,
    const unsigned char* key, const unsigned char* key2, int nr);
extern WOLFSSL_LOCAL void AES_XTS_encrypt_update_avx512(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* key,
    unsigned char* tweak_block, int nr);
extern WOLFSSL_LOCAL void AES_XTS_decrypt_avx512(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* i,
    const unsigned char* key, const unsigned char* key2, int nr);
extern WOLFSSL_LOCAL void AES_XTS_decrypt_update_avx512(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* key,
    unsigned char* tweak_block, int nr);

#endif
#endif
#endif
#ifdef WOLFSSL_AES_XTS
#ifdef WOLFSSL_X86_64_BUILD
WC_X64I_TARGET("sse2,aes")
WOLFSSL_LOCAL void AES_XTS_init_aesni(const unsigned char* i,
    const unsigned char* key, int nr)
{
    word64 rdi, rsi, rdx;
    __m128i x0, x2, x3 = _mm_setzero_si128();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;

    rdi = (word64)(size_t)i;
    rsi = (word64)(size_t)key;
    rdx = (word64)(word32)nr;

    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 0));
    /* aes_enc_block */
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 0)));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 16));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 32));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 48));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 64));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 80));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 96));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 112));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 128));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 144));
    x0 = _mm_aesenc_si128(x0, x2);
    zf1 = (word32)rdx;
    zf2 = 0xb;
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 160));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_XTS_init_aesni_tweak_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x2);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 176));
    x0 = _mm_aesenc_si128(x0, x3);
    zf3 = (word32)rdx;
    zf4 = 0xd;
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 192));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_init_aesni_tweak_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x2);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 208));
    x0 = _mm_aesenc_si128(x0, x3);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 224));
L_AES_XTS_init_aesni_tweak_aes_enc_block_last:
    x0 = _mm_aesenclast_si128(x0, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rdi, 0), x0);
}

XALIGNED(16) static const word32 L_aes_xts_gc_xts[] WC_X64I_UNUSED = {
    0x00000087, 0x00000001, 0x00000001, 0x00000001,
};

WC_X64I_TARGET("sse2,aes")
WOLFSSL_LOCAL void AES_XTS_encrypt_aesni(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* i,
    const unsigned char* key, const unsigned char* key2, int nr)
{
    word64 rdi, rsi, rax, r12, r8, r9, r10, rsp, r13 = 0, r11 = 0, rcx = 0,
           rdx = 0;
    __m128i x0, x1 = _mm_setzero_si128(), x2 = _mm_setzero_si128(),
            x3 = _mm_setzero_si128(), x4 = _mm_setzero_si128(), x5,
            x6 = _mm_setzero_si128(), x8 = _mm_setzero_si128(),
            x9 = _mm_setzero_si128(), x10 = _mm_setzero_si128(),
            x11 = _mm_setzero_si128(), x12;
    XALIGNED(32) WC_X64I_SLOT stk[8];
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

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rax = (word64)(word32)nbytes;
    r12 = (word64)(size_t)i;
    r8 = (word64)(size_t)key;
    r9 = (word64)(size_t)key2;
    r10 = (word64)(word32)nr;

    rsp = (word64)(size_t)stk + 64;
    rsp = (word64)(rsp - 64);
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(L_aes_xts_gc_xts, 0));
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r12, 0));
    /* aes_enc_block */
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(r9, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 16));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 32));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 48));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 64));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 80));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 96));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 112));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 128));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 144));
    x0 = _mm_aesenc_si128(x0, x5);
    zf1 = (word32)r10;
    zf2 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 160));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_XTS_encrypt_aesni_tweak_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 176));
    x0 = _mm_aesenc_si128(x0, x6);
    zf3 = (word32)r10;
    zf4 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 192));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_encrypt_aesni_tweak_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 208));
    x0 = _mm_aesenc_si128(x0, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 224));
L_AES_XTS_encrypt_aesni_tweak_aes_enc_block_last:
    x0 = _mm_aesenclast_si128(x0, x5);
    r13 = (word32)(0);
    zf5 = (word32)rax;
    zf6 = 0x40;
    r11 = (word32)((word32)rax);
    if ((zf5) < (zf6)) {
        goto L_AES_XTS_encrypt_aesni_done_64;
    }
    r11 = (word32)((word32)r11 & 0xffffffc0);
L_AES_XTS_encrypt_aesni_enc_64:
    /* 64 bytes of input */
    /* aes_enc_64 */
    rcx = (word64)(rdi + r13);
    rdx = (word64)(rsi + r13);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x9 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x10 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x4 = x0;
    x1 = x0;
    x4 = _mm_srai_epi32(x4, 31);
    x1 = _mm_slli_epi32(x1, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x1 = _mm_xor_si128(x1, x4);
    x4 = x1;
    x2 = x1;
    x4 = _mm_srai_epi32(x4, 31);
    x2 = _mm_slli_epi32(x2, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x2 = _mm_xor_si128(x2, x4);
    x4 = x2;
    x3 = x2;
    x4 = _mm_srai_epi32(x4, 31);
    x3 = _mm_slli_epi32(x3, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x3 = _mm_xor_si128(x3, x4);
    x8 = _mm_xor_si128(x8, x0);
    x9 = _mm_xor_si128(x9, x1);
    x10 = _mm_xor_si128(x10, x2);
    x11 = _mm_xor_si128(x11, x3);
    /* aes_enc_block */
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 0));
    x8 = _mm_xor_si128(x8, x4);
    x9 = _mm_xor_si128(x9, x4);
    x10 = _mm_xor_si128(x10, x4);
    x11 = _mm_xor_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    zf7 = (word32)r10;
    zf8 = 0xb;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_XTS_encrypt_aesni_aes_enc_64_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    zf9 = (word32)r10;
    zf10 = 0xd;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_XTS_encrypt_aesni_aes_enc_64_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_XTS_encrypt_aesni_aes_enc_64_aes_enc_block_last:
    x8 = _mm_aesenclast_si128(x8, x4);
    x9 = _mm_aesenclast_si128(x9, x4);
    x10 = _mm_aesenclast_si128(x10, x4);
    x11 = _mm_aesenclast_si128(x11, x4);
    x8 = _mm_xor_si128(x8, x0);
    x9 = _mm_xor_si128(x9, x1);
    x10 = _mm_xor_si128(x10, x2);
    x11 = _mm_xor_si128(x11, x3);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 16), x9);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 32), x10);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 48), x11);
    x4 = x3;
    x0 = x3;
    x4 = _mm_srai_epi32(x4, 31);
    x0 = _mm_slli_epi32(x0, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x0 = _mm_xor_si128(x0, x4);
    r13 = (word32)((word32)r13 + 0x40);
    if (((word32)r13) < ((word32)r11)) {
        goto L_AES_XTS_encrypt_aesni_enc_64;
    }
L_AES_XTS_encrypt_aesni_done_64:
    zf11 = (word32)r13;
    zf12 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf11) == (zf12)) {
        goto L_AES_XTS_encrypt_aesni_done_enc;
    }
    r11 = (word32)((word32)r11 - (word32)r13);
    zf13 = (word32)r11;
    zf14 = 0x10;
    r11 = (word32)((word32)rax);
    if ((zf13) < (zf14)) {
        goto L_AES_XTS_encrypt_aesni_last_15;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    /* 16 bytes of input */
L_AES_XTS_encrypt_aesni_enc_16:
    rcx = (word64)(rdi + r13);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x8 = _mm_xor_si128(x8, x0);
    /* aes_enc_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x8 = _mm_aesenc_si128(x8, x5);
    zf15 = (word32)r10;
    zf16 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf15) < (sword32)(zf16)) {
        goto L_AES_XTS_encrypt_aesni_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x8 = _mm_aesenc_si128(x8, x6);
    zf17 = (word32)r10;
    zf18 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_XTS_encrypt_aesni_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x8 = _mm_aesenc_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_XTS_encrypt_aesni_aes_enc_block_last:
    x8 = _mm_aesenclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x0);
    rcx = (word64)(rsi + r13);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), x8);
    x4 = x0;
    x4 = _mm_srai_epi32(x4, 31);
    x0 = _mm_slli_epi32(x0, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x0 = _mm_xor_si128(x0, x4);
    r13 = (word32)((word32)r13 + 0x10);
    if (((word32)r13) < ((word32)r11)) {
        goto L_AES_XTS_encrypt_aesni_enc_16;
    }
    if (((word32)r13) == ((word32)rax)) {
        goto L_AES_XTS_encrypt_aesni_done_enc;
    }
L_AES_XTS_encrypt_aesni_last_15:
    r13 = (word64)(r13 - 0x10);
    rcx = (word64)(rsi + r13);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    r13 = (word64)(r13 + 0x10);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), x8);
    rdx = (word64)(0);
L_AES_XTS_encrypt_aesni_last_15_byte_loop:
    r11 = (r11 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, rdx)) & 0xff);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, r13)) & 0xff);
    WC_S8(rsi, r13) = (byte)((byte)r11);
    WC_S8(rsp, rdx) = (byte)((byte)rcx);
    r13 = (word32)((word32)r13 + 1);
    rdx = (word32)((word32)rdx + 1);
    if (((word32)r13) < ((word32)rax)) {
        goto L_AES_XTS_encrypt_aesni_last_15_byte_loop;
    }
    r13 = (word64)(r13 - rdx);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsp, 0));
    r13 = (word64)(r13 - 0x10);
    x8 = _mm_xor_si128(x8, x0);
    /* aes_enc_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x8 = _mm_aesenc_si128(x8, x5);
    zf19 = (word32)r10;
    zf20 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf19) < (sword32)(zf20)) {
        goto L_AES_XTS_encrypt_aesni_last_15_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x8 = _mm_aesenc_si128(x8, x6);
    zf21 = (word32)r10;
    zf22 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf21) < (sword32)(zf22)) {
        goto L_AES_XTS_encrypt_aesni_last_15_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x8 = _mm_aesenc_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_XTS_encrypt_aesni_last_15_aes_enc_block_last:
    x8 = _mm_aesenclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x0);
    rcx = (word64)(rsi + r13);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), x8);
L_AES_XTS_encrypt_aesni_done_enc:
    ;
}

WC_X64I_TARGET("sse2,aes")
WOLFSSL_LOCAL void AES_XTS_encrypt_update_aesni(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* key,
    unsigned char* tweak_block, int nr)
{
    word64 rdi, rsi, rax, r10, r8, r9, rsp, r12, r11, rcx = 0, rdx = 0;
    __m128i x0, x1 = _mm_setzero_si128(), x2 = _mm_setzero_si128(),
            x3 = _mm_setzero_si128(), x4 = _mm_setzero_si128(),
            x5 = _mm_setzero_si128(), x6 = _mm_setzero_si128(),
            x8 = _mm_setzero_si128(), x9 = _mm_setzero_si128(),
            x10 = _mm_setzero_si128(), x11 = _mm_setzero_si128(), x12;
    XALIGNED(32) WC_X64I_SLOT stk[8];
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

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rax = (word64)(word32)nbytes;
    r10 = (word64)(size_t)key;
    r8 = (word64)(size_t)tweak_block;
    r9 = (word64)(word32)nr;

    rsp = (word64)(size_t)stk + 64;
    rsp = (word64)(rsp - 64);
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(L_aes_xts_gc_xts, 0));
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 0));
    r12 = (word32)(0);
    zf1 = (word32)rax;
    zf2 = 0x40;
    r11 = (word32)((word32)rax);
    if ((zf1) < (zf2)) {
        goto L_AES_XTS_encrypt_update_aesni_done_64;
    }
    r11 = (word32)((word32)r11 & 0xffffffc0);
L_AES_XTS_encrypt_update_aesni_enc_64:
    /* 64 bytes of input */
    /* aes_enc_64 */
    rcx = (word64)(rdi + r12);
    rdx = (word64)(rsi + r12);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x9 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x10 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x4 = x0;
    x1 = x0;
    x4 = _mm_srai_epi32(x4, 31);
    x1 = _mm_slli_epi32(x1, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x1 = _mm_xor_si128(x1, x4);
    x4 = x1;
    x2 = x1;
    x4 = _mm_srai_epi32(x4, 31);
    x2 = _mm_slli_epi32(x2, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x2 = _mm_xor_si128(x2, x4);
    x4 = x2;
    x3 = x2;
    x4 = _mm_srai_epi32(x4, 31);
    x3 = _mm_slli_epi32(x3, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x3 = _mm_xor_si128(x3, x4);
    x8 = _mm_xor_si128(x8, x0);
    x9 = _mm_xor_si128(x9, x1);
    x10 = _mm_xor_si128(x10, x2);
    x11 = _mm_xor_si128(x11, x3);
    /* aes_enc_block */
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    x8 = _mm_xor_si128(x8, x4);
    x9 = _mm_xor_si128(x9, x4);
    x10 = _mm_xor_si128(x10, x4);
    x11 = _mm_xor_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 64));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 80));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 96));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 112));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 128));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 144));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    zf3 = (word32)r9;
    zf4 = 0xb;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 160));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_encrypt_update_aesni_aes_enc_64_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 176));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    zf5 = (word32)r9;
    zf6 = 0xd;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 192));
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_XTS_encrypt_update_aesni_aes_enc_64_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 208));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 224));
L_AES_XTS_encrypt_update_aesni_aes_enc_64_aes_enc_block_last:
    x8 = _mm_aesenclast_si128(x8, x4);
    x9 = _mm_aesenclast_si128(x9, x4);
    x10 = _mm_aesenclast_si128(x10, x4);
    x11 = _mm_aesenclast_si128(x11, x4);
    x8 = _mm_xor_si128(x8, x0);
    x9 = _mm_xor_si128(x9, x1);
    x10 = _mm_xor_si128(x10, x2);
    x11 = _mm_xor_si128(x11, x3);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 16), x9);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 32), x10);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 48), x11);
    x4 = x3;
    x0 = x3;
    x4 = _mm_srai_epi32(x4, 31);
    x0 = _mm_slli_epi32(x0, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x0 = _mm_xor_si128(x0, x4);
    r12 = (word32)((word32)r12 + 0x40);
    if (((word32)r12) < ((word32)r11)) {
        goto L_AES_XTS_encrypt_update_aesni_enc_64;
    }
L_AES_XTS_encrypt_update_aesni_done_64:
    zf7 = (word32)r12;
    zf8 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf7) == (zf8)) {
        goto L_AES_XTS_encrypt_update_aesni_done_enc;
    }
    r11 = (word32)((word32)r11 - (word32)r12);
    zf9 = (word32)r11;
    zf10 = 0x10;
    r11 = (word32)((word32)rax);
    if ((zf9) < (zf10)) {
        goto L_AES_XTS_encrypt_update_aesni_last_15;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    /* 16 bytes of input */
L_AES_XTS_encrypt_update_aesni_enc_16:
    rcx = (word64)(rdi + r12);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x8 = _mm_xor_si128(x8, x0);
    /* aes_enc_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r10, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 64));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 80));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 96));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 112));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 128));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 144));
    x8 = _mm_aesenc_si128(x8, x5);
    zf11 = (word32)r9;
    zf12 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 160));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_XTS_encrypt_update_aesni_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 176));
    x8 = _mm_aesenc_si128(x8, x6);
    zf13 = (word32)r9;
    zf14 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 192));
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_XTS_encrypt_update_aesni_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 208));
    x8 = _mm_aesenc_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 224));
L_AES_XTS_encrypt_update_aesni_aes_enc_block_last:
    x8 = _mm_aesenclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x0);
    rcx = (word64)(rsi + r12);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), x8);
    x4 = x0;
    x4 = _mm_srai_epi32(x4, 31);
    x0 = _mm_slli_epi32(x0, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x0 = _mm_xor_si128(x0, x4);
    r12 = (word32)((word32)r12 + 0x10);
    if (((word32)r12) < ((word32)r11)) {
        goto L_AES_XTS_encrypt_update_aesni_enc_16;
    }
    if (((word32)r12) == ((word32)rax)) {
        goto L_AES_XTS_encrypt_update_aesni_done_enc;
    }
L_AES_XTS_encrypt_update_aesni_last_15:
    r12 = (word64)(r12 - 0x10);
    rcx = (word64)(rsi + r12);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    r12 = (word64)(r12 + 0x10);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), x8);
    rdx = (word64)(0);
L_AES_XTS_encrypt_update_aesni_last_15_byte_loop:
    r11 = (r11 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, rdx)) & 0xff);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, r12)) & 0xff);
    WC_S8(rsi, r12) = (byte)((byte)r11);
    WC_S8(rsp, rdx) = (byte)((byte)rcx);
    r12 = (word32)((word32)r12 + 1);
    rdx = (word32)((word32)rdx + 1);
    if (((word32)r12) < ((word32)rax)) {
        goto L_AES_XTS_encrypt_update_aesni_last_15_byte_loop;
    }
    r12 = (word64)(r12 - rdx);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsp, 0));
    r12 = (word64)(r12 - 0x10);
    x8 = _mm_xor_si128(x8, x0);
    /* aes_enc_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r10, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 64));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 80));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 96));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 112));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 128));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 144));
    x8 = _mm_aesenc_si128(x8, x5);
    zf15 = (word32)r9;
    zf16 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 160));
    if ((sword32)(zf15) < (sword32)(zf16)) {
        goto L_AES_XTS_encrypt_update_aesni_last_15_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 176));
    x8 = _mm_aesenc_si128(x8, x6);
    zf17 = (word32)r9;
    zf18 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 192));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_XTS_encrypt_update_aesni_last_15_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 208));
    x8 = _mm_aesenc_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 224));
L_AES_XTS_encrypt_update_aesni_last_15_aes_enc_block_last:
    x8 = _mm_aesenclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x0);
    rcx = (word64)(rsi + r12);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), x8);
L_AES_XTS_encrypt_update_aesni_done_enc:
    _mm_storeu_si128((__m128i*)WC_PW(r8, 0), x0);
}

WC_X64I_TARGET("sse2,aes")
WOLFSSL_LOCAL void AES_XTS_decrypt_aesni(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* i,
    const unsigned char* key, const unsigned char* key2, int nr)
{
    word64 rdi, rsi, rax, r12, r8, r9, r10, rsp, r13 = 0, r11 = 0, rcx = 0,
           rdx = 0;
    __m128i x0, x1 = _mm_setzero_si128(), x2 = _mm_setzero_si128(),
            x3 = _mm_setzero_si128(), x4 = _mm_setzero_si128(), x5,
            x6 = _mm_setzero_si128(), x7 = _mm_setzero_si128(),
            x8 = _mm_setzero_si128(), x9 = _mm_setzero_si128(),
            x10 = _mm_setzero_si128(), x11 = _mm_setzero_si128(), x12;
    XALIGNED(32) WC_X64I_SLOT stk[4];
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

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rax = (word64)(word32)nbytes;
    r12 = (word64)(size_t)i;
    r8 = (word64)(size_t)key;
    r9 = (word64)(size_t)key2;
    r10 = (word64)(word32)nr;

    rsp = (word64)(size_t)stk + 32;
    rsp = (word64)(rsp - 16);
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(L_aes_xts_gc_xts, 0));
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r12, 0));
    /* aes_enc_block */
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(r9, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 16));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 32));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 48));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 64));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 80));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 96));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 112));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 128));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 144));
    x0 = _mm_aesenc_si128(x0, x5);
    zf1 = (word32)r10;
    zf2 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 160));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_XTS_decrypt_aesni_tweak_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 176));
    x0 = _mm_aesenc_si128(x0, x6);
    zf3 = (word32)r10;
    zf4 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 192));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_decrypt_aesni_tweak_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 208));
    x0 = _mm_aesenc_si128(x0, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 224));
L_AES_XTS_decrypt_aesni_tweak_aes_enc_block_last:
    x0 = _mm_aesenclast_si128(x0, x5);
    r13 = (word32)(0);
    r11 = (word32)((word32)rax);
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_aesni_mul16_64;
    }
    r11 = (word32)((word32)r11 - 0x10);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_aesni_last_31_start;
    }
L_AES_XTS_decrypt_aesni_mul16_64:
    if (((word32)r11) < (0x40)) {
        goto L_AES_XTS_decrypt_aesni_done_64;
    }
    r11 = (word32)((word32)r11 & 0xffffffc0);
L_AES_XTS_decrypt_aesni_dec_64:
    /* 64 bytes of input */
    /* aes_dec_64 */
    rcx = (word64)(rdi + r13);
    rdx = (word64)(rsi + r13);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x9 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x10 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x4 = x0;
    x1 = x0;
    x4 = _mm_srai_epi32(x4, 31);
    x1 = _mm_slli_epi32(x1, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x1 = _mm_xor_si128(x1, x4);
    x4 = x1;
    x2 = x1;
    x4 = _mm_srai_epi32(x4, 31);
    x2 = _mm_slli_epi32(x2, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x2 = _mm_xor_si128(x2, x4);
    x4 = x2;
    x3 = x2;
    x4 = _mm_srai_epi32(x4, 31);
    x3 = _mm_slli_epi32(x3, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x3 = _mm_xor_si128(x3, x4);
    x8 = _mm_xor_si128(x8, x0);
    x9 = _mm_xor_si128(x9, x1);
    x10 = _mm_xor_si128(x10, x2);
    x11 = _mm_xor_si128(x11, x3);
    /* aes_dec_block */
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 0));
    x8 = _mm_xor_si128(x8, x4);
    x9 = _mm_xor_si128(x9, x4);
    x10 = _mm_xor_si128(x10, x4);
    x11 = _mm_xor_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    zf5 = (word32)r10;
    zf6 = 0xb;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_XTS_decrypt_aesni_aes_dec_64_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    zf7 = (word32)r10;
    zf8 = 0xd;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_XTS_decrypt_aesni_aes_dec_64_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_XTS_decrypt_aesni_aes_dec_64_aes_dec_block_last:
    x8 = _mm_aesdeclast_si128(x8, x4);
    x9 = _mm_aesdeclast_si128(x9, x4);
    x10 = _mm_aesdeclast_si128(x10, x4);
    x11 = _mm_aesdeclast_si128(x11, x4);
    x8 = _mm_xor_si128(x8, x0);
    x9 = _mm_xor_si128(x9, x1);
    x10 = _mm_xor_si128(x10, x2);
    x11 = _mm_xor_si128(x11, x3);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 16), x9);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 32), x10);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 48), x11);
    x4 = x3;
    x0 = x3;
    x4 = _mm_srai_epi32(x4, 31);
    x0 = _mm_slli_epi32(x0, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x0 = _mm_xor_si128(x0, x4);
    r13 = (word32)((word32)r13 + 0x40);
    if (((word32)r13) < ((word32)r11)) {
        goto L_AES_XTS_decrypt_aesni_dec_64;
    }
L_AES_XTS_decrypt_aesni_done_64:
    zf9 = (word32)r13;
    zf10 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf9) == (zf10)) {
        goto L_AES_XTS_decrypt_aesni_done_dec;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_aesni_mul16;
    }
    r11 = (word32)((word32)r11 - 0x10);
    r11 = (word32)((word32)r11 - (word32)r13);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_aesni_last_31_start;
    }
    r11 = (word32)((word32)r11 + (word32)r13);
L_AES_XTS_decrypt_aesni_mul16:
L_AES_XTS_decrypt_aesni_dec_16:
    /* 16 bytes of input */
    rcx = (word64)(rdi + r13);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x8 = _mm_xor_si128(x8, x0);
    /* aes_dec_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x8 = _mm_aesdec_si128(x8, x5);
    zf11 = (word32)r10;
    zf12 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_XTS_decrypt_aesni_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x8 = _mm_aesdec_si128(x8, x6);
    zf13 = (word32)r10;
    zf14 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_XTS_decrypt_aesni_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x8 = _mm_aesdec_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_XTS_decrypt_aesni_aes_dec_block_last:
    x8 = _mm_aesdeclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x0);
    rcx = (word64)(rsi + r13);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), x8);
    x4 = x0;
    x4 = _mm_srai_epi32(x4, 31);
    x0 = _mm_slli_epi32(x0, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x0 = _mm_xor_si128(x0, x4);
    r13 = (word32)((word32)r13 + 0x10);
    if (((word32)r13) < ((word32)r11)) {
        goto L_AES_XTS_decrypt_aesni_dec_16;
    }
    if (((word32)r13) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_aesni_done_dec;
    }
L_AES_XTS_decrypt_aesni_last_31_start:
    x4 = x0;
    x7 = x0;
    x4 = _mm_srai_epi32(x4, 31);
    x7 = _mm_slli_epi32(x7, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x7 = _mm_xor_si128(x7, x4);
    rcx = (word64)(rdi + r13);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x8 = _mm_xor_si128(x8, x7);
    /* aes_dec_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x8 = _mm_aesdec_si128(x8, x5);
    zf15 = (word32)r10;
    zf16 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf15) < (sword32)(zf16)) {
        goto L_AES_XTS_decrypt_aesni_last_31_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x8 = _mm_aesdec_si128(x8, x6);
    zf17 = (word32)r10;
    zf18 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_XTS_decrypt_aesni_last_31_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x8 = _mm_aesdec_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_XTS_decrypt_aesni_last_31_aes_dec_block_last:
    x8 = _mm_aesdeclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x7);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), x8);
    r13 = (word64)(r13 + 0x10);
    rdx = (word64)(0);
L_AES_XTS_decrypt_aesni_last_31_byte_loop:
    r11 = (r11 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, rdx)) & 0xff);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, r13)) & 0xff);
    WC_S8(rsi, r13) = (byte)((byte)r11);
    WC_S8(rsp, rdx) = (byte)((byte)rcx);
    r13 = (word32)((word32)r13 + 1);
    rdx = (word32)((word32)rdx + 1);
    if (((word32)r13) < ((word32)rax)) {
        goto L_AES_XTS_decrypt_aesni_last_31_byte_loop;
    }
    r13 = (word64)(r13 - rdx);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsp, 0));
    x8 = _mm_xor_si128(x8, x0);
    /* aes_dec_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x8 = _mm_aesdec_si128(x8, x5);
    zf19 = (word32)r10;
    zf20 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf19) < (sword32)(zf20)) {
        goto L_AES_XTS_decrypt_aesni_last_31_2_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x8 = _mm_aesdec_si128(x8, x6);
    zf21 = (word32)r10;
    zf22 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf21) < (sword32)(zf22)) {
        goto L_AES_XTS_decrypt_aesni_last_31_2_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x8 = _mm_aesdec_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_XTS_decrypt_aesni_last_31_2_aes_dec_block_last:
    x8 = _mm_aesdeclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x0);
    r13 = (word64)(r13 - 0x10);
    rcx = (word64)(rsi + r13);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), x8);
L_AES_XTS_decrypt_aesni_done_dec:
    ;
}

WC_X64I_TARGET("sse2,aes")
WOLFSSL_LOCAL void AES_XTS_decrypt_update_aesni(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* key,
    unsigned char* tweak_block, int nr)
{
    word64 rdi, rsi, rax, r10, r8, r9, rsp, r12, r11, rcx = 0, rdx = 0;
    __m128i x0, x1 = _mm_setzero_si128(), x2 = _mm_setzero_si128(),
            x3 = _mm_setzero_si128(), x4 = _mm_setzero_si128(),
            x5 = _mm_setzero_si128(), x6 = _mm_setzero_si128(),
            x7 = _mm_setzero_si128(), x8 = _mm_setzero_si128(),
            x9 = _mm_setzero_si128(), x10 = _mm_setzero_si128(),
            x11 = _mm_setzero_si128(), x12;
    XALIGNED(32) WC_X64I_SLOT stk[4];
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

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rax = (word64)(word32)nbytes;
    r10 = (word64)(size_t)key;
    r8 = (word64)(size_t)tweak_block;
    r9 = (word64)(word32)nr;

    rsp = (word64)(size_t)stk + 32;
    rsp = (word64)(rsp - 16);
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(L_aes_xts_gc_xts, 0));
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 0));
    r12 = (word32)(0);
    r11 = (word32)((word32)rax);
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_aesni_mul16_64;
    }
    r11 = (word32)((word32)r11 - 0x10);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_update_aesni_last_31_start;
    }
L_AES_XTS_decrypt_update_aesni_mul16_64:
    if (((word32)r11) < (0x40)) {
        goto L_AES_XTS_decrypt_update_aesni_done_64;
    }
    r11 = (word32)((word32)r11 & 0xffffffc0);
L_AES_XTS_decrypt_update_aesni_dec_64:
    /* 64 bytes of input */
    /* aes_dec_64 */
    rcx = (word64)(rdi + r12);
    rdx = (word64)(rsi + r12);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x9 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x10 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x4 = x0;
    x1 = x0;
    x4 = _mm_srai_epi32(x4, 31);
    x1 = _mm_slli_epi32(x1, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x1 = _mm_xor_si128(x1, x4);
    x4 = x1;
    x2 = x1;
    x4 = _mm_srai_epi32(x4, 31);
    x2 = _mm_slli_epi32(x2, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x2 = _mm_xor_si128(x2, x4);
    x4 = x2;
    x3 = x2;
    x4 = _mm_srai_epi32(x4, 31);
    x3 = _mm_slli_epi32(x3, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x3 = _mm_xor_si128(x3, x4);
    x8 = _mm_xor_si128(x8, x0);
    x9 = _mm_xor_si128(x9, x1);
    x10 = _mm_xor_si128(x10, x2);
    x11 = _mm_xor_si128(x11, x3);
    /* aes_dec_block */
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    x8 = _mm_xor_si128(x8, x4);
    x9 = _mm_xor_si128(x9, x4);
    x10 = _mm_xor_si128(x10, x4);
    x11 = _mm_xor_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 64));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 80));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 96));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 112));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 128));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 144));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    zf1 = (word32)r9;
    zf2 = 0xb;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 160));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_XTS_decrypt_update_aesni_aes_dec_64_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 176));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    zf3 = (word32)r9;
    zf4 = 0xd;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 192));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_decrypt_update_aesni_aes_dec_64_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 208));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 224));
L_AES_XTS_decrypt_update_aesni_aes_dec_64_aes_dec_block_last:
    x8 = _mm_aesdeclast_si128(x8, x4);
    x9 = _mm_aesdeclast_si128(x9, x4);
    x10 = _mm_aesdeclast_si128(x10, x4);
    x11 = _mm_aesdeclast_si128(x11, x4);
    x8 = _mm_xor_si128(x8, x0);
    x9 = _mm_xor_si128(x9, x1);
    x10 = _mm_xor_si128(x10, x2);
    x11 = _mm_xor_si128(x11, x3);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 16), x9);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 32), x10);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 48), x11);
    x4 = x3;
    x0 = x3;
    x4 = _mm_srai_epi32(x4, 31);
    x0 = _mm_slli_epi32(x0, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x0 = _mm_xor_si128(x0, x4);
    r12 = (word32)((word32)r12 + 0x40);
    if (((word32)r12) < ((word32)r11)) {
        goto L_AES_XTS_decrypt_update_aesni_dec_64;
    }
L_AES_XTS_decrypt_update_aesni_done_64:
    zf5 = (word32)r12;
    zf6 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf5) == (zf6)) {
        goto L_AES_XTS_decrypt_update_aesni_done_dec;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_aesni_mul16;
    }
    r11 = (word32)((word32)r11 - 0x10);
    r11 = (word32)((word32)r11 - (word32)r12);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_update_aesni_last_31_start;
    }
    r11 = (word32)((word32)r11 + (word32)r12);
L_AES_XTS_decrypt_update_aesni_mul16:
L_AES_XTS_decrypt_update_aesni_dec_16:
    /* 16 bytes of input */
    rcx = (word64)(rdi + r12);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x8 = _mm_xor_si128(x8, x0);
    /* aes_dec_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r10, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 64));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 80));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 96));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 112));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 128));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 144));
    x8 = _mm_aesdec_si128(x8, x5);
    zf7 = (word32)r9;
    zf8 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 160));
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_XTS_decrypt_update_aesni_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 176));
    x8 = _mm_aesdec_si128(x8, x6);
    zf9 = (word32)r9;
    zf10 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 192));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_XTS_decrypt_update_aesni_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 208));
    x8 = _mm_aesdec_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 224));
L_AES_XTS_decrypt_update_aesni_aes_dec_block_last:
    x8 = _mm_aesdeclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x0);
    rcx = (word64)(rsi + r12);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), x8);
    x4 = x0;
    x4 = _mm_srai_epi32(x4, 31);
    x0 = _mm_slli_epi32(x0, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x0 = _mm_xor_si128(x0, x4);
    r12 = (word32)((word32)r12 + 0x10);
    if (((word32)r12) < ((word32)r11)) {
        goto L_AES_XTS_decrypt_update_aesni_dec_16;
    }
    if (((word32)r12) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_aesni_done_dec;
    }
L_AES_XTS_decrypt_update_aesni_last_31_start:
    x4 = x0;
    x7 = x0;
    x4 = _mm_srai_epi32(x4, 31);
    x7 = _mm_slli_epi32(x7, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x7 = _mm_xor_si128(x7, x4);
    rcx = (word64)(rdi + r12);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x8 = _mm_xor_si128(x8, x7);
    /* aes_dec_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r10, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 64));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 80));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 96));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 112));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 128));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 144));
    x8 = _mm_aesdec_si128(x8, x5);
    zf11 = (word32)r9;
    zf12 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 160));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_XTS_decrypt_update_aesni_last_31_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 176));
    x8 = _mm_aesdec_si128(x8, x6);
    zf13 = (word32)r9;
    zf14 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 192));
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_XTS_decrypt_update_aesni_last_31_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 208));
    x8 = _mm_aesdec_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 224));
L_AES_XTS_decrypt_update_aesni_last_31_aes_dec_block_last:
    x8 = _mm_aesdeclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x7);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), x8);
    r12 = (word64)(r12 + 0x10);
    rdx = (word64)(0);
L_AES_XTS_decrypt_update_aesni_last_31_byte_loop:
    r11 = (r11 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, rdx)) & 0xff);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, r12)) & 0xff);
    WC_S8(rsi, r12) = (byte)((byte)r11);
    WC_S8(rsp, rdx) = (byte)((byte)rcx);
    r12 = (word32)((word32)r12 + 1);
    rdx = (word32)((word32)rdx + 1);
    if (((word32)r12) < ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_aesni_last_31_byte_loop;
    }
    r12 = (word64)(r12 - rdx);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsp, 0));
    x8 = _mm_xor_si128(x8, x0);
    /* aes_dec_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r10, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 64));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 80));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 96));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 112));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 128));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 144));
    x8 = _mm_aesdec_si128(x8, x5);
    zf15 = (word32)r9;
    zf16 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 160));
    if ((sword32)(zf15) < (sword32)(zf16)) {
        goto L_AES_XTS_decrypt_update_aesni_last_31_2_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 176));
    x8 = _mm_aesdec_si128(x8, x6);
    zf17 = (word32)r9;
    zf18 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 192));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_XTS_decrypt_update_aesni_last_31_2_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 208));
    x8 = _mm_aesdec_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 224));
L_AES_XTS_decrypt_update_aesni_last_31_2_aes_dec_block_last:
    x8 = _mm_aesdeclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x0);
    r12 = (word64)(r12 - 0x10);
    rcx = (word64)(rsi + r12);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), x8);
L_AES_XTS_decrypt_update_aesni_done_dec:
    _mm_storeu_si128((__m128i*)WC_PW(r8, 0), x0);
}

#ifdef HAVE_INTEL_AVX1
WC_X64I_TARGET("aes,avx")
WOLFSSL_LOCAL void AES_XTS_init_avx1(const unsigned char* i,
    const unsigned char* key, int nr)
{
    word64 rdi, rsi, rdx;
    __m128i x0, x2, x3 = _mm_setzero_si128();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;

    rdi = (word64)(size_t)i;
    rsi = (word64)(size_t)key;
    rdx = (word64)(word32)nr;

    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 0));
    /* aes_enc_block */
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 0)));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 16));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 32));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 48));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 64));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 80));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 96));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 112));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 128));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 144));
    x0 = _mm_aesenc_si128(x0, x2);
    zf1 = (word32)rdx;
    zf2 = 0xb;
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 160));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_XTS_init_avx1_tweak_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x2);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 176));
    x0 = _mm_aesenc_si128(x0, x3);
    zf3 = (word32)rdx;
    zf4 = 0xd;
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 192));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_init_avx1_tweak_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x2);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 208));
    x0 = _mm_aesenc_si128(x0, x3);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 224));
L_AES_XTS_init_avx1_tweak_aes_enc_block_last:
    x0 = _mm_aesenclast_si128(x0, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rdi, 0), x0);
}

XALIGNED(16) static const word32 L_avx1_aes_xts_gc_xts[] WC_X64I_UNUSED = {
    0x00000087, 0x00000001, 0x00000001, 0x00000001,
};

WC_X64I_TARGET("aes,avx")
WOLFSSL_LOCAL void AES_XTS_encrypt_avx1(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* i,
    const unsigned char* key, const unsigned char* key2, int nr)
{
    word64 rdi, rsi, rax, r12, r8, r9, r10, rsp, r13 = 0, r11 = 0, rcx = 0,
           rdx = 0;
    __m128i x0, x1 = _mm_setzero_si128(), x2 = _mm_setzero_si128(),
            x3 = _mm_setzero_si128(), x4 = _mm_setzero_si128(), x5,
            x6 = _mm_setzero_si128(), x8 = _mm_setzero_si128(),
            x9 = _mm_setzero_si128(), x10 = _mm_setzero_si128(),
            x11 = _mm_setzero_si128(), x12;
    XALIGNED(32) WC_X64I_SLOT stk[8];
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

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rax = (word64)(word32)nbytes;
    r12 = (word64)(size_t)i;
    r8 = (word64)(size_t)key;
    r9 = (word64)(size_t)key2;
    r10 = (word64)(word32)nr;

    rsp = (word64)(size_t)stk + 64;
    rsp = (word64)(rsp - 64);
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(L_avx1_aes_xts_gc_xts, 0));
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r12, 0));
    /* aes_enc_block */
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(r9, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 16));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 32));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 48));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 64));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 80));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 96));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 112));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 128));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 144));
    x0 = _mm_aesenc_si128(x0, x5);
    zf1 = (word32)r10;
    zf2 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 160));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_XTS_encrypt_avx1_tweak_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 176));
    x0 = _mm_aesenc_si128(x0, x6);
    zf3 = (word32)r10;
    zf4 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 192));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_encrypt_avx1_tweak_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 208));
    x0 = _mm_aesenc_si128(x0, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 224));
L_AES_XTS_encrypt_avx1_tweak_aes_enc_block_last:
    x0 = _mm_aesenclast_si128(x0, x5);
    r13 = (word32)(0);
    zf5 = (word32)rax;
    zf6 = 0x40;
    r11 = (word32)((word32)rax);
    if ((zf5) < (zf6)) {
        goto L_AES_XTS_encrypt_avx1_done_64;
    }
    r11 = (word32)((word32)r11 & 0xffffffc0);
L_AES_XTS_encrypt_avx1_enc_64:
    /* 64 bytes of input */
    /* aes_enc_64 */
    rcx = (word64)(rdi + r13);
    rdx = (word64)(rsi + r13);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x9 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x10 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x4 = _mm_srai_epi32(x0, 31);
    x1 = _mm_slli_epi32(x0, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x1 = _mm_xor_si128(x1, x4);
    x4 = _mm_srai_epi32(x1, 31);
    x2 = _mm_slli_epi32(x1, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x2 = _mm_xor_si128(x2, x4);
    x4 = _mm_srai_epi32(x2, 31);
    x3 = _mm_slli_epi32(x2, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x3 = _mm_xor_si128(x3, x4);
    x8 = _mm_xor_si128(x8, x0);
    x9 = _mm_xor_si128(x9, x1);
    x10 = _mm_xor_si128(x10, x2);
    x11 = _mm_xor_si128(x11, x3);
    /* aes_enc_block */
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 0));
    x8 = _mm_xor_si128(x8, x4);
    x9 = _mm_xor_si128(x9, x4);
    x10 = _mm_xor_si128(x10, x4);
    x11 = _mm_xor_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    zf7 = (word32)r10;
    zf8 = 0xb;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_XTS_encrypt_avx1_aes_enc_64_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    zf9 = (word32)r10;
    zf10 = 0xd;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_XTS_encrypt_avx1_aes_enc_64_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_XTS_encrypt_avx1_aes_enc_64_aes_enc_block_last:
    x8 = _mm_aesenclast_si128(x8, x4);
    x9 = _mm_aesenclast_si128(x9, x4);
    x10 = _mm_aesenclast_si128(x10, x4);
    x11 = _mm_aesenclast_si128(x11, x4);
    x8 = _mm_xor_si128(x8, x0);
    x9 = _mm_xor_si128(x9, x1);
    x10 = _mm_xor_si128(x10, x2);
    x11 = _mm_xor_si128(x11, x3);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 16), x9);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 32), x10);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 48), x11);
    x4 = _mm_srai_epi32(x3, 31);
    x0 = _mm_slli_epi32(x3, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x0 = _mm_xor_si128(x0, x4);
    r13 = (word32)((word32)r13 + 0x40);
    if (((word32)r13) < ((word32)r11)) {
        goto L_AES_XTS_encrypt_avx1_enc_64;
    }
L_AES_XTS_encrypt_avx1_done_64:
    zf11 = (word32)r13;
    zf12 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf11) == (zf12)) {
        goto L_AES_XTS_encrypt_avx1_done_enc;
    }
    r11 = (word32)((word32)r11 - (word32)r13);
    zf13 = (word32)r11;
    zf14 = 0x10;
    r11 = (word32)((word32)rax);
    if ((zf13) < (zf14)) {
        goto L_AES_XTS_encrypt_avx1_last_15;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    /* 16 bytes of input */
L_AES_XTS_encrypt_avx1_enc_16:
    rcx = (word64)(rdi + r13);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x8 = _mm_xor_si128(x8, x0);
    /* aes_enc_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x8 = _mm_aesenc_si128(x8, x5);
    zf15 = (word32)r10;
    zf16 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf15) < (sword32)(zf16)) {
        goto L_AES_XTS_encrypt_avx1_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x8 = _mm_aesenc_si128(x8, x6);
    zf17 = (word32)r10;
    zf18 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_XTS_encrypt_avx1_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x8 = _mm_aesenc_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_XTS_encrypt_avx1_aes_enc_block_last:
    x8 = _mm_aesenclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x0);
    rcx = (word64)(rsi + r13);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), x8);
    x4 = _mm_srai_epi32(x0, 31);
    x0 = _mm_slli_epi32(x0, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x0 = _mm_xor_si128(x0, x4);
    r13 = (word32)((word32)r13 + 0x10);
    if (((word32)r13) < ((word32)r11)) {
        goto L_AES_XTS_encrypt_avx1_enc_16;
    }
    if (((word32)r13) == ((word32)rax)) {
        goto L_AES_XTS_encrypt_avx1_done_enc;
    }
L_AES_XTS_encrypt_avx1_last_15:
    r13 = (word64)(r13 - 0x10);
    rcx = (word64)(rsi + r13);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    r13 = (word64)(r13 + 0x10);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), x8);
    rdx = (word64)(0);
L_AES_XTS_encrypt_avx1_last_15_byte_loop:
    r11 = (r11 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, rdx)) & 0xff);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, r13)) & 0xff);
    WC_S8(rsi, r13) = (byte)((byte)r11);
    WC_S8(rsp, rdx) = (byte)((byte)rcx);
    r13 = (word32)((word32)r13 + 1);
    rdx = (word32)((word32)rdx + 1);
    if (((word32)r13) < ((word32)rax)) {
        goto L_AES_XTS_encrypt_avx1_last_15_byte_loop;
    }
    r13 = (word64)(r13 - rdx);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsp, 0));
    r13 = (word64)(r13 - 0x10);
    x8 = _mm_xor_si128(x8, x0);
    /* aes_enc_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x8 = _mm_aesenc_si128(x8, x5);
    zf19 = (word32)r10;
    zf20 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf19) < (sword32)(zf20)) {
        goto L_AES_XTS_encrypt_avx1_last_15_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x8 = _mm_aesenc_si128(x8, x6);
    zf21 = (word32)r10;
    zf22 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf21) < (sword32)(zf22)) {
        goto L_AES_XTS_encrypt_avx1_last_15_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x8 = _mm_aesenc_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_XTS_encrypt_avx1_last_15_aes_enc_block_last:
    x8 = _mm_aesenclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x0);
    rcx = (word64)(rsi + r13);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), x8);
L_AES_XTS_encrypt_avx1_done_enc:
    ;
}

WC_X64I_TARGET("aes,avx")
WOLFSSL_LOCAL void AES_XTS_encrypt_update_avx1(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* key,
    unsigned char* tweak_block, int nr)
{
    word64 rdi, rsi, rax, r10, r8, r9, rsp, r12, r11, rcx = 0, rdx = 0;
    __m128i x0, x1 = _mm_setzero_si128(), x2 = _mm_setzero_si128(),
            x3 = _mm_setzero_si128(), x4 = _mm_setzero_si128(),
            x5 = _mm_setzero_si128(), x6 = _mm_setzero_si128(),
            x8 = _mm_setzero_si128(), x9 = _mm_setzero_si128(),
            x10 = _mm_setzero_si128(), x11 = _mm_setzero_si128(), x12;
    XALIGNED(32) WC_X64I_SLOT stk[8];
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

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rax = (word64)(word32)nbytes;
    r10 = (word64)(size_t)key;
    r8 = (word64)(size_t)tweak_block;
    r9 = (word64)(word32)nr;

    rsp = (word64)(size_t)stk + 64;
    rsp = (word64)(rsp - 64);
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(L_avx1_aes_xts_gc_xts, 0));
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 0));
    r12 = (word32)(0);
    zf1 = (word32)rax;
    zf2 = 0x40;
    r11 = (word32)((word32)rax);
    if ((zf1) < (zf2)) {
        goto L_AES_XTS_encrypt_update_avx1_done_64;
    }
    r11 = (word32)((word32)r11 & 0xffffffc0);
L_AES_XTS_encrypt_update_avx1_enc_64:
    /* 64 bytes of input */
    /* aes_enc_64 */
    rcx = (word64)(rdi + r12);
    rdx = (word64)(rsi + r12);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x9 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x10 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x4 = _mm_srai_epi32(x0, 31);
    x1 = _mm_slli_epi32(x0, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x1 = _mm_xor_si128(x1, x4);
    x4 = _mm_srai_epi32(x1, 31);
    x2 = _mm_slli_epi32(x1, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x2 = _mm_xor_si128(x2, x4);
    x4 = _mm_srai_epi32(x2, 31);
    x3 = _mm_slli_epi32(x2, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x3 = _mm_xor_si128(x3, x4);
    x8 = _mm_xor_si128(x8, x0);
    x9 = _mm_xor_si128(x9, x1);
    x10 = _mm_xor_si128(x10, x2);
    x11 = _mm_xor_si128(x11, x3);
    /* aes_enc_block */
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    x8 = _mm_xor_si128(x8, x4);
    x9 = _mm_xor_si128(x9, x4);
    x10 = _mm_xor_si128(x10, x4);
    x11 = _mm_xor_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 64));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 80));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 96));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 112));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 128));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 144));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    zf3 = (word32)r9;
    zf4 = 0xb;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 160));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_encrypt_update_avx1_aes_enc_64_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 176));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    zf5 = (word32)r9;
    zf6 = 0xd;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 192));
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_XTS_encrypt_update_avx1_aes_enc_64_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 208));
    x8 = _mm_aesenc_si128(x8, x4);
    x9 = _mm_aesenc_si128(x9, x4);
    x10 = _mm_aesenc_si128(x10, x4);
    x11 = _mm_aesenc_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 224));
L_AES_XTS_encrypt_update_avx1_aes_enc_64_aes_enc_block_last:
    x8 = _mm_aesenclast_si128(x8, x4);
    x9 = _mm_aesenclast_si128(x9, x4);
    x10 = _mm_aesenclast_si128(x10, x4);
    x11 = _mm_aesenclast_si128(x11, x4);
    x8 = _mm_xor_si128(x8, x0);
    x9 = _mm_xor_si128(x9, x1);
    x10 = _mm_xor_si128(x10, x2);
    x11 = _mm_xor_si128(x11, x3);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 16), x9);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 32), x10);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 48), x11);
    x4 = _mm_srai_epi32(x3, 31);
    x0 = _mm_slli_epi32(x3, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x0 = _mm_xor_si128(x0, x4);
    r12 = (word32)((word32)r12 + 0x40);
    if (((word32)r12) < ((word32)r11)) {
        goto L_AES_XTS_encrypt_update_avx1_enc_64;
    }
L_AES_XTS_encrypt_update_avx1_done_64:
    zf7 = (word32)r12;
    zf8 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf7) == (zf8)) {
        goto L_AES_XTS_encrypt_update_avx1_done_enc;
    }
    r11 = (word32)((word32)r11 - (word32)r12);
    zf9 = (word32)r11;
    zf10 = 0x10;
    r11 = (word32)((word32)rax);
    if ((zf9) < (zf10)) {
        goto L_AES_XTS_encrypt_update_avx1_last_15;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    /* 16 bytes of input */
L_AES_XTS_encrypt_update_avx1_enc_16:
    rcx = (word64)(rdi + r12);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x8 = _mm_xor_si128(x8, x0);
    /* aes_enc_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r10, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 64));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 80));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 96));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 112));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 128));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 144));
    x8 = _mm_aesenc_si128(x8, x5);
    zf11 = (word32)r9;
    zf12 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 160));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_XTS_encrypt_update_avx1_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 176));
    x8 = _mm_aesenc_si128(x8, x6);
    zf13 = (word32)r9;
    zf14 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 192));
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_XTS_encrypt_update_avx1_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 208));
    x8 = _mm_aesenc_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 224));
L_AES_XTS_encrypt_update_avx1_aes_enc_block_last:
    x8 = _mm_aesenclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x0);
    rcx = (word64)(rsi + r12);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), x8);
    x4 = _mm_srai_epi32(x0, 31);
    x0 = _mm_slli_epi32(x0, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x0 = _mm_xor_si128(x0, x4);
    r12 = (word32)((word32)r12 + 0x10);
    if (((word32)r12) < ((word32)r11)) {
        goto L_AES_XTS_encrypt_update_avx1_enc_16;
    }
    if (((word32)r12) == ((word32)rax)) {
        goto L_AES_XTS_encrypt_update_avx1_done_enc;
    }
L_AES_XTS_encrypt_update_avx1_last_15:
    r12 = (word64)(r12 - 0x10);
    rcx = (word64)(rsi + r12);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    r12 = (word64)(r12 + 0x10);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), x8);
    rdx = (word64)(0);
L_AES_XTS_encrypt_update_avx1_last_15_byte_loop:
    r11 = (r11 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, rdx)) & 0xff);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, r12)) & 0xff);
    WC_S8(rsi, r12) = (byte)((byte)r11);
    WC_S8(rsp, rdx) = (byte)((byte)rcx);
    r12 = (word32)((word32)r12 + 1);
    rdx = (word32)((word32)rdx + 1);
    if (((word32)r12) < ((word32)rax)) {
        goto L_AES_XTS_encrypt_update_avx1_last_15_byte_loop;
    }
    r12 = (word64)(r12 - rdx);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsp, 0));
    r12 = (word64)(r12 - 0x10);
    x8 = _mm_xor_si128(x8, x0);
    /* aes_enc_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r10, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 64));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 80));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 96));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 112));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 128));
    x8 = _mm_aesenc_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 144));
    x8 = _mm_aesenc_si128(x8, x5);
    zf15 = (word32)r9;
    zf16 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 160));
    if ((sword32)(zf15) < (sword32)(zf16)) {
        goto L_AES_XTS_encrypt_update_avx1_last_15_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 176));
    x8 = _mm_aesenc_si128(x8, x6);
    zf17 = (word32)r9;
    zf18 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 192));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_XTS_encrypt_update_avx1_last_15_aes_enc_block_last;
    }
    x8 = _mm_aesenc_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 208));
    x8 = _mm_aesenc_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 224));
L_AES_XTS_encrypt_update_avx1_last_15_aes_enc_block_last:
    x8 = _mm_aesenclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x0);
    rcx = (word64)(rsi + r12);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), x8);
L_AES_XTS_encrypt_update_avx1_done_enc:
    _mm_storeu_si128((__m128i*)WC_PW(r8, 0), x0);
}

WC_X64I_TARGET("aes,avx")
WOLFSSL_LOCAL void AES_XTS_decrypt_avx1(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* i,
    const unsigned char* key, const unsigned char* key2, int nr)
{
    word64 rdi, rsi, rax, r12, r8, r9, r10, rsp, r13 = 0, r11 = 0, rcx = 0,
           rdx = 0;
    __m128i x0, x1 = _mm_setzero_si128(), x2 = _mm_setzero_si128(),
            x3 = _mm_setzero_si128(), x4 = _mm_setzero_si128(), x5,
            x6 = _mm_setzero_si128(), x7 = _mm_setzero_si128(),
            x8 = _mm_setzero_si128(), x9 = _mm_setzero_si128(),
            x10 = _mm_setzero_si128(), x11 = _mm_setzero_si128(), x12;
    XALIGNED(32) WC_X64I_SLOT stk[4];
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

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rax = (word64)(word32)nbytes;
    r12 = (word64)(size_t)i;
    r8 = (word64)(size_t)key;
    r9 = (word64)(size_t)key2;
    r10 = (word64)(word32)nr;

    rsp = (word64)(size_t)stk + 32;
    rsp = (word64)(rsp - 16);
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(L_avx1_aes_xts_gc_xts, 0));
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r12, 0));
    /* aes_enc_block */
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(r9, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 16));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 32));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 48));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 64));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 80));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 96));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 112));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 128));
    x0 = _mm_aesenc_si128(x0, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 144));
    x0 = _mm_aesenc_si128(x0, x5);
    zf1 = (word32)r10;
    zf2 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 160));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_XTS_decrypt_avx1_tweak_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 176));
    x0 = _mm_aesenc_si128(x0, x6);
    zf3 = (word32)r10;
    zf4 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 192));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_decrypt_avx1_tweak_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 208));
    x0 = _mm_aesenc_si128(x0, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r9, 224));
L_AES_XTS_decrypt_avx1_tweak_aes_enc_block_last:
    x0 = _mm_aesenclast_si128(x0, x5);
    r13 = (word32)(0);
    r11 = (word32)((word32)rax);
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_avx1_mul16_64;
    }
    r11 = (word32)((word32)r11 - 0x10);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_avx1_last_31_start;
    }
L_AES_XTS_decrypt_avx1_mul16_64:
    if (((word32)r11) < (0x40)) {
        goto L_AES_XTS_decrypt_avx1_done_64;
    }
    r11 = (word32)((word32)r11 & 0xffffffc0);
L_AES_XTS_decrypt_avx1_dec_64:
    /* 64 bytes of input */
    /* aes_dec_64 */
    rcx = (word64)(rdi + r13);
    rdx = (word64)(rsi + r13);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x9 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x10 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x4 = _mm_srai_epi32(x0, 31);
    x1 = _mm_slli_epi32(x0, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x1 = _mm_xor_si128(x1, x4);
    x4 = _mm_srai_epi32(x1, 31);
    x2 = _mm_slli_epi32(x1, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x2 = _mm_xor_si128(x2, x4);
    x4 = _mm_srai_epi32(x2, 31);
    x3 = _mm_slli_epi32(x2, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x3 = _mm_xor_si128(x3, x4);
    x8 = _mm_xor_si128(x8, x0);
    x9 = _mm_xor_si128(x9, x1);
    x10 = _mm_xor_si128(x10, x2);
    x11 = _mm_xor_si128(x11, x3);
    /* aes_dec_block */
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 0));
    x8 = _mm_xor_si128(x8, x4);
    x9 = _mm_xor_si128(x9, x4);
    x10 = _mm_xor_si128(x10, x4);
    x11 = _mm_xor_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    zf5 = (word32)r10;
    zf6 = 0xb;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_XTS_decrypt_avx1_aes_dec_64_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    zf7 = (word32)r10;
    zf8 = 0xd;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_XTS_decrypt_avx1_aes_dec_64_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_XTS_decrypt_avx1_aes_dec_64_aes_dec_block_last:
    x8 = _mm_aesdeclast_si128(x8, x4);
    x9 = _mm_aesdeclast_si128(x9, x4);
    x10 = _mm_aesdeclast_si128(x10, x4);
    x11 = _mm_aesdeclast_si128(x11, x4);
    x8 = _mm_xor_si128(x8, x0);
    x9 = _mm_xor_si128(x9, x1);
    x10 = _mm_xor_si128(x10, x2);
    x11 = _mm_xor_si128(x11, x3);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 16), x9);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 32), x10);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 48), x11);
    x4 = _mm_srai_epi32(x3, 31);
    x0 = _mm_slli_epi32(x3, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x0 = _mm_xor_si128(x0, x4);
    r13 = (word32)((word32)r13 + 0x40);
    if (((word32)r13) < ((word32)r11)) {
        goto L_AES_XTS_decrypt_avx1_dec_64;
    }
L_AES_XTS_decrypt_avx1_done_64:
    zf9 = (word32)r13;
    zf10 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf9) == (zf10)) {
        goto L_AES_XTS_decrypt_avx1_done_dec;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_avx1_mul16;
    }
    r11 = (word32)((word32)r11 - 0x10);
    r11 = (word32)((word32)r11 - (word32)r13);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_avx1_last_31_start;
    }
    r11 = (word32)((word32)r11 + (word32)r13);
L_AES_XTS_decrypt_avx1_mul16:
L_AES_XTS_decrypt_avx1_dec_16:
    /* 16 bytes of input */
    rcx = (word64)(rdi + r13);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x8 = _mm_xor_si128(x8, x0);
    /* aes_dec_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x8 = _mm_aesdec_si128(x8, x5);
    zf11 = (word32)r10;
    zf12 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_XTS_decrypt_avx1_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x8 = _mm_aesdec_si128(x8, x6);
    zf13 = (word32)r10;
    zf14 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_XTS_decrypt_avx1_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x8 = _mm_aesdec_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_XTS_decrypt_avx1_aes_dec_block_last:
    x8 = _mm_aesdeclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x0);
    rcx = (word64)(rsi + r13);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), x8);
    x4 = _mm_srai_epi32(x0, 31);
    x0 = _mm_slli_epi32(x0, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x0 = _mm_xor_si128(x0, x4);
    r13 = (word32)((word32)r13 + 0x10);
    if (((word32)r13) < ((word32)r11)) {
        goto L_AES_XTS_decrypt_avx1_dec_16;
    }
    if (((word32)r13) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_avx1_done_dec;
    }
L_AES_XTS_decrypt_avx1_last_31_start:
    x4 = _mm_srai_epi32(x0, 31);
    x7 = _mm_slli_epi32(x0, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x7 = _mm_xor_si128(x7, x4);
    rcx = (word64)(rdi + r13);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x8 = _mm_xor_si128(x8, x7);
    /* aes_dec_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x8 = _mm_aesdec_si128(x8, x5);
    zf15 = (word32)r10;
    zf16 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf15) < (sword32)(zf16)) {
        goto L_AES_XTS_decrypt_avx1_last_31_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x8 = _mm_aesdec_si128(x8, x6);
    zf17 = (word32)r10;
    zf18 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_XTS_decrypt_avx1_last_31_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x8 = _mm_aesdec_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_XTS_decrypt_avx1_last_31_aes_dec_block_last:
    x8 = _mm_aesdeclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x7);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), x8);
    r13 = (word64)(r13 + 0x10);
    rdx = (word64)(0);
L_AES_XTS_decrypt_avx1_last_31_byte_loop:
    r11 = (r11 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, rdx)) & 0xff);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, r13)) & 0xff);
    WC_S8(rsi, r13) = (byte)((byte)r11);
    WC_S8(rsp, rdx) = (byte)((byte)rcx);
    r13 = (word32)((word32)r13 + 1);
    rdx = (word32)((word32)rdx + 1);
    if (((word32)r13) < ((word32)rax)) {
        goto L_AES_XTS_decrypt_avx1_last_31_byte_loop;
    }
    r13 = (word64)(r13 - rdx);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsp, 0));
    x8 = _mm_xor_si128(x8, x0);
    /* aes_dec_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 16));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 32));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 48));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 64));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 80));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 96));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 112));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 128));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 144));
    x8 = _mm_aesdec_si128(x8, x5);
    zf19 = (word32)r10;
    zf20 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 160));
    if ((sword32)(zf19) < (sword32)(zf20)) {
        goto L_AES_XTS_decrypt_avx1_last_31_2_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 176));
    x8 = _mm_aesdec_si128(x8, x6);
    zf21 = (word32)r10;
    zf22 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 192));
    if ((sword32)(zf21) < (sword32)(zf22)) {
        goto L_AES_XTS_decrypt_avx1_last_31_2_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 208));
    x8 = _mm_aesdec_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 224));
L_AES_XTS_decrypt_avx1_last_31_2_aes_dec_block_last:
    x8 = _mm_aesdeclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x0);
    r13 = (word64)(r13 - 0x10);
    rcx = (word64)(rsi + r13);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), x8);
L_AES_XTS_decrypt_avx1_done_dec:
    ;
}

WC_X64I_TARGET("aes,avx")
WOLFSSL_LOCAL void AES_XTS_decrypt_update_avx1(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* key,
    unsigned char* tweak_block, int nr)
{
    word64 rdi, rsi, rax, r10, r8, r9, rsp, r12, r11, rcx = 0, rdx = 0;
    __m128i x0, x1 = _mm_setzero_si128(), x2 = _mm_setzero_si128(),
            x3 = _mm_setzero_si128(), x4 = _mm_setzero_si128(),
            x5 = _mm_setzero_si128(), x6 = _mm_setzero_si128(),
            x7 = _mm_setzero_si128(), x8 = _mm_setzero_si128(),
            x9 = _mm_setzero_si128(), x10 = _mm_setzero_si128(),
            x11 = _mm_setzero_si128(), x12;
    XALIGNED(32) WC_X64I_SLOT stk[4];
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

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rax = (word64)(word32)nbytes;
    r10 = (word64)(size_t)key;
    r8 = (word64)(size_t)tweak_block;
    r9 = (word64)(word32)nr;

    rsp = (word64)(size_t)stk + 32;
    rsp = (word64)(rsp - 16);
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(L_avx1_aes_xts_gc_xts, 0));
    x0 = _mm_loadu_si128((const __m128i*)WC_PR(r8, 0));
    r12 = (word32)(0);
    r11 = (word32)((word32)rax);
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_avx1_mul16_64;
    }
    r11 = (word32)((word32)r11 - 0x10);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_update_avx1_last_31_start;
    }
L_AES_XTS_decrypt_update_avx1_mul16_64:
    if (((word32)r11) < (0x40)) {
        goto L_AES_XTS_decrypt_update_avx1_done_64;
    }
    r11 = (word32)((word32)r11 & 0xffffffc0);
L_AES_XTS_decrypt_update_avx1_dec_64:
    /* 64 bytes of input */
    /* aes_dec_64 */
    rcx = (word64)(rdi + r12);
    rdx = (word64)(rsi + r12);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x9 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 16));
    x10 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 32));
    x11 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 48));
    x4 = _mm_srai_epi32(x0, 31);
    x1 = _mm_slli_epi32(x0, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x1 = _mm_xor_si128(x1, x4);
    x4 = _mm_srai_epi32(x1, 31);
    x2 = _mm_slli_epi32(x1, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x2 = _mm_xor_si128(x2, x4);
    x4 = _mm_srai_epi32(x2, 31);
    x3 = _mm_slli_epi32(x2, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x3 = _mm_xor_si128(x3, x4);
    x8 = _mm_xor_si128(x8, x0);
    x9 = _mm_xor_si128(x9, x1);
    x10 = _mm_xor_si128(x10, x2);
    x11 = _mm_xor_si128(x11, x3);
    /* aes_dec_block */
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 0));
    x8 = _mm_xor_si128(x8, x4);
    x9 = _mm_xor_si128(x9, x4);
    x10 = _mm_xor_si128(x10, x4);
    x11 = _mm_xor_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 64));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 80));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 96));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 112));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 128));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 144));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    zf1 = (word32)r9;
    zf2 = 0xb;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 160));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_XTS_decrypt_update_avx1_aes_dec_64_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 176));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    zf3 = (word32)r9;
    zf4 = 0xd;
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 192));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_decrypt_update_avx1_aes_dec_64_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 208));
    x8 = _mm_aesdec_si128(x8, x4);
    x9 = _mm_aesdec_si128(x9, x4);
    x10 = _mm_aesdec_si128(x10, x4);
    x11 = _mm_aesdec_si128(x11, x4);
    x4 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 224));
L_AES_XTS_decrypt_update_avx1_aes_dec_64_aes_dec_block_last:
    x8 = _mm_aesdeclast_si128(x8, x4);
    x9 = _mm_aesdeclast_si128(x9, x4);
    x10 = _mm_aesdeclast_si128(x10, x4);
    x11 = _mm_aesdeclast_si128(x11, x4);
    x8 = _mm_xor_si128(x8, x0);
    x9 = _mm_xor_si128(x9, x1);
    x10 = _mm_xor_si128(x10, x2);
    x11 = _mm_xor_si128(x11, x3);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 0), x8);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 16), x9);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 32), x10);
    _mm_storeu_si128((__m128i*)WC_PW(rdx, 48), x11);
    x4 = _mm_srai_epi32(x3, 31);
    x0 = _mm_slli_epi32(x3, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x0 = _mm_xor_si128(x0, x4);
    r12 = (word32)((word32)r12 + 0x40);
    if (((word32)r12) < ((word32)r11)) {
        goto L_AES_XTS_decrypt_update_avx1_dec_64;
    }
L_AES_XTS_decrypt_update_avx1_done_64:
    zf5 = (word32)r12;
    zf6 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf5) == (zf6)) {
        goto L_AES_XTS_decrypt_update_avx1_done_dec;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_avx1_mul16;
    }
    r11 = (word32)((word32)r11 - 0x10);
    r11 = (word32)((word32)r11 - (word32)r12);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_update_avx1_last_31_start;
    }
    r11 = (word32)((word32)r11 + (word32)r12);
L_AES_XTS_decrypt_update_avx1_mul16:
L_AES_XTS_decrypt_update_avx1_dec_16:
    /* 16 bytes of input */
    rcx = (word64)(rdi + r12);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x8 = _mm_xor_si128(x8, x0);
    /* aes_dec_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r10, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 64));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 80));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 96));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 112));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 128));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 144));
    x8 = _mm_aesdec_si128(x8, x5);
    zf7 = (word32)r9;
    zf8 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 160));
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_XTS_decrypt_update_avx1_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 176));
    x8 = _mm_aesdec_si128(x8, x6);
    zf9 = (word32)r9;
    zf10 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 192));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_XTS_decrypt_update_avx1_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 208));
    x8 = _mm_aesdec_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 224));
L_AES_XTS_decrypt_update_avx1_aes_dec_block_last:
    x8 = _mm_aesdeclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x0);
    rcx = (word64)(rsi + r12);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), x8);
    x4 = _mm_srai_epi32(x0, 31);
    x0 = _mm_slli_epi32(x0, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x0 = _mm_xor_si128(x0, x4);
    r12 = (word32)((word32)r12 + 0x10);
    if (((word32)r12) < ((word32)r11)) {
        goto L_AES_XTS_decrypt_update_avx1_dec_16;
    }
    if (((word32)r12) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_avx1_done_dec;
    }
L_AES_XTS_decrypt_update_avx1_last_31_start:
    x4 = _mm_srai_epi32(x0, 31);
    x7 = _mm_slli_epi32(x0, 1);
    x4 = _mm_shuffle_epi32(x4, 0x93);
    x4 = _mm_and_si128(x4, x12);
    x7 = _mm_xor_si128(x7, x4);
    rcx = (word64)(rdi + r12);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rcx, 0));
    x8 = _mm_xor_si128(x8, x7);
    /* aes_dec_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r10, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 64));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 80));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 96));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 112));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 128));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 144));
    x8 = _mm_aesdec_si128(x8, x5);
    zf11 = (word32)r9;
    zf12 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 160));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_XTS_decrypt_update_avx1_last_31_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 176));
    x8 = _mm_aesdec_si128(x8, x6);
    zf13 = (word32)r9;
    zf14 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 192));
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_XTS_decrypt_update_avx1_last_31_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 208));
    x8 = _mm_aesdec_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 224));
L_AES_XTS_decrypt_update_avx1_last_31_aes_dec_block_last:
    x8 = _mm_aesdeclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x7);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), x8);
    r12 = (word64)(r12 + 0x10);
    rdx = (word64)(0);
L_AES_XTS_decrypt_update_avx1_last_31_byte_loop:
    r11 = (r11 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, rdx)) & 0xff);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, r12)) & 0xff);
    WC_S8(rsi, r12) = (byte)((byte)r11);
    WC_S8(rsp, rdx) = (byte)((byte)rcx);
    r12 = (word32)((word32)r12 + 1);
    rdx = (word32)((word32)rdx + 1);
    if (((word32)r12) < ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_avx1_last_31_byte_loop;
    }
    r12 = (word64)(r12 - rdx);
    x8 = _mm_loadu_si128((const __m128i*)WC_PR(rsp, 0));
    x8 = _mm_xor_si128(x8, x0);
    /* aes_dec_block */
    x8 = _mm_xor_si128(x8, _mm_loadu_si128((const __m128i*)WC_PR(r10, 0)));
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 16));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 32));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 48));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 64));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 80));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 96));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 112));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 128));
    x8 = _mm_aesdec_si128(x8, x5);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 144));
    x8 = _mm_aesdec_si128(x8, x5);
    zf15 = (word32)r9;
    zf16 = 0xb;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 160));
    if ((sword32)(zf15) < (sword32)(zf16)) {
        goto L_AES_XTS_decrypt_update_avx1_last_31_2_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 176));
    x8 = _mm_aesdec_si128(x8, x6);
    zf17 = (word32)r9;
    zf18 = 0xd;
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 192));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_XTS_decrypt_update_avx1_last_31_2_aes_dec_block_last;
    }
    x8 = _mm_aesdec_si128(x8, x5);
    x6 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 208));
    x8 = _mm_aesdec_si128(x8, x6);
    x5 = _mm_loadu_si128((const __m128i*)WC_PR(r10, 224));
L_AES_XTS_decrypt_update_avx1_last_31_2_aes_dec_block_last:
    x8 = _mm_aesdeclast_si128(x8, x5);
    x8 = _mm_xor_si128(x8, x0);
    r12 = (word64)(r12 - 0x10);
    rcx = (word64)(rsi + r12);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), x8);
L_AES_XTS_decrypt_update_avx1_done_dec:
    _mm_storeu_si128((__m128i*)WC_PW(r8, 0), x0);
}

#endif /* HAVE_INTEL_AVX1 */
#ifdef HAVE_INTEL_VAES
WC_X64I_TARGET("aes,avx")
WOLFSSL_LOCAL void AES_XTS_init_vaes(const unsigned char* i,
    const unsigned char* key, int nr)
{
    word64 rdi, rsi, rdx;
    __m128i x0, x2, x3 = _mm_setzero_si128();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;

    rdi = (word64)(size_t)i;
    rsi = (word64)(size_t)key;
    rdx = (word64)(word32)nr;

    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 0));
    /* aes_enc_block */
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 0)));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 16));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 32));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 48));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 64));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 80));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 96));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 112));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 128));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 144));
    x0 = _mm_aesenc_si128(x0, x2);
    zf1 = (word32)rdx;
    zf2 = 0xb;
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 160));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_XTS_init_vaes_tweak_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x2);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 176));
    x0 = _mm_aesenc_si128(x0, x3);
    zf3 = (word32)rdx;
    zf4 = 0xd;
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 192));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_init_vaes_tweak_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x2);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 208));
    x0 = _mm_aesenc_si128(x0, x3);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 224));
L_AES_XTS_init_vaes_tweak_aes_enc_block_last:
    x0 = _mm_aesenclast_si128(x0, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rdi, 0), x0);
}

XALIGNED(16) static const word32 L_vaes_aes_xts_gc_xts[] WC_X64I_UNUSED = {
    0x00000087, 0x00000000, 0x00000001, 0x00000000,
};

XALIGNED(16) static const word32 L_vaes_aes_xts_poly[] WC_X64I_UNUSED = {
    0x00000087, 0x00000000, 0x00000000, 0x00000000,
};

XALIGNED(16) static const word32 L_vaes_aes_xts_shl[] WC_X64I_UNUSED = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000001, 0x00000000, 0x00000001, 0x00000000,
};

XALIGNED(16) static const word32 L_vaes_aes_xts_shr[] WC_X64I_UNUSED = {
    0x00000040, 0x00000000, 0x00000040, 0x00000000,
    0x0000003f, 0x00000000, 0x0000003f, 0x00000000,
};

WC_X64I_TARGET("aes,vaes,pclmul,vpclmulqdq,avx2")
WOLFSSL_LOCAL void AES_XTS_encrypt_vaes(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* i,
    const unsigned char* key, const unsigned char* key2, int nr)
{
    word64 rdi, rsi, rax, r12, r8, r9, r10, rsp, r13 = 0, r11 = 0, rcx = 0,
           rdx = 0;
    __m128i x12;
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y4 = _mm256_setzero_si256(), y5, y6 = _mm256_setzero_si256(),
            y7 = _mm256_setzero_si256(), y8, y9 = _mm256_setzero_si256(),
            y10 = _mm256_setzero_si256(), y13, y14, y15;
    XALIGNED(32) WC_X64I_SLOT stk[8];
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
    word32 zf25;
    word32 zf26;
    word32 zf27;
    word32 zf28;
    word32 zf29;
    word32 zf30;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rax = (word64)(word32)nbytes;
    r12 = (word64)(size_t)i;
    r8 = (word64)(size_t)key;
    r9 = (word64)(size_t)key2;
    r10 = (word64)(word32)nr;

    rsp = (word64)(size_t)stk + 64;
    rsp = (word64)(rsp - 64);
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(L_vaes_aes_xts_gc_xts, 0));
    y13 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(
        L_vaes_aes_xts_poly, 0)));
    y14 = _mm256_loadu_si256((const __m256i*)WC_PR(L_vaes_aes_xts_shl, 0));
    y15 = _mm256_loadu_si256((const __m256i*)WC_PR(L_vaes_aes_xts_shr, 0));
    y8 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    /* aes_enc_block */
    y8 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y8),
        _mm_loadu_si128((const __m128i*)WC_PR(r9, 0))));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9, 16)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9, 32)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9, 48)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9, 64)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9, 80)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9, 96)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        112)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        128)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        144)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    zf1 = (word32)r10;
    zf2 = 0xb;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        160)));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_XTS_encrypt_vaes_tweak_aes_enc_block_last;
    }
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        176)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y6)));
    zf3 = (word32)r10;
    zf4 = 0xd;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        192)));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_encrypt_vaes_tweak_aes_enc_block_last;
    }
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        208)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y6)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        224)));
L_AES_XTS_encrypt_vaes_tweak_aes_enc_block_last:
    y8 = _mm256_zextsi128_si256(_mm_aesenclast_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    r13 = (word32)(0);
    if (((word32)rax) < (0x20)) {
        goto L_AES_XTS_encrypt_vaes_done_128;
    }
    zf5 = (word32)rax;
    zf6 = 0x80;
    r11 = (word32)((word32)rax);
    if ((zf5) < (zf6)) {
        goto L_AES_XTS_encrypt_vaes_done_128;
    }
    r11 = (word32)((word32)r11 & 0xffffff80);
    y5 = _mm256_permute2x128_si256(y8, y8, 0);
    y6 = _mm256_srlv_epi64(y5, y15);
    y7 = _mm256_clmulepi64_epi128(y6, y13, 1);
    y6 = _mm256_bslli_epi128(y6, 8);
    y4 = _mm256_sllv_epi64(y5, y14);
    y4 = _mm256_xor_si256(y4, y7);
    y4 = _mm256_xor_si256(y4, y6);
    y9 = _mm256_srli_epi64(y4, 62);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y5 = _mm256_slli_epi64(y4, 2);
    y5 = _mm256_xor_si256(y5, y10);
    y5 = _mm256_xor_si256(y5, y9);
    y9 = _mm256_srli_epi64(y5, 62);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y6 = _mm256_slli_epi64(y5, 2);
    y6 = _mm256_xor_si256(y6, y10);
    y6 = _mm256_xor_si256(y6, y9);
    y9 = _mm256_srli_epi64(y6, 62);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y7 = _mm256_slli_epi64(y6, 2);
    y7 = _mm256_xor_si256(y7, y10);
    y7 = _mm256_xor_si256(y7, y9);
L_AES_XTS_encrypt_vaes_enc_128:
    /* 128 bytes of input */
    /* aes_enc_128 */
    rcx = (word64)(rdi + r13);
    rdx = (word64)(rsi + r13);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 32));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 64));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 96));
    /* aes_enc_block */
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        0)));
    y0 = _mm256_xor_si256(y0, y4);
    y0 = _mm256_xor_si256(y0, y9);
    y1 = _mm256_xor_si256(y1, y5);
    y1 = _mm256_xor_si256(y1, y9);
    y2 = _mm256_xor_si256(y2, y6);
    y2 = _mm256_xor_si256(y2, y9);
    y3 = _mm256_xor_si256(y3, y7);
    y3 = _mm256_xor_si256(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        16)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        32)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        48)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        64)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        80)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        96)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    zf7 = (word32)r10;
    zf8 = 0xb;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_XTS_encrypt_vaes_aes_enc_128_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    zf9 = (word32)r10;
    zf10 = 0xd;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_XTS_encrypt_vaes_aes_enc_128_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_XTS_encrypt_vaes_aes_enc_128_aes_enc_block_last:
    y0 = _mm256_aesenclast_epi128(y0, y9);
    y1 = _mm256_aesenclast_epi128(y1, y9);
    y2 = _mm256_aesenclast_epi128(y2, y9);
    y3 = _mm256_aesenclast_epi128(y3, y9);
    y0 = _mm256_xor_si256(y0, y4);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 0), y0);
    y9 = _mm256_srli_epi64(y4, 56);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y4 = _mm256_slli_epi64(y4, 8);
    y4 = _mm256_xor_si256(y4, y10);
    y4 = _mm256_xor_si256(y4, y9);
    y1 = _mm256_xor_si256(y1, y5);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 32), y1);
    y9 = _mm256_srli_epi64(y5, 56);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y5 = _mm256_slli_epi64(y5, 8);
    y5 = _mm256_xor_si256(y5, y10);
    y5 = _mm256_xor_si256(y5, y9);
    y2 = _mm256_xor_si256(y2, y6);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 64), y2);
    y9 = _mm256_srli_epi64(y6, 56);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y6 = _mm256_slli_epi64(y6, 8);
    y6 = _mm256_xor_si256(y6, y10);
    y6 = _mm256_xor_si256(y6, y9);
    y3 = _mm256_xor_si256(y3, y7);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 96), y3);
    y9 = _mm256_srli_epi64(y7, 56);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y7 = _mm256_slli_epi64(y7, 8);
    y7 = _mm256_xor_si256(y7, y10);
    y7 = _mm256_xor_si256(y7, y9);
    r13 = (word32)((word32)r13 + 0x80);
    if (((word32)r13) < ((word32)r11)) {
        goto L_AES_XTS_encrypt_vaes_enc_128;
    }
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y4, 0));
L_AES_XTS_encrypt_vaes_done_128:
    r11 = (word32)((word32)rax);
    r11 = (word32)((word32)r11 & 0xffffffc0);
    if (((word32)r13) == ((word32)r11)) {
        goto L_AES_XTS_encrypt_vaes_done_64;
    }
    /* 64 bytes of input */
    /* aes_enc_64 */
    rcx = (word64)(rdi + r13);
    rdx = (word64)(rsi + r13);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 32));
    y5 = _mm256_permute2x128_si256(y8, y8, 0);
    y6 = _mm256_srlv_epi64(y5, y15);
    y7 = _mm256_clmulepi64_epi128(y6, y13, 1);
    y6 = _mm256_bslli_epi128(y6, 8);
    y4 = _mm256_sllv_epi64(y5, y14);
    y4 = _mm256_xor_si256(y4, y7);
    y4 = _mm256_xor_si256(y4, y6);
    y9 = _mm256_srli_epi64(y4, 62);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y5 = _mm256_slli_epi64(y4, 2);
    y5 = _mm256_xor_si256(y5, y10);
    y5 = _mm256_xor_si256(y5, y9);
    /* aes_enc_block */
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        0)));
    y0 = _mm256_xor_si256(y0, y4);
    y0 = _mm256_xor_si256(y0, y9);
    y1 = _mm256_xor_si256(y1, y5);
    y1 = _mm256_xor_si256(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        16)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        32)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        48)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        64)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        80)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        96)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    zf11 = (word32)r10;
    zf12 = 0xb;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_XTS_encrypt_vaes_aes_enc_64_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    zf13 = (word32)r10;
    zf14 = 0xd;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_XTS_encrypt_vaes_aes_enc_64_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_XTS_encrypt_vaes_aes_enc_64_aes_enc_block_last:
    y0 = _mm256_aesenclast_epi128(y0, y9);
    y1 = _mm256_aesenclast_epi128(y1, y9);
    y0 = _mm256_xor_si256(y0, y4);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 0), y0);
    y1 = _mm256_xor_si256(y1, y5);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 32), y1);
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y5, 1));
    y9 = _mm256_zextsi128_si256(_mm_shuffle_epi32(_mm256_castsi256_si128(y8),
        0x13));
    y8 = _mm256_zextsi128_si256(_mm_add_epi64(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y8)));
    y9 = _mm256_zextsi128_si256(_mm_srai_epi32(_mm256_castsi256_si128(y9), 31));
    y9 = _mm256_zextsi128_si256(_mm_and_si128(_mm256_castsi256_si128(y9), x12));
    y8 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y9)));
    r13 = (word32)((word32)r13 + 0x40);
L_AES_XTS_encrypt_vaes_done_64:
    r11 = (word32)((word32)rax);
    r11 = (word32)((word32)r11 & 0xffffffe0);
    if (((word32)r13) == ((word32)r11)) {
        goto L_AES_XTS_encrypt_vaes_done_32;
    }
    /* 32 bytes of input */
    /* aes_enc_32 */
    rcx = (word64)(rdi + r13);
    rdx = (word64)(rsi + r13);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 0));
    y5 = _mm256_permute2x128_si256(y8, y8, 0);
    y6 = _mm256_srlv_epi64(y5, y15);
    y7 = _mm256_clmulepi64_epi128(y6, y13, 1);
    y6 = _mm256_bslli_epi128(y6, 8);
    y4 = _mm256_sllv_epi64(y5, y14);
    y4 = _mm256_xor_si256(y4, y7);
    y4 = _mm256_xor_si256(y4, y6);
    /* aes_enc_block */
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        0)));
    y0 = _mm256_xor_si256(y0, y4);
    y0 = _mm256_xor_si256(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        16)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        32)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        48)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        64)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        80)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        96)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    zf15 = (word32)r10;
    zf16 = 0xb;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf15) < (sword32)(zf16)) {
        goto L_AES_XTS_encrypt_vaes_aes_enc_32_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    zf17 = (word32)r10;
    zf18 = 0xd;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_XTS_encrypt_vaes_aes_enc_32_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_XTS_encrypt_vaes_aes_enc_32_aes_enc_block_last:
    y0 = _mm256_aesenclast_epi128(y0, y9);
    y0 = _mm256_xor_si256(y0, y4);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 0), y0);
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y4, 1));
    y9 = _mm256_zextsi128_si256(_mm_shuffle_epi32(_mm256_castsi256_si128(y8),
        0x13));
    y8 = _mm256_zextsi128_si256(_mm_add_epi64(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y8)));
    y9 = _mm256_zextsi128_si256(_mm_srai_epi32(_mm256_castsi256_si128(y9), 31));
    y9 = _mm256_zextsi128_si256(_mm_and_si128(_mm256_castsi256_si128(y9), x12));
    y8 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y9)));
    r13 = (word32)((word32)r13 + 0x20);
L_AES_XTS_encrypt_vaes_done_32:
    zf19 = (word32)r13;
    zf20 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf19) == (zf20)) {
        goto L_AES_XTS_encrypt_vaes_done_enc;
    }
    r11 = (word32)((word32)r11 - (word32)r13);
    zf21 = (word32)r11;
    zf22 = 0x10;
    r11 = (word32)((word32)rax);
    if ((zf21) < (zf22)) {
        goto L_AES_XTS_encrypt_vaes_last_15;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    /* 16 bytes of input */
L_AES_XTS_encrypt_vaes_enc_16:
    rcx = (word64)(rdi + r13);
    y0 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    /* aes_enc_block */
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm_loadu_si128((const __m128i*)WC_PR(r8, 0))));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 16)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 32)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 48)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 64)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 80)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 96)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    zf23 = (word32)r10;
    zf24 = 0xb;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf23) < (sword32)(zf24)) {
        goto L_AES_XTS_encrypt_vaes_aes_enc_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    zf25 = (word32)r10;
    zf26 = 0xd;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf25) < (sword32)(zf26)) {
        goto L_AES_XTS_encrypt_vaes_aes_enc_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_XTS_encrypt_vaes_aes_enc_block_last:
    y0 = _mm256_zextsi128_si256(_mm_aesenclast_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    rcx = (word64)(rsi + r13);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), _mm256_castsi256_si128(y0));
    y4 = _mm256_zextsi128_si256(_mm_shuffle_epi32(_mm256_castsi256_si128(y8),
        0x13));
    y8 = _mm256_zextsi128_si256(_mm_add_epi64(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y8)));
    y4 = _mm256_zextsi128_si256(_mm_srai_epi32(_mm256_castsi256_si128(y4), 31));
    y4 = _mm256_zextsi128_si256(_mm_and_si128(_mm256_castsi256_si128(y4), x12));
    y8 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y4)));
    r13 = (word32)((word32)r13 + 0x10);
    if (((word32)r13) < ((word32)r11)) {
        goto L_AES_XTS_encrypt_vaes_enc_16;
    }
    if (((word32)r13) == ((word32)rax)) {
        goto L_AES_XTS_encrypt_vaes_done_enc;
    }
L_AES_XTS_encrypt_vaes_last_15:
    r13 = (word64)(r13 - 0x10);
    rcx = (word64)(rsi + r13);
    y0 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    r13 = (word64)(r13 + 0x10);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), _mm256_castsi256_si128(y0));
    rdx = (word64)(0);
L_AES_XTS_encrypt_vaes_last_15_byte_loop:
    r11 = (r11 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, rdx)) & 0xff);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, r13)) & 0xff);
    WC_S8(rsi, r13) = (byte)((byte)r11);
    WC_S8(rsp, rdx) = (byte)((byte)rcx);
    r13 = (word32)((word32)r13 + 1);
    rdx = (word32)((word32)rdx + 1);
    if (((word32)r13) < ((word32)rax)) {
        goto L_AES_XTS_encrypt_vaes_last_15_byte_loop;
    }
    r13 = (word64)(r13 - rdx);
    y0 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rsp, 0)));
    r13 = (word64)(r13 - 0x10);
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    /* aes_enc_block */
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm_loadu_si128((const __m128i*)WC_PR(r8, 0))));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 16)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 32)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 48)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 64)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 80)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 96)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    zf27 = (word32)r10;
    zf28 = 0xb;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf27) < (sword32)(zf28)) {
        goto L_AES_XTS_encrypt_vaes_last_15_aes_enc_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    zf29 = (word32)r10;
    zf30 = 0xd;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf29) < (sword32)(zf30)) {
        goto L_AES_XTS_encrypt_vaes_last_15_aes_enc_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_XTS_encrypt_vaes_last_15_aes_enc_block_last:
    y0 = _mm256_zextsi128_si256(_mm_aesenclast_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    rcx = (word64)(rsi + r13);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), _mm256_castsi256_si128(y0));
L_AES_XTS_encrypt_vaes_done_enc:
    ;
}

WC_X64I_TARGET("aes,vaes,pclmul,vpclmulqdq,avx2")
WOLFSSL_LOCAL void AES_XTS_encrypt_update_vaes(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* key,
    unsigned char* tweak_block, int nr)
{
    word64 rdi, rsi, rax, r10, r8, r9, rsp, r12, r11 = 0, rcx = 0, rdx = 0;
    __m128i x12;
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y4 = _mm256_setzero_si256(), y5 = _mm256_setzero_si256(),
            y6 = _mm256_setzero_si256(), y7 = _mm256_setzero_si256(), y8,
            y9 = _mm256_setzero_si256(), y10 = _mm256_setzero_si256(), y13,
            y14, y15;
    XALIGNED(32) WC_X64I_SLOT stk[8];
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
    word32 zf25;
    word32 zf26;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rax = (word64)(word32)nbytes;
    r10 = (word64)(size_t)key;
    r8 = (word64)(size_t)tweak_block;
    r9 = (word64)(word32)nr;

    rsp = (word64)(size_t)stk + 64;
    rsp = (word64)(rsp - 64);
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(L_vaes_aes_xts_gc_xts, 0));
    y13 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(
        L_vaes_aes_xts_poly, 0)));
    y14 = _mm256_loadu_si256((const __m256i*)WC_PR(L_vaes_aes_xts_shl, 0));
    y15 = _mm256_loadu_si256((const __m256i*)WC_PR(L_vaes_aes_xts_shr, 0));
    y8 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    r12 = (word32)(0);
    if (((word32)rax) < (0x20)) {
        goto L_AES_XTS_encrypt_update_vaes_done_128;
    }
    zf1 = (word32)rax;
    zf2 = 0x80;
    r11 = (word32)((word32)rax);
    if ((zf1) < (zf2)) {
        goto L_AES_XTS_encrypt_update_vaes_done_128;
    }
    r11 = (word32)((word32)r11 & 0xffffff80);
    y5 = _mm256_permute2x128_si256(y8, y8, 0);
    y6 = _mm256_srlv_epi64(y5, y15);
    y7 = _mm256_clmulepi64_epi128(y6, y13, 1);
    y6 = _mm256_bslli_epi128(y6, 8);
    y4 = _mm256_sllv_epi64(y5, y14);
    y4 = _mm256_xor_si256(y4, y7);
    y4 = _mm256_xor_si256(y4, y6);
    y9 = _mm256_srli_epi64(y4, 62);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y5 = _mm256_slli_epi64(y4, 2);
    y5 = _mm256_xor_si256(y5, y10);
    y5 = _mm256_xor_si256(y5, y9);
    y9 = _mm256_srli_epi64(y5, 62);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y6 = _mm256_slli_epi64(y5, 2);
    y6 = _mm256_xor_si256(y6, y10);
    y6 = _mm256_xor_si256(y6, y9);
    y9 = _mm256_srli_epi64(y6, 62);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y7 = _mm256_slli_epi64(y6, 2);
    y7 = _mm256_xor_si256(y7, y10);
    y7 = _mm256_xor_si256(y7, y9);
L_AES_XTS_encrypt_update_vaes_enc_128:
    /* 128 bytes of input */
    /* aes_enc_128 */
    rcx = (word64)(rdi + r12);
    rdx = (word64)(rsi + r12);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 32));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 64));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 96));
    /* aes_enc_block */
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        0)));
    y0 = _mm256_xor_si256(y0, y4);
    y0 = _mm256_xor_si256(y0, y9);
    y1 = _mm256_xor_si256(y1, y5);
    y1 = _mm256_xor_si256(y1, y9);
    y2 = _mm256_xor_si256(y2, y6);
    y2 = _mm256_xor_si256(y2, y9);
    y3 = _mm256_xor_si256(y3, y7);
    y3 = _mm256_xor_si256(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        16)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        32)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        48)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        64)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        80)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        96)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        112)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        128)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        144)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    zf3 = (word32)r9;
    zf4 = 0xb;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        160)));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_encrypt_update_vaes_aes_enc_128_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        176)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    zf5 = (word32)r9;
    zf6 = 0xd;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        192)));
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_XTS_encrypt_update_vaes_aes_enc_128_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        208)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y2 = _mm256_aesenc_epi128(y2, y9);
    y3 = _mm256_aesenc_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        224)));
L_AES_XTS_encrypt_update_vaes_aes_enc_128_aes_enc_block_last:
    y0 = _mm256_aesenclast_epi128(y0, y9);
    y1 = _mm256_aesenclast_epi128(y1, y9);
    y2 = _mm256_aesenclast_epi128(y2, y9);
    y3 = _mm256_aesenclast_epi128(y3, y9);
    y0 = _mm256_xor_si256(y0, y4);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 0), y0);
    y9 = _mm256_srli_epi64(y4, 56);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y4 = _mm256_slli_epi64(y4, 8);
    y4 = _mm256_xor_si256(y4, y10);
    y4 = _mm256_xor_si256(y4, y9);
    y1 = _mm256_xor_si256(y1, y5);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 32), y1);
    y9 = _mm256_srli_epi64(y5, 56);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y5 = _mm256_slli_epi64(y5, 8);
    y5 = _mm256_xor_si256(y5, y10);
    y5 = _mm256_xor_si256(y5, y9);
    y2 = _mm256_xor_si256(y2, y6);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 64), y2);
    y9 = _mm256_srli_epi64(y6, 56);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y6 = _mm256_slli_epi64(y6, 8);
    y6 = _mm256_xor_si256(y6, y10);
    y6 = _mm256_xor_si256(y6, y9);
    y3 = _mm256_xor_si256(y3, y7);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 96), y3);
    y9 = _mm256_srli_epi64(y7, 56);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y7 = _mm256_slli_epi64(y7, 8);
    y7 = _mm256_xor_si256(y7, y10);
    y7 = _mm256_xor_si256(y7, y9);
    r12 = (word32)((word32)r12 + 0x80);
    if (((word32)r12) < ((word32)r11)) {
        goto L_AES_XTS_encrypt_update_vaes_enc_128;
    }
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y4, 0));
L_AES_XTS_encrypt_update_vaes_done_128:
    r11 = (word32)((word32)rax);
    r11 = (word32)((word32)r11 & 0xffffffc0);
    if (((word32)r12) == ((word32)r11)) {
        goto L_AES_XTS_encrypt_update_vaes_done_64;
    }
    /* 64 bytes of input */
    /* aes_enc_64 */
    rcx = (word64)(rdi + r12);
    rdx = (word64)(rsi + r12);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 32));
    y5 = _mm256_permute2x128_si256(y8, y8, 0);
    y6 = _mm256_srlv_epi64(y5, y15);
    y7 = _mm256_clmulepi64_epi128(y6, y13, 1);
    y6 = _mm256_bslli_epi128(y6, 8);
    y4 = _mm256_sllv_epi64(y5, y14);
    y4 = _mm256_xor_si256(y4, y7);
    y4 = _mm256_xor_si256(y4, y6);
    y9 = _mm256_srli_epi64(y4, 62);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y5 = _mm256_slli_epi64(y4, 2);
    y5 = _mm256_xor_si256(y5, y10);
    y5 = _mm256_xor_si256(y5, y9);
    /* aes_enc_block */
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        0)));
    y0 = _mm256_xor_si256(y0, y4);
    y0 = _mm256_xor_si256(y0, y9);
    y1 = _mm256_xor_si256(y1, y5);
    y1 = _mm256_xor_si256(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        16)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        32)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        48)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        64)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        80)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        96)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        112)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        128)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        144)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    zf7 = (word32)r9;
    zf8 = 0xb;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        160)));
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_XTS_encrypt_update_vaes_aes_enc_64_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        176)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    zf9 = (word32)r9;
    zf10 = 0xd;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        192)));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_XTS_encrypt_update_vaes_aes_enc_64_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        208)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y1 = _mm256_aesenc_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        224)));
L_AES_XTS_encrypt_update_vaes_aes_enc_64_aes_enc_block_last:
    y0 = _mm256_aesenclast_epi128(y0, y9);
    y1 = _mm256_aesenclast_epi128(y1, y9);
    y0 = _mm256_xor_si256(y0, y4);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 0), y0);
    y1 = _mm256_xor_si256(y1, y5);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 32), y1);
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y5, 1));
    y9 = _mm256_zextsi128_si256(_mm_shuffle_epi32(_mm256_castsi256_si128(y8),
        0x13));
    y8 = _mm256_zextsi128_si256(_mm_add_epi64(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y8)));
    y9 = _mm256_zextsi128_si256(_mm_srai_epi32(_mm256_castsi256_si128(y9), 31));
    y9 = _mm256_zextsi128_si256(_mm_and_si128(_mm256_castsi256_si128(y9), x12));
    y8 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y9)));
    r12 = (word32)((word32)r12 + 0x40);
L_AES_XTS_encrypt_update_vaes_done_64:
    r11 = (word32)((word32)rax);
    r11 = (word32)((word32)r11 & 0xffffffe0);
    if (((word32)r12) == ((word32)r11)) {
        goto L_AES_XTS_encrypt_update_vaes_done_32;
    }
    /* 32 bytes of input */
    /* aes_enc_32 */
    rcx = (word64)(rdi + r12);
    rdx = (word64)(rsi + r12);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 0));
    y5 = _mm256_permute2x128_si256(y8, y8, 0);
    y6 = _mm256_srlv_epi64(y5, y15);
    y7 = _mm256_clmulepi64_epi128(y6, y13, 1);
    y6 = _mm256_bslli_epi128(y6, 8);
    y4 = _mm256_sllv_epi64(y5, y14);
    y4 = _mm256_xor_si256(y4, y7);
    y4 = _mm256_xor_si256(y4, y6);
    /* aes_enc_block */
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        0)));
    y0 = _mm256_xor_si256(y0, y4);
    y0 = _mm256_xor_si256(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        16)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        32)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        48)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        64)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        80)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        96)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        112)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        128)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        144)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    zf11 = (word32)r9;
    zf12 = 0xb;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        160)));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_XTS_encrypt_update_vaes_aes_enc_32_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        176)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    zf13 = (word32)r9;
    zf14 = 0xd;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        192)));
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_XTS_encrypt_update_vaes_aes_enc_32_aes_enc_block_last;
    }
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        208)));
    y0 = _mm256_aesenc_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        224)));
L_AES_XTS_encrypt_update_vaes_aes_enc_32_aes_enc_block_last:
    y0 = _mm256_aesenclast_epi128(y0, y9);
    y0 = _mm256_xor_si256(y0, y4);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 0), y0);
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y4, 1));
    y9 = _mm256_zextsi128_si256(_mm_shuffle_epi32(_mm256_castsi256_si128(y8),
        0x13));
    y8 = _mm256_zextsi128_si256(_mm_add_epi64(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y8)));
    y9 = _mm256_zextsi128_si256(_mm_srai_epi32(_mm256_castsi256_si128(y9), 31));
    y9 = _mm256_zextsi128_si256(_mm_and_si128(_mm256_castsi256_si128(y9), x12));
    y8 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y9)));
    r12 = (word32)((word32)r12 + 0x20);
L_AES_XTS_encrypt_update_vaes_done_32:
    zf15 = (word32)r12;
    zf16 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf15) == (zf16)) {
        goto L_AES_XTS_encrypt_update_vaes_done_enc;
    }
    r11 = (word32)((word32)r11 - (word32)r12);
    zf17 = (word32)r11;
    zf18 = 0x10;
    r11 = (word32)((word32)rax);
    if ((zf17) < (zf18)) {
        goto L_AES_XTS_encrypt_update_vaes_last_15;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    /* 16 bytes of input */
L_AES_XTS_encrypt_update_vaes_enc_16:
    rcx = (word64)(rdi + r12);
    y0 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    /* aes_enc_block */
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm_loadu_si128((const __m128i*)WC_PR(r10, 0))));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        16)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        32)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        48)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        64)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        80)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        96)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        112)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        128)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        144)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    zf19 = (word32)r9;
    zf20 = 0xb;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        160)));
    if ((sword32)(zf19) < (sword32)(zf20)) {
        goto L_AES_XTS_encrypt_update_vaes_aes_enc_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        176)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    zf21 = (word32)r9;
    zf22 = 0xd;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        192)));
    if ((sword32)(zf21) < (sword32)(zf22)) {
        goto L_AES_XTS_encrypt_update_vaes_aes_enc_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        208)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        224)));
L_AES_XTS_encrypt_update_vaes_aes_enc_block_last:
    y0 = _mm256_zextsi128_si256(_mm_aesenclast_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    rcx = (word64)(rsi + r12);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), _mm256_castsi256_si128(y0));
    y4 = _mm256_zextsi128_si256(_mm_shuffle_epi32(_mm256_castsi256_si128(y8),
        0x13));
    y8 = _mm256_zextsi128_si256(_mm_add_epi64(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y8)));
    y4 = _mm256_zextsi128_si256(_mm_srai_epi32(_mm256_castsi256_si128(y4), 31));
    y4 = _mm256_zextsi128_si256(_mm_and_si128(_mm256_castsi256_si128(y4), x12));
    y8 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y4)));
    r12 = (word32)((word32)r12 + 0x10);
    if (((word32)r12) < ((word32)r11)) {
        goto L_AES_XTS_encrypt_update_vaes_enc_16;
    }
    if (((word32)r12) == ((word32)rax)) {
        goto L_AES_XTS_encrypt_update_vaes_done_enc;
    }
L_AES_XTS_encrypt_update_vaes_last_15:
    r12 = (word64)(r12 - 0x10);
    rcx = (word64)(rsi + r12);
    y0 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    r12 = (word64)(r12 + 0x10);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), _mm256_castsi256_si128(y0));
    rdx = (word64)(0);
L_AES_XTS_encrypt_update_vaes_last_15_byte_loop:
    r11 = (r11 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, rdx)) & 0xff);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, r12)) & 0xff);
    WC_S8(rsi, r12) = (byte)((byte)r11);
    WC_S8(rsp, rdx) = (byte)((byte)rcx);
    r12 = (word32)((word32)r12 + 1);
    rdx = (word32)((word32)rdx + 1);
    if (((word32)r12) < ((word32)rax)) {
        goto L_AES_XTS_encrypt_update_vaes_last_15_byte_loop;
    }
    r12 = (word64)(r12 - rdx);
    y0 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rsp, 0)));
    r12 = (word64)(r12 - 0x10);
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    /* aes_enc_block */
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm_loadu_si128((const __m128i*)WC_PR(r10, 0))));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        16)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        32)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        48)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        64)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        80)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        96)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        112)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        128)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        144)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    zf23 = (word32)r9;
    zf24 = 0xb;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        160)));
    if ((sword32)(zf23) < (sword32)(zf24)) {
        goto L_AES_XTS_encrypt_update_vaes_last_15_aes_enc_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        176)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    zf25 = (word32)r9;
    zf26 = 0xd;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        192)));
    if ((sword32)(zf25) < (sword32)(zf26)) {
        goto L_AES_XTS_encrypt_update_vaes_last_15_aes_enc_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        208)));
    y0 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        224)));
L_AES_XTS_encrypt_update_vaes_last_15_aes_enc_block_last:
    y0 = _mm256_zextsi128_si256(_mm_aesenclast_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    rcx = (word64)(rsi + r12);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), _mm256_castsi256_si128(y0));
L_AES_XTS_encrypt_update_vaes_done_enc:
    _mm_storeu_si128((__m128i*)WC_PW(r8, 0), _mm256_castsi256_si128(y8));
}

WC_X64I_TARGET("aes,vaes,pclmul,vpclmulqdq,avx2")
WOLFSSL_LOCAL void AES_XTS_decrypt_vaes(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* i,
    const unsigned char* key, const unsigned char* key2, int nr)
{
    word64 rdi, rsi, rax, r12, r8, r9, r10, rsp, r13 = 0, r11 = 0, rcx = 0,
           rdx = 0;
    __m128i x12;
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y4 = _mm256_setzero_si256(), y5, y6 = _mm256_setzero_si256(),
            y7 = _mm256_setzero_si256(), y8, y9 = _mm256_setzero_si256(),
            y10 = _mm256_setzero_si256(), y13, y14, y15;
    XALIGNED(32) WC_X64I_SLOT stk[8];
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
    word32 zf25;
    word32 zf26;
    word32 zf27;
    word32 zf28;
    word32 zf29;
    word32 zf30;
    word32 zf31;
    word32 zf32;
    word32 zf33;
    word32 zf34;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rax = (word64)(word32)nbytes;
    r12 = (word64)(size_t)i;
    r8 = (word64)(size_t)key;
    r9 = (word64)(size_t)key2;
    r10 = (word64)(word32)nr;

    rsp = (word64)(size_t)stk + 64;
    rsp = (word64)(rsp - 64);
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(L_vaes_aes_xts_gc_xts, 0));
    y13 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(
        L_vaes_aes_xts_poly, 0)));
    y14 = _mm256_loadu_si256((const __m256i*)WC_PR(L_vaes_aes_xts_shl, 0));
    y15 = _mm256_loadu_si256((const __m256i*)WC_PR(L_vaes_aes_xts_shr, 0));
    y8 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    /* aes_enc_block */
    y8 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y8),
        _mm_loadu_si128((const __m128i*)WC_PR(r9, 0))));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9, 16)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9, 32)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9, 48)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9, 64)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9, 80)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9, 96)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        112)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        128)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        144)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    zf1 = (word32)r10;
    zf2 = 0xb;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        160)));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_XTS_decrypt_vaes_tweak_aes_enc_block_last;
    }
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        176)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y6)));
    zf3 = (word32)r10;
    zf4 = 0xd;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        192)));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_decrypt_vaes_tweak_aes_enc_block_last;
    }
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        208)));
    y8 = _mm256_zextsi128_si256(_mm_aesenc_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y6)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        224)));
L_AES_XTS_decrypt_vaes_tweak_aes_enc_block_last:
    y8 = _mm256_zextsi128_si256(_mm_aesenclast_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y5)));
    r13 = (word32)(0);
    r11 = (word32)((word32)rax);
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_vaes_mul16_128;
    }
    r11 = (word32)((word32)r11 - 0x10);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_vaes_last_31_start;
    }
L_AES_XTS_decrypt_vaes_mul16_128:
    if (((word32)r11) < (0x20)) {
        goto L_AES_XTS_decrypt_vaes_done_128;
    }
    if (((word32)r11) < (0x80)) {
        goto L_AES_XTS_decrypt_vaes_done_128;
    }
    r11 = (word32)((word32)r11 & 0xffffff80);
    y5 = _mm256_permute2x128_si256(y8, y8, 0);
    y6 = _mm256_srlv_epi64(y5, y15);
    y7 = _mm256_clmulepi64_epi128(y6, y13, 1);
    y6 = _mm256_bslli_epi128(y6, 8);
    y4 = _mm256_sllv_epi64(y5, y14);
    y4 = _mm256_xor_si256(y4, y7);
    y4 = _mm256_xor_si256(y4, y6);
    y9 = _mm256_srli_epi64(y4, 62);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y5 = _mm256_slli_epi64(y4, 2);
    y5 = _mm256_xor_si256(y5, y10);
    y5 = _mm256_xor_si256(y5, y9);
    y9 = _mm256_srli_epi64(y5, 62);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y6 = _mm256_slli_epi64(y5, 2);
    y6 = _mm256_xor_si256(y6, y10);
    y6 = _mm256_xor_si256(y6, y9);
    y9 = _mm256_srli_epi64(y6, 62);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y7 = _mm256_slli_epi64(y6, 2);
    y7 = _mm256_xor_si256(y7, y10);
    y7 = _mm256_xor_si256(y7, y9);
L_AES_XTS_decrypt_vaes_dec_128:
    /* 128 bytes of input */
    /* aes_dec_128 */
    rcx = (word64)(rdi + r13);
    rdx = (word64)(rsi + r13);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 32));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 64));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 96));
    /* aes_dec_block */
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        0)));
    y0 = _mm256_xor_si256(y0, y4);
    y0 = _mm256_xor_si256(y0, y9);
    y1 = _mm256_xor_si256(y1, y5);
    y1 = _mm256_xor_si256(y1, y9);
    y2 = _mm256_xor_si256(y2, y6);
    y2 = _mm256_xor_si256(y2, y9);
    y3 = _mm256_xor_si256(y3, y7);
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
    zf5 = (word32)r10;
    zf6 = 0xb;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_XTS_decrypt_vaes_aes_dec_128_aes_dec_block_last;
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
    zf7 = (word32)r10;
    zf8 = 0xd;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_XTS_decrypt_vaes_aes_dec_128_aes_dec_block_last;
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
L_AES_XTS_decrypt_vaes_aes_dec_128_aes_dec_block_last:
    y0 = _mm256_aesdeclast_epi128(y0, y9);
    y1 = _mm256_aesdeclast_epi128(y1, y9);
    y2 = _mm256_aesdeclast_epi128(y2, y9);
    y3 = _mm256_aesdeclast_epi128(y3, y9);
    y0 = _mm256_xor_si256(y0, y4);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 0), y0);
    y9 = _mm256_srli_epi64(y4, 56);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y4 = _mm256_slli_epi64(y4, 8);
    y4 = _mm256_xor_si256(y4, y10);
    y4 = _mm256_xor_si256(y4, y9);
    y1 = _mm256_xor_si256(y1, y5);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 32), y1);
    y9 = _mm256_srli_epi64(y5, 56);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y5 = _mm256_slli_epi64(y5, 8);
    y5 = _mm256_xor_si256(y5, y10);
    y5 = _mm256_xor_si256(y5, y9);
    y2 = _mm256_xor_si256(y2, y6);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 64), y2);
    y9 = _mm256_srli_epi64(y6, 56);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y6 = _mm256_slli_epi64(y6, 8);
    y6 = _mm256_xor_si256(y6, y10);
    y6 = _mm256_xor_si256(y6, y9);
    y3 = _mm256_xor_si256(y3, y7);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 96), y3);
    y9 = _mm256_srli_epi64(y7, 56);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y7 = _mm256_slli_epi64(y7, 8);
    y7 = _mm256_xor_si256(y7, y10);
    y7 = _mm256_xor_si256(y7, y9);
    r13 = (word32)((word32)r13 + 0x80);
    if (((word32)r13) < ((word32)r11)) {
        goto L_AES_XTS_decrypt_vaes_dec_128;
    }
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y4, 0));
L_AES_XTS_decrypt_vaes_done_128:
    zf9 = (word32)r13;
    zf10 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf9) == (zf10)) {
        goto L_AES_XTS_decrypt_vaes_done_dec;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_vaes_mul16_64;
    }
    r11 = (word32)((word32)r11 - 0x10);
    r11 = (word32)((word32)r11 - (word32)r13);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_vaes_last_31_start;
    }
    r11 = (word32)((word32)r11 + (word32)r13);
L_AES_XTS_decrypt_vaes_mul16_64:
    r11 = (word32)((word32)r11 & 0xffffffc0);
    if (((word32)r13) == ((word32)r11)) {
        goto L_AES_XTS_decrypt_vaes_done_64;
    }
    /* 64 bytes of input */
    /* aes_dec_64 */
    rcx = (word64)(rdi + r13);
    rdx = (word64)(rsi + r13);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 32));
    y5 = _mm256_permute2x128_si256(y8, y8, 0);
    y6 = _mm256_srlv_epi64(y5, y15);
    y7 = _mm256_clmulepi64_epi128(y6, y13, 1);
    y6 = _mm256_bslli_epi128(y6, 8);
    y4 = _mm256_sllv_epi64(y5, y14);
    y4 = _mm256_xor_si256(y4, y7);
    y4 = _mm256_xor_si256(y4, y6);
    y9 = _mm256_srli_epi64(y4, 62);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y5 = _mm256_slli_epi64(y4, 2);
    y5 = _mm256_xor_si256(y5, y10);
    y5 = _mm256_xor_si256(y5, y9);
    /* aes_dec_block */
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        0)));
    y0 = _mm256_xor_si256(y0, y4);
    y0 = _mm256_xor_si256(y0, y9);
    y1 = _mm256_xor_si256(y1, y5);
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
    zf11 = (word32)r10;
    zf12 = 0xb;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_XTS_decrypt_vaes_aes_dec_64_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    zf13 = (word32)r10;
    zf14 = 0xd;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_XTS_decrypt_vaes_aes_dec_64_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_XTS_decrypt_vaes_aes_dec_64_aes_dec_block_last:
    y0 = _mm256_aesdeclast_epi128(y0, y9);
    y1 = _mm256_aesdeclast_epi128(y1, y9);
    y0 = _mm256_xor_si256(y0, y4);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 0), y0);
    y1 = _mm256_xor_si256(y1, y5);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 32), y1);
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y5, 1));
    y9 = _mm256_zextsi128_si256(_mm_shuffle_epi32(_mm256_castsi256_si128(y8),
        0x13));
    y8 = _mm256_zextsi128_si256(_mm_add_epi64(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y8)));
    y9 = _mm256_zextsi128_si256(_mm_srai_epi32(_mm256_castsi256_si128(y9), 31));
    y9 = _mm256_zextsi128_si256(_mm_and_si128(_mm256_castsi256_si128(y9), x12));
    y8 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y9)));
    r13 = (word32)((word32)r13 + 0x40);
L_AES_XTS_decrypt_vaes_done_64:
    zf15 = (word32)r13;
    zf16 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf15) == (zf16)) {
        goto L_AES_XTS_decrypt_vaes_done_dec;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_vaes_mul16_32;
    }
    r11 = (word32)((word32)r11 - 0x10);
    r11 = (word32)((word32)r11 - (word32)r13);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_vaes_last_31_start;
    }
    r11 = (word32)((word32)r11 + (word32)r13);
L_AES_XTS_decrypt_vaes_mul16_32:
    r11 = (word32)((word32)r11 & 0xffffffe0);
    if (((word32)r13) == ((word32)r11)) {
        goto L_AES_XTS_decrypt_vaes_done_32;
    }
    /* 32 bytes of input */
    /* aes_dec_32 */
    rcx = (word64)(rdi + r13);
    rdx = (word64)(rsi + r13);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 0));
    y5 = _mm256_permute2x128_si256(y8, y8, 0);
    y6 = _mm256_srlv_epi64(y5, y15);
    y7 = _mm256_clmulepi64_epi128(y6, y13, 1);
    y6 = _mm256_bslli_epi128(y6, 8);
    y4 = _mm256_sllv_epi64(y5, y14);
    y4 = _mm256_xor_si256(y4, y7);
    y4 = _mm256_xor_si256(y4, y6);
    /* aes_dec_block */
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        0)));
    y0 = _mm256_xor_si256(y0, y4);
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
    zf17 = (word32)r10;
    zf18 = 0xb;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_XTS_decrypt_vaes_aes_dec_32_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    zf19 = (word32)r10;
    zf20 = 0xd;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf19) < (sword32)(zf20)) {
        goto L_AES_XTS_decrypt_vaes_aes_dec_32_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_XTS_decrypt_vaes_aes_dec_32_aes_dec_block_last:
    y0 = _mm256_aesdeclast_epi128(y0, y9);
    y0 = _mm256_xor_si256(y0, y4);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 0), y0);
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y4, 1));
    y9 = _mm256_zextsi128_si256(_mm_shuffle_epi32(_mm256_castsi256_si128(y8),
        0x13));
    y8 = _mm256_zextsi128_si256(_mm_add_epi64(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y8)));
    y9 = _mm256_zextsi128_si256(_mm_srai_epi32(_mm256_castsi256_si128(y9), 31));
    y9 = _mm256_zextsi128_si256(_mm_and_si128(_mm256_castsi256_si128(y9), x12));
    y8 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y9)));
    r13 = (word32)((word32)r13 + 0x20);
L_AES_XTS_decrypt_vaes_done_32:
    zf21 = (word32)r13;
    zf22 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf21) == (zf22)) {
        goto L_AES_XTS_decrypt_vaes_done_dec;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_vaes_mul16;
    }
    r11 = (word32)((word32)r11 - 0x10);
    r11 = (word32)((word32)r11 - (word32)r13);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_vaes_last_31_start;
    }
    r11 = (word32)((word32)r11 + (word32)r13);
L_AES_XTS_decrypt_vaes_mul16:
L_AES_XTS_decrypt_vaes_dec_16:
    /* 16 bytes of input */
    rcx = (word64)(rdi + r13);
    y0 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    /* aes_dec_block */
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm_loadu_si128((const __m128i*)WC_PR(r8, 0))));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 16)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 32)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 48)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 64)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 80)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 96)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    zf23 = (word32)r10;
    zf24 = 0xb;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf23) < (sword32)(zf24)) {
        goto L_AES_XTS_decrypt_vaes_aes_dec_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    zf25 = (word32)r10;
    zf26 = 0xd;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf25) < (sword32)(zf26)) {
        goto L_AES_XTS_decrypt_vaes_aes_dec_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_XTS_decrypt_vaes_aes_dec_block_last:
    y0 = _mm256_zextsi128_si256(_mm_aesdeclast_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    rcx = (word64)(rsi + r13);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), _mm256_castsi256_si128(y0));
    y4 = _mm256_zextsi128_si256(_mm_shuffle_epi32(_mm256_castsi256_si128(y8),
        0x13));
    y8 = _mm256_zextsi128_si256(_mm_add_epi64(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y8)));
    y4 = _mm256_zextsi128_si256(_mm_srai_epi32(_mm256_castsi256_si128(y4), 31));
    y4 = _mm256_zextsi128_si256(_mm_and_si128(_mm256_castsi256_si128(y4), x12));
    y8 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y4)));
    r13 = (word32)((word32)r13 + 0x10);
    if (((word32)r13) < ((word32)r11)) {
        goto L_AES_XTS_decrypt_vaes_dec_16;
    }
    if (((word32)r13) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_vaes_done_dec;
    }
L_AES_XTS_decrypt_vaes_last_31_start:
    y4 = _mm256_zextsi128_si256(_mm_shuffle_epi32(_mm256_castsi256_si128(y8),
        0x13));
    y7 = _mm256_zextsi128_si256(_mm_add_epi64(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y8)));
    y4 = _mm256_zextsi128_si256(_mm_srai_epi32(_mm256_castsi256_si128(y4), 31));
    y4 = _mm256_zextsi128_si256(_mm_and_si128(_mm256_castsi256_si128(y4), x12));
    y7 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y7),
        _mm256_castsi256_si128(y4)));
    rcx = (word64)(rdi + r13);
    y0 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y7)));
    /* aes_dec_block */
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm_loadu_si128((const __m128i*)WC_PR(r8, 0))));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 16)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 32)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 48)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 64)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 80)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 96)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    zf27 = (word32)r10;
    zf28 = 0xb;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf27) < (sword32)(zf28)) {
        goto L_AES_XTS_decrypt_vaes_last_31_aes_dec_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    zf29 = (word32)r10;
    zf30 = 0xd;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf29) < (sword32)(zf30)) {
        goto L_AES_XTS_decrypt_vaes_last_31_aes_dec_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_XTS_decrypt_vaes_last_31_aes_dec_block_last:
    y0 = _mm256_zextsi128_si256(_mm_aesdeclast_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y7)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), _mm256_castsi256_si128(y0));
    r13 = (word64)(r13 + 0x10);
    rdx = (word64)(0);
L_AES_XTS_decrypt_vaes_last_31_byte_loop:
    r11 = (r11 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, rdx)) & 0xff);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, r13)) & 0xff);
    WC_S8(rsi, r13) = (byte)((byte)r11);
    WC_S8(rsp, rdx) = (byte)((byte)rcx);
    r13 = (word32)((word32)r13 + 1);
    rdx = (word32)((word32)rdx + 1);
    if (((word32)r13) < ((word32)rax)) {
        goto L_AES_XTS_decrypt_vaes_last_31_byte_loop;
    }
    r13 = (word64)(r13 - rdx);
    y0 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rsp, 0)));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    /* aes_dec_block */
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm_loadu_si128((const __m128i*)WC_PR(r8, 0))));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 16)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 32)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 48)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 64)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 80)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 96)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    zf31 = (word32)r10;
    zf32 = 0xb;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf31) < (sword32)(zf32)) {
        goto L_AES_XTS_decrypt_vaes_last_31_2_aes_dec_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    zf33 = (word32)r10;
    zf34 = 0xd;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf33) < (sword32)(zf34)) {
        goto L_AES_XTS_decrypt_vaes_last_31_2_aes_dec_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_XTS_decrypt_vaes_last_31_2_aes_dec_block_last:
    y0 = _mm256_zextsi128_si256(_mm_aesdeclast_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    r13 = (word64)(r13 - 0x10);
    rcx = (word64)(rsi + r13);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), _mm256_castsi256_si128(y0));
L_AES_XTS_decrypt_vaes_done_dec:
    ;
}

WC_X64I_TARGET("aes,vaes,pclmul,vpclmulqdq,avx2")
WOLFSSL_LOCAL void AES_XTS_decrypt_update_vaes(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* key,
    unsigned char* tweak_block, int nr)
{
    word64 rdi, rsi, rax, r10, r8, r9, rsp, r12, r11, rcx = 0, rdx = 0;
    __m128i x12;
    __m256i y0 = _mm256_setzero_si256(), y1 = _mm256_setzero_si256(),
            y2 = _mm256_setzero_si256(), y3 = _mm256_setzero_si256(),
            y4 = _mm256_setzero_si256(), y5 = _mm256_setzero_si256(),
            y6 = _mm256_setzero_si256(), y7 = _mm256_setzero_si256(), y8,
            y9 = _mm256_setzero_si256(), y10 = _mm256_setzero_si256(), y13,
            y14, y15;
    XALIGNED(32) WC_X64I_SLOT stk[8];
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
    word32 zf25;
    word32 zf26;
    word32 zf27;
    word32 zf28;
    word32 zf29;
    word32 zf30;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rax = (word64)(word32)nbytes;
    r10 = (word64)(size_t)key;
    r8 = (word64)(size_t)tweak_block;
    r9 = (word64)(word32)nr;

    rsp = (word64)(size_t)stk + 64;
    rsp = (word64)(rsp - 64);
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(L_vaes_aes_xts_gc_xts, 0));
    y13 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(
        L_vaes_aes_xts_poly, 0)));
    y14 = _mm256_loadu_si256((const __m256i*)WC_PR(L_vaes_aes_xts_shl, 0));
    y15 = _mm256_loadu_si256((const __m256i*)WC_PR(L_vaes_aes_xts_shr, 0));
    y8 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    r12 = (word32)(0);
    r11 = (word32)((word32)rax);
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_vaes_mul16_128;
    }
    r11 = (word32)((word32)r11 - 0x10);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_update_vaes_last_31_start;
    }
L_AES_XTS_decrypt_update_vaes_mul16_128:
    if (((word32)r11) < (0x20)) {
        goto L_AES_XTS_decrypt_update_vaes_done_128;
    }
    if (((word32)r11) < (0x80)) {
        goto L_AES_XTS_decrypt_update_vaes_done_128;
    }
    r11 = (word32)((word32)r11 & 0xffffff80);
    y5 = _mm256_permute2x128_si256(y8, y8, 0);
    y6 = _mm256_srlv_epi64(y5, y15);
    y7 = _mm256_clmulepi64_epi128(y6, y13, 1);
    y6 = _mm256_bslli_epi128(y6, 8);
    y4 = _mm256_sllv_epi64(y5, y14);
    y4 = _mm256_xor_si256(y4, y7);
    y4 = _mm256_xor_si256(y4, y6);
    y9 = _mm256_srli_epi64(y4, 62);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y5 = _mm256_slli_epi64(y4, 2);
    y5 = _mm256_xor_si256(y5, y10);
    y5 = _mm256_xor_si256(y5, y9);
    y9 = _mm256_srli_epi64(y5, 62);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y6 = _mm256_slli_epi64(y5, 2);
    y6 = _mm256_xor_si256(y6, y10);
    y6 = _mm256_xor_si256(y6, y9);
    y9 = _mm256_srli_epi64(y6, 62);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y7 = _mm256_slli_epi64(y6, 2);
    y7 = _mm256_xor_si256(y7, y10);
    y7 = _mm256_xor_si256(y7, y9);
L_AES_XTS_decrypt_update_vaes_dec_128:
    /* 128 bytes of input */
    /* aes_dec_128 */
    rcx = (word64)(rdi + r12);
    rdx = (word64)(rsi + r12);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 32));
    y2 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 64));
    y3 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 96));
    /* aes_dec_block */
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        0)));
    y0 = _mm256_xor_si256(y0, y4);
    y0 = _mm256_xor_si256(y0, y9);
    y1 = _mm256_xor_si256(y1, y5);
    y1 = _mm256_xor_si256(y1, y9);
    y2 = _mm256_xor_si256(y2, y6);
    y2 = _mm256_xor_si256(y2, y9);
    y3 = _mm256_xor_si256(y3, y7);
    y3 = _mm256_xor_si256(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        16)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        32)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        48)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        64)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        80)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        96)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        112)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        128)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        144)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    zf1 = (word32)r9;
    zf2 = 0xb;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        160)));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_XTS_decrypt_update_vaes_aes_dec_128_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        176)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    zf3 = (word32)r9;
    zf4 = 0xd;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        192)));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_decrypt_update_vaes_aes_dec_128_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        208)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y2 = _mm256_aesdec_epi128(y2, y9);
    y3 = _mm256_aesdec_epi128(y3, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        224)));
L_AES_XTS_decrypt_update_vaes_aes_dec_128_aes_dec_block_last:
    y0 = _mm256_aesdeclast_epi128(y0, y9);
    y1 = _mm256_aesdeclast_epi128(y1, y9);
    y2 = _mm256_aesdeclast_epi128(y2, y9);
    y3 = _mm256_aesdeclast_epi128(y3, y9);
    y0 = _mm256_xor_si256(y0, y4);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 0), y0);
    y9 = _mm256_srli_epi64(y4, 56);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y4 = _mm256_slli_epi64(y4, 8);
    y4 = _mm256_xor_si256(y4, y10);
    y4 = _mm256_xor_si256(y4, y9);
    y1 = _mm256_xor_si256(y1, y5);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 32), y1);
    y9 = _mm256_srli_epi64(y5, 56);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y5 = _mm256_slli_epi64(y5, 8);
    y5 = _mm256_xor_si256(y5, y10);
    y5 = _mm256_xor_si256(y5, y9);
    y2 = _mm256_xor_si256(y2, y6);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 64), y2);
    y9 = _mm256_srli_epi64(y6, 56);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y6 = _mm256_slli_epi64(y6, 8);
    y6 = _mm256_xor_si256(y6, y10);
    y6 = _mm256_xor_si256(y6, y9);
    y3 = _mm256_xor_si256(y3, y7);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 96), y3);
    y9 = _mm256_srli_epi64(y7, 56);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y7 = _mm256_slli_epi64(y7, 8);
    y7 = _mm256_xor_si256(y7, y10);
    y7 = _mm256_xor_si256(y7, y9);
    r12 = (word32)((word32)r12 + 0x80);
    if (((word32)r12) < ((word32)r11)) {
        goto L_AES_XTS_decrypt_update_vaes_dec_128;
    }
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y4, 0));
L_AES_XTS_decrypt_update_vaes_done_128:
    zf5 = (word32)r12;
    zf6 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf5) == (zf6)) {
        goto L_AES_XTS_decrypt_update_vaes_done_dec;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_vaes_mul16_64;
    }
    r11 = (word32)((word32)r11 - 0x10);
    r11 = (word32)((word32)r11 - (word32)r12);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_update_vaes_last_31_start;
    }
    r11 = (word32)((word32)r11 + (word32)r12);
L_AES_XTS_decrypt_update_vaes_mul16_64:
    r11 = (word32)((word32)r11 & 0xffffffc0);
    if (((word32)r12) == ((word32)r11)) {
        goto L_AES_XTS_decrypt_update_vaes_done_64;
    }
    /* 64 bytes of input */
    /* aes_dec_64 */
    rcx = (word64)(rdi + r12);
    rdx = (word64)(rsi + r12);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 0));
    y1 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 32));
    y5 = _mm256_permute2x128_si256(y8, y8, 0);
    y6 = _mm256_srlv_epi64(y5, y15);
    y7 = _mm256_clmulepi64_epi128(y6, y13, 1);
    y6 = _mm256_bslli_epi128(y6, 8);
    y4 = _mm256_sllv_epi64(y5, y14);
    y4 = _mm256_xor_si256(y4, y7);
    y4 = _mm256_xor_si256(y4, y6);
    y9 = _mm256_srli_epi64(y4, 62);
    y10 = _mm256_clmulepi64_epi128(y9, y13, 1);
    y9 = _mm256_bslli_epi128(y9, 8);
    y5 = _mm256_slli_epi64(y4, 2);
    y5 = _mm256_xor_si256(y5, y10);
    y5 = _mm256_xor_si256(y5, y9);
    /* aes_dec_block */
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        0)));
    y0 = _mm256_xor_si256(y0, y4);
    y0 = _mm256_xor_si256(y0, y9);
    y1 = _mm256_xor_si256(y1, y5);
    y1 = _mm256_xor_si256(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        16)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        32)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        48)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        64)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        80)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        96)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        112)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        128)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        144)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    zf7 = (word32)r9;
    zf8 = 0xb;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        160)));
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_XTS_decrypt_update_vaes_aes_dec_64_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        176)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    zf9 = (word32)r9;
    zf10 = 0xd;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        192)));
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_XTS_decrypt_update_vaes_aes_dec_64_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        208)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y1 = _mm256_aesdec_epi128(y1, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        224)));
L_AES_XTS_decrypt_update_vaes_aes_dec_64_aes_dec_block_last:
    y0 = _mm256_aesdeclast_epi128(y0, y9);
    y1 = _mm256_aesdeclast_epi128(y1, y9);
    y0 = _mm256_xor_si256(y0, y4);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 0), y0);
    y1 = _mm256_xor_si256(y1, y5);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 32), y1);
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y5, 1));
    y9 = _mm256_zextsi128_si256(_mm_shuffle_epi32(_mm256_castsi256_si128(y8),
        0x13));
    y8 = _mm256_zextsi128_si256(_mm_add_epi64(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y8)));
    y9 = _mm256_zextsi128_si256(_mm_srai_epi32(_mm256_castsi256_si128(y9), 31));
    y9 = _mm256_zextsi128_si256(_mm_and_si128(_mm256_castsi256_si128(y9), x12));
    y8 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y9)));
    r12 = (word32)((word32)r12 + 0x40);
L_AES_XTS_decrypt_update_vaes_done_64:
    zf11 = (word32)r12;
    zf12 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf11) == (zf12)) {
        goto L_AES_XTS_decrypt_update_vaes_done_dec;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_vaes_mul16_32;
    }
    r11 = (word32)((word32)r11 - 0x10);
    r11 = (word32)((word32)r11 - (word32)r12);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_update_vaes_last_31_start;
    }
    r11 = (word32)((word32)r11 + (word32)r12);
L_AES_XTS_decrypt_update_vaes_mul16_32:
    r11 = (word32)((word32)r11 & 0xffffffe0);
    if (((word32)r12) == ((word32)r11)) {
        goto L_AES_XTS_decrypt_update_vaes_done_32;
    }
    /* 32 bytes of input */
    /* aes_dec_32 */
    rcx = (word64)(rdi + r12);
    rdx = (word64)(rsi + r12);
    y0 = _mm256_loadu_si256((const __m256i*)WC_PR(rcx, 0));
    y5 = _mm256_permute2x128_si256(y8, y8, 0);
    y6 = _mm256_srlv_epi64(y5, y15);
    y7 = _mm256_clmulepi64_epi128(y6, y13, 1);
    y6 = _mm256_bslli_epi128(y6, 8);
    y4 = _mm256_sllv_epi64(y5, y14);
    y4 = _mm256_xor_si256(y4, y7);
    y4 = _mm256_xor_si256(y4, y6);
    /* aes_dec_block */
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        0)));
    y0 = _mm256_xor_si256(y0, y4);
    y0 = _mm256_xor_si256(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        16)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        32)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        48)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        64)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        80)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        96)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        112)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        128)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        144)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    zf13 = (word32)r9;
    zf14 = 0xb;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        160)));
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_XTS_decrypt_update_vaes_aes_dec_32_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        176)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    zf15 = (word32)r9;
    zf16 = 0xd;
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        192)));
    if ((sword32)(zf15) < (sword32)(zf16)) {
        goto L_AES_XTS_decrypt_update_vaes_aes_dec_32_aes_dec_block_last;
    }
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        208)));
    y0 = _mm256_aesdec_epi128(y0, y9);
    y9 = _mm256_broadcastsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        224)));
L_AES_XTS_decrypt_update_vaes_aes_dec_32_aes_dec_block_last:
    y0 = _mm256_aesdeclast_epi128(y0, y9);
    y0 = _mm256_xor_si256(y0, y4);
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 0), y0);
    y8 = _mm256_zextsi128_si256(_mm256_extracti128_si256(y4, 1));
    y9 = _mm256_zextsi128_si256(_mm_shuffle_epi32(_mm256_castsi256_si128(y8),
        0x13));
    y8 = _mm256_zextsi128_si256(_mm_add_epi64(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y8)));
    y9 = _mm256_zextsi128_si256(_mm_srai_epi32(_mm256_castsi256_si128(y9), 31));
    y9 = _mm256_zextsi128_si256(_mm_and_si128(_mm256_castsi256_si128(y9), x12));
    y8 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y9)));
    r12 = (word32)((word32)r12 + 0x20);
L_AES_XTS_decrypt_update_vaes_done_32:
    zf17 = (word32)r12;
    zf18 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf17) == (zf18)) {
        goto L_AES_XTS_decrypt_update_vaes_done_dec;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_vaes_mul16;
    }
    r11 = (word32)((word32)r11 - 0x10);
    r11 = (word32)((word32)r11 - (word32)r12);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_update_vaes_last_31_start;
    }
    r11 = (word32)((word32)r11 + (word32)r12);
L_AES_XTS_decrypt_update_vaes_mul16:
L_AES_XTS_decrypt_update_vaes_dec_16:
    /* 16 bytes of input */
    rcx = (word64)(rdi + r12);
    y0 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    /* aes_dec_block */
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm_loadu_si128((const __m128i*)WC_PR(r10, 0))));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        16)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        32)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        48)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        64)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        80)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        96)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        112)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        128)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        144)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    zf19 = (word32)r9;
    zf20 = 0xb;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        160)));
    if ((sword32)(zf19) < (sword32)(zf20)) {
        goto L_AES_XTS_decrypt_update_vaes_aes_dec_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        176)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    zf21 = (word32)r9;
    zf22 = 0xd;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        192)));
    if ((sword32)(zf21) < (sword32)(zf22)) {
        goto L_AES_XTS_decrypt_update_vaes_aes_dec_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        208)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        224)));
L_AES_XTS_decrypt_update_vaes_aes_dec_block_last:
    y0 = _mm256_zextsi128_si256(_mm_aesdeclast_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    rcx = (word64)(rsi + r12);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), _mm256_castsi256_si128(y0));
    y4 = _mm256_zextsi128_si256(_mm_shuffle_epi32(_mm256_castsi256_si128(y8),
        0x13));
    y8 = _mm256_zextsi128_si256(_mm_add_epi64(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y8)));
    y4 = _mm256_zextsi128_si256(_mm_srai_epi32(_mm256_castsi256_si128(y4), 31));
    y4 = _mm256_zextsi128_si256(_mm_and_si128(_mm256_castsi256_si128(y4), x12));
    y8 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y4)));
    r12 = (word32)((word32)r12 + 0x10);
    if (((word32)r12) < ((word32)r11)) {
        goto L_AES_XTS_decrypt_update_vaes_dec_16;
    }
    if (((word32)r12) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_vaes_done_dec;
    }
L_AES_XTS_decrypt_update_vaes_last_31_start:
    y4 = _mm256_zextsi128_si256(_mm_shuffle_epi32(_mm256_castsi256_si128(y8),
        0x13));
    y7 = _mm256_zextsi128_si256(_mm_add_epi64(_mm256_castsi256_si128(y8),
        _mm256_castsi256_si128(y8)));
    y4 = _mm256_zextsi128_si256(_mm_srai_epi32(_mm256_castsi256_si128(y4), 31));
    y4 = _mm256_zextsi128_si256(_mm_and_si128(_mm256_castsi256_si128(y4), x12));
    y7 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y7),
        _mm256_castsi256_si128(y4)));
    rcx = (word64)(rdi + r12);
    y0 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y7)));
    /* aes_dec_block */
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm_loadu_si128((const __m128i*)WC_PR(r10, 0))));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        16)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        32)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        48)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        64)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        80)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        96)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        112)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        128)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        144)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    zf23 = (word32)r9;
    zf24 = 0xb;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        160)));
    if ((sword32)(zf23) < (sword32)(zf24)) {
        goto L_AES_XTS_decrypt_update_vaes_last_31_aes_dec_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        176)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    zf25 = (word32)r9;
    zf26 = 0xd;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        192)));
    if ((sword32)(zf25) < (sword32)(zf26)) {
        goto L_AES_XTS_decrypt_update_vaes_last_31_aes_dec_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        208)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        224)));
L_AES_XTS_decrypt_update_vaes_last_31_aes_dec_block_last:
    y0 = _mm256_zextsi128_si256(_mm_aesdeclast_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y7)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), _mm256_castsi256_si128(y0));
    r12 = (word64)(r12 + 0x10);
    rdx = (word64)(0);
L_AES_XTS_decrypt_update_vaes_last_31_byte_loop:
    r11 = (r11 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, rdx)) & 0xff);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, r12)) & 0xff);
    WC_S8(rsi, r12) = (byte)((byte)r11);
    WC_S8(rsp, rdx) = (byte)((byte)rcx);
    r12 = (word32)((word32)r12 + 1);
    rdx = (word32)((word32)rdx + 1);
    if (((word32)r12) < ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_vaes_last_31_byte_loop;
    }
    r12 = (word64)(r12 - rdx);
    y0 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(rsp, 0)));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    /* aes_dec_block */
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm_loadu_si128((const __m128i*)WC_PR(r10, 0))));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        16)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        32)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        48)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        64)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        80)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        96)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        112)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        128)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        144)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    zf27 = (word32)r9;
    zf28 = 0xb;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        160)));
    if ((sword32)(zf27) < (sword32)(zf28)) {
        goto L_AES_XTS_decrypt_update_vaes_last_31_2_aes_dec_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        176)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    zf29 = (word32)r9;
    zf30 = 0xd;
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        192)));
    if ((sword32)(zf29) < (sword32)(zf30)) {
        goto L_AES_XTS_decrypt_update_vaes_last_31_2_aes_dec_block_last;
    }
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y6 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        208)));
    y0 = _mm256_zextsi128_si256(_mm_aesdec_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y6)));
    y5 = _mm256_zextsi128_si256(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        224)));
L_AES_XTS_decrypt_update_vaes_last_31_2_aes_dec_block_last:
    y0 = _mm256_zextsi128_si256(_mm_aesdeclast_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y5)));
    y0 = _mm256_zextsi128_si256(_mm_xor_si128(_mm256_castsi256_si128(y0),
        _mm256_castsi256_si128(y8)));
    r12 = (word64)(r12 - 0x10);
    rcx = (word64)(rsi + r12);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), _mm256_castsi256_si128(y0));
L_AES_XTS_decrypt_update_vaes_done_dec:
    _mm_storeu_si128((__m128i*)WC_PW(r8, 0), _mm256_castsi256_si128(y8));
}

#endif /* HAVE_INTEL_VAES */
#ifdef HAVE_INTEL_AVX512
WC_X64I_TARGET("aes,avx")
WOLFSSL_LOCAL void AES_XTS_init_avx512(const unsigned char* i,
    const unsigned char* key, int nr)
{
    word64 rdi, rsi, rdx;
    __m128i x0, x2, x3 = _mm_setzero_si128();
    word32 zf1;
    word32 zf2;
    word32 zf3;
    word32 zf4;

    rdi = (word64)(size_t)i;
    rsi = (word64)(size_t)key;
    rdx = (word64)(word32)nr;

    x0 = _mm_loadu_si128((const __m128i*)WC_PR(rdi, 0));
    /* aes_enc_block */
    x0 = _mm_xor_si128(x0, _mm_loadu_si128((const __m128i*)WC_PR(rsi, 0)));
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 16));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 32));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 48));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 64));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 80));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 96));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 112));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 128));
    x0 = _mm_aesenc_si128(x0, x2);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 144));
    x0 = _mm_aesenc_si128(x0, x2);
    zf1 = (word32)rdx;
    zf2 = 0xb;
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 160));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_XTS_init_avx512_tweak_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x2);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 176));
    x0 = _mm_aesenc_si128(x0, x3);
    zf3 = (word32)rdx;
    zf4 = 0xd;
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 192));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_init_avx512_tweak_aes_enc_block_last;
    }
    x0 = _mm_aesenc_si128(x0, x2);
    x3 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 208));
    x0 = _mm_aesenc_si128(x0, x3);
    x2 = _mm_loadu_si128((const __m128i*)WC_PR(rsi, 224));
L_AES_XTS_init_avx512_tweak_aes_enc_block_last:
    x0 = _mm_aesenclast_si128(x0, x2);
    _mm_storeu_si128((__m128i*)WC_PW(rdi, 0), x0);
}

XALIGNED(16) static const word32 L_avx512_aes_xts_gc_xts[] WC_X64I_UNUSED = {
    0x00000087, 0x00000000, 0x00000001, 0x00000000,
};

XALIGNED(16) static const word32 L_avx512_aes_xts_poly[] WC_X64I_UNUSED = {
    0x00000087, 0x00000000, 0x00000000, 0x00000000,
};

XALIGNED(16) static const word32 L_avx512_aes_xts_shl[] WC_X64I_UNUSED = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000001, 0x00000000, 0x00000001, 0x00000000,
    0x00000002, 0x00000000, 0x00000002, 0x00000000,
    0x00000003, 0x00000000, 0x00000003, 0x00000000,
};

XALIGNED(16) static const word32 L_avx512_aes_xts_shr[] WC_X64I_UNUSED = {
    0x00000040, 0x00000000, 0x00000040, 0x00000000,
    0x0000003f, 0x00000000, 0x0000003f, 0x00000000,
    0x0000003e, 0x00000000, 0x0000003e, 0x00000000,
    0x0000003d, 0x00000000, 0x0000003d, 0x00000000,
};

WC_X64I_TARGET("aes,vaes,pclmul,vpclmulqdq,avx512f,avx512vl,avx512bw")
WOLFSSL_LOCAL void AES_XTS_encrypt_avx512(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* i,
    const unsigned char* key, const unsigned char* key2, int nr)
{
    word64 rdi, rsi, rax, r12, r8, r9, r10, rsp, r13 = 0, r11 = 0, rcx = 0,
           rdx = 0;
    __m128i x12;
    __m512i z0 = _mm512_setzero_si512(), z1 = _mm512_setzero_si512(),
            z2 = _mm512_setzero_si512(), z3 = _mm512_setzero_si512(),
            z4 = _mm512_setzero_si512(), z5, z6 = _mm512_setzero_si512(),
            z7 = _mm512_setzero_si512(), z8, z9 = _mm512_setzero_si512(),
            z10 = _mm512_setzero_si512(), z13, z14, z15,
            z16 = _mm512_setzero_si512(), z17 = _mm512_setzero_si512(),
            z18 = _mm512_setzero_si512(), z19 = _mm512_setzero_si512(),
            z20 = _mm512_setzero_si512(), z21 = _mm512_setzero_si512(),
            z22 = _mm512_setzero_si512(), z23 = _mm512_setzero_si512(),
            z24 = _mm512_setzero_si512(), z25 = _mm512_setzero_si512(),
            z26 = _mm512_setzero_si512(), z27 = _mm512_setzero_si512(),
            z28 = _mm512_setzero_si512(), z29 = _mm512_setzero_si512(),
            z30 = _mm512_setzero_si512();
    XALIGNED(32) WC_X64I_SLOT stk[8];
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
    word32 zf25;
    word32 zf26;
    word32 zf27;
    word32 zf28;
    word32 zf29;
    word32 zf30;
    word32 zf31;
    word32 zf32;
    word32 zf33;
    word32 zf34;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rax = (word64)(word32)nbytes;
    r12 = (word64)(size_t)i;
    r8 = (word64)(size_t)key;
    r9 = (word64)(size_t)key2;
    r10 = (word64)(word32)nr;

    rsp = (word64)(size_t)stk + 64;
    rsp = (word64)(rsp - 64);
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(L_avx512_aes_xts_gc_xts, 0));
    z13 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(
        L_avx512_aes_xts_poly, 0)));
    z14 = _mm512_loadu_si512((const void*)WC_PR(L_avx512_aes_xts_shl, 0));
    z15 = _mm512_loadu_si512((const void*)WC_PR(L_avx512_aes_xts_shr, 0));
    z8 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    /* aes_enc_block */
    z8 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z8),
        _mm_loadu_si128((const __m128i*)WC_PR(r9, 0))));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9, 16)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9, 32)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9, 48)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9, 64)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9, 80)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9, 96)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        112)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        128)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        144)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    zf1 = (word32)r10;
    zf2 = 0xb;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        160)));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_XTS_encrypt_avx512_tweak_aes_enc_block_last;
    }
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        176)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z6)));
    zf3 = (word32)r10;
    zf4 = 0xd;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        192)));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_encrypt_avx512_tweak_aes_enc_block_last;
    }
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        208)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z6)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        224)));
L_AES_XTS_encrypt_avx512_tweak_aes_enc_block_last:
    z8 = _mm512_zextsi128_si512(_mm_aesenclast_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    r13 = (word32)(0);
    if (((word32)rax) < (0x20)) {
        goto L_AES_XTS_encrypt_avx512_done_128;
    }
    z16 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    z17 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        16)));
    z18 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        32)));
    z19 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        48)));
    z20 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        64)));
    z21 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        80)));
    z22 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        96)));
    z23 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    z24 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    z25 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    z26 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)((word32)r10) < (sword32)(0xb)) {
        goto L_AES_XTS_encrypt_avx512_key_cached;
    }
    z27 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    z28 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)((word32)r10) < (sword32)(0xd)) {
        goto L_AES_XTS_encrypt_avx512_key_cached;
    }
    z29 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    z30 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_XTS_encrypt_avx512_key_cached:
    zf5 = (word32)rax;
    zf6 = 0x100;
    r11 = (word32)((word32)rax);
    if ((zf5) < (zf6)) {
        goto L_AES_XTS_encrypt_avx512_done_256;
    }
    r11 = (word32)((word32)r11 & 0xffffff00);
    z5 = _mm512_shuffle_i64x2(z8, z8, 0);
    z6 = _mm512_srlv_epi64(z5, z15);
    z7 = _mm512_clmulepi64_epi128(z6, z13, 1);
    z6 = _mm512_bslli_epi128(z6, 8);
    z4 = _mm512_sllv_epi64(z5, z14);
    z4 = _mm512_ternarylogic_epi64(z4, z7, z6, 0x96);
    z9 = _mm512_srli_epi64(z4, 60);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z5 = _mm512_slli_epi64(z4, 4);
    z5 = _mm512_ternarylogic_epi64(z5, z10, z9, 0x96);
    z9 = _mm512_srli_epi64(z5, 60);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z6 = _mm512_slli_epi64(z5, 4);
    z6 = _mm512_ternarylogic_epi64(z6, z10, z9, 0x96);
    z9 = _mm512_srli_epi64(z6, 60);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z7 = _mm512_slli_epi64(z6, 4);
    z7 = _mm512_ternarylogic_epi64(z7, z10, z9, 0x96);
L_AES_XTS_encrypt_avx512_enc_256:
    /* 256 bytes of input */
    /* aes_enc_256 */
    rcx = (word64)(rdi + r13);
    rdx = (word64)(rsi + r13);
    z0 = _mm512_loadu_si512((const void*)WC_PR(rcx, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(rcx, 64));
    z2 = _mm512_loadu_si512((const void*)WC_PR(rcx, 128));
    z3 = _mm512_loadu_si512((const void*)WC_PR(rcx, 192));
    /* aes_enc_block */
    z0 = _mm512_ternarylogic_epi64(z0, z16, z4, 0x96);
    z1 = _mm512_ternarylogic_epi64(z1, z16, z5, 0x96);
    z2 = _mm512_ternarylogic_epi64(z2, z16, z6, 0x96);
    z3 = _mm512_ternarylogic_epi64(z3, z16, z7, 0x96);
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
    z0 = _mm512_aesenc_epi128(z0, z25);
    z1 = _mm512_aesenc_epi128(z1, z25);
    z2 = _mm512_aesenc_epi128(z2, z25);
    z3 = _mm512_aesenc_epi128(z3, z25);
    zf7 = (word32)r10;
    zf8 = 0xb;
    z9 = z26;
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_XTS_encrypt_avx512_aes_enc_256_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z26);
    z1 = _mm512_aesenc_epi128(z1, z26);
    z2 = _mm512_aesenc_epi128(z2, z26);
    z3 = _mm512_aesenc_epi128(z3, z26);
    z0 = _mm512_aesenc_epi128(z0, z27);
    z1 = _mm512_aesenc_epi128(z1, z27);
    z2 = _mm512_aesenc_epi128(z2, z27);
    z3 = _mm512_aesenc_epi128(z3, z27);
    zf9 = (word32)r10;
    zf10 = 0xd;
    z9 = z28;
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_XTS_encrypt_avx512_aes_enc_256_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z28);
    z1 = _mm512_aesenc_epi128(z1, z28);
    z2 = _mm512_aesenc_epi128(z2, z28);
    z3 = _mm512_aesenc_epi128(z3, z28);
    z0 = _mm512_aesenc_epi128(z0, z29);
    z1 = _mm512_aesenc_epi128(z1, z29);
    z2 = _mm512_aesenc_epi128(z2, z29);
    z3 = _mm512_aesenc_epi128(z3, z29);
    z9 = z30;
L_AES_XTS_encrypt_avx512_aes_enc_256_aes_enc_block_last:
    z0 = _mm512_aesenclast_epi128(z0, z9);
    z1 = _mm512_aesenclast_epi128(z1, z9);
    z2 = _mm512_aesenclast_epi128(z2, z9);
    z3 = _mm512_aesenclast_epi128(z3, z9);
    z0 = _mm512_xor_si512(z0, z4);
    _mm512_storeu_si512((void*)WC_PW(rdx, 0), z0);
    z9 = _mm512_srli_epi64(z4, 48);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z4 = _mm512_slli_epi64(z4, 16);
    z4 = _mm512_ternarylogic_epi64(z4, z10, z9, 0x96);
    z1 = _mm512_xor_si512(z1, z5);
    _mm512_storeu_si512((void*)WC_PW(rdx, 64), z1);
    z9 = _mm512_srli_epi64(z5, 48);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z5 = _mm512_slli_epi64(z5, 16);
    z5 = _mm512_ternarylogic_epi64(z5, z10, z9, 0x96);
    z2 = _mm512_xor_si512(z2, z6);
    _mm512_storeu_si512((void*)WC_PW(rdx, 128), z2);
    z9 = _mm512_srli_epi64(z6, 48);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z6 = _mm512_slli_epi64(z6, 16);
    z6 = _mm512_ternarylogic_epi64(z6, z10, z9, 0x96);
    z3 = _mm512_xor_si512(z3, z7);
    _mm512_storeu_si512((void*)WC_PW(rdx, 192), z3);
    z9 = _mm512_srli_epi64(z7, 48);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z7 = _mm512_slli_epi64(z7, 16);
    z7 = _mm512_ternarylogic_epi64(z7, z10, z9, 0x96);
    r13 = (word32)((word32)r13 + 0x100);
    if (((word32)r13) < ((word32)r11)) {
        goto L_AES_XTS_encrypt_avx512_enc_256;
    }
    z8 = _mm512_zextsi128_si512(_mm512_extracti32x4_epi32(z4, 0));
L_AES_XTS_encrypt_avx512_done_256:
    r11 = (word32)((word32)rax);
    r11 = (word32)((word32)r11 & 0xffffff80);
    if (((word32)r13) == ((word32)r11)) {
        goto L_AES_XTS_encrypt_avx512_done_128;
    }
    /* 128 bytes of input */
    /* aes_enc_128 */
    rcx = (word64)(rdi + r13);
    rdx = (word64)(rsi + r13);
    z0 = _mm512_loadu_si512((const void*)WC_PR(rcx, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(rcx, 64));
    z5 = _mm512_shuffle_i64x2(z8, z8, 0);
    z6 = _mm512_srlv_epi64(z5, z15);
    z7 = _mm512_clmulepi64_epi128(z6, z13, 1);
    z6 = _mm512_bslli_epi128(z6, 8);
    z4 = _mm512_sllv_epi64(z5, z14);
    z4 = _mm512_ternarylogic_epi64(z4, z7, z6, 0x96);
    z9 = _mm512_srli_epi64(z4, 60);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z5 = _mm512_slli_epi64(z4, 4);
    z5 = _mm512_ternarylogic_epi64(z5, z10, z9, 0x96);
    /* aes_enc_block */
    z0 = _mm512_ternarylogic_epi64(z0, z16, z4, 0x96);
    z1 = _mm512_ternarylogic_epi64(z1, z16, z5, 0x96);
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
    z0 = _mm512_aesenc_epi128(z0, z25);
    z1 = _mm512_aesenc_epi128(z1, z25);
    zf11 = (word32)r10;
    zf12 = 0xb;
    z9 = z26;
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_XTS_encrypt_avx512_aes_enc_128_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z26);
    z1 = _mm512_aesenc_epi128(z1, z26);
    z0 = _mm512_aesenc_epi128(z0, z27);
    z1 = _mm512_aesenc_epi128(z1, z27);
    zf13 = (word32)r10;
    zf14 = 0xd;
    z9 = z28;
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_XTS_encrypt_avx512_aes_enc_128_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z28);
    z1 = _mm512_aesenc_epi128(z1, z28);
    z0 = _mm512_aesenc_epi128(z0, z29);
    z1 = _mm512_aesenc_epi128(z1, z29);
    z9 = z30;
L_AES_XTS_encrypt_avx512_aes_enc_128_aes_enc_block_last:
    z0 = _mm512_aesenclast_epi128(z0, z9);
    z1 = _mm512_aesenclast_epi128(z1, z9);
    z0 = _mm512_xor_si512(z0, z4);
    _mm512_storeu_si512((void*)WC_PW(rdx, 0), z0);
    z1 = _mm512_xor_si512(z1, z5);
    _mm512_storeu_si512((void*)WC_PW(rdx, 64), z1);
    z8 = _mm512_zextsi128_si512(_mm512_extracti32x4_epi32(z5, 3));
    z9 = _mm512_zextsi128_si512(_mm_shuffle_epi32(_mm512_castsi512_si128(z8),
        0x13));
    z8 = _mm512_zextsi128_si512(_mm_add_epi64(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z8)));
    z9 = _mm512_zextsi128_si512(_mm_srai_epi32(_mm512_castsi512_si128(z9), 31));
    z8 = _mm512_zextsi128_si512(_mm_ternarylogic_epi32(_mm512_castsi512_si128(
        z8), _mm512_castsi512_si128(z9), x12, 0x78));
    r13 = (word32)((word32)r13 + 0x80);
L_AES_XTS_encrypt_avx512_done_128:
    r11 = (word32)((word32)rax);
    r11 = (word32)((word32)r11 & 0xffffffc0);
    if (((word32)r13) == ((word32)r11)) {
        goto L_AES_XTS_encrypt_avx512_done_64;
    }
    /* 64 bytes of input */
    /* aes_enc_64 */
    rcx = (word64)(rdi + r13);
    rdx = (word64)(rsi + r13);
    z0 = _mm512_loadu_si512((const void*)WC_PR(rcx, 0));
    z5 = _mm512_shuffle_i64x2(z8, z8, 0);
    z6 = _mm512_srlv_epi64(z5, z15);
    z7 = _mm512_clmulepi64_epi128(z6, z13, 1);
    z6 = _mm512_bslli_epi128(z6, 8);
    z4 = _mm512_sllv_epi64(z5, z14);
    z4 = _mm512_ternarylogic_epi64(z4, z7, z6, 0x96);
    /* aes_enc_block */
    z0 = _mm512_ternarylogic_epi64(z0, z16, z4, 0x96);
    z0 = _mm512_aesenc_epi128(z0, z17);
    z0 = _mm512_aesenc_epi128(z0, z18);
    z0 = _mm512_aesenc_epi128(z0, z19);
    z0 = _mm512_aesenc_epi128(z0, z20);
    z0 = _mm512_aesenc_epi128(z0, z21);
    z0 = _mm512_aesenc_epi128(z0, z22);
    z0 = _mm512_aesenc_epi128(z0, z23);
    z0 = _mm512_aesenc_epi128(z0, z24);
    z0 = _mm512_aesenc_epi128(z0, z25);
    zf15 = (word32)r10;
    zf16 = 0xb;
    z9 = z26;
    if ((sword32)(zf15) < (sword32)(zf16)) {
        goto L_AES_XTS_encrypt_avx512_aes_enc_64_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z26);
    z0 = _mm512_aesenc_epi128(z0, z27);
    zf17 = (word32)r10;
    zf18 = 0xd;
    z9 = z28;
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_XTS_encrypt_avx512_aes_enc_64_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z28);
    z0 = _mm512_aesenc_epi128(z0, z29);
    z9 = z30;
L_AES_XTS_encrypt_avx512_aes_enc_64_aes_enc_block_last:
    z0 = _mm512_aesenclast_epi128(z0, z9);
    z0 = _mm512_xor_si512(z0, z4);
    _mm512_storeu_si512((void*)WC_PW(rdx, 0), z0);
    z8 = _mm512_zextsi128_si512(_mm512_extracti32x4_epi32(z4, 3));
    z9 = _mm512_zextsi128_si512(_mm_shuffle_epi32(_mm512_castsi512_si128(z8),
        0x13));
    z8 = _mm512_zextsi128_si512(_mm_add_epi64(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z8)));
    z9 = _mm512_zextsi128_si512(_mm_srai_epi32(_mm512_castsi512_si128(z9), 31));
    z8 = _mm512_zextsi128_si512(_mm_ternarylogic_epi32(_mm512_castsi512_si128(
        z8), _mm512_castsi512_si128(z9), x12, 0x78));
    r13 = (word32)((word32)r13 + 0x40);
L_AES_XTS_encrypt_avx512_done_64:
    r11 = (word32)((word32)rax);
    r11 = (word32)((word32)r11 & 0xffffffe0);
    if (((word32)r13) == ((word32)r11)) {
        goto L_AES_XTS_encrypt_avx512_done_32;
    }
    /* 32 bytes of input */
    /* aes_enc_32 */
    rcx = (word64)(rdi + r13);
    rdx = (word64)(rsi + r13);
    z0 = _mm512_zextsi256_si512(_mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        0)));
    z5 = _mm512_shuffle_i64x2(z8, z8, 0);
    z6 = _mm512_srlv_epi64(z5, z15);
    z7 = _mm512_clmulepi64_epi128(z6, z13, 1);
    z6 = _mm512_bslli_epi128(z6, 8);
    z4 = _mm512_sllv_epi64(z5, z14);
    z4 = _mm512_ternarylogic_epi64(z4, z7, z6, 0x96);
    /* aes_enc_block */
    z0 = _mm512_zextsi256_si512(_mm256_ternarylogic_epi64(
        _mm512_castsi512_si256(z0), _mm512_castsi512_si256(z16),
        _mm512_castsi512_si256(z4), 0x96));
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
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z25)));
    zf19 = (word32)r10;
    zf20 = 0xb;
    z9 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z26));
    if ((sword32)(zf19) < (sword32)(zf20)) {
        goto L_AES_XTS_encrypt_avx512_aes_enc_32_aes_enc_block_last;
    }
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z26)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z27)));
    zf21 = (word32)r10;
    zf22 = 0xd;
    z9 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z28));
    if ((sword32)(zf21) < (sword32)(zf22)) {
        goto L_AES_XTS_encrypt_avx512_aes_enc_32_aes_enc_block_last;
    }
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z28)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z29)));
    z9 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z30));
L_AES_XTS_encrypt_avx512_aes_enc_32_aes_enc_block_last:
    z0 = _mm512_zextsi256_si512(_mm256_aesenclast_epi128(_mm512_castsi512_si256(
        z0), _mm512_castsi512_si256(z9)));
    z0 = _mm512_zextsi256_si512(_mm256_xor_si256(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z4)));
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 0), _mm512_castsi512_si256(z0));
    z8 = _mm512_zextsi128_si512(_mm512_extracti32x4_epi32(z4, 2));
    r13 = (word32)((word32)r13 + 0x20);
L_AES_XTS_encrypt_avx512_done_32:
    zf23 = (word32)r13;
    zf24 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf23) == (zf24)) {
        goto L_AES_XTS_encrypt_avx512_done_enc;
    }
    r11 = (word32)((word32)r11 - (word32)r13);
    zf25 = (word32)r11;
    zf26 = 0x10;
    r11 = (word32)((word32)rax);
    if ((zf25) < (zf26)) {
        goto L_AES_XTS_encrypt_avx512_last_15;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    /* 16 bytes of input */
L_AES_XTS_encrypt_avx512_enc_16:
    rcx = (word64)(rdi + r13);
    z0 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z8)));
    /* aes_enc_block */
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm_loadu_si128((const __m128i*)WC_PR(r8, 0))));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 16)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 32)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 48)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 64)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 80)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 96)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    zf27 = (word32)r10;
    zf28 = 0xb;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf27) < (sword32)(zf28)) {
        goto L_AES_XTS_encrypt_avx512_aes_enc_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    zf29 = (word32)r10;
    zf30 = 0xd;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf29) < (sword32)(zf30)) {
        goto L_AES_XTS_encrypt_avx512_aes_enc_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_XTS_encrypt_avx512_aes_enc_block_last:
    z0 = _mm512_zextsi128_si512(_mm_aesenclast_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z8)));
    rcx = (word64)(rsi + r13);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), _mm512_castsi512_si128(z0));
    z4 = _mm512_zextsi128_si512(_mm_shuffle_epi32(_mm512_castsi512_si128(z8),
        0x13));
    z8 = _mm512_zextsi128_si512(_mm_add_epi64(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z8)));
    z4 = _mm512_zextsi128_si512(_mm_srai_epi32(_mm512_castsi512_si128(z4), 31));
    z8 = _mm512_zextsi128_si512(_mm_ternarylogic_epi32(_mm512_castsi512_si128(
        z8), _mm512_castsi512_si128(z4), x12, 0x78));
    r13 = (word32)((word32)r13 + 0x10);
    if (((word32)r13) < ((word32)r11)) {
        goto L_AES_XTS_encrypt_avx512_enc_16;
    }
    if (((word32)r13) == ((word32)rax)) {
        goto L_AES_XTS_encrypt_avx512_done_enc;
    }
L_AES_XTS_encrypt_avx512_last_15:
    r13 = (word64)(r13 - 0x10);
    rcx = (word64)(rsi + r13);
    z0 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    r13 = (word64)(r13 + 0x10);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), _mm512_castsi512_si128(z0));
    rdx = (word64)(0);
L_AES_XTS_encrypt_avx512_last_15_byte_loop:
    r11 = (r11 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, rdx)) & 0xff);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, r13)) & 0xff);
    WC_S8(rsi, r13) = (byte)((byte)r11);
    WC_S8(rsp, rdx) = (byte)((byte)rcx);
    r13 = (word32)((word32)r13 + 1);
    rdx = (word32)((word32)rdx + 1);
    if (((word32)r13) < ((word32)rax)) {
        goto L_AES_XTS_encrypt_avx512_last_15_byte_loop;
    }
    r13 = (word64)(r13 - rdx);
    z0 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rsp, 0)));
    r13 = (word64)(r13 - 0x10);
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z8)));
    /* aes_enc_block */
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm_loadu_si128((const __m128i*)WC_PR(r8, 0))));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 16)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 32)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 48)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 64)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 80)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 96)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    zf31 = (word32)r10;
    zf32 = 0xb;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf31) < (sword32)(zf32)) {
        goto L_AES_XTS_encrypt_avx512_last_15_aes_enc_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    zf33 = (word32)r10;
    zf34 = 0xd;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf33) < (sword32)(zf34)) {
        goto L_AES_XTS_encrypt_avx512_last_15_aes_enc_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_XTS_encrypt_avx512_last_15_aes_enc_block_last:
    z0 = _mm512_zextsi128_si512(_mm_aesenclast_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z8)));
    rcx = (word64)(rsi + r13);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), _mm512_castsi512_si128(z0));
L_AES_XTS_encrypt_avx512_done_enc:
    ;
}

WC_X64I_TARGET("aes,vaes,pclmul,vpclmulqdq,avx512f,avx512vl,avx512bw")
WOLFSSL_LOCAL void AES_XTS_encrypt_update_avx512(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* key,
    unsigned char* tweak_block, int nr)
{
    word64 rdi, rsi, rax, r10, r8, r9, rsp, r12, r11 = 0, rcx = 0, rdx = 0;
    __m128i x12;
    __m512i z0 = _mm512_setzero_si512(), z1 = _mm512_setzero_si512(),
            z2 = _mm512_setzero_si512(), z3 = _mm512_setzero_si512(),
            z4 = _mm512_setzero_si512(), z5 = _mm512_setzero_si512(),
            z6 = _mm512_setzero_si512(), z7 = _mm512_setzero_si512(), z8,
            z9 = _mm512_setzero_si512(), z10 = _mm512_setzero_si512(), z13,
            z14, z15, z16 = _mm512_setzero_si512(),
            z17 = _mm512_setzero_si512(), z18 = _mm512_setzero_si512(),
            z19 = _mm512_setzero_si512(), z20 = _mm512_setzero_si512(),
            z21 = _mm512_setzero_si512(), z22 = _mm512_setzero_si512(),
            z23 = _mm512_setzero_si512(), z24 = _mm512_setzero_si512(),
            z25 = _mm512_setzero_si512(), z26 = _mm512_setzero_si512(),
            z27 = _mm512_setzero_si512(), z28 = _mm512_setzero_si512(),
            z29 = _mm512_setzero_si512(), z30 = _mm512_setzero_si512();
    XALIGNED(32) WC_X64I_SLOT stk[8];
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
    word32 zf25;
    word32 zf26;
    word32 zf27;
    word32 zf28;
    word32 zf29;
    word32 zf30;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rax = (word64)(word32)nbytes;
    r10 = (word64)(size_t)key;
    r8 = (word64)(size_t)tweak_block;
    r9 = (word64)(word32)nr;

    rsp = (word64)(size_t)stk + 64;
    rsp = (word64)(rsp - 64);
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(L_avx512_aes_xts_gc_xts, 0));
    z13 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(
        L_avx512_aes_xts_poly, 0)));
    z14 = _mm512_loadu_si512((const void*)WC_PR(L_avx512_aes_xts_shl, 0));
    z15 = _mm512_loadu_si512((const void*)WC_PR(L_avx512_aes_xts_shr, 0));
    z8 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    r12 = (word32)(0);
    if (((word32)rax) < (0x20)) {
        goto L_AES_XTS_encrypt_update_avx512_done_128;
    }
    z16 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        0)));
    z17 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        16)));
    z18 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        32)));
    z19 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        48)));
    z20 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        64)));
    z21 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        80)));
    z22 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        96)));
    z23 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        112)));
    z24 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        128)));
    z25 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        144)));
    z26 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        160)));
    if ((sword32)((word32)r9) < (sword32)(0xb)) {
        goto L_AES_XTS_encrypt_update_avx512_key_cached;
    }
    z27 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        176)));
    z28 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        192)));
    if ((sword32)((word32)r9) < (sword32)(0xd)) {
        goto L_AES_XTS_encrypt_update_avx512_key_cached;
    }
    z29 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        208)));
    z30 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        224)));
L_AES_XTS_encrypt_update_avx512_key_cached:
    zf1 = (word32)rax;
    zf2 = 0x100;
    r11 = (word32)((word32)rax);
    if ((zf1) < (zf2)) {
        goto L_AES_XTS_encrypt_update_avx512_done_256;
    }
    r11 = (word32)((word32)r11 & 0xffffff00);
    z5 = _mm512_shuffle_i64x2(z8, z8, 0);
    z6 = _mm512_srlv_epi64(z5, z15);
    z7 = _mm512_clmulepi64_epi128(z6, z13, 1);
    z6 = _mm512_bslli_epi128(z6, 8);
    z4 = _mm512_sllv_epi64(z5, z14);
    z4 = _mm512_ternarylogic_epi64(z4, z7, z6, 0x96);
    z9 = _mm512_srli_epi64(z4, 60);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z5 = _mm512_slli_epi64(z4, 4);
    z5 = _mm512_ternarylogic_epi64(z5, z10, z9, 0x96);
    z9 = _mm512_srli_epi64(z5, 60);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z6 = _mm512_slli_epi64(z5, 4);
    z6 = _mm512_ternarylogic_epi64(z6, z10, z9, 0x96);
    z9 = _mm512_srli_epi64(z6, 60);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z7 = _mm512_slli_epi64(z6, 4);
    z7 = _mm512_ternarylogic_epi64(z7, z10, z9, 0x96);
L_AES_XTS_encrypt_update_avx512_enc_256:
    /* 256 bytes of input */
    /* aes_enc_256 */
    rcx = (word64)(rdi + r12);
    rdx = (word64)(rsi + r12);
    z0 = _mm512_loadu_si512((const void*)WC_PR(rcx, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(rcx, 64));
    z2 = _mm512_loadu_si512((const void*)WC_PR(rcx, 128));
    z3 = _mm512_loadu_si512((const void*)WC_PR(rcx, 192));
    /* aes_enc_block */
    z0 = _mm512_ternarylogic_epi64(z0, z16, z4, 0x96);
    z1 = _mm512_ternarylogic_epi64(z1, z16, z5, 0x96);
    z2 = _mm512_ternarylogic_epi64(z2, z16, z6, 0x96);
    z3 = _mm512_ternarylogic_epi64(z3, z16, z7, 0x96);
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
    z0 = _mm512_aesenc_epi128(z0, z25);
    z1 = _mm512_aesenc_epi128(z1, z25);
    z2 = _mm512_aesenc_epi128(z2, z25);
    z3 = _mm512_aesenc_epi128(z3, z25);
    zf3 = (word32)r9;
    zf4 = 0xb;
    z9 = z26;
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_encrypt_update_avx512_aes_enc_256_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z26);
    z1 = _mm512_aesenc_epi128(z1, z26);
    z2 = _mm512_aesenc_epi128(z2, z26);
    z3 = _mm512_aesenc_epi128(z3, z26);
    z0 = _mm512_aesenc_epi128(z0, z27);
    z1 = _mm512_aesenc_epi128(z1, z27);
    z2 = _mm512_aesenc_epi128(z2, z27);
    z3 = _mm512_aesenc_epi128(z3, z27);
    zf5 = (word32)r9;
    zf6 = 0xd;
    z9 = z28;
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_XTS_encrypt_update_avx512_aes_enc_256_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z28);
    z1 = _mm512_aesenc_epi128(z1, z28);
    z2 = _mm512_aesenc_epi128(z2, z28);
    z3 = _mm512_aesenc_epi128(z3, z28);
    z0 = _mm512_aesenc_epi128(z0, z29);
    z1 = _mm512_aesenc_epi128(z1, z29);
    z2 = _mm512_aesenc_epi128(z2, z29);
    z3 = _mm512_aesenc_epi128(z3, z29);
    z9 = z30;
L_AES_XTS_encrypt_update_avx512_aes_enc_256_aes_enc_block_last:
    z0 = _mm512_aesenclast_epi128(z0, z9);
    z1 = _mm512_aesenclast_epi128(z1, z9);
    z2 = _mm512_aesenclast_epi128(z2, z9);
    z3 = _mm512_aesenclast_epi128(z3, z9);
    z0 = _mm512_xor_si512(z0, z4);
    _mm512_storeu_si512((void*)WC_PW(rdx, 0), z0);
    z9 = _mm512_srli_epi64(z4, 48);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z4 = _mm512_slli_epi64(z4, 16);
    z4 = _mm512_ternarylogic_epi64(z4, z10, z9, 0x96);
    z1 = _mm512_xor_si512(z1, z5);
    _mm512_storeu_si512((void*)WC_PW(rdx, 64), z1);
    z9 = _mm512_srli_epi64(z5, 48);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z5 = _mm512_slli_epi64(z5, 16);
    z5 = _mm512_ternarylogic_epi64(z5, z10, z9, 0x96);
    z2 = _mm512_xor_si512(z2, z6);
    _mm512_storeu_si512((void*)WC_PW(rdx, 128), z2);
    z9 = _mm512_srli_epi64(z6, 48);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z6 = _mm512_slli_epi64(z6, 16);
    z6 = _mm512_ternarylogic_epi64(z6, z10, z9, 0x96);
    z3 = _mm512_xor_si512(z3, z7);
    _mm512_storeu_si512((void*)WC_PW(rdx, 192), z3);
    z9 = _mm512_srli_epi64(z7, 48);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z7 = _mm512_slli_epi64(z7, 16);
    z7 = _mm512_ternarylogic_epi64(z7, z10, z9, 0x96);
    r12 = (word32)((word32)r12 + 0x100);
    if (((word32)r12) < ((word32)r11)) {
        goto L_AES_XTS_encrypt_update_avx512_enc_256;
    }
    z8 = _mm512_zextsi128_si512(_mm512_extracti32x4_epi32(z4, 0));
L_AES_XTS_encrypt_update_avx512_done_256:
    r11 = (word32)((word32)rax);
    r11 = (word32)((word32)r11 & 0xffffff80);
    if (((word32)r12) == ((word32)r11)) {
        goto L_AES_XTS_encrypt_update_avx512_done_128;
    }
    /* 128 bytes of input */
    /* aes_enc_128 */
    rcx = (word64)(rdi + r12);
    rdx = (word64)(rsi + r12);
    z0 = _mm512_loadu_si512((const void*)WC_PR(rcx, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(rcx, 64));
    z5 = _mm512_shuffle_i64x2(z8, z8, 0);
    z6 = _mm512_srlv_epi64(z5, z15);
    z7 = _mm512_clmulepi64_epi128(z6, z13, 1);
    z6 = _mm512_bslli_epi128(z6, 8);
    z4 = _mm512_sllv_epi64(z5, z14);
    z4 = _mm512_ternarylogic_epi64(z4, z7, z6, 0x96);
    z9 = _mm512_srli_epi64(z4, 60);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z5 = _mm512_slli_epi64(z4, 4);
    z5 = _mm512_ternarylogic_epi64(z5, z10, z9, 0x96);
    /* aes_enc_block */
    z0 = _mm512_ternarylogic_epi64(z0, z16, z4, 0x96);
    z1 = _mm512_ternarylogic_epi64(z1, z16, z5, 0x96);
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
    z0 = _mm512_aesenc_epi128(z0, z25);
    z1 = _mm512_aesenc_epi128(z1, z25);
    zf7 = (word32)r9;
    zf8 = 0xb;
    z9 = z26;
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_XTS_encrypt_update_avx512_aes_enc_128_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z26);
    z1 = _mm512_aesenc_epi128(z1, z26);
    z0 = _mm512_aesenc_epi128(z0, z27);
    z1 = _mm512_aesenc_epi128(z1, z27);
    zf9 = (word32)r9;
    zf10 = 0xd;
    z9 = z28;
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_XTS_encrypt_update_avx512_aes_enc_128_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z28);
    z1 = _mm512_aesenc_epi128(z1, z28);
    z0 = _mm512_aesenc_epi128(z0, z29);
    z1 = _mm512_aesenc_epi128(z1, z29);
    z9 = z30;
L_AES_XTS_encrypt_update_avx512_aes_enc_128_aes_enc_block_last:
    z0 = _mm512_aesenclast_epi128(z0, z9);
    z1 = _mm512_aesenclast_epi128(z1, z9);
    z0 = _mm512_xor_si512(z0, z4);
    _mm512_storeu_si512((void*)WC_PW(rdx, 0), z0);
    z1 = _mm512_xor_si512(z1, z5);
    _mm512_storeu_si512((void*)WC_PW(rdx, 64), z1);
    z8 = _mm512_zextsi128_si512(_mm512_extracti32x4_epi32(z5, 3));
    z9 = _mm512_zextsi128_si512(_mm_shuffle_epi32(_mm512_castsi512_si128(z8),
        0x13));
    z8 = _mm512_zextsi128_si512(_mm_add_epi64(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z8)));
    z9 = _mm512_zextsi128_si512(_mm_srai_epi32(_mm512_castsi512_si128(z9), 31));
    z8 = _mm512_zextsi128_si512(_mm_ternarylogic_epi32(_mm512_castsi512_si128(
        z8), _mm512_castsi512_si128(z9), x12, 0x78));
    r12 = (word32)((word32)r12 + 0x80);
L_AES_XTS_encrypt_update_avx512_done_128:
    r11 = (word32)((word32)rax);
    r11 = (word32)((word32)r11 & 0xffffffc0);
    if (((word32)r12) == ((word32)r11)) {
        goto L_AES_XTS_encrypt_update_avx512_done_64;
    }
    /* 64 bytes of input */
    /* aes_enc_64 */
    rcx = (word64)(rdi + r12);
    rdx = (word64)(rsi + r12);
    z0 = _mm512_loadu_si512((const void*)WC_PR(rcx, 0));
    z5 = _mm512_shuffle_i64x2(z8, z8, 0);
    z6 = _mm512_srlv_epi64(z5, z15);
    z7 = _mm512_clmulepi64_epi128(z6, z13, 1);
    z6 = _mm512_bslli_epi128(z6, 8);
    z4 = _mm512_sllv_epi64(z5, z14);
    z4 = _mm512_ternarylogic_epi64(z4, z7, z6, 0x96);
    /* aes_enc_block */
    z0 = _mm512_ternarylogic_epi64(z0, z16, z4, 0x96);
    z0 = _mm512_aesenc_epi128(z0, z17);
    z0 = _mm512_aesenc_epi128(z0, z18);
    z0 = _mm512_aesenc_epi128(z0, z19);
    z0 = _mm512_aesenc_epi128(z0, z20);
    z0 = _mm512_aesenc_epi128(z0, z21);
    z0 = _mm512_aesenc_epi128(z0, z22);
    z0 = _mm512_aesenc_epi128(z0, z23);
    z0 = _mm512_aesenc_epi128(z0, z24);
    z0 = _mm512_aesenc_epi128(z0, z25);
    zf11 = (word32)r9;
    zf12 = 0xb;
    z9 = z26;
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_XTS_encrypt_update_avx512_aes_enc_64_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z26);
    z0 = _mm512_aesenc_epi128(z0, z27);
    zf13 = (word32)r9;
    zf14 = 0xd;
    z9 = z28;
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_XTS_encrypt_update_avx512_aes_enc_64_aes_enc_block_last;
    }
    z0 = _mm512_aesenc_epi128(z0, z28);
    z0 = _mm512_aesenc_epi128(z0, z29);
    z9 = z30;
L_AES_XTS_encrypt_update_avx512_aes_enc_64_aes_enc_block_last:
    z0 = _mm512_aesenclast_epi128(z0, z9);
    z0 = _mm512_xor_si512(z0, z4);
    _mm512_storeu_si512((void*)WC_PW(rdx, 0), z0);
    z8 = _mm512_zextsi128_si512(_mm512_extracti32x4_epi32(z4, 3));
    z9 = _mm512_zextsi128_si512(_mm_shuffle_epi32(_mm512_castsi512_si128(z8),
        0x13));
    z8 = _mm512_zextsi128_si512(_mm_add_epi64(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z8)));
    z9 = _mm512_zextsi128_si512(_mm_srai_epi32(_mm512_castsi512_si128(z9), 31));
    z8 = _mm512_zextsi128_si512(_mm_ternarylogic_epi32(_mm512_castsi512_si128(
        z8), _mm512_castsi512_si128(z9), x12, 0x78));
    r12 = (word32)((word32)r12 + 0x40);
L_AES_XTS_encrypt_update_avx512_done_64:
    r11 = (word32)((word32)rax);
    r11 = (word32)((word32)r11 & 0xffffffe0);
    if (((word32)r12) == ((word32)r11)) {
        goto L_AES_XTS_encrypt_update_avx512_done_32;
    }
    /* 32 bytes of input */
    /* aes_enc_32 */
    rcx = (word64)(rdi + r12);
    rdx = (word64)(rsi + r12);
    z0 = _mm512_zextsi256_si512(_mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        0)));
    z5 = _mm512_shuffle_i64x2(z8, z8, 0);
    z6 = _mm512_srlv_epi64(z5, z15);
    z7 = _mm512_clmulepi64_epi128(z6, z13, 1);
    z6 = _mm512_bslli_epi128(z6, 8);
    z4 = _mm512_sllv_epi64(z5, z14);
    z4 = _mm512_ternarylogic_epi64(z4, z7, z6, 0x96);
    /* aes_enc_block */
    z0 = _mm512_zextsi256_si512(_mm256_ternarylogic_epi64(
        _mm512_castsi512_si256(z0), _mm512_castsi512_si256(z16),
        _mm512_castsi512_si256(z4), 0x96));
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
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z25)));
    zf15 = (word32)r9;
    zf16 = 0xb;
    z9 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z26));
    if ((sword32)(zf15) < (sword32)(zf16)) {
        goto L_AES_XTS_encrypt_update_avx512_aes_enc_32_aes_enc_block_last;
    }
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z26)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z27)));
    zf17 = (word32)r9;
    zf18 = 0xd;
    z9 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z28));
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_XTS_encrypt_update_avx512_aes_enc_32_aes_enc_block_last;
    }
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z28)));
    z0 = _mm512_zextsi256_si512(_mm256_aesenc_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z29)));
    z9 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z30));
L_AES_XTS_encrypt_update_avx512_aes_enc_32_aes_enc_block_last:
    z0 = _mm512_zextsi256_si512(_mm256_aesenclast_epi128(_mm512_castsi512_si256(
        z0), _mm512_castsi512_si256(z9)));
    z0 = _mm512_zextsi256_si512(_mm256_xor_si256(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z4)));
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 0), _mm512_castsi512_si256(z0));
    z8 = _mm512_zextsi128_si512(_mm512_extracti32x4_epi32(z4, 2));
    r12 = (word32)((word32)r12 + 0x20);
L_AES_XTS_encrypt_update_avx512_done_32:
    zf19 = (word32)r12;
    zf20 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf19) == (zf20)) {
        goto L_AES_XTS_encrypt_update_avx512_done_enc;
    }
    r11 = (word32)((word32)r11 - (word32)r12);
    zf21 = (word32)r11;
    zf22 = 0x10;
    r11 = (word32)((word32)rax);
    if ((zf21) < (zf22)) {
        goto L_AES_XTS_encrypt_update_avx512_last_15;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    /* 16 bytes of input */
L_AES_XTS_encrypt_update_avx512_enc_16:
    rcx = (word64)(rdi + r12);
    z0 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z8)));
    /* aes_enc_block */
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm_loadu_si128((const __m128i*)WC_PR(r10, 0))));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        16)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        32)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        48)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        64)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        80)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        96)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        112)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        128)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        144)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    zf23 = (word32)r9;
    zf24 = 0xb;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        160)));
    if ((sword32)(zf23) < (sword32)(zf24)) {
        goto L_AES_XTS_encrypt_update_avx512_aes_enc_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        176)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    zf25 = (word32)r9;
    zf26 = 0xd;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        192)));
    if ((sword32)(zf25) < (sword32)(zf26)) {
        goto L_AES_XTS_encrypt_update_avx512_aes_enc_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        208)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        224)));
L_AES_XTS_encrypt_update_avx512_aes_enc_block_last:
    z0 = _mm512_zextsi128_si512(_mm_aesenclast_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z8)));
    rcx = (word64)(rsi + r12);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), _mm512_castsi512_si128(z0));
    z4 = _mm512_zextsi128_si512(_mm_shuffle_epi32(_mm512_castsi512_si128(z8),
        0x13));
    z8 = _mm512_zextsi128_si512(_mm_add_epi64(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z8)));
    z4 = _mm512_zextsi128_si512(_mm_srai_epi32(_mm512_castsi512_si128(z4), 31));
    z8 = _mm512_zextsi128_si512(_mm_ternarylogic_epi32(_mm512_castsi512_si128(
        z8), _mm512_castsi512_si128(z4), x12, 0x78));
    r12 = (word32)((word32)r12 + 0x10);
    if (((word32)r12) < ((word32)r11)) {
        goto L_AES_XTS_encrypt_update_avx512_enc_16;
    }
    if (((word32)r12) == ((word32)rax)) {
        goto L_AES_XTS_encrypt_update_avx512_done_enc;
    }
L_AES_XTS_encrypt_update_avx512_last_15:
    r12 = (word64)(r12 - 0x10);
    rcx = (word64)(rsi + r12);
    z0 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    r12 = (word64)(r12 + 0x10);
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), _mm512_castsi512_si128(z0));
    rdx = (word64)(0);
L_AES_XTS_encrypt_update_avx512_last_15_byte_loop:
    r11 = (r11 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, rdx)) & 0xff);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, r12)) & 0xff);
    WC_S8(rsi, r12) = (byte)((byte)r11);
    WC_S8(rsp, rdx) = (byte)((byte)rcx);
    r12 = (word32)((word32)r12 + 1);
    rdx = (word32)((word32)rdx + 1);
    if (((word32)r12) < ((word32)rax)) {
        goto L_AES_XTS_encrypt_update_avx512_last_15_byte_loop;
    }
    r12 = (word64)(r12 - rdx);
    z0 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rsp, 0)));
    r12 = (word64)(r12 - 0x10);
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z8)));
    /* aes_enc_block */
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm_loadu_si128((const __m128i*)WC_PR(r10, 0))));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        16)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        32)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        48)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        64)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        80)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        96)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        112)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        128)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        144)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    zf27 = (word32)r9;
    zf28 = 0xb;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        160)));
    if ((sword32)(zf27) < (sword32)(zf28)) {
        goto L_AES_XTS_encrypt_update_avx512_last_15_aes_enc_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        176)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    zf29 = (word32)r9;
    zf30 = 0xd;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        192)));
    if ((sword32)(zf29) < (sword32)(zf30)) {
        goto L_AES_XTS_encrypt_update_avx512_last_15_aes_enc_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        208)));
    z0 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        224)));
L_AES_XTS_encrypt_update_avx512_last_15_aes_enc_block_last:
    z0 = _mm512_zextsi128_si512(_mm_aesenclast_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z8)));
    rcx = (word64)(rsi + r12);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), _mm512_castsi512_si128(z0));
L_AES_XTS_encrypt_update_avx512_done_enc:
    _mm_storeu_si128((__m128i*)WC_PW(r8, 0), _mm512_castsi512_si128(z8));
}

WC_X64I_TARGET("aes,vaes,pclmul,vpclmulqdq,avx512f,avx512vl,avx512bw")
WOLFSSL_LOCAL void AES_XTS_decrypt_avx512(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* i,
    const unsigned char* key, const unsigned char* key2, int nr)
{
    word64 rdi, rsi, rax, r12, r8, r9, r10, rsp, r13 = 0, r11 = 0, rcx = 0,
           rdx = 0;
    __m128i x12;
    __m512i z0 = _mm512_setzero_si512(), z1 = _mm512_setzero_si512(),
            z2 = _mm512_setzero_si512(), z3 = _mm512_setzero_si512(),
            z4 = _mm512_setzero_si512(), z5, z6 = _mm512_setzero_si512(),
            z7 = _mm512_setzero_si512(), z8, z9 = _mm512_setzero_si512(),
            z10 = _mm512_setzero_si512(), z13, z14, z15,
            z16 = _mm512_setzero_si512(), z17 = _mm512_setzero_si512(),
            z18 = _mm512_setzero_si512(), z19 = _mm512_setzero_si512(),
            z20 = _mm512_setzero_si512(), z21 = _mm512_setzero_si512(),
            z22 = _mm512_setzero_si512(), z23 = _mm512_setzero_si512(),
            z24 = _mm512_setzero_si512(), z25 = _mm512_setzero_si512(),
            z26 = _mm512_setzero_si512(), z27 = _mm512_setzero_si512(),
            z28 = _mm512_setzero_si512(), z29 = _mm512_setzero_si512(),
            z30 = _mm512_setzero_si512();
    XALIGNED(32) WC_X64I_SLOT stk[8];
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
    word32 zf25;
    word32 zf26;
    word32 zf27;
    word32 zf28;
    word32 zf29;
    word32 zf30;
    word32 zf31;
    word32 zf32;
    word32 zf33;
    word32 zf34;
    word32 zf35;
    word32 zf36;
    word32 zf37;
    word32 zf38;
    word32 zf39;
    word32 zf40;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rax = (word64)(word32)nbytes;
    r12 = (word64)(size_t)i;
    r8 = (word64)(size_t)key;
    r9 = (word64)(size_t)key2;
    r10 = (word64)(word32)nr;

    rsp = (word64)(size_t)stk + 64;
    rsp = (word64)(rsp - 64);
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(L_avx512_aes_xts_gc_xts, 0));
    z13 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(
        L_avx512_aes_xts_poly, 0)));
    z14 = _mm512_loadu_si512((const void*)WC_PR(L_avx512_aes_xts_shl, 0));
    z15 = _mm512_loadu_si512((const void*)WC_PR(L_avx512_aes_xts_shr, 0));
    z8 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r12, 0)));
    /* aes_enc_block */
    z8 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z8),
        _mm_loadu_si128((const __m128i*)WC_PR(r9, 0))));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9, 16)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9, 32)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9, 48)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9, 64)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9, 80)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9, 96)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        112)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        128)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        144)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    zf1 = (word32)r10;
    zf2 = 0xb;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        160)));
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_XTS_decrypt_avx512_tweak_aes_enc_block_last;
    }
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        176)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z6)));
    zf3 = (word32)r10;
    zf4 = 0xd;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        192)));
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_decrypt_avx512_tweak_aes_enc_block_last;
    }
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        208)));
    z8 = _mm512_zextsi128_si512(_mm_aesenc_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z6)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r9,
        224)));
L_AES_XTS_decrypt_avx512_tweak_aes_enc_block_last:
    z8 = _mm512_zextsi128_si512(_mm_aesenclast_si128(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z5)));
    r13 = (word32)(0);
    r11 = (word32)((word32)rax);
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_avx512_mul16_256;
    }
    r11 = (word32)((word32)r11 - 0x10);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_avx512_last_31_start;
    }
L_AES_XTS_decrypt_avx512_mul16_256:
    if (((word32)r11) < (0x20)) {
        goto L_AES_XTS_decrypt_avx512_done_128;
    }
    z16 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    z17 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        16)));
    z18 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        32)));
    z19 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        48)));
    z20 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        64)));
    z21 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        80)));
    z22 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        96)));
    z23 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    z24 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    z25 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    z26 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)((word32)r10) < (sword32)(0xb)) {
        goto L_AES_XTS_decrypt_avx512_key_cached;
    }
    z27 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    z28 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)((word32)r10) < (sword32)(0xd)) {
        goto L_AES_XTS_decrypt_avx512_key_cached;
    }
    z29 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    z30 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_XTS_decrypt_avx512_key_cached:
    if (((word32)r11) < (0x100)) {
        goto L_AES_XTS_decrypt_avx512_done_256;
    }
    r11 = (word32)((word32)r11 & 0xffffff00);
    z5 = _mm512_shuffle_i64x2(z8, z8, 0);
    z6 = _mm512_srlv_epi64(z5, z15);
    z7 = _mm512_clmulepi64_epi128(z6, z13, 1);
    z6 = _mm512_bslli_epi128(z6, 8);
    z4 = _mm512_sllv_epi64(z5, z14);
    z4 = _mm512_ternarylogic_epi64(z4, z7, z6, 0x96);
    z9 = _mm512_srli_epi64(z4, 60);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z5 = _mm512_slli_epi64(z4, 4);
    z5 = _mm512_ternarylogic_epi64(z5, z10, z9, 0x96);
    z9 = _mm512_srli_epi64(z5, 60);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z6 = _mm512_slli_epi64(z5, 4);
    z6 = _mm512_ternarylogic_epi64(z6, z10, z9, 0x96);
    z9 = _mm512_srli_epi64(z6, 60);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z7 = _mm512_slli_epi64(z6, 4);
    z7 = _mm512_ternarylogic_epi64(z7, z10, z9, 0x96);
L_AES_XTS_decrypt_avx512_dec_256:
    /* 256 bytes of input */
    /* aes_dec_256 */
    rcx = (word64)(rdi + r13);
    rdx = (word64)(rsi + r13);
    z0 = _mm512_loadu_si512((const void*)WC_PR(rcx, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(rcx, 64));
    z2 = _mm512_loadu_si512((const void*)WC_PR(rcx, 128));
    z3 = _mm512_loadu_si512((const void*)WC_PR(rcx, 192));
    /* aes_dec_block */
    z0 = _mm512_ternarylogic_epi64(z0, z16, z4, 0x96);
    z1 = _mm512_ternarylogic_epi64(z1, z16, z5, 0x96);
    z2 = _mm512_ternarylogic_epi64(z2, z16, z6, 0x96);
    z3 = _mm512_ternarylogic_epi64(z3, z16, z7, 0x96);
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
    z0 = _mm512_aesdec_epi128(z0, z24);
    z1 = _mm512_aesdec_epi128(z1, z24);
    z2 = _mm512_aesdec_epi128(z2, z24);
    z3 = _mm512_aesdec_epi128(z3, z24);
    z0 = _mm512_aesdec_epi128(z0, z25);
    z1 = _mm512_aesdec_epi128(z1, z25);
    z2 = _mm512_aesdec_epi128(z2, z25);
    z3 = _mm512_aesdec_epi128(z3, z25);
    zf5 = (word32)r10;
    zf6 = 0xb;
    z9 = z26;
    if ((sword32)(zf5) < (sword32)(zf6)) {
        goto L_AES_XTS_decrypt_avx512_aes_dec_256_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z26);
    z1 = _mm512_aesdec_epi128(z1, z26);
    z2 = _mm512_aesdec_epi128(z2, z26);
    z3 = _mm512_aesdec_epi128(z3, z26);
    z0 = _mm512_aesdec_epi128(z0, z27);
    z1 = _mm512_aesdec_epi128(z1, z27);
    z2 = _mm512_aesdec_epi128(z2, z27);
    z3 = _mm512_aesdec_epi128(z3, z27);
    zf7 = (word32)r10;
    zf8 = 0xd;
    z9 = z28;
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_XTS_decrypt_avx512_aes_dec_256_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z28);
    z1 = _mm512_aesdec_epi128(z1, z28);
    z2 = _mm512_aesdec_epi128(z2, z28);
    z3 = _mm512_aesdec_epi128(z3, z28);
    z0 = _mm512_aesdec_epi128(z0, z29);
    z1 = _mm512_aesdec_epi128(z1, z29);
    z2 = _mm512_aesdec_epi128(z2, z29);
    z3 = _mm512_aesdec_epi128(z3, z29);
    z9 = z30;
L_AES_XTS_decrypt_avx512_aes_dec_256_aes_dec_block_last:
    z0 = _mm512_aesdeclast_epi128(z0, z9);
    z1 = _mm512_aesdeclast_epi128(z1, z9);
    z2 = _mm512_aesdeclast_epi128(z2, z9);
    z3 = _mm512_aesdeclast_epi128(z3, z9);
    z0 = _mm512_xor_si512(z0, z4);
    _mm512_storeu_si512((void*)WC_PW(rdx, 0), z0);
    z9 = _mm512_srli_epi64(z4, 48);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z4 = _mm512_slli_epi64(z4, 16);
    z4 = _mm512_ternarylogic_epi64(z4, z10, z9, 0x96);
    z1 = _mm512_xor_si512(z1, z5);
    _mm512_storeu_si512((void*)WC_PW(rdx, 64), z1);
    z9 = _mm512_srli_epi64(z5, 48);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z5 = _mm512_slli_epi64(z5, 16);
    z5 = _mm512_ternarylogic_epi64(z5, z10, z9, 0x96);
    z2 = _mm512_xor_si512(z2, z6);
    _mm512_storeu_si512((void*)WC_PW(rdx, 128), z2);
    z9 = _mm512_srli_epi64(z6, 48);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z6 = _mm512_slli_epi64(z6, 16);
    z6 = _mm512_ternarylogic_epi64(z6, z10, z9, 0x96);
    z3 = _mm512_xor_si512(z3, z7);
    _mm512_storeu_si512((void*)WC_PW(rdx, 192), z3);
    z9 = _mm512_srli_epi64(z7, 48);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z7 = _mm512_slli_epi64(z7, 16);
    z7 = _mm512_ternarylogic_epi64(z7, z10, z9, 0x96);
    r13 = (word32)((word32)r13 + 0x100);
    if (((word32)r13) < ((word32)r11)) {
        goto L_AES_XTS_decrypt_avx512_dec_256;
    }
    z8 = _mm512_zextsi128_si512(_mm512_extracti32x4_epi32(z4, 0));
L_AES_XTS_decrypt_avx512_done_256:
    zf9 = (word32)r13;
    zf10 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf9) == (zf10)) {
        goto L_AES_XTS_decrypt_avx512_done_dec;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_avx512_mul16_128;
    }
    r11 = (word32)((word32)r11 - 0x10);
    r11 = (word32)((word32)r11 - (word32)r13);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_avx512_last_31_start;
    }
    r11 = (word32)((word32)r11 + (word32)r13);
L_AES_XTS_decrypt_avx512_mul16_128:
    r11 = (word32)((word32)r11 & 0xffffff80);
    if (((word32)r13) == ((word32)r11)) {
        goto L_AES_XTS_decrypt_avx512_done_128;
    }
    /* 128 bytes of input */
    /* aes_dec_128 */
    rcx = (word64)(rdi + r13);
    rdx = (word64)(rsi + r13);
    z0 = _mm512_loadu_si512((const void*)WC_PR(rcx, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(rcx, 64));
    z5 = _mm512_shuffle_i64x2(z8, z8, 0);
    z6 = _mm512_srlv_epi64(z5, z15);
    z7 = _mm512_clmulepi64_epi128(z6, z13, 1);
    z6 = _mm512_bslli_epi128(z6, 8);
    z4 = _mm512_sllv_epi64(z5, z14);
    z4 = _mm512_ternarylogic_epi64(z4, z7, z6, 0x96);
    z9 = _mm512_srli_epi64(z4, 60);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z5 = _mm512_slli_epi64(z4, 4);
    z5 = _mm512_ternarylogic_epi64(z5, z10, z9, 0x96);
    /* aes_dec_block */
    z0 = _mm512_ternarylogic_epi64(z0, z16, z4, 0x96);
    z1 = _mm512_ternarylogic_epi64(z1, z16, z5, 0x96);
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
    z0 = _mm512_aesdec_epi128(z0, z24);
    z1 = _mm512_aesdec_epi128(z1, z24);
    z0 = _mm512_aesdec_epi128(z0, z25);
    z1 = _mm512_aesdec_epi128(z1, z25);
    zf11 = (word32)r10;
    zf12 = 0xb;
    z9 = z26;
    if ((sword32)(zf11) < (sword32)(zf12)) {
        goto L_AES_XTS_decrypt_avx512_aes_dec_128_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z26);
    z1 = _mm512_aesdec_epi128(z1, z26);
    z0 = _mm512_aesdec_epi128(z0, z27);
    z1 = _mm512_aesdec_epi128(z1, z27);
    zf13 = (word32)r10;
    zf14 = 0xd;
    z9 = z28;
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_XTS_decrypt_avx512_aes_dec_128_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z28);
    z1 = _mm512_aesdec_epi128(z1, z28);
    z0 = _mm512_aesdec_epi128(z0, z29);
    z1 = _mm512_aesdec_epi128(z1, z29);
    z9 = z30;
L_AES_XTS_decrypt_avx512_aes_dec_128_aes_dec_block_last:
    z0 = _mm512_aesdeclast_epi128(z0, z9);
    z1 = _mm512_aesdeclast_epi128(z1, z9);
    z0 = _mm512_xor_si512(z0, z4);
    _mm512_storeu_si512((void*)WC_PW(rdx, 0), z0);
    z1 = _mm512_xor_si512(z1, z5);
    _mm512_storeu_si512((void*)WC_PW(rdx, 64), z1);
    z8 = _mm512_zextsi128_si512(_mm512_extracti32x4_epi32(z5, 3));
    z9 = _mm512_zextsi128_si512(_mm_shuffle_epi32(_mm512_castsi512_si128(z8),
        0x13));
    z8 = _mm512_zextsi128_si512(_mm_add_epi64(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z8)));
    z9 = _mm512_zextsi128_si512(_mm_srai_epi32(_mm512_castsi512_si128(z9), 31));
    z8 = _mm512_zextsi128_si512(_mm_ternarylogic_epi32(_mm512_castsi512_si128(
        z8), _mm512_castsi512_si128(z9), x12, 0x78));
    r13 = (word32)((word32)r13 + 0x80);
L_AES_XTS_decrypt_avx512_done_128:
    zf15 = (word32)r13;
    zf16 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf15) == (zf16)) {
        goto L_AES_XTS_decrypt_avx512_done_dec;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_avx512_mul16_64;
    }
    r11 = (word32)((word32)r11 - 0x10);
    r11 = (word32)((word32)r11 - (word32)r13);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_avx512_last_31_start;
    }
    r11 = (word32)((word32)r11 + (word32)r13);
L_AES_XTS_decrypt_avx512_mul16_64:
    r11 = (word32)((word32)r11 & 0xffffffc0);
    if (((word32)r13) == ((word32)r11)) {
        goto L_AES_XTS_decrypt_avx512_done_64;
    }
    /* 64 bytes of input */
    /* aes_dec_64 */
    rcx = (word64)(rdi + r13);
    rdx = (word64)(rsi + r13);
    z0 = _mm512_loadu_si512((const void*)WC_PR(rcx, 0));
    z5 = _mm512_shuffle_i64x2(z8, z8, 0);
    z6 = _mm512_srlv_epi64(z5, z15);
    z7 = _mm512_clmulepi64_epi128(z6, z13, 1);
    z6 = _mm512_bslli_epi128(z6, 8);
    z4 = _mm512_sllv_epi64(z5, z14);
    z4 = _mm512_ternarylogic_epi64(z4, z7, z6, 0x96);
    /* aes_dec_block */
    z0 = _mm512_ternarylogic_epi64(z0, z16, z4, 0x96);
    z0 = _mm512_aesdec_epi128(z0, z17);
    z0 = _mm512_aesdec_epi128(z0, z18);
    z0 = _mm512_aesdec_epi128(z0, z19);
    z0 = _mm512_aesdec_epi128(z0, z20);
    z0 = _mm512_aesdec_epi128(z0, z21);
    z0 = _mm512_aesdec_epi128(z0, z22);
    z0 = _mm512_aesdec_epi128(z0, z23);
    z0 = _mm512_aesdec_epi128(z0, z24);
    z0 = _mm512_aesdec_epi128(z0, z25);
    zf17 = (word32)r10;
    zf18 = 0xb;
    z9 = z26;
    if ((sword32)(zf17) < (sword32)(zf18)) {
        goto L_AES_XTS_decrypt_avx512_aes_dec_64_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z26);
    z0 = _mm512_aesdec_epi128(z0, z27);
    zf19 = (word32)r10;
    zf20 = 0xd;
    z9 = z28;
    if ((sword32)(zf19) < (sword32)(zf20)) {
        goto L_AES_XTS_decrypt_avx512_aes_dec_64_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z28);
    z0 = _mm512_aesdec_epi128(z0, z29);
    z9 = z30;
L_AES_XTS_decrypt_avx512_aes_dec_64_aes_dec_block_last:
    z0 = _mm512_aesdeclast_epi128(z0, z9);
    z0 = _mm512_xor_si512(z0, z4);
    _mm512_storeu_si512((void*)WC_PW(rdx, 0), z0);
    z8 = _mm512_zextsi128_si512(_mm512_extracti32x4_epi32(z4, 3));
    z9 = _mm512_zextsi128_si512(_mm_shuffle_epi32(_mm512_castsi512_si128(z8),
        0x13));
    z8 = _mm512_zextsi128_si512(_mm_add_epi64(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z8)));
    z9 = _mm512_zextsi128_si512(_mm_srai_epi32(_mm512_castsi512_si128(z9), 31));
    z8 = _mm512_zextsi128_si512(_mm_ternarylogic_epi32(_mm512_castsi512_si128(
        z8), _mm512_castsi512_si128(z9), x12, 0x78));
    r13 = (word32)((word32)r13 + 0x40);
L_AES_XTS_decrypt_avx512_done_64:
    zf21 = (word32)r13;
    zf22 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf21) == (zf22)) {
        goto L_AES_XTS_decrypt_avx512_done_dec;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_avx512_mul16_32;
    }
    r11 = (word32)((word32)r11 - 0x10);
    r11 = (word32)((word32)r11 - (word32)r13);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_avx512_last_31_start;
    }
    r11 = (word32)((word32)r11 + (word32)r13);
L_AES_XTS_decrypt_avx512_mul16_32:
    r11 = (word32)((word32)r11 & 0xffffffe0);
    if (((word32)r13) == ((word32)r11)) {
        goto L_AES_XTS_decrypt_avx512_done_32;
    }
    /* 32 bytes of input */
    /* aes_dec_32 */
    rcx = (word64)(rdi + r13);
    rdx = (word64)(rsi + r13);
    z0 = _mm512_zextsi256_si512(_mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        0)));
    z5 = _mm512_shuffle_i64x2(z8, z8, 0);
    z6 = _mm512_srlv_epi64(z5, z15);
    z7 = _mm512_clmulepi64_epi128(z6, z13, 1);
    z6 = _mm512_bslli_epi128(z6, 8);
    z4 = _mm512_sllv_epi64(z5, z14);
    z4 = _mm512_ternarylogic_epi64(z4, z7, z6, 0x96);
    /* aes_dec_block */
    z0 = _mm512_zextsi256_si512(_mm256_ternarylogic_epi64(
        _mm512_castsi512_si256(z0), _mm512_castsi512_si256(z16),
        _mm512_castsi512_si256(z4), 0x96));
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
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z24)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z25)));
    zf23 = (word32)r10;
    zf24 = 0xb;
    z9 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z26));
    if ((sword32)(zf23) < (sword32)(zf24)) {
        goto L_AES_XTS_decrypt_avx512_aes_dec_32_aes_dec_block_last;
    }
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z26)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z27)));
    zf25 = (word32)r10;
    zf26 = 0xd;
    z9 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z28));
    if ((sword32)(zf25) < (sword32)(zf26)) {
        goto L_AES_XTS_decrypt_avx512_aes_dec_32_aes_dec_block_last;
    }
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z28)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z29)));
    z9 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z30));
L_AES_XTS_decrypt_avx512_aes_dec_32_aes_dec_block_last:
    z0 = _mm512_zextsi256_si512(_mm256_aesdeclast_epi128(_mm512_castsi512_si256(
        z0), _mm512_castsi512_si256(z9)));
    z0 = _mm512_zextsi256_si512(_mm256_xor_si256(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z4)));
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 0), _mm512_castsi512_si256(z0));
    z8 = _mm512_zextsi128_si512(_mm512_extracti32x4_epi32(z4, 2));
    r13 = (word32)((word32)r13 + 0x20);
L_AES_XTS_decrypt_avx512_done_32:
    zf27 = (word32)r13;
    zf28 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf27) == (zf28)) {
        goto L_AES_XTS_decrypt_avx512_done_dec;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_avx512_mul16;
    }
    r11 = (word32)((word32)r11 - 0x10);
    r11 = (word32)((word32)r11 - (word32)r13);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_avx512_last_31_start;
    }
    r11 = (word32)((word32)r11 + (word32)r13);
L_AES_XTS_decrypt_avx512_mul16:
L_AES_XTS_decrypt_avx512_dec_16:
    /* 16 bytes of input */
    rcx = (word64)(rdi + r13);
    z0 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z8)));
    /* aes_dec_block */
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm_loadu_si128((const __m128i*)WC_PR(r8, 0))));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 16)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 32)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 48)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 64)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 80)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 96)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    zf29 = (word32)r10;
    zf30 = 0xb;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf29) < (sword32)(zf30)) {
        goto L_AES_XTS_decrypt_avx512_aes_dec_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    zf31 = (word32)r10;
    zf32 = 0xd;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf31) < (sword32)(zf32)) {
        goto L_AES_XTS_decrypt_avx512_aes_dec_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_XTS_decrypt_avx512_aes_dec_block_last:
    z0 = _mm512_zextsi128_si512(_mm_aesdeclast_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z8)));
    rcx = (word64)(rsi + r13);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), _mm512_castsi512_si128(z0));
    z4 = _mm512_zextsi128_si512(_mm_shuffle_epi32(_mm512_castsi512_si128(z8),
        0x13));
    z8 = _mm512_zextsi128_si512(_mm_add_epi64(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z8)));
    z4 = _mm512_zextsi128_si512(_mm_srai_epi32(_mm512_castsi512_si128(z4), 31));
    z8 = _mm512_zextsi128_si512(_mm_ternarylogic_epi32(_mm512_castsi512_si128(
        z8), _mm512_castsi512_si128(z4), x12, 0x78));
    r13 = (word32)((word32)r13 + 0x10);
    if (((word32)r13) < ((word32)r11)) {
        goto L_AES_XTS_decrypt_avx512_dec_16;
    }
    if (((word32)r13) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_avx512_done_dec;
    }
L_AES_XTS_decrypt_avx512_last_31_start:
    z4 = _mm512_zextsi128_si512(_mm_shuffle_epi32(_mm512_castsi512_si128(z8),
        0x13));
    z7 = _mm512_zextsi128_si512(_mm_add_epi64(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z8)));
    z4 = _mm512_zextsi128_si512(_mm_srai_epi32(_mm512_castsi512_si128(z4), 31));
    z7 = _mm512_zextsi128_si512(_mm_ternarylogic_epi32(_mm512_castsi512_si128(
        z7), _mm512_castsi512_si128(z4), x12, 0x78));
    rcx = (word64)(rdi + r13);
    z0 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z7)));
    /* aes_dec_block */
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm_loadu_si128((const __m128i*)WC_PR(r8, 0))));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 16)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 32)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 48)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 64)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 80)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 96)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    zf33 = (word32)r10;
    zf34 = 0xb;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf33) < (sword32)(zf34)) {
        goto L_AES_XTS_decrypt_avx512_last_31_aes_dec_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    zf35 = (word32)r10;
    zf36 = 0xd;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf35) < (sword32)(zf36)) {
        goto L_AES_XTS_decrypt_avx512_last_31_aes_dec_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_XTS_decrypt_avx512_last_31_aes_dec_block_last:
    z0 = _mm512_zextsi128_si512(_mm_aesdeclast_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z7)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), _mm512_castsi512_si128(z0));
    r13 = (word64)(r13 + 0x10);
    rdx = (word64)(0);
L_AES_XTS_decrypt_avx512_last_31_byte_loop:
    r11 = (r11 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, rdx)) & 0xff);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, r13)) & 0xff);
    WC_S8(rsi, r13) = (byte)((byte)r11);
    WC_S8(rsp, rdx) = (byte)((byte)rcx);
    r13 = (word32)((word32)r13 + 1);
    rdx = (word32)((word32)rdx + 1);
    if (((word32)r13) < ((word32)rax)) {
        goto L_AES_XTS_decrypt_avx512_last_31_byte_loop;
    }
    r13 = (word64)(r13 - rdx);
    z0 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rsp, 0)));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z8)));
    /* aes_dec_block */
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm_loadu_si128((const __m128i*)WC_PR(r8, 0))));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 16)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 32)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 48)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 64)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 80)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 96)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        112)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        128)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        144)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    zf37 = (word32)r10;
    zf38 = 0xb;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        160)));
    if ((sword32)(zf37) < (sword32)(zf38)) {
        goto L_AES_XTS_decrypt_avx512_last_31_2_aes_dec_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        176)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    zf39 = (word32)r10;
    zf40 = 0xd;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        192)));
    if ((sword32)(zf39) < (sword32)(zf40)) {
        goto L_AES_XTS_decrypt_avx512_last_31_2_aes_dec_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        208)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8,
        224)));
L_AES_XTS_decrypt_avx512_last_31_2_aes_dec_block_last:
    z0 = _mm512_zextsi128_si512(_mm_aesdeclast_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z8)));
    r13 = (word64)(r13 - 0x10);
    rcx = (word64)(rsi + r13);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), _mm512_castsi512_si128(z0));
L_AES_XTS_decrypt_avx512_done_dec:
    ;
}

WC_X64I_TARGET("aes,vaes,pclmul,vpclmulqdq,avx512f,avx512vl,avx512bw")
WOLFSSL_LOCAL void AES_XTS_decrypt_update_avx512(const unsigned char* in,
    unsigned char* out, unsigned int nbytes, const unsigned char* key,
    unsigned char* tweak_block, int nr)
{
    word64 rdi, rsi, rax, r10, r8, r9, rsp, r12, r11, rcx = 0, rdx = 0;
    __m128i x12;
    __m512i z0 = _mm512_setzero_si512(), z1 = _mm512_setzero_si512(),
            z2 = _mm512_setzero_si512(), z3 = _mm512_setzero_si512(),
            z4 = _mm512_setzero_si512(), z5 = _mm512_setzero_si512(),
            z6 = _mm512_setzero_si512(), z7 = _mm512_setzero_si512(), z8,
            z9 = _mm512_setzero_si512(), z10 = _mm512_setzero_si512(), z13,
            z14, z15, z16 = _mm512_setzero_si512(),
            z17 = _mm512_setzero_si512(), z18 = _mm512_setzero_si512(),
            z19 = _mm512_setzero_si512(), z20 = _mm512_setzero_si512(),
            z21 = _mm512_setzero_si512(), z22 = _mm512_setzero_si512(),
            z23 = _mm512_setzero_si512(), z24 = _mm512_setzero_si512(),
            z25 = _mm512_setzero_si512(), z26 = _mm512_setzero_si512(),
            z27 = _mm512_setzero_si512(), z28 = _mm512_setzero_si512(),
            z29 = _mm512_setzero_si512(), z30 = _mm512_setzero_si512();
    XALIGNED(32) WC_X64I_SLOT stk[8];
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
    word32 zf25;
    word32 zf26;
    word32 zf27;
    word32 zf28;
    word32 zf29;
    word32 zf30;
    word32 zf31;
    word32 zf32;
    word32 zf33;
    word32 zf34;
    word32 zf35;
    word32 zf36;

    rdi = (word64)(size_t)in;
    rsi = (word64)(size_t)out;
    rax = (word64)(word32)nbytes;
    r10 = (word64)(size_t)key;
    r8 = (word64)(size_t)tweak_block;
    r9 = (word64)(word32)nr;

    rsp = (word64)(size_t)stk + 64;
    rsp = (word64)(rsp - 64);
    x12 = _mm_loadu_si128((const __m128i*)WC_PR(L_avx512_aes_xts_gc_xts, 0));
    z13 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(
        L_avx512_aes_xts_poly, 0)));
    z14 = _mm512_loadu_si512((const void*)WC_PR(L_avx512_aes_xts_shl, 0));
    z15 = _mm512_loadu_si512((const void*)WC_PR(L_avx512_aes_xts_shr, 0));
    z8 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r8, 0)));
    r12 = (word32)(0);
    r11 = (word32)((word32)rax);
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_avx512_mul16_256;
    }
    r11 = (word32)((word32)r11 - 0x10);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_update_avx512_last_31_start;
    }
L_AES_XTS_decrypt_update_avx512_mul16_256:
    if (((word32)r11) < (0x20)) {
        goto L_AES_XTS_decrypt_update_avx512_done_128;
    }
    z16 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        0)));
    z17 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        16)));
    z18 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        32)));
    z19 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        48)));
    z20 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        64)));
    z21 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        80)));
    z22 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        96)));
    z23 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        112)));
    z24 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        128)));
    z25 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        144)));
    z26 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        160)));
    if ((sword32)((word32)r9) < (sword32)(0xb)) {
        goto L_AES_XTS_decrypt_update_avx512_key_cached;
    }
    z27 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        176)));
    z28 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        192)));
    if ((sword32)((word32)r9) < (sword32)(0xd)) {
        goto L_AES_XTS_decrypt_update_avx512_key_cached;
    }
    z29 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        208)));
    z30 = _mm512_broadcast_i32x4(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        224)));
L_AES_XTS_decrypt_update_avx512_key_cached:
    if (((word32)r11) < (0x100)) {
        goto L_AES_XTS_decrypt_update_avx512_done_256;
    }
    r11 = (word32)((word32)r11 & 0xffffff00);
    z5 = _mm512_shuffle_i64x2(z8, z8, 0);
    z6 = _mm512_srlv_epi64(z5, z15);
    z7 = _mm512_clmulepi64_epi128(z6, z13, 1);
    z6 = _mm512_bslli_epi128(z6, 8);
    z4 = _mm512_sllv_epi64(z5, z14);
    z4 = _mm512_ternarylogic_epi64(z4, z7, z6, 0x96);
    z9 = _mm512_srli_epi64(z4, 60);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z5 = _mm512_slli_epi64(z4, 4);
    z5 = _mm512_ternarylogic_epi64(z5, z10, z9, 0x96);
    z9 = _mm512_srli_epi64(z5, 60);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z6 = _mm512_slli_epi64(z5, 4);
    z6 = _mm512_ternarylogic_epi64(z6, z10, z9, 0x96);
    z9 = _mm512_srli_epi64(z6, 60);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z7 = _mm512_slli_epi64(z6, 4);
    z7 = _mm512_ternarylogic_epi64(z7, z10, z9, 0x96);
L_AES_XTS_decrypt_update_avx512_dec_256:
    /* 256 bytes of input */
    /* aes_dec_256 */
    rcx = (word64)(rdi + r12);
    rdx = (word64)(rsi + r12);
    z0 = _mm512_loadu_si512((const void*)WC_PR(rcx, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(rcx, 64));
    z2 = _mm512_loadu_si512((const void*)WC_PR(rcx, 128));
    z3 = _mm512_loadu_si512((const void*)WC_PR(rcx, 192));
    /* aes_dec_block */
    z0 = _mm512_ternarylogic_epi64(z0, z16, z4, 0x96);
    z1 = _mm512_ternarylogic_epi64(z1, z16, z5, 0x96);
    z2 = _mm512_ternarylogic_epi64(z2, z16, z6, 0x96);
    z3 = _mm512_ternarylogic_epi64(z3, z16, z7, 0x96);
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
    z0 = _mm512_aesdec_epi128(z0, z24);
    z1 = _mm512_aesdec_epi128(z1, z24);
    z2 = _mm512_aesdec_epi128(z2, z24);
    z3 = _mm512_aesdec_epi128(z3, z24);
    z0 = _mm512_aesdec_epi128(z0, z25);
    z1 = _mm512_aesdec_epi128(z1, z25);
    z2 = _mm512_aesdec_epi128(z2, z25);
    z3 = _mm512_aesdec_epi128(z3, z25);
    zf1 = (word32)r9;
    zf2 = 0xb;
    z9 = z26;
    if ((sword32)(zf1) < (sword32)(zf2)) {
        goto L_AES_XTS_decrypt_update_avx512_aes_dec_256_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z26);
    z1 = _mm512_aesdec_epi128(z1, z26);
    z2 = _mm512_aesdec_epi128(z2, z26);
    z3 = _mm512_aesdec_epi128(z3, z26);
    z0 = _mm512_aesdec_epi128(z0, z27);
    z1 = _mm512_aesdec_epi128(z1, z27);
    z2 = _mm512_aesdec_epi128(z2, z27);
    z3 = _mm512_aesdec_epi128(z3, z27);
    zf3 = (word32)r9;
    zf4 = 0xd;
    z9 = z28;
    if ((sword32)(zf3) < (sword32)(zf4)) {
        goto L_AES_XTS_decrypt_update_avx512_aes_dec_256_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z28);
    z1 = _mm512_aesdec_epi128(z1, z28);
    z2 = _mm512_aesdec_epi128(z2, z28);
    z3 = _mm512_aesdec_epi128(z3, z28);
    z0 = _mm512_aesdec_epi128(z0, z29);
    z1 = _mm512_aesdec_epi128(z1, z29);
    z2 = _mm512_aesdec_epi128(z2, z29);
    z3 = _mm512_aesdec_epi128(z3, z29);
    z9 = z30;
L_AES_XTS_decrypt_update_avx512_aes_dec_256_aes_dec_block_last:
    z0 = _mm512_aesdeclast_epi128(z0, z9);
    z1 = _mm512_aesdeclast_epi128(z1, z9);
    z2 = _mm512_aesdeclast_epi128(z2, z9);
    z3 = _mm512_aesdeclast_epi128(z3, z9);
    z0 = _mm512_xor_si512(z0, z4);
    _mm512_storeu_si512((void*)WC_PW(rdx, 0), z0);
    z9 = _mm512_srli_epi64(z4, 48);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z4 = _mm512_slli_epi64(z4, 16);
    z4 = _mm512_ternarylogic_epi64(z4, z10, z9, 0x96);
    z1 = _mm512_xor_si512(z1, z5);
    _mm512_storeu_si512((void*)WC_PW(rdx, 64), z1);
    z9 = _mm512_srli_epi64(z5, 48);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z5 = _mm512_slli_epi64(z5, 16);
    z5 = _mm512_ternarylogic_epi64(z5, z10, z9, 0x96);
    z2 = _mm512_xor_si512(z2, z6);
    _mm512_storeu_si512((void*)WC_PW(rdx, 128), z2);
    z9 = _mm512_srli_epi64(z6, 48);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z6 = _mm512_slli_epi64(z6, 16);
    z6 = _mm512_ternarylogic_epi64(z6, z10, z9, 0x96);
    z3 = _mm512_xor_si512(z3, z7);
    _mm512_storeu_si512((void*)WC_PW(rdx, 192), z3);
    z9 = _mm512_srli_epi64(z7, 48);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z7 = _mm512_slli_epi64(z7, 16);
    z7 = _mm512_ternarylogic_epi64(z7, z10, z9, 0x96);
    r12 = (word32)((word32)r12 + 0x100);
    if (((word32)r12) < ((word32)r11)) {
        goto L_AES_XTS_decrypt_update_avx512_dec_256;
    }
    z8 = _mm512_zextsi128_si512(_mm512_extracti32x4_epi32(z4, 0));
L_AES_XTS_decrypt_update_avx512_done_256:
    zf5 = (word32)r12;
    zf6 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf5) == (zf6)) {
        goto L_AES_XTS_decrypt_update_avx512_done_dec;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_avx512_mul16_128;
    }
    r11 = (word32)((word32)r11 - 0x10);
    r11 = (word32)((word32)r11 - (word32)r12);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_update_avx512_last_31_start;
    }
    r11 = (word32)((word32)r11 + (word32)r12);
L_AES_XTS_decrypt_update_avx512_mul16_128:
    r11 = (word32)((word32)r11 & 0xffffff80);
    if (((word32)r12) == ((word32)r11)) {
        goto L_AES_XTS_decrypt_update_avx512_done_128;
    }
    /* 128 bytes of input */
    /* aes_dec_128 */
    rcx = (word64)(rdi + r12);
    rdx = (word64)(rsi + r12);
    z0 = _mm512_loadu_si512((const void*)WC_PR(rcx, 0));
    z1 = _mm512_loadu_si512((const void*)WC_PR(rcx, 64));
    z5 = _mm512_shuffle_i64x2(z8, z8, 0);
    z6 = _mm512_srlv_epi64(z5, z15);
    z7 = _mm512_clmulepi64_epi128(z6, z13, 1);
    z6 = _mm512_bslli_epi128(z6, 8);
    z4 = _mm512_sllv_epi64(z5, z14);
    z4 = _mm512_ternarylogic_epi64(z4, z7, z6, 0x96);
    z9 = _mm512_srli_epi64(z4, 60);
    z10 = _mm512_clmulepi64_epi128(z9, z13, 1);
    z9 = _mm512_bslli_epi128(z9, 8);
    z5 = _mm512_slli_epi64(z4, 4);
    z5 = _mm512_ternarylogic_epi64(z5, z10, z9, 0x96);
    /* aes_dec_block */
    z0 = _mm512_ternarylogic_epi64(z0, z16, z4, 0x96);
    z1 = _mm512_ternarylogic_epi64(z1, z16, z5, 0x96);
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
    z0 = _mm512_aesdec_epi128(z0, z24);
    z1 = _mm512_aesdec_epi128(z1, z24);
    z0 = _mm512_aesdec_epi128(z0, z25);
    z1 = _mm512_aesdec_epi128(z1, z25);
    zf7 = (word32)r9;
    zf8 = 0xb;
    z9 = z26;
    if ((sword32)(zf7) < (sword32)(zf8)) {
        goto L_AES_XTS_decrypt_update_avx512_aes_dec_128_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z26);
    z1 = _mm512_aesdec_epi128(z1, z26);
    z0 = _mm512_aesdec_epi128(z0, z27);
    z1 = _mm512_aesdec_epi128(z1, z27);
    zf9 = (word32)r9;
    zf10 = 0xd;
    z9 = z28;
    if ((sword32)(zf9) < (sword32)(zf10)) {
        goto L_AES_XTS_decrypt_update_avx512_aes_dec_128_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z28);
    z1 = _mm512_aesdec_epi128(z1, z28);
    z0 = _mm512_aesdec_epi128(z0, z29);
    z1 = _mm512_aesdec_epi128(z1, z29);
    z9 = z30;
L_AES_XTS_decrypt_update_avx512_aes_dec_128_aes_dec_block_last:
    z0 = _mm512_aesdeclast_epi128(z0, z9);
    z1 = _mm512_aesdeclast_epi128(z1, z9);
    z0 = _mm512_xor_si512(z0, z4);
    _mm512_storeu_si512((void*)WC_PW(rdx, 0), z0);
    z1 = _mm512_xor_si512(z1, z5);
    _mm512_storeu_si512((void*)WC_PW(rdx, 64), z1);
    z8 = _mm512_zextsi128_si512(_mm512_extracti32x4_epi32(z5, 3));
    z9 = _mm512_zextsi128_si512(_mm_shuffle_epi32(_mm512_castsi512_si128(z8),
        0x13));
    z8 = _mm512_zextsi128_si512(_mm_add_epi64(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z8)));
    z9 = _mm512_zextsi128_si512(_mm_srai_epi32(_mm512_castsi512_si128(z9), 31));
    z8 = _mm512_zextsi128_si512(_mm_ternarylogic_epi32(_mm512_castsi512_si128(
        z8), _mm512_castsi512_si128(z9), x12, 0x78));
    r12 = (word32)((word32)r12 + 0x80);
L_AES_XTS_decrypt_update_avx512_done_128:
    zf11 = (word32)r12;
    zf12 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf11) == (zf12)) {
        goto L_AES_XTS_decrypt_update_avx512_done_dec;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_avx512_mul16_64;
    }
    r11 = (word32)((word32)r11 - 0x10);
    r11 = (word32)((word32)r11 - (word32)r12);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_update_avx512_last_31_start;
    }
    r11 = (word32)((word32)r11 + (word32)r12);
L_AES_XTS_decrypt_update_avx512_mul16_64:
    r11 = (word32)((word32)r11 & 0xffffffc0);
    if (((word32)r12) == ((word32)r11)) {
        goto L_AES_XTS_decrypt_update_avx512_done_64;
    }
    /* 64 bytes of input */
    /* aes_dec_64 */
    rcx = (word64)(rdi + r12);
    rdx = (word64)(rsi + r12);
    z0 = _mm512_loadu_si512((const void*)WC_PR(rcx, 0));
    z5 = _mm512_shuffle_i64x2(z8, z8, 0);
    z6 = _mm512_srlv_epi64(z5, z15);
    z7 = _mm512_clmulepi64_epi128(z6, z13, 1);
    z6 = _mm512_bslli_epi128(z6, 8);
    z4 = _mm512_sllv_epi64(z5, z14);
    z4 = _mm512_ternarylogic_epi64(z4, z7, z6, 0x96);
    /* aes_dec_block */
    z0 = _mm512_ternarylogic_epi64(z0, z16, z4, 0x96);
    z0 = _mm512_aesdec_epi128(z0, z17);
    z0 = _mm512_aesdec_epi128(z0, z18);
    z0 = _mm512_aesdec_epi128(z0, z19);
    z0 = _mm512_aesdec_epi128(z0, z20);
    z0 = _mm512_aesdec_epi128(z0, z21);
    z0 = _mm512_aesdec_epi128(z0, z22);
    z0 = _mm512_aesdec_epi128(z0, z23);
    z0 = _mm512_aesdec_epi128(z0, z24);
    z0 = _mm512_aesdec_epi128(z0, z25);
    zf13 = (word32)r9;
    zf14 = 0xb;
    z9 = z26;
    if ((sword32)(zf13) < (sword32)(zf14)) {
        goto L_AES_XTS_decrypt_update_avx512_aes_dec_64_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z26);
    z0 = _mm512_aesdec_epi128(z0, z27);
    zf15 = (word32)r9;
    zf16 = 0xd;
    z9 = z28;
    if ((sword32)(zf15) < (sword32)(zf16)) {
        goto L_AES_XTS_decrypt_update_avx512_aes_dec_64_aes_dec_block_last;
    }
    z0 = _mm512_aesdec_epi128(z0, z28);
    z0 = _mm512_aesdec_epi128(z0, z29);
    z9 = z30;
L_AES_XTS_decrypt_update_avx512_aes_dec_64_aes_dec_block_last:
    z0 = _mm512_aesdeclast_epi128(z0, z9);
    z0 = _mm512_xor_si512(z0, z4);
    _mm512_storeu_si512((void*)WC_PW(rdx, 0), z0);
    z8 = _mm512_zextsi128_si512(_mm512_extracti32x4_epi32(z4, 3));
    z9 = _mm512_zextsi128_si512(_mm_shuffle_epi32(_mm512_castsi512_si128(z8),
        0x13));
    z8 = _mm512_zextsi128_si512(_mm_add_epi64(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z8)));
    z9 = _mm512_zextsi128_si512(_mm_srai_epi32(_mm512_castsi512_si128(z9), 31));
    z8 = _mm512_zextsi128_si512(_mm_ternarylogic_epi32(_mm512_castsi512_si128(
        z8), _mm512_castsi512_si128(z9), x12, 0x78));
    r12 = (word32)((word32)r12 + 0x40);
L_AES_XTS_decrypt_update_avx512_done_64:
    zf17 = (word32)r12;
    zf18 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf17) == (zf18)) {
        goto L_AES_XTS_decrypt_update_avx512_done_dec;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_avx512_mul16_32;
    }
    r11 = (word32)((word32)r11 - 0x10);
    r11 = (word32)((word32)r11 - (word32)r12);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_update_avx512_last_31_start;
    }
    r11 = (word32)((word32)r11 + (word32)r12);
L_AES_XTS_decrypt_update_avx512_mul16_32:
    r11 = (word32)((word32)r11 & 0xffffffe0);
    if (((word32)r12) == ((word32)r11)) {
        goto L_AES_XTS_decrypt_update_avx512_done_32;
    }
    /* 32 bytes of input */
    /* aes_dec_32 */
    rcx = (word64)(rdi + r12);
    rdx = (word64)(rsi + r12);
    z0 = _mm512_zextsi256_si512(_mm256_loadu_si256((const __m256i*)WC_PR(rcx,
        0)));
    z5 = _mm512_shuffle_i64x2(z8, z8, 0);
    z6 = _mm512_srlv_epi64(z5, z15);
    z7 = _mm512_clmulepi64_epi128(z6, z13, 1);
    z6 = _mm512_bslli_epi128(z6, 8);
    z4 = _mm512_sllv_epi64(z5, z14);
    z4 = _mm512_ternarylogic_epi64(z4, z7, z6, 0x96);
    /* aes_dec_block */
    z0 = _mm512_zextsi256_si512(_mm256_ternarylogic_epi64(
        _mm512_castsi512_si256(z0), _mm512_castsi512_si256(z16),
        _mm512_castsi512_si256(z4), 0x96));
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
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z24)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z25)));
    zf19 = (word32)r9;
    zf20 = 0xb;
    z9 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z26));
    if ((sword32)(zf19) < (sword32)(zf20)) {
        goto L_AES_XTS_decrypt_update_avx512_aes_dec_32_aes_dec_block_last;
    }
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z26)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z27)));
    zf21 = (word32)r9;
    zf22 = 0xd;
    z9 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z28));
    if ((sword32)(zf21) < (sword32)(zf22)) {
        goto L_AES_XTS_decrypt_update_avx512_aes_dec_32_aes_dec_block_last;
    }
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z28)));
    z0 = _mm512_zextsi256_si512(_mm256_aesdec_epi128(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z29)));
    z9 = _mm512_zextsi256_si512(_mm512_castsi512_si256(z30));
L_AES_XTS_decrypt_update_avx512_aes_dec_32_aes_dec_block_last:
    z0 = _mm512_zextsi256_si512(_mm256_aesdeclast_epi128(_mm512_castsi512_si256(
        z0), _mm512_castsi512_si256(z9)));
    z0 = _mm512_zextsi256_si512(_mm256_xor_si256(_mm512_castsi512_si256(z0),
        _mm512_castsi512_si256(z4)));
    _mm256_storeu_si256((__m256i*)WC_PW(rdx, 0), _mm512_castsi512_si256(z0));
    z8 = _mm512_zextsi128_si512(_mm512_extracti32x4_epi32(z4, 2));
    r12 = (word32)((word32)r12 + 0x20);
L_AES_XTS_decrypt_update_avx512_done_32:
    zf23 = (word32)r12;
    zf24 = (word32)rax;
    r11 = (word32)((word32)rax);
    if ((zf23) == (zf24)) {
        goto L_AES_XTS_decrypt_update_avx512_done_dec;
    }
    r11 = (word32)((word32)r11 & 0xfffffff0);
    if (((word32)r11) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_avx512_mul16;
    }
    r11 = (word32)((word32)r11 - 0x10);
    r11 = (word32)((word32)r11 - (word32)r12);
    if (((word32)r11) < (0x10)) {
        goto L_AES_XTS_decrypt_update_avx512_last_31_start;
    }
    r11 = (word32)((word32)r11 + (word32)r12);
L_AES_XTS_decrypt_update_avx512_mul16:
L_AES_XTS_decrypt_update_avx512_dec_16:
    /* 16 bytes of input */
    rcx = (word64)(rdi + r12);
    z0 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z8)));
    /* aes_dec_block */
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm_loadu_si128((const __m128i*)WC_PR(r10, 0))));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        16)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        32)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        48)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        64)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        80)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        96)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        112)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        128)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        144)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    zf25 = (word32)r9;
    zf26 = 0xb;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        160)));
    if ((sword32)(zf25) < (sword32)(zf26)) {
        goto L_AES_XTS_decrypt_update_avx512_aes_dec_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        176)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    zf27 = (word32)r9;
    zf28 = 0xd;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        192)));
    if ((sword32)(zf27) < (sword32)(zf28)) {
        goto L_AES_XTS_decrypt_update_avx512_aes_dec_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        208)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        224)));
L_AES_XTS_decrypt_update_avx512_aes_dec_block_last:
    z0 = _mm512_zextsi128_si512(_mm_aesdeclast_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z8)));
    rcx = (word64)(rsi + r12);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), _mm512_castsi512_si128(z0));
    z4 = _mm512_zextsi128_si512(_mm_shuffle_epi32(_mm512_castsi512_si128(z8),
        0x13));
    z8 = _mm512_zextsi128_si512(_mm_add_epi64(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z8)));
    z4 = _mm512_zextsi128_si512(_mm_srai_epi32(_mm512_castsi512_si128(z4), 31));
    z8 = _mm512_zextsi128_si512(_mm_ternarylogic_epi32(_mm512_castsi512_si128(
        z8), _mm512_castsi512_si128(z4), x12, 0x78));
    r12 = (word32)((word32)r12 + 0x10);
    if (((word32)r12) < ((word32)r11)) {
        goto L_AES_XTS_decrypt_update_avx512_dec_16;
    }
    if (((word32)r12) == ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_avx512_done_dec;
    }
L_AES_XTS_decrypt_update_avx512_last_31_start:
    z4 = _mm512_zextsi128_si512(_mm_shuffle_epi32(_mm512_castsi512_si128(z8),
        0x13));
    z7 = _mm512_zextsi128_si512(_mm_add_epi64(_mm512_castsi512_si128(z8),
        _mm512_castsi512_si128(z8)));
    z4 = _mm512_zextsi128_si512(_mm_srai_epi32(_mm512_castsi512_si128(z4), 31));
    z7 = _mm512_zextsi128_si512(_mm_ternarylogic_epi32(_mm512_castsi512_si128(
        z7), _mm512_castsi512_si128(z4), x12, 0x78));
    rcx = (word64)(rdi + r12);
    z0 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rcx, 0)));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z7)));
    /* aes_dec_block */
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm_loadu_si128((const __m128i*)WC_PR(r10, 0))));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        16)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        32)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        48)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        64)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        80)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        96)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        112)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        128)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        144)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    zf29 = (word32)r9;
    zf30 = 0xb;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        160)));
    if ((sword32)(zf29) < (sword32)(zf30)) {
        goto L_AES_XTS_decrypt_update_avx512_last_31_aes_dec_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        176)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    zf31 = (word32)r9;
    zf32 = 0xd;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        192)));
    if ((sword32)(zf31) < (sword32)(zf32)) {
        goto L_AES_XTS_decrypt_update_avx512_last_31_aes_dec_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        208)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        224)));
L_AES_XTS_decrypt_update_avx512_last_31_aes_dec_block_last:
    z0 = _mm512_zextsi128_si512(_mm_aesdeclast_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z7)));
    _mm_storeu_si128((__m128i*)WC_PW(rsp, 0), _mm512_castsi512_si128(z0));
    r12 = (word64)(r12 + 0x10);
    rdx = (word64)(0);
L_AES_XTS_decrypt_update_avx512_last_31_byte_loop:
    r11 = (r11 & ~(word64)0xff) | ((word64)(byte)(WC_L8(rsp, rdx)) & 0xff);
    rcx = (rcx & ~(word64)0xff) | ((word64)(byte)(WC_L8(rdi, r12)) & 0xff);
    WC_S8(rsi, r12) = (byte)((byte)r11);
    WC_S8(rsp, rdx) = (byte)((byte)rcx);
    r12 = (word32)((word32)r12 + 1);
    rdx = (word32)((word32)rdx + 1);
    if (((word32)r12) < ((word32)rax)) {
        goto L_AES_XTS_decrypt_update_avx512_last_31_byte_loop;
    }
    r12 = (word64)(r12 - rdx);
    z0 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(rsp, 0)));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z8)));
    /* aes_dec_block */
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm_loadu_si128((const __m128i*)WC_PR(r10, 0))));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        16)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        32)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        48)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        64)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        80)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        96)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        112)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        128)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        144)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    zf33 = (word32)r9;
    zf34 = 0xb;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        160)));
    if ((sword32)(zf33) < (sword32)(zf34)) {
        goto L_AES_XTS_decrypt_update_avx512_last_31_2_aes_dec_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        176)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    zf35 = (word32)r9;
    zf36 = 0xd;
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        192)));
    if ((sword32)(zf35) < (sword32)(zf36)) {
        goto L_AES_XTS_decrypt_update_avx512_last_31_2_aes_dec_block_last;
    }
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z6 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        208)));
    z0 = _mm512_zextsi128_si512(_mm_aesdec_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z6)));
    z5 = _mm512_zextsi128_si512(_mm_loadu_si128((const __m128i*)WC_PR(r10,
        224)));
L_AES_XTS_decrypt_update_avx512_last_31_2_aes_dec_block_last:
    z0 = _mm512_zextsi128_si512(_mm_aesdeclast_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z5)));
    z0 = _mm512_zextsi128_si512(_mm_xor_si128(_mm512_castsi512_si128(z0),
        _mm512_castsi512_si128(z8)));
    r12 = (word64)(r12 - 0x10);
    rcx = (word64)(rsi + r12);
    _mm_storeu_si128((__m128i*)WC_PW(rcx, 0), _mm512_castsi512_si128(z0));
L_AES_XTS_decrypt_update_avx512_done_dec:
    _mm_storeu_si128((__m128i*)WC_PW(r8, 0), _mm512_castsi512_si128(z8));
}

#endif /* HAVE_INTEL_AVX512 */
#endif /* WOLFSSL_X86_64_BUILD */
#endif /* WOLFSSL_AES_XTS */

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
