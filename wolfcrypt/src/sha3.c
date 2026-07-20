/* sha3.c
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

/*
 * SHA-3 Build Options:
 *
 * Core:
 * WOLFSSL_SHA3:             Enable SHA-3 support                  default: off
 * WOLFSSL_SHA3_SMALL:       Use smaller SHA-3 implementation      default: off
 * WOLFSSL_SHAKE128:         Enable SHAKE128 XOF                   default: off
 * WOLFSSL_SHAKE256:         Enable SHAKE256 XOF                   default: off
 * SHA3_BY_SPEC:             Use specification Keccak-f order      default: off
 * WC_SHA3_NO_ASM:           Disable SHA-3 assembly optimizations  default: off
 * WC_SHA3_FAULT_HARDEN:     Harden SHA-3 against fault attacks    default: off
 *
 * Hardware Acceleration (SHA-3-specific):
 * WC_ASYNC_ENABLE_SHA3:     Enable async SHA-3 operations         default: off
 * WOLFSSL_ARMASM_CRYPTO_SHA3: ARM crypto SHA-3 instructions       default: off
 * STM32_HASH_SHA3:          STM32 hardware SHA-3                  default: off
 * PSOC6_HASH_SHA3:          PSoC6 hardware SHA-3                  default: off
 */

#define _WC_BUILDING_SHA3_C

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WC_SHA3_NO_ASM
    #undef USE_INTEL_SPEEDUP
    #undef WOLFSSL_ARMASM
    #undef WOLFSSL_RISCV_ASM
#endif
#ifdef WOLFSSL_X86_BUILD
    #undef USE_INTEL_SPEEDUP
#endif

#if defined(WOLFSSL_PSOC6_CRYPTO)
    #include <wolfssl/wolfcrypt/port/cypress/psoc6_crypto.h>
#endif

#if defined(WOLFSSL_SHA3) && !defined(WOLFSSL_XILINX_CRYPT) && \
   !defined(WOLFSSL_AFALG_XILINX_SHA3)

#if FIPS_VERSION3_GE(2,0,0)
    /* set NO_WRAPPERS before headers, use direct internal f()s not wrappers */
    #define FIPS_NO_WRAPPERS

    #ifdef USE_WINDOWS_API
        #pragma code_seg(".fipsA$n")
        #pragma const_seg(".fipsB$n")
    #endif
#endif

#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/hash.h>

#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Gates the non-WOLFSSL_SHA3_SMALL software Keccak primitives
 * (hash_keccak_r, BlockSha3, InitSha3, Sha3Update, Sha3Final and the
 * Load64* helpers). Compiled when:
 *  - No HW SHA-3 backend is selected (the original baseline), OR
 *  - STM32 HW SHA-3 is selected and SHAKE is enabled - SHAKE on STM32MP13
 *    runs in software because the HASH peripheral's SHAKE support is
 *    fixed-length and does not match wolfSSL's variable-length / iterative
 *    SqueezeBlocks API. SHA-3 still uses the HASH peripheral.
 *
 * Note: the WOLFSSL_SHA3_SMALL branch earlier in this file defines its
 * own hash_keccak_r and BlockSha3 unconditionally inside its #ifdef
 * block, so this macro only controls the non-SMALL implementation. */
#if (!defined(STM32_HASH_SHA3) && !defined(PSOC6_HASH_SHA3)) || \
    (defined(STM32_HASH_SHA3) && \
     (defined(WOLFSSL_SHAKE128) || defined(WOLFSSL_SHAKE256)))
    #define WC_SHA3_SW_KECCAK
#endif

#if FIPS_VERSION3_GE(6,0,0)
    const unsigned int wolfCrypt_FIPS_sha3_ro_sanity[2] =
                                                     { 0x1a2b3c4d, 0x00000016 };
    int wolfCrypt_FIPS_SHA3_sanity(void)
    {
        return 0;
    }
#endif


#if defined(USE_INTEL_SPEEDUP) || (defined(__aarch64__) && \
        defined(WOLFSSL_ARMASM))
    #include <wolfssl/wolfcrypt/cpuid.h>

    static cpuid_flags_t cpuid_flags = WC_CPUID_INITIALIZER;
#ifdef WC_C_DYNAMIC_FALLBACK
    #define SHA3_BLOCK (sha3->sha3_block)
    #define SHA3_BLOCK_N (sha3->sha3_block_n)
#else
    void (*sha3_block)(word64 *s) = NULL;
    void (*sha3_block_n)(word64 *s, const byte* data, word32 n,
        word64 c) = NULL;
    #define SHA3_BLOCK sha3_block
    #define SHA3_BLOCK_N sha3_block_n
#endif
#endif

#ifdef USE_INTEL_SPEEDUP
    /* Block-function selection when USE_INTEL_SPEEDUP: AVX2 on Intel, else
     * BMI2, else the C block.  Measured single-instance Keccak-f[1600]
     * (Ethereum "Optimizing Keccak"; OpenSSL keccak1600-x86_64.pl): AVX2 is
     * ~13-17% faster than BMI2 on Intel Haswell..Skylake, tied on Ice Lake,
     * but ~2x SLOWER on AMD Zen, so AVX2 is Intel-only.  (Single-stream
     * AVX-512 is vpermt2q-bound and slower than BMI2 everywhere measured, so
     * it is not built - see scripts sha3_avx512.rb.)
     * Overrides: WOLFSSL_SHA3_AVX2 forces AVX2 on any vendor with it;
     *            WOLFSSL_SHA3_NO_AVX2 never uses AVX2. */
#if defined(WOLFSSL_SHA3_NO_AVX2)
    #define SHA3_USE_AVX2(f) 0
#elif defined(WOLFSSL_SHA3_AVX2)
    #define SHA3_USE_AVX2(f) IS_INTEL_AVX2(f)
#else
    #define SHA3_USE_AVX2(f) (IS_INTEL_AVX2(f) && IS_CPU_INTEL(f))
#endif

    /* True when the selected block function uses vector registers and so
     * needs the caller to save/restore them.  BMI2 and the C block use only
     * general registers. */
#ifdef WOLFSSL_SHA3_NO_AVX2
    #define SHA3_BLOCK_VREGS(f) 0
#else
    #define SHA3_BLOCK_VREGS(f) ((f) == sha3_block_avx2)
#endif
#endif

#if !defined(WOLFSSL_ARMASM) && !defined(WOLFSSL_RISCV_ASM) && \
    !defined(WOLFSSL_PPC64_ASM) && !defined(WOLFSSL_PPC32_ASM)

#ifdef WOLFSSL_SHA3_SMALL
/* Rotate a 64-bit value left.
 *
 * a  Number to rotate left.
 * r  Number od bits to rotate left.
 * returns the rotated number.
 */
#define ROTL64(a, n)    (((a)<<(n))|((a)>>(64-(n))))

/* An array of values to XOR for block operation. */
static const word64 hash_keccak_r[24] =
{
    0x0000000000000001UL, 0x0000000000008082UL,
    0x800000000000808aUL, 0x8000000080008000UL,
    0x000000000000808bUL, 0x0000000080000001UL,
    0x8000000080008081UL, 0x8000000000008009UL,
    0x000000000000008aUL, 0x0000000000000088UL,
    0x0000000080008009UL, 0x000000008000000aUL,
    0x000000008000808bUL, 0x800000000000008bUL,
    0x8000000000008089UL, 0x8000000000008003UL,
    0x8000000000008002UL, 0x8000000000000080UL,
    0x000000000000800aUL, 0x800000008000000aUL,
    0x8000000080008081UL, 0x8000000000008080UL,
    0x0000000080000001UL, 0x8000000080008008UL
};

/* Indices used in swap and rotate operation. */
#define K_I_0   10
#define K_I_1    7
#define K_I_2   11
#define K_I_3   17
#define K_I_4   18
#define K_I_5    3
#define K_I_6    5
#define K_I_7   16
#define K_I_8    8
#define K_I_9   21
#define K_I_10  24
#define K_I_11   4
#define K_I_12  15
#define K_I_13  23
#define K_I_14  19
#define K_I_15  13
#define K_I_16  12
#define K_I_17   2
#define K_I_18  20
#define K_I_19  14
#define K_I_20  22
#define K_I_21   9
#define K_I_22   6
#define K_I_23   1

/* Number of bits to rotate in swap and rotate operation. */
#define K_R_0    1
#define K_R_1    3
#define K_R_2    6
#define K_R_3   10
#define K_R_4   15
#define K_R_5   21
#define K_R_6   28
#define K_R_7   36
#define K_R_8   45
#define K_R_9   55
#define K_R_10   2
#define K_R_11  14
#define K_R_12  27
#define K_R_13  41
#define K_R_14  56
#define K_R_15   8
#define K_R_16  25
#define K_R_17  43
#define K_R_18  62
#define K_R_19  18
#define K_R_20  39
#define K_R_21  61
#define K_R_22  20
#define K_R_23  44

/* Swap and rotate left operation.
 *
 * s   The state.
 * t1  Temporary value.
 * t2  Second temporary value.
 * i   The index of the loop.
 */
#define SWAP_ROTL(s, t1, t2, i)                                         \
do {                                                                    \
    t2 = s[K_I_##i]; s[K_I_##i] = ROTL64(t1, K_R_##i);                  \
}                                                                       \
while (0)

/* Mix the XOR of the column's values into each number by column.
 *
 * s  The state.
 * b  Temporary array of XORed column values.
 * x  The index of the column.
 * t  Temporary variable.
 */
#define COL_MIX(s, b, x, t)                                             \
do {                                                                    \
    for (x = 0; x < 5; x++)                                             \
        b[x] = s[x + 0] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20]; \
    for (x = 0; x < 5; x++) {                                           \
        t = b[(x + 4) % 5] ^ ROTL64(b[(x + 1) % 5], 1);                 \
        s[x +  0] ^= t;                                                 \
        s[x +  5] ^= t;                                                 \
        s[x + 10] ^= t;                                                 \
        s[x + 15] ^= t;                                                 \
        s[x + 20] ^= t;                                                 \
    }                                                                   \
}                                                                       \
while (0)

#ifdef SHA3_BY_SPEC
/* Mix the row values.
 * BMI1 has ANDN instruction ((~a) & b) - Haswell and above.
 *
 * s   The state.
 * b   Temporary array of XORed row values.
 * y   The index of the row to work on.
 * x   The index of the column.
 * t0  Temporary variable.
 * t1  Temporary variable.
 */
#define ROW_MIX(s, b, y, x, t0, t1)                                     \
do {                                                                    \
    for (y = 0; y < 5; y++) {                                           \
        for (x = 0; x < 5; x++)                                         \
            b[x] = s[y * 5 + x];                                        \
        for (x = 0; x < 5; x++)                                         \
            s[y * 5 + x] = b[x] ^ (~b[(x + 1) % 5] & b[(x + 2) % 5]);   \
    }                                                                   \
}                                                                       \
while (0)
#else
/* Mix the row values.
 * a ^ (~b & c) == a ^ (c & (b ^ c)) == (a ^ b) ^ (b | c)
 *
 * s   The state.
 * b   Temporary array of XORed row values.
 * y   The index of the row to work on.
 * x   The index of the column.
 * t0  Temporary variable.
 * t1  Temporary variable.
 */
#define ROW_MIX(s, b, y, x, t12, t34)                                   \
do {                                                                    \
    for (y = 0; y < 5; y++) {                                           \
        for (x = 0; x < 5; x++)                                         \
            b[x] = s[y * 5 + x];                                        \
        t12 = (b[1] ^ b[2]); t34 = (b[3] ^ b[4]);                       \
        s[y * 5 + 0] = b[0] ^ (b[2] &  t12);                            \
        s[y * 5 + 1] =  t12 ^ (b[2] | b[3]);                            \
        s[y * 5 + 2] = b[2] ^ (b[4] &  t34);                            \
        s[y * 5 + 3] =  t34 ^ (b[4] | b[0]);                            \
        s[y * 5 + 4] = b[4] ^ (b[1] & (b[0] ^ b[1]));                   \
    }                                                                   \
}                                                                       \
while (0)
#endif /* SHA3_BY_SPEC */

/* The block operation performed on the state.
 *
 * s  The state.
 */
void BlockSha3(word64* s)
{
    byte i, x, y;
    word64 t0, t1;
    word64 b[5];

    for (i = 0; i < 24; i++)
    {
        COL_MIX(s, b, x, t0);

        t0 = s[1];
        SWAP_ROTL(s, t0, t1,  0);
        SWAP_ROTL(s, t1, t0,  1);
        SWAP_ROTL(s, t0, t1,  2);
        SWAP_ROTL(s, t1, t0,  3);
        SWAP_ROTL(s, t0, t1,  4);
        SWAP_ROTL(s, t1, t0,  5);
        SWAP_ROTL(s, t0, t1,  6);
        SWAP_ROTL(s, t1, t0,  7);
        SWAP_ROTL(s, t0, t1,  8);
        SWAP_ROTL(s, t1, t0,  9);
        SWAP_ROTL(s, t0, t1, 10);
        SWAP_ROTL(s, t1, t0, 11);
        SWAP_ROTL(s, t0, t1, 12);
        SWAP_ROTL(s, t1, t0, 13);
        SWAP_ROTL(s, t0, t1, 14);
        SWAP_ROTL(s, t1, t0, 15);
        SWAP_ROTL(s, t0, t1, 16);
        SWAP_ROTL(s, t1, t0, 17);
        SWAP_ROTL(s, t0, t1, 18);
        SWAP_ROTL(s, t1, t0, 19);
        SWAP_ROTL(s, t0, t1, 20);
        SWAP_ROTL(s, t1, t0, 21);
        SWAP_ROTL(s, t0, t1, 22);
        SWAP_ROTL(s, t1, t0, 23);

        ROW_MIX(s, b, y, x, t0, t1);

        s[0] ^= hash_keccak_r[i];
    }
}
#else
/* Rotate a 64-bit value left.
 *
 * a  Number to rotate left.
 * r  Number od bits to rotate left.
 * returns the rotated number.
 */
#define ROTL64(a, n)    (((a)<<(n))|((a)>>(64-(n))))

#ifdef WC_SHA3_SW_KECCAK
/* An array of values to XOR for block operation. */
static const word64 hash_keccak_r[24] =
{
    W64LIT(0x0000000000000001), W64LIT(0x0000000000008082),
    W64LIT(0x800000000000808a), W64LIT(0x8000000080008000),
    W64LIT(0x000000000000808b), W64LIT(0x0000000080000001),
    W64LIT(0x8000000080008081), W64LIT(0x8000000000008009),
    W64LIT(0x000000000000008a), W64LIT(0x0000000000000088),
    W64LIT(0x0000000080008009), W64LIT(0x000000008000000a),
    W64LIT(0x000000008000808b), W64LIT(0x800000000000008b),
    W64LIT(0x8000000000008089), W64LIT(0x8000000000008003),
    W64LIT(0x8000000000008002), W64LIT(0x8000000000000080),
    W64LIT(0x000000000000800a), W64LIT(0x800000008000000a),
    W64LIT(0x8000000080008081), W64LIT(0x8000000000008080),
    W64LIT(0x0000000080000001), W64LIT(0x8000000080008008)
};
#endif

/* Indices used in swap and rotate operation. */
#define KI_0     6
#define KI_1    12
#define KI_2    18
#define KI_3    24
#define KI_4     3
#define KI_5     9
#define KI_6    10
#define KI_7    16
#define KI_8    22
#define KI_9     1
#define KI_10    7
#define KI_11   13
#define KI_12   19
#define KI_13   20
#define KI_14    4
#define KI_15    5
#define KI_16   11
#define KI_17   17
#define KI_18   23
#define KI_19    2
#define KI_20    8
#define KI_21   14
#define KI_22   15
#define KI_23   21

/* Number of bits to rotate in swap and rotate operation. */
#define KR_0    44
#define KR_1    43
#define KR_2    21
#define KR_3    14
#define KR_4    28
#define KR_5    20
#define KR_6     3
#define KR_7    45
#define KR_8    61
#define KR_9     1
#define KR_10    6
#define KR_11   25
#define KR_12    8
#define KR_13   18
#define KR_14   27
#define KR_15   36
#define KR_16   10
#define KR_17   15
#define KR_18   56
#define KR_19   62
#define KR_20   55
#define KR_21   39
#define KR_22   41
#define KR_23    2

/* Mix the XOR of the column's values into each number by column.
 *
 * s  The state.
 * b  Temporary array of XORed column values.
 * x  The index of the column.
 * t  Temporary variable.
 */
#define COL_MIX(s, b, x, t)                                                         \
do {                                                                                \
    (b)[0] = (s)[0] ^ (s)[5] ^ (s)[10] ^ (s)[15] ^ (s)[20];                         \
    (b)[1] = (s)[1] ^ (s)[6] ^ (s)[11] ^ (s)[16] ^ (s)[21];                         \
    (b)[2] = (s)[2] ^ (s)[7] ^ (s)[12] ^ (s)[17] ^ (s)[22];                         \
    (b)[3] = (s)[3] ^ (s)[8] ^ (s)[13] ^ (s)[18] ^ (s)[23];                         \
    (b)[4] = (s)[4] ^ (s)[9] ^ (s)[14] ^ (s)[19] ^ (s)[24];                         \
    (t) = (b)[(0 + 4) % 5] ^ ROTL64((b)[(0 + 1) % 5], 1);                           \
    (s)[ 0] ^= (t); (s)[ 5] ^= (t); (s)[10] ^= (t); (s)[15] ^= (t); (s)[20] ^= (t); \
    (t) = (b)[(1 + 4) % 5] ^ ROTL64((b)[(1 + 1) % 5], 1);                           \
    (s)[ 1] ^= (t); (s)[ 6] ^= (t); (s)[11] ^= (t); (s)[16] ^= (t); (s)[21] ^= (t); \
    (t) = (b)[(2 + 4) % 5] ^ ROTL64((b)[(2 + 1) % 5], 1);                           \
    (s)[ 2] ^= (t); (s)[ 7] ^= (t); (s)[12] ^= (t); (s)[17] ^= (t); (s)[22] ^= (t); \
    (t) = (b)[(3 + 4) % 5] ^ ROTL64((b)[(3 + 1) % 5], 1);                           \
    (s)[ 3] ^= (t); (s)[ 8] ^= (t); (s)[13] ^= (t); (s)[18] ^= (t); (s)[23] ^= (t); \
    (t) = (b)[(4 + 4) % 5] ^ ROTL64((b)[(4 + 1) % 5], 1);                           \
    (s)[ 4] ^= (t); (s)[ 9] ^= (t); (s)[14] ^= (t); (s)[19] ^= (t); (s)[24] ^= (t); \
}                                                                                   \
while (0)

#define S(s1, i) ROTL64((s1)[KI_##i], KR_##i)

#ifdef SHA3_BY_SPEC
/* Mix the row values.
 * BMI1 has ANDN instruction ((~a) & b) - Haswell and above.
 *
 * s2  The new state.
 * s1  The current state.
 * b   Temporary array of XORed row values.
 * t0  Temporary variable. (Unused)
 * t1  Temporary variable. (Unused)
 */
#define ROW_MIX(s2, s1, b, t0, t1)                    \
do {                                                  \
    (b)[0] = (s1)[0];                                 \
    (b)[1] = S((s1), 0);                              \
    (b)[2] = S((s1), 1);                              \
    (b)[3] = S((s1), 2);                              \
    (b)[4] = S((s1), 3);                              \
    (s2)[0] = (b)[0] ^ (~(b)[1] & (b)[2]);            \
    (s2)[1] = (b)[1] ^ (~(b)[2] & (b)[3]);            \
    (s2)[2] = (b)[2] ^ (~(b)[3] & (b)[4]);            \
    (s2)[3] = (b)[3] ^ (~(b)[4] & (b)[0]);            \
    (s2)[4] = (b)[4] ^ (~(b)[0] & (b)[1]);            \
    (b)[0] = S((s1), 4);                              \
    (b)[1] = S((s1), 5);                              \
    (b)[2] = S((s1), 6);                              \
    (b)[3] = S((s1), 7);                              \
    (b)[4] = S((s1), 8);                              \
    (s2)[5] = (b)[0] ^ (~(b)[1] & (b)[2]);            \
    (s2)[6] = (b)[1] ^ (~(b)[2] & (b)[3]);            \
    (s2)[7] = (b)[2] ^ (~(b)[3] & (b)[4]);            \
    (s2)[8] = (b)[3] ^ (~(b)[4] & (b)[0]);            \
    (s2)[9] = (b)[4] ^ (~(b)[0] & (b)[1]);            \
    (b)[0] = S((s1), 9);                              \
    (b)[1] = S((s1), 10);                             \
    (b)[2] = S((s1), 11);                             \
    (b)[3] = S((s1), 12);                             \
    (b)[4] = S((s1), 13);                             \
    (s2)[10] = (b)[0] ^ (~(b)[1] & (b)[2]);           \
    (s2)[11] = (b)[1] ^ (~(b)[2] & (b)[3]);           \
    (s2)[12] = (b)[2] ^ (~(b)[3] & (b)[4]);           \
    (s2)[13] = (b)[3] ^ (~(b)[4] & (b)[0]);           \
    (s2)[14] = (b)[4] ^ (~(b)[0] & (b)[1]);           \
    (b)[0] = S((s1), 14);                             \
    (b)[1] = S((s1), 15);                             \
    (b)[2] = S((s1), 16);                             \
    (b)[3] = S((s1), 17);                             \
    (b)[4] = S((s1), 18);                             \
    (s2)[15] = (b)[0] ^ (~(b)[1] & (b)[2]);           \
    (s2)[16] = (b)[1] ^ (~(b)[2] & (b)[3]);           \
    (s2)[17] = (b)[2] ^ (~(b)[3] & (b)[4]);           \
    (s2)[18] = (b)[3] ^ (~(b)[4] & (b)[0]);           \
    (s2)[19] = (b)[4] ^ (~(b)[0] & (b)[1]);           \
    (b)[0] = S((s1), 19);                             \
    (b)[1] = S((s1), 20);                             \
    (b)[2] = S((s1), 21);                             \
    (b)[3] = S((s1), 22);                             \
    (b)[4] = S((s1), 23);                             \
    (s2)[20] = (b)[0] ^ (~(b)[1] & (b)[2]);           \
    (s2)[21] = (b)[1] ^ (~(b)[2] & (b)[3]);           \
    (s2)[22] = (b)[2] ^ (~(b)[3] & (b)[4]);           \
    (s2)[23] = (b)[3] ^ (~(b)[4] & (b)[0]);           \
    (s2)[24] = (b)[4] ^ (~(b)[0] & (b)[1]);           \
}                                                     \
while (0)
#else
/* Mix the row values.
 * a ^ (~b & c) == a ^ (c & (b ^ c)) == (a ^ b) ^ (b | c)
 *
 * s2  The new state.
 * s1  The current state.
 * b   Temporary array of XORed row values.
 * t12 Temporary variable.
 * t34 Temporary variable.
 */
#define ROW_MIX(s2, s1, b, t12, t34)                      \
do {                                                      \
    (b)[0] = (s1)[0];                                     \
    (b)[1] = S((s1), 0);                                  \
    (b)[2] = S((s1), 1);                                  \
    (b)[3] = S((s1), 2);                                  \
    (b)[4] = S((s1), 3);                                  \
    (t12) = ((b)[1] ^ (b)[2]); (t34) = ((b)[3] ^ (b)[4]); \
    (s2)[0] = (b)[0] ^ ((b)[2] &  (t12));                 \
    (s2)[1] =  (t12) ^ ((b)[2] | (b)[3]);                 \
    (s2)[2] = (b)[2] ^ ((b)[4] &  (t34));                 \
    (s2)[3] =  (t34) ^ ((b)[4] | (b)[0]);                 \
    (s2)[4] = (b)[4] ^ ((b)[1] & ((b)[0] ^ (b)[1]));      \
    (b)[0] = S((s1), 4);                                  \
    (b)[1] = S((s1), 5);                                  \
    (b)[2] = S((s1), 6);                                  \
    (b)[3] = S((s1), 7);                                  \
    (b)[4] = S((s1), 8);                                  \
    (t12) = ((b)[1] ^ (b)[2]); (t34) = ((b)[3] ^ (b)[4]); \
    (s2)[5] = (b)[0] ^ ((b)[2] &  (t12));                 \
    (s2)[6] =  (t12) ^ ((b)[2] | (b)[3]);                 \
    (s2)[7] = (b)[2] ^ ((b)[4] &  (t34));                 \
    (s2)[8] =  (t34) ^ ((b)[4] | (b)[0]);                 \
    (s2)[9] = (b)[4] ^ ((b)[1] & ((b)[0] ^ (b)[1]));      \
    (b)[0] = S((s1), 9);                                  \
    (b)[1] = S((s1), 10);                                 \
    (b)[2] = S((s1), 11);                                 \
    (b)[3] = S((s1), 12);                                 \
    (b)[4] = S((s1), 13);                                 \
    (t12) = ((b)[1] ^ (b)[2]); (t34) = ((b)[3] ^ (b)[4]); \
    (s2)[10] = (b)[0] ^ ((b)[2] &  (t12));                \
    (s2)[11] =  (t12) ^ ((b)[2] | (b)[3]);                \
    (s2)[12] = (b)[2] ^ ((b)[4] &  (t34));                \
    (s2)[13] =  (t34) ^ ((b)[4] | (b)[0]);                \
    (s2)[14] = (b)[4] ^ ((b)[1] & ((b)[0] ^ (b)[1]));     \
    (b)[0] = S((s1), 14);                                 \
    (b)[1] = S((s1), 15);                                 \
    (b)[2] = S((s1), 16);                                 \
    (b)[3] = S((s1), 17);                                 \
    (b)[4] = S((s1), 18);                                 \
    (t12) = ((b)[1] ^ (b)[2]); (t34) = ((b)[3] ^ (b)[4]); \
    (s2)[15] = (b)[0] ^ ((b)[2] &  (t12));                \
    (s2)[16] =  (t12) ^ ((b)[2] | (b)[3]);                \
    (s2)[17] = (b)[2] ^ ((b)[4] &  (t34));                \
    (s2)[18] =  (t34) ^ ((b)[4] | (b)[0]);                \
    (s2)[19] = (b)[4] ^ ((b)[1] & ((b)[0] ^ (b)[1]));     \
    (b)[0] = S((s1), 19);                                 \
    (b)[1] = S((s1), 20);                                 \
    (b)[2] = S((s1), 21);                                 \
    (b)[3] = S((s1), 22);                                 \
    (b)[4] = S((s1), 23);                                 \
    (t12) = ((b)[1] ^ (b)[2]); (t34) = ((b)[3] ^ (b)[4]); \
    (s2)[20] = (b)[0] ^ ((b)[2] &  (t12));                \
    (s2)[21] =  (t12) ^ ((b)[2] | (b)[3]);                \
    (s2)[22] = (b)[2] ^ ((b)[4] &  (t34));                \
    (s2)[23] =  (t34) ^ ((b)[4] | (b)[0]);                \
    (s2)[24] = (b)[4] ^ ((b)[1] & ((b)[0] ^ (b)[1]));     \
}                                                         \
while (0)
#endif /* SHA3_BY_SPEC */

#ifdef WC_SHA3_SW_KECCAK
/* The block operation performed on the state.
 *
 * s  The state.
 */
void BlockSha3(word64* s)
{
    word64 n[25];
    word64 b[5];
    word64 t0;
#ifndef SHA3_BY_SPEC
    word64 t1;
#endif
    word32 i;

    for (i = 0; i < 24; i += 2)
    {
        COL_MIX(s, b, x, t0);
        ROW_MIX(n, s, b, t0, t1);
        n[0] ^= hash_keccak_r[i];

        COL_MIX(n, b, x, t0);
        ROW_MIX(s, n, b, t0, t1);
        s[0] ^= hash_keccak_r[i+1];
    }
}
#endif /* WC_SHA3_SW_KECCAK */
#endif /* !WOLFSSL_SHA3_SMALL */
#endif /* !WOLFSSL_ARMASM && !WOLFSSL_RISCV_ASM && !WOLFSSL_PPC64_ASM &&
        * !WOLFSSL_PPC32_ASM */

#if defined(WOLFSSL_PPC64_ASM)
#if defined(WOLFSSL_PPC64_ASM_POWER8)
/* PowerPC64 provides two Keccak-f[1600] implementations: the scalar
 * BlockSha3_base and a POWER8 (PowerISA 2.07) VSX BlockSha3_power8 (which uses
 * vrld/mtvsrd).  Select the POWER8 one at run time when the CPU is POWER8 or
 * later.
 *
 * A run-time flag with direct calls is used rather than a function pointer: an
 * indirect call would require an ELFv1 function descriptor, whereas direct
 * calls work under both the ELFv1 and ELFv2 ABIs. */
#include <wolfssl/wolfcrypt/cpuid.h>

/* -1 = not yet determined, 0 = base, 1 = POWER8 */
static int sha3_use_power8 = -1;

void BlockSha3(word64* s)
{
    if (sha3_use_power8 < 0) {
        word32 f = cpuid_get_flags();
        /* The VSX permutation is only worthwhile where the scalar issue width
         * does not already win.  POWER9 (PowerISA 3.0 but not 3.1) has enough
         * scalar throughput that BlockSha3_base is faster, so use the VSX path
         * only on POWER8 and on POWER10 (3.1) or later. */
        sha3_use_power8 = IS_PPC64_ARCH_2_07(f) &&
            (!IS_PPC64_ARCH_3_00(f) || IS_PPC64_ARCH_3_1(f));
    }

    if (sha3_use_power8)
        BlockSha3_power8(s);
    else
        BlockSha3_base(s);
}
#else
/* Only the scalar implementation is built; call it directly (no run-time
 * dispatch, no function pointer). */
void BlockSha3(word64* s)
{
    BlockSha3_base(s);
}
#endif
#endif
/* Scalar PowerPC32 assembly provides BlockSha3 directly (see
 * wolfcrypt/src/port/ppc32/ppc32-sha3-asm.S), so nothing is needed here. */

#ifdef WC_SHA3_SW_KECCAK
#if defined(BIG_ENDIAN_ORDER)
static WC_INLINE word64 Load64Unaligned(const unsigned char *a)
{
    return ((word64)a[0] <<  0) |
           ((word64)a[1] <<  8) |
           ((word64)a[2] << 16) |
           ((word64)a[3] << 24) |
           ((word64)a[4] << 32) |
           ((word64)a[5] << 40) |
           ((word64)a[6] << 48) |
           ((word64)a[7] << 56);
}

/* Convert the array of bytes, in little-endian order, to a 64-bit integer.
 *
 * a  Array of bytes.
 * returns a 64-bit integer.
 */
static word64 Load64BitLittleEndian(const byte* a)
{
    word64 n = 0;
    int i;

    for (i = 0; i < 8; i++)
        n |= (word64)a[i] << (8 * i);

    return n;
}
#elif defined(WC_SHA3_FAULT_HARDEN)
static WC_INLINE word64 Load64Unaligned(const unsigned char *a) {
    return readUnalignedWord64(a);
}

/* Convert the array of bytes, in little-endian order, to a 64-bit integer.
 *
 * a  Array of bytes.
 * returns a 64-bit integer.
 */
static word64 Load64BitLittleEndian(const byte* a)
{
    return Load64Unaligned(a);
}
#endif

/* Initialize the state for a SHA3-224 hash operation.
 *
 * sha3   wc_Sha3 object holding state.
 * returns 0 on success.
 */

static int InitSha3(wc_Sha3* sha3)
{
    int i;

    for (i = 0; i < 25; i++)
        sha3->s[i] = 0;
    XMEMSET(sha3->t, 0, sizeof(sha3->t));
    sha3->i = 0;
#ifdef WOLFSSL_HASH_FLAGS
    sha3->flags = 0;
#endif
#ifdef WOLF_CRYPTO_CB
    /* Cached hash variant is tied to sponge state; clear it whenever the
     * state is reset so reuse for a different SHA3 variant dispatches
     * correctly through the crypto callback. */
    sha3->hashType = WC_HASH_TYPE_NONE;
#endif

#ifdef USE_INTEL_SPEEDUP
    {
        int cpuid_flags_were_updated = cpuid_get_flags_ex(&cpuid_flags);
#ifdef WC_C_DYNAMIC_FALLBACK
        (void)cpuid_flags_were_updated;
        if (! CAN_SAVE_VECTOR_REGISTERS()) {
            SHA3_BLOCK = BlockSha3;
            SHA3_BLOCK_N = NULL;
        }
        else
#else
        if ((! cpuid_flags_were_updated) && (SHA3_BLOCK != NULL)) {
        }
        else
#endif
        /* See the selection comment above: AVX2 on Intel, otherwise BMI2. */
        if (SHA3_USE_AVX2(cpuid_flags)) {
            SHA3_BLOCK = sha3_block_avx2;
            SHA3_BLOCK_N = sha3_block_n_avx2;
        }
        else if (IS_INTEL_BMI1(cpuid_flags) && IS_INTEL_BMI2(cpuid_flags)) {
            SHA3_BLOCK = sha3_block_bmi2;
            SHA3_BLOCK_N = sha3_block_n_bmi2;
        }
        else {
            SHA3_BLOCK = BlockSha3;
            SHA3_BLOCK_N = NULL;
        }
    }
#define SHA3_FUNC_PTR
#endif /* USE_INTEL_SPEEDUP */
#if defined(__aarch64__) && defined(WOLFSSL_ARMASM)
    {
        int cpuid_flags_were_updated = cpuid_get_flags_ex(&cpuid_flags);
        if ((! cpuid_flags_were_updated) && (SHA3_BLOCK != NULL)) {
        }
        else
    #ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
        if (IS_AARCH64_SHA3(cpuid_flags)) {
            SHA3_BLOCK = BlockSha3_crypto;
            SHA3_BLOCK_N = NULL;
        }
        else
    #endif
        {
            SHA3_BLOCK = BlockSha3_base;
            SHA3_BLOCK_N = NULL;
        }
    }
#define SHA3_FUNC_PTR
#endif

    return 0;
}

#if defined(__aarch64__) && defined(WOLFSSL_ARMASM)
void BlockSha3(word64* s)
{
    (*SHA3_BLOCK)(s);
}
#endif

/* 32-bit ARM BlockSha3 is NEON asm; a Linux kernel module must enable NEON
 * around it (SAVE/RESTORE_VECTOR_REGISTERS), else the vpush faults. */
#if !defined(USE_INTEL_SPEEDUP) && defined(WOLFSSL_ARMASM) && \
    !defined(__aarch64__) && !defined(WOLFSSL_ARMASM_THUMB2) && \
    !defined(WOLFSSL_ARMASM_NO_NEON)
    #define WC_SHA3_NEON_SVR_BEGIN() do { \
        int _svr_ret = SAVE_VECTOR_REGISTERS2(); \
        if (_svr_ret != 0) return _svr_ret; } while (0)
    #define WC_SHA3_NEON_SVR_END()   RESTORE_VECTOR_REGISTERS()
#else
    #define WC_SHA3_NEON_SVR_BEGIN() WC_DO_NOTHING
    #define WC_SHA3_NEON_SVR_END()   WC_DO_NOTHING
#endif

/* Update the SHA-3 hash state with message data.
 *
 * sha3  wc_Sha3 object holding state.
 * data  Message data to be hashed.
 * len   Length of the message data.
 * p     Number of 64-bit numbers in a block of data to process.
 * returns 0 on success.
 */
static int Sha3Update(wc_Sha3* sha3, const byte* data, word32 len, byte p)
{
    word32 i;
    word32 blocks;
#ifdef WC_SHA3_FAULT_HARDEN
    word32 check = 0;
    word32 total_check = 0;
#endif
#ifdef USE_INTEL_SPEEDUP
#ifdef WC_C_DYNAMIC_FALLBACK
    void (*sha3_block)(word64 *s) = SHA3_BLOCK;
    void (*sha3_block_n)(word64 *s, const byte* data, word32 n,
        word64 c) = SHA3_BLOCK_N;
#endif

    if (SHA3_BLOCK_VREGS(sha3_block)) {
        int ret = SAVE_VECTOR_REGISTERS2();
        if (ret != 0) {
#ifdef WC_C_DYNAMIC_FALLBACK
            sha3_block = BlockSha3;
            sha3_block_n = NULL;
#else
            return ret;
#endif
        }
    }
#endif /* USE_INTEL_SPEEDUP */

    if (sha3->i > 0) {
        byte *t;
        byte l = (byte)(p * 8 - sha3->i);
        if (l > len) {
            l = (byte)len;
        }

        t = &sha3->t[sha3->i];
        for (i = 0; i < l; i++) {
            t[i] = data[i];
    #ifdef WC_SHA3_FAULT_HARDEN
            check++;
    #endif
        }
    #ifdef WC_SHA3_FAULT_HARDEN
        if (check != l) {
            return BAD_COND_E;
        }
        total_check += l;
    #endif
        data += i;
        len -= i;
        sha3->i = (byte)(sha3->i + i);

        if (sha3->i == p * 8) {
    #if !defined(BIG_ENDIAN_ORDER) && !defined(WC_SHA3_FAULT_HARDEN)
            xorbuf(sha3->s, sha3->t, (word32)(p * 8));
    #else
            for (i = 0; i < p; i++) {
                sha3->s[i] ^= Load64BitLittleEndian(sha3->t + 8 * i);
            #ifdef WC_SHA3_FAULT_HARDEN
                check++;
            #endif
            }
        #ifdef WC_SHA3_FAULT_HARDEN
            if (check != p + l) {
                return BAD_COND_E;
            }
            total_check += p;
        #endif
    #endif
        #ifdef SHA3_FUNC_PTR
            (*sha3_block)(sha3->s);
        #else
            WC_SHA3_NEON_SVR_BEGIN();
            BlockSha3(sha3->s);
            WC_SHA3_NEON_SVR_END();
        #endif
            sha3->i = 0;
        }
    }
    blocks = len / (p * 8U);
    #ifdef SHA3_FUNC_PTR
    if ((sha3_block_n != NULL) && (blocks > 0)) {
        (*sha3_block_n)(sha3->s, data, blocks, p * 8U);
        len -= blocks * (p * 8U);
        data += blocks * (p * 8U);
        blocks = 0;
    }
    #endif
#ifdef WC_SHA3_FAULT_HARDEN
    total_check += blocks * p;
#endif
    for (; blocks > 0; blocks--) {
#if !defined(BIG_ENDIAN_ORDER) && !defined(WC_SHA3_FAULT_HARDEN)
        xorbuf(sha3->s, data, (word32)(p * 8));
#else
        for (i = 0; i < p; i++) {
            sha3->s[i] ^= Load64Unaligned(data + 8 * i);
        #ifdef WC_SHA3_FAULT_HARDEN
            check++;
        #endif
        }
    #ifdef WC_SHA3_FAULT_HARDEN
        if (check != total_check - ((blocks - 1) * p)) {
            return BAD_COND_E;
        }
    #endif
#endif
    #ifdef SHA3_FUNC_PTR
        (*sha3_block)(sha3->s);
    #else
        WC_SHA3_NEON_SVR_BEGIN();
        BlockSha3(sha3->s);
        WC_SHA3_NEON_SVR_END();
    #endif
        len -= p * 8U;
        data += p * 8U;
    }
#ifdef WC_SHA3_FAULT_HARDEN
    if (check != total_check) {
        return BAD_COND_E;
    }
#endif
#ifdef USE_INTEL_SPEEDUP
    if (SHA3_BLOCK_VREGS(sha3_block)) {
        RESTORE_VECTOR_REGISTERS();
    }
#endif
    if (len > 0) {
        XMEMCPY(sha3->t, data, len);
    }
    sha3->i = (byte)(sha3->i + len);

    return 0;
}

/* Calculate the SHA-3 hash based on all the message data seen.
 *
 * sha3  wc_Sha3 object holding state.
 * hash  Buffer to hold the hash result.
 * p     Number of 64-bit numbers in a block of data to process.
 * len   Number of bytes in output.
 * returns 0 on success.
 */
static int Sha3Final(wc_Sha3* sha3, byte padChar, byte* hash, byte p, word32 l)
{
    word32 rate = p * 8U;
    word32 j;
#if defined(BIG_ENDIAN_ORDER) || defined(WC_SHA3_FAULT_HARDEN)
    word32 i;
#endif
#ifdef WC_SHA3_FAULT_HARDEN
    int check = 0;
#endif
#if defined(WC_C_DYNAMIC_FALLBACK) && defined(USE_INTEL_SPEEDUP)
    void (*sha3_block)(word64 *s) = SHA3_BLOCK;
#endif

#if !defined(BIG_ENDIAN_ORDER) && !defined(WC_SHA3_FAULT_HARDEN)
    xorbuf(sha3->s, sha3->t, sha3->i);
#ifdef WOLFSSL_HASH_FLAGS
    if ((p == WC_SHA3_256_COUNT) && (sha3->flags & WC_HASH_SHA3_KECCAK256)) {
        padChar = 0x01;
    }
#endif
    ((byte*)sha3->s)[sha3->i ] ^= padChar;
    ((byte*)sha3->s)[rate - 1] ^= 0x80;
#else
    sha3->t[rate - 1]  = 0x00;
#ifdef WOLFSSL_HASH_FLAGS
    if ((p == WC_SHA3_256_COUNT) && (sha3->flags & WC_HASH_SHA3_KECCAK256)) {
        padChar = 0x01;
    }
#endif
    sha3->t[sha3->i ]  = padChar;
    sha3->t[rate - 1] |= 0x80;
    if (rate - 1 > (word32)sha3->i + 1) {
        XMEMSET(sha3->t + sha3->i + 1, 0, rate - 1U - (sha3->i + 1U));
    }
    for (i = 0; i < p; i++) {
        sha3->s[i] ^= Load64BitLittleEndian(sha3->t + 8 * i);
    #ifdef WC_SHA3_FAULT_HARDEN
        check++;
    #endif
    }
#ifdef WC_SHA3_FAULT_HARDEN
    if (check != p) {
        return BAD_COND_E;
    }
#endif
#endif

#ifdef USE_INTEL_SPEEDUP
    if (SHA3_BLOCK_VREGS(sha3_block)) {
        int ret = SAVE_VECTOR_REGISTERS2();
        if (ret != 0) {
#ifdef WC_C_DYNAMIC_FALLBACK
            sha3_block = BlockSha3;
#else
            return ret;
#endif
        }
    }
#endif

    for (j = 0; l - j >= rate; j += rate) {
    #ifdef SHA3_FUNC_PTR
        (*sha3_block)(sha3->s);
    #else
        WC_SHA3_NEON_SVR_BEGIN();
        BlockSha3(sha3->s);
        WC_SHA3_NEON_SVR_END();
    #endif
    #if defined(BIG_ENDIAN_ORDER)
        ByteReverseWords64((word64*)(hash + j), sha3->s, rate);
    #else
        XMEMCPY(hash + j, sha3->s, rate);
    #endif
    }
    if (j != l) {
    #ifdef SHA3_FUNC_PTR
        (*sha3_block)(sha3->s);
    #else
        WC_SHA3_NEON_SVR_BEGIN();
        BlockSha3(sha3->s);
        WC_SHA3_NEON_SVR_END();
    #endif
    #if defined(BIG_ENDIAN_ORDER)
        ByteReverseWords64(sha3->s, sha3->s, rate);
    #endif
        XMEMCPY(hash + j, sha3->s, l - j);
    }
#ifdef USE_INTEL_SPEEDUP
    if (SHA3_BLOCK_VREGS(sha3_block)) {
        RESTORE_VECTOR_REGISTERS();
    }
#endif

    return 0;
}
#endif /* WC_SHA3_SW_KECCAK */
#if defined(STM32_HASH_SHA3)

/* Supports CubeMX HAL or Standard Peripheral Library */

static int wc_InitSha3(wc_Sha3* sha3, void* heap, int devId)
{
    if (sha3 == NULL)
        return BAD_FUNC_ARG;

    (void)devId;
    (void)heap;

    XMEMSET(sha3, 0, sizeof(wc_Sha3));
    wc_Stm32_Hash_Init(&sha3->stmCtx);
    return 0;
}

static int Stm32GetAlgo(byte p)
{
    switch(p) {
        case WC_SHA3_224_COUNT:
            return HASH_ALGOSELECTION_SHA3_224;
        case WC_SHA3_256_COUNT:
            return HASH_ALGOSELECTION_SHA3_256;
        case WC_SHA3_384_COUNT:
            return HASH_ALGOSELECTION_SHA3_384;
        case WC_SHA3_512_COUNT:
            return HASH_ALGOSELECTION_SHA3_512;
    }
    /* Should never get here */
    return WC_SHA3_224_COUNT;
}

static int wc_Sha3Update(wc_Sha3* sha3, const byte* data, word32 len, byte p)
{
    int ret = 0;

    if (sha3 == NULL) {
        return BAD_FUNC_ARG;
    }
    if (data == NULL && len == 0) {
        /* valid, but do nothing */
        return 0;
    }
    if (data == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        ret = wc_Stm32_Hash_Update(&sha3->stmCtx, Stm32GetAlgo(p), data, len,
            p * 8);
        wolfSSL_CryptHwMutexUnLock();
    }
    return ret;
}

static int wc_Sha3Final(wc_Sha3* sha3, byte* hash, byte p, byte len)
{
    int ret = 0;

    if (sha3 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        ret = wc_Stm32_Hash_Final(&sha3->stmCtx, Stm32GetAlgo(p), hash, len);
        wolfSSL_CryptHwMutexUnLock();
    }

    (void)wc_InitSha3(sha3, NULL, 0); /* reset state */

    return ret;
}
#elif defined(PSOC6_HASH_SHA3)

static int wc_InitSha3(wc_Sha3* sha3, void* heap, int devId)
{
    int ret;
    if (sha3 == NULL) {
        return BAD_FUNC_ARG;
    }
    (void)devId;
    (void)heap;

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Initialize hash state for SHA-3 operation */
        ret = wc_Psoc6_Sha3_Init(sha3);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    return ret;
}

static int wc_Sha3Update(wc_Sha3* sha3, const byte* data, word32 len, byte p)
{
    int ret;

    if (sha3 == NULL || (data == NULL && len > 0)) {
        return BAD_FUNC_ARG;
    }

    if (data == NULL && len == 0) {
        /* valid, but do nothing */
        return 0;
    }

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Perform SHA3 on the input data and update the hash state */
        ret = wc_Psoc6_Sha3_Update(sha3, data, len, p);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    return ret;
}

static int wc_Sha3Final(wc_Sha3* sha3, byte* hash, byte p, byte len)
{
    int ret;

    if (sha3 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Finalize SHA3 operations and produce digest */
        ret = wc_Psoc6_Sha3_Final(sha3, 0x06, hash, p, len);
        if (ret == 0) {
            /* Initialize hash state for SHA-3 operation */
            ret = wc_Psoc6_Sha3_Init(sha3);
        }
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    return ret;
}

#else

/* Initialize the state for a SHA-3 hash operation.
 *
 * sha3   wc_Sha3 object holding state.
 * heap   Heap reference for dynamic memory allocation. (Used in async ops.)
 * devId  Device identifier for asynchronous operation.
 * returns 0 on success.
 */
static int wc_InitSha3(wc_Sha3* sha3, void* heap, int devId)
{
    int ret = 0;

    if (sha3 == NULL)
        return BAD_FUNC_ARG;

    sha3->heap = heap;
    ret = InitSha3(sha3);
    if (ret != 0)
        return ret;

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA3)
    ret = wolfAsync_DevCtxInit(&sha3->asyncDev,
                        WOLFSSL_ASYNC_MARKER_SHA3, sha3->heap, devId);
#endif
#if defined(WOLF_CRYPTO_CB)
    sha3->devId = devId;
    sha3->devCtx = NULL;
    /* Set to none to determine the hash type later */
    /* in the update/final functions based on the p value */
    sha3->hashType = WC_HASH_TYPE_NONE;
#endif
    (void)devId;

    return ret;
}

#if !(defined(WOLFSSL_NOSHA3_224) && defined(WOLFSSL_NOSHA3_256) && \
      defined(WOLFSSL_NOSHA3_384) && defined(WOLFSSL_NOSHA3_512))
/* Update the SHA-3 hash state with message data.
 *
 * sha3  wc_Sha3 object holding state.
 * data  Message data to be hashed.
 * len   Length of the message data.
 * p     Number of 64-bit numbers in a block of data to process.
 * returns 0 on success.
 */
static int wc_Sha3Update(wc_Sha3* sha3, const byte* data, word32 len, byte p)
{
    int ret;

    if (sha3 == NULL) {
        return BAD_FUNC_ARG;
    }

    if (data == NULL && len == 0) {
        /* valid, but do nothing */
        return 0;
    }

    if (data == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (sha3->devId != INVALID_DEVID)
    #endif
    {
        /* If the hash type is not set, determine it based on the p value */
        /* We can skip the switch statement if the hash type set already */
        if (sha3->hashType == WC_HASH_TYPE_NONE) {
            switch (p) {
                case WC_SHA3_224_COUNT:
                    sha3->hashType = WC_HASH_TYPE_SHA3_224; break;
                case WC_SHA3_256_COUNT:
                    sha3->hashType = WC_HASH_TYPE_SHA3_256; break;
                case WC_SHA3_384_COUNT:
                    sha3->hashType = WC_HASH_TYPE_SHA3_384; break;
                case WC_SHA3_512_COUNT:
                    sha3->hashType = WC_HASH_TYPE_SHA3_512; break;
                default: return BAD_FUNC_ARG;
            }
        }
        ret = wc_CryptoCb_Sha3Hash(sha3, sha3->hashType, data, len, NULL);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
    }
#endif
#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA3)
    if (sha3->asyncDev.marker == WOLFSSL_ASYNC_MARKER_SHA3) {
    #if defined(HAVE_INTEL_QA) && defined(QAT_V2)
        /* QAT only supports SHA3_256 */
        if (p == WC_SHA3_256_COUNT) {
            ret = IntelQaSymSha3(&sha3->asyncDev, NULL, data, len);
            if (ret != WC_NO_ERR_TRACE(NOT_COMPILED_IN))
                return ret;
            /* fall-through when unavailable */
        }
    #endif
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    ret = Sha3Update(sha3, data, len, p);

    return ret;
}

/* Calculate the SHA-3 hash based on all the message data seen.
 *
 * sha3  wc_Sha3 object holding state.
 * hash  Buffer to hold the hash result.
 * p     Number of 64-bit numbers in a block of data to process.
 * len   Number of bytes in output.
 * returns 0 on success.
 */
static int wc_Sha3Final(wc_Sha3* sha3, byte* hash, byte p, byte len)
{
    int ret;

    if (sha3 == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (sha3->devId != INVALID_DEVID)
    #endif
    {
        /* If the hash type is not set, determine it based on the p value */
        /* We can skip the switch statement if the hash type is set already */
        if (sha3->hashType == WC_HASH_TYPE_NONE) {
            switch (p) {
                case WC_SHA3_224_COUNT:
                    sha3->hashType = WC_HASH_TYPE_SHA3_224; break;
                case WC_SHA3_256_COUNT:
                    sha3->hashType = WC_HASH_TYPE_SHA3_256; break;
                case WC_SHA3_384_COUNT:
                    sha3->hashType = WC_HASH_TYPE_SHA3_384; break;
                case WC_SHA3_512_COUNT:
                    sha3->hashType = WC_HASH_TYPE_SHA3_512; break;
                default: return BAD_FUNC_ARG;
            }
        }
        ret = wc_CryptoCb_Sha3Hash(sha3, sha3->hashType, NULL, 0, hash);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
    }
#endif
#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA3)
    if (sha3->asyncDev.marker == WOLFSSL_ASYNC_MARKER_SHA3) {
    #if defined(HAVE_INTEL_QA) && defined(QAT_V2)
        /* QAT only supports SHA3_256 */
        /* QAT SHA-3 only supported on v2 (8970 or later cards) */
        if (len == WC_SHA3_256_DIGEST_SIZE) {
            ret = IntelQaSymSha3(&sha3->asyncDev, hash, NULL, len);
            if (ret != WC_NO_ERR_TRACE(NOT_COMPILED_IN))
                return ret;
            /* fall-through when unavailable */
        }
    #endif
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    ret = Sha3Final(sha3, 0x06, hash, p, (word32)len);
    if (ret != 0)
        return ret;

    return InitSha3(sha3);  /* reset state */
}
#endif
#endif

/* Dispose of any dynamically allocated data from the SHA3-384 operation.
 * (Required for async ops.)
 *
 * sha3  wc_Sha3 object holding state.
 * returns 0 on success.
 */
static void wc_Sha3Free(wc_Sha3* sha3)
{
#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_FREE)
    int ret = 0;
#endif

    (void)sha3;

#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_FREE)
    if (sha3 == NULL)
        return;

    #ifndef WOLF_CRYPTO_CB_FIND
    if (sha3->devId != INVALID_DEVID)
    #endif
    {
        ret = wc_CryptoCb_Free(sha3->devId, WC_ALGO_TYPE_HASH,
                         sha3->hashType, 0, (void*)sha3);
        /* If they want the standard free, they can call it themselves */
        /* via their callback setting devId to INVALID_DEVID */
        /* otherwise assume the callback handled it */
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return;
        /* fall-through when unavailable */
    }

    /* silence compiler warning */
    (void)ret;

#endif /* WOLF_CRYPTO_CB && WOLF_CRYPTO_CB_FREE */

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA3)
    if (sha3 == NULL)
        return;

    wolfAsync_DevCtxFree(&sha3->asyncDev, WOLFSSL_ASYNC_MARKER_SHA3);
#endif /* WOLFSSL_ASYNC_CRYPT */

#if defined(PSOC6_HASH_SHA3)
    wc_Psoc6_Sha_Free();
#endif
}

/* Copy the state of the SHA3 operation.
 *
 * src  wc_Sha3 object holding state top copy.
 * dst  wc_Sha3 object to copy into.
 * returns 0 on success.
 */
static int wc_Sha3Copy(wc_Sha3* src, wc_Sha3* dst)
{
    int ret = 0;

    if (src == NULL || dst == NULL)
        return BAD_FUNC_ARG;

#if defined(WOLF_CRYPTO_CB) && defined(WOLF_CRYPTO_CB_COPY)
    #ifndef WOLF_CRYPTO_CB_FIND
    if (src->devId != INVALID_DEVID)
    #endif
    {
        /* Cast the source and destination to be void to keep the abstraction */
        ret = wc_CryptoCb_Copy(src->devId, WC_ALGO_TYPE_HASH,
                               src->hashType, (void*)src, (void*)dst);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
    }
    ret = 0; /* Reset ret to 0 to avoid returning the callback error code */
#endif /* WOLF_CRYPTO_CB && WOLF_CRYPTO_CB_COPY */

    /* Free dst resources before copy to prevent memory leaks (e.g.,
     * hardware contexts). XMEMCPY overwrites dst. */
    wc_Sha3Free(dst);
    XMEMCPY(dst, src, sizeof(wc_Sha3));

#if defined(WOLFSSL_ASYNC_CRYPT) && defined(WC_ASYNC_ENABLE_SHA3)
    ret = wolfAsync_DevCopy(&src->asyncDev, &dst->asyncDev);
#endif

#if defined(PSOC6_HASH_SHA3)
    /* Re-initialize internal pointers in hash_state that point inside sha_buffers */
    dst->hash_state.hash = (uint8_t*)((cy_stc_crypto_v2_sha3_buffers_t *)&dst->sha_buffers)->hash;
#endif

#ifdef WOLFSSL_HASH_FLAGS
     dst->flags |= WC_HASH_FLAG_ISCOPY;
#endif

    return ret;
}

#if !(defined(WOLFSSL_NOSHA3_224) && defined(WOLFSSL_NOSHA3_256) && \
      defined(WOLFSSL_NOSHA3_384) && defined(WOLFSSL_NOSHA3_512))
/* Calculate the SHA3-224 hash based on all the message data so far.
 * More message data can be added, after this operation, using the current
 * state.
 *
 * sha3  wc_Sha3 object holding state.
 * hash  Buffer to hold the hash result. Must be at least 28 bytes.
 * p     Number of 64-bit numbers in a block of data to process.
 * len   Number of bytes in output.
 * returns 0 on success.
 */
static int wc_Sha3GetHash(wc_Sha3* sha3, byte* hash, byte p, byte len)
{
    int ret;
    WC_DECLARE_VAR(tmpSha3, wc_Sha3, 1, sha3 ? sha3->heap : NULL);

    if (sha3 == NULL || hash == NULL)
        return BAD_FUNC_ARG;

    WC_ALLOC_VAR_EX(tmpSha3, wc_Sha3, 1, sha3->heap, DYNAMIC_TYPE_TMP_BUFFER,
                    return MEMORY_E);

    XMEMSET(tmpSha3, 0, sizeof(*tmpSha3));
    ret = wc_Sha3Copy(sha3, tmpSha3);
    if (ret == 0) {
        ret = wc_Sha3Final(tmpSha3, hash, p, len);
    }

    WC_FREE_VAR_EX(tmpSha3, sha3->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#endif

#ifndef WOLFSSL_NOSHA3_224
/* Initialize the state for a SHA3-224 hash operation.
 *
 * sha3   wc_Sha3 object holding state.
 * heap   Heap reference for dynamic memory allocation. (Used in async ops.)
 * devId  Device identifier for asynchronous operation.
 * returns 0 on success.
 */
int wc_InitSha3_224(wc_Sha3* sha3, void* heap, int devId)
{
    return wc_InitSha3(sha3, heap, devId);
}

/* Update the SHA3-224 hash state with message data.
 *
 * sha3  wc_Sha3 object holding state.
 * data  Message data to be hashed.
 * len   Length of the message data.
 * returns 0 on success.
 */
int wc_Sha3_224_Update(wc_Sha3* sha3, const byte* data, word32 len)
{
    return wc_Sha3Update(sha3, data, len, WC_SHA3_224_COUNT);
}

/* Calculate the SHA3-224 hash based on all the message data seen.
 * The state is initialized ready for a new message to hash.
 *
 * sha3  wc_Sha3 object holding state.
 * hash  Buffer to hold the hash result. Must be at least 28 bytes.
 * returns 0 on success.
 */
int wc_Sha3_224_Final(wc_Sha3* sha3, byte* hash)
{
    return wc_Sha3Final(sha3, hash, WC_SHA3_224_COUNT, WC_SHA3_224_DIGEST_SIZE);
}

/* Dispose of any dynamically allocated data from the SHA3-224 operation.
 * (Required for async ops.)
 *
 * sha3  wc_Sha3 object holding state.
 * returns 0 on success.
 */
void wc_Sha3_224_Free(wc_Sha3* sha3)
{
    wc_Sha3Free(sha3);
}

/* Calculate the SHA3-224 hash based on all the message data so far.
 * More message data can be added, after this operation, using the current
 * state.
 *
 * sha3  wc_Sha3 object holding state.
 * hash  Buffer to hold the hash result. Must be at least 28 bytes.
 * returns 0 on success.
 */
int wc_Sha3_224_GetHash(wc_Sha3* sha3, byte* hash)
{
    return wc_Sha3GetHash(sha3, hash, WC_SHA3_224_COUNT, WC_SHA3_224_DIGEST_SIZE);
}

/* Copy the state of the SHA3-224 operation.
 *
 * src  wc_Sha3 object holding state top copy.
 * dst  wc_Sha3 object to copy into.
 * returns 0 on success.
 */
int wc_Sha3_224_Copy(wc_Sha3* src, wc_Sha3* dst)
{
    return wc_Sha3Copy(src, dst);
}
#endif

#ifndef WOLFSSL_NOSHA3_256
/* Initialize the state for a SHA3-256 hash operation.
 *
 * sha3   wc_Sha3 object holding state.
 * heap   Heap reference for dynamic memory allocation. (Used in async ops.)
 * devId  Device identifier for asynchronous operation.
 * returns 0 on success.
 */
int wc_InitSha3_256(wc_Sha3* sha3, void* heap, int devId)
{
    return wc_InitSha3(sha3, heap, devId);
}

/* Update the SHA3-256 hash state with message data.
 *
 * sha3  wc_Sha3 object holding state.
 * data  Message data to be hashed.
 * len   Length of the message data.
 * returns 0 on success.
 */
int wc_Sha3_256_Update(wc_Sha3* sha3, const byte* data, word32 len)
{
    return wc_Sha3Update(sha3, data, len, WC_SHA3_256_COUNT);
}

/* Calculate the SHA3-256 hash based on all the message data seen.
 * The state is initialized ready for a new message to hash.
 *
 * sha3  wc_Sha3 object holding state.
 * hash  Buffer to hold the hash result. Must be at least 32 bytes.
 * returns 0 on success.
 */
int wc_Sha3_256_Final(wc_Sha3* sha3, byte* hash)
{
    return wc_Sha3Final(sha3, hash, WC_SHA3_256_COUNT, WC_SHA3_256_DIGEST_SIZE);
}

/* Dispose of any dynamically allocated data from the SHA3-256 operation.
 * (Required for async ops.)
 *
 * sha3  wc_Sha3 object holding state.
 * returns 0 on success.
 */
void wc_Sha3_256_Free(wc_Sha3* sha3)
{
    wc_Sha3Free(sha3);
}

/* Calculate the SHA3-256 hash based on all the message data so far.
 * More message data can be added, after this operation, using the current
 * state.
 *
 * sha3  wc_Sha3 object holding state.
 * hash  Buffer to hold the hash result. Must be at least 32 bytes.
 * returns 0 on success.
 */
int wc_Sha3_256_GetHash(wc_Sha3* sha3, byte* hash)
{
    return wc_Sha3GetHash(sha3, hash, WC_SHA3_256_COUNT, WC_SHA3_256_DIGEST_SIZE);
}

/* Copy the state of the SHA3-256 operation.
 *
 * src  wc_Sha3 object holding state top copy.
 * dst  wc_Sha3 object to copy into.
 * returns 0 on success.
 */
int wc_Sha3_256_Copy(wc_Sha3* src, wc_Sha3* dst)
{
    return wc_Sha3Copy(src, dst);
}
#endif

#ifndef WOLFSSL_NOSHA3_384
/* Initialize the state for a SHA3-384 hash operation.
 *
 * sha3   wc_Sha3 object holding state.
 * heap   Heap reference for dynamic memory allocation. (Used in async ops.)
 * devId  Device identifier for asynchronous operation.
 * returns 0 on success.
 */
int wc_InitSha3_384(wc_Sha3* sha3, void* heap, int devId)
{
    return wc_InitSha3(sha3, heap, devId);
}

/* Update the SHA3-384 hash state with message data.
 *
 * sha3  wc_Sha3 object holding state.
 * data  Message data to be hashed.
 * len   Length of the message data.
 * returns 0 on success.
 */
int wc_Sha3_384_Update(wc_Sha3* sha3, const byte* data, word32 len)
{
    return wc_Sha3Update(sha3, data, len, WC_SHA3_384_COUNT);
}

/* Calculate the SHA3-384 hash based on all the message data seen.
 * The state is initialized ready for a new message to hash.
 *
 * sha3  wc_Sha3 object holding state.
 * hash  Buffer to hold the hash result. Must be at least 48 bytes.
 * returns 0 on success.
 */
int wc_Sha3_384_Final(wc_Sha3* sha3, byte* hash)
{
    return wc_Sha3Final(sha3, hash, WC_SHA3_384_COUNT, WC_SHA3_384_DIGEST_SIZE);
}

/* Dispose of any dynamically allocated data from the SHA3-384 operation.
 * (Required for async ops.)
 *
 * sha3  wc_Sha3 object holding state.
 * returns 0 on success.
 */
void wc_Sha3_384_Free(wc_Sha3* sha3)
{
    wc_Sha3Free(sha3);
}

/* Calculate the SHA3-384 hash based on all the message data so far.
 * More message data can be added, after this operation, using the current
 * state.
 *
 * sha3  wc_Sha3 object holding state.
 * hash  Buffer to hold the hash result. Must be at least 48 bytes.
 * returns 0 on success.
 */
int wc_Sha3_384_GetHash(wc_Sha3* sha3, byte* hash)
{
    return wc_Sha3GetHash(sha3, hash, WC_SHA3_384_COUNT, WC_SHA3_384_DIGEST_SIZE);
}

/* Copy the state of the SHA3-384 operation.
 *
 * src  wc_Sha3 object holding state top copy.
 * dst  wc_Sha3 object to copy into.
 * returns 0 on success.
 */
int wc_Sha3_384_Copy(wc_Sha3* src, wc_Sha3* dst)
{
    return wc_Sha3Copy(src, dst);
}
#endif

#ifndef WOLFSSL_NOSHA3_512
/* Initialize the state for a SHA3-512 hash operation.
 *
 * sha3   wc_Sha3 object holding state.
 * heap   Heap reference for dynamic memory allocation. (Used in async ops.)
 * devId  Device identifier for asynchronous operation.
 * returns 0 on success.
 */
int wc_InitSha3_512(wc_Sha3* sha3, void* heap, int devId)
{
    return wc_InitSha3(sha3, heap, devId);
}

/* Update the SHA3-512 hash state with message data.
 *
 * sha3  wc_Sha3 object holding state.
 * data  Message data to be hashed.
 * len   Length of the message data.
 * returns 0 on success.
 */
int wc_Sha3_512_Update(wc_Sha3* sha3, const byte* data, word32 len)
{
    return wc_Sha3Update(sha3, data, len, WC_SHA3_512_COUNT);
}

/* Calculate the SHA3-512 hash based on all the message data seen.
 * The state is initialized ready for a new message to hash.
 *
 * sha3  wc_Sha3 object holding state.
 * hash  Buffer to hold the hash result. Must be at least 64 bytes.
 * returns 0 on success.
 */
int wc_Sha3_512_Final(wc_Sha3* sha3, byte* hash)
{
    return wc_Sha3Final(sha3, hash, WC_SHA3_512_COUNT, WC_SHA3_512_DIGEST_SIZE);
}

/* Dispose of any dynamically allocated data from the SHA3-512 operation.
 * (Required for async ops.)
 *
 * sha3  wc_Sha3 object holding state.
 * returns 0 on success.
 */
void wc_Sha3_512_Free(wc_Sha3* sha3)
{
    wc_Sha3Free(sha3);
}

/* Calculate the SHA3-512 hash based on all the message data so far.
 * More message data can be added, after this operation, using the current
 * state.
 *
 * sha3  wc_Sha3 object holding state.
 * hash  Buffer to hold the hash result. Must be at least 64 bytes.
 * returns 0 on success.
 */
int wc_Sha3_512_GetHash(wc_Sha3* sha3, byte* hash)
{
    return wc_Sha3GetHash(sha3, hash, WC_SHA3_512_COUNT, WC_SHA3_512_DIGEST_SIZE);
}

/* Copy the state of the SHA3-512 operation.
 *
 * src  wc_Sha3 object holding state top copy.
 * dst  wc_Sha3 object to copy into.
 * returns 0 on success.
 */
int wc_Sha3_512_Copy(wc_Sha3* src, wc_Sha3* dst)
{
    return wc_Sha3Copy(src, dst);
}
#endif

#ifdef WOLFSSL_HASH_FLAGS
int wc_Sha3_SetFlags(wc_Sha3* sha3, word32 flags)
{
    if (sha3) {
        sha3->flags = flags;
    }
    return 0;
}
int wc_Sha3_GetFlags(wc_Sha3* sha3, word32* flags)
{
    if (sha3 && flags) {
        *flags = sha3->flags;
    }
    return 0;
}
#endif

#ifdef WOLFSSL_SHAKE128
/* Initialize the state for a Shake128 hash operation.
 *
 * shake  wc_Shake object holding state.
 * heap   Heap reference for dynamic memory allocation. (Used in async ops.)
 * devId  Device identifier for asynchronous operation.
 * returns 0 on success.
 */
int wc_InitShake128(wc_Shake* shake, void* heap, int devId)
{
    return wc_InitSha3(shake, heap, devId);
}

#if defined(PSOC6_HASH_SHA3)

int wc_Shake128_Update(wc_Shake* shake, const byte* data, word32 len)
{
    int ret;
    if (shake == NULL || (data == NULL && len > 0)) {
         return BAD_FUNC_ARG;
    }

    if (data == NULL && len == 0) {
        /* valid, but do nothing */
        return 0;
    }

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Perform SHA3 on the input data and update the hash state */
        ret = wc_Psoc6_Sha3_Update(shake, data, len, WC_SHA3_128_COUNT);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    return ret;
}

int wc_Shake128_Final(wc_Shake* shake, byte* hash, word32 hashLen)
{
    int ret;

    if (shake == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Finalize SHA3 operations and produce digest */
        ret = wc_Psoc6_Sha3_Final(shake, 0x1f, hash, WC_SHA3_128_COUNT, hashLen);
        if (ret == 0) {
            /* Initialize hash state for SHA-3 operation */
            ret = wc_Psoc6_Sha3_Init(shake);
        }
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    return ret;

}

int wc_Shake128_Absorb(wc_Shake* shake, const byte* data, word32 len)
{
    int ret;

    if ((shake == NULL) || (data == NULL && len != 0)) {
        return BAD_FUNC_ARG;
    }

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Perform SHA3 on the input data and update the hash state */
        ret = wc_Psoc6_Sha3_Update(shake, data, len, WC_SHA3_128_COUNT);
        if (ret == 0) {
            /* Finalize SHA3 operations and produce digest */
            ret = wc_Psoc6_Sha3_Final(shake, 0x1f, NULL, WC_SHA3_128_COUNT, 0);
        }
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    return ret;
}


int wc_Shake128_SqueezeBlocks(wc_Shake* shake, byte* out, word32 blockCnt)
{
    int ret;
    if ((shake == NULL) || (out == NULL && blockCnt != 0)) {
        return BAD_FUNC_ARG;
    }

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Squeeze output blocks from current hash state */
        ret = wc_Psoc6_Shake_SqueezeBlocks(shake, out, blockCnt);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    return ret;
}
#else
/* Update the SHAKE128 hash state with message data.
 *
 * shake  wc_Shake object holding state.
 * data  Message data to be hashed.
 * len   Length of the message data.
 * returns 0 on success.
 */
int wc_Shake128_Update(wc_Shake* shake, const byte* data, word32 len)
{
    if (shake == NULL) {
        return BAD_FUNC_ARG;
    }

    if (data == NULL && len == 0) {
        /* valid, but do nothing */
        return 0;
    }

    if (data == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (shake->devId != INVALID_DEVID)
    #endif
    {
        int ret = wc_CryptoCb_Shake(shake, WC_HASH_TYPE_SHAKE128, data, len,
            NULL, 0);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
    }
#endif

    return Sha3Update(shake, data, len, WC_SHA3_128_COUNT);
}

/* Calculate the SHAKE128 hash based on all the message data seen.
 * The state is initialized ready for a new message to hash.
 *
 * shake  wc_Shake object holding state.
 * hash  Buffer to hold the hash result. Must be at least 64 bytes.
 * returns 0 on success.
 */
int wc_Shake128_Final(wc_Shake* shake, byte* hash, word32 hashLen)
{
    int ret;

    if (shake == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (shake->devId != INVALID_DEVID)
    #endif
    {
        ret = wc_CryptoCb_Shake(shake, WC_HASH_TYPE_SHAKE128, NULL, 0, hash,
            hashLen);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
    }
#endif

    ret = Sha3Final(shake, 0x1f, hash, WC_SHA3_128_COUNT, hashLen);
    if (ret != 0)
        return ret;

    return InitSha3(shake);  /* reset state */
}

/* Absorb the data for squeezing.
 *
 * Update and final with data but no output and no reset
 *
 * shake  wc_Shake object holding state.
 * data  Data to absorb.
 * len  Length of d to absorb in bytes.
 * returns 0 on success.
 */
int wc_Shake128_Absorb(wc_Shake* shake, const byte* data, word32 len)
{
    int ret;

    if ((shake == NULL) || (data == NULL && len != 0)) {
        return BAD_FUNC_ARG;
    }

    ret = Sha3Update(shake, data, len, WC_SHA3_128_COUNT);
    if (ret == 0) {
        byte hash[1];
        ret = Sha3Final(shake, 0x1f, hash, WC_SHA3_128_COUNT, 0);
    }
    /* No partial data. */
    shake->i = 0;

    return ret;
}

#ifdef WC_C_DYNAMIC_FALLBACK
    #undef SHA3_BLOCK
    #undef SHA3_BLOCK_N
    #define SHA3_BLOCK (shake->sha3_block)
    #define SHA3_BLOCK_N (shake->sha3_block_n)
#endif

/* Squeeze the state to produce pseudo-random output.
 *
 * shake  wc_Shake object holding state.
 * out  Output buffer.
 * blockCnt  Number of blocks to write.
 * returns 0 on success.
 */
int wc_Shake128_SqueezeBlocks(wc_Shake* shake, byte* out, word32 blockCnt)
{
#if defined(WC_C_DYNAMIC_FALLBACK) && defined(USE_INTEL_SPEEDUP)
    void (*sha3_block)(word64 *s);
#endif

    if ((shake == NULL) || (out == NULL && blockCnt != 0)) {
        return BAD_FUNC_ARG;
    }

#ifdef USE_INTEL_SPEEDUP
#ifdef WC_C_DYNAMIC_FALLBACK
    sha3_block = SHA3_BLOCK;
#endif

    if (SHA3_BLOCK_VREGS(sha3_block)) {
        int ret = SAVE_VECTOR_REGISTERS2();
        if (ret != 0) {
#ifdef WC_C_DYNAMIC_FALLBACK
            sha3_block = BlockSha3;
#else
            return ret;
#endif
        }
    }
#endif /* USE_INTEL_SPEEDUP */

    for (; (blockCnt > 0); blockCnt--) {
    #ifdef SHA3_FUNC_PTR
        (*sha3_block)(shake->s);
    #else
        BlockSha3(shake->s);
    #endif
    #if defined(BIG_ENDIAN_ORDER)
        ByteReverseWords64((word64*)out, shake->s, WC_SHA3_128_COUNT * 8);
    #else
        XMEMCPY(out, shake->s, WC_SHA3_128_COUNT * 8);
    #endif
        out += WC_SHA3_128_COUNT * 8;
    }

#ifdef USE_INTEL_SPEEDUP
    if (SHA3_BLOCK_VREGS(sha3_block))
        RESTORE_VECTOR_REGISTERS();
#endif

    return 0;
}
#endif


/* Dispose of any dynamically allocated data from the SHAKE128 operation.
 * (Required for async ops.)
 *
 * shake  wc_Shake object holding state.
 * returns 0 on success.
 */
void wc_Shake128_Free(wc_Shake* shake)
{
    wc_Sha3Free(shake);
}

/* Copy the state of the SHA3-512 operation.
 *
 * src  wc_Shake object holding state top copy.
 * dst  wc_Shake object to copy into.
 * returns 0 on success.
 */
int wc_Shake128_Copy(wc_Shake* src, wc_Shake* dst)
{
    return wc_Sha3Copy(src, dst);
}
#endif

#ifdef WOLFSSL_SHAKE256
/* Initialize the state for a Shake256 hash operation.
 *
 * shake  wc_Shake object holding state.
 * heap   Heap reference for dynamic memory allocation. (Used in async ops.)
 * devId  Device identifier for asynchronous operation.
 * returns 0 on success.
 */
int wc_InitShake256(wc_Shake* shake, void* heap, int devId)
{
    return wc_InitSha3(shake, heap, devId);
}


#ifdef PSOC6_HASH_SHA3

int wc_Shake256_Update(wc_Shake* shake, const byte* data, word32 len)
{
    int ret;
    if (shake == NULL || (data == NULL && len > 0)) {
         return BAD_FUNC_ARG;
    }

    if (data == NULL && len == 0) {
        /* valid, but do nothing */
        return 0;
    }

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Perform SHA3 on the input data and update the hash state */
        ret = wc_Psoc6_Sha3_Update(shake, data, len, WC_SHA3_256_COUNT);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    return ret;
}

int wc_Shake256_Final(wc_Shake* shake, byte* hash, word32 hashLen)
{
    int ret;
    if (shake == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Finalize SHA3 operations and produce digest */
        ret = wc_Psoc6_Sha3_Final(shake, 0x1f, hash, WC_SHA3_256_COUNT, hashLen);
        if (ret == 0) {
            /* Initialize hash state for SHA-3 operation */
            ret = wc_Psoc6_Sha3_Init(shake);
        }
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    return ret;
}

int wc_Shake256_Absorb(wc_Shake* shake, const byte* data, word32 len)
{
    int ret;

    if ((shake == NULL) || (data == NULL && len != 0)) {
        return BAD_FUNC_ARG;
    }

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Perform SHA3 on the input data and update the hash state */
        ret = wc_Psoc6_Sha3_Update(shake, data, len, WC_SHA3_256_COUNT);
        if (ret == 0) {
            /* Finalize SHA3 operations and produce digest */
            ret = wc_Psoc6_Sha3_Final(shake, 0x1f, NULL, WC_SHA3_256_COUNT, 0);
        }
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    return ret;
}

int wc_Shake256_SqueezeBlocks(wc_Shake* shake, byte* out, word32 blockCnt)
{
    int ret;
    if ((shake == NULL) || (out == NULL && blockCnt != 0)) {
        return BAD_FUNC_ARG;
    }

    /* Lock the mutex to perform crypto operations */
    ret = wolfSSL_CryptHwMutexLock();
    if (ret == 0) {
        /* Squeeze output blocks from current hash state */
        ret = wc_Psoc6_Shake_SqueezeBlocks(shake, out, blockCnt);
        /* Release the lock */
        wolfSSL_CryptHwMutexUnLock();
    }

    return ret;
}

#else
/* Update the SHAKE256 hash state with message data.
 *
 * shake  wc_Shake object holding state.
 * data  Message data to be hashed.
 * len   Length of the message data.
 * returns 0 on success.
 */
int wc_Shake256_Update(wc_Shake* shake, const byte* data, word32 len)
{
    if (shake == NULL) {
        return BAD_FUNC_ARG;
    }

    if (data == NULL && len == 0) {
        /* valid, but do nothing */
        return 0;
    }

    if (data == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (shake->devId != INVALID_DEVID)
    #endif
    {
        int ret = wc_CryptoCb_Shake(shake, WC_HASH_TYPE_SHAKE256, data, len,
            NULL, 0);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
    }
#endif

    return Sha3Update(shake, data, len, WC_SHA3_256_COUNT);
}

/* Calculate the SHAKE256 hash based on all the message data seen.
 * The state is initialized ready for a new message to hash.
 *
 * shake  wc_Shake object holding state.
 * hash  Buffer to hold the hash result. Must be at least 64 bytes.
 * hashLen Size of hash in bytes.
 * returns 0 on success.
 */
int wc_Shake256_Final(wc_Shake* shake, byte* hash, word32 hashLen)
{
    int ret;

    if (shake == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLF_CRYPTO_CB
    #ifndef WOLF_CRYPTO_CB_FIND
    if (shake->devId != INVALID_DEVID)
    #endif
    {
        ret = wc_CryptoCb_Shake(shake, WC_HASH_TYPE_SHAKE256, NULL, 0, hash,
            hashLen);
        if (ret != WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE))
            return ret;
        /* fall-through when unavailable */
    }
#endif

    ret = Sha3Final(shake, 0x1f, hash, WC_SHA3_256_COUNT, hashLen);
    if (ret != 0)
        return ret;

    return InitSha3(shake);  /* reset state */
}

/* Absorb the data for squeezing.
 *
 * Update and final with data but no output and no reset
 *
 * shake  wc_Shake object holding state.
 * data  Data to absorb.
 * len  Length of d to absorb in bytes.
 * returns 0 on success.
 */
int wc_Shake256_Absorb(wc_Shake* shake, const byte* data, word32 len)
{
    int ret;

    if ((shake == NULL) || (data == NULL && len != 0)) {
        return BAD_FUNC_ARG;
    }

    ret = Sha3Update(shake, data, len, WC_SHA3_256_COUNT);
    if (ret == 0) {
        byte hash[1];
        ret = Sha3Final(shake, 0x1f, hash, WC_SHA3_256_COUNT, 0);
    }
    /* No partial data. */
    shake->i = 0;

    return ret;
}

/* Squeeze the state to produce pseudo-random output.
 *
 * shake  wc_Shake object holding state.
 * out  Output buffer.
 * blockCnt  Number of blocks to write.
 * returns 0 on success.
 */
int wc_Shake256_SqueezeBlocks(wc_Shake* shake, byte* out, word32 blockCnt)
{
#if defined(WC_C_DYNAMIC_FALLBACK) && defined(USE_INTEL_SPEEDUP)
    void (*sha3_block)(word64 *s);
#endif

    if ((shake == NULL) || (out == NULL && blockCnt != 0)) {
        return BAD_FUNC_ARG;
    }

#ifdef USE_INTEL_SPEEDUP
#ifdef WC_C_DYNAMIC_FALLBACK
    sha3_block = SHA3_BLOCK;
#endif

    if (SHA3_BLOCK_VREGS(sha3_block)) {
        int ret = SAVE_VECTOR_REGISTERS2();
        if (ret != 0) {
#ifdef WC_C_DYNAMIC_FALLBACK
            sha3_block = BlockSha3;
#else
            return ret;
#endif
        }
    }
#endif /* USE_INTEL_SPEEDUP */

    for (; (blockCnt > 0); blockCnt--) {
    #ifdef SHA3_FUNC_PTR
        (*sha3_block)(shake->s);
    #else
        BlockSha3(shake->s);
    #endif
    #if defined(BIG_ENDIAN_ORDER)
        ByteReverseWords64((word64*)out, shake->s, WC_SHA3_256_COUNT * 8);
    #else
        XMEMCPY(out, shake->s, WC_SHA3_256_COUNT * 8);
    #endif
        out += WC_SHA3_256_COUNT * 8;
    }

#ifdef USE_INTEL_SPEEDUP
    if (SHA3_BLOCK_VREGS(sha3_block))
        RESTORE_VECTOR_REGISTERS();
#endif

    return 0;
}
#endif

/* Dispose of any dynamically allocated data from the SHAKE256 operation.
 * (Required for async ops.)
 *
 * shake  wc_Shake object holding state.
 * returns 0 on success.
 */
void wc_Shake256_Free(wc_Shake* shake)
{
    wc_Sha3Free(shake);
}

/* Copy the state of the SHA3-512 operation.
 *
 * src  wc_Shake object holding state top copy.
 * dst  wc_Shake object to copy into.
 * returns 0 on success.
 */
int wc_Shake256_Copy(wc_Shake* src, wc_Shake* dst)
{
    return wc_Sha3Copy(src, dst);
}
#endif

#if (defined(WOLFSSL_KMAC) || defined(WOLFSSL_CSHAKE)) && \
    defined(WC_SHA3_SW_KECCAK)
/* cSHAKE and KMAC - NIST SP 800-185.
 *
 * cSHAKE is a customizable SHAKE; KMAC is cSHAKE keyed with the function name
 * "KMAC". Both feed length-prefixed strings into the SHAKE (KECCAK) sponge and
 * (when customized) finalize with the cSHAKE domain-separation pad byte 0x04
 * rather than SHAKE's 0x1f. The heavy lifting - absorbing message bytes and
 * squeezing output - reuses the software Sha3Update()/Sha3Final() helpers
 * above. The KMAC-specific code is compiled only when WOLFSSL_KMAC is set;
 * cSHAKE is also available on its own via WOLFSSL_CSHAKE. */

/* left_encode(value) per NIST SP 800-185, section 2.3.1.
 *
 * A length byte giving the number of value bytes, followed by that many bytes
 * of the value in big-endian (most significant first) order.
 *
 * @param [out] out    Buffer to write encoding to. Must hold at least 9 bytes.
 * @param [in]  value  Value to encode. 0 encodes as the bytes 0x01 0x00.
 *
 * @return  Number of bytes written to out - between 2 and 9.
 */
static word32 KmacLeftEncode(byte* out, word64 value)
{
    word32 n = 1;
    word64 v = value;

    /* Build up the number of significant bytes (min 1) by halving: test the
     * top 32 bits, then each smaller half, shifting away counted bytes. */
    if ((v >> 32) != 0) { n += 4; v >>= 32; }
    if ((v >> 16) != 0) { n += 2; v >>= 16; }
    if ((v >>  8) != 0) { n += 1;           }

    /* Length byte then the n value bytes big-endian.  Enter the switch at
     * case n and fall through, storing least-significant byte first into
     * out[n]..out[1]. */
    out[0] = (byte)n;
    switch (n) {
        case 8: out[8] = (byte)value; value >>= 8; FALL_THROUGH;
        case 7: out[7] = (byte)value; value >>= 8; FALL_THROUGH;
        case 6: out[6] = (byte)value; value >>= 8; FALL_THROUGH;
        case 5: out[5] = (byte)value; value >>= 8; FALL_THROUGH;
        case 4: out[4] = (byte)value; value >>= 8; FALL_THROUGH;
        case 3: out[3] = (byte)value; value >>= 8; FALL_THROUGH;
        case 2: out[2] = (byte)value; value >>= 8; FALL_THROUGH;
        default: out[1] = (byte)value;
    }

    return n + 1;
}

#ifdef WOLFSSL_KMAC
/* right_encode(value) per NIST SP 800-185, section 2.3.1. Only used by KMAC
 * (cSHAKE does not bind an output length).
 *
 * The value in big-endian (most significant first) order, followed by a length
 * byte giving the number of value bytes.
 *
 * @param [out] out    Buffer to write encoding to. Must hold at least 9 bytes.
 * @param [in]  value  Value to encode. 0 encodes as the bytes 0x00 0x01.
 *
 * @return  Number of bytes written to out - between 2 and 9.
 */
static word32 KmacRightEncode(byte* out, word64 value)
{
    word32 n = 1;
    word64 v = value;

    /* Build up the number of significant bytes (min 1) by halving: test the
     * top 32 bits, then each smaller half, shifting away counted bytes. */
    if ((v >> 32) != 0) { n += 4; v >>= 32; }
    if ((v >> 16) != 0) { n += 2; v >>= 16; }
    if ((v >>  8) != 0) { n += 1;           }

    /* The n value bytes big-endian then the length byte.  Enter the switch at
     * case n and fall through, storing least-significant byte first into
     * out[n-1]..out[0]. */
    switch (n) {
        case 8: out[7] = (byte)value; value >>= 8; FALL_THROUGH;
        case 7: out[6] = (byte)value; value >>= 8; FALL_THROUGH;
        case 6: out[5] = (byte)value; value >>= 8; FALL_THROUGH;
        case 5: out[4] = (byte)value; value >>= 8; FALL_THROUGH;
        case 4: out[3] = (byte)value; value >>= 8; FALL_THROUGH;
        case 3: out[2] = (byte)value; value >>= 8; FALL_THROUGH;
        case 2: out[1] = (byte)value; value >>= 8; FALL_THROUGH;
        default: out[0] = (byte)value;
    }
    out[n] = (byte)n;

    return n + 1;
}
#endif /* WOLFSSL_KMAC */

/* Zero-pad the current bytepad() block, per NIST SP 800-185, section 2.3.3.
 *
 * Fills the tail of the current block with zeros so the number of bytes fed
 * into the bytepad() block becomes a multiple of the KECCAK rate, then flushes
 * the completed block.  The block offset is the sponge's own shake->i.
 *
 * @param [in,out] shake  SHAKE (KECCAK) object holding the sponge state.
 * @param [in]     count  KECCAK 64-bit words per block - rate / 8.
 * @param [in]     rate   KECCAK rate in bytes - the block size.
 *
 * @return  0 on success.
 * @return  Negative error code from the sponge update on failure.
 */
static int CshakeBytePad(wc_Sha3* shake, byte count, word32 rate)
{
    int    ret = 0;
    word32 pad = (rate - shake->i) % rate;

    if (pad > 0) {
        /* Zero the rest of the block in place and flush it - a zero-length
         * update with i == rate triggers the XOR-in and permutation. */
        XMEMSET(shake->t + shake->i, 0, pad);
        shake->i = (byte)rate;
        ret = Sha3Update(shake, shake->t, 0, count);
    }
    return ret;
}

/* Absorb the leading customization block shared by cSHAKE and KMAC:
 *   bytepad(encode_string(name) || encode_string(custom), rate)
 * (NIST SP 800-185, sections 3.2 and 3.3).
 *
 * Only ever called right after Init, so the sponge is fresh (shake->i is 0
 * and shake->t is all zero). When the whole bytepad content fits in one block
 * (the common case) it is copied straight into the block buffer and flushed
 * once; otherwise the parts that may cross a block boundary go through
 * Sha3Update.
 *
 * @param [in,out] shake      SHAKE (KECCAK) object holding the sponge state.
 * @param [in]     count      KECCAK 64-bit words per block - rate / 8.
 * @param [in]     name       Function-name string, NULL when nameLen is 0.
 * @param [in]     nameLen    Length of name in bytes.
 * @param [in]     custom     Customization string, NULL when customLen is 0.
 * @param [in]     customLen  Length of custom in bytes.
 *
 * @return  0 on success.
 * @return  Negative error code from the sponge update on failure.
 */
static int CshakeAbsorbBlock(wc_Sha3* shake, byte count, const byte* name,
    word32 nameLen, const byte* custom, word32 customLen)
{
    word32 rate = (word32)count * 8U;
    byte   enc[9];
    word32 e;
    word32 h;
    word32 avail;
    int    ret = 0;

    /* left_encode(rate) || left_encode(nameLen * 8) straight into the block
     * buffer - fits at the start of a fresh block. */
    h  = KmacLeftEncode(shake->t, (word64)rate);
    h += KmacLeftEncode(shake->t + h, (word64)nameLen * 8);
    e  = KmacLeftEncode(enc, (word64)customLen * 8);
    avail = rate - h;

    /* Common case: the whole bytepad content fits in this one block, so copy
     * name || left_encode(customLen*8) || custom straight in and let the pad
     * flush it - no per-piece Sha3Update.  Conditions are ordered to avoid
     * word32 overflow when name/custom are large. */
    if ((nameLen < avail) && (e < avail - nameLen) &&
            (customLen < avail - nameLen - e)) {
        if (nameLen > 0) {
            XMEMCPY(shake->t + h, name, nameLen);
            h += nameLen;
        }
        XMEMCPY(shake->t + h, enc, e);
        h += e;
        if (customLen > 0) {
            XMEMCPY(shake->t + h, custom, customLen);
            h += customLen;
        }
        shake->i = (byte)h;
    }
    else {
        /* name and/or custom cross a block boundary - absorb them. */
        shake->i = (byte)h;
        if (nameLen > 0) {
            ret = Sha3Update(shake, name, nameLen, count);
        }
        if (ret == 0) {
            ret = Sha3Update(shake, enc, e, count);
        }
        if ((ret == 0) && (customLen > 0)) {
            ret = Sha3Update(shake, custom, customLen, count);
        }
    }

    /* bytepad zero-fill - shake->i already tracks the block offset. */
    if (ret == 0) {
        ret = CshakeBytePad(shake, count, rate);
    }
    return ret;
}

#ifdef WOLFSSL_KMAC
/* Initialize a KMAC operation for the given KECCAK block count.
 *
 * count is WC_SHA3_128_COUNT for KMAC128 or WC_SHA3_256_COUNT for KMAC256.
 * Absorbs the two leading cSHAKE/KMAC bytepad blocks, leaving the sponge ready
 * for message data (NIST SP 800-185, sections 3.2 and 4.3):
 *   bytepad(encode_string("KMAC") || encode_string(custom), rate)
 *   bytepad(encode_string(key), rate)
 *
 * @param [out] kmac       KMAC object to initialize.
 * @param [in]  count      KECCAK 64-bit words per block - rate / 8.
 * @param [in]  key        Key bytes.
 * @param [in]  keyLen     Length of key in bytes.
 * @param [in]  custom     Customization string, or NULL when customLen is 0.
 * @param [in]  customLen  Length of custom in bytes.
 * @param [in]  heap       Dynamic memory hint.
 * @param [in]  devId      Device identifier.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a NULL pointer has a non-zero length.
 * @return  Negative error code from the sponge update on failure.
 */
static int KmacInit(wc_Kmac* kmac, byte count, const byte* key, word32 keyLen,
    const byte* custom, word32 customLen, void* heap, int devId)
{
    /* The KMAC function name string "KMAC". */
    static const byte kmacName[4] = { 0x4b, 0x4d, 0x41, 0x43 };
    word32 rate;
    int    ret;

    if ((kmac == NULL) || ((key == NULL) && (keyLen != 0)) ||
            ((custom == NULL) && (customLen != 0))) {
        ret = BAD_FUNC_ARG;
    }
    else {
        kmac->count = count;
        rate = (word32)count * 8U;
        ret = wc_InitSha3(&kmac->shake, heap, devId);

        /* bytepad(encode_string("KMAC") || encode_string(custom), rate) */
        if (ret == 0) {
            ret = CshakeAbsorbBlock(&kmac->shake, count, kmacName,
                (word32)sizeof(kmacName), custom, customLen);
        }

        /* bytepad(encode_string(key), rate).  The block above flushed, so the
         * sponge is at a block boundary (shake->i == 0) - write the length
         * encodings straight into the block buffer, as in CshakeAbsorbBlock. */
        if (ret == 0) {
            word32 h;

            h  = KmacLeftEncode(kmac->shake.t, (word64)rate);
            h += KmacLeftEncode(kmac->shake.t + h, (word64)keyLen * 8);
            kmac->shake.i = (byte)h;

            if (keyLen > 0) {
                /* Copy a key that fits into the block straight in and flush
                 * once; a longer key crosses a boundary so is absorbed. */
                if (keyLen < rate - h) {
                    XMEMCPY(kmac->shake.t + h, key, keyLen);
                    kmac->shake.i += keyLen;
                }
                else {
                    ret = Sha3Update(&kmac->shake, key, keyLen, count);
                }
            }
            if (ret == 0) {
                ret = CshakeBytePad(&kmac->shake, count, rate);
            }
        }
    }

    return ret;
}

/* Absorb message data into a KMAC operation.
 *
 * @param [in,out] kmac   KMAC object holding the sponge state.
 * @param [in]     in     Message bytes, or NULL when inLen is 0.
 * @param [in]     inLen  Length of in in bytes.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG on a NULL message with a non-zero length.
 * @return  Negative error code from the sponge update on failure.
 */
static int KmacUpdate(wc_Kmac* kmac, const byte* in, word32 inLen)
{
    int ret;

    if ((kmac == NULL) || ((in == NULL) && (inLen != 0))) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = Sha3Update(&kmac->shake, in, inLen, kmac->count);
    }
    return ret;
}

/* Finalize a KMAC operation, producing outLen bytes of output.
 *
 * For fixed-length KMAC (xof == 0) the requested length is encoded into the
 * message (right_encode(outLen * 8)) before the cSHAKE pad, so changing outLen
 * changes the whole result - as required by SP 800-185. For the XOF variant
 * (xof != 0) right_encode(0) is used and any number of output bytes may be
 * produced without changing the leading bytes.
 *
 * @param [in,out] kmac    KMAC object holding the sponge state.
 * @param [out]    out     Buffer to hold output.
 * @param [in]     outLen  Number of output bytes to produce.
 * @param [in]     xof     Non-zero to finalize as an XOF - encode length 0.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when kmac or out is NULL.
 * @return  Negative error code from the sponge on failure.
 */
static int KmacFinal(wc_Kmac* kmac, byte* out, word32 outLen, int xof)
{
    word32 rate;
    int    ret = 0;

    if ((kmac == NULL) || (out == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        /* right_encode(outLen * 8), or right_encode(0) for the XOF. */
        word64 v = xof ? (word64)0 : (word64)outLen * 8;
        rate = (word32)kmac->count * 8U;

        /* The encoding is at most 9 bytes; when that many fit in the current
         * block, write it straight into the block buffer, otherwise use a
         * temporary and Sha3Update (which handles crossing the boundary). */
        if ((word32)kmac->shake.i + 9 < rate) {
            word32 l = KmacRightEncode(kmac->shake.t + kmac->shake.i, v);
            kmac->shake.i = (byte)(kmac->shake.i + l);
        }
        else {
            byte   enc[9];
            word32 encLen = KmacRightEncode(enc, v);
            ret = Sha3Update(&kmac->shake, enc, encLen, kmac->count);
        }
        if (ret == 0) {
            /* cSHAKE domain separation pad (0x04), then squeeze outLen. */
            ret = Sha3Final(&kmac->shake, 0x04, out, kmac->count, outLen);
        }
    }
    return ret;
}

/* Copy the state of a KMAC operation so it can be finalized more than once
 * (for example over a common prefix).
 *
 * dst must be an initialized wc_Kmac: the copy releases any resources it
 * already holds before overwriting it (as with wc_Sha3Copy/wc_Shake_Copy).
 *
 * @param [in]  src  KMAC object to copy from.
 * @param [out] dst  Initialized KMAC object to copy into.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when src or dst is NULL.
 * @return  Negative error code from the sponge copy on failure.
 */
static int KmacCopy(wc_Kmac* src, wc_Kmac* dst)
{
    int ret;

    if ((src == NULL) || (dst == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_Sha3Copy(&src->shake, &dst->shake);
        if (ret == 0) {
            dst->count = src->count;
        }
    }
    return ret;
}
#endif /* WOLFSSL_KMAC */

#if defined(WOLFSSL_CSHAKE128) || defined(WOLFSSL_CSHAKE256)
/* Initialize a cSHAKE operation for the given KECCAK block count.
 *
 * count is WC_SHA3_128_COUNT for cSHAKE128 or WC_SHA3_256_COUNT for cSHAKE256.
 * When both the function-name and customization strings are empty, cSHAKE is
 * defined to reduce to plain SHAKE (NIST SP 800-185, section 3.3), so no
 * customization block is absorbed and the SHAKE pad (0x1f) is used.
 *
 * @param [out] cshake     cSHAKE object to initialize.
 * @param [in]  count      KECCAK 64-bit words per block - rate / 8.
 * @param [in]  name       Function-name string, or NULL when nameLen is 0.
 * @param [in]  nameLen    Length of name in bytes.
 * @param [in]  custom     Customization string, or NULL when customLen is 0.
 * @param [in]  customLen  Length of custom in bytes.
 * @param [in]  heap       Dynamic memory hint.
 * @param [in]  devId      Device identifier.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a NULL pointer has a non-zero length.
 * @return  Negative error code from the sponge update on failure.
 */
static int CshakeInit(wc_Cshake* cshake, byte count, const byte* name,
    word32 nameLen, const byte* custom, word32 customLen, void* heap, int devId)
{
    int ret;

    if ((cshake == NULL) || ((name == NULL) && (nameLen != 0)) ||
            ((custom == NULL) && (customLen != 0))) {
        ret = BAD_FUNC_ARG;
    }
    else {
        cshake->count = count;
        ret = wc_InitSha3(&cshake->shake, heap, devId);
        if (ret == 0) {
            if ((nameLen == 0) && (customLen == 0)) {
                /* No customization: cSHAKE reduces to SHAKE. */
                cshake->pad = 0x1f;
            }
            else {
                cshake->pad = 0x04;
                ret = CshakeAbsorbBlock(&cshake->shake, count, name, nameLen,
                    custom, customLen);
            }
        }
    }
    return ret;
}

/* Absorb message data into a cSHAKE operation.
 *
 * @param [in,out] cshake  cSHAKE object holding the sponge state.
 * @param [in]     in      Message bytes, or NULL when inLen is 0.
 * @param [in]     inLen   Length of in in bytes.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG on a NULL message with a non-zero length.
 * @return  Negative error code from the sponge update on failure.
 */
static int CshakeUpdate(wc_Cshake* cshake, const byte* in, word32 inLen)
{
    int ret;

    if ((cshake == NULL) || ((in == NULL) && (inLen != 0))) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = Sha3Update(&cshake->shake, in, inLen, cshake->count);
    }
    return ret;
}

/* Finalize a cSHAKE operation, squeezing outLen bytes. cSHAKE is an XOF, so
 * the output length is not bound into the result and a longer squeeze extends
 * a shorter one.
 *
 * @param [in,out] cshake  cSHAKE object holding the sponge state.
 * @param [out]    out     Buffer to hold output.
 * @param [in]     outLen  Number of output bytes to produce.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when cshake or out is NULL.
 * @return  Negative error code from the sponge on failure.
 */
static int CshakeFinal(wc_Cshake* cshake, byte* out, word32 outLen)
{
    int ret;

    if ((cshake == NULL) || (out == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = Sha3Final(&cshake->shake, cshake->pad, out, cshake->count,
            outLen);
    }
    return ret;
}

/* Copy the state of a cSHAKE operation so it can be finalized more than once
 * (for example over a common message prefix).
 *
 * dst must be an initialized wc_Cshake: the copy releases any resources it
 * already holds before overwriting it (as with wc_Sha3Copy/wc_Shake_Copy).
 *
 * @param [in]  src  cSHAKE object to copy from.
 * @param [out] dst  Initialized cSHAKE object to copy into.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when src or dst is NULL.
 * @return  Negative error code from the sponge copy on failure.
 */
static int CshakeCopy(wc_Cshake* src, wc_Cshake* dst)
{
    int ret;

    if ((src == NULL) || (dst == NULL)) {
        ret = BAD_FUNC_ARG;
    }
    else {
        ret = wc_Sha3Copy(&src->shake, &dst->shake);
        if (ret == 0) {
            dst->count = src->count;
            dst->pad   = src->pad;
        }
    }
    return ret;
}
#endif /* WOLFSSL_CSHAKE128 || WOLFSSL_CSHAKE256 */

#ifdef WOLFSSL_KMAC128
/* Initialize a KMAC128 operation with a key and optional customization string.
 *
 * @param [out] kmac       wc_Kmac object to initialize.
 * @param [in]  key        Key bytes.
 * @param [in]  keyLen     Length of the key in bytes.
 * @param [in]  custom     Customization string, or NULL when customLen is 0.
 * @param [in]  customLen  Length of the customization string in bytes.
 * @param [in]  heap       Dynamic memory hint.
 * @param [in]  devId      Device identifier.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a required pointer is NULL.
 */
int wc_InitKmac128(wc_Kmac* kmac, const byte* key, word32 keyLen,
    const byte* custom, word32 customLen, void* heap, int devId)
{
    return KmacInit(kmac, WC_SHA3_128_COUNT, key, keyLen, custom, customLen,
        heap, devId);
}

/* Absorb message data into a KMAC128 operation.
 *
 * @param [in,out] kmac   wc_Kmac object holding state.
 * @param [in]     in     Message bytes, or NULL when inLen is 0.
 * @param [in]     inLen  Length of in in bytes.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG on a NULL message with a non-zero length.
 */
int wc_Kmac128_Update(wc_Kmac* kmac, const byte* in, word32 inLen)
{
    return KmacUpdate(kmac, in, inLen);
}

/* Finalize a KMAC128 operation, writing outLen bytes to out.
 *
 * The output length is bound into the result (NIST SP 800-185 KMAC).
 *
 * @param [in,out] kmac    wc_Kmac object holding state.
 * @param [out]    out     Buffer to hold the output.
 * @param [in]     outLen  Number of output bytes to produce.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 */
int wc_Kmac128_Final(wc_Kmac* kmac, byte* out, word32 outLen)
{
    return KmacFinal(kmac, out, outLen, 0);
}

/* Finalize a KMAC128 operation as an XOF - KMACXOF128.
 *
 * The output length is not bound into the result, so any amount of output may
 * be requested.
 *
 * @param [in,out] kmac    wc_Kmac object holding state.
 * @param [out]    out     Buffer to hold the output.
 * @param [in]     outLen  Number of output bytes to produce.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 */
int wc_Kmac128_FinalXof(wc_Kmac* kmac, byte* out, word32 outLen)
{
    return KmacFinal(kmac, out, outLen, 1);
}

/* Copy the state of a KMAC128 operation, allowing it to be finalized more
 * than once (for example over a common message prefix).
 *
 * @param [in]  src  wc_Kmac object to copy from.
 * @param [out] dst  wc_Kmac object to copy into.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when src or dst is NULL.
 */
int wc_Kmac128_Copy(wc_Kmac* src, wc_Kmac* dst)
{
    return KmacCopy(src, dst);
}

/* Dispose of any dynamically allocated data from a KMAC128 operation.
 *
 * The sponge state is key-derived, so it is zeroized on free, as with the
 * other keyed MACs, HMAC and CMAC.
 *
 * @param [in,out] kmac  wc_Kmac object to free. May be NULL.
 */
void wc_Kmac128_Free(wc_Kmac* kmac)
{
    if (kmac != NULL) {
        wc_Sha3Free(&kmac->shake);
        ForceZero(kmac, sizeof(*kmac));
    }
}

/* One-shot KMAC128 over a single message.
 *
 * @param [in]  key        Key bytes.
 * @param [in]  keyLen     Length of the key in bytes.
 * @param [in]  custom     Customization string, or NULL when customLen is 0.
 * @param [in]  customLen  Length of the customization string in bytes.
 * @param [in]  in         Message bytes, or NULL when inLen is 0.
 * @param [in]  inLen      Length of the message in bytes.
 * @param [out] out        Buffer to hold the output.
 * @param [in]  outLen     Number of output bytes to produce.
 *
 * @return  0 on success.
 * @return  Negative error code on failure.
 */
int wc_Kmac128Hash(const byte* key, word32 keyLen, const byte* custom,
    word32 customLen, const byte* in, word32 inLen, byte* out, word32 outLen)
{
    int ret = 0;
    /* Heap-allocate the state on small-stack builds (it is ~400 bytes). */
    WC_DECLARE_VAR(kmac, wc_Kmac, 1, NULL);

    WC_ALLOC_VAR_EX(kmac, wc_Kmac, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);

    if (ret == 0) {
        ret = wc_InitKmac128(kmac, key, keyLen, custom, customLen, NULL,
            INVALID_DEVID);
    }
    if (ret == 0) {
        ret = wc_Kmac128_Update(kmac, in, inLen);
    }
    if (ret == 0) {
        ret = wc_Kmac128_Final(kmac, out, outLen);
    }
    /* wc_Kmac128_Free tolerates a NULL pointer (allocation failure). */
    wc_Kmac128_Free(kmac);
    WC_FREE_VAR_EX(kmac, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

/* One-shot KMACXOF128 over a single message.
 *
 * As wc_Kmac128Hash(), but the output length is not bound into the result
 * (KMACXOF128), so any amount of output may be requested.
 *
 * @param [in]  key        Key bytes.
 * @param [in]  keyLen     Length of the key in bytes.
 * @param [in]  custom     Customization string, or NULL when customLen is 0.
 * @param [in]  customLen  Length of the customization string in bytes.
 * @param [in]  in         Message bytes, or NULL when inLen is 0.
 * @param [in]  inLen      Length of the message in bytes.
 * @param [out] out        Buffer to hold the output.
 * @param [in]  outLen     Number of output bytes to produce.
 *
 * @return  0 on success.
 * @return  Negative error code on failure.
 */
int wc_Kmac128HashXof(const byte* key, word32 keyLen, const byte* custom,
    word32 customLen, const byte* in, word32 inLen, byte* out, word32 outLen)
{
    int ret = 0;
    /* Heap-allocate the state on small-stack builds (it is ~400 bytes). */
    WC_DECLARE_VAR(kmac, wc_Kmac, 1, NULL);

    WC_ALLOC_VAR_EX(kmac, wc_Kmac, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);

    if (ret == 0) {
        ret = wc_InitKmac128(kmac, key, keyLen, custom, customLen, NULL,
            INVALID_DEVID);
    }
    if (ret == 0) {
        ret = wc_Kmac128_Update(kmac, in, inLen);
    }
    if (ret == 0) {
        ret = wc_Kmac128_FinalXof(kmac, out, outLen);
    }
    /* wc_Kmac128_Free tolerates a NULL pointer (allocation failure). */
    wc_Kmac128_Free(kmac);
    WC_FREE_VAR_EX(kmac, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}
#endif /* WOLFSSL_KMAC128 */

#ifdef WOLFSSL_KMAC256
/* Initialize a KMAC256 operation with a key and optional customization string.
 *
 * @param [out] kmac       wc_Kmac object to initialize.
 * @param [in]  key        Key bytes.
 * @param [in]  keyLen     Length of the key in bytes.
 * @param [in]  custom     Customization string, or NULL when customLen is 0.
 * @param [in]  customLen  Length of the customization string in bytes.
 * @param [in]  heap       Dynamic memory hint.
 * @param [in]  devId      Device identifier.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a required pointer is NULL.
 */
int wc_InitKmac256(wc_Kmac* kmac, const byte* key, word32 keyLen,
    const byte* custom, word32 customLen, void* heap, int devId)
{
    return KmacInit(kmac, WC_SHA3_256_COUNT, key, keyLen, custom, customLen,
        heap, devId);
}

/* Absorb message data into a KMAC256 operation.
 *
 * @param [in,out] kmac   wc_Kmac object holding state.
 * @param [in]     in     Message bytes, or NULL when inLen is 0.
 * @param [in]     inLen  Length of in in bytes.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG on a NULL message with a non-zero length.
 */
int wc_Kmac256_Update(wc_Kmac* kmac, const byte* in, word32 inLen)
{
    return KmacUpdate(kmac, in, inLen);
}

/* Finalize a KMAC256 operation, writing outLen bytes to out.
 *
 * The output length is bound into the result (NIST SP 800-185 KMAC).
 *
 * @param [in,out] kmac    wc_Kmac object holding state.
 * @param [out]    out     Buffer to hold the output.
 * @param [in]     outLen  Number of output bytes to produce.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 */
int wc_Kmac256_Final(wc_Kmac* kmac, byte* out, word32 outLen)
{
    return KmacFinal(kmac, out, outLen, 0);
}

/* Finalize a KMAC256 operation as an XOF - KMACXOF256.
 *
 * The output length is not bound into the result, so any amount of output may
 * be requested.
 *
 * @param [in,out] kmac    wc_Kmac object holding state.
 * @param [out]    out     Buffer to hold the output.
 * @param [in]     outLen  Number of output bytes to produce.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 */
int wc_Kmac256_FinalXof(wc_Kmac* kmac, byte* out, word32 outLen)
{
    return KmacFinal(kmac, out, outLen, 1);
}

/* Copy the state of a KMAC256 operation, allowing it to be finalized more
 * than once (for example over a common message prefix).
 *
 * @param [in]  src  wc_Kmac object to copy from.
 * @param [out] dst  wc_Kmac object to copy into.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when src or dst is NULL.
 */
int wc_Kmac256_Copy(wc_Kmac* src, wc_Kmac* dst)
{
    return KmacCopy(src, dst);
}

/* Dispose of any dynamically allocated data from a KMAC256 operation.
 *
 * The sponge state is key-derived, so it is zeroized on free, as with the
 * other keyed MACs, HMAC and CMAC.
 *
 * @param [in,out] kmac  wc_Kmac object to free. May be NULL.
 */
void wc_Kmac256_Free(wc_Kmac* kmac)
{
    if (kmac != NULL) {
        wc_Sha3Free(&kmac->shake);
        ForceZero(kmac, sizeof(*kmac));
    }
}

/* One-shot KMAC256 over a single message.
 *
 * @param [in]  key        Key bytes.
 * @param [in]  keyLen     Length of the key in bytes.
 * @param [in]  custom     Customization string, or NULL when customLen is 0.
 * @param [in]  customLen  Length of the customization string in bytes.
 * @param [in]  in         Message bytes, or NULL when inLen is 0.
 * @param [in]  inLen      Length of the message in bytes.
 * @param [out] out        Buffer to hold the output.
 * @param [in]  outLen     Number of output bytes to produce.
 *
 * @return  0 on success.
 * @return  Negative error code on failure.
 */
int wc_Kmac256Hash(const byte* key, word32 keyLen, const byte* custom,
    word32 customLen, const byte* in, word32 inLen, byte* out, word32 outLen)
{
    int ret = 0;
    /* Heap-allocate the state on small-stack builds (it is ~400 bytes). */
    WC_DECLARE_VAR(kmac, wc_Kmac, 1, NULL);

    WC_ALLOC_VAR_EX(kmac, wc_Kmac, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);

    if (ret == 0) {
        ret = wc_InitKmac256(kmac, key, keyLen, custom, customLen, NULL,
            INVALID_DEVID);
    }
    if (ret == 0) {
        ret = wc_Kmac256_Update(kmac, in, inLen);
    }
    if (ret == 0) {
        ret = wc_Kmac256_Final(kmac, out, outLen);
    }
    /* wc_Kmac256_Free tolerates a NULL pointer (allocation failure). */
    wc_Kmac256_Free(kmac);
    WC_FREE_VAR_EX(kmac, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

/* One-shot KMACXOF256 over a single message.
 *
 * As wc_Kmac256Hash(), but the output length is not bound into the result
 * (KMACXOF256), so any amount of output may be requested.
 *
 * @param [in]  key        Key bytes.
 * @param [in]  keyLen     Length of the key in bytes.
 * @param [in]  custom     Customization string, or NULL when customLen is 0.
 * @param [in]  customLen  Length of the customization string in bytes.
 * @param [in]  in         Message bytes, or NULL when inLen is 0.
 * @param [in]  inLen      Length of the message in bytes.
 * @param [out] out        Buffer to hold the output.
 * @param [in]  outLen     Number of output bytes to produce.
 *
 * @return  0 on success.
 * @return  Negative error code on failure.
 */
int wc_Kmac256HashXof(const byte* key, word32 keyLen, const byte* custom,
    word32 customLen, const byte* in, word32 inLen, byte* out, word32 outLen)
{
    int ret = 0;
    /* Heap-allocate the state on small-stack builds (it is ~400 bytes). */
    WC_DECLARE_VAR(kmac, wc_Kmac, 1, NULL);

    WC_ALLOC_VAR_EX(kmac, wc_Kmac, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);

    if (ret == 0) {
        ret = wc_InitKmac256(kmac, key, keyLen, custom, customLen, NULL,
            INVALID_DEVID);
    }
    if (ret == 0) {
        ret = wc_Kmac256_Update(kmac, in, inLen);
    }
    if (ret == 0) {
        ret = wc_Kmac256_FinalXof(kmac, out, outLen);
    }
    /* wc_Kmac256_Free tolerates a NULL pointer (allocation failure). */
    wc_Kmac256_Free(kmac);
    WC_FREE_VAR_EX(kmac, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}
#endif /* WOLFSSL_KMAC256 */

#ifdef WOLFSSL_CSHAKE128
/* Initialize a cSHAKE128 operation with a function-name and customization
 * string (NIST SP 800-185). Enabled together with KMAC (WOLFSSL_KMAC).
 *
 * @param [out] cshake     wc_Cshake object to initialize.
 * @param [in]  name       Function-name string, or NULL when nameLen is 0.
 *                         Reserved for NIST-defined functions; use an empty
 *                         string for application customization via custom.
 * @param [in]  nameLen    Length of name in bytes.
 * @param [in]  custom     Customization string, or NULL when customLen is 0.
 * @param [in]  customLen  Length of the customization string in bytes.
 * @param [in]  heap       Dynamic memory hint.
 * @param [in]  devId      Device identifier.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a required pointer is NULL.
 */
int wc_InitCshake128(wc_Cshake* cshake, const byte* name, word32 nameLen,
    const byte* custom, word32 customLen, void* heap, int devId)
{
    return CshakeInit(cshake, WC_SHA3_128_COUNT, name, nameLen, custom,
        customLen, heap, devId);
}

/* Absorb message data into a cSHAKE128 operation.
 *
 * @param [in,out] cshake  wc_Cshake object holding state.
 * @param [in]     in      Message bytes, or NULL when inLen is 0.
 * @param [in]     inLen   Length of in in bytes.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG on a NULL message with a non-zero length.
 */
int wc_Cshake128_Update(wc_Cshake* cshake, const byte* in, word32 inLen)
{
    return CshakeUpdate(cshake, in, inLen);
}

/* Finalize a cSHAKE128 operation, writing outLen bytes to out.
 *
 * @param [in,out] cshake  wc_Cshake object holding state.
 * @param [out]    out     Buffer to hold the output.
 * @param [in]     outLen  Number of output bytes to produce.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 */
int wc_Cshake128_Final(wc_Cshake* cshake, byte* out, word32 outLen)
{
    return CshakeFinal(cshake, out, outLen);
}

/* Copy the state of a cSHAKE128 operation, allowing it to be finalized more
 * than once (for example over a common message prefix). dst must already be
 * an initialized wc_Cshake.
 *
 * @param [in]  src  wc_Cshake object to copy from.
 * @param [out] dst  wc_Cshake object to copy into.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when src or dst is NULL.
 */
int wc_Cshake128_Copy(wc_Cshake* src, wc_Cshake* dst)
{
    return CshakeCopy(src, dst);
}

/* Dispose of any dynamically allocated data from a cSHAKE128 operation.
 *
 * @param [in,out] cshake  wc_Cshake object to free. May be NULL.
 */
void wc_Cshake128_Free(wc_Cshake* cshake)
{
    if (cshake != NULL) {
        wc_Sha3Free(&cshake->shake);
    }
}

/* One-shot cSHAKE128 over a single message.
 *
 * @param [in]  name       Function-name string, or NULL when nameLen is 0.
 * @param [in]  nameLen    Length of name in bytes.
 * @param [in]  custom     Customization string, or NULL when customLen is 0.
 * @param [in]  customLen  Length of the customization string in bytes.
 * @param [in]  in         Message bytes, or NULL when inLen is 0.
 * @param [in]  inLen      Length of the message in bytes.
 * @param [out] out        Buffer to hold the output.
 * @param [in]  outLen     Number of output bytes to produce.
 *
 * @return  0 on success.
 * @return  Negative error code on failure.
 */
int wc_Cshake128(const byte* name, word32 nameLen, const byte* custom,
    word32 customLen, const byte* in, word32 inLen, byte* out, word32 outLen)
{
    int ret = 0;
    /* Heap-allocate the state on small-stack builds (it is ~400 bytes). */
    WC_DECLARE_VAR(cshake, wc_Cshake, 1, NULL);

    WC_ALLOC_VAR_EX(cshake, wc_Cshake, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);

    if (ret == 0) {
        ret = wc_InitCshake128(cshake, name, nameLen, custom, customLen, NULL,
            INVALID_DEVID);
    }
    if (ret == 0) {
        ret = wc_Cshake128_Update(cshake, in, inLen);
    }
    if (ret == 0) {
        ret = wc_Cshake128_Final(cshake, out, outLen);
    }
    /* wc_Cshake128_Free tolerates a NULL pointer (allocation failure). */
    wc_Cshake128_Free(cshake);
    WC_FREE_VAR_EX(cshake, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}
#endif /* WOLFSSL_CSHAKE128 */

#ifdef WOLFSSL_CSHAKE256
/* Initialize a cSHAKE256 operation with a function-name and customization
 * string. See wc_InitCshake128() for parameter details.
 *
 * @param [out] cshake     wc_Cshake object to initialize.
 * @param [in]  name       Function-name string, or NULL when nameLen is 0.
 * @param [in]  nameLen    Length of name in bytes.
 * @param [in]  custom     Customization string, or NULL when customLen is 0.
 * @param [in]  customLen  Length of the customization string in bytes.
 * @param [in]  heap       Dynamic memory hint.
 * @param [in]  devId      Device identifier.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a required pointer is NULL.
 */
int wc_InitCshake256(wc_Cshake* cshake, const byte* name, word32 nameLen,
    const byte* custom, word32 customLen, void* heap, int devId)
{
    return CshakeInit(cshake, WC_SHA3_256_COUNT, name, nameLen, custom,
        customLen, heap, devId);
}

/* Absorb message data into a cSHAKE256 operation.
 *
 * @param [in,out] cshake  wc_Cshake object holding state.
 * @param [in]     in      Message bytes, or NULL when inLen is 0.
 * @param [in]     inLen   Length of in in bytes.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG on a NULL message with a non-zero length.
 */
int wc_Cshake256_Update(wc_Cshake* cshake, const byte* in, word32 inLen)
{
    return CshakeUpdate(cshake, in, inLen);
}

/* Finalize a cSHAKE256 operation, writing outLen bytes to out.
 *
 * @param [in,out] cshake  wc_Cshake object holding state.
 * @param [out]    out     Buffer to hold the output.
 * @param [in]     outLen  Number of output bytes to produce.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when a parameter is NULL.
 */
int wc_Cshake256_Final(wc_Cshake* cshake, byte* out, word32 outLen)
{
    return CshakeFinal(cshake, out, outLen);
}

/* Copy the state of a cSHAKE256 operation, allowing it to be finalized more
 * than once (for example over a common message prefix). dst must already be
 * an initialized wc_Cshake.
 *
 * @param [in]  src  wc_Cshake object to copy from.
 * @param [out] dst  wc_Cshake object to copy into.
 *
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when src or dst is NULL.
 */
int wc_Cshake256_Copy(wc_Cshake* src, wc_Cshake* dst)
{
    return CshakeCopy(src, dst);
}

/* Dispose of any dynamically allocated data from a cSHAKE256 operation.
 *
 * @param [in,out] cshake  wc_Cshake object to free. May be NULL.
 */
void wc_Cshake256_Free(wc_Cshake* cshake)
{
    if (cshake != NULL) {
        wc_Sha3Free(&cshake->shake);
    }
}

/* One-shot cSHAKE256 over a single message. See wc_Cshake128() for details.
 *
 * @param [in]  name       Function-name string, or NULL when nameLen is 0.
 * @param [in]  nameLen    Length of name in bytes.
 * @param [in]  custom     Customization string, or NULL when customLen is 0.
 * @param [in]  customLen  Length of the customization string in bytes.
 * @param [in]  in         Message bytes, or NULL when inLen is 0.
 * @param [in]  inLen      Length of the message in bytes.
 * @param [out] out        Buffer to hold the output.
 * @param [in]  outLen     Number of output bytes to produce.
 *
 * @return  0 on success.
 * @return  Negative error code on failure.
 */
int wc_Cshake256(const byte* name, word32 nameLen, const byte* custom,
    word32 customLen, const byte* in, word32 inLen, byte* out, word32 outLen)
{
    int ret = 0;
    /* Heap-allocate the state on small-stack builds (it is ~400 bytes). */
    WC_DECLARE_VAR(cshake, wc_Cshake, 1, NULL);

    WC_ALLOC_VAR_EX(cshake, wc_Cshake, 1, NULL, DYNAMIC_TYPE_TMP_BUFFER,
        ret = MEMORY_E);

    if (ret == 0) {
        ret = wc_InitCshake256(cshake, name, nameLen, custom, customLen, NULL,
            INVALID_DEVID);
    }
    if (ret == 0) {
        ret = wc_Cshake256_Update(cshake, in, inLen);
    }
    if (ret == 0) {
        ret = wc_Cshake256_Final(cshake, out, outLen);
    }
    /* wc_Cshake256_Free tolerates a NULL pointer (allocation failure). */
    wc_Cshake256_Free(cshake);
    WC_FREE_VAR_EX(cshake, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}
#endif /* WOLFSSL_CSHAKE256 */

#endif /* (WOLFSSL_KMAC || WOLFSSL_CSHAKE) && WC_SHA3_SW_KECCAK */

#endif /* WOLFSSL_SHA3 */
