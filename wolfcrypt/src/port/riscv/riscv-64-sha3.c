/* riscv-64-sha3.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/port/riscv/riscv-64-asm.h>

#ifdef WOLFSSL_RISCV_ASM
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

#ifndef WOLFSSL_RISCV_VECTOR

#define S0_0     "a1"
#define S0_1     "a2"
#define S0_2     "a3"
#define S0_3     "a4"
#define S0_4     "a5"
#define S1_0     "s1"
#define S1_1     "s2"
#define S1_2     "s3"
#define S1_3     "s4"
#define S1_4     "s5"
#define S2_0     "s6"
#define S2_1     "s7"
#define S2_2     "s8"
#define S2_3     "s9"
#define S2_4     "s10"
#define S3_0     "t0"
#define S3_1     "t1"
#define S3_2     "t2"
#define S3_3     "t3"
#define S3_4     "t4"

#define T_0      "a6"
#define T_1      "a7"
#define T_2      "t5"
#define T_3      "t6"
#define T_4      "s11"

#define SR0_0    REG_A1
#define SR0_1    REG_A2
#define SR0_2    REG_A3
#define SR0_3    REG_A4
#define SR0_4    REG_A5
#define SR1_0    REG_S1
#define SR1_1    REG_S2
#define SR1_2    REG_S3
#define SR1_3    REG_S4
#define SR1_4    REG_S5
#define SR2_0    REG_S6
#define SR2_1    REG_S7
#define SR2_2    REG_S8
#define SR2_3    REG_S9
#define SR2_4    REG_S10
#define SR3_0    REG_T0
#define SR3_1    REG_T1
#define SR3_2    REG_T2
#define SR3_3    REG_T3
#define SR3_4    REG_T4

#define TR_0     REG_A6
#define TR_1     REG_A7
#define TR_2     REG_T5
#define TR_3     REG_T6
#define TR_4     REG_S11

#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION

#define SWAP_ROTL(t0, tr0, t1, s, sr, rr, rl)       \
        "mv    " t1 ", " s  "\n\t"                  \
        "srli  " s  ", " t0 ", " #rr "\n\t"         \
        "slli  " t0 ", " t0 ", " #rl "\n\t"         \
        "or    " s  ", " s  ", " t0 "\n\t"

#define SWAP_ROTL_MEM(t0, tr0, t1, t2, s, rr, rl)   \
        "ld    " t1 ", " #s "(%[s])\n\t"            \
        "srli  " t2 ", " t0 ", " #rr "\n\t"         \
        "slli  " t0 ", " t0 ", " #rl "\n\t"         \
        "or    " t0 ", " t0 ", " t2 "\n\t"          \
        "sd    " t0 ", " #s "(%[s])\n\t"

#else

#define SWAP_ROTL(t0, tr0, t1, s, sr, rr, rl)       \
        "mv    " t1 ", " s "\n\t"                   \
        RORI(sr, tr0, rr)

#define SWAP_ROTL_MEM(t0, tr0, t1, t2, s, rr, rl)   \
        "ld    " t1 ", " #s "(%[s])\n\t"            \
        RORI(tr0, tr0, rr)                          \
        "sd    " t0 ", " #s "(%[s])\n\t"

#endif

void BlockSha3(word64* s)
{
    const word64* r = hash_keccak_r;

    __asm__ __volatile__ (
        "addi   sp, sp, -24\n\t"
        "li     " T_4 ", 24\n\t"
        "ld     " S0_0 ", 0(%[s])\n\t"
        "ld     " S0_1 ", 8(%[s])\n\t"
        "ld     " S0_2 ", 16(%[s])\n\t"
        "ld     " S0_3 ", 24(%[s])\n\t"
        "ld     " S0_4 ", 32(%[s])\n\t"
        "ld     " S1_0 ", 40(%[s])\n\t"
        "ld     " S1_1 ", 48(%[s])\n\t"
        "ld     " S1_2 ", 56(%[s])\n\t"
        "ld     " S1_3 ", 64(%[s])\n\t"
        "ld     " S1_4 ", 72(%[s])\n\t"
        "ld     " S2_0 ", 80(%[s])\n\t"
        "ld     " S2_1 ", 88(%[s])\n\t"
        "ld     " S2_2 ", 96(%[s])\n\t"
        "ld     " S2_3 ", 104(%[s])\n\t"
        "ld     " S2_4 ", 112(%[s])\n\t"
        "ld     " S3_0 ", 120(%[s])\n\t"
        "ld     " S3_1 ", 128(%[s])\n\t"
        "ld     " S3_2 ", 136(%[s])\n\t"
        "ld     " S3_3 ", 144(%[s])\n\t"
        "ld     " S3_4 ", 152(%[s])\n\t"
        "ld     " T_0 ", 160(%[s])\n\t"
        "ld     " T_1 ", 168(%[s])\n\t"
        "ld     " T_2 ", 176(%[s])\n\t"
        "\n"
    "L_riscv_64_block_sha3_loop:\n\t"
        "sd     " T_4 ", 16(sp)\n\t"

        /* COLUMN MIX */
        /* Calc b[0], b[1], b[2], b[3], b[4] */
        "ld     " T_3 ", 184(%[s])\n\t"
        "ld     " T_4 ", 192(%[s])\n\t"
        "xor    " T_0 ", " T_0 ", " S0_0 "\n\t"
        "xor    " T_1 ", " T_1 ", " S0_1 "\n\t"
        "xor    " T_2 ", " T_2 ", " S0_2 "\n\t"
        "xor    " T_3 ", " T_3 ", " S0_3 "\n\t"
        "xor    " T_4 ", " T_4 ", " S0_4 "\n\t"
        "xor    " T_0 ", " T_0 ", " S1_0 "\n\t"
        "xor    " T_1 ", " T_1 ", " S1_1 "\n\t"
        "xor    " T_2 ", " T_2 ", " S1_2 "\n\t"
        "xor    " T_3 ", " T_3 ", " S1_3 "\n\t"
        "xor    " T_4 ", " T_4 ", " S1_4 "\n\t"
        "xor    " T_0 ", " T_0 ", " S2_0 "\n\t"
        "xor    " T_1 ", " T_1 ", " S2_1 "\n\t"
        "xor    " T_2 ", " T_2 ", " S2_2 "\n\t"
        "xor    " T_3 ", " T_3 ", " S2_3 "\n\t"
        "xor    " T_4 ", " T_4 ", " S2_4 "\n\t"
        "xor    " T_0 ", " T_0 ", " S3_0 "\n\t"
        "xor    " T_1 ", " T_1 ", " S3_1 "\n\t"
        "xor    " T_2 ", " T_2 ", " S3_2 "\n\t"
        "xor    " T_3 ", " T_3 ", " S3_3 "\n\t"
        "xor    " T_4 ", " T_4 ", " S3_4 "\n\t"
        "sd     " T_1 ", 0(sp)\n\t"
        "sd     " T_3 ", 8(sp)\n\t"
        /* T_0, T_1, T_2, T_3, T_4 */

        /* s[0],s[5],s[10],s[15],s[20] ^= b[4] ^ ROTL(b[1], 1) */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "srli   " T_3 ", " T_1 ", 63\n\t"
        "slli   " T_1 ", " T_1 ", 1\n\t"
        "or     " T_1 ", " T_1 ", " T_3 "\n\t"
#else
        RORI(TR_1, TR_1, 63)
#endif
        "ld     " T_3 ", 160(%[s])\n\t"
        "xor    " T_1 ", " T_1 ", " T_4 "\n\t"
        "xor    " S0_0 ", " S0_0 ", " T_1 "\n\t"
        "xor    " S1_0 ", " S1_0 ", " T_1 "\n\t"
        "xor    " T_3 ", " T_3 ", " T_1 "\n\t"
        "xor    " S2_0 ", " S2_0 ", " T_1 "\n\t"
        "xor    " S3_0 ", " S3_0 ", " T_1 "\n\t"
        "sd     " T_3 ", 160(%[s])\n\t"
        /* T_0, T_2, T_4 */

        /* s[1],s[6],s[11],s[16],s[21] ^= b[0] ^ ROTL(b[2], 1)*/
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "srli   " T_3 ", " T_2 ", 63\n\t"
        "slli   " T_1 ", " T_2 ", 1\n\t"
        "or     " T_1 ", " T_1 ", " T_3 "\n\t"
#else
        RORI(TR_1, TR_2, 63)
#endif
        "ld     " T_3 ", 168(%[s])\n\t"
        "xor    " T_1 ", " T_1 ", " T_0 "\n\t"
        "xor    " S0_1 ", " S0_1 ", " T_1 "\n\t"
        "xor    " S1_1 ", " S1_1 ", " T_1 "\n\t"
        "xor    " T_3 ", " T_3 ", " T_1 "\n\t"
        "xor    " S2_1 ", " S2_1 ", " T_1 "\n\t"
        "xor    " S3_1 ", " S3_1 ", " T_1 "\n\t"
        "sd     " T_3 ", 168(%[s])\n\t"
        /* T_0, T_2, T_4 */

        /* s[3],s[8],s[13],s[18],s[23] ^= b[2] ^ ROTL(b[4], 1) */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "srli   " T_3 ", " T_4 ", 63\n\t"
        "slli   " T_4 ", " T_4 ", 1\n\t"
        "or     " T_4 ", " T_4 ", " T_3 "\n\t"
#else
        RORI(TR_4, TR_4, 63)
#endif
        "ld     " T_3 ", 184(%[s])\n\t"
        "xor    " T_4 ", " T_4 ", " T_2 "\n\t"
        "xor    " S0_3 ", " S0_3 ", " T_4 "\n\t"
        "xor    " S1_3 ", " S1_3 ", " T_4 "\n\t"
        "xor    " T_3 ", " T_3 ", " T_4 "\n\t"
        "xor    " S2_3 ", " S2_3 ", " T_4 "\n\t"
        "xor    " S3_3 ", " S3_3 ", " T_4 "\n\t"
        "sd     " T_3 ", 184(%[s])\n\t"
        /* T_0, T_2 */

        "ld     " T_3 ", 8(sp)\n\t"
        /* s[4],s[9],s[14],s[19],s[24] ^= b[3] ^ ROTL(b[0], 1) */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "srli   " T_2 ", " T_0 ", 63\n\t"
        "slli   " T_0 ", " T_0 ", 1\n\t"
        "or     " T_0 ", " T_0 ", " T_2 "\n\t"
#else
        RORI(TR_0, TR_0, 63)
#endif
        "ld     " T_4 ", 192(%[s])\n\t"
        "xor    " T_0 ", " T_0 ", " T_3 "\n\t"
        "xor    " S0_4 ", " S0_4 ", " T_0 "\n\t"
        "xor    " S1_4 ", " S1_4 ", " T_0 "\n\t"
        "xor    " T_4 ", " T_4 ", " T_0 "\n\t"
        "xor    " S2_4 ", " S2_4 ", " T_0 "\n\t"
        "xor    " S3_4 ", " S3_4 ", " T_0 "\n\t"
        /* T_3 */

        "ld     " T_1 ", 0(sp)\n\t"
        /* s[2],s[7],s[12],s[17],s[22] ^= b[1] ^ ROTL(b[3], 1) */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "srli   " T_2 ", " T_3 ", 63\n\t"
        "slli   " T_3 ", " T_3 ", 1\n\t"
        "or     " T_3 ", " T_3 ", " T_2 "\n\t"
#else
        RORI(TR_3, TR_3, 63)
#endif
        "ld     " T_2 ", 176(%[s])\n\t"
        "xor    " T_3 ", " T_3 ", " T_1 "\n\t"
        "xor    " S0_2 ", " S0_2 ", " T_3 "\n\t"
        "xor    " S1_2 ", " S1_2 ", " T_3 "\n\t"
        "xor    " T_2 ", " T_2 ", " T_3 "\n\t"
        "xor    " S2_2 ", " S2_2 ", " T_3 "\n\t"
        "xor    " S3_2 ", " S3_2 ", " T_3 "\n\t"

        /* SWAP ROTL */
        /* t0 = s[10], s[10] = s[1] >>> 63 */
        "mv    " T_0 ", " S2_0 "\n\t"
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "srli  " T_1 ", " S0_1 ", 63\n\t"
        "slli  " S2_0 ", " S0_1 ", 1\n\t"
        "or    " S2_0 ", " S2_0 ", " T_1 "\n\t"
#else
        RORI(SR2_0, SR0_1, 63)
#endif
        /* t1 = s[ 7], s[ 7] = t0 >>> 61 */
        SWAP_ROTL(T_0, TR_0, T_1, S1_2, SR1_2, 61, 3)
        /* t0 = s[11], s[11] = t1 >>> 58 */
        SWAP_ROTL(T_1, TR_1, T_0, S2_1, SR2_1, 58, 6)
        /* t1 = s[17], s[17] = t0 >>> 54 */
        SWAP_ROTL(T_0, TR_0, T_1, S3_2, SR3_2, 54, 10)
        /* t0 = s[18], s[18] = t1 >>> 49 */
        SWAP_ROTL(T_1, TR_1, T_0, S3_3, SR3_3, 49, 15)
        /* t1 = s[ 3], s[ 3] = t0 >>> 43 */
        SWAP_ROTL(T_0, TR_0, T_1, S0_3, SR0_3, 43, 21)
        /* t0 = s[ 5], s[ 5] = t1 >>> 36 */
        SWAP_ROTL(T_1, TR_1, T_0, S1_0, SR1_0, 36, 28)
        /* t1 = s[16], s[16] = t0 >>> 28 */
        SWAP_ROTL(T_0, TR_0, T_1, S3_1, SR3_1, 28, 36)
        /* t0 = s[ 8], s[ 8] = t1 >>> 19 */
        SWAP_ROTL(T_1, TR_1, T_0, S1_3, SR1_3, 19, 45)
        /* t1 = s[21], s[21] = t0 >>>  9 */
        SWAP_ROTL_MEM(T_0, TR_0, T_1, T_3, 168,  9, 55)
        /* t0 = s[24], s[24] = t1 >>> 62 */
        SWAP_ROTL(T_1, TR_1, T_0, T_4, TR_4, 62,  2)
        /* t1 = s[ 4], s[ 4] = t0 >>> 50 */
        SWAP_ROTL(T_0, TR_0, T_1, S0_4, SR0_4, 50, 14)
        /* t0 = s[15], s[15] = t1 >>> 37 */
        SWAP_ROTL(T_1, TR_1, T_0, S3_0, SR3_0, 37, 27)
        /* t1 = s[23], s[23] = t0 >>> 23 */
        SWAP_ROTL_MEM(T_0, TR_0, T_1, T_3, 184, 23, 41)
        /* t0 = s[19], s[19] = t1 >>>  8 */
        SWAP_ROTL(T_1, TR_1, T_0, S3_4, SR3_4,  8, 56)
        /* t1 = s[13], s[13] = t0 >>> 56 */
        SWAP_ROTL(T_0, TR_0, T_1, S2_3, SR2_3, 56,  8)
        /* t0 = s[12], s[12] = t1 >>> 39 */
        SWAP_ROTL(T_1, TR_1, T_0, S2_2, SR2_2, 39, 25)
        /* t1 = s[ 2], s[ 2] = t0 >>> 21 */
        SWAP_ROTL(T_0, TR_0, T_1, S0_2, SR0_2, 21, 43)
        /* t0 = s[20], s[20] = t1 >>>  2 */
        SWAP_ROTL_MEM(T_1, TR_1, T_0, T_3, 160,  2, 62)
        /* t1 = s[14], s[14] = t0 >>> 46 */
        SWAP_ROTL(T_0, TR_0, T_1, S2_4, SR2_4, 46, 18)
        /* t0 = s[22], s[22] = t1 >>> 25 */
        SWAP_ROTL(T_1, TR_1, T_0, T_2, TR_2, 25, 39)
        /* t1 = s[ 9], s[ 9] = t0 >>> 3 */
        SWAP_ROTL(T_0, TR_0, T_1, S1_4, SR1_4,  3, 61)
        /* t0 = s[ 6], s[ 6] = t1 >>> 44 */
        SWAP_ROTL(T_1, TR_1, T_0, S1_1, SR1_1, 44, 20)
        /*             s[ 1] = t0 >>> 20 */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "srli  " S0_1 ", " T_0 ", 20\n\t"
        "slli  " T_0 ", " T_0 ", 44\n\t"
        "or    " S0_1 ", " S0_1 ", " T_0 "\n\t"
#else
        RORI(SR0_1, TR_0, 20)
#endif

        /* ROW MIX */
        /* s[0] */
        "mv     " T_0 ", " S0_0 "\n\t"
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " S0_1 "\n\t"
        "and    " T_3 ", " T_3 ", " S0_2 "\n\t"
#else
        ANDN(TR_3, SR0_2, SR0_1)
#endif
        "xor    " S0_0 ", " S0_0 ", " T_3 "\n\t"
        /* s[1] */
        "mv     " T_1 ", " S0_1 "\n\t"
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " S0_2 "\n\t"
        "and    " T_3 ", " T_3 ", " S0_3 "\n\t"
#else
        ANDN(TR_3, SR0_3, SR0_2)
#endif
        "xor    " S0_1 ", " S0_1 ", " T_3 "\n\t"
        /* s[2] */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " S0_3 "\n\t"
        "and    " T_3 ", " T_3 ", " S0_4 "\n\t"
#else
        ANDN(TR_3, SR0_4, SR0_3)
#endif
        "xor    " S0_2 ", " S0_2 ", " T_3 "\n\t"
        /* s[3] */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " S0_4 "\n\t"
        "and    " T_3 ", " T_3 ", " T_0 "\n\t"
#else
        ANDN(TR_3, TR_0, SR0_4)
#endif
        "xor    " S0_3 ", " S0_3 ", " T_3 "\n\t"
        /* s[4] */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " T_0 "\n\t"
        "and    " T_3 ", " T_3 ", " T_1 "\n\t"
#else
        ANDN(TR_3, TR_1, TR_0)
#endif
        "xor    " S0_4 ", " S0_4 ", " T_3 "\n\t"

        /* s[5] */
        "mv     " T_0 ", " S1_0 "\n\t"
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " S1_1 "\n\t"
        "and    " T_3 ", " T_3 ", " S1_2 "\n\t"
#else
        ANDN(TR_3, SR1_2, SR1_1)
#endif
        "xor    " S1_0 ", " S1_0 ", " T_3 "\n\t"
        /* s[6] */
        "mv     " T_1 ", " S1_1 "\n\t"
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " S1_2 "\n\t"
        "and    " T_3 ", " T_3 ", " S1_3 "\n\t"
#else
        ANDN(TR_3, SR1_3, SR1_2)
#endif
        "xor    " S1_1 ", " S1_1 ", " T_3 "\n\t"
        /* s[7] */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " S1_3 "\n\t"
        "and    " T_3 ", " T_3 ", " S1_4 "\n\t"
#else
        ANDN(TR_3, SR1_4, SR1_3)
#endif
        "xor    " S1_2 ", " S1_2 ", " T_3 "\n\t"
        /* s[8] */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " S1_4 "\n\t"
        "and    " T_3 ", " T_3 ", " T_0 "\n\t"
#else
        ANDN(TR_3, TR_0, SR1_4)
#endif
        "xor    " S1_3 ", " S1_3 ", " T_3 "\n\t"
        /* s[9] */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " T_0 "\n\t"
        "and    " T_3 ", " T_3 ", " T_1 "\n\t"
#else
        ANDN(TR_3, TR_1, TR_0)
#endif
        "xor    " S1_4 ", " S1_4 ", " T_3 "\n\t"

        /* s[10] */
        "mv     " T_0 ", " S2_0 "\n\t"
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " S2_1 "\n\t"
        "and    " T_3 ", " T_3 ", " S2_2 "\n\t"
#else
        ANDN(TR_3, SR2_2, SR2_1)
#endif
        "xor    " S2_0 ", " S2_0 ", " T_3 "\n\t"
        /* s[11] */
        "mv     " T_1 ", " S2_1 "\n\t"
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " S2_2 "\n\t"
        "and    " T_3 ", " T_3 ", " S2_3 "\n\t"
#else
        ANDN(TR_3, SR2_3, SR2_2)
#endif
        "xor    " S2_1 ", " S2_1 ", " T_3 "\n\t"
        /* s[12] */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " S2_3 "\n\t"
        "and    " T_3 ", " T_3 ", " S2_4 "\n\t"
#else
        ANDN(TR_3, SR2_4, SR2_3)
#endif
        "xor    " S2_2 ", " S2_2 ", " T_3 "\n\t"
        /* s[13] */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " S2_4 "\n\t"
        "and    " T_3 ", " T_3 ", " T_0 "\n\t"
#else
        ANDN(TR_3, TR_0, SR2_4)
#endif
        "xor    " S2_3 ", " S2_3 ", " T_3 "\n\t"
        /* s[14] */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " T_0 "\n\t"
        "and    " T_3 ", " T_3 ", " T_1 "\n\t"
#else
        ANDN(TR_3, TR_1, TR_0)
#endif
        "xor    " S2_4 ", " S2_4 ", " T_3 "\n\t"

        /* s[15] */
        "mv     " T_0 ", " S3_0 "\n\t"
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " S3_1 "\n\t"
        "and    " T_3 ", " T_3 ", " S3_2 "\n\t"
#else
        ANDN(TR_3, SR3_2, SR3_1)
#endif
        "xor    " S3_0 ", " S3_0 ", " T_3 "\n\t"
        /* s[16] */
        "mv     " T_1 ", " S3_1 "\n\t"
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " S3_2 "\n\t"
        "and    " T_3 ", " T_3 ", " S3_3 "\n\t"
#else
        ANDN(TR_3, SR3_3, SR3_2)
#endif
        "xor    " S3_1 ", " S3_1 ", " T_3 "\n\t"
        /* s[17] */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " S3_3 "\n\t"
        "and    " T_3 ", " T_3 ", " S3_4 "\n\t"
#else
        ANDN(TR_3, SR3_4, SR3_3)
#endif
        "xor    " S3_2 ", " S3_2 ", " T_3 "\n\t"
        /* s[18] */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " S3_4 "\n\t"
        "and    " T_3 ", " T_3 ", " T_0 "\n\t"
#else
        ANDN(TR_3, TR_0, SR3_4)
#endif
        "xor    " S3_3 ", " S3_3 ", " T_3 "\n\t"
        /* s[19] */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " T_3 ", " T_0 "\n\t"
        "and    " T_3 ", " T_3 ", " T_1 "\n\t"
#else
        ANDN(TR_3, TR_1, TR_0)
#endif
        "xor    " S3_4 ", " S3_4 ", " T_3 "\n\t"

        "sd     " S3_0 ", 120(%[s])\n\t"
        "sd     " S3_1 ", 128(%[s])\n\t"
        "sd     " S3_2 ", 136(%[s])\n\t"
        "ld     " T_0 ", 160(%[s])\n\t"
        "ld     " T_1 ", 168(%[s])\n\t"
        "ld     " T_3 ", 184(%[s])\n\t"

        /* s[20] */
        "mv     " S3_0 ", " T_0 "\n\t"
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " S3_2 ", " T_1 "\n\t"
        "and    " S3_2 ", " S3_2 ", " T_2 "\n\t"
#else
        ANDN(SR3_2, TR_2, TR_1)
#endif
        "xor    " T_0 ", " T_0 ", " S3_2 "\n\t"
        /* s[21] */
        "mv     " S3_1 ", " T_1 "\n\t"
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " S3_2 ", " T_2 "\n\t"
        "and    " S3_2 ", " S3_2 ", " T_3 "\n\t"
#else
        ANDN(SR3_2, TR_3, TR_2)
#endif
        "xor    " T_1 ", " T_1 ", " S3_2 "\n\t"
        /* s[22] */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " S3_2 ", " T_3 "\n\t"
        "and    " S3_2 ", " S3_2 ", " T_4 "\n\t"
#else
        ANDN(SR3_2, TR_4, TR_3)
#endif
        "xor    " T_2 ", " T_2 ", " S3_2 "\n\t"
        /* s[23] */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " S3_2 ", " T_4 "\n\t"
        "and    " S3_2 ", " S3_2 ", " S3_0 "\n\t"
#else
        ANDN(SR3_2, SR3_0, TR_4)
#endif
        "xor    " T_3 ", " T_3 ", " S3_2 "\n\t"
        /* s[24] */
#ifndef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
        "not    " S3_2 ", " S3_0 "\n\t"
        "and    " S3_2 ", " S3_2 ", " S3_1 "\n\t"
#else
        ANDN(SR3_2, SR3_1, SR3_0)
#endif
        "xor    " T_4 ", " T_4 ", " S3_2 "\n\t"

        "ld     " S3_0 ", 120(%[s])\n\t"
        "ld     " S3_1 ", 128(%[s])\n\t"
        "ld     " S3_2 ", 136(%[s])\n\t"
        "sd     " T_0 ", 160(%[s])\n\t"
        "sd     " T_1 ", 168(%[s])\n\t"
        "sd     " T_2 ", 176(%[s])\n\t"
        "sd     " T_3 ", 184(%[s])\n\t"
        "sd     " T_4 ", 192(%[s])\n\t"

        "ld     " T_4 ", 16(sp)\n\t"
        "ld     " T_3 ", 0(%[r])\n\t"
        "addi   %[r], %[r], 8\n\t"
        "addi   " T_4 ", " T_4 ", -1\n\t"
        "xor    " S0_0 ", " S0_0 ", " T_3 "\n\t"
        "bnez   " T_4 ", L_riscv_64_block_sha3_loop\n\t"

        "sd     " S0_0 ", 0(%[s])\n\t"
        "sd     " S0_1 ", 8(%[s])\n\t"
        "sd     " S0_2 ", 16(%[s])\n\t"
        "sd     " S0_3 ", 24(%[s])\n\t"
        "sd     " S0_4 ", 32(%[s])\n\t"
        "sd     " S1_0 ", 40(%[s])\n\t"
        "sd     " S1_1 ", 48(%[s])\n\t"
        "sd     " S1_2 ", 56(%[s])\n\t"
        "sd     " S1_3 ", 64(%[s])\n\t"
        "sd     " S1_4 ", 72(%[s])\n\t"
        "sd     " S2_0 ", 80(%[s])\n\t"
        "sd     " S2_1 ", 88(%[s])\n\t"
        "sd     " S2_2 ", 96(%[s])\n\t"
        "sd     " S2_3 ", 104(%[s])\n\t"
        "sd     " S2_4 ", 112(%[s])\n\t"
        "sd     " S3_0 ", 120(%[s])\n\t"
        "sd     " S3_1 ", 128(%[s])\n\t"
        "sd     " S3_2 ", 136(%[s])\n\t"
        "sd     " S3_3 ", 144(%[s])\n\t"
        "sd     " S3_4 ", 152(%[s])\n\t"

        "addi   sp, sp, 24\n\t"

        : [r] "+r" (r)
        : [s] "r" (s)
        : "memory", "t0", "t1", "t2", "t3", "t4", "t5", "t6",
           "a1", "a2", "a3", "a4", "a5", "a6", "a7",
           "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11"
    );
}

#else

#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION

#define COL_MIX(r, b1, b4)                      \
        VSLL_VI(REG_V31, b1, 1)                 \
        VSRL_VX(REG_V30, b1, REG_T1)            \
        VXOR_VV(REG_V31, REG_V31, b4)           \
        VXOR_VV(REG_V31, REG_V31, REG_V30)      \
        VXOR_VV((r +  0), (r +  0), REG_V31)    \
        VXOR_VV((r +  5), (r +  5), REG_V31)    \
        VXOR_VV((r + 10), (r + 10), REG_V31)    \
        VXOR_VV((r + 15), (r + 15), REG_V31)    \
        VXOR_VV((r + 20), (r + 20), REG_V31)

#define SWAP_ROTL_LO(vr, vt0, vt1, sl)          \
        VMV_V_V(vt0, vr)                        \
        "li     t1, 64 - " #sl "\n\t"           \
        VSLL_VI(vr, vt1, sl)                    \
        VSRL_VX(vt1, vt1, REG_T1)               \
        VOR_VV(vr, vr, vt1)

#define SWAP_ROTL_HI(vr, vt0, vt1, sl)          \
        VMV_V_V(vt0, vr)                        \
        "li     t1, " #sl "\n\t"                \
        VSRL_VI(vr, vt1, (64 - sl))             \
        VSLL_VX(vt1, vt1, REG_T1)               \
        VOR_VV(vr, vr, vt1)

#define ROW_MIX(r)                              \
        VMV_V_V(REG_V25, (r + 0))               \
        VMV_V_V(REG_V26, (r + 1))               \
        VNOT_V(REG_V30, (r + 1))                \
        VNOT_V(REG_V31, (r + 2))                \
        VAND_VV(REG_V30, REG_V30, (r + 2))      \
        VAND_VV(REG_V31, REG_V31, (r + 3))      \
        VXOR_VV((r + 0), REG_V30, (r + 0))      \
        VXOR_VV((r + 1), REG_V31, (r + 1))      \
        VNOT_V(REG_V30, (r + 3))                \
        VNOT_V(REG_V31, (r + 4))                \
        VAND_VV(REG_V30, REG_V30, (r + 4))      \
        VAND_VV(REG_V31, REG_V31, REG_V25)      \
        VNOT_V(REG_V25, REG_V25)                \
        VXOR_VV((r + 2), REG_V30, (r + 2))      \
        VAND_VV(REG_V25, REG_V25, REG_V26)      \
        VXOR_VV((r + 3), REG_V31, (r + 3))      \
        VXOR_VV((r + 4), REG_V25, (r + 4))

#else

#define COL_MIX(r, t)                           \
        VXOR_VV((r +  0), (r +  0), t)          \
        VXOR_VV((r +  5), (r +  5), t)          \
        VXOR_VV((r + 10), (r + 10), t)          \
        VXOR_VV((r + 15), (r + 15), t)          \
        VXOR_VV((r + 20), (r + 20), t)

#define SWAP_ROTL(vr, vt0, vt1, sl)             \
        VMV_V_V(vt0, vr)                        \
        VROR_VI(vr, (64 - sl), vt1)

#define SWAP_ROTL_LO    SWAP_ROTL
#define SWAP_ROTL_HI    SWAP_ROTL

#define ROW_MIX(r)                              \
        VMV_V_V(REG_V25, (r + 0))               \
        VMV_V_V(REG_V26, (r + 1))               \
        VANDN_VV(REG_V30, (r + 1), (r + 2))     \
        VANDN_VV(REG_V31, (r + 2), (r + 3))     \
        VXOR_VV((r + 0), REG_V30, (r + 0))      \
        VXOR_VV((r + 1), REG_V31, (r + 1))      \
        VANDN_VV(REG_V30, (r + 3), (r + 4))     \
        VANDN_VV(REG_V31, (r + 4), REG_V25)     \
        VANDN_VV(REG_V25, REG_V25, REG_V26)     \
        VXOR_VV((r + 2), REG_V30, (r + 2))      \
        VXOR_VV((r + 3), REG_V31, (r + 3))      \
        VXOR_VV((r + 4), REG_V25, (r + 4))

#endif


void BlockSha3(word64* s)
{
    __asm__ __volatile__ (
        /* 1 x 64-bit */
        VSETIVLI(REG_X0, 1, 0, 1, 0b011, 0b000)

        "li     t2, 24\n\t"
        "mv     t0, %[r]\n\t"
        "mv     t1, %[s]\n\t"
        VLSEG8E64_V(REG_V0, REG_T1)
        "addi   t1, %[s], 64\n\t"
        VLSEG8E64_V(REG_V8, REG_T1)
        "addi   t1, %[s], 128\n\t"
        VLSEG8E64_V(REG_V16, REG_T1)
        "addi   t1, %[s], 192\n\t"
        VLSEG1E64_V(REG_V24, REG_T1)

        "\n"
    "L_riscv_64_block_sha3_loop:\n\t"

        /* COLUMN MIX */
        VXOR_VV(REG_V25, REG_V0, REG_V5)
        VXOR_VV(REG_V26, REG_V1, REG_V6)
        VXOR_VV(REG_V27, REG_V2, REG_V7)
        VXOR_VV(REG_V28, REG_V3, REG_V8)
        VXOR_VV(REG_V29, REG_V4, REG_V9)
        VXOR_VV(REG_V25, REG_V25, REG_V10)
        VXOR_VV(REG_V26, REG_V26, REG_V11)
        VXOR_VV(REG_V27, REG_V27, REG_V12)
        VXOR_VV(REG_V28, REG_V28, REG_V13)
        VXOR_VV(REG_V29, REG_V29, REG_V14)
        VXOR_VV(REG_V25, REG_V25, REG_V15)
        VXOR_VV(REG_V26, REG_V26, REG_V16)
        VXOR_VV(REG_V27, REG_V27, REG_V17)
        VXOR_VV(REG_V28, REG_V28, REG_V18)
        VXOR_VV(REG_V29, REG_V29, REG_V19)
        VXOR_VV(REG_V25, REG_V25, REG_V20)
        VXOR_VV(REG_V26, REG_V26, REG_V21)
        VXOR_VV(REG_V27, REG_V27, REG_V22)
        VXOR_VV(REG_V28, REG_V28, REG_V23)
        VXOR_VV(REG_V29, REG_V29, REG_V24)

#ifndef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
        "li     t1, 63\n\t"
        COL_MIX(REG_V0, REG_V26, REG_V29)
        COL_MIX(REG_V1, REG_V27, REG_V25)
        COL_MIX(REG_V2, REG_V28, REG_V26)
        COL_MIX(REG_V3, REG_V29, REG_V27)
        COL_MIX(REG_V4, REG_V25, REG_V28)
#else
        VROR_VI(REG_V30, 63, REG_V26)
        VROR_VI(REG_V31, 63, REG_V27)
        VXOR_VV(REG_V30, REG_V30, REG_V29)
        VXOR_VV(REG_V31, REG_V31, REG_V25)
        COL_MIX(REG_V0, REG_V30)
        COL_MIX(REG_V1, REG_V31)

        VROR_VI(REG_V30, 63, REG_V28)
        VROR_VI(REG_V31, 63, REG_V29)
        VROR_VI(REG_V25, 63, REG_V25)
        VXOR_VV(REG_V30, REG_V30, REG_V26)
        VXOR_VV(REG_V31, REG_V31, REG_V27)
        VXOR_VV(REG_V25, REG_V25, REG_V28)
        COL_MIX(REG_V2, REG_V30)
        COL_MIX(REG_V3, REG_V31)
        COL_MIX(REG_V4, REG_V25)
#endif
        /* SWAP ROTL */
        /* t1 = s[ 1]                   */
        VMV_V_V(REG_V26, REG_V1)
        /* t0 = s[10], s[10] = t1 <<< 1 */
        SWAP_ROTL_LO(REG_V10, REG_V25, REG_V26, 1)
        /* t1 = s[ 7], s[ 7] = t0 <<< 3 */
        SWAP_ROTL_LO(REG_V7 , REG_V26, REG_V25, 3)
        /* t0 = s[11], s[11] = t1 <<< 6 */
        SWAP_ROTL_LO(REG_V11, REG_V25, REG_V26, 6)
        /* t1 = s[17], s[17] = t0 <<< 10 */
        SWAP_ROTL_LO(REG_V17, REG_V26, REG_V25, 10)
        /* t0 = s[18], s[18] = t1 <<< 15 */
        SWAP_ROTL_LO(REG_V18, REG_V25, REG_V26, 15)
        /* t1 = s[ 3], s[ 3] = t0 <<< 21 */
        SWAP_ROTL_LO(REG_V3 , REG_V26, REG_V25, 21)
        /* t0 = s[ 5], s[ 5] = t1 <<< 28 */
        SWAP_ROTL_LO(REG_V5 , REG_V25, REG_V26, 28)
        /* t1 = s[16], s[16] = t0 <<< 36 */
        SWAP_ROTL_HI(REG_V16, REG_V26, REG_V25, 36)
        /* t0 = s[ 8], s[ 8] = t1 <<< 45 */
        SWAP_ROTL_HI(REG_V8 , REG_V25, REG_V26, 45)
        /* t1 = s[21], s[21] = t0 <<< 55 */
        SWAP_ROTL_HI(REG_V21, REG_V26, REG_V25, 55)
        /* t0 = s[24], s[24] = t1 <<< 2 */
        SWAP_ROTL_LO(REG_V24, REG_V25, REG_V26,  2)
        /* t1 = s[ 4], s[ 4] = t0 <<< 14 */
        SWAP_ROTL_LO(REG_V4 , REG_V26, REG_V25, 14)
        /* t0 = s[15], s[15] = t1 <<< 27 */
        SWAP_ROTL_LO(REG_V15, REG_V25, REG_V26, 27)
        /* t1 = s[23], s[23] = t0 <<< 41 */
        SWAP_ROTL_HI(REG_V23, REG_V26, REG_V25, 41)
        /* t0 = s[19], s[19] = t1 <<< 56 */
        SWAP_ROTL_HI(REG_V19, REG_V25, REG_V26, 56)
        /* t1 = s[13], s[13] = t0 <<< 8 */
        SWAP_ROTL_LO(REG_V13, REG_V26, REG_V25,  8)
        /* t0 = s[12], s[12] = t1 <<< 25 */
        SWAP_ROTL_LO(REG_V12, REG_V25, REG_V26, 25)
        /* t1 = s[ 2], s[ 2] = t0 <<< 43 */
        SWAP_ROTL_HI(REG_V2 , REG_V26, REG_V25, 43)
        /* t0 = s[20], s[20] = t1 <<< 62 */
        SWAP_ROTL_HI(REG_V20, REG_V25, REG_V26, 62)
        /* t1 = s[14], s[14] = t0 <<< 18 */
        SWAP_ROTL_LO(REG_V14, REG_V26, REG_V25, 18)
        /* t0 = s[22], s[22] = t1 <<< 39 */
        SWAP_ROTL_HI(REG_V22, REG_V25, REG_V26, 39)
        /* t1 = s[ 9], s[ 9] = t0 <<< 61 */
        SWAP_ROTL_HI(REG_V9 , REG_V26, REG_V25, 61)
        /* t0 = s[ 6], s[ 6] = t1 <<< 20 */
        SWAP_ROTL_LO(REG_V6 , REG_V25, REG_V26, 20)
        /*             s[ 1] = t0 <<< 44 */
        "li     t1, 44\n\t"
        VSRL_VI(REG_V1, REG_V25, (64 - 44))
        VSLL_VX(REG_V25, REG_V25, REG_T1)
        VOR_VV(REG_V1, REG_V1, REG_V25)

        /* ROW MIX */
        ROW_MIX(REG_V0)
        ROW_MIX(REG_V5)
        ROW_MIX(REG_V10)
        ROW_MIX(REG_V15)
        ROW_MIX(REG_V20)

        VL1RE64_V(REG_V25, REG_T0)
        "addi   t0, t0, 8\n\t"
        "addi   t2, t2, -1\n\t"
        VXOR_VV(REG_V0, REG_V0, REG_V25)
        "bnez   t2, L_riscv_64_block_sha3_loop\n\t"

        "mv     t1, %[s]\n\t"
        VSSEG8E64_V(REG_V0, REG_T1)
        "addi   t1, %[s], 64\n\t"
        VSSEG8E64_V(REG_V8, REG_T1)
        "addi   t1, %[s], 128\n\t"
        VSSEG8E64_V(REG_V16, REG_T1)
        "addi   t1, %[s], 192\n\t"
        VSSEG1E64_V(REG_V24, REG_T1)

        :
        : [s] "r" (s), [r] "r" (hash_keccak_r)
        : "memory", "t0", "t1", "t2"
    );
}

#endif /* WOLFSSL_RISCV_VECTOR */
#endif /* WOLFSSL_SHA3 && !XILINX */
#endif /* WOLFSSL_RISCV_ASM */
