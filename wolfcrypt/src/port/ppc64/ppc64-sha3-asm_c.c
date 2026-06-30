/* ppc64-sha3-asm
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

/* Generated using (from wolfssl):
 *   cd ../scripts
 *   ruby ./sha3/sha3.rb ppc64 \
 *       ../wolfssl/wolfcrypt/src/port/ppc64/ppc64-sha3-asm.c
 */
#ifdef WOLFSSL_PPC64_ASM
#include <stdint.h>
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
#ifdef WOLFSSL_PPC64_ASM_INLINE

#ifdef __IAR_SYSTEMS_ICC__
#define __asm__        asm
#define __volatile__   volatile
#define WOLFSSL_NO_VAR_ASSIGN_REG
#endif /* __IAR_SYSTEMS_ICC__ */
#ifdef __KEIL__
#define __asm__        __asm
#define __volatile__   volatile
#endif /* __KEIL__ */
#ifdef __ghs__
#define __asm__        __asm
#define __volatile__
#define WOLFSSL_NO_VAR_ASSIGN_REG
#endif /* __ghs__ */
#include <wolfssl/wolfcrypt/sha3.h>

#ifdef WOLFSSL_SHA3
static const word64 L_SHA3_transform_base_r[] = {
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
    0x0000000080000001UL, 0x8000000080008008UL,
};

void BlockSha3_base(word64* state);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void BlockSha3_base(word64* state_p)
#else
void BlockSha3_base(word64* state)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* state asm ("3") = (word64*)state_p;
    register word64* L_SHA3_transform_base_r_c asm ("4") =
        (word64*)&L_SHA3_transform_base_r;
#else
    register word64* L_SHA3_transform_base_r_c =
        (word64*)&L_SHA3_transform_base_r;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "subi    1, 1, 0xc8\n\t"
        "mr      29, %[L_SHA3_transform_base_r]\n\t"
        "std     %[state], 40(1)\n\t"
        "ld      0, 0(%[state])\n\t"
        "ld      4, 8(%[state])\n\t"
        "ld      5, 16(%[state])\n\t"
        "ld      6, 24(%[state])\n\t"
        "ld      7, 32(%[state])\n\t"
        "ld      8, 40(%[state])\n\t"
        "ld      9, 48(%[state])\n\t"
        "ld      10, 56(%[state])\n\t"
        "ld      11, 64(%[state])\n\t"
        "ld      12, 72(%[state])\n\t"
        "ld      14, 80(%[state])\n\t"
        "ld      15, 88(%[state])\n\t"
        "ld      16, 96(%[state])\n\t"
        "ld      17, 104(%[state])\n\t"
        "ld      18, 112(%[state])\n\t"
        "ld      19, 120(%[state])\n\t"
        "ld      20, 128(%[state])\n\t"
        "ld      21, 136(%[state])\n\t"
        "ld      22, 144(%[state])\n\t"
        "ld      23, 152(%[state])\n\t"
        "ld      24, 160(%[state])\n\t"
        "ld      25, 168(%[state])\n\t"
        "ld      26, 176(%[state])\n\t"
        "ld      27, 184(%[state])\n\t"
        "ld      28, 192(%[state])\n\t"
        "li      30, 24\n\t"
        "mtctr   30\n\t"
        /* Start of 24 rounds */
        "\n"
    "L_SHA3_transform_base_begin_%=: \n\t"
        /* Column Mix */
        "xor     30, 0, 8\n\t"
        "xor     30, 30, 14\n\t"
        "xor     30, 30, 19\n\t"
        "xor     30, 30, 24\n\t"
        "std     30, 0(1)\n\t"
        "xor     30, 4, 9\n\t"
        "xor     30, 30, 15\n\t"
        "xor     30, 30, 20\n\t"
        "xor     30, 30, 25\n\t"
        "std     30, 8(1)\n\t"
        "xor     30, 5, 10\n\t"
        "xor     30, 30, 16\n\t"
        "xor     30, 30, 21\n\t"
        "xor     30, 30, 26\n\t"
        "std     30, 16(1)\n\t"
        "xor     30, 6, 11\n\t"
        "xor     30, 30, 17\n\t"
        "xor     30, 30, 22\n\t"
        "xor     30, 30, 27\n\t"
        "std     30, 24(1)\n\t"
        "xor     30, 7, 12\n\t"
        "xor     30, 30, 18\n\t"
        "xor     30, 30, 23\n\t"
        "xor     30, 30, 28\n\t"
        "std     30, 32(1)\n\t"
        "ld      30, 8(1)\n\t"
        "rotldi  30, 30, 1\n\t"
        "ld      31, 32(1)\n\t"
        "xor     31, 31, 30\n\t"
        "xor     0, 0, 31\n\t"
        "xor     8, 8, 31\n\t"
        "xor     14, 14, 31\n\t"
        "xor     19, 19, 31\n\t"
        "xor     24, 24, 31\n\t"
        "ld      30, 16(1)\n\t"
        "rotldi  30, 30, 1\n\t"
        "ld      31, 0(1)\n\t"
        "xor     31, 31, 30\n\t"
        "xor     4, 4, 31\n\t"
        "xor     9, 9, 31\n\t"
        "xor     15, 15, 31\n\t"
        "xor     20, 20, 31\n\t"
        "xor     25, 25, 31\n\t"
        "ld      30, 24(1)\n\t"
        "rotldi  30, 30, 1\n\t"
        "ld      31, 8(1)\n\t"
        "xor     31, 31, 30\n\t"
        "xor     5, 5, 31\n\t"
        "xor     10, 10, 31\n\t"
        "xor     16, 16, 31\n\t"
        "xor     21, 21, 31\n\t"
        "xor     26, 26, 31\n\t"
        "ld      30, 32(1)\n\t"
        "rotldi  30, 30, 1\n\t"
        "ld      31, 16(1)\n\t"
        "xor     31, 31, 30\n\t"
        "xor     6, 6, 31\n\t"
        "xor     11, 11, 31\n\t"
        "xor     17, 17, 31\n\t"
        "xor     22, 22, 31\n\t"
        "xor     27, 27, 31\n\t"
        "ld      30, 0(1)\n\t"
        "rotldi  30, 30, 1\n\t"
        "ld      31, 24(1)\n\t"
        "xor     31, 31, 30\n\t"
        "xor     7, 7, 31\n\t"
        "xor     12, 12, 31\n\t"
        "xor     18, 18, 31\n\t"
        "xor     23, 23, 31\n\t"
        "xor     28, 28, 31\n\t"
        "std     29, 48(1)\n\t"
        /* Swap Rotate */
        "rotldi  %[state], 4, 1\n\t"
        "rotldi  4, 9, 44\n\t"
        "rotldi  9, 12, 20\n\t"
        "rotldi  12, 26, 61\n\t"
        "rotldi  26, 18, 39\n\t"
        "rotldi  18, 24, 18\n\t"
        "rotldi  24, 5, 62\n\t"
        "rotldi  5, 16, 43\n\t"
        "rotldi  16, 17, 25\n\t"
        "rotldi  17, 23, 8\n\t"
        "rotldi  23, 27, 56\n\t"
        "rotldi  27, 19, 41\n\t"
        "rotldi  19, 7, 27\n\t"
        "rotldi  7, 28, 14\n\t"
        "rotldi  28, 25, 2\n\t"
        "rotldi  25, 11, 55\n\t"
        "rotldi  11, 20, 45\n\t"
        "rotldi  20, 8, 36\n\t"
        "rotldi  8, 6, 28\n\t"
        "rotldi  6, 22, 21\n\t"
        "rotldi  22, 21, 15\n\t"
        "rotldi  21, 15, 10\n\t"
        "rotldi  15, 10, 6\n\t"
        "rotldi  10, 14, 3\n\t"
        /* Row Mix */
        "andc    14, 5, 4\n\t"
        "andc    29, 6, 5\n\t"
        "andc    30, 0, 7\n\t"
        "andc    31, 4, 0\n\t"
        "xor     0, 0, 14\n\t"
        "xor     4, 4, 29\n\t"
        "andc    14, 7, 6\n\t"
        "xor     6, 6, 30\n\t"
        "xor     5, 5, 14\n\t"
        "xor     7, 7, 31\n\t"
        "andc    14, 10, 9\n\t"
        "andc    29, 11, 10\n\t"
        "andc    30, 8, 12\n\t"
        "andc    31, 9, 8\n\t"
        "xor     8, 8, 14\n\t"
        "xor     9, 9, 29\n\t"
        "andc    14, 12, 11\n\t"
        "xor     11, 11, 30\n\t"
        "xor     10, 10, 14\n\t"
        "xor     12, 12, 31\n\t"
        "andc    14, 16, 15\n\t"
        "andc    29, 17, 16\n\t"
        "andc    30, %[state], 18\n\t"
        "andc    31, 15, %[state]\n\t"
        "xor     14, %[state], 14\n\t"
        "xor     15, 15, 29\n\t"
        "andc    %[state], 18, 17\n\t"
        "xor     17, 17, 30\n\t"
        "xor     16, 16, %[state]\n\t"
        "xor     18, 18, 31\n\t"
        "andc    %[state], 21, 20\n\t"
        "andc    29, 22, 21\n\t"
        "andc    30, 19, 23\n\t"
        "andc    31, 20, 19\n\t"
        "xor     19, 19, %[state]\n\t"
        "xor     20, 20, 29\n\t"
        "andc    %[state], 23, 22\n\t"
        "xor     22, 22, 30\n\t"
        "xor     21, 21, %[state]\n\t"
        "xor     23, 23, 31\n\t"
        "andc    %[state], 26, 25\n\t"
        "andc    29, 27, 26\n\t"
        "andc    30, 24, 28\n\t"
        "andc    31, 25, 24\n\t"
        "xor     24, 24, %[state]\n\t"
        "xor     25, 25, 29\n\t"
        "andc    %[state], 28, 27\n\t"
        "xor     27, 27, 30\n\t"
        "xor     26, 26, %[state]\n\t"
        "xor     28, 28, 31\n\t"
        "ld      29, 48(1)\n\t"
        /* Done transforming */
        "ld      30, 0(29)\n\t"
        "addi    29, 29, 8\n\t"
        "xor     0, 0, 30\n\t"
        "bdnz    L_SHA3_transform_base_begin_%=\n\t"
        "ld      %[state], 40(1)\n\t"
        "std     0, 0(%[state])\n\t"
        "std     4, 8(%[state])\n\t"
        "std     5, 16(%[state])\n\t"
        "std     6, 24(%[state])\n\t"
        "std     7, 32(%[state])\n\t"
        "std     8, 40(%[state])\n\t"
        "std     9, 48(%[state])\n\t"
        "std     10, 56(%[state])\n\t"
        "std     11, 64(%[state])\n\t"
        "std     12, 72(%[state])\n\t"
        "std     14, 80(%[state])\n\t"
        "std     15, 88(%[state])\n\t"
        "std     16, 96(%[state])\n\t"
        "std     17, 104(%[state])\n\t"
        "std     18, 112(%[state])\n\t"
        "std     19, 120(%[state])\n\t"
        "std     20, 128(%[state])\n\t"
        "std     21, 136(%[state])\n\t"
        "std     22, 144(%[state])\n\t"
        "std     23, 152(%[state])\n\t"
        "std     24, 160(%[state])\n\t"
        "std     25, 168(%[state])\n\t"
        "std     26, 176(%[state])\n\t"
        "std     27, 184(%[state])\n\t"
        "std     28, 192(%[state])\n\t"
        "addi    1, 1, 0xc8\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [state] "+r" (state),
          [L_SHA3_transform_base_r] "+r" (L_SHA3_transform_base_r_c)
        :
        : "memory", "cc", "0", "5", "6", "7", "8", "9", "10", "11", "12", "14",
            "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25",
            "26", "27", "28", "29", "30", "31"
#else
        :
        : [state] "r" (state),
          [L_SHA3_transform_base_r] "r" (L_SHA3_transform_base_r_c)
        : "memory", "cc", "0", "4", "5", "6", "7", "8", "9", "10", "11", "12",
            "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24",
            "25", "26", "27", "28", "29", "30", "31"
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
    );
}

#ifdef WOLFSSL_PPC64_ASM_POWER8
static const word64 L_SHA3_transform_power8_r[] = {
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
    0x0000000080000001UL, 0x8000000080008008UL,
};

__attribute__((target("cpu=power8")))
void BlockSha3_power8(word64* state);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void BlockSha3_power8(word64* state_p)
#else
void BlockSha3_power8(word64* state)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* state asm ("3") = (word64*)state_p;
    register word64* L_SHA3_transform_power8_r_c asm ("4") =
        (word64*)&L_SHA3_transform_power8_r;
#else
    register word64* L_SHA3_transform_power8_r_c =
        (word64*)&L_SHA3_transform_power8_r;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mr      4, %[L_SHA3_transform_power8_r]\n\t"
        /* Load state */
        "li      5, 0\n\t"
        "lxsdx   32, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   33, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   34, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   35, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   36, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   37, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   38, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   39, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   40, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   41, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   42, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   43, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   44, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   45, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   46, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   47, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   48, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   49, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   50, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   51, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   52, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   53, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   54, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   55, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "lxsdx   56, %[state], 5\n\t"
        "li      5, 24\n\t"
        "mtctr   5\n\t"
        /* Start of 24 rounds */
        "\n"
    "L_SHA3_transform_power8_begin_%=: \n\t"
        /* Column Mix */
        "vxor    25, 0, 5\n\t"
        "vxor    25, 25, 10\n\t"
        "vxor    25, 25, 15\n\t"
        "vxor    25, 25, 20\n\t"
        "vxor    26, 1, 6\n\t"
        "vxor    26, 26, 11\n\t"
        "vxor    26, 26, 16\n\t"
        "vxor    26, 26, 21\n\t"
        "vxor    27, 2, 7\n\t"
        "vxor    27, 27, 12\n\t"
        "vxor    27, 27, 17\n\t"
        "vxor    27, 27, 22\n\t"
        "vxor    28, 3, 8\n\t"
        "vxor    28, 28, 13\n\t"
        "vxor    28, 28, 18\n\t"
        "vxor    28, 28, 23\n\t"
        "vxor    29, 4, 9\n\t"
        "vxor    29, 29, 14\n\t"
        "vxor    29, 29, 19\n\t"
        "vxor    29, 29, 24\n\t"
        "li      6, 1\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    30, 26, 31\n\t"
        "vxor    30, 29, 30\n\t"
        "vxor    0, 0, 30\n\t"
        "vxor    5, 5, 30\n\t"
        "vxor    10, 10, 30\n\t"
        "vxor    15, 15, 30\n\t"
        "vxor    20, 20, 30\n\t"
        "vrld    30, 27, 31\n\t"
        "vxor    30, 25, 30\n\t"
        "vxor    1, 1, 30\n\t"
        "vxor    6, 6, 30\n\t"
        "vxor    11, 11, 30\n\t"
        "vxor    16, 16, 30\n\t"
        "vxor    21, 21, 30\n\t"
        "vrld    30, 28, 31\n\t"
        "vxor    30, 26, 30\n\t"
        "vxor    2, 2, 30\n\t"
        "vxor    7, 7, 30\n\t"
        "vxor    12, 12, 30\n\t"
        "vxor    17, 17, 30\n\t"
        "vxor    22, 22, 30\n\t"
        "vrld    30, 29, 31\n\t"
        "vxor    30, 27, 30\n\t"
        "vxor    3, 3, 30\n\t"
        "vxor    8, 8, 30\n\t"
        "vxor    13, 13, 30\n\t"
        "vxor    18, 18, 30\n\t"
        "vxor    23, 23, 30\n\t"
        "vrld    30, 25, 31\n\t"
        "vxor    30, 28, 30\n\t"
        "vxor    4, 4, 30\n\t"
        "vxor    9, 9, 30\n\t"
        "vxor    14, 14, 30\n\t"
        "vxor    19, 19, 30\n\t"
        "vxor    24, 24, 30\n\t"
        /* Swap Rotate */
        "li      6, 1\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    25, 1, 31\n\t"
        "li      6, 44\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    1, 6, 31\n\t"
        "li      6, 20\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    6, 9, 31\n\t"
        "li      6, 61\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    9, 22, 31\n\t"
        "li      6, 39\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    22, 14, 31\n\t"
        "li      6, 18\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    14, 20, 31\n\t"
        "li      6, 62\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    20, 2, 31\n\t"
        "li      6, 43\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    2, 12, 31\n\t"
        "li      6, 25\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    12, 13, 31\n\t"
        "li      6, 8\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    13, 19, 31\n\t"
        "li      6, 56\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    19, 23, 31\n\t"
        "li      6, 41\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    23, 15, 31\n\t"
        "li      6, 27\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    15, 4, 31\n\t"
        "li      6, 14\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    4, 24, 31\n\t"
        "li      6, 2\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    24, 21, 31\n\t"
        "li      6, 55\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    21, 8, 31\n\t"
        "li      6, 45\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    8, 16, 31\n\t"
        "li      6, 36\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    16, 5, 31\n\t"
        "li      6, 28\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    5, 3, 31\n\t"
        "li      6, 21\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    3, 18, 31\n\t"
        "li      6, 15\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    18, 17, 31\n\t"
        "li      6, 10\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    17, 11, 31\n\t"
        "li      6, 6\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    11, 7, 31\n\t"
        "li      6, 3\n\t"
        "mtvsrd  63, 6\n\t"
        "vrld    7, 10, 31\n\t"
        /* Row Mix */
        "vandc   10, 2, 1\n\t"
        "vandc   26, 3, 2\n\t"
        "vandc   27, 0, 4\n\t"
        "vandc   28, 1, 0\n\t"
        "vxor    0, 0, 10\n\t"
        "vxor    1, 1, 26\n\t"
        "vandc   10, 4, 3\n\t"
        "vxor    3, 3, 27\n\t"
        "vxor    2, 2, 10\n\t"
        "vxor    4, 4, 28\n\t"
        "vandc   10, 7, 6\n\t"
        "vandc   26, 8, 7\n\t"
        "vandc   27, 5, 9\n\t"
        "vandc   28, 6, 5\n\t"
        "vxor    5, 5, 10\n\t"
        "vxor    6, 6, 26\n\t"
        "vandc   10, 9, 8\n\t"
        "vxor    8, 8, 27\n\t"
        "vxor    7, 7, 10\n\t"
        "vxor    9, 9, 28\n\t"
        "vandc   10, 12, 11\n\t"
        "vandc   26, 13, 12\n\t"
        "vandc   27, 25, 14\n\t"
        "vandc   28, 11, 25\n\t"
        "vxor    10, 25, 10\n\t"
        "vxor    11, 11, 26\n\t"
        "vandc   25, 14, 13\n\t"
        "vxor    13, 13, 27\n\t"
        "vxor    12, 12, 25\n\t"
        "vxor    14, 14, 28\n\t"
        "vandc   25, 17, 16\n\t"
        "vandc   26, 18, 17\n\t"
        "vandc   27, 15, 19\n\t"
        "vandc   28, 16, 15\n\t"
        "vxor    15, 15, 25\n\t"
        "vxor    16, 16, 26\n\t"
        "vandc   25, 19, 18\n\t"
        "vxor    18, 18, 27\n\t"
        "vxor    17, 17, 25\n\t"
        "vxor    19, 19, 28\n\t"
        "vandc   25, 22, 21\n\t"
        "vandc   26, 23, 22\n\t"
        "vandc   27, 20, 24\n\t"
        "vandc   28, 21, 20\n\t"
        "vxor    20, 20, 25\n\t"
        "vxor    21, 21, 26\n\t"
        "vandc   25, 24, 23\n\t"
        "vxor    23, 23, 27\n\t"
        "vxor    22, 22, 25\n\t"
        "vxor    24, 24, 28\n\t"
        /* Iota - XOR round constant into lane 0 */
        "lxsdx   58, 0, 4\n\t"
        "addi    4, 4, 8\n\t"
        "vxor    0, 0, 26\n\t"
        "bdnz    L_SHA3_transform_power8_begin_%=\n\t"
        /* Store state */
        "li      5, 0\n\t"
        "stxsdx  32, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  33, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  34, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  35, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  36, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  37, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  38, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  39, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  40, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  41, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  42, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  43, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  44, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  45, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  46, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  47, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  48, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  49, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  50, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  51, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  52, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  53, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  54, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  55, %[state], 5\n\t"
        "addi    5, 5, 8\n\t"
        "stxsdx  56, %[state], 5\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [state] "+r" (state),
          [L_SHA3_transform_power8_r] "+r" (L_SHA3_transform_power8_r_c)
        :
        : "memory", "cc", "0", "5", "6", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
            "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24",
            "v25", "v26", "v27", "v28", "v29", "v30", "v31"
#else
        :
        : [state] "r" (state),
          [L_SHA3_transform_power8_r] "r" (L_SHA3_transform_power8_r_c)
        : "memory", "cc", "0", "4", "5", "6", "v0", "v1", "v2", "v3", "v4",
            "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14",
            "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
            "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
    );
}

#if (defined(WOLFSSL_HAVE_MLKEM) || \
        defined(HAVE_DILITHIUM)) && defined(WOLFSSL_SHA3_PPC64_BLOCKS_N)
static const word64 L_SHA3_blocksx2_power8_rot[] = {
    0x0000000000000001UL, 0x0000000000000001UL,
    0x000000000000002cUL, 0x0000000000000014UL,
    0x000000000000003dUL, 0x0000000000000027UL,
    0x0000000000000012UL, 0x000000000000003eUL,
    0x000000000000002bUL, 0x0000000000000019UL,
    0x0000000000000008UL, 0x0000000000000038UL,
    0x0000000000000029UL, 0x000000000000001bUL,
    0x000000000000000eUL, 0x0000000000000002UL,
    0x0000000000000037UL, 0x000000000000002dUL,
    0x0000000000000024UL, 0x000000000000001cUL,
    0x0000000000000015UL, 0x000000000000000fUL,
    0x000000000000000aUL, 0x0000000000000006UL,
    0x0000000000000003UL
};

static const word64 L_SHA3_blocksx2_power8_r[] = {
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
    0x0000000080000001UL, 0x8000000080008008UL,
};

__attribute__((target("cpu=power8")))
void sha3_blocksx2_power8(word64* s01);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void sha3_blocksx2_power8(word64* s01_p)
#else
void sha3_blocksx2_power8(word64* s01)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* s01 asm ("3") = (word64*)s01_p;
    register word64* L_SHA3_blocksx2_power8_rot_c asm ("4") =
        (word64*)&L_SHA3_blocksx2_power8_rot;
    register word64* L_SHA3_blocksx2_power8_r_c asm ("5") =
        (word64*)&L_SHA3_blocksx2_power8_r;
#else
    register word64* L_SHA3_blocksx2_power8_rot_c =
        (word64*)&L_SHA3_blocksx2_power8_rot;
    register word64* L_SHA3_blocksx2_power8_r_c =
        (word64*)&L_SHA3_blocksx2_power8_r;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "mr      4, %[L_SHA3_blocksx2_power8_r]\n\t"
        "mr      5, %[L_SHA3_blocksx2_power8_rot]\n\t"
        /* Load states 0,1 (interleaved) */
        "li      6, 0\n\t"
        "lxvd2x  32, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  33, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  34, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  35, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  36, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  37, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  38, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  39, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  40, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  41, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  42, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  43, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  44, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  45, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  46, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  47, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  48, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  49, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  50, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  51, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  52, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  53, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  54, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  55, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "lxvd2x  56, %[s01], 6\n\t"
        "li      6, 24\n\t"
        "mtctr   6\n\t"
        /* Start of 24 rounds */
        "\n"
    "L_SHA3_blocksx2_power8_begin_%=: \n\t"
        /* Column Mix */
        "vxor    25, 0, 5\n\t"
        "vxor    25, 25, 10\n\t"
        "vxor    25, 25, 15\n\t"
        "vxor    25, 25, 20\n\t"
        "vxor    26, 1, 6\n\t"
        "vxor    26, 26, 11\n\t"
        "vxor    26, 26, 16\n\t"
        "vxor    26, 26, 21\n\t"
        "vxor    27, 2, 7\n\t"
        "vxor    27, 27, 12\n\t"
        "vxor    27, 27, 17\n\t"
        "vxor    27, 27, 22\n\t"
        "vxor    28, 3, 8\n\t"
        "vxor    28, 28, 13\n\t"
        "vxor    28, 28, 18\n\t"
        "vxor    28, 28, 23\n\t"
        "vxor    29, 4, 9\n\t"
        "vxor    29, 29, 14\n\t"
        "vxor    29, 29, 19\n\t"
        "vxor    29, 29, 24\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    30, 26, 31\n\t"
        "vxor    30, 29, 30\n\t"
        "vxor    0, 0, 30\n\t"
        "vxor    5, 5, 30\n\t"
        "vxor    10, 10, 30\n\t"
        "vxor    15, 15, 30\n\t"
        "vxor    20, 20, 30\n\t"
        "vrld    30, 27, 31\n\t"
        "vxor    30, 25, 30\n\t"
        "vxor    1, 1, 30\n\t"
        "vxor    6, 6, 30\n\t"
        "vxor    11, 11, 30\n\t"
        "vxor    16, 16, 30\n\t"
        "vxor    21, 21, 30\n\t"
        "vrld    30, 28, 31\n\t"
        "vxor    30, 26, 30\n\t"
        "vxor    2, 2, 30\n\t"
        "vxor    7, 7, 30\n\t"
        "vxor    12, 12, 30\n\t"
        "vxor    17, 17, 30\n\t"
        "vxor    22, 22, 30\n\t"
        "vrld    30, 29, 31\n\t"
        "vxor    30, 27, 30\n\t"
        "vxor    3, 3, 30\n\t"
        "vxor    8, 8, 30\n\t"
        "vxor    13, 13, 30\n\t"
        "vxor    18, 18, 30\n\t"
        "vxor    23, 23, 30\n\t"
        "vrld    30, 25, 31\n\t"
        "vxor    30, 28, 30\n\t"
        "vxor    4, 4, 30\n\t"
        "vxor    9, 9, 30\n\t"
        "vxor    14, 14, 30\n\t"
        "vxor    19, 19, 30\n\t"
        "vxor    24, 24, 30\n\t"
        /* Swap Rotate */
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    25, 1, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    1, 6, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    6, 9, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    9, 22, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    22, 14, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    14, 20, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    20, 2, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    2, 12, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    12, 13, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    13, 19, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    19, 23, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    23, 15, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    15, 4, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    4, 24, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    24, 21, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    21, 8, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    8, 16, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    16, 5, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    5, 3, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    3, 18, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    18, 17, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    17, 11, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    11, 7, 31\n\t"
        "lxvdsx  63, 0, 5\n\t"
        "addi    5, 5, 8\n\t"
        "vrld    7, 10, 31\n\t"
        /* Row Mix */
        "vandc   10, 2, 1\n\t"
        "vandc   26, 3, 2\n\t"
        "vandc   27, 0, 4\n\t"
        "vandc   28, 1, 0\n\t"
        "vxor    0, 0, 10\n\t"
        "vxor    1, 1, 26\n\t"
        "vandc   10, 4, 3\n\t"
        "vxor    3, 3, 27\n\t"
        "vxor    2, 2, 10\n\t"
        "vxor    4, 4, 28\n\t"
        "vandc   10, 7, 6\n\t"
        "vandc   26, 8, 7\n\t"
        "vandc   27, 5, 9\n\t"
        "vandc   28, 6, 5\n\t"
        "vxor    5, 5, 10\n\t"
        "vxor    6, 6, 26\n\t"
        "vandc   10, 9, 8\n\t"
        "vxor    8, 8, 27\n\t"
        "vxor    7, 7, 10\n\t"
        "vxor    9, 9, 28\n\t"
        "vandc   10, 12, 11\n\t"
        "vandc   26, 13, 12\n\t"
        "vandc   27, 25, 14\n\t"
        "vandc   28, 11, 25\n\t"
        "vxor    10, 25, 10\n\t"
        "vxor    11, 11, 26\n\t"
        "vandc   25, 14, 13\n\t"
        "vxor    13, 13, 27\n\t"
        "vxor    12, 12, 25\n\t"
        "vxor    14, 14, 28\n\t"
        "vandc   25, 17, 16\n\t"
        "vandc   26, 18, 17\n\t"
        "vandc   27, 15, 19\n\t"
        "vandc   28, 16, 15\n\t"
        "vxor    15, 15, 25\n\t"
        "vxor    16, 16, 26\n\t"
        "vandc   25, 19, 18\n\t"
        "vxor    18, 18, 27\n\t"
        "vxor    17, 17, 25\n\t"
        "vxor    19, 19, 28\n\t"
        "vandc   25, 22, 21\n\t"
        "vandc   26, 23, 22\n\t"
        "vandc   27, 20, 24\n\t"
        "vandc   28, 21, 20\n\t"
        "vxor    20, 20, 25\n\t"
        "vxor    21, 21, 26\n\t"
        "vandc   25, 24, 23\n\t"
        "vxor    23, 23, 27\n\t"
        "vxor    22, 22, 25\n\t"
        "vxor    24, 24, 28\n\t"
        "subi    5, 5, 0xc8\n\t"
        /* Iota - XOR round constant into lane 0 of both states */
        "lxvdsx  58, 0, 4\n\t"
        "addi    4, 4, 8\n\t"
        "vxor    0, 0, 26\n\t"
        "bdnz    L_SHA3_blocksx2_power8_begin_%=\n\t"
        /* Store states 0,1 */
        "li      6, 0\n\t"
        "stxvd2x 32, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 33, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 34, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 35, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 36, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 37, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 38, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 39, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 40, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 41, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 42, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 43, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 44, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 45, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 46, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 47, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 48, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 49, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 50, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 51, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 52, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 53, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 54, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 55, %[s01], 6\n\t"
        "addi    6, 6, 16\n\t"
        "stxvd2x 56, %[s01], 6\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [s01] "+r" (s01),
          [L_SHA3_blocksx2_power8_rot] "+r" (L_SHA3_blocksx2_power8_rot_c),
          [L_SHA3_blocksx2_power8_r] "+r" (L_SHA3_blocksx2_power8_r_c)
        :
        : "memory", "cc", "0", "6", "v0", "v1", "v2", "v3", "v4", "v5", "v6",
            "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15", "v16",
            "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25",
            "v26", "v27", "v28", "v29", "v30", "v31"
#else
        :
        : [s01] "r" (s01),
          [L_SHA3_blocksx2_power8_rot] "r" (L_SHA3_blocksx2_power8_rot_c),
          [L_SHA3_blocksx2_power8_r] "r" (L_SHA3_blocksx2_power8_r_c)
        : "memory", "cc", "0", "4", "5", "6", "v0", "v1", "v2", "v3", "v4",
            "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14",
            "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
            "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
    );
}

static const word64 L_SHA3_blocksx3_power8_rot[] = {
    0x0000000000000001UL, 0x0000000000000001UL,
    0x000000000000002cUL, 0x0000000000000014UL,
    0x000000000000003dUL, 0x0000000000000027UL,
    0x0000000000000012UL, 0x000000000000003eUL,
    0x000000000000002bUL, 0x0000000000000019UL,
    0x0000000000000008UL, 0x0000000000000038UL,
    0x0000000000000029UL, 0x000000000000001bUL,
    0x000000000000000eUL, 0x0000000000000002UL,
    0x0000000000000037UL, 0x000000000000002dUL,
    0x0000000000000024UL, 0x000000000000001cUL,
    0x0000000000000015UL, 0x000000000000000fUL,
    0x000000000000000aUL, 0x0000000000000006UL,
    0x0000000000000003UL
};

static const word64 L_SHA3_blocksx3_power8_r[] = {
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
    0x0000000080000001UL, 0x8000000080008008UL,
};

__attribute__((target("cpu=power8")))
void sha3_blocksx3_power8(word64* s01, word64* s2);
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void sha3_blocksx3_power8(word64* s01_p, word64* s2_p)
#else
void sha3_blocksx3_power8(word64* s01, word64* s2)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word64* s01 asm ("3") = (word64*)s01_p;
    register word64* s2 asm ("4") = (word64*)s2_p;
    register word64* L_SHA3_blocksx3_power8_rot_c asm ("5") =
        (word64*)&L_SHA3_blocksx3_power8_rot;
    register word64* L_SHA3_blocksx3_power8_r_c asm ("6") =
        (word64*)&L_SHA3_blocksx3_power8_r;
#else
    register word64* L_SHA3_blocksx3_power8_rot_c =
        (word64*)&L_SHA3_blocksx3_power8_rot;
    register word64* L_SHA3_blocksx3_power8_r_c =
        (word64*)&L_SHA3_blocksx3_power8_r;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "subi    1, 1, 0xd0\n\t"
        /* Load states (0,1 interleaved into vectors; 2 into GPRs) */
        "li      30, 0\n\t"
        "lxvd2x  32, %[s01], 30\n\t"
        "ld      0, 0(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  33, %[s01], 30\n\t"
        "ld      5, 8(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  34, %[s01], 30\n\t"
        "ld      6, 16(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  35, %[s01], 30\n\t"
        "ld      7, 24(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  36, %[s01], 30\n\t"
        "ld      8, 32(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  37, %[s01], 30\n\t"
        "ld      9, 40(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  38, %[s01], 30\n\t"
        "ld      10, 48(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  39, %[s01], 30\n\t"
        "ld      11, 56(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  40, %[s01], 30\n\t"
        "ld      12, 64(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  41, %[s01], 30\n\t"
        "ld      14, 72(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  42, %[s01], 30\n\t"
        "ld      15, 80(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  43, %[s01], 30\n\t"
        "ld      16, 88(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  44, %[s01], 30\n\t"
        "ld      17, 96(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  45, %[s01], 30\n\t"
        "ld      18, 104(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  46, %[s01], 30\n\t"
        "ld      19, 112(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  47, %[s01], 30\n\t"
        "ld      20, 120(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  48, %[s01], 30\n\t"
        "ld      21, 128(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  49, %[s01], 30\n\t"
        "ld      22, 136(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  50, %[s01], 30\n\t"
        "ld      23, 144(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  51, %[s01], 30\n\t"
        "ld      24, 152(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  52, %[s01], 30\n\t"
        "ld      25, 160(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  53, %[s01], 30\n\t"
        "ld      26, 168(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  54, %[s01], 30\n\t"
        "ld      27, 176(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  55, %[s01], 30\n\t"
        "ld      28, 184(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "lxvd2x  56, %[s01], 30\n\t"
        "ld      29, 192(%[s2])\n\t"
        "mr      31, %[L_SHA3_blocksx3_power8_rot]\n\t"
        "mr      30, %[L_SHA3_blocksx3_power8_r]\n\t"
        "std     30, 56(1)\n\t"
        "std     %[s01], 40(1)\n\t"
        "std     %[s2], 48(1)\n\t"
        "li      30, 24\n\t"
        "mtctr   30\n\t"
        /* Start of 24 rounds */
        "\n"
    "L_SHA3_blocksx3_power8_begin_%=: \n\t"
        /* Theta - column parities (VSX || scalar) */
        "vxor    25, 0, 5\n\t"
        "xor     30, 0, 9\n\t"
        "vxor    25, 25, 10\n\t"
        "xor     30, 30, 15\n\t"
        "vxor    25, 25, 15\n\t"
        "xor     30, 30, 20\n\t"
        "vxor    25, 25, 20\n\t"
        "xor     30, 30, 25\n\t"
        "std     30, 0(1)\n\t"
        "vxor    26, 1, 6\n\t"
        "xor     30, 5, 10\n\t"
        "vxor    26, 26, 11\n\t"
        "xor     30, 30, 16\n\t"
        "vxor    26, 26, 16\n\t"
        "xor     30, 30, 21\n\t"
        "vxor    26, 26, 21\n\t"
        "xor     30, 30, 26\n\t"
        "std     30, 8(1)\n\t"
        "vxor    27, 2, 7\n\t"
        "xor     30, 6, 11\n\t"
        "vxor    27, 27, 12\n\t"
        "xor     30, 30, 17\n\t"
        "vxor    27, 27, 17\n\t"
        "xor     30, 30, 22\n\t"
        "vxor    27, 27, 22\n\t"
        "xor     30, 30, 27\n\t"
        "std     30, 16(1)\n\t"
        "vxor    28, 3, 8\n\t"
        "xor     30, 7, 12\n\t"
        "vxor    28, 28, 13\n\t"
        "xor     30, 30, 18\n\t"
        "vxor    28, 28, 18\n\t"
        "xor     30, 30, 23\n\t"
        "vxor    28, 28, 23\n\t"
        "xor     30, 30, 28\n\t"
        "std     30, 24(1)\n\t"
        "vxor    29, 4, 9\n\t"
        "xor     30, 8, 14\n\t"
        "vxor    29, 29, 14\n\t"
        "xor     30, 30, 19\n\t"
        "vxor    29, 29, 19\n\t"
        "xor     30, 30, 24\n\t"
        "vxor    29, 29, 24\n\t"
        "xor     30, 30, 29\n\t"
        "std     30, 32(1)\n\t"
        /* Theta - fold and apply (VSX || scalar) */
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    30, 26, 31\n\t"
        "ld      30, 8(1)\n\t"
        "vxor    30, 29, 30\n\t"
        "rotldi  30, 30, 1\n\t"
        "ld      %[s01], 32(1)\n\t"
        "xor     %[s01], %[s01], 30\n\t"
        "vxor    0, 0, 30\n\t"
        "xor     0, 0, %[s01]\n\t"
        "vxor    5, 5, 30\n\t"
        "xor     9, 9, %[s01]\n\t"
        "vxor    10, 10, 30\n\t"
        "xor     15, 15, %[s01]\n\t"
        "vxor    15, 15, 30\n\t"
        "xor     20, 20, %[s01]\n\t"
        "vxor    20, 20, 30\n\t"
        "xor     25, 25, %[s01]\n\t"
        "vrld    30, 27, 31\n\t"
        "ld      30, 16(1)\n\t"
        "vxor    30, 25, 30\n\t"
        "rotldi  30, 30, 1\n\t"
        "ld      %[s01], 0(1)\n\t"
        "xor     %[s01], %[s01], 30\n\t"
        "vxor    1, 1, 30\n\t"
        "xor     5, 5, %[s01]\n\t"
        "vxor    6, 6, 30\n\t"
        "xor     10, 10, %[s01]\n\t"
        "vxor    11, 11, 30\n\t"
        "xor     16, 16, %[s01]\n\t"
        "vxor    16, 16, 30\n\t"
        "xor     21, 21, %[s01]\n\t"
        "vxor    21, 21, 30\n\t"
        "xor     26, 26, %[s01]\n\t"
        "vrld    30, 28, 31\n\t"
        "ld      30, 24(1)\n\t"
        "vxor    30, 26, 30\n\t"
        "rotldi  30, 30, 1\n\t"
        "ld      %[s01], 8(1)\n\t"
        "xor     %[s01], %[s01], 30\n\t"
        "vxor    2, 2, 30\n\t"
        "xor     6, 6, %[s01]\n\t"
        "vxor    7, 7, 30\n\t"
        "xor     11, 11, %[s01]\n\t"
        "vxor    12, 12, 30\n\t"
        "xor     17, 17, %[s01]\n\t"
        "vxor    17, 17, 30\n\t"
        "xor     22, 22, %[s01]\n\t"
        "vxor    22, 22, 30\n\t"
        "xor     27, 27, %[s01]\n\t"
        "vrld    30, 29, 31\n\t"
        "ld      30, 32(1)\n\t"
        "vxor    30, 27, 30\n\t"
        "rotldi  30, 30, 1\n\t"
        "ld      %[s01], 16(1)\n\t"
        "xor     %[s01], %[s01], 30\n\t"
        "vxor    3, 3, 30\n\t"
        "xor     7, 7, %[s01]\n\t"
        "vxor    8, 8, 30\n\t"
        "xor     12, 12, %[s01]\n\t"
        "vxor    13, 13, 30\n\t"
        "xor     18, 18, %[s01]\n\t"
        "vxor    18, 18, 30\n\t"
        "xor     23, 23, %[s01]\n\t"
        "vxor    23, 23, 30\n\t"
        "xor     28, 28, %[s01]\n\t"
        "vrld    30, 25, 31\n\t"
        "ld      30, 0(1)\n\t"
        "vxor    30, 28, 30\n\t"
        "rotldi  30, 30, 1\n\t"
        "ld      %[s01], 24(1)\n\t"
        "xor     %[s01], %[s01], 30\n\t"
        "vxor    4, 4, 30\n\t"
        "xor     8, 8, %[s01]\n\t"
        "vxor    9, 9, 30\n\t"
        "xor     14, 14, %[s01]\n\t"
        "vxor    14, 14, 30\n\t"
        "xor     19, 19, %[s01]\n\t"
        "vxor    19, 19, 30\n\t"
        "xor     24, 24, %[s01]\n\t"
        "vxor    24, 24, 30\n\t"
        "xor     29, 29, %[s01]\n\t"
        /* Rho + Pi (VSX || scalar) */
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    25, 1, 31\n\t"
        "rotldi  %[s2], 5, 1\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    1, 6, 31\n\t"
        "rotldi  5, 10, 44\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    6, 9, 31\n\t"
        "rotldi  10, 14, 20\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    9, 22, 31\n\t"
        "rotldi  14, 27, 61\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    22, 14, 31\n\t"
        "rotldi  27, 19, 39\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    14, 20, 31\n\t"
        "rotldi  19, 25, 18\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    20, 2, 31\n\t"
        "rotldi  25, 6, 62\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    2, 12, 31\n\t"
        "rotldi  6, 17, 43\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    12, 13, 31\n\t"
        "rotldi  17, 18, 25\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    13, 19, 31\n\t"
        "rotldi  18, 24, 8\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    19, 23, 31\n\t"
        "rotldi  24, 28, 56\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    23, 15, 31\n\t"
        "rotldi  28, 20, 41\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    15, 4, 31\n\t"
        "rotldi  20, 8, 27\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    4, 24, 31\n\t"
        "rotldi  8, 29, 14\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    24, 21, 31\n\t"
        "rotldi  29, 26, 2\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    21, 8, 31\n\t"
        "rotldi  26, 12, 55\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    8, 16, 31\n\t"
        "rotldi  12, 21, 45\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    16, 5, 31\n\t"
        "rotldi  21, 9, 36\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    5, 3, 31\n\t"
        "rotldi  9, 7, 28\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    3, 18, 31\n\t"
        "rotldi  7, 23, 21\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    18, 17, 31\n\t"
        "rotldi  23, 22, 15\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    17, 11, 31\n\t"
        "rotldi  22, 16, 10\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    11, 7, 31\n\t"
        "rotldi  16, 11, 6\n\t"
        "lxvdsx  63, 0, 31\n\t"
        "addi    31, 31, 8\n\t"
        "vrld    7, 10, 31\n\t"
        "rotldi  11, 15, 3\n\t"
        /* Chi (VSX || scalar) */
        "vandc   26, 2, 1\n\t"
        "andc    30, 6, 5\n\t"
        "vandc   27, 3, 2\n\t"
        "andc    %[s01], 7, 6\n\t"
        "vandc   10, 4, 3\n\t"
        "andc    15, 8, 7\n\t"
        "vxor    2, 2, 10\n\t"
        "xor     6, 6, 15\n\t"
        "vandc   10, 0, 4\n\t"
        "andc    15, 0, 8\n\t"
        "vxor    3, 3, 10\n\t"
        "xor     7, 7, 15\n\t"
        "vandc   10, 1, 0\n\t"
        "andc    15, 5, 0\n\t"
        "vxor    1, 1, 27\n\t"
        "xor     5, 5, %[s01]\n\t"
        "vxor    4, 4, 10\n\t"
        "xor     8, 8, 15\n\t"
        "vxor    0, 0, 26\n\t"
        "xor     0, 0, 30\n\t"
        "vandc   26, 7, 6\n\t"
        "andc    30, 11, 10\n\t"
        "vandc   27, 8, 7\n\t"
        "andc    %[s01], 12, 11\n\t"
        "vandc   10, 9, 8\n\t"
        "andc    15, 14, 12\n\t"
        "vxor    7, 7, 10\n\t"
        "xor     11, 11, 15\n\t"
        "vandc   10, 5, 9\n\t"
        "andc    15, 9, 14\n\t"
        "vxor    8, 8, 10\n\t"
        "xor     12, 12, 15\n\t"
        "vandc   10, 6, 5\n\t"
        "andc    15, 10, 9\n\t"
        "vxor    6, 6, 27\n\t"
        "xor     10, 10, %[s01]\n\t"
        "vxor    9, 9, 10\n\t"
        "xor     14, 14, 15\n\t"
        "vxor    5, 5, 26\n\t"
        "xor     9, 9, 30\n\t"
        "vandc   26, 12, 11\n\t"
        "andc    30, 17, 16\n\t"
        "vandc   27, 13, 12\n\t"
        "andc    %[s01], 18, 17\n\t"
        "vandc   10, 14, 13\n\t"
        "andc    15, 19, 18\n\t"
        "vxor    12, 12, 10\n\t"
        "xor     17, 17, 15\n\t"
        "vandc   10, 25, 14\n\t"
        "andc    15, %[s2], 19\n\t"
        "vxor    13, 13, 10\n\t"
        "xor     18, 18, 15\n\t"
        "vandc   10, 11, 25\n\t"
        "andc    15, 16, %[s2]\n\t"
        "vxor    11, 11, 27\n\t"
        "xor     16, 16, %[s01]\n\t"
        "vxor    14, 14, 10\n\t"
        "xor     19, 19, 15\n\t"
        "vxor    10, 25, 26\n\t"
        "xor     15, %[s2], 30\n\t"
        "vandc   26, 17, 16\n\t"
        "andc    30, 22, 21\n\t"
        "vandc   27, 18, 17\n\t"
        "andc    %[s01], 23, 22\n\t"
        "vandc   25, 19, 18\n\t"
        "andc    %[s2], 24, 23\n\t"
        "vxor    17, 17, 25\n\t"
        "xor     22, 22, %[s2]\n\t"
        "vandc   25, 15, 19\n\t"
        "andc    %[s2], 20, 24\n\t"
        "vxor    18, 18, 25\n\t"
        "xor     23, 23, %[s2]\n\t"
        "vandc   25, 16, 15\n\t"
        "andc    %[s2], 21, 20\n\t"
        "vxor    16, 16, 27\n\t"
        "xor     21, 21, %[s01]\n\t"
        "vxor    19, 19, 25\n\t"
        "xor     24, 24, %[s2]\n\t"
        "vxor    15, 15, 26\n\t"
        "xor     20, 20, 30\n\t"
        "vandc   26, 22, 21\n\t"
        "andc    30, 27, 26\n\t"
        "vandc   27, 23, 22\n\t"
        "andc    %[s01], 28, 27\n\t"
        "vandc   25, 24, 23\n\t"
        "andc    %[s2], 29, 28\n\t"
        "vxor    22, 22, 25\n\t"
        "xor     27, 27, %[s2]\n\t"
        "vandc   25, 20, 24\n\t"
        "andc    %[s2], 25, 29\n\t"
        "vxor    23, 23, 25\n\t"
        "xor     28, 28, %[s2]\n\t"
        "vandc   25, 21, 20\n\t"
        "andc    %[s2], 26, 25\n\t"
        "vxor    21, 21, 27\n\t"
        "xor     26, 26, %[s01]\n\t"
        "vxor    24, 24, 25\n\t"
        "xor     29, 29, %[s2]\n\t"
        "vxor    20, 20, 26\n\t"
        "xor     25, 25, 30\n\t"
        "subi    31, 31, 0xc8\n\t"
        /* Iota - XOR round constant into lane 0 of each state */
        "ld      30, 56(1)\n\t"
        "lxvdsx  58, 0, 30\n\t"
        "vxor    0, 0, 26\n\t"
        "ld      %[s01], 0(30)\n\t"
        "xor     0, 0, %[s01]\n\t"
        "addi    30, 30, 8\n\t"
        "std     30, 56(1)\n\t"
        "bdnz    L_SHA3_blocksx3_power8_begin_%=\n\t"
        "ld      %[s01], 40(1)\n\t"
        "ld      %[s2], 48(1)\n\t"
        /* Store states */
        "li      30, 0\n\t"
        "stxvd2x 32, %[s01], 30\n\t"
        "std     0, 0(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 33, %[s01], 30\n\t"
        "std     5, 8(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 34, %[s01], 30\n\t"
        "std     6, 16(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 35, %[s01], 30\n\t"
        "std     7, 24(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 36, %[s01], 30\n\t"
        "std     8, 32(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 37, %[s01], 30\n\t"
        "std     9, 40(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 38, %[s01], 30\n\t"
        "std     10, 48(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 39, %[s01], 30\n\t"
        "std     11, 56(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 40, %[s01], 30\n\t"
        "std     12, 64(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 41, %[s01], 30\n\t"
        "std     14, 72(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 42, %[s01], 30\n\t"
        "std     15, 80(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 43, %[s01], 30\n\t"
        "std     16, 88(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 44, %[s01], 30\n\t"
        "std     17, 96(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 45, %[s01], 30\n\t"
        "std     18, 104(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 46, %[s01], 30\n\t"
        "std     19, 112(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 47, %[s01], 30\n\t"
        "std     20, 120(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 48, %[s01], 30\n\t"
        "std     21, 128(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 49, %[s01], 30\n\t"
        "std     22, 136(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 50, %[s01], 30\n\t"
        "std     23, 144(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 51, %[s01], 30\n\t"
        "std     24, 152(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 52, %[s01], 30\n\t"
        "std     25, 160(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 53, %[s01], 30\n\t"
        "std     26, 168(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 54, %[s01], 30\n\t"
        "std     27, 176(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 55, %[s01], 30\n\t"
        "std     28, 184(%[s2])\n\t"
        "addi    30, 30, 16\n\t"
        "stxvd2x 56, %[s01], 30\n\t"
        "std     29, 192(%[s2])\n\t"
        "addi    1, 1, 0xd0\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [s01] "+r" (s01), [s2] "+r" (s2),
          [L_SHA3_blocksx3_power8_rot] "+r" (L_SHA3_blocksx3_power8_rot_c),
          [L_SHA3_blocksx3_power8_r] "+r" (L_SHA3_blocksx3_power8_r_c)
        :
        : "memory", "cc", "0", "7", "8", "9", "10", "11", "12", "14", "15",
            "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26",
            "27", "28", "29", "30", "31", "v0", "v1", "v2", "v3", "v4", "v5",
            "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
            "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24",
            "v25", "v26", "v27", "v28", "v29", "v30", "v31"
#else
        :
        : [s01] "r" (s01), [s2] "r" (s2),
          [L_SHA3_blocksx3_power8_rot] "r" (L_SHA3_blocksx3_power8_rot_c),
          [L_SHA3_blocksx3_power8_r] "r" (L_SHA3_blocksx3_power8_r_c)
        : "memory", "cc", "0", "5", "6", "7", "8", "9", "10", "11", "12", "14",
            "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25",
            "26", "27", "28", "29", "30", "31", "v0", "v1", "v2", "v3", "v4",
            "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14",
            "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
            "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
    );
}

#endif /* (WOLFSSL_HAVE_MLKEM ||
        * HAVE_DILITHIUM) && WOLFSSL_SHA3_PPC64_BLOCKS_N */
#endif /* WOLFSSL_PPC64_ASM_POWER8 */
#endif /* WOLFSSL_SHA3 */
#endif /* WOLFSSL_PPC64_ASM */

#endif /* WOLFSSL_PPC64_ASM_INLINE */
