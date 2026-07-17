/* thumb2-frodokem-asm
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

/* Generated using (from wolfssl):
 *   cd ../scripts
 *   ruby ./frodokem/frodokem.rb \
 *       thumb2 ../wolfssl/wolfcrypt/src/port/arm/thumb2-frodokem-asm.c
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef WOLFSSL_ARMASM
#ifdef WOLFSSL_ARMASM_THUMB2
#ifdef WOLFSSL_ARMASM_INLINE

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

#include <wolfssl/wolfcrypt/wc_frodokem_mat.h>

#ifdef WOLFSSL_HAVE_FRODOKEM
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void frodokem_add_thumb2(word16* a_p, const word16* b_p,
    int qmask_p)
#else
WC_OMIT_FRAME_POINTER void frodokem_add_thumb2(word16* a, const word16* b,
    int qmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* a __asm__ ("r0") = (word16*)a_p;
    register const word16* b __asm__ ("r1") = (const word16*)b_p;
    register int qmask __asm__ ("r2") = (int)qmask_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "ORR	%[qmask], %[qmask], %[qmask], LSL #16\n\t"
        "MOV	r3, #32\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_frodokem_add_thumb2_blk:\n\t"
#else
    "L_frodokem_add_thumb2_blk_%=:\n\t"
#endif
        "LDR	r4, [%[a]]\n\t"
        "LDR	r5, [%[b]], #4\n\t"
        "SADD16	r4, r4, r5\n\t"
        "AND	r4, r4, %[qmask]\n\t"
        "STR	r4, [%[a]], #4\n\t"
        "SUBS	r3, r3, #1\n\t"
#if defined(__GNUC__)
        "BNE	L_frodokem_add_thumb2_blk_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.N	L_frodokem_add_thumb2_blk\n\t"
#else
        "BNE.N	L_frodokem_add_thumb2_blk_%=\n\t"
#endif
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [a] "+r" (a), [b] "+r" (b), [qmask] "+r" (qmask)
        :
#else
        :
        : [a] "r" (a), [b] "r" (b), [qmask] "r" (qmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r3", "r4", "r5"
    );
}

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void frodokem_sa_accum_thumb2(word16* out_p,
    const word16* s_p, const word16* row_p, int j_p, int n_p)
#else
WC_OMIT_FRAME_POINTER void frodokem_sa_accum_thumb2(word16* out,
    const word16* s, const word16* row, int j, int n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* out __asm__ ("r0") = (word16*)out_p;
    register const word16* s __asm__ ("r1") = (const word16*)s_p;
    register const word16* row __asm__ ("r2") = (const word16*)row_p;
    register int j __asm__ ("r3") = (int)j_p;
    register int n __asm__ ("r4") = (int)n_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "PUSH	{%[n]}\n\t"
        "LDR	r4, [sp]\n\t"
        "LSL	r4, r4, #1\n\t"
        "ADD	r5, %[s], %[j], LSL #1\n\t"
        "MOV	r8, #8\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_frodokem_sa_accum_thumb2_i:\n\t"
#else
    "L_frodokem_sa_accum_thumb2_i_%=:\n\t"
#endif
        "LDRH	r9, [r5]\n\t"
        "ADD	r5, r5, r4\n\t"
        "MOV	r6, %[row]\n\t"
        "LSR	r7, r4, #2\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_frodokem_sa_accum_thumb2_k:\n\t"
#else
    "L_frodokem_sa_accum_thumb2_k_%=:\n\t"
#endif
        "LDR	r11, [%[out]]\n\t"
        "LDR	r10, [r6], #4\n\t"
        "SMULBB	r12, r9, r10\n\t"
        "SMULBT	lr, r9, r10\n\t"
        "PKHBT	r12, r12, lr, LSL #16\n\t"
        "SADD16	r11, r11, r12\n\t"
        "STR	r11, [%[out]], #4\n\t"
        "SUBS	r7, r7, #1\n\t"
#if defined(__GNUC__)
        "BNE	L_frodokem_sa_accum_thumb2_k_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.N	L_frodokem_sa_accum_thumb2_k\n\t"
#else
        "BNE.N	L_frodokem_sa_accum_thumb2_k_%=\n\t"
#endif
        "SUBS	r8, r8, #1\n\t"
#if defined(__GNUC__)
        "BNE	L_frodokem_sa_accum_thumb2_i_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.N	L_frodokem_sa_accum_thumb2_i\n\t"
#else
        "BNE.N	L_frodokem_sa_accum_thumb2_i_%=\n\t"
#endif
        "POP	{%[n]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [s] "+r" (s), [row] "+r" (row), [j] "+r" (j),
          [n] "+r" (n)
        :
#else
        :
        : [out] "r" (out), [s] "r" (s), [row] "r" (row), [j] "r" (j),
          [n] "r" (n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12",
            "lr"
    );
}

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void frodokem_as_accum_thumb2(word16* out_p,
    const word16* s_p, const word16* row_p, int i_p, int n_p)
#else
WC_OMIT_FRAME_POINTER void frodokem_as_accum_thumb2(word16* out,
    const word16* s, const word16* row, int i, int n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* out __asm__ ("r0") = (word16*)out_p;
    register const word16* s __asm__ ("r1") = (const word16*)s_p;
    register const word16* row __asm__ ("r2") = (const word16*)row_p;
    register int i __asm__ ("r3") = (int)i_p;
    register int n __asm__ ("r4") = (int)n_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "PUSH	{%[n]}\n\t"
        "LDR	r4, [sp]\n\t"
        "LSL	r4, r4, #1\n\t"
        "ADD	r5, %[out], %[i], LSL #4\n\t"
        "MOV	r6, %[s]\n\t"
        "MOV	r9, #8\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_frodokem_as_accum_thumb2_c:\n\t"
#else
    "L_frodokem_as_accum_thumb2_c_%=:\n\t"
#endif
        "MOV	r11, #0\n\t"
        "MOV	r7, %[row]\n\t"
        "MOV	r8, r6\n\t"
        "LSR	r10, r4, #2\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_frodokem_as_accum_thumb2_j:\n\t"
#else
    "L_frodokem_as_accum_thumb2_j_%=:\n\t"
#endif
        "LDR	r12, [r7], #4\n\t"
        "LDR	lr, [r8], #4\n\t"
        "SMLAD	r11, r12, lr, r11\n\t"
        "SUBS	r10, r10, #1\n\t"
#if defined(__GNUC__)
        "BNE	L_frodokem_as_accum_thumb2_j_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.N	L_frodokem_as_accum_thumb2_j\n\t"
#else
        "BNE.N	L_frodokem_as_accum_thumb2_j_%=\n\t"
#endif
        "LDRH	r12, [r5]\n\t"
        "ADD	r12, r12, r11\n\t"
        "STRH	r12, [r5]\n\t"
        "ADD	r5, r5, #2\n\t"
        "ADD	r6, r6, r4\n\t"
        "SUBS	r9, r9, #1\n\t"
#if defined(__GNUC__)
        "BNE	L_frodokem_as_accum_thumb2_c_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.N	L_frodokem_as_accum_thumb2_c\n\t"
#else
        "BNE.N	L_frodokem_as_accum_thumb2_c_%=\n\t"
#endif
        "POP	{%[n]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [s] "+r" (s), [row] "+r" (row), [i] "+r" (i),
          [n] "+r" (n)
        :
#else
        :
        : [out] "r" (out), [s] "r" (s), [row] "r" (row), [i] "r" (i),
          [n] "r" (n)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12",
            "lr"
    );
}

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void frodokem_mul_bs_thumb2(word16* out_p,
    const word16* b_p, const word16* s_p, int n_p, int qmask_p)
#else
WC_OMIT_FRAME_POINTER void frodokem_mul_bs_thumb2(word16* out, const word16* b,
    const word16* s, int n, int qmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* out __asm__ ("r0") = (word16*)out_p;
    register const word16* b __asm__ ("r1") = (const word16*)b_p;
    register const word16* s __asm__ ("r2") = (const word16*)s_p;
    register int n __asm__ ("r3") = (int)n_p;
    register int qmask __asm__ ("r4") = (int)qmask_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "PUSH	{%[qmask]}\n\t"
        "MOV	r4, %[b]\n\t"
        "MOV	r8, #8\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_frodokem_mul_bs_thumb2_i:\n\t"
#else
    "L_frodokem_mul_bs_thumb2_i_%=:\n\t"
#endif
        "MOV	r5, %[s]\n\t"
        "MOV	r9, #8\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_frodokem_mul_bs_thumb2_c:\n\t"
#else
    "L_frodokem_mul_bs_thumb2_c_%=:\n\t"
#endif
        "MOV	r11, #0\n\t"
        "MOV	r6, r4\n\t"
        "MOV	r7, r5\n\t"
        "LSR	r10, %[n], #1\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_frodokem_mul_bs_thumb2_j:\n\t"
#else
    "L_frodokem_mul_bs_thumb2_j_%=:\n\t"
#endif
        "LDR	r12, [r6], #4\n\t"
        "LDR	lr, [r7], #4\n\t"
        "SMLAD	r11, r12, lr, r11\n\t"
        "SUBS	r10, r10, #1\n\t"
#if defined(__GNUC__)
        "BNE	L_frodokem_mul_bs_thumb2_j_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.N	L_frodokem_mul_bs_thumb2_j\n\t"
#else
        "BNE.N	L_frodokem_mul_bs_thumb2_j_%=\n\t"
#endif
        "LDR	r12, [sp]\n\t"
        "ORR	r12, r12, r12, LSL #16\n\t"
        "AND	r11, r11, r12\n\t"
        "STRH	r11, [%[out]]\n\t"
        "ADD	%[out], %[out], #2\n\t"
        "ADD	r5, r5, %[n], LSL #1\n\t"
        "SUBS	r9, r9, #1\n\t"
#if defined(__GNUC__)
        "BNE	L_frodokem_mul_bs_thumb2_c_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.N	L_frodokem_mul_bs_thumb2_c\n\t"
#else
        "BNE.N	L_frodokem_mul_bs_thumb2_c_%=\n\t"
#endif
        "ADD	r4, r4, %[n], LSL #1\n\t"
        "SUBS	r8, r8, #1\n\t"
#if defined(__GNUC__)
        "BNE	L_frodokem_mul_bs_thumb2_i_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.N	L_frodokem_mul_bs_thumb2_i\n\t"
#else
        "BNE.N	L_frodokem_mul_bs_thumb2_i_%=\n\t"
#endif
        "POP	{%[qmask]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [b] "+r" (b), [s] "+r" (s), [n] "+r" (n),
          [qmask] "+r" (qmask)
        :
#else
        :
        : [out] "r" (out), [b] "r" (b), [s] "r" (s), [n] "r" (n),
          [qmask] "r" (qmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12",
            "lr"
    );
}

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void frodokem_mul_add_sb_plus_e_thumb2(word16* out_p,
    const word16* b_p, const word16* s_p, int n_p, int qmask_p)
#else
WC_OMIT_FRAME_POINTER void frodokem_mul_add_sb_plus_e_thumb2(word16* out,
    const word16* b, const word16* s, int n, int qmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word16* out __asm__ ("r0") = (word16*)out_p;
    register const word16* b __asm__ ("r1") = (const word16*)b_p;
    register const word16* s __asm__ ("r2") = (const word16*)s_p;
    register int n __asm__ ("r3") = (int)n_p;
    register int qmask __asm__ ("r4") = (int)qmask_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "PUSH	{%[qmask]}\n\t"
        "SUB	sp, sp, #8\n\t"
        "LSL	r11, %[n], #1\n\t"
        "STR	r11, [sp, #4]\n\t"
        "STR	%[b], [sp]\n\t"
        "MOV	r4, #8\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_frodokem_mul_add_sb_plus_e_thumb2_i:\n\t"
#else
    "L_frodokem_mul_add_sb_plus_e_thumb2_i_%=:\n\t"
#endif
        "LDR	r11, [sp, #4]\n\t"
        "ADD	%[n], %[s], r11\n\t"
        "LDR	%[b], [sp]\n\t"
        "MOV	r5, %[s]\n\t"
        "LDR	r6, [%[out]]\n\t"
        "LDR	r7, [%[out], #4]\n\t"
        "LDR	r8, [%[out], #8]\n\t"
        "LDR	r9, [%[out], #12]\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_frodokem_mul_add_sb_plus_e_thumb2_j:\n\t"
#else
    "L_frodokem_mul_add_sb_plus_e_thumb2_j_%=:\n\t"
#endif
        "LDRH	r10, [r5]\n\t"
        "ADD	r5, r5, #2\n\t"
        "LDR	r11, [%[b]]\n\t"
        "SMULBB	r12, r10, r11\n\t"
        "SMULBT	lr, r10, r11\n\t"
        "PKHBT	r12, r12, lr, LSL #16\n\t"
        "SADD16	r6, r6, r12\n\t"
        "LDR	r11, [%[b], #4]\n\t"
        "SMULBB	r12, r10, r11\n\t"
        "SMULBT	lr, r10, r11\n\t"
        "PKHBT	r12, r12, lr, LSL #16\n\t"
        "SADD16	r7, r7, r12\n\t"
        "LDR	r11, [%[b], #8]\n\t"
        "SMULBB	r12, r10, r11\n\t"
        "SMULBT	lr, r10, r11\n\t"
        "PKHBT	r12, r12, lr, LSL #16\n\t"
        "SADD16	r8, r8, r12\n\t"
        "LDR	r11, [%[b], #12]\n\t"
        "SMULBB	r12, r10, r11\n\t"
        "SMULBT	lr, r10, r11\n\t"
        "PKHBT	r12, r12, lr, LSL #16\n\t"
        "SADD16	r9, r9, r12\n\t"
        "ADD	%[b], %[b], #16\n\t"
        "CMP	r5, %[n]\n\t"
#if defined(__GNUC__)
        "BNE	L_frodokem_mul_add_sb_plus_e_thumb2_j_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.N	L_frodokem_mul_add_sb_plus_e_thumb2_j\n\t"
#else
        "BNE.N	L_frodokem_mul_add_sb_plus_e_thumb2_j_%=\n\t"
#endif
        "LDR	r11, [sp, #8]\n\t"
        "ORR	r11, r11, r11, LSL #16\n\t"
        "AND	r6, r6, r11\n\t"
        "AND	r7, r7, r11\n\t"
        "AND	r8, r8, r11\n\t"
        "AND	r9, r9, r11\n\t"
        "STR	r6, [%[out]]\n\t"
        "STR	r7, [%[out], #4]\n\t"
        "STR	r8, [%[out], #8]\n\t"
        "STR	r9, [%[out], #12]\n\t"
        "ADD	%[out], %[out], #16\n\t"
        "MOV	%[s], %[n]\n\t"
        "SUBS	r4, r4, #1\n\t"
#if defined(__GNUC__)
        "BNE	L_frodokem_mul_add_sb_plus_e_thumb2_i_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.N	L_frodokem_mul_add_sb_plus_e_thumb2_i\n\t"
#else
        "BNE.N	L_frodokem_mul_add_sb_plus_e_thumb2_i_%=\n\t"
#endif
        "ADD	sp, sp, #8\n\t"
        "POP	{%[qmask]}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [out] "+r" (out), [b] "+r" (b), [s] "+r" (s), [n] "+r" (n),
          [qmask] "+r" (qmask)
        :
#else
        :
        : [out] "r" (out), [b] "r" (b), [s] "r" (s), [n] "r" (n),
          [qmask] "r" (qmask)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12",
            "lr"
    );
}

#endif /* WOLFSSL_HAVE_FRODOKEM */

#endif /* WOLFSSL_ARMASM_INLINE */
#endif /* WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */
