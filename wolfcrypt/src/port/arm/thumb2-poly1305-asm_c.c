/* thumb2-poly1305-asm
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
 *   ruby ./poly1305/poly1305.rb \
 *       thumb2 ../wolfssl/wolfcrypt/src/port/arm/thumb2-poly1305-asm.c
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
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

#ifdef HAVE_POLY1305
#include <wolfssl/wolfcrypt/poly1305.h>

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void poly1305_blocks_thumb2_16(Poly1305* ctx_p,
    const byte* m_p, word32 len_p, int notLast_p)
#else
WC_OMIT_FRAME_POINTER void poly1305_blocks_thumb2_16(Poly1305* ctx,
    const byte* m, word32 len, int notLast)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register Poly1305* ctx __asm__ ("r0") = (Poly1305*)ctx_p;
    register const byte* m __asm__ ("r1") = (const byte*)m_p;
    register word32 len __asm__ ("r2") = (word32)len_p;
    register int notLast __asm__ ("r3") = (int)notLast_p;
#else
    void* L_asm_args[4] = {(void*)(size_t)ctx, (void*)(size_t)m,
        (void*)(size_t)len, (void*)(size_t)notLast
    };
    void** L_asm_args_p = L_asm_args;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
        "PUSH	{%[L_asm_args]}\n\t"
        "LDM	%[L_asm_args], {r0, r1, r2, r3}\n\t"
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
        "SUB	sp, sp, #28\n\t"
        "CMP	r2, #0\n\t"
#if defined(__GNUC__)
        "BEQ	L_poly1305_thumb2_16_done_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.N	L_poly1305_thumb2_16_done\n\t"
#else
        "BEQ.N	L_poly1305_thumb2_16_done_%=\n\t"
#endif
        "ADD	lr, sp, #12\n\t"
        "STM	lr, {r0, r1, r2, r3}\n\t"
        /* Get h pointer */
        "ADD	lr, r0, #16\n\t"
        "LDM	lr, {r4, r5, r6, r7, r8}\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_poly1305_thumb2_16_loop:\n\t"
#else
    "L_poly1305_thumb2_16_loop_%=:\n\t"
#endif
        /* Add m to h */
        "LDR	r1, [sp, #16]\n\t"
        "LDR	r2, [r1]\n\t"
        "LDR	r3, [r1, #4]\n\t"
        "LDR	r9, [r1, #8]\n\t"
        "LDR	r10, [r1, #12]\n\t"
        "LDR	r11, [sp, #24]\n\t"
        "ADDS	r4, r4, r2\n\t"
        "ADCS	r5, r5, r3\n\t"
        "ADCS	r6, r6, r9\n\t"
        "ADCS	r7, r7, r10\n\t"
        "ADD	r1, r1, #16\n\t"
        "ADC	r8, r8, r11\n\t"
#ifdef WOLFSSL_ARM_ARCH_7M
        "STM	lr, {r4, r5, r6, r7, r8}\n\t"
#else
        /* h[0]-h[2] in r4-r6 for multiplication. */
        "STR	r7, [lr, #12]\n\t"
        "STR	r8, [lr, #16]\n\t"
#endif /* WOLFSSL_ARM_ARCH_7M */
        "STR	r1, [sp, #16]\n\t"
        "LDR	r1, [sp, #12]\n\t"
        /* Multiply h by r */
#ifdef WOLFSSL_ARM_ARCH_7M
        /* r0 = #0, r1 = r, lr = h, r2 = h[j], r3 = r[i] */
        "LDR	r3, [r1]\n\t"
        "EOR	r0, r0, r0\n\t"
        /* r[0] * h[0] */
        /* h[0] in r4 */
        "UMULL	r4, r5, r3, r4\n\t"
        /* r[0] * h[2] */
        /* h[2] in r6 */
        "UMULL	r6, r7, r3, r6\n\t"
        /* r[0] * h[4] */
        /* h[4] in r8 */
        "MUL	r8, r3, r8\n\t"
        /* r[0] * h[1] */
        "LDR	r2, [lr, #4]\n\t"
        "MOV	r12, r0\n\t"
        "UMLAL	r5, r12, r3, r2\n\t"
        /* r[0] * h[3] */
        "LDR	r2, [lr, #12]\n\t"
        "ADDS	r6, r6, r12\n\t"
        "ADC	r7, r7, r0\n\t"
        "UMLAL	r7, r8, r3, r2\n\t"
        /* r[1] * h[0] */
        "LDR	r3, [r1, #4]\n\t"
        "LDR	r2, [lr]\n\t"
        "MOV	r12, r0\n\t"
        "UMLAL	r5, r12, r3, r2\n\t"
        /* r[1] * h[1] */
        "LDR	r2, [lr, #4]\n\t"
        "ADDS	r6, r6, r12\n\t"
        "ADC	r12, r0, r0\n\t"
        "UMLAL	r6, r12, r3, r2\n\t"
        /* r[1] * h[2] */
        "LDR	r2, [lr, #8]\n\t"
        "ADDS	r7, r7, r12\n\t"
        "ADC	r12, r0, r0\n\t"
        "UMLAL	r7, r12, r3, r2\n\t"
        /* r[1] * h[3] */
        "LDR	r2, [lr, #12]\n\t"
        "ADDS	r8, r8, r12\n\t"
        "ADC	r9, r0, r0\n\t"
        "UMLAL	r8, r9, r3, r2\n\t"
        /* r[1] * h[4] */
        "LDR	r2, [lr, #16]\n\t"
        "MLA	r9, r3, r2, r9\n\t"
        /* r[2] * h[0] */
        "LDR	r3, [r1, #8]\n\t"
        "LDR	r2, [lr]\n\t"
        "MOV	r12, r0\n\t"
        "UMLAL	r6, r12, r3, r2\n\t"
        /* r[2] * h[1] */
        "LDR	r2, [lr, #4]\n\t"
        "ADDS	r7, r7, r12\n\t"
        "ADC	r12, r0, r0\n\t"
        "UMLAL	r7, r12, r3, r2\n\t"
        /* r[2] * h[2] */
        "LDR	r2, [lr, #8]\n\t"
        "ADDS	r8, r8, r12\n\t"
        "ADC	r12, r0, r0\n\t"
        "UMLAL	r8, r12, r3, r2\n\t"
        /* r[2] * h[3] */
        "LDR	r2, [lr, #12]\n\t"
        "ADDS	r9, r9, r12\n\t"
        "ADC	r10, r0, r0\n\t"
        "UMLAL	r9, r10, r3, r2\n\t"
        /* r[2] * h[4] */
        "LDR	r2, [lr, #16]\n\t"
        "MLA	r10, r3, r2, r10\n\t"
        /* r[3] * h[0] */
        "LDR	r3, [r1, #12]\n\t"
        "LDR	r2, [lr]\n\t"
        "MOV	r12, r0\n\t"
        "UMLAL	r7, r12, r3, r2\n\t"
        /* r[3] * h[1] */
        "LDR	r2, [lr, #4]\n\t"
        "ADDS	r8, r8, r12\n\t"
        "ADC	r12, r0, r0\n\t"
        "UMLAL	r8, r12, r3, r2\n\t"
        /* r[3] * h[2] */
        "LDR	r2, [lr, #8]\n\t"
        "ADDS	r9, r9, r12\n\t"
        "ADC	r10, r10, r0\n\t"
        "UMLAL	r9, r10, r3, r2\n\t"
        /* r[3] * h[3] */
        "LDR	r2, [lr, #12]\n\t"
        "MOV	r11, r0\n\t"
        "UMLAL	r10, r11, r3, r2\n\t"
        /* r[3] * h[4] */
        "LDR	r2, [lr, #16]\n\t"
        "MOV	r12, r0\n\t"
        "MLA	r11, r3, r2, r11\n\t"
#else
        "LDM	r1, {r0, r1, r2, r3}\n\t"
        /* r[0] * h[0] */
        "UMULL	r10, r11, r0, r4\n\t"
        /* r[1] * h[0] */
        "UMULL	r12, r7, r1, r4\n\t"
        /* r[0] * h[1] */
        "UMAAL	r11, r12, r0, r5\n\t"
        /* r[2] * h[0] */
        "UMULL	r8, r9, r2, r4\n\t"
        /* r[1] * h[1] */
        "UMAAL	r12, r8, r1, r5\n\t"
        /* r[0] * h[2] */
        "UMAAL	r12, r7, r0, r6\n\t"
        /* r[3] * h[0] */
        "UMAAL	r8, r9, r3, r4\n\t"
        "STM	sp, {r10, r11, r12}\n\t"
        /* r[2] * h[1] */
        "UMAAL	r7, r8, r2, r5\n\t"
        /* Replace h[0] with h[3] */
        "LDR	r4, [lr, #12]\n\t"
        /* r[1] * h[2] */
        "UMULL	r10, r11, r1, r6\n\t"
        /* r[2] * h[2] */
        "UMAAL	r8, r9, r2, r6\n\t"
        /* r[0] * h[3] */
        "UMAAL	r7, r10, r0, r4\n\t"
        /* r[3] * h[1] */
        "UMAAL	r8, r11, r3, r5\n\t"
        /* r[1] * h[3] */
        "UMAAL	r8, r10, r1, r4\n\t"
        /* r[3] * h[2] */
        "UMAAL	r9, r11, r3, r6\n\t"
        /* r[2] * h[3] */
        "UMAAL	r9, r10, r2, r4\n\t"
        /* Replace h[1] with h[4] */
        "LDR	r5, [lr, #16]\n\t"
        /* r[3] * h[3] */
        "UMAAL	r10, r11, r3, r4\n\t"
        "MOV	r12, #0\n\t"
        /* r[0] * h[4] */
        "UMAAL	r8, r12, r0, r5\n\t"
        /* r[1] * h[4] */
        "UMAAL	r9, r12, r1, r5\n\t"
        /* r[2] * h[4] */
        "UMAAL	r10, r12, r2, r5\n\t"
        /* r[3] * h[4] */
        "UMAAL	r11, r12, r3, r5\n\t"
        /* DONE */
        "LDM	sp, {r4, r5, r6}\n\t"
#endif /* WOLFSSL_ARM_ARCH_7M */
        /* r12 will be zero because r is masked. */
        /* Load length */
        "LDR	r2, [sp, #20]\n\t"
        /* Reduce mod 2^130 - 5 */
        "BIC	r3, r8, #3\n\t"
        "AND	r8, r8, #3\n\t"
        "ADDS	r4, r4, r3\n\t"
        "LSR	r3, r3, #2\n\t"
        "ADCS	r5, r5, r9\n\t"
        "ORR	r3, r3, r9, LSL #30\n\t"
        "ADCS	r6, r6, r10\n\t"
        "LSR	r9, r9, #2\n\t"
        "ADCS	r7, r7, r11\n\t"
        "ORR	r9, r9, r10, LSL #30\n\t"
        "ADC	r8, r8, r12\n\t"
        "LSR	r10, r10, #2\n\t"
        "ADDS	r4, r4, r3\n\t"
        "ORR	r10, r10, r11, LSL #30\n\t"
        "ADCS	r5, r5, r9\n\t"
        "LSR	r11, r11, #2\n\t"
        "ADCS	r6, r6, r10\n\t"
        "ADCS	r7, r7, r11\n\t"
        "ADC	r8, r8, r12\n\t"
        /* Sub 16 from length. */
        "SUBS	r2, r2, #16\n\t"
        /* Store length. */
        "STR	r2, [sp, #20]\n\t"
        /* Loop again if more message to do. */
#if defined(__GNUC__)
        "BGT	L_poly1305_thumb2_16_loop_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BGT.N	L_poly1305_thumb2_16_loop\n\t"
#else
        "BGT.N	L_poly1305_thumb2_16_loop_%=\n\t"
#endif
        "STM	lr, {r4, r5, r6, r7, r8}\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_poly1305_thumb2_16_done:\n\t"
#else
    "L_poly1305_thumb2_16_done_%=:\n\t"
#endif
        "ADD	sp, sp, #28\n\t"
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
        "POP	{%[L_asm_args]}\n\t"
        "STM	%[L_asm_args], {r0, r1, r2, r3}\n\t"
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [ctx] "+r" (ctx), [m] "+r" (m), [len] "+r" (len),
          [notLast] "+r" (notLast)
        :
        : "memory", "cc", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11",
            "r12", "lr"
#else
        : [L_asm_args] "+r" (L_asm_args_p)
        :
        : "memory", "cc", "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8",
            "r9", "r10", "r11", "lr"
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
    );
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
    ctx = (Poly1305*)(size_t)L_asm_args[0];
    m = (const byte*)(size_t)L_asm_args[1];
    len = (word32)(size_t)L_asm_args[2];
    notLast = (int)(size_t)L_asm_args[3];
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
}

XALIGNED(8) static const word32 L_poly1305_thumb2_clamp[] = {
    0x0fffffff, 0x0ffffffc, 0x0ffffffc, 0x0ffffffc,
};

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void poly1305_set_key(Poly1305* ctx_p, const byte* key_p)
#else
WC_OMIT_FRAME_POINTER void poly1305_set_key(Poly1305* ctx, const byte* key)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register Poly1305* ctx __asm__ ("r0") = (Poly1305*)ctx_p;
    register const byte* key __asm__ ("r1") = (const byte*)key_p;
    register word32* L_poly1305_thumb2_clamp_c __asm__ ("r2") =
        (word32*)&L_poly1305_thumb2_clamp;
#else
    void* L_asm_args[3] = {(void*)(size_t)ctx, (void*)(size_t)key,
        (void*)(size_t)&L_poly1305_thumb2_clamp
    };
    void** L_asm_args_p = L_asm_args;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
        "PUSH	{%[L_asm_args]}\n\t"
        "LDM	%[L_asm_args], {r0, r1, r2}\n\t"
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
        /* Load mask. */
        "MOV	r10, r2\n\t"
        "LDM	r10, {r6, r7, r8, r9}\n\t"
        /* Load and cache padding. */
        "LDR	r2, [r1, #16]\n\t"
        "LDR	r3, [r1, #20]\n\t"
        "LDR	r4, [r1, #24]\n\t"
        "LDR	r5, [r1, #28]\n\t"
        "ADD	r10, r0, #36\n\t"
        "STM	r10, {r2, r3, r4, r5}\n\t"
        /* Load, mask and store r. */
        "LDR	r2, [r1]\n\t"
        "LDR	r3, [r1, #4]\n\t"
        "LDR	r4, [r1, #8]\n\t"
        "LDR	r5, [r1, #12]\n\t"
        "AND	r2, r2, r6\n\t"
        "AND	r3, r3, r7\n\t"
        "AND	r4, r4, r8\n\t"
        "AND	r5, r5, r9\n\t"
        "ADD	r10, r0, #0\n\t"
        "STM	r10, {r2, r3, r4, r5}\n\t"
        /* h (accumulator) = 0 */
        "EOR	r6, r6, r6\n\t"
        "EOR	r7, r7, r7\n\t"
        "EOR	r8, r8, r8\n\t"
        "EOR	r9, r9, r9\n\t"
        "ADD	r10, r0, #16\n\t"
        "EOR	r5, r5, r5\n\t"
        "STM	r10, {r5, r6, r7, r8, r9}\n\t"
        /* Zero leftover */
        "STR	r5, [r0, #52]\n\t"
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
        "POP	{%[L_asm_args]}\n\t"
        "STM	%[L_asm_args], {r0, r1, r2}\n\t"
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [ctx] "+r" (ctx), [key] "+r" (key),
          [L_poly1305_thumb2_clamp] "+r" (L_poly1305_thumb2_clamp_c)
        :
        : "memory", "cc", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"
#else
        : [L_asm_args] "+r" (L_asm_args_p)
        :
        : "memory", "cc", "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8",
            "r9", "r10", "r11", "lr"
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
    );
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
    ctx = (Poly1305*)(size_t)L_asm_args[0];
    key = (const byte*)(size_t)L_asm_args[1];
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
}

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void poly1305_final(Poly1305* ctx_p, byte* mac_p)
#else
WC_OMIT_FRAME_POINTER void poly1305_final(Poly1305* ctx, byte* mac)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register Poly1305* ctx __asm__ ("r0") = (Poly1305*)ctx_p;
    register byte* mac __asm__ ("r1") = (byte*)mac_p;
#else
    void* L_asm_args[2] = {(void*)(size_t)ctx, (void*)(size_t)mac
    };
    void** L_asm_args_p = L_asm_args;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
        "PUSH	{%[L_asm_args]}\n\t"
        "LDM	%[L_asm_args], {r0, r1}\n\t"
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
        "ADD	r11, r0, #16\n\t"
        "LDM	r11, {r2, r3, r4, r5, r6}\n\t"
        /* Add 5 and check for h larger than p. */
        "ADDS	r7, r2, #5\n\t"
        "ADCS	r7, r3, #0\n\t"
        "ADCS	r7, r4, #0\n\t"
        "ADCS	r7, r5, #0\n\t"
        "ADC	r7, r6, #0\n\t"
        "SUB	r7, r7, #4\n\t"
        "LSR	r7, r7, #31\n\t"
        "SUB	r7, r7, #1\n\t"
        "AND	r7, r7, #5\n\t"
        /* Add 0/5 to h. */
        "ADDS	r2, r2, r7\n\t"
        "ADCS	r3, r3, #0\n\t"
        "ADCS	r4, r4, #0\n\t"
        "ADC	r5, r5, #0\n\t"
        /* Add padding */
        "ADD	r11, r0, #36\n\t"
        "LDM	r11, {r7, r8, r9, r10}\n\t"
        "ADDS	r2, r2, r7\n\t"
        "ADCS	r3, r3, r8\n\t"
        "ADCS	r4, r4, r9\n\t"
        "ADC	r5, r5, r10\n\t"
        /* Store MAC */
        "STR	r2, [r1]\n\t"
        "STR	r3, [r1, #4]\n\t"
        "STR	r4, [r1, #8]\n\t"
        "STR	r5, [r1, #12]\n\t"
        /* Zero out h. */
        "EOR	r2, r2, r2\n\t"
        "EOR	r3, r3, r3\n\t"
        "EOR	r4, r4, r4\n\t"
        "EOR	r5, r5, r5\n\t"
        "EOR	r6, r6, r6\n\t"
        "ADD	r11, r0, #16\n\t"
        "STM	r11, {r2, r3, r4, r5, r6}\n\t"
        /* Zero out r. */
        "ADD	r11, r0, #0\n\t"
        "STM	r11, {r2, r3, r4, r5}\n\t"
        /* Zero out padding. */
        "ADD	r11, r0, #36\n\t"
        "STM	r11, {r2, r3, r4, r5}\n\t"
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
        "POP	{%[L_asm_args]}\n\t"
        "STM	%[L_asm_args], {r0, r1}\n\t"
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [ctx] "+r" (ctx), [mac] "+r" (mac)
        :
        : "memory", "cc", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10",
            "r11"
#else
        : [L_asm_args] "+r" (L_asm_args_p)
        :
        : "memory", "cc", "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8",
            "r9", "r10", "r11", "lr"
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
    );
#ifdef WOLFSSL_NO_VAR_ASSIGN_REG
    ctx = (Poly1305*)(size_t)L_asm_args[0];
    mac = (byte*)(size_t)L_asm_args[1];
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
}

#endif /* HAVE_POLY1305 */
#endif /* WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#endif /* WOLFSSL_ARMASM_INLINE */
