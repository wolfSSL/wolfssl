/* thumb2-poly1305-asm
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

/* Generated using (from wolfssl):
 *   cd ../scripts
 *   ruby ./poly1305/poly1305.rb thumb2 ../wolfssl/wolfcrypt/src/port/arm/thumb2-poly1305-asm.c
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>
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
#ifdef HAVE_POLY1305
#include <wolfssl/wolfcrypt/poly1305.h>

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void poly1305_blocks_thumb2_16(Poly1305* ctx_p, const byte* m_p, word32 len_p, int notLast_p)
#else
void poly1305_blocks_thumb2_16(Poly1305* ctx, const byte* m, word32 len, int notLast)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register Poly1305* ctx __asm__ ("r0") = (Poly1305*)ctx_p;
    register const byte* m __asm__ ("r1") = (const byte*)m_p;
    register word32 len __asm__ ("r2") = (word32)len_p;
    register int notLast __asm__ ("r3") = (int)notLast_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "SUB	sp, sp, #0x1c\n\t"
        "CMP	%[len], #0x0\n\t"
#if defined(__GNUC__)
        "BEQ	L_poly1305_thumb2_16_done_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.N	L_poly1305_thumb2_16_done\n\t"
#else
        "BEQ.N	L_poly1305_thumb2_16_done_%=\n\t"
#endif
        "ADD	lr, sp, #0xc\n\t"
        "STM	lr, {%[ctx], %[m], %[len], %[notLast]}\n\t"
        /* Get h pointer */
        "ADD	lr, %[ctx], #0x10\n\t"
        "LDM	lr, {r4, r5, r6, r7, r8}\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_poly1305_thumb2_16_loop:\n\t"
#else
    "L_poly1305_thumb2_16_loop_%=:\n\t"
#endif
        /* Add m to h */
        "LDR	%[m], [sp, #16]\n\t"
        "LDR	%[len], [%[m]]\n\t"
        "LDR	%[notLast], [%[m], #4]\n\t"
        "LDR	r9, [%[m], #8]\n\t"
        "LDR	r10, [%[m], #12]\n\t"
        "LDR	r11, [sp, #24]\n\t"
        "ADDS	r4, r4, %[len]\n\t"
        "ADCS	r5, r5, %[notLast]\n\t"
        "ADCS	r6, r6, r9\n\t"
        "ADCS	r7, r7, r10\n\t"
        "ADD	%[m], %[m], #0x10\n\t"
        "ADC	r8, r8, r11\n\t"
#ifdef WOLFSSL_ARM_ARCH_7M
        "STM	lr, {r4, r5, r6, r7, r8}\n\t"
#else
        /* h[0]-h[2] in r4-r6 for multiplication. */
        "STR	r7, [lr, #12]\n\t"
        "STR	r8, [lr, #16]\n\t"
#endif /* WOLFSSL_ARM_ARCH_7M */
        "STR	%[m], [sp, #16]\n\t"
        "LDR	%[m], [sp, #12]\n\t"
        /* Multiply h by r */
#ifdef WOLFSSL_ARM_ARCH_7M
        /* r0 = #0, r1 = r, lr = h, r2 = h[j], r3 = r[i] */
        "LDR	%[notLast], [%[m]]\n\t"
        "EOR	%[ctx], %[ctx], %[ctx]\n\t"
        /* r[0] * h[0] */
        /* h[0] in r4 */
        "UMULL	r4, r5, %[notLast], r4\n\t"
        /* r[0] * h[2] */
        /* h[2] in r6 */
        "UMULL	r6, r7, %[notLast], r6\n\t"
        /* r[0] * h[4] */
        /* h[4] in r8 */
        "MUL	r8, %[notLast], r8\n\t"
        /* r[0] * h[1] */
        "LDR	%[len], [lr, #4]\n\t"
        "MOV	r12, %[ctx]\n\t"
        "UMLAL	r5, r12, %[notLast], %[len]\n\t"
        /* r[0] * h[3] */
        "LDR	%[len], [lr, #12]\n\t"
        "ADDS	r6, r6, r12\n\t"
        "ADC	r7, r7, %[ctx]\n\t"
        "UMLAL	r7, r8, %[notLast], %[len]\n\t"
        /* r[1] * h[0] */
        "LDR	%[notLast], [%[m], #4]\n\t"
        "LDR	%[len], [lr]\n\t"
        "MOV	r12, %[ctx]\n\t"
        "UMLAL	r5, r12, %[notLast], %[len]\n\t"
        /* r[1] * h[1] */
        "LDR	%[len], [lr, #4]\n\t"
        "ADDS	r6, r6, r12\n\t"
        "ADC	r12, %[ctx], %[ctx]\n\t"
        "UMLAL	r6, r12, %[notLast], %[len]\n\t"
        /* r[1] * h[2] */
        "LDR	%[len], [lr, #8]\n\t"
        "ADDS	r7, r7, r12\n\t"
        "ADC	r12, %[ctx], %[ctx]\n\t"
        "UMLAL	r7, r12, %[notLast], %[len]\n\t"
        /* r[1] * h[3] */
        "LDR	%[len], [lr, #12]\n\t"
        "ADDS	r8, r8, r12\n\t"
        "ADC	r9, %[ctx], %[ctx]\n\t"
        "UMLAL	r8, r9, %[notLast], %[len]\n\t"
        /* r[1] * h[4] */
        "LDR	%[len], [lr, #16]\n\t"
        "MLA	r9, %[notLast], %[len], r9\n\t"
        /* r[2] * h[0] */
        "LDR	%[notLast], [%[m], #8]\n\t"
        "LDR	%[len], [lr]\n\t"
        "MOV	r12, %[ctx]\n\t"
        "UMLAL	r6, r12, %[notLast], %[len]\n\t"
        /* r[2] * h[1] */
        "LDR	%[len], [lr, #4]\n\t"
        "ADDS	r7, r7, r12\n\t"
        "ADC	r12, %[ctx], %[ctx]\n\t"
        "UMLAL	r7, r12, %[notLast], %[len]\n\t"
        /* r[2] * h[2] */
        "LDR	%[len], [lr, #8]\n\t"
        "ADDS	r8, r8, r12\n\t"
        "ADC	r12, %[ctx], %[ctx]\n\t"
        "UMLAL	r8, r12, %[notLast], %[len]\n\t"
        /* r[2] * h[3] */
        "LDR	%[len], [lr, #12]\n\t"
        "ADDS	r9, r9, r12\n\t"
        "ADC	r10, %[ctx], %[ctx]\n\t"
        "UMLAL	r9, r10, %[notLast], %[len]\n\t"
        /* r[2] * h[4] */
        "LDR	%[len], [lr, #16]\n\t"
        "MLA	r10, %[notLast], %[len], r10\n\t"
        /* r[3] * h[0] */
        "LDR	%[notLast], [%[m], #12]\n\t"
        "LDR	%[len], [lr]\n\t"
        "MOV	r12, %[ctx]\n\t"
        "UMLAL	r7, r12, %[notLast], %[len]\n\t"
        /* r[3] * h[1] */
        "LDR	%[len], [lr, #4]\n\t"
        "ADDS	r8, r8, r12\n\t"
        "ADC	r12, %[ctx], %[ctx]\n\t"
        "UMLAL	r8, r12, %[notLast], %[len]\n\t"
        /* r[3] * h[2] */
        "LDR	%[len], [lr, #8]\n\t"
        "ADDS	r9, r9, r12\n\t"
        "ADC	r10, r10, %[ctx]\n\t"
        "UMLAL	r9, r10, %[notLast], %[len]\n\t"
        /* r[3] * h[3] */
        "LDR	%[len], [lr, #12]\n\t"
        "MOV	r11, %[ctx]\n\t"
        "UMLAL	r10, r11, %[notLast], %[len]\n\t"
        /* r[3] * h[4] */
        "LDR	%[len], [lr, #16]\n\t"
        "MOV	r12, %[ctx]\n\t"
        "MLA	r11, %[notLast], %[len], r11\n\t"
#else
        "LDM	%[m], {%[ctx], %[m], %[len], %[notLast]}\n\t"
        /* r[0] * h[0] */
        "UMULL	r10, r11, %[ctx], r4\n\t"
        /* r[1] * h[0] */
        "UMULL	r12, r7, %[m], r4\n\t"
        /* r[0] * h[1] */
        "UMAAL	r11, r12, %[ctx], r5\n\t"
        /* r[2] * h[0] */
        "UMULL	r8, r9, %[len], r4\n\t"
        /* r[1] * h[1] */
        "UMAAL	r12, r8, %[m], r5\n\t"
        /* r[0] * h[2] */
        "UMAAL	r12, r7, %[ctx], r6\n\t"
        /* r[3] * h[0] */
        "UMAAL	r8, r9, %[notLast], r4\n\t"
        "STM	sp, {r10, r11, r12}\n\t"
        /* r[2] * h[1] */
        "UMAAL	r7, r8, %[len], r5\n\t"
        /* Replace h[0] with h[3] */
        "LDR	r4, [lr, #12]\n\t"
        /* r[1] * h[2] */
        "UMULL	r10, r11, %[m], r6\n\t"
        /* r[2] * h[2] */
        "UMAAL	r8, r9, %[len], r6\n\t"
        /* r[0] * h[3] */
        "UMAAL	r7, r10, %[ctx], r4\n\t"
        /* r[3] * h[1] */
        "UMAAL	r8, r11, %[notLast], r5\n\t"
        /* r[1] * h[3] */
        "UMAAL	r8, r10, %[m], r4\n\t"
        /* r[3] * h[2] */
        "UMAAL	r9, r11, %[notLast], r6\n\t"
        /* r[2] * h[3] */
        "UMAAL	r9, r10, %[len], r4\n\t"
        /* Replace h[1] with h[4] */
        "LDR	r5, [lr, #16]\n\t"
        /* r[3] * h[3] */
        "UMAAL	r10, r11, %[notLast], r4\n\t"
        "MOV	r12, #0x0\n\t"
        /* r[0] * h[4] */
        "UMAAL	r8, r12, %[ctx], r5\n\t"
        /* r[1] * h[4] */
        "UMAAL	r9, r12, %[m], r5\n\t"
        /* r[2] * h[4] */
        "UMAAL	r10, r12, %[len], r5\n\t"
        /* r[3] * h[4] */
        "UMAAL	r11, r12, %[notLast], r5\n\t"
        /* DONE */
        "LDM	sp, {r4, r5, r6}\n\t"
#endif /* WOLFSSL_ARM_ARCH_7M */
        /* r12 will be zero because r is masked. */
        /* Load length */
        "LDR	%[len], [sp, #20]\n\t"
        /* Reduce mod 2^130 - 5 */
        "BIC	%[notLast], r8, #0x3\n\t"
        "AND	r8, r8, #0x3\n\t"
        "ADDS	r4, r4, %[notLast]\n\t"
        "LSR	%[notLast], %[notLast], #2\n\t"
        "ADCS	r5, r5, r9\n\t"
        "ORR	%[notLast], %[notLast], r9, LSL #30\n\t"
        "ADCS	r6, r6, r10\n\t"
        "LSR	r9, r9, #2\n\t"
        "ADCS	r7, r7, r11\n\t"
        "ORR	r9, r9, r10, LSL #30\n\t"
        "ADC	r8, r8, r12\n\t"
        "LSR	r10, r10, #2\n\t"
        "ADDS	r4, r4, %[notLast]\n\t"
        "ORR	r10, r10, r11, LSL #30\n\t"
        "ADCS	r5, r5, r9\n\t"
        "LSR	r11, r11, #2\n\t"
        "ADCS	r6, r6, r10\n\t"
        "ADCS	r7, r7, r11\n\t"
        "ADC	r8, r8, r12\n\t"
        /* Sub 16 from length. */
        "SUBS	%[len], %[len], #0x10\n\t"
        /* Store length. */
        "STR	%[len], [sp, #20]\n\t"
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
        "ADD	sp, sp, #0x1c\n\t"
        : [ctx] "+r" (ctx), [m] "+r" (m), [len] "+r" (len), [notLast] "+r" (notLast)
        :
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr", "cc"
    );
}

XALIGNED(16) static const word32 L_poly1305_thumb2_clamp[] = {
    0x0fffffff, 0x0ffffffc, 0x0ffffffc, 0x0ffffffc,
};

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void poly1305_set_key(Poly1305* ctx_p, const byte* key_p)
#else
void poly1305_set_key(Poly1305* ctx, const byte* key)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register Poly1305* ctx __asm__ ("r0") = (Poly1305*)ctx_p;
    register const byte* key __asm__ ("r1") = (const byte*)key_p;
    register word32* L_poly1305_thumb2_clamp_c __asm__ ("r2") = (word32*)&L_poly1305_thumb2_clamp;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        /* Load mask. */
        "MOV	r10, %[L_poly1305_thumb2_clamp]\n\t"
        "LDM	r10, {r6, r7, r8, r9}\n\t"
        /* Load and cache padding. */
        "LDR	r2, [%[key], #16]\n\t"
        "LDR	r3, [%[key], #20]\n\t"
        "LDR	r4, [%[key], #24]\n\t"
        "LDR	r5, [%[key], #28]\n\t"
        "ADD	r10, %[ctx], #0x24\n\t"
        "STM	r10, {r2, r3, r4, r5}\n\t"
        /* Load, mask and store r. */
        "LDR	r2, [%[key]]\n\t"
        "LDR	r3, [%[key], #4]\n\t"
        "LDR	r4, [%[key], #8]\n\t"
        "LDR	r5, [%[key], #12]\n\t"
        "AND	r2, r2, r6\n\t"
        "AND	r3, r3, r7\n\t"
        "AND	r4, r4, r8\n\t"
        "AND	r5, r5, r9\n\t"
        "ADD	r10, %[ctx], #0x0\n\t"
        "STM	r10, {r2, r3, r4, r5}\n\t"
        /* h (accumulator) = 0 */
        "EOR	r6, r6, r6\n\t"
        "EOR	r7, r7, r7\n\t"
        "EOR	r8, r8, r8\n\t"
        "EOR	r9, r9, r9\n\t"
        "ADD	r10, %[ctx], #0x10\n\t"
        "EOR	r5, r5, r5\n\t"
        "STM	r10, {r5, r6, r7, r8, r9}\n\t"
        /* Zero leftover */
        "STR	r5, [%[ctx], #52]\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [ctx] "+r" (ctx), [key] "+r" (key),
          [L_poly1305_thumb2_clamp] "+r" (L_poly1305_thumb2_clamp_c)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "cc"
#else
        : [ctx] "+r" (ctx), [key] "+r" (key)
        : [L_poly1305_thumb2_clamp] "r" (L_poly1305_thumb2_clamp)
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "cc"
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
    );
}

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void poly1305_final(Poly1305* ctx_p, byte* mac_p)
#else
void poly1305_final(Poly1305* ctx, byte* mac)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register Poly1305* ctx __asm__ ("r0") = (Poly1305*)ctx_p;
    register byte* mac __asm__ ("r1") = (byte*)mac_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "ADD	r11, %[ctx], #0x10\n\t"
        "LDM	r11, {r2, r3, r4, r5, r6}\n\t"
        /* Add 5 and check for h larger than p. */
        "ADDS	r7, r2, #0x5\n\t"
        "ADCS	r7, r3, #0x0\n\t"
        "ADCS	r7, r4, #0x0\n\t"
        "ADCS	r7, r5, #0x0\n\t"
        "ADC	r7, r6, #0x0\n\t"
        "SUB	r7, r7, #0x4\n\t"
        "LSR	r7, r7, #31\n\t"
        "SUB	r7, r7, #0x1\n\t"
        "AND	r7, r7, #0x5\n\t"
        /* Add 0/5 to h. */
        "ADDS	r2, r2, r7\n\t"
        "ADCS	r3, r3, #0x0\n\t"
        "ADCS	r4, r4, #0x0\n\t"
        "ADC	r5, r5, #0x0\n\t"
        /* Add padding */
        "ADD	r11, %[ctx], #0x24\n\t"
        "LDM	r11, {r7, r8, r9, r10}\n\t"
        "ADDS	r2, r2, r7\n\t"
        "ADCS	r3, r3, r8\n\t"
        "ADCS	r4, r4, r9\n\t"
        "ADC	r5, r5, r10\n\t"
        /* Store MAC */
        "STR	r2, [%[mac]]\n\t"
        "STR	r3, [%[mac], #4]\n\t"
        "STR	r4, [%[mac], #8]\n\t"
        "STR	r5, [%[mac], #12]\n\t"
        /* Zero out h. */
        "EOR	r2, r2, r2\n\t"
        "EOR	r3, r3, r3\n\t"
        "EOR	r4, r4, r4\n\t"
        "EOR	r5, r5, r5\n\t"
        "EOR	r6, r6, r6\n\t"
        "ADD	r11, %[ctx], #0x10\n\t"
        "STM	r11, {r2, r3, r4, r5, r6}\n\t"
        /* Zero out r. */
        "ADD	r11, %[ctx], #0x0\n\t"
        "STM	r11, {r2, r3, r4, r5}\n\t"
        /* Zero out padding. */
        "ADD	r11, %[ctx], #0x24\n\t"
        "STM	r11, {r2, r3, r4, r5}\n\t"
        : [ctx] "+r" (ctx), [mac] "+r" (mac)
        :
        : "memory", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "cc"
    );
}

#endif /* HAVE_POLY1305 */
#endif /* WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */
#endif /* WOLFSSL_ARMASM_INLINE */
