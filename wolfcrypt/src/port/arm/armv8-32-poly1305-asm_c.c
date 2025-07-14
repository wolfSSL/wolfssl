/* armv8-32-poly1305-asm
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

/* Generated using (from wolfssl):
 *   cd ../scripts
 *   ruby ./poly1305/poly1305.rb arm32 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-32-poly1305-asm.c
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef WOLFSSL_ARMASM
#if !defined(__aarch64__) && !defined(WOLFSSL_ARMASM_THUMB2)
#include <stdint.h>
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>
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

#ifdef WOLFSSL_ARMASM_NO_NEON
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void poly1305_arm32_blocks_16(Poly1305* ctx_p,
    const byte* m_p, word32 len_p, int notLast_p)
#else
WC_OMIT_FRAME_POINTER void poly1305_arm32_blocks_16(Poly1305* ctx,
    const byte* m, word32 len, int notLast)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register Poly1305* ctx asm ("r0") = (Poly1305*)ctx_p;
    register const byte* m asm ("r1") = (const byte*)m_p;
    register word32 len asm ("r2") = (word32)len_p;
    register int notLast asm ("r3") = (int)notLast_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "sub	sp, sp, #28\n\t"
        "cmp	%[len], #0\n\t"
        "beq	L_poly1305_arm32_16_done_%=\n\t"
        "add	lr, sp, #12\n\t"
        "stm	lr, {r0, r1, r2, r3}\n\t"
        /* Get h pointer */
        "add	lr, %[ctx], #16\n\t"
        "ldm	lr, {r4, r5, r6, r7, r8}\n\t"
        "\n"
    "L_poly1305_arm32_16_loop_%=: \n\t"
        /* Add m to h */
        "ldr	%[m], [sp, #16]\n\t"
        "ldr	%[len], [%[m]]\n\t"
        "ldr	%[notLast], [%[m], #4]\n\t"
        "ldr	r9, [%[m], #8]\n\t"
        "ldr	r10, [%[m], #12]\n\t"
        "ldr	r11, [sp, #24]\n\t"
        "adds	r4, r4, %[len]\n\t"
        "adcs	r5, r5, %[notLast]\n\t"
        "adcs	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "add	%[m], %[m], #16\n\t"
        "adc	r8, r8, r11\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
        "stm	lr, {r4, r5, r6, r7, r8}\n\t"
#else
        /* h[0]-h[2] in r4-r6 for multiplication. */
        "str	r7, [lr, #12]\n\t"
        "str	r8, [lr, #16]\n\t"
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
        "str	%[m], [sp, #16]\n\t"
        "ldr	%[m], [sp, #12]\n\t"
        /* Multiply h by r */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
        /* r0 = #0, r1 = r, lr = h, r2 = h[j], r3 = r[i] */
        "ldr	%[notLast], [%[m]]\n\t"
        "eor	%[ctx], %[ctx], %[ctx]\n\t"
        /* r[0] * h[0] */
        /* h[0] in r4 */
        "umull	r4, r5, %[notLast], r4\n\t"
        /* r[0] * h[2] */
        /* h[2] in r6 */
        "umull	r6, r7, %[notLast], r6\n\t"
        /* r[0] * h[4] */
        /* h[4] in r8 */
        "mul	r8, %[notLast], r8\n\t"
        /* r[0] * h[1] */
        "ldr	%[len], [lr, #4]\n\t"
        "mov	r12, %[ctx]\n\t"
        "umlal	r5, r12, %[notLast], %[len]\n\t"
        /* r[0] * h[3] */
        "ldr	%[len], [lr, #12]\n\t"
        "adds	r6, r6, r12\n\t"
        "adc	r7, r7, %[ctx]\n\t"
        "umlal	r7, r8, %[notLast], %[len]\n\t"
        /* r[1] * h[0] */
        "ldr	%[notLast], [%[m], #4]\n\t"
        "ldr	%[len], [lr]\n\t"
        "mov	r12, %[ctx]\n\t"
        "umlal	r5, r12, %[notLast], %[len]\n\t"
        /* r[1] * h[1] */
        "ldr	%[len], [lr, #4]\n\t"
        "adds	r6, r6, r12\n\t"
        "adc	r12, %[ctx], %[ctx]\n\t"
        "umlal	r6, r12, %[notLast], %[len]\n\t"
        /* r[1] * h[2] */
        "ldr	%[len], [lr, #8]\n\t"
        "adds	r7, r7, r12\n\t"
        "adc	r12, %[ctx], %[ctx]\n\t"
        "umlal	r7, r12, %[notLast], %[len]\n\t"
        /* r[1] * h[3] */
        "ldr	%[len], [lr, #12]\n\t"
        "adds	r8, r8, r12\n\t"
        "adc	r9, %[ctx], %[ctx]\n\t"
        "umlal	r8, r9, %[notLast], %[len]\n\t"
        /* r[1] * h[4] */
        "ldr	%[len], [lr, #16]\n\t"
        "mla	r9, %[notLast], %[len], r9\n\t"
        /* r[2] * h[0] */
        "ldr	%[notLast], [%[m], #8]\n\t"
        "ldr	%[len], [lr]\n\t"
        "mov	r12, %[ctx]\n\t"
        "umlal	r6, r12, %[notLast], %[len]\n\t"
        /* r[2] * h[1] */
        "ldr	%[len], [lr, #4]\n\t"
        "adds	r7, r7, r12\n\t"
        "adc	r12, %[ctx], %[ctx]\n\t"
        "umlal	r7, r12, %[notLast], %[len]\n\t"
        /* r[2] * h[2] */
        "ldr	%[len], [lr, #8]\n\t"
        "adds	r8, r8, r12\n\t"
        "adc	r12, %[ctx], %[ctx]\n\t"
        "umlal	r8, r12, %[notLast], %[len]\n\t"
        /* r[2] * h[3] */
        "ldr	%[len], [lr, #12]\n\t"
        "adds	r9, r9, r12\n\t"
        "adc	r10, %[ctx], %[ctx]\n\t"
        "umlal	r9, r10, %[notLast], %[len]\n\t"
        /* r[2] * h[4] */
        "ldr	%[len], [lr, #16]\n\t"
        "mla	r10, %[notLast], %[len], r10\n\t"
        /* r[3] * h[0] */
        "ldr	%[notLast], [%[m], #12]\n\t"
        "ldr	%[len], [lr]\n\t"
        "mov	r12, %[ctx]\n\t"
        "umlal	r7, r12, %[notLast], %[len]\n\t"
        /* r[3] * h[1] */
        "ldr	%[len], [lr, #4]\n\t"
        "adds	r8, r8, r12\n\t"
        "adc	r12, %[ctx], %[ctx]\n\t"
        "umlal	r8, r12, %[notLast], %[len]\n\t"
        /* r[3] * h[2] */
        "ldr	%[len], [lr, #8]\n\t"
        "adds	r9, r9, r12\n\t"
        "adc	r10, r10, %[ctx]\n\t"
        "umlal	r9, r10, %[notLast], %[len]\n\t"
        /* r[3] * h[3] */
        "ldr	%[len], [lr, #12]\n\t"
        "mov	r11, %[ctx]\n\t"
        "umlal	r10, r11, %[notLast], %[len]\n\t"
        /* r[3] * h[4] */
        "ldr	%[len], [lr, #16]\n\t"
        "mov	r12, %[ctx]\n\t"
        "mla	r11, %[notLast], %[len], r11\n\t"
#else
        "ldm	%[m], {r0, r1, r2, r3}\n\t"
        /* r[0] * h[0] */
        "umull	r10, r11, %[ctx], r4\n\t"
        /* r[1] * h[0] */
        "umull	r12, r7, %[m], r4\n\t"
        /* r[0] * h[1] */
        "umaal	r11, r12, %[ctx], r5\n\t"
        /* r[2] * h[0] */
        "umull	r8, r9, %[len], r4\n\t"
        /* r[1] * h[1] */
        "umaal	r12, r8, %[m], r5\n\t"
        /* r[0] * h[2] */
        "umaal	r12, r7, %[ctx], r6\n\t"
        /* r[3] * h[0] */
        "umaal	r8, r9, %[notLast], r4\n\t"
        "stm	sp, {r10, r11, r12}\n\t"
        /* r[2] * h[1] */
        "umaal	r7, r8, %[len], r5\n\t"
        /* Replace h[0] with h[3] */
        "ldr	r4, [lr, #12]\n\t"
        /* r[1] * h[2] */
        "umull	r10, r11, %[m], r6\n\t"
        /* r[2] * h[2] */
        "umaal	r8, r9, %[len], r6\n\t"
        /* r[0] * h[3] */
        "umaal	r7, r10, %[ctx], r4\n\t"
        /* r[3] * h[1] */
        "umaal	r8, r11, %[notLast], r5\n\t"
        /* r[1] * h[3] */
        "umaal	r8, r10, %[m], r4\n\t"
        /* r[3] * h[2] */
        "umaal	r9, r11, %[notLast], r6\n\t"
        /* r[2] * h[3] */
        "umaal	r9, r10, %[len], r4\n\t"
        /* Replace h[1] with h[4] */
        "ldr	r5, [lr, #16]\n\t"
        /* r[3] * h[3] */
        "umaal	r10, r11, %[notLast], r4\n\t"
        "mov	r12, #0\n\t"
        /* r[0] * h[4] */
        "umaal	r8, r12, %[ctx], r5\n\t"
        /* r[1] * h[4] */
        "umaal	r9, r12, %[m], r5\n\t"
        /* r[2] * h[4] */
        "umaal	r10, r12, %[len], r5\n\t"
        /* r[3] * h[4] */
        "umaal	r11, r12, %[notLast], r5\n\t"
        /* DONE */
        "ldm	sp, {r4, r5, r6}\n\t"
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
        /* r12 will be zero because r is masked. */
        /* Load length */
        "ldr	%[len], [sp, #20]\n\t"
        /* Reduce mod 2^130 - 5 */
        "bic	%[notLast], r8, #0x3\n\t"
        "and	r8, r8, #3\n\t"
        "adds	r4, r4, %[notLast]\n\t"
        "lsr	%[notLast], %[notLast], #2\n\t"
        "adcs	r5, r5, r9\n\t"
        "orr	%[notLast], %[notLast], r9, LSL #30\n\t"
        "adcs	r6, r6, r10\n\t"
        "lsr	r9, r9, #2\n\t"
        "adcs	r7, r7, r11\n\t"
        "orr	r9, r9, r10, LSL #30\n\t"
        "adc	r8, r8, r12\n\t"
        "lsr	r10, r10, #2\n\t"
        "adds	r4, r4, %[notLast]\n\t"
        "orr	r10, r10, r11, LSL #30\n\t"
        "adcs	r5, r5, r9\n\t"
        "lsr	r11, r11, #2\n\t"
        "adcs	r6, r6, r10\n\t"
        "adcs	r7, r7, r11\n\t"
        "adc	r8, r8, r12\n\t"
        /* Sub 16 from length. */
        "subs	%[len], %[len], #16\n\t"
        /* Store length. */
        "str	%[len], [sp, #20]\n\t"
        /* Loop again if more message to do. */
        "bgt	L_poly1305_arm32_16_loop_%=\n\t"
        "stm	lr, {r4, r5, r6, r7, r8}\n\t"
        "\n"
    "L_poly1305_arm32_16_done_%=: \n\t"
        "add	sp, sp, #28\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [ctx] "+r" (ctx), [m] "+r" (m), [len] "+r" (len),
          [notLast] "+r" (notLast)
        :
#else
        :
        : [ctx] "r" (ctx), [m] "r" (m), [len] "r" (len),
          [notLast] "r" (notLast)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9",
            "r10", "r11"
    );
}

static const word32 L_poly1305_arm32_clamp[] = {
    0x0fffffff, 0x0ffffffc, 0x0ffffffc, 0x0ffffffc,
};

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void poly1305_set_key(Poly1305* ctx_p, const byte* key_p)
#else
WC_OMIT_FRAME_POINTER void poly1305_set_key(Poly1305* ctx, const byte* key)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register Poly1305* ctx asm ("r0") = (Poly1305*)ctx_p;
    register const byte* key asm ("r1") = (const byte*)key_p;
    register word32* L_poly1305_arm32_clamp_c asm ("r2") =
        (word32*)&L_poly1305_arm32_clamp;
#else
    register word32* L_poly1305_arm32_clamp_c =
        (word32*)&L_poly1305_arm32_clamp;

#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        /* Load mask. */
        "mov	lr, %[L_poly1305_arm32_clamp]\n\t"
        "ldm	lr, {r6, r7, r8, r12}\n\t"
        /* Load and cache padding. */
        "ldr	r2, [%[key], #16]\n\t"
        "ldr	r3, [%[key], #20]\n\t"
        "ldr	r4, [%[key], #24]\n\t"
        "ldr	r5, [%[key], #28]\n\t"
        "add	lr, %[ctx], #36\n\t"
        "stm	lr, {r2, r3, r4, r5}\n\t"
        /* Load, mask and store r. */
        "ldr	r2, [%[key]]\n\t"
        "ldr	r3, [%[key], #4]\n\t"
        "ldr	r4, [%[key], #8]\n\t"
        "ldr	r5, [%[key], #12]\n\t"
        "and	r2, r2, r6\n\t"
        "and	r3, r3, r7\n\t"
        "and	r4, r4, r8\n\t"
        "and	r5, r5, r12\n\t"
        "add	lr, %[ctx], #0\n\t"
        "stm	lr, {r2, r3, r4, r5}\n\t"
        /* h (accumulator) = 0 */
        "eor	r6, r6, r6\n\t"
        "eor	r7, r7, r7\n\t"
        "eor	r8, r8, r8\n\t"
        "eor	r12, r12, r12\n\t"
        "add	lr, %[ctx], #16\n\t"
        "eor	r5, r5, r5\n\t"
        "stm	lr, {r5, r6, r7, r8, r12}\n\t"
        /* Zero leftover */
        "str	r5, [%[ctx], #52]\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [ctx] "+r" (ctx), [key] "+r" (key),
          [L_poly1305_arm32_clamp] "+r" (L_poly1305_arm32_clamp_c)
        :
#else
        :
        : [ctx] "r" (ctx), [key] "r" (key),
          [L_poly1305_arm32_clamp] "r" (L_poly1305_arm32_clamp_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8"
    );
}

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void poly1305_final(Poly1305* ctx_p, byte* mac_p)
#else
WC_OMIT_FRAME_POINTER void poly1305_final(Poly1305* ctx, byte* mac)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register Poly1305* ctx asm ("r0") = (Poly1305*)ctx_p;
    register byte* mac asm ("r1") = (byte*)mac_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "add	r9, %[ctx], #16\n\t"
        "ldm	r9, {r4, r5, r6, r7, r8}\n\t"
        /* Add 5 and check for h larger than p. */
        "adds	r2, r4, #5\n\t"
        "adcs	r2, r5, #0\n\t"
        "adcs	r2, r6, #0\n\t"
        "adcs	r2, r7, #0\n\t"
        "adc	r2, r8, #0\n\t"
        "sub	r2, r2, #4\n\t"
        "lsr	r2, r2, #31\n\t"
        "sub	r2, r2, #1\n\t"
        "and	r2, r2, #5\n\t"
        /* Add 0/5 to h. */
        "adds	r4, r4, r2\n\t"
        "adcs	r5, r5, #0\n\t"
        "adcs	r6, r6, #0\n\t"
        "adc	r7, r7, #0\n\t"
        /* Add padding */
        "add	r9, %[ctx], #36\n\t"
        "ldm	r9, {r2, r3, r12, lr}\n\t"
        "adds	r4, r4, r2\n\t"
        "adcs	r5, r5, r3\n\t"
        "adcs	r6, r6, r12\n\t"
        "adc	r7, r7, lr\n\t"
        /* Store MAC */
        "str	r4, [%[mac]]\n\t"
        "str	r5, [%[mac], #4]\n\t"
        "str	r6, [%[mac], #8]\n\t"
        "str	r7, [%[mac], #12]\n\t"
        /* Zero out h. */
        "eor	r4, r4, r4\n\t"
        "eor	r5, r5, r5\n\t"
        "eor	r6, r6, r6\n\t"
        "eor	r7, r7, r7\n\t"
        "eor	r8, r8, r8\n\t"
        "add	r9, %[ctx], #16\n\t"
        "stm	r9, {r4, r5, r6, r7, r8}\n\t"
        /* Zero out r. */
        "add	r9, %[ctx], #0\n\t"
        "stm	r9, {r4, r5, r6, r7}\n\t"
        /* Zero out padding. */
        "add	r9, %[ctx], #36\n\t"
        "stm	r9, {r4, r5, r6, r7}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [ctx] "+r" (ctx), [mac] "+r" (mac)
        :
#else
        :
        : [ctx] "r" (ctx), [mac] "r" (mac)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r2", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8",
            "r9"
    );
}

#else
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void poly1305_arm32_blocks_16(Poly1305* ctx_p,
    const byte* m_p, word32 len_p, int notLast_p)
#else
WC_OMIT_FRAME_POINTER void poly1305_arm32_blocks_16(Poly1305* ctx,
    const byte* m, word32 len, int notLast)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register Poly1305* ctx asm ("r0") = (Poly1305*)ctx_p;
    register const byte* m asm ("r1") = (const byte*)m_p;
    register word32 len asm ("r2") = (word32)len_p;
    register int notLast asm ("r3") = (int)notLast_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "sub	sp, sp, #28\n\t"
        "cmp	%[len], #0\n\t"
        "beq	L_poly1305_arm32_16_done_%=\n\t"
        "add	lr, sp, #12\n\t"
        "stm	lr, {r0, r1, r2, r3}\n\t"
        /* Get h pointer */
        "add	lr, %[ctx], #16\n\t"
        "ldm	lr, {r4, r5, r6, r7, r8}\n\t"
        "\n"
    "L_poly1305_arm32_16_loop_%=: \n\t"
        /* Add m to h */
        "ldr	%[m], [sp, #16]\n\t"
        "ldr	%[len], [%[m]]\n\t"
        "ldr	%[notLast], [%[m], #4]\n\t"
        "ldr	r9, [%[m], #8]\n\t"
        "ldr	r10, [%[m], #12]\n\t"
        "ldr	r11, [sp, #24]\n\t"
        "adds	r4, r4, %[len]\n\t"
        "adcs	r5, r5, %[notLast]\n\t"
        "adcs	r6, r6, r9\n\t"
        "adcs	r7, r7, r10\n\t"
        "add	%[m], %[m], #16\n\t"
        "adc	r8, r8, r11\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
        "stm	lr, {r4, r5, r6, r7, r8}\n\t"
#else
        /* h[0]-h[2] in r4-r6 for multiplication. */
        "str	r7, [lr, #12]\n\t"
        "str	r8, [lr, #16]\n\t"
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
        "str	%[m], [sp, #16]\n\t"
        "ldr	%[m], [sp, #12]\n\t"
        /* Multiply h by r */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
        /* r0 = #0, r1 = r, lr = h, r2 = h[j], r3 = r[i] */
        "ldr	%[notLast], [%[m]]\n\t"
        "eor	%[ctx], %[ctx], %[ctx]\n\t"
        /* r[0] * h[0] */
        /* h[0] in r4 */
        "umull	r4, r5, %[notLast], r4\n\t"
        /* r[0] * h[2] */
        /* h[2] in r6 */
        "umull	r6, r7, %[notLast], r6\n\t"
        /* r[0] * h[4] */
        /* h[4] in r8 */
        "mul	r8, %[notLast], r8\n\t"
        /* r[0] * h[1] */
        "ldr	%[len], [lr, #4]\n\t"
        "mov	r12, %[ctx]\n\t"
        "umlal	r5, r12, %[notLast], %[len]\n\t"
        /* r[0] * h[3] */
        "ldr	%[len], [lr, #12]\n\t"
        "adds	r6, r6, r12\n\t"
        "adc	r7, r7, %[ctx]\n\t"
        "umlal	r7, r8, %[notLast], %[len]\n\t"
        /* r[1] * h[0] */
        "ldr	%[notLast], [%[m], #4]\n\t"
        "ldr	%[len], [lr]\n\t"
        "mov	r12, %[ctx]\n\t"
        "umlal	r5, r12, %[notLast], %[len]\n\t"
        /* r[1] * h[1] */
        "ldr	%[len], [lr, #4]\n\t"
        "adds	r6, r6, r12\n\t"
        "adc	r12, %[ctx], %[ctx]\n\t"
        "umlal	r6, r12, %[notLast], %[len]\n\t"
        /* r[1] * h[2] */
        "ldr	%[len], [lr, #8]\n\t"
        "adds	r7, r7, r12\n\t"
        "adc	r12, %[ctx], %[ctx]\n\t"
        "umlal	r7, r12, %[notLast], %[len]\n\t"
        /* r[1] * h[3] */
        "ldr	%[len], [lr, #12]\n\t"
        "adds	r8, r8, r12\n\t"
        "adc	r9, %[ctx], %[ctx]\n\t"
        "umlal	r8, r9, %[notLast], %[len]\n\t"
        /* r[1] * h[4] */
        "ldr	%[len], [lr, #16]\n\t"
        "mla	r9, %[notLast], %[len], r9\n\t"
        /* r[2] * h[0] */
        "ldr	%[notLast], [%[m], #8]\n\t"
        "ldr	%[len], [lr]\n\t"
        "mov	r12, %[ctx]\n\t"
        "umlal	r6, r12, %[notLast], %[len]\n\t"
        /* r[2] * h[1] */
        "ldr	%[len], [lr, #4]\n\t"
        "adds	r7, r7, r12\n\t"
        "adc	r12, %[ctx], %[ctx]\n\t"
        "umlal	r7, r12, %[notLast], %[len]\n\t"
        /* r[2] * h[2] */
        "ldr	%[len], [lr, #8]\n\t"
        "adds	r8, r8, r12\n\t"
        "adc	r12, %[ctx], %[ctx]\n\t"
        "umlal	r8, r12, %[notLast], %[len]\n\t"
        /* r[2] * h[3] */
        "ldr	%[len], [lr, #12]\n\t"
        "adds	r9, r9, r12\n\t"
        "adc	r10, %[ctx], %[ctx]\n\t"
        "umlal	r9, r10, %[notLast], %[len]\n\t"
        /* r[2] * h[4] */
        "ldr	%[len], [lr, #16]\n\t"
        "mla	r10, %[notLast], %[len], r10\n\t"
        /* r[3] * h[0] */
        "ldr	%[notLast], [%[m], #12]\n\t"
        "ldr	%[len], [lr]\n\t"
        "mov	r12, %[ctx]\n\t"
        "umlal	r7, r12, %[notLast], %[len]\n\t"
        /* r[3] * h[1] */
        "ldr	%[len], [lr, #4]\n\t"
        "adds	r8, r8, r12\n\t"
        "adc	r12, %[ctx], %[ctx]\n\t"
        "umlal	r8, r12, %[notLast], %[len]\n\t"
        /* r[3] * h[2] */
        "ldr	%[len], [lr, #8]\n\t"
        "adds	r9, r9, r12\n\t"
        "adc	r10, r10, %[ctx]\n\t"
        "umlal	r9, r10, %[notLast], %[len]\n\t"
        /* r[3] * h[3] */
        "ldr	%[len], [lr, #12]\n\t"
        "mov	r11, %[ctx]\n\t"
        "umlal	r10, r11, %[notLast], %[len]\n\t"
        /* r[3] * h[4] */
        "ldr	%[len], [lr, #16]\n\t"
        "mov	r12, %[ctx]\n\t"
        "mla	r11, %[notLast], %[len], r11\n\t"
#else
        "ldm	%[m], {r0, r1, r2, r3}\n\t"
        /* r[0] * h[0] */
        "umull	r10, r11, %[ctx], r4\n\t"
        /* r[1] * h[0] */
        "umull	r12, r7, %[m], r4\n\t"
        /* r[0] * h[1] */
        "umaal	r11, r12, %[ctx], r5\n\t"
        /* r[2] * h[0] */
        "umull	r8, r9, %[len], r4\n\t"
        /* r[1] * h[1] */
        "umaal	r12, r8, %[m], r5\n\t"
        /* r[0] * h[2] */
        "umaal	r12, r7, %[ctx], r6\n\t"
        /* r[3] * h[0] */
        "umaal	r8, r9, %[notLast], r4\n\t"
        "stm	sp, {r10, r11, r12}\n\t"
        /* r[2] * h[1] */
        "umaal	r7, r8, %[len], r5\n\t"
        /* Replace h[0] with h[3] */
        "ldr	r4, [lr, #12]\n\t"
        /* r[1] * h[2] */
        "umull	r10, r11, %[m], r6\n\t"
        /* r[2] * h[2] */
        "umaal	r8, r9, %[len], r6\n\t"
        /* r[0] * h[3] */
        "umaal	r7, r10, %[ctx], r4\n\t"
        /* r[3] * h[1] */
        "umaal	r8, r11, %[notLast], r5\n\t"
        /* r[1] * h[3] */
        "umaal	r8, r10, %[m], r4\n\t"
        /* r[3] * h[2] */
        "umaal	r9, r11, %[notLast], r6\n\t"
        /* r[2] * h[3] */
        "umaal	r9, r10, %[len], r4\n\t"
        /* Replace h[1] with h[4] */
        "ldr	r5, [lr, #16]\n\t"
        /* r[3] * h[3] */
        "umaal	r10, r11, %[notLast], r4\n\t"
        "mov	r12, #0\n\t"
        /* r[0] * h[4] */
        "umaal	r8, r12, %[ctx], r5\n\t"
        /* r[1] * h[4] */
        "umaal	r9, r12, %[m], r5\n\t"
        /* r[2] * h[4] */
        "umaal	r10, r12, %[len], r5\n\t"
        /* r[3] * h[4] */
        "umaal	r11, r12, %[notLast], r5\n\t"
        /* DONE */
        "ldm	sp, {r4, r5, r6}\n\t"
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
        /* r12 will be zero because r is masked. */
        /* Load length */
        "ldr	%[len], [sp, #20]\n\t"
        /* Reduce mod 2^130 - 5 */
        "bic	%[notLast], r8, #0x3\n\t"
        "and	r8, r8, #3\n\t"
        "adds	r4, r4, %[notLast]\n\t"
        "lsr	%[notLast], %[notLast], #2\n\t"
        "adcs	r5, r5, r9\n\t"
        "orr	%[notLast], %[notLast], r9, LSL #30\n\t"
        "adcs	r6, r6, r10\n\t"
        "lsr	r9, r9, #2\n\t"
        "adcs	r7, r7, r11\n\t"
        "orr	r9, r9, r10, LSL #30\n\t"
        "adc	r8, r8, r12\n\t"
        "lsr	r10, r10, #2\n\t"
        "adds	r4, r4, %[notLast]\n\t"
        "orr	r10, r10, r11, LSL #30\n\t"
        "adcs	r5, r5, r9\n\t"
        "lsr	r11, r11, #2\n\t"
        "adcs	r6, r6, r10\n\t"
        "adcs	r7, r7, r11\n\t"
        "adc	r8, r8, r12\n\t"
        /* Sub 16 from length. */
        "subs	%[len], %[len], #16\n\t"
        /* Store length. */
        "str	%[len], [sp, #20]\n\t"
        /* Loop again if more message to do. */
        "bgt	L_poly1305_arm32_16_loop_%=\n\t"
        "stm	lr, {r4, r5, r6, r7, r8}\n\t"
        "\n"
    "L_poly1305_arm32_16_done_%=: \n\t"
        "add	sp, sp, #28\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [ctx] "+r" (ctx), [m] "+r" (m), [len] "+r" (len),
          [notLast] "+r" (notLast)
        :
#else
        :
        : [ctx] "r" (ctx), [m] "r" (m), [len] "r" (len),
          [notLast] "r" (notLast)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9",
            "r10", "r11"
    );
}

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void poly1305_arm32_blocks(Poly1305* ctx_p,
    const unsigned char* m_p, size_t bytes_p)
#else
WC_OMIT_FRAME_POINTER void poly1305_arm32_blocks(Poly1305* ctx,
    const unsigned char* m, size_t bytes)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register Poly1305* ctx asm ("r0") = (Poly1305*)ctx_p;
    register const unsigned char* m asm ("r1") = (const unsigned char*)m_p;
    register size_t bytes asm ("r2") = (size_t)bytes_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "cmp	%[bytes], #16\n\t"
        "add	r12, %[ctx], #16\n\t"
        "bgt	L_poly1305_arm32_blocks_begin_neon_%=\n\t"
        "ldm	r12, {r7, r8, r9, r10, r11}\n\t"
        "b	L_poly1305_arm32_blocks_start_1_%=\n\t"
        "\n"
    "L_poly1305_arm32_blocks_begin_neon_%=: \n\t"
        "vmov.i16	q15, #0xffff\n\t"
        "vshr.u64	q15, q15, #38\n\t"
        "vld1.64	{d0-d2}, [r12]\n\t"
        "vshl.u64	d4, d2, #24\n\t"
        "vsri.u64	d4, d1, #40\n\t"
        "vshr.u64	d3, d1, #14\n\t"
        "vshl.u64	d2, d1, #12\n\t"
        "vsri.u64	d1, d0, #26\n\t"
        "vsri.u64	d2, d0, #52\n\t"
        "vand.u64	d0, d0, d31\n\t"
        "vand.u64	d3, d3, d31\n\t"
        "vand.u64	d2, d2, d31\n\t"
        "vand.u64	d1, d1, d31\n\t"
        "add	r3, %[ctx], #0x7c\n\t"
        "vldm.32	r3, {d20-d24}\n\t"
        "cmp	%[bytes], #0x40\n\t"
        "bge	L_poly1305_arm32_blocks_begin_4_%=\n\t"
        "vshl.u32	d6, d21, #2\n\t"
        "vshl.u32	d7, d22, #2\n\t"
        "vshl.u32	d8, d23, #2\n\t"
        "vshl.u32	d9, d24, #2\n\t"
        "vadd.u32	d6, d6, d21\n\t"
        "vadd.u32	d7, d7, d22\n\t"
        "vadd.u32	d8, d8, d23\n\t"
        "vadd.u32	d9, d9, d24\n\t"
        "b	L_poly1305_arm32_blocks_start_2_%=\n\t"
        "\n"
    "L_poly1305_arm32_blocks_begin_4_%=: \n\t"
        "add	r3, %[ctx], #0xa4\n\t"
        "vldm.32	r3, {d26-d30}\n\t"
        "\n"
    "L_poly1305_arm32_blocks_start_4_%=: \n\t"
        "sub	%[bytes], #0x40\n\t"
        "vld4.32	{d10-d13}, [%[m]]!\n\t"
        "vshl.u32	d6, d27, #2\n\t"
        "vshl.u32	d7, d28, #2\n\t"
        "vshl.u32	d8, d29, #2\n\t"
        "vshl.u32	d9, d30, #2\n\t"
        "vadd.u32	d6, d6, d27\n\t"
        "vadd.u32	d7, d7, d28\n\t"
        "vadd.u32	d8, d8, d29\n\t"
        "vadd.u32	d9, d9, d30\n\t"
        "vshr.u32	d14, d13, #8\n\t"
        "vshl.u32	d13, d13, #18\n\t"
        "vorr.i32	d14, d14, #0x1000000\n\t"
        "vsri.u32	d13, d12, #14\n\t"
        "vshl.u32	d12, d12, #12\n\t"
        "vand.i32	d13, d13, #0x3ffffff\n\t"
        "vsri.u32	d12, d11, #20\n\t"
        "vshl.u32	d11, d11, #6\n\t"
        "vand.i32	d12, d12, #0x3ffffff\n\t"
        "vsri.u32	d11, d10, #26\n\t"
        "vand.i32	d10, d10, #0x3ffffff\n\t"
        "vand.i32	d11, d11, #0x3ffffff\n\t"
        "vadd.u32	d4, d4, d14\n\t"
        "vadd.u32	q1, q1, q6\n\t"
        "vadd.u32	q0, q0, q5\n\t"
        "vmull.u32	q5, d0, d26\n\t"
        "vmull.u32	q6, d0, d27\n\t"
        "vmull.u32	q7, d0, d28\n\t"
        "vmull.u32	q8, d0, d29\n\t"
        "vmull.u32	q9, d0, d30\n\t"
        "vmlal.u32	q5, d1, d9\n\t"
        "vmlal.u32	q6, d1, d26\n\t"
        "vmlal.u32	q7, d1, d27\n\t"
        "vmlal.u32	q8, d1, d28\n\t"
        "vmlal.u32	q9, d1, d29\n\t"
        "vmlal.u32	q5, d2, d8\n\t"
        "vmlal.u32	q6, d2, d9\n\t"
        "vmlal.u32	q7, d2, d26\n\t"
        "vmlal.u32	q8, d2, d27\n\t"
        "vmlal.u32	q9, d2, d28\n\t"
        "vmlal.u32	q5, d3, d7\n\t"
        "vmlal.u32	q6, d3, d8\n\t"
        "vmlal.u32	q7, d3, d9\n\t"
        "vmlal.u32	q8, d3, d26\n\t"
        "vmlal.u32	q9, d3, d27\n\t"
        "vmlal.u32	q5, d4, d6\n\t"
        "vmlal.u32	q6, d4, d7\n\t"
        "vmlal.u32	q7, d4, d8\n\t"
        "vmlal.u32	q8, d4, d9\n\t"
        "vmlal.u32	q9, d4, d26\n\t"
        "vld4.32	{d0-d3}, [%[m]]!\n\t"
        "vshl.u32	d6, d21, #2\n\t"
        "vshl.u32	d7, d22, #2\n\t"
        "vshl.u32	d8, d23, #2\n\t"
        "vshl.u32	d9, d24, #2\n\t"
        "vadd.u32	d6, d6, d21\n\t"
        "vadd.u32	d7, d7, d22\n\t"
        "vadd.u32	d8, d8, d23\n\t"
        "vadd.u32	d9, d9, d24\n\t"
        "vshr.u32	d4, d3, #8\n\t"
        "vshl.u32	d3, d3, #18\n\t"
        "vorr.i32	d4, d4, #0x1000000\n\t"
        "vsri.u32	d3, d2, #14\n\t"
        "vshl.u32	d2, d2, #12\n\t"
        "vand.i32	d3, d3, #0x3ffffff\n\t"
        "vsri.u32	d2, d1, #20\n\t"
        "vshl.u32	d1, d1, #6\n\t"
        "vand.i32	d2, d2, #0x3ffffff\n\t"
        "vsri.u32	d1, d0, #26\n\t"
        "vand.i32	d0, d0, #0x3ffffff\n\t"
        "vand.i32	d1, d1, #0x3ffffff\n\t"
        "vmlal.u32	q5, d0, d20\n\t"
        "vmlal.u32	q6, d0, d21\n\t"
        "vmlal.u32	q7, d0, d22\n\t"
        "vmlal.u32	q8, d0, d23\n\t"
        "vmlal.u32	q9, d0, d24\n\t"
        "vmlal.u32	q5, d1, d9\n\t"
        "vmlal.u32	q6, d1, d20\n\t"
        "vmlal.u32	q7, d1, d21\n\t"
        "vmlal.u32	q8, d1, d22\n\t"
        "vmlal.u32	q9, d1, d23\n\t"
        "vmlal.u32	q5, d2, d8\n\t"
        "vmlal.u32	q6, d2, d9\n\t"
        "vmlal.u32	q7, d2, d20\n\t"
        "vmlal.u32	q8, d2, d21\n\t"
        "vmlal.u32	q9, d2, d22\n\t"
        "vmlal.u32	q5, d3, d7\n\t"
        "vmlal.u32	q6, d3, d8\n\t"
        "vmlal.u32	q7, d3, d9\n\t"
        "vmlal.u32	q8, d3, d20\n\t"
        "vmlal.u32	q9, d3, d21\n\t"
        "vmlal.u32	q5, d4, d6\n\t"
        "vmlal.u32	q6, d4, d7\n\t"
        "vmlal.u32	q7, d4, d8\n\t"
        "vmlal.u32	q8, d4, d9\n\t"
        "vmlal.u32	q9, d4, d20\n\t"
        "vadd.u64	d0, d10, d11\n\t"
        "vadd.u64	d1, d12, d13\n\t"
        "vadd.u64	d2, d14, d15\n\t"
        "vadd.u64	d3, d16, d17\n\t"
        "vadd.u64	d4, d18, d19\n\t"
        "vsra.u64	d1, d0, #26\n\t"
        "vand.u64	d0, d0, d31\n\t"
        "vsra.u64	d2, d1, #26\n\t"
        "vand.u64	d1, d1, d31\n\t"
        "vsra.u64	d3, d2, #26\n\t"
        "vand.u64	d2, d2, d31\n\t"
        "vsra.u64	d4, d3, #26\n\t"
        "vand.u64	d3, d3, d31\n\t"
        "vshr.u64	d15, d4, #26\n\t"
        "vand.u64	d4, d4, d31\n\t"
        "vadd.u64	d0, d0, d15\n\t"
        "vshl.u64	d15, d15, #2\n\t"
        "vadd.u64	d0, d0, d15\n\t"
        "vsra.u64	d1, d0, #26\n\t"
        "vand.u64	d0, d0, d31\n\t"
        "cmp	%[bytes], #0x40\n\t"
        "bge	L_poly1305_arm32_blocks_start_4_%=\n\t"
        "cmp	%[bytes], #32\n\t"
        "blt	L_poly1305_arm32_blocks_done_neon_%=\n\t"
        "\n"
    "L_poly1305_arm32_blocks_start_2_%=: \n\t"
        "sub	%[bytes], #32\n\t"
        "vld4.32	{d10-d13}, [%[m]]!\n\t"
        "vshr.u32	d14, d13, #8\n\t"
        "vshl.u32	d13, d13, #18\n\t"
        "vorr.i32	d14, d14, #0x1000000\n\t"
        "vsri.u32	d13, d12, #14\n\t"
        "vshl.u32	d12, d12, #12\n\t"
        "vand.i32	d13, d13, #0x3ffffff\n\t"
        "vsri.u32	d12, d11, #20\n\t"
        "vshl.u32	d11, d11, #6\n\t"
        "vand.i32	d12, d12, #0x3ffffff\n\t"
        "vsri.u32	d11, d10, #26\n\t"
        "vand.i32	d10, d10, #0x3ffffff\n\t"
        "vand.i32	d11, d11, #0x3ffffff\n\t"
        "vadd.u32	d4, d4, d14\n\t"
        "vadd.u32	q1, q1, q6\n\t"
        "vadd.u32	q0, q0, q5\n\t"
        "vmull.u32	q5, d0, d20\n\t"
        "vmull.u32	q6, d0, d21\n\t"
        "vmull.u32	q7, d0, d22\n\t"
        "vmull.u32	q8, d0, d23\n\t"
        "vmull.u32	q9, d0, d24\n\t"
        "vmlal.u32	q5, d1, d9\n\t"
        "vmlal.u32	q6, d1, d20\n\t"
        "vmlal.u32	q7, d1, d21\n\t"
        "vmlal.u32	q8, d1, d22\n\t"
        "vmlal.u32	q9, d1, d23\n\t"
        "vmlal.u32	q5, d2, d8\n\t"
        "vmlal.u32	q6, d2, d9\n\t"
        "vmlal.u32	q7, d2, d20\n\t"
        "vmlal.u32	q8, d2, d21\n\t"
        "vmlal.u32	q9, d2, d22\n\t"
        "vmlal.u32	q5, d3, d7\n\t"
        "vmlal.u32	q6, d3, d8\n\t"
        "vmlal.u32	q7, d3, d9\n\t"
        "vmlal.u32	q8, d3, d20\n\t"
        "vmlal.u32	q9, d3, d21\n\t"
        "vmlal.u32	q5, d4, d6\n\t"
        "vmlal.u32	q6, d4, d7\n\t"
        "vmlal.u32	q7, d4, d8\n\t"
        "vmlal.u32	q8, d4, d9\n\t"
        "vmlal.u32	q9, d4, d20\n\t"
        "vadd.u64	d0, d10, d11\n\t"
        "vadd.u64	d1, d12, d13\n\t"
        "vadd.u64	d2, d14, d15\n\t"
        "vadd.u64	d3, d16, d17\n\t"
        "vadd.u64	d4, d18, d19\n\t"
        "vsra.u64	d1, d0, #26\n\t"
        "vand.u64	d0, d0, d31\n\t"
        "vsra.u64	d2, d1, #26\n\t"
        "vand.u64	d1, d1, d31\n\t"
        "vsra.u64	d3, d2, #26\n\t"
        "vand.u64	d2, d2, d31\n\t"
        "vsra.u64	d4, d3, #26\n\t"
        "vand.u64	d3, d3, d31\n\t"
        "vshr.u64	d5, d4, #26\n\t"
        "vand.u64	d4, d4, d31\n\t"
        "vadd.u64	d0, d0, d5\n\t"
        "vshl.u64	d5, d5, #2\n\t"
        "vadd.u64	d0, d0, d5\n\t"
        "vsra.u64	d1, d0, #26\n\t"
        "vand.u64	d0, d0, d31\n\t"
        "\n"
    "L_poly1305_arm32_blocks_done_neon_%=: \n\t"
        "cmp	%[bytes], #16\n\t"
        "beq	L_poly1305_arm32_blocks_begin_1_%=\n\t"
        "add	r12, %[ctx], #16\n\t"
        "vsli.u64	d0, d1, #26\n\t"
        "vsli.u64	d0, d2, #52\n\t"
        "vshr.u64	d1, d2, #12\n\t"
        "vsli.u64	d1, d3, #14\n\t"
        "vsli.u64	d1, d4, #40\n\t"
        "vshr.u64	d2, d4, #24\n\t"
        "vst1.64	{d0-d2}, [r12]\n\t"
        "b	L_poly1305_arm32_blocks_done_%=\n\t"
        "\n"
    "L_poly1305_arm32_blocks_begin_1_%=: \n\t"
        "vsli.u64	d0, d1, #26\n\t"
        "vsli.u64	d0, d2, #52\n\t"
        "vshr.u64	d1, d2, #12\n\t"
        "vsli.u64	d1, d3, #14\n\t"
        "vsli.u64	d1, d4, #40\n\t"
        "vshr.u64	d2, d4, #24\n\t"
        "vmov	r7, r8, d0\n\t"
        "vmov	r9, r10, d1\n\t"
        "vmov	r11, d2[0]\n\t"
        "\n"
    "L_poly1305_arm32_blocks_start_1_%=: \n\t"
        "mov	r12, #1\n\t"
        "push	{r2}\n\t"
        /* Load message */
        "ldr	%[bytes], [%[m]]\n\t"
        "ldr	r3, [%[m], #4]\n\t"
        "ldr	r4, [%[m], #8]\n\t"
        "ldr	r5, [%[m], #12]\n\t"
        /* Add message */
        "adds	r7, r7, %[bytes]\n\t"
        "adcs	r8, r8, r3\n\t"
        "adcs	r9, r9, r4\n\t"
        "adcs	r10, r10, r5\n\t"
        "adc	r11, r11, r12\n\t"
        "push	{r0-r1}\n\t"
        "add	%[m], %[ctx], #0\n\t"
        "add	lr, %[ctx], #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
        "stm	lr, {r7, r8, r9, r10, r11}\n\t"
#else
        /* h[0]-h[2] in r4-r6 for multiplication. */
        "str	r10, [lr, #12]\n\t"
        "str	r11, [lr, #16]\n\t"
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
        /* r0 = #0, r1 = r, lr = h, r2 = h[j], r3 = r[i] */
        "ldr	r3, [%[m]]\n\t"
        "eor	%[ctx], %[ctx], %[ctx]\n\t"
        /* r[0] * h[0] */
        /* h[0] in r4 */
        "umull	r7, r8, r3, r7\n\t"
        /* r[0] * h[2] */
        /* h[2] in r6 */
        "umull	r9, r10, r3, r9\n\t"
        /* r[0] * h[4] */
        /* h[4] in r8 */
        "mul	r11, r3, r11\n\t"
        /* r[0] * h[1] */
        "ldr	%[bytes], [lr, #4]\n\t"
        "mov	r12, %[ctx]\n\t"
        "umlal	r8, r12, r3, %[bytes]\n\t"
        /* r[0] * h[3] */
        "ldr	%[bytes], [lr, #12]\n\t"
        "adds	r9, r9, r12\n\t"
        "adc	r10, r10, %[ctx]\n\t"
        "umlal	r10, r11, r3, %[bytes]\n\t"
        /* r[1] * h[0] */
        "ldr	r3, [%[m], #4]\n\t"
        "ldr	%[bytes], [lr]\n\t"
        "mov	r12, %[ctx]\n\t"
        "umlal	r8, r12, r3, %[bytes]\n\t"
        /* r[1] * h[1] */
        "ldr	%[bytes], [lr, #4]\n\t"
        "adds	r9, r9, r12\n\t"
        "adc	r12, %[ctx], %[ctx]\n\t"
        "umlal	r9, r12, r3, %[bytes]\n\t"
        /* r[1] * h[2] */
        "ldr	%[bytes], [lr, #8]\n\t"
        "adds	r10, r10, r12\n\t"
        "adc	r12, %[ctx], %[ctx]\n\t"
        "umlal	r10, r12, r3, %[bytes]\n\t"
        /* r[1] * h[3] */
        "ldr	%[bytes], [lr, #12]\n\t"
        "adds	r11, r11, r12\n\t"
        "adc	r4, %[ctx], %[ctx]\n\t"
        "umlal	r11, r4, r3, %[bytes]\n\t"
        /* r[1] * h[4] */
        "ldr	%[bytes], [lr, #16]\n\t"
        "mla	r4, r3, %[bytes], r4\n\t"
        /* r[2] * h[0] */
        "ldr	r3, [%[m], #8]\n\t"
        "ldr	%[bytes], [lr]\n\t"
        "mov	r12, %[ctx]\n\t"
        "umlal	r9, r12, r3, %[bytes]\n\t"
        /* r[2] * h[1] */
        "ldr	%[bytes], [lr, #4]\n\t"
        "adds	r10, r10, r12\n\t"
        "adc	r12, %[ctx], %[ctx]\n\t"
        "umlal	r10, r12, r3, %[bytes]\n\t"
        /* r[2] * h[2] */
        "ldr	%[bytes], [lr, #8]\n\t"
        "adds	r11, r11, r12\n\t"
        "adc	r12, %[ctx], %[ctx]\n\t"
        "umlal	r11, r12, r3, %[bytes]\n\t"
        /* r[2] * h[3] */
        "ldr	%[bytes], [lr, #12]\n\t"
        "adds	r4, r4, r12\n\t"
        "adc	r5, %[ctx], %[ctx]\n\t"
        "umlal	r4, r5, r3, %[bytes]\n\t"
        /* r[2] * h[4] */
        "ldr	%[bytes], [lr, #16]\n\t"
        "mla	r5, r3, %[bytes], r5\n\t"
        /* r[3] * h[0] */
        "ldr	r3, [%[m], #12]\n\t"
        "ldr	%[bytes], [lr]\n\t"
        "mov	r12, %[ctx]\n\t"
        "umlal	r10, r12, r3, %[bytes]\n\t"
        /* r[3] * h[1] */
        "ldr	%[bytes], [lr, #4]\n\t"
        "adds	r11, r11, r12\n\t"
        "adc	r12, %[ctx], %[ctx]\n\t"
        "umlal	r11, r12, r3, %[bytes]\n\t"
        /* r[3] * h[2] */
        "ldr	%[bytes], [lr, #8]\n\t"
        "adds	r4, r4, r12\n\t"
        "adc	r5, r5, %[ctx]\n\t"
        "umlal	r4, r5, r3, %[bytes]\n\t"
        /* r[3] * h[3] */
        "ldr	%[bytes], [lr, #12]\n\t"
        "mov	r6, %[ctx]\n\t"
        "umlal	r5, r6, r3, %[bytes]\n\t"
        /* r[3] * h[4] */
        "ldr	%[bytes], [lr, #16]\n\t"
        "mov	r12, %[ctx]\n\t"
        "mla	r6, r3, %[bytes], r6\n\t"
#else
        "sub	sp, sp, #12\n\t"
        "ldm	%[m], {r0, r1, r2, r3}\n\t"
        /* r[0] * h[0] */
        "umull	r5, r6, %[ctx], r7\n\t"
        /* r[1] * h[0] */
        "umull	r12, r10, %[m], r7\n\t"
        /* r[0] * h[1] */
        "umaal	r6, r12, %[ctx], r8\n\t"
        /* r[2] * h[0] */
        "umull	r11, r4, %[bytes], r7\n\t"
        /* r[1] * h[1] */
        "umaal	r12, r11, %[m], r8\n\t"
        /* r[0] * h[2] */
        "umaal	r12, r10, %[ctx], r9\n\t"
        /* r[3] * h[0] */
        "umaal	r11, r4, r3, r7\n\t"
        "stm	sp, {r5, r6, r12}\n\t"
        /* r[2] * h[1] */
        "umaal	r10, r11, %[bytes], r8\n\t"
        /* Replace h[0] with h[3] */
        "ldr	r7, [lr, #12]\n\t"
        /* r[1] * h[2] */
        "umull	r5, r6, %[m], r9\n\t"
        /* r[2] * h[2] */
        "umaal	r11, r4, %[bytes], r9\n\t"
        /* r[0] * h[3] */
        "umaal	r10, r5, %[ctx], r7\n\t"
        /* r[3] * h[1] */
        "umaal	r11, r6, r3, r8\n\t"
        /* r[1] * h[3] */
        "umaal	r11, r5, %[m], r7\n\t"
        /* r[3] * h[2] */
        "umaal	r4, r6, r3, r9\n\t"
        /* r[2] * h[3] */
        "umaal	r4, r5, %[bytes], r7\n\t"
        /* Replace h[1] with h[4] */
        "ldr	r8, [lr, #16]\n\t"
        /* r[3] * h[3] */
        "umaal	r5, r6, r3, r7\n\t"
        "mov	r12, #0\n\t"
        /* r[0] * h[4] */
        "umaal	r11, r12, %[ctx], r8\n\t"
        /* r[1] * h[4] */
        "umaal	r4, r12, %[m], r8\n\t"
        /* r[2] * h[4] */
        "umaal	r5, r12, %[bytes], r8\n\t"
        /* r[3] * h[4] */
        "umaal	r6, r12, r3, r8\n\t"
        /* DONE */
        "ldm	sp, {r7, r8, r9}\n\t"
        "add	sp, sp, #12\n\t"
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
        /* Reduce mod 2^130 - 5 */
        "bic	r3, r11, #0x3\n\t"
        "and	r11, r11, #3\n\t"
        "adds	r7, r7, r3\n\t"
        "lsr	r3, r3, #2\n\t"
        "adcs	r8, r8, r4\n\t"
        "orr	r3, r3, r4, LSL #30\n\t"
        "adcs	r9, r9, r5\n\t"
        "lsr	r4, r4, #2\n\t"
        "adcs	r10, r10, r6\n\t"
        "orr	r4, r4, r5, LSL #30\n\t"
        "adc	r11, r11, r12\n\t"
        "lsr	r5, r5, #2\n\t"
        "adds	r7, r7, r3\n\t"
        "orr	r5, r5, r6, LSL #30\n\t"
        "adcs	r8, r8, r4\n\t"
        "lsr	r6, r6, #2\n\t"
        "adcs	r9, r9, r5\n\t"
        "adcs	r10, r10, r6\n\t"
        "adc	r11, r11, r12\n\t"
        "pop	{r0-r1}\n\t"
        "pop	{r2}\n\t"
        "add	r12, %[ctx], #16\n\t"
        "stm	r12, {r7, r8, r9, r10, r11}\n\t"
        "\n"
    "L_poly1305_arm32_blocks_done_%=: \n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [ctx] "+r" (ctx), [m] "+r" (m), [bytes] "+r" (bytes)
        :
#else
        :
        : [ctx] "r" (ctx), [m] "r" (m), [bytes] "r" (bytes)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9",
            "r10", "r11", "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8",
            "d9", "d10", "d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18",
            "d19", "d20", "d21", "d22", "d23", "d24", "d25", "d26", "d27",
            "d28", "d29", "d30", "d31"
    );
}

static const word32 L_poly1305_arm32_clamp[] = {
    0x0fffffff, 0x0ffffffc, 0x0ffffffc, 0x0ffffffc,
};

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void poly1305_set_key(Poly1305* ctx_p, const byte* key_p)
#else
WC_OMIT_FRAME_POINTER void poly1305_set_key(Poly1305* ctx, const byte* key)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register Poly1305* ctx asm ("r0") = (Poly1305*)ctx_p;
    register const byte* key asm ("r1") = (const byte*)key_p;
    register word32* L_poly1305_arm32_clamp_c asm ("r2") =
        (word32*)&L_poly1305_arm32_clamp;
#else
    register word32* L_poly1305_arm32_clamp_c =
        (word32*)&L_poly1305_arm32_clamp;

#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        /* Load mask. */
        "mov	lr, %[L_poly1305_arm32_clamp]\n\t"
        "ldm	lr, {r6, r7, r8, r9}\n\t"
        /* Load and cache padding. */
        "ldr	r2, [%[key], #16]\n\t"
        "ldr	r3, [%[key], #20]\n\t"
        "ldr	r4, [%[key], #24]\n\t"
        "ldr	r5, [%[key], #28]\n\t"
        "add	lr, %[ctx], #40\n\t"
        "stm	lr, {r2, r3, r4, r5}\n\t"
        /* Load, mask and store r. */
        "ldr	r2, [%[key]]\n\t"
        "ldr	r3, [%[key], #4]\n\t"
        "ldr	r4, [%[key], #8]\n\t"
        "ldr	r5, [%[key], #12]\n\t"
        "and	r2, r2, r6\n\t"
        "and	r3, r3, r7\n\t"
        "and	r4, r4, r8\n\t"
        "and	r5, r5, r9\n\t"
        "add	lr, %[ctx], #0\n\t"
        "stm	lr, {r2, r3, r4, r5}\n\t"
        "vmov.i16	q10, #0xffff\n\t"
        "vshr.u64	q10, q10, #38\n\t"
        "lsr	r8, r2, #26\n\t"
        "lsr	r9, r3, #20\n\t"
        "lsr	r10, r4, #14\n\t"
        "lsr	r11, r5, #8\n\t"
        "eor	r8, r8, r3, lsl #6\n\t"
        "eor	r9, r9, r4, lsl #12\n\t"
        "eor	r10, r10, r5, lsl #18\n\t"
        "and	r7, r2, #0x3ffffff\n\t"
        "and	r8, r8, #0x3ffffff\n\t"
        "and	r9, r9, #0x3ffffff\n\t"
        "and	r10, r10, #0x3ffffff\n\t"
        "vmov.i32	s1, r7\n\t"
        "vmov.i32	s3, r8\n\t"
        "vmov.i32	s5, r9\n\t"
        "vmov.i32	s7, r10\n\t"
        "vmov.i32	s9, r11\n\t"
        "push	{%[ctx]-%[key]}\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
        /* Square r */
        "umull	%[key], r6, r2, r3\n\t"
        "mov	r12, #0\n\t"
        "umull	r7, r8, r2, r5\n\t"
        "mov	lr, r12\n\t"
        "umlal	r6, lr, r2, r4\n\t"
        "adds	r7, r7, lr\n\t"
        "adc	lr, r12, r12\n\t"
        "umlal	r7, lr, r3, r4\n\t"
        "mov	r9, r12\n\t"
        "umlal	lr, r9, r3, r5\n\t"
        "adds	r8, r8, lr\n\t"
        "adcs	r9, r9, r12\n\t"
        "adc	r10, r12, r12\n\t"
        "umlal	r9, r10, r4, r5\n\t"
        "adds	%[key], %[key], %[key]\n\t"
        "adcs	r6, r6, r6\n\t"
        "adcs	r7, r7, r7\n\t"
        "adcs	r8, r8, r8\n\t"
        "adcs	r9, r9, r9\n\t"
        "adcs	r10, r10, r10\n\t"
        "adc	r11, r12, r12\n\t"
        "umull	%[ctx], lr, r2, r2\n\t"
        "adds	%[key], %[key], lr\n\t"
        "adcs	r6, r6, r12\n\t"
        "adc	lr, r12, r12\n\t"
        "umlal	r6, lr, r3, r3\n\t"
        "adds	r7, r7, lr\n\t"
        "adcs	r8, r8, r12\n\t"
        "adc	lr, r12, r12\n\t"
        "umlal	r8, lr, r4, r4\n\t"
        "adds	r9, r9, lr\n\t"
        "adcs	r10, r10, r12\n\t"
        "adc	r11, r11, r12\n\t"
        "umlal	r10, r11, r5, r5\n\t"
#else
        "umull	%[ctx], %[key], r2, r2\n\t"
        "umull	r6, r7, r2, r3\n\t"
        "adds	r6, r6, r6\n\t"
        "mov	r12, #0\n\t"
        "umaal	%[key], r6, r12, r12\n\t"
        "mov	r8, r12\n\t"
        "umaal	r8, r7, r2, r4\n\t"
        "adcs	r8, r8, r8\n\t"
        "umaal	r6, r8, r3, r3\n\t"
        "umull	r9, r10, r2, r5\n\t"
        "umaal	r7, r9, r3, r4\n\t"
        "adcs	r7, r7, r7\n\t"
        "umaal	r7, r8, r12, r12\n\t"
        "umaal	r10, r9, r3, r5\n\t"
        "adcs	r10, r10, r10\n\t"
        "umaal	r8, r10, r4, r4\n\t"
        "mov	r11, r12\n\t"
        "umaal	r9, r11, r4, r5\n\t"
        "adcs	r9, r9, r9\n\t"
        "umaal	r9, r10, r12, r12\n\t"
        "adcs	r11, r11, r11\n\t"
        "umaal	r10, r11, r5, r5\n\t"
        "adc	r11, r11, r12\n\t"
#endif /* defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6) */
        /* Reduce mod 2^130 - 5 */
        "bic	r2, r8, #0x3\n\t"
        "and	r8, r8, #3\n\t"
        "adds	%[ctx], %[ctx], r2\n\t"
        "lsr	r2, r2, #2\n\t"
        "adcs	%[key], %[key], r9\n\t"
        "orr	r2, r2, r9, LSL #30\n\t"
        "adcs	r6, r6, r10\n\t"
        "lsr	r9, r9, #2\n\t"
        "adcs	r7, r7, r11\n\t"
        "orr	r9, r9, r10, LSL #30\n\t"
        "adc	r8, r8, r12\n\t"
        "lsr	r10, r10, #2\n\t"
        "adds	%[ctx], %[ctx], r2\n\t"
        "orr	r10, r10, r11, LSL #30\n\t"
        "adcs	%[key], %[key], r9\n\t"
        "lsr	r11, r11, #2\n\t"
        "adcs	r6, r6, r10\n\t"
        "adcs	r7, r7, r11\n\t"
        "adc	r8, r8, r12\n\t"
        "lsr	r3, %[ctx], #26\n\t"
        "lsr	r4, %[key], #20\n\t"
        "lsr	r5, r6, #14\n\t"
        "lsr	r10, r7, #8\n\t"
        "eor	r3, r3, %[key], lsl #6\n\t"
        "eor	r4, r4, r6, lsl #12\n\t"
        "eor	r5, r5, r7, lsl #18\n\t"
        "eor	r10, r10, r8, lsl #24\n\t"
        "and	r2, %[ctx], #0x3ffffff\n\t"
        "and	r3, r3, #0x3ffffff\n\t"
        "and	r4, r4, #0x3ffffff\n\t"
        "and	r5, r5, #0x3ffffff\n\t"
        "vmov.i32	s0, r2\n\t"
        "vmov.i32	s2, r3\n\t"
        "vmov.i32	s4, r4\n\t"
        "vmov.i32	s6, r5\n\t"
        "vmov.i32	s8, r10\n\t"
        "pop	{%[ctx]-%[key]}\n\t"
        "add	lr, %[ctx], #0x7c\n\t"
        "vstm.32	lr, {d0-d4}\n\t"
        /* Multiply r^2, r by r^2 */
        "vshl.u32	d6, d1, #2\n\t"
        "vshl.u32	d7, d2, #2\n\t"
        "vshl.u32	d8, d3, #2\n\t"
        "vshl.u32	d9, d4, #2\n\t"
        "vadd.u32	d6, d6, d1\n\t"
        "vadd.u32	d7, d7, d2\n\t"
        "vadd.u32	d8, d8, d3\n\t"
        "vadd.u32	d9, d9, d4\n\t"
        "vmull.u32	q5, d0, d0[0]\n\t"
        "vmull.u32	q6, d0, d1[0]\n\t"
        "vmull.u32	q7, d0, d2[0]\n\t"
        "vmull.u32	q8, d0, d3[0]\n\t"
        "vmull.u32	q9, d0, d4[0]\n\t"
        "vmlal.u32	q5, d1, d9[0]\n\t"
        "vmlal.u32	q6, d1, d0[0]\n\t"
        "vmlal.u32	q7, d1, d1[0]\n\t"
        "vmlal.u32	q8, d1, d2[0]\n\t"
        "vmlal.u32	q9, d1, d3[0]\n\t"
        "vmlal.u32	q5, d2, d8[0]\n\t"
        "vmlal.u32	q6, d2, d9[0]\n\t"
        "vmlal.u32	q7, d2, d0[0]\n\t"
        "vmlal.u32	q8, d2, d1[0]\n\t"
        "vmlal.u32	q9, d2, d2[0]\n\t"
        "vmlal.u32	q5, d3, d7[0]\n\t"
        "vmlal.u32	q6, d3, d8[0]\n\t"
        "vmlal.u32	q7, d3, d9[0]\n\t"
        "vmlal.u32	q8, d3, d0[0]\n\t"
        "vmlal.u32	q9, d3, d1[0]\n\t"
        "vmlal.u32	q5, d4, d6[0]\n\t"
        "vmlal.u32	q6, d4, d7[0]\n\t"
        "vmlal.u32	q7, d4, d8[0]\n\t"
        "vmlal.u32	q8, d4, d9[0]\n\t"
        "vmlal.u32	q9, d4, d0[0]\n\t"
        "vsra.u64	q6, q5, #26\n\t"
        "vand.u64	q5, q5, q10\n\t"
        "vsra.u64	q7, q6, #26\n\t"
        "vand.u64	q6, q6, q10\n\t"
        "vsra.u64	q8, q7, #26\n\t"
        "vand.u64	q7, q7, q10\n\t"
        "vsra.u64	q9, q8, #26\n\t"
        "vand.u64	q8, q8, q10\n\t"
        "vshr.u64	q3, q9, #26\n\t"
        "vand.u64	q9, q9, q10\n\t"
        "vadd.u64	q5, q5, q3\n\t"
        "vshl.u64	q3, q3, #2\n\t"
        "vadd.u64	q5, q5, q3\n\t"
        "vsra.u64	q6, q5, #26\n\t"
        "vand.u64	q5, q5, q10\n\t"
        "vmovn.i64	d10, q5\n\t"
        "vmovn.i64	d11, q6\n\t"
        "vmovn.i64	d12, q7\n\t"
        "vmovn.i64	d13, q8\n\t"
        "vmovn.i64	d14, q9\n\t"
        "add	lr, %[ctx], #0xa4\n\t"
        "vstm.32	lr, {d10-d14}\n\t"
        /* h (accumulator) = 0 */
        "eor	r6, r6, r6\n\t"
        "eor	r7, r7, r7\n\t"
        "eor	r8, r8, r8\n\t"
        "eor	r9, r9, r9\n\t"
        "add	lr, %[ctx], #16\n\t"
        "eor	r4, r4, r4\n\t"
        "eor	r5, r5, r5\n\t"
        "stm	lr, {r4, r5, r6, r7, r8, r9}\n\t"
        /* Zero leftover */
        "str	r5, [%[ctx], #56]\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [ctx] "+r" (ctx), [key] "+r" (key),
          [L_poly1305_arm32_clamp] "+r" (L_poly1305_arm32_clamp_c)
        :
#else
        :
        : [ctx] "r" (ctx), [key] "r" (key),
          [L_poly1305_arm32_clamp] "r" (L_poly1305_arm32_clamp_c)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9",
            "r10", "r11", "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8",
            "d9", "d10", "d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18",
            "d19", "d20", "d21"
    );
}

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
WC_OMIT_FRAME_POINTER void poly1305_final(Poly1305* ctx_p, byte* mac_p)
#else
WC_OMIT_FRAME_POINTER void poly1305_final(Poly1305* ctx, byte* mac)
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register Poly1305* ctx asm ("r0") = (Poly1305*)ctx_p;
    register byte* mac asm ("r1") = (byte*)mac_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "add	r9, %[ctx], #16\n\t"
        "ldm	r9, {r4, r5, r6, r7, r8}\n\t"
        /* Add 5 and check for h larger than p. */
        "adds	r2, r4, #5\n\t"
        "adcs	r2, r5, #0\n\t"
        "adcs	r2, r6, #0\n\t"
        "adcs	r2, r7, #0\n\t"
        "adc	r2, r8, #0\n\t"
        "sub	r2, r2, #4\n\t"
        "lsr	r2, r2, #31\n\t"
        "sub	r2, r2, #1\n\t"
        "and	r2, r2, #5\n\t"
        /* Add 0/5 to h. */
        "adds	r4, r4, r2\n\t"
        "adcs	r5, r5, #0\n\t"
        "adcs	r6, r6, #0\n\t"
        "adc	r7, r7, #0\n\t"
        /* Add padding */
        "add	r9, %[ctx], #40\n\t"
        "ldm	r9, {r2, r3, r12, lr}\n\t"
        "adds	r4, r4, r2\n\t"
        "adcs	r5, r5, r3\n\t"
        "adcs	r6, r6, r12\n\t"
        "adc	r7, r7, lr\n\t"
        /* Store MAC */
        "str	r4, [%[mac]]\n\t"
        "str	r5, [%[mac], #4]\n\t"
        "str	r6, [%[mac], #8]\n\t"
        "str	r7, [%[mac], #12]\n\t"
        /* Zero out h. */
        "eor	r4, r4, r4\n\t"
        "eor	r5, r5, r5\n\t"
        "eor	r6, r6, r6\n\t"
        "eor	r7, r7, r7\n\t"
        "eor	r8, r8, r8\n\t"
        "add	r9, %[ctx], #16\n\t"
        "stm	r9, {r4, r5, r6, r7, r8}\n\t"
        /* Zero out r. */
        "add	r9, %[ctx], #0\n\t"
        "stm	r9, {r4, r5, r6, r7}\n\t"
        /* Zero out padding. */
        "add	r9, %[ctx], #40\n\t"
        "stm	r9, {r4, r5, r6, r7}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [ctx] "+r" (ctx), [mac] "+r" (mac)
        :
#else
        :
        : [ctx] "r" (ctx), [mac] "r" (mac)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
        : "memory", "cc", "r2", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8",
            "r9"
    );
}

#endif /* WOLFSSL_ARMASM_NO_NEON */
#endif /* HAVE_POLY1305 */
#endif /* !__aarch64__ && !WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#endif /* WOLFSSL_ARMASM_INLINE */
