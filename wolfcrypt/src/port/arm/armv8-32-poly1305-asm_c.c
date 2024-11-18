/* armv8-32-poly1305-asm
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
 *   ruby ./poly1305/poly1305.rb arm32 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-32-poly1305-asm.c
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef WOLFSSL_ARMASM
#if !defined(__aarch64__) && !defined(WOLFSSL_ARMASM_THUMB2)
#include <stdint.h>
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef WOLFSSL_ARMASM_INLINE

#ifdef __IAR_SYSTEMS_ICC__
#define __asm__        asm
#define __volatile__   volatile
#endif /* __IAR_SYSTEMS_ICC__ */
#ifdef __KEIL__
#define __asm__        __asm
#define __volatile__   volatile
#endif /* __KEIL__ */
#ifdef HAVE_POLY1305
#include <wolfssl/wolfcrypt/poly1305.h>

void poly1305_blocks_arm32_16(Poly1305* ctx_p, const byte* m_p, word32 len_p,
    int notLast_p)
{
    register Poly1305* ctx asm ("r0") = (Poly1305*)ctx_p;
    register const byte* m asm ("r1") = (const byte*)m_p;
    register word32 len asm ("r2") = (word32)len_p;
    register int notLast asm ("r3") = (int)notLast_p;

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
        : [ctx] "+r" (ctx), [m] "+r" (m), [len] "+r" (len),
          [notLast] "+r" (notLast)
        :
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9",
            "r10", "r11"
    );
}

static const word32 L_poly1305_arm32_clamp[] = {
    0x0fffffff, 0x0ffffffc, 0x0ffffffc, 0x0ffffffc,
};

void poly1305_set_key(Poly1305* ctx_p, const byte* key_p)
{
    register Poly1305* ctx asm ("r0") = (Poly1305*)ctx_p;
    register const byte* key asm ("r1") = (const byte*)key_p;
    register word32* L_poly1305_arm32_clamp_c asm ("r2") =
        (word32*)&L_poly1305_arm32_clamp;

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
        : [ctx] "+r" (ctx), [key] "+r" (key),
          [L_poly1305_arm32_clamp] "+r" (L_poly1305_arm32_clamp_c)
        :
        : "memory", "cc", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8"
    );
}

void poly1305_final(Poly1305* ctx_p, byte* mac_p)
{
    register Poly1305* ctx asm ("r0") = (Poly1305*)ctx_p;
    register byte* mac asm ("r1") = (byte*)mac_p;

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
        : [ctx] "+r" (ctx), [mac] "+r" (mac)
        :
        : "memory", "cc", "r2", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8",
            "r9"
    );
}

#endif /* HAVE_POLY1305 */
#endif /* !__aarch64__ && !WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#endif /* WOLFSSL_ARMASM_INLINE */
