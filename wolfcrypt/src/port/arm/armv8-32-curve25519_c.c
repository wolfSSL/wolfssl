/* armv8-32-curve25519
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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
 *   ruby ./x25519/x25519.rb arm32 ../wolfssl/wolfcrypt/src/port/arm/armv8-32-curve25519.c
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_ARMASM
#if !defined(__aarch64__) && defined(__arm__)
#include <stdint.h>
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>
#ifdef WOLFSSL_ARMASM_INLINE
/* Based on work by: Emil Lenngren
 * https://github.com/pornin/X25519-Cortex-M4
 */

#include <wolfssl/wolfcrypt/fe_operations.h>
#define CURVED25519_ASM
#include <wolfssl/wolfcrypt/ge_operations.h>

#if defined(HAVE_CURVE25519) || defined(HAVE_ED25519)
#if !defined(CURVE25519_SMALL) || !defined(ED25519_SMALL)

void fe_init()
{

    __asm__ __volatile__ (
        "\n\t"
        :
        :
        : "memory"
    );
}

void fe_add_sub_op(void);
void fe_add_sub_op()
{

    __asm__ __volatile__ (
        /* Add-Sub */
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r4, [r2]\n\t"
        "ldr	r5, [r2, #4]\n\t"
#else
        "ldrd	r4, r5, [r2]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r6, [r3]\n\t"
        "ldr	r7, [r3, #4]\n\t"
#else
        "ldrd	r6, r7, [r3]\n\t"
#endif
        /*  Add */
        "adds	r8, r4, r6\n\t"
        "mov	r12, #0\n\t"
        "adcs	r9, r5, r7\n\t"
        "adc	r12, r12, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r8, [r0]\n\t"
        "str	r9, [r0, #4]\n\t"
#else
        "strd	r8, r9, [r0]\n\t"
#endif
        /*  Sub */
        "subs	r10, r4, r6\n\t"
        "sbcs	r11, r5, r7\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [r1]\n\t"
        "str	r11, [r1, #4]\n\t"
#else
        "strd	r10, r11, [r1]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r4, [r2, #8]\n\t"
        "ldr	r5, [r2, #12]\n\t"
#else
        "ldrd	r4, r5, [r2, #8]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r6, [r3, #8]\n\t"
        "ldr	r7, [r3, #12]\n\t"
#else
        "ldrd	r6, r7, [r3, #8]\n\t"
#endif
        /*  Sub */
        "sbcs	r10, r4, r6\n\t"
        "mov	lr, #0\n\t"
        "sbcs	r11, r5, r7\n\t"
        "adc	lr, lr, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [r1, #8]\n\t"
        "str	r11, [r1, #12]\n\t"
#else
        "strd	r10, r11, [r1, #8]\n\t"
#endif
        /*  Add */
        "subs	r12, r12, #1\n\t"
        "adcs	r8, r4, r6\n\t"
        "adcs	r9, r5, r7\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r8, [r0, #8]\n\t"
        "str	r9, [r0, #12]\n\t"
#else
        "strd	r8, r9, [r0, #8]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r4, [r2, #16]\n\t"
        "ldr	r5, [r2, #20]\n\t"
#else
        "ldrd	r4, r5, [r2, #16]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r6, [r3, #16]\n\t"
        "ldr	r7, [r3, #20]\n\t"
#else
        "ldrd	r6, r7, [r3, #16]\n\t"
#endif
        /*  Add */
        "adcs	r8, r4, r6\n\t"
        "mov	r12, #0\n\t"
        "adcs	r9, r5, r7\n\t"
        "adc	r12, r12, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r8, [r0, #16]\n\t"
        "str	r9, [r0, #20]\n\t"
#else
        "strd	r8, r9, [r0, #16]\n\t"
#endif
        /*  Sub */
        "subs	lr, lr, #1\n\t"
        "sbcs	r10, r4, r6\n\t"
        "sbcs	r11, r5, r7\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [r1, #16]\n\t"
        "str	r11, [r1, #20]\n\t"
#else
        "strd	r10, r11, [r1, #16]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r4, [r2, #24]\n\t"
        "ldr	r5, [r2, #28]\n\t"
#else
        "ldrd	r4, r5, [r2, #24]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r6, [r3, #24]\n\t"
        "ldr	r7, [r3, #28]\n\t"
#else
        "ldrd	r6, r7, [r3, #24]\n\t"
#endif
        /*  Sub */
        "sbcs	r10, r4, r6\n\t"
        "sbcs	r11, r5, r7\n\t"
        "sbc	lr, lr, lr\n\t"
        /*  Add */
        "subs	r12, r12, #1\n\t"
        "adcs	r8, r4, r6\n\t"
        "mov	r12, #0\n\t"
        "adcs	r9, r5, r7\n\t"
        "adc	r12, r12, #0\n\t"
        /*   Multiply -modulus by overflow */
        "lsl	r3, r12, #1\n\t"
        "mov	r12, #19\n\t"
        "orr	r3, r3, r9, lsr #31\n\t"
        "mul	r12, r3, r12\n\t"
        /*   Add -x*modulus (if overflow) */
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r4, [r0]\n\t"
        "ldr	r5, [r0, #4]\n\t"
#else
        "ldrd	r4, r5, [r0]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r6, [r0, #8]\n\t"
        "ldr	r7, [r0, #12]\n\t"
#else
        "ldrd	r6, r7, [r0, #8]\n\t"
#endif
        "adds	r4, r4, r12\n\t"
        "adcs	r5, r5, #0\n\t"
        "adcs	r6, r6, #0\n\t"
        "adcs	r7, r7, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r4, [r0]\n\t"
        "str	r5, [r0, #4]\n\t"
#else
        "strd	r4, r5, [r0]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r6, [r0, #8]\n\t"
        "str	r7, [r0, #12]\n\t"
#else
        "strd	r6, r7, [r0, #8]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r4, [r0, #16]\n\t"
        "ldr	r5, [r0, #20]\n\t"
#else
        "ldrd	r4, r5, [r0, #16]\n\t"
#endif
        "adcs	r4, r4, #0\n\t"
        "adcs	r5, r5, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r4, [r0, #16]\n\t"
        "str	r5, [r0, #20]\n\t"
#else
        "strd	r4, r5, [r0, #16]\n\t"
#endif
        "bfc	r9, #31, #1\n\t"
        "adcs	r8, r8, #0\n\t"
        "adc	r9, r9, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r8, [r0, #24]\n\t"
        "str	r9, [r0, #28]\n\t"
#else
        "strd	r8, r9, [r0, #24]\n\t"
#endif
        /*   Multiply -modulus by underflow */
        "lsl	r3, lr, #1\n\t"
        "mvn	lr, #18\n\t"
        "orr	r3, r3, r11, lsr #31\n\t"
        "mul	lr, r3, lr\n\t"
        /*   Sub -x*modulus (if overflow) */
        "ldm	r1, {r4, r5, r6, r7, r8, r9}\n\t"
        "subs	r4, r4, lr\n\t"
        "sbcs	r5, r5, #0\n\t"
        "sbcs	r6, r6, #0\n\t"
        "sbcs	r7, r7, #0\n\t"
        "sbcs	r8, r8, #0\n\t"
        "sbcs	r9, r9, #0\n\t"
        "bfc	r11, #31, #1\n\t"
        "sbcs	r10, r10, #0\n\t"
        "sbc	r11, r11, #0\n\t"
        "stm	r1, {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        /* Done Add-Sub */
        :
        :
        : "memory", "lr"
    );
}

void fe_sub_op(void);
void fe_sub_op()
{

    __asm__ __volatile__ (
        /* Sub */
        "ldm	r2!, {r6, r7, r8, r9, r10, r11, r12, lr}\n\t"
        "ldm	r1!, {r2, r3, r4, r5}\n\t"
        "subs	r6, r2, r6\n\t"
        "sbcs	r7, r3, r7\n\t"
        "sbcs	r8, r4, r8\n\t"
        "sbcs	r9, r5, r9\n\t"
        "ldm	r1!, {r2, r3, r4, r5}\n\t"
        "sbcs	r10, r2, r10\n\t"
        "sbcs	r11, r3, r11\n\t"
        "sbcs	r12, r4, r12\n\t"
        "sbcs	lr, r5, lr\n\t"
        "sbc	r3, r3, r3\n\t"
        "mvn	r2, #18\n\t"
        "lsl	r3, r3, #1\n\t"
        "orr	r3, r3, lr, lsr #31\n\t"
        "mul	r2, r3, r2\n\t"
        "subs	r6, r6, r2\n\t"
        "sbcs	r7, r7, #0\n\t"
        "sbcs	r8, r8, #0\n\t"
        "sbcs	r9, r9, #0\n\t"
        "sbcs	r10, r10, #0\n\t"
        "sbcs	r11, r11, #0\n\t"
        "bfc	lr, #31, #1\n\t"
        "sbcs	r12, r12, #0\n\t"
        "sbc	lr, lr, #0\n\t"
        "stm	r0, {r6, r7, r8, r9, r10, r11, r12, lr}\n\t"
        /* Done Sub */
        :
        :
        : "memory", "lr"
    );
}

void fe_sub(fe r_p, const fe a_p, const fe b_p)
{
    register fe r asm ("r0") = r_p;
    register const fe a asm ("r1") = a_p;
    register const fe b asm ("r2") = b_p;

    __asm__ __volatile__ (
        "bl	fe_sub_op\n\t"
        : [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr"
    );
}

void fe_add_op(void);
void fe_add_op()
{

    __asm__ __volatile__ (
        /* Add */
        "ldm	r2!, {r6, r7, r8, r9, r10, r11, r12, lr}\n\t"
        "ldm	r1!, {r2, r3, r4, r5}\n\t"
        "adds	r6, r2, r6\n\t"
        "adcs	r7, r3, r7\n\t"
        "adcs	r8, r4, r8\n\t"
        "adcs	r9, r5, r9\n\t"
        "ldm	r1!, {r2, r3, r4, r5}\n\t"
        "adcs	r10, r2, r10\n\t"
        "adcs	r11, r3, r11\n\t"
        "adcs	r12, r4, r12\n\t"
        "mov	r3, #0\n\t"
        "adcs	lr, r5, lr\n\t"
        "adc	r3, r3, #0\n\t"
        "mov	r2, #19\n\t"
        "lsl	r3, r3, #1\n\t"
        "orr	r3, r3, lr, lsr #31\n\t"
        "mul	r2, r3, r2\n\t"
        "adds	r6, r6, r2\n\t"
        "adcs	r7, r7, #0\n\t"
        "adcs	r8, r8, #0\n\t"
        "adcs	r9, r9, #0\n\t"
        "adcs	r10, r10, #0\n\t"
        "adcs	r11, r11, #0\n\t"
        "bfc	lr, #31, #1\n\t"
        "adcs	r12, r12, #0\n\t"
        "adc	lr, lr, #0\n\t"
        "stm	r0, {r6, r7, r8, r9, r10, r11, r12, lr}\n\t"
        /* Done Add */
        :
        :
        : "memory", "lr"
    );
}

void fe_add(fe r_p, const fe a_p, const fe b_p)
{
    register fe r asm ("r0") = r_p;
    register const fe a asm ("r1") = a_p;
    register const fe b asm ("r2") = b_p;

    __asm__ __volatile__ (
        "bl	fe_add_op\n\t"
        : [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr"
    );
}

#ifdef HAVE_ED25519
void fe_frombytes(fe out_p, const unsigned char* in_p)
{
    register fe out asm ("r0") = out_p;
    register const unsigned char* in asm ("r1") = in_p;

    __asm__ __volatile__ (
        "ldm	%[in], {r2, r3, r4, r5, r6, r7, r8, r9}\n\t"
        "bfc	r9, #31, #1\n\t"
        "stm	%[out], {r2, r3, r4, r5, r6, r7, r8, r9}\n\t"
        : [out] "+r" (out), [in] "+r" (in)
        :
        : "memory", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9"
    );
}

void fe_tobytes(unsigned char* out_p, const fe n_p)
{
    register unsigned char* out asm ("r0") = out_p;
    register const fe n asm ("r1") = n_p;

    __asm__ __volatile__ (
        "ldm	%[n], {r2, r3, r4, r5, r6, r7, r8, r9}\n\t"
        "adds	r12, r2, #19\n\t"
        "adcs	r12, r3, #0\n\t"
        "adcs	r12, r4, #0\n\t"
        "adcs	r12, r5, #0\n\t"
        "adcs	r12, r6, #0\n\t"
        "adcs	r12, r7, #0\n\t"
        "adcs	r12, r8, #0\n\t"
        "adc	r12, r9, #0\n\t"
        "asr	r12, r12, #31\n\t"
        "and	r12, r12, #19\n\t"
        "adds	r2, r2, r12\n\t"
        "adcs	r3, r3, #0\n\t"
        "adcs	r4, r4, #0\n\t"
        "adcs	r5, r5, #0\n\t"
        "adcs	r6, r6, #0\n\t"
        "adcs	r7, r7, #0\n\t"
        "adcs	r8, r8, #0\n\t"
        "adc	r9, r9, #0\n\t"
        "bfc	r9, #31, #1\n\t"
        "stm	%[out], {r2, r3, r4, r5, r6, r7, r8, r9}\n\t"
        : [out] "+r" (out), [n] "+r" (n)
        :
        : "memory", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r12"
    );
}

void fe_1(fe n_p)
{
    register fe n asm ("r0") = n_p;

    __asm__ __volatile__ (
        /* Set one */
        "mov	r2, #1\n\t"
        "mov	r3, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r2, [%[n]]\n\t"
        "str	r3, [%[n], #4]\n\t"
#else
        "strd	r2, r3, [%[n]]\n\t"
#endif
        "mov	r2, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r2, [%[n], #8]\n\t"
        "str	r3, [%[n], #12]\n\t"
#else
        "strd	r2, r3, [%[n], #8]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r2, [%[n], #16]\n\t"
        "str	r3, [%[n], #20]\n\t"
#else
        "strd	r2, r3, [%[n], #16]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r2, [%[n], #24]\n\t"
        "str	r3, [%[n], #28]\n\t"
#else
        "strd	r2, r3, [%[n], #24]\n\t"
#endif
        : [n] "+r" (n)
        :
        : "memory", "r2", "r3"
    );
}

void fe_0(fe n_p)
{
    register fe n asm ("r0") = n_p;

    __asm__ __volatile__ (
        /* Set zero */
        "mov	r2, #0\n\t"
        "mov	r3, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r2, [%[n]]\n\t"
        "str	r3, [%[n], #4]\n\t"
#else
        "strd	r2, r3, [%[n]]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r2, [%[n], #8]\n\t"
        "str	r3, [%[n], #12]\n\t"
#else
        "strd	r2, r3, [%[n], #8]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r2, [%[n], #16]\n\t"
        "str	r3, [%[n], #20]\n\t"
#else
        "strd	r2, r3, [%[n], #16]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r2, [%[n], #24]\n\t"
        "str	r3, [%[n], #28]\n\t"
#else
        "strd	r2, r3, [%[n], #24]\n\t"
#endif
        : [n] "+r" (n)
        :
        : "memory", "r2", "r3"
    );
}

void fe_copy(fe r_p, const fe a_p)
{
    register fe r asm ("r0") = r_p;
    register const fe a asm ("r1") = a_p;

    __asm__ __volatile__ (
        /* Copy */
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r2, [%[a]]\n\t"
        "ldr	r3, [%[a], #4]\n\t"
#else
        "ldrd	r2, r3, [%[a]]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r4, [%[a], #8]\n\t"
        "ldr	r5, [%[a], #12]\n\t"
#else
        "ldrd	r4, r5, [%[a], #8]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r2, [%[r]]\n\t"
        "str	r3, [%[r], #4]\n\t"
#else
        "strd	r2, r3, [%[r]]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r4, [%[r], #8]\n\t"
        "str	r5, [%[r], #12]\n\t"
#else
        "strd	r4, r5, [%[r], #8]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r2, [%[a], #16]\n\t"
        "ldr	r3, [%[a], #20]\n\t"
#else
        "ldrd	r2, r3, [%[a], #16]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r4, [%[a], #24]\n\t"
        "ldr	r5, [%[a], #28]\n\t"
#else
        "ldrd	r4, r5, [%[a], #24]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r2, [%[r], #16]\n\t"
        "str	r3, [%[r], #20]\n\t"
#else
        "strd	r2, r3, [%[r], #16]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r4, [%[r], #24]\n\t"
        "str	r5, [%[r], #28]\n\t"
#else
        "strd	r4, r5, [%[r], #24]\n\t"
#endif
        : [r] "+r" (r), [a] "+r" (a)
        :
        : "memory", "r2", "r3", "r4", "r5"
    );
}

void fe_neg(fe r_p, const fe a_p)
{
    register fe r asm ("r0") = r_p;
    register const fe a asm ("r1") = a_p;

    __asm__ __volatile__ (
        "mvn	lr, #0\n\t"
        "mvn	r12, #18\n\t"
        "ldm	%[a]!, {r2, r3, r4, r5}\n\t"
        "subs	r2, r12, r2\n\t"
        "sbcs	r3, lr, r3\n\t"
        "sbcs	r4, lr, r4\n\t"
        "sbcs	r5, lr, r5\n\t"
        "stm	%[r]!, {r2, r3, r4, r5}\n\t"
        "mvn	r12, #0x80000000\n\t"
        "ldm	%[a]!, {r2, r3, r4, r5}\n\t"
        "sbcs	r2, lr, r2\n\t"
        "sbcs	r3, lr, r3\n\t"
        "sbcs	r4, lr, r4\n\t"
        "sbc	r5, r12, r5\n\t"
        "stm	%[r]!, {r2, r3, r4, r5}\n\t"
        : [r] "+r" (r), [a] "+r" (a)
        :
        : "memory", "r2", "r3", "r4", "r5", "r12", "lr"
    );
}

int fe_isnonzero(const fe a_p)
{
    register const fe a asm ("r0") = a_p;

    __asm__ __volatile__ (
        "ldm	%[a], {r2, r3, r4, r5, r6, r7, r8, r9}\n\t"
        "adds	r1, r2, #19\n\t"
        "adcs	r1, r3, #0\n\t"
        "adcs	r1, r4, #0\n\t"
        "adcs	r1, r5, #0\n\t"
        "adcs	r1, r6, #0\n\t"
        "adcs	r1, r7, #0\n\t"
        "adcs	r1, r8, #0\n\t"
        "adc	r1, r9, #0\n\t"
        "asr	r1, r1, #31\n\t"
        "and	r1, r1, #19\n\t"
        "adds	r2, r2, r1\n\t"
        "adcs	r3, r3, #0\n\t"
        "adcs	r4, r4, #0\n\t"
        "adcs	r5, r5, #0\n\t"
        "adcs	r6, r6, #0\n\t"
        "adcs	r7, r7, #0\n\t"
        "adcs	r8, r8, #0\n\t"
        "adc	r9, r9, #0\n\t"
        "bfc	r9, #31, #1\n\t"
        "orr	r2, r2, r3\n\t"
        "orr	r4, r4, r5\n\t"
        "orr	r6, r6, r7\n\t"
        "orr	r8, r8, r9\n\t"
        "orr	r4, r4, r6\n\t"
        "orr	r2, r2, r8\n\t"
        "orr	%[a], r2, r4\n\t"
        : [a] "+r" (a)
        :
        : "memory", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r12"
    );
    return (uint32_t)(size_t)a;
}

int fe_isnegative(const fe a_p)
{
    register const fe a asm ("r0") = a_p;

    __asm__ __volatile__ (
        "ldm	%[a]!, {r2, r3, r4, r5}\n\t"
        "adds	r1, r2, #19\n\t"
        "adcs	r1, r3, #0\n\t"
        "adcs	r1, r4, #0\n\t"
        "adcs	r1, r5, #0\n\t"
        "ldm	%[a], {r2, r3, r4, r5}\n\t"
        "adcs	r1, r2, #0\n\t"
        "adcs	r1, r3, #0\n\t"
        "adcs	r1, r4, #0\n\t"
        "ldr	r2, [%[a], #-16]\n\t"
        "adc	r1, r5, #0\n\t"
        "and	%[a], r2, #1\n\t"
        "lsr	r1, r1, #31\n\t"
        "eor	%[a], %[a], r1\n\t"
        : [a] "+r" (a)
        :
        : "memory", "r1", "r2", "r3", "r4", "r5"
    );
    return (uint32_t)(size_t)a;
}

#ifndef WC_NO_CACHE_RESISTANT
void fe_cmov_table(fe* r_p, fe* base_p, signed char b_p)
{
    register fe* r asm ("r0") = r_p;
    register fe* base asm ("r1") = base_p;
    register signed char b asm ("r2") = b_p;

    __asm__ __volatile__ (
        "sxtb	%[b], %[b]\n\t"
        "sbfx	r3, %[b], #7, #1\n\t"
        "eor	r12, %[b], r3\n\t"
        "sub	r12, r12, r3\n\t"
        "mov	r4, #1\n\t"
        "mov	r5, #0\n\t"
        "mov	r6, #1\n\t"
        "mov	r7, #0\n\t"
        "mov	r8, #0\n\t"
        "mov	r9, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #31\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base]]\n\t"
        "ldr	r11, [%[base], #4]\n\t"
#else
        "ldrd	r10, r11, [%[base]]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #32]\n\t"
        "ldr	r11, [%[base], #36]\n\t"
#else
        "ldrd	r10, r11, [%[base], #32]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #64]\n\t"
        "ldr	r11, [%[base], #68]\n\t"
#else
        "ldrd	r10, r11, [%[base], #64]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #30\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base]]\n\t"
        "ldr	r11, [%[base], #4]\n\t"
#else
        "ldrd	r10, r11, [%[base]]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #32]\n\t"
        "ldr	r11, [%[base], #36]\n\t"
#else
        "ldrd	r10, r11, [%[base], #32]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #64]\n\t"
        "ldr	r11, [%[base], #68]\n\t"
#else
        "ldrd	r10, r11, [%[base], #64]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #29\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base]]\n\t"
        "ldr	r11, [%[base], #4]\n\t"
#else
        "ldrd	r10, r11, [%[base]]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #32]\n\t"
        "ldr	r11, [%[base], #36]\n\t"
#else
        "ldrd	r10, r11, [%[base], #32]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #64]\n\t"
        "ldr	r11, [%[base], #68]\n\t"
#else
        "ldrd	r10, r11, [%[base], #64]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #28\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base]]\n\t"
        "ldr	r11, [%[base], #4]\n\t"
#else
        "ldrd	r10, r11, [%[base]]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #32]\n\t"
        "ldr	r11, [%[base], #36]\n\t"
#else
        "ldrd	r10, r11, [%[base], #32]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #64]\n\t"
        "ldr	r11, [%[base], #68]\n\t"
#else
        "ldrd	r10, r11, [%[base], #64]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #27\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base]]\n\t"
        "ldr	r11, [%[base], #4]\n\t"
#else
        "ldrd	r10, r11, [%[base]]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #32]\n\t"
        "ldr	r11, [%[base], #36]\n\t"
#else
        "ldrd	r10, r11, [%[base], #32]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #64]\n\t"
        "ldr	r11, [%[base], #68]\n\t"
#else
        "ldrd	r10, r11, [%[base], #64]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #26\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base]]\n\t"
        "ldr	r11, [%[base], #4]\n\t"
#else
        "ldrd	r10, r11, [%[base]]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #32]\n\t"
        "ldr	r11, [%[base], #36]\n\t"
#else
        "ldrd	r10, r11, [%[base], #32]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #64]\n\t"
        "ldr	r11, [%[base], #68]\n\t"
#else
        "ldrd	r10, r11, [%[base], #64]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #25\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base]]\n\t"
        "ldr	r11, [%[base], #4]\n\t"
#else
        "ldrd	r10, r11, [%[base]]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #32]\n\t"
        "ldr	r11, [%[base], #36]\n\t"
#else
        "ldrd	r10, r11, [%[base], #32]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #64]\n\t"
        "ldr	r11, [%[base], #68]\n\t"
#else
        "ldrd	r10, r11, [%[base], #64]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #24\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base]]\n\t"
        "ldr	r11, [%[base], #4]\n\t"
#else
        "ldrd	r10, r11, [%[base]]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #32]\n\t"
        "ldr	r11, [%[base], #36]\n\t"
#else
        "ldrd	r10, r11, [%[base], #32]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #64]\n\t"
        "ldr	r11, [%[base], #68]\n\t"
#else
        "ldrd	r10, r11, [%[base], #64]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "sub	%[base], %[base], #0x2a0\n\t"
        "mvn	r10, #18\n\t"
        "mvn	r11, #0\n\t"
        "subs	r10, r10, r8\n\t"
        "sbcs	r11, r11, r9\n\t"
        "sbc	lr, lr, lr\n\t"
        "asr	r12, %[b], #31\n\t"
        "eor	r3, r4, r6\n\t"
        "and	r3, r3, r12\n\t"
        "eor	r4, r4, r3\n\t"
        "eor	r6, r6, r3\n\t"
        "eor	r3, r5, r7\n\t"
        "and	r3, r3, r12\n\t"
        "eor	r5, r5, r3\n\t"
        "eor	r7, r7, r3\n\t"
        "eor	r10, r10, r8\n\t"
        "and	r10, r10, r12\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r11, r11, r12\n\t"
        "eor	r9, r9, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r4, [%[r]]\n\t"
        "str	r5, [%[r], #4]\n\t"
#else
        "strd	r4, r5, [%[r]]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r6, [%[r], #32]\n\t"
        "str	r7, [%[r], #36]\n\t"
#else
        "strd	r6, r7, [%[r], #32]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r8, [%[r], #64]\n\t"
        "str	r9, [%[r], #68]\n\t"
#else
        "strd	r8, r9, [%[r], #64]\n\t"
#endif
        "sbfx	r3, %[b], #7, #1\n\t"
        "eor	r12, %[b], r3\n\t"
        "sub	r12, r12, r3\n\t"
        "mov	r4, #0\n\t"
        "mov	r5, #0\n\t"
        "mov	r6, #0\n\t"
        "mov	r7, #0\n\t"
        "mov	r8, #0\n\t"
        "mov	r9, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #31\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #8]\n\t"
        "ldr	r11, [%[base], #12]\n\t"
#else
        "ldrd	r10, r11, [%[base], #8]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #40]\n\t"
        "ldr	r11, [%[base], #44]\n\t"
#else
        "ldrd	r10, r11, [%[base], #40]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #72]\n\t"
        "ldr	r11, [%[base], #76]\n\t"
#else
        "ldrd	r10, r11, [%[base], #72]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #30\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #8]\n\t"
        "ldr	r11, [%[base], #12]\n\t"
#else
        "ldrd	r10, r11, [%[base], #8]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #40]\n\t"
        "ldr	r11, [%[base], #44]\n\t"
#else
        "ldrd	r10, r11, [%[base], #40]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #72]\n\t"
        "ldr	r11, [%[base], #76]\n\t"
#else
        "ldrd	r10, r11, [%[base], #72]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #29\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #8]\n\t"
        "ldr	r11, [%[base], #12]\n\t"
#else
        "ldrd	r10, r11, [%[base], #8]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #40]\n\t"
        "ldr	r11, [%[base], #44]\n\t"
#else
        "ldrd	r10, r11, [%[base], #40]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #72]\n\t"
        "ldr	r11, [%[base], #76]\n\t"
#else
        "ldrd	r10, r11, [%[base], #72]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #28\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #8]\n\t"
        "ldr	r11, [%[base], #12]\n\t"
#else
        "ldrd	r10, r11, [%[base], #8]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #40]\n\t"
        "ldr	r11, [%[base], #44]\n\t"
#else
        "ldrd	r10, r11, [%[base], #40]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #72]\n\t"
        "ldr	r11, [%[base], #76]\n\t"
#else
        "ldrd	r10, r11, [%[base], #72]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #27\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #8]\n\t"
        "ldr	r11, [%[base], #12]\n\t"
#else
        "ldrd	r10, r11, [%[base], #8]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #40]\n\t"
        "ldr	r11, [%[base], #44]\n\t"
#else
        "ldrd	r10, r11, [%[base], #40]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #72]\n\t"
        "ldr	r11, [%[base], #76]\n\t"
#else
        "ldrd	r10, r11, [%[base], #72]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #26\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #8]\n\t"
        "ldr	r11, [%[base], #12]\n\t"
#else
        "ldrd	r10, r11, [%[base], #8]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #40]\n\t"
        "ldr	r11, [%[base], #44]\n\t"
#else
        "ldrd	r10, r11, [%[base], #40]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #72]\n\t"
        "ldr	r11, [%[base], #76]\n\t"
#else
        "ldrd	r10, r11, [%[base], #72]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #25\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #8]\n\t"
        "ldr	r11, [%[base], #12]\n\t"
#else
        "ldrd	r10, r11, [%[base], #8]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #40]\n\t"
        "ldr	r11, [%[base], #44]\n\t"
#else
        "ldrd	r10, r11, [%[base], #40]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #72]\n\t"
        "ldr	r11, [%[base], #76]\n\t"
#else
        "ldrd	r10, r11, [%[base], #72]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #24\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #8]\n\t"
        "ldr	r11, [%[base], #12]\n\t"
#else
        "ldrd	r10, r11, [%[base], #8]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #40]\n\t"
        "ldr	r11, [%[base], #44]\n\t"
#else
        "ldrd	r10, r11, [%[base], #40]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #72]\n\t"
        "ldr	r11, [%[base], #76]\n\t"
#else
        "ldrd	r10, r11, [%[base], #72]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "sub	%[base], %[base], #0x2a0\n\t"
        "mvn	r10, #0\n\t"
        "mvn	r11, #0\n\t"
        "rsbs	lr, lr, #0\n\t"
        "sbcs	r10, r10, r8\n\t"
        "sbcs	r11, r11, r9\n\t"
        "sbc	lr, lr, lr\n\t"
        "asr	r12, %[b], #31\n\t"
        "eor	r3, r4, r6\n\t"
        "and	r3, r3, r12\n\t"
        "eor	r4, r4, r3\n\t"
        "eor	r6, r6, r3\n\t"
        "eor	r3, r5, r7\n\t"
        "and	r3, r3, r12\n\t"
        "eor	r5, r5, r3\n\t"
        "eor	r7, r7, r3\n\t"
        "eor	r10, r10, r8\n\t"
        "and	r10, r10, r12\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r11, r11, r12\n\t"
        "eor	r9, r9, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r4, [%[r], #8]\n\t"
        "str	r5, [%[r], #12]\n\t"
#else
        "strd	r4, r5, [%[r], #8]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r6, [%[r], #40]\n\t"
        "str	r7, [%[r], #44]\n\t"
#else
        "strd	r6, r7, [%[r], #40]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r8, [%[r], #72]\n\t"
        "str	r9, [%[r], #76]\n\t"
#else
        "strd	r8, r9, [%[r], #72]\n\t"
#endif
        "sbfx	r3, %[b], #7, #1\n\t"
        "eor	r12, %[b], r3\n\t"
        "sub	r12, r12, r3\n\t"
        "mov	r4, #0\n\t"
        "mov	r5, #0\n\t"
        "mov	r6, #0\n\t"
        "mov	r7, #0\n\t"
        "mov	r8, #0\n\t"
        "mov	r9, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #31\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #16]\n\t"
        "ldr	r11, [%[base], #20]\n\t"
#else
        "ldrd	r10, r11, [%[base], #16]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #48]\n\t"
        "ldr	r11, [%[base], #52]\n\t"
#else
        "ldrd	r10, r11, [%[base], #48]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #80]\n\t"
        "ldr	r11, [%[base], #84]\n\t"
#else
        "ldrd	r10, r11, [%[base], #80]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #30\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #16]\n\t"
        "ldr	r11, [%[base], #20]\n\t"
#else
        "ldrd	r10, r11, [%[base], #16]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #48]\n\t"
        "ldr	r11, [%[base], #52]\n\t"
#else
        "ldrd	r10, r11, [%[base], #48]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #80]\n\t"
        "ldr	r11, [%[base], #84]\n\t"
#else
        "ldrd	r10, r11, [%[base], #80]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #29\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #16]\n\t"
        "ldr	r11, [%[base], #20]\n\t"
#else
        "ldrd	r10, r11, [%[base], #16]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #48]\n\t"
        "ldr	r11, [%[base], #52]\n\t"
#else
        "ldrd	r10, r11, [%[base], #48]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #80]\n\t"
        "ldr	r11, [%[base], #84]\n\t"
#else
        "ldrd	r10, r11, [%[base], #80]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #28\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #16]\n\t"
        "ldr	r11, [%[base], #20]\n\t"
#else
        "ldrd	r10, r11, [%[base], #16]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #48]\n\t"
        "ldr	r11, [%[base], #52]\n\t"
#else
        "ldrd	r10, r11, [%[base], #48]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #80]\n\t"
        "ldr	r11, [%[base], #84]\n\t"
#else
        "ldrd	r10, r11, [%[base], #80]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #27\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #16]\n\t"
        "ldr	r11, [%[base], #20]\n\t"
#else
        "ldrd	r10, r11, [%[base], #16]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #48]\n\t"
        "ldr	r11, [%[base], #52]\n\t"
#else
        "ldrd	r10, r11, [%[base], #48]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #80]\n\t"
        "ldr	r11, [%[base], #84]\n\t"
#else
        "ldrd	r10, r11, [%[base], #80]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #26\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #16]\n\t"
        "ldr	r11, [%[base], #20]\n\t"
#else
        "ldrd	r10, r11, [%[base], #16]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #48]\n\t"
        "ldr	r11, [%[base], #52]\n\t"
#else
        "ldrd	r10, r11, [%[base], #48]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #80]\n\t"
        "ldr	r11, [%[base], #84]\n\t"
#else
        "ldrd	r10, r11, [%[base], #80]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #25\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #16]\n\t"
        "ldr	r11, [%[base], #20]\n\t"
#else
        "ldrd	r10, r11, [%[base], #16]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #48]\n\t"
        "ldr	r11, [%[base], #52]\n\t"
#else
        "ldrd	r10, r11, [%[base], #48]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #80]\n\t"
        "ldr	r11, [%[base], #84]\n\t"
#else
        "ldrd	r10, r11, [%[base], #80]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #24\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #16]\n\t"
        "ldr	r11, [%[base], #20]\n\t"
#else
        "ldrd	r10, r11, [%[base], #16]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #48]\n\t"
        "ldr	r11, [%[base], #52]\n\t"
#else
        "ldrd	r10, r11, [%[base], #48]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #80]\n\t"
        "ldr	r11, [%[base], #84]\n\t"
#else
        "ldrd	r10, r11, [%[base], #80]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "sub	%[base], %[base], #0x2a0\n\t"
        "mvn	r10, #0\n\t"
        "mvn	r11, #0\n\t"
        "rsbs	lr, lr, #0\n\t"
        "sbcs	r10, r10, r8\n\t"
        "sbcs	r11, r11, r9\n\t"
        "sbc	lr, lr, lr\n\t"
        "asr	r12, %[b], #31\n\t"
        "eor	r3, r4, r6\n\t"
        "and	r3, r3, r12\n\t"
        "eor	r4, r4, r3\n\t"
        "eor	r6, r6, r3\n\t"
        "eor	r3, r5, r7\n\t"
        "and	r3, r3, r12\n\t"
        "eor	r5, r5, r3\n\t"
        "eor	r7, r7, r3\n\t"
        "eor	r10, r10, r8\n\t"
        "and	r10, r10, r12\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r11, r11, r12\n\t"
        "eor	r9, r9, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r4, [%[r], #16]\n\t"
        "str	r5, [%[r], #20]\n\t"
#else
        "strd	r4, r5, [%[r], #16]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r6, [%[r], #48]\n\t"
        "str	r7, [%[r], #52]\n\t"
#else
        "strd	r6, r7, [%[r], #48]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r8, [%[r], #80]\n\t"
        "str	r9, [%[r], #84]\n\t"
#else
        "strd	r8, r9, [%[r], #80]\n\t"
#endif
        "sbfx	r3, %[b], #7, #1\n\t"
        "eor	r12, %[b], r3\n\t"
        "sub	r12, r12, r3\n\t"
        "mov	r4, #0\n\t"
        "mov	r5, #0\n\t"
        "mov	r6, #0\n\t"
        "mov	r7, #0\n\t"
        "mov	r8, #0\n\t"
        "mov	r9, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #31\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #24]\n\t"
        "ldr	r11, [%[base], #28]\n\t"
#else
        "ldrd	r10, r11, [%[base], #24]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #56]\n\t"
        "ldr	r11, [%[base], #60]\n\t"
#else
        "ldrd	r10, r11, [%[base], #56]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #88]\n\t"
        "ldr	r11, [%[base], #92]\n\t"
#else
        "ldrd	r10, r11, [%[base], #88]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #30\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #24]\n\t"
        "ldr	r11, [%[base], #28]\n\t"
#else
        "ldrd	r10, r11, [%[base], #24]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #56]\n\t"
        "ldr	r11, [%[base], #60]\n\t"
#else
        "ldrd	r10, r11, [%[base], #56]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #88]\n\t"
        "ldr	r11, [%[base], #92]\n\t"
#else
        "ldrd	r10, r11, [%[base], #88]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #29\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #24]\n\t"
        "ldr	r11, [%[base], #28]\n\t"
#else
        "ldrd	r10, r11, [%[base], #24]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #56]\n\t"
        "ldr	r11, [%[base], #60]\n\t"
#else
        "ldrd	r10, r11, [%[base], #56]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #88]\n\t"
        "ldr	r11, [%[base], #92]\n\t"
#else
        "ldrd	r10, r11, [%[base], #88]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #28\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #24]\n\t"
        "ldr	r11, [%[base], #28]\n\t"
#else
        "ldrd	r10, r11, [%[base], #24]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #56]\n\t"
        "ldr	r11, [%[base], #60]\n\t"
#else
        "ldrd	r10, r11, [%[base], #56]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #88]\n\t"
        "ldr	r11, [%[base], #92]\n\t"
#else
        "ldrd	r10, r11, [%[base], #88]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #27\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #24]\n\t"
        "ldr	r11, [%[base], #28]\n\t"
#else
        "ldrd	r10, r11, [%[base], #24]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #56]\n\t"
        "ldr	r11, [%[base], #60]\n\t"
#else
        "ldrd	r10, r11, [%[base], #56]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #88]\n\t"
        "ldr	r11, [%[base], #92]\n\t"
#else
        "ldrd	r10, r11, [%[base], #88]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #26\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #24]\n\t"
        "ldr	r11, [%[base], #28]\n\t"
#else
        "ldrd	r10, r11, [%[base], #24]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #56]\n\t"
        "ldr	r11, [%[base], #60]\n\t"
#else
        "ldrd	r10, r11, [%[base], #56]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #88]\n\t"
        "ldr	r11, [%[base], #92]\n\t"
#else
        "ldrd	r10, r11, [%[base], #88]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #25\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #24]\n\t"
        "ldr	r11, [%[base], #28]\n\t"
#else
        "ldrd	r10, r11, [%[base], #24]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #56]\n\t"
        "ldr	r11, [%[base], #60]\n\t"
#else
        "ldrd	r10, r11, [%[base], #56]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #88]\n\t"
        "ldr	r11, [%[base], #92]\n\t"
#else
        "ldrd	r10, r11, [%[base], #88]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "add	%[base], %[base], #0x60\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x800000\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x0\n\t"
#else
        "mov	r3, #0x80000000\n\t"
#endif
        "ror	r3, r3, #24\n\t"
        "ror	r3, r3, r12\n\t"
        "asr	r3, r3, #31\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #24]\n\t"
        "ldr	r11, [%[base], #28]\n\t"
#else
        "ldrd	r10, r11, [%[base], #24]\n\t"
#endif
        "eor	r10, r10, r4\n\t"
        "eor	r11, r11, r5\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #56]\n\t"
        "ldr	r11, [%[base], #60]\n\t"
#else
        "ldrd	r10, r11, [%[base], #56]\n\t"
#endif
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r10, [%[base], #88]\n\t"
        "ldr	r11, [%[base], #92]\n\t"
#else
        "ldrd	r10, r11, [%[base], #88]\n\t"
#endif
        "eor	r10, r10, r8\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r9, r9, r11\n\t"
        "sub	%[base], %[base], #0x2a0\n\t"
        "mvn	r10, #0\n\t"
        "mvn	r11, #0x80000000\n\t"
        "rsbs	lr, lr, #0\n\t"
        "sbcs	r10, r10, r8\n\t"
        "sbc	r11, r11, r9\n\t"
        "asr	r12, %[b], #31\n\t"
        "eor	r3, r4, r6\n\t"
        "and	r3, r3, r12\n\t"
        "eor	r4, r4, r3\n\t"
        "eor	r6, r6, r3\n\t"
        "eor	r3, r5, r7\n\t"
        "and	r3, r3, r12\n\t"
        "eor	r5, r5, r3\n\t"
        "eor	r7, r7, r3\n\t"
        "eor	r10, r10, r8\n\t"
        "and	r10, r10, r12\n\t"
        "eor	r8, r8, r10\n\t"
        "eor	r11, r11, r9\n\t"
        "and	r11, r11, r12\n\t"
        "eor	r9, r9, r11\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r4, [%[r], #24]\n\t"
        "str	r5, [%[r], #28]\n\t"
#else
        "strd	r4, r5, [%[r], #24]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r6, [%[r], #56]\n\t"
        "str	r7, [%[r], #60]\n\t"
#else
        "strd	r6, r7, [%[r], #56]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r8, [%[r], #88]\n\t"
        "str	r9, [%[r], #92]\n\t"
#else
        "strd	r8, r9, [%[r], #88]\n\t"
#endif
        : [r] "+r" (r), [base] "+r" (base), [b] "+r" (b)
        :
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9", "r3", "r10", "r11", "r12", "lr"
    );
}

#else
void fe_cmov_table(fe* r_p, fe* base_p, signed char b_p)
{
    register fe* r asm ("r0") = r_p;
    register fe* base asm ("r1") = base_p;
    register signed char b asm ("r2") = b_p;

    __asm__ __volatile__ (
        "sxtb	%[b], %[b]\n\t"
        "sbfx	r3, %[b], #7, #1\n\t"
        "eor	%[b], %[b], r3\n\t"
        "sub	%[b], %[b], r3\n\t"
        "clz	lr, %[b]\n\t"
        "lsl	lr, lr, #26\n\t"
        "asr	lr, lr, #31\n\t"
        "mvn	lr, lr\n\t"
        "add	%[b], %[b], lr\n\t"
        "mov	r12, #0x60\n\t"
        "mul	%[b], %[b], r12\n\t"
        "add	%[base], %[base], %[b]\n\t"
        "ldm	%[base]!, {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        "and	r4, r4, lr\n\t"
        "and	r5, r5, lr\n\t"
        "and	r6, r6, lr\n\t"
        "and	r7, r7, lr\n\t"
        "and	r8, r8, lr\n\t"
        "and	r9, r9, lr\n\t"
        "and	r10, r10, lr\n\t"
        "and	r11, r11, lr\n\t"
        "mvn	r12, lr\n\t"
        "sub	r4, r4, r12\n\t"
        "mov	r12, #32\n\t"
        "and	r12, r12, r3\n\t"
        "add	%[r], %[r], r12\n\t"
        "stm	%[r], {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        "sub	%[r], %[r], r12\n\t"
        "ldm	%[base]!, {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        "and	r4, r4, lr\n\t"
        "and	r5, r5, lr\n\t"
        "and	r6, r6, lr\n\t"
        "and	r7, r7, lr\n\t"
        "and	r8, r8, lr\n\t"
        "and	r9, r9, lr\n\t"
        "and	r10, r10, lr\n\t"
        "and	r11, r11, lr\n\t"
        "mvn	r12, lr\n\t"
        "sub	r4, r4, r12\n\t"
        "mov	r12, #32\n\t"
        "bic	r12, r12, r3\n\t"
        "add	%[r], %[r], r12\n\t"
        "stm	%[r], {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        "sub	%[r], %[r], r12\n\t"
        "add	%[r], %[r], #0x40\n\t"
        "ldm	%[base]!, {r4, r5, r6, r7}\n\t"
        "mvn	r12, #18\n\t"
        "subs	r8, r12, r4\n\t"
        "sbcs	r9, r3, r5\n\t"
        "sbcs	r10, r3, r6\n\t"
        "sbcs	r11, r3, r7\n\t"
        "bic	r4, r4, r3\n\t"
        "bic	r5, r5, r3\n\t"
        "bic	r6, r6, r3\n\t"
        "bic	r7, r7, r3\n\t"
        "and	r8, r8, r3\n\t"
        "and	r9, r9, r3\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "orr	r4, r4, r8\n\t"
        "orr	r5, r5, r9\n\t"
        "orr	r6, r6, r10\n\t"
        "orr	r7, r7, r11\n\t"
        "and	r4, r4, lr\n\t"
        "and	r5, r5, lr\n\t"
        "and	r6, r6, lr\n\t"
        "and	r7, r7, lr\n\t"
        "stm	%[r]!, {r4, r5, r6, r7}\n\t"
        "ldm	%[base]!, {r4, r5, r6, r7}\n\t"
        "mvn	r12, #0x80000000\n\t"
        "sbcs	r8, r3, r4\n\t"
        "sbcs	r9, r3, r5\n\t"
        "sbcs	r10, r3, r6\n\t"
        "sbc	r11, r12, r7\n\t"
        "bic	r4, r4, r3\n\t"
        "bic	r5, r5, r3\n\t"
        "bic	r6, r6, r3\n\t"
        "bic	r7, r7, r3\n\t"
        "and	r8, r8, r3\n\t"
        "and	r9, r9, r3\n\t"
        "and	r10, r10, r3\n\t"
        "and	r11, r11, r3\n\t"
        "orr	r4, r4, r8\n\t"
        "orr	r5, r5, r9\n\t"
        "orr	r6, r6, r10\n\t"
        "orr	r7, r7, r11\n\t"
        "and	r4, r4, lr\n\t"
        "and	r5, r5, lr\n\t"
        "and	r6, r6, lr\n\t"
        "and	r7, r7, lr\n\t"
        "stm	%[r]!, {r4, r5, r6, r7}\n\t"
        "sub	%[base], %[base], %[b]\n\t"
        : [r] "+r" (r), [base] "+r" (base), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr"
    );
}

#endif /* WC_NO_CACHE_RESISTANT */
#endif /* HAVE_ED25519 */
void fe_mul_op(void);
void fe_mul_op()
{

    __asm__ __volatile__ (
        "sub	sp, sp, #44\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r0, [sp, #36]\n\t"
        "str	r1, [sp, #40]\n\t"
#else
        "strd	r0, r1, [sp, #36]\n\t"
#endif
        "mov	lr, r2\n\t"
        "ldm	r1, {r0, r1, r2, r3}\n\t"
        "ldm	lr!, {r4, r5, r6}\n\t"
        "umull	r10, r11, r0, r4\n\t"
        "umull	r12, r7, r1, r4\n\t"
        "umaal	r11, r12, r0, r5\n\t"
        "umull	r8, r9, r2, r4\n\t"
        "umaal	r12, r8, r1, r5\n\t"
        "umaal	r12, r7, r0, r6\n\t"
        "umaal	r8, r9, r3, r4\n\t"
        "stm	sp, {r10, r11, r12}\n\t"
        "umaal	r7, r8, r2, r5\n\t"
        "ldm	lr!, {r4}\n\t"
        "umull	r10, r11, r1, r6\n\t"
        "umaal	r8, r9, r2, r6\n\t"
        "umaal	r7, r10, r0, r4\n\t"
        "umaal	r8, r11, r3, r5\n\t"
        "str	r7, [sp, #12]\n\t"
        "umaal	r8, r10, r1, r4\n\t"
        "umaal	r9, r11, r3, r6\n\t"
        "umaal	r9, r10, r2, r4\n\t"
        "umaal	r10, r11, r3, r4\n\t"
        "ldm	lr, {r4, r5, r6, r7}\n\t"
        "mov	r12, #0\n\t"
        "umlal	r8, r12, r0, r4\n\t"
        "umaal	r9, r12, r1, r4\n\t"
        "umaal	r10, r12, r2, r4\n\t"
        "umaal	r11, r12, r3, r4\n\t"
        "mov	r4, #0\n\t"
        "umlal	r9, r4, r0, r5\n\t"
        "umaal	r10, r4, r1, r5\n\t"
        "umaal	r11, r4, r2, r5\n\t"
        "umaal	r12, r4, r3, r5\n\t"
        "mov	r5, #0\n\t"
        "umlal	r10, r5, r0, r6\n\t"
        "umaal	r11, r5, r1, r6\n\t"
        "umaal	r12, r5, r2, r6\n\t"
        "umaal	r4, r5, r3, r6\n\t"
        "mov	r6, #0\n\t"
        "umlal	r11, r6, r0, r7\n\t"
        "ldr	r0, [sp, #40]\n\t"
        "umaal	r12, r6, r1, r7\n\t"
        "add	r0, r0, #16\n\t"
        "umaal	r4, r6, r2, r7\n\t"
        "sub	lr, lr, #16\n\t"
        "umaal	r5, r6, r3, r7\n\t"
        "ldm	r0, {r0, r1, r2, r3}\n\t"
        "str	r6, [sp, #32]\n\t"
        "ldm	lr!, {r6}\n\t"
        "mov	r7, #0\n\t"
        "umlal	r8, r7, r0, r6\n\t"
        "umaal	r9, r7, r1, r6\n\t"
        "str	r8, [sp, #16]\n\t"
        "umaal	r10, r7, r2, r6\n\t"
        "umaal	r11, r7, r3, r6\n\t"
        "ldm	lr!, {r6}\n\t"
        "mov	r8, #0\n\t"
        "umlal	r9, r8, r0, r6\n\t"
        "umaal	r10, r8, r1, r6\n\t"
        "str	r9, [sp, #20]\n\t"
        "umaal	r11, r8, r2, r6\n\t"
        "umaal	r12, r8, r3, r6\n\t"
        "ldm	lr!, {r6}\n\t"
        "mov	r9, #0\n\t"
        "umlal	r10, r9, r0, r6\n\t"
        "umaal	r11, r9, r1, r6\n\t"
        "str	r10, [sp, #24]\n\t"
        "umaal	r12, r9, r2, r6\n\t"
        "umaal	r4, r9, r3, r6\n\t"
        "ldm	lr!, {r6}\n\t"
        "mov	r10, #0\n\t"
        "umlal	r11, r10, r0, r6\n\t"
        "umaal	r12, r10, r1, r6\n\t"
        "str	r11, [sp, #28]\n\t"
        "umaal	r4, r10, r2, r6\n\t"
        "umaal	r5, r10, r3, r6\n\t"
        "ldm	lr!, {r11}\n\t"
        "umaal	r12, r7, r0, r11\n\t"
        "umaal	r4, r7, r1, r11\n\t"
        "ldr	r6, [sp, #32]\n\t"
        "umaal	r5, r7, r2, r11\n\t"
        "umaal	r6, r7, r3, r11\n\t"
        "ldm	lr!, {r11}\n\t"
        "umaal	r4, r8, r0, r11\n\t"
        "umaal	r5, r8, r1, r11\n\t"
        "umaal	r6, r8, r2, r11\n\t"
        "umaal	r7, r8, r3, r11\n\t"
        "ldm	lr, {r11, lr}\n\t"
        "umaal	r5, r9, r0, r11\n\t"
        "umaal	r6, r10, r0, lr\n\t"
        "umaal	r6, r9, r1, r11\n\t"
        "umaal	r7, r10, r1, lr\n\t"
        "umaal	r7, r9, r2, r11\n\t"
        "umaal	r8, r10, r2, lr\n\t"
        "umaal	r8, r9, r3, r11\n\t"
        "umaal	r9, r10, r3, lr\n\t"
        /* Reduce */
        "ldr	r0, [sp, #28]\n\t"
        "mov	lr, #37\n\t"
        "umaal	r10, r0, r10, lr\n\t"
        "mov	lr, #19\n\t"
        "lsl	r0, r0, #1\n\t"
        "orr	r0, r0, r10, lsr #31\n\t"
        "mul	r11, r0, lr\n\t"
        "pop	{r0-r2}\n\t"
        "mov	lr, #38\n\t"
        "umaal	r0, r11, r12, lr\n\t"
        "umaal	r1, r11, r4, lr\n\t"
        "umaal	r2, r11, r5, lr\n\t"
        "pop	{r3-r5}\n\t"
        "umaal	r3, r11, r6, lr\n\t"
        "umaal	r4, r11, r7, lr\n\t"
        "umaal	r5, r11, r8, lr\n\t"
        "pop	{r6}\n\t"
        "bfc	r10, #31, #1\n\t"
        "umaal	r6, r11, r9, lr\n\t"
        "add	r7, r10, r11\n\t"
        "ldr	lr, [sp, #8]\n\t"
        /* Store */
        "stm	lr, {r0, r1, r2, r3, r4, r5, r6, r7}\n\t"
        "add	sp, sp, #16\n\t"
        :
        :
        : "memory", "lr"
    );
}

void fe_mul(fe r_p, const fe a_p, const fe b_p)
{
    register fe r asm ("r0") = r_p;
    register const fe a asm ("r1") = a_p;
    register const fe b asm ("r2") = b_p;

    __asm__ __volatile__ (
        "bl	fe_mul_op\n\t"
        : [r] "+r" (r), [a] "+r" (a), [b] "+r" (b)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr"
    );
}

void fe_sq_op(void);
void fe_sq_op()
{

    __asm__ __volatile__ (
        "sub	sp, sp, #32\n\t"
        "str	r0, [sp, #28]\n\t"
        "ldm	r1, {r0, r1, r2, r3, r4, r5, r6, r7}\n\t"
        /* Square */
        "umull	r9, r10, r0, r0\n\t"
        "umull	r11, r12, r0, r1\n\t"
        "adds	r11, r11, r11\n\t"
        "mov	lr, #0\n\t"
        "umaal	r10, r11, lr, lr\n\t"
        "stm	sp, {r9, r10}\n\t"
        "mov	r8, lr\n\t"
        "umaal	r8, r12, r0, r2\n\t"
        "adcs	r8, r8, r8\n\t"
        "umaal	r8, r11, r1, r1\n\t"
        "umull	r9, r10, r0, r3\n\t"
        "umaal	r9, r12, r1, r2\n\t"
        "adcs	r9, r9, r9\n\t"
        "umaal	r9, r11, lr, lr\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r8, [sp, #8]\n\t"
        "str	r9, [sp, #12]\n\t"
#else
        "strd	r8, r9, [sp, #8]\n\t"
#endif
        "mov	r9, lr\n\t"
        "umaal	r9, r10, r0, r4\n\t"
        "umaal	r9, r12, r1, r3\n\t"
        "adcs	r9, r9, r9\n\t"
        "umaal	r9, r11, r2, r2\n\t"
        "str	r9, [sp, #16]\n\t"
        "umull	r9, r8, r0, r5\n\t"
        "umaal	r9, r12, r1, r4\n\t"
        "umaal	r9, r10, r2, r3\n\t"
        "adcs	r9, r9, r9\n\t"
        "umaal	r9, r11, lr, lr\n\t"
        "str	r9, [sp, #20]\n\t"
        "mov	r9, lr\n\t"
        "umaal	r9, r8, r0, r6\n\t"
        "umaal	r9, r12, r1, r5\n\t"
        "umaal	r9, r10, r2, r4\n\t"
        "adcs	r9, r9, r9\n\t"
        "umaal	r9, r11, r3, r3\n\t"
        "str	r9, [sp, #24]\n\t"
        "umull	r0, r9, r0, r7\n\t"
        "umaal	r0, r8, r1, r6\n\t"
        "umaal	r0, r12, r2, r5\n\t"
        "umaal	r0, r10, r3, r4\n\t"
        "adcs	r0, r0, r0\n\t"
        "umaal	r0, r11, lr, lr\n\t"
        /* R[7] = r0 */
        "umaal	r9, r8, r1, r7\n\t"
        "umaal	r9, r10, r2, r6\n\t"
        "umaal	r12, r9, r3, r5\n\t"
        "adcs	r12, r12, r12\n\t"
        "umaal	r12, r11, r4, r4\n\t"
        /* R[8] = r12 */
        "umaal	r9, r8, r2, r7\n\t"
        "umaal	r10, r9, r3, r6\n\t"
        "mov	r2, lr\n\t"
        "umaal	r10, r2, r4, r5\n\t"
        "adcs	r10, r10, r10\n\t"
        "umaal	r11, r10, lr, lr\n\t"
        /* R[9] = r11 */
        "umaal	r2, r8, r3, r7\n\t"
        "umaal	r2, r9, r4, r6\n\t"
        "adcs	r3, r2, r2\n\t"
        "umaal	r10, r3, r5, r5\n\t"
        /* R[10] = r10 */
        "mov	r1, lr\n\t"
        "umaal	r1, r8, r4, r7\n\t"
        "umaal	r1, r9, r5, r6\n\t"
        "adcs	r4, r1, r1\n\t"
        "umaal	r3, r4, lr, lr\n\t"
        /* R[11] = r3 */
        "umaal	r8, r9, r5, r7\n\t"
        "adcs	r8, r8, r8\n\t"
        "umaal	r4, r8, r6, r6\n\t"
        /* R[12] = r4 */
        "mov	r5, lr\n\t"
        "umaal	r5, r9, r6, r7\n\t"
        "adcs	r5, r5, r5\n\t"
        "umaal	r8, r5, lr, lr\n\t"
        /* R[13] = r8 */
        "adcs	r9, r9, r9\n\t"
        "umaal	r9, r5, r7, r7\n\t"
        "adcs	r7, r5, lr\n\t"
        /* R[14] = r9 */
        /* R[15] = r7 */
        /* Reduce */
        "mov	r6, #37\n\t"
        "umaal	r7, r0, r7, r6\n\t"
        "mov	r6, #19\n\t"
        "lsl	r0, r0, #1\n\t"
        "orr	r0, r0, r7, lsr #31\n\t"
        "mul	lr, r0, r6\n\t"
        "pop	{r0-r1}\n\t"
        "mov	r6, #38\n\t"
        "umaal	r0, lr, r12, r6\n\t"
        "umaal	r1, lr, r11, r6\n\t"
        "mov	r12, r3\n\t"
        "mov	r11, r4\n\t"
        "pop	{r2-r4}\n\t"
        "umaal	r2, lr, r10, r6\n\t"
        "umaal	r3, lr, r12, r6\n\t"
        "umaal	r4, lr, r11, r6\n\t"
        "mov	r12, r6\n\t"
        "pop	{r5-r6}\n\t"
        "umaal	r5, lr, r8, r12\n\t"
        "bfc	r7, #31, #1\n\t"
        "umaal	r6, lr, r9, r12\n\t"
        "add	r7, r7, lr\n\t"
        "pop	{lr}\n\t"
        /* Store */
        "stm	lr, {r0, r1, r2, r3, r4, r5, r6, r7}\n\t"
        :
        :
        : "memory", "lr"
    );
}

void fe_sq(fe r_p, const fe a_p)
{
    register fe r asm ("r0") = r_p;
    register const fe a asm ("r1") = a_p;

    __asm__ __volatile__ (
        "bl	fe_sq_op\n\t"
        : [r] "+r" (r), [a] "+r" (a)
        :
        : "memory", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r12", "lr", "r10", "r11"
    );
}

void fe_mul121666(fe r_p, fe a_p)
{
    register fe r asm ("r0") = r_p;
    register fe a asm ("r1") = a_p;

    __asm__ __volatile__ (
        /* Multiply by 121666 */
        "ldm	%[a], {r2, r3, r4, r5, r6, r7, r8, r9}\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	lr, #0xdb\n\t"
        "lsl	lr, lr, #8\n\t"
        "add	lr, lr, #0x42\n\t"
#else
        "mov	lr, #0xdb42\n\t"
#endif
        "movt	lr, #1\n\t"
        "umull	r2, r10, r2, lr\n\t"
        "sub	r12, lr, #1\n\t"
        "umaal	r3, r10, r3, r12\n\t"
        "umaal	r4, r10, r4, r12\n\t"
        "umaal	r5, r10, r5, r12\n\t"
        "umaal	r6, r10, r6, r12\n\t"
        "umaal	r7, r10, r7, r12\n\t"
        "umaal	r8, r10, r8, r12\n\t"
        "mov	lr, #19\n\t"
        "umaal	r9, r10, r9, r12\n\t"
        "lsl	r10, r10, #1\n\t"
        "orr	r10, r10, r9, lsr #31\n\t"
        "mul	r10, r10, lr\n\t"
        "adds	r2, r2, r10\n\t"
        "adcs	r3, r3, #0\n\t"
        "adcs	r4, r4, #0\n\t"
        "adcs	r5, r5, #0\n\t"
        "adcs	r6, r6, #0\n\t"
        "adcs	r7, r7, #0\n\t"
        "bfc	r9, #31, #1\n\t"
        "adcs	r8, r8, #0\n\t"
        "adc	r9, r9, #0\n\t"
        "stm	%[r], {r2, r3, r4, r5, r6, r7, r8, r9}\n\t"
        : [r] "+r" (r), [a] "+r" (a)
        :
        : "memory", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r12", "lr", "r10"
    );
}

#ifndef WC_NO_CACHE_RESISTANT
int curve25519(byte* r_p, const byte* n_p, const byte* a_p)
{
    register byte* r asm ("r0") = r_p;
    register const byte* n asm ("r1") = n_p;
    register const byte* a asm ("r2") = a_p;

    __asm__ __volatile__ (
        "sub	sp, sp, #0xbc\n\t"
        "str	%[r], [sp, #160]\n\t"
        "str	%[n], [sp, #164]\n\t"
        "str	%[a], [sp, #168]\n\t"
        "mov	%[n], #0\n\t"
        "str	%[n], [sp, #172]\n\t"
        /* Set one */
        "mov	r10, #1\n\t"
        "mov	r11, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [%[r]]\n\t"
        "str	r11, [%[r], #4]\n\t"
#else
        "strd	r10, r11, [%[r]]\n\t"
#endif
        "mov	r10, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [%[r], #8]\n\t"
        "str	r11, [%[r], #12]\n\t"
#else
        "strd	r10, r11, [%[r], #8]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [%[r], #16]\n\t"
        "str	r11, [%[r], #20]\n\t"
#else
        "strd	r10, r11, [%[r], #16]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [%[r], #24]\n\t"
        "str	r11, [%[r], #28]\n\t"
#else
        "strd	r10, r11, [%[r], #24]\n\t"
#endif
        /* Set zero */
        "mov	r10, #0\n\t"
        "mov	r11, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [sp]\n\t"
        "str	r11, [sp, #4]\n\t"
#else
        "strd	r10, r11, [sp]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [sp, #8]\n\t"
        "str	r11, [sp, #12]\n\t"
#else
        "strd	r10, r11, [sp, #8]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [sp, #16]\n\t"
        "str	r11, [sp, #20]\n\t"
#else
        "strd	r10, r11, [sp, #16]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [sp, #24]\n\t"
        "str	r11, [sp, #28]\n\t"
#else
        "strd	r10, r11, [sp, #24]\n\t"
#endif
        /* Set one */
        "mov	r10, #1\n\t"
        "mov	r11, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [sp, #32]\n\t"
        "str	r11, [sp, #36]\n\t"
#else
        "strd	r10, r11, [sp, #32]\n\t"
#endif
        "mov	r10, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [sp, #40]\n\t"
        "str	r11, [sp, #44]\n\t"
#else
        "strd	r10, r11, [sp, #40]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [sp, #48]\n\t"
        "str	r11, [sp, #52]\n\t"
#else
        "strd	r10, r11, [sp, #48]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [sp, #56]\n\t"
        "str	r11, [sp, #60]\n\t"
#else
        "strd	r10, r11, [sp, #56]\n\t"
#endif
        "add	r3, sp, #0x40\n\t"
        /* Copy */
        "ldm	r2, {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        "stm	r3, {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        "mov	%[n], #30\n\t"
        "str	%[n], [sp, #180]\n\t"
        "mov	%[a], #28\n\t"
        "str	%[a], [sp, #176]\n\t"
        "\n"
    "L_curve25519_words_%=: \n\t"
        "\n"
    "L_curve25519_bits_%=: \n\t"
        "ldr	%[n], [sp, #164]\n\t"
        "ldr	%[a], [%[n], r2]\n\t"
        "ldr	%[n], [sp, #180]\n\t"
        "lsr	%[a], %[a], %[n]\n\t"
        "and	%[a], %[a], #1\n\t"
        "str	%[a], [sp, #184]\n\t"
        "ldr	%[n], [sp, #172]\n\t"
        "eor	%[n], %[n], %[a]\n\t"
        "str	%[n], [sp, #172]\n\t"
        "ldr	%[r], [sp, #160]\n\t"
        /* Conditional Swap */
        "rsb	%[n], %[n], #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r4, [%[r]]\n\t"
        "ldr	r5, [%[r], #4]\n\t"
#else
        "ldrd	r4, r5, [%[r]]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r6, [sp, #64]\n\t"
        "ldr	r7, [sp, #68]\n\t"
#else
        "ldrd	r6, r7, [sp, #64]\n\t"
#endif
        "eor	r8, r4, r6\n\t"
        "eor	r9, r5, r7\n\t"
        "and	r8, r8, %[n]\n\t"
        "and	r9, r9, %[n]\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r9\n\t"
        "eor	r6, r6, r8\n\t"
        "eor	r7, r7, r9\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r4, [%[r]]\n\t"
        "str	r5, [%[r], #4]\n\t"
#else
        "strd	r4, r5, [%[r]]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r6, [sp, #64]\n\t"
        "str	r7, [sp, #68]\n\t"
#else
        "strd	r6, r7, [sp, #64]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r4, [%[r], #8]\n\t"
        "ldr	r5, [%[r], #12]\n\t"
#else
        "ldrd	r4, r5, [%[r], #8]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r6, [sp, #72]\n\t"
        "ldr	r7, [sp, #76]\n\t"
#else
        "ldrd	r6, r7, [sp, #72]\n\t"
#endif
        "eor	r8, r4, r6\n\t"
        "eor	r9, r5, r7\n\t"
        "and	r8, r8, %[n]\n\t"
        "and	r9, r9, %[n]\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r9\n\t"
        "eor	r6, r6, r8\n\t"
        "eor	r7, r7, r9\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r4, [%[r], #8]\n\t"
        "str	r5, [%[r], #12]\n\t"
#else
        "strd	r4, r5, [%[r], #8]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r6, [sp, #72]\n\t"
        "str	r7, [sp, #76]\n\t"
#else
        "strd	r6, r7, [sp, #72]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r4, [%[r], #16]\n\t"
        "ldr	r5, [%[r], #20]\n\t"
#else
        "ldrd	r4, r5, [%[r], #16]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r6, [sp, #80]\n\t"
        "ldr	r7, [sp, #84]\n\t"
#else
        "ldrd	r6, r7, [sp, #80]\n\t"
#endif
        "eor	r8, r4, r6\n\t"
        "eor	r9, r5, r7\n\t"
        "and	r8, r8, %[n]\n\t"
        "and	r9, r9, %[n]\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r9\n\t"
        "eor	r6, r6, r8\n\t"
        "eor	r7, r7, r9\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r4, [%[r], #16]\n\t"
        "str	r5, [%[r], #20]\n\t"
#else
        "strd	r4, r5, [%[r], #16]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r6, [sp, #80]\n\t"
        "str	r7, [sp, #84]\n\t"
#else
        "strd	r6, r7, [sp, #80]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r4, [%[r], #24]\n\t"
        "ldr	r5, [%[r], #28]\n\t"
#else
        "ldrd	r4, r5, [%[r], #24]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r6, [sp, #88]\n\t"
        "ldr	r7, [sp, #92]\n\t"
#else
        "ldrd	r6, r7, [sp, #88]\n\t"
#endif
        "eor	r8, r4, r6\n\t"
        "eor	r9, r5, r7\n\t"
        "and	r8, r8, %[n]\n\t"
        "and	r9, r9, %[n]\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r9\n\t"
        "eor	r6, r6, r8\n\t"
        "eor	r7, r7, r9\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r4, [%[r], #24]\n\t"
        "str	r5, [%[r], #28]\n\t"
#else
        "strd	r4, r5, [%[r], #24]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r6, [sp, #88]\n\t"
        "str	r7, [sp, #92]\n\t"
#else
        "strd	r6, r7, [sp, #88]\n\t"
#endif
        "ldr	%[n], [sp, #172]\n\t"
        /* Conditional Swap */
        "rsb	%[n], %[n], #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r4, [sp]\n\t"
        "ldr	r5, [sp, #4]\n\t"
#else
        "ldrd	r4, r5, [sp]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r6, [sp, #32]\n\t"
        "ldr	r7, [sp, #36]\n\t"
#else
        "ldrd	r6, r7, [sp, #32]\n\t"
#endif
        "eor	r8, r4, r6\n\t"
        "eor	r9, r5, r7\n\t"
        "and	r8, r8, %[n]\n\t"
        "and	r9, r9, %[n]\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r9\n\t"
        "eor	r6, r6, r8\n\t"
        "eor	r7, r7, r9\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r4, [sp]\n\t"
        "str	r5, [sp, #4]\n\t"
#else
        "strd	r4, r5, [sp]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r6, [sp, #32]\n\t"
        "str	r7, [sp, #36]\n\t"
#else
        "strd	r6, r7, [sp, #32]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r4, [sp, #8]\n\t"
        "ldr	r5, [sp, #12]\n\t"
#else
        "ldrd	r4, r5, [sp, #8]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r6, [sp, #40]\n\t"
        "ldr	r7, [sp, #44]\n\t"
#else
        "ldrd	r6, r7, [sp, #40]\n\t"
#endif
        "eor	r8, r4, r6\n\t"
        "eor	r9, r5, r7\n\t"
        "and	r8, r8, %[n]\n\t"
        "and	r9, r9, %[n]\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r9\n\t"
        "eor	r6, r6, r8\n\t"
        "eor	r7, r7, r9\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r4, [sp, #8]\n\t"
        "str	r5, [sp, #12]\n\t"
#else
        "strd	r4, r5, [sp, #8]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r6, [sp, #40]\n\t"
        "str	r7, [sp, #44]\n\t"
#else
        "strd	r6, r7, [sp, #40]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r4, [sp, #16]\n\t"
        "ldr	r5, [sp, #20]\n\t"
#else
        "ldrd	r4, r5, [sp, #16]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r6, [sp, #48]\n\t"
        "ldr	r7, [sp, #52]\n\t"
#else
        "ldrd	r6, r7, [sp, #48]\n\t"
#endif
        "eor	r8, r4, r6\n\t"
        "eor	r9, r5, r7\n\t"
        "and	r8, r8, %[n]\n\t"
        "and	r9, r9, %[n]\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r9\n\t"
        "eor	r6, r6, r8\n\t"
        "eor	r7, r7, r9\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r4, [sp, #16]\n\t"
        "str	r5, [sp, #20]\n\t"
#else
        "strd	r4, r5, [sp, #16]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r6, [sp, #48]\n\t"
        "str	r7, [sp, #52]\n\t"
#else
        "strd	r6, r7, [sp, #48]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r4, [sp, #24]\n\t"
        "ldr	r5, [sp, #28]\n\t"
#else
        "ldrd	r4, r5, [sp, #24]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "ldr	r6, [sp, #56]\n\t"
        "ldr	r7, [sp, #60]\n\t"
#else
        "ldrd	r6, r7, [sp, #56]\n\t"
#endif
        "eor	r8, r4, r6\n\t"
        "eor	r9, r5, r7\n\t"
        "and	r8, r8, %[n]\n\t"
        "and	r9, r9, %[n]\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r9\n\t"
        "eor	r6, r6, r8\n\t"
        "eor	r7, r7, r9\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r4, [sp, #24]\n\t"
        "str	r5, [sp, #28]\n\t"
#else
        "strd	r4, r5, [sp, #24]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r6, [sp, #56]\n\t"
        "str	r7, [sp, #60]\n\t"
#else
        "strd	r6, r7, [sp, #56]\n\t"
#endif
        "ldr	%[n], [sp, #184]\n\t"
        "str	%[n], [sp, #172]\n\t"
        "mov	r3, sp\n\t"
        "ldr	r2, [sp, #160]\n\t"
        "add	r1, sp, #0x80\n\t"
        "ldr	r0, [sp, #160]\n\t"
        "bl	fe_add_sub_op\n\t"
        "add	r3, sp, #32\n\t"
        "add	r2, sp, #0x40\n\t"
        "add	r1, sp, #0x60\n\t"
        "mov	r0, sp\n\t"
        "bl	fe_add_sub_op\n\t"
        "ldr	r2, [sp, #160]\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_mul_op\n\t"
        "add	r2, sp, #0x80\n\t"
        "mov	r1, sp\n\t"
        "mov	r0, sp\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #0x80\n\t"
        "add	r0, sp, #0x80\n\t"
        "bl	fe_sq_op\n\t"
        "ldr	r1, [sp, #160]\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r3, sp\n\t"
        "add	r2, sp, #32\n\t"
        "mov	r1, sp\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_add_sub_op\n\t"
        "add	r2, sp, #0x80\n\t"
        "add	r1, sp, #0x60\n\t"
        "ldr	r0, [sp, #160]\n\t"
        "bl	fe_mul_op\n\t"
        "add	r2, sp, #0x80\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_sub_op\n\t"
        "mov	r1, sp\n\t"
        "mov	r0, sp\n\t"
        "bl	fe_sq_op\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_mul121666\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_sq_op\n\t"
        "add	r2, sp, #32\n\t"
        "add	r1, sp, #0x80\n\t"
        "add	r0, sp, #0x80\n\t"
        "bl	fe_add_op\n\t"
        "mov	r2, sp\n\t"
        "ldr	r1, [sp, #168]\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_mul_op\n\t"
        "add	r2, sp, #0x80\n\t"
        "add	r1, sp, #0x60\n\t"
        "mov	r0, sp\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	%[a], [sp, #176]\n\t"
        "ldr	%[n], [sp, #180]\n\t"
        "subs	%[n], %[n], #1\n\t"
        "str	%[n], [sp, #180]\n\t"
        "bge	L_curve25519_bits_%=\n\t"
        "mov	%[n], #31\n\t"
        "str	%[n], [sp, #180]\n\t"
        "subs	%[a], %[a], #4\n\t"
        "str	%[a], [sp, #176]\n\t"
        "bge	L_curve25519_words_%=\n\t"
        /* Invert */
        "add	r1, sp, #0\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_sq_op\n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_sq_op\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_sq_op\n\t"
        "add	r2, sp, #0x40\n\t"
        "add	r1, sp, #0\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "add	r2, sp, #0x40\n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_sq_op\n\t"
        "add	r2, sp, #0x60\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #4\n\t"
        "\n"
    "L_curve25519_inv_1_%=: \n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x60\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_curve25519_inv_1_%=\n\t"
        "add	r2, sp, #0x40\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #9\n\t"
        "\n"
    "L_curve25519_inv_2_%=: \n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x60\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_curve25519_inv_2_%=\n\t"
        "add	r2, sp, #0x40\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x80\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #19\n\t"
        "\n"
    "L_curve25519_inv_3_%=: \n\t"
        "add	r1, sp, #0x80\n\t"
        "add	r0, sp, #0x80\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_curve25519_inv_3_%=\n\t"
        "add	r2, sp, #0x60\n\t"
        "add	r1, sp, #0x80\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r12, #10\n\t"
        "\n"
    "L_curve25519_inv_4_%=: \n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x60\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_curve25519_inv_4_%=\n\t"
        "add	r2, sp, #0x40\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #49\n\t"
        "\n"
    "L_curve25519_inv_5_%=: \n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x60\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_curve25519_inv_5_%=\n\t"
        "add	r2, sp, #0x40\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x80\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #0x63\n\t"
        "\n"
    "L_curve25519_inv_6_%=: \n\t"
        "add	r1, sp, #0x80\n\t"
        "add	r0, sp, #0x80\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_curve25519_inv_6_%=\n\t"
        "add	r2, sp, #0x60\n\t"
        "add	r1, sp, #0x80\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r12, #50\n\t"
        "\n"
    "L_curve25519_inv_7_%=: \n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x60\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_curve25519_inv_7_%=\n\t"
        "add	r2, sp, #0x40\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r12, #5\n\t"
        "\n"
    "L_curve25519_inv_8_%=: \n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x40\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_curve25519_inv_8_%=\n\t"
        "add	r2, sp, #32\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r2, sp\n\t"
        "ldr	r1, [sp, #160]\n\t"
        "ldr	r0, [sp, #160]\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r0, #0\n\t"
        "add	sp, sp, #0xbc\n\t"
        : [r] "+r" (r), [n] "+r" (n), [a] "+r" (a)
        :
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r3", "r12", "lr"
    );
    return (uint32_t)(size_t)r;
}

#else
int curve25519(byte* r_p, const byte* n_p, const byte* a_p)
{
    register byte* r asm ("r0") = r_p;
    register const byte* n asm ("r1") = n_p;
    register const byte* a asm ("r2") = a_p;

    __asm__ __volatile__ (
        "sub	sp, sp, #0xc0\n\t"
        "str	%[r], [sp, #176]\n\t"
        "str	%[n], [sp, #160]\n\t"
        "str	%[a], [sp, #172]\n\t"
        "add	r5, sp, #0x40\n\t"
        "add	r4, sp, #32\n\t"
        "str	sp, [sp, #184]\n\t"
        "str	r5, [sp, #180]\n\t"
        "str	r4, [sp, #188]\n\t"
        "mov	%[n], #0\n\t"
        "str	%[n], [sp, #164]\n\t"
        /* Set one */
        "mov	r10, #1\n\t"
        "mov	r11, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [%[r]]\n\t"
        "str	r11, [%[r], #4]\n\t"
#else
        "strd	r10, r11, [%[r]]\n\t"
#endif
        "mov	r10, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [%[r], #8]\n\t"
        "str	r11, [%[r], #12]\n\t"
#else
        "strd	r10, r11, [%[r], #8]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [%[r], #16]\n\t"
        "str	r11, [%[r], #20]\n\t"
#else
        "strd	r10, r11, [%[r], #16]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [%[r], #24]\n\t"
        "str	r11, [%[r], #28]\n\t"
#else
        "strd	r10, r11, [%[r], #24]\n\t"
#endif
        /* Set zero */
        "mov	r10, #0\n\t"
        "mov	r11, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [sp]\n\t"
        "str	r11, [sp, #4]\n\t"
#else
        "strd	r10, r11, [sp]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [sp, #8]\n\t"
        "str	r11, [sp, #12]\n\t"
#else
        "strd	r10, r11, [sp, #8]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [sp, #16]\n\t"
        "str	r11, [sp, #20]\n\t"
#else
        "strd	r10, r11, [sp, #16]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [sp, #24]\n\t"
        "str	r11, [sp, #28]\n\t"
#else
        "strd	r10, r11, [sp, #24]\n\t"
#endif
        /* Set one */
        "mov	r10, #1\n\t"
        "mov	r11, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [sp, #32]\n\t"
        "str	r11, [sp, #36]\n\t"
#else
        "strd	r10, r11, [sp, #32]\n\t"
#endif
        "mov	r10, #0\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [sp, #40]\n\t"
        "str	r11, [sp, #44]\n\t"
#else
        "strd	r10, r11, [sp, #40]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [sp, #48]\n\t"
        "str	r11, [sp, #52]\n\t"
#else
        "strd	r10, r11, [sp, #48]\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r10, [sp, #56]\n\t"
        "str	r11, [sp, #60]\n\t"
#else
        "strd	r10, r11, [sp, #56]\n\t"
#endif
        "add	r3, sp, #0x40\n\t"
        /* Copy */
        "ldm	r2, {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        "stm	r3, {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        "mov	%[a], #0xfe\n\t"
        "\n"
    "L_curve25519_bits_%=: \n\t"
        "str	%[a], [sp, #168]\n\t"
        "ldr	%[n], [sp, #160]\n\t"
        "and	r4, %[a], #31\n\t"
        "lsr	%[a], %[a], #5\n\t"
        "ldr	%[a], [%[n], r2, lsl #2]\n\t"
        "rsb	r4, r4, #31\n\t"
        "lsl	%[a], %[a], r4\n\t"
        "ldr	%[n], [sp, #164]\n\t"
        "eor	%[n], %[n], %[a]\n\t"
        "asr	%[n], %[n], #31\n\t"
        "str	%[a], [sp, #164]\n\t"
        /* Conditional Swap */
        "add	r11, sp, #0xb0\n\t"
        "ldm	r11, {r4, r5, r6, r7}\n\t"
        "eor	r8, r4, r5\n\t"
        "eor	r9, r6, r7\n\t"
        "and	r8, r8, %[n]\n\t"
        "and	r9, r9, %[n]\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r8\n\t"
        "eor	r6, r6, r9\n\t"
        "eor	r7, r7, r9\n\t"
        "stm	r11, {r4, r5, r6, r7}\n\t"
        /* Ladder step */
        "ldr	r3, [sp, #184]\n\t"
        "ldr	r2, [sp, #176]\n\t"
        "add	r1, sp, #0x80\n\t"
        "ldr	r0, [sp, #176]\n\t"
        "bl	fe_add_sub_op\n\t"
        "ldr	r3, [sp, #188]\n\t"
        "ldr	r2, [sp, #180]\n\t"
        "add	r1, sp, #0x60\n\t"
        "ldr	r0, [sp, #184]\n\t"
        "bl	fe_add_sub_op\n\t"
        "ldr	r2, [sp, #176]\n\t"
        "add	r1, sp, #0x60\n\t"
        "ldr	r0, [sp, #188]\n\t"
        "bl	fe_mul_op\n\t"
        "add	r2, sp, #0x80\n\t"
        "ldr	r1, [sp, #184]\n\t"
        "ldr	r0, [sp, #184]\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #0x80\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_sq_op\n\t"
        "ldr	r1, [sp, #176]\n\t"
        "add	r0, sp, #0x80\n\t"
        "bl	fe_sq_op\n\t"
        "ldr	r3, [sp, #184]\n\t"
        "ldr	r2, [sp, #188]\n\t"
        "ldr	r1, [sp, #184]\n\t"
        "ldr	r0, [sp, #180]\n\t"
        "bl	fe_add_sub_op\n\t"
        "add	r2, sp, #0x60\n\t"
        "add	r1, sp, #0x80\n\t"
        "ldr	r0, [sp, #176]\n\t"
        "bl	fe_mul_op\n\t"
        "add	r2, sp, #0x60\n\t"
        "add	r1, sp, #0x80\n\t"
        "add	r0, sp, #0x80\n\t"
        "bl	fe_sub_op\n\t"
        "ldr	r1, [sp, #184]\n\t"
        "ldr	r0, [sp, #184]\n\t"
        "bl	fe_sq_op\n\t"
        "add	r1, sp, #0x80\n\t"
        "ldr	r0, [sp, #188]\n\t"
        "bl	fe_mul121666\n\t"
        "ldr	r1, [sp, #180]\n\t"
        "ldr	r0, [sp, #180]\n\t"
        "bl	fe_sq_op\n\t"
        "ldr	r2, [sp, #188]\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_add_op\n\t"
        "ldr	r2, [sp, #184]\n\t"
        "ldr	r1, [sp, #172]\n\t"
        "ldr	r0, [sp, #188]\n\t"
        "bl	fe_mul_op\n\t"
        "add	r2, sp, #0x60\n\t"
        "add	r1, sp, #0x80\n\t"
        "ldr	r0, [sp, #184]\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	%[a], [sp, #168]\n\t"
        "subs	%[a], %[a], #1\n\t"
        "bge	L_curve25519_bits_%=\n\t"
        "ldr	%[n], [sp, #184]\n\t"
        /* Copy */
        "ldm	r1, {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        "stm	sp, {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        /* Invert */
        "add	r1, sp, #0\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_sq_op\n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_sq_op\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_sq_op\n\t"
        "add	r2, sp, #0x40\n\t"
        "add	r1, sp, #0\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "add	r2, sp, #0x40\n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_sq_op\n\t"
        "add	r2, sp, #0x60\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #4\n\t"
        "\n"
    "L_curve25519_inv_1_%=: \n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x60\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_curve25519_inv_1_%=\n\t"
        "add	r2, sp, #0x40\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #9\n\t"
        "\n"
    "L_curve25519_inv_2_%=: \n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x60\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_curve25519_inv_2_%=\n\t"
        "add	r2, sp, #0x40\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x80\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #19\n\t"
        "\n"
    "L_curve25519_inv_3_%=: \n\t"
        "add	r1, sp, #0x80\n\t"
        "add	r0, sp, #0x80\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_curve25519_inv_3_%=\n\t"
        "add	r2, sp, #0x60\n\t"
        "add	r1, sp, #0x80\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r12, #10\n\t"
        "\n"
    "L_curve25519_inv_4_%=: \n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x60\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_curve25519_inv_4_%=\n\t"
        "add	r2, sp, #0x40\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #49\n\t"
        "\n"
    "L_curve25519_inv_5_%=: \n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x60\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_curve25519_inv_5_%=\n\t"
        "add	r2, sp, #0x40\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x80\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #0x63\n\t"
        "\n"
    "L_curve25519_inv_6_%=: \n\t"
        "add	r1, sp, #0x80\n\t"
        "add	r0, sp, #0x80\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_curve25519_inv_6_%=\n\t"
        "add	r2, sp, #0x60\n\t"
        "add	r1, sp, #0x80\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r12, #50\n\t"
        "\n"
    "L_curve25519_inv_7_%=: \n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x60\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_curve25519_inv_7_%=\n\t"
        "add	r2, sp, #0x40\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r12, #5\n\t"
        "\n"
    "L_curve25519_inv_8_%=: \n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x40\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_curve25519_inv_8_%=\n\t"
        "add	r2, sp, #32\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r2, [sp, #184]\n\t"
        "ldr	r1, [sp, #176]\n\t"
        "ldr	r0, [sp, #176]\n\t"
        "bl	fe_mul_op\n\t"
        /* Ensure result is less than modulus */
        "ldr	%[r], [sp, #176]\n\t"
        "ldm	%[r], {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        "mov	%[a], #19\n\t"
        "and	%[a], %[a], r11, asr #31\n\t"
        "adds	r4, r4, %[a]\n\t"
        "adcs	r5, r5, #0\n\t"
        "adcs	r6, r6, #0\n\t"
        "adcs	r7, r7, #0\n\t"
        "adcs	r8, r8, #0\n\t"
        "adcs	r9, r9, #0\n\t"
        "bfc	r11, #31, #1\n\t"
        "adcs	r10, r10, #0\n\t"
        "adc	r11, r11, #0\n\t"
        "stm	%[r], {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        "mov	r0, #0\n\t"
        "add	sp, sp, #0xc0\n\t"
        : [r] "+r" (r), [n] "+r" (n), [a] "+r" (a)
        :
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r3", "r12", "lr"
    );
    return (uint32_t)(size_t)r;
}

#endif /* WC_NO_CACHE_RESISTANT */
#ifdef HAVE_ED25519
void fe_invert(fe r_p, const fe a_p)
{
    register fe r asm ("r0") = r_p;
    register const fe a asm ("r1") = a_p;

    __asm__ __volatile__ (
        "sub	sp, sp, #0x88\n\t"
        /* Invert */
        "str	%[r], [sp, #128]\n\t"
        "str	%[a], [sp, #132]\n\t"
        "ldr	r1, [sp, #132]\n\t"
        "mov	r0, sp\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r1, sp\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_sq_op\n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_sq_op\n\t"
        "add	r2, sp, #32\n\t"
        "ldr	r1, [sp, #132]\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_mul_op\n\t"
        "add	r2, sp, #32\n\t"
        "mov	r1, sp\n\t"
        "mov	r0, sp\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r1, sp\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_sq_op\n\t"
        "add	r2, sp, #0x40\n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #4\n\t"
        "\n"
    "L_fe_invert1_%=: \n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x40\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_fe_invert1_%=\n\t"
        "add	r2, sp, #32\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #9\n\t"
        "\n"
    "L_fe_invert2_%=: \n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x40\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_fe_invert2_%=\n\t"
        "add	r2, sp, #32\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #19\n\t"
        "\n"
    "L_fe_invert3_%=: \n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x60\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_fe_invert3_%=\n\t"
        "add	r2, sp, #0x40\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r12, #10\n\t"
        "\n"
    "L_fe_invert4_%=: \n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x40\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_fe_invert4_%=\n\t"
        "add	r2, sp, #32\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #49\n\t"
        "\n"
    "L_fe_invert5_%=: \n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x40\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_fe_invert5_%=\n\t"
        "add	r2, sp, #32\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x60\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #0x63\n\t"
        "\n"
    "L_fe_invert6_%=: \n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x60\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_fe_invert6_%=\n\t"
        "add	r2, sp, #0x40\n\t"
        "add	r1, sp, #0x60\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r12, #50\n\t"
        "\n"
    "L_fe_invert7_%=: \n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x40\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_fe_invert7_%=\n\t"
        "add	r2, sp, #32\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r12, #5\n\t"
        "\n"
    "L_fe_invert8_%=: \n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #32\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_fe_invert8_%=\n\t"
        "mov	r2, sp\n\t"
        "add	r1, sp, #32\n\t"
        "ldr	r0, [sp, #128]\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	%[a], [sp, #132]\n\t"
        "ldr	%[r], [sp, #128]\n\t"
        "add	sp, sp, #0x88\n\t"
        : [r] "+r" (r), [a] "+r" (a)
        :
        : "memory", "lr", "r12", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"
    );
}

void fe_sq2(fe r_p, const fe a_p)
{
    register fe r asm ("r0") = r_p;
    register const fe a asm ("r1") = a_p;

    __asm__ __volatile__ (
        "sub	sp, sp, #36\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r0, [sp, #28]\n\t"
        "str	r1, [sp, #32]\n\t"
#else
        "strd	r0, r1, [sp, #28]\n\t"
#endif
        "ldm	r1, {r0, r1, r2, r3, r4, r5, r6, r7}\n\t"
        /* Square * 2 */
        "umull	r9, r10, r0, r0\n\t"
        "umull	r11, r12, r0, r1\n\t"
        "adds	r11, r11, r11\n\t"
        "mov	lr, #0\n\t"
        "umaal	r10, r11, lr, lr\n\t"
        "stm	sp, {r9, r10}\n\t"
        "mov	r8, lr\n\t"
        "umaal	r8, r12, r0, r2\n\t"
        "adcs	r8, r8, r8\n\t"
        "umaal	r8, r11, r1, r1\n\t"
        "umull	r9, r10, r0, r3\n\t"
        "umaal	r9, r12, r1, r2\n\t"
        "adcs	r9, r9, r9\n\t"
        "umaal	r9, r11, lr, lr\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "str	r8, [sp, #8]\n\t"
        "str	r9, [sp, #12]\n\t"
#else
        "strd	r8, r9, [sp, #8]\n\t"
#endif
        "mov	r9, lr\n\t"
        "umaal	r9, r10, r0, r4\n\t"
        "umaal	r9, r12, r1, r3\n\t"
        "adcs	r9, r9, r9\n\t"
        "umaal	r9, r11, r2, r2\n\t"
        "str	r9, [sp, #16]\n\t"
        "umull	r9, r8, r0, r5\n\t"
        "umaal	r9, r12, r1, r4\n\t"
        "umaal	r9, r10, r2, r3\n\t"
        "adcs	r9, r9, r9\n\t"
        "umaal	r9, r11, lr, lr\n\t"
        "str	r9, [sp, #20]\n\t"
        "mov	r9, lr\n\t"
        "umaal	r9, r8, r0, r6\n\t"
        "umaal	r9, r12, r1, r5\n\t"
        "umaal	r9, r10, r2, r4\n\t"
        "adcs	r9, r9, r9\n\t"
        "umaal	r9, r11, r3, r3\n\t"
        "str	r9, [sp, #24]\n\t"
        "umull	r0, r9, r0, r7\n\t"
        "umaal	r0, r8, r1, r6\n\t"
        "umaal	r0, r12, r2, r5\n\t"
        "umaal	r0, r10, r3, r4\n\t"
        "adcs	r0, r0, r0\n\t"
        "umaal	r0, r11, lr, lr\n\t"
        /* R[7] = r0 */
        "umaal	r9, r8, r1, r7\n\t"
        "umaal	r9, r10, r2, r6\n\t"
        "umaal	r12, r9, r3, r5\n\t"
        "adcs	r12, r12, r12\n\t"
        "umaal	r12, r11, r4, r4\n\t"
        /* R[8] = r12 */
        "umaal	r9, r8, r2, r7\n\t"
        "umaal	r10, r9, r3, r6\n\t"
        "mov	r2, lr\n\t"
        "umaal	r10, r2, r4, r5\n\t"
        "adcs	r10, r10, r10\n\t"
        "umaal	r11, r10, lr, lr\n\t"
        /* R[9] = r11 */
        "umaal	r2, r8, r3, r7\n\t"
        "umaal	r2, r9, r4, r6\n\t"
        "adcs	r3, r2, r2\n\t"
        "umaal	r10, r3, r5, r5\n\t"
        /* R[10] = r10 */
        "mov	r1, lr\n\t"
        "umaal	r1, r8, r4, r7\n\t"
        "umaal	r1, r9, r5, r6\n\t"
        "adcs	r4, r1, r1\n\t"
        "umaal	r3, r4, lr, lr\n\t"
        /* R[11] = r3 */
        "umaal	r8, r9, r5, r7\n\t"
        "adcs	r8, r8, r8\n\t"
        "umaal	r4, r8, r6, r6\n\t"
        /* R[12] = r4 */
        "mov	r5, lr\n\t"
        "umaal	r5, r9, r6, r7\n\t"
        "adcs	r5, r5, r5\n\t"
        "umaal	r8, r5, lr, lr\n\t"
        /* R[13] = r8 */
        "adcs	r9, r9, r9\n\t"
        "umaal	r9, r5, r7, r7\n\t"
        "adcs	r7, r5, lr\n\t"
        /* R[14] = r9 */
        /* R[15] = r7 */
        /* Reduce */
        "mov	r6, #37\n\t"
        "umaal	r7, r0, r7, r6\n\t"
        "mov	r6, #19\n\t"
        "lsl	r0, r0, #1\n\t"
        "orr	r0, r0, r7, lsr #31\n\t"
        "mul	lr, r0, r6\n\t"
        "pop	{r0-r1}\n\t"
        "mov	r6, #38\n\t"
        "umaal	r0, lr, r12, r6\n\t"
        "umaal	r1, lr, r11, r6\n\t"
        "mov	r12, r3\n\t"
        "mov	r11, r4\n\t"
        "pop	{r2-r4}\n\t"
        "umaal	r2, lr, r10, r6\n\t"
        "umaal	r3, lr, r12, r6\n\t"
        "umaal	r4, lr, r11, r6\n\t"
        "mov	r12, r6\n\t"
        "pop	{r5-r6}\n\t"
        "umaal	r5, lr, r8, r12\n\t"
        "bfc	r7, #31, #1\n\t"
        "umaal	r6, lr, r9, r12\n\t"
        "add	r7, r7, lr\n\t"
        /* Reduce if top bit set */
        "mov	r11, #19\n\t"
        "and	r12, r11, r7, ASR #31\n\t"
        "adds	r0, r0, r12\n\t"
        "adcs	r1, r1, #0\n\t"
        "adcs	r2, r2, #0\n\t"
        "adcs	r3, r3, #0\n\t"
        "adcs	r4, r4, #0\n\t"
        "adcs	r5, r5, #0\n\t"
        "bfc	r7, #31, #1\n\t"
        "adcs	r6, r6, #0\n\t"
        "adc	r7, r7, #0\n\t"
        /* Double */
        "adds	r0, r0, r0\n\t"
        "adcs	r1, r1, r1\n\t"
        "adcs	r2, r2, r2\n\t"
        "adcs	r3, r3, r3\n\t"
        "adcs	r4, r4, r4\n\t"
        "adcs	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adc	r7, r7, r7\n\t"
        /* Reduce if top bit set */
        "mov	r11, #19\n\t"
        "and	r12, r11, r7, ASR #31\n\t"
        "adds	r0, r0, r12\n\t"
        "adcs	r1, r1, #0\n\t"
        "adcs	r2, r2, #0\n\t"
        "adcs	r3, r3, #0\n\t"
        "adcs	r4, r4, #0\n\t"
        "adcs	r5, r5, #0\n\t"
        "bfc	r7, #31, #1\n\t"
        "adcs	r6, r6, #0\n\t"
        "adc	r7, r7, #0\n\t"
        "pop	{r12, lr}\n\t"
        /* Store */
        "stm	r12, {r0, r1, r2, r3, r4, r5, r6, r7}\n\t"
        "mov	r0, r12\n\t"
        "mov	r1, lr\n\t"
        : [r] "+r" (r), [a] "+r" (a)
        :
        : "memory", "lr"
    );
}

void fe_pow22523(fe r_p, const fe a_p)
{
    register fe r asm ("r0") = r_p;
    register const fe a asm ("r1") = a_p;

    __asm__ __volatile__ (
        "sub	sp, sp, #0x68\n\t"
        /* pow22523 */
        "str	%[r], [sp, #96]\n\t"
        "str	%[a], [sp, #100]\n\t"
        "ldr	r1, [sp, #100]\n\t"
        "mov	r0, sp\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r1, sp\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_sq_op\n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_sq_op\n\t"
        "add	r2, sp, #32\n\t"
        "ldr	r1, [sp, #100]\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_mul_op\n\t"
        "add	r2, sp, #32\n\t"
        "mov	r1, sp\n\t"
        "mov	r0, sp\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r1, sp\n\t"
        "mov	r0, sp\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r2, sp\n\t"
        "add	r1, sp, #32\n\t"
        "mov	r0, sp\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r1, sp\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #4\n\t"
        "\n"
    "L_fe_pow22523_1_%=: \n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #32\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_fe_pow22523_1_%=\n\t"
        "mov	r2, sp\n\t"
        "add	r1, sp, #32\n\t"
        "mov	r0, sp\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r1, sp\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #9\n\t"
        "\n"
    "L_fe_pow22523_2_%=: \n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #32\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_fe_pow22523_2_%=\n\t"
        "mov	r2, sp\n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #19\n\t"
        "\n"
    "L_fe_pow22523_3_%=: \n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x40\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_fe_pow22523_3_%=\n\t"
        "add	r2, sp, #32\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r12, #10\n\t"
        "\n"
    "L_fe_pow22523_4_%=: \n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #32\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_fe_pow22523_4_%=\n\t"
        "mov	r2, sp\n\t"
        "add	r1, sp, #32\n\t"
        "mov	r0, sp\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r1, sp\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #49\n\t"
        "\n"
    "L_fe_pow22523_5_%=: \n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #32\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_fe_pow22523_5_%=\n\t"
        "mov	r2, sp\n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_mul_op\n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #0x40\n\t"
        "bl	fe_sq_op\n\t"
        "mov	r12, #0x63\n\t"
        "\n"
    "L_fe_pow22523_6_%=: \n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #0x40\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_fe_pow22523_6_%=\n\t"
        "add	r2, sp, #32\n\t"
        "add	r1, sp, #0x40\n\t"
        "add	r0, sp, #32\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r12, #50\n\t"
        "\n"
    "L_fe_pow22523_7_%=: \n\t"
        "add	r1, sp, #32\n\t"
        "add	r0, sp, #32\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_fe_pow22523_7_%=\n\t"
        "mov	r2, sp\n\t"
        "add	r1, sp, #32\n\t"
        "mov	r0, sp\n\t"
        "bl	fe_mul_op\n\t"
        "mov	r12, #2\n\t"
        "\n"
    "L_fe_pow22523_8_%=: \n\t"
        "mov	r1, sp\n\t"
        "mov	r0, sp\n\t"
        "push	{r12}\n\t"
        "bl	fe_sq_op\n\t"
        "pop	{r12}\n\t"
        "subs	r12, r12, #1\n\t"
        "bne	L_fe_pow22523_8_%=\n\t"
        "ldr	r2, [sp, #100]\n\t"
        "mov	r1, sp\n\t"
        "ldr	r0, [sp, #96]\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	%[a], [sp, #100]\n\t"
        "ldr	%[r], [sp, #96]\n\t"
        "add	sp, sp, #0x68\n\t"
        : [r] "+r" (r), [a] "+r" (a)
        :
        : "memory", "lr", "r12", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"
    );
}

void ge_p1p1_to_p2(ge_p2 * r_p, const ge_p1p1 * p_p)
{
    register ge_p2 * r asm ("r0") = r_p;
    register const ge_p1p1 * p asm ("r1") = p_p;

    __asm__ __volatile__ (
        "sub	sp, sp, #8\n\t"
        "str	%[r], [sp]\n\t"
        "str	%[p], [sp, #4]\n\t"
        "add	r2, r1, #0x60\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r0, [sp]\n\t"
        "ldr	r1, [sp, #4]\n\t"
        "add	r2, r1, #0x40\n\t"
        "add	r1, r1, #32\n\t"
        "add	r0, r0, #32\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r0, [sp]\n\t"
        "ldr	r1, [sp, #4]\n\t"
        "add	r2, r1, #0x60\n\t"
        "add	r1, r1, #0x40\n\t"
        "add	r0, r0, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "add	sp, sp, #8\n\t"
        : [r] "+r" (r), [p] "+r" (p)
        :
        : "memory", "lr", "r2", "r3", "r12", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"
    );
}

void ge_p1p1_to_p3(ge_p3 * r_p, const ge_p1p1 * p_p)
{
    register ge_p3 * r asm ("r0") = r_p;
    register const ge_p1p1 * p asm ("r1") = p_p;

    __asm__ __volatile__ (
        "sub	sp, sp, #8\n\t"
        "str	%[r], [sp]\n\t"
        "str	%[p], [sp, #4]\n\t"
        "add	r2, r1, #0x60\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r0, [sp]\n\t"
        "ldr	r1, [sp, #4]\n\t"
        "add	r2, r1, #0x40\n\t"
        "add	r1, r1, #32\n\t"
        "add	r0, r0, #32\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r0, [sp]\n\t"
        "ldr	r1, [sp, #4]\n\t"
        "add	r2, r1, #0x60\n\t"
        "add	r1, r1, #0x40\n\t"
        "add	r0, r0, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r0, [sp]\n\t"
        "ldr	r1, [sp, #4]\n\t"
        "add	r2, r1, #32\n\t"
        "add	r0, r0, #0x60\n\t"
        "bl	fe_mul_op\n\t"
        "add	sp, sp, #8\n\t"
        : [r] "+r" (r), [p] "+r" (p)
        :
        : "memory", "lr", "r2", "r3", "r12", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11"
    );
}

void ge_p2_dbl(ge_p1p1 * r_p, const ge_p2 * p_p)
{
    register ge_p1p1 * r asm ("r0") = r_p;
    register const ge_p2 * p asm ("r1") = p_p;

    __asm__ __volatile__ (
        "sub	sp, sp, #8\n\t"
        "str	%[r], [sp]\n\t"
        "str	%[p], [sp, #4]\n\t"
        "bl	fe_sq_op\n\t"
        "ldr	r0, [sp]\n\t"
        "ldr	r1, [sp, #4]\n\t"
        "add	r1, r1, #32\n\t"
        "add	r0, r0, #0x40\n\t"
        "bl	fe_sq_op\n\t"
        "ldr	r0, [sp]\n\t"
        "ldr	r1, [sp, #4]\n\t"
        "add	r2, r1, #32\n\t"
        "add	r0, r0, #32\n\t"
        "bl	fe_add_op\n\t"
        "mov	r1, r0\n\t"
        "add	r0, r0, #0x40\n\t"
        "bl	fe_sq_op\n\t"
        "ldr	r0, [sp]\n\t"
        "mov	r3, r0\n\t"
        "add	r2, r0, #0x40\n\t"
        "add	r1, r0, #0x40\n\t"
        "add	r0, r0, #32\n\t"
        "bl	fe_add_sub_op\n\t"
        "mov	r2, r0\n\t"
        "add	r1, r0, #0x40\n\t"
        "sub	r0, r0, #32\n\t"
        "bl	fe_sub_op\n\t"
        "ldr	r1, [sp, #4]\n\t"
        "add	r1, r1, #0x40\n\t"
        "add	r0, r0, #0x60\n\t"
        "bl	fe_sq2\n\t"
        "sub	r2, r0, #32\n\t"
        "mov	r1, r0\n\t"
        "bl	fe_sub_op\n\t"
        "add	sp, sp, #8\n\t"
        : [r] "+r" (r), [p] "+r" (p)
        :
        : "memory", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr"
    );
}

void ge_madd(ge_p1p1 * r_p, const ge_p3 * p_p, const ge_precomp * q_p)
{
    register ge_p1p1 * r asm ("r0") = r_p;
    register const ge_p3 * p asm ("r1") = p_p;
    register const ge_precomp * q asm ("r2") = q_p;

    __asm__ __volatile__ (
        "sub	sp, sp, #12\n\t"
        "str	%[r], [sp]\n\t"
        "str	%[p], [sp, #4]\n\t"
        "str	%[q], [sp, #8]\n\t"
        "mov	r2, r1\n\t"
        "add	r1, r1, #32\n\t"
        "bl	fe_add_op\n\t"
        "ldr	r1, [sp, #4]\n\t"
        "mov	r2, r1\n\t"
        "add	r1, r1, #32\n\t"
        "add	r0, r0, #32\n\t"
        "bl	fe_sub_op\n\t"
        "ldr	r2, [sp, #8]\n\t"
        "sub	r1, r0, #32\n\t"
        "add	r0, r0, #32\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r0, [sp]\n\t"
        "ldr	r2, [sp, #8]\n\t"
        "add	r2, r2, #32\n\t"
        "add	r1, r0, #32\n\t"
        "add	r0, r0, #32\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r0, [sp]\n\t"
        "ldr	r1, [sp, #8]\n\t"
        "ldr	r2, [sp, #4]\n\t"
        "add	r2, r2, #0x60\n\t"
        "add	r1, r1, #0x40\n\t"
        "add	r0, r0, #0x60\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r0, [sp]\n\t"
        "add	r3, r0, #32\n\t"
        "add	r2, r0, #0x40\n\t"
        "mov	r1, r0\n\t"
        "add	r0, r0, #32\n\t"
        "bl	fe_add_sub_op\n\t"
        "ldr	r1, [sp, #4]\n\t"
        "add	r1, r1, #0x40\n\t"
        "add	r0, r0, #32\n\t"
        /* Double */
        "ldm	r1, {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        "adds	r4, r4, r4\n\t"
        "adcs	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adcs	r7, r7, r7\n\t"
        "adcs	r8, r8, r8\n\t"
        "adcs	r9, r9, r9\n\t"
        "adcs	r10, r10, r10\n\t"
        "mov	lr, #0\n\t"
        "adcs	r11, r11, r11\n\t"
        "adc	lr, lr, #0\n\t"
        "mov	r12, #19\n\t"
        "lsl	lr, lr, #1\n\t"
        "orr	lr, lr, r11, lsr #31\n\t"
        "mul	r12, lr, r12\n\t"
        "adds	r4, r4, r12\n\t"
        "adcs	r5, r5, #0\n\t"
        "adcs	r6, r6, #0\n\t"
        "adcs	r7, r7, #0\n\t"
        "adcs	r8, r8, #0\n\t"
        "adcs	r9, r9, #0\n\t"
        "bfc	r11, #31, #1\n\t"
        "adcs	r10, r10, #0\n\t"
        "adc	r11, r11, #0\n\t"
        "stm	r0, {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        /* Done Double */
        "add	r3, r0, #32\n\t"
        "add	r1, r0, #32\n\t"
        "bl	fe_add_sub_op\n\t"
        "add	sp, sp, #12\n\t"
        : [r] "+r" (r), [p] "+r" (p), [q] "+r" (q)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr"
    );
}

void ge_msub(ge_p1p1 * r_p, const ge_p3 * p_p, const ge_precomp * q_p)
{
    register ge_p1p1 * r asm ("r0") = r_p;
    register const ge_p3 * p asm ("r1") = p_p;
    register const ge_precomp * q asm ("r2") = q_p;

    __asm__ __volatile__ (
        "sub	sp, sp, #12\n\t"
        "str	%[r], [sp]\n\t"
        "str	%[p], [sp, #4]\n\t"
        "str	%[q], [sp, #8]\n\t"
        "mov	r2, r1\n\t"
        "add	r1, r1, #32\n\t"
        "bl	fe_add_op\n\t"
        "ldr	r1, [sp, #4]\n\t"
        "mov	r2, r1\n\t"
        "add	r1, r1, #32\n\t"
        "add	r0, r0, #32\n\t"
        "bl	fe_sub_op\n\t"
        "ldr	r2, [sp, #8]\n\t"
        "add	r2, r2, #32\n\t"
        "sub	r1, r0, #32\n\t"
        "add	r0, r0, #32\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r0, [sp]\n\t"
        "ldr	r2, [sp, #8]\n\t"
        "add	r1, r0, #32\n\t"
        "add	r0, r0, #32\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r0, [sp]\n\t"
        "ldr	r1, [sp, #8]\n\t"
        "ldr	r2, [sp, #4]\n\t"
        "add	r2, r2, #0x60\n\t"
        "add	r1, r1, #0x40\n\t"
        "add	r0, r0, #0x60\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r0, [sp]\n\t"
        "add	r3, r0, #32\n\t"
        "add	r2, r0, #0x40\n\t"
        "mov	r1, r0\n\t"
        "add	r0, r0, #32\n\t"
        "bl	fe_add_sub_op\n\t"
        "ldr	r1, [sp, #4]\n\t"
        "add	r1, r1, #0x40\n\t"
        "add	r0, r0, #32\n\t"
        /* Double */
        "ldm	r1, {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        "adds	r4, r4, r4\n\t"
        "adcs	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adcs	r7, r7, r7\n\t"
        "adcs	r8, r8, r8\n\t"
        "adcs	r9, r9, r9\n\t"
        "adcs	r10, r10, r10\n\t"
        "mov	lr, #0\n\t"
        "adcs	r11, r11, r11\n\t"
        "adc	lr, lr, #0\n\t"
        "mov	r12, #19\n\t"
        "lsl	lr, lr, #1\n\t"
        "orr	lr, lr, r11, lsr #31\n\t"
        "mul	r12, lr, r12\n\t"
        "adds	r4, r4, r12\n\t"
        "adcs	r5, r5, #0\n\t"
        "adcs	r6, r6, #0\n\t"
        "adcs	r7, r7, #0\n\t"
        "adcs	r8, r8, #0\n\t"
        "adcs	r9, r9, #0\n\t"
        "bfc	r11, #31, #1\n\t"
        "adcs	r10, r10, #0\n\t"
        "adc	r11, r11, #0\n\t"
        "stm	r0, {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        /* Done Double */
        "add	r3, r0, #32\n\t"
        "mov	r1, r0\n\t"
        "add	r0, r0, #32\n\t"
        "bl	fe_add_sub_op\n\t"
        "add	sp, sp, #12\n\t"
        : [r] "+r" (r), [p] "+r" (p), [q] "+r" (q)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr"
    );
}

void ge_add(ge_p1p1 * r_p, const ge_p3 * p_p, const ge_cached* q_p)
{
    register ge_p1p1 * r asm ("r0") = r_p;
    register const ge_p3 * p asm ("r1") = p_p;
    register const ge_cached* q asm ("r2") = q_p;

    __asm__ __volatile__ (
        "sub	sp, sp, #44\n\t"
        "str	%[r], [sp]\n\t"
        "str	%[p], [sp, #4]\n\t"
        "str	%[q], [sp, #8]\n\t"
        "mov	r3, r1\n\t"
        "add	r2, r1, #32\n\t"
        "add	r1, r0, #32\n\t"
        "bl	fe_add_sub_op\n\t"
        "ldr	r2, [sp, #8]\n\t"
        "mov	r1, r0\n\t"
        "add	r0, r0, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r0, [sp]\n\t"
        "ldr	r2, [sp, #8]\n\t"
        "add	r2, r2, #32\n\t"
        "add	r1, r0, #32\n\t"
        "add	r0, r0, #32\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r0, [sp]\n\t"
        "ldr	r1, [sp, #8]\n\t"
        "ldr	r2, [sp, #4]\n\t"
        "add	r2, r2, #0x60\n\t"
        "add	r1, r1, #0x60\n\t"
        "add	r0, r0, #0x60\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r0, [sp]\n\t"
        "ldr	r1, [sp, #4]\n\t"
        "ldr	r2, [sp, #8]\n\t"
        "add	r2, r2, #0x40\n\t"
        "add	r1, r1, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r1, [sp]\n\t"
        "add	r0, sp, #12\n\t"
        /* Double */
        "ldm	r1, {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        "adds	r4, r4, r4\n\t"
        "adcs	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adcs	r7, r7, r7\n\t"
        "adcs	r8, r8, r8\n\t"
        "adcs	r9, r9, r9\n\t"
        "adcs	r10, r10, r10\n\t"
        "mov	lr, #0\n\t"
        "adcs	r11, r11, r11\n\t"
        "adc	lr, lr, #0\n\t"
        "mov	r12, #19\n\t"
        "lsl	lr, lr, #1\n\t"
        "orr	lr, lr, r11, lsr #31\n\t"
        "mul	r12, lr, r12\n\t"
        "adds	r4, r4, r12\n\t"
        "adcs	r5, r5, #0\n\t"
        "adcs	r6, r6, #0\n\t"
        "adcs	r7, r7, #0\n\t"
        "adcs	r8, r8, #0\n\t"
        "adcs	r9, r9, #0\n\t"
        "bfc	r11, #31, #1\n\t"
        "adcs	r10, r10, #0\n\t"
        "adc	r11, r11, #0\n\t"
        "stm	r0, {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        /* Done Double */
        "add	r3, r1, #32\n\t"
        "add	r2, r1, #0x40\n\t"
        "add	r0, r1, #32\n\t"
        "bl	fe_add_sub_op\n\t"
        "add	r3, r0, #0x40\n\t"
        "add	r2, sp, #12\n\t"
        "add	r1, r0, #0x40\n\t"
        "add	r0, r0, #32\n\t"
        "bl	fe_add_sub_op\n\t"
        "add	sp, sp, #44\n\t"
        : [r] "+r" (r), [p] "+r" (p), [q] "+r" (q)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr"
    );
}

void ge_sub(ge_p1p1 * r_p, const ge_p3 * p_p, const ge_cached* q_p)
{
    register ge_p1p1 * r asm ("r0") = r_p;
    register const ge_p3 * p asm ("r1") = p_p;
    register const ge_cached* q asm ("r2") = q_p;

    __asm__ __volatile__ (
        "sub	sp, sp, #44\n\t"
        "str	%[r], [sp]\n\t"
        "str	%[p], [sp, #4]\n\t"
        "str	%[q], [sp, #8]\n\t"
        "mov	r3, r1\n\t"
        "add	r2, r1, #32\n\t"
        "add	r1, r0, #32\n\t"
        "bl	fe_add_sub_op\n\t"
        "ldr	r2, [sp, #8]\n\t"
        "add	r2, r2, #32\n\t"
        "mov	r1, r0\n\t"
        "add	r0, r0, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r0, [sp]\n\t"
        "ldr	r2, [sp, #8]\n\t"
        "add	r1, r0, #32\n\t"
        "add	r0, r0, #32\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r0, [sp]\n\t"
        "ldr	r1, [sp, #8]\n\t"
        "ldr	r2, [sp, #4]\n\t"
        "add	r2, r2, #0x60\n\t"
        "add	r1, r1, #0x60\n\t"
        "add	r0, r0, #0x60\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r0, [sp]\n\t"
        "ldr	r1, [sp, #4]\n\t"
        "ldr	r2, [sp, #8]\n\t"
        "add	r2, r2, #0x40\n\t"
        "add	r1, r1, #0x40\n\t"
        "bl	fe_mul_op\n\t"
        "ldr	r1, [sp]\n\t"
        "add	r0, sp, #12\n\t"
        /* Double */
        "ldm	r1, {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        "adds	r4, r4, r4\n\t"
        "adcs	r5, r5, r5\n\t"
        "adcs	r6, r6, r6\n\t"
        "adcs	r7, r7, r7\n\t"
        "adcs	r8, r8, r8\n\t"
        "adcs	r9, r9, r9\n\t"
        "adcs	r10, r10, r10\n\t"
        "mov	lr, #0\n\t"
        "adcs	r11, r11, r11\n\t"
        "adc	lr, lr, #0\n\t"
        "mov	r12, #19\n\t"
        "lsl	lr, lr, #1\n\t"
        "orr	lr, lr, r11, lsr #31\n\t"
        "mul	r12, lr, r12\n\t"
        "adds	r4, r4, r12\n\t"
        "adcs	r5, r5, #0\n\t"
        "adcs	r6, r6, #0\n\t"
        "adcs	r7, r7, #0\n\t"
        "adcs	r8, r8, #0\n\t"
        "adcs	r9, r9, #0\n\t"
        "bfc	r11, #31, #1\n\t"
        "adcs	r10, r10, #0\n\t"
        "adc	r11, r11, #0\n\t"
        "stm	r0, {r4, r5, r6, r7, r8, r9, r10, r11}\n\t"
        /* Done Double */
        "add	r3, r1, #32\n\t"
        "add	r2, r1, #0x40\n\t"
        "add	r0, r1, #32\n\t"
        "bl	fe_add_sub_op\n\t"
        "add	r3, r0, #0x40\n\t"
        "add	r2, sp, #12\n\t"
        "add	r1, r0, #32\n\t"
        "add	r0, r0, #0x40\n\t"
        "bl	fe_add_sub_op\n\t"
        "add	sp, sp, #44\n\t"
        : [r] "+r" (r), [p] "+r" (p), [q] "+r" (q)
        :
        : "memory", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr"
    );
}

void sc_reduce(byte* s_p)
{
    register byte* s asm ("r0") = s_p;

    __asm__ __volatile__ (
        "sub	sp, sp, #52\n\t"
        /* Load bits 252-511 */
        "add	%[s], %[s], #28\n\t"
        "ldm	%[s], {r1, r2, r3, r4, r5, r6, r7, r8, r9}\n\t"
        "lsr	lr, r9, #24\n\t"
        "lsl	r9, r9, #4\n\t"
        "orr	r9, r9, r8, lsr #28\n\t"
        "lsl	r8, r8, #4\n\t"
        "orr	r8, r8, r7, lsr #28\n\t"
        "lsl	r7, r7, #4\n\t"
        "orr	r7, r7, r6, lsr #28\n\t"
        "lsl	r6, r6, #4\n\t"
        "orr	r6, r6, r5, lsr #28\n\t"
        "lsl	r5, r5, #4\n\t"
        "orr	r5, r5, r4, lsr #28\n\t"
        "lsl	r4, r4, #4\n\t"
        "orr	r4, r4, r3, lsr #28\n\t"
        "lsl	r3, r3, #4\n\t"
        "orr	r3, r3, r2, lsr #28\n\t"
        "lsl	r2, r2, #4\n\t"
        "orr	r2, r2, r1, lsr #28\n\t"
        "bfc	r9, #28, #4\n\t"
        "sub	%[s], %[s], #28\n\t"
        /* Add order times bits 504..511 */
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r10, #0x2c\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x13\n\t"
#else
        "mov	r10, #0x2c13\n\t"
#endif
        "movt	r10, #0xa30a\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r11, #0x9c\n\t"
        "lsl	r11, r11, #8\n\t"
        "add	r11, r11, #0xe5\n\t"
#else
        "mov	r11, #0x9ce5\n\t"
#endif
        "movt	r11, #0xa7ed\n\t"
        "mov	r1, #0\n\t"
        "umlal	r2, r1, r10, lr\n\t"
        "umaal	r3, r1, r11, lr\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r10, #0x63\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x29\n\t"
#else
        "mov	r10, #0x6329\n\t"
#endif
        "movt	r10, #0x5d08\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r11, #0x6\n\t"
        "lsl	r11, r11, #8\n\t"
        "add	r11, r11, #0x21\n\t"
#else
        "mov	r11, #0x621\n\t"
#endif
        "movt	r11, #0xeb21\n\t"
        "umaal	r4, r1, r10, lr\n\t"
        "umaal	r5, r1, r11, lr\n\t"
        "adds	r6, r6, r1\n\t"
        "adcs	r7, r7, #0\n\t"
        "adcs	r8, r8, #0\n\t"
        "adc	r9, r9, #0\n\t"
        "subs	r6, r6, lr\n\t"
        "sbcs	r7, r7, #0\n\t"
        "sbcs	r8, r8, #0\n\t"
        "sbc	r9, r9, #0\n\t"
        /* Sub product of top 8 words and order */
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r1, #0x2c\n\t"
        "lsl	r1, r1, #8\n\t"
        "add	r1, r1, #0x13\n\t"
#else
        "mov	r1, #0x2c13\n\t"
#endif
        "movt	r1, #0xa30a\n\t"
        "mov	lr, #0\n\t"
        "ldm	%[s]!, {r10, r11, r12}\n\t"
        "umlal	r10, lr, r2, r1\n\t"
        "umaal	r11, lr, r3, r1\n\t"
        "umaal	r12, lr, r4, r1\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	%[s]!, {r10, r11, r12}\n\t"
        "umaal	r10, lr, r5, r1\n\t"
        "umaal	r11, lr, r6, r1\n\t"
        "umaal	r12, lr, r7, r1\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	%[s]!, {r10, r11}\n\t"
        "umaal	r10, lr, r8, r1\n\t"
        "bfc	r11, #28, #4\n\t"
        "umaal	r11, lr, r9, r1\n\t"
        "stm	sp!, {r10, r11, lr}\n\t"
        "sub	%[s], %[s], #16\n\t"
        "sub	sp, sp, #32\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r1, #0x9c\n\t"
        "lsl	r1, r1, #8\n\t"
        "add	r1, r1, #0xe5\n\t"
#else
        "mov	r1, #0x9ce5\n\t"
#endif
        "movt	r1, #0xa7ed\n\t"
        "mov	lr, #0\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "umlal	r10, lr, r2, r1\n\t"
        "umaal	r11, lr, r3, r1\n\t"
        "umaal	r12, lr, r4, r1\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "umaal	r10, lr, r5, r1\n\t"
        "umaal	r11, lr, r6, r1\n\t"
        "umaal	r12, lr, r7, r1\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11}\n\t"
        "umaal	r10, lr, r8, r1\n\t"
        "umaal	r11, lr, r9, r1\n\t"
        "stm	sp!, {r10, r11, lr}\n\t"
        "sub	sp, sp, #32\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r1, #0x63\n\t"
        "lsl	r1, r1, #8\n\t"
        "add	r1, r1, #0x29\n\t"
#else
        "mov	r1, #0x6329\n\t"
#endif
        "movt	r1, #0x5d08\n\t"
        "mov	lr, #0\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "umlal	r10, lr, r2, r1\n\t"
        "umaal	r11, lr, r3, r1\n\t"
        "umaal	r12, lr, r4, r1\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "umaal	r10, lr, r5, r1\n\t"
        "umaal	r11, lr, r6, r1\n\t"
        "umaal	r12, lr, r7, r1\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11}\n\t"
        "umaal	r10, lr, r8, r1\n\t"
        "umaal	r11, lr, r9, r1\n\t"
        "stm	sp!, {r10, r11, lr}\n\t"
        "sub	sp, sp, #32\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r1, #0x6\n\t"
        "lsl	r1, r1, #8\n\t"
        "add	r1, r1, #0x21\n\t"
#else
        "mov	r1, #0x621\n\t"
#endif
        "movt	r1, #0xeb21\n\t"
        "mov	lr, #0\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "umlal	r10, lr, r2, r1\n\t"
        "umaal	r11, lr, r3, r1\n\t"
        "umaal	r12, lr, r4, r1\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "umaal	r10, lr, r5, r1\n\t"
        "umaal	r11, lr, r6, r1\n\t"
        "umaal	r12, lr, r7, r1\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11}\n\t"
        "umaal	r10, lr, r8, r1\n\t"
        "umaal	r11, lr, r9, r1\n\t"
        "stm	sp!, {r10, r11, lr}\n\t"
        "sub	sp, sp, #32\n\t"
        /* Subtract at 4 * 32 */
        "ldm	sp, {r10, r11, r12}\n\t"
        "subs	r10, r10, r2\n\t"
        "sbcs	r11, r11, r3\n\t"
        "sbcs	r12, r12, r4\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "sbcs	r10, r10, r5\n\t"
        "sbcs	r11, r11, r6\n\t"
        "sbcs	r12, r12, r7\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11}\n\t"
        "sbcs	r10, r10, r8\n\t"
        "sbc	r11, r11, r9\n\t"
        "stm	sp!, {r10, r11}\n\t"
        "sub	sp, sp, #36\n\t"
        "asr	lr, r11, #25\n\t"
        /* Conditionally subtract order starting at bit 125 */
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r1, #0xa00000\n\t"
        "lsl	r1, r1, #8\n\t"
        "add	r1, r1, #0x0\n\t"
#else
        "mov	r1, #0xa0000000\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r2, #0xba\n\t"
        "lsl	r2, r2, #8\n\t"
        "add	r2, r2, #0x7d\n\t"
#else
        "mov	r2, #0xba7d\n\t"
#endif
        "movt	r2, #0x4b9e\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r3, #0x4c\n\t"
        "lsl	r3, r3, #8\n\t"
        "add	r3, r3, #0x63\n\t"
#else
        "mov	r3, #0x4c63\n\t"
#endif
        "movt	r3, #0xcb02\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r4, #0xf3\n\t"
        "lsl	r4, r4, #8\n\t"
        "add	r4, r4, #0x9a\n\t"
#else
        "mov	r4, #0xf39a\n\t"
#endif
        "movt	r4, #0xd45e\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r5, #0xdf\n\t"
        "lsl	r5, r5, #8\n\t"
        "add	r5, r5, #0x3b\n\t"
#else
        "mov	r5, #0xdf3b\n\t"
#endif
        "movt	r5, #0x29b\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r9, #0x20000\n\t"
        "lsl	r9, r9, #8\n\t"
        "add	r9, r9, #0x0\n\t"
#else
        "mov	r9, #0x2000000\n\t"
#endif
        "and	r1, r1, lr\n\t"
        "and	r2, r2, lr\n\t"
        "and	r3, r3, lr\n\t"
        "and	r4, r4, lr\n\t"
        "and	r5, r5, lr\n\t"
        "and	r9, r9, lr\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "adds	r10, r10, r1\n\t"
        "adcs	r11, r11, r2\n\t"
        "adcs	r12, r12, r3\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "adcs	r10, r10, r4\n\t"
        "adcs	r11, r11, r5\n\t"
        "adcs	r12, r12, #0\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "adcs	r10, r10, #0\n\t"
        "adcs	r11, r11, #0\n\t"
        "adcs	r12, r12, r9\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "sub	sp, sp, #48\n\t"
        "sub	%[s], %[s], #16\n\t"
        /* Load bits 252-376 */
        "add	sp, sp, #28\n\t"
        "ldm	sp, {r1, r2, r3, r4, r5}\n\t"
        "lsl	r5, r5, #4\n\t"
        "orr	r5, r5, r4, lsr #28\n\t"
        "lsl	r4, r4, #4\n\t"
        "orr	r4, r4, r3, lsr #28\n\t"
        "lsl	r3, r3, #4\n\t"
        "orr	r3, r3, r2, lsr #28\n\t"
        "lsl	r2, r2, #4\n\t"
        "orr	r2, r2, r1, lsr #28\n\t"
        "bfc	r5, #29, #3\n\t"
        "sub	sp, sp, #28\n\t"
        /* Sub product of top 8 words and order */
        /*   * -5cf5d3ed */
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r1, #0x2c\n\t"
        "lsl	r1, r1, #8\n\t"
        "add	r1, r1, #0x13\n\t"
#else
        "mov	r1, #0x2c13\n\t"
#endif
        "movt	r1, #0xa30a\n\t"
        "mov	lr, #0\n\t"
        "ldm	sp, {r6, r7, r8, r9}\n\t"
        "umlal	r6, lr, r2, r1\n\t"
        "umaal	r7, lr, r3, r1\n\t"
        "umaal	r8, lr, r4, r1\n\t"
        "umaal	r9, lr, r5, r1\n\t"
        "stm	sp, {r6, r7, r8, r9}\n\t"
        "add	sp, sp, #4\n\t"
        /*   * -5812631b */
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r1, #0x9c\n\t"
        "lsl	r1, r1, #8\n\t"
        "add	r1, r1, #0xe5\n\t"
#else
        "mov	r1, #0x9ce5\n\t"
#endif
        "movt	r1, #0xa7ed\n\t"
        "mov	r10, #0\n\t"
        "ldm	sp, {r6, r7, r8, r9}\n\t"
        "umlal	r6, r10, r2, r1\n\t"
        "umaal	r7, r10, r3, r1\n\t"
        "umaal	r8, r10, r4, r1\n\t"
        "umaal	r9, r10, r5, r1\n\t"
        "stm	sp, {r6, r7, r8, r9}\n\t"
        "add	sp, sp, #4\n\t"
        /*   * -a2f79cd7 */
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r1, #0x63\n\t"
        "lsl	r1, r1, #8\n\t"
        "add	r1, r1, #0x29\n\t"
#else
        "mov	r1, #0x6329\n\t"
#endif
        "movt	r1, #0x5d08\n\t"
        "mov	r11, #0\n\t"
        "ldm	sp, {r6, r7, r8, r9}\n\t"
        "umlal	r6, r11, r2, r1\n\t"
        "umaal	r7, r11, r3, r1\n\t"
        "umaal	r8, r11, r4, r1\n\t"
        "umaal	r9, r11, r5, r1\n\t"
        "stm	sp, {r6, r7, r8, r9}\n\t"
        "add	sp, sp, #4\n\t"
        /*   * -14def9df */
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r1, #0x6\n\t"
        "lsl	r1, r1, #8\n\t"
        "add	r1, r1, #0x21\n\t"
#else
        "mov	r1, #0x621\n\t"
#endif
        "movt	r1, #0xeb21\n\t"
        "mov	r12, #0\n\t"
        "ldm	sp, {r6, r7, r8, r9}\n\t"
        "umlal	r6, r12, r2, r1\n\t"
        "umaal	r7, r12, r3, r1\n\t"
        "umaal	r8, r12, r4, r1\n\t"
        "umaal	r9, r12, r5, r1\n\t"
        "stm	sp, {r6, r7, r8, r9}\n\t"
        "add	sp, sp, #4\n\t"
        /* Add overflows at 4 * 32 */
        "ldm	sp, {r6, r7, r8, r9}\n\t"
        "bfc	r9, #28, #4\n\t"
        "adds	r6, r6, lr\n\t"
        "adcs	r7, r7, r10\n\t"
        "adcs	r8, r8, r11\n\t"
        "adc	r9, r9, r12\n\t"
        /* Subtract top at 4 * 32 */
        "subs	r6, r6, r2\n\t"
        "sbcs	r7, r7, r3\n\t"
        "sbcs	r8, r8, r4\n\t"
        "sbcs	r9, r9, r5\n\t"
        "sbc	r1, r1, r1\n\t"
        "sub	sp, sp, #16\n\t"
        "ldm	sp, {r2, r3, r4, r5}\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r10, #0xd3\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xed\n\t"
#else
        "mov	r10, #0xd3ed\n\t"
#endif
        "movt	r10, #0x5cf5\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r11, #0x63\n\t"
        "lsl	r11, r11, #8\n\t"
        "add	r11, r11, #0x1a\n\t"
#else
        "mov	r11, #0x631a\n\t"
#endif
        "movt	r11, #0x5812\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r12, #0x9c\n\t"
        "lsl	r12, r12, #8\n\t"
        "add	r12, r12, #0xd6\n\t"
#else
        "mov	r12, #0x9cd6\n\t"
#endif
        "movt	r12, #0xa2f7\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	lr, #0xf9\n\t"
        "lsl	lr, lr, #8\n\t"
        "add	lr, lr, #0xde\n\t"
#else
        "mov	lr, #0xf9de\n\t"
#endif
        "movt	lr, #0x14de\n\t"
        "and	r10, r10, r1\n\t"
        "and	r11, r11, r1\n\t"
        "and	r12, r12, r1\n\t"
        "and	lr, lr, r1\n\t"
        "adds	r2, r2, r10\n\t"
        "adcs	r3, r3, r11\n\t"
        "adcs	r4, r4, r12\n\t"
        "adcs	r5, r5, lr\n\t"
        "adcs	r6, r6, #0\n\t"
        "adcs	r7, r7, #0\n\t"
        "and	r1, r1, #0x10000000\n\t"
        "adcs	r8, r8, #0\n\t"
        "adc	r9, r9, r1\n\t"
        "bfc	r9, #28, #4\n\t"
        /* Store result */
        "stm	%[s], {r2, r3, r4, r5, r6, r7, r8, r9}\n\t"
        "add	sp, sp, #52\n\t"
        : [s] "+r" (s)
        :
        : "memory", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr"
    );
}

void sc_muladd(byte* s_p, const byte* a_p, const byte* b_p, const byte* c_p)
{
    register byte* s asm ("r0") = s_p;
    register const byte* a asm ("r1") = a_p;
    register const byte* b asm ("r2") = b_p;
    register const byte* c asm ("r3") = c_p;

    __asm__ __volatile__ (
        "sub	sp, sp, #0x50\n\t"
        "add	lr, sp, #0x44\n\t"
        "stm	lr, {%[s], %[a], %[c]}\n\t"
        "mov	lr, %[b]\n\t"
        "ldm	%[a], {%[s], %[a], %[b], %[c]}\n\t"
        "ldm	lr!, {r4, r5, r6}\n\t"
        "umull	r10, r11, %[s], r4\n\t"
        "umull	r12, r7, %[a], r4\n\t"
        "umaal	r11, r12, %[s], r5\n\t"
        "umull	r8, r9, %[b], r4\n\t"
        "umaal	r12, r8, %[a], r5\n\t"
        "umaal	r12, r7, %[s], r6\n\t"
        "umaal	r8, r9, %[c], r4\n\t"
        "stm	sp, {r10, r11, r12}\n\t"
        "umaal	r7, r8, %[b], r5\n\t"
        "ldm	lr!, {r4}\n\t"
        "umull	r10, r11, %[a], r6\n\t"
        "umaal	r8, r9, %[b], r6\n\t"
        "umaal	r7, r10, %[s], r4\n\t"
        "umaal	r8, r11, %[c], r5\n\t"
        "str	r7, [sp, #12]\n\t"
        "umaal	r8, r10, %[a], r4\n\t"
        "umaal	r9, r11, %[c], r6\n\t"
        "umaal	r9, r10, %[b], r4\n\t"
        "umaal	r10, r11, %[c], r4\n\t"
        "ldm	lr, {r4, r5, r6, r7}\n\t"
        "mov	r12, #0\n\t"
        "umlal	r8, r12, %[s], r4\n\t"
        "umaal	r9, r12, %[a], r4\n\t"
        "umaal	r10, r12, %[b], r4\n\t"
        "umaal	r11, r12, %[c], r4\n\t"
        "mov	r4, #0\n\t"
        "umlal	r9, r4, %[s], r5\n\t"
        "umaal	r10, r4, %[a], r5\n\t"
        "umaal	r11, r4, %[b], r5\n\t"
        "umaal	r12, r4, %[c], r5\n\t"
        "mov	r5, #0\n\t"
        "umlal	r10, r5, %[s], r6\n\t"
        "umaal	r11, r5, %[a], r6\n\t"
        "umaal	r12, r5, %[b], r6\n\t"
        "umaal	r4, r5, %[c], r6\n\t"
        "mov	r6, #0\n\t"
        "umlal	r11, r6, %[s], r7\n\t"
        "ldr	%[s], [sp, #72]\n\t"
        "umaal	r12, r6, %[a], r7\n\t"
        "add	%[s], %[s], #16\n\t"
        "umaal	r4, r6, %[b], r7\n\t"
        "sub	lr, lr, #16\n\t"
        "umaal	r5, r6, %[c], r7\n\t"
        "ldm	%[s], {%[s], %[a], %[b], %[c]}\n\t"
        "str	r6, [sp, #64]\n\t"
        "ldm	lr!, {r6}\n\t"
        "mov	r7, #0\n\t"
        "umlal	r8, r7, %[s], r6\n\t"
        "umaal	r9, r7, %[a], r6\n\t"
        "str	r8, [sp, #16]\n\t"
        "umaal	r10, r7, %[b], r6\n\t"
        "umaal	r11, r7, %[c], r6\n\t"
        "ldm	lr!, {r6}\n\t"
        "mov	r8, #0\n\t"
        "umlal	r9, r8, %[s], r6\n\t"
        "umaal	r10, r8, %[a], r6\n\t"
        "str	r9, [sp, #20]\n\t"
        "umaal	r11, r8, %[b], r6\n\t"
        "umaal	r12, r8, %[c], r6\n\t"
        "ldm	lr!, {r6}\n\t"
        "mov	r9, #0\n\t"
        "umlal	r10, r9, %[s], r6\n\t"
        "umaal	r11, r9, %[a], r6\n\t"
        "str	r10, [sp, #24]\n\t"
        "umaal	r12, r9, %[b], r6\n\t"
        "umaal	r4, r9, %[c], r6\n\t"
        "ldm	lr!, {r6}\n\t"
        "mov	r10, #0\n\t"
        "umlal	r11, r10, %[s], r6\n\t"
        "umaal	r12, r10, %[a], r6\n\t"
        "str	r11, [sp, #28]\n\t"
        "umaal	r4, r10, %[b], r6\n\t"
        "umaal	r5, r10, %[c], r6\n\t"
        "ldm	lr!, {r11}\n\t"
        "umaal	r12, r7, %[s], r11\n\t"
        "umaal	r4, r7, %[a], r11\n\t"
        "ldr	r6, [sp, #64]\n\t"
        "umaal	r5, r7, %[b], r11\n\t"
        "umaal	r6, r7, %[c], r11\n\t"
        "ldm	lr!, {r11}\n\t"
        "umaal	r4, r8, %[s], r11\n\t"
        "umaal	r5, r8, %[a], r11\n\t"
        "umaal	r6, r8, %[b], r11\n\t"
        "umaal	r7, r8, %[c], r11\n\t"
        "ldm	lr, {r11, lr}\n\t"
        "umaal	r5, r9, %[s], r11\n\t"
        "umaal	r6, r10, %[s], lr\n\t"
        "umaal	r6, r9, %[a], r11\n\t"
        "umaal	r7, r10, %[a], lr\n\t"
        "umaal	r7, r9, %[b], r11\n\t"
        "umaal	r8, r10, %[b], lr\n\t"
        "umaal	r8, r9, %[c], r11\n\t"
        "umaal	r9, r10, %[c], lr\n\t"
        "mov	%[c], r12\n\t"
        "add	lr, sp, #32\n\t"
        "stm	lr, {%[c], r4, r5, r6, r7, r8, r9, r10}\n\t"
        "ldr	%[s], [sp, #68]\n\t"
        /* Add c to a * b */
        "ldr	lr, [sp, #76]\n\t"
        "ldm	sp!, {%[b], %[c], r4, r5, r6, r7, r8, r9}\n\t"
        "ldm	lr!, {%[a], r10, r11, r12}\n\t"
        "adds	%[b], %[b], %[a]\n\t"
        "adcs	%[c], %[c], r10\n\t"
        "adcs	r4, r4, r11\n\t"
        "adcs	r5, r5, r12\n\t"
        "ldm	lr!, {%[a], r10, r11, r12}\n\t"
        "adcs	r6, r6, %[a]\n\t"
        "adcs	r7, r7, r10\n\t"
        "adcs	r8, r8, r11\n\t"
        "adcs	r9, r9, r12\n\t"
        "mov	%[a], r9\n\t"
        "stm	%[s], {%[b], %[c], r4, r5, r6, r7, r8, r9}\n\t"
        "ldm	sp, {%[b], %[c], r4, r5, r6, r7, r8, r9}\n\t"
        "adcs	%[b], %[b], #0\n\t"
        "adcs	%[c], %[c], #0\n\t"
        "adcs	r4, r4, #0\n\t"
        "adcs	r5, r5, #0\n\t"
        "adcs	r6, r6, #0\n\t"
        "adcs	r7, r7, #0\n\t"
        "adcs	r8, r8, #0\n\t"
        "adc	r9, r9, #0\n\t"
        "sub	sp, sp, #32\n\t"
        /* Get 252..503 and 504..507 */
        "lsr	lr, r9, #24\n\t"
        "bfc	r9, #24, #8\n\t"
        "lsl	r9, r9, #4\n\t"
        "orr	r9, r9, r8, lsr #28\n\t"
        "lsl	r8, r8, #4\n\t"
        "orr	r8, r8, r7, lsr #28\n\t"
        "lsl	r7, r7, #4\n\t"
        "orr	r7, r7, r6, lsr #28\n\t"
        "lsl	r6, r6, #4\n\t"
        "orr	r6, r6, r5, lsr #28\n\t"
        "lsl	r5, r5, #4\n\t"
        "orr	r5, r5, r4, lsr #28\n\t"
        "lsl	r4, r4, #4\n\t"
        "orr	r4, r4, %[c], lsr #28\n\t"
        "lsl	%[c], %[c], #4\n\t"
        "orr	%[c], %[c], %[b], lsr #28\n\t"
        "lsl	%[b], %[b], #4\n\t"
        "orr	%[b], %[b], %[a], lsr #28\n\t"
        /* Add order times bits 504..507 */
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r10, #0x2c\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x13\n\t"
#else
        "mov	r10, #0x2c13\n\t"
#endif
        "movt	r10, #0xa30a\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r11, #0x9c\n\t"
        "lsl	r11, r11, #8\n\t"
        "add	r11, r11, #0xe5\n\t"
#else
        "mov	r11, #0x9ce5\n\t"
#endif
        "movt	r11, #0xa7ed\n\t"
        "mov	%[a], #0\n\t"
        "umlal	%[b], %[a], r10, lr\n\t"
        "umaal	%[c], %[a], r11, lr\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r10, #0x63\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x29\n\t"
#else
        "mov	r10, #0x6329\n\t"
#endif
        "movt	r10, #0x5d08\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r11, #0x6\n\t"
        "lsl	r11, r11, #8\n\t"
        "add	r11, r11, #0x21\n\t"
#else
        "mov	r11, #0x621\n\t"
#endif
        "movt	r11, #0xeb21\n\t"
        "umaal	r4, %[a], r10, lr\n\t"
        "umaal	r5, %[a], r11, lr\n\t"
        "adds	r6, r6, %[a]\n\t"
        "adcs	r7, r7, #0\n\t"
        "adcs	r8, r8, #0\n\t"
        "adc	r9, r9, #0\n\t"
        "subs	r6, r6, lr\n\t"
        "sbcs	r7, r7, #0\n\t"
        "sbcs	r8, r8, #0\n\t"
        "sbc	r9, r9, #0\n\t"
        /* Sub product of top 8 words and order */
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	%[a], #0x2c\n\t"
        "lsl	%[a], %[a], #8\n\t"
        "add	%[a], %[a], #0x13\n\t"
#else
        "mov	%[a], #0x2c13\n\t"
#endif
        "movt	%[a], #0xa30a\n\t"
        "mov	lr, #0\n\t"
        "ldm	%[s]!, {r10, r11, r12}\n\t"
        "umlal	r10, lr, %[b], %[a]\n\t"
        "umaal	r11, lr, %[c], %[a]\n\t"
        "umaal	r12, lr, r4, %[a]\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	%[s]!, {r10, r11, r12}\n\t"
        "umaal	r10, lr, r5, %[a]\n\t"
        "umaal	r11, lr, r6, %[a]\n\t"
        "umaal	r12, lr, r7, %[a]\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	%[s]!, {r10, r11}\n\t"
        "umaal	r10, lr, r8, %[a]\n\t"
        "bfc	r11, #28, #4\n\t"
        "umaal	r11, lr, r9, %[a]\n\t"
        "stm	sp!, {r10, r11, lr}\n\t"
        "sub	%[s], %[s], #16\n\t"
        "sub	sp, sp, #32\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	%[a], #0x9c\n\t"
        "lsl	%[a], %[a], #8\n\t"
        "add	%[a], %[a], #0xe5\n\t"
#else
        "mov	%[a], #0x9ce5\n\t"
#endif
        "movt	%[a], #0xa7ed\n\t"
        "mov	lr, #0\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "umlal	r10, lr, %[b], %[a]\n\t"
        "umaal	r11, lr, %[c], %[a]\n\t"
        "umaal	r12, lr, r4, %[a]\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "umaal	r10, lr, r5, %[a]\n\t"
        "umaal	r11, lr, r6, %[a]\n\t"
        "umaal	r12, lr, r7, %[a]\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11}\n\t"
        "umaal	r10, lr, r8, %[a]\n\t"
        "umaal	r11, lr, r9, %[a]\n\t"
        "stm	sp!, {r10, r11, lr}\n\t"
        "sub	sp, sp, #32\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	%[a], #0x63\n\t"
        "lsl	%[a], %[a], #8\n\t"
        "add	%[a], %[a], #0x29\n\t"
#else
        "mov	%[a], #0x6329\n\t"
#endif
        "movt	%[a], #0x5d08\n\t"
        "mov	lr, #0\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "umlal	r10, lr, %[b], %[a]\n\t"
        "umaal	r11, lr, %[c], %[a]\n\t"
        "umaal	r12, lr, r4, %[a]\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "umaal	r10, lr, r5, %[a]\n\t"
        "umaal	r11, lr, r6, %[a]\n\t"
        "umaal	r12, lr, r7, %[a]\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11}\n\t"
        "umaal	r10, lr, r8, %[a]\n\t"
        "umaal	r11, lr, r9, %[a]\n\t"
        "stm	sp!, {r10, r11, lr}\n\t"
        "sub	sp, sp, #32\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	%[a], #0x6\n\t"
        "lsl	%[a], %[a], #8\n\t"
        "add	%[a], %[a], #0x21\n\t"
#else
        "mov	%[a], #0x621\n\t"
#endif
        "movt	%[a], #0xeb21\n\t"
        "mov	lr, #0\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "umlal	r10, lr, %[b], %[a]\n\t"
        "umaal	r11, lr, %[c], %[a]\n\t"
        "umaal	r12, lr, r4, %[a]\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "umaal	r10, lr, r5, %[a]\n\t"
        "umaal	r11, lr, r6, %[a]\n\t"
        "umaal	r12, lr, r7, %[a]\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11}\n\t"
        "umaal	r10, lr, r8, %[a]\n\t"
        "umaal	r11, lr, r9, %[a]\n\t"
        "stm	sp!, {r10, r11, lr}\n\t"
        "sub	sp, sp, #32\n\t"
        /* Subtract at 4 * 32 */
        "ldm	sp, {r10, r11, r12}\n\t"
        "subs	r10, r10, %[b]\n\t"
        "sbcs	r11, r11, %[c]\n\t"
        "sbcs	r12, r12, r4\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "sbcs	r10, r10, r5\n\t"
        "sbcs	r11, r11, r6\n\t"
        "sbcs	r12, r12, r7\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11}\n\t"
        "sbcs	r10, r10, r8\n\t"
        "sbc	r11, r11, r9\n\t"
        "stm	sp!, {r10, r11}\n\t"
        "sub	sp, sp, #36\n\t"
        "asr	lr, r11, #25\n\t"
        /* Conditionally subtract order starting at bit 125 */
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	%[a], #0xa00000\n\t"
        "lsl	%[a], %[a], #8\n\t"
        "add	%[a], %[a], #0x0\n\t"
#else
        "mov	%[a], #0xa0000000\n\t"
#endif
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	%[b], #0xba\n\t"
        "lsl	%[b], %[b], #8\n\t"
        "add	%[b], %[b], #0x7d\n\t"
#else
        "mov	%[b], #0xba7d\n\t"
#endif
        "movt	%[b], #0x4b9e\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	%[c], #0x4c\n\t"
        "lsl	%[c], %[c], #8\n\t"
        "add	%[c], %[c], #0x63\n\t"
#else
        "mov	%[c], #0x4c63\n\t"
#endif
        "movt	%[c], #0xcb02\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r4, #0xf3\n\t"
        "lsl	r4, r4, #8\n\t"
        "add	r4, r4, #0x9a\n\t"
#else
        "mov	r4, #0xf39a\n\t"
#endif
        "movt	r4, #0xd45e\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r5, #0xdf\n\t"
        "lsl	r5, r5, #8\n\t"
        "add	r5, r5, #0x3b\n\t"
#else
        "mov	r5, #0xdf3b\n\t"
#endif
        "movt	r5, #0x29b\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r9, #0x20000\n\t"
        "lsl	r9, r9, #8\n\t"
        "add	r9, r9, #0x0\n\t"
#else
        "mov	r9, #0x2000000\n\t"
#endif
        "and	%[a], %[a], lr\n\t"
        "and	%[b], %[b], lr\n\t"
        "and	%[c], %[c], lr\n\t"
        "and	r4, r4, lr\n\t"
        "and	r5, r5, lr\n\t"
        "and	r9, r9, lr\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "adds	r10, r10, %[a]\n\t"
        "adcs	r11, r11, %[b]\n\t"
        "adcs	r12, r12, %[c]\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "adcs	r10, r10, r4\n\t"
        "adcs	r11, r11, r5\n\t"
        "adcs	r12, r12, #0\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "ldm	sp, {r10, r11, r12}\n\t"
        "adcs	r10, r10, #0\n\t"
        "adcs	r11, r11, #0\n\t"
        "adcs	r12, r12, r9\n\t"
        "stm	sp!, {r10, r11, r12}\n\t"
        "sub	sp, sp, #48\n\t"
        "sub	%[s], %[s], #16\n\t"
        /* Load bits 252-376 */
        "add	sp, sp, #28\n\t"
        "ldm	sp, {%[a], %[b], %[c], r4, r5}\n\t"
        "lsl	r5, r5, #4\n\t"
        "orr	r5, r5, r4, lsr #28\n\t"
        "lsl	r4, r4, #4\n\t"
        "orr	r4, r4, %[c], lsr #28\n\t"
        "lsl	%[c], %[c], #4\n\t"
        "orr	%[c], %[c], %[b], lsr #28\n\t"
        "lsl	%[b], %[b], #4\n\t"
        "orr	%[b], %[b], %[a], lsr #28\n\t"
        "bfc	r5, #29, #3\n\t"
        "sub	sp, sp, #28\n\t"
        /* Sub product of top 8 words and order */
        /*   * -5cf5d3ed */
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	%[a], #0x2c\n\t"
        "lsl	%[a], %[a], #8\n\t"
        "add	%[a], %[a], #0x13\n\t"
#else
        "mov	%[a], #0x2c13\n\t"
#endif
        "movt	%[a], #0xa30a\n\t"
        "mov	lr, #0\n\t"
        "ldm	sp, {r6, r7, r8, r9}\n\t"
        "umlal	r6, lr, %[b], %[a]\n\t"
        "umaal	r7, lr, %[c], %[a]\n\t"
        "umaal	r8, lr, r4, %[a]\n\t"
        "umaal	r9, lr, r5, %[a]\n\t"
        "stm	sp, {r6, r7, r8, r9}\n\t"
        "add	sp, sp, #4\n\t"
        /*   * -5812631b */
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	%[a], #0x9c\n\t"
        "lsl	%[a], %[a], #8\n\t"
        "add	%[a], %[a], #0xe5\n\t"
#else
        "mov	%[a], #0x9ce5\n\t"
#endif
        "movt	%[a], #0xa7ed\n\t"
        "mov	r10, #0\n\t"
        "ldm	sp, {r6, r7, r8, r9}\n\t"
        "umlal	r6, r10, %[b], %[a]\n\t"
        "umaal	r7, r10, %[c], %[a]\n\t"
        "umaal	r8, r10, r4, %[a]\n\t"
        "umaal	r9, r10, r5, %[a]\n\t"
        "stm	sp, {r6, r7, r8, r9}\n\t"
        "add	sp, sp, #4\n\t"
        /*   * -a2f79cd7 */
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	%[a], #0x63\n\t"
        "lsl	%[a], %[a], #8\n\t"
        "add	%[a], %[a], #0x29\n\t"
#else
        "mov	%[a], #0x6329\n\t"
#endif
        "movt	%[a], #0x5d08\n\t"
        "mov	r11, #0\n\t"
        "ldm	sp, {r6, r7, r8, r9}\n\t"
        "umlal	r6, r11, %[b], %[a]\n\t"
        "umaal	r7, r11, %[c], %[a]\n\t"
        "umaal	r8, r11, r4, %[a]\n\t"
        "umaal	r9, r11, r5, %[a]\n\t"
        "stm	sp, {r6, r7, r8, r9}\n\t"
        "add	sp, sp, #4\n\t"
        /*   * -14def9df */
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	%[a], #0x6\n\t"
        "lsl	%[a], %[a], #8\n\t"
        "add	%[a], %[a], #0x21\n\t"
#else
        "mov	%[a], #0x621\n\t"
#endif
        "movt	%[a], #0xeb21\n\t"
        "mov	r12, #0\n\t"
        "ldm	sp, {r6, r7, r8, r9}\n\t"
        "umlal	r6, r12, %[b], %[a]\n\t"
        "umaal	r7, r12, %[c], %[a]\n\t"
        "umaal	r8, r12, r4, %[a]\n\t"
        "umaal	r9, r12, r5, %[a]\n\t"
        "stm	sp, {r6, r7, r8, r9}\n\t"
        "add	sp, sp, #4\n\t"
        /* Add overflows at 4 * 32 */
        "ldm	sp, {r6, r7, r8, r9}\n\t"
        "bfc	r9, #28, #4\n\t"
        "adds	r6, r6, lr\n\t"
        "adcs	r7, r7, r10\n\t"
        "adcs	r8, r8, r11\n\t"
        "adc	r9, r9, r12\n\t"
        /* Subtract top at 4 * 32 */
        "subs	r6, r6, %[b]\n\t"
        "sbcs	r7, r7, %[c]\n\t"
        "sbcs	r8, r8, r4\n\t"
        "sbcs	r9, r9, r5\n\t"
        "sbc	%[a], %[a], %[a]\n\t"
        "sub	sp, sp, #16\n\t"
        "ldm	sp, {%[b], %[c], r4, r5}\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r10, #0xd3\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xed\n\t"
#else
        "mov	r10, #0xd3ed\n\t"
#endif
        "movt	r10, #0x5cf5\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r11, #0x63\n\t"
        "lsl	r11, r11, #8\n\t"
        "add	r11, r11, #0x1a\n\t"
#else
        "mov	r11, #0x631a\n\t"
#endif
        "movt	r11, #0x5812\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	r12, #0x9c\n\t"
        "lsl	r12, r12, #8\n\t"
        "add	r12, r12, #0xd6\n\t"
#else
        "mov	r12, #0x9cd6\n\t"
#endif
        "movt	r12, #0xa2f7\n\t"
#if defined(WOLFSSL_SP_ARM_ARCH) && (WOLFSSL_SP_ARM_ARCH < 7)
        "mov	lr, #0xf9\n\t"
        "lsl	lr, lr, #8\n\t"
        "add	lr, lr, #0xde\n\t"
#else
        "mov	lr, #0xf9de\n\t"
#endif
        "movt	lr, #0x14de\n\t"
        "and	r10, r10, %[a]\n\t"
        "and	r11, r11, %[a]\n\t"
        "and	r12, r12, %[a]\n\t"
        "and	lr, lr, %[a]\n\t"
        "adds	%[b], %[b], r10\n\t"
        "adcs	%[c], %[c], r11\n\t"
        "adcs	r4, r4, r12\n\t"
        "adcs	r5, r5, lr\n\t"
        "adcs	r6, r6, #0\n\t"
        "adcs	r7, r7, #0\n\t"
        "and	%[a], %[a], #0x10000000\n\t"
        "adcs	r8, r8, #0\n\t"
        "adc	r9, r9, %[a]\n\t"
        "bfc	r9, #28, #4\n\t"
        /* Store result */
        "stm	%[s], {%[b], %[c], r4, r5, r6, r7, r8, r9}\n\t"
        "add	sp, sp, #0x50\n\t"
        : [s] "+r" (s), [a] "+r" (a), [b] "+r" (b), [c] "+r" (c)
        :
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr"
    );
}

#endif /* HAVE_ED25519 */

#endif /* !CURVE25519_SMALL || !ED25519_SMALL */
#endif /* HAVE_CURVE25519 || HAVE_ED25519 */
#endif /* !__aarch64__ && !__thumb__ */
#endif /* WOLFSSL_ARMASM */
#endif /* WOLFSSL_ARMASM_INLINE */
