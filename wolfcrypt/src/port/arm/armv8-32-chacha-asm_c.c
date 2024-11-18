/* armv8-32-chacha-asm
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
 *   ruby ./chacha/chacha.rb arm32 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-32-chacha-asm.c
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
#ifdef HAVE_CHACHA
#include <wolfssl/wolfcrypt/chacha.h>

void wc_chacha_setiv(word32* x_p, const byte* iv_p, word32 counter_p)
{
    register word32* x asm ("r0") = (word32*)x_p;
    register const byte* iv asm ("r1") = (const byte*)iv_p;
    register word32 counter asm ("r2") = (word32)counter_p;

    __asm__ __volatile__ (
        "add	r3, %[x], #52\n\t"
        "ldr	r4, [%[iv]]\n\t"
        "ldr	r12, [%[iv], #4]\n\t"
        "ldr	lr, [%[iv], #8]\n\t"
        "str	%[counter], [%[x], #48]\n\t"
#ifdef BIG_ENDIAN_ORDER
        "rev	r4, r4\n\t"
        "rev	r12, r12\n\t"
        "rev	lr, lr\n\t"
#endif /* BIG_ENDIAN_ORDER */
        "stm	r3, {r4, r12, lr}\n\t"
        : [x] "+r" (x), [iv] "+r" (iv), [counter] "+r" (counter)
        :
        : "memory", "cc", "r3", "r12", "lr", "r4"
    );
}

static const word32 L_chacha_arm32_constants[] = {
    0x61707865, 0x3120646e, 0x79622d36, 0x6b206574,
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
};

void wc_chacha_setkey(word32* x_p, const byte* key_p, word32 keySz_p)
{
    register word32* x asm ("r0") = (word32*)x_p;
    register const byte* key asm ("r1") = (const byte*)key_p;
    register word32 keySz asm ("r2") = (word32)keySz_p;
    register word32* L_chacha_arm32_constants_c asm ("r3") =
        (word32*)&L_chacha_arm32_constants;

    __asm__ __volatile__ (
        "subs	%[keySz], %[keySz], #16\n\t"
        "add	r3, r3, %[keySz]\n\t"
        /* Start state with constants */
        "ldm	r3, {r4, r5, r12, lr}\n\t"
        "stm	%[x]!, {r4, r5, r12, lr}\n\t"
        /* Next is first 16 bytes of key. */
        "ldr	r4, [%[key]]\n\t"
        "ldr	r5, [%[key], #4]\n\t"
        "ldr	r12, [%[key], #8]\n\t"
        "ldr	lr, [%[key], #12]\n\t"
#ifdef BIG_ENDIAN_ORDER
        "rev	r4, r4\n\t"
        "rev	r5, r5\n\t"
        "rev	r12, r12\n\t"
        "rev	lr, lr\n\t"
#endif /* BIG_ENDIAN_ORDER */
        "stm	%[x]!, {r4, r5, r12, lr}\n\t"
        /* Next 16 bytes of key. */
        "beq	L_chacha_arm32_setkey_same_keyb_ytes_%=\n\t"
        /* Update key pointer for next 16 bytes. */
        "add	%[key], %[key], %[keySz]\n\t"
        "ldr	r4, [%[key]]\n\t"
        "ldr	r5, [%[key], #4]\n\t"
        "ldr	r12, [%[key], #8]\n\t"
        "ldr	lr, [%[key], #12]\n\t"
        "\n"
    "L_chacha_arm32_setkey_same_keyb_ytes_%=: \n\t"
        "stm	%[x], {r4, r5, r12, lr}\n\t"
        : [x] "+r" (x), [key] "+r" (key), [keySz] "+r" (keySz),
          [L_chacha_arm32_constants] "+r" (L_chacha_arm32_constants_c)
        :
        : "memory", "cc", "r12", "lr", "r4", "r5"
    );
}

#ifdef WOLFSSL_ARMASM_NO_NEON
void wc_chacha_crypt_bytes(ChaCha* ctx_p, byte* c_p, const byte* m_p,
    word32 len_p)
{
    register ChaCha* ctx asm ("r0") = (ChaCha*)ctx_p;
    register byte* c asm ("r1") = (byte*)c_p;
    register const byte* m asm ("r2") = (const byte*)m_p;
    register word32 len asm ("r3") = (word32)len_p;

    __asm__ __volatile__ (
        "sub	sp, sp, #52\n\t"
        "mov	lr, %[ctx]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	%[ctx], [sp, #32]\n\t"
        "str	%[c], [sp, #36]\n\t"
#else
        "strd	%[ctx], %[c], [sp, #32]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	%[m], [sp, #40]\n\t"
        "str	%[len], [sp, #44]\n\t"
#else
        "strd	%[m], %[len], [sp, #40]\n\t"
#endif
        "\n"
    "L_chacha_arm32_crypt_block_%=: \n\t"
        /* Put x[12]..x[15] onto stack. */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [lr, #48]\n\t"
        "ldr	r5, [lr, #52]\n\t"
#else
        "ldrd	r4, r5, [lr, #48]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [lr, #56]\n\t"
        "ldr	r7, [lr, #60]\n\t"
#else
        "ldrd	r6, r7, [lr, #56]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r4, [sp, #16]\n\t"
        "str	r5, [sp, #20]\n\t"
#else
        "strd	r4, r5, [sp, #16]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r6, [sp, #24]\n\t"
        "str	r7, [sp, #28]\n\t"
#else
        "strd	r6, r7, [sp, #24]\n\t"
#endif
        /* Load x[0]..x[12] into registers. */
        "ldm	lr, {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12}\n\t"
        /* 10x 2 full rounds to perform. */
        "mov	lr, #10\n\t"
        "str	lr, [sp, #48]\n\t"
        "\n"
    "L_chacha_arm32_crypt_loop_%=: \n\t"
        /* 0, 4,  8, 12 */
        /* 1, 5,  9, 13 */
        "ldr	lr, [sp, #20]\n\t"
        "add	%[ctx], %[ctx], r4\n\t"
        "add	%[c], %[c], r5\n\t"
        "eor	r12, r12, %[ctx]\n\t"
        "eor	lr, lr, %[c]\n\t"
        "ror	r12, r12, #16\n\t"
        "ror	lr, lr, #16\n\t"
        "add	r8, r8, r12\n\t"
        "add	r9, r9, lr\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r9\n\t"
        "ror	r4, r4, #20\n\t"
        "ror	r5, r5, #20\n\t"
        "add	%[ctx], %[ctx], r4\n\t"
        "add	%[c], %[c], r5\n\t"
        "eor	r12, r12, %[ctx]\n\t"
        "eor	lr, lr, %[c]\n\t"
        "ror	r12, r12, #24\n\t"
        "ror	lr, lr, #24\n\t"
        "add	r8, r8, r12\n\t"
        "add	r9, r9, lr\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r9\n\t"
        "ror	r4, r4, #25\n\t"
        "ror	r5, r5, #25\n\t"
        "str	r12, [sp, #16]\n\t"
        "str	lr, [sp, #20]\n\t"
        /* 2, 6, 10, 14 */
        /* 3, 7, 11, 15 */
        "ldr	r12, [sp, #24]\n\t"
        "ldr	lr, [sp, #28]\n\t"
        "add	%[m], %[m], r6\n\t"
        "add	%[len], %[len], r7\n\t"
        "eor	r12, r12, %[m]\n\t"
        "eor	lr, lr, %[len]\n\t"
        "ror	r12, r12, #16\n\t"
        "ror	lr, lr, #16\n\t"
        "add	r10, r10, r12\n\t"
        "add	r11, r11, lr\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
        "ror	r6, r6, #20\n\t"
        "ror	r7, r7, #20\n\t"
        "add	%[m], %[m], r6\n\t"
        "add	%[len], %[len], r7\n\t"
        "eor	r12, r12, %[m]\n\t"
        "eor	lr, lr, %[len]\n\t"
        "ror	r12, r12, #24\n\t"
        "ror	lr, lr, #24\n\t"
        "add	r10, r10, r12\n\t"
        "add	r11, r11, lr\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
        "ror	r6, r6, #25\n\t"
        "ror	r7, r7, #25\n\t"
        /* 3, 4,  9, 14 */
        /* 0, 5, 10, 15 */
        "add	%[len], %[len], r4\n\t"
        "add	%[ctx], %[ctx], r5\n\t"
        "eor	r12, r12, %[len]\n\t"
        "eor	lr, lr, %[ctx]\n\t"
        "ror	r12, r12, #16\n\t"
        "ror	lr, lr, #16\n\t"
        "add	r9, r9, r12\n\t"
        "add	r10, r10, lr\n\t"
        "eor	r4, r4, r9\n\t"
        "eor	r5, r5, r10\n\t"
        "ror	r4, r4, #20\n\t"
        "ror	r5, r5, #20\n\t"
        "add	%[len], %[len], r4\n\t"
        "add	%[ctx], %[ctx], r5\n\t"
        "eor	r12, r12, %[len]\n\t"
        "eor	lr, lr, %[ctx]\n\t"
        "ror	r12, r12, #24\n\t"
        "ror	lr, lr, #24\n\t"
        "add	r9, r9, r12\n\t"
        "add	r10, r10, lr\n\t"
        "eor	r4, r4, r9\n\t"
        "eor	r5, r5, r10\n\t"
        "ror	r4, r4, #25\n\t"
        "ror	r5, r5, #25\n\t"
        "str	r12, [sp, #24]\n\t"
        "str	lr, [sp, #28]\n\t"
        "ldr	r12, [sp, #16]\n\t"
        "ldr	lr, [sp, #20]\n\t"
        /* 1, 6, 11, 12 */
        /* 2, 7,  8, 13 */
        "add	%[c], %[c], r6\n\t"
        "add	%[m], %[m], r7\n\t"
        "eor	r12, r12, %[c]\n\t"
        "eor	lr, lr, %[m]\n\t"
        "ror	r12, r12, #16\n\t"
        "ror	lr, lr, #16\n\t"
        "add	r11, r11, r12\n\t"
        "add	r8, r8, lr\n\t"
        "eor	r6, r6, r11\n\t"
        "eor	r7, r7, r8\n\t"
        "ror	r6, r6, #20\n\t"
        "ror	r7, r7, #20\n\t"
        "add	%[c], %[c], r6\n\t"
        "add	%[m], %[m], r7\n\t"
        "eor	r12, r12, %[c]\n\t"
        "eor	lr, lr, %[m]\n\t"
        "ror	r12, r12, #24\n\t"
        "ror	lr, lr, #24\n\t"
        "add	r11, r11, r12\n\t"
        "add	r8, r8, lr\n\t"
        "eor	r6, r6, r11\n\t"
        "eor	r7, r7, r8\n\t"
        "ror	r6, r6, #25\n\t"
        "ror	r7, r7, #25\n\t"
        "str	lr, [sp, #20]\n\t"
        /* Check if we have done enough rounds. */
        "ldr	lr, [sp, #48]\n\t"
        "subs	lr, lr, #1\n\t"
        "str	lr, [sp, #48]\n\t"
        "bgt	L_chacha_arm32_crypt_loop_%=\n\t"
        "stm	sp, {r8, r9, r10, r11, r12}\n\t"
        "ldr	lr, [sp, #32]\n\t"
        "mov	r12, sp\n\t"
        /* Add in original state */
        "ldm	lr!, {r8, r9, r10, r11}\n\t"
        "add	%[ctx], %[ctx], r8\n\t"
        "add	%[c], %[c], r9\n\t"
        "add	%[m], %[m], r10\n\t"
        "add	%[len], %[len], r11\n\t"
        "ldm	lr!, {r8, r9, r10, r11}\n\t"
        "add	r4, r4, r8\n\t"
        "add	r5, r5, r9\n\t"
        "add	r6, r6, r10\n\t"
        "add	r7, r7, r11\n\t"
        "ldm	r12, {r8, r9}\n\t"
        "ldm	lr!, {r10, r11}\n\t"
        "add	r8, r8, r10\n\t"
        "add	r9, r9, r11\n\t"
        "stm	r12!, {r8, r9}\n\t"
        "ldm	r12, {r8, r9}\n\t"
        "ldm	lr!, {r10, r11}\n\t"
        "add	r8, r8, r10\n\t"
        "add	r9, r9, r11\n\t"
        "stm	r12!, {r8, r9}\n\t"
        "ldm	r12, {r8, r9}\n\t"
        "ldm	lr!, {r10, r11}\n\t"
        "add	r8, r8, r10\n\t"
        "add	r9, r9, r11\n\t"
        "add	r10, r10, #1\n\t"
        "stm	r12!, {r8, r9}\n\t"
        "str	r10, [lr, #-8]\n\t"
        "ldm	r12, {r8, r9}\n\t"
        "ldm	lr, {r10, r11}\n\t"
        "add	r8, r8, r10\n\t"
        "add	r9, r9, r11\n\t"
        "stm	r12, {r8, r9}\n\t"
        "ldr	r12, [sp, #44]\n\t"
        "cmp	r12, #0x40\n\t"
        "blt	L_chacha_arm32_crypt_lt_block_%=\n\t"
        "ldr	r12, [sp, #40]\n\t"
        "ldr	lr, [sp, #36]\n\t"
        /* XOR state into 64 bytes. */
        "ldr	r8, [r12]\n\t"
        "ldr	r9, [r12, #4]\n\t"
        "ldr	r10, [r12, #8]\n\t"
        "ldr	r11, [r12, #12]\n\t"
        "eor	%[ctx], %[ctx], r8\n\t"
        "eor	%[c], %[c], r9\n\t"
        "eor	%[m], %[m], r10\n\t"
        "eor	%[len], %[len], r11\n\t"
        "str	%[ctx], [lr]\n\t"
        "str	%[c], [lr, #4]\n\t"
        "str	%[m], [lr, #8]\n\t"
        "str	%[len], [lr, #12]\n\t"
        "ldr	r8, [r12, #16]\n\t"
        "ldr	r9, [r12, #20]\n\t"
        "ldr	r10, [r12, #24]\n\t"
        "ldr	r11, [r12, #28]\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r9\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
        "str	r4, [lr, #16]\n\t"
        "str	r5, [lr, #20]\n\t"
        "str	r6, [lr, #24]\n\t"
        "str	r7, [lr, #28]\n\t"
        "ldr	r4, [sp]\n\t"
        "ldr	r5, [sp, #4]\n\t"
        "ldr	r6, [sp, #8]\n\t"
        "ldr	r7, [sp, #12]\n\t"
        "ldr	r8, [r12, #32]\n\t"
        "ldr	r9, [r12, #36]\n\t"
        "ldr	r10, [r12, #40]\n\t"
        "ldr	r11, [r12, #44]\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r9\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
        "str	r4, [lr, #32]\n\t"
        "str	r5, [lr, #36]\n\t"
        "str	r6, [lr, #40]\n\t"
        "str	r7, [lr, #44]\n\t"
        "ldr	r4, [sp, #16]\n\t"
        "ldr	r5, [sp, #20]\n\t"
        "ldr	r6, [sp, #24]\n\t"
        "ldr	r7, [sp, #28]\n\t"
        "ldr	r8, [r12, #48]\n\t"
        "ldr	r9, [r12, #52]\n\t"
        "ldr	r10, [r12, #56]\n\t"
        "ldr	r11, [r12, #60]\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r9\n\t"
        "eor	r6, r6, r10\n\t"
        "eor	r7, r7, r11\n\t"
        "str	r4, [lr, #48]\n\t"
        "str	r5, [lr, #52]\n\t"
        "str	r6, [lr, #56]\n\t"
        "str	r7, [lr, #60]\n\t"
        "ldr	%[len], [sp, #44]\n\t"
        "add	r12, r12, #0x40\n\t"
        "add	lr, lr, #0x40\n\t"
        "str	r12, [sp, #40]\n\t"
        "str	lr, [sp, #36]\n\t"
        "subs	%[len], %[len], #0x40\n\t"
        "ldr	lr, [sp, #32]\n\t"
        "str	%[len], [sp, #44]\n\t"
        "bne	L_chacha_arm32_crypt_block_%=\n\t"
        "b	L_chacha_arm32_crypt_done_%=\n\t"
        "\n"
    "L_chacha_arm32_crypt_lt_block_%=: \n\t"
        /* Store in over field of ChaCha. */
        "ldr	lr, [sp, #32]\n\t"
        "add	r12, lr, #0x44\n\t"
        "stm	r12!, {r0, r1, r2, r3, r4, r5, r6, r7}\n\t"
        "ldm	sp, {r0, r1, r2, r3, r4, r5, r6, r7}\n\t"
        "stm	r12, {r0, r1, r2, r3, r4, r5, r6, r7}\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	%[m], [sp, #40]\n\t"
        "ldr	%[len], [sp, #44]\n\t"
#else
        "ldrd	%[m], %[len], [sp, #40]\n\t"
#endif
        "ldr	%[c], [sp, #36]\n\t"
        "rsb	r12, %[len], #0x40\n\t"
        "str	r12, [lr, #64]\n\t"
        "add	lr, lr, #0x44\n\t"
        "\n"
    "L_chacha_arm32_crypt_16byte_loop_%=: \n\t"
        "cmp	%[len], #16\n\t"
        "blt	L_chacha_arm32_crypt_word_loop_%=\n\t"
        /* 16 bytes of state XORed into message. */
        "ldm	lr!, {r4, r5, r6, r7}\n\t"
        "ldr	r8, [%[m]]\n\t"
        "ldr	r9, [%[m], #4]\n\t"
        "ldr	r10, [%[m], #8]\n\t"
        "ldr	r11, [%[m], #12]\n\t"
        "eor	r8, r8, r4\n\t"
        "eor	r9, r9, r5\n\t"
        "eor	r10, r10, r6\n\t"
        "eor	r11, r11, r7\n\t"
        "subs	%[len], %[len], #16\n\t"
        "str	r8, [%[c]]\n\t"
        "str	r9, [%[c], #4]\n\t"
        "str	r10, [%[c], #8]\n\t"
        "str	r11, [%[c], #12]\n\t"
        "beq	L_chacha_arm32_crypt_done_%=\n\t"
        "add	%[m], %[m], #16\n\t"
        "add	%[c], %[c], #16\n\t"
        "b	L_chacha_arm32_crypt_16byte_loop_%=\n\t"
        "\n"
    "L_chacha_arm32_crypt_word_loop_%=: \n\t"
        "cmp	%[len], #4\n\t"
        "blt	L_chacha_arm32_crypt_byte_start_%=\n\t"
        /* 4 bytes of state XORed into message. */
        "ldr	r4, [lr]\n\t"
        "ldr	r8, [%[m]]\n\t"
        "eor	r8, r8, r4\n\t"
        "subs	%[len], %[len], #4\n\t"
        "str	r8, [%[c]]\n\t"
        "beq	L_chacha_arm32_crypt_done_%=\n\t"
        "add	lr, lr, #4\n\t"
        "add	%[m], %[m], #4\n\t"
        "add	%[c], %[c], #4\n\t"
        "b	L_chacha_arm32_crypt_word_loop_%=\n\t"
        "\n"
    "L_chacha_arm32_crypt_byte_start_%=: \n\t"
        "ldr	r4, [lr]\n\t"
        "\n"
    "L_chacha_arm32_crypt_byte_loop_%=: \n\t"
        "ldrb	r8, [%[m]]\n\t"
        "eor	r8, r8, r4\n\t"
        "subs	%[len], %[len], #1\n\t"
        "strb	r8, [%[c]]\n\t"
        "beq	L_chacha_arm32_crypt_done_%=\n\t"
        "lsr	r4, r4, #8\n\t"
        "add	%[m], %[m], #1\n\t"
        "add	%[c], %[c], #1\n\t"
        "b	L_chacha_arm32_crypt_byte_loop_%=\n\t"
        "\n"
    "L_chacha_arm32_crypt_done_%=: \n\t"
        "add	sp, sp, #52\n\t"
        : [ctx] "+r" (ctx), [c] "+r" (c), [m] "+r" (m), [len] "+r" (len)
        :
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9",
            "r10", "r11"
    );
}

void wc_chacha_use_over(byte* over_p, byte* output_p, const byte* input_p,
    word32 len_p)
{
    register byte* over asm ("r0") = (byte*)over_p;
    register byte* output asm ("r1") = (byte*)output_p;
    register const byte* input asm ("r2") = (const byte*)input_p;
    register word32 len asm ("r3") = (word32)len_p;

    __asm__ __volatile__ (
        "\n"
    "L_chacha_arm32_over_16byte_loop_%=: \n\t"
        "cmp	%[len], #16\n\t"
        "blt	L_chacha_arm32_over_word_loop_%=\n\t"
        /* 16 bytes of state XORed into message. */
        "ldr	r12, [%[over]]\n\t"
        "ldr	lr, [%[over], #4]\n\t"
        "ldr	r4, [%[over], #8]\n\t"
        "ldr	r5, [%[over], #12]\n\t"
        "ldr	r6, [%[input]]\n\t"
        "ldr	r7, [%[input], #4]\n\t"
        "ldr	r8, [%[input], #8]\n\t"
        "ldr	r9, [%[input], #12]\n\t"
        "eor	r12, r12, r6\n\t"
        "eor	lr, lr, r7\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r9\n\t"
        "subs	%[len], %[len], #16\n\t"
        "str	r12, [%[output]]\n\t"
        "str	lr, [%[output], #4]\n\t"
        "str	r4, [%[output], #8]\n\t"
        "str	r5, [%[output], #12]\n\t"
        "beq	L_chacha_arm32_over_done_%=\n\t"
        "add	%[over], %[over], #16\n\t"
        "add	%[input], %[input], #16\n\t"
        "add	%[output], %[output], #16\n\t"
        "b	L_chacha_arm32_over_16byte_loop_%=\n\t"
        "\n"
    "L_chacha_arm32_over_word_loop_%=: \n\t"
        "cmp	%[len], #4\n\t"
        "blt	L_chacha_arm32_over_byte_loop_%=\n\t"
        /* 4 bytes of state XORed into message. */
        "ldr	r12, [%[over]]\n\t"
        "ldr	r6, [%[input]]\n\t"
        "eor	r12, r12, r6\n\t"
        "subs	%[len], %[len], #4\n\t"
        "str	r12, [%[output]]\n\t"
        "beq	L_chacha_arm32_over_done_%=\n\t"
        "add	%[over], %[over], #4\n\t"
        "add	%[input], %[input], #4\n\t"
        "add	%[output], %[output], #4\n\t"
        "b	L_chacha_arm32_over_word_loop_%=\n\t"
        "\n"
    "L_chacha_arm32_over_byte_loop_%=: \n\t"
        /* 4 bytes of state XORed into message. */
        "ldrb	r12, [%[over]]\n\t"
        "ldrb	r6, [%[input]]\n\t"
        "eor	r12, r12, r6\n\t"
        "subs	%[len], %[len], #1\n\t"
        "strb	r12, [%[output]]\n\t"
        "beq	L_chacha_arm32_over_done_%=\n\t"
        "add	%[over], %[over], #1\n\t"
        "add	%[input], %[input], #1\n\t"
        "add	%[output], %[output], #1\n\t"
        "b	L_chacha_arm32_over_byte_loop_%=\n\t"
        "\n"
    "L_chacha_arm32_over_done_%=: \n\t"
        : [over] "+r" (over), [output] "+r" (output), [input] "+r" (input),
          [len] "+r" (len)
        :
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9"
    );
}

#endif /* WOLFSSL_ARMASM_NO_NEON */
#endif /* HAVE_CHACHA */
#endif /* !__aarch64__ && !WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#endif /* WOLFSSL_ARMASM_INLINE */
