/* thumb2-chacha-asm
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
 *   ruby ./chacha/chacha.rb thumb2 ../wolfssl/wolfcrypt/src/port/arm/thumb2-chacha-asm.c
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
#ifdef HAVE_CHACHA
#include <wolfssl/wolfcrypt/chacha.h>

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void wc_chacha_setiv(word32* x_p, const byte* iv_p, word32 counter_p)
#else
void wc_chacha_setiv(word32* x, const byte* iv, word32 counter)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word32* x __asm__ ("r0") = (word32*)x_p;
    register const byte* iv __asm__ ("r1") = (const byte*)iv_p;
    register word32 counter __asm__ ("r2") = (word32)counter_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "ADD	r3, %[x], #0x34\n\t"
        "LDR	r4, [%[iv]]\n\t"
        "LDR	r5, [%[iv], #4]\n\t"
        "LDR	r6, [%[iv], #8]\n\t"
        "STR	%[counter], [%[x], #48]\n\t"
#ifdef BIG_ENDIAN_ORDER
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
#endif /* BIG_ENDIAN_ORDER */
        "STM	r3, {r4, r5, r6}\n\t"
        : [x] "+r" (x), [iv] "+r" (iv), [counter] "+r" (counter)
        :
        : "memory", "r3", "r4", "r5", "r6", "cc"
    );
}

XALIGNED(16) static const word32 L_chacha_thumb2_constants[] = {
    0x61707865, 0x3120646e, 0x79622d36, 0x6b206574,
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
};

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void wc_chacha_setkey(word32* x_p, const byte* key_p, word32 keySz_p)
#else
void wc_chacha_setkey(word32* x, const byte* key, word32 keySz)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register word32* x __asm__ ("r0") = (word32*)x_p;
    register const byte* key __asm__ ("r1") = (const byte*)key_p;
    register word32 keySz __asm__ ("r2") = (word32)keySz_p;
    register word32* L_chacha_thumb2_constants_c __asm__ ("r3") = (word32*)&L_chacha_thumb2_constants;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "MOV	r7, %[L_chacha_thumb2_constants]\n\t"
        "SUBS	%[keySz], %[keySz], #0x10\n\t"
        "ADD	r7, r7, %[keySz]\n\t"
        /* Start state with constants */
        "LDM	r7, {r3, r4, r5, r6}\n\t"
        "STM	%[x]!, {r3, r4, r5, r6}\n\t"
        /* Next is first 16 bytes of key. */
        "LDR	r3, [%[key]]\n\t"
        "LDR	r4, [%[key], #4]\n\t"
        "LDR	r5, [%[key], #8]\n\t"
        "LDR	r6, [%[key], #12]\n\t"
#ifdef BIG_ENDIAN_ORDER
        "REV	r3, r3\n\t"
        "REV	r4, r4\n\t"
        "REV	r5, r5\n\t"
        "REV	r6, r6\n\t"
#endif /* BIG_ENDIAN_ORDER */
        "STM	%[x]!, {r3, r4, r5, r6}\n\t"
        /* Next 16 bytes of key. */
#if defined(__GNUC__)
        "BEQ	L_chacha_thumb2_setkey_same_keyb_ytes_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.N	L_chacha_thumb2_setkey_same_keyb_ytes\n\t"
#else
        "BEQ.N	L_chacha_thumb2_setkey_same_keyb_ytes_%=\n\t"
#endif
        /* Update key pointer for next 16 bytes. */
        "ADD	%[key], %[key], %[keySz]\n\t"
        "LDR	r3, [%[key]]\n\t"
        "LDR	r4, [%[key], #4]\n\t"
        "LDR	r5, [%[key], #8]\n\t"
        "LDR	r6, [%[key], #12]\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_chacha_thumb2_setkey_same_keyb_ytes:\n\t"
#else
    "L_chacha_thumb2_setkey_same_keyb_ytes_%=:\n\t"
#endif
        "STM	%[x], {r3, r4, r5, r6}\n\t"
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
        : [x] "+r" (x), [key] "+r" (key), [keySz] "+r" (keySz),
          [L_chacha_thumb2_constants] "+r" (L_chacha_thumb2_constants_c)
        :
        : "memory", "r4", "r5", "r6", "r7", "cc"
#else
        : [x] "+r" (x), [key] "+r" (key), [keySz] "+r" (keySz)
        : [L_chacha_thumb2_constants] "r" (L_chacha_thumb2_constants)
        : "memory", "r4", "r5", "r6", "r7", "cc"
#endif /* WOLFSSL_NO_VAR_ASSIGN_REG */
    );
}

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void wc_chacha_crypt_bytes(ChaCha* ctx_p, byte* c_p, const byte* m_p, word32 len_p)
#else
void wc_chacha_crypt_bytes(ChaCha* ctx, byte* c, const byte* m, word32 len)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register ChaCha* ctx __asm__ ("r0") = (ChaCha*)ctx_p;
    register byte* c __asm__ ("r1") = (byte*)c_p;
    register const byte* m __asm__ ("r2") = (const byte*)m_p;
    register word32 len __asm__ ("r3") = (word32)len_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "SUB	sp, sp, #0x34\n\t"
        "MOV	lr, %[ctx]\n\t"
        "STRD	%[ctx], %[c], [sp, #32]\n\t"
        "STRD	%[m], %[len], [sp, #40]\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_chacha_thumb2_crypt_block:\n\t"
#else
    "L_chacha_thumb2_crypt_block_%=:\n\t"
#endif
        /* Put x[12]..x[15] onto stack. */
        "LDRD	r4, r5, [lr, #48]\n\t"
        "LDRD	r6, r7, [lr, #56]\n\t"
        "STRD	r4, r5, [sp, #16]\n\t"
        "STRD	r6, r7, [sp, #24]\n\t"
        /* Load x[0]..x[12] into registers. */
        "LDM	lr, {%[ctx], %[c], %[m], %[len], r4, r5, r6, r7, r8, r9, r10, r11, r12}\n\t"
        /* 10x 2 full rounds to perform. */
        "MOV	lr, #0xa\n\t"
        "STR	lr, [sp, #48]\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_chacha_thumb2_crypt_loop:\n\t"
#else
    "L_chacha_thumb2_crypt_loop_%=:\n\t"
#endif
        /* 0, 4,  8, 12 */
        /* 1, 5,  9, 13 */
        "LDR	lr, [sp, #20]\n\t"
        "ADD	%[ctx], %[ctx], r4\n\t"
        "ADD	%[c], %[c], r5\n\t"
        "EOR	r12, r12, %[ctx]\n\t"
        "EOR	lr, lr, %[c]\n\t"
        "ROR	r12, r12, #16\n\t"
        "ROR	lr, lr, #16\n\t"
        "ADD	r8, r8, r12\n\t"
        "ADD	r9, r9, lr\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "ROR	r4, r4, #20\n\t"
        "ROR	r5, r5, #20\n\t"
        "ADD	%[ctx], %[ctx], r4\n\t"
        "ADD	%[c], %[c], r5\n\t"
        "EOR	r12, r12, %[ctx]\n\t"
        "EOR	lr, lr, %[c]\n\t"
        "ROR	r12, r12, #24\n\t"
        "ROR	lr, lr, #24\n\t"
        "ADD	r8, r8, r12\n\t"
        "ADD	r9, r9, lr\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "ROR	r4, r4, #25\n\t"
        "ROR	r5, r5, #25\n\t"
        "STR	r12, [sp, #16]\n\t"
        "STR	lr, [sp, #20]\n\t"
        /* 2, 6, 10, 14 */
        /* 3, 7, 11, 15 */
        "LDR	r12, [sp, #24]\n\t"
        "LDR	lr, [sp, #28]\n\t"
        "ADD	%[m], %[m], r6\n\t"
        "ADD	%[len], %[len], r7\n\t"
        "EOR	r12, r12, %[m]\n\t"
        "EOR	lr, lr, %[len]\n\t"
        "ROR	r12, r12, #16\n\t"
        "ROR	lr, lr, #16\n\t"
        "ADD	r10, r10, r12\n\t"
        "ADD	r11, r11, lr\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "ROR	r6, r6, #20\n\t"
        "ROR	r7, r7, #20\n\t"
        "ADD	%[m], %[m], r6\n\t"
        "ADD	%[len], %[len], r7\n\t"
        "EOR	r12, r12, %[m]\n\t"
        "EOR	lr, lr, %[len]\n\t"
        "ROR	r12, r12, #24\n\t"
        "ROR	lr, lr, #24\n\t"
        "ADD	r10, r10, r12\n\t"
        "ADD	r11, r11, lr\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "ROR	r6, r6, #25\n\t"
        "ROR	r7, r7, #25\n\t"
        /* 3, 4,  9, 14 */
        /* 0, 5, 10, 15 */
        "ADD	%[len], %[len], r4\n\t"
        "ADD	%[ctx], %[ctx], r5\n\t"
        "EOR	r12, r12, %[len]\n\t"
        "EOR	lr, lr, %[ctx]\n\t"
        "ROR	r12, r12, #16\n\t"
        "ROR	lr, lr, #16\n\t"
        "ADD	r9, r9, r12\n\t"
        "ADD	r10, r10, lr\n\t"
        "EOR	r4, r4, r9\n\t"
        "EOR	r5, r5, r10\n\t"
        "ROR	r4, r4, #20\n\t"
        "ROR	r5, r5, #20\n\t"
        "ADD	%[len], %[len], r4\n\t"
        "ADD	%[ctx], %[ctx], r5\n\t"
        "EOR	r12, r12, %[len]\n\t"
        "EOR	lr, lr, %[ctx]\n\t"
        "ROR	r12, r12, #24\n\t"
        "ROR	lr, lr, #24\n\t"
        "ADD	r9, r9, r12\n\t"
        "ADD	r10, r10, lr\n\t"
        "EOR	r4, r4, r9\n\t"
        "EOR	r5, r5, r10\n\t"
        "ROR	r4, r4, #25\n\t"
        "ROR	r5, r5, #25\n\t"
        "STR	r12, [sp, #24]\n\t"
        "STR	lr, [sp, #28]\n\t"
        "LDR	r12, [sp, #16]\n\t"
        "LDR	lr, [sp, #20]\n\t"
        /* 1, 6, 11, 12 */
        /* 2, 7,  8, 13 */
        "ADD	%[c], %[c], r6\n\t"
        "ADD	%[m], %[m], r7\n\t"
        "EOR	r12, r12, %[c]\n\t"
        "EOR	lr, lr, %[m]\n\t"
        "ROR	r12, r12, #16\n\t"
        "ROR	lr, lr, #16\n\t"
        "ADD	r11, r11, r12\n\t"
        "ADD	r8, r8, lr\n\t"
        "EOR	r6, r6, r11\n\t"
        "EOR	r7, r7, r8\n\t"
        "ROR	r6, r6, #20\n\t"
        "ROR	r7, r7, #20\n\t"
        "ADD	%[c], %[c], r6\n\t"
        "ADD	%[m], %[m], r7\n\t"
        "EOR	r12, r12, %[c]\n\t"
        "EOR	lr, lr, %[m]\n\t"
        "ROR	r12, r12, #24\n\t"
        "ROR	lr, lr, #24\n\t"
        "ADD	r11, r11, r12\n\t"
        "ADD	r8, r8, lr\n\t"
        "EOR	r6, r6, r11\n\t"
        "EOR	r7, r7, r8\n\t"
        "ROR	r6, r6, #25\n\t"
        "ROR	r7, r7, #25\n\t"
        "STR	lr, [sp, #20]\n\t"
        /* Check if we have done enough rounds. */
        "LDR	lr, [sp, #48]\n\t"
        "SUBS	lr, lr, #0x1\n\t"
        "STR	lr, [sp, #48]\n\t"
#if defined(__GNUC__)
        "BGT	L_chacha_thumb2_crypt_loop_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BGT.N	L_chacha_thumb2_crypt_loop\n\t"
#else
        "BGT.N	L_chacha_thumb2_crypt_loop_%=\n\t"
#endif
        "STM	sp, {r8, r9, r10, r11, r12}\n\t"
        "LDR	lr, [sp, #32]\n\t"
        "MOV	r12, sp\n\t"
        /* Add in original state */
        "LDM	lr!, {r8, r9, r10, r11}\n\t"
        "ADD	%[ctx], %[ctx], r8\n\t"
        "ADD	%[c], %[c], r9\n\t"
        "ADD	%[m], %[m], r10\n\t"
        "ADD	%[len], %[len], r11\n\t"
        "LDM	lr!, {r8, r9, r10, r11}\n\t"
        "ADD	r4, r4, r8\n\t"
        "ADD	r5, r5, r9\n\t"
        "ADD	r6, r6, r10\n\t"
        "ADD	r7, r7, r11\n\t"
        "LDM	r12, {r8, r9}\n\t"
        "LDM	lr!, {r10, r11}\n\t"
        "ADD	r8, r8, r10\n\t"
        "ADD	r9, r9, r11\n\t"
        "STM	r12!, {r8, r9}\n\t"
        "LDM	r12, {r8, r9}\n\t"
        "LDM	lr!, {r10, r11}\n\t"
        "ADD	r8, r8, r10\n\t"
        "ADD	r9, r9, r11\n\t"
        "STM	r12!, {r8, r9}\n\t"
        "LDM	r12, {r8, r9}\n\t"
        "LDM	lr!, {r10, r11}\n\t"
        "ADD	r8, r8, r10\n\t"
        "ADD	r9, r9, r11\n\t"
        "ADD	r10, r10, #0x1\n\t"
        "STM	r12!, {r8, r9}\n\t"
        "STR	r10, [lr, #-8]\n\t"
        "LDM	r12, {r8, r9}\n\t"
        "LDM	lr, {r10, r11}\n\t"
        "ADD	r8, r8, r10\n\t"
        "ADD	r9, r9, r11\n\t"
        "STM	r12, {r8, r9}\n\t"
        "LDR	r12, [sp, #44]\n\t"
        "CMP	r12, #0x40\n\t"
#if defined(__GNUC__)
        "BLT	L_chacha_thumb2_crypt_lt_block_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BLT.N	L_chacha_thumb2_crypt_lt_block\n\t"
#else
        "BLT.N	L_chacha_thumb2_crypt_lt_block_%=\n\t"
#endif
        "LDR	r12, [sp, #40]\n\t"
        "LDR	lr, [sp, #36]\n\t"
        /* XOR state into 64 bytes. */
        "LDR	r8, [r12]\n\t"
        "LDR	r9, [r12, #4]\n\t"
        "LDR	r10, [r12, #8]\n\t"
        "LDR	r11, [r12, #12]\n\t"
        "EOR	%[ctx], %[ctx], r8\n\t"
        "EOR	%[c], %[c], r9\n\t"
        "EOR	%[m], %[m], r10\n\t"
        "EOR	%[len], %[len], r11\n\t"
        "STR	%[ctx], [lr]\n\t"
        "STR	%[c], [lr, #4]\n\t"
        "STR	%[m], [lr, #8]\n\t"
        "STR	%[len], [lr, #12]\n\t"
        "LDR	r8, [r12, #16]\n\t"
        "LDR	r9, [r12, #20]\n\t"
        "LDR	r10, [r12, #24]\n\t"
        "LDR	r11, [r12, #28]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "STR	r4, [lr, #16]\n\t"
        "STR	r5, [lr, #20]\n\t"
        "STR	r6, [lr, #24]\n\t"
        "STR	r7, [lr, #28]\n\t"
        "LDR	r4, [sp]\n\t"
        "LDR	r5, [sp, #4]\n\t"
        "LDR	r6, [sp, #8]\n\t"
        "LDR	r7, [sp, #12]\n\t"
        "LDR	r8, [r12, #32]\n\t"
        "LDR	r9, [r12, #36]\n\t"
        "LDR	r10, [r12, #40]\n\t"
        "LDR	r11, [r12, #44]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "STR	r4, [lr, #32]\n\t"
        "STR	r5, [lr, #36]\n\t"
        "STR	r6, [lr, #40]\n\t"
        "STR	r7, [lr, #44]\n\t"
        "LDR	r4, [sp, #16]\n\t"
        "LDR	r5, [sp, #20]\n\t"
        "LDR	r6, [sp, #24]\n\t"
        "LDR	r7, [sp, #28]\n\t"
        "LDR	r8, [r12, #48]\n\t"
        "LDR	r9, [r12, #52]\n\t"
        "LDR	r10, [r12, #56]\n\t"
        "LDR	r11, [r12, #60]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "STR	r4, [lr, #48]\n\t"
        "STR	r5, [lr, #52]\n\t"
        "STR	r6, [lr, #56]\n\t"
        "STR	r7, [lr, #60]\n\t"
        "LDR	%[len], [sp, #44]\n\t"
        "ADD	r12, r12, #0x40\n\t"
        "ADD	lr, lr, #0x40\n\t"
        "STR	r12, [sp, #40]\n\t"
        "STR	lr, [sp, #36]\n\t"
        "SUBS	%[len], %[len], #0x40\n\t"
        "LDR	lr, [sp, #32]\n\t"
        "STR	%[len], [sp, #44]\n\t"
#if defined(__GNUC__)
        "BNE	L_chacha_thumb2_crypt_block_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BNE.N	L_chacha_thumb2_crypt_block\n\t"
#else
        "BNE.N	L_chacha_thumb2_crypt_block_%=\n\t"
#endif
#if defined(__GNUC__)
        "B	L_chacha_thumb2_crypt_done_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.N	L_chacha_thumb2_crypt_done\n\t"
#else
        "B.N	L_chacha_thumb2_crypt_done_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_chacha_thumb2_crypt_lt_block:\n\t"
#else
    "L_chacha_thumb2_crypt_lt_block_%=:\n\t"
#endif
        /* Store in over field of ChaCha. */
        "LDR	lr, [sp, #32]\n\t"
        "ADD	r12, lr, #0x44\n\t"
        "STM	r12!, {%[ctx], %[c], %[m], %[len], r4, r5, r6, r7}\n\t"
        "LDM	sp, {%[ctx], %[c], %[m], %[len], r4, r5, r6, r7}\n\t"
        "STM	r12, {%[ctx], %[c], %[m], %[len], r4, r5, r6, r7}\n\t"
        "LDRD	%[m], %[len], [sp, #40]\n\t"
        "LDR	%[c], [sp, #36]\n\t"
        "RSB	r12, %[len], #0x40\n\t"
        "STR	r12, [lr, #64]\n\t"
        "ADD	lr, lr, #0x44\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_chacha_thumb2_crypt_16byte_loop:\n\t"
#else
    "L_chacha_thumb2_crypt_16byte_loop_%=:\n\t"
#endif
        "CMP	%[len], #0x10\n\t"
#if defined(__GNUC__)
        "BLT	L_chacha_thumb2_crypt_word_loop_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BLT.N	L_chacha_thumb2_crypt_word_loop\n\t"
#else
        "BLT.N	L_chacha_thumb2_crypt_word_loop_%=\n\t"
#endif
        /* 16 bytes of state XORed into message. */
        "LDM	lr!, {r4, r5, r6, r7}\n\t"
        "LDR	r8, [%[m]]\n\t"
        "LDR	r9, [%[m], #4]\n\t"
        "LDR	r10, [%[m], #8]\n\t"
        "LDR	r11, [%[m], #12]\n\t"
        "EOR	r8, r8, r4\n\t"
        "EOR	r9, r9, r5\n\t"
        "EOR	r10, r10, r6\n\t"
        "EOR	r11, r11, r7\n\t"
        "SUBS	%[len], %[len], #0x10\n\t"
        "STR	r8, [%[c]]\n\t"
        "STR	r9, [%[c], #4]\n\t"
        "STR	r10, [%[c], #8]\n\t"
        "STR	r11, [%[c], #12]\n\t"
#if defined(__GNUC__)
        "BEQ	L_chacha_thumb2_crypt_done_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.N	L_chacha_thumb2_crypt_done\n\t"
#else
        "BEQ.N	L_chacha_thumb2_crypt_done_%=\n\t"
#endif
        "ADD	%[m], %[m], #0x10\n\t"
        "ADD	%[c], %[c], #0x10\n\t"
#if defined(__GNUC__)
        "B	L_chacha_thumb2_crypt_16byte_loop_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.N	L_chacha_thumb2_crypt_16byte_loop\n\t"
#else
        "B.N	L_chacha_thumb2_crypt_16byte_loop_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_chacha_thumb2_crypt_word_loop:\n\t"
#else
    "L_chacha_thumb2_crypt_word_loop_%=:\n\t"
#endif
        "CMP	%[len], #0x4\n\t"
#if defined(__GNUC__)
        "BLT	L_chacha_thumb2_crypt_byte_start_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BLT.N	L_chacha_thumb2_crypt_byte_start\n\t"
#else
        "BLT.N	L_chacha_thumb2_crypt_byte_start_%=\n\t"
#endif
        /* 4 bytes of state XORed into message. */
        "LDR	r4, [lr]\n\t"
        "LDR	r8, [%[m]]\n\t"
        "EOR	r8, r8, r4\n\t"
        "SUBS	%[len], %[len], #0x4\n\t"
        "STR	r8, [%[c]]\n\t"
#if defined(__GNUC__)
        "BEQ	L_chacha_thumb2_crypt_done_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.N	L_chacha_thumb2_crypt_done\n\t"
#else
        "BEQ.N	L_chacha_thumb2_crypt_done_%=\n\t"
#endif
        "ADD	lr, lr, #0x4\n\t"
        "ADD	%[m], %[m], #0x4\n\t"
        "ADD	%[c], %[c], #0x4\n\t"
#if defined(__GNUC__)
        "B	L_chacha_thumb2_crypt_word_loop_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.N	L_chacha_thumb2_crypt_word_loop\n\t"
#else
        "B.N	L_chacha_thumb2_crypt_word_loop_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_chacha_thumb2_crypt_byte_start:\n\t"
#else
    "L_chacha_thumb2_crypt_byte_start_%=:\n\t"
#endif
        "LDR	r4, [lr]\n\t"
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_chacha_thumb2_crypt_byte_loop:\n\t"
#else
    "L_chacha_thumb2_crypt_byte_loop_%=:\n\t"
#endif
        "LDRB	r8, [%[m]]\n\t"
        "EOR	r8, r8, r4\n\t"
        "SUBS	%[len], %[len], #0x1\n\t"
        "STRB	r8, [%[c]]\n\t"
#if defined(__GNUC__)
        "BEQ	L_chacha_thumb2_crypt_done_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.N	L_chacha_thumb2_crypt_done\n\t"
#else
        "BEQ.N	L_chacha_thumb2_crypt_done_%=\n\t"
#endif
        "LSR	r4, r4, #8\n\t"
        "ADD	%[m], %[m], #0x1\n\t"
        "ADD	%[c], %[c], #0x1\n\t"
#if defined(__GNUC__)
        "B	L_chacha_thumb2_crypt_byte_loop_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.N	L_chacha_thumb2_crypt_byte_loop\n\t"
#else
        "B.N	L_chacha_thumb2_crypt_byte_loop_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_chacha_thumb2_crypt_done:\n\t"
#else
    "L_chacha_thumb2_crypt_done_%=:\n\t"
#endif
        "ADD	sp, sp, #0x34\n\t"
        : [ctx] "+r" (ctx), [c] "+r" (c), [m] "+r" (m), [len] "+r" (len)
        :
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr", "cc"
    );
}

#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
void wc_chacha_use_over(byte* over_p, byte* output_p, const byte* input_p, word32 len_p)
#else
void wc_chacha_use_over(byte* over, byte* output, const byte* input, word32 len)
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */
{
#ifndef WOLFSSL_NO_VAR_ASSIGN_REG
    register byte* over __asm__ ("r0") = (byte*)over_p;
    register byte* output __asm__ ("r1") = (byte*)output_p;
    register const byte* input __asm__ ("r2") = (const byte*)input_p;
    register word32 len __asm__ ("r3") = (word32)len_p;
#endif /* !WOLFSSL_NO_VAR_ASSIGN_REG */

    __asm__ __volatile__ (
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_chacha_thumb2_over_16byte_loop:\n\t"
#else
    "L_chacha_thumb2_over_16byte_loop_%=:\n\t"
#endif
        "CMP	%[len], #0x10\n\t"
#if defined(__GNUC__)
        "BLT	L_chacha_thumb2_over_word_loop_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BLT.N	L_chacha_thumb2_over_word_loop\n\t"
#else
        "BLT.N	L_chacha_thumb2_over_word_loop_%=\n\t"
#endif
        /* 16 bytes of state XORed into message. */
        "LDR	r4, [%[over]]\n\t"
        "LDR	r5, [%[over], #4]\n\t"
        "LDR	r6, [%[over], #8]\n\t"
        "LDR	r7, [%[over], #12]\n\t"
        "LDR	r8, [%[input]]\n\t"
        "LDR	r9, [%[input], #4]\n\t"
        "LDR	r10, [%[input], #8]\n\t"
        "LDR	r11, [%[input], #12]\n\t"
        "EOR	r4, r4, r8\n\t"
        "EOR	r5, r5, r9\n\t"
        "EOR	r6, r6, r10\n\t"
        "EOR	r7, r7, r11\n\t"
        "SUBS	%[len], %[len], #0x10\n\t"
        "STR	r4, [%[output]]\n\t"
        "STR	r5, [%[output], #4]\n\t"
        "STR	r6, [%[output], #8]\n\t"
        "STR	r7, [%[output], #12]\n\t"
#if defined(__GNUC__)
        "BEQ	L_chacha_thumb2_over_done_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.N	L_chacha_thumb2_over_done\n\t"
#else
        "BEQ.N	L_chacha_thumb2_over_done_%=\n\t"
#endif
        "ADD	%[over], %[over], #0x10\n\t"
        "ADD	%[input], %[input], #0x10\n\t"
        "ADD	%[output], %[output], #0x10\n\t"
#if defined(__GNUC__)
        "B	L_chacha_thumb2_over_16byte_loop_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.N	L_chacha_thumb2_over_16byte_loop\n\t"
#else
        "B.N	L_chacha_thumb2_over_16byte_loop_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_chacha_thumb2_over_word_loop:\n\t"
#else
    "L_chacha_thumb2_over_word_loop_%=:\n\t"
#endif
        "CMP	%[len], #0x4\n\t"
#if defined(__GNUC__)
        "BLT	L_chacha_thumb2_over_byte_loop_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BLT.N	L_chacha_thumb2_over_byte_loop\n\t"
#else
        "BLT.N	L_chacha_thumb2_over_byte_loop_%=\n\t"
#endif
        /* 4 bytes of state XORed into message. */
        "LDR	r4, [%[over]]\n\t"
        "LDR	r8, [%[input]]\n\t"
        "EOR	r4, r4, r8\n\t"
        "SUBS	%[len], %[len], #0x4\n\t"
        "STR	r4, [%[output]]\n\t"
#if defined(__GNUC__)
        "BEQ	L_chacha_thumb2_over_done_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.N	L_chacha_thumb2_over_done\n\t"
#else
        "BEQ.N	L_chacha_thumb2_over_done_%=\n\t"
#endif
        "ADD	%[over], %[over], #0x4\n\t"
        "ADD	%[input], %[input], #0x4\n\t"
        "ADD	%[output], %[output], #0x4\n\t"
#if defined(__GNUC__)
        "B	L_chacha_thumb2_over_word_loop_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.N	L_chacha_thumb2_over_word_loop\n\t"
#else
        "B.N	L_chacha_thumb2_over_word_loop_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_chacha_thumb2_over_byte_loop:\n\t"
#else
    "L_chacha_thumb2_over_byte_loop_%=:\n\t"
#endif
        /* 4 bytes of state XORed into message. */
        "LDRB	r4, [%[over]]\n\t"
        "LDRB	r8, [%[input]]\n\t"
        "EOR	r4, r4, r8\n\t"
        "SUBS	%[len], %[len], #0x1\n\t"
        "STRB	r4, [%[output]]\n\t"
#if defined(__GNUC__)
        "BEQ	L_chacha_thumb2_over_done_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "BEQ.N	L_chacha_thumb2_over_done\n\t"
#else
        "BEQ.N	L_chacha_thumb2_over_done_%=\n\t"
#endif
        "ADD	%[over], %[over], #0x1\n\t"
        "ADD	%[input], %[input], #0x1\n\t"
        "ADD	%[output], %[output], #0x1\n\t"
#if defined(__GNUC__)
        "B	L_chacha_thumb2_over_byte_loop_%=\n\t"
#elif defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
        "B.N	L_chacha_thumb2_over_byte_loop\n\t"
#else
        "B.N	L_chacha_thumb2_over_byte_loop_%=\n\t"
#endif
        "\n"
#if defined(__IAR_SYSTEMS_ICC__) && (__VER__ < 9000000)
    "L_chacha_thumb2_over_done:\n\t"
#else
    "L_chacha_thumb2_over_done_%=:\n\t"
#endif
        : [over] "+r" (over), [output] "+r" (output), [input] "+r" (input), [len] "+r" (len)
        :
        : "memory", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "cc"
    );
}

#endif /* HAVE_CHACHA */
#endif /* WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */
#endif /* WOLFSSL_ARMASM_INLINE */
