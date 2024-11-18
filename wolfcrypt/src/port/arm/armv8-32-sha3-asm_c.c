/* armv8-32-sha3-asm
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
 *   ruby ./sha3/sha3.rb arm32 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-32-sha3-asm.c
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
#ifdef WOLFSSL_SHA3
#ifndef WOLFSSL_ARMASM_NO_NEON
static const word64 L_sha3_arm2_neon_rt[] = {
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

#include <wolfssl/wolfcrypt/sha3.h>

void BlockSha3(word64* state_p)
{
    register word64* state asm ("r0") = (word64*)state_p;
    register word64* L_sha3_arm2_neon_rt_c asm ("r1") =
        (word64*)&L_sha3_arm2_neon_rt;

    __asm__ __volatile__ (
        "sub	sp, sp, #16\n\t"
        "mov	r2, #24\n\t"
        "mov	r3, sp\n\t"
        "vld1.8	{d0-d3}, [%[state]]!\n\t"
        "vld1.8	{d4-d7}, [%[state]]!\n\t"
        "vld1.8	{d8-d11}, [%[state]]!\n\t"
        "vld1.8	{d12-d15}, [%[state]]!\n\t"
        "vld1.8	{d16-d19}, [%[state]]!\n\t"
        "vld1.8	{d20-d23}, [%[state]]!\n\t"
        "vld1.8	{d24}, [%[state]]\n\t"
        "sub	%[state], %[state], #0xc0\n\t"
        "\n"
    "L_sha3_arm32_neon_begin_%=: \n\t"
        /* Calc b[0..4] */
        "veor	d26, d0, d5\n\t"
        "veor	d27, d1, d6\n\t"
        "veor	d28, d2, d7\n\t"
        "veor	d29, d3, d8\n\t"
        "veor	d25, d4, d9\n\t"
        "veor	d26, d26, d10\n\t"
        "veor	d27, d27, d11\n\t"
        "veor	d28, d28, d12\n\t"
        "veor	d29, d29, d13\n\t"
        "veor	d25, d25, d14\n\t"
        "veor	d26, d26, d15\n\t"
        "veor	d27, d27, d16\n\t"
        "veor	d28, d28, d17\n\t"
        "veor	d29, d29, d18\n\t"
        "veor	d25, d25, d19\n\t"
        "veor	d26, d26, d20\n\t"
        "veor	d27, d27, d21\n\t"
        "veor	d28, d28, d22\n\t"
        "veor	d29, d29, d23\n\t"
        "veor	d25, d25, d24\n\t"
        "vst1.8	{d25-d26}, [r3]\n\t"
        /* Calc t[0..4] and XOR into s[i*5..i*5+4] */
        /* t[0] */
        "vshr.u64	d30, d27, #63\n\t"
        "vshl.u64	d31, d27, #1\n\t"
        "veor	d25, d25, d30\n\t"
        "veor	d25, d25, d31\n\t"
        /* t[1] */
        "vshr.u64	d30, d28, #63\n\t"
        "vshl.u64	d31, d28, #1\n\t"
        "veor	d26, d26, d30\n\t"
        "veor	d26, d26, d31\n\t"
        /* t[2] */
        "vshr.u64	d30, d29, #63\n\t"
        "vshl.u64	d31, d29, #1\n\t"
        "veor	d27, d27, d30\n\t"
        "veor	d27, d27, d31\n\t"
        /* t[3] */
        "vldr.8	d31, [r3]\n\t"
        "vshr.u64	d30, d31, #63\n\t"
        "vshl.u64	d31, d31, #1\n\t"
        "veor	d28, d28, d30\n\t"
        "veor	d28, d28, d31\n\t"
        /* t[4] */
        "vldr.8	d31, [r3, #8]\n\t"
        "vshr.u64	d30, d31, #63\n\t"
        "vshl.u64	d31, d31, #1\n\t"
        "veor	d29, d29, d30\n\t"
        "veor	d29, d29, d31\n\t"
        "sub	r3, r3, #16\n\t"
        "veor	d0, d0, d25\n\t"
        /* s[1] => s[10] (tmp) */
        "veor	d30, d1, d26\n\t"
        "vshr.u64	d31, d30, #63\n\t"
        "vshl.u64	d30, d30, #1\n\t"
        "veor	d30, d30, d31\n\t"
        /* s[6] => s[1] */
        "veor	d1, d6, d26\n\t"
        "vshr.u64	d31, d1, #20\n\t"
        "vshl.u64	d1, d1, #44\n\t"
        "veor	d1, d1, d31\n\t"
        /* s[9] => s[6] */
        "veor	d6, d9, d29\n\t"
        "vshr.u64	d31, d6, #44\n\t"
        "vshl.u64	d6, d6, #20\n\t"
        "veor	d6, d6, d31\n\t"
        /* s[22] => s[9] */
        "veor	d9, d22, d27\n\t"
        "vshr.u64	d31, d9, #3\n\t"
        "vshl.u64	d9, d9, #61\n\t"
        "veor	d9, d9, d31\n\t"
        /* s[14] => s[22] */
        "veor	d22, d14, d29\n\t"
        "vshr.u64	d31, d22, #25\n\t"
        "vshl.u64	d22, d22, #39\n\t"
        "veor	d22, d22, d31\n\t"
        /* s[20] => s[14] */
        "veor	d14, d20, d25\n\t"
        "vshr.u64	d31, d14, #46\n\t"
        "vshl.u64	d14, d14, #18\n\t"
        "veor	d14, d14, d31\n\t"
        /* s[2] => s[20] */
        "veor	d20, d2, d27\n\t"
        "vshr.u64	d31, d20, #2\n\t"
        "vshl.u64	d20, d20, #62\n\t"
        "veor	d20, d20, d31\n\t"
        /* s[12] => s[2] */
        "veor	d2, d12, d27\n\t"
        "vshr.u64	d31, d2, #21\n\t"
        "vshl.u64	d2, d2, #43\n\t"
        "veor	d2, d2, d31\n\t"
        /* s[13] => s[12] */
        "veor	d12, d13, d28\n\t"
        "vshr.u64	d31, d12, #39\n\t"
        "vshl.u64	d12, d12, #25\n\t"
        "veor	d12, d12, d31\n\t"
        /* s[19] => s[13] */
        "veor	d13, d19, d29\n\t"
        "vshr.u64	d31, d13, #56\n\t"
        "vshl.u64	d13, d13, #8\n\t"
        "veor	d13, d13, d31\n\t"
        /* s[23] => s[19] */
        "veor	d19, d23, d28\n\t"
        "vshr.u64	d31, d19, #8\n\t"
        "vshl.u64	d19, d19, #56\n\t"
        "veor	d19, d19, d31\n\t"
        /* s[15] => s[23] */
        "veor	d23, d15, d25\n\t"
        "vshr.u64	d31, d23, #23\n\t"
        "vshl.u64	d23, d23, #41\n\t"
        "veor	d23, d23, d31\n\t"
        /* s[4] => s[15] */
        "veor	d15, d4, d29\n\t"
        "vshr.u64	d31, d15, #37\n\t"
        "vshl.u64	d15, d15, #27\n\t"
        "veor	d15, d15, d31\n\t"
        /* s[24] => s[4] */
        "veor	d4, d24, d29\n\t"
        "vshr.u64	d31, d4, #50\n\t"
        "vshl.u64	d4, d4, #14\n\t"
        "veor	d4, d4, d31\n\t"
        /* s[21] => s[24] */
        "veor	d24, d21, d26\n\t"
        "vshr.u64	d31, d24, #62\n\t"
        "vshl.u64	d24, d24, #2\n\t"
        "veor	d24, d24, d31\n\t"
        /* s[8] => s[21] */
        "veor	d21, d8, d28\n\t"
        "vshr.u64	d31, d21, #9\n\t"
        "vshl.u64	d21, d21, #55\n\t"
        "veor	d21, d21, d31\n\t"
        /* s[16] => s[8] */
        "veor	d8, d16, d26\n\t"
        "vshr.u64	d31, d8, #19\n\t"
        "vshl.u64	d8, d8, #45\n\t"
        "veor	d8, d8, d31\n\t"
        /* s[5] => s[16] */
        "veor	d16, d5, d25\n\t"
        "vshr.u64	d31, d16, #28\n\t"
        "vshl.u64	d16, d16, #36\n\t"
        "veor	d16, d16, d31\n\t"
        /* s[3] => s[5] */
        "veor	d5, d3, d28\n\t"
        "vshr.u64	d31, d5, #36\n\t"
        "vshl.u64	d5, d5, #28\n\t"
        "veor	d5, d5, d31\n\t"
        /* s[18] => s[3] */
        "veor	d3, d18, d28\n\t"
        "vshr.u64	d31, d3, #43\n\t"
        "vshl.u64	d3, d3, #21\n\t"
        "veor	d3, d3, d31\n\t"
        /* s[17] => s[18] */
        "veor	d18, d17, d27\n\t"
        "vshr.u64	d31, d18, #49\n\t"
        "vshl.u64	d18, d18, #15\n\t"
        "veor	d18, d18, d31\n\t"
        /* s[11] => s[17] */
        "veor	d17, d11, d26\n\t"
        "vshr.u64	d31, d17, #54\n\t"
        "vshl.u64	d17, d17, #10\n\t"
        "veor	d17, d17, d31\n\t"
        /* s[7] => s[11] */
        "veor	d11, d7, d27\n\t"
        "vshr.u64	d31, d11, #58\n\t"
        "vshl.u64	d11, d11, #6\n\t"
        "veor	d11, d11, d31\n\t"
        /* s[10] => s[7] */
        "veor	d7, d10, d25\n\t"
        "vshr.u64	d31, d7, #61\n\t"
        "vshl.u64	d7, d7, #3\n\t"
        "veor	d7, d7, d31\n\t"
        /* Row Mix */
        "vmov	d25, d0\n\t"
        "vmov	d26, d1\n\t"
        "vbic	d31, d2, d26\n\t"
        "veor	d0, d25, d31\n\t"
        "vbic	d31, d3, d2\n\t"
        "veor	d1, d26, d31\n\t"
        "vbic	d31, d4, d3\n\t"
        "veor	d2, d2, d31\n\t"
        "vbic	d31, d25, d4\n\t"
        "veor	d3, d3, d31\n\t"
        "vbic	d31, d26, d25\n\t"
        "veor	d4, d4, d31\n\t"
        "vmov	d25, d5\n\t"
        "vmov	d26, d6\n\t"
        "vbic	d31, d7, d26\n\t"
        "veor	d5, d25, d31\n\t"
        "vbic	d31, d8, d7\n\t"
        "veor	d6, d26, d31\n\t"
        "vbic	d31, d9, d8\n\t"
        "veor	d7, d7, d31\n\t"
        "vbic	d31, d25, d9\n\t"
        "veor	d8, d8, d31\n\t"
        "vbic	d31, d26, d25\n\t"
        "veor	d9, d9, d31\n\t"
        "vmov	d26, d11\n\t"
        "vbic	d31, d12, d26\n\t"
        "veor	d10, d30, d31\n\t"
        "vbic	d31, d13, d12\n\t"
        "veor	d11, d26, d31\n\t"
        "vbic	d31, d14, d13\n\t"
        "veor	d12, d12, d31\n\t"
        "vbic	d31, d30, d14\n\t"
        "veor	d13, d13, d31\n\t"
        "vbic	d31, d26, d30\n\t"
        "veor	d14, d14, d31\n\t"
        "vmov	d25, d15\n\t"
        "vmov	d26, d16\n\t"
        "vbic	d31, d17, d26\n\t"
        "veor	d15, d25, d31\n\t"
        "vbic	d31, d18, d17\n\t"
        "veor	d16, d26, d31\n\t"
        "vbic	d31, d19, d18\n\t"
        "veor	d17, d17, d31\n\t"
        "vbic	d31, d25, d19\n\t"
        "veor	d18, d18, d31\n\t"
        "vbic	d31, d26, d25\n\t"
        "veor	d19, d19, d31\n\t"
        "vmov	d25, d20\n\t"
        "vmov	d26, d21\n\t"
        "vbic	d31, d22, d26\n\t"
        "veor	d20, d25, d31\n\t"
        "vbic	d31, d23, d22\n\t"
        "veor	d21, d26, d31\n\t"
        "vbic	d31, d24, d23\n\t"
        "veor	d22, d22, d31\n\t"
        "vbic	d31, d25, d24\n\t"
        "veor	d23, d23, d31\n\t"
        "vbic	d31, d26, d25\n\t"
        "veor	d24, d24, d31\n\t"
        "vld1.8	{d30}, [r1]!\n\t"
        "subs	r2, r2, #1\n\t"
        "veor	d0, d0, d30\n\t"
        "bne	L_sha3_arm32_neon_begin_%=\n\t"
        "vst1.8	{d0-d3}, [%[state]]!\n\t"
        "vst1.8	{d4-d7}, [%[state]]!\n\t"
        "vst1.8	{d8-d11}, [%[state]]!\n\t"
        "vst1.8	{d12-d15}, [%[state]]!\n\t"
        "vst1.8	{d16-d19}, [%[state]]!\n\t"
        "vst1.8	{d20-d23}, [%[state]]!\n\t"
        "vst1.8	{d24}, [%[state]]\n\t"
        "add	sp, sp, #16\n\t"
        : [state] "+r" (state),
          [L_sha3_arm2_neon_rt] "+r" (L_sha3_arm2_neon_rt_c)
        :
        : "memory", "cc", "r2", "r3", "d0", "d1", "d2", "d3", "d4", "d5", "d6",
            "d7", "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15", "d16",
            "d17", "d18", "d19", "d20", "d21", "d22", "d23", "d24", "d25",
            "d26", "d27", "d28", "d29", "d30", "d31"
    );
}

#endif /* WOLFSSL_ARMASM_NO_NEON */
#ifdef WOLFSSL_ARMASM_NO_NEON
static const word64 L_sha3_arm2_rt[] = {
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

#include <wolfssl/wolfcrypt/sha3.h>

void BlockSha3(word64* state_p)
{
    register word64* state asm ("r0") = (word64*)state_p;
    register word64* L_sha3_arm2_rt_c asm ("r1") = (word64*)&L_sha3_arm2_rt;

    __asm__ __volatile__ (
        "sub	sp, sp, #0xcc\n\t"
        "mov	r2, #12\n\t"
        "\n"
    "L_sha3_arm32_begin_%=: \n\t"
        "str	r2, [sp, #200]\n\t"
        /* Round even */
        /* Calc b[4] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [%[state], #32]\n\t"
        "ldr	r5, [%[state], #36]\n\t"
#else
        "ldrd	r4, r5, [%[state], #32]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [%[state], #72]\n\t"
        "ldr	r7, [%[state], #76]\n\t"
#else
        "ldrd	r6, r7, [%[state], #72]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [%[state], #112]\n\t"
        "ldr	r9, [%[state], #116]\n\t"
#else
        "ldrd	r8, r9, [%[state], #112]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [%[state], #152]\n\t"
        "ldr	r11, [%[state], #156]\n\t"
#else
        "ldrd	r10, r11, [%[state], #152]\n\t"
#endif
        "ldr	r12, [%[state], #192]\n\t"
        "ldr	lr, [%[state], #196]\n\t"
        "eor	r2, r4, r6\n\t"
        "eor	r3, r5, r7\n\t"
        "eor	r2, r2, r8\n\t"
        "eor	r3, r3, r9\n\t"
        "eor	r2, r2, r10\n\t"
        "eor	r3, r3, r11\n\t"
        "eor	r2, r2, r12\n\t"
        "eor	r3, r3, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r2, [sp, #32]\n\t"
        "str	r3, [sp, #36]\n\t"
#else
        "strd	r2, r3, [sp, #32]\n\t"
#endif
        /* Calc b[1] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [%[state], #8]\n\t"
        "ldr	r5, [%[state], #12]\n\t"
#else
        "ldrd	r4, r5, [%[state], #8]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [%[state], #48]\n\t"
        "ldr	r7, [%[state], #52]\n\t"
#else
        "ldrd	r6, r7, [%[state], #48]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [%[state], #88]\n\t"
        "ldr	r9, [%[state], #92]\n\t"
#else
        "ldrd	r8, r9, [%[state], #88]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [%[state], #128]\n\t"
        "ldr	r11, [%[state], #132]\n\t"
#else
        "ldrd	r10, r11, [%[state], #128]\n\t"
#endif
        "ldr	r12, [%[state], #168]\n\t"
        "ldr	lr, [%[state], #172]\n\t"
        "eor	r4, r4, r6\n\t"
        "eor	r5, r5, r7\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r9\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
        "eor	r4, r4, r12\n\t"
        "eor	r5, r5, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r4, [sp, #8]\n\t"
        "str	r5, [sp, #12]\n\t"
#else
        "strd	r4, r5, [sp, #8]\n\t"
#endif
        /* Calc t[0] */
        "eor	r2, r2, r5, lsr #31\n\t"
        "eor	r3, r3, r4, lsr #31\n\t"
        "eor	r2, r2, r4, lsl #1\n\t"
        "eor	r3, r3, r5, lsl #1\n\t"
        /* Calc b[0] and XOR t[0] into s[x*5+0] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [%[state]]\n\t"
        "ldr	r5, [%[state], #4]\n\t"
#else
        "ldrd	r4, r5, [%[state]]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [%[state], #40]\n\t"
        "ldr	r7, [%[state], #44]\n\t"
#else
        "ldrd	r6, r7, [%[state], #40]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [%[state], #80]\n\t"
        "ldr	r9, [%[state], #84]\n\t"
#else
        "ldrd	r8, r9, [%[state], #80]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [%[state], #120]\n\t"
        "ldr	r11, [%[state], #124]\n\t"
#else
        "ldrd	r10, r11, [%[state], #120]\n\t"
#endif
        "eor	r12, r4, r6\n\t"
        "eor	lr, r5, r7\n\t"
        "eor	r12, r12, r8\n\t"
        "eor	lr, lr, r9\n\t"
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "eor	r4, r4, r2\n\t"
        "eor	r5, r5, r3\n\t"
        "eor	r6, r6, r2\n\t"
        "eor	r7, r7, r3\n\t"
        "eor	r8, r8, r2\n\t"
        "eor	r9, r9, r3\n\t"
        "eor	r10, r10, r2\n\t"
        "eor	r11, r11, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r4, [%[state]]\n\t"
        "str	r5, [%[state], #4]\n\t"
#else
        "strd	r4, r5, [%[state]]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r6, [%[state], #40]\n\t"
        "str	r7, [%[state], #44]\n\t"
#else
        "strd	r6, r7, [%[state], #40]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r8, [%[state], #80]\n\t"
        "str	r9, [%[state], #84]\n\t"
#else
        "strd	r8, r9, [%[state], #80]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r10, [%[state], #120]\n\t"
        "str	r11, [%[state], #124]\n\t"
#else
        "strd	r10, r11, [%[state], #120]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [%[state], #160]\n\t"
        "ldr	r11, [%[state], #164]\n\t"
#else
        "ldrd	r10, r11, [%[state], #160]\n\t"
#endif
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "eor	r10, r10, r2\n\t"
        "eor	r11, r11, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r10, [%[state], #160]\n\t"
        "str	r11, [%[state], #164]\n\t"
#else
        "strd	r10, r11, [%[state], #160]\n\t"
#endif
        "str	r12, [sp]\n\t"
        "str	lr, [sp, #4]\n\t"
        /* Calc b[3] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [%[state], #24]\n\t"
        "ldr	r5, [%[state], #28]\n\t"
#else
        "ldrd	r4, r5, [%[state], #24]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [%[state], #64]\n\t"
        "ldr	r7, [%[state], #68]\n\t"
#else
        "ldrd	r6, r7, [%[state], #64]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [%[state], #104]\n\t"
        "ldr	r9, [%[state], #108]\n\t"
#else
        "ldrd	r8, r9, [%[state], #104]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [%[state], #144]\n\t"
        "ldr	r11, [%[state], #148]\n\t"
#else
        "ldrd	r10, r11, [%[state], #144]\n\t"
#endif
        "ldr	r12, [%[state], #184]\n\t"
        "ldr	lr, [%[state], #188]\n\t"
        "eor	r4, r4, r6\n\t"
        "eor	r5, r5, r7\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r9\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
        "eor	r4, r4, r12\n\t"
        "eor	r5, r5, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r4, [sp, #24]\n\t"
        "str	r5, [sp, #28]\n\t"
#else
        "strd	r4, r5, [sp, #24]\n\t"
#endif
        /* Calc t[2] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [sp, #8]\n\t"
        "ldr	r3, [sp, #12]\n\t"
#else
        "ldrd	r2, r3, [sp, #8]\n\t"
#endif
        "eor	r2, r2, r5, lsr #31\n\t"
        "eor	r3, r3, r4, lsr #31\n\t"
        "eor	r2, r2, r4, lsl #1\n\t"
        "eor	r3, r3, r5, lsl #1\n\t"
        /* Calc b[2] and XOR t[2] into s[x*5+2] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [%[state], #16]\n\t"
        "ldr	r5, [%[state], #20]\n\t"
#else
        "ldrd	r4, r5, [%[state], #16]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [%[state], #56]\n\t"
        "ldr	r7, [%[state], #60]\n\t"
#else
        "ldrd	r6, r7, [%[state], #56]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [%[state], #96]\n\t"
        "ldr	r9, [%[state], #100]\n\t"
#else
        "ldrd	r8, r9, [%[state], #96]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [%[state], #136]\n\t"
        "ldr	r11, [%[state], #140]\n\t"
#else
        "ldrd	r10, r11, [%[state], #136]\n\t"
#endif
        "eor	r12, r4, r6\n\t"
        "eor	lr, r5, r7\n\t"
        "eor	r12, r12, r8\n\t"
        "eor	lr, lr, r9\n\t"
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "eor	r4, r4, r2\n\t"
        "eor	r5, r5, r3\n\t"
        "eor	r6, r6, r2\n\t"
        "eor	r7, r7, r3\n\t"
        "eor	r8, r8, r2\n\t"
        "eor	r9, r9, r3\n\t"
        "eor	r10, r10, r2\n\t"
        "eor	r11, r11, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r4, [%[state], #16]\n\t"
        "str	r5, [%[state], #20]\n\t"
#else
        "strd	r4, r5, [%[state], #16]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r6, [%[state], #56]\n\t"
        "str	r7, [%[state], #60]\n\t"
#else
        "strd	r6, r7, [%[state], #56]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r8, [%[state], #96]\n\t"
        "str	r9, [%[state], #100]\n\t"
#else
        "strd	r8, r9, [%[state], #96]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r10, [%[state], #136]\n\t"
        "str	r11, [%[state], #140]\n\t"
#else
        "strd	r10, r11, [%[state], #136]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [%[state], #176]\n\t"
        "ldr	r11, [%[state], #180]\n\t"
#else
        "ldrd	r10, r11, [%[state], #176]\n\t"
#endif
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "eor	r10, r10, r2\n\t"
        "eor	r11, r11, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r10, [%[state], #176]\n\t"
        "str	r11, [%[state], #180]\n\t"
#else
        "strd	r10, r11, [%[state], #176]\n\t"
#endif
        "str	r12, [sp, #16]\n\t"
        "str	lr, [sp, #20]\n\t"
        /* Calc t[1] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [sp]\n\t"
        "ldr	r3, [sp, #4]\n\t"
#else
        "ldrd	r2, r3, [sp]\n\t"
#endif
        "eor	r2, r2, lr, lsr #31\n\t"
        "eor	r3, r3, r12, lsr #31\n\t"
        "eor	r2, r2, r12, lsl #1\n\t"
        "eor	r3, r3, lr, lsl #1\n\t"
        /* XOR t[1] into s[x*5+1] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [%[state], #8]\n\t"
        "ldr	r5, [%[state], #12]\n\t"
#else
        "ldrd	r4, r5, [%[state], #8]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [%[state], #48]\n\t"
        "ldr	r7, [%[state], #52]\n\t"
#else
        "ldrd	r6, r7, [%[state], #48]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [%[state], #88]\n\t"
        "ldr	r9, [%[state], #92]\n\t"
#else
        "ldrd	r8, r9, [%[state], #88]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [%[state], #128]\n\t"
        "ldr	r11, [%[state], #132]\n\t"
#else
        "ldrd	r10, r11, [%[state], #128]\n\t"
#endif
        "ldr	r12, [%[state], #168]\n\t"
        "ldr	lr, [%[state], #172]\n\t"
        "eor	r4, r4, r2\n\t"
        "eor	r5, r5, r3\n\t"
        "eor	r6, r6, r2\n\t"
        "eor	r7, r7, r3\n\t"
        "eor	r8, r8, r2\n\t"
        "eor	r9, r9, r3\n\t"
        "eor	r10, r10, r2\n\t"
        "eor	r11, r11, r3\n\t"
        "eor	r12, r12, r2\n\t"
        "eor	lr, lr, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r4, [%[state], #8]\n\t"
        "str	r5, [%[state], #12]\n\t"
#else
        "strd	r4, r5, [%[state], #8]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r6, [%[state], #48]\n\t"
        "str	r7, [%[state], #52]\n\t"
#else
        "strd	r6, r7, [%[state], #48]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r8, [%[state], #88]\n\t"
        "str	r9, [%[state], #92]\n\t"
#else
        "strd	r8, r9, [%[state], #88]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r10, [%[state], #128]\n\t"
        "str	r11, [%[state], #132]\n\t"
#else
        "strd	r10, r11, [%[state], #128]\n\t"
#endif
        "str	r12, [%[state], #168]\n\t"
        "str	lr, [%[state], #172]\n\t"
        /* Calc t[3] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [sp, #16]\n\t"
        "ldr	r3, [sp, #20]\n\t"
#else
        "ldrd	r2, r3, [sp, #16]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [sp, #32]\n\t"
        "ldr	r5, [sp, #36]\n\t"
#else
        "ldrd	r4, r5, [sp, #32]\n\t"
#endif
        "eor	r2, r2, r5, lsr #31\n\t"
        "eor	r3, r3, r4, lsr #31\n\t"
        "eor	r2, r2, r4, lsl #1\n\t"
        "eor	r3, r3, r5, lsl #1\n\t"
        /* XOR t[3] into s[x*5+3] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [%[state], #24]\n\t"
        "ldr	r5, [%[state], #28]\n\t"
#else
        "ldrd	r4, r5, [%[state], #24]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [%[state], #64]\n\t"
        "ldr	r7, [%[state], #68]\n\t"
#else
        "ldrd	r6, r7, [%[state], #64]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [%[state], #104]\n\t"
        "ldr	r9, [%[state], #108]\n\t"
#else
        "ldrd	r8, r9, [%[state], #104]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [%[state], #144]\n\t"
        "ldr	r11, [%[state], #148]\n\t"
#else
        "ldrd	r10, r11, [%[state], #144]\n\t"
#endif
        "ldr	r12, [%[state], #184]\n\t"
        "ldr	lr, [%[state], #188]\n\t"
        "eor	r4, r4, r2\n\t"
        "eor	r5, r5, r3\n\t"
        "eor	r6, r6, r2\n\t"
        "eor	r7, r7, r3\n\t"
        "eor	r8, r8, r2\n\t"
        "eor	r9, r9, r3\n\t"
        "eor	r10, r10, r2\n\t"
        "eor	r11, r11, r3\n\t"
        "eor	r12, r12, r2\n\t"
        "eor	lr, lr, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r4, [%[state], #24]\n\t"
        "str	r5, [%[state], #28]\n\t"
#else
        "strd	r4, r5, [%[state], #24]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r6, [%[state], #64]\n\t"
        "str	r7, [%[state], #68]\n\t"
#else
        "strd	r6, r7, [%[state], #64]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r8, [%[state], #104]\n\t"
        "str	r9, [%[state], #108]\n\t"
#else
        "strd	r8, r9, [%[state], #104]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r10, [%[state], #144]\n\t"
        "str	r11, [%[state], #148]\n\t"
#else
        "strd	r10, r11, [%[state], #144]\n\t"
#endif
        "str	r12, [%[state], #184]\n\t"
        "str	lr, [%[state], #188]\n\t"
        /* Calc t[4] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [sp, #24]\n\t"
        "ldr	r3, [sp, #28]\n\t"
#else
        "ldrd	r2, r3, [sp, #24]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [sp]\n\t"
        "ldr	r5, [sp, #4]\n\t"
#else
        "ldrd	r4, r5, [sp]\n\t"
#endif
        "eor	r2, r2, r5, lsr #31\n\t"
        "eor	r3, r3, r4, lsr #31\n\t"
        "eor	r2, r2, r4, lsl #1\n\t"
        "eor	r3, r3, r5, lsl #1\n\t"
        /* XOR t[4] into s[x*5+4] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [%[state], #32]\n\t"
        "ldr	r5, [%[state], #36]\n\t"
#else
        "ldrd	r4, r5, [%[state], #32]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [%[state], #72]\n\t"
        "ldr	r7, [%[state], #76]\n\t"
#else
        "ldrd	r6, r7, [%[state], #72]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [%[state], #112]\n\t"
        "ldr	r9, [%[state], #116]\n\t"
#else
        "ldrd	r8, r9, [%[state], #112]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [%[state], #152]\n\t"
        "ldr	r11, [%[state], #156]\n\t"
#else
        "ldrd	r10, r11, [%[state], #152]\n\t"
#endif
        "ldr	r12, [%[state], #192]\n\t"
        "ldr	lr, [%[state], #196]\n\t"
        "eor	r4, r4, r2\n\t"
        "eor	r5, r5, r3\n\t"
        "eor	r6, r6, r2\n\t"
        "eor	r7, r7, r3\n\t"
        "eor	r8, r8, r2\n\t"
        "eor	r9, r9, r3\n\t"
        "eor	r10, r10, r2\n\t"
        "eor	r11, r11, r3\n\t"
        "eor	r12, r12, r2\n\t"
        "eor	lr, lr, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r4, [%[state], #32]\n\t"
        "str	r5, [%[state], #36]\n\t"
#else
        "strd	r4, r5, [%[state], #32]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r6, [%[state], #72]\n\t"
        "str	r7, [%[state], #76]\n\t"
#else
        "strd	r6, r7, [%[state], #72]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r8, [%[state], #112]\n\t"
        "str	r9, [%[state], #116]\n\t"
#else
        "strd	r8, r9, [%[state], #112]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r10, [%[state], #152]\n\t"
        "str	r11, [%[state], #156]\n\t"
#else
        "strd	r10, r11, [%[state], #152]\n\t"
#endif
        "str	r12, [%[state], #192]\n\t"
        "str	lr, [%[state], #196]\n\t"
        /* Row Mix */
        /* Row 0 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [%[state]]\n\t"
        "ldr	r3, [%[state], #4]\n\t"
#else
        "ldrd	r2, r3, [%[state]]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [%[state], #48]\n\t"
        "ldr	r5, [%[state], #52]\n\t"
#else
        "ldrd	r4, r5, [%[state], #48]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [%[state], #96]\n\t"
        "ldr	r7, [%[state], #100]\n\t"
#else
        "ldrd	r6, r7, [%[state], #96]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [%[state], #144]\n\t"
        "ldr	r9, [%[state], #148]\n\t"
#else
        "ldrd	r8, r9, [%[state], #144]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [%[state], #192]\n\t"
        "ldr	r11, [%[state], #196]\n\t"
#else
        "ldrd	r10, r11, [%[state], #192]\n\t"
#endif
        /* s[1] <<< 44 */
        "mov	lr, r4\n\t"
        "lsr	r12, r5, #20\n\t"
        "lsr	r4, r4, #20\n\t"
        "orr	r4, r4, r5, lsl #12\n\t"
        "orr	r5, r12, lr, lsl #12\n\t"
        /* s[2] <<< 43 */
        "mov	lr, r6\n\t"
        "lsr	r12, r7, #21\n\t"
        "lsr	r6, r6, #21\n\t"
        "orr	r6, r6, r7, lsl #11\n\t"
        "orr	r7, r12, lr, lsl #11\n\t"
        /* s[3] <<< 21 */
        "lsr	r12, r9, #11\n\t"
        "lsr	lr, r8, #11\n\t"
        "orr	r8, r12, r8, lsl #21\n\t"
        "orr	r9, lr, r9, lsl #21\n\t"
        /* s[4] <<< 14 */
        "lsr	r12, r11, #18\n\t"
        "lsr	lr, r10, #18\n\t"
        "orr	r10, r12, r10, lsl #14\n\t"
        "orr	r11, lr, r11, lsl #14\n\t"
        "bic	r12, r8, r6\n\t"
        "bic	lr, r9, r7\n\t"
        "eor	r12, r12, r4\n\t"
        "eor	lr, lr, r5\n\t"
        "str	r12, [sp, #8]\n\t"
        "str	lr, [sp, #12]\n\t"
        "bic	r12, r10, r8\n\t"
        "bic	lr, r11, r9\n\t"
        "eor	r12, r12, r6\n\t"
        "eor	lr, lr, r7\n\t"
        "str	r12, [sp, #16]\n\t"
        "str	lr, [sp, #20]\n\t"
        "bic	r12, r2, r10\n\t"
        "bic	lr, r3, r11\n\t"
        "eor	r12, r12, r8\n\t"
        "eor	lr, lr, r9\n\t"
        "str	r12, [sp, #24]\n\t"
        "str	lr, [sp, #28]\n\t"
        "bic	r12, r4, r2\n\t"
        "bic	lr, r5, r3\n\t"
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "str	r12, [sp, #32]\n\t"
        "str	lr, [sp, #36]\n\t"
        /* Get constant */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [r1]\n\t"
        "ldr	r11, [r1, #4]\n\t"
#else
        "ldrd	r10, r11, [r1]\n\t"
#endif
        "add	r1, r1, #8\n\t"
        "bic	r12, r6, r4\n\t"
        "bic	lr, r7, r5\n\t"
        "eor	r12, r12, r2\n\t"
        "eor	lr, lr, r3\n\t"
        /* XOR in constant */
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "str	r12, [sp]\n\t"
        "str	lr, [sp, #4]\n\t"
        /* Row 1 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [%[state], #24]\n\t"
        "ldr	r3, [%[state], #28]\n\t"
#else
        "ldrd	r2, r3, [%[state], #24]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [%[state], #72]\n\t"
        "ldr	r5, [%[state], #76]\n\t"
#else
        "ldrd	r4, r5, [%[state], #72]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [%[state], #80]\n\t"
        "ldr	r7, [%[state], #84]\n\t"
#else
        "ldrd	r6, r7, [%[state], #80]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [%[state], #128]\n\t"
        "ldr	r9, [%[state], #132]\n\t"
#else
        "ldrd	r8, r9, [%[state], #128]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [%[state], #176]\n\t"
        "ldr	r11, [%[state], #180]\n\t"
#else
        "ldrd	r10, r11, [%[state], #176]\n\t"
#endif
        /* s[0] <<< 28 */
        "lsr	r12, r3, #4\n\t"
        "lsr	lr, r2, #4\n\t"
        "orr	r2, r12, r2, lsl #28\n\t"
        "orr	r3, lr, r3, lsl #28\n\t"
        /* s[1] <<< 20 */
        "lsr	r12, r5, #12\n\t"
        "lsr	lr, r4, #12\n\t"
        "orr	r4, r12, r4, lsl #20\n\t"
        "orr	r5, lr, r5, lsl #20\n\t"
        /* s[2] <<< 3 */
        "lsr	r12, r7, #29\n\t"
        "lsr	lr, r6, #29\n\t"
        "orr	r6, r12, r6, lsl #3\n\t"
        "orr	r7, lr, r7, lsl #3\n\t"
        /* s[3] <<< 45 */
        "mov	lr, r8\n\t"
        "lsr	r12, r9, #19\n\t"
        "lsr	r8, r8, #19\n\t"
        "orr	r8, r8, r9, lsl #13\n\t"
        "orr	r9, r12, lr, lsl #13\n\t"
        /* s[4] <<< 61 */
        "mov	lr, r10\n\t"
        "lsr	r12, r11, #3\n\t"
        "lsr	r10, r10, #3\n\t"
        "orr	r10, r10, r11, lsl #29\n\t"
        "orr	r11, r12, lr, lsl #29\n\t"
        "bic	r12, r8, r6\n\t"
        "bic	lr, r9, r7\n\t"
        "eor	r12, r12, r4\n\t"
        "eor	lr, lr, r5\n\t"
        "str	r12, [sp, #48]\n\t"
        "str	lr, [sp, #52]\n\t"
        "bic	r12, r10, r8\n\t"
        "bic	lr, r11, r9\n\t"
        "eor	r12, r12, r6\n\t"
        "eor	lr, lr, r7\n\t"
        "str	r12, [sp, #56]\n\t"
        "str	lr, [sp, #60]\n\t"
        "bic	r12, r2, r10\n\t"
        "bic	lr, r3, r11\n\t"
        "eor	r12, r12, r8\n\t"
        "eor	lr, lr, r9\n\t"
        "str	r12, [sp, #64]\n\t"
        "str	lr, [sp, #68]\n\t"
        "bic	r12, r4, r2\n\t"
        "bic	lr, r5, r3\n\t"
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "str	r12, [sp, #72]\n\t"
        "str	lr, [sp, #76]\n\t"
        "bic	r12, r6, r4\n\t"
        "bic	lr, r7, r5\n\t"
        "eor	r12, r12, r2\n\t"
        "eor	lr, lr, r3\n\t"
        "str	r12, [sp, #40]\n\t"
        "str	lr, [sp, #44]\n\t"
        /* Row 2 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [%[state], #8]\n\t"
        "ldr	r3, [%[state], #12]\n\t"
#else
        "ldrd	r2, r3, [%[state], #8]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [%[state], #56]\n\t"
        "ldr	r5, [%[state], #60]\n\t"
#else
        "ldrd	r4, r5, [%[state], #56]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [%[state], #104]\n\t"
        "ldr	r7, [%[state], #108]\n\t"
#else
        "ldrd	r6, r7, [%[state], #104]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [%[state], #152]\n\t"
        "ldr	r9, [%[state], #156]\n\t"
#else
        "ldrd	r8, r9, [%[state], #152]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [%[state], #160]\n\t"
        "ldr	r11, [%[state], #164]\n\t"
#else
        "ldrd	r10, r11, [%[state], #160]\n\t"
#endif
        /* s[0] <<< 1 */
        "lsr	r12, r3, #31\n\t"
        "lsr	lr, r2, #31\n\t"
        "orr	r2, r12, r2, lsl #1\n\t"
        "orr	r3, lr, r3, lsl #1\n\t"
        /* s[1] <<< 6 */
        "lsr	r12, r5, #26\n\t"
        "lsr	lr, r4, #26\n\t"
        "orr	r4, r12, r4, lsl #6\n\t"
        "orr	r5, lr, r5, lsl #6\n\t"
        /* s[2] <<< 25 */
        "lsr	r12, r7, #7\n\t"
        "lsr	lr, r6, #7\n\t"
        "orr	r6, r12, r6, lsl #25\n\t"
        "orr	r7, lr, r7, lsl #25\n\t"
        /* s[3] <<< 8 */
        "lsr	r12, r9, #24\n\t"
        "lsr	lr, r8, #24\n\t"
        "orr	r8, r12, r8, lsl #8\n\t"
        "orr	r9, lr, r9, lsl #8\n\t"
        /* s[4] <<< 18 */
        "lsr	r12, r11, #14\n\t"
        "lsr	lr, r10, #14\n\t"
        "orr	r10, r12, r10, lsl #18\n\t"
        "orr	r11, lr, r11, lsl #18\n\t"
        "bic	r12, r8, r6\n\t"
        "bic	lr, r9, r7\n\t"
        "eor	r12, r12, r4\n\t"
        "eor	lr, lr, r5\n\t"
        "str	r12, [sp, #88]\n\t"
        "str	lr, [sp, #92]\n\t"
        "bic	r12, r10, r8\n\t"
        "bic	lr, r11, r9\n\t"
        "eor	r12, r12, r6\n\t"
        "eor	lr, lr, r7\n\t"
        "str	r12, [sp, #96]\n\t"
        "str	lr, [sp, #100]\n\t"
        "bic	r12, r2, r10\n\t"
        "bic	lr, r3, r11\n\t"
        "eor	r12, r12, r8\n\t"
        "eor	lr, lr, r9\n\t"
        "str	r12, [sp, #104]\n\t"
        "str	lr, [sp, #108]\n\t"
        "bic	r12, r4, r2\n\t"
        "bic	lr, r5, r3\n\t"
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "str	r12, [sp, #112]\n\t"
        "str	lr, [sp, #116]\n\t"
        "bic	r12, r6, r4\n\t"
        "bic	lr, r7, r5\n\t"
        "eor	r12, r12, r2\n\t"
        "eor	lr, lr, r3\n\t"
        "str	r12, [sp, #80]\n\t"
        "str	lr, [sp, #84]\n\t"
        /* Row 3 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [%[state], #32]\n\t"
        "ldr	r3, [%[state], #36]\n\t"
#else
        "ldrd	r2, r3, [%[state], #32]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [%[state], #40]\n\t"
        "ldr	r5, [%[state], #44]\n\t"
#else
        "ldrd	r4, r5, [%[state], #40]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [%[state], #88]\n\t"
        "ldr	r7, [%[state], #92]\n\t"
#else
        "ldrd	r6, r7, [%[state], #88]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [%[state], #136]\n\t"
        "ldr	r9, [%[state], #140]\n\t"
#else
        "ldrd	r8, r9, [%[state], #136]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [%[state], #184]\n\t"
        "ldr	r11, [%[state], #188]\n\t"
#else
        "ldrd	r10, r11, [%[state], #184]\n\t"
#endif
        /* s[0] <<< 27 */
        "lsr	r12, r3, #5\n\t"
        "lsr	lr, r2, #5\n\t"
        "orr	r2, r12, r2, lsl #27\n\t"
        "orr	r3, lr, r3, lsl #27\n\t"
        /* s[1] <<< 36 */
        "mov	lr, r4\n\t"
        "lsr	r12, r5, #28\n\t"
        "lsr	r4, r4, #28\n\t"
        "orr	r4, r4, r5, lsl #4\n\t"
        "orr	r5, r12, lr, lsl #4\n\t"
        /* s[2] <<< 10 */
        "lsr	r12, r7, #22\n\t"
        "lsr	lr, r6, #22\n\t"
        "orr	r6, r12, r6, lsl #10\n\t"
        "orr	r7, lr, r7, lsl #10\n\t"
        /* s[3] <<< 15 */
        "lsr	r12, r9, #17\n\t"
        "lsr	lr, r8, #17\n\t"
        "orr	r8, r12, r8, lsl #15\n\t"
        "orr	r9, lr, r9, lsl #15\n\t"
        /* s[4] <<< 56 */
        "mov	lr, r10\n\t"
        "lsr	r12, r11, #8\n\t"
        "lsr	r10, r10, #8\n\t"
        "orr	r10, r10, r11, lsl #24\n\t"
        "orr	r11, r12, lr, lsl #24\n\t"
        "bic	r12, r8, r6\n\t"
        "bic	lr, r9, r7\n\t"
        "eor	r12, r12, r4\n\t"
        "eor	lr, lr, r5\n\t"
        "str	r12, [sp, #128]\n\t"
        "str	lr, [sp, #132]\n\t"
        "bic	r12, r10, r8\n\t"
        "bic	lr, r11, r9\n\t"
        "eor	r12, r12, r6\n\t"
        "eor	lr, lr, r7\n\t"
        "str	r12, [sp, #136]\n\t"
        "str	lr, [sp, #140]\n\t"
        "bic	r12, r2, r10\n\t"
        "bic	lr, r3, r11\n\t"
        "eor	r12, r12, r8\n\t"
        "eor	lr, lr, r9\n\t"
        "str	r12, [sp, #144]\n\t"
        "str	lr, [sp, #148]\n\t"
        "bic	r12, r4, r2\n\t"
        "bic	lr, r5, r3\n\t"
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "str	r12, [sp, #152]\n\t"
        "str	lr, [sp, #156]\n\t"
        "bic	r12, r6, r4\n\t"
        "bic	lr, r7, r5\n\t"
        "eor	r12, r12, r2\n\t"
        "eor	lr, lr, r3\n\t"
        "str	r12, [sp, #120]\n\t"
        "str	lr, [sp, #124]\n\t"
        /* Row 4 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [%[state], #16]\n\t"
        "ldr	r3, [%[state], #20]\n\t"
#else
        "ldrd	r2, r3, [%[state], #16]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [%[state], #64]\n\t"
        "ldr	r5, [%[state], #68]\n\t"
#else
        "ldrd	r4, r5, [%[state], #64]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [%[state], #112]\n\t"
        "ldr	r7, [%[state], #116]\n\t"
#else
        "ldrd	r6, r7, [%[state], #112]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [%[state], #120]\n\t"
        "ldr	r9, [%[state], #124]\n\t"
#else
        "ldrd	r8, r9, [%[state], #120]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [%[state], #168]\n\t"
        "ldr	r11, [%[state], #172]\n\t"
#else
        "ldrd	r10, r11, [%[state], #168]\n\t"
#endif
        /* s[0] <<< 62 */
        "mov	lr, r2\n\t"
        "lsr	r12, r3, #2\n\t"
        "lsr	r2, r2, #2\n\t"
        "orr	r2, r2, r3, lsl #30\n\t"
        "orr	r3, r12, lr, lsl #30\n\t"
        /* s[1] <<< 55 */
        "mov	lr, r4\n\t"
        "lsr	r12, r5, #9\n\t"
        "lsr	r4, r4, #9\n\t"
        "orr	r4, r4, r5, lsl #23\n\t"
        "orr	r5, r12, lr, lsl #23\n\t"
        /* s[2] <<< 39 */
        "mov	lr, r6\n\t"
        "lsr	r12, r7, #25\n\t"
        "lsr	r6, r6, #25\n\t"
        "orr	r6, r6, r7, lsl #7\n\t"
        "orr	r7, r12, lr, lsl #7\n\t"
        /* s[3] <<< 41 */
        "mov	lr, r8\n\t"
        "lsr	r12, r9, #23\n\t"
        "lsr	r8, r8, #23\n\t"
        "orr	r8, r8, r9, lsl #9\n\t"
        "orr	r9, r12, lr, lsl #9\n\t"
        /* s[4] <<< 2 */
        "lsr	r12, r11, #30\n\t"
        "lsr	lr, r10, #30\n\t"
        "orr	r10, r12, r10, lsl #2\n\t"
        "orr	r11, lr, r11, lsl #2\n\t"
        "bic	r12, r8, r6\n\t"
        "bic	lr, r9, r7\n\t"
        "eor	r12, r12, r4\n\t"
        "eor	lr, lr, r5\n\t"
        "str	r12, [sp, #168]\n\t"
        "str	lr, [sp, #172]\n\t"
        "bic	r12, r10, r8\n\t"
        "bic	lr, r11, r9\n\t"
        "eor	r12, r12, r6\n\t"
        "eor	lr, lr, r7\n\t"
        "str	r12, [sp, #176]\n\t"
        "str	lr, [sp, #180]\n\t"
        "bic	r12, r2, r10\n\t"
        "bic	lr, r3, r11\n\t"
        "eor	r12, r12, r8\n\t"
        "eor	lr, lr, r9\n\t"
        "str	r12, [sp, #184]\n\t"
        "str	lr, [sp, #188]\n\t"
        "bic	r12, r4, r2\n\t"
        "bic	lr, r5, r3\n\t"
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "str	r12, [sp, #192]\n\t"
        "str	lr, [sp, #196]\n\t"
        "bic	r12, r6, r4\n\t"
        "bic	lr, r7, r5\n\t"
        "eor	r12, r12, r2\n\t"
        "eor	lr, lr, r3\n\t"
        "str	r12, [sp, #160]\n\t"
        "str	lr, [sp, #164]\n\t"
        /* Round odd */
        /* Calc b[4] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [sp, #32]\n\t"
        "ldr	r5, [sp, #36]\n\t"
#else
        "ldrd	r4, r5, [sp, #32]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [sp, #72]\n\t"
        "ldr	r7, [sp, #76]\n\t"
#else
        "ldrd	r6, r7, [sp, #72]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [sp, #112]\n\t"
        "ldr	r9, [sp, #116]\n\t"
#else
        "ldrd	r8, r9, [sp, #112]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [sp, #152]\n\t"
        "ldr	r11, [sp, #156]\n\t"
#else
        "ldrd	r10, r11, [sp, #152]\n\t"
#endif
        "ldr	r12, [sp, #192]\n\t"
        "ldr	lr, [sp, #196]\n\t"
        "eor	r2, r4, r6\n\t"
        "eor	r3, r5, r7\n\t"
        "eor	r2, r2, r8\n\t"
        "eor	r3, r3, r9\n\t"
        "eor	r2, r2, r10\n\t"
        "eor	r3, r3, r11\n\t"
        "eor	r2, r2, r12\n\t"
        "eor	r3, r3, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r2, [%[state], #32]\n\t"
        "str	r3, [%[state], #36]\n\t"
#else
        "strd	r2, r3, [%[state], #32]\n\t"
#endif
        /* Calc b[1] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [sp, #8]\n\t"
        "ldr	r5, [sp, #12]\n\t"
#else
        "ldrd	r4, r5, [sp, #8]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [sp, #48]\n\t"
        "ldr	r7, [sp, #52]\n\t"
#else
        "ldrd	r6, r7, [sp, #48]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [sp, #88]\n\t"
        "ldr	r9, [sp, #92]\n\t"
#else
        "ldrd	r8, r9, [sp, #88]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [sp, #128]\n\t"
        "ldr	r11, [sp, #132]\n\t"
#else
        "ldrd	r10, r11, [sp, #128]\n\t"
#endif
        "ldr	r12, [sp, #168]\n\t"
        "ldr	lr, [sp, #172]\n\t"
        "eor	r4, r4, r6\n\t"
        "eor	r5, r5, r7\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r9\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
        "eor	r4, r4, r12\n\t"
        "eor	r5, r5, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r4, [%[state], #8]\n\t"
        "str	r5, [%[state], #12]\n\t"
#else
        "strd	r4, r5, [%[state], #8]\n\t"
#endif
        /* Calc t[0] */
        "eor	r2, r2, r5, lsr #31\n\t"
        "eor	r3, r3, r4, lsr #31\n\t"
        "eor	r2, r2, r4, lsl #1\n\t"
        "eor	r3, r3, r5, lsl #1\n\t"
        /* Calc b[0] and XOR t[0] into s[x*5+0] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [sp]\n\t"
        "ldr	r5, [sp, #4]\n\t"
#else
        "ldrd	r4, r5, [sp]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [sp, #40]\n\t"
        "ldr	r7, [sp, #44]\n\t"
#else
        "ldrd	r6, r7, [sp, #40]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [sp, #80]\n\t"
        "ldr	r9, [sp, #84]\n\t"
#else
        "ldrd	r8, r9, [sp, #80]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [sp, #120]\n\t"
        "ldr	r11, [sp, #124]\n\t"
#else
        "ldrd	r10, r11, [sp, #120]\n\t"
#endif
        "eor	r12, r4, r6\n\t"
        "eor	lr, r5, r7\n\t"
        "eor	r12, r12, r8\n\t"
        "eor	lr, lr, r9\n\t"
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "eor	r4, r4, r2\n\t"
        "eor	r5, r5, r3\n\t"
        "eor	r6, r6, r2\n\t"
        "eor	r7, r7, r3\n\t"
        "eor	r8, r8, r2\n\t"
        "eor	r9, r9, r3\n\t"
        "eor	r10, r10, r2\n\t"
        "eor	r11, r11, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r4, [sp]\n\t"
        "str	r5, [sp, #4]\n\t"
#else
        "strd	r4, r5, [sp]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r6, [sp, #40]\n\t"
        "str	r7, [sp, #44]\n\t"
#else
        "strd	r6, r7, [sp, #40]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r8, [sp, #80]\n\t"
        "str	r9, [sp, #84]\n\t"
#else
        "strd	r8, r9, [sp, #80]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r10, [sp, #120]\n\t"
        "str	r11, [sp, #124]\n\t"
#else
        "strd	r10, r11, [sp, #120]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [sp, #160]\n\t"
        "ldr	r11, [sp, #164]\n\t"
#else
        "ldrd	r10, r11, [sp, #160]\n\t"
#endif
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "eor	r10, r10, r2\n\t"
        "eor	r11, r11, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r10, [sp, #160]\n\t"
        "str	r11, [sp, #164]\n\t"
#else
        "strd	r10, r11, [sp, #160]\n\t"
#endif
        "str	r12, [%[state]]\n\t"
        "str	lr, [%[state], #4]\n\t"
        /* Calc b[3] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [sp, #24]\n\t"
        "ldr	r5, [sp, #28]\n\t"
#else
        "ldrd	r4, r5, [sp, #24]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [sp, #64]\n\t"
        "ldr	r7, [sp, #68]\n\t"
#else
        "ldrd	r6, r7, [sp, #64]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [sp, #104]\n\t"
        "ldr	r9, [sp, #108]\n\t"
#else
        "ldrd	r8, r9, [sp, #104]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [sp, #144]\n\t"
        "ldr	r11, [sp, #148]\n\t"
#else
        "ldrd	r10, r11, [sp, #144]\n\t"
#endif
        "ldr	r12, [sp, #184]\n\t"
        "ldr	lr, [sp, #188]\n\t"
        "eor	r4, r4, r6\n\t"
        "eor	r5, r5, r7\n\t"
        "eor	r4, r4, r8\n\t"
        "eor	r5, r5, r9\n\t"
        "eor	r4, r4, r10\n\t"
        "eor	r5, r5, r11\n\t"
        "eor	r4, r4, r12\n\t"
        "eor	r5, r5, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r4, [%[state], #24]\n\t"
        "str	r5, [%[state], #28]\n\t"
#else
        "strd	r4, r5, [%[state], #24]\n\t"
#endif
        /* Calc t[2] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [%[state], #8]\n\t"
        "ldr	r3, [%[state], #12]\n\t"
#else
        "ldrd	r2, r3, [%[state], #8]\n\t"
#endif
        "eor	r2, r2, r5, lsr #31\n\t"
        "eor	r3, r3, r4, lsr #31\n\t"
        "eor	r2, r2, r4, lsl #1\n\t"
        "eor	r3, r3, r5, lsl #1\n\t"
        /* Calc b[2] and XOR t[2] into s[x*5+2] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [sp, #16]\n\t"
        "ldr	r5, [sp, #20]\n\t"
#else
        "ldrd	r4, r5, [sp, #16]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [sp, #56]\n\t"
        "ldr	r7, [sp, #60]\n\t"
#else
        "ldrd	r6, r7, [sp, #56]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [sp, #96]\n\t"
        "ldr	r9, [sp, #100]\n\t"
#else
        "ldrd	r8, r9, [sp, #96]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [sp, #136]\n\t"
        "ldr	r11, [sp, #140]\n\t"
#else
        "ldrd	r10, r11, [sp, #136]\n\t"
#endif
        "eor	r12, r4, r6\n\t"
        "eor	lr, r5, r7\n\t"
        "eor	r12, r12, r8\n\t"
        "eor	lr, lr, r9\n\t"
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "eor	r4, r4, r2\n\t"
        "eor	r5, r5, r3\n\t"
        "eor	r6, r6, r2\n\t"
        "eor	r7, r7, r3\n\t"
        "eor	r8, r8, r2\n\t"
        "eor	r9, r9, r3\n\t"
        "eor	r10, r10, r2\n\t"
        "eor	r11, r11, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r4, [sp, #16]\n\t"
        "str	r5, [sp, #20]\n\t"
#else
        "strd	r4, r5, [sp, #16]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r6, [sp, #56]\n\t"
        "str	r7, [sp, #60]\n\t"
#else
        "strd	r6, r7, [sp, #56]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r8, [sp, #96]\n\t"
        "str	r9, [sp, #100]\n\t"
#else
        "strd	r8, r9, [sp, #96]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r10, [sp, #136]\n\t"
        "str	r11, [sp, #140]\n\t"
#else
        "strd	r10, r11, [sp, #136]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [sp, #176]\n\t"
        "ldr	r11, [sp, #180]\n\t"
#else
        "ldrd	r10, r11, [sp, #176]\n\t"
#endif
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "eor	r10, r10, r2\n\t"
        "eor	r11, r11, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r10, [sp, #176]\n\t"
        "str	r11, [sp, #180]\n\t"
#else
        "strd	r10, r11, [sp, #176]\n\t"
#endif
        "str	r12, [%[state], #16]\n\t"
        "str	lr, [%[state], #20]\n\t"
        /* Calc t[1] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [%[state]]\n\t"
        "ldr	r3, [%[state], #4]\n\t"
#else
        "ldrd	r2, r3, [%[state]]\n\t"
#endif
        "eor	r2, r2, lr, lsr #31\n\t"
        "eor	r3, r3, r12, lsr #31\n\t"
        "eor	r2, r2, r12, lsl #1\n\t"
        "eor	r3, r3, lr, lsl #1\n\t"
        /* XOR t[1] into s[x*5+1] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [sp, #8]\n\t"
        "ldr	r5, [sp, #12]\n\t"
#else
        "ldrd	r4, r5, [sp, #8]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [sp, #48]\n\t"
        "ldr	r7, [sp, #52]\n\t"
#else
        "ldrd	r6, r7, [sp, #48]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [sp, #88]\n\t"
        "ldr	r9, [sp, #92]\n\t"
#else
        "ldrd	r8, r9, [sp, #88]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [sp, #128]\n\t"
        "ldr	r11, [sp, #132]\n\t"
#else
        "ldrd	r10, r11, [sp, #128]\n\t"
#endif
        "ldr	r12, [sp, #168]\n\t"
        "ldr	lr, [sp, #172]\n\t"
        "eor	r4, r4, r2\n\t"
        "eor	r5, r5, r3\n\t"
        "eor	r6, r6, r2\n\t"
        "eor	r7, r7, r3\n\t"
        "eor	r8, r8, r2\n\t"
        "eor	r9, r9, r3\n\t"
        "eor	r10, r10, r2\n\t"
        "eor	r11, r11, r3\n\t"
        "eor	r12, r12, r2\n\t"
        "eor	lr, lr, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r4, [sp, #8]\n\t"
        "str	r5, [sp, #12]\n\t"
#else
        "strd	r4, r5, [sp, #8]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r6, [sp, #48]\n\t"
        "str	r7, [sp, #52]\n\t"
#else
        "strd	r6, r7, [sp, #48]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r8, [sp, #88]\n\t"
        "str	r9, [sp, #92]\n\t"
#else
        "strd	r8, r9, [sp, #88]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r10, [sp, #128]\n\t"
        "str	r11, [sp, #132]\n\t"
#else
        "strd	r10, r11, [sp, #128]\n\t"
#endif
        "str	r12, [sp, #168]\n\t"
        "str	lr, [sp, #172]\n\t"
        /* Calc t[3] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [%[state], #16]\n\t"
        "ldr	r3, [%[state], #20]\n\t"
#else
        "ldrd	r2, r3, [%[state], #16]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [%[state], #32]\n\t"
        "ldr	r5, [%[state], #36]\n\t"
#else
        "ldrd	r4, r5, [%[state], #32]\n\t"
#endif
        "eor	r2, r2, r5, lsr #31\n\t"
        "eor	r3, r3, r4, lsr #31\n\t"
        "eor	r2, r2, r4, lsl #1\n\t"
        "eor	r3, r3, r5, lsl #1\n\t"
        /* XOR t[3] into s[x*5+3] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [sp, #24]\n\t"
        "ldr	r5, [sp, #28]\n\t"
#else
        "ldrd	r4, r5, [sp, #24]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [sp, #64]\n\t"
        "ldr	r7, [sp, #68]\n\t"
#else
        "ldrd	r6, r7, [sp, #64]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [sp, #104]\n\t"
        "ldr	r9, [sp, #108]\n\t"
#else
        "ldrd	r8, r9, [sp, #104]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [sp, #144]\n\t"
        "ldr	r11, [sp, #148]\n\t"
#else
        "ldrd	r10, r11, [sp, #144]\n\t"
#endif
        "ldr	r12, [sp, #184]\n\t"
        "ldr	lr, [sp, #188]\n\t"
        "eor	r4, r4, r2\n\t"
        "eor	r5, r5, r3\n\t"
        "eor	r6, r6, r2\n\t"
        "eor	r7, r7, r3\n\t"
        "eor	r8, r8, r2\n\t"
        "eor	r9, r9, r3\n\t"
        "eor	r10, r10, r2\n\t"
        "eor	r11, r11, r3\n\t"
        "eor	r12, r12, r2\n\t"
        "eor	lr, lr, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r4, [sp, #24]\n\t"
        "str	r5, [sp, #28]\n\t"
#else
        "strd	r4, r5, [sp, #24]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r6, [sp, #64]\n\t"
        "str	r7, [sp, #68]\n\t"
#else
        "strd	r6, r7, [sp, #64]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r8, [sp, #104]\n\t"
        "str	r9, [sp, #108]\n\t"
#else
        "strd	r8, r9, [sp, #104]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r10, [sp, #144]\n\t"
        "str	r11, [sp, #148]\n\t"
#else
        "strd	r10, r11, [sp, #144]\n\t"
#endif
        "str	r12, [sp, #184]\n\t"
        "str	lr, [sp, #188]\n\t"
        /* Calc t[4] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [%[state], #24]\n\t"
        "ldr	r3, [%[state], #28]\n\t"
#else
        "ldrd	r2, r3, [%[state], #24]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [%[state]]\n\t"
        "ldr	r5, [%[state], #4]\n\t"
#else
        "ldrd	r4, r5, [%[state]]\n\t"
#endif
        "eor	r2, r2, r5, lsr #31\n\t"
        "eor	r3, r3, r4, lsr #31\n\t"
        "eor	r2, r2, r4, lsl #1\n\t"
        "eor	r3, r3, r5, lsl #1\n\t"
        /* XOR t[4] into s[x*5+4] */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [sp, #32]\n\t"
        "ldr	r5, [sp, #36]\n\t"
#else
        "ldrd	r4, r5, [sp, #32]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [sp, #72]\n\t"
        "ldr	r7, [sp, #76]\n\t"
#else
        "ldrd	r6, r7, [sp, #72]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [sp, #112]\n\t"
        "ldr	r9, [sp, #116]\n\t"
#else
        "ldrd	r8, r9, [sp, #112]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [sp, #152]\n\t"
        "ldr	r11, [sp, #156]\n\t"
#else
        "ldrd	r10, r11, [sp, #152]\n\t"
#endif
        "ldr	r12, [sp, #192]\n\t"
        "ldr	lr, [sp, #196]\n\t"
        "eor	r4, r4, r2\n\t"
        "eor	r5, r5, r3\n\t"
        "eor	r6, r6, r2\n\t"
        "eor	r7, r7, r3\n\t"
        "eor	r8, r8, r2\n\t"
        "eor	r9, r9, r3\n\t"
        "eor	r10, r10, r2\n\t"
        "eor	r11, r11, r3\n\t"
        "eor	r12, r12, r2\n\t"
        "eor	lr, lr, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r4, [sp, #32]\n\t"
        "str	r5, [sp, #36]\n\t"
#else
        "strd	r4, r5, [sp, #32]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r6, [sp, #72]\n\t"
        "str	r7, [sp, #76]\n\t"
#else
        "strd	r6, r7, [sp, #72]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r8, [sp, #112]\n\t"
        "str	r9, [sp, #116]\n\t"
#else
        "strd	r8, r9, [sp, #112]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "str	r10, [sp, #152]\n\t"
        "str	r11, [sp, #156]\n\t"
#else
        "strd	r10, r11, [sp, #152]\n\t"
#endif
        "str	r12, [sp, #192]\n\t"
        "str	lr, [sp, #196]\n\t"
        /* Row Mix */
        /* Row 0 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [sp]\n\t"
        "ldr	r3, [sp, #4]\n\t"
#else
        "ldrd	r2, r3, [sp]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [sp, #48]\n\t"
        "ldr	r5, [sp, #52]\n\t"
#else
        "ldrd	r4, r5, [sp, #48]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [sp, #96]\n\t"
        "ldr	r7, [sp, #100]\n\t"
#else
        "ldrd	r6, r7, [sp, #96]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [sp, #144]\n\t"
        "ldr	r9, [sp, #148]\n\t"
#else
        "ldrd	r8, r9, [sp, #144]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [sp, #192]\n\t"
        "ldr	r11, [sp, #196]\n\t"
#else
        "ldrd	r10, r11, [sp, #192]\n\t"
#endif
        /* s[1] <<< 44 */
        "mov	lr, r4\n\t"
        "lsr	r12, r5, #20\n\t"
        "lsr	r4, r4, #20\n\t"
        "orr	r4, r4, r5, lsl #12\n\t"
        "orr	r5, r12, lr, lsl #12\n\t"
        /* s[2] <<< 43 */
        "mov	lr, r6\n\t"
        "lsr	r12, r7, #21\n\t"
        "lsr	r6, r6, #21\n\t"
        "orr	r6, r6, r7, lsl #11\n\t"
        "orr	r7, r12, lr, lsl #11\n\t"
        /* s[3] <<< 21 */
        "lsr	r12, r9, #11\n\t"
        "lsr	lr, r8, #11\n\t"
        "orr	r8, r12, r8, lsl #21\n\t"
        "orr	r9, lr, r9, lsl #21\n\t"
        /* s[4] <<< 14 */
        "lsr	r12, r11, #18\n\t"
        "lsr	lr, r10, #18\n\t"
        "orr	r10, r12, r10, lsl #14\n\t"
        "orr	r11, lr, r11, lsl #14\n\t"
        "bic	r12, r8, r6\n\t"
        "bic	lr, r9, r7\n\t"
        "eor	r12, r12, r4\n\t"
        "eor	lr, lr, r5\n\t"
        "str	r12, [%[state], #8]\n\t"
        "str	lr, [%[state], #12]\n\t"
        "bic	r12, r10, r8\n\t"
        "bic	lr, r11, r9\n\t"
        "eor	r12, r12, r6\n\t"
        "eor	lr, lr, r7\n\t"
        "str	r12, [%[state], #16]\n\t"
        "str	lr, [%[state], #20]\n\t"
        "bic	r12, r2, r10\n\t"
        "bic	lr, r3, r11\n\t"
        "eor	r12, r12, r8\n\t"
        "eor	lr, lr, r9\n\t"
        "str	r12, [%[state], #24]\n\t"
        "str	lr, [%[state], #28]\n\t"
        "bic	r12, r4, r2\n\t"
        "bic	lr, r5, r3\n\t"
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "str	r12, [%[state], #32]\n\t"
        "str	lr, [%[state], #36]\n\t"
        /* Get constant */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [r1]\n\t"
        "ldr	r11, [r1, #4]\n\t"
#else
        "ldrd	r10, r11, [r1]\n\t"
#endif
        "add	r1, r1, #8\n\t"
        "bic	r12, r6, r4\n\t"
        "bic	lr, r7, r5\n\t"
        "eor	r12, r12, r2\n\t"
        "eor	lr, lr, r3\n\t"
        /* XOR in constant */
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "str	r12, [%[state]]\n\t"
        "str	lr, [%[state], #4]\n\t"
        /* Row 1 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [sp, #24]\n\t"
        "ldr	r3, [sp, #28]\n\t"
#else
        "ldrd	r2, r3, [sp, #24]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [sp, #72]\n\t"
        "ldr	r5, [sp, #76]\n\t"
#else
        "ldrd	r4, r5, [sp, #72]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [sp, #80]\n\t"
        "ldr	r7, [sp, #84]\n\t"
#else
        "ldrd	r6, r7, [sp, #80]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [sp, #128]\n\t"
        "ldr	r9, [sp, #132]\n\t"
#else
        "ldrd	r8, r9, [sp, #128]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [sp, #176]\n\t"
        "ldr	r11, [sp, #180]\n\t"
#else
        "ldrd	r10, r11, [sp, #176]\n\t"
#endif
        /* s[0] <<< 28 */
        "lsr	r12, r3, #4\n\t"
        "lsr	lr, r2, #4\n\t"
        "orr	r2, r12, r2, lsl #28\n\t"
        "orr	r3, lr, r3, lsl #28\n\t"
        /* s[1] <<< 20 */
        "lsr	r12, r5, #12\n\t"
        "lsr	lr, r4, #12\n\t"
        "orr	r4, r12, r4, lsl #20\n\t"
        "orr	r5, lr, r5, lsl #20\n\t"
        /* s[2] <<< 3 */
        "lsr	r12, r7, #29\n\t"
        "lsr	lr, r6, #29\n\t"
        "orr	r6, r12, r6, lsl #3\n\t"
        "orr	r7, lr, r7, lsl #3\n\t"
        /* s[3] <<< 45 */
        "mov	lr, r8\n\t"
        "lsr	r12, r9, #19\n\t"
        "lsr	r8, r8, #19\n\t"
        "orr	r8, r8, r9, lsl #13\n\t"
        "orr	r9, r12, lr, lsl #13\n\t"
        /* s[4] <<< 61 */
        "mov	lr, r10\n\t"
        "lsr	r12, r11, #3\n\t"
        "lsr	r10, r10, #3\n\t"
        "orr	r10, r10, r11, lsl #29\n\t"
        "orr	r11, r12, lr, lsl #29\n\t"
        "bic	r12, r8, r6\n\t"
        "bic	lr, r9, r7\n\t"
        "eor	r12, r12, r4\n\t"
        "eor	lr, lr, r5\n\t"
        "str	r12, [%[state], #48]\n\t"
        "str	lr, [%[state], #52]\n\t"
        "bic	r12, r10, r8\n\t"
        "bic	lr, r11, r9\n\t"
        "eor	r12, r12, r6\n\t"
        "eor	lr, lr, r7\n\t"
        "str	r12, [%[state], #56]\n\t"
        "str	lr, [%[state], #60]\n\t"
        "bic	r12, r2, r10\n\t"
        "bic	lr, r3, r11\n\t"
        "eor	r12, r12, r8\n\t"
        "eor	lr, lr, r9\n\t"
        "str	r12, [%[state], #64]\n\t"
        "str	lr, [%[state], #68]\n\t"
        "bic	r12, r4, r2\n\t"
        "bic	lr, r5, r3\n\t"
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "str	r12, [%[state], #72]\n\t"
        "str	lr, [%[state], #76]\n\t"
        "bic	r12, r6, r4\n\t"
        "bic	lr, r7, r5\n\t"
        "eor	r12, r12, r2\n\t"
        "eor	lr, lr, r3\n\t"
        "str	r12, [%[state], #40]\n\t"
        "str	lr, [%[state], #44]\n\t"
        /* Row 2 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [sp, #8]\n\t"
        "ldr	r3, [sp, #12]\n\t"
#else
        "ldrd	r2, r3, [sp, #8]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [sp, #56]\n\t"
        "ldr	r5, [sp, #60]\n\t"
#else
        "ldrd	r4, r5, [sp, #56]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [sp, #104]\n\t"
        "ldr	r7, [sp, #108]\n\t"
#else
        "ldrd	r6, r7, [sp, #104]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [sp, #152]\n\t"
        "ldr	r9, [sp, #156]\n\t"
#else
        "ldrd	r8, r9, [sp, #152]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [sp, #160]\n\t"
        "ldr	r11, [sp, #164]\n\t"
#else
        "ldrd	r10, r11, [sp, #160]\n\t"
#endif
        /* s[0] <<< 1 */
        "lsr	r12, r3, #31\n\t"
        "lsr	lr, r2, #31\n\t"
        "orr	r2, r12, r2, lsl #1\n\t"
        "orr	r3, lr, r3, lsl #1\n\t"
        /* s[1] <<< 6 */
        "lsr	r12, r5, #26\n\t"
        "lsr	lr, r4, #26\n\t"
        "orr	r4, r12, r4, lsl #6\n\t"
        "orr	r5, lr, r5, lsl #6\n\t"
        /* s[2] <<< 25 */
        "lsr	r12, r7, #7\n\t"
        "lsr	lr, r6, #7\n\t"
        "orr	r6, r12, r6, lsl #25\n\t"
        "orr	r7, lr, r7, lsl #25\n\t"
        /* s[3] <<< 8 */
        "lsr	r12, r9, #24\n\t"
        "lsr	lr, r8, #24\n\t"
        "orr	r8, r12, r8, lsl #8\n\t"
        "orr	r9, lr, r9, lsl #8\n\t"
        /* s[4] <<< 18 */
        "lsr	r12, r11, #14\n\t"
        "lsr	lr, r10, #14\n\t"
        "orr	r10, r12, r10, lsl #18\n\t"
        "orr	r11, lr, r11, lsl #18\n\t"
        "bic	r12, r8, r6\n\t"
        "bic	lr, r9, r7\n\t"
        "eor	r12, r12, r4\n\t"
        "eor	lr, lr, r5\n\t"
        "str	r12, [%[state], #88]\n\t"
        "str	lr, [%[state], #92]\n\t"
        "bic	r12, r10, r8\n\t"
        "bic	lr, r11, r9\n\t"
        "eor	r12, r12, r6\n\t"
        "eor	lr, lr, r7\n\t"
        "str	r12, [%[state], #96]\n\t"
        "str	lr, [%[state], #100]\n\t"
        "bic	r12, r2, r10\n\t"
        "bic	lr, r3, r11\n\t"
        "eor	r12, r12, r8\n\t"
        "eor	lr, lr, r9\n\t"
        "str	r12, [%[state], #104]\n\t"
        "str	lr, [%[state], #108]\n\t"
        "bic	r12, r4, r2\n\t"
        "bic	lr, r5, r3\n\t"
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "str	r12, [%[state], #112]\n\t"
        "str	lr, [%[state], #116]\n\t"
        "bic	r12, r6, r4\n\t"
        "bic	lr, r7, r5\n\t"
        "eor	r12, r12, r2\n\t"
        "eor	lr, lr, r3\n\t"
        "str	r12, [%[state], #80]\n\t"
        "str	lr, [%[state], #84]\n\t"
        /* Row 3 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [sp, #32]\n\t"
        "ldr	r3, [sp, #36]\n\t"
#else
        "ldrd	r2, r3, [sp, #32]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [sp, #40]\n\t"
        "ldr	r5, [sp, #44]\n\t"
#else
        "ldrd	r4, r5, [sp, #40]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [sp, #88]\n\t"
        "ldr	r7, [sp, #92]\n\t"
#else
        "ldrd	r6, r7, [sp, #88]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [sp, #136]\n\t"
        "ldr	r9, [sp, #140]\n\t"
#else
        "ldrd	r8, r9, [sp, #136]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [sp, #184]\n\t"
        "ldr	r11, [sp, #188]\n\t"
#else
        "ldrd	r10, r11, [sp, #184]\n\t"
#endif
        /* s[0] <<< 27 */
        "lsr	r12, r3, #5\n\t"
        "lsr	lr, r2, #5\n\t"
        "orr	r2, r12, r2, lsl #27\n\t"
        "orr	r3, lr, r3, lsl #27\n\t"
        /* s[1] <<< 36 */
        "mov	lr, r4\n\t"
        "lsr	r12, r5, #28\n\t"
        "lsr	r4, r4, #28\n\t"
        "orr	r4, r4, r5, lsl #4\n\t"
        "orr	r5, r12, lr, lsl #4\n\t"
        /* s[2] <<< 10 */
        "lsr	r12, r7, #22\n\t"
        "lsr	lr, r6, #22\n\t"
        "orr	r6, r12, r6, lsl #10\n\t"
        "orr	r7, lr, r7, lsl #10\n\t"
        /* s[3] <<< 15 */
        "lsr	r12, r9, #17\n\t"
        "lsr	lr, r8, #17\n\t"
        "orr	r8, r12, r8, lsl #15\n\t"
        "orr	r9, lr, r9, lsl #15\n\t"
        /* s[4] <<< 56 */
        "mov	lr, r10\n\t"
        "lsr	r12, r11, #8\n\t"
        "lsr	r10, r10, #8\n\t"
        "orr	r10, r10, r11, lsl #24\n\t"
        "orr	r11, r12, lr, lsl #24\n\t"
        "bic	r12, r8, r6\n\t"
        "bic	lr, r9, r7\n\t"
        "eor	r12, r12, r4\n\t"
        "eor	lr, lr, r5\n\t"
        "str	r12, [%[state], #128]\n\t"
        "str	lr, [%[state], #132]\n\t"
        "bic	r12, r10, r8\n\t"
        "bic	lr, r11, r9\n\t"
        "eor	r12, r12, r6\n\t"
        "eor	lr, lr, r7\n\t"
        "str	r12, [%[state], #136]\n\t"
        "str	lr, [%[state], #140]\n\t"
        "bic	r12, r2, r10\n\t"
        "bic	lr, r3, r11\n\t"
        "eor	r12, r12, r8\n\t"
        "eor	lr, lr, r9\n\t"
        "str	r12, [%[state], #144]\n\t"
        "str	lr, [%[state], #148]\n\t"
        "bic	r12, r4, r2\n\t"
        "bic	lr, r5, r3\n\t"
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "str	r12, [%[state], #152]\n\t"
        "str	lr, [%[state], #156]\n\t"
        "bic	r12, r6, r4\n\t"
        "bic	lr, r7, r5\n\t"
        "eor	r12, r12, r2\n\t"
        "eor	lr, lr, r3\n\t"
        "str	r12, [%[state], #120]\n\t"
        "str	lr, [%[state], #124]\n\t"
        /* Row 4 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [sp, #16]\n\t"
        "ldr	r3, [sp, #20]\n\t"
#else
        "ldrd	r2, r3, [sp, #16]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r4, [sp, #64]\n\t"
        "ldr	r5, [sp, #68]\n\t"
#else
        "ldrd	r4, r5, [sp, #64]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r6, [sp, #112]\n\t"
        "ldr	r7, [sp, #116]\n\t"
#else
        "ldrd	r6, r7, [sp, #112]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r8, [sp, #120]\n\t"
        "ldr	r9, [sp, #124]\n\t"
#else
        "ldrd	r8, r9, [sp, #120]\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r10, [sp, #168]\n\t"
        "ldr	r11, [sp, #172]\n\t"
#else
        "ldrd	r10, r11, [sp, #168]\n\t"
#endif
        /* s[0] <<< 62 */
        "mov	lr, r2\n\t"
        "lsr	r12, r3, #2\n\t"
        "lsr	r2, r2, #2\n\t"
        "orr	r2, r2, r3, lsl #30\n\t"
        "orr	r3, r12, lr, lsl #30\n\t"
        /* s[1] <<< 55 */
        "mov	lr, r4\n\t"
        "lsr	r12, r5, #9\n\t"
        "lsr	r4, r4, #9\n\t"
        "orr	r4, r4, r5, lsl #23\n\t"
        "orr	r5, r12, lr, lsl #23\n\t"
        /* s[2] <<< 39 */
        "mov	lr, r6\n\t"
        "lsr	r12, r7, #25\n\t"
        "lsr	r6, r6, #25\n\t"
        "orr	r6, r6, r7, lsl #7\n\t"
        "orr	r7, r12, lr, lsl #7\n\t"
        /* s[3] <<< 41 */
        "mov	lr, r8\n\t"
        "lsr	r12, r9, #23\n\t"
        "lsr	r8, r8, #23\n\t"
        "orr	r8, r8, r9, lsl #9\n\t"
        "orr	r9, r12, lr, lsl #9\n\t"
        /* s[4] <<< 2 */
        "lsr	r12, r11, #30\n\t"
        "lsr	lr, r10, #30\n\t"
        "orr	r10, r12, r10, lsl #2\n\t"
        "orr	r11, lr, r11, lsl #2\n\t"
        "bic	r12, r8, r6\n\t"
        "bic	lr, r9, r7\n\t"
        "eor	r12, r12, r4\n\t"
        "eor	lr, lr, r5\n\t"
        "str	r12, [%[state], #168]\n\t"
        "str	lr, [%[state], #172]\n\t"
        "bic	r12, r10, r8\n\t"
        "bic	lr, r11, r9\n\t"
        "eor	r12, r12, r6\n\t"
        "eor	lr, lr, r7\n\t"
        "str	r12, [%[state], #176]\n\t"
        "str	lr, [%[state], #180]\n\t"
        "bic	r12, r2, r10\n\t"
        "bic	lr, r3, r11\n\t"
        "eor	r12, r12, r8\n\t"
        "eor	lr, lr, r9\n\t"
        "str	r12, [%[state], #184]\n\t"
        "str	lr, [%[state], #188]\n\t"
        "bic	r12, r4, r2\n\t"
        "bic	lr, r5, r3\n\t"
        "eor	r12, r12, r10\n\t"
        "eor	lr, lr, r11\n\t"
        "str	r12, [%[state], #192]\n\t"
        "str	lr, [%[state], #196]\n\t"
        "bic	r12, r6, r4\n\t"
        "bic	lr, r7, r5\n\t"
        "eor	r12, r12, r2\n\t"
        "eor	lr, lr, r3\n\t"
        "str	r12, [%[state], #160]\n\t"
        "str	lr, [%[state], #164]\n\t"
        "ldr	r2, [sp, #200]\n\t"
        "subs	r2, r2, #1\n\t"
        "bne	L_sha3_arm32_begin_%=\n\t"
        "add	sp, sp, #0xcc\n\t"
        : [state] "+r" (state), [L_sha3_arm2_rt] "+r" (L_sha3_arm2_rt_c)
        :
        : "memory", "cc", "r2", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8",
            "r9", "r10", "r11"
    );
}

#endif /* WOLFSSL_ARMASM_NO_NEON */
#endif /* WOLFSSL_SHA3 */
#endif /* !__aarch64__ && !WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#endif /* WOLFSSL_ARMASM_INLINE */
