/* armv8-32-kyber-asm
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
 *   ruby ./kyber/kyber.rb arm32 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-32-kyber-asm.c
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
#include <wolfssl/wolfcrypt/wc_kyber.h>

#ifdef WOLFSSL_WC_KYBER
static const word16 L_kyber_arm32_ntt_zetas[] = {
    0x08ed, 0x0a0b, 0x0b9a, 0x0714,
    0x05d5, 0x058e, 0x011f, 0x00ca,
    0x0c56, 0x026e, 0x0629, 0x00b6,
    0x03c2, 0x084f, 0x073f, 0x05bc,
    0x023d, 0x07d4, 0x0108, 0x017f,
    0x09c4, 0x05b2, 0x06bf, 0x0c7f,
    0x0a58, 0x03f9, 0x02dc, 0x0260,
    0x06fb, 0x019b, 0x0c34, 0x06de,
    0x04c7, 0x028c, 0x0ad9, 0x03f7,
    0x07f4, 0x05d3, 0x0be7, 0x06f9,
    0x0204, 0x0cf9, 0x0bc1, 0x0a67,
    0x06af, 0x0877, 0x007e, 0x05bd,
    0x09ac, 0x0ca7, 0x0bf2, 0x033e,
    0x006b, 0x0774, 0x0c0a, 0x094a,
    0x0b73, 0x03c1, 0x071d, 0x0a2c,
    0x01c0, 0x08d8, 0x02a5, 0x0806,
    0x08b2, 0x01ae, 0x022b, 0x034b,
    0x081e, 0x0367, 0x060e, 0x0069,
    0x01a6, 0x024b, 0x00b1, 0x0c16,
    0x0bde, 0x0b35, 0x0626, 0x0675,
    0x0c0b, 0x030a, 0x0487, 0x0c6e,
    0x09f8, 0x05cb, 0x0aa7, 0x045f,
    0x06cb, 0x0284, 0x0999, 0x015d,
    0x01a2, 0x0149, 0x0c65, 0x0cb6,
    0x0331, 0x0449, 0x025b, 0x0262,
    0x052a, 0x07fc, 0x0748, 0x0180,
    0x0842, 0x0c79, 0x04c2, 0x07ca,
    0x0997, 0x00dc, 0x085e, 0x0686,
    0x0860, 0x0707, 0x0803, 0x031a,
    0x071b, 0x09ab, 0x099b, 0x01de,
    0x0c95, 0x0bcd, 0x03e4, 0x03df,
    0x03be, 0x074d, 0x05f2, 0x065c,
};

void kyber_arm32_ntt(sword16* r_p)
{
    register sword16* r asm ("r0") = (sword16*)r_p;
    register word16* L_kyber_arm32_ntt_zetas_c asm ("r1") =
        (word16*)&L_kyber_arm32_ntt_zetas;

    __asm__ __volatile__ (
        "sub	sp, sp, #8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "orr	r10, r10, #0xc000000\n\t"
        "orr	r10, r10, #0xff0000\n\t"
#else
        "movt	r10, #0xcff\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "mov	r2, #16\n\t"
        "\n"
    "L_kyber_arm32_ntt_loop_123_%=: \n\t"
        "str	r2, [sp]\n\t"
        "ldrh	r11, [r1, #2]\n\t"
        "ldr	r2, [%[r]]\n\t"
        "ldr	r3, [%[r], #64]\n\t"
        "ldr	r4, [%[r], #128]\n\t"
        "ldr	r5, [%[r], #192]\n\t"
        "ldr	r6, [%[r], #256]\n\t"
        "ldr	r7, [%[r], #320]\n\t"
        "ldr	r8, [%[r], #384]\n\t"
        "ldr	r9, [%[r], #448]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r6\n\t"
        "smulbt	r6, r11, r6\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r6\n\t"
        "smlabb	lr, r10, lr, r6\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r6, r2, r12\n\t"
        "sadd16	r2, r2, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r6, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r6, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r6, r6, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r6, lr, r6\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r6, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r6, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r6\n\t"
        "sub	r6, r2, lr\n\t"
        "add	r2, r2, lr\n\t"
        "sub	lr, r2, r12, lsr #16\n\t"
        "add	r12, r2, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
        "ror	r6, r6, #16\n\t"
        "orr	r6, r6, lr, lsl #16\n\t"
        "ror	r6, r6, #16\n\t"
#else
        "bfi	r6, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
        "ror	r2, r2, #16\n\t"
        "orr	r2, r2, r12, lsl #16\n\t"
        "ror	r2, r2, #16\n\t"
#else
        "bfi	r2, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r7\n\t"
        "smulbt	r7, r11, r7\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r7\n\t"
        "smlabb	lr, r10, lr, r7\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r7, r3, r12\n\t"
        "sadd16	r3, r3, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r7, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r7, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r7, r7, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r7, lr, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r7, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r7, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r7\n\t"
        "sub	r7, r3, lr\n\t"
        "add	r3, r3, lr\n\t"
        "sub	lr, r3, r12, lsr #16\n\t"
        "add	r12, r3, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
        "ror	r7, r7, #16\n\t"
        "orr	r7, r7, lr, lsl #16\n\t"
        "ror	r7, r7, #16\n\t"
#else
        "bfi	r7, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
        "ror	r3, r3, #16\n\t"
        "orr	r3, r3, r12, lsl #16\n\t"
        "ror	r3, r3, #16\n\t"
#else
        "bfi	r3, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r8\n\t"
        "smulbt	r8, r11, r8\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r8\n\t"
        "smlabb	lr, r10, lr, r8\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r8, r4, r12\n\t"
        "sadd16	r4, r4, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r8, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r8, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r8, r8, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r8, lr, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r8, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r8, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r8\n\t"
        "sub	r8, r4, lr\n\t"
        "add	r4, r4, lr\n\t"
        "sub	lr, r4, r12, lsr #16\n\t"
        "add	r12, r4, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
        "ror	r8, r8, #16\n\t"
        "orr	r8, r8, lr, lsl #16\n\t"
        "ror	r8, r8, #16\n\t"
#else
        "bfi	r8, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
        "ror	r4, r4, #16\n\t"
        "orr	r4, r4, r12, lsl #16\n\t"
        "ror	r4, r4, #16\n\t"
#else
        "bfi	r4, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r9\n\t"
        "smulbt	r9, r11, r9\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r9\n\t"
        "smlabb	lr, r10, lr, r9\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r9, r5, r12\n\t"
        "sadd16	r5, r5, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r9, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r9, r9, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r9, lr, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r9, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r9, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r9\n\t"
        "sub	r9, r5, lr\n\t"
        "add	r5, r5, lr\n\t"
        "sub	lr, r5, r12, lsr #16\n\t"
        "add	r12, r5, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
        "ror	r9, r9, #16\n\t"
        "orr	r9, r9, lr, lsl #16\n\t"
        "ror	r9, r9, #16\n\t"
#else
        "bfi	r9, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
        "ror	r5, r5, #16\n\t"
        "orr	r5, r5, r12, lsl #16\n\t"
        "ror	r5, r5, #16\n\t"
#else
        "bfi	r5, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "ldr	r11, [r1, #4]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r4\n\t"
        "smulbt	r4, r11, r4\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r4\n\t"
        "smlabb	lr, r10, lr, r4\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r4, r2, r12\n\t"
        "sadd16	r2, r2, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r4, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r4, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r4, r4, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r4, lr, r4\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r4, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r4, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r4\n\t"
        "sub	r4, r2, lr\n\t"
        "add	r2, r2, lr\n\t"
        "sub	lr, r2, r12, lsr #16\n\t"
        "add	r12, r2, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
        "ror	r4, r4, #16\n\t"
        "orr	r4, r4, lr, lsl #16\n\t"
        "ror	r4, r4, #16\n\t"
#else
        "bfi	r4, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
        "ror	r2, r2, #16\n\t"
        "orr	r2, r2, r12, lsl #16\n\t"
        "ror	r2, r2, #16\n\t"
#else
        "bfi	r2, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r5\n\t"
        "smulbt	r5, r11, r5\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r5\n\t"
        "smlabb	lr, r10, lr, r5\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r5, r3, r12\n\t"
        "sadd16	r3, r3, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r5, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r5, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r5, r5, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r5, lr, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r5, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r5, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r5\n\t"
        "sub	r5, r3, lr\n\t"
        "add	r3, r3, lr\n\t"
        "sub	lr, r3, r12, lsr #16\n\t"
        "add	r12, r3, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
        "ror	r5, r5, #16\n\t"
        "orr	r5, r5, lr, lsl #16\n\t"
        "ror	r5, r5, #16\n\t"
#else
        "bfi	r5, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
        "ror	r3, r3, #16\n\t"
        "orr	r3, r3, r12, lsl #16\n\t"
        "ror	r3, r3, #16\n\t"
#else
        "bfi	r3, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smultb	r12, r11, r8\n\t"
        "smultt	r8, r11, r8\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r8\n\t"
        "smlabb	lr, r10, lr, r8\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r8, r6, r12\n\t"
        "sadd16	r6, r6, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r8, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r8, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r8, r8, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r8, lr, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r8, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r8, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r8\n\t"
        "sub	r8, r6, lr\n\t"
        "add	r6, r6, lr\n\t"
        "sub	lr, r6, r12, lsr #16\n\t"
        "add	r12, r6, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
        "ror	r8, r8, #16\n\t"
        "orr	r8, r8, lr, lsl #16\n\t"
        "ror	r8, r8, #16\n\t"
#else
        "bfi	r8, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
        "ror	r6, r6, #16\n\t"
        "orr	r6, r6, r12, lsl #16\n\t"
        "ror	r6, r6, #16\n\t"
#else
        "bfi	r6, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smultb	r12, r11, r9\n\t"
        "smultt	r9, r11, r9\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r9\n\t"
        "smlabb	lr, r10, lr, r9\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r9, r7, r12\n\t"
        "sadd16	r7, r7, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r9, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r9, r9, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r9, lr, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r9, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r9, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r9\n\t"
        "sub	r9, r7, lr\n\t"
        "add	r7, r7, lr\n\t"
        "sub	lr, r7, r12, lsr #16\n\t"
        "add	r12, r7, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
        "ror	r9, r9, #16\n\t"
        "orr	r9, r9, lr, lsl #16\n\t"
        "ror	r9, r9, #16\n\t"
#else
        "bfi	r9, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
        "ror	r7, r7, #16\n\t"
        "orr	r7, r7, r12, lsl #16\n\t"
        "ror	r7, r7, #16\n\t"
#else
        "bfi	r7, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "ldr	r11, [r1, #8]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r3\n\t"
        "smulbt	r3, r11, r3\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r3\n\t"
        "smlabb	lr, r10, lr, r3\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r3, r2, r12\n\t"
        "sadd16	r2, r2, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r3, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r3, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r3, r3, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r3, lr, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r3, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r3, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r3\n\t"
        "sub	r3, r2, lr\n\t"
        "add	r2, r2, lr\n\t"
        "sub	lr, r2, r12, lsr #16\n\t"
        "add	r12, r2, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
        "ror	r3, r3, #16\n\t"
        "orr	r3, r3, lr, lsl #16\n\t"
        "ror	r3, r3, #16\n\t"
#else
        "bfi	r3, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
        "ror	r2, r2, #16\n\t"
        "orr	r2, r2, r12, lsl #16\n\t"
        "ror	r2, r2, #16\n\t"
#else
        "bfi	r2, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smultb	r12, r11, r5\n\t"
        "smultt	r5, r11, r5\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r5\n\t"
        "smlabb	lr, r10, lr, r5\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r5, r4, r12\n\t"
        "sadd16	r4, r4, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r5, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r5, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r5, r5, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r5, lr, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r5, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r5, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r5\n\t"
        "sub	r5, r4, lr\n\t"
        "add	r4, r4, lr\n\t"
        "sub	lr, r4, r12, lsr #16\n\t"
        "add	r12, r4, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
        "ror	r5, r5, #16\n\t"
        "orr	r5, r5, lr, lsl #16\n\t"
        "ror	r5, r5, #16\n\t"
#else
        "bfi	r5, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
        "ror	r4, r4, #16\n\t"
        "orr	r4, r4, r12, lsl #16\n\t"
        "ror	r4, r4, #16\n\t"
#else
        "bfi	r4, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "ldr	r11, [r1, #12]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r7\n\t"
        "smulbt	r7, r11, r7\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r7\n\t"
        "smlabb	lr, r10, lr, r7\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r7, r6, r12\n\t"
        "sadd16	r6, r6, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r7, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r7, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r7, r7, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r7, lr, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r7, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r7, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r7\n\t"
        "sub	r7, r6, lr\n\t"
        "add	r6, r6, lr\n\t"
        "sub	lr, r6, r12, lsr #16\n\t"
        "add	r12, r6, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
        "ror	r7, r7, #16\n\t"
        "orr	r7, r7, lr, lsl #16\n\t"
        "ror	r7, r7, #16\n\t"
#else
        "bfi	r7, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
        "ror	r6, r6, #16\n\t"
        "orr	r6, r6, r12, lsl #16\n\t"
        "ror	r6, r6, #16\n\t"
#else
        "bfi	r6, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smultb	r12, r11, r9\n\t"
        "smultt	r9, r11, r9\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r9\n\t"
        "smlabb	lr, r10, lr, r9\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r9, r8, r12\n\t"
        "sadd16	r8, r8, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r9, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r9, r9, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r9, lr, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r9, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r9, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r9\n\t"
        "sub	r9, r8, lr\n\t"
        "add	r8, r8, lr\n\t"
        "sub	lr, r8, r12, lsr #16\n\t"
        "add	r12, r8, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
        "ror	r9, r9, #16\n\t"
        "orr	r9, r9, lr, lsl #16\n\t"
        "ror	r9, r9, #16\n\t"
#else
        "bfi	r9, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
        "ror	r8, r8, #16\n\t"
        "orr	r8, r8, r12, lsl #16\n\t"
        "ror	r8, r8, #16\n\t"
#else
        "bfi	r8, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "str	r2, [%[r]]\n\t"
        "str	r3, [%[r], #64]\n\t"
        "str	r4, [%[r], #128]\n\t"
        "str	r5, [%[r], #192]\n\t"
        "str	r6, [%[r], #256]\n\t"
        "str	r7, [%[r], #320]\n\t"
        "str	r8, [%[r], #384]\n\t"
        "str	r9, [%[r], #448]\n\t"
        "ldr	r2, [sp]\n\t"
        "subs	r2, r2, #1\n\t"
        "add	%[r], %[r], #4\n\t"
        "bne	L_kyber_arm32_ntt_loop_123_%=\n\t"
        "sub	%[r], %[r], #0x40\n\t"
        "mov	r3, #0\n\t"
        "\n"
    "L_kyber_arm32_ntt_loop_4_j_%=: \n\t"
        "str	r3, [sp, #4]\n\t"
        "add	r11, r1, r3, lsr #4\n\t"
        "mov	r2, #4\n\t"
        "ldr	r11, [r11, #16]\n\t"
        "\n"
    "L_kyber_arm32_ntt_loop_4_i_%=: \n\t"
        "str	r2, [sp]\n\t"
        "ldr	r2, [%[r]]\n\t"
        "ldr	r3, [%[r], #16]\n\t"
        "ldr	r4, [%[r], #32]\n\t"
        "ldr	r5, [%[r], #48]\n\t"
        "ldr	r6, [%[r], #64]\n\t"
        "ldr	r7, [%[r], #80]\n\t"
        "ldr	r8, [%[r], #96]\n\t"
        "ldr	r9, [%[r], #112]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r4\n\t"
        "smulbt	r4, r11, r4\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r4\n\t"
        "smlabb	lr, r10, lr, r4\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r4, r2, r12\n\t"
        "sadd16	r2, r2, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r4, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r4, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r4, r4, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r4, lr, r4\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r4, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r4, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r4\n\t"
        "sub	r4, r2, lr\n\t"
        "add	r2, r2, lr\n\t"
        "sub	lr, r2, r12, lsr #16\n\t"
        "add	r12, r2, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
        "ror	r4, r4, #16\n\t"
        "orr	r4, r4, lr, lsl #16\n\t"
        "ror	r4, r4, #16\n\t"
#else
        "bfi	r4, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
        "ror	r2, r2, #16\n\t"
        "orr	r2, r2, r12, lsl #16\n\t"
        "ror	r2, r2, #16\n\t"
#else
        "bfi	r2, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r5\n\t"
        "smulbt	r5, r11, r5\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r5\n\t"
        "smlabb	lr, r10, lr, r5\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r5, r3, r12\n\t"
        "sadd16	r3, r3, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r5, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r5, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r5, r5, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r5, lr, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r5, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r5, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r5\n\t"
        "sub	r5, r3, lr\n\t"
        "add	r3, r3, lr\n\t"
        "sub	lr, r3, r12, lsr #16\n\t"
        "add	r12, r3, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
        "ror	r5, r5, #16\n\t"
        "orr	r5, r5, lr, lsl #16\n\t"
        "ror	r5, r5, #16\n\t"
#else
        "bfi	r5, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
        "ror	r3, r3, #16\n\t"
        "orr	r3, r3, r12, lsl #16\n\t"
        "ror	r3, r3, #16\n\t"
#else
        "bfi	r3, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smultb	r12, r11, r8\n\t"
        "smultt	r8, r11, r8\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r8\n\t"
        "smlabb	lr, r10, lr, r8\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r8, r6, r12\n\t"
        "sadd16	r6, r6, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r8, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r8, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r8, r8, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r8, lr, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r8, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r8, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r8\n\t"
        "sub	r8, r6, lr\n\t"
        "add	r6, r6, lr\n\t"
        "sub	lr, r6, r12, lsr #16\n\t"
        "add	r12, r6, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
        "ror	r8, r8, #16\n\t"
        "orr	r8, r8, lr, lsl #16\n\t"
        "ror	r8, r8, #16\n\t"
#else
        "bfi	r8, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
        "ror	r6, r6, #16\n\t"
        "orr	r6, r6, r12, lsl #16\n\t"
        "ror	r6, r6, #16\n\t"
#else
        "bfi	r6, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smultb	r12, r11, r9\n\t"
        "smultt	r9, r11, r9\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r9\n\t"
        "smlabb	lr, r10, lr, r9\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r9, r7, r12\n\t"
        "sadd16	r7, r7, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r9, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r9, r9, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r9, lr, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r9, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r9, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r9\n\t"
        "sub	r9, r7, lr\n\t"
        "add	r7, r7, lr\n\t"
        "sub	lr, r7, r12, lsr #16\n\t"
        "add	r12, r7, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
        "ror	r9, r9, #16\n\t"
        "orr	r9, r9, lr, lsl #16\n\t"
        "ror	r9, r9, #16\n\t"
#else
        "bfi	r9, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
        "ror	r7, r7, #16\n\t"
        "orr	r7, r7, r12, lsl #16\n\t"
        "ror	r7, r7, #16\n\t"
#else
        "bfi	r7, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "str	r2, [%[r]]\n\t"
        "str	r3, [%[r], #16]\n\t"
        "str	r4, [%[r], #32]\n\t"
        "str	r5, [%[r], #48]\n\t"
        "str	r6, [%[r], #64]\n\t"
        "str	r7, [%[r], #80]\n\t"
        "str	r8, [%[r], #96]\n\t"
        "str	r9, [%[r], #112]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [sp]\n\t"
        "ldr	r3, [sp, #4]\n\t"
#else
        "ldrd	r2, r3, [sp]\n\t"
#endif
        "subs	r2, r2, #1\n\t"
        "add	%[r], %[r], #4\n\t"
        "bne	L_kyber_arm32_ntt_loop_4_i_%=\n\t"
        "add	r3, r3, #0x40\n\t"
        "rsbs	r12, r3, #0x100\n\t"
        "add	%[r], %[r], #0x70\n\t"
        "bne	L_kyber_arm32_ntt_loop_4_j_%=\n\t"
        "sub	%[r], %[r], #0x200\n\t"
        "mov	r3, #0\n\t"
        "\n"
    "L_kyber_arm32_ntt_loop_567_%=: \n\t"
        "add	r11, r1, r3, lsr #3\n\t"
        "str	r3, [sp, #4]\n\t"
        "ldrh	r11, [r11, #32]\n\t"
        "ldr	r2, [%[r]]\n\t"
        "ldr	r3, [%[r], #4]\n\t"
        "ldr	r4, [%[r], #8]\n\t"
        "ldr	r5, [%[r], #12]\n\t"
        "ldr	r6, [%[r], #16]\n\t"
        "ldr	r7, [%[r], #20]\n\t"
        "ldr	r8, [%[r], #24]\n\t"
        "ldr	r9, [%[r], #28]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r6\n\t"
        "smulbt	r6, r11, r6\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r6\n\t"
        "smlabb	lr, r10, lr, r6\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r6, r2, r12\n\t"
        "sadd16	r2, r2, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r6, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r6, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r6, r6, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r6, lr, r6\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r6, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r6, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r6\n\t"
        "sub	r6, r2, lr\n\t"
        "add	r2, r2, lr\n\t"
        "sub	lr, r2, r12, lsr #16\n\t"
        "add	r12, r2, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
        "ror	r6, r6, #16\n\t"
        "orr	r6, r6, lr, lsl #16\n\t"
        "ror	r6, r6, #16\n\t"
#else
        "bfi	r6, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
        "ror	r2, r2, #16\n\t"
        "orr	r2, r2, r12, lsl #16\n\t"
        "ror	r2, r2, #16\n\t"
#else
        "bfi	r2, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r7\n\t"
        "smulbt	r7, r11, r7\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r7\n\t"
        "smlabb	lr, r10, lr, r7\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r7, r3, r12\n\t"
        "sadd16	r3, r3, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r7, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r7, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r7, r7, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r7, lr, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r7, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r7, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r7\n\t"
        "sub	r7, r3, lr\n\t"
        "add	r3, r3, lr\n\t"
        "sub	lr, r3, r12, lsr #16\n\t"
        "add	r12, r3, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
        "ror	r7, r7, #16\n\t"
        "orr	r7, r7, lr, lsl #16\n\t"
        "ror	r7, r7, #16\n\t"
#else
        "bfi	r7, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
        "ror	r3, r3, #16\n\t"
        "orr	r3, r3, r12, lsl #16\n\t"
        "ror	r3, r3, #16\n\t"
#else
        "bfi	r3, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r8\n\t"
        "smulbt	r8, r11, r8\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r8\n\t"
        "smlabb	lr, r10, lr, r8\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r8, r4, r12\n\t"
        "sadd16	r4, r4, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r8, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r8, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r8, r8, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r8, lr, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r8, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r8, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r8\n\t"
        "sub	r8, r4, lr\n\t"
        "add	r4, r4, lr\n\t"
        "sub	lr, r4, r12, lsr #16\n\t"
        "add	r12, r4, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
        "ror	r8, r8, #16\n\t"
        "orr	r8, r8, lr, lsl #16\n\t"
        "ror	r8, r8, #16\n\t"
#else
        "bfi	r8, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
        "ror	r4, r4, #16\n\t"
        "orr	r4, r4, r12, lsl #16\n\t"
        "ror	r4, r4, #16\n\t"
#else
        "bfi	r4, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r9\n\t"
        "smulbt	r9, r11, r9\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r9\n\t"
        "smlabb	lr, r10, lr, r9\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r9, r5, r12\n\t"
        "sadd16	r5, r5, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r9, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r9, r9, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r9, lr, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r9, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r9, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r9\n\t"
        "sub	r9, r5, lr\n\t"
        "add	r5, r5, lr\n\t"
        "sub	lr, r5, r12, lsr #16\n\t"
        "add	r12, r5, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
        "ror	r9, r9, #16\n\t"
        "orr	r9, r9, lr, lsl #16\n\t"
        "ror	r9, r9, #16\n\t"
#else
        "bfi	r9, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
        "ror	r5, r5, #16\n\t"
        "orr	r5, r5, r12, lsl #16\n\t"
        "ror	r5, r5, #16\n\t"
#else
        "bfi	r5, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "ldr	r11, [sp, #4]\n\t"
        "add	r11, r1, r11, lsr #2\n\t"
        "ldr	r11, [r11, #64]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r4\n\t"
        "smulbt	r4, r11, r4\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r4\n\t"
        "smlabb	lr, r10, lr, r4\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r4, r2, r12\n\t"
        "sadd16	r2, r2, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r4, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r4, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r4, r4, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r4, lr, r4\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r4, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r4, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r4\n\t"
        "sub	r4, r2, lr\n\t"
        "add	r2, r2, lr\n\t"
        "sub	lr, r2, r12, lsr #16\n\t"
        "add	r12, r2, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
        "ror	r4, r4, #16\n\t"
        "orr	r4, r4, lr, lsl #16\n\t"
        "ror	r4, r4, #16\n\t"
#else
        "bfi	r4, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
        "ror	r2, r2, #16\n\t"
        "orr	r2, r2, r12, lsl #16\n\t"
        "ror	r2, r2, #16\n\t"
#else
        "bfi	r2, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r5\n\t"
        "smulbt	r5, r11, r5\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r5\n\t"
        "smlabb	lr, r10, lr, r5\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r5, r3, r12\n\t"
        "sadd16	r3, r3, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r5, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r5, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r5, r5, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r5, lr, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r5, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r5, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r5\n\t"
        "sub	r5, r3, lr\n\t"
        "add	r3, r3, lr\n\t"
        "sub	lr, r3, r12, lsr #16\n\t"
        "add	r12, r3, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
        "ror	r5, r5, #16\n\t"
        "orr	r5, r5, lr, lsl #16\n\t"
        "ror	r5, r5, #16\n\t"
#else
        "bfi	r5, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
        "ror	r3, r3, #16\n\t"
        "orr	r3, r3, r12, lsl #16\n\t"
        "ror	r3, r3, #16\n\t"
#else
        "bfi	r3, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smultb	r12, r11, r8\n\t"
        "smultt	r8, r11, r8\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r8\n\t"
        "smlabb	lr, r10, lr, r8\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r8, r6, r12\n\t"
        "sadd16	r6, r6, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r8, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r8, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r8, r8, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r8, lr, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r8, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r8, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r8\n\t"
        "sub	r8, r6, lr\n\t"
        "add	r6, r6, lr\n\t"
        "sub	lr, r6, r12, lsr #16\n\t"
        "add	r12, r6, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
        "ror	r8, r8, #16\n\t"
        "orr	r8, r8, lr, lsl #16\n\t"
        "ror	r8, r8, #16\n\t"
#else
        "bfi	r8, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
        "ror	r6, r6, #16\n\t"
        "orr	r6, r6, r12, lsl #16\n\t"
        "ror	r6, r6, #16\n\t"
#else
        "bfi	r6, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smultb	r12, r11, r9\n\t"
        "smultt	r9, r11, r9\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r9\n\t"
        "smlabb	lr, r10, lr, r9\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r9, r7, r12\n\t"
        "sadd16	r7, r7, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r9, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r9, r9, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r9, lr, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r9, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r9, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r9\n\t"
        "sub	r9, r7, lr\n\t"
        "add	r7, r7, lr\n\t"
        "sub	lr, r7, r12, lsr #16\n\t"
        "add	r12, r7, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
        "ror	r9, r9, #16\n\t"
        "orr	r9, r9, lr, lsl #16\n\t"
        "ror	r9, r9, #16\n\t"
#else
        "bfi	r9, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
        "ror	r7, r7, #16\n\t"
        "orr	r7, r7, r12, lsl #16\n\t"
        "ror	r7, r7, #16\n\t"
#else
        "bfi	r7, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "ldr	r11, [sp, #4]\n\t"
        "add	r11, r1, r11, lsr #1\n\t"
        "ldr	r11, [r11, #128]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r3\n\t"
        "smulbt	r3, r11, r3\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r3\n\t"
        "smlabb	lr, r10, lr, r3\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r3, r2, r12\n\t"
        "sadd16	r2, r2, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r3, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r3, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r3, r3, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r3, lr, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r3, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r3, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r3\n\t"
        "sub	r3, r2, lr\n\t"
        "add	r2, r2, lr\n\t"
        "sub	lr, r2, r12, lsr #16\n\t"
        "add	r12, r2, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
        "ror	r3, r3, #16\n\t"
        "orr	r3, r3, lr, lsl #16\n\t"
        "ror	r3, r3, #16\n\t"
#else
        "bfi	r3, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
        "ror	r2, r2, #16\n\t"
        "orr	r2, r2, r12, lsl #16\n\t"
        "ror	r2, r2, #16\n\t"
#else
        "bfi	r2, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smultb	r12, r11, r5\n\t"
        "smultt	r5, r11, r5\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r5\n\t"
        "smlabb	lr, r10, lr, r5\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r5, r4, r12\n\t"
        "sadd16	r4, r4, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r5, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r5, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r5, r5, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r5, lr, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r5, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r5, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r5\n\t"
        "sub	r5, r4, lr\n\t"
        "add	r4, r4, lr\n\t"
        "sub	lr, r4, r12, lsr #16\n\t"
        "add	r12, r4, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
        "ror	r5, r5, #16\n\t"
        "orr	r5, r5, lr, lsl #16\n\t"
        "ror	r5, r5, #16\n\t"
#else
        "bfi	r5, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
        "ror	r4, r4, #16\n\t"
        "orr	r4, r4, r12, lsl #16\n\t"
        "ror	r4, r4, #16\n\t"
#else
        "bfi	r4, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "ldr	r11, [sp, #4]\n\t"
        "add	r11, r1, r11, lsr #1\n\t"
        "ldr	r11, [r11, #132]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r7\n\t"
        "smulbt	r7, r11, r7\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r7\n\t"
        "smlabb	lr, r10, lr, r7\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r7, r6, r12\n\t"
        "sadd16	r6, r6, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r7, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r7, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r7, r7, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r7, lr, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r7, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r7, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r7\n\t"
        "sub	r7, r6, lr\n\t"
        "add	r6, r6, lr\n\t"
        "sub	lr, r6, r12, lsr #16\n\t"
        "add	r12, r6, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
        "ror	r7, r7, #16\n\t"
        "orr	r7, r7, lr, lsl #16\n\t"
        "ror	r7, r7, #16\n\t"
#else
        "bfi	r7, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
        "ror	r6, r6, #16\n\t"
        "orr	r6, r6, r12, lsl #16\n\t"
        "ror	r6, r6, #16\n\t"
#else
        "bfi	r6, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smultb	r12, r11, r9\n\t"
        "smultt	r9, r11, r9\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r9\n\t"
        "smlabb	lr, r10, lr, r9\n\t"
        "pkhtb	r12, lr, r12, ASR #16\n\t"
        "ssub16	r9, r8, r12\n\t"
        "sadd16	r8, r8, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r9, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r9, r9, #16\n\t"
        "mul	r12, lr, r12\n\t"
        "mul	r9, lr, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r9, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r9, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	lr, r10, lr, r9\n\t"
        "sub	r9, r8, lr\n\t"
        "add	r8, r8, lr\n\t"
        "sub	lr, r8, r12, lsr #16\n\t"
        "add	r12, r8, r12, lsr #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
        "ror	r9, r9, #16\n\t"
        "orr	r9, r9, lr, lsl #16\n\t"
        "ror	r9, r9, #16\n\t"
#else
        "bfi	r9, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
        "ror	r8, r8, #16\n\t"
        "orr	r8, r8, r12, lsl #16\n\t"
        "ror	r8, r8, #16\n\t"
#else
        "bfi	r8, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r11, #0xaf\n\t"
        "lsl	r11, r11, #8\n\t"
        "add	r11, r11, #0xc0\n\t"
#else
        "mov	r11, #0xafc0\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "orr	r11, r11, #0x130000\n\t"
#else
        "movt	r11, #0x13\n\t"
#endif
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r11, #0x4e\n\t"
        "lsl	r11, r11, #8\n\t"
        "add	r11, r11, #0xbf\n\t"
#else
        "mov	r11, #0x4ebf\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulwb	r12, r11, r2\n\t"
        "smulwt	lr, r11, r2\n\t"
        "smulbt	r12, r10, r12\n\t"
        "smulbt	lr, r10, lr\n\t"
        "pkhbt	r12, r12, lr, LSL #16\n\t"
        "ssub16	r2, r2, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r2, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r2, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r2, #16\n\t"
#else
        "sbfx	lr, r2, #16, #16\n\t"
#endif
        "mul	r12, r11, r12\n\t"
        "mul	lr, r11, lr\n\t"
        "asr	r12, r12, #26\n\t"
        "asr	lr, lr, #26\n\t"
        "mul	r12, r10, r12\n\t"
        "mul	lr, r10, lr\n\t"
        "sub	lr, r2, lr, lsl #16\n\t"
        "sub	r2, r2, r12\n\t"
        "lsr	lr, lr, #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff0000\n\t"
        "bic	r2, r2, #0xff000000\n\t"
        "orr	r2, r2, lr, lsl #16\n\t"
#else
        "bfi	r2, lr, #16, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulwb	r12, r11, r3\n\t"
        "smulwt	lr, r11, r3\n\t"
        "smulbt	r12, r10, r12\n\t"
        "smulbt	lr, r10, lr\n\t"
        "pkhbt	r12, r12, lr, LSL #16\n\t"
        "ssub16	r3, r3, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r3, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r3, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r3, #16\n\t"
#else
        "sbfx	lr, r3, #16, #16\n\t"
#endif
        "mul	r12, r11, r12\n\t"
        "mul	lr, r11, lr\n\t"
        "asr	r12, r12, #26\n\t"
        "asr	lr, lr, #26\n\t"
        "mul	r12, r10, r12\n\t"
        "mul	lr, r10, lr\n\t"
        "sub	lr, r3, lr, lsl #16\n\t"
        "sub	r3, r3, r12\n\t"
        "lsr	lr, lr, #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff0000\n\t"
        "bic	r3, r3, #0xff000000\n\t"
        "orr	r3, r3, lr, lsl #16\n\t"
#else
        "bfi	r3, lr, #16, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulwb	r12, r11, r4\n\t"
        "smulwt	lr, r11, r4\n\t"
        "smulbt	r12, r10, r12\n\t"
        "smulbt	lr, r10, lr\n\t"
        "pkhbt	r12, r12, lr, LSL #16\n\t"
        "ssub16	r4, r4, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r4, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r4, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r4, #16\n\t"
#else
        "sbfx	lr, r4, #16, #16\n\t"
#endif
        "mul	r12, r11, r12\n\t"
        "mul	lr, r11, lr\n\t"
        "asr	r12, r12, #26\n\t"
        "asr	lr, lr, #26\n\t"
        "mul	r12, r10, r12\n\t"
        "mul	lr, r10, lr\n\t"
        "sub	lr, r4, lr, lsl #16\n\t"
        "sub	r4, r4, r12\n\t"
        "lsr	lr, lr, #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff0000\n\t"
        "bic	r4, r4, #0xff000000\n\t"
        "orr	r4, r4, lr, lsl #16\n\t"
#else
        "bfi	r4, lr, #16, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulwb	r12, r11, r5\n\t"
        "smulwt	lr, r11, r5\n\t"
        "smulbt	r12, r10, r12\n\t"
        "smulbt	lr, r10, lr\n\t"
        "pkhbt	r12, r12, lr, LSL #16\n\t"
        "ssub16	r5, r5, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r5, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r5, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r5, #16\n\t"
#else
        "sbfx	lr, r5, #16, #16\n\t"
#endif
        "mul	r12, r11, r12\n\t"
        "mul	lr, r11, lr\n\t"
        "asr	r12, r12, #26\n\t"
        "asr	lr, lr, #26\n\t"
        "mul	r12, r10, r12\n\t"
        "mul	lr, r10, lr\n\t"
        "sub	lr, r5, lr, lsl #16\n\t"
        "sub	r5, r5, r12\n\t"
        "lsr	lr, lr, #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff0000\n\t"
        "bic	r5, r5, #0xff000000\n\t"
        "orr	r5, r5, lr, lsl #16\n\t"
#else
        "bfi	r5, lr, #16, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulwb	r12, r11, r6\n\t"
        "smulwt	lr, r11, r6\n\t"
        "smulbt	r12, r10, r12\n\t"
        "smulbt	lr, r10, lr\n\t"
        "pkhbt	r12, r12, lr, LSL #16\n\t"
        "ssub16	r6, r6, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r6, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r6, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r6, #16\n\t"
#else
        "sbfx	lr, r6, #16, #16\n\t"
#endif
        "mul	r12, r11, r12\n\t"
        "mul	lr, r11, lr\n\t"
        "asr	r12, r12, #26\n\t"
        "asr	lr, lr, #26\n\t"
        "mul	r12, r10, r12\n\t"
        "mul	lr, r10, lr\n\t"
        "sub	lr, r6, lr, lsl #16\n\t"
        "sub	r6, r6, r12\n\t"
        "lsr	lr, lr, #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff0000\n\t"
        "bic	r6, r6, #0xff000000\n\t"
        "orr	r6, r6, lr, lsl #16\n\t"
#else
        "bfi	r6, lr, #16, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulwb	r12, r11, r7\n\t"
        "smulwt	lr, r11, r7\n\t"
        "smulbt	r12, r10, r12\n\t"
        "smulbt	lr, r10, lr\n\t"
        "pkhbt	r12, r12, lr, LSL #16\n\t"
        "ssub16	r7, r7, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r7, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r7, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r7, #16\n\t"
#else
        "sbfx	lr, r7, #16, #16\n\t"
#endif
        "mul	r12, r11, r12\n\t"
        "mul	lr, r11, lr\n\t"
        "asr	r12, r12, #26\n\t"
        "asr	lr, lr, #26\n\t"
        "mul	r12, r10, r12\n\t"
        "mul	lr, r10, lr\n\t"
        "sub	lr, r7, lr, lsl #16\n\t"
        "sub	r7, r7, r12\n\t"
        "lsr	lr, lr, #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff0000\n\t"
        "bic	r7, r7, #0xff000000\n\t"
        "orr	r7, r7, lr, lsl #16\n\t"
#else
        "bfi	r7, lr, #16, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulwb	r12, r11, r8\n\t"
        "smulwt	lr, r11, r8\n\t"
        "smulbt	r12, r10, r12\n\t"
        "smulbt	lr, r10, lr\n\t"
        "pkhbt	r12, r12, lr, LSL #16\n\t"
        "ssub16	r8, r8, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r8, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r8, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r8, #16\n\t"
#else
        "sbfx	lr, r8, #16, #16\n\t"
#endif
        "mul	r12, r11, r12\n\t"
        "mul	lr, r11, lr\n\t"
        "asr	r12, r12, #26\n\t"
        "asr	lr, lr, #26\n\t"
        "mul	r12, r10, r12\n\t"
        "mul	lr, r10, lr\n\t"
        "sub	lr, r8, lr, lsl #16\n\t"
        "sub	r8, r8, r12\n\t"
        "lsr	lr, lr, #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff0000\n\t"
        "bic	r8, r8, #0xff000000\n\t"
        "orr	r8, r8, lr, lsl #16\n\t"
#else
        "bfi	r8, lr, #16, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulwb	r12, r11, r9\n\t"
        "smulwt	lr, r11, r9\n\t"
        "smulbt	r12, r10, r12\n\t"
        "smulbt	lr, r10, lr\n\t"
        "pkhbt	r12, r12, lr, LSL #16\n\t"
        "ssub16	r9, r9, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r9, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r9, #16\n\t"
#else
        "sbfx	lr, r9, #16, #16\n\t"
#endif
        "mul	r12, r11, r12\n\t"
        "mul	lr, r11, lr\n\t"
        "asr	r12, r12, #26\n\t"
        "asr	lr, lr, #26\n\t"
        "mul	r12, r10, r12\n\t"
        "mul	lr, r10, lr\n\t"
        "sub	lr, r9, lr, lsl #16\n\t"
        "sub	r9, r9, r12\n\t"
        "lsr	lr, lr, #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff0000\n\t"
        "bic	r9, r9, #0xff000000\n\t"
        "orr	r9, r9, lr, lsl #16\n\t"
#else
        "bfi	r9, lr, #16, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "orr	r10, r10, #0xc000000\n\t"
        "orr	r10, r10, #0xff0000\n\t"
#else
        "movt	r10, #0xcff\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "str	r2, [%[r]]\n\t"
        "str	r3, [%[r], #4]\n\t"
        "str	r4, [%[r], #8]\n\t"
        "str	r5, [%[r], #12]\n\t"
        "str	r6, [%[r], #16]\n\t"
        "str	r7, [%[r], #20]\n\t"
        "str	r8, [%[r], #24]\n\t"
        "str	r9, [%[r], #28]\n\t"
        "ldr	r3, [sp, #4]\n\t"
        "add	r3, r3, #16\n\t"
        "rsbs	r12, r3, #0x100\n\t"
        "add	%[r], %[r], #32\n\t"
        "bne	L_kyber_arm32_ntt_loop_567_%=\n\t"
        "add	sp, sp, #8\n\t"
        : [r] "+r" (r),
          [L_kyber_arm32_ntt_zetas] "+r" (L_kyber_arm32_ntt_zetas_c)
        :
        : "memory", "cc", "r2", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8",
            "r9", "r10", "r11"
    );
}

static const word16 L_kyber_arm32_invntt_zetas_inv[] = {
    0x06a5, 0x070f, 0x05b4, 0x0943,
    0x0922, 0x091d, 0x0134, 0x006c,
    0x0b23, 0x0366, 0x0356, 0x05e6,
    0x09e7, 0x04fe, 0x05fa, 0x04a1,
    0x067b, 0x04a3, 0x0c25, 0x036a,
    0x0537, 0x083f, 0x0088, 0x04bf,
    0x0b81, 0x05b9, 0x0505, 0x07d7,
    0x0a9f, 0x0aa6, 0x08b8, 0x09d0,
    0x004b, 0x009c, 0x0bb8, 0x0b5f,
    0x0ba4, 0x0368, 0x0a7d, 0x0636,
    0x08a2, 0x025a, 0x0736, 0x0309,
    0x0093, 0x087a, 0x09f7, 0x00f6,
    0x068c, 0x06db, 0x01cc, 0x0123,
    0x00eb, 0x0c50, 0x0ab6, 0x0b5b,
    0x0c98, 0x06f3, 0x099a, 0x04e3,
    0x09b6, 0x0ad6, 0x0b53, 0x044f,
    0x04fb, 0x0a5c, 0x0429, 0x0b41,
    0x02d5, 0x05e4, 0x0940, 0x018e,
    0x03b7, 0x00f7, 0x058d, 0x0c96,
    0x09c3, 0x010f, 0x005a, 0x0355,
    0x0744, 0x0c83, 0x048a, 0x0652,
    0x029a, 0x0140, 0x0008, 0x0afd,
    0x0608, 0x011a, 0x072e, 0x050d,
    0x090a, 0x0228, 0x0a75, 0x083a,
    0x0623, 0x00cd, 0x0b66, 0x0606,
    0x0aa1, 0x0a25, 0x0908, 0x02a9,
    0x0082, 0x0642, 0x074f, 0x033d,
    0x0b82, 0x0bf9, 0x052d, 0x0ac4,
    0x0745, 0x05c2, 0x04b2, 0x093f,
    0x0c4b, 0x06d8, 0x0a93, 0x00ab,
    0x0c37, 0x0be2, 0x0773, 0x072c,
    0x05ed, 0x0167, 0x02f6, 0x05a1,
};

void kyber_arm32_invntt(sword16* r_p)
{
    register sword16* r asm ("r0") = (sword16*)r_p;
    register word16* L_kyber_arm32_invntt_zetas_inv_c asm ("r1") =
        (word16*)&L_kyber_arm32_invntt_zetas_inv;

    __asm__ __volatile__ (
        "sub	sp, sp, #8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "orr	r10, r10, #0xc000000\n\t"
        "orr	r10, r10, #0xff0000\n\t"
#else
        "movt	r10, #0xcff\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "mov	r3, #0\n\t"
        "\n"
    "L_kyber_arm32_invntt_loop_765_%=: \n\t"
        "add	r11, r1, r3, lsr #1\n\t"
        "str	r3, [sp, #4]\n\t"
        "ldr	r2, [%[r]]\n\t"
        "ldr	r3, [%[r], #4]\n\t"
        "ldr	r4, [%[r], #8]\n\t"
        "ldr	r5, [%[r], #12]\n\t"
        "ldr	r6, [%[r], #16]\n\t"
        "ldr	r7, [%[r], #20]\n\t"
        "ldr	r8, [%[r], #24]\n\t"
        "ldr	r9, [%[r], #28]\n\t"
        "ldr	r11, [r11]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r2, r3\n\t"
        "sadd16	r2, r2, r3\n\t"
        "smulbt	r3, r11, r12\n\t"
        "smulbb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r3\n\t"
        "smlabb	r3, r10, lr, r3\n\t"
        "pkhtb	r3, r3, r12, ASR #16\n\t"
#else
        "sub	lr, r2, r3\n\t"
        "add	r10, r2, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
#else
        "bfc	r3, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
#else
        "bfc	r2, #0, #16\n\t"
#endif
        "sub	r12, r2, r3\n\t"
        "add	r2, r2, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
        "ror	r2, r2, #16\n\t"
        "orr	r2, r2, r10, lsl #16\n\t"
        "ror	r2, r2, #16\n\t"
#else
        "bfi	r2, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r3, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r3, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r3, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r3, r10, lr, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
        "ror	r3, r3, #16\n\t"
        "orr	r3, r3, r12, lsl #16\n\t"
        "ror	r3, r3, #16\n\t"
#else
        "bfi	r3, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r4, r5\n\t"
        "sadd16	r4, r4, r5\n\t"
        "smultt	r5, r11, r12\n\t"
        "smultb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r5\n\t"
        "smlabb	r5, r10, lr, r5\n\t"
        "pkhtb	r5, r5, r12, ASR #16\n\t"
#else
        "sub	lr, r4, r5\n\t"
        "add	r10, r4, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
#else
        "bfc	r5, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
#else
        "bfc	r4, #0, #16\n\t"
#endif
        "sub	r12, r4, r5\n\t"
        "add	r4, r4, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
        "ror	r4, r4, #16\n\t"
        "orr	r4, r4, r10, lsl #16\n\t"
        "ror	r4, r4, #16\n\t"
#else
        "bfi	r4, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r5, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r5, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r5, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r5, r10, lr, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
        "ror	r5, r5, #16\n\t"
        "orr	r5, r5, r12, lsl #16\n\t"
        "ror	r5, r5, #16\n\t"
#else
        "bfi	r5, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "ldr	r11, [sp, #4]\n\t"
        "add	r11, r1, r11, lsr #1\n\t"
        "ldr	r11, [r11, #4]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r6, r7\n\t"
        "sadd16	r6, r6, r7\n\t"
        "smulbt	r7, r11, r12\n\t"
        "smulbb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r7\n\t"
        "smlabb	r7, r10, lr, r7\n\t"
        "pkhtb	r7, r7, r12, ASR #16\n\t"
#else
        "sub	lr, r6, r7\n\t"
        "add	r10, r6, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
#else
        "bfc	r7, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
#else
        "bfc	r6, #0, #16\n\t"
#endif
        "sub	r12, r6, r7\n\t"
        "add	r6, r6, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
        "ror	r6, r6, #16\n\t"
        "orr	r6, r6, r10, lsl #16\n\t"
        "ror	r6, r6, #16\n\t"
#else
        "bfi	r6, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r7, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r7, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r7, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r7, r10, lr, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
        "ror	r7, r7, #16\n\t"
        "orr	r7, r7, r12, lsl #16\n\t"
        "ror	r7, r7, #16\n\t"
#else
        "bfi	r7, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r8, r9\n\t"
        "sadd16	r8, r8, r9\n\t"
        "smultt	r9, r11, r12\n\t"
        "smultb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r9\n\t"
        "smlabb	r9, r10, lr, r9\n\t"
        "pkhtb	r9, r9, r12, ASR #16\n\t"
#else
        "sub	lr, r8, r9\n\t"
        "add	r10, r8, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
#else
        "bfc	r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
#else
        "bfc	r8, #0, #16\n\t"
#endif
        "sub	r12, r8, r9\n\t"
        "add	r8, r8, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
        "ror	r8, r8, #16\n\t"
        "orr	r8, r8, r10, lsl #16\n\t"
        "ror	r8, r8, #16\n\t"
#else
        "bfi	r8, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r9, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r9, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r9, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r9, r10, lr, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
        "ror	r9, r9, #16\n\t"
        "orr	r9, r9, r12, lsl #16\n\t"
        "ror	r9, r9, #16\n\t"
#else
        "bfi	r9, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "ldr	r11, [sp, #4]\n\t"
        "add	r11, r1, r11, lsr #2\n\t"
        "ldr	r11, [r11, #128]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r2, r4\n\t"
        "sadd16	r2, r2, r4\n\t"
        "smulbt	r4, r11, r12\n\t"
        "smulbb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r4\n\t"
        "smlabb	r4, r10, lr, r4\n\t"
        "pkhtb	r4, r4, r12, ASR #16\n\t"
#else
        "sub	lr, r2, r4\n\t"
        "add	r10, r2, r4\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
#else
        "bfc	r4, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
#else
        "bfc	r2, #0, #16\n\t"
#endif
        "sub	r12, r2, r4\n\t"
        "add	r2, r2, r4\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
        "ror	r2, r2, #16\n\t"
        "orr	r2, r2, r10, lsl #16\n\t"
        "ror	r2, r2, #16\n\t"
#else
        "bfi	r2, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r4, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r4, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r4, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r4, r10, lr, r4\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
        "ror	r4, r4, #16\n\t"
        "orr	r4, r4, r12, lsl #16\n\t"
        "ror	r4, r4, #16\n\t"
#else
        "bfi	r4, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r3, r5\n\t"
        "sadd16	r3, r3, r5\n\t"
        "smulbt	r5, r11, r12\n\t"
        "smulbb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r5\n\t"
        "smlabb	r5, r10, lr, r5\n\t"
        "pkhtb	r5, r5, r12, ASR #16\n\t"
#else
        "sub	lr, r3, r5\n\t"
        "add	r10, r3, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
#else
        "bfc	r5, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
#else
        "bfc	r3, #0, #16\n\t"
#endif
        "sub	r12, r3, r5\n\t"
        "add	r3, r3, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
        "ror	r3, r3, #16\n\t"
        "orr	r3, r3, r10, lsl #16\n\t"
        "ror	r3, r3, #16\n\t"
#else
        "bfi	r3, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r5, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r5, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r5, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r5, r10, lr, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
        "ror	r5, r5, #16\n\t"
        "orr	r5, r5, r12, lsl #16\n\t"
        "ror	r5, r5, #16\n\t"
#else
        "bfi	r5, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r6, r8\n\t"
        "sadd16	r6, r6, r8\n\t"
        "smultt	r8, r11, r12\n\t"
        "smultb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r8\n\t"
        "smlabb	r8, r10, lr, r8\n\t"
        "pkhtb	r8, r8, r12, ASR #16\n\t"
#else
        "sub	lr, r6, r8\n\t"
        "add	r10, r6, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
#else
        "bfc	r8, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
#else
        "bfc	r6, #0, #16\n\t"
#endif
        "sub	r12, r6, r8\n\t"
        "add	r6, r6, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
        "ror	r6, r6, #16\n\t"
        "orr	r6, r6, r10, lsl #16\n\t"
        "ror	r6, r6, #16\n\t"
#else
        "bfi	r6, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r8, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r8, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r8, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r8, r10, lr, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
        "ror	r8, r8, #16\n\t"
        "orr	r8, r8, r12, lsl #16\n\t"
        "ror	r8, r8, #16\n\t"
#else
        "bfi	r8, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r7, r9\n\t"
        "sadd16	r7, r7, r9\n\t"
        "smultt	r9, r11, r12\n\t"
        "smultb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r9\n\t"
        "smlabb	r9, r10, lr, r9\n\t"
        "pkhtb	r9, r9, r12, ASR #16\n\t"
#else
        "sub	lr, r7, r9\n\t"
        "add	r10, r7, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
#else
        "bfc	r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
#else
        "bfc	r7, #0, #16\n\t"
#endif
        "sub	r12, r7, r9\n\t"
        "add	r7, r7, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
        "ror	r7, r7, #16\n\t"
        "orr	r7, r7, r10, lsl #16\n\t"
        "ror	r7, r7, #16\n\t"
#else
        "bfi	r7, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r9, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r9, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r9, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r9, r10, lr, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
        "ror	r9, r9, #16\n\t"
        "orr	r9, r9, r12, lsl #16\n\t"
        "ror	r9, r9, #16\n\t"
#else
        "bfi	r9, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "ldr	r11, [sp, #4]\n\t"
        "add	r11, r1, r11, lsr #3\n\t"
        "ldr	r11, [r11, #192]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r2, r6\n\t"
        "sadd16	r2, r2, r6\n\t"
        "smulbt	r6, r11, r12\n\t"
        "smulbb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r6\n\t"
        "smlabb	r6, r10, lr, r6\n\t"
        "pkhtb	r6, r6, r12, ASR #16\n\t"
#else
        "sub	lr, r2, r6\n\t"
        "add	r10, r2, r6\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
#else
        "bfc	r6, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
#else
        "bfc	r2, #0, #16\n\t"
#endif
        "sub	r12, r2, r6\n\t"
        "add	r2, r2, r6\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
        "ror	r2, r2, #16\n\t"
        "orr	r2, r2, r10, lsl #16\n\t"
        "ror	r2, r2, #16\n\t"
#else
        "bfi	r2, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r6, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r6, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r6, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r6, r10, lr, r6\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
        "ror	r6, r6, #16\n\t"
        "orr	r6, r6, r12, lsl #16\n\t"
        "ror	r6, r6, #16\n\t"
#else
        "bfi	r6, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r3, r7\n\t"
        "sadd16	r3, r3, r7\n\t"
        "smulbt	r7, r11, r12\n\t"
        "smulbb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r7\n\t"
        "smlabb	r7, r10, lr, r7\n\t"
        "pkhtb	r7, r7, r12, ASR #16\n\t"
#else
        "sub	lr, r3, r7\n\t"
        "add	r10, r3, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
#else
        "bfc	r7, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
#else
        "bfc	r3, #0, #16\n\t"
#endif
        "sub	r12, r3, r7\n\t"
        "add	r3, r3, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
        "ror	r3, r3, #16\n\t"
        "orr	r3, r3, r10, lsl #16\n\t"
        "ror	r3, r3, #16\n\t"
#else
        "bfi	r3, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r7, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r7, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r7, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r7, r10, lr, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
        "ror	r7, r7, #16\n\t"
        "orr	r7, r7, r12, lsl #16\n\t"
        "ror	r7, r7, #16\n\t"
#else
        "bfi	r7, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r4, r8\n\t"
        "sadd16	r4, r4, r8\n\t"
        "smulbt	r8, r11, r12\n\t"
        "smulbb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r8\n\t"
        "smlabb	r8, r10, lr, r8\n\t"
        "pkhtb	r8, r8, r12, ASR #16\n\t"
#else
        "sub	lr, r4, r8\n\t"
        "add	r10, r4, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
#else
        "bfc	r8, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
#else
        "bfc	r4, #0, #16\n\t"
#endif
        "sub	r12, r4, r8\n\t"
        "add	r4, r4, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
        "ror	r4, r4, #16\n\t"
        "orr	r4, r4, r10, lsl #16\n\t"
        "ror	r4, r4, #16\n\t"
#else
        "bfi	r4, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r8, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r8, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r8, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r8, r10, lr, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
        "ror	r8, r8, #16\n\t"
        "orr	r8, r8, r12, lsl #16\n\t"
        "ror	r8, r8, #16\n\t"
#else
        "bfi	r8, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r5, r9\n\t"
        "sadd16	r5, r5, r9\n\t"
        "smulbt	r9, r11, r12\n\t"
        "smulbb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r9\n\t"
        "smlabb	r9, r10, lr, r9\n\t"
        "pkhtb	r9, r9, r12, ASR #16\n\t"
#else
        "sub	lr, r5, r9\n\t"
        "add	r10, r5, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
#else
        "bfc	r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
#else
        "bfc	r5, #0, #16\n\t"
#endif
        "sub	r12, r5, r9\n\t"
        "add	r5, r5, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
        "ror	r5, r5, #16\n\t"
        "orr	r5, r5, r10, lsl #16\n\t"
        "ror	r5, r5, #16\n\t"
#else
        "bfi	r5, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r9, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r9, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r9, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r9, r10, lr, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
        "ror	r9, r9, #16\n\t"
        "orr	r9, r9, r12, lsl #16\n\t"
        "ror	r9, r9, #16\n\t"
#else
        "bfi	r9, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r11, #0xaf\n\t"
        "lsl	r11, r11, #8\n\t"
        "add	r11, r11, #0xc0\n\t"
#else
        "mov	r11, #0xafc0\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "orr	r11, r11, #0x130000\n\t"
#else
        "movt	r11, #0x13\n\t"
#endif
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r11, #0x4e\n\t"
        "lsl	r11, r11, #8\n\t"
        "add	r11, r11, #0xbf\n\t"
#else
        "mov	r11, #0x4ebf\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulwb	r12, r11, r2\n\t"
        "smulwt	lr, r11, r2\n\t"
        "smulbt	r12, r10, r12\n\t"
        "smulbt	lr, r10, lr\n\t"
        "pkhbt	r12, r12, lr, LSL #16\n\t"
        "ssub16	r2, r2, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r2, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r2, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r2, #16\n\t"
#else
        "sbfx	lr, r2, #16, #16\n\t"
#endif
        "mul	r12, r11, r12\n\t"
        "mul	lr, r11, lr\n\t"
        "asr	r12, r12, #26\n\t"
        "asr	lr, lr, #26\n\t"
        "mul	r12, r10, r12\n\t"
        "mul	lr, r10, lr\n\t"
        "sub	lr, r2, lr, lsl #16\n\t"
        "sub	r2, r2, r12\n\t"
        "lsr	lr, lr, #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff0000\n\t"
        "bic	r2, r2, #0xff000000\n\t"
        "orr	r2, r2, lr, lsl #16\n\t"
#else
        "bfi	r2, lr, #16, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulwb	r12, r11, r3\n\t"
        "smulwt	lr, r11, r3\n\t"
        "smulbt	r12, r10, r12\n\t"
        "smulbt	lr, r10, lr\n\t"
        "pkhbt	r12, r12, lr, LSL #16\n\t"
        "ssub16	r3, r3, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r3, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r3, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r3, #16\n\t"
#else
        "sbfx	lr, r3, #16, #16\n\t"
#endif
        "mul	r12, r11, r12\n\t"
        "mul	lr, r11, lr\n\t"
        "asr	r12, r12, #26\n\t"
        "asr	lr, lr, #26\n\t"
        "mul	r12, r10, r12\n\t"
        "mul	lr, r10, lr\n\t"
        "sub	lr, r3, lr, lsl #16\n\t"
        "sub	r3, r3, r12\n\t"
        "lsr	lr, lr, #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff0000\n\t"
        "bic	r3, r3, #0xff000000\n\t"
        "orr	r3, r3, lr, lsl #16\n\t"
#else
        "bfi	r3, lr, #16, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulwb	r12, r11, r4\n\t"
        "smulwt	lr, r11, r4\n\t"
        "smulbt	r12, r10, r12\n\t"
        "smulbt	lr, r10, lr\n\t"
        "pkhbt	r12, r12, lr, LSL #16\n\t"
        "ssub16	r4, r4, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r4, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r4, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r4, #16\n\t"
#else
        "sbfx	lr, r4, #16, #16\n\t"
#endif
        "mul	r12, r11, r12\n\t"
        "mul	lr, r11, lr\n\t"
        "asr	r12, r12, #26\n\t"
        "asr	lr, lr, #26\n\t"
        "mul	r12, r10, r12\n\t"
        "mul	lr, r10, lr\n\t"
        "sub	lr, r4, lr, lsl #16\n\t"
        "sub	r4, r4, r12\n\t"
        "lsr	lr, lr, #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff0000\n\t"
        "bic	r4, r4, #0xff000000\n\t"
        "orr	r4, r4, lr, lsl #16\n\t"
#else
        "bfi	r4, lr, #16, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulwb	r12, r11, r5\n\t"
        "smulwt	lr, r11, r5\n\t"
        "smulbt	r12, r10, r12\n\t"
        "smulbt	lr, r10, lr\n\t"
        "pkhbt	r12, r12, lr, LSL #16\n\t"
        "ssub16	r5, r5, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r5, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r5, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r5, #16\n\t"
#else
        "sbfx	lr, r5, #16, #16\n\t"
#endif
        "mul	r12, r11, r12\n\t"
        "mul	lr, r11, lr\n\t"
        "asr	r12, r12, #26\n\t"
        "asr	lr, lr, #26\n\t"
        "mul	r12, r10, r12\n\t"
        "mul	lr, r10, lr\n\t"
        "sub	lr, r5, lr, lsl #16\n\t"
        "sub	r5, r5, r12\n\t"
        "lsr	lr, lr, #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff0000\n\t"
        "bic	r5, r5, #0xff000000\n\t"
        "orr	r5, r5, lr, lsl #16\n\t"
#else
        "bfi	r5, lr, #16, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "str	r2, [%[r]]\n\t"
        "str	r3, [%[r], #4]\n\t"
        "str	r4, [%[r], #8]\n\t"
        "str	r5, [%[r], #12]\n\t"
        "str	r6, [%[r], #16]\n\t"
        "str	r7, [%[r], #20]\n\t"
        "str	r8, [%[r], #24]\n\t"
        "str	r9, [%[r], #28]\n\t"
        "ldr	r3, [sp, #4]\n\t"
        "add	r3, r3, #16\n\t"
        "rsbs	r12, r3, #0x100\n\t"
        "add	%[r], %[r], #32\n\t"
        "bne	L_kyber_arm32_invntt_loop_765_%=\n\t"
        "sub	%[r], %[r], #0x200\n\t"
        "mov	r3, #0\n\t"
        "\n"
    "L_kyber_arm32_invntt_loop_4_j_%=: \n\t"
        "str	r3, [sp, #4]\n\t"
        "add	r11, r1, r3, lsr #4\n\t"
        "mov	r2, #4\n\t"
        "ldr	r11, [r11, #224]\n\t"
        "\n"
    "L_kyber_arm32_invntt_loop_4_i_%=: \n\t"
        "str	r2, [sp]\n\t"
        "ldr	r2, [%[r]]\n\t"
        "ldr	r3, [%[r], #16]\n\t"
        "ldr	r4, [%[r], #32]\n\t"
        "ldr	r5, [%[r], #48]\n\t"
        "ldr	r6, [%[r], #64]\n\t"
        "ldr	r7, [%[r], #80]\n\t"
        "ldr	r8, [%[r], #96]\n\t"
        "ldr	r9, [%[r], #112]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r2, r4\n\t"
        "sadd16	r2, r2, r4\n\t"
        "smulbt	r4, r11, r12\n\t"
        "smulbb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r4\n\t"
        "smlabb	r4, r10, lr, r4\n\t"
        "pkhtb	r4, r4, r12, ASR #16\n\t"
#else
        "sub	lr, r2, r4\n\t"
        "add	r10, r2, r4\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
#else
        "bfc	r4, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
#else
        "bfc	r2, #0, #16\n\t"
#endif
        "sub	r12, r2, r4\n\t"
        "add	r2, r2, r4\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
        "ror	r2, r2, #16\n\t"
        "orr	r2, r2, r10, lsl #16\n\t"
        "ror	r2, r2, #16\n\t"
#else
        "bfi	r2, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r4, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r4, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r4, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r4, r10, lr, r4\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
        "ror	r4, r4, #16\n\t"
        "orr	r4, r4, r12, lsl #16\n\t"
        "ror	r4, r4, #16\n\t"
#else
        "bfi	r4, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r3, r5\n\t"
        "sadd16	r3, r3, r5\n\t"
        "smulbt	r5, r11, r12\n\t"
        "smulbb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r5\n\t"
        "smlabb	r5, r10, lr, r5\n\t"
        "pkhtb	r5, r5, r12, ASR #16\n\t"
#else
        "sub	lr, r3, r5\n\t"
        "add	r10, r3, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
#else
        "bfc	r5, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
#else
        "bfc	r3, #0, #16\n\t"
#endif
        "sub	r12, r3, r5\n\t"
        "add	r3, r3, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
        "ror	r3, r3, #16\n\t"
        "orr	r3, r3, r10, lsl #16\n\t"
        "ror	r3, r3, #16\n\t"
#else
        "bfi	r3, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r5, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r5, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r5, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r5, r10, lr, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
        "ror	r5, r5, #16\n\t"
        "orr	r5, r5, r12, lsl #16\n\t"
        "ror	r5, r5, #16\n\t"
#else
        "bfi	r5, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r6, r8\n\t"
        "sadd16	r6, r6, r8\n\t"
        "smultt	r8, r11, r12\n\t"
        "smultb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r8\n\t"
        "smlabb	r8, r10, lr, r8\n\t"
        "pkhtb	r8, r8, r12, ASR #16\n\t"
#else
        "sub	lr, r6, r8\n\t"
        "add	r10, r6, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
#else
        "bfc	r8, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
#else
        "bfc	r6, #0, #16\n\t"
#endif
        "sub	r12, r6, r8\n\t"
        "add	r6, r6, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
        "ror	r6, r6, #16\n\t"
        "orr	r6, r6, r10, lsl #16\n\t"
        "ror	r6, r6, #16\n\t"
#else
        "bfi	r6, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r8, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r8, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r8, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r8, r10, lr, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
        "ror	r8, r8, #16\n\t"
        "orr	r8, r8, r12, lsl #16\n\t"
        "ror	r8, r8, #16\n\t"
#else
        "bfi	r8, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r7, r9\n\t"
        "sadd16	r7, r7, r9\n\t"
        "smultt	r9, r11, r12\n\t"
        "smultb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r9\n\t"
        "smlabb	r9, r10, lr, r9\n\t"
        "pkhtb	r9, r9, r12, ASR #16\n\t"
#else
        "sub	lr, r7, r9\n\t"
        "add	r10, r7, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
#else
        "bfc	r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
#else
        "bfc	r7, #0, #16\n\t"
#endif
        "sub	r12, r7, r9\n\t"
        "add	r7, r7, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
        "ror	r7, r7, #16\n\t"
        "orr	r7, r7, r10, lsl #16\n\t"
        "ror	r7, r7, #16\n\t"
#else
        "bfi	r7, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r9, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r9, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r9, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r9, r10, lr, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
        "ror	r9, r9, #16\n\t"
        "orr	r9, r9, r12, lsl #16\n\t"
        "ror	r9, r9, #16\n\t"
#else
        "bfi	r9, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "str	r2, [%[r]]\n\t"
        "str	r3, [%[r], #16]\n\t"
        "str	r4, [%[r], #32]\n\t"
        "str	r5, [%[r], #48]\n\t"
        "str	r6, [%[r], #64]\n\t"
        "str	r7, [%[r], #80]\n\t"
        "str	r8, [%[r], #96]\n\t"
        "str	r9, [%[r], #112]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "ldr	r2, [sp]\n\t"
        "ldr	r3, [sp, #4]\n\t"
#else
        "ldrd	r2, r3, [sp]\n\t"
#endif
        "subs	r2, r2, #1\n\t"
        "add	%[r], %[r], #4\n\t"
        "bne	L_kyber_arm32_invntt_loop_4_i_%=\n\t"
        "add	r3, r3, #0x40\n\t"
        "rsbs	r12, r3, #0x100\n\t"
        "add	%[r], %[r], #0x70\n\t"
        "bne	L_kyber_arm32_invntt_loop_4_j_%=\n\t"
        "sub	%[r], %[r], #0x200\n\t"
        "mov	r2, #16\n\t"
        "\n"
    "L_kyber_arm32_invntt_loop_321_%=: \n\t"
        "str	r2, [sp]\n\t"
        "ldrh	r11, [r1, #2]\n\t"
        "ldr	r2, [%[r]]\n\t"
        "ldr	r3, [%[r], #64]\n\t"
        "ldr	r4, [%[r], #128]\n\t"
        "ldr	r5, [%[r], #192]\n\t"
        "ldr	r6, [%[r], #256]\n\t"
        "ldr	r7, [%[r], #320]\n\t"
        "ldr	r8, [%[r], #384]\n\t"
        "ldr	r9, [%[r], #448]\n\t"
        "ldr	r11, [r1, #240]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r2, r3\n\t"
        "sadd16	r2, r2, r3\n\t"
        "smulbt	r3, r11, r12\n\t"
        "smulbb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r3\n\t"
        "smlabb	r3, r10, lr, r3\n\t"
        "pkhtb	r3, r3, r12, ASR #16\n\t"
#else
        "sub	lr, r2, r3\n\t"
        "add	r10, r2, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
#else
        "bfc	r3, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
#else
        "bfc	r2, #0, #16\n\t"
#endif
        "sub	r12, r2, r3\n\t"
        "add	r2, r2, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
        "ror	r2, r2, #16\n\t"
        "orr	r2, r2, r10, lsl #16\n\t"
        "ror	r2, r2, #16\n\t"
#else
        "bfi	r2, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r3, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r3, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r3, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r3, r10, lr, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
        "ror	r3, r3, #16\n\t"
        "orr	r3, r3, r12, lsl #16\n\t"
        "ror	r3, r3, #16\n\t"
#else
        "bfi	r3, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r4, r5\n\t"
        "sadd16	r4, r4, r5\n\t"
        "smultt	r5, r11, r12\n\t"
        "smultb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r5\n\t"
        "smlabb	r5, r10, lr, r5\n\t"
        "pkhtb	r5, r5, r12, ASR #16\n\t"
#else
        "sub	lr, r4, r5\n\t"
        "add	r10, r4, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
#else
        "bfc	r5, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
#else
        "bfc	r4, #0, #16\n\t"
#endif
        "sub	r12, r4, r5\n\t"
        "add	r4, r4, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
        "ror	r4, r4, #16\n\t"
        "orr	r4, r4, r10, lsl #16\n\t"
        "ror	r4, r4, #16\n\t"
#else
        "bfi	r4, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r5, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r5, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r5, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r5, r10, lr, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
        "ror	r5, r5, #16\n\t"
        "orr	r5, r5, r12, lsl #16\n\t"
        "ror	r5, r5, #16\n\t"
#else
        "bfi	r5, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "ldr	r11, [r1, #244]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r6, r7\n\t"
        "sadd16	r6, r6, r7\n\t"
        "smulbt	r7, r11, r12\n\t"
        "smulbb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r7\n\t"
        "smlabb	r7, r10, lr, r7\n\t"
        "pkhtb	r7, r7, r12, ASR #16\n\t"
#else
        "sub	lr, r6, r7\n\t"
        "add	r10, r6, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
#else
        "bfc	r7, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
#else
        "bfc	r6, #0, #16\n\t"
#endif
        "sub	r12, r6, r7\n\t"
        "add	r6, r6, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
        "ror	r6, r6, #16\n\t"
        "orr	r6, r6, r10, lsl #16\n\t"
        "ror	r6, r6, #16\n\t"
#else
        "bfi	r6, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r7, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r7, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r7, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r7, r10, lr, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
        "ror	r7, r7, #16\n\t"
        "orr	r7, r7, r12, lsl #16\n\t"
        "ror	r7, r7, #16\n\t"
#else
        "bfi	r7, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r8, r9\n\t"
        "sadd16	r8, r8, r9\n\t"
        "smultt	r9, r11, r12\n\t"
        "smultb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r9\n\t"
        "smlabb	r9, r10, lr, r9\n\t"
        "pkhtb	r9, r9, r12, ASR #16\n\t"
#else
        "sub	lr, r8, r9\n\t"
        "add	r10, r8, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
#else
        "bfc	r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
#else
        "bfc	r8, #0, #16\n\t"
#endif
        "sub	r12, r8, r9\n\t"
        "add	r8, r8, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
        "ror	r8, r8, #16\n\t"
        "orr	r8, r8, r10, lsl #16\n\t"
        "ror	r8, r8, #16\n\t"
#else
        "bfi	r8, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r9, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r9, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r9, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r9, r10, lr, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
        "ror	r9, r9, #16\n\t"
        "orr	r9, r9, r12, lsl #16\n\t"
        "ror	r9, r9, #16\n\t"
#else
        "bfi	r9, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "ldr	r11, [r1, #248]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r2, r4\n\t"
        "sadd16	r2, r2, r4\n\t"
        "smulbt	r4, r11, r12\n\t"
        "smulbb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r4\n\t"
        "smlabb	r4, r10, lr, r4\n\t"
        "pkhtb	r4, r4, r12, ASR #16\n\t"
#else
        "sub	lr, r2, r4\n\t"
        "add	r10, r2, r4\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
#else
        "bfc	r4, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
#else
        "bfc	r2, #0, #16\n\t"
#endif
        "sub	r12, r2, r4\n\t"
        "add	r2, r2, r4\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
        "ror	r2, r2, #16\n\t"
        "orr	r2, r2, r10, lsl #16\n\t"
        "ror	r2, r2, #16\n\t"
#else
        "bfi	r2, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r4, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r4, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r4, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r4, r10, lr, r4\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
        "ror	r4, r4, #16\n\t"
        "orr	r4, r4, r12, lsl #16\n\t"
        "ror	r4, r4, #16\n\t"
#else
        "bfi	r4, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r3, r5\n\t"
        "sadd16	r3, r3, r5\n\t"
        "smulbt	r5, r11, r12\n\t"
        "smulbb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r5\n\t"
        "smlabb	r5, r10, lr, r5\n\t"
        "pkhtb	r5, r5, r12, ASR #16\n\t"
#else
        "sub	lr, r3, r5\n\t"
        "add	r10, r3, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
#else
        "bfc	r5, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
#else
        "bfc	r3, #0, #16\n\t"
#endif
        "sub	r12, r3, r5\n\t"
        "add	r3, r3, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
        "ror	r3, r3, #16\n\t"
        "orr	r3, r3, r10, lsl #16\n\t"
        "ror	r3, r3, #16\n\t"
#else
        "bfi	r3, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r5, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r5, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r5, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r5, r10, lr, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
        "ror	r5, r5, #16\n\t"
        "orr	r5, r5, r12, lsl #16\n\t"
        "ror	r5, r5, #16\n\t"
#else
        "bfi	r5, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r6, r8\n\t"
        "sadd16	r6, r6, r8\n\t"
        "smultt	r8, r11, r12\n\t"
        "smultb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r8\n\t"
        "smlabb	r8, r10, lr, r8\n\t"
        "pkhtb	r8, r8, r12, ASR #16\n\t"
#else
        "sub	lr, r6, r8\n\t"
        "add	r10, r6, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
#else
        "bfc	r8, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
#else
        "bfc	r6, #0, #16\n\t"
#endif
        "sub	r12, r6, r8\n\t"
        "add	r6, r6, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
        "ror	r6, r6, #16\n\t"
        "orr	r6, r6, r10, lsl #16\n\t"
        "ror	r6, r6, #16\n\t"
#else
        "bfi	r6, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r8, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r8, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r8, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r8, r10, lr, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
        "ror	r8, r8, #16\n\t"
        "orr	r8, r8, r12, lsl #16\n\t"
        "ror	r8, r8, #16\n\t"
#else
        "bfi	r8, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r7, r9\n\t"
        "sadd16	r7, r7, r9\n\t"
        "smultt	r9, r11, r12\n\t"
        "smultb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r9\n\t"
        "smlabb	r9, r10, lr, r9\n\t"
        "pkhtb	r9, r9, r12, ASR #16\n\t"
#else
        "sub	lr, r7, r9\n\t"
        "add	r10, r7, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
#else
        "bfc	r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
#else
        "bfc	r7, #0, #16\n\t"
#endif
        "sub	r12, r7, r9\n\t"
        "add	r7, r7, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
        "ror	r7, r7, #16\n\t"
        "orr	r7, r7, r10, lsl #16\n\t"
        "ror	r7, r7, #16\n\t"
#else
        "bfi	r7, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r11, #16\n\t"
#else
        "sbfx	lr, r11, #16, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r9, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r9, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r9, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r9, r10, lr, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
        "ror	r9, r9, #16\n\t"
        "orr	r9, r9, r12, lsl #16\n\t"
        "ror	r9, r9, #16\n\t"
#else
        "bfi	r9, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r11, #0xaf\n\t"
        "lsl	r11, r11, #8\n\t"
        "add	r11, r11, #0xc0\n\t"
#else
        "mov	r11, #0xafc0\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "orr	r11, r11, #0x130000\n\t"
#else
        "movt	r11, #0x13\n\t"
#endif
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r11, #0x4e\n\t"
        "lsl	r11, r11, #8\n\t"
        "add	r11, r11, #0xbf\n\t"
#else
        "mov	r11, #0x4ebf\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulwb	r12, r11, r2\n\t"
        "smulwt	lr, r11, r2\n\t"
        "smulbt	r12, r10, r12\n\t"
        "smulbt	lr, r10, lr\n\t"
        "pkhbt	r12, r12, lr, LSL #16\n\t"
        "ssub16	r2, r2, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r2, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r2, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r2, #16\n\t"
#else
        "sbfx	lr, r2, #16, #16\n\t"
#endif
        "mul	r12, r11, r12\n\t"
        "mul	lr, r11, lr\n\t"
        "asr	r12, r12, #26\n\t"
        "asr	lr, lr, #26\n\t"
        "mul	r12, r10, r12\n\t"
        "mul	lr, r10, lr\n\t"
        "sub	lr, r2, lr, lsl #16\n\t"
        "sub	r2, r2, r12\n\t"
        "lsr	lr, lr, #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff0000\n\t"
        "bic	r2, r2, #0xff000000\n\t"
        "orr	r2, r2, lr, lsl #16\n\t"
#else
        "bfi	r2, lr, #16, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulwb	r12, r11, r3\n\t"
        "smulwt	lr, r11, r3\n\t"
        "smulbt	r12, r10, r12\n\t"
        "smulbt	lr, r10, lr\n\t"
        "pkhbt	r12, r12, lr, LSL #16\n\t"
        "ssub16	r3, r3, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r3, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r3, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r3, #16\n\t"
#else
        "sbfx	lr, r3, #16, #16\n\t"
#endif
        "mul	r12, r11, r12\n\t"
        "mul	lr, r11, lr\n\t"
        "asr	r12, r12, #26\n\t"
        "asr	lr, lr, #26\n\t"
        "mul	r12, r10, r12\n\t"
        "mul	lr, r10, lr\n\t"
        "sub	lr, r3, lr, lsl #16\n\t"
        "sub	r3, r3, r12\n\t"
        "lsr	lr, lr, #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff0000\n\t"
        "bic	r3, r3, #0xff000000\n\t"
        "orr	r3, r3, lr, lsl #16\n\t"
#else
        "bfi	r3, lr, #16, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulwb	r12, r11, r4\n\t"
        "smulwt	lr, r11, r4\n\t"
        "smulbt	r12, r10, r12\n\t"
        "smulbt	lr, r10, lr\n\t"
        "pkhbt	r12, r12, lr, LSL #16\n\t"
        "ssub16	r4, r4, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r4, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r4, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r4, #16\n\t"
#else
        "sbfx	lr, r4, #16, #16\n\t"
#endif
        "mul	r12, r11, r12\n\t"
        "mul	lr, r11, lr\n\t"
        "asr	r12, r12, #26\n\t"
        "asr	lr, lr, #26\n\t"
        "mul	r12, r10, r12\n\t"
        "mul	lr, r10, lr\n\t"
        "sub	lr, r4, lr, lsl #16\n\t"
        "sub	r4, r4, r12\n\t"
        "lsr	lr, lr, #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff0000\n\t"
        "bic	r4, r4, #0xff000000\n\t"
        "orr	r4, r4, lr, lsl #16\n\t"
#else
        "bfi	r4, lr, #16, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulwb	r12, r11, r5\n\t"
        "smulwt	lr, r11, r5\n\t"
        "smulbt	r12, r10, r12\n\t"
        "smulbt	lr, r10, lr\n\t"
        "pkhbt	r12, r12, lr, LSL #16\n\t"
        "ssub16	r5, r5, r12\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r5, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r5, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	lr, r5, #16\n\t"
#else
        "sbfx	lr, r5, #16, #16\n\t"
#endif
        "mul	r12, r11, r12\n\t"
        "mul	lr, r11, lr\n\t"
        "asr	r12, r12, #26\n\t"
        "asr	lr, lr, #26\n\t"
        "mul	r12, r10, r12\n\t"
        "mul	lr, r10, lr\n\t"
        "sub	lr, r5, lr, lsl #16\n\t"
        "sub	r5, r5, r12\n\t"
        "lsr	lr, lr, #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff0000\n\t"
        "bic	r5, r5, #0xff000000\n\t"
        "orr	r5, r5, lr, lsl #16\n\t"
#else
        "bfi	r5, lr, #16, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "ldr	r11, [r1, #252]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r2, r6\n\t"
        "sadd16	r2, r2, r6\n\t"
        "smulbt	r6, r11, r12\n\t"
        "smulbb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r6\n\t"
        "smlabb	r6, r10, lr, r6\n\t"
        "pkhtb	r6, r6, r12, ASR #16\n\t"
#else
        "sub	lr, r2, r6\n\t"
        "add	r10, r2, r6\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
#else
        "bfc	r6, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
#else
        "bfc	r2, #0, #16\n\t"
#endif
        "sub	r12, r2, r6\n\t"
        "add	r2, r2, r6\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
        "ror	r2, r2, #16\n\t"
        "orr	r2, r2, r10, lsl #16\n\t"
        "ror	r2, r2, #16\n\t"
#else
        "bfi	r2, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r6, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r6, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r6, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r6, r10, lr, r6\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
        "ror	r6, r6, #16\n\t"
        "orr	r6, r6, r12, lsl #16\n\t"
        "ror	r6, r6, #16\n\t"
#else
        "bfi	r6, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r3, r7\n\t"
        "sadd16	r3, r3, r7\n\t"
        "smulbt	r7, r11, r12\n\t"
        "smulbb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r7\n\t"
        "smlabb	r7, r10, lr, r7\n\t"
        "pkhtb	r7, r7, r12, ASR #16\n\t"
#else
        "sub	lr, r3, r7\n\t"
        "add	r10, r3, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
#else
        "bfc	r7, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
#else
        "bfc	r3, #0, #16\n\t"
#endif
        "sub	r12, r3, r7\n\t"
        "add	r3, r3, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
        "ror	r3, r3, #16\n\t"
        "orr	r3, r3, r10, lsl #16\n\t"
        "ror	r3, r3, #16\n\t"
#else
        "bfi	r3, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r7, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r7, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r7, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r7, r10, lr, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
        "ror	r7, r7, #16\n\t"
        "orr	r7, r7, r12, lsl #16\n\t"
        "ror	r7, r7, #16\n\t"
#else
        "bfi	r7, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r4, r8\n\t"
        "sadd16	r4, r4, r8\n\t"
        "smulbt	r8, r11, r12\n\t"
        "smulbb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r8\n\t"
        "smlabb	r8, r10, lr, r8\n\t"
        "pkhtb	r8, r8, r12, ASR #16\n\t"
#else
        "sub	lr, r4, r8\n\t"
        "add	r10, r4, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
#else
        "bfc	r8, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
#else
        "bfc	r4, #0, #16\n\t"
#endif
        "sub	r12, r4, r8\n\t"
        "add	r4, r4, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
        "ror	r4, r4, #16\n\t"
        "orr	r4, r4, r10, lsl #16\n\t"
        "ror	r4, r4, #16\n\t"
#else
        "bfi	r4, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r8, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r8, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r8, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r8, r10, lr, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
        "ror	r8, r8, #16\n\t"
        "orr	r8, r8, r12, lsl #16\n\t"
        "ror	r8, r8, #16\n\t"
#else
        "bfi	r8, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r12, r5, r9\n\t"
        "sadd16	r5, r5, r9\n\t"
        "smulbt	r9, r11, r12\n\t"
        "smulbb	r12, r11, r12\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r9\n\t"
        "smlabb	r9, r10, lr, r9\n\t"
        "pkhtb	r9, r9, r12, ASR #16\n\t"
#else
        "sub	lr, r5, r9\n\t"
        "add	r10, r5, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
#else
        "bfc	r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
#else
        "bfc	r5, #0, #16\n\t"
#endif
        "sub	r12, r5, r9\n\t"
        "add	r5, r5, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r12, r12, #0xff\n\t"
        "bic	r12, r12, #0xff00\n\t"
        "ror	r12, r12, #16\n\t"
        "orr	r12, r12, lr, lsl #16\n\t"
        "ror	r12, r12, #16\n\t"
#else
        "bfi	r12, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
        "ror	r5, r5, #16\n\t"
        "orr	r5, r5, r10, lsl #16\n\t"
        "ror	r5, r5, #16\n\t"
#else
        "bfi	r5, r10, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
        "asr	r10, r12, #16\n\t"
        "mul	r9, lr, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r12, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r12, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r12, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r12, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r9, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r9, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r9, r10, lr, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
        "ror	r9, r9, #16\n\t"
        "orr	r9, r9, r12, lsl #16\n\t"
        "ror	r9, r9, #16\n\t"
#else
        "bfi	r9, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "ldr	r11, [r1, #254]\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r2\n\t"
        "smulbt	r2, r11, r2\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r2\n\t"
        "smlabb	r2, r10, lr, r2\n\t"
        "pkhtb	r2, r2, r12, ASR #16\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r2, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r2, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	r2, r2, #16\n\t"
#else
        "sbfx	r2, r2, #16, #16\n\t"
#endif
        "mul	r2, lr, r2\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r2, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r2, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r2, r10, lr, r2\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
        "ror	r2, r2, #16\n\t"
        "orr	r2, r2, r12, lsl #16\n\t"
        "ror	r2, r2, #16\n\t"
#else
        "bfi	r2, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r3\n\t"
        "smulbt	r3, r11, r3\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r3\n\t"
        "smlabb	r3, r10, lr, r3\n\t"
        "pkhtb	r3, r3, r12, ASR #16\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r3, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r3, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	r3, r3, #16\n\t"
#else
        "sbfx	r3, r3, #16, #16\n\t"
#endif
        "mul	r3, lr, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r3, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r3, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r3, r10, lr, r3\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
        "ror	r3, r3, #16\n\t"
        "orr	r3, r3, r12, lsl #16\n\t"
        "ror	r3, r3, #16\n\t"
#else
        "bfi	r3, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r4\n\t"
        "smulbt	r4, r11, r4\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r4\n\t"
        "smlabb	r4, r10, lr, r4\n\t"
        "pkhtb	r4, r4, r12, ASR #16\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r4, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r4, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	r4, r4, #16\n\t"
#else
        "sbfx	r4, r4, #16, #16\n\t"
#endif
        "mul	r4, lr, r4\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r4, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r4, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r4, r10, lr, r4\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
        "ror	r4, r4, #16\n\t"
        "orr	r4, r4, r12, lsl #16\n\t"
        "ror	r4, r4, #16\n\t"
#else
        "bfi	r4, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r5\n\t"
        "smulbt	r5, r11, r5\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r5\n\t"
        "smlabb	r5, r10, lr, r5\n\t"
        "pkhtb	r5, r5, r12, ASR #16\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r5, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r5, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	r5, r5, #16\n\t"
#else
        "sbfx	r5, r5, #16, #16\n\t"
#endif
        "mul	r5, lr, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r5, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r5, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r5, r10, lr, r5\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
        "ror	r5, r5, #16\n\t"
        "orr	r5, r5, r12, lsl #16\n\t"
        "ror	r5, r5, #16\n\t"
#else
        "bfi	r5, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r6\n\t"
        "smulbt	r6, r11, r6\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r6\n\t"
        "smlabb	r6, r10, lr, r6\n\t"
        "pkhtb	r6, r6, r12, ASR #16\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r6, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r6, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	r6, r6, #16\n\t"
#else
        "sbfx	r6, r6, #16, #16\n\t"
#endif
        "mul	r6, lr, r6\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r6, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r6, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r6, r10, lr, r6\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
        "ror	r6, r6, #16\n\t"
        "orr	r6, r6, r12, lsl #16\n\t"
        "ror	r6, r6, #16\n\t"
#else
        "bfi	r6, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r7\n\t"
        "smulbt	r7, r11, r7\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r7\n\t"
        "smlabb	r7, r10, lr, r7\n\t"
        "pkhtb	r7, r7, r12, ASR #16\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r7, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r7, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	r7, r7, #16\n\t"
#else
        "sbfx	r7, r7, #16, #16\n\t"
#endif
        "mul	r7, lr, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r7, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r7, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r7, r10, lr, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
        "ror	r7, r7, #16\n\t"
        "orr	r7, r7, r12, lsl #16\n\t"
        "ror	r7, r7, #16\n\t"
#else
        "bfi	r7, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r8\n\t"
        "smulbt	r8, r11, r8\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r8\n\t"
        "smlabb	r8, r10, lr, r8\n\t"
        "pkhtb	r8, r8, r12, ASR #16\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r8, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r8, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	r8, r8, #16\n\t"
#else
        "sbfx	r8, r8, #16, #16\n\t"
#endif
        "mul	r8, lr, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r8, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r8, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r8, r10, lr, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
        "ror	r8, r8, #16\n\t"
        "orr	r8, r8, r12, lsl #16\n\t"
        "ror	r8, r8, #16\n\t"
#else
        "bfi	r8, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smulbb	r12, r11, r9\n\t"
        "smulbt	r9, r11, r9\n\t"
        "smultb	lr, r10, r12\n\t"
        "smlabb	r12, r10, lr, r12\n\t"
        "smultb	lr, r10, r9\n\t"
        "smlabb	r9, r10, lr, r9\n\t"
        "pkhtb	r9, r9, r12, ASR #16\n\t"
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r11, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r11, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r9, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r9, #0, #16\n\t"
#endif
        "mul	r12, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "asr	r9, r9, #16\n\t"
#else
        "sbfx	r9, r9, #16, #16\n\t"
#endif
        "mul	r9, lr, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
        "mul	lr, r10, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "mla	r12, r10, lr, r12\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xc\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0xff\n\t"
#else
        "mov	r10, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, r9, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, r9, #0, #16\n\t"
#endif
        "mul	lr, r10, lr\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r10, #0xd\n\t"
        "lsl	r10, r10, #8\n\t"
        "add	r10, r10, #0x1\n\t"
#else
        "mov	r10, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	lr, lr, #16\n\t"
        "asr	lr, lr, #16\n\t"
#else
        "sbfx	lr, lr, #0, #16\n\t"
#endif
        "lsr	r12, r12, #16\n\t"
        "mla	r9, r10, lr, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
        "ror	r9, r9, #16\n\t"
        "orr	r9, r9, r12, lsl #16\n\t"
        "ror	r9, r9, #16\n\t"
#else
        "bfi	r9, r12, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "str	r2, [%[r]]\n\t"
        "str	r3, [%[r], #64]\n\t"
        "str	r4, [%[r], #128]\n\t"
        "str	r5, [%[r], #192]\n\t"
        "str	r6, [%[r], #256]\n\t"
        "str	r7, [%[r], #320]\n\t"
        "str	r8, [%[r], #384]\n\t"
        "str	r9, [%[r], #448]\n\t"
        "ldr	r2, [sp]\n\t"
        "subs	r2, r2, #1\n\t"
        "add	%[r], %[r], #4\n\t"
        "bne	L_kyber_arm32_invntt_loop_321_%=\n\t"
        "add	sp, sp, #8\n\t"
        : [r] "+r" (r),
          [L_kyber_arm32_invntt_zetas_inv] "+r" (L_kyber_arm32_invntt_zetas_inv_c)
        :
        : "memory", "cc", "r2", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8",
            "r9", "r10", "r11"
    );
}

static const word16 L_kyber_arm32_basemul_mont_zetas[] = {
    0x08ed, 0x0a0b, 0x0b9a, 0x0714,
    0x05d5, 0x058e, 0x011f, 0x00ca,
    0x0c56, 0x026e, 0x0629, 0x00b6,
    0x03c2, 0x084f, 0x073f, 0x05bc,
    0x023d, 0x07d4, 0x0108, 0x017f,
    0x09c4, 0x05b2, 0x06bf, 0x0c7f,
    0x0a58, 0x03f9, 0x02dc, 0x0260,
    0x06fb, 0x019b, 0x0c34, 0x06de,
    0x04c7, 0x028c, 0x0ad9, 0x03f7,
    0x07f4, 0x05d3, 0x0be7, 0x06f9,
    0x0204, 0x0cf9, 0x0bc1, 0x0a67,
    0x06af, 0x0877, 0x007e, 0x05bd,
    0x09ac, 0x0ca7, 0x0bf2, 0x033e,
    0x006b, 0x0774, 0x0c0a, 0x094a,
    0x0b73, 0x03c1, 0x071d, 0x0a2c,
    0x01c0, 0x08d8, 0x02a5, 0x0806,
    0x08b2, 0x01ae, 0x022b, 0x034b,
    0x081e, 0x0367, 0x060e, 0x0069,
    0x01a6, 0x024b, 0x00b1, 0x0c16,
    0x0bde, 0x0b35, 0x0626, 0x0675,
    0x0c0b, 0x030a, 0x0487, 0x0c6e,
    0x09f8, 0x05cb, 0x0aa7, 0x045f,
    0x06cb, 0x0284, 0x0999, 0x015d,
    0x01a2, 0x0149, 0x0c65, 0x0cb6,
    0x0331, 0x0449, 0x025b, 0x0262,
    0x052a, 0x07fc, 0x0748, 0x0180,
    0x0842, 0x0c79, 0x04c2, 0x07ca,
    0x0997, 0x00dc, 0x085e, 0x0686,
    0x0860, 0x0707, 0x0803, 0x031a,
    0x071b, 0x09ab, 0x099b, 0x01de,
    0x0c95, 0x0bcd, 0x03e4, 0x03df,
    0x03be, 0x074d, 0x05f2, 0x065c,
};

void kyber_arm32_basemul_mont(sword16* r_p, const sword16* a_p,
    const sword16* b_p)
{
    register sword16* r asm ("r0") = (sword16*)r_p;
    register const sword16* a asm ("r1") = (const sword16*)a_p;
    register const sword16* b asm ("r2") = (const sword16*)b_p;
    register word16* L_kyber_arm32_basemul_mont_zetas_c asm ("r3") =
        (word16*)&L_kyber_arm32_basemul_mont_zetas;

    __asm__ __volatile__ (
        "add	r3, r3, #0x80\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xd\n\t"
        "lsl	r12, r12, #8\n\t"
        "add	r12, r12, #0x1\n\t"
#else
        "mov	r12, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "orr	r12, r12, #0xc000000\n\t"
        "orr	r12, r12, #0xff0000\n\t"
#else
        "movt	r12, #0xcff\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "mov	r8, #0\n\t"
        "\n"
    "L_kyber_arm32_basemul_mont_loop_%=: \n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r7}\n\t"
        "ldr	lr, [r3, r8]\n\t"
        "add	r8, r8, #2\n\t"
        "push	{r8}\n\t"
        "cmp	r8, #0x80\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smultt	r8, r4, r6\n\t"
        "smultt	r10, r5, r7\n\t"
        "smultb	r9, r12, r8\n\t"
        "smultb	r11, r12, r10\n\t"
        "smlabb	r8, r12, r9, r8\n\t"
        "smlabb	r10, r12, r11, r10\n\t"
        "rsb	r11, lr, #0\n\t"
        "smulbt	r8, lr, r8\n\t"
        "smulbt	r10, r11, r10\n\t"
        "smlabb	r8, r4, r6, r8\n\t"
        "smlabb	r10, r5, r7, r10\n\t"
        "smultb	r9, r12, r8\n\t"
        "smultb	r11, r12, r10\n\t"
        "smlabb	r8, r12, r9, r8\n\t"
        "smlabb	r10, r12, r11, r10\n\t"
        "smulbt	r9, r4, r6\n\t"
        "smulbt	r11, r5, r7\n\t"
        "smlatb	r9, r4, r6, r9\n\t"
        "smlatb	r11, r5, r7, r11\n\t"
        "smultb	r6, r12, r9\n\t"
        "smultb	r7, r12, r11\n\t"
        "smlabb	r9, r12, r6, r9\n\t"
        "smlabb	r11, r12, r7, r11\n\t"
        "pkhtb	r4, r9, r8, ASR #16\n\t"
        "pkhtb	r5, r11, r10, ASR #16\n\t"
#else
        "asr	r8, r4, #16\n\t"
        "asr	r10, r5, #16\n\t"
        "asr	r9, r6, #16\n\t"
        "asr	r11, r7, #16\n\t"
        "mul	r8, r9, r8\n\t"
        "mul	r10, r11, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xc\n\t"
        "lsl	r12, r12, #8\n\t"
        "add	r12, r12, #0xff\n\t"
#else
        "mov	r12, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r9, r8, #16\n\t"
        "asr	r9, r9, #16\n\t"
#else
        "sbfx	r9, r8, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r11, r10, #16\n\t"
        "asr	r11, r11, #16\n\t"
#else
        "sbfx	r11, r10, #0, #16\n\t"
#endif
        "mul	r9, r12, r8\n\t"
        "mul	r11, r12, r11\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xd\n\t"
        "lsl	r12, r12, #8\n\t"
        "add	r12, r12, #0x1\n\t"
#else
        "mov	r12, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r9, r9, #16\n\t"
        "asr	r9, r9, #16\n\t"
#else
        "sbfx	r9, r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r11, r11, #16\n\t"
        "asr	r11, r11, #16\n\t"
#else
        "sbfx	r11, r11, #0, #16\n\t"
#endif
        "mla	r8, r12, r9, r8\n\t"
        "mla	r10, r12, r11, r10\n\t"
        "rsb	r11, lr, #0\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r9, lr, #16\n\t"
        "asr	r9, r9, #16\n\t"
#else
        "sbfx	r9, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r11, r11, #16\n\t"
        "asr	r11, r11, #16\n\t"
#else
        "sbfx	r11, r11, #0, #16\n\t"
#endif
        "asr	r8, r8, #16\n\t"
        "asr	r10, r10, #16\n\t"
        "mul	r8, r9, r8\n\t"
        "mul	r10, r11, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r9, r4, #16\n\t"
        "asr	r9, r9, #16\n\t"
#else
        "sbfx	r9, r4, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r11, r5, #16\n\t"
        "asr	r11, r11, #16\n\t"
#else
        "sbfx	r11, r5, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r6, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r6, #0, #16\n\t"
#endif
        "mla	r8, r9, r12, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r7, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r7, #0, #16\n\t"
#endif
        "mla	r10, r11, r12, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xc\n\t"
        "lsl	r12, r12, #8\n\t"
        "add	r12, r12, #0xff\n\t"
#else
        "mov	r12, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r9, r8, #16\n\t"
        "asr	r9, r9, #16\n\t"
#else
        "sbfx	r9, r8, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r11, r10, #16\n\t"
        "asr	r11, r11, #16\n\t"
#else
        "sbfx	r11, r10, #0, #16\n\t"
#endif
        "mul	r9, r12, r9\n\t"
        "mul	r11, r12, r11\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xd\n\t"
        "lsl	r12, r12, #8\n\t"
        "add	r12, r12, #0x1\n\t"
#else
        "mov	r12, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r9, r9, #16\n\t"
        "asr	r9, r9, #16\n\t"
#else
        "sbfx	r9, r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r11, r11, #16\n\t"
        "asr	r11, r11, #16\n\t"
#else
        "sbfx	r11, r11, #0, #16\n\t"
#endif
        "mla	r8, r12, r9, r8\n\t"
        "mla	r10, r12, r11, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r9, r4, #16\n\t"
        "asr	r9, r9, #16\n\t"
#else
        "sbfx	r9, r4, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r11, r5, #16\n\t"
        "asr	r11, r11, #16\n\t"
#else
        "sbfx	r11, r5, #0, #16\n\t"
#endif
        "asr	r12, r6, #16\n\t"
        "mul	r9, r12, r9\n\t"
        "asr	r12, r7, #16\n\t"
        "mul	r11, r12, r11\n\t"
        "asr	r4, r4, #16\n\t"
        "asr	r5, r5, #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r6, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r6, #0, #16\n\t"
#endif
        "mla	r9, r4, r12, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r7, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r7, #0, #16\n\t"
#endif
        "mla	r11, r5, r12, r11\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xc\n\t"
        "lsl	r12, r12, #8\n\t"
        "add	r12, r12, #0xff\n\t"
#else
        "mov	r12, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r6, r9, #16\n\t"
        "asr	r6, r6, #16\n\t"
#else
        "sbfx	r6, r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r7, r11, #16\n\t"
        "asr	r7, r7, #16\n\t"
#else
        "sbfx	r7, r11, #0, #16\n\t"
#endif
        "mul	r6, r12, r6\n\t"
        "mul	r7, r12, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xd\n\t"
        "lsl	r12, r12, #8\n\t"
        "add	r12, r12, #0x1\n\t"
#else
        "mov	r12, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r4, r6, #16\n\t"
        "asr	r4, r4, #16\n\t"
#else
        "sbfx	r4, r6, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r5, r7, #16\n\t"
        "asr	r5, r5, #16\n\t"
#else
        "sbfx	r5, r7, #0, #16\n\t"
#endif
        "mla	r9, r12, r4, r9\n\t"
        "mla	r11, r12, r5, r11\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
#else
        "bfc	r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r11, r11, #0xff\n\t"
        "bic	r11, r11, #0xff00\n\t"
#else
        "bfc	r11, #0, #16\n\t"
#endif
        "orr	r4, r9, r8, lsr #16\n\t"
        "orr	r5, r11, r10, lsr #16\n\t"
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "stm	%[r]!, {r4, r5}\n\t"
        "pop	{r8}\n\t"
        "bne	L_kyber_arm32_basemul_mont_loop_%=\n\t"
        : [r] "+r" (r), [a] "+r" (a), [b] "+r" (b),
          [L_kyber_arm32_basemul_mont_zetas] "+r" (L_kyber_arm32_basemul_mont_zetas_c)
        :
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9",
            "r10", "r11"
    );
}

void kyber_arm32_basemul_mont_add(sword16* r_p, const sword16* a_p,
    const sword16* b_p)
{
    register sword16* r asm ("r0") = (sword16*)r_p;
    register const sword16* a asm ("r1") = (const sword16*)a_p;
    register const sword16* b asm ("r2") = (const sword16*)b_p;
    register word16* L_kyber_arm32_basemul_mont_zetas_c asm ("r3") =
        (word16*)&L_kyber_arm32_basemul_mont_zetas;

    __asm__ __volatile__ (
        "add	r3, r3, #0x80\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xd\n\t"
        "lsl	r12, r12, #8\n\t"
        "add	r12, r12, #0x1\n\t"
#else
        "mov	r12, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "orr	r12, r12, #0xc000000\n\t"
        "orr	r12, r12, #0xff0000\n\t"
#else
        "movt	r12, #0xcff\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "mov	r8, #0\n\t"
        "\n"
    "L_kyber_arm32_basemul_mont_add_loop_%=: \n\t"
        "ldm	%[a]!, {r4, r5}\n\t"
        "ldm	%[b]!, {r6, r7}\n\t"
        "ldr	lr, [r3, r8]\n\t"
        "add	r8, r8, #2\n\t"
        "push	{r8}\n\t"
        "cmp	r8, #0x80\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "smultt	r8, r4, r6\n\t"
        "smultt	r10, r5, r7\n\t"
        "smultb	r9, r12, r8\n\t"
        "smultb	r11, r12, r10\n\t"
        "smlabb	r8, r12, r9, r8\n\t"
        "smlabb	r10, r12, r11, r10\n\t"
        "rsb	r11, lr, #0\n\t"
        "smulbt	r8, lr, r8\n\t"
        "smulbt	r10, r11, r10\n\t"
        "smlabb	r8, r4, r6, r8\n\t"
        "smlabb	r10, r5, r7, r10\n\t"
        "smultb	r9, r12, r8\n\t"
        "smultb	r11, r12, r10\n\t"
        "smlabb	r8, r12, r9, r8\n\t"
        "smlabb	r10, r12, r11, r10\n\t"
        "smulbt	r9, r4, r6\n\t"
        "smulbt	r11, r5, r7\n\t"
        "smlatb	r9, r4, r6, r9\n\t"
        "smlatb	r11, r5, r7, r11\n\t"
        "smultb	r6, r12, r9\n\t"
        "smultb	r7, r12, r11\n\t"
        "smlabb	r9, r12, r6, r9\n\t"
        "smlabb	r11, r12, r7, r11\n\t"
        "ldm	%[r], {r4, r5}\n\t"
        "pkhtb	r9, r9, r8, ASR #16\n\t"
        "pkhtb	r11, r11, r10, ASR #16\n\t"
        "sadd16	r4, r4, r9\n\t"
        "sadd16	r5, r5, r11\n\t"
#else
        "asr	r8, r4, #16\n\t"
        "asr	r10, r5, #16\n\t"
        "asr	r9, r6, #16\n\t"
        "asr	r11, r7, #16\n\t"
        "mul	r8, r9, r8\n\t"
        "mul	r10, r11, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xc\n\t"
        "lsl	r12, r12, #8\n\t"
        "add	r12, r12, #0xff\n\t"
#else
        "mov	r12, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r9, r8, #16\n\t"
        "asr	r9, r9, #16\n\t"
#else
        "sbfx	r9, r8, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r11, r10, #16\n\t"
        "asr	r11, r11, #16\n\t"
#else
        "sbfx	r11, r10, #0, #16\n\t"
#endif
        "mul	r9, r12, r8\n\t"
        "mul	r11, r12, r11\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xd\n\t"
        "lsl	r12, r12, #8\n\t"
        "add	r12, r12, #0x1\n\t"
#else
        "mov	r12, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r9, r9, #16\n\t"
        "asr	r9, r9, #16\n\t"
#else
        "sbfx	r9, r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r11, r11, #16\n\t"
        "asr	r11, r11, #16\n\t"
#else
        "sbfx	r11, r11, #0, #16\n\t"
#endif
        "mla	r8, r12, r9, r8\n\t"
        "mla	r10, r12, r11, r10\n\t"
        "rsb	r11, lr, #0\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r9, lr, #16\n\t"
        "asr	r9, r9, #16\n\t"
#else
        "sbfx	r9, lr, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r11, r11, #16\n\t"
        "asr	r11, r11, #16\n\t"
#else
        "sbfx	r11, r11, #0, #16\n\t"
#endif
        "asr	r8, r8, #16\n\t"
        "asr	r10, r10, #16\n\t"
        "mul	r8, r9, r8\n\t"
        "mul	r10, r11, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r9, r4, #16\n\t"
        "asr	r9, r9, #16\n\t"
#else
        "sbfx	r9, r4, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r11, r5, #16\n\t"
        "asr	r11, r11, #16\n\t"
#else
        "sbfx	r11, r5, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r6, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r6, #0, #16\n\t"
#endif
        "mla	r8, r9, r12, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r7, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r7, #0, #16\n\t"
#endif
        "mla	r10, r11, r12, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xc\n\t"
        "lsl	r12, r12, #8\n\t"
        "add	r12, r12, #0xff\n\t"
#else
        "mov	r12, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r9, r8, #16\n\t"
        "asr	r9, r9, #16\n\t"
#else
        "sbfx	r9, r8, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r11, r10, #16\n\t"
        "asr	r11, r11, #16\n\t"
#else
        "sbfx	r11, r10, #0, #16\n\t"
#endif
        "mul	r9, r12, r9\n\t"
        "mul	r11, r12, r11\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xd\n\t"
        "lsl	r12, r12, #8\n\t"
        "add	r12, r12, #0x1\n\t"
#else
        "mov	r12, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r9, r9, #16\n\t"
        "asr	r9, r9, #16\n\t"
#else
        "sbfx	r9, r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r11, r11, #16\n\t"
        "asr	r11, r11, #16\n\t"
#else
        "sbfx	r11, r11, #0, #16\n\t"
#endif
        "mla	r8, r12, r9, r8\n\t"
        "mla	r10, r12, r11, r10\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r9, r4, #16\n\t"
        "asr	r9, r9, #16\n\t"
#else
        "sbfx	r9, r4, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r11, r5, #16\n\t"
        "asr	r11, r11, #16\n\t"
#else
        "sbfx	r11, r5, #0, #16\n\t"
#endif
        "asr	r12, r6, #16\n\t"
        "mul	r9, r12, r9\n\t"
        "asr	r12, r7, #16\n\t"
        "mul	r11, r12, r11\n\t"
        "asr	r4, r4, #16\n\t"
        "asr	r5, r5, #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r6, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r6, #0, #16\n\t"
#endif
        "mla	r9, r4, r12, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r12, r7, #16\n\t"
        "asr	r12, r12, #16\n\t"
#else
        "sbfx	r12, r7, #0, #16\n\t"
#endif
        "mla	r11, r5, r12, r11\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xc\n\t"
        "lsl	r12, r12, #8\n\t"
        "add	r12, r12, #0xff\n\t"
#else
        "mov	r12, #0xcff\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r6, r9, #16\n\t"
        "asr	r6, r6, #16\n\t"
#else
        "sbfx	r6, r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r7, r11, #16\n\t"
        "asr	r7, r7, #16\n\t"
#else
        "sbfx	r7, r11, #0, #16\n\t"
#endif
        "mul	r6, r12, r6\n\t"
        "mul	r7, r12, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xd\n\t"
        "lsl	r12, r12, #8\n\t"
        "add	r12, r12, #0x1\n\t"
#else
        "mov	r12, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r4, r6, #16\n\t"
        "asr	r4, r4, #16\n\t"
#else
        "sbfx	r4, r6, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r5, r7, #16\n\t"
        "asr	r5, r5, #16\n\t"
#else
        "sbfx	r5, r7, #0, #16\n\t"
#endif
        "mla	r9, r12, r4, r9\n\t"
        "mla	r11, r12, r5, r11\n\t"
        "ldm	%[r], {r4, r5}\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
#else
        "bfc	r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r11, r11, #0xff\n\t"
        "bic	r11, r11, #0xff00\n\t"
#else
        "bfc	r11, #0, #16\n\t"
#endif
        "orr	r9, r9, r8, lsr #16\n\t"
        "orr	r11, r11, r10, lsr #16\n\t"
        "add	r8, r4, r9\n\t"
        "add	r10, r5, r11\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
#else
        "bfc	r9, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r11, r11, #0xff\n\t"
        "bic	r11, r11, #0xff00\n\t"
#else
        "bfc	r11, #0, #16\n\t"
#endif
        "add	r4, r4, r9\n\t"
        "add	r5, r5, r11\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
        "ror	r4, r4, #16\n\t"
        "orr	r4, r4, r8, lsl #16\n\t"
        "ror	r4, r4, #16\n\t"
#else
        "bfi	r4, r8, #0, #16\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
        "ror	r5, r5, #16\n\t"
        "orr	r5, r5, r10, lsl #16\n\t"
        "ror	r5, r5, #16\n\t"
#else
        "bfi	r5, r10, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "stm	%[r]!, {r4, r5}\n\t"
        "pop	{r8}\n\t"
        "bne	L_kyber_arm32_basemul_mont_add_loop_%=\n\t"
        : [r] "+r" (r), [a] "+r" (a), [b] "+r" (b),
          [L_kyber_arm32_basemul_mont_zetas] "+r" (L_kyber_arm32_basemul_mont_zetas_c)
        :
        : "memory", "cc", "r12", "lr", "r4", "r5", "r6", "r7", "r8", "r9",
            "r10", "r11"
    );
}

void kyber_arm32_csubq(sword16* p_p)
{
    register sword16* p asm ("r0") = (sword16*)p_p;
    register word16* L_kyber_arm32_basemul_mont_zetas_c asm ("r1") =
        (word16*)&L_kyber_arm32_basemul_mont_zetas;

    __asm__ __volatile__ (
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r12, #0xd\n\t"
        "lsl	r12, r12, #8\n\t"
        "add	r12, r12, #0x1\n\t"
#else
        "mov	r12, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	lr, #0xd\n\t"
        "lsl	lr, lr, #8\n\t"
        "add	lr, lr, #0x1\n\t"
#else
        "mov	lr, #0xd01\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "orr	lr, lr, #0xd000000\n\t"
        "orr	lr, lr, #0x10000\n\t"
#else
        "movt	lr, #0xd01\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r11, #0x80\n\t"
        "lsl	r11, r11, #8\n\t"
        "add	r11, r11, #0x0\n\t"
#else
        "mov	r11, #0x8000\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "orr	r11, r11, #0x80000000\n\t"
#else
        "movt	r11, #0x8000\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r1, #0x1\n\t"
        "lsl	r1, r1, #8\n\t"
        "add	r1, r1, #0x0\n\t"
#else
        "mov	r1, #0x100\n\t"
#endif
        "\n"
    "L_kyber_arm32_csubq_loop_%=: \n\t"
        "ldm	%[p], {r2, r3, r4, r5}\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
        "ssub16	r2, r2, lr\n\t"
        "ssub16	r3, r3, lr\n\t"
        "ssub16	r4, r4, lr\n\t"
        "ssub16	r5, r5, lr\n\t"
        "and	r6, r2, r11\n\t"
        "and	r7, r3, r11\n\t"
        "and	r8, r4, r11\n\t"
        "and	r9, r5, r11\n\t"
        "lsr	r6, r6, #15\n\t"
        "lsr	r7, r7, #15\n\t"
        "lsr	r8, r8, #15\n\t"
        "lsr	r9, r9, #15\n\t"
        "mul	r6, r12, r6\n\t"
        "mul	r7, r12, r7\n\t"
        "mul	r8, r12, r8\n\t"
        "mul	r9, r12, r9\n\t"
        "sadd16	r2, r2, r6\n\t"
        "sadd16	r3, r3, r7\n\t"
        "sadd16	r4, r4, r8\n\t"
        "sadd16	r5, r5, r9\n\t"
#else
        "sub	r6, r2, lr\n\t"
        "sub	r2, r2, lr, lsl #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
        "ror	r2, r2, #16\n\t"
        "orr	r2, r2, r6, lsl #16\n\t"
        "ror	r2, r2, #16\n\t"
#else
        "bfi	r2, r6, #0, #16\n\t"
#endif
        "sub	r7, r3, lr\n\t"
        "sub	r3, r3, lr, lsl #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
        "ror	r3, r3, #16\n\t"
        "orr	r3, r3, r7, lsl #16\n\t"
        "ror	r3, r3, #16\n\t"
#else
        "bfi	r3, r7, #0, #16\n\t"
#endif
        "sub	r8, r4, lr\n\t"
        "sub	r4, r4, lr, lsl #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
        "ror	r4, r4, #16\n\t"
        "orr	r4, r4, r8, lsl #16\n\t"
        "ror	r4, r4, #16\n\t"
#else
        "bfi	r4, r8, #0, #16\n\t"
#endif
        "sub	r9, r5, lr\n\t"
        "sub	r5, r5, lr, lsl #16\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
        "ror	r5, r5, #16\n\t"
        "orr	r5, r5, r9, lsl #16\n\t"
        "ror	r5, r5, #16\n\t"
#else
        "bfi	r5, r9, #0, #16\n\t"
#endif
        "and	r6, r2, r11\n\t"
        "and	r7, r3, r11\n\t"
        "and	r8, r4, r11\n\t"
        "and	r9, r5, r11\n\t"
        "lsr	r6, r6, #15\n\t"
        "lsr	r7, r7, #15\n\t"
        "lsr	r8, r8, #15\n\t"
        "lsr	r9, r9, #15\n\t"
        "mul	r6, r12, r6\n\t"
        "mul	r7, r12, r7\n\t"
        "mul	r8, r12, r8\n\t"
        "mul	r9, r12, r9\n\t"
        "add	r10, r2, r6\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r6, r6, #0xff\n\t"
        "bic	r6, r6, #0xff00\n\t"
#else
        "bfc	r6, #0, #16\n\t"
#endif
        "add	r2, r2, r6\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r2, r2, #0xff\n\t"
        "bic	r2, r2, #0xff00\n\t"
        "ror	r2, r2, #16\n\t"
        "orr	r2, r2, r10, lsl #16\n\t"
        "ror	r2, r2, #16\n\t"
#else
        "bfi	r2, r10, #0, #16\n\t"
#endif
        "add	r10, r3, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff\n\t"
        "bic	r7, r7, #0xff00\n\t"
#else
        "bfc	r7, #0, #16\n\t"
#endif
        "add	r3, r3, r7\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r3, r3, #0xff\n\t"
        "bic	r3, r3, #0xff00\n\t"
        "ror	r3, r3, #16\n\t"
        "orr	r3, r3, r10, lsl #16\n\t"
        "ror	r3, r3, #16\n\t"
#else
        "bfi	r3, r10, #0, #16\n\t"
#endif
        "add	r10, r4, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r8, r8, #0xff\n\t"
        "bic	r8, r8, #0xff00\n\t"
#else
        "bfc	r8, #0, #16\n\t"
#endif
        "add	r4, r4, r8\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r4, r4, #0xff\n\t"
        "bic	r4, r4, #0xff00\n\t"
        "ror	r4, r4, #16\n\t"
        "orr	r4, r4, r10, lsl #16\n\t"
        "ror	r4, r4, #16\n\t"
#else
        "bfi	r4, r10, #0, #16\n\t"
#endif
        "add	r10, r5, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r9, r9, #0xff\n\t"
        "bic	r9, r9, #0xff00\n\t"
#else
        "bfc	r9, #0, #16\n\t"
#endif
        "add	r5, r5, r9\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r5, r5, #0xff\n\t"
        "bic	r5, r5, #0xff00\n\t"
        "ror	r5, r5, #16\n\t"
        "orr	r5, r5, r10, lsl #16\n\t"
        "ror	r5, r5, #16\n\t"
#else
        "bfi	r5, r10, #0, #16\n\t"
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
        "stm	%[p]!, {r2, r3, r4, r5}\n\t"
        "subs	r1, r1, #8\n\t"
        "bne	L_kyber_arm32_csubq_loop_%=\n\t"
        : [p] "+r" (p),
          [L_kyber_arm32_basemul_mont_zetas] "+r" (L_kyber_arm32_basemul_mont_zetas_c)
        :
        : "memory", "cc", "r2", "r3", "r12", "lr", "r4", "r5", "r6", "r7", "r8",
            "r9", "r10", "r11"
    );
}

unsigned int kyber_arm32_rej_uniform(sword16* p_p, unsigned int len_p,
    const byte* r_p, unsigned int rLen_p)
{
    register sword16* p asm ("r0") = (sword16*)p_p;
    register unsigned int len asm ("r1") = (unsigned int)len_p;
    register const byte* r asm ("r2") = (const byte*)r_p;
    register unsigned int rLen asm ("r3") = (unsigned int)rLen_p;
    register word16* L_kyber_arm32_basemul_mont_zetas_c asm ("r4") =
        (word16*)&L_kyber_arm32_basemul_mont_zetas;

    __asm__ __volatile__ (
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "mov	r8, #0xd\n\t"
        "lsl	r8, r8, #8\n\t"
        "add	r8, r8, #0x1\n\t"
#else
        "mov	r8, #0xd01\n\t"
#endif
        "mov	r12, #0\n\t"
        "\n"
    "L_kyber_arm32_rej_uniform_loop_no_fail_%=: \n\t"
        "cmp	%[len], #8\n\t"
        "blt	L_kyber_arm32_rej_uniform_done_no_fail_%=\n\t"
        "ldm	%[r]!, {r4, r5, r6}\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r7, r4, #20\n\t"
        "lsr	r7, r7, #20\n\t"
#else
        "ubfx	r7, r4, #0, #12\n\t"
#endif
        "strh	r7, [%[p], r12]\n\t"
        "sub	lr, r7, r8\n\t"
        "lsr	lr, lr, #31\n\t"
        "sub	%[len], %[len], lr\n\t"
        "add	r12, r12, lr, lsl #1\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r7, r4, #8\n\t"
        "lsr	r7, r7, #20\n\t"
#else
        "ubfx	r7, r4, #12, #12\n\t"
#endif
        "strh	r7, [%[p], r12]\n\t"
        "sub	lr, r7, r8\n\t"
        "lsr	lr, lr, #31\n\t"
        "sub	%[len], %[len], lr\n\t"
        "add	r12, r12, lr, lsl #1\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsr	r7, r4, #24\n\t"
#else
        "ubfx	r7, r4, #24, #8\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xf00\n\t"
        "ror	r7, r7, #12\n\t"
        "orr	r7, r7, r5, lsl #28\n\t"
        "ror	r7, r7, #20\n\t"
#else
        "bfi	r7, r5, #8, #4\n\t"
#endif
        "strh	r7, [%[p], r12]\n\t"
        "sub	lr, r7, r8\n\t"
        "lsr	lr, lr, #31\n\t"
        "sub	%[len], %[len], lr\n\t"
        "add	r12, r12, lr, lsl #1\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r7, r5, #16\n\t"
        "lsr	r7, r7, #20\n\t"
#else
        "ubfx	r7, r5, #4, #12\n\t"
#endif
        "strh	r7, [%[p], r12]\n\t"
        "sub	lr, r7, r8\n\t"
        "lsr	lr, lr, #31\n\t"
        "sub	%[len], %[len], lr\n\t"
        "add	r12, r12, lr, lsl #1\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r7, r5, #4\n\t"
        "lsr	r7, r7, #20\n\t"
#else
        "ubfx	r7, r5, #16, #12\n\t"
#endif
        "strh	r7, [%[p], r12]\n\t"
        "sub	lr, r7, r8\n\t"
        "lsr	lr, lr, #31\n\t"
        "sub	%[len], %[len], lr\n\t"
        "add	r12, r12, lr, lsl #1\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsr	r7, r5, #28\n\t"
#else
        "ubfx	r7, r5, #28, #4\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff0\n\t"
        "ror	r7, r7, #12\n\t"
        "orr	r7, r7, r6, lsl #24\n\t"
        "ror	r7, r7, #20\n\t"
#else
        "bfi	r7, r6, #4, #8\n\t"
#endif
        "strh	r7, [%[p], r12]\n\t"
        "sub	lr, r7, r8\n\t"
        "lsr	lr, lr, #31\n\t"
        "sub	%[len], %[len], lr\n\t"
        "add	r12, r12, lr, lsl #1\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r7, r6, #12\n\t"
        "lsr	r7, r7, #20\n\t"
#else
        "ubfx	r7, r6, #8, #12\n\t"
#endif
        "strh	r7, [%[p], r12]\n\t"
        "sub	lr, r7, r8\n\t"
        "lsr	lr, lr, #31\n\t"
        "sub	%[len], %[len], lr\n\t"
        "add	r12, r12, lr, lsl #1\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsr	r7, r6, #20\n\t"
#else
        "ubfx	r7, r6, #20, #12\n\t"
#endif
        "strh	r7, [%[p], r12]\n\t"
        "sub	lr, r7, r8\n\t"
        "lsr	lr, lr, #31\n\t"
        "sub	%[len], %[len], lr\n\t"
        "add	r12, r12, lr, lsl #1\n\t"
        "subs	%[rLen], %[rLen], #12\n\t"
        "bne	L_kyber_arm32_rej_uniform_loop_no_fail_%=\n\t"
        "b	L_kyber_arm32_rej_uniform_done_%=\n\t"
        "\n"
    "L_kyber_arm32_rej_uniform_done_no_fail_%=: \n\t"
        "cmp	%[len], #0\n\t"
        "beq	L_kyber_arm32_rej_uniform_done_%=\n\t"
        "\n"
    "L_kyber_arm32_rej_uniform_loop_%=: \n\t"
        "ldm	%[r]!, {r4, r5, r6}\n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r7, r4, #20\n\t"
        "lsr	r7, r7, #20\n\t"
#else
        "ubfx	r7, r4, #0, #12\n\t"
#endif
        "cmp	r7, r8\n\t"
        "bge	L_kyber_arm32_rej_uniform_fail_0_%=\n\t"
        "strh	r7, [%[p], r12]\n\t"
        "subs	%[len], %[len], #1\n\t"
        "add	r12, r12, #2\n\t"
        "beq	L_kyber_arm32_rej_uniform_done_%=\n\t"
        "\n"
    "L_kyber_arm32_rej_uniform_fail_0_%=: \n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r7, r4, #8\n\t"
        "lsr	r7, r7, #20\n\t"
#else
        "ubfx	r7, r4, #12, #12\n\t"
#endif
        "cmp	r7, r8\n\t"
        "bge	L_kyber_arm32_rej_uniform_fail_1_%=\n\t"
        "strh	r7, [%[p], r12]\n\t"
        "subs	%[len], %[len], #1\n\t"
        "add	r12, r12, #2\n\t"
        "beq	L_kyber_arm32_rej_uniform_done_%=\n\t"
        "\n"
    "L_kyber_arm32_rej_uniform_fail_1_%=: \n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsr	r7, r4, #24\n\t"
#else
        "ubfx	r7, r4, #24, #8\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xf00\n\t"
        "ror	r7, r7, #12\n\t"
        "orr	r7, r7, r5, lsl #28\n\t"
        "ror	r7, r7, #20\n\t"
#else
        "bfi	r7, r5, #8, #4\n\t"
#endif
        "cmp	r7, r8\n\t"
        "bge	L_kyber_arm32_rej_uniform_fail_2_%=\n\t"
        "strh	r7, [%[p], r12]\n\t"
        "subs	%[len], %[len], #1\n\t"
        "add	r12, r12, #2\n\t"
        "beq	L_kyber_arm32_rej_uniform_done_%=\n\t"
        "\n"
    "L_kyber_arm32_rej_uniform_fail_2_%=: \n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r7, r5, #16\n\t"
        "lsr	r7, r7, #20\n\t"
#else
        "ubfx	r7, r5, #4, #12\n\t"
#endif
        "cmp	r7, r8\n\t"
        "bge	L_kyber_arm32_rej_uniform_fail_3_%=\n\t"
        "strh	r7, [%[p], r12]\n\t"
        "subs	%[len], %[len], #1\n\t"
        "add	r12, r12, #2\n\t"
        "beq	L_kyber_arm32_rej_uniform_done_%=\n\t"
        "\n"
    "L_kyber_arm32_rej_uniform_fail_3_%=: \n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r7, r5, #4\n\t"
        "lsr	r7, r7, #20\n\t"
#else
        "ubfx	r7, r5, #16, #12\n\t"
#endif
        "cmp	r7, r8\n\t"
        "bge	L_kyber_arm32_rej_uniform_fail_4_%=\n\t"
        "strh	r7, [%[p], r12]\n\t"
        "subs	%[len], %[len], #1\n\t"
        "add	r12, r12, #2\n\t"
        "beq	L_kyber_arm32_rej_uniform_done_%=\n\t"
        "\n"
    "L_kyber_arm32_rej_uniform_fail_4_%=: \n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsr	r7, r5, #28\n\t"
#else
        "ubfx	r7, r5, #28, #4\n\t"
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "bic	r7, r7, #0xff0\n\t"
        "ror	r7, r7, #12\n\t"
        "orr	r7, r7, r6, lsl #24\n\t"
        "ror	r7, r7, #20\n\t"
#else
        "bfi	r7, r6, #4, #8\n\t"
#endif
        "cmp	r7, r8\n\t"
        "bge	L_kyber_arm32_rej_uniform_fail_5_%=\n\t"
        "strh	r7, [%[p], r12]\n\t"
        "subs	%[len], %[len], #1\n\t"
        "add	r12, r12, #2\n\t"
        "beq	L_kyber_arm32_rej_uniform_done_%=\n\t"
        "\n"
    "L_kyber_arm32_rej_uniform_fail_5_%=: \n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsl	r7, r6, #12\n\t"
        "lsr	r7, r7, #20\n\t"
#else
        "ubfx	r7, r6, #8, #12\n\t"
#endif
        "cmp	r7, r8\n\t"
        "bge	L_kyber_arm32_rej_uniform_fail_6_%=\n\t"
        "strh	r7, [%[p], r12]\n\t"
        "subs	%[len], %[len], #1\n\t"
        "add	r12, r12, #2\n\t"
        "beq	L_kyber_arm32_rej_uniform_done_%=\n\t"
        "\n"
    "L_kyber_arm32_rej_uniform_fail_6_%=: \n\t"
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
        "lsr	r7, r6, #20\n\t"
#else
        "ubfx	r7, r6, #20, #12\n\t"
#endif
        "cmp	r7, r8\n\t"
        "bge	L_kyber_arm32_rej_uniform_fail_7_%=\n\t"
        "strh	r7, [%[p], r12]\n\t"
        "subs	%[len], %[len], #1\n\t"
        "add	r12, r12, #2\n\t"
        "beq	L_kyber_arm32_rej_uniform_done_%=\n\t"
        "\n"
    "L_kyber_arm32_rej_uniform_fail_7_%=: \n\t"
        "subs	%[rLen], %[rLen], #12\n\t"
        "bgt	L_kyber_arm32_rej_uniform_loop_%=\n\t"
        "\n"
    "L_kyber_arm32_rej_uniform_done_%=: \n\t"
        "lsr	r0, r12, #1\n\t"
        : [p] "+r" (p), [len] "+r" (len), [r] "+r" (r), [rLen] "+r" (rLen),
          [L_kyber_arm32_basemul_mont_zetas] "+r" (L_kyber_arm32_basemul_mont_zetas_c)
        :
        : "memory", "cc", "r12", "lr", "r5", "r6", "r7", "r8"
    );
    return (word32)(size_t)p;
}

#endif /* WOLFSSL_WC_KYBER */
#endif /* !__aarch64__ && !WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#endif /* WOLFSSL_ARMASM_INLINE */
