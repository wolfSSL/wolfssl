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
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-32-kyber-asm.S
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_ARMASM
#if !defined(__aarch64__) && !defined(WOLFSSL_ARMASM_THUMB2)
#ifndef WOLFSSL_ARMASM_INLINE
#ifdef WOLFSSL_WC_KYBER
	.text
	.type	L_kyber_arm32_ntt_zetas, %object
	.size	L_kyber_arm32_ntt_zetas, 256
	.align	4
L_kyber_arm32_ntt_zetas:
	.short	0x8ed
	.short	0xa0b
	.short	0xb9a
	.short	0x714
	.short	0x5d5
	.short	0x58e
	.short	0x11f
	.short	0xca
	.short	0xc56
	.short	0x26e
	.short	0x629
	.short	0xb6
	.short	0x3c2
	.short	0x84f
	.short	0x73f
	.short	0x5bc
	.short	0x23d
	.short	0x7d4
	.short	0x108
	.short	0x17f
	.short	0x9c4
	.short	0x5b2
	.short	0x6bf
	.short	0xc7f
	.short	0xa58
	.short	0x3f9
	.short	0x2dc
	.short	0x260
	.short	0x6fb
	.short	0x19b
	.short	0xc34
	.short	0x6de
	.short	0x4c7
	.short	0x28c
	.short	0xad9
	.short	0x3f7
	.short	0x7f4
	.short	0x5d3
	.short	0xbe7
	.short	0x6f9
	.short	0x204
	.short	0xcf9
	.short	0xbc1
	.short	0xa67
	.short	0x6af
	.short	0x877
	.short	0x7e
	.short	0x5bd
	.short	0x9ac
	.short	0xca7
	.short	0xbf2
	.short	0x33e
	.short	0x6b
	.short	0x774
	.short	0xc0a
	.short	0x94a
	.short	0xb73
	.short	0x3c1
	.short	0x71d
	.short	0xa2c
	.short	0x1c0
	.short	0x8d8
	.short	0x2a5
	.short	0x806
	.short	0x8b2
	.short	0x1ae
	.short	0x22b
	.short	0x34b
	.short	0x81e
	.short	0x367
	.short	0x60e
	.short	0x69
	.short	0x1a6
	.short	0x24b
	.short	0xb1
	.short	0xc16
	.short	0xbde
	.short	0xb35
	.short	0x626
	.short	0x675
	.short	0xc0b
	.short	0x30a
	.short	0x487
	.short	0xc6e
	.short	0x9f8
	.short	0x5cb
	.short	0xaa7
	.short	0x45f
	.short	0x6cb
	.short	0x284
	.short	0x999
	.short	0x15d
	.short	0x1a2
	.short	0x149
	.short	0xc65
	.short	0xcb6
	.short	0x331
	.short	0x449
	.short	0x25b
	.short	0x262
	.short	0x52a
	.short	0x7fc
	.short	0x748
	.short	0x180
	.short	0x842
	.short	0xc79
	.short	0x4c2
	.short	0x7ca
	.short	0x997
	.short	0xdc
	.short	0x85e
	.short	0x686
	.short	0x860
	.short	0x707
	.short	0x803
	.short	0x31a
	.short	0x71b
	.short	0x9ab
	.short	0x99b
	.short	0x1de
	.short	0xc95
	.short	0xbcd
	.short	0x3e4
	.short	0x3df
	.short	0x3be
	.short	0x74d
	.short	0x5f2
	.short	0x65c
	.text
	.align	4
	.globl	kyber_arm32_ntt
	.type	kyber_arm32_ntt, %function
kyber_arm32_ntt:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #8
	adr	r1, L_kyber_arm32_ntt_zetas
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	orr	r10, r10, #0xc000000
	orr	r10, r10, #0xff0000
#else
	movt	r10, #0xcff
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	mov	r2, #16
L_kyber_arm32_ntt_loop_123:
	str	r2, [sp]
	ldrh	r11, [r1, #2]
	ldr	r2, [r0]
	ldr	r3, [r0, #64]
	ldr	r4, [r0, #128]
	ldr	r5, [r0, #192]
	ldr	r6, [r0, #256]
	ldr	r7, [r0, #320]
	ldr	r8, [r0, #384]
	ldr	r9, [r0, #448]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r6
	smulbt	r6, r11, r6
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r6
	smlabb	lr, r10, lr, r6
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r6, r2, r12
	sadd16	r2, r2, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r6, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r6, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r6, r6, #16
	mul	r12, lr, r12
	mul	r6, lr, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r6, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r6, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r6
	sub	r6, r2, lr
	add	r2, r2, lr
	sub	lr, r2, r12, lsr #16
	add	r12, r2, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
	ror	r6, r6, #16
	orr	r6, r6, lr, lsl #16
	ror	r6, r6, #16
#else
	bfi	r6, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
	ror	r2, r2, #16
	orr	r2, r2, r12, lsl #16
	ror	r2, r2, #16
#else
	bfi	r2, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r7
	smulbt	r7, r11, r7
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r7
	smlabb	lr, r10, lr, r7
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r7, r3, r12
	sadd16	r3, r3, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r7, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r7, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r7, r7, #16
	mul	r12, lr, r12
	mul	r7, lr, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r7, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r7, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r7
	sub	r7, r3, lr
	add	r3, r3, lr
	sub	lr, r3, r12, lsr #16
	add	r12, r3, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
	ror	r7, r7, #16
	orr	r7, r7, lr, lsl #16
	ror	r7, r7, #16
#else
	bfi	r7, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
	ror	r3, r3, #16
	orr	r3, r3, r12, lsl #16
	ror	r3, r3, #16
#else
	bfi	r3, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r8
	smulbt	r8, r11, r8
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r8
	smlabb	lr, r10, lr, r8
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r8, r4, r12
	sadd16	r4, r4, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r8, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r8, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r8, r8, #16
	mul	r12, lr, r12
	mul	r8, lr, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r8, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r8, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r8
	sub	r8, r4, lr
	add	r4, r4, lr
	sub	lr, r4, r12, lsr #16
	add	r12, r4, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
	ror	r8, r8, #16
	orr	r8, r8, lr, lsl #16
	ror	r8, r8, #16
#else
	bfi	r8, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
	ror	r4, r4, #16
	orr	r4, r4, r12, lsl #16
	ror	r4, r4, #16
#else
	bfi	r4, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r9
	smulbt	r9, r11, r9
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r9
	smlabb	lr, r10, lr, r9
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r9, r5, r12
	sadd16	r5, r5, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r9, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r9, r9, #16
	mul	r12, lr, r12
	mul	r9, lr, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r9, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r9, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r9
	sub	r9, r5, lr
	add	r5, r5, lr
	sub	lr, r5, r12, lsr #16
	add	r12, r5, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
	ror	r9, r9, #16
	orr	r9, r9, lr, lsl #16
	ror	r9, r9, #16
#else
	bfi	r9, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
	ror	r5, r5, #16
	orr	r5, r5, r12, lsl #16
	ror	r5, r5, #16
#else
	bfi	r5, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	ldr	r11, [r1, #4]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r4
	smulbt	r4, r11, r4
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r4
	smlabb	lr, r10, lr, r4
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r4, r2, r12
	sadd16	r2, r2, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r4, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r4, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r4, r4, #16
	mul	r12, lr, r12
	mul	r4, lr, r4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r4, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r4, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r4
	sub	r4, r2, lr
	add	r2, r2, lr
	sub	lr, r2, r12, lsr #16
	add	r12, r2, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
	ror	r4, r4, #16
	orr	r4, r4, lr, lsl #16
	ror	r4, r4, #16
#else
	bfi	r4, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
	ror	r2, r2, #16
	orr	r2, r2, r12, lsl #16
	ror	r2, r2, #16
#else
	bfi	r2, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r5
	smulbt	r5, r11, r5
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r5
	smlabb	lr, r10, lr, r5
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r5, r3, r12
	sadd16	r3, r3, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r5, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r5, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r5, r5, #16
	mul	r12, lr, r12
	mul	r5, lr, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r5, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r5, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r5
	sub	r5, r3, lr
	add	r3, r3, lr
	sub	lr, r3, r12, lsr #16
	add	r12, r3, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
	ror	r5, r5, #16
	orr	r5, r5, lr, lsl #16
	ror	r5, r5, #16
#else
	bfi	r5, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
	ror	r3, r3, #16
	orr	r3, r3, r12, lsl #16
	ror	r3, r3, #16
#else
	bfi	r3, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smultb	r12, r11, r8
	smultt	r8, r11, r8
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r8
	smlabb	lr, r10, lr, r8
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r8, r6, r12
	sadd16	r6, r6, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r8, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r8, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r8, r8, #16
	mul	r12, lr, r12
	mul	r8, lr, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r8, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r8, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r8
	sub	r8, r6, lr
	add	r6, r6, lr
	sub	lr, r6, r12, lsr #16
	add	r12, r6, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
	ror	r8, r8, #16
	orr	r8, r8, lr, lsl #16
	ror	r8, r8, #16
#else
	bfi	r8, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
	ror	r6, r6, #16
	orr	r6, r6, r12, lsl #16
	ror	r6, r6, #16
#else
	bfi	r6, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smultb	r12, r11, r9
	smultt	r9, r11, r9
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r9
	smlabb	lr, r10, lr, r9
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r9, r7, r12
	sadd16	r7, r7, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r9, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r9, r9, #16
	mul	r12, lr, r12
	mul	r9, lr, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r9, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r9, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r9
	sub	r9, r7, lr
	add	r7, r7, lr
	sub	lr, r7, r12, lsr #16
	add	r12, r7, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
	ror	r9, r9, #16
	orr	r9, r9, lr, lsl #16
	ror	r9, r9, #16
#else
	bfi	r9, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
	ror	r7, r7, #16
	orr	r7, r7, r12, lsl #16
	ror	r7, r7, #16
#else
	bfi	r7, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	ldr	r11, [r1, #8]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r3
	smulbt	r3, r11, r3
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r3
	smlabb	lr, r10, lr, r3
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r3, r2, r12
	sadd16	r2, r2, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r3, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r3, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r3, r3, #16
	mul	r12, lr, r12
	mul	r3, lr, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r3, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r3, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r3
	sub	r3, r2, lr
	add	r2, r2, lr
	sub	lr, r2, r12, lsr #16
	add	r12, r2, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
	ror	r3, r3, #16
	orr	r3, r3, lr, lsl #16
	ror	r3, r3, #16
#else
	bfi	r3, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
	ror	r2, r2, #16
	orr	r2, r2, r12, lsl #16
	ror	r2, r2, #16
#else
	bfi	r2, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smultb	r12, r11, r5
	smultt	r5, r11, r5
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r5
	smlabb	lr, r10, lr, r5
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r5, r4, r12
	sadd16	r4, r4, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r5, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r5, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r5, r5, #16
	mul	r12, lr, r12
	mul	r5, lr, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r5, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r5, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r5
	sub	r5, r4, lr
	add	r4, r4, lr
	sub	lr, r4, r12, lsr #16
	add	r12, r4, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
	ror	r5, r5, #16
	orr	r5, r5, lr, lsl #16
	ror	r5, r5, #16
#else
	bfi	r5, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
	ror	r4, r4, #16
	orr	r4, r4, r12, lsl #16
	ror	r4, r4, #16
#else
	bfi	r4, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	ldr	r11, [r1, #12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r7
	smulbt	r7, r11, r7
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r7
	smlabb	lr, r10, lr, r7
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r7, r6, r12
	sadd16	r6, r6, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r7, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r7, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r7, r7, #16
	mul	r12, lr, r12
	mul	r7, lr, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r7, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r7, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r7
	sub	r7, r6, lr
	add	r6, r6, lr
	sub	lr, r6, r12, lsr #16
	add	r12, r6, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
	ror	r7, r7, #16
	orr	r7, r7, lr, lsl #16
	ror	r7, r7, #16
#else
	bfi	r7, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
	ror	r6, r6, #16
	orr	r6, r6, r12, lsl #16
	ror	r6, r6, #16
#else
	bfi	r6, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smultb	r12, r11, r9
	smultt	r9, r11, r9
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r9
	smlabb	lr, r10, lr, r9
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r9, r8, r12
	sadd16	r8, r8, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r9, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r9, r9, #16
	mul	r12, lr, r12
	mul	r9, lr, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r9, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r9, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r9
	sub	r9, r8, lr
	add	r8, r8, lr
	sub	lr, r8, r12, lsr #16
	add	r12, r8, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
	ror	r9, r9, #16
	orr	r9, r9, lr, lsl #16
	ror	r9, r9, #16
#else
	bfi	r9, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
	ror	r8, r8, #16
	orr	r8, r8, r12, lsl #16
	ror	r8, r8, #16
#else
	bfi	r8, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	str	r2, [r0]
	str	r3, [r0, #64]
	str	r4, [r0, #128]
	str	r5, [r0, #192]
	str	r6, [r0, #256]
	str	r7, [r0, #320]
	str	r8, [r0, #384]
	str	r9, [r0, #448]
	ldr	r2, [sp]
	subs	r2, r2, #1
	add	r0, r0, #4
	bne	L_kyber_arm32_ntt_loop_123
	sub	r0, r0, #0x40
	mov	r3, #0
L_kyber_arm32_ntt_loop_4_j:
	str	r3, [sp, #4]
	add	r11, r1, r3, lsr #4
	mov	r2, #4
	ldr	r11, [r11, #16]
L_kyber_arm32_ntt_loop_4_i:
	str	r2, [sp]
	ldr	r2, [r0]
	ldr	r3, [r0, #16]
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #48]
	ldr	r6, [r0, #64]
	ldr	r7, [r0, #80]
	ldr	r8, [r0, #96]
	ldr	r9, [r0, #112]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r4
	smulbt	r4, r11, r4
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r4
	smlabb	lr, r10, lr, r4
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r4, r2, r12
	sadd16	r2, r2, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r4, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r4, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r4, r4, #16
	mul	r12, lr, r12
	mul	r4, lr, r4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r4, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r4, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r4
	sub	r4, r2, lr
	add	r2, r2, lr
	sub	lr, r2, r12, lsr #16
	add	r12, r2, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
	ror	r4, r4, #16
	orr	r4, r4, lr, lsl #16
	ror	r4, r4, #16
#else
	bfi	r4, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
	ror	r2, r2, #16
	orr	r2, r2, r12, lsl #16
	ror	r2, r2, #16
#else
	bfi	r2, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r5
	smulbt	r5, r11, r5
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r5
	smlabb	lr, r10, lr, r5
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r5, r3, r12
	sadd16	r3, r3, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r5, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r5, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r5, r5, #16
	mul	r12, lr, r12
	mul	r5, lr, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r5, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r5, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r5
	sub	r5, r3, lr
	add	r3, r3, lr
	sub	lr, r3, r12, lsr #16
	add	r12, r3, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
	ror	r5, r5, #16
	orr	r5, r5, lr, lsl #16
	ror	r5, r5, #16
#else
	bfi	r5, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
	ror	r3, r3, #16
	orr	r3, r3, r12, lsl #16
	ror	r3, r3, #16
#else
	bfi	r3, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smultb	r12, r11, r8
	smultt	r8, r11, r8
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r8
	smlabb	lr, r10, lr, r8
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r8, r6, r12
	sadd16	r6, r6, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r8, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r8, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r8, r8, #16
	mul	r12, lr, r12
	mul	r8, lr, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r8, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r8, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r8
	sub	r8, r6, lr
	add	r6, r6, lr
	sub	lr, r6, r12, lsr #16
	add	r12, r6, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
	ror	r8, r8, #16
	orr	r8, r8, lr, lsl #16
	ror	r8, r8, #16
#else
	bfi	r8, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
	ror	r6, r6, #16
	orr	r6, r6, r12, lsl #16
	ror	r6, r6, #16
#else
	bfi	r6, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smultb	r12, r11, r9
	smultt	r9, r11, r9
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r9
	smlabb	lr, r10, lr, r9
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r9, r7, r12
	sadd16	r7, r7, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r9, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r9, r9, #16
	mul	r12, lr, r12
	mul	r9, lr, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r9, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r9, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r9
	sub	r9, r7, lr
	add	r7, r7, lr
	sub	lr, r7, r12, lsr #16
	add	r12, r7, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
	ror	r9, r9, #16
	orr	r9, r9, lr, lsl #16
	ror	r9, r9, #16
#else
	bfi	r9, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
	ror	r7, r7, #16
	orr	r7, r7, r12, lsl #16
	ror	r7, r7, #16
#else
	bfi	r7, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	str	r2, [r0]
	str	r3, [r0, #16]
	str	r4, [r0, #32]
	str	r5, [r0, #48]
	str	r6, [r0, #64]
	str	r7, [r0, #80]
	str	r8, [r0, #96]
	str	r9, [r0, #112]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [sp]
	ldr	r3, [sp, #4]
#else
	ldrd	r2, r3, [sp]
#endif
	subs	r2, r2, #1
	add	r0, r0, #4
	bne	L_kyber_arm32_ntt_loop_4_i
	add	r3, r3, #0x40
	rsbs	r12, r3, #0x100
	add	r0, r0, #0x70
	bne	L_kyber_arm32_ntt_loop_4_j
	sub	r0, r0, #0x200
	mov	r3, #0
L_kyber_arm32_ntt_loop_567:
	add	r11, r1, r3, lsr #3
	str	r3, [sp, #4]
	ldrh	r11, [r11, #32]
	ldr	r2, [r0]
	ldr	r3, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
	ldr	r6, [r0, #16]
	ldr	r7, [r0, #20]
	ldr	r8, [r0, #24]
	ldr	r9, [r0, #28]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r6
	smulbt	r6, r11, r6
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r6
	smlabb	lr, r10, lr, r6
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r6, r2, r12
	sadd16	r2, r2, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r6, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r6, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r6, r6, #16
	mul	r12, lr, r12
	mul	r6, lr, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r6, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r6, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r6
	sub	r6, r2, lr
	add	r2, r2, lr
	sub	lr, r2, r12, lsr #16
	add	r12, r2, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
	ror	r6, r6, #16
	orr	r6, r6, lr, lsl #16
	ror	r6, r6, #16
#else
	bfi	r6, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
	ror	r2, r2, #16
	orr	r2, r2, r12, lsl #16
	ror	r2, r2, #16
#else
	bfi	r2, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r7
	smulbt	r7, r11, r7
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r7
	smlabb	lr, r10, lr, r7
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r7, r3, r12
	sadd16	r3, r3, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r7, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r7, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r7, r7, #16
	mul	r12, lr, r12
	mul	r7, lr, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r7, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r7, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r7
	sub	r7, r3, lr
	add	r3, r3, lr
	sub	lr, r3, r12, lsr #16
	add	r12, r3, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
	ror	r7, r7, #16
	orr	r7, r7, lr, lsl #16
	ror	r7, r7, #16
#else
	bfi	r7, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
	ror	r3, r3, #16
	orr	r3, r3, r12, lsl #16
	ror	r3, r3, #16
#else
	bfi	r3, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r8
	smulbt	r8, r11, r8
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r8
	smlabb	lr, r10, lr, r8
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r8, r4, r12
	sadd16	r4, r4, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r8, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r8, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r8, r8, #16
	mul	r12, lr, r12
	mul	r8, lr, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r8, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r8, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r8
	sub	r8, r4, lr
	add	r4, r4, lr
	sub	lr, r4, r12, lsr #16
	add	r12, r4, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
	ror	r8, r8, #16
	orr	r8, r8, lr, lsl #16
	ror	r8, r8, #16
#else
	bfi	r8, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
	ror	r4, r4, #16
	orr	r4, r4, r12, lsl #16
	ror	r4, r4, #16
#else
	bfi	r4, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r9
	smulbt	r9, r11, r9
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r9
	smlabb	lr, r10, lr, r9
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r9, r5, r12
	sadd16	r5, r5, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r9, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r9, r9, #16
	mul	r12, lr, r12
	mul	r9, lr, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r9, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r9, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r9
	sub	r9, r5, lr
	add	r5, r5, lr
	sub	lr, r5, r12, lsr #16
	add	r12, r5, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
	ror	r9, r9, #16
	orr	r9, r9, lr, lsl #16
	ror	r9, r9, #16
#else
	bfi	r9, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
	ror	r5, r5, #16
	orr	r5, r5, r12, lsl #16
	ror	r5, r5, #16
#else
	bfi	r5, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	ldr	r11, [sp, #4]
	add	r11, r1, r11, lsr #2
	ldr	r11, [r11, #64]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r4
	smulbt	r4, r11, r4
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r4
	smlabb	lr, r10, lr, r4
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r4, r2, r12
	sadd16	r2, r2, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r4, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r4, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r4, r4, #16
	mul	r12, lr, r12
	mul	r4, lr, r4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r4, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r4, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r4
	sub	r4, r2, lr
	add	r2, r2, lr
	sub	lr, r2, r12, lsr #16
	add	r12, r2, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
	ror	r4, r4, #16
	orr	r4, r4, lr, lsl #16
	ror	r4, r4, #16
#else
	bfi	r4, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
	ror	r2, r2, #16
	orr	r2, r2, r12, lsl #16
	ror	r2, r2, #16
#else
	bfi	r2, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r5
	smulbt	r5, r11, r5
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r5
	smlabb	lr, r10, lr, r5
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r5, r3, r12
	sadd16	r3, r3, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r5, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r5, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r5, r5, #16
	mul	r12, lr, r12
	mul	r5, lr, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r5, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r5, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r5
	sub	r5, r3, lr
	add	r3, r3, lr
	sub	lr, r3, r12, lsr #16
	add	r12, r3, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
	ror	r5, r5, #16
	orr	r5, r5, lr, lsl #16
	ror	r5, r5, #16
#else
	bfi	r5, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
	ror	r3, r3, #16
	orr	r3, r3, r12, lsl #16
	ror	r3, r3, #16
#else
	bfi	r3, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smultb	r12, r11, r8
	smultt	r8, r11, r8
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r8
	smlabb	lr, r10, lr, r8
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r8, r6, r12
	sadd16	r6, r6, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r8, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r8, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r8, r8, #16
	mul	r12, lr, r12
	mul	r8, lr, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r8, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r8, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r8
	sub	r8, r6, lr
	add	r6, r6, lr
	sub	lr, r6, r12, lsr #16
	add	r12, r6, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
	ror	r8, r8, #16
	orr	r8, r8, lr, lsl #16
	ror	r8, r8, #16
#else
	bfi	r8, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
	ror	r6, r6, #16
	orr	r6, r6, r12, lsl #16
	ror	r6, r6, #16
#else
	bfi	r6, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smultb	r12, r11, r9
	smultt	r9, r11, r9
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r9
	smlabb	lr, r10, lr, r9
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r9, r7, r12
	sadd16	r7, r7, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r9, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r9, r9, #16
	mul	r12, lr, r12
	mul	r9, lr, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r9, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r9, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r9
	sub	r9, r7, lr
	add	r7, r7, lr
	sub	lr, r7, r12, lsr #16
	add	r12, r7, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
	ror	r9, r9, #16
	orr	r9, r9, lr, lsl #16
	ror	r9, r9, #16
#else
	bfi	r9, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
	ror	r7, r7, #16
	orr	r7, r7, r12, lsl #16
	ror	r7, r7, #16
#else
	bfi	r7, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	ldr	r11, [sp, #4]
	add	r11, r1, r11, lsr #1
	ldr	r11, [r11, #128]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r3
	smulbt	r3, r11, r3
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r3
	smlabb	lr, r10, lr, r3
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r3, r2, r12
	sadd16	r2, r2, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r3, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r3, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r3, r3, #16
	mul	r12, lr, r12
	mul	r3, lr, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r3, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r3, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r3
	sub	r3, r2, lr
	add	r2, r2, lr
	sub	lr, r2, r12, lsr #16
	add	r12, r2, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
	ror	r3, r3, #16
	orr	r3, r3, lr, lsl #16
	ror	r3, r3, #16
#else
	bfi	r3, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
	ror	r2, r2, #16
	orr	r2, r2, r12, lsl #16
	ror	r2, r2, #16
#else
	bfi	r2, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smultb	r12, r11, r5
	smultt	r5, r11, r5
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r5
	smlabb	lr, r10, lr, r5
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r5, r4, r12
	sadd16	r4, r4, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r5, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r5, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r5, r5, #16
	mul	r12, lr, r12
	mul	r5, lr, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r5, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r5, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r5
	sub	r5, r4, lr
	add	r4, r4, lr
	sub	lr, r4, r12, lsr #16
	add	r12, r4, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
	ror	r5, r5, #16
	orr	r5, r5, lr, lsl #16
	ror	r5, r5, #16
#else
	bfi	r5, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
	ror	r4, r4, #16
	orr	r4, r4, r12, lsl #16
	ror	r4, r4, #16
#else
	bfi	r4, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	ldr	r11, [sp, #4]
	add	r11, r1, r11, lsr #1
	ldr	r11, [r11, #132]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r7
	smulbt	r7, r11, r7
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r7
	smlabb	lr, r10, lr, r7
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r7, r6, r12
	sadd16	r6, r6, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r7, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r7, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r7, r7, #16
	mul	r12, lr, r12
	mul	r7, lr, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r7, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r7, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r7
	sub	r7, r6, lr
	add	r6, r6, lr
	sub	lr, r6, r12, lsr #16
	add	r12, r6, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
	ror	r7, r7, #16
	orr	r7, r7, lr, lsl #16
	ror	r7, r7, #16
#else
	bfi	r7, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
	ror	r6, r6, #16
	orr	r6, r6, r12, lsl #16
	ror	r6, r6, #16
#else
	bfi	r6, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smultb	r12, r11, r9
	smultt	r9, r11, r9
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r9
	smlabb	lr, r10, lr, r9
	pkhtb	r12, lr, r12, ASR #16
	ssub16	r9, r8, r12
	sadd16	r8, r8, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r9, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r9, r9, #16
	mul	r12, lr, r12
	mul	r9, lr, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r9, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r9, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	lr, r10, lr, r9
	sub	r9, r8, lr
	add	r8, r8, lr
	sub	lr, r8, r12, lsr #16
	add	r12, r8, r12, lsr #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
	ror	r9, r9, #16
	orr	r9, r9, lr, lsl #16
	ror	r9, r9, #16
#else
	bfi	r9, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
	ror	r8, r8, #16
	orr	r8, r8, r12, lsl #16
	ror	r8, r8, #16
#else
	bfi	r8, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0xaf
	lsl	r11, r11, #8
	add	r11, r11, #0xc0
#else
	mov	r11, #0xafc0
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	orr	r11, r11, #0x130000
#else
	movt	r11, #0x13
#endif
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x4e
	lsl	r11, r11, #8
	add	r11, r11, #0xbf
#else
	mov	r11, #0x4ebf
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulwb	r12, r11, r2
	smulwt	lr, r11, r2
	smulbt	r12, r10, r12
	smulbt	lr, r10, lr
	pkhbt	r12, r12, lr, LSL #16
	ssub16	r2, r2, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r2, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r2, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r2, #16
#else
	sbfx	lr, r2, #16, #16
#endif
	mul	r12, r11, r12
	mul	lr, r11, lr
	asr	r12, r12, #26
	asr	lr, lr, #26
	mul	r12, r10, r12
	mul	lr, r10, lr
	sub	lr, r2, lr, lsl #16
	sub	r2, r2, r12
	lsr	lr, lr, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff0000
	bic	r2, r2, #0xff000000
	orr	r2, r2, lr, lsl #16
#else
	bfi	r2, lr, #16, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulwb	r12, r11, r3
	smulwt	lr, r11, r3
	smulbt	r12, r10, r12
	smulbt	lr, r10, lr
	pkhbt	r12, r12, lr, LSL #16
	ssub16	r3, r3, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r3, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r3, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r3, #16
#else
	sbfx	lr, r3, #16, #16
#endif
	mul	r12, r11, r12
	mul	lr, r11, lr
	asr	r12, r12, #26
	asr	lr, lr, #26
	mul	r12, r10, r12
	mul	lr, r10, lr
	sub	lr, r3, lr, lsl #16
	sub	r3, r3, r12
	lsr	lr, lr, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff0000
	bic	r3, r3, #0xff000000
	orr	r3, r3, lr, lsl #16
#else
	bfi	r3, lr, #16, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulwb	r12, r11, r4
	smulwt	lr, r11, r4
	smulbt	r12, r10, r12
	smulbt	lr, r10, lr
	pkhbt	r12, r12, lr, LSL #16
	ssub16	r4, r4, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r4, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r4, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r4, #16
#else
	sbfx	lr, r4, #16, #16
#endif
	mul	r12, r11, r12
	mul	lr, r11, lr
	asr	r12, r12, #26
	asr	lr, lr, #26
	mul	r12, r10, r12
	mul	lr, r10, lr
	sub	lr, r4, lr, lsl #16
	sub	r4, r4, r12
	lsr	lr, lr, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff0000
	bic	r4, r4, #0xff000000
	orr	r4, r4, lr, lsl #16
#else
	bfi	r4, lr, #16, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulwb	r12, r11, r5
	smulwt	lr, r11, r5
	smulbt	r12, r10, r12
	smulbt	lr, r10, lr
	pkhbt	r12, r12, lr, LSL #16
	ssub16	r5, r5, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r5, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r5, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r5, #16
#else
	sbfx	lr, r5, #16, #16
#endif
	mul	r12, r11, r12
	mul	lr, r11, lr
	asr	r12, r12, #26
	asr	lr, lr, #26
	mul	r12, r10, r12
	mul	lr, r10, lr
	sub	lr, r5, lr, lsl #16
	sub	r5, r5, r12
	lsr	lr, lr, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff0000
	bic	r5, r5, #0xff000000
	orr	r5, r5, lr, lsl #16
#else
	bfi	r5, lr, #16, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulwb	r12, r11, r6
	smulwt	lr, r11, r6
	smulbt	r12, r10, r12
	smulbt	lr, r10, lr
	pkhbt	r12, r12, lr, LSL #16
	ssub16	r6, r6, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r6, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r6, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r6, #16
#else
	sbfx	lr, r6, #16, #16
#endif
	mul	r12, r11, r12
	mul	lr, r11, lr
	asr	r12, r12, #26
	asr	lr, lr, #26
	mul	r12, r10, r12
	mul	lr, r10, lr
	sub	lr, r6, lr, lsl #16
	sub	r6, r6, r12
	lsr	lr, lr, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff0000
	bic	r6, r6, #0xff000000
	orr	r6, r6, lr, lsl #16
#else
	bfi	r6, lr, #16, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulwb	r12, r11, r7
	smulwt	lr, r11, r7
	smulbt	r12, r10, r12
	smulbt	lr, r10, lr
	pkhbt	r12, r12, lr, LSL #16
	ssub16	r7, r7, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r7, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r7, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r7, #16
#else
	sbfx	lr, r7, #16, #16
#endif
	mul	r12, r11, r12
	mul	lr, r11, lr
	asr	r12, r12, #26
	asr	lr, lr, #26
	mul	r12, r10, r12
	mul	lr, r10, lr
	sub	lr, r7, lr, lsl #16
	sub	r7, r7, r12
	lsr	lr, lr, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff0000
	bic	r7, r7, #0xff000000
	orr	r7, r7, lr, lsl #16
#else
	bfi	r7, lr, #16, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulwb	r12, r11, r8
	smulwt	lr, r11, r8
	smulbt	r12, r10, r12
	smulbt	lr, r10, lr
	pkhbt	r12, r12, lr, LSL #16
	ssub16	r8, r8, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r8, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r8, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r8, #16
#else
	sbfx	lr, r8, #16, #16
#endif
	mul	r12, r11, r12
	mul	lr, r11, lr
	asr	r12, r12, #26
	asr	lr, lr, #26
	mul	r12, r10, r12
	mul	lr, r10, lr
	sub	lr, r8, lr, lsl #16
	sub	r8, r8, r12
	lsr	lr, lr, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff0000
	bic	r8, r8, #0xff000000
	orr	r8, r8, lr, lsl #16
#else
	bfi	r8, lr, #16, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulwb	r12, r11, r9
	smulwt	lr, r11, r9
	smulbt	r12, r10, r12
	smulbt	lr, r10, lr
	pkhbt	r12, r12, lr, LSL #16
	ssub16	r9, r9, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r9, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r9, #16
#else
	sbfx	lr, r9, #16, #16
#endif
	mul	r12, r11, r12
	mul	lr, r11, lr
	asr	r12, r12, #26
	asr	lr, lr, #26
	mul	r12, r10, r12
	mul	lr, r10, lr
	sub	lr, r9, lr, lsl #16
	sub	r9, r9, r12
	lsr	lr, lr, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff0000
	bic	r9, r9, #0xff000000
	orr	r9, r9, lr, lsl #16
#else
	bfi	r9, lr, #16, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	orr	r10, r10, #0xc000000
	orr	r10, r10, #0xff0000
#else
	movt	r10, #0xcff
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	str	r2, [r0]
	str	r3, [r0, #4]
	str	r4, [r0, #8]
	str	r5, [r0, #12]
	str	r6, [r0, #16]
	str	r7, [r0, #20]
	str	r8, [r0, #24]
	str	r9, [r0, #28]
	ldr	r3, [sp, #4]
	add	r3, r3, #16
	rsbs	r12, r3, #0x100
	add	r0, r0, #32
	bne	L_kyber_arm32_ntt_loop_567
	add	sp, sp, #8
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	kyber_arm32_ntt,.-kyber_arm32_ntt
	.text
	.type	L_kyber_arm32_invntt_zetas_inv, %object
	.size	L_kyber_arm32_invntt_zetas_inv, 256
	.align	4
L_kyber_arm32_invntt_zetas_inv:
	.short	0x6a5
	.short	0x70f
	.short	0x5b4
	.short	0x943
	.short	0x922
	.short	0x91d
	.short	0x134
	.short	0x6c
	.short	0xb23
	.short	0x366
	.short	0x356
	.short	0x5e6
	.short	0x9e7
	.short	0x4fe
	.short	0x5fa
	.short	0x4a1
	.short	0x67b
	.short	0x4a3
	.short	0xc25
	.short	0x36a
	.short	0x537
	.short	0x83f
	.short	0x88
	.short	0x4bf
	.short	0xb81
	.short	0x5b9
	.short	0x505
	.short	0x7d7
	.short	0xa9f
	.short	0xaa6
	.short	0x8b8
	.short	0x9d0
	.short	0x4b
	.short	0x9c
	.short	0xbb8
	.short	0xb5f
	.short	0xba4
	.short	0x368
	.short	0xa7d
	.short	0x636
	.short	0x8a2
	.short	0x25a
	.short	0x736
	.short	0x309
	.short	0x93
	.short	0x87a
	.short	0x9f7
	.short	0xf6
	.short	0x68c
	.short	0x6db
	.short	0x1cc
	.short	0x123
	.short	0xeb
	.short	0xc50
	.short	0xab6
	.short	0xb5b
	.short	0xc98
	.short	0x6f3
	.short	0x99a
	.short	0x4e3
	.short	0x9b6
	.short	0xad6
	.short	0xb53
	.short	0x44f
	.short	0x4fb
	.short	0xa5c
	.short	0x429
	.short	0xb41
	.short	0x2d5
	.short	0x5e4
	.short	0x940
	.short	0x18e
	.short	0x3b7
	.short	0xf7
	.short	0x58d
	.short	0xc96
	.short	0x9c3
	.short	0x10f
	.short	0x5a
	.short	0x355
	.short	0x744
	.short	0xc83
	.short	0x48a
	.short	0x652
	.short	0x29a
	.short	0x140
	.short	0x8
	.short	0xafd
	.short	0x608
	.short	0x11a
	.short	0x72e
	.short	0x50d
	.short	0x90a
	.short	0x228
	.short	0xa75
	.short	0x83a
	.short	0x623
	.short	0xcd
	.short	0xb66
	.short	0x606
	.short	0xaa1
	.short	0xa25
	.short	0x908
	.short	0x2a9
	.short	0x82
	.short	0x642
	.short	0x74f
	.short	0x33d
	.short	0xb82
	.short	0xbf9
	.short	0x52d
	.short	0xac4
	.short	0x745
	.short	0x5c2
	.short	0x4b2
	.short	0x93f
	.short	0xc4b
	.short	0x6d8
	.short	0xa93
	.short	0xab
	.short	0xc37
	.short	0xbe2
	.short	0x773
	.short	0x72c
	.short	0x5ed
	.short	0x167
	.short	0x2f6
	.short	0x5a1
	.text
	.align	4
	.globl	kyber_arm32_invntt
	.type	kyber_arm32_invntt, %function
kyber_arm32_invntt:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #8
	adr	r1, L_kyber_arm32_invntt_zetas_inv
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	orr	r10, r10, #0xc000000
	orr	r10, r10, #0xff0000
#else
	movt	r10, #0xcff
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	mov	r3, #0
L_kyber_arm32_invntt_loop_765:
	add	r11, r1, r3, lsr #1
	str	r3, [sp, #4]
	ldr	r2, [r0]
	ldr	r3, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
	ldr	r6, [r0, #16]
	ldr	r7, [r0, #20]
	ldr	r8, [r0, #24]
	ldr	r9, [r0, #28]
	ldr	r11, [r11]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r2, r3
	sadd16	r2, r2, r3
	smulbt	r3, r11, r12
	smulbb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r3
	smlabb	r3, r10, lr, r3
	pkhtb	r3, r3, r12, ASR #16
#else
	sub	lr, r2, r3
	add	r10, r2, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
#else
	bfc	r3, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
#else
	bfc	r2, #0, #16
#endif
	sub	r12, r2, r3
	add	r2, r2, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
	ror	r2, r2, #16
	orr	r2, r2, r10, lsl #16
	ror	r2, r2, #16
#else
	bfi	r2, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r10, r12, #16
	mul	r3, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r3, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r3, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r3, r10, lr, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
	ror	r3, r3, #16
	orr	r3, r3, r12, lsl #16
	ror	r3, r3, #16
#else
	bfi	r3, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r4, r5
	sadd16	r4, r4, r5
	smultt	r5, r11, r12
	smultb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r5
	smlabb	r5, r10, lr, r5
	pkhtb	r5, r5, r12, ASR #16
#else
	sub	lr, r4, r5
	add	r10, r4, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
#else
	bfc	r5, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
#else
	bfc	r4, #0, #16
#endif
	sub	r12, r4, r5
	add	r4, r4, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
	ror	r4, r4, #16
	orr	r4, r4, r10, lsl #16
	ror	r4, r4, #16
#else
	bfi	r4, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r10, r12, #16
	mul	r5, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r5, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r5, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r5, r10, lr, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
	ror	r5, r5, #16
	orr	r5, r5, r12, lsl #16
	ror	r5, r5, #16
#else
	bfi	r5, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	ldr	r11, [sp, #4]
	add	r11, r1, r11, lsr #1
	ldr	r11, [r11, #4]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r6, r7
	sadd16	r6, r6, r7
	smulbt	r7, r11, r12
	smulbb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r7
	smlabb	r7, r10, lr, r7
	pkhtb	r7, r7, r12, ASR #16
#else
	sub	lr, r6, r7
	add	r10, r6, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
#else
	bfc	r7, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
#else
	bfc	r6, #0, #16
#endif
	sub	r12, r6, r7
	add	r6, r6, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
	ror	r6, r6, #16
	orr	r6, r6, r10, lsl #16
	ror	r6, r6, #16
#else
	bfi	r6, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r10, r12, #16
	mul	r7, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r7, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r7, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r7, r10, lr, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
	ror	r7, r7, #16
	orr	r7, r7, r12, lsl #16
	ror	r7, r7, #16
#else
	bfi	r7, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r8, r9
	sadd16	r8, r8, r9
	smultt	r9, r11, r12
	smultb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r9
	smlabb	r9, r10, lr, r9
	pkhtb	r9, r9, r12, ASR #16
#else
	sub	lr, r8, r9
	add	r10, r8, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
#else
	bfc	r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
#else
	bfc	r8, #0, #16
#endif
	sub	r12, r8, r9
	add	r8, r8, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
	ror	r8, r8, #16
	orr	r8, r8, r10, lsl #16
	ror	r8, r8, #16
#else
	bfi	r8, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r10, r12, #16
	mul	r9, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r9, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r9, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r9, r10, lr, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
	ror	r9, r9, #16
	orr	r9, r9, r12, lsl #16
	ror	r9, r9, #16
#else
	bfi	r9, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	ldr	r11, [sp, #4]
	add	r11, r1, r11, lsr #2
	ldr	r11, [r11, #128]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r2, r4
	sadd16	r2, r2, r4
	smulbt	r4, r11, r12
	smulbb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r4
	smlabb	r4, r10, lr, r4
	pkhtb	r4, r4, r12, ASR #16
#else
	sub	lr, r2, r4
	add	r10, r2, r4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
#else
	bfc	r4, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
#else
	bfc	r2, #0, #16
#endif
	sub	r12, r2, r4
	add	r2, r2, r4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
	ror	r2, r2, #16
	orr	r2, r2, r10, lsl #16
	ror	r2, r2, #16
#else
	bfi	r2, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r10, r12, #16
	mul	r4, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r4, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r4, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r4, r10, lr, r4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
	ror	r4, r4, #16
	orr	r4, r4, r12, lsl #16
	ror	r4, r4, #16
#else
	bfi	r4, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r3, r5
	sadd16	r3, r3, r5
	smulbt	r5, r11, r12
	smulbb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r5
	smlabb	r5, r10, lr, r5
	pkhtb	r5, r5, r12, ASR #16
#else
	sub	lr, r3, r5
	add	r10, r3, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
#else
	bfc	r5, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
#else
	bfc	r3, #0, #16
#endif
	sub	r12, r3, r5
	add	r3, r3, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
	ror	r3, r3, #16
	orr	r3, r3, r10, lsl #16
	ror	r3, r3, #16
#else
	bfi	r3, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r10, r12, #16
	mul	r5, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r5, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r5, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r5, r10, lr, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
	ror	r5, r5, #16
	orr	r5, r5, r12, lsl #16
	ror	r5, r5, #16
#else
	bfi	r5, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r6, r8
	sadd16	r6, r6, r8
	smultt	r8, r11, r12
	smultb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r8
	smlabb	r8, r10, lr, r8
	pkhtb	r8, r8, r12, ASR #16
#else
	sub	lr, r6, r8
	add	r10, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
#else
	bfc	r8, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
#else
	bfc	r6, #0, #16
#endif
	sub	r12, r6, r8
	add	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
	ror	r6, r6, #16
	orr	r6, r6, r10, lsl #16
	ror	r6, r6, #16
#else
	bfi	r6, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r10, r12, #16
	mul	r8, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r8, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r8, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r8, r10, lr, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
	ror	r8, r8, #16
	orr	r8, r8, r12, lsl #16
	ror	r8, r8, #16
#else
	bfi	r8, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r7, r9
	sadd16	r7, r7, r9
	smultt	r9, r11, r12
	smultb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r9
	smlabb	r9, r10, lr, r9
	pkhtb	r9, r9, r12, ASR #16
#else
	sub	lr, r7, r9
	add	r10, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
#else
	bfc	r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
#else
	bfc	r7, #0, #16
#endif
	sub	r12, r7, r9
	add	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
	ror	r7, r7, #16
	orr	r7, r7, r10, lsl #16
	ror	r7, r7, #16
#else
	bfi	r7, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r10, r12, #16
	mul	r9, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r9, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r9, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r9, r10, lr, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
	ror	r9, r9, #16
	orr	r9, r9, r12, lsl #16
	ror	r9, r9, #16
#else
	bfi	r9, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	ldr	r11, [sp, #4]
	add	r11, r1, r11, lsr #3
	ldr	r11, [r11, #192]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r2, r6
	sadd16	r2, r2, r6
	smulbt	r6, r11, r12
	smulbb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r6
	smlabb	r6, r10, lr, r6
	pkhtb	r6, r6, r12, ASR #16
#else
	sub	lr, r2, r6
	add	r10, r2, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
#else
	bfc	r6, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
#else
	bfc	r2, #0, #16
#endif
	sub	r12, r2, r6
	add	r2, r2, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
	ror	r2, r2, #16
	orr	r2, r2, r10, lsl #16
	ror	r2, r2, #16
#else
	bfi	r2, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r10, r12, #16
	mul	r6, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r6, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r6, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r6, r10, lr, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
	ror	r6, r6, #16
	orr	r6, r6, r12, lsl #16
	ror	r6, r6, #16
#else
	bfi	r6, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r3, r7
	sadd16	r3, r3, r7
	smulbt	r7, r11, r12
	smulbb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r7
	smlabb	r7, r10, lr, r7
	pkhtb	r7, r7, r12, ASR #16
#else
	sub	lr, r3, r7
	add	r10, r3, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
#else
	bfc	r7, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
#else
	bfc	r3, #0, #16
#endif
	sub	r12, r3, r7
	add	r3, r3, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
	ror	r3, r3, #16
	orr	r3, r3, r10, lsl #16
	ror	r3, r3, #16
#else
	bfi	r3, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r10, r12, #16
	mul	r7, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r7, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r7, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r7, r10, lr, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
	ror	r7, r7, #16
	orr	r7, r7, r12, lsl #16
	ror	r7, r7, #16
#else
	bfi	r7, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r4, r8
	sadd16	r4, r4, r8
	smulbt	r8, r11, r12
	smulbb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r8
	smlabb	r8, r10, lr, r8
	pkhtb	r8, r8, r12, ASR #16
#else
	sub	lr, r4, r8
	add	r10, r4, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
#else
	bfc	r8, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
#else
	bfc	r4, #0, #16
#endif
	sub	r12, r4, r8
	add	r4, r4, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
	ror	r4, r4, #16
	orr	r4, r4, r10, lsl #16
	ror	r4, r4, #16
#else
	bfi	r4, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r10, r12, #16
	mul	r8, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r8, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r8, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r8, r10, lr, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
	ror	r8, r8, #16
	orr	r8, r8, r12, lsl #16
	ror	r8, r8, #16
#else
	bfi	r8, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r5, r9
	sadd16	r5, r5, r9
	smulbt	r9, r11, r12
	smulbb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r9
	smlabb	r9, r10, lr, r9
	pkhtb	r9, r9, r12, ASR #16
#else
	sub	lr, r5, r9
	add	r10, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
#else
	bfc	r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
#else
	bfc	r5, #0, #16
#endif
	sub	r12, r5, r9
	add	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
	ror	r5, r5, #16
	orr	r5, r5, r10, lsl #16
	ror	r5, r5, #16
#else
	bfi	r5, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r10, r12, #16
	mul	r9, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r9, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r9, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r9, r10, lr, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
	ror	r9, r9, #16
	orr	r9, r9, r12, lsl #16
	ror	r9, r9, #16
#else
	bfi	r9, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0xaf
	lsl	r11, r11, #8
	add	r11, r11, #0xc0
#else
	mov	r11, #0xafc0
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	orr	r11, r11, #0x130000
#else
	movt	r11, #0x13
#endif
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x4e
	lsl	r11, r11, #8
	add	r11, r11, #0xbf
#else
	mov	r11, #0x4ebf
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulwb	r12, r11, r2
	smulwt	lr, r11, r2
	smulbt	r12, r10, r12
	smulbt	lr, r10, lr
	pkhbt	r12, r12, lr, LSL #16
	ssub16	r2, r2, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r2, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r2, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r2, #16
#else
	sbfx	lr, r2, #16, #16
#endif
	mul	r12, r11, r12
	mul	lr, r11, lr
	asr	r12, r12, #26
	asr	lr, lr, #26
	mul	r12, r10, r12
	mul	lr, r10, lr
	sub	lr, r2, lr, lsl #16
	sub	r2, r2, r12
	lsr	lr, lr, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff0000
	bic	r2, r2, #0xff000000
	orr	r2, r2, lr, lsl #16
#else
	bfi	r2, lr, #16, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulwb	r12, r11, r3
	smulwt	lr, r11, r3
	smulbt	r12, r10, r12
	smulbt	lr, r10, lr
	pkhbt	r12, r12, lr, LSL #16
	ssub16	r3, r3, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r3, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r3, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r3, #16
#else
	sbfx	lr, r3, #16, #16
#endif
	mul	r12, r11, r12
	mul	lr, r11, lr
	asr	r12, r12, #26
	asr	lr, lr, #26
	mul	r12, r10, r12
	mul	lr, r10, lr
	sub	lr, r3, lr, lsl #16
	sub	r3, r3, r12
	lsr	lr, lr, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff0000
	bic	r3, r3, #0xff000000
	orr	r3, r3, lr, lsl #16
#else
	bfi	r3, lr, #16, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulwb	r12, r11, r4
	smulwt	lr, r11, r4
	smulbt	r12, r10, r12
	smulbt	lr, r10, lr
	pkhbt	r12, r12, lr, LSL #16
	ssub16	r4, r4, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r4, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r4, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r4, #16
#else
	sbfx	lr, r4, #16, #16
#endif
	mul	r12, r11, r12
	mul	lr, r11, lr
	asr	r12, r12, #26
	asr	lr, lr, #26
	mul	r12, r10, r12
	mul	lr, r10, lr
	sub	lr, r4, lr, lsl #16
	sub	r4, r4, r12
	lsr	lr, lr, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff0000
	bic	r4, r4, #0xff000000
	orr	r4, r4, lr, lsl #16
#else
	bfi	r4, lr, #16, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulwb	r12, r11, r5
	smulwt	lr, r11, r5
	smulbt	r12, r10, r12
	smulbt	lr, r10, lr
	pkhbt	r12, r12, lr, LSL #16
	ssub16	r5, r5, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r5, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r5, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r5, #16
#else
	sbfx	lr, r5, #16, #16
#endif
	mul	r12, r11, r12
	mul	lr, r11, lr
	asr	r12, r12, #26
	asr	lr, lr, #26
	mul	r12, r10, r12
	mul	lr, r10, lr
	sub	lr, r5, lr, lsl #16
	sub	r5, r5, r12
	lsr	lr, lr, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff0000
	bic	r5, r5, #0xff000000
	orr	r5, r5, lr, lsl #16
#else
	bfi	r5, lr, #16, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	str	r2, [r0]
	str	r3, [r0, #4]
	str	r4, [r0, #8]
	str	r5, [r0, #12]
	str	r6, [r0, #16]
	str	r7, [r0, #20]
	str	r8, [r0, #24]
	str	r9, [r0, #28]
	ldr	r3, [sp, #4]
	add	r3, r3, #16
	rsbs	r12, r3, #0x100
	add	r0, r0, #32
	bne	L_kyber_arm32_invntt_loop_765
	sub	r0, r0, #0x200
	mov	r3, #0
L_kyber_arm32_invntt_loop_4_j:
	str	r3, [sp, #4]
	add	r11, r1, r3, lsr #4
	mov	r2, #4
	ldr	r11, [r11, #224]
L_kyber_arm32_invntt_loop_4_i:
	str	r2, [sp]
	ldr	r2, [r0]
	ldr	r3, [r0, #16]
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #48]
	ldr	r6, [r0, #64]
	ldr	r7, [r0, #80]
	ldr	r8, [r0, #96]
	ldr	r9, [r0, #112]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r2, r4
	sadd16	r2, r2, r4
	smulbt	r4, r11, r12
	smulbb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r4
	smlabb	r4, r10, lr, r4
	pkhtb	r4, r4, r12, ASR #16
#else
	sub	lr, r2, r4
	add	r10, r2, r4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
#else
	bfc	r4, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
#else
	bfc	r2, #0, #16
#endif
	sub	r12, r2, r4
	add	r2, r2, r4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
	ror	r2, r2, #16
	orr	r2, r2, r10, lsl #16
	ror	r2, r2, #16
#else
	bfi	r2, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r10, r12, #16
	mul	r4, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r4, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r4, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r4, r10, lr, r4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
	ror	r4, r4, #16
	orr	r4, r4, r12, lsl #16
	ror	r4, r4, #16
#else
	bfi	r4, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r3, r5
	sadd16	r3, r3, r5
	smulbt	r5, r11, r12
	smulbb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r5
	smlabb	r5, r10, lr, r5
	pkhtb	r5, r5, r12, ASR #16
#else
	sub	lr, r3, r5
	add	r10, r3, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
#else
	bfc	r5, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
#else
	bfc	r3, #0, #16
#endif
	sub	r12, r3, r5
	add	r3, r3, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
	ror	r3, r3, #16
	orr	r3, r3, r10, lsl #16
	ror	r3, r3, #16
#else
	bfi	r3, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r10, r12, #16
	mul	r5, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r5, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r5, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r5, r10, lr, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
	ror	r5, r5, #16
	orr	r5, r5, r12, lsl #16
	ror	r5, r5, #16
#else
	bfi	r5, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r6, r8
	sadd16	r6, r6, r8
	smultt	r8, r11, r12
	smultb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r8
	smlabb	r8, r10, lr, r8
	pkhtb	r8, r8, r12, ASR #16
#else
	sub	lr, r6, r8
	add	r10, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
#else
	bfc	r8, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
#else
	bfc	r6, #0, #16
#endif
	sub	r12, r6, r8
	add	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
	ror	r6, r6, #16
	orr	r6, r6, r10, lsl #16
	ror	r6, r6, #16
#else
	bfi	r6, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r10, r12, #16
	mul	r8, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r8, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r8, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r8, r10, lr, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
	ror	r8, r8, #16
	orr	r8, r8, r12, lsl #16
	ror	r8, r8, #16
#else
	bfi	r8, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r7, r9
	sadd16	r7, r7, r9
	smultt	r9, r11, r12
	smultb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r9
	smlabb	r9, r10, lr, r9
	pkhtb	r9, r9, r12, ASR #16
#else
	sub	lr, r7, r9
	add	r10, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
#else
	bfc	r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
#else
	bfc	r7, #0, #16
#endif
	sub	r12, r7, r9
	add	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
	ror	r7, r7, #16
	orr	r7, r7, r10, lsl #16
	ror	r7, r7, #16
#else
	bfi	r7, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r10, r12, #16
	mul	r9, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r9, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r9, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r9, r10, lr, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
	ror	r9, r9, #16
	orr	r9, r9, r12, lsl #16
	ror	r9, r9, #16
#else
	bfi	r9, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	str	r2, [r0]
	str	r3, [r0, #16]
	str	r4, [r0, #32]
	str	r5, [r0, #48]
	str	r6, [r0, #64]
	str	r7, [r0, #80]
	str	r8, [r0, #96]
	str	r9, [r0, #112]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [sp]
	ldr	r3, [sp, #4]
#else
	ldrd	r2, r3, [sp]
#endif
	subs	r2, r2, #1
	add	r0, r0, #4
	bne	L_kyber_arm32_invntt_loop_4_i
	add	r3, r3, #0x40
	rsbs	r12, r3, #0x100
	add	r0, r0, #0x70
	bne	L_kyber_arm32_invntt_loop_4_j
	sub	r0, r0, #0x200
	mov	r2, #16
L_kyber_arm32_invntt_loop_321:
	str	r2, [sp]
	ldrh	r11, [r1, #2]
	ldr	r2, [r0]
	ldr	r3, [r0, #64]
	ldr	r4, [r0, #128]
	ldr	r5, [r0, #192]
	ldr	r6, [r0, #256]
	ldr	r7, [r0, #320]
	ldr	r8, [r0, #384]
	ldr	r9, [r0, #448]
	ldr	r11, [r1, #240]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r2, r3
	sadd16	r2, r2, r3
	smulbt	r3, r11, r12
	smulbb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r3
	smlabb	r3, r10, lr, r3
	pkhtb	r3, r3, r12, ASR #16
#else
	sub	lr, r2, r3
	add	r10, r2, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
#else
	bfc	r3, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
#else
	bfc	r2, #0, #16
#endif
	sub	r12, r2, r3
	add	r2, r2, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
	ror	r2, r2, #16
	orr	r2, r2, r10, lsl #16
	ror	r2, r2, #16
#else
	bfi	r2, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r10, r12, #16
	mul	r3, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r3, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r3, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r3, r10, lr, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
	ror	r3, r3, #16
	orr	r3, r3, r12, lsl #16
	ror	r3, r3, #16
#else
	bfi	r3, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r4, r5
	sadd16	r4, r4, r5
	smultt	r5, r11, r12
	smultb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r5
	smlabb	r5, r10, lr, r5
	pkhtb	r5, r5, r12, ASR #16
#else
	sub	lr, r4, r5
	add	r10, r4, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
#else
	bfc	r5, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
#else
	bfc	r4, #0, #16
#endif
	sub	r12, r4, r5
	add	r4, r4, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
	ror	r4, r4, #16
	orr	r4, r4, r10, lsl #16
	ror	r4, r4, #16
#else
	bfi	r4, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r10, r12, #16
	mul	r5, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r5, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r5, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r5, r10, lr, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
	ror	r5, r5, #16
	orr	r5, r5, r12, lsl #16
	ror	r5, r5, #16
#else
	bfi	r5, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	ldr	r11, [r1, #244]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r6, r7
	sadd16	r6, r6, r7
	smulbt	r7, r11, r12
	smulbb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r7
	smlabb	r7, r10, lr, r7
	pkhtb	r7, r7, r12, ASR #16
#else
	sub	lr, r6, r7
	add	r10, r6, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
#else
	bfc	r7, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
#else
	bfc	r6, #0, #16
#endif
	sub	r12, r6, r7
	add	r6, r6, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
	ror	r6, r6, #16
	orr	r6, r6, r10, lsl #16
	ror	r6, r6, #16
#else
	bfi	r6, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r10, r12, #16
	mul	r7, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r7, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r7, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r7, r10, lr, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
	ror	r7, r7, #16
	orr	r7, r7, r12, lsl #16
	ror	r7, r7, #16
#else
	bfi	r7, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r8, r9
	sadd16	r8, r8, r9
	smultt	r9, r11, r12
	smultb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r9
	smlabb	r9, r10, lr, r9
	pkhtb	r9, r9, r12, ASR #16
#else
	sub	lr, r8, r9
	add	r10, r8, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
#else
	bfc	r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
#else
	bfc	r8, #0, #16
#endif
	sub	r12, r8, r9
	add	r8, r8, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
	ror	r8, r8, #16
	orr	r8, r8, r10, lsl #16
	ror	r8, r8, #16
#else
	bfi	r8, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r10, r12, #16
	mul	r9, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r9, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r9, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r9, r10, lr, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
	ror	r9, r9, #16
	orr	r9, r9, r12, lsl #16
	ror	r9, r9, #16
#else
	bfi	r9, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	ldr	r11, [r1, #248]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r2, r4
	sadd16	r2, r2, r4
	smulbt	r4, r11, r12
	smulbb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r4
	smlabb	r4, r10, lr, r4
	pkhtb	r4, r4, r12, ASR #16
#else
	sub	lr, r2, r4
	add	r10, r2, r4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
#else
	bfc	r4, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
#else
	bfc	r2, #0, #16
#endif
	sub	r12, r2, r4
	add	r2, r2, r4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
	ror	r2, r2, #16
	orr	r2, r2, r10, lsl #16
	ror	r2, r2, #16
#else
	bfi	r2, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r10, r12, #16
	mul	r4, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r4, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r4, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r4, r10, lr, r4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
	ror	r4, r4, #16
	orr	r4, r4, r12, lsl #16
	ror	r4, r4, #16
#else
	bfi	r4, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r3, r5
	sadd16	r3, r3, r5
	smulbt	r5, r11, r12
	smulbb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r5
	smlabb	r5, r10, lr, r5
	pkhtb	r5, r5, r12, ASR #16
#else
	sub	lr, r3, r5
	add	r10, r3, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
#else
	bfc	r5, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
#else
	bfc	r3, #0, #16
#endif
	sub	r12, r3, r5
	add	r3, r3, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
	ror	r3, r3, #16
	orr	r3, r3, r10, lsl #16
	ror	r3, r3, #16
#else
	bfi	r3, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r10, r12, #16
	mul	r5, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r5, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r5, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r5, r10, lr, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
	ror	r5, r5, #16
	orr	r5, r5, r12, lsl #16
	ror	r5, r5, #16
#else
	bfi	r5, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r6, r8
	sadd16	r6, r6, r8
	smultt	r8, r11, r12
	smultb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r8
	smlabb	r8, r10, lr, r8
	pkhtb	r8, r8, r12, ASR #16
#else
	sub	lr, r6, r8
	add	r10, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
#else
	bfc	r8, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
#else
	bfc	r6, #0, #16
#endif
	sub	r12, r6, r8
	add	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
	ror	r6, r6, #16
	orr	r6, r6, r10, lsl #16
	ror	r6, r6, #16
#else
	bfi	r6, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r10, r12, #16
	mul	r8, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r8, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r8, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r8, r10, lr, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
	ror	r8, r8, #16
	orr	r8, r8, r12, lsl #16
	ror	r8, r8, #16
#else
	bfi	r8, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r7, r9
	sadd16	r7, r7, r9
	smultt	r9, r11, r12
	smultb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r9
	smlabb	r9, r10, lr, r9
	pkhtb	r9, r9, r12, ASR #16
#else
	sub	lr, r7, r9
	add	r10, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
#else
	bfc	r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
#else
	bfc	r7, #0, #16
#endif
	sub	r12, r7, r9
	add	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
	ror	r7, r7, #16
	orr	r7, r7, r10, lsl #16
	ror	r7, r7, #16
#else
	bfi	r7, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r11, #16
#else
	sbfx	lr, r11, #16, #16
#endif
	asr	r10, r12, #16
	mul	r9, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r9, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r9, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r9, r10, lr, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
	ror	r9, r9, #16
	orr	r9, r9, r12, lsl #16
	ror	r9, r9, #16
#else
	bfi	r9, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0xaf
	lsl	r11, r11, #8
	add	r11, r11, #0xc0
#else
	mov	r11, #0xafc0
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	orr	r11, r11, #0x130000
#else
	movt	r11, #0x13
#endif
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x4e
	lsl	r11, r11, #8
	add	r11, r11, #0xbf
#else
	mov	r11, #0x4ebf
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulwb	r12, r11, r2
	smulwt	lr, r11, r2
	smulbt	r12, r10, r12
	smulbt	lr, r10, lr
	pkhbt	r12, r12, lr, LSL #16
	ssub16	r2, r2, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r2, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r2, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r2, #16
#else
	sbfx	lr, r2, #16, #16
#endif
	mul	r12, r11, r12
	mul	lr, r11, lr
	asr	r12, r12, #26
	asr	lr, lr, #26
	mul	r12, r10, r12
	mul	lr, r10, lr
	sub	lr, r2, lr, lsl #16
	sub	r2, r2, r12
	lsr	lr, lr, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff0000
	bic	r2, r2, #0xff000000
	orr	r2, r2, lr, lsl #16
#else
	bfi	r2, lr, #16, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulwb	r12, r11, r3
	smulwt	lr, r11, r3
	smulbt	r12, r10, r12
	smulbt	lr, r10, lr
	pkhbt	r12, r12, lr, LSL #16
	ssub16	r3, r3, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r3, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r3, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r3, #16
#else
	sbfx	lr, r3, #16, #16
#endif
	mul	r12, r11, r12
	mul	lr, r11, lr
	asr	r12, r12, #26
	asr	lr, lr, #26
	mul	r12, r10, r12
	mul	lr, r10, lr
	sub	lr, r3, lr, lsl #16
	sub	r3, r3, r12
	lsr	lr, lr, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff0000
	bic	r3, r3, #0xff000000
	orr	r3, r3, lr, lsl #16
#else
	bfi	r3, lr, #16, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulwb	r12, r11, r4
	smulwt	lr, r11, r4
	smulbt	r12, r10, r12
	smulbt	lr, r10, lr
	pkhbt	r12, r12, lr, LSL #16
	ssub16	r4, r4, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r4, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r4, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r4, #16
#else
	sbfx	lr, r4, #16, #16
#endif
	mul	r12, r11, r12
	mul	lr, r11, lr
	asr	r12, r12, #26
	asr	lr, lr, #26
	mul	r12, r10, r12
	mul	lr, r10, lr
	sub	lr, r4, lr, lsl #16
	sub	r4, r4, r12
	lsr	lr, lr, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff0000
	bic	r4, r4, #0xff000000
	orr	r4, r4, lr, lsl #16
#else
	bfi	r4, lr, #16, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulwb	r12, r11, r5
	smulwt	lr, r11, r5
	smulbt	r12, r10, r12
	smulbt	lr, r10, lr
	pkhbt	r12, r12, lr, LSL #16
	ssub16	r5, r5, r12
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r5, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r5, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	lr, r5, #16
#else
	sbfx	lr, r5, #16, #16
#endif
	mul	r12, r11, r12
	mul	lr, r11, lr
	asr	r12, r12, #26
	asr	lr, lr, #26
	mul	r12, r10, r12
	mul	lr, r10, lr
	sub	lr, r5, lr, lsl #16
	sub	r5, r5, r12
	lsr	lr, lr, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff0000
	bic	r5, r5, #0xff000000
	orr	r5, r5, lr, lsl #16
#else
	bfi	r5, lr, #16, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	ldr	r11, [r1, #252]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r2, r6
	sadd16	r2, r2, r6
	smulbt	r6, r11, r12
	smulbb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r6
	smlabb	r6, r10, lr, r6
	pkhtb	r6, r6, r12, ASR #16
#else
	sub	lr, r2, r6
	add	r10, r2, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
#else
	bfc	r6, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
#else
	bfc	r2, #0, #16
#endif
	sub	r12, r2, r6
	add	r2, r2, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
	ror	r2, r2, #16
	orr	r2, r2, r10, lsl #16
	ror	r2, r2, #16
#else
	bfi	r2, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r10, r12, #16
	mul	r6, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r6, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r6, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r6, r10, lr, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
	ror	r6, r6, #16
	orr	r6, r6, r12, lsl #16
	ror	r6, r6, #16
#else
	bfi	r6, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r3, r7
	sadd16	r3, r3, r7
	smulbt	r7, r11, r12
	smulbb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r7
	smlabb	r7, r10, lr, r7
	pkhtb	r7, r7, r12, ASR #16
#else
	sub	lr, r3, r7
	add	r10, r3, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
#else
	bfc	r7, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
#else
	bfc	r3, #0, #16
#endif
	sub	r12, r3, r7
	add	r3, r3, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
	ror	r3, r3, #16
	orr	r3, r3, r10, lsl #16
	ror	r3, r3, #16
#else
	bfi	r3, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r10, r12, #16
	mul	r7, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r7, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r7, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r7, r10, lr, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
	ror	r7, r7, #16
	orr	r7, r7, r12, lsl #16
	ror	r7, r7, #16
#else
	bfi	r7, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r4, r8
	sadd16	r4, r4, r8
	smulbt	r8, r11, r12
	smulbb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r8
	smlabb	r8, r10, lr, r8
	pkhtb	r8, r8, r12, ASR #16
#else
	sub	lr, r4, r8
	add	r10, r4, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
#else
	bfc	r8, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
#else
	bfc	r4, #0, #16
#endif
	sub	r12, r4, r8
	add	r4, r4, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
	ror	r4, r4, #16
	orr	r4, r4, r10, lsl #16
	ror	r4, r4, #16
#else
	bfi	r4, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r10, r12, #16
	mul	r8, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r8, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r8, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r8, r10, lr, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
	ror	r8, r8, #16
	orr	r8, r8, r12, lsl #16
	ror	r8, r8, #16
#else
	bfi	r8, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r12, r5, r9
	sadd16	r5, r5, r9
	smulbt	r9, r11, r12
	smulbb	r12, r11, r12
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r9
	smlabb	r9, r10, lr, r9
	pkhtb	r9, r9, r12, ASR #16
#else
	sub	lr, r5, r9
	add	r10, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
#else
	bfc	r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
#else
	bfc	r5, #0, #16
#endif
	sub	r12, r5, r9
	add	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r12, r12, #0xff
	bic	r12, r12, #0xff00
	ror	r12, r12, #16
	orr	r12, r12, lr, lsl #16
	ror	r12, r12, #16
#else
	bfi	r12, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
	ror	r5, r5, #16
	orr	r5, r5, r10, lsl #16
	ror	r5, r5, #16
#else
	bfi	r5, r10, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
	asr	r10, r12, #16
	mul	r9, lr, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r12, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r12, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r12, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r12, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r9, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r9, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r9, r10, lr, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
	ror	r9, r9, #16
	orr	r9, r9, r12, lsl #16
	ror	r9, r9, #16
#else
	bfi	r9, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	ldr	r11, [r1, #254]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r2
	smulbt	r2, r11, r2
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r2
	smlabb	r2, r10, lr, r2
	pkhtb	r2, r2, r12, ASR #16
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r2, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r2, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	r2, r2, #16
#else
	sbfx	r2, r2, #16, #16
#endif
	mul	r2, lr, r2
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r2, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r2, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r2, r10, lr, r2
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
	ror	r2, r2, #16
	orr	r2, r2, r12, lsl #16
	ror	r2, r2, #16
#else
	bfi	r2, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r3
	smulbt	r3, r11, r3
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r3
	smlabb	r3, r10, lr, r3
	pkhtb	r3, r3, r12, ASR #16
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r3, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r3, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	r3, r3, #16
#else
	sbfx	r3, r3, #16, #16
#endif
	mul	r3, lr, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r3, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r3, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r3, r10, lr, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
	ror	r3, r3, #16
	orr	r3, r3, r12, lsl #16
	ror	r3, r3, #16
#else
	bfi	r3, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r4
	smulbt	r4, r11, r4
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r4
	smlabb	r4, r10, lr, r4
	pkhtb	r4, r4, r12, ASR #16
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r4, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r4, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	r4, r4, #16
#else
	sbfx	r4, r4, #16, #16
#endif
	mul	r4, lr, r4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r4, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r4, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r4, r10, lr, r4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
	ror	r4, r4, #16
	orr	r4, r4, r12, lsl #16
	ror	r4, r4, #16
#else
	bfi	r4, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r5
	smulbt	r5, r11, r5
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r5
	smlabb	r5, r10, lr, r5
	pkhtb	r5, r5, r12, ASR #16
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r5, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r5, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	r5, r5, #16
#else
	sbfx	r5, r5, #16, #16
#endif
	mul	r5, lr, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r5, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r5, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r5, r10, lr, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
	ror	r5, r5, #16
	orr	r5, r5, r12, lsl #16
	ror	r5, r5, #16
#else
	bfi	r5, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r6
	smulbt	r6, r11, r6
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r6
	smlabb	r6, r10, lr, r6
	pkhtb	r6, r6, r12, ASR #16
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r6, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r6, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	r6, r6, #16
#else
	sbfx	r6, r6, #16, #16
#endif
	mul	r6, lr, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r6, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r6, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r6, r10, lr, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
	ror	r6, r6, #16
	orr	r6, r6, r12, lsl #16
	ror	r6, r6, #16
#else
	bfi	r6, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r7
	smulbt	r7, r11, r7
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r7
	smlabb	r7, r10, lr, r7
	pkhtb	r7, r7, r12, ASR #16
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r7, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r7, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	r7, r7, #16
#else
	sbfx	r7, r7, #16, #16
#endif
	mul	r7, lr, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r7, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r7, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r7, r10, lr, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
	ror	r7, r7, #16
	orr	r7, r7, r12, lsl #16
	ror	r7, r7, #16
#else
	bfi	r7, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r8
	smulbt	r8, r11, r8
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r8
	smlabb	r8, r10, lr, r8
	pkhtb	r8, r8, r12, ASR #16
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r8, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r8, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	r8, r8, #16
#else
	sbfx	r8, r8, #16, #16
#endif
	mul	r8, lr, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r8, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r8, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r8, r10, lr, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
	ror	r8, r8, #16
	orr	r8, r8, r12, lsl #16
	ror	r8, r8, #16
#else
	bfi	r8, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smulbb	r12, r11, r9
	smulbt	r9, r11, r9
	smultb	lr, r10, r12
	smlabb	r12, r10, lr, r12
	smultb	lr, r10, r9
	smlabb	r9, r10, lr, r9
	pkhtb	r9, r9, r12, ASR #16
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r11, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r11, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r9, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r9, #0, #16
#endif
	mul	r12, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	asr	r9, r9, #16
#else
	sbfx	r9, r9, #16, #16
#endif
	mul	r9, lr, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
	mul	lr, r10, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	mla	r12, r10, lr, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xc
	lsl	r10, r10, #8
	add	r10, r10, #0xff
#else
	mov	r10, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, r9, #16
	asr	lr, lr, #16
#else
	sbfx	lr, r9, #0, #16
#endif
	mul	lr, r10, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd
	lsl	r10, r10, #8
	add	r10, r10, #0x1
#else
	mov	r10, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	lr, lr, #16
	asr	lr, lr, #16
#else
	sbfx	lr, lr, #0, #16
#endif
	lsr	r12, r12, #16
	mla	r9, r10, lr, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
	ror	r9, r9, #16
	orr	r9, r9, r12, lsl #16
	ror	r9, r9, #16
#else
	bfi	r9, r12, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	str	r2, [r0]
	str	r3, [r0, #64]
	str	r4, [r0, #128]
	str	r5, [r0, #192]
	str	r6, [r0, #256]
	str	r7, [r0, #320]
	str	r8, [r0, #384]
	str	r9, [r0, #448]
	ldr	r2, [sp]
	subs	r2, r2, #1
	add	r0, r0, #4
	bne	L_kyber_arm32_invntt_loop_321
	add	sp, sp, #8
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	kyber_arm32_invntt,.-kyber_arm32_invntt
	.text
	.type	L_kyber_arm32_basemul_mont_zetas, %object
	.size	L_kyber_arm32_basemul_mont_zetas, 256
	.align	4
L_kyber_arm32_basemul_mont_zetas:
	.short	0x8ed
	.short	0xa0b
	.short	0xb9a
	.short	0x714
	.short	0x5d5
	.short	0x58e
	.short	0x11f
	.short	0xca
	.short	0xc56
	.short	0x26e
	.short	0x629
	.short	0xb6
	.short	0x3c2
	.short	0x84f
	.short	0x73f
	.short	0x5bc
	.short	0x23d
	.short	0x7d4
	.short	0x108
	.short	0x17f
	.short	0x9c4
	.short	0x5b2
	.short	0x6bf
	.short	0xc7f
	.short	0xa58
	.short	0x3f9
	.short	0x2dc
	.short	0x260
	.short	0x6fb
	.short	0x19b
	.short	0xc34
	.short	0x6de
	.short	0x4c7
	.short	0x28c
	.short	0xad9
	.short	0x3f7
	.short	0x7f4
	.short	0x5d3
	.short	0xbe7
	.short	0x6f9
	.short	0x204
	.short	0xcf9
	.short	0xbc1
	.short	0xa67
	.short	0x6af
	.short	0x877
	.short	0x7e
	.short	0x5bd
	.short	0x9ac
	.short	0xca7
	.short	0xbf2
	.short	0x33e
	.short	0x6b
	.short	0x774
	.short	0xc0a
	.short	0x94a
	.short	0xb73
	.short	0x3c1
	.short	0x71d
	.short	0xa2c
	.short	0x1c0
	.short	0x8d8
	.short	0x2a5
	.short	0x806
	.short	0x8b2
	.short	0x1ae
	.short	0x22b
	.short	0x34b
	.short	0x81e
	.short	0x367
	.short	0x60e
	.short	0x69
	.short	0x1a6
	.short	0x24b
	.short	0xb1
	.short	0xc16
	.short	0xbde
	.short	0xb35
	.short	0x626
	.short	0x675
	.short	0xc0b
	.short	0x30a
	.short	0x487
	.short	0xc6e
	.short	0x9f8
	.short	0x5cb
	.short	0xaa7
	.short	0x45f
	.short	0x6cb
	.short	0x284
	.short	0x999
	.short	0x15d
	.short	0x1a2
	.short	0x149
	.short	0xc65
	.short	0xcb6
	.short	0x331
	.short	0x449
	.short	0x25b
	.short	0x262
	.short	0x52a
	.short	0x7fc
	.short	0x748
	.short	0x180
	.short	0x842
	.short	0xc79
	.short	0x4c2
	.short	0x7ca
	.short	0x997
	.short	0xdc
	.short	0x85e
	.short	0x686
	.short	0x860
	.short	0x707
	.short	0x803
	.short	0x31a
	.short	0x71b
	.short	0x9ab
	.short	0x99b
	.short	0x1de
	.short	0xc95
	.short	0xbcd
	.short	0x3e4
	.short	0x3df
	.short	0x3be
	.short	0x74d
	.short	0x5f2
	.short	0x65c
	.text
	.align	4
	.globl	kyber_arm32_basemul_mont
	.type	kyber_arm32_basemul_mont, %function
kyber_arm32_basemul_mont:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	adr	r3, L_kyber_arm32_basemul_mont_zetas
	add	r3, r3, #0x80
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xd
	lsl	r12, r12, #8
	add	r12, r12, #0x1
#else
	mov	r12, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	orr	r12, r12, #0xc000000
	orr	r12, r12, #0xff0000
#else
	movt	r12, #0xcff
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	mov	r8, #0
L_kyber_arm32_basemul_mont_loop:
	ldm	r1!, {r4, r5}
	ldm	r2!, {r6, r7}
	ldr	lr, [r3, r8]
	add	r8, r8, #2
	push	{r8}
	cmp	r8, #0x80
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smultt	r8, r4, r6
	smultt	r10, r5, r7
	smultb	r9, r12, r8
	smultb	r11, r12, r10
	smlabb	r8, r12, r9, r8
	smlabb	r10, r12, r11, r10
	rsb	r11, lr, #0
	smulbt	r8, lr, r8
	smulbt	r10, r11, r10
	smlabb	r8, r4, r6, r8
	smlabb	r10, r5, r7, r10
	smultb	r9, r12, r8
	smultb	r11, r12, r10
	smlabb	r8, r12, r9, r8
	smlabb	r10, r12, r11, r10
	smulbt	r9, r4, r6
	smulbt	r11, r5, r7
	smlatb	r9, r4, r6, r9
	smlatb	r11, r5, r7, r11
	smultb	r6, r12, r9
	smultb	r7, r12, r11
	smlabb	r9, r12, r6, r9
	smlabb	r11, r12, r7, r11
	pkhtb	r4, r9, r8, ASR #16
	pkhtb	r5, r11, r10, ASR #16
#else
	asr	r8, r4, #16
	asr	r10, r5, #16
	asr	r9, r6, #16
	asr	r11, r7, #16
	mul	r8, r9, r8
	mul	r10, r11, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xc
	lsl	r12, r12, #8
	add	r12, r12, #0xff
#else
	mov	r12, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r9, r8, #16
	asr	r9, r9, #16
#else
	sbfx	r9, r8, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r11, r10, #16
	asr	r11, r11, #16
#else
	sbfx	r11, r10, #0, #16
#endif
	mul	r9, r12, r8
	mul	r11, r12, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xd
	lsl	r12, r12, #8
	add	r12, r12, #0x1
#else
	mov	r12, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r9, r9, #16
	asr	r9, r9, #16
#else
	sbfx	r9, r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r11, r11, #16
	asr	r11, r11, #16
#else
	sbfx	r11, r11, #0, #16
#endif
	mla	r8, r12, r9, r8
	mla	r10, r12, r11, r10
	rsb	r11, lr, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r9, lr, #16
	asr	r9, r9, #16
#else
	sbfx	r9, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r11, r11, #16
	asr	r11, r11, #16
#else
	sbfx	r11, r11, #0, #16
#endif
	asr	r8, r8, #16
	asr	r10, r10, #16
	mul	r8, r9, r8
	mul	r10, r11, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r9, r4, #16
	asr	r9, r9, #16
#else
	sbfx	r9, r4, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r11, r5, #16
	asr	r11, r11, #16
#else
	sbfx	r11, r5, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r6, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r6, #0, #16
#endif
	mla	r8, r9, r12, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r7, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r7, #0, #16
#endif
	mla	r10, r11, r12, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xc
	lsl	r12, r12, #8
	add	r12, r12, #0xff
#else
	mov	r12, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r9, r8, #16
	asr	r9, r9, #16
#else
	sbfx	r9, r8, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r11, r10, #16
	asr	r11, r11, #16
#else
	sbfx	r11, r10, #0, #16
#endif
	mul	r9, r12, r9
	mul	r11, r12, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xd
	lsl	r12, r12, #8
	add	r12, r12, #0x1
#else
	mov	r12, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r9, r9, #16
	asr	r9, r9, #16
#else
	sbfx	r9, r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r11, r11, #16
	asr	r11, r11, #16
#else
	sbfx	r11, r11, #0, #16
#endif
	mla	r8, r12, r9, r8
	mla	r10, r12, r11, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r9, r4, #16
	asr	r9, r9, #16
#else
	sbfx	r9, r4, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r11, r5, #16
	asr	r11, r11, #16
#else
	sbfx	r11, r5, #0, #16
#endif
	asr	r12, r6, #16
	mul	r9, r12, r9
	asr	r12, r7, #16
	mul	r11, r12, r11
	asr	r4, r4, #16
	asr	r5, r5, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r6, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r6, #0, #16
#endif
	mla	r9, r4, r12, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r7, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r7, #0, #16
#endif
	mla	r11, r5, r12, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xc
	lsl	r12, r12, #8
	add	r12, r12, #0xff
#else
	mov	r12, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r6, r9, #16
	asr	r6, r6, #16
#else
	sbfx	r6, r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r7, r11, #16
	asr	r7, r7, #16
#else
	sbfx	r7, r11, #0, #16
#endif
	mul	r6, r12, r6
	mul	r7, r12, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xd
	lsl	r12, r12, #8
	add	r12, r12, #0x1
#else
	mov	r12, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r4, r6, #16
	asr	r4, r4, #16
#else
	sbfx	r4, r6, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r5, r7, #16
	asr	r5, r5, #16
#else
	sbfx	r5, r7, #0, #16
#endif
	mla	r9, r12, r4, r9
	mla	r11, r12, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
#else
	bfc	r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r11, r11, #0xff
	bic	r11, r11, #0xff00
#else
	bfc	r11, #0, #16
#endif
	orr	r4, r9, r8, lsr #16
	orr	r5, r11, r10, lsr #16
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	stm	r0!, {r4, r5}
	pop	{r8}
	bne	L_kyber_arm32_basemul_mont_loop
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	kyber_arm32_basemul_mont,.-kyber_arm32_basemul_mont
	.text
	.align	4
	.globl	kyber_arm32_basemul_mont_add
	.type	kyber_arm32_basemul_mont_add, %function
kyber_arm32_basemul_mont_add:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	adr	r3, L_kyber_arm32_basemul_mont_zetas
	add	r3, r3, #0x80
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xd
	lsl	r12, r12, #8
	add	r12, r12, #0x1
#else
	mov	r12, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	orr	r12, r12, #0xc000000
	orr	r12, r12, #0xff0000
#else
	movt	r12, #0xcff
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	mov	r8, #0
L_kyber_arm32_basemul_mont_add_loop:
	ldm	r1!, {r4, r5}
	ldm	r2!, {r6, r7}
	ldr	lr, [r3, r8]
	add	r8, r8, #2
	push	{r8}
	cmp	r8, #0x80
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	smultt	r8, r4, r6
	smultt	r10, r5, r7
	smultb	r9, r12, r8
	smultb	r11, r12, r10
	smlabb	r8, r12, r9, r8
	smlabb	r10, r12, r11, r10
	rsb	r11, lr, #0
	smulbt	r8, lr, r8
	smulbt	r10, r11, r10
	smlabb	r8, r4, r6, r8
	smlabb	r10, r5, r7, r10
	smultb	r9, r12, r8
	smultb	r11, r12, r10
	smlabb	r8, r12, r9, r8
	smlabb	r10, r12, r11, r10
	smulbt	r9, r4, r6
	smulbt	r11, r5, r7
	smlatb	r9, r4, r6, r9
	smlatb	r11, r5, r7, r11
	smultb	r6, r12, r9
	smultb	r7, r12, r11
	smlabb	r9, r12, r6, r9
	smlabb	r11, r12, r7, r11
	ldm	r0, {r4, r5}
	pkhtb	r9, r9, r8, ASR #16
	pkhtb	r11, r11, r10, ASR #16
	sadd16	r4, r4, r9
	sadd16	r5, r5, r11
#else
	asr	r8, r4, #16
	asr	r10, r5, #16
	asr	r9, r6, #16
	asr	r11, r7, #16
	mul	r8, r9, r8
	mul	r10, r11, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xc
	lsl	r12, r12, #8
	add	r12, r12, #0xff
#else
	mov	r12, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r9, r8, #16
	asr	r9, r9, #16
#else
	sbfx	r9, r8, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r11, r10, #16
	asr	r11, r11, #16
#else
	sbfx	r11, r10, #0, #16
#endif
	mul	r9, r12, r8
	mul	r11, r12, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xd
	lsl	r12, r12, #8
	add	r12, r12, #0x1
#else
	mov	r12, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r9, r9, #16
	asr	r9, r9, #16
#else
	sbfx	r9, r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r11, r11, #16
	asr	r11, r11, #16
#else
	sbfx	r11, r11, #0, #16
#endif
	mla	r8, r12, r9, r8
	mla	r10, r12, r11, r10
	rsb	r11, lr, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r9, lr, #16
	asr	r9, r9, #16
#else
	sbfx	r9, lr, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r11, r11, #16
	asr	r11, r11, #16
#else
	sbfx	r11, r11, #0, #16
#endif
	asr	r8, r8, #16
	asr	r10, r10, #16
	mul	r8, r9, r8
	mul	r10, r11, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r9, r4, #16
	asr	r9, r9, #16
#else
	sbfx	r9, r4, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r11, r5, #16
	asr	r11, r11, #16
#else
	sbfx	r11, r5, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r6, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r6, #0, #16
#endif
	mla	r8, r9, r12, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r7, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r7, #0, #16
#endif
	mla	r10, r11, r12, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xc
	lsl	r12, r12, #8
	add	r12, r12, #0xff
#else
	mov	r12, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r9, r8, #16
	asr	r9, r9, #16
#else
	sbfx	r9, r8, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r11, r10, #16
	asr	r11, r11, #16
#else
	sbfx	r11, r10, #0, #16
#endif
	mul	r9, r12, r9
	mul	r11, r12, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xd
	lsl	r12, r12, #8
	add	r12, r12, #0x1
#else
	mov	r12, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r9, r9, #16
	asr	r9, r9, #16
#else
	sbfx	r9, r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r11, r11, #16
	asr	r11, r11, #16
#else
	sbfx	r11, r11, #0, #16
#endif
	mla	r8, r12, r9, r8
	mla	r10, r12, r11, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r9, r4, #16
	asr	r9, r9, #16
#else
	sbfx	r9, r4, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r11, r5, #16
	asr	r11, r11, #16
#else
	sbfx	r11, r5, #0, #16
#endif
	asr	r12, r6, #16
	mul	r9, r12, r9
	asr	r12, r7, #16
	mul	r11, r12, r11
	asr	r4, r4, #16
	asr	r5, r5, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r6, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r6, #0, #16
#endif
	mla	r9, r4, r12, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r12, r7, #16
	asr	r12, r12, #16
#else
	sbfx	r12, r7, #0, #16
#endif
	mla	r11, r5, r12, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xc
	lsl	r12, r12, #8
	add	r12, r12, #0xff
#else
	mov	r12, #0xcff
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r6, r9, #16
	asr	r6, r6, #16
#else
	sbfx	r6, r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r7, r11, #16
	asr	r7, r7, #16
#else
	sbfx	r7, r11, #0, #16
#endif
	mul	r6, r12, r6
	mul	r7, r12, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xd
	lsl	r12, r12, #8
	add	r12, r12, #0x1
#else
	mov	r12, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r4, r6, #16
	asr	r4, r4, #16
#else
	sbfx	r4, r6, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r5, r7, #16
	asr	r5, r5, #16
#else
	sbfx	r5, r7, #0, #16
#endif
	mla	r9, r12, r4, r9
	mla	r11, r12, r5, r11
	ldm	r0, {r4, r5}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
#else
	bfc	r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r11, r11, #0xff
	bic	r11, r11, #0xff00
#else
	bfc	r11, #0, #16
#endif
	orr	r9, r9, r8, lsr #16
	orr	r11, r11, r10, lsr #16
	add	r8, r4, r9
	add	r10, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
#else
	bfc	r9, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r11, r11, #0xff
	bic	r11, r11, #0xff00
#else
	bfc	r11, #0, #16
#endif
	add	r4, r4, r9
	add	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
	ror	r4, r4, #16
	orr	r4, r4, r8, lsl #16
	ror	r4, r4, #16
#else
	bfi	r4, r8, #0, #16
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
	ror	r5, r5, #16
	orr	r5, r5, r10, lsl #16
	ror	r5, r5, #16
#else
	bfi	r5, r10, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	stm	r0!, {r4, r5}
	pop	{r8}
	bne	L_kyber_arm32_basemul_mont_add_loop
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	kyber_arm32_basemul_mont_add,.-kyber_arm32_basemul_mont_add
	.text
	.align	4
	.globl	kyber_arm32_csubq
	.type	kyber_arm32_csubq, %function
kyber_arm32_csubq:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xd
	lsl	r12, r12, #8
	add	r12, r12, #0x1
#else
	mov	r12, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	lr, #0xd
	lsl	lr, lr, #8
	add	lr, lr, #0x1
#else
	mov	lr, #0xd01
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	orr	lr, lr, #0xd000000
	orr	lr, lr, #0x10000
#else
	movt	lr, #0xd01
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x80
	lsl	r11, r11, #8
	add	r11, r11, #0x0
#else
	mov	r11, #0x8000
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	orr	r11, r11, #0x80000000
#else
	movt	r11, #0x8000
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x1
	lsl	r1, r1, #8
	add	r1, r1, #0x0
#else
	mov	r1, #0x100
#endif
L_kyber_arm32_csubq_loop:
	ldm	r0, {r2, r3, r4, r5}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH >= 6)
	ssub16	r2, r2, lr
	ssub16	r3, r3, lr
	ssub16	r4, r4, lr
	ssub16	r5, r5, lr
	and	r6, r2, r11
	and	r7, r3, r11
	and	r8, r4, r11
	and	r9, r5, r11
	lsr	r6, r6, #15
	lsr	r7, r7, #15
	lsr	r8, r8, #15
	lsr	r9, r9, #15
	mul	r6, r12, r6
	mul	r7, r12, r7
	mul	r8, r12, r8
	mul	r9, r12, r9
	sadd16	r2, r2, r6
	sadd16	r3, r3, r7
	sadd16	r4, r4, r8
	sadd16	r5, r5, r9
#else
	sub	r6, r2, lr
	sub	r2, r2, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
	ror	r2, r2, #16
	orr	r2, r2, r6, lsl #16
	ror	r2, r2, #16
#else
	bfi	r2, r6, #0, #16
#endif
	sub	r7, r3, lr
	sub	r3, r3, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
	ror	r3, r3, #16
	orr	r3, r3, r7, lsl #16
	ror	r3, r3, #16
#else
	bfi	r3, r7, #0, #16
#endif
	sub	r8, r4, lr
	sub	r4, r4, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
	ror	r4, r4, #16
	orr	r4, r4, r8, lsl #16
	ror	r4, r4, #16
#else
	bfi	r4, r8, #0, #16
#endif
	sub	r9, r5, lr
	sub	r5, r5, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
	ror	r5, r5, #16
	orr	r5, r5, r9, lsl #16
	ror	r5, r5, #16
#else
	bfi	r5, r9, #0, #16
#endif
	and	r6, r2, r11
	and	r7, r3, r11
	and	r8, r4, r11
	and	r9, r5, r11
	lsr	r6, r6, #15
	lsr	r7, r7, #15
	lsr	r8, r8, #15
	lsr	r9, r9, #15
	mul	r6, r12, r6
	mul	r7, r12, r7
	mul	r8, r12, r8
	mul	r9, r12, r9
	add	r10, r2, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r6, r6, #0xff
	bic	r6, r6, #0xff00
#else
	bfc	r6, #0, #16
#endif
	add	r2, r2, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r2, r2, #0xff
	bic	r2, r2, #0xff00
	ror	r2, r2, #16
	orr	r2, r2, r10, lsl #16
	ror	r2, r2, #16
#else
	bfi	r2, r10, #0, #16
#endif
	add	r10, r3, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff
	bic	r7, r7, #0xff00
#else
	bfc	r7, #0, #16
#endif
	add	r3, r3, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r3, r3, #0xff
	bic	r3, r3, #0xff00
	ror	r3, r3, #16
	orr	r3, r3, r10, lsl #16
	ror	r3, r3, #16
#else
	bfi	r3, r10, #0, #16
#endif
	add	r10, r4, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0xff
	bic	r8, r8, #0xff00
#else
	bfc	r8, #0, #16
#endif
	add	r4, r4, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r4, r4, #0xff
	bic	r4, r4, #0xff00
	ror	r4, r4, #16
	orr	r4, r4, r10, lsl #16
	ror	r4, r4, #16
#else
	bfi	r4, r10, #0, #16
#endif
	add	r10, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xff
	bic	r9, r9, #0xff00
#else
	bfc	r9, #0, #16
#endif
	add	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xff
	bic	r5, r5, #0xff00
	ror	r5, r5, #16
	orr	r5, r5, r10, lsl #16
	ror	r5, r5, #16
#else
	bfi	r5, r10, #0, #16
#endif
#endif /* WOLFSLS_ARM_ARCH && WOLFSSL_ARM_ARCH >= 6 */
	stm	r0!, {r2, r3, r4, r5}
	subs	r1, r1, #8
	bne	L_kyber_arm32_csubq_loop
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	kyber_arm32_csubq,.-kyber_arm32_csubq
	.text
	.align	4
	.globl	kyber_arm32_rej_uniform
	.type	kyber_arm32_rej_uniform, %function
kyber_arm32_rej_uniform:
	push	{r4, r5, r6, r7, r8, lr}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r8, #0xd
	lsl	r8, r8, #8
	add	r8, r8, #0x1
#else
	mov	r8, #0xd01
#endif
	mov	r12, #0
L_kyber_arm32_rej_uniform_loop_no_fail:
	cmp	r1, #8
	blt	L_kyber_arm32_rej_uniform_done_no_fail
	ldm	r2!, {r4, r5, r6}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r7, r4, #20
	lsr	r7, r7, #20
#else
	ubfx	r7, r4, #0, #12
#endif
	strh	r7, [r0, r12]
	sub	lr, r7, r8
	lsr	lr, lr, #31
	sub	r1, r1, lr
	add	r12, r12, lr, lsl #1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r7, r4, #8
	lsr	r7, r7, #20
#else
	ubfx	r7, r4, #12, #12
#endif
	strh	r7, [r0, r12]
	sub	lr, r7, r8
	lsr	lr, lr, #31
	sub	r1, r1, lr
	add	r12, r12, lr, lsl #1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsr	r7, r4, #24
#else
	ubfx	r7, r4, #24, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xf00
	ror	r7, r7, #12
	orr	r7, r7, r5, lsl #28
	ror	r7, r7, #20
#else
	bfi	r7, r5, #8, #4
#endif
	strh	r7, [r0, r12]
	sub	lr, r7, r8
	lsr	lr, lr, #31
	sub	r1, r1, lr
	add	r12, r12, lr, lsl #1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r7, r5, #16
	lsr	r7, r7, #20
#else
	ubfx	r7, r5, #4, #12
#endif
	strh	r7, [r0, r12]
	sub	lr, r7, r8
	lsr	lr, lr, #31
	sub	r1, r1, lr
	add	r12, r12, lr, lsl #1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r7, r5, #4
	lsr	r7, r7, #20
#else
	ubfx	r7, r5, #16, #12
#endif
	strh	r7, [r0, r12]
	sub	lr, r7, r8
	lsr	lr, lr, #31
	sub	r1, r1, lr
	add	r12, r12, lr, lsl #1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsr	r7, r5, #28
#else
	ubfx	r7, r5, #28, #4
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff0
	ror	r7, r7, #12
	orr	r7, r7, r6, lsl #24
	ror	r7, r7, #20
#else
	bfi	r7, r6, #4, #8
#endif
	strh	r7, [r0, r12]
	sub	lr, r7, r8
	lsr	lr, lr, #31
	sub	r1, r1, lr
	add	r12, r12, lr, lsl #1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r7, r6, #12
	lsr	r7, r7, #20
#else
	ubfx	r7, r6, #8, #12
#endif
	strh	r7, [r0, r12]
	sub	lr, r7, r8
	lsr	lr, lr, #31
	sub	r1, r1, lr
	add	r12, r12, lr, lsl #1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsr	r7, r6, #20
#else
	ubfx	r7, r6, #20, #12
#endif
	strh	r7, [r0, r12]
	sub	lr, r7, r8
	lsr	lr, lr, #31
	sub	r1, r1, lr
	add	r12, r12, lr, lsl #1
	subs	r3, r3, #12
	bne	L_kyber_arm32_rej_uniform_loop_no_fail
	b	L_kyber_arm32_rej_uniform_done
L_kyber_arm32_rej_uniform_done_no_fail:
	cmp	r1, #0
	beq	L_kyber_arm32_rej_uniform_done
L_kyber_arm32_rej_uniform_loop:
	ldm	r2!, {r4, r5, r6}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r7, r4, #20
	lsr	r7, r7, #20
#else
	ubfx	r7, r4, #0, #12
#endif
	cmp	r7, r8
	bge	L_kyber_arm32_rej_uniform_fail_0
	strh	r7, [r0, r12]
	subs	r1, r1, #1
	add	r12, r12, #2
	beq	L_kyber_arm32_rej_uniform_done
L_kyber_arm32_rej_uniform_fail_0:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r7, r4, #8
	lsr	r7, r7, #20
#else
	ubfx	r7, r4, #12, #12
#endif
	cmp	r7, r8
	bge	L_kyber_arm32_rej_uniform_fail_1
	strh	r7, [r0, r12]
	subs	r1, r1, #1
	add	r12, r12, #2
	beq	L_kyber_arm32_rej_uniform_done
L_kyber_arm32_rej_uniform_fail_1:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsr	r7, r4, #24
#else
	ubfx	r7, r4, #24, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xf00
	ror	r7, r7, #12
	orr	r7, r7, r5, lsl #28
	ror	r7, r7, #20
#else
	bfi	r7, r5, #8, #4
#endif
	cmp	r7, r8
	bge	L_kyber_arm32_rej_uniform_fail_2
	strh	r7, [r0, r12]
	subs	r1, r1, #1
	add	r12, r12, #2
	beq	L_kyber_arm32_rej_uniform_done
L_kyber_arm32_rej_uniform_fail_2:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r7, r5, #16
	lsr	r7, r7, #20
#else
	ubfx	r7, r5, #4, #12
#endif
	cmp	r7, r8
	bge	L_kyber_arm32_rej_uniform_fail_3
	strh	r7, [r0, r12]
	subs	r1, r1, #1
	add	r12, r12, #2
	beq	L_kyber_arm32_rej_uniform_done
L_kyber_arm32_rej_uniform_fail_3:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r7, r5, #4
	lsr	r7, r7, #20
#else
	ubfx	r7, r5, #16, #12
#endif
	cmp	r7, r8
	bge	L_kyber_arm32_rej_uniform_fail_4
	strh	r7, [r0, r12]
	subs	r1, r1, #1
	add	r12, r12, #2
	beq	L_kyber_arm32_rej_uniform_done
L_kyber_arm32_rej_uniform_fail_4:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsr	r7, r5, #28
#else
	ubfx	r7, r5, #28, #4
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0xff0
	ror	r7, r7, #12
	orr	r7, r7, r6, lsl #24
	ror	r7, r7, #20
#else
	bfi	r7, r6, #4, #8
#endif
	cmp	r7, r8
	bge	L_kyber_arm32_rej_uniform_fail_5
	strh	r7, [r0, r12]
	subs	r1, r1, #1
	add	r12, r12, #2
	beq	L_kyber_arm32_rej_uniform_done
L_kyber_arm32_rej_uniform_fail_5:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r7, r6, #12
	lsr	r7, r7, #20
#else
	ubfx	r7, r6, #8, #12
#endif
	cmp	r7, r8
	bge	L_kyber_arm32_rej_uniform_fail_6
	strh	r7, [r0, r12]
	subs	r1, r1, #1
	add	r12, r12, #2
	beq	L_kyber_arm32_rej_uniform_done
L_kyber_arm32_rej_uniform_fail_6:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsr	r7, r6, #20
#else
	ubfx	r7, r6, #20, #12
#endif
	cmp	r7, r8
	bge	L_kyber_arm32_rej_uniform_fail_7
	strh	r7, [r0, r12]
	subs	r1, r1, #1
	add	r12, r12, #2
	beq	L_kyber_arm32_rej_uniform_done
L_kyber_arm32_rej_uniform_fail_7:
	subs	r3, r3, #12
	bgt	L_kyber_arm32_rej_uniform_loop
L_kyber_arm32_rej_uniform_done:
	lsr	r0, r12, #1
	pop	{r4, r5, r6, r7, r8, pc}
	.size	kyber_arm32_rej_uniform,.-kyber_arm32_rej_uniform
#endif /* WOLFSSL_WC_KYBER */
#endif /* !__aarch64__ && !WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
