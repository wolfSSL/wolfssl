/* thumb2-kyber-asm
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
 *   ruby ./kyber/kyber.rb thumb2 ../wolfssl/wolfcrypt/src/port/arm/thumb2-kyber-asm.S
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_ARMASM
#ifdef WOLFSSL_ARMASM_THUMB2
#ifndef WOLFSSL_ARMASM_INLINE
	.thumb
	.syntax unified
#ifdef WOLFSSL_WC_KYBER
	.text
	.type	L_kyber_thumb2_ntt_zetas, %object
	.size	L_kyber_thumb2_ntt_zetas, 256
	.align	4
L_kyber_thumb2_ntt_zetas:
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
	.globl	kyber_thumb2_ntt
	.type	kyber_thumb2_ntt, %function
kyber_thumb2_ntt:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0x8
	ADR	r1, L_kyber_thumb2_ntt_zetas
#ifndef WOLFSSL_ARM_ARCH_7M
	MOV	r12, #0xd01
	MOVT	r12, #0xcff
#endif /* !WOLFSSL_ARM_ARCH_7M */
	MOV	r2, #0x10
L_kyber_thumb2_ntt_loop_123:
	STR	r2, [sp]
	LDRH	lr, [r1, #2]
	LDR	r2, [r0]
	LDR	r3, [r0, #64]
	LDR	r4, [r0, #128]
	LDR	r5, [r0, #192]
	LDR	r6, [r0, #256]
	LDR	r7, [r0, #320]
	LDR	r8, [r0, #384]
	LDR	r9, [r0, #448]
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r6
	SMULBT	r6, lr, r6
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r6
	SMLABB	r11, r12, r11, r6
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r6, r2, r10
	SADD16	r2, r2, r10
#else
	SBFX	r10, r6, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r6, r6, #16
	MUL	r10, r11, r10
	MUL	r6, r11, r6
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r6, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r6
	SUB	r6, r2, r11
	ADD	r2, r2, r11
	SUB	r11, r2, r10, LSR #16
	ADD	r10, r2, r10, LSR #16
	BFI	r6, r11, #0, #16
	BFI	r2, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r7
	SMULBT	r7, lr, r7
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r7
	SMLABB	r11, r12, r11, r7
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r7, r3, r10
	SADD16	r3, r3, r10
#else
	SBFX	r10, r7, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r7, r7, #16
	MUL	r10, r11, r10
	MUL	r7, r11, r7
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r7, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r7
	SUB	r7, r3, r11
	ADD	r3, r3, r11
	SUB	r11, r3, r10, LSR #16
	ADD	r10, r3, r10, LSR #16
	BFI	r7, r11, #0, #16
	BFI	r3, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r8
	SMULBT	r8, lr, r8
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r8
	SMLABB	r11, r12, r11, r8
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r8, r4, r10
	SADD16	r4, r4, r10
#else
	SBFX	r10, r8, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r8, r8, #16
	MUL	r10, r11, r10
	MUL	r8, r11, r8
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r8, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r8
	SUB	r8, r4, r11
	ADD	r4, r4, r11
	SUB	r11, r4, r10, LSR #16
	ADD	r10, r4, r10, LSR #16
	BFI	r8, r11, #0, #16
	BFI	r4, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r9
	SMULBT	r9, lr, r9
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r9
	SMLABB	r11, r12, r11, r9
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r9, r5, r10
	SADD16	r5, r5, r10
#else
	SBFX	r10, r9, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r9, r9, #16
	MUL	r10, r11, r10
	MUL	r9, r11, r9
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r9, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r9
	SUB	r9, r5, r11
	ADD	r5, r5, r11
	SUB	r11, r5, r10, LSR #16
	ADD	r10, r5, r10, LSR #16
	BFI	r9, r11, #0, #16
	BFI	r5, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	LDR	lr, [r1, #4]
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r4
	SMULBT	r4, lr, r4
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r4
	SMLABB	r11, r12, r11, r4
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r4, r2, r10
	SADD16	r2, r2, r10
#else
	SBFX	r10, r4, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r4, r4, #16
	MUL	r10, r11, r10
	MUL	r4, r11, r4
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r4, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r4
	SUB	r4, r2, r11
	ADD	r2, r2, r11
	SUB	r11, r2, r10, LSR #16
	ADD	r10, r2, r10, LSR #16
	BFI	r4, r11, #0, #16
	BFI	r2, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r5
	SMULBT	r5, lr, r5
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r5
	SMLABB	r11, r12, r11, r5
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r5, r3, r10
	SADD16	r3, r3, r10
#else
	SBFX	r10, r5, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r5, r5, #16
	MUL	r10, r11, r10
	MUL	r5, r11, r5
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r5, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r5
	SUB	r5, r3, r11
	ADD	r3, r3, r11
	SUB	r11, r3, r10, LSR #16
	ADD	r10, r3, r10, LSR #16
	BFI	r5, r11, #0, #16
	BFI	r3, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULTB	r10, lr, r8
	SMULTT	r8, lr, r8
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r8
	SMLABB	r11, r12, r11, r8
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r8, r6, r10
	SADD16	r6, r6, r10
#else
	SBFX	r10, r8, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r8, r8, #16
	MUL	r10, r11, r10
	MUL	r8, r11, r8
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r8, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r8
	SUB	r8, r6, r11
	ADD	r6, r6, r11
	SUB	r11, r6, r10, LSR #16
	ADD	r10, r6, r10, LSR #16
	BFI	r8, r11, #0, #16
	BFI	r6, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULTB	r10, lr, r9
	SMULTT	r9, lr, r9
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r9
	SMLABB	r11, r12, r11, r9
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r9, r7, r10
	SADD16	r7, r7, r10
#else
	SBFX	r10, r9, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r9, r9, #16
	MUL	r10, r11, r10
	MUL	r9, r11, r9
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r9, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r9
	SUB	r9, r7, r11
	ADD	r7, r7, r11
	SUB	r11, r7, r10, LSR #16
	ADD	r10, r7, r10, LSR #16
	BFI	r9, r11, #0, #16
	BFI	r7, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	LDR	lr, [r1, #8]
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r3
	SMULBT	r3, lr, r3
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r3
	SMLABB	r11, r12, r11, r3
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r3, r2, r10
	SADD16	r2, r2, r10
#else
	SBFX	r10, r3, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r3, r3, #16
	MUL	r10, r11, r10
	MUL	r3, r11, r3
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r3, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r3
	SUB	r3, r2, r11
	ADD	r2, r2, r11
	SUB	r11, r2, r10, LSR #16
	ADD	r10, r2, r10, LSR #16
	BFI	r3, r11, #0, #16
	BFI	r2, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULTB	r10, lr, r5
	SMULTT	r5, lr, r5
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r5
	SMLABB	r11, r12, r11, r5
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r5, r4, r10
	SADD16	r4, r4, r10
#else
	SBFX	r10, r5, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r5, r5, #16
	MUL	r10, r11, r10
	MUL	r5, r11, r5
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r5, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r5
	SUB	r5, r4, r11
	ADD	r4, r4, r11
	SUB	r11, r4, r10, LSR #16
	ADD	r10, r4, r10, LSR #16
	BFI	r5, r11, #0, #16
	BFI	r4, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	LDR	lr, [r1, #12]
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r7
	SMULBT	r7, lr, r7
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r7
	SMLABB	r11, r12, r11, r7
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r7, r6, r10
	SADD16	r6, r6, r10
#else
	SBFX	r10, r7, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r7, r7, #16
	MUL	r10, r11, r10
	MUL	r7, r11, r7
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r7, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r7
	SUB	r7, r6, r11
	ADD	r6, r6, r11
	SUB	r11, r6, r10, LSR #16
	ADD	r10, r6, r10, LSR #16
	BFI	r7, r11, #0, #16
	BFI	r6, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULTB	r10, lr, r9
	SMULTT	r9, lr, r9
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r9
	SMLABB	r11, r12, r11, r9
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r9, r8, r10
	SADD16	r8, r8, r10
#else
	SBFX	r10, r9, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r9, r9, #16
	MUL	r10, r11, r10
	MUL	r9, r11, r9
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r9, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r9
	SUB	r9, r8, r11
	ADD	r8, r8, r11
	SUB	r11, r8, r10, LSR #16
	ADD	r10, r8, r10, LSR #16
	BFI	r9, r11, #0, #16
	BFI	r8, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	STR	r2, [r0]
	STR	r3, [r0, #64]
	STR	r4, [r0, #128]
	STR	r5, [r0, #192]
	STR	r6, [r0, #256]
	STR	r7, [r0, #320]
	STR	r8, [r0, #384]
	STR	r9, [r0, #448]
	LDR	r2, [sp]
	SUBS	r2, r2, #0x1
	ADD	r0, r0, #0x4
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_kyber_thumb2_ntt_loop_123
#else
	BNE.N	L_kyber_thumb2_ntt_loop_123
#endif
	SUB	r0, r0, #0x40
	MOV	r3, #0x0
L_kyber_thumb2_ntt_loop_4_j:
	STR	r3, [sp, #4]
	ADD	lr, r1, r3, LSR #4
	MOV	r2, #0x4
	LDR	lr, [lr, #16]
L_kyber_thumb2_ntt_loop_4_i:
	STR	r2, [sp]
	LDR	r2, [r0]
	LDR	r3, [r0, #16]
	LDR	r4, [r0, #32]
	LDR	r5, [r0, #48]
	LDR	r6, [r0, #64]
	LDR	r7, [r0, #80]
	LDR	r8, [r0, #96]
	LDR	r9, [r0, #112]
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r4
	SMULBT	r4, lr, r4
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r4
	SMLABB	r11, r12, r11, r4
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r4, r2, r10
	SADD16	r2, r2, r10
#else
	SBFX	r10, r4, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r4, r4, #16
	MUL	r10, r11, r10
	MUL	r4, r11, r4
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r4, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r4
	SUB	r4, r2, r11
	ADD	r2, r2, r11
	SUB	r11, r2, r10, LSR #16
	ADD	r10, r2, r10, LSR #16
	BFI	r4, r11, #0, #16
	BFI	r2, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r5
	SMULBT	r5, lr, r5
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r5
	SMLABB	r11, r12, r11, r5
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r5, r3, r10
	SADD16	r3, r3, r10
#else
	SBFX	r10, r5, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r5, r5, #16
	MUL	r10, r11, r10
	MUL	r5, r11, r5
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r5, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r5
	SUB	r5, r3, r11
	ADD	r3, r3, r11
	SUB	r11, r3, r10, LSR #16
	ADD	r10, r3, r10, LSR #16
	BFI	r5, r11, #0, #16
	BFI	r3, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULTB	r10, lr, r8
	SMULTT	r8, lr, r8
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r8
	SMLABB	r11, r12, r11, r8
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r8, r6, r10
	SADD16	r6, r6, r10
#else
	SBFX	r10, r8, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r8, r8, #16
	MUL	r10, r11, r10
	MUL	r8, r11, r8
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r8, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r8
	SUB	r8, r6, r11
	ADD	r6, r6, r11
	SUB	r11, r6, r10, LSR #16
	ADD	r10, r6, r10, LSR #16
	BFI	r8, r11, #0, #16
	BFI	r6, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULTB	r10, lr, r9
	SMULTT	r9, lr, r9
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r9
	SMLABB	r11, r12, r11, r9
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r9, r7, r10
	SADD16	r7, r7, r10
#else
	SBFX	r10, r9, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r9, r9, #16
	MUL	r10, r11, r10
	MUL	r9, r11, r9
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r9, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r9
	SUB	r9, r7, r11
	ADD	r7, r7, r11
	SUB	r11, r7, r10, LSR #16
	ADD	r10, r7, r10, LSR #16
	BFI	r9, r11, #0, #16
	BFI	r7, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	STR	r2, [r0]
	STR	r3, [r0, #16]
	STR	r4, [r0, #32]
	STR	r5, [r0, #48]
	STR	r6, [r0, #64]
	STR	r7, [r0, #80]
	STR	r8, [r0, #96]
	STR	r9, [r0, #112]
	LDRD	r2, r3, [sp]
	SUBS	r2, r2, #0x1
	ADD	r0, r0, #0x4
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_kyber_thumb2_ntt_loop_4_i
#else
	BNE.N	L_kyber_thumb2_ntt_loop_4_i
#endif
	ADD	r3, r3, #0x40
	RSBS	r10, r3, #0x100
	ADD	r0, r0, #0x70
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_kyber_thumb2_ntt_loop_4_j
#else
	BNE.N	L_kyber_thumb2_ntt_loop_4_j
#endif
	SUB	r0, r0, #0x200
	MOV	r3, #0x0
L_kyber_thumb2_ntt_loop_567:
	ADD	lr, r1, r3, LSR #3
	STR	r3, [sp, #4]
	LDRH	lr, [lr, #32]
	LDR	r2, [r0]
	LDR	r3, [r0, #4]
	LDR	r4, [r0, #8]
	LDR	r5, [r0, #12]
	LDR	r6, [r0, #16]
	LDR	r7, [r0, #20]
	LDR	r8, [r0, #24]
	LDR	r9, [r0, #28]
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r6
	SMULBT	r6, lr, r6
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r6
	SMLABB	r11, r12, r11, r6
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r6, r2, r10
	SADD16	r2, r2, r10
#else
	SBFX	r10, r6, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r6, r6, #16
	MUL	r10, r11, r10
	MUL	r6, r11, r6
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r6, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r6
	SUB	r6, r2, r11
	ADD	r2, r2, r11
	SUB	r11, r2, r10, LSR #16
	ADD	r10, r2, r10, LSR #16
	BFI	r6, r11, #0, #16
	BFI	r2, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r7
	SMULBT	r7, lr, r7
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r7
	SMLABB	r11, r12, r11, r7
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r7, r3, r10
	SADD16	r3, r3, r10
#else
	SBFX	r10, r7, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r7, r7, #16
	MUL	r10, r11, r10
	MUL	r7, r11, r7
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r7, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r7
	SUB	r7, r3, r11
	ADD	r3, r3, r11
	SUB	r11, r3, r10, LSR #16
	ADD	r10, r3, r10, LSR #16
	BFI	r7, r11, #0, #16
	BFI	r3, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r8
	SMULBT	r8, lr, r8
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r8
	SMLABB	r11, r12, r11, r8
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r8, r4, r10
	SADD16	r4, r4, r10
#else
	SBFX	r10, r8, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r8, r8, #16
	MUL	r10, r11, r10
	MUL	r8, r11, r8
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r8, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r8
	SUB	r8, r4, r11
	ADD	r4, r4, r11
	SUB	r11, r4, r10, LSR #16
	ADD	r10, r4, r10, LSR #16
	BFI	r8, r11, #0, #16
	BFI	r4, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r9
	SMULBT	r9, lr, r9
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r9
	SMLABB	r11, r12, r11, r9
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r9, r5, r10
	SADD16	r5, r5, r10
#else
	SBFX	r10, r9, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r9, r9, #16
	MUL	r10, r11, r10
	MUL	r9, r11, r9
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r9, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r9
	SUB	r9, r5, r11
	ADD	r5, r5, r11
	SUB	r11, r5, r10, LSR #16
	ADD	r10, r5, r10, LSR #16
	BFI	r9, r11, #0, #16
	BFI	r5, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	LDR	lr, [sp, #4]
	ADD	lr, r1, lr, LSR #2
	LDR	lr, [lr, #64]
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r4
	SMULBT	r4, lr, r4
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r4
	SMLABB	r11, r12, r11, r4
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r4, r2, r10
	SADD16	r2, r2, r10
#else
	SBFX	r10, r4, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r4, r4, #16
	MUL	r10, r11, r10
	MUL	r4, r11, r4
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r4, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r4
	SUB	r4, r2, r11
	ADD	r2, r2, r11
	SUB	r11, r2, r10, LSR #16
	ADD	r10, r2, r10, LSR #16
	BFI	r4, r11, #0, #16
	BFI	r2, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r5
	SMULBT	r5, lr, r5
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r5
	SMLABB	r11, r12, r11, r5
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r5, r3, r10
	SADD16	r3, r3, r10
#else
	SBFX	r10, r5, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r5, r5, #16
	MUL	r10, r11, r10
	MUL	r5, r11, r5
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r5, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r5
	SUB	r5, r3, r11
	ADD	r3, r3, r11
	SUB	r11, r3, r10, LSR #16
	ADD	r10, r3, r10, LSR #16
	BFI	r5, r11, #0, #16
	BFI	r3, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULTB	r10, lr, r8
	SMULTT	r8, lr, r8
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r8
	SMLABB	r11, r12, r11, r8
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r8, r6, r10
	SADD16	r6, r6, r10
#else
	SBFX	r10, r8, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r8, r8, #16
	MUL	r10, r11, r10
	MUL	r8, r11, r8
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r8, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r8
	SUB	r8, r6, r11
	ADD	r6, r6, r11
	SUB	r11, r6, r10, LSR #16
	ADD	r10, r6, r10, LSR #16
	BFI	r8, r11, #0, #16
	BFI	r6, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULTB	r10, lr, r9
	SMULTT	r9, lr, r9
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r9
	SMLABB	r11, r12, r11, r9
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r9, r7, r10
	SADD16	r7, r7, r10
#else
	SBFX	r10, r9, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r9, r9, #16
	MUL	r10, r11, r10
	MUL	r9, r11, r9
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r9, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r9
	SUB	r9, r7, r11
	ADD	r7, r7, r11
	SUB	r11, r7, r10, LSR #16
	ADD	r10, r7, r10, LSR #16
	BFI	r9, r11, #0, #16
	BFI	r7, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	LDR	lr, [sp, #4]
	ADD	lr, r1, lr, LSR #1
	LDR	lr, [lr, #128]
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r3
	SMULBT	r3, lr, r3
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r3
	SMLABB	r11, r12, r11, r3
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r3, r2, r10
	SADD16	r2, r2, r10
#else
	SBFX	r10, r3, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r3, r3, #16
	MUL	r10, r11, r10
	MUL	r3, r11, r3
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r3, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r3
	SUB	r3, r2, r11
	ADD	r2, r2, r11
	SUB	r11, r2, r10, LSR #16
	ADD	r10, r2, r10, LSR #16
	BFI	r3, r11, #0, #16
	BFI	r2, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULTB	r10, lr, r5
	SMULTT	r5, lr, r5
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r5
	SMLABB	r11, r12, r11, r5
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r5, r4, r10
	SADD16	r4, r4, r10
#else
	SBFX	r10, r5, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r5, r5, #16
	MUL	r10, r11, r10
	MUL	r5, r11, r5
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r5, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r5
	SUB	r5, r4, r11
	ADD	r4, r4, r11
	SUB	r11, r4, r10, LSR #16
	ADD	r10, r4, r10, LSR #16
	BFI	r5, r11, #0, #16
	BFI	r4, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	LDR	lr, [sp, #4]
	ADD	lr, r1, lr, LSR #1
	LDR	lr, [lr, #132]
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r7
	SMULBT	r7, lr, r7
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r7
	SMLABB	r11, r12, r11, r7
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r7, r6, r10
	SADD16	r6, r6, r10
#else
	SBFX	r10, r7, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r7, r7, #16
	MUL	r10, r11, r10
	MUL	r7, r11, r7
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r7, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r7
	SUB	r7, r6, r11
	ADD	r6, r6, r11
	SUB	r11, r6, r10, LSR #16
	ADD	r10, r6, r10, LSR #16
	BFI	r7, r11, #0, #16
	BFI	r6, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULTB	r10, lr, r9
	SMULTT	r9, lr, r9
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r9
	SMLABB	r11, r12, r11, r9
	PKHTB	r10, r11, r10, ASR #16
	SSUB16	r9, r8, r10
	SADD16	r8, r8, r10
#else
	SBFX	r10, r9, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r9, r9, #16
	MUL	r10, r11, r10
	MUL	r9, r11, r9
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r9, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r11, r12, r11, r9
	SUB	r9, r8, r11
	ADD	r8, r8, r11
	SUB	r11, r8, r10, LSR #16
	ADD	r10, r8, r10, LSR #16
	BFI	r9, r11, #0, #16
	BFI	r8, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	MOV	lr, #0xafc0
	MOVT	lr, #0x13
#else
	MOV	lr, #0x4ebf
	MOV	r12, #0xd01
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULWB	r10, lr, r2
	SMULWT	r11, lr, r2
	SMULBT	r10, r12, r10
	SMULBT	r11, r12, r11
	PKHBT	r10, r10, r11, LSL #16
	SSUB16	r2, r2, r10
#else
	SBFX	r10, r2, #0, #16
	SBFX	r11, r2, #16, #16
	MUL	r10, lr, r10
	MUL	r11, lr, r11
	ASR	r10, r10, #26
	ASR	r11, r11, #26
	MUL	r10, r12, r10
	MUL	r11, r12, r11
	SUB	r11, r2, r11, LSL #16
	SUB	r2, r2, r10
	LSR	r11, r11, #16
	BFI	r2, r11, #16, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULWB	r10, lr, r3
	SMULWT	r11, lr, r3
	SMULBT	r10, r12, r10
	SMULBT	r11, r12, r11
	PKHBT	r10, r10, r11, LSL #16
	SSUB16	r3, r3, r10
#else
	SBFX	r10, r3, #0, #16
	SBFX	r11, r3, #16, #16
	MUL	r10, lr, r10
	MUL	r11, lr, r11
	ASR	r10, r10, #26
	ASR	r11, r11, #26
	MUL	r10, r12, r10
	MUL	r11, r12, r11
	SUB	r11, r3, r11, LSL #16
	SUB	r3, r3, r10
	LSR	r11, r11, #16
	BFI	r3, r11, #16, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULWB	r10, lr, r4
	SMULWT	r11, lr, r4
	SMULBT	r10, r12, r10
	SMULBT	r11, r12, r11
	PKHBT	r10, r10, r11, LSL #16
	SSUB16	r4, r4, r10
#else
	SBFX	r10, r4, #0, #16
	SBFX	r11, r4, #16, #16
	MUL	r10, lr, r10
	MUL	r11, lr, r11
	ASR	r10, r10, #26
	ASR	r11, r11, #26
	MUL	r10, r12, r10
	MUL	r11, r12, r11
	SUB	r11, r4, r11, LSL #16
	SUB	r4, r4, r10
	LSR	r11, r11, #16
	BFI	r4, r11, #16, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULWB	r10, lr, r5
	SMULWT	r11, lr, r5
	SMULBT	r10, r12, r10
	SMULBT	r11, r12, r11
	PKHBT	r10, r10, r11, LSL #16
	SSUB16	r5, r5, r10
#else
	SBFX	r10, r5, #0, #16
	SBFX	r11, r5, #16, #16
	MUL	r10, lr, r10
	MUL	r11, lr, r11
	ASR	r10, r10, #26
	ASR	r11, r11, #26
	MUL	r10, r12, r10
	MUL	r11, r12, r11
	SUB	r11, r5, r11, LSL #16
	SUB	r5, r5, r10
	LSR	r11, r11, #16
	BFI	r5, r11, #16, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULWB	r10, lr, r6
	SMULWT	r11, lr, r6
	SMULBT	r10, r12, r10
	SMULBT	r11, r12, r11
	PKHBT	r10, r10, r11, LSL #16
	SSUB16	r6, r6, r10
#else
	SBFX	r10, r6, #0, #16
	SBFX	r11, r6, #16, #16
	MUL	r10, lr, r10
	MUL	r11, lr, r11
	ASR	r10, r10, #26
	ASR	r11, r11, #26
	MUL	r10, r12, r10
	MUL	r11, r12, r11
	SUB	r11, r6, r11, LSL #16
	SUB	r6, r6, r10
	LSR	r11, r11, #16
	BFI	r6, r11, #16, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULWB	r10, lr, r7
	SMULWT	r11, lr, r7
	SMULBT	r10, r12, r10
	SMULBT	r11, r12, r11
	PKHBT	r10, r10, r11, LSL #16
	SSUB16	r7, r7, r10
#else
	SBFX	r10, r7, #0, #16
	SBFX	r11, r7, #16, #16
	MUL	r10, lr, r10
	MUL	r11, lr, r11
	ASR	r10, r10, #26
	ASR	r11, r11, #26
	MUL	r10, r12, r10
	MUL	r11, r12, r11
	SUB	r11, r7, r11, LSL #16
	SUB	r7, r7, r10
	LSR	r11, r11, #16
	BFI	r7, r11, #16, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULWB	r10, lr, r8
	SMULWT	r11, lr, r8
	SMULBT	r10, r12, r10
	SMULBT	r11, r12, r11
	PKHBT	r10, r10, r11, LSL #16
	SSUB16	r8, r8, r10
#else
	SBFX	r10, r8, #0, #16
	SBFX	r11, r8, #16, #16
	MUL	r10, lr, r10
	MUL	r11, lr, r11
	ASR	r10, r10, #26
	ASR	r11, r11, #26
	MUL	r10, r12, r10
	MUL	r11, r12, r11
	SUB	r11, r8, r11, LSL #16
	SUB	r8, r8, r10
	LSR	r11, r11, #16
	BFI	r8, r11, #16, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULWB	r10, lr, r9
	SMULWT	r11, lr, r9
	SMULBT	r10, r12, r10
	SMULBT	r11, r12, r11
	PKHBT	r10, r10, r11, LSL #16
	SSUB16	r9, r9, r10
#else
	SBFX	r10, r9, #0, #16
	SBFX	r11, r9, #16, #16
	MUL	r10, lr, r10
	MUL	r11, lr, r11
	ASR	r10, r10, #26
	ASR	r11, r11, #26
	MUL	r10, r12, r10
	MUL	r11, r12, r11
	SUB	r11, r9, r11, LSL #16
	SUB	r9, r9, r10
	LSR	r11, r11, #16
	BFI	r9, r11, #16, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	MOV	r12, #0xd01
	MOVT	r12, #0xcff
#endif /* !WOLFSSL_ARM_ARCH_7M */
	STR	r2, [r0]
	STR	r3, [r0, #4]
	STR	r4, [r0, #8]
	STR	r5, [r0, #12]
	STR	r6, [r0, #16]
	STR	r7, [r0, #20]
	STR	r8, [r0, #24]
	STR	r9, [r0, #28]
	LDR	r3, [sp, #4]
	ADD	r3, r3, #0x10
	RSBS	r10, r3, #0x100
	ADD	r0, r0, #0x20
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_kyber_thumb2_ntt_loop_567
#else
	BNE.N	L_kyber_thumb2_ntt_loop_567
#endif
	ADD	sp, sp, #0x8
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 1270 */
	.size	kyber_thumb2_ntt,.-kyber_thumb2_ntt
	.text
	.type	L_kyber_thumb2_invntt_zetas_inv, %object
	.size	L_kyber_thumb2_invntt_zetas_inv, 256
	.align	4
L_kyber_thumb2_invntt_zetas_inv:
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
	.globl	kyber_thumb2_invntt
	.type	kyber_thumb2_invntt, %function
kyber_thumb2_invntt:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0x8
	ADR	r1, L_kyber_thumb2_invntt_zetas_inv
#ifndef WOLFSSL_ARM_ARCH_7M
	MOV	r12, #0xd01
	MOVT	r12, #0xcff
#endif /* !WOLFSSL_ARM_ARCH_7M */
	MOV	r3, #0x0
L_kyber_thumb2_invntt_loop_765:
	ADD	lr, r1, r3, LSR #1
	STR	r3, [sp, #4]
	LDR	r2, [r0]
	LDR	r3, [r0, #4]
	LDR	r4, [r0, #8]
	LDR	r5, [r0, #12]
	LDR	r6, [r0, #16]
	LDR	r7, [r0, #20]
	LDR	r8, [r0, #24]
	LDR	r9, [r0, #28]
	LDR	lr, [lr]
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r2, r3
	SADD16	r2, r2, r3
	SMULBT	r3, lr, r10
	SMULBB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r3
	SMLABB	r3, r12, r11, r3
	PKHTB	r3, r3, r10, ASR #16
#else
	SUB	r11, r2, r3
	ADD	r12, r2, r3
	BFC	r3, #0, #16
	BFC	r2, #0, #16
	SUB	r10, r2, r3
	ADD	r2, r2, r3
	BFI	r10, r11, #0, #16
	BFI	r2, r12, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r12, r10, #16
	MUL	r3, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r3, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r3, r12, r11, r3
	BFI	r3, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r4, r5
	SADD16	r4, r4, r5
	SMULTT	r5, lr, r10
	SMULTB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r5
	SMLABB	r5, r12, r11, r5
	PKHTB	r5, r5, r10, ASR #16
#else
	SUB	r11, r4, r5
	ADD	r12, r4, r5
	BFC	r5, #0, #16
	BFC	r4, #0, #16
	SUB	r10, r4, r5
	ADD	r4, r4, r5
	BFI	r10, r11, #0, #16
	BFI	r4, r12, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r12, r10, #16
	MUL	r5, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r5, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r5, r12, r11, r5
	BFI	r5, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	LDR	lr, [sp, #4]
	ADD	lr, r1, lr, LSR #1
	LDR	lr, [lr, #4]
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r6, r7
	SADD16	r6, r6, r7
	SMULBT	r7, lr, r10
	SMULBB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r7
	SMLABB	r7, r12, r11, r7
	PKHTB	r7, r7, r10, ASR #16
#else
	SUB	r11, r6, r7
	ADD	r12, r6, r7
	BFC	r7, #0, #16
	BFC	r6, #0, #16
	SUB	r10, r6, r7
	ADD	r6, r6, r7
	BFI	r10, r11, #0, #16
	BFI	r6, r12, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r12, r10, #16
	MUL	r7, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r7, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r7, r12, r11, r7
	BFI	r7, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r8, r9
	SADD16	r8, r8, r9
	SMULTT	r9, lr, r10
	SMULTB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r9
	SMLABB	r9, r12, r11, r9
	PKHTB	r9, r9, r10, ASR #16
#else
	SUB	r11, r8, r9
	ADD	r12, r8, r9
	BFC	r9, #0, #16
	BFC	r8, #0, #16
	SUB	r10, r8, r9
	ADD	r8, r8, r9
	BFI	r10, r11, #0, #16
	BFI	r8, r12, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r12, r10, #16
	MUL	r9, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r9, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r9, r12, r11, r9
	BFI	r9, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	LDR	lr, [sp, #4]
	ADD	lr, r1, lr, LSR #2
	LDR	lr, [lr, #128]
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r2, r4
	SADD16	r2, r2, r4
	SMULBT	r4, lr, r10
	SMULBB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r4
	SMLABB	r4, r12, r11, r4
	PKHTB	r4, r4, r10, ASR #16
#else
	SUB	r11, r2, r4
	ADD	r12, r2, r4
	BFC	r4, #0, #16
	BFC	r2, #0, #16
	SUB	r10, r2, r4
	ADD	r2, r2, r4
	BFI	r10, r11, #0, #16
	BFI	r2, r12, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r12, r10, #16
	MUL	r4, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r4, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r4, r12, r11, r4
	BFI	r4, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r3, r5
	SADD16	r3, r3, r5
	SMULBT	r5, lr, r10
	SMULBB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r5
	SMLABB	r5, r12, r11, r5
	PKHTB	r5, r5, r10, ASR #16
#else
	SUB	r11, r3, r5
	ADD	r12, r3, r5
	BFC	r5, #0, #16
	BFC	r3, #0, #16
	SUB	r10, r3, r5
	ADD	r3, r3, r5
	BFI	r10, r11, #0, #16
	BFI	r3, r12, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r12, r10, #16
	MUL	r5, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r5, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r5, r12, r11, r5
	BFI	r5, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r6, r8
	SADD16	r6, r6, r8
	SMULTT	r8, lr, r10
	SMULTB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r8
	SMLABB	r8, r12, r11, r8
	PKHTB	r8, r8, r10, ASR #16
#else
	SUB	r11, r6, r8
	ADD	r12, r6, r8
	BFC	r8, #0, #16
	BFC	r6, #0, #16
	SUB	r10, r6, r8
	ADD	r6, r6, r8
	BFI	r10, r11, #0, #16
	BFI	r6, r12, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r12, r10, #16
	MUL	r8, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r8, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r8, r12, r11, r8
	BFI	r8, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r7, r9
	SADD16	r7, r7, r9
	SMULTT	r9, lr, r10
	SMULTB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r9
	SMLABB	r9, r12, r11, r9
	PKHTB	r9, r9, r10, ASR #16
#else
	SUB	r11, r7, r9
	ADD	r12, r7, r9
	BFC	r9, #0, #16
	BFC	r7, #0, #16
	SUB	r10, r7, r9
	ADD	r7, r7, r9
	BFI	r10, r11, #0, #16
	BFI	r7, r12, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r12, r10, #16
	MUL	r9, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r9, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r9, r12, r11, r9
	BFI	r9, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	LDR	lr, [sp, #4]
	ADD	lr, r1, lr, LSR #3
	LDR	lr, [lr, #192]
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r2, r6
	SADD16	r2, r2, r6
	SMULBT	r6, lr, r10
	SMULBB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r6
	SMLABB	r6, r12, r11, r6
	PKHTB	r6, r6, r10, ASR #16
#else
	SUB	r11, r2, r6
	ADD	r12, r2, r6
	BFC	r6, #0, #16
	BFC	r2, #0, #16
	SUB	r10, r2, r6
	ADD	r2, r2, r6
	BFI	r10, r11, #0, #16
	BFI	r2, r12, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r12, r10, #16
	MUL	r6, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r6, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r6, r12, r11, r6
	BFI	r6, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r3, r7
	SADD16	r3, r3, r7
	SMULBT	r7, lr, r10
	SMULBB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r7
	SMLABB	r7, r12, r11, r7
	PKHTB	r7, r7, r10, ASR #16
#else
	SUB	r11, r3, r7
	ADD	r12, r3, r7
	BFC	r7, #0, #16
	BFC	r3, #0, #16
	SUB	r10, r3, r7
	ADD	r3, r3, r7
	BFI	r10, r11, #0, #16
	BFI	r3, r12, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r12, r10, #16
	MUL	r7, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r7, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r7, r12, r11, r7
	BFI	r7, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r4, r8
	SADD16	r4, r4, r8
	SMULBT	r8, lr, r10
	SMULBB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r8
	SMLABB	r8, r12, r11, r8
	PKHTB	r8, r8, r10, ASR #16
#else
	SUB	r11, r4, r8
	ADD	r12, r4, r8
	BFC	r8, #0, #16
	BFC	r4, #0, #16
	SUB	r10, r4, r8
	ADD	r4, r4, r8
	BFI	r10, r11, #0, #16
	BFI	r4, r12, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r12, r10, #16
	MUL	r8, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r8, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r8, r12, r11, r8
	BFI	r8, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r5, r9
	SADD16	r5, r5, r9
	SMULBT	r9, lr, r10
	SMULBB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r9
	SMLABB	r9, r12, r11, r9
	PKHTB	r9, r9, r10, ASR #16
#else
	SUB	r11, r5, r9
	ADD	r12, r5, r9
	BFC	r9, #0, #16
	BFC	r5, #0, #16
	SUB	r10, r5, r9
	ADD	r5, r5, r9
	BFI	r10, r11, #0, #16
	BFI	r5, r12, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r12, r10, #16
	MUL	r9, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r9, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r9, r12, r11, r9
	BFI	r9, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	MOV	lr, #0xafc0
	MOVT	lr, #0x13
#else
	MOV	lr, #0x4ebf
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULWB	r10, lr, r2
	SMULWT	r11, lr, r2
	SMULBT	r10, r12, r10
	SMULBT	r11, r12, r11
	PKHBT	r10, r10, r11, LSL #16
	SSUB16	r2, r2, r10
#else
	SBFX	r10, r2, #0, #16
	SBFX	r11, r2, #16, #16
	MUL	r10, lr, r10
	MUL	r11, lr, r11
	ASR	r10, r10, #26
	ASR	r11, r11, #26
	MUL	r10, r12, r10
	MUL	r11, r12, r11
	SUB	r11, r2, r11, LSL #16
	SUB	r2, r2, r10
	LSR	r11, r11, #16
	BFI	r2, r11, #16, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULWB	r10, lr, r3
	SMULWT	r11, lr, r3
	SMULBT	r10, r12, r10
	SMULBT	r11, r12, r11
	PKHBT	r10, r10, r11, LSL #16
	SSUB16	r3, r3, r10
#else
	SBFX	r10, r3, #0, #16
	SBFX	r11, r3, #16, #16
	MUL	r10, lr, r10
	MUL	r11, lr, r11
	ASR	r10, r10, #26
	ASR	r11, r11, #26
	MUL	r10, r12, r10
	MUL	r11, r12, r11
	SUB	r11, r3, r11, LSL #16
	SUB	r3, r3, r10
	LSR	r11, r11, #16
	BFI	r3, r11, #16, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULWB	r10, lr, r4
	SMULWT	r11, lr, r4
	SMULBT	r10, r12, r10
	SMULBT	r11, r12, r11
	PKHBT	r10, r10, r11, LSL #16
	SSUB16	r4, r4, r10
#else
	SBFX	r10, r4, #0, #16
	SBFX	r11, r4, #16, #16
	MUL	r10, lr, r10
	MUL	r11, lr, r11
	ASR	r10, r10, #26
	ASR	r11, r11, #26
	MUL	r10, r12, r10
	MUL	r11, r12, r11
	SUB	r11, r4, r11, LSL #16
	SUB	r4, r4, r10
	LSR	r11, r11, #16
	BFI	r4, r11, #16, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULWB	r10, lr, r5
	SMULWT	r11, lr, r5
	SMULBT	r10, r12, r10
	SMULBT	r11, r12, r11
	PKHBT	r10, r10, r11, LSL #16
	SSUB16	r5, r5, r10
#else
	SBFX	r10, r5, #0, #16
	SBFX	r11, r5, #16, #16
	MUL	r10, lr, r10
	MUL	r11, lr, r11
	ASR	r10, r10, #26
	ASR	r11, r11, #26
	MUL	r10, r12, r10
	MUL	r11, r12, r11
	SUB	r11, r5, r11, LSL #16
	SUB	r5, r5, r10
	LSR	r11, r11, #16
	BFI	r5, r11, #16, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	STR	r2, [r0]
	STR	r3, [r0, #4]
	STR	r4, [r0, #8]
	STR	r5, [r0, #12]
	STR	r6, [r0, #16]
	STR	r7, [r0, #20]
	STR	r8, [r0, #24]
	STR	r9, [r0, #28]
	LDR	r3, [sp, #4]
	ADD	r3, r3, #0x10
	RSBS	r10, r3, #0x100
	ADD	r0, r0, #0x20
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_kyber_thumb2_invntt_loop_765
#else
	BNE.N	L_kyber_thumb2_invntt_loop_765
#endif
	SUB	r0, r0, #0x200
	MOV	r3, #0x0
L_kyber_thumb2_invntt_loop_4_j:
	STR	r3, [sp, #4]
	ADD	lr, r1, r3, LSR #4
	MOV	r2, #0x4
	LDR	lr, [lr, #224]
L_kyber_thumb2_invntt_loop_4_i:
	STR	r2, [sp]
	LDR	r2, [r0]
	LDR	r3, [r0, #16]
	LDR	r4, [r0, #32]
	LDR	r5, [r0, #48]
	LDR	r6, [r0, #64]
	LDR	r7, [r0, #80]
	LDR	r8, [r0, #96]
	LDR	r9, [r0, #112]
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r2, r4
	SADD16	r2, r2, r4
	SMULBT	r4, lr, r10
	SMULBB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r4
	SMLABB	r4, r12, r11, r4
	PKHTB	r4, r4, r10, ASR #16
#else
	SUB	r11, r2, r4
	ADD	r12, r2, r4
	BFC	r4, #0, #16
	BFC	r2, #0, #16
	SUB	r10, r2, r4
	ADD	r2, r2, r4
	BFI	r10, r11, #0, #16
	BFI	r2, r12, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r12, r10, #16
	MUL	r4, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r4, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r4, r12, r11, r4
	BFI	r4, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r3, r5
	SADD16	r3, r3, r5
	SMULBT	r5, lr, r10
	SMULBB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r5
	SMLABB	r5, r12, r11, r5
	PKHTB	r5, r5, r10, ASR #16
#else
	SUB	r11, r3, r5
	ADD	r12, r3, r5
	BFC	r5, #0, #16
	BFC	r3, #0, #16
	SUB	r10, r3, r5
	ADD	r3, r3, r5
	BFI	r10, r11, #0, #16
	BFI	r3, r12, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r12, r10, #16
	MUL	r5, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r5, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r5, r12, r11, r5
	BFI	r5, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r6, r8
	SADD16	r6, r6, r8
	SMULTT	r8, lr, r10
	SMULTB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r8
	SMLABB	r8, r12, r11, r8
	PKHTB	r8, r8, r10, ASR #16
#else
	SUB	r11, r6, r8
	ADD	r12, r6, r8
	BFC	r8, #0, #16
	BFC	r6, #0, #16
	SUB	r10, r6, r8
	ADD	r6, r6, r8
	BFI	r10, r11, #0, #16
	BFI	r6, r12, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r12, r10, #16
	MUL	r8, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r8, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r8, r12, r11, r8
	BFI	r8, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r7, r9
	SADD16	r7, r7, r9
	SMULTT	r9, lr, r10
	SMULTB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r9
	SMLABB	r9, r12, r11, r9
	PKHTB	r9, r9, r10, ASR #16
#else
	SUB	r11, r7, r9
	ADD	r12, r7, r9
	BFC	r9, #0, #16
	BFC	r7, #0, #16
	SUB	r10, r7, r9
	ADD	r7, r7, r9
	BFI	r10, r11, #0, #16
	BFI	r7, r12, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r12, r10, #16
	MUL	r9, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r9, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r9, r12, r11, r9
	BFI	r9, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	STR	r2, [r0]
	STR	r3, [r0, #16]
	STR	r4, [r0, #32]
	STR	r5, [r0, #48]
	STR	r6, [r0, #64]
	STR	r7, [r0, #80]
	STR	r8, [r0, #96]
	STR	r9, [r0, #112]
	LDRD	r2, r3, [sp]
	SUBS	r2, r2, #0x1
	ADD	r0, r0, #0x4
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_kyber_thumb2_invntt_loop_4_i
#else
	BNE.N	L_kyber_thumb2_invntt_loop_4_i
#endif
	ADD	r3, r3, #0x40
	RSBS	r10, r3, #0x100
	ADD	r0, r0, #0x70
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_kyber_thumb2_invntt_loop_4_j
#else
	BNE.N	L_kyber_thumb2_invntt_loop_4_j
#endif
	SUB	r0, r0, #0x200
	MOV	r2, #0x10
L_kyber_thumb2_invntt_loop_321:
	STR	r2, [sp]
	LDRH	lr, [r1, #2]
	LDR	r2, [r0]
	LDR	r3, [r0, #64]
	LDR	r4, [r0, #128]
	LDR	r5, [r0, #192]
	LDR	r6, [r0, #256]
	LDR	r7, [r0, #320]
	LDR	r8, [r0, #384]
	LDR	r9, [r0, #448]
	LDR	lr, [r1, #240]
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r2, r3
	SADD16	r2, r2, r3
	SMULBT	r3, lr, r10
	SMULBB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r3
	SMLABB	r3, r12, r11, r3
	PKHTB	r3, r3, r10, ASR #16
#else
	SUB	r11, r2, r3
	ADD	r12, r2, r3
	BFC	r3, #0, #16
	BFC	r2, #0, #16
	SUB	r10, r2, r3
	ADD	r2, r2, r3
	BFI	r10, r11, #0, #16
	BFI	r2, r12, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r12, r10, #16
	MUL	r3, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r3, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r3, r12, r11, r3
	BFI	r3, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r4, r5
	SADD16	r4, r4, r5
	SMULTT	r5, lr, r10
	SMULTB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r5
	SMLABB	r5, r12, r11, r5
	PKHTB	r5, r5, r10, ASR #16
#else
	SUB	r11, r4, r5
	ADD	r12, r4, r5
	BFC	r5, #0, #16
	BFC	r4, #0, #16
	SUB	r10, r4, r5
	ADD	r4, r4, r5
	BFI	r10, r11, #0, #16
	BFI	r4, r12, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r12, r10, #16
	MUL	r5, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r5, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r5, r12, r11, r5
	BFI	r5, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	LDR	lr, [r1, #244]
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r6, r7
	SADD16	r6, r6, r7
	SMULBT	r7, lr, r10
	SMULBB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r7
	SMLABB	r7, r12, r11, r7
	PKHTB	r7, r7, r10, ASR #16
#else
	SUB	r11, r6, r7
	ADD	r12, r6, r7
	BFC	r7, #0, #16
	BFC	r6, #0, #16
	SUB	r10, r6, r7
	ADD	r6, r6, r7
	BFI	r10, r11, #0, #16
	BFI	r6, r12, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r12, r10, #16
	MUL	r7, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r7, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r7, r12, r11, r7
	BFI	r7, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r8, r9
	SADD16	r8, r8, r9
	SMULTT	r9, lr, r10
	SMULTB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r9
	SMLABB	r9, r12, r11, r9
	PKHTB	r9, r9, r10, ASR #16
#else
	SUB	r11, r8, r9
	ADD	r12, r8, r9
	BFC	r9, #0, #16
	BFC	r8, #0, #16
	SUB	r10, r8, r9
	ADD	r8, r8, r9
	BFI	r10, r11, #0, #16
	BFI	r8, r12, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r12, r10, #16
	MUL	r9, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r9, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r9, r12, r11, r9
	BFI	r9, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	LDR	lr, [r1, #248]
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r2, r4
	SADD16	r2, r2, r4
	SMULBT	r4, lr, r10
	SMULBB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r4
	SMLABB	r4, r12, r11, r4
	PKHTB	r4, r4, r10, ASR #16
#else
	SUB	r11, r2, r4
	ADD	r12, r2, r4
	BFC	r4, #0, #16
	BFC	r2, #0, #16
	SUB	r10, r2, r4
	ADD	r2, r2, r4
	BFI	r10, r11, #0, #16
	BFI	r2, r12, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r12, r10, #16
	MUL	r4, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r4, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r4, r12, r11, r4
	BFI	r4, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r3, r5
	SADD16	r3, r3, r5
	SMULBT	r5, lr, r10
	SMULBB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r5
	SMLABB	r5, r12, r11, r5
	PKHTB	r5, r5, r10, ASR #16
#else
	SUB	r11, r3, r5
	ADD	r12, r3, r5
	BFC	r5, #0, #16
	BFC	r3, #0, #16
	SUB	r10, r3, r5
	ADD	r3, r3, r5
	BFI	r10, r11, #0, #16
	BFI	r3, r12, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r12, r10, #16
	MUL	r5, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r5, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r5, r12, r11, r5
	BFI	r5, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r6, r8
	SADD16	r6, r6, r8
	SMULTT	r8, lr, r10
	SMULTB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r8
	SMLABB	r8, r12, r11, r8
	PKHTB	r8, r8, r10, ASR #16
#else
	SUB	r11, r6, r8
	ADD	r12, r6, r8
	BFC	r8, #0, #16
	BFC	r6, #0, #16
	SUB	r10, r6, r8
	ADD	r6, r6, r8
	BFI	r10, r11, #0, #16
	BFI	r6, r12, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r12, r10, #16
	MUL	r8, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r8, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r8, r12, r11, r8
	BFI	r8, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r7, r9
	SADD16	r7, r7, r9
	SMULTT	r9, lr, r10
	SMULTB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r9
	SMLABB	r9, r12, r11, r9
	PKHTB	r9, r9, r10, ASR #16
#else
	SUB	r11, r7, r9
	ADD	r12, r7, r9
	BFC	r9, #0, #16
	BFC	r7, #0, #16
	SUB	r10, r7, r9
	ADD	r7, r7, r9
	BFI	r10, r11, #0, #16
	BFI	r7, r12, #0, #16
	SBFX	r11, lr, #16, #16
	ASR	r12, r10, #16
	MUL	r9, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r9, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r9, r12, r11, r9
	BFI	r9, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	MOV	lr, #0xafc0
	MOVT	lr, #0x13
#else
	MOV	lr, #0x4ebf
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULWB	r10, lr, r2
	SMULWT	r11, lr, r2
	SMULBT	r10, r12, r10
	SMULBT	r11, r12, r11
	PKHBT	r10, r10, r11, LSL #16
	SSUB16	r2, r2, r10
#else
	SBFX	r10, r2, #0, #16
	SBFX	r11, r2, #16, #16
	MUL	r10, lr, r10
	MUL	r11, lr, r11
	ASR	r10, r10, #26
	ASR	r11, r11, #26
	MUL	r10, r12, r10
	MUL	r11, r12, r11
	SUB	r11, r2, r11, LSL #16
	SUB	r2, r2, r10
	LSR	r11, r11, #16
	BFI	r2, r11, #16, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULWB	r10, lr, r3
	SMULWT	r11, lr, r3
	SMULBT	r10, r12, r10
	SMULBT	r11, r12, r11
	PKHBT	r10, r10, r11, LSL #16
	SSUB16	r3, r3, r10
#else
	SBFX	r10, r3, #0, #16
	SBFX	r11, r3, #16, #16
	MUL	r10, lr, r10
	MUL	r11, lr, r11
	ASR	r10, r10, #26
	ASR	r11, r11, #26
	MUL	r10, r12, r10
	MUL	r11, r12, r11
	SUB	r11, r3, r11, LSL #16
	SUB	r3, r3, r10
	LSR	r11, r11, #16
	BFI	r3, r11, #16, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULWB	r10, lr, r4
	SMULWT	r11, lr, r4
	SMULBT	r10, r12, r10
	SMULBT	r11, r12, r11
	PKHBT	r10, r10, r11, LSL #16
	SSUB16	r4, r4, r10
#else
	SBFX	r10, r4, #0, #16
	SBFX	r11, r4, #16, #16
	MUL	r10, lr, r10
	MUL	r11, lr, r11
	ASR	r10, r10, #26
	ASR	r11, r11, #26
	MUL	r10, r12, r10
	MUL	r11, r12, r11
	SUB	r11, r4, r11, LSL #16
	SUB	r4, r4, r10
	LSR	r11, r11, #16
	BFI	r4, r11, #16, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULWB	r10, lr, r5
	SMULWT	r11, lr, r5
	SMULBT	r10, r12, r10
	SMULBT	r11, r12, r11
	PKHBT	r10, r10, r11, LSL #16
	SSUB16	r5, r5, r10
#else
	SBFX	r10, r5, #0, #16
	SBFX	r11, r5, #16, #16
	MUL	r10, lr, r10
	MUL	r11, lr, r11
	ASR	r10, r10, #26
	ASR	r11, r11, #26
	MUL	r10, r12, r10
	MUL	r11, r12, r11
	SUB	r11, r5, r11, LSL #16
	SUB	r5, r5, r10
	LSR	r11, r11, #16
	BFI	r5, r11, #16, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	LDR	lr, [r1, #252]
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r2, r6
	SADD16	r2, r2, r6
	SMULBT	r6, lr, r10
	SMULBB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r6
	SMLABB	r6, r12, r11, r6
	PKHTB	r6, r6, r10, ASR #16
#else
	SUB	r11, r2, r6
	ADD	r12, r2, r6
	BFC	r6, #0, #16
	BFC	r2, #0, #16
	SUB	r10, r2, r6
	ADD	r2, r2, r6
	BFI	r10, r11, #0, #16
	BFI	r2, r12, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r12, r10, #16
	MUL	r6, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r6, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r6, r12, r11, r6
	BFI	r6, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r3, r7
	SADD16	r3, r3, r7
	SMULBT	r7, lr, r10
	SMULBB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r7
	SMLABB	r7, r12, r11, r7
	PKHTB	r7, r7, r10, ASR #16
#else
	SUB	r11, r3, r7
	ADD	r12, r3, r7
	BFC	r7, #0, #16
	BFC	r3, #0, #16
	SUB	r10, r3, r7
	ADD	r3, r3, r7
	BFI	r10, r11, #0, #16
	BFI	r3, r12, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r12, r10, #16
	MUL	r7, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r7, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r7, r12, r11, r7
	BFI	r7, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r4, r8
	SADD16	r4, r4, r8
	SMULBT	r8, lr, r10
	SMULBB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r8
	SMLABB	r8, r12, r11, r8
	PKHTB	r8, r8, r10, ASR #16
#else
	SUB	r11, r4, r8
	ADD	r12, r4, r8
	BFC	r8, #0, #16
	BFC	r4, #0, #16
	SUB	r10, r4, r8
	ADD	r4, r4, r8
	BFI	r10, r11, #0, #16
	BFI	r4, r12, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r12, r10, #16
	MUL	r8, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r8, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r8, r12, r11, r8
	BFI	r8, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r10, r5, r9
	SADD16	r5, r5, r9
	SMULBT	r9, lr, r10
	SMULBB	r10, lr, r10
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r9
	SMLABB	r9, r12, r11, r9
	PKHTB	r9, r9, r10, ASR #16
#else
	SUB	r11, r5, r9
	ADD	r12, r5, r9
	BFC	r9, #0, #16
	BFC	r5, #0, #16
	SUB	r10, r5, r9
	ADD	r5, r5, r9
	BFI	r10, r11, #0, #16
	BFI	r5, r12, #0, #16
	SBFX	r11, lr, #0, #16
	ASR	r12, r10, #16
	MUL	r9, r11, r12
	SBFX	r10, r10, #0, #16
	MUL	r10, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r10, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r9, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r9, r12, r11, r9
	BFI	r9, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	LDR	lr, [r1, #254]
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r2
	SMULBT	r2, lr, r2
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r2
	SMLABB	r2, r12, r11, r2
	PKHTB	r2, r2, r10, ASR #16
#else
	SBFX	r11, lr, #0, #16
	SBFX	r10, r2, #0, #16
	MUL	r10, r11, r10
	SBFX	r2, r2, #16, #16
	MUL	r2, r11, r2
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r2, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r2, r12, r11, r2
	BFI	r2, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r3
	SMULBT	r3, lr, r3
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r3
	SMLABB	r3, r12, r11, r3
	PKHTB	r3, r3, r10, ASR #16
#else
	SBFX	r11, lr, #0, #16
	SBFX	r10, r3, #0, #16
	MUL	r10, r11, r10
	SBFX	r3, r3, #16, #16
	MUL	r3, r11, r3
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r3, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r3, r12, r11, r3
	BFI	r3, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r4
	SMULBT	r4, lr, r4
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r4
	SMLABB	r4, r12, r11, r4
	PKHTB	r4, r4, r10, ASR #16
#else
	SBFX	r11, lr, #0, #16
	SBFX	r10, r4, #0, #16
	MUL	r10, r11, r10
	SBFX	r4, r4, #16, #16
	MUL	r4, r11, r4
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r4, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r4, r12, r11, r4
	BFI	r4, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r5
	SMULBT	r5, lr, r5
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r5
	SMLABB	r5, r12, r11, r5
	PKHTB	r5, r5, r10, ASR #16
#else
	SBFX	r11, lr, #0, #16
	SBFX	r10, r5, #0, #16
	MUL	r10, r11, r10
	SBFX	r5, r5, #16, #16
	MUL	r5, r11, r5
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r5, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r5, r12, r11, r5
	BFI	r5, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r6
	SMULBT	r6, lr, r6
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r6
	SMLABB	r6, r12, r11, r6
	PKHTB	r6, r6, r10, ASR #16
#else
	SBFX	r11, lr, #0, #16
	SBFX	r10, r6, #0, #16
	MUL	r10, r11, r10
	SBFX	r6, r6, #16, #16
	MUL	r6, r11, r6
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r6, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r6, r12, r11, r6
	BFI	r6, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r7
	SMULBT	r7, lr, r7
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r7
	SMLABB	r7, r12, r11, r7
	PKHTB	r7, r7, r10, ASR #16
#else
	SBFX	r11, lr, #0, #16
	SBFX	r10, r7, #0, #16
	MUL	r10, r11, r10
	SBFX	r7, r7, #16, #16
	MUL	r7, r11, r7
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r7, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r7, r12, r11, r7
	BFI	r7, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r8
	SMULBT	r8, lr, r8
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r8
	SMLABB	r8, r12, r11, r8
	PKHTB	r8, r8, r10, ASR #16
#else
	SBFX	r11, lr, #0, #16
	SBFX	r10, r8, #0, #16
	MUL	r10, r11, r10
	SBFX	r8, r8, #16, #16
	MUL	r8, r11, r8
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r8, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r8, r12, r11, r8
	BFI	r8, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULBB	r10, lr, r9
	SMULBT	r9, lr, r9
	SMULTB	r11, r12, r10
	SMLABB	r10, r12, r11, r10
	SMULTB	r11, r12, r9
	SMLABB	r9, r12, r11, r9
	PKHTB	r9, r9, r10, ASR #16
#else
	SBFX	r11, lr, #0, #16
	SBFX	r10, r9, #0, #16
	MUL	r10, r11, r10
	SBFX	r9, r9, #16, #16
	MUL	r9, r11, r9
	MOV	r12, #0xcff
	MUL	r11, r12, r10
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	MLA	r10, r12, r11, r10
	MOV	r12, #0xcff
	SBFX	r11, r9, #0, #16
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r11, r11, #0, #16
	LSR	r10, r10, #16
	MLA	r9, r12, r11, r9
	BFI	r9, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	STR	r2, [r0]
	STR	r3, [r0, #64]
	STR	r4, [r0, #128]
	STR	r5, [r0, #192]
	STR	r6, [r0, #256]
	STR	r7, [r0, #320]
	STR	r8, [r0, #384]
	STR	r9, [r0, #448]
	LDR	r2, [sp]
	SUBS	r2, r2, #0x1
	ADD	r0, r0, #0x4
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_kyber_thumb2_invntt_loop_321
#else
	BNE.N	L_kyber_thumb2_invntt_loop_321
#endif
	ADD	sp, sp, #0x8
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 1629 */
	.size	kyber_thumb2_invntt,.-kyber_thumb2_invntt
	.text
	.type	L_kyber_thumb2_basemul_mont_zetas, %object
	.size	L_kyber_thumb2_basemul_mont_zetas, 256
	.align	4
L_kyber_thumb2_basemul_mont_zetas:
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
	.globl	kyber_thumb2_basemul_mont
	.type	kyber_thumb2_basemul_mont, %function
kyber_thumb2_basemul_mont:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	ADR	r3, L_kyber_thumb2_basemul_mont_zetas
	ADD	r3, r3, #0x80
#ifndef WOLFSSL_ARM_ARCH_7M
	MOV	r12, #0xd01
	MOVT	r12, #0xcff
#endif /* !WOLFSSL_ARM_ARCH_7M */
	MOV	r8, #0x0
L_kyber_thumb2_basemul_mont_loop:
	LDM	r1!, {r4, r5}
	LDM	r2!, {r6, r7}
	LDR	lr, [r3, r8]
	ADD	r8, r8, #0x2
	PUSH	{r8}
	CMP	r8, #0x80
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULTT	r8, r4, r6
	SMULTT	r10, r5, r7
	SMULTB	r9, r12, r8
	SMULTB	r11, r12, r10
	SMLABB	r8, r12, r9, r8
	SMLABB	r10, r12, r11, r10
	RSB	r11, lr, #0x0
	SMULBT	r8, lr, r8
	SMULBT	r10, r11, r10
	SMLABB	r8, r4, r6, r8
	SMLABB	r10, r5, r7, r10
	SMULTB	r9, r12, r8
	SMULTB	r11, r12, r10
	SMLABB	r8, r12, r9, r8
	SMLABB	r10, r12, r11, r10
	SMULBT	r9, r4, r6
	SMULBT	r11, r5, r7
	SMLATB	r9, r4, r6, r9
	SMLATB	r11, r5, r7, r11
	SMULTB	r6, r12, r9
	SMULTB	r7, r12, r11
	SMLABB	r9, r12, r6, r9
	SMLABB	r11, r12, r7, r11
	PKHTB	r4, r9, r8, ASR #16
	PKHTB	r5, r11, r10, ASR #16
#else
	ASR	r8, r4, #16
	ASR	r10, r5, #16
	ASR	r9, r6, #16
	ASR	r11, r7, #16
	MUL	r8, r8, r9
	MUL	r10, r10, r11
	MOV	r12, #0xcff
	SBFX	r9, r8, #0, #16
	SBFX	r11, r10, #0, #16
	MUL	r9, r12, r8
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r9, r9, #0, #16
	SBFX	r11, r11, #0, #16
	MLA	r8, r12, r9, r8
	MLA	r10, r12, r11, r10
	RSB	r11, lr, #0x0
	SBFX	r9, lr, #0, #16
	SBFX	r11, r11, #0, #16
	ASR	r8, r8, #16
	ASR	r10, r10, #16
	MUL	r8, r9, r8
	MUL	r10, r11, r10
	SBFX	r9, r4, #0, #16
	SBFX	r11, r5, #0, #16
	SBFX	r12, r6, #0, #16
	MLA	r8, r9, r12, r8
	SBFX	r12, r7, #0, #16
	MLA	r10, r11, r12, r10
	MOV	r12, #0xcff
	SBFX	r9, r8, #0, #16
	SBFX	r11, r10, #0, #16
	MUL	r9, r12, r9
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r9, r9, #0, #16
	SBFX	r11, r11, #0, #16
	MLA	r8, r12, r9, r8
	MLA	r10, r12, r11, r10
	SBFX	r9, r4, #0, #16
	SBFX	r11, r5, #0, #16
	ASR	r12, r6, #16
	MUL	r9, r9, r12
	ASR	r12, r7, #16
	MUL	r11, r11, r12
	ASR	r4, r4, #16
	ASR	r5, r5, #16
	SBFX	r12, r6, #0, #16
	MLA	r9, r4, r12, r9
	SBFX	r12, r7, #0, #16
	MLA	r11, r5, r12, r11
	MOV	r12, #0xcff
	SBFX	r6, r9, #0, #16
	SBFX	r7, r11, #0, #16
	MUL	r6, r12, r6
	MUL	r7, r12, r7
	MOV	r12, #0xd01
	SBFX	r4, r6, #0, #16
	SBFX	r5, r7, #0, #16
	MLA	r9, r12, r4, r9
	MLA	r11, r12, r5, r11
	BFC	r9, #0, #16
	BFC	r11, #0, #16
	ORR	r4, r9, r8, LSR #16
	ORR	r5, r11, r10, LSR #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	STM	r0!, {r4, r5}
	POP	{r8}
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_kyber_thumb2_basemul_mont_loop
#else
	BNE.N	L_kyber_thumb2_basemul_mont_loop
#endif
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 146 */
	.size	kyber_thumb2_basemul_mont,.-kyber_thumb2_basemul_mont
	.text
	.align	4
	.globl	kyber_thumb2_basemul_mont_add
	.type	kyber_thumb2_basemul_mont_add, %function
kyber_thumb2_basemul_mont_add:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	ADR	r3, L_kyber_thumb2_basemul_mont_zetas
	ADD	r3, r3, #0x80
#ifndef WOLFSSL_ARM_ARCH_7M
	MOV	r12, #0xd01
	MOVT	r12, #0xcff
#endif /* !WOLFSSL_ARM_ARCH_7M */
	MOV	r8, #0x0
L_kyber_thumb2_basemul_mont_add_loop:
	LDM	r1!, {r4, r5}
	LDM	r2!, {r6, r7}
	LDR	lr, [r3, r8]
	ADD	r8, r8, #0x2
	PUSH	{r8}
	CMP	r8, #0x80
#ifndef WOLFSSL_ARM_ARCH_7M
	SMULTT	r8, r4, r6
	SMULTT	r10, r5, r7
	SMULTB	r9, r12, r8
	SMULTB	r11, r12, r10
	SMLABB	r8, r12, r9, r8
	SMLABB	r10, r12, r11, r10
	RSB	r11, lr, #0x0
	SMULBT	r8, lr, r8
	SMULBT	r10, r11, r10
	SMLABB	r8, r4, r6, r8
	SMLABB	r10, r5, r7, r10
	SMULTB	r9, r12, r8
	SMULTB	r11, r12, r10
	SMLABB	r8, r12, r9, r8
	SMLABB	r10, r12, r11, r10
	SMULBT	r9, r4, r6
	SMULBT	r11, r5, r7
	SMLATB	r9, r4, r6, r9
	SMLATB	r11, r5, r7, r11
	SMULTB	r6, r12, r9
	SMULTB	r7, r12, r11
	SMLABB	r9, r12, r6, r9
	SMLABB	r11, r12, r7, r11
	LDM	r0, {r4, r5}
	PKHTB	r9, r9, r8, ASR #16
	PKHTB	r11, r11, r10, ASR #16
	SADD16	r4, r4, r9
	SADD16	r5, r5, r11
#else
	ASR	r8, r4, #16
	ASR	r10, r5, #16
	ASR	r9, r6, #16
	ASR	r11, r7, #16
	MUL	r8, r8, r9
	MUL	r10, r10, r11
	MOV	r12, #0xcff
	SBFX	r9, r8, #0, #16
	SBFX	r11, r10, #0, #16
	MUL	r9, r12, r8
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r9, r9, #0, #16
	SBFX	r11, r11, #0, #16
	MLA	r8, r12, r9, r8
	MLA	r10, r12, r11, r10
	RSB	r11, lr, #0x0
	SBFX	r9, lr, #0, #16
	SBFX	r11, r11, #0, #16
	ASR	r8, r8, #16
	ASR	r10, r10, #16
	MUL	r8, r9, r8
	MUL	r10, r11, r10
	SBFX	r9, r4, #0, #16
	SBFX	r11, r5, #0, #16
	SBFX	r12, r6, #0, #16
	MLA	r8, r9, r12, r8
	SBFX	r12, r7, #0, #16
	MLA	r10, r11, r12, r10
	MOV	r12, #0xcff
	SBFX	r9, r8, #0, #16
	SBFX	r11, r10, #0, #16
	MUL	r9, r12, r9
	MUL	r11, r12, r11
	MOV	r12, #0xd01
	SBFX	r9, r9, #0, #16
	SBFX	r11, r11, #0, #16
	MLA	r8, r12, r9, r8
	MLA	r10, r12, r11, r10
	SBFX	r9, r4, #0, #16
	SBFX	r11, r5, #0, #16
	ASR	r12, r6, #16
	MUL	r9, r9, r12
	ASR	r12, r7, #16
	MUL	r11, r11, r12
	ASR	r4, r4, #16
	ASR	r5, r5, #16
	SBFX	r12, r6, #0, #16
	MLA	r9, r4, r12, r9
	SBFX	r12, r7, #0, #16
	MLA	r11, r5, r12, r11
	MOV	r12, #0xcff
	SBFX	r6, r9, #0, #16
	SBFX	r7, r11, #0, #16
	MUL	r6, r12, r6
	MUL	r7, r12, r7
	MOV	r12, #0xd01
	SBFX	r4, r6, #0, #16
	SBFX	r5, r7, #0, #16
	MLA	r9, r12, r4, r9
	MLA	r11, r12, r5, r11
	LDM	r0, {r4, r5}
	BFC	r9, #0, #16
	BFC	r11, #0, #16
	ORR	r9, r9, r8, LSR #16
	ORR	r11, r11, r10, LSR #16
	ADD	r8, r4, r9
	ADD	r10, r5, r11
	BFC	r9, #0, #16
	BFC	r11, #0, #16
	ADD	r4, r4, r9
	ADD	r5, r5, r11
	BFI	r4, r8, #0, #16
	BFI	r5, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	STM	r0!, {r4, r5}
	POP	{r8}
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_kyber_thumb2_basemul_mont_add_loop
#else
	BNE.N	L_kyber_thumb2_basemul_mont_add_loop
#endif
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 162 */
	.size	kyber_thumb2_basemul_mont_add,.-kyber_thumb2_basemul_mont_add
	.text
	.align	4
	.globl	kyber_thumb2_csubq
	.type	kyber_thumb2_csubq, %function
kyber_thumb2_csubq:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	MOV	r11, #0xd01
	MOV	r12, #0xd01
#ifndef WOLFSSL_ARM_ARCH_7M
	MOVT	r12, #0xd01
#endif /* !WOLFSSL_ARM_ARCH_7M */
	MOV	lr, #0x8000
	MOVT	lr, #0x8000
	MOV	r1, #0x100
L_kyber_thumb2_csubq_loop:
	LDM	r0, {r2, r3, r4, r5}
#ifndef WOLFSSL_ARM_ARCH_7M
	SSUB16	r2, r2, r12
	SSUB16	r3, r3, r12
	SSUB16	r4, r4, r12
	SSUB16	r5, r5, r12
	AND	r6, r2, lr
	AND	r7, r3, lr
	AND	r8, r4, lr
	AND	r9, r5, lr
	LSR	r6, r6, #15
	LSR	r7, r7, #15
	LSR	r8, r8, #15
	LSR	r9, r9, #15
	MUL	r6, r6, r11
	MUL	r7, r7, r11
	MUL	r8, r8, r11
	MUL	r9, r9, r11
	SADD16	r2, r2, r6
	SADD16	r3, r3, r7
	SADD16	r4, r4, r8
	SADD16	r5, r5, r9
#else
	SUB	r6, r2, r12
	SUB	r2, r2, r12, LSL #16
	BFI	r2, r6, #0, #16
	SUB	r7, r3, r12
	SUB	r3, r3, r12, LSL #16
	BFI	r3, r7, #0, #16
	SUB	r8, r4, r12
	SUB	r4, r4, r12, LSL #16
	BFI	r4, r8, #0, #16
	SUB	r9, r5, r12
	SUB	r5, r5, r12, LSL #16
	BFI	r5, r9, #0, #16
	AND	r6, r2, lr
	AND	r7, r3, lr
	AND	r8, r4, lr
	AND	r9, r5, lr
	LSR	r6, r6, #15
	LSR	r7, r7, #15
	LSR	r8, r8, #15
	LSR	r9, r9, #15
	MUL	r6, r6, r11
	MUL	r7, r7, r11
	MUL	r8, r8, r11
	MUL	r9, r9, r11
	ADD	r10, r2, r6
	BFC	r6, #0, #16
	ADD	r2, r2, r6
	BFI	r2, r10, #0, #16
	ADD	r10, r3, r7
	BFC	r7, #0, #16
	ADD	r3, r3, r7
	BFI	r3, r10, #0, #16
	ADD	r10, r4, r8
	BFC	r8, #0, #16
	ADD	r4, r4, r8
	BFI	r4, r10, #0, #16
	ADD	r10, r5, r9
	BFC	r9, #0, #16
	ADD	r5, r5, r9
	BFI	r5, r10, #0, #16
#endif /* !WOLFSSL_ARM_ARCH_7M */
	STM	r0!, {r2, r3, r4, r5}
	SUBS	r1, r1, #0x8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_kyber_thumb2_csubq_loop
#else
	BNE.N	L_kyber_thumb2_csubq_loop
#endif
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 101 */
	.size	kyber_thumb2_csubq,.-kyber_thumb2_csubq
	.text
	.align	4
	.globl	kyber_thumb2_rej_uniform
	.type	kyber_thumb2_rej_uniform, %function
kyber_thumb2_rej_uniform:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, lr}
	MOV	r8, #0xd01
	MOV	r9, #0x0
L_kyber_thumb2_rej_uniform_loop_no_fail:
	CMP	r1, #0x8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BLT	L_kyber_thumb2_rej_uniform_done_no_fail
#else
	BLT.N	L_kyber_thumb2_rej_uniform_done_no_fail
#endif
	LDM	r2!, {r4, r5, r6}
	UBFX	r7, r4, #0, #12
	STRH	r7, [r0, r9]
	SUB	r10, r7, r8
	LSR	r10, r10, #31
	SUB	r1, r1, r10
	ADD	r9, r9, r10, LSL #1
	UBFX	r7, r4, #12, #12
	STRH	r7, [r0, r9]
	SUB	r10, r7, r8
	LSR	r10, r10, #31
	SUB	r1, r1, r10
	ADD	r9, r9, r10, LSL #1
	UBFX	r7, r4, #24, #8
	BFI	r7, r5, #8, #4
	STRH	r7, [r0, r9]
	SUB	r10, r7, r8
	LSR	r10, r10, #31
	SUB	r1, r1, r10
	ADD	r9, r9, r10, LSL #1
	UBFX	r7, r5, #4, #12
	STRH	r7, [r0, r9]
	SUB	r10, r7, r8
	LSR	r10, r10, #31
	SUB	r1, r1, r10
	ADD	r9, r9, r10, LSL #1
	UBFX	r7, r5, #16, #12
	STRH	r7, [r0, r9]
	SUB	r10, r7, r8
	LSR	r10, r10, #31
	SUB	r1, r1, r10
	ADD	r9, r9, r10, LSL #1
	UBFX	r7, r5, #28, #4
	BFI	r7, r6, #4, #8
	STRH	r7, [r0, r9]
	SUB	r10, r7, r8
	LSR	r10, r10, #31
	SUB	r1, r1, r10
	ADD	r9, r9, r10, LSL #1
	UBFX	r7, r6, #8, #12
	STRH	r7, [r0, r9]
	SUB	r10, r7, r8
	LSR	r10, r10, #31
	SUB	r1, r1, r10
	ADD	r9, r9, r10, LSL #1
	UBFX	r7, r6, #20, #12
	STRH	r7, [r0, r9]
	SUB	r10, r7, r8
	LSR	r10, r10, #31
	SUB	r1, r1, r10
	ADD	r9, r9, r10, LSL #1
	SUBS	r3, r3, #0xc
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_kyber_thumb2_rej_uniform_loop_no_fail
#else
	BNE.N	L_kyber_thumb2_rej_uniform_loop_no_fail
#endif
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_kyber_thumb2_rej_uniform_done
#else
	B.N	L_kyber_thumb2_rej_uniform_done
#endif
L_kyber_thumb2_rej_uniform_done_no_fail:
	CMP	r1, #0x0
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_kyber_thumb2_rej_uniform_done
#else
	BEQ.N	L_kyber_thumb2_rej_uniform_done
#endif
L_kyber_thumb2_rej_uniform_loop:
	LDM	r2!, {r4, r5, r6}
	UBFX	r7, r4, #0, #12
	CMP	r7, r8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_kyber_thumb2_rej_uniform_fail_0
#else
	BGE.N	L_kyber_thumb2_rej_uniform_fail_0
#endif
	STRH	r7, [r0, r9]
	SUBS	r1, r1, #0x1
	ADD	r9, r9, #0x2
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_kyber_thumb2_rej_uniform_done
#else
	BEQ.N	L_kyber_thumb2_rej_uniform_done
#endif
L_kyber_thumb2_rej_uniform_fail_0:
	UBFX	r7, r4, #12, #12
	CMP	r7, r8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_kyber_thumb2_rej_uniform_fail_1
#else
	BGE.N	L_kyber_thumb2_rej_uniform_fail_1
#endif
	STRH	r7, [r0, r9]
	SUBS	r1, r1, #0x1
	ADD	r9, r9, #0x2
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_kyber_thumb2_rej_uniform_done
#else
	BEQ.N	L_kyber_thumb2_rej_uniform_done
#endif
L_kyber_thumb2_rej_uniform_fail_1:
	UBFX	r7, r4, #24, #8
	BFI	r7, r5, #8, #4
	CMP	r7, r8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_kyber_thumb2_rej_uniform_fail_2
#else
	BGE.N	L_kyber_thumb2_rej_uniform_fail_2
#endif
	STRH	r7, [r0, r9]
	SUBS	r1, r1, #0x1
	ADD	r9, r9, #0x2
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_kyber_thumb2_rej_uniform_done
#else
	BEQ.N	L_kyber_thumb2_rej_uniform_done
#endif
L_kyber_thumb2_rej_uniform_fail_2:
	UBFX	r7, r5, #4, #12
	CMP	r7, r8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_kyber_thumb2_rej_uniform_fail_3
#else
	BGE.N	L_kyber_thumb2_rej_uniform_fail_3
#endif
	STRH	r7, [r0, r9]
	SUBS	r1, r1, #0x1
	ADD	r9, r9, #0x2
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_kyber_thumb2_rej_uniform_done
#else
	BEQ.N	L_kyber_thumb2_rej_uniform_done
#endif
L_kyber_thumb2_rej_uniform_fail_3:
	UBFX	r7, r5, #16, #12
	CMP	r7, r8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_kyber_thumb2_rej_uniform_fail_4
#else
	BGE.N	L_kyber_thumb2_rej_uniform_fail_4
#endif
	STRH	r7, [r0, r9]
	SUBS	r1, r1, #0x1
	ADD	r9, r9, #0x2
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_kyber_thumb2_rej_uniform_done
#else
	BEQ.N	L_kyber_thumb2_rej_uniform_done
#endif
L_kyber_thumb2_rej_uniform_fail_4:
	UBFX	r7, r5, #28, #4
	BFI	r7, r6, #4, #8
	CMP	r7, r8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_kyber_thumb2_rej_uniform_fail_5
#else
	BGE.N	L_kyber_thumb2_rej_uniform_fail_5
#endif
	STRH	r7, [r0, r9]
	SUBS	r1, r1, #0x1
	ADD	r9, r9, #0x2
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_kyber_thumb2_rej_uniform_done
#else
	BEQ.N	L_kyber_thumb2_rej_uniform_done
#endif
L_kyber_thumb2_rej_uniform_fail_5:
	UBFX	r7, r6, #8, #12
	CMP	r7, r8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_kyber_thumb2_rej_uniform_fail_6
#else
	BGE.N	L_kyber_thumb2_rej_uniform_fail_6
#endif
	STRH	r7, [r0, r9]
	SUBS	r1, r1, #0x1
	ADD	r9, r9, #0x2
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_kyber_thumb2_rej_uniform_done
#else
	BEQ.N	L_kyber_thumb2_rej_uniform_done
#endif
L_kyber_thumb2_rej_uniform_fail_6:
	UBFX	r7, r6, #20, #12
	CMP	r7, r8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_kyber_thumb2_rej_uniform_fail_7
#else
	BGE.N	L_kyber_thumb2_rej_uniform_fail_7
#endif
	STRH	r7, [r0, r9]
	SUBS	r1, r1, #0x1
	ADD	r9, r9, #0x2
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_kyber_thumb2_rej_uniform_done
#else
	BEQ.N	L_kyber_thumb2_rej_uniform_done
#endif
L_kyber_thumb2_rej_uniform_fail_7:
	SUBS	r3, r3, #0xc
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGT	L_kyber_thumb2_rej_uniform_loop
#else
	BGT.N	L_kyber_thumb2_rej_uniform_loop
#endif
L_kyber_thumb2_rej_uniform_done:
	LSR	r0, r9, #1
	POP	{r4, r5, r6, r7, r8, r9, r10, pc}
	/* Cycle Count = 225 */
	.size	kyber_thumb2_rej_uniform,.-kyber_thumb2_rej_uniform
#endif /* WOLFSSL_WC_KYBER */
#endif /* WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section        .note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
