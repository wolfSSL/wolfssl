/* thumb2-mlkem-asm
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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
 *   ruby ./kyber/kyber.rb \
 *       thumb2 ../wolfssl/wolfcrypt/src/port/arm/thumb2-mlkem-asm.S
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

#ifdef WOLFSSL_ARMASM
#ifdef WOLFSSL_ARMASM_THUMB2
#ifndef WOLFSSL_ARMASM_INLINE
	.thumb
	.syntax unified
#ifdef WOLFSSL_HAVE_MLKEM
#ifndef __APPLE__
	.text
	.type	L_mlkem_thumb2_ntt_zetas, %object
	.size	L_mlkem_thumb2_ntt_zetas, 256
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	/* 4-byte aligned, 32-bit aligned */
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mlkem_thumb2_ntt_zetas:
	.short	0x08ed,0x0a0b,0x0b9a,0x0714,0x05d5,0x058e,0x011f,0x00ca
	.short	0x0c56,0x026e,0x0629,0x00b6,0x03c2,0x084f,0x073f,0x05bc
	.short	0x023d,0x07d4,0x0108,0x017f,0x09c4,0x05b2,0x06bf,0x0c7f
	.short	0x0a58,0x03f9,0x02dc,0x0260,0x06fb,0x019b,0x0c34,0x06de
	.short	0x04c7,0x028c,0x0ad9,0x03f7,0x07f4,0x05d3,0x0be7,0x06f9
	.short	0x0204,0x0cf9,0x0bc1,0x0a67,0x06af,0x0877,0x007e,0x05bd
	.short	0x09ac,0x0ca7,0x0bf2,0x033e,0x006b,0x0774,0x0c0a,0x094a
	.short	0x0b73,0x03c1,0x071d,0x0a2c,0x01c0,0x08d8,0x02a5,0x0806
	.short	0x08b2,0x01ae,0x022b,0x034b,0x081e,0x0367,0x060e,0x0069
	.short	0x01a6,0x024b,0x00b1,0x0c16,0x0bde,0x0b35,0x0626,0x0675
	.short	0x0c0b,0x030a,0x0487,0x0c6e,0x09f8,0x05cb,0x0aa7,0x045f
	.short	0x06cb,0x0284,0x0999,0x015d,0x01a2,0x0149,0x0c65,0x0cb6
	.short	0x0331,0x0449,0x025b,0x0262,0x052a,0x07fc,0x0748,0x0180
	.short	0x0842,0x0c79,0x04c2,0x07ca,0x0997,0x00dc,0x085e,0x0686
	.short	0x0860,0x0707,0x0803,0x031a,0x071b,0x09ab,0x099b,0x01de
	.short	0x0c95,0x0bcd,0x03e4,0x03df,0x03be,0x074d,0x05f2,0x065c
	.text
	.align	4
	.globl	mlkem_thumb2_ntt
	.type	mlkem_thumb2_ntt, %function
mlkem_thumb2_ntt:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0x8
	ADR	r1, L_mlkem_thumb2_ntt_zetas
#ifndef WOLFSSL_ARM_ARCH_7M
	MOV	r12, #0xd01
	MOVT	r12, #0xcff
#endif /* !WOLFSSL_ARM_ARCH_7M */
	MOV	r2, #0x10
L_mlkem_thumb2_ntt_loop_123:
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
	BNE	L_mlkem_thumb2_ntt_loop_123
#else
	BNE.N	L_mlkem_thumb2_ntt_loop_123
#endif
	SUB	r0, r0, #0x40
	MOV	r3, #0x0
L_mlkem_thumb2_ntt_loop_4_j:
	STR	r3, [sp, #4]
	ADD	lr, r1, r3, LSR #4
	MOV	r2, #0x4
	LDR	lr, [lr, #16]
L_mlkem_thumb2_ntt_loop_4_i:
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
	BNE	L_mlkem_thumb2_ntt_loop_4_i
#else
	BNE.N	L_mlkem_thumb2_ntt_loop_4_i
#endif
	ADD	r3, r3, #0x40
	RSBS	r10, r3, #0x100
	ADD	r0, r0, #0x70
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_mlkem_thumb2_ntt_loop_4_j
#else
	BNE.N	L_mlkem_thumb2_ntt_loop_4_j
#endif
	SUB	r0, r0, #0x200
	MOV	r3, #0x0
L_mlkem_thumb2_ntt_loop_567:
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
	BNE	L_mlkem_thumb2_ntt_loop_567
#else
	BNE.N	L_mlkem_thumb2_ntt_loop_567
#endif
	ADD	sp, sp, #0x8
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 1270 */
	.size	mlkem_thumb2_ntt,.-mlkem_thumb2_ntt
#ifndef __APPLE__
	.text
	.type	L_mlkem_invntt_zetas_inv, %object
	.size	L_mlkem_invntt_zetas_inv, 256
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	/* 4-byte aligned, 32-bit aligned */
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mlkem_invntt_zetas_inv:
	.short	0x06a5,0x070f,0x05b4,0x0943,0x0922,0x091d,0x0134,0x006c
	.short	0x0b23,0x0366,0x0356,0x05e6,0x09e7,0x04fe,0x05fa,0x04a1
	.short	0x067b,0x04a3,0x0c25,0x036a,0x0537,0x083f,0x0088,0x04bf
	.short	0x0b81,0x05b9,0x0505,0x07d7,0x0a9f,0x0aa6,0x08b8,0x09d0
	.short	0x004b,0x009c,0x0bb8,0x0b5f,0x0ba4,0x0368,0x0a7d,0x0636
	.short	0x08a2,0x025a,0x0736,0x0309,0x0093,0x087a,0x09f7,0x00f6
	.short	0x068c,0x06db,0x01cc,0x0123,0x00eb,0x0c50,0x0ab6,0x0b5b
	.short	0x0c98,0x06f3,0x099a,0x04e3,0x09b6,0x0ad6,0x0b53,0x044f
	.short	0x04fb,0x0a5c,0x0429,0x0b41,0x02d5,0x05e4,0x0940,0x018e
	.short	0x03b7,0x00f7,0x058d,0x0c96,0x09c3,0x010f,0x005a,0x0355
	.short	0x0744,0x0c83,0x048a,0x0652,0x029a,0x0140,0x0008,0x0afd
	.short	0x0608,0x011a,0x072e,0x050d,0x090a,0x0228,0x0a75,0x083a
	.short	0x0623,0x00cd,0x0b66,0x0606,0x0aa1,0x0a25,0x0908,0x02a9
	.short	0x0082,0x0642,0x074f,0x033d,0x0b82,0x0bf9,0x052d,0x0ac4
	.short	0x0745,0x05c2,0x04b2,0x093f,0x0c4b,0x06d8,0x0a93,0x00ab
	.short	0x0c37,0x0be2,0x0773,0x072c,0x05ed,0x0167,0x02f6,0x05a1
	.text
	.align	4
	.globl	mlkem_thumb2_invntt
	.type	mlkem_thumb2_invntt, %function
mlkem_thumb2_invntt:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0x8
	ADR	r1, L_mlkem_invntt_zetas_inv
#ifndef WOLFSSL_ARM_ARCH_7M
	MOV	r12, #0xd01
	MOVT	r12, #0xcff
#endif /* !WOLFSSL_ARM_ARCH_7M */
	MOV	r3, #0x0
L_mlkem_invntt_loop_765:
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
	BNE	L_mlkem_invntt_loop_765
#else
	BNE.N	L_mlkem_invntt_loop_765
#endif
	SUB	r0, r0, #0x200
	MOV	r3, #0x0
L_mlkem_invntt_loop_4_j:
	STR	r3, [sp, #4]
	ADD	lr, r1, r3, LSR #4
	MOV	r2, #0x4
	LDR	lr, [lr, #224]
L_mlkem_invntt_loop_4_i:
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
	BNE	L_mlkem_invntt_loop_4_i
#else
	BNE.N	L_mlkem_invntt_loop_4_i
#endif
	ADD	r3, r3, #0x40
	RSBS	r10, r3, #0x100
	ADD	r0, r0, #0x70
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_mlkem_invntt_loop_4_j
#else
	BNE.N	L_mlkem_invntt_loop_4_j
#endif
	SUB	r0, r0, #0x200
	MOV	r2, #0x10
L_mlkem_invntt_loop_321:
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
	BNE	L_mlkem_invntt_loop_321
#else
	BNE.N	L_mlkem_invntt_loop_321
#endif
	ADD	sp, sp, #0x8
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 1629 */
	.size	mlkem_thumb2_invntt,.-mlkem_thumb2_invntt
#ifndef __APPLE__
	.text
	.type	L_mlkem_basemul_mont_zetas, %object
	.size	L_mlkem_basemul_mont_zetas, 256
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	/* 4-byte aligned, 32-bit aligned */
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_mlkem_basemul_mont_zetas:
	.short	0x08ed,0x0a0b,0x0b9a,0x0714,0x05d5,0x058e,0x011f,0x00ca
	.short	0x0c56,0x026e,0x0629,0x00b6,0x03c2,0x084f,0x073f,0x05bc
	.short	0x023d,0x07d4,0x0108,0x017f,0x09c4,0x05b2,0x06bf,0x0c7f
	.short	0x0a58,0x03f9,0x02dc,0x0260,0x06fb,0x019b,0x0c34,0x06de
	.short	0x04c7,0x028c,0x0ad9,0x03f7,0x07f4,0x05d3,0x0be7,0x06f9
	.short	0x0204,0x0cf9,0x0bc1,0x0a67,0x06af,0x0877,0x007e,0x05bd
	.short	0x09ac,0x0ca7,0x0bf2,0x033e,0x006b,0x0774,0x0c0a,0x094a
	.short	0x0b73,0x03c1,0x071d,0x0a2c,0x01c0,0x08d8,0x02a5,0x0806
	.short	0x08b2,0x01ae,0x022b,0x034b,0x081e,0x0367,0x060e,0x0069
	.short	0x01a6,0x024b,0x00b1,0x0c16,0x0bde,0x0b35,0x0626,0x0675
	.short	0x0c0b,0x030a,0x0487,0x0c6e,0x09f8,0x05cb,0x0aa7,0x045f
	.short	0x06cb,0x0284,0x0999,0x015d,0x01a2,0x0149,0x0c65,0x0cb6
	.short	0x0331,0x0449,0x025b,0x0262,0x052a,0x07fc,0x0748,0x0180
	.short	0x0842,0x0c79,0x04c2,0x07ca,0x0997,0x00dc,0x085e,0x0686
	.short	0x0860,0x0707,0x0803,0x031a,0x071b,0x09ab,0x099b,0x01de
	.short	0x0c95,0x0bcd,0x03e4,0x03df,0x03be,0x074d,0x05f2,0x065c
	.text
	.align	4
	.globl	mlkem_thumb2_basemul_mont
	.type	mlkem_thumb2_basemul_mont, %function
mlkem_thumb2_basemul_mont:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	ADR	r3, L_mlkem_basemul_mont_zetas
	ADD	r3, r3, #0x80
#ifndef WOLFSSL_ARM_ARCH_7M
	MOV	r12, #0xd01
	MOVT	r12, #0xcff
#endif /* !WOLFSSL_ARM_ARCH_7M */
	MOV	r8, #0x0
L_mlkem_basemul_mont_loop:
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
	BNE	L_mlkem_basemul_mont_loop
#else
	BNE.N	L_mlkem_basemul_mont_loop
#endif
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 146 */
	.size	mlkem_thumb2_basemul_mont,.-mlkem_thumb2_basemul_mont
	.text
	.align	4
	.globl	mlkem_thumb2_basemul_mont_add
	.type	mlkem_thumb2_basemul_mont_add, %function
mlkem_thumb2_basemul_mont_add:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	ADR	r3, L_mlkem_basemul_mont_zetas
	ADD	r3, r3, #0x80
#ifndef WOLFSSL_ARM_ARCH_7M
	MOV	r12, #0xd01
	MOVT	r12, #0xcff
#endif /* !WOLFSSL_ARM_ARCH_7M */
	MOV	r8, #0x0
L_mlkem_thumb2_basemul_mont_add_loop:
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
	BNE	L_mlkem_thumb2_basemul_mont_add_loop
#else
	BNE.N	L_mlkem_thumb2_basemul_mont_add_loop
#endif
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 162 */
	.size	mlkem_thumb2_basemul_mont_add,.-mlkem_thumb2_basemul_mont_add
	.text
	.align	4
	.globl	mlkem_thumb2_csubq
	.type	mlkem_thumb2_csubq, %function
mlkem_thumb2_csubq:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	MOV	r11, #0xd01
	MOV	r12, #0xd01
#ifndef WOLFSSL_ARM_ARCH_7M
	MOVT	r12, #0xd01
#endif /* !WOLFSSL_ARM_ARCH_7M */
	MOV	lr, #0x8000
	MOVT	lr, #0x8000
	MOV	r1, #0x100
L_mlkem_thumb2_csubq_loop:
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
	BNE	L_mlkem_thumb2_csubq_loop
#else
	BNE.N	L_mlkem_thumb2_csubq_loop
#endif
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 101 */
	.size	mlkem_thumb2_csubq,.-mlkem_thumb2_csubq
	.text
	.align	4
	.globl	mlkem_thumb2_rej_uniform
	.type	mlkem_thumb2_rej_uniform, %function
mlkem_thumb2_rej_uniform:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, lr}
	MOV	r8, #0xd01
	MOV	r9, #0x0
L_mlkem_thumb2_rej_uniform_loop_no_fail:
	CMP	r1, #0x8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BLT	L_mlkem_thumb2_rej_uniform_done_no_fail
#else
	BLT.N	L_mlkem_thumb2_rej_uniform_done_no_fail
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
	BNE	L_mlkem_thumb2_rej_uniform_loop_no_fail
#else
	BNE.N	L_mlkem_thumb2_rej_uniform_loop_no_fail
#endif
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	B	L_mlkem_thumb2_rej_uniform_done
#else
	B.N	L_mlkem_thumb2_rej_uniform_done
#endif
L_mlkem_thumb2_rej_uniform_done_no_fail:
	CMP	r1, #0x0
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_mlkem_thumb2_rej_uniform_done
#else
	BEQ.N	L_mlkem_thumb2_rej_uniform_done
#endif
L_mlkem_thumb2_rej_uniform_loop:
	LDM	r2!, {r4, r5, r6}
	UBFX	r7, r4, #0, #12
	CMP	r7, r8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_mlkem_thumb2_rej_uniform_fail_0
#else
	BGE.N	L_mlkem_thumb2_rej_uniform_fail_0
#endif
	STRH	r7, [r0, r9]
	SUBS	r1, r1, #0x1
	ADD	r9, r9, #0x2
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_mlkem_thumb2_rej_uniform_done
#else
	BEQ.N	L_mlkem_thumb2_rej_uniform_done
#endif
L_mlkem_thumb2_rej_uniform_fail_0:
	UBFX	r7, r4, #12, #12
	CMP	r7, r8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_mlkem_thumb2_rej_uniform_fail_1
#else
	BGE.N	L_mlkem_thumb2_rej_uniform_fail_1
#endif
	STRH	r7, [r0, r9]
	SUBS	r1, r1, #0x1
	ADD	r9, r9, #0x2
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_mlkem_thumb2_rej_uniform_done
#else
	BEQ.N	L_mlkem_thumb2_rej_uniform_done
#endif
L_mlkem_thumb2_rej_uniform_fail_1:
	UBFX	r7, r4, #24, #8
	BFI	r7, r5, #8, #4
	CMP	r7, r8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_mlkem_thumb2_rej_uniform_fail_2
#else
	BGE.N	L_mlkem_thumb2_rej_uniform_fail_2
#endif
	STRH	r7, [r0, r9]
	SUBS	r1, r1, #0x1
	ADD	r9, r9, #0x2
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_mlkem_thumb2_rej_uniform_done
#else
	BEQ.N	L_mlkem_thumb2_rej_uniform_done
#endif
L_mlkem_thumb2_rej_uniform_fail_2:
	UBFX	r7, r5, #4, #12
	CMP	r7, r8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_mlkem_thumb2_rej_uniform_fail_3
#else
	BGE.N	L_mlkem_thumb2_rej_uniform_fail_3
#endif
	STRH	r7, [r0, r9]
	SUBS	r1, r1, #0x1
	ADD	r9, r9, #0x2
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_mlkem_thumb2_rej_uniform_done
#else
	BEQ.N	L_mlkem_thumb2_rej_uniform_done
#endif
L_mlkem_thumb2_rej_uniform_fail_3:
	UBFX	r7, r5, #16, #12
	CMP	r7, r8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_mlkem_thumb2_rej_uniform_fail_4
#else
	BGE.N	L_mlkem_thumb2_rej_uniform_fail_4
#endif
	STRH	r7, [r0, r9]
	SUBS	r1, r1, #0x1
	ADD	r9, r9, #0x2
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_mlkem_thumb2_rej_uniform_done
#else
	BEQ.N	L_mlkem_thumb2_rej_uniform_done
#endif
L_mlkem_thumb2_rej_uniform_fail_4:
	UBFX	r7, r5, #28, #4
	BFI	r7, r6, #4, #8
	CMP	r7, r8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_mlkem_thumb2_rej_uniform_fail_5
#else
	BGE.N	L_mlkem_thumb2_rej_uniform_fail_5
#endif
	STRH	r7, [r0, r9]
	SUBS	r1, r1, #0x1
	ADD	r9, r9, #0x2
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_mlkem_thumb2_rej_uniform_done
#else
	BEQ.N	L_mlkem_thumb2_rej_uniform_done
#endif
L_mlkem_thumb2_rej_uniform_fail_5:
	UBFX	r7, r6, #8, #12
	CMP	r7, r8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_mlkem_thumb2_rej_uniform_fail_6
#else
	BGE.N	L_mlkem_thumb2_rej_uniform_fail_6
#endif
	STRH	r7, [r0, r9]
	SUBS	r1, r1, #0x1
	ADD	r9, r9, #0x2
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_mlkem_thumb2_rej_uniform_done
#else
	BEQ.N	L_mlkem_thumb2_rej_uniform_done
#endif
L_mlkem_thumb2_rej_uniform_fail_6:
	UBFX	r7, r6, #20, #12
	CMP	r7, r8
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_mlkem_thumb2_rej_uniform_fail_7
#else
	BGE.N	L_mlkem_thumb2_rej_uniform_fail_7
#endif
	STRH	r7, [r0, r9]
	SUBS	r1, r1, #0x1
	ADD	r9, r9, #0x2
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_mlkem_thumb2_rej_uniform_done
#else
	BEQ.N	L_mlkem_thumb2_rej_uniform_done
#endif
L_mlkem_thumb2_rej_uniform_fail_7:
	SUBS	r3, r3, #0xc
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGT	L_mlkem_thumb2_rej_uniform_loop
#else
	BGT.N	L_mlkem_thumb2_rej_uniform_loop
#endif
L_mlkem_thumb2_rej_uniform_done:
	LSR	r0, r9, #1
	POP	{r4, r5, r6, r7, r8, r9, r10, pc}
	/* Cycle Count = 225 */
	.size	mlkem_thumb2_rej_uniform,.-mlkem_thumb2_rej_uniform
#endif /* WOLFSSL_HAVE_MLKEM */
#endif /* WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
