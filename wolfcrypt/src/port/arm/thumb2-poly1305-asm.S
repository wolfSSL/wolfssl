/* thumb2-poly1305-asm
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
 *   ruby ./poly1305/poly1305.rb thumb2 ../wolfssl/wolfcrypt/src/port/arm/thumb2-poly1305-asm.S
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_ARMASM
#if !defined(__aarch64__) && defined(__thumb__)
#ifndef WOLFSSL_ARMASM_INLINE
	.thumb
	.syntax unified
#ifdef HAVE_POLY1305
	.text
	.align	4
	.globl	poly1305_blocks_thumb2_16
	.type	poly1305_blocks_thumb2_16, %function
poly1305_blocks_thumb2_16:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0x1c
	CMP	r2, #0x0
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BEQ	L_poly1305_thumb2_16_done
#else
	BEQ.N	L_poly1305_thumb2_16_done
#endif
	ADD	lr, sp, #0xc
	STM	lr, {r0, r1, r2, r3}
	/* Get h pointer */
	ADD	lr, r0, #0x10
	LDM	lr, {r4, r5, r6, r7, r8}
L_poly1305_thumb2_16_loop:
	/* Add m to h */
	LDR	r1, [sp, #16]
	LDR	r2, [r1]
	LDR	r3, [r1, #4]
	LDR	r9, [r1, #8]
	LDR	r10, [r1, #12]
	LDR	r11, [sp, #24]
	ADDS	r4, r4, r2
	ADCS	r5, r5, r3
	ADCS	r6, r6, r9
	ADCS	r7, r7, r10
	ADD	r1, r1, #0x10
	ADC	r8, r8, r11
#ifdef WOLFSSL_SP_NO_UMAAL
	STM	lr, {r4, r5, r6, r7, r8}
#else
	/* h[0]-h[2] in r4-r6 for multiplication. */
	STR	r7, [lr, #12]
	STR	r8, [lr, #16]
#endif /* WOLFSSL_SP_NO_UMAAL */
	STR	r1, [sp, #16]
	LDR	r1, [sp, #12]
	/* Multiply h by r */
#ifdef WOLFSSL_SP_NO_UMAAL
	/* r0 = #0, r1 = r, lr = h, r2 = h[j], r3 = r[i] */
	LDR	r3, [r1]
	EOR	r0, r0, r0
	/* r[0] * h[0] */
	/* h[0] in r4 */
	UMULL	r4, r5, r3, r4
	/* r[0] * h[2] */
	/* h[2] in r6 */
	UMULL	r6, r7, r3, r6
	/* r[0] * h[4] */
	/* h[4] in r8 */
	MUL	r8, r3, r8
	/* r[0] * h[1] */
	LDR	r2, [lr, #4]
	MOV	r12, r0
	UMLAL	r5, r12, r3, r2
	/* r[0] * h[3] */
	LDR	r2, [lr, #12]
	ADDS	r6, r6, r12
	ADC	r7, r7, r0
	UMLAL	r7, r8, r3, r2
	/* r[1] * h[0] */
	LDR	r3, [r1, #4]
	LDR	r2, [lr]
	MOV	r12, r0
	UMLAL	r5, r12, r3, r2
	/* r[1] * h[1] */
	LDR	r2, [lr, #4]
	ADDS	r6, r6, r12
	ADC	r12, r0, r0
	UMLAL	r6, r12, r3, r2
	/* r[1] * h[2] */
	LDR	r2, [lr, #8]
	ADDS	r7, r7, r12
	ADC	r12, r0, r0
	UMLAL	r7, r12, r3, r2
	/* r[1] * h[3] */
	LDR	r2, [lr, #12]
	ADDS	r8, r8, r12
	ADC	r9, r0, r0
	UMLAL	r8, r9, r3, r2
	/* r[1] * h[4] */
	LDR	r2, [lr, #16]
	MLA	r9, r3, r2, r9
	/* r[2] * h[0] */
	LDR	r3, [r1, #8]
	LDR	r2, [lr]
	MOV	r12, r0
	UMLAL	r6, r12, r3, r2
	/* r[2] * h[1] */
	LDR	r2, [lr, #4]
	ADDS	r7, r7, r12
	ADC	r12, r0, r0
	UMLAL	r7, r12, r3, r2
	/* r[2] * h[2] */
	LDR	r2, [lr, #8]
	ADDS	r8, r8, r12
	ADC	r12, r0, r0
	UMLAL	r8, r12, r3, r2
	/* r[2] * h[3] */
	LDR	r2, [lr, #12]
	ADDS	r9, r9, r12
	ADC	r10, r0, r0
	UMLAL	r9, r10, r3, r2
	/* r[2] * h[4] */
	LDR	r2, [lr, #16]
	MLA	r10, r3, r2, r10
	/* r[3] * h[0] */
	LDR	r3, [r1, #12]
	LDR	r2, [lr]
	MOV	r12, r0
	UMLAL	r7, r12, r3, r2
	/* r[3] * h[1] */
	LDR	r2, [lr, #4]
	ADDS	r8, r8, r12
	ADC	r12, r0, r0
	UMLAL	r8, r12, r3, r2
	/* r[3] * h[2] */
	LDR	r2, [lr, #8]
	ADDS	r9, r9, r12
	ADC	r10, r10, r0
	UMLAL	r9, r10, r3, r2
	/* r[3] * h[3] */
	LDR	r2, [lr, #12]
	MOV	r11, r0
	UMLAL	r10, r11, r3, r2
	/* r[3] * h[4] */
	LDR	r2, [lr, #16]
	MOV	r12, r0
	MLA	r11, r3, r2, r11
#else
	LDM	r1, {r0, r1, r2, r3}
	/* r[0] * h[0] */
	UMULL	r10, r11, r0, r4
	/* r[1] * h[0] */
	UMULL	r12, r7, r1, r4
	/* r[0] * h[1] */
	UMAAL	r11, r12, r0, r5
	/* r[2] * h[0] */
	UMULL	r8, r9, r2, r4
	/* r[1] * h[1] */
	UMAAL	r12, r8, r1, r5
	/* r[0] * h[2] */
	UMAAL	r12, r7, r0, r6
	/* r[3] * h[0] */
	UMAAL	r8, r9, r3, r4
	STM	sp, {r10, r11, r12}
	/* r[2] * h[1] */
	UMAAL	r7, r8, r2, r5
	/* Replace h[0] with h[3] */
	LDR	r4, [lr, #12]
	/* r[1] * h[2] */
	UMULL	r10, r11, r1, r6
	/* r[2] * h[2] */
	UMAAL	r8, r9, r2, r6
	/* r[0] * h[3] */
	UMAAL	r7, r10, r0, r4
	/* r[3] * h[1] */
	UMAAL	r8, r11, r3, r5
	/* r[1] * h[3] */
	UMAAL	r8, r10, r1, r4
	/* r[3] * h[2] */
	UMAAL	r9, r11, r3, r6
	/* r[2] * h[3] */
	UMAAL	r9, r10, r2, r4
	/* Replace h[1] with h[4] */
	LDR	r5, [lr, #16]
	/* r[3] * h[3] */
	UMAAL	r10, r11, r3, r4
	MOV	r12, #0x0
	/* r[0] * h[4] */
	UMAAL	r8, r12, r0, r5
	/* r[1] * h[4] */
	UMAAL	r9, r12, r1, r5
	/* r[2] * h[4] */
	UMAAL	r10, r12, r2, r5
	/* r[3] * h[4] */
	UMAAL	r11, r12, r3, r5
	/* DONE */
	LDM	sp, {r4, r5, r6}
#endif /* WOLFSSL_SP_NO_UMAAL */
	/* r12 will be zero because r is masked. */
	/* Load length */
	LDR	r2, [sp, #20]
	/* Reduce mod 2^130 - 5 */
	BIC	r3, r8, #0x3
	AND	r8, r8, #0x3
	ADDS	r4, r4, r3
	LSR	r3, r3, #2
	ADCS	r5, r5, r9
	ORR	r3, r3, r9, LSL #30
	ADCS	r6, r6, r10
	LSR	r9, r9, #2
	ADCS	r7, r7, r11
	ORR	r9, r9, r10, LSL #30
	ADC	r8, r8, r12
	LSR	r10, r10, #2
	ADDS	r4, r4, r3
	ORR	r10, r10, r11, LSL #30
	ADCS	r5, r5, r9
	LSR	r11, r11, #2
	ADCS	r6, r6, r10
	ADCS	r7, r7, r11
	ADC	r8, r8, r12
	/* Sub 16 from length. */
	SUBS	r2, r2, #0x10
	/* Store length. */
	STR	r2, [sp, #20]
	/* Loop again if more message to do. */
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGT	L_poly1305_thumb2_16_loop
#else
	BGT.N	L_poly1305_thumb2_16_loop
#endif
	STM	lr, {r4, r5, r6, r7, r8}
L_poly1305_thumb2_16_done:
	ADD	sp, sp, #0x1c
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 250 */
	.size	poly1305_blocks_thumb2_16,.-poly1305_blocks_thumb2_16
	.text
	.type	L_poly1305_thumb2_clamp, %object
	.size	L_poly1305_thumb2_clamp, 16
	.align	4
L_poly1305_thumb2_clamp:
	.word	0xfffffff
	.word	0xffffffc
	.word	0xffffffc
	.word	0xffffffc
	.text
	.align	4
	.globl	poly1305_set_key
	.type	poly1305_set_key, %function
poly1305_set_key:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, lr}
	/* Load mask. */
	ADR	r10, L_poly1305_thumb2_clamp
	LDM	r10, {r6, r7, r8, r9}
	/* Load and cache padding. */
	LDR	r2, [r1, #16]
	LDR	r3, [r1, #20]
	LDR	r4, [r1, #24]
	LDR	r5, [r1, #28]
	ADD	r10, r0, #0x24
	STM	r10, {r2, r3, r4, r5}
	/* Load, mask and store r. */
	LDR	r2, [r1]
	LDR	r3, [r1, #4]
	LDR	r4, [r1, #8]
	LDR	r5, [r1, #12]
	AND	r2, r2, r6
	AND	r3, r3, r7
	AND	r4, r4, r8
	AND	r5, r5, r9
	ADD	r10, r0, #0x0
	STM	r10, {r2, r3, r4, r5}
	/* h (accumulator) = 0 */
	EOR	r6, r6, r6
	EOR	r7, r7, r7
	EOR	r8, r8, r8
	EOR	r9, r9, r9
	ADD	r10, r0, #0x10
	EOR	r5, r5, r5
	STM	r10, {r5, r6, r7, r8, r9}
	/* Zero leftover */
	STR	r5, [r0, #52]
	POP	{r4, r5, r6, r7, r8, r9, r10, pc}
	/* Cycle Count = 70 */
	.size	poly1305_set_key,.-poly1305_set_key
	.text
	.align	4
	.globl	poly1305_final
	.type	poly1305_final, %function
poly1305_final:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	ADD	r11, r0, #0x10
	LDM	r11, {r2, r3, r4, r5, r6}
	/* Add 5 and check for h larger than p. */
	ADDS	r7, r2, #0x5
	ADCS	r7, r3, #0x0
	ADCS	r7, r4, #0x0
	ADCS	r7, r5, #0x0
	ADC	r7, r6, #0x0
	SUB	r7, r7, #0x4
	LSR	r7, r7, #31
	SUB	r7, r7, #0x1
	AND	r7, r7, #0x5
	/* Add 0/5 to h. */
	ADDS	r2, r2, r7
	ADCS	r3, r3, #0x0
	ADCS	r4, r4, #0x0
	ADC	r5, r5, #0x0
	/* Add padding */
	ADD	r11, r0, #0x24
	LDM	r11, {r7, r8, r9, r10}
	ADDS	r2, r2, r7
	ADCS	r3, r3, r8
	ADCS	r4, r4, r9
	ADC	r5, r5, r10
	/* Store MAC */
	STR	r2, [r1]
	STR	r3, [r1, #4]
	STR	r4, [r1, #8]
	STR	r5, [r1, #12]
	/* Zero out h. */
	EOR	r2, r2, r2
	EOR	r3, r3, r3
	EOR	r4, r4, r4
	EOR	r5, r5, r5
	EOR	r6, r6, r6
	ADD	r11, r0, #0x10
	STM	r11, {r2, r3, r4, r5, r6}
	/* Zero out r. */
	ADD	r11, r0, #0x0
	STM	r11, {r2, r3, r4, r5}
	/* Zero out padding. */
	ADD	r11, r0, #0x24
	STM	r11, {r2, r3, r4, r5}
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 82 */
	.size	poly1305_final,.-poly1305_final
#endif /* HAVE_POLY1305 */
#endif /* !__aarch64__ && __thumb__ */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section        .note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
