/* thumb2-frodokem-asm
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
 *   ruby ./frodokem/frodokem.rb \
 *       thumb2 ../wolfssl/wolfcrypt/src/port/arm/thumb2-frodokem-asm.S
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

#ifdef WOLFSSL_ARMASM
#ifdef WOLFSSL_ARMASM_THUMB2
#ifndef WOLFSSL_ARMASM_INLINE
	.thumb
	.syntax unified
#ifdef WOLFSSL_HAVE_FRODOKEM
	.text
	.align	4
	.globl	frodokem_add_thumb2
	.type	frodokem_add_thumb2, %function
frodokem_add_thumb2:
	PUSH	{r4, r5, lr}
	ORR	r2, r2, r2, LSL #16
	MOV	r3, #32
L_frodokem_add_thumb2_blk:
	LDR	r4, [r0]
	LDR	r5, [r1], #4
	SADD16	r4, r4, r5
	AND	r4, r4, r2
	STR	r4, [r0], #4
	SUBS	r3, r3, #1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_frodokem_add_thumb2_blk
#else
	BNE.N	L_frodokem_add_thumb2_blk
#endif
	POP	{r4, r5, pc}
	/* Cycle Count = 23 */
	.size	frodokem_add_thumb2,.-frodokem_add_thumb2
	.text
	.align	4
	.globl	frodokem_sa_accum_thumb2
	.type	frodokem_sa_accum_thumb2, %function
frodokem_sa_accum_thumb2:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	LDR	r4, [sp, #36]
	LSL	r4, r4, #1
	ADD	r5, r1, r3, LSL #1
	MOV	r8, #8
L_frodokem_sa_accum_thumb2_i:
	LDRH	r9, [r5]
	ADD	r5, r5, r4
	MOV	r6, r2
	LSR	r7, r4, #2
L_frodokem_sa_accum_thumb2_k:
	LDR	r11, [r0]
	LDR	r10, [r6], #4
	SMULBB	r12, r9, r10
	SMULBT	lr, r9, r10
	PKHBT	r12, r12, lr, LSL #16
	SADD16	r11, r11, r12
	STR	r11, [r0], #4
	SUBS	r7, r7, #1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_frodokem_sa_accum_thumb2_k
#else
	BNE.N	L_frodokem_sa_accum_thumb2_k
#endif
	SUBS	r8, r8, #1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_frodokem_sa_accum_thumb2_i
#else
	BNE.N	L_frodokem_sa_accum_thumb2_i
#endif
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 50 */
	.size	frodokem_sa_accum_thumb2,.-frodokem_sa_accum_thumb2
	.text
	.align	4
	.globl	frodokem_as_accum_thumb2
	.type	frodokem_as_accum_thumb2, %function
frodokem_as_accum_thumb2:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	LDR	r4, [sp, #36]
	LSL	r4, r4, #1
	ADD	r5, r0, r3, LSL #4
	MOV	r6, r1
	MOV	r9, #8
L_frodokem_as_accum_thumb2_c:
	MOV	r11, #0
	MOV	r7, r2
	MOV	r8, r6
	LSR	r10, r4, #2
L_frodokem_as_accum_thumb2_j:
	LDR	r12, [r7], #4
	LDR	lr, [r8], #4
	SMLAD	r11, r12, lr, r11
	SUBS	r10, r10, #1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_frodokem_as_accum_thumb2_j
#else
	BNE.N	L_frodokem_as_accum_thumb2_j
#endif
	LDRH	r12, [r5]
	ADD	r12, r12, r11
	STRH	r12, [r5]
	ADD	r5, r5, #2
	ADD	r6, r6, r4
	SUBS	r9, r9, #1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_frodokem_as_accum_thumb2_c
#else
	BNE.N	L_frodokem_as_accum_thumb2_c
#endif
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 52 */
	.size	frodokem_as_accum_thumb2,.-frodokem_as_accum_thumb2
	.text
	.align	4
	.globl	frodokem_mul_bs_thumb2
	.type	frodokem_mul_bs_thumb2, %function
frodokem_mul_bs_thumb2:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	MOV	r4, r1
	MOV	r8, #8
L_frodokem_mul_bs_thumb2_i:
	MOV	r5, r2
	MOV	r9, #8
L_frodokem_mul_bs_thumb2_c:
	MOV	r11, #0
	MOV	r6, r4
	MOV	r7, r5
	LSR	r10, r3, #1
L_frodokem_mul_bs_thumb2_j:
	LDR	r12, [r6], #4
	LDR	lr, [r7], #4
	SMLAD	r11, r12, lr, r11
	SUBS	r10, r10, #1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_frodokem_mul_bs_thumb2_j
#else
	BNE.N	L_frodokem_mul_bs_thumb2_j
#endif
	LDR	r12, [sp, #36]
	ORR	r12, r12, r12, LSL #16
	AND	r11, r11, r12
	STRH	r11, [r0]
	ADD	r0, r0, #2
	ADD	r5, r5, r3, LSL #1
	SUBS	r9, r9, #1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_frodokem_mul_bs_thumb2_c
#else
	BNE.N	L_frodokem_mul_bs_thumb2_c
#endif
	ADD	r4, r4, r3, LSL #1
	SUBS	r8, r8, #1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_frodokem_mul_bs_thumb2_i
#else
	BNE.N	L_frodokem_mul_bs_thumb2_i
#endif
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 57 */
	.size	frodokem_mul_bs_thumb2,.-frodokem_mul_bs_thumb2
	.text
	.align	4
	.globl	frodokem_mul_add_sb_plus_e_thumb2
	.type	frodokem_mul_add_sb_plus_e_thumb2, %function
frodokem_mul_add_sb_plus_e_thumb2:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #8
	LSL	r11, r3, #1
	STR	r11, [sp, #4]
	STR	r1, [sp]
	MOV	r4, #8
L_frodokem_mul_add_sb_plus_e_thumb2_i:
	LDR	r11, [sp, #4]
	ADD	r3, r2, r11
	LDR	r1, [sp]
	MOV	r5, r2
	LDR	r6, [r0]
	LDR	r7, [r0, #4]
	LDR	r8, [r0, #8]
	LDR	r9, [r0, #12]
L_frodokem_mul_add_sb_plus_e_thumb2_j:
	LDRH	r10, [r5]
	ADD	r5, r5, #2
	LDR	r11, [r1]
	SMULBB	r12, r10, r11
	SMULBT	lr, r10, r11
	PKHBT	r12, r12, lr, LSL #16
	SADD16	r6, r6, r12
	LDR	r11, [r1, #4]
	SMULBB	r12, r10, r11
	SMULBT	lr, r10, r11
	PKHBT	r12, r12, lr, LSL #16
	SADD16	r7, r7, r12
	LDR	r11, [r1, #8]
	SMULBB	r12, r10, r11
	SMULBT	lr, r10, r11
	PKHBT	r12, r12, lr, LSL #16
	SADD16	r8, r8, r12
	LDR	r11, [r1, #12]
	SMULBB	r12, r10, r11
	SMULBT	lr, r10, r11
	PKHBT	r12, r12, lr, LSL #16
	SADD16	r9, r9, r12
	ADD	r1, r1, #16
	CMP	r5, r3
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_frodokem_mul_add_sb_plus_e_thumb2_j
#else
	BNE.N	L_frodokem_mul_add_sb_plus_e_thumb2_j
#endif
	LDR	r11, [sp, #44]
	ORR	r11, r11, r11, LSL #16
	AND	r6, r6, r11
	AND	r7, r7, r11
	AND	r8, r8, r11
	AND	r9, r9, r11
	STR	r6, [r0]
	STR	r7, [r0, #4]
	STR	r8, [r0, #8]
	STR	r9, [r0, #12]
	ADD	r0, r0, #16
	MOV	r2, r3
	SUBS	r4, r4, #1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_frodokem_mul_add_sb_plus_e_thumb2_i
#else
	BNE.N	L_frodokem_mul_add_sb_plus_e_thumb2_i
#endif
	ADD	sp, sp, #8
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 97 */
	.size	frodokem_mul_add_sb_plus_e_thumb2,.-frodokem_mul_add_sb_plus_e_thumb2
#endif /* WOLFSSL_HAVE_FRODOKEM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
#endif /* WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */
