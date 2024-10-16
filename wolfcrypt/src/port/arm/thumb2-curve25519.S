/* thumb2-curve25519
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
 *   ruby ./x25519/x25519.rb thumb2 ../wolfssl/wolfcrypt/src/port/arm/thumb2-curve25519.S
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
#if defined(HAVE_CURVE25519) || defined(HAVE_ED25519)
#if !defined(CURVE25519_SMALL) || !defined(ED25519_SMALL)

	.text
	.align	4
	.globl	fe_init
	.type	fe_init, %function
fe_init:
	BX	lr
	/* Cycle Count = 4 */
	.size	fe_init,.-fe_init
	.text
	.align	4
	.globl	fe_add_sub_op
	.type	fe_add_sub_op, %function
fe_add_sub_op:
	PUSH	{lr}
	/* Add-Sub */
	LDRD	r4, r5, [r2]
	LDRD	r6, r7, [r3]
	/*  Add */
	ADDS	r8, r4, r6
	MOV	r12, #0x0
	ADCS	r9, r5, r7
	ADC	r12, r12, #0x0
	STRD	r8, r9, [r0]
	/*  Sub */
	SUBS	r10, r4, r6
	SBCS	r11, r5, r7
	STRD	r10, r11, [r1]
	LDRD	r4, r5, [r2, #8]
	LDRD	r6, r7, [r3, #8]
	/*  Sub */
	SBCS	r10, r4, r6
	MOV	lr, #0x0
	SBCS	r11, r5, r7
	ADC	lr, lr, #0x0
	STRD	r10, r11, [r1, #8]
	/*  Add */
	SUBS	r12, r12, #0x1
	ADCS	r8, r4, r6
	ADCS	r9, r5, r7
	STRD	r8, r9, [r0, #8]
	LDRD	r4, r5, [r2, #16]
	LDRD	r6, r7, [r3, #16]
	/*  Add */
	ADCS	r8, r4, r6
	MOV	r12, #0x0
	ADCS	r9, r5, r7
	ADC	r12, r12, #0x0
	STRD	r8, r9, [r0, #16]
	/*  Sub */
	SUBS	lr, lr, #0x1
	SBCS	r10, r4, r6
	SBCS	r11, r5, r7
	STRD	r10, r11, [r1, #16]
	LDRD	r4, r5, [r2, #24]
	LDRD	r6, r7, [r3, #24]
	/*  Sub */
	SBCS	r10, r4, r6
	SBC	r11, r5, r7
	/*  Add */
	SUBS	r12, r12, #0x1
	ADCS	r8, r4, r6
	MOV	r12, #0x0
	ADCS	r9, r5, r7
	ADC	r12, r12, #0x0
	/*   Multiply -modulus by overflow */
	LSL	r3, r12, #1
	MOV	r12, #0x13
	ORR	r3, r3, r9, LSR #31
	MUL	r12, r3, r12
	/*   Add -x*modulus (if overflow) */
	LDRD	r4, r5, [r0]
	LDRD	r6, r7, [r0, #8]
	ADDS	r4, r4, r12
	ADCS	r5, r5, #0x0
	ADCS	r6, r6, #0x0
	ADCS	r7, r7, #0x0
	STRD	r4, r5, [r0]
	STRD	r6, r7, [r0, #8]
	LDRD	r4, r5, [r0, #16]
	ADCS	r4, r4, #0x0
	ADCS	r5, r5, #0x0
	STRD	r4, r5, [r0, #16]
	BFC	r9, #31, #1
	ADCS	r8, r8, #0x0
	ADC	r9, r9, #0x0
	STRD	r8, r9, [r0, #24]
	/*   Add -modulus on underflow */
	MOV	lr, #0x13
	AND	lr, lr, r11, ASR #31
	LDM	r1, {r4, r5, r6, r7, r8, r9}
	SUBS	r4, r4, lr
	SBCS	r5, r5, #0x0
	SBCS	r6, r6, #0x0
	SBCS	r7, r7, #0x0
	SBCS	r8, r8, #0x0
	SBCS	r9, r9, #0x0
	BFC	r11, #31, #1
	SBCS	r10, r10, #0x0
	SBC	r11, r11, #0x0
	STM	r1, {r4, r5, r6, r7, r8, r9, r10, r11}
	/* Done Add-Sub */
	POP	{pc}
	/* Cycle Count = 134 */
	.size	fe_add_sub_op,.-fe_add_sub_op
	.text
	.align	4
	.globl	fe_sub_op
	.type	fe_sub_op, %function
fe_sub_op:
	PUSH	{lr}
	/* Sub */
	LDM	r2!, {r6, r7, r8, r9, r10, r11, r12, lr}
	LDM	r1!, {r2, r3, r4, r5}
	SUBS	r6, r2, r6
	SBCS	r7, r3, r7
	SBCS	r8, r4, r8
	SBCS	r9, r5, r9
	LDM	r1!, {r2, r3, r4, r5}
	SBCS	r10, r2, r10
	SBCS	r11, r3, r11
	SBCS	r12, r4, r12
	SBC	lr, r5, lr
	MOV	r2, #0x13
	AND	r2, r2, lr, ASR #31
	SUBS	r6, r6, r2
	SBCS	r7, r7, #0x0
	SBCS	r8, r8, #0x0
	SBCS	r9, r9, #0x0
	SBCS	r10, r10, #0x0
	SBCS	r11, r11, #0x0
	BFC	lr, #31, #1
	SBCS	r12, r12, #0x0
	SBC	lr, lr, #0x0
	STM	r0, {r6, r7, r8, r9, r10, r11, r12, lr}
	/* Done Sub */
	POP	{pc}
	/* Cycle Count = 51 */
	.size	fe_sub_op,.-fe_sub_op
	.text
	.align	4
	.globl	fe_sub
	.type	fe_sub, %function
fe_sub:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	BL	fe_sub_op
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 24 */
	.size	fe_sub,.-fe_sub
	.text
	.align	4
	.globl	fe_add_op
	.type	fe_add_op, %function
fe_add_op:
	PUSH	{lr}
	/* Add */
	LDM	r2!, {r6, r7, r8, r9, r10, r11, r12, lr}
	LDM	r1!, {r2, r3, r4, r5}
	ADDS	r6, r2, r6
	ADCS	r7, r3, r7
	ADCS	r8, r4, r8
	ADCS	r9, r5, r9
	LDM	r1!, {r2, r3, r4, r5}
	ADCS	r10, r2, r10
	ADCS	r11, r3, r11
	ADCS	r12, r4, r12
	ADC	lr, r5, lr
	MOV	r2, #0x13
	AND	r2, r2, lr, ASR #31
	ADDS	r6, r6, r2
	ADCS	r7, r7, #0x0
	ADCS	r8, r8, #0x0
	ADCS	r9, r9, #0x0
	ADCS	r10, r10, #0x0
	ADCS	r11, r11, #0x0
	BFC	lr, #31, #1
	ADCS	r12, r12, #0x0
	ADC	lr, lr, #0x0
	STM	r0, {r6, r7, r8, r9, r10, r11, r12, lr}
	/* Done Add */
	POP	{pc}
	/* Cycle Count = 51 */
	.size	fe_add_op,.-fe_add_op
	.text
	.align	4
	.globl	fe_add
	.type	fe_add, %function
fe_add:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	BL	fe_add_op
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 24 */
	.size	fe_add,.-fe_add
#ifdef HAVE_ED25519
	.text
	.align	4
	.globl	fe_frombytes
	.type	fe_frombytes, %function
fe_frombytes:
	PUSH	{r4, r5, r6, r7, r8, r9, lr}
	LDR	r2, [r1]
	LDR	r3, [r1, #4]
	LDR	r4, [r1, #8]
	LDR	r5, [r1, #12]
	LDR	r6, [r1, #16]
	LDR	r7, [r1, #20]
	LDR	r8, [r1, #24]
	LDR	r9, [r1, #28]
	BFC	r9, #31, #1
	STR	r2, [r0]
	STR	r3, [r0, #4]
	STR	r4, [r0, #8]
	STR	r5, [r0, #12]
	STR	r6, [r0, #16]
	STR	r7, [r0, #20]
	STR	r8, [r0, #24]
	STR	r9, [r0, #28]
	POP	{r4, r5, r6, r7, r8, r9, pc}
	/* Cycle Count = 49 */
	.size	fe_frombytes,.-fe_frombytes
	.text
	.align	4
	.globl	fe_tobytes
	.type	fe_tobytes, %function
fe_tobytes:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, lr}
	LDM	r1, {r2, r3, r4, r5, r6, r7, r8, r9}
	ADDS	r10, r2, #0x13
	ADCS	r10, r3, #0x0
	ADCS	r10, r4, #0x0
	ADCS	r10, r5, #0x0
	ADCS	r10, r6, #0x0
	ADCS	r10, r7, #0x0
	ADCS	r10, r8, #0x0
	ADC	r10, r9, #0x0
	ASR	r10, r10, #31
	AND	r10, r10, #0x13
	ADDS	r2, r2, r10
	ADCS	r3, r3, #0x0
	ADCS	r4, r4, #0x0
	ADCS	r5, r5, #0x0
	ADCS	r6, r6, #0x0
	ADCS	r7, r7, #0x0
	ADCS	r8, r8, #0x0
	ADC	r9, r9, #0x0
	BFC	r9, #31, #1
	STR	r2, [r0]
	STR	r3, [r0, #4]
	STR	r4, [r0, #8]
	STR	r5, [r0, #12]
	STR	r6, [r0, #16]
	STR	r7, [r0, #20]
	STR	r8, [r0, #24]
	STR	r9, [r0, #28]
	POP	{r4, r5, r6, r7, r8, r9, r10, pc}
	/* Cycle Count = 62 */
	.size	fe_tobytes,.-fe_tobytes
	.text
	.align	4
	.globl	fe_1
	.type	fe_1, %function
fe_1:
	PUSH	{r4, r5, r6, r7, r8, r9, lr}
	/* Set one */
	MOV	r2, #0x1
	MOV	r3, #0x0
	MOV	r4, #0x0
	MOV	r5, #0x0
	MOV	r6, #0x0
	MOV	r7, #0x0
	MOV	r8, #0x0
	MOV	r9, #0x0
	STM	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	POP	{r4, r5, r6, r7, r8, r9, pc}
	/* Cycle Count = 33 */
	.size	fe_1,.-fe_1
	.text
	.align	4
	.globl	fe_0
	.type	fe_0, %function
fe_0:
	PUSH	{r4, r5, r6, r7, r8, r9, lr}
	/* Set zero */
	MOV	r2, #0x0
	MOV	r3, #0x0
	MOV	r4, #0x0
	MOV	r5, #0x0
	MOV	r6, #0x0
	MOV	r7, #0x0
	MOV	r8, #0x0
	MOV	r9, #0x0
	STM	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	POP	{r4, r5, r6, r7, r8, r9, pc}
	/* Cycle Count = 33 */
	.size	fe_0,.-fe_0
	.text
	.align	4
	.globl	fe_copy
	.type	fe_copy, %function
fe_copy:
	PUSH	{r4, r5, lr}
	/* Copy */
	LDRD	r2, r3, [r1]
	LDRD	r4, r5, [r1, #8]
	STRD	r2, r3, [r0]
	STRD	r4, r5, [r0, #8]
	LDRD	r2, r3, [r1, #16]
	LDRD	r4, r5, [r1, #24]
	STRD	r2, r3, [r0, #16]
	STRD	r4, r5, [r0, #24]
	POP	{r4, r5, pc}
	/* Cycle Count = 32 */
	.size	fe_copy,.-fe_copy
	.text
	.align	4
	.globl	fe_neg
	.type	fe_neg, %function
fe_neg:
	PUSH	{r4, r5, r6, r7, lr}
	MVN	r7, #0x0
	MVN	r6, #0x12
	LDM	r1!, {r2, r3, r4, r5}
	SUBS	r2, r6, r2
	SBCS	r3, r7, r3
	SBCS	r4, r7, r4
	SBCS	r5, r7, r5
	STM	r0!, {r2, r3, r4, r5}
	MVN	r6, #0x80000000
	LDM	r1!, {r2, r3, r4, r5}
	SBCS	r2, r7, r2
	SBCS	r3, r7, r3
	SBCS	r4, r7, r4
	SBC	r5, r6, r5
	STM	r0!, {r2, r3, r4, r5}
	POP	{r4, r5, r6, r7, pc}
	/* Cycle Count = 43 */
	.size	fe_neg,.-fe_neg
	.text
	.align	4
	.globl	fe_isnonzero
	.type	fe_isnonzero, %function
fe_isnonzero:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, lr}
	LDM	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	ADDS	r1, r2, #0x13
	ADCS	r1, r3, #0x0
	ADCS	r1, r4, #0x0
	ADCS	r1, r5, #0x0
	ADCS	r1, r6, #0x0
	ADCS	r1, r7, #0x0
	ADCS	r1, r8, #0x0
	ADC	r1, r9, #0x0
	ASR	r1, r1, #31
	AND	r1, r1, #0x13
	ADDS	r2, r2, r1
	ADCS	r3, r3, #0x0
	ADCS	r4, r4, #0x0
	ADCS	r5, r5, #0x0
	ADCS	r6, r6, #0x0
	ADCS	r7, r7, #0x0
	ADCS	r8, r8, #0x0
	ADC	r9, r9, #0x0
	BFC	r9, #31, #1
	ORR	r2, r2, r3
	ORR	r4, r4, r5
	ORR	r6, r6, r7
	ORR	r8, r8, r9
	ORR	r4, r4, r6
	ORR	r2, r2, r8
	ORR	r0, r2, r4
	POP	{r4, r5, r6, r7, r8, r9, r10, pc}
	/* Cycle Count = 53 */
	.size	fe_isnonzero,.-fe_isnonzero
	.text
	.align	4
	.globl	fe_isnegative
	.type	fe_isnegative, %function
fe_isnegative:
	PUSH	{r4, r5, lr}
	LDM	r0!, {r2, r3, r4, r5}
	ADDS	r1, r2, #0x13
	ADCS	r1, r3, #0x0
	ADCS	r1, r4, #0x0
	ADCS	r1, r5, #0x0
	LDM	r0, {r2, r3, r4, r5}
	ADCS	r1, r2, #0x0
	ADCS	r1, r3, #0x0
	ADCS	r1, r4, #0x0
	LDR	r2, [r0, #-16]
	ADC	r1, r5, #0x0
	AND	r0, r2, #0x1
	LSR	r1, r1, #31
	EOR	r0, r0, r1
	POP	{r4, r5, pc}
	/* Cycle Count = 31 */
	.size	fe_isnegative,.-fe_isnegative
#if defined(HAVE_ED25519_MAKE_KEY) || defined(HAVE_ED25519_SIGN)
#ifndef WC_NO_CACHE_RESISTANT
	.text
	.align	4
	.globl	fe_cmov_table
	.type	fe_cmov_table, %function
fe_cmov_table:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SXTB	r2, r2
	SBFX	r3, r2, #7, #1
	EOR	r12, r2, r3
	SUB	r12, r12, r3
	MOV	r4, #0x1
	MOV	r5, #0x0
	MOV	r6, #0x1
	MOV	r7, #0x0
	MOV	r8, #0x0
	MOV	r9, #0x0
	MOV	r3, #0x80000000
	ROR	r3, r3, #31
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #32]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #64]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #30
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #32]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #64]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #29
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #32]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #64]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #28
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #32]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #64]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #27
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #32]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #64]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #26
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #32]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #64]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #25
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #32]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #64]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #24
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #32]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #64]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	SUB	r1, r1, #0x2a0
	MVN	r10, #0x12
	MVN	r11, #0x0
	SUBS	r10, r10, r8
	SBCS	r11, r11, r9
	SBC	lr, lr, lr
	ASR	r12, r2, #31
	EOR	r3, r4, r6
	AND	r3, r3, r12
	EOR	r4, r4, r3
	EOR	r6, r6, r3
	EOR	r3, r5, r7
	AND	r3, r3, r12
	EOR	r5, r5, r3
	EOR	r7, r7, r3
	EOR	r10, r10, r8
	AND	r10, r10, r12
	EOR	r8, r8, r10
	EOR	r11, r11, r9
	AND	r11, r11, r12
	EOR	r9, r9, r11
	STRD	r4, r5, [r0]
	STRD	r6, r7, [r0, #32]
	STRD	r8, r9, [r0, #64]
	SBFX	r3, r2, #7, #1
	EOR	r12, r2, r3
	SUB	r12, r12, r3
	MOV	r4, #0x0
	MOV	r5, #0x0
	MOV	r6, #0x0
	MOV	r7, #0x0
	MOV	r8, #0x0
	MOV	r9, #0x0
	MOV	r3, #0x80000000
	ROR	r3, r3, #31
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #8]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #40]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #72]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #30
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #8]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #40]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #72]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #29
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #8]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #40]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #72]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #28
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #8]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #40]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #72]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #27
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #8]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #40]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #72]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #26
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #8]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #40]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #72]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #25
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #8]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #40]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #72]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #24
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #8]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #40]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #72]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	SUB	r1, r1, #0x2a0
	MVN	r10, #0x0
	MVN	r11, #0x0
	RSBS	lr, lr, #0x0
	SBCS	r10, r10, r8
	SBCS	r11, r11, r9
	SBC	lr, lr, lr
	ASR	r12, r2, #31
	EOR	r3, r4, r6
	AND	r3, r3, r12
	EOR	r4, r4, r3
	EOR	r6, r6, r3
	EOR	r3, r5, r7
	AND	r3, r3, r12
	EOR	r5, r5, r3
	EOR	r7, r7, r3
	EOR	r10, r10, r8
	AND	r10, r10, r12
	EOR	r8, r8, r10
	EOR	r11, r11, r9
	AND	r11, r11, r12
	EOR	r9, r9, r11
	STRD	r4, r5, [r0, #8]
	STRD	r6, r7, [r0, #40]
	STRD	r8, r9, [r0, #72]
	SBFX	r3, r2, #7, #1
	EOR	r12, r2, r3
	SUB	r12, r12, r3
	MOV	r4, #0x0
	MOV	r5, #0x0
	MOV	r6, #0x0
	MOV	r7, #0x0
	MOV	r8, #0x0
	MOV	r9, #0x0
	MOV	r3, #0x80000000
	ROR	r3, r3, #31
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #16]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #48]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #80]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #30
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #16]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #48]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #80]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #29
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #16]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #48]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #80]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #28
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #16]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #48]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #80]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #27
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #16]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #48]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #80]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #26
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #16]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #48]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #80]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #25
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #16]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #48]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #80]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #24
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #16]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #48]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #80]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	SUB	r1, r1, #0x2a0
	MVN	r10, #0x0
	MVN	r11, #0x0
	RSBS	lr, lr, #0x0
	SBCS	r10, r10, r8
	SBCS	r11, r11, r9
	SBC	lr, lr, lr
	ASR	r12, r2, #31
	EOR	r3, r4, r6
	AND	r3, r3, r12
	EOR	r4, r4, r3
	EOR	r6, r6, r3
	EOR	r3, r5, r7
	AND	r3, r3, r12
	EOR	r5, r5, r3
	EOR	r7, r7, r3
	EOR	r10, r10, r8
	AND	r10, r10, r12
	EOR	r8, r8, r10
	EOR	r11, r11, r9
	AND	r11, r11, r12
	EOR	r9, r9, r11
	STRD	r4, r5, [r0, #16]
	STRD	r6, r7, [r0, #48]
	STRD	r8, r9, [r0, #80]
	SBFX	r3, r2, #7, #1
	EOR	r12, r2, r3
	SUB	r12, r12, r3
	MOV	r4, #0x0
	MOV	r5, #0x0
	MOV	r6, #0x0
	MOV	r7, #0x0
	MOV	r8, #0x0
	MOV	r9, #0x0
	MOV	r3, #0x80000000
	ROR	r3, r3, #31
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #24]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #56]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #88]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #30
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #24]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #56]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #88]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #29
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #24]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #56]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #88]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #28
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #24]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #56]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #88]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #27
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #24]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #56]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #88]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #26
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #24]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #56]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #88]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #25
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #24]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #56]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #88]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	ADD	r1, r1, #0x60
	MOV	r3, #0x80000000
	ROR	r3, r3, #24
	ROR	r3, r3, r12
	ASR	r3, r3, #31
	LDRD	r10, r11, [r1, #24]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r4, r4, r10
	EOR	r5, r5, r11
	LDRD	r10, r11, [r1, #56]
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r6, r6, r10
	EOR	r7, r7, r11
	LDRD	r10, r11, [r1, #88]
	EOR	r10, r10, r8
	EOR	r11, r11, r9
	AND	r10, r10, r3
	AND	r11, r11, r3
	EOR	r8, r8, r10
	EOR	r9, r9, r11
	SUB	r1, r1, #0x2a0
	MVN	r10, #0x0
	MVN	r11, #0x80000000
	RSBS	lr, lr, #0x0
	SBCS	r10, r10, r8
	SBC	r11, r11, r9
	ASR	r12, r2, #31
	EOR	r3, r4, r6
	AND	r3, r3, r12
	EOR	r4, r4, r3
	EOR	r6, r6, r3
	EOR	r3, r5, r7
	AND	r3, r3, r12
	EOR	r5, r5, r3
	EOR	r7, r7, r3
	EOR	r10, r10, r8
	AND	r10, r10, r12
	EOR	r8, r8, r10
	EOR	r11, r11, r9
	AND	r11, r11, r12
	EOR	r9, r9, r11
	STRD	r4, r5, [r0, #24]
	STRD	r6, r7, [r0, #56]
	STRD	r8, r9, [r0, #88]
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 1195 */
	.size	fe_cmov_table,.-fe_cmov_table
#else
	.text
	.align	4
	.globl	fe_cmov_table
	.type	fe_cmov_table, %function
fe_cmov_table:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SXTB	r2, r2
	SBFX	r3, r2, #7, #1
	EOR	r2, r2, r3
	SUB	r2, r2, r3
	CLZ	lr, r2
	LSL	lr, lr, #26
	ASR	lr, lr, #31
	MVN	lr, lr
	ADD	r2, r2, lr
	MOV	r12, #0x60
	MUL	r2, r2, r12
	ADD	r1, r1, r2
	LDM	r1!, {r4, r5, r6, r7, r8, r9, r10, r11}
	AND	r4, r4, lr
	AND	r5, r5, lr
	AND	r6, r6, lr
	AND	r7, r7, lr
	AND	r8, r8, lr
	AND	r9, r9, lr
	AND	r10, r10, lr
	AND	r11, r11, lr
	MVN	r12, lr
	SUB	r4, r4, r12
	MOV	r12, #0x20
	AND	r12, r12, r3
	ADD	r0, r0, r12
	STM	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	SUB	r0, r0, r12
	LDM	r1!, {r4, r5, r6, r7, r8, r9, r10, r11}
	AND	r4, r4, lr
	AND	r5, r5, lr
	AND	r6, r6, lr
	AND	r7, r7, lr
	AND	r8, r8, lr
	AND	r9, r9, lr
	AND	r10, r10, lr
	AND	r11, r11, lr
	MVN	r12, lr
	SUB	r4, r4, r12
	MOV	r12, #0x20
	BIC	r12, r12, r3
	ADD	r0, r0, r12
	STM	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	SUB	r0, r0, r12
	ADD	r0, r0, #0x40
	LDM	r1!, {r4, r5, r6, r7}
	MVN	r12, #0x12
	SUBS	r8, r12, r4
	SBCS	r9, r3, r5
	SBCS	r10, r3, r6
	SBCS	r11, r3, r7
	BIC	r4, r4, r3
	BIC	r5, r5, r3
	BIC	r6, r6, r3
	BIC	r7, r7, r3
	AND	r8, r8, r3
	AND	r9, r9, r3
	AND	r10, r10, r3
	AND	r11, r11, r3
	ORR	r4, r4, r8
	ORR	r5, r5, r9
	ORR	r6, r6, r10
	ORR	r7, r7, r11
	AND	r4, r4, lr
	AND	r5, r5, lr
	AND	r6, r6, lr
	AND	r7, r7, lr
	STM	r0!, {r4, r5, r6, r7}
	LDM	r1!, {r4, r5, r6, r7}
	MVN	r12, #0x80000000
	SBCS	r8, r3, r4
	SBCS	r9, r3, r5
	SBCS	r10, r3, r6
	SBC	r11, r12, r7
	BIC	r4, r4, r3
	BIC	r5, r5, r3
	BIC	r6, r6, r3
	BIC	r7, r7, r3
	AND	r8, r8, r3
	AND	r9, r9, r3
	AND	r10, r10, r3
	AND	r11, r11, r3
	ORR	r4, r4, r8
	ORR	r5, r5, r9
	ORR	r6, r6, r10
	ORR	r7, r7, r11
	AND	r4, r4, lr
	AND	r5, r5, lr
	AND	r6, r6, lr
	AND	r7, r7, lr
	STM	r0!, {r4, r5, r6, r7}
	SUB	r1, r1, r2
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 160 */
	.size	fe_cmov_table,.-fe_cmov_table
#endif /* WC_NO_CACHE_RESISTANT */
#endif /* HAVE_ED25519_MAKE_KEY || HAVE_ED25519_SIGN */
#endif /* HAVE_ED25519 */
#ifdef WOLFSSL_ARM_ARCH_7M
	.text
	.align	4
	.globl	fe_mul_op
	.type	fe_mul_op, %function
fe_mul_op:
	PUSH	{lr}
	SUB	sp, sp, #0x28
	STR	r0, [sp, #36]
	MOV	r0, #0x0
	LDR	r12, [r1]
	/* A[0] * B[0] */
	LDR	lr, [r2]
	UMULL	r3, r4, r12, lr
	/* A[0] * B[2] */
	LDR	lr, [r2, #8]
	UMULL	r5, r6, r12, lr
	/* A[0] * B[4] */
	LDR	lr, [r2, #16]
	UMULL	r7, r8, r12, lr
	/* A[0] * B[6] */
	LDR	lr, [r2, #24]
	UMULL	r9, r10, r12, lr
	STR	r3, [sp]
	/* A[0] * B[1] */
	LDR	lr, [r2, #4]
	MOV	r11, r0
	UMLAL	r4, r11, r12, lr
	ADDS	r5, r5, r11
	/* A[0] * B[3] */
	LDR	lr, [r2, #12]
	ADCS	r6, r6, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r6, r11, r12, lr
	ADDS	r7, r7, r11
	/* A[0] * B[5] */
	LDR	lr, [r2, #20]
	ADCS	r8, r8, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r8, r11, r12, lr
	ADDS	r9, r9, r11
	/* A[0] * B[7] */
	LDR	lr, [r2, #28]
	ADCS	r10, r10, #0x0
	ADC	r3, r0, #0x0
	UMLAL	r10, r3, r12, lr
	/* A[1] * B[0] */
	LDR	r12, [r1, #4]
	LDR	lr, [r2]
	MOV	r11, #0x0
	UMLAL	r4, r11, r12, lr
	STR	r4, [sp, #4]
	ADDS	r5, r5, r11
	/* A[1] * B[1] */
	LDR	lr, [r2, #4]
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r12, lr
	ADDS	r6, r6, r11
	/* A[1] * B[2] */
	LDR	lr, [r2, #8]
	ADC	r11, r0, #0x0
	UMLAL	r6, r11, r12, lr
	ADDS	r7, r7, r11
	/* A[1] * B[3] */
	LDR	lr, [r2, #12]
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r12, lr
	ADDS	r8, r8, r11
	/* A[1] * B[4] */
	LDR	lr, [r2, #16]
	ADC	r11, r0, #0x0
	UMLAL	r8, r11, r12, lr
	ADDS	r9, r9, r11
	/* A[1] * B[5] */
	LDR	lr, [r2, #20]
	ADC	r11, r0, #0x0
	UMLAL	r9, r11, r12, lr
	ADDS	r10, r10, r11
	/* A[1] * B[6] */
	LDR	lr, [r2, #24]
	ADC	r11, r0, #0x0
	UMLAL	r10, r11, r12, lr
	ADDS	r3, r3, r11
	/* A[1] * B[7] */
	LDR	lr, [r2, #28]
	ADC	r4, r0, #0x0
	UMLAL	r3, r4, r12, lr
	/* A[2] * B[0] */
	LDR	r12, [r1, #8]
	LDR	lr, [r2]
	MOV	r11, #0x0
	UMLAL	r5, r11, r12, lr
	STR	r5, [sp, #8]
	ADDS	r6, r6, r11
	/* A[2] * B[1] */
	LDR	lr, [r2, #4]
	ADC	r11, r0, #0x0
	UMLAL	r6, r11, r12, lr
	ADDS	r7, r7, r11
	/* A[2] * B[2] */
	LDR	lr, [r2, #8]
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r12, lr
	ADDS	r8, r8, r11
	/* A[2] * B[3] */
	LDR	lr, [r2, #12]
	ADC	r11, r0, #0x0
	UMLAL	r8, r11, r12, lr
	ADDS	r9, r9, r11
	/* A[2] * B[4] */
	LDR	lr, [r2, #16]
	ADC	r11, r0, #0x0
	UMLAL	r9, r11, r12, lr
	ADDS	r10, r10, r11
	/* A[2] * B[5] */
	LDR	lr, [r2, #20]
	ADC	r11, r0, #0x0
	UMLAL	r10, r11, r12, lr
	ADDS	r3, r3, r11
	/* A[2] * B[6] */
	LDR	lr, [r2, #24]
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r12, lr
	ADDS	r4, r4, r11
	/* A[2] * B[7] */
	LDR	lr, [r2, #28]
	ADC	r5, r0, #0x0
	UMLAL	r4, r5, r12, lr
	/* A[3] * B[0] */
	LDR	r12, [r1, #12]
	LDR	lr, [r2]
	MOV	r11, #0x0
	UMLAL	r6, r11, r12, lr
	STR	r6, [sp, #12]
	ADDS	r7, r7, r11
	/* A[3] * B[1] */
	LDR	lr, [r2, #4]
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r12, lr
	ADDS	r8, r8, r11
	/* A[3] * B[2] */
	LDR	lr, [r2, #8]
	ADC	r11, r0, #0x0
	UMLAL	r8, r11, r12, lr
	ADDS	r9, r9, r11
	/* A[3] * B[3] */
	LDR	lr, [r2, #12]
	ADC	r11, r0, #0x0
	UMLAL	r9, r11, r12, lr
	ADDS	r10, r10, r11
	/* A[3] * B[4] */
	LDR	lr, [r2, #16]
	ADC	r11, r0, #0x0
	UMLAL	r10, r11, r12, lr
	ADDS	r3, r3, r11
	/* A[3] * B[5] */
	LDR	lr, [r2, #20]
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r12, lr
	ADDS	r4, r4, r11
	/* A[3] * B[6] */
	LDR	lr, [r2, #24]
	ADC	r11, r0, #0x0
	UMLAL	r4, r11, r12, lr
	ADDS	r5, r5, r11
	/* A[3] * B[7] */
	LDR	lr, [r2, #28]
	ADC	r6, r0, #0x0
	UMLAL	r5, r6, r12, lr
	/* A[4] * B[0] */
	LDR	r12, [r1, #16]
	LDR	lr, [r2]
	MOV	r11, #0x0
	UMLAL	r7, r11, r12, lr
	STR	r7, [sp, #16]
	ADDS	r8, r8, r11
	/* A[4] * B[1] */
	LDR	lr, [r2, #4]
	ADC	r11, r0, #0x0
	UMLAL	r8, r11, r12, lr
	ADDS	r9, r9, r11
	/* A[4] * B[2] */
	LDR	lr, [r2, #8]
	ADC	r11, r0, #0x0
	UMLAL	r9, r11, r12, lr
	ADDS	r10, r10, r11
	/* A[4] * B[3] */
	LDR	lr, [r2, #12]
	ADC	r11, r0, #0x0
	UMLAL	r10, r11, r12, lr
	ADDS	r3, r3, r11
	/* A[4] * B[4] */
	LDR	lr, [r2, #16]
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r12, lr
	ADDS	r4, r4, r11
	/* A[4] * B[5] */
	LDR	lr, [r2, #20]
	ADC	r11, r0, #0x0
	UMLAL	r4, r11, r12, lr
	ADDS	r5, r5, r11
	/* A[4] * B[6] */
	LDR	lr, [r2, #24]
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r12, lr
	ADDS	r6, r6, r11
	/* A[4] * B[7] */
	LDR	lr, [r2, #28]
	ADC	r7, r0, #0x0
	UMLAL	r6, r7, r12, lr
	/* A[5] * B[0] */
	LDR	r12, [r1, #20]
	LDR	lr, [r2]
	MOV	r11, #0x0
	UMLAL	r8, r11, r12, lr
	STR	r8, [sp, #20]
	ADDS	r9, r9, r11
	/* A[5] * B[1] */
	LDR	lr, [r2, #4]
	ADC	r11, r0, #0x0
	UMLAL	r9, r11, r12, lr
	ADDS	r10, r10, r11
	/* A[5] * B[2] */
	LDR	lr, [r2, #8]
	ADC	r11, r0, #0x0
	UMLAL	r10, r11, r12, lr
	ADDS	r3, r3, r11
	/* A[5] * B[3] */
	LDR	lr, [r2, #12]
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r12, lr
	ADDS	r4, r4, r11
	/* A[5] * B[4] */
	LDR	lr, [r2, #16]
	ADC	r11, r0, #0x0
	UMLAL	r4, r11, r12, lr
	ADDS	r5, r5, r11
	/* A[5] * B[5] */
	LDR	lr, [r2, #20]
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r12, lr
	ADDS	r6, r6, r11
	/* A[5] * B[6] */
	LDR	lr, [r2, #24]
	ADC	r11, r0, #0x0
	UMLAL	r6, r11, r12, lr
	ADDS	r7, r7, r11
	/* A[5] * B[7] */
	LDR	lr, [r2, #28]
	ADC	r8, r0, #0x0
	UMLAL	r7, r8, r12, lr
	/* A[6] * B[0] */
	LDR	r12, [r1, #24]
	LDR	lr, [r2]
	MOV	r11, #0x0
	UMLAL	r9, r11, r12, lr
	STR	r9, [sp, #24]
	ADDS	r10, r10, r11
	/* A[6] * B[1] */
	LDR	lr, [r2, #4]
	ADC	r11, r0, #0x0
	UMLAL	r10, r11, r12, lr
	ADDS	r3, r3, r11
	/* A[6] * B[2] */
	LDR	lr, [r2, #8]
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r12, lr
	ADDS	r4, r4, r11
	/* A[6] * B[3] */
	LDR	lr, [r2, #12]
	ADC	r11, r0, #0x0
	UMLAL	r4, r11, r12, lr
	ADDS	r5, r5, r11
	/* A[6] * B[4] */
	LDR	lr, [r2, #16]
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r12, lr
	ADDS	r6, r6, r11
	/* A[6] * B[5] */
	LDR	lr, [r2, #20]
	ADC	r11, r0, #0x0
	UMLAL	r6, r11, r12, lr
	ADDS	r7, r7, r11
	/* A[6] * B[6] */
	LDR	lr, [r2, #24]
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r12, lr
	ADDS	r8, r8, r11
	/* A[6] * B[7] */
	LDR	lr, [r2, #28]
	ADC	r9, r0, #0x0
	UMLAL	r8, r9, r12, lr
	/* A[7] * B[0] */
	LDR	r12, [r1, #28]
	LDR	lr, [r2]
	MOV	r11, #0x0
	UMLAL	r10, r11, r12, lr
	STR	r10, [sp, #28]
	ADDS	r3, r3, r11
	/* A[7] * B[1] */
	LDR	lr, [r2, #4]
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r12, lr
	ADDS	r4, r4, r11
	/* A[7] * B[2] */
	LDR	lr, [r2, #8]
	ADC	r11, r0, #0x0
	UMLAL	r4, r11, r12, lr
	ADDS	r5, r5, r11
	/* A[7] * B[3] */
	LDR	lr, [r2, #12]
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r12, lr
	ADDS	r6, r6, r11
	/* A[7] * B[4] */
	LDR	lr, [r2, #16]
	ADC	r11, r0, #0x0
	UMLAL	r6, r11, r12, lr
	ADDS	r7, r7, r11
	/* A[7] * B[5] */
	LDR	lr, [r2, #20]
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r12, lr
	ADDS	r8, r8, r11
	/* A[7] * B[6] */
	LDR	lr, [r2, #24]
	ADC	r11, r0, #0x0
	UMLAL	r8, r11, r12, lr
	ADDS	r9, r9, r11
	/* A[7] * B[7] */
	LDR	lr, [r2, #28]
	ADC	r10, r0, #0x0
	UMLAL	r9, r10, r12, lr
	/* Reduce */
	LDR	r2, [sp, #28]
	MOV	lr, sp
	MOV	r12, #0x26
	UMULL	r10, r11, r10, r12
	ADDS	r10, r10, r2
	ADC	r11, r11, #0x0
	MOV	r12, #0x13
	LSL	r11, r11, #1
	ORR	r11, r11, r10, LSR #31
	MUL	r11, r11, r12
	LDM	lr!, {r1, r2}
	MOV	r12, #0x26
	ADDS	r1, r1, r11
	ADC	r11, r0, #0x0
	UMLAL	r1, r11, r3, r12
	ADDS	r2, r2, r11
	ADC	r11, r0, #0x0
	UMLAL	r2, r11, r4, r12
	LDM	lr!, {r3, r4}
	ADDS	r3, r3, r11
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r5, r12
	ADDS	r4, r4, r11
	ADC	r11, r0, #0x0
	UMLAL	r4, r11, r6, r12
	LDM	lr!, {r5, r6}
	ADDS	r5, r5, r11
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r7, r12
	ADDS	r6, r6, r11
	ADC	r11, r0, #0x0
	UMLAL	r6, r11, r8, r12
	LDM	lr!, {r7, r8}
	ADDS	r7, r7, r11
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r9, r12
	BFC	r10, #31, #1
	ADDS	r8, r10, r11
	/* Store */
	LDR	r0, [sp, #36]
	STM	r0, {r1, r2, r3, r4, r5, r6, r7, r8}
	ADD	sp, sp, #0x28
	POP	{pc}
	/* Cycle Count = 406 */
	.size	fe_mul_op,.-fe_mul_op
#else
	.text
	.align	4
	.globl	fe_mul_op
	.type	fe_mul_op, %function
fe_mul_op:
	PUSH	{lr}
	SUB	sp, sp, #0x2c
	STRD	r0, r1, [sp, #36]
	MOV	lr, r2
	LDM	r1, {r0, r1, r2, r3}
	LDM	lr!, {r4, r5, r6}
	UMULL	r10, r11, r0, r4
	UMULL	r12, r7, r1, r4
	UMAAL	r11, r12, r0, r5
	UMULL	r8, r9, r2, r4
	UMAAL	r12, r8, r1, r5
	UMAAL	r12, r7, r0, r6
	UMAAL	r8, r9, r3, r4
	STM	sp, {r10, r11, r12}
	UMAAL	r7, r8, r2, r5
	LDM	lr!, {r4}
	UMULL	r10, r11, r1, r6
	UMAAL	r8, r9, r2, r6
	UMAAL	r7, r10, r0, r4
	UMAAL	r8, r11, r3, r5
	STR	r7, [sp, #12]
	UMAAL	r8, r10, r1, r4
	UMAAL	r9, r11, r3, r6
	UMAAL	r9, r10, r2, r4
	UMAAL	r10, r11, r3, r4
	LDM	lr, {r4, r5, r6, r7}
	MOV	r12, #0x0
	UMLAL	r8, r12, r0, r4
	UMAAL	r9, r12, r1, r4
	UMAAL	r10, r12, r2, r4
	UMAAL	r11, r12, r3, r4
	MOV	r4, #0x0
	UMLAL	r9, r4, r0, r5
	UMAAL	r10, r4, r1, r5
	UMAAL	r11, r4, r2, r5
	UMAAL	r12, r4, r3, r5
	MOV	r5, #0x0
	UMLAL	r10, r5, r0, r6
	UMAAL	r11, r5, r1, r6
	UMAAL	r12, r5, r2, r6
	UMAAL	r4, r5, r3, r6
	MOV	r6, #0x0
	UMLAL	r11, r6, r0, r7
	LDR	r0, [sp, #40]
	UMAAL	r12, r6, r1, r7
	ADD	r0, r0, #0x10
	UMAAL	r4, r6, r2, r7
	SUB	lr, lr, #0x10
	UMAAL	r5, r6, r3, r7
	LDM	r0, {r0, r1, r2, r3}
	STR	r6, [sp, #32]
	LDM	lr!, {r6}
	MOV	r7, #0x0
	UMLAL	r8, r7, r0, r6
	UMAAL	r9, r7, r1, r6
	STR	r8, [sp, #16]
	UMAAL	r10, r7, r2, r6
	UMAAL	r11, r7, r3, r6
	LDM	lr!, {r6}
	MOV	r8, #0x0
	UMLAL	r9, r8, r0, r6
	UMAAL	r10, r8, r1, r6
	STR	r9, [sp, #20]
	UMAAL	r11, r8, r2, r6
	UMAAL	r12, r8, r3, r6
	LDM	lr!, {r6}
	MOV	r9, #0x0
	UMLAL	r10, r9, r0, r6
	UMAAL	r11, r9, r1, r6
	STR	r10, [sp, #24]
	UMAAL	r12, r9, r2, r6
	UMAAL	r4, r9, r3, r6
	LDM	lr!, {r6}
	MOV	r10, #0x0
	UMLAL	r11, r10, r0, r6
	UMAAL	r12, r10, r1, r6
	STR	r11, [sp, #28]
	UMAAL	r4, r10, r2, r6
	UMAAL	r5, r10, r3, r6
	LDM	lr!, {r11}
	UMAAL	r12, r7, r0, r11
	UMAAL	r4, r7, r1, r11
	LDR	r6, [sp, #32]
	UMAAL	r5, r7, r2, r11
	UMAAL	r6, r7, r3, r11
	LDM	lr!, {r11}
	UMAAL	r4, r8, r0, r11
	UMAAL	r5, r8, r1, r11
	UMAAL	r6, r8, r2, r11
	UMAAL	r7, r8, r3, r11
	LDM	lr, {r11, lr}
	UMAAL	r5, r9, r0, r11
	UMAAL	r6, r10, r0, lr
	UMAAL	r6, r9, r1, r11
	UMAAL	r7, r10, r1, lr
	UMAAL	r7, r9, r2, r11
	UMAAL	r8, r10, r2, lr
	UMAAL	r8, r9, r3, r11
	UMAAL	r9, r10, r3, lr
	/* Reduce */
	LDR	r0, [sp, #28]
	MOV	lr, #0x25
	UMAAL	r10, r0, r10, lr
	MOV	lr, #0x13
	LSL	r0, r0, #1
	ORR	r0, r0, r10, LSR #31
	MUL	r11, r0, lr
	POP	{r0, r1, r2}
	MOV	lr, #0x26
	UMAAL	r0, r11, r12, lr
	UMAAL	r1, r11, r4, lr
	UMAAL	r2, r11, r5, lr
	POP	{r3, r4, r5}
	UMAAL	r3, r11, r6, lr
	UMAAL	r4, r11, r7, lr
	UMAAL	r5, r11, r8, lr
	POP	{r6}
	BFC	r10, #31, #1
	UMAAL	r6, r11, r9, lr
	ADD	r7, r10, r11
	LDR	lr, [sp, #8]
	/* Store */
	STM	lr, {r0, r1, r2, r3, r4, r5, r6, r7}
	ADD	sp, sp, #0x10
	POP	{pc}
	/* Cycle Count = 239 */
	.size	fe_mul_op,.-fe_mul_op
#endif /* WOLFSSL_ARM_ARCH_7M */
	.text
	.align	4
	.globl	fe_mul
	.type	fe_mul, %function
fe_mul:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	BL	fe_mul_op
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 24 */
	.size	fe_mul,.-fe_mul
#ifdef WOLFSSL_ARM_ARCH_7M
	.text
	.align	4
	.globl	fe_sq_op
	.type	fe_sq_op, %function
fe_sq_op:
	PUSH	{lr}
	SUB	sp, sp, #0x44
	STR	r0, [sp, #64]
	/* Square */
	MOV	r0, #0x0
	LDR	r12, [r1]
	/* A[0] * A[1] */
	LDR	lr, [r1, #4]
	UMULL	r4, r5, r12, lr
	/* A[0] * A[3] */
	LDR	lr, [r1, #12]
	UMULL	r6, r7, r12, lr
	/* A[0] * A[5] */
	LDR	lr, [r1, #20]
	UMULL	r8, r9, r12, lr
	/* A[0] * A[7] */
	LDR	lr, [r1, #28]
	UMULL	r10, r3, r12, lr
	/* A[0] * A[2] */
	LDR	lr, [r1, #8]
	MOV	r11, #0x0
	UMLAL	r5, r11, r12, lr
	ADDS	r6, r6, r11
	/* A[0] * A[4] */
	LDR	lr, [r1, #16]
	ADCS	r7, r7, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r12, lr
	ADDS	r8, r8, r11
	/* A[0] * A[6] */
	LDR	lr, [r1, #24]
	ADCS	r9, r9, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r9, r11, r12, lr
	ADDS	r10, r10, r11
	ADCS	r3, r3, #0x0
	STR	r4, [sp, #4]
	STR	r5, [sp, #8]
	/* A[1] * A[2] */
	LDR	r12, [r1, #4]
	LDR	lr, [r1, #8]
	MOV	r11, #0x0
	UMLAL	r6, r11, r12, lr
	STR	r6, [sp, #12]
	ADDS	r7, r7, r11
	/* A[1] * A[3] */
	LDR	lr, [r1, #12]
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r12, lr
	STR	r7, [sp, #16]
	ADDS	r8, r8, r11
	/* A[1] * A[4] */
	LDR	lr, [r1, #16]
	ADC	r11, r0, #0x0
	UMLAL	r8, r11, r12, lr
	ADDS	r9, r9, r11
	/* A[1] * A[5] */
	LDR	lr, [r1, #20]
	ADC	r11, r0, #0x0
	UMLAL	r9, r11, r12, lr
	ADDS	r10, r10, r11
	/* A[1] * A[6] */
	LDR	lr, [r1, #24]
	ADC	r11, r0, #0x0
	UMLAL	r10, r11, r12, lr
	ADDS	r3, r3, r11
	/* A[1] * A[7] */
	LDR	lr, [r1, #28]
	ADC	r4, r0, #0x0
	UMLAL	r3, r4, r12, lr
	/* A[2] * A[3] */
	LDR	r12, [r1, #8]
	LDR	lr, [r1, #12]
	MOV	r11, #0x0
	UMLAL	r8, r11, r12, lr
	STR	r8, [sp, #20]
	ADDS	r9, r9, r11
	/* A[2] * A[4] */
	LDR	lr, [r1, #16]
	ADC	r11, r0, #0x0
	UMLAL	r9, r11, r12, lr
	STR	r9, [sp, #24]
	ADDS	r10, r10, r11
	/* A[2] * A[5] */
	LDR	lr, [r1, #20]
	ADC	r11, r0, #0x0
	UMLAL	r10, r11, r12, lr
	ADDS	r3, r3, r11
	/* A[2] * A[6] */
	LDR	lr, [r1, #24]
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r12, lr
	ADDS	r4, r4, r11
	/* A[2] * A[7] */
	LDR	lr, [r1, #28]
	ADC	r5, r0, #0x0
	UMLAL	r4, r5, r12, lr
	/* A[3] * A[4] */
	LDR	r12, [r1, #12]
	LDR	lr, [r1, #16]
	MOV	r11, #0x0
	UMLAL	r10, r11, r12, lr
	STR	r10, [sp, #28]
	ADDS	r3, r3, r11
	/* A[3] * A[5] */
	LDR	lr, [r1, #20]
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r12, lr
	ADDS	r4, r4, r11
	/* A[3] * A[6] */
	LDR	lr, [r1, #24]
	ADC	r11, r0, #0x0
	UMLAL	r4, r11, r12, lr
	ADDS	r5, r5, r11
	/* A[3] * A[7] */
	LDR	lr, [r1, #28]
	ADC	r6, r0, #0x0
	UMLAL	r5, r6, r12, lr
	/* A[4] * A[5] */
	LDR	r12, [r1, #16]
	LDR	lr, [r1, #20]
	MOV	r11, #0x0
	UMLAL	r4, r11, r12, lr
	ADDS	r5, r5, r11
	/* A[4] * A[6] */
	LDR	lr, [r1, #24]
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r12, lr
	ADDS	r6, r6, r11
	/* A[4] * A[7] */
	LDR	lr, [r1, #28]
	ADC	r7, r0, #0x0
	UMLAL	r6, r7, r12, lr
	/* A[5] * A[6] */
	LDR	r12, [r1, #20]
	LDR	lr, [r1, #24]
	MOV	r11, #0x0
	UMLAL	r6, r11, r12, lr
	ADDS	r7, r7, r11
	/* A[5] * A[7] */
	LDR	lr, [r1, #28]
	ADC	r8, r0, #0x0
	UMLAL	r7, r8, r12, lr
	/* A[6] * A[7] */
	LDR	r12, [r1, #24]
	LDR	lr, [r1, #28]
	MOV	r9, #0x0
	UMLAL	r8, r9, r12, lr
	ADD	lr, sp, #0x20
	STM	lr, {r3, r4, r5, r6, r7, r8, r9}
	ADD	lr, sp, #0x4
	LDM	lr, {r4, r5, r6, r7, r8, r9, r10}
	ADDS	r4, r4, r4
	ADCS	r5, r5, r5
	ADCS	r6, r6, r6
	ADCS	r7, r7, r7
	ADCS	r8, r8, r8
	ADCS	r9, r9, r9
	ADCS	r10, r10, r10
	STM	lr!, {r4, r5, r6, r7, r8, r9, r10}
	LDM	lr, {r3, r4, r5, r6, r7, r8, r9}
	ADCS	r3, r3, r3
	ADCS	r4, r4, r4
	ADCS	r5, r5, r5
	ADCS	r6, r6, r6
	ADCS	r7, r7, r7
	ADCS	r8, r8, r8
	ADCS	r9, r9, r9
	ADC	r10, r0, #0x0
	STM	lr, {r3, r4, r5, r6, r7, r8, r9, r10}
	ADD	lr, sp, #0x4
	LDM	lr, {r4, r5, r6, r7, r8, r9, r10}
	MOV	lr, sp
	/* A[0] * A[0] */
	LDR	r12, [r1]
	UMULL	r3, r11, r12, r12
	ADDS	r4, r4, r11
	/* A[1] * A[1] */
	LDR	r12, [r1, #4]
	ADCS	r5, r5, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r12, r12
	ADDS	r6, r6, r11
	/* A[2] * A[2] */
	LDR	r12, [r1, #8]
	ADCS	r7, r7, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r12, r12
	ADDS	r8, r8, r11
	/* A[3] * A[3] */
	LDR	r12, [r1, #12]
	ADCS	r9, r9, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r9, r11, r12, r12
	ADDS	r10, r10, r11
	STM	lr!, {r3, r4, r5, r6, r7, r8, r9, r10}
	LDM	lr, {r3, r4, r5, r6, r7, r8, r9, r10}
	/* A[4] * A[4] */
	LDR	r12, [r1, #16]
	ADCS	r3, r3, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r12, r12
	ADDS	r4, r4, r11
	/* A[5] * A[5] */
	LDR	r12, [r1, #20]
	ADCS	r5, r5, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r12, r12
	ADDS	r6, r6, r11
	/* A[6] * A[6] */
	LDR	r12, [r1, #24]
	ADCS	r7, r7, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r12, r12
	ADDS	r8, r8, r11
	/* A[7] * A[7] */
	LDR	r12, [r1, #28]
	ADCS	r9, r9, #0x0
	ADC	r10, r10, #0x0
	UMLAL	r9, r10, r12, r12
	/* Reduce */
	LDR	r2, [sp, #28]
	MOV	lr, sp
	MOV	r12, #0x26
	UMULL	r10, r11, r10, r12
	ADDS	r10, r10, r2
	ADC	r11, r11, #0x0
	MOV	r12, #0x13
	LSL	r11, r11, #1
	ORR	r11, r11, r10, LSR #31
	MUL	r11, r11, r12
	LDM	lr!, {r1, r2}
	MOV	r12, #0x26
	ADDS	r1, r1, r11
	ADC	r11, r0, #0x0
	UMLAL	r1, r11, r3, r12
	ADDS	r2, r2, r11
	ADC	r11, r0, #0x0
	UMLAL	r2, r11, r4, r12
	LDM	lr!, {r3, r4}
	ADDS	r3, r3, r11
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r5, r12
	ADDS	r4, r4, r11
	ADC	r11, r0, #0x0
	UMLAL	r4, r11, r6, r12
	LDM	lr!, {r5, r6}
	ADDS	r5, r5, r11
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r7, r12
	ADDS	r6, r6, r11
	ADC	r11, r0, #0x0
	UMLAL	r6, r11, r8, r12
	LDM	lr!, {r7, r8}
	ADDS	r7, r7, r11
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r9, r12
	BFC	r10, #31, #1
	ADDS	r8, r10, r11
	/* Store */
	LDR	r0, [sp, #64]
	STM	r0, {r1, r2, r3, r4, r5, r6, r7, r8}
	ADD	sp, sp, #0x44
	POP	{pc}
	/* Cycle Count = 355 */
	.size	fe_sq_op,.-fe_sq_op
#else
	.text
	.align	4
	.globl	fe_sq_op
	.type	fe_sq_op, %function
fe_sq_op:
	PUSH	{lr}
	SUB	sp, sp, #0x20
	STR	r0, [sp, #28]
	LDM	r1, {r0, r1, r2, r3, r4, r5, r6, r7}
	/* Square */
	UMULL	r9, r10, r0, r0
	UMULL	r11, r12, r0, r1
	ADDS	r11, r11, r11
	MOV	lr, #0x0
	UMAAL	r10, r11, lr, lr
	STM	sp, {r9, r10}
	MOV	r8, lr
	UMAAL	r8, r12, r0, r2
	ADCS	r8, r8, r8
	UMAAL	r8, r11, r1, r1
	UMULL	r9, r10, r0, r3
	UMAAL	r9, r12, r1, r2
	ADCS	r9, r9, r9
	UMAAL	r9, r11, lr, lr
	STRD	r8, r9, [sp, #8]
	MOV	r9, lr
	UMAAL	r9, r10, r0, r4
	UMAAL	r9, r12, r1, r3
	ADCS	r9, r9, r9
	UMAAL	r9, r11, r2, r2
	STR	r9, [sp, #16]
	UMULL	r9, r8, r0, r5
	UMAAL	r9, r12, r1, r4
	UMAAL	r9, r10, r2, r3
	ADCS	r9, r9, r9
	UMAAL	r9, r11, lr, lr
	STR	r9, [sp, #20]
	MOV	r9, lr
	UMAAL	r9, r8, r0, r6
	UMAAL	r9, r12, r1, r5
	UMAAL	r9, r10, r2, r4
	ADCS	r9, r9, r9
	UMAAL	r9, r11, r3, r3
	STR	r9, [sp, #24]
	UMULL	r0, r9, r0, r7
	UMAAL	r0, r8, r1, r6
	UMAAL	r0, r12, r2, r5
	UMAAL	r0, r10, r3, r4
	ADCS	r0, r0, r0
	UMAAL	r0, r11, lr, lr
	/* R[7] = r0 */
	UMAAL	r9, r8, r1, r7
	UMAAL	r9, r10, r2, r6
	UMAAL	r12, r9, r3, r5
	ADCS	r12, r12, r12
	UMAAL	r12, r11, r4, r4
	/* R[8] = r12 */
	UMAAL	r9, r8, r2, r7
	UMAAL	r10, r9, r3, r6
	MOV	r2, lr
	UMAAL	r10, r2, r4, r5
	ADCS	r10, r10, r10
	UMAAL	r11, r10, lr, lr
	/* R[9] = r11 */
	UMAAL	r2, r8, r3, r7
	UMAAL	r2, r9, r4, r6
	ADCS	r3, r2, r2
	UMAAL	r10, r3, r5, r5
	/* R[10] = r10 */
	MOV	r1, lr
	UMAAL	r1, r8, r4, r7
	UMAAL	r1, r9, r5, r6
	ADCS	r4, r1, r1
	UMAAL	r3, r4, lr, lr
	/* R[11] = r3 */
	UMAAL	r8, r9, r5, r7
	ADCS	r8, r8, r8
	UMAAL	r4, r8, r6, r6
	/* R[12] = r4 */
	MOV	r5, lr
	UMAAL	r5, r9, r6, r7
	ADCS	r5, r5, r5
	UMAAL	r8, r5, lr, lr
	/* R[13] = r8 */
	ADCS	r9, r9, r9
	UMAAL	r9, r5, r7, r7
	ADCS	r7, r5, lr
	/* R[14] = r9 */
	/* R[15] = r7 */
	/* Reduce */
	MOV	r6, #0x25
	UMAAL	r7, r0, r7, r6
	MOV	r6, #0x13
	LSL	r0, r0, #1
	ORR	r0, r0, r7, LSR #31
	MUL	lr, r0, r6
	POP	{r0, r1}
	MOV	r6, #0x26
	UMAAL	r0, lr, r12, r6
	UMAAL	r1, lr, r11, r6
	MOV	r12, r3
	MOV	r11, r4
	POP	{r2, r3, r4}
	UMAAL	r2, lr, r10, r6
	UMAAL	r3, lr, r12, r6
	UMAAL	r4, lr, r11, r6
	MOV	r12, r6
	POP	{r5, r6}
	UMAAL	r5, lr, r8, r12
	BFC	r7, #31, #1
	UMAAL	r6, lr, r9, r12
	ADD	r7, r7, lr
	POP	{lr}
	/* Store */
	STM	lr, {r0, r1, r2, r3, r4, r5, r6, r7}
	POP	{pc}
	/* Cycle Count = 179 */
	.size	fe_sq_op,.-fe_sq_op
#endif /* WOLFSSL_ARM_ARCH_7M */
	.text
	.align	4
	.globl	fe_sq
	.type	fe_sq, %function
fe_sq:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	BL	fe_sq_op
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 24 */
	.size	fe_sq,.-fe_sq
#ifdef HAVE_CURVE25519
#ifdef WOLFSSL_ARM_ARCH_7M
	.text
	.align	4
	.globl	fe_mul121666
	.type	fe_mul121666, %function
fe_mul121666:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	/* Multiply by 121666 */
	LDM	r1, {r2, r3, r4, r5, r6, r7, r8, r9}
	MOV	r12, #0xdb42
	MOVT	r12, #0x1
	UMULL	r2, r10, r2, r12
	UMULL	r3, r11, r3, r12
	ADDS	r3, r3, r10
	ADC	r11, r11, #0x0
	UMULL	r4, r10, r4, r12
	ADDS	r4, r4, r11
	ADC	r10, r10, #0x0
	UMULL	r5, r11, r5, r12
	ADDS	r5, r5, r10
	ADC	r11, r11, #0x0
	UMULL	r6, r10, r6, r12
	ADDS	r6, r6, r11
	ADC	r10, r10, #0x0
	UMULL	r7, r11, r7, r12
	ADDS	r7, r7, r10
	ADC	r11, r11, #0x0
	UMULL	r8, r10, r8, r12
	ADDS	r8, r8, r11
	ADC	r10, r10, #0x0
	UMULL	r9, r11, r9, r12
	ADDS	r9, r9, r10
	MOV	r12, #0x13
	ADC	r11, r11, #0x0
	LSL	r11, r11, #1
	ORR	r11, r11, r9, LSR #31
	MUL	r11, r11, r12
	ADDS	r2, r2, r11
	ADCS	r3, r3, #0x0
	ADCS	r4, r4, #0x0
	ADCS	r5, r5, #0x0
	ADCS	r6, r6, #0x0
	ADCS	r7, r7, #0x0
	BFC	r9, #31, #1
	ADCS	r8, r8, #0x0
	ADC	r9, r9, #0x0
	STM	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 75 */
	.size	fe_mul121666,.-fe_mul121666
#else
	.text
	.align	4
	.globl	fe_mul121666
	.type	fe_mul121666, %function
fe_mul121666:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	/* Multiply by 121666 */
	LDM	r1, {r2, r3, r4, r5, r6, r7, r8, r9}
	MOV	r11, #0xdb42
	MOVT	r11, #0x1
	UMULL	r2, r12, r2, r11
	SUB	r10, r11, #0x1
	UMAAL	r3, r12, r3, r10
	UMAAL	r4, r12, r4, r10
	UMAAL	r5, r12, r5, r10
	UMAAL	r6, r12, r6, r10
	UMAAL	r7, r12, r7, r10
	UMAAL	r8, r12, r8, r10
	MOV	r11, #0x13
	UMAAL	r9, r12, r9, r10
	LSL	r12, r12, #1
	ORR	r12, r12, r9, LSR #31
	MUL	r12, r12, r11
	ADDS	r2, r2, r12
	ADCS	r3, r3, #0x0
	ADCS	r4, r4, #0x0
	ADCS	r5, r5, #0x0
	ADCS	r6, r6, #0x0
	ADCS	r7, r7, #0x0
	BFC	r9, #31, #1
	ADCS	r8, r8, #0x0
	ADC	r9, r9, #0x0
	STM	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 69 */
	.size	fe_mul121666,.-fe_mul121666
#endif /* WOLFSSL_ARM_ARCH_7M */
#ifndef WC_NO_CACHE_RESISTANT
	.text
	.align	4
	.globl	curve25519
	.type	curve25519, %function
curve25519:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0xbc
	STR	r0, [sp, #160]
	STR	r1, [sp, #164]
	STR	r2, [sp, #168]
	MOV	r1, #0x0
	STR	r1, [sp, #172]
	MOV	r4, #0x1
	MOV	r5, #0x0
	MOV	r6, #0x0
	MOV	r7, #0x0
	MOV	r8, #0x0
	MOV	r9, #0x0
	MOV	r10, #0x0
	MOV	r11, #0x0
	STM	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	ADD	r3, sp, #0x20
	STM	r3, {r4, r5, r6, r7, r8, r9, r10, r11}
	MOV	r4, #0x0
	MOV	r3, sp
	STM	r3, {r4, r5, r6, r7, r8, r9, r10, r11}
	ADD	r3, sp, #0x40
	/* Copy */
	LDM	r2, {r4, r5, r6, r7, r8, r9, r10, r11}
	STM	r3, {r4, r5, r6, r7, r8, r9, r10, r11}
	MOV	r1, #0x1e
	STR	r1, [sp, #180]
	MOV	r2, #0x1c
	STR	r2, [sp, #176]
L_curve25519_words:
L_curve25519_bits:
	LDR	r1, [sp, #164]
	LDR	r2, [r1, r2]
	LDR	r1, [sp, #180]
	LSR	r2, r2, r1
	AND	r2, r2, #0x1
	STR	r2, [sp, #184]
	LDR	r1, [sp, #172]
	EOR	r1, r1, r2
	STR	r1, [sp, #172]
	LDR	r0, [sp, #160]
	/* Conditional Swap */
	RSB	r1, r1, #0x0
	MOV	r3, r0
	ADD	r12, sp, #0x40
	LDM	r3, {r4, r5}
	LDM	r12, {r6, r7}
	EOR	r8, r4, r6
	EOR	r9, r5, r7
	AND	r8, r8, r1
	AND	r9, r9, r1
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	STM	r3!, {r4, r5}
	STM	r12!, {r6, r7}
	LDM	r3, {r4, r5}
	LDM	r12, {r6, r7}
	EOR	r8, r4, r6
	EOR	r9, r5, r7
	AND	r8, r8, r1
	AND	r9, r9, r1
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	STM	r3!, {r4, r5}
	STM	r12!, {r6, r7}
	LDM	r3, {r4, r5}
	LDM	r12, {r6, r7}
	EOR	r8, r4, r6
	EOR	r9, r5, r7
	AND	r8, r8, r1
	AND	r9, r9, r1
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	STM	r3!, {r4, r5}
	STM	r12!, {r6, r7}
	LDM	r3, {r4, r5}
	LDM	r12, {r6, r7}
	EOR	r8, r4, r6
	EOR	r9, r5, r7
	AND	r8, r8, r1
	AND	r9, r9, r1
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	STM	r3!, {r4, r5}
	STM	r12!, {r6, r7}
	LDR	r1, [sp, #172]
	/* Conditional Swap */
	RSB	r1, r1, #0x0
	MOV	r3, sp
	ADD	r12, sp, #0x20
	LDM	r3, {r4, r5}
	LDM	r12, {r6, r7}
	EOR	r8, r4, r6
	EOR	r9, r5, r7
	AND	r8, r8, r1
	AND	r9, r9, r1
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	STM	r3!, {r4, r5}
	STM	r12!, {r6, r7}
	LDM	r3, {r4, r5}
	LDM	r12, {r6, r7}
	EOR	r8, r4, r6
	EOR	r9, r5, r7
	AND	r8, r8, r1
	AND	r9, r9, r1
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	STM	r3!, {r4, r5}
	STM	r12!, {r6, r7}
	LDM	r3, {r4, r5}
	LDM	r12, {r6, r7}
	EOR	r8, r4, r6
	EOR	r9, r5, r7
	AND	r8, r8, r1
	AND	r9, r9, r1
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	STM	r3!, {r4, r5}
	STM	r12!, {r6, r7}
	LDM	r3, {r4, r5}
	LDM	r12, {r6, r7}
	EOR	r8, r4, r6
	EOR	r9, r5, r7
	AND	r8, r8, r1
	AND	r9, r9, r1
	EOR	r4, r4, r8
	EOR	r5, r5, r9
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	STM	r3!, {r4, r5}
	STM	r12!, {r6, r7}
	LDR	r1, [sp, #184]
	STR	r1, [sp, #172]
	MOV	r3, sp
	LDR	r2, [sp, #160]
	ADD	r1, sp, #0x80
	LDR	r0, [sp, #160]
	BL	fe_add_sub_op
	ADD	r3, sp, #0x20
	ADD	r2, sp, #0x40
	ADD	r1, sp, #0x60
	MOV	r0, sp
	BL	fe_add_sub_op
	LDR	r2, [sp, #160]
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x20
	BL	fe_mul_op
	ADD	r2, sp, #0x80
	MOV	r1, sp
	MOV	r0, sp
	BL	fe_mul_op
	ADD	r1, sp, #0x80
	ADD	r0, sp, #0x80
	BL	fe_sq_op
	LDR	r1, [sp, #160]
	ADD	r0, sp, #0x60
	BL	fe_sq_op
	MOV	r3, sp
	ADD	r2, sp, #0x20
	MOV	r1, sp
	ADD	r0, sp, #0x40
	BL	fe_add_sub_op
	ADD	r2, sp, #0x80
	ADD	r1, sp, #0x60
	LDR	r0, [sp, #160]
	BL	fe_mul_op
	ADD	r2, sp, #0x80
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x60
	BL	fe_sub_op
	MOV	r1, sp
	MOV	r0, sp
	BL	fe_sq_op
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x20
	BL	fe_mul121666
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x40
	BL	fe_sq_op
	ADD	r2, sp, #0x20
	ADD	r1, sp, #0x80
	ADD	r0, sp, #0x80
	BL	fe_add_op
	MOV	r2, sp
	LDR	r1, [sp, #168]
	ADD	r0, sp, #0x20
	BL	fe_mul_op
	ADD	r2, sp, #0x80
	ADD	r1, sp, #0x60
	MOV	r0, sp
	BL	fe_mul_op
	LDR	r2, [sp, #176]
	LDR	r1, [sp, #180]
	SUBS	r1, r1, #0x1
	STR	r1, [sp, #180]
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_curve25519_bits
#else
	BGE.W	L_curve25519_bits
#endif
	MOV	r1, #0x1f
	STR	r1, [sp, #180]
	SUBS	r2, r2, #0x4
	STR	r2, [sp, #176]
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_curve25519_words
#else
	BGE.W	L_curve25519_words
#endif
	/* Invert */
	ADD	r1, sp, #0x0
	ADD	r0, sp, #0x20
	BL	fe_sq_op
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x40
	BL	fe_sq_op
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x40
	BL	fe_sq_op
	ADD	r2, sp, #0x40
	ADD	r1, sp, #0x0
	ADD	r0, sp, #0x40
	BL	fe_mul_op
	ADD	r2, sp, #0x40
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x20
	BL	fe_mul_op
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x60
	BL	fe_sq_op
	ADD	r2, sp, #0x60
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x40
	BL	fe_mul_op
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x60
	BL	fe_sq_op
	MOV	r12, #0x4
L_curve25519_inv_1:
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x60
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_curve25519_inv_1
#else
	BNE.N	L_curve25519_inv_1
#endif
	ADD	r2, sp, #0x40
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x40
	BL	fe_mul_op
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x60
	BL	fe_sq_op
	MOV	r12, #0x9
L_curve25519_inv_2:
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x60
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_curve25519_inv_2
#else
	BNE.N	L_curve25519_inv_2
#endif
	ADD	r2, sp, #0x40
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x60
	BL	fe_mul_op
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x80
	BL	fe_sq_op
	MOV	r12, #0x13
L_curve25519_inv_3:
	ADD	r1, sp, #0x80
	ADD	r0, sp, #0x80
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_curve25519_inv_3
#else
	BNE.N	L_curve25519_inv_3
#endif
	ADD	r2, sp, #0x60
	ADD	r1, sp, #0x80
	ADD	r0, sp, #0x60
	BL	fe_mul_op
	MOV	r12, #0xa
L_curve25519_inv_4:
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x60
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_curve25519_inv_4
#else
	BNE.N	L_curve25519_inv_4
#endif
	ADD	r2, sp, #0x40
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x40
	BL	fe_mul_op
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x60
	BL	fe_sq_op
	MOV	r12, #0x31
L_curve25519_inv_5:
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x60
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_curve25519_inv_5
#else
	BNE.N	L_curve25519_inv_5
#endif
	ADD	r2, sp, #0x40
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x60
	BL	fe_mul_op
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x80
	BL	fe_sq_op
	MOV	r12, #0x63
L_curve25519_inv_6:
	ADD	r1, sp, #0x80
	ADD	r0, sp, #0x80
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_curve25519_inv_6
#else
	BNE.N	L_curve25519_inv_6
#endif
	ADD	r2, sp, #0x60
	ADD	r1, sp, #0x80
	ADD	r0, sp, #0x60
	BL	fe_mul_op
	MOV	r12, #0x32
L_curve25519_inv_7:
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x60
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_curve25519_inv_7
#else
	BNE.N	L_curve25519_inv_7
#endif
	ADD	r2, sp, #0x40
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x40
	BL	fe_mul_op
	MOV	r12, #0x5
L_curve25519_inv_8:
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x40
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_curve25519_inv_8
#else
	BNE.N	L_curve25519_inv_8
#endif
	ADD	r2, sp, #0x20
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x0
	BL	fe_mul_op
	MOV	r2, sp
	LDR	r1, [sp, #160]
	LDR	r0, [sp, #160]
	BL	fe_mul_op
	MOV	r0, #0x0
	ADD	sp, sp, #0xbc
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 682 */
	.size	curve25519,.-curve25519
#else
	.text
	.align	4
	.globl	curve25519
	.type	curve25519, %function
curve25519:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0xc0
	STR	r0, [sp, #176]
	STR	r1, [sp, #160]
	STR	r2, [sp, #172]
	ADD	r5, sp, #0x40
	ADD	r4, sp, #0x20
	STR	sp, [sp, #184]
	STR	r5, [sp, #180]
	STR	r4, [sp, #188]
	MOV	r1, #0x0
	STR	r1, [sp, #164]
	MOV	r4, #0x1
	MOV	r5, #0x0
	MOV	r6, #0x0
	MOV	r7, #0x0
	MOV	r8, #0x0
	MOV	r9, #0x0
	MOV	r10, #0x0
	MOV	r11, #0x0
	STM	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	ADD	r3, sp, #0x20
	STM	r3, {r4, r5, r6, r7, r8, r9, r10, r11}
	MOV	r4, #0x0
	MOV	r3, sp
	STM	r3, {r4, r5, r6, r7, r8, r9, r10, r11}
	ADD	r3, sp, #0x40
	/* Copy */
	LDM	r2, {r4, r5, r6, r7, r8, r9, r10, r11}
	STM	r3, {r4, r5, r6, r7, r8, r9, r10, r11}
	MOV	r2, #0xfe
L_curve25519_bits:
	STR	r2, [sp, #168]
	LDR	r1, [sp, #160]
	AND	r4, r2, #0x1f
	LSR	r2, r2, #5
	LDR	r2, [r1, r2, LSL #2]
	RSB	r4, r4, #0x1f
	LSL	r2, r2, r4
	LDR	r1, [sp, #164]
	EOR	r1, r1, r2
	ASR	r1, r1, #31
	STR	r2, [sp, #164]
	/* Conditional Swap */
	ADD	r11, sp, #0xb0
	LDM	r11, {r4, r5, r6, r7}
	EOR	r8, r4, r5
	EOR	r9, r6, r7
	AND	r8, r8, r1
	AND	r9, r9, r1
	EOR	r4, r4, r8
	EOR	r5, r5, r8
	EOR	r6, r6, r9
	EOR	r7, r7, r9
	STM	r11, {r4, r5, r6, r7}
	/* Ladder step */
	LDR	r3, [sp, #184]
	LDR	r2, [sp, #176]
	ADD	r1, sp, #0x80
	LDR	r0, [sp, #176]
	BL	fe_add_sub_op
	LDR	r3, [sp, #188]
	LDR	r2, [sp, #180]
	ADD	r1, sp, #0x60
	LDR	r0, [sp, #184]
	BL	fe_add_sub_op
	LDR	r2, [sp, #176]
	ADD	r1, sp, #0x60
	LDR	r0, [sp, #188]
	BL	fe_mul_op
	ADD	r2, sp, #0x80
	LDR	r1, [sp, #184]
	LDR	r0, [sp, #184]
	BL	fe_mul_op
	ADD	r1, sp, #0x80
	ADD	r0, sp, #0x60
	BL	fe_sq_op
	LDR	r1, [sp, #176]
	ADD	r0, sp, #0x80
	BL	fe_sq_op
	LDR	r3, [sp, #184]
	LDR	r2, [sp, #188]
	LDR	r1, [sp, #184]
	LDR	r0, [sp, #180]
	BL	fe_add_sub_op
	ADD	r2, sp, #0x60
	ADD	r1, sp, #0x80
	LDR	r0, [sp, #176]
	BL	fe_mul_op
	ADD	r2, sp, #0x60
	ADD	r1, sp, #0x80
	ADD	r0, sp, #0x80
	BL	fe_sub_op
	LDR	r1, [sp, #184]
	LDR	r0, [sp, #184]
	BL	fe_sq_op
	ADD	r1, sp, #0x80
	LDR	r0, [sp, #188]
	BL	fe_mul121666
	LDR	r1, [sp, #180]
	LDR	r0, [sp, #180]
	BL	fe_sq_op
	LDR	r2, [sp, #188]
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x60
	BL	fe_add_op
	LDR	r2, [sp, #184]
	LDR	r1, [sp, #172]
	LDR	r0, [sp, #188]
	BL	fe_mul_op
	ADD	r2, sp, #0x60
	ADD	r1, sp, #0x80
	LDR	r0, [sp, #184]
	BL	fe_mul_op
	LDR	r2, [sp, #168]
	SUBS	r2, r2, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BGE	L_curve25519_bits
#else
	BGE.N	L_curve25519_bits
#endif
	/*   Cycle Count: 171 */
	LDR	r1, [sp, #184]
	/* Copy */
	LDM	r1, {r4, r5, r6, r7, r8, r9, r10, r11}
	STM	sp, {r4, r5, r6, r7, r8, r9, r10, r11}
	/* Invert */
	ADD	r1, sp, #0x0
	ADD	r0, sp, #0x20
	BL	fe_sq_op
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x40
	BL	fe_sq_op
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x40
	BL	fe_sq_op
	ADD	r2, sp, #0x40
	ADD	r1, sp, #0x0
	ADD	r0, sp, #0x40
	BL	fe_mul_op
	ADD	r2, sp, #0x40
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x20
	BL	fe_mul_op
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x60
	BL	fe_sq_op
	ADD	r2, sp, #0x60
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x40
	BL	fe_mul_op
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x60
	BL	fe_sq_op
	MOV	r12, #0x4
L_curve25519_inv_1:
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x60
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_curve25519_inv_1
#else
	BNE.N	L_curve25519_inv_1
#endif
	ADD	r2, sp, #0x40
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x40
	BL	fe_mul_op
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x60
	BL	fe_sq_op
	MOV	r12, #0x9
L_curve25519_inv_2:
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x60
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_curve25519_inv_2
#else
	BNE.N	L_curve25519_inv_2
#endif
	ADD	r2, sp, #0x40
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x60
	BL	fe_mul_op
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x80
	BL	fe_sq_op
	MOV	r12, #0x13
L_curve25519_inv_3:
	ADD	r1, sp, #0x80
	ADD	r0, sp, #0x80
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_curve25519_inv_3
#else
	BNE.N	L_curve25519_inv_3
#endif
	ADD	r2, sp, #0x60
	ADD	r1, sp, #0x80
	ADD	r0, sp, #0x60
	BL	fe_mul_op
	MOV	r12, #0xa
L_curve25519_inv_4:
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x60
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_curve25519_inv_4
#else
	BNE.N	L_curve25519_inv_4
#endif
	ADD	r2, sp, #0x40
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x40
	BL	fe_mul_op
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x60
	BL	fe_sq_op
	MOV	r12, #0x31
L_curve25519_inv_5:
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x60
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_curve25519_inv_5
#else
	BNE.N	L_curve25519_inv_5
#endif
	ADD	r2, sp, #0x40
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x60
	BL	fe_mul_op
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x80
	BL	fe_sq_op
	MOV	r12, #0x63
L_curve25519_inv_6:
	ADD	r1, sp, #0x80
	ADD	r0, sp, #0x80
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_curve25519_inv_6
#else
	BNE.N	L_curve25519_inv_6
#endif
	ADD	r2, sp, #0x60
	ADD	r1, sp, #0x80
	ADD	r0, sp, #0x60
	BL	fe_mul_op
	MOV	r12, #0x32
L_curve25519_inv_7:
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x60
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_curve25519_inv_7
#else
	BNE.N	L_curve25519_inv_7
#endif
	ADD	r2, sp, #0x40
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x40
	BL	fe_mul_op
	MOV	r12, #0x5
L_curve25519_inv_8:
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x40
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_curve25519_inv_8
#else
	BNE.N	L_curve25519_inv_8
#endif
	ADD	r2, sp, #0x20
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x0
	BL	fe_mul_op
	LDR	r2, [sp, #184]
	LDR	r1, [sp, #176]
	LDR	r0, [sp, #176]
	BL	fe_mul_op
	/* Ensure result is less than modulus */
	LDR	r0, [sp, #176]
	LDM	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	MOV	r2, #0x13
	AND	r2, r2, r11, ASR #31
	ADDS	r4, r4, r2
	ADCS	r5, r5, #0x0
	ADCS	r6, r6, #0x0
	ADCS	r7, r7, #0x0
	ADCS	r8, r8, #0x0
	ADCS	r9, r9, #0x0
	BFC	r11, #31, #1
	ADCS	r10, r10, #0x0
	ADC	r11, r11, #0x0
	STM	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	MOV	r0, #0x0
	ADD	sp, sp, #0xc0
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 589 */
	.size	curve25519,.-curve25519
#endif /* WC_NO_CACHE_RESISTANT */
#endif /* HAVE_CURVE25519 */
#ifdef HAVE_ED25519
	.text
	.align	4
	.globl	fe_invert
	.type	fe_invert, %function
fe_invert:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0x88
	/* Invert */
	STR	r0, [sp, #128]
	STR	r1, [sp, #132]
	LDR	r1, [sp, #132]
	MOV	r0, sp
	BL	fe_sq_op
	MOV	r1, sp
	ADD	r0, sp, #0x20
	BL	fe_sq_op
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x20
	BL	fe_sq_op
	ADD	r2, sp, #0x20
	LDR	r1, [sp, #132]
	ADD	r0, sp, #0x20
	BL	fe_mul_op
	ADD	r2, sp, #0x20
	MOV	r1, sp
	MOV	r0, sp
	BL	fe_mul_op
	MOV	r1, sp
	ADD	r0, sp, #0x40
	BL	fe_sq_op
	ADD	r2, sp, #0x40
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x20
	BL	fe_mul_op
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x40
	BL	fe_sq_op
	MOV	r12, #0x4
L_fe_invert1:
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x40
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_fe_invert1
#else
	BNE.N	L_fe_invert1
#endif
	ADD	r2, sp, #0x20
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x20
	BL	fe_mul_op
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x40
	BL	fe_sq_op
	MOV	r12, #0x9
L_fe_invert2:
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x40
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_fe_invert2
#else
	BNE.N	L_fe_invert2
#endif
	ADD	r2, sp, #0x20
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x40
	BL	fe_mul_op
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x60
	BL	fe_sq_op
	MOV	r12, #0x13
L_fe_invert3:
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x60
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_fe_invert3
#else
	BNE.N	L_fe_invert3
#endif
	ADD	r2, sp, #0x40
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x40
	BL	fe_mul_op
	MOV	r12, #0xa
L_fe_invert4:
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x40
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_fe_invert4
#else
	BNE.N	L_fe_invert4
#endif
	ADD	r2, sp, #0x20
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x20
	BL	fe_mul_op
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x40
	BL	fe_sq_op
	MOV	r12, #0x31
L_fe_invert5:
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x40
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_fe_invert5
#else
	BNE.N	L_fe_invert5
#endif
	ADD	r2, sp, #0x20
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x40
	BL	fe_mul_op
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x60
	BL	fe_sq_op
	MOV	r12, #0x63
L_fe_invert6:
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x60
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_fe_invert6
#else
	BNE.N	L_fe_invert6
#endif
	ADD	r2, sp, #0x40
	ADD	r1, sp, #0x60
	ADD	r0, sp, #0x40
	BL	fe_mul_op
	MOV	r12, #0x32
L_fe_invert7:
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x40
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_fe_invert7
#else
	BNE.N	L_fe_invert7
#endif
	ADD	r2, sp, #0x20
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x20
	BL	fe_mul_op
	MOV	r12, #0x5
L_fe_invert8:
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x20
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_fe_invert8
#else
	BNE.N	L_fe_invert8
#endif
	MOV	r2, sp
	ADD	r1, sp, #0x20
	LDR	r0, [sp, #128]
	BL	fe_mul_op
	LDR	r1, [sp, #132]
	LDR	r0, [sp, #128]
	ADD	sp, sp, #0x88
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 292 */
	.size	fe_invert,.-fe_invert
#ifdef WOLFSSL_ARM_ARCH_7M
	.text
	.align	4
	.globl	fe_sq2
	.type	fe_sq2, %function
fe_sq2:
	PUSH	{lr}
	SUB	sp, sp, #0x44
	STR	r0, [sp, #64]
	/* Square * 2 */
	MOV	r0, #0x0
	LDR	r12, [r1]
	/* A[0] * A[1] */
	LDR	lr, [r1, #4]
	UMULL	r4, r5, r12, lr
	/* A[0] * A[3] */
	LDR	lr, [r1, #12]
	UMULL	r6, r7, r12, lr
	/* A[0] * A[5] */
	LDR	lr, [r1, #20]
	UMULL	r8, r9, r12, lr
	/* A[0] * A[7] */
	LDR	lr, [r1, #28]
	UMULL	r10, r3, r12, lr
	/* A[0] * A[2] */
	LDR	lr, [r1, #8]
	MOV	r11, #0x0
	UMLAL	r5, r11, r12, lr
	ADDS	r6, r6, r11
	/* A[0] * A[4] */
	LDR	lr, [r1, #16]
	ADCS	r7, r7, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r12, lr
	ADDS	r8, r8, r11
	/* A[0] * A[6] */
	LDR	lr, [r1, #24]
	ADCS	r9, r9, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r9, r11, r12, lr
	ADDS	r10, r10, r11
	ADCS	r3, r3, #0x0
	STR	r4, [sp, #4]
	STR	r5, [sp, #8]
	/* A[1] * A[2] */
	LDR	r12, [r1, #4]
	LDR	lr, [r1, #8]
	MOV	r11, #0x0
	UMLAL	r6, r11, r12, lr
	STR	r6, [sp, #12]
	ADDS	r7, r7, r11
	/* A[1] * A[3] */
	LDR	lr, [r1, #12]
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r12, lr
	STR	r7, [sp, #16]
	ADDS	r8, r8, r11
	/* A[1] * A[4] */
	LDR	lr, [r1, #16]
	ADC	r11, r0, #0x0
	UMLAL	r8, r11, r12, lr
	ADDS	r9, r9, r11
	/* A[1] * A[5] */
	LDR	lr, [r1, #20]
	ADC	r11, r0, #0x0
	UMLAL	r9, r11, r12, lr
	ADDS	r10, r10, r11
	/* A[1] * A[6] */
	LDR	lr, [r1, #24]
	ADC	r11, r0, #0x0
	UMLAL	r10, r11, r12, lr
	ADDS	r3, r3, r11
	/* A[1] * A[7] */
	LDR	lr, [r1, #28]
	ADC	r4, r0, #0x0
	UMLAL	r3, r4, r12, lr
	/* A[2] * A[3] */
	LDR	r12, [r1, #8]
	LDR	lr, [r1, #12]
	MOV	r11, #0x0
	UMLAL	r8, r11, r12, lr
	STR	r8, [sp, #20]
	ADDS	r9, r9, r11
	/* A[2] * A[4] */
	LDR	lr, [r1, #16]
	ADC	r11, r0, #0x0
	UMLAL	r9, r11, r12, lr
	STR	r9, [sp, #24]
	ADDS	r10, r10, r11
	/* A[2] * A[5] */
	LDR	lr, [r1, #20]
	ADC	r11, r0, #0x0
	UMLAL	r10, r11, r12, lr
	ADDS	r3, r3, r11
	/* A[2] * A[6] */
	LDR	lr, [r1, #24]
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r12, lr
	ADDS	r4, r4, r11
	/* A[2] * A[7] */
	LDR	lr, [r1, #28]
	ADC	r5, r0, #0x0
	UMLAL	r4, r5, r12, lr
	/* A[3] * A[4] */
	LDR	r12, [r1, #12]
	LDR	lr, [r1, #16]
	MOV	r11, #0x0
	UMLAL	r10, r11, r12, lr
	STR	r10, [sp, #28]
	ADDS	r3, r3, r11
	/* A[3] * A[5] */
	LDR	lr, [r1, #20]
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r12, lr
	ADDS	r4, r4, r11
	/* A[3] * A[6] */
	LDR	lr, [r1, #24]
	ADC	r11, r0, #0x0
	UMLAL	r4, r11, r12, lr
	ADDS	r5, r5, r11
	/* A[3] * A[7] */
	LDR	lr, [r1, #28]
	ADC	r6, r0, #0x0
	UMLAL	r5, r6, r12, lr
	/* A[4] * A[5] */
	LDR	r12, [r1, #16]
	LDR	lr, [r1, #20]
	MOV	r11, #0x0
	UMLAL	r4, r11, r12, lr
	ADDS	r5, r5, r11
	/* A[4] * A[6] */
	LDR	lr, [r1, #24]
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r12, lr
	ADDS	r6, r6, r11
	/* A[4] * A[7] */
	LDR	lr, [r1, #28]
	ADC	r7, r0, #0x0
	UMLAL	r6, r7, r12, lr
	/* A[5] * A[6] */
	LDR	r12, [r1, #20]
	LDR	lr, [r1, #24]
	MOV	r11, #0x0
	UMLAL	r6, r11, r12, lr
	ADDS	r7, r7, r11
	/* A[5] * A[7] */
	LDR	lr, [r1, #28]
	ADC	r8, r0, #0x0
	UMLAL	r7, r8, r12, lr
	/* A[6] * A[7] */
	LDR	r12, [r1, #24]
	LDR	lr, [r1, #28]
	MOV	r9, #0x0
	UMLAL	r8, r9, r12, lr
	ADD	lr, sp, #0x20
	STM	lr, {r3, r4, r5, r6, r7, r8, r9}
	ADD	lr, sp, #0x4
	LDM	lr, {r4, r5, r6, r7, r8, r9, r10}
	ADDS	r4, r4, r4
	ADCS	r5, r5, r5
	ADCS	r6, r6, r6
	ADCS	r7, r7, r7
	ADCS	r8, r8, r8
	ADCS	r9, r9, r9
	ADCS	r10, r10, r10
	STM	lr!, {r4, r5, r6, r7, r8, r9, r10}
	LDM	lr, {r3, r4, r5, r6, r7, r8, r9}
	ADCS	r3, r3, r3
	ADCS	r4, r4, r4
	ADCS	r5, r5, r5
	ADCS	r6, r6, r6
	ADCS	r7, r7, r7
	ADCS	r8, r8, r8
	ADCS	r9, r9, r9
	ADC	r10, r0, #0x0
	STM	lr, {r3, r4, r5, r6, r7, r8, r9, r10}
	ADD	lr, sp, #0x4
	LDM	lr, {r4, r5, r6, r7, r8, r9, r10}
	MOV	lr, sp
	/* A[0] * A[0] */
	LDR	r12, [r1]
	UMULL	r3, r11, r12, r12
	ADDS	r4, r4, r11
	/* A[1] * A[1] */
	LDR	r12, [r1, #4]
	ADCS	r5, r5, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r12, r12
	ADDS	r6, r6, r11
	/* A[2] * A[2] */
	LDR	r12, [r1, #8]
	ADCS	r7, r7, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r12, r12
	ADDS	r8, r8, r11
	/* A[3] * A[3] */
	LDR	r12, [r1, #12]
	ADCS	r9, r9, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r9, r11, r12, r12
	ADDS	r10, r10, r11
	STM	lr!, {r3, r4, r5, r6, r7, r8, r9, r10}
	LDM	lr, {r3, r4, r5, r6, r7, r8, r9, r10}
	/* A[4] * A[4] */
	LDR	r12, [r1, #16]
	ADCS	r3, r3, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r12, r12
	ADDS	r4, r4, r11
	/* A[5] * A[5] */
	LDR	r12, [r1, #20]
	ADCS	r5, r5, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r12, r12
	ADDS	r6, r6, r11
	/* A[6] * A[6] */
	LDR	r12, [r1, #24]
	ADCS	r7, r7, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r12, r12
	ADDS	r8, r8, r11
	/* A[7] * A[7] */
	LDR	r12, [r1, #28]
	ADCS	r9, r9, #0x0
	ADC	r10, r10, #0x0
	UMLAL	r9, r10, r12, r12
	/* Reduce */
	LDR	r2, [sp, #28]
	MOV	lr, sp
	MOV	r12, #0x26
	UMULL	r10, r11, r10, r12
	ADDS	r10, r10, r2
	ADC	r11, r11, #0x0
	MOV	r12, #0x13
	LSL	r11, r11, #1
	ORR	r11, r11, r10, LSR #31
	MUL	r11, r11, r12
	LDM	lr!, {r1, r2}
	MOV	r12, #0x26
	ADDS	r1, r1, r11
	ADC	r11, r0, #0x0
	UMLAL	r1, r11, r3, r12
	ADDS	r2, r2, r11
	ADC	r11, r0, #0x0
	UMLAL	r2, r11, r4, r12
	LDM	lr!, {r3, r4}
	ADDS	r3, r3, r11
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r5, r12
	ADDS	r4, r4, r11
	ADC	r11, r0, #0x0
	UMLAL	r4, r11, r6, r12
	LDM	lr!, {r5, r6}
	ADDS	r5, r5, r11
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r7, r12
	ADDS	r6, r6, r11
	ADC	r11, r0, #0x0
	UMLAL	r6, r11, r8, r12
	LDM	lr!, {r7, r8}
	ADDS	r7, r7, r11
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r9, r12
	BFC	r10, #31, #1
	ADDS	r8, r10, r11
	/* Reduce if top bit set */
	MOV	r12, #0x13
	AND	r11, r12, r8, ASR #31
	ADDS	r1, r1, r11
	ADCS	r2, r2, #0x0
	ADCS	r3, r3, #0x0
	ADCS	r4, r4, #0x0
	ADCS	r5, r5, #0x0
	ADCS	r6, r6, #0x0
	BFC	r8, #31, #1
	ADCS	r7, r7, #0x0
	ADC	r8, r8, #0x0
	/* Double */
	ADDS	r1, r1, r1
	ADCS	r2, r2, r2
	ADCS	r3, r3, r3
	ADCS	r4, r4, r4
	ADCS	r5, r5, r5
	ADCS	r6, r6, r6
	ADCS	r7, r7, r7
	ADC	r8, r8, r8
	/* Reduce if top bit set */
	MOV	r12, #0x13
	AND	r11, r12, r8, ASR #31
	ADDS	r1, r1, r11
	ADCS	r2, r2, #0x0
	ADCS	r3, r3, #0x0
	ADCS	r4, r4, #0x0
	ADCS	r5, r5, #0x0
	ADCS	r6, r6, #0x0
	BFC	r8, #31, #1
	ADCS	r7, r7, #0x0
	ADC	r8, r8, #0x0
	/* Store */
	LDR	r0, [sp, #64]
	STM	r0, {r1, r2, r3, r4, r5, r6, r7, r8}
	ADD	sp, sp, #0x44
	POP	{pc}
	/* Cycle Count = 385 */
	.size	fe_sq2,.-fe_sq2
#else
	.text
	.align	4
	.globl	fe_sq2
	.type	fe_sq2, %function
fe_sq2:
	PUSH	{lr}
	SUB	sp, sp, #0x24
	STRD	r0, r1, [sp, #28]
	LDM	r1, {r0, r1, r2, r3, r4, r5, r6, r7}
	/* Square * 2 */
	UMULL	r9, r10, r0, r0
	UMULL	r11, r12, r0, r1
	ADDS	r11, r11, r11
	MOV	lr, #0x0
	UMAAL	r10, r11, lr, lr
	STM	sp, {r9, r10}
	MOV	r8, lr
	UMAAL	r8, r12, r0, r2
	ADCS	r8, r8, r8
	UMAAL	r8, r11, r1, r1
	UMULL	r9, r10, r0, r3
	UMAAL	r9, r12, r1, r2
	ADCS	r9, r9, r9
	UMAAL	r9, r11, lr, lr
	STRD	r8, r9, [sp, #8]
	MOV	r9, lr
	UMAAL	r9, r10, r0, r4
	UMAAL	r9, r12, r1, r3
	ADCS	r9, r9, r9
	UMAAL	r9, r11, r2, r2
	STR	r9, [sp, #16]
	UMULL	r9, r8, r0, r5
	UMAAL	r9, r12, r1, r4
	UMAAL	r9, r10, r2, r3
	ADCS	r9, r9, r9
	UMAAL	r9, r11, lr, lr
	STR	r9, [sp, #20]
	MOV	r9, lr
	UMAAL	r9, r8, r0, r6
	UMAAL	r9, r12, r1, r5
	UMAAL	r9, r10, r2, r4
	ADCS	r9, r9, r9
	UMAAL	r9, r11, r3, r3
	STR	r9, [sp, #24]
	UMULL	r0, r9, r0, r7
	UMAAL	r0, r8, r1, r6
	UMAAL	r0, r12, r2, r5
	UMAAL	r0, r10, r3, r4
	ADCS	r0, r0, r0
	UMAAL	r0, r11, lr, lr
	/* R[7] = r0 */
	UMAAL	r9, r8, r1, r7
	UMAAL	r9, r10, r2, r6
	UMAAL	r12, r9, r3, r5
	ADCS	r12, r12, r12
	UMAAL	r12, r11, r4, r4
	/* R[8] = r12 */
	UMAAL	r9, r8, r2, r7
	UMAAL	r10, r9, r3, r6
	MOV	r2, lr
	UMAAL	r10, r2, r4, r5
	ADCS	r10, r10, r10
	UMAAL	r11, r10, lr, lr
	/* R[9] = r11 */
	UMAAL	r2, r8, r3, r7
	UMAAL	r2, r9, r4, r6
	ADCS	r3, r2, r2
	UMAAL	r10, r3, r5, r5
	/* R[10] = r10 */
	MOV	r1, lr
	UMAAL	r1, r8, r4, r7
	UMAAL	r1, r9, r5, r6
	ADCS	r4, r1, r1
	UMAAL	r3, r4, lr, lr
	/* R[11] = r3 */
	UMAAL	r8, r9, r5, r7
	ADCS	r8, r8, r8
	UMAAL	r4, r8, r6, r6
	/* R[12] = r4 */
	MOV	r5, lr
	UMAAL	r5, r9, r6, r7
	ADCS	r5, r5, r5
	UMAAL	r8, r5, lr, lr
	/* R[13] = r8 */
	ADCS	r9, r9, r9
	UMAAL	r9, r5, r7, r7
	ADCS	r7, r5, lr
	/* R[14] = r9 */
	/* R[15] = r7 */
	/* Reduce */
	MOV	r6, #0x25
	UMAAL	r7, r0, r7, r6
	MOV	r6, #0x13
	LSL	r0, r0, #1
	ORR	r0, r0, r7, LSR #31
	MUL	lr, r0, r6
	POP	{r0, r1}
	MOV	r6, #0x26
	UMAAL	r0, lr, r12, r6
	UMAAL	r1, lr, r11, r6
	MOV	r12, r3
	MOV	r11, r4
	POP	{r2, r3, r4}
	UMAAL	r2, lr, r10, r6
	UMAAL	r3, lr, r12, r6
	UMAAL	r4, lr, r11, r6
	MOV	r12, r6
	POP	{r5, r6}
	UMAAL	r5, lr, r8, r12
	BFC	r7, #31, #1
	UMAAL	r6, lr, r9, r12
	ADD	r7, r7, lr
	/* Reduce if top bit set */
	MOV	r11, #0x13
	AND	r12, r11, r7, ASR #31
	ADDS	r0, r0, r12
	ADCS	r1, r1, #0x0
	ADCS	r2, r2, #0x0
	ADCS	r3, r3, #0x0
	ADCS	r4, r4, #0x0
	ADCS	r5, r5, #0x0
	BFC	r7, #31, #1
	ADCS	r6, r6, #0x0
	ADC	r7, r7, #0x0
	/* Double */
	ADDS	r0, r0, r0
	ADCS	r1, r1, r1
	ADCS	r2, r2, r2
	ADCS	r3, r3, r3
	ADCS	r4, r4, r4
	ADCS	r5, r5, r5
	ADCS	r6, r6, r6
	ADC	r7, r7, r7
	/* Reduce if top bit set */
	MOV	r11, #0x13
	AND	r12, r11, r7, ASR #31
	ADDS	r0, r0, r12
	ADCS	r1, r1, #0x0
	ADCS	r2, r2, #0x0
	ADCS	r3, r3, #0x0
	ADCS	r4, r4, #0x0
	ADCS	r5, r5, #0x0
	BFC	r7, #31, #1
	ADCS	r6, r6, #0x0
	ADC	r7, r7, #0x0
	POP	{r12, lr}
	/* Store */
	STM	r12, {r0, r1, r2, r3, r4, r5, r6, r7}
	MOV	r0, r12
	MOV	r1, lr
	POP	{pc}
	/* Cycle Count = 213 */
	.size	fe_sq2,.-fe_sq2
#endif /* WOLFSSL_ARM_ARCH_7M */
	.text
	.align	4
	.globl	fe_pow22523
	.type	fe_pow22523, %function
fe_pow22523:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0x68
	/* pow22523 */
	STR	r0, [sp, #96]
	STR	r1, [sp, #100]
	LDR	r1, [sp, #100]
	MOV	r0, sp
	BL	fe_sq_op
	MOV	r1, sp
	ADD	r0, sp, #0x20
	BL	fe_sq_op
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x20
	BL	fe_sq_op
	ADD	r2, sp, #0x20
	LDR	r1, [sp, #100]
	ADD	r0, sp, #0x20
	BL	fe_mul_op
	ADD	r2, sp, #0x20
	MOV	r1, sp
	MOV	r0, sp
	BL	fe_mul_op
	MOV	r1, sp
	MOV	r0, sp
	BL	fe_sq_op
	MOV	r2, sp
	ADD	r1, sp, #0x20
	MOV	r0, sp
	BL	fe_mul_op
	MOV	r1, sp
	ADD	r0, sp, #0x20
	BL	fe_sq_op
	MOV	r12, #0x4
L_fe_pow22523_1:
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x20
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_fe_pow22523_1
#else
	BNE.N	L_fe_pow22523_1
#endif
	MOV	r2, sp
	ADD	r1, sp, #0x20
	MOV	r0, sp
	BL	fe_mul_op
	MOV	r1, sp
	ADD	r0, sp, #0x20
	BL	fe_sq_op
	MOV	r12, #0x9
L_fe_pow22523_2:
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x20
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_fe_pow22523_2
#else
	BNE.N	L_fe_pow22523_2
#endif
	MOV	r2, sp
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x20
	BL	fe_mul_op
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x40
	BL	fe_sq_op
	MOV	r12, #0x13
L_fe_pow22523_3:
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x40
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_fe_pow22523_3
#else
	BNE.N	L_fe_pow22523_3
#endif
	ADD	r2, sp, #0x20
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x20
	BL	fe_mul_op
	MOV	r12, #0xa
L_fe_pow22523_4:
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x20
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_fe_pow22523_4
#else
	BNE.N	L_fe_pow22523_4
#endif
	MOV	r2, sp
	ADD	r1, sp, #0x20
	MOV	r0, sp
	BL	fe_mul_op
	MOV	r1, sp
	ADD	r0, sp, #0x20
	BL	fe_sq_op
	MOV	r12, #0x31
L_fe_pow22523_5:
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x20
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_fe_pow22523_5
#else
	BNE.N	L_fe_pow22523_5
#endif
	MOV	r2, sp
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x20
	BL	fe_mul_op
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x40
	BL	fe_sq_op
	MOV	r12, #0x63
L_fe_pow22523_6:
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x40
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_fe_pow22523_6
#else
	BNE.N	L_fe_pow22523_6
#endif
	ADD	r2, sp, #0x20
	ADD	r1, sp, #0x40
	ADD	r0, sp, #0x20
	BL	fe_mul_op
	MOV	r12, #0x32
L_fe_pow22523_7:
	ADD	r1, sp, #0x20
	ADD	r0, sp, #0x20
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_fe_pow22523_7
#else
	BNE.N	L_fe_pow22523_7
#endif
	MOV	r2, sp
	ADD	r1, sp, #0x20
	MOV	r0, sp
	BL	fe_mul_op
	MOV	r12, #0x2
L_fe_pow22523_8:
	MOV	r1, sp
	MOV	r0, sp
	PUSH	{r12}
	BL	fe_sq_op
	POP	{r12}
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_fe_pow22523_8
#else
	BNE.N	L_fe_pow22523_8
#endif
	LDR	r2, [sp, #100]
	MOV	r1, sp
	LDR	r0, [sp, #96]
	BL	fe_mul_op
	LDR	r1, [sp, #100]
	LDR	r0, [sp, #96]
	ADD	sp, sp, #0x68
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 293 */
	.size	fe_pow22523,.-fe_pow22523
	.text
	.align	4
	.globl	ge_p1p1_to_p2
	.type	ge_p1p1_to_p2, %function
ge_p1p1_to_p2:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0x8
	STR	r0, [sp]
	STR	r1, [sp, #4]
	ADD	r2, r1, #0x60
	BL	fe_mul_op
	LDR	r0, [sp]
	LDR	r1, [sp, #4]
	ADD	r2, r1, #0x40
	ADD	r1, r1, #0x20
	ADD	r0, r0, #0x20
	BL	fe_mul_op
	LDR	r0, [sp]
	LDR	r1, [sp, #4]
	ADD	r2, r1, #0x60
	ADD	r1, r1, #0x40
	ADD	r0, r0, #0x40
	BL	fe_mul_op
	ADD	sp, sp, #0x8
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 53 */
	.size	ge_p1p1_to_p2,.-ge_p1p1_to_p2
	.text
	.align	4
	.globl	ge_p1p1_to_p3
	.type	ge_p1p1_to_p3, %function
ge_p1p1_to_p3:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0x8
	STR	r0, [sp]
	STR	r1, [sp, #4]
	ADD	r2, r1, #0x60
	BL	fe_mul_op
	LDR	r0, [sp]
	LDR	r1, [sp, #4]
	ADD	r2, r1, #0x40
	ADD	r1, r1, #0x20
	ADD	r0, r0, #0x20
	BL	fe_mul_op
	LDR	r0, [sp]
	LDR	r1, [sp, #4]
	ADD	r2, r1, #0x60
	ADD	r1, r1, #0x40
	ADD	r0, r0, #0x40
	BL	fe_mul_op
	LDR	r0, [sp]
	LDR	r1, [sp, #4]
	ADD	r2, r1, #0x20
	ADD	r0, r0, #0x60
	BL	fe_mul_op
	ADD	sp, sp, #0x8
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 63 */
	.size	ge_p1p1_to_p3,.-ge_p1p1_to_p3
	.text
	.align	4
	.globl	ge_p2_dbl
	.type	ge_p2_dbl, %function
ge_p2_dbl:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0x8
	STR	r0, [sp]
	STR	r1, [sp, #4]
	BL	fe_sq_op
	LDR	r0, [sp]
	LDR	r1, [sp, #4]
	ADD	r1, r1, #0x20
	ADD	r0, r0, #0x40
	BL	fe_sq_op
	LDR	r0, [sp]
	LDR	r1, [sp, #4]
	ADD	r2, r1, #0x20
	ADD	r0, r0, #0x20
	BL	fe_add_op
	MOV	r1, r0
	ADD	r0, r0, #0x40
	BL	fe_sq_op
	LDR	r0, [sp]
	MOV	r3, r0
	ADD	r2, r0, #0x40
	ADD	r1, r0, #0x40
	ADD	r0, r0, #0x20
	BL	fe_add_sub_op
	MOV	r2, r0
	ADD	r1, r0, #0x40
	SUB	r0, r0, #0x20
	BL	fe_sub_op
	LDR	r1, [sp, #4]
	ADD	r1, r1, #0x40
	ADD	r0, r0, #0x60
	BL	fe_sq2
	SUB	r2, r0, #0x20
	MOV	r1, r0
	BL	fe_sub_op
	ADD	sp, sp, #0x8
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 87 */
	.size	ge_p2_dbl,.-ge_p2_dbl
	.text
	.align	4
	.globl	ge_madd
	.type	ge_madd, %function
ge_madd:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0xc
	STR	r0, [sp]
	STR	r1, [sp, #4]
	STR	r2, [sp, #8]
	MOV	r2, r1
	ADD	r1, r1, #0x20
	BL	fe_add_op
	LDR	r1, [sp, #4]
	MOV	r2, r1
	ADD	r1, r1, #0x20
	ADD	r0, r0, #0x20
	BL	fe_sub_op
	LDR	r2, [sp, #8]
	SUB	r1, r0, #0x20
	ADD	r0, r0, #0x20
	BL	fe_mul_op
	LDR	r0, [sp]
	LDR	r2, [sp, #8]
	ADD	r2, r2, #0x20
	ADD	r1, r0, #0x20
	ADD	r0, r0, #0x20
	BL	fe_mul_op
	LDR	r0, [sp]
	LDR	r1, [sp, #8]
	LDR	r2, [sp, #4]
	ADD	r2, r2, #0x60
	ADD	r1, r1, #0x40
	ADD	r0, r0, #0x60
	BL	fe_mul_op
	LDR	r0, [sp]
	ADD	r3, r0, #0x20
	ADD	r2, r0, #0x40
	MOV	r1, r0
	ADD	r0, r0, #0x20
	BL	fe_add_sub_op
	LDR	r1, [sp, #4]
	ADD	r1, r1, #0x40
	ADD	r0, r0, #0x20
	/* Double */
	LDM	r1, {r4, r5, r6, r7, r8, r9, r10, r11}
	ADDS	r4, r4, r4
	ADCS	r5, r5, r5
	ADCS	r6, r6, r6
	ADCS	r7, r7, r7
	ADCS	r8, r8, r8
	ADCS	r9, r9, r9
	ADCS	r10, r10, r10
	MOV	lr, #0x0
	ADCS	r11, r11, r11
	ADC	lr, lr, #0x0
	MOV	r12, #0x13
	LSL	lr, lr, #1
	ORR	lr, lr, r11, LSR #31
	MUL	r12, lr, r12
	ADDS	r4, r4, r12
	ADCS	r5, r5, #0x0
	ADCS	r6, r6, #0x0
	ADCS	r7, r7, #0x0
	ADCS	r8, r8, #0x0
	ADCS	r9, r9, #0x0
	BFC	r11, #31, #1
	ADCS	r10, r10, #0x0
	ADC	r11, r11, #0x0
	STM	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	/* Done Double */
	ADD	r3, r0, #0x20
	ADD	r1, r0, #0x20
	BL	fe_add_sub_op
	ADD	sp, sp, #0xc
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 136 */
	.size	ge_madd,.-ge_madd
	.text
	.align	4
	.globl	ge_msub
	.type	ge_msub, %function
ge_msub:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0xc
	STR	r0, [sp]
	STR	r1, [sp, #4]
	STR	r2, [sp, #8]
	MOV	r2, r1
	ADD	r1, r1, #0x20
	BL	fe_add_op
	LDR	r1, [sp, #4]
	MOV	r2, r1
	ADD	r1, r1, #0x20
	ADD	r0, r0, #0x20
	BL	fe_sub_op
	LDR	r2, [sp, #8]
	ADD	r2, r2, #0x20
	SUB	r1, r0, #0x20
	ADD	r0, r0, #0x20
	BL	fe_mul_op
	LDR	r0, [sp]
	LDR	r2, [sp, #8]
	ADD	r1, r0, #0x20
	ADD	r0, r0, #0x20
	BL	fe_mul_op
	LDR	r0, [sp]
	LDR	r1, [sp, #8]
	LDR	r2, [sp, #4]
	ADD	r2, r2, #0x60
	ADD	r1, r1, #0x40
	ADD	r0, r0, #0x60
	BL	fe_mul_op
	LDR	r0, [sp]
	ADD	r3, r0, #0x20
	ADD	r2, r0, #0x40
	MOV	r1, r0
	ADD	r0, r0, #0x20
	BL	fe_add_sub_op
	LDR	r1, [sp, #4]
	ADD	r1, r1, #0x40
	ADD	r0, r0, #0x20
	/* Double */
	LDM	r1, {r4, r5, r6, r7, r8, r9, r10, r11}
	ADDS	r4, r4, r4
	ADCS	r5, r5, r5
	ADCS	r6, r6, r6
	ADCS	r7, r7, r7
	ADCS	r8, r8, r8
	ADCS	r9, r9, r9
	ADCS	r10, r10, r10
	MOV	lr, #0x0
	ADCS	r11, r11, r11
	ADC	lr, lr, #0x0
	MOV	r12, #0x13
	LSL	lr, lr, #1
	ORR	lr, lr, r11, LSR #31
	MUL	r12, lr, r12
	ADDS	r4, r4, r12
	ADCS	r5, r5, #0x0
	ADCS	r6, r6, #0x0
	ADCS	r7, r7, #0x0
	ADCS	r8, r8, #0x0
	ADCS	r9, r9, #0x0
	BFC	r11, #31, #1
	ADCS	r10, r10, #0x0
	ADC	r11, r11, #0x0
	STM	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	/* Done Double */
	ADD	r3, r0, #0x20
	MOV	r1, r0
	ADD	r0, r0, #0x20
	BL	fe_add_sub_op
	ADD	sp, sp, #0xc
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 137 */
	.size	ge_msub,.-ge_msub
	.text
	.align	4
	.globl	ge_add
	.type	ge_add, %function
ge_add:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0x2c
	STR	r0, [sp]
	STR	r1, [sp, #4]
	STR	r2, [sp, #8]
	MOV	r3, r1
	ADD	r2, r1, #0x20
	ADD	r1, r0, #0x20
	BL	fe_add_sub_op
	LDR	r2, [sp, #8]
	MOV	r1, r0
	ADD	r0, r0, #0x40
	BL	fe_mul_op
	LDR	r0, [sp]
	LDR	r2, [sp, #8]
	ADD	r2, r2, #0x20
	ADD	r1, r0, #0x20
	ADD	r0, r0, #0x20
	BL	fe_mul_op
	LDR	r0, [sp]
	LDR	r1, [sp, #8]
	LDR	r2, [sp, #4]
	ADD	r2, r2, #0x60
	ADD	r1, r1, #0x60
	ADD	r0, r0, #0x60
	BL	fe_mul_op
	LDR	r0, [sp]
	LDR	r1, [sp, #4]
	LDR	r2, [sp, #8]
	ADD	r2, r2, #0x40
	ADD	r1, r1, #0x40
	BL	fe_mul_op
	LDR	r1, [sp]
	ADD	r0, sp, #0xc
	/* Double */
	LDM	r1, {r4, r5, r6, r7, r8, r9, r10, r11}
	ADDS	r4, r4, r4
	ADCS	r5, r5, r5
	ADCS	r6, r6, r6
	ADCS	r7, r7, r7
	ADCS	r8, r8, r8
	ADCS	r9, r9, r9
	ADCS	r10, r10, r10
	MOV	lr, #0x0
	ADCS	r11, r11, r11
	ADC	lr, lr, #0x0
	MOV	r12, #0x13
	LSL	lr, lr, #1
	ORR	lr, lr, r11, LSR #31
	MUL	r12, lr, r12
	ADDS	r4, r4, r12
	ADCS	r5, r5, #0x0
	ADCS	r6, r6, #0x0
	ADCS	r7, r7, #0x0
	ADCS	r8, r8, #0x0
	ADCS	r9, r9, #0x0
	BFC	r11, #31, #1
	ADCS	r10, r10, #0x0
	ADC	r11, r11, #0x0
	STM	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	/* Done Double */
	ADD	r3, r1, #0x20
	ADD	r2, r1, #0x40
	ADD	r0, r1, #0x20
	BL	fe_add_sub_op
	ADD	r3, r0, #0x40
	ADD	r2, sp, #0xc
	ADD	r1, r0, #0x40
	ADD	r0, r0, #0x20
	BL	fe_add_sub_op
	ADD	sp, sp, #0x2c
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 138 */
	.size	ge_add,.-ge_add
	.text
	.align	4
	.globl	ge_sub
	.type	ge_sub, %function
ge_sub:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0x2c
	STR	r0, [sp]
	STR	r1, [sp, #4]
	STR	r2, [sp, #8]
	MOV	r3, r1
	ADD	r2, r1, #0x20
	ADD	r1, r0, #0x20
	BL	fe_add_sub_op
	LDR	r2, [sp, #8]
	ADD	r2, r2, #0x20
	MOV	r1, r0
	ADD	r0, r0, #0x40
	BL	fe_mul_op
	LDR	r0, [sp]
	LDR	r2, [sp, #8]
	ADD	r1, r0, #0x20
	ADD	r0, r0, #0x20
	BL	fe_mul_op
	LDR	r0, [sp]
	LDR	r1, [sp, #8]
	LDR	r2, [sp, #4]
	ADD	r2, r2, #0x60
	ADD	r1, r1, #0x60
	ADD	r0, r0, #0x60
	BL	fe_mul_op
	LDR	r0, [sp]
	LDR	r1, [sp, #4]
	LDR	r2, [sp, #8]
	ADD	r2, r2, #0x40
	ADD	r1, r1, #0x40
	BL	fe_mul_op
	LDR	r1, [sp]
	ADD	r0, sp, #0xc
	/* Double */
	LDM	r1, {r4, r5, r6, r7, r8, r9, r10, r11}
	ADDS	r4, r4, r4
	ADCS	r5, r5, r5
	ADCS	r6, r6, r6
	ADCS	r7, r7, r7
	ADCS	r8, r8, r8
	ADCS	r9, r9, r9
	ADCS	r10, r10, r10
	MOV	lr, #0x0
	ADCS	r11, r11, r11
	ADC	lr, lr, #0x0
	MOV	r12, #0x13
	LSL	lr, lr, #1
	ORR	lr, lr, r11, LSR #31
	MUL	r12, lr, r12
	ADDS	r4, r4, r12
	ADCS	r5, r5, #0x0
	ADCS	r6, r6, #0x0
	ADCS	r7, r7, #0x0
	ADCS	r8, r8, #0x0
	ADCS	r9, r9, #0x0
	BFC	r11, #31, #1
	ADCS	r10, r10, #0x0
	ADC	r11, r11, #0x0
	STM	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	/* Done Double */
	ADD	r3, r1, #0x20
	ADD	r2, r1, #0x40
	ADD	r0, r1, #0x20
	BL	fe_add_sub_op
	ADD	r3, r0, #0x40
	ADD	r2, sp, #0xc
	ADD	r1, r0, #0x20
	ADD	r0, r0, #0x40
	BL	fe_add_sub_op
	ADD	sp, sp, #0x2c
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 138 */
	.size	ge_sub,.-ge_sub
#ifdef WOLFSSL_ARM_ARCH_7M
	.text
	.align	4
	.globl	sc_reduce
	.type	sc_reduce, %function
sc_reduce:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0x38
	STR	r0, [sp, #52]
	/* Load bits 252-511 */
	ADD	r0, r0, #0x1c
	LDM	r0, {r1, r2, r3, r4, r5, r6, r7, r8, r9}
	LSR	lr, r9, #24
	LSL	r9, r9, #4
	ORR	r9, r9, r8, LSR #28
	LSL	r8, r8, #4
	ORR	r8, r8, r7, LSR #28
	LSL	r7, r7, #4
	ORR	r7, r7, r6, LSR #28
	LSL	r6, r6, #4
	ORR	r6, r6, r5, LSR #28
	LSL	r5, r5, #4
	ORR	r5, r5, r4, LSR #28
	LSL	r4, r4, #4
	ORR	r4, r4, r3, LSR #28
	LSL	r3, r3, #4
	ORR	r3, r3, r2, LSR #28
	LSL	r2, r2, #4
	ORR	r2, r2, r1, LSR #28
	BFC	r9, #28, #4
	SUB	r0, r0, #0x1c
	/* Add order times bits 504..511 */
	MOV	r10, #0x2c13
	MOVT	r10, #0xa30a
	MOV	r11, #0x9ce5
	MOVT	r11, #0xa7ed
	MOV	r1, #0x0
	UMLAL	r2, r1, r10, lr
	ADDS	r3, r3, r1
	MOV	r1, #0x0
	ADC	r1, r1, #0x0
	UMLAL	r3, r1, r11, lr
	MOV	r10, #0x6329
	MOVT	r10, #0x5d08
	MOV	r11, #0x621
	MOVT	r11, #0xeb21
	ADDS	r4, r4, r1
	MOV	r1, #0x0
	ADC	r1, r1, #0x0
	UMLAL	r4, r1, r10, lr
	ADDS	r5, r5, r1
	MOV	r1, #0x0
	ADC	r1, r1, #0x0
	UMLAL	r5, r1, r11, lr
	ADDS	r6, r6, r1
	ADCS	r7, r7, #0x0
	ADCS	r8, r8, #0x0
	ADC	r9, r9, #0x0
	SUBS	r6, r6, lr
	SBCS	r7, r7, #0x0
	SBCS	r8, r8, #0x0
	SBC	r9, r9, #0x0
	/* Sub product of top 8 words and order */
	MOV	r12, sp
	MOV	r1, #0x2c13
	MOVT	r1, #0xa30a
	MOV	lr, #0x0
	LDM	r0!, {r10, r11}
	UMLAL	r10, lr, r2, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r3, r1
	STM	r12!, {r10, r11}
	LDM	r0!, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r4, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r5, r1
	STM	r12!, {r10, r11}
	LDM	r0!, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r6, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r7, r1
	STM	r12!, {r10, r11}
	LDM	r0!, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r8, r1
	BFC	r11, #28, #4
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r9, r1
	STM	r12!, {r10, r11, lr}
	SUB	r0, r0, #0x10
	SUB	r12, r12, #0x20
	MOV	r1, #0x9ce5
	MOVT	r1, #0xa7ed
	MOV	lr, #0x0
	LDM	r12, {r10, r11}
	UMLAL	r10, lr, r2, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r3, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r4, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r5, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r6, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r7, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r8, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r9, r1
	STM	r12!, {r10, r11, lr}
	SUB	r12, r12, #0x20
	MOV	r1, #0x6329
	MOVT	r1, #0x5d08
	MOV	lr, #0x0
	LDM	r12, {r10, r11}
	UMLAL	r10, lr, r2, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r3, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r4, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r5, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r6, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r7, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r8, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r9, r1
	STM	r12!, {r10, r11, lr}
	SUB	r12, r12, #0x20
	MOV	r1, #0x621
	MOVT	r1, #0xeb21
	MOV	lr, #0x0
	LDM	r12, {r10, r11}
	UMLAL	r10, lr, r2, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r3, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r4, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r5, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r6, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r7, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r8, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r9, r1
	STM	r12!, {r10, r11, lr}
	SUB	r12, r12, #0x20
	/* Subtract at 4 * 32 */
	LDM	r12, {r10, r11}
	SUBS	r10, r10, r2
	SBCS	r11, r11, r3
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	SBCS	r10, r10, r4
	SBCS	r11, r11, r5
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	SBCS	r10, r10, r6
	SBCS	r11, r11, r7
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	SBCS	r10, r10, r8
	SBC	r11, r11, r9
	STM	r12!, {r10, r11}
	SUB	r12, r12, #0x24
	ASR	lr, r11, #25
	/* Conditionally subtract order starting at bit 125 */
	MOV	r1, #0xa0000000
	MOV	r2, #0xba7d
	MOVT	r2, #0x4b9e
	MOV	r3, #0x4c63
	MOVT	r3, #0xcb02
	MOV	r4, #0xf39a
	MOVT	r4, #0xd45e
	MOV	r5, #0xdf3b
	MOVT	r5, #0x29b
	MOV	r9, #0x2000000
	AND	r1, r1, lr
	AND	r2, r2, lr
	AND	r3, r3, lr
	AND	r4, r4, lr
	AND	r5, r5, lr
	AND	r9, r9, lr
	LDM	r12, {r10, r11}
	ADDS	r10, r10, r1
	ADCS	r11, r11, r2
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADCS	r10, r10, r3
	ADCS	r11, r11, r4
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADCS	r10, r10, r5
	ADCS	r11, r11, #0x0
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADCS	r10, r10, #0x0
	ADCS	r11, r11, #0x0
	STM	r12!, {r10, r11}
	LDM	r12, {r10}
	ADCS	r10, r10, #0x0
	STM	r12!, {r10}
	SUB	r0, r0, #0x10
	MOV	r12, sp
	/* Load bits 252-376 */
	ADD	r12, r12, #0x1c
	LDM	r12, {r1, r2, r3, r4, r5}
	LSL	r5, r5, #4
	ORR	r5, r5, r4, LSR #28
	LSL	r4, r4, #4
	ORR	r4, r4, r3, LSR #28
	LSL	r3, r3, #4
	ORR	r3, r3, r2, LSR #28
	LSL	r2, r2, #4
	ORR	r2, r2, r1, LSR #28
	BFC	r5, #29, #3
	SUB	r12, r12, #0x1c
	/* Sub product of top 4 words and order */
	MOV	r0, sp
	/*   * -5cf5d3ed */
	MOV	r1, #0x2c13
	MOVT	r1, #0xa30a
	MOV	lr, #0x0
	LDM	r0, {r6, r7, r8, r9}
	UMLAL	r6, lr, r2, r1
	ADDS	r7, r7, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r7, lr, r3, r1
	ADDS	r8, r8, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r8, lr, r4, r1
	ADDS	r9, r9, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r9, lr, r5, r1
	STM	r0, {r6, r7, r8, r9}
	ADD	r0, r0, #0x4
	/*   * -5812631b */
	MOV	r1, #0x9ce5
	MOVT	r1, #0xa7ed
	MOV	r10, #0x0
	LDM	r0, {r6, r7, r8, r9}
	UMLAL	r6, r10, r2, r1
	ADDS	r7, r7, r10
	MOV	r10, #0x0
	ADC	r10, r10, #0x0
	UMLAL	r7, r10, r3, r1
	ADDS	r8, r8, r10
	MOV	r10, #0x0
	ADC	r10, r10, #0x0
	UMLAL	r8, r10, r4, r1
	ADDS	r9, r9, r10
	MOV	r10, #0x0
	ADC	r10, r10, #0x0
	UMLAL	r9, r10, r5, r1
	STM	r0, {r6, r7, r8, r9}
	ADD	r0, r0, #0x4
	/*   * -a2f79cd7 */
	MOV	r1, #0x6329
	MOVT	r1, #0x5d08
	MOV	r11, #0x0
	LDM	r0, {r6, r7, r8, r9}
	UMLAL	r6, r11, r2, r1
	ADDS	r7, r7, r11
	MOV	r11, #0x0
	ADC	r11, r11, #0x0
	UMLAL	r7, r11, r3, r1
	ADDS	r8, r8, r11
	MOV	r11, #0x0
	ADC	r11, r11, #0x0
	UMLAL	r8, r11, r4, r1
	ADDS	r9, r9, r11
	MOV	r11, #0x0
	ADC	r11, r11, #0x0
	UMLAL	r9, r11, r5, r1
	STM	r0, {r6, r7, r8, r9}
	ADD	r0, r0, #0x4
	/*   * -14def9df */
	MOV	r1, #0x621
	MOVT	r1, #0xeb21
	MOV	r12, #0x0
	LDM	r0, {r6, r7, r8, r9}
	UMLAL	r6, r12, r2, r1
	ADDS	r7, r7, r12
	MOV	r12, #0x0
	ADC	r12, r12, #0x0
	UMLAL	r7, r12, r3, r1
	ADDS	r8, r8, r12
	MOV	r12, #0x0
	ADC	r12, r12, #0x0
	UMLAL	r8, r12, r4, r1
	ADDS	r9, r9, r12
	MOV	r12, #0x0
	ADC	r12, r12, #0x0
	UMLAL	r9, r12, r5, r1
	STM	r0, {r6, r7, r8, r9}
	ADD	r0, r0, #0x4
	/* Add overflows at 4 * 32 */
	LDM	r0, {r6, r7, r8, r9}
	BFC	r9, #28, #4
	ADDS	r6, r6, lr
	ADCS	r7, r7, r10
	ADCS	r8, r8, r11
	ADC	r9, r9, r12
	/* Subtract top at 4 * 32 */
	SUBS	r6, r6, r2
	SBCS	r7, r7, r3
	SBCS	r8, r8, r4
	SBCS	r9, r9, r5
	SBC	r1, r1, r1
	SUB	r0, r0, #0x10
	LDM	r0, {r2, r3, r4, r5}
	MOV	r10, #0xd3ed
	MOVT	r10, #0x5cf5
	MOV	r11, #0x631a
	MOVT	r11, #0x5812
	MOV	r12, #0x9cd6
	MOVT	r12, #0xa2f7
	MOV	lr, #0xf9de
	MOVT	lr, #0x14de
	AND	r10, r10, r1
	AND	r11, r11, r1
	AND	r12, r12, r1
	AND	lr, lr, r1
	ADDS	r2, r2, r10
	ADCS	r3, r3, r11
	ADCS	r4, r4, r12
	ADCS	r5, r5, lr
	ADCS	r6, r6, #0x0
	ADCS	r7, r7, #0x0
	AND	r1, r1, #0x10000000
	ADCS	r8, r8, #0x0
	ADC	r9, r9, r1
	BFC	r9, #28, #4
	/* Store result */
	LDR	r0, [sp, #52]
	STM	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	ADD	sp, sp, #0x38
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 588 */
	.size	sc_reduce,.-sc_reduce
#else
	.text
	.align	4
	.globl	sc_reduce
	.type	sc_reduce, %function
sc_reduce:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0x38
	STR	r0, [sp, #52]
	/* Load bits 252-511 */
	ADD	r0, r0, #0x1c
	LDM	r0, {r1, r2, r3, r4, r5, r6, r7, r8, r9}
	LSR	lr, r9, #24
	LSL	r9, r9, #4
	ORR	r9, r9, r8, LSR #28
	LSL	r8, r8, #4
	ORR	r8, r8, r7, LSR #28
	LSL	r7, r7, #4
	ORR	r7, r7, r6, LSR #28
	LSL	r6, r6, #4
	ORR	r6, r6, r5, LSR #28
	LSL	r5, r5, #4
	ORR	r5, r5, r4, LSR #28
	LSL	r4, r4, #4
	ORR	r4, r4, r3, LSR #28
	LSL	r3, r3, #4
	ORR	r3, r3, r2, LSR #28
	LSL	r2, r2, #4
	ORR	r2, r2, r1, LSR #28
	BFC	r9, #28, #4
	SUB	r0, r0, #0x1c
	/* Add order times bits 504..511 */
	MOV	r10, #0x2c13
	MOVT	r10, #0xa30a
	MOV	r11, #0x9ce5
	MOVT	r11, #0xa7ed
	MOV	r1, #0x0
	UMLAL	r2, r1, r10, lr
	UMAAL	r3, r1, r11, lr
	MOV	r10, #0x6329
	MOVT	r10, #0x5d08
	MOV	r11, #0x621
	MOVT	r11, #0xeb21
	UMAAL	r4, r1, r10, lr
	UMAAL	r5, r1, r11, lr
	ADDS	r6, r6, r1
	ADCS	r7, r7, #0x0
	ADCS	r8, r8, #0x0
	ADC	r9, r9, #0x0
	SUBS	r6, r6, lr
	SBCS	r7, r7, #0x0
	SBCS	r8, r8, #0x0
	SBC	r9, r9, #0x0
	/* Sub product of top 8 words and order */
	MOV	r12, sp
	MOV	r1, #0x2c13
	MOVT	r1, #0xa30a
	MOV	lr, #0x0
	LDM	r0!, {r10, r11}
	UMLAL	r10, lr, r2, r1
	UMAAL	r11, lr, r3, r1
	STM	r12!, {r10, r11}
	LDM	r0!, {r10, r11}
	UMAAL	r10, lr, r4, r1
	UMAAL	r11, lr, r5, r1
	STM	r12!, {r10, r11}
	LDM	r0!, {r10, r11}
	UMAAL	r10, lr, r6, r1
	UMAAL	r11, lr, r7, r1
	STM	r12!, {r10, r11}
	LDM	r0!, {r10, r11}
	UMAAL	r10, lr, r8, r1
	BFC	r11, #28, #4
	UMAAL	r11, lr, r9, r1
	STM	r12!, {r10, r11, lr}
	SUB	r0, r0, #0x10
	SUB	r12, r12, #0x20
	MOV	r1, #0x9ce5
	MOVT	r1, #0xa7ed
	MOV	lr, #0x0
	LDM	r12, {r10, r11}
	UMLAL	r10, lr, r2, r1
	UMAAL	r11, lr, r3, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	UMAAL	r10, lr, r4, r1
	UMAAL	r11, lr, r5, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	UMAAL	r10, lr, r6, r1
	UMAAL	r11, lr, r7, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	UMAAL	r10, lr, r8, r1
	UMAAL	r11, lr, r9, r1
	STM	r12!, {r10, r11, lr}
	SUB	r12, r12, #0x20
	MOV	r1, #0x6329
	MOVT	r1, #0x5d08
	MOV	lr, #0x0
	LDM	r12, {r10, r11}
	UMLAL	r10, lr, r2, r1
	UMAAL	r11, lr, r3, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	UMAAL	r10, lr, r4, r1
	UMAAL	r11, lr, r5, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	UMAAL	r10, lr, r6, r1
	UMAAL	r11, lr, r7, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	UMAAL	r10, lr, r8, r1
	UMAAL	r11, lr, r9, r1
	STM	r12!, {r10, r11, lr}
	SUB	r12, r12, #0x20
	MOV	r1, #0x621
	MOVT	r1, #0xeb21
	MOV	lr, #0x0
	LDM	r12, {r10, r11}
	UMLAL	r10, lr, r2, r1
	UMAAL	r11, lr, r3, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	UMAAL	r10, lr, r4, r1
	UMAAL	r11, lr, r5, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	UMAAL	r10, lr, r6, r1
	UMAAL	r11, lr, r7, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	UMAAL	r10, lr, r8, r1
	UMAAL	r11, lr, r9, r1
	STM	r12!, {r10, r11, lr}
	SUB	r12, r12, #0x20
	/* Subtract at 4 * 32 */
	LDM	r12, {r10, r11}
	SUBS	r10, r10, r2
	SBCS	r11, r11, r3
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	SBCS	r10, r10, r4
	SBCS	r11, r11, r5
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	SBCS	r10, r10, r6
	SBCS	r11, r11, r7
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	SBCS	r10, r10, r8
	SBC	r11, r11, r9
	STM	r12!, {r10, r11}
	SUB	r12, r12, #0x24
	ASR	lr, r11, #25
	/* Conditionally subtract order starting at bit 125 */
	MOV	r1, #0xa0000000
	MOV	r2, #0xba7d
	MOVT	r2, #0x4b9e
	MOV	r3, #0x4c63
	MOVT	r3, #0xcb02
	MOV	r4, #0xf39a
	MOVT	r4, #0xd45e
	MOV	r5, #0xdf3b
	MOVT	r5, #0x29b
	MOV	r9, #0x2000000
	AND	r1, r1, lr
	AND	r2, r2, lr
	AND	r3, r3, lr
	AND	r4, r4, lr
	AND	r5, r5, lr
	AND	r9, r9, lr
	LDM	r12, {r10, r11}
	ADDS	r10, r10, r1
	ADCS	r11, r11, r2
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADCS	r10, r10, r3
	ADCS	r11, r11, r4
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADCS	r10, r10, r5
	ADCS	r11, r11, #0x0
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADCS	r10, r10, #0x0
	ADCS	r11, r11, #0x0
	STM	r12!, {r10, r11}
	LDM	r12, {r10}
	ADCS	r10, r10, #0x0
	STM	r12!, {r10}
	SUB	r0, r0, #0x10
	MOV	r12, sp
	/* Load bits 252-376 */
	ADD	r12, r12, #0x1c
	LDM	r12, {r1, r2, r3, r4, r5}
	LSL	r5, r5, #4
	ORR	r5, r5, r4, LSR #28
	LSL	r4, r4, #4
	ORR	r4, r4, r3, LSR #28
	LSL	r3, r3, #4
	ORR	r3, r3, r2, LSR #28
	LSL	r2, r2, #4
	ORR	r2, r2, r1, LSR #28
	BFC	r5, #29, #3
	SUB	r12, r12, #0x1c
	/* Sub product of top 4 words and order */
	MOV	r0, sp
	/*   * -5cf5d3ed */
	MOV	r1, #0x2c13
	MOVT	r1, #0xa30a
	MOV	lr, #0x0
	LDM	r0, {r6, r7, r8, r9}
	UMLAL	r6, lr, r2, r1
	UMAAL	r7, lr, r3, r1
	UMAAL	r8, lr, r4, r1
	UMAAL	r9, lr, r5, r1
	STM	r0, {r6, r7, r8, r9}
	ADD	r0, r0, #0x4
	/*   * -5812631b */
	MOV	r1, #0x9ce5
	MOVT	r1, #0xa7ed
	MOV	r10, #0x0
	LDM	r0, {r6, r7, r8, r9}
	UMLAL	r6, r10, r2, r1
	UMAAL	r7, r10, r3, r1
	UMAAL	r8, r10, r4, r1
	UMAAL	r9, r10, r5, r1
	STM	r0, {r6, r7, r8, r9}
	ADD	r0, r0, #0x4
	/*   * -a2f79cd7 */
	MOV	r1, #0x6329
	MOVT	r1, #0x5d08
	MOV	r11, #0x0
	LDM	r0, {r6, r7, r8, r9}
	UMLAL	r6, r11, r2, r1
	UMAAL	r7, r11, r3, r1
	UMAAL	r8, r11, r4, r1
	UMAAL	r9, r11, r5, r1
	STM	r0, {r6, r7, r8, r9}
	ADD	r0, r0, #0x4
	/*   * -14def9df */
	MOV	r1, #0x621
	MOVT	r1, #0xeb21
	MOV	r12, #0x0
	LDM	r0, {r6, r7, r8, r9}
	UMLAL	r6, r12, r2, r1
	UMAAL	r7, r12, r3, r1
	UMAAL	r8, r12, r4, r1
	UMAAL	r9, r12, r5, r1
	STM	r0, {r6, r7, r8, r9}
	ADD	r0, r0, #0x4
	/* Add overflows at 4 * 32 */
	LDM	r0, {r6, r7, r8, r9}
	BFC	r9, #28, #4
	ADDS	r6, r6, lr
	ADCS	r7, r7, r10
	ADCS	r8, r8, r11
	ADC	r9, r9, r12
	/* Subtract top at 4 * 32 */
	SUBS	r6, r6, r2
	SBCS	r7, r7, r3
	SBCS	r8, r8, r4
	SBCS	r9, r9, r5
	SBC	r1, r1, r1
	SUB	r0, r0, #0x10
	LDM	r0, {r2, r3, r4, r5}
	MOV	r10, #0xd3ed
	MOVT	r10, #0x5cf5
	MOV	r11, #0x631a
	MOVT	r11, #0x5812
	MOV	r12, #0x9cd6
	MOVT	r12, #0xa2f7
	MOV	lr, #0xf9de
	MOVT	lr, #0x14de
	AND	r10, r10, r1
	AND	r11, r11, r1
	AND	r12, r12, r1
	AND	lr, lr, r1
	ADDS	r2, r2, r10
	ADCS	r3, r3, r11
	ADCS	r4, r4, r12
	ADCS	r5, r5, lr
	ADCS	r6, r6, #0x0
	ADCS	r7, r7, #0x0
	AND	r1, r1, #0x10000000
	ADCS	r8, r8, #0x0
	ADC	r9, r9, r1
	BFC	r9, #28, #4
	/* Store result */
	LDR	r0, [sp, #52]
	STM	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	ADD	sp, sp, #0x38
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 502 */
	.size	sc_reduce,.-sc_reduce
#endif /* WOLFSSL_ARM_ARCH_7M */
#ifdef HAVE_ED25519_SIGN
#ifdef WOLFSSL_ARM_ARCH_7M
	.text
	.align	4
	.globl	sc_muladd
	.type	sc_muladd, %function
sc_muladd:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0x50
	ADD	lr, sp, #0x44
	STM	lr, {r0, r1, r3}
	MOV	r0, #0x0
	LDR	r12, [r1]
	/* A[0] * B[0] */
	LDR	lr, [r2]
	UMULL	r3, r4, r12, lr
	/* A[0] * B[2] */
	LDR	lr, [r2, #8]
	UMULL	r5, r6, r12, lr
	/* A[0] * B[4] */
	LDR	lr, [r2, #16]
	UMULL	r7, r8, r12, lr
	/* A[0] * B[6] */
	LDR	lr, [r2, #24]
	UMULL	r9, r10, r12, lr
	STR	r3, [sp]
	/* A[0] * B[1] */
	LDR	lr, [r2, #4]
	MOV	r11, r0
	UMLAL	r4, r11, r12, lr
	ADDS	r5, r5, r11
	/* A[0] * B[3] */
	LDR	lr, [r2, #12]
	ADCS	r6, r6, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r6, r11, r12, lr
	ADDS	r7, r7, r11
	/* A[0] * B[5] */
	LDR	lr, [r2, #20]
	ADCS	r8, r8, #0x0
	ADC	r11, r0, #0x0
	UMLAL	r8, r11, r12, lr
	ADDS	r9, r9, r11
	/* A[0] * B[7] */
	LDR	lr, [r2, #28]
	ADCS	r10, r10, #0x0
	ADC	r3, r0, #0x0
	UMLAL	r10, r3, r12, lr
	/* A[1] * B[0] */
	LDR	r12, [r1, #4]
	LDR	lr, [r2]
	MOV	r11, #0x0
	UMLAL	r4, r11, r12, lr
	STR	r4, [sp, #4]
	ADDS	r5, r5, r11
	/* A[1] * B[1] */
	LDR	lr, [r2, #4]
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r12, lr
	ADDS	r6, r6, r11
	/* A[1] * B[2] */
	LDR	lr, [r2, #8]
	ADC	r11, r0, #0x0
	UMLAL	r6, r11, r12, lr
	ADDS	r7, r7, r11
	/* A[1] * B[3] */
	LDR	lr, [r2, #12]
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r12, lr
	ADDS	r8, r8, r11
	/* A[1] * B[4] */
	LDR	lr, [r2, #16]
	ADC	r11, r0, #0x0
	UMLAL	r8, r11, r12, lr
	ADDS	r9, r9, r11
	/* A[1] * B[5] */
	LDR	lr, [r2, #20]
	ADC	r11, r0, #0x0
	UMLAL	r9, r11, r12, lr
	ADDS	r10, r10, r11
	/* A[1] * B[6] */
	LDR	lr, [r2, #24]
	ADC	r11, r0, #0x0
	UMLAL	r10, r11, r12, lr
	ADDS	r3, r3, r11
	/* A[1] * B[7] */
	LDR	lr, [r2, #28]
	ADC	r4, r0, #0x0
	UMLAL	r3, r4, r12, lr
	/* A[2] * B[0] */
	LDR	r12, [r1, #8]
	LDR	lr, [r2]
	MOV	r11, #0x0
	UMLAL	r5, r11, r12, lr
	STR	r5, [sp, #8]
	ADDS	r6, r6, r11
	/* A[2] * B[1] */
	LDR	lr, [r2, #4]
	ADC	r11, r0, #0x0
	UMLAL	r6, r11, r12, lr
	ADDS	r7, r7, r11
	/* A[2] * B[2] */
	LDR	lr, [r2, #8]
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r12, lr
	ADDS	r8, r8, r11
	/* A[2] * B[3] */
	LDR	lr, [r2, #12]
	ADC	r11, r0, #0x0
	UMLAL	r8, r11, r12, lr
	ADDS	r9, r9, r11
	/* A[2] * B[4] */
	LDR	lr, [r2, #16]
	ADC	r11, r0, #0x0
	UMLAL	r9, r11, r12, lr
	ADDS	r10, r10, r11
	/* A[2] * B[5] */
	LDR	lr, [r2, #20]
	ADC	r11, r0, #0x0
	UMLAL	r10, r11, r12, lr
	ADDS	r3, r3, r11
	/* A[2] * B[6] */
	LDR	lr, [r2, #24]
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r12, lr
	ADDS	r4, r4, r11
	/* A[2] * B[7] */
	LDR	lr, [r2, #28]
	ADC	r5, r0, #0x0
	UMLAL	r4, r5, r12, lr
	/* A[3] * B[0] */
	LDR	r12, [r1, #12]
	LDR	lr, [r2]
	MOV	r11, #0x0
	UMLAL	r6, r11, r12, lr
	STR	r6, [sp, #12]
	ADDS	r7, r7, r11
	/* A[3] * B[1] */
	LDR	lr, [r2, #4]
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r12, lr
	ADDS	r8, r8, r11
	/* A[3] * B[2] */
	LDR	lr, [r2, #8]
	ADC	r11, r0, #0x0
	UMLAL	r8, r11, r12, lr
	ADDS	r9, r9, r11
	/* A[3] * B[3] */
	LDR	lr, [r2, #12]
	ADC	r11, r0, #0x0
	UMLAL	r9, r11, r12, lr
	ADDS	r10, r10, r11
	/* A[3] * B[4] */
	LDR	lr, [r2, #16]
	ADC	r11, r0, #0x0
	UMLAL	r10, r11, r12, lr
	ADDS	r3, r3, r11
	/* A[3] * B[5] */
	LDR	lr, [r2, #20]
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r12, lr
	ADDS	r4, r4, r11
	/* A[3] * B[6] */
	LDR	lr, [r2, #24]
	ADC	r11, r0, #0x0
	UMLAL	r4, r11, r12, lr
	ADDS	r5, r5, r11
	/* A[3] * B[7] */
	LDR	lr, [r2, #28]
	ADC	r6, r0, #0x0
	UMLAL	r5, r6, r12, lr
	/* A[4] * B[0] */
	LDR	r12, [r1, #16]
	LDR	lr, [r2]
	MOV	r11, #0x0
	UMLAL	r7, r11, r12, lr
	STR	r7, [sp, #16]
	ADDS	r8, r8, r11
	/* A[4] * B[1] */
	LDR	lr, [r2, #4]
	ADC	r11, r0, #0x0
	UMLAL	r8, r11, r12, lr
	ADDS	r9, r9, r11
	/* A[4] * B[2] */
	LDR	lr, [r2, #8]
	ADC	r11, r0, #0x0
	UMLAL	r9, r11, r12, lr
	ADDS	r10, r10, r11
	/* A[4] * B[3] */
	LDR	lr, [r2, #12]
	ADC	r11, r0, #0x0
	UMLAL	r10, r11, r12, lr
	ADDS	r3, r3, r11
	/* A[4] * B[4] */
	LDR	lr, [r2, #16]
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r12, lr
	ADDS	r4, r4, r11
	/* A[4] * B[5] */
	LDR	lr, [r2, #20]
	ADC	r11, r0, #0x0
	UMLAL	r4, r11, r12, lr
	ADDS	r5, r5, r11
	/* A[4] * B[6] */
	LDR	lr, [r2, #24]
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r12, lr
	ADDS	r6, r6, r11
	/* A[4] * B[7] */
	LDR	lr, [r2, #28]
	ADC	r7, r0, #0x0
	UMLAL	r6, r7, r12, lr
	/* A[5] * B[0] */
	LDR	r12, [r1, #20]
	LDR	lr, [r2]
	MOV	r11, #0x0
	UMLAL	r8, r11, r12, lr
	STR	r8, [sp, #20]
	ADDS	r9, r9, r11
	/* A[5] * B[1] */
	LDR	lr, [r2, #4]
	ADC	r11, r0, #0x0
	UMLAL	r9, r11, r12, lr
	ADDS	r10, r10, r11
	/* A[5] * B[2] */
	LDR	lr, [r2, #8]
	ADC	r11, r0, #0x0
	UMLAL	r10, r11, r12, lr
	ADDS	r3, r3, r11
	/* A[5] * B[3] */
	LDR	lr, [r2, #12]
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r12, lr
	ADDS	r4, r4, r11
	/* A[5] * B[4] */
	LDR	lr, [r2, #16]
	ADC	r11, r0, #0x0
	UMLAL	r4, r11, r12, lr
	ADDS	r5, r5, r11
	/* A[5] * B[5] */
	LDR	lr, [r2, #20]
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r12, lr
	ADDS	r6, r6, r11
	/* A[5] * B[6] */
	LDR	lr, [r2, #24]
	ADC	r11, r0, #0x0
	UMLAL	r6, r11, r12, lr
	ADDS	r7, r7, r11
	/* A[5] * B[7] */
	LDR	lr, [r2, #28]
	ADC	r8, r0, #0x0
	UMLAL	r7, r8, r12, lr
	/* A[6] * B[0] */
	LDR	r12, [r1, #24]
	LDR	lr, [r2]
	MOV	r11, #0x0
	UMLAL	r9, r11, r12, lr
	STR	r9, [sp, #24]
	ADDS	r10, r10, r11
	/* A[6] * B[1] */
	LDR	lr, [r2, #4]
	ADC	r11, r0, #0x0
	UMLAL	r10, r11, r12, lr
	ADDS	r3, r3, r11
	/* A[6] * B[2] */
	LDR	lr, [r2, #8]
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r12, lr
	ADDS	r4, r4, r11
	/* A[6] * B[3] */
	LDR	lr, [r2, #12]
	ADC	r11, r0, #0x0
	UMLAL	r4, r11, r12, lr
	ADDS	r5, r5, r11
	/* A[6] * B[4] */
	LDR	lr, [r2, #16]
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r12, lr
	ADDS	r6, r6, r11
	/* A[6] * B[5] */
	LDR	lr, [r2, #20]
	ADC	r11, r0, #0x0
	UMLAL	r6, r11, r12, lr
	ADDS	r7, r7, r11
	/* A[6] * B[6] */
	LDR	lr, [r2, #24]
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r12, lr
	ADDS	r8, r8, r11
	/* A[6] * B[7] */
	LDR	lr, [r2, #28]
	ADC	r9, r0, #0x0
	UMLAL	r8, r9, r12, lr
	/* A[7] * B[0] */
	LDR	r12, [r1, #28]
	LDR	lr, [r2]
	MOV	r11, #0x0
	UMLAL	r10, r11, r12, lr
	STR	r10, [sp, #28]
	ADDS	r3, r3, r11
	/* A[7] * B[1] */
	LDR	lr, [r2, #4]
	ADC	r11, r0, #0x0
	UMLAL	r3, r11, r12, lr
	ADDS	r4, r4, r11
	/* A[7] * B[2] */
	LDR	lr, [r2, #8]
	ADC	r11, r0, #0x0
	UMLAL	r4, r11, r12, lr
	ADDS	r5, r5, r11
	/* A[7] * B[3] */
	LDR	lr, [r2, #12]
	ADC	r11, r0, #0x0
	UMLAL	r5, r11, r12, lr
	ADDS	r6, r6, r11
	/* A[7] * B[4] */
	LDR	lr, [r2, #16]
	ADC	r11, r0, #0x0
	UMLAL	r6, r11, r12, lr
	ADDS	r7, r7, r11
	/* A[7] * B[5] */
	LDR	lr, [r2, #20]
	ADC	r11, r0, #0x0
	UMLAL	r7, r11, r12, lr
	ADDS	r8, r8, r11
	/* A[7] * B[6] */
	LDR	lr, [r2, #24]
	ADC	r11, r0, #0x0
	UMLAL	r8, r11, r12, lr
	ADDS	r9, r9, r11
	/* A[7] * B[7] */
	LDR	lr, [r2, #28]
	ADC	r10, r0, #0x0
	UMLAL	r9, r10, r12, lr
	ADD	lr, sp, #0x20
	STM	lr, {r3, r4, r5, r6, r7, r8, r9, r10}
	MOV	r0, sp
	/* Add c to a * b */
	LDR	lr, [sp, #76]
	LDM	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	LDM	lr!, {r1, r10, r11, r12}
	ADDS	r2, r2, r1
	ADCS	r3, r3, r10
	ADCS	r4, r4, r11
	ADCS	r5, r5, r12
	LDM	lr!, {r1, r10, r11, r12}
	ADCS	r6, r6, r1
	ADCS	r7, r7, r10
	ADCS	r8, r8, r11
	ADCS	r9, r9, r12
	MOV	r1, r9
	STM	r0!, {r2, r3, r4, r5, r6, r7, r8, r9}
	LDM	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	ADCS	r2, r2, #0x0
	ADCS	r3, r3, #0x0
	ADCS	r4, r4, #0x0
	ADCS	r5, r5, #0x0
	ADCS	r6, r6, #0x0
	ADCS	r7, r7, #0x0
	ADCS	r8, r8, #0x0
	ADC	r9, r9, #0x0
	SUB	r0, r0, #0x20
	/* Get 252..503 and 504..507 */
	LSR	lr, r9, #24
	LSL	r9, r9, #4
	ORR	r9, r9, r8, LSR #28
	LSL	r8, r8, #4
	ORR	r8, r8, r7, LSR #28
	LSL	r7, r7, #4
	ORR	r7, r7, r6, LSR #28
	LSL	r6, r6, #4
	ORR	r6, r6, r5, LSR #28
	LSL	r5, r5, #4
	ORR	r5, r5, r4, LSR #28
	LSL	r4, r4, #4
	ORR	r4, r4, r3, LSR #28
	LSL	r3, r3, #4
	ORR	r3, r3, r2, LSR #28
	LSL	r2, r2, #4
	ORR	r2, r2, r1, LSR #28
	BFC	r9, #28, #4
	/* Add order times bits 504..507 */
	MOV	r10, #0x2c13
	MOVT	r10, #0xa30a
	MOV	r11, #0x9ce5
	MOVT	r11, #0xa7ed
	MOV	r1, #0x0
	UMLAL	r2, r1, r10, lr
	ADDS	r3, r3, r1
	MOV	r1, #0x0
	ADC	r1, r1, #0x0
	UMLAL	r3, r1, r11, lr
	MOV	r10, #0x6329
	MOVT	r10, #0x5d08
	MOV	r11, #0x621
	MOVT	r11, #0xeb21
	ADDS	r4, r4, r1
	MOV	r1, #0x0
	ADC	r1, r1, #0x0
	UMLAL	r4, r1, r10, lr
	ADDS	r5, r5, r1
	MOV	r1, #0x0
	ADC	r1, r1, #0x0
	UMLAL	r5, r1, r11, lr
	ADDS	r6, r6, r1
	ADCS	r7, r7, #0x0
	ADCS	r8, r8, #0x0
	ADC	r9, r9, #0x0
	SUBS	r6, r6, lr
	SBCS	r7, r7, #0x0
	SBCS	r8, r8, #0x0
	SBC	r9, r9, #0x0
	/* Sub product of top 8 words and order */
	MOV	r12, sp
	MOV	r1, #0x2c13
	MOVT	r1, #0xa30a
	MOV	lr, #0x0
	LDM	r0!, {r10, r11}
	UMLAL	r10, lr, r2, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r3, r1
	STM	r12!, {r10, r11}
	LDM	r0!, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r4, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r5, r1
	STM	r12!, {r10, r11}
	LDM	r0!, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r6, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r7, r1
	STM	r12!, {r10, r11}
	LDM	r0!, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r8, r1
	BFC	r11, #28, #4
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r9, r1
	STM	r12!, {r10, r11, lr}
	SUB	r0, r0, #0x10
	SUB	r12, r12, #0x20
	MOV	r1, #0x9ce5
	MOVT	r1, #0xa7ed
	MOV	lr, #0x0
	LDM	r12, {r10, r11}
	UMLAL	r10, lr, r2, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r3, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r4, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r5, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r6, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r7, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r8, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r9, r1
	STM	r12!, {r10, r11, lr}
	SUB	r12, r12, #0x20
	MOV	r1, #0x6329
	MOVT	r1, #0x5d08
	MOV	lr, #0x0
	LDM	r12, {r10, r11}
	UMLAL	r10, lr, r2, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r3, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r4, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r5, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r6, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r7, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r8, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r9, r1
	STM	r12!, {r10, r11, lr}
	SUB	r12, r12, #0x20
	MOV	r1, #0x621
	MOVT	r1, #0xeb21
	MOV	lr, #0x0
	LDM	r12, {r10, r11}
	UMLAL	r10, lr, r2, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r3, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r4, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r5, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r6, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r7, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADDS	r10, r10, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r10, lr, r8, r1
	ADDS	r11, r11, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r11, lr, r9, r1
	STM	r12!, {r10, r11, lr}
	SUB	r12, r12, #0x20
	/* Subtract at 4 * 32 */
	LDM	r12, {r10, r11}
	SUBS	r10, r10, r2
	SBCS	r11, r11, r3
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	SBCS	r10, r10, r4
	SBCS	r11, r11, r5
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	SBCS	r10, r10, r6
	SBCS	r11, r11, r7
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	SBCS	r10, r10, r8
	SBC	r11, r11, r9
	STM	r12!, {r10, r11}
	SUB	r12, r12, #0x24
	ASR	lr, r11, #25
	/* Conditionally subtract order starting at bit 125 */
	MOV	r1, #0xa0000000
	MOV	r2, #0xba7d
	MOVT	r2, #0x4b9e
	MOV	r3, #0x4c63
	MOVT	r3, #0xcb02
	MOV	r4, #0xf39a
	MOVT	r4, #0xd45e
	MOV	r5, #0xdf3b
	MOVT	r5, #0x29b
	MOV	r9, #0x2000000
	AND	r1, r1, lr
	AND	r2, r2, lr
	AND	r3, r3, lr
	AND	r4, r4, lr
	AND	r5, r5, lr
	AND	r9, r9, lr
	LDM	r12, {r10, r11}
	ADDS	r10, r10, r1
	ADCS	r11, r11, r2
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADCS	r10, r10, r3
	ADCS	r11, r11, r4
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADCS	r10, r10, r5
	ADCS	r11, r11, #0x0
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADCS	r10, r10, #0x0
	ADCS	r11, r11, #0x0
	STM	r12!, {r10, r11}
	LDM	r12, {r10}
	ADCS	r10, r10, #0x0
	STM	r12!, {r10}
	SUB	r0, r0, #0x10
	MOV	r12, sp
	/* Load bits 252-376 */
	ADD	r12, r12, #0x1c
	LDM	r12, {r1, r2, r3, r4, r5}
	LSL	r5, r5, #4
	ORR	r5, r5, r4, LSR #28
	LSL	r4, r4, #4
	ORR	r4, r4, r3, LSR #28
	LSL	r3, r3, #4
	ORR	r3, r3, r2, LSR #28
	LSL	r2, r2, #4
	ORR	r2, r2, r1, LSR #28
	BFC	r5, #29, #3
	SUB	r12, r12, #0x1c
	/* Sub product of top 4 words and order */
	MOV	r0, sp
	/*   * -5cf5d3ed */
	MOV	r1, #0x2c13
	MOVT	r1, #0xa30a
	MOV	lr, #0x0
	LDM	r0, {r6, r7, r8, r9}
	UMLAL	r6, lr, r2, r1
	ADDS	r7, r7, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r7, lr, r3, r1
	ADDS	r8, r8, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r8, lr, r4, r1
	ADDS	r9, r9, lr
	MOV	lr, #0x0
	ADC	lr, lr, #0x0
	UMLAL	r9, lr, r5, r1
	STM	r0, {r6, r7, r8, r9}
	ADD	r0, r0, #0x4
	/*   * -5812631b */
	MOV	r1, #0x9ce5
	MOVT	r1, #0xa7ed
	MOV	r10, #0x0
	LDM	r0, {r6, r7, r8, r9}
	UMLAL	r6, r10, r2, r1
	ADDS	r7, r7, r10
	MOV	r10, #0x0
	ADC	r10, r10, #0x0
	UMLAL	r7, r10, r3, r1
	ADDS	r8, r8, r10
	MOV	r10, #0x0
	ADC	r10, r10, #0x0
	UMLAL	r8, r10, r4, r1
	ADDS	r9, r9, r10
	MOV	r10, #0x0
	ADC	r10, r10, #0x0
	UMLAL	r9, r10, r5, r1
	STM	r0, {r6, r7, r8, r9}
	ADD	r0, r0, #0x4
	/*   * -a2f79cd7 */
	MOV	r1, #0x6329
	MOVT	r1, #0x5d08
	MOV	r11, #0x0
	LDM	r0, {r6, r7, r8, r9}
	UMLAL	r6, r11, r2, r1
	ADDS	r7, r7, r11
	MOV	r11, #0x0
	ADC	r11, r11, #0x0
	UMLAL	r7, r11, r3, r1
	ADDS	r8, r8, r11
	MOV	r11, #0x0
	ADC	r11, r11, #0x0
	UMLAL	r8, r11, r4, r1
	ADDS	r9, r9, r11
	MOV	r11, #0x0
	ADC	r11, r11, #0x0
	UMLAL	r9, r11, r5, r1
	STM	r0, {r6, r7, r8, r9}
	ADD	r0, r0, #0x4
	/*   * -14def9df */
	MOV	r1, #0x621
	MOVT	r1, #0xeb21
	MOV	r12, #0x0
	LDM	r0, {r6, r7, r8, r9}
	UMLAL	r6, r12, r2, r1
	ADDS	r7, r7, r12
	MOV	r12, #0x0
	ADC	r12, r12, #0x0
	UMLAL	r7, r12, r3, r1
	ADDS	r8, r8, r12
	MOV	r12, #0x0
	ADC	r12, r12, #0x0
	UMLAL	r8, r12, r4, r1
	ADDS	r9, r9, r12
	MOV	r12, #0x0
	ADC	r12, r12, #0x0
	UMLAL	r9, r12, r5, r1
	STM	r0, {r6, r7, r8, r9}
	ADD	r0, r0, #0x4
	/* Add overflows at 4 * 32 */
	LDM	r0, {r6, r7, r8, r9}
	BFC	r9, #28, #4
	ADDS	r6, r6, lr
	ADCS	r7, r7, r10
	ADCS	r8, r8, r11
	ADC	r9, r9, r12
	/* Subtract top at 4 * 32 */
	SUBS	r6, r6, r2
	SBCS	r7, r7, r3
	SBCS	r8, r8, r4
	SBCS	r9, r9, r5
	SBC	r1, r1, r1
	SUB	r0, r0, #0x10
	LDM	r0, {r2, r3, r4, r5}
	MOV	r10, #0xd3ed
	MOVT	r10, #0x5cf5
	MOV	r11, #0x631a
	MOVT	r11, #0x5812
	MOV	r12, #0x9cd6
	MOVT	r12, #0xa2f7
	MOV	lr, #0xf9de
	MOVT	lr, #0x14de
	AND	r10, r10, r1
	AND	r11, r11, r1
	AND	r12, r12, r1
	AND	lr, lr, r1
	ADDS	r2, r2, r10
	ADCS	r3, r3, r11
	ADCS	r4, r4, r12
	ADCS	r5, r5, lr
	ADCS	r6, r6, #0x0
	ADCS	r7, r7, #0x0
	AND	r1, r1, #0x10000000
	ADCS	r8, r8, #0x0
	ADC	r9, r9, r1
	BFC	r9, #28, #4
	LDR	r0, [sp, #68]
	/* Store result */
	STR	r2, [r0]
	STR	r3, [r0, #4]
	STR	r4, [r0, #8]
	STR	r5, [r0, #12]
	STR	r6, [r0, #16]
	STR	r7, [r0, #20]
	STR	r8, [r0, #24]
	STR	r9, [r0, #28]
	ADD	sp, sp, #0x50
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 994 */
	.size	sc_muladd,.-sc_muladd
#else
	.text
	.align	4
	.globl	sc_muladd
	.type	sc_muladd, %function
sc_muladd:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0x50
	ADD	lr, sp, #0x44
	STM	lr, {r0, r1, r3}
	MOV	lr, r2
	LDM	r1, {r0, r1, r2, r3}
	LDM	lr!, {r4, r5, r6}
	UMULL	r10, r11, r0, r4
	UMULL	r12, r7, r1, r4
	UMAAL	r11, r12, r0, r5
	UMULL	r8, r9, r2, r4
	UMAAL	r12, r8, r1, r5
	UMAAL	r12, r7, r0, r6
	UMAAL	r8, r9, r3, r4
	STM	sp, {r10, r11, r12}
	UMAAL	r7, r8, r2, r5
	LDM	lr!, {r4}
	UMULL	r10, r11, r1, r6
	UMAAL	r8, r9, r2, r6
	UMAAL	r7, r10, r0, r4
	UMAAL	r8, r11, r3, r5
	STR	r7, [sp, #12]
	UMAAL	r8, r10, r1, r4
	UMAAL	r9, r11, r3, r6
	UMAAL	r9, r10, r2, r4
	UMAAL	r10, r11, r3, r4
	LDM	lr, {r4, r5, r6, r7}
	MOV	r12, #0x0
	UMLAL	r8, r12, r0, r4
	UMAAL	r9, r12, r1, r4
	UMAAL	r10, r12, r2, r4
	UMAAL	r11, r12, r3, r4
	MOV	r4, #0x0
	UMLAL	r9, r4, r0, r5
	UMAAL	r10, r4, r1, r5
	UMAAL	r11, r4, r2, r5
	UMAAL	r12, r4, r3, r5
	MOV	r5, #0x0
	UMLAL	r10, r5, r0, r6
	UMAAL	r11, r5, r1, r6
	UMAAL	r12, r5, r2, r6
	UMAAL	r4, r5, r3, r6
	MOV	r6, #0x0
	UMLAL	r11, r6, r0, r7
	LDR	r0, [sp, #72]
	UMAAL	r12, r6, r1, r7
	ADD	r0, r0, #0x10
	UMAAL	r4, r6, r2, r7
	SUB	lr, lr, #0x10
	UMAAL	r5, r6, r3, r7
	LDM	r0, {r0, r1, r2, r3}
	STR	r6, [sp, #64]
	LDM	lr!, {r6}
	MOV	r7, #0x0
	UMLAL	r8, r7, r0, r6
	UMAAL	r9, r7, r1, r6
	STR	r8, [sp, #16]
	UMAAL	r10, r7, r2, r6
	UMAAL	r11, r7, r3, r6
	LDM	lr!, {r6}
	MOV	r8, #0x0
	UMLAL	r9, r8, r0, r6
	UMAAL	r10, r8, r1, r6
	STR	r9, [sp, #20]
	UMAAL	r11, r8, r2, r6
	UMAAL	r12, r8, r3, r6
	LDM	lr!, {r6}
	MOV	r9, #0x0
	UMLAL	r10, r9, r0, r6
	UMAAL	r11, r9, r1, r6
	STR	r10, [sp, #24]
	UMAAL	r12, r9, r2, r6
	UMAAL	r4, r9, r3, r6
	LDM	lr!, {r6}
	MOV	r10, #0x0
	UMLAL	r11, r10, r0, r6
	UMAAL	r12, r10, r1, r6
	STR	r11, [sp, #28]
	UMAAL	r4, r10, r2, r6
	UMAAL	r5, r10, r3, r6
	LDM	lr!, {r11}
	UMAAL	r12, r7, r0, r11
	UMAAL	r4, r7, r1, r11
	LDR	r6, [sp, #64]
	UMAAL	r5, r7, r2, r11
	UMAAL	r6, r7, r3, r11
	LDM	lr!, {r11}
	UMAAL	r4, r8, r0, r11
	UMAAL	r5, r8, r1, r11
	UMAAL	r6, r8, r2, r11
	UMAAL	r7, r8, r3, r11
	LDM	lr, {r11, lr}
	UMAAL	r5, r9, r0, r11
	UMAAL	r6, r10, r0, lr
	UMAAL	r6, r9, r1, r11
	UMAAL	r7, r10, r1, lr
	UMAAL	r7, r9, r2, r11
	UMAAL	r8, r10, r2, lr
	UMAAL	r8, r9, r3, r11
	UMAAL	r9, r10, r3, lr
	MOV	r3, r12
	ADD	lr, sp, #0x20
	STM	lr, {r3, r4, r5, r6, r7, r8, r9, r10}
	MOV	r0, sp
	/* Add c to a * b */
	LDR	lr, [sp, #76]
	LDM	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	LDM	lr!, {r1, r10, r11, r12}
	ADDS	r2, r2, r1
	ADCS	r3, r3, r10
	ADCS	r4, r4, r11
	ADCS	r5, r5, r12
	LDM	lr!, {r1, r10, r11, r12}
	ADCS	r6, r6, r1
	ADCS	r7, r7, r10
	ADCS	r8, r8, r11
	ADCS	r9, r9, r12
	MOV	r1, r9
	STM	r0!, {r2, r3, r4, r5, r6, r7, r8, r9}
	LDM	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	ADCS	r2, r2, #0x0
	ADCS	r3, r3, #0x0
	ADCS	r4, r4, #0x0
	ADCS	r5, r5, #0x0
	ADCS	r6, r6, #0x0
	ADCS	r7, r7, #0x0
	ADCS	r8, r8, #0x0
	ADC	r9, r9, #0x0
	SUB	r0, r0, #0x20
	/* Get 252..503 and 504..507 */
	LSR	lr, r9, #24
	LSL	r9, r9, #4
	ORR	r9, r9, r8, LSR #28
	LSL	r8, r8, #4
	ORR	r8, r8, r7, LSR #28
	LSL	r7, r7, #4
	ORR	r7, r7, r6, LSR #28
	LSL	r6, r6, #4
	ORR	r6, r6, r5, LSR #28
	LSL	r5, r5, #4
	ORR	r5, r5, r4, LSR #28
	LSL	r4, r4, #4
	ORR	r4, r4, r3, LSR #28
	LSL	r3, r3, #4
	ORR	r3, r3, r2, LSR #28
	LSL	r2, r2, #4
	ORR	r2, r2, r1, LSR #28
	BFC	r9, #28, #4
	/* Add order times bits 504..507 */
	MOV	r10, #0x2c13
	MOVT	r10, #0xa30a
	MOV	r11, #0x9ce5
	MOVT	r11, #0xa7ed
	MOV	r1, #0x0
	UMLAL	r2, r1, r10, lr
	UMAAL	r3, r1, r11, lr
	MOV	r10, #0x6329
	MOVT	r10, #0x5d08
	MOV	r11, #0x621
	MOVT	r11, #0xeb21
	UMAAL	r4, r1, r10, lr
	UMAAL	r5, r1, r11, lr
	ADDS	r6, r6, r1
	ADCS	r7, r7, #0x0
	ADCS	r8, r8, #0x0
	ADC	r9, r9, #0x0
	SUBS	r6, r6, lr
	SBCS	r7, r7, #0x0
	SBCS	r8, r8, #0x0
	SBC	r9, r9, #0x0
	/* Sub product of top 8 words and order */
	MOV	r12, sp
	MOV	r1, #0x2c13
	MOVT	r1, #0xa30a
	MOV	lr, #0x0
	LDM	r0!, {r10, r11}
	UMLAL	r10, lr, r2, r1
	UMAAL	r11, lr, r3, r1
	STM	r12!, {r10, r11}
	LDM	r0!, {r10, r11}
	UMAAL	r10, lr, r4, r1
	UMAAL	r11, lr, r5, r1
	STM	r12!, {r10, r11}
	LDM	r0!, {r10, r11}
	UMAAL	r10, lr, r6, r1
	UMAAL	r11, lr, r7, r1
	STM	r12!, {r10, r11}
	LDM	r0!, {r10, r11}
	UMAAL	r10, lr, r8, r1
	BFC	r11, #28, #4
	UMAAL	r11, lr, r9, r1
	STM	r12!, {r10, r11, lr}
	SUB	r0, r0, #0x10
	SUB	r12, r12, #0x20
	MOV	r1, #0x9ce5
	MOVT	r1, #0xa7ed
	MOV	lr, #0x0
	LDM	r12, {r10, r11}
	UMLAL	r10, lr, r2, r1
	UMAAL	r11, lr, r3, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	UMAAL	r10, lr, r4, r1
	UMAAL	r11, lr, r5, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	UMAAL	r10, lr, r6, r1
	UMAAL	r11, lr, r7, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	UMAAL	r10, lr, r8, r1
	UMAAL	r11, lr, r9, r1
	STM	r12!, {r10, r11, lr}
	SUB	r12, r12, #0x20
	MOV	r1, #0x6329
	MOVT	r1, #0x5d08
	MOV	lr, #0x0
	LDM	r12, {r10, r11}
	UMLAL	r10, lr, r2, r1
	UMAAL	r11, lr, r3, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	UMAAL	r10, lr, r4, r1
	UMAAL	r11, lr, r5, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	UMAAL	r10, lr, r6, r1
	UMAAL	r11, lr, r7, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	UMAAL	r10, lr, r8, r1
	UMAAL	r11, lr, r9, r1
	STM	r12!, {r10, r11, lr}
	SUB	r12, r12, #0x20
	MOV	r1, #0x621
	MOVT	r1, #0xeb21
	MOV	lr, #0x0
	LDM	r12, {r10, r11}
	UMLAL	r10, lr, r2, r1
	UMAAL	r11, lr, r3, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	UMAAL	r10, lr, r4, r1
	UMAAL	r11, lr, r5, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	UMAAL	r10, lr, r6, r1
	UMAAL	r11, lr, r7, r1
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	UMAAL	r10, lr, r8, r1
	UMAAL	r11, lr, r9, r1
	STM	r12!, {r10, r11, lr}
	SUB	r12, r12, #0x20
	/* Subtract at 4 * 32 */
	LDM	r12, {r10, r11}
	SUBS	r10, r10, r2
	SBCS	r11, r11, r3
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	SBCS	r10, r10, r4
	SBCS	r11, r11, r5
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	SBCS	r10, r10, r6
	SBCS	r11, r11, r7
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	SBCS	r10, r10, r8
	SBC	r11, r11, r9
	STM	r12!, {r10, r11}
	SUB	r12, r12, #0x24
	ASR	lr, r11, #25
	/* Conditionally subtract order starting at bit 125 */
	MOV	r1, #0xa0000000
	MOV	r2, #0xba7d
	MOVT	r2, #0x4b9e
	MOV	r3, #0x4c63
	MOVT	r3, #0xcb02
	MOV	r4, #0xf39a
	MOVT	r4, #0xd45e
	MOV	r5, #0xdf3b
	MOVT	r5, #0x29b
	MOV	r9, #0x2000000
	AND	r1, r1, lr
	AND	r2, r2, lr
	AND	r3, r3, lr
	AND	r4, r4, lr
	AND	r5, r5, lr
	AND	r9, r9, lr
	LDM	r12, {r10, r11}
	ADDS	r10, r10, r1
	ADCS	r11, r11, r2
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADCS	r10, r10, r3
	ADCS	r11, r11, r4
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADCS	r10, r10, r5
	ADCS	r11, r11, #0x0
	STM	r12!, {r10, r11}
	LDM	r12, {r10, r11}
	ADCS	r10, r10, #0x0
	ADCS	r11, r11, #0x0
	STM	r12!, {r10, r11}
	LDM	r12, {r10}
	ADCS	r10, r10, #0x0
	STM	r12!, {r10}
	SUB	r0, r0, #0x10
	MOV	r12, sp
	/* Load bits 252-376 */
	ADD	r12, r12, #0x1c
	LDM	r12, {r1, r2, r3, r4, r5}
	LSL	r5, r5, #4
	ORR	r5, r5, r4, LSR #28
	LSL	r4, r4, #4
	ORR	r4, r4, r3, LSR #28
	LSL	r3, r3, #4
	ORR	r3, r3, r2, LSR #28
	LSL	r2, r2, #4
	ORR	r2, r2, r1, LSR #28
	BFC	r5, #29, #3
	SUB	r12, r12, #0x1c
	/* Sub product of top 4 words and order */
	MOV	r0, sp
	/*   * -5cf5d3ed */
	MOV	r1, #0x2c13
	MOVT	r1, #0xa30a
	MOV	lr, #0x0
	LDM	r0, {r6, r7, r8, r9}
	UMLAL	r6, lr, r2, r1
	UMAAL	r7, lr, r3, r1
	UMAAL	r8, lr, r4, r1
	UMAAL	r9, lr, r5, r1
	STM	r0, {r6, r7, r8, r9}
	ADD	r0, r0, #0x4
	/*   * -5812631b */
	MOV	r1, #0x9ce5
	MOVT	r1, #0xa7ed
	MOV	r10, #0x0
	LDM	r0, {r6, r7, r8, r9}
	UMLAL	r6, r10, r2, r1
	UMAAL	r7, r10, r3, r1
	UMAAL	r8, r10, r4, r1
	UMAAL	r9, r10, r5, r1
	STM	r0, {r6, r7, r8, r9}
	ADD	r0, r0, #0x4
	/*   * -a2f79cd7 */
	MOV	r1, #0x6329
	MOVT	r1, #0x5d08
	MOV	r11, #0x0
	LDM	r0, {r6, r7, r8, r9}
	UMLAL	r6, r11, r2, r1
	UMAAL	r7, r11, r3, r1
	UMAAL	r8, r11, r4, r1
	UMAAL	r9, r11, r5, r1
	STM	r0, {r6, r7, r8, r9}
	ADD	r0, r0, #0x4
	/*   * -14def9df */
	MOV	r1, #0x621
	MOVT	r1, #0xeb21
	MOV	r12, #0x0
	LDM	r0, {r6, r7, r8, r9}
	UMLAL	r6, r12, r2, r1
	UMAAL	r7, r12, r3, r1
	UMAAL	r8, r12, r4, r1
	UMAAL	r9, r12, r5, r1
	STM	r0, {r6, r7, r8, r9}
	ADD	r0, r0, #0x4
	/* Add overflows at 4 * 32 */
	LDM	r0, {r6, r7, r8, r9}
	BFC	r9, #28, #4
	ADDS	r6, r6, lr
	ADCS	r7, r7, r10
	ADCS	r8, r8, r11
	ADC	r9, r9, r12
	/* Subtract top at 4 * 32 */
	SUBS	r6, r6, r2
	SBCS	r7, r7, r3
	SBCS	r8, r8, r4
	SBCS	r9, r9, r5
	SBC	r1, r1, r1
	SUB	r0, r0, #0x10
	LDM	r0, {r2, r3, r4, r5}
	MOV	r10, #0xd3ed
	MOVT	r10, #0x5cf5
	MOV	r11, #0x631a
	MOVT	r11, #0x5812
	MOV	r12, #0x9cd6
	MOVT	r12, #0xa2f7
	MOV	lr, #0xf9de
	MOVT	lr, #0x14de
	AND	r10, r10, r1
	AND	r11, r11, r1
	AND	r12, r12, r1
	AND	lr, lr, r1
	ADDS	r2, r2, r10
	ADCS	r3, r3, r11
	ADCS	r4, r4, r12
	ADCS	r5, r5, lr
	ADCS	r6, r6, #0x0
	ADCS	r7, r7, #0x0
	AND	r1, r1, #0x10000000
	ADCS	r8, r8, #0x0
	ADC	r9, r9, r1
	BFC	r9, #28, #4
	LDR	r0, [sp, #68]
	/* Store result */
	STR	r2, [r0]
	STR	r3, [r0, #4]
	STR	r4, [r0, #8]
	STR	r5, [r0, #12]
	STR	r6, [r0, #16]
	STR	r7, [r0, #20]
	STR	r8, [r0, #24]
	STR	r9, [r0, #28]
	ADD	sp, sp, #0x50
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 752 */
	.size	sc_muladd,.-sc_muladd
#endif /* WOLFSSL_ARM_ARCH_7M */
#endif /* HAVE_ED25519_SIGN */
#endif /* HAVE_ED25519 */

#endif /* !CURVE25519_SMALL || !ED25519_SMALL */
#endif /* HAVE_CURVE25519 || HAVE_ED25519 */
#endif /* WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section        .note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
