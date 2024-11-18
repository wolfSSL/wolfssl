/* armv8-32-curve25519
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
 *   ruby ./x25519/x25519.rb arm32 ../wolfssl/wolfcrypt/src/port/arm/armv8-32-curve25519.S
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_ARMASM
#if !defined(__aarch64__) && defined(__arm__) && !defined(__thumb__)
#ifndef WOLFSSL_ARMASM_INLINE
#if defined(HAVE_CURVE25519) || defined(HAVE_ED25519)
#if !defined(CURVE25519_SMALL) || !defined(ED25519_SMALL)

	.text
	.align	4
	.globl	fe_init
	.type	fe_init, %function
fe_init:
	bx	lr
	.size	fe_init,.-fe_init
	.text
	.align	4
	.globl	fe_add_sub_op
	.type	fe_add_sub_op, %function
fe_add_sub_op:
	push	{lr}
	# Add-Sub
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r2]
	ldr	r5, [r2, #4]
#else
	ldrd	r4, r5, [r2]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3]
	ldr	r7, [r3, #4]
#else
	ldrd	r6, r7, [r3]
#endif
	#  Add
	adds	r8, r4, r6
	mov	r12, #0
	adcs	r9, r5, r7
	adc	r12, r12, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0]
	str	r9, [r0, #4]
#else
	strd	r8, r9, [r0]
#endif
	#  Sub
	subs	r10, r4, r6
	sbcs	r11, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [r1]
	str	r11, [r1, #4]
#else
	strd	r10, r11, [r1]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r2, #8]
	ldr	r5, [r2, #12]
#else
	ldrd	r4, r5, [r2, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #8]
	ldr	r7, [r3, #12]
#else
	ldrd	r6, r7, [r3, #8]
#endif
	#  Sub
	sbcs	r10, r4, r6
	mov	lr, #0
	sbcs	r11, r5, r7
	adc	lr, lr, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [r1, #8]
	str	r11, [r1, #12]
#else
	strd	r10, r11, [r1, #8]
#endif
	#  Add
	subs	r12, r12, #1
	adcs	r8, r4, r6
	adcs	r9, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #8]
	str	r9, [r0, #12]
#else
	strd	r8, r9, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r2, #16]
	ldr	r5, [r2, #20]
#else
	ldrd	r4, r5, [r2, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #16]
	ldr	r7, [r3, #20]
#else
	ldrd	r6, r7, [r3, #16]
#endif
	#  Add
	adcs	r8, r4, r6
	mov	r12, #0
	adcs	r9, r5, r7
	adc	r12, r12, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #16]
	str	r9, [r0, #20]
#else
	strd	r8, r9, [r0, #16]
#endif
	#  Sub
	subs	lr, lr, #1
	sbcs	r10, r4, r6
	sbcs	r11, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [r1, #16]
	str	r11, [r1, #20]
#else
	strd	r10, r11, [r1, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r2, #24]
	ldr	r5, [r2, #28]
#else
	ldrd	r4, r5, [r2, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #24]
	ldr	r7, [r3, #28]
#else
	ldrd	r6, r7, [r3, #24]
#endif
	#  Sub
	sbcs	r10, r4, r6
	sbcs	r11, r5, r7
	sbc	lr, lr, lr
	#  Add
	subs	r12, r12, #1
	adcs	r8, r4, r6
	mov	r12, #0
	adcs	r9, r5, r7
	adc	r12, r12, #0
	#   Multiply -modulus by overflow
	lsl	r3, r12, #1
	mov	r12, #19
	orr	r3, r3, r9, lsr #31
	mul	r12, r3, r12
	#   Add -x*modulus (if overflow)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0]
	ldr	r5, [r0, #4]
#else
	ldrd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
#else
	ldrd	r6, r7, [r0, #8]
#endif
	adds	r4, r4, r12
	adcs	r5, r5, #0
	adcs	r6, r6, #0
	adcs	r7, r7, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0]
	str	r5, [r0, #4]
#else
	strd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #8]
	str	r7, [r0, #12]
#else
	strd	r6, r7, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
	adcs	r4, r4, #0
	adcs	r5, r5, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #16]
	str	r5, [r0, #20]
#else
	strd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0x80000000
#else
	bfc	r9, #31, #1
#endif
	adcs	r8, r8, #0
	adc	r9, r9, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #24]
	str	r9, [r0, #28]
#else
	strd	r8, r9, [r0, #24]
#endif
	#   Multiply -modulus by underflow
	lsl	r3, lr, #1
	mvn	lr, #18
	orr	r3, r3, r11, lsr #31
	mul	lr, r3, lr
	#   Sub -x*modulus (if overflow)
	ldm	r1, {r4, r5, r6, r7, r8, r9}
	subs	r4, r4, lr
	sbcs	r5, r5, #0
	sbcs	r6, r6, #0
	sbcs	r7, r7, #0
	sbcs	r8, r8, #0
	sbcs	r9, r9, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r11, r11, #0x80000000
#else
	bfc	r11, #31, #1
#endif
	sbcs	r10, r10, #0
	sbc	r11, r11, #0
	stm	r1, {r4, r5, r6, r7, r8, r9, r10, r11}
	# Done Add-Sub
	pop	{pc}
	.size	fe_add_sub_op,.-fe_add_sub_op
	.text
	.align	4
	.globl	fe_sub_op
	.type	fe_sub_op, %function
fe_sub_op:
	push	{lr}
	# Sub
	ldm	r2!, {r6, r7, r8, r9, r10, r11, r12, lr}
	ldm	r1!, {r2, r3, r4, r5}
	subs	r6, r2, r6
	sbcs	r7, r3, r7
	sbcs	r8, r4, r8
	sbcs	r9, r5, r9
	ldm	r1!, {r2, r3, r4, r5}
	sbcs	r10, r2, r10
	sbcs	r11, r3, r11
	sbcs	r12, r4, r12
	sbcs	lr, r5, lr
	sbc	r3, r3, r3
	mvn	r2, #18
	lsl	r3, r3, #1
	orr	r3, r3, lr, lsr #31
	mul	r2, r3, r2
	subs	r6, r6, r2
	sbcs	r7, r7, #0
	sbcs	r8, r8, #0
	sbcs	r9, r9, #0
	sbcs	r10, r10, #0
	sbcs	r11, r11, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	lr, lr, #0x80000000
#else
	bfc	lr, #31, #1
#endif
	sbcs	r12, r12, #0
	sbc	lr, lr, #0
	stm	r0, {r6, r7, r8, r9, r10, r11, r12, lr}
	# Done Sub
	pop	{pc}
	.size	fe_sub_op,.-fe_sub_op
	.text
	.align	4
	.globl	fe_sub
	.type	fe_sub, %function
fe_sub:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	bl	fe_sub_op
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	fe_sub,.-fe_sub
	.text
	.align	4
	.globl	fe_add_op
	.type	fe_add_op, %function
fe_add_op:
	push	{lr}
	# Add
	ldm	r2!, {r6, r7, r8, r9, r10, r11, r12, lr}
	ldm	r1!, {r2, r3, r4, r5}
	adds	r6, r2, r6
	adcs	r7, r3, r7
	adcs	r8, r4, r8
	adcs	r9, r5, r9
	ldm	r1!, {r2, r3, r4, r5}
	adcs	r10, r2, r10
	adcs	r11, r3, r11
	adcs	r12, r4, r12
	mov	r3, #0
	adcs	lr, r5, lr
	adc	r3, r3, #0
	mov	r2, #19
	lsl	r3, r3, #1
	orr	r3, r3, lr, lsr #31
	mul	r2, r3, r2
	adds	r6, r6, r2
	adcs	r7, r7, #0
	adcs	r8, r8, #0
	adcs	r9, r9, #0
	adcs	r10, r10, #0
	adcs	r11, r11, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	lr, lr, #0x80000000
#else
	bfc	lr, #31, #1
#endif
	adcs	r12, r12, #0
	adc	lr, lr, #0
	stm	r0, {r6, r7, r8, r9, r10, r11, r12, lr}
	# Done Add
	pop	{pc}
	.size	fe_add_op,.-fe_add_op
	.text
	.align	4
	.globl	fe_add
	.type	fe_add, %function
fe_add:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	bl	fe_add_op
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	fe_add,.-fe_add
#ifdef HAVE_ED25519
	.text
	.align	4
	.globl	fe_frombytes
	.type	fe_frombytes, %function
fe_frombytes:
	push	{r4, r5, r6, r7, r8, r9, lr}
	ldr	r2, [r1]
	ldr	r3, [r1, #4]
	ldr	r4, [r1, #8]
	ldr	r5, [r1, #12]
	ldr	r6, [r1, #16]
	ldr	r7, [r1, #20]
	ldr	r8, [r1, #24]
	ldr	r9, [r1, #28]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0x80000000
#else
	bfc	r9, #31, #1
#endif
	str	r2, [r0]
	str	r3, [r0, #4]
	str	r4, [r0, #8]
	str	r5, [r0, #12]
	str	r6, [r0, #16]
	str	r7, [r0, #20]
	str	r8, [r0, #24]
	str	r9, [r0, #28]
	pop	{r4, r5, r6, r7, r8, r9, pc}
	.size	fe_frombytes,.-fe_frombytes
	.text
	.align	4
	.globl	fe_tobytes
	.type	fe_tobytes, %function
fe_tobytes:
	push	{r4, r5, r6, r7, r8, r9, lr}
	ldm	r1, {r2, r3, r4, r5, r6, r7, r8, r9}
	adds	r12, r2, #19
	adcs	r12, r3, #0
	adcs	r12, r4, #0
	adcs	r12, r5, #0
	adcs	r12, r6, #0
	adcs	r12, r7, #0
	adcs	r12, r8, #0
	adc	r12, r9, #0
	asr	r12, r12, #31
	and	r12, r12, #19
	adds	r2, r2, r12
	adcs	r3, r3, #0
	adcs	r4, r4, #0
	adcs	r5, r5, #0
	adcs	r6, r6, #0
	adcs	r7, r7, #0
	adcs	r8, r8, #0
	adc	r9, r9, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0x80000000
#else
	bfc	r9, #31, #1
#endif
	str	r2, [r0]
	str	r3, [r0, #4]
	str	r4, [r0, #8]
	str	r5, [r0, #12]
	str	r6, [r0, #16]
	str	r7, [r0, #20]
	str	r8, [r0, #24]
	str	r9, [r0, #28]
	pop	{r4, r5, r6, r7, r8, r9, pc}
	.size	fe_tobytes,.-fe_tobytes
	.text
	.align	4
	.globl	fe_1
	.type	fe_1, %function
fe_1:
	push	{r4, r5, r6, r7, r8, r9, lr}
	# Set one
	mov	r2, #1
	mov	r3, #0
	mov	r4, #0
	mov	r5, #0
	mov	r6, #0
	mov	r7, #0
	mov	r8, #0
	mov	r9, #0
	stm	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	pop	{r4, r5, r6, r7, r8, r9, pc}
	.size	fe_1,.-fe_1
	.text
	.align	4
	.globl	fe_0
	.type	fe_0, %function
fe_0:
	push	{r4, r5, r6, r7, r8, r9, lr}
	# Set zero
	mov	r2, #0
	mov	r3, #0
	mov	r4, #0
	mov	r5, #0
	mov	r6, #0
	mov	r7, #0
	mov	r8, #0
	mov	r9, #0
	stm	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	pop	{r4, r5, r6, r7, r8, r9, pc}
	.size	fe_0,.-fe_0
	.text
	.align	4
	.globl	fe_copy
	.type	fe_copy, %function
fe_copy:
	push	{r4, r5, lr}
	# Copy
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [r1]
	ldr	r3, [r1, #4]
#else
	ldrd	r2, r3, [r1]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r1, #8]
	ldr	r5, [r1, #12]
#else
	ldrd	r4, r5, [r1, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r2, [r0]
	str	r3, [r0, #4]
#else
	strd	r2, r3, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #8]
	str	r5, [r0, #12]
#else
	strd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [r1, #16]
	ldr	r3, [r1, #20]
#else
	ldrd	r2, r3, [r1, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r1, #24]
	ldr	r5, [r1, #28]
#else
	ldrd	r4, r5, [r1, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r2, [r0, #16]
	str	r3, [r0, #20]
#else
	strd	r2, r3, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #24]
	str	r5, [r0, #28]
#else
	strd	r4, r5, [r0, #24]
#endif
	pop	{r4, r5, pc}
	.size	fe_copy,.-fe_copy
	.text
	.align	4
	.globl	fe_neg
	.type	fe_neg, %function
fe_neg:
	push	{r4, r5, lr}
	mvn	lr, #0
	mvn	r12, #18
	ldm	r1!, {r2, r3, r4, r5}
	subs	r2, r12, r2
	sbcs	r3, lr, r3
	sbcs	r4, lr, r4
	sbcs	r5, lr, r5
	stm	r0!, {r2, r3, r4, r5}
	mvn	r12, #0x80000000
	ldm	r1!, {r2, r3, r4, r5}
	sbcs	r2, lr, r2
	sbcs	r3, lr, r3
	sbcs	r4, lr, r4
	sbc	r5, r12, r5
	stm	r0!, {r2, r3, r4, r5}
	pop	{r4, r5, pc}
	.size	fe_neg,.-fe_neg
	.text
	.align	4
	.globl	fe_isnonzero
	.type	fe_isnonzero, %function
fe_isnonzero:
	push	{r4, r5, r6, r7, r8, r9, lr}
	ldm	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	adds	r1, r2, #19
	adcs	r1, r3, #0
	adcs	r1, r4, #0
	adcs	r1, r5, #0
	adcs	r1, r6, #0
	adcs	r1, r7, #0
	adcs	r1, r8, #0
	adc	r1, r9, #0
	asr	r1, r1, #31
	and	r1, r1, #19
	adds	r2, r2, r1
	adcs	r3, r3, #0
	adcs	r4, r4, #0
	adcs	r5, r5, #0
	adcs	r6, r6, #0
	adcs	r7, r7, #0
	adcs	r8, r8, #0
	adc	r9, r9, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0x80000000
#else
	bfc	r9, #31, #1
#endif
	orr	r2, r2, r3
	orr	r4, r4, r5
	orr	r6, r6, r7
	orr	r8, r8, r9
	orr	r4, r4, r6
	orr	r2, r2, r8
	orr	r0, r2, r4
	pop	{r4, r5, r6, r7, r8, r9, pc}
	.size	fe_isnonzero,.-fe_isnonzero
	.text
	.align	4
	.globl	fe_isnegative
	.type	fe_isnegative, %function
fe_isnegative:
	push	{r4, r5, lr}
	ldm	r0!, {r2, r3, r4, r5}
	adds	r1, r2, #19
	adcs	r1, r3, #0
	adcs	r1, r4, #0
	adcs	r1, r5, #0
	ldm	r0, {r2, r3, r4, r5}
	adcs	r1, r2, #0
	adcs	r1, r3, #0
	adcs	r1, r4, #0
	ldr	r2, [r0, #-16]
	adc	r1, r5, #0
	and	r0, r2, #1
	lsr	r1, r1, #31
	eor	r0, r0, r1
	pop	{r4, r5, pc}
	.size	fe_isnegative,.-fe_isnegative
#if defined(HAVE_ED25519_MAKE_KEY) || defined(HAVE_ED25519_SIGN)
#ifndef WC_NO_CACHE_RESISTANT
	.text
	.align	4
	.globl	fe_cmov_table
	.type	fe_cmov_table, %function
fe_cmov_table:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r2, #24
	asr	r2, r2, #24
#else
	sxtb	r2, r2
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r3, r2, #24
	asr	r3, r2, #31
#else
	sbfx	r3, r2, #7, #1
#endif
	eor	r12, r2, r3
	sub	r12, r12, r3
	mov	r4, #1
	mov	r5, #0
	mov	r6, #1
	mov	r7, #0
	mov	r8, #0
	mov	r9, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #31
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1]
	ldr	r11, [r1, #4]
#else
	ldrd	r10, r11, [r1]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #32]
	ldr	r11, [r1, #36]
#else
	ldrd	r10, r11, [r1, #32]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #64]
	ldr	r11, [r1, #68]
#else
	ldrd	r10, r11, [r1, #64]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #30
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1]
	ldr	r11, [r1, #4]
#else
	ldrd	r10, r11, [r1]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #32]
	ldr	r11, [r1, #36]
#else
	ldrd	r10, r11, [r1, #32]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #64]
	ldr	r11, [r1, #68]
#else
	ldrd	r10, r11, [r1, #64]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #29
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1]
	ldr	r11, [r1, #4]
#else
	ldrd	r10, r11, [r1]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #32]
	ldr	r11, [r1, #36]
#else
	ldrd	r10, r11, [r1, #32]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #64]
	ldr	r11, [r1, #68]
#else
	ldrd	r10, r11, [r1, #64]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #28
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1]
	ldr	r11, [r1, #4]
#else
	ldrd	r10, r11, [r1]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #32]
	ldr	r11, [r1, #36]
#else
	ldrd	r10, r11, [r1, #32]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #64]
	ldr	r11, [r1, #68]
#else
	ldrd	r10, r11, [r1, #64]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #27
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1]
	ldr	r11, [r1, #4]
#else
	ldrd	r10, r11, [r1]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #32]
	ldr	r11, [r1, #36]
#else
	ldrd	r10, r11, [r1, #32]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #64]
	ldr	r11, [r1, #68]
#else
	ldrd	r10, r11, [r1, #64]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #26
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1]
	ldr	r11, [r1, #4]
#else
	ldrd	r10, r11, [r1]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #32]
	ldr	r11, [r1, #36]
#else
	ldrd	r10, r11, [r1, #32]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #64]
	ldr	r11, [r1, #68]
#else
	ldrd	r10, r11, [r1, #64]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #25
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1]
	ldr	r11, [r1, #4]
#else
	ldrd	r10, r11, [r1]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #32]
	ldr	r11, [r1, #36]
#else
	ldrd	r10, r11, [r1, #32]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #64]
	ldr	r11, [r1, #68]
#else
	ldrd	r10, r11, [r1, #64]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #24
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1]
	ldr	r11, [r1, #4]
#else
	ldrd	r10, r11, [r1]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #32]
	ldr	r11, [r1, #36]
#else
	ldrd	r10, r11, [r1, #32]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #64]
	ldr	r11, [r1, #68]
#else
	ldrd	r10, r11, [r1, #64]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	sub	r1, r1, #0x2a0
	mvn	r10, #18
	mvn	r11, #0
	subs	r10, r10, r8
	sbcs	r11, r11, r9
	sbc	lr, lr, lr
	asr	r12, r2, #31
	eor	r3, r4, r6
	and	r3, r3, r12
	eor	r4, r4, r3
	eor	r6, r6, r3
	eor	r3, r5, r7
	and	r3, r3, r12
	eor	r5, r5, r3
	eor	r7, r7, r3
	eor	r10, r10, r8
	and	r10, r10, r12
	eor	r8, r8, r10
	eor	r11, r11, r9
	and	r11, r11, r12
	eor	r9, r9, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0]
	str	r5, [r0, #4]
#else
	strd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #32]
	str	r7, [r0, #36]
#else
	strd	r6, r7, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #64]
	str	r9, [r0, #68]
#else
	strd	r8, r9, [r0, #64]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r3, r2, #24
	asr	r3, r2, #31
#else
	sbfx	r3, r2, #7, #1
#endif
	eor	r12, r2, r3
	sub	r12, r12, r3
	mov	r4, #0
	mov	r5, #0
	mov	r6, #0
	mov	r7, #0
	mov	r8, #0
	mov	r9, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #31
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #8]
	ldr	r11, [r1, #12]
#else
	ldrd	r10, r11, [r1, #8]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #40]
	ldr	r11, [r1, #44]
#else
	ldrd	r10, r11, [r1, #40]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #72]
	ldr	r11, [r1, #76]
#else
	ldrd	r10, r11, [r1, #72]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #30
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #8]
	ldr	r11, [r1, #12]
#else
	ldrd	r10, r11, [r1, #8]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #40]
	ldr	r11, [r1, #44]
#else
	ldrd	r10, r11, [r1, #40]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #72]
	ldr	r11, [r1, #76]
#else
	ldrd	r10, r11, [r1, #72]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #29
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #8]
	ldr	r11, [r1, #12]
#else
	ldrd	r10, r11, [r1, #8]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #40]
	ldr	r11, [r1, #44]
#else
	ldrd	r10, r11, [r1, #40]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #72]
	ldr	r11, [r1, #76]
#else
	ldrd	r10, r11, [r1, #72]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #28
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #8]
	ldr	r11, [r1, #12]
#else
	ldrd	r10, r11, [r1, #8]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #40]
	ldr	r11, [r1, #44]
#else
	ldrd	r10, r11, [r1, #40]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #72]
	ldr	r11, [r1, #76]
#else
	ldrd	r10, r11, [r1, #72]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #27
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #8]
	ldr	r11, [r1, #12]
#else
	ldrd	r10, r11, [r1, #8]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #40]
	ldr	r11, [r1, #44]
#else
	ldrd	r10, r11, [r1, #40]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #72]
	ldr	r11, [r1, #76]
#else
	ldrd	r10, r11, [r1, #72]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #26
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #8]
	ldr	r11, [r1, #12]
#else
	ldrd	r10, r11, [r1, #8]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #40]
	ldr	r11, [r1, #44]
#else
	ldrd	r10, r11, [r1, #40]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #72]
	ldr	r11, [r1, #76]
#else
	ldrd	r10, r11, [r1, #72]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #25
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #8]
	ldr	r11, [r1, #12]
#else
	ldrd	r10, r11, [r1, #8]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #40]
	ldr	r11, [r1, #44]
#else
	ldrd	r10, r11, [r1, #40]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #72]
	ldr	r11, [r1, #76]
#else
	ldrd	r10, r11, [r1, #72]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #24
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #8]
	ldr	r11, [r1, #12]
#else
	ldrd	r10, r11, [r1, #8]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #40]
	ldr	r11, [r1, #44]
#else
	ldrd	r10, r11, [r1, #40]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #72]
	ldr	r11, [r1, #76]
#else
	ldrd	r10, r11, [r1, #72]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	sub	r1, r1, #0x2a0
	mvn	r10, #0
	mvn	r11, #0
	rsbs	lr, lr, #0
	sbcs	r10, r10, r8
	sbcs	r11, r11, r9
	sbc	lr, lr, lr
	asr	r12, r2, #31
	eor	r3, r4, r6
	and	r3, r3, r12
	eor	r4, r4, r3
	eor	r6, r6, r3
	eor	r3, r5, r7
	and	r3, r3, r12
	eor	r5, r5, r3
	eor	r7, r7, r3
	eor	r10, r10, r8
	and	r10, r10, r12
	eor	r8, r8, r10
	eor	r11, r11, r9
	and	r11, r11, r12
	eor	r9, r9, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #8]
	str	r5, [r0, #12]
#else
	strd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #40]
	str	r7, [r0, #44]
#else
	strd	r6, r7, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #72]
	str	r9, [r0, #76]
#else
	strd	r8, r9, [r0, #72]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r3, r2, #24
	asr	r3, r2, #31
#else
	sbfx	r3, r2, #7, #1
#endif
	eor	r12, r2, r3
	sub	r12, r12, r3
	mov	r4, #0
	mov	r5, #0
	mov	r6, #0
	mov	r7, #0
	mov	r8, #0
	mov	r9, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #31
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #16]
	ldr	r11, [r1, #20]
#else
	ldrd	r10, r11, [r1, #16]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #48]
	ldr	r11, [r1, #52]
#else
	ldrd	r10, r11, [r1, #48]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #80]
	ldr	r11, [r1, #84]
#else
	ldrd	r10, r11, [r1, #80]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #30
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #16]
	ldr	r11, [r1, #20]
#else
	ldrd	r10, r11, [r1, #16]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #48]
	ldr	r11, [r1, #52]
#else
	ldrd	r10, r11, [r1, #48]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #80]
	ldr	r11, [r1, #84]
#else
	ldrd	r10, r11, [r1, #80]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #29
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #16]
	ldr	r11, [r1, #20]
#else
	ldrd	r10, r11, [r1, #16]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #48]
	ldr	r11, [r1, #52]
#else
	ldrd	r10, r11, [r1, #48]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #80]
	ldr	r11, [r1, #84]
#else
	ldrd	r10, r11, [r1, #80]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #28
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #16]
	ldr	r11, [r1, #20]
#else
	ldrd	r10, r11, [r1, #16]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #48]
	ldr	r11, [r1, #52]
#else
	ldrd	r10, r11, [r1, #48]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #80]
	ldr	r11, [r1, #84]
#else
	ldrd	r10, r11, [r1, #80]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #27
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #16]
	ldr	r11, [r1, #20]
#else
	ldrd	r10, r11, [r1, #16]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #48]
	ldr	r11, [r1, #52]
#else
	ldrd	r10, r11, [r1, #48]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #80]
	ldr	r11, [r1, #84]
#else
	ldrd	r10, r11, [r1, #80]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #26
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #16]
	ldr	r11, [r1, #20]
#else
	ldrd	r10, r11, [r1, #16]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #48]
	ldr	r11, [r1, #52]
#else
	ldrd	r10, r11, [r1, #48]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #80]
	ldr	r11, [r1, #84]
#else
	ldrd	r10, r11, [r1, #80]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #25
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #16]
	ldr	r11, [r1, #20]
#else
	ldrd	r10, r11, [r1, #16]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #48]
	ldr	r11, [r1, #52]
#else
	ldrd	r10, r11, [r1, #48]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #80]
	ldr	r11, [r1, #84]
#else
	ldrd	r10, r11, [r1, #80]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #24
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #16]
	ldr	r11, [r1, #20]
#else
	ldrd	r10, r11, [r1, #16]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #48]
	ldr	r11, [r1, #52]
#else
	ldrd	r10, r11, [r1, #48]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #80]
	ldr	r11, [r1, #84]
#else
	ldrd	r10, r11, [r1, #80]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	sub	r1, r1, #0x2a0
	mvn	r10, #0
	mvn	r11, #0
	rsbs	lr, lr, #0
	sbcs	r10, r10, r8
	sbcs	r11, r11, r9
	sbc	lr, lr, lr
	asr	r12, r2, #31
	eor	r3, r4, r6
	and	r3, r3, r12
	eor	r4, r4, r3
	eor	r6, r6, r3
	eor	r3, r5, r7
	and	r3, r3, r12
	eor	r5, r5, r3
	eor	r7, r7, r3
	eor	r10, r10, r8
	and	r10, r10, r12
	eor	r8, r8, r10
	eor	r11, r11, r9
	and	r11, r11, r12
	eor	r9, r9, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #16]
	str	r5, [r0, #20]
#else
	strd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #48]
	str	r7, [r0, #52]
#else
	strd	r6, r7, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #80]
	str	r9, [r0, #84]
#else
	strd	r8, r9, [r0, #80]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r3, r2, #24
	asr	r3, r2, #31
#else
	sbfx	r3, r2, #7, #1
#endif
	eor	r12, r2, r3
	sub	r12, r12, r3
	mov	r4, #0
	mov	r5, #0
	mov	r6, #0
	mov	r7, #0
	mov	r8, #0
	mov	r9, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #31
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #24]
	ldr	r11, [r1, #28]
#else
	ldrd	r10, r11, [r1, #24]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #56]
	ldr	r11, [r1, #60]
#else
	ldrd	r10, r11, [r1, #56]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #88]
	ldr	r11, [r1, #92]
#else
	ldrd	r10, r11, [r1, #88]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #30
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #24]
	ldr	r11, [r1, #28]
#else
	ldrd	r10, r11, [r1, #24]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #56]
	ldr	r11, [r1, #60]
#else
	ldrd	r10, r11, [r1, #56]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #88]
	ldr	r11, [r1, #92]
#else
	ldrd	r10, r11, [r1, #88]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #29
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #24]
	ldr	r11, [r1, #28]
#else
	ldrd	r10, r11, [r1, #24]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #56]
	ldr	r11, [r1, #60]
#else
	ldrd	r10, r11, [r1, #56]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #88]
	ldr	r11, [r1, #92]
#else
	ldrd	r10, r11, [r1, #88]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #28
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #24]
	ldr	r11, [r1, #28]
#else
	ldrd	r10, r11, [r1, #24]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #56]
	ldr	r11, [r1, #60]
#else
	ldrd	r10, r11, [r1, #56]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #88]
	ldr	r11, [r1, #92]
#else
	ldrd	r10, r11, [r1, #88]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #27
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #24]
	ldr	r11, [r1, #28]
#else
	ldrd	r10, r11, [r1, #24]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #56]
	ldr	r11, [r1, #60]
#else
	ldrd	r10, r11, [r1, #56]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #88]
	ldr	r11, [r1, #92]
#else
	ldrd	r10, r11, [r1, #88]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #26
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #24]
	ldr	r11, [r1, #28]
#else
	ldrd	r10, r11, [r1, #24]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #56]
	ldr	r11, [r1, #60]
#else
	ldrd	r10, r11, [r1, #56]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #88]
	ldr	r11, [r1, #92]
#else
	ldrd	r10, r11, [r1, #88]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #25
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #24]
	ldr	r11, [r1, #28]
#else
	ldrd	r10, r11, [r1, #24]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #56]
	ldr	r11, [r1, #60]
#else
	ldrd	r10, r11, [r1, #56]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #88]
	ldr	r11, [r1, #92]
#else
	ldrd	r10, r11, [r1, #88]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	add	r1, r1, #0x60
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x800000
	lsl	r3, r3, #8
	add	r3, r3, #0x0
#else
	mov	r3, #0x80000000
#endif
	ror	r3, r3, #24
	ror	r3, r3, r12
	asr	r3, r3, #31
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #24]
	ldr	r11, [r1, #28]
#else
	ldrd	r10, r11, [r1, #24]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r4, r4, r10
	eor	r5, r5, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #56]
	ldr	r11, [r1, #60]
#else
	ldrd	r10, r11, [r1, #56]
#endif
	eor	r10, r10, r6
	eor	r11, r11, r7
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r6, r6, r10
	eor	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1, #88]
	ldr	r11, [r1, #92]
#else
	ldrd	r10, r11, [r1, #88]
#endif
	eor	r10, r10, r8
	eor	r11, r11, r9
	and	r10, r10, r3
	and	r11, r11, r3
	eor	r8, r8, r10
	eor	r9, r9, r11
	sub	r1, r1, #0x2a0
	mvn	r10, #0
	mvn	r11, #0x80000000
	rsbs	lr, lr, #0
	sbcs	r10, r10, r8
	sbc	r11, r11, r9
	asr	r12, r2, #31
	eor	r3, r4, r6
	and	r3, r3, r12
	eor	r4, r4, r3
	eor	r6, r6, r3
	eor	r3, r5, r7
	and	r3, r3, r12
	eor	r5, r5, r3
	eor	r7, r7, r3
	eor	r10, r10, r8
	and	r10, r10, r12
	eor	r8, r8, r10
	eor	r11, r11, r9
	and	r11, r11, r12
	eor	r9, r9, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #24]
	str	r5, [r0, #28]
#else
	strd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #56]
	str	r7, [r0, #60]
#else
	strd	r6, r7, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #88]
	str	r9, [r0, #92]
#else
	strd	r8, r9, [r0, #88]
#endif
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	fe_cmov_table,.-fe_cmov_table
#else
	.text
	.align	4
	.globl	fe_cmov_table
	.type	fe_cmov_table, %function
fe_cmov_table:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r2, #24
	asr	r2, r2, #24
#else
	sxtb	r2, r2
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	lsl	r3, r2, #24
	asr	r3, r2, #31
#else
	sbfx	r3, r2, #7, #1
#endif
	eor	r2, r2, r3
	sub	r2, r2, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	sub	lr, r2, #1
#else
	clz	lr, r2
	lsl	lr, lr, #26
#endif /* defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6) */
	asr	lr, lr, #31
	mvn	lr, lr
	add	r2, r2, lr
	mov	r12, #0x60
	mul	r2, r2, r12
	add	r1, r1, r2
	ldm	r1!, {r4, r5, r6, r7, r8, r9, r10, r11}
	and	r4, r4, lr
	and	r5, r5, lr
	and	r6, r6, lr
	and	r7, r7, lr
	and	r8, r8, lr
	and	r9, r9, lr
	and	r10, r10, lr
	and	r11, r11, lr
	mvn	r12, lr
	sub	r4, r4, r12
	mov	r12, #32
	and	r12, r12, r3
	add	r0, r0, r12
	stm	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	sub	r0, r0, r12
	ldm	r1!, {r4, r5, r6, r7, r8, r9, r10, r11}
	and	r4, r4, lr
	and	r5, r5, lr
	and	r6, r6, lr
	and	r7, r7, lr
	and	r8, r8, lr
	and	r9, r9, lr
	and	r10, r10, lr
	and	r11, r11, lr
	mvn	r12, lr
	sub	r4, r4, r12
	mov	r12, #32
	bic	r12, r12, r3
	add	r0, r0, r12
	stm	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	sub	r0, r0, r12
	add	r0, r0, #0x40
	ldm	r1!, {r4, r5, r6, r7}
	mvn	r12, #18
	subs	r8, r12, r4
	sbcs	r9, r3, r5
	sbcs	r10, r3, r6
	sbcs	r11, r3, r7
	bic	r4, r4, r3
	bic	r5, r5, r3
	bic	r6, r6, r3
	bic	r7, r7, r3
	and	r8, r8, r3
	and	r9, r9, r3
	and	r10, r10, r3
	and	r11, r11, r3
	orr	r4, r4, r8
	orr	r5, r5, r9
	orr	r6, r6, r10
	orr	r7, r7, r11
	and	r4, r4, lr
	and	r5, r5, lr
	and	r6, r6, lr
	and	r7, r7, lr
	stm	r0!, {r4, r5, r6, r7}
	ldm	r1!, {r4, r5, r6, r7}
	mvn	r12, #0x80000000
	sbcs	r8, r3, r4
	sbcs	r9, r3, r5
	sbcs	r10, r3, r6
	sbc	r11, r12, r7
	bic	r4, r4, r3
	bic	r5, r5, r3
	bic	r6, r6, r3
	bic	r7, r7, r3
	and	r8, r8, r3
	and	r9, r9, r3
	and	r10, r10, r3
	and	r11, r11, r3
	orr	r4, r4, r8
	orr	r5, r5, r9
	orr	r6, r6, r10
	orr	r7, r7, r11
	and	r4, r4, lr
	and	r5, r5, lr
	and	r6, r6, lr
	and	r7, r7, lr
	stm	r0!, {r4, r5, r6, r7}
	sub	r1, r1, r2
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	fe_cmov_table,.-fe_cmov_table
#endif /* WC_NO_CACHE_RESISTANT */
#endif /* HAVE_ED25519_MAKE_KEY || HAVE_ED25519_SIGN */
#endif /* HAVE_ED25519 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	.text
	.align	4
	.globl	fe_mul_op
	.type	fe_mul_op, %function
fe_mul_op:
	push	{lr}
	sub	sp, sp, #40
	str	r0, [sp, #36]
	mov	r0, #0
	ldr	r12, [r1]
	# A[0] * B[0]
	ldr	lr, [r2]
	umull	r3, r4, r12, lr
	# A[0] * B[2]
	ldr	lr, [r2, #8]
	umull	r5, r6, r12, lr
	# A[0] * B[4]
	ldr	lr, [r2, #16]
	umull	r7, r8, r12, lr
	# A[0] * B[6]
	ldr	lr, [r2, #24]
	umull	r9, r10, r12, lr
	str	r3, [sp]
	# A[0] * B[1]
	ldr	lr, [r2, #4]
	mov	r11, r0
	umlal	r4, r11, r12, lr
	adds	r5, r5, r11
	# A[0] * B[3]
	ldr	lr, [r2, #12]
	adcs	r6, r6, #0
	adc	r11, r0, #0
	umlal	r6, r11, r12, lr
	adds	r7, r7, r11
	# A[0] * B[5]
	ldr	lr, [r2, #20]
	adcs	r8, r8, #0
	adc	r11, r0, #0
	umlal	r8, r11, r12, lr
	adds	r9, r9, r11
	# A[0] * B[7]
	ldr	lr, [r2, #28]
	adcs	r10, r10, #0
	adc	r3, r0, #0
	umlal	r10, r3, r12, lr
	# A[1] * B[0]
	ldr	r12, [r1, #4]
	ldr	lr, [r2]
	mov	r11, #0
	umlal	r4, r11, r12, lr
	str	r4, [sp, #4]
	adds	r5, r5, r11
	# A[1] * B[1]
	ldr	lr, [r2, #4]
	adc	r11, r0, #0
	umlal	r5, r11, r12, lr
	adds	r6, r6, r11
	# A[1] * B[2]
	ldr	lr, [r2, #8]
	adc	r11, r0, #0
	umlal	r6, r11, r12, lr
	adds	r7, r7, r11
	# A[1] * B[3]
	ldr	lr, [r2, #12]
	adc	r11, r0, #0
	umlal	r7, r11, r12, lr
	adds	r8, r8, r11
	# A[1] * B[4]
	ldr	lr, [r2, #16]
	adc	r11, r0, #0
	umlal	r8, r11, r12, lr
	adds	r9, r9, r11
	# A[1] * B[5]
	ldr	lr, [r2, #20]
	adc	r11, r0, #0
	umlal	r9, r11, r12, lr
	adds	r10, r10, r11
	# A[1] * B[6]
	ldr	lr, [r2, #24]
	adc	r11, r0, #0
	umlal	r10, r11, r12, lr
	adds	r3, r3, r11
	# A[1] * B[7]
	ldr	lr, [r2, #28]
	adc	r4, r0, #0
	umlal	r3, r4, r12, lr
	# A[2] * B[0]
	ldr	r12, [r1, #8]
	ldr	lr, [r2]
	mov	r11, #0
	umlal	r5, r11, r12, lr
	str	r5, [sp, #8]
	adds	r6, r6, r11
	# A[2] * B[1]
	ldr	lr, [r2, #4]
	adc	r11, r0, #0
	umlal	r6, r11, r12, lr
	adds	r7, r7, r11
	# A[2] * B[2]
	ldr	lr, [r2, #8]
	adc	r11, r0, #0
	umlal	r7, r11, r12, lr
	adds	r8, r8, r11
	# A[2] * B[3]
	ldr	lr, [r2, #12]
	adc	r11, r0, #0
	umlal	r8, r11, r12, lr
	adds	r9, r9, r11
	# A[2] * B[4]
	ldr	lr, [r2, #16]
	adc	r11, r0, #0
	umlal	r9, r11, r12, lr
	adds	r10, r10, r11
	# A[2] * B[5]
	ldr	lr, [r2, #20]
	adc	r11, r0, #0
	umlal	r10, r11, r12, lr
	adds	r3, r3, r11
	# A[2] * B[6]
	ldr	lr, [r2, #24]
	adc	r11, r0, #0
	umlal	r3, r11, r12, lr
	adds	r4, r4, r11
	# A[2] * B[7]
	ldr	lr, [r2, #28]
	adc	r5, r0, #0
	umlal	r4, r5, r12, lr
	# A[3] * B[0]
	ldr	r12, [r1, #12]
	ldr	lr, [r2]
	mov	r11, #0
	umlal	r6, r11, r12, lr
	str	r6, [sp, #12]
	adds	r7, r7, r11
	# A[3] * B[1]
	ldr	lr, [r2, #4]
	adc	r11, r0, #0
	umlal	r7, r11, r12, lr
	adds	r8, r8, r11
	# A[3] * B[2]
	ldr	lr, [r2, #8]
	adc	r11, r0, #0
	umlal	r8, r11, r12, lr
	adds	r9, r9, r11
	# A[3] * B[3]
	ldr	lr, [r2, #12]
	adc	r11, r0, #0
	umlal	r9, r11, r12, lr
	adds	r10, r10, r11
	# A[3] * B[4]
	ldr	lr, [r2, #16]
	adc	r11, r0, #0
	umlal	r10, r11, r12, lr
	adds	r3, r3, r11
	# A[3] * B[5]
	ldr	lr, [r2, #20]
	adc	r11, r0, #0
	umlal	r3, r11, r12, lr
	adds	r4, r4, r11
	# A[3] * B[6]
	ldr	lr, [r2, #24]
	adc	r11, r0, #0
	umlal	r4, r11, r12, lr
	adds	r5, r5, r11
	# A[3] * B[7]
	ldr	lr, [r2, #28]
	adc	r6, r0, #0
	umlal	r5, r6, r12, lr
	# A[4] * B[0]
	ldr	r12, [r1, #16]
	ldr	lr, [r2]
	mov	r11, #0
	umlal	r7, r11, r12, lr
	str	r7, [sp, #16]
	adds	r8, r8, r11
	# A[4] * B[1]
	ldr	lr, [r2, #4]
	adc	r11, r0, #0
	umlal	r8, r11, r12, lr
	adds	r9, r9, r11
	# A[4] * B[2]
	ldr	lr, [r2, #8]
	adc	r11, r0, #0
	umlal	r9, r11, r12, lr
	adds	r10, r10, r11
	# A[4] * B[3]
	ldr	lr, [r2, #12]
	adc	r11, r0, #0
	umlal	r10, r11, r12, lr
	adds	r3, r3, r11
	# A[4] * B[4]
	ldr	lr, [r2, #16]
	adc	r11, r0, #0
	umlal	r3, r11, r12, lr
	adds	r4, r4, r11
	# A[4] * B[5]
	ldr	lr, [r2, #20]
	adc	r11, r0, #0
	umlal	r4, r11, r12, lr
	adds	r5, r5, r11
	# A[4] * B[6]
	ldr	lr, [r2, #24]
	adc	r11, r0, #0
	umlal	r5, r11, r12, lr
	adds	r6, r6, r11
	# A[4] * B[7]
	ldr	lr, [r2, #28]
	adc	r7, r0, #0
	umlal	r6, r7, r12, lr
	# A[5] * B[0]
	ldr	r12, [r1, #20]
	ldr	lr, [r2]
	mov	r11, #0
	umlal	r8, r11, r12, lr
	str	r8, [sp, #20]
	adds	r9, r9, r11
	# A[5] * B[1]
	ldr	lr, [r2, #4]
	adc	r11, r0, #0
	umlal	r9, r11, r12, lr
	adds	r10, r10, r11
	# A[5] * B[2]
	ldr	lr, [r2, #8]
	adc	r11, r0, #0
	umlal	r10, r11, r12, lr
	adds	r3, r3, r11
	# A[5] * B[3]
	ldr	lr, [r2, #12]
	adc	r11, r0, #0
	umlal	r3, r11, r12, lr
	adds	r4, r4, r11
	# A[5] * B[4]
	ldr	lr, [r2, #16]
	adc	r11, r0, #0
	umlal	r4, r11, r12, lr
	adds	r5, r5, r11
	# A[5] * B[5]
	ldr	lr, [r2, #20]
	adc	r11, r0, #0
	umlal	r5, r11, r12, lr
	adds	r6, r6, r11
	# A[5] * B[6]
	ldr	lr, [r2, #24]
	adc	r11, r0, #0
	umlal	r6, r11, r12, lr
	adds	r7, r7, r11
	# A[5] * B[7]
	ldr	lr, [r2, #28]
	adc	r8, r0, #0
	umlal	r7, r8, r12, lr
	# A[6] * B[0]
	ldr	r12, [r1, #24]
	ldr	lr, [r2]
	mov	r11, #0
	umlal	r9, r11, r12, lr
	str	r9, [sp, #24]
	adds	r10, r10, r11
	# A[6] * B[1]
	ldr	lr, [r2, #4]
	adc	r11, r0, #0
	umlal	r10, r11, r12, lr
	adds	r3, r3, r11
	# A[6] * B[2]
	ldr	lr, [r2, #8]
	adc	r11, r0, #0
	umlal	r3, r11, r12, lr
	adds	r4, r4, r11
	# A[6] * B[3]
	ldr	lr, [r2, #12]
	adc	r11, r0, #0
	umlal	r4, r11, r12, lr
	adds	r5, r5, r11
	# A[6] * B[4]
	ldr	lr, [r2, #16]
	adc	r11, r0, #0
	umlal	r5, r11, r12, lr
	adds	r6, r6, r11
	# A[6] * B[5]
	ldr	lr, [r2, #20]
	adc	r11, r0, #0
	umlal	r6, r11, r12, lr
	adds	r7, r7, r11
	# A[6] * B[6]
	ldr	lr, [r2, #24]
	adc	r11, r0, #0
	umlal	r7, r11, r12, lr
	adds	r8, r8, r11
	# A[6] * B[7]
	ldr	lr, [r2, #28]
	adc	r9, r0, #0
	umlal	r8, r9, r12, lr
	# A[7] * B[0]
	ldr	r12, [r1, #28]
	ldr	lr, [r2]
	mov	r11, #0
	umlal	r10, r11, r12, lr
	str	r10, [sp, #28]
	adds	r3, r3, r11
	# A[7] * B[1]
	ldr	lr, [r2, #4]
	adc	r11, r0, #0
	umlal	r3, r11, r12, lr
	adds	r4, r4, r11
	# A[7] * B[2]
	ldr	lr, [r2, #8]
	adc	r11, r0, #0
	umlal	r4, r11, r12, lr
	adds	r5, r5, r11
	# A[7] * B[3]
	ldr	lr, [r2, #12]
	adc	r11, r0, #0
	umlal	r5, r11, r12, lr
	adds	r6, r6, r11
	# A[7] * B[4]
	ldr	lr, [r2, #16]
	adc	r11, r0, #0
	umlal	r6, r11, r12, lr
	adds	r7, r7, r11
	# A[7] * B[5]
	ldr	lr, [r2, #20]
	adc	r11, r0, #0
	umlal	r7, r11, r12, lr
	adds	r8, r8, r11
	# A[7] * B[6]
	ldr	lr, [r2, #24]
	adc	r11, r0, #0
	umlal	r8, r11, r12, lr
	adds	r9, r9, r11
	# A[7] * B[7]
	ldr	lr, [r2, #28]
	adc	r10, r0, #0
	umlal	r9, r10, r12, lr
	# Reduce
	ldr	r2, [sp, #28]
	mov	lr, sp
	mov	r12, #38
	umull	r10, r11, r12, r10
	adds	r10, r10, r2
	adc	r11, r11, #0
	mov	r12, #19
	lsl	r11, r11, #1
	orr	r11, r11, r10, LSR #31
	mul	r11, r12, r11
	ldm	lr!, {r1, r2}
	mov	r12, #38
	adds	r1, r1, r11
	adc	r11, r0, #0
	umlal	r1, r11, r3, r12
	adds	r2, r2, r11
	adc	r11, r0, #0
	umlal	r2, r11, r4, r12
	ldm	lr!, {r3, r4}
	adds	r3, r3, r11
	adc	r11, r0, #0
	umlal	r3, r11, r5, r12
	adds	r4, r4, r11
	adc	r11, r0, #0
	umlal	r4, r11, r6, r12
	ldm	lr!, {r5, r6}
	adds	r5, r5, r11
	adc	r11, r0, #0
	umlal	r5, r11, r7, r12
	adds	r6, r6, r11
	adc	r11, r0, #0
	umlal	r6, r11, r8, r12
	ldm	lr!, {r7, r8}
	adds	r7, r7, r11
	adc	r11, r0, #0
	umlal	r7, r11, r9, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r10, r10, #0x80000000
#else
	bfc	r10, #31, #1
#endif
	adds	r8, r10, r11
	# Store
	ldr	r0, [sp, #36]
	stm	r0, {r1, r2, r3, r4, r5, r6, r7, r8}
	add	sp, sp, #40
	pop	{pc}
	.size	fe_mul_op,.-fe_mul_op
#else
	.text
	.align	4
	.globl	fe_mul_op
	.type	fe_mul_op, %function
fe_mul_op:
	push	{lr}
	sub	sp, sp, #44
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r0, [sp, #36]
	str	r1, [sp, #40]
#else
	strd	r0, r1, [sp, #36]
#endif
	mov	lr, r2
	ldm	r1, {r0, r1, r2, r3}
	ldm	lr!, {r4, r5, r6}
	umull	r10, r11, r0, r4
	umull	r12, r7, r1, r4
	umaal	r11, r12, r0, r5
	umull	r8, r9, r2, r4
	umaal	r12, r8, r1, r5
	umaal	r12, r7, r0, r6
	umaal	r8, r9, r3, r4
	stm	sp, {r10, r11, r12}
	umaal	r7, r8, r2, r5
	ldm	lr!, {r4}
	umull	r10, r11, r1, r6
	umaal	r8, r9, r2, r6
	umaal	r7, r10, r0, r4
	umaal	r8, r11, r3, r5
	str	r7, [sp, #12]
	umaal	r8, r10, r1, r4
	umaal	r9, r11, r3, r6
	umaal	r9, r10, r2, r4
	umaal	r10, r11, r3, r4
	ldm	lr, {r4, r5, r6, r7}
	mov	r12, #0
	umlal	r8, r12, r0, r4
	umaal	r9, r12, r1, r4
	umaal	r10, r12, r2, r4
	umaal	r11, r12, r3, r4
	mov	r4, #0
	umlal	r9, r4, r0, r5
	umaal	r10, r4, r1, r5
	umaal	r11, r4, r2, r5
	umaal	r12, r4, r3, r5
	mov	r5, #0
	umlal	r10, r5, r0, r6
	umaal	r11, r5, r1, r6
	umaal	r12, r5, r2, r6
	umaal	r4, r5, r3, r6
	mov	r6, #0
	umlal	r11, r6, r0, r7
	ldr	r0, [sp, #40]
	umaal	r12, r6, r1, r7
	add	r0, r0, #16
	umaal	r4, r6, r2, r7
	sub	lr, lr, #16
	umaal	r5, r6, r3, r7
	ldm	r0, {r0, r1, r2, r3}
	str	r6, [sp, #32]
	ldm	lr!, {r6}
	mov	r7, #0
	umlal	r8, r7, r0, r6
	umaal	r9, r7, r1, r6
	str	r8, [sp, #16]
	umaal	r10, r7, r2, r6
	umaal	r11, r7, r3, r6
	ldm	lr!, {r6}
	mov	r8, #0
	umlal	r9, r8, r0, r6
	umaal	r10, r8, r1, r6
	str	r9, [sp, #20]
	umaal	r11, r8, r2, r6
	umaal	r12, r8, r3, r6
	ldm	lr!, {r6}
	mov	r9, #0
	umlal	r10, r9, r0, r6
	umaal	r11, r9, r1, r6
	str	r10, [sp, #24]
	umaal	r12, r9, r2, r6
	umaal	r4, r9, r3, r6
	ldm	lr!, {r6}
	mov	r10, #0
	umlal	r11, r10, r0, r6
	umaal	r12, r10, r1, r6
	str	r11, [sp, #28]
	umaal	r4, r10, r2, r6
	umaal	r5, r10, r3, r6
	ldm	lr!, {r11}
	umaal	r12, r7, r0, r11
	umaal	r4, r7, r1, r11
	ldr	r6, [sp, #32]
	umaal	r5, r7, r2, r11
	umaal	r6, r7, r3, r11
	ldm	lr!, {r11}
	umaal	r4, r8, r0, r11
	umaal	r5, r8, r1, r11
	umaal	r6, r8, r2, r11
	umaal	r7, r8, r3, r11
	ldm	lr, {r11, lr}
	umaal	r5, r9, r0, r11
	umaal	r6, r10, r0, lr
	umaal	r6, r9, r1, r11
	umaal	r7, r10, r1, lr
	umaal	r7, r9, r2, r11
	umaal	r8, r10, r2, lr
	umaal	r8, r9, r3, r11
	umaal	r9, r10, r3, lr
	# Reduce
	ldr	r0, [sp, #28]
	mov	lr, #37
	umaal	r10, r0, r10, lr
	mov	lr, #19
	lsl	r0, r0, #1
	orr	r0, r0, r10, lsr #31
	mul	r11, r0, lr
	pop	{r0, r1, r2}
	mov	lr, #38
	umaal	r0, r11, r12, lr
	umaal	r1, r11, r4, lr
	umaal	r2, r11, r5, lr
	pop	{r3, r4, r5}
	umaal	r3, r11, r6, lr
	umaal	r4, r11, r7, lr
	umaal	r5, r11, r8, lr
	pop	{r6}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r10, r10, #0x80000000
#else
	bfc	r10, #31, #1
#endif
	umaal	r6, r11, r9, lr
	add	r7, r10, r11
	ldr	lr, [sp, #8]
	# Store
	stm	lr, {r0, r1, r2, r3, r4, r5, r6, r7}
	add	sp, sp, #16
	pop	{pc}
	.size	fe_mul_op,.-fe_mul_op
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	.text
	.align	4
	.globl	fe_mul
	.type	fe_mul, %function
fe_mul:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	bl	fe_mul_op
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	fe_mul,.-fe_mul
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	.text
	.align	4
	.globl	fe_sq_op
	.type	fe_sq_op, %function
fe_sq_op:
	push	{lr}
	sub	sp, sp, #0x44
	str	r0, [sp, #64]
	# Square
	mov	r0, #0
	ldr	r12, [r1]
	# A[0] * A[1]
	ldr	lr, [r1, #4]
	umull	r4, r5, r12, lr
	# A[0] * A[3]
	ldr	lr, [r1, #12]
	umull	r6, r7, r12, lr
	# A[0] * A[5]
	ldr	lr, [r1, #20]
	umull	r8, r9, r12, lr
	# A[0] * A[7]
	ldr	lr, [r1, #28]
	umull	r10, r3, r12, lr
	# A[0] * A[2]
	ldr	lr, [r1, #8]
	mov	r11, #0
	umlal	r5, r11, r12, lr
	adds	r6, r6, r11
	# A[0] * A[4]
	ldr	lr, [r1, #16]
	adcs	r7, r7, #0
	adc	r11, r0, #0
	umlal	r7, r11, r12, lr
	adds	r8, r8, r11
	# A[0] * A[6]
	ldr	lr, [r1, #24]
	adcs	r9, r9, #0
	adc	r11, r0, #0
	umlal	r9, r11, r12, lr
	adds	r10, r10, r11
	adcs	r3, r3, #0
	str	r4, [sp, #4]
	str	r5, [sp, #8]
	# A[1] * A[2]
	ldr	r12, [r1, #4]
	ldr	lr, [r1, #8]
	mov	r11, #0
	umlal	r6, r11, r12, lr
	str	r6, [sp, #12]
	adds	r7, r7, r11
	# A[1] * A[3]
	ldr	lr, [r1, #12]
	adc	r11, r0, #0
	umlal	r7, r11, r12, lr
	str	r7, [sp, #16]
	adds	r8, r8, r11
	# A[1] * A[4]
	ldr	lr, [r1, #16]
	adc	r11, r0, #0
	umlal	r8, r11, r12, lr
	adds	r9, r9, r11
	# A[1] * A[5]
	ldr	lr, [r1, #20]
	adc	r11, r0, #0
	umlal	r9, r11, r12, lr
	adds	r10, r10, r11
	# A[1] * A[6]
	ldr	lr, [r1, #24]
	adc	r11, r0, #0
	umlal	r10, r11, r12, lr
	adds	r3, r3, r11
	# A[1] * A[7]
	ldr	lr, [r1, #28]
	adc	r4, r0, #0
	umlal	r3, r4, r12, lr
	# A[2] * A[3]
	ldr	r12, [r1, #8]
	ldr	lr, [r1, #12]
	mov	r11, #0
	umlal	r8, r11, r12, lr
	str	r8, [sp, #20]
	adds	r9, r9, r11
	# A[2] * A[4]
	ldr	lr, [r1, #16]
	adc	r11, r0, #0
	umlal	r9, r11, r12, lr
	str	r9, [sp, #24]
	adds	r10, r10, r11
	# A[2] * A[5]
	ldr	lr, [r1, #20]
	adc	r11, r0, #0
	umlal	r10, r11, r12, lr
	adds	r3, r3, r11
	# A[2] * A[6]
	ldr	lr, [r1, #24]
	adc	r11, r0, #0
	umlal	r3, r11, r12, lr
	adds	r4, r4, r11
	# A[2] * A[7]
	ldr	lr, [r1, #28]
	adc	r5, r0, #0
	umlal	r4, r5, r12, lr
	# A[3] * A[4]
	ldr	r12, [r1, #12]
	ldr	lr, [r1, #16]
	mov	r11, #0
	umlal	r10, r11, r12, lr
	str	r10, [sp, #28]
	adds	r3, r3, r11
	# A[3] * A[5]
	ldr	lr, [r1, #20]
	adc	r11, r0, #0
	umlal	r3, r11, r12, lr
	adds	r4, r4, r11
	# A[3] * A[6]
	ldr	lr, [r1, #24]
	adc	r11, r0, #0
	umlal	r4, r11, r12, lr
	adds	r5, r5, r11
	# A[3] * A[7]
	ldr	lr, [r1, #28]
	adc	r6, r0, #0
	umlal	r5, r6, r12, lr
	# A[4] * A[5]
	ldr	r12, [r1, #16]
	ldr	lr, [r1, #20]
	mov	r11, #0
	umlal	r4, r11, r12, lr
	adds	r5, r5, r11
	# A[4] * A[6]
	ldr	lr, [r1, #24]
	adc	r11, r0, #0
	umlal	r5, r11, r12, lr
	adds	r6, r6, r11
	# A[4] * A[7]
	ldr	lr, [r1, #28]
	adc	r7, r0, #0
	umlal	r6, r7, r12, lr
	# A[5] * A[6]
	ldr	r12, [r1, #20]
	ldr	lr, [r1, #24]
	mov	r11, #0
	umlal	r6, r11, r12, lr
	adds	r7, r7, r11
	# A[5] * A[7]
	ldr	lr, [r1, #28]
	adc	r8, r0, #0
	umlal	r7, r8, r12, lr
	# A[6] * A[7]
	ldr	r12, [r1, #24]
	ldr	lr, [r1, #28]
	mov	r9, #0
	umlal	r8, r9, r12, lr
	add	lr, sp, #32
	stm	lr, {r3, r4, r5, r6, r7, r8, r9}
	add	lr, sp, #4
	ldm	lr, {r4, r5, r6, r7, r8, r9, r10}
	adds	r4, r4, r4
	adcs	r5, r5, r5
	adcs	r6, r6, r6
	adcs	r7, r7, r7
	adcs	r8, r8, r8
	adcs	r9, r9, r9
	adcs	r10, r10, r10
	stm	lr!, {r4, r5, r6, r7, r8, r9, r10}
	ldm	lr, {r3, r4, r5, r6, r7, r8, r9}
	adcs	r3, r3, r3
	adcs	r4, r4, r4
	adcs	r5, r5, r5
	adcs	r6, r6, r6
	adcs	r7, r7, r7
	adcs	r8, r8, r8
	adcs	r9, r9, r9
	adc	r10, r0, #0
	stm	lr, {r3, r4, r5, r6, r7, r8, r9, r10}
	add	lr, sp, #4
	ldm	lr, {r4, r5, r6, r7, r8, r9, r10}
	mov	lr, sp
	# A[0] * A[0]
	ldr	r12, [r1]
	umull	r3, r11, r12, r12
	adds	r4, r4, r11
	# A[1] * A[1]
	ldr	r12, [r1, #4]
	adcs	r5, r5, #0
	adc	r11, r0, #0
	umlal	r5, r11, r12, r12
	adds	r6, r6, r11
	# A[2] * A[2]
	ldr	r12, [r1, #8]
	adcs	r7, r7, #0
	adc	r11, r0, #0
	umlal	r7, r11, r12, r12
	adds	r8, r8, r11
	# A[3] * A[3]
	ldr	r12, [r1, #12]
	adcs	r9, r9, #0
	adc	r11, r0, #0
	umlal	r9, r11, r12, r12
	adds	r10, r10, r11
	stm	lr!, {r3, r4, r5, r6, r7, r8, r9, r10}
	ldm	lr, {r3, r4, r5, r6, r7, r8, r9, r10}
	# A[4] * A[4]
	ldr	r12, [r1, #16]
	adcs	r3, r3, #0
	adc	r11, r0, #0
	umlal	r3, r11, r12, r12
	adds	r4, r4, r11
	# A[5] * A[5]
	ldr	r12, [r1, #20]
	adcs	r5, r5, #0
	adc	r11, r0, #0
	umlal	r5, r11, r12, r12
	adds	r6, r6, r11
	# A[6] * A[6]
	ldr	r12, [r1, #24]
	adcs	r7, r7, #0
	adc	r11, r0, #0
	umlal	r7, r11, r12, r12
	adds	r8, r8, r11
	# A[7] * A[7]
	ldr	r12, [r1, #28]
	adcs	r9, r9, #0
	adc	r10, r10, #0
	umlal	r9, r10, r12, r12
	# Reduce
	ldr	r2, [sp, #28]
	mov	lr, sp
	mov	r12, #38
	umull	r10, r11, r12, r10
	adds	r10, r10, r2
	adc	r11, r11, #0
	mov	r12, #19
	lsl	r11, r11, #1
	orr	r11, r11, r10, LSR #31
	mul	r11, r12, r11
	ldm	lr!, {r1, r2}
	mov	r12, #38
	adds	r1, r1, r11
	adc	r11, r0, #0
	umlal	r1, r11, r3, r12
	adds	r2, r2, r11
	adc	r11, r0, #0
	umlal	r2, r11, r4, r12
	ldm	lr!, {r3, r4}
	adds	r3, r3, r11
	adc	r11, r0, #0
	umlal	r3, r11, r5, r12
	adds	r4, r4, r11
	adc	r11, r0, #0
	umlal	r4, r11, r6, r12
	ldm	lr!, {r5, r6}
	adds	r5, r5, r11
	adc	r11, r0, #0
	umlal	r5, r11, r7, r12
	adds	r6, r6, r11
	adc	r11, r0, #0
	umlal	r6, r11, r8, r12
	ldm	lr!, {r7, r8}
	adds	r7, r7, r11
	adc	r11, r0, #0
	umlal	r7, r11, r9, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r10, r10, #0x80000000
#else
	bfc	r10, #31, #1
#endif
	adds	r8, r10, r11
	# Store
	ldr	r0, [sp, #64]
	stm	r0, {r1, r2, r3, r4, r5, r6, r7, r8}
	add	sp, sp, #0x44
	pop	{pc}
	.size	fe_sq_op,.-fe_sq_op
#else
	.text
	.align	4
	.globl	fe_sq_op
	.type	fe_sq_op, %function
fe_sq_op:
	push	{lr}
	sub	sp, sp, #32
	str	r0, [sp, #28]
	ldm	r1, {r0, r1, r2, r3, r4, r5, r6, r7}
	# Square
	umull	r9, r10, r0, r0
	umull	r11, r12, r0, r1
	adds	r11, r11, r11
	mov	lr, #0
	umaal	r10, r11, lr, lr
	stm	sp, {r9, r10}
	mov	r8, lr
	umaal	r8, r12, r0, r2
	adcs	r8, r8, r8
	umaal	r8, r11, r1, r1
	umull	r9, r10, r0, r3
	umaal	r9, r12, r1, r2
	adcs	r9, r9, r9
	umaal	r9, r11, lr, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [sp, #8]
	str	r9, [sp, #12]
#else
	strd	r8, r9, [sp, #8]
#endif
	mov	r9, lr
	umaal	r9, r10, r0, r4
	umaal	r9, r12, r1, r3
	adcs	r9, r9, r9
	umaal	r9, r11, r2, r2
	str	r9, [sp, #16]
	umull	r9, r8, r0, r5
	umaal	r9, r12, r1, r4
	umaal	r9, r10, r2, r3
	adcs	r9, r9, r9
	umaal	r9, r11, lr, lr
	str	r9, [sp, #20]
	mov	r9, lr
	umaal	r9, r8, r0, r6
	umaal	r9, r12, r1, r5
	umaal	r9, r10, r2, r4
	adcs	r9, r9, r9
	umaal	r9, r11, r3, r3
	str	r9, [sp, #24]
	umull	r0, r9, r0, r7
	umaal	r0, r8, r1, r6
	umaal	r0, r12, r2, r5
	umaal	r0, r10, r3, r4
	adcs	r0, r0, r0
	umaal	r0, r11, lr, lr
	# R[7] = r0
	umaal	r9, r8, r1, r7
	umaal	r9, r10, r2, r6
	umaal	r12, r9, r3, r5
	adcs	r12, r12, r12
	umaal	r12, r11, r4, r4
	# R[8] = r12
	umaal	r9, r8, r2, r7
	umaal	r10, r9, r3, r6
	mov	r2, lr
	umaal	r10, r2, r4, r5
	adcs	r10, r10, r10
	umaal	r11, r10, lr, lr
	# R[9] = r11
	umaal	r2, r8, r3, r7
	umaal	r2, r9, r4, r6
	adcs	r3, r2, r2
	umaal	r10, r3, r5, r5
	# R[10] = r10
	mov	r1, lr
	umaal	r1, r8, r4, r7
	umaal	r1, r9, r5, r6
	adcs	r4, r1, r1
	umaal	r3, r4, lr, lr
	# R[11] = r3
	umaal	r8, r9, r5, r7
	adcs	r8, r8, r8
	umaal	r4, r8, r6, r6
	# R[12] = r4
	mov	r5, lr
	umaal	r5, r9, r6, r7
	adcs	r5, r5, r5
	umaal	r8, r5, lr, lr
	# R[13] = r8
	adcs	r9, r9, r9
	umaal	r9, r5, r7, r7
	adcs	r7, r5, lr
	# R[14] = r9
	# R[15] = r7
	# Reduce
	mov	r6, #37
	umaal	r7, r0, r7, r6
	mov	r6, #19
	lsl	r0, r0, #1
	orr	r0, r0, r7, lsr #31
	mul	lr, r0, r6
	pop	{r0, r1}
	mov	r6, #38
	umaal	r0, lr, r12, r6
	umaal	r1, lr, r11, r6
	mov	r12, r3
	mov	r11, r4
	pop	{r2, r3, r4}
	umaal	r2, lr, r10, r6
	umaal	r3, lr, r12, r6
	umaal	r4, lr, r11, r6
	mov	r12, r6
	pop	{r5, r6}
	umaal	r5, lr, r8, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0x80000000
#else
	bfc	r7, #31, #1
#endif
	umaal	r6, lr, r9, r12
	add	r7, r7, lr
	pop	{lr}
	# Store
	stm	lr, {r0, r1, r2, r3, r4, r5, r6, r7}
	pop	{pc}
	.size	fe_sq_op,.-fe_sq_op
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	.text
	.align	4
	.globl	fe_sq
	.type	fe_sq, %function
fe_sq:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	bl	fe_sq_op
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	fe_sq,.-fe_sq
#ifdef HAVE_CURVE25519
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	.text
	.align	4
	.globl	fe_mul121666
	.type	fe_mul121666, %function
fe_mul121666:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	# Multiply by 121666
	ldm	r1, {r2, r3, r4, r5, r6, r7, r8, r9}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #1
	lsl	r10, r10, #8
	orr	r10, r10, #0xdb
	lsl	r10, r10, #8
	orr	r10, r10, #0x42
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xdb
	lsl	r10, r10, #8
	add	r10, r10, #0x42
#else
	mov	r10, #0xdb42
#endif
	movt	r10, #1
#endif
	umull	r2, r12, r10, r2
	umull	r3, lr, r10, r3
	adds	r3, r3, r12
	adc	lr, lr, #0
	umull	r4, r12, r10, r4
	adds	r4, r4, lr
	adc	r12, r12, #0
	umull	r5, lr, r10, r5
	adds	r5, r5, r12
	adc	lr, lr, #0
	umull	r6, r12, r10, r6
	adds	r6, r6, lr
	adc	r12, r12, #0
	umull	r7, lr, r10, r7
	adds	r7, r7, r12
	adc	lr, lr, #0
	umull	r8, r12, r10, r8
	adds	r8, r8, lr
	adc	r12, r12, #0
	umull	r9, lr, r10, r9
	adds	r9, r9, r12
	mov	r10, #19
	adc	lr, lr, #0
	lsl	lr, lr, #1
	orr	lr, lr, r9, LSR #31
	mul	lr, r10, lr
	adds	r2, r2, lr
	adcs	r3, r3, #0
	adcs	r4, r4, #0
	adcs	r5, r5, #0
	adcs	r6, r6, #0
	adcs	r7, r7, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0x80000000
#else
	bfc	r9, #31, #1
#endif
	adcs	r8, r8, #0
	adc	r9, r9, #0
	stm	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	fe_mul121666,.-fe_mul121666
#else
	.text
	.align	4
	.globl	fe_mul121666
	.type	fe_mul121666, %function
fe_mul121666:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	# Multiply by 121666
	ldm	r1, {r2, r3, r4, r5, r6, r7, r8, r9}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	lr, #1
	lsl	lr, lr, #8
	orr	lr, lr, #0xdb
	lsl	lr, lr, #8
	orr	lr, lr, #0x42
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	lr, #0xdb
	lsl	lr, lr, #8
	add	lr, lr, #0x42
#else
	mov	lr, #0xdb42
#endif
	movt	lr, #1
#endif
	umull	r2, r10, lr, r2
	sub	r12, lr, #1
	umaal	r3, r10, r12, r3
	umaal	r4, r10, r12, r4
	umaal	r5, r10, r12, r5
	umaal	r6, r10, r12, r6
	umaal	r7, r10, r12, r7
	umaal	r8, r10, r12, r8
	mov	lr, #19
	umaal	r9, r10, r12, r9
	lsl	r10, r10, #1
	orr	r10, r10, r9, lsr #31
	mul	r10, lr, r10
	adds	r2, r2, r10
	adcs	r3, r3, #0
	adcs	r4, r4, #0
	adcs	r5, r5, #0
	adcs	r6, r6, #0
	adcs	r7, r7, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0x80000000
#else
	bfc	r9, #31, #1
#endif
	adcs	r8, r8, #0
	adc	r9, r9, #0
	stm	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	fe_mul121666,.-fe_mul121666
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
#ifndef WC_NO_CACHE_RESISTANT
	.text
	.align	4
	.globl	curve25519
	.type	curve25519, %function
curve25519:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #0xbc
	str	r0, [sp, #160]
	str	r1, [sp, #164]
	str	r2, [sp, #168]
	mov	r1, #0
	str	r1, [sp, #172]
	mov	r4, #1
	mov	r5, #0
	mov	r6, #0
	mov	r7, #0
	mov	r8, #0
	mov	r9, #0
	mov	r10, #0
	mov	r11, #0
	stm	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	add	r3, sp, #32
	stm	r3, {r4, r5, r6, r7, r8, r9, r10, r11}
	mov	r4, #0
	mov	r3, sp
	stm	r3, {r4, r5, r6, r7, r8, r9, r10, r11}
	add	r3, sp, #0x40
	# Copy
	ldm	r2, {r4, r5, r6, r7, r8, r9, r10, r11}
	stm	r3, {r4, r5, r6, r7, r8, r9, r10, r11}
	mov	r1, #30
	str	r1, [sp, #180]
	mov	r2, #28
	str	r2, [sp, #176]
L_curve25519_words:
L_curve25519_bits:
	ldr	r1, [sp, #164]
	ldr	r2, [r1, r2]
	ldr	r1, [sp, #180]
	lsr	r2, r2, r1
	and	r2, r2, #1
	str	r2, [sp, #184]
	ldr	r1, [sp, #172]
	eor	r1, r1, r2
	str	r1, [sp, #172]
	ldr	r0, [sp, #160]
	# Conditional Swap
	rsb	r1, r1, #0
	mov	r3, r0
	add	r12, sp, #0x40
	ldm	r3, {r4, r5}
	ldm	r12, {r6, r7}
	eor	r8, r4, r6
	eor	r9, r5, r7
	and	r8, r8, r1
	and	r9, r9, r1
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r8
	eor	r7, r7, r9
	stm	r3!, {r4, r5}
	stm	r12!, {r6, r7}
	ldm	r3, {r4, r5}
	ldm	r12, {r6, r7}
	eor	r8, r4, r6
	eor	r9, r5, r7
	and	r8, r8, r1
	and	r9, r9, r1
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r8
	eor	r7, r7, r9
	stm	r3!, {r4, r5}
	stm	r12!, {r6, r7}
	ldm	r3, {r4, r5}
	ldm	r12, {r6, r7}
	eor	r8, r4, r6
	eor	r9, r5, r7
	and	r8, r8, r1
	and	r9, r9, r1
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r8
	eor	r7, r7, r9
	stm	r3!, {r4, r5}
	stm	r12!, {r6, r7}
	ldm	r3, {r4, r5}
	ldm	r12, {r6, r7}
	eor	r8, r4, r6
	eor	r9, r5, r7
	and	r8, r8, r1
	and	r9, r9, r1
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r8
	eor	r7, r7, r9
	stm	r3!, {r4, r5}
	stm	r12!, {r6, r7}
	ldr	r1, [sp, #172]
	# Conditional Swap
	rsb	r1, r1, #0
	mov	r3, sp
	add	r12, sp, #32
	ldm	r3, {r4, r5}
	ldm	r12, {r6, r7}
	eor	r8, r4, r6
	eor	r9, r5, r7
	and	r8, r8, r1
	and	r9, r9, r1
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r8
	eor	r7, r7, r9
	stm	r3!, {r4, r5}
	stm	r12!, {r6, r7}
	ldm	r3, {r4, r5}
	ldm	r12, {r6, r7}
	eor	r8, r4, r6
	eor	r9, r5, r7
	and	r8, r8, r1
	and	r9, r9, r1
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r8
	eor	r7, r7, r9
	stm	r3!, {r4, r5}
	stm	r12!, {r6, r7}
	ldm	r3, {r4, r5}
	ldm	r12, {r6, r7}
	eor	r8, r4, r6
	eor	r9, r5, r7
	and	r8, r8, r1
	and	r9, r9, r1
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r8
	eor	r7, r7, r9
	stm	r3!, {r4, r5}
	stm	r12!, {r6, r7}
	ldm	r3, {r4, r5}
	ldm	r12, {r6, r7}
	eor	r8, r4, r6
	eor	r9, r5, r7
	and	r8, r8, r1
	and	r9, r9, r1
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r8
	eor	r7, r7, r9
	stm	r3!, {r4, r5}
	stm	r12!, {r6, r7}
	ldr	r1, [sp, #184]
	str	r1, [sp, #172]
	mov	r3, sp
	ldr	r2, [sp, #160]
	add	r1, sp, #0x80
	ldr	r0, [sp, #160]
	bl	fe_add_sub_op
	add	r3, sp, #32
	add	r2, sp, #0x40
	add	r1, sp, #0x60
	mov	r0, sp
	bl	fe_add_sub_op
	ldr	r2, [sp, #160]
	add	r1, sp, #0x60
	add	r0, sp, #32
	bl	fe_mul_op
	add	r2, sp, #0x80
	mov	r1, sp
	mov	r0, sp
	bl	fe_mul_op
	add	r1, sp, #0x80
	add	r0, sp, #0x80
	bl	fe_sq_op
	ldr	r1, [sp, #160]
	add	r0, sp, #0x60
	bl	fe_sq_op
	mov	r3, sp
	add	r2, sp, #32
	mov	r1, sp
	add	r0, sp, #0x40
	bl	fe_add_sub_op
	add	r2, sp, #0x80
	add	r1, sp, #0x60
	ldr	r0, [sp, #160]
	bl	fe_mul_op
	add	r2, sp, #0x80
	add	r1, sp, #0x60
	add	r0, sp, #0x60
	bl	fe_sub_op
	mov	r1, sp
	mov	r0, sp
	bl	fe_sq_op
	add	r1, sp, #0x60
	add	r0, sp, #32
	bl	fe_mul121666
	add	r1, sp, #0x40
	add	r0, sp, #0x40
	bl	fe_sq_op
	add	r2, sp, #32
	add	r1, sp, #0x80
	add	r0, sp, #0x80
	bl	fe_add_op
	mov	r2, sp
	ldr	r1, [sp, #168]
	add	r0, sp, #32
	bl	fe_mul_op
	add	r2, sp, #0x80
	add	r1, sp, #0x60
	mov	r0, sp
	bl	fe_mul_op
	ldr	r2, [sp, #176]
	ldr	r1, [sp, #180]
	subs	r1, r1, #1
	str	r1, [sp, #180]
	bge	L_curve25519_bits
	mov	r1, #31
	str	r1, [sp, #180]
	subs	r2, r2, #4
	str	r2, [sp, #176]
	bge	L_curve25519_words
	# Invert
	add	r1, sp, #0
	add	r0, sp, #32
	bl	fe_sq_op
	add	r1, sp, #32
	add	r0, sp, #0x40
	bl	fe_sq_op
	add	r1, sp, #0x40
	add	r0, sp, #0x40
	bl	fe_sq_op
	add	r2, sp, #0x40
	add	r1, sp, #0
	add	r0, sp, #0x40
	bl	fe_mul_op
	add	r2, sp, #0x40
	add	r1, sp, #32
	add	r0, sp, #32
	bl	fe_mul_op
	add	r1, sp, #32
	add	r0, sp, #0x60
	bl	fe_sq_op
	add	r2, sp, #0x60
	add	r1, sp, #0x40
	add	r0, sp, #0x40
	bl	fe_mul_op
	add	r1, sp, #0x40
	add	r0, sp, #0x60
	bl	fe_sq_op
	mov	r12, #4
L_curve25519_inv_1:
	add	r1, sp, #0x60
	add	r0, sp, #0x60
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_curve25519_inv_1
	add	r2, sp, #0x40
	add	r1, sp, #0x60
	add	r0, sp, #0x40
	bl	fe_mul_op
	add	r1, sp, #0x40
	add	r0, sp, #0x60
	bl	fe_sq_op
	mov	r12, #9
L_curve25519_inv_2:
	add	r1, sp, #0x60
	add	r0, sp, #0x60
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_curve25519_inv_2
	add	r2, sp, #0x40
	add	r1, sp, #0x60
	add	r0, sp, #0x60
	bl	fe_mul_op
	add	r1, sp, #0x60
	add	r0, sp, #0x80
	bl	fe_sq_op
	mov	r12, #19
L_curve25519_inv_3:
	add	r1, sp, #0x80
	add	r0, sp, #0x80
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_curve25519_inv_3
	add	r2, sp, #0x60
	add	r1, sp, #0x80
	add	r0, sp, #0x60
	bl	fe_mul_op
	mov	r12, #10
L_curve25519_inv_4:
	add	r1, sp, #0x60
	add	r0, sp, #0x60
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_curve25519_inv_4
	add	r2, sp, #0x40
	add	r1, sp, #0x60
	add	r0, sp, #0x40
	bl	fe_mul_op
	add	r1, sp, #0x40
	add	r0, sp, #0x60
	bl	fe_sq_op
	mov	r12, #49
L_curve25519_inv_5:
	add	r1, sp, #0x60
	add	r0, sp, #0x60
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_curve25519_inv_5
	add	r2, sp, #0x40
	add	r1, sp, #0x60
	add	r0, sp, #0x60
	bl	fe_mul_op
	add	r1, sp, #0x60
	add	r0, sp, #0x80
	bl	fe_sq_op
	mov	r12, #0x63
L_curve25519_inv_6:
	add	r1, sp, #0x80
	add	r0, sp, #0x80
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_curve25519_inv_6
	add	r2, sp, #0x60
	add	r1, sp, #0x80
	add	r0, sp, #0x60
	bl	fe_mul_op
	mov	r12, #50
L_curve25519_inv_7:
	add	r1, sp, #0x60
	add	r0, sp, #0x60
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_curve25519_inv_7
	add	r2, sp, #0x40
	add	r1, sp, #0x60
	add	r0, sp, #0x40
	bl	fe_mul_op
	mov	r12, #5
L_curve25519_inv_8:
	add	r1, sp, #0x40
	add	r0, sp, #0x40
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_curve25519_inv_8
	add	r2, sp, #32
	add	r1, sp, #0x40
	add	r0, sp, #0
	bl	fe_mul_op
	mov	r2, sp
	ldr	r1, [sp, #160]
	ldr	r0, [sp, #160]
	bl	fe_mul_op
	mov	r0, #0
	add	sp, sp, #0xbc
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	curve25519,.-curve25519
#else
	.text
	.align	4
	.globl	curve25519
	.type	curve25519, %function
curve25519:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #0xc0
	str	r0, [sp, #176]
	str	r1, [sp, #160]
	str	r2, [sp, #172]
	add	r5, sp, #0x40
	add	r4, sp, #32
	str	sp, [sp, #184]
	str	r5, [sp, #180]
	str	r4, [sp, #188]
	mov	r1, #0
	str	r1, [sp, #164]
	mov	r4, #1
	mov	r5, #0
	mov	r6, #0
	mov	r7, #0
	mov	r8, #0
	mov	r9, #0
	mov	r10, #0
	mov	r11, #0
	stm	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	add	r3, sp, #32
	stm	r3, {r4, r5, r6, r7, r8, r9, r10, r11}
	mov	r4, #0
	mov	r3, sp
	stm	r3, {r4, r5, r6, r7, r8, r9, r10, r11}
	add	r3, sp, #0x40
	# Copy
	ldm	r2, {r4, r5, r6, r7, r8, r9, r10, r11}
	stm	r3, {r4, r5, r6, r7, r8, r9, r10, r11}
	mov	r2, #0xfe
L_curve25519_bits:
	str	r2, [sp, #168]
	ldr	r1, [sp, #160]
	and	r4, r2, #31
	lsr	r2, r2, #5
	ldr	r2, [r1, r2, lsl #2]
	rsb	r4, r4, #31
	lsl	r2, r2, r4
	ldr	r1, [sp, #164]
	eor	r1, r1, r2
	asr	r1, r1, #31
	str	r2, [sp, #164]
	# Conditional Swap
	add	r11, sp, #0xb0
	ldm	r11, {r4, r5, r6, r7}
	eor	r8, r4, r5
	eor	r9, r6, r7
	and	r8, r8, r1
	and	r9, r9, r1
	eor	r4, r4, r8
	eor	r5, r5, r8
	eor	r6, r6, r9
	eor	r7, r7, r9
	stm	r11, {r4, r5, r6, r7}
	# Ladder step
	ldr	r3, [sp, #184]
	ldr	r2, [sp, #176]
	add	r1, sp, #0x80
	ldr	r0, [sp, #176]
	bl	fe_add_sub_op
	ldr	r3, [sp, #188]
	ldr	r2, [sp, #180]
	add	r1, sp, #0x60
	ldr	r0, [sp, #184]
	bl	fe_add_sub_op
	ldr	r2, [sp, #176]
	add	r1, sp, #0x60
	ldr	r0, [sp, #188]
	bl	fe_mul_op
	add	r2, sp, #0x80
	ldr	r1, [sp, #184]
	ldr	r0, [sp, #184]
	bl	fe_mul_op
	add	r1, sp, #0x80
	add	r0, sp, #0x60
	bl	fe_sq_op
	ldr	r1, [sp, #176]
	add	r0, sp, #0x80
	bl	fe_sq_op
	ldr	r3, [sp, #184]
	ldr	r2, [sp, #188]
	ldr	r1, [sp, #184]
	ldr	r0, [sp, #180]
	bl	fe_add_sub_op
	add	r2, sp, #0x60
	add	r1, sp, #0x80
	ldr	r0, [sp, #176]
	bl	fe_mul_op
	add	r2, sp, #0x60
	add	r1, sp, #0x80
	add	r0, sp, #0x80
	bl	fe_sub_op
	ldr	r1, [sp, #184]
	ldr	r0, [sp, #184]
	bl	fe_sq_op
	add	r1, sp, #0x80
	ldr	r0, [sp, #188]
	bl	fe_mul121666
	ldr	r1, [sp, #180]
	ldr	r0, [sp, #180]
	bl	fe_sq_op
	ldr	r2, [sp, #188]
	add	r1, sp, #0x60
	add	r0, sp, #0x60
	bl	fe_add_op
	ldr	r2, [sp, #184]
	ldr	r1, [sp, #172]
	ldr	r0, [sp, #188]
	bl	fe_mul_op
	add	r2, sp, #0x60
	add	r1, sp, #0x80
	ldr	r0, [sp, #184]
	bl	fe_mul_op
	ldr	r2, [sp, #168]
	subs	r2, r2, #1
	bge	L_curve25519_bits
	ldr	r1, [sp, #184]
	# Copy
	ldm	r1, {r4, r5, r6, r7, r8, r9, r10, r11}
	stm	sp, {r4, r5, r6, r7, r8, r9, r10, r11}
	# Invert
	add	r1, sp, #0
	add	r0, sp, #32
	bl	fe_sq_op
	add	r1, sp, #32
	add	r0, sp, #0x40
	bl	fe_sq_op
	add	r1, sp, #0x40
	add	r0, sp, #0x40
	bl	fe_sq_op
	add	r2, sp, #0x40
	add	r1, sp, #0
	add	r0, sp, #0x40
	bl	fe_mul_op
	add	r2, sp, #0x40
	add	r1, sp, #32
	add	r0, sp, #32
	bl	fe_mul_op
	add	r1, sp, #32
	add	r0, sp, #0x60
	bl	fe_sq_op
	add	r2, sp, #0x60
	add	r1, sp, #0x40
	add	r0, sp, #0x40
	bl	fe_mul_op
	add	r1, sp, #0x40
	add	r0, sp, #0x60
	bl	fe_sq_op
	mov	r12, #4
L_curve25519_inv_1:
	add	r1, sp, #0x60
	add	r0, sp, #0x60
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_curve25519_inv_1
	add	r2, sp, #0x40
	add	r1, sp, #0x60
	add	r0, sp, #0x40
	bl	fe_mul_op
	add	r1, sp, #0x40
	add	r0, sp, #0x60
	bl	fe_sq_op
	mov	r12, #9
L_curve25519_inv_2:
	add	r1, sp, #0x60
	add	r0, sp, #0x60
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_curve25519_inv_2
	add	r2, sp, #0x40
	add	r1, sp, #0x60
	add	r0, sp, #0x60
	bl	fe_mul_op
	add	r1, sp, #0x60
	add	r0, sp, #0x80
	bl	fe_sq_op
	mov	r12, #19
L_curve25519_inv_3:
	add	r1, sp, #0x80
	add	r0, sp, #0x80
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_curve25519_inv_3
	add	r2, sp, #0x60
	add	r1, sp, #0x80
	add	r0, sp, #0x60
	bl	fe_mul_op
	mov	r12, #10
L_curve25519_inv_4:
	add	r1, sp, #0x60
	add	r0, sp, #0x60
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_curve25519_inv_4
	add	r2, sp, #0x40
	add	r1, sp, #0x60
	add	r0, sp, #0x40
	bl	fe_mul_op
	add	r1, sp, #0x40
	add	r0, sp, #0x60
	bl	fe_sq_op
	mov	r12, #49
L_curve25519_inv_5:
	add	r1, sp, #0x60
	add	r0, sp, #0x60
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_curve25519_inv_5
	add	r2, sp, #0x40
	add	r1, sp, #0x60
	add	r0, sp, #0x60
	bl	fe_mul_op
	add	r1, sp, #0x60
	add	r0, sp, #0x80
	bl	fe_sq_op
	mov	r12, #0x63
L_curve25519_inv_6:
	add	r1, sp, #0x80
	add	r0, sp, #0x80
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_curve25519_inv_6
	add	r2, sp, #0x60
	add	r1, sp, #0x80
	add	r0, sp, #0x60
	bl	fe_mul_op
	mov	r12, #50
L_curve25519_inv_7:
	add	r1, sp, #0x60
	add	r0, sp, #0x60
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_curve25519_inv_7
	add	r2, sp, #0x40
	add	r1, sp, #0x60
	add	r0, sp, #0x40
	bl	fe_mul_op
	mov	r12, #5
L_curve25519_inv_8:
	add	r1, sp, #0x40
	add	r0, sp, #0x40
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_curve25519_inv_8
	add	r2, sp, #32
	add	r1, sp, #0x40
	add	r0, sp, #0
	bl	fe_mul_op
	ldr	r2, [sp, #184]
	ldr	r1, [sp, #176]
	ldr	r0, [sp, #176]
	bl	fe_mul_op
	# Ensure result is less than modulus
	ldr	r0, [sp, #176]
	ldm	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	mov	r2, #19
	and	r2, r2, r11, asr #31
	adds	r4, r4, r2
	adcs	r5, r5, #0
	adcs	r6, r6, #0
	adcs	r7, r7, #0
	adcs	r8, r8, #0
	adcs	r9, r9, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r11, r11, #0x80000000
#else
	bfc	r11, #31, #1
#endif
	adcs	r10, r10, #0
	adc	r11, r11, #0
	stm	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	mov	r0, #0
	add	sp, sp, #0xc0
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	curve25519,.-curve25519
#endif /* WC_NO_CACHE_RESISTANT */
#endif /* HAVE_CURVE25519 */
#ifdef HAVE_ED25519
	.text
	.align	4
	.globl	fe_invert
	.type	fe_invert, %function
fe_invert:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #0x88
	# Invert
	str	r0, [sp, #128]
	str	r1, [sp, #132]
	ldr	r1, [sp, #132]
	mov	r0, sp
	bl	fe_sq_op
	mov	r1, sp
	add	r0, sp, #32
	bl	fe_sq_op
	add	r1, sp, #32
	add	r0, sp, #32
	bl	fe_sq_op
	add	r2, sp, #32
	ldr	r1, [sp, #132]
	add	r0, sp, #32
	bl	fe_mul_op
	add	r2, sp, #32
	mov	r1, sp
	mov	r0, sp
	bl	fe_mul_op
	mov	r1, sp
	add	r0, sp, #0x40
	bl	fe_sq_op
	add	r2, sp, #0x40
	add	r1, sp, #32
	add	r0, sp, #32
	bl	fe_mul_op
	add	r1, sp, #32
	add	r0, sp, #0x40
	bl	fe_sq_op
	mov	r12, #4
L_fe_invert1:
	add	r1, sp, #0x40
	add	r0, sp, #0x40
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_fe_invert1
	add	r2, sp, #32
	add	r1, sp, #0x40
	add	r0, sp, #32
	bl	fe_mul_op
	add	r1, sp, #32
	add	r0, sp, #0x40
	bl	fe_sq_op
	mov	r12, #9
L_fe_invert2:
	add	r1, sp, #0x40
	add	r0, sp, #0x40
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_fe_invert2
	add	r2, sp, #32
	add	r1, sp, #0x40
	add	r0, sp, #0x40
	bl	fe_mul_op
	add	r1, sp, #0x40
	add	r0, sp, #0x60
	bl	fe_sq_op
	mov	r12, #19
L_fe_invert3:
	add	r1, sp, #0x60
	add	r0, sp, #0x60
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_fe_invert3
	add	r2, sp, #0x40
	add	r1, sp, #0x60
	add	r0, sp, #0x40
	bl	fe_mul_op
	mov	r12, #10
L_fe_invert4:
	add	r1, sp, #0x40
	add	r0, sp, #0x40
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_fe_invert4
	add	r2, sp, #32
	add	r1, sp, #0x40
	add	r0, sp, #32
	bl	fe_mul_op
	add	r1, sp, #32
	add	r0, sp, #0x40
	bl	fe_sq_op
	mov	r12, #49
L_fe_invert5:
	add	r1, sp, #0x40
	add	r0, sp, #0x40
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_fe_invert5
	add	r2, sp, #32
	add	r1, sp, #0x40
	add	r0, sp, #0x40
	bl	fe_mul_op
	add	r1, sp, #0x40
	add	r0, sp, #0x60
	bl	fe_sq_op
	mov	r12, #0x63
L_fe_invert6:
	add	r1, sp, #0x60
	add	r0, sp, #0x60
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_fe_invert6
	add	r2, sp, #0x40
	add	r1, sp, #0x60
	add	r0, sp, #0x40
	bl	fe_mul_op
	mov	r12, #50
L_fe_invert7:
	add	r1, sp, #0x40
	add	r0, sp, #0x40
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_fe_invert7
	add	r2, sp, #32
	add	r1, sp, #0x40
	add	r0, sp, #32
	bl	fe_mul_op
	mov	r12, #5
L_fe_invert8:
	add	r1, sp, #32
	add	r0, sp, #32
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_fe_invert8
	mov	r2, sp
	add	r1, sp, #32
	ldr	r0, [sp, #128]
	bl	fe_mul_op
	ldr	r1, [sp, #132]
	ldr	r0, [sp, #128]
	add	sp, sp, #0x88
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	fe_invert,.-fe_invert
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	.text
	.align	4
	.globl	fe_sq2
	.type	fe_sq2, %function
fe_sq2:
	push	{lr}
	sub	sp, sp, #0x44
	str	r0, [sp, #64]
	# Square * 2
	mov	r0, #0
	ldr	r12, [r1]
	# A[0] * A[1]
	ldr	lr, [r1, #4]
	umull	r4, r5, r12, lr
	# A[0] * A[3]
	ldr	lr, [r1, #12]
	umull	r6, r7, r12, lr
	# A[0] * A[5]
	ldr	lr, [r1, #20]
	umull	r8, r9, r12, lr
	# A[0] * A[7]
	ldr	lr, [r1, #28]
	umull	r10, r3, r12, lr
	# A[0] * A[2]
	ldr	lr, [r1, #8]
	mov	r11, #0
	umlal	r5, r11, r12, lr
	adds	r6, r6, r11
	# A[0] * A[4]
	ldr	lr, [r1, #16]
	adcs	r7, r7, #0
	adc	r11, r0, #0
	umlal	r7, r11, r12, lr
	adds	r8, r8, r11
	# A[0] * A[6]
	ldr	lr, [r1, #24]
	adcs	r9, r9, #0
	adc	r11, r0, #0
	umlal	r9, r11, r12, lr
	adds	r10, r10, r11
	adcs	r3, r3, #0
	str	r4, [sp, #4]
	str	r5, [sp, #8]
	# A[1] * A[2]
	ldr	r12, [r1, #4]
	ldr	lr, [r1, #8]
	mov	r11, #0
	umlal	r6, r11, r12, lr
	str	r6, [sp, #12]
	adds	r7, r7, r11
	# A[1] * A[3]
	ldr	lr, [r1, #12]
	adc	r11, r0, #0
	umlal	r7, r11, r12, lr
	str	r7, [sp, #16]
	adds	r8, r8, r11
	# A[1] * A[4]
	ldr	lr, [r1, #16]
	adc	r11, r0, #0
	umlal	r8, r11, r12, lr
	adds	r9, r9, r11
	# A[1] * A[5]
	ldr	lr, [r1, #20]
	adc	r11, r0, #0
	umlal	r9, r11, r12, lr
	adds	r10, r10, r11
	# A[1] * A[6]
	ldr	lr, [r1, #24]
	adc	r11, r0, #0
	umlal	r10, r11, r12, lr
	adds	r3, r3, r11
	# A[1] * A[7]
	ldr	lr, [r1, #28]
	adc	r4, r0, #0
	umlal	r3, r4, r12, lr
	# A[2] * A[3]
	ldr	r12, [r1, #8]
	ldr	lr, [r1, #12]
	mov	r11, #0
	umlal	r8, r11, r12, lr
	str	r8, [sp, #20]
	adds	r9, r9, r11
	# A[2] * A[4]
	ldr	lr, [r1, #16]
	adc	r11, r0, #0
	umlal	r9, r11, r12, lr
	str	r9, [sp, #24]
	adds	r10, r10, r11
	# A[2] * A[5]
	ldr	lr, [r1, #20]
	adc	r11, r0, #0
	umlal	r10, r11, r12, lr
	adds	r3, r3, r11
	# A[2] * A[6]
	ldr	lr, [r1, #24]
	adc	r11, r0, #0
	umlal	r3, r11, r12, lr
	adds	r4, r4, r11
	# A[2] * A[7]
	ldr	lr, [r1, #28]
	adc	r5, r0, #0
	umlal	r4, r5, r12, lr
	# A[3] * A[4]
	ldr	r12, [r1, #12]
	ldr	lr, [r1, #16]
	mov	r11, #0
	umlal	r10, r11, r12, lr
	str	r10, [sp, #28]
	adds	r3, r3, r11
	# A[3] * A[5]
	ldr	lr, [r1, #20]
	adc	r11, r0, #0
	umlal	r3, r11, r12, lr
	adds	r4, r4, r11
	# A[3] * A[6]
	ldr	lr, [r1, #24]
	adc	r11, r0, #0
	umlal	r4, r11, r12, lr
	adds	r5, r5, r11
	# A[3] * A[7]
	ldr	lr, [r1, #28]
	adc	r6, r0, #0
	umlal	r5, r6, r12, lr
	# A[4] * A[5]
	ldr	r12, [r1, #16]
	ldr	lr, [r1, #20]
	mov	r11, #0
	umlal	r4, r11, r12, lr
	adds	r5, r5, r11
	# A[4] * A[6]
	ldr	lr, [r1, #24]
	adc	r11, r0, #0
	umlal	r5, r11, r12, lr
	adds	r6, r6, r11
	# A[4] * A[7]
	ldr	lr, [r1, #28]
	adc	r7, r0, #0
	umlal	r6, r7, r12, lr
	# A[5] * A[6]
	ldr	r12, [r1, #20]
	ldr	lr, [r1, #24]
	mov	r11, #0
	umlal	r6, r11, r12, lr
	adds	r7, r7, r11
	# A[5] * A[7]
	ldr	lr, [r1, #28]
	adc	r8, r0, #0
	umlal	r7, r8, r12, lr
	# A[6] * A[7]
	ldr	r12, [r1, #24]
	ldr	lr, [r1, #28]
	mov	r9, #0
	umlal	r8, r9, r12, lr
	add	lr, sp, #32
	stm	lr, {r3, r4, r5, r6, r7, r8, r9}
	add	lr, sp, #4
	ldm	lr, {r4, r5, r6, r7, r8, r9, r10}
	adds	r4, r4, r4
	adcs	r5, r5, r5
	adcs	r6, r6, r6
	adcs	r7, r7, r7
	adcs	r8, r8, r8
	adcs	r9, r9, r9
	adcs	r10, r10, r10
	stm	lr!, {r4, r5, r6, r7, r8, r9, r10}
	ldm	lr, {r3, r4, r5, r6, r7, r8, r9}
	adcs	r3, r3, r3
	adcs	r4, r4, r4
	adcs	r5, r5, r5
	adcs	r6, r6, r6
	adcs	r7, r7, r7
	adcs	r8, r8, r8
	adcs	r9, r9, r9
	adc	r10, r0, #0
	stm	lr, {r3, r4, r5, r6, r7, r8, r9, r10}
	add	lr, sp, #4
	ldm	lr, {r4, r5, r6, r7, r8, r9, r10}
	mov	lr, sp
	# A[0] * A[0]
	ldr	r12, [r1]
	umull	r3, r11, r12, r12
	adds	r4, r4, r11
	# A[1] * A[1]
	ldr	r12, [r1, #4]
	adcs	r5, r5, #0
	adc	r11, r0, #0
	umlal	r5, r11, r12, r12
	adds	r6, r6, r11
	# A[2] * A[2]
	ldr	r12, [r1, #8]
	adcs	r7, r7, #0
	adc	r11, r0, #0
	umlal	r7, r11, r12, r12
	adds	r8, r8, r11
	# A[3] * A[3]
	ldr	r12, [r1, #12]
	adcs	r9, r9, #0
	adc	r11, r0, #0
	umlal	r9, r11, r12, r12
	adds	r10, r10, r11
	stm	lr!, {r3, r4, r5, r6, r7, r8, r9, r10}
	ldm	lr, {r3, r4, r5, r6, r7, r8, r9, r10}
	# A[4] * A[4]
	ldr	r12, [r1, #16]
	adcs	r3, r3, #0
	adc	r11, r0, #0
	umlal	r3, r11, r12, r12
	adds	r4, r4, r11
	# A[5] * A[5]
	ldr	r12, [r1, #20]
	adcs	r5, r5, #0
	adc	r11, r0, #0
	umlal	r5, r11, r12, r12
	adds	r6, r6, r11
	# A[6] * A[6]
	ldr	r12, [r1, #24]
	adcs	r7, r7, #0
	adc	r11, r0, #0
	umlal	r7, r11, r12, r12
	adds	r8, r8, r11
	# A[7] * A[7]
	ldr	r12, [r1, #28]
	adcs	r9, r9, #0
	adc	r10, r10, #0
	umlal	r9, r10, r12, r12
	# Reduce
	ldr	r2, [sp, #28]
	mov	lr, sp
	mov	r12, #38
	umull	r10, r11, r12, r10
	adds	r10, r10, r2
	adc	r11, r11, #0
	mov	r12, #19
	lsl	r11, r11, #1
	orr	r11, r11, r10, LSR #31
	mul	r11, r12, r11
	ldm	lr!, {r1, r2}
	mov	r12, #38
	adds	r1, r1, r11
	adc	r11, r0, #0
	umlal	r1, r11, r3, r12
	adds	r2, r2, r11
	adc	r11, r0, #0
	umlal	r2, r11, r4, r12
	ldm	lr!, {r3, r4}
	adds	r3, r3, r11
	adc	r11, r0, #0
	umlal	r3, r11, r5, r12
	adds	r4, r4, r11
	adc	r11, r0, #0
	umlal	r4, r11, r6, r12
	ldm	lr!, {r5, r6}
	adds	r5, r5, r11
	adc	r11, r0, #0
	umlal	r5, r11, r7, r12
	adds	r6, r6, r11
	adc	r11, r0, #0
	umlal	r6, r11, r8, r12
	ldm	lr!, {r7, r8}
	adds	r7, r7, r11
	adc	r11, r0, #0
	umlal	r7, r11, r9, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r10, r10, #0x80000000
#else
	bfc	r10, #31, #1
#endif
	adds	r8, r10, r11
	# Reduce if top bit set
	mov	r12, #19
	and	r11, r12, r8, ASR #31
	adds	r1, r1, r11
	adcs	r2, r2, #0
	adcs	r3, r3, #0
	adcs	r4, r4, #0
	adcs	r5, r5, #0
	adcs	r6, r6, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0x80000000
#else
	bfc	r8, #31, #1
#endif
	adcs	r7, r7, #0
	adc	r8, r8, #0
	# Double
	adds	r1, r1, r1
	adcs	r2, r2, r2
	adcs	r3, r3, r3
	adcs	r4, r4, r4
	adcs	r5, r5, r5
	adcs	r6, r6, r6
	adcs	r7, r7, r7
	adc	r8, r8, r8
	# Reduce if top bit set
	mov	r12, #19
	and	r11, r12, r8, ASR #31
	adds	r1, r1, r11
	adcs	r2, r2, #0
	adcs	r3, r3, #0
	adcs	r4, r4, #0
	adcs	r5, r5, #0
	adcs	r6, r6, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r8, r8, #0x80000000
#else
	bfc	r8, #31, #1
#endif
	adcs	r7, r7, #0
	adc	r8, r8, #0
	# Store
	ldr	r0, [sp, #64]
	stm	r0, {r1, r2, r3, r4, r5, r6, r7, r8}
	add	sp, sp, #0x44
	pop	{pc}
	.size	fe_sq2,.-fe_sq2
#else
	.text
	.align	4
	.globl	fe_sq2
	.type	fe_sq2, %function
fe_sq2:
	push	{lr}
	sub	sp, sp, #36
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r0, [sp, #28]
	str	r1, [sp, #32]
#else
	strd	r0, r1, [sp, #28]
#endif
	ldm	r1, {r0, r1, r2, r3, r4, r5, r6, r7}
	# Square * 2
	umull	r9, r10, r0, r0
	umull	r11, r12, r0, r1
	adds	r11, r11, r11
	mov	lr, #0
	umaal	r10, r11, lr, lr
	stm	sp, {r9, r10}
	mov	r8, lr
	umaal	r8, r12, r0, r2
	adcs	r8, r8, r8
	umaal	r8, r11, r1, r1
	umull	r9, r10, r0, r3
	umaal	r9, r12, r1, r2
	adcs	r9, r9, r9
	umaal	r9, r11, lr, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [sp, #8]
	str	r9, [sp, #12]
#else
	strd	r8, r9, [sp, #8]
#endif
	mov	r9, lr
	umaal	r9, r10, r0, r4
	umaal	r9, r12, r1, r3
	adcs	r9, r9, r9
	umaal	r9, r11, r2, r2
	str	r9, [sp, #16]
	umull	r9, r8, r0, r5
	umaal	r9, r12, r1, r4
	umaal	r9, r10, r2, r3
	adcs	r9, r9, r9
	umaal	r9, r11, lr, lr
	str	r9, [sp, #20]
	mov	r9, lr
	umaal	r9, r8, r0, r6
	umaal	r9, r12, r1, r5
	umaal	r9, r10, r2, r4
	adcs	r9, r9, r9
	umaal	r9, r11, r3, r3
	str	r9, [sp, #24]
	umull	r0, r9, r0, r7
	umaal	r0, r8, r1, r6
	umaal	r0, r12, r2, r5
	umaal	r0, r10, r3, r4
	adcs	r0, r0, r0
	umaal	r0, r11, lr, lr
	# R[7] = r0
	umaal	r9, r8, r1, r7
	umaal	r9, r10, r2, r6
	umaal	r12, r9, r3, r5
	adcs	r12, r12, r12
	umaal	r12, r11, r4, r4
	# R[8] = r12
	umaal	r9, r8, r2, r7
	umaal	r10, r9, r3, r6
	mov	r2, lr
	umaal	r10, r2, r4, r5
	adcs	r10, r10, r10
	umaal	r11, r10, lr, lr
	# R[9] = r11
	umaal	r2, r8, r3, r7
	umaal	r2, r9, r4, r6
	adcs	r3, r2, r2
	umaal	r10, r3, r5, r5
	# R[10] = r10
	mov	r1, lr
	umaal	r1, r8, r4, r7
	umaal	r1, r9, r5, r6
	adcs	r4, r1, r1
	umaal	r3, r4, lr, lr
	# R[11] = r3
	umaal	r8, r9, r5, r7
	adcs	r8, r8, r8
	umaal	r4, r8, r6, r6
	# R[12] = r4
	mov	r5, lr
	umaal	r5, r9, r6, r7
	adcs	r5, r5, r5
	umaal	r8, r5, lr, lr
	# R[13] = r8
	adcs	r9, r9, r9
	umaal	r9, r5, r7, r7
	adcs	r7, r5, lr
	# R[14] = r9
	# R[15] = r7
	# Reduce
	mov	r6, #37
	umaal	r7, r0, r7, r6
	mov	r6, #19
	lsl	r0, r0, #1
	orr	r0, r0, r7, lsr #31
	mul	lr, r0, r6
	pop	{r0, r1}
	mov	r6, #38
	umaal	r0, lr, r12, r6
	umaal	r1, lr, r11, r6
	mov	r12, r3
	mov	r11, r4
	pop	{r2, r3, r4}
	umaal	r2, lr, r10, r6
	umaal	r3, lr, r12, r6
	umaal	r4, lr, r11, r6
	mov	r12, r6
	pop	{r5, r6}
	umaal	r5, lr, r8, r12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0x80000000
#else
	bfc	r7, #31, #1
#endif
	umaal	r6, lr, r9, r12
	add	r7, r7, lr
	# Reduce if top bit set
	mov	r11, #19
	and	r12, r11, r7, ASR #31
	adds	r0, r0, r12
	adcs	r1, r1, #0
	adcs	r2, r2, #0
	adcs	r3, r3, #0
	adcs	r4, r4, #0
	adcs	r5, r5, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0x80000000
#else
	bfc	r7, #31, #1
#endif
	adcs	r6, r6, #0
	adc	r7, r7, #0
	# Double
	adds	r0, r0, r0
	adcs	r1, r1, r1
	adcs	r2, r2, r2
	adcs	r3, r3, r3
	adcs	r4, r4, r4
	adcs	r5, r5, r5
	adcs	r6, r6, r6
	adc	r7, r7, r7
	# Reduce if top bit set
	mov	r11, #19
	and	r12, r11, r7, ASR #31
	adds	r0, r0, r12
	adcs	r1, r1, #0
	adcs	r2, r2, #0
	adcs	r3, r3, #0
	adcs	r4, r4, #0
	adcs	r5, r5, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r7, r7, #0x80000000
#else
	bfc	r7, #31, #1
#endif
	adcs	r6, r6, #0
	adc	r7, r7, #0
	pop	{r12, lr}
	# Store
	stm	r12, {r0, r1, r2, r3, r4, r5, r6, r7}
	mov	r0, r12
	mov	r1, lr
	pop	{pc}
	.size	fe_sq2,.-fe_sq2
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	.text
	.align	4
	.globl	fe_pow22523
	.type	fe_pow22523, %function
fe_pow22523:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #0x68
	# pow22523
	str	r0, [sp, #96]
	str	r1, [sp, #100]
	ldr	r1, [sp, #100]
	mov	r0, sp
	bl	fe_sq_op
	mov	r1, sp
	add	r0, sp, #32
	bl	fe_sq_op
	add	r1, sp, #32
	add	r0, sp, #32
	bl	fe_sq_op
	add	r2, sp, #32
	ldr	r1, [sp, #100]
	add	r0, sp, #32
	bl	fe_mul_op
	add	r2, sp, #32
	mov	r1, sp
	mov	r0, sp
	bl	fe_mul_op
	mov	r1, sp
	mov	r0, sp
	bl	fe_sq_op
	mov	r2, sp
	add	r1, sp, #32
	mov	r0, sp
	bl	fe_mul_op
	mov	r1, sp
	add	r0, sp, #32
	bl	fe_sq_op
	mov	r12, #4
L_fe_pow22523_1:
	add	r1, sp, #32
	add	r0, sp, #32
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_fe_pow22523_1
	mov	r2, sp
	add	r1, sp, #32
	mov	r0, sp
	bl	fe_mul_op
	mov	r1, sp
	add	r0, sp, #32
	bl	fe_sq_op
	mov	r12, #9
L_fe_pow22523_2:
	add	r1, sp, #32
	add	r0, sp, #32
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_fe_pow22523_2
	mov	r2, sp
	add	r1, sp, #32
	add	r0, sp, #32
	bl	fe_mul_op
	add	r1, sp, #32
	add	r0, sp, #0x40
	bl	fe_sq_op
	mov	r12, #19
L_fe_pow22523_3:
	add	r1, sp, #0x40
	add	r0, sp, #0x40
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_fe_pow22523_3
	add	r2, sp, #32
	add	r1, sp, #0x40
	add	r0, sp, #32
	bl	fe_mul_op
	mov	r12, #10
L_fe_pow22523_4:
	add	r1, sp, #32
	add	r0, sp, #32
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_fe_pow22523_4
	mov	r2, sp
	add	r1, sp, #32
	mov	r0, sp
	bl	fe_mul_op
	mov	r1, sp
	add	r0, sp, #32
	bl	fe_sq_op
	mov	r12, #49
L_fe_pow22523_5:
	add	r1, sp, #32
	add	r0, sp, #32
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_fe_pow22523_5
	mov	r2, sp
	add	r1, sp, #32
	add	r0, sp, #32
	bl	fe_mul_op
	add	r1, sp, #32
	add	r0, sp, #0x40
	bl	fe_sq_op
	mov	r12, #0x63
L_fe_pow22523_6:
	add	r1, sp, #0x40
	add	r0, sp, #0x40
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_fe_pow22523_6
	add	r2, sp, #32
	add	r1, sp, #0x40
	add	r0, sp, #32
	bl	fe_mul_op
	mov	r12, #50
L_fe_pow22523_7:
	add	r1, sp, #32
	add	r0, sp, #32
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_fe_pow22523_7
	mov	r2, sp
	add	r1, sp, #32
	mov	r0, sp
	bl	fe_mul_op
	mov	r12, #2
L_fe_pow22523_8:
	mov	r1, sp
	mov	r0, sp
	push	{r12}
	bl	fe_sq_op
	pop	{r12}
	subs	r12, r12, #1
	bne	L_fe_pow22523_8
	ldr	r2, [sp, #100]
	mov	r1, sp
	ldr	r0, [sp, #96]
	bl	fe_mul_op
	ldr	r1, [sp, #100]
	ldr	r0, [sp, #96]
	add	sp, sp, #0x68
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	fe_pow22523,.-fe_pow22523
	.text
	.align	4
	.globl	ge_p1p1_to_p2
	.type	ge_p1p1_to_p2, %function
ge_p1p1_to_p2:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #8
	str	r0, [sp]
	str	r1, [sp, #4]
	add	r2, r1, #0x60
	bl	fe_mul_op
	ldr	r0, [sp]
	ldr	r1, [sp, #4]
	add	r2, r1, #0x40
	add	r1, r1, #32
	add	r0, r0, #32
	bl	fe_mul_op
	ldr	r0, [sp]
	ldr	r1, [sp, #4]
	add	r2, r1, #0x60
	add	r1, r1, #0x40
	add	r0, r0, #0x40
	bl	fe_mul_op
	add	sp, sp, #8
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	ge_p1p1_to_p2,.-ge_p1p1_to_p2
	.text
	.align	4
	.globl	ge_p1p1_to_p3
	.type	ge_p1p1_to_p3, %function
ge_p1p1_to_p3:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #8
	str	r0, [sp]
	str	r1, [sp, #4]
	add	r2, r1, #0x60
	bl	fe_mul_op
	ldr	r0, [sp]
	ldr	r1, [sp, #4]
	add	r2, r1, #0x40
	add	r1, r1, #32
	add	r0, r0, #32
	bl	fe_mul_op
	ldr	r0, [sp]
	ldr	r1, [sp, #4]
	add	r2, r1, #0x60
	add	r1, r1, #0x40
	add	r0, r0, #0x40
	bl	fe_mul_op
	ldr	r0, [sp]
	ldr	r1, [sp, #4]
	add	r2, r1, #32
	add	r0, r0, #0x60
	bl	fe_mul_op
	add	sp, sp, #8
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	ge_p1p1_to_p3,.-ge_p1p1_to_p3
	.text
	.align	4
	.globl	ge_p2_dbl
	.type	ge_p2_dbl, %function
ge_p2_dbl:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #8
	str	r0, [sp]
	str	r1, [sp, #4]
	bl	fe_sq_op
	ldr	r0, [sp]
	ldr	r1, [sp, #4]
	add	r1, r1, #32
	add	r0, r0, #0x40
	bl	fe_sq_op
	ldr	r0, [sp]
	ldr	r1, [sp, #4]
	add	r2, r1, #32
	add	r0, r0, #32
	bl	fe_add_op
	mov	r1, r0
	add	r0, r0, #0x40
	bl	fe_sq_op
	ldr	r0, [sp]
	mov	r3, r0
	add	r2, r0, #0x40
	add	r1, r0, #0x40
	add	r0, r0, #32
	bl	fe_add_sub_op
	mov	r2, r0
	add	r1, r0, #0x40
	sub	r0, r0, #32
	bl	fe_sub_op
	ldr	r1, [sp, #4]
	add	r1, r1, #0x40
	add	r0, r0, #0x60
	bl	fe_sq2
	sub	r2, r0, #32
	mov	r1, r0
	bl	fe_sub_op
	add	sp, sp, #8
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	ge_p2_dbl,.-ge_p2_dbl
	.text
	.align	4
	.globl	ge_madd
	.type	ge_madd, %function
ge_madd:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #12
	str	r0, [sp]
	str	r1, [sp, #4]
	str	r2, [sp, #8]
	mov	r2, r1
	add	r1, r1, #32
	bl	fe_add_op
	ldr	r1, [sp, #4]
	mov	r2, r1
	add	r1, r1, #32
	add	r0, r0, #32
	bl	fe_sub_op
	ldr	r2, [sp, #8]
	sub	r1, r0, #32
	add	r0, r0, #32
	bl	fe_mul_op
	ldr	r0, [sp]
	ldr	r2, [sp, #8]
	add	r2, r2, #32
	add	r1, r0, #32
	add	r0, r0, #32
	bl	fe_mul_op
	ldr	r0, [sp]
	ldr	r1, [sp, #8]
	ldr	r2, [sp, #4]
	add	r2, r2, #0x60
	add	r1, r1, #0x40
	add	r0, r0, #0x60
	bl	fe_mul_op
	ldr	r0, [sp]
	add	r3, r0, #32
	add	r2, r0, #0x40
	mov	r1, r0
	add	r0, r0, #32
	bl	fe_add_sub_op
	ldr	r1, [sp, #4]
	add	r1, r1, #0x40
	add	r0, r0, #32
	# Double
	ldm	r1, {r4, r5, r6, r7, r8, r9, r10, r11}
	adds	r4, r4, r4
	adcs	r5, r5, r5
	adcs	r6, r6, r6
	adcs	r7, r7, r7
	adcs	r8, r8, r8
	adcs	r9, r9, r9
	adcs	r10, r10, r10
	mov	lr, #0
	adcs	r11, r11, r11
	adc	lr, lr, #0
	mov	r12, #19
	lsl	lr, lr, #1
	orr	lr, lr, r11, lsr #31
	mul	r12, lr, r12
	adds	r4, r4, r12
	adcs	r5, r5, #0
	adcs	r6, r6, #0
	adcs	r7, r7, #0
	adcs	r8, r8, #0
	adcs	r9, r9, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r11, r11, #0x80000000
#else
	bfc	r11, #31, #1
#endif
	adcs	r10, r10, #0
	adc	r11, r11, #0
	stm	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	# Done Double
	add	r3, r0, #32
	add	r1, r0, #32
	bl	fe_add_sub_op
	add	sp, sp, #12
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	ge_madd,.-ge_madd
	.text
	.align	4
	.globl	ge_msub
	.type	ge_msub, %function
ge_msub:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #12
	str	r0, [sp]
	str	r1, [sp, #4]
	str	r2, [sp, #8]
	mov	r2, r1
	add	r1, r1, #32
	bl	fe_add_op
	ldr	r1, [sp, #4]
	mov	r2, r1
	add	r1, r1, #32
	add	r0, r0, #32
	bl	fe_sub_op
	ldr	r2, [sp, #8]
	add	r2, r2, #32
	sub	r1, r0, #32
	add	r0, r0, #32
	bl	fe_mul_op
	ldr	r0, [sp]
	ldr	r2, [sp, #8]
	add	r1, r0, #32
	add	r0, r0, #32
	bl	fe_mul_op
	ldr	r0, [sp]
	ldr	r1, [sp, #8]
	ldr	r2, [sp, #4]
	add	r2, r2, #0x60
	add	r1, r1, #0x40
	add	r0, r0, #0x60
	bl	fe_mul_op
	ldr	r0, [sp]
	add	r3, r0, #32
	add	r2, r0, #0x40
	mov	r1, r0
	add	r0, r0, #32
	bl	fe_add_sub_op
	ldr	r1, [sp, #4]
	add	r1, r1, #0x40
	add	r0, r0, #32
	# Double
	ldm	r1, {r4, r5, r6, r7, r8, r9, r10, r11}
	adds	r4, r4, r4
	adcs	r5, r5, r5
	adcs	r6, r6, r6
	adcs	r7, r7, r7
	adcs	r8, r8, r8
	adcs	r9, r9, r9
	adcs	r10, r10, r10
	mov	lr, #0
	adcs	r11, r11, r11
	adc	lr, lr, #0
	mov	r12, #19
	lsl	lr, lr, #1
	orr	lr, lr, r11, lsr #31
	mul	r12, lr, r12
	adds	r4, r4, r12
	adcs	r5, r5, #0
	adcs	r6, r6, #0
	adcs	r7, r7, #0
	adcs	r8, r8, #0
	adcs	r9, r9, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r11, r11, #0x80000000
#else
	bfc	r11, #31, #1
#endif
	adcs	r10, r10, #0
	adc	r11, r11, #0
	stm	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	# Done Double
	add	r3, r0, #32
	mov	r1, r0
	add	r0, r0, #32
	bl	fe_add_sub_op
	add	sp, sp, #12
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	ge_msub,.-ge_msub
	.text
	.align	4
	.globl	ge_add
	.type	ge_add, %function
ge_add:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #44
	str	r0, [sp]
	str	r1, [sp, #4]
	str	r2, [sp, #8]
	mov	r3, r1
	add	r2, r1, #32
	add	r1, r0, #32
	bl	fe_add_sub_op
	ldr	r2, [sp, #8]
	mov	r1, r0
	add	r0, r0, #0x40
	bl	fe_mul_op
	ldr	r0, [sp]
	ldr	r2, [sp, #8]
	add	r2, r2, #32
	add	r1, r0, #32
	add	r0, r0, #32
	bl	fe_mul_op
	ldr	r0, [sp]
	ldr	r1, [sp, #8]
	ldr	r2, [sp, #4]
	add	r2, r2, #0x60
	add	r1, r1, #0x60
	add	r0, r0, #0x60
	bl	fe_mul_op
	ldr	r0, [sp]
	ldr	r1, [sp, #4]
	ldr	r2, [sp, #8]
	add	r2, r2, #0x40
	add	r1, r1, #0x40
	bl	fe_mul_op
	ldr	r1, [sp]
	add	r0, sp, #12
	# Double
	ldm	r1, {r4, r5, r6, r7, r8, r9, r10, r11}
	adds	r4, r4, r4
	adcs	r5, r5, r5
	adcs	r6, r6, r6
	adcs	r7, r7, r7
	adcs	r8, r8, r8
	adcs	r9, r9, r9
	adcs	r10, r10, r10
	mov	lr, #0
	adcs	r11, r11, r11
	adc	lr, lr, #0
	mov	r12, #19
	lsl	lr, lr, #1
	orr	lr, lr, r11, lsr #31
	mul	r12, lr, r12
	adds	r4, r4, r12
	adcs	r5, r5, #0
	adcs	r6, r6, #0
	adcs	r7, r7, #0
	adcs	r8, r8, #0
	adcs	r9, r9, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r11, r11, #0x80000000
#else
	bfc	r11, #31, #1
#endif
	adcs	r10, r10, #0
	adc	r11, r11, #0
	stm	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	# Done Double
	add	r3, r1, #32
	add	r2, r1, #0x40
	add	r0, r1, #32
	bl	fe_add_sub_op
	add	r3, r0, #0x40
	add	r2, sp, #12
	add	r1, r0, #0x40
	add	r0, r0, #32
	bl	fe_add_sub_op
	add	sp, sp, #44
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	ge_add,.-ge_add
	.text
	.align	4
	.globl	ge_sub
	.type	ge_sub, %function
ge_sub:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #44
	str	r0, [sp]
	str	r1, [sp, #4]
	str	r2, [sp, #8]
	mov	r3, r1
	add	r2, r1, #32
	add	r1, r0, #32
	bl	fe_add_sub_op
	ldr	r2, [sp, #8]
	add	r2, r2, #32
	mov	r1, r0
	add	r0, r0, #0x40
	bl	fe_mul_op
	ldr	r0, [sp]
	ldr	r2, [sp, #8]
	add	r1, r0, #32
	add	r0, r0, #32
	bl	fe_mul_op
	ldr	r0, [sp]
	ldr	r1, [sp, #8]
	ldr	r2, [sp, #4]
	add	r2, r2, #0x60
	add	r1, r1, #0x60
	add	r0, r0, #0x60
	bl	fe_mul_op
	ldr	r0, [sp]
	ldr	r1, [sp, #4]
	ldr	r2, [sp, #8]
	add	r2, r2, #0x40
	add	r1, r1, #0x40
	bl	fe_mul_op
	ldr	r1, [sp]
	add	r0, sp, #12
	# Double
	ldm	r1, {r4, r5, r6, r7, r8, r9, r10, r11}
	adds	r4, r4, r4
	adcs	r5, r5, r5
	adcs	r6, r6, r6
	adcs	r7, r7, r7
	adcs	r8, r8, r8
	adcs	r9, r9, r9
	adcs	r10, r10, r10
	mov	lr, #0
	adcs	r11, r11, r11
	adc	lr, lr, #0
	mov	r12, #19
	lsl	lr, lr, #1
	orr	lr, lr, r11, lsr #31
	mul	r12, lr, r12
	adds	r4, r4, r12
	adcs	r5, r5, #0
	adcs	r6, r6, #0
	adcs	r7, r7, #0
	adcs	r8, r8, #0
	adcs	r9, r9, #0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r11, r11, #0x80000000
#else
	bfc	r11, #31, #1
#endif
	adcs	r10, r10, #0
	adc	r11, r11, #0
	stm	r0, {r4, r5, r6, r7, r8, r9, r10, r11}
	# Done Double
	add	r3, r1, #32
	add	r2, r1, #0x40
	add	r0, r1, #32
	bl	fe_add_sub_op
	add	r3, r0, #0x40
	add	r2, sp, #12
	add	r1, r0, #32
	add	r0, r0, #0x40
	bl	fe_add_sub_op
	add	sp, sp, #44
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	ge_sub,.-ge_sub
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	.text
	.align	4
	.globl	sc_reduce
	.type	sc_reduce, %function
sc_reduce:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #56
	str	r0, [sp, #52]
	# Load bits 252-511
	add	r0, r0, #28
	ldm	r0, {r1, r2, r3, r4, r5, r6, r7, r8, r9}
	lsr	lr, r9, #24
	lsl	r9, r9, #4
	orr	r9, r9, r8, LSR #28
	lsl	r8, r8, #4
	orr	r8, r8, r7, LSR #28
	lsl	r7, r7, #4
	orr	r7, r7, r6, LSR #28
	lsl	r6, r6, #4
	orr	r6, r6, r5, LSR #28
	lsl	r5, r5, #4
	orr	r5, r5, r4, LSR #28
	lsl	r4, r4, #4
	orr	r4, r4, r3, LSR #28
	lsl	r3, r3, #4
	orr	r3, r3, r2, LSR #28
	lsl	r2, r2, #4
	orr	r2, r2, r1, LSR #28
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xf0000000
#else
	bfc	r9, #28, #4
#endif
	sub	r0, r0, #28
	# Add order times bits 504..511
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xa3
	lsl	r10, r10, #8
	orr	r10, r10, #10
	lsl	r10, r10, #8
	orr	r10, r10, #44
	lsl	r10, r10, #8
	orr	r10, r10, #19
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0x2c
	lsl	r10, r10, #8
	add	r10, r10, #0x13
#else
	mov	r10, #0x2c13
#endif
	movt	r10, #0xa30a
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0xa7
	lsl	r11, r11, #8
	orr	r11, r11, #0xed
	lsl	r11, r11, #8
	orr	r11, r11, #0x9c
	lsl	r11, r11, #8
	orr	r11, r11, #0xe5
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x9c
	lsl	r11, r11, #8
	add	r11, r11, #0xe5
#else
	mov	r11, #0x9ce5
#endif
	movt	r11, #0xa7ed
#endif
	mov	r1, #0
	umlal	r2, r1, r10, lr
	adds	r3, r3, r1
	mov	r1, #0
	adc	r1, r1, #0
	umlal	r3, r1, r11, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0x5d
	lsl	r10, r10, #8
	orr	r10, r10, #8
	lsl	r10, r10, #8
	orr	r10, r10, #0x63
	lsl	r10, r10, #8
	orr	r10, r10, #41
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0x63
	lsl	r10, r10, #8
	add	r10, r10, #0x29
#else
	mov	r10, #0x6329
#endif
	movt	r10, #0x5d08
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0xeb
	lsl	r11, r11, #8
	orr	r11, r11, #33
	lsl	r11, r11, #8
	orr	r11, r11, #6
	lsl	r11, r11, #8
	orr	r11, r11, #33
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x6
	lsl	r11, r11, #8
	add	r11, r11, #0x21
#else
	mov	r11, #0x621
#endif
	movt	r11, #0xeb21
#endif
	adds	r4, r4, r1
	mov	r1, #0
	adc	r1, r1, #0
	umlal	r4, r1, r10, lr
	adds	r5, r5, r1
	mov	r1, #0
	adc	r1, r1, #0
	umlal	r5, r1, r11, lr
	adds	r6, r6, r1
	adcs	r7, r7, #0
	adcs	r8, r8, #0
	adc	r9, r9, #0
	subs	r6, r6, lr
	sbcs	r7, r7, #0
	sbcs	r8, r8, #0
	sbc	r9, r9, #0
	# Sub product of top 8 words and order
	mov	r12, sp
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa3
	lsl	r1, r1, #8
	orr	r1, r1, #10
	lsl	r1, r1, #8
	orr	r1, r1, #44
	lsl	r1, r1, #8
	orr	r1, r1, #19
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x2c
	lsl	r1, r1, #8
	add	r1, r1, #0x13
#else
	mov	r1, #0x2c13
#endif
	movt	r1, #0xa30a
#endif
	mov	lr, #0
	ldm	r0!, {r10, r11}
	umlal	r10, lr, r2, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r3, r1
	stm	r12!, {r10, r11}
	ldm	r0!, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r4, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r5, r1
	stm	r12!, {r10, r11}
	ldm	r0!, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r6, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r7, r1
	stm	r12!, {r10, r11}
	ldm	r0!, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r8, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r11, r11, #0xf0000000
#else
	bfc	r11, #28, #4
#endif
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r9, r1
	stm	r12!, {r10, r11, lr}
	sub	r0, r0, #16
	sub	r12, r12, #32
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa7
	lsl	r1, r1, #8
	orr	r1, r1, #0xed
	lsl	r1, r1, #8
	orr	r1, r1, #0x9c
	lsl	r1, r1, #8
	orr	r1, r1, #0xe5
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x9c
	lsl	r1, r1, #8
	add	r1, r1, #0xe5
#else
	mov	r1, #0x9ce5
#endif
	movt	r1, #0xa7ed
#endif
	mov	lr, #0
	ldm	r12, {r10, r11}
	umlal	r10, lr, r2, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r3, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r4, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r5, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r6, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r7, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r8, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r9, r1
	stm	r12!, {r10, r11, lr}
	sub	r12, r12, #32
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x5d
	lsl	r1, r1, #8
	orr	r1, r1, #8
	lsl	r1, r1, #8
	orr	r1, r1, #0x63
	lsl	r1, r1, #8
	orr	r1, r1, #41
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x63
	lsl	r1, r1, #8
	add	r1, r1, #0x29
#else
	mov	r1, #0x6329
#endif
	movt	r1, #0x5d08
#endif
	mov	lr, #0
	ldm	r12, {r10, r11}
	umlal	r10, lr, r2, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r3, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r4, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r5, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r6, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r7, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r8, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r9, r1
	stm	r12!, {r10, r11, lr}
	sub	r12, r12, #32
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xeb
	lsl	r1, r1, #8
	orr	r1, r1, #33
	lsl	r1, r1, #8
	orr	r1, r1, #6
	lsl	r1, r1, #8
	orr	r1, r1, #33
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x6
	lsl	r1, r1, #8
	add	r1, r1, #0x21
#else
	mov	r1, #0x621
#endif
	movt	r1, #0xeb21
#endif
	mov	lr, #0
	ldm	r12, {r10, r11}
	umlal	r10, lr, r2, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r3, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r4, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r5, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r6, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r7, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r8, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r9, r1
	stm	r12!, {r10, r11, lr}
	sub	r12, r12, #32
	# Subtract at 4 * 32
	ldm	r12, {r10, r11}
	subs	r10, r10, r2
	sbcs	r11, r11, r3
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	sbcs	r10, r10, r4
	sbcs	r11, r11, r5
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	sbcs	r10, r10, r6
	sbcs	r11, r11, r7
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	sbcs	r10, r10, r8
	sbc	r11, r11, r9
	stm	r12!, {r10, r11}
	sub	r12, r12, #36
	asr	lr, r11, #25
	# Conditionally subtract order starting at bit 125
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa00000
	lsl	r1, r1, #8
	add	r1, r1, #0x0
#else
	mov	r1, #0xa0000000
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x4b
	lsl	r2, r2, #8
	orr	r2, r2, #0x9e
	lsl	r2, r2, #8
	orr	r2, r2, #0xba
	lsl	r2, r2, #8
	orr	r2, r2, #0x7d
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xba
	lsl	r2, r2, #8
	add	r2, r2, #0x7d
#else
	mov	r2, #0xba7d
#endif
	movt	r2, #0x4b9e
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0xcb
	lsl	r3, r3, #8
	orr	r3, r3, #2
	lsl	r3, r3, #8
	orr	r3, r3, #0x4c
	lsl	r3, r3, #8
	orr	r3, r3, #0x63
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x4c
	lsl	r3, r3, #8
	add	r3, r3, #0x63
#else
	mov	r3, #0x4c63
#endif
	movt	r3, #0xcb02
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r4, #0xd4
	lsl	r4, r4, #8
	orr	r4, r4, #0x5e
	lsl	r4, r4, #8
	orr	r4, r4, #0xf3
	lsl	r4, r4, #8
	orr	r4, r4, #0x9a
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r4, #0xf3
	lsl	r4, r4, #8
	add	r4, r4, #0x9a
#else
	mov	r4, #0xf39a
#endif
	movt	r4, #0xd45e
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r5, #2
	lsl	r5, r5, #8
	orr	r5, r5, #0x9b
	lsl	r5, r5, #8
	orr	r5, r5, #0xdf
	lsl	r5, r5, #8
	orr	r5, r5, #59
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r5, #0xdf
	lsl	r5, r5, #8
	add	r5, r5, #0x3b
#else
	mov	r5, #0xdf3b
#endif
	movt	r5, #0x29b
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r9, #0x20000
	lsl	r9, r9, #8
	add	r9, r9, #0x0
#else
	mov	r9, #0x2000000
#endif
	and	r1, r1, lr
	and	r2, r2, lr
	and	r3, r3, lr
	and	r4, r4, lr
	and	r5, r5, lr
	and	r9, r9, lr
	ldm	r12, {r10, r11}
	adds	r10, r10, r1
	adcs	r11, r11, r2
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adcs	r10, r10, r3
	adcs	r11, r11, r4
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adcs	r10, r10, r5
	adcs	r11, r11, #0
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adcs	r10, r10, #0
	adcs	r11, r11, #0
	stm	r12!, {r10, r11}
	ldm	r12, {r10}
	adcs	r10, r10, #0
	stm	r12!, {r10}
	sub	r0, r0, #16
	mov	r12, sp
	# Load bits 252-376
	add	r12, r12, #28
	ldm	r12, {r1, r2, r3, r4, r5}
	lsl	r5, r5, #4
	orr	r5, r5, r4, lsr #28
	lsl	r4, r4, #4
	orr	r4, r4, r3, lsr #28
	lsl	r3, r3, #4
	orr	r3, r3, r2, lsr #28
	lsl	r2, r2, #4
	orr	r2, r2, r1, lsr #28
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xe0000000
#else
	bfc	r5, #29, #3
#endif
	sub	r12, r12, #28
	# Sub product of top 4 words and order
	mov	r0, sp
	#   * -5cf5d3ed
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa3
	lsl	r1, r1, #8
	orr	r1, r1, #10
	lsl	r1, r1, #8
	orr	r1, r1, #44
	lsl	r1, r1, #8
	orr	r1, r1, #19
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x2c
	lsl	r1, r1, #8
	add	r1, r1, #0x13
#else
	mov	r1, #0x2c13
#endif
	movt	r1, #0xa30a
#endif
	mov	lr, #0
	ldm	r0, {r6, r7, r8, r9}
	umlal	r6, lr, r2, r1
	adds	r7, r7, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r7, lr, r3, r1
	adds	r8, r8, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r8, lr, r4, r1
	adds	r9, r9, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r9, lr, r5, r1
	stm	r0, {r6, r7, r8, r9}
	add	r0, r0, #4
	#   * -5812631b
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa7
	lsl	r1, r1, #8
	orr	r1, r1, #0xed
	lsl	r1, r1, #8
	orr	r1, r1, #0x9c
	lsl	r1, r1, #8
	orr	r1, r1, #0xe5
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x9c
	lsl	r1, r1, #8
	add	r1, r1, #0xe5
#else
	mov	r1, #0x9ce5
#endif
	movt	r1, #0xa7ed
#endif
	mov	r10, #0
	ldm	r0, {r6, r7, r8, r9}
	umlal	r6, r10, r2, r1
	adds	r7, r7, r10
	mov	r10, #0
	adc	r10, r10, #0
	umlal	r7, r10, r3, r1
	adds	r8, r8, r10
	mov	r10, #0
	adc	r10, r10, #0
	umlal	r8, r10, r4, r1
	adds	r9, r9, r10
	mov	r10, #0
	adc	r10, r10, #0
	umlal	r9, r10, r5, r1
	stm	r0, {r6, r7, r8, r9}
	add	r0, r0, #4
	#   * -a2f79cd7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x5d
	lsl	r1, r1, #8
	orr	r1, r1, #8
	lsl	r1, r1, #8
	orr	r1, r1, #0x63
	lsl	r1, r1, #8
	orr	r1, r1, #41
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x63
	lsl	r1, r1, #8
	add	r1, r1, #0x29
#else
	mov	r1, #0x6329
#endif
	movt	r1, #0x5d08
#endif
	mov	r11, #0
	ldm	r0, {r6, r7, r8, r9}
	umlal	r6, r11, r2, r1
	adds	r7, r7, r11
	mov	r11, #0
	adc	r11, r11, #0
	umlal	r7, r11, r3, r1
	adds	r8, r8, r11
	mov	r11, #0
	adc	r11, r11, #0
	umlal	r8, r11, r4, r1
	adds	r9, r9, r11
	mov	r11, #0
	adc	r11, r11, #0
	umlal	r9, r11, r5, r1
	stm	r0, {r6, r7, r8, r9}
	add	r0, r0, #4
	#   * -14def9df
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xeb
	lsl	r1, r1, #8
	orr	r1, r1, #33
	lsl	r1, r1, #8
	orr	r1, r1, #6
	lsl	r1, r1, #8
	orr	r1, r1, #33
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x6
	lsl	r1, r1, #8
	add	r1, r1, #0x21
#else
	mov	r1, #0x621
#endif
	movt	r1, #0xeb21
#endif
	mov	r12, #0
	ldm	r0, {r6, r7, r8, r9}
	umlal	r6, r12, r2, r1
	adds	r7, r7, r12
	mov	r12, #0
	adc	r12, r12, #0
	umlal	r7, r12, r3, r1
	adds	r8, r8, r12
	mov	r12, #0
	adc	r12, r12, #0
	umlal	r8, r12, r4, r1
	adds	r9, r9, r12
	mov	r12, #0
	adc	r12, r12, #0
	umlal	r9, r12, r5, r1
	stm	r0, {r6, r7, r8, r9}
	add	r0, r0, #4
	# Add overflows at 4 * 32
	ldm	r0, {r6, r7, r8, r9}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xf0000000
#else
	bfc	r9, #28, #4
#endif
	adds	r6, r6, lr
	adcs	r7, r7, r10
	adcs	r8, r8, r11
	adc	r9, r9, r12
	# Subtract top at 4 * 32
	subs	r6, r6, r2
	sbcs	r7, r7, r3
	sbcs	r8, r8, r4
	sbcs	r9, r9, r5
	sbc	r1, r1, r1
	sub	r0, r0, #16
	ldm	r0, {r2, r3, r4, r5}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0x5c
	lsl	r10, r10, #8
	orr	r10, r10, #0xf5
	lsl	r10, r10, #8
	orr	r10, r10, #0xd3
	lsl	r10, r10, #8
	orr	r10, r10, #0xed
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd3
	lsl	r10, r10, #8
	add	r10, r10, #0xed
#else
	mov	r10, #0xd3ed
#endif
	movt	r10, #0x5cf5
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x58
	lsl	r11, r11, #8
	orr	r11, r11, #18
	lsl	r11, r11, #8
	orr	r11, r11, #0x63
	lsl	r11, r11, #8
	orr	r11, r11, #26
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x63
	lsl	r11, r11, #8
	add	r11, r11, #0x1a
#else
	mov	r11, #0x631a
#endif
	movt	r11, #0x5812
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xa2
	lsl	r12, r12, #8
	orr	r12, r12, #0xf7
	lsl	r12, r12, #8
	orr	r12, r12, #0x9c
	lsl	r12, r12, #8
	orr	r12, r12, #0xd6
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0x9c
	lsl	r12, r12, #8
	add	r12, r12, #0xd6
#else
	mov	r12, #0x9cd6
#endif
	movt	r12, #0xa2f7
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	lr, #20
	lsl	lr, lr, #8
	orr	lr, lr, #0xde
	lsl	lr, lr, #8
	orr	lr, lr, #0xf9
	lsl	lr, lr, #8
	orr	lr, lr, #0xde
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	lr, #0xf9
	lsl	lr, lr, #8
	add	lr, lr, #0xde
#else
	mov	lr, #0xf9de
#endif
	movt	lr, #0x14de
#endif
	and	r10, r10, r1
	and	r11, r11, r1
	and	r12, r12, r1
	and	lr, lr, r1
	adds	r2, r2, r10
	adcs	r3, r3, r11
	adcs	r4, r4, r12
	adcs	r5, r5, lr
	adcs	r6, r6, #0
	adcs	r7, r7, #0
	and	r1, r1, #0x10000000
	adcs	r8, r8, #0
	adc	r9, r9, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xf0000000
#else
	bfc	r9, #28, #4
#endif
	# Store result
	ldr	r0, [sp, #52]
	stm	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	add	sp, sp, #56
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	sc_reduce,.-sc_reduce
#else
	.text
	.align	4
	.globl	sc_reduce
	.type	sc_reduce, %function
sc_reduce:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #56
	str	r0, [sp, #52]
	# Load bits 252-511
	add	r0, r0, #28
	ldm	r0, {r1, r2, r3, r4, r5, r6, r7, r8, r9}
	lsr	lr, r9, #24
	lsl	r9, r9, #4
	orr	r9, r9, r8, LSR #28
	lsl	r8, r8, #4
	orr	r8, r8, r7, LSR #28
	lsl	r7, r7, #4
	orr	r7, r7, r6, LSR #28
	lsl	r6, r6, #4
	orr	r6, r6, r5, LSR #28
	lsl	r5, r5, #4
	orr	r5, r5, r4, LSR #28
	lsl	r4, r4, #4
	orr	r4, r4, r3, LSR #28
	lsl	r3, r3, #4
	orr	r3, r3, r2, LSR #28
	lsl	r2, r2, #4
	orr	r2, r2, r1, LSR #28
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xf0000000
#else
	bfc	r9, #28, #4
#endif
	sub	r0, r0, #28
	# Add order times bits 504..511
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xa3
	lsl	r10, r10, #8
	orr	r10, r10, #10
	lsl	r10, r10, #8
	orr	r10, r10, #44
	lsl	r10, r10, #8
	orr	r10, r10, #19
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0x2c
	lsl	r10, r10, #8
	add	r10, r10, #0x13
#else
	mov	r10, #0x2c13
#endif
	movt	r10, #0xa30a
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0xa7
	lsl	r11, r11, #8
	orr	r11, r11, #0xed
	lsl	r11, r11, #8
	orr	r11, r11, #0x9c
	lsl	r11, r11, #8
	orr	r11, r11, #0xe5
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x9c
	lsl	r11, r11, #8
	add	r11, r11, #0xe5
#else
	mov	r11, #0x9ce5
#endif
	movt	r11, #0xa7ed
#endif
	mov	r1, #0
	umlal	r2, r1, r10, lr
	umaal	r3, r1, r11, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0x5d
	lsl	r10, r10, #8
	orr	r10, r10, #8
	lsl	r10, r10, #8
	orr	r10, r10, #0x63
	lsl	r10, r10, #8
	orr	r10, r10, #41
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0x63
	lsl	r10, r10, #8
	add	r10, r10, #0x29
#else
	mov	r10, #0x6329
#endif
	movt	r10, #0x5d08
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0xeb
	lsl	r11, r11, #8
	orr	r11, r11, #33
	lsl	r11, r11, #8
	orr	r11, r11, #6
	lsl	r11, r11, #8
	orr	r11, r11, #33
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x6
	lsl	r11, r11, #8
	add	r11, r11, #0x21
#else
	mov	r11, #0x621
#endif
	movt	r11, #0xeb21
#endif
	umaal	r4, r1, r10, lr
	umaal	r5, r1, r11, lr
	adds	r6, r6, r1
	adcs	r7, r7, #0
	adcs	r8, r8, #0
	adc	r9, r9, #0
	subs	r6, r6, lr
	sbcs	r7, r7, #0
	sbcs	r8, r8, #0
	sbc	r9, r9, #0
	# Sub product of top 8 words and order
	mov	r12, sp
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa3
	lsl	r1, r1, #8
	orr	r1, r1, #10
	lsl	r1, r1, #8
	orr	r1, r1, #44
	lsl	r1, r1, #8
	orr	r1, r1, #19
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x2c
	lsl	r1, r1, #8
	add	r1, r1, #0x13
#else
	mov	r1, #0x2c13
#endif
	movt	r1, #0xa30a
#endif
	mov	lr, #0
	ldm	r0!, {r10, r11}
	umlal	r10, lr, r2, r1
	umaal	r11, lr, r3, r1
	stm	r12!, {r10, r11}
	ldm	r0!, {r10, r11}
	umaal	r10, lr, r4, r1
	umaal	r11, lr, r5, r1
	stm	r12!, {r10, r11}
	ldm	r0!, {r10, r11}
	umaal	r10, lr, r6, r1
	umaal	r11, lr, r7, r1
	stm	r12!, {r10, r11}
	ldm	r0!, {r10, r11}
	umaal	r10, lr, r8, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r11, r11, #0xf0000000
#else
	bfc	r11, #28, #4
#endif
	umaal	r11, lr, r9, r1
	stm	r12!, {r10, r11, lr}
	sub	r0, r0, #16
	sub	r12, r12, #32
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa7
	lsl	r1, r1, #8
	orr	r1, r1, #0xed
	lsl	r1, r1, #8
	orr	r1, r1, #0x9c
	lsl	r1, r1, #8
	orr	r1, r1, #0xe5
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x9c
	lsl	r1, r1, #8
	add	r1, r1, #0xe5
#else
	mov	r1, #0x9ce5
#endif
	movt	r1, #0xa7ed
#endif
	mov	lr, #0
	ldm	r12, {r10, r11}
	umlal	r10, lr, r2, r1
	umaal	r11, lr, r3, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	umaal	r10, lr, r4, r1
	umaal	r11, lr, r5, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	umaal	r10, lr, r6, r1
	umaal	r11, lr, r7, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	umaal	r10, lr, r8, r1
	umaal	r11, lr, r9, r1
	stm	r12!, {r10, r11, lr}
	sub	r12, r12, #32
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x5d
	lsl	r1, r1, #8
	orr	r1, r1, #8
	lsl	r1, r1, #8
	orr	r1, r1, #0x63
	lsl	r1, r1, #8
	orr	r1, r1, #41
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x63
	lsl	r1, r1, #8
	add	r1, r1, #0x29
#else
	mov	r1, #0x6329
#endif
	movt	r1, #0x5d08
#endif
	mov	lr, #0
	ldm	r12, {r10, r11}
	umlal	r10, lr, r2, r1
	umaal	r11, lr, r3, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	umaal	r10, lr, r4, r1
	umaal	r11, lr, r5, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	umaal	r10, lr, r6, r1
	umaal	r11, lr, r7, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	umaal	r10, lr, r8, r1
	umaal	r11, lr, r9, r1
	stm	r12!, {r10, r11, lr}
	sub	r12, r12, #32
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xeb
	lsl	r1, r1, #8
	orr	r1, r1, #33
	lsl	r1, r1, #8
	orr	r1, r1, #6
	lsl	r1, r1, #8
	orr	r1, r1, #33
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x6
	lsl	r1, r1, #8
	add	r1, r1, #0x21
#else
	mov	r1, #0x621
#endif
	movt	r1, #0xeb21
#endif
	mov	lr, #0
	ldm	r12, {r10, r11}
	umlal	r10, lr, r2, r1
	umaal	r11, lr, r3, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	umaal	r10, lr, r4, r1
	umaal	r11, lr, r5, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	umaal	r10, lr, r6, r1
	umaal	r11, lr, r7, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	umaal	r10, lr, r8, r1
	umaal	r11, lr, r9, r1
	stm	r12!, {r10, r11, lr}
	sub	r12, r12, #32
	# Subtract at 4 * 32
	ldm	r12, {r10, r11}
	subs	r10, r10, r2
	sbcs	r11, r11, r3
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	sbcs	r10, r10, r4
	sbcs	r11, r11, r5
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	sbcs	r10, r10, r6
	sbcs	r11, r11, r7
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	sbcs	r10, r10, r8
	sbc	r11, r11, r9
	stm	r12!, {r10, r11}
	sub	r12, r12, #36
	asr	lr, r11, #25
	# Conditionally subtract order starting at bit 125
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa00000
	lsl	r1, r1, #8
	add	r1, r1, #0x0
#else
	mov	r1, #0xa0000000
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x4b
	lsl	r2, r2, #8
	orr	r2, r2, #0x9e
	lsl	r2, r2, #8
	orr	r2, r2, #0xba
	lsl	r2, r2, #8
	orr	r2, r2, #0x7d
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xba
	lsl	r2, r2, #8
	add	r2, r2, #0x7d
#else
	mov	r2, #0xba7d
#endif
	movt	r2, #0x4b9e
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0xcb
	lsl	r3, r3, #8
	orr	r3, r3, #2
	lsl	r3, r3, #8
	orr	r3, r3, #0x4c
	lsl	r3, r3, #8
	orr	r3, r3, #0x63
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x4c
	lsl	r3, r3, #8
	add	r3, r3, #0x63
#else
	mov	r3, #0x4c63
#endif
	movt	r3, #0xcb02
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r4, #0xd4
	lsl	r4, r4, #8
	orr	r4, r4, #0x5e
	lsl	r4, r4, #8
	orr	r4, r4, #0xf3
	lsl	r4, r4, #8
	orr	r4, r4, #0x9a
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r4, #0xf3
	lsl	r4, r4, #8
	add	r4, r4, #0x9a
#else
	mov	r4, #0xf39a
#endif
	movt	r4, #0xd45e
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r5, #2
	lsl	r5, r5, #8
	orr	r5, r5, #0x9b
	lsl	r5, r5, #8
	orr	r5, r5, #0xdf
	lsl	r5, r5, #8
	orr	r5, r5, #59
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r5, #0xdf
	lsl	r5, r5, #8
	add	r5, r5, #0x3b
#else
	mov	r5, #0xdf3b
#endif
	movt	r5, #0x29b
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r9, #0x20000
	lsl	r9, r9, #8
	add	r9, r9, #0x0
#else
	mov	r9, #0x2000000
#endif
	and	r1, r1, lr
	and	r2, r2, lr
	and	r3, r3, lr
	and	r4, r4, lr
	and	r5, r5, lr
	and	r9, r9, lr
	ldm	r12, {r10, r11}
	adds	r10, r10, r1
	adcs	r11, r11, r2
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adcs	r10, r10, r3
	adcs	r11, r11, r4
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adcs	r10, r10, r5
	adcs	r11, r11, #0
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adcs	r10, r10, #0
	adcs	r11, r11, #0
	stm	r12!, {r10, r11}
	ldm	r12, {r10}
	adcs	r10, r10, #0
	stm	r12!, {r10}
	sub	r0, r0, #16
	mov	r12, sp
	# Load bits 252-376
	add	r12, r12, #28
	ldm	r12, {r1, r2, r3, r4, r5}
	lsl	r5, r5, #4
	orr	r5, r5, r4, lsr #28
	lsl	r4, r4, #4
	orr	r4, r4, r3, lsr #28
	lsl	r3, r3, #4
	orr	r3, r3, r2, lsr #28
	lsl	r2, r2, #4
	orr	r2, r2, r1, lsr #28
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xe0000000
#else
	bfc	r5, #29, #3
#endif
	sub	r12, r12, #28
	# Sub product of top 4 words and order
	mov	r0, sp
	#   * -5cf5d3ed
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa3
	lsl	r1, r1, #8
	orr	r1, r1, #10
	lsl	r1, r1, #8
	orr	r1, r1, #44
	lsl	r1, r1, #8
	orr	r1, r1, #19
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x2c
	lsl	r1, r1, #8
	add	r1, r1, #0x13
#else
	mov	r1, #0x2c13
#endif
	movt	r1, #0xa30a
#endif
	mov	lr, #0
	ldm	r0, {r6, r7, r8, r9}
	umlal	r6, lr, r2, r1
	umaal	r7, lr, r3, r1
	umaal	r8, lr, r4, r1
	umaal	r9, lr, r5, r1
	stm	r0, {r6, r7, r8, r9}
	add	r0, r0, #4
	#   * -5812631b
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa7
	lsl	r1, r1, #8
	orr	r1, r1, #0xed
	lsl	r1, r1, #8
	orr	r1, r1, #0x9c
	lsl	r1, r1, #8
	orr	r1, r1, #0xe5
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x9c
	lsl	r1, r1, #8
	add	r1, r1, #0xe5
#else
	mov	r1, #0x9ce5
#endif
	movt	r1, #0xa7ed
#endif
	mov	r10, #0
	ldm	r0, {r6, r7, r8, r9}
	umlal	r6, r10, r2, r1
	umaal	r7, r10, r3, r1
	umaal	r8, r10, r4, r1
	umaal	r9, r10, r5, r1
	stm	r0, {r6, r7, r8, r9}
	add	r0, r0, #4
	#   * -a2f79cd7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x5d
	lsl	r1, r1, #8
	orr	r1, r1, #8
	lsl	r1, r1, #8
	orr	r1, r1, #0x63
	lsl	r1, r1, #8
	orr	r1, r1, #41
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x63
	lsl	r1, r1, #8
	add	r1, r1, #0x29
#else
	mov	r1, #0x6329
#endif
	movt	r1, #0x5d08
#endif
	mov	r11, #0
	ldm	r0, {r6, r7, r8, r9}
	umlal	r6, r11, r2, r1
	umaal	r7, r11, r3, r1
	umaal	r8, r11, r4, r1
	umaal	r9, r11, r5, r1
	stm	r0, {r6, r7, r8, r9}
	add	r0, r0, #4
	#   * -14def9df
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xeb
	lsl	r1, r1, #8
	orr	r1, r1, #33
	lsl	r1, r1, #8
	orr	r1, r1, #6
	lsl	r1, r1, #8
	orr	r1, r1, #33
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x6
	lsl	r1, r1, #8
	add	r1, r1, #0x21
#else
	mov	r1, #0x621
#endif
	movt	r1, #0xeb21
#endif
	mov	r12, #0
	ldm	r0, {r6, r7, r8, r9}
	umlal	r6, r12, r2, r1
	umaal	r7, r12, r3, r1
	umaal	r8, r12, r4, r1
	umaal	r9, r12, r5, r1
	stm	r0, {r6, r7, r8, r9}
	add	r0, r0, #4
	# Add overflows at 4 * 32
	ldm	r0, {r6, r7, r8, r9}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xf0000000
#else
	bfc	r9, #28, #4
#endif
	adds	r6, r6, lr
	adcs	r7, r7, r10
	adcs	r8, r8, r11
	adc	r9, r9, r12
	# Subtract top at 4 * 32
	subs	r6, r6, r2
	sbcs	r7, r7, r3
	sbcs	r8, r8, r4
	sbcs	r9, r9, r5
	sbc	r1, r1, r1
	sub	r0, r0, #16
	ldm	r0, {r2, r3, r4, r5}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0x5c
	lsl	r10, r10, #8
	orr	r10, r10, #0xf5
	lsl	r10, r10, #8
	orr	r10, r10, #0xd3
	lsl	r10, r10, #8
	orr	r10, r10, #0xed
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd3
	lsl	r10, r10, #8
	add	r10, r10, #0xed
#else
	mov	r10, #0xd3ed
#endif
	movt	r10, #0x5cf5
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x58
	lsl	r11, r11, #8
	orr	r11, r11, #18
	lsl	r11, r11, #8
	orr	r11, r11, #0x63
	lsl	r11, r11, #8
	orr	r11, r11, #26
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x63
	lsl	r11, r11, #8
	add	r11, r11, #0x1a
#else
	mov	r11, #0x631a
#endif
	movt	r11, #0x5812
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xa2
	lsl	r12, r12, #8
	orr	r12, r12, #0xf7
	lsl	r12, r12, #8
	orr	r12, r12, #0x9c
	lsl	r12, r12, #8
	orr	r12, r12, #0xd6
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0x9c
	lsl	r12, r12, #8
	add	r12, r12, #0xd6
#else
	mov	r12, #0x9cd6
#endif
	movt	r12, #0xa2f7
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	lr, #20
	lsl	lr, lr, #8
	orr	lr, lr, #0xde
	lsl	lr, lr, #8
	orr	lr, lr, #0xf9
	lsl	lr, lr, #8
	orr	lr, lr, #0xde
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	lr, #0xf9
	lsl	lr, lr, #8
	add	lr, lr, #0xde
#else
	mov	lr, #0xf9de
#endif
	movt	lr, #0x14de
#endif
	and	r10, r10, r1
	and	r11, r11, r1
	and	r12, r12, r1
	and	lr, lr, r1
	adds	r2, r2, r10
	adcs	r3, r3, r11
	adcs	r4, r4, r12
	adcs	r5, r5, lr
	adcs	r6, r6, #0
	adcs	r7, r7, #0
	and	r1, r1, #0x10000000
	adcs	r8, r8, #0
	adc	r9, r9, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xf0000000
#else
	bfc	r9, #28, #4
#endif
	# Store result
	ldr	r0, [sp, #52]
	stm	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	add	sp, sp, #56
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	sc_reduce,.-sc_reduce
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
#ifdef HAVE_ED25519_SIGN
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	.text
	.align	4
	.globl	sc_muladd
	.type	sc_muladd, %function
sc_muladd:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #0x50
	add	lr, sp, #0x44
	stm	lr, {r0, r1, r3}
	mov	r0, #0
	ldr	r12, [r1]
	# A[0] * B[0]
	ldr	lr, [r2]
	umull	r3, r4, r12, lr
	# A[0] * B[2]
	ldr	lr, [r2, #8]
	umull	r5, r6, r12, lr
	# A[0] * B[4]
	ldr	lr, [r2, #16]
	umull	r7, r8, r12, lr
	# A[0] * B[6]
	ldr	lr, [r2, #24]
	umull	r9, r10, r12, lr
	str	r3, [sp]
	# A[0] * B[1]
	ldr	lr, [r2, #4]
	mov	r11, r0
	umlal	r4, r11, r12, lr
	adds	r5, r5, r11
	# A[0] * B[3]
	ldr	lr, [r2, #12]
	adcs	r6, r6, #0
	adc	r11, r0, #0
	umlal	r6, r11, r12, lr
	adds	r7, r7, r11
	# A[0] * B[5]
	ldr	lr, [r2, #20]
	adcs	r8, r8, #0
	adc	r11, r0, #0
	umlal	r8, r11, r12, lr
	adds	r9, r9, r11
	# A[0] * B[7]
	ldr	lr, [r2, #28]
	adcs	r10, r10, #0
	adc	r3, r0, #0
	umlal	r10, r3, r12, lr
	# A[1] * B[0]
	ldr	r12, [r1, #4]
	ldr	lr, [r2]
	mov	r11, #0
	umlal	r4, r11, r12, lr
	str	r4, [sp, #4]
	adds	r5, r5, r11
	# A[1] * B[1]
	ldr	lr, [r2, #4]
	adc	r11, r0, #0
	umlal	r5, r11, r12, lr
	adds	r6, r6, r11
	# A[1] * B[2]
	ldr	lr, [r2, #8]
	adc	r11, r0, #0
	umlal	r6, r11, r12, lr
	adds	r7, r7, r11
	# A[1] * B[3]
	ldr	lr, [r2, #12]
	adc	r11, r0, #0
	umlal	r7, r11, r12, lr
	adds	r8, r8, r11
	# A[1] * B[4]
	ldr	lr, [r2, #16]
	adc	r11, r0, #0
	umlal	r8, r11, r12, lr
	adds	r9, r9, r11
	# A[1] * B[5]
	ldr	lr, [r2, #20]
	adc	r11, r0, #0
	umlal	r9, r11, r12, lr
	adds	r10, r10, r11
	# A[1] * B[6]
	ldr	lr, [r2, #24]
	adc	r11, r0, #0
	umlal	r10, r11, r12, lr
	adds	r3, r3, r11
	# A[1] * B[7]
	ldr	lr, [r2, #28]
	adc	r4, r0, #0
	umlal	r3, r4, r12, lr
	# A[2] * B[0]
	ldr	r12, [r1, #8]
	ldr	lr, [r2]
	mov	r11, #0
	umlal	r5, r11, r12, lr
	str	r5, [sp, #8]
	adds	r6, r6, r11
	# A[2] * B[1]
	ldr	lr, [r2, #4]
	adc	r11, r0, #0
	umlal	r6, r11, r12, lr
	adds	r7, r7, r11
	# A[2] * B[2]
	ldr	lr, [r2, #8]
	adc	r11, r0, #0
	umlal	r7, r11, r12, lr
	adds	r8, r8, r11
	# A[2] * B[3]
	ldr	lr, [r2, #12]
	adc	r11, r0, #0
	umlal	r8, r11, r12, lr
	adds	r9, r9, r11
	# A[2] * B[4]
	ldr	lr, [r2, #16]
	adc	r11, r0, #0
	umlal	r9, r11, r12, lr
	adds	r10, r10, r11
	# A[2] * B[5]
	ldr	lr, [r2, #20]
	adc	r11, r0, #0
	umlal	r10, r11, r12, lr
	adds	r3, r3, r11
	# A[2] * B[6]
	ldr	lr, [r2, #24]
	adc	r11, r0, #0
	umlal	r3, r11, r12, lr
	adds	r4, r4, r11
	# A[2] * B[7]
	ldr	lr, [r2, #28]
	adc	r5, r0, #0
	umlal	r4, r5, r12, lr
	# A[3] * B[0]
	ldr	r12, [r1, #12]
	ldr	lr, [r2]
	mov	r11, #0
	umlal	r6, r11, r12, lr
	str	r6, [sp, #12]
	adds	r7, r7, r11
	# A[3] * B[1]
	ldr	lr, [r2, #4]
	adc	r11, r0, #0
	umlal	r7, r11, r12, lr
	adds	r8, r8, r11
	# A[3] * B[2]
	ldr	lr, [r2, #8]
	adc	r11, r0, #0
	umlal	r8, r11, r12, lr
	adds	r9, r9, r11
	# A[3] * B[3]
	ldr	lr, [r2, #12]
	adc	r11, r0, #0
	umlal	r9, r11, r12, lr
	adds	r10, r10, r11
	# A[3] * B[4]
	ldr	lr, [r2, #16]
	adc	r11, r0, #0
	umlal	r10, r11, r12, lr
	adds	r3, r3, r11
	# A[3] * B[5]
	ldr	lr, [r2, #20]
	adc	r11, r0, #0
	umlal	r3, r11, r12, lr
	adds	r4, r4, r11
	# A[3] * B[6]
	ldr	lr, [r2, #24]
	adc	r11, r0, #0
	umlal	r4, r11, r12, lr
	adds	r5, r5, r11
	# A[3] * B[7]
	ldr	lr, [r2, #28]
	adc	r6, r0, #0
	umlal	r5, r6, r12, lr
	# A[4] * B[0]
	ldr	r12, [r1, #16]
	ldr	lr, [r2]
	mov	r11, #0
	umlal	r7, r11, r12, lr
	str	r7, [sp, #16]
	adds	r8, r8, r11
	# A[4] * B[1]
	ldr	lr, [r2, #4]
	adc	r11, r0, #0
	umlal	r8, r11, r12, lr
	adds	r9, r9, r11
	# A[4] * B[2]
	ldr	lr, [r2, #8]
	adc	r11, r0, #0
	umlal	r9, r11, r12, lr
	adds	r10, r10, r11
	# A[4] * B[3]
	ldr	lr, [r2, #12]
	adc	r11, r0, #0
	umlal	r10, r11, r12, lr
	adds	r3, r3, r11
	# A[4] * B[4]
	ldr	lr, [r2, #16]
	adc	r11, r0, #0
	umlal	r3, r11, r12, lr
	adds	r4, r4, r11
	# A[4] * B[5]
	ldr	lr, [r2, #20]
	adc	r11, r0, #0
	umlal	r4, r11, r12, lr
	adds	r5, r5, r11
	# A[4] * B[6]
	ldr	lr, [r2, #24]
	adc	r11, r0, #0
	umlal	r5, r11, r12, lr
	adds	r6, r6, r11
	# A[4] * B[7]
	ldr	lr, [r2, #28]
	adc	r7, r0, #0
	umlal	r6, r7, r12, lr
	# A[5] * B[0]
	ldr	r12, [r1, #20]
	ldr	lr, [r2]
	mov	r11, #0
	umlal	r8, r11, r12, lr
	str	r8, [sp, #20]
	adds	r9, r9, r11
	# A[5] * B[1]
	ldr	lr, [r2, #4]
	adc	r11, r0, #0
	umlal	r9, r11, r12, lr
	adds	r10, r10, r11
	# A[5] * B[2]
	ldr	lr, [r2, #8]
	adc	r11, r0, #0
	umlal	r10, r11, r12, lr
	adds	r3, r3, r11
	# A[5] * B[3]
	ldr	lr, [r2, #12]
	adc	r11, r0, #0
	umlal	r3, r11, r12, lr
	adds	r4, r4, r11
	# A[5] * B[4]
	ldr	lr, [r2, #16]
	adc	r11, r0, #0
	umlal	r4, r11, r12, lr
	adds	r5, r5, r11
	# A[5] * B[5]
	ldr	lr, [r2, #20]
	adc	r11, r0, #0
	umlal	r5, r11, r12, lr
	adds	r6, r6, r11
	# A[5] * B[6]
	ldr	lr, [r2, #24]
	adc	r11, r0, #0
	umlal	r6, r11, r12, lr
	adds	r7, r7, r11
	# A[5] * B[7]
	ldr	lr, [r2, #28]
	adc	r8, r0, #0
	umlal	r7, r8, r12, lr
	# A[6] * B[0]
	ldr	r12, [r1, #24]
	ldr	lr, [r2]
	mov	r11, #0
	umlal	r9, r11, r12, lr
	str	r9, [sp, #24]
	adds	r10, r10, r11
	# A[6] * B[1]
	ldr	lr, [r2, #4]
	adc	r11, r0, #0
	umlal	r10, r11, r12, lr
	adds	r3, r3, r11
	# A[6] * B[2]
	ldr	lr, [r2, #8]
	adc	r11, r0, #0
	umlal	r3, r11, r12, lr
	adds	r4, r4, r11
	# A[6] * B[3]
	ldr	lr, [r2, #12]
	adc	r11, r0, #0
	umlal	r4, r11, r12, lr
	adds	r5, r5, r11
	# A[6] * B[4]
	ldr	lr, [r2, #16]
	adc	r11, r0, #0
	umlal	r5, r11, r12, lr
	adds	r6, r6, r11
	# A[6] * B[5]
	ldr	lr, [r2, #20]
	adc	r11, r0, #0
	umlal	r6, r11, r12, lr
	adds	r7, r7, r11
	# A[6] * B[6]
	ldr	lr, [r2, #24]
	adc	r11, r0, #0
	umlal	r7, r11, r12, lr
	adds	r8, r8, r11
	# A[6] * B[7]
	ldr	lr, [r2, #28]
	adc	r9, r0, #0
	umlal	r8, r9, r12, lr
	# A[7] * B[0]
	ldr	r12, [r1, #28]
	ldr	lr, [r2]
	mov	r11, #0
	umlal	r10, r11, r12, lr
	str	r10, [sp, #28]
	adds	r3, r3, r11
	# A[7] * B[1]
	ldr	lr, [r2, #4]
	adc	r11, r0, #0
	umlal	r3, r11, r12, lr
	adds	r4, r4, r11
	# A[7] * B[2]
	ldr	lr, [r2, #8]
	adc	r11, r0, #0
	umlal	r4, r11, r12, lr
	adds	r5, r5, r11
	# A[7] * B[3]
	ldr	lr, [r2, #12]
	adc	r11, r0, #0
	umlal	r5, r11, r12, lr
	adds	r6, r6, r11
	# A[7] * B[4]
	ldr	lr, [r2, #16]
	adc	r11, r0, #0
	umlal	r6, r11, r12, lr
	adds	r7, r7, r11
	# A[7] * B[5]
	ldr	lr, [r2, #20]
	adc	r11, r0, #0
	umlal	r7, r11, r12, lr
	adds	r8, r8, r11
	# A[7] * B[6]
	ldr	lr, [r2, #24]
	adc	r11, r0, #0
	umlal	r8, r11, r12, lr
	adds	r9, r9, r11
	# A[7] * B[7]
	ldr	lr, [r2, #28]
	adc	r10, r0, #0
	umlal	r9, r10, r12, lr
	add	lr, sp, #32
	stm	lr, {r3, r4, r5, r6, r7, r8, r9, r10}
	mov	r0, sp
	# Add c to a * b
	ldr	lr, [sp, #76]
	ldm	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	ldm	lr!, {r1, r10, r11, r12}
	adds	r2, r2, r1
	adcs	r3, r3, r10
	adcs	r4, r4, r11
	adcs	r5, r5, r12
	ldm	lr!, {r1, r10, r11, r12}
	adcs	r6, r6, r1
	adcs	r7, r7, r10
	adcs	r8, r8, r11
	adcs	r9, r9, r12
	mov	r1, r9
	stm	r0!, {r2, r3, r4, r5, r6, r7, r8, r9}
	ldm	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	adcs	r2, r2, #0
	adcs	r3, r3, #0
	adcs	r4, r4, #0
	adcs	r5, r5, #0
	adcs	r6, r6, #0
	adcs	r7, r7, #0
	adcs	r8, r8, #0
	adc	r9, r9, #0
	sub	r0, r0, #32
	# Get 252..503 and 504..507
	lsr	lr, r9, #24
	lsl	r9, r9, #4
	orr	r9, r9, r8, LSR #28
	lsl	r8, r8, #4
	orr	r8, r8, r7, LSR #28
	lsl	r7, r7, #4
	orr	r7, r7, r6, LSR #28
	lsl	r6, r6, #4
	orr	r6, r6, r5, LSR #28
	lsl	r5, r5, #4
	orr	r5, r5, r4, LSR #28
	lsl	r4, r4, #4
	orr	r4, r4, r3, LSR #28
	lsl	r3, r3, #4
	orr	r3, r3, r2, LSR #28
	lsl	r2, r2, #4
	orr	r2, r2, r1, LSR #28
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xf0000000
#else
	bfc	r9, #28, #4
#endif
	# Add order times bits 504..507
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xa3
	lsl	r10, r10, #8
	orr	r10, r10, #10
	lsl	r10, r10, #8
	orr	r10, r10, #44
	lsl	r10, r10, #8
	orr	r10, r10, #19
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0x2c
	lsl	r10, r10, #8
	add	r10, r10, #0x13
#else
	mov	r10, #0x2c13
#endif
	movt	r10, #0xa30a
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0xa7
	lsl	r11, r11, #8
	orr	r11, r11, #0xed
	lsl	r11, r11, #8
	orr	r11, r11, #0x9c
	lsl	r11, r11, #8
	orr	r11, r11, #0xe5
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x9c
	lsl	r11, r11, #8
	add	r11, r11, #0xe5
#else
	mov	r11, #0x9ce5
#endif
	movt	r11, #0xa7ed
#endif
	mov	r1, #0
	umlal	r2, r1, r10, lr
	adds	r3, r3, r1
	mov	r1, #0
	adc	r1, r1, #0
	umlal	r3, r1, r11, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0x5d
	lsl	r10, r10, #8
	orr	r10, r10, #8
	lsl	r10, r10, #8
	orr	r10, r10, #0x63
	lsl	r10, r10, #8
	orr	r10, r10, #41
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0x63
	lsl	r10, r10, #8
	add	r10, r10, #0x29
#else
	mov	r10, #0x6329
#endif
	movt	r10, #0x5d08
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0xeb
	lsl	r11, r11, #8
	orr	r11, r11, #33
	lsl	r11, r11, #8
	orr	r11, r11, #6
	lsl	r11, r11, #8
	orr	r11, r11, #33
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x6
	lsl	r11, r11, #8
	add	r11, r11, #0x21
#else
	mov	r11, #0x621
#endif
	movt	r11, #0xeb21
#endif
	adds	r4, r4, r1
	mov	r1, #0
	adc	r1, r1, #0
	umlal	r4, r1, r10, lr
	adds	r5, r5, r1
	mov	r1, #0
	adc	r1, r1, #0
	umlal	r5, r1, r11, lr
	adds	r6, r6, r1
	adcs	r7, r7, #0
	adcs	r8, r8, #0
	adc	r9, r9, #0
	subs	r6, r6, lr
	sbcs	r7, r7, #0
	sbcs	r8, r8, #0
	sbc	r9, r9, #0
	# Sub product of top 8 words and order
	mov	r12, sp
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa3
	lsl	r1, r1, #8
	orr	r1, r1, #10
	lsl	r1, r1, #8
	orr	r1, r1, #44
	lsl	r1, r1, #8
	orr	r1, r1, #19
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x2c
	lsl	r1, r1, #8
	add	r1, r1, #0x13
#else
	mov	r1, #0x2c13
#endif
	movt	r1, #0xa30a
#endif
	mov	lr, #0
	ldm	r0!, {r10, r11}
	umlal	r10, lr, r2, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r3, r1
	stm	r12!, {r10, r11}
	ldm	r0!, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r4, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r5, r1
	stm	r12!, {r10, r11}
	ldm	r0!, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r6, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r7, r1
	stm	r12!, {r10, r11}
	ldm	r0!, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r8, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r11, r11, #0xf0000000
#else
	bfc	r11, #28, #4
#endif
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r9, r1
	stm	r12!, {r10, r11, lr}
	sub	r0, r0, #16
	sub	r12, r12, #32
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa7
	lsl	r1, r1, #8
	orr	r1, r1, #0xed
	lsl	r1, r1, #8
	orr	r1, r1, #0x9c
	lsl	r1, r1, #8
	orr	r1, r1, #0xe5
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x9c
	lsl	r1, r1, #8
	add	r1, r1, #0xe5
#else
	mov	r1, #0x9ce5
#endif
	movt	r1, #0xa7ed
#endif
	mov	lr, #0
	ldm	r12, {r10, r11}
	umlal	r10, lr, r2, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r3, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r4, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r5, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r6, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r7, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r8, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r9, r1
	stm	r12!, {r10, r11, lr}
	sub	r12, r12, #32
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x5d
	lsl	r1, r1, #8
	orr	r1, r1, #8
	lsl	r1, r1, #8
	orr	r1, r1, #0x63
	lsl	r1, r1, #8
	orr	r1, r1, #41
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x63
	lsl	r1, r1, #8
	add	r1, r1, #0x29
#else
	mov	r1, #0x6329
#endif
	movt	r1, #0x5d08
#endif
	mov	lr, #0
	ldm	r12, {r10, r11}
	umlal	r10, lr, r2, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r3, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r4, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r5, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r6, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r7, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r8, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r9, r1
	stm	r12!, {r10, r11, lr}
	sub	r12, r12, #32
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xeb
	lsl	r1, r1, #8
	orr	r1, r1, #33
	lsl	r1, r1, #8
	orr	r1, r1, #6
	lsl	r1, r1, #8
	orr	r1, r1, #33
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x6
	lsl	r1, r1, #8
	add	r1, r1, #0x21
#else
	mov	r1, #0x621
#endif
	movt	r1, #0xeb21
#endif
	mov	lr, #0
	ldm	r12, {r10, r11}
	umlal	r10, lr, r2, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r3, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r4, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r5, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r6, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r7, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adds	r10, r10, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r10, lr, r8, r1
	adds	r11, r11, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r11, lr, r9, r1
	stm	r12!, {r10, r11, lr}
	sub	r12, r12, #32
	# Subtract at 4 * 32
	ldm	r12, {r10, r11}
	subs	r10, r10, r2
	sbcs	r11, r11, r3
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	sbcs	r10, r10, r4
	sbcs	r11, r11, r5
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	sbcs	r10, r10, r6
	sbcs	r11, r11, r7
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	sbcs	r10, r10, r8
	sbc	r11, r11, r9
	stm	r12!, {r10, r11}
	sub	r12, r12, #36
	asr	lr, r11, #25
	# Conditionally subtract order starting at bit 125
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa00000
	lsl	r1, r1, #8
	add	r1, r1, #0x0
#else
	mov	r1, #0xa0000000
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x4b
	lsl	r2, r2, #8
	orr	r2, r2, #0x9e
	lsl	r2, r2, #8
	orr	r2, r2, #0xba
	lsl	r2, r2, #8
	orr	r2, r2, #0x7d
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xba
	lsl	r2, r2, #8
	add	r2, r2, #0x7d
#else
	mov	r2, #0xba7d
#endif
	movt	r2, #0x4b9e
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0xcb
	lsl	r3, r3, #8
	orr	r3, r3, #2
	lsl	r3, r3, #8
	orr	r3, r3, #0x4c
	lsl	r3, r3, #8
	orr	r3, r3, #0x63
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x4c
	lsl	r3, r3, #8
	add	r3, r3, #0x63
#else
	mov	r3, #0x4c63
#endif
	movt	r3, #0xcb02
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r4, #0xd4
	lsl	r4, r4, #8
	orr	r4, r4, #0x5e
	lsl	r4, r4, #8
	orr	r4, r4, #0xf3
	lsl	r4, r4, #8
	orr	r4, r4, #0x9a
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r4, #0xf3
	lsl	r4, r4, #8
	add	r4, r4, #0x9a
#else
	mov	r4, #0xf39a
#endif
	movt	r4, #0xd45e
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r5, #2
	lsl	r5, r5, #8
	orr	r5, r5, #0x9b
	lsl	r5, r5, #8
	orr	r5, r5, #0xdf
	lsl	r5, r5, #8
	orr	r5, r5, #59
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r5, #0xdf
	lsl	r5, r5, #8
	add	r5, r5, #0x3b
#else
	mov	r5, #0xdf3b
#endif
	movt	r5, #0x29b
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r9, #0x20000
	lsl	r9, r9, #8
	add	r9, r9, #0x0
#else
	mov	r9, #0x2000000
#endif
	and	r1, r1, lr
	and	r2, r2, lr
	and	r3, r3, lr
	and	r4, r4, lr
	and	r5, r5, lr
	and	r9, r9, lr
	ldm	r12, {r10, r11}
	adds	r10, r10, r1
	adcs	r11, r11, r2
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adcs	r10, r10, r3
	adcs	r11, r11, r4
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adcs	r10, r10, r5
	adcs	r11, r11, #0
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adcs	r10, r10, #0
	adcs	r11, r11, #0
	stm	r12!, {r10, r11}
	ldm	r12, {r10}
	adcs	r10, r10, #0
	stm	r12!, {r10}
	sub	r0, r0, #16
	mov	r12, sp
	# Load bits 252-376
	add	r12, r12, #28
	ldm	r12, {r1, r2, r3, r4, r5}
	lsl	r5, r5, #4
	orr	r5, r5, r4, lsr #28
	lsl	r4, r4, #4
	orr	r4, r4, r3, lsr #28
	lsl	r3, r3, #4
	orr	r3, r3, r2, lsr #28
	lsl	r2, r2, #4
	orr	r2, r2, r1, lsr #28
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xe0000000
#else
	bfc	r5, #29, #3
#endif
	sub	r12, r12, #28
	# Sub product of top 4 words and order
	mov	r0, sp
	#   * -5cf5d3ed
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa3
	lsl	r1, r1, #8
	orr	r1, r1, #10
	lsl	r1, r1, #8
	orr	r1, r1, #44
	lsl	r1, r1, #8
	orr	r1, r1, #19
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x2c
	lsl	r1, r1, #8
	add	r1, r1, #0x13
#else
	mov	r1, #0x2c13
#endif
	movt	r1, #0xa30a
#endif
	mov	lr, #0
	ldm	r0, {r6, r7, r8, r9}
	umlal	r6, lr, r2, r1
	adds	r7, r7, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r7, lr, r3, r1
	adds	r8, r8, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r8, lr, r4, r1
	adds	r9, r9, lr
	mov	lr, #0
	adc	lr, lr, #0
	umlal	r9, lr, r5, r1
	stm	r0, {r6, r7, r8, r9}
	add	r0, r0, #4
	#   * -5812631b
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa7
	lsl	r1, r1, #8
	orr	r1, r1, #0xed
	lsl	r1, r1, #8
	orr	r1, r1, #0x9c
	lsl	r1, r1, #8
	orr	r1, r1, #0xe5
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x9c
	lsl	r1, r1, #8
	add	r1, r1, #0xe5
#else
	mov	r1, #0x9ce5
#endif
	movt	r1, #0xa7ed
#endif
	mov	r10, #0
	ldm	r0, {r6, r7, r8, r9}
	umlal	r6, r10, r2, r1
	adds	r7, r7, r10
	mov	r10, #0
	adc	r10, r10, #0
	umlal	r7, r10, r3, r1
	adds	r8, r8, r10
	mov	r10, #0
	adc	r10, r10, #0
	umlal	r8, r10, r4, r1
	adds	r9, r9, r10
	mov	r10, #0
	adc	r10, r10, #0
	umlal	r9, r10, r5, r1
	stm	r0, {r6, r7, r8, r9}
	add	r0, r0, #4
	#   * -a2f79cd7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x5d
	lsl	r1, r1, #8
	orr	r1, r1, #8
	lsl	r1, r1, #8
	orr	r1, r1, #0x63
	lsl	r1, r1, #8
	orr	r1, r1, #41
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x63
	lsl	r1, r1, #8
	add	r1, r1, #0x29
#else
	mov	r1, #0x6329
#endif
	movt	r1, #0x5d08
#endif
	mov	r11, #0
	ldm	r0, {r6, r7, r8, r9}
	umlal	r6, r11, r2, r1
	adds	r7, r7, r11
	mov	r11, #0
	adc	r11, r11, #0
	umlal	r7, r11, r3, r1
	adds	r8, r8, r11
	mov	r11, #0
	adc	r11, r11, #0
	umlal	r8, r11, r4, r1
	adds	r9, r9, r11
	mov	r11, #0
	adc	r11, r11, #0
	umlal	r9, r11, r5, r1
	stm	r0, {r6, r7, r8, r9}
	add	r0, r0, #4
	#   * -14def9df
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xeb
	lsl	r1, r1, #8
	orr	r1, r1, #33
	lsl	r1, r1, #8
	orr	r1, r1, #6
	lsl	r1, r1, #8
	orr	r1, r1, #33
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x6
	lsl	r1, r1, #8
	add	r1, r1, #0x21
#else
	mov	r1, #0x621
#endif
	movt	r1, #0xeb21
#endif
	mov	r12, #0
	ldm	r0, {r6, r7, r8, r9}
	umlal	r6, r12, r2, r1
	adds	r7, r7, r12
	mov	r12, #0
	adc	r12, r12, #0
	umlal	r7, r12, r3, r1
	adds	r8, r8, r12
	mov	r12, #0
	adc	r12, r12, #0
	umlal	r8, r12, r4, r1
	adds	r9, r9, r12
	mov	r12, #0
	adc	r12, r12, #0
	umlal	r9, r12, r5, r1
	stm	r0, {r6, r7, r8, r9}
	add	r0, r0, #4
	# Add overflows at 4 * 32
	ldm	r0, {r6, r7, r8, r9}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xf0000000
#else
	bfc	r9, #28, #4
#endif
	adds	r6, r6, lr
	adcs	r7, r7, r10
	adcs	r8, r8, r11
	adc	r9, r9, r12
	# Subtract top at 4 * 32
	subs	r6, r6, r2
	sbcs	r7, r7, r3
	sbcs	r8, r8, r4
	sbcs	r9, r9, r5
	sbc	r1, r1, r1
	sub	r0, r0, #16
	ldm	r0, {r2, r3, r4, r5}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0x5c
	lsl	r10, r10, #8
	orr	r10, r10, #0xf5
	lsl	r10, r10, #8
	orr	r10, r10, #0xd3
	lsl	r10, r10, #8
	orr	r10, r10, #0xed
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd3
	lsl	r10, r10, #8
	add	r10, r10, #0xed
#else
	mov	r10, #0xd3ed
#endif
	movt	r10, #0x5cf5
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x58
	lsl	r11, r11, #8
	orr	r11, r11, #18
	lsl	r11, r11, #8
	orr	r11, r11, #0x63
	lsl	r11, r11, #8
	orr	r11, r11, #26
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x63
	lsl	r11, r11, #8
	add	r11, r11, #0x1a
#else
	mov	r11, #0x631a
#endif
	movt	r11, #0x5812
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xa2
	lsl	r12, r12, #8
	orr	r12, r12, #0xf7
	lsl	r12, r12, #8
	orr	r12, r12, #0x9c
	lsl	r12, r12, #8
	orr	r12, r12, #0xd6
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0x9c
	lsl	r12, r12, #8
	add	r12, r12, #0xd6
#else
	mov	r12, #0x9cd6
#endif
	movt	r12, #0xa2f7
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	lr, #20
	lsl	lr, lr, #8
	orr	lr, lr, #0xde
	lsl	lr, lr, #8
	orr	lr, lr, #0xf9
	lsl	lr, lr, #8
	orr	lr, lr, #0xde
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	lr, #0xf9
	lsl	lr, lr, #8
	add	lr, lr, #0xde
#else
	mov	lr, #0xf9de
#endif
	movt	lr, #0x14de
#endif
	and	r10, r10, r1
	and	r11, r11, r1
	and	r12, r12, r1
	and	lr, lr, r1
	adds	r2, r2, r10
	adcs	r3, r3, r11
	adcs	r4, r4, r12
	adcs	r5, r5, lr
	adcs	r6, r6, #0
	adcs	r7, r7, #0
	and	r1, r1, #0x10000000
	adcs	r8, r8, #0
	adc	r9, r9, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xf0000000
#else
	bfc	r9, #28, #4
#endif
	ldr	r0, [sp, #68]
	# Store result
	str	r2, [r0]
	str	r3, [r0, #4]
	str	r4, [r0, #8]
	str	r5, [r0, #12]
	str	r6, [r0, #16]
	str	r7, [r0, #20]
	str	r8, [r0, #24]
	str	r9, [r0, #28]
	add	sp, sp, #0x50
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	sc_muladd,.-sc_muladd
#else
	.text
	.align	4
	.globl	sc_muladd
	.type	sc_muladd, %function
sc_muladd:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #0x50
	add	lr, sp, #0x44
	stm	lr, {r0, r1, r3}
	mov	lr, r2
	ldm	r1, {r0, r1, r2, r3}
	ldm	lr!, {r4, r5, r6}
	umull	r10, r11, r0, r4
	umull	r12, r7, r1, r4
	umaal	r11, r12, r0, r5
	umull	r8, r9, r2, r4
	umaal	r12, r8, r1, r5
	umaal	r12, r7, r0, r6
	umaal	r8, r9, r3, r4
	stm	sp, {r10, r11, r12}
	umaal	r7, r8, r2, r5
	ldm	lr!, {r4}
	umull	r10, r11, r1, r6
	umaal	r8, r9, r2, r6
	umaal	r7, r10, r0, r4
	umaal	r8, r11, r3, r5
	str	r7, [sp, #12]
	umaal	r8, r10, r1, r4
	umaal	r9, r11, r3, r6
	umaal	r9, r10, r2, r4
	umaal	r10, r11, r3, r4
	ldm	lr, {r4, r5, r6, r7}
	mov	r12, #0
	umlal	r8, r12, r0, r4
	umaal	r9, r12, r1, r4
	umaal	r10, r12, r2, r4
	umaal	r11, r12, r3, r4
	mov	r4, #0
	umlal	r9, r4, r0, r5
	umaal	r10, r4, r1, r5
	umaal	r11, r4, r2, r5
	umaal	r12, r4, r3, r5
	mov	r5, #0
	umlal	r10, r5, r0, r6
	umaal	r11, r5, r1, r6
	umaal	r12, r5, r2, r6
	umaal	r4, r5, r3, r6
	mov	r6, #0
	umlal	r11, r6, r0, r7
	ldr	r0, [sp, #72]
	umaal	r12, r6, r1, r7
	add	r0, r0, #16
	umaal	r4, r6, r2, r7
	sub	lr, lr, #16
	umaal	r5, r6, r3, r7
	ldm	r0, {r0, r1, r2, r3}
	str	r6, [sp, #64]
	ldm	lr!, {r6}
	mov	r7, #0
	umlal	r8, r7, r0, r6
	umaal	r9, r7, r1, r6
	str	r8, [sp, #16]
	umaal	r10, r7, r2, r6
	umaal	r11, r7, r3, r6
	ldm	lr!, {r6}
	mov	r8, #0
	umlal	r9, r8, r0, r6
	umaal	r10, r8, r1, r6
	str	r9, [sp, #20]
	umaal	r11, r8, r2, r6
	umaal	r12, r8, r3, r6
	ldm	lr!, {r6}
	mov	r9, #0
	umlal	r10, r9, r0, r6
	umaal	r11, r9, r1, r6
	str	r10, [sp, #24]
	umaal	r12, r9, r2, r6
	umaal	r4, r9, r3, r6
	ldm	lr!, {r6}
	mov	r10, #0
	umlal	r11, r10, r0, r6
	umaal	r12, r10, r1, r6
	str	r11, [sp, #28]
	umaal	r4, r10, r2, r6
	umaal	r5, r10, r3, r6
	ldm	lr!, {r11}
	umaal	r12, r7, r0, r11
	umaal	r4, r7, r1, r11
	ldr	r6, [sp, #64]
	umaal	r5, r7, r2, r11
	umaal	r6, r7, r3, r11
	ldm	lr!, {r11}
	umaal	r4, r8, r0, r11
	umaal	r5, r8, r1, r11
	umaal	r6, r8, r2, r11
	umaal	r7, r8, r3, r11
	ldm	lr, {r11, lr}
	umaal	r5, r9, r0, r11
	umaal	r6, r10, r0, lr
	umaal	r6, r9, r1, r11
	umaal	r7, r10, r1, lr
	umaal	r7, r9, r2, r11
	umaal	r8, r10, r2, lr
	umaal	r8, r9, r3, r11
	umaal	r9, r10, r3, lr
	mov	r3, r12
	add	lr, sp, #32
	stm	lr, {r3, r4, r5, r6, r7, r8, r9, r10}
	mov	r0, sp
	# Add c to a * b
	ldr	lr, [sp, #76]
	ldm	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	ldm	lr!, {r1, r10, r11, r12}
	adds	r2, r2, r1
	adcs	r3, r3, r10
	adcs	r4, r4, r11
	adcs	r5, r5, r12
	ldm	lr!, {r1, r10, r11, r12}
	adcs	r6, r6, r1
	adcs	r7, r7, r10
	adcs	r8, r8, r11
	adcs	r9, r9, r12
	mov	r1, r9
	stm	r0!, {r2, r3, r4, r5, r6, r7, r8, r9}
	ldm	r0, {r2, r3, r4, r5, r6, r7, r8, r9}
	adcs	r2, r2, #0
	adcs	r3, r3, #0
	adcs	r4, r4, #0
	adcs	r5, r5, #0
	adcs	r6, r6, #0
	adcs	r7, r7, #0
	adcs	r8, r8, #0
	adc	r9, r9, #0
	sub	r0, r0, #32
	# Get 252..503 and 504..507
	lsr	lr, r9, #24
	lsl	r9, r9, #4
	orr	r9, r9, r8, LSR #28
	lsl	r8, r8, #4
	orr	r8, r8, r7, LSR #28
	lsl	r7, r7, #4
	orr	r7, r7, r6, LSR #28
	lsl	r6, r6, #4
	orr	r6, r6, r5, LSR #28
	lsl	r5, r5, #4
	orr	r5, r5, r4, LSR #28
	lsl	r4, r4, #4
	orr	r4, r4, r3, LSR #28
	lsl	r3, r3, #4
	orr	r3, r3, r2, LSR #28
	lsl	r2, r2, #4
	orr	r2, r2, r1, LSR #28
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xf0000000
#else
	bfc	r9, #28, #4
#endif
	# Add order times bits 504..507
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xa3
	lsl	r10, r10, #8
	orr	r10, r10, #10
	lsl	r10, r10, #8
	orr	r10, r10, #44
	lsl	r10, r10, #8
	orr	r10, r10, #19
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0x2c
	lsl	r10, r10, #8
	add	r10, r10, #0x13
#else
	mov	r10, #0x2c13
#endif
	movt	r10, #0xa30a
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0xa7
	lsl	r11, r11, #8
	orr	r11, r11, #0xed
	lsl	r11, r11, #8
	orr	r11, r11, #0x9c
	lsl	r11, r11, #8
	orr	r11, r11, #0xe5
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x9c
	lsl	r11, r11, #8
	add	r11, r11, #0xe5
#else
	mov	r11, #0x9ce5
#endif
	movt	r11, #0xa7ed
#endif
	mov	r1, #0
	umlal	r2, r1, r10, lr
	umaal	r3, r1, r11, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0x5d
	lsl	r10, r10, #8
	orr	r10, r10, #8
	lsl	r10, r10, #8
	orr	r10, r10, #0x63
	lsl	r10, r10, #8
	orr	r10, r10, #41
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0x63
	lsl	r10, r10, #8
	add	r10, r10, #0x29
#else
	mov	r10, #0x6329
#endif
	movt	r10, #0x5d08
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0xeb
	lsl	r11, r11, #8
	orr	r11, r11, #33
	lsl	r11, r11, #8
	orr	r11, r11, #6
	lsl	r11, r11, #8
	orr	r11, r11, #33
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x6
	lsl	r11, r11, #8
	add	r11, r11, #0x21
#else
	mov	r11, #0x621
#endif
	movt	r11, #0xeb21
#endif
	umaal	r4, r1, r10, lr
	umaal	r5, r1, r11, lr
	adds	r6, r6, r1
	adcs	r7, r7, #0
	adcs	r8, r8, #0
	adc	r9, r9, #0
	subs	r6, r6, lr
	sbcs	r7, r7, #0
	sbcs	r8, r8, #0
	sbc	r9, r9, #0
	# Sub product of top 8 words and order
	mov	r12, sp
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa3
	lsl	r1, r1, #8
	orr	r1, r1, #10
	lsl	r1, r1, #8
	orr	r1, r1, #44
	lsl	r1, r1, #8
	orr	r1, r1, #19
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x2c
	lsl	r1, r1, #8
	add	r1, r1, #0x13
#else
	mov	r1, #0x2c13
#endif
	movt	r1, #0xa30a
#endif
	mov	lr, #0
	ldm	r0!, {r10, r11}
	umlal	r10, lr, r2, r1
	umaal	r11, lr, r3, r1
	stm	r12!, {r10, r11}
	ldm	r0!, {r10, r11}
	umaal	r10, lr, r4, r1
	umaal	r11, lr, r5, r1
	stm	r12!, {r10, r11}
	ldm	r0!, {r10, r11}
	umaal	r10, lr, r6, r1
	umaal	r11, lr, r7, r1
	stm	r12!, {r10, r11}
	ldm	r0!, {r10, r11}
	umaal	r10, lr, r8, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r11, r11, #0xf0000000
#else
	bfc	r11, #28, #4
#endif
	umaal	r11, lr, r9, r1
	stm	r12!, {r10, r11, lr}
	sub	r0, r0, #16
	sub	r12, r12, #32
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa7
	lsl	r1, r1, #8
	orr	r1, r1, #0xed
	lsl	r1, r1, #8
	orr	r1, r1, #0x9c
	lsl	r1, r1, #8
	orr	r1, r1, #0xe5
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x9c
	lsl	r1, r1, #8
	add	r1, r1, #0xe5
#else
	mov	r1, #0x9ce5
#endif
	movt	r1, #0xa7ed
#endif
	mov	lr, #0
	ldm	r12, {r10, r11}
	umlal	r10, lr, r2, r1
	umaal	r11, lr, r3, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	umaal	r10, lr, r4, r1
	umaal	r11, lr, r5, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	umaal	r10, lr, r6, r1
	umaal	r11, lr, r7, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	umaal	r10, lr, r8, r1
	umaal	r11, lr, r9, r1
	stm	r12!, {r10, r11, lr}
	sub	r12, r12, #32
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x5d
	lsl	r1, r1, #8
	orr	r1, r1, #8
	lsl	r1, r1, #8
	orr	r1, r1, #0x63
	lsl	r1, r1, #8
	orr	r1, r1, #41
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x63
	lsl	r1, r1, #8
	add	r1, r1, #0x29
#else
	mov	r1, #0x6329
#endif
	movt	r1, #0x5d08
#endif
	mov	lr, #0
	ldm	r12, {r10, r11}
	umlal	r10, lr, r2, r1
	umaal	r11, lr, r3, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	umaal	r10, lr, r4, r1
	umaal	r11, lr, r5, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	umaal	r10, lr, r6, r1
	umaal	r11, lr, r7, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	umaal	r10, lr, r8, r1
	umaal	r11, lr, r9, r1
	stm	r12!, {r10, r11, lr}
	sub	r12, r12, #32
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xeb
	lsl	r1, r1, #8
	orr	r1, r1, #33
	lsl	r1, r1, #8
	orr	r1, r1, #6
	lsl	r1, r1, #8
	orr	r1, r1, #33
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x6
	lsl	r1, r1, #8
	add	r1, r1, #0x21
#else
	mov	r1, #0x621
#endif
	movt	r1, #0xeb21
#endif
	mov	lr, #0
	ldm	r12, {r10, r11}
	umlal	r10, lr, r2, r1
	umaal	r11, lr, r3, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	umaal	r10, lr, r4, r1
	umaal	r11, lr, r5, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	umaal	r10, lr, r6, r1
	umaal	r11, lr, r7, r1
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	umaal	r10, lr, r8, r1
	umaal	r11, lr, r9, r1
	stm	r12!, {r10, r11, lr}
	sub	r12, r12, #32
	# Subtract at 4 * 32
	ldm	r12, {r10, r11}
	subs	r10, r10, r2
	sbcs	r11, r11, r3
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	sbcs	r10, r10, r4
	sbcs	r11, r11, r5
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	sbcs	r10, r10, r6
	sbcs	r11, r11, r7
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	sbcs	r10, r10, r8
	sbc	r11, r11, r9
	stm	r12!, {r10, r11}
	sub	r12, r12, #36
	asr	lr, r11, #25
	# Conditionally subtract order starting at bit 125
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa00000
	lsl	r1, r1, #8
	add	r1, r1, #0x0
#else
	mov	r1, #0xa0000000
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0x4b
	lsl	r2, r2, #8
	orr	r2, r2, #0x9e
	lsl	r2, r2, #8
	orr	r2, r2, #0xba
	lsl	r2, r2, #8
	orr	r2, r2, #0x7d
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r2, #0xba
	lsl	r2, r2, #8
	add	r2, r2, #0x7d
#else
	mov	r2, #0xba7d
#endif
	movt	r2, #0x4b9e
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0xcb
	lsl	r3, r3, #8
	orr	r3, r3, #2
	lsl	r3, r3, #8
	orr	r3, r3, #0x4c
	lsl	r3, r3, #8
	orr	r3, r3, #0x63
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r3, #0x4c
	lsl	r3, r3, #8
	add	r3, r3, #0x63
#else
	mov	r3, #0x4c63
#endif
	movt	r3, #0xcb02
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r4, #0xd4
	lsl	r4, r4, #8
	orr	r4, r4, #0x5e
	lsl	r4, r4, #8
	orr	r4, r4, #0xf3
	lsl	r4, r4, #8
	orr	r4, r4, #0x9a
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r4, #0xf3
	lsl	r4, r4, #8
	add	r4, r4, #0x9a
#else
	mov	r4, #0xf39a
#endif
	movt	r4, #0xd45e
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r5, #2
	lsl	r5, r5, #8
	orr	r5, r5, #0x9b
	lsl	r5, r5, #8
	orr	r5, r5, #0xdf
	lsl	r5, r5, #8
	orr	r5, r5, #59
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r5, #0xdf
	lsl	r5, r5, #8
	add	r5, r5, #0x3b
#else
	mov	r5, #0xdf3b
#endif
	movt	r5, #0x29b
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r9, #0x20000
	lsl	r9, r9, #8
	add	r9, r9, #0x0
#else
	mov	r9, #0x2000000
#endif
	and	r1, r1, lr
	and	r2, r2, lr
	and	r3, r3, lr
	and	r4, r4, lr
	and	r5, r5, lr
	and	r9, r9, lr
	ldm	r12, {r10, r11}
	adds	r10, r10, r1
	adcs	r11, r11, r2
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adcs	r10, r10, r3
	adcs	r11, r11, r4
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adcs	r10, r10, r5
	adcs	r11, r11, #0
	stm	r12!, {r10, r11}
	ldm	r12, {r10, r11}
	adcs	r10, r10, #0
	adcs	r11, r11, #0
	stm	r12!, {r10, r11}
	ldm	r12, {r10}
	adcs	r10, r10, #0
	stm	r12!, {r10}
	sub	r0, r0, #16
	mov	r12, sp
	# Load bits 252-376
	add	r12, r12, #28
	ldm	r12, {r1, r2, r3, r4, r5}
	lsl	r5, r5, #4
	orr	r5, r5, r4, lsr #28
	lsl	r4, r4, #4
	orr	r4, r4, r3, lsr #28
	lsl	r3, r3, #4
	orr	r3, r3, r2, lsr #28
	lsl	r2, r2, #4
	orr	r2, r2, r1, lsr #28
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r5, r5, #0xe0000000
#else
	bfc	r5, #29, #3
#endif
	sub	r12, r12, #28
	# Sub product of top 4 words and order
	mov	r0, sp
	#   * -5cf5d3ed
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa3
	lsl	r1, r1, #8
	orr	r1, r1, #10
	lsl	r1, r1, #8
	orr	r1, r1, #44
	lsl	r1, r1, #8
	orr	r1, r1, #19
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x2c
	lsl	r1, r1, #8
	add	r1, r1, #0x13
#else
	mov	r1, #0x2c13
#endif
	movt	r1, #0xa30a
#endif
	mov	lr, #0
	ldm	r0, {r6, r7, r8, r9}
	umlal	r6, lr, r2, r1
	umaal	r7, lr, r3, r1
	umaal	r8, lr, r4, r1
	umaal	r9, lr, r5, r1
	stm	r0, {r6, r7, r8, r9}
	add	r0, r0, #4
	#   * -5812631b
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xa7
	lsl	r1, r1, #8
	orr	r1, r1, #0xed
	lsl	r1, r1, #8
	orr	r1, r1, #0x9c
	lsl	r1, r1, #8
	orr	r1, r1, #0xe5
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x9c
	lsl	r1, r1, #8
	add	r1, r1, #0xe5
#else
	mov	r1, #0x9ce5
#endif
	movt	r1, #0xa7ed
#endif
	mov	r10, #0
	ldm	r0, {r6, r7, r8, r9}
	umlal	r6, r10, r2, r1
	umaal	r7, r10, r3, r1
	umaal	r8, r10, r4, r1
	umaal	r9, r10, r5, r1
	stm	r0, {r6, r7, r8, r9}
	add	r0, r0, #4
	#   * -a2f79cd7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x5d
	lsl	r1, r1, #8
	orr	r1, r1, #8
	lsl	r1, r1, #8
	orr	r1, r1, #0x63
	lsl	r1, r1, #8
	orr	r1, r1, #41
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x63
	lsl	r1, r1, #8
	add	r1, r1, #0x29
#else
	mov	r1, #0x6329
#endif
	movt	r1, #0x5d08
#endif
	mov	r11, #0
	ldm	r0, {r6, r7, r8, r9}
	umlal	r6, r11, r2, r1
	umaal	r7, r11, r3, r1
	umaal	r8, r11, r4, r1
	umaal	r9, r11, r5, r1
	stm	r0, {r6, r7, r8, r9}
	add	r0, r0, #4
	#   * -14def9df
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0xeb
	lsl	r1, r1, #8
	orr	r1, r1, #33
	lsl	r1, r1, #8
	orr	r1, r1, #6
	lsl	r1, r1, #8
	orr	r1, r1, #33
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r1, #0x6
	lsl	r1, r1, #8
	add	r1, r1, #0x21
#else
	mov	r1, #0x621
#endif
	movt	r1, #0xeb21
#endif
	mov	r12, #0
	ldm	r0, {r6, r7, r8, r9}
	umlal	r6, r12, r2, r1
	umaal	r7, r12, r3, r1
	umaal	r8, r12, r4, r1
	umaal	r9, r12, r5, r1
	stm	r0, {r6, r7, r8, r9}
	add	r0, r0, #4
	# Add overflows at 4 * 32
	ldm	r0, {r6, r7, r8, r9}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xf0000000
#else
	bfc	r9, #28, #4
#endif
	adds	r6, r6, lr
	adcs	r7, r7, r10
	adcs	r8, r8, r11
	adc	r9, r9, r12
	# Subtract top at 4 * 32
	subs	r6, r6, r2
	sbcs	r7, r7, r3
	sbcs	r8, r8, r4
	sbcs	r9, r9, r5
	sbc	r1, r1, r1
	sub	r0, r0, #16
	ldm	r0, {r2, r3, r4, r5}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0x5c
	lsl	r10, r10, #8
	orr	r10, r10, #0xf5
	lsl	r10, r10, #8
	orr	r10, r10, #0xd3
	lsl	r10, r10, #8
	orr	r10, r10, #0xed
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r10, #0xd3
	lsl	r10, r10, #8
	add	r10, r10, #0xed
#else
	mov	r10, #0xd3ed
#endif
	movt	r10, #0x5cf5
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x58
	lsl	r11, r11, #8
	orr	r11, r11, #18
	lsl	r11, r11, #8
	orr	r11, r11, #0x63
	lsl	r11, r11, #8
	orr	r11, r11, #26
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r11, #0x63
	lsl	r11, r11, #8
	add	r11, r11, #0x1a
#else
	mov	r11, #0x631a
#endif
	movt	r11, #0x5812
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0xa2
	lsl	r12, r12, #8
	orr	r12, r12, #0xf7
	lsl	r12, r12, #8
	orr	r12, r12, #0x9c
	lsl	r12, r12, #8
	orr	r12, r12, #0xd6
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	r12, #0x9c
	lsl	r12, r12, #8
	add	r12, r12, #0xd6
#else
	mov	r12, #0x9cd6
#endif
	movt	r12, #0xa2f7
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	lr, #20
	lsl	lr, lr, #8
	orr	lr, lr, #0xde
	lsl	lr, lr, #8
	orr	lr, lr, #0xf9
	lsl	lr, lr, #8
	orr	lr, lr, #0xde
#else
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	mov	lr, #0xf9
	lsl	lr, lr, #8
	add	lr, lr, #0xde
#else
	mov	lr, #0xf9de
#endif
	movt	lr, #0x14de
#endif
	and	r10, r10, r1
	and	r11, r11, r1
	and	r12, r12, r1
	and	lr, lr, r1
	adds	r2, r2, r10
	adcs	r3, r3, r11
	adcs	r4, r4, r12
	adcs	r5, r5, lr
	adcs	r6, r6, #0
	adcs	r7, r7, #0
	and	r1, r1, #0x10000000
	adcs	r8, r8, #0
	adc	r9, r9, r1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	bic	r9, r9, #0xf0000000
#else
	bfc	r9, #28, #4
#endif
	ldr	r0, [sp, #68]
	# Store result
	str	r2, [r0]
	str	r3, [r0, #4]
	str	r4, [r0, #8]
	str	r5, [r0, #12]
	str	r6, [r0, #16]
	str	r7, [r0, #20]
	str	r8, [r0, #24]
	str	r9, [r0, #28]
	add	sp, sp, #0x50
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	sc_muladd,.-sc_muladd
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
#endif /* HAVE_ED25519_SIGN */
#endif /* HAVE_ED25519 */

#endif /* !CURVE25519_SMALL || !ED25519_SMALL */
#endif /* HAVE_CURVE25519 || HAVE_ED25519 */
#endif /* !__aarch64__ && __arm__ && !__thumb__ */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
