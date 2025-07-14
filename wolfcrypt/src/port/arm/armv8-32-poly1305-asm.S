/* armv8-32-poly1305-asm
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
 *   ruby ./poly1305/poly1305.rb arm32 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-32-poly1305-asm.S
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

#ifdef WOLFSSL_ARMASM
#if !defined(__aarch64__) && !defined(WOLFSSL_ARMASM_THUMB2)
#ifndef WOLFSSL_ARMASM_INLINE
#ifdef HAVE_POLY1305
#ifdef WOLFSSL_ARMASM_NO_NEON
	.text
	.align	4
	.globl	poly1305_arm32_blocks_16
	.type	poly1305_arm32_blocks_16, %function
poly1305_arm32_blocks_16:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #28
	cmp	r2, #0
	beq	L_poly1305_arm32_16_done
	add	lr, sp, #12
	stm	lr, {r0, r1, r2, r3}
	# Get h pointer
	add	lr, r0, #16
	ldm	lr, {r4, r5, r6, r7, r8}
L_poly1305_arm32_16_loop:
	# Add m to h
	ldr	r1, [sp, #16]
	ldr	r2, [r1]
	ldr	r3, [r1, #4]
	ldr	r9, [r1, #8]
	ldr	r10, [r1, #12]
	ldr	r11, [sp, #24]
	adds	r4, r4, r2
	adcs	r5, r5, r3
	adcs	r6, r6, r9
	adcs	r7, r7, r10
	add	r1, r1, #16
	adc	r8, r8, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	stm	lr, {r4, r5, r6, r7, r8}
#else
	# h[0]-h[2] in r4-r6 for multiplication.
	str	r7, [lr, #12]
	str	r8, [lr, #16]
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	str	r1, [sp, #16]
	ldr	r1, [sp, #12]
	# Multiply h by r
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	# r0 = #0, r1 = r, lr = h, r2 = h[j], r3 = r[i]
	ldr	r3, [r1]
	eor	r0, r0, r0
	# r[0] * h[0]
	# h[0] in r4
	umull	r4, r5, r3, r4
	# r[0] * h[2]
	# h[2] in r6
	umull	r6, r7, r3, r6
	# r[0] * h[4]
	# h[4] in r8
	mul	r8, r3, r8
	# r[0] * h[1]
	ldr	r2, [lr, #4]
	mov	r12, r0
	umlal	r5, r12, r3, r2
	# r[0] * h[3]
	ldr	r2, [lr, #12]
	adds	r6, r6, r12
	adc	r7, r7, r0
	umlal	r7, r8, r3, r2
	# r[1] * h[0]
	ldr	r3, [r1, #4]
	ldr	r2, [lr]
	mov	r12, r0
	umlal	r5, r12, r3, r2
	# r[1] * h[1]
	ldr	r2, [lr, #4]
	adds	r6, r6, r12
	adc	r12, r0, r0
	umlal	r6, r12, r3, r2
	# r[1] * h[2]
	ldr	r2, [lr, #8]
	adds	r7, r7, r12
	adc	r12, r0, r0
	umlal	r7, r12, r3, r2
	# r[1] * h[3]
	ldr	r2, [lr, #12]
	adds	r8, r8, r12
	adc	r9, r0, r0
	umlal	r8, r9, r3, r2
	# r[1] * h[4]
	ldr	r2, [lr, #16]
	mla	r9, r3, r2, r9
	# r[2] * h[0]
	ldr	r3, [r1, #8]
	ldr	r2, [lr]
	mov	r12, r0
	umlal	r6, r12, r3, r2
	# r[2] * h[1]
	ldr	r2, [lr, #4]
	adds	r7, r7, r12
	adc	r12, r0, r0
	umlal	r7, r12, r3, r2
	# r[2] * h[2]
	ldr	r2, [lr, #8]
	adds	r8, r8, r12
	adc	r12, r0, r0
	umlal	r8, r12, r3, r2
	# r[2] * h[3]
	ldr	r2, [lr, #12]
	adds	r9, r9, r12
	adc	r10, r0, r0
	umlal	r9, r10, r3, r2
	# r[2] * h[4]
	ldr	r2, [lr, #16]
	mla	r10, r3, r2, r10
	# r[3] * h[0]
	ldr	r3, [r1, #12]
	ldr	r2, [lr]
	mov	r12, r0
	umlal	r7, r12, r3, r2
	# r[3] * h[1]
	ldr	r2, [lr, #4]
	adds	r8, r8, r12
	adc	r12, r0, r0
	umlal	r8, r12, r3, r2
	# r[3] * h[2]
	ldr	r2, [lr, #8]
	adds	r9, r9, r12
	adc	r10, r10, r0
	umlal	r9, r10, r3, r2
	# r[3] * h[3]
	ldr	r2, [lr, #12]
	mov	r11, r0
	umlal	r10, r11, r3, r2
	# r[3] * h[4]
	ldr	r2, [lr, #16]
	mov	r12, r0
	mla	r11, r3, r2, r11
#else
	ldm	r1, {r0, r1, r2, r3}
	# r[0] * h[0]
	umull	r10, r11, r0, r4
	# r[1] * h[0]
	umull	r12, r7, r1, r4
	# r[0] * h[1]
	umaal	r11, r12, r0, r5
	# r[2] * h[0]
	umull	r8, r9, r2, r4
	# r[1] * h[1]
	umaal	r12, r8, r1, r5
	# r[0] * h[2]
	umaal	r12, r7, r0, r6
	# r[3] * h[0]
	umaal	r8, r9, r3, r4
	stm	sp, {r10, r11, r12}
	# r[2] * h[1]
	umaal	r7, r8, r2, r5
	# Replace h[0] with h[3]
	ldr	r4, [lr, #12]
	# r[1] * h[2]
	umull	r10, r11, r1, r6
	# r[2] * h[2]
	umaal	r8, r9, r2, r6
	# r[0] * h[3]
	umaal	r7, r10, r0, r4
	# r[3] * h[1]
	umaal	r8, r11, r3, r5
	# r[1] * h[3]
	umaal	r8, r10, r1, r4
	# r[3] * h[2]
	umaal	r9, r11, r3, r6
	# r[2] * h[3]
	umaal	r9, r10, r2, r4
	# Replace h[1] with h[4]
	ldr	r5, [lr, #16]
	# r[3] * h[3]
	umaal	r10, r11, r3, r4
	mov	r12, #0
	# r[0] * h[4]
	umaal	r8, r12, r0, r5
	# r[1] * h[4]
	umaal	r9, r12, r1, r5
	# r[2] * h[4]
	umaal	r10, r12, r2, r5
	# r[3] * h[4]
	umaal	r11, r12, r3, r5
	# DONE
	ldm	sp, {r4, r5, r6}
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	# r12 will be zero because r is masked.
	# Load length
	ldr	r2, [sp, #20]
	# Reduce mod 2^130 - 5
	bic	r3, r8, #0x3
	and	r8, r8, #3
	adds	r4, r4, r3
	lsr	r3, r3, #2
	adcs	r5, r5, r9
	orr	r3, r3, r9, LSL #30
	adcs	r6, r6, r10
	lsr	r9, r9, #2
	adcs	r7, r7, r11
	orr	r9, r9, r10, LSL #30
	adc	r8, r8, r12
	lsr	r10, r10, #2
	adds	r4, r4, r3
	orr	r10, r10, r11, LSL #30
	adcs	r5, r5, r9
	lsr	r11, r11, #2
	adcs	r6, r6, r10
	adcs	r7, r7, r11
	adc	r8, r8, r12
	# Sub 16 from length.
	subs	r2, r2, #16
	# Store length.
	str	r2, [sp, #20]
	# Loop again if more message to do.
	bgt	L_poly1305_arm32_16_loop
	stm	lr, {r4, r5, r6, r7, r8}
L_poly1305_arm32_16_done:
	add	sp, sp, #28
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	poly1305_arm32_blocks_16,.-poly1305_arm32_blocks_16
	.text
	.type	L_poly1305_arm32_clamp, %object
	.size	L_poly1305_arm32_clamp, 16
	.align	4
L_poly1305_arm32_clamp:
	.word	0xfffffff
	.word	0xffffffc
	.word	0xffffffc
	.word	0xffffffc
	.text
	.align	4
	.globl	poly1305_set_key
	.type	poly1305_set_key, %function
poly1305_set_key:
	push	{r4, r5, r6, r7, r8, lr}
	# Load mask.
	adr	lr, L_poly1305_arm32_clamp
	ldm	lr, {r6, r7, r8, r12}
	# Load and cache padding.
	ldr	r2, [r1, #16]
	ldr	r3, [r1, #20]
	ldr	r4, [r1, #24]
	ldr	r5, [r1, #28]
	add	lr, r0, #36
	stm	lr, {r2, r3, r4, r5}
	# Load, mask and store r.
	ldr	r2, [r1]
	ldr	r3, [r1, #4]
	ldr	r4, [r1, #8]
	ldr	r5, [r1, #12]
	and	r2, r2, r6
	and	r3, r3, r7
	and	r4, r4, r8
	and	r5, r5, r12
	add	lr, r0, #0
	stm	lr, {r2, r3, r4, r5}
	# h (accumulator) = 0
	eor	r6, r6, r6
	eor	r7, r7, r7
	eor	r8, r8, r8
	eor	r12, r12, r12
	add	lr, r0, #16
	eor	r5, r5, r5
	stm	lr, {r5, r6, r7, r8, r12}
	# Zero leftover
	str	r5, [r0, #52]
	pop	{r4, r5, r6, r7, r8, pc}
	.size	poly1305_set_key,.-poly1305_set_key
	.text
	.align	4
	.globl	poly1305_final
	.type	poly1305_final, %function
poly1305_final:
	push	{r4, r5, r6, r7, r8, r9, lr}
	add	r9, r0, #16
	ldm	r9, {r4, r5, r6, r7, r8}
	# Add 5 and check for h larger than p.
	adds	r2, r4, #5
	adcs	r2, r5, #0
	adcs	r2, r6, #0
	adcs	r2, r7, #0
	adc	r2, r8, #0
	sub	r2, r2, #4
	lsr	r2, r2, #31
	sub	r2, r2, #1
	and	r2, r2, #5
	# Add 0/5 to h.
	adds	r4, r4, r2
	adcs	r5, r5, #0
	adcs	r6, r6, #0
	adc	r7, r7, #0
	# Add padding
	add	r9, r0, #36
	ldm	r9, {r2, r3, r12, lr}
	adds	r4, r4, r2
	adcs	r5, r5, r3
	adcs	r6, r6, r12
	adc	r7, r7, lr
	# Store MAC
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	# Zero out h.
	eor	r4, r4, r4
	eor	r5, r5, r5
	eor	r6, r6, r6
	eor	r7, r7, r7
	eor	r8, r8, r8
	add	r9, r0, #16
	stm	r9, {r4, r5, r6, r7, r8}
	# Zero out r.
	add	r9, r0, #0
	stm	r9, {r4, r5, r6, r7}
	# Zero out padding.
	add	r9, r0, #36
	stm	r9, {r4, r5, r6, r7}
	pop	{r4, r5, r6, r7, r8, r9, pc}
	.size	poly1305_final,.-poly1305_final
#else
	.text
	.align	4
	.globl	poly1305_arm32_blocks_16
	.type	poly1305_arm32_blocks_16, %function
poly1305_arm32_blocks_16:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #28
	cmp	r2, #0
	beq	L_poly1305_arm32_16_done
	add	lr, sp, #12
	stm	lr, {r0, r1, r2, r3}
	# Get h pointer
	add	lr, r0, #16
	ldm	lr, {r4, r5, r6, r7, r8}
L_poly1305_arm32_16_loop:
	# Add m to h
	ldr	r1, [sp, #16]
	ldr	r2, [r1]
	ldr	r3, [r1, #4]
	ldr	r9, [r1, #8]
	ldr	r10, [r1, #12]
	ldr	r11, [sp, #24]
	adds	r4, r4, r2
	adcs	r5, r5, r3
	adcs	r6, r6, r9
	adcs	r7, r7, r10
	add	r1, r1, #16
	adc	r8, r8, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	stm	lr, {r4, r5, r6, r7, r8}
#else
	# h[0]-h[2] in r4-r6 for multiplication.
	str	r7, [lr, #12]
	str	r8, [lr, #16]
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	str	r1, [sp, #16]
	ldr	r1, [sp, #12]
	# Multiply h by r
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	# r0 = #0, r1 = r, lr = h, r2 = h[j], r3 = r[i]
	ldr	r3, [r1]
	eor	r0, r0, r0
	# r[0] * h[0]
	# h[0] in r4
	umull	r4, r5, r3, r4
	# r[0] * h[2]
	# h[2] in r6
	umull	r6, r7, r3, r6
	# r[0] * h[4]
	# h[4] in r8
	mul	r8, r3, r8
	# r[0] * h[1]
	ldr	r2, [lr, #4]
	mov	r12, r0
	umlal	r5, r12, r3, r2
	# r[0] * h[3]
	ldr	r2, [lr, #12]
	adds	r6, r6, r12
	adc	r7, r7, r0
	umlal	r7, r8, r3, r2
	# r[1] * h[0]
	ldr	r3, [r1, #4]
	ldr	r2, [lr]
	mov	r12, r0
	umlal	r5, r12, r3, r2
	# r[1] * h[1]
	ldr	r2, [lr, #4]
	adds	r6, r6, r12
	adc	r12, r0, r0
	umlal	r6, r12, r3, r2
	# r[1] * h[2]
	ldr	r2, [lr, #8]
	adds	r7, r7, r12
	adc	r12, r0, r0
	umlal	r7, r12, r3, r2
	# r[1] * h[3]
	ldr	r2, [lr, #12]
	adds	r8, r8, r12
	adc	r9, r0, r0
	umlal	r8, r9, r3, r2
	# r[1] * h[4]
	ldr	r2, [lr, #16]
	mla	r9, r3, r2, r9
	# r[2] * h[0]
	ldr	r3, [r1, #8]
	ldr	r2, [lr]
	mov	r12, r0
	umlal	r6, r12, r3, r2
	# r[2] * h[1]
	ldr	r2, [lr, #4]
	adds	r7, r7, r12
	adc	r12, r0, r0
	umlal	r7, r12, r3, r2
	# r[2] * h[2]
	ldr	r2, [lr, #8]
	adds	r8, r8, r12
	adc	r12, r0, r0
	umlal	r8, r12, r3, r2
	# r[2] * h[3]
	ldr	r2, [lr, #12]
	adds	r9, r9, r12
	adc	r10, r0, r0
	umlal	r9, r10, r3, r2
	# r[2] * h[4]
	ldr	r2, [lr, #16]
	mla	r10, r3, r2, r10
	# r[3] * h[0]
	ldr	r3, [r1, #12]
	ldr	r2, [lr]
	mov	r12, r0
	umlal	r7, r12, r3, r2
	# r[3] * h[1]
	ldr	r2, [lr, #4]
	adds	r8, r8, r12
	adc	r12, r0, r0
	umlal	r8, r12, r3, r2
	# r[3] * h[2]
	ldr	r2, [lr, #8]
	adds	r9, r9, r12
	adc	r10, r10, r0
	umlal	r9, r10, r3, r2
	# r[3] * h[3]
	ldr	r2, [lr, #12]
	mov	r11, r0
	umlal	r10, r11, r3, r2
	# r[3] * h[4]
	ldr	r2, [lr, #16]
	mov	r12, r0
	mla	r11, r3, r2, r11
#else
	ldm	r1, {r0, r1, r2, r3}
	# r[0] * h[0]
	umull	r10, r11, r0, r4
	# r[1] * h[0]
	umull	r12, r7, r1, r4
	# r[0] * h[1]
	umaal	r11, r12, r0, r5
	# r[2] * h[0]
	umull	r8, r9, r2, r4
	# r[1] * h[1]
	umaal	r12, r8, r1, r5
	# r[0] * h[2]
	umaal	r12, r7, r0, r6
	# r[3] * h[0]
	umaal	r8, r9, r3, r4
	stm	sp, {r10, r11, r12}
	# r[2] * h[1]
	umaal	r7, r8, r2, r5
	# Replace h[0] with h[3]
	ldr	r4, [lr, #12]
	# r[1] * h[2]
	umull	r10, r11, r1, r6
	# r[2] * h[2]
	umaal	r8, r9, r2, r6
	# r[0] * h[3]
	umaal	r7, r10, r0, r4
	# r[3] * h[1]
	umaal	r8, r11, r3, r5
	# r[1] * h[3]
	umaal	r8, r10, r1, r4
	# r[3] * h[2]
	umaal	r9, r11, r3, r6
	# r[2] * h[3]
	umaal	r9, r10, r2, r4
	# Replace h[1] with h[4]
	ldr	r5, [lr, #16]
	# r[3] * h[3]
	umaal	r10, r11, r3, r4
	mov	r12, #0
	# r[0] * h[4]
	umaal	r8, r12, r0, r5
	# r[1] * h[4]
	umaal	r9, r12, r1, r5
	# r[2] * h[4]
	umaal	r10, r12, r2, r5
	# r[3] * h[4]
	umaal	r11, r12, r3, r5
	# DONE
	ldm	sp, {r4, r5, r6}
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	# r12 will be zero because r is masked.
	# Load length
	ldr	r2, [sp, #20]
	# Reduce mod 2^130 - 5
	bic	r3, r8, #0x3
	and	r8, r8, #3
	adds	r4, r4, r3
	lsr	r3, r3, #2
	adcs	r5, r5, r9
	orr	r3, r3, r9, LSL #30
	adcs	r6, r6, r10
	lsr	r9, r9, #2
	adcs	r7, r7, r11
	orr	r9, r9, r10, LSL #30
	adc	r8, r8, r12
	lsr	r10, r10, #2
	adds	r4, r4, r3
	orr	r10, r10, r11, LSL #30
	adcs	r5, r5, r9
	lsr	r11, r11, #2
	adcs	r6, r6, r10
	adcs	r7, r7, r11
	adc	r8, r8, r12
	# Sub 16 from length.
	subs	r2, r2, #16
	# Store length.
	str	r2, [sp, #20]
	# Loop again if more message to do.
	bgt	L_poly1305_arm32_16_loop
	stm	lr, {r4, r5, r6, r7, r8}
L_poly1305_arm32_16_done:
	add	sp, sp, #28
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	poly1305_arm32_blocks_16,.-poly1305_arm32_blocks_16
	.text
	.align	4
	.globl	poly1305_arm32_blocks
	.type	poly1305_arm32_blocks, %function
poly1305_arm32_blocks:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	vpush	{d8-d15}
	cmp	r2, #16
	add	r12, r0, #16
	bgt	L_poly1305_arm32_blocks_begin_neon
	ldm	r12, {r7, r8, r9, r10, r11}
	b	L_poly1305_arm32_blocks_start_1
L_poly1305_arm32_blocks_begin_neon:
	vmov.i16	q15, #0xffff
	vshr.u64	q15, q15, #38
	vld1.64	{d0-d2}, [r12]
	vshl.u64	d4, d2, #24
	vsri.u64	d4, d1, #40
	vshr.u64	d3, d1, #14
	vshl.u64	d2, d1, #12
	vsri.u64	d1, d0, #26
	vsri.u64	d2, d0, #52
	vand.u64	d0, d0, d31
	vand.u64	d3, d3, d31
	vand.u64	d2, d2, d31
	vand.u64	d1, d1, d31
	add	r3, r0, #0x7c
	vldm.32	r3, {d20-d24}
	cmp	r2, #0x40
	bge	L_poly1305_arm32_blocks_begin_4
	vshl.u32	d6, d21, #2
	vshl.u32	d7, d22, #2
	vshl.u32	d8, d23, #2
	vshl.u32	d9, d24, #2
	vadd.u32	d6, d6, d21
	vadd.u32	d7, d7, d22
	vadd.u32	d8, d8, d23
	vadd.u32	d9, d9, d24
	b	L_poly1305_arm32_blocks_start_2
L_poly1305_arm32_blocks_begin_4:
	add	r3, r0, #0xa4
	vldm.32	r3, {d26-d30}
L_poly1305_arm32_blocks_start_4:
	sub	r2, #0x40
	vld4.32	{d10-d13}, [r1]!
	vshl.u32	d6, d27, #2
	vshl.u32	d7, d28, #2
	vshl.u32	d8, d29, #2
	vshl.u32	d9, d30, #2
	vadd.u32	d6, d6, d27
	vadd.u32	d7, d7, d28
	vadd.u32	d8, d8, d29
	vadd.u32	d9, d9, d30
	vshr.u32	d14, d13, #8
	vshl.u32	d13, d13, #18
	vorr.i32	d14, d14, #0x1000000
	vsri.u32	d13, d12, #14
	vshl.u32	d12, d12, #12
	vand.i32	d13, d13, #0x3ffffff
	vsri.u32	d12, d11, #20
	vshl.u32	d11, d11, #6
	vand.i32	d12, d12, #0x3ffffff
	vsri.u32	d11, d10, #26
	vand.i32	d10, d10, #0x3ffffff
	vand.i32	d11, d11, #0x3ffffff
	vadd.u32	d4, d4, d14
	vadd.u32	q1, q1, q6
	vadd.u32	q0, q0, q5
	vmull.u32	q5, d0, d26
	vmull.u32	q6, d0, d27
	vmull.u32	q7, d0, d28
	vmull.u32	q8, d0, d29
	vmull.u32	q9, d0, d30
	vmlal.u32	q5, d1, d9
	vmlal.u32	q6, d1, d26
	vmlal.u32	q7, d1, d27
	vmlal.u32	q8, d1, d28
	vmlal.u32	q9, d1, d29
	vmlal.u32	q5, d2, d8
	vmlal.u32	q6, d2, d9
	vmlal.u32	q7, d2, d26
	vmlal.u32	q8, d2, d27
	vmlal.u32	q9, d2, d28
	vmlal.u32	q5, d3, d7
	vmlal.u32	q6, d3, d8
	vmlal.u32	q7, d3, d9
	vmlal.u32	q8, d3, d26
	vmlal.u32	q9, d3, d27
	vmlal.u32	q5, d4, d6
	vmlal.u32	q6, d4, d7
	vmlal.u32	q7, d4, d8
	vmlal.u32	q8, d4, d9
	vmlal.u32	q9, d4, d26
	vld4.32	{d0-d3}, [r1]!
	vshl.u32	d6, d21, #2
	vshl.u32	d7, d22, #2
	vshl.u32	d8, d23, #2
	vshl.u32	d9, d24, #2
	vadd.u32	d6, d6, d21
	vadd.u32	d7, d7, d22
	vadd.u32	d8, d8, d23
	vadd.u32	d9, d9, d24
	vshr.u32	d4, d3, #8
	vshl.u32	d3, d3, #18
	vorr.i32	d4, d4, #0x1000000
	vsri.u32	d3, d2, #14
	vshl.u32	d2, d2, #12
	vand.i32	d3, d3, #0x3ffffff
	vsri.u32	d2, d1, #20
	vshl.u32	d1, d1, #6
	vand.i32	d2, d2, #0x3ffffff
	vsri.u32	d1, d0, #26
	vand.i32	d0, d0, #0x3ffffff
	vand.i32	d1, d1, #0x3ffffff
	vmlal.u32	q5, d0, d20
	vmlal.u32	q6, d0, d21
	vmlal.u32	q7, d0, d22
	vmlal.u32	q8, d0, d23
	vmlal.u32	q9, d0, d24
	vmlal.u32	q5, d1, d9
	vmlal.u32	q6, d1, d20
	vmlal.u32	q7, d1, d21
	vmlal.u32	q8, d1, d22
	vmlal.u32	q9, d1, d23
	vmlal.u32	q5, d2, d8
	vmlal.u32	q6, d2, d9
	vmlal.u32	q7, d2, d20
	vmlal.u32	q8, d2, d21
	vmlal.u32	q9, d2, d22
	vmlal.u32	q5, d3, d7
	vmlal.u32	q6, d3, d8
	vmlal.u32	q7, d3, d9
	vmlal.u32	q8, d3, d20
	vmlal.u32	q9, d3, d21
	vmlal.u32	q5, d4, d6
	vmlal.u32	q6, d4, d7
	vmlal.u32	q7, d4, d8
	vmlal.u32	q8, d4, d9
	vmlal.u32	q9, d4, d20
	vadd.u64	d0, d10, d11
	vadd.u64	d1, d12, d13
	vadd.u64	d2, d14, d15
	vadd.u64	d3, d16, d17
	vadd.u64	d4, d18, d19
	vsra.u64	d1, d0, #26
	vand.u64	d0, d0, d31
	vsra.u64	d2, d1, #26
	vand.u64	d1, d1, d31
	vsra.u64	d3, d2, #26
	vand.u64	d2, d2, d31
	vsra.u64	d4, d3, #26
	vand.u64	d3, d3, d31
	vshr.u64	d15, d4, #26
	vand.u64	d4, d4, d31
	vadd.u64	d0, d0, d15
	vshl.u64	d15, d15, #2
	vadd.u64	d0, d0, d15
	vsra.u64	d1, d0, #26
	vand.u64	d0, d0, d31
	cmp	r2, #0x40
	bge	L_poly1305_arm32_blocks_start_4
	cmp	r2, #32
	blt	L_poly1305_arm32_blocks_done_neon
L_poly1305_arm32_blocks_start_2:
	sub	r2, #32
	vld4.32	{d10-d13}, [r1]!
	vshr.u32	d14, d13, #8
	vshl.u32	d13, d13, #18
	vorr.i32	d14, d14, #0x1000000
	vsri.u32	d13, d12, #14
	vshl.u32	d12, d12, #12
	vand.i32	d13, d13, #0x3ffffff
	vsri.u32	d12, d11, #20
	vshl.u32	d11, d11, #6
	vand.i32	d12, d12, #0x3ffffff
	vsri.u32	d11, d10, #26
	vand.i32	d10, d10, #0x3ffffff
	vand.i32	d11, d11, #0x3ffffff
	vadd.u32	d4, d4, d14
	vadd.u32	q1, q1, q6
	vadd.u32	q0, q0, q5
	vmull.u32	q5, d0, d20
	vmull.u32	q6, d0, d21
	vmull.u32	q7, d0, d22
	vmull.u32	q8, d0, d23
	vmull.u32	q9, d0, d24
	vmlal.u32	q5, d1, d9
	vmlal.u32	q6, d1, d20
	vmlal.u32	q7, d1, d21
	vmlal.u32	q8, d1, d22
	vmlal.u32	q9, d1, d23
	vmlal.u32	q5, d2, d8
	vmlal.u32	q6, d2, d9
	vmlal.u32	q7, d2, d20
	vmlal.u32	q8, d2, d21
	vmlal.u32	q9, d2, d22
	vmlal.u32	q5, d3, d7
	vmlal.u32	q6, d3, d8
	vmlal.u32	q7, d3, d9
	vmlal.u32	q8, d3, d20
	vmlal.u32	q9, d3, d21
	vmlal.u32	q5, d4, d6
	vmlal.u32	q6, d4, d7
	vmlal.u32	q7, d4, d8
	vmlal.u32	q8, d4, d9
	vmlal.u32	q9, d4, d20
	vadd.u64	d0, d10, d11
	vadd.u64	d1, d12, d13
	vadd.u64	d2, d14, d15
	vadd.u64	d3, d16, d17
	vadd.u64	d4, d18, d19
	vsra.u64	d1, d0, #26
	vand.u64	d0, d0, d31
	vsra.u64	d2, d1, #26
	vand.u64	d1, d1, d31
	vsra.u64	d3, d2, #26
	vand.u64	d2, d2, d31
	vsra.u64	d4, d3, #26
	vand.u64	d3, d3, d31
	vshr.u64	d5, d4, #26
	vand.u64	d4, d4, d31
	vadd.u64	d0, d0, d5
	vshl.u64	d5, d5, #2
	vadd.u64	d0, d0, d5
	vsra.u64	d1, d0, #26
	vand.u64	d0, d0, d31
L_poly1305_arm32_blocks_done_neon:
	cmp	r2, #16
	beq	L_poly1305_arm32_blocks_begin_1
	add	r12, r0, #16
	vsli.u64	d0, d1, #26
	vsli.u64	d0, d2, #52
	vshr.u64	d1, d2, #12
	vsli.u64	d1, d3, #14
	vsli.u64	d1, d4, #40
	vshr.u64	d2, d4, #24
	vst1.64	{d0-d2}, [r12]
	b	L_poly1305_arm32_blocks_done
L_poly1305_arm32_blocks_begin_1:
	vsli.u64	d0, d1, #26
	vsli.u64	d0, d2, #52
	vshr.u64	d1, d2, #12
	vsli.u64	d1, d3, #14
	vsli.u64	d1, d4, #40
	vshr.u64	d2, d4, #24
	vmov	r7, r8, d0
	vmov	r9, r10, d1
	vmov	r11, d2[0]
L_poly1305_arm32_blocks_start_1:
	mov	r12, #1
	push	{r2}
	# Load message
	ldr	r2, [r1]
	ldr	r3, [r1, #4]
	ldr	r4, [r1, #8]
	ldr	r5, [r1, #12]
	# Add message
	adds	r7, r7, r2
	adcs	r8, r8, r3
	adcs	r9, r9, r4
	adcs	r10, r10, r5
	adc	r11, r11, r12
	push	{r0, r1}
	add	r1, r0, #0
	add	lr, r0, #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	stm	lr, {r7, r8, r9, r10, r11}
#else
	# h[0]-h[2] in r4-r6 for multiplication.
	str	r10, [lr, #12]
	str	r11, [lr, #16]
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	# r0 = #0, r1 = r, lr = h, r2 = h[j], r3 = r[i]
	ldr	r3, [r1]
	eor	r0, r0, r0
	# r[0] * h[0]
	# h[0] in r4
	umull	r7, r8, r3, r7
	# r[0] * h[2]
	# h[2] in r6
	umull	r9, r10, r3, r9
	# r[0] * h[4]
	# h[4] in r8
	mul	r11, r3, r11
	# r[0] * h[1]
	ldr	r2, [lr, #4]
	mov	r12, r0
	umlal	r8, r12, r3, r2
	# r[0] * h[3]
	ldr	r2, [lr, #12]
	adds	r9, r9, r12
	adc	r10, r10, r0
	umlal	r10, r11, r3, r2
	# r[1] * h[0]
	ldr	r3, [r1, #4]
	ldr	r2, [lr]
	mov	r12, r0
	umlal	r8, r12, r3, r2
	# r[1] * h[1]
	ldr	r2, [lr, #4]
	adds	r9, r9, r12
	adc	r12, r0, r0
	umlal	r9, r12, r3, r2
	# r[1] * h[2]
	ldr	r2, [lr, #8]
	adds	r10, r10, r12
	adc	r12, r0, r0
	umlal	r10, r12, r3, r2
	# r[1] * h[3]
	ldr	r2, [lr, #12]
	adds	r11, r11, r12
	adc	r4, r0, r0
	umlal	r11, r4, r3, r2
	# r[1] * h[4]
	ldr	r2, [lr, #16]
	mla	r4, r3, r2, r4
	# r[2] * h[0]
	ldr	r3, [r1, #8]
	ldr	r2, [lr]
	mov	r12, r0
	umlal	r9, r12, r3, r2
	# r[2] * h[1]
	ldr	r2, [lr, #4]
	adds	r10, r10, r12
	adc	r12, r0, r0
	umlal	r10, r12, r3, r2
	# r[2] * h[2]
	ldr	r2, [lr, #8]
	adds	r11, r11, r12
	adc	r12, r0, r0
	umlal	r11, r12, r3, r2
	# r[2] * h[3]
	ldr	r2, [lr, #12]
	adds	r4, r4, r12
	adc	r5, r0, r0
	umlal	r4, r5, r3, r2
	# r[2] * h[4]
	ldr	r2, [lr, #16]
	mla	r5, r3, r2, r5
	# r[3] * h[0]
	ldr	r3, [r1, #12]
	ldr	r2, [lr]
	mov	r12, r0
	umlal	r10, r12, r3, r2
	# r[3] * h[1]
	ldr	r2, [lr, #4]
	adds	r11, r11, r12
	adc	r12, r0, r0
	umlal	r11, r12, r3, r2
	# r[3] * h[2]
	ldr	r2, [lr, #8]
	adds	r4, r4, r12
	adc	r5, r5, r0
	umlal	r4, r5, r3, r2
	# r[3] * h[3]
	ldr	r2, [lr, #12]
	mov	r6, r0
	umlal	r5, r6, r3, r2
	# r[3] * h[4]
	ldr	r2, [lr, #16]
	mov	r12, r0
	mla	r6, r3, r2, r6
#else
	sub	sp, sp, #12
	ldm	r1, {r0, r1, r2, r3}
	# r[0] * h[0]
	umull	r5, r6, r0, r7
	# r[1] * h[0]
	umull	r12, r10, r1, r7
	# r[0] * h[1]
	umaal	r6, r12, r0, r8
	# r[2] * h[0]
	umull	r11, r4, r2, r7
	# r[1] * h[1]
	umaal	r12, r11, r1, r8
	# r[0] * h[2]
	umaal	r12, r10, r0, r9
	# r[3] * h[0]
	umaal	r11, r4, r3, r7
	stm	sp, {r5, r6, r12}
	# r[2] * h[1]
	umaal	r10, r11, r2, r8
	# Replace h[0] with h[3]
	ldr	r7, [lr, #12]
	# r[1] * h[2]
	umull	r5, r6, r1, r9
	# r[2] * h[2]
	umaal	r11, r4, r2, r9
	# r[0] * h[3]
	umaal	r10, r5, r0, r7
	# r[3] * h[1]
	umaal	r11, r6, r3, r8
	# r[1] * h[3]
	umaal	r11, r5, r1, r7
	# r[3] * h[2]
	umaal	r4, r6, r3, r9
	# r[2] * h[3]
	umaal	r4, r5, r2, r7
	# Replace h[1] with h[4]
	ldr	r8, [lr, #16]
	# r[3] * h[3]
	umaal	r5, r6, r3, r7
	mov	r12, #0
	# r[0] * h[4]
	umaal	r11, r12, r0, r8
	# r[1] * h[4]
	umaal	r4, r12, r1, r8
	# r[2] * h[4]
	umaal	r5, r12, r2, r8
	# r[3] * h[4]
	umaal	r6, r12, r3, r8
	# DONE
	ldm	sp, {r7, r8, r9}
	add	sp, sp, #12
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	# Reduce mod 2^130 - 5
	bic	r3, r11, #0x3
	and	r11, r11, #3
	adds	r7, r7, r3
	lsr	r3, r3, #2
	adcs	r8, r8, r4
	orr	r3, r3, r4, LSL #30
	adcs	r9, r9, r5
	lsr	r4, r4, #2
	adcs	r10, r10, r6
	orr	r4, r4, r5, LSL #30
	adc	r11, r11, r12
	lsr	r5, r5, #2
	adds	r7, r7, r3
	orr	r5, r5, r6, LSL #30
	adcs	r8, r8, r4
	lsr	r6, r6, #2
	adcs	r9, r9, r5
	adcs	r10, r10, r6
	adc	r11, r11, r12
	pop	{r0, r1}
	pop	{r2}
	add	r12, r0, #16
	stm	r12, {r7, r8, r9, r10, r11}
L_poly1305_arm32_blocks_done:
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	poly1305_arm32_blocks,.-poly1305_arm32_blocks
	.text
	.type	L_poly1305_arm32_clamp, %object
	.size	L_poly1305_arm32_clamp, 16
	.align	4
L_poly1305_arm32_clamp:
	.word	0xfffffff
	.word	0xffffffc
	.word	0xffffffc
	.word	0xffffffc
	.text
	.align	4
	.globl	poly1305_set_key
	.type	poly1305_set_key, %function
poly1305_set_key:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	vpush	{d8-d15}
	# Load mask.
	adr	lr, L_poly1305_arm32_clamp
	ldm	lr, {r6, r7, r8, r9}
	# Load and cache padding.
	ldr	r2, [r1, #16]
	ldr	r3, [r1, #20]
	ldr	r4, [r1, #24]
	ldr	r5, [r1, #28]
	add	lr, r0, #40
	stm	lr, {r2, r3, r4, r5}
	# Load, mask and store r.
	ldr	r2, [r1]
	ldr	r3, [r1, #4]
	ldr	r4, [r1, #8]
	ldr	r5, [r1, #12]
	and	r2, r2, r6
	and	r3, r3, r7
	and	r4, r4, r8
	and	r5, r5, r9
	add	lr, r0, #0
	stm	lr, {r2, r3, r4, r5}
	vmov.i16	q10, #0xffff
	vshr.u64	q10, q10, #38
	lsr	r8, r2, #26
	lsr	r9, r3, #20
	lsr	r10, r4, #14
	lsr	r11, r5, #8
	eor	r8, r8, r3, lsl #6
	eor	r9, r9, r4, lsl #12
	eor	r10, r10, r5, lsl #18
	and	r7, r2, #0x3ffffff
	and	r8, r8, #0x3ffffff
	and	r9, r9, #0x3ffffff
	and	r10, r10, #0x3ffffff
	vmov.i32	s1, r7
	vmov.i32	s3, r8
	vmov.i32	s5, r9
	vmov.i32	s7, r10
	vmov.i32	s9, r11
	push	{r0, r1}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	# Square r
	umull	r1, r6, r2, r3
	mov	r12, #0
	umull	r7, r8, r2, r5
	mov	lr, r12
	umlal	r6, lr, r2, r4
	adds	r7, r7, lr
	adc	lr, r12, r12
	umlal	r7, lr, r3, r4
	mov	r9, r12
	umlal	lr, r9, r3, r5
	adds	r8, r8, lr
	adcs	r9, r9, r12
	adc	r10, r12, r12
	umlal	r9, r10, r4, r5
	adds	r1, r1, r1
	adcs	r6, r6, r6
	adcs	r7, r7, r7
	adcs	r8, r8, r8
	adcs	r9, r9, r9
	adcs	r10, r10, r10
	adc	r11, r12, r12
	umull	r0, lr, r2, r2
	adds	r1, r1, lr
	adcs	r6, r6, r12
	adc	lr, r12, r12
	umlal	r6, lr, r3, r3
	adds	r7, r7, lr
	adcs	r8, r8, r12
	adc	lr, r12, r12
	umlal	r8, lr, r4, r4
	adds	r9, r9, lr
	adcs	r10, r10, r12
	adc	r11, r11, r12
	umlal	r10, r11, r5, r5
#else
	umull	r0, r1, r2, r2
	umull	r6, r7, r2, r3
	adds	r6, r6, r6
	mov	r12, #0
	umaal	r1, r6, r12, r12
	mov	r8, r12
	umaal	r8, r7, r2, r4
	adcs	r8, r8, r8
	umaal	r6, r8, r3, r3
	umull	r9, r10, r2, r5
	umaal	r7, r9, r3, r4
	adcs	r7, r7, r7
	umaal	r7, r8, r12, r12
	umaal	r10, r9, r3, r5
	adcs	r10, r10, r10
	umaal	r8, r10, r4, r4
	mov	r11, r12
	umaal	r9, r11, r4, r5
	adcs	r9, r9, r9
	umaal	r9, r10, r12, r12
	adcs	r11, r11, r11
	umaal	r10, r11, r5, r5
	adc	r11, r11, r12
#endif /* defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6) */
	# Reduce mod 2^130 - 5
	bic	r2, r8, #0x3
	and	r8, r8, #3
	adds	r0, r0, r2
	lsr	r2, r2, #2
	adcs	r1, r1, r9
	orr	r2, r2, r9, LSL #30
	adcs	r6, r6, r10
	lsr	r9, r9, #2
	adcs	r7, r7, r11
	orr	r9, r9, r10, LSL #30
	adc	r8, r8, r12
	lsr	r10, r10, #2
	adds	r0, r0, r2
	orr	r10, r10, r11, LSL #30
	adcs	r1, r1, r9
	lsr	r11, r11, #2
	adcs	r6, r6, r10
	adcs	r7, r7, r11
	adc	r8, r8, r12
	lsr	r3, r0, #26
	lsr	r4, r1, #20
	lsr	r5, r6, #14
	lsr	r10, r7, #8
	eor	r3, r3, r1, lsl #6
	eor	r4, r4, r6, lsl #12
	eor	r5, r5, r7, lsl #18
	eor	r10, r10, r8, lsl #24
	and	r2, r0, #0x3ffffff
	and	r3, r3, #0x3ffffff
	and	r4, r4, #0x3ffffff
	and	r5, r5, #0x3ffffff
	vmov.i32	s0, r2
	vmov.i32	s2, r3
	vmov.i32	s4, r4
	vmov.i32	s6, r5
	vmov.i32	s8, r10
	pop	{r0, r1}
	add	lr, r0, #0x7c
	vstm.32	lr, {d0-d4}
	# Multiply r^2, r by r^2
	vshl.u32	d6, d1, #2
	vshl.u32	d7, d2, #2
	vshl.u32	d8, d3, #2
	vshl.u32	d9, d4, #2
	vadd.u32	d6, d6, d1
	vadd.u32	d7, d7, d2
	vadd.u32	d8, d8, d3
	vadd.u32	d9, d9, d4
	vmull.u32	q5, d0, d0[0]
	vmull.u32	q6, d0, d1[0]
	vmull.u32	q7, d0, d2[0]
	vmull.u32	q8, d0, d3[0]
	vmull.u32	q9, d0, d4[0]
	vmlal.u32	q5, d1, d9[0]
	vmlal.u32	q6, d1, d0[0]
	vmlal.u32	q7, d1, d1[0]
	vmlal.u32	q8, d1, d2[0]
	vmlal.u32	q9, d1, d3[0]
	vmlal.u32	q5, d2, d8[0]
	vmlal.u32	q6, d2, d9[0]
	vmlal.u32	q7, d2, d0[0]
	vmlal.u32	q8, d2, d1[0]
	vmlal.u32	q9, d2, d2[0]
	vmlal.u32	q5, d3, d7[0]
	vmlal.u32	q6, d3, d8[0]
	vmlal.u32	q7, d3, d9[0]
	vmlal.u32	q8, d3, d0[0]
	vmlal.u32	q9, d3, d1[0]
	vmlal.u32	q5, d4, d6[0]
	vmlal.u32	q6, d4, d7[0]
	vmlal.u32	q7, d4, d8[0]
	vmlal.u32	q8, d4, d9[0]
	vmlal.u32	q9, d4, d0[0]
	vsra.u64	q6, q5, #26
	vand.u64	q5, q5, q10
	vsra.u64	q7, q6, #26
	vand.u64	q6, q6, q10
	vsra.u64	q8, q7, #26
	vand.u64	q7, q7, q10
	vsra.u64	q9, q8, #26
	vand.u64	q8, q8, q10
	vshr.u64	q3, q9, #26
	vand.u64	q9, q9, q10
	vadd.u64	q5, q5, q3
	vshl.u64	q3, q3, #2
	vadd.u64	q5, q5, q3
	vsra.u64	q6, q5, #26
	vand.u64	q5, q5, q10
	vmovn.i64	d10, q5
	vmovn.i64	d11, q6
	vmovn.i64	d12, q7
	vmovn.i64	d13, q8
	vmovn.i64	d14, q9
	add	lr, r0, #0xa4
	vstm.32	lr, {d10-d14}
	# h (accumulator) = 0
	eor	r6, r6, r6
	eor	r7, r7, r7
	eor	r8, r8, r8
	eor	r9, r9, r9
	add	lr, r0, #16
	eor	r4, r4, r4
	eor	r5, r5, r5
	stm	lr, {r4, r5, r6, r7, r8, r9}
	# Zero leftover
	str	r5, [r0, #56]
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	poly1305_set_key,.-poly1305_set_key
	.text
	.align	4
	.globl	poly1305_final
	.type	poly1305_final, %function
poly1305_final:
	push	{r4, r5, r6, r7, r8, r9, lr}
	add	r9, r0, #16
	ldm	r9, {r4, r5, r6, r7, r8}
	# Add 5 and check for h larger than p.
	adds	r2, r4, #5
	adcs	r2, r5, #0
	adcs	r2, r6, #0
	adcs	r2, r7, #0
	adc	r2, r8, #0
	sub	r2, r2, #4
	lsr	r2, r2, #31
	sub	r2, r2, #1
	and	r2, r2, #5
	# Add 0/5 to h.
	adds	r4, r4, r2
	adcs	r5, r5, #0
	adcs	r6, r6, #0
	adc	r7, r7, #0
	# Add padding
	add	r9, r0, #40
	ldm	r9, {r2, r3, r12, lr}
	adds	r4, r4, r2
	adcs	r5, r5, r3
	adcs	r6, r6, r12
	adc	r7, r7, lr
	# Store MAC
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	# Zero out h.
	eor	r4, r4, r4
	eor	r5, r5, r5
	eor	r6, r6, r6
	eor	r7, r7, r7
	eor	r8, r8, r8
	add	r9, r0, #16
	stm	r9, {r4, r5, r6, r7, r8}
	# Zero out r.
	add	r9, r0, #0
	stm	r9, {r4, r5, r6, r7}
	# Zero out padding.
	add	r9, r0, #40
	stm	r9, {r4, r5, r6, r7}
	pop	{r4, r5, r6, r7, r8, r9, pc}
	.size	poly1305_final,.-poly1305_final
#endif /* WOLFSSL_ARMASM_NO_NEON */
#endif /* HAVE_POLY1305 */
#endif /* !__aarch64__ && !WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
