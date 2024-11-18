/* armv8-32-poly1305-asm
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
 *   ruby ./poly1305/poly1305.rb arm32 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-32-poly1305-asm.S
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_ARMASM
#if !defined(__aarch64__) && !defined(WOLFSSL_ARMASM_THUMB2)
#ifndef WOLFSSL_ARMASM_INLINE
#ifdef HAVE_POLY1305
	.text
	.align	4
	.globl	poly1305_blocks_arm32_16
	.type	poly1305_blocks_arm32_16, %function
poly1305_blocks_arm32_16:
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
	.size	poly1305_blocks_arm32_16,.-poly1305_blocks_arm32_16
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
#endif /* HAVE_POLY1305 */
#endif /* !__aarch64__ && !WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
