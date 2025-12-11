/* armv8-32-chacha-asm
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
 *   ruby ./chacha/chacha.rb arm32 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-32-chacha-asm.S
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

#ifdef WOLFSSL_ARMASM
#if !defined(__aarch64__) && !defined(WOLFSSL_ARMASM_THUMB2)
#ifndef WOLFSSL_ARMASM_INLINE
#ifdef HAVE_CHACHA
	.text
	.align	4
	.globl	wc_chacha_setiv
	.type	wc_chacha_setiv, %function
wc_chacha_setiv:
	push	{r4, lr}
	add	r3, r0, #52
	ldr	r4, [r1]
	ldr	r12, [r1, #4]
	ldr	lr, [r1, #8]
	str	r2, [r0, #48]
#ifdef BIG_ENDIAN_ORDER
	rev	r4, r4
	rev	r12, r12
	rev	lr, lr
#endif /* BIG_ENDIAN_ORDER */
	stm	r3, {r4, r12, lr}
	pop	{r4, pc}
	.size	wc_chacha_setiv,.-wc_chacha_setiv
#ifdef WOLFSSL_ARMASM_NO_NEON
	.text
	.type	L_chacha_arm32_constants, %object
	.size	L_chacha_arm32_constants, 32
	.align	4
L_chacha_arm32_constants:
	.word	0x61707865
	.word	0x3120646e
	.word	0x79622d36
	.word	0x6b206574
	.word	0x61707865
	.word	0x3320646e
	.word	0x79622d32
	.word	0x6b206574
	.text
	.align	4
	.globl	wc_chacha_setkey
	.type	wc_chacha_setkey, %function
wc_chacha_setkey:
	push	{r4, r5, lr}
	adr	r3, L_chacha_arm32_constants
	subs	r2, r2, #16
	add	r3, r3, r2
	# Start state with constants
	ldm	r3, {r4, r5, r12, lr}
	stm	r0!, {r4, r5, r12, lr}
	# Next is first 16 bytes of key.
	ldr	r4, [r1]
	ldr	r5, [r1, #4]
	ldr	r12, [r1, #8]
	ldr	lr, [r1, #12]
#ifdef BIG_ENDIAN_ORDER
	rev	r4, r4
	rev	r5, r5
	rev	r12, r12
	rev	lr, lr
#endif /* BIG_ENDIAN_ORDER */
	stm	r0!, {r4, r5, r12, lr}
	# Next 16 bytes of key.
	beq	L_chacha_arm32_setkey_same_keyb_ytes
	# Update key pointer for next 16 bytes.
	add	r1, r1, r2
	ldr	r4, [r1]
	ldr	r5, [r1, #4]
	ldr	r12, [r1, #8]
	ldr	lr, [r1, #12]
L_chacha_arm32_setkey_same_keyb_ytes:
	stm	r0, {r4, r5, r12, lr}
	pop	{r4, r5, pc}
	.size	wc_chacha_setkey,.-wc_chacha_setkey
	.text
	.align	4
	.globl	wc_chacha_crypt_bytes
	.type	wc_chacha_crypt_bytes, %function
wc_chacha_crypt_bytes:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #52
	mov	lr, r0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r0, [sp, #32]
	str	r1, [sp, #36]
#else
	strd	r0, r1, [sp, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r2, [sp, #40]
	str	r3, [sp, #44]
#else
	strd	r2, r3, [sp, #40]
#endif
L_chacha_arm32_crypt_block:
	# Put x[12]..x[15] onto stack.
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [lr, #48]
	ldr	r5, [lr, #52]
#else
	ldrd	r4, r5, [lr, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [lr, #56]
	ldr	r7, [lr, #60]
#else
	ldrd	r6, r7, [lr, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #16]
	str	r5, [sp, #20]
#else
	strd	r4, r5, [sp, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [sp, #24]
	str	r7, [sp, #28]
#else
	strd	r6, r7, [sp, #24]
#endif
	# Load x[0]..x[12] into registers.
	ldm	lr, {r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12}
	# 10x 2 full rounds to perform.
	mov	lr, #10
	str	lr, [sp, #48]
L_chacha_arm32_crypt_loop:
	# 0, 4,  8, 12
	# 1, 5,  9, 13
	ldr	lr, [sp, #20]
	add	r0, r0, r4
	add	r1, r1, r5
	eor	r12, r12, r0
	eor	lr, lr, r1
	ror	r12, r12, #16
	ror	lr, lr, #16
	add	r8, r8, r12
	add	r9, r9, lr
	eor	r4, r4, r8
	eor	r5, r5, r9
	ror	r4, r4, #20
	ror	r5, r5, #20
	add	r0, r0, r4
	add	r1, r1, r5
	eor	r12, r12, r0
	eor	lr, lr, r1
	ror	r12, r12, #24
	ror	lr, lr, #24
	add	r8, r8, r12
	add	r9, r9, lr
	eor	r4, r4, r8
	eor	r5, r5, r9
	ror	r4, r4, #25
	ror	r5, r5, #25
	str	r12, [sp, #16]
	str	lr, [sp, #20]
	# 2, 6, 10, 14
	# 3, 7, 11, 15
	ldr	r12, [sp, #24]
	ldr	lr, [sp, #28]
	add	r2, r2, r6
	add	r3, r3, r7
	eor	r12, r12, r2
	eor	lr, lr, r3
	ror	r12, r12, #16
	ror	lr, lr, #16
	add	r10, r10, r12
	add	r11, r11, lr
	eor	r6, r6, r10
	eor	r7, r7, r11
	ror	r6, r6, #20
	ror	r7, r7, #20
	add	r2, r2, r6
	add	r3, r3, r7
	eor	r12, r12, r2
	eor	lr, lr, r3
	ror	r12, r12, #24
	ror	lr, lr, #24
	add	r10, r10, r12
	add	r11, r11, lr
	eor	r6, r6, r10
	eor	r7, r7, r11
	ror	r6, r6, #25
	ror	r7, r7, #25
	# 3, 4,  9, 14
	# 0, 5, 10, 15
	add	r3, r3, r4
	add	r0, r0, r5
	eor	r12, r12, r3
	eor	lr, lr, r0
	ror	r12, r12, #16
	ror	lr, lr, #16
	add	r9, r9, r12
	add	r10, r10, lr
	eor	r4, r4, r9
	eor	r5, r5, r10
	ror	r4, r4, #20
	ror	r5, r5, #20
	add	r3, r3, r4
	add	r0, r0, r5
	eor	r12, r12, r3
	eor	lr, lr, r0
	ror	r12, r12, #24
	ror	lr, lr, #24
	add	r9, r9, r12
	add	r10, r10, lr
	eor	r4, r4, r9
	eor	r5, r5, r10
	ror	r4, r4, #25
	ror	r5, r5, #25
	str	r12, [sp, #24]
	str	lr, [sp, #28]
	ldr	r12, [sp, #16]
	ldr	lr, [sp, #20]
	# 1, 6, 11, 12
	# 2, 7,  8, 13
	add	r1, r1, r6
	add	r2, r2, r7
	eor	r12, r12, r1
	eor	lr, lr, r2
	ror	r12, r12, #16
	ror	lr, lr, #16
	add	r11, r11, r12
	add	r8, r8, lr
	eor	r6, r6, r11
	eor	r7, r7, r8
	ror	r6, r6, #20
	ror	r7, r7, #20
	add	r1, r1, r6
	add	r2, r2, r7
	eor	r12, r12, r1
	eor	lr, lr, r2
	ror	r12, r12, #24
	ror	lr, lr, #24
	add	r11, r11, r12
	add	r8, r8, lr
	eor	r6, r6, r11
	eor	r7, r7, r8
	ror	r6, r6, #25
	ror	r7, r7, #25
	str	lr, [sp, #20]
	# Check if we have done enough rounds.
	ldr	lr, [sp, #48]
	subs	lr, lr, #1
	str	lr, [sp, #48]
	bgt	L_chacha_arm32_crypt_loop
	stm	sp, {r8, r9, r10, r11, r12}
	ldr	lr, [sp, #32]
	mov	r12, sp
	# Add in original state
	ldm	lr!, {r8, r9, r10, r11}
	add	r0, r0, r8
	add	r1, r1, r9
	add	r2, r2, r10
	add	r3, r3, r11
	ldm	lr!, {r8, r9, r10, r11}
	add	r4, r4, r8
	add	r5, r5, r9
	add	r6, r6, r10
	add	r7, r7, r11
	ldm	r12, {r8, r9}
	ldm	lr!, {r10, r11}
	add	r8, r8, r10
	add	r9, r9, r11
	stm	r12!, {r8, r9}
	ldm	r12, {r8, r9}
	ldm	lr!, {r10, r11}
	add	r8, r8, r10
	add	r9, r9, r11
	stm	r12!, {r8, r9}
	ldm	r12, {r8, r9}
	ldm	lr!, {r10, r11}
	add	r8, r8, r10
	add	r9, r9, r11
	add	r10, r10, #1
	stm	r12!, {r8, r9}
	str	r10, [lr, #-8]
	ldm	r12, {r8, r9}
	ldm	lr, {r10, r11}
	add	r8, r8, r10
	add	r9, r9, r11
	stm	r12, {r8, r9}
	ldr	r12, [sp, #44]
	cmp	r12, #0x40
	blt	L_chacha_arm32_crypt_lt_block
	ldr	r12, [sp, #40]
	ldr	lr, [sp, #36]
	# XOR state into 64 bytes.
	ldr	r8, [r12]
	ldr	r9, [r12, #4]
	ldr	r10, [r12, #8]
	ldr	r11, [r12, #12]
	eor	r0, r0, r8
	eor	r1, r1, r9
	eor	r2, r2, r10
	eor	r3, r3, r11
	str	r0, [lr]
	str	r1, [lr, #4]
	str	r2, [lr, #8]
	str	r3, [lr, #12]
	ldr	r8, [r12, #16]
	ldr	r9, [r12, #20]
	ldr	r10, [r12, #24]
	ldr	r11, [r12, #28]
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	str	r4, [lr, #16]
	str	r5, [lr, #20]
	str	r6, [lr, #24]
	str	r7, [lr, #28]
	ldr	r4, [sp]
	ldr	r5, [sp, #4]
	ldr	r6, [sp, #8]
	ldr	r7, [sp, #12]
	ldr	r8, [r12, #32]
	ldr	r9, [r12, #36]
	ldr	r10, [r12, #40]
	ldr	r11, [r12, #44]
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	str	r4, [lr, #32]
	str	r5, [lr, #36]
	str	r6, [lr, #40]
	str	r7, [lr, #44]
	ldr	r4, [sp, #16]
	ldr	r5, [sp, #20]
	ldr	r6, [sp, #24]
	ldr	r7, [sp, #28]
	ldr	r8, [r12, #48]
	ldr	r9, [r12, #52]
	ldr	r10, [r12, #56]
	ldr	r11, [r12, #60]
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	str	r4, [lr, #48]
	str	r5, [lr, #52]
	str	r6, [lr, #56]
	str	r7, [lr, #60]
	ldr	r3, [sp, #44]
	add	r12, r12, #0x40
	add	lr, lr, #0x40
	str	r12, [sp, #40]
	str	lr, [sp, #36]
	subs	r3, r3, #0x40
	ldr	lr, [sp, #32]
	str	r3, [sp, #44]
	bne	L_chacha_arm32_crypt_block
	b	L_chacha_arm32_crypt_done
L_chacha_arm32_crypt_lt_block:
	# Store in over field of ChaCha.
	ldr	lr, [sp, #32]
	add	r12, lr, #0x44
	stm	r12!, {r0, r1, r2, r3, r4, r5, r6, r7}
	ldm	sp, {r0, r1, r2, r3, r4, r5, r6, r7}
	stm	r12, {r0, r1, r2, r3, r4, r5, r6, r7}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [sp, #40]
	ldr	r3, [sp, #44]
#else
	ldrd	r2, r3, [sp, #40]
#endif
	ldr	r1, [sp, #36]
	rsb	r12, r3, #0x40
	str	r12, [lr, #64]
	add	lr, lr, #0x44
L_chacha_arm32_crypt_16byte_loop:
	cmp	r3, #16
	blt	L_chacha_arm32_crypt_word_loop
	# 16 bytes of state XORed into message.
	ldm	lr!, {r4, r5, r6, r7}
	ldr	r8, [r2]
	ldr	r9, [r2, #4]
	ldr	r10, [r2, #8]
	ldr	r11, [r2, #12]
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	subs	r3, r3, #16
	str	r8, [r1]
	str	r9, [r1, #4]
	str	r10, [r1, #8]
	str	r11, [r1, #12]
	beq	L_chacha_arm32_crypt_done
	add	r2, r2, #16
	add	r1, r1, #16
	b	L_chacha_arm32_crypt_16byte_loop
L_chacha_arm32_crypt_word_loop:
	cmp	r3, #4
	blt	L_chacha_arm32_crypt_byte_start
	# 4 bytes of state XORed into message.
	ldr	r4, [lr]
	ldr	r8, [r2]
	eor	r8, r8, r4
	subs	r3, r3, #4
	str	r8, [r1]
	beq	L_chacha_arm32_crypt_done
	add	lr, lr, #4
	add	r2, r2, #4
	add	r1, r1, #4
	b	L_chacha_arm32_crypt_word_loop
L_chacha_arm32_crypt_byte_start:
	ldr	r4, [lr]
L_chacha_arm32_crypt_byte_loop:
	ldrb	r8, [r2]
	eor	r8, r8, r4
	subs	r3, r3, #1
	strb	r8, [r1]
	beq	L_chacha_arm32_crypt_done
	lsr	r4, r4, #8
	add	r2, r2, #1
	add	r1, r1, #1
	b	L_chacha_arm32_crypt_byte_loop
L_chacha_arm32_crypt_done:
	add	sp, sp, #52
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_chacha_crypt_bytes,.-wc_chacha_crypt_bytes
	.text
	.align	4
	.globl	wc_chacha_use_over
	.type	wc_chacha_use_over, %function
wc_chacha_use_over:
	push	{r4, r5, r6, r7, r8, r9, lr}
L_chacha_arm32_over_16byte_loop:
	cmp	r3, #16
	blt	L_chacha_arm32_over_word_loop
	# 16 bytes of state XORed into message.
	ldr	r12, [r0]
	ldr	lr, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
	ldr	r6, [r2]
	ldr	r7, [r2, #4]
	ldr	r8, [r2, #8]
	ldr	r9, [r2, #12]
	eor	r12, r12, r6
	eor	lr, lr, r7
	eor	r4, r4, r8
	eor	r5, r5, r9
	subs	r3, r3, #16
	str	r12, [r1]
	str	lr, [r1, #4]
	str	r4, [r1, #8]
	str	r5, [r1, #12]
	beq	L_chacha_arm32_over_done
	add	r0, r0, #16
	add	r2, r2, #16
	add	r1, r1, #16
	b	L_chacha_arm32_over_16byte_loop
L_chacha_arm32_over_word_loop:
	cmp	r3, #4
	blt	L_chacha_arm32_over_byte_loop
	# 4 bytes of state XORed into message.
	ldr	r12, [r0]
	ldr	r6, [r2]
	eor	r12, r12, r6
	subs	r3, r3, #4
	str	r12, [r1]
	beq	L_chacha_arm32_over_done
	add	r0, r0, #4
	add	r2, r2, #4
	add	r1, r1, #4
	b	L_chacha_arm32_over_word_loop
L_chacha_arm32_over_byte_loop:
	# 4 bytes of state XORed into message.
	ldrb	r12, [r0]
	ldrb	r6, [r2]
	eor	r12, r12, r6
	subs	r3, r3, #1
	strb	r12, [r1]
	beq	L_chacha_arm32_over_done
	add	r0, r0, #1
	add	r2, r2, #1
	add	r1, r1, #1
	b	L_chacha_arm32_over_byte_loop
L_chacha_arm32_over_done:
	pop	{r4, r5, r6, r7, r8, r9, pc}
	.size	wc_chacha_use_over,.-wc_chacha_use_over
#endif /* WOLFSSL_ARMASM_NO_NEON */
#ifndef WOLFSSL_ARMASM_NO_NEON
	.text
	.align	4
	.globl	wc_chacha_crypt_bytes
	.type	wc_chacha_crypt_bytes, %function
wc_chacha_crypt_bytes:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	vpush	{d8-d15}
	sub	sp, sp, #44
	# Load state to encrypt
	vldm.32	r0, {q12-q15}
	cmp	r3, #0x100
	blt	L_chacha_crypt_bytes_arm32_lt_256
	str	r0, [sp, #28]
L_chacha_crypt_bytes_arm32_start_256:
	str	r2, [sp, #32]
	str	r1, [sp, #36]
	str	r3, [sp, #40]
	# Move state into regular register
	vmov	r1, r3, d29
	vmov	r8, r9, d28
	stm	sp, {r1, r3}
	vmov	r12, lr, d31
	vmov	r10, r11, d30
	str	lr, [sp, #8]
	vmov	r0, r2, d24
	vmov	r1, r3, d25
	vmov	r4, r5, d26
	vmov	r6, r7, d27
	# Move state into vector registers
	vmov	q0, q12
	vmov	q1, q13
	add	lr, r10, #1
	vmov	q2, q14
	vmov	q3, q15
	vmov	d6[0], lr
	vmov	q4, q12
	vmov	q5, q13
	add	lr, r10, #2
	vmov	q6, q14
	vmov	q7, q15
	vmov	d14[0], lr
	add	r10, r10, #3
	# Set number of odd+even rounds to perform
	mov	lr, #10
L_chacha_crypt_bytes_arm32_round_start_256:
	subs	lr, lr, #1
	# Round odd
	# a += b; d ^= a; d <<<= 16;
	add	r0, r0, r4
	vadd.i32	q12, q12, q13
	add	r2, r2, r5
	vadd.i32	q0, q0, q1
	eor	r10, r10, r0
	vadd.i32	q4, q4, q5
	eor	r11, r11, r2
	veor	q15, q15, q12
	ror	r10, r10, #16
	veor	q3, q3, q0
	ror	r11, r11, #16
	veor	q7, q7, q4
	add	r8, r8, r10
	vrev32.i16	q15, q15
	add	r9, r9, r11
	vrev32.i16	q3, q3
	eor	r4, r4, r8
	vrev32.i16	q7, q7
	eor	r5, r5, r9
	# c += d; b ^= c; b <<<= 12;
	vadd.i32	q14, q14, q15
	ror	r4, r4, #20
	vadd.i32	q2, q2, q3
	ror	r5, r5, #20
	vadd.i32	q6, q6, q7
	add	r0, r0, r4
	veor	q8, q13, q14
	add	r2, r2, r5
	veor	q9, q1, q2
	eor	r10, r10, r0
	veor	q10, q5, q6
	eor	r11, r11, r2
	vshl.i32	q13, q8, #12
	ror	r10, r10, #24
	vshl.i32	q1, q9, #12
	ror	r11, r11, #24
	vshl.i32	q5, q10, #12
	add	r8, r8, r10
	vsri.i32	q13, q8, #20
	add	r9, r9, r11
	vsri.i32	q1, q9, #20
	eor	r4, r4, r8
	vsri.i32	q5, q10, #20
	str	r11, [sp, #20]
	# a += b; d ^= a; d <<<= 8;
	vadd.i32	q12, q12, q13
	eor	r5, r5, r9
	vadd.i32	q0, q0, q1
	ldr	r11, [sp, #8]
	vadd.i32	q4, q4, q5
	ror	r4, r4, #25
	veor	q8, q15, q12
	ror	r5, r5, #25
	veor	q9, q3, q0
	add	r1, r1, r6
	veor	q10, q7, q4
	str	r8, [sp, #12]
	vshl.i32	q15, q8, #8
	add	r3, r3, r7
	vshl.i32	q3, q9, #8
	ldr	r8, [sp]
	vshl.i32	q7, q10, #8
	eor	r12, r12, r1
	vsri.i32	q15, q8, #24
	str	r9, [sp, #16]
	vsri.i32	q3, q9, #24
	eor	r11, r11, r3
	vsri.i32	q7, q10, #24
	ldr	r9, [sp, #4]
	# c += d; b ^= c; b <<<= 7;
	vadd.i32	q14, q14, q15
	ror	r12, r12, #16
	vadd.i32	q2, q2, q3
	ror	r11, r11, #16
	vadd.i32	q6, q6, q7
	add	r8, r8, r12
	veor	q8, q13, q14
	add	r9, r9, r11
	veor	q9, q1, q2
	eor	r6, r6, r8
	veor	q10, q5, q6
	eor	r7, r7, r9
	vshl.i32	q13, q8, #7
	ror	r6, r6, #20
	vshl.i32	q1, q9, #7
	ror	r7, r7, #20
	vshl.i32	q5, q10, #7
	add	r1, r1, r6
	vsri.i32	q13, q8, #25
	add	r3, r3, r7
	vsri.i32	q1, q9, #25
	eor	r12, r12, r1
	vsri.i32	q5, q10, #25
	eor	r11, r11, r3
	vext.8	q15, q15, q15, #12
	ror	r12, r12, #24
	vext.8	q3, q3, q3, #12
	ror	r11, r11, #24
	vext.8	q7, q7, q7, #12
	add	r8, r8, r12
	vext.8	q13, q13, q13, #4
	add	r9, r9, r11
	vext.8	q1, q1, q1, #4
	eor	r6, r6, r8
	vext.8	q5, q5, q5, #4
	eor	r7, r7, r9
	vext.8	q14, q14, q14, #8
	ror	r6, r6, #25
	vext.8	q2, q2, q2, #8
	ror	r7, r7, #25
	vext.8	q6, q6, q6, #8
	# Round even
	# a += b; d ^= a; d <<<= 16;
	add	r0, r0, r5
	vadd.i32	q12, q12, q13
	add	r2, r2, r6
	vadd.i32	q0, q0, q1
	eor	r11, r11, r0
	vadd.i32	q4, q4, q5
	eor	r10, r10, r2
	veor	q15, q15, q12
	ror	r11, r11, #16
	veor	q3, q3, q0
	ror	r10, r10, #16
	veor	q7, q7, q4
	add	r8, r8, r11
	vrev32.i16	q15, q15
	add	r9, r9, r10
	vrev32.i16	q3, q3
	eor	r5, r5, r8
	vrev32.i16	q7, q7
	eor	r6, r6, r9
	# c += d; b ^= c; b <<<= 12;
	vadd.i32	q14, q14, q15
	ror	r5, r5, #20
	vadd.i32	q2, q2, q3
	ror	r6, r6, #20
	vadd.i32	q6, q6, q7
	add	r0, r0, r5
	veor	q8, q13, q14
	add	r2, r2, r6
	veor	q9, q1, q2
	eor	r11, r11, r0
	veor	q10, q5, q6
	eor	r10, r10, r2
	vshl.i32	q13, q8, #12
	ror	r11, r11, #24
	vshl.i32	q1, q9, #12
	ror	r10, r10, #24
	vshl.i32	q5, q10, #12
	add	r8, r8, r11
	vsri.i32	q13, q8, #20
	add	r9, r9, r10
	vsri.i32	q1, q9, #20
	eor	r5, r5, r8
	vsri.i32	q5, q10, #20
	eor	r6, r6, r9
	str	r11, [sp, #8]
	# a += b; d ^= a; d <<<= 8;
	vadd.i32	q12, q12, q13
	vadd.i32	q0, q0, q1
	ldr	r11, [sp, #20]
	vadd.i32	q4, q4, q5
	ror	r5, r5, #25
	veor	q8, q15, q12
	ror	r6, r6, #25
	veor	q9, q3, q0
	add	r1, r1, r7
	veor	q10, q7, q4
	str	r8, [sp]
	vshl.i32	q15, q8, #8
	add	r3, r3, r4
	vshl.i32	q3, q9, #8
	ldr	r8, [sp, #12]
	vshl.i32	q7, q10, #8
	eor	r11, r11, r1
	vsri.i32	q15, q8, #24
	str	r9, [sp, #4]
	vsri.i32	q3, q9, #24
	eor	r12, r12, r3
	vsri.i32	q7, q10, #24
	ldr	r9, [sp, #16]
	# c += d; b ^= c; b <<<= 7;
	vadd.i32	q14, q14, q15
	ror	r11, r11, #16
	vadd.i32	q2, q2, q3
	ror	r12, r12, #16
	vadd.i32	q6, q6, q7
	add	r8, r8, r11
	veor	q8, q13, q14
	add	r9, r9, r12
	veor	q9, q1, q2
	eor	r7, r7, r8
	veor	q10, q5, q6
	eor	r4, r4, r9
	vshl.i32	q13, q8, #7
	ror	r7, r7, #20
	vshl.i32	q1, q9, #7
	ror	r4, r4, #20
	vshl.i32	q5, q10, #7
	add	r1, r1, r7
	vsri.i32	q13, q8, #25
	add	r3, r3, r4
	vsri.i32	q1, q9, #25
	eor	r11, r11, r1
	vsri.i32	q5, q10, #25
	eor	r12, r12, r3
	vext.8	q15, q15, q15, #4
	ror	r11, r11, #24
	vext.8	q3, q3, q3, #4
	ror	r12, r12, #24
	vext.8	q7, q7, q7, #4
	add	r8, r8, r11
	vext.8	q13, q13, q13, #12
	add	r9, r9, r12
	vext.8	q1, q1, q1, #12
	eor	r7, r7, r8
	vext.8	q5, q5, q5, #12
	eor	r4, r4, r9
	vext.8	q14, q14, q14, #8
	ror	r7, r7, #25
	vext.8	q2, q2, q2, #8
	ror	r4, r4, #25
	vext.8	q6, q6, q6, #8
	bne	L_chacha_crypt_bytes_arm32_round_start_256
	str	r3, [sp, #24]
	# Add back state
	ldr	lr, [sp, #28]
	vldm	lr, {q8-q11}
	ldr	lr, [lr, #48]
	vadd.i32	q12, q12, q8
	vadd.i32	q13, q13, q9
	vadd.i32	q14, q14, q10
	vadd.i32	q15, q15, q11
	add	lr, lr, #1
	vadd.i32	q0, q0, q8
	vadd.i32	q1, q1, q9
	vmov	d22[0], lr
	vadd.i32	q2, q2, q10
	vadd.i32	q3, q3, q11
	add	lr, lr, #1
	vadd.i32	q4, q4, q8
	vadd.i32	q5, q5, q9
	vmov	d22[0], lr
	vadd.i32	q6, q6, q10
	vadd.i32	q7, q7, q11
	ldr	lr, [sp, #28]
	# Load and XOR in message
	ldr	lr, [sp, #32]
	ldr	r3, [sp, #36]
	vldm	lr!, {q8-q11}
	veor	q12, q12, q8
	veor	q13, q13, q9
	veor	q14, q14, q10
	veor	q15, q15, q11
	vstm	r3!, {q12-q15}
	vldm	lr!, {q8-q11}
	veor	q0, q0, q8
	veor	q1, q1, q9
	veor	q2, q2, q10
	veor	q3, q3, q11
	vstm	r3!, {q0-q3}
	vldm	lr!, {q8-q11}
	veor	q4, q4, q8
	veor	q5, q5, q9
	veor	q6, q6, q10
	veor	q7, q7, q11
	vstm	r3!, {q4-q7}
	str	r3, [sp, #36]
	ldr	r3, [sp, #24]
	add	r10, r10, #3
	vmov	d0, r0, r2
	mov	r2, lr
	vmov	d1, r1, r3
	ldr	r1, [sp]
	vmov	d2, r4, r5
	ldr	r3, [sp, #4]
	vmov	d3, r6, r7
	ldr	lr, [sp, #8]
	vmov	d4, r8, r9
	vmov	d5, r1, r3
	ldr	r0, [sp, #28]
	vmov	d6, r10, r11
	ldr	r1, [sp, #36]
	vmov	d7, r12, lr
	ldr	r3, [sp, #40]
	vldm	r0, {q12-q15}
	vldm	r2!, {q4-q7}
	vadd.i32	q0, q0, q12
	vadd.i32	q1, q1, q13
	vadd.i32	q2, q2, q14
	vadd.i32	q3, q3, q15
	ldr	lr, [r0, #48]
	veor	q0, q0, q4
	veor	q1, q1, q5
	add	lr, lr, #4
	veor	q2, q2, q6
	veor	q3, q3, q7
	vstm	r1!, {q0-q3}
	vmov	d30[0], lr
	str	lr, [r0, #48]
	sub	r3, r3, #0x100
	# Done 256-byte block
	cmp	r3, #0x100
	bge	L_chacha_crypt_bytes_arm32_start_256
L_chacha_crypt_bytes_arm32_lt_256:
	cmp	r3, #0x80
	blt	L_chacha_crypt_bytes_arm32_lt_128
	# Move state into vector registers
	veor	q8, q8, q8
	mov	r12, #1
	vmov	q4, q12
	vmov	q5, q13
	vmov	q6, q14
	vmov	q7, q15
	vmov	q0, q12
	vmov	q1, q13
	vmov	q2, q14
	vmov	q3, q15
	# Add counter word
	vmov.i32	d16[0], r12
	vadd.i32	q7, q7, q8
	# Set number of odd+even rounds to perform
	mov	lr, #10
L_chacha_crypt_bytes_arm32_round_start_128:
	subs	lr, lr, #1
	# Round odd
	# a += b; d ^= a; d <<<= 16;
	vadd.i32	q0, q0, q1
	vadd.i32	q4, q4, q5
	veor	q3, q3, q0
	veor	q7, q7, q4
	vrev32.i16	q3, q3
	vrev32.i16	q7, q7
	# c += d; b ^= c; b <<<= 12;
	vadd.i32	q2, q2, q3
	vadd.i32	q6, q6, q7
	veor	q8, q1, q2
	veor	q9, q5, q6
	vshl.i32	q1, q8, #12
	vshl.i32	q5, q9, #12
	vsri.i32	q1, q8, #20
	vsri.i32	q5, q9, #20
	# a += b; d ^= a; d <<<= 8;
	vadd.i32	q0, q0, q1
	vadd.i32	q4, q4, q5
	veor	q8, q3, q0
	veor	q9, q7, q4
	vshl.i32	q3, q8, #8
	vshl.i32	q7, q9, #8
	vsri.i32	q3, q8, #24
	vsri.i32	q7, q9, #24
	# c += d; b ^= c; b <<<= 7;
	vadd.i32	q2, q2, q3
	vadd.i32	q6, q6, q7
	veor	q8, q1, q2
	veor	q9, q5, q6
	vshl.i32	q1, q8, #7
	vshl.i32	q5, q9, #7
	vsri.i32	q1, q8, #25
	vsri.i32	q5, q9, #25
	vext.8	q3, q3, q3, #12
	vext.8	q7, q7, q7, #12
	vext.8	q1, q1, q1, #4
	vext.8	q5, q5, q5, #4
	vext.8	q2, q2, q2, #8
	vext.8	q6, q6, q6, #8
	# Round even
	# a += b; d ^= a; d <<<= 16;
	vadd.i32	q0, q0, q1
	vadd.i32	q4, q4, q5
	veor	q3, q3, q0
	veor	q7, q7, q4
	vrev32.i16	q3, q3
	vrev32.i16	q7, q7
	# c += d; b ^= c; b <<<= 12;
	vadd.i32	q2, q2, q3
	vadd.i32	q6, q6, q7
	veor	q8, q1, q2
	veor	q9, q5, q6
	vshl.i32	q1, q8, #12
	vshl.i32	q5, q9, #12
	vsri.i32	q1, q8, #20
	vsri.i32	q5, q9, #20
	# a += b; d ^= a; d <<<= 8;
	vadd.i32	q0, q0, q1
	vadd.i32	q4, q4, q5
	veor	q8, q3, q0
	veor	q9, q7, q4
	vshl.i32	q3, q8, #8
	vshl.i32	q7, q9, #8
	vsri.i32	q3, q8, #24
	vsri.i32	q7, q9, #24
	# c += d; b ^= c; b <<<= 7;
	vadd.i32	q2, q2, q3
	vadd.i32	q6, q6, q7
	veor	q8, q1, q2
	veor	q9, q5, q6
	vshl.i32	q1, q8, #7
	vshl.i32	q5, q9, #7
	vsri.i32	q1, q8, #25
	vsri.i32	q5, q9, #25
	vext.8	q3, q3, q3, #4
	vext.8	q7, q7, q7, #4
	vext.8	q1, q1, q1, #12
	vext.8	q5, q5, q5, #12
	vext.8	q2, q2, q2, #8
	vext.8	q6, q6, q6, #8
	bne	L_chacha_crypt_bytes_arm32_round_start_128
	# Add back state, XOR in message and store (load next block)
	vld1.8	{q8, q9}, [r2]!
	vld1.8	{q10, q11}, [r2]!
	vadd.i32	q0, q0, q12
	vadd.i32	q1, q1, q13
	vadd.i32	q2, q2, q14
	vadd.i32	q3, q3, q15
	veor	q0, q0, q8
	veor	q1, q1, q9
	veor	q2, q2, q10
	veor	q3, q3, q11
	vld1.8	{q8, q9}, [r2]!
	vld1.8	{q10, q11}, [r2]!
	vst1.8	{q0, q1}, [r1]!
	vst1.8	{q2, q3}, [r1]!
	veor	q0, q0, q0
	mov	r12, #1
	vmov.i32	d0[0], r12
	vadd.i32	q15, q15, q0
	vadd.i32	q4, q4, q12
	vadd.i32	q5, q5, q13
	vadd.i32	q6, q6, q14
	vadd.i32	q7, q7, q15
	veor	q4, q4, q8
	veor	q5, q5, q9
	veor	q6, q6, q10
	veor	q7, q7, q11
	vst1.8	{q4, q5}, [r1]!
	vst1.8	{q6, q7}, [r1]!
	vadd.i32	q15, q15, q0
	sub	r3, r3, #0x80
	# Done 128-byte block
L_chacha_crypt_bytes_arm32_lt_128:
	cmp	r3, #0
	beq	L_chacha_crypt_bytes_arm32_done_all
	mov	r12, #1
	veor	q9, q9, q9
	add	r5, r0, #0x44
	vmov	d18[0], r12
	mov	r12, #0x40
L_chacha_crypt_bytes_arm32_loop_64:
	# Move state into vector registers
	vmov	q0, q12
	vmov	q1, q13
	vmov	q2, q14
	vmov	q3, q15
	# Set number of odd+even rounds to perform
	mov	lr, #10
L_chacha_crypt_bytes_arm32_round_64:
	subs	lr, lr, #1
	# Round odd
	# a += b; d ^= a; d <<<= 16;
	vadd.i32	q0, q0, q1
	veor	q3, q3, q0
	vrev32.16	q3, q3
	# c += d; b ^= c; b <<<= 12;
	vadd.i32	q2, q2, q3
	veor	q8, q1, q2
	vshl.i32	q1, q8, #12
	vsri.i32	q1, q8, #20
	# a += b; d ^= a; d <<<= 8;
	vadd.i32	q0, q0, q1
	veor	q8, q3, q0
	vshl.i32	q3, q8, #8
	vsri.i32	q3, q8, #24
	# c += d; b ^= c; b <<<= 7;
	vadd.i32	q2, q2, q3
	veor	q8, q1, q2
	vshl.i32	q1, q8, #7
	vsri.i32	q1, q8, #25
	vext.8	q3, q3, q3, #12
	vext.8	q1, q1, q1, #4
	vext.8	q2, q2, q2, #8
	# Round even
	# a += b; d ^= a; d <<<= 16;
	vadd.i32	q0, q0, q1
	veor	q3, q3, q0
	vrev32.16	q3, q3
	# c += d; b ^= c; b <<<= 12;
	vadd.i32	q2, q2, q3
	veor	q8, q1, q2
	vshl.i32	q1, q8, #12
	vsri.i32	q1, q8, #20
	# a += b; d ^= a; d <<<= 8;
	vadd.i32	q0, q0, q1
	veor	q8, q3, q0
	vshl.i32	q3, q8, #8
	vsri.i32	q3, q8, #24
	# c += d; b ^= c; b <<<= 7;
	vadd.i32	q2, q2, q3
	veor	q8, q1, q2
	vshl.i32	q1, q8, #7
	vsri.i32	q1, q8, #25
	vext.8	q3, q3, q3, #4
	vext.8	q1, q1, q1, #12
	vext.8	q2, q2, q2, #8
	bne	L_chacha_crypt_bytes_arm32_round_64
	# Add back state
	vadd.i32	q0, q0, q12
	vadd.i32	q1, q1, q13
	vadd.i32	q2, q2, q14
	vadd.i32	q3, q3, q15
	# Check if data is less than 64 bytes - store in over
	cmp	r3, #0x40
	vadd.i32	q15, q15, q9
	blt	L_chacha_crypt_bytes_arm32_lt_64
	# Encipher 64 bytes
	vld1.8	{q4, q5}, [r2]!
	vld1.8	{q6, q7}, [r2]!
	veor	q4, q4, q0
	veor	q5, q5, q1
	veor	q6, q6, q2
	veor	q7, q7, q3
	vst1.8	{q4, q5}, [r1]!
	vst1.8	{q6, q7}, [r1]!
	# Check for more bytes to be enciphered
	subs	r3, r3, #0x40
	bne	L_chacha_crypt_bytes_arm32_loop_64
	b	L_chacha_crypt_bytes_arm32_done
L_chacha_crypt_bytes_arm32_lt_64:
	# Calculate bytes left in block not used
	sub	r12, r12, r3
	# Store encipher block in over for further operations and left
	vstm	r5, {q0-q3}
	sub	r5, r5, #32
	str	r12, [r0, #64]
	# Encipher 32 bytes
	cmp	r3, #32
	blt	L_chacha_crypt_bytes_arm32_lt_32
	vld1.8	{q4, q5}, [r2]!
	veor	q4, q4, q0
	veor	q5, q5, q1
	vst1.8	{q4, q5}, [r1]!
	subs	r3, r3, #32
	vmov	q0, q2
	vmov	q1, q3
	beq	L_chacha_crypt_bytes_arm32_done
L_chacha_crypt_bytes_arm32_lt_32:
	cmp	r3, #16
	blt	L_chacha_crypt_bytes_arm32_lt_16
	# Encipher 16 bytes
	vld1.8	{q4}, [r2]!
	veor	q4, q4, q0
	vst1.8	{q4}, [r1]!
	subs	r3, r3, #16
	vmov	q0, q1
	beq	L_chacha_crypt_bytes_arm32_done
L_chacha_crypt_bytes_arm32_lt_16:
	cmp	r3, #8
	blt	L_chacha_crypt_bytes_arm32_lt_8
	# Encipher 8 bytes
	vld1.8	{d8}, [r2]!
	veor	d8, d8, d0
	vst1.8	{d8}, [r1]!
	subs	r3, r3, #8
	vmov	d0, d1
	beq	L_chacha_crypt_bytes_arm32_done
L_chacha_crypt_bytes_arm32_lt_8:
	cmp	r3, #4
	blt	L_chacha_crypt_bytes_arm32_lt_4
	# Encipher 8 bytes
	ldr	r12, [r2], #4
	vmov	r4, d0[0]
	eor	r12, r12, r4
	str	r12, [r1], #4
	subs	r3, r3, #4
	vshr.u64	d0, d0, #32
	beq	L_chacha_crypt_bytes_arm32_done
L_chacha_crypt_bytes_arm32_lt_4:
	vmov	r12, s0
L_chacha_crypt_bytes_arm32loop_lt_4:
	# Encipher 1 byte at a time
	ldrb	r4, [r2], #1
	eor	r4, r4, r12
	strb	r4, [r1], #1
	subs	r3, r3, #1
	lsr	r12, r12, #8
	bgt	L_chacha_crypt_bytes_arm32loop_lt_4
L_chacha_crypt_bytes_arm32_done:
L_chacha_crypt_bytes_arm32_done_all:
	vstm.32	r0, {q12-q15}
	add	sp, sp, #44
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	wc_chacha_crypt_bytes,.-wc_chacha_crypt_bytes
	.text
	.type	L_chacha_setkey_arm32_constant, %object
	.size	L_chacha_setkey_arm32_constant, 32
	.align	4
L_chacha_setkey_arm32_constant:
	.word	0x61707865
	.word	0x3120646e
	.word	0x79622d36
	.word	0x6b206574
	.word	0x61707865
	.word	0x3320646e
	.word	0x79622d32
	.word	0x6b206574
	.text
	.align	4
	.globl	wc_chacha_setkey
	.type	wc_chacha_setkey, %function
wc_chacha_setkey:
	adr	r3, L_chacha_setkey_arm32_constant
	subs	r2, r2, #16
	add	r3, r3, r2
	# Start with constants
	vldm	r3, {q0}
	vld1.8	{q1}, [r1]!
#ifdef BIG_ENDIAN_ORDER
	vrev32.i16	q1, q1
#endif /* BIG_ENDIAN_ORDER */
	vstm	r0!, {q0, q1}
	beq	L_chacha_setkey_arm32_done
	vld1.8	{q1}, [r1]
#ifdef BIG_ENDIAN_ORDER
	vrev32.i16	q1, q1
#endif /* BIG_ENDIAN_ORDER */
L_chacha_setkey_arm32_done:
	vstm	r0, {q1}
	bx	lr
	.size	wc_chacha_setkey,.-wc_chacha_setkey
	.text
	.align	4
	.globl	wc_chacha_use_over
	.type	wc_chacha_use_over, %function
wc_chacha_use_over:
	push	{lr}
L_chacha_use_over_arm32_16byte_loop:
	cmp	r3, #16
	blt	L_chacha_use_over_arm32_word_loop
	# 16 bytes of state XORed into message.
	vld1.8	{q0}, [r0]!
	vld1.8	{q1}, [r2]!
	veor	q1, q1, q0
	subs	r3, r3, #16
	vst1.8	{q1}, [r1]!
	beq	L_chacha_use_over_arm32_done
	b	L_chacha_use_over_arm32_16byte_loop
L_chacha_use_over_arm32_word_loop:
	cmp	r3, #4
	blt	L_chacha_use_over_arm32_byte_loop
	# 4 bytes of state XORed into message.
	ldr	r12, [r0], #4
	ldr	lr, [r2], #4
	eor	lr, lr, r12
	subs	r3, r3, #4
	str	lr, [r1], #4
	beq	L_chacha_use_over_arm32_done
	b	L_chacha_use_over_arm32_word_loop
L_chacha_use_over_arm32_byte_loop:
	# 1 bytes of state XORed into message.
	ldrb	r12, [r0], #1
	ldrb	lr, [r2], #1
	eor	lr, lr, r12
	subs	r3, r3, #1
	strb	lr, [r1], #1
	beq	L_chacha_use_over_arm32_done
	b	L_chacha_use_over_arm32_byte_loop
L_chacha_use_over_arm32_done:
	pop	{pc}
	.size	wc_chacha_use_over,.-wc_chacha_use_over
#endif /* !WOLFSSL_ARMASM_NO_NEON */
#endif /* HAVE_CHACHA */
#endif /* !__aarch64__ && !WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
