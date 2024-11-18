/* armv8-32-chacha-asm
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
 *   ruby ./chacha/chacha.rb arm32 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-32-chacha-asm.S
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>

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
#ifdef WOLFSSL_ARMASM_NO_NEON
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
#endif /* HAVE_CHACHA */
#endif /* !__aarch64__ && !WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
