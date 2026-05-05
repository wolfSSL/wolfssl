/* armv8-32-aes-asm
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
 *   ruby ./aes/aes.rb arm32 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-32-aes-asm.S
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

#ifdef WOLFSSL_ARMASM
#if !defined(__aarch64__) && !defined(WOLFSSL_ARMASM_THUMB2)
#ifndef WOLFSSL_ARMASM_INLINE
#ifndef NO_AES
#ifndef WOLFSSL_ARMASM_NO_HW_CRYPTO
	.text
	.align	4
	.globl	AES_set_key_AARCH32
	.type	AES_set_key_AARCH32, %function
AES_set_key_AARCH32:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	cmp	r1, #24
	blt	L_aes_set_key_arm32_crypto_start_128
	bgt	L_aes_set_key_arm32_crypto_start_256
	ldr	r4, [r0], #4
	ldr	r5, [r0], #4
	ldr	r6, [r0], #4
	ldr	r7, [r0], #4
	ldr	r8, [r0], #4
	ldr	r9, [r0], #4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r8, r9}
#else
	strd	r8, r9, [r2], #8
#endif
	vdup.32	q1, r9
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #1
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
	eor	r8, r8, r7
	eor	r9, r9, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r8, r9}
#else
	strd	r8, r9, [r2], #8
#endif
	vdup.32	q1, r9
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #2
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
	eor	r8, r8, r7
	eor	r9, r9, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r8, r9}
#else
	strd	r8, r9, [r2], #8
#endif
	vdup.32	q1, r9
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #4
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
	eor	r8, r8, r7
	eor	r9, r9, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r8, r9}
#else
	strd	r8, r9, [r2], #8
#endif
	vdup.32	q1, r9
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #8
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
	eor	r8, r8, r7
	eor	r9, r9, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r8, r9}
#else
	strd	r8, r9, [r2], #8
#endif
	vdup.32	q1, r9
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #16
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
	eor	r8, r8, r7
	eor	r9, r9, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r8, r9}
#else
	strd	r8, r9, [r2], #8
#endif
	vdup.32	q1, r9
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #32
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
	eor	r8, r8, r7
	eor	r9, r9, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r8, r9}
#else
	strd	r8, r9, [r2], #8
#endif
	vdup.32	q1, r9
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #0x40
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
	eor	r8, r8, r7
	eor	r9, r9, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r8, r9}
#else
	strd	r8, r9, [r2], #8
#endif
	vdup.32	q1, r9
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #0x80
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
	cmp	r3, #0
	beq	L_aes_set_key_arm32_crypto_done
	sub	r2, r2, #0xd0
	vld1.32	{q0}, [r2]
	add	r2, r2, #0xc0
	vld1.32	{q1}, [r2]
	sub	r2, r2, #0xc0
	vst1.32	{q1}, [r2]
	add	r2, r2, #0xc0
	vst1.32	{q0}, [r2]
	sub	r2, r2, #0xb0
	vld1.32	{q0}, [r2]
	add	r2, r2, #0xa0
	vld1.32	{q1}, [r2]
	sub	r2, r2, #0xa0
	aesimc.8	q0, q0
	aesimc.8	q1, q1
	vst1.32	{q1}, [r2]
	add	r2, r2, #0xa0
	vst1.32	{q0}, [r2]
	sub	r2, r2, #0x90
	vld1.32	{q0}, [r2]
	add	r2, r2, #0x80
	vld1.32	{q1}, [r2]
	sub	r2, r2, #0x80
	aesimc.8	q0, q0
	aesimc.8	q1, q1
	vst1.32	{q1}, [r2]
	add	r2, r2, #0x80
	vst1.32	{q0}, [r2]
	sub	r2, r2, #0x70
	vld1.32	{q0}, [r2]
	add	r2, r2, #0x60
	vld1.32	{q1}, [r2]
	sub	r2, r2, #0x60
	aesimc.8	q0, q0
	aesimc.8	q1, q1
	vst1.32	{q1}, [r2]
	add	r2, r2, #0x60
	vst1.32	{q0}, [r2]
	sub	r2, r2, #0x50
	vld1.32	{q0}, [r2]
	add	r2, r2, #0x40
	vld1.32	{q1}, [r2]
	sub	r2, r2, #0x40
	aesimc.8	q0, q0
	aesimc.8	q1, q1
	vst1.32	{q1}, [r2]
	add	r2, r2, #0x40
	vst1.32	{q0}, [r2]
	sub	r2, r2, #48
	vld1.32	{q0}, [r2]
	add	r2, r2, #32
	vld1.32	{q1}, [r2]
	sub	r2, r2, #32
	aesimc.8	q0, q0
	aesimc.8	q1, q1
	vst1.32	{q1}, [r2]
	add	r2, r2, #32
	vst1.32	{q0}, [r2]
	sub	r2, r2, #16
	vld1.32	{q0}, [r2]
	aesimc.8	q0, q0
	vst1.32	{q0}, [r2]
	b	L_aes_set_key_arm32_crypto_done
L_aes_set_key_arm32_crypto_start_256:
	ldr	r4, [r0], #4
	ldr	r5, [r0], #4
	ldr	r6, [r0], #4
	ldr	r7, [r0], #4
	ldr	r8, [r0], #4
	ldr	r9, [r0], #4
	ldr	r10, [r0], #4
	ldr	r11, [r0], #4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r8, r9}
#else
	strd	r8, r9, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r10, r11}
#else
	strd	r10, r11, [r2], #8
#endif
	vdup.32	q1, r11
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #1
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
	vdup.32	q1, r7
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	eor	r8, r8, r12
	eor	r9, r9, r8
	eor	r10, r10, r9
	eor	r11, r11, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r8, r9}
#else
	strd	r8, r9, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r10, r11}
#else
	strd	r10, r11, [r2], #8
#endif
	vdup.32	q1, r11
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #2
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
	vdup.32	q1, r7
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	eor	r8, r8, r12
	eor	r9, r9, r8
	eor	r10, r10, r9
	eor	r11, r11, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r8, r9}
#else
	strd	r8, r9, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r10, r11}
#else
	strd	r10, r11, [r2], #8
#endif
	vdup.32	q1, r11
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #4
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
	vdup.32	q1, r7
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	eor	r8, r8, r12
	eor	r9, r9, r8
	eor	r10, r10, r9
	eor	r11, r11, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r8, r9}
#else
	strd	r8, r9, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r10, r11}
#else
	strd	r10, r11, [r2], #8
#endif
	vdup.32	q1, r11
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #8
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
	vdup.32	q1, r7
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	eor	r8, r8, r12
	eor	r9, r9, r8
	eor	r10, r10, r9
	eor	r11, r11, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r8, r9}
#else
	strd	r8, r9, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r10, r11}
#else
	strd	r10, r11, [r2], #8
#endif
	vdup.32	q1, r11
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #16
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
	vdup.32	q1, r7
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	eor	r8, r8, r12
	eor	r9, r9, r8
	eor	r10, r10, r9
	eor	r11, r11, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r8, r9}
#else
	strd	r8, r9, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r10, r11}
#else
	strd	r10, r11, [r2], #8
#endif
	vdup.32	q1, r11
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #32
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
	vdup.32	q1, r7
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	eor	r8, r8, r12
	eor	r9, r9, r8
	eor	r10, r10, r9
	eor	r11, r11, r10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r8, r9}
#else
	strd	r8, r9, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r10, r11}
#else
	strd	r10, r11, [r2], #8
#endif
	vdup.32	q1, r11
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #0x40
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
	cmp	r3, #0
	beq	L_aes_set_key_arm32_crypto_done
	sub	r2, r2, #0xf0
	vld1.32	{q0}, [r2]
	add	r2, r2, #0xe0
	vld1.32	{q1}, [r2]
	sub	r2, r2, #0xe0
	vst1.32	{q1}, [r2]
	add	r2, r2, #0xe0
	vst1.32	{q0}, [r2]
	sub	r2, r2, #0xd0
	vld1.32	{q0}, [r2]
	add	r2, r2, #0xc0
	vld1.32	{q1}, [r2]
	sub	r2, r2, #0xc0
	aesimc.8	q0, q0
	aesimc.8	q1, q1
	vst1.32	{q1}, [r2]
	add	r2, r2, #0xc0
	vst1.32	{q0}, [r2]
	sub	r2, r2, #0xb0
	vld1.32	{q0}, [r2]
	add	r2, r2, #0xa0
	vld1.32	{q1}, [r2]
	sub	r2, r2, #0xa0
	aesimc.8	q0, q0
	aesimc.8	q1, q1
	vst1.32	{q1}, [r2]
	add	r2, r2, #0xa0
	vst1.32	{q0}, [r2]
	sub	r2, r2, #0x90
	vld1.32	{q0}, [r2]
	add	r2, r2, #0x80
	vld1.32	{q1}, [r2]
	sub	r2, r2, #0x80
	aesimc.8	q0, q0
	aesimc.8	q1, q1
	vst1.32	{q1}, [r2]
	add	r2, r2, #0x80
	vst1.32	{q0}, [r2]
	sub	r2, r2, #0x70
	vld1.32	{q0}, [r2]
	add	r2, r2, #0x60
	vld1.32	{q1}, [r2]
	sub	r2, r2, #0x60
	aesimc.8	q0, q0
	aesimc.8	q1, q1
	vst1.32	{q1}, [r2]
	add	r2, r2, #0x60
	vst1.32	{q0}, [r2]
	sub	r2, r2, #0x50
	vld1.32	{q0}, [r2]
	add	r2, r2, #0x40
	vld1.32	{q1}, [r2]
	sub	r2, r2, #0x40
	aesimc.8	q0, q0
	aesimc.8	q1, q1
	vst1.32	{q1}, [r2]
	add	r2, r2, #0x40
	vst1.32	{q0}, [r2]
	sub	r2, r2, #48
	vld1.32	{q0}, [r2]
	add	r2, r2, #32
	vld1.32	{q1}, [r2]
	sub	r2, r2, #32
	aesimc.8	q0, q0
	aesimc.8	q1, q1
	vst1.32	{q1}, [r2]
	add	r2, r2, #32
	vst1.32	{q0}, [r2]
	sub	r2, r2, #16
	vld1.32	{q0}, [r2]
	aesimc.8	q0, q0
	vst1.32	{q0}, [r2]
	b	L_aes_set_key_arm32_crypto_done
L_aes_set_key_arm32_crypto_start_128:
	ldr	r4, [r0], #4
	ldr	r5, [r0], #4
	ldr	r6, [r0], #4
	ldr	r7, [r0], #4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
	vdup.32	q1, r7
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #1
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
	vdup.32	q1, r7
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #2
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
	vdup.32	q1, r7
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #4
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
	vdup.32	q1, r7
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #8
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
	vdup.32	q1, r7
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #16
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
	vdup.32	q1, r7
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #32
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
	vdup.32	q1, r7
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #0x40
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
	vdup.32	q1, r7
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	ror	r12, r12, #8
	eor	r4, r4, #0x80
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
	vdup.32	q1, r7
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	mov	lr, #27
	ror	r12, r12, #8
	eor	r4, r4, lr
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
	vdup.32	q1, r7
	vmov.i32	q0, #0
	aese.8	q0, q1
	vmov.i32	r12, s0
	mov	lr, #54
	ror	r12, r12, #8
	eor	r4, r4, lr
	eor	r4, r4, r12
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r4, r5}
#else
	strd	r4, r5, [r2], #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r2!, {r6, r7}
#else
	strd	r6, r7, [r2], #8
#endif
	cmp	r3, #0
	beq	L_aes_set_key_arm32_crypto_done
	sub	r2, r2, #0xb0
	vld1.32	{q0}, [r2]
	add	r2, r2, #0xa0
	vld1.32	{q1}, [r2]
	sub	r2, r2, #0xa0
	vst1.32	{q1}, [r2]
	add	r2, r2, #0xa0
	vst1.32	{q0}, [r2]
	sub	r2, r2, #0x90
	vld1.32	{q0}, [r2]
	add	r2, r2, #0x80
	vld1.32	{q1}, [r2]
	sub	r2, r2, #0x80
	aesimc.8	q0, q0
	aesimc.8	q1, q1
	vst1.32	{q1}, [r2]
	add	r2, r2, #0x80
	vst1.32	{q0}, [r2]
	sub	r2, r2, #0x70
	vld1.32	{q0}, [r2]
	add	r2, r2, #0x60
	vld1.32	{q1}, [r2]
	sub	r2, r2, #0x60
	aesimc.8	q0, q0
	aesimc.8	q1, q1
	vst1.32	{q1}, [r2]
	add	r2, r2, #0x60
	vst1.32	{q0}, [r2]
	sub	r2, r2, #0x50
	vld1.32	{q0}, [r2]
	add	r2, r2, #0x40
	vld1.32	{q1}, [r2]
	sub	r2, r2, #0x40
	aesimc.8	q0, q0
	aesimc.8	q1, q1
	vst1.32	{q1}, [r2]
	add	r2, r2, #0x40
	vst1.32	{q0}, [r2]
	sub	r2, r2, #48
	vld1.32	{q0}, [r2]
	add	r2, r2, #32
	vld1.32	{q1}, [r2]
	sub	r2, r2, #32
	aesimc.8	q0, q0
	aesimc.8	q1, q1
	vst1.32	{q1}, [r2]
	add	r2, r2, #32
	vst1.32	{q0}, [r2]
	sub	r2, r2, #16
	vld1.32	{q0}, [r2]
	aesimc.8	q0, q0
	vst1.32	{q0}, [r2]
L_aes_set_key_arm32_crypto_done:
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	AES_set_key_AARCH32,.-AES_set_key_AARCH32
#if defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) || defined(HAVE_AES_CBC)
	.text
	.align	4
	.globl	AES_encrypt_AARCH32
	.type	AES_encrypt_AARCH32, %function
AES_encrypt_AARCH32:
	vpush	{d8-d9}
	vld1.8	{q0}, [r0]
	vldm	r2!, {q1-q4}
	aese.8	q0, q1
	aesmc.8	q0, q0
	aese.8	q0, q2
	aesmc.8	q0, q0
	aese.8	q0, q3
	aesmc.8	q0, q0
	aese.8	q0, q4
	aesmc.8	q0, q0
	vldm	r2!, {q1-q4}
	aese.8	q0, q1
	aesmc.8	q0, q0
	aese.8	q0, q2
	aesmc.8	q0, q0
	aese.8	q0, q3
	aesmc.8	q0, q0
	aese.8	q0, q4
	aesmc.8	q0, q0
	subs	r3, r3, #10
	vld1.32	{q1-q2}, [r2]!
	aese.8	q0, q1
	aesmc.8	q0, q0
	aese.8	q0, q2
	beq	L_aes_encrypt_arm32_crypto_round_done
	vld1.32	{q1-q2}, [r2]!
	subs	r3, r3, #2
	aesmc.8	q0, q0
	aese.8	q0, q1
	aesmc.8	q0, q0
	aese.8	q0, q2
	beq	L_aes_encrypt_arm32_crypto_round_done
	vld1.32	{q1-q2}, [r2]!
	aesmc.8	q0, q0
	aese.8	q0, q1
	aesmc.8	q0, q0
	aese.8	q0, q2
L_aes_encrypt_arm32_crypto_round_done:
	vld1.32	{q1}, [r2]
	veor.32	q0, q0, q1
	vst1.8	{q0}, [r1]
	vpop	{d8-d9}
	bx	lr
	.size	AES_encrypt_AARCH32,.-AES_encrypt_AARCH32
#endif /* defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) || defined(HAVE_AES_CBC) */
#if !defined(WC_AES_BITSLICED) || defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
#ifdef HAVE_AES_DECRYPT
	.text
	.align	4
	.globl	AES_decrypt_AARCH32
	.type	AES_decrypt_AARCH32, %function
AES_decrypt_AARCH32:
	vpush	{d8-d9}
	vld1.8	{q0}, [r0]
	vldm	r2!, {q1-q4}
	aesd.8	q0, q1
	aesimc.8	q0, q0
	aesd.8	q0, q2
	aesimc.8	q0, q0
	aesd.8	q0, q3
	aesimc.8	q0, q0
	aesd.8	q0, q4
	aesimc.8	q0, q0
	vldm	r2!, {q1-q4}
	aesd.8	q0, q1
	aesimc.8	q0, q0
	aesd.8	q0, q2
	aesimc.8	q0, q0
	aesd.8	q0, q3
	aesimc.8	q0, q0
	aesd.8	q0, q4
	aesimc.8	q0, q0
	vld1.32	{q1-q2}, [r2]!
	aesd.8	q0, q1
	aesimc.8	q0, q0
	aesd.8	q0, q2
	subs	r3, r3, #10
	beq	L_aes_decrypt_arm32_crypto_round_done
	vld1.32	{q1-q2}, [r2]!
	aesimc.8	q0, q0
	aesd.8	q0, q1
	aesimc.8	q0, q0
	aesd.8	q0, q2
	subs	r3, r3, #2
	beq	L_aes_decrypt_arm32_crypto_round_done
	vld1.32	{q1-q2}, [r2]!
	aesimc.8	q0, q0
	aesd.8	q0, q1
	aesimc.8	q0, q0
	aesd.8	q0, q2
L_aes_decrypt_arm32_crypto_round_done:
	vld1.32	{q1}, [r2]
	veor.32	q0, q0, q1
	vst1.8	{q0}, [r1]
	vpop	{d8-d9}
	bx	lr
	.size	AES_decrypt_AARCH32,.-AES_decrypt_AARCH32
#endif /* HAVE_AES_DECRYPT */
#endif /* !defined(WC_AES_BITSLICED) || defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) */
#ifdef HAVE_AES_ECB
	.text
	.align	4
	.globl	AES_encrypt_blocks_AARCH32
	.type	AES_encrypt_blocks_AARCH32, %function
AES_encrypt_blocks_AARCH32:
	vpush	{d8-d15}
	ldr	r12, [sp, #64]
	vldm.32	r3!, {q0-q7}
	lsr	r2, r2, #4
	cmp	r12, #12
	blt	L_aes_encrypt_blocks_arm32_crypto_start_128
	bgt	L_aes_encrypt_blocks_arm32_crypto_start_256
	# AES_ECB_192
#ifndef NO_AES_192
	vld1.32	{q8-q9}, [r3]!
	cmp	r2, #1
	beq	L_aes_encrypt_blocks_arm32_crypto_192_start_1
L_aes_encrypt_blocks_arm32_crypto_192_start_4:
	cmp	r2, #4
	blt	L_aes_encrypt_blocks_arm32_crypto_192_start_2
	vldm.8	r0!, {q12-q15}
	aese.8	q12, q0
	aesmc.8	q12, q12
	aese.8	q13, q0
	aesmc.8	q13, q13
	aese.8	q14, q0
	aesmc.8	q14, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q12, q1
	aesmc.8	q12, q12
	aese.8	q13, q1
	aesmc.8	q13, q13
	aese.8	q14, q1
	aesmc.8	q14, q14
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q12, q2
	aesmc.8	q12, q12
	aese.8	q13, q2
	aesmc.8	q13, q13
	aese.8	q14, q2
	aesmc.8	q14, q14
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q12, q3
	aesmc.8	q12, q12
	aese.8	q13, q3
	aesmc.8	q13, q13
	aese.8	q14, q3
	aesmc.8	q14, q14
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q12, q4
	aesmc.8	q12, q12
	aese.8	q13, q4
	aesmc.8	q13, q13
	aese.8	q14, q4
	aesmc.8	q14, q14
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q12, q5
	aesmc.8	q12, q12
	aese.8	q13, q5
	aesmc.8	q13, q13
	aese.8	q14, q5
	aesmc.8	q14, q14
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q12, q6
	aesmc.8	q12, q12
	aese.8	q13, q6
	aesmc.8	q13, q13
	aese.8	q14, q6
	aesmc.8	q14, q14
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q12, q7
	aesmc.8	q12, q12
	aese.8	q13, q7
	aesmc.8	q13, q13
	aese.8	q14, q7
	aesmc.8	q14, q14
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q12, q8
	aesmc.8	q12, q12
	aese.8	q13, q8
	aesmc.8	q13, q13
	aese.8	q14, q8
	aesmc.8	q14, q14
	aese.8	q15, q8
	aesmc.8	q15, q15
	vld1.32	{q10}, [r3]!
	aese.8	q12, q9
	aesmc.8	q12, q12
	aese.8	q13, q9
	aesmc.8	q13, q13
	aese.8	q14, q9
	aesmc.8	q14, q14
	aese.8	q15, q9
	aesmc.8	q15, q15
	vld1.32	{q11}, [r3]!
	aese.8	q12, q10
	aesmc.8	q12, q12
	aese.8	q13, q10
	aesmc.8	q13, q13
	aese.8	q14, q10
	aesmc.8	q14, q14
	aese.8	q15, q10
	aesmc.8	q15, q15
	vld1.32	{q10}, [r3]!
	aese.8	q12, q11
	veor.32	q12, q12, q10
	aese.8	q13, q11
	veor.32	q13, q13, q10
	aese.8	q14, q11
	veor.32	q14, q14, q10
	aese.8	q15, q11
	veor.32	q15, q15, q10
	sub	r3, r3, #48
	sub	r2, r2, #4
	vstm.8	r1!, {q12-q15}
	cmp	r2, #4
	bge	L_aes_encrypt_blocks_arm32_crypto_192_start_4
L_aes_encrypt_blocks_arm32_crypto_192_start_2:
	cmp	r2, #2
	blt	L_aes_encrypt_blocks_arm32_crypto_192_start_1
	vld1.8	{q12-q13}, [r0]!
	aese.8	q12, q0
	aesmc.8	q12, q12
	aese.8	q13, q0
	aesmc.8	q13, q13
	aese.8	q12, q1
	aesmc.8	q12, q12
	aese.8	q13, q1
	aesmc.8	q13, q13
	aese.8	q12, q2
	aesmc.8	q12, q12
	aese.8	q13, q2
	aesmc.8	q13, q13
	aese.8	q12, q3
	aesmc.8	q12, q12
	aese.8	q13, q3
	aesmc.8	q13, q13
	aese.8	q12, q4
	aesmc.8	q12, q12
	aese.8	q13, q4
	aesmc.8	q13, q13
	aese.8	q12, q5
	aesmc.8	q12, q12
	aese.8	q13, q5
	aesmc.8	q13, q13
	aese.8	q12, q6
	aesmc.8	q12, q12
	aese.8	q13, q6
	aesmc.8	q13, q13
	aese.8	q12, q7
	aesmc.8	q12, q12
	aese.8	q13, q7
	aesmc.8	q13, q13
	aese.8	q12, q8
	aesmc.8	q12, q12
	aese.8	q13, q8
	aesmc.8	q13, q13
	vld1.32	{q10}, [r3]!
	aese.8	q12, q9
	aesmc.8	q12, q12
	aese.8	q13, q9
	aesmc.8	q13, q13
	vld1.32	{q11}, [r3]!
	aese.8	q12, q10
	aesmc.8	q12, q12
	aese.8	q13, q10
	aesmc.8	q13, q13
	vld1.32	{q10}, [r3]!
	aese.8	q12, q11
	veor.32	q12, q12, q10
	aese.8	q13, q11
	veor.32	q13, q13, q10
	sub	r3, r3, #48
	sub	r2, r2, #2
	vst1.8	{q12-q13}, [r1]!
L_aes_encrypt_blocks_arm32_crypto_192_start_1:
	cmp	r2, #0
	beq	L_aes_encrypt_blocks_arm32_crypto_192_done
	vld1.8	{q12}, [r0]!
	aese.8	q12, q0
	aesmc.8	q12, q12
	aese.8	q12, q1
	aesmc.8	q12, q12
	aese.8	q12, q2
	aesmc.8	q12, q12
	aese.8	q12, q3
	aesmc.8	q12, q12
	aese.8	q12, q4
	aesmc.8	q12, q12
	aese.8	q12, q5
	aesmc.8	q12, q12
	aese.8	q12, q6
	aesmc.8	q12, q12
	aese.8	q12, q7
	aesmc.8	q12, q12
	aese.8	q12, q8
	aesmc.8	q12, q12
	vld1.32	{q10}, [r3]!
	aese.8	q12, q9
	aesmc.8	q12, q12
	vld1.32	{q11}, [r3]!
	aese.8	q12, q10
	aesmc.8	q12, q12
	vld1.32	{q10}, [r3]!
	aese.8	q12, q11
	veor.32	q12, q12, q10
	sub	r3, r3, #48
	vst1.8	{q12}, [r1]!
L_aes_encrypt_blocks_arm32_crypto_192_done:
#endif /* !NO_AES_192 */
	b	L_aes_encrypt_blocks_arm32_crypto_done
	# AES_ECB_256
L_aes_encrypt_blocks_arm32_crypto_start_256:
#ifndef NO_AES_256
	vld1.32	{q8-q9}, [r3]!
	cmp	r2, #1
	beq	L_aes_encrypt_blocks_arm32_crypto_256_start_1
L_aes_encrypt_blocks_arm32_crypto_256_start_4:
	cmp	r2, #4
	blt	L_aes_encrypt_blocks_arm32_crypto_256_start_2
	vldm.8	r0!, {q12-q15}
	aese.8	q12, q0
	aesmc.8	q12, q12
	aese.8	q13, q0
	aesmc.8	q13, q13
	aese.8	q14, q0
	aesmc.8	q14, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q12, q1
	aesmc.8	q12, q12
	aese.8	q13, q1
	aesmc.8	q13, q13
	aese.8	q14, q1
	aesmc.8	q14, q14
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q12, q2
	aesmc.8	q12, q12
	aese.8	q13, q2
	aesmc.8	q13, q13
	aese.8	q14, q2
	aesmc.8	q14, q14
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q12, q3
	aesmc.8	q12, q12
	aese.8	q13, q3
	aesmc.8	q13, q13
	aese.8	q14, q3
	aesmc.8	q14, q14
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q12, q4
	aesmc.8	q12, q12
	aese.8	q13, q4
	aesmc.8	q13, q13
	aese.8	q14, q4
	aesmc.8	q14, q14
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q12, q5
	aesmc.8	q12, q12
	aese.8	q13, q5
	aesmc.8	q13, q13
	aese.8	q14, q5
	aesmc.8	q14, q14
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q12, q6
	aesmc.8	q12, q12
	aese.8	q13, q6
	aesmc.8	q13, q13
	aese.8	q14, q6
	aesmc.8	q14, q14
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q12, q7
	aesmc.8	q12, q12
	aese.8	q13, q7
	aesmc.8	q13, q13
	aese.8	q14, q7
	aesmc.8	q14, q14
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q12, q8
	aesmc.8	q12, q12
	aese.8	q13, q8
	aesmc.8	q13, q13
	aese.8	q14, q8
	aesmc.8	q14, q14
	aese.8	q15, q8
	aesmc.8	q15, q15
	vld1.32	{q10}, [r3]!
	aese.8	q12, q9
	aesmc.8	q12, q12
	aese.8	q13, q9
	aesmc.8	q13, q13
	aese.8	q14, q9
	aesmc.8	q14, q14
	aese.8	q15, q9
	aesmc.8	q15, q15
	vld1.32	{q11}, [r3]!
	aese.8	q12, q10
	aesmc.8	q12, q12
	aese.8	q13, q10
	aesmc.8	q13, q13
	aese.8	q14, q10
	aesmc.8	q14, q14
	aese.8	q15, q10
	aesmc.8	q15, q15
	vld1.32	{q10}, [r3]!
	aese.8	q12, q11
	aesmc.8	q12, q12
	aese.8	q13, q11
	aesmc.8	q13, q13
	aese.8	q14, q11
	aesmc.8	q14, q14
	aese.8	q15, q11
	aesmc.8	q15, q15
	vld1.32	{q11}, [r3]!
	aese.8	q12, q10
	aesmc.8	q12, q12
	aese.8	q13, q10
	aesmc.8	q13, q13
	aese.8	q14, q10
	aesmc.8	q14, q14
	aese.8	q15, q10
	aesmc.8	q15, q15
	vld1.32	{q10}, [r3]!
	aese.8	q12, q11
	veor.32	q12, q12, q10
	aese.8	q13, q11
	veor.32	q13, q13, q10
	aese.8	q14, q11
	veor.32	q14, q14, q10
	aese.8	q15, q11
	veor.32	q15, q15, q10
	sub	r3, r3, #0x50
	sub	r2, r2, #4
	vstm.8	r1!, {q12-q15}
	cmp	r2, #4
	bge	L_aes_encrypt_blocks_arm32_crypto_256_start_4
L_aes_encrypt_blocks_arm32_crypto_256_start_2:
	cmp	r2, #2
	blt	L_aes_encrypt_blocks_arm32_crypto_256_start_1
	vld1.8	{q12-q13}, [r0]!
	aese.8	q12, q0
	aesmc.8	q12, q12
	aese.8	q13, q0
	aesmc.8	q13, q13
	aese.8	q12, q1
	aesmc.8	q12, q12
	aese.8	q13, q1
	aesmc.8	q13, q13
	aese.8	q12, q2
	aesmc.8	q12, q12
	aese.8	q13, q2
	aesmc.8	q13, q13
	aese.8	q12, q3
	aesmc.8	q12, q12
	aese.8	q13, q3
	aesmc.8	q13, q13
	aese.8	q12, q4
	aesmc.8	q12, q12
	aese.8	q13, q4
	aesmc.8	q13, q13
	aese.8	q12, q5
	aesmc.8	q12, q12
	aese.8	q13, q5
	aesmc.8	q13, q13
	aese.8	q12, q6
	aesmc.8	q12, q12
	aese.8	q13, q6
	aesmc.8	q13, q13
	aese.8	q12, q7
	aesmc.8	q12, q12
	aese.8	q13, q7
	aesmc.8	q13, q13
	aese.8	q12, q8
	aesmc.8	q12, q12
	aese.8	q13, q8
	aesmc.8	q13, q13
	vld1.32	{q10}, [r3]!
	aese.8	q12, q9
	aesmc.8	q12, q12
	aese.8	q13, q9
	aesmc.8	q13, q13
	vld1.32	{q11}, [r3]!
	aese.8	q12, q10
	aesmc.8	q12, q12
	aese.8	q13, q10
	aesmc.8	q13, q13
	vld1.32	{q10}, [r3]!
	aese.8	q12, q11
	aesmc.8	q12, q12
	aese.8	q13, q11
	aesmc.8	q13, q13
	vld1.32	{q11}, [r3]!
	aese.8	q12, q10
	aesmc.8	q12, q12
	aese.8	q13, q10
	aesmc.8	q13, q13
	vld1.32	{q10}, [r3]!
	aese.8	q12, q11
	veor.32	q12, q12, q10
	aese.8	q13, q11
	veor.32	q13, q13, q10
	sub	r3, r3, #0x50
	sub	r2, r2, #2
	vst1.8	{q12-q13}, [r1]!
L_aes_encrypt_blocks_arm32_crypto_256_start_1:
	cmp	r2, #0
	beq	L_aes_encrypt_blocks_arm32_crypto_256_done
	vld1.8	{q12}, [r0]!
	aese.8	q12, q0
	aesmc.8	q12, q12
	aese.8	q12, q1
	aesmc.8	q12, q12
	aese.8	q12, q2
	aesmc.8	q12, q12
	aese.8	q12, q3
	aesmc.8	q12, q12
	aese.8	q12, q4
	aesmc.8	q12, q12
	aese.8	q12, q5
	aesmc.8	q12, q12
	aese.8	q12, q6
	aesmc.8	q12, q12
	aese.8	q12, q7
	aesmc.8	q12, q12
	aese.8	q12, q8
	aesmc.8	q12, q12
	vld1.32	{q10}, [r3]!
	aese.8	q12, q9
	aesmc.8	q12, q12
	vld1.32	{q11}, [r3]!
	aese.8	q12, q10
	aesmc.8	q12, q12
	vld1.32	{q10}, [r3]!
	aese.8	q12, q11
	aesmc.8	q12, q12
	vld1.32	{q11}, [r3]!
	aese.8	q12, q10
	aesmc.8	q12, q12
	vld1.32	{q10}, [r3]!
	aese.8	q12, q11
	veor.32	q12, q12, q10
	sub	r3, r3, #0x50
	vst1.8	{q12}, [r1]!
L_aes_encrypt_blocks_arm32_crypto_256_done:
#endif /* !NO_AES_256 */
	b	L_aes_encrypt_blocks_arm32_crypto_done
	# AES_ECB_128
L_aes_encrypt_blocks_arm32_crypto_start_128:
#ifndef NO_AES_128
	vldm.32	r3!, {q8-q10}
	cmp	r2, #1
	beq	L_aes_encrypt_blocks_arm32_crypto_128_start_1
L_aes_encrypt_blocks_arm32_crypto_128_start_4:
	cmp	r2, #4
	blt	L_aes_encrypt_blocks_arm32_crypto_128_start_2
	vldm.8	r0!, {q12-q15}
	aese.8	q12, q0
	aesmc.8	q12, q12
	aese.8	q13, q0
	aesmc.8	q13, q13
	aese.8	q14, q0
	aesmc.8	q14, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q12, q1
	aesmc.8	q12, q12
	aese.8	q13, q1
	aesmc.8	q13, q13
	aese.8	q14, q1
	aesmc.8	q14, q14
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q12, q2
	aesmc.8	q12, q12
	aese.8	q13, q2
	aesmc.8	q13, q13
	aese.8	q14, q2
	aesmc.8	q14, q14
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q12, q3
	aesmc.8	q12, q12
	aese.8	q13, q3
	aesmc.8	q13, q13
	aese.8	q14, q3
	aesmc.8	q14, q14
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q12, q4
	aesmc.8	q12, q12
	aese.8	q13, q4
	aesmc.8	q13, q13
	aese.8	q14, q4
	aesmc.8	q14, q14
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q12, q5
	aesmc.8	q12, q12
	aese.8	q13, q5
	aesmc.8	q13, q13
	aese.8	q14, q5
	aesmc.8	q14, q14
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q12, q6
	aesmc.8	q12, q12
	aese.8	q13, q6
	aesmc.8	q13, q13
	aese.8	q14, q6
	aesmc.8	q14, q14
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q12, q7
	aesmc.8	q12, q12
	aese.8	q13, q7
	aesmc.8	q13, q13
	aese.8	q14, q7
	aesmc.8	q14, q14
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q12, q8
	aesmc.8	q12, q12
	aese.8	q13, q8
	aesmc.8	q13, q13
	aese.8	q14, q8
	aesmc.8	q14, q14
	aese.8	q15, q8
	aesmc.8	q15, q15
	aese.8	q12, q9
	veor.32	q12, q12, q10
	aese.8	q13, q9
	veor.32	q13, q13, q10
	aese.8	q14, q9
	veor.32	q14, q14, q10
	aese.8	q15, q9
	veor.32	q15, q15, q10
	sub	r2, r2, #4
	vstm.8	r1!, {q12-q15}
	cmp	r2, #4
	bge	L_aes_encrypt_blocks_arm32_crypto_128_start_4
L_aes_encrypt_blocks_arm32_crypto_128_start_2:
	cmp	r2, #2
	blt	L_aes_encrypt_blocks_arm32_crypto_128_start_1
	vld1.8	{q12-q13}, [r0]!
	aese.8	q12, q0
	aesmc.8	q12, q12
	aese.8	q13, q0
	aesmc.8	q13, q13
	aese.8	q12, q1
	aesmc.8	q12, q12
	aese.8	q13, q1
	aesmc.8	q13, q13
	aese.8	q12, q2
	aesmc.8	q12, q12
	aese.8	q13, q2
	aesmc.8	q13, q13
	aese.8	q12, q3
	aesmc.8	q12, q12
	aese.8	q13, q3
	aesmc.8	q13, q13
	aese.8	q12, q4
	aesmc.8	q12, q12
	aese.8	q13, q4
	aesmc.8	q13, q13
	aese.8	q12, q5
	aesmc.8	q12, q12
	aese.8	q13, q5
	aesmc.8	q13, q13
	aese.8	q12, q6
	aesmc.8	q12, q12
	aese.8	q13, q6
	aesmc.8	q13, q13
	aese.8	q12, q7
	aesmc.8	q12, q12
	aese.8	q13, q7
	aesmc.8	q13, q13
	aese.8	q12, q8
	aesmc.8	q12, q12
	aese.8	q13, q8
	aesmc.8	q13, q13
	aese.8	q12, q9
	veor.32	q12, q12, q10
	aese.8	q13, q9
	veor.32	q13, q13, q10
	sub	r2, r2, #2
	vst1.8	{q12-q13}, [r1]!
L_aes_encrypt_blocks_arm32_crypto_128_start_1:
	cmp	r2, #0
	beq	L_aes_encrypt_blocks_arm32_crypto_128_done
	vld1.8	{q12}, [r0]!
	aese.8	q12, q0
	aesmc.8	q12, q12
	aese.8	q12, q1
	aesmc.8	q12, q12
	aese.8	q12, q2
	aesmc.8	q12, q12
	aese.8	q12, q3
	aesmc.8	q12, q12
	aese.8	q12, q4
	aesmc.8	q12, q12
	aese.8	q12, q5
	aesmc.8	q12, q12
	aese.8	q12, q6
	aesmc.8	q12, q12
	aese.8	q12, q7
	aesmc.8	q12, q12
	aese.8	q12, q8
	aesmc.8	q12, q12
	aese.8	q12, q9
	veor.32	q12, q12, q10
	vst1.8	{q12}, [r1]!
L_aes_encrypt_blocks_arm32_crypto_128_done:
#endif /* !NO_AES_128 */
L_aes_encrypt_blocks_arm32_crypto_done:
	vpop	{d8-d15}
	bx	lr
	.size	AES_encrypt_blocks_AARCH32,.-AES_encrypt_blocks_AARCH32
#ifdef HAVE_AES_DECRYPT
	.text
	.align	4
	.globl	AES_decrypt_blocks_AARCH32
	.type	AES_decrypt_blocks_AARCH32, %function
AES_decrypt_blocks_AARCH32:
	vpush	{d8-d15}
	ldr	r12, [sp, #64]
	vldm.32	r3!, {q0-q7}
	lsr	r2, r2, #4
	cmp	r12, #12
	blt	L_aes_decrypt_blocks_arm32_crypto_start_128
	bgt	L_aes_decrypt_blocks_arm32_crypto_start_256
	# AES_ECB_192
#ifndef NO_AES_192
	vld1.32	{q8-q9}, [r3]!
	cmp	r2, #1
	beq	L_aes_decrypt_blocks_arm32_crypto_192_start_1
	cmp	r2, #4
	blt	L_aes_decrypt_blocks_arm32_crypto_192_start_2
L_aes_decrypt_blocks_arm32_crypto_192_start_4:
	vldm.8	r0!, {q12-q15}
	aesd.8	q12, q0
	aesimc.8	q12, q12
	aesd.8	q13, q0
	aesimc.8	q13, q13
	aesd.8	q14, q0
	aesimc.8	q14, q14
	aesd.8	q15, q0
	aesimc.8	q15, q15
	aesd.8	q12, q1
	aesimc.8	q12, q12
	aesd.8	q13, q1
	aesimc.8	q13, q13
	aesd.8	q14, q1
	aesimc.8	q14, q14
	aesd.8	q15, q1
	aesimc.8	q15, q15
	aesd.8	q12, q2
	aesimc.8	q12, q12
	aesd.8	q13, q2
	aesimc.8	q13, q13
	aesd.8	q14, q2
	aesimc.8	q14, q14
	aesd.8	q15, q2
	aesimc.8	q15, q15
	aesd.8	q12, q3
	aesimc.8	q12, q12
	aesd.8	q13, q3
	aesimc.8	q13, q13
	aesd.8	q14, q3
	aesimc.8	q14, q14
	aesd.8	q15, q3
	aesimc.8	q15, q15
	aesd.8	q12, q4
	aesimc.8	q12, q12
	aesd.8	q13, q4
	aesimc.8	q13, q13
	aesd.8	q14, q4
	aesimc.8	q14, q14
	aesd.8	q15, q4
	aesimc.8	q15, q15
	aesd.8	q12, q5
	aesimc.8	q12, q12
	aesd.8	q13, q5
	aesimc.8	q13, q13
	aesd.8	q14, q5
	aesimc.8	q14, q14
	aesd.8	q15, q5
	aesimc.8	q15, q15
	aesd.8	q12, q6
	aesimc.8	q12, q12
	aesd.8	q13, q6
	aesimc.8	q13, q13
	aesd.8	q14, q6
	aesimc.8	q14, q14
	aesd.8	q15, q6
	aesimc.8	q15, q15
	aesd.8	q12, q7
	aesimc.8	q12, q12
	aesd.8	q13, q7
	aesimc.8	q13, q13
	aesd.8	q14, q7
	aesimc.8	q14, q14
	aesd.8	q15, q7
	aesimc.8	q15, q15
	aesd.8	q12, q8
	aesimc.8	q12, q12
	aesd.8	q13, q8
	aesimc.8	q13, q13
	aesd.8	q14, q8
	aesimc.8	q14, q14
	aesd.8	q15, q8
	aesimc.8	q15, q15
	vld1.32	{q10}, [r3]!
	aesd.8	q12, q9
	aesimc.8	q12, q12
	aesd.8	q13, q9
	aesimc.8	q13, q13
	aesd.8	q14, q9
	aesimc.8	q14, q14
	aesd.8	q15, q9
	aesimc.8	q15, q15
	vld1.32	{q11}, [r3]!
	aesd.8	q12, q10
	aesimc.8	q12, q12
	aesd.8	q13, q10
	aesimc.8	q13, q13
	aesd.8	q14, q10
	aesimc.8	q14, q14
	aesd.8	q15, q10
	aesimc.8	q15, q15
	vld1.32	{q10}, [r3]!
	aesd.8	q12, q11
	veor.32	q12, q12, q10
	aesd.8	q13, q11
	veor.32	q13, q13, q10
	aesd.8	q14, q11
	veor.32	q14, q14, q10
	aesd.8	q15, q11
	veor.32	q15, q15, q10
	sub	r3, r3, #48
	sub	r2, r2, #4
	vstm.8	r1!, {q12-q15}
	cmp	r2, #4
	bge	L_aes_decrypt_blocks_arm32_crypto_192_start_4
L_aes_decrypt_blocks_arm32_crypto_192_start_2:
	cmp	r2, #2
	blt	L_aes_decrypt_blocks_arm32_crypto_192_start_1
	vld1.8	{q12-q13}, [r0]!
	aesd.8	q12, q0
	aesimc.8	q12, q12
	aesd.8	q13, q0
	aesimc.8	q13, q13
	aesd.8	q12, q1
	aesimc.8	q12, q12
	aesd.8	q13, q1
	aesimc.8	q13, q13
	aesd.8	q12, q2
	aesimc.8	q12, q12
	aesd.8	q13, q2
	aesimc.8	q13, q13
	aesd.8	q12, q3
	aesimc.8	q12, q12
	aesd.8	q13, q3
	aesimc.8	q13, q13
	aesd.8	q12, q4
	aesimc.8	q12, q12
	aesd.8	q13, q4
	aesimc.8	q13, q13
	aesd.8	q12, q5
	aesimc.8	q12, q12
	aesd.8	q13, q5
	aesimc.8	q13, q13
	aesd.8	q12, q6
	aesimc.8	q12, q12
	aesd.8	q13, q6
	aesimc.8	q13, q13
	aesd.8	q12, q7
	aesimc.8	q12, q12
	aesd.8	q13, q7
	aesimc.8	q13, q13
	aesd.8	q12, q8
	aesimc.8	q12, q12
	aesd.8	q13, q8
	aesimc.8	q13, q13
	vld1.32	{q10}, [r3]!
	aesd.8	q12, q9
	aesimc.8	q12, q12
	aesd.8	q13, q9
	aesimc.8	q13, q13
	vld1.32	{q11}, [r3]!
	aesd.8	q12, q10
	aesimc.8	q12, q12
	aesd.8	q13, q10
	aesimc.8	q13, q13
	vld1.32	{q10}, [r3]!
	aesd.8	q12, q11
	veor.32	q12, q12, q10
	aesd.8	q13, q11
	veor.32	q13, q13, q10
	sub	r3, r3, #48
	sub	r2, r2, #2
	vst1.8	{q12-q13}, [r1]!
L_aes_decrypt_blocks_arm32_crypto_192_start_1:
	cmp	r2, #0
	beq	L_aes_decrypt_blocks_arm32_crypto_192_done
	vld1.8	{q12}, [r0]!
	aesd.8	q12, q0
	aesimc.8	q12, q12
	aesd.8	q12, q1
	aesimc.8	q12, q12
	aesd.8	q12, q2
	aesimc.8	q12, q12
	aesd.8	q12, q3
	aesimc.8	q12, q12
	aesd.8	q12, q4
	aesimc.8	q12, q12
	aesd.8	q12, q5
	aesimc.8	q12, q12
	aesd.8	q12, q6
	aesimc.8	q12, q12
	aesd.8	q12, q7
	aesimc.8	q12, q12
	aesd.8	q12, q8
	aesimc.8	q12, q12
	vld1.32	{q10}, [r3]!
	aesd.8	q12, q9
	aesimc.8	q12, q12
	vld1.32	{q11}, [r3]!
	aesd.8	q12, q10
	aesimc.8	q12, q12
	vld1.32	{q10}, [r3]!
	aesd.8	q12, q11
	veor.32	q12, q12, q10
	sub	r3, r3, #48
	vst1.8	{q12}, [r1]!
L_aes_decrypt_blocks_arm32_crypto_192_done:
#endif /* !NO_AES_192 */
	b	L_aes_decrypt_blocks_arm32_crypto_done
	# AES_ECB_256
L_aes_decrypt_blocks_arm32_crypto_start_256:
#ifndef NO_AES_256
	vld1.32	{q8-q9}, [r3]!
	cmp	r2, #1
	beq	L_aes_decrypt_blocks_arm32_crypto_256_start_1
	cmp	r2, #4
	blt	L_aes_decrypt_blocks_arm32_crypto_256_start_2
L_aes_decrypt_blocks_arm32_crypto_256_start_4:
	vldm.8	r0!, {q12-q15}
	aesd.8	q12, q0
	aesimc.8	q12, q12
	aesd.8	q13, q0
	aesimc.8	q13, q13
	aesd.8	q14, q0
	aesimc.8	q14, q14
	aesd.8	q15, q0
	aesimc.8	q15, q15
	aesd.8	q12, q1
	aesimc.8	q12, q12
	aesd.8	q13, q1
	aesimc.8	q13, q13
	aesd.8	q14, q1
	aesimc.8	q14, q14
	aesd.8	q15, q1
	aesimc.8	q15, q15
	aesd.8	q12, q2
	aesimc.8	q12, q12
	aesd.8	q13, q2
	aesimc.8	q13, q13
	aesd.8	q14, q2
	aesimc.8	q14, q14
	aesd.8	q15, q2
	aesimc.8	q15, q15
	aesd.8	q12, q3
	aesimc.8	q12, q12
	aesd.8	q13, q3
	aesimc.8	q13, q13
	aesd.8	q14, q3
	aesimc.8	q14, q14
	aesd.8	q15, q3
	aesimc.8	q15, q15
	aesd.8	q12, q4
	aesimc.8	q12, q12
	aesd.8	q13, q4
	aesimc.8	q13, q13
	aesd.8	q14, q4
	aesimc.8	q14, q14
	aesd.8	q15, q4
	aesimc.8	q15, q15
	aesd.8	q12, q5
	aesimc.8	q12, q12
	aesd.8	q13, q5
	aesimc.8	q13, q13
	aesd.8	q14, q5
	aesimc.8	q14, q14
	aesd.8	q15, q5
	aesimc.8	q15, q15
	aesd.8	q12, q6
	aesimc.8	q12, q12
	aesd.8	q13, q6
	aesimc.8	q13, q13
	aesd.8	q14, q6
	aesimc.8	q14, q14
	aesd.8	q15, q6
	aesimc.8	q15, q15
	aesd.8	q12, q7
	aesimc.8	q12, q12
	aesd.8	q13, q7
	aesimc.8	q13, q13
	aesd.8	q14, q7
	aesimc.8	q14, q14
	aesd.8	q15, q7
	aesimc.8	q15, q15
	aesd.8	q12, q8
	aesimc.8	q12, q12
	aesd.8	q13, q8
	aesimc.8	q13, q13
	aesd.8	q14, q8
	aesimc.8	q14, q14
	aesd.8	q15, q8
	aesimc.8	q15, q15
	vld1.32	{q10}, [r3]!
	aesd.8	q12, q9
	aesimc.8	q12, q12
	aesd.8	q13, q9
	aesimc.8	q13, q13
	aesd.8	q14, q9
	aesimc.8	q14, q14
	aesd.8	q15, q9
	aesimc.8	q15, q15
	vld1.32	{q11}, [r3]!
	aesd.8	q12, q10
	aesimc.8	q12, q12
	aesd.8	q13, q10
	aesimc.8	q13, q13
	aesd.8	q14, q10
	aesimc.8	q14, q14
	aesd.8	q15, q10
	aesimc.8	q15, q15
	vld1.32	{q10}, [r3]!
	aesd.8	q12, q11
	aesimc.8	q12, q12
	aesd.8	q13, q11
	aesimc.8	q13, q13
	aesd.8	q14, q11
	aesimc.8	q14, q14
	aesd.8	q15, q11
	aesimc.8	q15, q15
	vld1.32	{q11}, [r3]!
	aesd.8	q12, q10
	aesimc.8	q12, q12
	aesd.8	q13, q10
	aesimc.8	q13, q13
	aesd.8	q14, q10
	aesimc.8	q14, q14
	aesd.8	q15, q10
	aesimc.8	q15, q15
	vld1.32	{q10}, [r3]!
	aesd.8	q12, q11
	veor.32	q12, q12, q10
	aesd.8	q13, q11
	veor.32	q13, q13, q10
	aesd.8	q14, q11
	veor.32	q14, q14, q10
	aesd.8	q15, q11
	veor.32	q15, q15, q10
	sub	r3, r3, #0x50
	sub	r2, r2, #4
	vstm.8	r1!, {q12-q15}
	cmp	r2, #4
	bge	L_aes_decrypt_blocks_arm32_crypto_256_start_4
L_aes_decrypt_blocks_arm32_crypto_256_start_2:
	cmp	r2, #2
	blt	L_aes_decrypt_blocks_arm32_crypto_256_start_1
	vld1.8	{q12-q13}, [r0]!
	aesd.8	q12, q0
	aesimc.8	q12, q12
	aesd.8	q13, q0
	aesimc.8	q13, q13
	aesd.8	q12, q1
	aesimc.8	q12, q12
	aesd.8	q13, q1
	aesimc.8	q13, q13
	aesd.8	q12, q2
	aesimc.8	q12, q12
	aesd.8	q13, q2
	aesimc.8	q13, q13
	aesd.8	q12, q3
	aesimc.8	q12, q12
	aesd.8	q13, q3
	aesimc.8	q13, q13
	aesd.8	q12, q4
	aesimc.8	q12, q12
	aesd.8	q13, q4
	aesimc.8	q13, q13
	aesd.8	q12, q5
	aesimc.8	q12, q12
	aesd.8	q13, q5
	aesimc.8	q13, q13
	aesd.8	q12, q6
	aesimc.8	q12, q12
	aesd.8	q13, q6
	aesimc.8	q13, q13
	aesd.8	q12, q7
	aesimc.8	q12, q12
	aesd.8	q13, q7
	aesimc.8	q13, q13
	aesd.8	q12, q8
	aesimc.8	q12, q12
	aesd.8	q13, q8
	aesimc.8	q13, q13
	vld1.32	{q10}, [r3]!
	aesd.8	q12, q9
	aesimc.8	q12, q12
	aesd.8	q13, q9
	aesimc.8	q13, q13
	vld1.32	{q11}, [r3]!
	aesd.8	q12, q10
	aesimc.8	q12, q12
	aesd.8	q13, q10
	aesimc.8	q13, q13
	vld1.32	{q10}, [r3]!
	aesd.8	q12, q11
	aesimc.8	q12, q12
	aesd.8	q13, q11
	aesimc.8	q13, q13
	vld1.32	{q11}, [r3]!
	aesd.8	q12, q10
	aesimc.8	q12, q12
	aesd.8	q13, q10
	aesimc.8	q13, q13
	vld1.32	{q10}, [r3]!
	aesd.8	q12, q11
	veor.32	q12, q12, q10
	aesd.8	q13, q11
	veor.32	q13, q13, q10
	sub	r3, r3, #0x50
	sub	r2, r2, #2
	vst1.8	{q12-q13}, [r1]!
L_aes_decrypt_blocks_arm32_crypto_256_start_1:
	cmp	r2, #0
	beq	L_aes_decrypt_blocks_arm32_crypto_256_done
	vld1.8	{q12}, [r0]!
	aesd.8	q12, q0
	aesimc.8	q12, q12
	aesd.8	q12, q1
	aesimc.8	q12, q12
	aesd.8	q12, q2
	aesimc.8	q12, q12
	aesd.8	q12, q3
	aesimc.8	q12, q12
	aesd.8	q12, q4
	aesimc.8	q12, q12
	aesd.8	q12, q5
	aesimc.8	q12, q12
	aesd.8	q12, q6
	aesimc.8	q12, q12
	aesd.8	q12, q7
	aesimc.8	q12, q12
	aesd.8	q12, q8
	aesimc.8	q12, q12
	vld1.32	{q10}, [r3]!
	aesd.8	q12, q9
	aesimc.8	q12, q12
	vld1.32	{q11}, [r3]!
	aesd.8	q12, q10
	aesimc.8	q12, q12
	vld1.32	{q10}, [r3]!
	aesd.8	q12, q11
	aesimc.8	q12, q12
	vld1.32	{q11}, [r3]!
	aesd.8	q12, q10
	aesimc.8	q12, q12
	vld1.32	{q10}, [r3]!
	aesd.8	q12, q11
	veor.32	q12, q12, q10
	sub	r3, r3, #0x50
	vst1.8	{q12}, [r1]!
L_aes_decrypt_blocks_arm32_crypto_256_done:
#endif /* !NO_AES_256 */
	b	L_aes_decrypt_blocks_arm32_crypto_done
	# AES_ECB_128
L_aes_decrypt_blocks_arm32_crypto_start_128:
#ifndef NO_AES_128
	vldm.32	r3!, {q8-q10}
	cmp	r2, #1
	beq	L_aes_decrypt_blocks_arm32_crypto_128_start_1
	cmp	r2, #4
	blt	L_aes_decrypt_blocks_arm32_crypto_128_start_2
L_aes_decrypt_blocks_arm32_crypto_128_start_4:
	vldm.8	r0!, {q12-q15}
	aesd.8	q12, q0
	aesimc.8	q12, q12
	aesd.8	q13, q0
	aesimc.8	q13, q13
	aesd.8	q14, q0
	aesimc.8	q14, q14
	aesd.8	q15, q0
	aesimc.8	q15, q15
	aesd.8	q12, q1
	aesimc.8	q12, q12
	aesd.8	q13, q1
	aesimc.8	q13, q13
	aesd.8	q14, q1
	aesimc.8	q14, q14
	aesd.8	q15, q1
	aesimc.8	q15, q15
	aesd.8	q12, q2
	aesimc.8	q12, q12
	aesd.8	q13, q2
	aesimc.8	q13, q13
	aesd.8	q14, q2
	aesimc.8	q14, q14
	aesd.8	q15, q2
	aesimc.8	q15, q15
	aesd.8	q12, q3
	aesimc.8	q12, q12
	aesd.8	q13, q3
	aesimc.8	q13, q13
	aesd.8	q14, q3
	aesimc.8	q14, q14
	aesd.8	q15, q3
	aesimc.8	q15, q15
	aesd.8	q12, q4
	aesimc.8	q12, q12
	aesd.8	q13, q4
	aesimc.8	q13, q13
	aesd.8	q14, q4
	aesimc.8	q14, q14
	aesd.8	q15, q4
	aesimc.8	q15, q15
	aesd.8	q12, q5
	aesimc.8	q12, q12
	aesd.8	q13, q5
	aesimc.8	q13, q13
	aesd.8	q14, q5
	aesimc.8	q14, q14
	aesd.8	q15, q5
	aesimc.8	q15, q15
	aesd.8	q12, q6
	aesimc.8	q12, q12
	aesd.8	q13, q6
	aesimc.8	q13, q13
	aesd.8	q14, q6
	aesimc.8	q14, q14
	aesd.8	q15, q6
	aesimc.8	q15, q15
	aesd.8	q12, q7
	aesimc.8	q12, q12
	aesd.8	q13, q7
	aesimc.8	q13, q13
	aesd.8	q14, q7
	aesimc.8	q14, q14
	aesd.8	q15, q7
	aesimc.8	q15, q15
	aesd.8	q12, q8
	aesimc.8	q12, q12
	aesd.8	q13, q8
	aesimc.8	q13, q13
	aesd.8	q14, q8
	aesimc.8	q14, q14
	aesd.8	q15, q8
	aesimc.8	q15, q15
	aesd.8	q12, q9
	veor.32	q12, q12, q10
	aesd.8	q13, q9
	veor.32	q13, q13, q10
	aesd.8	q14, q9
	veor.32	q14, q14, q10
	aesd.8	q15, q9
	veor.32	q15, q15, q10
	sub	r2, r2, #4
	vstm.8	r1!, {q12-q15}
	cmp	r2, #4
	bge	L_aes_decrypt_blocks_arm32_crypto_128_start_4
L_aes_decrypt_blocks_arm32_crypto_128_start_2:
	cmp	r2, #2
	blt	L_aes_decrypt_blocks_arm32_crypto_128_start_1
	vld1.8	{q12-q13}, [r0]!
	aesd.8	q12, q0
	aesimc.8	q12, q12
	aesd.8	q13, q0
	aesimc.8	q13, q13
	aesd.8	q12, q1
	aesimc.8	q12, q12
	aesd.8	q13, q1
	aesimc.8	q13, q13
	aesd.8	q12, q2
	aesimc.8	q12, q12
	aesd.8	q13, q2
	aesimc.8	q13, q13
	aesd.8	q12, q3
	aesimc.8	q12, q12
	aesd.8	q13, q3
	aesimc.8	q13, q13
	aesd.8	q12, q4
	aesimc.8	q12, q12
	aesd.8	q13, q4
	aesimc.8	q13, q13
	aesd.8	q12, q5
	aesimc.8	q12, q12
	aesd.8	q13, q5
	aesimc.8	q13, q13
	aesd.8	q12, q6
	aesimc.8	q12, q12
	aesd.8	q13, q6
	aesimc.8	q13, q13
	aesd.8	q12, q7
	aesimc.8	q12, q12
	aesd.8	q13, q7
	aesimc.8	q13, q13
	aesd.8	q12, q8
	aesimc.8	q12, q12
	aesd.8	q13, q8
	aesimc.8	q13, q13
	aesd.8	q12, q9
	veor.32	q12, q12, q10
	aesd.8	q13, q9
	veor.32	q13, q13, q10
	sub	r2, r2, #2
	vst1.8	{q12-q13}, [r1]!
L_aes_decrypt_blocks_arm32_crypto_128_start_1:
	cmp	r2, #0
	beq	L_aes_decrypt_blocks_arm32_crypto_128_done
	vld1.8	{q12}, [r0]!
	aesd.8	q12, q0
	aesimc.8	q12, q12
	aesd.8	q12, q1
	aesimc.8	q12, q12
	aesd.8	q12, q2
	aesimc.8	q12, q12
	aesd.8	q12, q3
	aesimc.8	q12, q12
	aesd.8	q12, q4
	aesimc.8	q12, q12
	aesd.8	q12, q5
	aesimc.8	q12, q12
	aesd.8	q12, q6
	aesimc.8	q12, q12
	aesd.8	q12, q7
	aesimc.8	q12, q12
	aesd.8	q12, q8
	aesimc.8	q12, q12
	aesd.8	q12, q9
	veor.32	q12, q12, q10
	vst1.8	{q12}, [r1]!
L_aes_decrypt_blocks_arm32_crypto_128_done:
#endif /* !NO_AES_128 */
L_aes_decrypt_blocks_arm32_crypto_done:
	vpop	{d8-d15}
	bx	lr
	.size	AES_decrypt_blocks_AARCH32,.-AES_decrypt_blocks_AARCH32
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AES_ECB */
#ifdef HAVE_AES_CBC
	.text
	.align	4
	.globl	AES_CBC_encrypt_AARCH32
	.type	AES_CBC_encrypt_AARCH32, %function
AES_CBC_encrypt_AARCH32:
	push	{lr}
	vpush	{d8-d15}
	ldr	r12, [sp, #68]
	ldr	lr, [sp, #72]
	vldm.32	r12!, {q0-q7}
	vld1.32	{q15}, [r3]
	subs	lr, lr, #12
	lsr	r2, r2, #4
	blt	L_aes_cbc_encrypt_arm32_crypto_start_128
	bgt	L_aes_cbc_encrypt_arm32_crypto_start_256
	# AES_CBC_192
#ifndef NO_AES_192
	vld1.8	{q14}, [r0]!
	vldm.32	r12!, {q8-q12}
	cmp	r2, #1
	beq	L_aes_cbc_encrypt_arm32_crypto_192_start_1
	cmp	r2, #4
	blt	L_aes_cbc_encrypt_arm32_crypto_192_start_2
L_aes_cbc_encrypt_arm32_crypto_192_start_4:
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	aese.8	q15, q9
	aesmc.8	q15, q15
	aese.8	q15, q10
	aesmc.8	q15, q15
	vld1.8	{q14}, [r0]!
	aese.8	q15, q11
	veor.32	q15, q15, q12
	vst1.8	{q15}, [r1]!
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	aese.8	q15, q9
	aesmc.8	q15, q15
	aese.8	q15, q10
	aesmc.8	q15, q15
	vld1.8	{q14}, [r0]!
	aese.8	q15, q11
	veor.32	q15, q15, q12
	vst1.8	{q15}, [r1]!
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	aese.8	q15, q9
	aesmc.8	q15, q15
	aese.8	q15, q10
	aesmc.8	q15, q15
	vld1.8	{q14}, [r0]!
	aese.8	q15, q11
	veor.32	q15, q15, q12
	vst1.8	{q15}, [r1]!
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	aese.8	q15, q9
	aesmc.8	q15, q15
	subs	r2, r2, #4
	aese.8	q15, q10
	aesmc.8	q15, q15
	aese.8	q15, q11
	veor.32	q15, q15, q12
	beq	L_aes_cbc_encrypt_arm32_crypto_192_done
	vld1.8	{q14}, [r0]!
	cmp	r2, #4
	vst1.8	{q15}, [r1]!
	bge	L_aes_cbc_encrypt_arm32_crypto_192_start_4
	cmp	r2, #2
	blt	L_aes_cbc_encrypt_arm32_crypto_192_start_1
L_aes_cbc_encrypt_arm32_crypto_192_start_2:
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	aese.8	q15, q9
	aesmc.8	q15, q15
	aese.8	q15, q10
	aesmc.8	q15, q15
	vld1.8	{q14}, [r0]!
	aese.8	q15, q11
	veor.32	q15, q15, q12
	vst1.8	{q15}, [r1]!
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	aese.8	q15, q9
	aesmc.8	q15, q15
	subs	r2, r2, #2
	aese.8	q15, q10
	aesmc.8	q15, q15
	aese.8	q15, q11
	veor.32	q15, q15, q12
	beq	L_aes_cbc_encrypt_arm32_crypto_192_done
	vld1.8	{q14}, [r0]!
	vst1.8	{q15}, [r1]!
L_aes_cbc_encrypt_arm32_crypto_192_start_1:
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	aese.8	q15, q9
	aesmc.8	q15, q15
	aese.8	q15, q10
	aesmc.8	q15, q15
	aese.8	q15, q11
	veor.32	q15, q15, q12
L_aes_cbc_encrypt_arm32_crypto_192_done:
	vst1.8	{q15}, [r1]!
#endif /* !NO_AES_192 */
	b	L_aes_cbc_encrypt_arm32_crypto_done
	# AES_CBC_256
L_aes_cbc_encrypt_arm32_crypto_start_256:
#ifndef NO_AES_256
	vld1.8	{q14}, [r0]!
	vldm.32	r12!, {q8-q11}
	add	r12, r12, #16
	vld1.32	{q12-q13}, [r12]
	sub	r12, r12, #16
	cmp	r2, #1
	beq	L_aes_cbc_encrypt_arm32_crypto_256_start_1
	cmp	r2, #4
	blt	L_aes_cbc_encrypt_arm32_crypto_256_start_2
L_aes_cbc_encrypt_arm32_crypto_256_start_4:
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	aese.8	q15, q9
	aesmc.8	q15, q15
	aese.8	q15, q10
	aesmc.8	q15, q15
	vld1.32	{q14}, [r12]
	aese.8	q15, q11
	aesmc.8	q15, q15
	aese.8	q15, q14
	aesmc.8	q15, q15
	vld1.8	{q14}, [r0]!
	aese.8	q15, q12
	veor.32	q15, q15, q13
	vst1.8	{q15}, [r1]!
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	aese.8	q15, q9
	aesmc.8	q15, q15
	aese.8	q15, q10
	aesmc.8	q15, q15
	vld1.32	{q14}, [r12]
	aese.8	q15, q11
	aesmc.8	q15, q15
	aese.8	q15, q14
	aesmc.8	q15, q15
	vld1.8	{q14}, [r0]!
	aese.8	q15, q12
	veor.32	q15, q15, q13
	vst1.8	{q15}, [r1]!
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	aese.8	q15, q9
	aesmc.8	q15, q15
	aese.8	q15, q10
	aesmc.8	q15, q15
	vld1.32	{q14}, [r12]
	aese.8	q15, q11
	aesmc.8	q15, q15
	aese.8	q15, q14
	aesmc.8	q15, q15
	vld1.8	{q14}, [r0]!
	aese.8	q15, q12
	veor.32	q15, q15, q13
	vst1.8	{q15}, [r1]!
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	aese.8	q15, q9
	aesmc.8	q15, q15
	aese.8	q15, q10
	aesmc.8	q15, q15
	vld1.32	{q14}, [r12]
	aese.8	q15, q11
	aesmc.8	q15, q15
	subs	r2, r2, #4
	aese.8	q15, q14
	aesmc.8	q15, q15
	aese.8	q15, q12
	veor.32	q15, q15, q13
	beq	L_aes_cbc_encrypt_arm32_crypto_256_done
	vld1.8	{q14}, [r0]!
	cmp	r2, #4
	vst1.8	{q15}, [r1]!
	bge	L_aes_cbc_encrypt_arm32_crypto_256_start_4
	cmp	r2, #2
	blt	L_aes_cbc_encrypt_arm32_crypto_256_start_1
L_aes_cbc_encrypt_arm32_crypto_256_start_2:
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	aese.8	q15, q9
	aesmc.8	q15, q15
	aese.8	q15, q10
	aesmc.8	q15, q15
	vld1.32	{q14}, [r12]
	aese.8	q15, q11
	aesmc.8	q15, q15
	aese.8	q15, q14
	aesmc.8	q15, q15
	vld1.8	{q14}, [r0]!
	aese.8	q15, q12
	veor.32	q15, q15, q13
	vst1.8	{q15}, [r1]!
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	aese.8	q15, q9
	aesmc.8	q15, q15
	aese.8	q15, q10
	aesmc.8	q15, q15
	vld1.32	{q14}, [r12]
	aese.8	q15, q11
	aesmc.8	q15, q15
	subs	r2, r2, #2
	aese.8	q15, q14
	aesmc.8	q15, q15
	aese.8	q15, q12
	veor.32	q15, q15, q13
	beq	L_aes_cbc_encrypt_arm32_crypto_256_done
	vld1.8	{q14}, [r0]!
	vst1.8	{q15}, [r1]!
L_aes_cbc_encrypt_arm32_crypto_256_start_1:
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	aese.8	q15, q9
	aesmc.8	q15, q15
	aese.8	q15, q10
	aesmc.8	q15, q15
	vld1.32	{q14}, [r12]
	aese.8	q15, q11
	aesmc.8	q15, q15
	aese.8	q15, q14
	aesmc.8	q15, q15
	aese.8	q15, q12
	veor.32	q15, q15, q13
L_aes_cbc_encrypt_arm32_crypto_256_done:
	vst1.8	{q15}, [r1]!
#endif /* !NO_AES_256 */
	b	L_aes_cbc_encrypt_arm32_crypto_done
	# AES_CBC_128
L_aes_cbc_encrypt_arm32_crypto_start_128:
#ifndef NO_AES_128
	vld1.8	{q14}, [r0]!
	vldm.32	r12!, {q8-q10}
	cmp	r2, #1
	beq	L_aes_cbc_encrypt_arm32_crypto_128_start_1
	cmp	r2, #4
	blt	L_aes_cbc_encrypt_arm32_crypto_128_start_2
L_aes_cbc_encrypt_arm32_crypto_128_start_4:
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	vld1.8	{q14}, [r0]!
	aese.8	q15, q9
	veor.32	q15, q15, q10
	vst1.8	{q15}, [r1]!
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	vld1.8	{q14}, [r0]!
	aese.8	q15, q9
	veor.32	q15, q15, q10
	vst1.8	{q15}, [r1]!
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	vld1.8	{q14}, [r0]!
	aese.8	q15, q9
	veor.32	q15, q15, q10
	vst1.8	{q15}, [r1]!
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	subs	r2, r2, #4
	aese.8	q15, q8
	aesmc.8	q15, q15
	aese.8	q15, q9
	veor.32	q15, q15, q10
	beq	L_aes_cbc_encrypt_arm32_crypto_128_done
	vld1.8	{q14}, [r0]!
	cmp	r2, #4
	vst1.8	{q15}, [r1]!
	bge	L_aes_cbc_encrypt_arm32_crypto_128_start_4
	cmp	r2, #2
	blt	L_aes_cbc_encrypt_arm32_crypto_128_start_1
L_aes_cbc_encrypt_arm32_crypto_128_start_2:
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	vld1.8	{q14}, [r0]!
	aese.8	q15, q9
	veor.32	q15, q15, q10
	vst1.8	{q15}, [r1]!
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	subs	r2, r2, #2
	aese.8	q15, q8
	aesmc.8	q15, q15
	aese.8	q15, q9
	veor.32	q15, q15, q10
	beq	L_aes_cbc_encrypt_arm32_crypto_128_done
	vld1.8	{q14}, [r0]!
	vst1.8	{q15}, [r1]!
L_aes_cbc_encrypt_arm32_crypto_128_start_1:
	veor.32	q15, q15, q14
	aese.8	q15, q0
	aesmc.8	q15, q15
	aese.8	q15, q1
	aesmc.8	q15, q15
	aese.8	q15, q2
	aesmc.8	q15, q15
	aese.8	q15, q3
	aesmc.8	q15, q15
	aese.8	q15, q4
	aesmc.8	q15, q15
	aese.8	q15, q5
	aesmc.8	q15, q15
	aese.8	q15, q6
	aesmc.8	q15, q15
	aese.8	q15, q7
	aesmc.8	q15, q15
	aese.8	q15, q8
	aesmc.8	q15, q15
	aese.8	q15, q9
	veor.32	q15, q15, q10
L_aes_cbc_encrypt_arm32_crypto_128_done:
	vst1.8	{q15}, [r1]!
#endif /* !NO_AES_128 */
L_aes_cbc_encrypt_arm32_crypto_done:
	vst1.32	{q15}, [r3]
	vpop	{d8-d15}
	pop	{pc}
	.size	AES_CBC_encrypt_AARCH32,.-AES_CBC_encrypt_AARCH32
#ifdef HAVE_AES_DECRYPT
	.text
	.align	4
	.globl	AES_CBC_decrypt_AARCH32
	.type	AES_CBC_decrypt_AARCH32, %function
AES_CBC_decrypt_AARCH32:
	push	{lr}
	vpush	{d8-d15}
	ldr	r12, [sp, #68]
	ldr	lr, [sp, #72]
	vldm.32	r12!, {q0-q7}
	vld1.32	{q13}, [r3]
	lsr	r2, r2, #4
	cmp	lr, #12
	blt	L_aes_cbc_decrypt_blocks_arm32_crypto_start_128
	bgt	L_aes_cbc_decrypt_blocks_arm32_crypto_start_256
	# AES_CBC_192
#ifndef NO_AES_192
	vld1.32	{q8}, [r12]!
	cmp	r2, #1
	beq	L_aes_cbc_decrypt_blocks_arm32_crypto_192_start_1
L_aes_cbc_decrypt_blocks_arm32_crypto_192_start_2:
	vld1.8	{q14-q15}, [r0]!
	vmov	q11, q13
	vmov	q12, q14
	vmov	q13, q15
	aesd.8	q14, q0
	aesimc.8	q14, q14
	aesd.8	q15, q0
	aesimc.8	q15, q15
	aesd.8	q14, q1
	aesimc.8	q14, q14
	aesd.8	q15, q1
	aesimc.8	q15, q15
	aesd.8	q14, q2
	aesimc.8	q14, q14
	aesd.8	q15, q2
	aesimc.8	q15, q15
	aesd.8	q14, q3
	aesimc.8	q14, q14
	aesd.8	q15, q3
	aesimc.8	q15, q15
	aesd.8	q14, q4
	aesimc.8	q14, q14
	aesd.8	q15, q4
	aesimc.8	q15, q15
	aesd.8	q14, q5
	aesimc.8	q14, q14
	aesd.8	q15, q5
	aesimc.8	q15, q15
	aesd.8	q14, q6
	aesimc.8	q14, q14
	aesd.8	q15, q6
	aesimc.8	q15, q15
	aesd.8	q14, q7
	aesimc.8	q14, q14
	aesd.8	q15, q7
	aesimc.8	q15, q15
	vld1.32	{q9}, [r12]!
	aesd.8	q14, q8
	aesimc.8	q14, q14
	aesd.8	q15, q8
	aesimc.8	q15, q15
	vld1.32	{q10}, [r12]!
	aesd.8	q14, q9
	aesimc.8	q14, q14
	aesd.8	q15, q9
	aesimc.8	q15, q15
	vld1.32	{q9}, [r12]!
	aesd.8	q14, q10
	aesimc.8	q14, q14
	aesd.8	q15, q10
	aesimc.8	q15, q15
	vld1.32	{q10}, [r12]
	aesd.8	q14, q9
	aesd.8	q15, q9
	sub	r2, r2, #2
	veor.32	q14, q14, q10
	veor.32	q15, q15, q10
	cmp	r2, #1
	veor.32	q14, q14, q11
	veor.32	q15, q15, q12
	vst1.8	{q14-q15}, [r1]!
	sub	r12, r12, #48
	blt	L_aes_cbc_decrypt_blocks_arm32_crypto_192_done
	bgt	L_aes_cbc_decrypt_blocks_arm32_crypto_192_start_2
L_aes_cbc_decrypt_blocks_arm32_crypto_192_start_1:
	vld1.8	{q14}, [r0]!
	vmov	q11, q13
	vmov	q13, q14
	aesd.8	q14, q0
	aesimc.8	q14, q14
	aesd.8	q14, q1
	aesimc.8	q14, q14
	aesd.8	q14, q2
	aesimc.8	q14, q14
	aesd.8	q14, q3
	aesimc.8	q14, q14
	aesd.8	q14, q4
	aesimc.8	q14, q14
	aesd.8	q14, q5
	aesimc.8	q14, q14
	aesd.8	q14, q6
	aesimc.8	q14, q14
	aesd.8	q14, q7
	aesimc.8	q14, q14
	vld1.32	{q9}, [r12]!
	aesd.8	q14, q8
	aesimc.8	q14, q14
	vld1.32	{q10}, [r12]!
	aesd.8	q14, q9
	aesimc.8	q14, q14
	vld1.32	{q9}, [r12]!
	aesd.8	q14, q10
	aesimc.8	q14, q14
	vld1.32	{q10}, [r12]
	aesd.8	q14, q9
	veor.32	q14, q14, q10
	veor.32	q14, q14, q11
	vst1.8	{q14}, [r1]!
L_aes_cbc_decrypt_blocks_arm32_crypto_192_done:
#endif /* !NO_AES_192 */
	b	L_aes_cbc_decrypt_blocks_arm32_crypto_done
	# AES_CBC_256
L_aes_cbc_decrypt_blocks_arm32_crypto_start_256:
#ifndef NO_AES_256
	vld1.32	{q8}, [r12]!
	cmp	r2, #1
	beq	L_aes_cbc_decrypt_blocks_arm32_crypto_256_start_1
L_aes_cbc_decrypt_blocks_arm32_crypto_256_start_2:
	vld1.8	{q14-q15}, [r0]!
	vmov	q11, q13
	vmov	q12, q14
	vmov	q13, q15
	aesd.8	q14, q0
	aesimc.8	q14, q14
	aesd.8	q15, q0
	aesimc.8	q15, q15
	aesd.8	q14, q1
	aesimc.8	q14, q14
	aesd.8	q15, q1
	aesimc.8	q15, q15
	aesd.8	q14, q2
	aesimc.8	q14, q14
	aesd.8	q15, q2
	aesimc.8	q15, q15
	aesd.8	q14, q3
	aesimc.8	q14, q14
	aesd.8	q15, q3
	aesimc.8	q15, q15
	aesd.8	q14, q4
	aesimc.8	q14, q14
	aesd.8	q15, q4
	aesimc.8	q15, q15
	aesd.8	q14, q5
	aesimc.8	q14, q14
	aesd.8	q15, q5
	aesimc.8	q15, q15
	aesd.8	q14, q6
	aesimc.8	q14, q14
	aesd.8	q15, q6
	aesimc.8	q15, q15
	aesd.8	q14, q7
	aesimc.8	q14, q14
	aesd.8	q15, q7
	aesimc.8	q15, q15
	vld1.32	{q9}, [r12]!
	aesd.8	q14, q8
	aesimc.8	q14, q14
	aesd.8	q15, q8
	aesimc.8	q15, q15
	vld1.32	{q10}, [r12]!
	aesd.8	q14, q9
	aesimc.8	q14, q14
	aesd.8	q15, q9
	aesimc.8	q15, q15
	vld1.32	{q9}, [r12]!
	aesd.8	q14, q10
	aesimc.8	q14, q14
	aesd.8	q15, q10
	aesimc.8	q15, q15
	vld1.32	{q10}, [r12]!
	aesd.8	q14, q9
	aesimc.8	q14, q14
	aesd.8	q15, q9
	aesimc.8	q15, q15
	vld1.32	{q9}, [r12]!
	aesd.8	q14, q10
	aesimc.8	q14, q14
	aesd.8	q15, q10
	aesimc.8	q15, q15
	vld1.32	{q10}, [r12]
	aesd.8	q14, q9
	aesd.8	q15, q9
	sub	r2, r2, #2
	veor.32	q14, q14, q10
	veor.32	q15, q15, q10
	cmp	r2, #1
	veor.32	q14, q14, q11
	veor.32	q15, q15, q12
	vst1.8	{q14-q15}, [r1]!
	sub	r12, r12, #0x50
	blt	L_aes_cbc_decrypt_blocks_arm32_crypto_256_done
	bgt	L_aes_cbc_decrypt_blocks_arm32_crypto_256_start_2
L_aes_cbc_decrypt_blocks_arm32_crypto_256_start_1:
	vld1.8	{q14}, [r0]!
	vmov	q11, q13
	vmov	q13, q14
	aesd.8	q14, q0
	aesimc.8	q14, q14
	aesd.8	q14, q1
	aesimc.8	q14, q14
	aesd.8	q14, q2
	aesimc.8	q14, q14
	aesd.8	q14, q3
	aesimc.8	q14, q14
	aesd.8	q14, q4
	aesimc.8	q14, q14
	aesd.8	q14, q5
	aesimc.8	q14, q14
	aesd.8	q14, q6
	aesimc.8	q14, q14
	aesd.8	q14, q7
	aesimc.8	q14, q14
	vld1.32	{q9}, [r12]!
	aesd.8	q14, q8
	aesimc.8	q14, q14
	vld1.32	{q10}, [r12]!
	aesd.8	q14, q9
	aesimc.8	q14, q14
	vld1.32	{q9}, [r12]!
	aesd.8	q14, q10
	aesimc.8	q14, q14
	vld1.32	{q10}, [r12]!
	aesd.8	q14, q9
	aesimc.8	q14, q14
	vld1.32	{q9}, [r12]!
	aesd.8	q14, q10
	aesimc.8	q14, q14
	vld1.32	{q10}, [r12]
	aesd.8	q14, q9
	veor.32	q14, q14, q10
	veor.32	q14, q14, q11
	vst1.8	{q14}, [r1]!
L_aes_cbc_decrypt_blocks_arm32_crypto_256_done:
#endif /* !NO_AES_256 */
	b	L_aes_cbc_decrypt_blocks_arm32_crypto_done
	# AES_CBC_128
L_aes_cbc_decrypt_blocks_arm32_crypto_start_128:
#ifndef NO_AES_128
	vldm.32	r12!, {q8-q10}
	cmp	r2, #1
	beq	L_aes_cbc_decrypt_blocks_arm32_crypto_128_start_1
L_aes_cbc_decrypt_blocks_arm32_crypto_128_start_2:
	vld1.8	{q14-q15}, [r0]!
	vmov	q11, q13
	vmov	q12, q14
	vmov	q13, q15
	aesd.8	q14, q0
	aesimc.8	q14, q14
	aesd.8	q15, q0
	aesimc.8	q15, q15
	aesd.8	q14, q1
	aesimc.8	q14, q14
	aesd.8	q15, q1
	aesimc.8	q15, q15
	aesd.8	q14, q2
	aesimc.8	q14, q14
	aesd.8	q15, q2
	aesimc.8	q15, q15
	aesd.8	q14, q3
	aesimc.8	q14, q14
	aesd.8	q15, q3
	aesimc.8	q15, q15
	aesd.8	q14, q4
	aesimc.8	q14, q14
	aesd.8	q15, q4
	aesimc.8	q15, q15
	aesd.8	q14, q5
	aesimc.8	q14, q14
	aesd.8	q15, q5
	aesimc.8	q15, q15
	aesd.8	q14, q6
	aesimc.8	q14, q14
	aesd.8	q15, q6
	aesimc.8	q15, q15
	aesd.8	q14, q7
	aesimc.8	q14, q14
	aesd.8	q15, q7
	aesimc.8	q15, q15
	aesd.8	q14, q8
	aesimc.8	q14, q14
	aesd.8	q15, q8
	aesimc.8	q15, q15
	aesd.8	q14, q9
	aesd.8	q15, q9
	sub	r2, r2, #2
	veor.32	q14, q14, q10
	veor.32	q15, q15, q10
	cmp	r2, #1
	veor.32	q14, q14, q11
	veor.32	q15, q15, q12
	vst1.8	{q14-q15}, [r1]!
	blt	L_aes_cbc_decrypt_blocks_arm32_crypto_128_done
	bgt	L_aes_cbc_decrypt_blocks_arm32_crypto_128_start_2
L_aes_cbc_decrypt_blocks_arm32_crypto_128_start_1:
	vld1.8	{q14}, [r0]!
	vmov	q11, q13
	vmov	q13, q14
	aesd.8	q14, q0
	aesimc.8	q14, q14
	aesd.8	q14, q1
	aesimc.8	q14, q14
	aesd.8	q14, q2
	aesimc.8	q14, q14
	aesd.8	q14, q3
	aesimc.8	q14, q14
	aesd.8	q14, q4
	aesimc.8	q14, q14
	aesd.8	q14, q5
	aesimc.8	q14, q14
	aesd.8	q14, q6
	aesimc.8	q14, q14
	aesd.8	q14, q7
	aesimc.8	q14, q14
	aesd.8	q14, q8
	aesimc.8	q14, q14
	aesd.8	q14, q9
	veor.32	q14, q14, q10
	veor.32	q14, q14, q11
	vst1.8	{q14}, [r1]!
L_aes_cbc_decrypt_blocks_arm32_crypto_128_done:
#endif /* !NO_AES_128 */
L_aes_cbc_decrypt_blocks_arm32_crypto_done:
	vst1.32	{q13}, [r3]
	vpop	{d8-d15}
	pop	{pc}
	.size	AES_CBC_decrypt_AARCH32,.-AES_CBC_decrypt_AARCH32
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AES_CBC */
#ifdef WOLFSSL_AES_COUNTER
	.text
	.align	4
	.globl	AES_CTR_encrypt_AARCH32
	.type	AES_CTR_encrypt_AARCH32, %function
AES_CTR_encrypt_AARCH32:
	push	{r4, r5, r6, r7, r8, lr}
	vpush	{d8-d15}
	vld1.32	{q0}, [r3]
	ldr	r12, [sp, #88]
	vrev32.8	q2, q0
	lsr	r4, r2, #4
	vmov	r5, r6, d4
	and	r2, r2, #15
	vmov	r7, r8, d5
	vldm.32	r12!, {q3-q10}
	ldr	lr, [sp, #100]
	cmp	lr, #12
	blt	L_aes_ctr_encrypt_arm32_crypto_start_128
	bgt	L_aes_ctr_encrypt_arm32_crypto_start_256
	# AES_CTR_192
#ifndef NO_AES_192
	vldm.32	r12!, {q11-q13}
	mov	lr, #1
	cmp	r4, #1
	blt	L_aes_ctr_encrypt_arm32_crypto_192_done
	beq	L_aes_ctr_encrypt_arm32_crypto_192_start_1
	adds	r8, r8, #1
	adcs	r7, r7, #0
	adcs	r6, r6, #0
	adc	r5, r5, #0
	vmov	d3, r7, r8
	vmov	d2, r5, r6
	vrev32.8	q1, q1
L_aes_ctr_encrypt_arm32_crypto_192_start_2:
	aese.8	q0, q3
	aesmc.8	q0, q0
	aese.8	q1, q3
	aesmc.8	q1, q1
	adds	r8, r8, #1
	aese.8	q0, q4
	aesmc.8	q0, q0
	aese.8	q1, q4
	aesmc.8	q1, q1
	adcs	r7, r7, #0
	aese.8	q0, q5
	aesmc.8	q0, q0
	aese.8	q1, q5
	aesmc.8	q1, q1
	adcs	r6, r6, #0
	aese.8	q0, q6
	aesmc.8	q0, q0
	aese.8	q1, q6
	aesmc.8	q1, q1
	adc	r5, r5, #0
	aese.8	q0, q7
	aesmc.8	q0, q0
	aese.8	q1, q7
	aesmc.8	q1, q1
	aese.8	q0, q8
	aesmc.8	q0, q0
	aese.8	q1, q8
	aesmc.8	q1, q1
	aese.8	q0, q9
	aesmc.8	q0, q0
	aese.8	q1, q9
	aesmc.8	q1, q1
	aese.8	q0, q10
	aesmc.8	q0, q0
	aese.8	q1, q10
	aesmc.8	q1, q1
	aese.8	q0, q11
	aesmc.8	q0, q0
	aese.8	q1, q11
	aesmc.8	q1, q1
	aese.8	q0, q12
	aesmc.8	q0, q0
	aese.8	q1, q12
	aesmc.8	q1, q1
	vld1.32	{q14}, [r12]!
	vmov	d5, r7, r8
	aese.8	q0, q13
	aesmc.8	q0, q0
	aese.8	q1, q13
	aesmc.8	q1, q1
	vld1.32	{q15}, [r12]
	vmov	d4, r5, r6
	aese.8	q0, q14
	aese.8	q1, q14
	sub	r4, r4, #2
	veor.32	q0, q0, q15
	veor.32	q1, q1, q15
	adds	r8, r8, #1
	vld1.8	{q14-q15}, [r0]!
	adcs	r7, r7, #0
	sub	r12, r12, #16
	veor.32	q14, q14, q0
	veor.32	q15, q15, q1
	adcs	r6, r6, #0
	vrev32.8	q0, q2
	adc	r5, r5, #0
	vmov	d2, r5, r6
	vmov	d3, r7, r8
	cmp	r4, #1
	vst1.8	{q14-q15}, [r1]!
	vrev32.8	q1, q1
	bgt	L_aes_ctr_encrypt_arm32_crypto_192_start_2
	mov	lr, #0
	blt	L_aes_ctr_encrypt_arm32_crypto_192_done
L_aes_ctr_encrypt_arm32_crypto_192_start_1:
	aese.8	q0, q3
	aesmc.8	q0, q0
	adds	r8, r8, lr
	aese.8	q0, q4
	aesmc.8	q0, q0
	adcs	r7, r7, #0
	aese.8	q0, q5
	aesmc.8	q0, q0
	adcs	r6, r6, #0
	aese.8	q0, q6
	aesmc.8	q0, q0
	adc	r5, r5, #0
	aese.8	q0, q7
	aesmc.8	q0, q0
	vmov	d5, r7, r8
	aese.8	q0, q8
	aesmc.8	q0, q0
	vmov	d4, r5, r6
	aese.8	q0, q9
	aesmc.8	q0, q0
	aese.8	q0, q10
	aesmc.8	q0, q0
	aese.8	q0, q11
	aesmc.8	q0, q0
	aese.8	q0, q12
	aesmc.8	q0, q0
	vld1.32	{q14}, [r12]!
	aese.8	q0, q13
	aesmc.8	q0, q0
	vld1.32	{q15}, [r12]
	aese.8	q0, q14
	vld1.8	{q14}, [r0]!
	veor.32	q0, q0, q15
	veor.32	q14, q14, q0
	sub	r12, r12, #16
	vst1.8	{q14}, [r1]!
	mov	lr, #1
	vrev32.8	q0, q2
L_aes_ctr_encrypt_arm32_crypto_192_done:
	cmp	r2, #0
	beq	L_aes_ctr_encrypt_arm32_crypto_192_partial_done
	ldr	r4, [sp, #96]
	aese.8	q0, q3
	aesmc.8	q0, q0
	adds	r8, r8, lr
	aese.8	q0, q4
	aesmc.8	q0, q0
	adcs	r7, r7, #0
	aese.8	q0, q5
	aesmc.8	q0, q0
	adcs	r6, r6, #0
	aese.8	q0, q6
	aesmc.8	q0, q0
	adc	r5, r5, #0
	aese.8	q0, q7
	aesmc.8	q0, q0
	vmov	d5, r7, r8
	aese.8	q0, q8
	aesmc.8	q0, q0
	vmov	d4, r5, r6
	aese.8	q0, q9
	aesmc.8	q0, q0
	aese.8	q0, q10
	aesmc.8	q0, q0
	aese.8	q0, q11
	aesmc.8	q0, q0
	aese.8	q0, q12
	aesmc.8	q0, q0
	vld1.32	{q14}, [r12]!
	aese.8	q0, q13
	aesmc.8	q0, q0
	vld1.32	{q15}, [r12]
	ldr	lr, [sp, #92]
	aese.8	q0, q14
	veor.32	q0, q0, q15
	vst1.32	{q0}, [lr]
	vmov	q0, q2
	mov	r5, #16
	sub	r5, r5, r2
L_aes_ctr_encrypt_arm32_crypto_192_start_byte:
	ldrb	r7, [lr], #1
	ldrb	r8, [r0], #1
	eor	r7, r7, r8
	subs	r2, r2, #1
	strb	r7, [r1], #1
	bgt	L_aes_ctr_encrypt_arm32_crypto_192_start_byte
	vrev32.8	q0, q2
	str	r5, [r4]
L_aes_ctr_encrypt_arm32_crypto_192_partial_done:
#endif /* !NO_AES_192 */
	b	L_aes_ctr_encrypt_arm32_crypto_done
	# AES_CTR_256
L_aes_ctr_encrypt_arm32_crypto_start_256:
#ifndef NO_AES_256
	vldm.32	r12!, {q11-q13}
	mov	lr, #1
	cmp	r4, #1
	blt	L_aes_ctr_encrypt_arm32_crypto_256_done
	beq	L_aes_ctr_encrypt_arm32_crypto_256_start_1
	adds	r8, r8, #1
	adcs	r7, r7, #0
	adcs	r6, r6, #0
	adc	r5, r5, #0
	vmov	d3, r7, r8
	vmov	d2, r5, r6
	vrev32.8	q1, q1
L_aes_ctr_encrypt_arm32_crypto_256_start_2:
	aese.8	q0, q3
	aesmc.8	q0, q0
	aese.8	q1, q3
	aesmc.8	q1, q1
	adds	r8, r8, #1
	aese.8	q0, q4
	aesmc.8	q0, q0
	aese.8	q1, q4
	aesmc.8	q1, q1
	adcs	r7, r7, #0
	aese.8	q0, q5
	aesmc.8	q0, q0
	aese.8	q1, q5
	aesmc.8	q1, q1
	adcs	r6, r6, #0
	aese.8	q0, q6
	aesmc.8	q0, q0
	aese.8	q1, q6
	aesmc.8	q1, q1
	adc	r5, r5, #0
	aese.8	q0, q7
	aesmc.8	q0, q0
	aese.8	q1, q7
	aesmc.8	q1, q1
	aese.8	q0, q8
	aesmc.8	q0, q0
	aese.8	q1, q8
	aesmc.8	q1, q1
	aese.8	q0, q9
	aesmc.8	q0, q0
	aese.8	q1, q9
	aesmc.8	q1, q1
	aese.8	q0, q10
	aesmc.8	q0, q0
	aese.8	q1, q10
	aesmc.8	q1, q1
	aese.8	q0, q11
	aesmc.8	q0, q0
	aese.8	q1, q11
	aesmc.8	q1, q1
	aese.8	q0, q12
	aesmc.8	q0, q0
	aese.8	q1, q12
	aesmc.8	q1, q1
	vld1.32	{q14}, [r12]!
	vmov	d5, r7, r8
	aese.8	q0, q13
	aesmc.8	q0, q0
	aese.8	q1, q13
	aesmc.8	q1, q1
	vld1.32	{q15}, [r12]!
	vmov	d4, r5, r6
	aese.8	q0, q14
	aesmc.8	q0, q0
	aese.8	q1, q14
	aesmc.8	q1, q1
	vld1.32	{q14}, [r12]!
	adds	r8, r8, #1
	aese.8	q0, q15
	aesmc.8	q0, q0
	aese.8	q1, q15
	aesmc.8	q1, q1
	vld1.32	{q15}, [r12]
	adcs	r7, r7, #0
	aese.8	q0, q14
	aese.8	q1, q14
	sub	r4, r4, #2
	veor.32	q0, q0, q15
	veor.32	q1, q1, q15
	adcs	r6, r6, #0
	vld1.8	{q14-q15}, [r0]!
	sub	r12, r12, #48
	veor.32	q14, q14, q0
	veor.32	q15, q15, q1
	adc	r5, r5, #0
	vrev32.8	q0, q2
	vmov	d2, r5, r6
	vmov	d3, r7, r8
	cmp	r4, #1
	vst1.8	{q14-q15}, [r1]!
	vrev32.8	q1, q1
	bgt	L_aes_ctr_encrypt_arm32_crypto_256_start_2
	mov	lr, #0
	blt	L_aes_ctr_encrypt_arm32_crypto_256_done
L_aes_ctr_encrypt_arm32_crypto_256_start_1:
	aese.8	q0, q3
	aesmc.8	q0, q0
	adds	r8, r8, lr
	aese.8	q0, q4
	aesmc.8	q0, q0
	adcs	r7, r7, #0
	aese.8	q0, q5
	aesmc.8	q0, q0
	adcs	r6, r6, #0
	aese.8	q0, q6
	aesmc.8	q0, q0
	adc	r5, r5, #0
	aese.8	q0, q7
	aesmc.8	q0, q0
	vmov	d5, r7, r8
	aese.8	q0, q8
	aesmc.8	q0, q0
	vmov	d4, r5, r6
	aese.8	q0, q9
	aesmc.8	q0, q0
	aese.8	q0, q10
	aesmc.8	q0, q0
	aese.8	q0, q11
	aesmc.8	q0, q0
	aese.8	q0, q12
	aesmc.8	q0, q0
	vld1.32	{q14}, [r12]!
	aese.8	q0, q13
	aesmc.8	q0, q0
	vld1.32	{q15}, [r12]!
	aese.8	q0, q14
	aesmc.8	q0, q0
	vld1.32	{q14}, [r12]!
	aese.8	q0, q15
	aesmc.8	q0, q0
	vld1.32	{q15}, [r12]
	aese.8	q0, q14
	vld1.8	{q14}, [r0]!
	veor.32	q0, q0, q15
	veor.32	q14, q14, q0
	sub	r12, r12, #48
	vst1.8	{q14}, [r1]!
	mov	lr, #1
	vrev32.8	q0, q2
L_aes_ctr_encrypt_arm32_crypto_256_done:
	cmp	r2, #0
	beq	L_aes_ctr_encrypt_arm32_crypto_256_partial_done
	ldr	r4, [sp, #96]
	aese.8	q0, q3
	aesmc.8	q0, q0
	adds	r8, r8, lr
	aese.8	q0, q4
	aesmc.8	q0, q0
	adcs	r7, r7, #0
	aese.8	q0, q5
	aesmc.8	q0, q0
	adcs	r6, r6, #0
	aese.8	q0, q6
	aesmc.8	q0, q0
	adc	r5, r5, #0
	aese.8	q0, q7
	aesmc.8	q0, q0
	vmov	d5, r7, r8
	aese.8	q0, q8
	aesmc.8	q0, q0
	vmov	d4, r5, r6
	aese.8	q0, q9
	aesmc.8	q0, q0
	aese.8	q0, q10
	aesmc.8	q0, q0
	aese.8	q0, q11
	aesmc.8	q0, q0
	aese.8	q0, q12
	aesmc.8	q0, q0
	vld1.32	{q14}, [r12]!
	aese.8	q0, q13
	aesmc.8	q0, q0
	vld1.32	{q15}, [r12]!
	aese.8	q0, q14
	aesmc.8	q0, q0
	vld1.32	{q14}, [r12]!
	aese.8	q0, q15
	aesmc.8	q0, q0
	vld1.32	{q15}, [r12]
	ldr	lr, [sp, #92]
	aese.8	q0, q14
	veor.32	q0, q0, q15
	vst1.32	{q0}, [lr]
	vmov	q0, q2
	mov	r5, #16
	sub	r5, r5, r2
L_aes_ctr_encrypt_arm32_crypto_256_start_byte:
	ldrb	r7, [lr], #1
	ldrb	r8, [r0], #1
	eor	r7, r7, r8
	subs	r2, r2, #1
	strb	r7, [r1], #1
	bgt	L_aes_ctr_encrypt_arm32_crypto_256_start_byte
	vrev32.8	q0, q2
	str	r5, [r4]
L_aes_ctr_encrypt_arm32_crypto_256_partial_done:
#endif /* !NO_AES_256 */
	b	L_aes_ctr_encrypt_arm32_crypto_done
	# AES_CTR_128
L_aes_ctr_encrypt_arm32_crypto_start_128:
#ifndef NO_AES_128
	vldm.32	r12!, {q11-q13}
	mov	lr, #1
	cmp	r4, #1
	blt	L_aes_ctr_encrypt_arm32_crypto_128_done
	beq	L_aes_ctr_encrypt_arm32_crypto_128_start_1
	adds	r8, r8, #1
	adcs	r7, r7, #0
	adcs	r6, r6, #0
	adc	r5, r5, #0
	vmov	d3, r7, r8
	vmov	d2, r5, r6
	vrev32.8	q1, q1
L_aes_ctr_encrypt_arm32_crypto_128_start_2:
	aese.8	q0, q3
	aesmc.8	q0, q0
	aese.8	q1, q3
	aesmc.8	q1, q1
	adds	r8, r8, #1
	aese.8	q0, q4
	aesmc.8	q0, q0
	aese.8	q1, q4
	aesmc.8	q1, q1
	adcs	r7, r7, #0
	aese.8	q0, q5
	aesmc.8	q0, q0
	aese.8	q1, q5
	aesmc.8	q1, q1
	adcs	r6, r6, #0
	aese.8	q0, q6
	aesmc.8	q0, q0
	aese.8	q1, q6
	aesmc.8	q1, q1
	adc	r5, r5, #0
	aese.8	q0, q7
	aesmc.8	q0, q0
	aese.8	q1, q7
	aesmc.8	q1, q1
	vmov	d5, r7, r8
	aese.8	q0, q8
	aesmc.8	q0, q0
	aese.8	q1, q8
	aesmc.8	q1, q1
	vmov	d4, r5, r6
	aese.8	q0, q9
	aesmc.8	q0, q0
	aese.8	q1, q9
	aesmc.8	q1, q1
	adds	r8, r8, #1
	aese.8	q0, q10
	aesmc.8	q0, q0
	aese.8	q1, q10
	aesmc.8	q1, q1
	adcs	r7, r7, #0
	aese.8	q0, q11
	aesmc.8	q0, q0
	aese.8	q1, q11
	aesmc.8	q1, q1
	adcs	r6, r6, #0
	vld1.8	{q14-q15}, [r0]!
	adc	r5, r5, #0
	aese.8	q0, q12
	aese.8	q1, q12
	sub	r4, r4, #2
	veor.32	q14, q14, q13
	veor.32	q15, q15, q13
	veor.32	q14, q14, q0
	veor.32	q15, q15, q1
	vrev32.8	q0, q2
	vmov	d2, r5, r6
	vmov	d3, r7, r8
	cmp	r4, #1
	vst1.8	{q14-q15}, [r1]!
	vrev32.8	q1, q1
	bgt	L_aes_ctr_encrypt_arm32_crypto_128_start_2
	mov	lr, #0
	blt	L_aes_ctr_encrypt_arm32_crypto_128_done
L_aes_ctr_encrypt_arm32_crypto_128_start_1:
	aese.8	q0, q3
	aesmc.8	q0, q0
	adds	r8, r8, lr
	aese.8	q0, q4
	aesmc.8	q0, q0
	adcs	r7, r7, #0
	aese.8	q0, q5
	aesmc.8	q0, q0
	adcs	r6, r6, #0
	aese.8	q0, q6
	aesmc.8	q0, q0
	adc	r5, r5, #0
	aese.8	q0, q7
	aesmc.8	q0, q0
	vmov	d5, r7, r8
	aese.8	q0, q8
	aesmc.8	q0, q0
	vmov	d4, r5, r6
	aese.8	q0, q9
	aesmc.8	q0, q0
	aese.8	q0, q10
	aesmc.8	q0, q0
	aese.8	q0, q11
	aesmc.8	q0, q0
	vld1.8	{q14}, [r0]!
	aese.8	q0, q12
	veor.32	q0, q0, q13
	veor.32	q14, q14, q0
	vst1.8	{q14}, [r1]!
	mov	lr, #1
	vrev32.8	q0, q2
L_aes_ctr_encrypt_arm32_crypto_128_done:
	cmp	r2, #0
	beq	L_aes_ctr_encrypt_arm32_crypto_128_partial_done
	ldr	r4, [sp, #96]
	aese.8	q0, q3
	aesmc.8	q0, q0
	adds	r8, r8, lr
	aese.8	q0, q4
	aesmc.8	q0, q0
	adcs	r7, r7, #0
	aese.8	q0, q5
	aesmc.8	q0, q0
	adcs	r6, r6, #0
	aese.8	q0, q6
	aesmc.8	q0, q0
	adc	r5, r5, #0
	aese.8	q0, q7
	aesmc.8	q0, q0
	vmov	d5, r7, r8
	aese.8	q0, q8
	aesmc.8	q0, q0
	vmov	d4, r5, r6
	aese.8	q0, q9
	aesmc.8	q0, q0
	aese.8	q0, q10
	aesmc.8	q0, q0
	aese.8	q0, q11
	aesmc.8	q0, q0
	ldr	lr, [sp, #92]
	aese.8	q0, q12
	veor.32	q0, q0, q13
	vst1.32	{q0}, [lr]
	vmov	q0, q2
	mov	r5, #16
	sub	r5, r5, r2
L_aes_ctr_encrypt_arm32_crypto_128_start_byte:
	ldrb	r7, [lr], #1
	ldrb	r8, [r0], #1
	eor	r7, r7, r8
	subs	r2, r2, #1
	strb	r7, [r1], #1
	bgt	L_aes_ctr_encrypt_arm32_crypto_128_start_byte
	vrev32.8	q0, q2
	str	r5, [r4]
L_aes_ctr_encrypt_arm32_crypto_128_partial_done:
#endif /* !NO_AES_128 */
L_aes_ctr_encrypt_arm32_crypto_done:
	vst1.32	{q0}, [r3]
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, pc}
	.size	AES_CTR_encrypt_AARCH32,.-AES_CTR_encrypt_AARCH32
#endif /* WOLFSSL_AES_COUNTER */
#ifdef HAVE_AESGCM
	.text
	.align	4
	.globl	AES_GCM_set_key_AARCH32
	.type	AES_GCM_set_key_AARCH32, %function
AES_GCM_set_key_AARCH32:
	vpush	{d8-d9}
	vld1.8	{q0}, [r0]
	vld1.8	{q1-q2}, [r1]!
	vld1.8	{q3-q4}, [r1]!
	aese.8	q0, q1
	aesmc.8	q0, q0
	aese.8	q0, q2
	aesmc.8	q0, q0
	aese.8	q0, q3
	aesmc.8	q0, q0
	aese.8	q0, q4
	aesmc.8	q0, q0
	vld1.8	{q1-q2}, [r1]!
	vld1.8	{q3-q4}, [r1]!
	aese.8	q0, q1
	aesmc.8	q0, q0
	aese.8	q0, q2
	aesmc.8	q0, q0
	aese.8	q0, q3
	aesmc.8	q0, q0
	aese.8	q0, q4
	aesmc.8	q0, q0
	subs	r3, r3, #10
	vld1.8	{q1-q2}, [r1]!
	aese.8	q0, q1
	aesmc.8	q0, q0
	aese.8	q0, q2
	beq	L_aes_gcm_set_key_arm32_crypto_round_done
	vld1.8	{q1-q2}, [r1]!
	subs	r3, r3, #2
	aesmc.8	q0, q0
	aese.8	q0, q1
	aesmc.8	q0, q0
	aese.8	q0, q2
	beq	L_aes_gcm_set_key_arm32_crypto_round_done
	vld1.8	{q1-q2}, [r1]!
	aesmc.8	q0, q0
	aese.8	q0, q1
	aesmc.8	q0, q0
	aese.8	q0, q2
L_aes_gcm_set_key_arm32_crypto_round_done:
	vld1.8	{q1}, [r1]
	veor	q0, q0, q1
	vmov.i8	q1, #0x55
	vshl.u8	q2, q0, #1
	vshr.u8	q0, q0, #1
	vbif.8	q0, q2, q1
	vmov.i8	q1, #51
	vshl.u8	q2, q0, #2
	vshr.u8	q0, q0, #2
	vbit.8	q2, q0, q1
	vshl.u8	q0, q2, #4
	vsri.u8	q0, q2, #4
	vst1.32	{q0}, [r2]
	vpop	{d8-d9}
	bx	lr
	.size	AES_GCM_set_key_AARCH32,.-AES_GCM_set_key_AARCH32
	.text
	.align	4
	.globl	AES_GCM_encrypt_AARCH32
	.type	AES_GCM_encrypt_AARCH32, %function
AES_GCM_encrypt_AARCH32:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	vpush	{d8-d15}
	# key
	ldr	r7, [sp, #120]
	# tmp
	ldr	r9, [sp, #128]
	# nonceSz
	ldr	r12, [sp, #100]
	cmp	r12, #12
	beq	L_aes_gcm_encrypt_arm32_crypto_nonce_setup_done
	vmov.i8	q13, #0x87
	# gcm_h
	ldr	r8, [sp, #124]
	veor.8	q6, q6, q6
	vshr.u64	q13, q13, #56
	vld1.32	{q8}, [r8]
L_aes_gcm_encrypt_arm32_crypto_nonce_setup_done:
	# Load Nonce
	cmp	r12, #12
	bne	L_aes_gcm_encrypt_arm32_crypto_ghash_nonce
	ldr	r5, [r3]
	ldr	r8, [r3, #4]
	ldr	r12, [r3, #8]
	vmov.i32	q6, #0x1000000
	vmov.32	s24, r5
	vmov.32	s25, r8
	vmov.32	s26, r12
	mov	r5, #1
	b	L_aes_gcm_encrypt_arm32_crypto_done_nonce
L_aes_gcm_encrypt_arm32_crypto_ghash_nonce:
	lsr	r10, r12, #4
	cmp	r10, #0
	beq	L_aes_gcm_encrypt_arm32_crypto_nonce_done
L_aes_gcm_encrypt_arm32_crypto_nonce_start_1:
	vld1.32	{q14}, [r3]!
	vmov.i8	q12, #0x55
	vshl.u8	q0, q14, #1
	vshr.u8	q14, q14, #1
	vbif.8	q14, q0, q12
	vmov.i8	q12, #51
	vshl.u8	q0, q14, #2
	vshr.u8	q14, q14, #2
	vbit.8	q0, q14, q12
	vshl.u8	q14, q0, #4
	vsri.u8	q14, q0, #4
	veor.8	q12, q6, q14
	#   X  = C * H^1
	vmull.p64	q2, d25, d16
	vmull.p64	q6, d24, d17
	vmull.p64	q0, d24, d16
	vmull.p64	q1, d25, d17
	veor.8	q2, q2, q6
	#   Reduce
	vmull.p64	q6, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d13
	veor.8	d1, d1, d12
	vmull.p64	q6, d2, d26
	veor.8	q6, q6, q0
	# Done GHASH
	subs	r10, r10, #1
	bne	L_aes_gcm_encrypt_arm32_crypto_nonce_start_1
L_aes_gcm_encrypt_arm32_crypto_nonce_done:
	ands	r11, r12, #15
	beq	L_aes_gcm_encrypt_arm32_crypto_nonce_partial_done
	veor.8	q0, q0, q0
	mov	r12, r11
	vst1.32	{q0}, [r9]
	cmp	r12, #4
	blt	L_aes_gcm_encrypt_arm32_crypto_nonce_start_sw
L_aes_gcm_encrypt_arm32_crypto_nonce_start_dw:
	ldr	r8, [r3], #4
	sub	r12, r12, #4
	str	r8, [r9], #4
	cmp	r12, #4
	bge	L_aes_gcm_encrypt_arm32_crypto_nonce_start_dw
L_aes_gcm_encrypt_arm32_crypto_nonce_start_sw:
	cmp	r12, #2
	blt	L_aes_gcm_encrypt_arm32_crypto_nonce_start_byte
	ldrh	r8, [r3], #2
	sub	r12, r12, #2
	strh	r8, [r9], #2
L_aes_gcm_encrypt_arm32_crypto_nonce_start_byte:
	cmp	r12, #1
	blt	L_aes_gcm_encrypt_arm32_crypto_nonce_end_bytes
	ldrb	r8, [r3], #1
	subs	r12, r12, #1
	strb	r8, [r9], #1
	bne	L_aes_gcm_encrypt_arm32_crypto_nonce_start_byte
L_aes_gcm_encrypt_arm32_crypto_nonce_end_bytes:
	sub	r9, r9, r11
	vld1.32	{q14}, [r9]
	vmov.i8	q12, #0x55
	vshl.u8	q0, q14, #1
	vshr.u8	q14, q14, #1
	vbif.8	q14, q0, q12
	vmov.i8	q12, #51
	vshl.u8	q0, q14, #2
	vshr.u8	q14, q14, #2
	vbit.8	q0, q14, q12
	vshl.u8	q14, q0, #4
	vsri.u8	q14, q0, #4
	veor.8	q12, q6, q14
	#   X  = C * H^1
	vmull.p64	q2, d25, d16
	vmull.p64	q6, d24, d17
	vmull.p64	q0, d24, d16
	vmull.p64	q1, d25, d17
	veor.8	q2, q2, q6
	#   Reduce
	vmull.p64	q6, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d13
	veor.8	d1, d1, d12
	vmull.p64	q6, d2, d26
	veor.8	q6, q6, q0
	# Done GHASH
L_aes_gcm_encrypt_arm32_crypto_nonce_partial_done:
	veor.8	q0, q0, q0
	# nonceSz
	ldr	r12, [sp, #100]
	lsr	r10, r12, #29
	lsl	r11, r12, #3
	rbit	r10, r10
	rbit	r11, r11
	vmov.32	s2, r10
	vmov.32	s3, r11
	veor.8	q6, q6, q0
	vmull.p64	q2, d13, d16
	vmull.p64	q12, d12, d17
	vmull.p64	q0, d12, d16
	vmull.p64	q1, d13, d17
	veor.8	q2, q2, q12
	vmull.p64	q6, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d13
	veor.8	d1, d1, d12
	vmull.p64	q6, d2, d26
	veor.8	q6, q6, q0
	vmov.32	r5, s24
	vmov.32	r8, s25
	vmov.32	r12, s26
	rbit	r5, r5
	rbit	r8, r8
	rbit	r12, r12
	rev	r5, r5
	rev	r8, r8
	rev	r12, r12
	vmov.32	s24, r5
	vmov.32	s25, r8
	vmov.32	s26, r12
	vmov.32	r5, s27
	rbit	r5, r5
	rev	r5, r5
	vmov.32	s27, r5
	rev	r5, r5
L_aes_gcm_encrypt_arm32_crypto_done_nonce:
	vldm.32	r7!, {q0-q3}
	vldm.32	r7!, {q7-q13}
	# nr
	ldr	r12, [sp, #136]
	lsr	r10, r2, #4
	cmp	r12, #12
	blt	L_aes_gcm_encrypt_arm32_crypto_start_128
	bgt	L_aes_gcm_encrypt_arm32_crypto_start_256
	# AES_GCM_192
#ifndef NO_AES_192
	cmp	r10, #1
	blt	L_aes_gcm_encrypt_arm32_crypto_192_done
	beq	L_aes_gcm_encrypt_arm32_crypto_192_start_1
L_aes_gcm_encrypt_arm32_crypto_192_start_2:
	add	r8, r5, #1
	vmov.8	q4, q6
	add	r5, r5, #2
	vmov.8	q5, q6
	rev	r8, r8
	rev	r12, r5
	vmov	s19, r8
	vmov	s23, r12
	aese.8	q4, q0
	aesmc.8	q4, q4
	aese.8	q5, q0
	aesmc.8	q5, q5
	aese.8	q4, q1
	aesmc.8	q4, q4
	aese.8	q5, q1
	aesmc.8	q5, q5
	aese.8	q4, q2
	aesmc.8	q4, q4
	aese.8	q5, q2
	aesmc.8	q5, q5
	aese.8	q4, q3
	aesmc.8	q4, q4
	aese.8	q5, q3
	aesmc.8	q5, q5
	aese.8	q4, q7
	aesmc.8	q4, q4
	aese.8	q5, q7
	aesmc.8	q5, q5
	aese.8	q4, q8
	aesmc.8	q4, q4
	aese.8	q5, q8
	aesmc.8	q5, q5
	aese.8	q4, q9
	aesmc.8	q4, q4
	aese.8	q5, q9
	aesmc.8	q5, q5
	subs	r10, r10, #2
	aese.8	q4, q10
	aesmc.8	q4, q4
	aese.8	q5, q10
	aesmc.8	q5, q5
	aese.8	q4, q11
	aesmc.8	q4, q4
	aese.8	q5, q11
	aesmc.8	q5, q5
	aese.8	q4, q12
	aesmc.8	q4, q4
	aese.8	q5, q12
	aesmc.8	q5, q5
	vld1.32	{q14}, [r7]!
	aese.8	q4, q13
	aesmc.8	q4, q4
	aese.8	q5, q13
	aesmc.8	q5, q5
	vld1.32	{q15}, [r7]
	aese.8	q4, q14
	veor.8	q4, q4, q15
	aese.8	q5, q14
	veor.8	q5, q5, q15
	vld1.8	{q14-q15}, [r0]!
	sub	r7, r7, #16
	veor.8	q14, q14, q4
	veor.8	q15, q15, q5
	vst1.8	{q14-q15}, [r1]!
	cmp	r10, #1
	bgt	L_aes_gcm_encrypt_arm32_crypto_192_start_2
	blt	L_aes_gcm_encrypt_arm32_crypto_192_done
L_aes_gcm_encrypt_arm32_crypto_192_start_1:
	add	r5, r5, #1
	vmov.8	q4, q6
	rev	r8, r5
	vmov	s19, r8
	aese.8	q4, q0
	aesmc.8	q4, q4
	aese.8	q4, q1
	aesmc.8	q4, q4
	aese.8	q4, q2
	aesmc.8	q4, q4
	aese.8	q4, q3
	aesmc.8	q4, q4
	aese.8	q4, q7
	aesmc.8	q4, q4
	aese.8	q4, q8
	aesmc.8	q4, q4
	aese.8	q4, q9
	aesmc.8	q4, q4
	aese.8	q4, q10
	aesmc.8	q4, q4
	aese.8	q4, q11
	aesmc.8	q4, q4
	aese.8	q4, q12
	aesmc.8	q4, q4
	vld1.32	{q14}, [r7]!
	aese.8	q4, q13
	aesmc.8	q4, q4
	vld1.32	{q15}, [r7]
	aese.8	q4, q14
	veor.8	q4, q4, q15
	vld1.8	{q14}, [r0]!
	sub	r7, r7, #16
	veor.8	q14, q14, q4
	vst1.32	{q14}, [r1]!
L_aes_gcm_encrypt_arm32_crypto_192_done:
	ands	r11, r2, #15
	beq	L_aes_gcm_encrypt_arm32_crypto_192_partial_done
	veor.8	q14, q14, q14
	mov	r4, r11
	vst1.32	{q14}, [r9]
	cmp	r4, #4
	blt	L_aes_gcm_encrypt_arm32_crypto_192_start_sw
L_aes_gcm_encrypt_arm32_crypto_192_start_dw:
	ldr	lr, [r0], #4
	sub	r4, r4, #4
	str	lr, [r9], #4
	cmp	r4, #4
	bge	L_aes_gcm_encrypt_arm32_crypto_192_start_dw
L_aes_gcm_encrypt_arm32_crypto_192_start_sw:
	cmp	r4, #2
	blt	L_aes_gcm_encrypt_arm32_crypto_192_start_byte
	ldrh	lr, [r0], #2
	sub	r4, r4, #2
	strh	lr, [r9], #2
L_aes_gcm_encrypt_arm32_crypto_192_start_byte:
	cmp	r4, #1
	blt	L_aes_gcm_encrypt_arm32_crypto_192_end_bytes
	ldrb	lr, [r0], #1
	subs	r4, r4, #1
	strb	lr, [r9], #1
	bne	L_aes_gcm_encrypt_arm32_crypto_192_start_byte
L_aes_gcm_encrypt_arm32_crypto_192_end_bytes:
	sub	r9, r9, r11
	add	r5, r5, #1
	vmov.8	q4, q6
	rev	r8, r5
	vmov	s19, r8
	aese.8	q4, q0
	aesmc.8	q4, q4
	aese.8	q4, q1
	aesmc.8	q4, q4
	aese.8	q4, q2
	aesmc.8	q4, q4
	aese.8	q4, q3
	aesmc.8	q4, q4
	aese.8	q4, q7
	aesmc.8	q4, q4
	aese.8	q4, q8
	aesmc.8	q4, q4
	aese.8	q4, q9
	aesmc.8	q4, q4
	aese.8	q4, q10
	aesmc.8	q4, q4
	aese.8	q4, q11
	aesmc.8	q4, q4
	aese.8	q4, q12
	aesmc.8	q4, q4
	vld1.32	{q14}, [r7]!
	aese.8	q4, q13
	aesmc.8	q4, q4
	vld1.32	{q15}, [r7]
	aese.8	q4, q14
	veor.8	q4, q4, q15
	vld1.8	{q14}, [r9]
	sub	r7, r7, #16
	veor.8	q14, q14, q4
	vst1.32	{q14}, [r9]
	mov	r4, r11
	cmp	r4, #4
	blt	L_aes_gcm_encrypt_arm32_crypto_192_out_start_sw
L_aes_gcm_encrypt_arm32_crypto_192_out_start_dw:
	ldr	lr, [r9], #4
	sub	r4, r4, #4
	str	lr, [r1], #4
	cmp	r4, #4
	bge	L_aes_gcm_encrypt_arm32_crypto_192_out_start_dw
L_aes_gcm_encrypt_arm32_crypto_192_out_start_sw:
	cmp	r4, #2
	blt	L_aes_gcm_encrypt_arm32_crypto_192_out_start_byte
	ldrh	lr, [r9], #2
	sub	r4, r4, #2
	strh	lr, [r1], #2
L_aes_gcm_encrypt_arm32_crypto_192_out_start_byte:
	cmp	r4, #1
	blt	L_aes_gcm_encrypt_arm32_crypto_192_out_end_bytes
	ldrb	lr, [r9], #1
	subs	r4, r4, #1
	strb	lr, [r1], #1
	bne	L_aes_gcm_encrypt_arm32_crypto_192_out_start_byte
L_aes_gcm_encrypt_arm32_crypto_192_out_end_bytes:
L_aes_gcm_encrypt_arm32_crypto_192_partial_done:
	# Finish
	add	r8, r2, #15
	sub	r8, r5, r8, lsr #4
	rev	r8, r8
	vmov.32	s27, r8
	aese.8	q6, q0
	aesmc.8	q6, q6
	aese.8	q6, q1
	aesmc.8	q6, q6
	aese.8	q6, q2
	aesmc.8	q6, q6
	aese.8	q6, q3
	aesmc.8	q6, q6
	aese.8	q6, q7
	aesmc.8	q6, q6
	aese.8	q6, q8
	aesmc.8	q6, q6
	aese.8	q6, q9
	aesmc.8	q6, q6
	aese.8	q6, q10
	aesmc.8	q6, q6
	aese.8	q6, q11
	aesmc.8	q6, q6
	aese.8	q6, q12
	aesmc.8	q6, q6
	vld1.32	{q14}, [r7]!
	aese.8	q6, q13
	aesmc.8	q6, q6
	vld1.32	{q15}, [r7]
	aese.8	q6, q14
	veor.8	q6, q6, q15
	sub	r7, r7, #16
#endif /* !NO_AES_192 */
	b	L_aes_gcm_encrypt_arm32_crypto_done_enc
	# AES_GCM_256
L_aes_gcm_encrypt_arm32_crypto_start_256:
#ifndef NO_AES_256
	cmp	r10, #1
	blt	L_aes_gcm_encrypt_arm32_crypto_256_done
	beq	L_aes_gcm_encrypt_arm32_crypto_256_start_1
L_aes_gcm_encrypt_arm32_crypto_256_start_2:
	add	r8, r5, #1
	vmov.8	q4, q6
	add	r5, r5, #2
	vmov.8	q5, q6
	rev	r8, r8
	rev	r12, r5
	vmov	s19, r8
	vmov	s23, r12
	aese.8	q4, q0
	aesmc.8	q4, q4
	aese.8	q5, q0
	aesmc.8	q5, q5
	aese.8	q4, q1
	aesmc.8	q4, q4
	aese.8	q5, q1
	aesmc.8	q5, q5
	aese.8	q4, q2
	aesmc.8	q4, q4
	aese.8	q5, q2
	aesmc.8	q5, q5
	aese.8	q4, q3
	aesmc.8	q4, q4
	aese.8	q5, q3
	aesmc.8	q5, q5
	aese.8	q4, q7
	aesmc.8	q4, q4
	aese.8	q5, q7
	aesmc.8	q5, q5
	aese.8	q4, q8
	aesmc.8	q4, q4
	aese.8	q5, q8
	aesmc.8	q5, q5
	aese.8	q4, q9
	aesmc.8	q4, q4
	aese.8	q5, q9
	aesmc.8	q5, q5
	subs	r10, r10, #2
	aese.8	q4, q10
	aesmc.8	q4, q4
	aese.8	q5, q10
	aesmc.8	q5, q5
	aese.8	q4, q11
	aesmc.8	q4, q4
	aese.8	q5, q11
	aesmc.8	q5, q5
	aese.8	q4, q12
	aesmc.8	q4, q4
	aese.8	q5, q12
	aesmc.8	q5, q5
	vld1.32	{q14}, [r7]!
	aese.8	q4, q13
	aesmc.8	q4, q4
	aese.8	q5, q13
	aesmc.8	q5, q5
	vld1.32	{q15}, [r7]!
	aese.8	q4, q14
	aesmc.8	q4, q4
	aese.8	q5, q14
	aesmc.8	q5, q5
	vld1.32	{q14}, [r7]!
	aese.8	q4, q15
	aesmc.8	q4, q4
	aese.8	q5, q15
	aesmc.8	q5, q5
	vld1.32	{q15}, [r7]
	aese.8	q4, q14
	veor.8	q4, q4, q15
	aese.8	q5, q14
	veor.8	q5, q5, q15
	vld1.8	{q14-q15}, [r0]!
	sub	r7, r7, #48
	veor.8	q14, q14, q4
	veor.8	q15, q15, q5
	vst1.8	{q14-q15}, [r1]!
	cmp	r10, #1
	bgt	L_aes_gcm_encrypt_arm32_crypto_256_start_2
	blt	L_aes_gcm_encrypt_arm32_crypto_256_done
L_aes_gcm_encrypt_arm32_crypto_256_start_1:
	add	r5, r5, #1
	vmov.8	q4, q6
	rev	r8, r5
	vmov	s19, r8
	aese.8	q4, q0
	aesmc.8	q4, q4
	aese.8	q4, q1
	aesmc.8	q4, q4
	aese.8	q4, q2
	aesmc.8	q4, q4
	aese.8	q4, q3
	aesmc.8	q4, q4
	aese.8	q4, q7
	aesmc.8	q4, q4
	aese.8	q4, q8
	aesmc.8	q4, q4
	aese.8	q4, q9
	aesmc.8	q4, q4
	aese.8	q4, q10
	aesmc.8	q4, q4
	aese.8	q4, q11
	aesmc.8	q4, q4
	aese.8	q4, q12
	aesmc.8	q4, q4
	vld1.32	{q14}, [r7]!
	aese.8	q4, q13
	aesmc.8	q4, q4
	vld1.32	{q15}, [r7]!
	aese.8	q4, q14
	aesmc.8	q4, q4
	vld1.32	{q14}, [r7]!
	aese.8	q4, q15
	aesmc.8	q4, q4
	vld1.32	{q15}, [r7]
	aese.8	q4, q14
	veor.8	q4, q4, q15
	vld1.8	{q14}, [r0]!
	sub	r7, r7, #48
	veor.8	q14, q14, q4
	vst1.32	{q14}, [r1]!
L_aes_gcm_encrypt_arm32_crypto_256_done:
	ands	r11, r2, #15
	beq	L_aes_gcm_encrypt_arm32_crypto_256_partial_done
	veor.8	q14, q14, q14
	mov	r4, r11
	vst1.32	{q14}, [r9]
	cmp	r4, #4
	blt	L_aes_gcm_encrypt_arm32_crypto_256_start_sw
L_aes_gcm_encrypt_arm32_crypto_256_start_dw:
	ldr	lr, [r0], #4
	sub	r4, r4, #4
	str	lr, [r9], #4
	cmp	r4, #4
	bge	L_aes_gcm_encrypt_arm32_crypto_256_start_dw
L_aes_gcm_encrypt_arm32_crypto_256_start_sw:
	cmp	r4, #2
	blt	L_aes_gcm_encrypt_arm32_crypto_256_start_byte
	ldrh	lr, [r0], #2
	sub	r4, r4, #2
	strh	lr, [r9], #2
L_aes_gcm_encrypt_arm32_crypto_256_start_byte:
	cmp	r4, #1
	blt	L_aes_gcm_encrypt_arm32_crypto_256_end_bytes
	ldrb	lr, [r0], #1
	subs	r4, r4, #1
	strb	lr, [r9], #1
	bne	L_aes_gcm_encrypt_arm32_crypto_256_start_byte
L_aes_gcm_encrypt_arm32_crypto_256_end_bytes:
	sub	r9, r9, r11
	add	r5, r5, #1
	vmov.8	q4, q6
	rev	r8, r5
	vmov	s19, r8
	aese.8	q4, q0
	aesmc.8	q4, q4
	aese.8	q4, q1
	aesmc.8	q4, q4
	aese.8	q4, q2
	aesmc.8	q4, q4
	aese.8	q4, q3
	aesmc.8	q4, q4
	aese.8	q4, q7
	aesmc.8	q4, q4
	aese.8	q4, q8
	aesmc.8	q4, q4
	aese.8	q4, q9
	aesmc.8	q4, q4
	aese.8	q4, q10
	aesmc.8	q4, q4
	aese.8	q4, q11
	aesmc.8	q4, q4
	aese.8	q4, q12
	aesmc.8	q4, q4
	vld1.32	{q14}, [r7]!
	aese.8	q4, q13
	aesmc.8	q4, q4
	vld1.32	{q15}, [r7]!
	aese.8	q4, q14
	aesmc.8	q4, q4
	vld1.32	{q14}, [r7]!
	aese.8	q4, q15
	aesmc.8	q4, q4
	vld1.32	{q15}, [r7]
	aese.8	q4, q14
	veor.8	q4, q4, q15
	vld1.8	{q14}, [r9]
	sub	r7, r7, #48
	veor.8	q14, q14, q4
	vst1.32	{q14}, [r9]
	mov	r4, r11
	cmp	r4, #4
	blt	L_aes_gcm_encrypt_arm32_crypto_256_out_start_sw
L_aes_gcm_encrypt_arm32_crypto_256_out_start_dw:
	ldr	lr, [r9], #4
	sub	r4, r4, #4
	str	lr, [r1], #4
	cmp	r4, #4
	bge	L_aes_gcm_encrypt_arm32_crypto_256_out_start_dw
L_aes_gcm_encrypt_arm32_crypto_256_out_start_sw:
	cmp	r4, #2
	blt	L_aes_gcm_encrypt_arm32_crypto_256_out_start_byte
	ldrh	lr, [r9], #2
	sub	r4, r4, #2
	strh	lr, [r1], #2
L_aes_gcm_encrypt_arm32_crypto_256_out_start_byte:
	cmp	r4, #1
	blt	L_aes_gcm_encrypt_arm32_crypto_256_out_end_bytes
	ldrb	lr, [r9], #1
	subs	r4, r4, #1
	strb	lr, [r1], #1
	bne	L_aes_gcm_encrypt_arm32_crypto_256_out_start_byte
L_aes_gcm_encrypt_arm32_crypto_256_out_end_bytes:
L_aes_gcm_encrypt_arm32_crypto_256_partial_done:
	# Finish
	add	r8, r2, #15
	sub	r8, r5, r8, lsr #4
	rev	r8, r8
	vmov.32	s27, r8
	aese.8	q6, q0
	aesmc.8	q6, q6
	aese.8	q6, q1
	aesmc.8	q6, q6
	aese.8	q6, q2
	aesmc.8	q6, q6
	aese.8	q6, q3
	aesmc.8	q6, q6
	aese.8	q6, q7
	aesmc.8	q6, q6
	aese.8	q6, q8
	aesmc.8	q6, q6
	aese.8	q6, q9
	aesmc.8	q6, q6
	aese.8	q6, q10
	aesmc.8	q6, q6
	aese.8	q6, q11
	aesmc.8	q6, q6
	aese.8	q6, q12
	aesmc.8	q6, q6
	vld1.32	{q14}, [r7]!
	aese.8	q6, q13
	aesmc.8	q6, q6
	vld1.32	{q15}, [r7]!
	aese.8	q6, q14
	aesmc.8	q6, q6
	vld1.32	{q14}, [r7]!
	aese.8	q6, q15
	aesmc.8	q6, q6
	vld1.32	{q15}, [r7]
	aese.8	q6, q14
	veor.8	q6, q6, q15
	sub	r7, r7, #48
#endif /* !NO_AES_256 */
	b	L_aes_gcm_encrypt_arm32_crypto_done_enc
	# AES_GCM_128
L_aes_gcm_encrypt_arm32_crypto_start_128:
#ifndef NO_AES_128
	cmp	r10, #1
	blt	L_aes_gcm_encrypt_arm32_crypto_128_done
	beq	L_aes_gcm_encrypt_arm32_crypto_128_start_1
L_aes_gcm_encrypt_arm32_crypto_128_start_2:
	add	r8, r5, #1
	vmov.8	q4, q6
	add	r5, r5, #2
	vmov.8	q5, q6
	rev	r8, r8
	rev	r12, r5
	vmov	s19, r8
	vmov	s23, r12
	aese.8	q4, q0
	aesmc.8	q4, q4
	aese.8	q5, q0
	aesmc.8	q5, q5
	aese.8	q4, q1
	aesmc.8	q4, q4
	aese.8	q5, q1
	aesmc.8	q5, q5
	aese.8	q4, q2
	aesmc.8	q4, q4
	aese.8	q5, q2
	aesmc.8	q5, q5
	aese.8	q4, q3
	aesmc.8	q4, q4
	aese.8	q5, q3
	aesmc.8	q5, q5
	aese.8	q4, q7
	aesmc.8	q4, q4
	aese.8	q5, q7
	aesmc.8	q5, q5
	aese.8	q4, q8
	aesmc.8	q4, q4
	aese.8	q5, q8
	aesmc.8	q5, q5
	aese.8	q4, q9
	aesmc.8	q4, q4
	aese.8	q5, q9
	aesmc.8	q5, q5
	subs	r10, r10, #2
	aese.8	q4, q10
	aesmc.8	q4, q4
	aese.8	q5, q10
	aesmc.8	q5, q5
	aese.8	q4, q11
	aesmc.8	q4, q4
	aese.8	q5, q11
	aesmc.8	q5, q5
	vld1.8	{q14-q15}, [r0]!
	aese.8	q4, q12
	veor.8	q4, q4, q13
	aese.8	q5, q12
	veor.8	q5, q5, q13
	veor.8	q14, q14, q4
	veor.8	q15, q15, q5
	vst1.8	{q14-q15}, [r1]!
	cmp	r10, #1
	bgt	L_aes_gcm_encrypt_arm32_crypto_128_start_2
	blt	L_aes_gcm_encrypt_arm32_crypto_128_done
L_aes_gcm_encrypt_arm32_crypto_128_start_1:
	add	r5, r5, #1
	vmov.8	q4, q6
	rev	r8, r5
	vmov	s19, r8
	aese.8	q4, q0
	aesmc.8	q4, q4
	aese.8	q4, q1
	aesmc.8	q4, q4
	aese.8	q4, q2
	aesmc.8	q4, q4
	aese.8	q4, q3
	aesmc.8	q4, q4
	aese.8	q4, q7
	aesmc.8	q4, q4
	aese.8	q4, q8
	aesmc.8	q4, q4
	aese.8	q4, q9
	aesmc.8	q4, q4
	aese.8	q4, q10
	aesmc.8	q4, q4
	aese.8	q4, q11
	aesmc.8	q4, q4
	vld1.8	{q14}, [r0]!
	aese.8	q4, q12
	veor.8	q4, q4, q13
	veor.8	q14, q14, q4
	vst1.32	{q14}, [r1]!
L_aes_gcm_encrypt_arm32_crypto_128_done:
	ands	r11, r2, #15
	beq	L_aes_gcm_encrypt_arm32_crypto_128_partial_done
	veor.8	q14, q14, q14
	mov	r4, r11
	vst1.32	{q14}, [r9]
	cmp	r4, #4
	blt	L_aes_gcm_encrypt_arm32_crypto_128_start_sw
L_aes_gcm_encrypt_arm32_crypto_128_start_dw:
	ldr	lr, [r0], #4
	sub	r4, r4, #4
	str	lr, [r9], #4
	cmp	r4, #4
	bge	L_aes_gcm_encrypt_arm32_crypto_128_start_dw
L_aes_gcm_encrypt_arm32_crypto_128_start_sw:
	cmp	r4, #2
	blt	L_aes_gcm_encrypt_arm32_crypto_128_start_byte
	ldrh	lr, [r0], #2
	sub	r4, r4, #2
	strh	lr, [r9], #2
L_aes_gcm_encrypt_arm32_crypto_128_start_byte:
	cmp	r4, #1
	blt	L_aes_gcm_encrypt_arm32_crypto_128_end_bytes
	ldrb	lr, [r0], #1
	subs	r4, r4, #1
	strb	lr, [r9], #1
	bne	L_aes_gcm_encrypt_arm32_crypto_128_start_byte
L_aes_gcm_encrypt_arm32_crypto_128_end_bytes:
	sub	r9, r9, r11
	add	r5, r5, #1
	vmov.8	q4, q6
	rev	r8, r5
	vmov	s19, r8
	aese.8	q4, q0
	aesmc.8	q4, q4
	aese.8	q4, q1
	aesmc.8	q4, q4
	aese.8	q4, q2
	aesmc.8	q4, q4
	aese.8	q4, q3
	aesmc.8	q4, q4
	aese.8	q4, q7
	aesmc.8	q4, q4
	aese.8	q4, q8
	aesmc.8	q4, q4
	aese.8	q4, q9
	aesmc.8	q4, q4
	aese.8	q4, q10
	aesmc.8	q4, q4
	aese.8	q4, q11
	aesmc.8	q4, q4
	vld1.8	{q14}, [r9]
	aese.8	q4, q12
	veor.8	q4, q4, q13
	veor.8	q14, q14, q4
	vst1.32	{q14}, [r9]
	mov	r4, r11
	cmp	r4, #4
	blt	L_aes_gcm_encrypt_arm32_crypto_128_out_start_sw
L_aes_gcm_encrypt_arm32_crypto_128_out_start_dw:
	ldr	lr, [r9], #4
	sub	r4, r4, #4
	str	lr, [r1], #4
	cmp	r4, #4
	bge	L_aes_gcm_encrypt_arm32_crypto_128_out_start_dw
L_aes_gcm_encrypt_arm32_crypto_128_out_start_sw:
	cmp	r4, #2
	blt	L_aes_gcm_encrypt_arm32_crypto_128_out_start_byte
	ldrh	lr, [r9], #2
	sub	r4, r4, #2
	strh	lr, [r1], #2
L_aes_gcm_encrypt_arm32_crypto_128_out_start_byte:
	cmp	r4, #1
	blt	L_aes_gcm_encrypt_arm32_crypto_128_out_end_bytes
	ldrb	lr, [r9], #1
	subs	r4, r4, #1
	strb	lr, [r1], #1
	bne	L_aes_gcm_encrypt_arm32_crypto_128_out_start_byte
L_aes_gcm_encrypt_arm32_crypto_128_out_end_bytes:
L_aes_gcm_encrypt_arm32_crypto_128_partial_done:
	# Finish
	add	r8, r2, #15
	sub	r8, r5, r8, lsr #4
	rev	r8, r8
	vmov.32	s27, r8
	aese.8	q6, q0
	aesmc.8	q6, q6
	aese.8	q6, q1
	aesmc.8	q6, q6
	aese.8	q6, q2
	aesmc.8	q6, q6
	aese.8	q6, q3
	aesmc.8	q6, q6
	aese.8	q6, q7
	aesmc.8	q6, q6
	aese.8	q6, q8
	aesmc.8	q6, q6
	aese.8	q6, q9
	aesmc.8	q6, q6
	aese.8	q6, q10
	aesmc.8	q6, q6
	aese.8	q6, q11
	aesmc.8	q6, q6
	aese.8	q6, q12
	veor.8	q6, q6, q13
#endif /* !NO_AES_128 */
L_aes_gcm_encrypt_arm32_crypto_done_enc:
	# aadSz
	ldr	r6, [sp, #116]
	# gcm_h
	ldr	r8, [sp, #124]
	sub	r1, r1, r2
	vmov.i8	q13, #0x87
	veor.8	q7, q7, q7
	vshr.u64	q13, q13, #56
	vld1.32	{q8}, [r8]
	orr	r10, r6, r2
	cmp	r10, #32
	blt	L_aes_gcm_encrypt_arm32_crypto_h_done
	# Square H => H^2
	vmull.p64	q1, d17, d17
	vmull.p64	q0, d16, d16
	vmull.p64	q9, d3, d27
	veor.8	d2, d2, d19
	veor.8	d1, d1, d18
	vmull.p64	q9, d2, d26
	veor.8	q9, q9, q0
	cmp	r10, #0x40
	blt	L_aes_gcm_encrypt_arm32_crypto_h_done
	# Multiply H and H^2  => H^3
	vmull.p64	q2, d17, d18
	vmull.p64	q3, d16, d19
	vmull.p64	q0, d16, d18
	vmull.p64	q1, d17, d19
	veor.8	q2, q2, q3
	#   Reduce
	vmull.p64	q10, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d21
	veor.8	d1, d1, d20
	vmull.p64	q10, d2, d26
	veor.8	q10, q10, q0
	# Square H^2 => H^4
	vmull.p64	q1, d19, d19
	vmull.p64	q0, d18, d18
	vmull.p64	q11, d3, d27
	veor.8	d2, d2, d23
	veor.8	d1, d1, d22
	vmull.p64	q11, d2, d26
	veor.8	q11, q11, q0
	# Done
L_aes_gcm_encrypt_arm32_crypto_h_done:
	# aad
	ldr	r5, [sp, #112]
	lsr	r10, r6, #4
	cmp	r10, #1
	blt	L_aes_gcm_encrypt_arm32_crypto_aad_done
	beq	L_aes_gcm_encrypt_arm32_crypto_aad_start_1
	cmp	r10, #4
	blt	L_aes_gcm_encrypt_arm32_crypto_aad_start_2
L_aes_gcm_encrypt_arm32_crypto_aad_start_4:
	vldm	r5!, {q0-q2}
	vmov.i8	q12, #0x55
	vmov.i8	q5, #51
	vshl.u8	q14, q0, #1
	vshl.u8	q15, q1, #1
	vshl.u8	q4, q2, #1
	ldr	lr, [r5], #4
	vshr.u8	q0, q0, #1
	vshr.u8	q1, q1, #1
	vshr.u8	q2, q2, #1
	ldr	r4, [r5], #4
	vbit.8	q14, q0, q12
	vbit.8	q15, q1, q12
	vbit.8	q4, q2, q12
	ldr	r8, [r5], #4
	vshl.u8	q0, q14, #2
	vshl.u8	q1, q15, #2
	vshl.u8	q2, q4, #2
	ldr	r12, [r5], #4
	vshr.u8	q14, q14, #2
	vshr.u8	q15, q15, #2
	vshr.u8	q4, q4, #2
	rbit	lr, lr
	vbit.8	q0, q14, q5
	rbit	r4, r4
	vbit.8	q1, q15, q5
	rbit	r8, r8
	vbit.8	q2, q4, q5
	rbit	r12, r12
	vshl.u8	q14, q0, #4
	rev	lr, lr
	vshl.u8	q15, q1, #4
	rev	r4, r4
	vshl.u8	q4, q2, #4
	rev	r8, r8
	vsri.u8	q14, q0, #4
	rev	r12, r12
	vsri.u8	q15, q1, #4
	vsri.u8	q4, q2, #4
	vmov	d10, lr, r4
	vmov	d11, r8, r12
	veor.8	q12, q7, q14
	#   X  = C * H^1
	vmull.p64	q2, d11, d16
	vmull.p64	q7, d10, d17
	vmull.p64	q0, d10, d16
	vmull.p64	q1, d11, d17
	veor.8	q2, q2, q7
	#   X += C * H^2
	vmull.p64	q3, d8, d18
	vmull.p64	q7, d9, d19
	veor.8	q0, q0, q3
	veor.8	q1, q1, q7
	vmull.p64	q3, d9, d18
	vmull.p64	q7, d8, d19
	veor.8	q2, q2, q3
	veor.8	q2, q2, q7
	#   X += C * H^3
	vmull.p64	q3, d30, d20
	vmull.p64	q7, d31, d21
	veor.8	q0, q0, q3
	veor.8	q1, q1, q7
	vmull.p64	q3, d31, d20
	vmull.p64	q7, d30, d21
	veor.8	q2, q2, q3
	veor.8	q2, q2, q7
	#   X += C * H^4
	vmull.p64	q3, d24, d22
	vmull.p64	q7, d25, d23
	veor.8	q0, q0, q3
	veor.8	q1, q1, q7
	vmull.p64	q3, d25, d22
	vmull.p64	q7, d24, d23
	veor.8	q2, q2, q3
	veor.8	q2, q2, q7
	#   Reduce
	vmull.p64	q7, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d15
	veor.8	d1, d1, d14
	vmull.p64	q7, d2, d26
	veor.8	q7, q7, q0
	# Done GHASH
	sub	r10, r10, #4
	cmp	r10, #4
	bge	L_aes_gcm_encrypt_arm32_crypto_aad_start_4
	cmp	r10, #1
	blt	L_aes_gcm_encrypt_arm32_crypto_aad_done
	beq	L_aes_gcm_encrypt_arm32_crypto_aad_start_1
L_aes_gcm_encrypt_arm32_crypto_aad_start_2:
	vld1.32	{q14-q15}, [r5]!
	vmov.i8	q12, #0x55
	vshl.u8	q0, q14, #1
	vshl.u8	q1, q15, #1
	vshr.u8	q14, q14, #1
	vshr.u8	q15, q15, #1
	vbif.8	q14, q0, q12
	vbif.8	q15, q1, q12
	vmov.i8	q12, #51
	vshl.u8	q0, q14, #2
	vshl.u8	q1, q15, #2
	vshr.u8	q14, q14, #2
	vshr.u8	q15, q15, #2
	vbit.8	q0, q14, q12
	vbit.8	q1, q15, q12
	vshl.u8	q14, q0, #4
	vshl.u8	q15, q1, #4
	vsri.u8	q14, q0, #4
	vsri.u8	q15, q1, #4
	veor.8	q12, q7, q14
	#   X  = C * H^1
	vmull.p64	q2, d31, d16
	vmull.p64	q7, d30, d17
	vmull.p64	q0, d30, d16
	vmull.p64	q1, d31, d17
	veor.8	q2, q2, q7
	#   X += C * H^2
	vmull.p64	q3, d24, d18
	vmull.p64	q7, d25, d19
	veor.8	q0, q0, q3
	veor.8	q1, q1, q7
	vmull.p64	q3, d25, d18
	vmull.p64	q7, d24, d19
	veor.8	q2, q2, q3
	veor.8	q2, q2, q7
	#   Reduce
	vmull.p64	q7, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d15
	veor.8	d1, d1, d14
	vmull.p64	q7, d2, d26
	veor.8	q7, q7, q0
	# Done GHASH
	sub	r10, r10, #2
	cmp	r10, #0
	beq	L_aes_gcm_encrypt_arm32_crypto_aad_done
L_aes_gcm_encrypt_arm32_crypto_aad_start_1:
	vld1.32	{q14}, [r5]!
	vmov.i8	q12, #0x55
	vshl.u8	q0, q14, #1
	vshr.u8	q14, q14, #1
	vbif.8	q14, q0, q12
	vmov.i8	q12, #51
	vshl.u8	q0, q14, #2
	vshr.u8	q14, q14, #2
	vbit.8	q0, q14, q12
	vshl.u8	q14, q0, #4
	vsri.u8	q14, q0, #4
	veor.8	q12, q7, q14
	#   X  = C * H^1
	vmull.p64	q2, d25, d16
	vmull.p64	q7, d24, d17
	vmull.p64	q0, d24, d16
	vmull.p64	q1, d25, d17
	veor.8	q2, q2, q7
	#   Reduce
	vmull.p64	q7, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d15
	veor.8	d1, d1, d14
	vmull.p64	q7, d2, d26
	veor.8	q7, q7, q0
	# Done GHASH
L_aes_gcm_encrypt_arm32_crypto_aad_done:
	ands	r11, r6, #15
	beq	L_aes_gcm_encrypt_arm32_crypto_aad_partial_done
	veor.8	q0, q0, q0
	mov	r12, r11
	vst1.32	{q0}, [r9]
	cmp	r12, #4
	blt	L_aes_gcm_encrypt_arm32_crypto_aad_start_sw
L_aes_gcm_encrypt_arm32_crypto_aad_start_dw:
	ldr	r8, [r5], #4
	sub	r12, r12, #4
	str	r8, [r9], #4
	cmp	r12, #4
	bge	L_aes_gcm_encrypt_arm32_crypto_aad_start_dw
L_aes_gcm_encrypt_arm32_crypto_aad_start_sw:
	cmp	r12, #2
	blt	L_aes_gcm_encrypt_arm32_crypto_aad_start_byte
	ldrh	r8, [r5], #2
	sub	r12, r12, #2
	strh	r8, [r9], #2
L_aes_gcm_encrypt_arm32_crypto_aad_start_byte:
	cmp	r12, #1
	blt	L_aes_gcm_encrypt_arm32_crypto_aad_end_bytes
	ldrb	r8, [r5], #1
	subs	r12, r12, #1
	strb	r8, [r9], #1
	bne	L_aes_gcm_encrypt_arm32_crypto_aad_start_byte
L_aes_gcm_encrypt_arm32_crypto_aad_end_bytes:
	sub	r9, r9, r11
	vld1.32	{q14}, [r9]
	vmov.i8	q12, #0x55
	vshl.u8	q0, q14, #1
	vshr.u8	q14, q14, #1
	vbif.8	q14, q0, q12
	vmov.i8	q12, #51
	vshl.u8	q0, q14, #2
	vshr.u8	q14, q14, #2
	vbit.8	q0, q14, q12
	vshl.u8	q14, q0, #4
	vsri.u8	q14, q0, #4
	veor.8	q12, q7, q14
	#   X  = C * H^1
	vmull.p64	q2, d25, d16
	vmull.p64	q7, d24, d17
	vmull.p64	q0, d24, d16
	vmull.p64	q1, d25, d17
	veor.8	q2, q2, q7
	#   Reduce
	vmull.p64	q7, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d15
	veor.8	d1, d1, d14
	vmull.p64	q7, d2, d26
	veor.8	q7, q7, q0
	# Done GHASH
L_aes_gcm_encrypt_arm32_crypto_aad_partial_done:
	# out
	lsr	r10, r2, #4
	cmp	r10, #1
	blt	L_aes_gcm_encrypt_arm32_crypto_out_done
	beq	L_aes_gcm_encrypt_arm32_crypto_out_start_1
	cmp	r10, #4
	blt	L_aes_gcm_encrypt_arm32_crypto_out_start_2
L_aes_gcm_encrypt_arm32_crypto_out_start_4:
	vldm	r1!, {q0-q2}
	vmov.i8	q12, #0x55
	vmov.i8	q5, #51
	vshl.u8	q14, q0, #1
	vshl.u8	q15, q1, #1
	vshl.u8	q4, q2, #1
	ldr	lr, [r1], #4
	vshr.u8	q0, q0, #1
	vshr.u8	q1, q1, #1
	vshr.u8	q2, q2, #1
	ldr	r4, [r1], #4
	vbit.8	q14, q0, q12
	vbit.8	q15, q1, q12
	vbit.8	q4, q2, q12
	ldr	r8, [r1], #4
	vshl.u8	q0, q14, #2
	vshl.u8	q1, q15, #2
	vshl.u8	q2, q4, #2
	ldr	r12, [r1], #4
	vshr.u8	q14, q14, #2
	vshr.u8	q15, q15, #2
	vshr.u8	q4, q4, #2
	rbit	lr, lr
	vbit.8	q0, q14, q5
	rbit	r4, r4
	vbit.8	q1, q15, q5
	rbit	r8, r8
	vbit.8	q2, q4, q5
	rbit	r12, r12
	vshl.u8	q14, q0, #4
	rev	lr, lr
	vshl.u8	q15, q1, #4
	rev	r4, r4
	vshl.u8	q4, q2, #4
	rev	r8, r8
	vsri.u8	q14, q0, #4
	rev	r12, r12
	vsri.u8	q15, q1, #4
	vsri.u8	q4, q2, #4
	vmov	d10, lr, r4
	vmov	d11, r8, r12
	veor.8	q12, q7, q14
	#   X  = C * H^1
	vmull.p64	q2, d11, d16
	vmull.p64	q7, d10, d17
	vmull.p64	q0, d10, d16
	vmull.p64	q1, d11, d17
	veor.8	q2, q2, q7
	#   X += C * H^2
	vmull.p64	q3, d8, d18
	vmull.p64	q7, d9, d19
	veor.8	q0, q0, q3
	veor.8	q1, q1, q7
	vmull.p64	q3, d9, d18
	vmull.p64	q7, d8, d19
	veor.8	q2, q2, q3
	veor.8	q2, q2, q7
	#   X += C * H^3
	vmull.p64	q3, d30, d20
	vmull.p64	q7, d31, d21
	veor.8	q0, q0, q3
	veor.8	q1, q1, q7
	vmull.p64	q3, d31, d20
	vmull.p64	q7, d30, d21
	veor.8	q2, q2, q3
	veor.8	q2, q2, q7
	#   X += C * H^4
	vmull.p64	q3, d24, d22
	vmull.p64	q7, d25, d23
	veor.8	q0, q0, q3
	veor.8	q1, q1, q7
	vmull.p64	q3, d25, d22
	vmull.p64	q7, d24, d23
	veor.8	q2, q2, q3
	veor.8	q2, q2, q7
	#   Reduce
	vmull.p64	q7, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d15
	veor.8	d1, d1, d14
	vmull.p64	q7, d2, d26
	veor.8	q7, q7, q0
	# Done GHASH
	sub	r10, r10, #4
	cmp	r10, #4
	bge	L_aes_gcm_encrypt_arm32_crypto_out_start_4
	cmp	r10, #1
	blt	L_aes_gcm_encrypt_arm32_crypto_out_done
	beq	L_aes_gcm_encrypt_arm32_crypto_out_start_1
L_aes_gcm_encrypt_arm32_crypto_out_start_2:
	vld1.32	{q14-q15}, [r1]!
	vmov.i8	q12, #0x55
	vshl.u8	q0, q14, #1
	vshl.u8	q1, q15, #1
	vshr.u8	q14, q14, #1
	vshr.u8	q15, q15, #1
	vbif.8	q14, q0, q12
	vbif.8	q15, q1, q12
	vmov.i8	q12, #51
	vshl.u8	q0, q14, #2
	vshl.u8	q1, q15, #2
	vshr.u8	q14, q14, #2
	vshr.u8	q15, q15, #2
	vbit.8	q0, q14, q12
	vbit.8	q1, q15, q12
	vshl.u8	q14, q0, #4
	vshl.u8	q15, q1, #4
	vsri.u8	q14, q0, #4
	vsri.u8	q15, q1, #4
	veor.8	q12, q7, q14
	#   X  = C * H^1
	vmull.p64	q2, d31, d16
	vmull.p64	q7, d30, d17
	vmull.p64	q0, d30, d16
	vmull.p64	q1, d31, d17
	veor.8	q2, q2, q7
	#   X += C * H^2
	vmull.p64	q3, d24, d18
	vmull.p64	q7, d25, d19
	veor.8	q0, q0, q3
	veor.8	q1, q1, q7
	vmull.p64	q3, d25, d18
	vmull.p64	q7, d24, d19
	veor.8	q2, q2, q3
	veor.8	q2, q2, q7
	#   Reduce
	vmull.p64	q7, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d15
	veor.8	d1, d1, d14
	vmull.p64	q7, d2, d26
	veor.8	q7, q7, q0
	# Done GHASH
	sub	r10, r10, #2
	cmp	r10, #0
	beq	L_aes_gcm_encrypt_arm32_crypto_out_done
L_aes_gcm_encrypt_arm32_crypto_out_start_1:
	vld1.32	{q14}, [r1]!
	vmov.i8	q12, #0x55
	vshl.u8	q0, q14, #1
	vshr.u8	q14, q14, #1
	vbif.8	q14, q0, q12
	vmov.i8	q12, #51
	vshl.u8	q0, q14, #2
	vshr.u8	q14, q14, #2
	vbit.8	q0, q14, q12
	vshl.u8	q14, q0, #4
	vsri.u8	q14, q0, #4
	veor.8	q12, q7, q14
	#   X  = C * H^1
	vmull.p64	q2, d25, d16
	vmull.p64	q7, d24, d17
	vmull.p64	q0, d24, d16
	vmull.p64	q1, d25, d17
	veor.8	q2, q2, q7
	#   Reduce
	vmull.p64	q7, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d15
	veor.8	d1, d1, d14
	vmull.p64	q7, d2, d26
	veor.8	q7, q7, q0
	# Done GHASH
L_aes_gcm_encrypt_arm32_crypto_out_done:
	ands	r11, r2, #15
	beq	L_aes_gcm_encrypt_arm32_crypto_out_partial_done
	veor.8	q0, q0, q0
	mov	r12, r11
	vst1.32	{q0}, [r9]
	cmp	r12, #4
	blt	L_aes_gcm_encrypt_arm32_crypto_out_start_sw
L_aes_gcm_encrypt_arm32_crypto_out_start_dw:
	ldr	r8, [r1], #4
	sub	r12, r12, #4
	str	r8, [r9], #4
	cmp	r12, #4
	bge	L_aes_gcm_encrypt_arm32_crypto_out_start_dw
L_aes_gcm_encrypt_arm32_crypto_out_start_sw:
	cmp	r12, #2
	blt	L_aes_gcm_encrypt_arm32_crypto_out_start_byte
	ldrh	r8, [r1], #2
	sub	r12, r12, #2
	strh	r8, [r9], #2
L_aes_gcm_encrypt_arm32_crypto_out_start_byte:
	cmp	r12, #1
	blt	L_aes_gcm_encrypt_arm32_crypto_out_end_bytes
	ldrb	r8, [r1], #1
	subs	r12, r12, #1
	strb	r8, [r9], #1
	bne	L_aes_gcm_encrypt_arm32_crypto_out_start_byte
L_aes_gcm_encrypt_arm32_crypto_out_end_bytes:
	sub	r9, r9, r11
	vld1.32	{q14}, [r9]
	vmov.i8	q12, #0x55
	vshl.u8	q0, q14, #1
	vshr.u8	q14, q14, #1
	vbif.8	q14, q0, q12
	vmov.i8	q12, #51
	vshl.u8	q0, q14, #2
	vshr.u8	q14, q14, #2
	vbit.8	q0, q14, q12
	vshl.u8	q14, q0, #4
	vsri.u8	q14, q0, #4
	veor.8	q12, q7, q14
	#   X  = C * H^1
	vmull.p64	q2, d25, d16
	vmull.p64	q7, d24, d17
	vmull.p64	q0, d24, d16
	vmull.p64	q1, d25, d17
	veor.8	q2, q2, q7
	#   Reduce
	vmull.p64	q7, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d15
	veor.8	d1, d1, d14
	vmull.p64	q7, d2, d26
	veor.8	q7, q7, q0
	# Done GHASH
L_aes_gcm_encrypt_arm32_crypto_out_partial_done:
	lsr	lr, r6, #29
	lsl	r6, r6, #3
	rbit	lr, lr
	rbit	r6, r6
	vmov	s0, lr
	vmov	s1, r6
	lsr	lr, r2, #29
	lsl	r2, r2, #3
	rbit	lr, lr
	rbit	r2, r2
	vmov	s2, lr
	vmov	s3, r2
	veor.8	q7, q7, q0
	vmull.p64	q2, d15, d16
	vmull.p64	q3, d14, d17
	vmull.p64	q0, d14, d16
	vmull.p64	q1, d15, d17
	veor.8	q2, q2, q3
	#   Reduce
	vmull.p64	q7, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d15
	veor.8	d1, d1, d14
	vmull.p64	q7, d2, d26
	veor.8	q7, q7, q0
	vmov.i8	q0, #0x55
	vshl.u8	q1, q7, #1
	vshr.u8	q7, q7, #1
	vbif.8	q7, q1, q0
	vmov.i8	q0, #51
	vshl.u8	q1, q7, #2
	vshr.u8	q7, q7, #2
	vbit.8	q1, q7, q0
	vshl.u8	q7, q1, #4
	vsri.u8	q7, q1, #4
	# DONE
	veor.8	q7, q7, q6
	# tag
	ldr	lr, [sp, #104]
	# tagSz
	ldr	r4, [sp, #108]
	cmp	r4, #16
	bne	L_aes_gcm_encrypt_arm32_crypto_tag_tag_partial
	vst1.8	{q7}, [lr]
	b	L_aes_gcm_encrypt_arm32_crypto_done_gcm
L_aes_gcm_encrypt_arm32_crypto_tag_tag_partial:
	vst1.8	{q7}, [r9]
	cmp	r4, #4
	blt	L_aes_gcm_encrypt_arm32_crypto_tag_tag_start_sw
L_aes_gcm_encrypt_arm32_crypto_tag_tag_start_dw:
	ldr	r8, [r9], #4
	sub	r4, r4, #4
	str	r8, [lr], #4
	cmp	r4, #4
	bge	L_aes_gcm_encrypt_arm32_crypto_tag_tag_start_dw
L_aes_gcm_encrypt_arm32_crypto_tag_tag_start_sw:
	cmp	r4, #2
	blt	L_aes_gcm_encrypt_arm32_crypto_tag_tag_start_byte
	ldrh	r8, [r9], #2
	sub	r4, r4, #2
	strh	r8, [lr], #2
L_aes_gcm_encrypt_arm32_crypto_tag_tag_start_byte:
	cmp	r4, #1
	blt	L_aes_gcm_encrypt_arm32_crypto_tag_tag_end_bytes
	ldrb	r8, [r9], #1
	subs	r4, r4, #1
	strb	r8, [lr], #1
	bne	L_aes_gcm_encrypt_arm32_crypto_tag_tag_start_byte
L_aes_gcm_encrypt_arm32_crypto_tag_tag_end_bytes:
L_aes_gcm_encrypt_arm32_crypto_done_gcm:
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	AES_GCM_encrypt_AARCH32,.-AES_GCM_encrypt_AARCH32
#ifdef HAVE_AES_DECRYPT
	.text
	.align	4
	.globl	AES_GCM_decrypt_AARCH32
	.type	AES_GCM_decrypt_AARCH32, %function
AES_GCM_decrypt_AARCH32:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	vpush	{d8-d15}
	# key
	ldr	r7, [sp, #120]
	# tmp
	ldr	r9, [sp, #128]
	# aadSz
	ldr	r6, [sp, #116]
	# gcm_h
	ldr	r8, [sp, #124]
	vmov.i8	q13, #0x87
	veor.8	q7, q7, q7
	vshr.u64	q13, q13, #56
	vld1.32	{q8}, [r8]
	orr	r10, r6, r2
	cmp	r10, #32
	blt	L_aes_gcm_decrypt_arm32_crypto_h_done
	# Square H => H^2
	vmull.p64	q1, d17, d17
	vmull.p64	q0, d16, d16
	vmull.p64	q9, d3, d27
	veor.8	d2, d2, d19
	veor.8	d1, d1, d18
	vmull.p64	q9, d2, d26
	veor.8	q9, q9, q0
	cmp	r10, #0x40
	blt	L_aes_gcm_decrypt_arm32_crypto_h_done
	# Multiply H and H^2  => H^3
	vmull.p64	q2, d17, d18
	vmull.p64	q3, d16, d19
	vmull.p64	q0, d16, d18
	vmull.p64	q1, d17, d19
	veor.8	q2, q2, q3
	#   Reduce
	vmull.p64	q10, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d21
	veor.8	d1, d1, d20
	vmull.p64	q10, d2, d26
	veor.8	q10, q10, q0
	# Square H^2 => H^4
	vmull.p64	q1, d19, d19
	vmull.p64	q0, d18, d18
	vmull.p64	q11, d3, d27
	veor.8	d2, d2, d23
	veor.8	d1, d1, d22
	vmull.p64	q11, d2, d26
	veor.8	q11, q11, q0
	# Done
L_aes_gcm_decrypt_arm32_crypto_h_done:
	# aad
	ldr	r5, [sp, #112]
	lsr	r10, r6, #4
	cmp	r10, #1
	blt	L_aes_gcm_decrypt_arm32_crypto_aad_done
	beq	L_aes_gcm_decrypt_arm32_crypto_aad_start_1
	cmp	r10, #4
	blt	L_aes_gcm_decrypt_arm32_crypto_aad_start_2
L_aes_gcm_decrypt_arm32_crypto_aad_start_4:
	vldm	r5!, {q0-q2}
	vmov.i8	q12, #0x55
	vmov.i8	q5, #51
	vshl.u8	q14, q0, #1
	vshl.u8	q15, q1, #1
	vshl.u8	q4, q2, #1
	ldr	lr, [r5], #4
	vshr.u8	q0, q0, #1
	vshr.u8	q1, q1, #1
	vshr.u8	q2, q2, #1
	ldr	r4, [r5], #4
	vbit.8	q14, q0, q12
	vbit.8	q15, q1, q12
	vbit.8	q4, q2, q12
	ldr	r8, [r5], #4
	vshl.u8	q0, q14, #2
	vshl.u8	q1, q15, #2
	vshl.u8	q2, q4, #2
	ldr	r12, [r5], #4
	vshr.u8	q14, q14, #2
	vshr.u8	q15, q15, #2
	vshr.u8	q4, q4, #2
	rbit	lr, lr
	vbit.8	q0, q14, q5
	rbit	r4, r4
	vbit.8	q1, q15, q5
	rbit	r8, r8
	vbit.8	q2, q4, q5
	rbit	r12, r12
	vshl.u8	q14, q0, #4
	rev	lr, lr
	vshl.u8	q15, q1, #4
	rev	r4, r4
	vshl.u8	q4, q2, #4
	rev	r8, r8
	vsri.u8	q14, q0, #4
	rev	r12, r12
	vsri.u8	q15, q1, #4
	vsri.u8	q4, q2, #4
	vmov	d10, lr, r4
	vmov	d11, r8, r12
	veor.8	q12, q7, q14
	#   X  = C * H^1
	vmull.p64	q2, d11, d16
	vmull.p64	q7, d10, d17
	vmull.p64	q0, d10, d16
	vmull.p64	q1, d11, d17
	veor.8	q2, q2, q7
	#   X += C * H^2
	vmull.p64	q3, d8, d18
	vmull.p64	q7, d9, d19
	veor.8	q0, q0, q3
	veor.8	q1, q1, q7
	vmull.p64	q3, d9, d18
	vmull.p64	q7, d8, d19
	veor.8	q2, q2, q3
	veor.8	q2, q2, q7
	#   X += C * H^3
	vmull.p64	q3, d30, d20
	vmull.p64	q7, d31, d21
	veor.8	q0, q0, q3
	veor.8	q1, q1, q7
	vmull.p64	q3, d31, d20
	vmull.p64	q7, d30, d21
	veor.8	q2, q2, q3
	veor.8	q2, q2, q7
	#   X += C * H^4
	vmull.p64	q3, d24, d22
	vmull.p64	q7, d25, d23
	veor.8	q0, q0, q3
	veor.8	q1, q1, q7
	vmull.p64	q3, d25, d22
	vmull.p64	q7, d24, d23
	veor.8	q2, q2, q3
	veor.8	q2, q2, q7
	#   Reduce
	vmull.p64	q7, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d15
	veor.8	d1, d1, d14
	vmull.p64	q7, d2, d26
	veor.8	q7, q7, q0
	# Done GHASH
	sub	r10, r10, #4
	cmp	r10, #4
	bge	L_aes_gcm_decrypt_arm32_crypto_aad_start_4
	cmp	r10, #1
	blt	L_aes_gcm_decrypt_arm32_crypto_aad_done
	beq	L_aes_gcm_decrypt_arm32_crypto_aad_start_1
L_aes_gcm_decrypt_arm32_crypto_aad_start_2:
	vld1.32	{q14-q15}, [r5]!
	vmov.i8	q12, #0x55
	vshl.u8	q0, q14, #1
	vshl.u8	q1, q15, #1
	vshr.u8	q14, q14, #1
	vshr.u8	q15, q15, #1
	vbif.8	q14, q0, q12
	vbif.8	q15, q1, q12
	vmov.i8	q12, #51
	vshl.u8	q0, q14, #2
	vshl.u8	q1, q15, #2
	vshr.u8	q14, q14, #2
	vshr.u8	q15, q15, #2
	vbit.8	q0, q14, q12
	vbit.8	q1, q15, q12
	vshl.u8	q14, q0, #4
	vshl.u8	q15, q1, #4
	vsri.u8	q14, q0, #4
	vsri.u8	q15, q1, #4
	veor.8	q12, q7, q14
	#   X  = C * H^1
	vmull.p64	q2, d31, d16
	vmull.p64	q7, d30, d17
	vmull.p64	q0, d30, d16
	vmull.p64	q1, d31, d17
	veor.8	q2, q2, q7
	#   X += C * H^2
	vmull.p64	q3, d24, d18
	vmull.p64	q7, d25, d19
	veor.8	q0, q0, q3
	veor.8	q1, q1, q7
	vmull.p64	q3, d25, d18
	vmull.p64	q7, d24, d19
	veor.8	q2, q2, q3
	veor.8	q2, q2, q7
	#   Reduce
	vmull.p64	q7, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d15
	veor.8	d1, d1, d14
	vmull.p64	q7, d2, d26
	veor.8	q7, q7, q0
	# Done GHASH
	sub	r10, r10, #2
	cmp	r10, #0
	beq	L_aes_gcm_decrypt_arm32_crypto_aad_done
L_aes_gcm_decrypt_arm32_crypto_aad_start_1:
	vld1.32	{q14}, [r5]!
	vmov.i8	q12, #0x55
	vshl.u8	q0, q14, #1
	vshr.u8	q14, q14, #1
	vbif.8	q14, q0, q12
	vmov.i8	q12, #51
	vshl.u8	q0, q14, #2
	vshr.u8	q14, q14, #2
	vbit.8	q0, q14, q12
	vshl.u8	q14, q0, #4
	vsri.u8	q14, q0, #4
	veor.8	q12, q7, q14
	#   X  = C * H^1
	vmull.p64	q2, d25, d16
	vmull.p64	q7, d24, d17
	vmull.p64	q0, d24, d16
	vmull.p64	q1, d25, d17
	veor.8	q2, q2, q7
	#   Reduce
	vmull.p64	q7, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d15
	veor.8	d1, d1, d14
	vmull.p64	q7, d2, d26
	veor.8	q7, q7, q0
	# Done GHASH
L_aes_gcm_decrypt_arm32_crypto_aad_done:
	ands	r11, r6, #15
	beq	L_aes_gcm_decrypt_arm32_crypto_aad_partial_done
	veor.8	q0, q0, q0
	mov	r12, r11
	vst1.32	{q0}, [r9]
	cmp	r12, #4
	blt	L_aes_gcm_decrypt_arm32_crypto_aad_start_sw
L_aes_gcm_decrypt_arm32_crypto_aad_start_dw:
	ldr	r8, [r5], #4
	sub	r12, r12, #4
	str	r8, [r9], #4
	cmp	r12, #4
	bge	L_aes_gcm_decrypt_arm32_crypto_aad_start_dw
L_aes_gcm_decrypt_arm32_crypto_aad_start_sw:
	cmp	r12, #2
	blt	L_aes_gcm_decrypt_arm32_crypto_aad_start_byte
	ldrh	r8, [r5], #2
	sub	r12, r12, #2
	strh	r8, [r9], #2
L_aes_gcm_decrypt_arm32_crypto_aad_start_byte:
	cmp	r12, #1
	blt	L_aes_gcm_decrypt_arm32_crypto_aad_end_bytes
	ldrb	r8, [r5], #1
	subs	r12, r12, #1
	strb	r8, [r9], #1
	bne	L_aes_gcm_decrypt_arm32_crypto_aad_start_byte
L_aes_gcm_decrypt_arm32_crypto_aad_end_bytes:
	sub	r9, r9, r11
	vld1.32	{q14}, [r9]
	vmov.i8	q12, #0x55
	vshl.u8	q0, q14, #1
	vshr.u8	q14, q14, #1
	vbif.8	q14, q0, q12
	vmov.i8	q12, #51
	vshl.u8	q0, q14, #2
	vshr.u8	q14, q14, #2
	vbit.8	q0, q14, q12
	vshl.u8	q14, q0, #4
	vsri.u8	q14, q0, #4
	veor.8	q12, q7, q14
	#   X  = C * H^1
	vmull.p64	q2, d25, d16
	vmull.p64	q7, d24, d17
	vmull.p64	q0, d24, d16
	vmull.p64	q1, d25, d17
	veor.8	q2, q2, q7
	#   Reduce
	vmull.p64	q7, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d15
	veor.8	d1, d1, d14
	vmull.p64	q7, d2, d26
	veor.8	q7, q7, q0
	# Done GHASH
L_aes_gcm_decrypt_arm32_crypto_aad_partial_done:
	# in
	lsr	r10, r2, #4
	cmp	r10, #1
	blt	L_aes_gcm_decrypt_arm32_crypto_in_done
	beq	L_aes_gcm_decrypt_arm32_crypto_in_start_1
	cmp	r10, #4
	blt	L_aes_gcm_decrypt_arm32_crypto_in_start_2
L_aes_gcm_decrypt_arm32_crypto_in_start_4:
	vldm	r0!, {q0-q2}
	vmov.i8	q12, #0x55
	vmov.i8	q5, #51
	vshl.u8	q14, q0, #1
	vshl.u8	q15, q1, #1
	vshl.u8	q4, q2, #1
	ldr	lr, [r0], #4
	vshr.u8	q0, q0, #1
	vshr.u8	q1, q1, #1
	vshr.u8	q2, q2, #1
	ldr	r4, [r0], #4
	vbit.8	q14, q0, q12
	vbit.8	q15, q1, q12
	vbit.8	q4, q2, q12
	ldr	r8, [r0], #4
	vshl.u8	q0, q14, #2
	vshl.u8	q1, q15, #2
	vshl.u8	q2, q4, #2
	ldr	r12, [r0], #4
	vshr.u8	q14, q14, #2
	vshr.u8	q15, q15, #2
	vshr.u8	q4, q4, #2
	rbit	lr, lr
	vbit.8	q0, q14, q5
	rbit	r4, r4
	vbit.8	q1, q15, q5
	rbit	r8, r8
	vbit.8	q2, q4, q5
	rbit	r12, r12
	vshl.u8	q14, q0, #4
	rev	lr, lr
	vshl.u8	q15, q1, #4
	rev	r4, r4
	vshl.u8	q4, q2, #4
	rev	r8, r8
	vsri.u8	q14, q0, #4
	rev	r12, r12
	vsri.u8	q15, q1, #4
	vsri.u8	q4, q2, #4
	vmov	d10, lr, r4
	vmov	d11, r8, r12
	veor.8	q12, q7, q14
	#   X  = C * H^1
	vmull.p64	q2, d11, d16
	vmull.p64	q7, d10, d17
	vmull.p64	q0, d10, d16
	vmull.p64	q1, d11, d17
	veor.8	q2, q2, q7
	#   X += C * H^2
	vmull.p64	q3, d8, d18
	vmull.p64	q7, d9, d19
	veor.8	q0, q0, q3
	veor.8	q1, q1, q7
	vmull.p64	q3, d9, d18
	vmull.p64	q7, d8, d19
	veor.8	q2, q2, q3
	veor.8	q2, q2, q7
	#   X += C * H^3
	vmull.p64	q3, d30, d20
	vmull.p64	q7, d31, d21
	veor.8	q0, q0, q3
	veor.8	q1, q1, q7
	vmull.p64	q3, d31, d20
	vmull.p64	q7, d30, d21
	veor.8	q2, q2, q3
	veor.8	q2, q2, q7
	#   X += C * H^4
	vmull.p64	q3, d24, d22
	vmull.p64	q7, d25, d23
	veor.8	q0, q0, q3
	veor.8	q1, q1, q7
	vmull.p64	q3, d25, d22
	vmull.p64	q7, d24, d23
	veor.8	q2, q2, q3
	veor.8	q2, q2, q7
	#   Reduce
	vmull.p64	q7, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d15
	veor.8	d1, d1, d14
	vmull.p64	q7, d2, d26
	veor.8	q7, q7, q0
	# Done GHASH
	sub	r10, r10, #4
	cmp	r10, #4
	bge	L_aes_gcm_decrypt_arm32_crypto_in_start_4
	cmp	r10, #1
	blt	L_aes_gcm_decrypt_arm32_crypto_in_done
	beq	L_aes_gcm_decrypt_arm32_crypto_in_start_1
L_aes_gcm_decrypt_arm32_crypto_in_start_2:
	vld1.32	{q14-q15}, [r0]!
	vmov.i8	q12, #0x55
	vshl.u8	q0, q14, #1
	vshl.u8	q1, q15, #1
	vshr.u8	q14, q14, #1
	vshr.u8	q15, q15, #1
	vbif.8	q14, q0, q12
	vbif.8	q15, q1, q12
	vmov.i8	q12, #51
	vshl.u8	q0, q14, #2
	vshl.u8	q1, q15, #2
	vshr.u8	q14, q14, #2
	vshr.u8	q15, q15, #2
	vbit.8	q0, q14, q12
	vbit.8	q1, q15, q12
	vshl.u8	q14, q0, #4
	vshl.u8	q15, q1, #4
	vsri.u8	q14, q0, #4
	vsri.u8	q15, q1, #4
	veor.8	q12, q7, q14
	#   X  = C * H^1
	vmull.p64	q2, d31, d16
	vmull.p64	q7, d30, d17
	vmull.p64	q0, d30, d16
	vmull.p64	q1, d31, d17
	veor.8	q2, q2, q7
	#   X += C * H^2
	vmull.p64	q3, d24, d18
	vmull.p64	q7, d25, d19
	veor.8	q0, q0, q3
	veor.8	q1, q1, q7
	vmull.p64	q3, d25, d18
	vmull.p64	q7, d24, d19
	veor.8	q2, q2, q3
	veor.8	q2, q2, q7
	#   Reduce
	vmull.p64	q7, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d15
	veor.8	d1, d1, d14
	vmull.p64	q7, d2, d26
	veor.8	q7, q7, q0
	# Done GHASH
	sub	r10, r10, #2
	cmp	r10, #0
	beq	L_aes_gcm_decrypt_arm32_crypto_in_done
L_aes_gcm_decrypt_arm32_crypto_in_start_1:
	vld1.32	{q14}, [r0]!
	vmov.i8	q12, #0x55
	vshl.u8	q0, q14, #1
	vshr.u8	q14, q14, #1
	vbif.8	q14, q0, q12
	vmov.i8	q12, #51
	vshl.u8	q0, q14, #2
	vshr.u8	q14, q14, #2
	vbit.8	q0, q14, q12
	vshl.u8	q14, q0, #4
	vsri.u8	q14, q0, #4
	veor.8	q12, q7, q14
	#   X  = C * H^1
	vmull.p64	q2, d25, d16
	vmull.p64	q7, d24, d17
	vmull.p64	q0, d24, d16
	vmull.p64	q1, d25, d17
	veor.8	q2, q2, q7
	#   Reduce
	vmull.p64	q7, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d15
	veor.8	d1, d1, d14
	vmull.p64	q7, d2, d26
	veor.8	q7, q7, q0
	# Done GHASH
L_aes_gcm_decrypt_arm32_crypto_in_done:
	ands	r11, r2, #15
	beq	L_aes_gcm_decrypt_arm32_crypto_in_partial_done
	veor.8	q0, q0, q0
	mov	r12, r11
	vst1.32	{q0}, [r9]
	cmp	r12, #4
	blt	L_aes_gcm_decrypt_arm32_crypto_in_start_sw
L_aes_gcm_decrypt_arm32_crypto_in_start_dw:
	ldr	r8, [r0], #4
	sub	r12, r12, #4
	str	r8, [r9], #4
	cmp	r12, #4
	bge	L_aes_gcm_decrypt_arm32_crypto_in_start_dw
L_aes_gcm_decrypt_arm32_crypto_in_start_sw:
	cmp	r12, #2
	blt	L_aes_gcm_decrypt_arm32_crypto_in_start_byte
	ldrh	r8, [r0], #2
	sub	r12, r12, #2
	strh	r8, [r9], #2
L_aes_gcm_decrypt_arm32_crypto_in_start_byte:
	cmp	r12, #1
	blt	L_aes_gcm_decrypt_arm32_crypto_in_end_bytes
	ldrb	r8, [r0], #1
	subs	r12, r12, #1
	strb	r8, [r9], #1
	bne	L_aes_gcm_decrypt_arm32_crypto_in_start_byte
L_aes_gcm_decrypt_arm32_crypto_in_end_bytes:
	sub	r9, r9, r11
	vld1.32	{q14}, [r9]
	vmov.i8	q12, #0x55
	vshl.u8	q0, q14, #1
	vshr.u8	q14, q14, #1
	vbif.8	q14, q0, q12
	vmov.i8	q12, #51
	vshl.u8	q0, q14, #2
	vshr.u8	q14, q14, #2
	vbit.8	q0, q14, q12
	vshl.u8	q14, q0, #4
	vsri.u8	q14, q0, #4
	veor.8	q12, q7, q14
	#   X  = C * H^1
	vmull.p64	q2, d25, d16
	vmull.p64	q7, d24, d17
	vmull.p64	q0, d24, d16
	vmull.p64	q1, d25, d17
	veor.8	q2, q2, q7
	#   Reduce
	vmull.p64	q7, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d15
	veor.8	d1, d1, d14
	vmull.p64	q7, d2, d26
	veor.8	q7, q7, q0
	# Done GHASH
L_aes_gcm_decrypt_arm32_crypto_in_partial_done:
	sub	r0, r0, r2
L_aes_gcm_decrypt_arm32_crypto_done_gcm:
	# nonceSz
	ldr	r12, [sp, #100]
	# Load Nonce
	cmp	r12, #12
	bne	L_aes_gcm_decrypt_arm32_crypto_ghash_nonce
	ldr	r5, [r3]
	ldr	r8, [r3, #4]
	ldr	r12, [r3, #8]
	vmov.i32	q6, #0x1000000
	vmov.32	s24, r5
	vmov.32	s25, r8
	vmov.32	s26, r12
	mov	r5, #1
	b	L_aes_gcm_decrypt_arm32_crypto_done_nonce
L_aes_gcm_decrypt_arm32_crypto_ghash_nonce:
	lsr	r10, r12, #4
	cmp	r10, #0
	beq	L_aes_gcm_decrypt_arm32_crypto_nonce_done
L_aes_gcm_decrypt_arm32_crypto_nonce_start_1:
	vld1.32	{q14}, [r3]!
	vmov.i8	q12, #0x55
	vshl.u8	q0, q14, #1
	vshr.u8	q14, q14, #1
	vbif.8	q14, q0, q12
	vmov.i8	q12, #51
	vshl.u8	q0, q14, #2
	vshr.u8	q14, q14, #2
	vbit.8	q0, q14, q12
	vshl.u8	q14, q0, #4
	vsri.u8	q14, q0, #4
	veor.8	q12, q6, q14
	#   X  = C * H^1
	vmull.p64	q2, d25, d16
	vmull.p64	q6, d24, d17
	vmull.p64	q0, d24, d16
	vmull.p64	q1, d25, d17
	veor.8	q2, q2, q6
	#   Reduce
	vmull.p64	q6, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d13
	veor.8	d1, d1, d12
	vmull.p64	q6, d2, d26
	veor.8	q6, q6, q0
	# Done GHASH
	subs	r10, r10, #1
	bne	L_aes_gcm_decrypt_arm32_crypto_nonce_start_1
L_aes_gcm_decrypt_arm32_crypto_nonce_done:
	ands	r11, r12, #15
	beq	L_aes_gcm_decrypt_arm32_crypto_nonce_partial_done
	veor.8	q0, q0, q0
	mov	r12, r11
	vst1.32	{q0}, [r9]
	cmp	r12, #4
	blt	L_aes_gcm_decrypt_arm32_crypto_nonce_start_sw
L_aes_gcm_decrypt_arm32_crypto_nonce_start_dw:
	ldr	r8, [r3], #4
	sub	r12, r12, #4
	str	r8, [r9], #4
	cmp	r12, #4
	bge	L_aes_gcm_decrypt_arm32_crypto_nonce_start_dw
L_aes_gcm_decrypt_arm32_crypto_nonce_start_sw:
	cmp	r12, #2
	blt	L_aes_gcm_decrypt_arm32_crypto_nonce_start_byte
	ldrh	r8, [r3], #2
	sub	r12, r12, #2
	strh	r8, [r9], #2
L_aes_gcm_decrypt_arm32_crypto_nonce_start_byte:
	cmp	r12, #1
	blt	L_aes_gcm_decrypt_arm32_crypto_nonce_end_bytes
	ldrb	r8, [r3], #1
	subs	r12, r12, #1
	strb	r8, [r9], #1
	bne	L_aes_gcm_decrypt_arm32_crypto_nonce_start_byte
L_aes_gcm_decrypt_arm32_crypto_nonce_end_bytes:
	sub	r9, r9, r11
	vld1.32	{q14}, [r9]
	vmov.i8	q12, #0x55
	vshl.u8	q0, q14, #1
	vshr.u8	q14, q14, #1
	vbif.8	q14, q0, q12
	vmov.i8	q12, #51
	vshl.u8	q0, q14, #2
	vshr.u8	q14, q14, #2
	vbit.8	q0, q14, q12
	vshl.u8	q14, q0, #4
	vsri.u8	q14, q0, #4
	veor.8	q12, q6, q14
	#   X  = C * H^1
	vmull.p64	q2, d25, d16
	vmull.p64	q6, d24, d17
	vmull.p64	q0, d24, d16
	vmull.p64	q1, d25, d17
	veor.8	q2, q2, q6
	#   Reduce
	vmull.p64	q6, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d13
	veor.8	d1, d1, d12
	vmull.p64	q6, d2, d26
	veor.8	q6, q6, q0
	# Done GHASH
L_aes_gcm_decrypt_arm32_crypto_nonce_partial_done:
	veor.8	q0, q0, q0
	# nonceSz
	ldr	r12, [sp, #100]
	lsr	r10, r12, #29
	lsl	r11, r12, #3
	rbit	r10, r10
	rbit	r11, r11
	vmov.32	s2, r10
	vmov.32	s3, r11
	veor.8	q6, q6, q0
	vmull.p64	q2, d13, d16
	vmull.p64	q12, d12, d17
	vmull.p64	q0, d12, d16
	vmull.p64	q1, d13, d17
	veor.8	q2, q2, q12
	vmull.p64	q6, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d13
	veor.8	d1, d1, d12
	vmull.p64	q6, d2, d26
	veor.8	q6, q6, q0
	vmov.32	r5, s24
	vmov.32	r8, s25
	vmov.32	r12, s26
	rbit	r5, r5
	rbit	r8, r8
	rbit	r12, r12
	rev	r5, r5
	rev	r8, r8
	rev	r12, r12
	vmov.32	s24, r5
	vmov.32	s25, r8
	vmov.32	s26, r12
	vmov.32	r5, s27
	rbit	r5, r5
	rev	r5, r5
	vmov.32	s27, r5
	rev	r5, r5
L_aes_gcm_decrypt_arm32_crypto_done_nonce:
	# reg
	ldr	r9, [sp, #132]
	vst1.32	{q7}, [r9]
	# tmp
	ldr	r9, [sp, #128]
	vldm.32	r7!, {q0-q3}
	vldm.32	r7!, {q7-q13}
	# nr
	ldr	r12, [sp, #136]
	lsr	r10, r2, #4
	and	r11, r2, #15
	cmp	r12, #12
	blt	L_aes_gcm_decrypt_arm32_crypto_start_128
	bgt	L_aes_gcm_decrypt_arm32_crypto_start_256
	# AES_GCM_192
#ifndef NO_AES_192
	cmp	r10, #1
	blt	L_aes_gcm_decrypt_arm32_crypto_192_done
	beq	L_aes_gcm_decrypt_arm32_crypto_192_start_1
L_aes_gcm_decrypt_arm32_crypto_192_start_2:
	add	r8, r5, #1
	vmov.8	q4, q6
	add	r5, r5, #2
	vmov.8	q5, q6
	rev	r8, r8
	rev	r12, r5
	vmov	s19, r8
	vmov	s23, r12
	aese.8	q4, q0
	aesmc.8	q4, q4
	aese.8	q5, q0
	aesmc.8	q5, q5
	aese.8	q4, q1
	aesmc.8	q4, q4
	aese.8	q5, q1
	aesmc.8	q5, q5
	aese.8	q4, q2
	aesmc.8	q4, q4
	aese.8	q5, q2
	aesmc.8	q5, q5
	aese.8	q4, q3
	aesmc.8	q4, q4
	aese.8	q5, q3
	aesmc.8	q5, q5
	aese.8	q4, q7
	aesmc.8	q4, q4
	aese.8	q5, q7
	aesmc.8	q5, q5
	aese.8	q4, q8
	aesmc.8	q4, q4
	aese.8	q5, q8
	aesmc.8	q5, q5
	aese.8	q4, q9
	aesmc.8	q4, q4
	aese.8	q5, q9
	aesmc.8	q5, q5
	subs	r10, r10, #2
	aese.8	q4, q10
	aesmc.8	q4, q4
	aese.8	q5, q10
	aesmc.8	q5, q5
	aese.8	q4, q11
	aesmc.8	q4, q4
	aese.8	q5, q11
	aesmc.8	q5, q5
	aese.8	q4, q12
	aesmc.8	q4, q4
	aese.8	q5, q12
	aesmc.8	q5, q5
	vld1.32	{q14}, [r7]!
	aese.8	q4, q13
	aesmc.8	q4, q4
	aese.8	q5, q13
	aesmc.8	q5, q5
	vld1.32	{q15}, [r7]
	aese.8	q4, q14
	veor.8	q4, q4, q15
	aese.8	q5, q14
	veor.8	q5, q5, q15
	vld1.8	{q14-q15}, [r0]!
	sub	r7, r7, #16
	veor.8	q14, q14, q4
	veor.8	q15, q15, q5
	vst1.8	{q14-q15}, [r1]!
	cmp	r10, #1
	bgt	L_aes_gcm_decrypt_arm32_crypto_192_start_2
	blt	L_aes_gcm_decrypt_arm32_crypto_192_done
L_aes_gcm_decrypt_arm32_crypto_192_start_1:
	add	r5, r5, #1
	vmov.8	q4, q6
	rev	r8, r5
	vmov	s19, r8
	aese.8	q4, q0
	aesmc.8	q4, q4
	aese.8	q4, q1
	aesmc.8	q4, q4
	aese.8	q4, q2
	aesmc.8	q4, q4
	aese.8	q4, q3
	aesmc.8	q4, q4
	aese.8	q4, q7
	aesmc.8	q4, q4
	aese.8	q4, q8
	aesmc.8	q4, q4
	aese.8	q4, q9
	aesmc.8	q4, q4
	aese.8	q4, q10
	aesmc.8	q4, q4
	aese.8	q4, q11
	aesmc.8	q4, q4
	aese.8	q4, q12
	aesmc.8	q4, q4
	vld1.32	{q14}, [r7]!
	aese.8	q4, q13
	aesmc.8	q4, q4
	vld1.32	{q15}, [r7]
	aese.8	q4, q14
	veor.8	q4, q4, q15
	vld1.8	{q14}, [r0]!
	sub	r7, r7, #16
	veor.8	q14, q14, q4
	vst1.32	{q14}, [r1]!
L_aes_gcm_decrypt_arm32_crypto_192_done:
	ands	r11, r2, #15
	beq	L_aes_gcm_decrypt_arm32_crypto_192_partial_done
	veor.8	q14, q14, q14
	mov	r4, r11
	vst1.32	{q14}, [r9]
	cmp	r4, #4
	blt	L_aes_gcm_decrypt_arm32_crypto_192_start_sw
L_aes_gcm_decrypt_arm32_crypto_192_start_dw:
	ldr	lr, [r0], #4
	sub	r4, r4, #4
	str	lr, [r9], #4
	cmp	r4, #4
	bge	L_aes_gcm_decrypt_arm32_crypto_192_start_dw
L_aes_gcm_decrypt_arm32_crypto_192_start_sw:
	cmp	r4, #2
	blt	L_aes_gcm_decrypt_arm32_crypto_192_start_byte
	ldrh	lr, [r0], #2
	sub	r4, r4, #2
	strh	lr, [r9], #2
L_aes_gcm_decrypt_arm32_crypto_192_start_byte:
	cmp	r4, #1
	blt	L_aes_gcm_decrypt_arm32_crypto_192_end_bytes
	ldrb	lr, [r0], #1
	subs	r4, r4, #1
	strb	lr, [r9], #1
	bne	L_aes_gcm_decrypt_arm32_crypto_192_start_byte
L_aes_gcm_decrypt_arm32_crypto_192_end_bytes:
	sub	r9, r9, r11
	add	r5, r5, #1
	vmov.8	q4, q6
	rev	r8, r5
	vmov	s19, r8
	aese.8	q4, q0
	aesmc.8	q4, q4
	aese.8	q4, q1
	aesmc.8	q4, q4
	aese.8	q4, q2
	aesmc.8	q4, q4
	aese.8	q4, q3
	aesmc.8	q4, q4
	aese.8	q4, q7
	aesmc.8	q4, q4
	aese.8	q4, q8
	aesmc.8	q4, q4
	aese.8	q4, q9
	aesmc.8	q4, q4
	aese.8	q4, q10
	aesmc.8	q4, q4
	aese.8	q4, q11
	aesmc.8	q4, q4
	aese.8	q4, q12
	aesmc.8	q4, q4
	vld1.32	{q14}, [r7]!
	aese.8	q4, q13
	aesmc.8	q4, q4
	vld1.32	{q15}, [r7]
	aese.8	q4, q14
	veor.8	q4, q4, q15
	vld1.8	{q14}, [r9]
	sub	r7, r7, #16
	veor.8	q14, q14, q4
	vst1.32	{q14}, [r9]
	mov	r4, r11
	cmp	r4, #4
	blt	L_aes_gcm_decrypt_arm32_crypto_192_out_start_sw
L_aes_gcm_decrypt_arm32_crypto_192_out_start_dw:
	ldr	lr, [r9], #4
	sub	r4, r4, #4
	str	lr, [r1], #4
	cmp	r4, #4
	bge	L_aes_gcm_decrypt_arm32_crypto_192_out_start_dw
L_aes_gcm_decrypt_arm32_crypto_192_out_start_sw:
	cmp	r4, #2
	blt	L_aes_gcm_decrypt_arm32_crypto_192_out_start_byte
	ldrh	lr, [r9], #2
	sub	r4, r4, #2
	strh	lr, [r1], #2
L_aes_gcm_decrypt_arm32_crypto_192_out_start_byte:
	cmp	r4, #1
	blt	L_aes_gcm_decrypt_arm32_crypto_192_out_end_bytes
	ldrb	lr, [r9], #1
	subs	r4, r4, #1
	strb	lr, [r1], #1
	bne	L_aes_gcm_decrypt_arm32_crypto_192_out_start_byte
L_aes_gcm_decrypt_arm32_crypto_192_out_end_bytes:
L_aes_gcm_decrypt_arm32_crypto_192_partial_done:
	# Finish
	add	r8, r2, #15
	sub	r8, r5, r8, lsr #4
	rev	r8, r8
	vmov.32	s27, r8
	aese.8	q6, q0
	aesmc.8	q6, q6
	aese.8	q6, q1
	aesmc.8	q6, q6
	aese.8	q6, q2
	aesmc.8	q6, q6
	aese.8	q6, q3
	aesmc.8	q6, q6
	aese.8	q6, q7
	aesmc.8	q6, q6
	aese.8	q6, q8
	aesmc.8	q6, q6
	aese.8	q6, q9
	aesmc.8	q6, q6
	aese.8	q6, q10
	aesmc.8	q6, q6
	aese.8	q6, q11
	aesmc.8	q6, q6
	aese.8	q6, q12
	aesmc.8	q6, q6
	vld1.32	{q14}, [r7]!
	aese.8	q6, q13
	aesmc.8	q6, q6
	vld1.32	{q15}, [r7]
	aese.8	q6, q14
	veor.8	q6, q6, q15
	sub	r7, r7, #16
#endif /* !NO_AES_192 */
	b	L_aes_gcm_decrypt_arm32_crypto_done_enc
	# AES_GCM_256
L_aes_gcm_decrypt_arm32_crypto_start_256:
#ifndef NO_AES_256
	cmp	r10, #1
	blt	L_aes_gcm_decrypt_arm32_crypto_256_done
	beq	L_aes_gcm_decrypt_arm32_crypto_256_start_1
L_aes_gcm_decrypt_arm32_crypto_256_start_2:
	add	r8, r5, #1
	vmov.8	q4, q6
	add	r5, r5, #2
	vmov.8	q5, q6
	rev	r8, r8
	rev	r12, r5
	vmov	s19, r8
	vmov	s23, r12
	aese.8	q4, q0
	aesmc.8	q4, q4
	aese.8	q5, q0
	aesmc.8	q5, q5
	aese.8	q4, q1
	aesmc.8	q4, q4
	aese.8	q5, q1
	aesmc.8	q5, q5
	aese.8	q4, q2
	aesmc.8	q4, q4
	aese.8	q5, q2
	aesmc.8	q5, q5
	aese.8	q4, q3
	aesmc.8	q4, q4
	aese.8	q5, q3
	aesmc.8	q5, q5
	aese.8	q4, q7
	aesmc.8	q4, q4
	aese.8	q5, q7
	aesmc.8	q5, q5
	aese.8	q4, q8
	aesmc.8	q4, q4
	aese.8	q5, q8
	aesmc.8	q5, q5
	aese.8	q4, q9
	aesmc.8	q4, q4
	aese.8	q5, q9
	aesmc.8	q5, q5
	subs	r10, r10, #2
	aese.8	q4, q10
	aesmc.8	q4, q4
	aese.8	q5, q10
	aesmc.8	q5, q5
	aese.8	q4, q11
	aesmc.8	q4, q4
	aese.8	q5, q11
	aesmc.8	q5, q5
	aese.8	q4, q12
	aesmc.8	q4, q4
	aese.8	q5, q12
	aesmc.8	q5, q5
	vld1.32	{q14}, [r7]!
	aese.8	q4, q13
	aesmc.8	q4, q4
	aese.8	q5, q13
	aesmc.8	q5, q5
	vld1.32	{q15}, [r7]!
	aese.8	q4, q14
	aesmc.8	q4, q4
	aese.8	q5, q14
	aesmc.8	q5, q5
	vld1.32	{q14}, [r7]!
	aese.8	q4, q15
	aesmc.8	q4, q4
	aese.8	q5, q15
	aesmc.8	q5, q5
	vld1.32	{q15}, [r7]
	aese.8	q4, q14
	veor.8	q4, q4, q15
	aese.8	q5, q14
	veor.8	q5, q5, q15
	vld1.8	{q14-q15}, [r0]!
	sub	r7, r7, #48
	veor.8	q14, q14, q4
	veor.8	q15, q15, q5
	vst1.8	{q14-q15}, [r1]!
	cmp	r10, #1
	bgt	L_aes_gcm_decrypt_arm32_crypto_256_start_2
	blt	L_aes_gcm_decrypt_arm32_crypto_256_done
L_aes_gcm_decrypt_arm32_crypto_256_start_1:
	add	r5, r5, #1
	vmov.8	q4, q6
	rev	r8, r5
	vmov	s19, r8
	aese.8	q4, q0
	aesmc.8	q4, q4
	aese.8	q4, q1
	aesmc.8	q4, q4
	aese.8	q4, q2
	aesmc.8	q4, q4
	aese.8	q4, q3
	aesmc.8	q4, q4
	aese.8	q4, q7
	aesmc.8	q4, q4
	aese.8	q4, q8
	aesmc.8	q4, q4
	aese.8	q4, q9
	aesmc.8	q4, q4
	aese.8	q4, q10
	aesmc.8	q4, q4
	aese.8	q4, q11
	aesmc.8	q4, q4
	aese.8	q4, q12
	aesmc.8	q4, q4
	vld1.32	{q14}, [r7]!
	aese.8	q4, q13
	aesmc.8	q4, q4
	vld1.32	{q15}, [r7]!
	aese.8	q4, q14
	aesmc.8	q4, q4
	vld1.32	{q14}, [r7]!
	aese.8	q4, q15
	aesmc.8	q4, q4
	vld1.32	{q15}, [r7]
	aese.8	q4, q14
	veor.8	q4, q4, q15
	vld1.8	{q14}, [r0]!
	sub	r7, r7, #48
	veor.8	q14, q14, q4
	vst1.32	{q14}, [r1]!
L_aes_gcm_decrypt_arm32_crypto_256_done:
	ands	r11, r2, #15
	beq	L_aes_gcm_decrypt_arm32_crypto_256_partial_done
	veor.8	q14, q14, q14
	mov	r4, r11
	vst1.32	{q14}, [r9]
	cmp	r4, #4
	blt	L_aes_gcm_decrypt_arm32_crypto_256_start_sw
L_aes_gcm_decrypt_arm32_crypto_256_start_dw:
	ldr	lr, [r0], #4
	sub	r4, r4, #4
	str	lr, [r9], #4
	cmp	r4, #4
	bge	L_aes_gcm_decrypt_arm32_crypto_256_start_dw
L_aes_gcm_decrypt_arm32_crypto_256_start_sw:
	cmp	r4, #2
	blt	L_aes_gcm_decrypt_arm32_crypto_256_start_byte
	ldrh	lr, [r0], #2
	sub	r4, r4, #2
	strh	lr, [r9], #2
L_aes_gcm_decrypt_arm32_crypto_256_start_byte:
	cmp	r4, #1
	blt	L_aes_gcm_decrypt_arm32_crypto_256_end_bytes
	ldrb	lr, [r0], #1
	subs	r4, r4, #1
	strb	lr, [r9], #1
	bne	L_aes_gcm_decrypt_arm32_crypto_256_start_byte
L_aes_gcm_decrypt_arm32_crypto_256_end_bytes:
	sub	r9, r9, r11
	add	r5, r5, #1
	vmov.8	q4, q6
	rev	r8, r5
	vmov	s19, r8
	aese.8	q4, q0
	aesmc.8	q4, q4
	aese.8	q4, q1
	aesmc.8	q4, q4
	aese.8	q4, q2
	aesmc.8	q4, q4
	aese.8	q4, q3
	aesmc.8	q4, q4
	aese.8	q4, q7
	aesmc.8	q4, q4
	aese.8	q4, q8
	aesmc.8	q4, q4
	aese.8	q4, q9
	aesmc.8	q4, q4
	aese.8	q4, q10
	aesmc.8	q4, q4
	aese.8	q4, q11
	aesmc.8	q4, q4
	aese.8	q4, q12
	aesmc.8	q4, q4
	vld1.32	{q14}, [r7]!
	aese.8	q4, q13
	aesmc.8	q4, q4
	vld1.32	{q15}, [r7]!
	aese.8	q4, q14
	aesmc.8	q4, q4
	vld1.32	{q14}, [r7]!
	aese.8	q4, q15
	aesmc.8	q4, q4
	vld1.32	{q15}, [r7]
	aese.8	q4, q14
	veor.8	q4, q4, q15
	vld1.8	{q14}, [r9]
	sub	r7, r7, #48
	veor.8	q14, q14, q4
	vst1.32	{q14}, [r9]
	mov	r4, r11
	cmp	r4, #4
	blt	L_aes_gcm_decrypt_arm32_crypto_256_out_start_sw
L_aes_gcm_decrypt_arm32_crypto_256_out_start_dw:
	ldr	lr, [r9], #4
	sub	r4, r4, #4
	str	lr, [r1], #4
	cmp	r4, #4
	bge	L_aes_gcm_decrypt_arm32_crypto_256_out_start_dw
L_aes_gcm_decrypt_arm32_crypto_256_out_start_sw:
	cmp	r4, #2
	blt	L_aes_gcm_decrypt_arm32_crypto_256_out_start_byte
	ldrh	lr, [r9], #2
	sub	r4, r4, #2
	strh	lr, [r1], #2
L_aes_gcm_decrypt_arm32_crypto_256_out_start_byte:
	cmp	r4, #1
	blt	L_aes_gcm_decrypt_arm32_crypto_256_out_end_bytes
	ldrb	lr, [r9], #1
	subs	r4, r4, #1
	strb	lr, [r1], #1
	bne	L_aes_gcm_decrypt_arm32_crypto_256_out_start_byte
L_aes_gcm_decrypt_arm32_crypto_256_out_end_bytes:
L_aes_gcm_decrypt_arm32_crypto_256_partial_done:
	# Finish
	add	r8, r2, #15
	sub	r8, r5, r8, lsr #4
	rev	r8, r8
	vmov.32	s27, r8
	aese.8	q6, q0
	aesmc.8	q6, q6
	aese.8	q6, q1
	aesmc.8	q6, q6
	aese.8	q6, q2
	aesmc.8	q6, q6
	aese.8	q6, q3
	aesmc.8	q6, q6
	aese.8	q6, q7
	aesmc.8	q6, q6
	aese.8	q6, q8
	aesmc.8	q6, q6
	aese.8	q6, q9
	aesmc.8	q6, q6
	aese.8	q6, q10
	aesmc.8	q6, q6
	aese.8	q6, q11
	aesmc.8	q6, q6
	aese.8	q6, q12
	aesmc.8	q6, q6
	vld1.32	{q14}, [r7]!
	aese.8	q6, q13
	aesmc.8	q6, q6
	vld1.32	{q15}, [r7]!
	aese.8	q6, q14
	aesmc.8	q6, q6
	vld1.32	{q14}, [r7]!
	aese.8	q6, q15
	aesmc.8	q6, q6
	vld1.32	{q15}, [r7]
	aese.8	q6, q14
	veor.8	q6, q6, q15
	sub	r7, r7, #48
#endif /* !NO_AES_256 */
	b	L_aes_gcm_decrypt_arm32_crypto_done_enc
	# AES_GCM_128
L_aes_gcm_decrypt_arm32_crypto_start_128:
#ifndef NO_AES_128
	cmp	r10, #1
	blt	L_aes_gcm_decrypt_arm32_crypto_128_done
	beq	L_aes_gcm_decrypt_arm32_crypto_128_start_1
L_aes_gcm_decrypt_arm32_crypto_128_start_2:
	add	r8, r5, #1
	vmov.8	q4, q6
	add	r5, r5, #2
	vmov.8	q5, q6
	rev	r8, r8
	rev	r12, r5
	vmov	s19, r8
	vmov	s23, r12
	aese.8	q4, q0
	aesmc.8	q4, q4
	aese.8	q5, q0
	aesmc.8	q5, q5
	aese.8	q4, q1
	aesmc.8	q4, q4
	aese.8	q5, q1
	aesmc.8	q5, q5
	aese.8	q4, q2
	aesmc.8	q4, q4
	aese.8	q5, q2
	aesmc.8	q5, q5
	aese.8	q4, q3
	aesmc.8	q4, q4
	aese.8	q5, q3
	aesmc.8	q5, q5
	aese.8	q4, q7
	aesmc.8	q4, q4
	aese.8	q5, q7
	aesmc.8	q5, q5
	aese.8	q4, q8
	aesmc.8	q4, q4
	aese.8	q5, q8
	aesmc.8	q5, q5
	aese.8	q4, q9
	aesmc.8	q4, q4
	aese.8	q5, q9
	aesmc.8	q5, q5
	subs	r10, r10, #2
	aese.8	q4, q10
	aesmc.8	q4, q4
	aese.8	q5, q10
	aesmc.8	q5, q5
	aese.8	q4, q11
	aesmc.8	q4, q4
	aese.8	q5, q11
	aesmc.8	q5, q5
	vld1.8	{q14-q15}, [r0]!
	aese.8	q4, q12
	veor.8	q4, q4, q13
	aese.8	q5, q12
	veor.8	q5, q5, q13
	veor.8	q14, q14, q4
	veor.8	q15, q15, q5
	vst1.8	{q14-q15}, [r1]!
	cmp	r10, #1
	bgt	L_aes_gcm_decrypt_arm32_crypto_128_start_2
	blt	L_aes_gcm_decrypt_arm32_crypto_128_done
L_aes_gcm_decrypt_arm32_crypto_128_start_1:
	add	r5, r5, #1
	vmov.8	q4, q6
	rev	r8, r5
	vmov	s19, r8
	aese.8	q4, q0
	aesmc.8	q4, q4
	aese.8	q4, q1
	aesmc.8	q4, q4
	aese.8	q4, q2
	aesmc.8	q4, q4
	aese.8	q4, q3
	aesmc.8	q4, q4
	aese.8	q4, q7
	aesmc.8	q4, q4
	aese.8	q4, q8
	aesmc.8	q4, q4
	aese.8	q4, q9
	aesmc.8	q4, q4
	aese.8	q4, q10
	aesmc.8	q4, q4
	aese.8	q4, q11
	aesmc.8	q4, q4
	vld1.8	{q14}, [r0]!
	aese.8	q4, q12
	veor.8	q4, q4, q13
	veor.8	q14, q14, q4
	vst1.32	{q14}, [r1]!
L_aes_gcm_decrypt_arm32_crypto_128_done:
	ands	r11, r2, #15
	beq	L_aes_gcm_decrypt_arm32_crypto_128_partial_done
	veor.8	q14, q14, q14
	mov	r4, r11
	vst1.32	{q14}, [r9]
	cmp	r4, #4
	blt	L_aes_gcm_decrypt_arm32_crypto_128_start_sw
L_aes_gcm_decrypt_arm32_crypto_128_start_dw:
	ldr	lr, [r0], #4
	sub	r4, r4, #4
	str	lr, [r9], #4
	cmp	r4, #4
	bge	L_aes_gcm_decrypt_arm32_crypto_128_start_dw
L_aes_gcm_decrypt_arm32_crypto_128_start_sw:
	cmp	r4, #2
	blt	L_aes_gcm_decrypt_arm32_crypto_128_start_byte
	ldrh	lr, [r0], #2
	sub	r4, r4, #2
	strh	lr, [r9], #2
L_aes_gcm_decrypt_arm32_crypto_128_start_byte:
	cmp	r4, #1
	blt	L_aes_gcm_decrypt_arm32_crypto_128_end_bytes
	ldrb	lr, [r0], #1
	subs	r4, r4, #1
	strb	lr, [r9], #1
	bne	L_aes_gcm_decrypt_arm32_crypto_128_start_byte
L_aes_gcm_decrypt_arm32_crypto_128_end_bytes:
	sub	r9, r9, r11
	add	r5, r5, #1
	vmov.8	q4, q6
	rev	r8, r5
	vmov	s19, r8
	aese.8	q4, q0
	aesmc.8	q4, q4
	aese.8	q4, q1
	aesmc.8	q4, q4
	aese.8	q4, q2
	aesmc.8	q4, q4
	aese.8	q4, q3
	aesmc.8	q4, q4
	aese.8	q4, q7
	aesmc.8	q4, q4
	aese.8	q4, q8
	aesmc.8	q4, q4
	aese.8	q4, q9
	aesmc.8	q4, q4
	aese.8	q4, q10
	aesmc.8	q4, q4
	aese.8	q4, q11
	aesmc.8	q4, q4
	vld1.8	{q14}, [r9]
	aese.8	q4, q12
	veor.8	q4, q4, q13
	veor.8	q14, q14, q4
	vst1.32	{q14}, [r9]
	mov	r4, r11
	cmp	r4, #4
	blt	L_aes_gcm_decrypt_arm32_crypto_128_out_start_sw
L_aes_gcm_decrypt_arm32_crypto_128_out_start_dw:
	ldr	lr, [r9], #4
	sub	r4, r4, #4
	str	lr, [r1], #4
	cmp	r4, #4
	bge	L_aes_gcm_decrypt_arm32_crypto_128_out_start_dw
L_aes_gcm_decrypt_arm32_crypto_128_out_start_sw:
	cmp	r4, #2
	blt	L_aes_gcm_decrypt_arm32_crypto_128_out_start_byte
	ldrh	lr, [r9], #2
	sub	r4, r4, #2
	strh	lr, [r1], #2
L_aes_gcm_decrypt_arm32_crypto_128_out_start_byte:
	cmp	r4, #1
	blt	L_aes_gcm_decrypt_arm32_crypto_128_out_end_bytes
	ldrb	lr, [r9], #1
	subs	r4, r4, #1
	strb	lr, [r1], #1
	bne	L_aes_gcm_decrypt_arm32_crypto_128_out_start_byte
L_aes_gcm_decrypt_arm32_crypto_128_out_end_bytes:
L_aes_gcm_decrypt_arm32_crypto_128_partial_done:
	# Finish
	add	r8, r2, #15
	sub	r8, r5, r8, lsr #4
	rev	r8, r8
	vmov.32	s27, r8
	aese.8	q6, q0
	aesmc.8	q6, q6
	aese.8	q6, q1
	aesmc.8	q6, q6
	aese.8	q6, q2
	aesmc.8	q6, q6
	aese.8	q6, q3
	aesmc.8	q6, q6
	aese.8	q6, q7
	aesmc.8	q6, q6
	aese.8	q6, q8
	aesmc.8	q6, q6
	aese.8	q6, q9
	aesmc.8	q6, q6
	aese.8	q6, q10
	aesmc.8	q6, q6
	aese.8	q6, q11
	aesmc.8	q6, q6
	aese.8	q6, q12
	veor.8	q6, q6, q13
#endif /* !NO_AES_128 */
L_aes_gcm_decrypt_arm32_crypto_done_enc:
	vmov.i8	q13, #0x87
	vshr.u64	q13, q13, #56
	# gcm_h
	ldr	r8, [sp, #124]
	vld1.32	{q8}, [r8]
	# reg
	ldr	r9, [sp, #132]
	vld1.32	{q7}, [r9]
	# tmp
	ldr	r9, [sp, #128]
	lsr	lr, r6, #29
	lsl	r6, r6, #3
	rbit	lr, lr
	rbit	r6, r6
	vmov	s0, lr
	vmov	s1, r6
	lsr	lr, r2, #29
	lsl	r2, r2, #3
	rbit	lr, lr
	rbit	r2, r2
	vmov	s2, lr
	vmov	s3, r2
	veor.8	q7, q7, q0
	vmull.p64	q2, d15, d16
	vmull.p64	q3, d14, d17
	vmull.p64	q0, d14, d16
	vmull.p64	q1, d15, d17
	veor.8	q2, q2, q3
	#   Reduce
	vmull.p64	q7, d3, d27
	veor.8	d2, d2, d5
	veor.8	d1, d1, d4
	veor.8	d2, d2, d15
	veor.8	d1, d1, d14
	vmull.p64	q7, d2, d26
	veor.8	q7, q7, q0
	vmov.i8	q0, #0x55
	vshl.u8	q1, q7, #1
	vshr.u8	q7, q7, #1
	vbif.8	q7, q1, q0
	vmov.i8	q0, #51
	vshl.u8	q1, q7, #2
	vshr.u8	q7, q7, #2
	vbit.8	q1, q7, q0
	vshl.u8	q7, q1, #4
	vsri.u8	q7, q1, #4
	# DONE
	veor.8	q7, q7, q6
	# tag
	ldr	lr, [sp, #104]
	# tagSz
	ldr	r4, [sp, #108]
	cmp	r4, #16
	blt	L_aes_gcm_decrypt_arm32_crypto_tag_part_tag
	vld1.8	{q0}, [lr]
	b	L_aes_gcm_decrypt_arm32_crypto_tag_tag_loaded
L_aes_gcm_decrypt_arm32_crypto_tag_part_tag:
	veor.8	q0, q0, q0
	mov	r12, r4
	vst1.32	{q0}, [r9]
	cmp	r12, #4
	blt	L_aes_gcm_decrypt_arm32_crypto_tag_tag_start_sw
L_aes_gcm_decrypt_arm32_crypto_tag_tag_start_dw:
	ldr	r8, [lr], #4
	sub	r12, r12, #4
	str	r8, [r9], #4
	cmp	r12, #4
	bge	L_aes_gcm_decrypt_arm32_crypto_tag_tag_start_dw
L_aes_gcm_decrypt_arm32_crypto_tag_tag_start_sw:
	cmp	r12, #2
	blt	L_aes_gcm_decrypt_arm32_crypto_tag_tag_start_byte
	ldrh	r8, [lr], #2
	sub	r12, r12, #2
	strh	r8, [r9], #2
L_aes_gcm_decrypt_arm32_crypto_tag_tag_start_byte:
	cmp	r12, #1
	blt	L_aes_gcm_decrypt_arm32_crypto_tag_tag_end_bytes
	ldrb	r8, [lr], #1
	subs	r12, r12, #1
	strb	r8, [r9], #1
	bne	L_aes_gcm_decrypt_arm32_crypto_tag_tag_start_byte
L_aes_gcm_decrypt_arm32_crypto_tag_tag_end_bytes:
	sub	r9, r9, r4
	vld1.32	{q0}, [r9]
	mov	r12, #16
	vst1.32	{q7}, [r9]
	sub	r12, r12, r4
	eor	r8, r8, r8
	add	r9, r9, r4
L_aes_gcm_decrypt_arm32_crypto_tag_calc_tag_byte:
	strb	r8, [r9], #1
	subs	r12, r12, #1
	bne	L_aes_gcm_decrypt_arm32_crypto_tag_calc_tag_byte
	subs	r9, r9, #16
	vld1.32	{q7}, [r9]
L_aes_gcm_decrypt_arm32_crypto_tag_tag_loaded:
	vceq.i32	q0, q0, q7
	vmov	r5, s0
	vmov	r8, s1
	and	r12, r5, r8
	vmov	r5, s2
	vmov	r8, s3
	and	r12, r12, r5
	and	r12, r12, r8
	mov	r5, #-180
	mvn	r12, r12
	and	r0, r5, r12
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	AES_GCM_decrypt_AARCH32,.-AES_GCM_decrypt_AARCH32
#endif /* HAVE_AES_DECRYPT */
#endif /* HAVE_AESGCM */
#ifdef WOLFSSL_AES_XTS
	.text
	.align	4
	.globl	AES_XTS_encrypt_AARCH32
	.type	AES_XTS_encrypt_AARCH32, %function
AES_XTS_encrypt_AARCH32:
	push	{r4, r5, r6, r7, r8, r9, lr}
	vpush	{d8-d15}
	ldr	r12, [sp, #92]
	ldr	lr, [sp, #96]
	ldr	r5, [sp, #104]
	vldm.32	lr!, {q2-q9}
	lsr	r4, r2, #4
	and	r2, r2, #15
	vld1.8	{q0}, [r3]
	cmp	r5, #12
	blt	L_aes_xts_encrypt_arm32_crypto_start_128
	bgt	L_aes_xts_encrypt_arm32_crypto_start_256
	# AES_XTS_192
#ifndef NO_AES_192
	vldm.32	lr!, {q10-q14}
	aese.8	q0, q2
	aesmc.8	q0, q0
	aese.8	q0, q3
	aesmc.8	q0, q0
	aese.8	q0, q4
	aesmc.8	q0, q0
	aese.8	q0, q5
	aesmc.8	q0, q0
	aese.8	q0, q6
	aesmc.8	q0, q0
	aese.8	q0, q7
	aesmc.8	q0, q0
	aese.8	q0, q8
	aesmc.8	q0, q0
	aese.8	q0, q9
	aesmc.8	q0, q0
	aese.8	q0, q10
	aesmc.8	q0, q0
	aese.8	q0, q11
	aesmc.8	q0, q0
	aese.8	q0, q12
	aesmc.8	q0, q0
	aese.8	q0, q13
	veor.32	q0, q0, q14
	vmov	r6, r7, d0
	vmov	r8, r9, d1
	vldm.32	r12!, {q2-q9}
	vldm.32	r12!, {q10-q14}
	mov	lr, #0x87
	cmp	r4, #1
	blt	L_aes_xts_encrypt_arm32_crypto_192_done
L_aes_xts_encrypt_arm32_crypto_192_start_1:
	vld1.8	{q1}, [r0]!
	veor.32	q1, q1, q0
	aese.8	q1, q2
	aesmc.8	q1, q1
	and	r5, lr, r9, asr #31
	aese.8	q1, q3
	aesmc.8	q1, q1
	lsl	r9, r9, #1
	aese.8	q1, q4
	aesmc.8	q1, q1
	orr	r9, r9, r8, lsr #31
	aese.8	q1, q5
	aesmc.8	q1, q1
	lsl	r8, r8, #1
	aese.8	q1, q6
	aesmc.8	q1, q1
	orr	r8, r8, r7, lsr #31
	aese.8	q1, q7
	aesmc.8	q1, q1
	lsl	r7, r7, #1
	aese.8	q1, q8
	aesmc.8	q1, q1
	orr	r7, r7, r6, lsr #31
	aese.8	q1, q9
	aesmc.8	q1, q1
	eor	r6, r5, r6, lsl #1
	aese.8	q1, q10
	aesmc.8	q1, q1
	aese.8	q1, q11
	aesmc.8	q1, q1
	aese.8	q1, q12
	aesmc.8	q1, q1
	aese.8	q1, q13
	veor.32	q1, q1, q14
	veor.32	q1, q1, q0
	vmov	d0, r6, r7
	vmov	d1, r8, r9
	subs	r4, r4, #1
	vst1.8	{q1}, [r1]!
	bne	L_aes_xts_encrypt_arm32_crypto_192_start_1
L_aes_xts_encrypt_arm32_crypto_192_done:
	cmp	r2, #0
	beq	L_aes_xts_encrypt_arm32_crypto_192_partial_done
	sub	r1, r1, #16
	ldr	r4, [sp, #100]
	vld1.8	{q1}, [r1]!
	vst1.32	{q1}, [r4]
	mov	r5, r2
L_aes_xts_encrypt_arm32_crypto_192_start_byte:
	ldrb	r8, [r4]
	ldrb	r9, [r0], #1
	strb	r8, [r1], #1
	strb	r9, [r4], #1
	subs	r5, r5, #1
	bgt	L_aes_xts_encrypt_arm32_crypto_192_start_byte
	sub	r1, r1, r2
	sub	r4, r4, r2
	sub	r1, r1, #16
	vld1.32	{q1}, [r4]
	veor.32	q1, q1, q0
	aese.8	q1, q2
	aesmc.8	q1, q1
	aese.8	q1, q3
	aesmc.8	q1, q1
	aese.8	q1, q4
	aesmc.8	q1, q1
	aese.8	q1, q5
	aesmc.8	q1, q1
	aese.8	q1, q6
	aesmc.8	q1, q1
	aese.8	q1, q7
	aesmc.8	q1, q1
	aese.8	q1, q8
	aesmc.8	q1, q1
	aese.8	q1, q9
	aesmc.8	q1, q1
	aese.8	q1, q10
	aesmc.8	q1, q1
	aese.8	q1, q11
	aesmc.8	q1, q1
	aese.8	q1, q12
	aesmc.8	q1, q1
	aese.8	q1, q13
	veor.32	q1, q1, q14
	veor.32	q1, q1, q0
	vst1.8	{q1}, [r1]
L_aes_xts_encrypt_arm32_crypto_192_partial_done:
#endif /* !NO_AES_192 */
	b	L_aes_xts_encrypt_arm32_crypto_done
	# AES_XTS_256
L_aes_xts_encrypt_arm32_crypto_start_256:
#ifndef NO_AES_256
	vldm.32	lr!, {q10-q13}
	aese.8	q0, q2
	aesmc.8	q0, q0
	aese.8	q0, q3
	aesmc.8	q0, q0
	aese.8	q0, q4
	aesmc.8	q0, q0
	aese.8	q0, q5
	aesmc.8	q0, q0
	aese.8	q0, q6
	aesmc.8	q0, q0
	aese.8	q0, q7
	aesmc.8	q0, q0
	aese.8	q0, q8
	aesmc.8	q0, q0
	aese.8	q0, q9
	aesmc.8	q0, q0
	aese.8	q0, q10
	aesmc.8	q0, q0
	aese.8	q0, q11
	aesmc.8	q0, q0
	aese.8	q0, q12
	aesmc.8	q0, q0
	vld1.32	{q14}, [lr]!
	aese.8	q0, q13
	aesmc.8	q0, q0
	vld1.32	{q15}, [lr]!
	aese.8	q0, q14
	aesmc.8	q0, q0
	vld1.32	{q14}, [lr]!
	aese.8	q0, q15
	veor.32	q0, q0, q14
	vmov	r6, r7, d0
	vmov	r8, r9, d1
	vldm.32	r12!, {q2-q9}
	vldm.32	r12!, {q10-q13}
	mov	lr, #0x87
	cmp	r4, #1
	blt	L_aes_xts_encrypt_arm32_crypto_256_done
L_aes_xts_encrypt_arm32_crypto_256_start_1:
	vld1.8	{q1}, [r0]!
	veor.32	q1, q1, q0
	aese.8	q1, q2
	aesmc.8	q1, q1
	and	r5, lr, r9, asr #31
	aese.8	q1, q3
	aesmc.8	q1, q1
	lsl	r9, r9, #1
	aese.8	q1, q4
	aesmc.8	q1, q1
	orr	r9, r9, r8, lsr #31
	aese.8	q1, q5
	aesmc.8	q1, q1
	lsl	r8, r8, #1
	aese.8	q1, q6
	aesmc.8	q1, q1
	orr	r8, r8, r7, lsr #31
	aese.8	q1, q7
	aesmc.8	q1, q1
	lsl	r7, r7, #1
	aese.8	q1, q8
	aesmc.8	q1, q1
	orr	r7, r7, r6, lsr #31
	aese.8	q1, q9
	aesmc.8	q1, q1
	eor	r6, r5, r6, lsl #1
	aese.8	q1, q10
	aesmc.8	q1, q1
	aese.8	q1, q11
	aesmc.8	q1, q1
	aese.8	q1, q12
	aesmc.8	q1, q1
	vld1.32	{q14}, [r12]!
	aese.8	q1, q13
	aesmc.8	q1, q1
	vld1.32	{q15}, [r12]!
	aese.8	q1, q14
	aesmc.8	q1, q1
	vld1.32	{q14}, [r12]!
	aese.8	q1, q15
	veor.32	q1, q1, q14
	sub	r12, r12, #48
	veor.32	q1, q1, q0
	vmov	d0, r6, r7
	vmov	d1, r8, r9
	subs	r4, r4, #1
	vst1.8	{q1}, [r1]!
	bne	L_aes_xts_encrypt_arm32_crypto_256_start_1
L_aes_xts_encrypt_arm32_crypto_256_done:
	cmp	r2, #0
	beq	L_aes_xts_encrypt_arm32_crypto_256_partial_done
	sub	r1, r1, #16
	ldr	r4, [sp, #100]
	vld1.8	{q1}, [r1]!
	vst1.32	{q1}, [r4]
	mov	r5, r2
L_aes_xts_encrypt_arm32_crypto_256_start_byte:
	ldrb	r8, [r4]
	ldrb	r9, [r0], #1
	strb	r8, [r1], #1
	strb	r9, [r4], #1
	subs	r5, r5, #1
	bgt	L_aes_xts_encrypt_arm32_crypto_256_start_byte
	sub	r1, r1, r2
	sub	r4, r4, r2
	sub	r1, r1, #16
	vld1.32	{q1}, [r4]
	veor.32	q1, q1, q0
	aese.8	q1, q2
	aesmc.8	q1, q1
	aese.8	q1, q3
	aesmc.8	q1, q1
	aese.8	q1, q4
	aesmc.8	q1, q1
	aese.8	q1, q5
	aesmc.8	q1, q1
	aese.8	q1, q6
	aesmc.8	q1, q1
	aese.8	q1, q7
	aesmc.8	q1, q1
	aese.8	q1, q8
	aesmc.8	q1, q1
	aese.8	q1, q9
	aesmc.8	q1, q1
	aese.8	q1, q10
	aesmc.8	q1, q1
	aese.8	q1, q11
	aesmc.8	q1, q1
	aese.8	q1, q12
	aesmc.8	q1, q1
	vld1.32	{q14}, [r12]!
	aese.8	q1, q13
	aesmc.8	q1, q1
	vld1.32	{q15}, [r12]!
	aese.8	q1, q14
	aesmc.8	q1, q1
	vld1.32	{q14}, [r12]!
	aese.8	q1, q15
	veor.32	q1, q1, q14
	veor.32	q1, q1, q0
	vst1.8	{q1}, [r1]
L_aes_xts_encrypt_arm32_crypto_256_partial_done:
#endif /* !NO_AES_256 */
	b	L_aes_xts_encrypt_arm32_crypto_done
	# AES_XTS_128
L_aes_xts_encrypt_arm32_crypto_start_128:
#ifndef NO_AES_128
	vldm.32	lr!, {q10-q12}
	aese.8	q0, q2
	aesmc.8	q0, q0
	aese.8	q0, q3
	aesmc.8	q0, q0
	aese.8	q0, q4
	aesmc.8	q0, q0
	aese.8	q0, q5
	aesmc.8	q0, q0
	aese.8	q0, q6
	aesmc.8	q0, q0
	aese.8	q0, q7
	aesmc.8	q0, q0
	aese.8	q0, q8
	aesmc.8	q0, q0
	aese.8	q0, q9
	aesmc.8	q0, q0
	aese.8	q0, q10
	aesmc.8	q0, q0
	aese.8	q0, q11
	veor.32	q0, q0, q12
	vmov	r6, r7, d0
	vmov	r8, r9, d1
	vldm.32	r12!, {q2-q9}
	vldm.32	r12!, {q10-q12}
	mov	lr, #0x87
	cmp	r4, #1
	blt	L_aes_xts_encrypt_arm32_crypto_128_done
L_aes_xts_encrypt_arm32_crypto_128_start_1:
	vld1.8	{q1}, [r0]!
	veor.32	q1, q1, q0
	aese.8	q1, q2
	aesmc.8	q1, q1
	and	r5, lr, r9, asr #31
	aese.8	q1, q3
	aesmc.8	q1, q1
	lsl	r9, r9, #1
	aese.8	q1, q4
	aesmc.8	q1, q1
	orr	r9, r9, r8, lsr #31
	aese.8	q1, q5
	aesmc.8	q1, q1
	lsl	r8, r8, #1
	aese.8	q1, q6
	aesmc.8	q1, q1
	orr	r8, r8, r7, lsr #31
	aese.8	q1, q7
	aesmc.8	q1, q1
	lsl	r7, r7, #1
	aese.8	q1, q8
	aesmc.8	q1, q1
	orr	r7, r7, r6, lsr #31
	aese.8	q1, q9
	aesmc.8	q1, q1
	eor	r6, r5, r6, lsl #1
	aese.8	q1, q10
	aesmc.8	q1, q1
	aese.8	q1, q11
	veor.32	q1, q1, q12
	veor.32	q1, q1, q0
	vmov	d0, r6, r7
	vmov	d1, r8, r9
	subs	r4, r4, #1
	vst1.8	{q1}, [r1]!
	bne	L_aes_xts_encrypt_arm32_crypto_128_start_1
L_aes_xts_encrypt_arm32_crypto_128_done:
	cmp	r2, #0
	beq	L_aes_xts_encrypt_arm32_crypto_128_partial_done
	sub	r1, r1, #16
	ldr	r4, [sp, #100]
	vld1.8	{q1}, [r1]!
	vst1.32	{q1}, [r4]
	mov	r5, r2
L_aes_xts_encrypt_arm32_crypto_128_start_byte:
	ldrb	r8, [r4]
	ldrb	r9, [r0], #1
	strb	r8, [r1], #1
	strb	r9, [r4], #1
	subs	r5, r5, #1
	bgt	L_aes_xts_encrypt_arm32_crypto_128_start_byte
	sub	r1, r1, r2
	sub	r4, r4, r2
	sub	r1, r1, #16
	vld1.32	{q1}, [r4]
	veor.32	q1, q1, q0
	aese.8	q1, q2
	aesmc.8	q1, q1
	aese.8	q1, q3
	aesmc.8	q1, q1
	aese.8	q1, q4
	aesmc.8	q1, q1
	aese.8	q1, q5
	aesmc.8	q1, q1
	aese.8	q1, q6
	aesmc.8	q1, q1
	aese.8	q1, q7
	aesmc.8	q1, q1
	aese.8	q1, q8
	aesmc.8	q1, q1
	aese.8	q1, q9
	aesmc.8	q1, q1
	aese.8	q1, q10
	aesmc.8	q1, q1
	aese.8	q1, q11
	veor.32	q1, q1, q12
	veor.32	q1, q1, q0
	vst1.8	{q1}, [r1]
L_aes_xts_encrypt_arm32_crypto_128_partial_done:
#endif /* !NO_AES_128 */
L_aes_xts_encrypt_arm32_crypto_done:
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, r9, pc}
	.size	AES_XTS_encrypt_AARCH32,.-AES_XTS_encrypt_AARCH32
#ifdef HAVE_AES_DECRYPT
	.text
	.align	4
	.globl	AES_XTS_decrypt_AARCH32
	.type	AES_XTS_decrypt_AARCH32, %function
AES_XTS_decrypt_AARCH32:
	push	{r4, r5, r6, r7, r8, r9, lr}
	vpush	{d8-d15}
	ldr	r12, [sp, #92]
	ldr	lr, [sp, #96]
	vldm.32	lr!, {q2-q9}
	eor	r5, r5, r5
	lsr	r4, r2, #4
	ands	r2, r2, #15
	sub	r5, r5, r2
	sub	r4, r4, r5, lsr #31
	vld1.8	{q1}, [r3]
	ldr	r5, [sp, #104]
	cmp	r5, #12
	blt	L_aes_xts_decrypt_arm32_crypto_start_128
	bgt	L_aes_xts_decrypt_arm32_crypto_start_256
	# AES_XTS_192
#ifndef NO_AES_192
	vldm.32	lr!, {q10-q14}
	aese.8	q1, q2
	aesmc.8	q1, q1
	aese.8	q1, q3
	aesmc.8	q1, q1
	aese.8	q1, q4
	aesmc.8	q1, q1
	aese.8	q1, q5
	aesmc.8	q1, q1
	aese.8	q1, q6
	aesmc.8	q1, q1
	aese.8	q1, q7
	aesmc.8	q1, q1
	aese.8	q1, q8
	aesmc.8	q1, q1
	aese.8	q1, q9
	aesmc.8	q1, q1
	aese.8	q1, q10
	aesmc.8	q1, q1
	aese.8	q1, q11
	aesmc.8	q1, q1
	aese.8	q1, q12
	aesmc.8	q1, q1
	aese.8	q1, q13
	veor.32	q1, q1, q14
	vmov	r6, r7, d2
	vmov	r8, r9, d3
	vldm.32	r12!, {q2-q9}
	vldm.32	r12!, {q10-q14}
	mov	lr, #0x87
	cmp	r4, #1
	blt	L_aes_xts_decrypt_arm32_crypto_192_done
L_aes_xts_decrypt_arm32_crypto_192_start_1:
	vld1.8	{q0}, [r0]!
	veor.32	q0, q0, q1
	aesd.8	q0, q2
	aesimc.8	q0, q0
	and	r5, lr, r9, asr #31
	aesd.8	q0, q3
	aesimc.8	q0, q0
	lsl	r9, r9, #1
	aesd.8	q0, q4
	aesimc.8	q0, q0
	orr	r9, r9, r8, lsr #31
	aesd.8	q0, q5
	aesimc.8	q0, q0
	lsl	r8, r8, #1
	aesd.8	q0, q6
	aesimc.8	q0, q0
	orr	r8, r8, r7, lsr #31
	aesd.8	q0, q7
	aesimc.8	q0, q0
	lsl	r7, r7, #1
	aesd.8	q0, q8
	aesimc.8	q0, q0
	orr	r7, r7, r6, lsr #31
	aesd.8	q0, q9
	aesimc.8	q0, q0
	eor	r6, r5, r6, lsl #1
	aesd.8	q0, q10
	aesimc.8	q0, q0
	aesd.8	q0, q11
	aesimc.8	q0, q0
	aesd.8	q0, q12
	aesimc.8	q0, q0
	aesd.8	q0, q13
	veor.32	q0, q0, q14
	veor.32	q0, q0, q1
	vmov	d2, r6, r7
	vmov	d3, r8, r9
	subs	r4, r4, #1
	vst1.8	{q0}, [r1]!
	bne	L_aes_xts_decrypt_arm32_crypto_192_start_1
L_aes_xts_decrypt_arm32_crypto_192_done:
	cmp	r2, #0
	beq	L_aes_xts_decrypt_arm32_crypto_192_partial_done
	and	r5, lr, r9, asr #31
	lsl	r9, r9, #1
	orr	r9, r9, r8, lsr #31
	lsl	r8, r8, #1
	orr	r8, r8, r7, lsr #31
	lsl	r7, r7, #1
	orr	r7, r7, r6, lsr #31
	eor	r6, r5, r6, lsl #1
	vmov	d30, r6, r7
	vmov	d31, r8, r9
	vld1.8	{q0}, [r0]!
	ldr	r4, [sp, #100]
	veor.32	q0, q0, q15
	aesd.8	q0, q2
	aesimc.8	q0, q0
	aesd.8	q0, q3
	aesimc.8	q0, q0
	aesd.8	q0, q4
	aesimc.8	q0, q0
	aesd.8	q0, q5
	aesimc.8	q0, q0
	aesd.8	q0, q6
	aesimc.8	q0, q0
	aesd.8	q0, q7
	aesimc.8	q0, q0
	aesd.8	q0, q8
	aesimc.8	q0, q0
	aesd.8	q0, q9
	aesimc.8	q0, q0
	aesd.8	q0, q10
	aesimc.8	q0, q0
	aesd.8	q0, q11
	aesimc.8	q0, q0
	aesd.8	q0, q12
	aesimc.8	q0, q0
	aesd.8	q0, q13
	veor.32	q0, q0, q14
	veor.32	q0, q0, q15
	vst1.32	{q0}, [r4]
	add	r1, r1, #16
	mov	r5, r2
L_aes_xts_decrypt_arm32_crypto_192_start_byte:
	ldrb	r8, [r4]
	ldrb	r9, [r0], #1
	strb	r8, [r1], #1
	strb	r9, [r4], #1
	subs	r5, r5, #1
	bgt	L_aes_xts_decrypt_arm32_crypto_192_start_byte
	sub	r1, r1, r2
	sub	r4, r4, r2
	sub	r1, r1, #16
	vld1.32	{q0}, [r4]
	veor.32	q0, q0, q1
	aesd.8	q0, q2
	aesimc.8	q0, q0
	aesd.8	q0, q3
	aesimc.8	q0, q0
	aesd.8	q0, q4
	aesimc.8	q0, q0
	aesd.8	q0, q5
	aesimc.8	q0, q0
	aesd.8	q0, q6
	aesimc.8	q0, q0
	aesd.8	q0, q7
	aesimc.8	q0, q0
	aesd.8	q0, q8
	aesimc.8	q0, q0
	aesd.8	q0, q9
	aesimc.8	q0, q0
	aesd.8	q0, q10
	aesimc.8	q0, q0
	aesd.8	q0, q11
	aesimc.8	q0, q0
	aesd.8	q0, q12
	aesimc.8	q0, q0
	aesd.8	q0, q13
	veor.32	q0, q0, q14
	veor.32	q0, q0, q1
	vst1.8	{q0}, [r1]
L_aes_xts_decrypt_arm32_crypto_192_partial_done:
#endif /* !NO_AES_192 */
	b	L_aes_xts_decrypt_arm32_crypto_done
	# AES_XTS_256
L_aes_xts_decrypt_arm32_crypto_start_256:
#ifndef NO_AES_256
	vldm.32	lr!, {q10-q13}
	aese.8	q1, q2
	aesmc.8	q1, q1
	aese.8	q1, q3
	aesmc.8	q1, q1
	aese.8	q1, q4
	aesmc.8	q1, q1
	aese.8	q1, q5
	aesmc.8	q1, q1
	aese.8	q1, q6
	aesmc.8	q1, q1
	aese.8	q1, q7
	aesmc.8	q1, q1
	aese.8	q1, q8
	aesmc.8	q1, q1
	aese.8	q1, q9
	aesmc.8	q1, q1
	aese.8	q1, q10
	aesmc.8	q1, q1
	aese.8	q1, q11
	aesmc.8	q1, q1
	aese.8	q1, q12
	aesmc.8	q1, q1
	vld1.32	{q14}, [lr]!
	aese.8	q1, q13
	aesmc.8	q1, q1
	vld1.32	{q15}, [lr]!
	aese.8	q1, q14
	aesmc.8	q1, q1
	vld1.32	{q14}, [lr]!
	aese.8	q1, q15
	veor.32	q1, q1, q14
	vmov	r6, r7, d2
	vmov	r8, r9, d3
	vldm.32	r12!, {q2-q9}
	vldm.32	r12!, {q10-q12}
	mov	lr, #0x87
	cmp	r4, #1
	blt	L_aes_xts_decrypt_arm32_crypto_256_done
L_aes_xts_decrypt_arm32_crypto_256_start_1:
	vld1.8	{q0}, [r0]!
	veor.32	q0, q0, q1
	aesd.8	q0, q2
	aesimc.8	q0, q0
	and	r5, lr, r9, asr #31
	aesd.8	q0, q3
	aesimc.8	q0, q0
	lsl	r9, r9, #1
	aesd.8	q0, q4
	aesimc.8	q0, q0
	orr	r9, r9, r8, lsr #31
	aesd.8	q0, q5
	aesimc.8	q0, q0
	lsl	r8, r8, #1
	aesd.8	q0, q6
	aesimc.8	q0, q0
	orr	r8, r8, r7, lsr #31
	aesd.8	q0, q7
	aesimc.8	q0, q0
	lsl	r7, r7, #1
	aesd.8	q0, q8
	aesimc.8	q0, q0
	orr	r7, r7, r6, lsr #31
	aesd.8	q0, q9
	aesimc.8	q0, q0
	eor	r6, r5, r6, lsl #1
	aesd.8	q0, q10
	aesimc.8	q0, q0
	aesd.8	q0, q11
	aesimc.8	q0, q0
	vld1.32	{q13}, [r12]!
	aesd.8	q0, q12
	aesimc.8	q0, q0
	vld1.32	{q14}, [r12]!
	aesd.8	q0, q13
	aesimc.8	q0, q0
	vld1.32	{q13}, [r12]!
	aesd.8	q0, q14
	aesimc.8	q0, q0
	vld1.32	{q14}, [r12]
	aesd.8	q0, q13
	veor.32	q0, q0, q14
	sub	r12, r12, #48
	veor.32	q0, q0, q1
	vmov	d2, r6, r7
	vmov	d3, r8, r9
	subs	r4, r4, #1
	vst1.8	{q0}, [r1]!
	bne	L_aes_xts_decrypt_arm32_crypto_256_start_1
L_aes_xts_decrypt_arm32_crypto_256_done:
	cmp	r2, #0
	beq	L_aes_xts_decrypt_arm32_crypto_256_partial_done
	and	r5, lr, r9, asr #31
	lsl	r9, r9, #1
	orr	r9, r9, r8, lsr #31
	lsl	r8, r8, #1
	orr	r8, r8, r7, lsr #31
	lsl	r7, r7, #1
	orr	r7, r7, r6, lsr #31
	eor	r6, r5, r6, lsl #1
	vmov	d30, r6, r7
	vmov	d31, r8, r9
	vld1.8	{q0}, [r0]!
	ldr	r4, [sp, #100]
	veor.32	q0, q0, q15
	aesd.8	q0, q2
	aesimc.8	q0, q0
	aesd.8	q0, q3
	aesimc.8	q0, q0
	aesd.8	q0, q4
	aesimc.8	q0, q0
	aesd.8	q0, q5
	aesimc.8	q0, q0
	aesd.8	q0, q6
	aesimc.8	q0, q0
	aesd.8	q0, q7
	aesimc.8	q0, q0
	aesd.8	q0, q8
	aesimc.8	q0, q0
	aesd.8	q0, q9
	aesimc.8	q0, q0
	aesd.8	q0, q10
	aesimc.8	q0, q0
	aesd.8	q0, q11
	aesimc.8	q0, q0
	vld1.32	{q13}, [r12]!
	aesd.8	q0, q12
	aesimc.8	q0, q0
	vld1.32	{q14}, [r12]!
	aesd.8	q0, q13
	aesimc.8	q0, q0
	vld1.32	{q13}, [r12]!
	aesd.8	q0, q14
	aesimc.8	q0, q0
	vld1.32	{q14}, [r12]
	aesd.8	q0, q13
	veor.32	q0, q0, q14
	sub	r12, r12, #48
	veor.32	q0, q0, q15
	vst1.32	{q0}, [r4]
	add	r1, r1, #16
	mov	r5, r2
L_aes_xts_decrypt_arm32_crypto_256_start_byte:
	ldrb	r8, [r4]
	ldrb	r9, [r0], #1
	strb	r8, [r1], #1
	strb	r9, [r4], #1
	subs	r5, r5, #1
	bgt	L_aes_xts_decrypt_arm32_crypto_256_start_byte
	sub	r1, r1, r2
	sub	r4, r4, r2
	sub	r1, r1, #16
	vld1.32	{q0}, [r4]
	veor.32	q0, q0, q1
	aesd.8	q0, q2
	aesimc.8	q0, q0
	aesd.8	q0, q3
	aesimc.8	q0, q0
	aesd.8	q0, q4
	aesimc.8	q0, q0
	aesd.8	q0, q5
	aesimc.8	q0, q0
	aesd.8	q0, q6
	aesimc.8	q0, q0
	aesd.8	q0, q7
	aesimc.8	q0, q0
	aesd.8	q0, q8
	aesimc.8	q0, q0
	aesd.8	q0, q9
	aesimc.8	q0, q0
	aesd.8	q0, q10
	aesimc.8	q0, q0
	aesd.8	q0, q11
	aesimc.8	q0, q0
	vld1.32	{q13}, [r12]!
	aesd.8	q0, q12
	aesimc.8	q0, q0
	vld1.32	{q14}, [r12]!
	aesd.8	q0, q13
	aesimc.8	q0, q0
	vld1.32	{q13}, [r12]!
	aesd.8	q0, q14
	aesimc.8	q0, q0
	vld1.32	{q14}, [r12]
	aesd.8	q0, q13
	veor.32	q0, q0, q14
	veor.32	q0, q0, q1
	vst1.8	{q0}, [r1]
L_aes_xts_decrypt_arm32_crypto_256_partial_done:
#endif /* !NO_AES_256 */
	b	L_aes_xts_decrypt_arm32_crypto_done
	# AES_XTS_128
L_aes_xts_decrypt_arm32_crypto_start_128:
#ifndef NO_AES_128
	vldm.32	lr!, {q10-q12}
	aese.8	q1, q2
	aesmc.8	q1, q1
	aese.8	q1, q3
	aesmc.8	q1, q1
	aese.8	q1, q4
	aesmc.8	q1, q1
	aese.8	q1, q5
	aesmc.8	q1, q1
	aese.8	q1, q6
	aesmc.8	q1, q1
	aese.8	q1, q7
	aesmc.8	q1, q1
	aese.8	q1, q8
	aesmc.8	q1, q1
	aese.8	q1, q9
	aesmc.8	q1, q1
	aese.8	q1, q10
	aesmc.8	q1, q1
	aese.8	q1, q11
	veor.32	q1, q1, q12
	vmov	r6, r7, d2
	vmov	r8, r9, d3
	vldm.32	r12!, {q2-q9}
	vldm.32	r12!, {q10-q12}
	mov	lr, #0x87
	cmp	r4, #1
	blt	L_aes_xts_decrypt_arm32_crypto_128_done
L_aes_xts_decrypt_arm32_crypto_128_start_1:
	vld1.8	{q0}, [r0]!
	veor.32	q0, q0, q1
	aesd.8	q0, q2
	aesimc.8	q0, q0
	and	r5, lr, r9, asr #31
	aesd.8	q0, q3
	aesimc.8	q0, q0
	lsl	r9, r9, #1
	aesd.8	q0, q4
	aesimc.8	q0, q0
	orr	r9, r9, r8, lsr #31
	aesd.8	q0, q5
	aesimc.8	q0, q0
	lsl	r8, r8, #1
	aesd.8	q0, q6
	aesimc.8	q0, q0
	orr	r8, r8, r7, lsr #31
	aesd.8	q0, q7
	aesimc.8	q0, q0
	lsl	r7, r7, #1
	aesd.8	q0, q8
	aesimc.8	q0, q0
	orr	r7, r7, r6, lsr #31
	aesd.8	q0, q9
	aesimc.8	q0, q0
	eor	r6, r5, r6, lsl #1
	aesd.8	q0, q10
	aesimc.8	q0, q0
	aesd.8	q0, q11
	veor.32	q0, q0, q12
	veor.32	q0, q0, q1
	vmov	d2, r6, r7
	vmov	d3, r8, r9
	subs	r4, r4, #1
	vst1.8	{q0}, [r1]!
	bne	L_aes_xts_decrypt_arm32_crypto_128_start_1
L_aes_xts_decrypt_arm32_crypto_128_done:
	cmp	r2, #0
	beq	L_aes_xts_decrypt_arm32_crypto_128_partial_done
	and	r5, lr, r9, asr #31
	lsl	r9, r9, #1
	orr	r9, r9, r8, lsr #31
	lsl	r8, r8, #1
	orr	r8, r8, r7, lsr #31
	lsl	r7, r7, #1
	orr	r7, r7, r6, lsr #31
	eor	r6, r5, r6, lsl #1
	vmov	d30, r6, r7
	vmov	d31, r8, r9
	vld1.8	{q0}, [r0]!
	ldr	r4, [sp, #100]
	veor.32	q0, q0, q15
	aesd.8	q0, q2
	aesimc.8	q0, q0
	aesd.8	q0, q3
	aesimc.8	q0, q0
	aesd.8	q0, q4
	aesimc.8	q0, q0
	aesd.8	q0, q5
	aesimc.8	q0, q0
	aesd.8	q0, q6
	aesimc.8	q0, q0
	aesd.8	q0, q7
	aesimc.8	q0, q0
	aesd.8	q0, q8
	aesimc.8	q0, q0
	aesd.8	q0, q9
	aesimc.8	q0, q0
	aesd.8	q0, q10
	aesimc.8	q0, q0
	aesd.8	q0, q11
	veor.32	q0, q0, q12
	veor.32	q0, q0, q15
	vst1.32	{q0}, [r4]
	add	r1, r1, #16
	mov	r5, r2
L_aes_xts_decrypt_arm32_crypto_128_start_byte:
	ldrb	r8, [r4]
	ldrb	r9, [r0], #1
	strb	r8, [r1], #1
	strb	r9, [r4], #1
	subs	r5, r5, #1
	bgt	L_aes_xts_decrypt_arm32_crypto_128_start_byte
	sub	r1, r1, r2
	sub	r4, r4, r2
	sub	r1, r1, #16
	vld1.32	{q0}, [r4]
	veor.32	q0, q0, q1
	aesd.8	q0, q2
	aesimc.8	q0, q0
	aesd.8	q0, q3
	aesimc.8	q0, q0
	aesd.8	q0, q4
	aesimc.8	q0, q0
	aesd.8	q0, q5
	aesimc.8	q0, q0
	aesd.8	q0, q6
	aesimc.8	q0, q0
	aesd.8	q0, q7
	aesimc.8	q0, q0
	aesd.8	q0, q8
	aesimc.8	q0, q0
	aesd.8	q0, q9
	aesimc.8	q0, q0
	aesd.8	q0, q10
	aesimc.8	q0, q0
	aesd.8	q0, q11
	veor.32	q0, q0, q12
	veor.32	q0, q0, q1
	vst1.8	{q0}, [r1]
L_aes_xts_decrypt_arm32_crypto_128_partial_done:
#endif /* !NO_AES_128 */
L_aes_xts_decrypt_arm32_crypto_done:
	vpop	{d8-d15}
	pop	{r4, r5, r6, r7, r8, r9, pc}
	.size	AES_XTS_decrypt_AARCH32,.-AES_XTS_decrypt_AARCH32
#endif /* HAVE_AES_DECRYPT */
#endif /* WOLFSSL_AES_XTS */
#else
#ifdef HAVE_AES_DECRYPT
#ifndef __APPLE__
	.text
	.type	L_AES_ARM32_td_data, %object
	.size	L_AES_ARM32_td_data, 1024
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_ARM32_td_data:
	.long	0x5051f4a7,0x537e4165,0xc31a17a4,0x963a275e
	.long	0xcb3bab6b,0xf11f9d45,0xabacfa58,0x934be303
	.long	0x552030fa,0xf6ad766d,0x9188cc76,0x25f5024c
	.long	0xfc4fe5d7,0xd7c52acb,0x80263544,0x8fb562a3
	.long	0x49deb15a,0x6725ba1b,0x9845ea0e,0xe15dfec0
	.long	0x02c32f75,0x12814cf0,0xa38d4697,0xc66bd3f9
	.long	0xe7038f5f,0x9515929c,0xebbf6d7a,0xda955259
	.long	0x2dd4be83,0xd3587421,0x2949e069,0x448ec9c8
	.long	0x6a75c289,0x78f48e79,0x6b99583e,0xdd27b971
	.long	0xb6bee14f,0x17f088ad,0x66c920ac,0xb47dce3a
	.long	0x1863df4a,0x82e51a31,0x60975133,0x4562537f
	.long	0xe0b16477,0x84bb6bae,0x1cfe81a0,0x94f9082b
	.long	0x58704868,0x198f45fd,0x8794de6c,0xb7527bf8
	.long	0x23ab73d3,0xe2724b02,0x57e31f8f,0x2a6655ab
	.long	0x07b2eb28,0x032fb5c2,0x9a86c57b,0xa5d33708
	.long	0xf2302887,0xb223bfa5,0xba02036a,0x5ced1682
	.long	0x2b8acf1c,0x92a779b4,0xf0f307f2,0xa14e69e2
	.long	0xcd65daf4,0xd50605be,0x1fd13462,0x8ac4a6fe
	.long	0x9d342e53,0xa0a2f355,0x32058ae1,0x75a4f6eb
	.long	0x390b83ec,0xaa4060ef,0x065e719f,0x51bd6e10
	.long	0xf93e218a,0x3d96dd06,0xaedd3e05,0x464de6bd
	.long	0xb591548d,0x0571c45d,0x6f0406d4,0xff605015
	.long	0x241998fb,0x97d6bde9,0xcc894043,0x7767d99e
	.long	0xbdb0e842,0x8807898b,0x38e7195b,0xdb79c8ee
	.long	0x47a17c0a,0xe97c420f,0xc9f8841e,0x00000000
	.long	0x83098086,0x48322bed,0xac1e1170,0x4e6c5a72
	.long	0xfbfd0eff,0x560f8538,0x1e3daed5,0x27362d39
	.long	0x640a0fd9,0x21685ca6,0xd19b5b54,0x3a24362e
	.long	0xb10c0a67,0x0f9357e7,0xd2b4ee96,0x9e1b9b91
	.long	0x4f80c0c5,0xa261dc20,0x695a774b,0x161c121a
	.long	0x0ae293ba,0xe5c0a02a,0x433c22e0,0x1d121b17
	.long	0x0b0e090d,0xadf28bc7,0xb92db6a8,0xc8141ea9
	.long	0x8557f119,0x4caf7507,0xbbee99dd,0xfda37f60
	.long	0x9ff70126,0xbc5c72f5,0xc544663b,0x345bfb7e
	.long	0x768b4329,0xdccb23c6,0x68b6edfc,0x63b8e4f1
	.long	0xcad731dc,0x10426385,0x40139722,0x2084c611
	.long	0x7d854a24,0xf8d2bb3d,0x11aef932,0x6dc729a1
	.long	0x4b1d9e2f,0xf3dcb230,0xec0d8652,0xd077c1e3
	.long	0x6c2bb316,0x99a970b9,0xfa119448,0x2247e964
	.long	0xc4a8fc8c,0x1aa0f03f,0xd8567d2c,0xef223390
	.long	0xc787494e,0xc1d938d1,0xfe8ccaa2,0x3698d40b
	.long	0xcfa6f581,0x28a57ade,0x26dab78e,0xa43fadbf
	.long	0xe42c3a9d,0x0d507892,0x9b6a5fcc,0x62547e46
	.long	0xc2f68d13,0xe890d8b8,0x5e2e39f7,0xf582c3af
	.long	0xbe9f5d80,0x7c69d093,0xa96fd52d,0xb3cf2512
	.long	0x3bc8ac99,0xa710187d,0x6ee89c63,0x7bdb3bbb
	.long	0x09cd2678,0xf46e5918,0x01ec9ab7,0xa8834f9a
	.long	0x65e6956e,0x7eaaffe6,0x0821bccf,0xe6ef15e8
	.long	0xd9bae79b,0xce4a6f36,0xd4ea9f09,0xd629b07c
	.long	0xaf31a4b2,0x312a3f23,0x30c6a594,0xc035a266
	.long	0x37744ebc,0xa6fc82ca,0xb0e090d0,0x1533a7d8
	.long	0x4af10498,0xf741ecda,0x0e7fcd50,0x2f1791f6
	.long	0x8d764dd6,0x4d43efb0,0x54ccaa4d,0xdfe49604
	.long	0xe39ed1b5,0x1b4c6a88,0xb8c12c1f,0x7f466551
	.long	0x049d5eea,0x5d018c35,0x73fa8774,0x2efb0b41
	.long	0x5ab3671d,0x5292dbd2,0x33e91056,0x136dd647
	.long	0x8c9ad761,0x7a37a10c,0x8e59f814,0x89eb133c
	.long	0xeecea927,0x35b761c9,0xede11ce5,0x3c7a47b1
	.long	0x599cd2df,0x3f55f273,0x791814ce,0xbf73c737
	.long	0xea53f7cd,0x5b5ffdaa,0x14df3d6f,0x867844db
	.long	0x81caaff3,0x3eb968c4,0x2c382434,0x5fc2a340
	.long	0x72161dc3,0x0cbce225,0x8b283c49,0x41ff0d95
	.long	0x7139a801,0xde080cb3,0x9cd8b4e4,0x906456c1
	.long	0x617bcb84,0x70d532b6,0x74486c5c,0x42d0b857
#endif /* HAVE_AES_DECRYPT */
#if defined(HAVE_AES_DECRYPT) || defined(HAVE_AES_CBC) || \
    defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || \
    defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
#ifndef __APPLE__
	.text
	.type	L_AES_ARM32_te_data, %object
	.size	L_AES_ARM32_te_data, 1024
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_ARM32_te_data:
	.long	0xa5c66363,0x84f87c7c,0x99ee7777,0x8df67b7b
	.long	0x0dfff2f2,0xbdd66b6b,0xb1de6f6f,0x5491c5c5
	.long	0x50603030,0x03020101,0xa9ce6767,0x7d562b2b
	.long	0x19e7fefe,0x62b5d7d7,0xe64dabab,0x9aec7676
	.long	0x458fcaca,0x9d1f8282,0x4089c9c9,0x87fa7d7d
	.long	0x15effafa,0xebb25959,0xc98e4747,0x0bfbf0f0
	.long	0xec41adad,0x67b3d4d4,0xfd5fa2a2,0xea45afaf
	.long	0xbf239c9c,0xf753a4a4,0x96e47272,0x5b9bc0c0
	.long	0xc275b7b7,0x1ce1fdfd,0xae3d9393,0x6a4c2626
	.long	0x5a6c3636,0x417e3f3f,0x02f5f7f7,0x4f83cccc
	.long	0x5c683434,0xf451a5a5,0x34d1e5e5,0x08f9f1f1
	.long	0x93e27171,0x73abd8d8,0x53623131,0x3f2a1515
	.long	0x0c080404,0x5295c7c7,0x65462323,0x5e9dc3c3
	.long	0x28301818,0xa1379696,0x0f0a0505,0xb52f9a9a
	.long	0x090e0707,0x36241212,0x9b1b8080,0x3ddfe2e2
	.long	0x26cdebeb,0x694e2727,0xcd7fb2b2,0x9fea7575
	.long	0x1b120909,0x9e1d8383,0x74582c2c,0x2e341a1a
	.long	0x2d361b1b,0xb2dc6e6e,0xeeb45a5a,0xfb5ba0a0
	.long	0xf6a45252,0x4d763b3b,0x61b7d6d6,0xce7db3b3
	.long	0x7b522929,0x3edde3e3,0x715e2f2f,0x97138484
	.long	0xf5a65353,0x68b9d1d1,0x00000000,0x2cc1eded
	.long	0x60402020,0x1fe3fcfc,0xc879b1b1,0xedb65b5b
	.long	0xbed46a6a,0x468dcbcb,0xd967bebe,0x4b723939
	.long	0xde944a4a,0xd4984c4c,0xe8b05858,0x4a85cfcf
	.long	0x6bbbd0d0,0x2ac5efef,0xe54faaaa,0x16edfbfb
	.long	0xc5864343,0xd79a4d4d,0x55663333,0x94118585
	.long	0xcf8a4545,0x10e9f9f9,0x06040202,0x81fe7f7f
	.long	0xf0a05050,0x44783c3c,0xba259f9f,0xe34ba8a8
	.long	0xf3a25151,0xfe5da3a3,0xc0804040,0x8a058f8f
	.long	0xad3f9292,0xbc219d9d,0x48703838,0x04f1f5f5
	.long	0xdf63bcbc,0xc177b6b6,0x75afdada,0x63422121
	.long	0x30201010,0x1ae5ffff,0x0efdf3f3,0x6dbfd2d2
	.long	0x4c81cdcd,0x14180c0c,0x35261313,0x2fc3ecec
	.long	0xe1be5f5f,0xa2359797,0xcc884444,0x392e1717
	.long	0x5793c4c4,0xf255a7a7,0x82fc7e7e,0x477a3d3d
	.long	0xacc86464,0xe7ba5d5d,0x2b321919,0x95e67373
	.long	0xa0c06060,0x98198181,0xd19e4f4f,0x7fa3dcdc
	.long	0x66442222,0x7e542a2a,0xab3b9090,0x830b8888
	.long	0xca8c4646,0x29c7eeee,0xd36bb8b8,0x3c281414
	.long	0x79a7dede,0xe2bc5e5e,0x1d160b0b,0x76addbdb
	.long	0x3bdbe0e0,0x56643232,0x4e743a3a,0x1e140a0a
	.long	0xdb924949,0x0a0c0606,0x6c482424,0xe4b85c5c
	.long	0x5d9fc2c2,0x6ebdd3d3,0xef43acac,0xa6c46262
	.long	0xa8399191,0xa4319595,0x37d3e4e4,0x8bf27979
	.long	0x32d5e7e7,0x438bc8c8,0x596e3737,0xb7da6d6d
	.long	0x8c018d8d,0x64b1d5d5,0xd29c4e4e,0xe049a9a9
	.long	0xb4d86c6c,0xfaac5656,0x07f3f4f4,0x25cfeaea
	.long	0xafca6565,0x8ef47a7a,0xe947aeae,0x18100808
	.long	0xd56fbaba,0x88f07878,0x6f4a2525,0x725c2e2e
	.long	0x24381c1c,0xf157a6a6,0xc773b4b4,0x5197c6c6
	.long	0x23cbe8e8,0x7ca1dddd,0x9ce87474,0x213e1f1f
	.long	0xdd964b4b,0xdc61bdbd,0x860d8b8b,0x850f8a8a
	.long	0x90e07070,0x427c3e3e,0xc471b5b5,0xaacc6666
	.long	0xd8904848,0x05060303,0x01f7f6f6,0x121c0e0e
	.long	0xa3c26161,0x5f6a3535,0xf9ae5757,0xd069b9b9
	.long	0x91178686,0x5899c1c1,0x273a1d1d,0xb9279e9e
	.long	0x38d9e1e1,0x13ebf8f8,0xb32b9898,0x33221111
	.long	0xbbd26969,0x70a9d9d9,0x89078e8e,0xa7339494
	.long	0xb62d9b9b,0x223c1e1e,0x92158787,0x20c9e9e9
	.long	0x4987cece,0xffaa5555,0x78502828,0x7aa5dfdf
	.long	0x8f038c8c,0xf859a1a1,0x80098989,0x171a0d0d
	.long	0xda65bfbf,0x31d7e6e6,0xc6844242,0xb8d06868
	.long	0xc3824141,0xb0299999,0x775a2d2d,0x111e0f0f
	.long	0xcb7bb0b0,0xfca85454,0xd66dbbbb,0x3a2c1616
#endif /* HAVE_AES_DECRYPT || HAVE_AES_CBC || HAVE_AESCCM || HAVE_AESGCM ||
        * WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_DECRYPT
#ifndef __APPLE__
	.text
	.type	L_AES_ARM32_td, %object
	.size	L_AES_ARM32_td, 12
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_ARM32_td:
	.long	L_AES_ARM32_td_data
#endif /* HAVE_AES_DECRYPT */
#if defined(HAVE_AES_DECRYPT) || defined(HAVE_AES_CBC) || \
    defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || \
    defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER)
#ifndef __APPLE__
	.text
	.type	L_AES_ARM32_te, %object
	.size	L_AES_ARM32_te, 12
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_ARM32_te:
	.long	L_AES_ARM32_te_data
#endif /* HAVE_AES_DECRYPT || HAVE_AES_CBC || HAVE_AESCCM || HAVE_AESGCM ||
        * WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_DECRYPT
	.text
	.align	4
	.globl	AES_invert_key
	.type	AES_invert_key, %function
AES_invert_key:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	adr	r12, L_AES_ARM32_te
	ldr	r12, [r12]
	adr	lr, L_AES_ARM32_td
	ldr	lr, [lr]
	add	r10, r0, r1, lsl #4
	mov	r11, r1
L_AES_invert_key_loop:
	ldm	r0, {r2, r3, r4, r5}
	ldm	r10, {r6, r7, r8, r9}
	stm	r10, {r2, r3, r4, r5}
	stm	r0!, {r6, r7, r8, r9}
	subs	r11, r11, #2
	sub	r10, r10, #16
	bne	L_AES_invert_key_loop
	sub	r0, r0, r1, lsl #3
	add	r0, r0, #16
	sub	r11, r1, #1
L_AES_invert_key_mix_loop:
	ldm	r0, {r2, r3, r4, r5}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r2, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r2
#endif
#else
	ubfx	r6, r2, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r2, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r2, ror #8
#endif
#else
	ubfx	r7, r2, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r2, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r2, ror #16
#endif
#else
	ubfx	r8, r2, #16, #8
#endif
	lsr	r9, r2, #24
	ldrb	r6, [r12, r6, lsl #2]
	ldrb	r7, [r12, r7, lsl #2]
	ldrb	r8, [r12, r8, lsl #2]
	ldrb	r9, [r12, r9, lsl #2]
	ldr	r6, [lr, r6, lsl #2]
	ldr	r7, [lr, r7, lsl #2]
	ldr	r8, [lr, r8, lsl #2]
	ldr	r9, [lr, r9, lsl #2]
	eor	r8, r8, r6, ror #16
	eor	r8, r8, r7, ror #8
	eor	r8, r8, r9, ror #24
	str	r8, [r0], #4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r3, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r3
#endif
#else
	ubfx	r6, r3, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r3, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r3, ror #8
#endif
#else
	ubfx	r7, r3, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r3, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r3, ror #16
#endif
#else
	ubfx	r8, r3, #16, #8
#endif
	lsr	r9, r3, #24
	ldrb	r6, [r12, r6, lsl #2]
	ldrb	r7, [r12, r7, lsl #2]
	ldrb	r8, [r12, r8, lsl #2]
	ldrb	r9, [r12, r9, lsl #2]
	ldr	r6, [lr, r6, lsl #2]
	ldr	r7, [lr, r7, lsl #2]
	ldr	r8, [lr, r8, lsl #2]
	ldr	r9, [lr, r9, lsl #2]
	eor	r8, r8, r6, ror #16
	eor	r8, r8, r7, ror #8
	eor	r8, r8, r9, ror #24
	str	r8, [r0], #4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r4, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r4
#endif
#else
	ubfx	r6, r4, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r4, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r4, ror #8
#endif
#else
	ubfx	r7, r4, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r4, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r4, ror #16
#endif
#else
	ubfx	r8, r4, #16, #8
#endif
	lsr	r9, r4, #24
	ldrb	r6, [r12, r6, lsl #2]
	ldrb	r7, [r12, r7, lsl #2]
	ldrb	r8, [r12, r8, lsl #2]
	ldrb	r9, [r12, r9, lsl #2]
	ldr	r6, [lr, r6, lsl #2]
	ldr	r7, [lr, r7, lsl #2]
	ldr	r8, [lr, r8, lsl #2]
	ldr	r9, [lr, r9, lsl #2]
	eor	r8, r8, r6, ror #16
	eor	r8, r8, r7, ror #8
	eor	r8, r8, r9, ror #24
	str	r8, [r0], #4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r5, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r5
#endif
#else
	ubfx	r6, r5, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r5, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r5, ror #8
#endif
#else
	ubfx	r7, r5, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r9, r5, #24
	ldrb	r6, [r12, r6, lsl #2]
	ldrb	r7, [r12, r7, lsl #2]
	ldrb	r8, [r12, r8, lsl #2]
	ldrb	r9, [r12, r9, lsl #2]
	ldr	r6, [lr, r6, lsl #2]
	ldr	r7, [lr, r7, lsl #2]
	ldr	r8, [lr, r8, lsl #2]
	ldr	r9, [lr, r9, lsl #2]
	eor	r8, r8, r6, ror #16
	eor	r8, r8, r7, ror #8
	eor	r8, r8, r9, ror #24
	str	r8, [r0], #4
	subs	r11, r11, #1
	bne	L_AES_invert_key_mix_loop
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	AES_invert_key,.-AES_invert_key
#endif /* HAVE_AES_DECRYPT */
#ifndef __APPLE__
	.text
	.type	L_AES_ARM32_rcon, %object
	.size	L_AES_ARM32_rcon, 40
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_ARM32_rcon:
	.long	0x01000000,0x02000000,0x04000000,0x08000000
	.long	0x10000000,0x20000000,0x40000000,0x80000000
	.long	0x1b000000,0x36000000
	.text
	.align	4
	.globl	AES_set_encrypt_key
	.type	AES_set_encrypt_key, %function
AES_set_encrypt_key:
	push	{r4, r5, r6, r7, r8, lr}
	adr	r8, L_AES_ARM32_te
	ldr	r8, [r8]
	adr	lr, L_AES_ARM32_rcon
	cmp	r1, #0x80
	beq	L_AES_set_encrypt_key_start_128
	cmp	r1, #0xc0
	beq	L_AES_set_encrypt_key_start_192
	ldr	r4, [r0]
	ldr	r5, [r0, #4]
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	# REV r4, r4
	eor	r3, r4, r4, ror #16
	bic	r3, r3, #0xff0000
	ror	r4, r4, #8
	eor	r4, r4, r3, lsr #8
	# REV r5, r5
	eor	r3, r5, r5, ror #16
	bic	r3, r3, #0xff0000
	ror	r5, r5, #8
	eor	r5, r5, r3, lsr #8
	# REV r6, r6
	eor	r3, r6, r6, ror #16
	bic	r3, r3, #0xff0000
	ror	r6, r6, #8
	eor	r6, r6, r3, lsr #8
	# REV r7, r7
	eor	r3, r7, r7, ror #16
	bic	r3, r3, #0xff0000
	ror	r7, r7, #8
	eor	r7, r7, r3, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	stm	r2!, {r4, r5, r6, r7}
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
	ldr	r6, [r0, #24]
	ldr	r7, [r0, #28]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	# REV r4, r4
	eor	r3, r4, r4, ror #16
	bic	r3, r3, #0xff0000
	ror	r4, r4, #8
	eor	r4, r4, r3, lsr #8
	# REV r5, r5
	eor	r3, r5, r5, ror #16
	bic	r3, r3, #0xff0000
	ror	r5, r5, #8
	eor	r5, r5, r3, lsr #8
	# REV r6, r6
	eor	r3, r6, r6, ror #16
	bic	r3, r3, #0xff0000
	ror	r6, r6, #8
	eor	r6, r6, r3, lsr #8
	# REV r7, r7
	eor	r3, r7, r7, ror #16
	bic	r3, r3, #0xff0000
	ror	r7, r7, #8
	eor	r7, r7, r3, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	stm	r2, {r4, r5, r6, r7}
	sub	r2, r2, #16
	mov	r12, #6
L_AES_set_encrypt_key_loop_256:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r7, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r7
#endif
#else
	ubfx	r4, r7, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r7, #16
	lsr	r5, r5, #24
#else
	uxtb	r5, r7, ror #8
#endif
#else
	ubfx	r5, r7, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r7, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r7, ror #16
#endif
#else
	ubfx	r6, r7, #16, #8
#endif
	lsr	r7, r7, #24
	ldrb	r4, [r8, r4, lsl #2]
	ldrb	r5, [r8, r5, lsl #2]
	ldrb	r6, [r8, r6, lsl #2]
	ldrb	r7, [r8, r7, lsl #2]
	eor	r3, r7, r4, lsl #8
	eor	r3, r3, r5, lsl #16
	eor	r3, r3, r6, lsl #24
	ldm	r2!, {r4, r5, r6, r7}
	eor	r4, r4, r3
	ldm	lr!, {r3}
	eor	r4, r4, r3
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
	add	r2, r2, #16
	stm	r2, {r4, r5, r6, r7}
	sub	r2, r2, #16
	mov	r3, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r3, #16
	lsr	r4, r4, #24
#else
	uxtb	r4, r3, ror #8
#endif
#else
	ubfx	r4, r3, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r3, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r3, ror #16
#endif
#else
	ubfx	r5, r3, #16, #8
#endif
	lsr	r6, r3, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r3, r3, #24
	lsr	r3, r3, #24
#else
	uxtb	r3, r3
#endif
#else
	ubfx	r3, r3, #0, #8
#endif
	ldrb	r4, [r8, r4, lsl #2]
	ldrb	r6, [r8, r6, lsl #2]
	ldrb	r5, [r8, r5, lsl #2]
	ldrb	r3, [r8, r3, lsl #2]
	eor	r3, r3, r4, lsl #8
	eor	r3, r3, r5, lsl #16
	eor	r3, r3, r6, lsl #24
	ldm	r2!, {r4, r5, r6, r7}
	eor	r4, r4, r3
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
	add	r2, r2, #16
	stm	r2, {r4, r5, r6, r7}
	sub	r2, r2, #16
	subs	r12, r12, #1
	bne	L_AES_set_encrypt_key_loop_256
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r7, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r7
#endif
#else
	ubfx	r4, r7, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r7, #16
	lsr	r5, r5, #24
#else
	uxtb	r5, r7, ror #8
#endif
#else
	ubfx	r5, r7, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r7, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r7, ror #16
#endif
#else
	ubfx	r6, r7, #16, #8
#endif
	lsr	r7, r7, #24
	ldrb	r4, [r8, r4, lsl #2]
	ldrb	r5, [r8, r5, lsl #2]
	ldrb	r6, [r8, r6, lsl #2]
	ldrb	r7, [r8, r7, lsl #2]
	eor	r3, r7, r4, lsl #8
	eor	r3, r3, r5, lsl #16
	eor	r3, r3, r6, lsl #24
	ldm	r2!, {r4, r5, r6, r7}
	eor	r4, r4, r3
	ldm	lr!, {r3}
	eor	r4, r4, r3
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
	add	r2, r2, #16
	stm	r2, {r4, r5, r6, r7}
	sub	r2, r2, #16
	b	L_AES_set_encrypt_key_end
L_AES_set_encrypt_key_start_192:
	ldr	r4, [r0]
	ldr	r5, [r0, #4]
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
	ldr	r1, [r0, #20]
	ldr	r0, [r0, #16]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	# REV r4, r4
	eor	r3, r4, r4, ror #16
	bic	r3, r3, #0xff0000
	ror	r4, r4, #8
	eor	r4, r4, r3, lsr #8
	# REV r5, r5
	eor	r3, r5, r5, ror #16
	bic	r3, r3, #0xff0000
	ror	r5, r5, #8
	eor	r5, r5, r3, lsr #8
	# REV r6, r6
	eor	r3, r6, r6, ror #16
	bic	r3, r3, #0xff0000
	ror	r6, r6, #8
	eor	r6, r6, r3, lsr #8
	# REV r7, r7
	eor	r3, r7, r7, ror #16
	bic	r3, r3, #0xff0000
	ror	r7, r7, #8
	eor	r7, r7, r3, lsr #8
	# REV r0, r0
	eor	r3, r0, r0, ror #16
	bic	r3, r3, #0xff0000
	ror	r0, r0, #8
	eor	r0, r0, r3, lsr #8
	# REV r1, r1
	eor	r3, r1, r1, ror #16
	bic	r3, r3, #0xff0000
	ror	r1, r1, #8
	eor	r1, r1, r3, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
	rev	r0, r0
	rev	r1, r1
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	stm	r2, {r4, r5, r6, r7}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r0, [r2, #16]
	str	r1, [r2, #20]
#else
	strd	r0, r1, [r2, #16]
#endif
	mov	r7, r1
	mov	r12, #7
L_AES_set_encrypt_key_loop_192:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r0, r7, #24
	lsr	r0, r0, #24
#else
	uxtb	r0, r7
#endif
#else
	ubfx	r0, r7, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r1, r7, #16
	lsr	r1, r1, #24
#else
	uxtb	r1, r7, ror #8
#endif
#else
	ubfx	r1, r7, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r7, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r7, ror #16
#endif
#else
	ubfx	r4, r7, #16, #8
#endif
	lsr	r7, r7, #24
	ldrb	r0, [r8, r0, lsl #2]
	ldrb	r1, [r8, r1, lsl #2]
	ldrb	r4, [r8, r4, lsl #2]
	ldrb	r7, [r8, r7, lsl #2]
	eor	r3, r7, r0, lsl #8
	eor	r3, r3, r1, lsl #16
	eor	r3, r3, r4, lsl #24
	ldm	r2!, {r0, r1, r4, r5, r6, r7}
	eor	r0, r0, r3
	ldm	lr!, {r3}
	eor	r0, r0, r3
	eor	r1, r1, r0
	eor	r4, r4, r1
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
	stm	r2, {r0, r1, r4, r5, r6, r7}
	subs	r12, r12, #1
	bne	L_AES_set_encrypt_key_loop_192
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r0, r7, #24
	lsr	r0, r0, #24
#else
	uxtb	r0, r7
#endif
#else
	ubfx	r0, r7, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r1, r7, #16
	lsr	r1, r1, #24
#else
	uxtb	r1, r7, ror #8
#endif
#else
	ubfx	r1, r7, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r7, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r7, ror #16
#endif
#else
	ubfx	r4, r7, #16, #8
#endif
	lsr	r7, r7, #24
	ldrb	r0, [r8, r0, lsl #2]
	ldrb	r1, [r8, r1, lsl #2]
	ldrb	r4, [r8, r4, lsl #2]
	ldrb	r7, [r8, r7, lsl #2]
	eor	r3, r7, r0, lsl #8
	eor	r3, r3, r1, lsl #16
	eor	r3, r3, r4, lsl #24
	ldm	r2!, {r0, r1, r4, r5, r6, r7}
	eor	r0, r0, r3
	ldm	lr!, {r3}
	eor	r0, r0, r3
	eor	r1, r1, r0
	eor	r4, r4, r1
	eor	r5, r5, r4
	stm	r2, {r0, r1, r4, r5}
	b	L_AES_set_encrypt_key_end
L_AES_set_encrypt_key_start_128:
	ldr	r4, [r0]
	ldr	r5, [r0, #4]
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	# REV r4, r4
	eor	r3, r4, r4, ror #16
	bic	r3, r3, #0xff0000
	ror	r4, r4, #8
	eor	r4, r4, r3, lsr #8
	# REV r5, r5
	eor	r3, r5, r5, ror #16
	bic	r3, r3, #0xff0000
	ror	r5, r5, #8
	eor	r5, r5, r3, lsr #8
	# REV r6, r6
	eor	r3, r6, r6, ror #16
	bic	r3, r3, #0xff0000
	ror	r6, r6, #8
	eor	r6, r6, r3, lsr #8
	# REV r7, r7
	eor	r3, r7, r7, ror #16
	bic	r3, r3, #0xff0000
	ror	r7, r7, #8
	eor	r7, r7, r3, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	stm	r2, {r4, r5, r6, r7}
	mov	r12, #10
L_AES_set_encrypt_key_loop_128:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r7, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r7
#endif
#else
	ubfx	r4, r7, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r7, #16
	lsr	r5, r5, #24
#else
	uxtb	r5, r7, ror #8
#endif
#else
	ubfx	r5, r7, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r7, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r7, ror #16
#endif
#else
	ubfx	r6, r7, #16, #8
#endif
	lsr	r7, r7, #24
	ldrb	r4, [r8, r4, lsl #2]
	ldrb	r5, [r8, r5, lsl #2]
	ldrb	r6, [r8, r6, lsl #2]
	ldrb	r7, [r8, r7, lsl #2]
	eor	r3, r7, r4, lsl #8
	eor	r3, r3, r5, lsl #16
	eor	r3, r3, r6, lsl #24
	ldm	r2!, {r4, r5, r6, r7}
	eor	r4, r4, r3
	ldm	lr!, {r3}
	eor	r4, r4, r3
	eor	r5, r5, r4
	eor	r6, r6, r5
	eor	r7, r7, r6
	stm	r2, {r4, r5, r6, r7}
	subs	r12, r12, #1
	bne	L_AES_set_encrypt_key_loop_128
L_AES_set_encrypt_key_end:
	pop	{r4, r5, r6, r7, r8, pc}
	.size	AES_set_encrypt_key,.-AES_set_encrypt_key
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	.text
	.align	4
	.globl	AES_encrypt_block
	.type	AES_encrypt_block, %function
AES_encrypt_block:
	push	{lr}
L_AES_encrypt_block_nr:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r9, ror #16
#endif
#else
	ubfx	r4, r9, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #8
#endif
#else
	ubfx	lr, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r11, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r11
#endif
#else
	ubfx	r2, r11, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r10, ror #16
#endif
#else
	ubfx	r5, r10, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #8
#endif
#else
	ubfx	lr, r11, #8, #8
#endif
	eor	r4, r4, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r8
#endif
#else
	ubfx	r2, r8, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r11, ror #16
#endif
#else
	ubfx	r6, r11, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r8, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r8, ror #8
#endif
#else
	ubfx	lr, r8, #8, #8
#endif
	eor	r5, r5, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r9
#endif
#else
	ubfx	r2, r9, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r10, #24
	lsr	r10, r10, #24
#else
	uxtb	r10, r10
#endif
#else
	ubfx	r10, r10, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #16
#endif
#else
	ubfx	r7, r8, #16, #8
#endif
	eor	r6, r6, lr, ror #8
	lsr	lr, r11, #24
	eor	r6, r6, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r9, ror #8
#endif
#else
	ubfx	r2, r9, #8, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r10, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #24
	eor	r7, r7, r2, ror #8
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_encrypt_block_nr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r11
#endif
#else
	ubfx	r4, r11, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #16
#endif
#else
	ubfx	lr, r9, #16, #8
#endif
	lsr	r2, r8, #24
	ldrb	r4, [r0, r4, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r8
#endif
#else
	ubfx	r5, r8, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	eor	r4, r4, r2, lsl #24
	lsr	r2, r9, #24
	ldrb	r5, [r0, r5, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r9
#endif
#else
	ubfx	r6, r9, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #16
#endif
#else
	ubfx	lr, r11, #16, #8
#endif
	eor	r5, r5, r2, lsl #24
	lsr	r2, r10, #24
	ldrb	r6, [r0, r6, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r10
#endif
#else
	ubfx	r7, r10, #0, #8
#endif
	eor	r6, r6, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	eor	r6, r6, r2, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #8
	lsr	r2, r2, #24
#else
	uxtb	r2, r8, ror #16
#endif
#else
	ubfx	r2, r8, #16, #8
#endif
	ldrb	r11, [r0, r11, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	eor	lr, lr, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, lr, lsl #8
	eor	r7, r7, r2, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	pop	{pc}
	.size	AES_encrypt_block,.-AES_encrypt_block
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
#if defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || \
    defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) || \
    defined(HAVE_AES_ECB)
#ifndef __APPLE__
	.text
	.type	L_AES_ARM32_te_ecb, %object
	.size	L_AES_ARM32_te_ecb, 12
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_ARM32_te_ecb:
	.long	L_AES_ARM32_te_data
	.text
	.align	4
	.globl	AES_ECB_encrypt
	.type	AES_ECB_encrypt, %function
AES_ECB_encrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	mov	lr, r0
	adr	r0, L_AES_ARM32_te_ecb
	ldr	r0, [r0]
	ldr	r12, [sp, #36]
	push	{r3}
	cmp	r12, #10
	beq	L_AES_ECB_encrypt_start_block_128
	cmp	r12, #12
	beq	L_AES_ECB_encrypt_start_block_192
L_AES_ECB_encrypt_loop_block_256:
	ldr	r4, [lr]
	ldr	r5, [lr, #4]
	ldr	r6, [lr, #8]
	ldr	r7, [lr, #12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	push	{r1, r2, lr}
	ldm	r3!, {r8, r9, r10, r11}
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #6
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_encrypt_block
#else
L_AES_ECB_encrypt_block_nr_256:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r9, ror #16
#endif
#else
	ubfx	r4, r9, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #8
#endif
#else
	ubfx	lr, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r11, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r11
#endif
#else
	ubfx	r2, r11, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r10, ror #16
#endif
#else
	ubfx	r5, r10, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #8
#endif
#else
	ubfx	lr, r11, #8, #8
#endif
	eor	r4, r4, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r8
#endif
#else
	ubfx	r2, r8, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r11, ror #16
#endif
#else
	ubfx	r6, r11, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r8, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r8, ror #8
#endif
#else
	ubfx	lr, r8, #8, #8
#endif
	eor	r5, r5, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r9
#endif
#else
	ubfx	r2, r9, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r10, #24
	lsr	r10, r10, #24
#else
	uxtb	r10, r10
#endif
#else
	ubfx	r10, r10, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #16
#endif
#else
	ubfx	r7, r8, #16, #8
#endif
	eor	r6, r6, lr, ror #8
	lsr	lr, r11, #24
	eor	r6, r6, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r9, ror #8
#endif
#else
	ubfx	r2, r9, #8, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r10, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #24
	eor	r7, r7, r2, ror #8
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_ECB_encrypt_block_nr_256
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r11
#endif
#else
	ubfx	r4, r11, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #16
#endif
#else
	ubfx	lr, r9, #16, #8
#endif
	lsr	r2, r8, #24
	ldrb	r4, [r0, r4, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r8
#endif
#else
	ubfx	r5, r8, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	eor	r4, r4, r2, lsl #24
	lsr	r2, r9, #24
	ldrb	r5, [r0, r5, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r9
#endif
#else
	ubfx	r6, r9, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #16
#endif
#else
	ubfx	lr, r11, #16, #8
#endif
	eor	r5, r5, r2, lsl #24
	lsr	r2, r10, #24
	ldrb	r6, [r0, r6, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r10
#endif
#else
	ubfx	r7, r10, #0, #8
#endif
	eor	r6, r6, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	eor	r6, r6, r2, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #8
	lsr	r2, r2, #24
#else
	uxtb	r2, r8, ror #16
#endif
#else
	ubfx	r2, r8, #16, #8
#endif
	ldrb	r11, [r0, r11, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	eor	lr, lr, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, lr, lsl #8
	eor	r7, r7, r2, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	pop	{r1, r2, lr}
	ldr	r3, [sp]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	subs	r2, r2, #16
	add	lr, lr, #16
	add	r1, r1, #16
	bne	L_AES_ECB_encrypt_loop_block_256
	b	L_AES_ECB_encrypt_end
L_AES_ECB_encrypt_start_block_192:
L_AES_ECB_encrypt_loop_block_192:
	ldr	r4, [lr]
	ldr	r5, [lr, #4]
	ldr	r6, [lr, #8]
	ldr	r7, [lr, #12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	push	{r1, r2, lr}
	ldm	r3!, {r8, r9, r10, r11}
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #5
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_encrypt_block
#else
L_AES_ECB_encrypt_block_nr_192:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r9, ror #16
#endif
#else
	ubfx	r4, r9, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #8
#endif
#else
	ubfx	lr, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r11, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r11
#endif
#else
	ubfx	r2, r11, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r10, ror #16
#endif
#else
	ubfx	r5, r10, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #8
#endif
#else
	ubfx	lr, r11, #8, #8
#endif
	eor	r4, r4, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r8
#endif
#else
	ubfx	r2, r8, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r11, ror #16
#endif
#else
	ubfx	r6, r11, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r8, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r8, ror #8
#endif
#else
	ubfx	lr, r8, #8, #8
#endif
	eor	r5, r5, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r9
#endif
#else
	ubfx	r2, r9, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r10, #24
	lsr	r10, r10, #24
#else
	uxtb	r10, r10
#endif
#else
	ubfx	r10, r10, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #16
#endif
#else
	ubfx	r7, r8, #16, #8
#endif
	eor	r6, r6, lr, ror #8
	lsr	lr, r11, #24
	eor	r6, r6, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r9, ror #8
#endif
#else
	ubfx	r2, r9, #8, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r10, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #24
	eor	r7, r7, r2, ror #8
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_ECB_encrypt_block_nr_192
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r11
#endif
#else
	ubfx	r4, r11, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #16
#endif
#else
	ubfx	lr, r9, #16, #8
#endif
	lsr	r2, r8, #24
	ldrb	r4, [r0, r4, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r8
#endif
#else
	ubfx	r5, r8, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	eor	r4, r4, r2, lsl #24
	lsr	r2, r9, #24
	ldrb	r5, [r0, r5, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r9
#endif
#else
	ubfx	r6, r9, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #16
#endif
#else
	ubfx	lr, r11, #16, #8
#endif
	eor	r5, r5, r2, lsl #24
	lsr	r2, r10, #24
	ldrb	r6, [r0, r6, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r10
#endif
#else
	ubfx	r7, r10, #0, #8
#endif
	eor	r6, r6, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	eor	r6, r6, r2, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #8
	lsr	r2, r2, #24
#else
	uxtb	r2, r8, ror #16
#endif
#else
	ubfx	r2, r8, #16, #8
#endif
	ldrb	r11, [r0, r11, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	eor	lr, lr, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, lr, lsl #8
	eor	r7, r7, r2, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	pop	{r1, r2, lr}
	ldr	r3, [sp]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	subs	r2, r2, #16
	add	lr, lr, #16
	add	r1, r1, #16
	bne	L_AES_ECB_encrypt_loop_block_192
	b	L_AES_ECB_encrypt_end
L_AES_ECB_encrypt_start_block_128:
L_AES_ECB_encrypt_loop_block_128:
	ldr	r4, [lr]
	ldr	r5, [lr, #4]
	ldr	r6, [lr, #8]
	ldr	r7, [lr, #12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	push	{r1, r2, lr}
	ldm	r3!, {r8, r9, r10, r11}
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #4
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_encrypt_block
#else
L_AES_ECB_encrypt_block_nr_128:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r9, ror #16
#endif
#else
	ubfx	r4, r9, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #8
#endif
#else
	ubfx	lr, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r11, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r11
#endif
#else
	ubfx	r2, r11, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r10, ror #16
#endif
#else
	ubfx	r5, r10, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #8
#endif
#else
	ubfx	lr, r11, #8, #8
#endif
	eor	r4, r4, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r8
#endif
#else
	ubfx	r2, r8, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r11, ror #16
#endif
#else
	ubfx	r6, r11, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r8, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r8, ror #8
#endif
#else
	ubfx	lr, r8, #8, #8
#endif
	eor	r5, r5, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r9
#endif
#else
	ubfx	r2, r9, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r10, #24
	lsr	r10, r10, #24
#else
	uxtb	r10, r10
#endif
#else
	ubfx	r10, r10, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #16
#endif
#else
	ubfx	r7, r8, #16, #8
#endif
	eor	r6, r6, lr, ror #8
	lsr	lr, r11, #24
	eor	r6, r6, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r9, ror #8
#endif
#else
	ubfx	r2, r9, #8, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r10, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #24
	eor	r7, r7, r2, ror #8
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_ECB_encrypt_block_nr_128
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r11
#endif
#else
	ubfx	r4, r11, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #16
#endif
#else
	ubfx	lr, r9, #16, #8
#endif
	lsr	r2, r8, #24
	ldrb	r4, [r0, r4, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r8
#endif
#else
	ubfx	r5, r8, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	eor	r4, r4, r2, lsl #24
	lsr	r2, r9, #24
	ldrb	r5, [r0, r5, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r9
#endif
#else
	ubfx	r6, r9, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #16
#endif
#else
	ubfx	lr, r11, #16, #8
#endif
	eor	r5, r5, r2, lsl #24
	lsr	r2, r10, #24
	ldrb	r6, [r0, r6, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r10
#endif
#else
	ubfx	r7, r10, #0, #8
#endif
	eor	r6, r6, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	eor	r6, r6, r2, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #8
	lsr	r2, r2, #24
#else
	uxtb	r2, r8, ror #16
#endif
#else
	ubfx	r2, r8, #16, #8
#endif
	ldrb	r11, [r0, r11, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	eor	lr, lr, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, lr, lsl #8
	eor	r7, r7, r2, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	pop	{r1, r2, lr}
	ldr	r3, [sp]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	subs	r2, r2, #16
	add	lr, lr, #16
	add	r1, r1, #16
	bne	L_AES_ECB_encrypt_loop_block_128
L_AES_ECB_encrypt_end:
	pop	{r3}
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	AES_ECB_encrypt,.-AES_ECB_encrypt
#endif /* HAVE_AESCCM || HAVE_AESGCM || WOLFSSL_AES_DIRECT ||
        * WOLFSSL_AES_COUNTER || HAVE_AES_ECB */
#ifdef HAVE_AES_CBC
#ifndef __APPLE__
	.text
	.type	L_AES_ARM32_te_cbc, %object
	.size	L_AES_ARM32_te_cbc, 12
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_ARM32_te_cbc:
	.long	L_AES_ARM32_te_data
	.text
	.align	4
	.globl	AES_CBC_encrypt
	.type	AES_CBC_encrypt, %function
AES_CBC_encrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	ldr	r8, [sp, #36]
	ldr	r9, [sp, #40]
	mov	lr, r0
	adr	r0, L_AES_ARM32_te_cbc
	ldr	r0, [r0]
	ldm	r9, {r4, r5, r6, r7}
	push	{r3, r9}
	cmp	r8, #10
	beq	L_AES_CBC_encrypt_start_block_128
	cmp	r8, #12
	beq	L_AES_CBC_encrypt_start_block_192
L_AES_CBC_encrypt_loop_block_256:
	ldr	r8, [lr]
	ldr	r9, [lr, #4]
	ldr	r10, [lr, #8]
	ldr	r11, [lr, #12]
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	push	{r1, r2, lr}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	ldm	r3!, {r8, r9, r10, r11}
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #6
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_encrypt_block
#else
L_AES_CBC_encrypt_block_nr_256:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r9, ror #16
#endif
#else
	ubfx	r4, r9, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #8
#endif
#else
	ubfx	lr, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r11, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r11
#endif
#else
	ubfx	r2, r11, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r10, ror #16
#endif
#else
	ubfx	r5, r10, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #8
#endif
#else
	ubfx	lr, r11, #8, #8
#endif
	eor	r4, r4, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r8
#endif
#else
	ubfx	r2, r8, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r11, ror #16
#endif
#else
	ubfx	r6, r11, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r8, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r8, ror #8
#endif
#else
	ubfx	lr, r8, #8, #8
#endif
	eor	r5, r5, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r9
#endif
#else
	ubfx	r2, r9, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r10, #24
	lsr	r10, r10, #24
#else
	uxtb	r10, r10
#endif
#else
	ubfx	r10, r10, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #16
#endif
#else
	ubfx	r7, r8, #16, #8
#endif
	eor	r6, r6, lr, ror #8
	lsr	lr, r11, #24
	eor	r6, r6, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r9, ror #8
#endif
#else
	ubfx	r2, r9, #8, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r10, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #24
	eor	r7, r7, r2, ror #8
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_CBC_encrypt_block_nr_256
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r11
#endif
#else
	ubfx	r4, r11, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #16
#endif
#else
	ubfx	lr, r9, #16, #8
#endif
	lsr	r2, r8, #24
	ldrb	r4, [r0, r4, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r8
#endif
#else
	ubfx	r5, r8, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	eor	r4, r4, r2, lsl #24
	lsr	r2, r9, #24
	ldrb	r5, [r0, r5, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r9
#endif
#else
	ubfx	r6, r9, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #16
#endif
#else
	ubfx	lr, r11, #16, #8
#endif
	eor	r5, r5, r2, lsl #24
	lsr	r2, r10, #24
	ldrb	r6, [r0, r6, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r10
#endif
#else
	ubfx	r7, r10, #0, #8
#endif
	eor	r6, r6, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	eor	r6, r6, r2, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #8
	lsr	r2, r2, #24
#else
	uxtb	r2, r8, ror #16
#endif
#else
	ubfx	r2, r8, #16, #8
#endif
	ldrb	r11, [r0, r11, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	eor	lr, lr, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, lr, lsl #8
	eor	r7, r7, r2, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	pop	{r1, r2, lr}
	ldr	r3, [sp]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	subs	r2, r2, #16
	add	lr, lr, #16
	add	r1, r1, #16
	bne	L_AES_CBC_encrypt_loop_block_256
	b	L_AES_CBC_encrypt_end
L_AES_CBC_encrypt_start_block_192:
L_AES_CBC_encrypt_loop_block_192:
	ldr	r8, [lr]
	ldr	r9, [lr, #4]
	ldr	r10, [lr, #8]
	ldr	r11, [lr, #12]
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	push	{r1, r2, lr}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	ldm	r3!, {r8, r9, r10, r11}
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #5
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_encrypt_block
#else
L_AES_CBC_encrypt_block_nr_192:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r9, ror #16
#endif
#else
	ubfx	r4, r9, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #8
#endif
#else
	ubfx	lr, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r11, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r11
#endif
#else
	ubfx	r2, r11, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r10, ror #16
#endif
#else
	ubfx	r5, r10, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #8
#endif
#else
	ubfx	lr, r11, #8, #8
#endif
	eor	r4, r4, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r8
#endif
#else
	ubfx	r2, r8, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r11, ror #16
#endif
#else
	ubfx	r6, r11, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r8, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r8, ror #8
#endif
#else
	ubfx	lr, r8, #8, #8
#endif
	eor	r5, r5, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r9
#endif
#else
	ubfx	r2, r9, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r10, #24
	lsr	r10, r10, #24
#else
	uxtb	r10, r10
#endif
#else
	ubfx	r10, r10, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #16
#endif
#else
	ubfx	r7, r8, #16, #8
#endif
	eor	r6, r6, lr, ror #8
	lsr	lr, r11, #24
	eor	r6, r6, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r9, ror #8
#endif
#else
	ubfx	r2, r9, #8, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r10, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #24
	eor	r7, r7, r2, ror #8
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_CBC_encrypt_block_nr_192
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r11
#endif
#else
	ubfx	r4, r11, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #16
#endif
#else
	ubfx	lr, r9, #16, #8
#endif
	lsr	r2, r8, #24
	ldrb	r4, [r0, r4, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r8
#endif
#else
	ubfx	r5, r8, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	eor	r4, r4, r2, lsl #24
	lsr	r2, r9, #24
	ldrb	r5, [r0, r5, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r9
#endif
#else
	ubfx	r6, r9, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #16
#endif
#else
	ubfx	lr, r11, #16, #8
#endif
	eor	r5, r5, r2, lsl #24
	lsr	r2, r10, #24
	ldrb	r6, [r0, r6, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r10
#endif
#else
	ubfx	r7, r10, #0, #8
#endif
	eor	r6, r6, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	eor	r6, r6, r2, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #8
	lsr	r2, r2, #24
#else
	uxtb	r2, r8, ror #16
#endif
#else
	ubfx	r2, r8, #16, #8
#endif
	ldrb	r11, [r0, r11, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	eor	lr, lr, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, lr, lsl #8
	eor	r7, r7, r2, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	pop	{r1, r2, lr}
	ldr	r3, [sp]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	subs	r2, r2, #16
	add	lr, lr, #16
	add	r1, r1, #16
	bne	L_AES_CBC_encrypt_loop_block_192
	b	L_AES_CBC_encrypt_end
L_AES_CBC_encrypt_start_block_128:
L_AES_CBC_encrypt_loop_block_128:
	ldr	r8, [lr]
	ldr	r9, [lr, #4]
	ldr	r10, [lr, #8]
	ldr	r11, [lr, #12]
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	push	{r1, r2, lr}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	ldm	r3!, {r8, r9, r10, r11}
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #4
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_encrypt_block
#else
L_AES_CBC_encrypt_block_nr_128:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r9, ror #16
#endif
#else
	ubfx	r4, r9, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #8
#endif
#else
	ubfx	lr, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r11, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r11
#endif
#else
	ubfx	r2, r11, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r10, ror #16
#endif
#else
	ubfx	r5, r10, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #8
#endif
#else
	ubfx	lr, r11, #8, #8
#endif
	eor	r4, r4, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r8
#endif
#else
	ubfx	r2, r8, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r11, ror #16
#endif
#else
	ubfx	r6, r11, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r8, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r8, ror #8
#endif
#else
	ubfx	lr, r8, #8, #8
#endif
	eor	r5, r5, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r9
#endif
#else
	ubfx	r2, r9, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r10, #24
	lsr	r10, r10, #24
#else
	uxtb	r10, r10
#endif
#else
	ubfx	r10, r10, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #16
#endif
#else
	ubfx	r7, r8, #16, #8
#endif
	eor	r6, r6, lr, ror #8
	lsr	lr, r11, #24
	eor	r6, r6, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r9, ror #8
#endif
#else
	ubfx	r2, r9, #8, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r10, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #24
	eor	r7, r7, r2, ror #8
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_CBC_encrypt_block_nr_128
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r11
#endif
#else
	ubfx	r4, r11, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #16
#endif
#else
	ubfx	lr, r9, #16, #8
#endif
	lsr	r2, r8, #24
	ldrb	r4, [r0, r4, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r8
#endif
#else
	ubfx	r5, r8, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	eor	r4, r4, r2, lsl #24
	lsr	r2, r9, #24
	ldrb	r5, [r0, r5, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r9
#endif
#else
	ubfx	r6, r9, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #16
#endif
#else
	ubfx	lr, r11, #16, #8
#endif
	eor	r5, r5, r2, lsl #24
	lsr	r2, r10, #24
	ldrb	r6, [r0, r6, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r10
#endif
#else
	ubfx	r7, r10, #0, #8
#endif
	eor	r6, r6, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	eor	r6, r6, r2, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #8
	lsr	r2, r2, #24
#else
	uxtb	r2, r8, ror #16
#endif
#else
	ubfx	r2, r8, #16, #8
#endif
	ldrb	r11, [r0, r11, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	eor	lr, lr, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, lr, lsl #8
	eor	r7, r7, r2, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	pop	{r1, r2, lr}
	ldr	r3, [sp]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	subs	r2, r2, #16
	add	lr, lr, #16
	add	r1, r1, #16
	bne	L_AES_CBC_encrypt_loop_block_128
L_AES_CBC_encrypt_end:
	pop	{r3, r9}
	stm	r9, {r4, r5, r6, r7}
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	AES_CBC_encrypt,.-AES_CBC_encrypt
#endif /* HAVE_AES_CBC */
#ifdef WOLFSSL_AES_COUNTER
#ifndef __APPLE__
	.text
	.type	L_AES_ARM32_te_ctr, %object
	.size	L_AES_ARM32_te_ctr, 12
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_ARM32_te_ctr:
	.long	L_AES_ARM32_te_data
	.text
	.align	4
	.globl	AES_CTR_encrypt
	.type	AES_CTR_encrypt, %function
AES_CTR_encrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	ldr	r12, [sp, #36]
	ldr	r8, [sp, #40]
	mov	lr, r0
	adr	r0, L_AES_ARM32_te_ctr
	ldr	r0, [r0]
	ldm	r8, {r4, r5, r6, r7}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r10, r4, r4, ror #16
	eor	r11, r5, r5, ror #16
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	eor	r4, r4, r10, lsr #8
	eor	r5, r5, r11, lsr #8
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	stm	r8, {r4, r5, r6, r7}
	push	{r3, r8}
	cmp	r12, #10
	beq	L_AES_CTR_encrypt_start_block_128
	cmp	r12, #12
	beq	L_AES_CTR_encrypt_start_block_192
L_AES_CTR_encrypt_loop_block_256:
	push	{r1, r2, lr}
	ldr	lr, [sp, #16]
	adds	r11, r7, #1
	adcs	r10, r6, #0
	adcs	r9, r5, #0
	adc	r8, r4, #0
	stm	lr, {r8, r9, r10, r11}
	ldm	r3!, {r8, r9, r10, r11}
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #6
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_encrypt_block
#else
L_AES_CTR_encrypt_block_nr_256:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r9, ror #16
#endif
#else
	ubfx	r4, r9, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #8
#endif
#else
	ubfx	lr, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r11, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r11
#endif
#else
	ubfx	r2, r11, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r10, ror #16
#endif
#else
	ubfx	r5, r10, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #8
#endif
#else
	ubfx	lr, r11, #8, #8
#endif
	eor	r4, r4, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r8
#endif
#else
	ubfx	r2, r8, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r11, ror #16
#endif
#else
	ubfx	r6, r11, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r8, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r8, ror #8
#endif
#else
	ubfx	lr, r8, #8, #8
#endif
	eor	r5, r5, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r9
#endif
#else
	ubfx	r2, r9, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r10, #24
	lsr	r10, r10, #24
#else
	uxtb	r10, r10
#endif
#else
	ubfx	r10, r10, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #16
#endif
#else
	ubfx	r7, r8, #16, #8
#endif
	eor	r6, r6, lr, ror #8
	lsr	lr, r11, #24
	eor	r6, r6, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r9, ror #8
#endif
#else
	ubfx	r2, r9, #8, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r10, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #24
	eor	r7, r7, r2, ror #8
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_CTR_encrypt_block_nr_256
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r11
#endif
#else
	ubfx	r4, r11, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #16
#endif
#else
	ubfx	lr, r9, #16, #8
#endif
	lsr	r2, r8, #24
	ldrb	r4, [r0, r4, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r8
#endif
#else
	ubfx	r5, r8, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	eor	r4, r4, r2, lsl #24
	lsr	r2, r9, #24
	ldrb	r5, [r0, r5, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r9
#endif
#else
	ubfx	r6, r9, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #16
#endif
#else
	ubfx	lr, r11, #16, #8
#endif
	eor	r5, r5, r2, lsl #24
	lsr	r2, r10, #24
	ldrb	r6, [r0, r6, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r10
#endif
#else
	ubfx	r7, r10, #0, #8
#endif
	eor	r6, r6, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	eor	r6, r6, r2, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #8
	lsr	r2, r2, #24
#else
	uxtb	r2, r8, ror #16
#endif
#else
	ubfx	r2, r8, #16, #8
#endif
	ldrb	r11, [r0, r11, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	eor	lr, lr, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, lr, lsl #8
	eor	r7, r7, r2, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	pop	{r1, r2, lr}
	ldr	r3, [sp]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	ldr	r8, [lr]
	ldr	r9, [lr, #4]
	ldr	r10, [lr, #8]
	ldr	r11, [lr, #12]
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	ldr	r8, [sp, #4]
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	ldm	r8, {r4, r5, r6, r7}
	subs	r2, r2, #16
	add	lr, lr, #16
	add	r1, r1, #16
	bne	L_AES_CTR_encrypt_loop_block_256
	b	L_AES_CTR_encrypt_end
L_AES_CTR_encrypt_start_block_192:
L_AES_CTR_encrypt_loop_block_192:
	push	{r1, r2, lr}
	ldr	lr, [sp, #16]
	adds	r11, r7, #1
	adcs	r10, r6, #0
	adcs	r9, r5, #0
	adc	r8, r4, #0
	stm	lr, {r8, r9, r10, r11}
	ldm	r3!, {r8, r9, r10, r11}
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #5
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_encrypt_block
#else
L_AES_CTR_encrypt_block_nr_192:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r9, ror #16
#endif
#else
	ubfx	r4, r9, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #8
#endif
#else
	ubfx	lr, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r11, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r11
#endif
#else
	ubfx	r2, r11, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r10, ror #16
#endif
#else
	ubfx	r5, r10, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #8
#endif
#else
	ubfx	lr, r11, #8, #8
#endif
	eor	r4, r4, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r8
#endif
#else
	ubfx	r2, r8, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r11, ror #16
#endif
#else
	ubfx	r6, r11, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r8, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r8, ror #8
#endif
#else
	ubfx	lr, r8, #8, #8
#endif
	eor	r5, r5, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r9
#endif
#else
	ubfx	r2, r9, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r10, #24
	lsr	r10, r10, #24
#else
	uxtb	r10, r10
#endif
#else
	ubfx	r10, r10, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #16
#endif
#else
	ubfx	r7, r8, #16, #8
#endif
	eor	r6, r6, lr, ror #8
	lsr	lr, r11, #24
	eor	r6, r6, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r9, ror #8
#endif
#else
	ubfx	r2, r9, #8, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r10, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #24
	eor	r7, r7, r2, ror #8
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_CTR_encrypt_block_nr_192
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r11
#endif
#else
	ubfx	r4, r11, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #16
#endif
#else
	ubfx	lr, r9, #16, #8
#endif
	lsr	r2, r8, #24
	ldrb	r4, [r0, r4, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r8
#endif
#else
	ubfx	r5, r8, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	eor	r4, r4, r2, lsl #24
	lsr	r2, r9, #24
	ldrb	r5, [r0, r5, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r9
#endif
#else
	ubfx	r6, r9, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #16
#endif
#else
	ubfx	lr, r11, #16, #8
#endif
	eor	r5, r5, r2, lsl #24
	lsr	r2, r10, #24
	ldrb	r6, [r0, r6, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r10
#endif
#else
	ubfx	r7, r10, #0, #8
#endif
	eor	r6, r6, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	eor	r6, r6, r2, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #8
	lsr	r2, r2, #24
#else
	uxtb	r2, r8, ror #16
#endif
#else
	ubfx	r2, r8, #16, #8
#endif
	ldrb	r11, [r0, r11, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	eor	lr, lr, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, lr, lsl #8
	eor	r7, r7, r2, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	pop	{r1, r2, lr}
	ldr	r3, [sp]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	ldr	r8, [lr]
	ldr	r9, [lr, #4]
	ldr	r10, [lr, #8]
	ldr	r11, [lr, #12]
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	ldr	r8, [sp, #4]
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	ldm	r8, {r4, r5, r6, r7}
	subs	r2, r2, #16
	add	lr, lr, #16
	add	r1, r1, #16
	bne	L_AES_CTR_encrypt_loop_block_192
	b	L_AES_CTR_encrypt_end
L_AES_CTR_encrypt_start_block_128:
L_AES_CTR_encrypt_loop_block_128:
	push	{r1, r2, lr}
	ldr	lr, [sp, #16]
	adds	r11, r7, #1
	adcs	r10, r6, #0
	adcs	r9, r5, #0
	adc	r8, r4, #0
	stm	lr, {r8, r9, r10, r11}
	ldm	r3!, {r8, r9, r10, r11}
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #4
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_encrypt_block
#else
L_AES_CTR_encrypt_block_nr_128:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r9, ror #16
#endif
#else
	ubfx	r4, r9, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #8
#endif
#else
	ubfx	lr, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r11, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r11
#endif
#else
	ubfx	r2, r11, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r10, ror #16
#endif
#else
	ubfx	r5, r10, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #8
#endif
#else
	ubfx	lr, r11, #8, #8
#endif
	eor	r4, r4, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r8
#endif
#else
	ubfx	r2, r8, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r11, ror #16
#endif
#else
	ubfx	r6, r11, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r8, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r8, ror #8
#endif
#else
	ubfx	lr, r8, #8, #8
#endif
	eor	r5, r5, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r9
#endif
#else
	ubfx	r2, r9, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r10, #24
	lsr	r10, r10, #24
#else
	uxtb	r10, r10
#endif
#else
	ubfx	r10, r10, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #16
#endif
#else
	ubfx	r7, r8, #16, #8
#endif
	eor	r6, r6, lr, ror #8
	lsr	lr, r11, #24
	eor	r6, r6, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r9, ror #8
#endif
#else
	ubfx	r2, r9, #8, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r10, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #24
	eor	r7, r7, r2, ror #8
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_CTR_encrypt_block_nr_128
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r11
#endif
#else
	ubfx	r4, r11, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #16
#endif
#else
	ubfx	lr, r9, #16, #8
#endif
	lsr	r2, r8, #24
	ldrb	r4, [r0, r4, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r8
#endif
#else
	ubfx	r5, r8, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	eor	r4, r4, r2, lsl #24
	lsr	r2, r9, #24
	ldrb	r5, [r0, r5, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r9
#endif
#else
	ubfx	r6, r9, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #16
#endif
#else
	ubfx	lr, r11, #16, #8
#endif
	eor	r5, r5, r2, lsl #24
	lsr	r2, r10, #24
	ldrb	r6, [r0, r6, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r10
#endif
#else
	ubfx	r7, r10, #0, #8
#endif
	eor	r6, r6, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	eor	r6, r6, r2, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #8
	lsr	r2, r2, #24
#else
	uxtb	r2, r8, ror #16
#endif
#else
	ubfx	r2, r8, #16, #8
#endif
	ldrb	r11, [r0, r11, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	eor	lr, lr, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, lr, lsl #8
	eor	r7, r7, r2, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	pop	{r1, r2, lr}
	ldr	r3, [sp]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	ldr	r8, [lr]
	ldr	r9, [lr, #4]
	ldr	r10, [lr, #8]
	ldr	r11, [lr, #12]
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	ldr	r8, [sp, #4]
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	ldm	r8, {r4, r5, r6, r7}
	subs	r2, r2, #16
	add	lr, lr, #16
	add	r1, r1, #16
	bne	L_AES_CTR_encrypt_loop_block_128
L_AES_CTR_encrypt_end:
	pop	{r3, r8}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r10, r4, r4, ror #16
	eor	r11, r5, r5, ror #16
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	eor	r4, r4, r10, lsr #8
	eor	r5, r5, r11, lsr #8
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	stm	r8, {r4, r5, r6, r7}
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	AES_CTR_encrypt,.-AES_CTR_encrypt
#endif /* WOLFSSL_AES_COUNTER */
#ifdef HAVE_AES_DECRYPT
#if defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) || \
    defined(HAVE_AES_CBC) || defined(HAVE_AES_ECB)
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	.text
	.align	4
	.globl	AES_decrypt_block
	.type	AES_decrypt_block, %function
AES_decrypt_block:
	push	{lr}
L_AES_decrypt_block_nr:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r11, ror #16
#endif
#else
	ubfx	r4, r11, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r10, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r10, ror #8
#endif
#else
	ubfx	r12, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r9
#endif
#else
	ubfx	lr, r9, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r8, ror #16
#endif
#else
	ubfx	r5, r8, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #8
#endif
#else
	ubfx	r12, r11, #8, #8
#endif
	eor	r4, r4, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r10
#endif
#else
	ubfx	lr, r10, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r9, ror #16
#endif
#else
	ubfx	r6, r9, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #8
#endif
#else
	ubfx	r12, r8, #8, #8
#endif
	eor	r5, r5, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r11
#endif
#else
	ubfx	lr, r11, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r8, #24
	lsr	r8, r8, #24
#else
	uxtb	r8, r8
#endif
#else
	ubfx	r8, r8, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #16
#endif
#else
	ubfx	r7, r10, #16, #8
#endif
	eor	r6, r6, r12, ror #8
	lsr	r12, r11, #24
	eor	r6, r6, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r8, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #8
	eor	r7, r7, r12, ror #24
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_decrypt_block_nr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r9
#endif
#else
	ubfx	r4, r9, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #16
#endif
#else
	ubfx	r12, r11, #16, #8
#endif
	lsr	lr, r8, #24
	ldrb	r4, [r2, r4]
	ldrb	r7, [r2, r7]
	ldrb	r12, [r2, r12]
	ldrb	lr, [r2, lr]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r10
#endif
#else
	ubfx	r5, r10, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #16
#endif
#else
	ubfx	r12, r8, #16, #8
#endif
	eor	r4, r4, lr, lsl #24
	lsr	lr, r9, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r5, [r2, r5]
	ldrb	r12, [r2, r12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r11
#endif
#else
	ubfx	r6, r11, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #16
#endif
#else
	ubfx	r12, r9, #16, #8
#endif
	eor	r5, r5, lr, lsl #24
	lsr	lr, r10, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r6, [r2, r6]
	ldrb	r12, [r2, r12]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r8
#endif
#else
	ubfx	r7, r8, #0, #8
#endif
	eor	r6, r6, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #8
#endif
#else
	ubfx	r12, r9, #8, #8
#endif
	eor	r6, r6, lr, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	ldrb	r11, [r2, r11]
	ldrb	r12, [r2, r12]
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	eor	r12, r12, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, r12, lsl #8
	eor	r7, r7, lr, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	pop	{pc}
	.size	AES_decrypt_block,.-AES_decrypt_block
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
#ifndef __APPLE__
	.text
	.type	L_AES_ARM32_td_ecb, %object
	.size	L_AES_ARM32_td_ecb, 12
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_ARM32_td_ecb:
	.long	L_AES_ARM32_td_data
#if defined(WOLFSSL_AES_DIRECT) || defined(WOLFSSL_AES_COUNTER) || defined(HAVE_AES_ECB)
#ifndef __APPLE__
	.text
	.type	L_AES_ARM32_ecb_td4, %object
	.size	L_AES_ARM32_ecb_td4, 256
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_AES_ARM32_ecb_td4:
	.byte	0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38
	.byte	0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb
	.byte	0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87
	.byte	0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb
	.byte	0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d
	.byte	0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e
	.byte	0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2
	.byte	0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25
	.byte	0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16
	.byte	0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92
	.byte	0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda
	.byte	0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84
	.byte	0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a
	.byte	0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06
	.byte	0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02
	.byte	0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b
	.byte	0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea
	.byte	0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73
	.byte	0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85
	.byte	0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e
	.byte	0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89
	.byte	0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b
	.byte	0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20
	.byte	0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4
	.byte	0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31
	.byte	0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f
	.byte	0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d
	.byte	0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef
	.byte	0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0
	.byte	0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61
	.byte	0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26
	.byte	0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
	.text
	.align	4
	.globl	AES_ECB_decrypt
	.type	AES_ECB_decrypt, %function
AES_ECB_decrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	ldr	r8, [sp, #36]
	mov	lr, r0
	adr	r0, L_AES_ARM32_td_ecb
	ldr	r0, [r0]
	mov	r12, r2
	adr	r2, L_AES_ARM32_ecb_td4
	cmp	r8, #10
	beq	L_AES_ECB_decrypt_start_block_128
	cmp	r8, #12
	beq	L_AES_ECB_decrypt_start_block_192
L_AES_ECB_decrypt_loop_block_256:
	ldr	r4, [lr]
	ldr	r5, [lr, #4]
	ldr	r6, [lr, #8]
	ldr	r7, [lr, #12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	push	{r1, r3, r12, lr}
	ldm	r3!, {r8, r9, r10, r11}
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #6
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_decrypt_block
#else
L_AES_ECB_decrypt_block_nr_256:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r11, ror #16
#endif
#else
	ubfx	r4, r11, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r10, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r10, ror #8
#endif
#else
	ubfx	r12, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r9
#endif
#else
	ubfx	lr, r9, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r8, ror #16
#endif
#else
	ubfx	r5, r8, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #8
#endif
#else
	ubfx	r12, r11, #8, #8
#endif
	eor	r4, r4, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r10
#endif
#else
	ubfx	lr, r10, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r9, ror #16
#endif
#else
	ubfx	r6, r9, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #8
#endif
#else
	ubfx	r12, r8, #8, #8
#endif
	eor	r5, r5, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r11
#endif
#else
	ubfx	lr, r11, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r8, #24
	lsr	r8, r8, #24
#else
	uxtb	r8, r8
#endif
#else
	ubfx	r8, r8, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #16
#endif
#else
	ubfx	r7, r10, #16, #8
#endif
	eor	r6, r6, r12, ror #8
	lsr	r12, r11, #24
	eor	r6, r6, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r8, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #8
	eor	r7, r7, r12, ror #24
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_ECB_decrypt_block_nr_256
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r9
#endif
#else
	ubfx	r4, r9, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #16
#endif
#else
	ubfx	r12, r11, #16, #8
#endif
	lsr	lr, r8, #24
	ldrb	r4, [r2, r4]
	ldrb	r7, [r2, r7]
	ldrb	r12, [r2, r12]
	ldrb	lr, [r2, lr]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r10
#endif
#else
	ubfx	r5, r10, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #16
#endif
#else
	ubfx	r12, r8, #16, #8
#endif
	eor	r4, r4, lr, lsl #24
	lsr	lr, r9, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r5, [r2, r5]
	ldrb	r12, [r2, r12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r11
#endif
#else
	ubfx	r6, r11, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #16
#endif
#else
	ubfx	r12, r9, #16, #8
#endif
	eor	r5, r5, lr, lsl #24
	lsr	lr, r10, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r6, [r2, r6]
	ldrb	r12, [r2, r12]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r8
#endif
#else
	ubfx	r7, r8, #0, #8
#endif
	eor	r6, r6, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #8
#endif
#else
	ubfx	r12, r9, #8, #8
#endif
	eor	r6, r6, lr, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	ldrb	r11, [r2, r11]
	ldrb	r12, [r2, r12]
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	eor	r12, r12, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, r12, lsl #8
	eor	r7, r7, lr, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	pop	{r1, r3, r12, lr}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	subs	r12, r12, #16
	add	lr, lr, #16
	add	r1, r1, #16
	bne	L_AES_ECB_decrypt_loop_block_256
	b	L_AES_ECB_decrypt_end
L_AES_ECB_decrypt_start_block_192:
L_AES_ECB_decrypt_loop_block_192:
	ldr	r4, [lr]
	ldr	r5, [lr, #4]
	ldr	r6, [lr, #8]
	ldr	r7, [lr, #12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	push	{r1, r3, r12, lr}
	ldm	r3!, {r8, r9, r10, r11}
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #5
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_decrypt_block
#else
L_AES_ECB_decrypt_block_nr_192:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r11, ror #16
#endif
#else
	ubfx	r4, r11, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r10, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r10, ror #8
#endif
#else
	ubfx	r12, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r9
#endif
#else
	ubfx	lr, r9, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r8, ror #16
#endif
#else
	ubfx	r5, r8, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #8
#endif
#else
	ubfx	r12, r11, #8, #8
#endif
	eor	r4, r4, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r10
#endif
#else
	ubfx	lr, r10, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r9, ror #16
#endif
#else
	ubfx	r6, r9, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #8
#endif
#else
	ubfx	r12, r8, #8, #8
#endif
	eor	r5, r5, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r11
#endif
#else
	ubfx	lr, r11, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r8, #24
	lsr	r8, r8, #24
#else
	uxtb	r8, r8
#endif
#else
	ubfx	r8, r8, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #16
#endif
#else
	ubfx	r7, r10, #16, #8
#endif
	eor	r6, r6, r12, ror #8
	lsr	r12, r11, #24
	eor	r6, r6, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r8, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #8
	eor	r7, r7, r12, ror #24
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_ECB_decrypt_block_nr_192
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r9
#endif
#else
	ubfx	r4, r9, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #16
#endif
#else
	ubfx	r12, r11, #16, #8
#endif
	lsr	lr, r8, #24
	ldrb	r4, [r2, r4]
	ldrb	r7, [r2, r7]
	ldrb	r12, [r2, r12]
	ldrb	lr, [r2, lr]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r10
#endif
#else
	ubfx	r5, r10, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #16
#endif
#else
	ubfx	r12, r8, #16, #8
#endif
	eor	r4, r4, lr, lsl #24
	lsr	lr, r9, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r5, [r2, r5]
	ldrb	r12, [r2, r12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r11
#endif
#else
	ubfx	r6, r11, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #16
#endif
#else
	ubfx	r12, r9, #16, #8
#endif
	eor	r5, r5, lr, lsl #24
	lsr	lr, r10, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r6, [r2, r6]
	ldrb	r12, [r2, r12]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r8
#endif
#else
	ubfx	r7, r8, #0, #8
#endif
	eor	r6, r6, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #8
#endif
#else
	ubfx	r12, r9, #8, #8
#endif
	eor	r6, r6, lr, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	ldrb	r11, [r2, r11]
	ldrb	r12, [r2, r12]
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	eor	r12, r12, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, r12, lsl #8
	eor	r7, r7, lr, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	pop	{r1, r3, r12, lr}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	subs	r12, r12, #16
	add	lr, lr, #16
	add	r1, r1, #16
	bne	L_AES_ECB_decrypt_loop_block_192
	b	L_AES_ECB_decrypt_end
L_AES_ECB_decrypt_start_block_128:
L_AES_ECB_decrypt_loop_block_128:
	ldr	r4, [lr]
	ldr	r5, [lr, #4]
	ldr	r6, [lr, #8]
	ldr	r7, [lr, #12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	push	{r1, r3, r12, lr}
	ldm	r3!, {r8, r9, r10, r11}
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #4
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_decrypt_block
#else
L_AES_ECB_decrypt_block_nr_128:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r11, ror #16
#endif
#else
	ubfx	r4, r11, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r10, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r10, ror #8
#endif
#else
	ubfx	r12, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r9
#endif
#else
	ubfx	lr, r9, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r8, ror #16
#endif
#else
	ubfx	r5, r8, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #8
#endif
#else
	ubfx	r12, r11, #8, #8
#endif
	eor	r4, r4, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r10
#endif
#else
	ubfx	lr, r10, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r9, ror #16
#endif
#else
	ubfx	r6, r9, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #8
#endif
#else
	ubfx	r12, r8, #8, #8
#endif
	eor	r5, r5, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r11
#endif
#else
	ubfx	lr, r11, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r8, #24
	lsr	r8, r8, #24
#else
	uxtb	r8, r8
#endif
#else
	ubfx	r8, r8, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #16
#endif
#else
	ubfx	r7, r10, #16, #8
#endif
	eor	r6, r6, r12, ror #8
	lsr	r12, r11, #24
	eor	r6, r6, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r8, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #8
	eor	r7, r7, r12, ror #24
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_ECB_decrypt_block_nr_128
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r9
#endif
#else
	ubfx	r4, r9, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #16
#endif
#else
	ubfx	r12, r11, #16, #8
#endif
	lsr	lr, r8, #24
	ldrb	r4, [r2, r4]
	ldrb	r7, [r2, r7]
	ldrb	r12, [r2, r12]
	ldrb	lr, [r2, lr]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r10
#endif
#else
	ubfx	r5, r10, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #16
#endif
#else
	ubfx	r12, r8, #16, #8
#endif
	eor	r4, r4, lr, lsl #24
	lsr	lr, r9, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r5, [r2, r5]
	ldrb	r12, [r2, r12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r11
#endif
#else
	ubfx	r6, r11, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #16
#endif
#else
	ubfx	r12, r9, #16, #8
#endif
	eor	r5, r5, lr, lsl #24
	lsr	lr, r10, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r6, [r2, r6]
	ldrb	r12, [r2, r12]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r8
#endif
#else
	ubfx	r7, r8, #0, #8
#endif
	eor	r6, r6, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #8
#endif
#else
	ubfx	r12, r9, #8, #8
#endif
	eor	r6, r6, lr, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	ldrb	r11, [r2, r11]
	ldrb	r12, [r2, r12]
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	eor	r12, r12, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, r12, lsl #8
	eor	r7, r7, lr, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	pop	{r1, r3, r12, lr}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	subs	r12, r12, #16
	add	lr, lr, #16
	add	r1, r1, #16
	bne	L_AES_ECB_decrypt_loop_block_128
L_AES_ECB_decrypt_end:
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	AES_ECB_decrypt,.-AES_ECB_decrypt
#endif /* WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER || defined(HAVE_AES_ECB) */
#ifdef HAVE_AES_CBC
#ifndef __APPLE__
	.text
	.type	L_AES_ARM32_cbc_td4, %object
	.size	L_AES_ARM32_cbc_td4, 256
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 4-byte aligned, 32-bit aligned
#ifndef __APPLE__
	.align	2
#else
	.p2align	2
#endif /* __APPLE__ */
L_AES_ARM32_cbc_td4:
	.byte	0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38
	.byte	0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb
	.byte	0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87
	.byte	0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb
	.byte	0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d
	.byte	0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e
	.byte	0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2
	.byte	0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25
	.byte	0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16
	.byte	0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92
	.byte	0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda
	.byte	0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84
	.byte	0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a
	.byte	0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06
	.byte	0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02
	.byte	0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b
	.byte	0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea
	.byte	0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73
	.byte	0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85
	.byte	0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e
	.byte	0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89
	.byte	0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b
	.byte	0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20
	.byte	0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4
	.byte	0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31
	.byte	0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f
	.byte	0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d
	.byte	0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef
	.byte	0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0
	.byte	0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61
	.byte	0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26
	.byte	0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
	.text
	.align	4
	.globl	AES_CBC_decrypt
	.type	AES_CBC_decrypt, %function
AES_CBC_decrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	mov	lr, r0
	adr	r0, L_AES_ARM32_td_ecb
	ldr	r0, [r0]
	mov	r12, r2
	adr	r2, L_AES_ARM32_cbc_td4
	ldr	r8, [sp, #36]
	ldr	r4, [sp, #40]
	push	{r3-r4}
	cmp	r8, #10
	beq	L_AES_CBC_decrypt_loop_block_128
	cmp	r8, #12
	beq	L_AES_CBC_decrypt_loop_block_192
L_AES_CBC_decrypt_loop_block_256:
	push	{r1, r12, lr}
	ldr	r4, [lr]
	ldr	r5, [lr, #4]
	ldr	r6, [lr, #8]
	ldr	r7, [lr, #12]
	ldr	lr, [sp, #16]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [lr, #16]
	str	r5, [lr, #20]
#else
	strd	r4, r5, [lr, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [lr, #24]
	str	r7, [lr, #28]
#else
	strd	r6, r7, [lr, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	ldm	r3!, {r8, r9, r10, r11}
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #6
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_decrypt_block
#else
L_AES_CBC_decrypt_block_nr_256_odd:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r11, ror #16
#endif
#else
	ubfx	r4, r11, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r10, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r10, ror #8
#endif
#else
	ubfx	r12, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r9
#endif
#else
	ubfx	lr, r9, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r8, ror #16
#endif
#else
	ubfx	r5, r8, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #8
#endif
#else
	ubfx	r12, r11, #8, #8
#endif
	eor	r4, r4, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r10
#endif
#else
	ubfx	lr, r10, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r9, ror #16
#endif
#else
	ubfx	r6, r9, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #8
#endif
#else
	ubfx	r12, r8, #8, #8
#endif
	eor	r5, r5, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r11
#endif
#else
	ubfx	lr, r11, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r8, #24
	lsr	r8, r8, #24
#else
	uxtb	r8, r8
#endif
#else
	ubfx	r8, r8, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #16
#endif
#else
	ubfx	r7, r10, #16, #8
#endif
	eor	r6, r6, r12, ror #8
	lsr	r12, r11, #24
	eor	r6, r6, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r8, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #8
	eor	r7, r7, r12, ror #24
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_CBC_decrypt_block_nr_256_odd
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r9
#endif
#else
	ubfx	r4, r9, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #16
#endif
#else
	ubfx	r12, r11, #16, #8
#endif
	lsr	lr, r8, #24
	ldrb	r4, [r2, r4]
	ldrb	r7, [r2, r7]
	ldrb	r12, [r2, r12]
	ldrb	lr, [r2, lr]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r10
#endif
#else
	ubfx	r5, r10, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #16
#endif
#else
	ubfx	r12, r8, #16, #8
#endif
	eor	r4, r4, lr, lsl #24
	lsr	lr, r9, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r5, [r2, r5]
	ldrb	r12, [r2, r12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r11
#endif
#else
	ubfx	r6, r11, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #16
#endif
#else
	ubfx	r12, r9, #16, #8
#endif
	eor	r5, r5, lr, lsl #24
	lsr	lr, r10, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r6, [r2, r6]
	ldrb	r12, [r2, r12]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r8
#endif
#else
	ubfx	r7, r8, #0, #8
#endif
	eor	r6, r6, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #8
#endif
#else
	ubfx	r12, r9, #8, #8
#endif
	eor	r6, r6, lr, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	ldrb	r11, [r2, r11]
	ldrb	r12, [r2, r12]
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	eor	r12, r12, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, r12, lsl #8
	eor	r7, r7, lr, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	ldr	lr, [sp, #16]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	ldm	lr, {r8, r9, r10, r11}
	pop	{r1, r12, lr}
	ldr	r3, [sp]
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	subs	r12, r12, #16
	add	lr, lr, #16
	add	r1, r1, #16
	beq	L_AES_CBC_decrypt_end_odd
	push	{r1, r12, lr}
	ldr	r4, [lr]
	ldr	r5, [lr, #4]
	ldr	r6, [lr, #8]
	ldr	r7, [lr, #12]
	ldr	lr, [sp, #16]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	lr, {r4, r5}
#else
	strd	r4, r5, [lr]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [lr, #8]
	str	r7, [lr, #12]
#else
	strd	r6, r7, [lr, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	ldm	r3!, {r8, r9, r10, r11}
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #6
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_decrypt_block
#else
L_AES_CBC_decrypt_block_nr_256_even:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r11, ror #16
#endif
#else
	ubfx	r4, r11, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r10, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r10, ror #8
#endif
#else
	ubfx	r12, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r9
#endif
#else
	ubfx	lr, r9, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r8, ror #16
#endif
#else
	ubfx	r5, r8, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #8
#endif
#else
	ubfx	r12, r11, #8, #8
#endif
	eor	r4, r4, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r10
#endif
#else
	ubfx	lr, r10, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r9, ror #16
#endif
#else
	ubfx	r6, r9, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #8
#endif
#else
	ubfx	r12, r8, #8, #8
#endif
	eor	r5, r5, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r11
#endif
#else
	ubfx	lr, r11, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r8, #24
	lsr	r8, r8, #24
#else
	uxtb	r8, r8
#endif
#else
	ubfx	r8, r8, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #16
#endif
#else
	ubfx	r7, r10, #16, #8
#endif
	eor	r6, r6, r12, ror #8
	lsr	r12, r11, #24
	eor	r6, r6, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r8, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #8
	eor	r7, r7, r12, ror #24
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_CBC_decrypt_block_nr_256_even
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r9
#endif
#else
	ubfx	r4, r9, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #16
#endif
#else
	ubfx	r12, r11, #16, #8
#endif
	lsr	lr, r8, #24
	ldrb	r4, [r2, r4]
	ldrb	r7, [r2, r7]
	ldrb	r12, [r2, r12]
	ldrb	lr, [r2, lr]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r10
#endif
#else
	ubfx	r5, r10, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #16
#endif
#else
	ubfx	r12, r8, #16, #8
#endif
	eor	r4, r4, lr, lsl #24
	lsr	lr, r9, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r5, [r2, r5]
	ldrb	r12, [r2, r12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r11
#endif
#else
	ubfx	r6, r11, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #16
#endif
#else
	ubfx	r12, r9, #16, #8
#endif
	eor	r5, r5, lr, lsl #24
	lsr	lr, r10, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r6, [r2, r6]
	ldrb	r12, [r2, r12]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r8
#endif
#else
	ubfx	r7, r8, #0, #8
#endif
	eor	r6, r6, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #8
#endif
#else
	ubfx	r12, r9, #8, #8
#endif
	eor	r6, r6, lr, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	ldrb	r11, [r2, r11]
	ldrb	r12, [r2, r12]
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	eor	r12, r12, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, r12, lsl #8
	eor	r7, r7, lr, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	ldr	lr, [sp, #16]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [lr, #16]
	ldr	r9, [lr, #20]
#else
	ldrd	r8, r9, [lr, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [lr, #24]
	ldr	r11, [lr, #28]
#else
	ldrd	r10, r11, [lr, #24]
#endif
	pop	{r1, r12, lr}
	ldr	r3, [sp]
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	subs	r12, r12, #16
	add	lr, lr, #16
	add	r1, r1, #16
	bne	L_AES_CBC_decrypt_loop_block_256
	b	L_AES_CBC_decrypt_end
L_AES_CBC_decrypt_loop_block_192:
	push	{r1, r12, lr}
	ldr	r4, [lr]
	ldr	r5, [lr, #4]
	ldr	r6, [lr, #8]
	ldr	r7, [lr, #12]
	ldr	lr, [sp, #16]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [lr, #16]
	str	r5, [lr, #20]
#else
	strd	r4, r5, [lr, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [lr, #24]
	str	r7, [lr, #28]
#else
	strd	r6, r7, [lr, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	ldm	r3!, {r8, r9, r10, r11}
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #5
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_decrypt_block
#else
L_AES_CBC_decrypt_block_nr_192_odd:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r11, ror #16
#endif
#else
	ubfx	r4, r11, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r10, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r10, ror #8
#endif
#else
	ubfx	r12, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r9
#endif
#else
	ubfx	lr, r9, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r8, ror #16
#endif
#else
	ubfx	r5, r8, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #8
#endif
#else
	ubfx	r12, r11, #8, #8
#endif
	eor	r4, r4, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r10
#endif
#else
	ubfx	lr, r10, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r9, ror #16
#endif
#else
	ubfx	r6, r9, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #8
#endif
#else
	ubfx	r12, r8, #8, #8
#endif
	eor	r5, r5, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r11
#endif
#else
	ubfx	lr, r11, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r8, #24
	lsr	r8, r8, #24
#else
	uxtb	r8, r8
#endif
#else
	ubfx	r8, r8, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #16
#endif
#else
	ubfx	r7, r10, #16, #8
#endif
	eor	r6, r6, r12, ror #8
	lsr	r12, r11, #24
	eor	r6, r6, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r8, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #8
	eor	r7, r7, r12, ror #24
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_CBC_decrypt_block_nr_192_odd
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r9
#endif
#else
	ubfx	r4, r9, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #16
#endif
#else
	ubfx	r12, r11, #16, #8
#endif
	lsr	lr, r8, #24
	ldrb	r4, [r2, r4]
	ldrb	r7, [r2, r7]
	ldrb	r12, [r2, r12]
	ldrb	lr, [r2, lr]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r10
#endif
#else
	ubfx	r5, r10, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #16
#endif
#else
	ubfx	r12, r8, #16, #8
#endif
	eor	r4, r4, lr, lsl #24
	lsr	lr, r9, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r5, [r2, r5]
	ldrb	r12, [r2, r12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r11
#endif
#else
	ubfx	r6, r11, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #16
#endif
#else
	ubfx	r12, r9, #16, #8
#endif
	eor	r5, r5, lr, lsl #24
	lsr	lr, r10, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r6, [r2, r6]
	ldrb	r12, [r2, r12]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r8
#endif
#else
	ubfx	r7, r8, #0, #8
#endif
	eor	r6, r6, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #8
#endif
#else
	ubfx	r12, r9, #8, #8
#endif
	eor	r6, r6, lr, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	ldrb	r11, [r2, r11]
	ldrb	r12, [r2, r12]
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	eor	r12, r12, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, r12, lsl #8
	eor	r7, r7, lr, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	ldr	lr, [sp, #16]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	ldm	lr, {r8, r9, r10, r11}
	pop	{r1, r12, lr}
	ldr	r3, [sp]
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	subs	r12, r12, #16
	add	lr, lr, #16
	add	r1, r1, #16
	beq	L_AES_CBC_decrypt_end_odd
	push	{r1, r12, lr}
	ldr	r4, [lr]
	ldr	r5, [lr, #4]
	ldr	r6, [lr, #8]
	ldr	r7, [lr, #12]
	ldr	lr, [sp, #16]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	lr, {r4, r5}
#else
	strd	r4, r5, [lr]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [lr, #8]
	str	r7, [lr, #12]
#else
	strd	r6, r7, [lr, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	ldm	r3!, {r8, r9, r10, r11}
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #5
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_decrypt_block
#else
L_AES_CBC_decrypt_block_nr_192_even:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r11, ror #16
#endif
#else
	ubfx	r4, r11, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r10, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r10, ror #8
#endif
#else
	ubfx	r12, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r9
#endif
#else
	ubfx	lr, r9, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r8, ror #16
#endif
#else
	ubfx	r5, r8, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #8
#endif
#else
	ubfx	r12, r11, #8, #8
#endif
	eor	r4, r4, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r10
#endif
#else
	ubfx	lr, r10, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r9, ror #16
#endif
#else
	ubfx	r6, r9, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #8
#endif
#else
	ubfx	r12, r8, #8, #8
#endif
	eor	r5, r5, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r11
#endif
#else
	ubfx	lr, r11, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r8, #24
	lsr	r8, r8, #24
#else
	uxtb	r8, r8
#endif
#else
	ubfx	r8, r8, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #16
#endif
#else
	ubfx	r7, r10, #16, #8
#endif
	eor	r6, r6, r12, ror #8
	lsr	r12, r11, #24
	eor	r6, r6, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r8, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #8
	eor	r7, r7, r12, ror #24
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_CBC_decrypt_block_nr_192_even
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r9
#endif
#else
	ubfx	r4, r9, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #16
#endif
#else
	ubfx	r12, r11, #16, #8
#endif
	lsr	lr, r8, #24
	ldrb	r4, [r2, r4]
	ldrb	r7, [r2, r7]
	ldrb	r12, [r2, r12]
	ldrb	lr, [r2, lr]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r10
#endif
#else
	ubfx	r5, r10, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #16
#endif
#else
	ubfx	r12, r8, #16, #8
#endif
	eor	r4, r4, lr, lsl #24
	lsr	lr, r9, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r5, [r2, r5]
	ldrb	r12, [r2, r12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r11
#endif
#else
	ubfx	r6, r11, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #16
#endif
#else
	ubfx	r12, r9, #16, #8
#endif
	eor	r5, r5, lr, lsl #24
	lsr	lr, r10, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r6, [r2, r6]
	ldrb	r12, [r2, r12]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r8
#endif
#else
	ubfx	r7, r8, #0, #8
#endif
	eor	r6, r6, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #8
#endif
#else
	ubfx	r12, r9, #8, #8
#endif
	eor	r6, r6, lr, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	ldrb	r11, [r2, r11]
	ldrb	r12, [r2, r12]
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	eor	r12, r12, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, r12, lsl #8
	eor	r7, r7, lr, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	ldr	lr, [sp, #16]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [lr, #16]
	ldr	r9, [lr, #20]
#else
	ldrd	r8, r9, [lr, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [lr, #24]
	ldr	r11, [lr, #28]
#else
	ldrd	r10, r11, [lr, #24]
#endif
	pop	{r1, r12, lr}
	ldr	r3, [sp]
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	subs	r12, r12, #16
	add	lr, lr, #16
	add	r1, r1, #16
	bne	L_AES_CBC_decrypt_loop_block_192
	b	L_AES_CBC_decrypt_end
L_AES_CBC_decrypt_loop_block_128:
	push	{r1, r12, lr}
	ldr	r4, [lr]
	ldr	r5, [lr, #4]
	ldr	r6, [lr, #8]
	ldr	r7, [lr, #12]
	ldr	lr, [sp, #16]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [lr, #16]
	str	r5, [lr, #20]
#else
	strd	r4, r5, [lr, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [lr, #24]
	str	r7, [lr, #28]
#else
	strd	r6, r7, [lr, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	ldm	r3!, {r8, r9, r10, r11}
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #4
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_decrypt_block
#else
L_AES_CBC_decrypt_block_nr_128_odd:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r11, ror #16
#endif
#else
	ubfx	r4, r11, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r10, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r10, ror #8
#endif
#else
	ubfx	r12, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r9
#endif
#else
	ubfx	lr, r9, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r8, ror #16
#endif
#else
	ubfx	r5, r8, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #8
#endif
#else
	ubfx	r12, r11, #8, #8
#endif
	eor	r4, r4, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r10
#endif
#else
	ubfx	lr, r10, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r9, ror #16
#endif
#else
	ubfx	r6, r9, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #8
#endif
#else
	ubfx	r12, r8, #8, #8
#endif
	eor	r5, r5, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r11
#endif
#else
	ubfx	lr, r11, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r8, #24
	lsr	r8, r8, #24
#else
	uxtb	r8, r8
#endif
#else
	ubfx	r8, r8, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #16
#endif
#else
	ubfx	r7, r10, #16, #8
#endif
	eor	r6, r6, r12, ror #8
	lsr	r12, r11, #24
	eor	r6, r6, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r8, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #8
	eor	r7, r7, r12, ror #24
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_CBC_decrypt_block_nr_128_odd
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r9
#endif
#else
	ubfx	r4, r9, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #16
#endif
#else
	ubfx	r12, r11, #16, #8
#endif
	lsr	lr, r8, #24
	ldrb	r4, [r2, r4]
	ldrb	r7, [r2, r7]
	ldrb	r12, [r2, r12]
	ldrb	lr, [r2, lr]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r10
#endif
#else
	ubfx	r5, r10, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #16
#endif
#else
	ubfx	r12, r8, #16, #8
#endif
	eor	r4, r4, lr, lsl #24
	lsr	lr, r9, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r5, [r2, r5]
	ldrb	r12, [r2, r12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r11
#endif
#else
	ubfx	r6, r11, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #16
#endif
#else
	ubfx	r12, r9, #16, #8
#endif
	eor	r5, r5, lr, lsl #24
	lsr	lr, r10, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r6, [r2, r6]
	ldrb	r12, [r2, r12]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r8
#endif
#else
	ubfx	r7, r8, #0, #8
#endif
	eor	r6, r6, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #8
#endif
#else
	ubfx	r12, r9, #8, #8
#endif
	eor	r6, r6, lr, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	ldrb	r11, [r2, r11]
	ldrb	r12, [r2, r12]
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	eor	r12, r12, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, r12, lsl #8
	eor	r7, r7, lr, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	ldr	lr, [sp, #16]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	ldm	lr, {r8, r9, r10, r11}
	pop	{r1, r12, lr}
	ldr	r3, [sp]
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	subs	r12, r12, #16
	add	lr, lr, #16
	add	r1, r1, #16
	beq	L_AES_CBC_decrypt_end_odd
	push	{r1, r12, lr}
	ldr	r4, [lr]
	ldr	r5, [lr, #4]
	ldr	r6, [lr, #8]
	ldr	r7, [lr, #12]
	ldr	lr, [sp, #16]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	lr, {r4, r5}
#else
	strd	r4, r5, [lr]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [lr, #8]
	str	r7, [lr, #12]
#else
	strd	r6, r7, [lr, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	ldm	r3!, {r8, r9, r10, r11}
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #4
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_decrypt_block
#else
L_AES_CBC_decrypt_block_nr_128_even:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r11, ror #16
#endif
#else
	ubfx	r4, r11, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r10, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r10, ror #8
#endif
#else
	ubfx	r12, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r9
#endif
#else
	ubfx	lr, r9, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r8, ror #16
#endif
#else
	ubfx	r5, r8, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #8
#endif
#else
	ubfx	r12, r11, #8, #8
#endif
	eor	r4, r4, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r10
#endif
#else
	ubfx	lr, r10, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r9, ror #16
#endif
#else
	ubfx	r6, r9, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #8
#endif
#else
	ubfx	r12, r8, #8, #8
#endif
	eor	r5, r5, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r11
#endif
#else
	ubfx	lr, r11, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r8, #24
	lsr	r8, r8, #24
#else
	uxtb	r8, r8
#endif
#else
	ubfx	r8, r8, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #16
#endif
#else
	ubfx	r7, r10, #16, #8
#endif
	eor	r6, r6, r12, ror #8
	lsr	r12, r11, #24
	eor	r6, r6, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r8, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #8
	eor	r7, r7, r12, ror #24
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_CBC_decrypt_block_nr_128_even
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r7, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r7, ror #16
#endif
#else
	ubfx	r8, r7, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r6, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r6, ror #8
#endif
#else
	ubfx	r12, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r5
#endif
#else
	ubfx	lr, r5, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r4, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r4, ror #16
#endif
#else
	ubfx	r9, r4, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r7, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r7, ror #8
#endif
#else
	ubfx	r12, r7, #8, #8
#endif
	eor	r8, r8, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r6
#endif
#else
	ubfx	lr, r6, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r5, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r5, ror #16
#endif
#else
	ubfx	r10, r5, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, r12, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r4, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r4, ror #8
#endif
#else
	ubfx	r12, r4, #8, #8
#endif
	eor	r9, r9, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #24
	lsr	lr, lr, #24
#else
	uxtb	lr, r7
#endif
#else
	ubfx	lr, r7, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r4, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r4
#endif
#else
	ubfx	r4, r4, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r6, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r6, ror #16
#endif
#else
	ubfx	r11, r6, #16, #8
#endif
	eor	r10, r10, r12, ror #8
	lsr	r12, r7, #24
	eor	r10, r10, lr, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r5, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r5, ror #8
#endif
#else
	ubfx	lr, r5, #8, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r12, [r0, r12, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	eor	r12, r12, r4, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #8
	eor	r11, r11, r12, ror #24
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r9
#endif
#else
	ubfx	r4, r9, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r11, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r11, ror #16
#endif
#else
	ubfx	r12, r11, #16, #8
#endif
	lsr	lr, r8, #24
	ldrb	r4, [r2, r4]
	ldrb	r7, [r2, r7]
	ldrb	r12, [r2, r12]
	ldrb	lr, [r2, lr]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r10
#endif
#else
	ubfx	r5, r10, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r8, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r8, ror #16
#endif
#else
	ubfx	r12, r8, #16, #8
#endif
	eor	r4, r4, lr, lsl #24
	lsr	lr, r9, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r5, [r2, r5]
	ldrb	r12, [r2, r12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r11
#endif
#else
	ubfx	r6, r11, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #8
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #16
#endif
#else
	ubfx	r12, r9, #16, #8
#endif
	eor	r5, r5, lr, lsl #24
	lsr	lr, r10, #24
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	ldrb	r6, [r2, r6]
	ldrb	r12, [r2, r12]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r8
#endif
#else
	ubfx	r7, r8, #0, #8
#endif
	eor	r6, r6, r12, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r12, r9, #16
	lsr	r12, r12, #24
#else
	uxtb	r12, r9, ror #8
#endif
#else
	ubfx	r12, r9, #8, #8
#endif
	eor	r6, r6, lr, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	ldrb	r11, [r2, r11]
	ldrb	r12, [r2, r12]
	ldrb	r7, [r2, r7]
	ldrb	lr, [r2, lr]
	eor	r12, r12, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, r12, lsl #8
	eor	r7, r7, lr, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	ldr	lr, [sp, #16]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [lr, #16]
	ldr	r9, [lr, #20]
#else
	ldrd	r8, r9, [lr, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [lr, #24]
	ldr	r11, [lr, #28]
#else
	ldrd	r10, r11, [lr, #24]
#endif
	pop	{r1, r12, lr}
	ldr	r3, [sp]
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	subs	r12, r12, #16
	add	lr, lr, #16
	add	r1, r1, #16
	bne	L_AES_CBC_decrypt_loop_block_128
	b	L_AES_CBC_decrypt_end
L_AES_CBC_decrypt_end_odd:
	ldr	r4, [sp, #4]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r4, #16]
	ldr	r9, [r4, #20]
#else
	ldrd	r8, r9, [r4, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r4, #24]
	ldr	r11, [r4, #28]
#else
	ldrd	r10, r11, [r4, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r4, {r8, r9}
#else
	strd	r8, r9, [r4]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [r4, #8]
	str	r11, [r4, #12]
#else
	strd	r10, r11, [r4, #8]
#endif
L_AES_CBC_decrypt_end:
	pop	{r3-r4}
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	AES_CBC_decrypt,.-AES_CBC_decrypt
#endif /* HAVE_AES_CBC */
#endif /* WOLFSSL_AES_DIRECT || WOLFSSL_AES_COUNTER || HAVE_AES_CBC
        * HAVE_AES_ECB */
#endif /* HAVE_AES_DECRYPT */
#ifdef HAVE_AESGCM
#ifndef __APPLE__
	.text
	.type	L_GCM_gmult_len_r, %object
	.size	L_GCM_gmult_len_r, 64
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_GCM_gmult_len_r:
	.long	0x00000000,0x1c200000,0x38400000,0x24600000
	.long	0x70800000,0x6ca00000,0x48c00000,0x54e00000
	.long	0xe1000000,0xfd200000,0xd9400000,0xc5600000
	.long	0x91800000,0x8da00000,0xa9c00000,0xb5e00000
	.text
	.align	4
	.globl	GCM_gmult_len
	.type	GCM_gmult_len, %function
GCM_gmult_len:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	adr	lr, L_GCM_gmult_len_r
L_GCM_gmult_len_start_block:
	push	{r3}
	ldr	r12, [r0, #12]
	ldr	r3, [r2, #12]
	eor	r12, r12, r3
	lsr	r3, r12, #24
	and	r3, r3, #15
	add	r3, r1, r3, lsl #4
	ldm	r3, {r8, r9, r10, r11}
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #28
	eor	r11, r11, r10, lsl #28
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #16
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #20
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #8
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #12
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	and	r4, r12, #15
	eor	r11, r11, r10, lsl #28
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #4
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	eor	r11, r11, r10, lsl #28
	ldr	r3, [lr, r3, lsl #2]
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	ldr	r12, [r0, #8]
	ldr	r3, [r2, #8]
	eor	r12, r12, r3
	lsr	r3, r12, #24
	and	r3, r3, #15
	add	r3, r1, r3, lsl #4
	ldm	r3, {r4, r5, r6, r7}
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #28
	eor	r11, r11, r10, lsl #28
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #16
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #20
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #8
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #12
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	and	r4, r12, #15
	eor	r11, r11, r10, lsl #28
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #4
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	eor	r11, r11, r10, lsl #28
	ldr	r3, [lr, r3, lsl #2]
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	ldr	r12, [r0, #4]
	ldr	r3, [r2, #4]
	eor	r12, r12, r3
	lsr	r3, r12, #24
	and	r3, r3, #15
	add	r3, r1, r3, lsl #4
	ldm	r3, {r4, r5, r6, r7}
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #28
	eor	r11, r11, r10, lsl #28
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #16
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #20
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #8
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #12
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	and	r4, r12, #15
	eor	r11, r11, r10, lsl #28
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #4
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	eor	r11, r11, r10, lsl #28
	ldr	r3, [lr, r3, lsl #2]
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	ldr	r12, [r0]
	ldr	r3, [r2]
	eor	r12, r12, r3
	lsr	r3, r12, #24
	and	r3, r3, #15
	add	r3, r1, r3, lsl #4
	ldm	r3, {r4, r5, r6, r7}
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #28
	eor	r11, r11, r10, lsl #28
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #16
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #20
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #8
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #12
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	and	r4, r12, #15
	eor	r11, r11, r10, lsl #28
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
	lsr	r6, r10, #4
	and	r3, r11, #15
	lsr	r11, r11, #4
	lsr	r4, r12, #4
	eor	r11, r11, r10, lsl #28
	and	r4, r4, #15
	ldr	r3, [lr, r3, lsl #2]
	add	r4, r1, r4, lsl #4
	eor	r10, r6, r9, lsl #28
	lsr	r9, r9, #4
	ldm	r4, {r4, r5, r6, r7}
	eor	r9, r9, r8, lsl #28
	eor	r8, r3, r8, lsr #4
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	# REV r8, r8
	eor	r3, r8, r8, ror #16
	bic	r3, r3, #0xff0000
	ror	r8, r8, #8
	eor	r8, r8, r3, lsr #8
	# REV r9, r9
	eor	r3, r9, r9, ror #16
	bic	r3, r3, #0xff0000
	ror	r9, r9, #8
	eor	r9, r9, r3, lsr #8
	# REV r10, r10
	eor	r3, r10, r10, ror #16
	bic	r3, r3, #0xff0000
	ror	r10, r10, #8
	eor	r10, r10, r3, lsr #8
	# REV r11, r11
	eor	r3, r11, r11, ror #16
	bic	r3, r3, #0xff0000
	ror	r11, r11, #8
	eor	r11, r11, r3, lsr #8
#else
	rev	r8, r8
	rev	r9, r9
	rev	r10, r10
	rev	r11, r11
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	stm	r0, {r8, r9, r10, r11}
	pop	{r3}
	subs	r3, r3, #16
	add	r2, r2, #16
	bne	L_GCM_gmult_len_start_block
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	GCM_gmult_len,.-GCM_gmult_len
#ifndef __APPLE__
	.text
	.type	L_AES_ARM32_te_gcm, %object
	.size	L_AES_ARM32_te_gcm, 12
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_AES_ARM32_te_gcm:
	.long	L_AES_ARM32_te_data
	.text
	.align	4
	.globl	AES_GCM_encrypt
	.type	AES_GCM_encrypt, %function
AES_GCM_encrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	ldr	r12, [sp, #36]
	ldr	r8, [sp, #40]
	mov	lr, r0
	adr	r0, L_AES_ARM32_te_gcm
	ldr	r0, [r0]
	ldm	r8, {r4, r5, r6, r7}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r10, r4, r4, ror #16
	eor	r11, r5, r5, ror #16
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	eor	r4, r4, r10, lsr #8
	eor	r5, r5, r11, lsr #8
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	stm	r8, {r4, r5, r6, r7}
	push	{r3, r8}
	cmp	r12, #10
	beq	L_AES_GCM_encrypt_start_block_128
	cmp	r12, #12
	beq	L_AES_GCM_encrypt_start_block_192
L_AES_GCM_encrypt_loop_block_256:
	push	{r1, r2, lr}
	ldr	lr, [sp, #16]
	add	r7, r7, #1
	ldm	r3!, {r8, r9, r10, r11}
	str	r7, [lr, #12]
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #6
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_encrypt_block
#else
L_AES_GCM_encrypt_block_nr_256:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r9, ror #16
#endif
#else
	ubfx	r4, r9, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #8
#endif
#else
	ubfx	lr, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r11, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r11
#endif
#else
	ubfx	r2, r11, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r10, ror #16
#endif
#else
	ubfx	r5, r10, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #8
#endif
#else
	ubfx	lr, r11, #8, #8
#endif
	eor	r4, r4, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r8
#endif
#else
	ubfx	r2, r8, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r11, ror #16
#endif
#else
	ubfx	r6, r11, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r8, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r8, ror #8
#endif
#else
	ubfx	lr, r8, #8, #8
#endif
	eor	r5, r5, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r9
#endif
#else
	ubfx	r2, r9, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r10, #24
	lsr	r10, r10, #24
#else
	uxtb	r10, r10
#endif
#else
	ubfx	r10, r10, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #16
#endif
#else
	ubfx	r7, r8, #16, #8
#endif
	eor	r6, r6, lr, ror #8
	lsr	lr, r11, #24
	eor	r6, r6, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r9, ror #8
#endif
#else
	ubfx	r2, r9, #8, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r10, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #24
	eor	r7, r7, r2, ror #8
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_GCM_encrypt_block_nr_256
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r11
#endif
#else
	ubfx	r4, r11, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #16
#endif
#else
	ubfx	lr, r9, #16, #8
#endif
	lsr	r2, r8, #24
	ldrb	r4, [r0, r4, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r8
#endif
#else
	ubfx	r5, r8, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	eor	r4, r4, r2, lsl #24
	lsr	r2, r9, #24
	ldrb	r5, [r0, r5, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r9
#endif
#else
	ubfx	r6, r9, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #16
#endif
#else
	ubfx	lr, r11, #16, #8
#endif
	eor	r5, r5, r2, lsl #24
	lsr	r2, r10, #24
	ldrb	r6, [r0, r6, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r10
#endif
#else
	ubfx	r7, r10, #0, #8
#endif
	eor	r6, r6, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	eor	r6, r6, r2, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #8
	lsr	r2, r2, #24
#else
	uxtb	r2, r8, ror #16
#endif
#else
	ubfx	r2, r8, #16, #8
#endif
	ldrb	r11, [r0, r11, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	eor	lr, lr, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, lr, lsl #8
	eor	r7, r7, r2, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	pop	{r1, r2, lr}
	ldr	r3, [sp]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	ldr	r8, [lr]
	ldr	r9, [lr, #4]
	ldr	r10, [lr, #8]
	ldr	r11, [lr, #12]
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	ldr	r8, [sp, #4]
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	ldm	r8, {r4, r5, r6, r7}
	subs	r2, r2, #16
	add	lr, lr, #16
	add	r1, r1, #16
	bne	L_AES_GCM_encrypt_loop_block_256
	b	L_AES_GCM_encrypt_end
L_AES_GCM_encrypt_start_block_192:
L_AES_GCM_encrypt_loop_block_192:
	push	{r1, r2, lr}
	ldr	lr, [sp, #16]
	add	r7, r7, #1
	ldm	r3!, {r8, r9, r10, r11}
	str	r7, [lr, #12]
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #5
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_encrypt_block
#else
L_AES_GCM_encrypt_block_nr_192:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r9, ror #16
#endif
#else
	ubfx	r4, r9, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #8
#endif
#else
	ubfx	lr, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r11, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r11
#endif
#else
	ubfx	r2, r11, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r10, ror #16
#endif
#else
	ubfx	r5, r10, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #8
#endif
#else
	ubfx	lr, r11, #8, #8
#endif
	eor	r4, r4, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r8
#endif
#else
	ubfx	r2, r8, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r11, ror #16
#endif
#else
	ubfx	r6, r11, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r8, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r8, ror #8
#endif
#else
	ubfx	lr, r8, #8, #8
#endif
	eor	r5, r5, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r9
#endif
#else
	ubfx	r2, r9, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r10, #24
	lsr	r10, r10, #24
#else
	uxtb	r10, r10
#endif
#else
	ubfx	r10, r10, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #16
#endif
#else
	ubfx	r7, r8, #16, #8
#endif
	eor	r6, r6, lr, ror #8
	lsr	lr, r11, #24
	eor	r6, r6, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r9, ror #8
#endif
#else
	ubfx	r2, r9, #8, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r10, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #24
	eor	r7, r7, r2, ror #8
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_GCM_encrypt_block_nr_192
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r11
#endif
#else
	ubfx	r4, r11, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #16
#endif
#else
	ubfx	lr, r9, #16, #8
#endif
	lsr	r2, r8, #24
	ldrb	r4, [r0, r4, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r8
#endif
#else
	ubfx	r5, r8, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	eor	r4, r4, r2, lsl #24
	lsr	r2, r9, #24
	ldrb	r5, [r0, r5, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r9
#endif
#else
	ubfx	r6, r9, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #16
#endif
#else
	ubfx	lr, r11, #16, #8
#endif
	eor	r5, r5, r2, lsl #24
	lsr	r2, r10, #24
	ldrb	r6, [r0, r6, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r10
#endif
#else
	ubfx	r7, r10, #0, #8
#endif
	eor	r6, r6, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	eor	r6, r6, r2, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #8
	lsr	r2, r2, #24
#else
	uxtb	r2, r8, ror #16
#endif
#else
	ubfx	r2, r8, #16, #8
#endif
	ldrb	r11, [r0, r11, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	eor	lr, lr, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, lr, lsl #8
	eor	r7, r7, r2, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	pop	{r1, r2, lr}
	ldr	r3, [sp]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	ldr	r8, [lr]
	ldr	r9, [lr, #4]
	ldr	r10, [lr, #8]
	ldr	r11, [lr, #12]
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	ldr	r8, [sp, #4]
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	ldm	r8, {r4, r5, r6, r7}
	subs	r2, r2, #16
	add	lr, lr, #16
	add	r1, r1, #16
	bne	L_AES_GCM_encrypt_loop_block_192
	b	L_AES_GCM_encrypt_end
L_AES_GCM_encrypt_start_block_128:
L_AES_GCM_encrypt_loop_block_128:
	push	{r1, r2, lr}
	ldr	lr, [sp, #16]
	add	r7, r7, #1
	ldm	r3!, {r8, r9, r10, r11}
	str	r7, [lr, #12]
	# Round: 0 - XOR in key schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	mov	r1, #4
#ifndef WOLFSSL_ARMASM_AES_BLOCK_INLINE
	bl	AES_encrypt_block
#else
L_AES_GCM_encrypt_block_nr_128:
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r9, #8
	lsr	r4, r4, #24
#else
	uxtb	r4, r9, ror #16
#endif
#else
	ubfx	r4, r9, #16, #8
#endif
	lsr	r7, r8, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #8
#endif
#else
	ubfx	lr, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r11, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r11
#endif
#else
	ubfx	r2, r11, #0, #8
#endif
	ldr	r4, [r0, r4, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r10, #8
	lsr	r5, r5, #24
#else
	uxtb	r5, r10, ror #16
#endif
#else
	ubfx	r5, r10, #16, #8
#endif
	eor	r4, r4, r7, ror #24
	lsr	r7, r9, #24
	eor	r4, r4, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #8
#endif
#else
	ubfx	lr, r11, #8, #8
#endif
	eor	r4, r4, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r8
#endif
#else
	ubfx	r2, r8, #0, #8
#endif
	ldr	r5, [r0, r5, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r11, #8
	lsr	r6, r6, #24
#else
	uxtb	r6, r11, ror #16
#endif
#else
	ubfx	r6, r11, #16, #8
#endif
	eor	r5, r5, r7, ror #24
	lsr	r7, r10, #24
	eor	r5, r5, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r8, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r8, ror #8
#endif
#else
	ubfx	lr, r8, #8, #8
#endif
	eor	r5, r5, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r9
#endif
#else
	ubfx	r2, r9, #0, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r10, #24
	lsr	r10, r10, #24
#else
	uxtb	r10, r10
#endif
#else
	ubfx	r10, r10, #0, #8
#endif
	eor	r6, r6, r7, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #8
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #16
#endif
#else
	ubfx	r7, r8, #16, #8
#endif
	eor	r6, r6, lr, ror #8
	lsr	lr, r11, #24
	eor	r6, r6, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r9, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r9, ror #8
#endif
#else
	ubfx	r2, r9, #8, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r7, [r0, r7, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r10, ror #24
	ldm	r3!, {r8, r9, r10, r11}
	eor	r7, r7, lr, ror #24
	eor	r7, r7, r2, ror #8
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	subs	r1, r1, #1
	bne	L_AES_GCM_encrypt_block_nr_128
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r8, r5, #8
	lsr	r8, r8, #24
#else
	uxtb	r8, r5, ror #16
#endif
#else
	ubfx	r8, r5, #16, #8
#endif
	lsr	r11, r4, #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r6, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r6, ror #8
#endif
#else
	ubfx	lr, r6, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r7, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r7
#endif
#else
	ubfx	r2, r7, #0, #8
#endif
	ldr	r8, [r0, r8, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r9, r6, #8
	lsr	r9, r9, #24
#else
	uxtb	r9, r6, ror #16
#endif
#else
	ubfx	r9, r6, #16, #8
#endif
	eor	r8, r8, r11, ror #24
	lsr	r11, r5, #24
	eor	r8, r8, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r7, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r7, ror #8
#endif
#else
	ubfx	lr, r7, #8, #8
#endif
	eor	r8, r8, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r4, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r4
#endif
#else
	ubfx	r2, r4, #0, #8
#endif
	ldr	r9, [r0, r9, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r10, r7, #8
	lsr	r10, r10, #24
#else
	uxtb	r10, r7, ror #16
#endif
#else
	ubfx	r10, r7, #16, #8
#endif
	eor	r9, r9, r11, ror #24
	lsr	r11, r6, #24
	eor	r9, r9, lr, ror #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r4, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r4, ror #8
#endif
#else
	ubfx	lr, r4, #8, #8
#endif
	eor	r9, r9, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #24
	lsr	r2, r2, #24
#else
	uxtb	r2, r5
#endif
#else
	ubfx	r2, r5, #0, #8
#endif
	ldr	r10, [r0, r10, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r6, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r6
#endif
#else
	ubfx	r6, r6, #0, #8
#endif
	eor	r10, r10, r11, ror #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r11, r4, #8
	lsr	r11, r11, #24
#else
	uxtb	r11, r4, ror #16
#endif
#else
	ubfx	r11, r4, #16, #8
#endif
	eor	r10, r10, lr, ror #8
	lsr	lr, r7, #24
	eor	r10, r10, r2, ror #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r5, #16
	lsr	r2, r2, #24
#else
	uxtb	r2, r5, ror #8
#endif
#else
	ubfx	r2, r5, #8, #8
#endif
	ldr	r6, [r0, r6, lsl #2]
	ldr	lr, [r0, lr, lsl #2]
	ldr	r11, [r0, r11, lsl #2]
	ldr	r2, [r0, r2, lsl #2]
	eor	lr, lr, r6, ror #24
	ldm	r3!, {r4, r5, r6, r7}
	eor	r11, r11, lr, ror #24
	eor	r11, r11, r2, ror #8
	#   XOR in Key Schedule
	eor	r8, r8, r4
	eor	r9, r9, r5
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r4, r11, #24
	lsr	r4, r4, #24
#else
	uxtb	r4, r11
#endif
#else
	ubfx	r4, r11, #0, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r10, ror #8
#endif
#else
	ubfx	r7, r10, #8, #8
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #16
#endif
#else
	ubfx	lr, r9, #16, #8
#endif
	lsr	r2, r8, #24
	ldrb	r4, [r0, r4, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r5, r8, #24
	lsr	r5, r5, #24
#else
	uxtb	r5, r8
#endif
#else
	ubfx	r5, r8, #0, #8
#endif
	eor	r4, r4, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r11, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r11, ror #8
#endif
#else
	ubfx	r7, r11, #8, #8
#endif
	eor	r4, r4, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r10, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r10, ror #16
#endif
#else
	ubfx	lr, r10, #16, #8
#endif
	eor	r4, r4, r2, lsl #24
	lsr	r2, r9, #24
	ldrb	r5, [r0, r5, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r6, r9, #24
	lsr	r6, r6, #24
#else
	uxtb	r6, r9
#endif
#else
	ubfx	r6, r9, #0, #8
#endif
	eor	r5, r5, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r8, #16
	lsr	r7, r7, #24
#else
	uxtb	r7, r8, ror #8
#endif
#else
	ubfx	r7, r8, #8, #8
#endif
	eor	r5, r5, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r11, #8
	lsr	lr, lr, #24
#else
	uxtb	lr, r11, ror #16
#endif
#else
	ubfx	lr, r11, #16, #8
#endif
	eor	r5, r5, r2, lsl #24
	lsr	r2, r10, #24
	ldrb	r6, [r0, r6, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	lsr	r11, r11, #24
	eor	r6, r6, r7, lsl #8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r7, r10, #24
	lsr	r7, r7, #24
#else
	uxtb	r7, r10
#endif
#else
	ubfx	r7, r10, #0, #8
#endif
	eor	r6, r6, lr, lsl #16
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	lr, r9, #16
	lsr	lr, lr, #24
#else
	uxtb	lr, r9, ror #8
#endif
#else
	ubfx	lr, r9, #8, #8
#endif
	eor	r6, r6, r2, lsl #24
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	lsl	r2, r8, #8
	lsr	r2, r2, #24
#else
	uxtb	r2, r8, ror #16
#endif
#else
	ubfx	r2, r8, #16, #8
#endif
	ldrb	r11, [r0, r11, lsl #2]
	ldrb	r7, [r0, r7, lsl #2]
	ldrb	lr, [r0, lr, lsl #2]
	ldrb	r2, [r0, r2, lsl #2]
	eor	lr, lr, r11, lsl #16
	ldm	r3, {r8, r9, r10, r11}
	eor	r7, r7, lr, lsl #8
	eor	r7, r7, r2, lsl #16
	#   XOR in Key Schedule
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
#endif /* !WOLFSSL_ARMASM_AES_BLOCK_INLINE */
	pop	{r1, r2, lr}
	ldr	r3, [sp]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r8, r4, r4, ror #16
	eor	r9, r5, r5, ror #16
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r8, r8, #0xff0000
	bic	r9, r9, #0xff0000
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r4, r4, r8, lsr #8
	eor	r5, r5, r9, lsr #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	ldr	r8, [lr]
	ldr	r9, [lr, #4]
	ldr	r10, [lr, #8]
	ldr	r11, [lr, #12]
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r6, r6, r10
	eor	r7, r7, r11
	ldr	r8, [sp, #4]
	str	r4, [r1]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r7, [r1, #12]
	ldm	r8, {r4, r5, r6, r7}
	subs	r2, r2, #16
	add	lr, lr, #16
	add	r1, r1, #16
	bne	L_AES_GCM_encrypt_loop_block_128
L_AES_GCM_encrypt_end:
	pop	{r3, r8}
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	eor	r10, r4, r4, ror #16
	eor	r11, r5, r5, ror #16
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r4, r4, #8
	ror	r5, r5, #8
	eor	r4, r4, r10, lsr #8
	eor	r5, r5, r11, lsr #8
	eor	r10, r6, r6, ror #16
	eor	r11, r7, r7, ror #16
	bic	r10, r10, #0xff0000
	bic	r11, r11, #0xff0000
	ror	r6, r6, #8
	ror	r7, r7, #8
	eor	r6, r6, r10, lsr #8
	eor	r7, r7, r11, lsr #8
#else
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	stm	r8, {r4, r5, r6, r7}
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	AES_GCM_encrypt,.-AES_GCM_encrypt
#endif /* HAVE_AESGCM */
#endif /* !WOLFSSL_ARMASM_NO_HW_CRYPTO */
#endif /* !NO_AES */
#endif /* !__aarch64__ && !WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
