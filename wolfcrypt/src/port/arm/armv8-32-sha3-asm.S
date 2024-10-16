/* armv8-32-sha3-asm
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
 *   ruby ./sha3/sha3.rb arm32 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-32-sha3-asm.S
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_ARMASM
#if !defined(__aarch64__) && !defined(WOLFSSL_ARMASM_THUMB2)
#ifndef WOLFSSL_ARMASM_INLINE
#ifdef WOLFSSL_SHA3
#ifndef WOLFSSL_ARMASM_NO_NEON
	.text
	.type	L_sha3_arm2_neon_rt, %object
	.size	L_sha3_arm2_neon_rt, 192
	.align	4
L_sha3_arm2_neon_rt:
	.word	0x1
	.word	0x0
	.word	0x8082
	.word	0x0
	.word	0x808a
	.word	0x80000000
	.word	0x80008000
	.word	0x80000000
	.word	0x808b
	.word	0x0
	.word	0x80000001
	.word	0x0
	.word	0x80008081
	.word	0x80000000
	.word	0x8009
	.word	0x80000000
	.word	0x8a
	.word	0x0
	.word	0x88
	.word	0x0
	.word	0x80008009
	.word	0x0
	.word	0x8000000a
	.word	0x0
	.word	0x8000808b
	.word	0x0
	.word	0x8b
	.word	0x80000000
	.word	0x8089
	.word	0x80000000
	.word	0x8003
	.word	0x80000000
	.word	0x8002
	.word	0x80000000
	.word	0x80
	.word	0x80000000
	.word	0x800a
	.word	0x0
	.word	0x8000000a
	.word	0x80000000
	.word	0x80008081
	.word	0x80000000
	.word	0x8080
	.word	0x80000000
	.word	0x80000001
	.word	0x0
	.word	0x80008008
	.word	0x80000000
	.text
	.align	4
	.globl	BlockSha3
	.type	BlockSha3, %function
BlockSha3:
	vpush	{d8-d15}
	sub	sp, sp, #16
	adr	r1, L_sha3_arm2_neon_rt
	mov	r2, #24
	mov	r3, sp
	vld1.8	{d0-d3}, [r0]!
	vld1.8	{d4-d7}, [r0]!
	vld1.8	{d8-d11}, [r0]!
	vld1.8	{d12-d15}, [r0]!
	vld1.8	{d16-d19}, [r0]!
	vld1.8	{d20-d23}, [r0]!
	vld1.8	{d24}, [r0]
	sub	r0, r0, #0xc0
L_sha3_arm32_neon_begin:
	# Calc b[0..4]
	veor	d26, d0, d5
	veor	d27, d1, d6
	veor	d28, d2, d7
	veor	d29, d3, d8
	veor	d25, d4, d9
	veor	d26, d26, d10
	veor	d27, d27, d11
	veor	d28, d28, d12
	veor	d29, d29, d13
	veor	d25, d25, d14
	veor	d26, d26, d15
	veor	d27, d27, d16
	veor	d28, d28, d17
	veor	d29, d29, d18
	veor	d25, d25, d19
	veor	d26, d26, d20
	veor	d27, d27, d21
	veor	d28, d28, d22
	veor	d29, d29, d23
	veor	d25, d25, d24
	vst1.8	{d25, d26}, [r3]
	# Calc t[0..4] and XOR into s[i*5..i*5+4]
	# t[0]
	vshr.u64	d30, d27, #63
	vshl.u64	d31, d27, #1
	veor	d25, d25, d30
	veor	d25, d25, d31
	# t[1]
	vshr.u64	d30, d28, #63
	vshl.u64	d31, d28, #1
	veor	d26, d26, d30
	veor	d26, d26, d31
	# t[2]
	vshr.u64	d30, d29, #63
	vshl.u64	d31, d29, #1
	veor	d27, d27, d30
	veor	d27, d27, d31
	# t[3]
	vldr.8	d31, [r3]
	vshr.u64	d30, d31, #63
	vshl.u64	d31, d31, #1
	veor	d28, d28, d30
	veor	d28, d28, d31
	# t[4]
	vldr.8	d31, [r3, #8]
	vshr.u64	d30, d31, #63
	vshl.u64	d31, d31, #1
	veor	d29, d29, d30
	veor	d29, d29, d31
	sub	r3, r3, #16
	veor	d0, d0, d25
	# s[1] => s[10] (tmp)
	veor	d30, d1, d26
	vshr.u64	d31, d30, #63
	vshl.u64	d30, d30, #1
	veor	d30, d30, d31
	# s[6] => s[1]
	veor	d1, d6, d26
	vshr.u64	d31, d1, #20
	vshl.u64	d1, d1, #44
	veor	d1, d1, d31
	# s[9] => s[6]
	veor	d6, d9, d29
	vshr.u64	d31, d6, #44
	vshl.u64	d6, d6, #20
	veor	d6, d6, d31
	# s[22] => s[9]
	veor	d9, d22, d27
	vshr.u64	d31, d9, #3
	vshl.u64	d9, d9, #61
	veor	d9, d9, d31
	# s[14] => s[22]
	veor	d22, d14, d29
	vshr.u64	d31, d22, #25
	vshl.u64	d22, d22, #39
	veor	d22, d22, d31
	# s[20] => s[14]
	veor	d14, d20, d25
	vshr.u64	d31, d14, #46
	vshl.u64	d14, d14, #18
	veor	d14, d14, d31
	# s[2] => s[20]
	veor	d20, d2, d27
	vshr.u64	d31, d20, #2
	vshl.u64	d20, d20, #62
	veor	d20, d20, d31
	# s[12] => s[2]
	veor	d2, d12, d27
	vshr.u64	d31, d2, #21
	vshl.u64	d2, d2, #43
	veor	d2, d2, d31
	# s[13] => s[12]
	veor	d12, d13, d28
	vshr.u64	d31, d12, #39
	vshl.u64	d12, d12, #25
	veor	d12, d12, d31
	# s[19] => s[13]
	veor	d13, d19, d29
	vshr.u64	d31, d13, #56
	vshl.u64	d13, d13, #8
	veor	d13, d13, d31
	# s[23] => s[19]
	veor	d19, d23, d28
	vshr.u64	d31, d19, #8
	vshl.u64	d19, d19, #56
	veor	d19, d19, d31
	# s[15] => s[23]
	veor	d23, d15, d25
	vshr.u64	d31, d23, #23
	vshl.u64	d23, d23, #41
	veor	d23, d23, d31
	# s[4] => s[15]
	veor	d15, d4, d29
	vshr.u64	d31, d15, #37
	vshl.u64	d15, d15, #27
	veor	d15, d15, d31
	# s[24] => s[4]
	veor	d4, d24, d29
	vshr.u64	d31, d4, #50
	vshl.u64	d4, d4, #14
	veor	d4, d4, d31
	# s[21] => s[24]
	veor	d24, d21, d26
	vshr.u64	d31, d24, #62
	vshl.u64	d24, d24, #2
	veor	d24, d24, d31
	# s[8] => s[21]
	veor	d21, d8, d28
	vshr.u64	d31, d21, #9
	vshl.u64	d21, d21, #55
	veor	d21, d21, d31
	# s[16] => s[8]
	veor	d8, d16, d26
	vshr.u64	d31, d8, #19
	vshl.u64	d8, d8, #45
	veor	d8, d8, d31
	# s[5] => s[16]
	veor	d16, d5, d25
	vshr.u64	d31, d16, #28
	vshl.u64	d16, d16, #36
	veor	d16, d16, d31
	# s[3] => s[5]
	veor	d5, d3, d28
	vshr.u64	d31, d5, #36
	vshl.u64	d5, d5, #28
	veor	d5, d5, d31
	# s[18] => s[3]
	veor	d3, d18, d28
	vshr.u64	d31, d3, #43
	vshl.u64	d3, d3, #21
	veor	d3, d3, d31
	# s[17] => s[18]
	veor	d18, d17, d27
	vshr.u64	d31, d18, #49
	vshl.u64	d18, d18, #15
	veor	d18, d18, d31
	# s[11] => s[17]
	veor	d17, d11, d26
	vshr.u64	d31, d17, #54
	vshl.u64	d17, d17, #10
	veor	d17, d17, d31
	# s[7] => s[11]
	veor	d11, d7, d27
	vshr.u64	d31, d11, #58
	vshl.u64	d11, d11, #6
	veor	d11, d11, d31
	# s[10] => s[7]
	veor	d7, d10, d25
	vshr.u64	d31, d7, #61
	vshl.u64	d7, d7, #3
	veor	d7, d7, d31
	# Row Mix
	vmov	d25, d0
	vmov	d26, d1
	vbic	d31, d2, d26
	veor	d0, d25, d31
	vbic	d31, d3, d2
	veor	d1, d26, d31
	vbic	d31, d4, d3
	veor	d2, d2, d31
	vbic	d31, d25, d4
	veor	d3, d3, d31
	vbic	d31, d26, d25
	veor	d4, d4, d31
	vmov	d25, d5
	vmov	d26, d6
	vbic	d31, d7, d26
	veor	d5, d25, d31
	vbic	d31, d8, d7
	veor	d6, d26, d31
	vbic	d31, d9, d8
	veor	d7, d7, d31
	vbic	d31, d25, d9
	veor	d8, d8, d31
	vbic	d31, d26, d25
	veor	d9, d9, d31
	vmov	d26, d11
	vbic	d31, d12, d26
	veor	d10, d30, d31
	vbic	d31, d13, d12
	veor	d11, d26, d31
	vbic	d31, d14, d13
	veor	d12, d12, d31
	vbic	d31, d30, d14
	veor	d13, d13, d31
	vbic	d31, d26, d30
	veor	d14, d14, d31
	vmov	d25, d15
	vmov	d26, d16
	vbic	d31, d17, d26
	veor	d15, d25, d31
	vbic	d31, d18, d17
	veor	d16, d26, d31
	vbic	d31, d19, d18
	veor	d17, d17, d31
	vbic	d31, d25, d19
	veor	d18, d18, d31
	vbic	d31, d26, d25
	veor	d19, d19, d31
	vmov	d25, d20
	vmov	d26, d21
	vbic	d31, d22, d26
	veor	d20, d25, d31
	vbic	d31, d23, d22
	veor	d21, d26, d31
	vbic	d31, d24, d23
	veor	d22, d22, d31
	vbic	d31, d25, d24
	veor	d23, d23, d31
	vbic	d31, d26, d25
	veor	d24, d24, d31
	vld1.8	{d30}, [r1]!
	subs	r2, r2, #1
	veor	d0, d0, d30
	bne	L_sha3_arm32_neon_begin
	vst1.8	{d0-d3}, [r0]!
	vst1.8	{d4-d7}, [r0]!
	vst1.8	{d8-d11}, [r0]!
	vst1.8	{d12-d15}, [r0]!
	vst1.8	{d16-d19}, [r0]!
	vst1.8	{d20-d23}, [r0]!
	vst1.8	{d24}, [r0]
	add	sp, sp, #16
	vpop	{d8-d15}
	bx	lr
	.size	BlockSha3,.-BlockSha3
#endif /* WOLFSSL_ARMASM_NO_NEON */
#ifdef WOLFSSL_ARMASM_NO_NEON
	.text
	.type	L_sha3_arm2_rt, %object
	.size	L_sha3_arm2_rt, 192
	.align	4
L_sha3_arm2_rt:
	.word	0x1
	.word	0x0
	.word	0x8082
	.word	0x0
	.word	0x808a
	.word	0x80000000
	.word	0x80008000
	.word	0x80000000
	.word	0x808b
	.word	0x0
	.word	0x80000001
	.word	0x0
	.word	0x80008081
	.word	0x80000000
	.word	0x8009
	.word	0x80000000
	.word	0x8a
	.word	0x0
	.word	0x88
	.word	0x0
	.word	0x80008009
	.word	0x0
	.word	0x8000000a
	.word	0x0
	.word	0x8000808b
	.word	0x0
	.word	0x8b
	.word	0x80000000
	.word	0x8089
	.word	0x80000000
	.word	0x8003
	.word	0x80000000
	.word	0x8002
	.word	0x80000000
	.word	0x80
	.word	0x80000000
	.word	0x800a
	.word	0x0
	.word	0x8000000a
	.word	0x80000000
	.word	0x80008081
	.word	0x80000000
	.word	0x8080
	.word	0x80000000
	.word	0x80000001
	.word	0x0
	.word	0x80008008
	.word	0x80000000
	.text
	.align	4
	.globl	BlockSha3
	.type	BlockSha3, %function
BlockSha3:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #0xcc
	adr	r1, L_sha3_arm2_rt
	mov	r2, #12
L_sha3_arm32_begin:
	str	r2, [sp, #200]
	# Round even
	# Calc b[4]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #72]
	ldr	r7, [r0, #76]
#else
	ldrd	r6, r7, [r0, #72]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #112]
	ldr	r9, [r0, #116]
#else
	ldrd	r8, r9, [r0, #112]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r0, #152]
	ldr	r11, [r0, #156]
#else
	ldrd	r10, r11, [r0, #152]
#endif
	ldr	r12, [r0, #192]
	ldr	lr, [r0, #196]
	eor	r2, r4, r6
	eor	r3, r5, r7
	eor	r2, r2, r8
	eor	r3, r3, r9
	eor	r2, r2, r10
	eor	r3, r3, r11
	eor	r2, r2, r12
	eor	r3, r3, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r2, [sp, #32]
	str	r3, [sp, #36]
#else
	strd	r2, r3, [sp, #32]
#endif
	# Calc b[1]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #48]
	ldr	r7, [r0, #52]
#else
	ldrd	r6, r7, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #88]
	ldr	r9, [r0, #92]
#else
	ldrd	r8, r9, [r0, #88]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r0, #128]
	ldr	r11, [r0, #132]
#else
	ldrd	r10, r11, [r0, #128]
#endif
	ldr	r12, [r0, #168]
	ldr	lr, [r0, #172]
	eor	r4, r4, r6
	eor	r5, r5, r7
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r4, r4, r10
	eor	r5, r5, r11
	eor	r4, r4, r12
	eor	r5, r5, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #8]
	str	r5, [sp, #12]
#else
	strd	r4, r5, [sp, #8]
#endif
	# Calc t[0]
	eor	r2, r2, r5, lsr #31
	eor	r3, r3, r4, lsr #31
	eor	r2, r2, r4, lsl #1
	eor	r3, r3, r5, lsl #1
	# Calc b[0] and XOR t[0] into s[x*5+0]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0]
	ldr	r5, [r0, #4]
#else
	ldrd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #40]
	ldr	r7, [r0, #44]
#else
	ldrd	r6, r7, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #80]
	ldr	r9, [r0, #84]
#else
	ldrd	r8, r9, [r0, #80]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r0, #120]
	ldr	r11, [r0, #124]
#else
	ldrd	r10, r11, [r0, #120]
#endif
	eor	r12, r4, r6
	eor	lr, r5, r7
	eor	r12, r12, r8
	eor	lr, lr, r9
	eor	r12, r12, r10
	eor	lr, lr, r11
	eor	r4, r4, r2
	eor	r5, r5, r3
	eor	r6, r6, r2
	eor	r7, r7, r3
	eor	r8, r8, r2
	eor	r9, r9, r3
	eor	r10, r10, r2
	eor	r11, r11, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0]
	str	r5, [r0, #4]
#else
	strd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #40]
	str	r7, [r0, #44]
#else
	strd	r6, r7, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #80]
	str	r9, [r0, #84]
#else
	strd	r8, r9, [r0, #80]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [r0, #120]
	str	r11, [r0, #124]
#else
	strd	r10, r11, [r0, #120]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r0, #160]
	ldr	r11, [r0, #164]
#else
	ldrd	r10, r11, [r0, #160]
#endif
	eor	r12, r12, r10
	eor	lr, lr, r11
	eor	r10, r10, r2
	eor	r11, r11, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [r0, #160]
	str	r11, [r0, #164]
#else
	strd	r10, r11, [r0, #160]
#endif
	str	r12, [sp]
	str	lr, [sp, #4]
	# Calc b[3]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #64]
	ldr	r7, [r0, #68]
#else
	ldrd	r6, r7, [r0, #64]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #104]
	ldr	r9, [r0, #108]
#else
	ldrd	r8, r9, [r0, #104]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r0, #144]
	ldr	r11, [r0, #148]
#else
	ldrd	r10, r11, [r0, #144]
#endif
	ldr	r12, [r0, #184]
	ldr	lr, [r0, #188]
	eor	r4, r4, r6
	eor	r5, r5, r7
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r4, r4, r10
	eor	r5, r5, r11
	eor	r4, r4, r12
	eor	r5, r5, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #24]
	str	r5, [sp, #28]
#else
	strd	r4, r5, [sp, #24]
#endif
	# Calc t[2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [sp, #8]
	ldr	r3, [sp, #12]
#else
	ldrd	r2, r3, [sp, #8]
#endif
	eor	r2, r2, r5, lsr #31
	eor	r3, r3, r4, lsr #31
	eor	r2, r2, r4, lsl #1
	eor	r3, r3, r5, lsl #1
	# Calc b[2] and XOR t[2] into s[x*5+2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #56]
	ldr	r7, [r0, #60]
#else
	ldrd	r6, r7, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #96]
	ldr	r9, [r0, #100]
#else
	ldrd	r8, r9, [r0, #96]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r0, #136]
	ldr	r11, [r0, #140]
#else
	ldrd	r10, r11, [r0, #136]
#endif
	eor	r12, r4, r6
	eor	lr, r5, r7
	eor	r12, r12, r8
	eor	lr, lr, r9
	eor	r12, r12, r10
	eor	lr, lr, r11
	eor	r4, r4, r2
	eor	r5, r5, r3
	eor	r6, r6, r2
	eor	r7, r7, r3
	eor	r8, r8, r2
	eor	r9, r9, r3
	eor	r10, r10, r2
	eor	r11, r11, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #16]
	str	r5, [r0, #20]
#else
	strd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #56]
	str	r7, [r0, #60]
#else
	strd	r6, r7, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #96]
	str	r9, [r0, #100]
#else
	strd	r8, r9, [r0, #96]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [r0, #136]
	str	r11, [r0, #140]
#else
	strd	r10, r11, [r0, #136]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r0, #176]
	ldr	r11, [r0, #180]
#else
	ldrd	r10, r11, [r0, #176]
#endif
	eor	r12, r12, r10
	eor	lr, lr, r11
	eor	r10, r10, r2
	eor	r11, r11, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [r0, #176]
	str	r11, [r0, #180]
#else
	strd	r10, r11, [r0, #176]
#endif
	str	r12, [sp, #16]
	str	lr, [sp, #20]
	# Calc t[1]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [sp]
	ldr	r3, [sp, #4]
#else
	ldrd	r2, r3, [sp]
#endif
	eor	r2, r2, lr, lsr #31
	eor	r3, r3, r12, lsr #31
	eor	r2, r2, r12, lsl #1
	eor	r3, r3, lr, lsl #1
	# XOR t[1] into s[x*5+1]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #48]
	ldr	r7, [r0, #52]
#else
	ldrd	r6, r7, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #88]
	ldr	r9, [r0, #92]
#else
	ldrd	r8, r9, [r0, #88]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r0, #128]
	ldr	r11, [r0, #132]
#else
	ldrd	r10, r11, [r0, #128]
#endif
	ldr	r12, [r0, #168]
	ldr	lr, [r0, #172]
	eor	r4, r4, r2
	eor	r5, r5, r3
	eor	r6, r6, r2
	eor	r7, r7, r3
	eor	r8, r8, r2
	eor	r9, r9, r3
	eor	r10, r10, r2
	eor	r11, r11, r3
	eor	r12, r12, r2
	eor	lr, lr, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #8]
	str	r5, [r0, #12]
#else
	strd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #48]
	str	r7, [r0, #52]
#else
	strd	r6, r7, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #88]
	str	r9, [r0, #92]
#else
	strd	r8, r9, [r0, #88]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [r0, #128]
	str	r11, [r0, #132]
#else
	strd	r10, r11, [r0, #128]
#endif
	str	r12, [r0, #168]
	str	lr, [r0, #172]
	# Calc t[3]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [sp, #16]
	ldr	r3, [sp, #20]
#else
	ldrd	r2, r3, [sp, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #32]
	ldr	r5, [sp, #36]
#else
	ldrd	r4, r5, [sp, #32]
#endif
	eor	r2, r2, r5, lsr #31
	eor	r3, r3, r4, lsr #31
	eor	r2, r2, r4, lsl #1
	eor	r3, r3, r5, lsl #1
	# XOR t[3] into s[x*5+3]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #64]
	ldr	r7, [r0, #68]
#else
	ldrd	r6, r7, [r0, #64]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #104]
	ldr	r9, [r0, #108]
#else
	ldrd	r8, r9, [r0, #104]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r0, #144]
	ldr	r11, [r0, #148]
#else
	ldrd	r10, r11, [r0, #144]
#endif
	ldr	r12, [r0, #184]
	ldr	lr, [r0, #188]
	eor	r4, r4, r2
	eor	r5, r5, r3
	eor	r6, r6, r2
	eor	r7, r7, r3
	eor	r8, r8, r2
	eor	r9, r9, r3
	eor	r10, r10, r2
	eor	r11, r11, r3
	eor	r12, r12, r2
	eor	lr, lr, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #24]
	str	r5, [r0, #28]
#else
	strd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #64]
	str	r7, [r0, #68]
#else
	strd	r6, r7, [r0, #64]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #104]
	str	r9, [r0, #108]
#else
	strd	r8, r9, [r0, #104]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [r0, #144]
	str	r11, [r0, #148]
#else
	strd	r10, r11, [r0, #144]
#endif
	str	r12, [r0, #184]
	str	lr, [r0, #188]
	# Calc t[4]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [sp, #24]
	ldr	r3, [sp, #28]
#else
	ldrd	r2, r3, [sp, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp]
	ldr	r5, [sp, #4]
#else
	ldrd	r4, r5, [sp]
#endif
	eor	r2, r2, r5, lsr #31
	eor	r3, r3, r4, lsr #31
	eor	r2, r2, r4, lsl #1
	eor	r3, r3, r5, lsl #1
	# XOR t[4] into s[x*5+4]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #72]
	ldr	r7, [r0, #76]
#else
	ldrd	r6, r7, [r0, #72]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #112]
	ldr	r9, [r0, #116]
#else
	ldrd	r8, r9, [r0, #112]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r0, #152]
	ldr	r11, [r0, #156]
#else
	ldrd	r10, r11, [r0, #152]
#endif
	ldr	r12, [r0, #192]
	ldr	lr, [r0, #196]
	eor	r4, r4, r2
	eor	r5, r5, r3
	eor	r6, r6, r2
	eor	r7, r7, r3
	eor	r8, r8, r2
	eor	r9, r9, r3
	eor	r10, r10, r2
	eor	r11, r11, r3
	eor	r12, r12, r2
	eor	lr, lr, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #32]
	str	r5, [r0, #36]
#else
	strd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #72]
	str	r7, [r0, #76]
#else
	strd	r6, r7, [r0, #72]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #112]
	str	r9, [r0, #116]
#else
	strd	r8, r9, [r0, #112]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [r0, #152]
	str	r11, [r0, #156]
#else
	strd	r10, r11, [r0, #152]
#endif
	str	r12, [r0, #192]
	str	lr, [r0, #196]
	# Row Mix
	# Row 0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [r0]
	ldr	r3, [r0, #4]
#else
	ldrd	r2, r3, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #96]
	ldr	r7, [r0, #100]
#else
	ldrd	r6, r7, [r0, #96]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #144]
	ldr	r9, [r0, #148]
#else
	ldrd	r8, r9, [r0, #144]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r0, #192]
	ldr	r11, [r0, #196]
#else
	ldrd	r10, r11, [r0, #192]
#endif
	# s[1] <<< 44
	mov	lr, r4
	lsr	r12, r5, #20
	lsr	r4, r4, #20
	orr	r4, r4, r5, lsl #12
	orr	r5, r12, lr, lsl #12
	# s[2] <<< 43
	mov	lr, r6
	lsr	r12, r7, #21
	lsr	r6, r6, #21
	orr	r6, r6, r7, lsl #11
	orr	r7, r12, lr, lsl #11
	# s[3] <<< 21
	lsr	r12, r9, #11
	lsr	lr, r8, #11
	orr	r8, r12, r8, lsl #21
	orr	r9, lr, r9, lsl #21
	# s[4] <<< 14
	lsr	r12, r11, #18
	lsr	lr, r10, #18
	orr	r10, r12, r10, lsl #14
	orr	r11, lr, r11, lsl #14
	bic	r12, r8, r6
	bic	lr, r9, r7
	eor	r12, r12, r4
	eor	lr, lr, r5
	str	r12, [sp, #8]
	str	lr, [sp, #12]
	bic	r12, r10, r8
	bic	lr, r11, r9
	eor	r12, r12, r6
	eor	lr, lr, r7
	str	r12, [sp, #16]
	str	lr, [sp, #20]
	bic	r12, r2, r10
	bic	lr, r3, r11
	eor	r12, r12, r8
	eor	lr, lr, r9
	str	r12, [sp, #24]
	str	lr, [sp, #28]
	bic	r12, r4, r2
	bic	lr, r5, r3
	eor	r12, r12, r10
	eor	lr, lr, r11
	str	r12, [sp, #32]
	str	lr, [sp, #36]
	# Get constant
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1]
	ldr	r11, [r1, #4]
#else
	ldrd	r10, r11, [r1]
#endif
	add	r1, r1, #8
	bic	r12, r6, r4
	bic	lr, r7, r5
	eor	r12, r12, r2
	eor	lr, lr, r3
	# XOR in constant
	eor	r12, r12, r10
	eor	lr, lr, r11
	str	r12, [sp]
	str	lr, [sp, #4]
	# Row 1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [r0, #24]
	ldr	r3, [r0, #28]
#else
	ldrd	r2, r3, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #72]
	ldr	r5, [r0, #76]
#else
	ldrd	r4, r5, [r0, #72]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #80]
	ldr	r7, [r0, #84]
#else
	ldrd	r6, r7, [r0, #80]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #128]
	ldr	r9, [r0, #132]
#else
	ldrd	r8, r9, [r0, #128]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r0, #176]
	ldr	r11, [r0, #180]
#else
	ldrd	r10, r11, [r0, #176]
#endif
	# s[0] <<< 28
	lsr	r12, r3, #4
	lsr	lr, r2, #4
	orr	r2, r12, r2, lsl #28
	orr	r3, lr, r3, lsl #28
	# s[1] <<< 20
	lsr	r12, r5, #12
	lsr	lr, r4, #12
	orr	r4, r12, r4, lsl #20
	orr	r5, lr, r5, lsl #20
	# s[2] <<< 3
	lsr	r12, r7, #29
	lsr	lr, r6, #29
	orr	r6, r12, r6, lsl #3
	orr	r7, lr, r7, lsl #3
	# s[3] <<< 45
	mov	lr, r8
	lsr	r12, r9, #19
	lsr	r8, r8, #19
	orr	r8, r8, r9, lsl #13
	orr	r9, r12, lr, lsl #13
	# s[4] <<< 61
	mov	lr, r10
	lsr	r12, r11, #3
	lsr	r10, r10, #3
	orr	r10, r10, r11, lsl #29
	orr	r11, r12, lr, lsl #29
	bic	r12, r8, r6
	bic	lr, r9, r7
	eor	r12, r12, r4
	eor	lr, lr, r5
	str	r12, [sp, #48]
	str	lr, [sp, #52]
	bic	r12, r10, r8
	bic	lr, r11, r9
	eor	r12, r12, r6
	eor	lr, lr, r7
	str	r12, [sp, #56]
	str	lr, [sp, #60]
	bic	r12, r2, r10
	bic	lr, r3, r11
	eor	r12, r12, r8
	eor	lr, lr, r9
	str	r12, [sp, #64]
	str	lr, [sp, #68]
	bic	r12, r4, r2
	bic	lr, r5, r3
	eor	r12, r12, r10
	eor	lr, lr, r11
	str	r12, [sp, #72]
	str	lr, [sp, #76]
	bic	r12, r6, r4
	bic	lr, r7, r5
	eor	r12, r12, r2
	eor	lr, lr, r3
	str	r12, [sp, #40]
	str	lr, [sp, #44]
	# Row 2
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [r0, #8]
	ldr	r3, [r0, #12]
#else
	ldrd	r2, r3, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #104]
	ldr	r7, [r0, #108]
#else
	ldrd	r6, r7, [r0, #104]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #152]
	ldr	r9, [r0, #156]
#else
	ldrd	r8, r9, [r0, #152]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r0, #160]
	ldr	r11, [r0, #164]
#else
	ldrd	r10, r11, [r0, #160]
#endif
	# s[0] <<< 1
	lsr	r12, r3, #31
	lsr	lr, r2, #31
	orr	r2, r12, r2, lsl #1
	orr	r3, lr, r3, lsl #1
	# s[1] <<< 6
	lsr	r12, r5, #26
	lsr	lr, r4, #26
	orr	r4, r12, r4, lsl #6
	orr	r5, lr, r5, lsl #6
	# s[2] <<< 25
	lsr	r12, r7, #7
	lsr	lr, r6, #7
	orr	r6, r12, r6, lsl #25
	orr	r7, lr, r7, lsl #25
	# s[3] <<< 8
	lsr	r12, r9, #24
	lsr	lr, r8, #24
	orr	r8, r12, r8, lsl #8
	orr	r9, lr, r9, lsl #8
	# s[4] <<< 18
	lsr	r12, r11, #14
	lsr	lr, r10, #14
	orr	r10, r12, r10, lsl #18
	orr	r11, lr, r11, lsl #18
	bic	r12, r8, r6
	bic	lr, r9, r7
	eor	r12, r12, r4
	eor	lr, lr, r5
	str	r12, [sp, #88]
	str	lr, [sp, #92]
	bic	r12, r10, r8
	bic	lr, r11, r9
	eor	r12, r12, r6
	eor	lr, lr, r7
	str	r12, [sp, #96]
	str	lr, [sp, #100]
	bic	r12, r2, r10
	bic	lr, r3, r11
	eor	r12, r12, r8
	eor	lr, lr, r9
	str	r12, [sp, #104]
	str	lr, [sp, #108]
	bic	r12, r4, r2
	bic	lr, r5, r3
	eor	r12, r12, r10
	eor	lr, lr, r11
	str	r12, [sp, #112]
	str	lr, [sp, #116]
	bic	r12, r6, r4
	bic	lr, r7, r5
	eor	r12, r12, r2
	eor	lr, lr, r3
	str	r12, [sp, #80]
	str	lr, [sp, #84]
	# Row 3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [r0, #32]
	ldr	r3, [r0, #36]
#else
	ldrd	r2, r3, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #88]
	ldr	r7, [r0, #92]
#else
	ldrd	r6, r7, [r0, #88]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #136]
	ldr	r9, [r0, #140]
#else
	ldrd	r8, r9, [r0, #136]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r0, #184]
	ldr	r11, [r0, #188]
#else
	ldrd	r10, r11, [r0, #184]
#endif
	# s[0] <<< 27
	lsr	r12, r3, #5
	lsr	lr, r2, #5
	orr	r2, r12, r2, lsl #27
	orr	r3, lr, r3, lsl #27
	# s[1] <<< 36
	mov	lr, r4
	lsr	r12, r5, #28
	lsr	r4, r4, #28
	orr	r4, r4, r5, lsl #4
	orr	r5, r12, lr, lsl #4
	# s[2] <<< 10
	lsr	r12, r7, #22
	lsr	lr, r6, #22
	orr	r6, r12, r6, lsl #10
	orr	r7, lr, r7, lsl #10
	# s[3] <<< 15
	lsr	r12, r9, #17
	lsr	lr, r8, #17
	orr	r8, r12, r8, lsl #15
	orr	r9, lr, r9, lsl #15
	# s[4] <<< 56
	mov	lr, r10
	lsr	r12, r11, #8
	lsr	r10, r10, #8
	orr	r10, r10, r11, lsl #24
	orr	r11, r12, lr, lsl #24
	bic	r12, r8, r6
	bic	lr, r9, r7
	eor	r12, r12, r4
	eor	lr, lr, r5
	str	r12, [sp, #128]
	str	lr, [sp, #132]
	bic	r12, r10, r8
	bic	lr, r11, r9
	eor	r12, r12, r6
	eor	lr, lr, r7
	str	r12, [sp, #136]
	str	lr, [sp, #140]
	bic	r12, r2, r10
	bic	lr, r3, r11
	eor	r12, r12, r8
	eor	lr, lr, r9
	str	r12, [sp, #144]
	str	lr, [sp, #148]
	bic	r12, r4, r2
	bic	lr, r5, r3
	eor	r12, r12, r10
	eor	lr, lr, r11
	str	r12, [sp, #152]
	str	lr, [sp, #156]
	bic	r12, r6, r4
	bic	lr, r7, r5
	eor	r12, r12, r2
	eor	lr, lr, r3
	str	r12, [sp, #120]
	str	lr, [sp, #124]
	# Row 4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [r0, #16]
	ldr	r3, [r0, #20]
#else
	ldrd	r2, r3, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #64]
	ldr	r5, [r0, #68]
#else
	ldrd	r4, r5, [r0, #64]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #112]
	ldr	r7, [r0, #116]
#else
	ldrd	r6, r7, [r0, #112]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #120]
	ldr	r9, [r0, #124]
#else
	ldrd	r8, r9, [r0, #120]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r0, #168]
	ldr	r11, [r0, #172]
#else
	ldrd	r10, r11, [r0, #168]
#endif
	# s[0] <<< 62
	mov	lr, r2
	lsr	r12, r3, #2
	lsr	r2, r2, #2
	orr	r2, r2, r3, lsl #30
	orr	r3, r12, lr, lsl #30
	# s[1] <<< 55
	mov	lr, r4
	lsr	r12, r5, #9
	lsr	r4, r4, #9
	orr	r4, r4, r5, lsl #23
	orr	r5, r12, lr, lsl #23
	# s[2] <<< 39
	mov	lr, r6
	lsr	r12, r7, #25
	lsr	r6, r6, #25
	orr	r6, r6, r7, lsl #7
	orr	r7, r12, lr, lsl #7
	# s[3] <<< 41
	mov	lr, r8
	lsr	r12, r9, #23
	lsr	r8, r8, #23
	orr	r8, r8, r9, lsl #9
	orr	r9, r12, lr, lsl #9
	# s[4] <<< 2
	lsr	r12, r11, #30
	lsr	lr, r10, #30
	orr	r10, r12, r10, lsl #2
	orr	r11, lr, r11, lsl #2
	bic	r12, r8, r6
	bic	lr, r9, r7
	eor	r12, r12, r4
	eor	lr, lr, r5
	str	r12, [sp, #168]
	str	lr, [sp, #172]
	bic	r12, r10, r8
	bic	lr, r11, r9
	eor	r12, r12, r6
	eor	lr, lr, r7
	str	r12, [sp, #176]
	str	lr, [sp, #180]
	bic	r12, r2, r10
	bic	lr, r3, r11
	eor	r12, r12, r8
	eor	lr, lr, r9
	str	r12, [sp, #184]
	str	lr, [sp, #188]
	bic	r12, r4, r2
	bic	lr, r5, r3
	eor	r12, r12, r10
	eor	lr, lr, r11
	str	r12, [sp, #192]
	str	lr, [sp, #196]
	bic	r12, r6, r4
	bic	lr, r7, r5
	eor	r12, r12, r2
	eor	lr, lr, r3
	str	r12, [sp, #160]
	str	lr, [sp, #164]
	# Round odd
	# Calc b[4]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #32]
	ldr	r5, [sp, #36]
#else
	ldrd	r4, r5, [sp, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [sp, #72]
	ldr	r7, [sp, #76]
#else
	ldrd	r6, r7, [sp, #72]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #112]
	ldr	r9, [sp, #116]
#else
	ldrd	r8, r9, [sp, #112]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #152]
	ldr	r11, [sp, #156]
#else
	ldrd	r10, r11, [sp, #152]
#endif
	ldr	r12, [sp, #192]
	ldr	lr, [sp, #196]
	eor	r2, r4, r6
	eor	r3, r5, r7
	eor	r2, r2, r8
	eor	r3, r3, r9
	eor	r2, r2, r10
	eor	r3, r3, r11
	eor	r2, r2, r12
	eor	r3, r3, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r2, [r0, #32]
	str	r3, [r0, #36]
#else
	strd	r2, r3, [r0, #32]
#endif
	# Calc b[1]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #8]
	ldr	r5, [sp, #12]
#else
	ldrd	r4, r5, [sp, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [sp, #48]
	ldr	r7, [sp, #52]
#else
	ldrd	r6, r7, [sp, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #88]
	ldr	r9, [sp, #92]
#else
	ldrd	r8, r9, [sp, #88]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #128]
	ldr	r11, [sp, #132]
#else
	ldrd	r10, r11, [sp, #128]
#endif
	ldr	r12, [sp, #168]
	ldr	lr, [sp, #172]
	eor	r4, r4, r6
	eor	r5, r5, r7
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r4, r4, r10
	eor	r5, r5, r11
	eor	r4, r4, r12
	eor	r5, r5, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #8]
	str	r5, [r0, #12]
#else
	strd	r4, r5, [r0, #8]
#endif
	# Calc t[0]
	eor	r2, r2, r5, lsr #31
	eor	r3, r3, r4, lsr #31
	eor	r2, r2, r4, lsl #1
	eor	r3, r3, r5, lsl #1
	# Calc b[0] and XOR t[0] into s[x*5+0]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp]
	ldr	r5, [sp, #4]
#else
	ldrd	r4, r5, [sp]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [sp, #40]
	ldr	r7, [sp, #44]
#else
	ldrd	r6, r7, [sp, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #80]
	ldr	r9, [sp, #84]
#else
	ldrd	r8, r9, [sp, #80]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #120]
	ldr	r11, [sp, #124]
#else
	ldrd	r10, r11, [sp, #120]
#endif
	eor	r12, r4, r6
	eor	lr, r5, r7
	eor	r12, r12, r8
	eor	lr, lr, r9
	eor	r12, r12, r10
	eor	lr, lr, r11
	eor	r4, r4, r2
	eor	r5, r5, r3
	eor	r6, r6, r2
	eor	r7, r7, r3
	eor	r8, r8, r2
	eor	r9, r9, r3
	eor	r10, r10, r2
	eor	r11, r11, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp]
	str	r5, [sp, #4]
#else
	strd	r4, r5, [sp]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [sp, #40]
	str	r7, [sp, #44]
#else
	strd	r6, r7, [sp, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [sp, #80]
	str	r9, [sp, #84]
#else
	strd	r8, r9, [sp, #80]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [sp, #120]
	str	r11, [sp, #124]
#else
	strd	r10, r11, [sp, #120]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #160]
	ldr	r11, [sp, #164]
#else
	ldrd	r10, r11, [sp, #160]
#endif
	eor	r12, r12, r10
	eor	lr, lr, r11
	eor	r10, r10, r2
	eor	r11, r11, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [sp, #160]
	str	r11, [sp, #164]
#else
	strd	r10, r11, [sp, #160]
#endif
	str	r12, [r0]
	str	lr, [r0, #4]
	# Calc b[3]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #24]
	ldr	r5, [sp, #28]
#else
	ldrd	r4, r5, [sp, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [sp, #64]
	ldr	r7, [sp, #68]
#else
	ldrd	r6, r7, [sp, #64]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #104]
	ldr	r9, [sp, #108]
#else
	ldrd	r8, r9, [sp, #104]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #144]
	ldr	r11, [sp, #148]
#else
	ldrd	r10, r11, [sp, #144]
#endif
	ldr	r12, [sp, #184]
	ldr	lr, [sp, #188]
	eor	r4, r4, r6
	eor	r5, r5, r7
	eor	r4, r4, r8
	eor	r5, r5, r9
	eor	r4, r4, r10
	eor	r5, r5, r11
	eor	r4, r4, r12
	eor	r5, r5, lr
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #24]
	str	r5, [r0, #28]
#else
	strd	r4, r5, [r0, #24]
#endif
	# Calc t[2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [r0, #8]
	ldr	r3, [r0, #12]
#else
	ldrd	r2, r3, [r0, #8]
#endif
	eor	r2, r2, r5, lsr #31
	eor	r3, r3, r4, lsr #31
	eor	r2, r2, r4, lsl #1
	eor	r3, r3, r5, lsl #1
	# Calc b[2] and XOR t[2] into s[x*5+2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #16]
	ldr	r5, [sp, #20]
#else
	ldrd	r4, r5, [sp, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [sp, #56]
	ldr	r7, [sp, #60]
#else
	ldrd	r6, r7, [sp, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #96]
	ldr	r9, [sp, #100]
#else
	ldrd	r8, r9, [sp, #96]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #136]
	ldr	r11, [sp, #140]
#else
	ldrd	r10, r11, [sp, #136]
#endif
	eor	r12, r4, r6
	eor	lr, r5, r7
	eor	r12, r12, r8
	eor	lr, lr, r9
	eor	r12, r12, r10
	eor	lr, lr, r11
	eor	r4, r4, r2
	eor	r5, r5, r3
	eor	r6, r6, r2
	eor	r7, r7, r3
	eor	r8, r8, r2
	eor	r9, r9, r3
	eor	r10, r10, r2
	eor	r11, r11, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #16]
	str	r5, [sp, #20]
#else
	strd	r4, r5, [sp, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [sp, #56]
	str	r7, [sp, #60]
#else
	strd	r6, r7, [sp, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [sp, #96]
	str	r9, [sp, #100]
#else
	strd	r8, r9, [sp, #96]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [sp, #136]
	str	r11, [sp, #140]
#else
	strd	r10, r11, [sp, #136]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #176]
	ldr	r11, [sp, #180]
#else
	ldrd	r10, r11, [sp, #176]
#endif
	eor	r12, r12, r10
	eor	lr, lr, r11
	eor	r10, r10, r2
	eor	r11, r11, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [sp, #176]
	str	r11, [sp, #180]
#else
	strd	r10, r11, [sp, #176]
#endif
	str	r12, [r0, #16]
	str	lr, [r0, #20]
	# Calc t[1]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [r0]
	ldr	r3, [r0, #4]
#else
	ldrd	r2, r3, [r0]
#endif
	eor	r2, r2, lr, lsr #31
	eor	r3, r3, r12, lsr #31
	eor	r2, r2, r12, lsl #1
	eor	r3, r3, lr, lsl #1
	# XOR t[1] into s[x*5+1]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #8]
	ldr	r5, [sp, #12]
#else
	ldrd	r4, r5, [sp, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [sp, #48]
	ldr	r7, [sp, #52]
#else
	ldrd	r6, r7, [sp, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #88]
	ldr	r9, [sp, #92]
#else
	ldrd	r8, r9, [sp, #88]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #128]
	ldr	r11, [sp, #132]
#else
	ldrd	r10, r11, [sp, #128]
#endif
	ldr	r12, [sp, #168]
	ldr	lr, [sp, #172]
	eor	r4, r4, r2
	eor	r5, r5, r3
	eor	r6, r6, r2
	eor	r7, r7, r3
	eor	r8, r8, r2
	eor	r9, r9, r3
	eor	r10, r10, r2
	eor	r11, r11, r3
	eor	r12, r12, r2
	eor	lr, lr, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #8]
	str	r5, [sp, #12]
#else
	strd	r4, r5, [sp, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [sp, #48]
	str	r7, [sp, #52]
#else
	strd	r6, r7, [sp, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [sp, #88]
	str	r9, [sp, #92]
#else
	strd	r8, r9, [sp, #88]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [sp, #128]
	str	r11, [sp, #132]
#else
	strd	r10, r11, [sp, #128]
#endif
	str	r12, [sp, #168]
	str	lr, [sp, #172]
	# Calc t[3]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [r0, #16]
	ldr	r3, [r0, #20]
#else
	ldrd	r2, r3, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
	eor	r2, r2, r5, lsr #31
	eor	r3, r3, r4, lsr #31
	eor	r2, r2, r4, lsl #1
	eor	r3, r3, r5, lsl #1
	# XOR t[3] into s[x*5+3]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #24]
	ldr	r5, [sp, #28]
#else
	ldrd	r4, r5, [sp, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [sp, #64]
	ldr	r7, [sp, #68]
#else
	ldrd	r6, r7, [sp, #64]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #104]
	ldr	r9, [sp, #108]
#else
	ldrd	r8, r9, [sp, #104]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #144]
	ldr	r11, [sp, #148]
#else
	ldrd	r10, r11, [sp, #144]
#endif
	ldr	r12, [sp, #184]
	ldr	lr, [sp, #188]
	eor	r4, r4, r2
	eor	r5, r5, r3
	eor	r6, r6, r2
	eor	r7, r7, r3
	eor	r8, r8, r2
	eor	r9, r9, r3
	eor	r10, r10, r2
	eor	r11, r11, r3
	eor	r12, r12, r2
	eor	lr, lr, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #24]
	str	r5, [sp, #28]
#else
	strd	r4, r5, [sp, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [sp, #64]
	str	r7, [sp, #68]
#else
	strd	r6, r7, [sp, #64]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [sp, #104]
	str	r9, [sp, #108]
#else
	strd	r8, r9, [sp, #104]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [sp, #144]
	str	r11, [sp, #148]
#else
	strd	r10, r11, [sp, #144]
#endif
	str	r12, [sp, #184]
	str	lr, [sp, #188]
	# Calc t[4]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [r0, #24]
	ldr	r3, [r0, #28]
#else
	ldrd	r2, r3, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0]
	ldr	r5, [r0, #4]
#else
	ldrd	r4, r5, [r0]
#endif
	eor	r2, r2, r5, lsr #31
	eor	r3, r3, r4, lsr #31
	eor	r2, r2, r4, lsl #1
	eor	r3, r3, r5, lsl #1
	# XOR t[4] into s[x*5+4]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #32]
	ldr	r5, [sp, #36]
#else
	ldrd	r4, r5, [sp, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [sp, #72]
	ldr	r7, [sp, #76]
#else
	ldrd	r6, r7, [sp, #72]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #112]
	ldr	r9, [sp, #116]
#else
	ldrd	r8, r9, [sp, #112]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #152]
	ldr	r11, [sp, #156]
#else
	ldrd	r10, r11, [sp, #152]
#endif
	ldr	r12, [sp, #192]
	ldr	lr, [sp, #196]
	eor	r4, r4, r2
	eor	r5, r5, r3
	eor	r6, r6, r2
	eor	r7, r7, r3
	eor	r8, r8, r2
	eor	r9, r9, r3
	eor	r10, r10, r2
	eor	r11, r11, r3
	eor	r12, r12, r2
	eor	lr, lr, r3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #32]
	str	r5, [sp, #36]
#else
	strd	r4, r5, [sp, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [sp, #72]
	str	r7, [sp, #76]
#else
	strd	r6, r7, [sp, #72]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [sp, #112]
	str	r9, [sp, #116]
#else
	strd	r8, r9, [sp, #112]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [sp, #152]
	str	r11, [sp, #156]
#else
	strd	r10, r11, [sp, #152]
#endif
	str	r12, [sp, #192]
	str	lr, [sp, #196]
	# Row Mix
	# Row 0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [sp]
	ldr	r3, [sp, #4]
#else
	ldrd	r2, r3, [sp]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #48]
	ldr	r5, [sp, #52]
#else
	ldrd	r4, r5, [sp, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [sp, #96]
	ldr	r7, [sp, #100]
#else
	ldrd	r6, r7, [sp, #96]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #144]
	ldr	r9, [sp, #148]
#else
	ldrd	r8, r9, [sp, #144]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #192]
	ldr	r11, [sp, #196]
#else
	ldrd	r10, r11, [sp, #192]
#endif
	# s[1] <<< 44
	mov	lr, r4
	lsr	r12, r5, #20
	lsr	r4, r4, #20
	orr	r4, r4, r5, lsl #12
	orr	r5, r12, lr, lsl #12
	# s[2] <<< 43
	mov	lr, r6
	lsr	r12, r7, #21
	lsr	r6, r6, #21
	orr	r6, r6, r7, lsl #11
	orr	r7, r12, lr, lsl #11
	# s[3] <<< 21
	lsr	r12, r9, #11
	lsr	lr, r8, #11
	orr	r8, r12, r8, lsl #21
	orr	r9, lr, r9, lsl #21
	# s[4] <<< 14
	lsr	r12, r11, #18
	lsr	lr, r10, #18
	orr	r10, r12, r10, lsl #14
	orr	r11, lr, r11, lsl #14
	bic	r12, r8, r6
	bic	lr, r9, r7
	eor	r12, r12, r4
	eor	lr, lr, r5
	str	r12, [r0, #8]
	str	lr, [r0, #12]
	bic	r12, r10, r8
	bic	lr, r11, r9
	eor	r12, r12, r6
	eor	lr, lr, r7
	str	r12, [r0, #16]
	str	lr, [r0, #20]
	bic	r12, r2, r10
	bic	lr, r3, r11
	eor	r12, r12, r8
	eor	lr, lr, r9
	str	r12, [r0, #24]
	str	lr, [r0, #28]
	bic	r12, r4, r2
	bic	lr, r5, r3
	eor	r12, r12, r10
	eor	lr, lr, r11
	str	r12, [r0, #32]
	str	lr, [r0, #36]
	# Get constant
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r1]
	ldr	r11, [r1, #4]
#else
	ldrd	r10, r11, [r1]
#endif
	add	r1, r1, #8
	bic	r12, r6, r4
	bic	lr, r7, r5
	eor	r12, r12, r2
	eor	lr, lr, r3
	# XOR in constant
	eor	r12, r12, r10
	eor	lr, lr, r11
	str	r12, [r0]
	str	lr, [r0, #4]
	# Row 1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [sp, #24]
	ldr	r3, [sp, #28]
#else
	ldrd	r2, r3, [sp, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #72]
	ldr	r5, [sp, #76]
#else
	ldrd	r4, r5, [sp, #72]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [sp, #80]
	ldr	r7, [sp, #84]
#else
	ldrd	r6, r7, [sp, #80]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #128]
	ldr	r9, [sp, #132]
#else
	ldrd	r8, r9, [sp, #128]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #176]
	ldr	r11, [sp, #180]
#else
	ldrd	r10, r11, [sp, #176]
#endif
	# s[0] <<< 28
	lsr	r12, r3, #4
	lsr	lr, r2, #4
	orr	r2, r12, r2, lsl #28
	orr	r3, lr, r3, lsl #28
	# s[1] <<< 20
	lsr	r12, r5, #12
	lsr	lr, r4, #12
	orr	r4, r12, r4, lsl #20
	orr	r5, lr, r5, lsl #20
	# s[2] <<< 3
	lsr	r12, r7, #29
	lsr	lr, r6, #29
	orr	r6, r12, r6, lsl #3
	orr	r7, lr, r7, lsl #3
	# s[3] <<< 45
	mov	lr, r8
	lsr	r12, r9, #19
	lsr	r8, r8, #19
	orr	r8, r8, r9, lsl #13
	orr	r9, r12, lr, lsl #13
	# s[4] <<< 61
	mov	lr, r10
	lsr	r12, r11, #3
	lsr	r10, r10, #3
	orr	r10, r10, r11, lsl #29
	orr	r11, r12, lr, lsl #29
	bic	r12, r8, r6
	bic	lr, r9, r7
	eor	r12, r12, r4
	eor	lr, lr, r5
	str	r12, [r0, #48]
	str	lr, [r0, #52]
	bic	r12, r10, r8
	bic	lr, r11, r9
	eor	r12, r12, r6
	eor	lr, lr, r7
	str	r12, [r0, #56]
	str	lr, [r0, #60]
	bic	r12, r2, r10
	bic	lr, r3, r11
	eor	r12, r12, r8
	eor	lr, lr, r9
	str	r12, [r0, #64]
	str	lr, [r0, #68]
	bic	r12, r4, r2
	bic	lr, r5, r3
	eor	r12, r12, r10
	eor	lr, lr, r11
	str	r12, [r0, #72]
	str	lr, [r0, #76]
	bic	r12, r6, r4
	bic	lr, r7, r5
	eor	r12, r12, r2
	eor	lr, lr, r3
	str	r12, [r0, #40]
	str	lr, [r0, #44]
	# Row 2
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [sp, #8]
	ldr	r3, [sp, #12]
#else
	ldrd	r2, r3, [sp, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #56]
	ldr	r5, [sp, #60]
#else
	ldrd	r4, r5, [sp, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [sp, #104]
	ldr	r7, [sp, #108]
#else
	ldrd	r6, r7, [sp, #104]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #152]
	ldr	r9, [sp, #156]
#else
	ldrd	r8, r9, [sp, #152]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #160]
	ldr	r11, [sp, #164]
#else
	ldrd	r10, r11, [sp, #160]
#endif
	# s[0] <<< 1
	lsr	r12, r3, #31
	lsr	lr, r2, #31
	orr	r2, r12, r2, lsl #1
	orr	r3, lr, r3, lsl #1
	# s[1] <<< 6
	lsr	r12, r5, #26
	lsr	lr, r4, #26
	orr	r4, r12, r4, lsl #6
	orr	r5, lr, r5, lsl #6
	# s[2] <<< 25
	lsr	r12, r7, #7
	lsr	lr, r6, #7
	orr	r6, r12, r6, lsl #25
	orr	r7, lr, r7, lsl #25
	# s[3] <<< 8
	lsr	r12, r9, #24
	lsr	lr, r8, #24
	orr	r8, r12, r8, lsl #8
	orr	r9, lr, r9, lsl #8
	# s[4] <<< 18
	lsr	r12, r11, #14
	lsr	lr, r10, #14
	orr	r10, r12, r10, lsl #18
	orr	r11, lr, r11, lsl #18
	bic	r12, r8, r6
	bic	lr, r9, r7
	eor	r12, r12, r4
	eor	lr, lr, r5
	str	r12, [r0, #88]
	str	lr, [r0, #92]
	bic	r12, r10, r8
	bic	lr, r11, r9
	eor	r12, r12, r6
	eor	lr, lr, r7
	str	r12, [r0, #96]
	str	lr, [r0, #100]
	bic	r12, r2, r10
	bic	lr, r3, r11
	eor	r12, r12, r8
	eor	lr, lr, r9
	str	r12, [r0, #104]
	str	lr, [r0, #108]
	bic	r12, r4, r2
	bic	lr, r5, r3
	eor	r12, r12, r10
	eor	lr, lr, r11
	str	r12, [r0, #112]
	str	lr, [r0, #116]
	bic	r12, r6, r4
	bic	lr, r7, r5
	eor	r12, r12, r2
	eor	lr, lr, r3
	str	r12, [r0, #80]
	str	lr, [r0, #84]
	# Row 3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [sp, #32]
	ldr	r3, [sp, #36]
#else
	ldrd	r2, r3, [sp, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #40]
	ldr	r5, [sp, #44]
#else
	ldrd	r4, r5, [sp, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [sp, #88]
	ldr	r7, [sp, #92]
#else
	ldrd	r6, r7, [sp, #88]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #136]
	ldr	r9, [sp, #140]
#else
	ldrd	r8, r9, [sp, #136]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #184]
	ldr	r11, [sp, #188]
#else
	ldrd	r10, r11, [sp, #184]
#endif
	# s[0] <<< 27
	lsr	r12, r3, #5
	lsr	lr, r2, #5
	orr	r2, r12, r2, lsl #27
	orr	r3, lr, r3, lsl #27
	# s[1] <<< 36
	mov	lr, r4
	lsr	r12, r5, #28
	lsr	r4, r4, #28
	orr	r4, r4, r5, lsl #4
	orr	r5, r12, lr, lsl #4
	# s[2] <<< 10
	lsr	r12, r7, #22
	lsr	lr, r6, #22
	orr	r6, r12, r6, lsl #10
	orr	r7, lr, r7, lsl #10
	# s[3] <<< 15
	lsr	r12, r9, #17
	lsr	lr, r8, #17
	orr	r8, r12, r8, lsl #15
	orr	r9, lr, r9, lsl #15
	# s[4] <<< 56
	mov	lr, r10
	lsr	r12, r11, #8
	lsr	r10, r10, #8
	orr	r10, r10, r11, lsl #24
	orr	r11, r12, lr, lsl #24
	bic	r12, r8, r6
	bic	lr, r9, r7
	eor	r12, r12, r4
	eor	lr, lr, r5
	str	r12, [r0, #128]
	str	lr, [r0, #132]
	bic	r12, r10, r8
	bic	lr, r11, r9
	eor	r12, r12, r6
	eor	lr, lr, r7
	str	r12, [r0, #136]
	str	lr, [r0, #140]
	bic	r12, r2, r10
	bic	lr, r3, r11
	eor	r12, r12, r8
	eor	lr, lr, r9
	str	r12, [r0, #144]
	str	lr, [r0, #148]
	bic	r12, r4, r2
	bic	lr, r5, r3
	eor	r12, r12, r10
	eor	lr, lr, r11
	str	r12, [r0, #152]
	str	lr, [r0, #156]
	bic	r12, r6, r4
	bic	lr, r7, r5
	eor	r12, r12, r2
	eor	lr, lr, r3
	str	r12, [r0, #120]
	str	lr, [r0, #124]
	# Row 4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r2, [sp, #16]
	ldr	r3, [sp, #20]
#else
	ldrd	r2, r3, [sp, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #64]
	ldr	r5, [sp, #68]
#else
	ldrd	r4, r5, [sp, #64]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [sp, #112]
	ldr	r7, [sp, #116]
#else
	ldrd	r6, r7, [sp, #112]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #120]
	ldr	r9, [sp, #124]
#else
	ldrd	r8, r9, [sp, #120]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #168]
	ldr	r11, [sp, #172]
#else
	ldrd	r10, r11, [sp, #168]
#endif
	# s[0] <<< 62
	mov	lr, r2
	lsr	r12, r3, #2
	lsr	r2, r2, #2
	orr	r2, r2, r3, lsl #30
	orr	r3, r12, lr, lsl #30
	# s[1] <<< 55
	mov	lr, r4
	lsr	r12, r5, #9
	lsr	r4, r4, #9
	orr	r4, r4, r5, lsl #23
	orr	r5, r12, lr, lsl #23
	# s[2] <<< 39
	mov	lr, r6
	lsr	r12, r7, #25
	lsr	r6, r6, #25
	orr	r6, r6, r7, lsl #7
	orr	r7, r12, lr, lsl #7
	# s[3] <<< 41
	mov	lr, r8
	lsr	r12, r9, #23
	lsr	r8, r8, #23
	orr	r8, r8, r9, lsl #9
	orr	r9, r12, lr, lsl #9
	# s[4] <<< 2
	lsr	r12, r11, #30
	lsr	lr, r10, #30
	orr	r10, r12, r10, lsl #2
	orr	r11, lr, r11, lsl #2
	bic	r12, r8, r6
	bic	lr, r9, r7
	eor	r12, r12, r4
	eor	lr, lr, r5
	str	r12, [r0, #168]
	str	lr, [r0, #172]
	bic	r12, r10, r8
	bic	lr, r11, r9
	eor	r12, r12, r6
	eor	lr, lr, r7
	str	r12, [r0, #176]
	str	lr, [r0, #180]
	bic	r12, r2, r10
	bic	lr, r3, r11
	eor	r12, r12, r8
	eor	lr, lr, r9
	str	r12, [r0, #184]
	str	lr, [r0, #188]
	bic	r12, r4, r2
	bic	lr, r5, r3
	eor	r12, r12, r10
	eor	lr, lr, r11
	str	r12, [r0, #192]
	str	lr, [r0, #196]
	bic	r12, r6, r4
	bic	lr, r7, r5
	eor	r12, r12, r2
	eor	lr, lr, r3
	str	r12, [r0, #160]
	str	lr, [r0, #164]
	ldr	r2, [sp, #200]
	subs	r2, r2, #1
	bne	L_sha3_arm32_begin
	add	sp, sp, #0xcc
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	BlockSha3,.-BlockSha3
#endif /* WOLFSSL_ARMASM_NO_NEON */
#endif /* WOLFSSL_SHA3 */
#endif /* !__aarch64__ && !WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
