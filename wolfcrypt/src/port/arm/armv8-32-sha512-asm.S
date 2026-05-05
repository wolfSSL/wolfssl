/* armv8-32-sha512-asm
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
 *   ruby ./sha2/sha512.rb arm32 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-32-sha512-asm.S
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

#ifdef WOLFSSL_ARMASM
#if !defined(__aarch64__) && !defined(WOLFSSL_ARMASM_THUMB2)
#ifndef WOLFSSL_ARMASM_INLINE
#if defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA384)
#ifdef WOLFSSL_ARMASM_NO_NEON
#ifndef __APPLE__
	.text
	.type	L_SHA512_transform_len_k, %object
	.size	L_SHA512_transform_len_k, 640
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_SHA512_transform_len_k:
	.quad	0x428a2f98d728ae22,0x7137449123ef65cd
	.quad	0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
	.quad	0x3956c25bf348b538,0x59f111f1b605d019
	.quad	0x923f82a4af194f9b,0xab1c5ed5da6d8118
	.quad	0xd807aa98a3030242,0x12835b0145706fbe
	.quad	0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
	.quad	0x72be5d74f27b896f,0x80deb1fe3b1696b1
	.quad	0x9bdc06a725c71235,0xc19bf174cf692694
	.quad	0xe49b69c19ef14ad2,0xefbe4786384f25e3
	.quad	0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
	.quad	0x2de92c6f592b0275,0x4a7484aa6ea6e483
	.quad	0x5cb0a9dcbd41fbd4,0x76f988da831153b5
	.quad	0x983e5152ee66dfab,0xa831c66d2db43210
	.quad	0xb00327c898fb213f,0xbf597fc7beef0ee4
	.quad	0xc6e00bf33da88fc2,0xd5a79147930aa725
	.quad	0x06ca6351e003826f,0x142929670a0e6e70
	.quad	0x27b70a8546d22ffc,0x2e1b21385c26c926
	.quad	0x4d2c6dfc5ac42aed,0x53380d139d95b3df
	.quad	0x650a73548baf63de,0x766a0abb3c77b2a8
	.quad	0x81c2c92e47edaee6,0x92722c851482353b
	.quad	0xa2bfe8a14cf10364,0xa81a664bbc423001
	.quad	0xc24b8b70d0f89791,0xc76c51a30654be30
	.quad	0xd192e819d6ef5218,0xd69906245565a910
	.quad	0xf40e35855771202a,0x106aa07032bbd1b8
	.quad	0x19a4c116b8d2d0c8,0x1e376c085141ab53
	.quad	0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
	.quad	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
	.quad	0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
	.quad	0x748f82ee5defb2fc,0x78a5636f43172f60
	.quad	0x84c87814a1f0ab72,0x8cc702081a6439ec
	.quad	0x90befffa23631e28,0xa4506cebde82bde9
	.quad	0xbef9a3f7b2c67915,0xc67178f2e372532b
	.quad	0xca273eceea26619c,0xd186b8c721c0c207
	.quad	0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
	.quad	0x06f067aa72176fba,0x0a637dc5a2c898a6
	.quad	0x113f9804bef90dae,0x1b710b35131c471b
	.quad	0x28db77f523047d84,0x32caab7b40c72493
	.quad	0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
	.quad	0x4cc5d4becb3e42b6,0x597f299cfc657e2a
	.quad	0x5fcb6fab3ad6faec,0x6c44198c4a475817
	.text
	.align	4
	.globl	Transform_Sha512_Len_base
	.type	Transform_Sha512_Len_base, %function
Transform_Sha512_Len_base:
	push	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	sub	sp, sp, #0xc0
	adr	r3, L_SHA512_transform_len_k
	# Copy digest to add in at end
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
#else
	ldrd	r6, r7, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #16]
	ldr	r9, [r0, #20]
#else
	ldrd	r8, r9, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r0, #24]
	ldr	r11, [r0, #28]
#else
	ldrd	r10, r11, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #128]
	str	r5, [sp, #132]
#else
	strd	r4, r5, [sp, #128]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [sp, #136]
	str	r7, [sp, #140]
#else
	strd	r6, r7, [sp, #136]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [sp, #144]
	str	r9, [sp, #148]
#else
	strd	r8, r9, [sp, #144]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [sp, #152]
	str	r11, [sp, #156]
#else
	strd	r10, r11, [sp, #152]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #40]
	ldr	r7, [r0, #44]
#else
	ldrd	r6, r7, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #48]
	ldr	r9, [r0, #52]
#else
	ldrd	r8, r9, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r0, #56]
	ldr	r11, [r0, #60]
#else
	ldrd	r10, r11, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #160]
	str	r5, [sp, #164]
#else
	strd	r4, r5, [sp, #160]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [sp, #168]
	str	r7, [sp, #172]
#else
	strd	r6, r7, [sp, #168]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [sp, #176]
	str	r9, [sp, #180]
#else
	strd	r8, r9, [sp, #176]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r10, [sp, #184]
	str	r11, [sp, #188]
#else
	strd	r10, r11, [sp, #184]
#endif
	# Start of loop processing a block
L_SHA512_transform_len_begin:
	# Load, Reverse and Store W - 64 bytes
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 6)
	ldr	r4, [r1]
	ldr	r5, [r1, #4]
	ldr	r6, [r1, #8]
	ldr	r7, [r1, #12]
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
	str	r5, [sp]
	str	r4, [sp, #4]
	str	r7, [sp, #8]
	str	r6, [sp, #12]
	ldr	r4, [r1, #16]
	ldr	r5, [r1, #20]
	ldr	r6, [r1, #24]
	ldr	r7, [r1, #28]
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
	str	r5, [sp, #16]
	str	r4, [sp, #20]
	str	r7, [sp, #24]
	str	r6, [sp, #28]
	ldr	r4, [r1, #32]
	ldr	r5, [r1, #36]
	ldr	r6, [r1, #40]
	ldr	r7, [r1, #44]
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
	str	r5, [sp, #32]
	str	r4, [sp, #36]
	str	r7, [sp, #40]
	str	r6, [sp, #44]
	ldr	r4, [r1, #48]
	ldr	r5, [r1, #52]
	ldr	r6, [r1, #56]
	ldr	r7, [r1, #60]
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
	str	r5, [sp, #48]
	str	r4, [sp, #52]
	str	r7, [sp, #56]
	str	r6, [sp, #60]
	ldr	r4, [r1, #64]
	ldr	r5, [r1, #68]
	ldr	r6, [r1, #72]
	ldr	r7, [r1, #76]
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
	str	r5, [sp, #64]
	str	r4, [sp, #68]
	str	r7, [sp, #72]
	str	r6, [sp, #76]
	ldr	r4, [r1, #80]
	ldr	r5, [r1, #84]
	ldr	r6, [r1, #88]
	ldr	r7, [r1, #92]
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
	str	r5, [sp, #80]
	str	r4, [sp, #84]
	str	r7, [sp, #88]
	str	r6, [sp, #92]
	ldr	r4, [r1, #96]
	ldr	r5, [r1, #100]
	ldr	r6, [r1, #104]
	ldr	r7, [r1, #108]
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
	str	r5, [sp, #96]
	str	r4, [sp, #100]
	str	r7, [sp, #104]
	str	r6, [sp, #108]
	ldr	r4, [r1, #112]
	ldr	r5, [r1, #116]
	ldr	r6, [r1, #120]
	ldr	r7, [r1, #124]
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
	str	r5, [sp, #112]
	str	r4, [sp, #116]
	str	r7, [sp, #120]
	str	r6, [sp, #124]
#else
	ldr	r4, [r1]
	ldr	r5, [r1, #4]
	ldr	r6, [r1, #8]
	ldr	r7, [r1, #12]
	ldr	r8, [r1, #16]
	ldr	r9, [r1, #20]
	ldr	r10, [r1, #24]
	ldr	r11, [r1, #28]
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
	rev	r8, r8
	rev	r9, r9
	rev	r10, r10
	rev	r11, r11
	str	r5, [sp]
	str	r4, [sp, #4]
	str	r7, [sp, #8]
	str	r6, [sp, #12]
	str	r9, [sp, #16]
	str	r8, [sp, #20]
	str	r11, [sp, #24]
	str	r10, [sp, #28]
	ldr	r4, [r1, #32]
	ldr	r5, [r1, #36]
	ldr	r6, [r1, #40]
	ldr	r7, [r1, #44]
	ldr	r8, [r1, #48]
	ldr	r9, [r1, #52]
	ldr	r10, [r1, #56]
	ldr	r11, [r1, #60]
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
	rev	r8, r8
	rev	r9, r9
	rev	r10, r10
	rev	r11, r11
	str	r5, [sp, #32]
	str	r4, [sp, #36]
	str	r7, [sp, #40]
	str	r6, [sp, #44]
	str	r9, [sp, #48]
	str	r8, [sp, #52]
	str	r11, [sp, #56]
	str	r10, [sp, #60]
	ldr	r4, [r1, #64]
	ldr	r5, [r1, #68]
	ldr	r6, [r1, #72]
	ldr	r7, [r1, #76]
	ldr	r8, [r1, #80]
	ldr	r9, [r1, #84]
	ldr	r10, [r1, #88]
	ldr	r11, [r1, #92]
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
	rev	r8, r8
	rev	r9, r9
	rev	r10, r10
	rev	r11, r11
	str	r5, [sp, #64]
	str	r4, [sp, #68]
	str	r7, [sp, #72]
	str	r6, [sp, #76]
	str	r9, [sp, #80]
	str	r8, [sp, #84]
	str	r11, [sp, #88]
	str	r10, [sp, #92]
	ldr	r4, [r1, #96]
	ldr	r5, [r1, #100]
	ldr	r6, [r1, #104]
	ldr	r7, [r1, #108]
	ldr	r8, [r1, #112]
	ldr	r9, [r1, #116]
	ldr	r10, [r1, #120]
	ldr	r11, [r1, #124]
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
	rev	r8, r8
	rev	r9, r9
	rev	r10, r10
	rev	r11, r11
	str	r5, [sp, #96]
	str	r4, [sp, #100]
	str	r7, [sp, #104]
	str	r6, [sp, #108]
	str	r9, [sp, #112]
	str	r8, [sp, #116]
	str	r11, [sp, #120]
	str	r10, [sp, #124]
#endif /* WOLFSSL_ARM_ARCH && WOLFSSL_ARM_ARCH < 6 */
	# Pre-calc: b ^ c
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [r0, #8]
	ldr	r11, [r0, #12]
#else
	ldrd	r10, r11, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
	eor	r10, r10, r4
	eor	r11, r11, r5
	mov	r12, #4
	# Start of 16 rounds
L_SHA512_transform_len_start:
	# Round 0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #56]
	str	r5, [r0, #60]
#else
	strd	r4, r5, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #40]
	ldr	r7, [r0, #44]
#else
	ldrd	r6, r7, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #48]
	ldr	r9, [r0, #52]
#else
	ldrd	r8, r9, [r0, #48]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	sp, {r8, r9}
#else
	ldrd	r8, r9, [sp]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r3, {r6, r7}
#else
	ldrd	r6, r7, [r3]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #24]
	ldr	r9, [r0, #28]
#else
	ldrd	r8, r9, [r0, #24]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #56]
	str	r5, [r0, #60]
#else
	strd	r4, r5, [r0, #56]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #24]
	str	r9, [r0, #28]
#else
	strd	r8, r9, [r0, #24]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r8, r9}
#else
	ldrd	r8, r9, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
#else
	ldrd	r6, r7, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #56]
	str	r5, [r0, #60]
#else
	strd	r4, r5, [r0, #56]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #56]
	ldr	r7, [r0, #60]
#else
	ldrd	r6, r7, [r0, #56]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #56]
	str	r7, [r0, #60]
#else
	strd	r6, r7, [r0, #56]
#endif
	mov	r10, r8
	mov	r11, r9
	# Calc new W[0]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #112]
	ldr	r5, [sp, #116]
#else
	ldrd	r4, r5, [sp, #112]
#endif
	lsrs	r6, r4, #19
	lsrs	r7, r5, #19
	orr	r7, r7, r4, lsl #13
	orr	r6, r6, r5, lsl #13
	lsls	r8, r4, #3
	lsls	r9, r5, #3
	orr	r9, r9, r4, lsr #29
	orr	r8, r8, r5, lsr #29
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #6
	lsrs	r9, r5, #6
	orr	r8, r8, r5, lsl #26
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	sp, {r4, r5}
#else
	ldrd	r4, r5, [sp]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #72]
	ldr	r9, [sp, #76]
#else
	ldrd	r8, r9, [sp, #72]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	sp, {r4, r5}
#else
	strd	r4, r5, [sp]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #8]
	ldr	r5, [sp, #12]
#else
	ldrd	r4, r5, [sp, #8]
#endif
	lsrs	r6, r4, #1
	lsrs	r7, r5, #1
	orr	r7, r7, r4, lsl #31
	orr	r6, r6, r5, lsl #31
	lsrs	r8, r4, #8
	lsrs	r9, r5, #8
	orr	r9, r9, r4, lsl #24
	orr	r8, r8, r5, lsl #24
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #7
	lsrs	r9, r5, #7
	orr	r8, r8, r5, lsl #25
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	sp, {r4, r5}
#else
	ldrd	r4, r5, [sp]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	sp, {r4, r5}
#else
	strd	r4, r5, [sp]
#endif
	# Round 1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #48]
	str	r5, [r0, #52]
#else
	strd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #32]
	ldr	r7, [r0, #36]
#else
	ldrd	r6, r7, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #40]
	ldr	r9, [r0, #44]
#else
	ldrd	r8, r9, [r0, #40]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #8]
	ldr	r9, [sp, #12]
#else
	ldrd	r8, r9, [sp, #8]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #8]
	ldr	r7, [r3, #12]
#else
	ldrd	r6, r7, [r3, #8]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #16]
	ldr	r9, [r0, #20]
#else
	ldrd	r8, r9, [r0, #16]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #48]
	str	r5, [r0, #52]
#else
	strd	r4, r5, [r0, #48]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #16]
	str	r9, [r0, #20]
#else
	strd	r8, r9, [r0, #16]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #56]
	ldr	r9, [r0, #60]
#else
	ldrd	r8, r9, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r6, r7}
#else
	ldrd	r6, r7, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #48]
	str	r5, [r0, #52]
#else
	strd	r4, r5, [r0, #48]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #48]
	ldr	r7, [r0, #52]
#else
	ldrd	r6, r7, [r0, #48]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #48]
	str	r7, [r0, #52]
#else
	strd	r6, r7, [r0, #48]
#endif
	mov	r10, r8
	mov	r11, r9
	# Calc new W[1]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #120]
	ldr	r5, [sp, #124]
#else
	ldrd	r4, r5, [sp, #120]
#endif
	lsrs	r6, r4, #19
	lsrs	r7, r5, #19
	orr	r7, r7, r4, lsl #13
	orr	r6, r6, r5, lsl #13
	lsls	r8, r4, #3
	lsls	r9, r5, #3
	orr	r9, r9, r4, lsr #29
	orr	r8, r8, r5, lsr #29
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #6
	lsrs	r9, r5, #6
	orr	r8, r8, r5, lsl #26
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #8]
	ldr	r5, [sp, #12]
#else
	ldrd	r4, r5, [sp, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #80]
	ldr	r9, [sp, #84]
#else
	ldrd	r8, r9, [sp, #80]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #8]
	str	r5, [sp, #12]
#else
	strd	r4, r5, [sp, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #16]
	ldr	r5, [sp, #20]
#else
	ldrd	r4, r5, [sp, #16]
#endif
	lsrs	r6, r4, #1
	lsrs	r7, r5, #1
	orr	r7, r7, r4, lsl #31
	orr	r6, r6, r5, lsl #31
	lsrs	r8, r4, #8
	lsrs	r9, r5, #8
	orr	r9, r9, r4, lsl #24
	orr	r8, r8, r5, lsl #24
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #7
	lsrs	r9, r5, #7
	orr	r8, r8, r5, lsl #25
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #8]
	ldr	r5, [sp, #12]
#else
	ldrd	r4, r5, [sp, #8]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #8]
	str	r5, [sp, #12]
#else
	strd	r4, r5, [sp, #8]
#endif
	# Round 2
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #40]
	str	r5, [r0, #44]
#else
	strd	r4, r5, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #24]
	ldr	r7, [r0, #28]
#else
	ldrd	r6, r7, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #32]
	ldr	r9, [r0, #36]
#else
	ldrd	r8, r9, [r0, #32]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #16]
	ldr	r9, [sp, #20]
#else
	ldrd	r8, r9, [sp, #16]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #16]
	ldr	r7, [r3, #20]
#else
	ldrd	r6, r7, [r3, #16]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #8]
	ldr	r9, [r0, #12]
#else
	ldrd	r8, r9, [r0, #8]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #40]
	str	r5, [r0, #44]
#else
	strd	r4, r5, [r0, #40]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #8]
	str	r9, [r0, #12]
#else
	strd	r8, r9, [r0, #8]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #48]
	ldr	r9, [r0, #52]
#else
	ldrd	r8, r9, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #56]
	ldr	r7, [r0, #60]
#else
	ldrd	r6, r7, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #40]
	str	r5, [r0, #44]
#else
	strd	r4, r5, [r0, #40]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #40]
	ldr	r7, [r0, #44]
#else
	ldrd	r6, r7, [r0, #40]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #40]
	str	r7, [r0, #44]
#else
	strd	r6, r7, [r0, #40]
#endif
	mov	r10, r8
	mov	r11, r9
	# Calc new W[2]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	sp, {r4, r5}
#else
	ldrd	r4, r5, [sp]
#endif
	lsrs	r6, r4, #19
	lsrs	r7, r5, #19
	orr	r7, r7, r4, lsl #13
	orr	r6, r6, r5, lsl #13
	lsls	r8, r4, #3
	lsls	r9, r5, #3
	orr	r9, r9, r4, lsr #29
	orr	r8, r8, r5, lsr #29
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #6
	lsrs	r9, r5, #6
	orr	r8, r8, r5, lsl #26
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #16]
	ldr	r5, [sp, #20]
#else
	ldrd	r4, r5, [sp, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #88]
	ldr	r9, [sp, #92]
#else
	ldrd	r8, r9, [sp, #88]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #16]
	str	r5, [sp, #20]
#else
	strd	r4, r5, [sp, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #24]
	ldr	r5, [sp, #28]
#else
	ldrd	r4, r5, [sp, #24]
#endif
	lsrs	r6, r4, #1
	lsrs	r7, r5, #1
	orr	r7, r7, r4, lsl #31
	orr	r6, r6, r5, lsl #31
	lsrs	r8, r4, #8
	lsrs	r9, r5, #8
	orr	r9, r9, r4, lsl #24
	orr	r8, r8, r5, lsl #24
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #7
	lsrs	r9, r5, #7
	orr	r8, r8, r5, lsl #25
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #16]
	ldr	r5, [sp, #20]
#else
	ldrd	r4, r5, [sp, #16]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #16]
	str	r5, [sp, #20]
#else
	strd	r4, r5, [sp, #16]
#endif
	# Round 3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #32]
	str	r5, [r0, #36]
#else
	strd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #16]
	ldr	r7, [r0, #20]
#else
	ldrd	r6, r7, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #24]
	ldr	r9, [r0, #28]
#else
	ldrd	r8, r9, [r0, #24]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #24]
	ldr	r9, [sp, #28]
#else
	ldrd	r8, r9, [sp, #24]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #24]
	ldr	r7, [r3, #28]
#else
	ldrd	r6, r7, [r3, #24]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r8, r9}
#else
	ldrd	r8, r9, [r0]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #32]
	str	r5, [r0, #36]
#else
	strd	r4, r5, [r0, #32]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r8, r9}
#else
	strd	r8, r9, [r0]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #40]
	ldr	r9, [r0, #44]
#else
	ldrd	r8, r9, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #48]
	ldr	r7, [r0, #52]
#else
	ldrd	r6, r7, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #32]
	str	r5, [r0, #36]
#else
	strd	r4, r5, [r0, #32]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #32]
	ldr	r7, [r0, #36]
#else
	ldrd	r6, r7, [r0, #32]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #32]
	str	r7, [r0, #36]
#else
	strd	r6, r7, [r0, #32]
#endif
	mov	r10, r8
	mov	r11, r9
	# Calc new W[3]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #8]
	ldr	r5, [sp, #12]
#else
	ldrd	r4, r5, [sp, #8]
#endif
	lsrs	r6, r4, #19
	lsrs	r7, r5, #19
	orr	r7, r7, r4, lsl #13
	orr	r6, r6, r5, lsl #13
	lsls	r8, r4, #3
	lsls	r9, r5, #3
	orr	r9, r9, r4, lsr #29
	orr	r8, r8, r5, lsr #29
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #6
	lsrs	r9, r5, #6
	orr	r8, r8, r5, lsl #26
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #24]
	ldr	r5, [sp, #28]
#else
	ldrd	r4, r5, [sp, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #96]
	ldr	r9, [sp, #100]
#else
	ldrd	r8, r9, [sp, #96]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #24]
	str	r5, [sp, #28]
#else
	strd	r4, r5, [sp, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #32]
	ldr	r5, [sp, #36]
#else
	ldrd	r4, r5, [sp, #32]
#endif
	lsrs	r6, r4, #1
	lsrs	r7, r5, #1
	orr	r7, r7, r4, lsl #31
	orr	r6, r6, r5, lsl #31
	lsrs	r8, r4, #8
	lsrs	r9, r5, #8
	orr	r9, r9, r4, lsl #24
	orr	r8, r8, r5, lsl #24
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #7
	lsrs	r9, r5, #7
	orr	r8, r8, r5, lsl #25
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #24]
	ldr	r5, [sp, #28]
#else
	ldrd	r4, r5, [sp, #24]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #24]
	str	r5, [sp, #28]
#else
	strd	r4, r5, [sp, #24]
#endif
	# Round 4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #24]
	str	r5, [r0, #28]
#else
	strd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
#else
	ldrd	r6, r7, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #16]
	ldr	r9, [r0, #20]
#else
	ldrd	r8, r9, [r0, #16]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #32]
	ldr	r9, [sp, #36]
#else
	ldrd	r8, r9, [sp, #32]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #32]
	ldr	r7, [r3, #36]
#else
	ldrd	r6, r7, [r3, #32]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #56]
	ldr	r9, [r0, #60]
#else
	ldrd	r8, r9, [r0, #56]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #24]
	str	r5, [r0, #28]
#else
	strd	r4, r5, [r0, #24]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #56]
	str	r9, [r0, #60]
#else
	strd	r8, r9, [r0, #56]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #32]
	ldr	r9, [r0, #36]
#else
	ldrd	r8, r9, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #40]
	ldr	r7, [r0, #44]
#else
	ldrd	r6, r7, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #24]
	str	r5, [r0, #28]
#else
	strd	r4, r5, [r0, #24]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #24]
	ldr	r7, [r0, #28]
#else
	ldrd	r6, r7, [r0, #24]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #24]
	str	r7, [r0, #28]
#else
	strd	r6, r7, [r0, #24]
#endif
	mov	r10, r8
	mov	r11, r9
	# Calc new W[4]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #16]
	ldr	r5, [sp, #20]
#else
	ldrd	r4, r5, [sp, #16]
#endif
	lsrs	r6, r4, #19
	lsrs	r7, r5, #19
	orr	r7, r7, r4, lsl #13
	orr	r6, r6, r5, lsl #13
	lsls	r8, r4, #3
	lsls	r9, r5, #3
	orr	r9, r9, r4, lsr #29
	orr	r8, r8, r5, lsr #29
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #6
	lsrs	r9, r5, #6
	orr	r8, r8, r5, lsl #26
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #32]
	ldr	r5, [sp, #36]
#else
	ldrd	r4, r5, [sp, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #104]
	ldr	r9, [sp, #108]
#else
	ldrd	r8, r9, [sp, #104]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #32]
	str	r5, [sp, #36]
#else
	strd	r4, r5, [sp, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #40]
	ldr	r5, [sp, #44]
#else
	ldrd	r4, r5, [sp, #40]
#endif
	lsrs	r6, r4, #1
	lsrs	r7, r5, #1
	orr	r7, r7, r4, lsl #31
	orr	r6, r6, r5, lsl #31
	lsrs	r8, r4, #8
	lsrs	r9, r5, #8
	orr	r9, r9, r4, lsl #24
	orr	r8, r8, r5, lsl #24
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #7
	lsrs	r9, r5, #7
	orr	r8, r8, r5, lsl #25
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #32]
	ldr	r5, [sp, #36]
#else
	ldrd	r4, r5, [sp, #32]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #32]
	str	r5, [sp, #36]
#else
	strd	r4, r5, [sp, #32]
#endif
	# Round 5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #16]
	str	r5, [r0, #20]
#else
	strd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r6, r7}
#else
	ldrd	r6, r7, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #8]
	ldr	r9, [r0, #12]
#else
	ldrd	r8, r9, [r0, #8]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #40]
	ldr	r9, [sp, #44]
#else
	ldrd	r8, r9, [sp, #40]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #40]
	ldr	r7, [r3, #44]
#else
	ldrd	r6, r7, [r3, #40]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #48]
	ldr	r9, [r0, #52]
#else
	ldrd	r8, r9, [r0, #48]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #16]
	str	r5, [r0, #20]
#else
	strd	r4, r5, [r0, #16]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #48]
	str	r9, [r0, #52]
#else
	strd	r8, r9, [r0, #48]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #24]
	ldr	r9, [r0, #28]
#else
	ldrd	r8, r9, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #32]
	ldr	r7, [r0, #36]
#else
	ldrd	r6, r7, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #16]
	str	r5, [r0, #20]
#else
	strd	r4, r5, [r0, #16]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #16]
	ldr	r7, [r0, #20]
#else
	ldrd	r6, r7, [r0, #16]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #16]
	str	r7, [r0, #20]
#else
	strd	r6, r7, [r0, #16]
#endif
	mov	r10, r8
	mov	r11, r9
	# Calc new W[5]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #24]
	ldr	r5, [sp, #28]
#else
	ldrd	r4, r5, [sp, #24]
#endif
	lsrs	r6, r4, #19
	lsrs	r7, r5, #19
	orr	r7, r7, r4, lsl #13
	orr	r6, r6, r5, lsl #13
	lsls	r8, r4, #3
	lsls	r9, r5, #3
	orr	r9, r9, r4, lsr #29
	orr	r8, r8, r5, lsr #29
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #6
	lsrs	r9, r5, #6
	orr	r8, r8, r5, lsl #26
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #40]
	ldr	r5, [sp, #44]
#else
	ldrd	r4, r5, [sp, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #112]
	ldr	r9, [sp, #116]
#else
	ldrd	r8, r9, [sp, #112]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #40]
	str	r5, [sp, #44]
#else
	strd	r4, r5, [sp, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #48]
	ldr	r5, [sp, #52]
#else
	ldrd	r4, r5, [sp, #48]
#endif
	lsrs	r6, r4, #1
	lsrs	r7, r5, #1
	orr	r7, r7, r4, lsl #31
	orr	r6, r6, r5, lsl #31
	lsrs	r8, r4, #8
	lsrs	r9, r5, #8
	orr	r9, r9, r4, lsl #24
	orr	r8, r8, r5, lsl #24
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #7
	lsrs	r9, r5, #7
	orr	r8, r8, r5, lsl #25
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #40]
	ldr	r5, [sp, #44]
#else
	ldrd	r4, r5, [sp, #40]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #40]
	str	r5, [sp, #44]
#else
	strd	r4, r5, [sp, #40]
#endif
	# Round 6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #8]
	str	r5, [r0, #12]
#else
	strd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #56]
	ldr	r7, [r0, #60]
#else
	ldrd	r6, r7, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r8, r9}
#else
	ldrd	r8, r9, [r0]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #48]
	ldr	r9, [sp, #52]
#else
	ldrd	r8, r9, [sp, #48]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #48]
	ldr	r7, [r3, #52]
#else
	ldrd	r6, r7, [r3, #48]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #40]
	ldr	r9, [r0, #44]
#else
	ldrd	r8, r9, [r0, #40]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #8]
	str	r5, [r0, #12]
#else
	strd	r4, r5, [r0, #8]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #40]
	str	r9, [r0, #44]
#else
	strd	r8, r9, [r0, #40]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #16]
	ldr	r9, [r0, #20]
#else
	ldrd	r8, r9, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #24]
	ldr	r7, [r0, #28]
#else
	ldrd	r6, r7, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #8]
	str	r5, [r0, #12]
#else
	strd	r4, r5, [r0, #8]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
#else
	ldrd	r6, r7, [r0, #8]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #8]
	str	r7, [r0, #12]
#else
	strd	r6, r7, [r0, #8]
#endif
	mov	r10, r8
	mov	r11, r9
	# Calc new W[6]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #32]
	ldr	r5, [sp, #36]
#else
	ldrd	r4, r5, [sp, #32]
#endif
	lsrs	r6, r4, #19
	lsrs	r7, r5, #19
	orr	r7, r7, r4, lsl #13
	orr	r6, r6, r5, lsl #13
	lsls	r8, r4, #3
	lsls	r9, r5, #3
	orr	r9, r9, r4, lsr #29
	orr	r8, r8, r5, lsr #29
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #6
	lsrs	r9, r5, #6
	orr	r8, r8, r5, lsl #26
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #48]
	ldr	r5, [sp, #52]
#else
	ldrd	r4, r5, [sp, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #120]
	ldr	r9, [sp, #124]
#else
	ldrd	r8, r9, [sp, #120]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #48]
	str	r5, [sp, #52]
#else
	strd	r4, r5, [sp, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #56]
	ldr	r5, [sp, #60]
#else
	ldrd	r4, r5, [sp, #56]
#endif
	lsrs	r6, r4, #1
	lsrs	r7, r5, #1
	orr	r7, r7, r4, lsl #31
	orr	r6, r6, r5, lsl #31
	lsrs	r8, r4, #8
	lsrs	r9, r5, #8
	orr	r9, r9, r4, lsl #24
	orr	r8, r8, r5, lsl #24
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #7
	lsrs	r9, r5, #7
	orr	r8, r8, r5, lsl #25
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #48]
	ldr	r5, [sp, #52]
#else
	ldrd	r4, r5, [sp, #48]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #48]
	str	r5, [sp, #52]
#else
	strd	r4, r5, [sp, #48]
#endif
	# Round 7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r4, r5}
#else
	strd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #48]
	ldr	r7, [r0, #52]
#else
	ldrd	r6, r7, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #56]
	ldr	r9, [r0, #60]
#else
	ldrd	r8, r9, [r0, #56]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #56]
	ldr	r9, [sp, #60]
#else
	ldrd	r8, r9, [sp, #56]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #56]
	ldr	r7, [r3, #60]
#else
	ldrd	r6, r7, [r3, #56]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #32]
	ldr	r9, [r0, #36]
#else
	ldrd	r8, r9, [r0, #32]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r4, r5}
#else
	strd	r4, r5, [r0]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #32]
	str	r9, [r0, #36]
#else
	strd	r8, r9, [r0, #32]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #8]
	ldr	r9, [r0, #12]
#else
	ldrd	r8, r9, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #16]
	ldr	r7, [r0, #20]
#else
	ldrd	r6, r7, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r4, r5}
#else
	strd	r4, r5, [r0]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r6, r7}
#else
	ldrd	r6, r7, [r0]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r6, r7}
#else
	strd	r6, r7, [r0]
#endif
	mov	r10, r8
	mov	r11, r9
	# Calc new W[7]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #40]
	ldr	r5, [sp, #44]
#else
	ldrd	r4, r5, [sp, #40]
#endif
	lsrs	r6, r4, #19
	lsrs	r7, r5, #19
	orr	r7, r7, r4, lsl #13
	orr	r6, r6, r5, lsl #13
	lsls	r8, r4, #3
	lsls	r9, r5, #3
	orr	r9, r9, r4, lsr #29
	orr	r8, r8, r5, lsr #29
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #6
	lsrs	r9, r5, #6
	orr	r8, r8, r5, lsl #26
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #56]
	ldr	r5, [sp, #60]
#else
	ldrd	r4, r5, [sp, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	sp, {r8, r9}
#else
	ldrd	r8, r9, [sp]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #56]
	str	r5, [sp, #60]
#else
	strd	r4, r5, [sp, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #64]
	ldr	r5, [sp, #68]
#else
	ldrd	r4, r5, [sp, #64]
#endif
	lsrs	r6, r4, #1
	lsrs	r7, r5, #1
	orr	r7, r7, r4, lsl #31
	orr	r6, r6, r5, lsl #31
	lsrs	r8, r4, #8
	lsrs	r9, r5, #8
	orr	r9, r9, r4, lsl #24
	orr	r8, r8, r5, lsl #24
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #7
	lsrs	r9, r5, #7
	orr	r8, r8, r5, lsl #25
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #56]
	ldr	r5, [sp, #60]
#else
	ldrd	r4, r5, [sp, #56]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #56]
	str	r5, [sp, #60]
#else
	strd	r4, r5, [sp, #56]
#endif
	# Round 8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #56]
	str	r5, [r0, #60]
#else
	strd	r4, r5, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #40]
	ldr	r7, [r0, #44]
#else
	ldrd	r6, r7, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #48]
	ldr	r9, [r0, #52]
#else
	ldrd	r8, r9, [r0, #48]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #64]
	ldr	r9, [sp, #68]
#else
	ldrd	r8, r9, [sp, #64]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #64]
	ldr	r7, [r3, #68]
#else
	ldrd	r6, r7, [r3, #64]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #24]
	ldr	r9, [r0, #28]
#else
	ldrd	r8, r9, [r0, #24]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #56]
	str	r5, [r0, #60]
#else
	strd	r4, r5, [r0, #56]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #24]
	str	r9, [r0, #28]
#else
	strd	r8, r9, [r0, #24]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r8, r9}
#else
	ldrd	r8, r9, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
#else
	ldrd	r6, r7, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #56]
	str	r5, [r0, #60]
#else
	strd	r4, r5, [r0, #56]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #56]
	ldr	r7, [r0, #60]
#else
	ldrd	r6, r7, [r0, #56]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #56]
	str	r7, [r0, #60]
#else
	strd	r6, r7, [r0, #56]
#endif
	mov	r10, r8
	mov	r11, r9
	# Calc new W[8]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #48]
	ldr	r5, [sp, #52]
#else
	ldrd	r4, r5, [sp, #48]
#endif
	lsrs	r6, r4, #19
	lsrs	r7, r5, #19
	orr	r7, r7, r4, lsl #13
	orr	r6, r6, r5, lsl #13
	lsls	r8, r4, #3
	lsls	r9, r5, #3
	orr	r9, r9, r4, lsr #29
	orr	r8, r8, r5, lsr #29
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #6
	lsrs	r9, r5, #6
	orr	r8, r8, r5, lsl #26
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #64]
	ldr	r5, [sp, #68]
#else
	ldrd	r4, r5, [sp, #64]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #8]
	ldr	r9, [sp, #12]
#else
	ldrd	r8, r9, [sp, #8]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #64]
	str	r5, [sp, #68]
#else
	strd	r4, r5, [sp, #64]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #72]
	ldr	r5, [sp, #76]
#else
	ldrd	r4, r5, [sp, #72]
#endif
	lsrs	r6, r4, #1
	lsrs	r7, r5, #1
	orr	r7, r7, r4, lsl #31
	orr	r6, r6, r5, lsl #31
	lsrs	r8, r4, #8
	lsrs	r9, r5, #8
	orr	r9, r9, r4, lsl #24
	orr	r8, r8, r5, lsl #24
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #7
	lsrs	r9, r5, #7
	orr	r8, r8, r5, lsl #25
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #64]
	ldr	r5, [sp, #68]
#else
	ldrd	r4, r5, [sp, #64]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #64]
	str	r5, [sp, #68]
#else
	strd	r4, r5, [sp, #64]
#endif
	# Round 9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #48]
	str	r5, [r0, #52]
#else
	strd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #32]
	ldr	r7, [r0, #36]
#else
	ldrd	r6, r7, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #40]
	ldr	r9, [r0, #44]
#else
	ldrd	r8, r9, [r0, #40]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #72]
	ldr	r9, [sp, #76]
#else
	ldrd	r8, r9, [sp, #72]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #72]
	ldr	r7, [r3, #76]
#else
	ldrd	r6, r7, [r3, #72]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #16]
	ldr	r9, [r0, #20]
#else
	ldrd	r8, r9, [r0, #16]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #48]
	str	r5, [r0, #52]
#else
	strd	r4, r5, [r0, #48]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #16]
	str	r9, [r0, #20]
#else
	strd	r8, r9, [r0, #16]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #56]
	ldr	r9, [r0, #60]
#else
	ldrd	r8, r9, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r6, r7}
#else
	ldrd	r6, r7, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #48]
	str	r5, [r0, #52]
#else
	strd	r4, r5, [r0, #48]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #48]
	ldr	r7, [r0, #52]
#else
	ldrd	r6, r7, [r0, #48]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #48]
	str	r7, [r0, #52]
#else
	strd	r6, r7, [r0, #48]
#endif
	mov	r10, r8
	mov	r11, r9
	# Calc new W[9]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #56]
	ldr	r5, [sp, #60]
#else
	ldrd	r4, r5, [sp, #56]
#endif
	lsrs	r6, r4, #19
	lsrs	r7, r5, #19
	orr	r7, r7, r4, lsl #13
	orr	r6, r6, r5, lsl #13
	lsls	r8, r4, #3
	lsls	r9, r5, #3
	orr	r9, r9, r4, lsr #29
	orr	r8, r8, r5, lsr #29
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #6
	lsrs	r9, r5, #6
	orr	r8, r8, r5, lsl #26
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #72]
	ldr	r5, [sp, #76]
#else
	ldrd	r4, r5, [sp, #72]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #16]
	ldr	r9, [sp, #20]
#else
	ldrd	r8, r9, [sp, #16]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #72]
	str	r5, [sp, #76]
#else
	strd	r4, r5, [sp, #72]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #80]
	ldr	r5, [sp, #84]
#else
	ldrd	r4, r5, [sp, #80]
#endif
	lsrs	r6, r4, #1
	lsrs	r7, r5, #1
	orr	r7, r7, r4, lsl #31
	orr	r6, r6, r5, lsl #31
	lsrs	r8, r4, #8
	lsrs	r9, r5, #8
	orr	r9, r9, r4, lsl #24
	orr	r8, r8, r5, lsl #24
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #7
	lsrs	r9, r5, #7
	orr	r8, r8, r5, lsl #25
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #72]
	ldr	r5, [sp, #76]
#else
	ldrd	r4, r5, [sp, #72]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #72]
	str	r5, [sp, #76]
#else
	strd	r4, r5, [sp, #72]
#endif
	# Round 10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #40]
	str	r5, [r0, #44]
#else
	strd	r4, r5, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #24]
	ldr	r7, [r0, #28]
#else
	ldrd	r6, r7, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #32]
	ldr	r9, [r0, #36]
#else
	ldrd	r8, r9, [r0, #32]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #80]
	ldr	r9, [sp, #84]
#else
	ldrd	r8, r9, [sp, #80]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #80]
	ldr	r7, [r3, #84]
#else
	ldrd	r6, r7, [r3, #80]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #8]
	ldr	r9, [r0, #12]
#else
	ldrd	r8, r9, [r0, #8]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #40]
	str	r5, [r0, #44]
#else
	strd	r4, r5, [r0, #40]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #8]
	str	r9, [r0, #12]
#else
	strd	r8, r9, [r0, #8]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #48]
	ldr	r9, [r0, #52]
#else
	ldrd	r8, r9, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #56]
	ldr	r7, [r0, #60]
#else
	ldrd	r6, r7, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #40]
	str	r5, [r0, #44]
#else
	strd	r4, r5, [r0, #40]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #40]
	ldr	r7, [r0, #44]
#else
	ldrd	r6, r7, [r0, #40]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #40]
	str	r7, [r0, #44]
#else
	strd	r6, r7, [r0, #40]
#endif
	mov	r10, r8
	mov	r11, r9
	# Calc new W[10]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #64]
	ldr	r5, [sp, #68]
#else
	ldrd	r4, r5, [sp, #64]
#endif
	lsrs	r6, r4, #19
	lsrs	r7, r5, #19
	orr	r7, r7, r4, lsl #13
	orr	r6, r6, r5, lsl #13
	lsls	r8, r4, #3
	lsls	r9, r5, #3
	orr	r9, r9, r4, lsr #29
	orr	r8, r8, r5, lsr #29
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #6
	lsrs	r9, r5, #6
	orr	r8, r8, r5, lsl #26
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #80]
	ldr	r5, [sp, #84]
#else
	ldrd	r4, r5, [sp, #80]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #24]
	ldr	r9, [sp, #28]
#else
	ldrd	r8, r9, [sp, #24]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #80]
	str	r5, [sp, #84]
#else
	strd	r4, r5, [sp, #80]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #88]
	ldr	r5, [sp, #92]
#else
	ldrd	r4, r5, [sp, #88]
#endif
	lsrs	r6, r4, #1
	lsrs	r7, r5, #1
	orr	r7, r7, r4, lsl #31
	orr	r6, r6, r5, lsl #31
	lsrs	r8, r4, #8
	lsrs	r9, r5, #8
	orr	r9, r9, r4, lsl #24
	orr	r8, r8, r5, lsl #24
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #7
	lsrs	r9, r5, #7
	orr	r8, r8, r5, lsl #25
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #80]
	ldr	r5, [sp, #84]
#else
	ldrd	r4, r5, [sp, #80]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #80]
	str	r5, [sp, #84]
#else
	strd	r4, r5, [sp, #80]
#endif
	# Round 11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #32]
	str	r5, [r0, #36]
#else
	strd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #16]
	ldr	r7, [r0, #20]
#else
	ldrd	r6, r7, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #24]
	ldr	r9, [r0, #28]
#else
	ldrd	r8, r9, [r0, #24]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #88]
	ldr	r9, [sp, #92]
#else
	ldrd	r8, r9, [sp, #88]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #88]
	ldr	r7, [r3, #92]
#else
	ldrd	r6, r7, [r3, #88]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r8, r9}
#else
	ldrd	r8, r9, [r0]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #32]
	str	r5, [r0, #36]
#else
	strd	r4, r5, [r0, #32]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r8, r9}
#else
	strd	r8, r9, [r0]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #40]
	ldr	r9, [r0, #44]
#else
	ldrd	r8, r9, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #48]
	ldr	r7, [r0, #52]
#else
	ldrd	r6, r7, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #32]
	str	r5, [r0, #36]
#else
	strd	r4, r5, [r0, #32]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #32]
	ldr	r7, [r0, #36]
#else
	ldrd	r6, r7, [r0, #32]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #32]
	str	r7, [r0, #36]
#else
	strd	r6, r7, [r0, #32]
#endif
	mov	r10, r8
	mov	r11, r9
	# Calc new W[11]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #72]
	ldr	r5, [sp, #76]
#else
	ldrd	r4, r5, [sp, #72]
#endif
	lsrs	r6, r4, #19
	lsrs	r7, r5, #19
	orr	r7, r7, r4, lsl #13
	orr	r6, r6, r5, lsl #13
	lsls	r8, r4, #3
	lsls	r9, r5, #3
	orr	r9, r9, r4, lsr #29
	orr	r8, r8, r5, lsr #29
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #6
	lsrs	r9, r5, #6
	orr	r8, r8, r5, lsl #26
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #88]
	ldr	r5, [sp, #92]
#else
	ldrd	r4, r5, [sp, #88]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #32]
	ldr	r9, [sp, #36]
#else
	ldrd	r8, r9, [sp, #32]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #88]
	str	r5, [sp, #92]
#else
	strd	r4, r5, [sp, #88]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #96]
	ldr	r5, [sp, #100]
#else
	ldrd	r4, r5, [sp, #96]
#endif
	lsrs	r6, r4, #1
	lsrs	r7, r5, #1
	orr	r7, r7, r4, lsl #31
	orr	r6, r6, r5, lsl #31
	lsrs	r8, r4, #8
	lsrs	r9, r5, #8
	orr	r9, r9, r4, lsl #24
	orr	r8, r8, r5, lsl #24
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #7
	lsrs	r9, r5, #7
	orr	r8, r8, r5, lsl #25
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #88]
	ldr	r5, [sp, #92]
#else
	ldrd	r4, r5, [sp, #88]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #88]
	str	r5, [sp, #92]
#else
	strd	r4, r5, [sp, #88]
#endif
	# Round 12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #24]
	str	r5, [r0, #28]
#else
	strd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
#else
	ldrd	r6, r7, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #16]
	ldr	r9, [r0, #20]
#else
	ldrd	r8, r9, [r0, #16]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #96]
	ldr	r9, [sp, #100]
#else
	ldrd	r8, r9, [sp, #96]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #96]
	ldr	r7, [r3, #100]
#else
	ldrd	r6, r7, [r3, #96]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #56]
	ldr	r9, [r0, #60]
#else
	ldrd	r8, r9, [r0, #56]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #24]
	str	r5, [r0, #28]
#else
	strd	r4, r5, [r0, #24]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #56]
	str	r9, [r0, #60]
#else
	strd	r8, r9, [r0, #56]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #32]
	ldr	r9, [r0, #36]
#else
	ldrd	r8, r9, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #40]
	ldr	r7, [r0, #44]
#else
	ldrd	r6, r7, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #24]
	str	r5, [r0, #28]
#else
	strd	r4, r5, [r0, #24]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #24]
	ldr	r7, [r0, #28]
#else
	ldrd	r6, r7, [r0, #24]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #24]
	str	r7, [r0, #28]
#else
	strd	r6, r7, [r0, #24]
#endif
	mov	r10, r8
	mov	r11, r9
	# Calc new W[12]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #80]
	ldr	r5, [sp, #84]
#else
	ldrd	r4, r5, [sp, #80]
#endif
	lsrs	r6, r4, #19
	lsrs	r7, r5, #19
	orr	r7, r7, r4, lsl #13
	orr	r6, r6, r5, lsl #13
	lsls	r8, r4, #3
	lsls	r9, r5, #3
	orr	r9, r9, r4, lsr #29
	orr	r8, r8, r5, lsr #29
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #6
	lsrs	r9, r5, #6
	orr	r8, r8, r5, lsl #26
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #96]
	ldr	r5, [sp, #100]
#else
	ldrd	r4, r5, [sp, #96]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #40]
	ldr	r9, [sp, #44]
#else
	ldrd	r8, r9, [sp, #40]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #96]
	str	r5, [sp, #100]
#else
	strd	r4, r5, [sp, #96]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #104]
	ldr	r5, [sp, #108]
#else
	ldrd	r4, r5, [sp, #104]
#endif
	lsrs	r6, r4, #1
	lsrs	r7, r5, #1
	orr	r7, r7, r4, lsl #31
	orr	r6, r6, r5, lsl #31
	lsrs	r8, r4, #8
	lsrs	r9, r5, #8
	orr	r9, r9, r4, lsl #24
	orr	r8, r8, r5, lsl #24
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #7
	lsrs	r9, r5, #7
	orr	r8, r8, r5, lsl #25
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #96]
	ldr	r5, [sp, #100]
#else
	ldrd	r4, r5, [sp, #96]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #96]
	str	r5, [sp, #100]
#else
	strd	r4, r5, [sp, #96]
#endif
	# Round 13
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #16]
	str	r5, [r0, #20]
#else
	strd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r6, r7}
#else
	ldrd	r6, r7, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #8]
	ldr	r9, [r0, #12]
#else
	ldrd	r8, r9, [r0, #8]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #104]
	ldr	r9, [sp, #108]
#else
	ldrd	r8, r9, [sp, #104]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #104]
	ldr	r7, [r3, #108]
#else
	ldrd	r6, r7, [r3, #104]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #48]
	ldr	r9, [r0, #52]
#else
	ldrd	r8, r9, [r0, #48]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #16]
	str	r5, [r0, #20]
#else
	strd	r4, r5, [r0, #16]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #48]
	str	r9, [r0, #52]
#else
	strd	r8, r9, [r0, #48]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #24]
	ldr	r9, [r0, #28]
#else
	ldrd	r8, r9, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #32]
	ldr	r7, [r0, #36]
#else
	ldrd	r6, r7, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #16]
	str	r5, [r0, #20]
#else
	strd	r4, r5, [r0, #16]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #16]
	ldr	r7, [r0, #20]
#else
	ldrd	r6, r7, [r0, #16]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #16]
	str	r7, [r0, #20]
#else
	strd	r6, r7, [r0, #16]
#endif
	mov	r10, r8
	mov	r11, r9
	# Calc new W[13]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #88]
	ldr	r5, [sp, #92]
#else
	ldrd	r4, r5, [sp, #88]
#endif
	lsrs	r6, r4, #19
	lsrs	r7, r5, #19
	orr	r7, r7, r4, lsl #13
	orr	r6, r6, r5, lsl #13
	lsls	r8, r4, #3
	lsls	r9, r5, #3
	orr	r9, r9, r4, lsr #29
	orr	r8, r8, r5, lsr #29
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #6
	lsrs	r9, r5, #6
	orr	r8, r8, r5, lsl #26
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #104]
	ldr	r5, [sp, #108]
#else
	ldrd	r4, r5, [sp, #104]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #48]
	ldr	r9, [sp, #52]
#else
	ldrd	r8, r9, [sp, #48]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #104]
	str	r5, [sp, #108]
#else
	strd	r4, r5, [sp, #104]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #112]
	ldr	r5, [sp, #116]
#else
	ldrd	r4, r5, [sp, #112]
#endif
	lsrs	r6, r4, #1
	lsrs	r7, r5, #1
	orr	r7, r7, r4, lsl #31
	orr	r6, r6, r5, lsl #31
	lsrs	r8, r4, #8
	lsrs	r9, r5, #8
	orr	r9, r9, r4, lsl #24
	orr	r8, r8, r5, lsl #24
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #7
	lsrs	r9, r5, #7
	orr	r8, r8, r5, lsl #25
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #104]
	ldr	r5, [sp, #108]
#else
	ldrd	r4, r5, [sp, #104]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #104]
	str	r5, [sp, #108]
#else
	strd	r4, r5, [sp, #104]
#endif
	# Round 14
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #8]
	str	r5, [r0, #12]
#else
	strd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #56]
	ldr	r7, [r0, #60]
#else
	ldrd	r6, r7, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r8, r9}
#else
	ldrd	r8, r9, [r0]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #112]
	ldr	r9, [sp, #116]
#else
	ldrd	r8, r9, [sp, #112]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #112]
	ldr	r7, [r3, #116]
#else
	ldrd	r6, r7, [r3, #112]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #40]
	ldr	r9, [r0, #44]
#else
	ldrd	r8, r9, [r0, #40]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #8]
	str	r5, [r0, #12]
#else
	strd	r4, r5, [r0, #8]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #40]
	str	r9, [r0, #44]
#else
	strd	r8, r9, [r0, #40]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #16]
	ldr	r9, [r0, #20]
#else
	ldrd	r8, r9, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #24]
	ldr	r7, [r0, #28]
#else
	ldrd	r6, r7, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #8]
	str	r5, [r0, #12]
#else
	strd	r4, r5, [r0, #8]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
#else
	ldrd	r6, r7, [r0, #8]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #8]
	str	r7, [r0, #12]
#else
	strd	r6, r7, [r0, #8]
#endif
	mov	r10, r8
	mov	r11, r9
	# Calc new W[14]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #96]
	ldr	r5, [sp, #100]
#else
	ldrd	r4, r5, [sp, #96]
#endif
	lsrs	r6, r4, #19
	lsrs	r7, r5, #19
	orr	r7, r7, r4, lsl #13
	orr	r6, r6, r5, lsl #13
	lsls	r8, r4, #3
	lsls	r9, r5, #3
	orr	r9, r9, r4, lsr #29
	orr	r8, r8, r5, lsr #29
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #6
	lsrs	r9, r5, #6
	orr	r8, r8, r5, lsl #26
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #112]
	ldr	r5, [sp, #116]
#else
	ldrd	r4, r5, [sp, #112]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #56]
	ldr	r9, [sp, #60]
#else
	ldrd	r8, r9, [sp, #56]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #112]
	str	r5, [sp, #116]
#else
	strd	r4, r5, [sp, #112]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #120]
	ldr	r5, [sp, #124]
#else
	ldrd	r4, r5, [sp, #120]
#endif
	lsrs	r6, r4, #1
	lsrs	r7, r5, #1
	orr	r7, r7, r4, lsl #31
	orr	r6, r6, r5, lsl #31
	lsrs	r8, r4, #8
	lsrs	r9, r5, #8
	orr	r9, r9, r4, lsl #24
	orr	r8, r8, r5, lsl #24
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #7
	lsrs	r9, r5, #7
	orr	r8, r8, r5, lsl #25
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #112]
	ldr	r5, [sp, #116]
#else
	ldrd	r4, r5, [sp, #112]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #112]
	str	r5, [sp, #116]
#else
	strd	r4, r5, [sp, #112]
#endif
	# Round 15
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r4, r5}
#else
	strd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #48]
	ldr	r7, [r0, #52]
#else
	ldrd	r6, r7, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #56]
	ldr	r9, [r0, #60]
#else
	ldrd	r8, r9, [r0, #56]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #120]
	ldr	r9, [sp, #124]
#else
	ldrd	r8, r9, [sp, #120]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #120]
	ldr	r7, [r3, #124]
#else
	ldrd	r6, r7, [r3, #120]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #32]
	ldr	r9, [r0, #36]
#else
	ldrd	r8, r9, [r0, #32]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r4, r5}
#else
	strd	r4, r5, [r0]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #32]
	str	r9, [r0, #36]
#else
	strd	r8, r9, [r0, #32]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #8]
	ldr	r9, [r0, #12]
#else
	ldrd	r8, r9, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #16]
	ldr	r7, [r0, #20]
#else
	ldrd	r6, r7, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r4, r5}
#else
	strd	r4, r5, [r0]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r6, r7}
#else
	ldrd	r6, r7, [r0]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r6, r7}
#else
	strd	r6, r7, [r0]
#endif
	mov	r10, r8
	mov	r11, r9
	# Calc new W[15]
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #104]
	ldr	r5, [sp, #108]
#else
	ldrd	r4, r5, [sp, #104]
#endif
	lsrs	r6, r4, #19
	lsrs	r7, r5, #19
	orr	r7, r7, r4, lsl #13
	orr	r6, r6, r5, lsl #13
	lsls	r8, r4, #3
	lsls	r9, r5, #3
	orr	r9, r9, r4, lsr #29
	orr	r8, r8, r5, lsr #29
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #6
	lsrs	r9, r5, #6
	orr	r8, r8, r5, lsl #26
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #120]
	ldr	r5, [sp, #124]
#else
	ldrd	r4, r5, [sp, #120]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #64]
	ldr	r9, [sp, #68]
#else
	ldrd	r8, r9, [sp, #64]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #120]
	str	r5, [sp, #124]
#else
	strd	r4, r5, [sp, #120]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	sp, {r4, r5}
#else
	ldrd	r4, r5, [sp]
#endif
	lsrs	r6, r4, #1
	lsrs	r7, r5, #1
	orr	r7, r7, r4, lsl #31
	orr	r6, r6, r5, lsl #31
	lsrs	r8, r4, #8
	lsrs	r9, r5, #8
	orr	r9, r9, r4, lsl #24
	orr	r8, r8, r5, lsl #24
	eor	r7, r7, r9
	eor	r6, r6, r8
	lsrs	r8, r4, #7
	lsrs	r9, r5, #7
	orr	r8, r8, r5, lsl #25
	eor	r7, r7, r9
	eor	r6, r6, r8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [sp, #120]
	ldr	r5, [sp, #124]
#else
	ldrd	r4, r5, [sp, #120]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #120]
	str	r5, [sp, #124]
#else
	strd	r4, r5, [sp, #120]
#endif
	add	r3, r3, #0x80
	subs	r12, r12, #1
	bne	L_SHA512_transform_len_start
	# Round 0
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #56]
	str	r5, [r0, #60]
#else
	strd	r4, r5, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #40]
	ldr	r7, [r0, #44]
#else
	ldrd	r6, r7, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #48]
	ldr	r9, [r0, #52]
#else
	ldrd	r8, r9, [r0, #48]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	sp, {r8, r9}
#else
	ldrd	r8, r9, [sp]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r3, {r6, r7}
#else
	ldrd	r6, r7, [r3]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #24]
	ldr	r9, [r0, #28]
#else
	ldrd	r8, r9, [r0, #24]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #56]
	str	r5, [r0, #60]
#else
	strd	r4, r5, [r0, #56]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #24]
	str	r9, [r0, #28]
#else
	strd	r8, r9, [r0, #24]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r8, r9}
#else
	ldrd	r8, r9, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
#else
	ldrd	r6, r7, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #56]
	str	r5, [r0, #60]
#else
	strd	r4, r5, [r0, #56]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #56]
	ldr	r7, [r0, #60]
#else
	ldrd	r6, r7, [r0, #56]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #56]
	str	r7, [r0, #60]
#else
	strd	r6, r7, [r0, #56]
#endif
	mov	r10, r8
	mov	r11, r9
	# Round 1
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #48]
	str	r5, [r0, #52]
#else
	strd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #32]
	ldr	r7, [r0, #36]
#else
	ldrd	r6, r7, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #40]
	ldr	r9, [r0, #44]
#else
	ldrd	r8, r9, [r0, #40]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #8]
	ldr	r9, [sp, #12]
#else
	ldrd	r8, r9, [sp, #8]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #8]
	ldr	r7, [r3, #12]
#else
	ldrd	r6, r7, [r3, #8]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #16]
	ldr	r9, [r0, #20]
#else
	ldrd	r8, r9, [r0, #16]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #48]
	str	r5, [r0, #52]
#else
	strd	r4, r5, [r0, #48]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #16]
	str	r9, [r0, #20]
#else
	strd	r8, r9, [r0, #16]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #56]
	ldr	r9, [r0, #60]
#else
	ldrd	r8, r9, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r6, r7}
#else
	ldrd	r6, r7, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #48]
	str	r5, [r0, #52]
#else
	strd	r4, r5, [r0, #48]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #48]
	ldr	r7, [r0, #52]
#else
	ldrd	r6, r7, [r0, #48]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #48]
	str	r7, [r0, #52]
#else
	strd	r6, r7, [r0, #48]
#endif
	mov	r10, r8
	mov	r11, r9
	# Round 2
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #40]
	str	r5, [r0, #44]
#else
	strd	r4, r5, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #24]
	ldr	r7, [r0, #28]
#else
	ldrd	r6, r7, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #32]
	ldr	r9, [r0, #36]
#else
	ldrd	r8, r9, [r0, #32]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #16]
	ldr	r9, [sp, #20]
#else
	ldrd	r8, r9, [sp, #16]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #16]
	ldr	r7, [r3, #20]
#else
	ldrd	r6, r7, [r3, #16]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #8]
	ldr	r9, [r0, #12]
#else
	ldrd	r8, r9, [r0, #8]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #40]
	str	r5, [r0, #44]
#else
	strd	r4, r5, [r0, #40]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #8]
	str	r9, [r0, #12]
#else
	strd	r8, r9, [r0, #8]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #48]
	ldr	r9, [r0, #52]
#else
	ldrd	r8, r9, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #56]
	ldr	r7, [r0, #60]
#else
	ldrd	r6, r7, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #40]
	str	r5, [r0, #44]
#else
	strd	r4, r5, [r0, #40]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #40]
	ldr	r7, [r0, #44]
#else
	ldrd	r6, r7, [r0, #40]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #40]
	str	r7, [r0, #44]
#else
	strd	r6, r7, [r0, #40]
#endif
	mov	r10, r8
	mov	r11, r9
	# Round 3
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #32]
	str	r5, [r0, #36]
#else
	strd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #16]
	ldr	r7, [r0, #20]
#else
	ldrd	r6, r7, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #24]
	ldr	r9, [r0, #28]
#else
	ldrd	r8, r9, [r0, #24]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #24]
	ldr	r9, [sp, #28]
#else
	ldrd	r8, r9, [sp, #24]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #24]
	ldr	r7, [r3, #28]
#else
	ldrd	r6, r7, [r3, #24]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r8, r9}
#else
	ldrd	r8, r9, [r0]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #32]
	str	r5, [r0, #36]
#else
	strd	r4, r5, [r0, #32]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r8, r9}
#else
	strd	r8, r9, [r0]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #40]
	ldr	r9, [r0, #44]
#else
	ldrd	r8, r9, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #48]
	ldr	r7, [r0, #52]
#else
	ldrd	r6, r7, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #32]
	str	r5, [r0, #36]
#else
	strd	r4, r5, [r0, #32]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #32]
	ldr	r7, [r0, #36]
#else
	ldrd	r6, r7, [r0, #32]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #32]
	str	r7, [r0, #36]
#else
	strd	r6, r7, [r0, #32]
#endif
	mov	r10, r8
	mov	r11, r9
	# Round 4
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #24]
	str	r5, [r0, #28]
#else
	strd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
#else
	ldrd	r6, r7, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #16]
	ldr	r9, [r0, #20]
#else
	ldrd	r8, r9, [r0, #16]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #32]
	ldr	r9, [sp, #36]
#else
	ldrd	r8, r9, [sp, #32]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #32]
	ldr	r7, [r3, #36]
#else
	ldrd	r6, r7, [r3, #32]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #56]
	ldr	r9, [r0, #60]
#else
	ldrd	r8, r9, [r0, #56]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #24]
	str	r5, [r0, #28]
#else
	strd	r4, r5, [r0, #24]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #56]
	str	r9, [r0, #60]
#else
	strd	r8, r9, [r0, #56]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #32]
	ldr	r9, [r0, #36]
#else
	ldrd	r8, r9, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #40]
	ldr	r7, [r0, #44]
#else
	ldrd	r6, r7, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #24]
	str	r5, [r0, #28]
#else
	strd	r4, r5, [r0, #24]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #24]
	ldr	r7, [r0, #28]
#else
	ldrd	r6, r7, [r0, #24]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #24]
	str	r7, [r0, #28]
#else
	strd	r6, r7, [r0, #24]
#endif
	mov	r10, r8
	mov	r11, r9
	# Round 5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #16]
	str	r5, [r0, #20]
#else
	strd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r6, r7}
#else
	ldrd	r6, r7, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #8]
	ldr	r9, [r0, #12]
#else
	ldrd	r8, r9, [r0, #8]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #40]
	ldr	r9, [sp, #44]
#else
	ldrd	r8, r9, [sp, #40]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #40]
	ldr	r7, [r3, #44]
#else
	ldrd	r6, r7, [r3, #40]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #48]
	ldr	r9, [r0, #52]
#else
	ldrd	r8, r9, [r0, #48]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #16]
	str	r5, [r0, #20]
#else
	strd	r4, r5, [r0, #16]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #48]
	str	r9, [r0, #52]
#else
	strd	r8, r9, [r0, #48]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #24]
	ldr	r9, [r0, #28]
#else
	ldrd	r8, r9, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #32]
	ldr	r7, [r0, #36]
#else
	ldrd	r6, r7, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #16]
	str	r5, [r0, #20]
#else
	strd	r4, r5, [r0, #16]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #16]
	ldr	r7, [r0, #20]
#else
	ldrd	r6, r7, [r0, #16]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #16]
	str	r7, [r0, #20]
#else
	strd	r6, r7, [r0, #16]
#endif
	mov	r10, r8
	mov	r11, r9
	# Round 6
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #8]
	str	r5, [r0, #12]
#else
	strd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #56]
	ldr	r7, [r0, #60]
#else
	ldrd	r6, r7, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r8, r9}
#else
	ldrd	r8, r9, [r0]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #48]
	ldr	r9, [sp, #52]
#else
	ldrd	r8, r9, [sp, #48]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #48]
	ldr	r7, [r3, #52]
#else
	ldrd	r6, r7, [r3, #48]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #40]
	ldr	r9, [r0, #44]
#else
	ldrd	r8, r9, [r0, #40]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #8]
	str	r5, [r0, #12]
#else
	strd	r4, r5, [r0, #8]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #40]
	str	r9, [r0, #44]
#else
	strd	r8, r9, [r0, #40]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #16]
	ldr	r9, [r0, #20]
#else
	ldrd	r8, r9, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #24]
	ldr	r7, [r0, #28]
#else
	ldrd	r6, r7, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #8]
	str	r5, [r0, #12]
#else
	strd	r4, r5, [r0, #8]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
#else
	ldrd	r6, r7, [r0, #8]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #8]
	str	r7, [r0, #12]
#else
	strd	r6, r7, [r0, #8]
#endif
	mov	r10, r8
	mov	r11, r9
	# Round 7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r4, r5}
#else
	strd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #48]
	ldr	r7, [r0, #52]
#else
	ldrd	r6, r7, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #56]
	ldr	r9, [r0, #60]
#else
	ldrd	r8, r9, [r0, #56]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #56]
	ldr	r9, [sp, #60]
#else
	ldrd	r8, r9, [sp, #56]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #56]
	ldr	r7, [r3, #60]
#else
	ldrd	r6, r7, [r3, #56]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #32]
	ldr	r9, [r0, #36]
#else
	ldrd	r8, r9, [r0, #32]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r4, r5}
#else
	strd	r4, r5, [r0]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #32]
	str	r9, [r0, #36]
#else
	strd	r8, r9, [r0, #32]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #8]
	ldr	r9, [r0, #12]
#else
	ldrd	r8, r9, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #16]
	ldr	r7, [r0, #20]
#else
	ldrd	r6, r7, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r4, r5}
#else
	strd	r4, r5, [r0]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r6, r7}
#else
	ldrd	r6, r7, [r0]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r6, r7}
#else
	strd	r6, r7, [r0]
#endif
	mov	r10, r8
	mov	r11, r9
	# Round 8
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #56]
	str	r5, [r0, #60]
#else
	strd	r4, r5, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #40]
	ldr	r7, [r0, #44]
#else
	ldrd	r6, r7, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #48]
	ldr	r9, [r0, #52]
#else
	ldrd	r8, r9, [r0, #48]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #64]
	ldr	r9, [sp, #68]
#else
	ldrd	r8, r9, [sp, #64]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #64]
	ldr	r7, [r3, #68]
#else
	ldrd	r6, r7, [r3, #64]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #24]
	ldr	r9, [r0, #28]
#else
	ldrd	r8, r9, [r0, #24]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #56]
	str	r5, [r0, #60]
#else
	strd	r4, r5, [r0, #56]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #24]
	str	r9, [r0, #28]
#else
	strd	r8, r9, [r0, #24]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r8, r9}
#else
	ldrd	r8, r9, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
#else
	ldrd	r6, r7, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #56]
	str	r5, [r0, #60]
#else
	strd	r4, r5, [r0, #56]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #56]
	ldr	r7, [r0, #60]
#else
	ldrd	r6, r7, [r0, #56]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #56]
	str	r7, [r0, #60]
#else
	strd	r6, r7, [r0, #56]
#endif
	mov	r10, r8
	mov	r11, r9
	# Round 9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #48]
	str	r5, [r0, #52]
#else
	strd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #32]
	ldr	r7, [r0, #36]
#else
	ldrd	r6, r7, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #40]
	ldr	r9, [r0, #44]
#else
	ldrd	r8, r9, [r0, #40]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #72]
	ldr	r9, [sp, #76]
#else
	ldrd	r8, r9, [sp, #72]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #72]
	ldr	r7, [r3, #76]
#else
	ldrd	r6, r7, [r3, #72]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #16]
	ldr	r9, [r0, #20]
#else
	ldrd	r8, r9, [r0, #16]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #48]
	str	r5, [r0, #52]
#else
	strd	r4, r5, [r0, #48]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #16]
	str	r9, [r0, #20]
#else
	strd	r8, r9, [r0, #16]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #56]
	ldr	r9, [r0, #60]
#else
	ldrd	r8, r9, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r6, r7}
#else
	ldrd	r6, r7, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #48]
	str	r5, [r0, #52]
#else
	strd	r4, r5, [r0, #48]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #48]
	ldr	r7, [r0, #52]
#else
	ldrd	r6, r7, [r0, #48]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #48]
	str	r7, [r0, #52]
#else
	strd	r6, r7, [r0, #48]
#endif
	mov	r10, r8
	mov	r11, r9
	# Round 10
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #40]
	str	r5, [r0, #44]
#else
	strd	r4, r5, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #24]
	ldr	r7, [r0, #28]
#else
	ldrd	r6, r7, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #32]
	ldr	r9, [r0, #36]
#else
	ldrd	r8, r9, [r0, #32]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #80]
	ldr	r9, [sp, #84]
#else
	ldrd	r8, r9, [sp, #80]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #80]
	ldr	r7, [r3, #84]
#else
	ldrd	r6, r7, [r3, #80]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #8]
	ldr	r9, [r0, #12]
#else
	ldrd	r8, r9, [r0, #8]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #40]
	str	r5, [r0, #44]
#else
	strd	r4, r5, [r0, #40]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #8]
	str	r9, [r0, #12]
#else
	strd	r8, r9, [r0, #8]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #48]
	ldr	r9, [r0, #52]
#else
	ldrd	r8, r9, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #56]
	ldr	r7, [r0, #60]
#else
	ldrd	r6, r7, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #40]
	str	r5, [r0, #44]
#else
	strd	r4, r5, [r0, #40]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #40]
	ldr	r7, [r0, #44]
#else
	ldrd	r6, r7, [r0, #40]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #40]
	str	r7, [r0, #44]
#else
	strd	r6, r7, [r0, #40]
#endif
	mov	r10, r8
	mov	r11, r9
	# Round 11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #32]
	str	r5, [r0, #36]
#else
	strd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #16]
	ldr	r7, [r0, #20]
#else
	ldrd	r6, r7, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #24]
	ldr	r9, [r0, #28]
#else
	ldrd	r8, r9, [r0, #24]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #88]
	ldr	r9, [sp, #92]
#else
	ldrd	r8, r9, [sp, #88]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #88]
	ldr	r7, [r3, #92]
#else
	ldrd	r6, r7, [r3, #88]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r8, r9}
#else
	ldrd	r8, r9, [r0]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #32]
	str	r5, [r0, #36]
#else
	strd	r4, r5, [r0, #32]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r8, r9}
#else
	strd	r8, r9, [r0]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #40]
	ldr	r9, [r0, #44]
#else
	ldrd	r8, r9, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #48]
	ldr	r7, [r0, #52]
#else
	ldrd	r6, r7, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #32]
	str	r5, [r0, #36]
#else
	strd	r4, r5, [r0, #32]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #32]
	ldr	r7, [r0, #36]
#else
	ldrd	r6, r7, [r0, #32]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #32]
	str	r7, [r0, #36]
#else
	strd	r6, r7, [r0, #32]
#endif
	mov	r10, r8
	mov	r11, r9
	# Round 12
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #24]
	str	r5, [r0, #28]
#else
	strd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
#else
	ldrd	r6, r7, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #16]
	ldr	r9, [r0, #20]
#else
	ldrd	r8, r9, [r0, #16]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #96]
	ldr	r9, [sp, #100]
#else
	ldrd	r8, r9, [sp, #96]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #96]
	ldr	r7, [r3, #100]
#else
	ldrd	r6, r7, [r3, #96]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #56]
	ldr	r9, [r0, #60]
#else
	ldrd	r8, r9, [r0, #56]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #24]
	str	r5, [r0, #28]
#else
	strd	r4, r5, [r0, #24]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #56]
	str	r9, [r0, #60]
#else
	strd	r8, r9, [r0, #56]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #32]
	ldr	r9, [r0, #36]
#else
	ldrd	r8, r9, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #40]
	ldr	r7, [r0, #44]
#else
	ldrd	r6, r7, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #24]
	str	r5, [r0, #28]
#else
	strd	r4, r5, [r0, #24]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #24]
	ldr	r7, [r0, #28]
#else
	ldrd	r6, r7, [r0, #24]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #24]
	str	r7, [r0, #28]
#else
	strd	r6, r7, [r0, #24]
#endif
	mov	r10, r8
	mov	r11, r9
	# Round 13
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #16]
	str	r5, [r0, #20]
#else
	strd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
#else
	ldrd	r4, r5, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r6, r7}
#else
	ldrd	r6, r7, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #8]
	ldr	r9, [r0, #12]
#else
	ldrd	r8, r9, [r0, #8]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #104]
	ldr	r9, [sp, #108]
#else
	ldrd	r8, r9, [sp, #104]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #104]
	ldr	r7, [r3, #108]
#else
	ldrd	r6, r7, [r3, #104]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #48]
	ldr	r9, [r0, #52]
#else
	ldrd	r8, r9, [r0, #48]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #16]
	str	r5, [r0, #20]
#else
	strd	r4, r5, [r0, #16]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
#else
	ldrd	r4, r5, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #48]
	str	r9, [r0, #52]
#else
	strd	r8, r9, [r0, #48]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #24]
	ldr	r9, [r0, #28]
#else
	ldrd	r8, r9, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #32]
	ldr	r7, [r0, #36]
#else
	ldrd	r6, r7, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #16]
	str	r5, [r0, #20]
#else
	strd	r4, r5, [r0, #16]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #16]
	ldr	r7, [r0, #20]
#else
	ldrd	r6, r7, [r0, #16]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #16]
	str	r7, [r0, #20]
#else
	strd	r6, r7, [r0, #16]
#endif
	mov	r10, r8
	mov	r11, r9
	# Round 14
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #8]
	str	r5, [r0, #12]
#else
	strd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #56]
	ldr	r7, [r0, #60]
#else
	ldrd	r6, r7, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r8, r9}
#else
	ldrd	r8, r9, [r0]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #112]
	ldr	r9, [sp, #116]
#else
	ldrd	r8, r9, [sp, #112]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #112]
	ldr	r7, [r3, #116]
#else
	ldrd	r6, r7, [r3, #112]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #40]
	ldr	r9, [r0, #44]
#else
	ldrd	r8, r9, [r0, #40]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #8]
	str	r5, [r0, #12]
#else
	strd	r4, r5, [r0, #8]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #40]
	str	r9, [r0, #44]
#else
	strd	r8, r9, [r0, #40]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #16]
	ldr	r9, [r0, #20]
#else
	ldrd	r8, r9, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #24]
	ldr	r7, [r0, #28]
#else
	ldrd	r6, r7, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #8]
	str	r5, [r0, #12]
#else
	strd	r4, r5, [r0, #8]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
#else
	ldrd	r6, r7, [r0, #8]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #8]
	str	r7, [r0, #12]
#else
	strd	r6, r7, [r0, #8]
#endif
	mov	r10, r8
	mov	r11, r9
	# Round 15
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
	lsrs	r6, r4, #14
	lsrs	r7, r5, #14
	orr	r7, r7, r4, lsl #18
	orr	r6, r6, r5, lsl #18
	lsrs	r8, r4, #18
	lsrs	r9, r5, #18
	orr	r9, r9, r4, lsl #14
	orr	r8, r8, r5, lsl #14
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #23
	lsls	r9, r5, #23
	orr	r9, r9, r4, lsr #9
	orr	r8, r8, r5, lsr #9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r4, r5}
#else
	strd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
#else
	ldrd	r4, r5, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #48]
	ldr	r7, [r0, #52]
#else
	ldrd	r6, r7, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #56]
	ldr	r9, [r0, #60]
#else
	ldrd	r8, r9, [r0, #56]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	and	r6, r6, r4
	and	r7, r7, r5
	eor	r6, r6, r8
	eor	r7, r7, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #120]
	ldr	r9, [sp, #124]
#else
	ldrd	r8, r9, [sp, #120]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r3, #120]
	ldr	r7, [r3, #124]
#else
	ldrd	r6, r7, [r3, #120]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #32]
	ldr	r9, [r0, #36]
#else
	ldrd	r8, r9, [r0, #32]
#endif
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r4, r5}
#else
	strd	r4, r5, [r0]
#endif
	adds	r8, r8, r4
	adc	r9, r9, r5
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
#else
	ldrd	r4, r5, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r8, [r0, #32]
	str	r9, [r0, #36]
#else
	strd	r8, r9, [r0, #32]
#endif
	lsrs	r6, r4, #28
	lsrs	r7, r5, #28
	orr	r7, r7, r4, lsl #4
	orr	r6, r6, r5, lsl #4
	lsls	r8, r4, #30
	lsls	r9, r5, #30
	orr	r9, r9, r4, lsr #2
	orr	r8, r8, r5, lsr #2
	eor	r6, r6, r8
	eor	r7, r7, r9
	lsls	r8, r4, #25
	lsls	r9, r5, #25
	orr	r9, r9, r4, lsr #7
	orr	r8, r8, r5, lsr #7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
	eor	r6, r6, r8
	eor	r7, r7, r9
	adds	r4, r4, r6
	adc	r5, r5, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [r0, #8]
	ldr	r9, [r0, #12]
#else
	ldrd	r8, r9, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #16]
	ldr	r7, [r0, #20]
#else
	ldrd	r6, r7, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r4, r5}
#else
	strd	r4, r5, [r0]
#endif
	eor	r8, r8, r6
	eor	r9, r9, r7
	and	r10, r10, r8
	and	r11, r11, r9
	eor	r10, r10, r6
	eor	r11, r11, r7
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r6, r7}
#else
	ldrd	r6, r7, [r0]
#endif
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r6, r7}
#else
	strd	r6, r7, [r0]
#endif
	mov	r10, r8
	mov	r11, r9
	# Add in digest from start
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldm	r0, {r4, r5}
#else
	ldrd	r4, r5, [r0]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #8]
	ldr	r7, [r0, #12]
#else
	ldrd	r6, r7, [r0, #8]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #128]
	ldr	r9, [sp, #132]
#else
	ldrd	r8, r9, [sp, #128]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #136]
	ldr	r11, [sp, #140]
#else
	ldrd	r10, r11, [sp, #136]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	stm	r0, {r4, r5}
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
	str	r4, [sp, #128]
	str	r5, [sp, #132]
#else
	strd	r4, r5, [sp, #128]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [sp, #136]
	str	r7, [sp, #140]
#else
	strd	r6, r7, [sp, #136]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
#else
	ldrd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #24]
	ldr	r7, [r0, #28]
#else
	ldrd	r6, r7, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #144]
	ldr	r9, [sp, #148]
#else
	ldrd	r8, r9, [sp, #144]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #152]
	ldr	r11, [sp, #156]
#else
	ldrd	r10, r11, [sp, #152]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #16]
	str	r5, [r0, #20]
#else
	strd	r4, r5, [r0, #16]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #24]
	str	r7, [r0, #28]
#else
	strd	r6, r7, [r0, #24]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #144]
	str	r5, [sp, #148]
#else
	strd	r4, r5, [sp, #144]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [sp, #152]
	str	r7, [sp, #156]
#else
	strd	r6, r7, [sp, #152]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #32]
	ldr	r5, [r0, #36]
#else
	ldrd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #40]
	ldr	r7, [r0, #44]
#else
	ldrd	r6, r7, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #160]
	ldr	r9, [sp, #164]
#else
	ldrd	r8, r9, [sp, #160]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #168]
	ldr	r11, [sp, #172]
#else
	ldrd	r10, r11, [sp, #168]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #32]
	str	r5, [r0, #36]
#else
	strd	r4, r5, [r0, #32]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #40]
	str	r7, [r0, #44]
#else
	strd	r6, r7, [r0, #40]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #160]
	str	r5, [sp, #164]
#else
	strd	r4, r5, [sp, #160]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [sp, #168]
	str	r7, [sp, #172]
#else
	strd	r6, r7, [sp, #168]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
#else
	ldrd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r6, [r0, #56]
	ldr	r7, [r0, #60]
#else
	ldrd	r6, r7, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r8, [sp, #176]
	ldr	r9, [sp, #180]
#else
	ldrd	r8, r9, [sp, #176]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	ldr	r10, [sp, #184]
	ldr	r11, [sp, #188]
#else
	ldrd	r10, r11, [sp, #184]
#endif
	adds	r4, r4, r8
	adc	r5, r5, r9
	adds	r6, r6, r10
	adc	r7, r7, r11
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [r0, #48]
	str	r5, [r0, #52]
#else
	strd	r4, r5, [r0, #48]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [r0, #56]
	str	r7, [r0, #60]
#else
	strd	r6, r7, [r0, #56]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r4, [sp, #176]
	str	r5, [sp, #180]
#else
	strd	r4, r5, [sp, #176]
#endif
#if defined(WOLFSSL_ARM_ARCH) && (WOLFSSL_ARM_ARCH < 7)
	str	r6, [sp, #184]
	str	r7, [sp, #188]
#else
	strd	r6, r7, [sp, #184]
#endif
	subs	r2, r2, #0x80
	sub	r3, r3, #0x200
	add	r1, r1, #0x80
	bne	L_SHA512_transform_len_begin
	eor	r0, r0, r0
	add	sp, sp, #0xc0
	pop	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	.size	Transform_Sha512_Len_base,.-Transform_Sha512_Len_base
#endif /* WOLFSSL_ARMASM_NO_NEON */
#ifndef WOLFSSL_ARMASM_NO_NEON
#ifndef __APPLE__
	.text
	.type	L_SHA512_transform_neon_len_k, %object
	.size	L_SHA512_transform_neon_len_k, 640
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_SHA512_transform_neon_len_k:
	.quad	0x428a2f98d728ae22,0x7137449123ef65cd
	.quad	0xb5c0fbcfec4d3b2f,0xe9b5dba58189dbbc
	.quad	0x3956c25bf348b538,0x59f111f1b605d019
	.quad	0x923f82a4af194f9b,0xab1c5ed5da6d8118
	.quad	0xd807aa98a3030242,0x12835b0145706fbe
	.quad	0x243185be4ee4b28c,0x550c7dc3d5ffb4e2
	.quad	0x72be5d74f27b896f,0x80deb1fe3b1696b1
	.quad	0x9bdc06a725c71235,0xc19bf174cf692694
	.quad	0xe49b69c19ef14ad2,0xefbe4786384f25e3
	.quad	0x0fc19dc68b8cd5b5,0x240ca1cc77ac9c65
	.quad	0x2de92c6f592b0275,0x4a7484aa6ea6e483
	.quad	0x5cb0a9dcbd41fbd4,0x76f988da831153b5
	.quad	0x983e5152ee66dfab,0xa831c66d2db43210
	.quad	0xb00327c898fb213f,0xbf597fc7beef0ee4
	.quad	0xc6e00bf33da88fc2,0xd5a79147930aa725
	.quad	0x06ca6351e003826f,0x142929670a0e6e70
	.quad	0x27b70a8546d22ffc,0x2e1b21385c26c926
	.quad	0x4d2c6dfc5ac42aed,0x53380d139d95b3df
	.quad	0x650a73548baf63de,0x766a0abb3c77b2a8
	.quad	0x81c2c92e47edaee6,0x92722c851482353b
	.quad	0xa2bfe8a14cf10364,0xa81a664bbc423001
	.quad	0xc24b8b70d0f89791,0xc76c51a30654be30
	.quad	0xd192e819d6ef5218,0xd69906245565a910
	.quad	0xf40e35855771202a,0x106aa07032bbd1b8
	.quad	0x19a4c116b8d2d0c8,0x1e376c085141ab53
	.quad	0x2748774cdf8eeb99,0x34b0bcb5e19b48a8
	.quad	0x391c0cb3c5c95a63,0x4ed8aa4ae3418acb
	.quad	0x5b9cca4f7763e373,0x682e6ff3d6b2b8a3
	.quad	0x748f82ee5defb2fc,0x78a5636f43172f60
	.quad	0x84c87814a1f0ab72,0x8cc702081a6439ec
	.quad	0x90befffa23631e28,0xa4506cebde82bde9
	.quad	0xbef9a3f7b2c67915,0xc67178f2e372532b
	.quad	0xca273eceea26619c,0xd186b8c721c0c207
	.quad	0xeada7dd6cde0eb1e,0xf57d4f7fee6ed178
	.quad	0x06f067aa72176fba,0x0a637dc5a2c898a6
	.quad	0x113f9804bef90dae,0x1b710b35131c471b
	.quad	0x28db77f523047d84,0x32caab7b40c72493
	.quad	0x3c9ebe0a15c9bebc,0x431d67c49c100d4c
	.quad	0x4cc5d4becb3e42b6,0x597f299cfc657e2a
	.quad	0x5fcb6fab3ad6faec,0x6c44198c4a475817
	.text
	.align	4
	.fpu	neon
	.globl	Transform_Sha512_Len_neon
	.type	Transform_Sha512_Len_neon, %function
Transform_Sha512_Len_neon:
	vpush	{d8-d15}
	adr	r3, L_SHA512_transform_neon_len_k
	# Load digest into working vars
	vldm.64	r0, {d0-d7}
	# Start of loop processing a block
L_SHA512_transform_neon_len_begin:
	# Load W
	vld1.8	{q8-q9}, [r1]!
	vld1.8	{q10-q11}, [r1]!
	vld1.8	{q12-q13}, [r1]!
	vld1.8	{q14-q15}, [r1]!
#ifndef WOLFSSL_ARM_ARCH_NEON_64BIT
	vrev64.8	q8, q8
	vrev64.8	q9, q9
	vrev64.8	q10, q10
	vrev64.8	q11, q11
	vrev64.8	q12, q12
	vrev64.8	q13, q13
	vrev64.8	q14, q14
	vrev64.8	q15, q15
#else
	vrev64.8	d16, d16
	vrev64.8	d17, d17
	vrev64.8	d18, d18
	vrev64.8	d19, d19
	vrev64.8	d20, d20
	vrev64.8	d21, d21
	vrev64.8	d22, d22
	vrev64.8	d23, d23
	vrev64.8	d24, d24
	vrev64.8	d25, d25
	vrev64.8	d26, d26
	vrev64.8	d27, d27
	vrev64.8	d28, d28
	vrev64.8	d29, d29
	vrev64.8	d30, d30
	vrev64.8	d31, d31
#endif /* WOLFSSL_ARM_ARCH_NEON_64BIT */
	mov	r12, #4
	# Start of 16 rounds
L_SHA512_transform_neon_len_start:
	# Round 0
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d4, #50
	vsri.u64	d8, d4, #14
	vshl.u64	d9, d0, #36
	vsri.u64	d9, d0, #28
	vshl.u64	d10, d4, #46
	vsri.u64	d10, d4, #18
	vshl.u64	d11, d0, #30
	vsri.u64	d11, d0, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d4, #23
	vsri.u64	d10, d4, #41
	vshl.u64	d11, d0, #25
	vsri.u64	d11, d0, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d7, d8
	vadd.i64	d12, d16
	vmov	d8, d4
	veor	d10, d1, d2
	vadd.i64	d7, d12
	vbsl	d8, d5, d6
	vbsl	d10, d0, d2
	vadd.i64	d7, d8
	vadd.i64	d10, d9
	vadd.i64	d3, d7
	vadd.i64	d7, d10
	# Round 1
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d3, #50
	vsri.u64	d8, d3, #14
	vshl.u64	d9, d7, #36
	vsri.u64	d9, d7, #28
	vshl.u64	d10, d3, #46
	vsri.u64	d10, d3, #18
	vshl.u64	d11, d7, #30
	vsri.u64	d11, d7, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d3, #23
	vsri.u64	d10, d3, #41
	vshl.u64	d11, d7, #25
	vsri.u64	d11, d7, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d6, d8
	vadd.i64	d12, d17
	vmov	d8, d3
	veor	d10, d0, d1
	vadd.i64	d6, d12
	vbsl	d8, d4, d5
	vbsl	d10, d7, d1
	vadd.i64	d6, d8
	vadd.i64	d10, d9
	vadd.i64	d2, d6
	vadd.i64	d6, d10
#ifndef WOLFSSL_ARM_ARCH_NEON_64BIT
	# Calc new W[0]-W[1]
	vext.8	q6, q8, q9, #8
	vshl.u64	q4, q15, #45
	vsri.u64	q4, q15, #19
	vshl.u64	q5, q15, #3
	vsri.u64	q5, q15, #61
	veor	q5, q4
	vshr.u64	q4, q15, #6
	veor	q5, q4
	vadd.i64	q8, q5
	vext.8	q7, q12, q13, #8
	vadd.i64	q8, q7
	vshl.u64	q4, q6, #63
	vsri.u64	q4, q6, #1
	vshl.u64	q5, q6, #56
	vsri.u64	q5, q6, #8
	veor	q5, q4
	vshr.u64	q6, #7
	veor	q5, q6
	vadd.i64	q8, q5
#else
	# Calc new W[0]-W[1]
	vmov	d12, d17
	vmov	d13, d18
	vshl.u64	d8, d30, #45
	vshl.u64	d9, d31, #45
	vsri.u64	d8, d30, #19
	vsri.u64	d9, d31, #19
	vshl.u64	d10, d30, #3
	vshl.u64	d11, d31, #3
	vsri.u64	d10, d30, #61
	vsri.u64	d11, d31, #61
	veor	d10, d8
	veor	d11, d9
	vshr.u64	d8, d30, #6
	vshr.u64	d9, d31, #6
	veor	d10, d8
	veor	d11, d9
	vadd.i64	d16, d10
	vadd.i64	d17, d11
	vmov	d14, d25
	vmov	d15, d26
	vadd.i64	d16, d14
	vadd.i64	d17, d15
	vshl.u64	d8, d12, #63
	vshl.u64	d9, d13, #63
	vsri.u64	d8, d12, #1
	vsri.u64	d9, d13, #1
	vshl.u64	d10, d12, #56
	vshl.u64	d11, d13, #56
	vsri.u64	d10, d12, #8
	vsri.u64	d11, d13, #8
	veor	d10, d8
	veor	d11, d9
	vshr.u64	d12, #7
	vshr.u64	d13, #7
	veor	d10, d12
	veor	d11, d13
	vadd.i64	d16, d10
	vadd.i64	d17, d11
#endif /* WOLFSSL_ARM_ARCH_NEON_64BIT */
	# Round 2
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d2, #50
	vsri.u64	d8, d2, #14
	vshl.u64	d9, d6, #36
	vsri.u64	d9, d6, #28
	vshl.u64	d10, d2, #46
	vsri.u64	d10, d2, #18
	vshl.u64	d11, d6, #30
	vsri.u64	d11, d6, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d2, #23
	vsri.u64	d10, d2, #41
	vshl.u64	d11, d6, #25
	vsri.u64	d11, d6, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d5, d8
	vadd.i64	d12, d18
	vmov	d8, d2
	veor	d10, d7, d0
	vadd.i64	d5, d12
	vbsl	d8, d3, d4
	vbsl	d10, d6, d0
	vadd.i64	d5, d8
	vadd.i64	d10, d9
	vadd.i64	d1, d5
	vadd.i64	d5, d10
	# Round 3
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d1, #50
	vsri.u64	d8, d1, #14
	vshl.u64	d9, d5, #36
	vsri.u64	d9, d5, #28
	vshl.u64	d10, d1, #46
	vsri.u64	d10, d1, #18
	vshl.u64	d11, d5, #30
	vsri.u64	d11, d5, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d1, #23
	vsri.u64	d10, d1, #41
	vshl.u64	d11, d5, #25
	vsri.u64	d11, d5, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d4, d8
	vadd.i64	d12, d19
	vmov	d8, d1
	veor	d10, d6, d7
	vadd.i64	d4, d12
	vbsl	d8, d2, d3
	vbsl	d10, d5, d7
	vadd.i64	d4, d8
	vadd.i64	d10, d9
	vadd.i64	d0, d4
	vadd.i64	d4, d10
#ifndef WOLFSSL_ARM_ARCH_NEON_64BIT
	# Calc new W[2]-W[3]
	vext.8	q6, q9, q10, #8
	vshl.u64	q4, q8, #45
	vsri.u64	q4, q8, #19
	vshl.u64	q5, q8, #3
	vsri.u64	q5, q8, #61
	veor	q5, q4
	vshr.u64	q4, q8, #6
	veor	q5, q4
	vadd.i64	q9, q5
	vext.8	q7, q13, q14, #8
	vadd.i64	q9, q7
	vshl.u64	q4, q6, #63
	vsri.u64	q4, q6, #1
	vshl.u64	q5, q6, #56
	vsri.u64	q5, q6, #8
	veor	q5, q4
	vshr.u64	q6, #7
	veor	q5, q6
	vadd.i64	q9, q5
#else
	# Calc new W[2]-W[3]
	vmov	d12, d19
	vmov	d13, d20
	vshl.u64	d8, d16, #45
	vshl.u64	d9, d17, #45
	vsri.u64	d8, d16, #19
	vsri.u64	d9, d17, #19
	vshl.u64	d10, d16, #3
	vshl.u64	d11, d17, #3
	vsri.u64	d10, d16, #61
	vsri.u64	d11, d17, #61
	veor	d10, d8
	veor	d11, d9
	vshr.u64	d8, d16, #6
	vshr.u64	d9, d17, #6
	veor	d10, d8
	veor	d11, d9
	vadd.i64	d18, d10
	vadd.i64	d19, d11
	vmov	d14, d27
	vmov	d15, d28
	vadd.i64	d18, d14
	vadd.i64	d19, d15
	vshl.u64	d8, d12, #63
	vshl.u64	d9, d13, #63
	vsri.u64	d8, d12, #1
	vsri.u64	d9, d13, #1
	vshl.u64	d10, d12, #56
	vshl.u64	d11, d13, #56
	vsri.u64	d10, d12, #8
	vsri.u64	d11, d13, #8
	veor	d10, d8
	veor	d11, d9
	vshr.u64	d12, #7
	vshr.u64	d13, #7
	veor	d10, d12
	veor	d11, d13
	vadd.i64	d18, d10
	vadd.i64	d19, d11
#endif /* WOLFSSL_ARM_ARCH_NEON_64BIT */
	# Round 4
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d0, #50
	vsri.u64	d8, d0, #14
	vshl.u64	d9, d4, #36
	vsri.u64	d9, d4, #28
	vshl.u64	d10, d0, #46
	vsri.u64	d10, d0, #18
	vshl.u64	d11, d4, #30
	vsri.u64	d11, d4, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d0, #23
	vsri.u64	d10, d0, #41
	vshl.u64	d11, d4, #25
	vsri.u64	d11, d4, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d3, d8
	vadd.i64	d12, d20
	vmov	d8, d0
	veor	d10, d5, d6
	vadd.i64	d3, d12
	vbsl	d8, d1, d2
	vbsl	d10, d4, d6
	vadd.i64	d3, d8
	vadd.i64	d10, d9
	vadd.i64	d7, d3
	vadd.i64	d3, d10
	# Round 5
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d7, #50
	vsri.u64	d8, d7, #14
	vshl.u64	d9, d3, #36
	vsri.u64	d9, d3, #28
	vshl.u64	d10, d7, #46
	vsri.u64	d10, d7, #18
	vshl.u64	d11, d3, #30
	vsri.u64	d11, d3, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d7, #23
	vsri.u64	d10, d7, #41
	vshl.u64	d11, d3, #25
	vsri.u64	d11, d3, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d2, d8
	vadd.i64	d12, d21
	vmov	d8, d7
	veor	d10, d4, d5
	vadd.i64	d2, d12
	vbsl	d8, d0, d1
	vbsl	d10, d3, d5
	vadd.i64	d2, d8
	vadd.i64	d10, d9
	vadd.i64	d6, d2
	vadd.i64	d2, d10
#ifndef WOLFSSL_ARM_ARCH_NEON_64BIT
	# Calc new W[4]-W[5]
	vext.8	q6, q10, q11, #8
	vshl.u64	q4, q9, #45
	vsri.u64	q4, q9, #19
	vshl.u64	q5, q9, #3
	vsri.u64	q5, q9, #61
	veor	q5, q4
	vshr.u64	q4, q9, #6
	veor	q5, q4
	vadd.i64	q10, q5
	vext.8	q7, q14, q15, #8
	vadd.i64	q10, q7
	vshl.u64	q4, q6, #63
	vsri.u64	q4, q6, #1
	vshl.u64	q5, q6, #56
	vsri.u64	q5, q6, #8
	veor	q5, q4
	vshr.u64	q6, #7
	veor	q5, q6
	vadd.i64	q10, q5
#else
	# Calc new W[4]-W[5]
	vmov	d12, d21
	vmov	d13, d22
	vshl.u64	d8, d18, #45
	vshl.u64	d9, d19, #45
	vsri.u64	d8, d18, #19
	vsri.u64	d9, d19, #19
	vshl.u64	d10, d18, #3
	vshl.u64	d11, d19, #3
	vsri.u64	d10, d18, #61
	vsri.u64	d11, d19, #61
	veor	d10, d8
	veor	d11, d9
	vshr.u64	d8, d18, #6
	vshr.u64	d9, d19, #6
	veor	d10, d8
	veor	d11, d9
	vadd.i64	d20, d10
	vadd.i64	d21, d11
	vmov	d14, d29
	vmov	d15, d30
	vadd.i64	d20, d14
	vadd.i64	d21, d15
	vshl.u64	d8, d12, #63
	vshl.u64	d9, d13, #63
	vsri.u64	d8, d12, #1
	vsri.u64	d9, d13, #1
	vshl.u64	d10, d12, #56
	vshl.u64	d11, d13, #56
	vsri.u64	d10, d12, #8
	vsri.u64	d11, d13, #8
	veor	d10, d8
	veor	d11, d9
	vshr.u64	d12, #7
	vshr.u64	d13, #7
	veor	d10, d12
	veor	d11, d13
	vadd.i64	d20, d10
	vadd.i64	d21, d11
#endif /* WOLFSSL_ARM_ARCH_NEON_64BIT */
	# Round 6
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d6, #50
	vsri.u64	d8, d6, #14
	vshl.u64	d9, d2, #36
	vsri.u64	d9, d2, #28
	vshl.u64	d10, d6, #46
	vsri.u64	d10, d6, #18
	vshl.u64	d11, d2, #30
	vsri.u64	d11, d2, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d6, #23
	vsri.u64	d10, d6, #41
	vshl.u64	d11, d2, #25
	vsri.u64	d11, d2, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d1, d8
	vadd.i64	d12, d22
	vmov	d8, d6
	veor	d10, d3, d4
	vadd.i64	d1, d12
	vbsl	d8, d7, d0
	vbsl	d10, d2, d4
	vadd.i64	d1, d8
	vadd.i64	d10, d9
	vadd.i64	d5, d1
	vadd.i64	d1, d10
	# Round 7
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d5, #50
	vsri.u64	d8, d5, #14
	vshl.u64	d9, d1, #36
	vsri.u64	d9, d1, #28
	vshl.u64	d10, d5, #46
	vsri.u64	d10, d5, #18
	vshl.u64	d11, d1, #30
	vsri.u64	d11, d1, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d5, #23
	vsri.u64	d10, d5, #41
	vshl.u64	d11, d1, #25
	vsri.u64	d11, d1, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d0, d8
	vadd.i64	d12, d23
	vmov	d8, d5
	veor	d10, d2, d3
	vadd.i64	d0, d12
	vbsl	d8, d6, d7
	vbsl	d10, d1, d3
	vadd.i64	d0, d8
	vadd.i64	d10, d9
	vadd.i64	d4, d0
	vadd.i64	d0, d10
#ifndef WOLFSSL_ARM_ARCH_NEON_64BIT
	# Calc new W[6]-W[7]
	vext.8	q6, q11, q12, #8
	vshl.u64	q4, q10, #45
	vsri.u64	q4, q10, #19
	vshl.u64	q5, q10, #3
	vsri.u64	q5, q10, #61
	veor	q5, q4
	vshr.u64	q4, q10, #6
	veor	q5, q4
	vadd.i64	q11, q5
	vext.8	q7, q15, q8, #8
	vadd.i64	q11, q7
	vshl.u64	q4, q6, #63
	vsri.u64	q4, q6, #1
	vshl.u64	q5, q6, #56
	vsri.u64	q5, q6, #8
	veor	q5, q4
	vshr.u64	q6, #7
	veor	q5, q6
	vadd.i64	q11, q5
#else
	# Calc new W[6]-W[7]
	vmov	d12, d23
	vmov	d13, d24
	vshl.u64	d8, d20, #45
	vshl.u64	d9, d21, #45
	vsri.u64	d8, d20, #19
	vsri.u64	d9, d21, #19
	vshl.u64	d10, d20, #3
	vshl.u64	d11, d21, #3
	vsri.u64	d10, d20, #61
	vsri.u64	d11, d21, #61
	veor	d10, d8
	veor	d11, d9
	vshr.u64	d8, d20, #6
	vshr.u64	d9, d21, #6
	veor	d10, d8
	veor	d11, d9
	vadd.i64	d22, d10
	vadd.i64	d23, d11
	vmov	d14, d31
	vmov	d15, d16
	vadd.i64	d22, d14
	vadd.i64	d23, d15
	vshl.u64	d8, d12, #63
	vshl.u64	d9, d13, #63
	vsri.u64	d8, d12, #1
	vsri.u64	d9, d13, #1
	vshl.u64	d10, d12, #56
	vshl.u64	d11, d13, #56
	vsri.u64	d10, d12, #8
	vsri.u64	d11, d13, #8
	veor	d10, d8
	veor	d11, d9
	vshr.u64	d12, #7
	vshr.u64	d13, #7
	veor	d10, d12
	veor	d11, d13
	vadd.i64	d22, d10
	vadd.i64	d23, d11
#endif /* WOLFSSL_ARM_ARCH_NEON_64BIT */
	# Round 8
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d4, #50
	vsri.u64	d8, d4, #14
	vshl.u64	d9, d0, #36
	vsri.u64	d9, d0, #28
	vshl.u64	d10, d4, #46
	vsri.u64	d10, d4, #18
	vshl.u64	d11, d0, #30
	vsri.u64	d11, d0, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d4, #23
	vsri.u64	d10, d4, #41
	vshl.u64	d11, d0, #25
	vsri.u64	d11, d0, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d7, d8
	vadd.i64	d12, d24
	vmov	d8, d4
	veor	d10, d1, d2
	vadd.i64	d7, d12
	vbsl	d8, d5, d6
	vbsl	d10, d0, d2
	vadd.i64	d7, d8
	vadd.i64	d10, d9
	vadd.i64	d3, d7
	vadd.i64	d7, d10
	# Round 9
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d3, #50
	vsri.u64	d8, d3, #14
	vshl.u64	d9, d7, #36
	vsri.u64	d9, d7, #28
	vshl.u64	d10, d3, #46
	vsri.u64	d10, d3, #18
	vshl.u64	d11, d7, #30
	vsri.u64	d11, d7, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d3, #23
	vsri.u64	d10, d3, #41
	vshl.u64	d11, d7, #25
	vsri.u64	d11, d7, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d6, d8
	vadd.i64	d12, d25
	vmov	d8, d3
	veor	d10, d0, d1
	vadd.i64	d6, d12
	vbsl	d8, d4, d5
	vbsl	d10, d7, d1
	vadd.i64	d6, d8
	vadd.i64	d10, d9
	vadd.i64	d2, d6
	vadd.i64	d6, d10
#ifndef WOLFSSL_ARM_ARCH_NEON_64BIT
	# Calc new W[8]-W[9]
	vext.8	q6, q12, q13, #8
	vshl.u64	q4, q11, #45
	vsri.u64	q4, q11, #19
	vshl.u64	q5, q11, #3
	vsri.u64	q5, q11, #61
	veor	q5, q4
	vshr.u64	q4, q11, #6
	veor	q5, q4
	vadd.i64	q12, q5
	vext.8	q7, q8, q9, #8
	vadd.i64	q12, q7
	vshl.u64	q4, q6, #63
	vsri.u64	q4, q6, #1
	vshl.u64	q5, q6, #56
	vsri.u64	q5, q6, #8
	veor	q5, q4
	vshr.u64	q6, #7
	veor	q5, q6
	vadd.i64	q12, q5
#else
	# Calc new W[8]-W[9]
	vmov	d12, d25
	vmov	d13, d26
	vshl.u64	d8, d22, #45
	vshl.u64	d9, d23, #45
	vsri.u64	d8, d22, #19
	vsri.u64	d9, d23, #19
	vshl.u64	d10, d22, #3
	vshl.u64	d11, d23, #3
	vsri.u64	d10, d22, #61
	vsri.u64	d11, d23, #61
	veor	d10, d8
	veor	d11, d9
	vshr.u64	d8, d22, #6
	vshr.u64	d9, d23, #6
	veor	d10, d8
	veor	d11, d9
	vadd.i64	d24, d10
	vadd.i64	d25, d11
	vmov	d14, d17
	vmov	d15, d18
	vadd.i64	d24, d14
	vadd.i64	d25, d15
	vshl.u64	d8, d12, #63
	vshl.u64	d9, d13, #63
	vsri.u64	d8, d12, #1
	vsri.u64	d9, d13, #1
	vshl.u64	d10, d12, #56
	vshl.u64	d11, d13, #56
	vsri.u64	d10, d12, #8
	vsri.u64	d11, d13, #8
	veor	d10, d8
	veor	d11, d9
	vshr.u64	d12, #7
	vshr.u64	d13, #7
	veor	d10, d12
	veor	d11, d13
	vadd.i64	d24, d10
	vadd.i64	d25, d11
#endif /* WOLFSSL_ARM_ARCH_NEON_64BIT */
	# Round 10
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d2, #50
	vsri.u64	d8, d2, #14
	vshl.u64	d9, d6, #36
	vsri.u64	d9, d6, #28
	vshl.u64	d10, d2, #46
	vsri.u64	d10, d2, #18
	vshl.u64	d11, d6, #30
	vsri.u64	d11, d6, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d2, #23
	vsri.u64	d10, d2, #41
	vshl.u64	d11, d6, #25
	vsri.u64	d11, d6, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d5, d8
	vadd.i64	d12, d26
	vmov	d8, d2
	veor	d10, d7, d0
	vadd.i64	d5, d12
	vbsl	d8, d3, d4
	vbsl	d10, d6, d0
	vadd.i64	d5, d8
	vadd.i64	d10, d9
	vadd.i64	d1, d5
	vadd.i64	d5, d10
	# Round 11
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d1, #50
	vsri.u64	d8, d1, #14
	vshl.u64	d9, d5, #36
	vsri.u64	d9, d5, #28
	vshl.u64	d10, d1, #46
	vsri.u64	d10, d1, #18
	vshl.u64	d11, d5, #30
	vsri.u64	d11, d5, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d1, #23
	vsri.u64	d10, d1, #41
	vshl.u64	d11, d5, #25
	vsri.u64	d11, d5, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d4, d8
	vadd.i64	d12, d27
	vmov	d8, d1
	veor	d10, d6, d7
	vadd.i64	d4, d12
	vbsl	d8, d2, d3
	vbsl	d10, d5, d7
	vadd.i64	d4, d8
	vadd.i64	d10, d9
	vadd.i64	d0, d4
	vadd.i64	d4, d10
#ifndef WOLFSSL_ARM_ARCH_NEON_64BIT
	# Calc new W[10]-W[11]
	vext.8	q6, q13, q14, #8
	vshl.u64	q4, q12, #45
	vsri.u64	q4, q12, #19
	vshl.u64	q5, q12, #3
	vsri.u64	q5, q12, #61
	veor	q5, q4
	vshr.u64	q4, q12, #6
	veor	q5, q4
	vadd.i64	q13, q5
	vext.8	q7, q9, q10, #8
	vadd.i64	q13, q7
	vshl.u64	q4, q6, #63
	vsri.u64	q4, q6, #1
	vshl.u64	q5, q6, #56
	vsri.u64	q5, q6, #8
	veor	q5, q4
	vshr.u64	q6, #7
	veor	q5, q6
	vadd.i64	q13, q5
#else
	# Calc new W[10]-W[11]
	vmov	d12, d27
	vmov	d13, d28
	vshl.u64	d8, d24, #45
	vshl.u64	d9, d25, #45
	vsri.u64	d8, d24, #19
	vsri.u64	d9, d25, #19
	vshl.u64	d10, d24, #3
	vshl.u64	d11, d25, #3
	vsri.u64	d10, d24, #61
	vsri.u64	d11, d25, #61
	veor	d10, d8
	veor	d11, d9
	vshr.u64	d8, d24, #6
	vshr.u64	d9, d25, #6
	veor	d10, d8
	veor	d11, d9
	vadd.i64	d26, d10
	vadd.i64	d27, d11
	vmov	d14, d19
	vmov	d15, d20
	vadd.i64	d26, d14
	vadd.i64	d27, d15
	vshl.u64	d8, d12, #63
	vshl.u64	d9, d13, #63
	vsri.u64	d8, d12, #1
	vsri.u64	d9, d13, #1
	vshl.u64	d10, d12, #56
	vshl.u64	d11, d13, #56
	vsri.u64	d10, d12, #8
	vsri.u64	d11, d13, #8
	veor	d10, d8
	veor	d11, d9
	vshr.u64	d12, #7
	vshr.u64	d13, #7
	veor	d10, d12
	veor	d11, d13
	vadd.i64	d26, d10
	vadd.i64	d27, d11
#endif /* WOLFSSL_ARM_ARCH_NEON_64BIT */
	# Round 12
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d0, #50
	vsri.u64	d8, d0, #14
	vshl.u64	d9, d4, #36
	vsri.u64	d9, d4, #28
	vshl.u64	d10, d0, #46
	vsri.u64	d10, d0, #18
	vshl.u64	d11, d4, #30
	vsri.u64	d11, d4, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d0, #23
	vsri.u64	d10, d0, #41
	vshl.u64	d11, d4, #25
	vsri.u64	d11, d4, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d3, d8
	vadd.i64	d12, d28
	vmov	d8, d0
	veor	d10, d5, d6
	vadd.i64	d3, d12
	vbsl	d8, d1, d2
	vbsl	d10, d4, d6
	vadd.i64	d3, d8
	vadd.i64	d10, d9
	vadd.i64	d7, d3
	vadd.i64	d3, d10
	# Round 13
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d7, #50
	vsri.u64	d8, d7, #14
	vshl.u64	d9, d3, #36
	vsri.u64	d9, d3, #28
	vshl.u64	d10, d7, #46
	vsri.u64	d10, d7, #18
	vshl.u64	d11, d3, #30
	vsri.u64	d11, d3, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d7, #23
	vsri.u64	d10, d7, #41
	vshl.u64	d11, d3, #25
	vsri.u64	d11, d3, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d2, d8
	vadd.i64	d12, d29
	vmov	d8, d7
	veor	d10, d4, d5
	vadd.i64	d2, d12
	vbsl	d8, d0, d1
	vbsl	d10, d3, d5
	vadd.i64	d2, d8
	vadd.i64	d10, d9
	vadd.i64	d6, d2
	vadd.i64	d2, d10
#ifndef WOLFSSL_ARM_ARCH_NEON_64BIT
	# Calc new W[12]-W[13]
	vext.8	q6, q14, q15, #8
	vshl.u64	q4, q13, #45
	vsri.u64	q4, q13, #19
	vshl.u64	q5, q13, #3
	vsri.u64	q5, q13, #61
	veor	q5, q4
	vshr.u64	q4, q13, #6
	veor	q5, q4
	vadd.i64	q14, q5
	vext.8	q7, q10, q11, #8
	vadd.i64	q14, q7
	vshl.u64	q4, q6, #63
	vsri.u64	q4, q6, #1
	vshl.u64	q5, q6, #56
	vsri.u64	q5, q6, #8
	veor	q5, q4
	vshr.u64	q6, #7
	veor	q5, q6
	vadd.i64	q14, q5
#else
	# Calc new W[12]-W[13]
	vmov	d12, d29
	vmov	d13, d30
	vshl.u64	d8, d26, #45
	vshl.u64	d9, d27, #45
	vsri.u64	d8, d26, #19
	vsri.u64	d9, d27, #19
	vshl.u64	d10, d26, #3
	vshl.u64	d11, d27, #3
	vsri.u64	d10, d26, #61
	vsri.u64	d11, d27, #61
	veor	d10, d8
	veor	d11, d9
	vshr.u64	d8, d26, #6
	vshr.u64	d9, d27, #6
	veor	d10, d8
	veor	d11, d9
	vadd.i64	d28, d10
	vadd.i64	d29, d11
	vmov	d14, d21
	vmov	d15, d22
	vadd.i64	d28, d14
	vadd.i64	d29, d15
	vshl.u64	d8, d12, #63
	vshl.u64	d9, d13, #63
	vsri.u64	d8, d12, #1
	vsri.u64	d9, d13, #1
	vshl.u64	d10, d12, #56
	vshl.u64	d11, d13, #56
	vsri.u64	d10, d12, #8
	vsri.u64	d11, d13, #8
	veor	d10, d8
	veor	d11, d9
	vshr.u64	d12, #7
	vshr.u64	d13, #7
	veor	d10, d12
	veor	d11, d13
	vadd.i64	d28, d10
	vadd.i64	d29, d11
#endif /* WOLFSSL_ARM_ARCH_NEON_64BIT */
	# Round 14
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d6, #50
	vsri.u64	d8, d6, #14
	vshl.u64	d9, d2, #36
	vsri.u64	d9, d2, #28
	vshl.u64	d10, d6, #46
	vsri.u64	d10, d6, #18
	vshl.u64	d11, d2, #30
	vsri.u64	d11, d2, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d6, #23
	vsri.u64	d10, d6, #41
	vshl.u64	d11, d2, #25
	vsri.u64	d11, d2, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d1, d8
	vadd.i64	d12, d30
	vmov	d8, d6
	veor	d10, d3, d4
	vadd.i64	d1, d12
	vbsl	d8, d7, d0
	vbsl	d10, d2, d4
	vadd.i64	d1, d8
	vadd.i64	d10, d9
	vadd.i64	d5, d1
	vadd.i64	d1, d10
	# Round 15
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d5, #50
	vsri.u64	d8, d5, #14
	vshl.u64	d9, d1, #36
	vsri.u64	d9, d1, #28
	vshl.u64	d10, d5, #46
	vsri.u64	d10, d5, #18
	vshl.u64	d11, d1, #30
	vsri.u64	d11, d1, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d5, #23
	vsri.u64	d10, d5, #41
	vshl.u64	d11, d1, #25
	vsri.u64	d11, d1, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d0, d8
	vadd.i64	d12, d31
	vmov	d8, d5
	veor	d10, d2, d3
	vadd.i64	d0, d12
	vbsl	d8, d6, d7
	vbsl	d10, d1, d3
	vadd.i64	d0, d8
	vadd.i64	d10, d9
	vadd.i64	d4, d0
	vadd.i64	d0, d10
#ifndef WOLFSSL_ARM_ARCH_NEON_64BIT
	# Calc new W[14]-W[15]
	vext.8	q6, q15, q8, #8
	vshl.u64	q4, q14, #45
	vsri.u64	q4, q14, #19
	vshl.u64	q5, q14, #3
	vsri.u64	q5, q14, #61
	veor	q5, q4
	vshr.u64	q4, q14, #6
	veor	q5, q4
	vadd.i64	q15, q5
	vext.8	q7, q11, q12, #8
	vadd.i64	q15, q7
	vshl.u64	q4, q6, #63
	vsri.u64	q4, q6, #1
	vshl.u64	q5, q6, #56
	vsri.u64	q5, q6, #8
	veor	q5, q4
	vshr.u64	q6, #7
	veor	q5, q6
	vadd.i64	q15, q5
#else
	# Calc new W[14]-W[15]
	vmov	d12, d31
	vmov	d13, d16
	vshl.u64	d8, d28, #45
	vshl.u64	d9, d29, #45
	vsri.u64	d8, d28, #19
	vsri.u64	d9, d29, #19
	vshl.u64	d10, d28, #3
	vshl.u64	d11, d29, #3
	vsri.u64	d10, d28, #61
	vsri.u64	d11, d29, #61
	veor	d10, d8
	veor	d11, d9
	vshr.u64	d8, d28, #6
	vshr.u64	d9, d29, #6
	veor	d10, d8
	veor	d11, d9
	vadd.i64	d30, d10
	vadd.i64	d31, d11
	vmov	d14, d23
	vmov	d15, d24
	vadd.i64	d30, d14
	vadd.i64	d31, d15
	vshl.u64	d8, d12, #63
	vshl.u64	d9, d13, #63
	vsri.u64	d8, d12, #1
	vsri.u64	d9, d13, #1
	vshl.u64	d10, d12, #56
	vshl.u64	d11, d13, #56
	vsri.u64	d10, d12, #8
	vsri.u64	d11, d13, #8
	veor	d10, d8
	veor	d11, d9
	vshr.u64	d12, #7
	vshr.u64	d13, #7
	veor	d10, d12
	veor	d11, d13
	vadd.i64	d30, d10
	vadd.i64	d31, d11
#endif /* WOLFSSL_ARM_ARCH_NEON_64BIT */
	subs	r12, r12, #1
	bne	L_SHA512_transform_neon_len_start
	# Round 0
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d4, #50
	vsri.u64	d8, d4, #14
	vshl.u64	d9, d0, #36
	vsri.u64	d9, d0, #28
	vshl.u64	d10, d4, #46
	vsri.u64	d10, d4, #18
	vshl.u64	d11, d0, #30
	vsri.u64	d11, d0, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d4, #23
	vsri.u64	d10, d4, #41
	vshl.u64	d11, d0, #25
	vsri.u64	d11, d0, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d7, d8
	vadd.i64	d12, d16
	vmov	d8, d4
	veor	d10, d1, d2
	vadd.i64	d7, d12
	vbsl	d8, d5, d6
	vbsl	d10, d0, d2
	vadd.i64	d7, d8
	vadd.i64	d10, d9
	vadd.i64	d3, d7
	vadd.i64	d7, d10
	# Round 1
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d3, #50
	vsri.u64	d8, d3, #14
	vshl.u64	d9, d7, #36
	vsri.u64	d9, d7, #28
	vshl.u64	d10, d3, #46
	vsri.u64	d10, d3, #18
	vshl.u64	d11, d7, #30
	vsri.u64	d11, d7, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d3, #23
	vsri.u64	d10, d3, #41
	vshl.u64	d11, d7, #25
	vsri.u64	d11, d7, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d6, d8
	vadd.i64	d12, d17
	vmov	d8, d3
	veor	d10, d0, d1
	vadd.i64	d6, d12
	vbsl	d8, d4, d5
	vbsl	d10, d7, d1
	vadd.i64	d6, d8
	vadd.i64	d10, d9
	vadd.i64	d2, d6
	vadd.i64	d6, d10
	# Round 2
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d2, #50
	vsri.u64	d8, d2, #14
	vshl.u64	d9, d6, #36
	vsri.u64	d9, d6, #28
	vshl.u64	d10, d2, #46
	vsri.u64	d10, d2, #18
	vshl.u64	d11, d6, #30
	vsri.u64	d11, d6, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d2, #23
	vsri.u64	d10, d2, #41
	vshl.u64	d11, d6, #25
	vsri.u64	d11, d6, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d5, d8
	vadd.i64	d12, d18
	vmov	d8, d2
	veor	d10, d7, d0
	vadd.i64	d5, d12
	vbsl	d8, d3, d4
	vbsl	d10, d6, d0
	vadd.i64	d5, d8
	vadd.i64	d10, d9
	vadd.i64	d1, d5
	vadd.i64	d5, d10
	# Round 3
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d1, #50
	vsri.u64	d8, d1, #14
	vshl.u64	d9, d5, #36
	vsri.u64	d9, d5, #28
	vshl.u64	d10, d1, #46
	vsri.u64	d10, d1, #18
	vshl.u64	d11, d5, #30
	vsri.u64	d11, d5, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d1, #23
	vsri.u64	d10, d1, #41
	vshl.u64	d11, d5, #25
	vsri.u64	d11, d5, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d4, d8
	vadd.i64	d12, d19
	vmov	d8, d1
	veor	d10, d6, d7
	vadd.i64	d4, d12
	vbsl	d8, d2, d3
	vbsl	d10, d5, d7
	vadd.i64	d4, d8
	vadd.i64	d10, d9
	vadd.i64	d0, d4
	vadd.i64	d4, d10
	# Round 4
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d0, #50
	vsri.u64	d8, d0, #14
	vshl.u64	d9, d4, #36
	vsri.u64	d9, d4, #28
	vshl.u64	d10, d0, #46
	vsri.u64	d10, d0, #18
	vshl.u64	d11, d4, #30
	vsri.u64	d11, d4, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d0, #23
	vsri.u64	d10, d0, #41
	vshl.u64	d11, d4, #25
	vsri.u64	d11, d4, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d3, d8
	vadd.i64	d12, d20
	vmov	d8, d0
	veor	d10, d5, d6
	vadd.i64	d3, d12
	vbsl	d8, d1, d2
	vbsl	d10, d4, d6
	vadd.i64	d3, d8
	vadd.i64	d10, d9
	vadd.i64	d7, d3
	vadd.i64	d3, d10
	# Round 5
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d7, #50
	vsri.u64	d8, d7, #14
	vshl.u64	d9, d3, #36
	vsri.u64	d9, d3, #28
	vshl.u64	d10, d7, #46
	vsri.u64	d10, d7, #18
	vshl.u64	d11, d3, #30
	vsri.u64	d11, d3, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d7, #23
	vsri.u64	d10, d7, #41
	vshl.u64	d11, d3, #25
	vsri.u64	d11, d3, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d2, d8
	vadd.i64	d12, d21
	vmov	d8, d7
	veor	d10, d4, d5
	vadd.i64	d2, d12
	vbsl	d8, d0, d1
	vbsl	d10, d3, d5
	vadd.i64	d2, d8
	vadd.i64	d10, d9
	vadd.i64	d6, d2
	vadd.i64	d2, d10
	# Round 6
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d6, #50
	vsri.u64	d8, d6, #14
	vshl.u64	d9, d2, #36
	vsri.u64	d9, d2, #28
	vshl.u64	d10, d6, #46
	vsri.u64	d10, d6, #18
	vshl.u64	d11, d2, #30
	vsri.u64	d11, d2, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d6, #23
	vsri.u64	d10, d6, #41
	vshl.u64	d11, d2, #25
	vsri.u64	d11, d2, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d1, d8
	vadd.i64	d12, d22
	vmov	d8, d6
	veor	d10, d3, d4
	vadd.i64	d1, d12
	vbsl	d8, d7, d0
	vbsl	d10, d2, d4
	vadd.i64	d1, d8
	vadd.i64	d10, d9
	vadd.i64	d5, d1
	vadd.i64	d1, d10
	# Round 7
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d5, #50
	vsri.u64	d8, d5, #14
	vshl.u64	d9, d1, #36
	vsri.u64	d9, d1, #28
	vshl.u64	d10, d5, #46
	vsri.u64	d10, d5, #18
	vshl.u64	d11, d1, #30
	vsri.u64	d11, d1, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d5, #23
	vsri.u64	d10, d5, #41
	vshl.u64	d11, d1, #25
	vsri.u64	d11, d1, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d0, d8
	vadd.i64	d12, d23
	vmov	d8, d5
	veor	d10, d2, d3
	vadd.i64	d0, d12
	vbsl	d8, d6, d7
	vbsl	d10, d1, d3
	vadd.i64	d0, d8
	vadd.i64	d10, d9
	vadd.i64	d4, d0
	vadd.i64	d0, d10
	# Round 8
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d4, #50
	vsri.u64	d8, d4, #14
	vshl.u64	d9, d0, #36
	vsri.u64	d9, d0, #28
	vshl.u64	d10, d4, #46
	vsri.u64	d10, d4, #18
	vshl.u64	d11, d0, #30
	vsri.u64	d11, d0, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d4, #23
	vsri.u64	d10, d4, #41
	vshl.u64	d11, d0, #25
	vsri.u64	d11, d0, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d7, d8
	vadd.i64	d12, d24
	vmov	d8, d4
	veor	d10, d1, d2
	vadd.i64	d7, d12
	vbsl	d8, d5, d6
	vbsl	d10, d0, d2
	vadd.i64	d7, d8
	vadd.i64	d10, d9
	vadd.i64	d3, d7
	vadd.i64	d7, d10
	# Round 9
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d3, #50
	vsri.u64	d8, d3, #14
	vshl.u64	d9, d7, #36
	vsri.u64	d9, d7, #28
	vshl.u64	d10, d3, #46
	vsri.u64	d10, d3, #18
	vshl.u64	d11, d7, #30
	vsri.u64	d11, d7, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d3, #23
	vsri.u64	d10, d3, #41
	vshl.u64	d11, d7, #25
	vsri.u64	d11, d7, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d6, d8
	vadd.i64	d12, d25
	vmov	d8, d3
	veor	d10, d0, d1
	vadd.i64	d6, d12
	vbsl	d8, d4, d5
	vbsl	d10, d7, d1
	vadd.i64	d6, d8
	vadd.i64	d10, d9
	vadd.i64	d2, d6
	vadd.i64	d6, d10
	# Round 10
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d2, #50
	vsri.u64	d8, d2, #14
	vshl.u64	d9, d6, #36
	vsri.u64	d9, d6, #28
	vshl.u64	d10, d2, #46
	vsri.u64	d10, d2, #18
	vshl.u64	d11, d6, #30
	vsri.u64	d11, d6, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d2, #23
	vsri.u64	d10, d2, #41
	vshl.u64	d11, d6, #25
	vsri.u64	d11, d6, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d5, d8
	vadd.i64	d12, d26
	vmov	d8, d2
	veor	d10, d7, d0
	vadd.i64	d5, d12
	vbsl	d8, d3, d4
	vbsl	d10, d6, d0
	vadd.i64	d5, d8
	vadd.i64	d10, d9
	vadd.i64	d1, d5
	vadd.i64	d5, d10
	# Round 11
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d1, #50
	vsri.u64	d8, d1, #14
	vshl.u64	d9, d5, #36
	vsri.u64	d9, d5, #28
	vshl.u64	d10, d1, #46
	vsri.u64	d10, d1, #18
	vshl.u64	d11, d5, #30
	vsri.u64	d11, d5, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d1, #23
	vsri.u64	d10, d1, #41
	vshl.u64	d11, d5, #25
	vsri.u64	d11, d5, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d4, d8
	vadd.i64	d12, d27
	vmov	d8, d1
	veor	d10, d6, d7
	vadd.i64	d4, d12
	vbsl	d8, d2, d3
	vbsl	d10, d5, d7
	vadd.i64	d4, d8
	vadd.i64	d10, d9
	vadd.i64	d0, d4
	vadd.i64	d4, d10
	# Round 12
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d0, #50
	vsri.u64	d8, d0, #14
	vshl.u64	d9, d4, #36
	vsri.u64	d9, d4, #28
	vshl.u64	d10, d0, #46
	vsri.u64	d10, d0, #18
	vshl.u64	d11, d4, #30
	vsri.u64	d11, d4, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d0, #23
	vsri.u64	d10, d0, #41
	vshl.u64	d11, d4, #25
	vsri.u64	d11, d4, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d3, d8
	vadd.i64	d12, d28
	vmov	d8, d0
	veor	d10, d5, d6
	vadd.i64	d3, d12
	vbsl	d8, d1, d2
	vbsl	d10, d4, d6
	vadd.i64	d3, d8
	vadd.i64	d10, d9
	vadd.i64	d7, d3
	vadd.i64	d3, d10
	# Round 13
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d7, #50
	vsri.u64	d8, d7, #14
	vshl.u64	d9, d3, #36
	vsri.u64	d9, d3, #28
	vshl.u64	d10, d7, #46
	vsri.u64	d10, d7, #18
	vshl.u64	d11, d3, #30
	vsri.u64	d11, d3, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d7, #23
	vsri.u64	d10, d7, #41
	vshl.u64	d11, d3, #25
	vsri.u64	d11, d3, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d2, d8
	vadd.i64	d12, d29
	vmov	d8, d7
	veor	d10, d4, d5
	vadd.i64	d2, d12
	vbsl	d8, d0, d1
	vbsl	d10, d3, d5
	vadd.i64	d2, d8
	vadd.i64	d10, d9
	vadd.i64	d6, d2
	vadd.i64	d2, d10
	# Round 14
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d6, #50
	vsri.u64	d8, d6, #14
	vshl.u64	d9, d2, #36
	vsri.u64	d9, d2, #28
	vshl.u64	d10, d6, #46
	vsri.u64	d10, d6, #18
	vshl.u64	d11, d2, #30
	vsri.u64	d11, d2, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d6, #23
	vsri.u64	d10, d6, #41
	vshl.u64	d11, d2, #25
	vsri.u64	d11, d2, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d1, d8
	vadd.i64	d12, d30
	vmov	d8, d6
	veor	d10, d3, d4
	vadd.i64	d1, d12
	vbsl	d8, d7, d0
	vbsl	d10, d2, d4
	vadd.i64	d1, d8
	vadd.i64	d10, d9
	vadd.i64	d5, d1
	vadd.i64	d1, d10
	# Round 15
	vld1.64	{d12}, [r3:64]!
	vshl.u64	d8, d5, #50
	vsri.u64	d8, d5, #14
	vshl.u64	d9, d1, #36
	vsri.u64	d9, d1, #28
	vshl.u64	d10, d5, #46
	vsri.u64	d10, d5, #18
	vshl.u64	d11, d1, #30
	vsri.u64	d11, d1, #34
	veor	d8, d10
	veor	d9, d11
	vshl.u64	d10, d5, #23
	vsri.u64	d10, d5, #41
	vshl.u64	d11, d1, #25
	vsri.u64	d11, d1, #39
	veor	d8, d10
	veor	d9, d11
	vadd.i64	d0, d8
	vadd.i64	d12, d31
	vmov	d8, d5
	veor	d10, d2, d3
	vadd.i64	d0, d12
	vbsl	d8, d6, d7
	vbsl	d10, d1, d3
	vadd.i64	d0, d8
	vadd.i64	d10, d9
	vadd.i64	d4, d0
	vadd.i64	d0, d10
	# Add in digest from start
	vldm.64	r0, {d8-d15}
#ifndef WOLFSSL_ARM_ARCH_NEON_64BIT
	vadd.i64	q0, q0, q4
	vadd.i64	q1, q1, q5
	vadd.i64	q2, q2, q6
	vadd.i64	q3, q3, q7
#else
	vadd.i64	d0, d0, d8
	vadd.i64	d1, d1, d9
	vadd.i64	d2, d2, d10
	vadd.i64	d3, d3, d11
	vadd.i64	d4, d4, d12
	vadd.i64	d5, d5, d13
	vadd.i64	d6, d6, d14
	vadd.i64	d7, d7, d15
#endif /* WOLFSSL_ARM_ARCH_NEON_64BIT */
	vstm.64	r0, {d0-d7}
	subs	r2, r2, #0x80
	sub	r3, r3, #0x280
	bne	L_SHA512_transform_neon_len_begin
	vpop	{d8-d15}
	bx	lr
	.size	Transform_Sha512_Len_neon,.-Transform_Sha512_Len_neon
#endif /* !WOLFSSL_ARMASM_NO_NEON */
#endif /* WOLFSSL_SHA512 || WOLFSSL_SHA384 */
#endif /* !__aarch64__ && !WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
