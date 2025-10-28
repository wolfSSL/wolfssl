/* armv8-sha256-asm
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

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

/* Generated using (from wolfssl):
 *   cd ../scripts
 *   ruby ./sha2/sha256.rb arm64 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-sha256-asm.S
 */
#ifdef WOLFSSL_ARMASM
#ifdef __aarch64__
#ifndef WOLFSSL_ARMASM_INLINE
#if  !defined(NO_SHA256) || defined(WOLFSSL_SHA224)
#ifndef __APPLE__
	.text
	.type	L_SHA256_transform_neon_len_k, %object
	.section	.rodata
	.size	L_SHA256_transform_neon_len_k, 256
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_SHA256_transform_neon_len_k:
	.word	0x428a2f98
	.word	0x71374491
	.word	0xb5c0fbcf
	.word	0xe9b5dba5
	.word	0x3956c25b
	.word	0x59f111f1
	.word	0x923f82a4
	.word	0xab1c5ed5
	.word	0xd807aa98
	.word	0x12835b01
	.word	0x243185be
	.word	0x550c7dc3
	.word	0x72be5d74
	.word	0x80deb1fe
	.word	0x9bdc06a7
	.word	0xc19bf174
	.word	0xe49b69c1
	.word	0xefbe4786
	.word	0x0fc19dc6
	.word	0x240ca1cc
	.word	0x2de92c6f
	.word	0x4a7484aa
	.word	0x5cb0a9dc
	.word	0x76f988da
	.word	0x983e5152
	.word	0xa831c66d
	.word	0xb00327c8
	.word	0xbf597fc7
	.word	0xc6e00bf3
	.word	0xd5a79147
	.word	0x06ca6351
	.word	0x14292967
	.word	0x27b70a85
	.word	0x2e1b2138
	.word	0x4d2c6dfc
	.word	0x53380d13
	.word	0x650a7354
	.word	0x766a0abb
	.word	0x81c2c92e
	.word	0x92722c85
	.word	0xa2bfe8a1
	.word	0xa81a664b
	.word	0xc24b8b70
	.word	0xc76c51a3
	.word	0xd192e819
	.word	0xd6990624
	.word	0xf40e3585
	.word	0x106aa070
	.word	0x19a4c116
	.word	0x1e376c08
	.word	0x2748774c
	.word	0x34b0bcb5
	.word	0x391c0cb3
	.word	0x4ed8aa4a
	.word	0x5b9cca4f
	.word	0x682e6ff3
	.word	0x748f82ee
	.word	0x78a5636f
	.word	0x84c87814
	.word	0x8cc70208
	.word	0x90befffa
	.word	0xa4506ceb
	.word	0xbef9a3f7
	.word	0xc67178f2
#ifndef __APPLE__
.text
.globl	Transform_Sha256_Len_neon
.type	Transform_Sha256_Len_neon,@function
.align	2
Transform_Sha256_Len_neon:
#else
.section	__TEXT,__text
.globl	_Transform_Sha256_Len_neon
.p2align	2
_Transform_Sha256_Len_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-112]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #24]
	stp	x20, x21, [x29, #40]
	stp	x22, x23, [x29, #56]
	str	x24, [x29, #72]
	stp	d8, d9, [x29, #80]
	stp	d10, d11, [x29, #96]
#ifndef __APPLE__
	adrp x3, L_SHA256_transform_neon_len_k
	add  x3, x3, :lo12:L_SHA256_transform_neon_len_k
#else
	adrp x3, L_SHA256_transform_neon_len_k@PAGE
	add  x3, x3, :lo12:L_SHA256_transform_neon_len_k@PAGEOFF
#endif /* __APPLE__ */
	# Load digest into working vars
	ldr	w4, [x0]
	ldr	w5, [x0, #4]
	ldr	w6, [x0, #8]
	ldr	w7, [x0, #12]
	ldr	w8, [x0, #16]
	ldr	w9, [x0, #20]
	ldr	w10, [x0, #24]
	ldr	w11, [x0, #28]
	# Start of loop processing a block
L_sha256_len_neon_begin:
	# Load W
	# Copy digest to add in at end
	ld1	{v0.8b, v1.8b, v2.8b, v3.8b}, [x1], #32
	mov	w15, w4
	ld1	{v4.8b, v5.8b, v6.8b, v7.8b}, [x1], #32
	mov	w16, w5
	rev32	v0.8b, v0.8b
	mov	w17, w6
	rev32	v1.8b, v1.8b
	mov	w19, w7
	rev32	v2.8b, v2.8b
	mov	w20, w8
	rev32	v3.8b, v3.8b
	mov	w21, w9
	rev32	v4.8b, v4.8b
	mov	w22, w10
	rev32	v5.8b, v5.8b
	mov	w23, w11
	rev32	v6.8b, v6.8b
	rev32	v7.8b, v7.8b
	mov	x24, #3
	# Start of 16 rounds
L_sha256_len_neon_start:
	# Round 0
	mov	w14, v0.s[0]
	ror	w12, w8, #6
	eor	w13, w9, w10
	eor	w12, w12, w8, ror 11
	and	w13, w13, w8
	eor	w12, w12, w8, ror 25
	eor	w13, w13, w10
	add	w11, w11, w12
	add	w11, w11, w13
	ldr	w12, [x3]
	add	w11, w11, w14
	add	w11, w11, w12
	add	w7, w7, w11
	ror	w12, w4, #2
	eor	w13, w4, w5
	eor	w12, w12, w4, ror 13
	eor	w14, w5, w6
	and	w13, w13, w14
	eor	w12, w12, w4, ror 22
	eor	w13, w13, w5
	add	w11, w11, w12
	add	w11, w11, w13
	# Round 1
	mov	w14, v0.s[1]
	# Calc new W[0]-W[1]
	ext	v10.8b, v0.8b, v1.8b, #4
	ror	w12, w7, #6
	shl	v8.2s, v7.2s, #15
	eor	w13, w8, w9
	sri	v8.2s, v7.2s, #17
	eor	w12, w12, w7, ror 11
	shl	v9.2s, v7.2s, #13
	and	w13, w13, w7
	sri	v9.2s, v7.2s, #19
	eor	w12, w12, w7, ror 25
	eor	v9.8b, v9.8b, v8.8b
	eor	w13, w13, w9
	ushr	v8.2s, v7.2s, #10
	add	w10, w10, w12
	eor	v9.8b, v9.8b, v8.8b
	add	w10, w10, w13
	add	v0.2s, v0.2s, v9.2s
	ldr	w12, [x3, #4]
	ext	v11.8b, v4.8b, v5.8b, #4
	add	w10, w10, w14
	add	v0.2s, v0.2s, v11.2s
	add	w10, w10, w12
	shl	v8.2s, v10.2s, #25
	add	w6, w6, w10
	sri	v8.2s, v10.2s, #7
	ror	w12, w11, #2
	shl	v9.2s, v10.2s, #14
	eor	w13, w11, w4
	sri	v9.2s, v10.2s, #18
	eor	w12, w12, w11, ror 13
	eor	v9.8b, v9.8b, v8.8b
	eor	w14, w4, w5
	ushr	v10.2s, v10.2s, #3
	and	w13, w13, w14
	eor	v9.8b, v9.8b, v10.8b
	eor	w12, w12, w11, ror 22
	add	v0.2s, v0.2s, v9.2s
	eor	w13, w13, w4
	add	w10, w10, w12
	add	w10, w10, w13
	# Round 2
	mov	w14, v1.s[0]
	ror	w12, w6, #6
	eor	w13, w7, w8
	eor	w12, w12, w6, ror 11
	and	w13, w13, w6
	eor	w12, w12, w6, ror 25
	eor	w13, w13, w8
	add	w9, w9, w12
	add	w9, w9, w13
	ldr	w12, [x3, #8]
	add	w9, w9, w14
	add	w9, w9, w12
	add	w5, w5, w9
	ror	w12, w10, #2
	eor	w13, w10, w11
	eor	w12, w12, w10, ror 13
	eor	w14, w11, w4
	and	w13, w13, w14
	eor	w12, w12, w10, ror 22
	eor	w13, w13, w11
	add	w9, w9, w12
	add	w9, w9, w13
	# Round 3
	mov	w14, v1.s[1]
	# Calc new W[2]-W[3]
	ext	v10.8b, v1.8b, v2.8b, #4
	ror	w12, w5, #6
	shl	v8.2s, v0.2s, #15
	eor	w13, w6, w7
	sri	v8.2s, v0.2s, #17
	eor	w12, w12, w5, ror 11
	shl	v9.2s, v0.2s, #13
	and	w13, w13, w5
	sri	v9.2s, v0.2s, #19
	eor	w12, w12, w5, ror 25
	eor	v9.8b, v9.8b, v8.8b
	eor	w13, w13, w7
	ushr	v8.2s, v0.2s, #10
	add	w8, w8, w12
	eor	v9.8b, v9.8b, v8.8b
	add	w8, w8, w13
	add	v1.2s, v1.2s, v9.2s
	ldr	w12, [x3, #12]
	ext	v11.8b, v5.8b, v6.8b, #4
	add	w8, w8, w14
	add	v1.2s, v1.2s, v11.2s
	add	w8, w8, w12
	shl	v8.2s, v10.2s, #25
	add	w4, w4, w8
	sri	v8.2s, v10.2s, #7
	ror	w12, w9, #2
	shl	v9.2s, v10.2s, #14
	eor	w13, w9, w10
	sri	v9.2s, v10.2s, #18
	eor	w12, w12, w9, ror 13
	eor	v9.8b, v9.8b, v8.8b
	eor	w14, w10, w11
	ushr	v10.2s, v10.2s, #3
	and	w13, w13, w14
	eor	v9.8b, v9.8b, v10.8b
	eor	w12, w12, w9, ror 22
	add	v1.2s, v1.2s, v9.2s
	eor	w13, w13, w10
	add	w8, w8, w12
	add	w8, w8, w13
	# Round 4
	mov	w14, v2.s[0]
	ror	w12, w4, #6
	eor	w13, w5, w6
	eor	w12, w12, w4, ror 11
	and	w13, w13, w4
	eor	w12, w12, w4, ror 25
	eor	w13, w13, w6
	add	w7, w7, w12
	add	w7, w7, w13
	ldr	w12, [x3, #16]
	add	w7, w7, w14
	add	w7, w7, w12
	add	w11, w11, w7
	ror	w12, w8, #2
	eor	w13, w8, w9
	eor	w12, w12, w8, ror 13
	eor	w14, w9, w10
	and	w13, w13, w14
	eor	w12, w12, w8, ror 22
	eor	w13, w13, w9
	add	w7, w7, w12
	add	w7, w7, w13
	# Round 5
	mov	w14, v2.s[1]
	# Calc new W[4]-W[5]
	ext	v10.8b, v2.8b, v3.8b, #4
	ror	w12, w11, #6
	shl	v8.2s, v1.2s, #15
	eor	w13, w4, w5
	sri	v8.2s, v1.2s, #17
	eor	w12, w12, w11, ror 11
	shl	v9.2s, v1.2s, #13
	and	w13, w13, w11
	sri	v9.2s, v1.2s, #19
	eor	w12, w12, w11, ror 25
	eor	v9.8b, v9.8b, v8.8b
	eor	w13, w13, w5
	ushr	v8.2s, v1.2s, #10
	add	w6, w6, w12
	eor	v9.8b, v9.8b, v8.8b
	add	w6, w6, w13
	add	v2.2s, v2.2s, v9.2s
	ldr	w12, [x3, #20]
	ext	v11.8b, v6.8b, v7.8b, #4
	add	w6, w6, w14
	add	v2.2s, v2.2s, v11.2s
	add	w6, w6, w12
	shl	v8.2s, v10.2s, #25
	add	w10, w10, w6
	sri	v8.2s, v10.2s, #7
	ror	w12, w7, #2
	shl	v9.2s, v10.2s, #14
	eor	w13, w7, w8
	sri	v9.2s, v10.2s, #18
	eor	w12, w12, w7, ror 13
	eor	v9.8b, v9.8b, v8.8b
	eor	w14, w8, w9
	ushr	v10.2s, v10.2s, #3
	and	w13, w13, w14
	eor	v9.8b, v9.8b, v10.8b
	eor	w12, w12, w7, ror 22
	add	v2.2s, v2.2s, v9.2s
	eor	w13, w13, w8
	add	w6, w6, w12
	add	w6, w6, w13
	# Round 6
	mov	w14, v3.s[0]
	ror	w12, w10, #6
	eor	w13, w11, w4
	eor	w12, w12, w10, ror 11
	and	w13, w13, w10
	eor	w12, w12, w10, ror 25
	eor	w13, w13, w4
	add	w5, w5, w12
	add	w5, w5, w13
	ldr	w12, [x3, #24]
	add	w5, w5, w14
	add	w5, w5, w12
	add	w9, w9, w5
	ror	w12, w6, #2
	eor	w13, w6, w7
	eor	w12, w12, w6, ror 13
	eor	w14, w7, w8
	and	w13, w13, w14
	eor	w12, w12, w6, ror 22
	eor	w13, w13, w7
	add	w5, w5, w12
	add	w5, w5, w13
	# Round 7
	mov	w14, v3.s[1]
	# Calc new W[6]-W[7]
	ext	v10.8b, v3.8b, v4.8b, #4
	ror	w12, w9, #6
	shl	v8.2s, v2.2s, #15
	eor	w13, w10, w11
	sri	v8.2s, v2.2s, #17
	eor	w12, w12, w9, ror 11
	shl	v9.2s, v2.2s, #13
	and	w13, w13, w9
	sri	v9.2s, v2.2s, #19
	eor	w12, w12, w9, ror 25
	eor	v9.8b, v9.8b, v8.8b
	eor	w13, w13, w11
	ushr	v8.2s, v2.2s, #10
	add	w4, w4, w12
	eor	v9.8b, v9.8b, v8.8b
	add	w4, w4, w13
	add	v3.2s, v3.2s, v9.2s
	ldr	w12, [x3, #28]
	ext	v11.8b, v7.8b, v0.8b, #4
	add	w4, w4, w14
	add	v3.2s, v3.2s, v11.2s
	add	w4, w4, w12
	shl	v8.2s, v10.2s, #25
	add	w8, w8, w4
	sri	v8.2s, v10.2s, #7
	ror	w12, w5, #2
	shl	v9.2s, v10.2s, #14
	eor	w13, w5, w6
	sri	v9.2s, v10.2s, #18
	eor	w12, w12, w5, ror 13
	eor	v9.8b, v9.8b, v8.8b
	eor	w14, w6, w7
	ushr	v10.2s, v10.2s, #3
	and	w13, w13, w14
	eor	v9.8b, v9.8b, v10.8b
	eor	w12, w12, w5, ror 22
	add	v3.2s, v3.2s, v9.2s
	eor	w13, w13, w6
	add	w4, w4, w12
	add	w4, w4, w13
	# Round 8
	mov	w14, v4.s[0]
	ror	w12, w8, #6
	eor	w13, w9, w10
	eor	w12, w12, w8, ror 11
	and	w13, w13, w8
	eor	w12, w12, w8, ror 25
	eor	w13, w13, w10
	add	w11, w11, w12
	add	w11, w11, w13
	ldr	w12, [x3, #32]
	add	w11, w11, w14
	add	w11, w11, w12
	add	w7, w7, w11
	ror	w12, w4, #2
	eor	w13, w4, w5
	eor	w12, w12, w4, ror 13
	eor	w14, w5, w6
	and	w13, w13, w14
	eor	w12, w12, w4, ror 22
	eor	w13, w13, w5
	add	w11, w11, w12
	add	w11, w11, w13
	# Round 9
	mov	w14, v4.s[1]
	# Calc new W[8]-W[9]
	ext	v10.8b, v4.8b, v5.8b, #4
	ror	w12, w7, #6
	shl	v8.2s, v3.2s, #15
	eor	w13, w8, w9
	sri	v8.2s, v3.2s, #17
	eor	w12, w12, w7, ror 11
	shl	v9.2s, v3.2s, #13
	and	w13, w13, w7
	sri	v9.2s, v3.2s, #19
	eor	w12, w12, w7, ror 25
	eor	v9.8b, v9.8b, v8.8b
	eor	w13, w13, w9
	ushr	v8.2s, v3.2s, #10
	add	w10, w10, w12
	eor	v9.8b, v9.8b, v8.8b
	add	w10, w10, w13
	add	v4.2s, v4.2s, v9.2s
	ldr	w12, [x3, #36]
	ext	v11.8b, v0.8b, v1.8b, #4
	add	w10, w10, w14
	add	v4.2s, v4.2s, v11.2s
	add	w10, w10, w12
	shl	v8.2s, v10.2s, #25
	add	w6, w6, w10
	sri	v8.2s, v10.2s, #7
	ror	w12, w11, #2
	shl	v9.2s, v10.2s, #14
	eor	w13, w11, w4
	sri	v9.2s, v10.2s, #18
	eor	w12, w12, w11, ror 13
	eor	v9.8b, v9.8b, v8.8b
	eor	w14, w4, w5
	ushr	v10.2s, v10.2s, #3
	and	w13, w13, w14
	eor	v9.8b, v9.8b, v10.8b
	eor	w12, w12, w11, ror 22
	add	v4.2s, v4.2s, v9.2s
	eor	w13, w13, w4
	add	w10, w10, w12
	add	w10, w10, w13
	# Round 10
	mov	w14, v5.s[0]
	ror	w12, w6, #6
	eor	w13, w7, w8
	eor	w12, w12, w6, ror 11
	and	w13, w13, w6
	eor	w12, w12, w6, ror 25
	eor	w13, w13, w8
	add	w9, w9, w12
	add	w9, w9, w13
	ldr	w12, [x3, #40]
	add	w9, w9, w14
	add	w9, w9, w12
	add	w5, w5, w9
	ror	w12, w10, #2
	eor	w13, w10, w11
	eor	w12, w12, w10, ror 13
	eor	w14, w11, w4
	and	w13, w13, w14
	eor	w12, w12, w10, ror 22
	eor	w13, w13, w11
	add	w9, w9, w12
	add	w9, w9, w13
	# Round 11
	mov	w14, v5.s[1]
	# Calc new W[10]-W[11]
	ext	v10.8b, v5.8b, v6.8b, #4
	ror	w12, w5, #6
	shl	v8.2s, v4.2s, #15
	eor	w13, w6, w7
	sri	v8.2s, v4.2s, #17
	eor	w12, w12, w5, ror 11
	shl	v9.2s, v4.2s, #13
	and	w13, w13, w5
	sri	v9.2s, v4.2s, #19
	eor	w12, w12, w5, ror 25
	eor	v9.8b, v9.8b, v8.8b
	eor	w13, w13, w7
	ushr	v8.2s, v4.2s, #10
	add	w8, w8, w12
	eor	v9.8b, v9.8b, v8.8b
	add	w8, w8, w13
	add	v5.2s, v5.2s, v9.2s
	ldr	w12, [x3, #44]
	ext	v11.8b, v1.8b, v2.8b, #4
	add	w8, w8, w14
	add	v5.2s, v5.2s, v11.2s
	add	w8, w8, w12
	shl	v8.2s, v10.2s, #25
	add	w4, w4, w8
	sri	v8.2s, v10.2s, #7
	ror	w12, w9, #2
	shl	v9.2s, v10.2s, #14
	eor	w13, w9, w10
	sri	v9.2s, v10.2s, #18
	eor	w12, w12, w9, ror 13
	eor	v9.8b, v9.8b, v8.8b
	eor	w14, w10, w11
	ushr	v10.2s, v10.2s, #3
	and	w13, w13, w14
	eor	v9.8b, v9.8b, v10.8b
	eor	w12, w12, w9, ror 22
	add	v5.2s, v5.2s, v9.2s
	eor	w13, w13, w10
	add	w8, w8, w12
	add	w8, w8, w13
	# Round 12
	mov	w14, v6.s[0]
	ror	w12, w4, #6
	eor	w13, w5, w6
	eor	w12, w12, w4, ror 11
	and	w13, w13, w4
	eor	w12, w12, w4, ror 25
	eor	w13, w13, w6
	add	w7, w7, w12
	add	w7, w7, w13
	ldr	w12, [x3, #48]
	add	w7, w7, w14
	add	w7, w7, w12
	add	w11, w11, w7
	ror	w12, w8, #2
	eor	w13, w8, w9
	eor	w12, w12, w8, ror 13
	eor	w14, w9, w10
	and	w13, w13, w14
	eor	w12, w12, w8, ror 22
	eor	w13, w13, w9
	add	w7, w7, w12
	add	w7, w7, w13
	# Round 13
	mov	w14, v6.s[1]
	# Calc new W[12]-W[13]
	ext	v10.8b, v6.8b, v7.8b, #4
	ror	w12, w11, #6
	shl	v8.2s, v5.2s, #15
	eor	w13, w4, w5
	sri	v8.2s, v5.2s, #17
	eor	w12, w12, w11, ror 11
	shl	v9.2s, v5.2s, #13
	and	w13, w13, w11
	sri	v9.2s, v5.2s, #19
	eor	w12, w12, w11, ror 25
	eor	v9.8b, v9.8b, v8.8b
	eor	w13, w13, w5
	ushr	v8.2s, v5.2s, #10
	add	w6, w6, w12
	eor	v9.8b, v9.8b, v8.8b
	add	w6, w6, w13
	add	v6.2s, v6.2s, v9.2s
	ldr	w12, [x3, #52]
	ext	v11.8b, v2.8b, v3.8b, #4
	add	w6, w6, w14
	add	v6.2s, v6.2s, v11.2s
	add	w6, w6, w12
	shl	v8.2s, v10.2s, #25
	add	w10, w10, w6
	sri	v8.2s, v10.2s, #7
	ror	w12, w7, #2
	shl	v9.2s, v10.2s, #14
	eor	w13, w7, w8
	sri	v9.2s, v10.2s, #18
	eor	w12, w12, w7, ror 13
	eor	v9.8b, v9.8b, v8.8b
	eor	w14, w8, w9
	ushr	v10.2s, v10.2s, #3
	and	w13, w13, w14
	eor	v9.8b, v9.8b, v10.8b
	eor	w12, w12, w7, ror 22
	add	v6.2s, v6.2s, v9.2s
	eor	w13, w13, w8
	add	w6, w6, w12
	add	w6, w6, w13
	# Round 14
	mov	w14, v7.s[0]
	ror	w12, w10, #6
	eor	w13, w11, w4
	eor	w12, w12, w10, ror 11
	and	w13, w13, w10
	eor	w12, w12, w10, ror 25
	eor	w13, w13, w4
	add	w5, w5, w12
	add	w5, w5, w13
	ldr	w12, [x3, #56]
	add	w5, w5, w14
	add	w5, w5, w12
	add	w9, w9, w5
	ror	w12, w6, #2
	eor	w13, w6, w7
	eor	w12, w12, w6, ror 13
	eor	w14, w7, w8
	and	w13, w13, w14
	eor	w12, w12, w6, ror 22
	eor	w13, w13, w7
	add	w5, w5, w12
	add	w5, w5, w13
	# Round 15
	mov	w14, v7.s[1]
	# Calc new W[14]-W[15]
	ext	v10.8b, v7.8b, v0.8b, #4
	ror	w12, w9, #6
	shl	v8.2s, v6.2s, #15
	eor	w13, w10, w11
	sri	v8.2s, v6.2s, #17
	eor	w12, w12, w9, ror 11
	shl	v9.2s, v6.2s, #13
	and	w13, w13, w9
	sri	v9.2s, v6.2s, #19
	eor	w12, w12, w9, ror 25
	eor	v9.8b, v9.8b, v8.8b
	eor	w13, w13, w11
	ushr	v8.2s, v6.2s, #10
	add	w4, w4, w12
	eor	v9.8b, v9.8b, v8.8b
	add	w4, w4, w13
	add	v7.2s, v7.2s, v9.2s
	ldr	w12, [x3, #60]
	ext	v11.8b, v3.8b, v4.8b, #4
	add	w4, w4, w14
	add	v7.2s, v7.2s, v11.2s
	add	w4, w4, w12
	shl	v8.2s, v10.2s, #25
	add	w8, w8, w4
	sri	v8.2s, v10.2s, #7
	ror	w12, w5, #2
	shl	v9.2s, v10.2s, #14
	eor	w13, w5, w6
	sri	v9.2s, v10.2s, #18
	eor	w12, w12, w5, ror 13
	eor	v9.8b, v9.8b, v8.8b
	eor	w14, w6, w7
	ushr	v10.2s, v10.2s, #3
	and	w13, w13, w14
	eor	v9.8b, v9.8b, v10.8b
	eor	w12, w12, w5, ror 22
	add	v7.2s, v7.2s, v9.2s
	eor	w13, w13, w6
	add	w4, w4, w12
	add	w4, w4, w13
	add	x3, x3, #0x40
	subs	x24, x24, #1
	bne	L_sha256_len_neon_start
	# Round 0
	mov	w14, v0.s[0]
	ror	w12, w8, #6
	eor	w13, w9, w10
	eor	w12, w12, w8, ror 11
	and	w13, w13, w8
	eor	w12, w12, w8, ror 25
	eor	w13, w13, w10
	add	w11, w11, w12
	add	w11, w11, w13
	ldr	w12, [x3]
	add	w11, w11, w14
	add	w11, w11, w12
	add	w7, w7, w11
	ror	w12, w4, #2
	eor	w13, w4, w5
	eor	w12, w12, w4, ror 13
	eor	w14, w5, w6
	and	w13, w13, w14
	eor	w12, w12, w4, ror 22
	eor	w13, w13, w5
	add	w11, w11, w12
	add	w11, w11, w13
	# Round 1
	mov	w14, v0.s[1]
	ror	w12, w7, #6
	eor	w13, w8, w9
	eor	w12, w12, w7, ror 11
	and	w13, w13, w7
	eor	w12, w12, w7, ror 25
	eor	w13, w13, w9
	add	w10, w10, w12
	add	w10, w10, w13
	ldr	w12, [x3, #4]
	add	w10, w10, w14
	add	w10, w10, w12
	add	w6, w6, w10
	ror	w12, w11, #2
	eor	w13, w11, w4
	eor	w12, w12, w11, ror 13
	eor	w14, w4, w5
	and	w13, w13, w14
	eor	w12, w12, w11, ror 22
	eor	w13, w13, w4
	add	w10, w10, w12
	add	w10, w10, w13
	# Round 2
	mov	w14, v1.s[0]
	ror	w12, w6, #6
	eor	w13, w7, w8
	eor	w12, w12, w6, ror 11
	and	w13, w13, w6
	eor	w12, w12, w6, ror 25
	eor	w13, w13, w8
	add	w9, w9, w12
	add	w9, w9, w13
	ldr	w12, [x3, #8]
	add	w9, w9, w14
	add	w9, w9, w12
	add	w5, w5, w9
	ror	w12, w10, #2
	eor	w13, w10, w11
	eor	w12, w12, w10, ror 13
	eor	w14, w11, w4
	and	w13, w13, w14
	eor	w12, w12, w10, ror 22
	eor	w13, w13, w11
	add	w9, w9, w12
	add	w9, w9, w13
	# Round 3
	mov	w14, v1.s[1]
	ror	w12, w5, #6
	eor	w13, w6, w7
	eor	w12, w12, w5, ror 11
	and	w13, w13, w5
	eor	w12, w12, w5, ror 25
	eor	w13, w13, w7
	add	w8, w8, w12
	add	w8, w8, w13
	ldr	w12, [x3, #12]
	add	w8, w8, w14
	add	w8, w8, w12
	add	w4, w4, w8
	ror	w12, w9, #2
	eor	w13, w9, w10
	eor	w12, w12, w9, ror 13
	eor	w14, w10, w11
	and	w13, w13, w14
	eor	w12, w12, w9, ror 22
	eor	w13, w13, w10
	add	w8, w8, w12
	add	w8, w8, w13
	# Round 4
	mov	w14, v2.s[0]
	ror	w12, w4, #6
	eor	w13, w5, w6
	eor	w12, w12, w4, ror 11
	and	w13, w13, w4
	eor	w12, w12, w4, ror 25
	eor	w13, w13, w6
	add	w7, w7, w12
	add	w7, w7, w13
	ldr	w12, [x3, #16]
	add	w7, w7, w14
	add	w7, w7, w12
	add	w11, w11, w7
	ror	w12, w8, #2
	eor	w13, w8, w9
	eor	w12, w12, w8, ror 13
	eor	w14, w9, w10
	and	w13, w13, w14
	eor	w12, w12, w8, ror 22
	eor	w13, w13, w9
	add	w7, w7, w12
	add	w7, w7, w13
	# Round 5
	mov	w14, v2.s[1]
	ror	w12, w11, #6
	eor	w13, w4, w5
	eor	w12, w12, w11, ror 11
	and	w13, w13, w11
	eor	w12, w12, w11, ror 25
	eor	w13, w13, w5
	add	w6, w6, w12
	add	w6, w6, w13
	ldr	w12, [x3, #20]
	add	w6, w6, w14
	add	w6, w6, w12
	add	w10, w10, w6
	ror	w12, w7, #2
	eor	w13, w7, w8
	eor	w12, w12, w7, ror 13
	eor	w14, w8, w9
	and	w13, w13, w14
	eor	w12, w12, w7, ror 22
	eor	w13, w13, w8
	add	w6, w6, w12
	add	w6, w6, w13
	# Round 6
	mov	w14, v3.s[0]
	ror	w12, w10, #6
	eor	w13, w11, w4
	eor	w12, w12, w10, ror 11
	and	w13, w13, w10
	eor	w12, w12, w10, ror 25
	eor	w13, w13, w4
	add	w5, w5, w12
	add	w5, w5, w13
	ldr	w12, [x3, #24]
	add	w5, w5, w14
	add	w5, w5, w12
	add	w9, w9, w5
	ror	w12, w6, #2
	eor	w13, w6, w7
	eor	w12, w12, w6, ror 13
	eor	w14, w7, w8
	and	w13, w13, w14
	eor	w12, w12, w6, ror 22
	eor	w13, w13, w7
	add	w5, w5, w12
	add	w5, w5, w13
	# Round 7
	mov	w14, v3.s[1]
	ror	w12, w9, #6
	eor	w13, w10, w11
	eor	w12, w12, w9, ror 11
	and	w13, w13, w9
	eor	w12, w12, w9, ror 25
	eor	w13, w13, w11
	add	w4, w4, w12
	add	w4, w4, w13
	ldr	w12, [x3, #28]
	add	w4, w4, w14
	add	w4, w4, w12
	add	w8, w8, w4
	ror	w12, w5, #2
	eor	w13, w5, w6
	eor	w12, w12, w5, ror 13
	eor	w14, w6, w7
	and	w13, w13, w14
	eor	w12, w12, w5, ror 22
	eor	w13, w13, w6
	add	w4, w4, w12
	add	w4, w4, w13
	# Round 8
	mov	w14, v4.s[0]
	ror	w12, w8, #6
	eor	w13, w9, w10
	eor	w12, w12, w8, ror 11
	and	w13, w13, w8
	eor	w12, w12, w8, ror 25
	eor	w13, w13, w10
	add	w11, w11, w12
	add	w11, w11, w13
	ldr	w12, [x3, #32]
	add	w11, w11, w14
	add	w11, w11, w12
	add	w7, w7, w11
	ror	w12, w4, #2
	eor	w13, w4, w5
	eor	w12, w12, w4, ror 13
	eor	w14, w5, w6
	and	w13, w13, w14
	eor	w12, w12, w4, ror 22
	eor	w13, w13, w5
	add	w11, w11, w12
	add	w11, w11, w13
	# Round 9
	mov	w14, v4.s[1]
	ror	w12, w7, #6
	eor	w13, w8, w9
	eor	w12, w12, w7, ror 11
	and	w13, w13, w7
	eor	w12, w12, w7, ror 25
	eor	w13, w13, w9
	add	w10, w10, w12
	add	w10, w10, w13
	ldr	w12, [x3, #36]
	add	w10, w10, w14
	add	w10, w10, w12
	add	w6, w6, w10
	ror	w12, w11, #2
	eor	w13, w11, w4
	eor	w12, w12, w11, ror 13
	eor	w14, w4, w5
	and	w13, w13, w14
	eor	w12, w12, w11, ror 22
	eor	w13, w13, w4
	add	w10, w10, w12
	add	w10, w10, w13
	# Round 10
	mov	w14, v5.s[0]
	ror	w12, w6, #6
	eor	w13, w7, w8
	eor	w12, w12, w6, ror 11
	and	w13, w13, w6
	eor	w12, w12, w6, ror 25
	eor	w13, w13, w8
	add	w9, w9, w12
	add	w9, w9, w13
	ldr	w12, [x3, #40]
	add	w9, w9, w14
	add	w9, w9, w12
	add	w5, w5, w9
	ror	w12, w10, #2
	eor	w13, w10, w11
	eor	w12, w12, w10, ror 13
	eor	w14, w11, w4
	and	w13, w13, w14
	eor	w12, w12, w10, ror 22
	eor	w13, w13, w11
	add	w9, w9, w12
	add	w9, w9, w13
	# Round 11
	mov	w14, v5.s[1]
	ror	w12, w5, #6
	eor	w13, w6, w7
	eor	w12, w12, w5, ror 11
	and	w13, w13, w5
	eor	w12, w12, w5, ror 25
	eor	w13, w13, w7
	add	w8, w8, w12
	add	w8, w8, w13
	ldr	w12, [x3, #44]
	add	w8, w8, w14
	add	w8, w8, w12
	add	w4, w4, w8
	ror	w12, w9, #2
	eor	w13, w9, w10
	eor	w12, w12, w9, ror 13
	eor	w14, w10, w11
	and	w13, w13, w14
	eor	w12, w12, w9, ror 22
	eor	w13, w13, w10
	add	w8, w8, w12
	add	w8, w8, w13
	# Round 12
	mov	w14, v6.s[0]
	ror	w12, w4, #6
	eor	w13, w5, w6
	eor	w12, w12, w4, ror 11
	and	w13, w13, w4
	eor	w12, w12, w4, ror 25
	eor	w13, w13, w6
	add	w7, w7, w12
	add	w7, w7, w13
	ldr	w12, [x3, #48]
	add	w7, w7, w14
	add	w7, w7, w12
	add	w11, w11, w7
	ror	w12, w8, #2
	eor	w13, w8, w9
	eor	w12, w12, w8, ror 13
	eor	w14, w9, w10
	and	w13, w13, w14
	eor	w12, w12, w8, ror 22
	eor	w13, w13, w9
	add	w7, w7, w12
	add	w7, w7, w13
	# Round 13
	mov	w14, v6.s[1]
	ror	w12, w11, #6
	eor	w13, w4, w5
	eor	w12, w12, w11, ror 11
	and	w13, w13, w11
	eor	w12, w12, w11, ror 25
	eor	w13, w13, w5
	add	w6, w6, w12
	add	w6, w6, w13
	ldr	w12, [x3, #52]
	add	w6, w6, w14
	add	w6, w6, w12
	add	w10, w10, w6
	ror	w12, w7, #2
	eor	w13, w7, w8
	eor	w12, w12, w7, ror 13
	eor	w14, w8, w9
	and	w13, w13, w14
	eor	w12, w12, w7, ror 22
	eor	w13, w13, w8
	add	w6, w6, w12
	add	w6, w6, w13
	# Round 14
	mov	w14, v7.s[0]
	ror	w12, w10, #6
	eor	w13, w11, w4
	eor	w12, w12, w10, ror 11
	and	w13, w13, w10
	eor	w12, w12, w10, ror 25
	eor	w13, w13, w4
	add	w5, w5, w12
	add	w5, w5, w13
	ldr	w12, [x3, #56]
	add	w5, w5, w14
	add	w5, w5, w12
	add	w9, w9, w5
	ror	w12, w6, #2
	eor	w13, w6, w7
	eor	w12, w12, w6, ror 13
	eor	w14, w7, w8
	and	w13, w13, w14
	eor	w12, w12, w6, ror 22
	eor	w13, w13, w7
	add	w5, w5, w12
	add	w5, w5, w13
	# Round 15
	mov	w14, v7.s[1]
	ror	w12, w9, #6
	eor	w13, w10, w11
	eor	w12, w12, w9, ror 11
	and	w13, w13, w9
	eor	w12, w12, w9, ror 25
	eor	w13, w13, w11
	add	w4, w4, w12
	add	w4, w4, w13
	ldr	w12, [x3, #60]
	add	w4, w4, w14
	add	w4, w4, w12
	add	w8, w8, w4
	ror	w12, w5, #2
	eor	w13, w5, w6
	eor	w12, w12, w5, ror 13
	eor	w14, w6, w7
	and	w13, w13, w14
	eor	w12, w12, w5, ror 22
	eor	w13, w13, w6
	add	w4, w4, w12
	add	w4, w4, w13
	add	w11, w11, w23
	add	w10, w10, w22
	add	w9, w9, w21
	add	w8, w8, w20
	add	w7, w7, w19
	add	w6, w6, w17
	add	w5, w5, w16
	add	w4, w4, w15
	subs	w2, w2, #0x40
	sub	x3, x3, #0xc0
	bne	L_sha256_len_neon_begin
	str	w4, [x0]
	str	w5, [x0, #4]
	str	w6, [x0, #8]
	str	w7, [x0, #12]
	str	w8, [x0, #16]
	str	w9, [x0, #20]
	str	w10, [x0, #24]
	str	w11, [x0, #28]
	ldp	x17, x19, [x29, #24]
	ldp	x20, x21, [x29, #40]
	ldp	x22, x23, [x29, #56]
	ldr	x24, [x29, #72]
	ldp	d8, d9, [x29, #80]
	ldp	d10, d11, [x29, #96]
	ldp	x29, x30, [sp], #0x70
	ret
#ifndef __APPLE__
	.size	Transform_Sha256_Len_neon,.-Transform_Sha256_Len_neon
#endif /* __APPLE__ */
#ifndef WOLFSSL_ARMASM_NO_HW_CRYPTO
#ifndef __APPLE__
	.text
	.type	L_SHA256_trans_crypto_len_k, %object
	.section	.rodata
	.size	L_SHA256_trans_crypto_len_k, 256
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_SHA256_trans_crypto_len_k:
	.word	0x428a2f98
	.word	0x71374491
	.word	0xb5c0fbcf
	.word	0xe9b5dba5
	.word	0x3956c25b
	.word	0x59f111f1
	.word	0x923f82a4
	.word	0xab1c5ed5
	.word	0xd807aa98
	.word	0x12835b01
	.word	0x243185be
	.word	0x550c7dc3
	.word	0x72be5d74
	.word	0x80deb1fe
	.word	0x9bdc06a7
	.word	0xc19bf174
	.word	0xe49b69c1
	.word	0xefbe4786
	.word	0x0fc19dc6
	.word	0x240ca1cc
	.word	0x2de92c6f
	.word	0x4a7484aa
	.word	0x5cb0a9dc
	.word	0x76f988da
	.word	0x983e5152
	.word	0xa831c66d
	.word	0xb00327c8
	.word	0xbf597fc7
	.word	0xc6e00bf3
	.word	0xd5a79147
	.word	0x06ca6351
	.word	0x14292967
	.word	0x27b70a85
	.word	0x2e1b2138
	.word	0x4d2c6dfc
	.word	0x53380d13
	.word	0x650a7354
	.word	0x766a0abb
	.word	0x81c2c92e
	.word	0x92722c85
	.word	0xa2bfe8a1
	.word	0xa81a664b
	.word	0xc24b8b70
	.word	0xc76c51a3
	.word	0xd192e819
	.word	0xd6990624
	.word	0xf40e3585
	.word	0x106aa070
	.word	0x19a4c116
	.word	0x1e376c08
	.word	0x2748774c
	.word	0x34b0bcb5
	.word	0x391c0cb3
	.word	0x4ed8aa4a
	.word	0x5b9cca4f
	.word	0x682e6ff3
	.word	0x748f82ee
	.word	0x78a5636f
	.word	0x84c87814
	.word	0x8cc70208
	.word	0x90befffa
	.word	0xa4506ceb
	.word	0xbef9a3f7
	.word	0xc67178f2
#ifndef __APPLE__
.text
.globl	Transform_Sha256_Len_crypto
.type	Transform_Sha256_Len_crypto,@function
.align	2
Transform_Sha256_Len_crypto:
#else
.section	__TEXT,__text
.globl	_Transform_Sha256_Len_crypto
.p2align	2
_Transform_Sha256_Len_crypto:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x3, L_SHA256_trans_crypto_len_k
	add  x3, x3, :lo12:L_SHA256_trans_crypto_len_k
#else
	adrp x3, L_SHA256_trans_crypto_len_k@PAGE
	add  x3, x3, :lo12:L_SHA256_trans_crypto_len_k@PAGEOFF
#endif /* __APPLE__ */
	# Load K into vector registers
	ld1	{v8.4s, v9.4s, v10.4s, v11.4s}, [x3], #0x40
	ld1	{v12.4s, v13.4s, v14.4s, v15.4s}, [x3], #0x40
	ld1	{v16.4s, v17.4s, v18.4s, v19.4s}, [x3], #0x40
	ld1	{v20.4s, v21.4s, v22.4s, v23.4s}, [x3], #0x40
	# Load digest into working vars
	ld1	{v0.4s, v1.4s}, [x0]
	# Start of loop processing a block
L_sha256_len_crypto_begin:
	# Load W
	ld1	{v4.4s, v5.4s, v6.4s, v7.4s}, [x1], #0x40
	rev32	v4.16b, v4.16b
	rev32	v5.16b, v5.16b
	rev32	v6.16b, v6.16b
	rev32	v7.16b, v7.16b
	# Copy digest to add in at end
	mov	v2.16b, v0.16b
	mov	v3.16b, v1.16b
	# Start 16 rounds
	# Round 1
	add	v24.4s, v4.4s, v8.4s
	mov	v25.16b, v0.16b
	sha256h	q0, q1, v24.4s
	sha256h2	q1, q25, v24.4s
	# Round 2
	sha256su0	v4.4s, v5.4s
	add	v24.4s, v5.4s, v9.4s
	mov	v25.16b, v0.16b
	sha256su1	v4.4s, v6.4s, v7.4s
	sha256h	q0, q1, v24.4s
	sha256h2	q1, q25, v24.4s
	# Round 3
	sha256su0	v5.4s, v6.4s
	add	v24.4s, v6.4s, v10.4s
	mov	v25.16b, v0.16b
	sha256su1	v5.4s, v7.4s, v4.4s
	sha256h	q0, q1, v24.4s
	sha256h2	q1, q25, v24.4s
	# Round 4
	sha256su0	v6.4s, v7.4s
	add	v24.4s, v7.4s, v11.4s
	mov	v25.16b, v0.16b
	sha256su1	v6.4s, v4.4s, v5.4s
	sha256h	q0, q1, v24.4s
	sha256h2	q1, q25, v24.4s
	# Round 5
	sha256su0	v7.4s, v4.4s
	add	v24.4s, v4.4s, v12.4s
	mov	v25.16b, v0.16b
	sha256su1	v7.4s, v5.4s, v6.4s
	sha256h	q0, q1, v24.4s
	sha256h2	q1, q25, v24.4s
	# Round 6
	sha256su0	v4.4s, v5.4s
	add	v24.4s, v5.4s, v13.4s
	mov	v25.16b, v0.16b
	sha256su1	v4.4s, v6.4s, v7.4s
	sha256h	q0, q1, v24.4s
	sha256h2	q1, q25, v24.4s
	# Round 7
	sha256su0	v5.4s, v6.4s
	add	v24.4s, v6.4s, v14.4s
	mov	v25.16b, v0.16b
	sha256su1	v5.4s, v7.4s, v4.4s
	sha256h	q0, q1, v24.4s
	sha256h2	q1, q25, v24.4s
	# Round 8
	sha256su0	v6.4s, v7.4s
	add	v24.4s, v7.4s, v15.4s
	mov	v25.16b, v0.16b
	sha256su1	v6.4s, v4.4s, v5.4s
	sha256h	q0, q1, v24.4s
	sha256h2	q1, q25, v24.4s
	# Round 9
	sha256su0	v7.4s, v4.4s
	add	v24.4s, v4.4s, v16.4s
	mov	v25.16b, v0.16b
	sha256su1	v7.4s, v5.4s, v6.4s
	sha256h	q0, q1, v24.4s
	sha256h2	q1, q25, v24.4s
	# Round 10
	sha256su0	v4.4s, v5.4s
	add	v24.4s, v5.4s, v17.4s
	mov	v25.16b, v0.16b
	sha256su1	v4.4s, v6.4s, v7.4s
	sha256h	q0, q1, v24.4s
	sha256h2	q1, q25, v24.4s
	# Round 11
	sha256su0	v5.4s, v6.4s
	add	v24.4s, v6.4s, v18.4s
	mov	v25.16b, v0.16b
	sha256su1	v5.4s, v7.4s, v4.4s
	sha256h	q0, q1, v24.4s
	sha256h2	q1, q25, v24.4s
	# Round 12
	sha256su0	v6.4s, v7.4s
	add	v24.4s, v7.4s, v19.4s
	mov	v25.16b, v0.16b
	sha256su1	v6.4s, v4.4s, v5.4s
	sha256h	q0, q1, v24.4s
	sha256h2	q1, q25, v24.4s
	# Round 13
	sha256su0	v7.4s, v4.4s
	add	v24.4s, v4.4s, v20.4s
	mov	v25.16b, v0.16b
	sha256su1	v7.4s, v5.4s, v6.4s
	sha256h	q0, q1, v24.4s
	sha256h2	q1, q25, v24.4s
	# Round 14
	add	v24.4s, v5.4s, v21.4s
	mov	v25.16b, v0.16b
	sha256h	q0, q1, v24.4s
	sha256h2	q1, q25, v24.4s
	# Round 15
	add	v24.4s, v6.4s, v22.4s
	mov	v25.16b, v0.16b
	sha256h	q0, q1, v24.4s
	sha256h2	q1, q25, v24.4s
	# Round 16
	add	v24.4s, v7.4s, v23.4s
	mov	v25.16b, v0.16b
	sha256h	q0, q1, v24.4s
	sha256h2	q1, q25, v24.4s
	# Done 16 rounds
	add	v0.4s, v0.4s, v2.4s
	add	v1.4s, v1.4s, v3.4s
	subs	w2, w2, #0x40
	bne	L_sha256_len_crypto_begin
	# Store digest back
	st1	{v0.4s, v1.4s}, [x0]
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	Transform_Sha256_Len_crypto,.-Transform_Sha256_Len_crypto
#endif /* __APPLE__ */
#endif /* !WOLFSSL_ARMASM_NO_HW_CRYPTO */
#endif /* !NO_SHA256 || WOLFSSL_SHA224 */
#endif /* __aarch64__ */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
