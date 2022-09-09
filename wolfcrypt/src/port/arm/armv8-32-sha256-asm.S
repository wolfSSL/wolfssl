/* armv8-32-sha256-asm
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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
 *   ruby ./sha2/sha256.rb arm32 ../wolfssl/wolfcrypt/src/port/arm/armv8-32-sha256-asm.S
 */

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_ARMASM
#ifndef __aarch64__
#ifndef NO_SHA256
#ifdef WOLFSSL_ARMASM_NO_NEON
	.text
	.type	L_SHA256_transform_len_k, %object
	.size	L_SHA256_transform_len_k, 256
	.align	3
L_SHA256_transform_len_k:
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
	.word	0xfc19dc6
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
	.word	0x6ca6351
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
	.text
	.align	2
	.globl	Transform_Sha256_Len
	.type	Transform_Sha256_Len, %function
Transform_Sha256_Len:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	sub	sp, sp, #0xc0
	adr	r3, L_SHA256_transform_len_k
	# Copy digest to add in at end
	ldr	r12, [r0]
	ldr	lr, [r0, #4]
	ldrd	r4, r5, [r0, #8]
	ldrd	r6, r7, [r0, #16]
	ldrd	r8, r9, [r0, #24]
	str	r12, [sp, #64]
	str	lr, [sp, #68]
	strd	r4, r5, [sp, #72]
	strd	r6, r7, [sp, #80]
	strd	r8, r9, [sp, #88]
	# Start of loop processing a block
L_SHA256_transform_len_begin:
	# Load, Reverse and Store W - 64 bytes
	ldr	r12, [r1]
	ldr	lr, [r1, #4]
	ldrd	r4, r5, [r1, #8]
	ldrd	r6, r7, [r1, #16]
	ldrd	r8, r9, [r1, #24]
	rev	r12, r12
	rev	lr, lr
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
	rev	r8, r8
	rev	r9, r9
	str	r12, [sp]
	str	lr, [sp, #4]
	strd	r4, r5, [sp, #8]
	strd	r6, r7, [sp, #16]
	strd	r8, r9, [sp, #24]
	ldr	r12, [r1, #32]
	ldr	lr, [r1, #36]
	ldrd	r4, r5, [r1, #40]
	ldrd	r6, r7, [r1, #48]
	ldrd	r8, r9, [r1, #56]
	rev	r12, r12
	rev	lr, lr
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r7, r7
	rev	r8, r8
	rev	r9, r9
	str	r12, [sp, #32]
	str	lr, [sp, #36]
	strd	r4, r5, [sp, #40]
	strd	r6, r7, [sp, #48]
	strd	r8, r9, [sp, #56]
	ldr	r9, [r0, #4]
	ldr	r12, [r0, #8]
	eor	r9, r9, r12
	mov	r10, #3
	# Start of 16 rounds
L_SHA256_transform_len_start:
	# Round 0
	ldr	lr, [r0, #16]
	ldr	r4, [r0, #20]
	ldr	r5, [r0, #24]
	ldr	r7, [r0, #28]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp]
	ldr	r4, [r3]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0]
	ldr	r4, [r0, #4]
	ldr	r5, [r0, #8]
	ldr	r6, [r0, #12]
	ror	r12, lr, #2
	eor	r8, lr, r4
	eor	r12, r12, lr, ror #13
	and	r9, r9, r8
	eor	r12, r12, lr, ror #22
	eor	r9, r9, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r9
	str	r6, [r0, #12]
	str	r7, [r0, #28]
	# Calc new W[0]
	ldr	r4, [sp, #56]
	ldr	r5, [sp, #36]
	ldr	r6, [sp, #4]
	ldr	r7, [sp]
	ror	r12, r4, #17
	ror	lr, r6, #7
	eor	r12, r12, r4, ror #19
	eor	lr, lr, r6, ror #18
	eor	r12, r12, r4, lsr #10
	eor	lr, lr, r6, lsr #3
	add	r7, r7, r5
	add	r12, r12, lr
	add	r7, r7, r12
	str	r7, [sp]
	# Round 1
	ldr	lr, [r0, #12]
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
	ldr	r7, [r0, #24]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #4]
	ldr	r4, [r3, #4]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #28]
	ldr	r4, [r0]
	ldr	r5, [r0, #4]
	ldr	r6, [r0, #8]
	ror	r12, lr, #2
	eor	r9, lr, r4
	eor	r12, r12, lr, ror #13
	and	r8, r8, r9
	eor	r12, r12, lr, ror #22
	eor	r8, r8, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r8
	str	r6, [r0, #8]
	str	r7, [r0, #24]
	# Calc new W[1]
	ldr	r4, [sp, #60]
	ldr	r5, [sp, #40]
	ldr	r6, [sp, #8]
	ldr	r7, [sp, #4]
	ror	r12, r4, #17
	ror	lr, r6, #7
	eor	r12, r12, r4, ror #19
	eor	lr, lr, r6, ror #18
	eor	r12, r12, r4, lsr #10
	eor	lr, lr, r6, lsr #3
	add	r7, r7, r5
	add	r12, r12, lr
	add	r7, r7, r12
	str	r7, [sp, #4]
	# Round 2
	ldr	lr, [r0, #8]
	ldr	r4, [r0, #12]
	ldr	r5, [r0, #16]
	ldr	r7, [r0, #20]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #8]
	ldr	r4, [r3, #8]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #24]
	ldr	r4, [r0, #28]
	ldr	r5, [r0]
	ldr	r6, [r0, #4]
	ror	r12, lr, #2
	eor	r8, lr, r4
	eor	r12, r12, lr, ror #13
	and	r9, r9, r8
	eor	r12, r12, lr, ror #22
	eor	r9, r9, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r9
	str	r6, [r0, #4]
	str	r7, [r0, #20]
	# Calc new W[2]
	ldr	r4, [sp]
	ldr	r5, [sp, #44]
	ldr	r6, [sp, #12]
	ldr	r7, [sp, #8]
	ror	r12, r4, #17
	ror	lr, r6, #7
	eor	r12, r12, r4, ror #19
	eor	lr, lr, r6, ror #18
	eor	r12, r12, r4, lsr #10
	eor	lr, lr, r6, lsr #3
	add	r7, r7, r5
	add	r12, r12, lr
	add	r7, r7, r12
	str	r7, [sp, #8]
	# Round 3
	ldr	lr, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
	ldr	r7, [r0, #16]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #12]
	ldr	r4, [r3, #12]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #20]
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
	ldr	r6, [r0]
	ror	r12, lr, #2
	eor	r9, lr, r4
	eor	r12, r12, lr, ror #13
	and	r8, r8, r9
	eor	r12, r12, lr, ror #22
	eor	r8, r8, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r8
	str	r6, [r0]
	str	r7, [r0, #16]
	# Calc new W[3]
	ldr	r4, [sp, #4]
	ldr	r5, [sp, #48]
	ldr	r6, [sp, #16]
	ldr	r7, [sp, #12]
	ror	r12, r4, #17
	ror	lr, r6, #7
	eor	r12, r12, r4, ror #19
	eor	lr, lr, r6, ror #18
	eor	r12, r12, r4, lsr #10
	eor	lr, lr, r6, lsr #3
	add	r7, r7, r5
	add	r12, r12, lr
	add	r7, r7, r12
	str	r7, [sp, #12]
	# Round 4
	ldr	lr, [r0]
	ldr	r4, [r0, #4]
	ldr	r5, [r0, #8]
	ldr	r7, [r0, #12]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #16]
	ldr	r4, [r3, #16]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #16]
	ldr	r4, [r0, #20]
	ldr	r5, [r0, #24]
	ldr	r6, [r0, #28]
	ror	r12, lr, #2
	eor	r8, lr, r4
	eor	r12, r12, lr, ror #13
	and	r9, r9, r8
	eor	r12, r12, lr, ror #22
	eor	r9, r9, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r9
	str	r6, [r0, #28]
	str	r7, [r0, #12]
	# Calc new W[4]
	ldr	r4, [sp, #8]
	ldr	r5, [sp, #52]
	ldr	r6, [sp, #20]
	ldr	r7, [sp, #16]
	ror	r12, r4, #17
	ror	lr, r6, #7
	eor	r12, r12, r4, ror #19
	eor	lr, lr, r6, ror #18
	eor	r12, r12, r4, lsr #10
	eor	lr, lr, r6, lsr #3
	add	r7, r7, r5
	add	r12, r12, lr
	add	r7, r7, r12
	str	r7, [sp, #16]
	# Round 5
	ldr	lr, [r0, #28]
	ldr	r4, [r0]
	ldr	r5, [r0, #4]
	ldr	r7, [r0, #8]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #20]
	ldr	r4, [r3, #20]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #12]
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
	ldr	r6, [r0, #24]
	ror	r12, lr, #2
	eor	r9, lr, r4
	eor	r12, r12, lr, ror #13
	and	r8, r8, r9
	eor	r12, r12, lr, ror #22
	eor	r8, r8, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r8
	str	r6, [r0, #24]
	str	r7, [r0, #8]
	# Calc new W[5]
	ldr	r4, [sp, #12]
	ldr	r5, [sp, #56]
	ldr	r6, [sp, #24]
	ldr	r7, [sp, #20]
	ror	r12, r4, #17
	ror	lr, r6, #7
	eor	r12, r12, r4, ror #19
	eor	lr, lr, r6, ror #18
	eor	r12, r12, r4, lsr #10
	eor	lr, lr, r6, lsr #3
	add	r7, r7, r5
	add	r12, r12, lr
	add	r7, r7, r12
	str	r7, [sp, #20]
	# Round 6
	ldr	lr, [r0, #24]
	ldr	r4, [r0, #28]
	ldr	r5, [r0]
	ldr	r7, [r0, #4]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #24]
	ldr	r4, [r3, #24]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #8]
	ldr	r4, [r0, #12]
	ldr	r5, [r0, #16]
	ldr	r6, [r0, #20]
	ror	r12, lr, #2
	eor	r8, lr, r4
	eor	r12, r12, lr, ror #13
	and	r9, r9, r8
	eor	r12, r12, lr, ror #22
	eor	r9, r9, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r9
	str	r6, [r0, #20]
	str	r7, [r0, #4]
	# Calc new W[6]
	ldr	r4, [sp, #16]
	ldr	r5, [sp, #60]
	ldr	r6, [sp, #28]
	ldr	r7, [sp, #24]
	ror	r12, r4, #17
	ror	lr, r6, #7
	eor	r12, r12, r4, ror #19
	eor	lr, lr, r6, ror #18
	eor	r12, r12, r4, lsr #10
	eor	lr, lr, r6, lsr #3
	add	r7, r7, r5
	add	r12, r12, lr
	add	r7, r7, r12
	str	r7, [sp, #24]
	# Round 7
	ldr	lr, [r0, #20]
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
	ldr	r7, [r0]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #28]
	ldr	r4, [r3, #28]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
	ldr	r6, [r0, #16]
	ror	r12, lr, #2
	eor	r9, lr, r4
	eor	r12, r12, lr, ror #13
	and	r8, r8, r9
	eor	r12, r12, lr, ror #22
	eor	r8, r8, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r8
	str	r6, [r0, #16]
	str	r7, [r0]
	# Calc new W[7]
	ldr	r4, [sp, #20]
	ldr	r5, [sp]
	ldr	r6, [sp, #32]
	ldr	r7, [sp, #28]
	ror	r12, r4, #17
	ror	lr, r6, #7
	eor	r12, r12, r4, ror #19
	eor	lr, lr, r6, ror #18
	eor	r12, r12, r4, lsr #10
	eor	lr, lr, r6, lsr #3
	add	r7, r7, r5
	add	r12, r12, lr
	add	r7, r7, r12
	str	r7, [sp, #28]
	# Round 8
	ldr	lr, [r0, #16]
	ldr	r4, [r0, #20]
	ldr	r5, [r0, #24]
	ldr	r7, [r0, #28]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #32]
	ldr	r4, [r3, #32]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0]
	ldr	r4, [r0, #4]
	ldr	r5, [r0, #8]
	ldr	r6, [r0, #12]
	ror	r12, lr, #2
	eor	r8, lr, r4
	eor	r12, r12, lr, ror #13
	and	r9, r9, r8
	eor	r12, r12, lr, ror #22
	eor	r9, r9, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r9
	str	r6, [r0, #12]
	str	r7, [r0, #28]
	# Calc new W[8]
	ldr	r4, [sp, #24]
	ldr	r5, [sp, #4]
	ldr	r6, [sp, #36]
	ldr	r7, [sp, #32]
	ror	r12, r4, #17
	ror	lr, r6, #7
	eor	r12, r12, r4, ror #19
	eor	lr, lr, r6, ror #18
	eor	r12, r12, r4, lsr #10
	eor	lr, lr, r6, lsr #3
	add	r7, r7, r5
	add	r12, r12, lr
	add	r7, r7, r12
	str	r7, [sp, #32]
	# Round 9
	ldr	lr, [r0, #12]
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
	ldr	r7, [r0, #24]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #36]
	ldr	r4, [r3, #36]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #28]
	ldr	r4, [r0]
	ldr	r5, [r0, #4]
	ldr	r6, [r0, #8]
	ror	r12, lr, #2
	eor	r9, lr, r4
	eor	r12, r12, lr, ror #13
	and	r8, r8, r9
	eor	r12, r12, lr, ror #22
	eor	r8, r8, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r8
	str	r6, [r0, #8]
	str	r7, [r0, #24]
	# Calc new W[9]
	ldr	r4, [sp, #28]
	ldr	r5, [sp, #8]
	ldr	r6, [sp, #40]
	ldr	r7, [sp, #36]
	ror	r12, r4, #17
	ror	lr, r6, #7
	eor	r12, r12, r4, ror #19
	eor	lr, lr, r6, ror #18
	eor	r12, r12, r4, lsr #10
	eor	lr, lr, r6, lsr #3
	add	r7, r7, r5
	add	r12, r12, lr
	add	r7, r7, r12
	str	r7, [sp, #36]
	# Round 10
	ldr	lr, [r0, #8]
	ldr	r4, [r0, #12]
	ldr	r5, [r0, #16]
	ldr	r7, [r0, #20]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #40]
	ldr	r4, [r3, #40]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #24]
	ldr	r4, [r0, #28]
	ldr	r5, [r0]
	ldr	r6, [r0, #4]
	ror	r12, lr, #2
	eor	r8, lr, r4
	eor	r12, r12, lr, ror #13
	and	r9, r9, r8
	eor	r12, r12, lr, ror #22
	eor	r9, r9, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r9
	str	r6, [r0, #4]
	str	r7, [r0, #20]
	# Calc new W[10]
	ldr	r4, [sp, #32]
	ldr	r5, [sp, #12]
	ldr	r6, [sp, #44]
	ldr	r7, [sp, #40]
	ror	r12, r4, #17
	ror	lr, r6, #7
	eor	r12, r12, r4, ror #19
	eor	lr, lr, r6, ror #18
	eor	r12, r12, r4, lsr #10
	eor	lr, lr, r6, lsr #3
	add	r7, r7, r5
	add	r12, r12, lr
	add	r7, r7, r12
	str	r7, [sp, #40]
	# Round 11
	ldr	lr, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
	ldr	r7, [r0, #16]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #44]
	ldr	r4, [r3, #44]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #20]
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
	ldr	r6, [r0]
	ror	r12, lr, #2
	eor	r9, lr, r4
	eor	r12, r12, lr, ror #13
	and	r8, r8, r9
	eor	r12, r12, lr, ror #22
	eor	r8, r8, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r8
	str	r6, [r0]
	str	r7, [r0, #16]
	# Calc new W[11]
	ldr	r4, [sp, #36]
	ldr	r5, [sp, #16]
	ldr	r6, [sp, #48]
	ldr	r7, [sp, #44]
	ror	r12, r4, #17
	ror	lr, r6, #7
	eor	r12, r12, r4, ror #19
	eor	lr, lr, r6, ror #18
	eor	r12, r12, r4, lsr #10
	eor	lr, lr, r6, lsr #3
	add	r7, r7, r5
	add	r12, r12, lr
	add	r7, r7, r12
	str	r7, [sp, #44]
	# Round 12
	ldr	lr, [r0]
	ldr	r4, [r0, #4]
	ldr	r5, [r0, #8]
	ldr	r7, [r0, #12]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #48]
	ldr	r4, [r3, #48]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #16]
	ldr	r4, [r0, #20]
	ldr	r5, [r0, #24]
	ldr	r6, [r0, #28]
	ror	r12, lr, #2
	eor	r8, lr, r4
	eor	r12, r12, lr, ror #13
	and	r9, r9, r8
	eor	r12, r12, lr, ror #22
	eor	r9, r9, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r9
	str	r6, [r0, #28]
	str	r7, [r0, #12]
	# Calc new W[12]
	ldr	r4, [sp, #40]
	ldr	r5, [sp, #20]
	ldr	r6, [sp, #52]
	ldr	r7, [sp, #48]
	ror	r12, r4, #17
	ror	lr, r6, #7
	eor	r12, r12, r4, ror #19
	eor	lr, lr, r6, ror #18
	eor	r12, r12, r4, lsr #10
	eor	lr, lr, r6, lsr #3
	add	r7, r7, r5
	add	r12, r12, lr
	add	r7, r7, r12
	str	r7, [sp, #48]
	# Round 13
	ldr	lr, [r0, #28]
	ldr	r4, [r0]
	ldr	r5, [r0, #4]
	ldr	r7, [r0, #8]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #52]
	ldr	r4, [r3, #52]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #12]
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
	ldr	r6, [r0, #24]
	ror	r12, lr, #2
	eor	r9, lr, r4
	eor	r12, r12, lr, ror #13
	and	r8, r8, r9
	eor	r12, r12, lr, ror #22
	eor	r8, r8, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r8
	str	r6, [r0, #24]
	str	r7, [r0, #8]
	# Calc new W[13]
	ldr	r4, [sp, #44]
	ldr	r5, [sp, #24]
	ldr	r6, [sp, #56]
	ldr	r7, [sp, #52]
	ror	r12, r4, #17
	ror	lr, r6, #7
	eor	r12, r12, r4, ror #19
	eor	lr, lr, r6, ror #18
	eor	r12, r12, r4, lsr #10
	eor	lr, lr, r6, lsr #3
	add	r7, r7, r5
	add	r12, r12, lr
	add	r7, r7, r12
	str	r7, [sp, #52]
	# Round 14
	ldr	lr, [r0, #24]
	ldr	r4, [r0, #28]
	ldr	r5, [r0]
	ldr	r7, [r0, #4]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #56]
	ldr	r4, [r3, #56]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #8]
	ldr	r4, [r0, #12]
	ldr	r5, [r0, #16]
	ldr	r6, [r0, #20]
	ror	r12, lr, #2
	eor	r8, lr, r4
	eor	r12, r12, lr, ror #13
	and	r9, r9, r8
	eor	r12, r12, lr, ror #22
	eor	r9, r9, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r9
	str	r6, [r0, #20]
	str	r7, [r0, #4]
	# Calc new W[14]
	ldr	r4, [sp, #48]
	ldr	r5, [sp, #28]
	ldr	r6, [sp, #60]
	ldr	r7, [sp, #56]
	ror	r12, r4, #17
	ror	lr, r6, #7
	eor	r12, r12, r4, ror #19
	eor	lr, lr, r6, ror #18
	eor	r12, r12, r4, lsr #10
	eor	lr, lr, r6, lsr #3
	add	r7, r7, r5
	add	r12, r12, lr
	add	r7, r7, r12
	str	r7, [sp, #56]
	# Round 15
	ldr	lr, [r0, #20]
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
	ldr	r7, [r0]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #60]
	ldr	r4, [r3, #60]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
	ldr	r6, [r0, #16]
	ror	r12, lr, #2
	eor	r9, lr, r4
	eor	r12, r12, lr, ror #13
	and	r8, r8, r9
	eor	r12, r12, lr, ror #22
	eor	r8, r8, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r8
	str	r6, [r0, #16]
	str	r7, [r0]
	# Calc new W[15]
	ldr	r4, [sp, #52]
	ldr	r5, [sp, #32]
	ldr	r6, [sp]
	ldr	r7, [sp, #60]
	ror	r12, r4, #17
	ror	lr, r6, #7
	eor	r12, r12, r4, ror #19
	eor	lr, lr, r6, ror #18
	eor	r12, r12, r4, lsr #10
	eor	lr, lr, r6, lsr #3
	add	r7, r7, r5
	add	r12, r12, lr
	add	r7, r7, r12
	str	r7, [sp, #60]
	add	r3, r3, #0x40
	subs	r10, r10, #1
	bne	L_SHA256_transform_len_start
	# Round 0
	ldr	lr, [r0, #16]
	ldr	r4, [r0, #20]
	ldr	r5, [r0, #24]
	ldr	r7, [r0, #28]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp]
	ldr	r4, [r3]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0]
	ldr	r4, [r0, #4]
	ldr	r5, [r0, #8]
	ldr	r6, [r0, #12]
	ror	r12, lr, #2
	eor	r8, lr, r4
	eor	r12, r12, lr, ror #13
	and	r9, r9, r8
	eor	r12, r12, lr, ror #22
	eor	r9, r9, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r9
	str	r6, [r0, #12]
	str	r7, [r0, #28]
	# Round 1
	ldr	lr, [r0, #12]
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
	ldr	r7, [r0, #24]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #4]
	ldr	r4, [r3, #4]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #28]
	ldr	r4, [r0]
	ldr	r5, [r0, #4]
	ldr	r6, [r0, #8]
	ror	r12, lr, #2
	eor	r9, lr, r4
	eor	r12, r12, lr, ror #13
	and	r8, r8, r9
	eor	r12, r12, lr, ror #22
	eor	r8, r8, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r8
	str	r6, [r0, #8]
	str	r7, [r0, #24]
	# Round 2
	ldr	lr, [r0, #8]
	ldr	r4, [r0, #12]
	ldr	r5, [r0, #16]
	ldr	r7, [r0, #20]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #8]
	ldr	r4, [r3, #8]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #24]
	ldr	r4, [r0, #28]
	ldr	r5, [r0]
	ldr	r6, [r0, #4]
	ror	r12, lr, #2
	eor	r8, lr, r4
	eor	r12, r12, lr, ror #13
	and	r9, r9, r8
	eor	r12, r12, lr, ror #22
	eor	r9, r9, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r9
	str	r6, [r0, #4]
	str	r7, [r0, #20]
	# Round 3
	ldr	lr, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
	ldr	r7, [r0, #16]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #12]
	ldr	r4, [r3, #12]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #20]
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
	ldr	r6, [r0]
	ror	r12, lr, #2
	eor	r9, lr, r4
	eor	r12, r12, lr, ror #13
	and	r8, r8, r9
	eor	r12, r12, lr, ror #22
	eor	r8, r8, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r8
	str	r6, [r0]
	str	r7, [r0, #16]
	# Round 4
	ldr	lr, [r0]
	ldr	r4, [r0, #4]
	ldr	r5, [r0, #8]
	ldr	r7, [r0, #12]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #16]
	ldr	r4, [r3, #16]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #16]
	ldr	r4, [r0, #20]
	ldr	r5, [r0, #24]
	ldr	r6, [r0, #28]
	ror	r12, lr, #2
	eor	r8, lr, r4
	eor	r12, r12, lr, ror #13
	and	r9, r9, r8
	eor	r12, r12, lr, ror #22
	eor	r9, r9, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r9
	str	r6, [r0, #28]
	str	r7, [r0, #12]
	# Round 5
	ldr	lr, [r0, #28]
	ldr	r4, [r0]
	ldr	r5, [r0, #4]
	ldr	r7, [r0, #8]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #20]
	ldr	r4, [r3, #20]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #12]
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
	ldr	r6, [r0, #24]
	ror	r12, lr, #2
	eor	r9, lr, r4
	eor	r12, r12, lr, ror #13
	and	r8, r8, r9
	eor	r12, r12, lr, ror #22
	eor	r8, r8, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r8
	str	r6, [r0, #24]
	str	r7, [r0, #8]
	# Round 6
	ldr	lr, [r0, #24]
	ldr	r4, [r0, #28]
	ldr	r5, [r0]
	ldr	r7, [r0, #4]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #24]
	ldr	r4, [r3, #24]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #8]
	ldr	r4, [r0, #12]
	ldr	r5, [r0, #16]
	ldr	r6, [r0, #20]
	ror	r12, lr, #2
	eor	r8, lr, r4
	eor	r12, r12, lr, ror #13
	and	r9, r9, r8
	eor	r12, r12, lr, ror #22
	eor	r9, r9, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r9
	str	r6, [r0, #20]
	str	r7, [r0, #4]
	# Round 7
	ldr	lr, [r0, #20]
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
	ldr	r7, [r0]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #28]
	ldr	r4, [r3, #28]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
	ldr	r6, [r0, #16]
	ror	r12, lr, #2
	eor	r9, lr, r4
	eor	r12, r12, lr, ror #13
	and	r8, r8, r9
	eor	r12, r12, lr, ror #22
	eor	r8, r8, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r8
	str	r6, [r0, #16]
	str	r7, [r0]
	# Round 8
	ldr	lr, [r0, #16]
	ldr	r4, [r0, #20]
	ldr	r5, [r0, #24]
	ldr	r7, [r0, #28]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #32]
	ldr	r4, [r3, #32]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0]
	ldr	r4, [r0, #4]
	ldr	r5, [r0, #8]
	ldr	r6, [r0, #12]
	ror	r12, lr, #2
	eor	r8, lr, r4
	eor	r12, r12, lr, ror #13
	and	r9, r9, r8
	eor	r12, r12, lr, ror #22
	eor	r9, r9, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r9
	str	r6, [r0, #12]
	str	r7, [r0, #28]
	# Round 9
	ldr	lr, [r0, #12]
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
	ldr	r7, [r0, #24]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #36]
	ldr	r4, [r3, #36]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #28]
	ldr	r4, [r0]
	ldr	r5, [r0, #4]
	ldr	r6, [r0, #8]
	ror	r12, lr, #2
	eor	r9, lr, r4
	eor	r12, r12, lr, ror #13
	and	r8, r8, r9
	eor	r12, r12, lr, ror #22
	eor	r8, r8, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r8
	str	r6, [r0, #8]
	str	r7, [r0, #24]
	# Round 10
	ldr	lr, [r0, #8]
	ldr	r4, [r0, #12]
	ldr	r5, [r0, #16]
	ldr	r7, [r0, #20]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #40]
	ldr	r4, [r3, #40]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #24]
	ldr	r4, [r0, #28]
	ldr	r5, [r0]
	ldr	r6, [r0, #4]
	ror	r12, lr, #2
	eor	r8, lr, r4
	eor	r12, r12, lr, ror #13
	and	r9, r9, r8
	eor	r12, r12, lr, ror #22
	eor	r9, r9, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r9
	str	r6, [r0, #4]
	str	r7, [r0, #20]
	# Round 11
	ldr	lr, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
	ldr	r7, [r0, #16]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #44]
	ldr	r4, [r3, #44]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #20]
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
	ldr	r6, [r0]
	ror	r12, lr, #2
	eor	r9, lr, r4
	eor	r12, r12, lr, ror #13
	and	r8, r8, r9
	eor	r12, r12, lr, ror #22
	eor	r8, r8, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r8
	str	r6, [r0]
	str	r7, [r0, #16]
	# Round 12
	ldr	lr, [r0]
	ldr	r4, [r0, #4]
	ldr	r5, [r0, #8]
	ldr	r7, [r0, #12]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #48]
	ldr	r4, [r3, #48]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #16]
	ldr	r4, [r0, #20]
	ldr	r5, [r0, #24]
	ldr	r6, [r0, #28]
	ror	r12, lr, #2
	eor	r8, lr, r4
	eor	r12, r12, lr, ror #13
	and	r9, r9, r8
	eor	r12, r12, lr, ror #22
	eor	r9, r9, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r9
	str	r6, [r0, #28]
	str	r7, [r0, #12]
	# Round 13
	ldr	lr, [r0, #28]
	ldr	r4, [r0]
	ldr	r5, [r0, #4]
	ldr	r7, [r0, #8]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #52]
	ldr	r4, [r3, #52]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #12]
	ldr	r4, [r0, #16]
	ldr	r5, [r0, #20]
	ldr	r6, [r0, #24]
	ror	r12, lr, #2
	eor	r9, lr, r4
	eor	r12, r12, lr, ror #13
	and	r8, r8, r9
	eor	r12, r12, lr, ror #22
	eor	r8, r8, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r8
	str	r6, [r0, #24]
	str	r7, [r0, #8]
	# Round 14
	ldr	lr, [r0, #24]
	ldr	r4, [r0, #28]
	ldr	r5, [r0]
	ldr	r7, [r0, #4]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #56]
	ldr	r4, [r3, #56]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #8]
	ldr	r4, [r0, #12]
	ldr	r5, [r0, #16]
	ldr	r6, [r0, #20]
	ror	r12, lr, #2
	eor	r8, lr, r4
	eor	r12, r12, lr, ror #13
	and	r9, r9, r8
	eor	r12, r12, lr, ror #22
	eor	r9, r9, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r9
	str	r6, [r0, #20]
	str	r7, [r0, #4]
	# Round 15
	ldr	lr, [r0, #20]
	ldr	r4, [r0, #24]
	ldr	r5, [r0, #28]
	ldr	r7, [r0]
	ror	r12, lr, #6
	eor	r4, r4, r5
	eor	r12, r12, lr, ror #11
	and	r4, r4, lr
	eor	r12, r12, lr, ror #25
	eor	r4, r4, r5
	add	r7, r7, r12
	add	r7, r7, r4
	ldr	lr, [sp, #60]
	ldr	r4, [r3, #60]
	add	r7, r7, lr
	add	r7, r7, r4
	ldr	lr, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r5, [r0, #12]
	ldr	r6, [r0, #16]
	ror	r12, lr, #2
	eor	r9, lr, r4
	eor	r12, r12, lr, ror #13
	and	r8, r8, r9
	eor	r12, r12, lr, ror #22
	eor	r8, r8, r4
	add	r6, r6, r7
	add	r7, r7, r12
	add	r7, r7, r8
	str	r6, [r0, #16]
	str	r7, [r0]
	# Add in digest from start
	ldr	r12, [r0]
	ldr	lr, [r0, #4]
	ldrd	r4, r5, [r0, #8]
	ldrd	r6, r7, [sp, #64]
	ldrd	r8, r9, [sp, #72]
	add	r12, r12, r6
	add	lr, lr, r7
	add	r4, r4, r8
	add	r5, r5, r9
	str	r12, [r0]
	str	lr, [r0, #4]
	strd	r4, r5, [r0, #8]
	str	r12, [sp, #64]
	str	lr, [sp, #68]
	strd	r4, r5, [sp, #72]
	ldr	r12, [r0, #16]
	ldr	lr, [r0, #20]
	ldrd	r4, r5, [r0, #24]
	ldrd	r6, r7, [sp, #80]
	ldrd	r8, r9, [sp, #88]
	add	r12, r12, r6
	add	lr, lr, r7
	add	r4, r4, r8
	add	r5, r5, r9
	str	r12, [r0, #16]
	str	lr, [r0, #20]
	strd	r4, r5, [r0, #24]
	str	r12, [sp, #80]
	str	lr, [sp, #84]
	strd	r4, r5, [sp, #88]
	subs	r2, r2, #0x40
	sub	r3, r3, #0xc0
	add	r1, r1, #0x40
	bne	L_SHA256_transform_len_begin
	add	sp, sp, #0xc0
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	Transform_Sha256_Len,.-Transform_Sha256_Len
#endif /* WOLFSSL_ARMASM_NO_NEON */
#ifndef WOLFSSL_ARMASM_NO_NEON
	.text
	.type	L_SHA256_transform_neon_len_k, %object
	.size	L_SHA256_transform_neon_len_k, 256
	.align	3
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
	.word	0xfc19dc6
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
	.word	0x6ca6351
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
	.text
	.align	2
	.globl	Transform_Sha256_Len
	.type	Transform_Sha256_Len, %function
Transform_Sha256_Len:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	vpush	{d8-d11}
	sub	sp, sp, #24
	strd	r0, r1, [sp]
	str	r2, [sp, #8]
	adr	r12, L_SHA256_transform_neon_len_k
	# Load digest into registers
	ldrd	r2, r3, [r0]
	ldrd	r4, r5, [r0, #8]
	ldrd	r6, r7, [r0, #16]
	ldrd	r8, r9, [r0, #24]
	# Start of loop processing a block
L_SHA256_transform_neon_len_begin:
	# Load W
	vldm.32	r1!, {d0-d7}
#ifndef WOLFSSL_ARM_ARCH_NO_VREV
	vrev32.8	q0, q0
	vrev32.8	q1, q1
	vrev32.8	q2, q2
	vrev32.8	q3, q3
#else
	vshl.i16	q4, q0, #8
	vshl.i16	q5, q1, #8
	vsri.i16	q4, q0, #8
	vsri.i16	q5, q1, #8
	vshl.i32	q0, q4, #16
	vshl.i32	q1, q5, #16
	vsri.i32	q0, q4, #16
	vsri.i32	q1, q5, #16
	vshl.i16	q4, q2, #8
	vshl.i16	q5, q3, #8
	vsri.i16	q4, q2, #8
	vsri.i16	q5, q3, #8
	vshl.i32	q2, q4, #16
	vshl.i32	q3, q5, #16
	vsri.i32	q2, q4, #16
	vsri.i32	q3, q5, #16
#endif /* WOLFSSL_ARM_ARCH_NO_VREV */
	str	r1, [sp, #4]
	mov	lr, #3
	# Start of 16 rounds
L_SHA256_transform_neon_len_start:
	# Round 0
	vmov	r10, d0[0]
	ror	r0, r6, #6
	eor	r1, r7, r8
	eor	r0, r0, r6, ror #11
	and	r1, r1, r6
	eor	r0, r0, r6, ror #25
	eor	r1, r1, r8
	add	r9, r9, r0
	add	r9, r9, r1
	ldr	r0, [r12]
	add	r9, r9, r10
	add	r9, r9, r0
	add	r5, r5, r9
	ror	r0, r2, #2
	eor	r1, r2, r3
	eor	r0, r0, r2, ror #13
	eor	r10, r3, r4
	and	r1, r1, r10
	eor	r0, r0, r2, ror #22
	eor	r1, r1, r3
	add	r9, r9, r0
	add	r9, r9, r1
	# Round 1
	vmov	r10, d0[1]
	# Calc new W[0]-W[1]
	vext.8	d10, d0, d1, #4
	ror	r0, r5, #6
	vshl.u32	d8, d7, #15
	eor	r1, r6, r7
	vsri.u32	d8, d7, #17
	eor	r0, r0, r5, ror #11
	vshl.u32	d9, d7, #13
	and	r1, r1, r5
	vsri.u32	d9, d7, #19
	eor	r0, r0, r5, ror #25
	veor	d9, d8
	eor	r1, r1, r7
	vshr.u32	d8, d7, #10
	add	r8, r8, r0
	veor	d9, d8
	add	r8, r8, r1
	vadd.i32	d0, d9
	ldr	r0, [r12, #4]
	vext.8	d11, d4, d5, #4
	add	r8, r8, r10
	vadd.i32	d0, d11
	add	r8, r8, r0
	vshl.u32	d8, d10, #25
	add	r4, r4, r8
	vsri.u32	d8, d10, #7
	ror	r0, r9, #2
	vshl.u32	d9, d10, #14
	eor	r1, r9, r2
	vsri.u32	d9, d10, #18
	eor	r0, r0, r9, ror #13
	veor	d9, d8
	eor	r10, r2, r3
	vshr.u32	d10, #3
	and	r1, r1, r10
	veor	d9, d10
	eor	r0, r0, r9, ror #22
	vadd.i32	d0, d9
	eor	r1, r1, r2
	add	r8, r8, r0
	add	r8, r8, r1
	# Round 2
	vmov	r10, d1[0]
	ror	r0, r4, #6
	eor	r1, r5, r6
	eor	r0, r0, r4, ror #11
	and	r1, r1, r4
	eor	r0, r0, r4, ror #25
	eor	r1, r1, r6
	add	r7, r7, r0
	add	r7, r7, r1
	ldr	r0, [r12, #8]
	add	r7, r7, r10
	add	r7, r7, r0
	add	r3, r3, r7
	ror	r0, r8, #2
	eor	r1, r8, r9
	eor	r0, r0, r8, ror #13
	eor	r10, r9, r2
	and	r1, r1, r10
	eor	r0, r0, r8, ror #22
	eor	r1, r1, r9
	add	r7, r7, r0
	add	r7, r7, r1
	# Round 3
	vmov	r10, d1[1]
	# Calc new W[2]-W[3]
	vext.8	d10, d1, d2, #4
	ror	r0, r3, #6
	vshl.u32	d8, d0, #15
	eor	r1, r4, r5
	vsri.u32	d8, d0, #17
	eor	r0, r0, r3, ror #11
	vshl.u32	d9, d0, #13
	and	r1, r1, r3
	vsri.u32	d9, d0, #19
	eor	r0, r0, r3, ror #25
	veor	d9, d8
	eor	r1, r1, r5
	vshr.u32	d8, d0, #10
	add	r6, r6, r0
	veor	d9, d8
	add	r6, r6, r1
	vadd.i32	d1, d9
	ldr	r0, [r12, #12]
	vext.8	d11, d5, d6, #4
	add	r6, r6, r10
	vadd.i32	d1, d11
	add	r6, r6, r0
	vshl.u32	d8, d10, #25
	add	r2, r2, r6
	vsri.u32	d8, d10, #7
	ror	r0, r7, #2
	vshl.u32	d9, d10, #14
	eor	r1, r7, r8
	vsri.u32	d9, d10, #18
	eor	r0, r0, r7, ror #13
	veor	d9, d8
	eor	r10, r8, r9
	vshr.u32	d10, #3
	and	r1, r1, r10
	veor	d9, d10
	eor	r0, r0, r7, ror #22
	vadd.i32	d1, d9
	eor	r1, r1, r8
	add	r6, r6, r0
	add	r6, r6, r1
	# Round 4
	vmov	r10, d2[0]
	ror	r0, r2, #6
	eor	r1, r3, r4
	eor	r0, r0, r2, ror #11
	and	r1, r1, r2
	eor	r0, r0, r2, ror #25
	eor	r1, r1, r4
	add	r5, r5, r0
	add	r5, r5, r1
	ldr	r0, [r12, #16]
	add	r5, r5, r10
	add	r5, r5, r0
	add	r9, r9, r5
	ror	r0, r6, #2
	eor	r1, r6, r7
	eor	r0, r0, r6, ror #13
	eor	r10, r7, r8
	and	r1, r1, r10
	eor	r0, r0, r6, ror #22
	eor	r1, r1, r7
	add	r5, r5, r0
	add	r5, r5, r1
	# Round 5
	vmov	r10, d2[1]
	# Calc new W[4]-W[5]
	vext.8	d10, d2, d3, #4
	ror	r0, r9, #6
	vshl.u32	d8, d1, #15
	eor	r1, r2, r3
	vsri.u32	d8, d1, #17
	eor	r0, r0, r9, ror #11
	vshl.u32	d9, d1, #13
	and	r1, r1, r9
	vsri.u32	d9, d1, #19
	eor	r0, r0, r9, ror #25
	veor	d9, d8
	eor	r1, r1, r3
	vshr.u32	d8, d1, #10
	add	r4, r4, r0
	veor	d9, d8
	add	r4, r4, r1
	vadd.i32	d2, d9
	ldr	r0, [r12, #20]
	vext.8	d11, d6, d7, #4
	add	r4, r4, r10
	vadd.i32	d2, d11
	add	r4, r4, r0
	vshl.u32	d8, d10, #25
	add	r8, r8, r4
	vsri.u32	d8, d10, #7
	ror	r0, r5, #2
	vshl.u32	d9, d10, #14
	eor	r1, r5, r6
	vsri.u32	d9, d10, #18
	eor	r0, r0, r5, ror #13
	veor	d9, d8
	eor	r10, r6, r7
	vshr.u32	d10, #3
	and	r1, r1, r10
	veor	d9, d10
	eor	r0, r0, r5, ror #22
	vadd.i32	d2, d9
	eor	r1, r1, r6
	add	r4, r4, r0
	add	r4, r4, r1
	# Round 6
	vmov	r10, d3[0]
	ror	r0, r8, #6
	eor	r1, r9, r2
	eor	r0, r0, r8, ror #11
	and	r1, r1, r8
	eor	r0, r0, r8, ror #25
	eor	r1, r1, r2
	add	r3, r3, r0
	add	r3, r3, r1
	ldr	r0, [r12, #24]
	add	r3, r3, r10
	add	r3, r3, r0
	add	r7, r7, r3
	ror	r0, r4, #2
	eor	r1, r4, r5
	eor	r0, r0, r4, ror #13
	eor	r10, r5, r6
	and	r1, r1, r10
	eor	r0, r0, r4, ror #22
	eor	r1, r1, r5
	add	r3, r3, r0
	add	r3, r3, r1
	# Round 7
	vmov	r10, d3[1]
	# Calc new W[6]-W[7]
	vext.8	d10, d3, d4, #4
	ror	r0, r7, #6
	vshl.u32	d8, d2, #15
	eor	r1, r8, r9
	vsri.u32	d8, d2, #17
	eor	r0, r0, r7, ror #11
	vshl.u32	d9, d2, #13
	and	r1, r1, r7
	vsri.u32	d9, d2, #19
	eor	r0, r0, r7, ror #25
	veor	d9, d8
	eor	r1, r1, r9
	vshr.u32	d8, d2, #10
	add	r2, r2, r0
	veor	d9, d8
	add	r2, r2, r1
	vadd.i32	d3, d9
	ldr	r0, [r12, #28]
	vext.8	d11, d7, d0, #4
	add	r2, r2, r10
	vadd.i32	d3, d11
	add	r2, r2, r0
	vshl.u32	d8, d10, #25
	add	r6, r6, r2
	vsri.u32	d8, d10, #7
	ror	r0, r3, #2
	vshl.u32	d9, d10, #14
	eor	r1, r3, r4
	vsri.u32	d9, d10, #18
	eor	r0, r0, r3, ror #13
	veor	d9, d8
	eor	r10, r4, r5
	vshr.u32	d10, #3
	and	r1, r1, r10
	veor	d9, d10
	eor	r0, r0, r3, ror #22
	vadd.i32	d3, d9
	eor	r1, r1, r4
	add	r2, r2, r0
	add	r2, r2, r1
	# Round 8
	vmov	r10, d4[0]
	ror	r0, r6, #6
	eor	r1, r7, r8
	eor	r0, r0, r6, ror #11
	and	r1, r1, r6
	eor	r0, r0, r6, ror #25
	eor	r1, r1, r8
	add	r9, r9, r0
	add	r9, r9, r1
	ldr	r0, [r12, #32]
	add	r9, r9, r10
	add	r9, r9, r0
	add	r5, r5, r9
	ror	r0, r2, #2
	eor	r1, r2, r3
	eor	r0, r0, r2, ror #13
	eor	r10, r3, r4
	and	r1, r1, r10
	eor	r0, r0, r2, ror #22
	eor	r1, r1, r3
	add	r9, r9, r0
	add	r9, r9, r1
	# Round 9
	vmov	r10, d4[1]
	# Calc new W[8]-W[9]
	vext.8	d10, d4, d5, #4
	ror	r0, r5, #6
	vshl.u32	d8, d3, #15
	eor	r1, r6, r7
	vsri.u32	d8, d3, #17
	eor	r0, r0, r5, ror #11
	vshl.u32	d9, d3, #13
	and	r1, r1, r5
	vsri.u32	d9, d3, #19
	eor	r0, r0, r5, ror #25
	veor	d9, d8
	eor	r1, r1, r7
	vshr.u32	d8, d3, #10
	add	r8, r8, r0
	veor	d9, d8
	add	r8, r8, r1
	vadd.i32	d4, d9
	ldr	r0, [r12, #36]
	vext.8	d11, d0, d1, #4
	add	r8, r8, r10
	vadd.i32	d4, d11
	add	r8, r8, r0
	vshl.u32	d8, d10, #25
	add	r4, r4, r8
	vsri.u32	d8, d10, #7
	ror	r0, r9, #2
	vshl.u32	d9, d10, #14
	eor	r1, r9, r2
	vsri.u32	d9, d10, #18
	eor	r0, r0, r9, ror #13
	veor	d9, d8
	eor	r10, r2, r3
	vshr.u32	d10, #3
	and	r1, r1, r10
	veor	d9, d10
	eor	r0, r0, r9, ror #22
	vadd.i32	d4, d9
	eor	r1, r1, r2
	add	r8, r8, r0
	add	r8, r8, r1
	# Round 10
	vmov	r10, d5[0]
	ror	r0, r4, #6
	eor	r1, r5, r6
	eor	r0, r0, r4, ror #11
	and	r1, r1, r4
	eor	r0, r0, r4, ror #25
	eor	r1, r1, r6
	add	r7, r7, r0
	add	r7, r7, r1
	ldr	r0, [r12, #40]
	add	r7, r7, r10
	add	r7, r7, r0
	add	r3, r3, r7
	ror	r0, r8, #2
	eor	r1, r8, r9
	eor	r0, r0, r8, ror #13
	eor	r10, r9, r2
	and	r1, r1, r10
	eor	r0, r0, r8, ror #22
	eor	r1, r1, r9
	add	r7, r7, r0
	add	r7, r7, r1
	# Round 11
	vmov	r10, d5[1]
	# Calc new W[10]-W[11]
	vext.8	d10, d5, d6, #4
	ror	r0, r3, #6
	vshl.u32	d8, d4, #15
	eor	r1, r4, r5
	vsri.u32	d8, d4, #17
	eor	r0, r0, r3, ror #11
	vshl.u32	d9, d4, #13
	and	r1, r1, r3
	vsri.u32	d9, d4, #19
	eor	r0, r0, r3, ror #25
	veor	d9, d8
	eor	r1, r1, r5
	vshr.u32	d8, d4, #10
	add	r6, r6, r0
	veor	d9, d8
	add	r6, r6, r1
	vadd.i32	d5, d9
	ldr	r0, [r12, #44]
	vext.8	d11, d1, d2, #4
	add	r6, r6, r10
	vadd.i32	d5, d11
	add	r6, r6, r0
	vshl.u32	d8, d10, #25
	add	r2, r2, r6
	vsri.u32	d8, d10, #7
	ror	r0, r7, #2
	vshl.u32	d9, d10, #14
	eor	r1, r7, r8
	vsri.u32	d9, d10, #18
	eor	r0, r0, r7, ror #13
	veor	d9, d8
	eor	r10, r8, r9
	vshr.u32	d10, #3
	and	r1, r1, r10
	veor	d9, d10
	eor	r0, r0, r7, ror #22
	vadd.i32	d5, d9
	eor	r1, r1, r8
	add	r6, r6, r0
	add	r6, r6, r1
	# Round 12
	vmov	r10, d6[0]
	ror	r0, r2, #6
	eor	r1, r3, r4
	eor	r0, r0, r2, ror #11
	and	r1, r1, r2
	eor	r0, r0, r2, ror #25
	eor	r1, r1, r4
	add	r5, r5, r0
	add	r5, r5, r1
	ldr	r0, [r12, #48]
	add	r5, r5, r10
	add	r5, r5, r0
	add	r9, r9, r5
	ror	r0, r6, #2
	eor	r1, r6, r7
	eor	r0, r0, r6, ror #13
	eor	r10, r7, r8
	and	r1, r1, r10
	eor	r0, r0, r6, ror #22
	eor	r1, r1, r7
	add	r5, r5, r0
	add	r5, r5, r1
	# Round 13
	vmov	r10, d6[1]
	# Calc new W[12]-W[13]
	vext.8	d10, d6, d7, #4
	ror	r0, r9, #6
	vshl.u32	d8, d5, #15
	eor	r1, r2, r3
	vsri.u32	d8, d5, #17
	eor	r0, r0, r9, ror #11
	vshl.u32	d9, d5, #13
	and	r1, r1, r9
	vsri.u32	d9, d5, #19
	eor	r0, r0, r9, ror #25
	veor	d9, d8
	eor	r1, r1, r3
	vshr.u32	d8, d5, #10
	add	r4, r4, r0
	veor	d9, d8
	add	r4, r4, r1
	vadd.i32	d6, d9
	ldr	r0, [r12, #52]
	vext.8	d11, d2, d3, #4
	add	r4, r4, r10
	vadd.i32	d6, d11
	add	r4, r4, r0
	vshl.u32	d8, d10, #25
	add	r8, r8, r4
	vsri.u32	d8, d10, #7
	ror	r0, r5, #2
	vshl.u32	d9, d10, #14
	eor	r1, r5, r6
	vsri.u32	d9, d10, #18
	eor	r0, r0, r5, ror #13
	veor	d9, d8
	eor	r10, r6, r7
	vshr.u32	d10, #3
	and	r1, r1, r10
	veor	d9, d10
	eor	r0, r0, r5, ror #22
	vadd.i32	d6, d9
	eor	r1, r1, r6
	add	r4, r4, r0
	add	r4, r4, r1
	# Round 14
	vmov	r10, d7[0]
	ror	r0, r8, #6
	eor	r1, r9, r2
	eor	r0, r0, r8, ror #11
	and	r1, r1, r8
	eor	r0, r0, r8, ror #25
	eor	r1, r1, r2
	add	r3, r3, r0
	add	r3, r3, r1
	ldr	r0, [r12, #56]
	add	r3, r3, r10
	add	r3, r3, r0
	add	r7, r7, r3
	ror	r0, r4, #2
	eor	r1, r4, r5
	eor	r0, r0, r4, ror #13
	eor	r10, r5, r6
	and	r1, r1, r10
	eor	r0, r0, r4, ror #22
	eor	r1, r1, r5
	add	r3, r3, r0
	add	r3, r3, r1
	# Round 15
	vmov	r10, d7[1]
	# Calc new W[14]-W[15]
	vext.8	d10, d7, d0, #4
	ror	r0, r7, #6
	vshl.u32	d8, d6, #15
	eor	r1, r8, r9
	vsri.u32	d8, d6, #17
	eor	r0, r0, r7, ror #11
	vshl.u32	d9, d6, #13
	and	r1, r1, r7
	vsri.u32	d9, d6, #19
	eor	r0, r0, r7, ror #25
	veor	d9, d8
	eor	r1, r1, r9
	vshr.u32	d8, d6, #10
	add	r2, r2, r0
	veor	d9, d8
	add	r2, r2, r1
	vadd.i32	d7, d9
	ldr	r0, [r12, #60]
	vext.8	d11, d3, d4, #4
	add	r2, r2, r10
	vadd.i32	d7, d11
	add	r2, r2, r0
	vshl.u32	d8, d10, #25
	add	r6, r6, r2
	vsri.u32	d8, d10, #7
	ror	r0, r3, #2
	vshl.u32	d9, d10, #14
	eor	r1, r3, r4
	vsri.u32	d9, d10, #18
	eor	r0, r0, r3, ror #13
	veor	d9, d8
	eor	r10, r4, r5
	vshr.u32	d10, #3
	and	r1, r1, r10
	veor	d9, d10
	eor	r0, r0, r3, ror #22
	vadd.i32	d7, d9
	eor	r1, r1, r4
	add	r2, r2, r0
	add	r2, r2, r1
	add	r12, r12, #0x40
	subs	lr, lr, #1
	bne	L_SHA256_transform_neon_len_start
	# Round 0
	vmov	r10, d0[0]
	ror	r0, r6, #6
	eor	r1, r7, r8
	eor	r0, r0, r6, ror #11
	and	r1, r1, r6
	eor	r0, r0, r6, ror #25
	eor	r1, r1, r8
	add	r9, r9, r0
	add	r9, r9, r1
	ldr	r0, [r12]
	add	r9, r9, r10
	add	r9, r9, r0
	add	r5, r5, r9
	ror	r0, r2, #2
	eor	r1, r2, r3
	eor	r0, r0, r2, ror #13
	eor	r10, r3, r4
	and	r1, r1, r10
	eor	r0, r0, r2, ror #22
	eor	r1, r1, r3
	add	r9, r9, r0
	add	r9, r9, r1
	# Round 1
	vmov	r10, d0[1]
	ror	r0, r5, #6
	eor	r1, r6, r7
	eor	r0, r0, r5, ror #11
	and	r1, r1, r5
	eor	r0, r0, r5, ror #25
	eor	r1, r1, r7
	add	r8, r8, r0
	add	r8, r8, r1
	ldr	r0, [r12, #4]
	add	r8, r8, r10
	add	r8, r8, r0
	add	r4, r4, r8
	ror	r0, r9, #2
	eor	r1, r9, r2
	eor	r0, r0, r9, ror #13
	eor	r10, r2, r3
	and	r1, r1, r10
	eor	r0, r0, r9, ror #22
	eor	r1, r1, r2
	add	r8, r8, r0
	add	r8, r8, r1
	# Round 2
	vmov	r10, d1[0]
	ror	r0, r4, #6
	eor	r1, r5, r6
	eor	r0, r0, r4, ror #11
	and	r1, r1, r4
	eor	r0, r0, r4, ror #25
	eor	r1, r1, r6
	add	r7, r7, r0
	add	r7, r7, r1
	ldr	r0, [r12, #8]
	add	r7, r7, r10
	add	r7, r7, r0
	add	r3, r3, r7
	ror	r0, r8, #2
	eor	r1, r8, r9
	eor	r0, r0, r8, ror #13
	eor	r10, r9, r2
	and	r1, r1, r10
	eor	r0, r0, r8, ror #22
	eor	r1, r1, r9
	add	r7, r7, r0
	add	r7, r7, r1
	# Round 3
	vmov	r10, d1[1]
	ror	r0, r3, #6
	eor	r1, r4, r5
	eor	r0, r0, r3, ror #11
	and	r1, r1, r3
	eor	r0, r0, r3, ror #25
	eor	r1, r1, r5
	add	r6, r6, r0
	add	r6, r6, r1
	ldr	r0, [r12, #12]
	add	r6, r6, r10
	add	r6, r6, r0
	add	r2, r2, r6
	ror	r0, r7, #2
	eor	r1, r7, r8
	eor	r0, r0, r7, ror #13
	eor	r10, r8, r9
	and	r1, r1, r10
	eor	r0, r0, r7, ror #22
	eor	r1, r1, r8
	add	r6, r6, r0
	add	r6, r6, r1
	# Round 4
	vmov	r10, d2[0]
	ror	r0, r2, #6
	eor	r1, r3, r4
	eor	r0, r0, r2, ror #11
	and	r1, r1, r2
	eor	r0, r0, r2, ror #25
	eor	r1, r1, r4
	add	r5, r5, r0
	add	r5, r5, r1
	ldr	r0, [r12, #16]
	add	r5, r5, r10
	add	r5, r5, r0
	add	r9, r9, r5
	ror	r0, r6, #2
	eor	r1, r6, r7
	eor	r0, r0, r6, ror #13
	eor	r10, r7, r8
	and	r1, r1, r10
	eor	r0, r0, r6, ror #22
	eor	r1, r1, r7
	add	r5, r5, r0
	add	r5, r5, r1
	# Round 5
	vmov	r10, d2[1]
	ror	r0, r9, #6
	eor	r1, r2, r3
	eor	r0, r0, r9, ror #11
	and	r1, r1, r9
	eor	r0, r0, r9, ror #25
	eor	r1, r1, r3
	add	r4, r4, r0
	add	r4, r4, r1
	ldr	r0, [r12, #20]
	add	r4, r4, r10
	add	r4, r4, r0
	add	r8, r8, r4
	ror	r0, r5, #2
	eor	r1, r5, r6
	eor	r0, r0, r5, ror #13
	eor	r10, r6, r7
	and	r1, r1, r10
	eor	r0, r0, r5, ror #22
	eor	r1, r1, r6
	add	r4, r4, r0
	add	r4, r4, r1
	# Round 6
	vmov	r10, d3[0]
	ror	r0, r8, #6
	eor	r1, r9, r2
	eor	r0, r0, r8, ror #11
	and	r1, r1, r8
	eor	r0, r0, r8, ror #25
	eor	r1, r1, r2
	add	r3, r3, r0
	add	r3, r3, r1
	ldr	r0, [r12, #24]
	add	r3, r3, r10
	add	r3, r3, r0
	add	r7, r7, r3
	ror	r0, r4, #2
	eor	r1, r4, r5
	eor	r0, r0, r4, ror #13
	eor	r10, r5, r6
	and	r1, r1, r10
	eor	r0, r0, r4, ror #22
	eor	r1, r1, r5
	add	r3, r3, r0
	add	r3, r3, r1
	# Round 7
	vmov	r10, d3[1]
	ror	r0, r7, #6
	eor	r1, r8, r9
	eor	r0, r0, r7, ror #11
	and	r1, r1, r7
	eor	r0, r0, r7, ror #25
	eor	r1, r1, r9
	add	r2, r2, r0
	add	r2, r2, r1
	ldr	r0, [r12, #28]
	add	r2, r2, r10
	add	r2, r2, r0
	add	r6, r6, r2
	ror	r0, r3, #2
	eor	r1, r3, r4
	eor	r0, r0, r3, ror #13
	eor	r10, r4, r5
	and	r1, r1, r10
	eor	r0, r0, r3, ror #22
	eor	r1, r1, r4
	add	r2, r2, r0
	add	r2, r2, r1
	# Round 8
	vmov	r10, d4[0]
	ror	r0, r6, #6
	eor	r1, r7, r8
	eor	r0, r0, r6, ror #11
	and	r1, r1, r6
	eor	r0, r0, r6, ror #25
	eor	r1, r1, r8
	add	r9, r9, r0
	add	r9, r9, r1
	ldr	r0, [r12, #32]
	add	r9, r9, r10
	add	r9, r9, r0
	add	r5, r5, r9
	ror	r0, r2, #2
	eor	r1, r2, r3
	eor	r0, r0, r2, ror #13
	eor	r10, r3, r4
	and	r1, r1, r10
	eor	r0, r0, r2, ror #22
	eor	r1, r1, r3
	add	r9, r9, r0
	add	r9, r9, r1
	# Round 9
	vmov	r10, d4[1]
	ror	r0, r5, #6
	eor	r1, r6, r7
	eor	r0, r0, r5, ror #11
	and	r1, r1, r5
	eor	r0, r0, r5, ror #25
	eor	r1, r1, r7
	add	r8, r8, r0
	add	r8, r8, r1
	ldr	r0, [r12, #36]
	add	r8, r8, r10
	add	r8, r8, r0
	add	r4, r4, r8
	ror	r0, r9, #2
	eor	r1, r9, r2
	eor	r0, r0, r9, ror #13
	eor	r10, r2, r3
	and	r1, r1, r10
	eor	r0, r0, r9, ror #22
	eor	r1, r1, r2
	add	r8, r8, r0
	add	r8, r8, r1
	# Round 10
	vmov	r10, d5[0]
	ror	r0, r4, #6
	eor	r1, r5, r6
	eor	r0, r0, r4, ror #11
	and	r1, r1, r4
	eor	r0, r0, r4, ror #25
	eor	r1, r1, r6
	add	r7, r7, r0
	add	r7, r7, r1
	ldr	r0, [r12, #40]
	add	r7, r7, r10
	add	r7, r7, r0
	add	r3, r3, r7
	ror	r0, r8, #2
	eor	r1, r8, r9
	eor	r0, r0, r8, ror #13
	eor	r10, r9, r2
	and	r1, r1, r10
	eor	r0, r0, r8, ror #22
	eor	r1, r1, r9
	add	r7, r7, r0
	add	r7, r7, r1
	# Round 11
	vmov	r10, d5[1]
	ror	r0, r3, #6
	eor	r1, r4, r5
	eor	r0, r0, r3, ror #11
	and	r1, r1, r3
	eor	r0, r0, r3, ror #25
	eor	r1, r1, r5
	add	r6, r6, r0
	add	r6, r6, r1
	ldr	r0, [r12, #44]
	add	r6, r6, r10
	add	r6, r6, r0
	add	r2, r2, r6
	ror	r0, r7, #2
	eor	r1, r7, r8
	eor	r0, r0, r7, ror #13
	eor	r10, r8, r9
	and	r1, r1, r10
	eor	r0, r0, r7, ror #22
	eor	r1, r1, r8
	add	r6, r6, r0
	add	r6, r6, r1
	# Round 12
	vmov	r10, d6[0]
	ror	r0, r2, #6
	eor	r1, r3, r4
	eor	r0, r0, r2, ror #11
	and	r1, r1, r2
	eor	r0, r0, r2, ror #25
	eor	r1, r1, r4
	add	r5, r5, r0
	add	r5, r5, r1
	ldr	r0, [r12, #48]
	add	r5, r5, r10
	add	r5, r5, r0
	add	r9, r9, r5
	ror	r0, r6, #2
	eor	r1, r6, r7
	eor	r0, r0, r6, ror #13
	eor	r10, r7, r8
	and	r1, r1, r10
	eor	r0, r0, r6, ror #22
	eor	r1, r1, r7
	add	r5, r5, r0
	add	r5, r5, r1
	# Round 13
	vmov	r10, d6[1]
	ror	r0, r9, #6
	eor	r1, r2, r3
	eor	r0, r0, r9, ror #11
	and	r1, r1, r9
	eor	r0, r0, r9, ror #25
	eor	r1, r1, r3
	add	r4, r4, r0
	add	r4, r4, r1
	ldr	r0, [r12, #52]
	add	r4, r4, r10
	add	r4, r4, r0
	add	r8, r8, r4
	ror	r0, r5, #2
	eor	r1, r5, r6
	eor	r0, r0, r5, ror #13
	eor	r10, r6, r7
	and	r1, r1, r10
	eor	r0, r0, r5, ror #22
	eor	r1, r1, r6
	add	r4, r4, r0
	add	r4, r4, r1
	# Round 14
	vmov	r10, d7[0]
	ror	r0, r8, #6
	eor	r1, r9, r2
	eor	r0, r0, r8, ror #11
	and	r1, r1, r8
	eor	r0, r0, r8, ror #25
	eor	r1, r1, r2
	add	r3, r3, r0
	add	r3, r3, r1
	ldr	r0, [r12, #56]
	add	r3, r3, r10
	add	r3, r3, r0
	add	r7, r7, r3
	ror	r0, r4, #2
	eor	r1, r4, r5
	eor	r0, r0, r4, ror #13
	eor	r10, r5, r6
	and	r1, r1, r10
	eor	r0, r0, r4, ror #22
	eor	r1, r1, r5
	add	r3, r3, r0
	add	r3, r3, r1
	# Round 15
	vmov	r10, d7[1]
	ror	r0, r7, #6
	eor	r1, r8, r9
	eor	r0, r0, r7, ror #11
	and	r1, r1, r7
	eor	r0, r0, r7, ror #25
	eor	r1, r1, r9
	add	r2, r2, r0
	add	r2, r2, r1
	ldr	r0, [r12, #60]
	add	r2, r2, r10
	add	r2, r2, r0
	add	r6, r6, r2
	ror	r0, r3, #2
	eor	r1, r3, r4
	eor	r0, r0, r3, ror #13
	eor	r10, r4, r5
	and	r1, r1, r10
	eor	r0, r0, r3, ror #22
	eor	r1, r1, r4
	add	r2, r2, r0
	add	r2, r2, r1
	ldr	r10, [sp]
	# Add in digest from start
	ldrd	r0, r1, [r10]
	add	r2, r2, r0
	add	r3, r3, r1
	strd	r2, r3, [r10]
	ldrd	r0, r1, [r10, #8]
	add	r4, r4, r0
	add	r5, r5, r1
	strd	r4, r5, [r10, #8]
	ldrd	r0, r1, [r10, #16]
	add	r6, r6, r0
	add	r7, r7, r1
	strd	r6, r7, [r10, #16]
	ldrd	r0, r1, [r10, #24]
	add	r8, r8, r0
	add	r9, r9, r1
	strd	r8, r9, [r10, #24]
	ldr	r10, [sp, #8]
	ldr	r1, [sp, #4]
	subs	r10, r10, #0x40
	sub	r12, r12, #0xc0
	str	r10, [sp, #8]
	bne	L_SHA256_transform_neon_len_begin
	add	sp, sp, #24
	vpop	{d8-d11}
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	Transform_Sha256_Len,.-Transform_Sha256_Len
#endif /* WOLFSSL_ARMASM_NO_NEON */
#endif /* !NO_SHA256 */
#endif /* !__aarch64__ */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
