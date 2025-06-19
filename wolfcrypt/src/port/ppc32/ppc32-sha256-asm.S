/* ppc32-sha256-asm
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
 *   ruby ./sha2/sha256.rb ppc32 \
 *       ../wolfssl/wolfcrypt/src/port/ppc32/ppc32-sha256-asm.S
 */


#ifdef WOLFSSL_PPC32_ASM
#ifndef WOLFSSL_PPC32_ASM_INLINE
	.machine ppc
#ifndef NO_SHA256
	.section	".text"
	.section	.rodata
	.type	L_SHA256_transform_len_k, @object
	.size	L_SHA256_transform_len_k, 256
	.align	4
L_SHA256_transform_len_k:
	.long	0x428a2f98
	.long	0x71374491
	.long	0xb5c0fbcf
	.long	0xe9b5dba5
	.long	0x3956c25b
	.long	0x59f111f1
	.long	0x923f82a4
	.long	0xab1c5ed5
	.long	0xd807aa98
	.long	0x12835b01
	.long	0x243185be
	.long	0x550c7dc3
	.long	0x72be5d74
	.long	0x80deb1fe
	.long	0x9bdc06a7
	.long	0xc19bf174
	.long	0xe49b69c1
	.long	0xefbe4786
	.long	0xfc19dc6
	.long	0x240ca1cc
	.long	0x2de92c6f
	.long	0x4a7484aa
	.long	0x5cb0a9dc
	.long	0x76f988da
	.long	0x983e5152
	.long	0xa831c66d
	.long	0xb00327c8
	.long	0xbf597fc7
	.long	0xc6e00bf3
	.long	0xd5a79147
	.long	0x6ca6351
	.long	0x14292967
	.long	0x27b70a85
	.long	0x2e1b2138
	.long	0x4d2c6dfc
	.long	0x53380d13
	.long	0x650a7354
	.long	0x766a0abb
	.long	0x81c2c92e
	.long	0x92722c85
	.long	0xa2bfe8a1
	.long	0xa81a664b
	.long	0xc24b8b70
	.long	0xc76c51a3
	.long	0xd192e819
	.long	0xd6990624
	.long	0xf40e3585
	.long	0x106aa070
	.long	0x19a4c116
	.long	0x1e376c08
	.long	0x2748774c
	.long	0x34b0bcb5
	.long	0x391c0cb3
	.long	0x4ed8aa4a
	.long	0x5b9cca4f
	.long	0x682e6ff3
	.long	0x748f82ee
	.long	0x78a5636f
	.long	0x84c87814
	.long	0x8cc70208
	.long	0x90befffa
	.long	0xa4506ceb
	.long	0xbef9a3f7
	.long	0xc67178f2
	.section	".text"
	.align	4
	.globl	Transform_Sha256_Len
	.type	Transform_Sha256_Len, @function
Transform_Sha256_Len:
	stwu	1, -76(1)
	mflr	0
	stw	0, 72(1)
	stw	14, 0(1)
	stw	15, 4(1)
	stw	16, 8(1)
	stw	17, 12(1)
	stw	18, 16(1)
	stw	19, 20(1)
	stw	20, 24(1)
	stw	21, 28(1)
	stw	22, 32(1)
	stw	23, 36(1)
	stw	24, 40(1)
	stw	25, 44(1)
	stw	26, 48(1)
	stw	27, 52(1)
	stw	28, 56(1)
	stw	29, 60(1)
	stw	30, 64(1)
	stw	31, 68(1)
	subi	1, 1, 32
	srwi	5, 5, 6
	lis	6, L_SHA256_transform_len_k@ha
	la	6, L_SHA256_transform_len_k@l(6)
	# Copy digest to add in at end
	lwz	8, 0(3)
	lwz	9, 4(3)
	lwz	10, 8(3)
	lwz	11, 12(3)
	lwz	12, 16(3)
	lwz	13, 20(3)
	lwz	14, 24(3)
	lwz	15, 28(3)
	stw	8, 0(1)
	stw	9, 4(1)
	stw	10, 8(1)
	stw	11, 12(1)
	stw	12, 16(1)
	stw	13, 20(1)
	stw	14, 24(1)
	stw	15, 28(1)
	# Start of loop processing a block
L_SHA256_transform_len_begin:
	# Load W - 64 bytes
	lwz	16, 0(4)
	lwz	17, 4(4)
	lwz	18, 8(4)
	lwz	19, 12(4)
	lwz	20, 16(4)
	lwz	21, 20(4)
	lwz	22, 24(4)
	lwz	23, 28(4)
	lwz	24, 32(4)
	lwz	25, 36(4)
	lwz	26, 40(4)
	lwz	27, 44(4)
	lwz	28, 48(4)
	lwz	29, 52(4)
	lwz	30, 56(4)
	lwz	31, 60(4)
#ifndef WOLFSSL_PPC32_ASM_SMALL
	li	7, 3
	mtctr	7
	# Start of 16 rounds
L_SHA256_transform_len_start:
	# Round 0
	rotlwi	0, 12, 26
	rotlwi	7, 12, 21
	xor	0, 0, 7
	rotlwi	7, 12, 7
	xor	0, 0, 7
	add	15, 15, 0
	xor	0, 13, 14
	and	0, 0, 12
	xor	0, 0, 14
	add	15, 15, 0
	lwz	0, 0(6)
	add	15, 15, 16
	add	15, 15, 0
	add	11, 11, 15
	rotlwi	0, 8, 30
	rotlwi	7, 8, 19
	xor	0, 0, 7
	rotlwi	7, 8, 10
	xor	0, 0, 7
	add	15, 15, 0
	xor	7, 8, 9
	xor	0, 9, 10
	and	0, 0, 7
	xor	0, 0, 9
	add	15, 15, 0
	# Calc new W[0]
	rotlwi	0, 17, 25
	rotlwi	7, 17, 14
	xor	0, 0, 7
	srwi	7, 17, 3
	xor	0, 0, 7
	add	16, 16, 0
	rotlwi	0, 30, 15
	rotlwi	7, 30, 13
	xor	0, 0, 7
	srwi	7, 30, 10
	xor	0, 0, 7
	add	16, 16, 0
	add	16, 16, 25
	# Round 1
	rotlwi	0, 11, 26
	rotlwi	7, 11, 21
	xor	0, 0, 7
	rotlwi	7, 11, 7
	xor	0, 0, 7
	add	14, 14, 0
	xor	0, 12, 13
	and	0, 0, 11
	xor	0, 0, 13
	add	14, 14, 0
	lwz	0, 4(6)
	add	14, 14, 17
	add	14, 14, 0
	add	10, 10, 14
	rotlwi	0, 15, 30
	rotlwi	7, 15, 19
	xor	0, 0, 7
	rotlwi	7, 15, 10
	xor	0, 0, 7
	add	14, 14, 0
	xor	7, 15, 8
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 8
	add	14, 14, 0
	# Calc new W[1]
	rotlwi	0, 18, 25
	rotlwi	7, 18, 14
	xor	0, 0, 7
	srwi	7, 18, 3
	xor	0, 0, 7
	add	17, 17, 0
	rotlwi	0, 31, 15
	rotlwi	7, 31, 13
	xor	0, 0, 7
	srwi	7, 31, 10
	xor	0, 0, 7
	add	17, 17, 0
	add	17, 17, 26
	# Round 2
	rotlwi	0, 10, 26
	rotlwi	7, 10, 21
	xor	0, 0, 7
	rotlwi	7, 10, 7
	xor	0, 0, 7
	add	13, 13, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	13, 13, 0
	lwz	0, 8(6)
	add	13, 13, 18
	add	13, 13, 0
	add	9, 9, 13
	rotlwi	0, 14, 30
	rotlwi	7, 14, 19
	xor	0, 0, 7
	rotlwi	7, 14, 10
	xor	0, 0, 7
	add	13, 13, 0
	xor	7, 14, 15
	xor	0, 15, 8
	and	0, 0, 7
	xor	0, 0, 15
	add	13, 13, 0
	# Calc new W[2]
	rotlwi	0, 19, 25
	rotlwi	7, 19, 14
	xor	0, 0, 7
	srwi	7, 19, 3
	xor	0, 0, 7
	add	18, 18, 0
	rotlwi	0, 16, 15
	rotlwi	7, 16, 13
	xor	0, 0, 7
	srwi	7, 16, 10
	xor	0, 0, 7
	add	18, 18, 0
	add	18, 18, 27
	# Round 3
	rotlwi	0, 9, 26
	rotlwi	7, 9, 21
	xor	0, 0, 7
	rotlwi	7, 9, 7
	xor	0, 0, 7
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	lwz	0, 12(6)
	add	12, 12, 19
	add	12, 12, 0
	add	8, 8, 12
	rotlwi	0, 13, 30
	rotlwi	7, 13, 19
	xor	0, 0, 7
	rotlwi	7, 13, 10
	xor	0, 0, 7
	add	12, 12, 0
	xor	7, 13, 14
	xor	0, 14, 15
	and	0, 0, 7
	xor	0, 0, 14
	add	12, 12, 0
	# Calc new W[3]
	rotlwi	0, 20, 25
	rotlwi	7, 20, 14
	xor	0, 0, 7
	srwi	7, 20, 3
	xor	0, 0, 7
	add	19, 19, 0
	rotlwi	0, 17, 15
	rotlwi	7, 17, 13
	xor	0, 0, 7
	srwi	7, 17, 10
	xor	0, 0, 7
	add	19, 19, 0
	add	19, 19, 28
	# Round 4
	rotlwi	0, 8, 26
	rotlwi	7, 8, 21
	xor	0, 0, 7
	rotlwi	7, 8, 7
	xor	0, 0, 7
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	lwz	0, 16(6)
	add	11, 11, 20
	add	11, 11, 0
	add	15, 15, 11
	rotlwi	0, 12, 30
	rotlwi	7, 12, 19
	xor	0, 0, 7
	rotlwi	7, 12, 10
	xor	0, 0, 7
	add	11, 11, 0
	xor	7, 12, 13
	xor	0, 13, 14
	and	0, 0, 7
	xor	0, 0, 13
	add	11, 11, 0
	# Calc new W[4]
	rotlwi	0, 21, 25
	rotlwi	7, 21, 14
	xor	0, 0, 7
	srwi	7, 21, 3
	xor	0, 0, 7
	add	20, 20, 0
	rotlwi	0, 18, 15
	rotlwi	7, 18, 13
	xor	0, 0, 7
	srwi	7, 18, 10
	xor	0, 0, 7
	add	20, 20, 0
	add	20, 20, 29
	# Round 5
	rotlwi	0, 15, 26
	rotlwi	7, 15, 21
	xor	0, 0, 7
	rotlwi	7, 15, 7
	xor	0, 0, 7
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 15
	xor	0, 0, 9
	add	10, 10, 0
	lwz	0, 20(6)
	add	10, 10, 21
	add	10, 10, 0
	add	14, 14, 10
	rotlwi	0, 11, 30
	rotlwi	7, 11, 19
	xor	0, 0, 7
	rotlwi	7, 11, 10
	xor	0, 0, 7
	add	10, 10, 0
	xor	7, 11, 12
	xor	0, 12, 13
	and	0, 0, 7
	xor	0, 0, 12
	add	10, 10, 0
	# Calc new W[5]
	rotlwi	0, 22, 25
	rotlwi	7, 22, 14
	xor	0, 0, 7
	srwi	7, 22, 3
	xor	0, 0, 7
	add	21, 21, 0
	rotlwi	0, 19, 15
	rotlwi	7, 19, 13
	xor	0, 0, 7
	srwi	7, 19, 10
	xor	0, 0, 7
	add	21, 21, 0
	add	21, 21, 30
	# Round 6
	rotlwi	0, 14, 26
	rotlwi	7, 14, 21
	xor	0, 0, 7
	rotlwi	7, 14, 7
	xor	0, 0, 7
	add	9, 9, 0
	xor	0, 15, 8
	and	0, 0, 14
	xor	0, 0, 8
	add	9, 9, 0
	lwz	0, 24(6)
	add	9, 9, 22
	add	9, 9, 0
	add	13, 13, 9
	rotlwi	0, 10, 30
	rotlwi	7, 10, 19
	xor	0, 0, 7
	rotlwi	7, 10, 10
	xor	0, 0, 7
	add	9, 9, 0
	xor	7, 10, 11
	xor	0, 11, 12
	and	0, 0, 7
	xor	0, 0, 11
	add	9, 9, 0
	# Calc new W[6]
	rotlwi	0, 23, 25
	rotlwi	7, 23, 14
	xor	0, 0, 7
	srwi	7, 23, 3
	xor	0, 0, 7
	add	22, 22, 0
	rotlwi	0, 20, 15
	rotlwi	7, 20, 13
	xor	0, 0, 7
	srwi	7, 20, 10
	xor	0, 0, 7
	add	22, 22, 0
	add	22, 22, 31
	# Round 7
	rotlwi	0, 13, 26
	rotlwi	7, 13, 21
	xor	0, 0, 7
	rotlwi	7, 13, 7
	xor	0, 0, 7
	add	8, 8, 0
	xor	0, 14, 15
	and	0, 0, 13
	xor	0, 0, 15
	add	8, 8, 0
	lwz	0, 28(6)
	add	8, 8, 23
	add	8, 8, 0
	add	12, 12, 8
	rotlwi	0, 9, 30
	rotlwi	7, 9, 19
	xor	0, 0, 7
	rotlwi	7, 9, 10
	xor	0, 0, 7
	add	8, 8, 0
	xor	7, 9, 10
	xor	0, 10, 11
	and	0, 0, 7
	xor	0, 0, 10
	add	8, 8, 0
	# Calc new W[7]
	rotlwi	0, 24, 25
	rotlwi	7, 24, 14
	xor	0, 0, 7
	srwi	7, 24, 3
	xor	0, 0, 7
	add	23, 23, 0
	rotlwi	0, 21, 15
	rotlwi	7, 21, 13
	xor	0, 0, 7
	srwi	7, 21, 10
	xor	0, 0, 7
	add	23, 23, 0
	add	23, 23, 16
	# Round 8
	rotlwi	0, 12, 26
	rotlwi	7, 12, 21
	xor	0, 0, 7
	rotlwi	7, 12, 7
	xor	0, 0, 7
	add	15, 15, 0
	xor	0, 13, 14
	and	0, 0, 12
	xor	0, 0, 14
	add	15, 15, 0
	lwz	0, 32(6)
	add	15, 15, 24
	add	15, 15, 0
	add	11, 11, 15
	rotlwi	0, 8, 30
	rotlwi	7, 8, 19
	xor	0, 0, 7
	rotlwi	7, 8, 10
	xor	0, 0, 7
	add	15, 15, 0
	xor	7, 8, 9
	xor	0, 9, 10
	and	0, 0, 7
	xor	0, 0, 9
	add	15, 15, 0
	# Calc new W[8]
	rotlwi	0, 25, 25
	rotlwi	7, 25, 14
	xor	0, 0, 7
	srwi	7, 25, 3
	xor	0, 0, 7
	add	24, 24, 0
	rotlwi	0, 22, 15
	rotlwi	7, 22, 13
	xor	0, 0, 7
	srwi	7, 22, 10
	xor	0, 0, 7
	add	24, 24, 0
	add	24, 24, 17
	# Round 9
	rotlwi	0, 11, 26
	rotlwi	7, 11, 21
	xor	0, 0, 7
	rotlwi	7, 11, 7
	xor	0, 0, 7
	add	14, 14, 0
	xor	0, 12, 13
	and	0, 0, 11
	xor	0, 0, 13
	add	14, 14, 0
	lwz	0, 36(6)
	add	14, 14, 25
	add	14, 14, 0
	add	10, 10, 14
	rotlwi	0, 15, 30
	rotlwi	7, 15, 19
	xor	0, 0, 7
	rotlwi	7, 15, 10
	xor	0, 0, 7
	add	14, 14, 0
	xor	7, 15, 8
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 8
	add	14, 14, 0
	# Calc new W[9]
	rotlwi	0, 26, 25
	rotlwi	7, 26, 14
	xor	0, 0, 7
	srwi	7, 26, 3
	xor	0, 0, 7
	add	25, 25, 0
	rotlwi	0, 23, 15
	rotlwi	7, 23, 13
	xor	0, 0, 7
	srwi	7, 23, 10
	xor	0, 0, 7
	add	25, 25, 0
	add	25, 25, 18
	# Round 10
	rotlwi	0, 10, 26
	rotlwi	7, 10, 21
	xor	0, 0, 7
	rotlwi	7, 10, 7
	xor	0, 0, 7
	add	13, 13, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	13, 13, 0
	lwz	0, 40(6)
	add	13, 13, 26
	add	13, 13, 0
	add	9, 9, 13
	rotlwi	0, 14, 30
	rotlwi	7, 14, 19
	xor	0, 0, 7
	rotlwi	7, 14, 10
	xor	0, 0, 7
	add	13, 13, 0
	xor	7, 14, 15
	xor	0, 15, 8
	and	0, 0, 7
	xor	0, 0, 15
	add	13, 13, 0
	# Calc new W[10]
	rotlwi	0, 27, 25
	rotlwi	7, 27, 14
	xor	0, 0, 7
	srwi	7, 27, 3
	xor	0, 0, 7
	add	26, 26, 0
	rotlwi	0, 24, 15
	rotlwi	7, 24, 13
	xor	0, 0, 7
	srwi	7, 24, 10
	xor	0, 0, 7
	add	26, 26, 0
	add	26, 26, 19
	# Round 11
	rotlwi	0, 9, 26
	rotlwi	7, 9, 21
	xor	0, 0, 7
	rotlwi	7, 9, 7
	xor	0, 0, 7
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	lwz	0, 44(6)
	add	12, 12, 27
	add	12, 12, 0
	add	8, 8, 12
	rotlwi	0, 13, 30
	rotlwi	7, 13, 19
	xor	0, 0, 7
	rotlwi	7, 13, 10
	xor	0, 0, 7
	add	12, 12, 0
	xor	7, 13, 14
	xor	0, 14, 15
	and	0, 0, 7
	xor	0, 0, 14
	add	12, 12, 0
	# Calc new W[11]
	rotlwi	0, 28, 25
	rotlwi	7, 28, 14
	xor	0, 0, 7
	srwi	7, 28, 3
	xor	0, 0, 7
	add	27, 27, 0
	rotlwi	0, 25, 15
	rotlwi	7, 25, 13
	xor	0, 0, 7
	srwi	7, 25, 10
	xor	0, 0, 7
	add	27, 27, 0
	add	27, 27, 20
	# Round 12
	rotlwi	0, 8, 26
	rotlwi	7, 8, 21
	xor	0, 0, 7
	rotlwi	7, 8, 7
	xor	0, 0, 7
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	lwz	0, 48(6)
	add	11, 11, 28
	add	11, 11, 0
	add	15, 15, 11
	rotlwi	0, 12, 30
	rotlwi	7, 12, 19
	xor	0, 0, 7
	rotlwi	7, 12, 10
	xor	0, 0, 7
	add	11, 11, 0
	xor	7, 12, 13
	xor	0, 13, 14
	and	0, 0, 7
	xor	0, 0, 13
	add	11, 11, 0
	# Calc new W[12]
	rotlwi	0, 29, 25
	rotlwi	7, 29, 14
	xor	0, 0, 7
	srwi	7, 29, 3
	xor	0, 0, 7
	add	28, 28, 0
	rotlwi	0, 26, 15
	rotlwi	7, 26, 13
	xor	0, 0, 7
	srwi	7, 26, 10
	xor	0, 0, 7
	add	28, 28, 0
	add	28, 28, 21
	# Round 13
	rotlwi	0, 15, 26
	rotlwi	7, 15, 21
	xor	0, 0, 7
	rotlwi	7, 15, 7
	xor	0, 0, 7
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 15
	xor	0, 0, 9
	add	10, 10, 0
	lwz	0, 52(6)
	add	10, 10, 29
	add	10, 10, 0
	add	14, 14, 10
	rotlwi	0, 11, 30
	rotlwi	7, 11, 19
	xor	0, 0, 7
	rotlwi	7, 11, 10
	xor	0, 0, 7
	add	10, 10, 0
	xor	7, 11, 12
	xor	0, 12, 13
	and	0, 0, 7
	xor	0, 0, 12
	add	10, 10, 0
	# Calc new W[13]
	rotlwi	0, 30, 25
	rotlwi	7, 30, 14
	xor	0, 0, 7
	srwi	7, 30, 3
	xor	0, 0, 7
	add	29, 29, 0
	rotlwi	0, 27, 15
	rotlwi	7, 27, 13
	xor	0, 0, 7
	srwi	7, 27, 10
	xor	0, 0, 7
	add	29, 29, 0
	add	29, 29, 22
	# Round 14
	rotlwi	0, 14, 26
	rotlwi	7, 14, 21
	xor	0, 0, 7
	rotlwi	7, 14, 7
	xor	0, 0, 7
	add	9, 9, 0
	xor	0, 15, 8
	and	0, 0, 14
	xor	0, 0, 8
	add	9, 9, 0
	lwz	0, 56(6)
	add	9, 9, 30
	add	9, 9, 0
	add	13, 13, 9
	rotlwi	0, 10, 30
	rotlwi	7, 10, 19
	xor	0, 0, 7
	rotlwi	7, 10, 10
	xor	0, 0, 7
	add	9, 9, 0
	xor	7, 10, 11
	xor	0, 11, 12
	and	0, 0, 7
	xor	0, 0, 11
	add	9, 9, 0
	# Calc new W[14]
	rotlwi	0, 31, 25
	rotlwi	7, 31, 14
	xor	0, 0, 7
	srwi	7, 31, 3
	xor	0, 0, 7
	add	30, 30, 0
	rotlwi	0, 28, 15
	rotlwi	7, 28, 13
	xor	0, 0, 7
	srwi	7, 28, 10
	xor	0, 0, 7
	add	30, 30, 0
	add	30, 30, 23
	# Round 15
	rotlwi	0, 13, 26
	rotlwi	7, 13, 21
	xor	0, 0, 7
	rotlwi	7, 13, 7
	xor	0, 0, 7
	add	8, 8, 0
	xor	0, 14, 15
	and	0, 0, 13
	xor	0, 0, 15
	add	8, 8, 0
	lwz	0, 60(6)
	add	8, 8, 31
	add	8, 8, 0
	add	12, 12, 8
	rotlwi	0, 9, 30
	rotlwi	7, 9, 19
	xor	0, 0, 7
	rotlwi	7, 9, 10
	xor	0, 0, 7
	add	8, 8, 0
	xor	7, 9, 10
	xor	0, 10, 11
	and	0, 0, 7
	xor	0, 0, 10
	add	8, 8, 0
	# Calc new W[15]
	rotlwi	0, 16, 25
	rotlwi	7, 16, 14
	xor	0, 0, 7
	srwi	7, 16, 3
	xor	0, 0, 7
	add	31, 31, 0
	rotlwi	0, 29, 15
	rotlwi	7, 29, 13
	xor	0, 0, 7
	srwi	7, 29, 10
	xor	0, 0, 7
	add	31, 31, 0
	add	31, 31, 24
	addi	6, 6, 0x40
	bdnz	L_SHA256_transform_len_start
	# Round 0
	rotlwi	0, 12, 26
	rotlwi	7, 12, 21
	xor	0, 0, 7
	rotlwi	7, 12, 7
	xor	0, 0, 7
	add	15, 15, 0
	xor	0, 13, 14
	and	0, 0, 12
	xor	0, 0, 14
	add	15, 15, 0
	lwz	0, 0(6)
	add	15, 15, 16
	add	15, 15, 0
	add	11, 11, 15
	rotlwi	0, 8, 30
	rotlwi	7, 8, 19
	xor	0, 0, 7
	rotlwi	7, 8, 10
	xor	0, 0, 7
	add	15, 15, 0
	xor	7, 8, 9
	xor	0, 9, 10
	and	0, 0, 7
	xor	0, 0, 9
	add	15, 15, 0
	# Round 1
	rotlwi	0, 11, 26
	rotlwi	7, 11, 21
	xor	0, 0, 7
	rotlwi	7, 11, 7
	xor	0, 0, 7
	add	14, 14, 0
	xor	0, 12, 13
	and	0, 0, 11
	xor	0, 0, 13
	add	14, 14, 0
	lwz	0, 4(6)
	add	14, 14, 17
	add	14, 14, 0
	add	10, 10, 14
	rotlwi	0, 15, 30
	rotlwi	7, 15, 19
	xor	0, 0, 7
	rotlwi	7, 15, 10
	xor	0, 0, 7
	add	14, 14, 0
	xor	7, 15, 8
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 8
	add	14, 14, 0
	# Round 2
	rotlwi	0, 10, 26
	rotlwi	7, 10, 21
	xor	0, 0, 7
	rotlwi	7, 10, 7
	xor	0, 0, 7
	add	13, 13, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	13, 13, 0
	lwz	0, 8(6)
	add	13, 13, 18
	add	13, 13, 0
	add	9, 9, 13
	rotlwi	0, 14, 30
	rotlwi	7, 14, 19
	xor	0, 0, 7
	rotlwi	7, 14, 10
	xor	0, 0, 7
	add	13, 13, 0
	xor	7, 14, 15
	xor	0, 15, 8
	and	0, 0, 7
	xor	0, 0, 15
	add	13, 13, 0
	# Round 3
	rotlwi	0, 9, 26
	rotlwi	7, 9, 21
	xor	0, 0, 7
	rotlwi	7, 9, 7
	xor	0, 0, 7
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	lwz	0, 12(6)
	add	12, 12, 19
	add	12, 12, 0
	add	8, 8, 12
	rotlwi	0, 13, 30
	rotlwi	7, 13, 19
	xor	0, 0, 7
	rotlwi	7, 13, 10
	xor	0, 0, 7
	add	12, 12, 0
	xor	7, 13, 14
	xor	0, 14, 15
	and	0, 0, 7
	xor	0, 0, 14
	add	12, 12, 0
	# Round 4
	rotlwi	0, 8, 26
	rotlwi	7, 8, 21
	xor	0, 0, 7
	rotlwi	7, 8, 7
	xor	0, 0, 7
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	lwz	0, 16(6)
	add	11, 11, 20
	add	11, 11, 0
	add	15, 15, 11
	rotlwi	0, 12, 30
	rotlwi	7, 12, 19
	xor	0, 0, 7
	rotlwi	7, 12, 10
	xor	0, 0, 7
	add	11, 11, 0
	xor	7, 12, 13
	xor	0, 13, 14
	and	0, 0, 7
	xor	0, 0, 13
	add	11, 11, 0
	# Round 5
	rotlwi	0, 15, 26
	rotlwi	7, 15, 21
	xor	0, 0, 7
	rotlwi	7, 15, 7
	xor	0, 0, 7
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 15
	xor	0, 0, 9
	add	10, 10, 0
	lwz	0, 20(6)
	add	10, 10, 21
	add	10, 10, 0
	add	14, 14, 10
	rotlwi	0, 11, 30
	rotlwi	7, 11, 19
	xor	0, 0, 7
	rotlwi	7, 11, 10
	xor	0, 0, 7
	add	10, 10, 0
	xor	7, 11, 12
	xor	0, 12, 13
	and	0, 0, 7
	xor	0, 0, 12
	add	10, 10, 0
	# Round 6
	rotlwi	0, 14, 26
	rotlwi	7, 14, 21
	xor	0, 0, 7
	rotlwi	7, 14, 7
	xor	0, 0, 7
	add	9, 9, 0
	xor	0, 15, 8
	and	0, 0, 14
	xor	0, 0, 8
	add	9, 9, 0
	lwz	0, 24(6)
	add	9, 9, 22
	add	9, 9, 0
	add	13, 13, 9
	rotlwi	0, 10, 30
	rotlwi	7, 10, 19
	xor	0, 0, 7
	rotlwi	7, 10, 10
	xor	0, 0, 7
	add	9, 9, 0
	xor	7, 10, 11
	xor	0, 11, 12
	and	0, 0, 7
	xor	0, 0, 11
	add	9, 9, 0
	# Round 7
	rotlwi	0, 13, 26
	rotlwi	7, 13, 21
	xor	0, 0, 7
	rotlwi	7, 13, 7
	xor	0, 0, 7
	add	8, 8, 0
	xor	0, 14, 15
	and	0, 0, 13
	xor	0, 0, 15
	add	8, 8, 0
	lwz	0, 28(6)
	add	8, 8, 23
	add	8, 8, 0
	add	12, 12, 8
	rotlwi	0, 9, 30
	rotlwi	7, 9, 19
	xor	0, 0, 7
	rotlwi	7, 9, 10
	xor	0, 0, 7
	add	8, 8, 0
	xor	7, 9, 10
	xor	0, 10, 11
	and	0, 0, 7
	xor	0, 0, 10
	add	8, 8, 0
	# Round 8
	rotlwi	0, 12, 26
	rotlwi	7, 12, 21
	xor	0, 0, 7
	rotlwi	7, 12, 7
	xor	0, 0, 7
	add	15, 15, 0
	xor	0, 13, 14
	and	0, 0, 12
	xor	0, 0, 14
	add	15, 15, 0
	lwz	0, 32(6)
	add	15, 15, 24
	add	15, 15, 0
	add	11, 11, 15
	rotlwi	0, 8, 30
	rotlwi	7, 8, 19
	xor	0, 0, 7
	rotlwi	7, 8, 10
	xor	0, 0, 7
	add	15, 15, 0
	xor	7, 8, 9
	xor	0, 9, 10
	and	0, 0, 7
	xor	0, 0, 9
	add	15, 15, 0
	# Round 9
	rotlwi	0, 11, 26
	rotlwi	7, 11, 21
	xor	0, 0, 7
	rotlwi	7, 11, 7
	xor	0, 0, 7
	add	14, 14, 0
	xor	0, 12, 13
	and	0, 0, 11
	xor	0, 0, 13
	add	14, 14, 0
	lwz	0, 36(6)
	add	14, 14, 25
	add	14, 14, 0
	add	10, 10, 14
	rotlwi	0, 15, 30
	rotlwi	7, 15, 19
	xor	0, 0, 7
	rotlwi	7, 15, 10
	xor	0, 0, 7
	add	14, 14, 0
	xor	7, 15, 8
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 8
	add	14, 14, 0
	# Round 10
	rotlwi	0, 10, 26
	rotlwi	7, 10, 21
	xor	0, 0, 7
	rotlwi	7, 10, 7
	xor	0, 0, 7
	add	13, 13, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	13, 13, 0
	lwz	0, 40(6)
	add	13, 13, 26
	add	13, 13, 0
	add	9, 9, 13
	rotlwi	0, 14, 30
	rotlwi	7, 14, 19
	xor	0, 0, 7
	rotlwi	7, 14, 10
	xor	0, 0, 7
	add	13, 13, 0
	xor	7, 14, 15
	xor	0, 15, 8
	and	0, 0, 7
	xor	0, 0, 15
	add	13, 13, 0
	# Round 11
	rotlwi	0, 9, 26
	rotlwi	7, 9, 21
	xor	0, 0, 7
	rotlwi	7, 9, 7
	xor	0, 0, 7
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	lwz	0, 44(6)
	add	12, 12, 27
	add	12, 12, 0
	add	8, 8, 12
	rotlwi	0, 13, 30
	rotlwi	7, 13, 19
	xor	0, 0, 7
	rotlwi	7, 13, 10
	xor	0, 0, 7
	add	12, 12, 0
	xor	7, 13, 14
	xor	0, 14, 15
	and	0, 0, 7
	xor	0, 0, 14
	add	12, 12, 0
	# Round 12
	rotlwi	0, 8, 26
	rotlwi	7, 8, 21
	xor	0, 0, 7
	rotlwi	7, 8, 7
	xor	0, 0, 7
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	lwz	0, 48(6)
	add	11, 11, 28
	add	11, 11, 0
	add	15, 15, 11
	rotlwi	0, 12, 30
	rotlwi	7, 12, 19
	xor	0, 0, 7
	rotlwi	7, 12, 10
	xor	0, 0, 7
	add	11, 11, 0
	xor	7, 12, 13
	xor	0, 13, 14
	and	0, 0, 7
	xor	0, 0, 13
	add	11, 11, 0
	# Round 13
	rotlwi	0, 15, 26
	rotlwi	7, 15, 21
	xor	0, 0, 7
	rotlwi	7, 15, 7
	xor	0, 0, 7
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 15
	xor	0, 0, 9
	add	10, 10, 0
	lwz	0, 52(6)
	add	10, 10, 29
	add	10, 10, 0
	add	14, 14, 10
	rotlwi	0, 11, 30
	rotlwi	7, 11, 19
	xor	0, 0, 7
	rotlwi	7, 11, 10
	xor	0, 0, 7
	add	10, 10, 0
	xor	7, 11, 12
	xor	0, 12, 13
	and	0, 0, 7
	xor	0, 0, 12
	add	10, 10, 0
	# Round 14
	rotlwi	0, 14, 26
	rotlwi	7, 14, 21
	xor	0, 0, 7
	rotlwi	7, 14, 7
	xor	0, 0, 7
	add	9, 9, 0
	xor	0, 15, 8
	and	0, 0, 14
	xor	0, 0, 8
	add	9, 9, 0
	lwz	0, 56(6)
	add	9, 9, 30
	add	9, 9, 0
	add	13, 13, 9
	rotlwi	0, 10, 30
	rotlwi	7, 10, 19
	xor	0, 0, 7
	rotlwi	7, 10, 10
	xor	0, 0, 7
	add	9, 9, 0
	xor	7, 10, 11
	xor	0, 11, 12
	and	0, 0, 7
	xor	0, 0, 11
	add	9, 9, 0
	# Round 15
	rotlwi	0, 13, 26
	rotlwi	7, 13, 21
	xor	0, 0, 7
	rotlwi	7, 13, 7
	xor	0, 0, 7
	add	8, 8, 0
	xor	0, 14, 15
	and	0, 0, 13
	xor	0, 0, 15
	add	8, 8, 0
	lwz	0, 60(6)
	add	8, 8, 31
	add	8, 8, 0
	add	12, 12, 8
	rotlwi	0, 9, 30
	rotlwi	7, 9, 19
	xor	0, 0, 7
	rotlwi	7, 9, 10
	xor	0, 0, 7
	add	8, 8, 0
	xor	7, 9, 10
	xor	0, 10, 11
	and	0, 0, 7
	xor	0, 0, 10
	add	8, 8, 0
	subi	6, 6, 0xc0
#else
	li	7, 4
	mtctr	7
	# Start of 16 rounds
L_SHA256_transform_len_start:
	# Round 0
	rotlwi	0, 12, 26
	rotlwi	7, 12, 21
	xor	0, 0, 7
	rotlwi	7, 12, 7
	xor	0, 0, 7
	add	15, 15, 0
	xor	0, 13, 14
	and	0, 0, 12
	xor	0, 0, 14
	add	15, 15, 0
	lwz	0, 0(6)
	add	15, 15, 16
	add	15, 15, 0
	add	11, 11, 15
	rotlwi	0, 8, 30
	rotlwi	7, 8, 19
	xor	0, 0, 7
	rotlwi	7, 8, 10
	xor	0, 0, 7
	add	15, 15, 0
	xor	7, 8, 9
	xor	0, 9, 10
	and	0, 0, 7
	xor	0, 0, 9
	add	15, 15, 0
	mfctr	7
	cmpwi	0, 7, 1
	beq	0, L_SHA256_transform_len_after_blk_0
	# Calc new W[0]
	rotlwi	0, 17, 25
	rotlwi	7, 17, 14
	xor	0, 0, 7
	srwi	7, 17, 3
	xor	0, 0, 7
	add	16, 16, 0
	rotlwi	0, 30, 15
	rotlwi	7, 30, 13
	xor	0, 0, 7
	srwi	7, 30, 10
	xor	0, 0, 7
	add	16, 16, 0
	add	16, 16, 25
L_SHA256_transform_len_after_blk_0:
	# Round 1
	rotlwi	0, 11, 26
	rotlwi	7, 11, 21
	xor	0, 0, 7
	rotlwi	7, 11, 7
	xor	0, 0, 7
	add	14, 14, 0
	xor	0, 12, 13
	and	0, 0, 11
	xor	0, 0, 13
	add	14, 14, 0
	lwz	0, 4(6)
	add	14, 14, 17
	add	14, 14, 0
	add	10, 10, 14
	rotlwi	0, 15, 30
	rotlwi	7, 15, 19
	xor	0, 0, 7
	rotlwi	7, 15, 10
	xor	0, 0, 7
	add	14, 14, 0
	xor	7, 15, 8
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 8
	add	14, 14, 0
	mfctr	7
	cmpwi	0, 7, 1
	beq	0, L_SHA256_transform_len_after_blk_1
	# Calc new W[1]
	rotlwi	0, 18, 25
	rotlwi	7, 18, 14
	xor	0, 0, 7
	srwi	7, 18, 3
	xor	0, 0, 7
	add	17, 17, 0
	rotlwi	0, 31, 15
	rotlwi	7, 31, 13
	xor	0, 0, 7
	srwi	7, 31, 10
	xor	0, 0, 7
	add	17, 17, 0
	add	17, 17, 26
L_SHA256_transform_len_after_blk_1:
	# Round 2
	rotlwi	0, 10, 26
	rotlwi	7, 10, 21
	xor	0, 0, 7
	rotlwi	7, 10, 7
	xor	0, 0, 7
	add	13, 13, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	13, 13, 0
	lwz	0, 8(6)
	add	13, 13, 18
	add	13, 13, 0
	add	9, 9, 13
	rotlwi	0, 14, 30
	rotlwi	7, 14, 19
	xor	0, 0, 7
	rotlwi	7, 14, 10
	xor	0, 0, 7
	add	13, 13, 0
	xor	7, 14, 15
	xor	0, 15, 8
	and	0, 0, 7
	xor	0, 0, 15
	add	13, 13, 0
	mfctr	7
	cmpwi	0, 7, 1
	beq	0, L_SHA256_transform_len_after_blk_2
	# Calc new W[2]
	rotlwi	0, 19, 25
	rotlwi	7, 19, 14
	xor	0, 0, 7
	srwi	7, 19, 3
	xor	0, 0, 7
	add	18, 18, 0
	rotlwi	0, 16, 15
	rotlwi	7, 16, 13
	xor	0, 0, 7
	srwi	7, 16, 10
	xor	0, 0, 7
	add	18, 18, 0
	add	18, 18, 27
L_SHA256_transform_len_after_blk_2:
	# Round 3
	rotlwi	0, 9, 26
	rotlwi	7, 9, 21
	xor	0, 0, 7
	rotlwi	7, 9, 7
	xor	0, 0, 7
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	lwz	0, 12(6)
	add	12, 12, 19
	add	12, 12, 0
	add	8, 8, 12
	rotlwi	0, 13, 30
	rotlwi	7, 13, 19
	xor	0, 0, 7
	rotlwi	7, 13, 10
	xor	0, 0, 7
	add	12, 12, 0
	xor	7, 13, 14
	xor	0, 14, 15
	and	0, 0, 7
	xor	0, 0, 14
	add	12, 12, 0
	mfctr	7
	cmpwi	0, 7, 1
	beq	0, L_SHA256_transform_len_after_blk_3
	# Calc new W[3]
	rotlwi	0, 20, 25
	rotlwi	7, 20, 14
	xor	0, 0, 7
	srwi	7, 20, 3
	xor	0, 0, 7
	add	19, 19, 0
	rotlwi	0, 17, 15
	rotlwi	7, 17, 13
	xor	0, 0, 7
	srwi	7, 17, 10
	xor	0, 0, 7
	add	19, 19, 0
	add	19, 19, 28
L_SHA256_transform_len_after_blk_3:
	# Round 4
	rotlwi	0, 8, 26
	rotlwi	7, 8, 21
	xor	0, 0, 7
	rotlwi	7, 8, 7
	xor	0, 0, 7
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	lwz	0, 16(6)
	add	11, 11, 20
	add	11, 11, 0
	add	15, 15, 11
	rotlwi	0, 12, 30
	rotlwi	7, 12, 19
	xor	0, 0, 7
	rotlwi	7, 12, 10
	xor	0, 0, 7
	add	11, 11, 0
	xor	7, 12, 13
	xor	0, 13, 14
	and	0, 0, 7
	xor	0, 0, 13
	add	11, 11, 0
	mfctr	7
	cmpwi	0, 7, 1
	beq	0, L_SHA256_transform_len_after_blk_4
	# Calc new W[4]
	rotlwi	0, 21, 25
	rotlwi	7, 21, 14
	xor	0, 0, 7
	srwi	7, 21, 3
	xor	0, 0, 7
	add	20, 20, 0
	rotlwi	0, 18, 15
	rotlwi	7, 18, 13
	xor	0, 0, 7
	srwi	7, 18, 10
	xor	0, 0, 7
	add	20, 20, 0
	add	20, 20, 29
L_SHA256_transform_len_after_blk_4:
	# Round 5
	rotlwi	0, 15, 26
	rotlwi	7, 15, 21
	xor	0, 0, 7
	rotlwi	7, 15, 7
	xor	0, 0, 7
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 15
	xor	0, 0, 9
	add	10, 10, 0
	lwz	0, 20(6)
	add	10, 10, 21
	add	10, 10, 0
	add	14, 14, 10
	rotlwi	0, 11, 30
	rotlwi	7, 11, 19
	xor	0, 0, 7
	rotlwi	7, 11, 10
	xor	0, 0, 7
	add	10, 10, 0
	xor	7, 11, 12
	xor	0, 12, 13
	and	0, 0, 7
	xor	0, 0, 12
	add	10, 10, 0
	mfctr	7
	cmpwi	0, 7, 1
	beq	0, L_SHA256_transform_len_after_blk_5
	# Calc new W[5]
	rotlwi	0, 22, 25
	rotlwi	7, 22, 14
	xor	0, 0, 7
	srwi	7, 22, 3
	xor	0, 0, 7
	add	21, 21, 0
	rotlwi	0, 19, 15
	rotlwi	7, 19, 13
	xor	0, 0, 7
	srwi	7, 19, 10
	xor	0, 0, 7
	add	21, 21, 0
	add	21, 21, 30
L_SHA256_transform_len_after_blk_5:
	# Round 6
	rotlwi	0, 14, 26
	rotlwi	7, 14, 21
	xor	0, 0, 7
	rotlwi	7, 14, 7
	xor	0, 0, 7
	add	9, 9, 0
	xor	0, 15, 8
	and	0, 0, 14
	xor	0, 0, 8
	add	9, 9, 0
	lwz	0, 24(6)
	add	9, 9, 22
	add	9, 9, 0
	add	13, 13, 9
	rotlwi	0, 10, 30
	rotlwi	7, 10, 19
	xor	0, 0, 7
	rotlwi	7, 10, 10
	xor	0, 0, 7
	add	9, 9, 0
	xor	7, 10, 11
	xor	0, 11, 12
	and	0, 0, 7
	xor	0, 0, 11
	add	9, 9, 0
	mfctr	7
	cmpwi	0, 7, 1
	beq	0, L_SHA256_transform_len_after_blk_6
	# Calc new W[6]
	rotlwi	0, 23, 25
	rotlwi	7, 23, 14
	xor	0, 0, 7
	srwi	7, 23, 3
	xor	0, 0, 7
	add	22, 22, 0
	rotlwi	0, 20, 15
	rotlwi	7, 20, 13
	xor	0, 0, 7
	srwi	7, 20, 10
	xor	0, 0, 7
	add	22, 22, 0
	add	22, 22, 31
L_SHA256_transform_len_after_blk_6:
	# Round 7
	rotlwi	0, 13, 26
	rotlwi	7, 13, 21
	xor	0, 0, 7
	rotlwi	7, 13, 7
	xor	0, 0, 7
	add	8, 8, 0
	xor	0, 14, 15
	and	0, 0, 13
	xor	0, 0, 15
	add	8, 8, 0
	lwz	0, 28(6)
	add	8, 8, 23
	add	8, 8, 0
	add	12, 12, 8
	rotlwi	0, 9, 30
	rotlwi	7, 9, 19
	xor	0, 0, 7
	rotlwi	7, 9, 10
	xor	0, 0, 7
	add	8, 8, 0
	xor	7, 9, 10
	xor	0, 10, 11
	and	0, 0, 7
	xor	0, 0, 10
	add	8, 8, 0
	mfctr	7
	cmpwi	0, 7, 1
	beq	0, L_SHA256_transform_len_after_blk_7
	# Calc new W[7]
	rotlwi	0, 24, 25
	rotlwi	7, 24, 14
	xor	0, 0, 7
	srwi	7, 24, 3
	xor	0, 0, 7
	add	23, 23, 0
	rotlwi	0, 21, 15
	rotlwi	7, 21, 13
	xor	0, 0, 7
	srwi	7, 21, 10
	xor	0, 0, 7
	add	23, 23, 0
	add	23, 23, 16
L_SHA256_transform_len_after_blk_7:
	# Round 8
	rotlwi	0, 12, 26
	rotlwi	7, 12, 21
	xor	0, 0, 7
	rotlwi	7, 12, 7
	xor	0, 0, 7
	add	15, 15, 0
	xor	0, 13, 14
	and	0, 0, 12
	xor	0, 0, 14
	add	15, 15, 0
	lwz	0, 32(6)
	add	15, 15, 24
	add	15, 15, 0
	add	11, 11, 15
	rotlwi	0, 8, 30
	rotlwi	7, 8, 19
	xor	0, 0, 7
	rotlwi	7, 8, 10
	xor	0, 0, 7
	add	15, 15, 0
	xor	7, 8, 9
	xor	0, 9, 10
	and	0, 0, 7
	xor	0, 0, 9
	add	15, 15, 0
	mfctr	7
	cmpwi	0, 7, 1
	beq	0, L_SHA256_transform_len_after_blk_8
	# Calc new W[8]
	rotlwi	0, 25, 25
	rotlwi	7, 25, 14
	xor	0, 0, 7
	srwi	7, 25, 3
	xor	0, 0, 7
	add	24, 24, 0
	rotlwi	0, 22, 15
	rotlwi	7, 22, 13
	xor	0, 0, 7
	srwi	7, 22, 10
	xor	0, 0, 7
	add	24, 24, 0
	add	24, 24, 17
L_SHA256_transform_len_after_blk_8:
	# Round 9
	rotlwi	0, 11, 26
	rotlwi	7, 11, 21
	xor	0, 0, 7
	rotlwi	7, 11, 7
	xor	0, 0, 7
	add	14, 14, 0
	xor	0, 12, 13
	and	0, 0, 11
	xor	0, 0, 13
	add	14, 14, 0
	lwz	0, 36(6)
	add	14, 14, 25
	add	14, 14, 0
	add	10, 10, 14
	rotlwi	0, 15, 30
	rotlwi	7, 15, 19
	xor	0, 0, 7
	rotlwi	7, 15, 10
	xor	0, 0, 7
	add	14, 14, 0
	xor	7, 15, 8
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 8
	add	14, 14, 0
	mfctr	7
	cmpwi	0, 7, 1
	beq	0, L_SHA256_transform_len_after_blk_9
	# Calc new W[9]
	rotlwi	0, 26, 25
	rotlwi	7, 26, 14
	xor	0, 0, 7
	srwi	7, 26, 3
	xor	0, 0, 7
	add	25, 25, 0
	rotlwi	0, 23, 15
	rotlwi	7, 23, 13
	xor	0, 0, 7
	srwi	7, 23, 10
	xor	0, 0, 7
	add	25, 25, 0
	add	25, 25, 18
L_SHA256_transform_len_after_blk_9:
	# Round 10
	rotlwi	0, 10, 26
	rotlwi	7, 10, 21
	xor	0, 0, 7
	rotlwi	7, 10, 7
	xor	0, 0, 7
	add	13, 13, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	13, 13, 0
	lwz	0, 40(6)
	add	13, 13, 26
	add	13, 13, 0
	add	9, 9, 13
	rotlwi	0, 14, 30
	rotlwi	7, 14, 19
	xor	0, 0, 7
	rotlwi	7, 14, 10
	xor	0, 0, 7
	add	13, 13, 0
	xor	7, 14, 15
	xor	0, 15, 8
	and	0, 0, 7
	xor	0, 0, 15
	add	13, 13, 0
	mfctr	7
	cmpwi	0, 7, 1
	beq	0, L_SHA256_transform_len_after_blk_10
	# Calc new W[10]
	rotlwi	0, 27, 25
	rotlwi	7, 27, 14
	xor	0, 0, 7
	srwi	7, 27, 3
	xor	0, 0, 7
	add	26, 26, 0
	rotlwi	0, 24, 15
	rotlwi	7, 24, 13
	xor	0, 0, 7
	srwi	7, 24, 10
	xor	0, 0, 7
	add	26, 26, 0
	add	26, 26, 19
L_SHA256_transform_len_after_blk_10:
	# Round 11
	rotlwi	0, 9, 26
	rotlwi	7, 9, 21
	xor	0, 0, 7
	rotlwi	7, 9, 7
	xor	0, 0, 7
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	lwz	0, 44(6)
	add	12, 12, 27
	add	12, 12, 0
	add	8, 8, 12
	rotlwi	0, 13, 30
	rotlwi	7, 13, 19
	xor	0, 0, 7
	rotlwi	7, 13, 10
	xor	0, 0, 7
	add	12, 12, 0
	xor	7, 13, 14
	xor	0, 14, 15
	and	0, 0, 7
	xor	0, 0, 14
	add	12, 12, 0
	mfctr	7
	cmpwi	0, 7, 1
	beq	0, L_SHA256_transform_len_after_blk_11
	# Calc new W[11]
	rotlwi	0, 28, 25
	rotlwi	7, 28, 14
	xor	0, 0, 7
	srwi	7, 28, 3
	xor	0, 0, 7
	add	27, 27, 0
	rotlwi	0, 25, 15
	rotlwi	7, 25, 13
	xor	0, 0, 7
	srwi	7, 25, 10
	xor	0, 0, 7
	add	27, 27, 0
	add	27, 27, 20
L_SHA256_transform_len_after_blk_11:
	# Round 12
	rotlwi	0, 8, 26
	rotlwi	7, 8, 21
	xor	0, 0, 7
	rotlwi	7, 8, 7
	xor	0, 0, 7
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	lwz	0, 48(6)
	add	11, 11, 28
	add	11, 11, 0
	add	15, 15, 11
	rotlwi	0, 12, 30
	rotlwi	7, 12, 19
	xor	0, 0, 7
	rotlwi	7, 12, 10
	xor	0, 0, 7
	add	11, 11, 0
	xor	7, 12, 13
	xor	0, 13, 14
	and	0, 0, 7
	xor	0, 0, 13
	add	11, 11, 0
	mfctr	7
	cmpwi	0, 7, 1
	beq	0, L_SHA256_transform_len_after_blk_12
	# Calc new W[12]
	rotlwi	0, 29, 25
	rotlwi	7, 29, 14
	xor	0, 0, 7
	srwi	7, 29, 3
	xor	0, 0, 7
	add	28, 28, 0
	rotlwi	0, 26, 15
	rotlwi	7, 26, 13
	xor	0, 0, 7
	srwi	7, 26, 10
	xor	0, 0, 7
	add	28, 28, 0
	add	28, 28, 21
L_SHA256_transform_len_after_blk_12:
	# Round 13
	rotlwi	0, 15, 26
	rotlwi	7, 15, 21
	xor	0, 0, 7
	rotlwi	7, 15, 7
	xor	0, 0, 7
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 15
	xor	0, 0, 9
	add	10, 10, 0
	lwz	0, 52(6)
	add	10, 10, 29
	add	10, 10, 0
	add	14, 14, 10
	rotlwi	0, 11, 30
	rotlwi	7, 11, 19
	xor	0, 0, 7
	rotlwi	7, 11, 10
	xor	0, 0, 7
	add	10, 10, 0
	xor	7, 11, 12
	xor	0, 12, 13
	and	0, 0, 7
	xor	0, 0, 12
	add	10, 10, 0
	mfctr	7
	cmpwi	0, 7, 1
	beq	0, L_SHA256_transform_len_after_blk_13
	# Calc new W[13]
	rotlwi	0, 30, 25
	rotlwi	7, 30, 14
	xor	0, 0, 7
	srwi	7, 30, 3
	xor	0, 0, 7
	add	29, 29, 0
	rotlwi	0, 27, 15
	rotlwi	7, 27, 13
	xor	0, 0, 7
	srwi	7, 27, 10
	xor	0, 0, 7
	add	29, 29, 0
	add	29, 29, 22
L_SHA256_transform_len_after_blk_13:
	# Round 14
	rotlwi	0, 14, 26
	rotlwi	7, 14, 21
	xor	0, 0, 7
	rotlwi	7, 14, 7
	xor	0, 0, 7
	add	9, 9, 0
	xor	0, 15, 8
	and	0, 0, 14
	xor	0, 0, 8
	add	9, 9, 0
	lwz	0, 56(6)
	add	9, 9, 30
	add	9, 9, 0
	add	13, 13, 9
	rotlwi	0, 10, 30
	rotlwi	7, 10, 19
	xor	0, 0, 7
	rotlwi	7, 10, 10
	xor	0, 0, 7
	add	9, 9, 0
	xor	7, 10, 11
	xor	0, 11, 12
	and	0, 0, 7
	xor	0, 0, 11
	add	9, 9, 0
	mfctr	7
	cmpwi	0, 7, 1
	beq	0, L_SHA256_transform_len_after_blk_14
	# Calc new W[14]
	rotlwi	0, 31, 25
	rotlwi	7, 31, 14
	xor	0, 0, 7
	srwi	7, 31, 3
	xor	0, 0, 7
	add	30, 30, 0
	rotlwi	0, 28, 15
	rotlwi	7, 28, 13
	xor	0, 0, 7
	srwi	7, 28, 10
	xor	0, 0, 7
	add	30, 30, 0
	add	30, 30, 23
L_SHA256_transform_len_after_blk_14:
	# Round 15
	rotlwi	0, 13, 26
	rotlwi	7, 13, 21
	xor	0, 0, 7
	rotlwi	7, 13, 7
	xor	0, 0, 7
	add	8, 8, 0
	xor	0, 14, 15
	and	0, 0, 13
	xor	0, 0, 15
	add	8, 8, 0
	lwz	0, 60(6)
	add	8, 8, 31
	add	8, 8, 0
	add	12, 12, 8
	rotlwi	0, 9, 30
	rotlwi	7, 9, 19
	xor	0, 0, 7
	rotlwi	7, 9, 10
	xor	0, 0, 7
	add	8, 8, 0
	xor	7, 9, 10
	xor	0, 10, 11
	and	0, 0, 7
	xor	0, 0, 10
	add	8, 8, 0
	mfctr	7
	cmpwi	0, 7, 1
	beq	0, L_SHA256_transform_len_after_blk_15
	# Calc new W[15]
	rotlwi	0, 16, 25
	rotlwi	7, 16, 14
	xor	0, 0, 7
	srwi	7, 16, 3
	xor	0, 0, 7
	add	31, 31, 0
	rotlwi	0, 29, 15
	rotlwi	7, 29, 13
	xor	0, 0, 7
	srwi	7, 29, 10
	xor	0, 0, 7
	add	31, 31, 0
	add	31, 31, 24
L_SHA256_transform_len_after_blk_15:
	addi	6, 6, 0x40
	bdnz	L_SHA256_transform_len_start
	subi	6, 6, 0x100
#endif /* WOLFSSL_PPC32_ASM_SMALL */
	# Add in digest from start
	lwz	0, 0(1)
	lwz	7, 4(1)
	add	8, 8, 0
	add	9, 9, 7
	lwz	0, 8(1)
	lwz	7, 12(1)
	add	10, 10, 0
	add	11, 11, 7
	lwz	0, 16(1)
	lwz	7, 20(1)
	add	12, 12, 0
	add	13, 13, 7
	lwz	0, 24(1)
	lwz	7, 28(1)
	add	14, 14, 0
	add	15, 15, 7
	stw	8, 0(1)
	stw	9, 4(1)
	stw	10, 8(1)
	stw	11, 12(1)
	stw	12, 16(1)
	stw	13, 20(1)
	stw	14, 24(1)
	stw	15, 28(1)
	mtctr	5
	addi	4, 4, 0x40
	subi	5, 5, 1
	bdnz	L_SHA256_transform_len_begin
	stw	8, 0(3)
	stw	9, 4(3)
	stw	10, 8(3)
	stw	11, 12(3)
	stw	12, 16(3)
	stw	13, 20(3)
	stw	14, 24(3)
	stw	15, 28(3)
	addi	1, 1, 32
	lwz	0, 72(1)
	mtlr	0
	lwz	14, 0(1)
	lwz	15, 4(1)
	lwz	16, 8(1)
	lwz	17, 12(1)
	lwz	18, 16(1)
	lwz	19, 20(1)
	lwz	20, 24(1)
	lwz	21, 28(1)
	lwz	22, 32(1)
	lwz	23, 36(1)
	lwz	24, 40(1)
	lwz	25, 44(1)
	lwz	26, 48(1)
	lwz	27, 52(1)
	lwz	28, 56(1)
	lwz	29, 60(1)
	lwz	30, 64(1)
	lwz	31, 68(1)
	addi	1, 1, 0x4c
	blr
	.size	Transform_Sha256_Len,.-Transform_Sha256_Len
#endif /* !NO_SHA256 */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_PPC32_ASM_INLINE */
#endif /* WOLFSSL_PPC32_ASM */
