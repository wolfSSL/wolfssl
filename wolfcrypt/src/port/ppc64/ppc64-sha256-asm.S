/* ppc64-sha256-asm
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
 *   ruby ./sha2/sha256.rb ppc64 \
 *       ../wolfssl/wolfcrypt/src/port/ppc64/ppc64-sha256-asm.S
 */
#ifdef WOLFSSL_PPC64_ASM
#ifndef WOLFSSL_PPC64_ASM_INLINE
#ifndef NO_SHA256
#ifndef __APPLE__
	.text
	.type	L_SHA256_transform_len_k, %object
	.size	L_SHA256_transform_len_k, 256
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_SHA256_transform_len_k:
	.long	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5
	.long	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
	.long	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3
	.long	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
	.long	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc
	.long	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
	.long	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7
	.long	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
	.long	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13
	.long	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
	.long	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3
	.long	0xd192e819,0xd6990624,0xf40e3585,0x106aa070
	.long	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5
	.long	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
	.long	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208
	.long	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
#ifndef __APPLE__
.text
.globl	Transform_Sha256_Len
.type	Transform_Sha256_Len,@function
.align	16
Transform_Sha256_Len:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	Transform_Sha256_Len, .-Transform_Sha256_Len
#endif
#else
.section	__TEXT,__text
.globl	_Transform_Sha256_Len
.p2align	4
_Transform_Sha256_Len:
#endif /* __APPLE__ */
	stdu	1, -152(1)
	mflr	0
	std	0, 144(1)
	std	14, 0(1)
	std	15, 8(1)
	std	16, 16(1)
	std	17, 24(1)
	std	18, 32(1)
	std	19, 40(1)
	std	20, 48(1)
	std	21, 56(1)
	std	22, 64(1)
	std	23, 72(1)
	std	24, 80(1)
	std	25, 88(1)
	std	26, 96(1)
	std	27, 104(1)
	std	28, 112(1)
	std	29, 120(1)
	std	30, 128(1)
	std	31, 136(1)
	srwi	5, 5, 6
	addis	6, 2, L_SHA256_transform_len_k@toc@ha
	addi	6, 6, L_SHA256_transform_len_k@toc@l
	# Copy digest to add in at end
	lwz	7, 0(3)
	lwz	8, 4(3)
	lwz	9, 8(3)
	lwz	10, 12(3)
	lwz	11, 16(3)
	lwz	12, 20(3)
	lwz	14, 24(3)
	lwz	15, 28(3)
#ifndef WOLFSSL_PPC64_ASM_SMALL
	mtctr	5
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
	# Start of 16 rounds
	# Round 0
	rotlwi	0, 11, 26
	rotlwi	5, 11, 21
	xor	0, 0, 5
	rotlwi	5, 11, 7
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	lwz	0, 0(6)
	add	15, 15, 16
	add	15, 15, 0
	add	10, 10, 15
	rotlwi	0, 7, 30
	rotlwi	5, 7, 19
	xor	0, 0, 5
	rotlwi	5, 7, 10
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	# Calc new W[0]
	rotlwi	0, 17, 25
	rotlwi	5, 17, 14
	xor	0, 0, 5
	srwi	5, 17, 3
	xor	0, 0, 5
	add	16, 16, 0
	rotlwi	0, 30, 15
	rotlwi	5, 30, 13
	xor	0, 0, 5
	srwi	5, 30, 10
	xor	0, 0, 5
	add	16, 16, 0
	add	16, 16, 25
	# Round 1
	rotlwi	0, 10, 26
	rotlwi	5, 10, 21
	xor	0, 0, 5
	rotlwi	5, 10, 7
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	lwz	0, 4(6)
	add	14, 14, 17
	add	14, 14, 0
	add	9, 9, 14
	rotlwi	0, 15, 30
	rotlwi	5, 15, 19
	xor	0, 0, 5
	rotlwi	5, 15, 10
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	# Calc new W[1]
	rotlwi	0, 18, 25
	rotlwi	5, 18, 14
	xor	0, 0, 5
	srwi	5, 18, 3
	xor	0, 0, 5
	add	17, 17, 0
	rotlwi	0, 31, 15
	rotlwi	5, 31, 13
	xor	0, 0, 5
	srwi	5, 31, 10
	xor	0, 0, 5
	add	17, 17, 0
	add	17, 17, 26
	# Round 2
	rotlwi	0, 9, 26
	rotlwi	5, 9, 21
	xor	0, 0, 5
	rotlwi	5, 9, 7
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	lwz	0, 8(6)
	add	12, 12, 18
	add	12, 12, 0
	add	8, 8, 12
	rotlwi	0, 14, 30
	rotlwi	5, 14, 19
	xor	0, 0, 5
	rotlwi	5, 14, 10
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	# Calc new W[2]
	rotlwi	0, 19, 25
	rotlwi	5, 19, 14
	xor	0, 0, 5
	srwi	5, 19, 3
	xor	0, 0, 5
	add	18, 18, 0
	rotlwi	0, 16, 15
	rotlwi	5, 16, 13
	xor	0, 0, 5
	srwi	5, 16, 10
	xor	0, 0, 5
	add	18, 18, 0
	add	18, 18, 27
	# Round 3
	rotlwi	0, 8, 26
	rotlwi	5, 8, 21
	xor	0, 0, 5
	rotlwi	5, 8, 7
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	lwz	0, 12(6)
	add	11, 11, 19
	add	11, 11, 0
	add	7, 7, 11
	rotlwi	0, 12, 30
	rotlwi	5, 12, 19
	xor	0, 0, 5
	rotlwi	5, 12, 10
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	# Calc new W[3]
	rotlwi	0, 20, 25
	rotlwi	5, 20, 14
	xor	0, 0, 5
	srwi	5, 20, 3
	xor	0, 0, 5
	add	19, 19, 0
	rotlwi	0, 17, 15
	rotlwi	5, 17, 13
	xor	0, 0, 5
	srwi	5, 17, 10
	xor	0, 0, 5
	add	19, 19, 0
	add	19, 19, 28
	# Round 4
	rotlwi	0, 7, 26
	rotlwi	5, 7, 21
	xor	0, 0, 5
	rotlwi	5, 7, 7
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	lwz	0, 16(6)
	add	10, 10, 20
	add	10, 10, 0
	add	15, 15, 10
	rotlwi	0, 11, 30
	rotlwi	5, 11, 19
	xor	0, 0, 5
	rotlwi	5, 11, 10
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	# Calc new W[4]
	rotlwi	0, 21, 25
	rotlwi	5, 21, 14
	xor	0, 0, 5
	srwi	5, 21, 3
	xor	0, 0, 5
	add	20, 20, 0
	rotlwi	0, 18, 15
	rotlwi	5, 18, 13
	xor	0, 0, 5
	srwi	5, 18, 10
	xor	0, 0, 5
	add	20, 20, 0
	add	20, 20, 29
	# Round 5
	rotlwi	0, 15, 26
	rotlwi	5, 15, 21
	xor	0, 0, 5
	rotlwi	5, 15, 7
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	lwz	0, 20(6)
	add	9, 9, 21
	add	9, 9, 0
	add	14, 14, 9
	rotlwi	0, 10, 30
	rotlwi	5, 10, 19
	xor	0, 0, 5
	rotlwi	5, 10, 10
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	# Calc new W[5]
	rotlwi	0, 22, 25
	rotlwi	5, 22, 14
	xor	0, 0, 5
	srwi	5, 22, 3
	xor	0, 0, 5
	add	21, 21, 0
	rotlwi	0, 19, 15
	rotlwi	5, 19, 13
	xor	0, 0, 5
	srwi	5, 19, 10
	xor	0, 0, 5
	add	21, 21, 0
	add	21, 21, 30
	# Round 6
	rotlwi	0, 14, 26
	rotlwi	5, 14, 21
	xor	0, 0, 5
	rotlwi	5, 14, 7
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	lwz	0, 24(6)
	add	8, 8, 22
	add	8, 8, 0
	add	12, 12, 8
	rotlwi	0, 9, 30
	rotlwi	5, 9, 19
	xor	0, 0, 5
	rotlwi	5, 9, 10
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	# Calc new W[6]
	rotlwi	0, 23, 25
	rotlwi	5, 23, 14
	xor	0, 0, 5
	srwi	5, 23, 3
	xor	0, 0, 5
	add	22, 22, 0
	rotlwi	0, 20, 15
	rotlwi	5, 20, 13
	xor	0, 0, 5
	srwi	5, 20, 10
	xor	0, 0, 5
	add	22, 22, 0
	add	22, 22, 31
	# Round 7
	rotlwi	0, 12, 26
	rotlwi	5, 12, 21
	xor	0, 0, 5
	rotlwi	5, 12, 7
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	lwz	0, 28(6)
	add	7, 7, 23
	add	7, 7, 0
	add	11, 11, 7
	rotlwi	0, 8, 30
	rotlwi	5, 8, 19
	xor	0, 0, 5
	rotlwi	5, 8, 10
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	# Calc new W[7]
	rotlwi	0, 24, 25
	rotlwi	5, 24, 14
	xor	0, 0, 5
	srwi	5, 24, 3
	xor	0, 0, 5
	add	23, 23, 0
	rotlwi	0, 21, 15
	rotlwi	5, 21, 13
	xor	0, 0, 5
	srwi	5, 21, 10
	xor	0, 0, 5
	add	23, 23, 0
	add	23, 23, 16
	# Round 8
	rotlwi	0, 11, 26
	rotlwi	5, 11, 21
	xor	0, 0, 5
	rotlwi	5, 11, 7
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	lwz	0, 32(6)
	add	15, 15, 24
	add	15, 15, 0
	add	10, 10, 15
	rotlwi	0, 7, 30
	rotlwi	5, 7, 19
	xor	0, 0, 5
	rotlwi	5, 7, 10
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	# Calc new W[8]
	rotlwi	0, 25, 25
	rotlwi	5, 25, 14
	xor	0, 0, 5
	srwi	5, 25, 3
	xor	0, 0, 5
	add	24, 24, 0
	rotlwi	0, 22, 15
	rotlwi	5, 22, 13
	xor	0, 0, 5
	srwi	5, 22, 10
	xor	0, 0, 5
	add	24, 24, 0
	add	24, 24, 17
	# Round 9
	rotlwi	0, 10, 26
	rotlwi	5, 10, 21
	xor	0, 0, 5
	rotlwi	5, 10, 7
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	lwz	0, 36(6)
	add	14, 14, 25
	add	14, 14, 0
	add	9, 9, 14
	rotlwi	0, 15, 30
	rotlwi	5, 15, 19
	xor	0, 0, 5
	rotlwi	5, 15, 10
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	# Calc new W[9]
	rotlwi	0, 26, 25
	rotlwi	5, 26, 14
	xor	0, 0, 5
	srwi	5, 26, 3
	xor	0, 0, 5
	add	25, 25, 0
	rotlwi	0, 23, 15
	rotlwi	5, 23, 13
	xor	0, 0, 5
	srwi	5, 23, 10
	xor	0, 0, 5
	add	25, 25, 0
	add	25, 25, 18
	# Round 10
	rotlwi	0, 9, 26
	rotlwi	5, 9, 21
	xor	0, 0, 5
	rotlwi	5, 9, 7
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	lwz	0, 40(6)
	add	12, 12, 26
	add	12, 12, 0
	add	8, 8, 12
	rotlwi	0, 14, 30
	rotlwi	5, 14, 19
	xor	0, 0, 5
	rotlwi	5, 14, 10
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	# Calc new W[10]
	rotlwi	0, 27, 25
	rotlwi	5, 27, 14
	xor	0, 0, 5
	srwi	5, 27, 3
	xor	0, 0, 5
	add	26, 26, 0
	rotlwi	0, 24, 15
	rotlwi	5, 24, 13
	xor	0, 0, 5
	srwi	5, 24, 10
	xor	0, 0, 5
	add	26, 26, 0
	add	26, 26, 19
	# Round 11
	rotlwi	0, 8, 26
	rotlwi	5, 8, 21
	xor	0, 0, 5
	rotlwi	5, 8, 7
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	lwz	0, 44(6)
	add	11, 11, 27
	add	11, 11, 0
	add	7, 7, 11
	rotlwi	0, 12, 30
	rotlwi	5, 12, 19
	xor	0, 0, 5
	rotlwi	5, 12, 10
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	# Calc new W[11]
	rotlwi	0, 28, 25
	rotlwi	5, 28, 14
	xor	0, 0, 5
	srwi	5, 28, 3
	xor	0, 0, 5
	add	27, 27, 0
	rotlwi	0, 25, 15
	rotlwi	5, 25, 13
	xor	0, 0, 5
	srwi	5, 25, 10
	xor	0, 0, 5
	add	27, 27, 0
	add	27, 27, 20
	# Round 12
	rotlwi	0, 7, 26
	rotlwi	5, 7, 21
	xor	0, 0, 5
	rotlwi	5, 7, 7
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	lwz	0, 48(6)
	add	10, 10, 28
	add	10, 10, 0
	add	15, 15, 10
	rotlwi	0, 11, 30
	rotlwi	5, 11, 19
	xor	0, 0, 5
	rotlwi	5, 11, 10
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	# Calc new W[12]
	rotlwi	0, 29, 25
	rotlwi	5, 29, 14
	xor	0, 0, 5
	srwi	5, 29, 3
	xor	0, 0, 5
	add	28, 28, 0
	rotlwi	0, 26, 15
	rotlwi	5, 26, 13
	xor	0, 0, 5
	srwi	5, 26, 10
	xor	0, 0, 5
	add	28, 28, 0
	add	28, 28, 21
	# Round 13
	rotlwi	0, 15, 26
	rotlwi	5, 15, 21
	xor	0, 0, 5
	rotlwi	5, 15, 7
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	lwz	0, 52(6)
	add	9, 9, 29
	add	9, 9, 0
	add	14, 14, 9
	rotlwi	0, 10, 30
	rotlwi	5, 10, 19
	xor	0, 0, 5
	rotlwi	5, 10, 10
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	# Calc new W[13]
	rotlwi	0, 30, 25
	rotlwi	5, 30, 14
	xor	0, 0, 5
	srwi	5, 30, 3
	xor	0, 0, 5
	add	29, 29, 0
	rotlwi	0, 27, 15
	rotlwi	5, 27, 13
	xor	0, 0, 5
	srwi	5, 27, 10
	xor	0, 0, 5
	add	29, 29, 0
	add	29, 29, 22
	# Round 14
	rotlwi	0, 14, 26
	rotlwi	5, 14, 21
	xor	0, 0, 5
	rotlwi	5, 14, 7
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	lwz	0, 56(6)
	add	8, 8, 30
	add	8, 8, 0
	add	12, 12, 8
	rotlwi	0, 9, 30
	rotlwi	5, 9, 19
	xor	0, 0, 5
	rotlwi	5, 9, 10
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	# Calc new W[14]
	rotlwi	0, 31, 25
	rotlwi	5, 31, 14
	xor	0, 0, 5
	srwi	5, 31, 3
	xor	0, 0, 5
	add	30, 30, 0
	rotlwi	0, 28, 15
	rotlwi	5, 28, 13
	xor	0, 0, 5
	srwi	5, 28, 10
	xor	0, 0, 5
	add	30, 30, 0
	add	30, 30, 23
	# Round 15
	rotlwi	0, 12, 26
	rotlwi	5, 12, 21
	xor	0, 0, 5
	rotlwi	5, 12, 7
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	lwz	0, 60(6)
	add	7, 7, 31
	add	7, 7, 0
	add	11, 11, 7
	rotlwi	0, 8, 30
	rotlwi	5, 8, 19
	xor	0, 0, 5
	rotlwi	5, 8, 10
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	# Calc new W[15]
	rotlwi	0, 16, 25
	rotlwi	5, 16, 14
	xor	0, 0, 5
	srwi	5, 16, 3
	xor	0, 0, 5
	add	31, 31, 0
	rotlwi	0, 29, 15
	rotlwi	5, 29, 13
	xor	0, 0, 5
	srwi	5, 29, 10
	xor	0, 0, 5
	add	31, 31, 0
	add	31, 31, 24
	addi	6, 6, 0x40
	# Round 0
	rotlwi	0, 11, 26
	rotlwi	5, 11, 21
	xor	0, 0, 5
	rotlwi	5, 11, 7
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	lwz	0, 0(6)
	add	15, 15, 16
	add	15, 15, 0
	add	10, 10, 15
	rotlwi	0, 7, 30
	rotlwi	5, 7, 19
	xor	0, 0, 5
	rotlwi	5, 7, 10
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	# Calc new W[0]
	rotlwi	0, 17, 25
	rotlwi	5, 17, 14
	xor	0, 0, 5
	srwi	5, 17, 3
	xor	0, 0, 5
	add	16, 16, 0
	rotlwi	0, 30, 15
	rotlwi	5, 30, 13
	xor	0, 0, 5
	srwi	5, 30, 10
	xor	0, 0, 5
	add	16, 16, 0
	add	16, 16, 25
	# Round 1
	rotlwi	0, 10, 26
	rotlwi	5, 10, 21
	xor	0, 0, 5
	rotlwi	5, 10, 7
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	lwz	0, 4(6)
	add	14, 14, 17
	add	14, 14, 0
	add	9, 9, 14
	rotlwi	0, 15, 30
	rotlwi	5, 15, 19
	xor	0, 0, 5
	rotlwi	5, 15, 10
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	# Calc new W[1]
	rotlwi	0, 18, 25
	rotlwi	5, 18, 14
	xor	0, 0, 5
	srwi	5, 18, 3
	xor	0, 0, 5
	add	17, 17, 0
	rotlwi	0, 31, 15
	rotlwi	5, 31, 13
	xor	0, 0, 5
	srwi	5, 31, 10
	xor	0, 0, 5
	add	17, 17, 0
	add	17, 17, 26
	# Round 2
	rotlwi	0, 9, 26
	rotlwi	5, 9, 21
	xor	0, 0, 5
	rotlwi	5, 9, 7
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	lwz	0, 8(6)
	add	12, 12, 18
	add	12, 12, 0
	add	8, 8, 12
	rotlwi	0, 14, 30
	rotlwi	5, 14, 19
	xor	0, 0, 5
	rotlwi	5, 14, 10
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	# Calc new W[2]
	rotlwi	0, 19, 25
	rotlwi	5, 19, 14
	xor	0, 0, 5
	srwi	5, 19, 3
	xor	0, 0, 5
	add	18, 18, 0
	rotlwi	0, 16, 15
	rotlwi	5, 16, 13
	xor	0, 0, 5
	srwi	5, 16, 10
	xor	0, 0, 5
	add	18, 18, 0
	add	18, 18, 27
	# Round 3
	rotlwi	0, 8, 26
	rotlwi	5, 8, 21
	xor	0, 0, 5
	rotlwi	5, 8, 7
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	lwz	0, 12(6)
	add	11, 11, 19
	add	11, 11, 0
	add	7, 7, 11
	rotlwi	0, 12, 30
	rotlwi	5, 12, 19
	xor	0, 0, 5
	rotlwi	5, 12, 10
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	# Calc new W[3]
	rotlwi	0, 20, 25
	rotlwi	5, 20, 14
	xor	0, 0, 5
	srwi	5, 20, 3
	xor	0, 0, 5
	add	19, 19, 0
	rotlwi	0, 17, 15
	rotlwi	5, 17, 13
	xor	0, 0, 5
	srwi	5, 17, 10
	xor	0, 0, 5
	add	19, 19, 0
	add	19, 19, 28
	# Round 4
	rotlwi	0, 7, 26
	rotlwi	5, 7, 21
	xor	0, 0, 5
	rotlwi	5, 7, 7
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	lwz	0, 16(6)
	add	10, 10, 20
	add	10, 10, 0
	add	15, 15, 10
	rotlwi	0, 11, 30
	rotlwi	5, 11, 19
	xor	0, 0, 5
	rotlwi	5, 11, 10
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	# Calc new W[4]
	rotlwi	0, 21, 25
	rotlwi	5, 21, 14
	xor	0, 0, 5
	srwi	5, 21, 3
	xor	0, 0, 5
	add	20, 20, 0
	rotlwi	0, 18, 15
	rotlwi	5, 18, 13
	xor	0, 0, 5
	srwi	5, 18, 10
	xor	0, 0, 5
	add	20, 20, 0
	add	20, 20, 29
	# Round 5
	rotlwi	0, 15, 26
	rotlwi	5, 15, 21
	xor	0, 0, 5
	rotlwi	5, 15, 7
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	lwz	0, 20(6)
	add	9, 9, 21
	add	9, 9, 0
	add	14, 14, 9
	rotlwi	0, 10, 30
	rotlwi	5, 10, 19
	xor	0, 0, 5
	rotlwi	5, 10, 10
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	# Calc new W[5]
	rotlwi	0, 22, 25
	rotlwi	5, 22, 14
	xor	0, 0, 5
	srwi	5, 22, 3
	xor	0, 0, 5
	add	21, 21, 0
	rotlwi	0, 19, 15
	rotlwi	5, 19, 13
	xor	0, 0, 5
	srwi	5, 19, 10
	xor	0, 0, 5
	add	21, 21, 0
	add	21, 21, 30
	# Round 6
	rotlwi	0, 14, 26
	rotlwi	5, 14, 21
	xor	0, 0, 5
	rotlwi	5, 14, 7
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	lwz	0, 24(6)
	add	8, 8, 22
	add	8, 8, 0
	add	12, 12, 8
	rotlwi	0, 9, 30
	rotlwi	5, 9, 19
	xor	0, 0, 5
	rotlwi	5, 9, 10
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	# Calc new W[6]
	rotlwi	0, 23, 25
	rotlwi	5, 23, 14
	xor	0, 0, 5
	srwi	5, 23, 3
	xor	0, 0, 5
	add	22, 22, 0
	rotlwi	0, 20, 15
	rotlwi	5, 20, 13
	xor	0, 0, 5
	srwi	5, 20, 10
	xor	0, 0, 5
	add	22, 22, 0
	add	22, 22, 31
	# Round 7
	rotlwi	0, 12, 26
	rotlwi	5, 12, 21
	xor	0, 0, 5
	rotlwi	5, 12, 7
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	lwz	0, 28(6)
	add	7, 7, 23
	add	7, 7, 0
	add	11, 11, 7
	rotlwi	0, 8, 30
	rotlwi	5, 8, 19
	xor	0, 0, 5
	rotlwi	5, 8, 10
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	# Calc new W[7]
	rotlwi	0, 24, 25
	rotlwi	5, 24, 14
	xor	0, 0, 5
	srwi	5, 24, 3
	xor	0, 0, 5
	add	23, 23, 0
	rotlwi	0, 21, 15
	rotlwi	5, 21, 13
	xor	0, 0, 5
	srwi	5, 21, 10
	xor	0, 0, 5
	add	23, 23, 0
	add	23, 23, 16
	# Round 8
	rotlwi	0, 11, 26
	rotlwi	5, 11, 21
	xor	0, 0, 5
	rotlwi	5, 11, 7
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	lwz	0, 32(6)
	add	15, 15, 24
	add	15, 15, 0
	add	10, 10, 15
	rotlwi	0, 7, 30
	rotlwi	5, 7, 19
	xor	0, 0, 5
	rotlwi	5, 7, 10
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	# Calc new W[8]
	rotlwi	0, 25, 25
	rotlwi	5, 25, 14
	xor	0, 0, 5
	srwi	5, 25, 3
	xor	0, 0, 5
	add	24, 24, 0
	rotlwi	0, 22, 15
	rotlwi	5, 22, 13
	xor	0, 0, 5
	srwi	5, 22, 10
	xor	0, 0, 5
	add	24, 24, 0
	add	24, 24, 17
	# Round 9
	rotlwi	0, 10, 26
	rotlwi	5, 10, 21
	xor	0, 0, 5
	rotlwi	5, 10, 7
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	lwz	0, 36(6)
	add	14, 14, 25
	add	14, 14, 0
	add	9, 9, 14
	rotlwi	0, 15, 30
	rotlwi	5, 15, 19
	xor	0, 0, 5
	rotlwi	5, 15, 10
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	# Calc new W[9]
	rotlwi	0, 26, 25
	rotlwi	5, 26, 14
	xor	0, 0, 5
	srwi	5, 26, 3
	xor	0, 0, 5
	add	25, 25, 0
	rotlwi	0, 23, 15
	rotlwi	5, 23, 13
	xor	0, 0, 5
	srwi	5, 23, 10
	xor	0, 0, 5
	add	25, 25, 0
	add	25, 25, 18
	# Round 10
	rotlwi	0, 9, 26
	rotlwi	5, 9, 21
	xor	0, 0, 5
	rotlwi	5, 9, 7
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	lwz	0, 40(6)
	add	12, 12, 26
	add	12, 12, 0
	add	8, 8, 12
	rotlwi	0, 14, 30
	rotlwi	5, 14, 19
	xor	0, 0, 5
	rotlwi	5, 14, 10
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	# Calc new W[10]
	rotlwi	0, 27, 25
	rotlwi	5, 27, 14
	xor	0, 0, 5
	srwi	5, 27, 3
	xor	0, 0, 5
	add	26, 26, 0
	rotlwi	0, 24, 15
	rotlwi	5, 24, 13
	xor	0, 0, 5
	srwi	5, 24, 10
	xor	0, 0, 5
	add	26, 26, 0
	add	26, 26, 19
	# Round 11
	rotlwi	0, 8, 26
	rotlwi	5, 8, 21
	xor	0, 0, 5
	rotlwi	5, 8, 7
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	lwz	0, 44(6)
	add	11, 11, 27
	add	11, 11, 0
	add	7, 7, 11
	rotlwi	0, 12, 30
	rotlwi	5, 12, 19
	xor	0, 0, 5
	rotlwi	5, 12, 10
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	# Calc new W[11]
	rotlwi	0, 28, 25
	rotlwi	5, 28, 14
	xor	0, 0, 5
	srwi	5, 28, 3
	xor	0, 0, 5
	add	27, 27, 0
	rotlwi	0, 25, 15
	rotlwi	5, 25, 13
	xor	0, 0, 5
	srwi	5, 25, 10
	xor	0, 0, 5
	add	27, 27, 0
	add	27, 27, 20
	# Round 12
	rotlwi	0, 7, 26
	rotlwi	5, 7, 21
	xor	0, 0, 5
	rotlwi	5, 7, 7
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	lwz	0, 48(6)
	add	10, 10, 28
	add	10, 10, 0
	add	15, 15, 10
	rotlwi	0, 11, 30
	rotlwi	5, 11, 19
	xor	0, 0, 5
	rotlwi	5, 11, 10
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	# Calc new W[12]
	rotlwi	0, 29, 25
	rotlwi	5, 29, 14
	xor	0, 0, 5
	srwi	5, 29, 3
	xor	0, 0, 5
	add	28, 28, 0
	rotlwi	0, 26, 15
	rotlwi	5, 26, 13
	xor	0, 0, 5
	srwi	5, 26, 10
	xor	0, 0, 5
	add	28, 28, 0
	add	28, 28, 21
	# Round 13
	rotlwi	0, 15, 26
	rotlwi	5, 15, 21
	xor	0, 0, 5
	rotlwi	5, 15, 7
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	lwz	0, 52(6)
	add	9, 9, 29
	add	9, 9, 0
	add	14, 14, 9
	rotlwi	0, 10, 30
	rotlwi	5, 10, 19
	xor	0, 0, 5
	rotlwi	5, 10, 10
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	# Calc new W[13]
	rotlwi	0, 30, 25
	rotlwi	5, 30, 14
	xor	0, 0, 5
	srwi	5, 30, 3
	xor	0, 0, 5
	add	29, 29, 0
	rotlwi	0, 27, 15
	rotlwi	5, 27, 13
	xor	0, 0, 5
	srwi	5, 27, 10
	xor	0, 0, 5
	add	29, 29, 0
	add	29, 29, 22
	# Round 14
	rotlwi	0, 14, 26
	rotlwi	5, 14, 21
	xor	0, 0, 5
	rotlwi	5, 14, 7
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	lwz	0, 56(6)
	add	8, 8, 30
	add	8, 8, 0
	add	12, 12, 8
	rotlwi	0, 9, 30
	rotlwi	5, 9, 19
	xor	0, 0, 5
	rotlwi	5, 9, 10
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	# Calc new W[14]
	rotlwi	0, 31, 25
	rotlwi	5, 31, 14
	xor	0, 0, 5
	srwi	5, 31, 3
	xor	0, 0, 5
	add	30, 30, 0
	rotlwi	0, 28, 15
	rotlwi	5, 28, 13
	xor	0, 0, 5
	srwi	5, 28, 10
	xor	0, 0, 5
	add	30, 30, 0
	add	30, 30, 23
	# Round 15
	rotlwi	0, 12, 26
	rotlwi	5, 12, 21
	xor	0, 0, 5
	rotlwi	5, 12, 7
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	lwz	0, 60(6)
	add	7, 7, 31
	add	7, 7, 0
	add	11, 11, 7
	rotlwi	0, 8, 30
	rotlwi	5, 8, 19
	xor	0, 0, 5
	rotlwi	5, 8, 10
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	# Calc new W[15]
	rotlwi	0, 16, 25
	rotlwi	5, 16, 14
	xor	0, 0, 5
	srwi	5, 16, 3
	xor	0, 0, 5
	add	31, 31, 0
	rotlwi	0, 29, 15
	rotlwi	5, 29, 13
	xor	0, 0, 5
	srwi	5, 29, 10
	xor	0, 0, 5
	add	31, 31, 0
	add	31, 31, 24
	addi	6, 6, 0x40
	# Round 0
	rotlwi	0, 11, 26
	rotlwi	5, 11, 21
	xor	0, 0, 5
	rotlwi	5, 11, 7
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	lwz	0, 0(6)
	add	15, 15, 16
	add	15, 15, 0
	add	10, 10, 15
	rotlwi	0, 7, 30
	rotlwi	5, 7, 19
	xor	0, 0, 5
	rotlwi	5, 7, 10
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	# Calc new W[0]
	rotlwi	0, 17, 25
	rotlwi	5, 17, 14
	xor	0, 0, 5
	srwi	5, 17, 3
	xor	0, 0, 5
	add	16, 16, 0
	rotlwi	0, 30, 15
	rotlwi	5, 30, 13
	xor	0, 0, 5
	srwi	5, 30, 10
	xor	0, 0, 5
	add	16, 16, 0
	add	16, 16, 25
	# Round 1
	rotlwi	0, 10, 26
	rotlwi	5, 10, 21
	xor	0, 0, 5
	rotlwi	5, 10, 7
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	lwz	0, 4(6)
	add	14, 14, 17
	add	14, 14, 0
	add	9, 9, 14
	rotlwi	0, 15, 30
	rotlwi	5, 15, 19
	xor	0, 0, 5
	rotlwi	5, 15, 10
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	# Calc new W[1]
	rotlwi	0, 18, 25
	rotlwi	5, 18, 14
	xor	0, 0, 5
	srwi	5, 18, 3
	xor	0, 0, 5
	add	17, 17, 0
	rotlwi	0, 31, 15
	rotlwi	5, 31, 13
	xor	0, 0, 5
	srwi	5, 31, 10
	xor	0, 0, 5
	add	17, 17, 0
	add	17, 17, 26
	# Round 2
	rotlwi	0, 9, 26
	rotlwi	5, 9, 21
	xor	0, 0, 5
	rotlwi	5, 9, 7
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	lwz	0, 8(6)
	add	12, 12, 18
	add	12, 12, 0
	add	8, 8, 12
	rotlwi	0, 14, 30
	rotlwi	5, 14, 19
	xor	0, 0, 5
	rotlwi	5, 14, 10
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	# Calc new W[2]
	rotlwi	0, 19, 25
	rotlwi	5, 19, 14
	xor	0, 0, 5
	srwi	5, 19, 3
	xor	0, 0, 5
	add	18, 18, 0
	rotlwi	0, 16, 15
	rotlwi	5, 16, 13
	xor	0, 0, 5
	srwi	5, 16, 10
	xor	0, 0, 5
	add	18, 18, 0
	add	18, 18, 27
	# Round 3
	rotlwi	0, 8, 26
	rotlwi	5, 8, 21
	xor	0, 0, 5
	rotlwi	5, 8, 7
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	lwz	0, 12(6)
	add	11, 11, 19
	add	11, 11, 0
	add	7, 7, 11
	rotlwi	0, 12, 30
	rotlwi	5, 12, 19
	xor	0, 0, 5
	rotlwi	5, 12, 10
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	# Calc new W[3]
	rotlwi	0, 20, 25
	rotlwi	5, 20, 14
	xor	0, 0, 5
	srwi	5, 20, 3
	xor	0, 0, 5
	add	19, 19, 0
	rotlwi	0, 17, 15
	rotlwi	5, 17, 13
	xor	0, 0, 5
	srwi	5, 17, 10
	xor	0, 0, 5
	add	19, 19, 0
	add	19, 19, 28
	# Round 4
	rotlwi	0, 7, 26
	rotlwi	5, 7, 21
	xor	0, 0, 5
	rotlwi	5, 7, 7
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	lwz	0, 16(6)
	add	10, 10, 20
	add	10, 10, 0
	add	15, 15, 10
	rotlwi	0, 11, 30
	rotlwi	5, 11, 19
	xor	0, 0, 5
	rotlwi	5, 11, 10
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	# Calc new W[4]
	rotlwi	0, 21, 25
	rotlwi	5, 21, 14
	xor	0, 0, 5
	srwi	5, 21, 3
	xor	0, 0, 5
	add	20, 20, 0
	rotlwi	0, 18, 15
	rotlwi	5, 18, 13
	xor	0, 0, 5
	srwi	5, 18, 10
	xor	0, 0, 5
	add	20, 20, 0
	add	20, 20, 29
	# Round 5
	rotlwi	0, 15, 26
	rotlwi	5, 15, 21
	xor	0, 0, 5
	rotlwi	5, 15, 7
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	lwz	0, 20(6)
	add	9, 9, 21
	add	9, 9, 0
	add	14, 14, 9
	rotlwi	0, 10, 30
	rotlwi	5, 10, 19
	xor	0, 0, 5
	rotlwi	5, 10, 10
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	# Calc new W[5]
	rotlwi	0, 22, 25
	rotlwi	5, 22, 14
	xor	0, 0, 5
	srwi	5, 22, 3
	xor	0, 0, 5
	add	21, 21, 0
	rotlwi	0, 19, 15
	rotlwi	5, 19, 13
	xor	0, 0, 5
	srwi	5, 19, 10
	xor	0, 0, 5
	add	21, 21, 0
	add	21, 21, 30
	# Round 6
	rotlwi	0, 14, 26
	rotlwi	5, 14, 21
	xor	0, 0, 5
	rotlwi	5, 14, 7
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	lwz	0, 24(6)
	add	8, 8, 22
	add	8, 8, 0
	add	12, 12, 8
	rotlwi	0, 9, 30
	rotlwi	5, 9, 19
	xor	0, 0, 5
	rotlwi	5, 9, 10
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	# Calc new W[6]
	rotlwi	0, 23, 25
	rotlwi	5, 23, 14
	xor	0, 0, 5
	srwi	5, 23, 3
	xor	0, 0, 5
	add	22, 22, 0
	rotlwi	0, 20, 15
	rotlwi	5, 20, 13
	xor	0, 0, 5
	srwi	5, 20, 10
	xor	0, 0, 5
	add	22, 22, 0
	add	22, 22, 31
	# Round 7
	rotlwi	0, 12, 26
	rotlwi	5, 12, 21
	xor	0, 0, 5
	rotlwi	5, 12, 7
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	lwz	0, 28(6)
	add	7, 7, 23
	add	7, 7, 0
	add	11, 11, 7
	rotlwi	0, 8, 30
	rotlwi	5, 8, 19
	xor	0, 0, 5
	rotlwi	5, 8, 10
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	# Calc new W[7]
	rotlwi	0, 24, 25
	rotlwi	5, 24, 14
	xor	0, 0, 5
	srwi	5, 24, 3
	xor	0, 0, 5
	add	23, 23, 0
	rotlwi	0, 21, 15
	rotlwi	5, 21, 13
	xor	0, 0, 5
	srwi	5, 21, 10
	xor	0, 0, 5
	add	23, 23, 0
	add	23, 23, 16
	# Round 8
	rotlwi	0, 11, 26
	rotlwi	5, 11, 21
	xor	0, 0, 5
	rotlwi	5, 11, 7
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	lwz	0, 32(6)
	add	15, 15, 24
	add	15, 15, 0
	add	10, 10, 15
	rotlwi	0, 7, 30
	rotlwi	5, 7, 19
	xor	0, 0, 5
	rotlwi	5, 7, 10
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	# Calc new W[8]
	rotlwi	0, 25, 25
	rotlwi	5, 25, 14
	xor	0, 0, 5
	srwi	5, 25, 3
	xor	0, 0, 5
	add	24, 24, 0
	rotlwi	0, 22, 15
	rotlwi	5, 22, 13
	xor	0, 0, 5
	srwi	5, 22, 10
	xor	0, 0, 5
	add	24, 24, 0
	add	24, 24, 17
	# Round 9
	rotlwi	0, 10, 26
	rotlwi	5, 10, 21
	xor	0, 0, 5
	rotlwi	5, 10, 7
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	lwz	0, 36(6)
	add	14, 14, 25
	add	14, 14, 0
	add	9, 9, 14
	rotlwi	0, 15, 30
	rotlwi	5, 15, 19
	xor	0, 0, 5
	rotlwi	5, 15, 10
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	# Calc new W[9]
	rotlwi	0, 26, 25
	rotlwi	5, 26, 14
	xor	0, 0, 5
	srwi	5, 26, 3
	xor	0, 0, 5
	add	25, 25, 0
	rotlwi	0, 23, 15
	rotlwi	5, 23, 13
	xor	0, 0, 5
	srwi	5, 23, 10
	xor	0, 0, 5
	add	25, 25, 0
	add	25, 25, 18
	# Round 10
	rotlwi	0, 9, 26
	rotlwi	5, 9, 21
	xor	0, 0, 5
	rotlwi	5, 9, 7
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	lwz	0, 40(6)
	add	12, 12, 26
	add	12, 12, 0
	add	8, 8, 12
	rotlwi	0, 14, 30
	rotlwi	5, 14, 19
	xor	0, 0, 5
	rotlwi	5, 14, 10
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	# Calc new W[10]
	rotlwi	0, 27, 25
	rotlwi	5, 27, 14
	xor	0, 0, 5
	srwi	5, 27, 3
	xor	0, 0, 5
	add	26, 26, 0
	rotlwi	0, 24, 15
	rotlwi	5, 24, 13
	xor	0, 0, 5
	srwi	5, 24, 10
	xor	0, 0, 5
	add	26, 26, 0
	add	26, 26, 19
	# Round 11
	rotlwi	0, 8, 26
	rotlwi	5, 8, 21
	xor	0, 0, 5
	rotlwi	5, 8, 7
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	lwz	0, 44(6)
	add	11, 11, 27
	add	11, 11, 0
	add	7, 7, 11
	rotlwi	0, 12, 30
	rotlwi	5, 12, 19
	xor	0, 0, 5
	rotlwi	5, 12, 10
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	# Calc new W[11]
	rotlwi	0, 28, 25
	rotlwi	5, 28, 14
	xor	0, 0, 5
	srwi	5, 28, 3
	xor	0, 0, 5
	add	27, 27, 0
	rotlwi	0, 25, 15
	rotlwi	5, 25, 13
	xor	0, 0, 5
	srwi	5, 25, 10
	xor	0, 0, 5
	add	27, 27, 0
	add	27, 27, 20
	# Round 12
	rotlwi	0, 7, 26
	rotlwi	5, 7, 21
	xor	0, 0, 5
	rotlwi	5, 7, 7
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	lwz	0, 48(6)
	add	10, 10, 28
	add	10, 10, 0
	add	15, 15, 10
	rotlwi	0, 11, 30
	rotlwi	5, 11, 19
	xor	0, 0, 5
	rotlwi	5, 11, 10
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	# Calc new W[12]
	rotlwi	0, 29, 25
	rotlwi	5, 29, 14
	xor	0, 0, 5
	srwi	5, 29, 3
	xor	0, 0, 5
	add	28, 28, 0
	rotlwi	0, 26, 15
	rotlwi	5, 26, 13
	xor	0, 0, 5
	srwi	5, 26, 10
	xor	0, 0, 5
	add	28, 28, 0
	add	28, 28, 21
	# Round 13
	rotlwi	0, 15, 26
	rotlwi	5, 15, 21
	xor	0, 0, 5
	rotlwi	5, 15, 7
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	lwz	0, 52(6)
	add	9, 9, 29
	add	9, 9, 0
	add	14, 14, 9
	rotlwi	0, 10, 30
	rotlwi	5, 10, 19
	xor	0, 0, 5
	rotlwi	5, 10, 10
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	# Calc new W[13]
	rotlwi	0, 30, 25
	rotlwi	5, 30, 14
	xor	0, 0, 5
	srwi	5, 30, 3
	xor	0, 0, 5
	add	29, 29, 0
	rotlwi	0, 27, 15
	rotlwi	5, 27, 13
	xor	0, 0, 5
	srwi	5, 27, 10
	xor	0, 0, 5
	add	29, 29, 0
	add	29, 29, 22
	# Round 14
	rotlwi	0, 14, 26
	rotlwi	5, 14, 21
	xor	0, 0, 5
	rotlwi	5, 14, 7
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	lwz	0, 56(6)
	add	8, 8, 30
	add	8, 8, 0
	add	12, 12, 8
	rotlwi	0, 9, 30
	rotlwi	5, 9, 19
	xor	0, 0, 5
	rotlwi	5, 9, 10
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	# Calc new W[14]
	rotlwi	0, 31, 25
	rotlwi	5, 31, 14
	xor	0, 0, 5
	srwi	5, 31, 3
	xor	0, 0, 5
	add	30, 30, 0
	rotlwi	0, 28, 15
	rotlwi	5, 28, 13
	xor	0, 0, 5
	srwi	5, 28, 10
	xor	0, 0, 5
	add	30, 30, 0
	add	30, 30, 23
	# Round 15
	rotlwi	0, 12, 26
	rotlwi	5, 12, 21
	xor	0, 0, 5
	rotlwi	5, 12, 7
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	lwz	0, 60(6)
	add	7, 7, 31
	add	7, 7, 0
	add	11, 11, 7
	rotlwi	0, 8, 30
	rotlwi	5, 8, 19
	xor	0, 0, 5
	rotlwi	5, 8, 10
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	# Calc new W[15]
	rotlwi	0, 16, 25
	rotlwi	5, 16, 14
	xor	0, 0, 5
	srwi	5, 16, 3
	xor	0, 0, 5
	add	31, 31, 0
	rotlwi	0, 29, 15
	rotlwi	5, 29, 13
	xor	0, 0, 5
	srwi	5, 29, 10
	xor	0, 0, 5
	add	31, 31, 0
	add	31, 31, 24
	addi	6, 6, 0x40
	# Round 0
	rotlwi	0, 11, 26
	rotlwi	5, 11, 21
	xor	0, 0, 5
	rotlwi	5, 11, 7
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	lwz	0, 0(6)
	add	15, 15, 16
	add	15, 15, 0
	add	10, 10, 15
	rotlwi	0, 7, 30
	rotlwi	5, 7, 19
	xor	0, 0, 5
	rotlwi	5, 7, 10
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	# Round 1
	rotlwi	0, 10, 26
	rotlwi	5, 10, 21
	xor	0, 0, 5
	rotlwi	5, 10, 7
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	lwz	0, 4(6)
	add	14, 14, 17
	add	14, 14, 0
	add	9, 9, 14
	rotlwi	0, 15, 30
	rotlwi	5, 15, 19
	xor	0, 0, 5
	rotlwi	5, 15, 10
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	# Round 2
	rotlwi	0, 9, 26
	rotlwi	5, 9, 21
	xor	0, 0, 5
	rotlwi	5, 9, 7
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	lwz	0, 8(6)
	add	12, 12, 18
	add	12, 12, 0
	add	8, 8, 12
	rotlwi	0, 14, 30
	rotlwi	5, 14, 19
	xor	0, 0, 5
	rotlwi	5, 14, 10
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	# Round 3
	rotlwi	0, 8, 26
	rotlwi	5, 8, 21
	xor	0, 0, 5
	rotlwi	5, 8, 7
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	lwz	0, 12(6)
	add	11, 11, 19
	add	11, 11, 0
	add	7, 7, 11
	rotlwi	0, 12, 30
	rotlwi	5, 12, 19
	xor	0, 0, 5
	rotlwi	5, 12, 10
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	# Round 4
	rotlwi	0, 7, 26
	rotlwi	5, 7, 21
	xor	0, 0, 5
	rotlwi	5, 7, 7
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	lwz	0, 16(6)
	add	10, 10, 20
	add	10, 10, 0
	add	15, 15, 10
	rotlwi	0, 11, 30
	rotlwi	5, 11, 19
	xor	0, 0, 5
	rotlwi	5, 11, 10
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	# Round 5
	rotlwi	0, 15, 26
	rotlwi	5, 15, 21
	xor	0, 0, 5
	rotlwi	5, 15, 7
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	lwz	0, 20(6)
	add	9, 9, 21
	add	9, 9, 0
	add	14, 14, 9
	rotlwi	0, 10, 30
	rotlwi	5, 10, 19
	xor	0, 0, 5
	rotlwi	5, 10, 10
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	# Round 6
	rotlwi	0, 14, 26
	rotlwi	5, 14, 21
	xor	0, 0, 5
	rotlwi	5, 14, 7
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	lwz	0, 24(6)
	add	8, 8, 22
	add	8, 8, 0
	add	12, 12, 8
	rotlwi	0, 9, 30
	rotlwi	5, 9, 19
	xor	0, 0, 5
	rotlwi	5, 9, 10
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	# Round 7
	rotlwi	0, 12, 26
	rotlwi	5, 12, 21
	xor	0, 0, 5
	rotlwi	5, 12, 7
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	lwz	0, 28(6)
	add	7, 7, 23
	add	7, 7, 0
	add	11, 11, 7
	rotlwi	0, 8, 30
	rotlwi	5, 8, 19
	xor	0, 0, 5
	rotlwi	5, 8, 10
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	# Round 8
	rotlwi	0, 11, 26
	rotlwi	5, 11, 21
	xor	0, 0, 5
	rotlwi	5, 11, 7
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	lwz	0, 32(6)
	add	15, 15, 24
	add	15, 15, 0
	add	10, 10, 15
	rotlwi	0, 7, 30
	rotlwi	5, 7, 19
	xor	0, 0, 5
	rotlwi	5, 7, 10
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	# Round 9
	rotlwi	0, 10, 26
	rotlwi	5, 10, 21
	xor	0, 0, 5
	rotlwi	5, 10, 7
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	lwz	0, 36(6)
	add	14, 14, 25
	add	14, 14, 0
	add	9, 9, 14
	rotlwi	0, 15, 30
	rotlwi	5, 15, 19
	xor	0, 0, 5
	rotlwi	5, 15, 10
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	# Round 10
	rotlwi	0, 9, 26
	rotlwi	5, 9, 21
	xor	0, 0, 5
	rotlwi	5, 9, 7
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	lwz	0, 40(6)
	add	12, 12, 26
	add	12, 12, 0
	add	8, 8, 12
	rotlwi	0, 14, 30
	rotlwi	5, 14, 19
	xor	0, 0, 5
	rotlwi	5, 14, 10
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	# Round 11
	rotlwi	0, 8, 26
	rotlwi	5, 8, 21
	xor	0, 0, 5
	rotlwi	5, 8, 7
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	lwz	0, 44(6)
	add	11, 11, 27
	add	11, 11, 0
	add	7, 7, 11
	rotlwi	0, 12, 30
	rotlwi	5, 12, 19
	xor	0, 0, 5
	rotlwi	5, 12, 10
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	# Round 12
	rotlwi	0, 7, 26
	rotlwi	5, 7, 21
	xor	0, 0, 5
	rotlwi	5, 7, 7
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	lwz	0, 48(6)
	add	10, 10, 28
	add	10, 10, 0
	add	15, 15, 10
	rotlwi	0, 11, 30
	rotlwi	5, 11, 19
	xor	0, 0, 5
	rotlwi	5, 11, 10
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	# Round 13
	rotlwi	0, 15, 26
	rotlwi	5, 15, 21
	xor	0, 0, 5
	rotlwi	5, 15, 7
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	lwz	0, 52(6)
	add	9, 9, 29
	add	9, 9, 0
	add	14, 14, 9
	rotlwi	0, 10, 30
	rotlwi	5, 10, 19
	xor	0, 0, 5
	rotlwi	5, 10, 10
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	# Round 14
	rotlwi	0, 14, 26
	rotlwi	5, 14, 21
	xor	0, 0, 5
	rotlwi	5, 14, 7
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	lwz	0, 56(6)
	add	8, 8, 30
	add	8, 8, 0
	add	12, 12, 8
	rotlwi	0, 9, 30
	rotlwi	5, 9, 19
	xor	0, 0, 5
	rotlwi	5, 9, 10
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	# Round 15
	rotlwi	0, 12, 26
	rotlwi	5, 12, 21
	xor	0, 0, 5
	rotlwi	5, 12, 7
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	lwz	0, 60(6)
	add	7, 7, 31
	add	7, 7, 0
	add	11, 11, 7
	rotlwi	0, 8, 30
	rotlwi	5, 8, 19
	xor	0, 0, 5
	rotlwi	5, 8, 10
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	subi	6, 6, 0xc0
	# Add in digest from start
	lwz	0, 0(3)
	lwz	5, 4(3)
	add	7, 7, 0
	add	8, 8, 5
	lwz	0, 8(3)
	lwz	5, 12(3)
	add	9, 9, 0
	add	10, 10, 5
	lwz	0, 16(3)
	lwz	5, 20(3)
	add	11, 11, 0
	add	12, 12, 5
	lwz	0, 24(3)
	lwz	5, 28(3)
	add	14, 14, 0
	add	15, 15, 5
	stw	7, 0(3)
	stw	8, 4(3)
	stw	9, 8(3)
	stw	10, 12(3)
	stw	11, 16(3)
	stw	12, 20(3)
	stw	14, 24(3)
	stw	15, 28(3)
	addi	4, 4, 0x40
	bdnz	L_SHA256_transform_len_begin
#else
	subi	1, 1, 16
	stw	5, 0(1)
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
	li	0, 4
	mtctr	0
	# Start of 16 rounds
L_SHA256_transform_len_start:
	# Round 0
	rotlwi	0, 11, 26
	rotlwi	5, 11, 21
	xor	0, 0, 5
	rotlwi	5, 11, 7
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	lwz	0, 0(6)
	add	15, 15, 16
	add	15, 15, 0
	add	10, 10, 15
	rotlwi	0, 7, 30
	rotlwi	5, 7, 19
	xor	0, 0, 5
	rotlwi	5, 7, 10
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA256_transform_len_after_blk_0
	# Calc new W[0]
	rotlwi	0, 17, 25
	rotlwi	5, 17, 14
	xor	0, 0, 5
	srwi	5, 17, 3
	xor	0, 0, 5
	add	16, 16, 0
	rotlwi	0, 30, 15
	rotlwi	5, 30, 13
	xor	0, 0, 5
	srwi	5, 30, 10
	xor	0, 0, 5
	add	16, 16, 0
	add	16, 16, 25
L_SHA256_transform_len_after_blk_0:
	# Round 1
	rotlwi	0, 10, 26
	rotlwi	5, 10, 21
	xor	0, 0, 5
	rotlwi	5, 10, 7
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	lwz	0, 4(6)
	add	14, 14, 17
	add	14, 14, 0
	add	9, 9, 14
	rotlwi	0, 15, 30
	rotlwi	5, 15, 19
	xor	0, 0, 5
	rotlwi	5, 15, 10
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA256_transform_len_after_blk_1
	# Calc new W[1]
	rotlwi	0, 18, 25
	rotlwi	5, 18, 14
	xor	0, 0, 5
	srwi	5, 18, 3
	xor	0, 0, 5
	add	17, 17, 0
	rotlwi	0, 31, 15
	rotlwi	5, 31, 13
	xor	0, 0, 5
	srwi	5, 31, 10
	xor	0, 0, 5
	add	17, 17, 0
	add	17, 17, 26
L_SHA256_transform_len_after_blk_1:
	# Round 2
	rotlwi	0, 9, 26
	rotlwi	5, 9, 21
	xor	0, 0, 5
	rotlwi	5, 9, 7
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	lwz	0, 8(6)
	add	12, 12, 18
	add	12, 12, 0
	add	8, 8, 12
	rotlwi	0, 14, 30
	rotlwi	5, 14, 19
	xor	0, 0, 5
	rotlwi	5, 14, 10
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA256_transform_len_after_blk_2
	# Calc new W[2]
	rotlwi	0, 19, 25
	rotlwi	5, 19, 14
	xor	0, 0, 5
	srwi	5, 19, 3
	xor	0, 0, 5
	add	18, 18, 0
	rotlwi	0, 16, 15
	rotlwi	5, 16, 13
	xor	0, 0, 5
	srwi	5, 16, 10
	xor	0, 0, 5
	add	18, 18, 0
	add	18, 18, 27
L_SHA256_transform_len_after_blk_2:
	# Round 3
	rotlwi	0, 8, 26
	rotlwi	5, 8, 21
	xor	0, 0, 5
	rotlwi	5, 8, 7
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	lwz	0, 12(6)
	add	11, 11, 19
	add	11, 11, 0
	add	7, 7, 11
	rotlwi	0, 12, 30
	rotlwi	5, 12, 19
	xor	0, 0, 5
	rotlwi	5, 12, 10
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA256_transform_len_after_blk_3
	# Calc new W[3]
	rotlwi	0, 20, 25
	rotlwi	5, 20, 14
	xor	0, 0, 5
	srwi	5, 20, 3
	xor	0, 0, 5
	add	19, 19, 0
	rotlwi	0, 17, 15
	rotlwi	5, 17, 13
	xor	0, 0, 5
	srwi	5, 17, 10
	xor	0, 0, 5
	add	19, 19, 0
	add	19, 19, 28
L_SHA256_transform_len_after_blk_3:
	# Round 4
	rotlwi	0, 7, 26
	rotlwi	5, 7, 21
	xor	0, 0, 5
	rotlwi	5, 7, 7
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	lwz	0, 16(6)
	add	10, 10, 20
	add	10, 10, 0
	add	15, 15, 10
	rotlwi	0, 11, 30
	rotlwi	5, 11, 19
	xor	0, 0, 5
	rotlwi	5, 11, 10
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA256_transform_len_after_blk_4
	# Calc new W[4]
	rotlwi	0, 21, 25
	rotlwi	5, 21, 14
	xor	0, 0, 5
	srwi	5, 21, 3
	xor	0, 0, 5
	add	20, 20, 0
	rotlwi	0, 18, 15
	rotlwi	5, 18, 13
	xor	0, 0, 5
	srwi	5, 18, 10
	xor	0, 0, 5
	add	20, 20, 0
	add	20, 20, 29
L_SHA256_transform_len_after_blk_4:
	# Round 5
	rotlwi	0, 15, 26
	rotlwi	5, 15, 21
	xor	0, 0, 5
	rotlwi	5, 15, 7
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	lwz	0, 20(6)
	add	9, 9, 21
	add	9, 9, 0
	add	14, 14, 9
	rotlwi	0, 10, 30
	rotlwi	5, 10, 19
	xor	0, 0, 5
	rotlwi	5, 10, 10
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA256_transform_len_after_blk_5
	# Calc new W[5]
	rotlwi	0, 22, 25
	rotlwi	5, 22, 14
	xor	0, 0, 5
	srwi	5, 22, 3
	xor	0, 0, 5
	add	21, 21, 0
	rotlwi	0, 19, 15
	rotlwi	5, 19, 13
	xor	0, 0, 5
	srwi	5, 19, 10
	xor	0, 0, 5
	add	21, 21, 0
	add	21, 21, 30
L_SHA256_transform_len_after_blk_5:
	# Round 6
	rotlwi	0, 14, 26
	rotlwi	5, 14, 21
	xor	0, 0, 5
	rotlwi	5, 14, 7
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	lwz	0, 24(6)
	add	8, 8, 22
	add	8, 8, 0
	add	12, 12, 8
	rotlwi	0, 9, 30
	rotlwi	5, 9, 19
	xor	0, 0, 5
	rotlwi	5, 9, 10
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA256_transform_len_after_blk_6
	# Calc new W[6]
	rotlwi	0, 23, 25
	rotlwi	5, 23, 14
	xor	0, 0, 5
	srwi	5, 23, 3
	xor	0, 0, 5
	add	22, 22, 0
	rotlwi	0, 20, 15
	rotlwi	5, 20, 13
	xor	0, 0, 5
	srwi	5, 20, 10
	xor	0, 0, 5
	add	22, 22, 0
	add	22, 22, 31
L_SHA256_transform_len_after_blk_6:
	# Round 7
	rotlwi	0, 12, 26
	rotlwi	5, 12, 21
	xor	0, 0, 5
	rotlwi	5, 12, 7
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	lwz	0, 28(6)
	add	7, 7, 23
	add	7, 7, 0
	add	11, 11, 7
	rotlwi	0, 8, 30
	rotlwi	5, 8, 19
	xor	0, 0, 5
	rotlwi	5, 8, 10
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA256_transform_len_after_blk_7
	# Calc new W[7]
	rotlwi	0, 24, 25
	rotlwi	5, 24, 14
	xor	0, 0, 5
	srwi	5, 24, 3
	xor	0, 0, 5
	add	23, 23, 0
	rotlwi	0, 21, 15
	rotlwi	5, 21, 13
	xor	0, 0, 5
	srwi	5, 21, 10
	xor	0, 0, 5
	add	23, 23, 0
	add	23, 23, 16
L_SHA256_transform_len_after_blk_7:
	# Round 8
	rotlwi	0, 11, 26
	rotlwi	5, 11, 21
	xor	0, 0, 5
	rotlwi	5, 11, 7
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	lwz	0, 32(6)
	add	15, 15, 24
	add	15, 15, 0
	add	10, 10, 15
	rotlwi	0, 7, 30
	rotlwi	5, 7, 19
	xor	0, 0, 5
	rotlwi	5, 7, 10
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA256_transform_len_after_blk_8
	# Calc new W[8]
	rotlwi	0, 25, 25
	rotlwi	5, 25, 14
	xor	0, 0, 5
	srwi	5, 25, 3
	xor	0, 0, 5
	add	24, 24, 0
	rotlwi	0, 22, 15
	rotlwi	5, 22, 13
	xor	0, 0, 5
	srwi	5, 22, 10
	xor	0, 0, 5
	add	24, 24, 0
	add	24, 24, 17
L_SHA256_transform_len_after_blk_8:
	# Round 9
	rotlwi	0, 10, 26
	rotlwi	5, 10, 21
	xor	0, 0, 5
	rotlwi	5, 10, 7
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	lwz	0, 36(6)
	add	14, 14, 25
	add	14, 14, 0
	add	9, 9, 14
	rotlwi	0, 15, 30
	rotlwi	5, 15, 19
	xor	0, 0, 5
	rotlwi	5, 15, 10
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA256_transform_len_after_blk_9
	# Calc new W[9]
	rotlwi	0, 26, 25
	rotlwi	5, 26, 14
	xor	0, 0, 5
	srwi	5, 26, 3
	xor	0, 0, 5
	add	25, 25, 0
	rotlwi	0, 23, 15
	rotlwi	5, 23, 13
	xor	0, 0, 5
	srwi	5, 23, 10
	xor	0, 0, 5
	add	25, 25, 0
	add	25, 25, 18
L_SHA256_transform_len_after_blk_9:
	# Round 10
	rotlwi	0, 9, 26
	rotlwi	5, 9, 21
	xor	0, 0, 5
	rotlwi	5, 9, 7
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	lwz	0, 40(6)
	add	12, 12, 26
	add	12, 12, 0
	add	8, 8, 12
	rotlwi	0, 14, 30
	rotlwi	5, 14, 19
	xor	0, 0, 5
	rotlwi	5, 14, 10
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA256_transform_len_after_blk_10
	# Calc new W[10]
	rotlwi	0, 27, 25
	rotlwi	5, 27, 14
	xor	0, 0, 5
	srwi	5, 27, 3
	xor	0, 0, 5
	add	26, 26, 0
	rotlwi	0, 24, 15
	rotlwi	5, 24, 13
	xor	0, 0, 5
	srwi	5, 24, 10
	xor	0, 0, 5
	add	26, 26, 0
	add	26, 26, 19
L_SHA256_transform_len_after_blk_10:
	# Round 11
	rotlwi	0, 8, 26
	rotlwi	5, 8, 21
	xor	0, 0, 5
	rotlwi	5, 8, 7
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	lwz	0, 44(6)
	add	11, 11, 27
	add	11, 11, 0
	add	7, 7, 11
	rotlwi	0, 12, 30
	rotlwi	5, 12, 19
	xor	0, 0, 5
	rotlwi	5, 12, 10
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA256_transform_len_after_blk_11
	# Calc new W[11]
	rotlwi	0, 28, 25
	rotlwi	5, 28, 14
	xor	0, 0, 5
	srwi	5, 28, 3
	xor	0, 0, 5
	add	27, 27, 0
	rotlwi	0, 25, 15
	rotlwi	5, 25, 13
	xor	0, 0, 5
	srwi	5, 25, 10
	xor	0, 0, 5
	add	27, 27, 0
	add	27, 27, 20
L_SHA256_transform_len_after_blk_11:
	# Round 12
	rotlwi	0, 7, 26
	rotlwi	5, 7, 21
	xor	0, 0, 5
	rotlwi	5, 7, 7
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	lwz	0, 48(6)
	add	10, 10, 28
	add	10, 10, 0
	add	15, 15, 10
	rotlwi	0, 11, 30
	rotlwi	5, 11, 19
	xor	0, 0, 5
	rotlwi	5, 11, 10
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA256_transform_len_after_blk_12
	# Calc new W[12]
	rotlwi	0, 29, 25
	rotlwi	5, 29, 14
	xor	0, 0, 5
	srwi	5, 29, 3
	xor	0, 0, 5
	add	28, 28, 0
	rotlwi	0, 26, 15
	rotlwi	5, 26, 13
	xor	0, 0, 5
	srwi	5, 26, 10
	xor	0, 0, 5
	add	28, 28, 0
	add	28, 28, 21
L_SHA256_transform_len_after_blk_12:
	# Round 13
	rotlwi	0, 15, 26
	rotlwi	5, 15, 21
	xor	0, 0, 5
	rotlwi	5, 15, 7
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	lwz	0, 52(6)
	add	9, 9, 29
	add	9, 9, 0
	add	14, 14, 9
	rotlwi	0, 10, 30
	rotlwi	5, 10, 19
	xor	0, 0, 5
	rotlwi	5, 10, 10
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA256_transform_len_after_blk_13
	# Calc new W[13]
	rotlwi	0, 30, 25
	rotlwi	5, 30, 14
	xor	0, 0, 5
	srwi	5, 30, 3
	xor	0, 0, 5
	add	29, 29, 0
	rotlwi	0, 27, 15
	rotlwi	5, 27, 13
	xor	0, 0, 5
	srwi	5, 27, 10
	xor	0, 0, 5
	add	29, 29, 0
	add	29, 29, 22
L_SHA256_transform_len_after_blk_13:
	# Round 14
	rotlwi	0, 14, 26
	rotlwi	5, 14, 21
	xor	0, 0, 5
	rotlwi	5, 14, 7
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	lwz	0, 56(6)
	add	8, 8, 30
	add	8, 8, 0
	add	12, 12, 8
	rotlwi	0, 9, 30
	rotlwi	5, 9, 19
	xor	0, 0, 5
	rotlwi	5, 9, 10
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA256_transform_len_after_blk_14
	# Calc new W[14]
	rotlwi	0, 31, 25
	rotlwi	5, 31, 14
	xor	0, 0, 5
	srwi	5, 31, 3
	xor	0, 0, 5
	add	30, 30, 0
	rotlwi	0, 28, 15
	rotlwi	5, 28, 13
	xor	0, 0, 5
	srwi	5, 28, 10
	xor	0, 0, 5
	add	30, 30, 0
	add	30, 30, 23
L_SHA256_transform_len_after_blk_14:
	# Round 15
	rotlwi	0, 12, 26
	rotlwi	5, 12, 21
	xor	0, 0, 5
	rotlwi	5, 12, 7
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	lwz	0, 60(6)
	add	7, 7, 31
	add	7, 7, 0
	add	11, 11, 7
	rotlwi	0, 8, 30
	rotlwi	5, 8, 19
	xor	0, 0, 5
	rotlwi	5, 8, 10
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA256_transform_len_after_blk_15
	# Calc new W[15]
	rotlwi	0, 16, 25
	rotlwi	5, 16, 14
	xor	0, 0, 5
	srwi	5, 16, 3
	xor	0, 0, 5
	add	31, 31, 0
	rotlwi	0, 29, 15
	rotlwi	5, 29, 13
	xor	0, 0, 5
	srwi	5, 29, 10
	xor	0, 0, 5
	add	31, 31, 0
	add	31, 31, 24
L_SHA256_transform_len_after_blk_15:
	addi	6, 6, 0x40
	bdnz	L_SHA256_transform_len_start
	subi	6, 6, 0x100
	# Add in digest from start
	lwz	0, 0(3)
	lwz	5, 4(3)
	add	7, 7, 0
	add	8, 8, 5
	lwz	0, 8(3)
	lwz	5, 12(3)
	add	9, 9, 0
	add	10, 10, 5
	lwz	0, 16(3)
	lwz	5, 20(3)
	add	11, 11, 0
	add	12, 12, 5
	lwz	0, 24(3)
	lwz	5, 28(3)
	add	14, 14, 0
	add	15, 15, 5
	stw	7, 0(3)
	stw	8, 4(3)
	stw	9, 8(3)
	stw	10, 12(3)
	stw	11, 16(3)
	stw	12, 20(3)
	stw	14, 24(3)
	stw	15, 28(3)
	lwz	5, 0(1)
	mtctr	5
	subi	5, 5, 1
	addi	4, 4, 0x40
	stw	5, 0(1)
	bdnz	L_SHA256_transform_len_begin
	addi	1, 1, 16
#endif /* WOLFSSL_PPC64_ASM_SMALL */
	ld	0, 144(1)
	mtlr	0
	ld	14, 0(1)
	ld	15, 8(1)
	ld	16, 16(1)
	ld	17, 24(1)
	ld	18, 32(1)
	ld	19, 40(1)
	ld	20, 48(1)
	ld	21, 56(1)
	ld	22, 64(1)
	ld	23, 72(1)
	ld	24, 80(1)
	ld	25, 88(1)
	ld	26, 96(1)
	ld	27, 104(1)
	ld	28, 112(1)
	ld	29, 120(1)
	ld	30, 128(1)
	ld	31, 136(1)
	addi	1, 1, 0x98
	blr
#ifndef __APPLE__
	.size	Transform_Sha256_Len,.-Transform_Sha256_Len
#endif /* __APPLE__ */
#ifdef WOLFSSL_PPC64_ASM_CRYPTO
#ifndef __APPLE__
	.text
	.type	L_SHA256_crypto_k, %object
	.size	L_SHA256_crypto_k, 272
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_SHA256_crypto_k:
	.long	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5
	.long	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5
	.long	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3
	.long	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174
	.long	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc
	.long	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da
	.long	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7
	.long	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967
	.long	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13
	.long	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85
	.long	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3
	.long	0xd192e819,0xd6990624,0xf40e3585,0x106aa070
	.long	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5
	.long	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3
	.long	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208
	.long	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	.long	0x00000000,0x00000000,0x00000000,0x00000000
	.machine	"push"
	.machine	"power8"
#ifndef __APPLE__
.text
.globl	Transform_Sha256_Len_crypto
.type	Transform_Sha256_Len_crypto,@function
.align	16
Transform_Sha256_Len_crypto:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	Transform_Sha256_Len_crypto, .-Transform_Sha256_Len_crypto
#endif
#else
.section	__TEXT,__text
.globl	_Transform_Sha256_Len_crypto
.p2align	4
_Transform_Sha256_Len_crypto:
#endif /* __APPLE__ */
	subi	1, 1, 0xc0
	li	0, 0
	stxvd2x	52, 1, 0
	li	0, 16
	stxvd2x	53, 1, 0
	li	0, 32
	stxvd2x	54, 1, 0
	li	0, 48
	stxvd2x	55, 1, 0
	li	0, 0x40
	stxvd2x	56, 1, 0
	li	0, 0x50
	stxvd2x	57, 1, 0
	li	0, 0x60
	stxvd2x	58, 1, 0
	li	0, 0x70
	stxvd2x	59, 1, 0
	li	0, 0x80
	stxvd2x	60, 1, 0
	li	0, 0x90
	stxvd2x	61, 1, 0
	li	0, 0xa0
	stxvd2x	62, 1, 0
	li	0, 0xb0
	stxvd2x	63, 1, 0
	stdu	1, -8(1)
	mflr	0
	std	0, 0(1)
	srwi	5, 5, 6
	mtctr	5
	li	8, 16
	addis	6, 2, L_SHA256_crypto_k@toc@ha
	addi	6, 6, L_SHA256_crypto_k@toc@l
	# Start of loop processing a block
L_SHA256_crypto_begin:
	# Load state, one word per vector register
	lxvw4x	32, 0, 3
	lxvw4x	36, 8, 3
	vsldoi	1, 0, 0, 4
	vsldoi	2, 0, 0, 8
	vsldoi	3, 0, 0, 12
	vsldoi	5, 4, 4, 4
	vsldoi	6, 4, 4, 8
	vsldoi	7, 4, 4, 12
	# Load message, one word per vector register
	lxvw4x	48, 0, 4
	addi	4, 4, 16
	vsldoi	17, 16, 16, 4
	vsldoi	18, 16, 16, 8
	vsldoi	19, 16, 16, 12
	lxvw4x	52, 0, 4
	addi	4, 4, 16
	vsldoi	21, 20, 20, 4
	vsldoi	22, 20, 20, 8
	vsldoi	23, 20, 20, 12
	lxvw4x	56, 0, 4
	addi	4, 4, 16
	vsldoi	25, 24, 24, 4
	vsldoi	26, 24, 24, 8
	vsldoi	27, 24, 24, 12
	lxvw4x	60, 0, 4
	addi	4, 4, 16
	vsldoi	29, 28, 28, 4
	vsldoi	30, 28, 28, 8
	vsldoi	31, 28, 28, 12
	# Preload first key
	lxvw4x	40, 0, 6
	li	7, 4
	# 64 rounds
	vadduwm	10, 8, 16
	vadduwm	13, 7, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 3, 7
	vadduwm	11, 11, 10
	vshasigmaw	15, 4, 1, 15
	vshasigmaw	14, 0, 1, 0
	vxor	12, 1, 2
	vsel	9, 6, 5, 4
	vsel	12, 2, 0, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	7, 15, 14
	vadduwm	3, 9, 15
	vadduwm	7, 7, 12
	vadduwm	10, 8, 17
	vadduwm	13, 6, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 2, 6
	vadduwm	11, 11, 10
	vshasigmaw	15, 3, 1, 15
	vshasigmaw	14, 7, 1, 0
	vxor	12, 0, 1
	vsel	9, 5, 4, 3
	vsel	12, 1, 7, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	6, 15, 14
	vadduwm	2, 9, 15
	vadduwm	6, 6, 12
	vadduwm	10, 8, 18
	vadduwm	13, 5, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 1, 5
	vadduwm	11, 11, 10
	vshasigmaw	15, 2, 1, 15
	vshasigmaw	14, 6, 1, 0
	vxor	12, 7, 0
	vsel	9, 4, 3, 2
	vsel	12, 0, 6, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	5, 15, 14
	vadduwm	1, 9, 15
	vadduwm	5, 5, 12
	vadduwm	10, 8, 19
	vadduwm	13, 4, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 0, 4
	vadduwm	11, 11, 10
	vshasigmaw	15, 1, 1, 15
	vshasigmaw	14, 5, 1, 0
	vxor	12, 6, 7
	vsel	9, 3, 2, 1
	vsel	12, 7, 5, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	4, 15, 14
	vadduwm	0, 9, 15
	vadduwm	4, 4, 12
	vadduwm	10, 8, 20
	vadduwm	13, 3, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 7, 3
	vadduwm	11, 11, 10
	vshasigmaw	15, 0, 1, 15
	vshasigmaw	14, 4, 1, 0
	vxor	12, 5, 6
	vsel	9, 2, 1, 0
	vsel	12, 6, 4, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	3, 15, 14
	vadduwm	7, 9, 15
	vadduwm	3, 3, 12
	vadduwm	10, 8, 21
	vadduwm	13, 2, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 6, 2
	vadduwm	11, 11, 10
	vshasigmaw	15, 7, 1, 15
	vshasigmaw	14, 3, 1, 0
	vxor	12, 4, 5
	vsel	9, 1, 0, 7
	vsel	12, 5, 3, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	2, 15, 14
	vadduwm	6, 9, 15
	vadduwm	2, 2, 12
	vadduwm	10, 8, 22
	vadduwm	13, 1, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 5, 1
	vadduwm	11, 11, 10
	vshasigmaw	15, 6, 1, 15
	vshasigmaw	14, 2, 1, 0
	vxor	12, 3, 4
	vsel	9, 0, 7, 6
	vsel	12, 4, 2, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	1, 15, 14
	vadduwm	5, 9, 15
	vadduwm	1, 1, 12
	vadduwm	10, 8, 23
	vadduwm	13, 0, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 4, 0
	vadduwm	11, 11, 10
	vshasigmaw	15, 5, 1, 15
	vshasigmaw	14, 1, 1, 0
	vxor	12, 2, 3
	vsel	9, 7, 6, 5
	vsel	12, 3, 1, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	0, 15, 14
	vadduwm	4, 9, 15
	vadduwm	0, 0, 12
	vadduwm	10, 8, 24
	vadduwm	13, 7, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 3, 7
	vadduwm	11, 11, 10
	vshasigmaw	15, 4, 1, 15
	vshasigmaw	14, 0, 1, 0
	vxor	12, 1, 2
	vsel	9, 6, 5, 4
	vsel	12, 2, 0, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	7, 15, 14
	vadduwm	3, 9, 15
	vadduwm	7, 7, 12
	vadduwm	10, 8, 25
	vadduwm	13, 6, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 2, 6
	vadduwm	11, 11, 10
	vshasigmaw	15, 3, 1, 15
	vshasigmaw	14, 7, 1, 0
	vxor	12, 0, 1
	vsel	9, 5, 4, 3
	vsel	12, 1, 7, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	6, 15, 14
	vadduwm	2, 9, 15
	vadduwm	6, 6, 12
	vadduwm	10, 8, 26
	vadduwm	13, 5, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 1, 5
	vadduwm	11, 11, 10
	vshasigmaw	15, 2, 1, 15
	vshasigmaw	14, 6, 1, 0
	vxor	12, 7, 0
	vsel	9, 4, 3, 2
	vsel	12, 0, 6, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	5, 15, 14
	vadduwm	1, 9, 15
	vadduwm	5, 5, 12
	vadduwm	10, 8, 27
	vadduwm	13, 4, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 0, 4
	vadduwm	11, 11, 10
	vshasigmaw	15, 1, 1, 15
	vshasigmaw	14, 5, 1, 0
	vxor	12, 6, 7
	vsel	9, 3, 2, 1
	vsel	12, 7, 5, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	4, 15, 14
	vadduwm	0, 9, 15
	vadduwm	4, 4, 12
	vadduwm	10, 8, 28
	vadduwm	13, 3, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 7, 3
	vadduwm	11, 11, 10
	vshasigmaw	15, 0, 1, 15
	vshasigmaw	14, 4, 1, 0
	vxor	12, 5, 6
	vsel	9, 2, 1, 0
	vsel	12, 6, 4, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	3, 15, 14
	vadduwm	7, 9, 15
	vadduwm	3, 3, 12
	vadduwm	10, 8, 29
	vadduwm	13, 2, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 6, 2
	vadduwm	11, 11, 10
	vshasigmaw	15, 7, 1, 15
	vshasigmaw	14, 3, 1, 0
	vxor	12, 4, 5
	vsel	9, 1, 0, 7
	vsel	12, 5, 3, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	2, 15, 14
	vadduwm	6, 9, 15
	vadduwm	2, 2, 12
	vadduwm	10, 8, 30
	vadduwm	13, 1, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 5, 1
	vadduwm	11, 11, 10
	vshasigmaw	15, 6, 1, 15
	vshasigmaw	14, 2, 1, 0
	vxor	12, 3, 4
	vsel	9, 0, 7, 6
	vsel	12, 4, 2, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	1, 15, 14
	vadduwm	5, 9, 15
	vadduwm	1, 1, 12
	vadduwm	10, 8, 31
	vadduwm	13, 0, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 4, 0
	vadduwm	11, 11, 10
	vshasigmaw	15, 5, 1, 15
	vshasigmaw	14, 1, 1, 0
	vxor	12, 2, 3
	vsel	9, 7, 6, 5
	vsel	12, 3, 1, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	0, 15, 14
	vadduwm	4, 9, 15
	vadduwm	0, 0, 12
	vshasigmaw	15, 30, 0, 15
	vshasigmaw	14, 17, 0, 0
	vadduwm	16, 16, 15
	vadduwm	16, 16, 14
	vadduwm	16, 16, 25
	vadduwm	10, 8, 16
	vadduwm	13, 7, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 3, 7
	vadduwm	11, 11, 10
	vshasigmaw	15, 4, 1, 15
	vshasigmaw	14, 0, 1, 0
	vxor	12, 1, 2
	vsel	9, 6, 5, 4
	vsel	12, 2, 0, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	7, 15, 14
	vadduwm	3, 9, 15
	vadduwm	7, 7, 12
	vshasigmaw	15, 31, 0, 15
	vshasigmaw	14, 18, 0, 0
	vadduwm	17, 17, 15
	vadduwm	17, 17, 14
	vadduwm	17, 17, 26
	vadduwm	10, 8, 17
	vadduwm	13, 6, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 2, 6
	vadduwm	11, 11, 10
	vshasigmaw	15, 3, 1, 15
	vshasigmaw	14, 7, 1, 0
	vxor	12, 0, 1
	vsel	9, 5, 4, 3
	vsel	12, 1, 7, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	6, 15, 14
	vadduwm	2, 9, 15
	vadduwm	6, 6, 12
	vshasigmaw	15, 16, 0, 15
	vshasigmaw	14, 19, 0, 0
	vadduwm	18, 18, 15
	vadduwm	18, 18, 14
	vadduwm	18, 18, 27
	vadduwm	10, 8, 18
	vadduwm	13, 5, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 1, 5
	vadduwm	11, 11, 10
	vshasigmaw	15, 2, 1, 15
	vshasigmaw	14, 6, 1, 0
	vxor	12, 7, 0
	vsel	9, 4, 3, 2
	vsel	12, 0, 6, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	5, 15, 14
	vadduwm	1, 9, 15
	vadduwm	5, 5, 12
	vshasigmaw	15, 17, 0, 15
	vshasigmaw	14, 20, 0, 0
	vadduwm	19, 19, 15
	vadduwm	19, 19, 14
	vadduwm	19, 19, 28
	vadduwm	10, 8, 19
	vadduwm	13, 4, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 0, 4
	vadduwm	11, 11, 10
	vshasigmaw	15, 1, 1, 15
	vshasigmaw	14, 5, 1, 0
	vxor	12, 6, 7
	vsel	9, 3, 2, 1
	vsel	12, 7, 5, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	4, 15, 14
	vadduwm	0, 9, 15
	vadduwm	4, 4, 12
	vshasigmaw	15, 18, 0, 15
	vshasigmaw	14, 21, 0, 0
	vadduwm	20, 20, 15
	vadduwm	20, 20, 14
	vadduwm	20, 20, 29
	vadduwm	10, 8, 20
	vadduwm	13, 3, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 7, 3
	vadduwm	11, 11, 10
	vshasigmaw	15, 0, 1, 15
	vshasigmaw	14, 4, 1, 0
	vxor	12, 5, 6
	vsel	9, 2, 1, 0
	vsel	12, 6, 4, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	3, 15, 14
	vadduwm	7, 9, 15
	vadduwm	3, 3, 12
	vshasigmaw	15, 19, 0, 15
	vshasigmaw	14, 22, 0, 0
	vadduwm	21, 21, 15
	vadduwm	21, 21, 14
	vadduwm	21, 21, 30
	vadduwm	10, 8, 21
	vadduwm	13, 2, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 6, 2
	vadduwm	11, 11, 10
	vshasigmaw	15, 7, 1, 15
	vshasigmaw	14, 3, 1, 0
	vxor	12, 4, 5
	vsel	9, 1, 0, 7
	vsel	12, 5, 3, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	2, 15, 14
	vadduwm	6, 9, 15
	vadduwm	2, 2, 12
	vshasigmaw	15, 20, 0, 15
	vshasigmaw	14, 23, 0, 0
	vadduwm	22, 22, 15
	vadduwm	22, 22, 14
	vadduwm	22, 22, 31
	vadduwm	10, 8, 22
	vadduwm	13, 1, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 5, 1
	vadduwm	11, 11, 10
	vshasigmaw	15, 6, 1, 15
	vshasigmaw	14, 2, 1, 0
	vxor	12, 3, 4
	vsel	9, 0, 7, 6
	vsel	12, 4, 2, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	1, 15, 14
	vadduwm	5, 9, 15
	vadduwm	1, 1, 12
	vshasigmaw	15, 21, 0, 15
	vshasigmaw	14, 24, 0, 0
	vadduwm	23, 23, 15
	vadduwm	23, 23, 14
	vadduwm	23, 23, 16
	vadduwm	10, 8, 23
	vadduwm	13, 0, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 4, 0
	vadduwm	11, 11, 10
	vshasigmaw	15, 5, 1, 15
	vshasigmaw	14, 1, 1, 0
	vxor	12, 2, 3
	vsel	9, 7, 6, 5
	vsel	12, 3, 1, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	0, 15, 14
	vadduwm	4, 9, 15
	vadduwm	0, 0, 12
	vshasigmaw	15, 22, 0, 15
	vshasigmaw	14, 25, 0, 0
	vadduwm	24, 24, 15
	vadduwm	24, 24, 14
	vadduwm	24, 24, 17
	vadduwm	10, 8, 24
	vadduwm	13, 7, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 3, 7
	vadduwm	11, 11, 10
	vshasigmaw	15, 4, 1, 15
	vshasigmaw	14, 0, 1, 0
	vxor	12, 1, 2
	vsel	9, 6, 5, 4
	vsel	12, 2, 0, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	7, 15, 14
	vadduwm	3, 9, 15
	vadduwm	7, 7, 12
	vshasigmaw	15, 23, 0, 15
	vshasigmaw	14, 26, 0, 0
	vadduwm	25, 25, 15
	vadduwm	25, 25, 14
	vadduwm	25, 25, 18
	vadduwm	10, 8, 25
	vadduwm	13, 6, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 2, 6
	vadduwm	11, 11, 10
	vshasigmaw	15, 3, 1, 15
	vshasigmaw	14, 7, 1, 0
	vxor	12, 0, 1
	vsel	9, 5, 4, 3
	vsel	12, 1, 7, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	6, 15, 14
	vadduwm	2, 9, 15
	vadduwm	6, 6, 12
	vshasigmaw	15, 24, 0, 15
	vshasigmaw	14, 27, 0, 0
	vadduwm	26, 26, 15
	vadduwm	26, 26, 14
	vadduwm	26, 26, 19
	vadduwm	10, 8, 26
	vadduwm	13, 5, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 1, 5
	vadduwm	11, 11, 10
	vshasigmaw	15, 2, 1, 15
	vshasigmaw	14, 6, 1, 0
	vxor	12, 7, 0
	vsel	9, 4, 3, 2
	vsel	12, 0, 6, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	5, 15, 14
	vadduwm	1, 9, 15
	vadduwm	5, 5, 12
	vshasigmaw	15, 25, 0, 15
	vshasigmaw	14, 28, 0, 0
	vadduwm	27, 27, 15
	vadduwm	27, 27, 14
	vadduwm	27, 27, 20
	vadduwm	10, 8, 27
	vadduwm	13, 4, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 0, 4
	vadduwm	11, 11, 10
	vshasigmaw	15, 1, 1, 15
	vshasigmaw	14, 5, 1, 0
	vxor	12, 6, 7
	vsel	9, 3, 2, 1
	vsel	12, 7, 5, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	4, 15, 14
	vadduwm	0, 9, 15
	vadduwm	4, 4, 12
	vshasigmaw	15, 26, 0, 15
	vshasigmaw	14, 29, 0, 0
	vadduwm	28, 28, 15
	vadduwm	28, 28, 14
	vadduwm	28, 28, 21
	vadduwm	10, 8, 28
	vadduwm	13, 3, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 7, 3
	vadduwm	11, 11, 10
	vshasigmaw	15, 0, 1, 15
	vshasigmaw	14, 4, 1, 0
	vxor	12, 5, 6
	vsel	9, 2, 1, 0
	vsel	12, 6, 4, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	3, 15, 14
	vadduwm	7, 9, 15
	vadduwm	3, 3, 12
	vshasigmaw	15, 27, 0, 15
	vshasigmaw	14, 30, 0, 0
	vadduwm	29, 29, 15
	vadduwm	29, 29, 14
	vadduwm	29, 29, 22
	vadduwm	10, 8, 29
	vadduwm	13, 2, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 6, 2
	vadduwm	11, 11, 10
	vshasigmaw	15, 7, 1, 15
	vshasigmaw	14, 3, 1, 0
	vxor	12, 4, 5
	vsel	9, 1, 0, 7
	vsel	12, 5, 3, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	2, 15, 14
	vadduwm	6, 9, 15
	vadduwm	2, 2, 12
	vshasigmaw	15, 28, 0, 15
	vshasigmaw	14, 31, 0, 0
	vadduwm	30, 30, 15
	vadduwm	30, 30, 14
	vadduwm	30, 30, 23
	vadduwm	10, 8, 30
	vadduwm	13, 1, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 5, 1
	vadduwm	11, 11, 10
	vshasigmaw	15, 6, 1, 15
	vshasigmaw	14, 2, 1, 0
	vxor	12, 3, 4
	vsel	9, 0, 7, 6
	vsel	12, 4, 2, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	1, 15, 14
	vadduwm	5, 9, 15
	vadduwm	1, 1, 12
	vshasigmaw	15, 29, 0, 15
	vshasigmaw	14, 16, 0, 0
	vadduwm	31, 31, 15
	vadduwm	31, 31, 14
	vadduwm	31, 31, 24
	vadduwm	10, 8, 31
	vadduwm	13, 0, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 4, 0
	vadduwm	11, 11, 10
	vshasigmaw	15, 5, 1, 15
	vshasigmaw	14, 1, 1, 0
	vxor	12, 2, 3
	vsel	9, 7, 6, 5
	vsel	12, 3, 1, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	0, 15, 14
	vadduwm	4, 9, 15
	vadduwm	0, 0, 12
	vshasigmaw	15, 30, 0, 15
	vshasigmaw	14, 17, 0, 0
	vadduwm	16, 16, 15
	vadduwm	16, 16, 14
	vadduwm	16, 16, 25
	vadduwm	10, 8, 16
	vadduwm	13, 7, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 3, 7
	vadduwm	11, 11, 10
	vshasigmaw	15, 4, 1, 15
	vshasigmaw	14, 0, 1, 0
	vxor	12, 1, 2
	vsel	9, 6, 5, 4
	vsel	12, 2, 0, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	7, 15, 14
	vadduwm	3, 9, 15
	vadduwm	7, 7, 12
	vshasigmaw	15, 31, 0, 15
	vshasigmaw	14, 18, 0, 0
	vadduwm	17, 17, 15
	vadduwm	17, 17, 14
	vadduwm	17, 17, 26
	vadduwm	10, 8, 17
	vadduwm	13, 6, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 2, 6
	vadduwm	11, 11, 10
	vshasigmaw	15, 3, 1, 15
	vshasigmaw	14, 7, 1, 0
	vxor	12, 0, 1
	vsel	9, 5, 4, 3
	vsel	12, 1, 7, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	6, 15, 14
	vadduwm	2, 9, 15
	vadduwm	6, 6, 12
	vshasigmaw	15, 16, 0, 15
	vshasigmaw	14, 19, 0, 0
	vadduwm	18, 18, 15
	vadduwm	18, 18, 14
	vadduwm	18, 18, 27
	vadduwm	10, 8, 18
	vadduwm	13, 5, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 1, 5
	vadduwm	11, 11, 10
	vshasigmaw	15, 2, 1, 15
	vshasigmaw	14, 6, 1, 0
	vxor	12, 7, 0
	vsel	9, 4, 3, 2
	vsel	12, 0, 6, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	5, 15, 14
	vadduwm	1, 9, 15
	vadduwm	5, 5, 12
	vshasigmaw	15, 17, 0, 15
	vshasigmaw	14, 20, 0, 0
	vadduwm	19, 19, 15
	vadduwm	19, 19, 14
	vadduwm	19, 19, 28
	vadduwm	10, 8, 19
	vadduwm	13, 4, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 0, 4
	vadduwm	11, 11, 10
	vshasigmaw	15, 1, 1, 15
	vshasigmaw	14, 5, 1, 0
	vxor	12, 6, 7
	vsel	9, 3, 2, 1
	vsel	12, 7, 5, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	4, 15, 14
	vadduwm	0, 9, 15
	vadduwm	4, 4, 12
	vshasigmaw	15, 18, 0, 15
	vshasigmaw	14, 21, 0, 0
	vadduwm	20, 20, 15
	vadduwm	20, 20, 14
	vadduwm	20, 20, 29
	vadduwm	10, 8, 20
	vadduwm	13, 3, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 7, 3
	vadduwm	11, 11, 10
	vshasigmaw	15, 0, 1, 15
	vshasigmaw	14, 4, 1, 0
	vxor	12, 5, 6
	vsel	9, 2, 1, 0
	vsel	12, 6, 4, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	3, 15, 14
	vadduwm	7, 9, 15
	vadduwm	3, 3, 12
	vshasigmaw	15, 19, 0, 15
	vshasigmaw	14, 22, 0, 0
	vadduwm	21, 21, 15
	vadduwm	21, 21, 14
	vadduwm	21, 21, 30
	vadduwm	10, 8, 21
	vadduwm	13, 2, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 6, 2
	vadduwm	11, 11, 10
	vshasigmaw	15, 7, 1, 15
	vshasigmaw	14, 3, 1, 0
	vxor	12, 4, 5
	vsel	9, 1, 0, 7
	vsel	12, 5, 3, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	2, 15, 14
	vadduwm	6, 9, 15
	vadduwm	2, 2, 12
	vshasigmaw	15, 20, 0, 15
	vshasigmaw	14, 23, 0, 0
	vadduwm	22, 22, 15
	vadduwm	22, 22, 14
	vadduwm	22, 22, 31
	vadduwm	10, 8, 22
	vadduwm	13, 1, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 5, 1
	vadduwm	11, 11, 10
	vshasigmaw	15, 6, 1, 15
	vshasigmaw	14, 2, 1, 0
	vxor	12, 3, 4
	vsel	9, 0, 7, 6
	vsel	12, 4, 2, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	1, 15, 14
	vadduwm	5, 9, 15
	vadduwm	1, 1, 12
	vshasigmaw	15, 21, 0, 15
	vshasigmaw	14, 24, 0, 0
	vadduwm	23, 23, 15
	vadduwm	23, 23, 14
	vadduwm	23, 23, 16
	vadduwm	10, 8, 23
	vadduwm	13, 0, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 4, 0
	vadduwm	11, 11, 10
	vshasigmaw	15, 5, 1, 15
	vshasigmaw	14, 1, 1, 0
	vxor	12, 2, 3
	vsel	9, 7, 6, 5
	vsel	12, 3, 1, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	0, 15, 14
	vadduwm	4, 9, 15
	vadduwm	0, 0, 12
	vshasigmaw	15, 22, 0, 15
	vshasigmaw	14, 25, 0, 0
	vadduwm	24, 24, 15
	vadduwm	24, 24, 14
	vadduwm	24, 24, 17
	vadduwm	10, 8, 24
	vadduwm	13, 7, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 3, 7
	vadduwm	11, 11, 10
	vshasigmaw	15, 4, 1, 15
	vshasigmaw	14, 0, 1, 0
	vxor	12, 1, 2
	vsel	9, 6, 5, 4
	vsel	12, 2, 0, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	7, 15, 14
	vadduwm	3, 9, 15
	vadduwm	7, 7, 12
	vshasigmaw	15, 23, 0, 15
	vshasigmaw	14, 26, 0, 0
	vadduwm	25, 25, 15
	vadduwm	25, 25, 14
	vadduwm	25, 25, 18
	vadduwm	10, 8, 25
	vadduwm	13, 6, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 2, 6
	vadduwm	11, 11, 10
	vshasigmaw	15, 3, 1, 15
	vshasigmaw	14, 7, 1, 0
	vxor	12, 0, 1
	vsel	9, 5, 4, 3
	vsel	12, 1, 7, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	6, 15, 14
	vadduwm	2, 9, 15
	vadduwm	6, 6, 12
	vshasigmaw	15, 24, 0, 15
	vshasigmaw	14, 27, 0, 0
	vadduwm	26, 26, 15
	vadduwm	26, 26, 14
	vadduwm	26, 26, 19
	vadduwm	10, 8, 26
	vadduwm	13, 5, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 1, 5
	vadduwm	11, 11, 10
	vshasigmaw	15, 2, 1, 15
	vshasigmaw	14, 6, 1, 0
	vxor	12, 7, 0
	vsel	9, 4, 3, 2
	vsel	12, 0, 6, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	5, 15, 14
	vadduwm	1, 9, 15
	vadduwm	5, 5, 12
	vshasigmaw	15, 25, 0, 15
	vshasigmaw	14, 28, 0, 0
	vadduwm	27, 27, 15
	vadduwm	27, 27, 14
	vadduwm	27, 27, 20
	vadduwm	10, 8, 27
	vadduwm	13, 4, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 0, 4
	vadduwm	11, 11, 10
	vshasigmaw	15, 1, 1, 15
	vshasigmaw	14, 5, 1, 0
	vxor	12, 6, 7
	vsel	9, 3, 2, 1
	vsel	12, 7, 5, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	4, 15, 14
	vadduwm	0, 9, 15
	vadduwm	4, 4, 12
	vshasigmaw	15, 26, 0, 15
	vshasigmaw	14, 29, 0, 0
	vadduwm	28, 28, 15
	vadduwm	28, 28, 14
	vadduwm	28, 28, 21
	vadduwm	10, 8, 28
	vadduwm	13, 3, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 7, 3
	vadduwm	11, 11, 10
	vshasigmaw	15, 0, 1, 15
	vshasigmaw	14, 4, 1, 0
	vxor	12, 5, 6
	vsel	9, 2, 1, 0
	vsel	12, 6, 4, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	3, 15, 14
	vadduwm	7, 9, 15
	vadduwm	3, 3, 12
	vshasigmaw	15, 27, 0, 15
	vshasigmaw	14, 30, 0, 0
	vadduwm	29, 29, 15
	vadduwm	29, 29, 14
	vadduwm	29, 29, 22
	vadduwm	10, 8, 29
	vadduwm	13, 2, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 6, 2
	vadduwm	11, 11, 10
	vshasigmaw	15, 7, 1, 15
	vshasigmaw	14, 3, 1, 0
	vxor	12, 4, 5
	vsel	9, 1, 0, 7
	vsel	12, 5, 3, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	2, 15, 14
	vadduwm	6, 9, 15
	vadduwm	2, 2, 12
	vshasigmaw	15, 28, 0, 15
	vshasigmaw	14, 31, 0, 0
	vadduwm	30, 30, 15
	vadduwm	30, 30, 14
	vadduwm	30, 30, 23
	vadduwm	10, 8, 30
	vadduwm	13, 1, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 5, 1
	vadduwm	11, 11, 10
	vshasigmaw	15, 6, 1, 15
	vshasigmaw	14, 2, 1, 0
	vxor	12, 3, 4
	vsel	9, 0, 7, 6
	vsel	12, 4, 2, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	1, 15, 14
	vadduwm	5, 9, 15
	vadduwm	1, 1, 12
	vshasigmaw	15, 29, 0, 15
	vshasigmaw	14, 16, 0, 0
	vadduwm	31, 31, 15
	vadduwm	31, 31, 14
	vadduwm	31, 31, 24
	vadduwm	10, 8, 31
	vadduwm	13, 0, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 4, 0
	vadduwm	11, 11, 10
	vshasigmaw	15, 5, 1, 15
	vshasigmaw	14, 1, 1, 0
	vxor	12, 2, 3
	vsel	9, 7, 6, 5
	vsel	12, 3, 1, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	0, 15, 14
	vadduwm	4, 9, 15
	vadduwm	0, 0, 12
	vshasigmaw	15, 30, 0, 15
	vshasigmaw	14, 17, 0, 0
	vadduwm	16, 16, 15
	vadduwm	16, 16, 14
	vadduwm	16, 16, 25
	vadduwm	10, 8, 16
	vadduwm	13, 7, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 3, 7
	vadduwm	11, 11, 10
	vshasigmaw	15, 4, 1, 15
	vshasigmaw	14, 0, 1, 0
	vxor	12, 1, 2
	vsel	9, 6, 5, 4
	vsel	12, 2, 0, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	7, 15, 14
	vadduwm	3, 9, 15
	vadduwm	7, 7, 12
	vshasigmaw	15, 31, 0, 15
	vshasigmaw	14, 18, 0, 0
	vadduwm	17, 17, 15
	vadduwm	17, 17, 14
	vadduwm	17, 17, 26
	vadduwm	10, 8, 17
	vadduwm	13, 6, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 2, 6
	vadduwm	11, 11, 10
	vshasigmaw	15, 3, 1, 15
	vshasigmaw	14, 7, 1, 0
	vxor	12, 0, 1
	vsel	9, 5, 4, 3
	vsel	12, 1, 7, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	6, 15, 14
	vadduwm	2, 9, 15
	vadduwm	6, 6, 12
	vshasigmaw	15, 16, 0, 15
	vshasigmaw	14, 19, 0, 0
	vadduwm	18, 18, 15
	vadduwm	18, 18, 14
	vadduwm	18, 18, 27
	vadduwm	10, 8, 18
	vadduwm	13, 5, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 1, 5
	vadduwm	11, 11, 10
	vshasigmaw	15, 2, 1, 15
	vshasigmaw	14, 6, 1, 0
	vxor	12, 7, 0
	vsel	9, 4, 3, 2
	vsel	12, 0, 6, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	5, 15, 14
	vadduwm	1, 9, 15
	vadduwm	5, 5, 12
	vshasigmaw	15, 17, 0, 15
	vshasigmaw	14, 20, 0, 0
	vadduwm	19, 19, 15
	vadduwm	19, 19, 14
	vadduwm	19, 19, 28
	vadduwm	10, 8, 19
	vadduwm	13, 4, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 0, 4
	vadduwm	11, 11, 10
	vshasigmaw	15, 1, 1, 15
	vshasigmaw	14, 5, 1, 0
	vxor	12, 6, 7
	vsel	9, 3, 2, 1
	vsel	12, 7, 5, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	4, 15, 14
	vadduwm	0, 9, 15
	vadduwm	4, 4, 12
	vshasigmaw	15, 18, 0, 15
	vshasigmaw	14, 21, 0, 0
	vadduwm	20, 20, 15
	vadduwm	20, 20, 14
	vadduwm	20, 20, 29
	vadduwm	10, 8, 20
	vadduwm	13, 3, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 7, 3
	vadduwm	11, 11, 10
	vshasigmaw	15, 0, 1, 15
	vshasigmaw	14, 4, 1, 0
	vxor	12, 5, 6
	vsel	9, 2, 1, 0
	vsel	12, 6, 4, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	3, 15, 14
	vadduwm	7, 9, 15
	vadduwm	3, 3, 12
	vshasigmaw	15, 19, 0, 15
	vshasigmaw	14, 22, 0, 0
	vadduwm	21, 21, 15
	vadduwm	21, 21, 14
	vadduwm	21, 21, 30
	vadduwm	10, 8, 21
	vadduwm	13, 2, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 6, 2
	vadduwm	11, 11, 10
	vshasigmaw	15, 7, 1, 15
	vshasigmaw	14, 3, 1, 0
	vxor	12, 4, 5
	vsel	9, 1, 0, 7
	vsel	12, 5, 3, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	2, 15, 14
	vadduwm	6, 9, 15
	vadduwm	2, 2, 12
	vshasigmaw	15, 20, 0, 15
	vshasigmaw	14, 23, 0, 0
	vadduwm	22, 22, 15
	vadduwm	22, 22, 14
	vadduwm	22, 22, 31
	vadduwm	10, 8, 22
	vadduwm	13, 1, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 5, 1
	vadduwm	11, 11, 10
	vshasigmaw	15, 6, 1, 15
	vshasigmaw	14, 2, 1, 0
	vxor	12, 3, 4
	vsel	9, 0, 7, 6
	vsel	12, 4, 2, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	1, 15, 14
	vadduwm	5, 9, 15
	vadduwm	1, 1, 12
	vshasigmaw	15, 21, 0, 15
	vshasigmaw	14, 24, 0, 0
	vadduwm	23, 23, 15
	vadduwm	23, 23, 14
	vadduwm	23, 23, 16
	vadduwm	10, 8, 23
	vadduwm	13, 0, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 4, 0
	vadduwm	11, 11, 10
	vshasigmaw	15, 5, 1, 15
	vshasigmaw	14, 1, 1, 0
	vxor	12, 2, 3
	vsel	9, 7, 6, 5
	vsel	12, 3, 1, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	0, 15, 14
	vadduwm	4, 9, 15
	vadduwm	0, 0, 12
	vshasigmaw	15, 22, 0, 15
	vshasigmaw	14, 25, 0, 0
	vadduwm	24, 24, 15
	vadduwm	24, 24, 14
	vadduwm	24, 24, 17
	vadduwm	10, 8, 24
	vadduwm	13, 7, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 3, 7
	vadduwm	11, 11, 10
	vshasigmaw	15, 4, 1, 15
	vshasigmaw	14, 0, 1, 0
	vxor	12, 1, 2
	vsel	9, 6, 5, 4
	vsel	12, 2, 0, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	7, 15, 14
	vadduwm	3, 9, 15
	vadduwm	7, 7, 12
	vshasigmaw	15, 23, 0, 15
	vshasigmaw	14, 26, 0, 0
	vadduwm	25, 25, 15
	vadduwm	25, 25, 14
	vadduwm	25, 25, 18
	vadduwm	10, 8, 25
	vadduwm	13, 6, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 2, 6
	vadduwm	11, 11, 10
	vshasigmaw	15, 3, 1, 15
	vshasigmaw	14, 7, 1, 0
	vxor	12, 0, 1
	vsel	9, 5, 4, 3
	vsel	12, 1, 7, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	6, 15, 14
	vadduwm	2, 9, 15
	vadduwm	6, 6, 12
	vshasigmaw	15, 24, 0, 15
	vshasigmaw	14, 27, 0, 0
	vadduwm	26, 26, 15
	vadduwm	26, 26, 14
	vadduwm	26, 26, 19
	vadduwm	10, 8, 26
	vadduwm	13, 5, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 1, 5
	vadduwm	11, 11, 10
	vshasigmaw	15, 2, 1, 15
	vshasigmaw	14, 6, 1, 0
	vxor	12, 7, 0
	vsel	9, 4, 3, 2
	vsel	12, 0, 6, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	5, 15, 14
	vadduwm	1, 9, 15
	vadduwm	5, 5, 12
	vshasigmaw	15, 25, 0, 15
	vshasigmaw	14, 28, 0, 0
	vadduwm	27, 27, 15
	vadduwm	27, 27, 14
	vadduwm	27, 27, 20
	vadduwm	10, 8, 27
	vadduwm	13, 4, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 0, 4
	vadduwm	11, 11, 10
	vshasigmaw	15, 1, 1, 15
	vshasigmaw	14, 5, 1, 0
	vxor	12, 6, 7
	vsel	9, 3, 2, 1
	vsel	12, 7, 5, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	4, 15, 14
	vadduwm	0, 9, 15
	vadduwm	4, 4, 12
	vshasigmaw	15, 26, 0, 15
	vshasigmaw	14, 29, 0, 0
	vadduwm	28, 28, 15
	vadduwm	28, 28, 14
	vadduwm	28, 28, 21
	vadduwm	10, 8, 28
	vadduwm	13, 3, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 7, 3
	vadduwm	11, 11, 10
	vshasigmaw	15, 0, 1, 15
	vshasigmaw	14, 4, 1, 0
	vxor	12, 5, 6
	vsel	9, 2, 1, 0
	vsel	12, 6, 4, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	3, 15, 14
	vadduwm	7, 9, 15
	vadduwm	3, 3, 12
	vshasigmaw	15, 27, 0, 15
	vshasigmaw	14, 30, 0, 0
	vadduwm	29, 29, 15
	vadduwm	29, 29, 14
	vadduwm	29, 29, 22
	vadduwm	10, 8, 29
	vadduwm	13, 2, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 6, 2
	vadduwm	11, 11, 10
	vshasigmaw	15, 7, 1, 15
	vshasigmaw	14, 3, 1, 0
	vxor	12, 4, 5
	vsel	9, 1, 0, 7
	vsel	12, 5, 3, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	2, 15, 14
	vadduwm	6, 9, 15
	vadduwm	2, 2, 12
	vshasigmaw	15, 28, 0, 15
	vshasigmaw	14, 31, 0, 0
	vadduwm	30, 30, 15
	vadduwm	30, 30, 14
	vadduwm	30, 30, 23
	vadduwm	10, 8, 30
	vadduwm	13, 1, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 5, 1
	vadduwm	11, 11, 10
	vshasigmaw	15, 6, 1, 15
	vshasigmaw	14, 2, 1, 0
	vxor	12, 3, 4
	vsel	9, 0, 7, 6
	vsel	12, 4, 2, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	1, 15, 14
	vadduwm	5, 9, 15
	vadduwm	1, 1, 12
	vshasigmaw	15, 29, 0, 15
	vshasigmaw	14, 16, 0, 0
	vadduwm	31, 31, 15
	vadduwm	31, 31, 14
	vadduwm	31, 31, 24
	vadduwm	10, 8, 31
	vadduwm	13, 0, 10
	lxvw4x	40, 7, 6
	addi	7, 7, 4
	vadduwm	11, 4, 0
	vadduwm	11, 11, 10
	vshasigmaw	15, 5, 1, 15
	vshasigmaw	14, 1, 1, 0
	vxor	12, 2, 3
	vsel	9, 7, 6, 5
	vsel	12, 3, 1, 12
	vadduwm	13, 13, 9
	vadduwm	12, 12, 13
	vadduwm	9, 9, 11
	vadduwm	0, 15, 14
	vadduwm	4, 9, 15
	vadduwm	0, 0, 12
	# Repack state, add original digest and store
	vmrghw	0, 0, 1
	vmrghw	2, 2, 3
	xxmrghd	32, 32, 34
	vmrghw	4, 4, 5
	vmrghw	6, 6, 7
	xxmrghd	36, 36, 38
	lxvw4x	41, 0, 3
	lxvw4x	42, 8, 3
	vadduwm	0, 0, 9
	vadduwm	4, 4, 10
	stxvw4x	32, 0, 3
	stxvw4x	36, 8, 3
	bdnz	L_SHA256_crypto_begin
	ld	0, 0(1)
	mtlr	0
	addi	1, 1, 8
	li	0, 0
	lxvd2x	52, 1, 0
	li	0, 16
	lxvd2x	53, 1, 0
	li	0, 32
	lxvd2x	54, 1, 0
	li	0, 48
	lxvd2x	55, 1, 0
	li	0, 0x40
	lxvd2x	56, 1, 0
	li	0, 0x50
	lxvd2x	57, 1, 0
	li	0, 0x60
	lxvd2x	58, 1, 0
	li	0, 0x70
	lxvd2x	59, 1, 0
	li	0, 0x80
	lxvd2x	60, 1, 0
	li	0, 0x90
	lxvd2x	61, 1, 0
	li	0, 0xa0
	lxvd2x	62, 1, 0
	li	0, 0xb0
	lxvd2x	63, 1, 0
	addi	1, 1, 0xc0
	blr
#ifndef __APPLE__
	.size	Transform_Sha256_Len_crypto,.-Transform_Sha256_Len_crypto
#endif /* __APPLE__ */
	.machine	"pop"
#endif /* WOLFSSL_PPC64_ASM_CRYPTO */
#endif /* !NO_SHA256 */
#endif /* WOLFSSL_PPC64_ASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_PPC64_ASM_INLINE */
