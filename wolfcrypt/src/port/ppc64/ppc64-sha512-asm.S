/* ppc64-sha512-asm
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
 *   ruby ./sha2/sha512.rb ppc64 \
 *       ../wolfssl/wolfcrypt/src/port/ppc64/ppc64-sha512-asm.S
 */
#ifdef WOLFSSL_PPC64_ASM
#ifndef WOLFSSL_PPC64_ASM_INLINE
#if defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA384)
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
#ifndef __APPLE__
#if defined(_CALL_ELF) && _CALL_ELF == 2
.text
.globl	Transform_Sha512_Len
.type	Transform_Sha512_Len,@function
.align	16
Transform_Sha512_Len:
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	Transform_Sha512_Len, .-Transform_Sha512_Len
#else
	/* Power ELF V1 ABI: emit a function descriptor in .opd that
	 * points at the code (.L.Transform_Sha512_Len) and the TOC base. */
.section	.opd,"aw",@progbits
.globl	Transform_Sha512_Len
.type	Transform_Sha512_Len,@function
.align	3
Transform_Sha512_Len:
	.quad	.L.Transform_Sha512_Len,.TOC.@tocbase,0
	.size	Transform_Sha512_Len,24
.text
.align	16
.L.Transform_Sha512_Len:
#endif /* _CALL_ELF == 2 */
#else
.section	__TEXT,__text
.globl	_Transform_Sha512_Len
.p2align	4
_Transform_Sha512_Len:
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
	srdi	5, 5, 7
	addis	6, 2, L_SHA512_transform_len_k@toc@ha
	addi	6, 6, L_SHA512_transform_len_k@toc@l
	# Copy digest to add in at end
	ld	7, 0(3)
	ld	8, 8(3)
	ld	9, 16(3)
	ld	10, 24(3)
	ld	11, 32(3)
	ld	12, 40(3)
	ld	14, 48(3)
	ld	15, 56(3)
#ifndef WOLFSSL_PPC64_ASM_SMALL
	mtctr	5
	# Start of loop processing a block
L_SHA512_transform_len_begin:
	# Load W - 128 bytes
#ifdef __LITTLE_ENDIAN__
	li	0, 0
	ldbrx	16, 4, 0
	li	0, 8
	ldbrx	17, 4, 0
	li	0, 16
	ldbrx	18, 4, 0
	li	0, 24
	ldbrx	19, 4, 0
	li	0, 32
	ldbrx	20, 4, 0
	li	0, 40
	ldbrx	21, 4, 0
	li	0, 48
	ldbrx	22, 4, 0
	li	0, 56
	ldbrx	23, 4, 0
	li	0, 0x40
	ldbrx	24, 4, 0
	li	0, 0x48
	ldbrx	25, 4, 0
	li	0, 0x50
	ldbrx	26, 4, 0
	li	0, 0x58
	ldbrx	27, 4, 0
	li	0, 0x60
	ldbrx	28, 4, 0
	li	0, 0x68
	ldbrx	29, 4, 0
	li	0, 0x70
	ldbrx	30, 4, 0
	li	0, 0x78
	ldbrx	31, 4, 0
#else
	ld	16, 0(4)
	ld	17, 8(4)
	ld	18, 16(4)
	ld	19, 24(4)
	ld	20, 32(4)
	ld	21, 40(4)
	ld	22, 48(4)
	ld	23, 56(4)
	ld	24, 64(4)
	ld	25, 72(4)
	ld	26, 80(4)
	ld	27, 88(4)
	ld	28, 96(4)
	ld	29, 104(4)
	ld	30, 112(4)
	ld	31, 120(4)
#endif /* __LITTLE_ENDIAN__ */
	# Start of 80 rounds
	# Round 0
	rotrdi	0, 11, 14
	rotrdi	5, 11, 18
	xor	0, 0, 5
	rotrdi	5, 11, 41
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	ld	0, 0(6)
	add	15, 15, 16
	add	15, 15, 0
	add	10, 10, 15
	rotrdi	0, 7, 28
	rotrdi	5, 7, 34
	xor	0, 0, 5
	rotrdi	5, 7, 39
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	# Calc new W[0]
	rotrdi	0, 17, 1
	rotrdi	5, 17, 8
	xor	0, 0, 5
	srdi	5, 17, 7
	xor	0, 0, 5
	add	16, 16, 0
	rotrdi	0, 30, 19
	rotrdi	5, 30, 61
	xor	0, 0, 5
	srdi	5, 30, 6
	xor	0, 0, 5
	add	16, 16, 0
	add	16, 16, 25
	# Round 1
	rotrdi	0, 10, 14
	rotrdi	5, 10, 18
	xor	0, 0, 5
	rotrdi	5, 10, 41
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	ld	0, 8(6)
	add	14, 14, 17
	add	14, 14, 0
	add	9, 9, 14
	rotrdi	0, 15, 28
	rotrdi	5, 15, 34
	xor	0, 0, 5
	rotrdi	5, 15, 39
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	# Calc new W[1]
	rotrdi	0, 18, 1
	rotrdi	5, 18, 8
	xor	0, 0, 5
	srdi	5, 18, 7
	xor	0, 0, 5
	add	17, 17, 0
	rotrdi	0, 31, 19
	rotrdi	5, 31, 61
	xor	0, 0, 5
	srdi	5, 31, 6
	xor	0, 0, 5
	add	17, 17, 0
	add	17, 17, 26
	# Round 2
	rotrdi	0, 9, 14
	rotrdi	5, 9, 18
	xor	0, 0, 5
	rotrdi	5, 9, 41
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	ld	0, 16(6)
	add	12, 12, 18
	add	12, 12, 0
	add	8, 8, 12
	rotrdi	0, 14, 28
	rotrdi	5, 14, 34
	xor	0, 0, 5
	rotrdi	5, 14, 39
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	# Calc new W[2]
	rotrdi	0, 19, 1
	rotrdi	5, 19, 8
	xor	0, 0, 5
	srdi	5, 19, 7
	xor	0, 0, 5
	add	18, 18, 0
	rotrdi	0, 16, 19
	rotrdi	5, 16, 61
	xor	0, 0, 5
	srdi	5, 16, 6
	xor	0, 0, 5
	add	18, 18, 0
	add	18, 18, 27
	# Round 3
	rotrdi	0, 8, 14
	rotrdi	5, 8, 18
	xor	0, 0, 5
	rotrdi	5, 8, 41
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	ld	0, 24(6)
	add	11, 11, 19
	add	11, 11, 0
	add	7, 7, 11
	rotrdi	0, 12, 28
	rotrdi	5, 12, 34
	xor	0, 0, 5
	rotrdi	5, 12, 39
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	# Calc new W[3]
	rotrdi	0, 20, 1
	rotrdi	5, 20, 8
	xor	0, 0, 5
	srdi	5, 20, 7
	xor	0, 0, 5
	add	19, 19, 0
	rotrdi	0, 17, 19
	rotrdi	5, 17, 61
	xor	0, 0, 5
	srdi	5, 17, 6
	xor	0, 0, 5
	add	19, 19, 0
	add	19, 19, 28
	# Round 4
	rotrdi	0, 7, 14
	rotrdi	5, 7, 18
	xor	0, 0, 5
	rotrdi	5, 7, 41
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	ld	0, 32(6)
	add	10, 10, 20
	add	10, 10, 0
	add	15, 15, 10
	rotrdi	0, 11, 28
	rotrdi	5, 11, 34
	xor	0, 0, 5
	rotrdi	5, 11, 39
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	# Calc new W[4]
	rotrdi	0, 21, 1
	rotrdi	5, 21, 8
	xor	0, 0, 5
	srdi	5, 21, 7
	xor	0, 0, 5
	add	20, 20, 0
	rotrdi	0, 18, 19
	rotrdi	5, 18, 61
	xor	0, 0, 5
	srdi	5, 18, 6
	xor	0, 0, 5
	add	20, 20, 0
	add	20, 20, 29
	# Round 5
	rotrdi	0, 15, 14
	rotrdi	5, 15, 18
	xor	0, 0, 5
	rotrdi	5, 15, 41
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	ld	0, 40(6)
	add	9, 9, 21
	add	9, 9, 0
	add	14, 14, 9
	rotrdi	0, 10, 28
	rotrdi	5, 10, 34
	xor	0, 0, 5
	rotrdi	5, 10, 39
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	# Calc new W[5]
	rotrdi	0, 22, 1
	rotrdi	5, 22, 8
	xor	0, 0, 5
	srdi	5, 22, 7
	xor	0, 0, 5
	add	21, 21, 0
	rotrdi	0, 19, 19
	rotrdi	5, 19, 61
	xor	0, 0, 5
	srdi	5, 19, 6
	xor	0, 0, 5
	add	21, 21, 0
	add	21, 21, 30
	# Round 6
	rotrdi	0, 14, 14
	rotrdi	5, 14, 18
	xor	0, 0, 5
	rotrdi	5, 14, 41
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	ld	0, 48(6)
	add	8, 8, 22
	add	8, 8, 0
	add	12, 12, 8
	rotrdi	0, 9, 28
	rotrdi	5, 9, 34
	xor	0, 0, 5
	rotrdi	5, 9, 39
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	# Calc new W[6]
	rotrdi	0, 23, 1
	rotrdi	5, 23, 8
	xor	0, 0, 5
	srdi	5, 23, 7
	xor	0, 0, 5
	add	22, 22, 0
	rotrdi	0, 20, 19
	rotrdi	5, 20, 61
	xor	0, 0, 5
	srdi	5, 20, 6
	xor	0, 0, 5
	add	22, 22, 0
	add	22, 22, 31
	# Round 7
	rotrdi	0, 12, 14
	rotrdi	5, 12, 18
	xor	0, 0, 5
	rotrdi	5, 12, 41
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	ld	0, 56(6)
	add	7, 7, 23
	add	7, 7, 0
	add	11, 11, 7
	rotrdi	0, 8, 28
	rotrdi	5, 8, 34
	xor	0, 0, 5
	rotrdi	5, 8, 39
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	# Calc new W[7]
	rotrdi	0, 24, 1
	rotrdi	5, 24, 8
	xor	0, 0, 5
	srdi	5, 24, 7
	xor	0, 0, 5
	add	23, 23, 0
	rotrdi	0, 21, 19
	rotrdi	5, 21, 61
	xor	0, 0, 5
	srdi	5, 21, 6
	xor	0, 0, 5
	add	23, 23, 0
	add	23, 23, 16
	# Round 8
	rotrdi	0, 11, 14
	rotrdi	5, 11, 18
	xor	0, 0, 5
	rotrdi	5, 11, 41
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	ld	0, 64(6)
	add	15, 15, 24
	add	15, 15, 0
	add	10, 10, 15
	rotrdi	0, 7, 28
	rotrdi	5, 7, 34
	xor	0, 0, 5
	rotrdi	5, 7, 39
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	# Calc new W[8]
	rotrdi	0, 25, 1
	rotrdi	5, 25, 8
	xor	0, 0, 5
	srdi	5, 25, 7
	xor	0, 0, 5
	add	24, 24, 0
	rotrdi	0, 22, 19
	rotrdi	5, 22, 61
	xor	0, 0, 5
	srdi	5, 22, 6
	xor	0, 0, 5
	add	24, 24, 0
	add	24, 24, 17
	# Round 9
	rotrdi	0, 10, 14
	rotrdi	5, 10, 18
	xor	0, 0, 5
	rotrdi	5, 10, 41
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	ld	0, 72(6)
	add	14, 14, 25
	add	14, 14, 0
	add	9, 9, 14
	rotrdi	0, 15, 28
	rotrdi	5, 15, 34
	xor	0, 0, 5
	rotrdi	5, 15, 39
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	# Calc new W[9]
	rotrdi	0, 26, 1
	rotrdi	5, 26, 8
	xor	0, 0, 5
	srdi	5, 26, 7
	xor	0, 0, 5
	add	25, 25, 0
	rotrdi	0, 23, 19
	rotrdi	5, 23, 61
	xor	0, 0, 5
	srdi	5, 23, 6
	xor	0, 0, 5
	add	25, 25, 0
	add	25, 25, 18
	# Round 10
	rotrdi	0, 9, 14
	rotrdi	5, 9, 18
	xor	0, 0, 5
	rotrdi	5, 9, 41
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	ld	0, 80(6)
	add	12, 12, 26
	add	12, 12, 0
	add	8, 8, 12
	rotrdi	0, 14, 28
	rotrdi	5, 14, 34
	xor	0, 0, 5
	rotrdi	5, 14, 39
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	# Calc new W[10]
	rotrdi	0, 27, 1
	rotrdi	5, 27, 8
	xor	0, 0, 5
	srdi	5, 27, 7
	xor	0, 0, 5
	add	26, 26, 0
	rotrdi	0, 24, 19
	rotrdi	5, 24, 61
	xor	0, 0, 5
	srdi	5, 24, 6
	xor	0, 0, 5
	add	26, 26, 0
	add	26, 26, 19
	# Round 11
	rotrdi	0, 8, 14
	rotrdi	5, 8, 18
	xor	0, 0, 5
	rotrdi	5, 8, 41
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	ld	0, 88(6)
	add	11, 11, 27
	add	11, 11, 0
	add	7, 7, 11
	rotrdi	0, 12, 28
	rotrdi	5, 12, 34
	xor	0, 0, 5
	rotrdi	5, 12, 39
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	# Calc new W[11]
	rotrdi	0, 28, 1
	rotrdi	5, 28, 8
	xor	0, 0, 5
	srdi	5, 28, 7
	xor	0, 0, 5
	add	27, 27, 0
	rotrdi	0, 25, 19
	rotrdi	5, 25, 61
	xor	0, 0, 5
	srdi	5, 25, 6
	xor	0, 0, 5
	add	27, 27, 0
	add	27, 27, 20
	# Round 12
	rotrdi	0, 7, 14
	rotrdi	5, 7, 18
	xor	0, 0, 5
	rotrdi	5, 7, 41
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	ld	0, 96(6)
	add	10, 10, 28
	add	10, 10, 0
	add	15, 15, 10
	rotrdi	0, 11, 28
	rotrdi	5, 11, 34
	xor	0, 0, 5
	rotrdi	5, 11, 39
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	# Calc new W[12]
	rotrdi	0, 29, 1
	rotrdi	5, 29, 8
	xor	0, 0, 5
	srdi	5, 29, 7
	xor	0, 0, 5
	add	28, 28, 0
	rotrdi	0, 26, 19
	rotrdi	5, 26, 61
	xor	0, 0, 5
	srdi	5, 26, 6
	xor	0, 0, 5
	add	28, 28, 0
	add	28, 28, 21
	# Round 13
	rotrdi	0, 15, 14
	rotrdi	5, 15, 18
	xor	0, 0, 5
	rotrdi	5, 15, 41
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	ld	0, 104(6)
	add	9, 9, 29
	add	9, 9, 0
	add	14, 14, 9
	rotrdi	0, 10, 28
	rotrdi	5, 10, 34
	xor	0, 0, 5
	rotrdi	5, 10, 39
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	# Calc new W[13]
	rotrdi	0, 30, 1
	rotrdi	5, 30, 8
	xor	0, 0, 5
	srdi	5, 30, 7
	xor	0, 0, 5
	add	29, 29, 0
	rotrdi	0, 27, 19
	rotrdi	5, 27, 61
	xor	0, 0, 5
	srdi	5, 27, 6
	xor	0, 0, 5
	add	29, 29, 0
	add	29, 29, 22
	# Round 14
	rotrdi	0, 14, 14
	rotrdi	5, 14, 18
	xor	0, 0, 5
	rotrdi	5, 14, 41
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	ld	0, 112(6)
	add	8, 8, 30
	add	8, 8, 0
	add	12, 12, 8
	rotrdi	0, 9, 28
	rotrdi	5, 9, 34
	xor	0, 0, 5
	rotrdi	5, 9, 39
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	# Calc new W[14]
	rotrdi	0, 31, 1
	rotrdi	5, 31, 8
	xor	0, 0, 5
	srdi	5, 31, 7
	xor	0, 0, 5
	add	30, 30, 0
	rotrdi	0, 28, 19
	rotrdi	5, 28, 61
	xor	0, 0, 5
	srdi	5, 28, 6
	xor	0, 0, 5
	add	30, 30, 0
	add	30, 30, 23
	# Round 15
	rotrdi	0, 12, 14
	rotrdi	5, 12, 18
	xor	0, 0, 5
	rotrdi	5, 12, 41
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	ld	0, 120(6)
	add	7, 7, 31
	add	7, 7, 0
	add	11, 11, 7
	rotrdi	0, 8, 28
	rotrdi	5, 8, 34
	xor	0, 0, 5
	rotrdi	5, 8, 39
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	# Calc new W[15]
	rotrdi	0, 16, 1
	rotrdi	5, 16, 8
	xor	0, 0, 5
	srdi	5, 16, 7
	xor	0, 0, 5
	add	31, 31, 0
	rotrdi	0, 29, 19
	rotrdi	5, 29, 61
	xor	0, 0, 5
	srdi	5, 29, 6
	xor	0, 0, 5
	add	31, 31, 0
	add	31, 31, 24
	addi	6, 6, 0x80
	# Round 0
	rotrdi	0, 11, 14
	rotrdi	5, 11, 18
	xor	0, 0, 5
	rotrdi	5, 11, 41
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	ld	0, 0(6)
	add	15, 15, 16
	add	15, 15, 0
	add	10, 10, 15
	rotrdi	0, 7, 28
	rotrdi	5, 7, 34
	xor	0, 0, 5
	rotrdi	5, 7, 39
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	# Calc new W[0]
	rotrdi	0, 17, 1
	rotrdi	5, 17, 8
	xor	0, 0, 5
	srdi	5, 17, 7
	xor	0, 0, 5
	add	16, 16, 0
	rotrdi	0, 30, 19
	rotrdi	5, 30, 61
	xor	0, 0, 5
	srdi	5, 30, 6
	xor	0, 0, 5
	add	16, 16, 0
	add	16, 16, 25
	# Round 1
	rotrdi	0, 10, 14
	rotrdi	5, 10, 18
	xor	0, 0, 5
	rotrdi	5, 10, 41
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	ld	0, 8(6)
	add	14, 14, 17
	add	14, 14, 0
	add	9, 9, 14
	rotrdi	0, 15, 28
	rotrdi	5, 15, 34
	xor	0, 0, 5
	rotrdi	5, 15, 39
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	# Calc new W[1]
	rotrdi	0, 18, 1
	rotrdi	5, 18, 8
	xor	0, 0, 5
	srdi	5, 18, 7
	xor	0, 0, 5
	add	17, 17, 0
	rotrdi	0, 31, 19
	rotrdi	5, 31, 61
	xor	0, 0, 5
	srdi	5, 31, 6
	xor	0, 0, 5
	add	17, 17, 0
	add	17, 17, 26
	# Round 2
	rotrdi	0, 9, 14
	rotrdi	5, 9, 18
	xor	0, 0, 5
	rotrdi	5, 9, 41
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	ld	0, 16(6)
	add	12, 12, 18
	add	12, 12, 0
	add	8, 8, 12
	rotrdi	0, 14, 28
	rotrdi	5, 14, 34
	xor	0, 0, 5
	rotrdi	5, 14, 39
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	# Calc new W[2]
	rotrdi	0, 19, 1
	rotrdi	5, 19, 8
	xor	0, 0, 5
	srdi	5, 19, 7
	xor	0, 0, 5
	add	18, 18, 0
	rotrdi	0, 16, 19
	rotrdi	5, 16, 61
	xor	0, 0, 5
	srdi	5, 16, 6
	xor	0, 0, 5
	add	18, 18, 0
	add	18, 18, 27
	# Round 3
	rotrdi	0, 8, 14
	rotrdi	5, 8, 18
	xor	0, 0, 5
	rotrdi	5, 8, 41
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	ld	0, 24(6)
	add	11, 11, 19
	add	11, 11, 0
	add	7, 7, 11
	rotrdi	0, 12, 28
	rotrdi	5, 12, 34
	xor	0, 0, 5
	rotrdi	5, 12, 39
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	# Calc new W[3]
	rotrdi	0, 20, 1
	rotrdi	5, 20, 8
	xor	0, 0, 5
	srdi	5, 20, 7
	xor	0, 0, 5
	add	19, 19, 0
	rotrdi	0, 17, 19
	rotrdi	5, 17, 61
	xor	0, 0, 5
	srdi	5, 17, 6
	xor	0, 0, 5
	add	19, 19, 0
	add	19, 19, 28
	# Round 4
	rotrdi	0, 7, 14
	rotrdi	5, 7, 18
	xor	0, 0, 5
	rotrdi	5, 7, 41
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	ld	0, 32(6)
	add	10, 10, 20
	add	10, 10, 0
	add	15, 15, 10
	rotrdi	0, 11, 28
	rotrdi	5, 11, 34
	xor	0, 0, 5
	rotrdi	5, 11, 39
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	# Calc new W[4]
	rotrdi	0, 21, 1
	rotrdi	5, 21, 8
	xor	0, 0, 5
	srdi	5, 21, 7
	xor	0, 0, 5
	add	20, 20, 0
	rotrdi	0, 18, 19
	rotrdi	5, 18, 61
	xor	0, 0, 5
	srdi	5, 18, 6
	xor	0, 0, 5
	add	20, 20, 0
	add	20, 20, 29
	# Round 5
	rotrdi	0, 15, 14
	rotrdi	5, 15, 18
	xor	0, 0, 5
	rotrdi	5, 15, 41
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	ld	0, 40(6)
	add	9, 9, 21
	add	9, 9, 0
	add	14, 14, 9
	rotrdi	0, 10, 28
	rotrdi	5, 10, 34
	xor	0, 0, 5
	rotrdi	5, 10, 39
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	# Calc new W[5]
	rotrdi	0, 22, 1
	rotrdi	5, 22, 8
	xor	0, 0, 5
	srdi	5, 22, 7
	xor	0, 0, 5
	add	21, 21, 0
	rotrdi	0, 19, 19
	rotrdi	5, 19, 61
	xor	0, 0, 5
	srdi	5, 19, 6
	xor	0, 0, 5
	add	21, 21, 0
	add	21, 21, 30
	# Round 6
	rotrdi	0, 14, 14
	rotrdi	5, 14, 18
	xor	0, 0, 5
	rotrdi	5, 14, 41
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	ld	0, 48(6)
	add	8, 8, 22
	add	8, 8, 0
	add	12, 12, 8
	rotrdi	0, 9, 28
	rotrdi	5, 9, 34
	xor	0, 0, 5
	rotrdi	5, 9, 39
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	# Calc new W[6]
	rotrdi	0, 23, 1
	rotrdi	5, 23, 8
	xor	0, 0, 5
	srdi	5, 23, 7
	xor	0, 0, 5
	add	22, 22, 0
	rotrdi	0, 20, 19
	rotrdi	5, 20, 61
	xor	0, 0, 5
	srdi	5, 20, 6
	xor	0, 0, 5
	add	22, 22, 0
	add	22, 22, 31
	# Round 7
	rotrdi	0, 12, 14
	rotrdi	5, 12, 18
	xor	0, 0, 5
	rotrdi	5, 12, 41
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	ld	0, 56(6)
	add	7, 7, 23
	add	7, 7, 0
	add	11, 11, 7
	rotrdi	0, 8, 28
	rotrdi	5, 8, 34
	xor	0, 0, 5
	rotrdi	5, 8, 39
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	# Calc new W[7]
	rotrdi	0, 24, 1
	rotrdi	5, 24, 8
	xor	0, 0, 5
	srdi	5, 24, 7
	xor	0, 0, 5
	add	23, 23, 0
	rotrdi	0, 21, 19
	rotrdi	5, 21, 61
	xor	0, 0, 5
	srdi	5, 21, 6
	xor	0, 0, 5
	add	23, 23, 0
	add	23, 23, 16
	# Round 8
	rotrdi	0, 11, 14
	rotrdi	5, 11, 18
	xor	0, 0, 5
	rotrdi	5, 11, 41
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	ld	0, 64(6)
	add	15, 15, 24
	add	15, 15, 0
	add	10, 10, 15
	rotrdi	0, 7, 28
	rotrdi	5, 7, 34
	xor	0, 0, 5
	rotrdi	5, 7, 39
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	# Calc new W[8]
	rotrdi	0, 25, 1
	rotrdi	5, 25, 8
	xor	0, 0, 5
	srdi	5, 25, 7
	xor	0, 0, 5
	add	24, 24, 0
	rotrdi	0, 22, 19
	rotrdi	5, 22, 61
	xor	0, 0, 5
	srdi	5, 22, 6
	xor	0, 0, 5
	add	24, 24, 0
	add	24, 24, 17
	# Round 9
	rotrdi	0, 10, 14
	rotrdi	5, 10, 18
	xor	0, 0, 5
	rotrdi	5, 10, 41
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	ld	0, 72(6)
	add	14, 14, 25
	add	14, 14, 0
	add	9, 9, 14
	rotrdi	0, 15, 28
	rotrdi	5, 15, 34
	xor	0, 0, 5
	rotrdi	5, 15, 39
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	# Calc new W[9]
	rotrdi	0, 26, 1
	rotrdi	5, 26, 8
	xor	0, 0, 5
	srdi	5, 26, 7
	xor	0, 0, 5
	add	25, 25, 0
	rotrdi	0, 23, 19
	rotrdi	5, 23, 61
	xor	0, 0, 5
	srdi	5, 23, 6
	xor	0, 0, 5
	add	25, 25, 0
	add	25, 25, 18
	# Round 10
	rotrdi	0, 9, 14
	rotrdi	5, 9, 18
	xor	0, 0, 5
	rotrdi	5, 9, 41
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	ld	0, 80(6)
	add	12, 12, 26
	add	12, 12, 0
	add	8, 8, 12
	rotrdi	0, 14, 28
	rotrdi	5, 14, 34
	xor	0, 0, 5
	rotrdi	5, 14, 39
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	# Calc new W[10]
	rotrdi	0, 27, 1
	rotrdi	5, 27, 8
	xor	0, 0, 5
	srdi	5, 27, 7
	xor	0, 0, 5
	add	26, 26, 0
	rotrdi	0, 24, 19
	rotrdi	5, 24, 61
	xor	0, 0, 5
	srdi	5, 24, 6
	xor	0, 0, 5
	add	26, 26, 0
	add	26, 26, 19
	# Round 11
	rotrdi	0, 8, 14
	rotrdi	5, 8, 18
	xor	0, 0, 5
	rotrdi	5, 8, 41
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	ld	0, 88(6)
	add	11, 11, 27
	add	11, 11, 0
	add	7, 7, 11
	rotrdi	0, 12, 28
	rotrdi	5, 12, 34
	xor	0, 0, 5
	rotrdi	5, 12, 39
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	# Calc new W[11]
	rotrdi	0, 28, 1
	rotrdi	5, 28, 8
	xor	0, 0, 5
	srdi	5, 28, 7
	xor	0, 0, 5
	add	27, 27, 0
	rotrdi	0, 25, 19
	rotrdi	5, 25, 61
	xor	0, 0, 5
	srdi	5, 25, 6
	xor	0, 0, 5
	add	27, 27, 0
	add	27, 27, 20
	# Round 12
	rotrdi	0, 7, 14
	rotrdi	5, 7, 18
	xor	0, 0, 5
	rotrdi	5, 7, 41
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	ld	0, 96(6)
	add	10, 10, 28
	add	10, 10, 0
	add	15, 15, 10
	rotrdi	0, 11, 28
	rotrdi	5, 11, 34
	xor	0, 0, 5
	rotrdi	5, 11, 39
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	# Calc new W[12]
	rotrdi	0, 29, 1
	rotrdi	5, 29, 8
	xor	0, 0, 5
	srdi	5, 29, 7
	xor	0, 0, 5
	add	28, 28, 0
	rotrdi	0, 26, 19
	rotrdi	5, 26, 61
	xor	0, 0, 5
	srdi	5, 26, 6
	xor	0, 0, 5
	add	28, 28, 0
	add	28, 28, 21
	# Round 13
	rotrdi	0, 15, 14
	rotrdi	5, 15, 18
	xor	0, 0, 5
	rotrdi	5, 15, 41
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	ld	0, 104(6)
	add	9, 9, 29
	add	9, 9, 0
	add	14, 14, 9
	rotrdi	0, 10, 28
	rotrdi	5, 10, 34
	xor	0, 0, 5
	rotrdi	5, 10, 39
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	# Calc new W[13]
	rotrdi	0, 30, 1
	rotrdi	5, 30, 8
	xor	0, 0, 5
	srdi	5, 30, 7
	xor	0, 0, 5
	add	29, 29, 0
	rotrdi	0, 27, 19
	rotrdi	5, 27, 61
	xor	0, 0, 5
	srdi	5, 27, 6
	xor	0, 0, 5
	add	29, 29, 0
	add	29, 29, 22
	# Round 14
	rotrdi	0, 14, 14
	rotrdi	5, 14, 18
	xor	0, 0, 5
	rotrdi	5, 14, 41
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	ld	0, 112(6)
	add	8, 8, 30
	add	8, 8, 0
	add	12, 12, 8
	rotrdi	0, 9, 28
	rotrdi	5, 9, 34
	xor	0, 0, 5
	rotrdi	5, 9, 39
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	# Calc new W[14]
	rotrdi	0, 31, 1
	rotrdi	5, 31, 8
	xor	0, 0, 5
	srdi	5, 31, 7
	xor	0, 0, 5
	add	30, 30, 0
	rotrdi	0, 28, 19
	rotrdi	5, 28, 61
	xor	0, 0, 5
	srdi	5, 28, 6
	xor	0, 0, 5
	add	30, 30, 0
	add	30, 30, 23
	# Round 15
	rotrdi	0, 12, 14
	rotrdi	5, 12, 18
	xor	0, 0, 5
	rotrdi	5, 12, 41
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	ld	0, 120(6)
	add	7, 7, 31
	add	7, 7, 0
	add	11, 11, 7
	rotrdi	0, 8, 28
	rotrdi	5, 8, 34
	xor	0, 0, 5
	rotrdi	5, 8, 39
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	# Calc new W[15]
	rotrdi	0, 16, 1
	rotrdi	5, 16, 8
	xor	0, 0, 5
	srdi	5, 16, 7
	xor	0, 0, 5
	add	31, 31, 0
	rotrdi	0, 29, 19
	rotrdi	5, 29, 61
	xor	0, 0, 5
	srdi	5, 29, 6
	xor	0, 0, 5
	add	31, 31, 0
	add	31, 31, 24
	addi	6, 6, 0x80
	# Round 0
	rotrdi	0, 11, 14
	rotrdi	5, 11, 18
	xor	0, 0, 5
	rotrdi	5, 11, 41
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	ld	0, 0(6)
	add	15, 15, 16
	add	15, 15, 0
	add	10, 10, 15
	rotrdi	0, 7, 28
	rotrdi	5, 7, 34
	xor	0, 0, 5
	rotrdi	5, 7, 39
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	# Calc new W[0]
	rotrdi	0, 17, 1
	rotrdi	5, 17, 8
	xor	0, 0, 5
	srdi	5, 17, 7
	xor	0, 0, 5
	add	16, 16, 0
	rotrdi	0, 30, 19
	rotrdi	5, 30, 61
	xor	0, 0, 5
	srdi	5, 30, 6
	xor	0, 0, 5
	add	16, 16, 0
	add	16, 16, 25
	# Round 1
	rotrdi	0, 10, 14
	rotrdi	5, 10, 18
	xor	0, 0, 5
	rotrdi	5, 10, 41
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	ld	0, 8(6)
	add	14, 14, 17
	add	14, 14, 0
	add	9, 9, 14
	rotrdi	0, 15, 28
	rotrdi	5, 15, 34
	xor	0, 0, 5
	rotrdi	5, 15, 39
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	# Calc new W[1]
	rotrdi	0, 18, 1
	rotrdi	5, 18, 8
	xor	0, 0, 5
	srdi	5, 18, 7
	xor	0, 0, 5
	add	17, 17, 0
	rotrdi	0, 31, 19
	rotrdi	5, 31, 61
	xor	0, 0, 5
	srdi	5, 31, 6
	xor	0, 0, 5
	add	17, 17, 0
	add	17, 17, 26
	# Round 2
	rotrdi	0, 9, 14
	rotrdi	5, 9, 18
	xor	0, 0, 5
	rotrdi	5, 9, 41
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	ld	0, 16(6)
	add	12, 12, 18
	add	12, 12, 0
	add	8, 8, 12
	rotrdi	0, 14, 28
	rotrdi	5, 14, 34
	xor	0, 0, 5
	rotrdi	5, 14, 39
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	# Calc new W[2]
	rotrdi	0, 19, 1
	rotrdi	5, 19, 8
	xor	0, 0, 5
	srdi	5, 19, 7
	xor	0, 0, 5
	add	18, 18, 0
	rotrdi	0, 16, 19
	rotrdi	5, 16, 61
	xor	0, 0, 5
	srdi	5, 16, 6
	xor	0, 0, 5
	add	18, 18, 0
	add	18, 18, 27
	# Round 3
	rotrdi	0, 8, 14
	rotrdi	5, 8, 18
	xor	0, 0, 5
	rotrdi	5, 8, 41
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	ld	0, 24(6)
	add	11, 11, 19
	add	11, 11, 0
	add	7, 7, 11
	rotrdi	0, 12, 28
	rotrdi	5, 12, 34
	xor	0, 0, 5
	rotrdi	5, 12, 39
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	# Calc new W[3]
	rotrdi	0, 20, 1
	rotrdi	5, 20, 8
	xor	0, 0, 5
	srdi	5, 20, 7
	xor	0, 0, 5
	add	19, 19, 0
	rotrdi	0, 17, 19
	rotrdi	5, 17, 61
	xor	0, 0, 5
	srdi	5, 17, 6
	xor	0, 0, 5
	add	19, 19, 0
	add	19, 19, 28
	# Round 4
	rotrdi	0, 7, 14
	rotrdi	5, 7, 18
	xor	0, 0, 5
	rotrdi	5, 7, 41
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	ld	0, 32(6)
	add	10, 10, 20
	add	10, 10, 0
	add	15, 15, 10
	rotrdi	0, 11, 28
	rotrdi	5, 11, 34
	xor	0, 0, 5
	rotrdi	5, 11, 39
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	# Calc new W[4]
	rotrdi	0, 21, 1
	rotrdi	5, 21, 8
	xor	0, 0, 5
	srdi	5, 21, 7
	xor	0, 0, 5
	add	20, 20, 0
	rotrdi	0, 18, 19
	rotrdi	5, 18, 61
	xor	0, 0, 5
	srdi	5, 18, 6
	xor	0, 0, 5
	add	20, 20, 0
	add	20, 20, 29
	# Round 5
	rotrdi	0, 15, 14
	rotrdi	5, 15, 18
	xor	0, 0, 5
	rotrdi	5, 15, 41
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	ld	0, 40(6)
	add	9, 9, 21
	add	9, 9, 0
	add	14, 14, 9
	rotrdi	0, 10, 28
	rotrdi	5, 10, 34
	xor	0, 0, 5
	rotrdi	5, 10, 39
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	# Calc new W[5]
	rotrdi	0, 22, 1
	rotrdi	5, 22, 8
	xor	0, 0, 5
	srdi	5, 22, 7
	xor	0, 0, 5
	add	21, 21, 0
	rotrdi	0, 19, 19
	rotrdi	5, 19, 61
	xor	0, 0, 5
	srdi	5, 19, 6
	xor	0, 0, 5
	add	21, 21, 0
	add	21, 21, 30
	# Round 6
	rotrdi	0, 14, 14
	rotrdi	5, 14, 18
	xor	0, 0, 5
	rotrdi	5, 14, 41
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	ld	0, 48(6)
	add	8, 8, 22
	add	8, 8, 0
	add	12, 12, 8
	rotrdi	0, 9, 28
	rotrdi	5, 9, 34
	xor	0, 0, 5
	rotrdi	5, 9, 39
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	# Calc new W[6]
	rotrdi	0, 23, 1
	rotrdi	5, 23, 8
	xor	0, 0, 5
	srdi	5, 23, 7
	xor	0, 0, 5
	add	22, 22, 0
	rotrdi	0, 20, 19
	rotrdi	5, 20, 61
	xor	0, 0, 5
	srdi	5, 20, 6
	xor	0, 0, 5
	add	22, 22, 0
	add	22, 22, 31
	# Round 7
	rotrdi	0, 12, 14
	rotrdi	5, 12, 18
	xor	0, 0, 5
	rotrdi	5, 12, 41
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	ld	0, 56(6)
	add	7, 7, 23
	add	7, 7, 0
	add	11, 11, 7
	rotrdi	0, 8, 28
	rotrdi	5, 8, 34
	xor	0, 0, 5
	rotrdi	5, 8, 39
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	# Calc new W[7]
	rotrdi	0, 24, 1
	rotrdi	5, 24, 8
	xor	0, 0, 5
	srdi	5, 24, 7
	xor	0, 0, 5
	add	23, 23, 0
	rotrdi	0, 21, 19
	rotrdi	5, 21, 61
	xor	0, 0, 5
	srdi	5, 21, 6
	xor	0, 0, 5
	add	23, 23, 0
	add	23, 23, 16
	# Round 8
	rotrdi	0, 11, 14
	rotrdi	5, 11, 18
	xor	0, 0, 5
	rotrdi	5, 11, 41
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	ld	0, 64(6)
	add	15, 15, 24
	add	15, 15, 0
	add	10, 10, 15
	rotrdi	0, 7, 28
	rotrdi	5, 7, 34
	xor	0, 0, 5
	rotrdi	5, 7, 39
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	# Calc new W[8]
	rotrdi	0, 25, 1
	rotrdi	5, 25, 8
	xor	0, 0, 5
	srdi	5, 25, 7
	xor	0, 0, 5
	add	24, 24, 0
	rotrdi	0, 22, 19
	rotrdi	5, 22, 61
	xor	0, 0, 5
	srdi	5, 22, 6
	xor	0, 0, 5
	add	24, 24, 0
	add	24, 24, 17
	# Round 9
	rotrdi	0, 10, 14
	rotrdi	5, 10, 18
	xor	0, 0, 5
	rotrdi	5, 10, 41
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	ld	0, 72(6)
	add	14, 14, 25
	add	14, 14, 0
	add	9, 9, 14
	rotrdi	0, 15, 28
	rotrdi	5, 15, 34
	xor	0, 0, 5
	rotrdi	5, 15, 39
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	# Calc new W[9]
	rotrdi	0, 26, 1
	rotrdi	5, 26, 8
	xor	0, 0, 5
	srdi	5, 26, 7
	xor	0, 0, 5
	add	25, 25, 0
	rotrdi	0, 23, 19
	rotrdi	5, 23, 61
	xor	0, 0, 5
	srdi	5, 23, 6
	xor	0, 0, 5
	add	25, 25, 0
	add	25, 25, 18
	# Round 10
	rotrdi	0, 9, 14
	rotrdi	5, 9, 18
	xor	0, 0, 5
	rotrdi	5, 9, 41
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	ld	0, 80(6)
	add	12, 12, 26
	add	12, 12, 0
	add	8, 8, 12
	rotrdi	0, 14, 28
	rotrdi	5, 14, 34
	xor	0, 0, 5
	rotrdi	5, 14, 39
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	# Calc new W[10]
	rotrdi	0, 27, 1
	rotrdi	5, 27, 8
	xor	0, 0, 5
	srdi	5, 27, 7
	xor	0, 0, 5
	add	26, 26, 0
	rotrdi	0, 24, 19
	rotrdi	5, 24, 61
	xor	0, 0, 5
	srdi	5, 24, 6
	xor	0, 0, 5
	add	26, 26, 0
	add	26, 26, 19
	# Round 11
	rotrdi	0, 8, 14
	rotrdi	5, 8, 18
	xor	0, 0, 5
	rotrdi	5, 8, 41
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	ld	0, 88(6)
	add	11, 11, 27
	add	11, 11, 0
	add	7, 7, 11
	rotrdi	0, 12, 28
	rotrdi	5, 12, 34
	xor	0, 0, 5
	rotrdi	5, 12, 39
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	# Calc new W[11]
	rotrdi	0, 28, 1
	rotrdi	5, 28, 8
	xor	0, 0, 5
	srdi	5, 28, 7
	xor	0, 0, 5
	add	27, 27, 0
	rotrdi	0, 25, 19
	rotrdi	5, 25, 61
	xor	0, 0, 5
	srdi	5, 25, 6
	xor	0, 0, 5
	add	27, 27, 0
	add	27, 27, 20
	# Round 12
	rotrdi	0, 7, 14
	rotrdi	5, 7, 18
	xor	0, 0, 5
	rotrdi	5, 7, 41
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	ld	0, 96(6)
	add	10, 10, 28
	add	10, 10, 0
	add	15, 15, 10
	rotrdi	0, 11, 28
	rotrdi	5, 11, 34
	xor	0, 0, 5
	rotrdi	5, 11, 39
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	# Calc new W[12]
	rotrdi	0, 29, 1
	rotrdi	5, 29, 8
	xor	0, 0, 5
	srdi	5, 29, 7
	xor	0, 0, 5
	add	28, 28, 0
	rotrdi	0, 26, 19
	rotrdi	5, 26, 61
	xor	0, 0, 5
	srdi	5, 26, 6
	xor	0, 0, 5
	add	28, 28, 0
	add	28, 28, 21
	# Round 13
	rotrdi	0, 15, 14
	rotrdi	5, 15, 18
	xor	0, 0, 5
	rotrdi	5, 15, 41
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	ld	0, 104(6)
	add	9, 9, 29
	add	9, 9, 0
	add	14, 14, 9
	rotrdi	0, 10, 28
	rotrdi	5, 10, 34
	xor	0, 0, 5
	rotrdi	5, 10, 39
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	# Calc new W[13]
	rotrdi	0, 30, 1
	rotrdi	5, 30, 8
	xor	0, 0, 5
	srdi	5, 30, 7
	xor	0, 0, 5
	add	29, 29, 0
	rotrdi	0, 27, 19
	rotrdi	5, 27, 61
	xor	0, 0, 5
	srdi	5, 27, 6
	xor	0, 0, 5
	add	29, 29, 0
	add	29, 29, 22
	# Round 14
	rotrdi	0, 14, 14
	rotrdi	5, 14, 18
	xor	0, 0, 5
	rotrdi	5, 14, 41
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	ld	0, 112(6)
	add	8, 8, 30
	add	8, 8, 0
	add	12, 12, 8
	rotrdi	0, 9, 28
	rotrdi	5, 9, 34
	xor	0, 0, 5
	rotrdi	5, 9, 39
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	# Calc new W[14]
	rotrdi	0, 31, 1
	rotrdi	5, 31, 8
	xor	0, 0, 5
	srdi	5, 31, 7
	xor	0, 0, 5
	add	30, 30, 0
	rotrdi	0, 28, 19
	rotrdi	5, 28, 61
	xor	0, 0, 5
	srdi	5, 28, 6
	xor	0, 0, 5
	add	30, 30, 0
	add	30, 30, 23
	# Round 15
	rotrdi	0, 12, 14
	rotrdi	5, 12, 18
	xor	0, 0, 5
	rotrdi	5, 12, 41
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	ld	0, 120(6)
	add	7, 7, 31
	add	7, 7, 0
	add	11, 11, 7
	rotrdi	0, 8, 28
	rotrdi	5, 8, 34
	xor	0, 0, 5
	rotrdi	5, 8, 39
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	# Calc new W[15]
	rotrdi	0, 16, 1
	rotrdi	5, 16, 8
	xor	0, 0, 5
	srdi	5, 16, 7
	xor	0, 0, 5
	add	31, 31, 0
	rotrdi	0, 29, 19
	rotrdi	5, 29, 61
	xor	0, 0, 5
	srdi	5, 29, 6
	xor	0, 0, 5
	add	31, 31, 0
	add	31, 31, 24
	addi	6, 6, 0x80
	# Round 0
	rotrdi	0, 11, 14
	rotrdi	5, 11, 18
	xor	0, 0, 5
	rotrdi	5, 11, 41
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	ld	0, 0(6)
	add	15, 15, 16
	add	15, 15, 0
	add	10, 10, 15
	rotrdi	0, 7, 28
	rotrdi	5, 7, 34
	xor	0, 0, 5
	rotrdi	5, 7, 39
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	# Calc new W[0]
	rotrdi	0, 17, 1
	rotrdi	5, 17, 8
	xor	0, 0, 5
	srdi	5, 17, 7
	xor	0, 0, 5
	add	16, 16, 0
	rotrdi	0, 30, 19
	rotrdi	5, 30, 61
	xor	0, 0, 5
	srdi	5, 30, 6
	xor	0, 0, 5
	add	16, 16, 0
	add	16, 16, 25
	# Round 1
	rotrdi	0, 10, 14
	rotrdi	5, 10, 18
	xor	0, 0, 5
	rotrdi	5, 10, 41
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	ld	0, 8(6)
	add	14, 14, 17
	add	14, 14, 0
	add	9, 9, 14
	rotrdi	0, 15, 28
	rotrdi	5, 15, 34
	xor	0, 0, 5
	rotrdi	5, 15, 39
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	# Calc new W[1]
	rotrdi	0, 18, 1
	rotrdi	5, 18, 8
	xor	0, 0, 5
	srdi	5, 18, 7
	xor	0, 0, 5
	add	17, 17, 0
	rotrdi	0, 31, 19
	rotrdi	5, 31, 61
	xor	0, 0, 5
	srdi	5, 31, 6
	xor	0, 0, 5
	add	17, 17, 0
	add	17, 17, 26
	# Round 2
	rotrdi	0, 9, 14
	rotrdi	5, 9, 18
	xor	0, 0, 5
	rotrdi	5, 9, 41
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	ld	0, 16(6)
	add	12, 12, 18
	add	12, 12, 0
	add	8, 8, 12
	rotrdi	0, 14, 28
	rotrdi	5, 14, 34
	xor	0, 0, 5
	rotrdi	5, 14, 39
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	# Calc new W[2]
	rotrdi	0, 19, 1
	rotrdi	5, 19, 8
	xor	0, 0, 5
	srdi	5, 19, 7
	xor	0, 0, 5
	add	18, 18, 0
	rotrdi	0, 16, 19
	rotrdi	5, 16, 61
	xor	0, 0, 5
	srdi	5, 16, 6
	xor	0, 0, 5
	add	18, 18, 0
	add	18, 18, 27
	# Round 3
	rotrdi	0, 8, 14
	rotrdi	5, 8, 18
	xor	0, 0, 5
	rotrdi	5, 8, 41
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	ld	0, 24(6)
	add	11, 11, 19
	add	11, 11, 0
	add	7, 7, 11
	rotrdi	0, 12, 28
	rotrdi	5, 12, 34
	xor	0, 0, 5
	rotrdi	5, 12, 39
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	# Calc new W[3]
	rotrdi	0, 20, 1
	rotrdi	5, 20, 8
	xor	0, 0, 5
	srdi	5, 20, 7
	xor	0, 0, 5
	add	19, 19, 0
	rotrdi	0, 17, 19
	rotrdi	5, 17, 61
	xor	0, 0, 5
	srdi	5, 17, 6
	xor	0, 0, 5
	add	19, 19, 0
	add	19, 19, 28
	# Round 4
	rotrdi	0, 7, 14
	rotrdi	5, 7, 18
	xor	0, 0, 5
	rotrdi	5, 7, 41
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	ld	0, 32(6)
	add	10, 10, 20
	add	10, 10, 0
	add	15, 15, 10
	rotrdi	0, 11, 28
	rotrdi	5, 11, 34
	xor	0, 0, 5
	rotrdi	5, 11, 39
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	# Calc new W[4]
	rotrdi	0, 21, 1
	rotrdi	5, 21, 8
	xor	0, 0, 5
	srdi	5, 21, 7
	xor	0, 0, 5
	add	20, 20, 0
	rotrdi	0, 18, 19
	rotrdi	5, 18, 61
	xor	0, 0, 5
	srdi	5, 18, 6
	xor	0, 0, 5
	add	20, 20, 0
	add	20, 20, 29
	# Round 5
	rotrdi	0, 15, 14
	rotrdi	5, 15, 18
	xor	0, 0, 5
	rotrdi	5, 15, 41
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	ld	0, 40(6)
	add	9, 9, 21
	add	9, 9, 0
	add	14, 14, 9
	rotrdi	0, 10, 28
	rotrdi	5, 10, 34
	xor	0, 0, 5
	rotrdi	5, 10, 39
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	# Calc new W[5]
	rotrdi	0, 22, 1
	rotrdi	5, 22, 8
	xor	0, 0, 5
	srdi	5, 22, 7
	xor	0, 0, 5
	add	21, 21, 0
	rotrdi	0, 19, 19
	rotrdi	5, 19, 61
	xor	0, 0, 5
	srdi	5, 19, 6
	xor	0, 0, 5
	add	21, 21, 0
	add	21, 21, 30
	# Round 6
	rotrdi	0, 14, 14
	rotrdi	5, 14, 18
	xor	0, 0, 5
	rotrdi	5, 14, 41
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	ld	0, 48(6)
	add	8, 8, 22
	add	8, 8, 0
	add	12, 12, 8
	rotrdi	0, 9, 28
	rotrdi	5, 9, 34
	xor	0, 0, 5
	rotrdi	5, 9, 39
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	# Calc new W[6]
	rotrdi	0, 23, 1
	rotrdi	5, 23, 8
	xor	0, 0, 5
	srdi	5, 23, 7
	xor	0, 0, 5
	add	22, 22, 0
	rotrdi	0, 20, 19
	rotrdi	5, 20, 61
	xor	0, 0, 5
	srdi	5, 20, 6
	xor	0, 0, 5
	add	22, 22, 0
	add	22, 22, 31
	# Round 7
	rotrdi	0, 12, 14
	rotrdi	5, 12, 18
	xor	0, 0, 5
	rotrdi	5, 12, 41
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	ld	0, 56(6)
	add	7, 7, 23
	add	7, 7, 0
	add	11, 11, 7
	rotrdi	0, 8, 28
	rotrdi	5, 8, 34
	xor	0, 0, 5
	rotrdi	5, 8, 39
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	# Calc new W[7]
	rotrdi	0, 24, 1
	rotrdi	5, 24, 8
	xor	0, 0, 5
	srdi	5, 24, 7
	xor	0, 0, 5
	add	23, 23, 0
	rotrdi	0, 21, 19
	rotrdi	5, 21, 61
	xor	0, 0, 5
	srdi	5, 21, 6
	xor	0, 0, 5
	add	23, 23, 0
	add	23, 23, 16
	# Round 8
	rotrdi	0, 11, 14
	rotrdi	5, 11, 18
	xor	0, 0, 5
	rotrdi	5, 11, 41
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	ld	0, 64(6)
	add	15, 15, 24
	add	15, 15, 0
	add	10, 10, 15
	rotrdi	0, 7, 28
	rotrdi	5, 7, 34
	xor	0, 0, 5
	rotrdi	5, 7, 39
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	# Calc new W[8]
	rotrdi	0, 25, 1
	rotrdi	5, 25, 8
	xor	0, 0, 5
	srdi	5, 25, 7
	xor	0, 0, 5
	add	24, 24, 0
	rotrdi	0, 22, 19
	rotrdi	5, 22, 61
	xor	0, 0, 5
	srdi	5, 22, 6
	xor	0, 0, 5
	add	24, 24, 0
	add	24, 24, 17
	# Round 9
	rotrdi	0, 10, 14
	rotrdi	5, 10, 18
	xor	0, 0, 5
	rotrdi	5, 10, 41
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	ld	0, 72(6)
	add	14, 14, 25
	add	14, 14, 0
	add	9, 9, 14
	rotrdi	0, 15, 28
	rotrdi	5, 15, 34
	xor	0, 0, 5
	rotrdi	5, 15, 39
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	# Calc new W[9]
	rotrdi	0, 26, 1
	rotrdi	5, 26, 8
	xor	0, 0, 5
	srdi	5, 26, 7
	xor	0, 0, 5
	add	25, 25, 0
	rotrdi	0, 23, 19
	rotrdi	5, 23, 61
	xor	0, 0, 5
	srdi	5, 23, 6
	xor	0, 0, 5
	add	25, 25, 0
	add	25, 25, 18
	# Round 10
	rotrdi	0, 9, 14
	rotrdi	5, 9, 18
	xor	0, 0, 5
	rotrdi	5, 9, 41
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	ld	0, 80(6)
	add	12, 12, 26
	add	12, 12, 0
	add	8, 8, 12
	rotrdi	0, 14, 28
	rotrdi	5, 14, 34
	xor	0, 0, 5
	rotrdi	5, 14, 39
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	# Calc new W[10]
	rotrdi	0, 27, 1
	rotrdi	5, 27, 8
	xor	0, 0, 5
	srdi	5, 27, 7
	xor	0, 0, 5
	add	26, 26, 0
	rotrdi	0, 24, 19
	rotrdi	5, 24, 61
	xor	0, 0, 5
	srdi	5, 24, 6
	xor	0, 0, 5
	add	26, 26, 0
	add	26, 26, 19
	# Round 11
	rotrdi	0, 8, 14
	rotrdi	5, 8, 18
	xor	0, 0, 5
	rotrdi	5, 8, 41
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	ld	0, 88(6)
	add	11, 11, 27
	add	11, 11, 0
	add	7, 7, 11
	rotrdi	0, 12, 28
	rotrdi	5, 12, 34
	xor	0, 0, 5
	rotrdi	5, 12, 39
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	# Calc new W[11]
	rotrdi	0, 28, 1
	rotrdi	5, 28, 8
	xor	0, 0, 5
	srdi	5, 28, 7
	xor	0, 0, 5
	add	27, 27, 0
	rotrdi	0, 25, 19
	rotrdi	5, 25, 61
	xor	0, 0, 5
	srdi	5, 25, 6
	xor	0, 0, 5
	add	27, 27, 0
	add	27, 27, 20
	# Round 12
	rotrdi	0, 7, 14
	rotrdi	5, 7, 18
	xor	0, 0, 5
	rotrdi	5, 7, 41
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	ld	0, 96(6)
	add	10, 10, 28
	add	10, 10, 0
	add	15, 15, 10
	rotrdi	0, 11, 28
	rotrdi	5, 11, 34
	xor	0, 0, 5
	rotrdi	5, 11, 39
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	# Calc new W[12]
	rotrdi	0, 29, 1
	rotrdi	5, 29, 8
	xor	0, 0, 5
	srdi	5, 29, 7
	xor	0, 0, 5
	add	28, 28, 0
	rotrdi	0, 26, 19
	rotrdi	5, 26, 61
	xor	0, 0, 5
	srdi	5, 26, 6
	xor	0, 0, 5
	add	28, 28, 0
	add	28, 28, 21
	# Round 13
	rotrdi	0, 15, 14
	rotrdi	5, 15, 18
	xor	0, 0, 5
	rotrdi	5, 15, 41
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	ld	0, 104(6)
	add	9, 9, 29
	add	9, 9, 0
	add	14, 14, 9
	rotrdi	0, 10, 28
	rotrdi	5, 10, 34
	xor	0, 0, 5
	rotrdi	5, 10, 39
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	# Calc new W[13]
	rotrdi	0, 30, 1
	rotrdi	5, 30, 8
	xor	0, 0, 5
	srdi	5, 30, 7
	xor	0, 0, 5
	add	29, 29, 0
	rotrdi	0, 27, 19
	rotrdi	5, 27, 61
	xor	0, 0, 5
	srdi	5, 27, 6
	xor	0, 0, 5
	add	29, 29, 0
	add	29, 29, 22
	# Round 14
	rotrdi	0, 14, 14
	rotrdi	5, 14, 18
	xor	0, 0, 5
	rotrdi	5, 14, 41
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	ld	0, 112(6)
	add	8, 8, 30
	add	8, 8, 0
	add	12, 12, 8
	rotrdi	0, 9, 28
	rotrdi	5, 9, 34
	xor	0, 0, 5
	rotrdi	5, 9, 39
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	# Calc new W[14]
	rotrdi	0, 31, 1
	rotrdi	5, 31, 8
	xor	0, 0, 5
	srdi	5, 31, 7
	xor	0, 0, 5
	add	30, 30, 0
	rotrdi	0, 28, 19
	rotrdi	5, 28, 61
	xor	0, 0, 5
	srdi	5, 28, 6
	xor	0, 0, 5
	add	30, 30, 0
	add	30, 30, 23
	# Round 15
	rotrdi	0, 12, 14
	rotrdi	5, 12, 18
	xor	0, 0, 5
	rotrdi	5, 12, 41
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	ld	0, 120(6)
	add	7, 7, 31
	add	7, 7, 0
	add	11, 11, 7
	rotrdi	0, 8, 28
	rotrdi	5, 8, 34
	xor	0, 0, 5
	rotrdi	5, 8, 39
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	# Calc new W[15]
	rotrdi	0, 16, 1
	rotrdi	5, 16, 8
	xor	0, 0, 5
	srdi	5, 16, 7
	xor	0, 0, 5
	add	31, 31, 0
	rotrdi	0, 29, 19
	rotrdi	5, 29, 61
	xor	0, 0, 5
	srdi	5, 29, 6
	xor	0, 0, 5
	add	31, 31, 0
	add	31, 31, 24
	addi	6, 6, 0x80
	# Round 0
	rotrdi	0, 11, 14
	rotrdi	5, 11, 18
	xor	0, 0, 5
	rotrdi	5, 11, 41
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	ld	0, 0(6)
	add	15, 15, 16
	add	15, 15, 0
	add	10, 10, 15
	rotrdi	0, 7, 28
	rotrdi	5, 7, 34
	xor	0, 0, 5
	rotrdi	5, 7, 39
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	# Round 1
	rotrdi	0, 10, 14
	rotrdi	5, 10, 18
	xor	0, 0, 5
	rotrdi	5, 10, 41
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	ld	0, 8(6)
	add	14, 14, 17
	add	14, 14, 0
	add	9, 9, 14
	rotrdi	0, 15, 28
	rotrdi	5, 15, 34
	xor	0, 0, 5
	rotrdi	5, 15, 39
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	# Round 2
	rotrdi	0, 9, 14
	rotrdi	5, 9, 18
	xor	0, 0, 5
	rotrdi	5, 9, 41
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	ld	0, 16(6)
	add	12, 12, 18
	add	12, 12, 0
	add	8, 8, 12
	rotrdi	0, 14, 28
	rotrdi	5, 14, 34
	xor	0, 0, 5
	rotrdi	5, 14, 39
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	# Round 3
	rotrdi	0, 8, 14
	rotrdi	5, 8, 18
	xor	0, 0, 5
	rotrdi	5, 8, 41
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	ld	0, 24(6)
	add	11, 11, 19
	add	11, 11, 0
	add	7, 7, 11
	rotrdi	0, 12, 28
	rotrdi	5, 12, 34
	xor	0, 0, 5
	rotrdi	5, 12, 39
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	# Round 4
	rotrdi	0, 7, 14
	rotrdi	5, 7, 18
	xor	0, 0, 5
	rotrdi	5, 7, 41
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	ld	0, 32(6)
	add	10, 10, 20
	add	10, 10, 0
	add	15, 15, 10
	rotrdi	0, 11, 28
	rotrdi	5, 11, 34
	xor	0, 0, 5
	rotrdi	5, 11, 39
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	# Round 5
	rotrdi	0, 15, 14
	rotrdi	5, 15, 18
	xor	0, 0, 5
	rotrdi	5, 15, 41
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	ld	0, 40(6)
	add	9, 9, 21
	add	9, 9, 0
	add	14, 14, 9
	rotrdi	0, 10, 28
	rotrdi	5, 10, 34
	xor	0, 0, 5
	rotrdi	5, 10, 39
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	# Round 6
	rotrdi	0, 14, 14
	rotrdi	5, 14, 18
	xor	0, 0, 5
	rotrdi	5, 14, 41
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	ld	0, 48(6)
	add	8, 8, 22
	add	8, 8, 0
	add	12, 12, 8
	rotrdi	0, 9, 28
	rotrdi	5, 9, 34
	xor	0, 0, 5
	rotrdi	5, 9, 39
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	# Round 7
	rotrdi	0, 12, 14
	rotrdi	5, 12, 18
	xor	0, 0, 5
	rotrdi	5, 12, 41
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	ld	0, 56(6)
	add	7, 7, 23
	add	7, 7, 0
	add	11, 11, 7
	rotrdi	0, 8, 28
	rotrdi	5, 8, 34
	xor	0, 0, 5
	rotrdi	5, 8, 39
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	# Round 8
	rotrdi	0, 11, 14
	rotrdi	5, 11, 18
	xor	0, 0, 5
	rotrdi	5, 11, 41
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	ld	0, 64(6)
	add	15, 15, 24
	add	15, 15, 0
	add	10, 10, 15
	rotrdi	0, 7, 28
	rotrdi	5, 7, 34
	xor	0, 0, 5
	rotrdi	5, 7, 39
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	# Round 9
	rotrdi	0, 10, 14
	rotrdi	5, 10, 18
	xor	0, 0, 5
	rotrdi	5, 10, 41
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	ld	0, 72(6)
	add	14, 14, 25
	add	14, 14, 0
	add	9, 9, 14
	rotrdi	0, 15, 28
	rotrdi	5, 15, 34
	xor	0, 0, 5
	rotrdi	5, 15, 39
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	# Round 10
	rotrdi	0, 9, 14
	rotrdi	5, 9, 18
	xor	0, 0, 5
	rotrdi	5, 9, 41
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	ld	0, 80(6)
	add	12, 12, 26
	add	12, 12, 0
	add	8, 8, 12
	rotrdi	0, 14, 28
	rotrdi	5, 14, 34
	xor	0, 0, 5
	rotrdi	5, 14, 39
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	# Round 11
	rotrdi	0, 8, 14
	rotrdi	5, 8, 18
	xor	0, 0, 5
	rotrdi	5, 8, 41
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	ld	0, 88(6)
	add	11, 11, 27
	add	11, 11, 0
	add	7, 7, 11
	rotrdi	0, 12, 28
	rotrdi	5, 12, 34
	xor	0, 0, 5
	rotrdi	5, 12, 39
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	# Round 12
	rotrdi	0, 7, 14
	rotrdi	5, 7, 18
	xor	0, 0, 5
	rotrdi	5, 7, 41
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	ld	0, 96(6)
	add	10, 10, 28
	add	10, 10, 0
	add	15, 15, 10
	rotrdi	0, 11, 28
	rotrdi	5, 11, 34
	xor	0, 0, 5
	rotrdi	5, 11, 39
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	# Round 13
	rotrdi	0, 15, 14
	rotrdi	5, 15, 18
	xor	0, 0, 5
	rotrdi	5, 15, 41
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	ld	0, 104(6)
	add	9, 9, 29
	add	9, 9, 0
	add	14, 14, 9
	rotrdi	0, 10, 28
	rotrdi	5, 10, 34
	xor	0, 0, 5
	rotrdi	5, 10, 39
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	# Round 14
	rotrdi	0, 14, 14
	rotrdi	5, 14, 18
	xor	0, 0, 5
	rotrdi	5, 14, 41
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	ld	0, 112(6)
	add	8, 8, 30
	add	8, 8, 0
	add	12, 12, 8
	rotrdi	0, 9, 28
	rotrdi	5, 9, 34
	xor	0, 0, 5
	rotrdi	5, 9, 39
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	# Round 15
	rotrdi	0, 12, 14
	rotrdi	5, 12, 18
	xor	0, 0, 5
	rotrdi	5, 12, 41
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	ld	0, 120(6)
	add	7, 7, 31
	add	7, 7, 0
	add	11, 11, 7
	rotrdi	0, 8, 28
	rotrdi	5, 8, 34
	xor	0, 0, 5
	rotrdi	5, 8, 39
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	subi	6, 6, 0x200
	# Add in digest from start
	ld	0, 0(3)
	ld	5, 8(3)
	add	7, 7, 0
	add	8, 8, 5
	ld	0, 16(3)
	ld	5, 24(3)
	add	9, 9, 0
	add	10, 10, 5
	ld	0, 32(3)
	ld	5, 40(3)
	add	11, 11, 0
	add	12, 12, 5
	ld	0, 48(3)
	ld	5, 56(3)
	add	14, 14, 0
	add	15, 15, 5
	std	7, 0(3)
	std	8, 8(3)
	std	9, 16(3)
	std	10, 24(3)
	std	11, 32(3)
	std	12, 40(3)
	std	14, 48(3)
	std	15, 56(3)
	addi	4, 4, 0x80
	bdnz	L_SHA512_transform_len_begin
#else
	subi	1, 1, 16
	stw	5, 0(1)
	# Start of loop processing a block
L_SHA512_transform_len_begin:
	# Load W - 128 bytes
#ifdef __LITTLE_ENDIAN__
	li	0, 0
	ldbrx	16, 4, 0
	li	0, 8
	ldbrx	17, 4, 0
	li	0, 16
	ldbrx	18, 4, 0
	li	0, 24
	ldbrx	19, 4, 0
	li	0, 32
	ldbrx	20, 4, 0
	li	0, 40
	ldbrx	21, 4, 0
	li	0, 48
	ldbrx	22, 4, 0
	li	0, 56
	ldbrx	23, 4, 0
	li	0, 0x40
	ldbrx	24, 4, 0
	li	0, 0x48
	ldbrx	25, 4, 0
	li	0, 0x50
	ldbrx	26, 4, 0
	li	0, 0x58
	ldbrx	27, 4, 0
	li	0, 0x60
	ldbrx	28, 4, 0
	li	0, 0x68
	ldbrx	29, 4, 0
	li	0, 0x70
	ldbrx	30, 4, 0
	li	0, 0x78
	ldbrx	31, 4, 0
#else
	ld	16, 0(4)
	ld	17, 8(4)
	ld	18, 16(4)
	ld	19, 24(4)
	ld	20, 32(4)
	ld	21, 40(4)
	ld	22, 48(4)
	ld	23, 56(4)
	ld	24, 64(4)
	ld	25, 72(4)
	ld	26, 80(4)
	ld	27, 88(4)
	ld	28, 96(4)
	ld	29, 104(4)
	ld	30, 112(4)
	ld	31, 120(4)
#endif /* __LITTLE_ENDIAN__ */
	li	0, 5
	mtctr	0
	# Start of 80 rounds
L_SHA512_transform_len_start:
	# Round 0
	rotrdi	0, 11, 14
	rotrdi	5, 11, 18
	xor	0, 0, 5
	rotrdi	5, 11, 41
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	ld	0, 0(6)
	add	15, 15, 16
	add	15, 15, 0
	add	10, 10, 15
	rotrdi	0, 7, 28
	rotrdi	5, 7, 34
	xor	0, 0, 5
	rotrdi	5, 7, 39
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA512_transform_len_after_blk_0
	# Calc new W[0]
	rotrdi	0, 17, 1
	rotrdi	5, 17, 8
	xor	0, 0, 5
	srdi	5, 17, 7
	xor	0, 0, 5
	add	16, 16, 0
	rotrdi	0, 30, 19
	rotrdi	5, 30, 61
	xor	0, 0, 5
	srdi	5, 30, 6
	xor	0, 0, 5
	add	16, 16, 0
	add	16, 16, 25
L_SHA512_transform_len_after_blk_0:
	# Round 1
	rotrdi	0, 10, 14
	rotrdi	5, 10, 18
	xor	0, 0, 5
	rotrdi	5, 10, 41
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	ld	0, 8(6)
	add	14, 14, 17
	add	14, 14, 0
	add	9, 9, 14
	rotrdi	0, 15, 28
	rotrdi	5, 15, 34
	xor	0, 0, 5
	rotrdi	5, 15, 39
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA512_transform_len_after_blk_1
	# Calc new W[1]
	rotrdi	0, 18, 1
	rotrdi	5, 18, 8
	xor	0, 0, 5
	srdi	5, 18, 7
	xor	0, 0, 5
	add	17, 17, 0
	rotrdi	0, 31, 19
	rotrdi	5, 31, 61
	xor	0, 0, 5
	srdi	5, 31, 6
	xor	0, 0, 5
	add	17, 17, 0
	add	17, 17, 26
L_SHA512_transform_len_after_blk_1:
	# Round 2
	rotrdi	0, 9, 14
	rotrdi	5, 9, 18
	xor	0, 0, 5
	rotrdi	5, 9, 41
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	ld	0, 16(6)
	add	12, 12, 18
	add	12, 12, 0
	add	8, 8, 12
	rotrdi	0, 14, 28
	rotrdi	5, 14, 34
	xor	0, 0, 5
	rotrdi	5, 14, 39
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA512_transform_len_after_blk_2
	# Calc new W[2]
	rotrdi	0, 19, 1
	rotrdi	5, 19, 8
	xor	0, 0, 5
	srdi	5, 19, 7
	xor	0, 0, 5
	add	18, 18, 0
	rotrdi	0, 16, 19
	rotrdi	5, 16, 61
	xor	0, 0, 5
	srdi	5, 16, 6
	xor	0, 0, 5
	add	18, 18, 0
	add	18, 18, 27
L_SHA512_transform_len_after_blk_2:
	# Round 3
	rotrdi	0, 8, 14
	rotrdi	5, 8, 18
	xor	0, 0, 5
	rotrdi	5, 8, 41
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	ld	0, 24(6)
	add	11, 11, 19
	add	11, 11, 0
	add	7, 7, 11
	rotrdi	0, 12, 28
	rotrdi	5, 12, 34
	xor	0, 0, 5
	rotrdi	5, 12, 39
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA512_transform_len_after_blk_3
	# Calc new W[3]
	rotrdi	0, 20, 1
	rotrdi	5, 20, 8
	xor	0, 0, 5
	srdi	5, 20, 7
	xor	0, 0, 5
	add	19, 19, 0
	rotrdi	0, 17, 19
	rotrdi	5, 17, 61
	xor	0, 0, 5
	srdi	5, 17, 6
	xor	0, 0, 5
	add	19, 19, 0
	add	19, 19, 28
L_SHA512_transform_len_after_blk_3:
	# Round 4
	rotrdi	0, 7, 14
	rotrdi	5, 7, 18
	xor	0, 0, 5
	rotrdi	5, 7, 41
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	ld	0, 32(6)
	add	10, 10, 20
	add	10, 10, 0
	add	15, 15, 10
	rotrdi	0, 11, 28
	rotrdi	5, 11, 34
	xor	0, 0, 5
	rotrdi	5, 11, 39
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA512_transform_len_after_blk_4
	# Calc new W[4]
	rotrdi	0, 21, 1
	rotrdi	5, 21, 8
	xor	0, 0, 5
	srdi	5, 21, 7
	xor	0, 0, 5
	add	20, 20, 0
	rotrdi	0, 18, 19
	rotrdi	5, 18, 61
	xor	0, 0, 5
	srdi	5, 18, 6
	xor	0, 0, 5
	add	20, 20, 0
	add	20, 20, 29
L_SHA512_transform_len_after_blk_4:
	# Round 5
	rotrdi	0, 15, 14
	rotrdi	5, 15, 18
	xor	0, 0, 5
	rotrdi	5, 15, 41
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	ld	0, 40(6)
	add	9, 9, 21
	add	9, 9, 0
	add	14, 14, 9
	rotrdi	0, 10, 28
	rotrdi	5, 10, 34
	xor	0, 0, 5
	rotrdi	5, 10, 39
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA512_transform_len_after_blk_5
	# Calc new W[5]
	rotrdi	0, 22, 1
	rotrdi	5, 22, 8
	xor	0, 0, 5
	srdi	5, 22, 7
	xor	0, 0, 5
	add	21, 21, 0
	rotrdi	0, 19, 19
	rotrdi	5, 19, 61
	xor	0, 0, 5
	srdi	5, 19, 6
	xor	0, 0, 5
	add	21, 21, 0
	add	21, 21, 30
L_SHA512_transform_len_after_blk_5:
	# Round 6
	rotrdi	0, 14, 14
	rotrdi	5, 14, 18
	xor	0, 0, 5
	rotrdi	5, 14, 41
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	ld	0, 48(6)
	add	8, 8, 22
	add	8, 8, 0
	add	12, 12, 8
	rotrdi	0, 9, 28
	rotrdi	5, 9, 34
	xor	0, 0, 5
	rotrdi	5, 9, 39
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA512_transform_len_after_blk_6
	# Calc new W[6]
	rotrdi	0, 23, 1
	rotrdi	5, 23, 8
	xor	0, 0, 5
	srdi	5, 23, 7
	xor	0, 0, 5
	add	22, 22, 0
	rotrdi	0, 20, 19
	rotrdi	5, 20, 61
	xor	0, 0, 5
	srdi	5, 20, 6
	xor	0, 0, 5
	add	22, 22, 0
	add	22, 22, 31
L_SHA512_transform_len_after_blk_6:
	# Round 7
	rotrdi	0, 12, 14
	rotrdi	5, 12, 18
	xor	0, 0, 5
	rotrdi	5, 12, 41
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	ld	0, 56(6)
	add	7, 7, 23
	add	7, 7, 0
	add	11, 11, 7
	rotrdi	0, 8, 28
	rotrdi	5, 8, 34
	xor	0, 0, 5
	rotrdi	5, 8, 39
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA512_transform_len_after_blk_7
	# Calc new W[7]
	rotrdi	0, 24, 1
	rotrdi	5, 24, 8
	xor	0, 0, 5
	srdi	5, 24, 7
	xor	0, 0, 5
	add	23, 23, 0
	rotrdi	0, 21, 19
	rotrdi	5, 21, 61
	xor	0, 0, 5
	srdi	5, 21, 6
	xor	0, 0, 5
	add	23, 23, 0
	add	23, 23, 16
L_SHA512_transform_len_after_blk_7:
	# Round 8
	rotrdi	0, 11, 14
	rotrdi	5, 11, 18
	xor	0, 0, 5
	rotrdi	5, 11, 41
	xor	0, 0, 5
	add	15, 15, 0
	xor	0, 12, 14
	and	0, 0, 11
	xor	0, 0, 14
	add	15, 15, 0
	ld	0, 64(6)
	add	15, 15, 24
	add	15, 15, 0
	add	10, 10, 15
	rotrdi	0, 7, 28
	rotrdi	5, 7, 34
	xor	0, 0, 5
	rotrdi	5, 7, 39
	xor	0, 0, 5
	add	15, 15, 0
	xor	5, 7, 8
	xor	0, 8, 9
	and	0, 0, 5
	xor	0, 0, 8
	add	15, 15, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA512_transform_len_after_blk_8
	# Calc new W[8]
	rotrdi	0, 25, 1
	rotrdi	5, 25, 8
	xor	0, 0, 5
	srdi	5, 25, 7
	xor	0, 0, 5
	add	24, 24, 0
	rotrdi	0, 22, 19
	rotrdi	5, 22, 61
	xor	0, 0, 5
	srdi	5, 22, 6
	xor	0, 0, 5
	add	24, 24, 0
	add	24, 24, 17
L_SHA512_transform_len_after_blk_8:
	# Round 9
	rotrdi	0, 10, 14
	rotrdi	5, 10, 18
	xor	0, 0, 5
	rotrdi	5, 10, 41
	xor	0, 0, 5
	add	14, 14, 0
	xor	0, 11, 12
	and	0, 0, 10
	xor	0, 0, 12
	add	14, 14, 0
	ld	0, 72(6)
	add	14, 14, 25
	add	14, 14, 0
	add	9, 9, 14
	rotrdi	0, 15, 28
	rotrdi	5, 15, 34
	xor	0, 0, 5
	rotrdi	5, 15, 39
	xor	0, 0, 5
	add	14, 14, 0
	xor	5, 15, 7
	xor	0, 7, 8
	and	0, 0, 5
	xor	0, 0, 7
	add	14, 14, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA512_transform_len_after_blk_9
	# Calc new W[9]
	rotrdi	0, 26, 1
	rotrdi	5, 26, 8
	xor	0, 0, 5
	srdi	5, 26, 7
	xor	0, 0, 5
	add	25, 25, 0
	rotrdi	0, 23, 19
	rotrdi	5, 23, 61
	xor	0, 0, 5
	srdi	5, 23, 6
	xor	0, 0, 5
	add	25, 25, 0
	add	25, 25, 18
L_SHA512_transform_len_after_blk_9:
	# Round 10
	rotrdi	0, 9, 14
	rotrdi	5, 9, 18
	xor	0, 0, 5
	rotrdi	5, 9, 41
	xor	0, 0, 5
	add	12, 12, 0
	xor	0, 10, 11
	and	0, 0, 9
	xor	0, 0, 11
	add	12, 12, 0
	ld	0, 80(6)
	add	12, 12, 26
	add	12, 12, 0
	add	8, 8, 12
	rotrdi	0, 14, 28
	rotrdi	5, 14, 34
	xor	0, 0, 5
	rotrdi	5, 14, 39
	xor	0, 0, 5
	add	12, 12, 0
	xor	5, 14, 15
	xor	0, 15, 7
	and	0, 0, 5
	xor	0, 0, 15
	add	12, 12, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA512_transform_len_after_blk_10
	# Calc new W[10]
	rotrdi	0, 27, 1
	rotrdi	5, 27, 8
	xor	0, 0, 5
	srdi	5, 27, 7
	xor	0, 0, 5
	add	26, 26, 0
	rotrdi	0, 24, 19
	rotrdi	5, 24, 61
	xor	0, 0, 5
	srdi	5, 24, 6
	xor	0, 0, 5
	add	26, 26, 0
	add	26, 26, 19
L_SHA512_transform_len_after_blk_10:
	# Round 11
	rotrdi	0, 8, 14
	rotrdi	5, 8, 18
	xor	0, 0, 5
	rotrdi	5, 8, 41
	xor	0, 0, 5
	add	11, 11, 0
	xor	0, 9, 10
	and	0, 0, 8
	xor	0, 0, 10
	add	11, 11, 0
	ld	0, 88(6)
	add	11, 11, 27
	add	11, 11, 0
	add	7, 7, 11
	rotrdi	0, 12, 28
	rotrdi	5, 12, 34
	xor	0, 0, 5
	rotrdi	5, 12, 39
	xor	0, 0, 5
	add	11, 11, 0
	xor	5, 12, 14
	xor	0, 14, 15
	and	0, 0, 5
	xor	0, 0, 14
	add	11, 11, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA512_transform_len_after_blk_11
	# Calc new W[11]
	rotrdi	0, 28, 1
	rotrdi	5, 28, 8
	xor	0, 0, 5
	srdi	5, 28, 7
	xor	0, 0, 5
	add	27, 27, 0
	rotrdi	0, 25, 19
	rotrdi	5, 25, 61
	xor	0, 0, 5
	srdi	5, 25, 6
	xor	0, 0, 5
	add	27, 27, 0
	add	27, 27, 20
L_SHA512_transform_len_after_blk_11:
	# Round 12
	rotrdi	0, 7, 14
	rotrdi	5, 7, 18
	xor	0, 0, 5
	rotrdi	5, 7, 41
	xor	0, 0, 5
	add	10, 10, 0
	xor	0, 8, 9
	and	0, 0, 7
	xor	0, 0, 9
	add	10, 10, 0
	ld	0, 96(6)
	add	10, 10, 28
	add	10, 10, 0
	add	15, 15, 10
	rotrdi	0, 11, 28
	rotrdi	5, 11, 34
	xor	0, 0, 5
	rotrdi	5, 11, 39
	xor	0, 0, 5
	add	10, 10, 0
	xor	5, 11, 12
	xor	0, 12, 14
	and	0, 0, 5
	xor	0, 0, 12
	add	10, 10, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA512_transform_len_after_blk_12
	# Calc new W[12]
	rotrdi	0, 29, 1
	rotrdi	5, 29, 8
	xor	0, 0, 5
	srdi	5, 29, 7
	xor	0, 0, 5
	add	28, 28, 0
	rotrdi	0, 26, 19
	rotrdi	5, 26, 61
	xor	0, 0, 5
	srdi	5, 26, 6
	xor	0, 0, 5
	add	28, 28, 0
	add	28, 28, 21
L_SHA512_transform_len_after_blk_12:
	# Round 13
	rotrdi	0, 15, 14
	rotrdi	5, 15, 18
	xor	0, 0, 5
	rotrdi	5, 15, 41
	xor	0, 0, 5
	add	9, 9, 0
	xor	0, 7, 8
	and	0, 0, 15
	xor	0, 0, 8
	add	9, 9, 0
	ld	0, 104(6)
	add	9, 9, 29
	add	9, 9, 0
	add	14, 14, 9
	rotrdi	0, 10, 28
	rotrdi	5, 10, 34
	xor	0, 0, 5
	rotrdi	5, 10, 39
	xor	0, 0, 5
	add	9, 9, 0
	xor	5, 10, 11
	xor	0, 11, 12
	and	0, 0, 5
	xor	0, 0, 11
	add	9, 9, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA512_transform_len_after_blk_13
	# Calc new W[13]
	rotrdi	0, 30, 1
	rotrdi	5, 30, 8
	xor	0, 0, 5
	srdi	5, 30, 7
	xor	0, 0, 5
	add	29, 29, 0
	rotrdi	0, 27, 19
	rotrdi	5, 27, 61
	xor	0, 0, 5
	srdi	5, 27, 6
	xor	0, 0, 5
	add	29, 29, 0
	add	29, 29, 22
L_SHA512_transform_len_after_blk_13:
	# Round 14
	rotrdi	0, 14, 14
	rotrdi	5, 14, 18
	xor	0, 0, 5
	rotrdi	5, 14, 41
	xor	0, 0, 5
	add	8, 8, 0
	xor	0, 15, 7
	and	0, 0, 14
	xor	0, 0, 7
	add	8, 8, 0
	ld	0, 112(6)
	add	8, 8, 30
	add	8, 8, 0
	add	12, 12, 8
	rotrdi	0, 9, 28
	rotrdi	5, 9, 34
	xor	0, 0, 5
	rotrdi	5, 9, 39
	xor	0, 0, 5
	add	8, 8, 0
	xor	5, 9, 10
	xor	0, 10, 11
	and	0, 0, 5
	xor	0, 0, 10
	add	8, 8, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA512_transform_len_after_blk_14
	# Calc new W[14]
	rotrdi	0, 31, 1
	rotrdi	5, 31, 8
	xor	0, 0, 5
	srdi	5, 31, 7
	xor	0, 0, 5
	add	30, 30, 0
	rotrdi	0, 28, 19
	rotrdi	5, 28, 61
	xor	0, 0, 5
	srdi	5, 28, 6
	xor	0, 0, 5
	add	30, 30, 0
	add	30, 30, 23
L_SHA512_transform_len_after_blk_14:
	# Round 15
	rotrdi	0, 12, 14
	rotrdi	5, 12, 18
	xor	0, 0, 5
	rotrdi	5, 12, 41
	xor	0, 0, 5
	add	7, 7, 0
	xor	0, 14, 15
	and	0, 0, 12
	xor	0, 0, 15
	add	7, 7, 0
	ld	0, 120(6)
	add	7, 7, 31
	add	7, 7, 0
	add	11, 11, 7
	rotrdi	0, 8, 28
	rotrdi	5, 8, 34
	xor	0, 0, 5
	rotrdi	5, 8, 39
	xor	0, 0, 5
	add	7, 7, 0
	xor	5, 8, 9
	xor	0, 9, 10
	and	0, 0, 5
	xor	0, 0, 9
	add	7, 7, 0
	mfctr	5
	cmpwi	0, 5, 1
	beq	0, L_SHA512_transform_len_after_blk_15
	# Calc new W[15]
	rotrdi	0, 16, 1
	rotrdi	5, 16, 8
	xor	0, 0, 5
	srdi	5, 16, 7
	xor	0, 0, 5
	add	31, 31, 0
	rotrdi	0, 29, 19
	rotrdi	5, 29, 61
	xor	0, 0, 5
	srdi	5, 29, 6
	xor	0, 0, 5
	add	31, 31, 0
	add	31, 31, 24
L_SHA512_transform_len_after_blk_15:
	addi	6, 6, 0x80
	bdnz	L_SHA512_transform_len_start
	subi	6, 6, 0x280
	# Add in digest from start
	ld	0, 0(3)
	ld	5, 8(3)
	add	7, 7, 0
	add	8, 8, 5
	ld	0, 16(3)
	ld	5, 24(3)
	add	9, 9, 0
	add	10, 10, 5
	ld	0, 32(3)
	ld	5, 40(3)
	add	11, 11, 0
	add	12, 12, 5
	ld	0, 48(3)
	ld	5, 56(3)
	add	14, 14, 0
	add	15, 15, 5
	std	7, 0(3)
	std	8, 8(3)
	std	9, 16(3)
	std	10, 24(3)
	std	11, 32(3)
	std	12, 40(3)
	std	14, 48(3)
	std	15, 56(3)
	lwz	5, 0(1)
	mtctr	5
	subi	5, 5, 1
	addi	4, 4, 0x80
	stw	5, 0(1)
	bdnz	L_SHA512_transform_len_begin
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
#if defined(_CALL_ELF) && _CALL_ELF == 2
	.size	Transform_Sha512_Len,.-Transform_Sha512_Len
#else
	.size	.L.Transform_Sha512_Len,.-.L.Transform_Sha512_Len
#endif /* _CALL_ELF == 2 */
#endif /* __APPLE__ */
#ifdef WOLFSSL_PPC64_ASM_CRYPTO
#ifndef __APPLE__
	.text
	.type	L_SHA512_crypto_k, %object
	.size	L_SHA512_crypto_k, 656
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_SHA512_crypto_k:
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
	.quad	0x0000000000000000,0x0000000000000000
	.machine	"push"
	.machine	"power8"
#ifndef __APPLE__
#if defined(_CALL_ELF) && _CALL_ELF == 2
.text
.globl	Transform_Sha512_Len_crypto
.type	Transform_Sha512_Len_crypto,@function
.align	16
Transform_Sha512_Len_crypto:
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	Transform_Sha512_Len_crypto, .-Transform_Sha512_Len_crypto
#else
	/* Power ELF V1 ABI: emit a function descriptor in .opd that
	 * points at the code (.L.Transform_Sha512_Len_crypto) and the TOC base. */
.section	.opd,"aw",@progbits
.globl	Transform_Sha512_Len_crypto
.type	Transform_Sha512_Len_crypto,@function
.align	3
Transform_Sha512_Len_crypto:
	.quad	.L.Transform_Sha512_Len_crypto,.TOC.@tocbase,0
	.size	Transform_Sha512_Len_crypto,24
.text
.align	16
.L.Transform_Sha512_Len_crypto:
#endif /* _CALL_ELF == 2 */
#else
.section	__TEXT,__text
.globl	_Transform_Sha512_Len_crypto
.p2align	4
_Transform_Sha512_Len_crypto:
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
	srdi	5, 5, 7
	mtctr	5
	li	8, 16
	li	9, 32
	li	10, 48
	addis	6, 2, L_SHA512_crypto_k@toc@ha
	addi	6, 6, L_SHA512_crypto_k@toc@l
	# Start of loop processing a block
L_SHA512_crypto_begin:
	# Load state, one doubleword per vector register
	lxvd2x	32, 0, 3
	lxvd2x	34, 8, 3
	lxvd2x	36, 9, 3
	lxvd2x	38, 10, 3
	vsldoi	1, 0, 0, 8
	vsldoi	3, 2, 2, 8
	vsldoi	5, 4, 4, 8
	vsldoi	7, 6, 6, 8
	# Load message, one doubleword per vector register
	lxvd2x	48, 0, 4
	addi	4, 4, 16
	vsldoi	17, 16, 16, 8
	lxvd2x	50, 0, 4
	addi	4, 4, 16
	vsldoi	19, 18, 18, 8
	lxvd2x	52, 0, 4
	addi	4, 4, 16
	vsldoi	21, 20, 20, 8
	lxvd2x	54, 0, 4
	addi	4, 4, 16
	vsldoi	23, 22, 22, 8
	lxvd2x	56, 0, 4
	addi	4, 4, 16
	vsldoi	25, 24, 24, 8
	lxvd2x	58, 0, 4
	addi	4, 4, 16
	vsldoi	27, 26, 26, 8
	lxvd2x	60, 0, 4
	addi	4, 4, 16
	vsldoi	29, 28, 28, 8
	lxvd2x	62, 0, 4
	addi	4, 4, 16
	vsldoi	31, 30, 30, 8
	# Preload first key
	lxvd2x	40, 0, 6
	li	7, 8
	# 80 rounds
	vaddudm	10, 8, 16
	vaddudm	13, 7, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 3, 7
	vaddudm	11, 11, 10
	vshasigmad	15, 4, 1, 15
	vshasigmad	14, 0, 1, 0
	vxor	12, 1, 2
	vsel	9, 6, 5, 4
	vsel	12, 2, 0, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	7, 15, 14
	vaddudm	3, 9, 15
	vaddudm	7, 7, 12
	vaddudm	10, 8, 17
	vaddudm	13, 6, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 2, 6
	vaddudm	11, 11, 10
	vshasigmad	15, 3, 1, 15
	vshasigmad	14, 7, 1, 0
	vxor	12, 0, 1
	vsel	9, 5, 4, 3
	vsel	12, 1, 7, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	6, 15, 14
	vaddudm	2, 9, 15
	vaddudm	6, 6, 12
	vaddudm	10, 8, 18
	vaddudm	13, 5, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 1, 5
	vaddudm	11, 11, 10
	vshasigmad	15, 2, 1, 15
	vshasigmad	14, 6, 1, 0
	vxor	12, 7, 0
	vsel	9, 4, 3, 2
	vsel	12, 0, 6, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	5, 15, 14
	vaddudm	1, 9, 15
	vaddudm	5, 5, 12
	vaddudm	10, 8, 19
	vaddudm	13, 4, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 0, 4
	vaddudm	11, 11, 10
	vshasigmad	15, 1, 1, 15
	vshasigmad	14, 5, 1, 0
	vxor	12, 6, 7
	vsel	9, 3, 2, 1
	vsel	12, 7, 5, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	4, 15, 14
	vaddudm	0, 9, 15
	vaddudm	4, 4, 12
	vaddudm	10, 8, 20
	vaddudm	13, 3, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 7, 3
	vaddudm	11, 11, 10
	vshasigmad	15, 0, 1, 15
	vshasigmad	14, 4, 1, 0
	vxor	12, 5, 6
	vsel	9, 2, 1, 0
	vsel	12, 6, 4, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	3, 15, 14
	vaddudm	7, 9, 15
	vaddudm	3, 3, 12
	vaddudm	10, 8, 21
	vaddudm	13, 2, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 6, 2
	vaddudm	11, 11, 10
	vshasigmad	15, 7, 1, 15
	vshasigmad	14, 3, 1, 0
	vxor	12, 4, 5
	vsel	9, 1, 0, 7
	vsel	12, 5, 3, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	2, 15, 14
	vaddudm	6, 9, 15
	vaddudm	2, 2, 12
	vaddudm	10, 8, 22
	vaddudm	13, 1, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 5, 1
	vaddudm	11, 11, 10
	vshasigmad	15, 6, 1, 15
	vshasigmad	14, 2, 1, 0
	vxor	12, 3, 4
	vsel	9, 0, 7, 6
	vsel	12, 4, 2, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	1, 15, 14
	vaddudm	5, 9, 15
	vaddudm	1, 1, 12
	vaddudm	10, 8, 23
	vaddudm	13, 0, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 4, 0
	vaddudm	11, 11, 10
	vshasigmad	15, 5, 1, 15
	vshasigmad	14, 1, 1, 0
	vxor	12, 2, 3
	vsel	9, 7, 6, 5
	vsel	12, 3, 1, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	0, 15, 14
	vaddudm	4, 9, 15
	vaddudm	0, 0, 12
	vaddudm	10, 8, 24
	vaddudm	13, 7, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 3, 7
	vaddudm	11, 11, 10
	vshasigmad	15, 4, 1, 15
	vshasigmad	14, 0, 1, 0
	vxor	12, 1, 2
	vsel	9, 6, 5, 4
	vsel	12, 2, 0, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	7, 15, 14
	vaddudm	3, 9, 15
	vaddudm	7, 7, 12
	vaddudm	10, 8, 25
	vaddudm	13, 6, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 2, 6
	vaddudm	11, 11, 10
	vshasigmad	15, 3, 1, 15
	vshasigmad	14, 7, 1, 0
	vxor	12, 0, 1
	vsel	9, 5, 4, 3
	vsel	12, 1, 7, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	6, 15, 14
	vaddudm	2, 9, 15
	vaddudm	6, 6, 12
	vaddudm	10, 8, 26
	vaddudm	13, 5, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 1, 5
	vaddudm	11, 11, 10
	vshasigmad	15, 2, 1, 15
	vshasigmad	14, 6, 1, 0
	vxor	12, 7, 0
	vsel	9, 4, 3, 2
	vsel	12, 0, 6, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	5, 15, 14
	vaddudm	1, 9, 15
	vaddudm	5, 5, 12
	vaddudm	10, 8, 27
	vaddudm	13, 4, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 0, 4
	vaddudm	11, 11, 10
	vshasigmad	15, 1, 1, 15
	vshasigmad	14, 5, 1, 0
	vxor	12, 6, 7
	vsel	9, 3, 2, 1
	vsel	12, 7, 5, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	4, 15, 14
	vaddudm	0, 9, 15
	vaddudm	4, 4, 12
	vaddudm	10, 8, 28
	vaddudm	13, 3, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 7, 3
	vaddudm	11, 11, 10
	vshasigmad	15, 0, 1, 15
	vshasigmad	14, 4, 1, 0
	vxor	12, 5, 6
	vsel	9, 2, 1, 0
	vsel	12, 6, 4, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	3, 15, 14
	vaddudm	7, 9, 15
	vaddudm	3, 3, 12
	vaddudm	10, 8, 29
	vaddudm	13, 2, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 6, 2
	vaddudm	11, 11, 10
	vshasigmad	15, 7, 1, 15
	vshasigmad	14, 3, 1, 0
	vxor	12, 4, 5
	vsel	9, 1, 0, 7
	vsel	12, 5, 3, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	2, 15, 14
	vaddudm	6, 9, 15
	vaddudm	2, 2, 12
	vaddudm	10, 8, 30
	vaddudm	13, 1, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 5, 1
	vaddudm	11, 11, 10
	vshasigmad	15, 6, 1, 15
	vshasigmad	14, 2, 1, 0
	vxor	12, 3, 4
	vsel	9, 0, 7, 6
	vsel	12, 4, 2, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	1, 15, 14
	vaddudm	5, 9, 15
	vaddudm	1, 1, 12
	vaddudm	10, 8, 31
	vaddudm	13, 0, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 4, 0
	vaddudm	11, 11, 10
	vshasigmad	15, 5, 1, 15
	vshasigmad	14, 1, 1, 0
	vxor	12, 2, 3
	vsel	9, 7, 6, 5
	vsel	12, 3, 1, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	0, 15, 14
	vaddudm	4, 9, 15
	vaddudm	0, 0, 12
	vshasigmad	15, 30, 0, 15
	vshasigmad	14, 17, 0, 0
	vaddudm	16, 16, 15
	vaddudm	16, 16, 14
	vaddudm	16, 16, 25
	vaddudm	10, 8, 16
	vaddudm	13, 7, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 3, 7
	vaddudm	11, 11, 10
	vshasigmad	15, 4, 1, 15
	vshasigmad	14, 0, 1, 0
	vxor	12, 1, 2
	vsel	9, 6, 5, 4
	vsel	12, 2, 0, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	7, 15, 14
	vaddudm	3, 9, 15
	vaddudm	7, 7, 12
	vshasigmad	15, 31, 0, 15
	vshasigmad	14, 18, 0, 0
	vaddudm	17, 17, 15
	vaddudm	17, 17, 14
	vaddudm	17, 17, 26
	vaddudm	10, 8, 17
	vaddudm	13, 6, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 2, 6
	vaddudm	11, 11, 10
	vshasigmad	15, 3, 1, 15
	vshasigmad	14, 7, 1, 0
	vxor	12, 0, 1
	vsel	9, 5, 4, 3
	vsel	12, 1, 7, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	6, 15, 14
	vaddudm	2, 9, 15
	vaddudm	6, 6, 12
	vshasigmad	15, 16, 0, 15
	vshasigmad	14, 19, 0, 0
	vaddudm	18, 18, 15
	vaddudm	18, 18, 14
	vaddudm	18, 18, 27
	vaddudm	10, 8, 18
	vaddudm	13, 5, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 1, 5
	vaddudm	11, 11, 10
	vshasigmad	15, 2, 1, 15
	vshasigmad	14, 6, 1, 0
	vxor	12, 7, 0
	vsel	9, 4, 3, 2
	vsel	12, 0, 6, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	5, 15, 14
	vaddudm	1, 9, 15
	vaddudm	5, 5, 12
	vshasigmad	15, 17, 0, 15
	vshasigmad	14, 20, 0, 0
	vaddudm	19, 19, 15
	vaddudm	19, 19, 14
	vaddudm	19, 19, 28
	vaddudm	10, 8, 19
	vaddudm	13, 4, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 0, 4
	vaddudm	11, 11, 10
	vshasigmad	15, 1, 1, 15
	vshasigmad	14, 5, 1, 0
	vxor	12, 6, 7
	vsel	9, 3, 2, 1
	vsel	12, 7, 5, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	4, 15, 14
	vaddudm	0, 9, 15
	vaddudm	4, 4, 12
	vshasigmad	15, 18, 0, 15
	vshasigmad	14, 21, 0, 0
	vaddudm	20, 20, 15
	vaddudm	20, 20, 14
	vaddudm	20, 20, 29
	vaddudm	10, 8, 20
	vaddudm	13, 3, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 7, 3
	vaddudm	11, 11, 10
	vshasigmad	15, 0, 1, 15
	vshasigmad	14, 4, 1, 0
	vxor	12, 5, 6
	vsel	9, 2, 1, 0
	vsel	12, 6, 4, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	3, 15, 14
	vaddudm	7, 9, 15
	vaddudm	3, 3, 12
	vshasigmad	15, 19, 0, 15
	vshasigmad	14, 22, 0, 0
	vaddudm	21, 21, 15
	vaddudm	21, 21, 14
	vaddudm	21, 21, 30
	vaddudm	10, 8, 21
	vaddudm	13, 2, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 6, 2
	vaddudm	11, 11, 10
	vshasigmad	15, 7, 1, 15
	vshasigmad	14, 3, 1, 0
	vxor	12, 4, 5
	vsel	9, 1, 0, 7
	vsel	12, 5, 3, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	2, 15, 14
	vaddudm	6, 9, 15
	vaddudm	2, 2, 12
	vshasigmad	15, 20, 0, 15
	vshasigmad	14, 23, 0, 0
	vaddudm	22, 22, 15
	vaddudm	22, 22, 14
	vaddudm	22, 22, 31
	vaddudm	10, 8, 22
	vaddudm	13, 1, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 5, 1
	vaddudm	11, 11, 10
	vshasigmad	15, 6, 1, 15
	vshasigmad	14, 2, 1, 0
	vxor	12, 3, 4
	vsel	9, 0, 7, 6
	vsel	12, 4, 2, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	1, 15, 14
	vaddudm	5, 9, 15
	vaddudm	1, 1, 12
	vshasigmad	15, 21, 0, 15
	vshasigmad	14, 24, 0, 0
	vaddudm	23, 23, 15
	vaddudm	23, 23, 14
	vaddudm	23, 23, 16
	vaddudm	10, 8, 23
	vaddudm	13, 0, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 4, 0
	vaddudm	11, 11, 10
	vshasigmad	15, 5, 1, 15
	vshasigmad	14, 1, 1, 0
	vxor	12, 2, 3
	vsel	9, 7, 6, 5
	vsel	12, 3, 1, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	0, 15, 14
	vaddudm	4, 9, 15
	vaddudm	0, 0, 12
	vshasigmad	15, 22, 0, 15
	vshasigmad	14, 25, 0, 0
	vaddudm	24, 24, 15
	vaddudm	24, 24, 14
	vaddudm	24, 24, 17
	vaddudm	10, 8, 24
	vaddudm	13, 7, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 3, 7
	vaddudm	11, 11, 10
	vshasigmad	15, 4, 1, 15
	vshasigmad	14, 0, 1, 0
	vxor	12, 1, 2
	vsel	9, 6, 5, 4
	vsel	12, 2, 0, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	7, 15, 14
	vaddudm	3, 9, 15
	vaddudm	7, 7, 12
	vshasigmad	15, 23, 0, 15
	vshasigmad	14, 26, 0, 0
	vaddudm	25, 25, 15
	vaddudm	25, 25, 14
	vaddudm	25, 25, 18
	vaddudm	10, 8, 25
	vaddudm	13, 6, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 2, 6
	vaddudm	11, 11, 10
	vshasigmad	15, 3, 1, 15
	vshasigmad	14, 7, 1, 0
	vxor	12, 0, 1
	vsel	9, 5, 4, 3
	vsel	12, 1, 7, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	6, 15, 14
	vaddudm	2, 9, 15
	vaddudm	6, 6, 12
	vshasigmad	15, 24, 0, 15
	vshasigmad	14, 27, 0, 0
	vaddudm	26, 26, 15
	vaddudm	26, 26, 14
	vaddudm	26, 26, 19
	vaddudm	10, 8, 26
	vaddudm	13, 5, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 1, 5
	vaddudm	11, 11, 10
	vshasigmad	15, 2, 1, 15
	vshasigmad	14, 6, 1, 0
	vxor	12, 7, 0
	vsel	9, 4, 3, 2
	vsel	12, 0, 6, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	5, 15, 14
	vaddudm	1, 9, 15
	vaddudm	5, 5, 12
	vshasigmad	15, 25, 0, 15
	vshasigmad	14, 28, 0, 0
	vaddudm	27, 27, 15
	vaddudm	27, 27, 14
	vaddudm	27, 27, 20
	vaddudm	10, 8, 27
	vaddudm	13, 4, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 0, 4
	vaddudm	11, 11, 10
	vshasigmad	15, 1, 1, 15
	vshasigmad	14, 5, 1, 0
	vxor	12, 6, 7
	vsel	9, 3, 2, 1
	vsel	12, 7, 5, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	4, 15, 14
	vaddudm	0, 9, 15
	vaddudm	4, 4, 12
	vshasigmad	15, 26, 0, 15
	vshasigmad	14, 29, 0, 0
	vaddudm	28, 28, 15
	vaddudm	28, 28, 14
	vaddudm	28, 28, 21
	vaddudm	10, 8, 28
	vaddudm	13, 3, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 7, 3
	vaddudm	11, 11, 10
	vshasigmad	15, 0, 1, 15
	vshasigmad	14, 4, 1, 0
	vxor	12, 5, 6
	vsel	9, 2, 1, 0
	vsel	12, 6, 4, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	3, 15, 14
	vaddudm	7, 9, 15
	vaddudm	3, 3, 12
	vshasigmad	15, 27, 0, 15
	vshasigmad	14, 30, 0, 0
	vaddudm	29, 29, 15
	vaddudm	29, 29, 14
	vaddudm	29, 29, 22
	vaddudm	10, 8, 29
	vaddudm	13, 2, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 6, 2
	vaddudm	11, 11, 10
	vshasigmad	15, 7, 1, 15
	vshasigmad	14, 3, 1, 0
	vxor	12, 4, 5
	vsel	9, 1, 0, 7
	vsel	12, 5, 3, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	2, 15, 14
	vaddudm	6, 9, 15
	vaddudm	2, 2, 12
	vshasigmad	15, 28, 0, 15
	vshasigmad	14, 31, 0, 0
	vaddudm	30, 30, 15
	vaddudm	30, 30, 14
	vaddudm	30, 30, 23
	vaddudm	10, 8, 30
	vaddudm	13, 1, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 5, 1
	vaddudm	11, 11, 10
	vshasigmad	15, 6, 1, 15
	vshasigmad	14, 2, 1, 0
	vxor	12, 3, 4
	vsel	9, 0, 7, 6
	vsel	12, 4, 2, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	1, 15, 14
	vaddudm	5, 9, 15
	vaddudm	1, 1, 12
	vshasigmad	15, 29, 0, 15
	vshasigmad	14, 16, 0, 0
	vaddudm	31, 31, 15
	vaddudm	31, 31, 14
	vaddudm	31, 31, 24
	vaddudm	10, 8, 31
	vaddudm	13, 0, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 4, 0
	vaddudm	11, 11, 10
	vshasigmad	15, 5, 1, 15
	vshasigmad	14, 1, 1, 0
	vxor	12, 2, 3
	vsel	9, 7, 6, 5
	vsel	12, 3, 1, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	0, 15, 14
	vaddudm	4, 9, 15
	vaddudm	0, 0, 12
	vshasigmad	15, 30, 0, 15
	vshasigmad	14, 17, 0, 0
	vaddudm	16, 16, 15
	vaddudm	16, 16, 14
	vaddudm	16, 16, 25
	vaddudm	10, 8, 16
	vaddudm	13, 7, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 3, 7
	vaddudm	11, 11, 10
	vshasigmad	15, 4, 1, 15
	vshasigmad	14, 0, 1, 0
	vxor	12, 1, 2
	vsel	9, 6, 5, 4
	vsel	12, 2, 0, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	7, 15, 14
	vaddudm	3, 9, 15
	vaddudm	7, 7, 12
	vshasigmad	15, 31, 0, 15
	vshasigmad	14, 18, 0, 0
	vaddudm	17, 17, 15
	vaddudm	17, 17, 14
	vaddudm	17, 17, 26
	vaddudm	10, 8, 17
	vaddudm	13, 6, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 2, 6
	vaddudm	11, 11, 10
	vshasigmad	15, 3, 1, 15
	vshasigmad	14, 7, 1, 0
	vxor	12, 0, 1
	vsel	9, 5, 4, 3
	vsel	12, 1, 7, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	6, 15, 14
	vaddudm	2, 9, 15
	vaddudm	6, 6, 12
	vshasigmad	15, 16, 0, 15
	vshasigmad	14, 19, 0, 0
	vaddudm	18, 18, 15
	vaddudm	18, 18, 14
	vaddudm	18, 18, 27
	vaddudm	10, 8, 18
	vaddudm	13, 5, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 1, 5
	vaddudm	11, 11, 10
	vshasigmad	15, 2, 1, 15
	vshasigmad	14, 6, 1, 0
	vxor	12, 7, 0
	vsel	9, 4, 3, 2
	vsel	12, 0, 6, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	5, 15, 14
	vaddudm	1, 9, 15
	vaddudm	5, 5, 12
	vshasigmad	15, 17, 0, 15
	vshasigmad	14, 20, 0, 0
	vaddudm	19, 19, 15
	vaddudm	19, 19, 14
	vaddudm	19, 19, 28
	vaddudm	10, 8, 19
	vaddudm	13, 4, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 0, 4
	vaddudm	11, 11, 10
	vshasigmad	15, 1, 1, 15
	vshasigmad	14, 5, 1, 0
	vxor	12, 6, 7
	vsel	9, 3, 2, 1
	vsel	12, 7, 5, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	4, 15, 14
	vaddudm	0, 9, 15
	vaddudm	4, 4, 12
	vshasigmad	15, 18, 0, 15
	vshasigmad	14, 21, 0, 0
	vaddudm	20, 20, 15
	vaddudm	20, 20, 14
	vaddudm	20, 20, 29
	vaddudm	10, 8, 20
	vaddudm	13, 3, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 7, 3
	vaddudm	11, 11, 10
	vshasigmad	15, 0, 1, 15
	vshasigmad	14, 4, 1, 0
	vxor	12, 5, 6
	vsel	9, 2, 1, 0
	vsel	12, 6, 4, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	3, 15, 14
	vaddudm	7, 9, 15
	vaddudm	3, 3, 12
	vshasigmad	15, 19, 0, 15
	vshasigmad	14, 22, 0, 0
	vaddudm	21, 21, 15
	vaddudm	21, 21, 14
	vaddudm	21, 21, 30
	vaddudm	10, 8, 21
	vaddudm	13, 2, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 6, 2
	vaddudm	11, 11, 10
	vshasigmad	15, 7, 1, 15
	vshasigmad	14, 3, 1, 0
	vxor	12, 4, 5
	vsel	9, 1, 0, 7
	vsel	12, 5, 3, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	2, 15, 14
	vaddudm	6, 9, 15
	vaddudm	2, 2, 12
	vshasigmad	15, 20, 0, 15
	vshasigmad	14, 23, 0, 0
	vaddudm	22, 22, 15
	vaddudm	22, 22, 14
	vaddudm	22, 22, 31
	vaddudm	10, 8, 22
	vaddudm	13, 1, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 5, 1
	vaddudm	11, 11, 10
	vshasigmad	15, 6, 1, 15
	vshasigmad	14, 2, 1, 0
	vxor	12, 3, 4
	vsel	9, 0, 7, 6
	vsel	12, 4, 2, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	1, 15, 14
	vaddudm	5, 9, 15
	vaddudm	1, 1, 12
	vshasigmad	15, 21, 0, 15
	vshasigmad	14, 24, 0, 0
	vaddudm	23, 23, 15
	vaddudm	23, 23, 14
	vaddudm	23, 23, 16
	vaddudm	10, 8, 23
	vaddudm	13, 0, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 4, 0
	vaddudm	11, 11, 10
	vshasigmad	15, 5, 1, 15
	vshasigmad	14, 1, 1, 0
	vxor	12, 2, 3
	vsel	9, 7, 6, 5
	vsel	12, 3, 1, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	0, 15, 14
	vaddudm	4, 9, 15
	vaddudm	0, 0, 12
	vshasigmad	15, 22, 0, 15
	vshasigmad	14, 25, 0, 0
	vaddudm	24, 24, 15
	vaddudm	24, 24, 14
	vaddudm	24, 24, 17
	vaddudm	10, 8, 24
	vaddudm	13, 7, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 3, 7
	vaddudm	11, 11, 10
	vshasigmad	15, 4, 1, 15
	vshasigmad	14, 0, 1, 0
	vxor	12, 1, 2
	vsel	9, 6, 5, 4
	vsel	12, 2, 0, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	7, 15, 14
	vaddudm	3, 9, 15
	vaddudm	7, 7, 12
	vshasigmad	15, 23, 0, 15
	vshasigmad	14, 26, 0, 0
	vaddudm	25, 25, 15
	vaddudm	25, 25, 14
	vaddudm	25, 25, 18
	vaddudm	10, 8, 25
	vaddudm	13, 6, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 2, 6
	vaddudm	11, 11, 10
	vshasigmad	15, 3, 1, 15
	vshasigmad	14, 7, 1, 0
	vxor	12, 0, 1
	vsel	9, 5, 4, 3
	vsel	12, 1, 7, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	6, 15, 14
	vaddudm	2, 9, 15
	vaddudm	6, 6, 12
	vshasigmad	15, 24, 0, 15
	vshasigmad	14, 27, 0, 0
	vaddudm	26, 26, 15
	vaddudm	26, 26, 14
	vaddudm	26, 26, 19
	vaddudm	10, 8, 26
	vaddudm	13, 5, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 1, 5
	vaddudm	11, 11, 10
	vshasigmad	15, 2, 1, 15
	vshasigmad	14, 6, 1, 0
	vxor	12, 7, 0
	vsel	9, 4, 3, 2
	vsel	12, 0, 6, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	5, 15, 14
	vaddudm	1, 9, 15
	vaddudm	5, 5, 12
	vshasigmad	15, 25, 0, 15
	vshasigmad	14, 28, 0, 0
	vaddudm	27, 27, 15
	vaddudm	27, 27, 14
	vaddudm	27, 27, 20
	vaddudm	10, 8, 27
	vaddudm	13, 4, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 0, 4
	vaddudm	11, 11, 10
	vshasigmad	15, 1, 1, 15
	vshasigmad	14, 5, 1, 0
	vxor	12, 6, 7
	vsel	9, 3, 2, 1
	vsel	12, 7, 5, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	4, 15, 14
	vaddudm	0, 9, 15
	vaddudm	4, 4, 12
	vshasigmad	15, 26, 0, 15
	vshasigmad	14, 29, 0, 0
	vaddudm	28, 28, 15
	vaddudm	28, 28, 14
	vaddudm	28, 28, 21
	vaddudm	10, 8, 28
	vaddudm	13, 3, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 7, 3
	vaddudm	11, 11, 10
	vshasigmad	15, 0, 1, 15
	vshasigmad	14, 4, 1, 0
	vxor	12, 5, 6
	vsel	9, 2, 1, 0
	vsel	12, 6, 4, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	3, 15, 14
	vaddudm	7, 9, 15
	vaddudm	3, 3, 12
	vshasigmad	15, 27, 0, 15
	vshasigmad	14, 30, 0, 0
	vaddudm	29, 29, 15
	vaddudm	29, 29, 14
	vaddudm	29, 29, 22
	vaddudm	10, 8, 29
	vaddudm	13, 2, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 6, 2
	vaddudm	11, 11, 10
	vshasigmad	15, 7, 1, 15
	vshasigmad	14, 3, 1, 0
	vxor	12, 4, 5
	vsel	9, 1, 0, 7
	vsel	12, 5, 3, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	2, 15, 14
	vaddudm	6, 9, 15
	vaddudm	2, 2, 12
	vshasigmad	15, 28, 0, 15
	vshasigmad	14, 31, 0, 0
	vaddudm	30, 30, 15
	vaddudm	30, 30, 14
	vaddudm	30, 30, 23
	vaddudm	10, 8, 30
	vaddudm	13, 1, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 5, 1
	vaddudm	11, 11, 10
	vshasigmad	15, 6, 1, 15
	vshasigmad	14, 2, 1, 0
	vxor	12, 3, 4
	vsel	9, 0, 7, 6
	vsel	12, 4, 2, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	1, 15, 14
	vaddudm	5, 9, 15
	vaddudm	1, 1, 12
	vshasigmad	15, 29, 0, 15
	vshasigmad	14, 16, 0, 0
	vaddudm	31, 31, 15
	vaddudm	31, 31, 14
	vaddudm	31, 31, 24
	vaddudm	10, 8, 31
	vaddudm	13, 0, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 4, 0
	vaddudm	11, 11, 10
	vshasigmad	15, 5, 1, 15
	vshasigmad	14, 1, 1, 0
	vxor	12, 2, 3
	vsel	9, 7, 6, 5
	vsel	12, 3, 1, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	0, 15, 14
	vaddudm	4, 9, 15
	vaddudm	0, 0, 12
	vshasigmad	15, 30, 0, 15
	vshasigmad	14, 17, 0, 0
	vaddudm	16, 16, 15
	vaddudm	16, 16, 14
	vaddudm	16, 16, 25
	vaddudm	10, 8, 16
	vaddudm	13, 7, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 3, 7
	vaddudm	11, 11, 10
	vshasigmad	15, 4, 1, 15
	vshasigmad	14, 0, 1, 0
	vxor	12, 1, 2
	vsel	9, 6, 5, 4
	vsel	12, 2, 0, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	7, 15, 14
	vaddudm	3, 9, 15
	vaddudm	7, 7, 12
	vshasigmad	15, 31, 0, 15
	vshasigmad	14, 18, 0, 0
	vaddudm	17, 17, 15
	vaddudm	17, 17, 14
	vaddudm	17, 17, 26
	vaddudm	10, 8, 17
	vaddudm	13, 6, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 2, 6
	vaddudm	11, 11, 10
	vshasigmad	15, 3, 1, 15
	vshasigmad	14, 7, 1, 0
	vxor	12, 0, 1
	vsel	9, 5, 4, 3
	vsel	12, 1, 7, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	6, 15, 14
	vaddudm	2, 9, 15
	vaddudm	6, 6, 12
	vshasigmad	15, 16, 0, 15
	vshasigmad	14, 19, 0, 0
	vaddudm	18, 18, 15
	vaddudm	18, 18, 14
	vaddudm	18, 18, 27
	vaddudm	10, 8, 18
	vaddudm	13, 5, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 1, 5
	vaddudm	11, 11, 10
	vshasigmad	15, 2, 1, 15
	vshasigmad	14, 6, 1, 0
	vxor	12, 7, 0
	vsel	9, 4, 3, 2
	vsel	12, 0, 6, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	5, 15, 14
	vaddudm	1, 9, 15
	vaddudm	5, 5, 12
	vshasigmad	15, 17, 0, 15
	vshasigmad	14, 20, 0, 0
	vaddudm	19, 19, 15
	vaddudm	19, 19, 14
	vaddudm	19, 19, 28
	vaddudm	10, 8, 19
	vaddudm	13, 4, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 0, 4
	vaddudm	11, 11, 10
	vshasigmad	15, 1, 1, 15
	vshasigmad	14, 5, 1, 0
	vxor	12, 6, 7
	vsel	9, 3, 2, 1
	vsel	12, 7, 5, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	4, 15, 14
	vaddudm	0, 9, 15
	vaddudm	4, 4, 12
	vshasigmad	15, 18, 0, 15
	vshasigmad	14, 21, 0, 0
	vaddudm	20, 20, 15
	vaddudm	20, 20, 14
	vaddudm	20, 20, 29
	vaddudm	10, 8, 20
	vaddudm	13, 3, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 7, 3
	vaddudm	11, 11, 10
	vshasigmad	15, 0, 1, 15
	vshasigmad	14, 4, 1, 0
	vxor	12, 5, 6
	vsel	9, 2, 1, 0
	vsel	12, 6, 4, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	3, 15, 14
	vaddudm	7, 9, 15
	vaddudm	3, 3, 12
	vshasigmad	15, 19, 0, 15
	vshasigmad	14, 22, 0, 0
	vaddudm	21, 21, 15
	vaddudm	21, 21, 14
	vaddudm	21, 21, 30
	vaddudm	10, 8, 21
	vaddudm	13, 2, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 6, 2
	vaddudm	11, 11, 10
	vshasigmad	15, 7, 1, 15
	vshasigmad	14, 3, 1, 0
	vxor	12, 4, 5
	vsel	9, 1, 0, 7
	vsel	12, 5, 3, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	2, 15, 14
	vaddudm	6, 9, 15
	vaddudm	2, 2, 12
	vshasigmad	15, 20, 0, 15
	vshasigmad	14, 23, 0, 0
	vaddudm	22, 22, 15
	vaddudm	22, 22, 14
	vaddudm	22, 22, 31
	vaddudm	10, 8, 22
	vaddudm	13, 1, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 5, 1
	vaddudm	11, 11, 10
	vshasigmad	15, 6, 1, 15
	vshasigmad	14, 2, 1, 0
	vxor	12, 3, 4
	vsel	9, 0, 7, 6
	vsel	12, 4, 2, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	1, 15, 14
	vaddudm	5, 9, 15
	vaddudm	1, 1, 12
	vshasigmad	15, 21, 0, 15
	vshasigmad	14, 24, 0, 0
	vaddudm	23, 23, 15
	vaddudm	23, 23, 14
	vaddudm	23, 23, 16
	vaddudm	10, 8, 23
	vaddudm	13, 0, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 4, 0
	vaddudm	11, 11, 10
	vshasigmad	15, 5, 1, 15
	vshasigmad	14, 1, 1, 0
	vxor	12, 2, 3
	vsel	9, 7, 6, 5
	vsel	12, 3, 1, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	0, 15, 14
	vaddudm	4, 9, 15
	vaddudm	0, 0, 12
	vshasigmad	15, 22, 0, 15
	vshasigmad	14, 25, 0, 0
	vaddudm	24, 24, 15
	vaddudm	24, 24, 14
	vaddudm	24, 24, 17
	vaddudm	10, 8, 24
	vaddudm	13, 7, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 3, 7
	vaddudm	11, 11, 10
	vshasigmad	15, 4, 1, 15
	vshasigmad	14, 0, 1, 0
	vxor	12, 1, 2
	vsel	9, 6, 5, 4
	vsel	12, 2, 0, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	7, 15, 14
	vaddudm	3, 9, 15
	vaddudm	7, 7, 12
	vshasigmad	15, 23, 0, 15
	vshasigmad	14, 26, 0, 0
	vaddudm	25, 25, 15
	vaddudm	25, 25, 14
	vaddudm	25, 25, 18
	vaddudm	10, 8, 25
	vaddudm	13, 6, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 2, 6
	vaddudm	11, 11, 10
	vshasigmad	15, 3, 1, 15
	vshasigmad	14, 7, 1, 0
	vxor	12, 0, 1
	vsel	9, 5, 4, 3
	vsel	12, 1, 7, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	6, 15, 14
	vaddudm	2, 9, 15
	vaddudm	6, 6, 12
	vshasigmad	15, 24, 0, 15
	vshasigmad	14, 27, 0, 0
	vaddudm	26, 26, 15
	vaddudm	26, 26, 14
	vaddudm	26, 26, 19
	vaddudm	10, 8, 26
	vaddudm	13, 5, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 1, 5
	vaddudm	11, 11, 10
	vshasigmad	15, 2, 1, 15
	vshasigmad	14, 6, 1, 0
	vxor	12, 7, 0
	vsel	9, 4, 3, 2
	vsel	12, 0, 6, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	5, 15, 14
	vaddudm	1, 9, 15
	vaddudm	5, 5, 12
	vshasigmad	15, 25, 0, 15
	vshasigmad	14, 28, 0, 0
	vaddudm	27, 27, 15
	vaddudm	27, 27, 14
	vaddudm	27, 27, 20
	vaddudm	10, 8, 27
	vaddudm	13, 4, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 0, 4
	vaddudm	11, 11, 10
	vshasigmad	15, 1, 1, 15
	vshasigmad	14, 5, 1, 0
	vxor	12, 6, 7
	vsel	9, 3, 2, 1
	vsel	12, 7, 5, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	4, 15, 14
	vaddudm	0, 9, 15
	vaddudm	4, 4, 12
	vshasigmad	15, 26, 0, 15
	vshasigmad	14, 29, 0, 0
	vaddudm	28, 28, 15
	vaddudm	28, 28, 14
	vaddudm	28, 28, 21
	vaddudm	10, 8, 28
	vaddudm	13, 3, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 7, 3
	vaddudm	11, 11, 10
	vshasigmad	15, 0, 1, 15
	vshasigmad	14, 4, 1, 0
	vxor	12, 5, 6
	vsel	9, 2, 1, 0
	vsel	12, 6, 4, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	3, 15, 14
	vaddudm	7, 9, 15
	vaddudm	3, 3, 12
	vshasigmad	15, 27, 0, 15
	vshasigmad	14, 30, 0, 0
	vaddudm	29, 29, 15
	vaddudm	29, 29, 14
	vaddudm	29, 29, 22
	vaddudm	10, 8, 29
	vaddudm	13, 2, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 6, 2
	vaddudm	11, 11, 10
	vshasigmad	15, 7, 1, 15
	vshasigmad	14, 3, 1, 0
	vxor	12, 4, 5
	vsel	9, 1, 0, 7
	vsel	12, 5, 3, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	2, 15, 14
	vaddudm	6, 9, 15
	vaddudm	2, 2, 12
	vshasigmad	15, 28, 0, 15
	vshasigmad	14, 31, 0, 0
	vaddudm	30, 30, 15
	vaddudm	30, 30, 14
	vaddudm	30, 30, 23
	vaddudm	10, 8, 30
	vaddudm	13, 1, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 5, 1
	vaddudm	11, 11, 10
	vshasigmad	15, 6, 1, 15
	vshasigmad	14, 2, 1, 0
	vxor	12, 3, 4
	vsel	9, 0, 7, 6
	vsel	12, 4, 2, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	1, 15, 14
	vaddudm	5, 9, 15
	vaddudm	1, 1, 12
	vshasigmad	15, 29, 0, 15
	vshasigmad	14, 16, 0, 0
	vaddudm	31, 31, 15
	vaddudm	31, 31, 14
	vaddudm	31, 31, 24
	vaddudm	10, 8, 31
	vaddudm	13, 0, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 4, 0
	vaddudm	11, 11, 10
	vshasigmad	15, 5, 1, 15
	vshasigmad	14, 1, 1, 0
	vxor	12, 2, 3
	vsel	9, 7, 6, 5
	vsel	12, 3, 1, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	0, 15, 14
	vaddudm	4, 9, 15
	vaddudm	0, 0, 12
	vshasigmad	15, 30, 0, 15
	vshasigmad	14, 17, 0, 0
	vaddudm	16, 16, 15
	vaddudm	16, 16, 14
	vaddudm	16, 16, 25
	vaddudm	10, 8, 16
	vaddudm	13, 7, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 3, 7
	vaddudm	11, 11, 10
	vshasigmad	15, 4, 1, 15
	vshasigmad	14, 0, 1, 0
	vxor	12, 1, 2
	vsel	9, 6, 5, 4
	vsel	12, 2, 0, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	7, 15, 14
	vaddudm	3, 9, 15
	vaddudm	7, 7, 12
	vshasigmad	15, 31, 0, 15
	vshasigmad	14, 18, 0, 0
	vaddudm	17, 17, 15
	vaddudm	17, 17, 14
	vaddudm	17, 17, 26
	vaddudm	10, 8, 17
	vaddudm	13, 6, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 2, 6
	vaddudm	11, 11, 10
	vshasigmad	15, 3, 1, 15
	vshasigmad	14, 7, 1, 0
	vxor	12, 0, 1
	vsel	9, 5, 4, 3
	vsel	12, 1, 7, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	6, 15, 14
	vaddudm	2, 9, 15
	vaddudm	6, 6, 12
	vshasigmad	15, 16, 0, 15
	vshasigmad	14, 19, 0, 0
	vaddudm	18, 18, 15
	vaddudm	18, 18, 14
	vaddudm	18, 18, 27
	vaddudm	10, 8, 18
	vaddudm	13, 5, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 1, 5
	vaddudm	11, 11, 10
	vshasigmad	15, 2, 1, 15
	vshasigmad	14, 6, 1, 0
	vxor	12, 7, 0
	vsel	9, 4, 3, 2
	vsel	12, 0, 6, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	5, 15, 14
	vaddudm	1, 9, 15
	vaddudm	5, 5, 12
	vshasigmad	15, 17, 0, 15
	vshasigmad	14, 20, 0, 0
	vaddudm	19, 19, 15
	vaddudm	19, 19, 14
	vaddudm	19, 19, 28
	vaddudm	10, 8, 19
	vaddudm	13, 4, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 0, 4
	vaddudm	11, 11, 10
	vshasigmad	15, 1, 1, 15
	vshasigmad	14, 5, 1, 0
	vxor	12, 6, 7
	vsel	9, 3, 2, 1
	vsel	12, 7, 5, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	4, 15, 14
	vaddudm	0, 9, 15
	vaddudm	4, 4, 12
	vshasigmad	15, 18, 0, 15
	vshasigmad	14, 21, 0, 0
	vaddudm	20, 20, 15
	vaddudm	20, 20, 14
	vaddudm	20, 20, 29
	vaddudm	10, 8, 20
	vaddudm	13, 3, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 7, 3
	vaddudm	11, 11, 10
	vshasigmad	15, 0, 1, 15
	vshasigmad	14, 4, 1, 0
	vxor	12, 5, 6
	vsel	9, 2, 1, 0
	vsel	12, 6, 4, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	3, 15, 14
	vaddudm	7, 9, 15
	vaddudm	3, 3, 12
	vshasigmad	15, 19, 0, 15
	vshasigmad	14, 22, 0, 0
	vaddudm	21, 21, 15
	vaddudm	21, 21, 14
	vaddudm	21, 21, 30
	vaddudm	10, 8, 21
	vaddudm	13, 2, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 6, 2
	vaddudm	11, 11, 10
	vshasigmad	15, 7, 1, 15
	vshasigmad	14, 3, 1, 0
	vxor	12, 4, 5
	vsel	9, 1, 0, 7
	vsel	12, 5, 3, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	2, 15, 14
	vaddudm	6, 9, 15
	vaddudm	2, 2, 12
	vshasigmad	15, 20, 0, 15
	vshasigmad	14, 23, 0, 0
	vaddudm	22, 22, 15
	vaddudm	22, 22, 14
	vaddudm	22, 22, 31
	vaddudm	10, 8, 22
	vaddudm	13, 1, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 5, 1
	vaddudm	11, 11, 10
	vshasigmad	15, 6, 1, 15
	vshasigmad	14, 2, 1, 0
	vxor	12, 3, 4
	vsel	9, 0, 7, 6
	vsel	12, 4, 2, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	1, 15, 14
	vaddudm	5, 9, 15
	vaddudm	1, 1, 12
	vshasigmad	15, 21, 0, 15
	vshasigmad	14, 24, 0, 0
	vaddudm	23, 23, 15
	vaddudm	23, 23, 14
	vaddudm	23, 23, 16
	vaddudm	10, 8, 23
	vaddudm	13, 0, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 4, 0
	vaddudm	11, 11, 10
	vshasigmad	15, 5, 1, 15
	vshasigmad	14, 1, 1, 0
	vxor	12, 2, 3
	vsel	9, 7, 6, 5
	vsel	12, 3, 1, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	0, 15, 14
	vaddudm	4, 9, 15
	vaddudm	0, 0, 12
	vshasigmad	15, 22, 0, 15
	vshasigmad	14, 25, 0, 0
	vaddudm	24, 24, 15
	vaddudm	24, 24, 14
	vaddudm	24, 24, 17
	vaddudm	10, 8, 24
	vaddudm	13, 7, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 3, 7
	vaddudm	11, 11, 10
	vshasigmad	15, 4, 1, 15
	vshasigmad	14, 0, 1, 0
	vxor	12, 1, 2
	vsel	9, 6, 5, 4
	vsel	12, 2, 0, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	7, 15, 14
	vaddudm	3, 9, 15
	vaddudm	7, 7, 12
	vshasigmad	15, 23, 0, 15
	vshasigmad	14, 26, 0, 0
	vaddudm	25, 25, 15
	vaddudm	25, 25, 14
	vaddudm	25, 25, 18
	vaddudm	10, 8, 25
	vaddudm	13, 6, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 2, 6
	vaddudm	11, 11, 10
	vshasigmad	15, 3, 1, 15
	vshasigmad	14, 7, 1, 0
	vxor	12, 0, 1
	vsel	9, 5, 4, 3
	vsel	12, 1, 7, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	6, 15, 14
	vaddudm	2, 9, 15
	vaddudm	6, 6, 12
	vshasigmad	15, 24, 0, 15
	vshasigmad	14, 27, 0, 0
	vaddudm	26, 26, 15
	vaddudm	26, 26, 14
	vaddudm	26, 26, 19
	vaddudm	10, 8, 26
	vaddudm	13, 5, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 1, 5
	vaddudm	11, 11, 10
	vshasigmad	15, 2, 1, 15
	vshasigmad	14, 6, 1, 0
	vxor	12, 7, 0
	vsel	9, 4, 3, 2
	vsel	12, 0, 6, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	5, 15, 14
	vaddudm	1, 9, 15
	vaddudm	5, 5, 12
	vshasigmad	15, 25, 0, 15
	vshasigmad	14, 28, 0, 0
	vaddudm	27, 27, 15
	vaddudm	27, 27, 14
	vaddudm	27, 27, 20
	vaddudm	10, 8, 27
	vaddudm	13, 4, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 0, 4
	vaddudm	11, 11, 10
	vshasigmad	15, 1, 1, 15
	vshasigmad	14, 5, 1, 0
	vxor	12, 6, 7
	vsel	9, 3, 2, 1
	vsel	12, 7, 5, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	4, 15, 14
	vaddudm	0, 9, 15
	vaddudm	4, 4, 12
	vshasigmad	15, 26, 0, 15
	vshasigmad	14, 29, 0, 0
	vaddudm	28, 28, 15
	vaddudm	28, 28, 14
	vaddudm	28, 28, 21
	vaddudm	10, 8, 28
	vaddudm	13, 3, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 7, 3
	vaddudm	11, 11, 10
	vshasigmad	15, 0, 1, 15
	vshasigmad	14, 4, 1, 0
	vxor	12, 5, 6
	vsel	9, 2, 1, 0
	vsel	12, 6, 4, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	3, 15, 14
	vaddudm	7, 9, 15
	vaddudm	3, 3, 12
	vshasigmad	15, 27, 0, 15
	vshasigmad	14, 30, 0, 0
	vaddudm	29, 29, 15
	vaddudm	29, 29, 14
	vaddudm	29, 29, 22
	vaddudm	10, 8, 29
	vaddudm	13, 2, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 6, 2
	vaddudm	11, 11, 10
	vshasigmad	15, 7, 1, 15
	vshasigmad	14, 3, 1, 0
	vxor	12, 4, 5
	vsel	9, 1, 0, 7
	vsel	12, 5, 3, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	2, 15, 14
	vaddudm	6, 9, 15
	vaddudm	2, 2, 12
	vshasigmad	15, 28, 0, 15
	vshasigmad	14, 31, 0, 0
	vaddudm	30, 30, 15
	vaddudm	30, 30, 14
	vaddudm	30, 30, 23
	vaddudm	10, 8, 30
	vaddudm	13, 1, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 5, 1
	vaddudm	11, 11, 10
	vshasigmad	15, 6, 1, 15
	vshasigmad	14, 2, 1, 0
	vxor	12, 3, 4
	vsel	9, 0, 7, 6
	vsel	12, 4, 2, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	1, 15, 14
	vaddudm	5, 9, 15
	vaddudm	1, 1, 12
	vshasigmad	15, 29, 0, 15
	vshasigmad	14, 16, 0, 0
	vaddudm	31, 31, 15
	vaddudm	31, 31, 14
	vaddudm	31, 31, 24
	vaddudm	10, 8, 31
	vaddudm	13, 0, 10
	lxvd2x	40, 7, 6
	addi	7, 7, 8
	vaddudm	11, 4, 0
	vaddudm	11, 11, 10
	vshasigmad	15, 5, 1, 15
	vshasigmad	14, 1, 1, 0
	vxor	12, 2, 3
	vsel	9, 7, 6, 5
	vsel	12, 3, 1, 12
	vaddudm	13, 13, 9
	vaddudm	12, 12, 13
	vaddudm	9, 9, 11
	vaddudm	0, 15, 14
	vaddudm	4, 9, 15
	vaddudm	0, 0, 12
	# Repack state, add original digest and store
	xxmrghd	32, 32, 33
	xxmrghd	34, 34, 35
	xxmrghd	36, 36, 37
	xxmrghd	38, 38, 39
	lxvd2x	41, 0, 3
	lxvd2x	42, 8, 3
	lxvd2x	43, 9, 3
	lxvd2x	44, 10, 3
	vaddudm	0, 0, 9
	vaddudm	2, 2, 10
	vaddudm	4, 4, 11
	vaddudm	6, 6, 12
	stxvd2x	32, 0, 3
	stxvd2x	34, 8, 3
	stxvd2x	36, 9, 3
	stxvd2x	38, 10, 3
	bdnz	L_SHA512_crypto_begin
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
#if defined(_CALL_ELF) && _CALL_ELF == 2
	.size	Transform_Sha512_Len_crypto,.-Transform_Sha512_Len_crypto
#else
	.size	.L.Transform_Sha512_Len_crypto,.-.L.Transform_Sha512_Len_crypto
#endif /* _CALL_ELF == 2 */
#endif /* __APPLE__ */
	.machine	"pop"
#endif /* WOLFSSL_PPC64_ASM_CRYPTO */
#endif /* WOLFSSL_SHA512 || WOLFSSL_SHA384 */
#endif /* WOLFSSL_PPC64_ASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_PPC64_ASM_INLINE */
