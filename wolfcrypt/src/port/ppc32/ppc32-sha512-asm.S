/* ppc32-sha512-asm
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
 *   ruby ./sha2/sha512.rb ppc32 \
 *       ../wolfssl/wolfcrypt/src/port/ppc32/ppc32-sha512-asm.S
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

#ifdef WOLFSSL_PPC32_ASM
#ifndef WOLFSSL_PPC32_ASM_INLINE
	.machine ppc
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
	.section	".text"
	.align	4
	.globl	Transform_Sha512_Len
	.type	Transform_Sha512_Len, @function
Transform_Sha512_Len:
	stwu	1, -72(1)
	mflr	0
	stw	0, 68(1)
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
	srwi	5, 5, 7
	lis	30, L_SHA512_transform_len_k@ha
	la	30, L_SHA512_transform_len_k@l(30)
	# Copy digest to add in at end
	lwz	0, 0(3)
	lwz	6, 4(3)
	lwz	7, 8(3)
	lwz	8, 12(3)
	lwz	9, 16(3)
	lwz	10, 20(3)
	lwz	11, 24(3)
	lwz	12, 28(3)
	lwz	14, 32(3)
	lwz	15, 36(3)
	lwz	16, 40(3)
	lwz	17, 44(3)
	lwz	18, 48(3)
	lwz	19, 52(3)
	lwz	20, 56(3)
	lwz	21, 60(3)
	subi	1, 1, 0x80
	mtctr	5
	# Start of loop processing a block
L_SHA512_transform_len_begin:
	# Load W - 128 bytes
	lwz	22, 0(4)
	lwz	23, 4(4)
	stw	22, 0(1)
	stw	23, 4(1)
	lwz	22, 8(4)
	lwz	23, 12(4)
	stw	22, 8(1)
	stw	23, 12(1)
	lwz	22, 16(4)
	lwz	23, 20(4)
	stw	22, 16(1)
	stw	23, 20(1)
	lwz	22, 24(4)
	lwz	23, 28(4)
	stw	22, 24(1)
	stw	23, 28(1)
	lwz	22, 32(4)
	lwz	23, 36(4)
	stw	22, 32(1)
	stw	23, 36(1)
	lwz	22, 40(4)
	lwz	23, 44(4)
	stw	22, 40(1)
	stw	23, 44(1)
	lwz	22, 48(4)
	lwz	23, 52(4)
	stw	22, 48(1)
	stw	23, 52(1)
	lwz	22, 56(4)
	lwz	23, 60(4)
	stw	22, 56(1)
	stw	23, 60(1)
	lwz	22, 64(4)
	lwz	23, 68(4)
	stw	22, 64(1)
	stw	23, 68(1)
	lwz	22, 72(4)
	lwz	23, 76(4)
	stw	22, 72(1)
	stw	23, 76(1)
	lwz	22, 80(4)
	lwz	23, 84(4)
	stw	22, 80(1)
	stw	23, 84(1)
	lwz	22, 88(4)
	lwz	23, 92(4)
	stw	22, 88(1)
	stw	23, 92(1)
	lwz	22, 96(4)
	lwz	23, 100(4)
	stw	22, 96(1)
	stw	23, 100(1)
	lwz	22, 104(4)
	lwz	23, 108(4)
	stw	22, 104(1)
	stw	23, 108(1)
	lwz	22, 112(4)
	lwz	23, 116(4)
	stw	22, 112(1)
	stw	23, 116(1)
	lwz	22, 120(4)
	lwz	23, 124(4)
	stw	22, 120(1)
	stw	23, 124(1)
	# Start of 80 rounds
	# Round 0
	rlwinm	22, 14, 18, 14, 31
	rlwimi	22, 15, 18, 0, 13
	rlwinm	23, 15, 18, 14, 31
	rlwimi	23, 14, 18, 0, 13
	rlwinm	24, 14, 14, 18, 31
	rlwimi	24, 15, 14, 0, 17
	rlwinm	25, 15, 14, 18, 31
	rlwimi	25, 14, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 23, 9, 31
	rlwimi	24, 14, 23, 0, 8
	rlwinm	25, 14, 23, 9, 31
	rlwimi	25, 15, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 16, 18
	xor	23, 17, 19
	and	22, 22, 14
	and	23, 23, 15
	xor	22, 22, 18
	xor	23, 23, 19
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 0(1)
	lwz	23, 4(1)
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 0(30)
	lwz	23, 4(30)
	addc	21, 21, 23
	adde	20, 20, 22
	addc	12, 12, 21
	adde	11, 11, 20
	rlwinm	22, 0, 4, 28, 31
	rlwimi	22, 6, 4, 0, 27
	rlwinm	23, 6, 4, 28, 31
	rlwimi	23, 0, 4, 0, 27
	rlwinm	24, 6, 30, 2, 31
	rlwimi	24, 0, 30, 0, 1
	rlwinm	25, 0, 30, 2, 31
	rlwimi	25, 6, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 25, 7, 31
	rlwimi	24, 0, 25, 0, 6
	rlwinm	25, 0, 25, 7, 31
	rlwimi	25, 6, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 0, 7
	xor	23, 6, 8
	xor	24, 7, 9
	xor	25, 8, 10
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 7
	xor	23, 23, 8
	addc	21, 21, 23
	adde	20, 20, 22
	# Calc new W[0]
	lwz	28, 0(1)
	lwz	29, 4(1)
	lwz	24, 72(1)
	lwz	25, 76(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 112(1)
	lwz	23, 116(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 8(1)
	lwz	23, 12(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 0(1)
	stw	29, 4(1)
	# Round 1
	rlwinm	22, 11, 18, 14, 31
	rlwimi	22, 12, 18, 0, 13
	rlwinm	23, 12, 18, 14, 31
	rlwimi	23, 11, 18, 0, 13
	rlwinm	24, 11, 14, 18, 31
	rlwimi	24, 12, 14, 0, 17
	rlwinm	25, 12, 14, 18, 31
	rlwimi	25, 11, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 23, 9, 31
	rlwimi	24, 11, 23, 0, 8
	rlwinm	25, 11, 23, 9, 31
	rlwimi	25, 12, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 14, 16
	xor	23, 15, 17
	and	22, 22, 11
	and	23, 23, 12
	xor	22, 22, 16
	xor	23, 23, 17
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 8(1)
	lwz	23, 12(1)
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 8(30)
	lwz	23, 12(30)
	addc	19, 19, 23
	adde	18, 18, 22
	addc	10, 10, 19
	adde	9, 9, 18
	rlwinm	22, 20, 4, 28, 31
	rlwimi	22, 21, 4, 0, 27
	rlwinm	23, 21, 4, 28, 31
	rlwimi	23, 20, 4, 0, 27
	rlwinm	24, 21, 30, 2, 31
	rlwimi	24, 20, 30, 0, 1
	rlwinm	25, 20, 30, 2, 31
	rlwimi	25, 21, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 25, 7, 31
	rlwimi	24, 20, 25, 0, 6
	rlwinm	25, 20, 25, 7, 31
	rlwimi	25, 21, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 20, 0
	xor	23, 21, 6
	xor	24, 0, 7
	xor	25, 6, 8
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 0
	xor	23, 23, 6
	addc	19, 19, 23
	adde	18, 18, 22
	# Calc new W[1]
	lwz	28, 8(1)
	lwz	29, 12(1)
	lwz	24, 80(1)
	lwz	25, 84(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 120(1)
	lwz	23, 124(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 16(1)
	lwz	23, 20(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 8(1)
	stw	29, 12(1)
	# Round 2
	rlwinm	22, 9, 18, 14, 31
	rlwimi	22, 10, 18, 0, 13
	rlwinm	23, 10, 18, 14, 31
	rlwimi	23, 9, 18, 0, 13
	rlwinm	24, 9, 14, 18, 31
	rlwimi	24, 10, 14, 0, 17
	rlwinm	25, 10, 14, 18, 31
	rlwimi	25, 9, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 23, 9, 31
	rlwimi	24, 9, 23, 0, 8
	rlwinm	25, 9, 23, 9, 31
	rlwimi	25, 10, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 11, 14
	xor	23, 12, 15
	and	22, 22, 9
	and	23, 23, 10
	xor	22, 22, 14
	xor	23, 23, 15
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 16(1)
	lwz	23, 20(1)
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 16(30)
	lwz	23, 20(30)
	addc	17, 17, 23
	adde	16, 16, 22
	addc	8, 8, 17
	adde	7, 7, 16
	rlwinm	22, 18, 4, 28, 31
	rlwimi	22, 19, 4, 0, 27
	rlwinm	23, 19, 4, 28, 31
	rlwimi	23, 18, 4, 0, 27
	rlwinm	24, 19, 30, 2, 31
	rlwimi	24, 18, 30, 0, 1
	rlwinm	25, 18, 30, 2, 31
	rlwimi	25, 19, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 25, 7, 31
	rlwimi	24, 18, 25, 0, 6
	rlwinm	25, 18, 25, 7, 31
	rlwimi	25, 19, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 18, 20
	xor	23, 19, 21
	xor	24, 20, 0
	xor	25, 21, 6
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 20
	xor	23, 23, 21
	addc	17, 17, 23
	adde	16, 16, 22
	# Calc new W[2]
	lwz	28, 16(1)
	lwz	29, 20(1)
	lwz	24, 88(1)
	lwz	25, 92(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 0(1)
	lwz	23, 4(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 24(1)
	lwz	23, 28(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 16(1)
	stw	29, 20(1)
	# Round 3
	rlwinm	22, 7, 18, 14, 31
	rlwimi	22, 8, 18, 0, 13
	rlwinm	23, 8, 18, 14, 31
	rlwimi	23, 7, 18, 0, 13
	rlwinm	24, 7, 14, 18, 31
	rlwimi	24, 8, 14, 0, 17
	rlwinm	25, 8, 14, 18, 31
	rlwimi	25, 7, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 23, 9, 31
	rlwimi	24, 7, 23, 0, 8
	rlwinm	25, 7, 23, 9, 31
	rlwimi	25, 8, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 9, 11
	xor	23, 10, 12
	and	22, 22, 7
	and	23, 23, 8
	xor	22, 22, 11
	xor	23, 23, 12
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 24(1)
	lwz	23, 28(1)
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 24(30)
	lwz	23, 28(30)
	addc	15, 15, 23
	adde	14, 14, 22
	addc	6, 6, 15
	adde	0, 0, 14
	rlwinm	22, 16, 4, 28, 31
	rlwimi	22, 17, 4, 0, 27
	rlwinm	23, 17, 4, 28, 31
	rlwimi	23, 16, 4, 0, 27
	rlwinm	24, 17, 30, 2, 31
	rlwimi	24, 16, 30, 0, 1
	rlwinm	25, 16, 30, 2, 31
	rlwimi	25, 17, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 25, 7, 31
	rlwimi	24, 16, 25, 0, 6
	rlwinm	25, 16, 25, 7, 31
	rlwimi	25, 17, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 16, 18
	xor	23, 17, 19
	xor	24, 18, 20
	xor	25, 19, 21
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 18
	xor	23, 23, 19
	addc	15, 15, 23
	adde	14, 14, 22
	# Calc new W[3]
	lwz	28, 24(1)
	lwz	29, 28(1)
	lwz	24, 96(1)
	lwz	25, 100(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 8(1)
	lwz	23, 12(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 32(1)
	lwz	23, 36(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 24(1)
	stw	29, 28(1)
	# Round 4
	rlwinm	22, 0, 18, 14, 31
	rlwimi	22, 6, 18, 0, 13
	rlwinm	23, 6, 18, 14, 31
	rlwimi	23, 0, 18, 0, 13
	rlwinm	24, 0, 14, 18, 31
	rlwimi	24, 6, 14, 0, 17
	rlwinm	25, 6, 14, 18, 31
	rlwimi	25, 0, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 23, 9, 31
	rlwimi	24, 0, 23, 0, 8
	rlwinm	25, 0, 23, 9, 31
	rlwimi	25, 6, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 7, 9
	xor	23, 8, 10
	and	22, 22, 0
	and	23, 23, 6
	xor	22, 22, 9
	xor	23, 23, 10
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 32(1)
	lwz	23, 36(1)
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 32(30)
	lwz	23, 36(30)
	addc	12, 12, 23
	adde	11, 11, 22
	addc	21, 21, 12
	adde	20, 20, 11
	rlwinm	22, 14, 4, 28, 31
	rlwimi	22, 15, 4, 0, 27
	rlwinm	23, 15, 4, 28, 31
	rlwimi	23, 14, 4, 0, 27
	rlwinm	24, 15, 30, 2, 31
	rlwimi	24, 14, 30, 0, 1
	rlwinm	25, 14, 30, 2, 31
	rlwimi	25, 15, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 25, 7, 31
	rlwimi	24, 14, 25, 0, 6
	rlwinm	25, 14, 25, 7, 31
	rlwimi	25, 15, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 14, 16
	xor	23, 15, 17
	xor	24, 16, 18
	xor	25, 17, 19
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 16
	xor	23, 23, 17
	addc	12, 12, 23
	adde	11, 11, 22
	# Calc new W[4]
	lwz	28, 32(1)
	lwz	29, 36(1)
	lwz	24, 104(1)
	lwz	25, 108(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 16(1)
	lwz	23, 20(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 40(1)
	lwz	23, 44(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 32(1)
	stw	29, 36(1)
	# Round 5
	rlwinm	22, 20, 18, 14, 31
	rlwimi	22, 21, 18, 0, 13
	rlwinm	23, 21, 18, 14, 31
	rlwimi	23, 20, 18, 0, 13
	rlwinm	24, 20, 14, 18, 31
	rlwimi	24, 21, 14, 0, 17
	rlwinm	25, 21, 14, 18, 31
	rlwimi	25, 20, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 23, 9, 31
	rlwimi	24, 20, 23, 0, 8
	rlwinm	25, 20, 23, 9, 31
	rlwimi	25, 21, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 0, 7
	xor	23, 6, 8
	and	22, 22, 20
	and	23, 23, 21
	xor	22, 22, 7
	xor	23, 23, 8
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 40(1)
	lwz	23, 44(1)
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 40(30)
	lwz	23, 44(30)
	addc	10, 10, 23
	adde	9, 9, 22
	addc	19, 19, 10
	adde	18, 18, 9
	rlwinm	22, 11, 4, 28, 31
	rlwimi	22, 12, 4, 0, 27
	rlwinm	23, 12, 4, 28, 31
	rlwimi	23, 11, 4, 0, 27
	rlwinm	24, 12, 30, 2, 31
	rlwimi	24, 11, 30, 0, 1
	rlwinm	25, 11, 30, 2, 31
	rlwimi	25, 12, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 25, 7, 31
	rlwimi	24, 11, 25, 0, 6
	rlwinm	25, 11, 25, 7, 31
	rlwimi	25, 12, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 11, 14
	xor	23, 12, 15
	xor	24, 14, 16
	xor	25, 15, 17
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 14
	xor	23, 23, 15
	addc	10, 10, 23
	adde	9, 9, 22
	# Calc new W[5]
	lwz	28, 40(1)
	lwz	29, 44(1)
	lwz	24, 112(1)
	lwz	25, 116(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 24(1)
	lwz	23, 28(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 48(1)
	lwz	23, 52(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 40(1)
	stw	29, 44(1)
	# Round 6
	rlwinm	22, 18, 18, 14, 31
	rlwimi	22, 19, 18, 0, 13
	rlwinm	23, 19, 18, 14, 31
	rlwimi	23, 18, 18, 0, 13
	rlwinm	24, 18, 14, 18, 31
	rlwimi	24, 19, 14, 0, 17
	rlwinm	25, 19, 14, 18, 31
	rlwimi	25, 18, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 23, 9, 31
	rlwimi	24, 18, 23, 0, 8
	rlwinm	25, 18, 23, 9, 31
	rlwimi	25, 19, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 20, 0
	xor	23, 21, 6
	and	22, 22, 18
	and	23, 23, 19
	xor	22, 22, 0
	xor	23, 23, 6
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 48(1)
	lwz	23, 52(1)
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 48(30)
	lwz	23, 52(30)
	addc	8, 8, 23
	adde	7, 7, 22
	addc	17, 17, 8
	adde	16, 16, 7
	rlwinm	22, 9, 4, 28, 31
	rlwimi	22, 10, 4, 0, 27
	rlwinm	23, 10, 4, 28, 31
	rlwimi	23, 9, 4, 0, 27
	rlwinm	24, 10, 30, 2, 31
	rlwimi	24, 9, 30, 0, 1
	rlwinm	25, 9, 30, 2, 31
	rlwimi	25, 10, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 25, 7, 31
	rlwimi	24, 9, 25, 0, 6
	rlwinm	25, 9, 25, 7, 31
	rlwimi	25, 10, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 9, 11
	xor	23, 10, 12
	xor	24, 11, 14
	xor	25, 12, 15
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 11
	xor	23, 23, 12
	addc	8, 8, 23
	adde	7, 7, 22
	# Calc new W[6]
	lwz	28, 48(1)
	lwz	29, 52(1)
	lwz	24, 120(1)
	lwz	25, 124(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 32(1)
	lwz	23, 36(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 56(1)
	lwz	23, 60(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 48(1)
	stw	29, 52(1)
	# Round 7
	rlwinm	22, 16, 18, 14, 31
	rlwimi	22, 17, 18, 0, 13
	rlwinm	23, 17, 18, 14, 31
	rlwimi	23, 16, 18, 0, 13
	rlwinm	24, 16, 14, 18, 31
	rlwimi	24, 17, 14, 0, 17
	rlwinm	25, 17, 14, 18, 31
	rlwimi	25, 16, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 23, 9, 31
	rlwimi	24, 16, 23, 0, 8
	rlwinm	25, 16, 23, 9, 31
	rlwimi	25, 17, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 18, 20
	xor	23, 19, 21
	and	22, 22, 16
	and	23, 23, 17
	xor	22, 22, 20
	xor	23, 23, 21
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 56(1)
	lwz	23, 60(1)
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 56(30)
	lwz	23, 60(30)
	addc	6, 6, 23
	adde	0, 0, 22
	addc	15, 15, 6
	adde	14, 14, 0
	rlwinm	22, 7, 4, 28, 31
	rlwimi	22, 8, 4, 0, 27
	rlwinm	23, 8, 4, 28, 31
	rlwimi	23, 7, 4, 0, 27
	rlwinm	24, 8, 30, 2, 31
	rlwimi	24, 7, 30, 0, 1
	rlwinm	25, 7, 30, 2, 31
	rlwimi	25, 8, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 25, 7, 31
	rlwimi	24, 7, 25, 0, 6
	rlwinm	25, 7, 25, 7, 31
	rlwimi	25, 8, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 7, 9
	xor	23, 8, 10
	xor	24, 9, 11
	xor	25, 10, 12
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 9
	xor	23, 23, 10
	addc	6, 6, 23
	adde	0, 0, 22
	# Calc new W[7]
	lwz	28, 56(1)
	lwz	29, 60(1)
	lwz	24, 0(1)
	lwz	25, 4(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 40(1)
	lwz	23, 44(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 64(1)
	lwz	23, 68(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 56(1)
	stw	29, 60(1)
	# Round 8
	rlwinm	22, 14, 18, 14, 31
	rlwimi	22, 15, 18, 0, 13
	rlwinm	23, 15, 18, 14, 31
	rlwimi	23, 14, 18, 0, 13
	rlwinm	24, 14, 14, 18, 31
	rlwimi	24, 15, 14, 0, 17
	rlwinm	25, 15, 14, 18, 31
	rlwimi	25, 14, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 23, 9, 31
	rlwimi	24, 14, 23, 0, 8
	rlwinm	25, 14, 23, 9, 31
	rlwimi	25, 15, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 16, 18
	xor	23, 17, 19
	and	22, 22, 14
	and	23, 23, 15
	xor	22, 22, 18
	xor	23, 23, 19
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 64(1)
	lwz	23, 68(1)
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 64(30)
	lwz	23, 68(30)
	addc	21, 21, 23
	adde	20, 20, 22
	addc	12, 12, 21
	adde	11, 11, 20
	rlwinm	22, 0, 4, 28, 31
	rlwimi	22, 6, 4, 0, 27
	rlwinm	23, 6, 4, 28, 31
	rlwimi	23, 0, 4, 0, 27
	rlwinm	24, 6, 30, 2, 31
	rlwimi	24, 0, 30, 0, 1
	rlwinm	25, 0, 30, 2, 31
	rlwimi	25, 6, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 25, 7, 31
	rlwimi	24, 0, 25, 0, 6
	rlwinm	25, 0, 25, 7, 31
	rlwimi	25, 6, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 0, 7
	xor	23, 6, 8
	xor	24, 7, 9
	xor	25, 8, 10
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 7
	xor	23, 23, 8
	addc	21, 21, 23
	adde	20, 20, 22
	# Calc new W[8]
	lwz	28, 64(1)
	lwz	29, 68(1)
	lwz	24, 8(1)
	lwz	25, 12(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 48(1)
	lwz	23, 52(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 72(1)
	lwz	23, 76(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 64(1)
	stw	29, 68(1)
	# Round 9
	rlwinm	22, 11, 18, 14, 31
	rlwimi	22, 12, 18, 0, 13
	rlwinm	23, 12, 18, 14, 31
	rlwimi	23, 11, 18, 0, 13
	rlwinm	24, 11, 14, 18, 31
	rlwimi	24, 12, 14, 0, 17
	rlwinm	25, 12, 14, 18, 31
	rlwimi	25, 11, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 23, 9, 31
	rlwimi	24, 11, 23, 0, 8
	rlwinm	25, 11, 23, 9, 31
	rlwimi	25, 12, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 14, 16
	xor	23, 15, 17
	and	22, 22, 11
	and	23, 23, 12
	xor	22, 22, 16
	xor	23, 23, 17
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 72(1)
	lwz	23, 76(1)
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 72(30)
	lwz	23, 76(30)
	addc	19, 19, 23
	adde	18, 18, 22
	addc	10, 10, 19
	adde	9, 9, 18
	rlwinm	22, 20, 4, 28, 31
	rlwimi	22, 21, 4, 0, 27
	rlwinm	23, 21, 4, 28, 31
	rlwimi	23, 20, 4, 0, 27
	rlwinm	24, 21, 30, 2, 31
	rlwimi	24, 20, 30, 0, 1
	rlwinm	25, 20, 30, 2, 31
	rlwimi	25, 21, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 25, 7, 31
	rlwimi	24, 20, 25, 0, 6
	rlwinm	25, 20, 25, 7, 31
	rlwimi	25, 21, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 20, 0
	xor	23, 21, 6
	xor	24, 0, 7
	xor	25, 6, 8
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 0
	xor	23, 23, 6
	addc	19, 19, 23
	adde	18, 18, 22
	# Calc new W[9]
	lwz	28, 72(1)
	lwz	29, 76(1)
	lwz	24, 16(1)
	lwz	25, 20(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 56(1)
	lwz	23, 60(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 80(1)
	lwz	23, 84(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 72(1)
	stw	29, 76(1)
	# Round 10
	rlwinm	22, 9, 18, 14, 31
	rlwimi	22, 10, 18, 0, 13
	rlwinm	23, 10, 18, 14, 31
	rlwimi	23, 9, 18, 0, 13
	rlwinm	24, 9, 14, 18, 31
	rlwimi	24, 10, 14, 0, 17
	rlwinm	25, 10, 14, 18, 31
	rlwimi	25, 9, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 23, 9, 31
	rlwimi	24, 9, 23, 0, 8
	rlwinm	25, 9, 23, 9, 31
	rlwimi	25, 10, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 11, 14
	xor	23, 12, 15
	and	22, 22, 9
	and	23, 23, 10
	xor	22, 22, 14
	xor	23, 23, 15
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 80(1)
	lwz	23, 84(1)
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 80(30)
	lwz	23, 84(30)
	addc	17, 17, 23
	adde	16, 16, 22
	addc	8, 8, 17
	adde	7, 7, 16
	rlwinm	22, 18, 4, 28, 31
	rlwimi	22, 19, 4, 0, 27
	rlwinm	23, 19, 4, 28, 31
	rlwimi	23, 18, 4, 0, 27
	rlwinm	24, 19, 30, 2, 31
	rlwimi	24, 18, 30, 0, 1
	rlwinm	25, 18, 30, 2, 31
	rlwimi	25, 19, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 25, 7, 31
	rlwimi	24, 18, 25, 0, 6
	rlwinm	25, 18, 25, 7, 31
	rlwimi	25, 19, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 18, 20
	xor	23, 19, 21
	xor	24, 20, 0
	xor	25, 21, 6
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 20
	xor	23, 23, 21
	addc	17, 17, 23
	adde	16, 16, 22
	# Calc new W[10]
	lwz	28, 80(1)
	lwz	29, 84(1)
	lwz	24, 24(1)
	lwz	25, 28(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 64(1)
	lwz	23, 68(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 88(1)
	lwz	23, 92(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 80(1)
	stw	29, 84(1)
	# Round 11
	rlwinm	22, 7, 18, 14, 31
	rlwimi	22, 8, 18, 0, 13
	rlwinm	23, 8, 18, 14, 31
	rlwimi	23, 7, 18, 0, 13
	rlwinm	24, 7, 14, 18, 31
	rlwimi	24, 8, 14, 0, 17
	rlwinm	25, 8, 14, 18, 31
	rlwimi	25, 7, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 23, 9, 31
	rlwimi	24, 7, 23, 0, 8
	rlwinm	25, 7, 23, 9, 31
	rlwimi	25, 8, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 9, 11
	xor	23, 10, 12
	and	22, 22, 7
	and	23, 23, 8
	xor	22, 22, 11
	xor	23, 23, 12
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 88(1)
	lwz	23, 92(1)
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 88(30)
	lwz	23, 92(30)
	addc	15, 15, 23
	adde	14, 14, 22
	addc	6, 6, 15
	adde	0, 0, 14
	rlwinm	22, 16, 4, 28, 31
	rlwimi	22, 17, 4, 0, 27
	rlwinm	23, 17, 4, 28, 31
	rlwimi	23, 16, 4, 0, 27
	rlwinm	24, 17, 30, 2, 31
	rlwimi	24, 16, 30, 0, 1
	rlwinm	25, 16, 30, 2, 31
	rlwimi	25, 17, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 25, 7, 31
	rlwimi	24, 16, 25, 0, 6
	rlwinm	25, 16, 25, 7, 31
	rlwimi	25, 17, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 16, 18
	xor	23, 17, 19
	xor	24, 18, 20
	xor	25, 19, 21
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 18
	xor	23, 23, 19
	addc	15, 15, 23
	adde	14, 14, 22
	# Calc new W[11]
	lwz	28, 88(1)
	lwz	29, 92(1)
	lwz	24, 32(1)
	lwz	25, 36(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 72(1)
	lwz	23, 76(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 96(1)
	lwz	23, 100(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 88(1)
	stw	29, 92(1)
	# Round 12
	rlwinm	22, 0, 18, 14, 31
	rlwimi	22, 6, 18, 0, 13
	rlwinm	23, 6, 18, 14, 31
	rlwimi	23, 0, 18, 0, 13
	rlwinm	24, 0, 14, 18, 31
	rlwimi	24, 6, 14, 0, 17
	rlwinm	25, 6, 14, 18, 31
	rlwimi	25, 0, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 23, 9, 31
	rlwimi	24, 0, 23, 0, 8
	rlwinm	25, 0, 23, 9, 31
	rlwimi	25, 6, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 7, 9
	xor	23, 8, 10
	and	22, 22, 0
	and	23, 23, 6
	xor	22, 22, 9
	xor	23, 23, 10
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 96(1)
	lwz	23, 100(1)
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 96(30)
	lwz	23, 100(30)
	addc	12, 12, 23
	adde	11, 11, 22
	addc	21, 21, 12
	adde	20, 20, 11
	rlwinm	22, 14, 4, 28, 31
	rlwimi	22, 15, 4, 0, 27
	rlwinm	23, 15, 4, 28, 31
	rlwimi	23, 14, 4, 0, 27
	rlwinm	24, 15, 30, 2, 31
	rlwimi	24, 14, 30, 0, 1
	rlwinm	25, 14, 30, 2, 31
	rlwimi	25, 15, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 25, 7, 31
	rlwimi	24, 14, 25, 0, 6
	rlwinm	25, 14, 25, 7, 31
	rlwimi	25, 15, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 14, 16
	xor	23, 15, 17
	xor	24, 16, 18
	xor	25, 17, 19
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 16
	xor	23, 23, 17
	addc	12, 12, 23
	adde	11, 11, 22
	# Calc new W[12]
	lwz	28, 96(1)
	lwz	29, 100(1)
	lwz	24, 40(1)
	lwz	25, 44(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 80(1)
	lwz	23, 84(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 104(1)
	lwz	23, 108(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 96(1)
	stw	29, 100(1)
	# Round 13
	rlwinm	22, 20, 18, 14, 31
	rlwimi	22, 21, 18, 0, 13
	rlwinm	23, 21, 18, 14, 31
	rlwimi	23, 20, 18, 0, 13
	rlwinm	24, 20, 14, 18, 31
	rlwimi	24, 21, 14, 0, 17
	rlwinm	25, 21, 14, 18, 31
	rlwimi	25, 20, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 23, 9, 31
	rlwimi	24, 20, 23, 0, 8
	rlwinm	25, 20, 23, 9, 31
	rlwimi	25, 21, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 0, 7
	xor	23, 6, 8
	and	22, 22, 20
	and	23, 23, 21
	xor	22, 22, 7
	xor	23, 23, 8
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 104(1)
	lwz	23, 108(1)
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 104(30)
	lwz	23, 108(30)
	addc	10, 10, 23
	adde	9, 9, 22
	addc	19, 19, 10
	adde	18, 18, 9
	rlwinm	22, 11, 4, 28, 31
	rlwimi	22, 12, 4, 0, 27
	rlwinm	23, 12, 4, 28, 31
	rlwimi	23, 11, 4, 0, 27
	rlwinm	24, 12, 30, 2, 31
	rlwimi	24, 11, 30, 0, 1
	rlwinm	25, 11, 30, 2, 31
	rlwimi	25, 12, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 25, 7, 31
	rlwimi	24, 11, 25, 0, 6
	rlwinm	25, 11, 25, 7, 31
	rlwimi	25, 12, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 11, 14
	xor	23, 12, 15
	xor	24, 14, 16
	xor	25, 15, 17
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 14
	xor	23, 23, 15
	addc	10, 10, 23
	adde	9, 9, 22
	# Calc new W[13]
	lwz	28, 104(1)
	lwz	29, 108(1)
	lwz	24, 48(1)
	lwz	25, 52(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 88(1)
	lwz	23, 92(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 112(1)
	lwz	23, 116(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 104(1)
	stw	29, 108(1)
	# Round 14
	rlwinm	22, 18, 18, 14, 31
	rlwimi	22, 19, 18, 0, 13
	rlwinm	23, 19, 18, 14, 31
	rlwimi	23, 18, 18, 0, 13
	rlwinm	24, 18, 14, 18, 31
	rlwimi	24, 19, 14, 0, 17
	rlwinm	25, 19, 14, 18, 31
	rlwimi	25, 18, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 23, 9, 31
	rlwimi	24, 18, 23, 0, 8
	rlwinm	25, 18, 23, 9, 31
	rlwimi	25, 19, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 20, 0
	xor	23, 21, 6
	and	22, 22, 18
	and	23, 23, 19
	xor	22, 22, 0
	xor	23, 23, 6
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 112(1)
	lwz	23, 116(1)
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 112(30)
	lwz	23, 116(30)
	addc	8, 8, 23
	adde	7, 7, 22
	addc	17, 17, 8
	adde	16, 16, 7
	rlwinm	22, 9, 4, 28, 31
	rlwimi	22, 10, 4, 0, 27
	rlwinm	23, 10, 4, 28, 31
	rlwimi	23, 9, 4, 0, 27
	rlwinm	24, 10, 30, 2, 31
	rlwimi	24, 9, 30, 0, 1
	rlwinm	25, 9, 30, 2, 31
	rlwimi	25, 10, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 25, 7, 31
	rlwimi	24, 9, 25, 0, 6
	rlwinm	25, 9, 25, 7, 31
	rlwimi	25, 10, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 9, 11
	xor	23, 10, 12
	xor	24, 11, 14
	xor	25, 12, 15
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 11
	xor	23, 23, 12
	addc	8, 8, 23
	adde	7, 7, 22
	# Calc new W[14]
	lwz	28, 112(1)
	lwz	29, 116(1)
	lwz	24, 56(1)
	lwz	25, 60(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 96(1)
	lwz	23, 100(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 120(1)
	lwz	23, 124(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 112(1)
	stw	29, 116(1)
	# Round 15
	rlwinm	22, 16, 18, 14, 31
	rlwimi	22, 17, 18, 0, 13
	rlwinm	23, 17, 18, 14, 31
	rlwimi	23, 16, 18, 0, 13
	rlwinm	24, 16, 14, 18, 31
	rlwimi	24, 17, 14, 0, 17
	rlwinm	25, 17, 14, 18, 31
	rlwimi	25, 16, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 23, 9, 31
	rlwimi	24, 16, 23, 0, 8
	rlwinm	25, 16, 23, 9, 31
	rlwimi	25, 17, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 18, 20
	xor	23, 19, 21
	and	22, 22, 16
	and	23, 23, 17
	xor	22, 22, 20
	xor	23, 23, 21
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 120(1)
	lwz	23, 124(1)
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 120(30)
	lwz	23, 124(30)
	addc	6, 6, 23
	adde	0, 0, 22
	addc	15, 15, 6
	adde	14, 14, 0
	rlwinm	22, 7, 4, 28, 31
	rlwimi	22, 8, 4, 0, 27
	rlwinm	23, 8, 4, 28, 31
	rlwimi	23, 7, 4, 0, 27
	rlwinm	24, 8, 30, 2, 31
	rlwimi	24, 7, 30, 0, 1
	rlwinm	25, 7, 30, 2, 31
	rlwimi	25, 8, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 25, 7, 31
	rlwimi	24, 7, 25, 0, 6
	rlwinm	25, 7, 25, 7, 31
	rlwimi	25, 8, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 7, 9
	xor	23, 8, 10
	xor	24, 9, 11
	xor	25, 10, 12
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 9
	xor	23, 23, 10
	addc	6, 6, 23
	adde	0, 0, 22
	# Calc new W[15]
	lwz	28, 120(1)
	lwz	29, 124(1)
	lwz	24, 64(1)
	lwz	25, 68(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 104(1)
	lwz	23, 108(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 0(1)
	lwz	23, 4(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 120(1)
	stw	29, 124(1)
	addi	30, 30, 0x80
	# Round 0
	rlwinm	22, 14, 18, 14, 31
	rlwimi	22, 15, 18, 0, 13
	rlwinm	23, 15, 18, 14, 31
	rlwimi	23, 14, 18, 0, 13
	rlwinm	24, 14, 14, 18, 31
	rlwimi	24, 15, 14, 0, 17
	rlwinm	25, 15, 14, 18, 31
	rlwimi	25, 14, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 23, 9, 31
	rlwimi	24, 14, 23, 0, 8
	rlwinm	25, 14, 23, 9, 31
	rlwimi	25, 15, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 16, 18
	xor	23, 17, 19
	and	22, 22, 14
	and	23, 23, 15
	xor	22, 22, 18
	xor	23, 23, 19
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 0(1)
	lwz	23, 4(1)
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 0(30)
	lwz	23, 4(30)
	addc	21, 21, 23
	adde	20, 20, 22
	addc	12, 12, 21
	adde	11, 11, 20
	rlwinm	22, 0, 4, 28, 31
	rlwimi	22, 6, 4, 0, 27
	rlwinm	23, 6, 4, 28, 31
	rlwimi	23, 0, 4, 0, 27
	rlwinm	24, 6, 30, 2, 31
	rlwimi	24, 0, 30, 0, 1
	rlwinm	25, 0, 30, 2, 31
	rlwimi	25, 6, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 25, 7, 31
	rlwimi	24, 0, 25, 0, 6
	rlwinm	25, 0, 25, 7, 31
	rlwimi	25, 6, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 0, 7
	xor	23, 6, 8
	xor	24, 7, 9
	xor	25, 8, 10
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 7
	xor	23, 23, 8
	addc	21, 21, 23
	adde	20, 20, 22
	# Calc new W[0]
	lwz	28, 0(1)
	lwz	29, 4(1)
	lwz	24, 72(1)
	lwz	25, 76(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 112(1)
	lwz	23, 116(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 8(1)
	lwz	23, 12(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 0(1)
	stw	29, 4(1)
	# Round 1
	rlwinm	22, 11, 18, 14, 31
	rlwimi	22, 12, 18, 0, 13
	rlwinm	23, 12, 18, 14, 31
	rlwimi	23, 11, 18, 0, 13
	rlwinm	24, 11, 14, 18, 31
	rlwimi	24, 12, 14, 0, 17
	rlwinm	25, 12, 14, 18, 31
	rlwimi	25, 11, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 23, 9, 31
	rlwimi	24, 11, 23, 0, 8
	rlwinm	25, 11, 23, 9, 31
	rlwimi	25, 12, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 14, 16
	xor	23, 15, 17
	and	22, 22, 11
	and	23, 23, 12
	xor	22, 22, 16
	xor	23, 23, 17
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 8(1)
	lwz	23, 12(1)
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 8(30)
	lwz	23, 12(30)
	addc	19, 19, 23
	adde	18, 18, 22
	addc	10, 10, 19
	adde	9, 9, 18
	rlwinm	22, 20, 4, 28, 31
	rlwimi	22, 21, 4, 0, 27
	rlwinm	23, 21, 4, 28, 31
	rlwimi	23, 20, 4, 0, 27
	rlwinm	24, 21, 30, 2, 31
	rlwimi	24, 20, 30, 0, 1
	rlwinm	25, 20, 30, 2, 31
	rlwimi	25, 21, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 25, 7, 31
	rlwimi	24, 20, 25, 0, 6
	rlwinm	25, 20, 25, 7, 31
	rlwimi	25, 21, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 20, 0
	xor	23, 21, 6
	xor	24, 0, 7
	xor	25, 6, 8
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 0
	xor	23, 23, 6
	addc	19, 19, 23
	adde	18, 18, 22
	# Calc new W[1]
	lwz	28, 8(1)
	lwz	29, 12(1)
	lwz	24, 80(1)
	lwz	25, 84(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 120(1)
	lwz	23, 124(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 16(1)
	lwz	23, 20(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 8(1)
	stw	29, 12(1)
	# Round 2
	rlwinm	22, 9, 18, 14, 31
	rlwimi	22, 10, 18, 0, 13
	rlwinm	23, 10, 18, 14, 31
	rlwimi	23, 9, 18, 0, 13
	rlwinm	24, 9, 14, 18, 31
	rlwimi	24, 10, 14, 0, 17
	rlwinm	25, 10, 14, 18, 31
	rlwimi	25, 9, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 23, 9, 31
	rlwimi	24, 9, 23, 0, 8
	rlwinm	25, 9, 23, 9, 31
	rlwimi	25, 10, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 11, 14
	xor	23, 12, 15
	and	22, 22, 9
	and	23, 23, 10
	xor	22, 22, 14
	xor	23, 23, 15
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 16(1)
	lwz	23, 20(1)
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 16(30)
	lwz	23, 20(30)
	addc	17, 17, 23
	adde	16, 16, 22
	addc	8, 8, 17
	adde	7, 7, 16
	rlwinm	22, 18, 4, 28, 31
	rlwimi	22, 19, 4, 0, 27
	rlwinm	23, 19, 4, 28, 31
	rlwimi	23, 18, 4, 0, 27
	rlwinm	24, 19, 30, 2, 31
	rlwimi	24, 18, 30, 0, 1
	rlwinm	25, 18, 30, 2, 31
	rlwimi	25, 19, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 25, 7, 31
	rlwimi	24, 18, 25, 0, 6
	rlwinm	25, 18, 25, 7, 31
	rlwimi	25, 19, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 18, 20
	xor	23, 19, 21
	xor	24, 20, 0
	xor	25, 21, 6
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 20
	xor	23, 23, 21
	addc	17, 17, 23
	adde	16, 16, 22
	# Calc new W[2]
	lwz	28, 16(1)
	lwz	29, 20(1)
	lwz	24, 88(1)
	lwz	25, 92(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 0(1)
	lwz	23, 4(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 24(1)
	lwz	23, 28(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 16(1)
	stw	29, 20(1)
	# Round 3
	rlwinm	22, 7, 18, 14, 31
	rlwimi	22, 8, 18, 0, 13
	rlwinm	23, 8, 18, 14, 31
	rlwimi	23, 7, 18, 0, 13
	rlwinm	24, 7, 14, 18, 31
	rlwimi	24, 8, 14, 0, 17
	rlwinm	25, 8, 14, 18, 31
	rlwimi	25, 7, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 23, 9, 31
	rlwimi	24, 7, 23, 0, 8
	rlwinm	25, 7, 23, 9, 31
	rlwimi	25, 8, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 9, 11
	xor	23, 10, 12
	and	22, 22, 7
	and	23, 23, 8
	xor	22, 22, 11
	xor	23, 23, 12
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 24(1)
	lwz	23, 28(1)
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 24(30)
	lwz	23, 28(30)
	addc	15, 15, 23
	adde	14, 14, 22
	addc	6, 6, 15
	adde	0, 0, 14
	rlwinm	22, 16, 4, 28, 31
	rlwimi	22, 17, 4, 0, 27
	rlwinm	23, 17, 4, 28, 31
	rlwimi	23, 16, 4, 0, 27
	rlwinm	24, 17, 30, 2, 31
	rlwimi	24, 16, 30, 0, 1
	rlwinm	25, 16, 30, 2, 31
	rlwimi	25, 17, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 25, 7, 31
	rlwimi	24, 16, 25, 0, 6
	rlwinm	25, 16, 25, 7, 31
	rlwimi	25, 17, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 16, 18
	xor	23, 17, 19
	xor	24, 18, 20
	xor	25, 19, 21
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 18
	xor	23, 23, 19
	addc	15, 15, 23
	adde	14, 14, 22
	# Calc new W[3]
	lwz	28, 24(1)
	lwz	29, 28(1)
	lwz	24, 96(1)
	lwz	25, 100(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 8(1)
	lwz	23, 12(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 32(1)
	lwz	23, 36(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 24(1)
	stw	29, 28(1)
	# Round 4
	rlwinm	22, 0, 18, 14, 31
	rlwimi	22, 6, 18, 0, 13
	rlwinm	23, 6, 18, 14, 31
	rlwimi	23, 0, 18, 0, 13
	rlwinm	24, 0, 14, 18, 31
	rlwimi	24, 6, 14, 0, 17
	rlwinm	25, 6, 14, 18, 31
	rlwimi	25, 0, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 23, 9, 31
	rlwimi	24, 0, 23, 0, 8
	rlwinm	25, 0, 23, 9, 31
	rlwimi	25, 6, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 7, 9
	xor	23, 8, 10
	and	22, 22, 0
	and	23, 23, 6
	xor	22, 22, 9
	xor	23, 23, 10
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 32(1)
	lwz	23, 36(1)
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 32(30)
	lwz	23, 36(30)
	addc	12, 12, 23
	adde	11, 11, 22
	addc	21, 21, 12
	adde	20, 20, 11
	rlwinm	22, 14, 4, 28, 31
	rlwimi	22, 15, 4, 0, 27
	rlwinm	23, 15, 4, 28, 31
	rlwimi	23, 14, 4, 0, 27
	rlwinm	24, 15, 30, 2, 31
	rlwimi	24, 14, 30, 0, 1
	rlwinm	25, 14, 30, 2, 31
	rlwimi	25, 15, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 25, 7, 31
	rlwimi	24, 14, 25, 0, 6
	rlwinm	25, 14, 25, 7, 31
	rlwimi	25, 15, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 14, 16
	xor	23, 15, 17
	xor	24, 16, 18
	xor	25, 17, 19
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 16
	xor	23, 23, 17
	addc	12, 12, 23
	adde	11, 11, 22
	# Calc new W[4]
	lwz	28, 32(1)
	lwz	29, 36(1)
	lwz	24, 104(1)
	lwz	25, 108(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 16(1)
	lwz	23, 20(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 40(1)
	lwz	23, 44(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 32(1)
	stw	29, 36(1)
	# Round 5
	rlwinm	22, 20, 18, 14, 31
	rlwimi	22, 21, 18, 0, 13
	rlwinm	23, 21, 18, 14, 31
	rlwimi	23, 20, 18, 0, 13
	rlwinm	24, 20, 14, 18, 31
	rlwimi	24, 21, 14, 0, 17
	rlwinm	25, 21, 14, 18, 31
	rlwimi	25, 20, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 23, 9, 31
	rlwimi	24, 20, 23, 0, 8
	rlwinm	25, 20, 23, 9, 31
	rlwimi	25, 21, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 0, 7
	xor	23, 6, 8
	and	22, 22, 20
	and	23, 23, 21
	xor	22, 22, 7
	xor	23, 23, 8
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 40(1)
	lwz	23, 44(1)
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 40(30)
	lwz	23, 44(30)
	addc	10, 10, 23
	adde	9, 9, 22
	addc	19, 19, 10
	adde	18, 18, 9
	rlwinm	22, 11, 4, 28, 31
	rlwimi	22, 12, 4, 0, 27
	rlwinm	23, 12, 4, 28, 31
	rlwimi	23, 11, 4, 0, 27
	rlwinm	24, 12, 30, 2, 31
	rlwimi	24, 11, 30, 0, 1
	rlwinm	25, 11, 30, 2, 31
	rlwimi	25, 12, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 25, 7, 31
	rlwimi	24, 11, 25, 0, 6
	rlwinm	25, 11, 25, 7, 31
	rlwimi	25, 12, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 11, 14
	xor	23, 12, 15
	xor	24, 14, 16
	xor	25, 15, 17
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 14
	xor	23, 23, 15
	addc	10, 10, 23
	adde	9, 9, 22
	# Calc new W[5]
	lwz	28, 40(1)
	lwz	29, 44(1)
	lwz	24, 112(1)
	lwz	25, 116(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 24(1)
	lwz	23, 28(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 48(1)
	lwz	23, 52(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 40(1)
	stw	29, 44(1)
	# Round 6
	rlwinm	22, 18, 18, 14, 31
	rlwimi	22, 19, 18, 0, 13
	rlwinm	23, 19, 18, 14, 31
	rlwimi	23, 18, 18, 0, 13
	rlwinm	24, 18, 14, 18, 31
	rlwimi	24, 19, 14, 0, 17
	rlwinm	25, 19, 14, 18, 31
	rlwimi	25, 18, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 23, 9, 31
	rlwimi	24, 18, 23, 0, 8
	rlwinm	25, 18, 23, 9, 31
	rlwimi	25, 19, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 20, 0
	xor	23, 21, 6
	and	22, 22, 18
	and	23, 23, 19
	xor	22, 22, 0
	xor	23, 23, 6
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 48(1)
	lwz	23, 52(1)
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 48(30)
	lwz	23, 52(30)
	addc	8, 8, 23
	adde	7, 7, 22
	addc	17, 17, 8
	adde	16, 16, 7
	rlwinm	22, 9, 4, 28, 31
	rlwimi	22, 10, 4, 0, 27
	rlwinm	23, 10, 4, 28, 31
	rlwimi	23, 9, 4, 0, 27
	rlwinm	24, 10, 30, 2, 31
	rlwimi	24, 9, 30, 0, 1
	rlwinm	25, 9, 30, 2, 31
	rlwimi	25, 10, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 25, 7, 31
	rlwimi	24, 9, 25, 0, 6
	rlwinm	25, 9, 25, 7, 31
	rlwimi	25, 10, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 9, 11
	xor	23, 10, 12
	xor	24, 11, 14
	xor	25, 12, 15
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 11
	xor	23, 23, 12
	addc	8, 8, 23
	adde	7, 7, 22
	# Calc new W[6]
	lwz	28, 48(1)
	lwz	29, 52(1)
	lwz	24, 120(1)
	lwz	25, 124(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 32(1)
	lwz	23, 36(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 56(1)
	lwz	23, 60(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 48(1)
	stw	29, 52(1)
	# Round 7
	rlwinm	22, 16, 18, 14, 31
	rlwimi	22, 17, 18, 0, 13
	rlwinm	23, 17, 18, 14, 31
	rlwimi	23, 16, 18, 0, 13
	rlwinm	24, 16, 14, 18, 31
	rlwimi	24, 17, 14, 0, 17
	rlwinm	25, 17, 14, 18, 31
	rlwimi	25, 16, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 23, 9, 31
	rlwimi	24, 16, 23, 0, 8
	rlwinm	25, 16, 23, 9, 31
	rlwimi	25, 17, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 18, 20
	xor	23, 19, 21
	and	22, 22, 16
	and	23, 23, 17
	xor	22, 22, 20
	xor	23, 23, 21
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 56(1)
	lwz	23, 60(1)
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 56(30)
	lwz	23, 60(30)
	addc	6, 6, 23
	adde	0, 0, 22
	addc	15, 15, 6
	adde	14, 14, 0
	rlwinm	22, 7, 4, 28, 31
	rlwimi	22, 8, 4, 0, 27
	rlwinm	23, 8, 4, 28, 31
	rlwimi	23, 7, 4, 0, 27
	rlwinm	24, 8, 30, 2, 31
	rlwimi	24, 7, 30, 0, 1
	rlwinm	25, 7, 30, 2, 31
	rlwimi	25, 8, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 25, 7, 31
	rlwimi	24, 7, 25, 0, 6
	rlwinm	25, 7, 25, 7, 31
	rlwimi	25, 8, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 7, 9
	xor	23, 8, 10
	xor	24, 9, 11
	xor	25, 10, 12
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 9
	xor	23, 23, 10
	addc	6, 6, 23
	adde	0, 0, 22
	# Calc new W[7]
	lwz	28, 56(1)
	lwz	29, 60(1)
	lwz	24, 0(1)
	lwz	25, 4(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 40(1)
	lwz	23, 44(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 64(1)
	lwz	23, 68(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 56(1)
	stw	29, 60(1)
	# Round 8
	rlwinm	22, 14, 18, 14, 31
	rlwimi	22, 15, 18, 0, 13
	rlwinm	23, 15, 18, 14, 31
	rlwimi	23, 14, 18, 0, 13
	rlwinm	24, 14, 14, 18, 31
	rlwimi	24, 15, 14, 0, 17
	rlwinm	25, 15, 14, 18, 31
	rlwimi	25, 14, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 23, 9, 31
	rlwimi	24, 14, 23, 0, 8
	rlwinm	25, 14, 23, 9, 31
	rlwimi	25, 15, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 16, 18
	xor	23, 17, 19
	and	22, 22, 14
	and	23, 23, 15
	xor	22, 22, 18
	xor	23, 23, 19
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 64(1)
	lwz	23, 68(1)
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 64(30)
	lwz	23, 68(30)
	addc	21, 21, 23
	adde	20, 20, 22
	addc	12, 12, 21
	adde	11, 11, 20
	rlwinm	22, 0, 4, 28, 31
	rlwimi	22, 6, 4, 0, 27
	rlwinm	23, 6, 4, 28, 31
	rlwimi	23, 0, 4, 0, 27
	rlwinm	24, 6, 30, 2, 31
	rlwimi	24, 0, 30, 0, 1
	rlwinm	25, 0, 30, 2, 31
	rlwimi	25, 6, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 25, 7, 31
	rlwimi	24, 0, 25, 0, 6
	rlwinm	25, 0, 25, 7, 31
	rlwimi	25, 6, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 0, 7
	xor	23, 6, 8
	xor	24, 7, 9
	xor	25, 8, 10
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 7
	xor	23, 23, 8
	addc	21, 21, 23
	adde	20, 20, 22
	# Calc new W[8]
	lwz	28, 64(1)
	lwz	29, 68(1)
	lwz	24, 8(1)
	lwz	25, 12(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 48(1)
	lwz	23, 52(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 72(1)
	lwz	23, 76(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 64(1)
	stw	29, 68(1)
	# Round 9
	rlwinm	22, 11, 18, 14, 31
	rlwimi	22, 12, 18, 0, 13
	rlwinm	23, 12, 18, 14, 31
	rlwimi	23, 11, 18, 0, 13
	rlwinm	24, 11, 14, 18, 31
	rlwimi	24, 12, 14, 0, 17
	rlwinm	25, 12, 14, 18, 31
	rlwimi	25, 11, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 23, 9, 31
	rlwimi	24, 11, 23, 0, 8
	rlwinm	25, 11, 23, 9, 31
	rlwimi	25, 12, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 14, 16
	xor	23, 15, 17
	and	22, 22, 11
	and	23, 23, 12
	xor	22, 22, 16
	xor	23, 23, 17
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 72(1)
	lwz	23, 76(1)
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 72(30)
	lwz	23, 76(30)
	addc	19, 19, 23
	adde	18, 18, 22
	addc	10, 10, 19
	adde	9, 9, 18
	rlwinm	22, 20, 4, 28, 31
	rlwimi	22, 21, 4, 0, 27
	rlwinm	23, 21, 4, 28, 31
	rlwimi	23, 20, 4, 0, 27
	rlwinm	24, 21, 30, 2, 31
	rlwimi	24, 20, 30, 0, 1
	rlwinm	25, 20, 30, 2, 31
	rlwimi	25, 21, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 25, 7, 31
	rlwimi	24, 20, 25, 0, 6
	rlwinm	25, 20, 25, 7, 31
	rlwimi	25, 21, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 20, 0
	xor	23, 21, 6
	xor	24, 0, 7
	xor	25, 6, 8
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 0
	xor	23, 23, 6
	addc	19, 19, 23
	adde	18, 18, 22
	# Calc new W[9]
	lwz	28, 72(1)
	lwz	29, 76(1)
	lwz	24, 16(1)
	lwz	25, 20(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 56(1)
	lwz	23, 60(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 80(1)
	lwz	23, 84(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 72(1)
	stw	29, 76(1)
	# Round 10
	rlwinm	22, 9, 18, 14, 31
	rlwimi	22, 10, 18, 0, 13
	rlwinm	23, 10, 18, 14, 31
	rlwimi	23, 9, 18, 0, 13
	rlwinm	24, 9, 14, 18, 31
	rlwimi	24, 10, 14, 0, 17
	rlwinm	25, 10, 14, 18, 31
	rlwimi	25, 9, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 23, 9, 31
	rlwimi	24, 9, 23, 0, 8
	rlwinm	25, 9, 23, 9, 31
	rlwimi	25, 10, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 11, 14
	xor	23, 12, 15
	and	22, 22, 9
	and	23, 23, 10
	xor	22, 22, 14
	xor	23, 23, 15
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 80(1)
	lwz	23, 84(1)
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 80(30)
	lwz	23, 84(30)
	addc	17, 17, 23
	adde	16, 16, 22
	addc	8, 8, 17
	adde	7, 7, 16
	rlwinm	22, 18, 4, 28, 31
	rlwimi	22, 19, 4, 0, 27
	rlwinm	23, 19, 4, 28, 31
	rlwimi	23, 18, 4, 0, 27
	rlwinm	24, 19, 30, 2, 31
	rlwimi	24, 18, 30, 0, 1
	rlwinm	25, 18, 30, 2, 31
	rlwimi	25, 19, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 25, 7, 31
	rlwimi	24, 18, 25, 0, 6
	rlwinm	25, 18, 25, 7, 31
	rlwimi	25, 19, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 18, 20
	xor	23, 19, 21
	xor	24, 20, 0
	xor	25, 21, 6
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 20
	xor	23, 23, 21
	addc	17, 17, 23
	adde	16, 16, 22
	# Calc new W[10]
	lwz	28, 80(1)
	lwz	29, 84(1)
	lwz	24, 24(1)
	lwz	25, 28(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 64(1)
	lwz	23, 68(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 88(1)
	lwz	23, 92(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 80(1)
	stw	29, 84(1)
	# Round 11
	rlwinm	22, 7, 18, 14, 31
	rlwimi	22, 8, 18, 0, 13
	rlwinm	23, 8, 18, 14, 31
	rlwimi	23, 7, 18, 0, 13
	rlwinm	24, 7, 14, 18, 31
	rlwimi	24, 8, 14, 0, 17
	rlwinm	25, 8, 14, 18, 31
	rlwimi	25, 7, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 23, 9, 31
	rlwimi	24, 7, 23, 0, 8
	rlwinm	25, 7, 23, 9, 31
	rlwimi	25, 8, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 9, 11
	xor	23, 10, 12
	and	22, 22, 7
	and	23, 23, 8
	xor	22, 22, 11
	xor	23, 23, 12
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 88(1)
	lwz	23, 92(1)
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 88(30)
	lwz	23, 92(30)
	addc	15, 15, 23
	adde	14, 14, 22
	addc	6, 6, 15
	adde	0, 0, 14
	rlwinm	22, 16, 4, 28, 31
	rlwimi	22, 17, 4, 0, 27
	rlwinm	23, 17, 4, 28, 31
	rlwimi	23, 16, 4, 0, 27
	rlwinm	24, 17, 30, 2, 31
	rlwimi	24, 16, 30, 0, 1
	rlwinm	25, 16, 30, 2, 31
	rlwimi	25, 17, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 25, 7, 31
	rlwimi	24, 16, 25, 0, 6
	rlwinm	25, 16, 25, 7, 31
	rlwimi	25, 17, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 16, 18
	xor	23, 17, 19
	xor	24, 18, 20
	xor	25, 19, 21
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 18
	xor	23, 23, 19
	addc	15, 15, 23
	adde	14, 14, 22
	# Calc new W[11]
	lwz	28, 88(1)
	lwz	29, 92(1)
	lwz	24, 32(1)
	lwz	25, 36(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 72(1)
	lwz	23, 76(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 96(1)
	lwz	23, 100(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 88(1)
	stw	29, 92(1)
	# Round 12
	rlwinm	22, 0, 18, 14, 31
	rlwimi	22, 6, 18, 0, 13
	rlwinm	23, 6, 18, 14, 31
	rlwimi	23, 0, 18, 0, 13
	rlwinm	24, 0, 14, 18, 31
	rlwimi	24, 6, 14, 0, 17
	rlwinm	25, 6, 14, 18, 31
	rlwimi	25, 0, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 23, 9, 31
	rlwimi	24, 0, 23, 0, 8
	rlwinm	25, 0, 23, 9, 31
	rlwimi	25, 6, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 7, 9
	xor	23, 8, 10
	and	22, 22, 0
	and	23, 23, 6
	xor	22, 22, 9
	xor	23, 23, 10
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 96(1)
	lwz	23, 100(1)
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 96(30)
	lwz	23, 100(30)
	addc	12, 12, 23
	adde	11, 11, 22
	addc	21, 21, 12
	adde	20, 20, 11
	rlwinm	22, 14, 4, 28, 31
	rlwimi	22, 15, 4, 0, 27
	rlwinm	23, 15, 4, 28, 31
	rlwimi	23, 14, 4, 0, 27
	rlwinm	24, 15, 30, 2, 31
	rlwimi	24, 14, 30, 0, 1
	rlwinm	25, 14, 30, 2, 31
	rlwimi	25, 15, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 25, 7, 31
	rlwimi	24, 14, 25, 0, 6
	rlwinm	25, 14, 25, 7, 31
	rlwimi	25, 15, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 14, 16
	xor	23, 15, 17
	xor	24, 16, 18
	xor	25, 17, 19
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 16
	xor	23, 23, 17
	addc	12, 12, 23
	adde	11, 11, 22
	# Calc new W[12]
	lwz	28, 96(1)
	lwz	29, 100(1)
	lwz	24, 40(1)
	lwz	25, 44(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 80(1)
	lwz	23, 84(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 104(1)
	lwz	23, 108(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 96(1)
	stw	29, 100(1)
	# Round 13
	rlwinm	22, 20, 18, 14, 31
	rlwimi	22, 21, 18, 0, 13
	rlwinm	23, 21, 18, 14, 31
	rlwimi	23, 20, 18, 0, 13
	rlwinm	24, 20, 14, 18, 31
	rlwimi	24, 21, 14, 0, 17
	rlwinm	25, 21, 14, 18, 31
	rlwimi	25, 20, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 23, 9, 31
	rlwimi	24, 20, 23, 0, 8
	rlwinm	25, 20, 23, 9, 31
	rlwimi	25, 21, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 0, 7
	xor	23, 6, 8
	and	22, 22, 20
	and	23, 23, 21
	xor	22, 22, 7
	xor	23, 23, 8
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 104(1)
	lwz	23, 108(1)
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 104(30)
	lwz	23, 108(30)
	addc	10, 10, 23
	adde	9, 9, 22
	addc	19, 19, 10
	adde	18, 18, 9
	rlwinm	22, 11, 4, 28, 31
	rlwimi	22, 12, 4, 0, 27
	rlwinm	23, 12, 4, 28, 31
	rlwimi	23, 11, 4, 0, 27
	rlwinm	24, 12, 30, 2, 31
	rlwimi	24, 11, 30, 0, 1
	rlwinm	25, 11, 30, 2, 31
	rlwimi	25, 12, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 25, 7, 31
	rlwimi	24, 11, 25, 0, 6
	rlwinm	25, 11, 25, 7, 31
	rlwimi	25, 12, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 11, 14
	xor	23, 12, 15
	xor	24, 14, 16
	xor	25, 15, 17
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 14
	xor	23, 23, 15
	addc	10, 10, 23
	adde	9, 9, 22
	# Calc new W[13]
	lwz	28, 104(1)
	lwz	29, 108(1)
	lwz	24, 48(1)
	lwz	25, 52(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 88(1)
	lwz	23, 92(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 112(1)
	lwz	23, 116(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 104(1)
	stw	29, 108(1)
	# Round 14
	rlwinm	22, 18, 18, 14, 31
	rlwimi	22, 19, 18, 0, 13
	rlwinm	23, 19, 18, 14, 31
	rlwimi	23, 18, 18, 0, 13
	rlwinm	24, 18, 14, 18, 31
	rlwimi	24, 19, 14, 0, 17
	rlwinm	25, 19, 14, 18, 31
	rlwimi	25, 18, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 23, 9, 31
	rlwimi	24, 18, 23, 0, 8
	rlwinm	25, 18, 23, 9, 31
	rlwimi	25, 19, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 20, 0
	xor	23, 21, 6
	and	22, 22, 18
	and	23, 23, 19
	xor	22, 22, 0
	xor	23, 23, 6
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 112(1)
	lwz	23, 116(1)
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 112(30)
	lwz	23, 116(30)
	addc	8, 8, 23
	adde	7, 7, 22
	addc	17, 17, 8
	adde	16, 16, 7
	rlwinm	22, 9, 4, 28, 31
	rlwimi	22, 10, 4, 0, 27
	rlwinm	23, 10, 4, 28, 31
	rlwimi	23, 9, 4, 0, 27
	rlwinm	24, 10, 30, 2, 31
	rlwimi	24, 9, 30, 0, 1
	rlwinm	25, 9, 30, 2, 31
	rlwimi	25, 10, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 25, 7, 31
	rlwimi	24, 9, 25, 0, 6
	rlwinm	25, 9, 25, 7, 31
	rlwimi	25, 10, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 9, 11
	xor	23, 10, 12
	xor	24, 11, 14
	xor	25, 12, 15
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 11
	xor	23, 23, 12
	addc	8, 8, 23
	adde	7, 7, 22
	# Calc new W[14]
	lwz	28, 112(1)
	lwz	29, 116(1)
	lwz	24, 56(1)
	lwz	25, 60(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 96(1)
	lwz	23, 100(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 120(1)
	lwz	23, 124(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 112(1)
	stw	29, 116(1)
	# Round 15
	rlwinm	22, 16, 18, 14, 31
	rlwimi	22, 17, 18, 0, 13
	rlwinm	23, 17, 18, 14, 31
	rlwimi	23, 16, 18, 0, 13
	rlwinm	24, 16, 14, 18, 31
	rlwimi	24, 17, 14, 0, 17
	rlwinm	25, 17, 14, 18, 31
	rlwimi	25, 16, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 23, 9, 31
	rlwimi	24, 16, 23, 0, 8
	rlwinm	25, 16, 23, 9, 31
	rlwimi	25, 17, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 18, 20
	xor	23, 19, 21
	and	22, 22, 16
	and	23, 23, 17
	xor	22, 22, 20
	xor	23, 23, 21
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 120(1)
	lwz	23, 124(1)
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 120(30)
	lwz	23, 124(30)
	addc	6, 6, 23
	adde	0, 0, 22
	addc	15, 15, 6
	adde	14, 14, 0
	rlwinm	22, 7, 4, 28, 31
	rlwimi	22, 8, 4, 0, 27
	rlwinm	23, 8, 4, 28, 31
	rlwimi	23, 7, 4, 0, 27
	rlwinm	24, 8, 30, 2, 31
	rlwimi	24, 7, 30, 0, 1
	rlwinm	25, 7, 30, 2, 31
	rlwimi	25, 8, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 25, 7, 31
	rlwimi	24, 7, 25, 0, 6
	rlwinm	25, 7, 25, 7, 31
	rlwimi	25, 8, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 7, 9
	xor	23, 8, 10
	xor	24, 9, 11
	xor	25, 10, 12
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 9
	xor	23, 23, 10
	addc	6, 6, 23
	adde	0, 0, 22
	# Calc new W[15]
	lwz	28, 120(1)
	lwz	29, 124(1)
	lwz	24, 64(1)
	lwz	25, 68(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 104(1)
	lwz	23, 108(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 0(1)
	lwz	23, 4(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 120(1)
	stw	29, 124(1)
	addi	30, 30, 0x80
	# Round 0
	rlwinm	22, 14, 18, 14, 31
	rlwimi	22, 15, 18, 0, 13
	rlwinm	23, 15, 18, 14, 31
	rlwimi	23, 14, 18, 0, 13
	rlwinm	24, 14, 14, 18, 31
	rlwimi	24, 15, 14, 0, 17
	rlwinm	25, 15, 14, 18, 31
	rlwimi	25, 14, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 23, 9, 31
	rlwimi	24, 14, 23, 0, 8
	rlwinm	25, 14, 23, 9, 31
	rlwimi	25, 15, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 16, 18
	xor	23, 17, 19
	and	22, 22, 14
	and	23, 23, 15
	xor	22, 22, 18
	xor	23, 23, 19
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 0(1)
	lwz	23, 4(1)
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 0(30)
	lwz	23, 4(30)
	addc	21, 21, 23
	adde	20, 20, 22
	addc	12, 12, 21
	adde	11, 11, 20
	rlwinm	22, 0, 4, 28, 31
	rlwimi	22, 6, 4, 0, 27
	rlwinm	23, 6, 4, 28, 31
	rlwimi	23, 0, 4, 0, 27
	rlwinm	24, 6, 30, 2, 31
	rlwimi	24, 0, 30, 0, 1
	rlwinm	25, 0, 30, 2, 31
	rlwimi	25, 6, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 25, 7, 31
	rlwimi	24, 0, 25, 0, 6
	rlwinm	25, 0, 25, 7, 31
	rlwimi	25, 6, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 0, 7
	xor	23, 6, 8
	xor	24, 7, 9
	xor	25, 8, 10
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 7
	xor	23, 23, 8
	addc	21, 21, 23
	adde	20, 20, 22
	# Calc new W[0]
	lwz	28, 0(1)
	lwz	29, 4(1)
	lwz	24, 72(1)
	lwz	25, 76(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 112(1)
	lwz	23, 116(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 8(1)
	lwz	23, 12(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 0(1)
	stw	29, 4(1)
	# Round 1
	rlwinm	22, 11, 18, 14, 31
	rlwimi	22, 12, 18, 0, 13
	rlwinm	23, 12, 18, 14, 31
	rlwimi	23, 11, 18, 0, 13
	rlwinm	24, 11, 14, 18, 31
	rlwimi	24, 12, 14, 0, 17
	rlwinm	25, 12, 14, 18, 31
	rlwimi	25, 11, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 23, 9, 31
	rlwimi	24, 11, 23, 0, 8
	rlwinm	25, 11, 23, 9, 31
	rlwimi	25, 12, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 14, 16
	xor	23, 15, 17
	and	22, 22, 11
	and	23, 23, 12
	xor	22, 22, 16
	xor	23, 23, 17
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 8(1)
	lwz	23, 12(1)
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 8(30)
	lwz	23, 12(30)
	addc	19, 19, 23
	adde	18, 18, 22
	addc	10, 10, 19
	adde	9, 9, 18
	rlwinm	22, 20, 4, 28, 31
	rlwimi	22, 21, 4, 0, 27
	rlwinm	23, 21, 4, 28, 31
	rlwimi	23, 20, 4, 0, 27
	rlwinm	24, 21, 30, 2, 31
	rlwimi	24, 20, 30, 0, 1
	rlwinm	25, 20, 30, 2, 31
	rlwimi	25, 21, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 25, 7, 31
	rlwimi	24, 20, 25, 0, 6
	rlwinm	25, 20, 25, 7, 31
	rlwimi	25, 21, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 20, 0
	xor	23, 21, 6
	xor	24, 0, 7
	xor	25, 6, 8
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 0
	xor	23, 23, 6
	addc	19, 19, 23
	adde	18, 18, 22
	# Calc new W[1]
	lwz	28, 8(1)
	lwz	29, 12(1)
	lwz	24, 80(1)
	lwz	25, 84(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 120(1)
	lwz	23, 124(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 16(1)
	lwz	23, 20(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 8(1)
	stw	29, 12(1)
	# Round 2
	rlwinm	22, 9, 18, 14, 31
	rlwimi	22, 10, 18, 0, 13
	rlwinm	23, 10, 18, 14, 31
	rlwimi	23, 9, 18, 0, 13
	rlwinm	24, 9, 14, 18, 31
	rlwimi	24, 10, 14, 0, 17
	rlwinm	25, 10, 14, 18, 31
	rlwimi	25, 9, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 23, 9, 31
	rlwimi	24, 9, 23, 0, 8
	rlwinm	25, 9, 23, 9, 31
	rlwimi	25, 10, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 11, 14
	xor	23, 12, 15
	and	22, 22, 9
	and	23, 23, 10
	xor	22, 22, 14
	xor	23, 23, 15
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 16(1)
	lwz	23, 20(1)
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 16(30)
	lwz	23, 20(30)
	addc	17, 17, 23
	adde	16, 16, 22
	addc	8, 8, 17
	adde	7, 7, 16
	rlwinm	22, 18, 4, 28, 31
	rlwimi	22, 19, 4, 0, 27
	rlwinm	23, 19, 4, 28, 31
	rlwimi	23, 18, 4, 0, 27
	rlwinm	24, 19, 30, 2, 31
	rlwimi	24, 18, 30, 0, 1
	rlwinm	25, 18, 30, 2, 31
	rlwimi	25, 19, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 25, 7, 31
	rlwimi	24, 18, 25, 0, 6
	rlwinm	25, 18, 25, 7, 31
	rlwimi	25, 19, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 18, 20
	xor	23, 19, 21
	xor	24, 20, 0
	xor	25, 21, 6
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 20
	xor	23, 23, 21
	addc	17, 17, 23
	adde	16, 16, 22
	# Calc new W[2]
	lwz	28, 16(1)
	lwz	29, 20(1)
	lwz	24, 88(1)
	lwz	25, 92(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 0(1)
	lwz	23, 4(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 24(1)
	lwz	23, 28(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 16(1)
	stw	29, 20(1)
	# Round 3
	rlwinm	22, 7, 18, 14, 31
	rlwimi	22, 8, 18, 0, 13
	rlwinm	23, 8, 18, 14, 31
	rlwimi	23, 7, 18, 0, 13
	rlwinm	24, 7, 14, 18, 31
	rlwimi	24, 8, 14, 0, 17
	rlwinm	25, 8, 14, 18, 31
	rlwimi	25, 7, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 23, 9, 31
	rlwimi	24, 7, 23, 0, 8
	rlwinm	25, 7, 23, 9, 31
	rlwimi	25, 8, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 9, 11
	xor	23, 10, 12
	and	22, 22, 7
	and	23, 23, 8
	xor	22, 22, 11
	xor	23, 23, 12
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 24(1)
	lwz	23, 28(1)
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 24(30)
	lwz	23, 28(30)
	addc	15, 15, 23
	adde	14, 14, 22
	addc	6, 6, 15
	adde	0, 0, 14
	rlwinm	22, 16, 4, 28, 31
	rlwimi	22, 17, 4, 0, 27
	rlwinm	23, 17, 4, 28, 31
	rlwimi	23, 16, 4, 0, 27
	rlwinm	24, 17, 30, 2, 31
	rlwimi	24, 16, 30, 0, 1
	rlwinm	25, 16, 30, 2, 31
	rlwimi	25, 17, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 25, 7, 31
	rlwimi	24, 16, 25, 0, 6
	rlwinm	25, 16, 25, 7, 31
	rlwimi	25, 17, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 16, 18
	xor	23, 17, 19
	xor	24, 18, 20
	xor	25, 19, 21
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 18
	xor	23, 23, 19
	addc	15, 15, 23
	adde	14, 14, 22
	# Calc new W[3]
	lwz	28, 24(1)
	lwz	29, 28(1)
	lwz	24, 96(1)
	lwz	25, 100(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 8(1)
	lwz	23, 12(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 32(1)
	lwz	23, 36(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 24(1)
	stw	29, 28(1)
	# Round 4
	rlwinm	22, 0, 18, 14, 31
	rlwimi	22, 6, 18, 0, 13
	rlwinm	23, 6, 18, 14, 31
	rlwimi	23, 0, 18, 0, 13
	rlwinm	24, 0, 14, 18, 31
	rlwimi	24, 6, 14, 0, 17
	rlwinm	25, 6, 14, 18, 31
	rlwimi	25, 0, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 23, 9, 31
	rlwimi	24, 0, 23, 0, 8
	rlwinm	25, 0, 23, 9, 31
	rlwimi	25, 6, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 7, 9
	xor	23, 8, 10
	and	22, 22, 0
	and	23, 23, 6
	xor	22, 22, 9
	xor	23, 23, 10
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 32(1)
	lwz	23, 36(1)
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 32(30)
	lwz	23, 36(30)
	addc	12, 12, 23
	adde	11, 11, 22
	addc	21, 21, 12
	adde	20, 20, 11
	rlwinm	22, 14, 4, 28, 31
	rlwimi	22, 15, 4, 0, 27
	rlwinm	23, 15, 4, 28, 31
	rlwimi	23, 14, 4, 0, 27
	rlwinm	24, 15, 30, 2, 31
	rlwimi	24, 14, 30, 0, 1
	rlwinm	25, 14, 30, 2, 31
	rlwimi	25, 15, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 25, 7, 31
	rlwimi	24, 14, 25, 0, 6
	rlwinm	25, 14, 25, 7, 31
	rlwimi	25, 15, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 14, 16
	xor	23, 15, 17
	xor	24, 16, 18
	xor	25, 17, 19
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 16
	xor	23, 23, 17
	addc	12, 12, 23
	adde	11, 11, 22
	# Calc new W[4]
	lwz	28, 32(1)
	lwz	29, 36(1)
	lwz	24, 104(1)
	lwz	25, 108(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 16(1)
	lwz	23, 20(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 40(1)
	lwz	23, 44(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 32(1)
	stw	29, 36(1)
	# Round 5
	rlwinm	22, 20, 18, 14, 31
	rlwimi	22, 21, 18, 0, 13
	rlwinm	23, 21, 18, 14, 31
	rlwimi	23, 20, 18, 0, 13
	rlwinm	24, 20, 14, 18, 31
	rlwimi	24, 21, 14, 0, 17
	rlwinm	25, 21, 14, 18, 31
	rlwimi	25, 20, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 23, 9, 31
	rlwimi	24, 20, 23, 0, 8
	rlwinm	25, 20, 23, 9, 31
	rlwimi	25, 21, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 0, 7
	xor	23, 6, 8
	and	22, 22, 20
	and	23, 23, 21
	xor	22, 22, 7
	xor	23, 23, 8
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 40(1)
	lwz	23, 44(1)
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 40(30)
	lwz	23, 44(30)
	addc	10, 10, 23
	adde	9, 9, 22
	addc	19, 19, 10
	adde	18, 18, 9
	rlwinm	22, 11, 4, 28, 31
	rlwimi	22, 12, 4, 0, 27
	rlwinm	23, 12, 4, 28, 31
	rlwimi	23, 11, 4, 0, 27
	rlwinm	24, 12, 30, 2, 31
	rlwimi	24, 11, 30, 0, 1
	rlwinm	25, 11, 30, 2, 31
	rlwimi	25, 12, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 25, 7, 31
	rlwimi	24, 11, 25, 0, 6
	rlwinm	25, 11, 25, 7, 31
	rlwimi	25, 12, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 11, 14
	xor	23, 12, 15
	xor	24, 14, 16
	xor	25, 15, 17
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 14
	xor	23, 23, 15
	addc	10, 10, 23
	adde	9, 9, 22
	# Calc new W[5]
	lwz	28, 40(1)
	lwz	29, 44(1)
	lwz	24, 112(1)
	lwz	25, 116(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 24(1)
	lwz	23, 28(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 48(1)
	lwz	23, 52(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 40(1)
	stw	29, 44(1)
	# Round 6
	rlwinm	22, 18, 18, 14, 31
	rlwimi	22, 19, 18, 0, 13
	rlwinm	23, 19, 18, 14, 31
	rlwimi	23, 18, 18, 0, 13
	rlwinm	24, 18, 14, 18, 31
	rlwimi	24, 19, 14, 0, 17
	rlwinm	25, 19, 14, 18, 31
	rlwimi	25, 18, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 23, 9, 31
	rlwimi	24, 18, 23, 0, 8
	rlwinm	25, 18, 23, 9, 31
	rlwimi	25, 19, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 20, 0
	xor	23, 21, 6
	and	22, 22, 18
	and	23, 23, 19
	xor	22, 22, 0
	xor	23, 23, 6
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 48(1)
	lwz	23, 52(1)
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 48(30)
	lwz	23, 52(30)
	addc	8, 8, 23
	adde	7, 7, 22
	addc	17, 17, 8
	adde	16, 16, 7
	rlwinm	22, 9, 4, 28, 31
	rlwimi	22, 10, 4, 0, 27
	rlwinm	23, 10, 4, 28, 31
	rlwimi	23, 9, 4, 0, 27
	rlwinm	24, 10, 30, 2, 31
	rlwimi	24, 9, 30, 0, 1
	rlwinm	25, 9, 30, 2, 31
	rlwimi	25, 10, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 25, 7, 31
	rlwimi	24, 9, 25, 0, 6
	rlwinm	25, 9, 25, 7, 31
	rlwimi	25, 10, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 9, 11
	xor	23, 10, 12
	xor	24, 11, 14
	xor	25, 12, 15
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 11
	xor	23, 23, 12
	addc	8, 8, 23
	adde	7, 7, 22
	# Calc new W[6]
	lwz	28, 48(1)
	lwz	29, 52(1)
	lwz	24, 120(1)
	lwz	25, 124(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 32(1)
	lwz	23, 36(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 56(1)
	lwz	23, 60(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 48(1)
	stw	29, 52(1)
	# Round 7
	rlwinm	22, 16, 18, 14, 31
	rlwimi	22, 17, 18, 0, 13
	rlwinm	23, 17, 18, 14, 31
	rlwimi	23, 16, 18, 0, 13
	rlwinm	24, 16, 14, 18, 31
	rlwimi	24, 17, 14, 0, 17
	rlwinm	25, 17, 14, 18, 31
	rlwimi	25, 16, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 23, 9, 31
	rlwimi	24, 16, 23, 0, 8
	rlwinm	25, 16, 23, 9, 31
	rlwimi	25, 17, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 18, 20
	xor	23, 19, 21
	and	22, 22, 16
	and	23, 23, 17
	xor	22, 22, 20
	xor	23, 23, 21
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 56(1)
	lwz	23, 60(1)
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 56(30)
	lwz	23, 60(30)
	addc	6, 6, 23
	adde	0, 0, 22
	addc	15, 15, 6
	adde	14, 14, 0
	rlwinm	22, 7, 4, 28, 31
	rlwimi	22, 8, 4, 0, 27
	rlwinm	23, 8, 4, 28, 31
	rlwimi	23, 7, 4, 0, 27
	rlwinm	24, 8, 30, 2, 31
	rlwimi	24, 7, 30, 0, 1
	rlwinm	25, 7, 30, 2, 31
	rlwimi	25, 8, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 25, 7, 31
	rlwimi	24, 7, 25, 0, 6
	rlwinm	25, 7, 25, 7, 31
	rlwimi	25, 8, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 7, 9
	xor	23, 8, 10
	xor	24, 9, 11
	xor	25, 10, 12
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 9
	xor	23, 23, 10
	addc	6, 6, 23
	adde	0, 0, 22
	# Calc new W[7]
	lwz	28, 56(1)
	lwz	29, 60(1)
	lwz	24, 0(1)
	lwz	25, 4(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 40(1)
	lwz	23, 44(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 64(1)
	lwz	23, 68(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 56(1)
	stw	29, 60(1)
	# Round 8
	rlwinm	22, 14, 18, 14, 31
	rlwimi	22, 15, 18, 0, 13
	rlwinm	23, 15, 18, 14, 31
	rlwimi	23, 14, 18, 0, 13
	rlwinm	24, 14, 14, 18, 31
	rlwimi	24, 15, 14, 0, 17
	rlwinm	25, 15, 14, 18, 31
	rlwimi	25, 14, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 23, 9, 31
	rlwimi	24, 14, 23, 0, 8
	rlwinm	25, 14, 23, 9, 31
	rlwimi	25, 15, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 16, 18
	xor	23, 17, 19
	and	22, 22, 14
	and	23, 23, 15
	xor	22, 22, 18
	xor	23, 23, 19
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 64(1)
	lwz	23, 68(1)
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 64(30)
	lwz	23, 68(30)
	addc	21, 21, 23
	adde	20, 20, 22
	addc	12, 12, 21
	adde	11, 11, 20
	rlwinm	22, 0, 4, 28, 31
	rlwimi	22, 6, 4, 0, 27
	rlwinm	23, 6, 4, 28, 31
	rlwimi	23, 0, 4, 0, 27
	rlwinm	24, 6, 30, 2, 31
	rlwimi	24, 0, 30, 0, 1
	rlwinm	25, 0, 30, 2, 31
	rlwimi	25, 6, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 25, 7, 31
	rlwimi	24, 0, 25, 0, 6
	rlwinm	25, 0, 25, 7, 31
	rlwimi	25, 6, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 0, 7
	xor	23, 6, 8
	xor	24, 7, 9
	xor	25, 8, 10
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 7
	xor	23, 23, 8
	addc	21, 21, 23
	adde	20, 20, 22
	# Calc new W[8]
	lwz	28, 64(1)
	lwz	29, 68(1)
	lwz	24, 8(1)
	lwz	25, 12(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 48(1)
	lwz	23, 52(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 72(1)
	lwz	23, 76(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 64(1)
	stw	29, 68(1)
	# Round 9
	rlwinm	22, 11, 18, 14, 31
	rlwimi	22, 12, 18, 0, 13
	rlwinm	23, 12, 18, 14, 31
	rlwimi	23, 11, 18, 0, 13
	rlwinm	24, 11, 14, 18, 31
	rlwimi	24, 12, 14, 0, 17
	rlwinm	25, 12, 14, 18, 31
	rlwimi	25, 11, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 23, 9, 31
	rlwimi	24, 11, 23, 0, 8
	rlwinm	25, 11, 23, 9, 31
	rlwimi	25, 12, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 14, 16
	xor	23, 15, 17
	and	22, 22, 11
	and	23, 23, 12
	xor	22, 22, 16
	xor	23, 23, 17
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 72(1)
	lwz	23, 76(1)
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 72(30)
	lwz	23, 76(30)
	addc	19, 19, 23
	adde	18, 18, 22
	addc	10, 10, 19
	adde	9, 9, 18
	rlwinm	22, 20, 4, 28, 31
	rlwimi	22, 21, 4, 0, 27
	rlwinm	23, 21, 4, 28, 31
	rlwimi	23, 20, 4, 0, 27
	rlwinm	24, 21, 30, 2, 31
	rlwimi	24, 20, 30, 0, 1
	rlwinm	25, 20, 30, 2, 31
	rlwimi	25, 21, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 25, 7, 31
	rlwimi	24, 20, 25, 0, 6
	rlwinm	25, 20, 25, 7, 31
	rlwimi	25, 21, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 20, 0
	xor	23, 21, 6
	xor	24, 0, 7
	xor	25, 6, 8
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 0
	xor	23, 23, 6
	addc	19, 19, 23
	adde	18, 18, 22
	# Calc new W[9]
	lwz	28, 72(1)
	lwz	29, 76(1)
	lwz	24, 16(1)
	lwz	25, 20(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 56(1)
	lwz	23, 60(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 80(1)
	lwz	23, 84(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 72(1)
	stw	29, 76(1)
	# Round 10
	rlwinm	22, 9, 18, 14, 31
	rlwimi	22, 10, 18, 0, 13
	rlwinm	23, 10, 18, 14, 31
	rlwimi	23, 9, 18, 0, 13
	rlwinm	24, 9, 14, 18, 31
	rlwimi	24, 10, 14, 0, 17
	rlwinm	25, 10, 14, 18, 31
	rlwimi	25, 9, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 23, 9, 31
	rlwimi	24, 9, 23, 0, 8
	rlwinm	25, 9, 23, 9, 31
	rlwimi	25, 10, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 11, 14
	xor	23, 12, 15
	and	22, 22, 9
	and	23, 23, 10
	xor	22, 22, 14
	xor	23, 23, 15
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 80(1)
	lwz	23, 84(1)
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 80(30)
	lwz	23, 84(30)
	addc	17, 17, 23
	adde	16, 16, 22
	addc	8, 8, 17
	adde	7, 7, 16
	rlwinm	22, 18, 4, 28, 31
	rlwimi	22, 19, 4, 0, 27
	rlwinm	23, 19, 4, 28, 31
	rlwimi	23, 18, 4, 0, 27
	rlwinm	24, 19, 30, 2, 31
	rlwimi	24, 18, 30, 0, 1
	rlwinm	25, 18, 30, 2, 31
	rlwimi	25, 19, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 25, 7, 31
	rlwimi	24, 18, 25, 0, 6
	rlwinm	25, 18, 25, 7, 31
	rlwimi	25, 19, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 18, 20
	xor	23, 19, 21
	xor	24, 20, 0
	xor	25, 21, 6
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 20
	xor	23, 23, 21
	addc	17, 17, 23
	adde	16, 16, 22
	# Calc new W[10]
	lwz	28, 80(1)
	lwz	29, 84(1)
	lwz	24, 24(1)
	lwz	25, 28(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 64(1)
	lwz	23, 68(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 88(1)
	lwz	23, 92(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 80(1)
	stw	29, 84(1)
	# Round 11
	rlwinm	22, 7, 18, 14, 31
	rlwimi	22, 8, 18, 0, 13
	rlwinm	23, 8, 18, 14, 31
	rlwimi	23, 7, 18, 0, 13
	rlwinm	24, 7, 14, 18, 31
	rlwimi	24, 8, 14, 0, 17
	rlwinm	25, 8, 14, 18, 31
	rlwimi	25, 7, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 23, 9, 31
	rlwimi	24, 7, 23, 0, 8
	rlwinm	25, 7, 23, 9, 31
	rlwimi	25, 8, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 9, 11
	xor	23, 10, 12
	and	22, 22, 7
	and	23, 23, 8
	xor	22, 22, 11
	xor	23, 23, 12
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 88(1)
	lwz	23, 92(1)
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 88(30)
	lwz	23, 92(30)
	addc	15, 15, 23
	adde	14, 14, 22
	addc	6, 6, 15
	adde	0, 0, 14
	rlwinm	22, 16, 4, 28, 31
	rlwimi	22, 17, 4, 0, 27
	rlwinm	23, 17, 4, 28, 31
	rlwimi	23, 16, 4, 0, 27
	rlwinm	24, 17, 30, 2, 31
	rlwimi	24, 16, 30, 0, 1
	rlwinm	25, 16, 30, 2, 31
	rlwimi	25, 17, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 25, 7, 31
	rlwimi	24, 16, 25, 0, 6
	rlwinm	25, 16, 25, 7, 31
	rlwimi	25, 17, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 16, 18
	xor	23, 17, 19
	xor	24, 18, 20
	xor	25, 19, 21
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 18
	xor	23, 23, 19
	addc	15, 15, 23
	adde	14, 14, 22
	# Calc new W[11]
	lwz	28, 88(1)
	lwz	29, 92(1)
	lwz	24, 32(1)
	lwz	25, 36(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 72(1)
	lwz	23, 76(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 96(1)
	lwz	23, 100(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 88(1)
	stw	29, 92(1)
	# Round 12
	rlwinm	22, 0, 18, 14, 31
	rlwimi	22, 6, 18, 0, 13
	rlwinm	23, 6, 18, 14, 31
	rlwimi	23, 0, 18, 0, 13
	rlwinm	24, 0, 14, 18, 31
	rlwimi	24, 6, 14, 0, 17
	rlwinm	25, 6, 14, 18, 31
	rlwimi	25, 0, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 23, 9, 31
	rlwimi	24, 0, 23, 0, 8
	rlwinm	25, 0, 23, 9, 31
	rlwimi	25, 6, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 7, 9
	xor	23, 8, 10
	and	22, 22, 0
	and	23, 23, 6
	xor	22, 22, 9
	xor	23, 23, 10
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 96(1)
	lwz	23, 100(1)
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 96(30)
	lwz	23, 100(30)
	addc	12, 12, 23
	adde	11, 11, 22
	addc	21, 21, 12
	adde	20, 20, 11
	rlwinm	22, 14, 4, 28, 31
	rlwimi	22, 15, 4, 0, 27
	rlwinm	23, 15, 4, 28, 31
	rlwimi	23, 14, 4, 0, 27
	rlwinm	24, 15, 30, 2, 31
	rlwimi	24, 14, 30, 0, 1
	rlwinm	25, 14, 30, 2, 31
	rlwimi	25, 15, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 25, 7, 31
	rlwimi	24, 14, 25, 0, 6
	rlwinm	25, 14, 25, 7, 31
	rlwimi	25, 15, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 14, 16
	xor	23, 15, 17
	xor	24, 16, 18
	xor	25, 17, 19
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 16
	xor	23, 23, 17
	addc	12, 12, 23
	adde	11, 11, 22
	# Calc new W[12]
	lwz	28, 96(1)
	lwz	29, 100(1)
	lwz	24, 40(1)
	lwz	25, 44(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 80(1)
	lwz	23, 84(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 104(1)
	lwz	23, 108(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 96(1)
	stw	29, 100(1)
	# Round 13
	rlwinm	22, 20, 18, 14, 31
	rlwimi	22, 21, 18, 0, 13
	rlwinm	23, 21, 18, 14, 31
	rlwimi	23, 20, 18, 0, 13
	rlwinm	24, 20, 14, 18, 31
	rlwimi	24, 21, 14, 0, 17
	rlwinm	25, 21, 14, 18, 31
	rlwimi	25, 20, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 23, 9, 31
	rlwimi	24, 20, 23, 0, 8
	rlwinm	25, 20, 23, 9, 31
	rlwimi	25, 21, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 0, 7
	xor	23, 6, 8
	and	22, 22, 20
	and	23, 23, 21
	xor	22, 22, 7
	xor	23, 23, 8
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 104(1)
	lwz	23, 108(1)
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 104(30)
	lwz	23, 108(30)
	addc	10, 10, 23
	adde	9, 9, 22
	addc	19, 19, 10
	adde	18, 18, 9
	rlwinm	22, 11, 4, 28, 31
	rlwimi	22, 12, 4, 0, 27
	rlwinm	23, 12, 4, 28, 31
	rlwimi	23, 11, 4, 0, 27
	rlwinm	24, 12, 30, 2, 31
	rlwimi	24, 11, 30, 0, 1
	rlwinm	25, 11, 30, 2, 31
	rlwimi	25, 12, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 25, 7, 31
	rlwimi	24, 11, 25, 0, 6
	rlwinm	25, 11, 25, 7, 31
	rlwimi	25, 12, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 11, 14
	xor	23, 12, 15
	xor	24, 14, 16
	xor	25, 15, 17
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 14
	xor	23, 23, 15
	addc	10, 10, 23
	adde	9, 9, 22
	# Calc new W[13]
	lwz	28, 104(1)
	lwz	29, 108(1)
	lwz	24, 48(1)
	lwz	25, 52(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 88(1)
	lwz	23, 92(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 112(1)
	lwz	23, 116(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 104(1)
	stw	29, 108(1)
	# Round 14
	rlwinm	22, 18, 18, 14, 31
	rlwimi	22, 19, 18, 0, 13
	rlwinm	23, 19, 18, 14, 31
	rlwimi	23, 18, 18, 0, 13
	rlwinm	24, 18, 14, 18, 31
	rlwimi	24, 19, 14, 0, 17
	rlwinm	25, 19, 14, 18, 31
	rlwimi	25, 18, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 23, 9, 31
	rlwimi	24, 18, 23, 0, 8
	rlwinm	25, 18, 23, 9, 31
	rlwimi	25, 19, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 20, 0
	xor	23, 21, 6
	and	22, 22, 18
	and	23, 23, 19
	xor	22, 22, 0
	xor	23, 23, 6
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 112(1)
	lwz	23, 116(1)
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 112(30)
	lwz	23, 116(30)
	addc	8, 8, 23
	adde	7, 7, 22
	addc	17, 17, 8
	adde	16, 16, 7
	rlwinm	22, 9, 4, 28, 31
	rlwimi	22, 10, 4, 0, 27
	rlwinm	23, 10, 4, 28, 31
	rlwimi	23, 9, 4, 0, 27
	rlwinm	24, 10, 30, 2, 31
	rlwimi	24, 9, 30, 0, 1
	rlwinm	25, 9, 30, 2, 31
	rlwimi	25, 10, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 25, 7, 31
	rlwimi	24, 9, 25, 0, 6
	rlwinm	25, 9, 25, 7, 31
	rlwimi	25, 10, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 9, 11
	xor	23, 10, 12
	xor	24, 11, 14
	xor	25, 12, 15
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 11
	xor	23, 23, 12
	addc	8, 8, 23
	adde	7, 7, 22
	# Calc new W[14]
	lwz	28, 112(1)
	lwz	29, 116(1)
	lwz	24, 56(1)
	lwz	25, 60(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 96(1)
	lwz	23, 100(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 120(1)
	lwz	23, 124(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 112(1)
	stw	29, 116(1)
	# Round 15
	rlwinm	22, 16, 18, 14, 31
	rlwimi	22, 17, 18, 0, 13
	rlwinm	23, 17, 18, 14, 31
	rlwimi	23, 16, 18, 0, 13
	rlwinm	24, 16, 14, 18, 31
	rlwimi	24, 17, 14, 0, 17
	rlwinm	25, 17, 14, 18, 31
	rlwimi	25, 16, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 23, 9, 31
	rlwimi	24, 16, 23, 0, 8
	rlwinm	25, 16, 23, 9, 31
	rlwimi	25, 17, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 18, 20
	xor	23, 19, 21
	and	22, 22, 16
	and	23, 23, 17
	xor	22, 22, 20
	xor	23, 23, 21
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 120(1)
	lwz	23, 124(1)
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 120(30)
	lwz	23, 124(30)
	addc	6, 6, 23
	adde	0, 0, 22
	addc	15, 15, 6
	adde	14, 14, 0
	rlwinm	22, 7, 4, 28, 31
	rlwimi	22, 8, 4, 0, 27
	rlwinm	23, 8, 4, 28, 31
	rlwimi	23, 7, 4, 0, 27
	rlwinm	24, 8, 30, 2, 31
	rlwimi	24, 7, 30, 0, 1
	rlwinm	25, 7, 30, 2, 31
	rlwimi	25, 8, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 25, 7, 31
	rlwimi	24, 7, 25, 0, 6
	rlwinm	25, 7, 25, 7, 31
	rlwimi	25, 8, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 7, 9
	xor	23, 8, 10
	xor	24, 9, 11
	xor	25, 10, 12
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 9
	xor	23, 23, 10
	addc	6, 6, 23
	adde	0, 0, 22
	# Calc new W[15]
	lwz	28, 120(1)
	lwz	29, 124(1)
	lwz	24, 64(1)
	lwz	25, 68(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 104(1)
	lwz	23, 108(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 0(1)
	lwz	23, 4(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 120(1)
	stw	29, 124(1)
	addi	30, 30, 0x80
	# Round 0
	rlwinm	22, 14, 18, 14, 31
	rlwimi	22, 15, 18, 0, 13
	rlwinm	23, 15, 18, 14, 31
	rlwimi	23, 14, 18, 0, 13
	rlwinm	24, 14, 14, 18, 31
	rlwimi	24, 15, 14, 0, 17
	rlwinm	25, 15, 14, 18, 31
	rlwimi	25, 14, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 23, 9, 31
	rlwimi	24, 14, 23, 0, 8
	rlwinm	25, 14, 23, 9, 31
	rlwimi	25, 15, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 16, 18
	xor	23, 17, 19
	and	22, 22, 14
	and	23, 23, 15
	xor	22, 22, 18
	xor	23, 23, 19
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 0(1)
	lwz	23, 4(1)
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 0(30)
	lwz	23, 4(30)
	addc	21, 21, 23
	adde	20, 20, 22
	addc	12, 12, 21
	adde	11, 11, 20
	rlwinm	22, 0, 4, 28, 31
	rlwimi	22, 6, 4, 0, 27
	rlwinm	23, 6, 4, 28, 31
	rlwimi	23, 0, 4, 0, 27
	rlwinm	24, 6, 30, 2, 31
	rlwimi	24, 0, 30, 0, 1
	rlwinm	25, 0, 30, 2, 31
	rlwimi	25, 6, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 25, 7, 31
	rlwimi	24, 0, 25, 0, 6
	rlwinm	25, 0, 25, 7, 31
	rlwimi	25, 6, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 0, 7
	xor	23, 6, 8
	xor	24, 7, 9
	xor	25, 8, 10
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 7
	xor	23, 23, 8
	addc	21, 21, 23
	adde	20, 20, 22
	# Calc new W[0]
	lwz	28, 0(1)
	lwz	29, 4(1)
	lwz	24, 72(1)
	lwz	25, 76(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 112(1)
	lwz	23, 116(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 8(1)
	lwz	23, 12(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 0(1)
	stw	29, 4(1)
	# Round 1
	rlwinm	22, 11, 18, 14, 31
	rlwimi	22, 12, 18, 0, 13
	rlwinm	23, 12, 18, 14, 31
	rlwimi	23, 11, 18, 0, 13
	rlwinm	24, 11, 14, 18, 31
	rlwimi	24, 12, 14, 0, 17
	rlwinm	25, 12, 14, 18, 31
	rlwimi	25, 11, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 23, 9, 31
	rlwimi	24, 11, 23, 0, 8
	rlwinm	25, 11, 23, 9, 31
	rlwimi	25, 12, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 14, 16
	xor	23, 15, 17
	and	22, 22, 11
	and	23, 23, 12
	xor	22, 22, 16
	xor	23, 23, 17
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 8(1)
	lwz	23, 12(1)
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 8(30)
	lwz	23, 12(30)
	addc	19, 19, 23
	adde	18, 18, 22
	addc	10, 10, 19
	adde	9, 9, 18
	rlwinm	22, 20, 4, 28, 31
	rlwimi	22, 21, 4, 0, 27
	rlwinm	23, 21, 4, 28, 31
	rlwimi	23, 20, 4, 0, 27
	rlwinm	24, 21, 30, 2, 31
	rlwimi	24, 20, 30, 0, 1
	rlwinm	25, 20, 30, 2, 31
	rlwimi	25, 21, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 25, 7, 31
	rlwimi	24, 20, 25, 0, 6
	rlwinm	25, 20, 25, 7, 31
	rlwimi	25, 21, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 20, 0
	xor	23, 21, 6
	xor	24, 0, 7
	xor	25, 6, 8
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 0
	xor	23, 23, 6
	addc	19, 19, 23
	adde	18, 18, 22
	# Calc new W[1]
	lwz	28, 8(1)
	lwz	29, 12(1)
	lwz	24, 80(1)
	lwz	25, 84(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 120(1)
	lwz	23, 124(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 16(1)
	lwz	23, 20(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 8(1)
	stw	29, 12(1)
	# Round 2
	rlwinm	22, 9, 18, 14, 31
	rlwimi	22, 10, 18, 0, 13
	rlwinm	23, 10, 18, 14, 31
	rlwimi	23, 9, 18, 0, 13
	rlwinm	24, 9, 14, 18, 31
	rlwimi	24, 10, 14, 0, 17
	rlwinm	25, 10, 14, 18, 31
	rlwimi	25, 9, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 23, 9, 31
	rlwimi	24, 9, 23, 0, 8
	rlwinm	25, 9, 23, 9, 31
	rlwimi	25, 10, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 11, 14
	xor	23, 12, 15
	and	22, 22, 9
	and	23, 23, 10
	xor	22, 22, 14
	xor	23, 23, 15
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 16(1)
	lwz	23, 20(1)
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 16(30)
	lwz	23, 20(30)
	addc	17, 17, 23
	adde	16, 16, 22
	addc	8, 8, 17
	adde	7, 7, 16
	rlwinm	22, 18, 4, 28, 31
	rlwimi	22, 19, 4, 0, 27
	rlwinm	23, 19, 4, 28, 31
	rlwimi	23, 18, 4, 0, 27
	rlwinm	24, 19, 30, 2, 31
	rlwimi	24, 18, 30, 0, 1
	rlwinm	25, 18, 30, 2, 31
	rlwimi	25, 19, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 25, 7, 31
	rlwimi	24, 18, 25, 0, 6
	rlwinm	25, 18, 25, 7, 31
	rlwimi	25, 19, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 18, 20
	xor	23, 19, 21
	xor	24, 20, 0
	xor	25, 21, 6
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 20
	xor	23, 23, 21
	addc	17, 17, 23
	adde	16, 16, 22
	# Calc new W[2]
	lwz	28, 16(1)
	lwz	29, 20(1)
	lwz	24, 88(1)
	lwz	25, 92(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 0(1)
	lwz	23, 4(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 24(1)
	lwz	23, 28(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 16(1)
	stw	29, 20(1)
	# Round 3
	rlwinm	22, 7, 18, 14, 31
	rlwimi	22, 8, 18, 0, 13
	rlwinm	23, 8, 18, 14, 31
	rlwimi	23, 7, 18, 0, 13
	rlwinm	24, 7, 14, 18, 31
	rlwimi	24, 8, 14, 0, 17
	rlwinm	25, 8, 14, 18, 31
	rlwimi	25, 7, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 23, 9, 31
	rlwimi	24, 7, 23, 0, 8
	rlwinm	25, 7, 23, 9, 31
	rlwimi	25, 8, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 9, 11
	xor	23, 10, 12
	and	22, 22, 7
	and	23, 23, 8
	xor	22, 22, 11
	xor	23, 23, 12
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 24(1)
	lwz	23, 28(1)
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 24(30)
	lwz	23, 28(30)
	addc	15, 15, 23
	adde	14, 14, 22
	addc	6, 6, 15
	adde	0, 0, 14
	rlwinm	22, 16, 4, 28, 31
	rlwimi	22, 17, 4, 0, 27
	rlwinm	23, 17, 4, 28, 31
	rlwimi	23, 16, 4, 0, 27
	rlwinm	24, 17, 30, 2, 31
	rlwimi	24, 16, 30, 0, 1
	rlwinm	25, 16, 30, 2, 31
	rlwimi	25, 17, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 25, 7, 31
	rlwimi	24, 16, 25, 0, 6
	rlwinm	25, 16, 25, 7, 31
	rlwimi	25, 17, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 16, 18
	xor	23, 17, 19
	xor	24, 18, 20
	xor	25, 19, 21
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 18
	xor	23, 23, 19
	addc	15, 15, 23
	adde	14, 14, 22
	# Calc new W[3]
	lwz	28, 24(1)
	lwz	29, 28(1)
	lwz	24, 96(1)
	lwz	25, 100(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 8(1)
	lwz	23, 12(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 32(1)
	lwz	23, 36(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 24(1)
	stw	29, 28(1)
	# Round 4
	rlwinm	22, 0, 18, 14, 31
	rlwimi	22, 6, 18, 0, 13
	rlwinm	23, 6, 18, 14, 31
	rlwimi	23, 0, 18, 0, 13
	rlwinm	24, 0, 14, 18, 31
	rlwimi	24, 6, 14, 0, 17
	rlwinm	25, 6, 14, 18, 31
	rlwimi	25, 0, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 23, 9, 31
	rlwimi	24, 0, 23, 0, 8
	rlwinm	25, 0, 23, 9, 31
	rlwimi	25, 6, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 7, 9
	xor	23, 8, 10
	and	22, 22, 0
	and	23, 23, 6
	xor	22, 22, 9
	xor	23, 23, 10
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 32(1)
	lwz	23, 36(1)
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 32(30)
	lwz	23, 36(30)
	addc	12, 12, 23
	adde	11, 11, 22
	addc	21, 21, 12
	adde	20, 20, 11
	rlwinm	22, 14, 4, 28, 31
	rlwimi	22, 15, 4, 0, 27
	rlwinm	23, 15, 4, 28, 31
	rlwimi	23, 14, 4, 0, 27
	rlwinm	24, 15, 30, 2, 31
	rlwimi	24, 14, 30, 0, 1
	rlwinm	25, 14, 30, 2, 31
	rlwimi	25, 15, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 25, 7, 31
	rlwimi	24, 14, 25, 0, 6
	rlwinm	25, 14, 25, 7, 31
	rlwimi	25, 15, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 14, 16
	xor	23, 15, 17
	xor	24, 16, 18
	xor	25, 17, 19
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 16
	xor	23, 23, 17
	addc	12, 12, 23
	adde	11, 11, 22
	# Calc new W[4]
	lwz	28, 32(1)
	lwz	29, 36(1)
	lwz	24, 104(1)
	lwz	25, 108(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 16(1)
	lwz	23, 20(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 40(1)
	lwz	23, 44(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 32(1)
	stw	29, 36(1)
	# Round 5
	rlwinm	22, 20, 18, 14, 31
	rlwimi	22, 21, 18, 0, 13
	rlwinm	23, 21, 18, 14, 31
	rlwimi	23, 20, 18, 0, 13
	rlwinm	24, 20, 14, 18, 31
	rlwimi	24, 21, 14, 0, 17
	rlwinm	25, 21, 14, 18, 31
	rlwimi	25, 20, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 23, 9, 31
	rlwimi	24, 20, 23, 0, 8
	rlwinm	25, 20, 23, 9, 31
	rlwimi	25, 21, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 0, 7
	xor	23, 6, 8
	and	22, 22, 20
	and	23, 23, 21
	xor	22, 22, 7
	xor	23, 23, 8
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 40(1)
	lwz	23, 44(1)
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 40(30)
	lwz	23, 44(30)
	addc	10, 10, 23
	adde	9, 9, 22
	addc	19, 19, 10
	adde	18, 18, 9
	rlwinm	22, 11, 4, 28, 31
	rlwimi	22, 12, 4, 0, 27
	rlwinm	23, 12, 4, 28, 31
	rlwimi	23, 11, 4, 0, 27
	rlwinm	24, 12, 30, 2, 31
	rlwimi	24, 11, 30, 0, 1
	rlwinm	25, 11, 30, 2, 31
	rlwimi	25, 12, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 25, 7, 31
	rlwimi	24, 11, 25, 0, 6
	rlwinm	25, 11, 25, 7, 31
	rlwimi	25, 12, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 11, 14
	xor	23, 12, 15
	xor	24, 14, 16
	xor	25, 15, 17
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 14
	xor	23, 23, 15
	addc	10, 10, 23
	adde	9, 9, 22
	# Calc new W[5]
	lwz	28, 40(1)
	lwz	29, 44(1)
	lwz	24, 112(1)
	lwz	25, 116(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 24(1)
	lwz	23, 28(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 48(1)
	lwz	23, 52(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 40(1)
	stw	29, 44(1)
	# Round 6
	rlwinm	22, 18, 18, 14, 31
	rlwimi	22, 19, 18, 0, 13
	rlwinm	23, 19, 18, 14, 31
	rlwimi	23, 18, 18, 0, 13
	rlwinm	24, 18, 14, 18, 31
	rlwimi	24, 19, 14, 0, 17
	rlwinm	25, 19, 14, 18, 31
	rlwimi	25, 18, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 23, 9, 31
	rlwimi	24, 18, 23, 0, 8
	rlwinm	25, 18, 23, 9, 31
	rlwimi	25, 19, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 20, 0
	xor	23, 21, 6
	and	22, 22, 18
	and	23, 23, 19
	xor	22, 22, 0
	xor	23, 23, 6
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 48(1)
	lwz	23, 52(1)
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 48(30)
	lwz	23, 52(30)
	addc	8, 8, 23
	adde	7, 7, 22
	addc	17, 17, 8
	adde	16, 16, 7
	rlwinm	22, 9, 4, 28, 31
	rlwimi	22, 10, 4, 0, 27
	rlwinm	23, 10, 4, 28, 31
	rlwimi	23, 9, 4, 0, 27
	rlwinm	24, 10, 30, 2, 31
	rlwimi	24, 9, 30, 0, 1
	rlwinm	25, 9, 30, 2, 31
	rlwimi	25, 10, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 25, 7, 31
	rlwimi	24, 9, 25, 0, 6
	rlwinm	25, 9, 25, 7, 31
	rlwimi	25, 10, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 9, 11
	xor	23, 10, 12
	xor	24, 11, 14
	xor	25, 12, 15
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 11
	xor	23, 23, 12
	addc	8, 8, 23
	adde	7, 7, 22
	# Calc new W[6]
	lwz	28, 48(1)
	lwz	29, 52(1)
	lwz	24, 120(1)
	lwz	25, 124(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 32(1)
	lwz	23, 36(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 56(1)
	lwz	23, 60(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 48(1)
	stw	29, 52(1)
	# Round 7
	rlwinm	22, 16, 18, 14, 31
	rlwimi	22, 17, 18, 0, 13
	rlwinm	23, 17, 18, 14, 31
	rlwimi	23, 16, 18, 0, 13
	rlwinm	24, 16, 14, 18, 31
	rlwimi	24, 17, 14, 0, 17
	rlwinm	25, 17, 14, 18, 31
	rlwimi	25, 16, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 23, 9, 31
	rlwimi	24, 16, 23, 0, 8
	rlwinm	25, 16, 23, 9, 31
	rlwimi	25, 17, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 18, 20
	xor	23, 19, 21
	and	22, 22, 16
	and	23, 23, 17
	xor	22, 22, 20
	xor	23, 23, 21
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 56(1)
	lwz	23, 60(1)
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 56(30)
	lwz	23, 60(30)
	addc	6, 6, 23
	adde	0, 0, 22
	addc	15, 15, 6
	adde	14, 14, 0
	rlwinm	22, 7, 4, 28, 31
	rlwimi	22, 8, 4, 0, 27
	rlwinm	23, 8, 4, 28, 31
	rlwimi	23, 7, 4, 0, 27
	rlwinm	24, 8, 30, 2, 31
	rlwimi	24, 7, 30, 0, 1
	rlwinm	25, 7, 30, 2, 31
	rlwimi	25, 8, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 25, 7, 31
	rlwimi	24, 7, 25, 0, 6
	rlwinm	25, 7, 25, 7, 31
	rlwimi	25, 8, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 7, 9
	xor	23, 8, 10
	xor	24, 9, 11
	xor	25, 10, 12
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 9
	xor	23, 23, 10
	addc	6, 6, 23
	adde	0, 0, 22
	# Calc new W[7]
	lwz	28, 56(1)
	lwz	29, 60(1)
	lwz	24, 0(1)
	lwz	25, 4(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 40(1)
	lwz	23, 44(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 64(1)
	lwz	23, 68(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 56(1)
	stw	29, 60(1)
	# Round 8
	rlwinm	22, 14, 18, 14, 31
	rlwimi	22, 15, 18, 0, 13
	rlwinm	23, 15, 18, 14, 31
	rlwimi	23, 14, 18, 0, 13
	rlwinm	24, 14, 14, 18, 31
	rlwimi	24, 15, 14, 0, 17
	rlwinm	25, 15, 14, 18, 31
	rlwimi	25, 14, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 23, 9, 31
	rlwimi	24, 14, 23, 0, 8
	rlwinm	25, 14, 23, 9, 31
	rlwimi	25, 15, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 16, 18
	xor	23, 17, 19
	and	22, 22, 14
	and	23, 23, 15
	xor	22, 22, 18
	xor	23, 23, 19
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 64(1)
	lwz	23, 68(1)
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 64(30)
	lwz	23, 68(30)
	addc	21, 21, 23
	adde	20, 20, 22
	addc	12, 12, 21
	adde	11, 11, 20
	rlwinm	22, 0, 4, 28, 31
	rlwimi	22, 6, 4, 0, 27
	rlwinm	23, 6, 4, 28, 31
	rlwimi	23, 0, 4, 0, 27
	rlwinm	24, 6, 30, 2, 31
	rlwimi	24, 0, 30, 0, 1
	rlwinm	25, 0, 30, 2, 31
	rlwimi	25, 6, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 25, 7, 31
	rlwimi	24, 0, 25, 0, 6
	rlwinm	25, 0, 25, 7, 31
	rlwimi	25, 6, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 0, 7
	xor	23, 6, 8
	xor	24, 7, 9
	xor	25, 8, 10
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 7
	xor	23, 23, 8
	addc	21, 21, 23
	adde	20, 20, 22
	# Calc new W[8]
	lwz	28, 64(1)
	lwz	29, 68(1)
	lwz	24, 8(1)
	lwz	25, 12(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 48(1)
	lwz	23, 52(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 72(1)
	lwz	23, 76(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 64(1)
	stw	29, 68(1)
	# Round 9
	rlwinm	22, 11, 18, 14, 31
	rlwimi	22, 12, 18, 0, 13
	rlwinm	23, 12, 18, 14, 31
	rlwimi	23, 11, 18, 0, 13
	rlwinm	24, 11, 14, 18, 31
	rlwimi	24, 12, 14, 0, 17
	rlwinm	25, 12, 14, 18, 31
	rlwimi	25, 11, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 23, 9, 31
	rlwimi	24, 11, 23, 0, 8
	rlwinm	25, 11, 23, 9, 31
	rlwimi	25, 12, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 14, 16
	xor	23, 15, 17
	and	22, 22, 11
	and	23, 23, 12
	xor	22, 22, 16
	xor	23, 23, 17
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 72(1)
	lwz	23, 76(1)
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 72(30)
	lwz	23, 76(30)
	addc	19, 19, 23
	adde	18, 18, 22
	addc	10, 10, 19
	adde	9, 9, 18
	rlwinm	22, 20, 4, 28, 31
	rlwimi	22, 21, 4, 0, 27
	rlwinm	23, 21, 4, 28, 31
	rlwimi	23, 20, 4, 0, 27
	rlwinm	24, 21, 30, 2, 31
	rlwimi	24, 20, 30, 0, 1
	rlwinm	25, 20, 30, 2, 31
	rlwimi	25, 21, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 25, 7, 31
	rlwimi	24, 20, 25, 0, 6
	rlwinm	25, 20, 25, 7, 31
	rlwimi	25, 21, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 20, 0
	xor	23, 21, 6
	xor	24, 0, 7
	xor	25, 6, 8
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 0
	xor	23, 23, 6
	addc	19, 19, 23
	adde	18, 18, 22
	# Calc new W[9]
	lwz	28, 72(1)
	lwz	29, 76(1)
	lwz	24, 16(1)
	lwz	25, 20(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 56(1)
	lwz	23, 60(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 80(1)
	lwz	23, 84(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 72(1)
	stw	29, 76(1)
	# Round 10
	rlwinm	22, 9, 18, 14, 31
	rlwimi	22, 10, 18, 0, 13
	rlwinm	23, 10, 18, 14, 31
	rlwimi	23, 9, 18, 0, 13
	rlwinm	24, 9, 14, 18, 31
	rlwimi	24, 10, 14, 0, 17
	rlwinm	25, 10, 14, 18, 31
	rlwimi	25, 9, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 23, 9, 31
	rlwimi	24, 9, 23, 0, 8
	rlwinm	25, 9, 23, 9, 31
	rlwimi	25, 10, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 11, 14
	xor	23, 12, 15
	and	22, 22, 9
	and	23, 23, 10
	xor	22, 22, 14
	xor	23, 23, 15
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 80(1)
	lwz	23, 84(1)
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 80(30)
	lwz	23, 84(30)
	addc	17, 17, 23
	adde	16, 16, 22
	addc	8, 8, 17
	adde	7, 7, 16
	rlwinm	22, 18, 4, 28, 31
	rlwimi	22, 19, 4, 0, 27
	rlwinm	23, 19, 4, 28, 31
	rlwimi	23, 18, 4, 0, 27
	rlwinm	24, 19, 30, 2, 31
	rlwimi	24, 18, 30, 0, 1
	rlwinm	25, 18, 30, 2, 31
	rlwimi	25, 19, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 25, 7, 31
	rlwimi	24, 18, 25, 0, 6
	rlwinm	25, 18, 25, 7, 31
	rlwimi	25, 19, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 18, 20
	xor	23, 19, 21
	xor	24, 20, 0
	xor	25, 21, 6
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 20
	xor	23, 23, 21
	addc	17, 17, 23
	adde	16, 16, 22
	# Calc new W[10]
	lwz	28, 80(1)
	lwz	29, 84(1)
	lwz	24, 24(1)
	lwz	25, 28(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 64(1)
	lwz	23, 68(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 88(1)
	lwz	23, 92(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 80(1)
	stw	29, 84(1)
	# Round 11
	rlwinm	22, 7, 18, 14, 31
	rlwimi	22, 8, 18, 0, 13
	rlwinm	23, 8, 18, 14, 31
	rlwimi	23, 7, 18, 0, 13
	rlwinm	24, 7, 14, 18, 31
	rlwimi	24, 8, 14, 0, 17
	rlwinm	25, 8, 14, 18, 31
	rlwimi	25, 7, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 23, 9, 31
	rlwimi	24, 7, 23, 0, 8
	rlwinm	25, 7, 23, 9, 31
	rlwimi	25, 8, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 9, 11
	xor	23, 10, 12
	and	22, 22, 7
	and	23, 23, 8
	xor	22, 22, 11
	xor	23, 23, 12
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 88(1)
	lwz	23, 92(1)
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 88(30)
	lwz	23, 92(30)
	addc	15, 15, 23
	adde	14, 14, 22
	addc	6, 6, 15
	adde	0, 0, 14
	rlwinm	22, 16, 4, 28, 31
	rlwimi	22, 17, 4, 0, 27
	rlwinm	23, 17, 4, 28, 31
	rlwimi	23, 16, 4, 0, 27
	rlwinm	24, 17, 30, 2, 31
	rlwimi	24, 16, 30, 0, 1
	rlwinm	25, 16, 30, 2, 31
	rlwimi	25, 17, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 25, 7, 31
	rlwimi	24, 16, 25, 0, 6
	rlwinm	25, 16, 25, 7, 31
	rlwimi	25, 17, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 16, 18
	xor	23, 17, 19
	xor	24, 18, 20
	xor	25, 19, 21
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 18
	xor	23, 23, 19
	addc	15, 15, 23
	adde	14, 14, 22
	# Calc new W[11]
	lwz	28, 88(1)
	lwz	29, 92(1)
	lwz	24, 32(1)
	lwz	25, 36(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 72(1)
	lwz	23, 76(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 96(1)
	lwz	23, 100(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 88(1)
	stw	29, 92(1)
	# Round 12
	rlwinm	22, 0, 18, 14, 31
	rlwimi	22, 6, 18, 0, 13
	rlwinm	23, 6, 18, 14, 31
	rlwimi	23, 0, 18, 0, 13
	rlwinm	24, 0, 14, 18, 31
	rlwimi	24, 6, 14, 0, 17
	rlwinm	25, 6, 14, 18, 31
	rlwimi	25, 0, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 23, 9, 31
	rlwimi	24, 0, 23, 0, 8
	rlwinm	25, 0, 23, 9, 31
	rlwimi	25, 6, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 7, 9
	xor	23, 8, 10
	and	22, 22, 0
	and	23, 23, 6
	xor	22, 22, 9
	xor	23, 23, 10
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 96(1)
	lwz	23, 100(1)
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 96(30)
	lwz	23, 100(30)
	addc	12, 12, 23
	adde	11, 11, 22
	addc	21, 21, 12
	adde	20, 20, 11
	rlwinm	22, 14, 4, 28, 31
	rlwimi	22, 15, 4, 0, 27
	rlwinm	23, 15, 4, 28, 31
	rlwimi	23, 14, 4, 0, 27
	rlwinm	24, 15, 30, 2, 31
	rlwimi	24, 14, 30, 0, 1
	rlwinm	25, 14, 30, 2, 31
	rlwimi	25, 15, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 25, 7, 31
	rlwimi	24, 14, 25, 0, 6
	rlwinm	25, 14, 25, 7, 31
	rlwimi	25, 15, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 14, 16
	xor	23, 15, 17
	xor	24, 16, 18
	xor	25, 17, 19
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 16
	xor	23, 23, 17
	addc	12, 12, 23
	adde	11, 11, 22
	# Calc new W[12]
	lwz	28, 96(1)
	lwz	29, 100(1)
	lwz	24, 40(1)
	lwz	25, 44(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 80(1)
	lwz	23, 84(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 104(1)
	lwz	23, 108(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 96(1)
	stw	29, 100(1)
	# Round 13
	rlwinm	22, 20, 18, 14, 31
	rlwimi	22, 21, 18, 0, 13
	rlwinm	23, 21, 18, 14, 31
	rlwimi	23, 20, 18, 0, 13
	rlwinm	24, 20, 14, 18, 31
	rlwimi	24, 21, 14, 0, 17
	rlwinm	25, 21, 14, 18, 31
	rlwimi	25, 20, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 23, 9, 31
	rlwimi	24, 20, 23, 0, 8
	rlwinm	25, 20, 23, 9, 31
	rlwimi	25, 21, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 0, 7
	xor	23, 6, 8
	and	22, 22, 20
	and	23, 23, 21
	xor	22, 22, 7
	xor	23, 23, 8
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 104(1)
	lwz	23, 108(1)
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 104(30)
	lwz	23, 108(30)
	addc	10, 10, 23
	adde	9, 9, 22
	addc	19, 19, 10
	adde	18, 18, 9
	rlwinm	22, 11, 4, 28, 31
	rlwimi	22, 12, 4, 0, 27
	rlwinm	23, 12, 4, 28, 31
	rlwimi	23, 11, 4, 0, 27
	rlwinm	24, 12, 30, 2, 31
	rlwimi	24, 11, 30, 0, 1
	rlwinm	25, 11, 30, 2, 31
	rlwimi	25, 12, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 25, 7, 31
	rlwimi	24, 11, 25, 0, 6
	rlwinm	25, 11, 25, 7, 31
	rlwimi	25, 12, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 11, 14
	xor	23, 12, 15
	xor	24, 14, 16
	xor	25, 15, 17
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 14
	xor	23, 23, 15
	addc	10, 10, 23
	adde	9, 9, 22
	# Calc new W[13]
	lwz	28, 104(1)
	lwz	29, 108(1)
	lwz	24, 48(1)
	lwz	25, 52(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 88(1)
	lwz	23, 92(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 112(1)
	lwz	23, 116(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 104(1)
	stw	29, 108(1)
	# Round 14
	rlwinm	22, 18, 18, 14, 31
	rlwimi	22, 19, 18, 0, 13
	rlwinm	23, 19, 18, 14, 31
	rlwimi	23, 18, 18, 0, 13
	rlwinm	24, 18, 14, 18, 31
	rlwimi	24, 19, 14, 0, 17
	rlwinm	25, 19, 14, 18, 31
	rlwimi	25, 18, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 23, 9, 31
	rlwimi	24, 18, 23, 0, 8
	rlwinm	25, 18, 23, 9, 31
	rlwimi	25, 19, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 20, 0
	xor	23, 21, 6
	and	22, 22, 18
	and	23, 23, 19
	xor	22, 22, 0
	xor	23, 23, 6
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 112(1)
	lwz	23, 116(1)
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 112(30)
	lwz	23, 116(30)
	addc	8, 8, 23
	adde	7, 7, 22
	addc	17, 17, 8
	adde	16, 16, 7
	rlwinm	22, 9, 4, 28, 31
	rlwimi	22, 10, 4, 0, 27
	rlwinm	23, 10, 4, 28, 31
	rlwimi	23, 9, 4, 0, 27
	rlwinm	24, 10, 30, 2, 31
	rlwimi	24, 9, 30, 0, 1
	rlwinm	25, 9, 30, 2, 31
	rlwimi	25, 10, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 25, 7, 31
	rlwimi	24, 9, 25, 0, 6
	rlwinm	25, 9, 25, 7, 31
	rlwimi	25, 10, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 9, 11
	xor	23, 10, 12
	xor	24, 11, 14
	xor	25, 12, 15
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 11
	xor	23, 23, 12
	addc	8, 8, 23
	adde	7, 7, 22
	# Calc new W[14]
	lwz	28, 112(1)
	lwz	29, 116(1)
	lwz	24, 56(1)
	lwz	25, 60(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 96(1)
	lwz	23, 100(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 120(1)
	lwz	23, 124(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 112(1)
	stw	29, 116(1)
	# Round 15
	rlwinm	22, 16, 18, 14, 31
	rlwimi	22, 17, 18, 0, 13
	rlwinm	23, 17, 18, 14, 31
	rlwimi	23, 16, 18, 0, 13
	rlwinm	24, 16, 14, 18, 31
	rlwimi	24, 17, 14, 0, 17
	rlwinm	25, 17, 14, 18, 31
	rlwimi	25, 16, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 23, 9, 31
	rlwimi	24, 16, 23, 0, 8
	rlwinm	25, 16, 23, 9, 31
	rlwimi	25, 17, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 18, 20
	xor	23, 19, 21
	and	22, 22, 16
	and	23, 23, 17
	xor	22, 22, 20
	xor	23, 23, 21
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 120(1)
	lwz	23, 124(1)
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 120(30)
	lwz	23, 124(30)
	addc	6, 6, 23
	adde	0, 0, 22
	addc	15, 15, 6
	adde	14, 14, 0
	rlwinm	22, 7, 4, 28, 31
	rlwimi	22, 8, 4, 0, 27
	rlwinm	23, 8, 4, 28, 31
	rlwimi	23, 7, 4, 0, 27
	rlwinm	24, 8, 30, 2, 31
	rlwimi	24, 7, 30, 0, 1
	rlwinm	25, 7, 30, 2, 31
	rlwimi	25, 8, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 25, 7, 31
	rlwimi	24, 7, 25, 0, 6
	rlwinm	25, 7, 25, 7, 31
	rlwimi	25, 8, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 7, 9
	xor	23, 8, 10
	xor	24, 9, 11
	xor	25, 10, 12
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 9
	xor	23, 23, 10
	addc	6, 6, 23
	adde	0, 0, 22
	# Calc new W[15]
	lwz	28, 120(1)
	lwz	29, 124(1)
	lwz	24, 64(1)
	lwz	25, 68(1)
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 104(1)
	lwz	23, 108(1)
	rlwinm	24, 22, 13, 19, 31
	rlwimi	24, 23, 13, 0, 18
	rlwinm	25, 23, 13, 19, 31
	rlwimi	25, 22, 13, 0, 18
	rlwinm	26, 23, 3, 29, 31
	rlwimi	26, 22, 3, 0, 28
	rlwinm	27, 22, 3, 29, 31
	rlwimi	27, 23, 3, 0, 28
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 6
	rlwinm	27, 23, 26, 6, 31
	rlwimi	27, 22, 26, 0, 5
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	lwz	22, 0(1)
	lwz	23, 4(1)
	rlwinm	24, 22, 31, 1, 31
	rlwimi	24, 23, 31, 0, 0
	rlwinm	25, 23, 31, 1, 31
	rlwimi	25, 22, 31, 0, 0
	rlwinm	26, 22, 24, 8, 31
	rlwimi	26, 23, 24, 0, 7
	rlwinm	27, 23, 24, 8, 31
	rlwimi	27, 22, 24, 0, 7
	xor	24, 24, 26
	xor	25, 25, 27
	srwi	26, 22, 7
	rlwinm	27, 23, 25, 7, 31
	rlwimi	27, 22, 25, 0, 6
	xor	24, 24, 26
	xor	25, 25, 27
	addc	29, 29, 25
	adde	28, 28, 24
	stw	28, 120(1)
	stw	29, 124(1)
	addi	30, 30, 0x80
	# Round 0
	rlwinm	22, 14, 18, 14, 31
	rlwimi	22, 15, 18, 0, 13
	rlwinm	23, 15, 18, 14, 31
	rlwimi	23, 14, 18, 0, 13
	rlwinm	24, 14, 14, 18, 31
	rlwimi	24, 15, 14, 0, 17
	rlwinm	25, 15, 14, 18, 31
	rlwimi	25, 14, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 23, 9, 31
	rlwimi	24, 14, 23, 0, 8
	rlwinm	25, 14, 23, 9, 31
	rlwimi	25, 15, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 16, 18
	xor	23, 17, 19
	and	22, 22, 14
	and	23, 23, 15
	xor	22, 22, 18
	xor	23, 23, 19
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 0(1)
	lwz	23, 4(1)
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 0(30)
	lwz	23, 4(30)
	addc	21, 21, 23
	adde	20, 20, 22
	addc	12, 12, 21
	adde	11, 11, 20
	rlwinm	22, 0, 4, 28, 31
	rlwimi	22, 6, 4, 0, 27
	rlwinm	23, 6, 4, 28, 31
	rlwimi	23, 0, 4, 0, 27
	rlwinm	24, 6, 30, 2, 31
	rlwimi	24, 0, 30, 0, 1
	rlwinm	25, 0, 30, 2, 31
	rlwimi	25, 6, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 25, 7, 31
	rlwimi	24, 0, 25, 0, 6
	rlwinm	25, 0, 25, 7, 31
	rlwimi	25, 6, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 0, 7
	xor	23, 6, 8
	xor	24, 7, 9
	xor	25, 8, 10
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 7
	xor	23, 23, 8
	addc	21, 21, 23
	adde	20, 20, 22
	# Round 1
	rlwinm	22, 11, 18, 14, 31
	rlwimi	22, 12, 18, 0, 13
	rlwinm	23, 12, 18, 14, 31
	rlwimi	23, 11, 18, 0, 13
	rlwinm	24, 11, 14, 18, 31
	rlwimi	24, 12, 14, 0, 17
	rlwinm	25, 12, 14, 18, 31
	rlwimi	25, 11, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 23, 9, 31
	rlwimi	24, 11, 23, 0, 8
	rlwinm	25, 11, 23, 9, 31
	rlwimi	25, 12, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 14, 16
	xor	23, 15, 17
	and	22, 22, 11
	and	23, 23, 12
	xor	22, 22, 16
	xor	23, 23, 17
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 8(1)
	lwz	23, 12(1)
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 8(30)
	lwz	23, 12(30)
	addc	19, 19, 23
	adde	18, 18, 22
	addc	10, 10, 19
	adde	9, 9, 18
	rlwinm	22, 20, 4, 28, 31
	rlwimi	22, 21, 4, 0, 27
	rlwinm	23, 21, 4, 28, 31
	rlwimi	23, 20, 4, 0, 27
	rlwinm	24, 21, 30, 2, 31
	rlwimi	24, 20, 30, 0, 1
	rlwinm	25, 20, 30, 2, 31
	rlwimi	25, 21, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 25, 7, 31
	rlwimi	24, 20, 25, 0, 6
	rlwinm	25, 20, 25, 7, 31
	rlwimi	25, 21, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 20, 0
	xor	23, 21, 6
	xor	24, 0, 7
	xor	25, 6, 8
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 0
	xor	23, 23, 6
	addc	19, 19, 23
	adde	18, 18, 22
	# Round 2
	rlwinm	22, 9, 18, 14, 31
	rlwimi	22, 10, 18, 0, 13
	rlwinm	23, 10, 18, 14, 31
	rlwimi	23, 9, 18, 0, 13
	rlwinm	24, 9, 14, 18, 31
	rlwimi	24, 10, 14, 0, 17
	rlwinm	25, 10, 14, 18, 31
	rlwimi	25, 9, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 23, 9, 31
	rlwimi	24, 9, 23, 0, 8
	rlwinm	25, 9, 23, 9, 31
	rlwimi	25, 10, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 11, 14
	xor	23, 12, 15
	and	22, 22, 9
	and	23, 23, 10
	xor	22, 22, 14
	xor	23, 23, 15
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 16(1)
	lwz	23, 20(1)
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 16(30)
	lwz	23, 20(30)
	addc	17, 17, 23
	adde	16, 16, 22
	addc	8, 8, 17
	adde	7, 7, 16
	rlwinm	22, 18, 4, 28, 31
	rlwimi	22, 19, 4, 0, 27
	rlwinm	23, 19, 4, 28, 31
	rlwimi	23, 18, 4, 0, 27
	rlwinm	24, 19, 30, 2, 31
	rlwimi	24, 18, 30, 0, 1
	rlwinm	25, 18, 30, 2, 31
	rlwimi	25, 19, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 25, 7, 31
	rlwimi	24, 18, 25, 0, 6
	rlwinm	25, 18, 25, 7, 31
	rlwimi	25, 19, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 18, 20
	xor	23, 19, 21
	xor	24, 20, 0
	xor	25, 21, 6
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 20
	xor	23, 23, 21
	addc	17, 17, 23
	adde	16, 16, 22
	# Round 3
	rlwinm	22, 7, 18, 14, 31
	rlwimi	22, 8, 18, 0, 13
	rlwinm	23, 8, 18, 14, 31
	rlwimi	23, 7, 18, 0, 13
	rlwinm	24, 7, 14, 18, 31
	rlwimi	24, 8, 14, 0, 17
	rlwinm	25, 8, 14, 18, 31
	rlwimi	25, 7, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 23, 9, 31
	rlwimi	24, 7, 23, 0, 8
	rlwinm	25, 7, 23, 9, 31
	rlwimi	25, 8, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 9, 11
	xor	23, 10, 12
	and	22, 22, 7
	and	23, 23, 8
	xor	22, 22, 11
	xor	23, 23, 12
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 24(1)
	lwz	23, 28(1)
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 24(30)
	lwz	23, 28(30)
	addc	15, 15, 23
	adde	14, 14, 22
	addc	6, 6, 15
	adde	0, 0, 14
	rlwinm	22, 16, 4, 28, 31
	rlwimi	22, 17, 4, 0, 27
	rlwinm	23, 17, 4, 28, 31
	rlwimi	23, 16, 4, 0, 27
	rlwinm	24, 17, 30, 2, 31
	rlwimi	24, 16, 30, 0, 1
	rlwinm	25, 16, 30, 2, 31
	rlwimi	25, 17, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 25, 7, 31
	rlwimi	24, 16, 25, 0, 6
	rlwinm	25, 16, 25, 7, 31
	rlwimi	25, 17, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 16, 18
	xor	23, 17, 19
	xor	24, 18, 20
	xor	25, 19, 21
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 18
	xor	23, 23, 19
	addc	15, 15, 23
	adde	14, 14, 22
	# Round 4
	rlwinm	22, 0, 18, 14, 31
	rlwimi	22, 6, 18, 0, 13
	rlwinm	23, 6, 18, 14, 31
	rlwimi	23, 0, 18, 0, 13
	rlwinm	24, 0, 14, 18, 31
	rlwimi	24, 6, 14, 0, 17
	rlwinm	25, 6, 14, 18, 31
	rlwimi	25, 0, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 23, 9, 31
	rlwimi	24, 0, 23, 0, 8
	rlwinm	25, 0, 23, 9, 31
	rlwimi	25, 6, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 7, 9
	xor	23, 8, 10
	and	22, 22, 0
	and	23, 23, 6
	xor	22, 22, 9
	xor	23, 23, 10
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 32(1)
	lwz	23, 36(1)
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 32(30)
	lwz	23, 36(30)
	addc	12, 12, 23
	adde	11, 11, 22
	addc	21, 21, 12
	adde	20, 20, 11
	rlwinm	22, 14, 4, 28, 31
	rlwimi	22, 15, 4, 0, 27
	rlwinm	23, 15, 4, 28, 31
	rlwimi	23, 14, 4, 0, 27
	rlwinm	24, 15, 30, 2, 31
	rlwimi	24, 14, 30, 0, 1
	rlwinm	25, 14, 30, 2, 31
	rlwimi	25, 15, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 25, 7, 31
	rlwimi	24, 14, 25, 0, 6
	rlwinm	25, 14, 25, 7, 31
	rlwimi	25, 15, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 14, 16
	xor	23, 15, 17
	xor	24, 16, 18
	xor	25, 17, 19
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 16
	xor	23, 23, 17
	addc	12, 12, 23
	adde	11, 11, 22
	# Round 5
	rlwinm	22, 20, 18, 14, 31
	rlwimi	22, 21, 18, 0, 13
	rlwinm	23, 21, 18, 14, 31
	rlwimi	23, 20, 18, 0, 13
	rlwinm	24, 20, 14, 18, 31
	rlwimi	24, 21, 14, 0, 17
	rlwinm	25, 21, 14, 18, 31
	rlwimi	25, 20, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 23, 9, 31
	rlwimi	24, 20, 23, 0, 8
	rlwinm	25, 20, 23, 9, 31
	rlwimi	25, 21, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 0, 7
	xor	23, 6, 8
	and	22, 22, 20
	and	23, 23, 21
	xor	22, 22, 7
	xor	23, 23, 8
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 40(1)
	lwz	23, 44(1)
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 40(30)
	lwz	23, 44(30)
	addc	10, 10, 23
	adde	9, 9, 22
	addc	19, 19, 10
	adde	18, 18, 9
	rlwinm	22, 11, 4, 28, 31
	rlwimi	22, 12, 4, 0, 27
	rlwinm	23, 12, 4, 28, 31
	rlwimi	23, 11, 4, 0, 27
	rlwinm	24, 12, 30, 2, 31
	rlwimi	24, 11, 30, 0, 1
	rlwinm	25, 11, 30, 2, 31
	rlwimi	25, 12, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 25, 7, 31
	rlwimi	24, 11, 25, 0, 6
	rlwinm	25, 11, 25, 7, 31
	rlwimi	25, 12, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 11, 14
	xor	23, 12, 15
	xor	24, 14, 16
	xor	25, 15, 17
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 14
	xor	23, 23, 15
	addc	10, 10, 23
	adde	9, 9, 22
	# Round 6
	rlwinm	22, 18, 18, 14, 31
	rlwimi	22, 19, 18, 0, 13
	rlwinm	23, 19, 18, 14, 31
	rlwimi	23, 18, 18, 0, 13
	rlwinm	24, 18, 14, 18, 31
	rlwimi	24, 19, 14, 0, 17
	rlwinm	25, 19, 14, 18, 31
	rlwimi	25, 18, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 23, 9, 31
	rlwimi	24, 18, 23, 0, 8
	rlwinm	25, 18, 23, 9, 31
	rlwimi	25, 19, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 20, 0
	xor	23, 21, 6
	and	22, 22, 18
	and	23, 23, 19
	xor	22, 22, 0
	xor	23, 23, 6
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 48(1)
	lwz	23, 52(1)
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 48(30)
	lwz	23, 52(30)
	addc	8, 8, 23
	adde	7, 7, 22
	addc	17, 17, 8
	adde	16, 16, 7
	rlwinm	22, 9, 4, 28, 31
	rlwimi	22, 10, 4, 0, 27
	rlwinm	23, 10, 4, 28, 31
	rlwimi	23, 9, 4, 0, 27
	rlwinm	24, 10, 30, 2, 31
	rlwimi	24, 9, 30, 0, 1
	rlwinm	25, 9, 30, 2, 31
	rlwimi	25, 10, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 25, 7, 31
	rlwimi	24, 9, 25, 0, 6
	rlwinm	25, 9, 25, 7, 31
	rlwimi	25, 10, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 9, 11
	xor	23, 10, 12
	xor	24, 11, 14
	xor	25, 12, 15
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 11
	xor	23, 23, 12
	addc	8, 8, 23
	adde	7, 7, 22
	# Round 7
	rlwinm	22, 16, 18, 14, 31
	rlwimi	22, 17, 18, 0, 13
	rlwinm	23, 17, 18, 14, 31
	rlwimi	23, 16, 18, 0, 13
	rlwinm	24, 16, 14, 18, 31
	rlwimi	24, 17, 14, 0, 17
	rlwinm	25, 17, 14, 18, 31
	rlwimi	25, 16, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 23, 9, 31
	rlwimi	24, 16, 23, 0, 8
	rlwinm	25, 16, 23, 9, 31
	rlwimi	25, 17, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 18, 20
	xor	23, 19, 21
	and	22, 22, 16
	and	23, 23, 17
	xor	22, 22, 20
	xor	23, 23, 21
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 56(1)
	lwz	23, 60(1)
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 56(30)
	lwz	23, 60(30)
	addc	6, 6, 23
	adde	0, 0, 22
	addc	15, 15, 6
	adde	14, 14, 0
	rlwinm	22, 7, 4, 28, 31
	rlwimi	22, 8, 4, 0, 27
	rlwinm	23, 8, 4, 28, 31
	rlwimi	23, 7, 4, 0, 27
	rlwinm	24, 8, 30, 2, 31
	rlwimi	24, 7, 30, 0, 1
	rlwinm	25, 7, 30, 2, 31
	rlwimi	25, 8, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 25, 7, 31
	rlwimi	24, 7, 25, 0, 6
	rlwinm	25, 7, 25, 7, 31
	rlwimi	25, 8, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 7, 9
	xor	23, 8, 10
	xor	24, 9, 11
	xor	25, 10, 12
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 9
	xor	23, 23, 10
	addc	6, 6, 23
	adde	0, 0, 22
	# Round 8
	rlwinm	22, 14, 18, 14, 31
	rlwimi	22, 15, 18, 0, 13
	rlwinm	23, 15, 18, 14, 31
	rlwimi	23, 14, 18, 0, 13
	rlwinm	24, 14, 14, 18, 31
	rlwimi	24, 15, 14, 0, 17
	rlwinm	25, 15, 14, 18, 31
	rlwimi	25, 14, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 23, 9, 31
	rlwimi	24, 14, 23, 0, 8
	rlwinm	25, 14, 23, 9, 31
	rlwimi	25, 15, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 16, 18
	xor	23, 17, 19
	and	22, 22, 14
	and	23, 23, 15
	xor	22, 22, 18
	xor	23, 23, 19
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 64(1)
	lwz	23, 68(1)
	addc	21, 21, 23
	adde	20, 20, 22
	lwz	22, 64(30)
	lwz	23, 68(30)
	addc	21, 21, 23
	adde	20, 20, 22
	addc	12, 12, 21
	adde	11, 11, 20
	rlwinm	22, 0, 4, 28, 31
	rlwimi	22, 6, 4, 0, 27
	rlwinm	23, 6, 4, 28, 31
	rlwimi	23, 0, 4, 0, 27
	rlwinm	24, 6, 30, 2, 31
	rlwimi	24, 0, 30, 0, 1
	rlwinm	25, 0, 30, 2, 31
	rlwimi	25, 6, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 25, 7, 31
	rlwimi	24, 0, 25, 0, 6
	rlwinm	25, 0, 25, 7, 31
	rlwimi	25, 6, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	21, 21, 23
	adde	20, 20, 22
	xor	22, 0, 7
	xor	23, 6, 8
	xor	24, 7, 9
	xor	25, 8, 10
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 7
	xor	23, 23, 8
	addc	21, 21, 23
	adde	20, 20, 22
	# Round 9
	rlwinm	22, 11, 18, 14, 31
	rlwimi	22, 12, 18, 0, 13
	rlwinm	23, 12, 18, 14, 31
	rlwimi	23, 11, 18, 0, 13
	rlwinm	24, 11, 14, 18, 31
	rlwimi	24, 12, 14, 0, 17
	rlwinm	25, 12, 14, 18, 31
	rlwimi	25, 11, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 23, 9, 31
	rlwimi	24, 11, 23, 0, 8
	rlwinm	25, 11, 23, 9, 31
	rlwimi	25, 12, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 14, 16
	xor	23, 15, 17
	and	22, 22, 11
	and	23, 23, 12
	xor	22, 22, 16
	xor	23, 23, 17
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 72(1)
	lwz	23, 76(1)
	addc	19, 19, 23
	adde	18, 18, 22
	lwz	22, 72(30)
	lwz	23, 76(30)
	addc	19, 19, 23
	adde	18, 18, 22
	addc	10, 10, 19
	adde	9, 9, 18
	rlwinm	22, 20, 4, 28, 31
	rlwimi	22, 21, 4, 0, 27
	rlwinm	23, 21, 4, 28, 31
	rlwimi	23, 20, 4, 0, 27
	rlwinm	24, 21, 30, 2, 31
	rlwimi	24, 20, 30, 0, 1
	rlwinm	25, 20, 30, 2, 31
	rlwimi	25, 21, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 25, 7, 31
	rlwimi	24, 20, 25, 0, 6
	rlwinm	25, 20, 25, 7, 31
	rlwimi	25, 21, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	19, 19, 23
	adde	18, 18, 22
	xor	22, 20, 0
	xor	23, 21, 6
	xor	24, 0, 7
	xor	25, 6, 8
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 0
	xor	23, 23, 6
	addc	19, 19, 23
	adde	18, 18, 22
	# Round 10
	rlwinm	22, 9, 18, 14, 31
	rlwimi	22, 10, 18, 0, 13
	rlwinm	23, 10, 18, 14, 31
	rlwimi	23, 9, 18, 0, 13
	rlwinm	24, 9, 14, 18, 31
	rlwimi	24, 10, 14, 0, 17
	rlwinm	25, 10, 14, 18, 31
	rlwimi	25, 9, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 23, 9, 31
	rlwimi	24, 9, 23, 0, 8
	rlwinm	25, 9, 23, 9, 31
	rlwimi	25, 10, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 11, 14
	xor	23, 12, 15
	and	22, 22, 9
	and	23, 23, 10
	xor	22, 22, 14
	xor	23, 23, 15
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 80(1)
	lwz	23, 84(1)
	addc	17, 17, 23
	adde	16, 16, 22
	lwz	22, 80(30)
	lwz	23, 84(30)
	addc	17, 17, 23
	adde	16, 16, 22
	addc	8, 8, 17
	adde	7, 7, 16
	rlwinm	22, 18, 4, 28, 31
	rlwimi	22, 19, 4, 0, 27
	rlwinm	23, 19, 4, 28, 31
	rlwimi	23, 18, 4, 0, 27
	rlwinm	24, 19, 30, 2, 31
	rlwimi	24, 18, 30, 0, 1
	rlwinm	25, 18, 30, 2, 31
	rlwimi	25, 19, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 25, 7, 31
	rlwimi	24, 18, 25, 0, 6
	rlwinm	25, 18, 25, 7, 31
	rlwimi	25, 19, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	17, 17, 23
	adde	16, 16, 22
	xor	22, 18, 20
	xor	23, 19, 21
	xor	24, 20, 0
	xor	25, 21, 6
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 20
	xor	23, 23, 21
	addc	17, 17, 23
	adde	16, 16, 22
	# Round 11
	rlwinm	22, 7, 18, 14, 31
	rlwimi	22, 8, 18, 0, 13
	rlwinm	23, 8, 18, 14, 31
	rlwimi	23, 7, 18, 0, 13
	rlwinm	24, 7, 14, 18, 31
	rlwimi	24, 8, 14, 0, 17
	rlwinm	25, 8, 14, 18, 31
	rlwimi	25, 7, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 23, 9, 31
	rlwimi	24, 7, 23, 0, 8
	rlwinm	25, 7, 23, 9, 31
	rlwimi	25, 8, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 9, 11
	xor	23, 10, 12
	and	22, 22, 7
	and	23, 23, 8
	xor	22, 22, 11
	xor	23, 23, 12
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 88(1)
	lwz	23, 92(1)
	addc	15, 15, 23
	adde	14, 14, 22
	lwz	22, 88(30)
	lwz	23, 92(30)
	addc	15, 15, 23
	adde	14, 14, 22
	addc	6, 6, 15
	adde	0, 0, 14
	rlwinm	22, 16, 4, 28, 31
	rlwimi	22, 17, 4, 0, 27
	rlwinm	23, 17, 4, 28, 31
	rlwimi	23, 16, 4, 0, 27
	rlwinm	24, 17, 30, 2, 31
	rlwimi	24, 16, 30, 0, 1
	rlwinm	25, 16, 30, 2, 31
	rlwimi	25, 17, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 25, 7, 31
	rlwimi	24, 16, 25, 0, 6
	rlwinm	25, 16, 25, 7, 31
	rlwimi	25, 17, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	15, 15, 23
	adde	14, 14, 22
	xor	22, 16, 18
	xor	23, 17, 19
	xor	24, 18, 20
	xor	25, 19, 21
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 18
	xor	23, 23, 19
	addc	15, 15, 23
	adde	14, 14, 22
	# Round 12
	rlwinm	22, 0, 18, 14, 31
	rlwimi	22, 6, 18, 0, 13
	rlwinm	23, 6, 18, 14, 31
	rlwimi	23, 0, 18, 0, 13
	rlwinm	24, 0, 14, 18, 31
	rlwimi	24, 6, 14, 0, 17
	rlwinm	25, 6, 14, 18, 31
	rlwimi	25, 0, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 6, 23, 9, 31
	rlwimi	24, 0, 23, 0, 8
	rlwinm	25, 0, 23, 9, 31
	rlwimi	25, 6, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 7, 9
	xor	23, 8, 10
	and	22, 22, 0
	and	23, 23, 6
	xor	22, 22, 9
	xor	23, 23, 10
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 96(1)
	lwz	23, 100(1)
	addc	12, 12, 23
	adde	11, 11, 22
	lwz	22, 96(30)
	lwz	23, 100(30)
	addc	12, 12, 23
	adde	11, 11, 22
	addc	21, 21, 12
	adde	20, 20, 11
	rlwinm	22, 14, 4, 28, 31
	rlwimi	22, 15, 4, 0, 27
	rlwinm	23, 15, 4, 28, 31
	rlwimi	23, 14, 4, 0, 27
	rlwinm	24, 15, 30, 2, 31
	rlwimi	24, 14, 30, 0, 1
	rlwinm	25, 14, 30, 2, 31
	rlwimi	25, 15, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 15, 25, 7, 31
	rlwimi	24, 14, 25, 0, 6
	rlwinm	25, 14, 25, 7, 31
	rlwimi	25, 15, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	12, 12, 23
	adde	11, 11, 22
	xor	22, 14, 16
	xor	23, 15, 17
	xor	24, 16, 18
	xor	25, 17, 19
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 16
	xor	23, 23, 17
	addc	12, 12, 23
	adde	11, 11, 22
	# Round 13
	rlwinm	22, 20, 18, 14, 31
	rlwimi	22, 21, 18, 0, 13
	rlwinm	23, 21, 18, 14, 31
	rlwimi	23, 20, 18, 0, 13
	rlwinm	24, 20, 14, 18, 31
	rlwimi	24, 21, 14, 0, 17
	rlwinm	25, 21, 14, 18, 31
	rlwimi	25, 20, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 21, 23, 9, 31
	rlwimi	24, 20, 23, 0, 8
	rlwinm	25, 20, 23, 9, 31
	rlwimi	25, 21, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 0, 7
	xor	23, 6, 8
	and	22, 22, 20
	and	23, 23, 21
	xor	22, 22, 7
	xor	23, 23, 8
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 104(1)
	lwz	23, 108(1)
	addc	10, 10, 23
	adde	9, 9, 22
	lwz	22, 104(30)
	lwz	23, 108(30)
	addc	10, 10, 23
	adde	9, 9, 22
	addc	19, 19, 10
	adde	18, 18, 9
	rlwinm	22, 11, 4, 28, 31
	rlwimi	22, 12, 4, 0, 27
	rlwinm	23, 12, 4, 28, 31
	rlwimi	23, 11, 4, 0, 27
	rlwinm	24, 12, 30, 2, 31
	rlwimi	24, 11, 30, 0, 1
	rlwinm	25, 11, 30, 2, 31
	rlwimi	25, 12, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 12, 25, 7, 31
	rlwimi	24, 11, 25, 0, 6
	rlwinm	25, 11, 25, 7, 31
	rlwimi	25, 12, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	10, 10, 23
	adde	9, 9, 22
	xor	22, 11, 14
	xor	23, 12, 15
	xor	24, 14, 16
	xor	25, 15, 17
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 14
	xor	23, 23, 15
	addc	10, 10, 23
	adde	9, 9, 22
	# Round 14
	rlwinm	22, 18, 18, 14, 31
	rlwimi	22, 19, 18, 0, 13
	rlwinm	23, 19, 18, 14, 31
	rlwimi	23, 18, 18, 0, 13
	rlwinm	24, 18, 14, 18, 31
	rlwimi	24, 19, 14, 0, 17
	rlwinm	25, 19, 14, 18, 31
	rlwimi	25, 18, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 19, 23, 9, 31
	rlwimi	24, 18, 23, 0, 8
	rlwinm	25, 18, 23, 9, 31
	rlwimi	25, 19, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 20, 0
	xor	23, 21, 6
	and	22, 22, 18
	and	23, 23, 19
	xor	22, 22, 0
	xor	23, 23, 6
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 112(1)
	lwz	23, 116(1)
	addc	8, 8, 23
	adde	7, 7, 22
	lwz	22, 112(30)
	lwz	23, 116(30)
	addc	8, 8, 23
	adde	7, 7, 22
	addc	17, 17, 8
	adde	16, 16, 7
	rlwinm	22, 9, 4, 28, 31
	rlwimi	22, 10, 4, 0, 27
	rlwinm	23, 10, 4, 28, 31
	rlwimi	23, 9, 4, 0, 27
	rlwinm	24, 10, 30, 2, 31
	rlwimi	24, 9, 30, 0, 1
	rlwinm	25, 9, 30, 2, 31
	rlwimi	25, 10, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 10, 25, 7, 31
	rlwimi	24, 9, 25, 0, 6
	rlwinm	25, 9, 25, 7, 31
	rlwimi	25, 10, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	8, 8, 23
	adde	7, 7, 22
	xor	22, 9, 11
	xor	23, 10, 12
	xor	24, 11, 14
	xor	25, 12, 15
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 11
	xor	23, 23, 12
	addc	8, 8, 23
	adde	7, 7, 22
	# Round 15
	rlwinm	22, 16, 18, 14, 31
	rlwimi	22, 17, 18, 0, 13
	rlwinm	23, 17, 18, 14, 31
	rlwimi	23, 16, 18, 0, 13
	rlwinm	24, 16, 14, 18, 31
	rlwimi	24, 17, 14, 0, 17
	rlwinm	25, 17, 14, 18, 31
	rlwimi	25, 16, 14, 0, 17
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 17, 23, 9, 31
	rlwimi	24, 16, 23, 0, 8
	rlwinm	25, 16, 23, 9, 31
	rlwimi	25, 17, 23, 0, 8
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 18, 20
	xor	23, 19, 21
	and	22, 22, 16
	and	23, 23, 17
	xor	22, 22, 20
	xor	23, 23, 21
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 120(1)
	lwz	23, 124(1)
	addc	6, 6, 23
	adde	0, 0, 22
	lwz	22, 120(30)
	lwz	23, 124(30)
	addc	6, 6, 23
	adde	0, 0, 22
	addc	15, 15, 6
	adde	14, 14, 0
	rlwinm	22, 7, 4, 28, 31
	rlwimi	22, 8, 4, 0, 27
	rlwinm	23, 8, 4, 28, 31
	rlwimi	23, 7, 4, 0, 27
	rlwinm	24, 8, 30, 2, 31
	rlwimi	24, 7, 30, 0, 1
	rlwinm	25, 7, 30, 2, 31
	rlwimi	25, 8, 30, 0, 1
	xor	22, 22, 24
	xor	23, 23, 25
	rlwinm	24, 8, 25, 7, 31
	rlwimi	24, 7, 25, 0, 6
	rlwinm	25, 7, 25, 7, 31
	rlwimi	25, 8, 25, 0, 6
	xor	22, 22, 24
	xor	23, 23, 25
	addc	6, 6, 23
	adde	0, 0, 22
	xor	22, 7, 9
	xor	23, 8, 10
	xor	24, 9, 11
	xor	25, 10, 12
	and	22, 22, 24
	and	23, 23, 25
	xor	22, 22, 9
	xor	23, 23, 10
	addc	6, 6, 23
	adde	0, 0, 22
	subi	30, 30, 0x200
	# Add in digest from start
	lwz	22, 0(3)
	lwz	23, 4(3)
	addc	6, 6, 23
	adde	0, 0, 22
	stw	0, 0(3)
	stw	6, 4(3)
	lwz	22, 8(3)
	lwz	23, 12(3)
	addc	8, 8, 23
	adde	7, 7, 22
	stw	7, 8(3)
	stw	8, 12(3)
	lwz	22, 16(3)
	lwz	23, 20(3)
	addc	10, 10, 23
	adde	9, 9, 22
	stw	9, 16(3)
	stw	10, 20(3)
	lwz	22, 24(3)
	lwz	23, 28(3)
	addc	12, 12, 23
	adde	11, 11, 22
	stw	11, 24(3)
	stw	12, 28(3)
	lwz	22, 32(3)
	lwz	23, 36(3)
	addc	15, 15, 23
	adde	14, 14, 22
	stw	14, 32(3)
	stw	15, 36(3)
	lwz	22, 40(3)
	lwz	23, 44(3)
	addc	17, 17, 23
	adde	16, 16, 22
	stw	16, 40(3)
	stw	17, 44(3)
	lwz	22, 48(3)
	lwz	23, 52(3)
	addc	19, 19, 23
	adde	18, 18, 22
	stw	18, 48(3)
	stw	19, 52(3)
	lwz	22, 56(3)
	lwz	23, 60(3)
	addc	21, 21, 23
	adde	20, 20, 22
	stw	20, 56(3)
	stw	21, 60(3)
	addi	4, 4, 0x80
	bdnz	L_SHA512_transform_len_begin
	addi	1, 1, 0x80
	lwz	0, 68(1)
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
	addi	1, 1, 0x48
	blr
	.size	Transform_Sha512_Len,.-Transform_Sha512_Len
#endif /* WOLFSSL_SHA512 || WOLFSSL_SHA384 */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_PPC32_ASM_INLINE */
#endif /* WOLFSSL_PPC32_ASM */
