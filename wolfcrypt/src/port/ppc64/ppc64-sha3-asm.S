/* ppc64-sha3-asm
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
 *   ruby ./sha3/sha3.rb ppc64 \
 *       ../wolfssl/wolfcrypt/src/port/ppc64/ppc64-sha3-asm.S
 */
#ifdef WOLFSSL_PPC64_ASM
#ifndef WOLFSSL_PPC64_ASM_INLINE
#ifdef WOLFSSL_SHA3
#ifndef __APPLE__
	.text
	.type	L_SHA3_transform_base_r, %object
	.size	L_SHA3_transform_base_r, 192
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_SHA3_transform_base_r:
	.quad	0x0000000000000001,0x0000000000008082
	.quad	0x800000000000808a,0x8000000080008000
	.quad	0x000000000000808b,0x0000000080000001
	.quad	0x8000000080008081,0x8000000000008009
	.quad	0x000000000000008a,0x0000000000000088
	.quad	0x0000000080008009,0x000000008000000a
	.quad	0x000000008000808b,0x800000000000008b
	.quad	0x8000000000008089,0x8000000000008003
	.quad	0x8000000000008002,0x8000000000000080
	.quad	0x000000000000800a,0x800000008000000a
	.quad	0x8000000080008081,0x8000000000008080
	.quad	0x0000000080000001,0x8000000080008008
#ifndef __APPLE__
.text
.globl	BlockSha3_base
.type	BlockSha3_base,@function
.align	16
BlockSha3_base:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	BlockSha3_base, .-BlockSha3_base
#endif
#else
.section	__TEXT,__text
.globl	_BlockSha3_base
.p2align	4
_BlockSha3_base:
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
	subi	1, 1, 56
	addis	29, 2, L_SHA3_transform_base_r@toc@ha
	addi	29, 29, L_SHA3_transform_base_r@toc@l
	std	3, 40(1)
	ld	0, 0(3)
	ld	4, 8(3)
	ld	5, 16(3)
	ld	6, 24(3)
	ld	7, 32(3)
	ld	8, 40(3)
	ld	9, 48(3)
	ld	10, 56(3)
	ld	11, 64(3)
	ld	12, 72(3)
	ld	14, 80(3)
	ld	15, 88(3)
	ld	16, 96(3)
	ld	17, 104(3)
	ld	18, 112(3)
	ld	19, 120(3)
	ld	20, 128(3)
	ld	21, 136(3)
	ld	22, 144(3)
	ld	23, 152(3)
	ld	24, 160(3)
	ld	25, 168(3)
	ld	26, 176(3)
	ld	27, 184(3)
	ld	28, 192(3)
	li	30, 24
	mtctr	30
	# Start of 24 rounds
L_SHA3_transform_base_begin:
	# Column Mix
	xor	30, 0, 8
	xor	30, 30, 14
	xor	30, 30, 19
	xor	30, 30, 24
	std	30, 0(1)
	xor	30, 4, 9
	xor	30, 30, 15
	xor	30, 30, 20
	xor	30, 30, 25
	std	30, 8(1)
	xor	30, 5, 10
	xor	30, 30, 16
	xor	30, 30, 21
	xor	30, 30, 26
	std	30, 16(1)
	xor	30, 6, 11
	xor	30, 30, 17
	xor	30, 30, 22
	xor	30, 30, 27
	std	30, 24(1)
	xor	30, 7, 12
	xor	30, 30, 18
	xor	30, 30, 23
	xor	30, 30, 28
	std	30, 32(1)
	ld	30, 8(1)
	rotldi	30, 30, 1
	ld	31, 32(1)
	xor	31, 31, 30
	xor	0, 0, 31
	xor	8, 8, 31
	xor	14, 14, 31
	xor	19, 19, 31
	xor	24, 24, 31
	ld	30, 16(1)
	rotldi	30, 30, 1
	ld	31, 0(1)
	xor	31, 31, 30
	xor	4, 4, 31
	xor	9, 9, 31
	xor	15, 15, 31
	xor	20, 20, 31
	xor	25, 25, 31
	ld	30, 24(1)
	rotldi	30, 30, 1
	ld	31, 8(1)
	xor	31, 31, 30
	xor	5, 5, 31
	xor	10, 10, 31
	xor	16, 16, 31
	xor	21, 21, 31
	xor	26, 26, 31
	ld	30, 32(1)
	rotldi	30, 30, 1
	ld	31, 16(1)
	xor	31, 31, 30
	xor	6, 6, 31
	xor	11, 11, 31
	xor	17, 17, 31
	xor	22, 22, 31
	xor	27, 27, 31
	ld	30, 0(1)
	rotldi	30, 30, 1
	ld	31, 24(1)
	xor	31, 31, 30
	xor	7, 7, 31
	xor	12, 12, 31
	xor	18, 18, 31
	xor	23, 23, 31
	xor	28, 28, 31
	std	29, 48(1)
	# Swap Rotate
	rotldi	3, 4, 1
	rotldi	4, 9, 44
	rotldi	9, 12, 20
	rotldi	12, 26, 61
	rotldi	26, 18, 39
	rotldi	18, 24, 18
	rotldi	24, 5, 62
	rotldi	5, 16, 43
	rotldi	16, 17, 25
	rotldi	17, 23, 8
	rotldi	23, 27, 56
	rotldi	27, 19, 41
	rotldi	19, 7, 27
	rotldi	7, 28, 14
	rotldi	28, 25, 2
	rotldi	25, 11, 55
	rotldi	11, 20, 45
	rotldi	20, 8, 36
	rotldi	8, 6, 28
	rotldi	6, 22, 21
	rotldi	22, 21, 15
	rotldi	21, 15, 10
	rotldi	15, 10, 6
	rotldi	10, 14, 3
	# Row Mix
	andc	14, 5, 4
	andc	29, 6, 5
	andc	30, 0, 7
	andc	31, 4, 0
	xor	0, 0, 14
	xor	4, 4, 29
	andc	14, 7, 6
	xor	6, 6, 30
	xor	5, 5, 14
	xor	7, 7, 31
	andc	14, 10, 9
	andc	29, 11, 10
	andc	30, 8, 12
	andc	31, 9, 8
	xor	8, 8, 14
	xor	9, 9, 29
	andc	14, 12, 11
	xor	11, 11, 30
	xor	10, 10, 14
	xor	12, 12, 31
	andc	14, 16, 15
	andc	29, 17, 16
	andc	30, 3, 18
	andc	31, 15, 3
	xor	14, 3, 14
	xor	15, 15, 29
	andc	3, 18, 17
	xor	17, 17, 30
	xor	16, 16, 3
	xor	18, 18, 31
	andc	3, 21, 20
	andc	29, 22, 21
	andc	30, 19, 23
	andc	31, 20, 19
	xor	19, 19, 3
	xor	20, 20, 29
	andc	3, 23, 22
	xor	22, 22, 30
	xor	21, 21, 3
	xor	23, 23, 31
	andc	3, 26, 25
	andc	29, 27, 26
	andc	30, 24, 28
	andc	31, 25, 24
	xor	24, 24, 3
	xor	25, 25, 29
	andc	3, 28, 27
	xor	27, 27, 30
	xor	26, 26, 3
	xor	28, 28, 31
	ld	29, 48(1)
	# Done transforming
	ld	30, 0(29)
	addi	29, 29, 8
	xor	0, 0, 30
	bdnz	L_SHA3_transform_base_begin
	ld	3, 40(1)
	std	0, 0(3)
	std	4, 8(3)
	std	5, 16(3)
	std	6, 24(3)
	std	7, 32(3)
	std	8, 40(3)
	std	9, 48(3)
	std	10, 56(3)
	std	11, 64(3)
	std	12, 72(3)
	std	14, 80(3)
	std	15, 88(3)
	std	16, 96(3)
	std	17, 104(3)
	std	18, 112(3)
	std	19, 120(3)
	std	20, 128(3)
	std	21, 136(3)
	std	22, 144(3)
	std	23, 152(3)
	std	24, 160(3)
	std	25, 168(3)
	std	26, 176(3)
	std	27, 184(3)
	std	28, 192(3)
	addi	1, 1, 56
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
	.size	BlockSha3_base,.-BlockSha3_base
#endif /* __APPLE__ */
#ifdef WOLFSSL_PPC64_ASM_POWER8
#ifndef __APPLE__
	.text
	.type	L_SHA3_transform_power8_r, %object
	.size	L_SHA3_transform_power8_r, 192
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_SHA3_transform_power8_r:
	.quad	0x0000000000000001,0x0000000000008082
	.quad	0x800000000000808a,0x8000000080008000
	.quad	0x000000000000808b,0x0000000080000001
	.quad	0x8000000080008081,0x8000000000008009
	.quad	0x000000000000008a,0x0000000000000088
	.quad	0x0000000080008009,0x000000008000000a
	.quad	0x000000008000808b,0x800000000000008b
	.quad	0x8000000000008089,0x8000000000008003
	.quad	0x8000000000008002,0x8000000000000080
	.quad	0x000000000000800a,0x800000008000000a
	.quad	0x8000000080008081,0x8000000000008080
	.quad	0x0000000080000001,0x8000000080008008
	.machine	"push"
	.machine	"power8"
#ifndef __APPLE__
.text
.globl	BlockSha3_power8
.type	BlockSha3_power8,@function
.align	16
BlockSha3_power8:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	BlockSha3_power8, .-BlockSha3_power8
#endif
#else
.section	__TEXT,__text
.globl	_BlockSha3_power8
.p2align	4
_BlockSha3_power8:
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
	addis	4, 2, L_SHA3_transform_power8_r@toc@ha
	addi	4, 4, L_SHA3_transform_power8_r@toc@l
	# Load state
	li	5, 0
	lxsdx	32, 3, 5
	addi	5, 5, 8
	lxsdx	33, 3, 5
	addi	5, 5, 8
	lxsdx	34, 3, 5
	addi	5, 5, 8
	lxsdx	35, 3, 5
	addi	5, 5, 8
	lxsdx	36, 3, 5
	addi	5, 5, 8
	lxsdx	37, 3, 5
	addi	5, 5, 8
	lxsdx	38, 3, 5
	addi	5, 5, 8
	lxsdx	39, 3, 5
	addi	5, 5, 8
	lxsdx	40, 3, 5
	addi	5, 5, 8
	lxsdx	41, 3, 5
	addi	5, 5, 8
	lxsdx	42, 3, 5
	addi	5, 5, 8
	lxsdx	43, 3, 5
	addi	5, 5, 8
	lxsdx	44, 3, 5
	addi	5, 5, 8
	lxsdx	45, 3, 5
	addi	5, 5, 8
	lxsdx	46, 3, 5
	addi	5, 5, 8
	lxsdx	47, 3, 5
	addi	5, 5, 8
	lxsdx	48, 3, 5
	addi	5, 5, 8
	lxsdx	49, 3, 5
	addi	5, 5, 8
	lxsdx	50, 3, 5
	addi	5, 5, 8
	lxsdx	51, 3, 5
	addi	5, 5, 8
	lxsdx	52, 3, 5
	addi	5, 5, 8
	lxsdx	53, 3, 5
	addi	5, 5, 8
	lxsdx	54, 3, 5
	addi	5, 5, 8
	lxsdx	55, 3, 5
	addi	5, 5, 8
	lxsdx	56, 3, 5
	li	5, 24
	mtctr	5
	# Start of 24 rounds
L_SHA3_transform_power8_begin:
	# Column Mix
	vxor	25, 0, 5
	vxor	25, 25, 10
	vxor	25, 25, 15
	vxor	25, 25, 20
	vxor	26, 1, 6
	vxor	26, 26, 11
	vxor	26, 26, 16
	vxor	26, 26, 21
	vxor	27, 2, 7
	vxor	27, 27, 12
	vxor	27, 27, 17
	vxor	27, 27, 22
	vxor	28, 3, 8
	vxor	28, 28, 13
	vxor	28, 28, 18
	vxor	28, 28, 23
	vxor	29, 4, 9
	vxor	29, 29, 14
	vxor	29, 29, 19
	vxor	29, 29, 24
	li	6, 1
	mtvsrd	63, 6
	vrld	30, 26, 31
	vxor	30, 29, 30
	vxor	0, 0, 30
	vxor	5, 5, 30
	vxor	10, 10, 30
	vxor	15, 15, 30
	vxor	20, 20, 30
	vrld	30, 27, 31
	vxor	30, 25, 30
	vxor	1, 1, 30
	vxor	6, 6, 30
	vxor	11, 11, 30
	vxor	16, 16, 30
	vxor	21, 21, 30
	vrld	30, 28, 31
	vxor	30, 26, 30
	vxor	2, 2, 30
	vxor	7, 7, 30
	vxor	12, 12, 30
	vxor	17, 17, 30
	vxor	22, 22, 30
	vrld	30, 29, 31
	vxor	30, 27, 30
	vxor	3, 3, 30
	vxor	8, 8, 30
	vxor	13, 13, 30
	vxor	18, 18, 30
	vxor	23, 23, 30
	vrld	30, 25, 31
	vxor	30, 28, 30
	vxor	4, 4, 30
	vxor	9, 9, 30
	vxor	14, 14, 30
	vxor	19, 19, 30
	vxor	24, 24, 30
	# Swap Rotate
	li	6, 1
	mtvsrd	63, 6
	vrld	25, 1, 31
	li	6, 44
	mtvsrd	63, 6
	vrld	1, 6, 31
	li	6, 20
	mtvsrd	63, 6
	vrld	6, 9, 31
	li	6, 61
	mtvsrd	63, 6
	vrld	9, 22, 31
	li	6, 39
	mtvsrd	63, 6
	vrld	22, 14, 31
	li	6, 18
	mtvsrd	63, 6
	vrld	14, 20, 31
	li	6, 62
	mtvsrd	63, 6
	vrld	20, 2, 31
	li	6, 43
	mtvsrd	63, 6
	vrld	2, 12, 31
	li	6, 25
	mtvsrd	63, 6
	vrld	12, 13, 31
	li	6, 8
	mtvsrd	63, 6
	vrld	13, 19, 31
	li	6, 56
	mtvsrd	63, 6
	vrld	19, 23, 31
	li	6, 41
	mtvsrd	63, 6
	vrld	23, 15, 31
	li	6, 27
	mtvsrd	63, 6
	vrld	15, 4, 31
	li	6, 14
	mtvsrd	63, 6
	vrld	4, 24, 31
	li	6, 2
	mtvsrd	63, 6
	vrld	24, 21, 31
	li	6, 55
	mtvsrd	63, 6
	vrld	21, 8, 31
	li	6, 45
	mtvsrd	63, 6
	vrld	8, 16, 31
	li	6, 36
	mtvsrd	63, 6
	vrld	16, 5, 31
	li	6, 28
	mtvsrd	63, 6
	vrld	5, 3, 31
	li	6, 21
	mtvsrd	63, 6
	vrld	3, 18, 31
	li	6, 15
	mtvsrd	63, 6
	vrld	18, 17, 31
	li	6, 10
	mtvsrd	63, 6
	vrld	17, 11, 31
	li	6, 6
	mtvsrd	63, 6
	vrld	11, 7, 31
	li	6, 3
	mtvsrd	63, 6
	vrld	7, 10, 31
	# Row Mix
	vandc	10, 2, 1
	vandc	26, 3, 2
	vandc	27, 0, 4
	vandc	28, 1, 0
	vxor	0, 0, 10
	vxor	1, 1, 26
	vandc	10, 4, 3
	vxor	3, 3, 27
	vxor	2, 2, 10
	vxor	4, 4, 28
	vandc	10, 7, 6
	vandc	26, 8, 7
	vandc	27, 5, 9
	vandc	28, 6, 5
	vxor	5, 5, 10
	vxor	6, 6, 26
	vandc	10, 9, 8
	vxor	8, 8, 27
	vxor	7, 7, 10
	vxor	9, 9, 28
	vandc	10, 12, 11
	vandc	26, 13, 12
	vandc	27, 25, 14
	vandc	28, 11, 25
	vxor	10, 25, 10
	vxor	11, 11, 26
	vandc	25, 14, 13
	vxor	13, 13, 27
	vxor	12, 12, 25
	vxor	14, 14, 28
	vandc	25, 17, 16
	vandc	26, 18, 17
	vandc	27, 15, 19
	vandc	28, 16, 15
	vxor	15, 15, 25
	vxor	16, 16, 26
	vandc	25, 19, 18
	vxor	18, 18, 27
	vxor	17, 17, 25
	vxor	19, 19, 28
	vandc	25, 22, 21
	vandc	26, 23, 22
	vandc	27, 20, 24
	vandc	28, 21, 20
	vxor	20, 20, 25
	vxor	21, 21, 26
	vandc	25, 24, 23
	vxor	23, 23, 27
	vxor	22, 22, 25
	vxor	24, 24, 28
	# Iota - XOR round constant into lane 0
	lxsdx	58, 0, 4
	addi	4, 4, 8
	vxor	0, 0, 26
	bdnz	L_SHA3_transform_power8_begin
	# Store state
	li	5, 0
	stxsdx	32, 3, 5
	addi	5, 5, 8
	stxsdx	33, 3, 5
	addi	5, 5, 8
	stxsdx	34, 3, 5
	addi	5, 5, 8
	stxsdx	35, 3, 5
	addi	5, 5, 8
	stxsdx	36, 3, 5
	addi	5, 5, 8
	stxsdx	37, 3, 5
	addi	5, 5, 8
	stxsdx	38, 3, 5
	addi	5, 5, 8
	stxsdx	39, 3, 5
	addi	5, 5, 8
	stxsdx	40, 3, 5
	addi	5, 5, 8
	stxsdx	41, 3, 5
	addi	5, 5, 8
	stxsdx	42, 3, 5
	addi	5, 5, 8
	stxsdx	43, 3, 5
	addi	5, 5, 8
	stxsdx	44, 3, 5
	addi	5, 5, 8
	stxsdx	45, 3, 5
	addi	5, 5, 8
	stxsdx	46, 3, 5
	addi	5, 5, 8
	stxsdx	47, 3, 5
	addi	5, 5, 8
	stxsdx	48, 3, 5
	addi	5, 5, 8
	stxsdx	49, 3, 5
	addi	5, 5, 8
	stxsdx	50, 3, 5
	addi	5, 5, 8
	stxsdx	51, 3, 5
	addi	5, 5, 8
	stxsdx	52, 3, 5
	addi	5, 5, 8
	stxsdx	53, 3, 5
	addi	5, 5, 8
	stxsdx	54, 3, 5
	addi	5, 5, 8
	stxsdx	55, 3, 5
	addi	5, 5, 8
	stxsdx	56, 3, 5
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
	.size	BlockSha3_power8,.-BlockSha3_power8
#endif /* __APPLE__ */
	.machine	"pop"
#if (defined(WOLFSSL_HAVE_MLKEM) || defined(HAVE_DILITHIUM)) && defined(WOLFSSL_SHA3_PPC64_BLOCKS_N)
#ifndef __APPLE__
	.text
	.type	L_SHA3_blocksx2_power8_rot, %object
	.size	L_SHA3_blocksx2_power8_rot, 200
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_SHA3_blocksx2_power8_rot:
	.quad	0x0000000000000001,0x0000000000000001
	.quad	0x000000000000002c,0x0000000000000014
	.quad	0x000000000000003d,0x0000000000000027
	.quad	0x0000000000000012,0x000000000000003e
	.quad	0x000000000000002b,0x0000000000000019
	.quad	0x0000000000000008,0x0000000000000038
	.quad	0x0000000000000029,0x000000000000001b
	.quad	0x000000000000000e,0x0000000000000002
	.quad	0x0000000000000037,0x000000000000002d
	.quad	0x0000000000000024,0x000000000000001c
	.quad	0x0000000000000015,0x000000000000000f
	.quad	0x000000000000000a,0x0000000000000006
	.quad	0x0000000000000003
#ifndef __APPLE__
	.text
	.type	L_SHA3_blocksx2_power8_r, %object
	.size	L_SHA3_blocksx2_power8_r, 192
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_SHA3_blocksx2_power8_r:
	.quad	0x0000000000000001,0x0000000000008082
	.quad	0x800000000000808a,0x8000000080008000
	.quad	0x000000000000808b,0x0000000080000001
	.quad	0x8000000080008081,0x8000000000008009
	.quad	0x000000000000008a,0x0000000000000088
	.quad	0x0000000080008009,0x000000008000000a
	.quad	0x000000008000808b,0x800000000000008b
	.quad	0x8000000000008089,0x8000000000008003
	.quad	0x8000000000008002,0x8000000000000080
	.quad	0x000000000000800a,0x800000008000000a
	.quad	0x8000000080008081,0x8000000000008080
	.quad	0x0000000080000001,0x8000000080008008
	.machine	"push"
	.machine	"power8"
#ifndef __APPLE__
.text
.globl	sha3_blocksx2_power8
.type	sha3_blocksx2_power8,@function
.align	16
sha3_blocksx2_power8:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	sha3_blocksx2_power8, .-sha3_blocksx2_power8
#endif
#else
.section	__TEXT,__text
.globl	_sha3_blocksx2_power8
.p2align	4
_sha3_blocksx2_power8:
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
	addis	4, 2, L_SHA3_blocksx2_power8_r@toc@ha
	addi	4, 4, L_SHA3_blocksx2_power8_r@toc@l
	addis	5, 2, L_SHA3_blocksx2_power8_rot@toc@ha
	addi	5, 5, L_SHA3_blocksx2_power8_rot@toc@l
	# Load states 0,1 (interleaved)
	li	6, 0
	lxvd2x	32, 3, 6
	addi	6, 6, 16
	lxvd2x	33, 3, 6
	addi	6, 6, 16
	lxvd2x	34, 3, 6
	addi	6, 6, 16
	lxvd2x	35, 3, 6
	addi	6, 6, 16
	lxvd2x	36, 3, 6
	addi	6, 6, 16
	lxvd2x	37, 3, 6
	addi	6, 6, 16
	lxvd2x	38, 3, 6
	addi	6, 6, 16
	lxvd2x	39, 3, 6
	addi	6, 6, 16
	lxvd2x	40, 3, 6
	addi	6, 6, 16
	lxvd2x	41, 3, 6
	addi	6, 6, 16
	lxvd2x	42, 3, 6
	addi	6, 6, 16
	lxvd2x	43, 3, 6
	addi	6, 6, 16
	lxvd2x	44, 3, 6
	addi	6, 6, 16
	lxvd2x	45, 3, 6
	addi	6, 6, 16
	lxvd2x	46, 3, 6
	addi	6, 6, 16
	lxvd2x	47, 3, 6
	addi	6, 6, 16
	lxvd2x	48, 3, 6
	addi	6, 6, 16
	lxvd2x	49, 3, 6
	addi	6, 6, 16
	lxvd2x	50, 3, 6
	addi	6, 6, 16
	lxvd2x	51, 3, 6
	addi	6, 6, 16
	lxvd2x	52, 3, 6
	addi	6, 6, 16
	lxvd2x	53, 3, 6
	addi	6, 6, 16
	lxvd2x	54, 3, 6
	addi	6, 6, 16
	lxvd2x	55, 3, 6
	addi	6, 6, 16
	lxvd2x	56, 3, 6
	li	6, 24
	mtctr	6
	# Start of 24 rounds
L_SHA3_blocksx2_power8_begin:
	# Column Mix
	vxor	25, 0, 5
	vxor	25, 25, 10
	vxor	25, 25, 15
	vxor	25, 25, 20
	vxor	26, 1, 6
	vxor	26, 26, 11
	vxor	26, 26, 16
	vxor	26, 26, 21
	vxor	27, 2, 7
	vxor	27, 27, 12
	vxor	27, 27, 17
	vxor	27, 27, 22
	vxor	28, 3, 8
	vxor	28, 28, 13
	vxor	28, 28, 18
	vxor	28, 28, 23
	vxor	29, 4, 9
	vxor	29, 29, 14
	vxor	29, 29, 19
	vxor	29, 29, 24
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	30, 26, 31
	vxor	30, 29, 30
	vxor	0, 0, 30
	vxor	5, 5, 30
	vxor	10, 10, 30
	vxor	15, 15, 30
	vxor	20, 20, 30
	vrld	30, 27, 31
	vxor	30, 25, 30
	vxor	1, 1, 30
	vxor	6, 6, 30
	vxor	11, 11, 30
	vxor	16, 16, 30
	vxor	21, 21, 30
	vrld	30, 28, 31
	vxor	30, 26, 30
	vxor	2, 2, 30
	vxor	7, 7, 30
	vxor	12, 12, 30
	vxor	17, 17, 30
	vxor	22, 22, 30
	vrld	30, 29, 31
	vxor	30, 27, 30
	vxor	3, 3, 30
	vxor	8, 8, 30
	vxor	13, 13, 30
	vxor	18, 18, 30
	vxor	23, 23, 30
	vrld	30, 25, 31
	vxor	30, 28, 30
	vxor	4, 4, 30
	vxor	9, 9, 30
	vxor	14, 14, 30
	vxor	19, 19, 30
	vxor	24, 24, 30
	# Swap Rotate
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	25, 1, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	1, 6, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	6, 9, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	9, 22, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	22, 14, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	14, 20, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	20, 2, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	2, 12, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	12, 13, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	13, 19, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	19, 23, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	23, 15, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	15, 4, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	4, 24, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	24, 21, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	21, 8, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	8, 16, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	16, 5, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	5, 3, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	3, 18, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	18, 17, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	17, 11, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	11, 7, 31
	lxvdsx	63, 0, 5
	addi	5, 5, 8
	vrld	7, 10, 31
	# Row Mix
	vandc	10, 2, 1
	vandc	26, 3, 2
	vandc	27, 0, 4
	vandc	28, 1, 0
	vxor	0, 0, 10
	vxor	1, 1, 26
	vandc	10, 4, 3
	vxor	3, 3, 27
	vxor	2, 2, 10
	vxor	4, 4, 28
	vandc	10, 7, 6
	vandc	26, 8, 7
	vandc	27, 5, 9
	vandc	28, 6, 5
	vxor	5, 5, 10
	vxor	6, 6, 26
	vandc	10, 9, 8
	vxor	8, 8, 27
	vxor	7, 7, 10
	vxor	9, 9, 28
	vandc	10, 12, 11
	vandc	26, 13, 12
	vandc	27, 25, 14
	vandc	28, 11, 25
	vxor	10, 25, 10
	vxor	11, 11, 26
	vandc	25, 14, 13
	vxor	13, 13, 27
	vxor	12, 12, 25
	vxor	14, 14, 28
	vandc	25, 17, 16
	vandc	26, 18, 17
	vandc	27, 15, 19
	vandc	28, 16, 15
	vxor	15, 15, 25
	vxor	16, 16, 26
	vandc	25, 19, 18
	vxor	18, 18, 27
	vxor	17, 17, 25
	vxor	19, 19, 28
	vandc	25, 22, 21
	vandc	26, 23, 22
	vandc	27, 20, 24
	vandc	28, 21, 20
	vxor	20, 20, 25
	vxor	21, 21, 26
	vandc	25, 24, 23
	vxor	23, 23, 27
	vxor	22, 22, 25
	vxor	24, 24, 28
	subi	5, 5, 0xc8
	# Iota - XOR round constant into lane 0 of both states
	lxvdsx	58, 0, 4
	addi	4, 4, 8
	vxor	0, 0, 26
	bdnz	L_SHA3_blocksx2_power8_begin
	# Store states 0,1
	li	6, 0
	stxvd2x	32, 3, 6
	addi	6, 6, 16
	stxvd2x	33, 3, 6
	addi	6, 6, 16
	stxvd2x	34, 3, 6
	addi	6, 6, 16
	stxvd2x	35, 3, 6
	addi	6, 6, 16
	stxvd2x	36, 3, 6
	addi	6, 6, 16
	stxvd2x	37, 3, 6
	addi	6, 6, 16
	stxvd2x	38, 3, 6
	addi	6, 6, 16
	stxvd2x	39, 3, 6
	addi	6, 6, 16
	stxvd2x	40, 3, 6
	addi	6, 6, 16
	stxvd2x	41, 3, 6
	addi	6, 6, 16
	stxvd2x	42, 3, 6
	addi	6, 6, 16
	stxvd2x	43, 3, 6
	addi	6, 6, 16
	stxvd2x	44, 3, 6
	addi	6, 6, 16
	stxvd2x	45, 3, 6
	addi	6, 6, 16
	stxvd2x	46, 3, 6
	addi	6, 6, 16
	stxvd2x	47, 3, 6
	addi	6, 6, 16
	stxvd2x	48, 3, 6
	addi	6, 6, 16
	stxvd2x	49, 3, 6
	addi	6, 6, 16
	stxvd2x	50, 3, 6
	addi	6, 6, 16
	stxvd2x	51, 3, 6
	addi	6, 6, 16
	stxvd2x	52, 3, 6
	addi	6, 6, 16
	stxvd2x	53, 3, 6
	addi	6, 6, 16
	stxvd2x	54, 3, 6
	addi	6, 6, 16
	stxvd2x	55, 3, 6
	addi	6, 6, 16
	stxvd2x	56, 3, 6
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
	.size	sha3_blocksx2_power8,.-sha3_blocksx2_power8
#endif /* __APPLE__ */
	.machine	"pop"
#ifndef __APPLE__
	.text
	.type	L_SHA3_blocksx3_power8_rot, %object
	.size	L_SHA3_blocksx3_power8_rot, 200
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_SHA3_blocksx3_power8_rot:
	.quad	0x0000000000000001,0x0000000000000001
	.quad	0x000000000000002c,0x0000000000000014
	.quad	0x000000000000003d,0x0000000000000027
	.quad	0x0000000000000012,0x000000000000003e
	.quad	0x000000000000002b,0x0000000000000019
	.quad	0x0000000000000008,0x0000000000000038
	.quad	0x0000000000000029,0x000000000000001b
	.quad	0x000000000000000e,0x0000000000000002
	.quad	0x0000000000000037,0x000000000000002d
	.quad	0x0000000000000024,0x000000000000001c
	.quad	0x0000000000000015,0x000000000000000f
	.quad	0x000000000000000a,0x0000000000000006
	.quad	0x0000000000000003
#ifndef __APPLE__
	.text
	.type	L_SHA3_blocksx3_power8_r, %object
	.size	L_SHA3_blocksx3_power8_r, 192
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_SHA3_blocksx3_power8_r:
	.quad	0x0000000000000001,0x0000000000008082
	.quad	0x800000000000808a,0x8000000080008000
	.quad	0x000000000000808b,0x0000000080000001
	.quad	0x8000000080008081,0x8000000000008009
	.quad	0x000000000000008a,0x0000000000000088
	.quad	0x0000000080008009,0x000000008000000a
	.quad	0x000000008000808b,0x800000000000008b
	.quad	0x8000000000008089,0x8000000000008003
	.quad	0x8000000000008002,0x8000000000000080
	.quad	0x000000000000800a,0x800000008000000a
	.quad	0x8000000080008081,0x8000000000008080
	.quad	0x0000000080000001,0x8000000080008008
	.machine	"push"
	.machine	"power8"
#ifndef __APPLE__
.text
.globl	sha3_blocksx3_power8
.type	sha3_blocksx3_power8,@function
.align	16
sha3_blocksx3_power8:
#if defined(_CALL_ELF) && _CALL_ELF == 2
0:	addis	2, 12, .TOC.-0b@ha
	addi	2, 2, .TOC.-0b@l
	.localentry	sha3_blocksx3_power8, .-sha3_blocksx3_power8
#endif
#else
.section	__TEXT,__text
.globl	_sha3_blocksx3_power8
.p2align	4
_sha3_blocksx3_power8:
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
	subi	1, 1, 0x40
	# Load states (0,1 interleaved into vectors; 2 into GPRs)
	li	30, 0
	lxvd2x	32, 3, 30
	ld	0, 0(4)
	addi	30, 30, 16
	lxvd2x	33, 3, 30
	ld	5, 8(4)
	addi	30, 30, 16
	lxvd2x	34, 3, 30
	ld	6, 16(4)
	addi	30, 30, 16
	lxvd2x	35, 3, 30
	ld	7, 24(4)
	addi	30, 30, 16
	lxvd2x	36, 3, 30
	ld	8, 32(4)
	addi	30, 30, 16
	lxvd2x	37, 3, 30
	ld	9, 40(4)
	addi	30, 30, 16
	lxvd2x	38, 3, 30
	ld	10, 48(4)
	addi	30, 30, 16
	lxvd2x	39, 3, 30
	ld	11, 56(4)
	addi	30, 30, 16
	lxvd2x	40, 3, 30
	ld	12, 64(4)
	addi	30, 30, 16
	lxvd2x	41, 3, 30
	ld	14, 72(4)
	addi	30, 30, 16
	lxvd2x	42, 3, 30
	ld	15, 80(4)
	addi	30, 30, 16
	lxvd2x	43, 3, 30
	ld	16, 88(4)
	addi	30, 30, 16
	lxvd2x	44, 3, 30
	ld	17, 96(4)
	addi	30, 30, 16
	lxvd2x	45, 3, 30
	ld	18, 104(4)
	addi	30, 30, 16
	lxvd2x	46, 3, 30
	ld	19, 112(4)
	addi	30, 30, 16
	lxvd2x	47, 3, 30
	ld	20, 120(4)
	addi	30, 30, 16
	lxvd2x	48, 3, 30
	ld	21, 128(4)
	addi	30, 30, 16
	lxvd2x	49, 3, 30
	ld	22, 136(4)
	addi	30, 30, 16
	lxvd2x	50, 3, 30
	ld	23, 144(4)
	addi	30, 30, 16
	lxvd2x	51, 3, 30
	ld	24, 152(4)
	addi	30, 30, 16
	lxvd2x	52, 3, 30
	ld	25, 160(4)
	addi	30, 30, 16
	lxvd2x	53, 3, 30
	ld	26, 168(4)
	addi	30, 30, 16
	lxvd2x	54, 3, 30
	ld	27, 176(4)
	addi	30, 30, 16
	lxvd2x	55, 3, 30
	ld	28, 184(4)
	addi	30, 30, 16
	lxvd2x	56, 3, 30
	ld	29, 192(4)
	addis	31, 2, L_SHA3_blocksx3_power8_rot@toc@ha
	addi	31, 31, L_SHA3_blocksx3_power8_rot@toc@l
	addis	30, 2, L_SHA3_blocksx3_power8_r@toc@ha
	addi	30, 30, L_SHA3_blocksx3_power8_r@toc@l
	std	30, 56(1)
	std	3, 40(1)
	std	4, 48(1)
	li	30, 24
	mtctr	30
	# Start of 24 rounds
L_SHA3_blocksx3_power8_begin:
	# Theta - column parities (VSX || scalar)
	vxor	25, 0, 5
	xor	30, 0, 9
	vxor	25, 25, 10
	xor	30, 30, 15
	vxor	25, 25, 15
	xor	30, 30, 20
	vxor	25, 25, 20
	xor	30, 30, 25
	std	30, 0(1)
	vxor	26, 1, 6
	xor	30, 5, 10
	vxor	26, 26, 11
	xor	30, 30, 16
	vxor	26, 26, 16
	xor	30, 30, 21
	vxor	26, 26, 21
	xor	30, 30, 26
	std	30, 8(1)
	vxor	27, 2, 7
	xor	30, 6, 11
	vxor	27, 27, 12
	xor	30, 30, 17
	vxor	27, 27, 17
	xor	30, 30, 22
	vxor	27, 27, 22
	xor	30, 30, 27
	std	30, 16(1)
	vxor	28, 3, 8
	xor	30, 7, 12
	vxor	28, 28, 13
	xor	30, 30, 18
	vxor	28, 28, 18
	xor	30, 30, 23
	vxor	28, 28, 23
	xor	30, 30, 28
	std	30, 24(1)
	vxor	29, 4, 9
	xor	30, 8, 14
	vxor	29, 29, 14
	xor	30, 30, 19
	vxor	29, 29, 19
	xor	30, 30, 24
	vxor	29, 29, 24
	xor	30, 30, 29
	std	30, 32(1)
	# Theta - fold and apply (VSX || scalar)
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	30, 26, 31
	ld	30, 8(1)
	vxor	30, 29, 30
	rotldi	30, 30, 1
	ld	3, 32(1)
	xor	3, 3, 30
	vxor	0, 0, 30
	xor	0, 0, 3
	vxor	5, 5, 30
	xor	9, 9, 3
	vxor	10, 10, 30
	xor	15, 15, 3
	vxor	15, 15, 30
	xor	20, 20, 3
	vxor	20, 20, 30
	xor	25, 25, 3
	vrld	30, 27, 31
	ld	30, 16(1)
	vxor	30, 25, 30
	rotldi	30, 30, 1
	ld	3, 0(1)
	xor	3, 3, 30
	vxor	1, 1, 30
	xor	5, 5, 3
	vxor	6, 6, 30
	xor	10, 10, 3
	vxor	11, 11, 30
	xor	16, 16, 3
	vxor	16, 16, 30
	xor	21, 21, 3
	vxor	21, 21, 30
	xor	26, 26, 3
	vrld	30, 28, 31
	ld	30, 24(1)
	vxor	30, 26, 30
	rotldi	30, 30, 1
	ld	3, 8(1)
	xor	3, 3, 30
	vxor	2, 2, 30
	xor	6, 6, 3
	vxor	7, 7, 30
	xor	11, 11, 3
	vxor	12, 12, 30
	xor	17, 17, 3
	vxor	17, 17, 30
	xor	22, 22, 3
	vxor	22, 22, 30
	xor	27, 27, 3
	vrld	30, 29, 31
	ld	30, 32(1)
	vxor	30, 27, 30
	rotldi	30, 30, 1
	ld	3, 16(1)
	xor	3, 3, 30
	vxor	3, 3, 30
	xor	7, 7, 3
	vxor	8, 8, 30
	xor	12, 12, 3
	vxor	13, 13, 30
	xor	18, 18, 3
	vxor	18, 18, 30
	xor	23, 23, 3
	vxor	23, 23, 30
	xor	28, 28, 3
	vrld	30, 25, 31
	ld	30, 0(1)
	vxor	30, 28, 30
	rotldi	30, 30, 1
	ld	3, 24(1)
	xor	3, 3, 30
	vxor	4, 4, 30
	xor	8, 8, 3
	vxor	9, 9, 30
	xor	14, 14, 3
	vxor	14, 14, 30
	xor	19, 19, 3
	vxor	19, 19, 30
	xor	24, 24, 3
	vxor	24, 24, 30
	xor	29, 29, 3
	# Rho + Pi (VSX || scalar)
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	25, 1, 31
	rotldi	4, 5, 1
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	1, 6, 31
	rotldi	5, 10, 44
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	6, 9, 31
	rotldi	10, 14, 20
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	9, 22, 31
	rotldi	14, 27, 61
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	22, 14, 31
	rotldi	27, 19, 39
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	14, 20, 31
	rotldi	19, 25, 18
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	20, 2, 31
	rotldi	25, 6, 62
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	2, 12, 31
	rotldi	6, 17, 43
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	12, 13, 31
	rotldi	17, 18, 25
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	13, 19, 31
	rotldi	18, 24, 8
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	19, 23, 31
	rotldi	24, 28, 56
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	23, 15, 31
	rotldi	28, 20, 41
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	15, 4, 31
	rotldi	20, 8, 27
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	4, 24, 31
	rotldi	8, 29, 14
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	24, 21, 31
	rotldi	29, 26, 2
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	21, 8, 31
	rotldi	26, 12, 55
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	8, 16, 31
	rotldi	12, 21, 45
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	16, 5, 31
	rotldi	21, 9, 36
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	5, 3, 31
	rotldi	9, 7, 28
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	3, 18, 31
	rotldi	7, 23, 21
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	18, 17, 31
	rotldi	23, 22, 15
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	17, 11, 31
	rotldi	22, 16, 10
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	11, 7, 31
	rotldi	16, 11, 6
	lxvdsx	63, 0, 31
	addi	31, 31, 8
	vrld	7, 10, 31
	rotldi	11, 15, 3
	# Chi (VSX || scalar)
	vandc	26, 2, 1
	andc	30, 6, 5
	vandc	27, 3, 2
	andc	3, 7, 6
	vandc	10, 4, 3
	andc	15, 8, 7
	vxor	2, 2, 10
	xor	6, 6, 15
	vandc	10, 0, 4
	andc	15, 0, 8
	vxor	3, 3, 10
	xor	7, 7, 15
	vandc	10, 1, 0
	andc	15, 5, 0
	vxor	1, 1, 27
	xor	5, 5, 3
	vxor	4, 4, 10
	xor	8, 8, 15
	vxor	0, 0, 26
	xor	0, 0, 30
	vandc	26, 7, 6
	andc	30, 11, 10
	vandc	27, 8, 7
	andc	3, 12, 11
	vandc	10, 9, 8
	andc	15, 14, 12
	vxor	7, 7, 10
	xor	11, 11, 15
	vandc	10, 5, 9
	andc	15, 9, 14
	vxor	8, 8, 10
	xor	12, 12, 15
	vandc	10, 6, 5
	andc	15, 10, 9
	vxor	6, 6, 27
	xor	10, 10, 3
	vxor	9, 9, 10
	xor	14, 14, 15
	vxor	5, 5, 26
	xor	9, 9, 30
	vandc	26, 12, 11
	andc	30, 17, 16
	vandc	27, 13, 12
	andc	3, 18, 17
	vandc	10, 14, 13
	andc	15, 19, 18
	vxor	12, 12, 10
	xor	17, 17, 15
	vandc	10, 25, 14
	andc	15, 4, 19
	vxor	13, 13, 10
	xor	18, 18, 15
	vandc	10, 11, 25
	andc	15, 16, 4
	vxor	11, 11, 27
	xor	16, 16, 3
	vxor	14, 14, 10
	xor	19, 19, 15
	vxor	10, 25, 26
	xor	15, 4, 30
	vandc	26, 17, 16
	andc	30, 22, 21
	vandc	27, 18, 17
	andc	3, 23, 22
	vandc	25, 19, 18
	andc	4, 24, 23
	vxor	17, 17, 25
	xor	22, 22, 4
	vandc	25, 15, 19
	andc	4, 20, 24
	vxor	18, 18, 25
	xor	23, 23, 4
	vandc	25, 16, 15
	andc	4, 21, 20
	vxor	16, 16, 27
	xor	21, 21, 3
	vxor	19, 19, 25
	xor	24, 24, 4
	vxor	15, 15, 26
	xor	20, 20, 30
	vandc	26, 22, 21
	andc	30, 27, 26
	vandc	27, 23, 22
	andc	3, 28, 27
	vandc	25, 24, 23
	andc	4, 29, 28
	vxor	22, 22, 25
	xor	27, 27, 4
	vandc	25, 20, 24
	andc	4, 25, 29
	vxor	23, 23, 25
	xor	28, 28, 4
	vandc	25, 21, 20
	andc	4, 26, 25
	vxor	21, 21, 27
	xor	26, 26, 3
	vxor	24, 24, 25
	xor	29, 29, 4
	vxor	20, 20, 26
	xor	25, 25, 30
	subi	31, 31, 0xc8
	# Iota - XOR round constant into lane 0 of each state
	ld	30, 56(1)
	lxvdsx	58, 0, 30
	vxor	0, 0, 26
	ld	3, 0(30)
	xor	0, 0, 3
	addi	30, 30, 8
	std	30, 56(1)
	bdnz	L_SHA3_blocksx3_power8_begin
	ld	3, 40(1)
	ld	4, 48(1)
	# Store states
	li	30, 0
	stxvd2x	32, 3, 30
	std	0, 0(4)
	addi	30, 30, 16
	stxvd2x	33, 3, 30
	std	5, 8(4)
	addi	30, 30, 16
	stxvd2x	34, 3, 30
	std	6, 16(4)
	addi	30, 30, 16
	stxvd2x	35, 3, 30
	std	7, 24(4)
	addi	30, 30, 16
	stxvd2x	36, 3, 30
	std	8, 32(4)
	addi	30, 30, 16
	stxvd2x	37, 3, 30
	std	9, 40(4)
	addi	30, 30, 16
	stxvd2x	38, 3, 30
	std	10, 48(4)
	addi	30, 30, 16
	stxvd2x	39, 3, 30
	std	11, 56(4)
	addi	30, 30, 16
	stxvd2x	40, 3, 30
	std	12, 64(4)
	addi	30, 30, 16
	stxvd2x	41, 3, 30
	std	14, 72(4)
	addi	30, 30, 16
	stxvd2x	42, 3, 30
	std	15, 80(4)
	addi	30, 30, 16
	stxvd2x	43, 3, 30
	std	16, 88(4)
	addi	30, 30, 16
	stxvd2x	44, 3, 30
	std	17, 96(4)
	addi	30, 30, 16
	stxvd2x	45, 3, 30
	std	18, 104(4)
	addi	30, 30, 16
	stxvd2x	46, 3, 30
	std	19, 112(4)
	addi	30, 30, 16
	stxvd2x	47, 3, 30
	std	20, 120(4)
	addi	30, 30, 16
	stxvd2x	48, 3, 30
	std	21, 128(4)
	addi	30, 30, 16
	stxvd2x	49, 3, 30
	std	22, 136(4)
	addi	30, 30, 16
	stxvd2x	50, 3, 30
	std	23, 144(4)
	addi	30, 30, 16
	stxvd2x	51, 3, 30
	std	24, 152(4)
	addi	30, 30, 16
	stxvd2x	52, 3, 30
	std	25, 160(4)
	addi	30, 30, 16
	stxvd2x	53, 3, 30
	std	26, 168(4)
	addi	30, 30, 16
	stxvd2x	54, 3, 30
	std	27, 176(4)
	addi	30, 30, 16
	stxvd2x	55, 3, 30
	std	28, 184(4)
	addi	30, 30, 16
	stxvd2x	56, 3, 30
	std	29, 192(4)
	addi	1, 1, 0x40
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
	.size	sha3_blocksx3_power8,.-sha3_blocksx3_power8
#endif /* __APPLE__ */
	.machine	"pop"
#endif /* (WOLFSSL_HAVE_MLKEM || HAVE_DILITHIUM) && WOLFSSL_SHA3_PPC64_BLOCKS_N */
#endif /* WOLFSSL_PPC64_ASM_POWER8 */
#endif /* WOLFSSL_SHA3 */
#endif /* WOLFSSL_PPC64_ASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_PPC64_ASM_INLINE */
