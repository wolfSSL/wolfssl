/* ppc32-sha3-asm
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
 *   ruby ./sha3/sha3.rb ppc32 \
 *       ../wolfssl/wolfcrypt/src/port/ppc32/ppc32-sha3-asm.S
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

#ifdef WOLFSSL_PPC32_ASM
#ifndef WOLFSSL_PPC32_ASM_INLINE
	.machine ppc
#if defined(WOLFSSL_SHA3) && defined(WOLFSSL_PPC32_ASM)
#ifndef __APPLE__
	.text
	.type	L_sha3_ppc32_rt, %object
	.size	L_sha3_ppc32_rt, 192
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_sha3_ppc32_rt:
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
	.section	".text"
	.align	4
	.globl	BlockSha3
	.type	BlockSha3, @function
BlockSha3:
	stwu	1, -32(1)
	mflr	0
	stw	0, 28(1)
	stw	14, 0(1)
	stw	15, 4(1)
	stw	16, 8(1)
	stw	17, 12(1)
	stw	18, 16(1)
	stw	19, 20(1)
	stw	20, 24(1)
	lis	20, L_sha3_ppc32_rt@ha
	la	20, L_sha3_ppc32_rt@l(20)
	subi	1, 1, 0xd0
	li	14, 12
	mtctr	14
	# Start of 24 rounds (two per iteration)
L_sha3_ppc32_begin:
	# Round even - state -> scratch
	# Column Mix
	lwz	0, 0(3)
	lwz	4, 4(3)
	lwz	18, 40(3)
	lwz	19, 44(3)
	xor	0, 0, 18
	xor	4, 4, 19
	lwz	18, 80(3)
	lwz	19, 84(3)
	xor	0, 0, 18
	xor	4, 4, 19
	lwz	18, 120(3)
	lwz	19, 124(3)
	xor	0, 0, 18
	xor	4, 4, 19
	lwz	18, 160(3)
	lwz	19, 164(3)
	xor	0, 0, 18
	xor	4, 4, 19
	lwz	5, 8(3)
	lwz	6, 12(3)
	lwz	18, 48(3)
	lwz	19, 52(3)
	xor	5, 5, 18
	xor	6, 6, 19
	lwz	18, 88(3)
	lwz	19, 92(3)
	xor	5, 5, 18
	xor	6, 6, 19
	lwz	18, 128(3)
	lwz	19, 132(3)
	xor	5, 5, 18
	xor	6, 6, 19
	lwz	18, 168(3)
	lwz	19, 172(3)
	xor	5, 5, 18
	xor	6, 6, 19
	lwz	7, 16(3)
	lwz	8, 20(3)
	lwz	18, 56(3)
	lwz	19, 60(3)
	xor	7, 7, 18
	xor	8, 8, 19
	lwz	18, 96(3)
	lwz	19, 100(3)
	xor	7, 7, 18
	xor	8, 8, 19
	lwz	18, 136(3)
	lwz	19, 140(3)
	xor	7, 7, 18
	xor	8, 8, 19
	lwz	18, 176(3)
	lwz	19, 180(3)
	xor	7, 7, 18
	xor	8, 8, 19
	lwz	9, 24(3)
	lwz	10, 28(3)
	lwz	18, 64(3)
	lwz	19, 68(3)
	xor	9, 9, 18
	xor	10, 10, 19
	lwz	18, 104(3)
	lwz	19, 108(3)
	xor	9, 9, 18
	xor	10, 10, 19
	lwz	18, 144(3)
	lwz	19, 148(3)
	xor	9, 9, 18
	xor	10, 10, 19
	lwz	18, 184(3)
	lwz	19, 188(3)
	xor	9, 9, 18
	xor	10, 10, 19
	lwz	11, 32(3)
	lwz	12, 36(3)
	lwz	18, 72(3)
	lwz	19, 76(3)
	xor	11, 11, 18
	xor	12, 12, 19
	lwz	18, 112(3)
	lwz	19, 116(3)
	xor	11, 11, 18
	xor	12, 12, 19
	lwz	18, 152(3)
	lwz	19, 156(3)
	xor	11, 11, 18
	xor	12, 12, 19
	lwz	18, 192(3)
	lwz	19, 196(3)
	xor	11, 11, 18
	xor	12, 12, 19
	rlwinm	14, 5, 1, 0, 30
	rlwimi	14, 6, 1, 31, 31
	rlwinm	15, 6, 1, 0, 30
	rlwimi	15, 5, 1, 31, 31
	xor	16, 11, 14
	xor	17, 12, 15
	lwz	18, 0(3)
	lwz	19, 4(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 0(3)
	stw	19, 4(3)
	lwz	18, 40(3)
	lwz	19, 44(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 40(3)
	stw	19, 44(3)
	lwz	18, 80(3)
	lwz	19, 84(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 80(3)
	stw	19, 84(3)
	lwz	18, 120(3)
	lwz	19, 124(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 120(3)
	stw	19, 124(3)
	lwz	18, 160(3)
	lwz	19, 164(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 160(3)
	stw	19, 164(3)
	rlwinm	14, 7, 1, 0, 30
	rlwimi	14, 8, 1, 31, 31
	rlwinm	15, 8, 1, 0, 30
	rlwimi	15, 7, 1, 31, 31
	xor	16, 0, 14
	xor	17, 4, 15
	lwz	18, 8(3)
	lwz	19, 12(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 8(3)
	stw	19, 12(3)
	lwz	18, 48(3)
	lwz	19, 52(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 48(3)
	stw	19, 52(3)
	lwz	18, 88(3)
	lwz	19, 92(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 88(3)
	stw	19, 92(3)
	lwz	18, 128(3)
	lwz	19, 132(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 128(3)
	stw	19, 132(3)
	lwz	18, 168(3)
	lwz	19, 172(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 168(3)
	stw	19, 172(3)
	rlwinm	14, 9, 1, 0, 30
	rlwimi	14, 10, 1, 31, 31
	rlwinm	15, 10, 1, 0, 30
	rlwimi	15, 9, 1, 31, 31
	xor	16, 5, 14
	xor	17, 6, 15
	lwz	18, 16(3)
	lwz	19, 20(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 16(3)
	stw	19, 20(3)
	lwz	18, 56(3)
	lwz	19, 60(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 56(3)
	stw	19, 60(3)
	lwz	18, 96(3)
	lwz	19, 100(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 96(3)
	stw	19, 100(3)
	lwz	18, 136(3)
	lwz	19, 140(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 136(3)
	stw	19, 140(3)
	lwz	18, 176(3)
	lwz	19, 180(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 176(3)
	stw	19, 180(3)
	rlwinm	14, 11, 1, 0, 30
	rlwimi	14, 12, 1, 31, 31
	rlwinm	15, 12, 1, 0, 30
	rlwimi	15, 11, 1, 31, 31
	xor	16, 7, 14
	xor	17, 8, 15
	lwz	18, 24(3)
	lwz	19, 28(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 24(3)
	stw	19, 28(3)
	lwz	18, 64(3)
	lwz	19, 68(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 64(3)
	stw	19, 68(3)
	lwz	18, 104(3)
	lwz	19, 108(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 104(3)
	stw	19, 108(3)
	lwz	18, 144(3)
	lwz	19, 148(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 144(3)
	stw	19, 148(3)
	lwz	18, 184(3)
	lwz	19, 188(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 184(3)
	stw	19, 188(3)
	rlwinm	14, 0, 1, 0, 30
	rlwimi	14, 4, 1, 31, 31
	rlwinm	15, 4, 1, 0, 30
	rlwimi	15, 0, 1, 31, 31
	xor	16, 9, 14
	xor	17, 10, 15
	lwz	18, 32(3)
	lwz	19, 36(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 32(3)
	stw	19, 36(3)
	lwz	18, 72(3)
	lwz	19, 76(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 72(3)
	stw	19, 76(3)
	lwz	18, 112(3)
	lwz	19, 116(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 112(3)
	stw	19, 116(3)
	lwz	18, 152(3)
	lwz	19, 156(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 152(3)
	stw	19, 156(3)
	lwz	18, 192(3)
	lwz	19, 196(3)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 192(3)
	stw	19, 196(3)
	# Row Mix
	# Row 0
	lwz	0, 0(3)
	lwz	4, 4(3)
	lwz	14, 48(3)
	lwz	15, 52(3)
	rlwinm	5, 15, 12, 0, 19
	rlwimi	5, 14, 12, 20, 31
	rlwinm	6, 14, 12, 0, 19
	rlwimi	6, 15, 12, 20, 31
	lwz	14, 96(3)
	lwz	15, 100(3)
	rlwinm	7, 15, 11, 0, 20
	rlwimi	7, 14, 11, 21, 31
	rlwinm	8, 14, 11, 0, 20
	rlwimi	8, 15, 11, 21, 31
	lwz	14, 144(3)
	lwz	15, 148(3)
	rlwinm	9, 14, 21, 0, 10
	rlwimi	9, 15, 21, 11, 31
	rlwinm	10, 15, 21, 0, 10
	rlwimi	10, 14, 21, 11, 31
	lwz	14, 192(3)
	lwz	15, 196(3)
	rlwinm	11, 14, 14, 0, 17
	rlwimi	11, 15, 14, 18, 31
	rlwinm	12, 15, 14, 0, 17
	rlwimi	12, 14, 14, 18, 31
	andc	14, 9, 7
	andc	15, 10, 8
	xor	14, 14, 5
	xor	15, 15, 6
	stw	14, 8(1)
	stw	15, 12(1)
	andc	14, 11, 9
	andc	15, 12, 10
	xor	14, 14, 7
	xor	15, 15, 8
	stw	14, 16(1)
	stw	15, 20(1)
	andc	14, 0, 11
	andc	15, 4, 12
	xor	14, 14, 9
	xor	15, 15, 10
	stw	14, 24(1)
	stw	15, 28(1)
	andc	14, 5, 0
	andc	15, 6, 4
	xor	14, 14, 11
	xor	15, 15, 12
	stw	14, 32(1)
	stw	15, 36(1)
	# Get constant
	lwz	11, 0(20)
	lwz	12, 4(20)
	addi	20, 20, 8
	andc	14, 7, 5
	andc	15, 8, 6
	xor	14, 14, 0
	xor	15, 15, 4
	# XOR in constant
	xor	14, 14, 11
	xor	15, 15, 12
	stw	14, 0(1)
	stw	15, 4(1)
	# Row 1
	lwz	14, 24(3)
	lwz	15, 28(3)
	rlwinm	0, 14, 28, 0, 3
	rlwimi	0, 15, 28, 4, 31
	rlwinm	4, 15, 28, 0, 3
	rlwimi	4, 14, 28, 4, 31
	lwz	14, 72(3)
	lwz	15, 76(3)
	rlwinm	5, 14, 20, 0, 11
	rlwimi	5, 15, 20, 12, 31
	rlwinm	6, 15, 20, 0, 11
	rlwimi	6, 14, 20, 12, 31
	lwz	14, 80(3)
	lwz	15, 84(3)
	rlwinm	7, 14, 3, 0, 28
	rlwimi	7, 15, 3, 29, 31
	rlwinm	8, 15, 3, 0, 28
	rlwimi	8, 14, 3, 29, 31
	lwz	14, 128(3)
	lwz	15, 132(3)
	rlwinm	9, 15, 13, 0, 18
	rlwimi	9, 14, 13, 19, 31
	rlwinm	10, 14, 13, 0, 18
	rlwimi	10, 15, 13, 19, 31
	lwz	14, 176(3)
	lwz	15, 180(3)
	rlwinm	11, 15, 29, 0, 2
	rlwimi	11, 14, 29, 3, 31
	rlwinm	12, 14, 29, 0, 2
	rlwimi	12, 15, 29, 3, 31
	andc	14, 9, 7
	andc	15, 10, 8
	xor	14, 14, 5
	xor	15, 15, 6
	stw	14, 48(1)
	stw	15, 52(1)
	andc	14, 11, 9
	andc	15, 12, 10
	xor	14, 14, 7
	xor	15, 15, 8
	stw	14, 56(1)
	stw	15, 60(1)
	andc	14, 0, 11
	andc	15, 4, 12
	xor	14, 14, 9
	xor	15, 15, 10
	stw	14, 64(1)
	stw	15, 68(1)
	andc	14, 5, 0
	andc	15, 6, 4
	xor	14, 14, 11
	xor	15, 15, 12
	stw	14, 72(1)
	stw	15, 76(1)
	andc	14, 7, 5
	andc	15, 8, 6
	xor	14, 14, 0
	xor	15, 15, 4
	stw	14, 40(1)
	stw	15, 44(1)
	# Row 2
	lwz	14, 8(3)
	lwz	15, 12(3)
	rlwinm	0, 14, 1, 0, 30
	rlwimi	0, 15, 1, 31, 31
	rlwinm	4, 15, 1, 0, 30
	rlwimi	4, 14, 1, 31, 31
	lwz	14, 56(3)
	lwz	15, 60(3)
	rlwinm	5, 14, 6, 0, 25
	rlwimi	5, 15, 6, 26, 31
	rlwinm	6, 15, 6, 0, 25
	rlwimi	6, 14, 6, 26, 31
	lwz	14, 104(3)
	lwz	15, 108(3)
	rlwinm	7, 14, 25, 0, 6
	rlwimi	7, 15, 25, 7, 31
	rlwinm	8, 15, 25, 0, 6
	rlwimi	8, 14, 25, 7, 31
	lwz	14, 152(3)
	lwz	15, 156(3)
	rlwinm	9, 14, 8, 0, 23
	rlwimi	9, 15, 8, 24, 31
	rlwinm	10, 15, 8, 0, 23
	rlwimi	10, 14, 8, 24, 31
	lwz	14, 160(3)
	lwz	15, 164(3)
	rlwinm	11, 14, 18, 0, 13
	rlwimi	11, 15, 18, 14, 31
	rlwinm	12, 15, 18, 0, 13
	rlwimi	12, 14, 18, 14, 31
	andc	14, 9, 7
	andc	15, 10, 8
	xor	14, 14, 5
	xor	15, 15, 6
	stw	14, 88(1)
	stw	15, 92(1)
	andc	14, 11, 9
	andc	15, 12, 10
	xor	14, 14, 7
	xor	15, 15, 8
	stw	14, 96(1)
	stw	15, 100(1)
	andc	14, 0, 11
	andc	15, 4, 12
	xor	14, 14, 9
	xor	15, 15, 10
	stw	14, 104(1)
	stw	15, 108(1)
	andc	14, 5, 0
	andc	15, 6, 4
	xor	14, 14, 11
	xor	15, 15, 12
	stw	14, 112(1)
	stw	15, 116(1)
	andc	14, 7, 5
	andc	15, 8, 6
	xor	14, 14, 0
	xor	15, 15, 4
	stw	14, 80(1)
	stw	15, 84(1)
	# Row 3
	lwz	14, 32(3)
	lwz	15, 36(3)
	rlwinm	0, 14, 27, 0, 4
	rlwimi	0, 15, 27, 5, 31
	rlwinm	4, 15, 27, 0, 4
	rlwimi	4, 14, 27, 5, 31
	lwz	14, 40(3)
	lwz	15, 44(3)
	rlwinm	5, 15, 4, 0, 27
	rlwimi	5, 14, 4, 28, 31
	rlwinm	6, 14, 4, 0, 27
	rlwimi	6, 15, 4, 28, 31
	lwz	14, 88(3)
	lwz	15, 92(3)
	rlwinm	7, 14, 10, 0, 21
	rlwimi	7, 15, 10, 22, 31
	rlwinm	8, 15, 10, 0, 21
	rlwimi	8, 14, 10, 22, 31
	lwz	14, 136(3)
	lwz	15, 140(3)
	rlwinm	9, 14, 15, 0, 16
	rlwimi	9, 15, 15, 17, 31
	rlwinm	10, 15, 15, 0, 16
	rlwimi	10, 14, 15, 17, 31
	lwz	14, 184(3)
	lwz	15, 188(3)
	rlwinm	11, 15, 24, 0, 7
	rlwimi	11, 14, 24, 8, 31
	rlwinm	12, 14, 24, 0, 7
	rlwimi	12, 15, 24, 8, 31
	andc	14, 9, 7
	andc	15, 10, 8
	xor	14, 14, 5
	xor	15, 15, 6
	stw	14, 128(1)
	stw	15, 132(1)
	andc	14, 11, 9
	andc	15, 12, 10
	xor	14, 14, 7
	xor	15, 15, 8
	stw	14, 136(1)
	stw	15, 140(1)
	andc	14, 0, 11
	andc	15, 4, 12
	xor	14, 14, 9
	xor	15, 15, 10
	stw	14, 144(1)
	stw	15, 148(1)
	andc	14, 5, 0
	andc	15, 6, 4
	xor	14, 14, 11
	xor	15, 15, 12
	stw	14, 152(1)
	stw	15, 156(1)
	andc	14, 7, 5
	andc	15, 8, 6
	xor	14, 14, 0
	xor	15, 15, 4
	stw	14, 120(1)
	stw	15, 124(1)
	# Row 4
	lwz	14, 16(3)
	lwz	15, 20(3)
	rlwinm	0, 15, 30, 0, 1
	rlwimi	0, 14, 30, 2, 31
	rlwinm	4, 14, 30, 0, 1
	rlwimi	4, 15, 30, 2, 31
	lwz	14, 64(3)
	lwz	15, 68(3)
	rlwinm	5, 15, 23, 0, 8
	rlwimi	5, 14, 23, 9, 31
	rlwinm	6, 14, 23, 0, 8
	rlwimi	6, 15, 23, 9, 31
	lwz	14, 112(3)
	lwz	15, 116(3)
	rlwinm	7, 15, 7, 0, 24
	rlwimi	7, 14, 7, 25, 31
	rlwinm	8, 14, 7, 0, 24
	rlwimi	8, 15, 7, 25, 31
	lwz	14, 120(3)
	lwz	15, 124(3)
	rlwinm	9, 15, 9, 0, 22
	rlwimi	9, 14, 9, 23, 31
	rlwinm	10, 14, 9, 0, 22
	rlwimi	10, 15, 9, 23, 31
	lwz	14, 168(3)
	lwz	15, 172(3)
	rlwinm	11, 14, 2, 0, 29
	rlwimi	11, 15, 2, 30, 31
	rlwinm	12, 15, 2, 0, 29
	rlwimi	12, 14, 2, 30, 31
	andc	14, 9, 7
	andc	15, 10, 8
	xor	14, 14, 5
	xor	15, 15, 6
	stw	14, 168(1)
	stw	15, 172(1)
	andc	14, 11, 9
	andc	15, 12, 10
	xor	14, 14, 7
	xor	15, 15, 8
	stw	14, 176(1)
	stw	15, 180(1)
	andc	14, 0, 11
	andc	15, 4, 12
	xor	14, 14, 9
	xor	15, 15, 10
	stw	14, 184(1)
	stw	15, 188(1)
	andc	14, 5, 0
	andc	15, 6, 4
	xor	14, 14, 11
	xor	15, 15, 12
	stw	14, 192(1)
	stw	15, 196(1)
	andc	14, 7, 5
	andc	15, 8, 6
	xor	14, 14, 0
	xor	15, 15, 4
	stw	14, 160(1)
	stw	15, 164(1)
	# Round odd - scratch -> state
	# Column Mix
	lwz	0, 0(1)
	lwz	4, 4(1)
	lwz	18, 40(1)
	lwz	19, 44(1)
	xor	0, 0, 18
	xor	4, 4, 19
	lwz	18, 80(1)
	lwz	19, 84(1)
	xor	0, 0, 18
	xor	4, 4, 19
	lwz	18, 120(1)
	lwz	19, 124(1)
	xor	0, 0, 18
	xor	4, 4, 19
	lwz	18, 160(1)
	lwz	19, 164(1)
	xor	0, 0, 18
	xor	4, 4, 19
	lwz	5, 8(1)
	lwz	6, 12(1)
	lwz	18, 48(1)
	lwz	19, 52(1)
	xor	5, 5, 18
	xor	6, 6, 19
	lwz	18, 88(1)
	lwz	19, 92(1)
	xor	5, 5, 18
	xor	6, 6, 19
	lwz	18, 128(1)
	lwz	19, 132(1)
	xor	5, 5, 18
	xor	6, 6, 19
	lwz	18, 168(1)
	lwz	19, 172(1)
	xor	5, 5, 18
	xor	6, 6, 19
	lwz	7, 16(1)
	lwz	8, 20(1)
	lwz	18, 56(1)
	lwz	19, 60(1)
	xor	7, 7, 18
	xor	8, 8, 19
	lwz	18, 96(1)
	lwz	19, 100(1)
	xor	7, 7, 18
	xor	8, 8, 19
	lwz	18, 136(1)
	lwz	19, 140(1)
	xor	7, 7, 18
	xor	8, 8, 19
	lwz	18, 176(1)
	lwz	19, 180(1)
	xor	7, 7, 18
	xor	8, 8, 19
	lwz	9, 24(1)
	lwz	10, 28(1)
	lwz	18, 64(1)
	lwz	19, 68(1)
	xor	9, 9, 18
	xor	10, 10, 19
	lwz	18, 104(1)
	lwz	19, 108(1)
	xor	9, 9, 18
	xor	10, 10, 19
	lwz	18, 144(1)
	lwz	19, 148(1)
	xor	9, 9, 18
	xor	10, 10, 19
	lwz	18, 184(1)
	lwz	19, 188(1)
	xor	9, 9, 18
	xor	10, 10, 19
	lwz	11, 32(1)
	lwz	12, 36(1)
	lwz	18, 72(1)
	lwz	19, 76(1)
	xor	11, 11, 18
	xor	12, 12, 19
	lwz	18, 112(1)
	lwz	19, 116(1)
	xor	11, 11, 18
	xor	12, 12, 19
	lwz	18, 152(1)
	lwz	19, 156(1)
	xor	11, 11, 18
	xor	12, 12, 19
	lwz	18, 192(1)
	lwz	19, 196(1)
	xor	11, 11, 18
	xor	12, 12, 19
	rlwinm	14, 5, 1, 0, 30
	rlwimi	14, 6, 1, 31, 31
	rlwinm	15, 6, 1, 0, 30
	rlwimi	15, 5, 1, 31, 31
	xor	16, 11, 14
	xor	17, 12, 15
	lwz	18, 0(1)
	lwz	19, 4(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 0(1)
	stw	19, 4(1)
	lwz	18, 40(1)
	lwz	19, 44(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 40(1)
	stw	19, 44(1)
	lwz	18, 80(1)
	lwz	19, 84(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 80(1)
	stw	19, 84(1)
	lwz	18, 120(1)
	lwz	19, 124(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 120(1)
	stw	19, 124(1)
	lwz	18, 160(1)
	lwz	19, 164(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 160(1)
	stw	19, 164(1)
	rlwinm	14, 7, 1, 0, 30
	rlwimi	14, 8, 1, 31, 31
	rlwinm	15, 8, 1, 0, 30
	rlwimi	15, 7, 1, 31, 31
	xor	16, 0, 14
	xor	17, 4, 15
	lwz	18, 8(1)
	lwz	19, 12(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 8(1)
	stw	19, 12(1)
	lwz	18, 48(1)
	lwz	19, 52(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 48(1)
	stw	19, 52(1)
	lwz	18, 88(1)
	lwz	19, 92(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 88(1)
	stw	19, 92(1)
	lwz	18, 128(1)
	lwz	19, 132(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 128(1)
	stw	19, 132(1)
	lwz	18, 168(1)
	lwz	19, 172(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 168(1)
	stw	19, 172(1)
	rlwinm	14, 9, 1, 0, 30
	rlwimi	14, 10, 1, 31, 31
	rlwinm	15, 10, 1, 0, 30
	rlwimi	15, 9, 1, 31, 31
	xor	16, 5, 14
	xor	17, 6, 15
	lwz	18, 16(1)
	lwz	19, 20(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 16(1)
	stw	19, 20(1)
	lwz	18, 56(1)
	lwz	19, 60(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 56(1)
	stw	19, 60(1)
	lwz	18, 96(1)
	lwz	19, 100(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 96(1)
	stw	19, 100(1)
	lwz	18, 136(1)
	lwz	19, 140(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 136(1)
	stw	19, 140(1)
	lwz	18, 176(1)
	lwz	19, 180(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 176(1)
	stw	19, 180(1)
	rlwinm	14, 11, 1, 0, 30
	rlwimi	14, 12, 1, 31, 31
	rlwinm	15, 12, 1, 0, 30
	rlwimi	15, 11, 1, 31, 31
	xor	16, 7, 14
	xor	17, 8, 15
	lwz	18, 24(1)
	lwz	19, 28(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 24(1)
	stw	19, 28(1)
	lwz	18, 64(1)
	lwz	19, 68(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 64(1)
	stw	19, 68(1)
	lwz	18, 104(1)
	lwz	19, 108(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 104(1)
	stw	19, 108(1)
	lwz	18, 144(1)
	lwz	19, 148(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 144(1)
	stw	19, 148(1)
	lwz	18, 184(1)
	lwz	19, 188(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 184(1)
	stw	19, 188(1)
	rlwinm	14, 0, 1, 0, 30
	rlwimi	14, 4, 1, 31, 31
	rlwinm	15, 4, 1, 0, 30
	rlwimi	15, 0, 1, 31, 31
	xor	16, 9, 14
	xor	17, 10, 15
	lwz	18, 32(1)
	lwz	19, 36(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 32(1)
	stw	19, 36(1)
	lwz	18, 72(1)
	lwz	19, 76(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 72(1)
	stw	19, 76(1)
	lwz	18, 112(1)
	lwz	19, 116(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 112(1)
	stw	19, 116(1)
	lwz	18, 152(1)
	lwz	19, 156(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 152(1)
	stw	19, 156(1)
	lwz	18, 192(1)
	lwz	19, 196(1)
	xor	18, 18, 16
	xor	19, 19, 17
	stw	18, 192(1)
	stw	19, 196(1)
	# Row Mix
	# Row 0
	lwz	0, 0(1)
	lwz	4, 4(1)
	lwz	14, 48(1)
	lwz	15, 52(1)
	rlwinm	5, 15, 12, 0, 19
	rlwimi	5, 14, 12, 20, 31
	rlwinm	6, 14, 12, 0, 19
	rlwimi	6, 15, 12, 20, 31
	lwz	14, 96(1)
	lwz	15, 100(1)
	rlwinm	7, 15, 11, 0, 20
	rlwimi	7, 14, 11, 21, 31
	rlwinm	8, 14, 11, 0, 20
	rlwimi	8, 15, 11, 21, 31
	lwz	14, 144(1)
	lwz	15, 148(1)
	rlwinm	9, 14, 21, 0, 10
	rlwimi	9, 15, 21, 11, 31
	rlwinm	10, 15, 21, 0, 10
	rlwimi	10, 14, 21, 11, 31
	lwz	14, 192(1)
	lwz	15, 196(1)
	rlwinm	11, 14, 14, 0, 17
	rlwimi	11, 15, 14, 18, 31
	rlwinm	12, 15, 14, 0, 17
	rlwimi	12, 14, 14, 18, 31
	andc	14, 9, 7
	andc	15, 10, 8
	xor	14, 14, 5
	xor	15, 15, 6
	stw	14, 8(3)
	stw	15, 12(3)
	andc	14, 11, 9
	andc	15, 12, 10
	xor	14, 14, 7
	xor	15, 15, 8
	stw	14, 16(3)
	stw	15, 20(3)
	andc	14, 0, 11
	andc	15, 4, 12
	xor	14, 14, 9
	xor	15, 15, 10
	stw	14, 24(3)
	stw	15, 28(3)
	andc	14, 5, 0
	andc	15, 6, 4
	xor	14, 14, 11
	xor	15, 15, 12
	stw	14, 32(3)
	stw	15, 36(3)
	# Get constant
	lwz	11, 0(20)
	lwz	12, 4(20)
	addi	20, 20, 8
	andc	14, 7, 5
	andc	15, 8, 6
	xor	14, 14, 0
	xor	15, 15, 4
	# XOR in constant
	xor	14, 14, 11
	xor	15, 15, 12
	stw	14, 0(3)
	stw	15, 4(3)
	# Row 1
	lwz	14, 24(1)
	lwz	15, 28(1)
	rlwinm	0, 14, 28, 0, 3
	rlwimi	0, 15, 28, 4, 31
	rlwinm	4, 15, 28, 0, 3
	rlwimi	4, 14, 28, 4, 31
	lwz	14, 72(1)
	lwz	15, 76(1)
	rlwinm	5, 14, 20, 0, 11
	rlwimi	5, 15, 20, 12, 31
	rlwinm	6, 15, 20, 0, 11
	rlwimi	6, 14, 20, 12, 31
	lwz	14, 80(1)
	lwz	15, 84(1)
	rlwinm	7, 14, 3, 0, 28
	rlwimi	7, 15, 3, 29, 31
	rlwinm	8, 15, 3, 0, 28
	rlwimi	8, 14, 3, 29, 31
	lwz	14, 128(1)
	lwz	15, 132(1)
	rlwinm	9, 15, 13, 0, 18
	rlwimi	9, 14, 13, 19, 31
	rlwinm	10, 14, 13, 0, 18
	rlwimi	10, 15, 13, 19, 31
	lwz	14, 176(1)
	lwz	15, 180(1)
	rlwinm	11, 15, 29, 0, 2
	rlwimi	11, 14, 29, 3, 31
	rlwinm	12, 14, 29, 0, 2
	rlwimi	12, 15, 29, 3, 31
	andc	14, 9, 7
	andc	15, 10, 8
	xor	14, 14, 5
	xor	15, 15, 6
	stw	14, 48(3)
	stw	15, 52(3)
	andc	14, 11, 9
	andc	15, 12, 10
	xor	14, 14, 7
	xor	15, 15, 8
	stw	14, 56(3)
	stw	15, 60(3)
	andc	14, 0, 11
	andc	15, 4, 12
	xor	14, 14, 9
	xor	15, 15, 10
	stw	14, 64(3)
	stw	15, 68(3)
	andc	14, 5, 0
	andc	15, 6, 4
	xor	14, 14, 11
	xor	15, 15, 12
	stw	14, 72(3)
	stw	15, 76(3)
	andc	14, 7, 5
	andc	15, 8, 6
	xor	14, 14, 0
	xor	15, 15, 4
	stw	14, 40(3)
	stw	15, 44(3)
	# Row 2
	lwz	14, 8(1)
	lwz	15, 12(1)
	rlwinm	0, 14, 1, 0, 30
	rlwimi	0, 15, 1, 31, 31
	rlwinm	4, 15, 1, 0, 30
	rlwimi	4, 14, 1, 31, 31
	lwz	14, 56(1)
	lwz	15, 60(1)
	rlwinm	5, 14, 6, 0, 25
	rlwimi	5, 15, 6, 26, 31
	rlwinm	6, 15, 6, 0, 25
	rlwimi	6, 14, 6, 26, 31
	lwz	14, 104(1)
	lwz	15, 108(1)
	rlwinm	7, 14, 25, 0, 6
	rlwimi	7, 15, 25, 7, 31
	rlwinm	8, 15, 25, 0, 6
	rlwimi	8, 14, 25, 7, 31
	lwz	14, 152(1)
	lwz	15, 156(1)
	rlwinm	9, 14, 8, 0, 23
	rlwimi	9, 15, 8, 24, 31
	rlwinm	10, 15, 8, 0, 23
	rlwimi	10, 14, 8, 24, 31
	lwz	14, 160(1)
	lwz	15, 164(1)
	rlwinm	11, 14, 18, 0, 13
	rlwimi	11, 15, 18, 14, 31
	rlwinm	12, 15, 18, 0, 13
	rlwimi	12, 14, 18, 14, 31
	andc	14, 9, 7
	andc	15, 10, 8
	xor	14, 14, 5
	xor	15, 15, 6
	stw	14, 88(3)
	stw	15, 92(3)
	andc	14, 11, 9
	andc	15, 12, 10
	xor	14, 14, 7
	xor	15, 15, 8
	stw	14, 96(3)
	stw	15, 100(3)
	andc	14, 0, 11
	andc	15, 4, 12
	xor	14, 14, 9
	xor	15, 15, 10
	stw	14, 104(3)
	stw	15, 108(3)
	andc	14, 5, 0
	andc	15, 6, 4
	xor	14, 14, 11
	xor	15, 15, 12
	stw	14, 112(3)
	stw	15, 116(3)
	andc	14, 7, 5
	andc	15, 8, 6
	xor	14, 14, 0
	xor	15, 15, 4
	stw	14, 80(3)
	stw	15, 84(3)
	# Row 3
	lwz	14, 32(1)
	lwz	15, 36(1)
	rlwinm	0, 14, 27, 0, 4
	rlwimi	0, 15, 27, 5, 31
	rlwinm	4, 15, 27, 0, 4
	rlwimi	4, 14, 27, 5, 31
	lwz	14, 40(1)
	lwz	15, 44(1)
	rlwinm	5, 15, 4, 0, 27
	rlwimi	5, 14, 4, 28, 31
	rlwinm	6, 14, 4, 0, 27
	rlwimi	6, 15, 4, 28, 31
	lwz	14, 88(1)
	lwz	15, 92(1)
	rlwinm	7, 14, 10, 0, 21
	rlwimi	7, 15, 10, 22, 31
	rlwinm	8, 15, 10, 0, 21
	rlwimi	8, 14, 10, 22, 31
	lwz	14, 136(1)
	lwz	15, 140(1)
	rlwinm	9, 14, 15, 0, 16
	rlwimi	9, 15, 15, 17, 31
	rlwinm	10, 15, 15, 0, 16
	rlwimi	10, 14, 15, 17, 31
	lwz	14, 184(1)
	lwz	15, 188(1)
	rlwinm	11, 15, 24, 0, 7
	rlwimi	11, 14, 24, 8, 31
	rlwinm	12, 14, 24, 0, 7
	rlwimi	12, 15, 24, 8, 31
	andc	14, 9, 7
	andc	15, 10, 8
	xor	14, 14, 5
	xor	15, 15, 6
	stw	14, 128(3)
	stw	15, 132(3)
	andc	14, 11, 9
	andc	15, 12, 10
	xor	14, 14, 7
	xor	15, 15, 8
	stw	14, 136(3)
	stw	15, 140(3)
	andc	14, 0, 11
	andc	15, 4, 12
	xor	14, 14, 9
	xor	15, 15, 10
	stw	14, 144(3)
	stw	15, 148(3)
	andc	14, 5, 0
	andc	15, 6, 4
	xor	14, 14, 11
	xor	15, 15, 12
	stw	14, 152(3)
	stw	15, 156(3)
	andc	14, 7, 5
	andc	15, 8, 6
	xor	14, 14, 0
	xor	15, 15, 4
	stw	14, 120(3)
	stw	15, 124(3)
	# Row 4
	lwz	14, 16(1)
	lwz	15, 20(1)
	rlwinm	0, 15, 30, 0, 1
	rlwimi	0, 14, 30, 2, 31
	rlwinm	4, 14, 30, 0, 1
	rlwimi	4, 15, 30, 2, 31
	lwz	14, 64(1)
	lwz	15, 68(1)
	rlwinm	5, 15, 23, 0, 8
	rlwimi	5, 14, 23, 9, 31
	rlwinm	6, 14, 23, 0, 8
	rlwimi	6, 15, 23, 9, 31
	lwz	14, 112(1)
	lwz	15, 116(1)
	rlwinm	7, 15, 7, 0, 24
	rlwimi	7, 14, 7, 25, 31
	rlwinm	8, 14, 7, 0, 24
	rlwimi	8, 15, 7, 25, 31
	lwz	14, 120(1)
	lwz	15, 124(1)
	rlwinm	9, 15, 9, 0, 22
	rlwimi	9, 14, 9, 23, 31
	rlwinm	10, 14, 9, 0, 22
	rlwimi	10, 15, 9, 23, 31
	lwz	14, 168(1)
	lwz	15, 172(1)
	rlwinm	11, 14, 2, 0, 29
	rlwimi	11, 15, 2, 30, 31
	rlwinm	12, 15, 2, 0, 29
	rlwimi	12, 14, 2, 30, 31
	andc	14, 9, 7
	andc	15, 10, 8
	xor	14, 14, 5
	xor	15, 15, 6
	stw	14, 168(3)
	stw	15, 172(3)
	andc	14, 11, 9
	andc	15, 12, 10
	xor	14, 14, 7
	xor	15, 15, 8
	stw	14, 176(3)
	stw	15, 180(3)
	andc	14, 0, 11
	andc	15, 4, 12
	xor	14, 14, 9
	xor	15, 15, 10
	stw	14, 184(3)
	stw	15, 188(3)
	andc	14, 5, 0
	andc	15, 6, 4
	xor	14, 14, 11
	xor	15, 15, 12
	stw	14, 192(3)
	stw	15, 196(3)
	andc	14, 7, 5
	andc	15, 8, 6
	xor	14, 14, 0
	xor	15, 15, 4
	stw	14, 160(3)
	stw	15, 164(3)
	bdnz	L_sha3_ppc32_begin
	addi	1, 1, 0xd0
	lwz	0, 28(1)
	mtlr	0
	lwz	14, 0(1)
	lwz	15, 4(1)
	lwz	16, 8(1)
	lwz	17, 12(1)
	lwz	18, 16(1)
	lwz	19, 20(1)
	lwz	20, 24(1)
	addi	1, 1, 32
	blr
	.size	BlockSha3,.-BlockSha3
#endif /* WOLFSSL_SHA3 && WOLFSSL_PPC32_ASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_PPC32_ASM_INLINE */
#endif /* WOLFSSL_PPC32_ASM */
