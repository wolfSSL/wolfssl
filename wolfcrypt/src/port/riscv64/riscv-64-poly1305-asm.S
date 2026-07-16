/* riscv-64-poly1305-asm
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

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

/* Generated using (from wolfssl):
 *   cd ../scripts
 *   ruby ./poly1305/poly1305.rb riscv64 \
 *       ../wolfssl/wolfcrypt/src/port/riscv64/riscv-64-poly1305-asm.S
 */
#ifdef WOLFSSL_RISCV_ASM
#ifndef WOLFSSL_RISCV_ASM_INLINE
#ifdef HAVE_POLY1305
	.text
	.globl	poly1305_set_key_riscv64
	.type	poly1305_set_key_riscv64,@function
	.align	2
poly1305_set_key_riscv64:
	# r &= 0xffffffc0ffffffc0ffffffc0fffffff (split into 44-bit limbs)
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	t0, 0(a1)
#else
	andi	t3, a1, 7
	bnez	t3, L_ualn_ld1_w
	ld	t0, 0(a1)
	j	L_ualn_ld1_e
L_ualn_ld1_w:
	andi	t3, t3, 3
	bnez	t3, L_ualn_ld1_h
	lwu	t0, 0(a1)
	lwu	t3, 4(a1)
	slli	t3, t3, 32
	or	t0, t0, t3
	j	L_ualn_ld1_e
L_ualn_ld1_h:
	andi	t3, t3, 1
	bnez	t3, L_ualn_ld1_b
	lhu	t0, 0(a1)
	lhu	t3, 2(a1)
	slli	t3, t3, 16
	or	t0, t0, t3
	lhu	t3, 4(a1)
	slli	t3, t3, 32
	or	t0, t0, t3
	lhu	t3, 6(a1)
	slli	t3, t3, 48
	or	t0, t0, t3
	j	L_ualn_ld1_e
L_ualn_ld1_b:
	lbu	t0, 0(a1)
	lbu	t3, 1(a1)
	slli	t3, t3, 8
	or	t0, t0, t3
	lbu	t3, 2(a1)
	slli	t3, t3, 16
	or	t0, t0, t3
	lbu	t3, 3(a1)
	slli	t3, t3, 24
	or	t0, t0, t3
	lbu	t3, 4(a1)
	slli	t3, t3, 32
	or	t0, t0, t3
	lbu	t3, 5(a1)
	slli	t3, t3, 40
	or	t0, t0, t3
	lbu	t3, 6(a1)
	slli	t3, t3, 48
	or	t0, t0, t3
	lbu	t3, 7(a1)
	slli	t3, t3, 56
	or	t0, t0, t3
L_ualn_ld1_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	t1, 8(a1)
#else
	andi	t3, a1, 7
	bnez	t3, L_ualn_ld2_w
	ld	t1, 8(a1)
	j	L_ualn_ld2_e
L_ualn_ld2_w:
	andi	t3, t3, 3
	bnez	t3, L_ualn_ld2_h
	lwu	t1, 8(a1)
	lwu	t3, 12(a1)
	slli	t3, t3, 32
	or	t1, t1, t3
	j	L_ualn_ld2_e
L_ualn_ld2_h:
	andi	t3, t3, 1
	bnez	t3, L_ualn_ld2_b
	lhu	t1, 8(a1)
	lhu	t3, 10(a1)
	slli	t3, t3, 16
	or	t1, t1, t3
	lhu	t3, 12(a1)
	slli	t3, t3, 32
	or	t1, t1, t3
	lhu	t3, 14(a1)
	slli	t3, t3, 48
	or	t1, t1, t3
	j	L_ualn_ld2_e
L_ualn_ld2_b:
	lbu	t1, 8(a1)
	lbu	t3, 9(a1)
	slli	t3, t3, 8
	or	t1, t1, t3
	lbu	t3, 10(a1)
	slli	t3, t3, 16
	or	t1, t1, t3
	lbu	t3, 11(a1)
	slli	t3, t3, 24
	or	t1, t1, t3
	lbu	t3, 12(a1)
	slli	t3, t3, 32
	or	t1, t1, t3
	lbu	t3, 13(a1)
	slli	t3, t3, 40
	or	t1, t1, t3
	lbu	t3, 14(a1)
	slli	t3, t3, 48
	or	t1, t1, t3
	lbu	t3, 15(a1)
	slli	t3, t3, 56
	or	t1, t1, t3
L_ualn_ld2_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	li	t4, 17575274610687
	and	t2, t0, t4
	sd	t2, 0(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t2, t1, t0, 44
	.word	0x2ec353b3
#else
	srli	t2, t0, 44
	slli	t3, t1, 20
	or	t2, t2, t3
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	li	t4, 17592181915647
	and	t2, t2, t4
	sd	t2, 8(a0)
	srli	t2, t1, 24
	li	t4, 68719475727
	and	t2, t2, t4
	sd	t2, 16(a0)
	# h = 0
	sd	zero, 24(a0)
	sd	zero, 32(a0)
	sd	zero, 40(a0)
	# save pad = key[16..31]
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	t0, 16(a1)
#else
	andi	t3, a1, 7
	bnez	t3, L_ualn_ld3_w
	ld	t0, 16(a1)
	j	L_ualn_ld3_e
L_ualn_ld3_w:
	andi	t3, t3, 3
	bnez	t3, L_ualn_ld3_h
	lwu	t0, 16(a1)
	lwu	t3, 20(a1)
	slli	t3, t3, 32
	or	t0, t0, t3
	j	L_ualn_ld3_e
L_ualn_ld3_h:
	andi	t3, t3, 1
	bnez	t3, L_ualn_ld3_b
	lhu	t0, 16(a1)
	lhu	t3, 18(a1)
	slli	t3, t3, 16
	or	t0, t0, t3
	lhu	t3, 20(a1)
	slli	t3, t3, 32
	or	t0, t0, t3
	lhu	t3, 22(a1)
	slli	t3, t3, 48
	or	t0, t0, t3
	j	L_ualn_ld3_e
L_ualn_ld3_b:
	lbu	t0, 16(a1)
	lbu	t3, 17(a1)
	slli	t3, t3, 8
	or	t0, t0, t3
	lbu	t3, 18(a1)
	slli	t3, t3, 16
	or	t0, t0, t3
	lbu	t3, 19(a1)
	slli	t3, t3, 24
	or	t0, t0, t3
	lbu	t3, 20(a1)
	slli	t3, t3, 32
	or	t0, t0, t3
	lbu	t3, 21(a1)
	slli	t3, t3, 40
	or	t0, t0, t3
	lbu	t3, 22(a1)
	slli	t3, t3, 48
	or	t0, t0, t3
	lbu	t3, 23(a1)
	slli	t3, t3, 56
	or	t0, t0, t3
L_ualn_ld3_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	t1, 24(a1)
#else
	andi	t3, a1, 7
	bnez	t3, L_ualn_ld4_w
	ld	t1, 24(a1)
	j	L_ualn_ld4_e
L_ualn_ld4_w:
	andi	t3, t3, 3
	bnez	t3, L_ualn_ld4_h
	lwu	t1, 24(a1)
	lwu	t3, 28(a1)
	slli	t3, t3, 32
	or	t1, t1, t3
	j	L_ualn_ld4_e
L_ualn_ld4_h:
	andi	t3, t3, 1
	bnez	t3, L_ualn_ld4_b
	lhu	t1, 24(a1)
	lhu	t3, 26(a1)
	slli	t3, t3, 16
	or	t1, t1, t3
	lhu	t3, 28(a1)
	slli	t3, t3, 32
	or	t1, t1, t3
	lhu	t3, 30(a1)
	slli	t3, t3, 48
	or	t1, t1, t3
	j	L_ualn_ld4_e
L_ualn_ld4_b:
	lbu	t1, 24(a1)
	lbu	t3, 25(a1)
	slli	t3, t3, 8
	or	t1, t1, t3
	lbu	t3, 26(a1)
	slli	t3, t3, 16
	or	t1, t1, t3
	lbu	t3, 27(a1)
	slli	t3, t3, 24
	or	t1, t1, t3
	lbu	t3, 28(a1)
	slli	t3, t3, 32
	or	t1, t1, t3
	lbu	t3, 29(a1)
	slli	t3, t3, 40
	or	t1, t1, t3
	lbu	t3, 30(a1)
	slli	t3, t3, 48
	or	t1, t1, t3
	lbu	t3, 31(a1)
	slli	t3, t3, 56
	or	t1, t1, t3
L_ualn_ld4_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	sd	t0, 48(a0)
	sd	t1, 56(a0)
	# leftover = 0; finished = 0
	sd	zero, 64(a0)
	sb	zero, 88(a0)
#ifdef WOLFSSL_RISCV_VECTOR
	# Powers of r are computed lazily by the blocks path (size-aware), so
	# a small message never pays for the r^2/r^3/r^4 setup: level = 0.
	sb	zero, 288(a0)
#endif /* WOLFSSL_RISCV_VECTOR */
	ret
	.size	poly1305_set_key_riscv64,.-poly1305_set_key_riscv64
	.text
	.globl	poly1305_block_16_riscv64
	.type	poly1305_block_16_riscv64,@function
	.align	2
poly1305_block_16_riscv64:
	addi	sp, sp, -80
	sd	s1, 8(sp)
	sd	s2, 16(sp)
	sd	s3, 24(sp)
	sd	s4, 32(sp)
	sd	s5, 40(sp)
	sd	s6, 48(sp)
	sd	s7, 56(sp)
	sd	s8, 64(sp)
	sd	s9, 72(sp)
	# Load r, h and compute s1=r1*20, s2=r2*20
	ld	t0, 0(a0)
	ld	t1, 8(a0)
	ld	t2, 16(a0)
	ld	t5, 24(a0)
	ld	t6, 32(a0)
	ld	a2, 40(a0)
	li	a6, 20
	mul	t3, t1, a6
	mul	t4, t2, a6
	li	a3, 17592186044415
	srli	a4, a3, 2
	# hibit = finished ? 0 : (1 << 40)
	lbu	a6, 88(a0)
	li	a5, 1099511627776
	seqz	a6, a6
	neg	a6, a6
	and	a5, a5, a6
	# Add message block into h (split 44,44,42)
	ld	s2, 0(a1)
	ld	s3, 8(a1)
	and	a6, s2, a3
	add	t5, t5, a6
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri a6, s3, s2, 44
	.word	0x96c9d833
#else
	srli	a6, s2, 44
	slli	a7, s3, 20
	or	a6, a6, a7
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	a6, a6, a3
	add	t6, t6, a6
	srli	a6, s3, 24
	and	a6, a6, a4
	or	a6, a6, a5
	add	a2, a2, a6
	# d0 = h0*r0 + h1*s2 + h2*s1
	mul	s4, t5, t0
	mulhu	s5, t5, t0
	mul	a6, t6, t4
	mulhu	a7, t6, t4
	add	s4, s4, a6
	sltu	s1, s4, a6
	add	s5, s5, a7
	add	s5, s5, s1
	mul	a6, a2, t3
	mulhu	a7, a2, t3
	add	s4, s4, a6
	sltu	s1, s4, a6
	add	s5, s5, a7
	add	s5, s5, s1
	# d1 = h0*r1 + h1*r0 + h2*s2
	mul	s6, t5, t1
	mulhu	s7, t5, t1
	mul	a6, t6, t0
	mulhu	a7, t6, t0
	add	s6, s6, a6
	sltu	s1, s6, a6
	add	s7, s7, a7
	add	s7, s7, s1
	mul	a6, a2, t4
	mulhu	a7, a2, t4
	add	s6, s6, a6
	sltu	s1, s6, a6
	add	s7, s7, a7
	add	s7, s7, s1
	# d2 = h0*r2 + h1*r1 + h2*r0
	mul	s8, t5, t2
	mulhu	s9, t5, t2
	mul	a6, t6, t1
	mulhu	a7, t6, t1
	add	s8, s8, a6
	sltu	s1, s8, a6
	add	s9, s9, a7
	add	s9, s9, s1
	mul	a6, a2, t0
	mulhu	a7, a2, t0
	add	s8, s8, a6
	sltu	s1, s8, a6
	add	s9, s9, a7
	add	s9, s9, s1
	# Reduce: carry chain across 44/44/42-bit limbs
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri s1, s5, s4, 44
	.word	0xa6cad4b3
#else
	srli	s1, s4, 44
	slli	a6, s5, 20
	or	s1, s1, a6
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	t5, s4, a3
	add	s6, s6, s1
	sltu	a6, s6, s1
	add	s7, s7, a6
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri s1, s7, s6, 44
	.word	0xb6cbd4b3
#else
	srli	s1, s6, 44
	slli	a6, s7, 20
	or	s1, s1, a6
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	t6, s6, a3
	add	s8, s8, s1
	sltu	a6, s8, s1
	add	s9, s9, a6
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri s1, s9, s8, 42
	.word	0xc6acd4b3
#else
	srli	s1, s8, 42
	slli	a6, s9, 22
	or	s1, s1, a6
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	a2, s8, a4
	slli	a6, s1, 2
	add	s1, s1, a6
	add	t5, t5, s1
	srli	s1, t5, 44
	and	t5, t5, a3
	add	t6, t6, s1
	# Store h back
	sd	t5, 24(a0)
	sd	t6, 32(a0)
	sd	a2, 40(a0)
	ld	s1, 8(sp)
	ld	s2, 16(sp)
	ld	s3, 24(sp)
	ld	s4, 32(sp)
	ld	s5, 40(sp)
	ld	s6, 48(sp)
	ld	s7, 56(sp)
	ld	s8, 64(sp)
	ld	s9, 72(sp)
	addi	sp, sp, 80
	ret
	.size	poly1305_block_16_riscv64,.-poly1305_block_16_riscv64
	.text
	.globl	poly1305_blocks_riscv64
	.type	poly1305_blocks_riscv64,@function
	.align	2
poly1305_blocks_riscv64:
	addi	sp, sp, -96
	sd	s1, 8(sp)
	sd	s2, 16(sp)
	sd	s3, 24(sp)
	sd	s4, 32(sp)
	sd	s5, 40(sp)
	sd	s6, 48(sp)
	sd	s7, 56(sp)
	sd	s8, 64(sp)
	sd	s9, 72(sp)
	sd	s10, 80(sp)
	sd	s11, 88(sp)
	# Nothing to do when less than a block
	li	t0, 16
	bltu	a2, t0, L_poly1305_riscv64_blocks_done
	# Load r, h and compute s1=r1*5*4, s2=r2*5*4
	ld	s1, 0(a0)
	ld	s2, 8(a0)
	ld	s3, 16(a0)
	ld	s6, 24(a0)
	ld	s7, 32(a0)
	ld	s8, 40(a0)
	li	t0, 20
	mul	s4, s2, t0
	mul	s5, s3, t0
	li	s9, 17592186044415
	srli	s10, s9, 2
	# hibit = finished ? 0 : (1 << 40)
	lbu	t0, 88(a0)
	li	s11, 1099511627776
	seqz	t0, t0
	neg	t0, t0
	and	s11, s11, t0
#ifdef WOLFSSL_RISCV_VECTOR
	.option arch, +v
	# Lane-staging scratch (96 bytes); gated in the vector path so the
	# base/scalar prologue is unchanged.
	addi	sp, sp, -96
	# Vectorized 8-block path: h <- (h+m0)r^8 + m1*r^7 + ... + m7*r
	li	t0, 128
	bltu	a2, t0, L_poly1305_riscv64_blocks_v8skip
	lbu	t0, 288(a0)
	li	t1, 3
	bge	t0, t1, L_poly1305_riscv64_have_r58
	li	t1, 2
	bge	t0, t1, L_poly1305_riscv64_r58_have_r4
	li	t1, 1
	bge	t0, t1, L_poly1305_riscv64_r58_have_r2
	ld	t0, 0(a0)
	sd	t0, 168(a0)
	ld	t0, 8(a0)
	sd	t0, 176(a0)
	ld	t0, 16(a0)
	sd	t0, 184(a0)
	li	t2, 20
	ld	t0, 8(a0)
	mul	a6, t0, t2
	ld	t0, 16(a0)
	mul	a7, t0, t2
	li	t5, 17592186044415
	# d0 = a0*b0 + a1*s2 + a2*s1 ; o0 = d0 & m44 ; cc = d0 >> 44
	ld	t0, 0(a0)
	ld	t1, 0(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 8(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 16(a0)
	mul	a4, t0, a6
	mulhu	a5, t0, a6
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	and	t2, t6, t5
	sd	t2, 144(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d1 = a0*b1 + a1*b0 + a2*s2 (+cc) ; o1 = d1 & m44 ; cc = d1 >> 44
	ld	t0, 0(a0)
	ld	t1, 8(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 8(a0)
	ld	t1, 0(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 16(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	and	t2, t6, t5
	sd	t2, 152(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d2 = a0*b2 + a1*b1 + a2*b0 (+cc) ; o2 = d2 & m42 ; cc = d2 >> 42
	ld	t0, 0(a0)
	ld	t1, 16(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 8(a0)
	ld	t1, 8(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 16(a0)
	ld	t1, 0(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	srli	t5, t5, 2
	and	a6, t6, t5
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 42
	.word	0xfea6deb3
#else
	srli	t4, t6, 42
	slli	a4, a3, 22
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# fold top carry: o0 += cc*5 ; propagate into o1
	slli	a4, t4, 2
	add	t4, t4, a4
	li	t5, 17592186044415
	ld	a4, 144(a0)
	add	a4, a4, t4
	srli	a5, a4, 44
	and	a4, a4, t5
	sd	a4, 144(a0)
	ld	a4, 152(a0)
	add	a4, a4, a5
	sd	a4, 152(a0)
	sd	a6, 160(a0)
L_poly1305_riscv64_r58_have_r2:
	li	t2, 20
	ld	t0, 8(a0)
	mul	a6, t0, t2
	ld	t0, 16(a0)
	mul	a7, t0, t2
	li	t5, 17592186044415
	# d0 = a0*b0 + a1*s2 + a2*s1 ; o0 = d0 & m44 ; cc = d0 >> 44
	ld	t0, 144(a0)
	ld	t1, 0(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 152(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 160(a0)
	mul	a4, t0, a6
	mulhu	a5, t0, a6
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	and	t2, t6, t5
	sd	t2, 120(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d1 = a0*b1 + a1*b0 + a2*s2 (+cc) ; o1 = d1 & m44 ; cc = d1 >> 44
	ld	t0, 144(a0)
	ld	t1, 8(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 152(a0)
	ld	t1, 0(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 160(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	and	t2, t6, t5
	sd	t2, 128(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d2 = a0*b2 + a1*b1 + a2*b0 (+cc) ; o2 = d2 & m42 ; cc = d2 >> 42
	ld	t0, 144(a0)
	ld	t1, 16(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 152(a0)
	ld	t1, 8(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 160(a0)
	ld	t1, 0(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	srli	t5, t5, 2
	and	a6, t6, t5
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 42
	.word	0xfea6deb3
#else
	srli	t4, t6, 42
	slli	a4, a3, 22
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# fold top carry: o0 += cc*5 ; propagate into o1
	slli	a4, t4, 2
	add	t4, t4, a4
	li	t5, 17592186044415
	ld	a4, 120(a0)
	add	a4, a4, t4
	srli	a5, a4, 44
	and	a4, a4, t5
	sd	a4, 120(a0)
	ld	a4, 128(a0)
	add	a4, a4, a5
	sd	a4, 128(a0)
	sd	a6, 136(a0)
	li	t2, 20
	ld	t0, 152(a0)
	mul	a6, t0, t2
	ld	t0, 160(a0)
	mul	a7, t0, t2
	li	t5, 17592186044415
	# d0 = a0*b0 + a1*s2 + a2*s1 ; o0 = d0 & m44 ; cc = d0 >> 44
	ld	t0, 144(a0)
	ld	t1, 144(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 152(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 160(a0)
	mul	a4, t0, a6
	mulhu	a5, t0, a6
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	and	t2, t6, t5
	sd	t2, 96(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d1 = a0*b1 + a1*b0 + a2*s2 (+cc) ; o1 = d1 & m44 ; cc = d1 >> 44
	ld	t0, 144(a0)
	ld	t1, 152(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 152(a0)
	ld	t1, 144(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 160(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	and	t2, t6, t5
	sd	t2, 104(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d2 = a0*b2 + a1*b1 + a2*b0 (+cc) ; o2 = d2 & m42 ; cc = d2 >> 42
	ld	t0, 144(a0)
	ld	t1, 160(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 152(a0)
	ld	t1, 152(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 160(a0)
	ld	t1, 144(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	srli	t5, t5, 2
	and	a6, t6, t5
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 42
	.word	0xfea6deb3
#else
	srli	t4, t6, 42
	slli	a4, a3, 22
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# fold top carry: o0 += cc*5 ; propagate into o1
	slli	a4, t4, 2
	add	t4, t4, a4
	li	t5, 17592186044415
	ld	a4, 96(a0)
	add	a4, a4, t4
	srli	a5, a4, 44
	and	a4, a4, t5
	sd	a4, 96(a0)
	ld	a4, 104(a0)
	add	a4, a4, a5
	sd	a4, 104(a0)
	sd	a6, 112(a0)
L_poly1305_riscv64_r58_have_r4:
	li	t2, 20
	ld	t0, 176(a0)
	mul	a6, t0, t2
	ld	t0, 184(a0)
	mul	a7, t0, t2
	li	t5, 17592186044415
	# d0 = a0*b0 + a1*s2 + a2*s1 ; o0 = d0 & m44 ; cc = d0 >> 44
	ld	t0, 96(a0)
	ld	t1, 168(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 104(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 112(a0)
	mul	a4, t0, a6
	mulhu	a5, t0, a6
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	and	t2, t6, t5
	sd	t2, 264(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d1 = a0*b1 + a1*b0 + a2*s2 (+cc) ; o1 = d1 & m44 ; cc = d1 >> 44
	ld	t0, 96(a0)
	ld	t1, 176(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 104(a0)
	ld	t1, 168(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 112(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	and	t2, t6, t5
	sd	t2, 272(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d2 = a0*b2 + a1*b1 + a2*b0 (+cc) ; o2 = d2 & m42 ; cc = d2 >> 42
	ld	t0, 96(a0)
	ld	t1, 184(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 104(a0)
	ld	t1, 176(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 112(a0)
	ld	t1, 168(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	srli	t5, t5, 2
	and	a6, t6, t5
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 42
	.word	0xfea6deb3
#else
	srli	t4, t6, 42
	slli	a4, a3, 22
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# fold top carry: o0 += cc*5 ; propagate into o1
	slli	a4, t4, 2
	add	t4, t4, a4
	li	t5, 17592186044415
	ld	a4, 264(a0)
	add	a4, a4, t4
	srli	a5, a4, 44
	and	a4, a4, t5
	sd	a4, 264(a0)
	ld	a4, 272(a0)
	add	a4, a4, a5
	sd	a4, 272(a0)
	sd	a6, 280(a0)
	li	t2, 20
	ld	t0, 152(a0)
	mul	a6, t0, t2
	ld	t0, 160(a0)
	mul	a7, t0, t2
	li	t5, 17592186044415
	# d0 = a0*b0 + a1*s2 + a2*s1 ; o0 = d0 & m44 ; cc = d0 >> 44
	ld	t0, 96(a0)
	ld	t1, 144(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 104(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 112(a0)
	mul	a4, t0, a6
	mulhu	a5, t0, a6
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	and	t2, t6, t5
	sd	t2, 240(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d1 = a0*b1 + a1*b0 + a2*s2 (+cc) ; o1 = d1 & m44 ; cc = d1 >> 44
	ld	t0, 96(a0)
	ld	t1, 152(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 104(a0)
	ld	t1, 144(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 112(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	and	t2, t6, t5
	sd	t2, 248(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d2 = a0*b2 + a1*b1 + a2*b0 (+cc) ; o2 = d2 & m42 ; cc = d2 >> 42
	ld	t0, 96(a0)
	ld	t1, 160(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 104(a0)
	ld	t1, 152(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 112(a0)
	ld	t1, 144(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	srli	t5, t5, 2
	and	a6, t6, t5
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 42
	.word	0xfea6deb3
#else
	srli	t4, t6, 42
	slli	a4, a3, 22
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# fold top carry: o0 += cc*5 ; propagate into o1
	slli	a4, t4, 2
	add	t4, t4, a4
	li	t5, 17592186044415
	ld	a4, 240(a0)
	add	a4, a4, t4
	srli	a5, a4, 44
	and	a4, a4, t5
	sd	a4, 240(a0)
	ld	a4, 248(a0)
	add	a4, a4, a5
	sd	a4, 248(a0)
	sd	a6, 256(a0)
	li	t2, 20
	ld	t0, 128(a0)
	mul	a6, t0, t2
	ld	t0, 136(a0)
	mul	a7, t0, t2
	li	t5, 17592186044415
	# d0 = a0*b0 + a1*s2 + a2*s1 ; o0 = d0 & m44 ; cc = d0 >> 44
	ld	t0, 96(a0)
	ld	t1, 120(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 104(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 112(a0)
	mul	a4, t0, a6
	mulhu	a5, t0, a6
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	and	t2, t6, t5
	sd	t2, 216(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d1 = a0*b1 + a1*b0 + a2*s2 (+cc) ; o1 = d1 & m44 ; cc = d1 >> 44
	ld	t0, 96(a0)
	ld	t1, 128(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 104(a0)
	ld	t1, 120(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 112(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	and	t2, t6, t5
	sd	t2, 224(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d2 = a0*b2 + a1*b1 + a2*b0 (+cc) ; o2 = d2 & m42 ; cc = d2 >> 42
	ld	t0, 96(a0)
	ld	t1, 136(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 104(a0)
	ld	t1, 128(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 112(a0)
	ld	t1, 120(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	srli	t5, t5, 2
	and	a6, t6, t5
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 42
	.word	0xfea6deb3
#else
	srli	t4, t6, 42
	slli	a4, a3, 22
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# fold top carry: o0 += cc*5 ; propagate into o1
	slli	a4, t4, 2
	add	t4, t4, a4
	li	t5, 17592186044415
	ld	a4, 216(a0)
	add	a4, a4, t4
	srli	a5, a4, 44
	and	a4, a4, t5
	sd	a4, 216(a0)
	ld	a4, 224(a0)
	add	a4, a4, a5
	sd	a4, 224(a0)
	sd	a6, 232(a0)
	li	t2, 20
	ld	t0, 104(a0)
	mul	a6, t0, t2
	ld	t0, 112(a0)
	mul	a7, t0, t2
	li	t5, 17592186044415
	# d0 = a0*b0 + a1*s2 + a2*s1 ; o0 = d0 & m44 ; cc = d0 >> 44
	ld	t0, 96(a0)
	ld	t1, 96(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 104(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 112(a0)
	mul	a4, t0, a6
	mulhu	a5, t0, a6
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	and	t2, t6, t5
	sd	t2, 192(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d1 = a0*b1 + a1*b0 + a2*s2 (+cc) ; o1 = d1 & m44 ; cc = d1 >> 44
	ld	t0, 96(a0)
	ld	t1, 104(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 104(a0)
	ld	t1, 96(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 112(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	and	t2, t6, t5
	sd	t2, 200(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d2 = a0*b2 + a1*b1 + a2*b0 (+cc) ; o2 = d2 & m42 ; cc = d2 >> 42
	ld	t0, 96(a0)
	ld	t1, 112(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 104(a0)
	ld	t1, 104(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 112(a0)
	ld	t1, 96(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	srli	t5, t5, 2
	and	a6, t6, t5
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 42
	.word	0xfea6deb3
#else
	srli	t4, t6, 42
	slli	a4, a3, 22
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# fold top carry: o0 += cc*5 ; propagate into o1
	slli	a4, t4, 2
	add	t4, t4, a4
	li	t5, 17592186044415
	ld	a4, 192(a0)
	add	a4, a4, t4
	srli	a5, a4, 44
	and	a4, a4, t5
	sd	a4, 192(a0)
	ld	a4, 200(a0)
	add	a4, a4, a5
	sd	a4, 200(a0)
	sd	a6, 208(a0)
	li	t0, 3
	sb	t0, 288(a0)
L_poly1305_riscv64_have_r58:
L_poly1305_riscv64_blocks_v8loop:
	li	a7, 20
	vsetivli	zero, 4, e64, m2, ta, ma
	li	a6, 24
	addi	t0, a0, 192
		vlse64.v	v20, (t0), a6
	addi	t0, a0, 200
		vlse64.v	v22, (t0), a6
	addi	t0, a0, 208
		vlse64.v	v24, (t0), a6
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a5, 0(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld5_w
	ld	a5, 0(a1)
	j	L_ualn_ld5_e
L_ualn_ld5_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld5_h
	lwu	a5, 0(a1)
	lwu	t0, 4(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	j	L_ualn_ld5_e
L_ualn_ld5_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld5_b
	lhu	a5, 0(a1)
	lhu	t0, 2(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lhu	t0, 4(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lhu	t0, 6(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	j	L_ualn_ld5_e
L_ualn_ld5_b:
	lbu	a5, 0(a1)
	lbu	t0, 1(a1)
	slli	t0, t0, 8
	or	a5, a5, t0
	lbu	t0, 2(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lbu	t0, 3(a1)
	slli	t0, t0, 24
	or	a5, a5, t0
	lbu	t0, 4(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lbu	t0, 5(a1)
	slli	t0, t0, 40
	or	a5, a5, t0
	lbu	t0, 6(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	lbu	t0, 7(a1)
	slli	t0, t0, 56
	or	a5, a5, t0
L_ualn_ld5_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a6, 8(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld6_w
	ld	a6, 8(a1)
	j	L_ualn_ld6_e
L_ualn_ld6_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld6_h
	lwu	a6, 8(a1)
	lwu	t0, 12(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	j	L_ualn_ld6_e
L_ualn_ld6_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld6_b
	lhu	a6, 8(a1)
	lhu	t0, 10(a1)
	slli	t0, t0, 16
	or	a6, a6, t0
	lhu	t0, 12(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	lhu	t0, 14(a1)
	slli	t0, t0, 48
	or	a6, a6, t0
	j	L_ualn_ld6_e
L_ualn_ld6_b:
	lbu	a6, 8(a1)
	lbu	t0, 9(a1)
	slli	t0, t0, 8
	or	a6, a6, t0
	lbu	t0, 10(a1)
	slli	t0, t0, 16
	or	a6, a6, t0
	lbu	t0, 11(a1)
	slli	t0, t0, 24
	or	a6, a6, t0
	lbu	t0, 12(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	lbu	t0, 13(a1)
	slli	t0, t0, 40
	or	a6, a6, t0
	lbu	t0, 14(a1)
	slli	t0, t0, 48
	or	a6, a6, t0
	lbu	t0, 15(a1)
	slli	t0, t0, 56
	or	a6, a6, t0
L_ualn_ld6_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	and	t3, a5, s9
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a6, a5, 44
	.word	0x7ec85eb3
#else
	srli	t4, a5, 44
	slli	t0, a6, 20
	or	t4, t4, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	t4, t4, s9
	srli	t5, a6, 24
	and	t5, t5, s10
	or	t5, t5, s11
	add	t3, s6, t3
	add	t4, s7, t4
	add	t5, s8, t5
	sd	t3, 0(sp)
	sd	t4, 32(sp)
	sd	t5, 64(sp)
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a5, 16(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld7_w
	ld	a5, 16(a1)
	j	L_ualn_ld7_e
L_ualn_ld7_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld7_h
	lwu	a5, 16(a1)
	lwu	t0, 20(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	j	L_ualn_ld7_e
L_ualn_ld7_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld7_b
	lhu	a5, 16(a1)
	lhu	t0, 18(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lhu	t0, 20(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lhu	t0, 22(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	j	L_ualn_ld7_e
L_ualn_ld7_b:
	lbu	a5, 16(a1)
	lbu	t0, 17(a1)
	slli	t0, t0, 8
	or	a5, a5, t0
	lbu	t0, 18(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lbu	t0, 19(a1)
	slli	t0, t0, 24
	or	a5, a5, t0
	lbu	t0, 20(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lbu	t0, 21(a1)
	slli	t0, t0, 40
	or	a5, a5, t0
	lbu	t0, 22(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	lbu	t0, 23(a1)
	slli	t0, t0, 56
	or	a5, a5, t0
L_ualn_ld7_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a6, 24(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld8_w
	ld	a6, 24(a1)
	j	L_ualn_ld8_e
L_ualn_ld8_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld8_h
	lwu	a6, 24(a1)
	lwu	t0, 28(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	j	L_ualn_ld8_e
L_ualn_ld8_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld8_b
	lhu	a6, 24(a1)
	lhu	t0, 26(a1)
	slli	t0, t0, 16
	or	a6, a6, t0
	lhu	t0, 28(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	lhu	t0, 30(a1)
	slli	t0, t0, 48
	or	a6, a6, t0
	j	L_ualn_ld8_e
L_ualn_ld8_b:
	lbu	a6, 24(a1)
	lbu	t0, 25(a1)
	slli	t0, t0, 8
	or	a6, a6, t0
	lbu	t0, 26(a1)
	slli	t0, t0, 16
	or	a6, a6, t0
	lbu	t0, 27(a1)
	slli	t0, t0, 24
	or	a6, a6, t0
	lbu	t0, 28(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	lbu	t0, 29(a1)
	slli	t0, t0, 40
	or	a6, a6, t0
	lbu	t0, 30(a1)
	slli	t0, t0, 48
	or	a6, a6, t0
	lbu	t0, 31(a1)
	slli	t0, t0, 56
	or	a6, a6, t0
L_ualn_ld8_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	and	t3, a5, s9
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a6, a5, 44
	.word	0x7ec85eb3
#else
	srli	t4, a5, 44
	slli	t0, a6, 20
	or	t4, t4, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	t4, t4, s9
	srli	t5, a6, 24
	and	t5, t5, s10
	or	t5, t5, s11
	sd	t3, 8(sp)
	sd	t4, 40(sp)
	sd	t5, 72(sp)
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a5, 32(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld9_w
	ld	a5, 32(a1)
	j	L_ualn_ld9_e
L_ualn_ld9_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld9_h
	lwu	a5, 32(a1)
	lwu	t0, 36(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	j	L_ualn_ld9_e
L_ualn_ld9_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld9_b
	lhu	a5, 32(a1)
	lhu	t0, 34(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lhu	t0, 36(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lhu	t0, 38(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	j	L_ualn_ld9_e
L_ualn_ld9_b:
	lbu	a5, 32(a1)
	lbu	t0, 33(a1)
	slli	t0, t0, 8
	or	a5, a5, t0
	lbu	t0, 34(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lbu	t0, 35(a1)
	slli	t0, t0, 24
	or	a5, a5, t0
	lbu	t0, 36(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lbu	t0, 37(a1)
	slli	t0, t0, 40
	or	a5, a5, t0
	lbu	t0, 38(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	lbu	t0, 39(a1)
	slli	t0, t0, 56
	or	a5, a5, t0
L_ualn_ld9_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a6, 40(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld10_w
	ld	a6, 40(a1)
	j	L_ualn_ld10_e
L_ualn_ld10_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld10_h
	lwu	a6, 40(a1)
	lwu	t0, 44(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	j	L_ualn_ld10_e
L_ualn_ld10_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld10_b
	lhu	a6, 40(a1)
	lhu	t0, 42(a1)
	slli	t0, t0, 16
	or	a6, a6, t0
	lhu	t0, 44(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	lhu	t0, 46(a1)
	slli	t0, t0, 48
	or	a6, a6, t0
	j	L_ualn_ld10_e
L_ualn_ld10_b:
	lbu	a6, 40(a1)
	lbu	t0, 41(a1)
	slli	t0, t0, 8
	or	a6, a6, t0
	lbu	t0, 42(a1)
	slli	t0, t0, 16
	or	a6, a6, t0
	lbu	t0, 43(a1)
	slli	t0, t0, 24
	or	a6, a6, t0
	lbu	t0, 44(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	lbu	t0, 45(a1)
	slli	t0, t0, 40
	or	a6, a6, t0
	lbu	t0, 46(a1)
	slli	t0, t0, 48
	or	a6, a6, t0
	lbu	t0, 47(a1)
	slli	t0, t0, 56
	or	a6, a6, t0
L_ualn_ld10_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	and	t3, a5, s9
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a6, a5, 44
	.word	0x7ec85eb3
#else
	srli	t4, a5, 44
	slli	t0, a6, 20
	or	t4, t4, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	t4, t4, s9
	srli	t5, a6, 24
	and	t5, t5, s10
	or	t5, t5, s11
	sd	t3, 16(sp)
	sd	t4, 48(sp)
	sd	t5, 80(sp)
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a5, 48(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld11_w
	ld	a5, 48(a1)
	j	L_ualn_ld11_e
L_ualn_ld11_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld11_h
	lwu	a5, 48(a1)
	lwu	t0, 52(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	j	L_ualn_ld11_e
L_ualn_ld11_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld11_b
	lhu	a5, 48(a1)
	lhu	t0, 50(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lhu	t0, 52(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lhu	t0, 54(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	j	L_ualn_ld11_e
L_ualn_ld11_b:
	lbu	a5, 48(a1)
	lbu	t0, 49(a1)
	slli	t0, t0, 8
	or	a5, a5, t0
	lbu	t0, 50(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lbu	t0, 51(a1)
	slli	t0, t0, 24
	or	a5, a5, t0
	lbu	t0, 52(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lbu	t0, 53(a1)
	slli	t0, t0, 40
	or	a5, a5, t0
	lbu	t0, 54(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	lbu	t0, 55(a1)
	slli	t0, t0, 56
	or	a5, a5, t0
L_ualn_ld11_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a6, 56(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld12_w
	ld	a6, 56(a1)
	j	L_ualn_ld12_e
L_ualn_ld12_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld12_h
	lwu	a6, 56(a1)
	lwu	t0, 60(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	j	L_ualn_ld12_e
L_ualn_ld12_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld12_b
	lhu	a6, 56(a1)
	lhu	t0, 58(a1)
	slli	t0, t0, 16
	or	a6, a6, t0
	lhu	t0, 60(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	lhu	t0, 62(a1)
	slli	t0, t0, 48
	or	a6, a6, t0
	j	L_ualn_ld12_e
L_ualn_ld12_b:
	lbu	a6, 56(a1)
	lbu	t0, 57(a1)
	slli	t0, t0, 8
	or	a6, a6, t0
	lbu	t0, 58(a1)
	slli	t0, t0, 16
	or	a6, a6, t0
	lbu	t0, 59(a1)
	slli	t0, t0, 24
	or	a6, a6, t0
	lbu	t0, 60(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	lbu	t0, 61(a1)
	slli	t0, t0, 40
	or	a6, a6, t0
	lbu	t0, 62(a1)
	slli	t0, t0, 48
	or	a6, a6, t0
	lbu	t0, 63(a1)
	slli	t0, t0, 56
	or	a6, a6, t0
L_ualn_ld12_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	and	t3, a5, s9
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a6, a5, 44
	.word	0x7ec85eb3
#else
	srli	t4, a5, 44
	slli	t0, a6, 20
	or	t4, t4, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	t4, t4, s9
	srli	t5, a6, 24
	and	t5, t5, s10
	or	t5, t5, s11
	sd	t3, 24(sp)
	sd	t4, 56(sp)
	sd	t5, 88(sp)
	addi	t0, sp, 0
		vle64.v	v14, (t0)
	addi	t0, sp, 32
		vle64.v	v16, (t0)
	addi	t0, sp, 64
		vle64.v	v18, (t0)
	vmul.vv	v2, v14, v20
	vmulhu.vv	v4, v14, v20
	vmul.vx	v30, v24, a7
	vmul.vv	v26, v16, v30
	vmulhu.vv	v28, v16, v30
	vmadc.vv	v0, v2, v26
	vadd.vv	v2, v2, v26
	vadd.vv	v4, v4, v28
		vadc.vim	v4, v4, 0, v0
	vmul.vx	v30, v22, a7
	vmul.vv	v26, v18, v30
	vmulhu.vv	v28, v18, v30
	vmadc.vv	v0, v2, v26
	vadd.vv	v2, v2, v26
	vadd.vv	v4, v4, v28
		vadc.vim	v4, v4, 0, v0
	vmul.vv	v6, v14, v22
	vmulhu.vv	v8, v14, v22
	vmul.vv	v26, v16, v20
	vmulhu.vv	v28, v16, v20
	vmadc.vv	v0, v6, v26
	vadd.vv	v6, v6, v26
	vadd.vv	v8, v8, v28
		vadc.vim	v8, v8, 0, v0
	vmul.vx	v30, v24, a7
	vmul.vv	v26, v18, v30
	vmulhu.vv	v28, v18, v30
	vmadc.vv	v0, v6, v26
	vadd.vv	v6, v6, v26
	vadd.vv	v8, v8, v28
		vadc.vim	v8, v8, 0, v0
	vmul.vv	v10, v14, v24
	vmulhu.vv	v12, v14, v24
	vmul.vv	v26, v16, v22
	vmulhu.vv	v28, v16, v22
	vmadc.vv	v0, v10, v26
	vadd.vv	v10, v10, v26
	vadd.vv	v12, v12, v28
		vadc.vim	v12, v12, 0, v0
	vmul.vv	v26, v18, v20
	vmulhu.vv	v28, v18, v20
	vmadc.vv	v0, v10, v26
	vadd.vv	v10, v10, v26
	vadd.vv	v12, v12, v28
		vadc.vim	v12, v12, 0, v0
	vsetivli	zero, 4, e64, m2, ta, ma
	li	a6, 24
	addi	t0, a0, 96
		vlse64.v	v20, (t0), a6
	addi	t0, a0, 104
		vlse64.v	v22, (t0), a6
	addi	t0, a0, 112
		vlse64.v	v24, (t0), a6
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a5, 64(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld13_w
	ld	a5, 64(a1)
	j	L_ualn_ld13_e
L_ualn_ld13_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld13_h
	lwu	a5, 64(a1)
	lwu	t0, 68(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	j	L_ualn_ld13_e
L_ualn_ld13_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld13_b
	lhu	a5, 64(a1)
	lhu	t0, 66(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lhu	t0, 68(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lhu	t0, 70(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	j	L_ualn_ld13_e
L_ualn_ld13_b:
	lbu	a5, 64(a1)
	lbu	t0, 65(a1)
	slli	t0, t0, 8
	or	a5, a5, t0
	lbu	t0, 66(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lbu	t0, 67(a1)
	slli	t0, t0, 24
	or	a5, a5, t0
	lbu	t0, 68(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lbu	t0, 69(a1)
	slli	t0, t0, 40
	or	a5, a5, t0
	lbu	t0, 70(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	lbu	t0, 71(a1)
	slli	t0, t0, 56
	or	a5, a5, t0
L_ualn_ld13_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a6, 72(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld14_w
	ld	a6, 72(a1)
	j	L_ualn_ld14_e
L_ualn_ld14_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld14_h
	lwu	a6, 72(a1)
	lwu	t0, 76(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	j	L_ualn_ld14_e
L_ualn_ld14_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld14_b
	lhu	a6, 72(a1)
	lhu	t0, 74(a1)
	slli	t0, t0, 16
	or	a6, a6, t0
	lhu	t0, 76(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	lhu	t0, 78(a1)
	slli	t0, t0, 48
	or	a6, a6, t0
	j	L_ualn_ld14_e
L_ualn_ld14_b:
	lbu	a6, 72(a1)
	lbu	t0, 73(a1)
	slli	t0, t0, 8
	or	a6, a6, t0
	lbu	t0, 74(a1)
	slli	t0, t0, 16
	or	a6, a6, t0
	lbu	t0, 75(a1)
	slli	t0, t0, 24
	or	a6, a6, t0
	lbu	t0, 76(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	lbu	t0, 77(a1)
	slli	t0, t0, 40
	or	a6, a6, t0
	lbu	t0, 78(a1)
	slli	t0, t0, 48
	or	a6, a6, t0
	lbu	t0, 79(a1)
	slli	t0, t0, 56
	or	a6, a6, t0
L_ualn_ld14_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	and	t3, a5, s9
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a6, a5, 44
	.word	0x7ec85eb3
#else
	srli	t4, a5, 44
	slli	t0, a6, 20
	or	t4, t4, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	t4, t4, s9
	srli	t5, a6, 24
	and	t5, t5, s10
	or	t5, t5, s11
	sd	t3, 0(sp)
	sd	t4, 32(sp)
	sd	t5, 64(sp)
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a5, 80(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld15_w
	ld	a5, 80(a1)
	j	L_ualn_ld15_e
L_ualn_ld15_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld15_h
	lwu	a5, 80(a1)
	lwu	t0, 84(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	j	L_ualn_ld15_e
L_ualn_ld15_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld15_b
	lhu	a5, 80(a1)
	lhu	t0, 82(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lhu	t0, 84(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lhu	t0, 86(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	j	L_ualn_ld15_e
L_ualn_ld15_b:
	lbu	a5, 80(a1)
	lbu	t0, 81(a1)
	slli	t0, t0, 8
	or	a5, a5, t0
	lbu	t0, 82(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lbu	t0, 83(a1)
	slli	t0, t0, 24
	or	a5, a5, t0
	lbu	t0, 84(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lbu	t0, 85(a1)
	slli	t0, t0, 40
	or	a5, a5, t0
	lbu	t0, 86(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	lbu	t0, 87(a1)
	slli	t0, t0, 56
	or	a5, a5, t0
L_ualn_ld15_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a6, 88(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld16_w
	ld	a6, 88(a1)
	j	L_ualn_ld16_e
L_ualn_ld16_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld16_h
	lwu	a6, 88(a1)
	lwu	t0, 92(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	j	L_ualn_ld16_e
L_ualn_ld16_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld16_b
	lhu	a6, 88(a1)
	lhu	t0, 90(a1)
	slli	t0, t0, 16
	or	a6, a6, t0
	lhu	t0, 92(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	lhu	t0, 94(a1)
	slli	t0, t0, 48
	or	a6, a6, t0
	j	L_ualn_ld16_e
L_ualn_ld16_b:
	lbu	a6, 88(a1)
	lbu	t0, 89(a1)
	slli	t0, t0, 8
	or	a6, a6, t0
	lbu	t0, 90(a1)
	slli	t0, t0, 16
	or	a6, a6, t0
	lbu	t0, 91(a1)
	slli	t0, t0, 24
	or	a6, a6, t0
	lbu	t0, 92(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	lbu	t0, 93(a1)
	slli	t0, t0, 40
	or	a6, a6, t0
	lbu	t0, 94(a1)
	slli	t0, t0, 48
	or	a6, a6, t0
	lbu	t0, 95(a1)
	slli	t0, t0, 56
	or	a6, a6, t0
L_ualn_ld16_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	and	t3, a5, s9
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a6, a5, 44
	.word	0x7ec85eb3
#else
	srli	t4, a5, 44
	slli	t0, a6, 20
	or	t4, t4, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	t4, t4, s9
	srli	t5, a6, 24
	and	t5, t5, s10
	or	t5, t5, s11
	sd	t3, 8(sp)
	sd	t4, 40(sp)
	sd	t5, 72(sp)
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a5, 96(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld17_w
	ld	a5, 96(a1)
	j	L_ualn_ld17_e
L_ualn_ld17_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld17_h
	lwu	a5, 96(a1)
	lwu	t0, 100(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	j	L_ualn_ld17_e
L_ualn_ld17_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld17_b
	lhu	a5, 96(a1)
	lhu	t0, 98(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lhu	t0, 100(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lhu	t0, 102(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	j	L_ualn_ld17_e
L_ualn_ld17_b:
	lbu	a5, 96(a1)
	lbu	t0, 97(a1)
	slli	t0, t0, 8
	or	a5, a5, t0
	lbu	t0, 98(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lbu	t0, 99(a1)
	slli	t0, t0, 24
	or	a5, a5, t0
	lbu	t0, 100(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lbu	t0, 101(a1)
	slli	t0, t0, 40
	or	a5, a5, t0
	lbu	t0, 102(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	lbu	t0, 103(a1)
	slli	t0, t0, 56
	or	a5, a5, t0
L_ualn_ld17_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a6, 104(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld18_w
	ld	a6, 104(a1)
	j	L_ualn_ld18_e
L_ualn_ld18_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld18_h
	lwu	a6, 104(a1)
	lwu	t0, 108(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	j	L_ualn_ld18_e
L_ualn_ld18_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld18_b
	lhu	a6, 104(a1)
	lhu	t0, 106(a1)
	slli	t0, t0, 16
	or	a6, a6, t0
	lhu	t0, 108(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	lhu	t0, 110(a1)
	slli	t0, t0, 48
	or	a6, a6, t0
	j	L_ualn_ld18_e
L_ualn_ld18_b:
	lbu	a6, 104(a1)
	lbu	t0, 105(a1)
	slli	t0, t0, 8
	or	a6, a6, t0
	lbu	t0, 106(a1)
	slli	t0, t0, 16
	or	a6, a6, t0
	lbu	t0, 107(a1)
	slli	t0, t0, 24
	or	a6, a6, t0
	lbu	t0, 108(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	lbu	t0, 109(a1)
	slli	t0, t0, 40
	or	a6, a6, t0
	lbu	t0, 110(a1)
	slli	t0, t0, 48
	or	a6, a6, t0
	lbu	t0, 111(a1)
	slli	t0, t0, 56
	or	a6, a6, t0
L_ualn_ld18_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	and	t3, a5, s9
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a6, a5, 44
	.word	0x7ec85eb3
#else
	srli	t4, a5, 44
	slli	t0, a6, 20
	or	t4, t4, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	t4, t4, s9
	srli	t5, a6, 24
	and	t5, t5, s10
	or	t5, t5, s11
	sd	t3, 16(sp)
	sd	t4, 48(sp)
	sd	t5, 80(sp)
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a5, 112(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld19_w
	ld	a5, 112(a1)
	j	L_ualn_ld19_e
L_ualn_ld19_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld19_h
	lwu	a5, 112(a1)
	lwu	t0, 116(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	j	L_ualn_ld19_e
L_ualn_ld19_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld19_b
	lhu	a5, 112(a1)
	lhu	t0, 114(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lhu	t0, 116(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lhu	t0, 118(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	j	L_ualn_ld19_e
L_ualn_ld19_b:
	lbu	a5, 112(a1)
	lbu	t0, 113(a1)
	slli	t0, t0, 8
	or	a5, a5, t0
	lbu	t0, 114(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lbu	t0, 115(a1)
	slli	t0, t0, 24
	or	a5, a5, t0
	lbu	t0, 116(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lbu	t0, 117(a1)
	slli	t0, t0, 40
	or	a5, a5, t0
	lbu	t0, 118(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	lbu	t0, 119(a1)
	slli	t0, t0, 56
	or	a5, a5, t0
L_ualn_ld19_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a6, 120(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld20_w
	ld	a6, 120(a1)
	j	L_ualn_ld20_e
L_ualn_ld20_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld20_h
	lwu	a6, 120(a1)
	lwu	t0, 124(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	j	L_ualn_ld20_e
L_ualn_ld20_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld20_b
	lhu	a6, 120(a1)
	lhu	t0, 122(a1)
	slli	t0, t0, 16
	or	a6, a6, t0
	lhu	t0, 124(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	lhu	t0, 126(a1)
	slli	t0, t0, 48
	or	a6, a6, t0
	j	L_ualn_ld20_e
L_ualn_ld20_b:
	lbu	a6, 120(a1)
	lbu	t0, 121(a1)
	slli	t0, t0, 8
	or	a6, a6, t0
	lbu	t0, 122(a1)
	slli	t0, t0, 16
	or	a6, a6, t0
	lbu	t0, 123(a1)
	slli	t0, t0, 24
	or	a6, a6, t0
	lbu	t0, 124(a1)
	slli	t0, t0, 32
	or	a6, a6, t0
	lbu	t0, 125(a1)
	slli	t0, t0, 40
	or	a6, a6, t0
	lbu	t0, 126(a1)
	slli	t0, t0, 48
	or	a6, a6, t0
	lbu	t0, 127(a1)
	slli	t0, t0, 56
	or	a6, a6, t0
L_ualn_ld20_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	and	t3, a5, s9
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a6, a5, 44
	.word	0x7ec85eb3
#else
	srli	t4, a5, 44
	slli	t0, a6, 20
	or	t4, t4, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	t4, t4, s9
	srli	t5, a6, 24
	and	t5, t5, s10
	or	t5, t5, s11
	sd	t3, 24(sp)
	sd	t4, 56(sp)
	sd	t5, 88(sp)
	addi	t0, sp, 0
		vle64.v	v14, (t0)
	addi	t0, sp, 32
		vle64.v	v16, (t0)
	addi	t0, sp, 64
		vle64.v	v18, (t0)
	vmul.vv	v26, v14, v20
	vmulhu.vv	v28, v14, v20
	vmadc.vv	v0, v2, v26
	vadd.vv	v2, v2, v26
	vadd.vv	v4, v4, v28
		vadc.vim	v4, v4, 0, v0
	vmul.vx	v30, v24, a7
	vmul.vv	v26, v16, v30
	vmulhu.vv	v28, v16, v30
	vmadc.vv	v0, v2, v26
	vadd.vv	v2, v2, v26
	vadd.vv	v4, v4, v28
		vadc.vim	v4, v4, 0, v0
	vmul.vx	v30, v22, a7
	vmul.vv	v26, v18, v30
	vmulhu.vv	v28, v18, v30
	vmadc.vv	v0, v2, v26
	vadd.vv	v2, v2, v26
	vadd.vv	v4, v4, v28
		vadc.vim	v4, v4, 0, v0
	vmul.vv	v26, v14, v22
	vmulhu.vv	v28, v14, v22
	vmadc.vv	v0, v6, v26
	vadd.vv	v6, v6, v26
	vadd.vv	v8, v8, v28
		vadc.vim	v8, v8, 0, v0
	vmul.vv	v26, v16, v20
	vmulhu.vv	v28, v16, v20
	vmadc.vv	v0, v6, v26
	vadd.vv	v6, v6, v26
	vadd.vv	v8, v8, v28
		vadc.vim	v8, v8, 0, v0
	vmul.vx	v30, v24, a7
	vmul.vv	v26, v18, v30
	vmulhu.vv	v28, v18, v30
	vmadc.vv	v0, v6, v26
	vadd.vv	v6, v6, v26
	vadd.vv	v8, v8, v28
		vadc.vim	v8, v8, 0, v0
	vmul.vv	v26, v14, v24
	vmulhu.vv	v28, v14, v24
	vmadc.vv	v0, v10, v26
	vadd.vv	v10, v10, v26
	vadd.vv	v12, v12, v28
		vadc.vim	v12, v12, 0, v0
	vmul.vv	v26, v16, v22
	vmulhu.vv	v28, v16, v22
	vmadc.vv	v0, v10, v26
	vadd.vv	v10, v10, v26
	vadd.vv	v12, v12, v28
		vadc.vim	v12, v12, 0, v0
	vmul.vv	v26, v18, v20
	vmulhu.vv	v28, v18, v20
	vmadc.vv	v0, v10, v26
	vadd.vv	v10, v10, v26
	vadd.vv	v12, v12, v28
		vadc.vim	v12, v12, 0, v0
	vslidedown.vi	v26, v2, 2
	vslidedown.vi	v28, v4, 2
	vmadc.vv	v0, v2, v26
	vadd.vv	v2, v2, v26
	vadd.vv	v4, v4, v28
		vadc.vim	v4, v4, 0, v0
	vslidedown.vi	v26, v2, 1
	vslidedown.vi	v28, v4, 1
	vmadc.vv	v0, v2, v26
	vadd.vv	v2, v2, v26
	vadd.vv	v4, v4, v28
		vadc.vim	v4, v4, 0, v0
	vmv.x.s	t3, v2
	vmv.x.s	t4, v4
	vslidedown.vi	v26, v6, 2
	vslidedown.vi	v28, v8, 2
	vmadc.vv	v0, v6, v26
	vadd.vv	v6, v6, v26
	vadd.vv	v8, v8, v28
		vadc.vim	v8, v8, 0, v0
	vslidedown.vi	v26, v6, 1
	vslidedown.vi	v28, v8, 1
	vmadc.vv	v0, v6, v26
	vadd.vv	v6, v6, v26
	vadd.vv	v8, v8, v28
		vadc.vim	v8, v8, 0, v0
	vmv.x.s	t5, v6
	vmv.x.s	t6, v8
	vslidedown.vi	v26, v10, 2
	vslidedown.vi	v28, v12, 2
	vmadc.vv	v0, v10, v26
	vadd.vv	v10, v10, v26
	vadd.vv	v12, v12, v28
		vadc.vim	v12, v12, 0, v0
	vslidedown.vi	v26, v10, 1
	vslidedown.vi	v28, v12, 1
	vmadc.vv	v0, v10, v26
	vadd.vv	v10, v10, v26
	vadd.vv	v12, v12, v28
		vadc.vim	v12, v12, 0, v0
	vmv.x.s	a3, v10
	vmv.x.s	a4, v12
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t2, t4, t3, 44
	.word	0xe6ced3b3
#else
	srli	t2, t3, 44
	slli	t0, t4, 20
	or	t2, t2, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	s6, t3, s9
	add	t5, t5, t2
	sltu	t0, t5, t2
	add	t6, t6, t0
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t2, t6, t5, 44
	.word	0xf6cfd3b3
#else
	srli	t2, t5, 44
	slli	t0, t6, 20
	or	t2, t2, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	s7, t5, s9
	add	a3, a3, t2
	sltu	t0, a3, t2
	add	a4, a4, t0
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t2, a4, a3, 42
	.word	0x6ea753b3
#else
	srli	t2, a3, 42
	slli	t0, a4, 22
	or	t2, t2, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	s8, a3, s10
	slli	t0, t2, 2
	add	t2, t2, t0
	add	s6, s6, t2
	srli	t2, s6, 44
	and	s6, s6, s9
	add	s7, s7, t2
	addi	a1, a1, 128
	addi	a2, a2, -128
	li	t0, 128
	bgeu	a2, t0, L_poly1305_riscv64_blocks_v8loop
L_poly1305_riscv64_blocks_v8skip:
	# Vectorized 4-block path: h <- (h+m0)r^4 + m1*r^3 + m2*r^2 + m3*r
	li	t0, 64
	bltu	a2, t0, L_poly1305_riscv64_blocks_v2tail
	lbu	t0, 288(a0)
	li	t1, 2
	bge	t0, t1, L_poly1305_riscv64_have_r34
	li	t1, 1
	bge	t0, t1, L_poly1305_riscv64_r34_have_r2
	ld	t0, 0(a0)
	sd	t0, 168(a0)
	ld	t0, 8(a0)
	sd	t0, 176(a0)
	ld	t0, 16(a0)
	sd	t0, 184(a0)
	li	t2, 20
	ld	t0, 8(a0)
	mul	a6, t0, t2
	ld	t0, 16(a0)
	mul	a7, t0, t2
	li	t5, 17592186044415
	# d0 = a0*b0 + a1*s2 + a2*s1 ; o0 = d0 & m44 ; cc = d0 >> 44
	ld	t0, 0(a0)
	ld	t1, 0(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 8(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 16(a0)
	mul	a4, t0, a6
	mulhu	a5, t0, a6
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	and	t2, t6, t5
	sd	t2, 144(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d1 = a0*b1 + a1*b0 + a2*s2 (+cc) ; o1 = d1 & m44 ; cc = d1 >> 44
	ld	t0, 0(a0)
	ld	t1, 8(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 8(a0)
	ld	t1, 0(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 16(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	and	t2, t6, t5
	sd	t2, 152(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d2 = a0*b2 + a1*b1 + a2*b0 (+cc) ; o2 = d2 & m42 ; cc = d2 >> 42
	ld	t0, 0(a0)
	ld	t1, 16(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 8(a0)
	ld	t1, 8(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 16(a0)
	ld	t1, 0(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	srli	t5, t5, 2
	and	a6, t6, t5
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 42
	.word	0xfea6deb3
#else
	srli	t4, t6, 42
	slli	a4, a3, 22
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# fold top carry: o0 += cc*5 ; propagate into o1
	slli	a4, t4, 2
	add	t4, t4, a4
	li	t5, 17592186044415
	ld	a4, 144(a0)
	add	a4, a4, t4
	srli	a5, a4, 44
	and	a4, a4, t5
	sd	a4, 144(a0)
	ld	a4, 152(a0)
	add	a4, a4, a5
	sd	a4, 152(a0)
	sd	a6, 160(a0)
L_poly1305_riscv64_r34_have_r2:
	li	t2, 20
	ld	t0, 8(a0)
	mul	a6, t0, t2
	ld	t0, 16(a0)
	mul	a7, t0, t2
	li	t5, 17592186044415
	# d0 = a0*b0 + a1*s2 + a2*s1 ; o0 = d0 & m44 ; cc = d0 >> 44
	ld	t0, 144(a0)
	ld	t1, 0(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 152(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 160(a0)
	mul	a4, t0, a6
	mulhu	a5, t0, a6
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	and	t2, t6, t5
	sd	t2, 120(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d1 = a0*b1 + a1*b0 + a2*s2 (+cc) ; o1 = d1 & m44 ; cc = d1 >> 44
	ld	t0, 144(a0)
	ld	t1, 8(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 152(a0)
	ld	t1, 0(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 160(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	and	t2, t6, t5
	sd	t2, 128(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d2 = a0*b2 + a1*b1 + a2*b0 (+cc) ; o2 = d2 & m42 ; cc = d2 >> 42
	ld	t0, 144(a0)
	ld	t1, 16(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 152(a0)
	ld	t1, 8(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 160(a0)
	ld	t1, 0(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	srli	t5, t5, 2
	and	a6, t6, t5
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 42
	.word	0xfea6deb3
#else
	srli	t4, t6, 42
	slli	a4, a3, 22
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# fold top carry: o0 += cc*5 ; propagate into o1
	slli	a4, t4, 2
	add	t4, t4, a4
	li	t5, 17592186044415
	ld	a4, 120(a0)
	add	a4, a4, t4
	srli	a5, a4, 44
	and	a4, a4, t5
	sd	a4, 120(a0)
	ld	a4, 128(a0)
	add	a4, a4, a5
	sd	a4, 128(a0)
	sd	a6, 136(a0)
	li	t2, 20
	ld	t0, 152(a0)
	mul	a6, t0, t2
	ld	t0, 160(a0)
	mul	a7, t0, t2
	li	t5, 17592186044415
	# d0 = a0*b0 + a1*s2 + a2*s1 ; o0 = d0 & m44 ; cc = d0 >> 44
	ld	t0, 144(a0)
	ld	t1, 144(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 152(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 160(a0)
	mul	a4, t0, a6
	mulhu	a5, t0, a6
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	and	t2, t6, t5
	sd	t2, 96(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d1 = a0*b1 + a1*b0 + a2*s2 (+cc) ; o1 = d1 & m44 ; cc = d1 >> 44
	ld	t0, 144(a0)
	ld	t1, 152(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 152(a0)
	ld	t1, 144(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 160(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	and	t2, t6, t5
	sd	t2, 104(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d2 = a0*b2 + a1*b1 + a2*b0 (+cc) ; o2 = d2 & m42 ; cc = d2 >> 42
	ld	t0, 144(a0)
	ld	t1, 160(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 152(a0)
	ld	t1, 152(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 160(a0)
	ld	t1, 144(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	srli	t5, t5, 2
	and	a6, t6, t5
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 42
	.word	0xfea6deb3
#else
	srli	t4, t6, 42
	slli	a4, a3, 22
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# fold top carry: o0 += cc*5 ; propagate into o1
	slli	a4, t4, 2
	add	t4, t4, a4
	li	t5, 17592186044415
	ld	a4, 96(a0)
	add	a4, a4, t4
	srli	a5, a4, 44
	and	a4, a4, t5
	sd	a4, 96(a0)
	ld	a4, 104(a0)
	add	a4, a4, a5
	sd	a4, 104(a0)
	sd	a6, 112(a0)
	li	t0, 2
	sb	t0, 288(a0)
L_poly1305_riscv64_have_r34:
	vsetivli	zero, 4, e64, m2, ta, ma
	li	a6, 24
	addi	t0, a0, 96
		vlse64.v	v2, (t0), a6
	addi	t0, a0, 104
		vlse64.v	v4, (t0), a6
	addi	t0, a0, 112
		vlse64.v	v6, (t0), a6
	li	a5, 20
	vmul.vx	v8, v4, a5
	vmul.vx	v10, v6, a5
	vmv.v.i	v12, 0
L_poly1305_riscv64_blocks_v4loop:
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a4, 0(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld21_w
	ld	a4, 0(a1)
	j	L_ualn_ld21_e
L_ualn_ld21_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld21_h
	lwu	a4, 0(a1)
	lwu	t0, 4(a1)
	slli	t0, t0, 32
	or	a4, a4, t0
	j	L_ualn_ld21_e
L_ualn_ld21_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld21_b
	lhu	a4, 0(a1)
	lhu	t0, 2(a1)
	slli	t0, t0, 16
	or	a4, a4, t0
	lhu	t0, 4(a1)
	slli	t0, t0, 32
	or	a4, a4, t0
	lhu	t0, 6(a1)
	slli	t0, t0, 48
	or	a4, a4, t0
	j	L_ualn_ld21_e
L_ualn_ld21_b:
	lbu	a4, 0(a1)
	lbu	t0, 1(a1)
	slli	t0, t0, 8
	or	a4, a4, t0
	lbu	t0, 2(a1)
	slli	t0, t0, 16
	or	a4, a4, t0
	lbu	t0, 3(a1)
	slli	t0, t0, 24
	or	a4, a4, t0
	lbu	t0, 4(a1)
	slli	t0, t0, 32
	or	a4, a4, t0
	lbu	t0, 5(a1)
	slli	t0, t0, 40
	or	a4, a4, t0
	lbu	t0, 6(a1)
	slli	t0, t0, 48
	or	a4, a4, t0
	lbu	t0, 7(a1)
	slli	t0, t0, 56
	or	a4, a4, t0
L_ualn_ld21_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a5, 8(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld22_w
	ld	a5, 8(a1)
	j	L_ualn_ld22_e
L_ualn_ld22_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld22_h
	lwu	a5, 8(a1)
	lwu	t0, 12(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	j	L_ualn_ld22_e
L_ualn_ld22_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld22_b
	lhu	a5, 8(a1)
	lhu	t0, 10(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lhu	t0, 12(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lhu	t0, 14(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	j	L_ualn_ld22_e
L_ualn_ld22_b:
	lbu	a5, 8(a1)
	lbu	t0, 9(a1)
	slli	t0, t0, 8
	or	a5, a5, t0
	lbu	t0, 10(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lbu	t0, 11(a1)
	slli	t0, t0, 24
	or	a5, a5, t0
	lbu	t0, 12(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lbu	t0, 13(a1)
	slli	t0, t0, 40
	or	a5, a5, t0
	lbu	t0, 14(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	lbu	t0, 15(a1)
	slli	t0, t0, 56
	or	a5, a5, t0
L_ualn_ld22_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	and	t2, a4, s9
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t3, a5, a4, 44
	.word	0x76c7de33
#else
	srli	t3, a4, 44
	slli	t0, a5, 20
	or	t3, t3, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	t3, t3, s9
	srli	t4, a5, 24
	and	t4, t4, s10
	or	t4, t4, s11
	add	t2, s6, t2
	add	t3, s7, t3
	add	t4, s8, t4
	sd	t2, 0(sp)
	sd	t3, 32(sp)
	sd	t4, 64(sp)
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a4, 16(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld23_w
	ld	a4, 16(a1)
	j	L_ualn_ld23_e
L_ualn_ld23_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld23_h
	lwu	a4, 16(a1)
	lwu	t0, 20(a1)
	slli	t0, t0, 32
	or	a4, a4, t0
	j	L_ualn_ld23_e
L_ualn_ld23_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld23_b
	lhu	a4, 16(a1)
	lhu	t0, 18(a1)
	slli	t0, t0, 16
	or	a4, a4, t0
	lhu	t0, 20(a1)
	slli	t0, t0, 32
	or	a4, a4, t0
	lhu	t0, 22(a1)
	slli	t0, t0, 48
	or	a4, a4, t0
	j	L_ualn_ld23_e
L_ualn_ld23_b:
	lbu	a4, 16(a1)
	lbu	t0, 17(a1)
	slli	t0, t0, 8
	or	a4, a4, t0
	lbu	t0, 18(a1)
	slli	t0, t0, 16
	or	a4, a4, t0
	lbu	t0, 19(a1)
	slli	t0, t0, 24
	or	a4, a4, t0
	lbu	t0, 20(a1)
	slli	t0, t0, 32
	or	a4, a4, t0
	lbu	t0, 21(a1)
	slli	t0, t0, 40
	or	a4, a4, t0
	lbu	t0, 22(a1)
	slli	t0, t0, 48
	or	a4, a4, t0
	lbu	t0, 23(a1)
	slli	t0, t0, 56
	or	a4, a4, t0
L_ualn_ld23_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a5, 24(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld24_w
	ld	a5, 24(a1)
	j	L_ualn_ld24_e
L_ualn_ld24_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld24_h
	lwu	a5, 24(a1)
	lwu	t0, 28(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	j	L_ualn_ld24_e
L_ualn_ld24_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld24_b
	lhu	a5, 24(a1)
	lhu	t0, 26(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lhu	t0, 28(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lhu	t0, 30(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	j	L_ualn_ld24_e
L_ualn_ld24_b:
	lbu	a5, 24(a1)
	lbu	t0, 25(a1)
	slli	t0, t0, 8
	or	a5, a5, t0
	lbu	t0, 26(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lbu	t0, 27(a1)
	slli	t0, t0, 24
	or	a5, a5, t0
	lbu	t0, 28(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lbu	t0, 29(a1)
	slli	t0, t0, 40
	or	a5, a5, t0
	lbu	t0, 30(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	lbu	t0, 31(a1)
	slli	t0, t0, 56
	or	a5, a5, t0
L_ualn_ld24_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	and	t2, a4, s9
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t3, a5, a4, 44
	.word	0x76c7de33
#else
	srli	t3, a4, 44
	slli	t0, a5, 20
	or	t3, t3, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	t3, t3, s9
	srli	t4, a5, 24
	and	t4, t4, s10
	or	t4, t4, s11
	sd	t2, 8(sp)
	sd	t3, 40(sp)
	sd	t4, 72(sp)
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a4, 32(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld25_w
	ld	a4, 32(a1)
	j	L_ualn_ld25_e
L_ualn_ld25_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld25_h
	lwu	a4, 32(a1)
	lwu	t0, 36(a1)
	slli	t0, t0, 32
	or	a4, a4, t0
	j	L_ualn_ld25_e
L_ualn_ld25_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld25_b
	lhu	a4, 32(a1)
	lhu	t0, 34(a1)
	slli	t0, t0, 16
	or	a4, a4, t0
	lhu	t0, 36(a1)
	slli	t0, t0, 32
	or	a4, a4, t0
	lhu	t0, 38(a1)
	slli	t0, t0, 48
	or	a4, a4, t0
	j	L_ualn_ld25_e
L_ualn_ld25_b:
	lbu	a4, 32(a1)
	lbu	t0, 33(a1)
	slli	t0, t0, 8
	or	a4, a4, t0
	lbu	t0, 34(a1)
	slli	t0, t0, 16
	or	a4, a4, t0
	lbu	t0, 35(a1)
	slli	t0, t0, 24
	or	a4, a4, t0
	lbu	t0, 36(a1)
	slli	t0, t0, 32
	or	a4, a4, t0
	lbu	t0, 37(a1)
	slli	t0, t0, 40
	or	a4, a4, t0
	lbu	t0, 38(a1)
	slli	t0, t0, 48
	or	a4, a4, t0
	lbu	t0, 39(a1)
	slli	t0, t0, 56
	or	a4, a4, t0
L_ualn_ld25_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a5, 40(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld26_w
	ld	a5, 40(a1)
	j	L_ualn_ld26_e
L_ualn_ld26_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld26_h
	lwu	a5, 40(a1)
	lwu	t0, 44(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	j	L_ualn_ld26_e
L_ualn_ld26_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld26_b
	lhu	a5, 40(a1)
	lhu	t0, 42(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lhu	t0, 44(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lhu	t0, 46(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	j	L_ualn_ld26_e
L_ualn_ld26_b:
	lbu	a5, 40(a1)
	lbu	t0, 41(a1)
	slli	t0, t0, 8
	or	a5, a5, t0
	lbu	t0, 42(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lbu	t0, 43(a1)
	slli	t0, t0, 24
	or	a5, a5, t0
	lbu	t0, 44(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lbu	t0, 45(a1)
	slli	t0, t0, 40
	or	a5, a5, t0
	lbu	t0, 46(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	lbu	t0, 47(a1)
	slli	t0, t0, 56
	or	a5, a5, t0
L_ualn_ld26_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	and	t2, a4, s9
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t3, a5, a4, 44
	.word	0x76c7de33
#else
	srli	t3, a4, 44
	slli	t0, a5, 20
	or	t3, t3, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	t3, t3, s9
	srli	t4, a5, 24
	and	t4, t4, s10
	or	t4, t4, s11
	sd	t2, 16(sp)
	sd	t3, 48(sp)
	sd	t4, 80(sp)
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a4, 48(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld27_w
	ld	a4, 48(a1)
	j	L_ualn_ld27_e
L_ualn_ld27_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld27_h
	lwu	a4, 48(a1)
	lwu	t0, 52(a1)
	slli	t0, t0, 32
	or	a4, a4, t0
	j	L_ualn_ld27_e
L_ualn_ld27_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld27_b
	lhu	a4, 48(a1)
	lhu	t0, 50(a1)
	slli	t0, t0, 16
	or	a4, a4, t0
	lhu	t0, 52(a1)
	slli	t0, t0, 32
	or	a4, a4, t0
	lhu	t0, 54(a1)
	slli	t0, t0, 48
	or	a4, a4, t0
	j	L_ualn_ld27_e
L_ualn_ld27_b:
	lbu	a4, 48(a1)
	lbu	t0, 49(a1)
	slli	t0, t0, 8
	or	a4, a4, t0
	lbu	t0, 50(a1)
	slli	t0, t0, 16
	or	a4, a4, t0
	lbu	t0, 51(a1)
	slli	t0, t0, 24
	or	a4, a4, t0
	lbu	t0, 52(a1)
	slli	t0, t0, 32
	or	a4, a4, t0
	lbu	t0, 53(a1)
	slli	t0, t0, 40
	or	a4, a4, t0
	lbu	t0, 54(a1)
	slli	t0, t0, 48
	or	a4, a4, t0
	lbu	t0, 55(a1)
	slli	t0, t0, 56
	or	a4, a4, t0
L_ualn_ld27_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a5, 56(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld28_w
	ld	a5, 56(a1)
	j	L_ualn_ld28_e
L_ualn_ld28_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld28_h
	lwu	a5, 56(a1)
	lwu	t0, 60(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	j	L_ualn_ld28_e
L_ualn_ld28_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld28_b
	lhu	a5, 56(a1)
	lhu	t0, 58(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lhu	t0, 60(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lhu	t0, 62(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	j	L_ualn_ld28_e
L_ualn_ld28_b:
	lbu	a5, 56(a1)
	lbu	t0, 57(a1)
	slli	t0, t0, 8
	or	a5, a5, t0
	lbu	t0, 58(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lbu	t0, 59(a1)
	slli	t0, t0, 24
	or	a5, a5, t0
	lbu	t0, 60(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lbu	t0, 61(a1)
	slli	t0, t0, 40
	or	a5, a5, t0
	lbu	t0, 62(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	lbu	t0, 63(a1)
	slli	t0, t0, 56
	or	a5, a5, t0
L_ualn_ld28_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	and	t2, a4, s9
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t3, a5, a4, 44
	.word	0x76c7de33
#else
	srli	t3, a4, 44
	slli	t0, a5, 20
	or	t3, t3, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	t3, t3, s9
	srli	t4, a5, 24
	and	t4, t4, s10
	or	t4, t4, s11
	sd	t2, 24(sp)
	sd	t3, 56(sp)
	sd	t4, 88(sp)
	addi	t0, sp, 0
		vle64.v	v14, (t0)
	addi	t0, sp, 32
		vle64.v	v16, (t0)
	addi	t0, sp, 64
		vle64.v	v18, (t0)
	vmul.vv	v20, v14, v2
	vmulhu.vv	v22, v14, v2
	vmul.vv	v24, v16, v10
	vmulhu.vv	v26, v16, v10
	vmadc.vv	v0, v20, v24
	vadd.vv	v20, v20, v24
	vadd.vv	v22, v22, v26
	vadc.vvm	v22, v22, v12, v0
	vmul.vv	v24, v18, v8
	vmulhu.vv	v26, v18, v8
	vmadc.vv	v0, v20, v24
	vadd.vv	v20, v20, v24
	vadd.vv	v22, v22, v26
	vadc.vvm	v22, v22, v12, v0
	vslidedown.vi	v28, v20, 2
	vslidedown.vi	v30, v22, 2
	vmadc.vv	v0, v20, v28
	vadd.vv	v20, v20, v28
	vadd.vv	v22, v22, v30
	vadc.vvm	v22, v22, v12, v0
	vslidedown.vi	v28, v20, 1
	vslidedown.vi	v30, v22, 1
	vmadc.vv	v0, v20, v28
	vadd.vv	v20, v20, v28
	vadd.vv	v22, v22, v30
	vadc.vvm	v22, v22, v12, v0
	vmv.x.s	t2, v20
	vmv.x.s	t3, v22
	vmul.vv	v20, v14, v4
	vmulhu.vv	v22, v14, v4
	vmul.vv	v24, v16, v2
	vmulhu.vv	v26, v16, v2
	vmadc.vv	v0, v20, v24
	vadd.vv	v20, v20, v24
	vadd.vv	v22, v22, v26
	vadc.vvm	v22, v22, v12, v0
	vmul.vv	v24, v18, v10
	vmulhu.vv	v26, v18, v10
	vmadc.vv	v0, v20, v24
	vadd.vv	v20, v20, v24
	vadd.vv	v22, v22, v26
	vadc.vvm	v22, v22, v12, v0
	vslidedown.vi	v28, v20, 2
	vslidedown.vi	v30, v22, 2
	vmadc.vv	v0, v20, v28
	vadd.vv	v20, v20, v28
	vadd.vv	v22, v22, v30
	vadc.vvm	v22, v22, v12, v0
	vslidedown.vi	v28, v20, 1
	vslidedown.vi	v30, v22, 1
	vmadc.vv	v0, v20, v28
	vadd.vv	v20, v20, v28
	vadd.vv	v22, v22, v30
	vadc.vvm	v22, v22, v12, v0
	vmv.x.s	t4, v20
	vmv.x.s	t5, v22
	vmul.vv	v20, v14, v6
	vmulhu.vv	v22, v14, v6
	vmul.vv	v24, v16, v4
	vmulhu.vv	v26, v16, v4
	vmadc.vv	v0, v20, v24
	vadd.vv	v20, v20, v24
	vadd.vv	v22, v22, v26
	vadc.vvm	v22, v22, v12, v0
	vmul.vv	v24, v18, v2
	vmulhu.vv	v26, v18, v2
	vmadc.vv	v0, v20, v24
	vadd.vv	v20, v20, v24
	vadd.vv	v22, v22, v26
	vadc.vvm	v22, v22, v12, v0
	vslidedown.vi	v28, v20, 2
	vslidedown.vi	v30, v22, 2
	vmadc.vv	v0, v20, v28
	vadd.vv	v20, v20, v28
	vadd.vv	v22, v22, v30
	vadc.vvm	v22, v22, v12, v0
	vslidedown.vi	v28, v20, 1
	vslidedown.vi	v30, v22, 1
	vmadc.vv	v0, v20, v28
	vadd.vv	v20, v20, v28
	vadd.vv	v22, v22, v30
	vadc.vvm	v22, v22, v12, v0
	vmv.x.s	t6, v20
	vmv.x.s	a3, v22
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t1, t3, t2, 44
	.word	0x3ece5333
#else
	srli	t1, t2, 44
	slli	t0, t3, 20
	or	t1, t1, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	s6, t2, s9
	add	t4, t4, t1
	sltu	t0, t4, t1
	add	t5, t5, t0
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t1, t5, t4, 44
	.word	0xeecf5333
#else
	srli	t1, t4, 44
	slli	t0, t5, 20
	or	t1, t1, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	s7, t4, s9
	add	t6, t6, t1
	sltu	t0, t6, t1
	add	a3, a3, t0
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t1, a3, t6, 42
	.word	0xfea6d333
#else
	srli	t1, t6, 42
	slli	t0, a3, 22
	or	t1, t1, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	s8, t6, s10
	slli	t0, t1, 2
	add	t1, t1, t0
	add	s6, s6, t1
	srli	t1, s6, 44
	and	s6, s6, s9
	add	s7, s7, t1
	addi	a1, a1, 64
	addi	a2, a2, -64
	li	t0, 64
	bgeu	a2, t0, L_poly1305_riscv64_blocks_v4loop
L_poly1305_riscv64_blocks_v2tail:
	# Vectorized 2-block tail: h <- (h+A)*r^2 + B*r
	li	t0, 32
	bltu	a2, t0, L_poly1305_riscv64_blocks_vskip
	lbu	t0, 288(a0)
	li	t1, 1
	bge	t0, t1, L_poly1305_riscv64_have_r2
	ld	t0, 0(a0)
	sd	t0, 168(a0)
	ld	t0, 8(a0)
	sd	t0, 176(a0)
	ld	t0, 16(a0)
	sd	t0, 184(a0)
	li	t2, 20
	ld	t0, 8(a0)
	mul	a6, t0, t2
	ld	t0, 16(a0)
	mul	a7, t0, t2
	li	t5, 17592186044415
	# d0 = a0*b0 + a1*s2 + a2*s1 ; o0 = d0 & m44 ; cc = d0 >> 44
	ld	t0, 0(a0)
	ld	t1, 0(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 8(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 16(a0)
	mul	a4, t0, a6
	mulhu	a5, t0, a6
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	and	t2, t6, t5
	sd	t2, 144(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d1 = a0*b1 + a1*b0 + a2*s2 (+cc) ; o1 = d1 & m44 ; cc = d1 >> 44
	ld	t0, 0(a0)
	ld	t1, 8(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 8(a0)
	ld	t1, 0(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 16(a0)
	mul	a4, t0, a7
	mulhu	a5, t0, a7
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	and	t2, t6, t5
	sd	t2, 152(a0)
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 44
	.word	0xfec6deb3
#else
	srli	t4, t6, 44
	slli	a4, a3, 20
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# d2 = a0*b2 + a1*b1 + a2*b0 (+cc) ; o2 = d2 & m42 ; cc = d2 >> 42
	ld	t0, 0(a0)
	ld	t1, 16(a0)
	mul	t6, t0, t1
	mulhu	a3, t0, t1
	ld	t0, 8(a0)
	ld	t1, 8(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	ld	t0, 16(a0)
	ld	t1, 0(a0)
	mul	a4, t0, t1
	mulhu	a5, t0, t1
	add	t6, t6, a4
	sltu	t3, t6, a4
	add	a3, a3, a5
	add	a3, a3, t3
	add	t6, t6, t4
	sltu	a4, t6, t4
	add	a3, a3, a4
	srli	t5, t5, 2
	and	a6, t6, t5
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t4, a3, t6, 42
	.word	0xfea6deb3
#else
	srli	t4, t6, 42
	slli	a4, a3, 22
	or	t4, t4, a4
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	# fold top carry: o0 += cc*5 ; propagate into o1
	slli	a4, t4, 2
	add	t4, t4, a4
	li	t5, 17592186044415
	ld	a4, 144(a0)
	add	a4, a4, t4
	srli	a5, a4, 44
	and	a4, a4, t5
	sd	a4, 144(a0)
	ld	a4, 152(a0)
	add	a4, a4, a5
	sd	a4, 152(a0)
	sd	a6, 160(a0)
	li	t0, 1
	sb	t0, 288(a0)
L_poly1305_riscv64_have_r2:
	vsetivli	zero, 2, e64, m1, ta, ma
	li	a6, 24
	addi	t0, a0, 144
		vlse64.v	v2, (t0), a6
	addi	t0, a0, 152
		vlse64.v	v4, (t0), a6
	addi	t0, a0, 160
		vlse64.v	v6, (t0), a6
	li	a5, 20
	vmul.vx	v8, v4, a5
	vmul.vx	v10, v6, a5
	vmv.v.i	v12, 0
L_poly1305_riscv64_blocks_vloop:
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a4, 0(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld29_w
	ld	a4, 0(a1)
	j	L_ualn_ld29_e
L_ualn_ld29_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld29_h
	lwu	a4, 0(a1)
	lwu	t0, 4(a1)
	slli	t0, t0, 32
	or	a4, a4, t0
	j	L_ualn_ld29_e
L_ualn_ld29_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld29_b
	lhu	a4, 0(a1)
	lhu	t0, 2(a1)
	slli	t0, t0, 16
	or	a4, a4, t0
	lhu	t0, 4(a1)
	slli	t0, t0, 32
	or	a4, a4, t0
	lhu	t0, 6(a1)
	slli	t0, t0, 48
	or	a4, a4, t0
	j	L_ualn_ld29_e
L_ualn_ld29_b:
	lbu	a4, 0(a1)
	lbu	t0, 1(a1)
	slli	t0, t0, 8
	or	a4, a4, t0
	lbu	t0, 2(a1)
	slli	t0, t0, 16
	or	a4, a4, t0
	lbu	t0, 3(a1)
	slli	t0, t0, 24
	or	a4, a4, t0
	lbu	t0, 4(a1)
	slli	t0, t0, 32
	or	a4, a4, t0
	lbu	t0, 5(a1)
	slli	t0, t0, 40
	or	a4, a4, t0
	lbu	t0, 6(a1)
	slli	t0, t0, 48
	or	a4, a4, t0
	lbu	t0, 7(a1)
	slli	t0, t0, 56
	or	a4, a4, t0
L_ualn_ld29_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a5, 8(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld30_w
	ld	a5, 8(a1)
	j	L_ualn_ld30_e
L_ualn_ld30_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld30_h
	lwu	a5, 8(a1)
	lwu	t0, 12(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	j	L_ualn_ld30_e
L_ualn_ld30_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld30_b
	lhu	a5, 8(a1)
	lhu	t0, 10(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lhu	t0, 12(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lhu	t0, 14(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	j	L_ualn_ld30_e
L_ualn_ld30_b:
	lbu	a5, 8(a1)
	lbu	t0, 9(a1)
	slli	t0, t0, 8
	or	a5, a5, t0
	lbu	t0, 10(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lbu	t0, 11(a1)
	slli	t0, t0, 24
	or	a5, a5, t0
	lbu	t0, 12(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lbu	t0, 13(a1)
	slli	t0, t0, 40
	or	a5, a5, t0
	lbu	t0, 14(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	lbu	t0, 15(a1)
	slli	t0, t0, 56
	or	a5, a5, t0
L_ualn_ld30_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	and	t2, a4, s9
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t3, a5, a4, 44
	.word	0x76c7de33
#else
	srli	t3, a4, 44
	slli	t0, a5, 20
	or	t3, t3, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	t3, t3, s9
	srli	t4, a5, 24
	and	t4, t4, s10
	or	t4, t4, s11
	add	t2, s6, t2
	add	t3, s7, t3
	add	t4, s8, t4
	sd	t2, 0(sp)
	sd	t3, 32(sp)
	sd	t4, 64(sp)
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a4, 16(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld31_w
	ld	a4, 16(a1)
	j	L_ualn_ld31_e
L_ualn_ld31_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld31_h
	lwu	a4, 16(a1)
	lwu	t0, 20(a1)
	slli	t0, t0, 32
	or	a4, a4, t0
	j	L_ualn_ld31_e
L_ualn_ld31_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld31_b
	lhu	a4, 16(a1)
	lhu	t0, 18(a1)
	slli	t0, t0, 16
	or	a4, a4, t0
	lhu	t0, 20(a1)
	slli	t0, t0, 32
	or	a4, a4, t0
	lhu	t0, 22(a1)
	slli	t0, t0, 48
	or	a4, a4, t0
	j	L_ualn_ld31_e
L_ualn_ld31_b:
	lbu	a4, 16(a1)
	lbu	t0, 17(a1)
	slli	t0, t0, 8
	or	a4, a4, t0
	lbu	t0, 18(a1)
	slli	t0, t0, 16
	or	a4, a4, t0
	lbu	t0, 19(a1)
	slli	t0, t0, 24
	or	a4, a4, t0
	lbu	t0, 20(a1)
	slli	t0, t0, 32
	or	a4, a4, t0
	lbu	t0, 21(a1)
	slli	t0, t0, 40
	or	a4, a4, t0
	lbu	t0, 22(a1)
	slli	t0, t0, 48
	or	a4, a4, t0
	lbu	t0, 23(a1)
	slli	t0, t0, 56
	or	a4, a4, t0
L_ualn_ld31_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a5, 24(a1)
#else
	andi	t0, a1, 7
	bnez	t0, L_ualn_ld32_w
	ld	a5, 24(a1)
	j	L_ualn_ld32_e
L_ualn_ld32_w:
	andi	t0, t0, 3
	bnez	t0, L_ualn_ld32_h
	lwu	a5, 24(a1)
	lwu	t0, 28(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	j	L_ualn_ld32_e
L_ualn_ld32_h:
	andi	t0, t0, 1
	bnez	t0, L_ualn_ld32_b
	lhu	a5, 24(a1)
	lhu	t0, 26(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lhu	t0, 28(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lhu	t0, 30(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	j	L_ualn_ld32_e
L_ualn_ld32_b:
	lbu	a5, 24(a1)
	lbu	t0, 25(a1)
	slli	t0, t0, 8
	or	a5, a5, t0
	lbu	t0, 26(a1)
	slli	t0, t0, 16
	or	a5, a5, t0
	lbu	t0, 27(a1)
	slli	t0, t0, 24
	or	a5, a5, t0
	lbu	t0, 28(a1)
	slli	t0, t0, 32
	or	a5, a5, t0
	lbu	t0, 29(a1)
	slli	t0, t0, 40
	or	a5, a5, t0
	lbu	t0, 30(a1)
	slli	t0, t0, 48
	or	a5, a5, t0
	lbu	t0, 31(a1)
	slli	t0, t0, 56
	or	a5, a5, t0
L_ualn_ld32_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	and	t2, a4, s9
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t3, a5, a4, 44
	.word	0x76c7de33
#else
	srli	t3, a4, 44
	slli	t0, a5, 20
	or	t3, t3, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	t3, t3, s9
	srli	t4, a5, 24
	and	t4, t4, s10
	or	t4, t4, s11
	sd	t2, 8(sp)
	sd	t3, 40(sp)
	sd	t4, 72(sp)
	addi	t0, sp, 0
		vle64.v	v14, (t0)
	addi	t0, sp, 32
		vle64.v	v16, (t0)
	addi	t0, sp, 64
		vle64.v	v18, (t0)
	vmul.vv	v20, v14, v2
	vmulhu.vv	v22, v14, v2
	vmul.vv	v24, v16, v10
	vmulhu.vv	v26, v16, v10
	vmadc.vv	v0, v20, v24
	vadd.vv	v20, v20, v24
	vadd.vv	v22, v22, v26
	vadc.vvm	v22, v22, v12, v0
	vmul.vv	v24, v18, v8
	vmulhu.vv	v26, v18, v8
	vmadc.vv	v0, v20, v24
	vadd.vv	v20, v20, v24
	vadd.vv	v22, v22, v26
	vadc.vvm	v22, v22, v12, v0
	vslidedown.vi	v28, v20, 1
	vslidedown.vi	v30, v22, 1
	vmadc.vv	v0, v20, v28
	vadd.vv	v20, v20, v28
	vadd.vv	v22, v22, v30
	vadc.vvm	v22, v22, v12, v0
	vmv.x.s	t2, v20
	vmv.x.s	t3, v22
	vmul.vv	v20, v14, v4
	vmulhu.vv	v22, v14, v4
	vmul.vv	v24, v16, v2
	vmulhu.vv	v26, v16, v2
	vmadc.vv	v0, v20, v24
	vadd.vv	v20, v20, v24
	vadd.vv	v22, v22, v26
	vadc.vvm	v22, v22, v12, v0
	vmul.vv	v24, v18, v10
	vmulhu.vv	v26, v18, v10
	vmadc.vv	v0, v20, v24
	vadd.vv	v20, v20, v24
	vadd.vv	v22, v22, v26
	vadc.vvm	v22, v22, v12, v0
	vslidedown.vi	v28, v20, 1
	vslidedown.vi	v30, v22, 1
	vmadc.vv	v0, v20, v28
	vadd.vv	v20, v20, v28
	vadd.vv	v22, v22, v30
	vadc.vvm	v22, v22, v12, v0
	vmv.x.s	t4, v20
	vmv.x.s	t5, v22
	vmul.vv	v20, v14, v6
	vmulhu.vv	v22, v14, v6
	vmul.vv	v24, v16, v4
	vmulhu.vv	v26, v16, v4
	vmadc.vv	v0, v20, v24
	vadd.vv	v20, v20, v24
	vadd.vv	v22, v22, v26
	vadc.vvm	v22, v22, v12, v0
	vmul.vv	v24, v18, v2
	vmulhu.vv	v26, v18, v2
	vmadc.vv	v0, v20, v24
	vadd.vv	v20, v20, v24
	vadd.vv	v22, v22, v26
	vadc.vvm	v22, v22, v12, v0
	vslidedown.vi	v28, v20, 1
	vslidedown.vi	v30, v22, 1
	vmadc.vv	v0, v20, v28
	vadd.vv	v20, v20, v28
	vadd.vv	v22, v22, v30
	vadc.vvm	v22, v22, v12, v0
	vmv.x.s	t6, v20
	vmv.x.s	a3, v22
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t1, t3, t2, 44
	.word	0x3ece5333
#else
	srli	t1, t2, 44
	slli	t0, t3, 20
	or	t1, t1, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	s6, t2, s9
	add	t4, t4, t1
	sltu	t0, t4, t1
	add	t5, t5, t0
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t1, t5, t4, 44
	.word	0xeecf5333
#else
	srli	t1, t4, 44
	slli	t0, t5, 20
	or	t1, t1, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	s7, t4, s9
	add	t6, t6, t1
	sltu	t0, t6, t1
	add	a3, a3, t0
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t1, a3, t6, 42
	.word	0xfea6d333
#else
	srli	t1, t6, 42
	slli	t0, a3, 22
	or	t1, t1, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	s8, t6, s10
	slli	t0, t1, 2
	add	t1, t1, t0
	add	s6, s6, t1
	srli	t1, s6, 44
	and	s6, s6, s9
	add	s7, s7, t1
	addi	a1, a1, 32
	addi	a2, a2, -32
	li	t0, 32
	bgeu	a2, t0, L_poly1305_riscv64_blocks_vloop
L_poly1305_riscv64_blocks_vskip:
	addi	sp, sp, 96
	# Remaining < 32: one block via scalar loop, else store h and finish
	li	t0, 16
	bgeu	a2, t0, L_poly1305_riscv64_blocks_loop
	sd	s6, 24(a0)
	sd	s7, 32(a0)
	sd	s8, 40(a0)
	j	L_poly1305_riscv64_blocks_done
#endif /* WOLFSSL_RISCV_VECTOR */
L_poly1305_riscv64_blocks_loop:
	# Add message block into h (split 44,44,42)
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	t3, 0(a1)
#else
	andi	t1, a1, 7
	bnez	t1, L_ualn_ld33_w
	ld	t3, 0(a1)
	j	L_ualn_ld33_e
L_ualn_ld33_w:
	andi	t1, t1, 3
	bnez	t1, L_ualn_ld33_h
	lwu	t3, 0(a1)
	lwu	t1, 4(a1)
	slli	t1, t1, 32
	or	t3, t3, t1
	j	L_ualn_ld33_e
L_ualn_ld33_h:
	andi	t1, t1, 1
	bnez	t1, L_ualn_ld33_b
	lhu	t3, 0(a1)
	lhu	t1, 2(a1)
	slli	t1, t1, 16
	or	t3, t3, t1
	lhu	t1, 4(a1)
	slli	t1, t1, 32
	or	t3, t3, t1
	lhu	t1, 6(a1)
	slli	t1, t1, 48
	or	t3, t3, t1
	j	L_ualn_ld33_e
L_ualn_ld33_b:
	lbu	t3, 0(a1)
	lbu	t1, 1(a1)
	slli	t1, t1, 8
	or	t3, t3, t1
	lbu	t1, 2(a1)
	slli	t1, t1, 16
	or	t3, t3, t1
	lbu	t1, 3(a1)
	slli	t1, t1, 24
	or	t3, t3, t1
	lbu	t1, 4(a1)
	slli	t1, t1, 32
	or	t3, t3, t1
	lbu	t1, 5(a1)
	slli	t1, t1, 40
	or	t3, t3, t1
	lbu	t1, 6(a1)
	slli	t1, t1, 48
	or	t3, t3, t1
	lbu	t1, 7(a1)
	slli	t1, t1, 56
	or	t3, t3, t1
L_ualn_ld33_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	t4, 8(a1)
#else
	andi	t1, a1, 7
	bnez	t1, L_ualn_ld34_w
	ld	t4, 8(a1)
	j	L_ualn_ld34_e
L_ualn_ld34_w:
	andi	t1, t1, 3
	bnez	t1, L_ualn_ld34_h
	lwu	t4, 8(a1)
	lwu	t1, 12(a1)
	slli	t1, t1, 32
	or	t4, t4, t1
	j	L_ualn_ld34_e
L_ualn_ld34_h:
	andi	t1, t1, 1
	bnez	t1, L_ualn_ld34_b
	lhu	t4, 8(a1)
	lhu	t1, 10(a1)
	slli	t1, t1, 16
	or	t4, t4, t1
	lhu	t1, 12(a1)
	slli	t1, t1, 32
	or	t4, t4, t1
	lhu	t1, 14(a1)
	slli	t1, t1, 48
	or	t4, t4, t1
	j	L_ualn_ld34_e
L_ualn_ld34_b:
	lbu	t4, 8(a1)
	lbu	t1, 9(a1)
	slli	t1, t1, 8
	or	t4, t4, t1
	lbu	t1, 10(a1)
	slli	t1, t1, 16
	or	t4, t4, t1
	lbu	t1, 11(a1)
	slli	t1, t1, 24
	or	t4, t4, t1
	lbu	t1, 12(a1)
	slli	t1, t1, 32
	or	t4, t4, t1
	lbu	t1, 13(a1)
	slli	t1, t1, 40
	or	t4, t4, t1
	lbu	t1, 14(a1)
	slli	t1, t1, 48
	or	t4, t4, t1
	lbu	t1, 15(a1)
	slli	t1, t1, 56
	or	t4, t4, t1
L_ualn_ld34_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	and	t0, t3, s9
	add	s6, s6, t0
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t0, t4, t3, 44
	.word	0xe6ced2b3
#else
	srli	t0, t3, 44
	slli	t1, t4, 20
	or	t0, t0, t1
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	t0, t0, s9
	add	s7, s7, t0
	srli	t0, t4, 24
	and	t0, t0, s10
	or	t0, t0, s11
	add	s8, s8, t0
	# d0 = h0*r0 + h1*s2 + h2*s1
	mul	t5, s6, s1
	mulhu	t6, s6, s1
	mul	t0, s7, s5
	mulhu	t1, s7, s5
	add	t5, t5, t0
	sltu	t2, t5, t0
	add	t6, t6, t1
	add	t6, t6, t2
	mul	t0, s8, s4
	mulhu	t1, s8, s4
	add	t5, t5, t0
	sltu	t2, t5, t0
	add	t6, t6, t1
	add	t6, t6, t2
	# d1 = h0*r1 + h1*r0 + h2*s2
	mul	a3, s6, s2
	mulhu	a4, s6, s2
	mul	t0, s7, s1
	mulhu	t1, s7, s1
	add	a3, a3, t0
	sltu	t2, a3, t0
	add	a4, a4, t1
	add	a4, a4, t2
	mul	t0, s8, s5
	mulhu	t1, s8, s5
	add	a3, a3, t0
	sltu	t2, a3, t0
	add	a4, a4, t1
	add	a4, a4, t2
	# d2 = h0*r2 + h1*r1 + h2*r0
	mul	a5, s6, s3
	mulhu	a6, s6, s3
	mul	t0, s7, s2
	mulhu	t1, s7, s2
	add	a5, a5, t0
	sltu	t2, a5, t0
	add	a6, a6, t1
	add	a6, a6, t2
	mul	t0, s8, s1
	mulhu	t1, s8, s1
	add	a5, a5, t0
	sltu	t2, a5, t0
	add	a6, a6, t1
	add	a6, a6, t2
	# Reduce: carry chain across 44/44/42-bit limbs
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t2, t6, t5, 44
	.word	0xf6cfd3b3
#else
	srli	t2, t5, 44
	slli	t0, t6, 20
	or	t2, t2, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	s6, t5, s9
	add	a3, a3, t2
	sltu	t0, a3, t2
	add	a4, a4, t0
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t2, a4, a3, 44
	.word	0x6ec753b3
#else
	srli	t2, a3, 44
	slli	t0, a4, 20
	or	t2, t2, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	s7, a3, s9
	add	a5, a5, t2
	sltu	t0, a5, t2
	add	a6, a6, t0
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri t2, a6, a5, 42
	.word	0x7ea853b3
#else
	srli	t2, a5, 42
	slli	t0, a6, 22
	or	t2, t2, t0
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	s8, a5, s10
	slli	t0, t2, 2
	add	t2, t2, t0
	add	s6, s6, t2
	srli	t2, s6, 44
	and	s6, s6, s9
	add	s7, s7, t2
	addi	a1, a1, 16
	addi	a2, a2, -16
	li	t0, 16
	bgeu	a2, t0, L_poly1305_riscv64_blocks_loop
	# Store h back
	sd	s6, 24(a0)
	sd	s7, 32(a0)
	sd	s8, 40(a0)
L_poly1305_riscv64_blocks_done:
	ld	s1, 8(sp)
	ld	s2, 16(sp)
	ld	s3, 24(sp)
	ld	s4, 32(sp)
	ld	s5, 40(sp)
	ld	s6, 48(sp)
	ld	s7, 56(sp)
	ld	s8, 64(sp)
	ld	s9, 72(sp)
	ld	s10, 80(sp)
	ld	s11, 88(sp)
	addi	sp, sp, 96
	ret
	.size	poly1305_blocks_riscv64,.-poly1305_blocks_riscv64
	.text
	.globl	poly1305_final_riscv64
	.type	poly1305_final_riscv64,@function
	.align	2
poly1305_final_riscv64:
	ld	t0, 24(a0)
	ld	t1, 32(a0)
	ld	t2, 40(a0)
	li	t6, 17592186044415
	li	a2, 4398046511103
	# Fully carry h
	srli	a3, t1, 44
	and	t1, t1, t6
	add	t2, t2, a3
	srli	a3, t2, 42
	and	t2, t2, a2
	slli	a4, a3, 2
	add	a3, a3, a4
	add	t0, t0, a3
	srli	a3, t0, 44
	and	t0, t0, t6
	add	t1, t1, a3
	srli	a3, t1, 44
	and	t1, t1, t6
	add	t2, t2, a3
	srli	a3, t2, 42
	and	t2, t2, a2
	slli	a4, a3, 2
	add	a3, a3, a4
	add	t0, t0, a3
	srli	a3, t0, 44
	and	t0, t0, t6
	add	t1, t1, a3
	# g = h + -p
	addi	t3, t0, 5
	srli	a3, t3, 44
	and	t3, t3, t6
	add	t4, t1, a3
	srli	a3, t4, 44
	and	t4, t4, t6
	li	a4, 4398046511104
	add	t5, t2, a3
	sub	t5, t5, a4
	# Select h if h < p else g (constant time)
	srli	a3, t5, 63
	addi	a3, a3, -1
	and	t3, t3, a3
	and	t4, t4, a3
	and	t5, t5, a3
	not	a6, a3
	and	t0, t0, a6
	or	t0, t0, t3
	and	t1, t1, a6
	or	t1, t1, t4
	and	t2, t2, a6
	or	t2, t2, t5
	# h += pad
	ld	a4, 48(a0)
	ld	a7, 56(a0)
	and	a5, a4, t6
	add	t0, t0, a5
	srli	a3, t0, 44
	and	t0, t0, t6
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY
	# fsri a5, a7, a4, 44
	.word	0x76c8d7b3
#else
	srli	a5, a4, 44
	slli	t3, a7, 20
	or	a5, a5, t3
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION_TERNARY */
	and	a5, a5, t6
	add	t1, t1, a5
	add	t1, t1, a3
	srli	a3, t1, 44
	and	t1, t1, t6
	srli	a5, a7, 24
	and	a5, a5, a2
	add	t2, t2, a5
	add	t2, t2, a3
	and	t2, t2, a2
	# mac = (h mod 2^128) packed little-endian
	slli	a4, t1, 44
	or	t0, t0, a4
	srli	a5, t1, 20
	slli	a7, t2, 24
	or	t1, a5, a7
	sd	t0, 0(a1)
	sd	t1, 8(a1)
	# Zero out the state
	sd	zero, 24(a0)
	sd	zero, 32(a0)
	sd	zero, 40(a0)
	sd	zero, 0(a0)
	sd	zero, 8(a0)
	sd	zero, 16(a0)
	sd	zero, 48(a0)
	sd	zero, 56(a0)
	ret
	.size	poly1305_final_riscv64,.-poly1305_final_riscv64
#endif /* HAVE_POLY1305 */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_RISCV_ASM_INLINE */
#endif /* WOLFSSL_RISCV_ASM */
