/* riscv-64-sha256-asm
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
 *   ruby ./sha2/sha256.rb riscv64 \
 *       ../wolfssl/wolfcrypt/src/port/riscv64/riscv-64-sha256-asm.S
 */
#ifdef WOLFSSL_RISCV_ASM
#ifndef WOLFSSL_RISCV_ASM_INLINE
#if  !defined(NO_SHA256) || defined(WOLFSSL_SHA224)
#ifdef WOLFSSL_RISCV_VECTOR_CRYPTO_ASM
	.section	.rodata
	.type	L_SHA256_transform_riscv_vector_len_k, %object
	.size	L_SHA256_transform_riscv_vector_len_k, 256
	# 4-byte aligned, 32-bit aligned
	.align	2
L_SHA256_transform_riscv_vector_len_k:
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
	.text
	.globl	Transform_Sha256_Len_riscv_vector
	.type	Transform_Sha256_Len_riscv_vector,@function
	.align	2
Transform_Sha256_Len_riscv_vector:
	addi	sp, sp, -32
	la	t0, L_SHA256_transform_riscv_vector_len_k
	.option arch, +v, +zvkb, +zvknha
	# VLEN == 128: 4 x 32-bit elements per vector register
	vsetivli	zero, 4, e32, m1, ta, ma
	# Permute standard digest a..h into {f,e,b,a},{h,g,d,c} order
	lw	t2, 20(a0)
	sw	t2, 0(sp)
	lw	t2, 16(a0)
	sw	t2, 4(sp)
	lw	t2, 4(a0)
	sw	t2, 8(sp)
	lw	t2, 0(a0)
	sw	t2, 12(sp)
	lw	t2, 28(a0)
	sw	t2, 16(sp)
	lw	t2, 24(a0)
	sw	t2, 20(sp)
	lw	t2, 12(a0)
	sw	t2, 24(sp)
	lw	t2, 8(a0)
	sw	t2, 28(sp)
	vl2re32.v	v4, (sp)
	# Load K into vector registers
	mv	t1, t0
	vl8re32.v	v8, (t1)
	addi	t1, t0, 128
	vl8re32.v	v16, (t1)
	srli	a2, a2, 6
	# Start of loop processing a block
L_SHA256_transform_riscv_vector_len_begin:
	# Save state to add back after compression
	vmv.v.v	v30, v4
	vmv.v.v	v31, v5
	# Load 16 W into 4 vectors of 4 32-bit words
	mv	t1, a1
	vl4re32.v	v0, (t1)
	vrev8.v	v0, v0
	vrev8.v	v1, v1
	vrev8.v	v2, v2
	vrev8.v	v3, v3
	vadd.vv	v7, v0, v8
	vmv.x.s	t2, v1
	vsha2cl.vv	v5, v4, v7
	vmv.v.v	v6, v2
	vsha2ch.vv	v4, v5, v7
	vmv.s.x	v6, t2
	vsha2ms.vv	v0, v6, v3
	vadd.vv	v7, v1, v9
	vmv.x.s	t2, v2
	vsha2cl.vv	v5, v4, v7
	vmv.v.v	v6, v3
	vsha2ch.vv	v4, v5, v7
	vmv.s.x	v6, t2
	vsha2ms.vv	v1, v6, v0
	vadd.vv	v7, v2, v10
	vmv.x.s	t2, v3
	vsha2cl.vv	v5, v4, v7
	vmv.v.v	v6, v0
	vsha2ch.vv	v4, v5, v7
	vmv.s.x	v6, t2
	vsha2ms.vv	v2, v6, v1
	vadd.vv	v7, v3, v11
	vmv.x.s	t2, v0
	vsha2cl.vv	v5, v4, v7
	vmv.v.v	v6, v1
	vsha2ch.vv	v4, v5, v7
	vmv.s.x	v6, t2
	vsha2ms.vv	v3, v6, v2
	vadd.vv	v7, v0, v12
	vmv.x.s	t2, v1
	vsha2cl.vv	v5, v4, v7
	vmv.v.v	v6, v2
	vsha2ch.vv	v4, v5, v7
	vmv.s.x	v6, t2
	vsha2ms.vv	v0, v6, v3
	vadd.vv	v7, v1, v13
	vmv.x.s	t2, v2
	vsha2cl.vv	v5, v4, v7
	vmv.v.v	v6, v3
	vsha2ch.vv	v4, v5, v7
	vmv.s.x	v6, t2
	vsha2ms.vv	v1, v6, v0
	vadd.vv	v7, v2, v14
	vmv.x.s	t2, v3
	vsha2cl.vv	v5, v4, v7
	vmv.v.v	v6, v0
	vsha2ch.vv	v4, v5, v7
	vmv.s.x	v6, t2
	vsha2ms.vv	v2, v6, v1
	vadd.vv	v7, v3, v15
	vmv.x.s	t2, v0
	vsha2cl.vv	v5, v4, v7
	vmv.v.v	v6, v1
	vsha2ch.vv	v4, v5, v7
	vmv.s.x	v6, t2
	vsha2ms.vv	v3, v6, v2
	vadd.vv	v7, v0, v16
	vmv.x.s	t2, v1
	vsha2cl.vv	v5, v4, v7
	vmv.v.v	v6, v2
	vsha2ch.vv	v4, v5, v7
	vmv.s.x	v6, t2
	vsha2ms.vv	v0, v6, v3
	vadd.vv	v7, v1, v17
	vmv.x.s	t2, v2
	vsha2cl.vv	v5, v4, v7
	vmv.v.v	v6, v3
	vsha2ch.vv	v4, v5, v7
	vmv.s.x	v6, t2
	vsha2ms.vv	v1, v6, v0
	vadd.vv	v7, v2, v18
	vmv.x.s	t2, v3
	vsha2cl.vv	v5, v4, v7
	vmv.v.v	v6, v0
	vsha2ch.vv	v4, v5, v7
	vmv.s.x	v6, t2
	vsha2ms.vv	v2, v6, v1
	vadd.vv	v7, v3, v19
	vmv.x.s	t2, v0
	vsha2cl.vv	v5, v4, v7
	vmv.v.v	v6, v1
	vsha2ch.vv	v4, v5, v7
	vmv.s.x	v6, t2
	vsha2ms.vv	v3, v6, v2
	vadd.vv	v7, v0, v20
	vsha2cl.vv	v5, v4, v7
	vsha2ch.vv	v4, v5, v7
	vadd.vv	v7, v1, v21
	vsha2cl.vv	v5, v4, v7
	vsha2ch.vv	v4, v5, v7
	vadd.vv	v7, v2, v22
	vsha2cl.vv	v5, v4, v7
	vsha2ch.vv	v4, v5, v7
	vadd.vv	v7, v3, v23
	vsha2cl.vv	v5, v4, v7
	vsha2ch.vv	v4, v5, v7
	vadd.vv	v4, v4, v30
	vadd.vv	v5, v5, v31
	addi	a2, a2, -1
	addi	a1, a1, 64
	bnez	a2, L_SHA256_transform_riscv_vector_len_begin
	# Store state back in standard digest order a..h
	vs2r.v	v4, (sp)
	lw	t2, 12(sp)
	sw	t2, 0(a0)
	lw	t2, 8(sp)
	sw	t2, 4(a0)
	lw	t2, 28(sp)
	sw	t2, 8(a0)
	lw	t2, 24(sp)
	sw	t2, 12(a0)
	lw	t2, 4(sp)
	sw	t2, 16(a0)
	lw	t2, 0(sp)
	sw	t2, 20(a0)
	lw	t2, 20(sp)
	sw	t2, 24(a0)
	lw	t2, 16(sp)
	sw	t2, 28(a0)
	addi	sp, sp, 32
	ret
	.size	Transform_Sha256_Len_riscv_vector,.-Transform_Sha256_Len_riscv_vector
#elif defined(WOLFSSL_RISCV_SCALAR_CRYPTO_ASM)
	.section	.rodata
	.type	L_SHA256_transform_riscv_crypto_len_k, %object
	.size	L_SHA256_transform_riscv_crypto_len_k, 256
	# 4-byte aligned, 32-bit aligned
	.align	2
L_SHA256_transform_riscv_crypto_len_k:
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
	.text
	.globl	Transform_Sha256_Len_riscv_crypto
	.type	Transform_Sha256_Len_riscv_crypto,@function
	.align	2
Transform_Sha256_Len_riscv_crypto:
	addi	sp, sp, -96
	sd	s0, 0(sp)
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
	la	t0, L_SHA256_transform_riscv_crypto_len_k
	.option arch, +zknh
	# Load digest into working variables
	ld	t1, 0(a0)
	ld	t3, 8(a0)
	ld	t5, 16(a0)
	ld	a3, 24(a0)
	srli	t2, t1, 32
	srli	t4, t3, 32
	srli	t6, t5, 32
	srli	a4, a3, 32
	srli	a2, a2, 4
	# Start of loop processing a block
L_SHA256_transform_riscv_crypto_len_begin:
	# Load W - big endian into two-words-per-register
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) || defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lbu	s6, 0(a1)
	lbu	s7, 1(a1)
	lbu	s8, 2(a1)
	lbu	a5, 3(a1)
	slli	s6, s6, 24
	slli	s7, s7, 16
	slli	s8, s8, 8
	or	a5, a5, s6
	or	a5, a5, s7
	or	a5, a5, s8
	lbu	s6, 4(a1)
	lbu	s7, 5(a1)
	lbu	s8, 6(a1)
	lbu	s9, 7(a1)
	slli	s6, s6, 56
	slli	s7, s7, 48
	slli	s8, s8, 40
	slli	s9, s9, 32
	or	a5, a5, s6
	or	a5, a5, s7
	or	a5, a5, s8
	or	a5, a5, s9
	lbu	s6, 8(a1)
	lbu	s7, 9(a1)
	lbu	s8, 10(a1)
	lbu	a6, 11(a1)
	slli	s6, s6, 24
	slli	s7, s7, 16
	slli	s8, s8, 8
	or	a6, a6, s6
	or	a6, a6, s7
	or	a6, a6, s8
	lbu	s6, 12(a1)
	lbu	s7, 13(a1)
	lbu	s8, 14(a1)
	lbu	s9, 15(a1)
	slli	s6, s6, 56
	slli	s7, s7, 48
	slli	s8, s8, 40
	slli	s9, s9, 32
	or	a6, a6, s6
	or	a6, a6, s7
	or	a6, a6, s8
	or	a6, a6, s9
	lbu	s6, 16(a1)
	lbu	s7, 17(a1)
	lbu	s8, 18(a1)
	lbu	a7, 19(a1)
	slli	s6, s6, 24
	slli	s7, s7, 16
	slli	s8, s8, 8
	or	a7, a7, s6
	or	a7, a7, s7
	or	a7, a7, s8
	lbu	s6, 20(a1)
	lbu	s7, 21(a1)
	lbu	s8, 22(a1)
	lbu	s9, 23(a1)
	slli	s6, s6, 56
	slli	s7, s7, 48
	slli	s8, s8, 40
	slli	s9, s9, 32
	or	a7, a7, s6
	or	a7, a7, s7
	or	a7, a7, s8
	or	a7, a7, s9
	lbu	s6, 24(a1)
	lbu	s7, 25(a1)
	lbu	s8, 26(a1)
	lbu	s1, 27(a1)
	slli	s6, s6, 24
	slli	s7, s7, 16
	slli	s8, s8, 8
	or	s1, s1, s6
	or	s1, s1, s7
	or	s1, s1, s8
	lbu	s6, 28(a1)
	lbu	s7, 29(a1)
	lbu	s8, 30(a1)
	lbu	s9, 31(a1)
	slli	s6, s6, 56
	slli	s7, s7, 48
	slli	s8, s8, 40
	slli	s9, s9, 32
	or	s1, s1, s6
	or	s1, s1, s7
	or	s1, s1, s8
	or	s1, s1, s9
	lbu	s6, 32(a1)
	lbu	s7, 33(a1)
	lbu	s8, 34(a1)
	lbu	s2, 35(a1)
	slli	s6, s6, 24
	slli	s7, s7, 16
	slli	s8, s8, 8
	or	s2, s2, s6
	or	s2, s2, s7
	or	s2, s2, s8
	lbu	s6, 36(a1)
	lbu	s7, 37(a1)
	lbu	s8, 38(a1)
	lbu	s9, 39(a1)
	slli	s6, s6, 56
	slli	s7, s7, 48
	slli	s8, s8, 40
	slli	s9, s9, 32
	or	s2, s2, s6
	or	s2, s2, s7
	or	s2, s2, s8
	or	s2, s2, s9
	lbu	s6, 40(a1)
	lbu	s7, 41(a1)
	lbu	s8, 42(a1)
	lbu	s3, 43(a1)
	slli	s6, s6, 24
	slli	s7, s7, 16
	slli	s8, s8, 8
	or	s3, s3, s6
	or	s3, s3, s7
	or	s3, s3, s8
	lbu	s6, 44(a1)
	lbu	s7, 45(a1)
	lbu	s8, 46(a1)
	lbu	s9, 47(a1)
	slli	s6, s6, 56
	slli	s7, s7, 48
	slli	s8, s8, 40
	slli	s9, s9, 32
	or	s3, s3, s6
	or	s3, s3, s7
	or	s3, s3, s8
	or	s3, s3, s9
	lbu	s6, 48(a1)
	lbu	s7, 49(a1)
	lbu	s8, 50(a1)
	lbu	s4, 51(a1)
	slli	s6, s6, 24
	slli	s7, s7, 16
	slli	s8, s8, 8
	or	s4, s4, s6
	or	s4, s4, s7
	or	s4, s4, s8
	lbu	s6, 52(a1)
	lbu	s7, 53(a1)
	lbu	s8, 54(a1)
	lbu	s9, 55(a1)
	slli	s6, s6, 56
	slli	s7, s7, 48
	slli	s8, s8, 40
	slli	s9, s9, 32
	or	s4, s4, s6
	or	s4, s4, s7
	or	s4, s4, s8
	or	s4, s4, s9
	lbu	s6, 56(a1)
	lbu	s7, 57(a1)
	lbu	s8, 58(a1)
	lbu	s5, 59(a1)
	slli	s6, s6, 24
	slli	s7, s7, 16
	slli	s8, s8, 8
	or	s5, s5, s6
	or	s5, s5, s7
	or	s5, s5, s8
	lbu	s6, 60(a1)
	lbu	s7, 61(a1)
	lbu	s8, 62(a1)
	lbu	s9, 63(a1)
	slli	s6, s6, 56
	slli	s7, s7, 48
	slli	s8, s8, 40
	slli	s9, s9, 32
	or	s5, s5, s6
	or	s5, s5, s7
	or	s5, s5, s8
	or	s5, s5, s9
#else
	ld	a5, 0(a1)
	# rev8 a5, a5
	.word	0x6b87d793
	# rori a5, a5, 32
	.word	0x6207d793
	ld	a6, 8(a1)
	# rev8 a6, a6
	.word	0x6b885813
	# rori a6, a6, 32
	.word	0x62085813
	ld	a7, 16(a1)
	# rev8 a7, a7
	.word	0x6b88d893
	# rori a7, a7, 32
	.word	0x6208d893
	ld	s1, 24(a1)
	# rev8 s1, s1
	.word	0x6b84d493
	# rori s1, s1, 32
	.word	0x6204d493
	ld	s2, 32(a1)
	# rev8 s2, s2
	.word	0x6b895913
	# rori s2, s2, 32
	.word	0x62095913
	ld	s3, 40(a1)
	# rev8 s3, s3
	.word	0x6b89d993
	# rori s3, s3, 32
	.word	0x6209d993
	ld	s4, 48(a1)
	# rev8 s4, s4
	.word	0x6b8a5a13
	# rori s4, s4, 32
	.word	0x620a5a13
	ld	s5, 56(a1)
	# rev8 s5, s5
	.word	0x6b8ada93
	# rori s5, s5, 32
	.word	0x620ada93
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) || defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	addi	a2, a2, -1
L_SHA256_transform_riscv_crypto_len_inner:
	ld	s8, 0(t0)
	mv	s6, t5
	mv	s7, t1
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t6, a3
	xor	s10, t1, t2
	xor	s11, t2, t3
	and	s0, s0, t5
	addw	a4, a4, s6
	and	s11, s11, s10
	xor	s0, s0, a3
	addw	s10, s8, a5
	xor	s11, s11, t2
	addw	a4, a4, s0
	addw	a4, a4, s10
	addw	s11, s7, s11
	addw	t4, t4, a4
	addw	a4, a4, s11
	srli	s8, s8, 32
	srli	s9, a5, 32
	mv	s6, t4
	mv	s7, a4
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t5, t6
	xor	s10, a4, t1
	xor	s11, t1, t2
	and	s0, s0, t4
	addw	a3, a3, s6
	and	s11, s11, s10
	xor	s0, s0, t6
	addw	s10, s8, s9
	xor	s11, s11, t1
	addw	a3, a3, s0
	addw	a3, a3, s10
	addw	s11, s7, s11
	addw	t3, t3, a3
	addw	a3, a3, s11
	srli	s10, a5, 32
	srli	s0, s2, 32
	sha256sig0	s6, s10
	sha256sig1	s7, s5
	addw	s7, s7, s0
	addw	a5, a5, s6
	srli	s11, s5, 32
	addw	a5, s7, a5
	sha256sig0	s8, a6
	sha256sig1	s9, s11
	addw	s9, s9, s3
	addw	s11, s8, s10
	addw	s9, s9, s11
	slli	a5, a5, 32
	slli	s9, s9, 32
	srli	a5, a5, 32
	or	a5, a5, s9
	ld	s8, 8(t0)
	mv	s6, t3
	mv	s7, a3
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t4, t5
	xor	s10, a3, a4
	xor	s11, a4, t1
	and	s0, s0, t3
	addw	t6, t6, s6
	and	s11, s11, s10
	xor	s0, s0, t5
	addw	s10, s8, a6
	xor	s11, s11, a4
	addw	t6, t6, s0
	addw	t6, t6, s10
	addw	s11, s7, s11
	addw	t2, t2, t6
	addw	t6, t6, s11
	srli	s8, s8, 32
	srli	s9, a6, 32
	mv	s6, t2
	mv	s7, t6
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t3, t4
	xor	s10, t6, a3
	xor	s11, a3, a4
	and	s0, s0, t2
	addw	t5, t5, s6
	and	s11, s11, s10
	xor	s0, s0, t4
	addw	s10, s8, s9
	xor	s11, s11, a3
	addw	t5, t5, s0
	addw	t5, t5, s10
	addw	s11, s7, s11
	addw	t1, t1, t5
	addw	t5, t5, s11
	srli	s10, a6, 32
	srli	s0, s3, 32
	sha256sig0	s6, s10
	sha256sig1	s7, a5
	addw	s7, s7, s0
	addw	a6, a6, s6
	srli	s11, a5, 32
	addw	a6, s7, a6
	sha256sig0	s8, a7
	sha256sig1	s9, s11
	addw	s9, s9, s4
	addw	s11, s8, s10
	addw	s9, s9, s11
	slli	a6, a6, 32
	slli	s9, s9, 32
	srli	a6, a6, 32
	or	a6, a6, s9
	ld	s8, 16(t0)
	mv	s6, t1
	mv	s7, t5
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t2, t3
	xor	s10, t5, t6
	xor	s11, t6, a3
	and	s0, s0, t1
	addw	t4, t4, s6
	and	s11, s11, s10
	xor	s0, s0, t3
	addw	s10, s8, a7
	xor	s11, s11, t6
	addw	t4, t4, s0
	addw	t4, t4, s10
	addw	s11, s7, s11
	addw	a4, a4, t4
	addw	t4, t4, s11
	srli	s8, s8, 32
	srli	s9, a7, 32
	mv	s6, a4
	mv	s7, t4
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t1, t2
	xor	s10, t4, t5
	xor	s11, t5, t6
	and	s0, s0, a4
	addw	t3, t3, s6
	and	s11, s11, s10
	xor	s0, s0, t2
	addw	s10, s8, s9
	xor	s11, s11, t5
	addw	t3, t3, s0
	addw	t3, t3, s10
	addw	s11, s7, s11
	addw	a3, a3, t3
	addw	t3, t3, s11
	srli	s10, a7, 32
	srli	s0, s4, 32
	sha256sig0	s6, s10
	sha256sig1	s7, a6
	addw	s7, s7, s0
	addw	a7, a7, s6
	srli	s11, a6, 32
	addw	a7, s7, a7
	sha256sig0	s8, s1
	sha256sig1	s9, s11
	addw	s9, s9, s5
	addw	s11, s8, s10
	addw	s9, s9, s11
	slli	a7, a7, 32
	slli	s9, s9, 32
	srli	a7, a7, 32
	or	a7, a7, s9
	ld	s8, 24(t0)
	mv	s6, a3
	mv	s7, t3
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, a4, t1
	xor	s10, t3, t4
	xor	s11, t4, t5
	and	s0, s0, a3
	addw	t2, t2, s6
	and	s11, s11, s10
	xor	s0, s0, t1
	addw	s10, s8, s1
	xor	s11, s11, t4
	addw	t2, t2, s0
	addw	t2, t2, s10
	addw	s11, s7, s11
	addw	t6, t6, t2
	addw	t2, t2, s11
	srli	s8, s8, 32
	srli	s9, s1, 32
	mv	s6, t6
	mv	s7, t2
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, a3, a4
	xor	s10, t2, t3
	xor	s11, t3, t4
	and	s0, s0, t6
	addw	t1, t1, s6
	and	s11, s11, s10
	xor	s0, s0, a4
	addw	s10, s8, s9
	xor	s11, s11, t3
	addw	t1, t1, s0
	addw	t1, t1, s10
	addw	s11, s7, s11
	addw	t5, t5, t1
	addw	t1, t1, s11
	srli	s10, s1, 32
	srli	s0, s5, 32
	sha256sig0	s6, s10
	sha256sig1	s7, a7
	addw	s7, s7, s0
	addw	s1, s1, s6
	srli	s11, a7, 32
	addw	s1, s7, s1
	sha256sig0	s8, s2
	sha256sig1	s9, s11
	addw	s9, s9, a5
	addw	s11, s8, s10
	addw	s9, s9, s11
	slli	s1, s1, 32
	slli	s9, s9, 32
	srli	s1, s1, 32
	or	s1, s1, s9
	ld	s8, 32(t0)
	mv	s6, t5
	mv	s7, t1
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t6, a3
	xor	s10, t1, t2
	xor	s11, t2, t3
	and	s0, s0, t5
	addw	a4, a4, s6
	and	s11, s11, s10
	xor	s0, s0, a3
	addw	s10, s8, s2
	xor	s11, s11, t2
	addw	a4, a4, s0
	addw	a4, a4, s10
	addw	s11, s7, s11
	addw	t4, t4, a4
	addw	a4, a4, s11
	srli	s8, s8, 32
	srli	s9, s2, 32
	mv	s6, t4
	mv	s7, a4
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t5, t6
	xor	s10, a4, t1
	xor	s11, t1, t2
	and	s0, s0, t4
	addw	a3, a3, s6
	and	s11, s11, s10
	xor	s0, s0, t6
	addw	s10, s8, s9
	xor	s11, s11, t1
	addw	a3, a3, s0
	addw	a3, a3, s10
	addw	s11, s7, s11
	addw	t3, t3, a3
	addw	a3, a3, s11
	srli	s10, s2, 32
	srli	s0, a5, 32
	sha256sig0	s6, s10
	sha256sig1	s7, s1
	addw	s7, s7, s0
	addw	s2, s2, s6
	srli	s11, s1, 32
	addw	s2, s7, s2
	sha256sig0	s8, s3
	sha256sig1	s9, s11
	addw	s9, s9, a6
	addw	s11, s8, s10
	addw	s9, s9, s11
	slli	s2, s2, 32
	slli	s9, s9, 32
	srli	s2, s2, 32
	or	s2, s2, s9
	ld	s8, 40(t0)
	mv	s6, t3
	mv	s7, a3
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t4, t5
	xor	s10, a3, a4
	xor	s11, a4, t1
	and	s0, s0, t3
	addw	t6, t6, s6
	and	s11, s11, s10
	xor	s0, s0, t5
	addw	s10, s8, s3
	xor	s11, s11, a4
	addw	t6, t6, s0
	addw	t6, t6, s10
	addw	s11, s7, s11
	addw	t2, t2, t6
	addw	t6, t6, s11
	srli	s8, s8, 32
	srli	s9, s3, 32
	mv	s6, t2
	mv	s7, t6
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t3, t4
	xor	s10, t6, a3
	xor	s11, a3, a4
	and	s0, s0, t2
	addw	t5, t5, s6
	and	s11, s11, s10
	xor	s0, s0, t4
	addw	s10, s8, s9
	xor	s11, s11, a3
	addw	t5, t5, s0
	addw	t5, t5, s10
	addw	s11, s7, s11
	addw	t1, t1, t5
	addw	t5, t5, s11
	srli	s10, s3, 32
	srli	s0, a6, 32
	sha256sig0	s6, s10
	sha256sig1	s7, s2
	addw	s7, s7, s0
	addw	s3, s3, s6
	srli	s11, s2, 32
	addw	s3, s7, s3
	sha256sig0	s8, s4
	sha256sig1	s9, s11
	addw	s9, s9, a7
	addw	s11, s8, s10
	addw	s9, s9, s11
	slli	s3, s3, 32
	slli	s9, s9, 32
	srli	s3, s3, 32
	or	s3, s3, s9
	ld	s8, 48(t0)
	mv	s6, t1
	mv	s7, t5
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t2, t3
	xor	s10, t5, t6
	xor	s11, t6, a3
	and	s0, s0, t1
	addw	t4, t4, s6
	and	s11, s11, s10
	xor	s0, s0, t3
	addw	s10, s8, s4
	xor	s11, s11, t6
	addw	t4, t4, s0
	addw	t4, t4, s10
	addw	s11, s7, s11
	addw	a4, a4, t4
	addw	t4, t4, s11
	srli	s8, s8, 32
	srli	s9, s4, 32
	mv	s6, a4
	mv	s7, t4
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t1, t2
	xor	s10, t4, t5
	xor	s11, t5, t6
	and	s0, s0, a4
	addw	t3, t3, s6
	and	s11, s11, s10
	xor	s0, s0, t2
	addw	s10, s8, s9
	xor	s11, s11, t5
	addw	t3, t3, s0
	addw	t3, t3, s10
	addw	s11, s7, s11
	addw	a3, a3, t3
	addw	t3, t3, s11
	srli	s10, s4, 32
	srli	s0, a7, 32
	sha256sig0	s6, s10
	sha256sig1	s7, s3
	addw	s7, s7, s0
	addw	s4, s4, s6
	srli	s11, s3, 32
	addw	s4, s7, s4
	sha256sig0	s8, s5
	sha256sig1	s9, s11
	addw	s9, s9, s1
	addw	s11, s8, s10
	addw	s9, s9, s11
	slli	s4, s4, 32
	slli	s9, s9, 32
	srli	s4, s4, 32
	or	s4, s4, s9
	ld	s8, 56(t0)
	mv	s6, a3
	mv	s7, t3
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, a4, t1
	xor	s10, t3, t4
	xor	s11, t4, t5
	and	s0, s0, a3
	addw	t2, t2, s6
	and	s11, s11, s10
	xor	s0, s0, t1
	addw	s10, s8, s5
	xor	s11, s11, t4
	addw	t2, t2, s0
	addw	t2, t2, s10
	addw	s11, s7, s11
	addw	t6, t6, t2
	addw	t2, t2, s11
	srli	s8, s8, 32
	srli	s9, s5, 32
	mv	s6, t6
	mv	s7, t2
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, a3, a4
	xor	s10, t2, t3
	xor	s11, t3, t4
	and	s0, s0, t6
	addw	t1, t1, s6
	and	s11, s11, s10
	xor	s0, s0, a4
	addw	s10, s8, s9
	xor	s11, s11, t3
	addw	t1, t1, s0
	addw	t1, t1, s10
	addw	s11, s7, s11
	addw	t5, t5, t1
	addw	t1, t1, s11
	srli	s10, s5, 32
	srli	s0, s1, 32
	sha256sig0	s6, s10
	sha256sig1	s7, s4
	addw	s7, s7, s0
	addw	s5, s5, s6
	srli	s11, s4, 32
	addw	s5, s7, s5
	sha256sig0	s8, a5
	sha256sig1	s9, s11
	addw	s9, s9, s2
	addw	s11, s8, s10
	addw	s9, s9, s11
	slli	s5, s5, 32
	slli	s9, s9, 32
	srli	s5, s5, 32
	or	s5, s5, s9
	addi	a2, a2, -1
	addi	t0, t0, 64
	andi	s6, a2, 3
	bnez	s6, L_SHA256_transform_riscv_crypto_len_inner
	ld	s8, 0(t0)
	mv	s6, t5
	mv	s7, t1
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t6, a3
	xor	s10, t1, t2
	xor	s11, t2, t3
	and	s0, s0, t5
	addw	a4, a4, s6
	and	s11, s11, s10
	xor	s0, s0, a3
	addw	s10, s8, a5
	xor	s11, s11, t2
	addw	a4, a4, s0
	addw	a4, a4, s10
	addw	s11, s7, s11
	addw	t4, t4, a4
	addw	a4, a4, s11
	srli	s8, s8, 32
	srli	s9, a5, 32
	mv	s6, t4
	mv	s7, a4
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t5, t6
	xor	s10, a4, t1
	xor	s11, t1, t2
	and	s0, s0, t4
	addw	a3, a3, s6
	and	s11, s11, s10
	xor	s0, s0, t6
	addw	s10, s8, s9
	xor	s11, s11, t1
	addw	a3, a3, s0
	addw	a3, a3, s10
	addw	s11, s7, s11
	addw	t3, t3, a3
	addw	a3, a3, s11
	ld	s8, 8(t0)
	mv	s6, t3
	mv	s7, a3
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t4, t5
	xor	s10, a3, a4
	xor	s11, a4, t1
	and	s0, s0, t3
	addw	t6, t6, s6
	and	s11, s11, s10
	xor	s0, s0, t5
	addw	s10, s8, a6
	xor	s11, s11, a4
	addw	t6, t6, s0
	addw	t6, t6, s10
	addw	s11, s7, s11
	addw	t2, t2, t6
	addw	t6, t6, s11
	srli	s8, s8, 32
	srli	s9, a6, 32
	mv	s6, t2
	mv	s7, t6
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t3, t4
	xor	s10, t6, a3
	xor	s11, a3, a4
	and	s0, s0, t2
	addw	t5, t5, s6
	and	s11, s11, s10
	xor	s0, s0, t4
	addw	s10, s8, s9
	xor	s11, s11, a3
	addw	t5, t5, s0
	addw	t5, t5, s10
	addw	s11, s7, s11
	addw	t1, t1, t5
	addw	t5, t5, s11
	ld	s8, 16(t0)
	mv	s6, t1
	mv	s7, t5
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t2, t3
	xor	s10, t5, t6
	xor	s11, t6, a3
	and	s0, s0, t1
	addw	t4, t4, s6
	and	s11, s11, s10
	xor	s0, s0, t3
	addw	s10, s8, a7
	xor	s11, s11, t6
	addw	t4, t4, s0
	addw	t4, t4, s10
	addw	s11, s7, s11
	addw	a4, a4, t4
	addw	t4, t4, s11
	srli	s8, s8, 32
	srli	s9, a7, 32
	mv	s6, a4
	mv	s7, t4
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t1, t2
	xor	s10, t4, t5
	xor	s11, t5, t6
	and	s0, s0, a4
	addw	t3, t3, s6
	and	s11, s11, s10
	xor	s0, s0, t2
	addw	s10, s8, s9
	xor	s11, s11, t5
	addw	t3, t3, s0
	addw	t3, t3, s10
	addw	s11, s7, s11
	addw	a3, a3, t3
	addw	t3, t3, s11
	ld	s8, 24(t0)
	mv	s6, a3
	mv	s7, t3
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, a4, t1
	xor	s10, t3, t4
	xor	s11, t4, t5
	and	s0, s0, a3
	addw	t2, t2, s6
	and	s11, s11, s10
	xor	s0, s0, t1
	addw	s10, s8, s1
	xor	s11, s11, t4
	addw	t2, t2, s0
	addw	t2, t2, s10
	addw	s11, s7, s11
	addw	t6, t6, t2
	addw	t2, t2, s11
	srli	s8, s8, 32
	srli	s9, s1, 32
	mv	s6, t6
	mv	s7, t2
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, a3, a4
	xor	s10, t2, t3
	xor	s11, t3, t4
	and	s0, s0, t6
	addw	t1, t1, s6
	and	s11, s11, s10
	xor	s0, s0, a4
	addw	s10, s8, s9
	xor	s11, s11, t3
	addw	t1, t1, s0
	addw	t1, t1, s10
	addw	s11, s7, s11
	addw	t5, t5, t1
	addw	t1, t1, s11
	ld	s8, 32(t0)
	mv	s6, t5
	mv	s7, t1
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t6, a3
	xor	s10, t1, t2
	xor	s11, t2, t3
	and	s0, s0, t5
	addw	a4, a4, s6
	and	s11, s11, s10
	xor	s0, s0, a3
	addw	s10, s8, s2
	xor	s11, s11, t2
	addw	a4, a4, s0
	addw	a4, a4, s10
	addw	s11, s7, s11
	addw	t4, t4, a4
	addw	a4, a4, s11
	srli	s8, s8, 32
	srli	s9, s2, 32
	mv	s6, t4
	mv	s7, a4
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t5, t6
	xor	s10, a4, t1
	xor	s11, t1, t2
	and	s0, s0, t4
	addw	a3, a3, s6
	and	s11, s11, s10
	xor	s0, s0, t6
	addw	s10, s8, s9
	xor	s11, s11, t1
	addw	a3, a3, s0
	addw	a3, a3, s10
	addw	s11, s7, s11
	addw	t3, t3, a3
	addw	a3, a3, s11
	ld	s8, 40(t0)
	mv	s6, t3
	mv	s7, a3
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t4, t5
	xor	s10, a3, a4
	xor	s11, a4, t1
	and	s0, s0, t3
	addw	t6, t6, s6
	and	s11, s11, s10
	xor	s0, s0, t5
	addw	s10, s8, s3
	xor	s11, s11, a4
	addw	t6, t6, s0
	addw	t6, t6, s10
	addw	s11, s7, s11
	addw	t2, t2, t6
	addw	t6, t6, s11
	srli	s8, s8, 32
	srli	s9, s3, 32
	mv	s6, t2
	mv	s7, t6
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t3, t4
	xor	s10, t6, a3
	xor	s11, a3, a4
	and	s0, s0, t2
	addw	t5, t5, s6
	and	s11, s11, s10
	xor	s0, s0, t4
	addw	s10, s8, s9
	xor	s11, s11, a3
	addw	t5, t5, s0
	addw	t5, t5, s10
	addw	s11, s7, s11
	addw	t1, t1, t5
	addw	t5, t5, s11
	ld	s8, 48(t0)
	mv	s6, t1
	mv	s7, t5
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t2, t3
	xor	s10, t5, t6
	xor	s11, t6, a3
	and	s0, s0, t1
	addw	t4, t4, s6
	and	s11, s11, s10
	xor	s0, s0, t3
	addw	s10, s8, s4
	xor	s11, s11, t6
	addw	t4, t4, s0
	addw	t4, t4, s10
	addw	s11, s7, s11
	addw	a4, a4, t4
	addw	t4, t4, s11
	srli	s8, s8, 32
	srli	s9, s4, 32
	mv	s6, a4
	mv	s7, t4
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, t1, t2
	xor	s10, t4, t5
	xor	s11, t5, t6
	and	s0, s0, a4
	addw	t3, t3, s6
	and	s11, s11, s10
	xor	s0, s0, t2
	addw	s10, s8, s9
	xor	s11, s11, t5
	addw	t3, t3, s0
	addw	t3, t3, s10
	addw	s11, s7, s11
	addw	a3, a3, t3
	addw	t3, t3, s11
	ld	s8, 56(t0)
	mv	s6, a3
	mv	s7, t3
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, a4, t1
	xor	s10, t3, t4
	xor	s11, t4, t5
	and	s0, s0, a3
	addw	t2, t2, s6
	and	s11, s11, s10
	xor	s0, s0, t1
	addw	s10, s8, s5
	xor	s11, s11, t4
	addw	t2, t2, s0
	addw	t2, t2, s10
	addw	s11, s7, s11
	addw	t6, t6, t2
	addw	t2, t2, s11
	srli	s8, s8, 32
	srli	s9, s5, 32
	mv	s6, t6
	mv	s7, t2
	sha256sum1	s6, s6
	sha256sum0	s7, s7
	xor	s0, a3, a4
	xor	s10, t2, t3
	xor	s11, t3, t4
	and	s0, s0, t6
	addw	t1, t1, s6
	and	s11, s11, s10
	xor	s0, s0, a4
	addw	s10, s8, s9
	xor	s11, s11, t3
	addw	t1, t1, s0
	addw	t1, t1, s10
	addw	s11, s7, s11
	addw	t5, t5, t1
	addw	t1, t1, s11
	addi	t0, t0, -192
	# Add working variables back into digest state
	ld	s6, 0(a0)
	ld	s7, 8(a0)
	ld	s8, 16(a0)
	ld	s9, 24(a0)
	addw	t1, t1, s6
	addw	t3, t3, s7
	addw	t5, t5, s8
	addw	a3, a3, s9
	srli	s6, s6, 32
	srli	s7, s7, 32
	srli	s8, s8, 32
	srli	s9, s9, 32
	addw	t2, t2, s6
	addw	t4, t4, s7
	addw	t6, t6, s8
	addw	a4, a4, s9
	# Store digest
	sw	t1, 0(a0)
	sw	t2, 4(a0)
	sw	t3, 8(a0)
	sw	t4, 12(a0)
	sw	t5, 16(a0)
	sw	t6, 20(a0)
	sw	a3, 24(a0)
	sw	a4, 28(a0)
	addi	a1, a1, 64
	bnez	a2, L_SHA256_transform_riscv_crypto_len_begin
	ld	s0, 0(sp)
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
	.size	Transform_Sha256_Len_riscv_crypto,.-Transform_Sha256_Len_riscv_crypto
#else
	.section	.rodata
	.type	L_SHA256_transform_riscv_len_k, %object
	.size	L_SHA256_transform_riscv_len_k, 256
	# 4-byte aligned, 32-bit aligned
	.align	2
L_SHA256_transform_riscv_len_k:
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
	.text
	.globl	Transform_Sha256_Len_riscv
	.type	Transform_Sha256_Len_riscv,@function
	.align	2
Transform_Sha256_Len_riscv:
	addi	sp, sp, -96
	sd	s0, 0(sp)
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
	la	t0, L_SHA256_transform_riscv_len_k
	# Load digest into working variables
	ld	t1, 0(a0)
	ld	t3, 8(a0)
	ld	t5, 16(a0)
	ld	a3, 24(a0)
	srli	t2, t1, 32
	srli	t4, t3, 32
	srli	t6, t5, 32
	srli	a4, a3, 32
	srli	a2, a2, 4
	# Start of loop processing a block
L_SHA256_transform_riscv_len_begin:
	# Load W - big endian into two-words-per-register
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) || defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lbu	s6, 0(a1)
	lbu	s7, 1(a1)
	lbu	s8, 2(a1)
	lbu	a5, 3(a1)
	slli	s6, s6, 24
	slli	s7, s7, 16
	slli	s8, s8, 8
	or	a5, a5, s6
	or	a5, a5, s7
	or	a5, a5, s8
	lbu	s6, 4(a1)
	lbu	s7, 5(a1)
	lbu	s8, 6(a1)
	lbu	s9, 7(a1)
	slli	s6, s6, 56
	slli	s7, s7, 48
	slli	s8, s8, 40
	slli	s9, s9, 32
	or	a5, a5, s6
	or	a5, a5, s7
	or	a5, a5, s8
	or	a5, a5, s9
	lbu	s6, 8(a1)
	lbu	s7, 9(a1)
	lbu	s8, 10(a1)
	lbu	a6, 11(a1)
	slli	s6, s6, 24
	slli	s7, s7, 16
	slli	s8, s8, 8
	or	a6, a6, s6
	or	a6, a6, s7
	or	a6, a6, s8
	lbu	s6, 12(a1)
	lbu	s7, 13(a1)
	lbu	s8, 14(a1)
	lbu	s9, 15(a1)
	slli	s6, s6, 56
	slli	s7, s7, 48
	slli	s8, s8, 40
	slli	s9, s9, 32
	or	a6, a6, s6
	or	a6, a6, s7
	or	a6, a6, s8
	or	a6, a6, s9
	lbu	s6, 16(a1)
	lbu	s7, 17(a1)
	lbu	s8, 18(a1)
	lbu	a7, 19(a1)
	slli	s6, s6, 24
	slli	s7, s7, 16
	slli	s8, s8, 8
	or	a7, a7, s6
	or	a7, a7, s7
	or	a7, a7, s8
	lbu	s6, 20(a1)
	lbu	s7, 21(a1)
	lbu	s8, 22(a1)
	lbu	s9, 23(a1)
	slli	s6, s6, 56
	slli	s7, s7, 48
	slli	s8, s8, 40
	slli	s9, s9, 32
	or	a7, a7, s6
	or	a7, a7, s7
	or	a7, a7, s8
	or	a7, a7, s9
	lbu	s6, 24(a1)
	lbu	s7, 25(a1)
	lbu	s8, 26(a1)
	lbu	s1, 27(a1)
	slli	s6, s6, 24
	slli	s7, s7, 16
	slli	s8, s8, 8
	or	s1, s1, s6
	or	s1, s1, s7
	or	s1, s1, s8
	lbu	s6, 28(a1)
	lbu	s7, 29(a1)
	lbu	s8, 30(a1)
	lbu	s9, 31(a1)
	slli	s6, s6, 56
	slli	s7, s7, 48
	slli	s8, s8, 40
	slli	s9, s9, 32
	or	s1, s1, s6
	or	s1, s1, s7
	or	s1, s1, s8
	or	s1, s1, s9
	lbu	s6, 32(a1)
	lbu	s7, 33(a1)
	lbu	s8, 34(a1)
	lbu	s2, 35(a1)
	slli	s6, s6, 24
	slli	s7, s7, 16
	slli	s8, s8, 8
	or	s2, s2, s6
	or	s2, s2, s7
	or	s2, s2, s8
	lbu	s6, 36(a1)
	lbu	s7, 37(a1)
	lbu	s8, 38(a1)
	lbu	s9, 39(a1)
	slli	s6, s6, 56
	slli	s7, s7, 48
	slli	s8, s8, 40
	slli	s9, s9, 32
	or	s2, s2, s6
	or	s2, s2, s7
	or	s2, s2, s8
	or	s2, s2, s9
	lbu	s6, 40(a1)
	lbu	s7, 41(a1)
	lbu	s8, 42(a1)
	lbu	s3, 43(a1)
	slli	s6, s6, 24
	slli	s7, s7, 16
	slli	s8, s8, 8
	or	s3, s3, s6
	or	s3, s3, s7
	or	s3, s3, s8
	lbu	s6, 44(a1)
	lbu	s7, 45(a1)
	lbu	s8, 46(a1)
	lbu	s9, 47(a1)
	slli	s6, s6, 56
	slli	s7, s7, 48
	slli	s8, s8, 40
	slli	s9, s9, 32
	or	s3, s3, s6
	or	s3, s3, s7
	or	s3, s3, s8
	or	s3, s3, s9
	lbu	s6, 48(a1)
	lbu	s7, 49(a1)
	lbu	s8, 50(a1)
	lbu	s4, 51(a1)
	slli	s6, s6, 24
	slli	s7, s7, 16
	slli	s8, s8, 8
	or	s4, s4, s6
	or	s4, s4, s7
	or	s4, s4, s8
	lbu	s6, 52(a1)
	lbu	s7, 53(a1)
	lbu	s8, 54(a1)
	lbu	s9, 55(a1)
	slli	s6, s6, 56
	slli	s7, s7, 48
	slli	s8, s8, 40
	slli	s9, s9, 32
	or	s4, s4, s6
	or	s4, s4, s7
	or	s4, s4, s8
	or	s4, s4, s9
	lbu	s6, 56(a1)
	lbu	s7, 57(a1)
	lbu	s8, 58(a1)
	lbu	s5, 59(a1)
	slli	s6, s6, 24
	slli	s7, s7, 16
	slli	s8, s8, 8
	or	s5, s5, s6
	or	s5, s5, s7
	or	s5, s5, s8
	lbu	s6, 60(a1)
	lbu	s7, 61(a1)
	lbu	s8, 62(a1)
	lbu	s9, 63(a1)
	slli	s6, s6, 56
	slli	s7, s7, 48
	slli	s8, s8, 40
	slli	s9, s9, 32
	or	s5, s5, s6
	or	s5, s5, s7
	or	s5, s5, s8
	or	s5, s5, s9
#else
	ld	a5, 0(a1)
	# rev8 a5, a5
	.word	0x6b87d793
	# rori a5, a5, 32
	.word	0x6207d793
	ld	a6, 8(a1)
	# rev8 a6, a6
	.word	0x6b885813
	# rori a6, a6, 32
	.word	0x62085813
	ld	a7, 16(a1)
	# rev8 a7, a7
	.word	0x6b88d893
	# rori a7, a7, 32
	.word	0x6208d893
	ld	s1, 24(a1)
	# rev8 s1, s1
	.word	0x6b84d493
	# rori s1, s1, 32
	.word	0x6204d493
	ld	s2, 32(a1)
	# rev8 s2, s2
	.word	0x6b895913
	# rori s2, s2, 32
	.word	0x62095913
	ld	s3, 40(a1)
	# rev8 s3, s3
	.word	0x6b89d993
	# rori s3, s3, 32
	.word	0x6209d993
	ld	s4, 48(a1)
	# rev8 s4, s4
	.word	0x6b8a5a13
	# rori s4, s4, 32
	.word	0x620a5a13
	ld	s5, 56(a1)
	# rev8 s5, s5
	.word	0x6b8ada93
	# rori s5, s5, 32
	.word	0x620ada93
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) || defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	addi	a2, a2, -1
L_SHA256_transform_riscv_len_inner:
	ld	s8, 0(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t5, 6
	.word	0x606f5d1b
	# roriw s11, t5, 11
	.word	0x60bf5d9b
	# roriw s6, t5, 25
	.word	0x619f5b1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t6, a3
	and	s0, s0, t5
	xor	s0, s0, a3
	addw	a4, a4, s6
	addw	a4, a4, s0
	addw	s6, s8, a5
	addw	a4, a4, s6
	# roriw s10, t1, 2
	.word	0x60235d1b
	# roriw s11, t1, 13
	.word	0x60d35d9b
	# roriw s7, t1, 22
	.word	0x61635b9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t1, t2
	xor	s6, t2, t3
	and	s11, s11, s6
	xor	s11, s11, t2
	addw	t4, t4, a4
	addw	s11, s7, s11
	addw	a4, a4, s11
#else
	slliw	s11, t5, 26
	srliw	s10, t5, 6
	slliw	s0, t5, 21
	srliw	s6, t5, 11
	slliw	s7, t5, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t5, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t1, 30
	xor	s6, s6, s10
	srliw	s10, t1, 2
	slliw	s0, t1, 19
	addw	a4, a4, s6
	srliw	s7, t1, 13
	slliw	s6, t1, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t1, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t6, a3
	xor	s11, t1, t2
	xor	s6, t2, t3
	xor	s7, s7, s10
	and	s0, s0, t5
	and	s11, s11, s6
	xor	s0, s0, a3
	addw	s6, s8, a5
	addw	a4, a4, s0
	xor	s11, s11, t2
	addw	a4, a4, s6
	addw	s11, s7, s11
	addw	t4, t4, a4
	addw	a4, a4, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	srli	s8, s8, 32
	srli	s9, a5, 32
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t4, 6
	.word	0x606edd1b
	# roriw s11, t4, 11
	.word	0x60bedd9b
	# roriw s6, t4, 25
	.word	0x619edb1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t5, t6
	and	s0, s0, t4
	xor	s0, s0, t6
	addw	a3, a3, s6
	addw	a3, a3, s0
	addw	s6, s8, s9
	addw	a3, a3, s6
	# roriw s10, a4, 2
	.word	0x60275d1b
	# roriw s11, a4, 13
	.word	0x60d75d9b
	# roriw s7, a4, 22
	.word	0x61675b9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, a4, t1
	xor	s6, t1, t2
	and	s11, s11, s6
	xor	s11, s11, t1
	addw	t3, t3, a3
	addw	s11, s7, s11
	addw	a3, a3, s11
#else
	slliw	s11, t4, 26
	srliw	s10, t4, 6
	slliw	s0, t4, 21
	srliw	s6, t4, 11
	slliw	s7, t4, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t4, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, a4, 30
	xor	s6, s6, s10
	srliw	s10, a4, 2
	slliw	s0, a4, 19
	addw	a3, a3, s6
	srliw	s7, a4, 13
	slliw	s6, a4, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, a4, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t5, t6
	xor	s11, a4, t1
	xor	s6, t1, t2
	xor	s7, s7, s10
	and	s0, s0, t4
	and	s11, s11, s6
	xor	s0, s0, t6
	addw	s6, s8, s9
	addw	a3, a3, s0
	xor	s11, s11, t1
	addw	a3, a3, s6
	addw	s11, s7, s11
	addw	t3, t3, a3
	addw	a3, a3, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s9, a5, 32
	srli	s8, s2, 32
	# roriw s10, s9, 7
	.word	0x607cdd1b
	# roriw s11, s9, 18
	.word	0x612cdd9b
	srliw	s6, s9, 3
	xor	s6, s6, s10
	xor	s6, s6, s11
	# roriw s10, s5, 17
	.word	0x611add1b
	# roriw s11, s5, 19
	.word	0x613add9b
	srliw	s7, s5, 10
	xor	s7, s7, s10
	xor	s7, s7, s11
	addw	a5, a5, s6
	addw	s7, s7, s8
	addw	a5, s7, a5
	srli	s6, s5, 32
	# roriw s10, a6, 7
	.word	0x60785d1b
	# roriw s11, a6, 18
	.word	0x61285d9b
	srliw	s8, a6, 3
	xor	s8, s8, s10
	xor	s8, s8, s11
	# roriw s10, s6, 17
	.word	0x611b5d1b
	# roriw s11, s6, 19
	.word	0x613b5d9b
	srliw	s7, s6, 10
	xor	s7, s7, s10
	xor	s7, s7, s11
	addw	s11, s8, s9
	addw	s7, s7, s3
	addw	s7, s7, s11
	slli	a5, a5, 32
	slli	s7, s7, 32
	srli	a5, a5, 32
	or	a5, a5, s7
#else
	srli	s9, a5, 32
	srli	s8, s2, 32
	slliw	s10, s9, 25
	srliw	s11, s9, 7
	slliw	s0, s9, 14
	srliw	s6, s9, 18
	or	s10, s10, s11
	srliw	s11, s9, 3
	xor	s6, s6, s0
	xor	s10, s10, s11
	slliw	s0, s5, 15
	srliw	s11, s5, 17
	xor	s6, s6, s10
	slliw	s10, s5, 13
	srliw	s7, s5, 19
	or	s0, s0, s11
	srliw	s11, s5, 10
	xor	s7, s7, s10
	xor	s0, s0, s11
	xor	s7, s7, s0
	addw	a5, a5, s6
	addw	s7, s7, s8
	addw	a5, s7, a5
	srli	s6, s5, 32
	slliw	s10, a6, 25
	srliw	s11, a6, 7
	slliw	s0, a6, 14
	srliw	s8, a6, 18
	or	s10, s10, s11
	srliw	s11, a6, 3
	xor	s8, s8, s0
	xor	s10, s10, s11
	slliw	s0, s6, 15
	srliw	s11, s6, 17
	xor	s8, s8, s10
	slliw	s10, s6, 13
	srliw	s7, s6, 19
	or	s0, s0, s11
	srliw	s11, s6, 10
	xor	s7, s7, s10
	xor	s0, s0, s11
	xor	s7, s7, s0
	addw	s11, s8, s9
	addw	s7, s7, s3
	addw	s7, s7, s11
	slli	a5, a5, 32
	slli	s7, s7, 32
	srli	a5, a5, 32
	or	a5, a5, s7
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s8, 8(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t3, 6
	.word	0x606e5d1b
	# roriw s11, t3, 11
	.word	0x60be5d9b
	# roriw s6, t3, 25
	.word	0x619e5b1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t4, t5
	and	s0, s0, t3
	xor	s0, s0, t5
	addw	t6, t6, s6
	addw	t6, t6, s0
	addw	s6, s8, a6
	addw	t6, t6, s6
	# roriw s10, a3, 2
	.word	0x6026dd1b
	# roriw s11, a3, 13
	.word	0x60d6dd9b
	# roriw s7, a3, 22
	.word	0x6166db9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, a3, a4
	xor	s6, a4, t1
	and	s11, s11, s6
	xor	s11, s11, a4
	addw	t2, t2, t6
	addw	s11, s7, s11
	addw	t6, t6, s11
#else
	slliw	s11, t3, 26
	srliw	s10, t3, 6
	slliw	s0, t3, 21
	srliw	s6, t3, 11
	slliw	s7, t3, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t3, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, a3, 30
	xor	s6, s6, s10
	srliw	s10, a3, 2
	slliw	s0, a3, 19
	addw	t6, t6, s6
	srliw	s7, a3, 13
	slliw	s6, a3, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, a3, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t4, t5
	xor	s11, a3, a4
	xor	s6, a4, t1
	xor	s7, s7, s10
	and	s0, s0, t3
	and	s11, s11, s6
	xor	s0, s0, t5
	addw	s6, s8, a6
	addw	t6, t6, s0
	xor	s11, s11, a4
	addw	t6, t6, s6
	addw	s11, s7, s11
	addw	t2, t2, t6
	addw	t6, t6, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	srli	s8, s8, 32
	srli	s9, a6, 32
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t2, 6
	.word	0x6063dd1b
	# roriw s11, t2, 11
	.word	0x60b3dd9b
	# roriw s6, t2, 25
	.word	0x6193db1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t3, t4
	and	s0, s0, t2
	xor	s0, s0, t4
	addw	t5, t5, s6
	addw	t5, t5, s0
	addw	s6, s8, s9
	addw	t5, t5, s6
	# roriw s10, t6, 2
	.word	0x602fdd1b
	# roriw s11, t6, 13
	.word	0x60dfdd9b
	# roriw s7, t6, 22
	.word	0x616fdb9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t6, a3
	xor	s6, a3, a4
	and	s11, s11, s6
	xor	s11, s11, a3
	addw	t1, t1, t5
	addw	s11, s7, s11
	addw	t5, t5, s11
#else
	slliw	s11, t2, 26
	srliw	s10, t2, 6
	slliw	s0, t2, 21
	srliw	s6, t2, 11
	slliw	s7, t2, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t2, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t6, 30
	xor	s6, s6, s10
	srliw	s10, t6, 2
	slliw	s0, t6, 19
	addw	t5, t5, s6
	srliw	s7, t6, 13
	slliw	s6, t6, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t6, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t3, t4
	xor	s11, t6, a3
	xor	s6, a3, a4
	xor	s7, s7, s10
	and	s0, s0, t2
	and	s11, s11, s6
	xor	s0, s0, t4
	addw	s6, s8, s9
	addw	t5, t5, s0
	xor	s11, s11, a3
	addw	t5, t5, s6
	addw	s11, s7, s11
	addw	t1, t1, t5
	addw	t5, t5, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s9, a6, 32
	srli	s8, s3, 32
	# roriw s10, s9, 7
	.word	0x607cdd1b
	# roriw s11, s9, 18
	.word	0x612cdd9b
	srliw	s6, s9, 3
	xor	s6, s6, s10
	xor	s6, s6, s11
	# roriw s10, a5, 17
	.word	0x6117dd1b
	# roriw s11, a5, 19
	.word	0x6137dd9b
	srliw	s7, a5, 10
	xor	s7, s7, s10
	xor	s7, s7, s11
	addw	a6, a6, s6
	addw	s7, s7, s8
	addw	a6, s7, a6
	srli	s6, a5, 32
	# roriw s10, a7, 7
	.word	0x6078dd1b
	# roriw s11, a7, 18
	.word	0x6128dd9b
	srliw	s8, a7, 3
	xor	s8, s8, s10
	xor	s8, s8, s11
	# roriw s10, s6, 17
	.word	0x611b5d1b
	# roriw s11, s6, 19
	.word	0x613b5d9b
	srliw	s7, s6, 10
	xor	s7, s7, s10
	xor	s7, s7, s11
	addw	s11, s8, s9
	addw	s7, s7, s4
	addw	s7, s7, s11
	slli	a6, a6, 32
	slli	s7, s7, 32
	srli	a6, a6, 32
	or	a6, a6, s7
#else
	srli	s9, a6, 32
	srli	s8, s3, 32
	slliw	s10, s9, 25
	srliw	s11, s9, 7
	slliw	s0, s9, 14
	srliw	s6, s9, 18
	or	s10, s10, s11
	srliw	s11, s9, 3
	xor	s6, s6, s0
	xor	s10, s10, s11
	slliw	s0, a5, 15
	srliw	s11, a5, 17
	xor	s6, s6, s10
	slliw	s10, a5, 13
	srliw	s7, a5, 19
	or	s0, s0, s11
	srliw	s11, a5, 10
	xor	s7, s7, s10
	xor	s0, s0, s11
	xor	s7, s7, s0
	addw	a6, a6, s6
	addw	s7, s7, s8
	addw	a6, s7, a6
	srli	s6, a5, 32
	slliw	s10, a7, 25
	srliw	s11, a7, 7
	slliw	s0, a7, 14
	srliw	s8, a7, 18
	or	s10, s10, s11
	srliw	s11, a7, 3
	xor	s8, s8, s0
	xor	s10, s10, s11
	slliw	s0, s6, 15
	srliw	s11, s6, 17
	xor	s8, s8, s10
	slliw	s10, s6, 13
	srliw	s7, s6, 19
	or	s0, s0, s11
	srliw	s11, s6, 10
	xor	s7, s7, s10
	xor	s0, s0, s11
	xor	s7, s7, s0
	addw	s11, s8, s9
	addw	s7, s7, s4
	addw	s7, s7, s11
	slli	a6, a6, 32
	slli	s7, s7, 32
	srli	a6, a6, 32
	or	a6, a6, s7
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s8, 16(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t1, 6
	.word	0x60635d1b
	# roriw s11, t1, 11
	.word	0x60b35d9b
	# roriw s6, t1, 25
	.word	0x61935b1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t2, t3
	and	s0, s0, t1
	xor	s0, s0, t3
	addw	t4, t4, s6
	addw	t4, t4, s0
	addw	s6, s8, a7
	addw	t4, t4, s6
	# roriw s10, t5, 2
	.word	0x602f5d1b
	# roriw s11, t5, 13
	.word	0x60df5d9b
	# roriw s7, t5, 22
	.word	0x616f5b9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t5, t6
	xor	s6, t6, a3
	and	s11, s11, s6
	xor	s11, s11, t6
	addw	a4, a4, t4
	addw	s11, s7, s11
	addw	t4, t4, s11
#else
	slliw	s11, t1, 26
	srliw	s10, t1, 6
	slliw	s0, t1, 21
	srliw	s6, t1, 11
	slliw	s7, t1, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t1, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t5, 30
	xor	s6, s6, s10
	srliw	s10, t5, 2
	slliw	s0, t5, 19
	addw	t4, t4, s6
	srliw	s7, t5, 13
	slliw	s6, t5, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t5, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t2, t3
	xor	s11, t5, t6
	xor	s6, t6, a3
	xor	s7, s7, s10
	and	s0, s0, t1
	and	s11, s11, s6
	xor	s0, s0, t3
	addw	s6, s8, a7
	addw	t4, t4, s0
	xor	s11, s11, t6
	addw	t4, t4, s6
	addw	s11, s7, s11
	addw	a4, a4, t4
	addw	t4, t4, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	srli	s8, s8, 32
	srli	s9, a7, 32
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, a4, 6
	.word	0x60675d1b
	# roriw s11, a4, 11
	.word	0x60b75d9b
	# roriw s6, a4, 25
	.word	0x61975b1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t1, t2
	and	s0, s0, a4
	xor	s0, s0, t2
	addw	t3, t3, s6
	addw	t3, t3, s0
	addw	s6, s8, s9
	addw	t3, t3, s6
	# roriw s10, t4, 2
	.word	0x602edd1b
	# roriw s11, t4, 13
	.word	0x60dedd9b
	# roriw s7, t4, 22
	.word	0x616edb9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t4, t5
	xor	s6, t5, t6
	and	s11, s11, s6
	xor	s11, s11, t5
	addw	a3, a3, t3
	addw	s11, s7, s11
	addw	t3, t3, s11
#else
	slliw	s11, a4, 26
	srliw	s10, a4, 6
	slliw	s0, a4, 21
	srliw	s6, a4, 11
	slliw	s7, a4, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, a4, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t4, 30
	xor	s6, s6, s10
	srliw	s10, t4, 2
	slliw	s0, t4, 19
	addw	t3, t3, s6
	srliw	s7, t4, 13
	slliw	s6, t4, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t4, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t1, t2
	xor	s11, t4, t5
	xor	s6, t5, t6
	xor	s7, s7, s10
	and	s0, s0, a4
	and	s11, s11, s6
	xor	s0, s0, t2
	addw	s6, s8, s9
	addw	t3, t3, s0
	xor	s11, s11, t5
	addw	t3, t3, s6
	addw	s11, s7, s11
	addw	a3, a3, t3
	addw	t3, t3, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s9, a7, 32
	srli	s8, s4, 32
	# roriw s10, s9, 7
	.word	0x607cdd1b
	# roriw s11, s9, 18
	.word	0x612cdd9b
	srliw	s6, s9, 3
	xor	s6, s6, s10
	xor	s6, s6, s11
	# roriw s10, a6, 17
	.word	0x61185d1b
	# roriw s11, a6, 19
	.word	0x61385d9b
	srliw	s7, a6, 10
	xor	s7, s7, s10
	xor	s7, s7, s11
	addw	a7, a7, s6
	addw	s7, s7, s8
	addw	a7, s7, a7
	srli	s6, a6, 32
	# roriw s10, s1, 7
	.word	0x6074dd1b
	# roriw s11, s1, 18
	.word	0x6124dd9b
	srliw	s8, s1, 3
	xor	s8, s8, s10
	xor	s8, s8, s11
	# roriw s10, s6, 17
	.word	0x611b5d1b
	# roriw s11, s6, 19
	.word	0x613b5d9b
	srliw	s7, s6, 10
	xor	s7, s7, s10
	xor	s7, s7, s11
	addw	s11, s8, s9
	addw	s7, s7, s5
	addw	s7, s7, s11
	slli	a7, a7, 32
	slli	s7, s7, 32
	srli	a7, a7, 32
	or	a7, a7, s7
#else
	srli	s9, a7, 32
	srli	s8, s4, 32
	slliw	s10, s9, 25
	srliw	s11, s9, 7
	slliw	s0, s9, 14
	srliw	s6, s9, 18
	or	s10, s10, s11
	srliw	s11, s9, 3
	xor	s6, s6, s0
	xor	s10, s10, s11
	slliw	s0, a6, 15
	srliw	s11, a6, 17
	xor	s6, s6, s10
	slliw	s10, a6, 13
	srliw	s7, a6, 19
	or	s0, s0, s11
	srliw	s11, a6, 10
	xor	s7, s7, s10
	xor	s0, s0, s11
	xor	s7, s7, s0
	addw	a7, a7, s6
	addw	s7, s7, s8
	addw	a7, s7, a7
	srli	s6, a6, 32
	slliw	s10, s1, 25
	srliw	s11, s1, 7
	slliw	s0, s1, 14
	srliw	s8, s1, 18
	or	s10, s10, s11
	srliw	s11, s1, 3
	xor	s8, s8, s0
	xor	s10, s10, s11
	slliw	s0, s6, 15
	srliw	s11, s6, 17
	xor	s8, s8, s10
	slliw	s10, s6, 13
	srliw	s7, s6, 19
	or	s0, s0, s11
	srliw	s11, s6, 10
	xor	s7, s7, s10
	xor	s0, s0, s11
	xor	s7, s7, s0
	addw	s11, s8, s9
	addw	s7, s7, s5
	addw	s7, s7, s11
	slli	a7, a7, 32
	slli	s7, s7, 32
	srli	a7, a7, 32
	or	a7, a7, s7
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s8, 24(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, a3, 6
	.word	0x6066dd1b
	# roriw s11, a3, 11
	.word	0x60b6dd9b
	# roriw s6, a3, 25
	.word	0x6196db1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, a4, t1
	and	s0, s0, a3
	xor	s0, s0, t1
	addw	t2, t2, s6
	addw	t2, t2, s0
	addw	s6, s8, s1
	addw	t2, t2, s6
	# roriw s10, t3, 2
	.word	0x602e5d1b
	# roriw s11, t3, 13
	.word	0x60de5d9b
	# roriw s7, t3, 22
	.word	0x616e5b9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t3, t4
	xor	s6, t4, t5
	and	s11, s11, s6
	xor	s11, s11, t4
	addw	t6, t6, t2
	addw	s11, s7, s11
	addw	t2, t2, s11
#else
	slliw	s11, a3, 26
	srliw	s10, a3, 6
	slliw	s0, a3, 21
	srliw	s6, a3, 11
	slliw	s7, a3, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, a3, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t3, 30
	xor	s6, s6, s10
	srliw	s10, t3, 2
	slliw	s0, t3, 19
	addw	t2, t2, s6
	srliw	s7, t3, 13
	slliw	s6, t3, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t3, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, a4, t1
	xor	s11, t3, t4
	xor	s6, t4, t5
	xor	s7, s7, s10
	and	s0, s0, a3
	and	s11, s11, s6
	xor	s0, s0, t1
	addw	s6, s8, s1
	addw	t2, t2, s0
	xor	s11, s11, t4
	addw	t2, t2, s6
	addw	s11, s7, s11
	addw	t6, t6, t2
	addw	t2, t2, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	srli	s8, s8, 32
	srli	s9, s1, 32
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t6, 6
	.word	0x606fdd1b
	# roriw s11, t6, 11
	.word	0x60bfdd9b
	# roriw s6, t6, 25
	.word	0x619fdb1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, a3, a4
	and	s0, s0, t6
	xor	s0, s0, a4
	addw	t1, t1, s6
	addw	t1, t1, s0
	addw	s6, s8, s9
	addw	t1, t1, s6
	# roriw s10, t2, 2
	.word	0x6023dd1b
	# roriw s11, t2, 13
	.word	0x60d3dd9b
	# roriw s7, t2, 22
	.word	0x6163db9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t2, t3
	xor	s6, t3, t4
	and	s11, s11, s6
	xor	s11, s11, t3
	addw	t5, t5, t1
	addw	s11, s7, s11
	addw	t1, t1, s11
#else
	slliw	s11, t6, 26
	srliw	s10, t6, 6
	slliw	s0, t6, 21
	srliw	s6, t6, 11
	slliw	s7, t6, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t6, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t2, 30
	xor	s6, s6, s10
	srliw	s10, t2, 2
	slliw	s0, t2, 19
	addw	t1, t1, s6
	srliw	s7, t2, 13
	slliw	s6, t2, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t2, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, a3, a4
	xor	s11, t2, t3
	xor	s6, t3, t4
	xor	s7, s7, s10
	and	s0, s0, t6
	and	s11, s11, s6
	xor	s0, s0, a4
	addw	s6, s8, s9
	addw	t1, t1, s0
	xor	s11, s11, t3
	addw	t1, t1, s6
	addw	s11, s7, s11
	addw	t5, t5, t1
	addw	t1, t1, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s9, s1, 32
	srli	s8, s5, 32
	# roriw s10, s9, 7
	.word	0x607cdd1b
	# roriw s11, s9, 18
	.word	0x612cdd9b
	srliw	s6, s9, 3
	xor	s6, s6, s10
	xor	s6, s6, s11
	# roriw s10, a7, 17
	.word	0x6118dd1b
	# roriw s11, a7, 19
	.word	0x6138dd9b
	srliw	s7, a7, 10
	xor	s7, s7, s10
	xor	s7, s7, s11
	addw	s1, s1, s6
	addw	s7, s7, s8
	addw	s1, s7, s1
	srli	s6, a7, 32
	# roriw s10, s2, 7
	.word	0x60795d1b
	# roriw s11, s2, 18
	.word	0x61295d9b
	srliw	s8, s2, 3
	xor	s8, s8, s10
	xor	s8, s8, s11
	# roriw s10, s6, 17
	.word	0x611b5d1b
	# roriw s11, s6, 19
	.word	0x613b5d9b
	srliw	s7, s6, 10
	xor	s7, s7, s10
	xor	s7, s7, s11
	addw	s11, s8, s9
	addw	s7, s7, a5
	addw	s7, s7, s11
	slli	s1, s1, 32
	slli	s7, s7, 32
	srli	s1, s1, 32
	or	s1, s1, s7
#else
	srli	s9, s1, 32
	srli	s8, s5, 32
	slliw	s10, s9, 25
	srliw	s11, s9, 7
	slliw	s0, s9, 14
	srliw	s6, s9, 18
	or	s10, s10, s11
	srliw	s11, s9, 3
	xor	s6, s6, s0
	xor	s10, s10, s11
	slliw	s0, a7, 15
	srliw	s11, a7, 17
	xor	s6, s6, s10
	slliw	s10, a7, 13
	srliw	s7, a7, 19
	or	s0, s0, s11
	srliw	s11, a7, 10
	xor	s7, s7, s10
	xor	s0, s0, s11
	xor	s7, s7, s0
	addw	s1, s1, s6
	addw	s7, s7, s8
	addw	s1, s7, s1
	srli	s6, a7, 32
	slliw	s10, s2, 25
	srliw	s11, s2, 7
	slliw	s0, s2, 14
	srliw	s8, s2, 18
	or	s10, s10, s11
	srliw	s11, s2, 3
	xor	s8, s8, s0
	xor	s10, s10, s11
	slliw	s0, s6, 15
	srliw	s11, s6, 17
	xor	s8, s8, s10
	slliw	s10, s6, 13
	srliw	s7, s6, 19
	or	s0, s0, s11
	srliw	s11, s6, 10
	xor	s7, s7, s10
	xor	s0, s0, s11
	xor	s7, s7, s0
	addw	s11, s8, s9
	addw	s7, s7, a5
	addw	s7, s7, s11
	slli	s1, s1, 32
	slli	s7, s7, 32
	srli	s1, s1, 32
	or	s1, s1, s7
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s8, 32(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t5, 6
	.word	0x606f5d1b
	# roriw s11, t5, 11
	.word	0x60bf5d9b
	# roriw s6, t5, 25
	.word	0x619f5b1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t6, a3
	and	s0, s0, t5
	xor	s0, s0, a3
	addw	a4, a4, s6
	addw	a4, a4, s0
	addw	s6, s8, s2
	addw	a4, a4, s6
	# roriw s10, t1, 2
	.word	0x60235d1b
	# roriw s11, t1, 13
	.word	0x60d35d9b
	# roriw s7, t1, 22
	.word	0x61635b9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t1, t2
	xor	s6, t2, t3
	and	s11, s11, s6
	xor	s11, s11, t2
	addw	t4, t4, a4
	addw	s11, s7, s11
	addw	a4, a4, s11
#else
	slliw	s11, t5, 26
	srliw	s10, t5, 6
	slliw	s0, t5, 21
	srliw	s6, t5, 11
	slliw	s7, t5, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t5, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t1, 30
	xor	s6, s6, s10
	srliw	s10, t1, 2
	slliw	s0, t1, 19
	addw	a4, a4, s6
	srliw	s7, t1, 13
	slliw	s6, t1, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t1, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t6, a3
	xor	s11, t1, t2
	xor	s6, t2, t3
	xor	s7, s7, s10
	and	s0, s0, t5
	and	s11, s11, s6
	xor	s0, s0, a3
	addw	s6, s8, s2
	addw	a4, a4, s0
	xor	s11, s11, t2
	addw	a4, a4, s6
	addw	s11, s7, s11
	addw	t4, t4, a4
	addw	a4, a4, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	srli	s8, s8, 32
	srli	s9, s2, 32
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t4, 6
	.word	0x606edd1b
	# roriw s11, t4, 11
	.word	0x60bedd9b
	# roriw s6, t4, 25
	.word	0x619edb1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t5, t6
	and	s0, s0, t4
	xor	s0, s0, t6
	addw	a3, a3, s6
	addw	a3, a3, s0
	addw	s6, s8, s9
	addw	a3, a3, s6
	# roriw s10, a4, 2
	.word	0x60275d1b
	# roriw s11, a4, 13
	.word	0x60d75d9b
	# roriw s7, a4, 22
	.word	0x61675b9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, a4, t1
	xor	s6, t1, t2
	and	s11, s11, s6
	xor	s11, s11, t1
	addw	t3, t3, a3
	addw	s11, s7, s11
	addw	a3, a3, s11
#else
	slliw	s11, t4, 26
	srliw	s10, t4, 6
	slliw	s0, t4, 21
	srliw	s6, t4, 11
	slliw	s7, t4, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t4, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, a4, 30
	xor	s6, s6, s10
	srliw	s10, a4, 2
	slliw	s0, a4, 19
	addw	a3, a3, s6
	srliw	s7, a4, 13
	slliw	s6, a4, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, a4, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t5, t6
	xor	s11, a4, t1
	xor	s6, t1, t2
	xor	s7, s7, s10
	and	s0, s0, t4
	and	s11, s11, s6
	xor	s0, s0, t6
	addw	s6, s8, s9
	addw	a3, a3, s0
	xor	s11, s11, t1
	addw	a3, a3, s6
	addw	s11, s7, s11
	addw	t3, t3, a3
	addw	a3, a3, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s9, s2, 32
	srli	s8, a5, 32
	# roriw s10, s9, 7
	.word	0x607cdd1b
	# roriw s11, s9, 18
	.word	0x612cdd9b
	srliw	s6, s9, 3
	xor	s6, s6, s10
	xor	s6, s6, s11
	# roriw s10, s1, 17
	.word	0x6114dd1b
	# roriw s11, s1, 19
	.word	0x6134dd9b
	srliw	s7, s1, 10
	xor	s7, s7, s10
	xor	s7, s7, s11
	addw	s2, s2, s6
	addw	s7, s7, s8
	addw	s2, s7, s2
	srli	s6, s1, 32
	# roriw s10, s3, 7
	.word	0x6079dd1b
	# roriw s11, s3, 18
	.word	0x6129dd9b
	srliw	s8, s3, 3
	xor	s8, s8, s10
	xor	s8, s8, s11
	# roriw s10, s6, 17
	.word	0x611b5d1b
	# roriw s11, s6, 19
	.word	0x613b5d9b
	srliw	s7, s6, 10
	xor	s7, s7, s10
	xor	s7, s7, s11
	addw	s11, s8, s9
	addw	s7, s7, a6
	addw	s7, s7, s11
	slli	s2, s2, 32
	slli	s7, s7, 32
	srli	s2, s2, 32
	or	s2, s2, s7
#else
	srli	s9, s2, 32
	srli	s8, a5, 32
	slliw	s10, s9, 25
	srliw	s11, s9, 7
	slliw	s0, s9, 14
	srliw	s6, s9, 18
	or	s10, s10, s11
	srliw	s11, s9, 3
	xor	s6, s6, s0
	xor	s10, s10, s11
	slliw	s0, s1, 15
	srliw	s11, s1, 17
	xor	s6, s6, s10
	slliw	s10, s1, 13
	srliw	s7, s1, 19
	or	s0, s0, s11
	srliw	s11, s1, 10
	xor	s7, s7, s10
	xor	s0, s0, s11
	xor	s7, s7, s0
	addw	s2, s2, s6
	addw	s7, s7, s8
	addw	s2, s7, s2
	srli	s6, s1, 32
	slliw	s10, s3, 25
	srliw	s11, s3, 7
	slliw	s0, s3, 14
	srliw	s8, s3, 18
	or	s10, s10, s11
	srliw	s11, s3, 3
	xor	s8, s8, s0
	xor	s10, s10, s11
	slliw	s0, s6, 15
	srliw	s11, s6, 17
	xor	s8, s8, s10
	slliw	s10, s6, 13
	srliw	s7, s6, 19
	or	s0, s0, s11
	srliw	s11, s6, 10
	xor	s7, s7, s10
	xor	s0, s0, s11
	xor	s7, s7, s0
	addw	s11, s8, s9
	addw	s7, s7, a6
	addw	s7, s7, s11
	slli	s2, s2, 32
	slli	s7, s7, 32
	srli	s2, s2, 32
	or	s2, s2, s7
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s8, 40(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t3, 6
	.word	0x606e5d1b
	# roriw s11, t3, 11
	.word	0x60be5d9b
	# roriw s6, t3, 25
	.word	0x619e5b1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t4, t5
	and	s0, s0, t3
	xor	s0, s0, t5
	addw	t6, t6, s6
	addw	t6, t6, s0
	addw	s6, s8, s3
	addw	t6, t6, s6
	# roriw s10, a3, 2
	.word	0x6026dd1b
	# roriw s11, a3, 13
	.word	0x60d6dd9b
	# roriw s7, a3, 22
	.word	0x6166db9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, a3, a4
	xor	s6, a4, t1
	and	s11, s11, s6
	xor	s11, s11, a4
	addw	t2, t2, t6
	addw	s11, s7, s11
	addw	t6, t6, s11
#else
	slliw	s11, t3, 26
	srliw	s10, t3, 6
	slliw	s0, t3, 21
	srliw	s6, t3, 11
	slliw	s7, t3, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t3, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, a3, 30
	xor	s6, s6, s10
	srliw	s10, a3, 2
	slliw	s0, a3, 19
	addw	t6, t6, s6
	srliw	s7, a3, 13
	slliw	s6, a3, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, a3, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t4, t5
	xor	s11, a3, a4
	xor	s6, a4, t1
	xor	s7, s7, s10
	and	s0, s0, t3
	and	s11, s11, s6
	xor	s0, s0, t5
	addw	s6, s8, s3
	addw	t6, t6, s0
	xor	s11, s11, a4
	addw	t6, t6, s6
	addw	s11, s7, s11
	addw	t2, t2, t6
	addw	t6, t6, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	srli	s8, s8, 32
	srli	s9, s3, 32
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t2, 6
	.word	0x6063dd1b
	# roriw s11, t2, 11
	.word	0x60b3dd9b
	# roriw s6, t2, 25
	.word	0x6193db1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t3, t4
	and	s0, s0, t2
	xor	s0, s0, t4
	addw	t5, t5, s6
	addw	t5, t5, s0
	addw	s6, s8, s9
	addw	t5, t5, s6
	# roriw s10, t6, 2
	.word	0x602fdd1b
	# roriw s11, t6, 13
	.word	0x60dfdd9b
	# roriw s7, t6, 22
	.word	0x616fdb9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t6, a3
	xor	s6, a3, a4
	and	s11, s11, s6
	xor	s11, s11, a3
	addw	t1, t1, t5
	addw	s11, s7, s11
	addw	t5, t5, s11
#else
	slliw	s11, t2, 26
	srliw	s10, t2, 6
	slliw	s0, t2, 21
	srliw	s6, t2, 11
	slliw	s7, t2, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t2, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t6, 30
	xor	s6, s6, s10
	srliw	s10, t6, 2
	slliw	s0, t6, 19
	addw	t5, t5, s6
	srliw	s7, t6, 13
	slliw	s6, t6, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t6, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t3, t4
	xor	s11, t6, a3
	xor	s6, a3, a4
	xor	s7, s7, s10
	and	s0, s0, t2
	and	s11, s11, s6
	xor	s0, s0, t4
	addw	s6, s8, s9
	addw	t5, t5, s0
	xor	s11, s11, a3
	addw	t5, t5, s6
	addw	s11, s7, s11
	addw	t1, t1, t5
	addw	t5, t5, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s9, s3, 32
	srli	s8, a6, 32
	# roriw s10, s9, 7
	.word	0x607cdd1b
	# roriw s11, s9, 18
	.word	0x612cdd9b
	srliw	s6, s9, 3
	xor	s6, s6, s10
	xor	s6, s6, s11
	# roriw s10, s2, 17
	.word	0x61195d1b
	# roriw s11, s2, 19
	.word	0x61395d9b
	srliw	s7, s2, 10
	xor	s7, s7, s10
	xor	s7, s7, s11
	addw	s3, s3, s6
	addw	s7, s7, s8
	addw	s3, s7, s3
	srli	s6, s2, 32
	# roriw s10, s4, 7
	.word	0x607a5d1b
	# roriw s11, s4, 18
	.word	0x612a5d9b
	srliw	s8, s4, 3
	xor	s8, s8, s10
	xor	s8, s8, s11
	# roriw s10, s6, 17
	.word	0x611b5d1b
	# roriw s11, s6, 19
	.word	0x613b5d9b
	srliw	s7, s6, 10
	xor	s7, s7, s10
	xor	s7, s7, s11
	addw	s11, s8, s9
	addw	s7, s7, a7
	addw	s7, s7, s11
	slli	s3, s3, 32
	slli	s7, s7, 32
	srli	s3, s3, 32
	or	s3, s3, s7
#else
	srli	s9, s3, 32
	srli	s8, a6, 32
	slliw	s10, s9, 25
	srliw	s11, s9, 7
	slliw	s0, s9, 14
	srliw	s6, s9, 18
	or	s10, s10, s11
	srliw	s11, s9, 3
	xor	s6, s6, s0
	xor	s10, s10, s11
	slliw	s0, s2, 15
	srliw	s11, s2, 17
	xor	s6, s6, s10
	slliw	s10, s2, 13
	srliw	s7, s2, 19
	or	s0, s0, s11
	srliw	s11, s2, 10
	xor	s7, s7, s10
	xor	s0, s0, s11
	xor	s7, s7, s0
	addw	s3, s3, s6
	addw	s7, s7, s8
	addw	s3, s7, s3
	srli	s6, s2, 32
	slliw	s10, s4, 25
	srliw	s11, s4, 7
	slliw	s0, s4, 14
	srliw	s8, s4, 18
	or	s10, s10, s11
	srliw	s11, s4, 3
	xor	s8, s8, s0
	xor	s10, s10, s11
	slliw	s0, s6, 15
	srliw	s11, s6, 17
	xor	s8, s8, s10
	slliw	s10, s6, 13
	srliw	s7, s6, 19
	or	s0, s0, s11
	srliw	s11, s6, 10
	xor	s7, s7, s10
	xor	s0, s0, s11
	xor	s7, s7, s0
	addw	s11, s8, s9
	addw	s7, s7, a7
	addw	s7, s7, s11
	slli	s3, s3, 32
	slli	s7, s7, 32
	srli	s3, s3, 32
	or	s3, s3, s7
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s8, 48(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t1, 6
	.word	0x60635d1b
	# roriw s11, t1, 11
	.word	0x60b35d9b
	# roriw s6, t1, 25
	.word	0x61935b1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t2, t3
	and	s0, s0, t1
	xor	s0, s0, t3
	addw	t4, t4, s6
	addw	t4, t4, s0
	addw	s6, s8, s4
	addw	t4, t4, s6
	# roriw s10, t5, 2
	.word	0x602f5d1b
	# roriw s11, t5, 13
	.word	0x60df5d9b
	# roriw s7, t5, 22
	.word	0x616f5b9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t5, t6
	xor	s6, t6, a3
	and	s11, s11, s6
	xor	s11, s11, t6
	addw	a4, a4, t4
	addw	s11, s7, s11
	addw	t4, t4, s11
#else
	slliw	s11, t1, 26
	srliw	s10, t1, 6
	slliw	s0, t1, 21
	srliw	s6, t1, 11
	slliw	s7, t1, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t1, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t5, 30
	xor	s6, s6, s10
	srliw	s10, t5, 2
	slliw	s0, t5, 19
	addw	t4, t4, s6
	srliw	s7, t5, 13
	slliw	s6, t5, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t5, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t2, t3
	xor	s11, t5, t6
	xor	s6, t6, a3
	xor	s7, s7, s10
	and	s0, s0, t1
	and	s11, s11, s6
	xor	s0, s0, t3
	addw	s6, s8, s4
	addw	t4, t4, s0
	xor	s11, s11, t6
	addw	t4, t4, s6
	addw	s11, s7, s11
	addw	a4, a4, t4
	addw	t4, t4, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	srli	s8, s8, 32
	srli	s9, s4, 32
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, a4, 6
	.word	0x60675d1b
	# roriw s11, a4, 11
	.word	0x60b75d9b
	# roriw s6, a4, 25
	.word	0x61975b1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t1, t2
	and	s0, s0, a4
	xor	s0, s0, t2
	addw	t3, t3, s6
	addw	t3, t3, s0
	addw	s6, s8, s9
	addw	t3, t3, s6
	# roriw s10, t4, 2
	.word	0x602edd1b
	# roriw s11, t4, 13
	.word	0x60dedd9b
	# roriw s7, t4, 22
	.word	0x616edb9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t4, t5
	xor	s6, t5, t6
	and	s11, s11, s6
	xor	s11, s11, t5
	addw	a3, a3, t3
	addw	s11, s7, s11
	addw	t3, t3, s11
#else
	slliw	s11, a4, 26
	srliw	s10, a4, 6
	slliw	s0, a4, 21
	srliw	s6, a4, 11
	slliw	s7, a4, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, a4, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t4, 30
	xor	s6, s6, s10
	srliw	s10, t4, 2
	slliw	s0, t4, 19
	addw	t3, t3, s6
	srliw	s7, t4, 13
	slliw	s6, t4, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t4, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t1, t2
	xor	s11, t4, t5
	xor	s6, t5, t6
	xor	s7, s7, s10
	and	s0, s0, a4
	and	s11, s11, s6
	xor	s0, s0, t2
	addw	s6, s8, s9
	addw	t3, t3, s0
	xor	s11, s11, t5
	addw	t3, t3, s6
	addw	s11, s7, s11
	addw	a3, a3, t3
	addw	t3, t3, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s9, s4, 32
	srli	s8, a7, 32
	# roriw s10, s9, 7
	.word	0x607cdd1b
	# roriw s11, s9, 18
	.word	0x612cdd9b
	srliw	s6, s9, 3
	xor	s6, s6, s10
	xor	s6, s6, s11
	# roriw s10, s3, 17
	.word	0x6119dd1b
	# roriw s11, s3, 19
	.word	0x6139dd9b
	srliw	s7, s3, 10
	xor	s7, s7, s10
	xor	s7, s7, s11
	addw	s4, s4, s6
	addw	s7, s7, s8
	addw	s4, s7, s4
	srli	s6, s3, 32
	# roriw s10, s5, 7
	.word	0x607add1b
	# roriw s11, s5, 18
	.word	0x612add9b
	srliw	s8, s5, 3
	xor	s8, s8, s10
	xor	s8, s8, s11
	# roriw s10, s6, 17
	.word	0x611b5d1b
	# roriw s11, s6, 19
	.word	0x613b5d9b
	srliw	s7, s6, 10
	xor	s7, s7, s10
	xor	s7, s7, s11
	addw	s11, s8, s9
	addw	s7, s7, s1
	addw	s7, s7, s11
	slli	s4, s4, 32
	slli	s7, s7, 32
	srli	s4, s4, 32
	or	s4, s4, s7
#else
	srli	s9, s4, 32
	srli	s8, a7, 32
	slliw	s10, s9, 25
	srliw	s11, s9, 7
	slliw	s0, s9, 14
	srliw	s6, s9, 18
	or	s10, s10, s11
	srliw	s11, s9, 3
	xor	s6, s6, s0
	xor	s10, s10, s11
	slliw	s0, s3, 15
	srliw	s11, s3, 17
	xor	s6, s6, s10
	slliw	s10, s3, 13
	srliw	s7, s3, 19
	or	s0, s0, s11
	srliw	s11, s3, 10
	xor	s7, s7, s10
	xor	s0, s0, s11
	xor	s7, s7, s0
	addw	s4, s4, s6
	addw	s7, s7, s8
	addw	s4, s7, s4
	srli	s6, s3, 32
	slliw	s10, s5, 25
	srliw	s11, s5, 7
	slliw	s0, s5, 14
	srliw	s8, s5, 18
	or	s10, s10, s11
	srliw	s11, s5, 3
	xor	s8, s8, s0
	xor	s10, s10, s11
	slliw	s0, s6, 15
	srliw	s11, s6, 17
	xor	s8, s8, s10
	slliw	s10, s6, 13
	srliw	s7, s6, 19
	or	s0, s0, s11
	srliw	s11, s6, 10
	xor	s7, s7, s10
	xor	s0, s0, s11
	xor	s7, s7, s0
	addw	s11, s8, s9
	addw	s7, s7, s1
	addw	s7, s7, s11
	slli	s4, s4, 32
	slli	s7, s7, 32
	srli	s4, s4, 32
	or	s4, s4, s7
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s8, 56(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, a3, 6
	.word	0x6066dd1b
	# roriw s11, a3, 11
	.word	0x60b6dd9b
	# roriw s6, a3, 25
	.word	0x6196db1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, a4, t1
	and	s0, s0, a3
	xor	s0, s0, t1
	addw	t2, t2, s6
	addw	t2, t2, s0
	addw	s6, s8, s5
	addw	t2, t2, s6
	# roriw s10, t3, 2
	.word	0x602e5d1b
	# roriw s11, t3, 13
	.word	0x60de5d9b
	# roriw s7, t3, 22
	.word	0x616e5b9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t3, t4
	xor	s6, t4, t5
	and	s11, s11, s6
	xor	s11, s11, t4
	addw	t6, t6, t2
	addw	s11, s7, s11
	addw	t2, t2, s11
#else
	slliw	s11, a3, 26
	srliw	s10, a3, 6
	slliw	s0, a3, 21
	srliw	s6, a3, 11
	slliw	s7, a3, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, a3, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t3, 30
	xor	s6, s6, s10
	srliw	s10, t3, 2
	slliw	s0, t3, 19
	addw	t2, t2, s6
	srliw	s7, t3, 13
	slliw	s6, t3, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t3, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, a4, t1
	xor	s11, t3, t4
	xor	s6, t4, t5
	xor	s7, s7, s10
	and	s0, s0, a3
	and	s11, s11, s6
	xor	s0, s0, t1
	addw	s6, s8, s5
	addw	t2, t2, s0
	xor	s11, s11, t4
	addw	t2, t2, s6
	addw	s11, s7, s11
	addw	t6, t6, t2
	addw	t2, t2, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	srli	s8, s8, 32
	srli	s9, s5, 32
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t6, 6
	.word	0x606fdd1b
	# roriw s11, t6, 11
	.word	0x60bfdd9b
	# roriw s6, t6, 25
	.word	0x619fdb1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, a3, a4
	and	s0, s0, t6
	xor	s0, s0, a4
	addw	t1, t1, s6
	addw	t1, t1, s0
	addw	s6, s8, s9
	addw	t1, t1, s6
	# roriw s10, t2, 2
	.word	0x6023dd1b
	# roriw s11, t2, 13
	.word	0x60d3dd9b
	# roriw s7, t2, 22
	.word	0x6163db9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t2, t3
	xor	s6, t3, t4
	and	s11, s11, s6
	xor	s11, s11, t3
	addw	t5, t5, t1
	addw	s11, s7, s11
	addw	t1, t1, s11
#else
	slliw	s11, t6, 26
	srliw	s10, t6, 6
	slliw	s0, t6, 21
	srliw	s6, t6, 11
	slliw	s7, t6, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t6, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t2, 30
	xor	s6, s6, s10
	srliw	s10, t2, 2
	slliw	s0, t2, 19
	addw	t1, t1, s6
	srliw	s7, t2, 13
	slliw	s6, t2, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t2, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, a3, a4
	xor	s11, t2, t3
	xor	s6, t3, t4
	xor	s7, s7, s10
	and	s0, s0, t6
	and	s11, s11, s6
	xor	s0, s0, a4
	addw	s6, s8, s9
	addw	t1, t1, s0
	xor	s11, s11, t3
	addw	t1, t1, s6
	addw	s11, s7, s11
	addw	t5, t5, t1
	addw	t1, t1, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s9, s5, 32
	srli	s8, s1, 32
	# roriw s10, s9, 7
	.word	0x607cdd1b
	# roriw s11, s9, 18
	.word	0x612cdd9b
	srliw	s6, s9, 3
	xor	s6, s6, s10
	xor	s6, s6, s11
	# roriw s10, s4, 17
	.word	0x611a5d1b
	# roriw s11, s4, 19
	.word	0x613a5d9b
	srliw	s7, s4, 10
	xor	s7, s7, s10
	xor	s7, s7, s11
	addw	s5, s5, s6
	addw	s7, s7, s8
	addw	s5, s7, s5
	srli	s6, s4, 32
	# roriw s10, a5, 7
	.word	0x6077dd1b
	# roriw s11, a5, 18
	.word	0x6127dd9b
	srliw	s8, a5, 3
	xor	s8, s8, s10
	xor	s8, s8, s11
	# roriw s10, s6, 17
	.word	0x611b5d1b
	# roriw s11, s6, 19
	.word	0x613b5d9b
	srliw	s7, s6, 10
	xor	s7, s7, s10
	xor	s7, s7, s11
	addw	s11, s8, s9
	addw	s7, s7, s2
	addw	s7, s7, s11
	slli	s5, s5, 32
	slli	s7, s7, 32
	srli	s5, s5, 32
	or	s5, s5, s7
#else
	srli	s9, s5, 32
	srli	s8, s1, 32
	slliw	s10, s9, 25
	srliw	s11, s9, 7
	slliw	s0, s9, 14
	srliw	s6, s9, 18
	or	s10, s10, s11
	srliw	s11, s9, 3
	xor	s6, s6, s0
	xor	s10, s10, s11
	slliw	s0, s4, 15
	srliw	s11, s4, 17
	xor	s6, s6, s10
	slliw	s10, s4, 13
	srliw	s7, s4, 19
	or	s0, s0, s11
	srliw	s11, s4, 10
	xor	s7, s7, s10
	xor	s0, s0, s11
	xor	s7, s7, s0
	addw	s5, s5, s6
	addw	s7, s7, s8
	addw	s5, s7, s5
	srli	s6, s4, 32
	slliw	s10, a5, 25
	srliw	s11, a5, 7
	slliw	s0, a5, 14
	srliw	s8, a5, 18
	or	s10, s10, s11
	srliw	s11, a5, 3
	xor	s8, s8, s0
	xor	s10, s10, s11
	slliw	s0, s6, 15
	srliw	s11, s6, 17
	xor	s8, s8, s10
	slliw	s10, s6, 13
	srliw	s7, s6, 19
	or	s0, s0, s11
	srliw	s11, s6, 10
	xor	s7, s7, s10
	xor	s0, s0, s11
	xor	s7, s7, s0
	addw	s11, s8, s9
	addw	s7, s7, s2
	addw	s7, s7, s11
	slli	s5, s5, 32
	slli	s7, s7, 32
	srli	s5, s5, 32
	or	s5, s5, s7
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	addi	a2, a2, -1
	addi	t0, t0, 64
	andi	s6, a2, 3
	bnez	s6, L_SHA256_transform_riscv_len_inner
	ld	s8, 0(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t5, 6
	.word	0x606f5d1b
	# roriw s11, t5, 11
	.word	0x60bf5d9b
	# roriw s6, t5, 25
	.word	0x619f5b1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t6, a3
	and	s0, s0, t5
	xor	s0, s0, a3
	addw	a4, a4, s6
	addw	a4, a4, s0
	addw	s6, s8, a5
	addw	a4, a4, s6
	# roriw s10, t1, 2
	.word	0x60235d1b
	# roriw s11, t1, 13
	.word	0x60d35d9b
	# roriw s7, t1, 22
	.word	0x61635b9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t1, t2
	xor	s6, t2, t3
	and	s11, s11, s6
	xor	s11, s11, t2
	addw	t4, t4, a4
	addw	s11, s7, s11
	addw	a4, a4, s11
#else
	slliw	s11, t5, 26
	srliw	s10, t5, 6
	slliw	s0, t5, 21
	srliw	s6, t5, 11
	slliw	s7, t5, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t5, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t1, 30
	xor	s6, s6, s10
	srliw	s10, t1, 2
	slliw	s0, t1, 19
	addw	a4, a4, s6
	srliw	s7, t1, 13
	slliw	s6, t1, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t1, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t6, a3
	xor	s11, t1, t2
	xor	s6, t2, t3
	xor	s7, s7, s10
	and	s0, s0, t5
	and	s11, s11, s6
	xor	s0, s0, a3
	addw	s6, s8, a5
	addw	a4, a4, s0
	xor	s11, s11, t2
	addw	a4, a4, s6
	addw	s11, s7, s11
	addw	t4, t4, a4
	addw	a4, a4, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	srli	s8, s8, 32
	srli	s9, a5, 32
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t4, 6
	.word	0x606edd1b
	# roriw s11, t4, 11
	.word	0x60bedd9b
	# roriw s6, t4, 25
	.word	0x619edb1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t5, t6
	and	s0, s0, t4
	xor	s0, s0, t6
	addw	a3, a3, s6
	addw	a3, a3, s0
	addw	s6, s8, s9
	addw	a3, a3, s6
	# roriw s10, a4, 2
	.word	0x60275d1b
	# roriw s11, a4, 13
	.word	0x60d75d9b
	# roriw s7, a4, 22
	.word	0x61675b9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, a4, t1
	xor	s6, t1, t2
	and	s11, s11, s6
	xor	s11, s11, t1
	addw	t3, t3, a3
	addw	s11, s7, s11
	addw	a3, a3, s11
#else
	slliw	s11, t4, 26
	srliw	s10, t4, 6
	slliw	s0, t4, 21
	srliw	s6, t4, 11
	slliw	s7, t4, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t4, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, a4, 30
	xor	s6, s6, s10
	srliw	s10, a4, 2
	slliw	s0, a4, 19
	addw	a3, a3, s6
	srliw	s7, a4, 13
	slliw	s6, a4, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, a4, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t5, t6
	xor	s11, a4, t1
	xor	s6, t1, t2
	xor	s7, s7, s10
	and	s0, s0, t4
	and	s11, s11, s6
	xor	s0, s0, t6
	addw	s6, s8, s9
	addw	a3, a3, s0
	xor	s11, s11, t1
	addw	a3, a3, s6
	addw	s11, s7, s11
	addw	t3, t3, a3
	addw	a3, a3, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s8, 8(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t3, 6
	.word	0x606e5d1b
	# roriw s11, t3, 11
	.word	0x60be5d9b
	# roriw s6, t3, 25
	.word	0x619e5b1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t4, t5
	and	s0, s0, t3
	xor	s0, s0, t5
	addw	t6, t6, s6
	addw	t6, t6, s0
	addw	s6, s8, a6
	addw	t6, t6, s6
	# roriw s10, a3, 2
	.word	0x6026dd1b
	# roriw s11, a3, 13
	.word	0x60d6dd9b
	# roriw s7, a3, 22
	.word	0x6166db9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, a3, a4
	xor	s6, a4, t1
	and	s11, s11, s6
	xor	s11, s11, a4
	addw	t2, t2, t6
	addw	s11, s7, s11
	addw	t6, t6, s11
#else
	slliw	s11, t3, 26
	srliw	s10, t3, 6
	slliw	s0, t3, 21
	srliw	s6, t3, 11
	slliw	s7, t3, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t3, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, a3, 30
	xor	s6, s6, s10
	srliw	s10, a3, 2
	slliw	s0, a3, 19
	addw	t6, t6, s6
	srliw	s7, a3, 13
	slliw	s6, a3, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, a3, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t4, t5
	xor	s11, a3, a4
	xor	s6, a4, t1
	xor	s7, s7, s10
	and	s0, s0, t3
	and	s11, s11, s6
	xor	s0, s0, t5
	addw	s6, s8, a6
	addw	t6, t6, s0
	xor	s11, s11, a4
	addw	t6, t6, s6
	addw	s11, s7, s11
	addw	t2, t2, t6
	addw	t6, t6, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	srli	s8, s8, 32
	srli	s9, a6, 32
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t2, 6
	.word	0x6063dd1b
	# roriw s11, t2, 11
	.word	0x60b3dd9b
	# roriw s6, t2, 25
	.word	0x6193db1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t3, t4
	and	s0, s0, t2
	xor	s0, s0, t4
	addw	t5, t5, s6
	addw	t5, t5, s0
	addw	s6, s8, s9
	addw	t5, t5, s6
	# roriw s10, t6, 2
	.word	0x602fdd1b
	# roriw s11, t6, 13
	.word	0x60dfdd9b
	# roriw s7, t6, 22
	.word	0x616fdb9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t6, a3
	xor	s6, a3, a4
	and	s11, s11, s6
	xor	s11, s11, a3
	addw	t1, t1, t5
	addw	s11, s7, s11
	addw	t5, t5, s11
#else
	slliw	s11, t2, 26
	srliw	s10, t2, 6
	slliw	s0, t2, 21
	srliw	s6, t2, 11
	slliw	s7, t2, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t2, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t6, 30
	xor	s6, s6, s10
	srliw	s10, t6, 2
	slliw	s0, t6, 19
	addw	t5, t5, s6
	srliw	s7, t6, 13
	slliw	s6, t6, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t6, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t3, t4
	xor	s11, t6, a3
	xor	s6, a3, a4
	xor	s7, s7, s10
	and	s0, s0, t2
	and	s11, s11, s6
	xor	s0, s0, t4
	addw	s6, s8, s9
	addw	t5, t5, s0
	xor	s11, s11, a3
	addw	t5, t5, s6
	addw	s11, s7, s11
	addw	t1, t1, t5
	addw	t5, t5, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s8, 16(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t1, 6
	.word	0x60635d1b
	# roriw s11, t1, 11
	.word	0x60b35d9b
	# roriw s6, t1, 25
	.word	0x61935b1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t2, t3
	and	s0, s0, t1
	xor	s0, s0, t3
	addw	t4, t4, s6
	addw	t4, t4, s0
	addw	s6, s8, a7
	addw	t4, t4, s6
	# roriw s10, t5, 2
	.word	0x602f5d1b
	# roriw s11, t5, 13
	.word	0x60df5d9b
	# roriw s7, t5, 22
	.word	0x616f5b9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t5, t6
	xor	s6, t6, a3
	and	s11, s11, s6
	xor	s11, s11, t6
	addw	a4, a4, t4
	addw	s11, s7, s11
	addw	t4, t4, s11
#else
	slliw	s11, t1, 26
	srliw	s10, t1, 6
	slliw	s0, t1, 21
	srliw	s6, t1, 11
	slliw	s7, t1, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t1, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t5, 30
	xor	s6, s6, s10
	srliw	s10, t5, 2
	slliw	s0, t5, 19
	addw	t4, t4, s6
	srliw	s7, t5, 13
	slliw	s6, t5, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t5, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t2, t3
	xor	s11, t5, t6
	xor	s6, t6, a3
	xor	s7, s7, s10
	and	s0, s0, t1
	and	s11, s11, s6
	xor	s0, s0, t3
	addw	s6, s8, a7
	addw	t4, t4, s0
	xor	s11, s11, t6
	addw	t4, t4, s6
	addw	s11, s7, s11
	addw	a4, a4, t4
	addw	t4, t4, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	srli	s8, s8, 32
	srli	s9, a7, 32
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, a4, 6
	.word	0x60675d1b
	# roriw s11, a4, 11
	.word	0x60b75d9b
	# roriw s6, a4, 25
	.word	0x61975b1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t1, t2
	and	s0, s0, a4
	xor	s0, s0, t2
	addw	t3, t3, s6
	addw	t3, t3, s0
	addw	s6, s8, s9
	addw	t3, t3, s6
	# roriw s10, t4, 2
	.word	0x602edd1b
	# roriw s11, t4, 13
	.word	0x60dedd9b
	# roriw s7, t4, 22
	.word	0x616edb9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t4, t5
	xor	s6, t5, t6
	and	s11, s11, s6
	xor	s11, s11, t5
	addw	a3, a3, t3
	addw	s11, s7, s11
	addw	t3, t3, s11
#else
	slliw	s11, a4, 26
	srliw	s10, a4, 6
	slliw	s0, a4, 21
	srliw	s6, a4, 11
	slliw	s7, a4, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, a4, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t4, 30
	xor	s6, s6, s10
	srliw	s10, t4, 2
	slliw	s0, t4, 19
	addw	t3, t3, s6
	srliw	s7, t4, 13
	slliw	s6, t4, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t4, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t1, t2
	xor	s11, t4, t5
	xor	s6, t5, t6
	xor	s7, s7, s10
	and	s0, s0, a4
	and	s11, s11, s6
	xor	s0, s0, t2
	addw	s6, s8, s9
	addw	t3, t3, s0
	xor	s11, s11, t5
	addw	t3, t3, s6
	addw	s11, s7, s11
	addw	a3, a3, t3
	addw	t3, t3, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s8, 24(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, a3, 6
	.word	0x6066dd1b
	# roriw s11, a3, 11
	.word	0x60b6dd9b
	# roriw s6, a3, 25
	.word	0x6196db1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, a4, t1
	and	s0, s0, a3
	xor	s0, s0, t1
	addw	t2, t2, s6
	addw	t2, t2, s0
	addw	s6, s8, s1
	addw	t2, t2, s6
	# roriw s10, t3, 2
	.word	0x602e5d1b
	# roriw s11, t3, 13
	.word	0x60de5d9b
	# roriw s7, t3, 22
	.word	0x616e5b9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t3, t4
	xor	s6, t4, t5
	and	s11, s11, s6
	xor	s11, s11, t4
	addw	t6, t6, t2
	addw	s11, s7, s11
	addw	t2, t2, s11
#else
	slliw	s11, a3, 26
	srliw	s10, a3, 6
	slliw	s0, a3, 21
	srliw	s6, a3, 11
	slliw	s7, a3, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, a3, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t3, 30
	xor	s6, s6, s10
	srliw	s10, t3, 2
	slliw	s0, t3, 19
	addw	t2, t2, s6
	srliw	s7, t3, 13
	slliw	s6, t3, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t3, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, a4, t1
	xor	s11, t3, t4
	xor	s6, t4, t5
	xor	s7, s7, s10
	and	s0, s0, a3
	and	s11, s11, s6
	xor	s0, s0, t1
	addw	s6, s8, s1
	addw	t2, t2, s0
	xor	s11, s11, t4
	addw	t2, t2, s6
	addw	s11, s7, s11
	addw	t6, t6, t2
	addw	t2, t2, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	srli	s8, s8, 32
	srli	s9, s1, 32
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t6, 6
	.word	0x606fdd1b
	# roriw s11, t6, 11
	.word	0x60bfdd9b
	# roriw s6, t6, 25
	.word	0x619fdb1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, a3, a4
	and	s0, s0, t6
	xor	s0, s0, a4
	addw	t1, t1, s6
	addw	t1, t1, s0
	addw	s6, s8, s9
	addw	t1, t1, s6
	# roriw s10, t2, 2
	.word	0x6023dd1b
	# roriw s11, t2, 13
	.word	0x60d3dd9b
	# roriw s7, t2, 22
	.word	0x6163db9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t2, t3
	xor	s6, t3, t4
	and	s11, s11, s6
	xor	s11, s11, t3
	addw	t5, t5, t1
	addw	s11, s7, s11
	addw	t1, t1, s11
#else
	slliw	s11, t6, 26
	srliw	s10, t6, 6
	slliw	s0, t6, 21
	srliw	s6, t6, 11
	slliw	s7, t6, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t6, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t2, 30
	xor	s6, s6, s10
	srliw	s10, t2, 2
	slliw	s0, t2, 19
	addw	t1, t1, s6
	srliw	s7, t2, 13
	slliw	s6, t2, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t2, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, a3, a4
	xor	s11, t2, t3
	xor	s6, t3, t4
	xor	s7, s7, s10
	and	s0, s0, t6
	and	s11, s11, s6
	xor	s0, s0, a4
	addw	s6, s8, s9
	addw	t1, t1, s0
	xor	s11, s11, t3
	addw	t1, t1, s6
	addw	s11, s7, s11
	addw	t5, t5, t1
	addw	t1, t1, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s8, 32(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t5, 6
	.word	0x606f5d1b
	# roriw s11, t5, 11
	.word	0x60bf5d9b
	# roriw s6, t5, 25
	.word	0x619f5b1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t6, a3
	and	s0, s0, t5
	xor	s0, s0, a3
	addw	a4, a4, s6
	addw	a4, a4, s0
	addw	s6, s8, s2
	addw	a4, a4, s6
	# roriw s10, t1, 2
	.word	0x60235d1b
	# roriw s11, t1, 13
	.word	0x60d35d9b
	# roriw s7, t1, 22
	.word	0x61635b9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t1, t2
	xor	s6, t2, t3
	and	s11, s11, s6
	xor	s11, s11, t2
	addw	t4, t4, a4
	addw	s11, s7, s11
	addw	a4, a4, s11
#else
	slliw	s11, t5, 26
	srliw	s10, t5, 6
	slliw	s0, t5, 21
	srliw	s6, t5, 11
	slliw	s7, t5, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t5, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t1, 30
	xor	s6, s6, s10
	srliw	s10, t1, 2
	slliw	s0, t1, 19
	addw	a4, a4, s6
	srliw	s7, t1, 13
	slliw	s6, t1, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t1, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t6, a3
	xor	s11, t1, t2
	xor	s6, t2, t3
	xor	s7, s7, s10
	and	s0, s0, t5
	and	s11, s11, s6
	xor	s0, s0, a3
	addw	s6, s8, s2
	addw	a4, a4, s0
	xor	s11, s11, t2
	addw	a4, a4, s6
	addw	s11, s7, s11
	addw	t4, t4, a4
	addw	a4, a4, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	srli	s8, s8, 32
	srli	s9, s2, 32
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t4, 6
	.word	0x606edd1b
	# roriw s11, t4, 11
	.word	0x60bedd9b
	# roriw s6, t4, 25
	.word	0x619edb1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t5, t6
	and	s0, s0, t4
	xor	s0, s0, t6
	addw	a3, a3, s6
	addw	a3, a3, s0
	addw	s6, s8, s9
	addw	a3, a3, s6
	# roriw s10, a4, 2
	.word	0x60275d1b
	# roriw s11, a4, 13
	.word	0x60d75d9b
	# roriw s7, a4, 22
	.word	0x61675b9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, a4, t1
	xor	s6, t1, t2
	and	s11, s11, s6
	xor	s11, s11, t1
	addw	t3, t3, a3
	addw	s11, s7, s11
	addw	a3, a3, s11
#else
	slliw	s11, t4, 26
	srliw	s10, t4, 6
	slliw	s0, t4, 21
	srliw	s6, t4, 11
	slliw	s7, t4, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t4, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, a4, 30
	xor	s6, s6, s10
	srliw	s10, a4, 2
	slliw	s0, a4, 19
	addw	a3, a3, s6
	srliw	s7, a4, 13
	slliw	s6, a4, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, a4, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t5, t6
	xor	s11, a4, t1
	xor	s6, t1, t2
	xor	s7, s7, s10
	and	s0, s0, t4
	and	s11, s11, s6
	xor	s0, s0, t6
	addw	s6, s8, s9
	addw	a3, a3, s0
	xor	s11, s11, t1
	addw	a3, a3, s6
	addw	s11, s7, s11
	addw	t3, t3, a3
	addw	a3, a3, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s8, 40(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t3, 6
	.word	0x606e5d1b
	# roriw s11, t3, 11
	.word	0x60be5d9b
	# roriw s6, t3, 25
	.word	0x619e5b1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t4, t5
	and	s0, s0, t3
	xor	s0, s0, t5
	addw	t6, t6, s6
	addw	t6, t6, s0
	addw	s6, s8, s3
	addw	t6, t6, s6
	# roriw s10, a3, 2
	.word	0x6026dd1b
	# roriw s11, a3, 13
	.word	0x60d6dd9b
	# roriw s7, a3, 22
	.word	0x6166db9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, a3, a4
	xor	s6, a4, t1
	and	s11, s11, s6
	xor	s11, s11, a4
	addw	t2, t2, t6
	addw	s11, s7, s11
	addw	t6, t6, s11
#else
	slliw	s11, t3, 26
	srliw	s10, t3, 6
	slliw	s0, t3, 21
	srliw	s6, t3, 11
	slliw	s7, t3, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t3, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, a3, 30
	xor	s6, s6, s10
	srliw	s10, a3, 2
	slliw	s0, a3, 19
	addw	t6, t6, s6
	srliw	s7, a3, 13
	slliw	s6, a3, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, a3, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t4, t5
	xor	s11, a3, a4
	xor	s6, a4, t1
	xor	s7, s7, s10
	and	s0, s0, t3
	and	s11, s11, s6
	xor	s0, s0, t5
	addw	s6, s8, s3
	addw	t6, t6, s0
	xor	s11, s11, a4
	addw	t6, t6, s6
	addw	s11, s7, s11
	addw	t2, t2, t6
	addw	t6, t6, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	srli	s8, s8, 32
	srli	s9, s3, 32
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t2, 6
	.word	0x6063dd1b
	# roriw s11, t2, 11
	.word	0x60b3dd9b
	# roriw s6, t2, 25
	.word	0x6193db1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t3, t4
	and	s0, s0, t2
	xor	s0, s0, t4
	addw	t5, t5, s6
	addw	t5, t5, s0
	addw	s6, s8, s9
	addw	t5, t5, s6
	# roriw s10, t6, 2
	.word	0x602fdd1b
	# roriw s11, t6, 13
	.word	0x60dfdd9b
	# roriw s7, t6, 22
	.word	0x616fdb9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t6, a3
	xor	s6, a3, a4
	and	s11, s11, s6
	xor	s11, s11, a3
	addw	t1, t1, t5
	addw	s11, s7, s11
	addw	t5, t5, s11
#else
	slliw	s11, t2, 26
	srliw	s10, t2, 6
	slliw	s0, t2, 21
	srliw	s6, t2, 11
	slliw	s7, t2, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t2, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t6, 30
	xor	s6, s6, s10
	srliw	s10, t6, 2
	slliw	s0, t6, 19
	addw	t5, t5, s6
	srliw	s7, t6, 13
	slliw	s6, t6, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t6, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t3, t4
	xor	s11, t6, a3
	xor	s6, a3, a4
	xor	s7, s7, s10
	and	s0, s0, t2
	and	s11, s11, s6
	xor	s0, s0, t4
	addw	s6, s8, s9
	addw	t5, t5, s0
	xor	s11, s11, a3
	addw	t5, t5, s6
	addw	s11, s7, s11
	addw	t1, t1, t5
	addw	t5, t5, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s8, 48(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t1, 6
	.word	0x60635d1b
	# roriw s11, t1, 11
	.word	0x60b35d9b
	# roriw s6, t1, 25
	.word	0x61935b1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t2, t3
	and	s0, s0, t1
	xor	s0, s0, t3
	addw	t4, t4, s6
	addw	t4, t4, s0
	addw	s6, s8, s4
	addw	t4, t4, s6
	# roriw s10, t5, 2
	.word	0x602f5d1b
	# roriw s11, t5, 13
	.word	0x60df5d9b
	# roriw s7, t5, 22
	.word	0x616f5b9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t5, t6
	xor	s6, t6, a3
	and	s11, s11, s6
	xor	s11, s11, t6
	addw	a4, a4, t4
	addw	s11, s7, s11
	addw	t4, t4, s11
#else
	slliw	s11, t1, 26
	srliw	s10, t1, 6
	slliw	s0, t1, 21
	srliw	s6, t1, 11
	slliw	s7, t1, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t1, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t5, 30
	xor	s6, s6, s10
	srliw	s10, t5, 2
	slliw	s0, t5, 19
	addw	t4, t4, s6
	srliw	s7, t5, 13
	slliw	s6, t5, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t5, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t2, t3
	xor	s11, t5, t6
	xor	s6, t6, a3
	xor	s7, s7, s10
	and	s0, s0, t1
	and	s11, s11, s6
	xor	s0, s0, t3
	addw	s6, s8, s4
	addw	t4, t4, s0
	xor	s11, s11, t6
	addw	t4, t4, s6
	addw	s11, s7, s11
	addw	a4, a4, t4
	addw	t4, t4, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	srli	s8, s8, 32
	srli	s9, s4, 32
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, a4, 6
	.word	0x60675d1b
	# roriw s11, a4, 11
	.word	0x60b75d9b
	# roriw s6, a4, 25
	.word	0x61975b1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, t1, t2
	and	s0, s0, a4
	xor	s0, s0, t2
	addw	t3, t3, s6
	addw	t3, t3, s0
	addw	s6, s8, s9
	addw	t3, t3, s6
	# roriw s10, t4, 2
	.word	0x602edd1b
	# roriw s11, t4, 13
	.word	0x60dedd9b
	# roriw s7, t4, 22
	.word	0x616edb9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t4, t5
	xor	s6, t5, t6
	and	s11, s11, s6
	xor	s11, s11, t5
	addw	a3, a3, t3
	addw	s11, s7, s11
	addw	t3, t3, s11
#else
	slliw	s11, a4, 26
	srliw	s10, a4, 6
	slliw	s0, a4, 21
	srliw	s6, a4, 11
	slliw	s7, a4, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, a4, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t4, 30
	xor	s6, s6, s10
	srliw	s10, t4, 2
	slliw	s0, t4, 19
	addw	t3, t3, s6
	srliw	s7, t4, 13
	slliw	s6, t4, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t4, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, t1, t2
	xor	s11, t4, t5
	xor	s6, t5, t6
	xor	s7, s7, s10
	and	s0, s0, a4
	and	s11, s11, s6
	xor	s0, s0, t2
	addw	s6, s8, s9
	addw	t3, t3, s0
	xor	s11, s11, t5
	addw	t3, t3, s6
	addw	s11, s7, s11
	addw	a3, a3, t3
	addw	t3, t3, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s8, 56(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, a3, 6
	.word	0x6066dd1b
	# roriw s11, a3, 11
	.word	0x60b6dd9b
	# roriw s6, a3, 25
	.word	0x6196db1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, a4, t1
	and	s0, s0, a3
	xor	s0, s0, t1
	addw	t2, t2, s6
	addw	t2, t2, s0
	addw	s6, s8, s5
	addw	t2, t2, s6
	# roriw s10, t3, 2
	.word	0x602e5d1b
	# roriw s11, t3, 13
	.word	0x60de5d9b
	# roriw s7, t3, 22
	.word	0x616e5b9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t3, t4
	xor	s6, t4, t5
	and	s11, s11, s6
	xor	s11, s11, t4
	addw	t6, t6, t2
	addw	s11, s7, s11
	addw	t2, t2, s11
#else
	slliw	s11, a3, 26
	srliw	s10, a3, 6
	slliw	s0, a3, 21
	srliw	s6, a3, 11
	slliw	s7, a3, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, a3, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t3, 30
	xor	s6, s6, s10
	srliw	s10, t3, 2
	slliw	s0, t3, 19
	addw	t2, t2, s6
	srliw	s7, t3, 13
	slliw	s6, t3, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t3, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, a4, t1
	xor	s11, t3, t4
	xor	s6, t4, t5
	xor	s7, s7, s10
	and	s0, s0, a3
	and	s11, s11, s6
	xor	s0, s0, t1
	addw	s6, s8, s5
	addw	t2, t2, s0
	xor	s11, s11, t4
	addw	t2, t2, s6
	addw	s11, s7, s11
	addw	t6, t6, t2
	addw	t2, t2, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	srli	s8, s8, 32
	srli	s9, s5, 32
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# roriw s10, t6, 6
	.word	0x606fdd1b
	# roriw s11, t6, 11
	.word	0x60bfdd9b
	# roriw s6, t6, 25
	.word	0x619fdb1b
	xor	s6, s6, s10
	xor	s6, s6, s11
	xor	s0, a3, a4
	and	s0, s0, t6
	xor	s0, s0, a4
	addw	t1, t1, s6
	addw	t1, t1, s0
	addw	s6, s8, s9
	addw	t1, t1, s6
	# roriw s10, t2, 2
	.word	0x6023dd1b
	# roriw s11, t2, 13
	.word	0x60d3dd9b
	# roriw s7, t2, 22
	.word	0x6163db9b
	xor	s7, s7, s10
	xor	s7, s7, s11
	xor	s11, t2, t3
	xor	s6, t3, t4
	and	s11, s11, s6
	xor	s11, s11, t3
	addw	t5, t5, t1
	addw	s11, s7, s11
	addw	t1, t1, s11
#else
	slliw	s11, t6, 26
	srliw	s10, t6, 6
	slliw	s0, t6, 21
	srliw	s6, t6, 11
	slliw	s7, t6, 7
	or	s10, s10, s11
	xor	s6, s6, s0
	srliw	s11, t6, 25
	xor	s10, s10, s7
	xor	s6, s6, s11
	slliw	s11, t2, 30
	xor	s6, s6, s10
	srliw	s10, t2, 2
	slliw	s0, t2, 19
	addw	t1, t1, s6
	srliw	s7, t2, 13
	slliw	s6, t2, 10
	or	s10, s10, s11
	xor	s7, s7, s0
	srliw	s0, t2, 22
	xor	s10, s10, s6
	xor	s7, s7, s0
	xor	s0, a3, a4
	xor	s11, t2, t3
	xor	s6, t3, t4
	xor	s7, s7, s10
	and	s0, s0, t6
	and	s11, s11, s6
	xor	s0, s0, a4
	addw	s6, s8, s9
	addw	t1, t1, s0
	xor	s11, s11, t3
	addw	t1, t1, s6
	addw	s11, s7, s11
	addw	t5, t5, t1
	addw	t1, t1, s11
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	addi	t0, t0, -192
	# Add working variables back into digest state
	ld	s6, 0(a0)
	ld	s7, 8(a0)
	ld	s8, 16(a0)
	ld	s9, 24(a0)
	addw	t1, t1, s6
	addw	t3, t3, s7
	addw	t5, t5, s8
	addw	a3, a3, s9
	srli	s6, s6, 32
	srli	s7, s7, 32
	srli	s8, s8, 32
	srli	s9, s9, 32
	addw	t2, t2, s6
	addw	t4, t4, s7
	addw	t6, t6, s8
	addw	a4, a4, s9
	# Store digest
	sw	t1, 0(a0)
	sw	t2, 4(a0)
	sw	t3, 8(a0)
	sw	t4, 12(a0)
	sw	t5, 16(a0)
	sw	t6, 20(a0)
	sw	a3, 24(a0)
	sw	a4, 28(a0)
	addi	a1, a1, 64
	bnez	a2, L_SHA256_transform_riscv_len_begin
	ld	s0, 0(sp)
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
	.size	Transform_Sha256_Len_riscv,.-Transform_Sha256_Len_riscv
#endif /* WOLFSSL_RISCV_VECTOR_CRYPTO_ASM */
#endif /* !NO_SHA256 || WOLFSSL_SHA224 */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_RISCV_ASM_INLINE */
#endif /* WOLFSSL_RISCV_ASM */
