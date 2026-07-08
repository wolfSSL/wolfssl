/* riscv-64-sha512-asm
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
 *   ruby ./sha2/sha512.rb riscv64 \
 *       ../wolfssl/wolfcrypt/src/port/riscv64/riscv-64-sha512-asm.S
 */
#ifdef WOLFSSL_RISCV_ASM
#ifndef WOLFSSL_RISCV_ASM_INLINE
#if  defined(WOLFSSL_SHA512) || defined(WOLFSSL_SHA384)
#ifdef WOLFSSL_RISCV_VECTOR_CRYPTO_ASM
	.section	.rodata
	.type	L_SHA512_transform_riscv_vector_len_k, %object
	.size	L_SHA512_transform_riscv_vector_len_k, 640
	# 8-byte aligned, 64-bit aligned
	.align	3
L_SHA512_transform_riscv_vector_len_k:
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
	.text
	.globl	Transform_Sha512_Len_riscv_vector
	.type	Transform_Sha512_Len_riscv_vector,@function
	.align	2
Transform_Sha512_Len_riscv_vector:
	addi	sp, sp, -64
	la	t0, L_SHA512_transform_riscv_vector_len_k
	.option arch, +v, +zvkb, +zvknhb
	# VLEN == 128: SEW=64, LMUL=2, 4 elements per group
	vsetivli	zero, 4, e64, m2, ta, ma
	# Permute standard digest a..h into {f,e,b,a},{h,g,d,c} order
	ld	t2, 40(a0)
	sd	t2, 0(sp)
	ld	t2, 32(a0)
	sd	t2, 8(sp)
	ld	t2, 8(a0)
	sd	t2, 16(sp)
	ld	t2, 0(a0)
	sd	t2, 24(sp)
	ld	t2, 56(a0)
	sd	t2, 32(sp)
	ld	t2, 48(a0)
	sd	t2, 40(sp)
	ld	t2, 24(a0)
	sd	t2, 48(sp)
	ld	t2, 16(a0)
	sd	t2, 56(sp)
	vl4re64.v	v8, (sp)
	srli	a2, a2, 7
	# Start of loop processing a block
L_SHA512_transform_riscv_vector_len_begin:
	# Save state to add back after compression
	vmv4r.v	v28, v8
	# Load 16 W into 4 m2 groups of 4 64-bit words
	mv	t1, a1
	vl8re64.v	v0, (t1)
	vrev8.v	v0, v0
	vrev8.v	v2, v2
	vrev8.v	v4, v4
	vrev8.v	v6, v6
	# Load K (5 x 16 64-bit words) and run rounds
	mv	t1, t0
	vl8re64.v	v16, (t1)
	vadd.vv	v14, v0, v16
	vmv.x.s	t2, v2
	vsha2cl.vv	v10, v8, v14
	vmv.v.v	v12, v4
	vsha2ch.vv	v8, v10, v14
	vmv.s.x	v12, t2
	vsha2ms.vv	v0, v12, v6
	vadd.vv	v14, v2, v18
	vmv.x.s	t2, v4
	vsha2cl.vv	v10, v8, v14
	vmv.v.v	v12, v6
	vsha2ch.vv	v8, v10, v14
	vmv.s.x	v12, t2
	vsha2ms.vv	v2, v12, v0
	vadd.vv	v14, v4, v20
	vmv.x.s	t2, v6
	vsha2cl.vv	v10, v8, v14
	vmv.v.v	v12, v0
	vsha2ch.vv	v8, v10, v14
	vmv.s.x	v12, t2
	vsha2ms.vv	v4, v12, v2
	vadd.vv	v14, v6, v22
	vmv.x.s	t2, v0
	vsha2cl.vv	v10, v8, v14
	vmv.v.v	v12, v2
	vsha2ch.vv	v8, v10, v14
	vmv.s.x	v12, t2
	vsha2ms.vv	v6, v12, v4
	addi	t1, t0, 128
	vl8re64.v	v16, (t1)
	vadd.vv	v14, v0, v16
	vmv.x.s	t2, v2
	vsha2cl.vv	v10, v8, v14
	vmv.v.v	v12, v4
	vsha2ch.vv	v8, v10, v14
	vmv.s.x	v12, t2
	vsha2ms.vv	v0, v12, v6
	vadd.vv	v14, v2, v18
	vmv.x.s	t2, v4
	vsha2cl.vv	v10, v8, v14
	vmv.v.v	v12, v6
	vsha2ch.vv	v8, v10, v14
	vmv.s.x	v12, t2
	vsha2ms.vv	v2, v12, v0
	vadd.vv	v14, v4, v20
	vmv.x.s	t2, v6
	vsha2cl.vv	v10, v8, v14
	vmv.v.v	v12, v0
	vsha2ch.vv	v8, v10, v14
	vmv.s.x	v12, t2
	vsha2ms.vv	v4, v12, v2
	vadd.vv	v14, v6, v22
	vmv.x.s	t2, v0
	vsha2cl.vv	v10, v8, v14
	vmv.v.v	v12, v2
	vsha2ch.vv	v8, v10, v14
	vmv.s.x	v12, t2
	vsha2ms.vv	v6, v12, v4
	addi	t1, t0, 256
	vl8re64.v	v16, (t1)
	vadd.vv	v14, v0, v16
	vmv.x.s	t2, v2
	vsha2cl.vv	v10, v8, v14
	vmv.v.v	v12, v4
	vsha2ch.vv	v8, v10, v14
	vmv.s.x	v12, t2
	vsha2ms.vv	v0, v12, v6
	vadd.vv	v14, v2, v18
	vmv.x.s	t2, v4
	vsha2cl.vv	v10, v8, v14
	vmv.v.v	v12, v6
	vsha2ch.vv	v8, v10, v14
	vmv.s.x	v12, t2
	vsha2ms.vv	v2, v12, v0
	vadd.vv	v14, v4, v20
	vmv.x.s	t2, v6
	vsha2cl.vv	v10, v8, v14
	vmv.v.v	v12, v0
	vsha2ch.vv	v8, v10, v14
	vmv.s.x	v12, t2
	vsha2ms.vv	v4, v12, v2
	vadd.vv	v14, v6, v22
	vmv.x.s	t2, v0
	vsha2cl.vv	v10, v8, v14
	vmv.v.v	v12, v2
	vsha2ch.vv	v8, v10, v14
	vmv.s.x	v12, t2
	vsha2ms.vv	v6, v12, v4
	addi	t1, t0, 384
	vl8re64.v	v16, (t1)
	vadd.vv	v14, v0, v16
	vmv.x.s	t2, v2
	vsha2cl.vv	v10, v8, v14
	vmv.v.v	v12, v4
	vsha2ch.vv	v8, v10, v14
	vmv.s.x	v12, t2
	vsha2ms.vv	v0, v12, v6
	vadd.vv	v14, v2, v18
	vmv.x.s	t2, v4
	vsha2cl.vv	v10, v8, v14
	vmv.v.v	v12, v6
	vsha2ch.vv	v8, v10, v14
	vmv.s.x	v12, t2
	vsha2ms.vv	v2, v12, v0
	vadd.vv	v14, v4, v20
	vmv.x.s	t2, v6
	vsha2cl.vv	v10, v8, v14
	vmv.v.v	v12, v0
	vsha2ch.vv	v8, v10, v14
	vmv.s.x	v12, t2
	vsha2ms.vv	v4, v12, v2
	vadd.vv	v14, v6, v22
	vmv.x.s	t2, v0
	vsha2cl.vv	v10, v8, v14
	vmv.v.v	v12, v2
	vsha2ch.vv	v8, v10, v14
	vmv.s.x	v12, t2
	vsha2ms.vv	v6, v12, v4
	addi	t1, t0, 512
	vl8re64.v	v16, (t1)
	vadd.vv	v14, v0, v16
	vsha2cl.vv	v10, v8, v14
	vsha2ch.vv	v8, v10, v14
	vadd.vv	v14, v2, v18
	vsha2cl.vv	v10, v8, v14
	vsha2ch.vv	v8, v10, v14
	vadd.vv	v14, v4, v20
	vsha2cl.vv	v10, v8, v14
	vsha2ch.vv	v8, v10, v14
	vadd.vv	v14, v6, v22
	vsha2cl.vv	v10, v8, v14
	vsha2ch.vv	v8, v10, v14
	vadd.vv	v8, v8, v28
	vadd.vv	v10, v10, v30
	addi	a2, a2, -1
	addi	a1, a1, 128
	bnez	a2, L_SHA512_transform_riscv_vector_len_begin
	# Store state back in standard digest order a..h
	vs4r.v	v8, (sp)
	ld	t2, 24(sp)
	sd	t2, 0(a0)
	ld	t2, 16(sp)
	sd	t2, 8(a0)
	ld	t2, 56(sp)
	sd	t2, 16(a0)
	ld	t2, 48(sp)
	sd	t2, 24(a0)
	ld	t2, 8(sp)
	sd	t2, 32(a0)
	ld	t2, 0(sp)
	sd	t2, 40(a0)
	ld	t2, 40(sp)
	sd	t2, 48(a0)
	ld	t2, 32(sp)
	sd	t2, 56(a0)
	addi	sp, sp, 64
	ret
	.size	Transform_Sha512_Len_riscv_vector,.-Transform_Sha512_Len_riscv_vector
#elif defined(WOLFSSL_RISCV_SCALAR_CRYPTO_ASM)
	.section	.rodata
	.type	L_SHA512_transform_riscv_crypto_len_k, %object
	.size	L_SHA512_transform_riscv_crypto_len_k, 640
	# 8-byte aligned, 64-bit aligned
	.align	3
L_SHA512_transform_riscv_crypto_len_k:
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
	.text
	.globl	Transform_Sha512_Len_riscv_crypto
	.type	Transform_Sha512_Len_riscv_crypto,@function
	.align	2
Transform_Sha512_Len_riscv_crypto:
	addi	sp, sp, -224
	sd	s1, 136(sp)
	sd	s2, 144(sp)
	sd	s3, 152(sp)
	sd	s4, 160(sp)
	sd	s5, 168(sp)
	sd	s6, 176(sp)
	sd	s7, 184(sp)
	sd	s8, 192(sp)
	sd	s9, 200(sp)
	sd	s10, 208(sp)
	sd	s11, 216(sp)
	la	t0, L_SHA512_transform_riscv_crypto_len_k
	.option arch, +zknh
	# Load digest into working variables
	ld	t1, 0(a0)
	ld	t2, 8(a0)
	ld	t3, 16(a0)
	ld	t4, 24(a0)
	ld	t5, 32(a0)
	ld	t6, 40(a0)
	ld	a3, 48(a0)
	ld	a4, 56(a0)
	srli	a2, a2, 5
	# Start of loop processing a block
L_SHA512_transform_riscv_crypto_len_begin:
	# Load W into stack buffer, big-endian
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) || defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lbu	s8, 4(a1)
	lbu	s9, 5(a1)
	lbu	s10, 6(a1)
	lbu	s5, 7(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s5, s5, s8
	or	s5, s5, s9
	or	s5, s5, s10
	lbu	s8, 0(a1)
	lbu	s9, 1(a1)
	lbu	s10, 2(a1)
	lbu	s11, 3(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s5, s5, s8
	or	s5, s5, s9
	or	s5, s5, s10
	or	s5, s5, s11
	lbu	s8, 12(a1)
	lbu	s9, 13(a1)
	lbu	s10, 14(a1)
	lbu	a5, 15(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	a5, a5, s8
	or	a5, a5, s9
	or	a5, a5, s10
	lbu	s8, 8(a1)
	lbu	s9, 9(a1)
	lbu	s10, 10(a1)
	lbu	s11, 11(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	a5, a5, s8
	or	a5, a5, s9
	or	a5, a5, s10
	or	a5, a5, s11
	lbu	s8, 20(a1)
	lbu	s9, 21(a1)
	lbu	s10, 22(a1)
	lbu	a6, 23(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	a6, a6, s8
	or	a6, a6, s9
	or	a6, a6, s10
	lbu	s8, 16(a1)
	lbu	s9, 17(a1)
	lbu	s10, 18(a1)
	lbu	s11, 19(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	a6, a6, s8
	or	a6, a6, s9
	or	a6, a6, s10
	or	a6, a6, s11
	lbu	s8, 28(a1)
	lbu	s9, 29(a1)
	lbu	s10, 30(a1)
	lbu	a7, 31(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	a7, a7, s8
	or	a7, a7, s9
	or	a7, a7, s10
	lbu	s8, 24(a1)
	lbu	s9, 25(a1)
	lbu	s10, 26(a1)
	lbu	s11, 27(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	a7, a7, s8
	or	a7, a7, s9
	or	a7, a7, s10
	or	a7, a7, s11
	lbu	s8, 36(a1)
	lbu	s9, 37(a1)
	lbu	s10, 38(a1)
	lbu	s1, 39(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s1, s1, s8
	or	s1, s1, s9
	or	s1, s1, s10
	lbu	s8, 32(a1)
	lbu	s9, 33(a1)
	lbu	s10, 34(a1)
	lbu	s11, 35(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s1, s1, s8
	or	s1, s1, s9
	or	s1, s1, s10
	or	s1, s1, s11
	lbu	s8, 44(a1)
	lbu	s9, 45(a1)
	lbu	s10, 46(a1)
	lbu	s2, 47(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s2, s2, s8
	or	s2, s2, s9
	or	s2, s2, s10
	lbu	s8, 40(a1)
	lbu	s9, 41(a1)
	lbu	s10, 42(a1)
	lbu	s11, 43(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s2, s2, s8
	or	s2, s2, s9
	or	s2, s2, s10
	or	s2, s2, s11
	lbu	s8, 52(a1)
	lbu	s9, 53(a1)
	lbu	s10, 54(a1)
	lbu	s3, 55(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s3, s3, s8
	or	s3, s3, s9
	or	s3, s3, s10
	lbu	s8, 48(a1)
	lbu	s9, 49(a1)
	lbu	s10, 50(a1)
	lbu	s11, 51(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s3, s3, s8
	or	s3, s3, s9
	or	s3, s3, s10
	or	s3, s3, s11
	lbu	s8, 60(a1)
	lbu	s9, 61(a1)
	lbu	s10, 62(a1)
	lbu	s4, 63(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s4, s4, s8
	or	s4, s4, s9
	or	s4, s4, s10
	lbu	s8, 56(a1)
	lbu	s9, 57(a1)
	lbu	s10, 58(a1)
	lbu	s11, 59(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s4, s4, s8
	or	s4, s4, s9
	or	s4, s4, s10
	or	s4, s4, s11
	sd	s5, 0(sp)
	sd	a5, 8(sp)
	sd	a6, 16(sp)
	sd	a7, 24(sp)
	sd	s1, 32(sp)
	sd	s2, 40(sp)
	sd	s3, 48(sp)
	sd	s4, 56(sp)
	lbu	s8, 68(a1)
	lbu	s9, 69(a1)
	lbu	s10, 70(a1)
	lbu	s5, 71(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s5, s5, s8
	or	s5, s5, s9
	or	s5, s5, s10
	lbu	s8, 64(a1)
	lbu	s9, 65(a1)
	lbu	s10, 66(a1)
	lbu	s11, 67(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s5, s5, s8
	or	s5, s5, s9
	or	s5, s5, s10
	or	s5, s5, s11
	lbu	s8, 76(a1)
	lbu	s9, 77(a1)
	lbu	s10, 78(a1)
	lbu	a5, 79(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	a5, a5, s8
	or	a5, a5, s9
	or	a5, a5, s10
	lbu	s8, 72(a1)
	lbu	s9, 73(a1)
	lbu	s10, 74(a1)
	lbu	s11, 75(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	a5, a5, s8
	or	a5, a5, s9
	or	a5, a5, s10
	or	a5, a5, s11
	lbu	s8, 84(a1)
	lbu	s9, 85(a1)
	lbu	s10, 86(a1)
	lbu	a6, 87(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	a6, a6, s8
	or	a6, a6, s9
	or	a6, a6, s10
	lbu	s8, 80(a1)
	lbu	s9, 81(a1)
	lbu	s10, 82(a1)
	lbu	s11, 83(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	a6, a6, s8
	or	a6, a6, s9
	or	a6, a6, s10
	or	a6, a6, s11
	lbu	s8, 92(a1)
	lbu	s9, 93(a1)
	lbu	s10, 94(a1)
	lbu	a7, 95(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	a7, a7, s8
	or	a7, a7, s9
	or	a7, a7, s10
	lbu	s8, 88(a1)
	lbu	s9, 89(a1)
	lbu	s10, 90(a1)
	lbu	s11, 91(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	a7, a7, s8
	or	a7, a7, s9
	or	a7, a7, s10
	or	a7, a7, s11
	lbu	s8, 100(a1)
	lbu	s9, 101(a1)
	lbu	s10, 102(a1)
	lbu	s1, 103(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s1, s1, s8
	or	s1, s1, s9
	or	s1, s1, s10
	lbu	s8, 96(a1)
	lbu	s9, 97(a1)
	lbu	s10, 98(a1)
	lbu	s11, 99(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s1, s1, s8
	or	s1, s1, s9
	or	s1, s1, s10
	or	s1, s1, s11
	lbu	s8, 108(a1)
	lbu	s9, 109(a1)
	lbu	s10, 110(a1)
	lbu	s2, 111(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s2, s2, s8
	or	s2, s2, s9
	or	s2, s2, s10
	lbu	s8, 104(a1)
	lbu	s9, 105(a1)
	lbu	s10, 106(a1)
	lbu	s11, 107(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s2, s2, s8
	or	s2, s2, s9
	or	s2, s2, s10
	or	s2, s2, s11
	lbu	s8, 116(a1)
	lbu	s9, 117(a1)
	lbu	s10, 118(a1)
	lbu	s3, 119(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s3, s3, s8
	or	s3, s3, s9
	or	s3, s3, s10
	lbu	s8, 112(a1)
	lbu	s9, 113(a1)
	lbu	s10, 114(a1)
	lbu	s11, 115(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s3, s3, s8
	or	s3, s3, s9
	or	s3, s3, s10
	or	s3, s3, s11
	lbu	s8, 124(a1)
	lbu	s9, 125(a1)
	lbu	s10, 126(a1)
	lbu	s4, 127(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s4, s4, s8
	or	s4, s4, s9
	or	s4, s4, s10
	lbu	s8, 120(a1)
	lbu	s9, 121(a1)
	lbu	s10, 122(a1)
	lbu	s11, 123(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s4, s4, s8
	or	s4, s4, s9
	or	s4, s4, s10
	or	s4, s4, s11
	sd	s5, 64(sp)
	sd	a5, 72(sp)
	sd	a6, 80(sp)
	sd	a7, 88(sp)
	sd	s1, 96(sp)
	sd	s2, 104(sp)
	sd	s3, 112(sp)
	sd	s4, 120(sp)
#else
	ld	s5, 0(a1)
	# rev8 s5, s5
	.word	0x6b8ada93
	ld	a5, 8(a1)
	# rev8 a5, a5
	.word	0x6b87d793
	ld	a6, 16(a1)
	# rev8 a6, a6
	.word	0x6b885813
	ld	a7, 24(a1)
	# rev8 a7, a7
	.word	0x6b88d893
	ld	s1, 32(a1)
	# rev8 s1, s1
	.word	0x6b84d493
	ld	s2, 40(a1)
	# rev8 s2, s2
	.word	0x6b895913
	ld	s3, 48(a1)
	# rev8 s3, s3
	.word	0x6b89d993
	ld	s4, 56(a1)
	# rev8 s4, s4
	.word	0x6b8a5a13
	sd	s5, 0(sp)
	sd	a5, 8(sp)
	sd	a6, 16(sp)
	sd	a7, 24(sp)
	sd	s1, 32(sp)
	sd	s2, 40(sp)
	sd	s3, 48(sp)
	sd	s4, 56(sp)
	ld	s5, 64(a1)
	# rev8 s5, s5
	.word	0x6b8ada93
	ld	a5, 72(a1)
	# rev8 a5, a5
	.word	0x6b87d793
	ld	a6, 80(a1)
	# rev8 a6, a6
	.word	0x6b885813
	ld	a7, 88(a1)
	# rev8 a7, a7
	.word	0x6b88d893
	ld	s1, 96(a1)
	# rev8 s1, s1
	.word	0x6b84d493
	ld	s2, 104(a1)
	# rev8 s2, s2
	.word	0x6b895913
	ld	s3, 112(a1)
	# rev8 s3, s3
	.word	0x6b89d993
	ld	s4, 120(a1)
	# rev8 s4, s4
	.word	0x6b8a5a13
	sd	s5, 64(sp)
	sd	a5, 72(sp)
	sd	a6, 80(sp)
	sd	a7, 88(sp)
	sd	s1, 96(sp)
	sd	s2, 104(sp)
	sd	s3, 112(sp)
	sd	s4, 120(sp)
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) || defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
L_SHA512_transform_riscv_crypto_len_inner:
	# Reload W[0], W[14], W[15] for message schedule
	ld	a5, 0(sp)
	ld	s1, 112(sp)
	ld	s2, 120(sp)
	addi	a2, a2, -1
	ld	s10, 0(t0)
	ld	s11, 8(t0)
	mv	s8, t5
	mv	s9, t1
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t1, t2
	xor	s7, t6, a3
	xor	s6, t2, t3
	and	s7, s7, t5
	and	s6, s6, s5
	xor	s7, s7, a3
	xor	s6, s6, t2
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	a4, a4, s5
	add	s6, s9, s6
	add	t4, t4, a4
	add	a4, a4, s6
	ld	a6, 8(sp)
	ld	a7, 72(sp)
	sha512sig0	s8, a6
	sha512sig1	s9, s1
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
	mv	s8, t4
	mv	s9, a4
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, a4, t1
	xor	s7, t5, t6
	xor	s6, t1, t2
	and	s7, s7, t4
	and	s6, s6, s5
	xor	s7, s7, t6
	xor	s6, s6, t1
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	a3, a3, s5
	add	s6, s9, s6
	add	t3, t3, a3
	add	a3, a3, s6
	mv	s1, a5
	ld	a5, 16(sp)
	ld	a7, 80(sp)
	sha512sig0	s8, a5
	sha512sig1	s9, s2
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
	sd	s1, 0(sp)
	mv	s2, a6
	sd	a6, 8(sp)
	ld	s10, 16(t0)
	ld	s11, 24(t0)
	mv	s8, t3
	mv	s9, a3
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, a3, a4
	xor	s7, t4, t5
	xor	s6, a4, t1
	and	s7, s7, t3
	and	s6, s6, s5
	xor	s7, s7, t5
	xor	s6, s6, a4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t6, t6, s5
	add	s6, s9, s6
	add	t2, t2, t6
	add	t6, t6, s6
	ld	a6, 24(sp)
	ld	a7, 88(sp)
	sha512sig0	s8, a6
	sha512sig1	s9, s1
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
	mv	s8, t2
	mv	s9, t6
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t6, a3
	xor	s7, t3, t4
	xor	s6, a3, a4
	and	s7, s7, t2
	and	s6, s6, s5
	xor	s7, s7, t4
	xor	s6, s6, a3
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	t5, t5, s5
	add	s6, s9, s6
	add	t1, t1, t5
	add	t5, t5, s6
	mv	s1, a5
	ld	a5, 32(sp)
	ld	a7, 96(sp)
	sha512sig0	s8, a5
	sha512sig1	s9, s2
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
	sd	s1, 16(sp)
	mv	s2, a6
	sd	a6, 24(sp)
	ld	s10, 32(t0)
	ld	s11, 40(t0)
	mv	s8, t1
	mv	s9, t5
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t5, t6
	xor	s7, t2, t3
	xor	s6, t6, a3
	and	s7, s7, t1
	and	s6, s6, s5
	xor	s7, s7, t3
	xor	s6, s6, t6
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t4, t4, s5
	add	s6, s9, s6
	add	a4, a4, t4
	add	t4, t4, s6
	ld	a6, 40(sp)
	ld	a7, 104(sp)
	sha512sig0	s8, a6
	sha512sig1	s9, s1
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
	mv	s8, a4
	mv	s9, t4
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t4, t5
	xor	s7, t1, t2
	xor	s6, t5, t6
	and	s7, s7, a4
	and	s6, s6, s5
	xor	s7, s7, t2
	xor	s6, s6, t5
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	t3, t3, s5
	add	s6, s9, s6
	add	a3, a3, t3
	add	t3, t3, s6
	mv	s1, a5
	ld	a5, 48(sp)
	ld	a7, 112(sp)
	sha512sig0	s8, a5
	sha512sig1	s9, s2
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
	sd	s1, 32(sp)
	mv	s2, a6
	sd	a6, 40(sp)
	ld	s10, 48(t0)
	ld	s11, 56(t0)
	mv	s8, a3
	mv	s9, t3
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t3, t4
	xor	s7, a4, t1
	xor	s6, t4, t5
	and	s7, s7, a3
	and	s6, s6, s5
	xor	s7, s7, t1
	xor	s6, s6, t4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t2, t2, s5
	add	s6, s9, s6
	add	t6, t6, t2
	add	t2, t2, s6
	ld	a6, 56(sp)
	ld	a7, 120(sp)
	sha512sig0	s8, a6
	sha512sig1	s9, s1
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
	mv	s8, t6
	mv	s9, t2
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t2, t3
	xor	s7, a3, a4
	xor	s6, t3, t4
	and	s7, s7, t6
	and	s6, s6, s5
	xor	s7, s7, a4
	xor	s6, s6, t3
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	t1, t1, s5
	add	s6, s9, s6
	add	t5, t5, t1
	add	t1, t1, s6
	mv	s1, a5
	ld	a5, 64(sp)
	ld	a7, 0(sp)
	sha512sig0	s8, a5
	sha512sig1	s9, s2
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
	sd	s1, 48(sp)
	mv	s2, a6
	sd	a6, 56(sp)
	ld	s10, 64(t0)
	ld	s11, 72(t0)
	mv	s8, t5
	mv	s9, t1
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t1, t2
	xor	s7, t6, a3
	xor	s6, t2, t3
	and	s7, s7, t5
	and	s6, s6, s5
	xor	s7, s7, a3
	xor	s6, s6, t2
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	a4, a4, s5
	add	s6, s9, s6
	add	t4, t4, a4
	add	a4, a4, s6
	ld	a6, 72(sp)
	ld	a7, 8(sp)
	sha512sig0	s8, a6
	sha512sig1	s9, s1
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
	mv	s8, t4
	mv	s9, a4
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, a4, t1
	xor	s7, t5, t6
	xor	s6, t1, t2
	and	s7, s7, t4
	and	s6, s6, s5
	xor	s7, s7, t6
	xor	s6, s6, t1
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	a3, a3, s5
	add	s6, s9, s6
	add	t3, t3, a3
	add	a3, a3, s6
	mv	s1, a5
	ld	a5, 80(sp)
	ld	a7, 16(sp)
	sha512sig0	s8, a5
	sha512sig1	s9, s2
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
	sd	s1, 64(sp)
	mv	s2, a6
	sd	a6, 72(sp)
	ld	s10, 80(t0)
	ld	s11, 88(t0)
	mv	s8, t3
	mv	s9, a3
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, a3, a4
	xor	s7, t4, t5
	xor	s6, a4, t1
	and	s7, s7, t3
	and	s6, s6, s5
	xor	s7, s7, t5
	xor	s6, s6, a4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t6, t6, s5
	add	s6, s9, s6
	add	t2, t2, t6
	add	t6, t6, s6
	ld	a6, 88(sp)
	ld	a7, 24(sp)
	sha512sig0	s8, a6
	sha512sig1	s9, s1
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
	mv	s8, t2
	mv	s9, t6
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t6, a3
	xor	s7, t3, t4
	xor	s6, a3, a4
	and	s7, s7, t2
	and	s6, s6, s5
	xor	s7, s7, t4
	xor	s6, s6, a3
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	t5, t5, s5
	add	s6, s9, s6
	add	t1, t1, t5
	add	t5, t5, s6
	mv	s1, a5
	ld	a5, 96(sp)
	ld	a7, 32(sp)
	sha512sig0	s8, a5
	sha512sig1	s9, s2
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
	sd	s1, 80(sp)
	mv	s2, a6
	sd	a6, 88(sp)
	ld	s10, 96(t0)
	ld	s11, 104(t0)
	mv	s8, t1
	mv	s9, t5
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t5, t6
	xor	s7, t2, t3
	xor	s6, t6, a3
	and	s7, s7, t1
	and	s6, s6, s5
	xor	s7, s7, t3
	xor	s6, s6, t6
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t4, t4, s5
	add	s6, s9, s6
	add	a4, a4, t4
	add	t4, t4, s6
	ld	a6, 104(sp)
	ld	a7, 40(sp)
	sha512sig0	s8, a6
	sha512sig1	s9, s1
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
	mv	s8, a4
	mv	s9, t4
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t4, t5
	xor	s7, t1, t2
	xor	s6, t5, t6
	and	s7, s7, a4
	and	s6, s6, s5
	xor	s7, s7, t2
	xor	s6, s6, t5
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	t3, t3, s5
	add	s6, s9, s6
	add	a3, a3, t3
	add	t3, t3, s6
	mv	s1, a5
	ld	a5, 112(sp)
	ld	a7, 48(sp)
	sha512sig0	s8, a5
	sha512sig1	s9, s2
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
	sd	s1, 96(sp)
	mv	s2, a6
	sd	a6, 104(sp)
	ld	s10, 112(t0)
	ld	s11, 120(t0)
	mv	s8, a3
	mv	s9, t3
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t3, t4
	xor	s7, a4, t1
	xor	s6, t4, t5
	and	s7, s7, a3
	and	s6, s6, s5
	xor	s7, s7, t1
	xor	s6, s6, t4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t2, t2, s5
	add	s6, s9, s6
	add	t6, t6, t2
	add	t2, t2, s6
	ld	a6, 120(sp)
	ld	a7, 56(sp)
	sha512sig0	s8, a6
	sha512sig1	s9, s1
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
	mv	s8, t6
	mv	s9, t2
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t2, t3
	xor	s7, a3, a4
	xor	s6, t3, t4
	and	s7, s7, t6
	and	s6, s6, s5
	xor	s7, s7, a4
	xor	s6, s6, t3
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	t1, t1, s5
	add	s6, s9, s6
	add	t5, t5, t1
	add	t1, t1, s6
	mv	s1, a5
	ld	a5, 0(sp)
	ld	a7, 64(sp)
	sha512sig0	s8, a5
	sha512sig1	s9, s2
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
	sd	s1, 112(sp)
	mv	s2, a6
	sd	a6, 120(sp)
	andi	s8, a2, 3
	addi	t0, t0, 128
	bnez	s8, L_SHA512_transform_riscv_crypto_len_inner
	ld	s10, 0(t0)
	ld	a5, 0(sp)
	mv	s8, t5
	mv	s9, t1
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t1, t2
	xor	s7, t6, a3
	xor	s6, t2, t3
	and	s7, s7, t5
	and	s6, s6, s5
	xor	s7, s7, a3
	xor	s6, s6, t2
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	a4, a4, s5
	add	s6, s9, s6
	add	t4, t4, a4
	add	a4, a4, s6
	ld	s10, 8(t0)
	ld	a5, 8(sp)
	mv	s8, t4
	mv	s9, a4
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, a4, t1
	xor	s7, t5, t6
	xor	s6, t1, t2
	and	s7, s7, t4
	and	s6, s6, s5
	xor	s7, s7, t6
	xor	s6, s6, t1
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	a3, a3, s5
	add	s6, s9, s6
	add	t3, t3, a3
	add	a3, a3, s6
	ld	s10, 16(t0)
	ld	a5, 16(sp)
	mv	s8, t3
	mv	s9, a3
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, a3, a4
	xor	s7, t4, t5
	xor	s6, a4, t1
	and	s7, s7, t3
	and	s6, s6, s5
	xor	s7, s7, t5
	xor	s6, s6, a4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t6, t6, s5
	add	s6, s9, s6
	add	t2, t2, t6
	add	t6, t6, s6
	ld	s10, 24(t0)
	ld	a5, 24(sp)
	mv	s8, t2
	mv	s9, t6
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t6, a3
	xor	s7, t3, t4
	xor	s6, a3, a4
	and	s7, s7, t2
	and	s6, s6, s5
	xor	s7, s7, t4
	xor	s6, s6, a3
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t5, t5, s5
	add	s6, s9, s6
	add	t1, t1, t5
	add	t5, t5, s6
	ld	s10, 32(t0)
	ld	a5, 32(sp)
	mv	s8, t1
	mv	s9, t5
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t5, t6
	xor	s7, t2, t3
	xor	s6, t6, a3
	and	s7, s7, t1
	and	s6, s6, s5
	xor	s7, s7, t3
	xor	s6, s6, t6
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t4, t4, s5
	add	s6, s9, s6
	add	a4, a4, t4
	add	t4, t4, s6
	ld	s10, 40(t0)
	ld	a5, 40(sp)
	mv	s8, a4
	mv	s9, t4
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t4, t5
	xor	s7, t1, t2
	xor	s6, t5, t6
	and	s7, s7, a4
	and	s6, s6, s5
	xor	s7, s7, t2
	xor	s6, s6, t5
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t3, t3, s5
	add	s6, s9, s6
	add	a3, a3, t3
	add	t3, t3, s6
	ld	s10, 48(t0)
	ld	a5, 48(sp)
	mv	s8, a3
	mv	s9, t3
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t3, t4
	xor	s7, a4, t1
	xor	s6, t4, t5
	and	s7, s7, a3
	and	s6, s6, s5
	xor	s7, s7, t1
	xor	s6, s6, t4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t2, t2, s5
	add	s6, s9, s6
	add	t6, t6, t2
	add	t2, t2, s6
	ld	s10, 56(t0)
	ld	a5, 56(sp)
	mv	s8, t6
	mv	s9, t2
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t2, t3
	xor	s7, a3, a4
	xor	s6, t3, t4
	and	s7, s7, t6
	and	s6, s6, s5
	xor	s7, s7, a4
	xor	s6, s6, t3
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t1, t1, s5
	add	s6, s9, s6
	add	t5, t5, t1
	add	t1, t1, s6
	ld	s10, 64(t0)
	ld	a5, 64(sp)
	mv	s8, t5
	mv	s9, t1
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t1, t2
	xor	s7, t6, a3
	xor	s6, t2, t3
	and	s7, s7, t5
	and	s6, s6, s5
	xor	s7, s7, a3
	xor	s6, s6, t2
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	a4, a4, s5
	add	s6, s9, s6
	add	t4, t4, a4
	add	a4, a4, s6
	ld	s10, 72(t0)
	ld	a5, 72(sp)
	mv	s8, t4
	mv	s9, a4
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, a4, t1
	xor	s7, t5, t6
	xor	s6, t1, t2
	and	s7, s7, t4
	and	s6, s6, s5
	xor	s7, s7, t6
	xor	s6, s6, t1
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	a3, a3, s5
	add	s6, s9, s6
	add	t3, t3, a3
	add	a3, a3, s6
	ld	s10, 80(t0)
	ld	a5, 80(sp)
	mv	s8, t3
	mv	s9, a3
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, a3, a4
	xor	s7, t4, t5
	xor	s6, a4, t1
	and	s7, s7, t3
	and	s6, s6, s5
	xor	s7, s7, t5
	xor	s6, s6, a4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t6, t6, s5
	add	s6, s9, s6
	add	t2, t2, t6
	add	t6, t6, s6
	ld	s10, 88(t0)
	ld	a5, 88(sp)
	mv	s8, t2
	mv	s9, t6
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t6, a3
	xor	s7, t3, t4
	xor	s6, a3, a4
	and	s7, s7, t2
	and	s6, s6, s5
	xor	s7, s7, t4
	xor	s6, s6, a3
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t5, t5, s5
	add	s6, s9, s6
	add	t1, t1, t5
	add	t5, t5, s6
	ld	s10, 96(t0)
	ld	a5, 96(sp)
	mv	s8, t1
	mv	s9, t5
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t5, t6
	xor	s7, t2, t3
	xor	s6, t6, a3
	and	s7, s7, t1
	and	s6, s6, s5
	xor	s7, s7, t3
	xor	s6, s6, t6
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t4, t4, s5
	add	s6, s9, s6
	add	a4, a4, t4
	add	t4, t4, s6
	ld	s10, 104(t0)
	ld	a5, 104(sp)
	mv	s8, a4
	mv	s9, t4
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t4, t5
	xor	s7, t1, t2
	xor	s6, t5, t6
	and	s7, s7, a4
	and	s6, s6, s5
	xor	s7, s7, t2
	xor	s6, s6, t5
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t3, t3, s5
	add	s6, s9, s6
	add	a3, a3, t3
	add	t3, t3, s6
	ld	s10, 112(t0)
	ld	a5, 112(sp)
	mv	s8, a3
	mv	s9, t3
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t3, t4
	xor	s7, a4, t1
	xor	s6, t4, t5
	and	s7, s7, a3
	and	s6, s6, s5
	xor	s7, s7, t1
	xor	s6, s6, t4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t2, t2, s5
	add	s6, s9, s6
	add	t6, t6, t2
	add	t2, t2, s6
	ld	s10, 120(t0)
	ld	a5, 120(sp)
	mv	s8, t6
	mv	s9, t2
	sha512sum1	s8, s8
	sha512sum0	s9, s9
	xor	s5, t2, t3
	xor	s7, a3, a4
	xor	s6, t3, t4
	and	s7, s7, t6
	and	s6, s6, s5
	xor	s7, s7, a4
	xor	s6, s6, t3
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t1, t1, s5
	add	s6, s9, s6
	add	t5, t5, t1
	add	t1, t1, s6
	addi	t0, t0, -512
	# Add working variables back into digest state
	ld	s5, 0(a0)
	ld	a5, 8(a0)
	ld	a6, 16(a0)
	ld	a7, 24(a0)
	ld	s1, 32(a0)
	ld	s2, 40(a0)
	ld	s3, 48(a0)
	ld	s4, 56(a0)
	add	t1, t1, s5
	add	t2, t2, a5
	add	t3, t3, a6
	add	t4, t4, a7
	add	t5, t5, s1
	add	t6, t6, s2
	add	a3, a3, s3
	add	a4, a4, s4
	# Store digest
	sd	t1, 0(a0)
	sd	t2, 8(a0)
	sd	t3, 16(a0)
	sd	t4, 24(a0)
	sd	t5, 32(a0)
	sd	t6, 40(a0)
	sd	a3, 48(a0)
	sd	a4, 56(a0)
	addi	a1, a1, 128
	bnez	a2, L_SHA512_transform_riscv_crypto_len_begin
	ld	s1, 136(sp)
	ld	s2, 144(sp)
	ld	s3, 152(sp)
	ld	s4, 160(sp)
	ld	s5, 168(sp)
	ld	s6, 176(sp)
	ld	s7, 184(sp)
	ld	s8, 192(sp)
	ld	s9, 200(sp)
	ld	s10, 208(sp)
	ld	s11, 216(sp)
	addi	sp, sp, 224
	ret
	.size	Transform_Sha512_Len_riscv_crypto,.-Transform_Sha512_Len_riscv_crypto
#else
	.section	.rodata
	.type	L_SHA512_transform_riscv_len_k, %object
	.size	L_SHA512_transform_riscv_len_k, 640
	# 8-byte aligned, 64-bit aligned
	.align	3
L_SHA512_transform_riscv_len_k:
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
	.text
	.globl	Transform_Sha512_Len_riscv
	.type	Transform_Sha512_Len_riscv,@function
	.align	2
Transform_Sha512_Len_riscv:
	addi	sp, sp, -224
	sd	s1, 136(sp)
	sd	s2, 144(sp)
	sd	s3, 152(sp)
	sd	s4, 160(sp)
	sd	s5, 168(sp)
	sd	s6, 176(sp)
	sd	s7, 184(sp)
	sd	s8, 192(sp)
	sd	s9, 200(sp)
	sd	s10, 208(sp)
	sd	s11, 216(sp)
	la	t0, L_SHA512_transform_riscv_len_k
	# Load digest into working variables
	ld	t1, 0(a0)
	ld	t2, 8(a0)
	ld	t3, 16(a0)
	ld	t4, 24(a0)
	ld	t5, 32(a0)
	ld	t6, 40(a0)
	ld	a3, 48(a0)
	ld	a4, 56(a0)
	srli	a2, a2, 5
	# Start of loop processing a block
L_SHA512_transform_riscv_len_begin:
	# Load W into stack buffer, big-endian
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) || defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lbu	s8, 4(a1)
	lbu	s9, 5(a1)
	lbu	s10, 6(a1)
	lbu	s5, 7(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s5, s5, s8
	or	s5, s5, s9
	or	s5, s5, s10
	lbu	s8, 0(a1)
	lbu	s9, 1(a1)
	lbu	s10, 2(a1)
	lbu	s11, 3(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s5, s5, s8
	or	s5, s5, s9
	or	s5, s5, s10
	or	s5, s5, s11
	lbu	s8, 12(a1)
	lbu	s9, 13(a1)
	lbu	s10, 14(a1)
	lbu	a5, 15(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	a5, a5, s8
	or	a5, a5, s9
	or	a5, a5, s10
	lbu	s8, 8(a1)
	lbu	s9, 9(a1)
	lbu	s10, 10(a1)
	lbu	s11, 11(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	a5, a5, s8
	or	a5, a5, s9
	or	a5, a5, s10
	or	a5, a5, s11
	lbu	s8, 20(a1)
	lbu	s9, 21(a1)
	lbu	s10, 22(a1)
	lbu	a6, 23(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	a6, a6, s8
	or	a6, a6, s9
	or	a6, a6, s10
	lbu	s8, 16(a1)
	lbu	s9, 17(a1)
	lbu	s10, 18(a1)
	lbu	s11, 19(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	a6, a6, s8
	or	a6, a6, s9
	or	a6, a6, s10
	or	a6, a6, s11
	lbu	s8, 28(a1)
	lbu	s9, 29(a1)
	lbu	s10, 30(a1)
	lbu	a7, 31(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	a7, a7, s8
	or	a7, a7, s9
	or	a7, a7, s10
	lbu	s8, 24(a1)
	lbu	s9, 25(a1)
	lbu	s10, 26(a1)
	lbu	s11, 27(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	a7, a7, s8
	or	a7, a7, s9
	or	a7, a7, s10
	or	a7, a7, s11
	lbu	s8, 36(a1)
	lbu	s9, 37(a1)
	lbu	s10, 38(a1)
	lbu	s1, 39(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s1, s1, s8
	or	s1, s1, s9
	or	s1, s1, s10
	lbu	s8, 32(a1)
	lbu	s9, 33(a1)
	lbu	s10, 34(a1)
	lbu	s11, 35(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s1, s1, s8
	or	s1, s1, s9
	or	s1, s1, s10
	or	s1, s1, s11
	lbu	s8, 44(a1)
	lbu	s9, 45(a1)
	lbu	s10, 46(a1)
	lbu	s2, 47(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s2, s2, s8
	or	s2, s2, s9
	or	s2, s2, s10
	lbu	s8, 40(a1)
	lbu	s9, 41(a1)
	lbu	s10, 42(a1)
	lbu	s11, 43(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s2, s2, s8
	or	s2, s2, s9
	or	s2, s2, s10
	or	s2, s2, s11
	lbu	s8, 52(a1)
	lbu	s9, 53(a1)
	lbu	s10, 54(a1)
	lbu	s3, 55(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s3, s3, s8
	or	s3, s3, s9
	or	s3, s3, s10
	lbu	s8, 48(a1)
	lbu	s9, 49(a1)
	lbu	s10, 50(a1)
	lbu	s11, 51(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s3, s3, s8
	or	s3, s3, s9
	or	s3, s3, s10
	or	s3, s3, s11
	lbu	s8, 60(a1)
	lbu	s9, 61(a1)
	lbu	s10, 62(a1)
	lbu	s4, 63(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s4, s4, s8
	or	s4, s4, s9
	or	s4, s4, s10
	lbu	s8, 56(a1)
	lbu	s9, 57(a1)
	lbu	s10, 58(a1)
	lbu	s11, 59(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s4, s4, s8
	or	s4, s4, s9
	or	s4, s4, s10
	or	s4, s4, s11
	sd	s5, 0(sp)
	sd	a5, 8(sp)
	sd	a6, 16(sp)
	sd	a7, 24(sp)
	sd	s1, 32(sp)
	sd	s2, 40(sp)
	sd	s3, 48(sp)
	sd	s4, 56(sp)
	lbu	s8, 68(a1)
	lbu	s9, 69(a1)
	lbu	s10, 70(a1)
	lbu	s5, 71(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s5, s5, s8
	or	s5, s5, s9
	or	s5, s5, s10
	lbu	s8, 64(a1)
	lbu	s9, 65(a1)
	lbu	s10, 66(a1)
	lbu	s11, 67(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s5, s5, s8
	or	s5, s5, s9
	or	s5, s5, s10
	or	s5, s5, s11
	lbu	s8, 76(a1)
	lbu	s9, 77(a1)
	lbu	s10, 78(a1)
	lbu	a5, 79(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	a5, a5, s8
	or	a5, a5, s9
	or	a5, a5, s10
	lbu	s8, 72(a1)
	lbu	s9, 73(a1)
	lbu	s10, 74(a1)
	lbu	s11, 75(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	a5, a5, s8
	or	a5, a5, s9
	or	a5, a5, s10
	or	a5, a5, s11
	lbu	s8, 84(a1)
	lbu	s9, 85(a1)
	lbu	s10, 86(a1)
	lbu	a6, 87(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	a6, a6, s8
	or	a6, a6, s9
	or	a6, a6, s10
	lbu	s8, 80(a1)
	lbu	s9, 81(a1)
	lbu	s10, 82(a1)
	lbu	s11, 83(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	a6, a6, s8
	or	a6, a6, s9
	or	a6, a6, s10
	or	a6, a6, s11
	lbu	s8, 92(a1)
	lbu	s9, 93(a1)
	lbu	s10, 94(a1)
	lbu	a7, 95(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	a7, a7, s8
	or	a7, a7, s9
	or	a7, a7, s10
	lbu	s8, 88(a1)
	lbu	s9, 89(a1)
	lbu	s10, 90(a1)
	lbu	s11, 91(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	a7, a7, s8
	or	a7, a7, s9
	or	a7, a7, s10
	or	a7, a7, s11
	lbu	s8, 100(a1)
	lbu	s9, 101(a1)
	lbu	s10, 102(a1)
	lbu	s1, 103(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s1, s1, s8
	or	s1, s1, s9
	or	s1, s1, s10
	lbu	s8, 96(a1)
	lbu	s9, 97(a1)
	lbu	s10, 98(a1)
	lbu	s11, 99(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s1, s1, s8
	or	s1, s1, s9
	or	s1, s1, s10
	or	s1, s1, s11
	lbu	s8, 108(a1)
	lbu	s9, 109(a1)
	lbu	s10, 110(a1)
	lbu	s2, 111(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s2, s2, s8
	or	s2, s2, s9
	or	s2, s2, s10
	lbu	s8, 104(a1)
	lbu	s9, 105(a1)
	lbu	s10, 106(a1)
	lbu	s11, 107(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s2, s2, s8
	or	s2, s2, s9
	or	s2, s2, s10
	or	s2, s2, s11
	lbu	s8, 116(a1)
	lbu	s9, 117(a1)
	lbu	s10, 118(a1)
	lbu	s3, 119(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s3, s3, s8
	or	s3, s3, s9
	or	s3, s3, s10
	lbu	s8, 112(a1)
	lbu	s9, 113(a1)
	lbu	s10, 114(a1)
	lbu	s11, 115(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s3, s3, s8
	or	s3, s3, s9
	or	s3, s3, s10
	or	s3, s3, s11
	lbu	s8, 124(a1)
	lbu	s9, 125(a1)
	lbu	s10, 126(a1)
	lbu	s4, 127(a1)
	slli	s8, s8, 24
	slli	s9, s9, 16
	slli	s10, s10, 8
	or	s4, s4, s8
	or	s4, s4, s9
	or	s4, s4, s10
	lbu	s8, 120(a1)
	lbu	s9, 121(a1)
	lbu	s10, 122(a1)
	lbu	s11, 123(a1)
	slli	s8, s8, 56
	slli	s9, s9, 48
	slli	s10, s10, 40
	slli	s11, s11, 32
	or	s4, s4, s8
	or	s4, s4, s9
	or	s4, s4, s10
	or	s4, s4, s11
	sd	s5, 64(sp)
	sd	a5, 72(sp)
	sd	a6, 80(sp)
	sd	a7, 88(sp)
	sd	s1, 96(sp)
	sd	s2, 104(sp)
	sd	s3, 112(sp)
	sd	s4, 120(sp)
#else
	ld	s5, 0(a1)
	# rev8 s5, s5
	.word	0x6b8ada93
	ld	a5, 8(a1)
	# rev8 a5, a5
	.word	0x6b87d793
	ld	a6, 16(a1)
	# rev8 a6, a6
	.word	0x6b885813
	ld	a7, 24(a1)
	# rev8 a7, a7
	.word	0x6b88d893
	ld	s1, 32(a1)
	# rev8 s1, s1
	.word	0x6b84d493
	ld	s2, 40(a1)
	# rev8 s2, s2
	.word	0x6b895913
	ld	s3, 48(a1)
	# rev8 s3, s3
	.word	0x6b89d993
	ld	s4, 56(a1)
	# rev8 s4, s4
	.word	0x6b8a5a13
	sd	s5, 0(sp)
	sd	a5, 8(sp)
	sd	a6, 16(sp)
	sd	a7, 24(sp)
	sd	s1, 32(sp)
	sd	s2, 40(sp)
	sd	s3, 48(sp)
	sd	s4, 56(sp)
	ld	s5, 64(a1)
	# rev8 s5, s5
	.word	0x6b8ada93
	ld	a5, 72(a1)
	# rev8 a5, a5
	.word	0x6b87d793
	ld	a6, 80(a1)
	# rev8 a6, a6
	.word	0x6b885813
	ld	a7, 88(a1)
	# rev8 a7, a7
	.word	0x6b88d893
	ld	s1, 96(a1)
	# rev8 s1, s1
	.word	0x6b84d493
	ld	s2, 104(a1)
	# rev8 s2, s2
	.word	0x6b895913
	ld	s3, 112(a1)
	# rev8 s3, s3
	.word	0x6b89d993
	ld	s4, 120(a1)
	# rev8 s4, s4
	.word	0x6b8a5a13
	sd	s5, 64(sp)
	sd	a5, 72(sp)
	sd	a6, 80(sp)
	sd	a7, 88(sp)
	sd	s1, 96(sp)
	sd	s2, 104(sp)
	sd	s3, 112(sp)
	sd	s4, 120(sp)
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) || defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
L_SHA512_transform_riscv_len_inner:
	# Reload W[0], W[14], W[15] for message schedule
	ld	a5, 0(sp)
	ld	s1, 112(sp)
	ld	s2, 120(sp)
	addi	a2, a2, -1
	ld	s10, 0(t0)
	ld	s11, 8(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t5, 14
	.word	0x60ef5a93
	# rori s6, t5, 18
	.word	0x612f5b13
	# rori s8, t5, 41
	.word	0x629f5c13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t1, 28
	.word	0x61c35a93
	# rori s6, t1, 34
	.word	0x62235b13
	# rori s9, t1, 39
	.word	0x62735c93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t1, t2
	xor	s7, t6, a3
	xor	s6, t2, t3
	and	s7, s7, t5
	and	s6, s6, s5
	xor	s7, s7, a3
	xor	s6, s6, t2
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	a4, a4, s5
	add	s6, s9, s6
	add	t4, t4, a4
	add	a4, a4, s6
#else
	slli	s6, t5, 50
	srli	s5, t5, 14
	slli	s7, t5, 46
	or	s5, s5, s6
	srli	s6, t5, 18
	xor	s5, s5, s7
	slli	s7, t5, 23
	xor	s5, s5, s6
	srli	s8, t5, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t1, 36
	srli	s5, t1, 28
	slli	s7, t1, 30
	or	s5, s5, s6
	srli	s6, t1, 34
	xor	s5, s5, s7
	slli	s7, t1, 25
	xor	s5, s5, s6
	srli	s9, t1, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t1, t2
	xor	s7, t6, a3
	xor	s6, t2, t3
	and	s7, s7, t5
	and	s6, s6, s5
	xor	s7, s7, a3
	xor	s6, s6, t2
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	a4, a4, s5
	add	s6, s9, s6
	add	t4, t4, a4
	add	a4, a4, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	a6, 8(sp)
	ld	a7, 72(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a6, 1
	.word	0x60185a93
	# rori s6, a6, 8
	.word	0x60885b13
	srli	s8, a6, 7
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, s1, 19
	.word	0x6134da93
	# rori s6, s1, 61
	.word	0x63d4db13
	srli	s9, s1, 6
	xor	s9, s9, s5
	xor	s9, s9, s6
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
#else
	slli	s6, a6, 63
	srli	s7, a6, 1
	slli	s5, a6, 56
	or	s7, s7, s6
	srli	s6, a6, 8
	xor	s7, s7, s5
	srli	s8, a6, 7
	xor	s7, s7, s6
	xor	s8, s8, s7
	slli	s6, s1, 45
	srli	s7, s1, 19
	slli	s5, s1, 3
	or	s7, s7, s6
	srli	s6, s1, 61
	xor	s7, s7, s5
	srli	s9, s1, 6
	xor	s7, s7, s6
	xor	s9, s9, s7
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t4, 14
	.word	0x60eeda93
	# rori s6, t4, 18
	.word	0x612edb13
	# rori s8, t4, 41
	.word	0x629edc13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, a4, 28
	.word	0x61c75a93
	# rori s6, a4, 34
	.word	0x62275b13
	# rori s9, a4, 39
	.word	0x62775c93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, a4, t1
	xor	s7, t5, t6
	xor	s6, t1, t2
	and	s7, s7, t4
	and	s6, s6, s5
	xor	s7, s7, t6
	xor	s6, s6, t1
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	a3, a3, s5
	add	s6, s9, s6
	add	t3, t3, a3
	add	a3, a3, s6
#else
	slli	s6, t4, 50
	srli	s5, t4, 14
	slli	s7, t4, 46
	or	s5, s5, s6
	srli	s6, t4, 18
	xor	s5, s5, s7
	slli	s7, t4, 23
	xor	s5, s5, s6
	srli	s8, t4, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, a4, 36
	srli	s5, a4, 28
	slli	s7, a4, 30
	or	s5, s5, s6
	srli	s6, a4, 34
	xor	s5, s5, s7
	slli	s7, a4, 25
	xor	s5, s5, s6
	srli	s9, a4, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, a4, t1
	xor	s7, t5, t6
	xor	s6, t1, t2
	and	s7, s7, t4
	and	s6, s6, s5
	xor	s7, s7, t6
	xor	s6, s6, t1
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	a3, a3, s5
	add	s6, s9, s6
	add	t3, t3, a3
	add	a3, a3, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s1, a5
	ld	a5, 16(sp)
	ld	a7, 80(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a5, 1
	.word	0x6017da93
	# rori s6, a5, 8
	.word	0x6087db13
	srli	s8, a5, 7
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, s2, 19
	.word	0x61395a93
	# rori s6, s2, 61
	.word	0x63d95b13
	srli	s9, s2, 6
	xor	s9, s9, s5
	xor	s9, s9, s6
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
#else
	slli	s6, a5, 63
	srli	s7, a5, 1
	slli	s5, a5, 56
	or	s7, s7, s6
	srli	s6, a5, 8
	xor	s7, s7, s5
	srli	s8, a5, 7
	xor	s7, s7, s6
	xor	s8, s8, s7
	slli	s6, s2, 45
	srli	s7, s2, 19
	slli	s5, s2, 3
	or	s7, s7, s6
	srli	s6, s2, 61
	xor	s7, s7, s5
	srli	s9, s2, 6
	xor	s7, s7, s6
	xor	s9, s9, s7
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	sd	s1, 0(sp)
	mv	s2, a6
	sd	a6, 8(sp)
	ld	s10, 16(t0)
	ld	s11, 24(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t3, 14
	.word	0x60ee5a93
	# rori s6, t3, 18
	.word	0x612e5b13
	# rori s8, t3, 41
	.word	0x629e5c13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, a3, 28
	.word	0x61c6da93
	# rori s6, a3, 34
	.word	0x6226db13
	# rori s9, a3, 39
	.word	0x6276dc93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, a3, a4
	xor	s7, t4, t5
	xor	s6, a4, t1
	and	s7, s7, t3
	and	s6, s6, s5
	xor	s7, s7, t5
	xor	s6, s6, a4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t6, t6, s5
	add	s6, s9, s6
	add	t2, t2, t6
	add	t6, t6, s6
#else
	slli	s6, t3, 50
	srli	s5, t3, 14
	slli	s7, t3, 46
	or	s5, s5, s6
	srli	s6, t3, 18
	xor	s5, s5, s7
	slli	s7, t3, 23
	xor	s5, s5, s6
	srli	s8, t3, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, a3, 36
	srli	s5, a3, 28
	slli	s7, a3, 30
	or	s5, s5, s6
	srli	s6, a3, 34
	xor	s5, s5, s7
	slli	s7, a3, 25
	xor	s5, s5, s6
	srli	s9, a3, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, a3, a4
	xor	s7, t4, t5
	xor	s6, a4, t1
	and	s7, s7, t3
	and	s6, s6, s5
	xor	s7, s7, t5
	xor	s6, s6, a4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t6, t6, s5
	add	s6, s9, s6
	add	t2, t2, t6
	add	t6, t6, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	a6, 24(sp)
	ld	a7, 88(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a6, 1
	.word	0x60185a93
	# rori s6, a6, 8
	.word	0x60885b13
	srli	s8, a6, 7
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, s1, 19
	.word	0x6134da93
	# rori s6, s1, 61
	.word	0x63d4db13
	srli	s9, s1, 6
	xor	s9, s9, s5
	xor	s9, s9, s6
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
#else
	slli	s6, a6, 63
	srli	s7, a6, 1
	slli	s5, a6, 56
	or	s7, s7, s6
	srli	s6, a6, 8
	xor	s7, s7, s5
	srli	s8, a6, 7
	xor	s7, s7, s6
	xor	s8, s8, s7
	slli	s6, s1, 45
	srli	s7, s1, 19
	slli	s5, s1, 3
	or	s7, s7, s6
	srli	s6, s1, 61
	xor	s7, s7, s5
	srli	s9, s1, 6
	xor	s7, s7, s6
	xor	s9, s9, s7
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t2, 14
	.word	0x60e3da93
	# rori s6, t2, 18
	.word	0x6123db13
	# rori s8, t2, 41
	.word	0x6293dc13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t6, 28
	.word	0x61cfda93
	# rori s6, t6, 34
	.word	0x622fdb13
	# rori s9, t6, 39
	.word	0x627fdc93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t6, a3
	xor	s7, t3, t4
	xor	s6, a3, a4
	and	s7, s7, t2
	and	s6, s6, s5
	xor	s7, s7, t4
	xor	s6, s6, a3
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	t5, t5, s5
	add	s6, s9, s6
	add	t1, t1, t5
	add	t5, t5, s6
#else
	slli	s6, t2, 50
	srli	s5, t2, 14
	slli	s7, t2, 46
	or	s5, s5, s6
	srli	s6, t2, 18
	xor	s5, s5, s7
	slli	s7, t2, 23
	xor	s5, s5, s6
	srli	s8, t2, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t6, 36
	srli	s5, t6, 28
	slli	s7, t6, 30
	or	s5, s5, s6
	srli	s6, t6, 34
	xor	s5, s5, s7
	slli	s7, t6, 25
	xor	s5, s5, s6
	srli	s9, t6, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t6, a3
	xor	s7, t3, t4
	xor	s6, a3, a4
	and	s7, s7, t2
	and	s6, s6, s5
	xor	s7, s7, t4
	xor	s6, s6, a3
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	t5, t5, s5
	add	s6, s9, s6
	add	t1, t1, t5
	add	t5, t5, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s1, a5
	ld	a5, 32(sp)
	ld	a7, 96(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a5, 1
	.word	0x6017da93
	# rori s6, a5, 8
	.word	0x6087db13
	srli	s8, a5, 7
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, s2, 19
	.word	0x61395a93
	# rori s6, s2, 61
	.word	0x63d95b13
	srli	s9, s2, 6
	xor	s9, s9, s5
	xor	s9, s9, s6
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
#else
	slli	s6, a5, 63
	srli	s7, a5, 1
	slli	s5, a5, 56
	or	s7, s7, s6
	srli	s6, a5, 8
	xor	s7, s7, s5
	srli	s8, a5, 7
	xor	s7, s7, s6
	xor	s8, s8, s7
	slli	s6, s2, 45
	srli	s7, s2, 19
	slli	s5, s2, 3
	or	s7, s7, s6
	srli	s6, s2, 61
	xor	s7, s7, s5
	srli	s9, s2, 6
	xor	s7, s7, s6
	xor	s9, s9, s7
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	sd	s1, 16(sp)
	mv	s2, a6
	sd	a6, 24(sp)
	ld	s10, 32(t0)
	ld	s11, 40(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t1, 14
	.word	0x60e35a93
	# rori s6, t1, 18
	.word	0x61235b13
	# rori s8, t1, 41
	.word	0x62935c13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t5, 28
	.word	0x61cf5a93
	# rori s6, t5, 34
	.word	0x622f5b13
	# rori s9, t5, 39
	.word	0x627f5c93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t5, t6
	xor	s7, t2, t3
	xor	s6, t6, a3
	and	s7, s7, t1
	and	s6, s6, s5
	xor	s7, s7, t3
	xor	s6, s6, t6
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t4, t4, s5
	add	s6, s9, s6
	add	a4, a4, t4
	add	t4, t4, s6
#else
	slli	s6, t1, 50
	srli	s5, t1, 14
	slli	s7, t1, 46
	or	s5, s5, s6
	srli	s6, t1, 18
	xor	s5, s5, s7
	slli	s7, t1, 23
	xor	s5, s5, s6
	srli	s8, t1, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t5, 36
	srli	s5, t5, 28
	slli	s7, t5, 30
	or	s5, s5, s6
	srli	s6, t5, 34
	xor	s5, s5, s7
	slli	s7, t5, 25
	xor	s5, s5, s6
	srli	s9, t5, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t5, t6
	xor	s7, t2, t3
	xor	s6, t6, a3
	and	s7, s7, t1
	and	s6, s6, s5
	xor	s7, s7, t3
	xor	s6, s6, t6
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t4, t4, s5
	add	s6, s9, s6
	add	a4, a4, t4
	add	t4, t4, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	a6, 40(sp)
	ld	a7, 104(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a6, 1
	.word	0x60185a93
	# rori s6, a6, 8
	.word	0x60885b13
	srli	s8, a6, 7
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, s1, 19
	.word	0x6134da93
	# rori s6, s1, 61
	.word	0x63d4db13
	srli	s9, s1, 6
	xor	s9, s9, s5
	xor	s9, s9, s6
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
#else
	slli	s6, a6, 63
	srli	s7, a6, 1
	slli	s5, a6, 56
	or	s7, s7, s6
	srli	s6, a6, 8
	xor	s7, s7, s5
	srli	s8, a6, 7
	xor	s7, s7, s6
	xor	s8, s8, s7
	slli	s6, s1, 45
	srli	s7, s1, 19
	slli	s5, s1, 3
	or	s7, s7, s6
	srli	s6, s1, 61
	xor	s7, s7, s5
	srli	s9, s1, 6
	xor	s7, s7, s6
	xor	s9, s9, s7
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a4, 14
	.word	0x60e75a93
	# rori s6, a4, 18
	.word	0x61275b13
	# rori s8, a4, 41
	.word	0x62975c13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t4, 28
	.word	0x61ceda93
	# rori s6, t4, 34
	.word	0x622edb13
	# rori s9, t4, 39
	.word	0x627edc93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t4, t5
	xor	s7, t1, t2
	xor	s6, t5, t6
	and	s7, s7, a4
	and	s6, s6, s5
	xor	s7, s7, t2
	xor	s6, s6, t5
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	t3, t3, s5
	add	s6, s9, s6
	add	a3, a3, t3
	add	t3, t3, s6
#else
	slli	s6, a4, 50
	srli	s5, a4, 14
	slli	s7, a4, 46
	or	s5, s5, s6
	srli	s6, a4, 18
	xor	s5, s5, s7
	slli	s7, a4, 23
	xor	s5, s5, s6
	srli	s8, a4, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t4, 36
	srli	s5, t4, 28
	slli	s7, t4, 30
	or	s5, s5, s6
	srli	s6, t4, 34
	xor	s5, s5, s7
	slli	s7, t4, 25
	xor	s5, s5, s6
	srli	s9, t4, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t4, t5
	xor	s7, t1, t2
	xor	s6, t5, t6
	and	s7, s7, a4
	and	s6, s6, s5
	xor	s7, s7, t2
	xor	s6, s6, t5
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	t3, t3, s5
	add	s6, s9, s6
	add	a3, a3, t3
	add	t3, t3, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s1, a5
	ld	a5, 48(sp)
	ld	a7, 112(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a5, 1
	.word	0x6017da93
	# rori s6, a5, 8
	.word	0x6087db13
	srli	s8, a5, 7
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, s2, 19
	.word	0x61395a93
	# rori s6, s2, 61
	.word	0x63d95b13
	srli	s9, s2, 6
	xor	s9, s9, s5
	xor	s9, s9, s6
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
#else
	slli	s6, a5, 63
	srli	s7, a5, 1
	slli	s5, a5, 56
	or	s7, s7, s6
	srli	s6, a5, 8
	xor	s7, s7, s5
	srli	s8, a5, 7
	xor	s7, s7, s6
	xor	s8, s8, s7
	slli	s6, s2, 45
	srli	s7, s2, 19
	slli	s5, s2, 3
	or	s7, s7, s6
	srli	s6, s2, 61
	xor	s7, s7, s5
	srli	s9, s2, 6
	xor	s7, s7, s6
	xor	s9, s9, s7
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	sd	s1, 32(sp)
	mv	s2, a6
	sd	a6, 40(sp)
	ld	s10, 48(t0)
	ld	s11, 56(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a3, 14
	.word	0x60e6da93
	# rori s6, a3, 18
	.word	0x6126db13
	# rori s8, a3, 41
	.word	0x6296dc13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t3, 28
	.word	0x61ce5a93
	# rori s6, t3, 34
	.word	0x622e5b13
	# rori s9, t3, 39
	.word	0x627e5c93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t3, t4
	xor	s7, a4, t1
	xor	s6, t4, t5
	and	s7, s7, a3
	and	s6, s6, s5
	xor	s7, s7, t1
	xor	s6, s6, t4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t2, t2, s5
	add	s6, s9, s6
	add	t6, t6, t2
	add	t2, t2, s6
#else
	slli	s6, a3, 50
	srli	s5, a3, 14
	slli	s7, a3, 46
	or	s5, s5, s6
	srli	s6, a3, 18
	xor	s5, s5, s7
	slli	s7, a3, 23
	xor	s5, s5, s6
	srli	s8, a3, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t3, 36
	srli	s5, t3, 28
	slli	s7, t3, 30
	or	s5, s5, s6
	srli	s6, t3, 34
	xor	s5, s5, s7
	slli	s7, t3, 25
	xor	s5, s5, s6
	srli	s9, t3, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t3, t4
	xor	s7, a4, t1
	xor	s6, t4, t5
	and	s7, s7, a3
	and	s6, s6, s5
	xor	s7, s7, t1
	xor	s6, s6, t4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t2, t2, s5
	add	s6, s9, s6
	add	t6, t6, t2
	add	t2, t2, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	a6, 56(sp)
	ld	a7, 120(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a6, 1
	.word	0x60185a93
	# rori s6, a6, 8
	.word	0x60885b13
	srli	s8, a6, 7
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, s1, 19
	.word	0x6134da93
	# rori s6, s1, 61
	.word	0x63d4db13
	srli	s9, s1, 6
	xor	s9, s9, s5
	xor	s9, s9, s6
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
#else
	slli	s6, a6, 63
	srli	s7, a6, 1
	slli	s5, a6, 56
	or	s7, s7, s6
	srli	s6, a6, 8
	xor	s7, s7, s5
	srli	s8, a6, 7
	xor	s7, s7, s6
	xor	s8, s8, s7
	slli	s6, s1, 45
	srli	s7, s1, 19
	slli	s5, s1, 3
	or	s7, s7, s6
	srli	s6, s1, 61
	xor	s7, s7, s5
	srli	s9, s1, 6
	xor	s7, s7, s6
	xor	s9, s9, s7
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t6, 14
	.word	0x60efda93
	# rori s6, t6, 18
	.word	0x612fdb13
	# rori s8, t6, 41
	.word	0x629fdc13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t2, 28
	.word	0x61c3da93
	# rori s6, t2, 34
	.word	0x6223db13
	# rori s9, t2, 39
	.word	0x6273dc93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t2, t3
	xor	s7, a3, a4
	xor	s6, t3, t4
	and	s7, s7, t6
	and	s6, s6, s5
	xor	s7, s7, a4
	xor	s6, s6, t3
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	t1, t1, s5
	add	s6, s9, s6
	add	t5, t5, t1
	add	t1, t1, s6
#else
	slli	s6, t6, 50
	srli	s5, t6, 14
	slli	s7, t6, 46
	or	s5, s5, s6
	srli	s6, t6, 18
	xor	s5, s5, s7
	slli	s7, t6, 23
	xor	s5, s5, s6
	srli	s8, t6, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t2, 36
	srli	s5, t2, 28
	slli	s7, t2, 30
	or	s5, s5, s6
	srli	s6, t2, 34
	xor	s5, s5, s7
	slli	s7, t2, 25
	xor	s5, s5, s6
	srli	s9, t2, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t2, t3
	xor	s7, a3, a4
	xor	s6, t3, t4
	and	s7, s7, t6
	and	s6, s6, s5
	xor	s7, s7, a4
	xor	s6, s6, t3
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	t1, t1, s5
	add	s6, s9, s6
	add	t5, t5, t1
	add	t1, t1, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s1, a5
	ld	a5, 64(sp)
	ld	a7, 0(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a5, 1
	.word	0x6017da93
	# rori s6, a5, 8
	.word	0x6087db13
	srli	s8, a5, 7
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, s2, 19
	.word	0x61395a93
	# rori s6, s2, 61
	.word	0x63d95b13
	srli	s9, s2, 6
	xor	s9, s9, s5
	xor	s9, s9, s6
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
#else
	slli	s6, a5, 63
	srli	s7, a5, 1
	slli	s5, a5, 56
	or	s7, s7, s6
	srli	s6, a5, 8
	xor	s7, s7, s5
	srli	s8, a5, 7
	xor	s7, s7, s6
	xor	s8, s8, s7
	slli	s6, s2, 45
	srli	s7, s2, 19
	slli	s5, s2, 3
	or	s7, s7, s6
	srli	s6, s2, 61
	xor	s7, s7, s5
	srli	s9, s2, 6
	xor	s7, s7, s6
	xor	s9, s9, s7
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	sd	s1, 48(sp)
	mv	s2, a6
	sd	a6, 56(sp)
	ld	s10, 64(t0)
	ld	s11, 72(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t5, 14
	.word	0x60ef5a93
	# rori s6, t5, 18
	.word	0x612f5b13
	# rori s8, t5, 41
	.word	0x629f5c13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t1, 28
	.word	0x61c35a93
	# rori s6, t1, 34
	.word	0x62235b13
	# rori s9, t1, 39
	.word	0x62735c93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t1, t2
	xor	s7, t6, a3
	xor	s6, t2, t3
	and	s7, s7, t5
	and	s6, s6, s5
	xor	s7, s7, a3
	xor	s6, s6, t2
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	a4, a4, s5
	add	s6, s9, s6
	add	t4, t4, a4
	add	a4, a4, s6
#else
	slli	s6, t5, 50
	srli	s5, t5, 14
	slli	s7, t5, 46
	or	s5, s5, s6
	srli	s6, t5, 18
	xor	s5, s5, s7
	slli	s7, t5, 23
	xor	s5, s5, s6
	srli	s8, t5, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t1, 36
	srli	s5, t1, 28
	slli	s7, t1, 30
	or	s5, s5, s6
	srli	s6, t1, 34
	xor	s5, s5, s7
	slli	s7, t1, 25
	xor	s5, s5, s6
	srli	s9, t1, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t1, t2
	xor	s7, t6, a3
	xor	s6, t2, t3
	and	s7, s7, t5
	and	s6, s6, s5
	xor	s7, s7, a3
	xor	s6, s6, t2
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	a4, a4, s5
	add	s6, s9, s6
	add	t4, t4, a4
	add	a4, a4, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	a6, 72(sp)
	ld	a7, 8(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a6, 1
	.word	0x60185a93
	# rori s6, a6, 8
	.word	0x60885b13
	srli	s8, a6, 7
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, s1, 19
	.word	0x6134da93
	# rori s6, s1, 61
	.word	0x63d4db13
	srli	s9, s1, 6
	xor	s9, s9, s5
	xor	s9, s9, s6
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
#else
	slli	s6, a6, 63
	srli	s7, a6, 1
	slli	s5, a6, 56
	or	s7, s7, s6
	srli	s6, a6, 8
	xor	s7, s7, s5
	srli	s8, a6, 7
	xor	s7, s7, s6
	xor	s8, s8, s7
	slli	s6, s1, 45
	srli	s7, s1, 19
	slli	s5, s1, 3
	or	s7, s7, s6
	srli	s6, s1, 61
	xor	s7, s7, s5
	srli	s9, s1, 6
	xor	s7, s7, s6
	xor	s9, s9, s7
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t4, 14
	.word	0x60eeda93
	# rori s6, t4, 18
	.word	0x612edb13
	# rori s8, t4, 41
	.word	0x629edc13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, a4, 28
	.word	0x61c75a93
	# rori s6, a4, 34
	.word	0x62275b13
	# rori s9, a4, 39
	.word	0x62775c93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, a4, t1
	xor	s7, t5, t6
	xor	s6, t1, t2
	and	s7, s7, t4
	and	s6, s6, s5
	xor	s7, s7, t6
	xor	s6, s6, t1
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	a3, a3, s5
	add	s6, s9, s6
	add	t3, t3, a3
	add	a3, a3, s6
#else
	slli	s6, t4, 50
	srli	s5, t4, 14
	slli	s7, t4, 46
	or	s5, s5, s6
	srli	s6, t4, 18
	xor	s5, s5, s7
	slli	s7, t4, 23
	xor	s5, s5, s6
	srli	s8, t4, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, a4, 36
	srli	s5, a4, 28
	slli	s7, a4, 30
	or	s5, s5, s6
	srli	s6, a4, 34
	xor	s5, s5, s7
	slli	s7, a4, 25
	xor	s5, s5, s6
	srli	s9, a4, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, a4, t1
	xor	s7, t5, t6
	xor	s6, t1, t2
	and	s7, s7, t4
	and	s6, s6, s5
	xor	s7, s7, t6
	xor	s6, s6, t1
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	a3, a3, s5
	add	s6, s9, s6
	add	t3, t3, a3
	add	a3, a3, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s1, a5
	ld	a5, 80(sp)
	ld	a7, 16(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a5, 1
	.word	0x6017da93
	# rori s6, a5, 8
	.word	0x6087db13
	srli	s8, a5, 7
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, s2, 19
	.word	0x61395a93
	# rori s6, s2, 61
	.word	0x63d95b13
	srli	s9, s2, 6
	xor	s9, s9, s5
	xor	s9, s9, s6
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
#else
	slli	s6, a5, 63
	srli	s7, a5, 1
	slli	s5, a5, 56
	or	s7, s7, s6
	srli	s6, a5, 8
	xor	s7, s7, s5
	srli	s8, a5, 7
	xor	s7, s7, s6
	xor	s8, s8, s7
	slli	s6, s2, 45
	srli	s7, s2, 19
	slli	s5, s2, 3
	or	s7, s7, s6
	srli	s6, s2, 61
	xor	s7, s7, s5
	srli	s9, s2, 6
	xor	s7, s7, s6
	xor	s9, s9, s7
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	sd	s1, 64(sp)
	mv	s2, a6
	sd	a6, 72(sp)
	ld	s10, 80(t0)
	ld	s11, 88(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t3, 14
	.word	0x60ee5a93
	# rori s6, t3, 18
	.word	0x612e5b13
	# rori s8, t3, 41
	.word	0x629e5c13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, a3, 28
	.word	0x61c6da93
	# rori s6, a3, 34
	.word	0x6226db13
	# rori s9, a3, 39
	.word	0x6276dc93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, a3, a4
	xor	s7, t4, t5
	xor	s6, a4, t1
	and	s7, s7, t3
	and	s6, s6, s5
	xor	s7, s7, t5
	xor	s6, s6, a4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t6, t6, s5
	add	s6, s9, s6
	add	t2, t2, t6
	add	t6, t6, s6
#else
	slli	s6, t3, 50
	srli	s5, t3, 14
	slli	s7, t3, 46
	or	s5, s5, s6
	srli	s6, t3, 18
	xor	s5, s5, s7
	slli	s7, t3, 23
	xor	s5, s5, s6
	srli	s8, t3, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, a3, 36
	srli	s5, a3, 28
	slli	s7, a3, 30
	or	s5, s5, s6
	srli	s6, a3, 34
	xor	s5, s5, s7
	slli	s7, a3, 25
	xor	s5, s5, s6
	srli	s9, a3, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, a3, a4
	xor	s7, t4, t5
	xor	s6, a4, t1
	and	s7, s7, t3
	and	s6, s6, s5
	xor	s7, s7, t5
	xor	s6, s6, a4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t6, t6, s5
	add	s6, s9, s6
	add	t2, t2, t6
	add	t6, t6, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	a6, 88(sp)
	ld	a7, 24(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a6, 1
	.word	0x60185a93
	# rori s6, a6, 8
	.word	0x60885b13
	srli	s8, a6, 7
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, s1, 19
	.word	0x6134da93
	# rori s6, s1, 61
	.word	0x63d4db13
	srli	s9, s1, 6
	xor	s9, s9, s5
	xor	s9, s9, s6
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
#else
	slli	s6, a6, 63
	srli	s7, a6, 1
	slli	s5, a6, 56
	or	s7, s7, s6
	srli	s6, a6, 8
	xor	s7, s7, s5
	srli	s8, a6, 7
	xor	s7, s7, s6
	xor	s8, s8, s7
	slli	s6, s1, 45
	srli	s7, s1, 19
	slli	s5, s1, 3
	or	s7, s7, s6
	srli	s6, s1, 61
	xor	s7, s7, s5
	srli	s9, s1, 6
	xor	s7, s7, s6
	xor	s9, s9, s7
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t2, 14
	.word	0x60e3da93
	# rori s6, t2, 18
	.word	0x6123db13
	# rori s8, t2, 41
	.word	0x6293dc13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t6, 28
	.word	0x61cfda93
	# rori s6, t6, 34
	.word	0x622fdb13
	# rori s9, t6, 39
	.word	0x627fdc93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t6, a3
	xor	s7, t3, t4
	xor	s6, a3, a4
	and	s7, s7, t2
	and	s6, s6, s5
	xor	s7, s7, t4
	xor	s6, s6, a3
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	t5, t5, s5
	add	s6, s9, s6
	add	t1, t1, t5
	add	t5, t5, s6
#else
	slli	s6, t2, 50
	srli	s5, t2, 14
	slli	s7, t2, 46
	or	s5, s5, s6
	srli	s6, t2, 18
	xor	s5, s5, s7
	slli	s7, t2, 23
	xor	s5, s5, s6
	srli	s8, t2, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t6, 36
	srli	s5, t6, 28
	slli	s7, t6, 30
	or	s5, s5, s6
	srli	s6, t6, 34
	xor	s5, s5, s7
	slli	s7, t6, 25
	xor	s5, s5, s6
	srli	s9, t6, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t6, a3
	xor	s7, t3, t4
	xor	s6, a3, a4
	and	s7, s7, t2
	and	s6, s6, s5
	xor	s7, s7, t4
	xor	s6, s6, a3
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	t5, t5, s5
	add	s6, s9, s6
	add	t1, t1, t5
	add	t5, t5, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s1, a5
	ld	a5, 96(sp)
	ld	a7, 32(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a5, 1
	.word	0x6017da93
	# rori s6, a5, 8
	.word	0x6087db13
	srli	s8, a5, 7
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, s2, 19
	.word	0x61395a93
	# rori s6, s2, 61
	.word	0x63d95b13
	srli	s9, s2, 6
	xor	s9, s9, s5
	xor	s9, s9, s6
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
#else
	slli	s6, a5, 63
	srli	s7, a5, 1
	slli	s5, a5, 56
	or	s7, s7, s6
	srli	s6, a5, 8
	xor	s7, s7, s5
	srli	s8, a5, 7
	xor	s7, s7, s6
	xor	s8, s8, s7
	slli	s6, s2, 45
	srli	s7, s2, 19
	slli	s5, s2, 3
	or	s7, s7, s6
	srli	s6, s2, 61
	xor	s7, s7, s5
	srli	s9, s2, 6
	xor	s7, s7, s6
	xor	s9, s9, s7
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	sd	s1, 80(sp)
	mv	s2, a6
	sd	a6, 88(sp)
	ld	s10, 96(t0)
	ld	s11, 104(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t1, 14
	.word	0x60e35a93
	# rori s6, t1, 18
	.word	0x61235b13
	# rori s8, t1, 41
	.word	0x62935c13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t5, 28
	.word	0x61cf5a93
	# rori s6, t5, 34
	.word	0x622f5b13
	# rori s9, t5, 39
	.word	0x627f5c93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t5, t6
	xor	s7, t2, t3
	xor	s6, t6, a3
	and	s7, s7, t1
	and	s6, s6, s5
	xor	s7, s7, t3
	xor	s6, s6, t6
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t4, t4, s5
	add	s6, s9, s6
	add	a4, a4, t4
	add	t4, t4, s6
#else
	slli	s6, t1, 50
	srli	s5, t1, 14
	slli	s7, t1, 46
	or	s5, s5, s6
	srli	s6, t1, 18
	xor	s5, s5, s7
	slli	s7, t1, 23
	xor	s5, s5, s6
	srli	s8, t1, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t5, 36
	srli	s5, t5, 28
	slli	s7, t5, 30
	or	s5, s5, s6
	srli	s6, t5, 34
	xor	s5, s5, s7
	slli	s7, t5, 25
	xor	s5, s5, s6
	srli	s9, t5, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t5, t6
	xor	s7, t2, t3
	xor	s6, t6, a3
	and	s7, s7, t1
	and	s6, s6, s5
	xor	s7, s7, t3
	xor	s6, s6, t6
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t4, t4, s5
	add	s6, s9, s6
	add	a4, a4, t4
	add	t4, t4, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	a6, 104(sp)
	ld	a7, 40(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a6, 1
	.word	0x60185a93
	# rori s6, a6, 8
	.word	0x60885b13
	srli	s8, a6, 7
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, s1, 19
	.word	0x6134da93
	# rori s6, s1, 61
	.word	0x63d4db13
	srli	s9, s1, 6
	xor	s9, s9, s5
	xor	s9, s9, s6
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
#else
	slli	s6, a6, 63
	srli	s7, a6, 1
	slli	s5, a6, 56
	or	s7, s7, s6
	srli	s6, a6, 8
	xor	s7, s7, s5
	srli	s8, a6, 7
	xor	s7, s7, s6
	xor	s8, s8, s7
	slli	s6, s1, 45
	srli	s7, s1, 19
	slli	s5, s1, 3
	or	s7, s7, s6
	srli	s6, s1, 61
	xor	s7, s7, s5
	srli	s9, s1, 6
	xor	s7, s7, s6
	xor	s9, s9, s7
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a4, 14
	.word	0x60e75a93
	# rori s6, a4, 18
	.word	0x61275b13
	# rori s8, a4, 41
	.word	0x62975c13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t4, 28
	.word	0x61ceda93
	# rori s6, t4, 34
	.word	0x622edb13
	# rori s9, t4, 39
	.word	0x627edc93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t4, t5
	xor	s7, t1, t2
	xor	s6, t5, t6
	and	s7, s7, a4
	and	s6, s6, s5
	xor	s7, s7, t2
	xor	s6, s6, t5
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	t3, t3, s5
	add	s6, s9, s6
	add	a3, a3, t3
	add	t3, t3, s6
#else
	slli	s6, a4, 50
	srli	s5, a4, 14
	slli	s7, a4, 46
	or	s5, s5, s6
	srli	s6, a4, 18
	xor	s5, s5, s7
	slli	s7, a4, 23
	xor	s5, s5, s6
	srli	s8, a4, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t4, 36
	srli	s5, t4, 28
	slli	s7, t4, 30
	or	s5, s5, s6
	srli	s6, t4, 34
	xor	s5, s5, s7
	slli	s7, t4, 25
	xor	s5, s5, s6
	srli	s9, t4, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t4, t5
	xor	s7, t1, t2
	xor	s6, t5, t6
	and	s7, s7, a4
	and	s6, s6, s5
	xor	s7, s7, t2
	xor	s6, s6, t5
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	t3, t3, s5
	add	s6, s9, s6
	add	a3, a3, t3
	add	t3, t3, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s1, a5
	ld	a5, 112(sp)
	ld	a7, 48(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a5, 1
	.word	0x6017da93
	# rori s6, a5, 8
	.word	0x6087db13
	srli	s8, a5, 7
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, s2, 19
	.word	0x61395a93
	# rori s6, s2, 61
	.word	0x63d95b13
	srli	s9, s2, 6
	xor	s9, s9, s5
	xor	s9, s9, s6
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
#else
	slli	s6, a5, 63
	srli	s7, a5, 1
	slli	s5, a5, 56
	or	s7, s7, s6
	srli	s6, a5, 8
	xor	s7, s7, s5
	srli	s8, a5, 7
	xor	s7, s7, s6
	xor	s8, s8, s7
	slli	s6, s2, 45
	srli	s7, s2, 19
	slli	s5, s2, 3
	or	s7, s7, s6
	srli	s6, s2, 61
	xor	s7, s7, s5
	srli	s9, s2, 6
	xor	s7, s7, s6
	xor	s9, s9, s7
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	sd	s1, 96(sp)
	mv	s2, a6
	sd	a6, 104(sp)
	ld	s10, 112(t0)
	ld	s11, 120(t0)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a3, 14
	.word	0x60e6da93
	# rori s6, a3, 18
	.word	0x6126db13
	# rori s8, a3, 41
	.word	0x6296dc13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t3, 28
	.word	0x61ce5a93
	# rori s6, t3, 34
	.word	0x622e5b13
	# rori s9, t3, 39
	.word	0x627e5c93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t3, t4
	xor	s7, a4, t1
	xor	s6, t4, t5
	and	s7, s7, a3
	and	s6, s6, s5
	xor	s7, s7, t1
	xor	s6, s6, t4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t2, t2, s5
	add	s6, s9, s6
	add	t6, t6, t2
	add	t2, t2, s6
#else
	slli	s6, a3, 50
	srli	s5, a3, 14
	slli	s7, a3, 46
	or	s5, s5, s6
	srli	s6, a3, 18
	xor	s5, s5, s7
	slli	s7, a3, 23
	xor	s5, s5, s6
	srli	s8, a3, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t3, 36
	srli	s5, t3, 28
	slli	s7, t3, 30
	or	s5, s5, s6
	srli	s6, t3, 34
	xor	s5, s5, s7
	slli	s7, t3, 25
	xor	s5, s5, s6
	srli	s9, t3, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t3, t4
	xor	s7, a4, t1
	xor	s6, t4, t5
	and	s7, s7, a3
	and	s6, s6, s5
	xor	s7, s7, t1
	xor	s6, s6, t4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t2, t2, s5
	add	s6, s9, s6
	add	t6, t6, t2
	add	t2, t2, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	a6, 120(sp)
	ld	a7, 56(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a6, 1
	.word	0x60185a93
	# rori s6, a6, 8
	.word	0x60885b13
	srli	s8, a6, 7
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, s1, 19
	.word	0x6134da93
	# rori s6, s1, 61
	.word	0x63d4db13
	srli	s9, s1, 6
	xor	s9, s9, s5
	xor	s9, s9, s6
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
#else
	slli	s6, a6, 63
	srli	s7, a6, 1
	slli	s5, a6, 56
	or	s7, s7, s6
	srli	s6, a6, 8
	xor	s7, s7, s5
	srli	s8, a6, 7
	xor	s7, s7, s6
	xor	s8, s8, s7
	slli	s6, s1, 45
	srli	s7, s1, 19
	slli	s5, s1, 3
	or	s7, s7, s6
	srli	s6, s1, 61
	xor	s7, s7, s5
	srli	s9, s1, 6
	xor	s7, s7, s6
	xor	s9, s9, s7
	add	s9, s9, a7
	add	a5, a5, s8
	add	a5, s9, a5
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t6, 14
	.word	0x60efda93
	# rori s6, t6, 18
	.word	0x612fdb13
	# rori s8, t6, 41
	.word	0x629fdc13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t2, 28
	.word	0x61c3da93
	# rori s6, t2, 34
	.word	0x6223db13
	# rori s9, t2, 39
	.word	0x6273dc93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t2, t3
	xor	s7, a3, a4
	xor	s6, t3, t4
	and	s7, s7, t6
	and	s6, s6, s5
	xor	s7, s7, a4
	xor	s6, s6, t3
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	t1, t1, s5
	add	s6, s9, s6
	add	t5, t5, t1
	add	t1, t1, s6
#else
	slli	s6, t6, 50
	srli	s5, t6, 14
	slli	s7, t6, 46
	or	s5, s5, s6
	srli	s6, t6, 18
	xor	s5, s5, s7
	slli	s7, t6, 23
	xor	s5, s5, s6
	srli	s8, t6, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t2, 36
	srli	s5, t2, 28
	slli	s7, t2, 30
	or	s5, s5, s6
	srli	s6, t2, 34
	xor	s5, s5, s7
	slli	s7, t2, 25
	xor	s5, s5, s6
	srli	s9, t2, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t2, t3
	xor	s7, a3, a4
	xor	s6, t3, t4
	and	s7, s7, t6
	and	s6, s6, s5
	xor	s7, s7, a4
	xor	s6, s6, t3
	add	s5, s8, s7
	add	s7, s11, a6
	add	s5, s5, s7
	add	t1, t1, s5
	add	s6, s9, s6
	add	t5, t5, t1
	add	t1, t1, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s1, a5
	ld	a5, 0(sp)
	ld	a7, 64(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a5, 1
	.word	0x6017da93
	# rori s6, a5, 8
	.word	0x6087db13
	srli	s8, a5, 7
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, s2, 19
	.word	0x61395a93
	# rori s6, s2, 61
	.word	0x63d95b13
	srli	s9, s2, 6
	xor	s9, s9, s5
	xor	s9, s9, s6
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
#else
	slli	s6, a5, 63
	srli	s7, a5, 1
	slli	s5, a5, 56
	or	s7, s7, s6
	srli	s6, a5, 8
	xor	s7, s7, s5
	srli	s8, a5, 7
	xor	s7, s7, s6
	xor	s8, s8, s7
	slli	s6, s2, 45
	srli	s7, s2, 19
	slli	s5, s2, 3
	or	s7, s7, s6
	srli	s6, s2, 61
	xor	s7, s7, s5
	srli	s9, s2, 6
	xor	s7, s7, s6
	xor	s9, s9, s7
	add	s9, s9, a7
	add	a6, a6, s8
	add	a6, s9, a6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	sd	s1, 112(sp)
	mv	s2, a6
	sd	a6, 120(sp)
	andi	s8, a2, 3
	addi	t0, t0, 128
	bnez	s8, L_SHA512_transform_riscv_len_inner
	ld	s10, 0(t0)
	ld	a5, 0(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t5, 14
	.word	0x60ef5a93
	# rori s6, t5, 18
	.word	0x612f5b13
	# rori s8, t5, 41
	.word	0x629f5c13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t1, 28
	.word	0x61c35a93
	# rori s6, t1, 34
	.word	0x62235b13
	# rori s9, t1, 39
	.word	0x62735c93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t1, t2
	xor	s7, t6, a3
	xor	s6, t2, t3
	and	s7, s7, t5
	and	s6, s6, s5
	xor	s7, s7, a3
	xor	s6, s6, t2
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	a4, a4, s5
	add	s6, s9, s6
	add	t4, t4, a4
	add	a4, a4, s6
#else
	slli	s6, t5, 50
	srli	s5, t5, 14
	slli	s7, t5, 46
	or	s5, s5, s6
	srli	s6, t5, 18
	xor	s5, s5, s7
	slli	s7, t5, 23
	xor	s5, s5, s6
	srli	s8, t5, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t1, 36
	srli	s5, t1, 28
	slli	s7, t1, 30
	or	s5, s5, s6
	srli	s6, t1, 34
	xor	s5, s5, s7
	slli	s7, t1, 25
	xor	s5, s5, s6
	srli	s9, t1, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t1, t2
	xor	s7, t6, a3
	xor	s6, t2, t3
	and	s7, s7, t5
	and	s6, s6, s5
	xor	s7, s7, a3
	xor	s6, s6, t2
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	a4, a4, s5
	add	s6, s9, s6
	add	t4, t4, a4
	add	a4, a4, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s10, 8(t0)
	ld	a5, 8(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t4, 14
	.word	0x60eeda93
	# rori s6, t4, 18
	.word	0x612edb13
	# rori s8, t4, 41
	.word	0x629edc13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, a4, 28
	.word	0x61c75a93
	# rori s6, a4, 34
	.word	0x62275b13
	# rori s9, a4, 39
	.word	0x62775c93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, a4, t1
	xor	s7, t5, t6
	xor	s6, t1, t2
	and	s7, s7, t4
	and	s6, s6, s5
	xor	s7, s7, t6
	xor	s6, s6, t1
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	a3, a3, s5
	add	s6, s9, s6
	add	t3, t3, a3
	add	a3, a3, s6
#else
	slli	s6, t4, 50
	srli	s5, t4, 14
	slli	s7, t4, 46
	or	s5, s5, s6
	srli	s6, t4, 18
	xor	s5, s5, s7
	slli	s7, t4, 23
	xor	s5, s5, s6
	srli	s8, t4, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, a4, 36
	srli	s5, a4, 28
	slli	s7, a4, 30
	or	s5, s5, s6
	srli	s6, a4, 34
	xor	s5, s5, s7
	slli	s7, a4, 25
	xor	s5, s5, s6
	srli	s9, a4, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, a4, t1
	xor	s7, t5, t6
	xor	s6, t1, t2
	and	s7, s7, t4
	and	s6, s6, s5
	xor	s7, s7, t6
	xor	s6, s6, t1
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	a3, a3, s5
	add	s6, s9, s6
	add	t3, t3, a3
	add	a3, a3, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s10, 16(t0)
	ld	a5, 16(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t3, 14
	.word	0x60ee5a93
	# rori s6, t3, 18
	.word	0x612e5b13
	# rori s8, t3, 41
	.word	0x629e5c13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, a3, 28
	.word	0x61c6da93
	# rori s6, a3, 34
	.word	0x6226db13
	# rori s9, a3, 39
	.word	0x6276dc93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, a3, a4
	xor	s7, t4, t5
	xor	s6, a4, t1
	and	s7, s7, t3
	and	s6, s6, s5
	xor	s7, s7, t5
	xor	s6, s6, a4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t6, t6, s5
	add	s6, s9, s6
	add	t2, t2, t6
	add	t6, t6, s6
#else
	slli	s6, t3, 50
	srli	s5, t3, 14
	slli	s7, t3, 46
	or	s5, s5, s6
	srli	s6, t3, 18
	xor	s5, s5, s7
	slli	s7, t3, 23
	xor	s5, s5, s6
	srli	s8, t3, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, a3, 36
	srli	s5, a3, 28
	slli	s7, a3, 30
	or	s5, s5, s6
	srli	s6, a3, 34
	xor	s5, s5, s7
	slli	s7, a3, 25
	xor	s5, s5, s6
	srli	s9, a3, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, a3, a4
	xor	s7, t4, t5
	xor	s6, a4, t1
	and	s7, s7, t3
	and	s6, s6, s5
	xor	s7, s7, t5
	xor	s6, s6, a4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t6, t6, s5
	add	s6, s9, s6
	add	t2, t2, t6
	add	t6, t6, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s10, 24(t0)
	ld	a5, 24(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t2, 14
	.word	0x60e3da93
	# rori s6, t2, 18
	.word	0x6123db13
	# rori s8, t2, 41
	.word	0x6293dc13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t6, 28
	.word	0x61cfda93
	# rori s6, t6, 34
	.word	0x622fdb13
	# rori s9, t6, 39
	.word	0x627fdc93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t6, a3
	xor	s7, t3, t4
	xor	s6, a3, a4
	and	s7, s7, t2
	and	s6, s6, s5
	xor	s7, s7, t4
	xor	s6, s6, a3
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t5, t5, s5
	add	s6, s9, s6
	add	t1, t1, t5
	add	t5, t5, s6
#else
	slli	s6, t2, 50
	srli	s5, t2, 14
	slli	s7, t2, 46
	or	s5, s5, s6
	srli	s6, t2, 18
	xor	s5, s5, s7
	slli	s7, t2, 23
	xor	s5, s5, s6
	srli	s8, t2, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t6, 36
	srli	s5, t6, 28
	slli	s7, t6, 30
	or	s5, s5, s6
	srli	s6, t6, 34
	xor	s5, s5, s7
	slli	s7, t6, 25
	xor	s5, s5, s6
	srli	s9, t6, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t6, a3
	xor	s7, t3, t4
	xor	s6, a3, a4
	and	s7, s7, t2
	and	s6, s6, s5
	xor	s7, s7, t4
	xor	s6, s6, a3
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t5, t5, s5
	add	s6, s9, s6
	add	t1, t1, t5
	add	t5, t5, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s10, 32(t0)
	ld	a5, 32(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t1, 14
	.word	0x60e35a93
	# rori s6, t1, 18
	.word	0x61235b13
	# rori s8, t1, 41
	.word	0x62935c13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t5, 28
	.word	0x61cf5a93
	# rori s6, t5, 34
	.word	0x622f5b13
	# rori s9, t5, 39
	.word	0x627f5c93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t5, t6
	xor	s7, t2, t3
	xor	s6, t6, a3
	and	s7, s7, t1
	and	s6, s6, s5
	xor	s7, s7, t3
	xor	s6, s6, t6
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t4, t4, s5
	add	s6, s9, s6
	add	a4, a4, t4
	add	t4, t4, s6
#else
	slli	s6, t1, 50
	srli	s5, t1, 14
	slli	s7, t1, 46
	or	s5, s5, s6
	srli	s6, t1, 18
	xor	s5, s5, s7
	slli	s7, t1, 23
	xor	s5, s5, s6
	srli	s8, t1, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t5, 36
	srli	s5, t5, 28
	slli	s7, t5, 30
	or	s5, s5, s6
	srli	s6, t5, 34
	xor	s5, s5, s7
	slli	s7, t5, 25
	xor	s5, s5, s6
	srli	s9, t5, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t5, t6
	xor	s7, t2, t3
	xor	s6, t6, a3
	and	s7, s7, t1
	and	s6, s6, s5
	xor	s7, s7, t3
	xor	s6, s6, t6
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t4, t4, s5
	add	s6, s9, s6
	add	a4, a4, t4
	add	t4, t4, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s10, 40(t0)
	ld	a5, 40(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a4, 14
	.word	0x60e75a93
	# rori s6, a4, 18
	.word	0x61275b13
	# rori s8, a4, 41
	.word	0x62975c13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t4, 28
	.word	0x61ceda93
	# rori s6, t4, 34
	.word	0x622edb13
	# rori s9, t4, 39
	.word	0x627edc93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t4, t5
	xor	s7, t1, t2
	xor	s6, t5, t6
	and	s7, s7, a4
	and	s6, s6, s5
	xor	s7, s7, t2
	xor	s6, s6, t5
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t3, t3, s5
	add	s6, s9, s6
	add	a3, a3, t3
	add	t3, t3, s6
#else
	slli	s6, a4, 50
	srli	s5, a4, 14
	slli	s7, a4, 46
	or	s5, s5, s6
	srli	s6, a4, 18
	xor	s5, s5, s7
	slli	s7, a4, 23
	xor	s5, s5, s6
	srli	s8, a4, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t4, 36
	srli	s5, t4, 28
	slli	s7, t4, 30
	or	s5, s5, s6
	srli	s6, t4, 34
	xor	s5, s5, s7
	slli	s7, t4, 25
	xor	s5, s5, s6
	srli	s9, t4, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t4, t5
	xor	s7, t1, t2
	xor	s6, t5, t6
	and	s7, s7, a4
	and	s6, s6, s5
	xor	s7, s7, t2
	xor	s6, s6, t5
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t3, t3, s5
	add	s6, s9, s6
	add	a3, a3, t3
	add	t3, t3, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s10, 48(t0)
	ld	a5, 48(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a3, 14
	.word	0x60e6da93
	# rori s6, a3, 18
	.word	0x6126db13
	# rori s8, a3, 41
	.word	0x6296dc13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t3, 28
	.word	0x61ce5a93
	# rori s6, t3, 34
	.word	0x622e5b13
	# rori s9, t3, 39
	.word	0x627e5c93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t3, t4
	xor	s7, a4, t1
	xor	s6, t4, t5
	and	s7, s7, a3
	and	s6, s6, s5
	xor	s7, s7, t1
	xor	s6, s6, t4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t2, t2, s5
	add	s6, s9, s6
	add	t6, t6, t2
	add	t2, t2, s6
#else
	slli	s6, a3, 50
	srli	s5, a3, 14
	slli	s7, a3, 46
	or	s5, s5, s6
	srli	s6, a3, 18
	xor	s5, s5, s7
	slli	s7, a3, 23
	xor	s5, s5, s6
	srli	s8, a3, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t3, 36
	srli	s5, t3, 28
	slli	s7, t3, 30
	or	s5, s5, s6
	srli	s6, t3, 34
	xor	s5, s5, s7
	slli	s7, t3, 25
	xor	s5, s5, s6
	srli	s9, t3, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t3, t4
	xor	s7, a4, t1
	xor	s6, t4, t5
	and	s7, s7, a3
	and	s6, s6, s5
	xor	s7, s7, t1
	xor	s6, s6, t4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t2, t2, s5
	add	s6, s9, s6
	add	t6, t6, t2
	add	t2, t2, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s10, 56(t0)
	ld	a5, 56(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t6, 14
	.word	0x60efda93
	# rori s6, t6, 18
	.word	0x612fdb13
	# rori s8, t6, 41
	.word	0x629fdc13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t2, 28
	.word	0x61c3da93
	# rori s6, t2, 34
	.word	0x6223db13
	# rori s9, t2, 39
	.word	0x6273dc93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t2, t3
	xor	s7, a3, a4
	xor	s6, t3, t4
	and	s7, s7, t6
	and	s6, s6, s5
	xor	s7, s7, a4
	xor	s6, s6, t3
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t1, t1, s5
	add	s6, s9, s6
	add	t5, t5, t1
	add	t1, t1, s6
#else
	slli	s6, t6, 50
	srli	s5, t6, 14
	slli	s7, t6, 46
	or	s5, s5, s6
	srli	s6, t6, 18
	xor	s5, s5, s7
	slli	s7, t6, 23
	xor	s5, s5, s6
	srli	s8, t6, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t2, 36
	srli	s5, t2, 28
	slli	s7, t2, 30
	or	s5, s5, s6
	srli	s6, t2, 34
	xor	s5, s5, s7
	slli	s7, t2, 25
	xor	s5, s5, s6
	srli	s9, t2, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t2, t3
	xor	s7, a3, a4
	xor	s6, t3, t4
	and	s7, s7, t6
	and	s6, s6, s5
	xor	s7, s7, a4
	xor	s6, s6, t3
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t1, t1, s5
	add	s6, s9, s6
	add	t5, t5, t1
	add	t1, t1, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s10, 64(t0)
	ld	a5, 64(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t5, 14
	.word	0x60ef5a93
	# rori s6, t5, 18
	.word	0x612f5b13
	# rori s8, t5, 41
	.word	0x629f5c13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t1, 28
	.word	0x61c35a93
	# rori s6, t1, 34
	.word	0x62235b13
	# rori s9, t1, 39
	.word	0x62735c93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t1, t2
	xor	s7, t6, a3
	xor	s6, t2, t3
	and	s7, s7, t5
	and	s6, s6, s5
	xor	s7, s7, a3
	xor	s6, s6, t2
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	a4, a4, s5
	add	s6, s9, s6
	add	t4, t4, a4
	add	a4, a4, s6
#else
	slli	s6, t5, 50
	srli	s5, t5, 14
	slli	s7, t5, 46
	or	s5, s5, s6
	srli	s6, t5, 18
	xor	s5, s5, s7
	slli	s7, t5, 23
	xor	s5, s5, s6
	srli	s8, t5, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t1, 36
	srli	s5, t1, 28
	slli	s7, t1, 30
	or	s5, s5, s6
	srli	s6, t1, 34
	xor	s5, s5, s7
	slli	s7, t1, 25
	xor	s5, s5, s6
	srli	s9, t1, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t1, t2
	xor	s7, t6, a3
	xor	s6, t2, t3
	and	s7, s7, t5
	and	s6, s6, s5
	xor	s7, s7, a3
	xor	s6, s6, t2
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	a4, a4, s5
	add	s6, s9, s6
	add	t4, t4, a4
	add	a4, a4, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s10, 72(t0)
	ld	a5, 72(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t4, 14
	.word	0x60eeda93
	# rori s6, t4, 18
	.word	0x612edb13
	# rori s8, t4, 41
	.word	0x629edc13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, a4, 28
	.word	0x61c75a93
	# rori s6, a4, 34
	.word	0x62275b13
	# rori s9, a4, 39
	.word	0x62775c93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, a4, t1
	xor	s7, t5, t6
	xor	s6, t1, t2
	and	s7, s7, t4
	and	s6, s6, s5
	xor	s7, s7, t6
	xor	s6, s6, t1
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	a3, a3, s5
	add	s6, s9, s6
	add	t3, t3, a3
	add	a3, a3, s6
#else
	slli	s6, t4, 50
	srli	s5, t4, 14
	slli	s7, t4, 46
	or	s5, s5, s6
	srli	s6, t4, 18
	xor	s5, s5, s7
	slli	s7, t4, 23
	xor	s5, s5, s6
	srli	s8, t4, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, a4, 36
	srli	s5, a4, 28
	slli	s7, a4, 30
	or	s5, s5, s6
	srli	s6, a4, 34
	xor	s5, s5, s7
	slli	s7, a4, 25
	xor	s5, s5, s6
	srli	s9, a4, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, a4, t1
	xor	s7, t5, t6
	xor	s6, t1, t2
	and	s7, s7, t4
	and	s6, s6, s5
	xor	s7, s7, t6
	xor	s6, s6, t1
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	a3, a3, s5
	add	s6, s9, s6
	add	t3, t3, a3
	add	a3, a3, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s10, 80(t0)
	ld	a5, 80(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t3, 14
	.word	0x60ee5a93
	# rori s6, t3, 18
	.word	0x612e5b13
	# rori s8, t3, 41
	.word	0x629e5c13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, a3, 28
	.word	0x61c6da93
	# rori s6, a3, 34
	.word	0x6226db13
	# rori s9, a3, 39
	.word	0x6276dc93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, a3, a4
	xor	s7, t4, t5
	xor	s6, a4, t1
	and	s7, s7, t3
	and	s6, s6, s5
	xor	s7, s7, t5
	xor	s6, s6, a4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t6, t6, s5
	add	s6, s9, s6
	add	t2, t2, t6
	add	t6, t6, s6
#else
	slli	s6, t3, 50
	srli	s5, t3, 14
	slli	s7, t3, 46
	or	s5, s5, s6
	srli	s6, t3, 18
	xor	s5, s5, s7
	slli	s7, t3, 23
	xor	s5, s5, s6
	srli	s8, t3, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, a3, 36
	srli	s5, a3, 28
	slli	s7, a3, 30
	or	s5, s5, s6
	srli	s6, a3, 34
	xor	s5, s5, s7
	slli	s7, a3, 25
	xor	s5, s5, s6
	srli	s9, a3, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, a3, a4
	xor	s7, t4, t5
	xor	s6, a4, t1
	and	s7, s7, t3
	and	s6, s6, s5
	xor	s7, s7, t5
	xor	s6, s6, a4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t6, t6, s5
	add	s6, s9, s6
	add	t2, t2, t6
	add	t6, t6, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s10, 88(t0)
	ld	a5, 88(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t2, 14
	.word	0x60e3da93
	# rori s6, t2, 18
	.word	0x6123db13
	# rori s8, t2, 41
	.word	0x6293dc13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t6, 28
	.word	0x61cfda93
	# rori s6, t6, 34
	.word	0x622fdb13
	# rori s9, t6, 39
	.word	0x627fdc93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t6, a3
	xor	s7, t3, t4
	xor	s6, a3, a4
	and	s7, s7, t2
	and	s6, s6, s5
	xor	s7, s7, t4
	xor	s6, s6, a3
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t5, t5, s5
	add	s6, s9, s6
	add	t1, t1, t5
	add	t5, t5, s6
#else
	slli	s6, t2, 50
	srli	s5, t2, 14
	slli	s7, t2, 46
	or	s5, s5, s6
	srli	s6, t2, 18
	xor	s5, s5, s7
	slli	s7, t2, 23
	xor	s5, s5, s6
	srli	s8, t2, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t6, 36
	srli	s5, t6, 28
	slli	s7, t6, 30
	or	s5, s5, s6
	srli	s6, t6, 34
	xor	s5, s5, s7
	slli	s7, t6, 25
	xor	s5, s5, s6
	srli	s9, t6, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t6, a3
	xor	s7, t3, t4
	xor	s6, a3, a4
	and	s7, s7, t2
	and	s6, s6, s5
	xor	s7, s7, t4
	xor	s6, s6, a3
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t5, t5, s5
	add	s6, s9, s6
	add	t1, t1, t5
	add	t5, t5, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s10, 96(t0)
	ld	a5, 96(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t1, 14
	.word	0x60e35a93
	# rori s6, t1, 18
	.word	0x61235b13
	# rori s8, t1, 41
	.word	0x62935c13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t5, 28
	.word	0x61cf5a93
	# rori s6, t5, 34
	.word	0x622f5b13
	# rori s9, t5, 39
	.word	0x627f5c93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t5, t6
	xor	s7, t2, t3
	xor	s6, t6, a3
	and	s7, s7, t1
	and	s6, s6, s5
	xor	s7, s7, t3
	xor	s6, s6, t6
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t4, t4, s5
	add	s6, s9, s6
	add	a4, a4, t4
	add	t4, t4, s6
#else
	slli	s6, t1, 50
	srli	s5, t1, 14
	slli	s7, t1, 46
	or	s5, s5, s6
	srli	s6, t1, 18
	xor	s5, s5, s7
	slli	s7, t1, 23
	xor	s5, s5, s6
	srli	s8, t1, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t5, 36
	srli	s5, t5, 28
	slli	s7, t5, 30
	or	s5, s5, s6
	srli	s6, t5, 34
	xor	s5, s5, s7
	slli	s7, t5, 25
	xor	s5, s5, s6
	srli	s9, t5, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t5, t6
	xor	s7, t2, t3
	xor	s6, t6, a3
	and	s7, s7, t1
	and	s6, s6, s5
	xor	s7, s7, t3
	xor	s6, s6, t6
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t4, t4, s5
	add	s6, s9, s6
	add	a4, a4, t4
	add	t4, t4, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s10, 104(t0)
	ld	a5, 104(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a4, 14
	.word	0x60e75a93
	# rori s6, a4, 18
	.word	0x61275b13
	# rori s8, a4, 41
	.word	0x62975c13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t4, 28
	.word	0x61ceda93
	# rori s6, t4, 34
	.word	0x622edb13
	# rori s9, t4, 39
	.word	0x627edc93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t4, t5
	xor	s7, t1, t2
	xor	s6, t5, t6
	and	s7, s7, a4
	and	s6, s6, s5
	xor	s7, s7, t2
	xor	s6, s6, t5
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t3, t3, s5
	add	s6, s9, s6
	add	a3, a3, t3
	add	t3, t3, s6
#else
	slli	s6, a4, 50
	srli	s5, a4, 14
	slli	s7, a4, 46
	or	s5, s5, s6
	srli	s6, a4, 18
	xor	s5, s5, s7
	slli	s7, a4, 23
	xor	s5, s5, s6
	srli	s8, a4, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t4, 36
	srli	s5, t4, 28
	slli	s7, t4, 30
	or	s5, s5, s6
	srli	s6, t4, 34
	xor	s5, s5, s7
	slli	s7, t4, 25
	xor	s5, s5, s6
	srli	s9, t4, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t4, t5
	xor	s7, t1, t2
	xor	s6, t5, t6
	and	s7, s7, a4
	and	s6, s6, s5
	xor	s7, s7, t2
	xor	s6, s6, t5
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t3, t3, s5
	add	s6, s9, s6
	add	a3, a3, t3
	add	t3, t3, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s10, 112(t0)
	ld	a5, 112(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, a3, 14
	.word	0x60e6da93
	# rori s6, a3, 18
	.word	0x6126db13
	# rori s8, a3, 41
	.word	0x6296dc13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t3, 28
	.word	0x61ce5a93
	# rori s6, t3, 34
	.word	0x622e5b13
	# rori s9, t3, 39
	.word	0x627e5c93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t3, t4
	xor	s7, a4, t1
	xor	s6, t4, t5
	and	s7, s7, a3
	and	s6, s6, s5
	xor	s7, s7, t1
	xor	s6, s6, t4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t2, t2, s5
	add	s6, s9, s6
	add	t6, t6, t2
	add	t2, t2, s6
#else
	slli	s6, a3, 50
	srli	s5, a3, 14
	slli	s7, a3, 46
	or	s5, s5, s6
	srli	s6, a3, 18
	xor	s5, s5, s7
	slli	s7, a3, 23
	xor	s5, s5, s6
	srli	s8, a3, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t3, 36
	srli	s5, t3, 28
	slli	s7, t3, 30
	or	s5, s5, s6
	srli	s6, t3, 34
	xor	s5, s5, s7
	slli	s7, t3, 25
	xor	s5, s5, s6
	srli	s9, t3, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t3, t4
	xor	s7, a4, t1
	xor	s6, t4, t5
	and	s7, s7, a3
	and	s6, s6, s5
	xor	s7, s7, t1
	xor	s6, s6, t4
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t2, t2, s5
	add	s6, s9, s6
	add	t6, t6, t2
	add	t2, t2, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s10, 120(t0)
	ld	a5, 120(sp)
#if defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	# rori s5, t6, 14
	.word	0x60efda93
	# rori s6, t6, 18
	.word	0x612fdb13
	# rori s8, t6, 41
	.word	0x629fdc13
	xor	s8, s8, s5
	xor	s8, s8, s6
	# rori s5, t2, 28
	.word	0x61c3da93
	# rori s6, t2, 34
	.word	0x6223db13
	# rori s9, t2, 39
	.word	0x6273dc93
	xor	s9, s9, s5
	xor	s9, s9, s6
	xor	s5, t2, t3
	xor	s7, a3, a4
	xor	s6, t3, t4
	and	s7, s7, t6
	and	s6, s6, s5
	xor	s7, s7, a4
	xor	s6, s6, t3
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t1, t1, s5
	add	s6, s9, s6
	add	t5, t5, t1
	add	t1, t1, s6
#else
	slli	s6, t6, 50
	srli	s5, t6, 14
	slli	s7, t6, 46
	or	s5, s5, s6
	srli	s6, t6, 18
	xor	s5, s5, s7
	slli	s7, t6, 23
	xor	s5, s5, s6
	srli	s8, t6, 41
	xor	s5, s5, s7
	xor	s8, s8, s5
	slli	s6, t2, 36
	srli	s5, t2, 28
	slli	s7, t2, 30
	or	s5, s5, s6
	srli	s6, t2, 34
	xor	s5, s5, s7
	slli	s7, t2, 25
	xor	s5, s5, s6
	srli	s9, t2, 39
	xor	s5, s5, s7
	xor	s9, s9, s5
	xor	s5, t2, t3
	xor	s7, a3, a4
	xor	s6, t3, t4
	and	s7, s7, t6
	and	s6, s6, s5
	xor	s7, s7, a4
	xor	s6, s6, t3
	add	s5, s8, s7
	add	s7, s10, a5
	add	s5, s5, s7
	add	t1, t1, s5
	add	s6, s9, s6
	add	t5, t5, t1
	add	t1, t1, s6
#endif /* defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	addi	t0, t0, -512
	# Add working variables back into digest state
	ld	s5, 0(a0)
	ld	a5, 8(a0)
	ld	a6, 16(a0)
	ld	a7, 24(a0)
	ld	s1, 32(a0)
	ld	s2, 40(a0)
	ld	s3, 48(a0)
	ld	s4, 56(a0)
	add	t1, t1, s5
	add	t2, t2, a5
	add	t3, t3, a6
	add	t4, t4, a7
	add	t5, t5, s1
	add	t6, t6, s2
	add	a3, a3, s3
	add	a4, a4, s4
	# Store digest
	sd	t1, 0(a0)
	sd	t2, 8(a0)
	sd	t3, 16(a0)
	sd	t4, 24(a0)
	sd	t5, 32(a0)
	sd	t6, 40(a0)
	sd	a3, 48(a0)
	sd	a4, 56(a0)
	addi	a1, a1, 128
	bnez	a2, L_SHA512_transform_riscv_len_begin
	ld	s1, 136(sp)
	ld	s2, 144(sp)
	ld	s3, 152(sp)
	ld	s4, 160(sp)
	ld	s5, 168(sp)
	ld	s6, 176(sp)
	ld	s7, 184(sp)
	ld	s8, 192(sp)
	ld	s9, 200(sp)
	ld	s10, 208(sp)
	ld	s11, 216(sp)
	addi	sp, sp, 224
	ret
	.size	Transform_Sha512_Len_riscv,.-Transform_Sha512_Len_riscv
#endif /* WOLFSSL_RISCV_VECTOR_CRYPTO_ASM */
#endif /* WOLFSSL_SHA512 || WOLFSSL_SHA384 */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_RISCV_ASM_INLINE */
#endif /* WOLFSSL_RISCV_ASM */
