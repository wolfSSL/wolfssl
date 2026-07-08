/* riscv-64-sha3-asm
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
 *   ruby ./sha3/sha3.rb riscv64 \
 *       ../wolfssl/wolfcrypt/src/port/riscv64/riscv-64-sha3-asm.S
 */
#ifdef WOLFSSL_RISCV_ASM
#ifndef WOLFSSL_RISCV_ASM_INLINE
#ifdef WOLFSSL_SHA3
#ifdef WOLFSSL_RISCV_VECTOR
	.section	.rodata
	.type	L_SHA3_transform_vector_r, %object
	.size	L_SHA3_transform_vector_r, 192
	# 8-byte aligned, 64-bit aligned
	.align	3
L_SHA3_transform_vector_r:
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
	.text
	.globl	BlockSha3
	.type	BlockSha3,@function
	.align	2
BlockSha3:
	la	t0, L_SHA3_transform_vector_r
#if defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	.option arch, +v, +zvkb, +zvbb
#else
	.option arch, +v
#endif /* defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vsetivli	zero, 1, e64, m1, ta, ma
	li	t3, 24
	mv	t1, t0
	mv	t2, a0
	vlseg8e64.v	v0, (t2)
	addi	t2, a0, 64
	vlseg8e64.v	v8, (t2)
	addi	t2, a0, 128
	vlseg8e64.v	v16, (t2)
	addi	t2, a0, 192
	vle64.v	v24, (t2)
L_riscv_64_block_sha3_vector_loop:
	# COLUMN MIX
	vxor.vv	v25, v0, v5
	vxor.vv	v26, v1, v6
	vxor.vv	v27, v2, v7
	vxor.vv	v28, v3, v8
	vxor.vv	v29, v4, v9
	vxor.vv	v25, v25, v10
	vxor.vv	v26, v26, v11
	vxor.vv	v27, v27, v12
	vxor.vv	v28, v28, v13
	vxor.vv	v29, v29, v14
	vxor.vv	v25, v25, v15
	vxor.vv	v26, v26, v16
	vxor.vv	v27, v27, v17
	vxor.vv	v28, v28, v18
	vxor.vv	v29, v29, v19
	vxor.vv	v25, v25, v20
	vxor.vv	v26, v26, v21
	vxor.vv	v27, v27, v22
	vxor.vv	v28, v28, v23
	vxor.vv	v29, v29, v24
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 63
	vsll.vi	v31, v26, 1
	vsrl.vx	v30, v26, t2
	vxor.vv	v31, v31, v29
	vxor.vv	v31, v31, v30
	vxor.vv	v0, v0, v31
	vxor.vv	v5, v5, v31
	vxor.vv	v10, v10, v31
	vxor.vv	v15, v15, v31
	vxor.vv	v20, v20, v31
	vsll.vi	v31, v27, 1
	vsrl.vx	v30, v27, t2
	vxor.vv	v31, v31, v25
	vxor.vv	v31, v31, v30
	vxor.vv	v1, v1, v31
	vxor.vv	v6, v6, v31
	vxor.vv	v11, v11, v31
	vxor.vv	v16, v16, v31
	vxor.vv	v21, v21, v31
	vsll.vi	v31, v28, 1
	vsrl.vx	v30, v28, t2
	vxor.vv	v31, v31, v26
	vxor.vv	v31, v31, v30
	vxor.vv	v2, v2, v31
	vxor.vv	v7, v7, v31
	vxor.vv	v12, v12, v31
	vxor.vv	v17, v17, v31
	vxor.vv	v22, v22, v31
	vsll.vi	v31, v29, 1
	vsrl.vx	v30, v29, t2
	vxor.vv	v31, v31, v27
	vxor.vv	v31, v31, v30
	vxor.vv	v3, v3, v31
	vxor.vv	v8, v8, v31
	vxor.vv	v13, v13, v31
	vxor.vv	v18, v18, v31
	vxor.vv	v23, v23, v31
	vsll.vi	v31, v25, 1
	vsrl.vx	v30, v25, t2
	vxor.vv	v31, v31, v28
	vxor.vv	v31, v31, v30
	vxor.vv	v4, v4, v31
	vxor.vv	v9, v9, v31
	vxor.vv	v14, v14, v31
	vxor.vv	v19, v19, v31
	vxor.vv	v24, v24, v31
#else
	vror.vi	v30, v26, 63
	vror.vi	v31, v27, 63
	vxor.vv	v30, v30, v29
	vxor.vv	v31, v31, v25
	vxor.vv	v0, v0, v30
	vxor.vv	v5, v5, v30
	vxor.vv	v10, v10, v30
	vxor.vv	v15, v15, v30
	vxor.vv	v20, v20, v30
	vxor.vv	v1, v1, v31
	vxor.vv	v6, v6, v31
	vxor.vv	v11, v11, v31
	vxor.vv	v16, v16, v31
	vxor.vv	v21, v21, v31
	vror.vi	v30, v28, 63
	vror.vi	v31, v29, 63
	vror.vi	v25, v25, 63
	vxor.vv	v30, v30, v26
	vxor.vv	v31, v31, v27
	vxor.vv	v25, v25, v28
	vxor.vv	v2, v2, v30
	vxor.vv	v7, v7, v30
	vxor.vv	v12, v12, v30
	vxor.vv	v17, v17, v30
	vxor.vv	v22, v22, v30
	vxor.vv	v3, v3, v31
	vxor.vv	v8, v8, v31
	vxor.vv	v13, v13, v31
	vxor.vv	v18, v18, v31
	vxor.vv	v23, v23, v31
	vxor.vv	v4, v4, v25
	vxor.vv	v9, v9, v25
	vxor.vv	v14, v14, v25
	vxor.vv	v19, v19, v25
	vxor.vv	v24, v24, v25
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	# SWAP ROTL (rho + pi)
	vmv.v.v	v26, v1
	vmv.v.v	v25, v10
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 63
	vsll.vi	v10, v26, 1
	vsrl.vx	v26, v26, t2
	vor.vv	v10, v10, v26
#else
	vror.vi	v10, v26, 63
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v26, v7
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 61
	vsll.vi	v7, v25, 3
	vsrl.vx	v25, v25, t2
	vor.vv	v7, v7, v25
#else
	vror.vi	v7, v25, 61
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v25, v11
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 58
	vsll.vi	v11, v26, 6
	vsrl.vx	v26, v26, t2
	vor.vv	v11, v11, v26
#else
	vror.vi	v11, v26, 58
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v26, v17
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 54
	vsll.vi	v17, v25, 10
	vsrl.vx	v25, v25, t2
	vor.vv	v17, v17, v25
#else
	vror.vi	v17, v25, 54
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v25, v18
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 49
	vsll.vi	v18, v26, 15
	vsrl.vx	v26, v26, t2
	vor.vv	v18, v18, v26
#else
	vror.vi	v18, v26, 49
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v26, v3
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 43
	vsll.vi	v3, v25, 21
	vsrl.vx	v25, v25, t2
	vor.vv	v3, v3, v25
#else
	vror.vi	v3, v25, 43
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v25, v5
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 36
	vsll.vi	v5, v26, 28
	vsrl.vx	v26, v26, t2
	vor.vv	v5, v5, v26
#else
	vror.vi	v5, v26, 36
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v26, v16
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 36
	vsrl.vi	v16, v25, 28
	vsll.vx	v25, v25, t2
	vor.vv	v16, v16, v25
#else
	vror.vi	v16, v25, 28
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v25, v8
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 45
	vsrl.vi	v8, v26, 19
	vsll.vx	v26, v26, t2
	vor.vv	v8, v8, v26
#else
	vror.vi	v8, v26, 19
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v26, v21
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 55
	vsrl.vi	v21, v25, 9
	vsll.vx	v25, v25, t2
	vor.vv	v21, v21, v25
#else
	vror.vi	v21, v25, 9
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v25, v24
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 62
	vsll.vi	v24, v26, 2
	vsrl.vx	v26, v26, t2
	vor.vv	v24, v24, v26
#else
	vror.vi	v24, v26, 62
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v26, v4
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 50
	vsll.vi	v4, v25, 14
	vsrl.vx	v25, v25, t2
	vor.vv	v4, v4, v25
#else
	vror.vi	v4, v25, 50
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v25, v15
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 37
	vsll.vi	v15, v26, 27
	vsrl.vx	v26, v26, t2
	vor.vv	v15, v15, v26
#else
	vror.vi	v15, v26, 37
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v26, v23
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 41
	vsrl.vi	v23, v25, 23
	vsll.vx	v25, v25, t2
	vor.vv	v23, v23, v25
#else
	vror.vi	v23, v25, 23
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v25, v19
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 56
	vsrl.vi	v19, v26, 8
	vsll.vx	v26, v26, t2
	vor.vv	v19, v19, v26
#else
	vror.vi	v19, v26, 8
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v26, v13
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 56
	vsll.vi	v13, v25, 8
	vsrl.vx	v25, v25, t2
	vor.vv	v13, v13, v25
#else
	vror.vi	v13, v25, 56
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v25, v12
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 39
	vsll.vi	v12, v26, 25
	vsrl.vx	v26, v26, t2
	vor.vv	v12, v12, v26
#else
	vror.vi	v12, v26, 39
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v26, v2
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 43
	vsrl.vi	v2, v25, 21
	vsll.vx	v25, v25, t2
	vor.vv	v2, v2, v25
#else
	vror.vi	v2, v25, 21
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v25, v20
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 62
	vsrl.vi	v20, v26, 2
	vsll.vx	v26, v26, t2
	vor.vv	v20, v20, v26
#else
	vror.vi	v20, v26, 2
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v26, v14
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 46
	vsll.vi	v14, v25, 18
	vsrl.vx	v25, v25, t2
	vor.vv	v14, v14, v25
#else
	vror.vi	v14, v25, 46
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v25, v22
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 39
	vsrl.vi	v22, v26, 25
	vsll.vx	v26, v26, t2
	vor.vv	v22, v22, v26
#else
	vror.vi	v22, v26, 25
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v26, v9
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 61
	vsrl.vi	v9, v25, 3
	vsll.vx	v25, v25, t2
	vor.vv	v9, v9, v25
#else
	vror.vi	v9, v25, 3
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v25, v6
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	li	t2, 44
	vsll.vi	v6, v26, 20
	vsrl.vx	v26, v26, t2
	vor.vv	v6, v6, v26
#else
	vror.vi	v6, v26, 44
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	li	t2, 44
	vsrl.vi	v1, v25, 20
	vsll.vx	v25, v25, t2
	vor.vv	v1, v1, v25
	# ROW MIX (chi)
	vmv.v.v	v25, v0
	vmv.v.v	v26, v1
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	vnot.v	v30, v1
	vnot.v	v31, v2
	vand.vv	v30, v30, v2
	vand.vv	v31, v31, v3
	vxor.vv	v0, v30, v0
	vxor.vv	v1, v31, v1
	vnot.v	v30, v3
	vnot.v	v31, v4
	vand.vv	v30, v30, v4
	vand.vv	v31, v31, v25
	vnot.v	v25, v25
	vxor.vv	v2, v30, v2
	vand.vv	v25, v25, v26
	vxor.vv	v3, v31, v3
	vxor.vv	v4, v25, v4
#else
	vandn.vv	v30, v2, v1
	vandn.vv	v31, v3, v2
	vxor.vv	v0, v30, v0
	vxor.vv	v1, v31, v1
	vandn.vv	v30, v4, v3
	vandn.vv	v31, v25, v4
	vandn.vv	v25, v26, v25
	vxor.vv	v2, v30, v2
	vxor.vv	v3, v31, v3
	vxor.vv	v4, v25, v4
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v25, v5
	vmv.v.v	v26, v6
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	vnot.v	v30, v6
	vnot.v	v31, v7
	vand.vv	v30, v30, v7
	vand.vv	v31, v31, v8
	vxor.vv	v5, v30, v5
	vxor.vv	v6, v31, v6
	vnot.v	v30, v8
	vnot.v	v31, v9
	vand.vv	v30, v30, v9
	vand.vv	v31, v31, v25
	vnot.v	v25, v25
	vxor.vv	v7, v30, v7
	vand.vv	v25, v25, v26
	vxor.vv	v8, v31, v8
	vxor.vv	v9, v25, v9
#else
	vandn.vv	v30, v7, v6
	vandn.vv	v31, v8, v7
	vxor.vv	v5, v30, v5
	vxor.vv	v6, v31, v6
	vandn.vv	v30, v9, v8
	vandn.vv	v31, v25, v9
	vandn.vv	v25, v26, v25
	vxor.vv	v7, v30, v7
	vxor.vv	v8, v31, v8
	vxor.vv	v9, v25, v9
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v25, v10
	vmv.v.v	v26, v11
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	vnot.v	v30, v11
	vnot.v	v31, v12
	vand.vv	v30, v30, v12
	vand.vv	v31, v31, v13
	vxor.vv	v10, v30, v10
	vxor.vv	v11, v31, v11
	vnot.v	v30, v13
	vnot.v	v31, v14
	vand.vv	v30, v30, v14
	vand.vv	v31, v31, v25
	vnot.v	v25, v25
	vxor.vv	v12, v30, v12
	vand.vv	v25, v25, v26
	vxor.vv	v13, v31, v13
	vxor.vv	v14, v25, v14
#else
	vandn.vv	v30, v12, v11
	vandn.vv	v31, v13, v12
	vxor.vv	v10, v30, v10
	vxor.vv	v11, v31, v11
	vandn.vv	v30, v14, v13
	vandn.vv	v31, v25, v14
	vandn.vv	v25, v26, v25
	vxor.vv	v12, v30, v12
	vxor.vv	v13, v31, v13
	vxor.vv	v14, v25, v14
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v25, v15
	vmv.v.v	v26, v16
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	vnot.v	v30, v16
	vnot.v	v31, v17
	vand.vv	v30, v30, v17
	vand.vv	v31, v31, v18
	vxor.vv	v15, v30, v15
	vxor.vv	v16, v31, v16
	vnot.v	v30, v18
	vnot.v	v31, v19
	vand.vv	v30, v30, v19
	vand.vv	v31, v31, v25
	vnot.v	v25, v25
	vxor.vv	v17, v30, v17
	vand.vv	v25, v25, v26
	vxor.vv	v18, v31, v18
	vxor.vv	v19, v25, v19
#else
	vandn.vv	v30, v17, v16
	vandn.vv	v31, v18, v17
	vxor.vv	v15, v30, v15
	vxor.vv	v16, v31, v16
	vandn.vv	v30, v19, v18
	vandn.vv	v31, v25, v19
	vandn.vv	v25, v26, v25
	vxor.vv	v17, v30, v17
	vxor.vv	v18, v31, v18
	vxor.vv	v19, v25, v19
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	vmv.v.v	v25, v20
	vmv.v.v	v26, v21
#if !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION)
	vnot.v	v30, v21
	vnot.v	v31, v22
	vand.vv	v30, v30, v22
	vand.vv	v31, v31, v23
	vxor.vv	v20, v30, v20
	vxor.vv	v21, v31, v21
	vnot.v	v30, v23
	vnot.v	v31, v24
	vand.vv	v30, v30, v24
	vand.vv	v31, v31, v25
	vnot.v	v25, v25
	vxor.vv	v22, v30, v22
	vand.vv	v25, v25, v26
	vxor.vv	v23, v31, v23
	vxor.vv	v24, v25, v24
#else
	vandn.vv	v30, v22, v21
	vandn.vv	v31, v23, v22
	vxor.vv	v20, v30, v20
	vxor.vv	v21, v31, v21
	vandn.vv	v30, v24, v23
	vandn.vv	v31, v25, v24
	vandn.vv	v25, v26, v25
	vxor.vv	v22, v30, v22
	vxor.vv	v23, v31, v23
	vxor.vv	v24, v25, v24
#endif /* !defined(WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION) */
	# IOTA (round constant)
	vl1re64.v	v25, (t1)
	addi	t1, t1, 8
	addi	t3, t3, -1
	vxor.vv	v0, v0, v25
	bnez	t3, L_riscv_64_block_sha3_vector_loop
	mv	t2, a0
	vsseg8e64.v	v0, (t2)
	addi	t2, a0, 64
	vsseg8e64.v	v8, (t2)
	addi	t2, a0, 128
	vsseg8e64.v	v16, (t2)
	addi	t2, a0, 192
	vse64.v	v24, (t2)
	ret
	.size	BlockSha3,.-BlockSha3
#else
	.section	.rodata
	.type	L_SHA3_transform_riscv_r, %object
	.size	L_SHA3_transform_riscv_r, 192
	# 8-byte aligned, 64-bit aligned
	.align	3
L_SHA3_transform_riscv_r:
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
	.text
	.globl	BlockSha3
	.type	BlockSha3,@function
	.align	2
BlockSha3:
	addi	sp, sp, -128
	sd	s0, 32(sp)
	sd	s1, 40(sp)
	sd	s2, 48(sp)
	sd	s3, 56(sp)
	sd	s4, 64(sp)
	sd	s5, 72(sp)
	sd	s6, 80(sp)
	sd	s7, 88(sp)
	sd	s8, 96(sp)
	sd	s9, 104(sp)
	sd	s10, 112(sp)
	sd	s11, 120(sp)
	la	t0, L_SHA3_transform_riscv_r
	li	s0, 24
	ld	t1, 0(a0)
	ld	t2, 8(a0)
	ld	t3, 16(a0)
	ld	t4, 24(a0)
	ld	t5, 32(a0)
	ld	t6, 40(a0)
	ld	a1, 48(a0)
	ld	a2, 56(a0)
	ld	a3, 64(a0)
	ld	a4, 72(a0)
	ld	a5, 80(a0)
	ld	a6, 88(a0)
	ld	a7, 96(a0)
	ld	s1, 104(a0)
	ld	s2, 112(a0)
	ld	s3, 120(a0)
	ld	s4, 128(a0)
	ld	s5, 136(a0)
	ld	s6, 144(a0)
	ld	s7, 152(a0)
	ld	s8, 160(a0)
	ld	s9, 168(a0)
	ld	s10, 176(a0)
L_riscv_64_block_sha3_loop:
	sd	s0, 16(sp)
	# COLUMN MIX
	ld	s11, 184(a0)
	ld	s0, 192(a0)
	xor	s8, s8, t1
	xor	s9, s9, t2
	xor	s10, s10, t3
	xor	s11, s11, t4
	xor	s0, s0, t5
	xor	s8, s8, t6
	xor	s9, s9, a1
	xor	s10, s10, a2
	xor	s11, s11, a3
	xor	s0, s0, a4
	xor	s8, s8, a5
	xor	s9, s9, a6
	xor	s10, s10, a7
	xor	s11, s11, s1
	xor	s0, s0, s2
	xor	s8, s8, s3
	xor	s9, s9, s4
	xor	s10, s10, s5
	xor	s11, s11, s6
	xor	s0, s0, s7
	sd	s9, 0(sp)
	sd	s11, 8(sp)
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s11, s9, 63
	slli	s9, s9, 1
	or	s9, s9, s11
#else
	# rori s9, s9, 63
	.word	0x63fcdc93
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s11, 160(a0)
	xor	s9, s9, s0
	xor	t1, t1, s9
	xor	t6, t6, s9
	xor	s11, s11, s9
	xor	a5, a5, s9
	xor	s3, s3, s9
	sd	s11, 160(a0)
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s11, s10, 63
	slli	s9, s10, 1
	or	s9, s9, s11
#else
	# rori s9, s10, 63
	.word	0x63fd5c93
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s11, 168(a0)
	xor	s9, s9, s8
	xor	t2, t2, s9
	xor	a1, a1, s9
	xor	s11, s11, s9
	xor	a6, a6, s9
	xor	s4, s4, s9
	sd	s11, 168(a0)
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s11, s0, 63
	slli	s0, s0, 1
	or	s0, s0, s11
#else
	# rori s0, s0, 63
	.word	0x63f45413
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s11, 184(a0)
	xor	s0, s0, s10
	xor	t4, t4, s0
	xor	a3, a3, s0
	xor	s11, s11, s0
	xor	s1, s1, s0
	xor	s6, s6, s0
	sd	s11, 184(a0)
	ld	s11, 8(sp)
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s10, s8, 63
	slli	s8, s8, 1
	or	s8, s8, s10
#else
	# rori s8, s8, 63
	.word	0x63fc5c13
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s0, 192(a0)
	xor	s8, s8, s11
	xor	t5, t5, s8
	xor	a4, a4, s8
	xor	s0, s0, s8
	xor	s2, s2, s8
	xor	s7, s7, s8
	ld	s9, 0(sp)
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s10, s11, 63
	slli	s11, s11, 1
	or	s11, s11, s10
#else
	# rori s11, s11, 63
	.word	0x63fddd93
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s10, 176(a0)
	xor	s11, s11, s9
	xor	t3, t3, s11
	xor	a2, a2, s11
	xor	s10, s10, s11
	xor	a7, a7, s11
	xor	s5, s5, s11
	# SWAP ROTL (rho + pi)
	mv	s8, a5
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s9, t2, 63
	slli	a5, t2, 1
	or	a5, a5, s9
#else
	# rori a5, t2, 63
	.word	0x63f3d793
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s9, a2
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	a2, s8, 61
	slli	s8, s8, 3
	or	a2, a2, s8
#else
	# rori a2, s8, 61
	.word	0x63dc5613
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s8, a6
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	a6, s9, 58
	slli	s9, s9, 6
	or	a6, a6, s9
#else
	# rori a6, s9, 58
	.word	0x63acd813
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s9, s5
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s5, s8, 54
	slli	s8, s8, 10
	or	s5, s5, s8
#else
	# rori s5, s8, 54
	.word	0x636c5a93
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s8, s6
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s6, s9, 49
	slli	s9, s9, 15
	or	s6, s6, s9
#else
	# rori s6, s9, 49
	.word	0x631cdb13
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s9, t4
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	t4, s8, 43
	slli	s8, s8, 21
	or	t4, t4, s8
#else
	# rori t4, s8, 43
	.word	0x62bc5e93
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s8, t6
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	t6, s9, 36
	slli	s9, s9, 28
	or	t6, t6, s9
#else
	# rori t6, s9, 36
	.word	0x624cdf93
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s9, s4
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s4, s8, 28
	slli	s8, s8, 36
	or	s4, s4, s8
#else
	# rori s4, s8, 28
	.word	0x61cc5a13
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s8, a3
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	a3, s9, 19
	slli	s9, s9, 45
	or	a3, a3, s9
#else
	# rori a3, s9, 19
	.word	0x613cd693
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s9, 168(a0)
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s11, s8, 9
	slli	s8, s8, 55
	or	s8, s8, s11
#else
	# rori s8, s8, 9
	.word	0x609c5c13
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	sd	s8, 168(a0)
	mv	s8, s0
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s0, s9, 62
	slli	s9, s9, 2
	or	s0, s0, s9
#else
	# rori s0, s9, 62
	.word	0x63ecd413
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s9, t5
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	t5, s8, 50
	slli	s8, s8, 14
	or	t5, t5, s8
#else
	# rori t5, s8, 50
	.word	0x632c5f13
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s8, s3
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s3, s9, 37
	slli	s9, s9, 27
	or	s3, s3, s9
#else
	# rori s3, s9, 37
	.word	0x625cd993
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s9, 184(a0)
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s11, s8, 23
	slli	s8, s8, 41
	or	s8, s8, s11
#else
	# rori s8, s8, 23
	.word	0x617c5c13
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	sd	s8, 184(a0)
	mv	s8, s7
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s7, s9, 8
	slli	s9, s9, 56
	or	s7, s7, s9
#else
	# rori s7, s9, 8
	.word	0x608cdb93
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s9, s1
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s1, s8, 56
	slli	s8, s8, 8
	or	s1, s1, s8
#else
	# rori s1, s8, 56
	.word	0x638c5493
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s8, a7
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	a7, s9, 39
	slli	s9, s9, 25
	or	a7, a7, s9
#else
	# rori a7, s9, 39
	.word	0x627cd893
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s9, t3
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	t3, s8, 21
	slli	s8, s8, 43
	or	t3, t3, s8
#else
	# rori t3, s8, 21
	.word	0x615c5e13
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	ld	s8, 160(a0)
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s11, s9, 2
	slli	s9, s9, 62
	or	s9, s9, s11
#else
	# rori s9, s9, 2
	.word	0x602cdc93
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	sd	s9, 160(a0)
	mv	s9, s2
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s2, s8, 46
	slli	s8, s8, 18
	or	s2, s2, s8
#else
	# rori s2, s8, 46
	.word	0x62ec5913
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s8, s10
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	s10, s9, 25
	slli	s9, s9, 39
	or	s10, s10, s9
#else
	# rori s10, s9, 25
	.word	0x619cdd13
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s9, a4
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	a4, s8, 3
	slli	s8, s8, 61
	or	a4, a4, s8
#else
	# rori a4, s8, 3
	.word	0x603c5713
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	mv	s8, a1
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	a1, s9, 44
	slli	s9, s9, 20
	or	a1, a1, s9
#else
	# rori a1, s9, 44
	.word	0x62ccd593
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	srli	t2, s8, 20
	slli	s8, s8, 44
	or	t2, t2, s8
#else
	# rori t2, s8, 20
	.word	0x614c5393
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	# ROW MIX (chi)
	mv	s8, t1
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, t2
	and	s11, s11, t3
#else
	# andn s11, t3, t2
	.word	0x407e7db3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	t1, t1, s11
	mv	s9, t2
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, t3
	and	s11, s11, t4
#else
	# andn s11, t4, t3
	.word	0x41cefdb3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	t2, t2, s11
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, t4
	and	s11, s11, t5
#else
	# andn s11, t5, t4
	.word	0x41df7db3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	t3, t3, s11
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, t5
	and	s11, s11, s8
#else
	# andn s11, s8, t5
	.word	0x41ec7db3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	t4, t4, s11
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, s8
	and	s11, s11, s9
#else
	# andn s11, s9, s8
	.word	0x418cfdb3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	t5, t5, s11
	mv	s8, t6
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, a1
	and	s11, s11, a2
#else
	# andn s11, a2, a1
	.word	0x40b67db3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	t6, t6, s11
	mv	s9, a1
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, a2
	and	s11, s11, a3
#else
	# andn s11, a3, a2
	.word	0x40c6fdb3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	a1, a1, s11
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, a3
	and	s11, s11, a4
#else
	# andn s11, a4, a3
	.word	0x40d77db3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	a2, a2, s11
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, a4
	and	s11, s11, s8
#else
	# andn s11, s8, a4
	.word	0x40ec7db3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	a3, a3, s11
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, s8
	and	s11, s11, s9
#else
	# andn s11, s9, s8
	.word	0x418cfdb3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	a4, a4, s11
	mv	s8, a5
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, a6
	and	s11, s11, a7
#else
	# andn s11, a7, a6
	.word	0x4108fdb3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	a5, a5, s11
	mv	s9, a6
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, a7
	and	s11, s11, s1
#else
	# andn s11, s1, a7
	.word	0x4114fdb3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	a6, a6, s11
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, s1
	and	s11, s11, s2
#else
	# andn s11, s2, s1
	.word	0x40997db3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	a7, a7, s11
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, s2
	and	s11, s11, s8
#else
	# andn s11, s8, s2
	.word	0x412c7db3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	s1, s1, s11
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, s8
	and	s11, s11, s9
#else
	# andn s11, s9, s8
	.word	0x418cfdb3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	s2, s2, s11
	mv	s8, s3
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, s4
	and	s11, s11, s5
#else
	# andn s11, s5, s4
	.word	0x414afdb3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	s3, s3, s11
	mv	s9, s4
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, s5
	and	s11, s11, s6
#else
	# andn s11, s6, s5
	.word	0x415b7db3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	s4, s4, s11
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, s6
	and	s11, s11, s7
#else
	# andn s11, s7, s6
	.word	0x416bfdb3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	s5, s5, s11
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, s7
	and	s11, s11, s8
#else
	# andn s11, s8, s7
	.word	0x417c7db3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	s6, s6, s11
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s11, s8
	and	s11, s11, s9
#else
	# andn s11, s9, s8
	.word	0x418cfdb3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	s7, s7, s11
	sd	s3, 120(a0)
	sd	s4, 128(a0)
	sd	s5, 136(a0)
	ld	s8, 160(a0)
	ld	s9, 168(a0)
	ld	s11, 184(a0)
	mv	s3, s8
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s5, s9
	and	s5, s5, s10
#else
	# andn s5, s10, s9
	.word	0x419d7ab3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	s8, s8, s5
	mv	s4, s9
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s5, s10
	and	s5, s5, s11
#else
	# andn s5, s11, s10
	.word	0x41adfab3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	s9, s9, s5
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s5, s11
	and	s5, s5, s0
#else
	# andn s5, s0, s11
	.word	0x41b47ab3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	s10, s10, s5
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s5, s0
	and	s5, s5, s3
#else
	# andn s5, s3, s0
	.word	0x4089fab3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	s11, s11, s5
#if !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION)
	not	s5, s3
	and	s5, s5, s4
#else
	# andn s5, s4, s3
	.word	0x413a7ab3
#endif /* !defined(WOLFSSL_RISCV_BASE_BIT_MANIPULATION) */
	xor	s0, s0, s5
	ld	s3, 120(a0)
	ld	s4, 128(a0)
	ld	s5, 136(a0)
	sd	s8, 160(a0)
	sd	s9, 168(a0)
	sd	s10, 176(a0)
	sd	s11, 184(a0)
	sd	s0, 192(a0)
	# IOTA (round constant)
	ld	s0, 16(sp)
	ld	s11, 0(t0)
	addi	t0, t0, 8
	addi	s0, s0, -1
	xor	t1, t1, s11
	bnez	s0, L_riscv_64_block_sha3_loop
	sd	t1, 0(a0)
	sd	t2, 8(a0)
	sd	t3, 16(a0)
	sd	t4, 24(a0)
	sd	t5, 32(a0)
	sd	t6, 40(a0)
	sd	a1, 48(a0)
	sd	a2, 56(a0)
	sd	a3, 64(a0)
	sd	a4, 72(a0)
	sd	a5, 80(a0)
	sd	a6, 88(a0)
	sd	a7, 96(a0)
	sd	s1, 104(a0)
	sd	s2, 112(a0)
	sd	s3, 120(a0)
	sd	s4, 128(a0)
	sd	s5, 136(a0)
	sd	s6, 144(a0)
	sd	s7, 152(a0)
	ld	s0, 32(sp)
	ld	s1, 40(sp)
	ld	s2, 48(sp)
	ld	s3, 56(sp)
	ld	s4, 64(sp)
	ld	s5, 72(sp)
	ld	s6, 80(sp)
	ld	s7, 88(sp)
	ld	s8, 96(sp)
	ld	s9, 104(sp)
	ld	s10, 112(sp)
	ld	s11, 120(sp)
	addi	sp, sp, 128
	ret
	.size	BlockSha3,.-BlockSha3
#endif /* WOLFSSL_RISCV_VECTOR */
#endif /* WOLFSSL_SHA3 */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_RISCV_ASM_INLINE */
#endif /* WOLFSSL_RISCV_ASM */
