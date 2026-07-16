/* riscv-64-chacha-asm
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
 *   ruby ./chacha/chacha.rb riscv64 \
 *       ../wolfssl/wolfcrypt/src/port/riscv64/riscv-64-chacha-asm.S
 */
#ifdef WOLFSSL_RISCV_ASM
#ifndef WOLFSSL_RISCV_ASM_INLINE
#ifdef HAVE_CHACHA
	.text
	.globl	wc_chacha_setiv
	.type	wc_chacha_setiv,@function
	.align	2
wc_chacha_setiv:
	# Set counter and 96-bit nonce: X[12]=counter, X[13..15]=iv
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lw	t0, 0(a1)
#else
	andi	t3, a1, 3
	bnez	t3, L_ualn_lw1_h
	lw	t0, 0(a1)
	j	L_ualn_lw1_e
L_ualn_lw1_h:
	andi	t3, t3, 1
	bnez	t3, L_ualn_lw1_b
	lhu	t0, 0(a1)
	lhu	t3, 2(a1)
	slli	t3, t3, 16
	or	t0, t0, t3
	addiw	t0, t0, 0
	j	L_ualn_lw1_e
L_ualn_lw1_b:
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
	addiw	t0, t0, 0
L_ualn_lw1_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lw	t1, 4(a1)
#else
	andi	t3, a1, 3
	bnez	t3, L_ualn_lw2_h
	lw	t1, 4(a1)
	j	L_ualn_lw2_e
L_ualn_lw2_h:
	andi	t3, t3, 1
	bnez	t3, L_ualn_lw2_b
	lhu	t1, 4(a1)
	lhu	t3, 6(a1)
	slli	t3, t3, 16
	or	t1, t1, t3
	addiw	t1, t1, 0
	j	L_ualn_lw2_e
L_ualn_lw2_b:
	lbu	t1, 4(a1)
	lbu	t3, 5(a1)
	slli	t3, t3, 8
	or	t1, t1, t3
	lbu	t3, 6(a1)
	slli	t3, t3, 16
	or	t1, t1, t3
	lbu	t3, 7(a1)
	slli	t3, t3, 24
	or	t1, t1, t3
	addiw	t1, t1, 0
L_ualn_lw2_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lw	t2, 8(a1)
#else
	andi	t3, a1, 3
	bnez	t3, L_ualn_lw3_h
	lw	t2, 8(a1)
	j	L_ualn_lw3_e
L_ualn_lw3_h:
	andi	t3, t3, 1
	bnez	t3, L_ualn_lw3_b
	lhu	t2, 8(a1)
	lhu	t3, 10(a1)
	slli	t3, t3, 16
	or	t2, t2, t3
	addiw	t2, t2, 0
	j	L_ualn_lw3_e
L_ualn_lw3_b:
	lbu	t2, 8(a1)
	lbu	t3, 9(a1)
	slli	t3, t3, 8
	or	t2, t2, t3
	lbu	t3, 10(a1)
	slli	t3, t3, 16
	or	t2, t2, t3
	lbu	t3, 11(a1)
	slli	t3, t3, 24
	or	t2, t2, t3
	addiw	t2, t2, 0
L_ualn_lw3_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	sw	a2, 48(a0)
	sw	t0, 52(a0)
	sw	t1, 56(a0)
	sw	t2, 60(a0)
	ret
	.size	wc_chacha_setiv,.-wc_chacha_setiv
	.section	.rodata
	.type	L_chacha20_riscv64_setkey_constants, %object
	.size	L_chacha20_riscv64_setkey_constants, 32
	# 4-byte aligned, 32-bit aligned
	.align	2
L_chacha20_riscv64_setkey_constants:
	.long	0x61707865,0x3120646e,0x79622d36,0x6b206574
	.long	0x61707865,0x3320646e,0x79622d32,0x6b206574
	.text
	.globl	wc_chacha_setkey
	.type	wc_chacha_setkey,@function
	.align	2
wc_chacha_setkey:
	la	t0, L_chacha20_riscv64_setkey_constants
	# keySz 16 -> tau (offset 0); keySz 32 -> sigma (offset 16)
	addi	a2, a2, -16
	add	t0, t0, a2
	# X[0..3] = constants
	lw	t1, 0(t0)
	sw	t1, 0(a0)
	lw	t1, 4(t0)
	sw	t1, 4(a0)
	lw	t1, 8(t0)
	sw	t1, 8(a0)
	lw	t1, 12(t0)
	sw	t1, 12(a0)
	# X[4..7] = key[0..15]
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lw	t1, 0(a1)
#else
	andi	t2, a1, 3
	bnez	t2, L_ualn_lw4_h
	lw	t1, 0(a1)
	j	L_ualn_lw4_e
L_ualn_lw4_h:
	andi	t2, t2, 1
	bnez	t2, L_ualn_lw4_b
	lhu	t1, 0(a1)
	lhu	t2, 2(a1)
	slli	t2, t2, 16
	or	t1, t1, t2
	addiw	t1, t1, 0
	j	L_ualn_lw4_e
L_ualn_lw4_b:
	lbu	t1, 0(a1)
	lbu	t2, 1(a1)
	slli	t2, t2, 8
	or	t1, t1, t2
	lbu	t2, 2(a1)
	slli	t2, t2, 16
	or	t1, t1, t2
	lbu	t2, 3(a1)
	slli	t2, t2, 24
	or	t1, t1, t2
	addiw	t1, t1, 0
L_ualn_lw4_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	sw	t1, 16(a0)
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lw	t1, 4(a1)
#else
	andi	t2, a1, 3
	bnez	t2, L_ualn_lw5_h
	lw	t1, 4(a1)
	j	L_ualn_lw5_e
L_ualn_lw5_h:
	andi	t2, t2, 1
	bnez	t2, L_ualn_lw5_b
	lhu	t1, 4(a1)
	lhu	t2, 6(a1)
	slli	t2, t2, 16
	or	t1, t1, t2
	addiw	t1, t1, 0
	j	L_ualn_lw5_e
L_ualn_lw5_b:
	lbu	t1, 4(a1)
	lbu	t2, 5(a1)
	slli	t2, t2, 8
	or	t1, t1, t2
	lbu	t2, 6(a1)
	slli	t2, t2, 16
	or	t1, t1, t2
	lbu	t2, 7(a1)
	slli	t2, t2, 24
	or	t1, t1, t2
	addiw	t1, t1, 0
L_ualn_lw5_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	sw	t1, 20(a0)
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lw	t1, 8(a1)
#else
	andi	t2, a1, 3
	bnez	t2, L_ualn_lw6_h
	lw	t1, 8(a1)
	j	L_ualn_lw6_e
L_ualn_lw6_h:
	andi	t2, t2, 1
	bnez	t2, L_ualn_lw6_b
	lhu	t1, 8(a1)
	lhu	t2, 10(a1)
	slli	t2, t2, 16
	or	t1, t1, t2
	addiw	t1, t1, 0
	j	L_ualn_lw6_e
L_ualn_lw6_b:
	lbu	t1, 8(a1)
	lbu	t2, 9(a1)
	slli	t2, t2, 8
	or	t1, t1, t2
	lbu	t2, 10(a1)
	slli	t2, t2, 16
	or	t1, t1, t2
	lbu	t2, 11(a1)
	slli	t2, t2, 24
	or	t1, t1, t2
	addiw	t1, t1, 0
L_ualn_lw6_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	sw	t1, 24(a0)
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lw	t1, 12(a1)
#else
	andi	t2, a1, 3
	bnez	t2, L_ualn_lw7_h
	lw	t1, 12(a1)
	j	L_ualn_lw7_e
L_ualn_lw7_h:
	andi	t2, t2, 1
	bnez	t2, L_ualn_lw7_b
	lhu	t1, 12(a1)
	lhu	t2, 14(a1)
	slli	t2, t2, 16
	or	t1, t1, t2
	addiw	t1, t1, 0
	j	L_ualn_lw7_e
L_ualn_lw7_b:
	lbu	t1, 12(a1)
	lbu	t2, 13(a1)
	slli	t2, t2, 8
	or	t1, t1, t2
	lbu	t2, 14(a1)
	slli	t2, t2, 16
	or	t1, t1, t2
	lbu	t2, 15(a1)
	slli	t2, t2, 24
	or	t1, t1, t2
	addiw	t1, t1, 0
L_ualn_lw7_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	sw	t1, 28(a0)
	# X[8..11] = key[0..15] (16-byte) or key[16..31] (32-byte)
	add	a1, a1, a2
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lw	t1, 0(a1)
#else
	andi	t2, a1, 3
	bnez	t2, L_ualn_lw8_h
	lw	t1, 0(a1)
	j	L_ualn_lw8_e
L_ualn_lw8_h:
	andi	t2, t2, 1
	bnez	t2, L_ualn_lw8_b
	lhu	t1, 0(a1)
	lhu	t2, 2(a1)
	slli	t2, t2, 16
	or	t1, t1, t2
	addiw	t1, t1, 0
	j	L_ualn_lw8_e
L_ualn_lw8_b:
	lbu	t1, 0(a1)
	lbu	t2, 1(a1)
	slli	t2, t2, 8
	or	t1, t1, t2
	lbu	t2, 2(a1)
	slli	t2, t2, 16
	or	t1, t1, t2
	lbu	t2, 3(a1)
	slli	t2, t2, 24
	or	t1, t1, t2
	addiw	t1, t1, 0
L_ualn_lw8_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	sw	t1, 32(a0)
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lw	t1, 4(a1)
#else
	andi	t2, a1, 3
	bnez	t2, L_ualn_lw9_h
	lw	t1, 4(a1)
	j	L_ualn_lw9_e
L_ualn_lw9_h:
	andi	t2, t2, 1
	bnez	t2, L_ualn_lw9_b
	lhu	t1, 4(a1)
	lhu	t2, 6(a1)
	slli	t2, t2, 16
	or	t1, t1, t2
	addiw	t1, t1, 0
	j	L_ualn_lw9_e
L_ualn_lw9_b:
	lbu	t1, 4(a1)
	lbu	t2, 5(a1)
	slli	t2, t2, 8
	or	t1, t1, t2
	lbu	t2, 6(a1)
	slli	t2, t2, 16
	or	t1, t1, t2
	lbu	t2, 7(a1)
	slli	t2, t2, 24
	or	t1, t1, t2
	addiw	t1, t1, 0
L_ualn_lw9_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	sw	t1, 36(a0)
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lw	t1, 8(a1)
#else
	andi	t2, a1, 3
	bnez	t2, L_ualn_lw10_h
	lw	t1, 8(a1)
	j	L_ualn_lw10_e
L_ualn_lw10_h:
	andi	t2, t2, 1
	bnez	t2, L_ualn_lw10_b
	lhu	t1, 8(a1)
	lhu	t2, 10(a1)
	slli	t2, t2, 16
	or	t1, t1, t2
	addiw	t1, t1, 0
	j	L_ualn_lw10_e
L_ualn_lw10_b:
	lbu	t1, 8(a1)
	lbu	t2, 9(a1)
	slli	t2, t2, 8
	or	t1, t1, t2
	lbu	t2, 10(a1)
	slli	t2, t2, 16
	or	t1, t1, t2
	lbu	t2, 11(a1)
	slli	t2, t2, 24
	or	t1, t1, t2
	addiw	t1, t1, 0
L_ualn_lw10_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	sw	t1, 40(a0)
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lw	t1, 12(a1)
#else
	andi	t2, a1, 3
	bnez	t2, L_ualn_lw11_h
	lw	t1, 12(a1)
	j	L_ualn_lw11_e
L_ualn_lw11_h:
	andi	t2, t2, 1
	bnez	t2, L_ualn_lw11_b
	lhu	t1, 12(a1)
	lhu	t2, 14(a1)
	slli	t2, t2, 16
	or	t1, t1, t2
	addiw	t1, t1, 0
	j	L_ualn_lw11_e
L_ualn_lw11_b:
	lbu	t1, 12(a1)
	lbu	t2, 13(a1)
	slli	t2, t2, 8
	or	t1, t1, t2
	lbu	t2, 14(a1)
	slli	t2, t2, 16
	or	t1, t1, t2
	lbu	t2, 15(a1)
	slli	t2, t2, 24
	or	t1, t1, t2
	addiw	t1, t1, 0
L_ualn_lw11_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	sw	t1, 44(a0)
	ret
	.size	wc_chacha_setkey,.-wc_chacha_setkey
	.text
	.globl	wc_chacha_use_over
	.type	wc_chacha_use_over,@function
	.align	2
wc_chacha_use_over:
L_chacha20_riscv64_use_over_loop_8:
	li	t2, 8
	bltu	a3, t2, L_chacha20_riscv64_use_over_lt_4
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	t0, 0(a2)
#else
	andi	t3, a2, 7
	bnez	t3, L_ualn_ld12_w
	ld	t0, 0(a2)
	j	L_ualn_ld12_e
L_ualn_ld12_w:
	andi	t3, t3, 3
	bnez	t3, L_ualn_ld12_h
	lwu	t0, 0(a2)
	lwu	t3, 4(a2)
	slli	t3, t3, 32
	or	t0, t0, t3
	j	L_ualn_ld12_e
L_ualn_ld12_h:
	andi	t3, t3, 1
	bnez	t3, L_ualn_ld12_b
	lhu	t0, 0(a2)
	lhu	t3, 2(a2)
	slli	t3, t3, 16
	or	t0, t0, t3
	lhu	t3, 4(a2)
	slli	t3, t3, 32
	or	t0, t0, t3
	lhu	t3, 6(a2)
	slli	t3, t3, 48
	or	t0, t0, t3
	j	L_ualn_ld12_e
L_ualn_ld12_b:
	lbu	t0, 0(a2)
	lbu	t3, 1(a2)
	slli	t3, t3, 8
	or	t0, t0, t3
	lbu	t3, 2(a2)
	slli	t3, t3, 16
	or	t0, t0, t3
	lbu	t3, 3(a2)
	slli	t3, t3, 24
	or	t0, t0, t3
	lbu	t3, 4(a2)
	slli	t3, t3, 32
	or	t0, t0, t3
	lbu	t3, 5(a2)
	slli	t3, t3, 40
	or	t0, t0, t3
	lbu	t3, 6(a2)
	slli	t3, t3, 48
	or	t0, t0, t3
	lbu	t3, 7(a2)
	slli	t3, t3, 56
	or	t0, t0, t3
L_ualn_ld12_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	ld	t1, 0(a0)
	xor	t0, t0, t1
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sd	t0, 0(a1)
#else
	andi	t3, a1, 7
	bnez	t3, L_ualn_sd13_w
	sd	t0, 0(a1)
	j	L_ualn_sd13_e
L_ualn_sd13_w:
	andi	t3, t3, 3
	bnez	t3, L_ualn_sd13_h
	sw	t0, 0(a1)
	srli	t3, t0, 32
	sw	t3, 4(a1)
	j	L_ualn_sd13_e
L_ualn_sd13_h:
	andi	t3, t3, 1
	bnez	t3, L_ualn_sd13_b
	sh	t0, 0(a1)
	srli	t3, t0, 16
	sh	t3, 2(a1)
	srli	t3, t0, 32
	sh	t3, 4(a1)
	srli	t3, t0, 48
	sh	t3, 6(a1)
	j	L_ualn_sd13_e
L_ualn_sd13_b:
	sb	t0, 0(a1)
	srli	t3, t0, 8
	sb	t3, 1(a1)
	srli	t3, t0, 16
	sb	t3, 2(a1)
	srli	t3, t0, 24
	sb	t3, 3(a1)
	srli	t3, t0, 32
	sb	t3, 4(a1)
	srli	t3, t0, 40
	sb	t3, 5(a1)
	srli	t3, t0, 48
	sb	t3, 6(a1)
	srli	t3, t0, 56
	sb	t3, 7(a1)
L_ualn_sd13_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	addi	a2, a2, 8
	addi	a0, a0, 8
	addi	a1, a1, 8
	addi	a3, a3, -8
	j	L_chacha20_riscv64_use_over_loop_8
L_chacha20_riscv64_use_over_lt_4:
	li	t2, 4
	bltu	a3, t2, L_chacha20_riscv64_use_over_lt_2
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lw	t0, 0(a2)
#else
	andi	t3, a2, 3
	bnez	t3, L_ualn_lw14_h
	lw	t0, 0(a2)
	j	L_ualn_lw14_e
L_ualn_lw14_h:
	andi	t3, t3, 1
	bnez	t3, L_ualn_lw14_b
	lhu	t0, 0(a2)
	lhu	t3, 2(a2)
	slli	t3, t3, 16
	or	t0, t0, t3
	addiw	t0, t0, 0
	j	L_ualn_lw14_e
L_ualn_lw14_b:
	lbu	t0, 0(a2)
	lbu	t3, 1(a2)
	slli	t3, t3, 8
	or	t0, t0, t3
	lbu	t3, 2(a2)
	slli	t3, t3, 16
	or	t0, t0, t3
	lbu	t3, 3(a2)
	slli	t3, t3, 24
	or	t0, t0, t3
	addiw	t0, t0, 0
L_ualn_lw14_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	lw	t1, 0(a0)
	xor	t0, t0, t1
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sw	t0, 0(a1)
#else
	andi	t3, a1, 3
	bnez	t3, L_ualn_sw15_h
	sw	t0, 0(a1)
	j	L_ualn_sw15_e
L_ualn_sw15_h:
	andi	t3, t3, 1
	bnez	t3, L_ualn_sw15_b
	sh	t0, 0(a1)
	srli	t3, t0, 16
	sh	t3, 2(a1)
	j	L_ualn_sw15_e
L_ualn_sw15_b:
	sb	t0, 0(a1)
	srli	t3, t0, 8
	sb	t3, 1(a1)
	srli	t3, t0, 16
	sb	t3, 2(a1)
	srli	t3, t0, 24
	sb	t3, 3(a1)
L_ualn_sw15_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	addi	a2, a2, 4
	addi	a0, a0, 4
	addi	a1, a1, 4
	addi	a3, a3, -4
L_chacha20_riscv64_use_over_lt_2:
	li	t2, 2
	bltu	a3, t2, L_chacha20_riscv64_use_over_lt_1
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lh	t0, 0(a2)
#else
	lbu	t0, 0(a2)
	lb	t3, 1(a2)
	slli	t3, t3, 8
	or	t0, t0, t3
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	lh	t1, 0(a0)
	xor	t0, t0, t1
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sh	t0, 0(a1)
#else
	sb	t0, 0(a1)
	srli	t3, t0, 8
	sb	t3, 1(a1)
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	addi	a2, a2, 2
	addi	a0, a0, 2
	addi	a1, a1, 2
	addi	a3, a3, -2
L_chacha20_riscv64_use_over_lt_1:
	beqz	a3, L_chacha20_riscv64_use_over_done
	lb	t0, 0(a2)
	lb	t1, 0(a0)
	xor	t0, t0, t1
	sb	t0, 0(a1)
L_chacha20_riscv64_use_over_done:
	ret
	.size	wc_chacha_use_over,.-wc_chacha_use_over
#ifdef WOLFSSL_RISCV_VECTOR
	.text
	.globl	wc_chacha_crypt_bytes
	.type	wc_chacha_crypt_bytes,@function
	.align	2
wc_chacha_crypt_bytes:
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
	.option arch, +v
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	.option arch, +zvkb
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
#ifdef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
	.option arch, +zbb
#endif /* WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
	# VLEN == 128: 4 x 32-bit elements per vector register
	vsetivli	zero, 4, e32, m1, ta, ma
	# Ensure 64-bit length has top bits clear
	slli	a3, a3, 32
	srli	a3, a3, 32
	# ctx->left = (CHACHA_CHUNK_BYTES - (len & 63)) & 63
	andi	s6, a3, 63
	li	s7, 64
	sub	s6, s7, s6
	andi	s6, s6, 63
	sw	s6, 64(a0)
	# Six-block (384-byte) tier, looped
	li	s7, 384
	bltu	a3, s7, L_chacha20_riscv64_vec_after_384
	# Load state; build lane-rotate indices v25/v26/v27
	mv	s8, a0
	vl4re32.v	v28, (s8)
	vid.v	v20
	vslidedown.vi	v25, v20, 1
	vslideup.vi	v25, v20, 3
	vslidedown.vi	v26, v20, 2
	vslideup.vi	v26, v20, 2
	vslidedown.vi	v27, v20, 3
	vslideup.vi	v27, v20, 1
	# n384 = len / 384; len -= n384 * 384; ctx->X[12] += n384 * 6
	li	s6, 384
	divu	s11, a3, s6
	mul	s7, s11, s6
	sub	a3, a3, s7
	slli	s7, s11, 1
	add	s7, s7, s11
	slli	s7, s7, 1
	lw	s6, 48(a0)
	add	s6, s6, s7
	sw	s6, 48(a0)
L_chacha20_riscv64_vec_384_outer:
	# Scalar state (X[12] from running counter v31)
	ld	t0, 0(a0)
	ld	t2, 8(a0)
	ld	t4, 16(a0)
	ld	t6, 24(a0)
	ld	a5, 32(a0)
	ld	a7, 40(a0)
	lw	s3, 52(a0)
	ld	s4, 56(a0)
	srli	t1, t0, 32
	srli	t3, t2, 32
	srli	t5, t4, 32
	srli	a4, t6, 32
	srli	a6, a5, 32
	srli	s1, a7, 32
	srli	s5, s4, 32
	vmv.x.s	s2, v31
	# Vector blocks = state; counters base+1 .. base+4; scalar base+5
	vmv4r.v	v0, v28
	vmv4r.v	v4, v28
	vmv4r.v	v8, v28
	vmv4r.v	v12, v28
	vmv4r.v	v16, v28
	addi	s7, s2, 1
	vmv.s.x	v7, s7
	addi	s7, s2, 2
	vmv.s.x	v11, s7
	addi	s7, s2, 3
	vmv.s.x	v15, s7
	addi	s7, s2, 4
	vmv.s.x	v19, s7
	addi	s2, s2, 5
	li	s10, 10
L_chacha20_riscv64_vec_384_loop:
	vadd.vv	v0, v0, v1
	vadd.vv	v4, v4, v5
	vadd.vv	v8, v8, v9
	vadd.vv	v12, v12, v13
	vadd.vv	v16, v16, v17
	add	t0, t0, t4
	add	t1, t1, t5
	add	t2, t2, t6
	add	t3, t3, a4
	vxor.vv	v3, v3, v0
	vxor.vv	v7, v7, v4
	vxor.vv	v11, v11, v8
	vxor.vv	v15, v15, v12
	vxor.vv	v19, v19, v16
	xor	s2, s2, t0
	xor	s3, s3, t1
	xor	s4, s4, t2
	xor	s5, s5, t3
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
	vror.vi	v7, v7, 16
	vror.vi	v11, v11, 16
	vror.vi	v15, v15, 16
	vror.vi	v19, v19, 16
#ifdef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
	# roriw s2, s2, 16
	.word	0x6109591b
	# roriw s3, s3, 16
	.word	0x6109d99b
	# roriw s4, s4, 16
	.word	0x610a5a1b
	# roriw s5, s5, 16
	.word	0x610ada9b
#else
	slli	s6, s2, 16
	slli	s7, s3, 16
	slli	s8, s4, 16
	slli	s9, s5, 16
	srliw	s2, s2, 16
	srliw	s3, s3, 16
	srliw	s4, s4, 16
	srliw	s5, s5, 16
	or	s2, s2, s6
	or	s3, s3, s7
	or	s4, s4, s8
	or	s5, s5, s9
#endif /* WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
#else
	vsll.vi	v20, v3, 16
	vsll.vi	v21, v7, 16
	vsll.vi	v22, v11, 16
	vsll.vi	v23, v15, 16
	vsll.vi	v24, v19, 16
	vsrl.vi	v3, v3, 16
	vsrl.vi	v7, v7, 16
	vsrl.vi	v11, v11, 16
	vsrl.vi	v15, v15, 16
	vsrl.vi	v19, v19, 16
	vor.vv	v3, v3, v20
	vor.vv	v7, v7, v21
	vor.vv	v11, v11, v22
	vor.vv	v15, v15, v23
	vor.vv	v19, v19, v24
	slli	s6, s2, 16
	slli	s7, s3, 16
	slli	s8, s4, 16
	slli	s9, s5, 16
	srliw	s2, s2, 16
	srliw	s3, s3, 16
	srliw	s4, s4, 16
	srliw	s5, s5, 16
	or	s2, s2, s6
	or	s3, s3, s7
	or	s4, s4, s8
	or	s5, s5, s9
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vadd.vv	v6, v6, v7
	vadd.vv	v10, v10, v11
	vadd.vv	v14, v14, v15
	vadd.vv	v18, v18, v19
	add	a5, a5, s2
	add	a6, a6, s3
	add	a7, a7, s4
	add	s1, s1, s5
	vxor.vv	v1, v1, v2
	vxor.vv	v5, v5, v6
	vxor.vv	v9, v9, v10
	vxor.vv	v13, v13, v14
	vxor.vv	v17, v17, v18
	xor	t4, t4, a5
	xor	t5, t5, a6
	xor	t6, t6, a7
	xor	a4, a4, s1
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
	vror.vi	v5, v5, 20
	vror.vi	v9, v9, 20
	vror.vi	v13, v13, 20
	vror.vi	v17, v17, 20
#ifdef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
	# roriw t4, t4, 20
	.word	0x614ede9b
	# roriw t5, t5, 20
	.word	0x614f5f1b
	# roriw t6, t6, 20
	.word	0x614fdf9b
	# roriw a4, a4, 20
	.word	0x6147571b
#else
	slli	s6, t4, 12
	slli	s7, t5, 12
	slli	s8, t6, 12
	slli	s9, a4, 12
	srliw	t4, t4, 20
	srliw	t5, t5, 20
	srliw	t6, t6, 20
	srliw	a4, a4, 20
	or	t4, t4, s6
	or	t5, t5, s7
	or	t6, t6, s8
	or	a4, a4, s9
#endif /* WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
#else
	vsll.vi	v20, v1, 12
	vsll.vi	v21, v5, 12
	vsll.vi	v22, v9, 12
	vsll.vi	v23, v13, 12
	vsll.vi	v24, v17, 12
	vsrl.vi	v1, v1, 20
	vsrl.vi	v5, v5, 20
	vsrl.vi	v9, v9, 20
	vsrl.vi	v13, v13, 20
	vsrl.vi	v17, v17, 20
	vor.vv	v1, v1, v20
	vor.vv	v5, v5, v21
	vor.vv	v9, v9, v22
	vor.vv	v13, v13, v23
	vor.vv	v17, v17, v24
	slli	s6, t4, 12
	slli	s7, t5, 12
	slli	s8, t6, 12
	slli	s9, a4, 12
	srliw	t4, t4, 20
	srliw	t5, t5, 20
	srliw	t6, t6, 20
	srliw	a4, a4, 20
	or	t4, t4, s6
	or	t5, t5, s7
	or	t6, t6, s8
	or	a4, a4, s9
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vadd.vv	v4, v4, v5
	vadd.vv	v8, v8, v9
	vadd.vv	v12, v12, v13
	vadd.vv	v16, v16, v17
	add	t0, t0, t4
	add	t1, t1, t5
	add	t2, t2, t6
	add	t3, t3, a4
	vxor.vv	v3, v3, v0
	vxor.vv	v7, v7, v4
	vxor.vv	v11, v11, v8
	vxor.vv	v15, v15, v12
	vxor.vv	v19, v19, v16
	xor	s2, s2, t0
	xor	s3, s3, t1
	xor	s4, s4, t2
	xor	s5, s5, t3
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
	vror.vi	v7, v7, 24
	vror.vi	v11, v11, 24
	vror.vi	v15, v15, 24
	vror.vi	v19, v19, 24
#ifdef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
	# roriw s2, s2, 24
	.word	0x6189591b
	# roriw s3, s3, 24
	.word	0x6189d99b
	# roriw s4, s4, 24
	.word	0x618a5a1b
	# roriw s5, s5, 24
	.word	0x618ada9b
#else
	slli	s6, s2, 8
	slli	s7, s3, 8
	slli	s8, s4, 8
	slli	s9, s5, 8
	srliw	s2, s2, 24
	srliw	s3, s3, 24
	srliw	s4, s4, 24
	srliw	s5, s5, 24
	or	s2, s2, s6
	or	s3, s3, s7
	or	s4, s4, s8
	or	s5, s5, s9
#endif /* WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
#else
	vsll.vi	v20, v3, 8
	vsll.vi	v21, v7, 8
	vsll.vi	v22, v11, 8
	vsll.vi	v23, v15, 8
	vsll.vi	v24, v19, 8
	vsrl.vi	v3, v3, 24
	vsrl.vi	v7, v7, 24
	vsrl.vi	v11, v11, 24
	vsrl.vi	v15, v15, 24
	vsrl.vi	v19, v19, 24
	vor.vv	v3, v3, v20
	vor.vv	v7, v7, v21
	vor.vv	v11, v11, v22
	vor.vv	v15, v15, v23
	vor.vv	v19, v19, v24
	slli	s6, s2, 8
	slli	s7, s3, 8
	slli	s8, s4, 8
	slli	s9, s5, 8
	srliw	s2, s2, 24
	srliw	s3, s3, 24
	srliw	s4, s4, 24
	srliw	s5, s5, 24
	or	s2, s2, s6
	or	s3, s3, s7
	or	s4, s4, s8
	or	s5, s5, s9
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vadd.vv	v6, v6, v7
	vadd.vv	v10, v10, v11
	vadd.vv	v14, v14, v15
	vadd.vv	v18, v18, v19
	add	a5, a5, s2
	add	a6, a6, s3
	add	a7, a7, s4
	add	s1, s1, s5
	vxor.vv	v1, v1, v2
	vxor.vv	v5, v5, v6
	vxor.vv	v9, v9, v10
	vxor.vv	v13, v13, v14
	vxor.vv	v17, v17, v18
	xor	t4, t4, a5
	xor	t5, t5, a6
	xor	t6, t6, a7
	xor	a4, a4, s1
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
	vror.vi	v5, v5, 25
	vror.vi	v9, v9, 25
	vror.vi	v13, v13, 25
	vror.vi	v17, v17, 25
#ifdef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
	# roriw t4, t4, 25
	.word	0x619ede9b
	# roriw t5, t5, 25
	.word	0x619f5f1b
	# roriw t6, t6, 25
	.word	0x619fdf9b
	# roriw a4, a4, 25
	.word	0x6197571b
#else
	slli	s6, t4, 7
	slli	s7, t5, 7
	slli	s8, t6, 7
	slli	s9, a4, 7
	srliw	t4, t4, 25
	srliw	t5, t5, 25
	srliw	t6, t6, 25
	srliw	a4, a4, 25
	or	t4, t4, s6
	or	t5, t5, s7
	or	t6, t6, s8
	or	a4, a4, s9
#endif /* WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
#else
	vsll.vi	v20, v1, 7
	vsll.vi	v21, v5, 7
	vsll.vi	v22, v9, 7
	vsll.vi	v23, v13, 7
	vsll.vi	v24, v17, 7
	vsrl.vi	v1, v1, 25
	vsrl.vi	v5, v5, 25
	vsrl.vi	v9, v9, 25
	vsrl.vi	v13, v13, 25
	vsrl.vi	v17, v17, 25
	vor.vv	v1, v1, v20
	vor.vv	v5, v5, v21
	vor.vv	v9, v9, v22
	vor.vv	v13, v13, v23
	vor.vv	v17, v17, v24
	slli	s6, t4, 7
	slli	s7, t5, 7
	slli	s8, t6, 7
	slli	s9, a4, 7
	srliw	t4, t4, 25
	srliw	t5, t5, 25
	srliw	t6, t6, 25
	srliw	a4, a4, 25
	or	t4, t4, s6
	or	t5, t5, s7
	or	t6, t6, s8
	or	a4, a4, s9
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vrgather.vv	v20, v3, v27
	vrgather.vv	v21, v7, v27
	vrgather.vv	v22, v11, v27
	vrgather.vv	v23, v15, v27
	vrgather.vv	v24, v19, v27
	vmv.v.v	v3, v20
	vmv.v.v	v7, v21
	vmv.v.v	v11, v22
	vmv.v.v	v15, v23
	vmv.v.v	v19, v24
	vrgather.vv	v20, v1, v25
	vrgather.vv	v21, v5, v25
	vrgather.vv	v22, v9, v25
	vrgather.vv	v23, v13, v25
	vrgather.vv	v24, v17, v25
	vmv.v.v	v1, v20
	vmv.v.v	v5, v21
	vmv.v.v	v9, v22
	vmv.v.v	v13, v23
	vmv.v.v	v17, v24
	vrgather.vv	v20, v2, v26
	vrgather.vv	v21, v6, v26
	vrgather.vv	v22, v10, v26
	vrgather.vv	v23, v14, v26
	vrgather.vv	v24, v18, v26
	vmv.v.v	v2, v20
	vmv.v.v	v6, v21
	vmv.v.v	v10, v22
	vmv.v.v	v14, v23
	vmv.v.v	v18, v24
	vadd.vv	v0, v0, v1
	vadd.vv	v4, v4, v5
	vadd.vv	v8, v8, v9
	vadd.vv	v12, v12, v13
	vadd.vv	v16, v16, v17
	add	t0, t0, t5
	add	t1, t1, t6
	add	t2, t2, a4
	add	t3, t3, t4
	vxor.vv	v3, v3, v0
	vxor.vv	v7, v7, v4
	vxor.vv	v11, v11, v8
	vxor.vv	v15, v15, v12
	vxor.vv	v19, v19, v16
	xor	s5, s5, t0
	xor	s2, s2, t1
	xor	s3, s3, t2
	xor	s4, s4, t3
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
	vror.vi	v7, v7, 16
	vror.vi	v11, v11, 16
	vror.vi	v15, v15, 16
	vror.vi	v19, v19, 16
#ifdef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
	# roriw s5, s5, 16
	.word	0x610ada9b
	# roriw s2, s2, 16
	.word	0x6109591b
	# roriw s3, s3, 16
	.word	0x6109d99b
	# roriw s4, s4, 16
	.word	0x610a5a1b
#else
	slli	s6, s5, 16
	slli	s7, s2, 16
	slli	s8, s3, 16
	slli	s9, s4, 16
	srliw	s5, s5, 16
	srliw	s2, s2, 16
	srliw	s3, s3, 16
	srliw	s4, s4, 16
	or	s5, s5, s6
	or	s2, s2, s7
	or	s3, s3, s8
	or	s4, s4, s9
#endif /* WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
#else
	vsll.vi	v20, v3, 16
	vsll.vi	v21, v7, 16
	vsll.vi	v22, v11, 16
	vsll.vi	v23, v15, 16
	vsll.vi	v24, v19, 16
	vsrl.vi	v3, v3, 16
	vsrl.vi	v7, v7, 16
	vsrl.vi	v11, v11, 16
	vsrl.vi	v15, v15, 16
	vsrl.vi	v19, v19, 16
	vor.vv	v3, v3, v20
	vor.vv	v7, v7, v21
	vor.vv	v11, v11, v22
	vor.vv	v15, v15, v23
	vor.vv	v19, v19, v24
	slli	s6, s5, 16
	slli	s7, s2, 16
	slli	s8, s3, 16
	slli	s9, s4, 16
	srliw	s5, s5, 16
	srliw	s2, s2, 16
	srliw	s3, s3, 16
	srliw	s4, s4, 16
	or	s5, s5, s6
	or	s2, s2, s7
	or	s3, s3, s8
	or	s4, s4, s9
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vadd.vv	v6, v6, v7
	vadd.vv	v10, v10, v11
	vadd.vv	v14, v14, v15
	vadd.vv	v18, v18, v19
	add	a7, a7, s5
	add	s1, s1, s2
	add	a5, a5, s3
	add	a6, a6, s4
	vxor.vv	v1, v1, v2
	vxor.vv	v5, v5, v6
	vxor.vv	v9, v9, v10
	vxor.vv	v13, v13, v14
	vxor.vv	v17, v17, v18
	xor	t5, t5, a7
	xor	t6, t6, s1
	xor	a4, a4, a5
	xor	t4, t4, a6
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
	vror.vi	v5, v5, 20
	vror.vi	v9, v9, 20
	vror.vi	v13, v13, 20
	vror.vi	v17, v17, 20
#ifdef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
	# roriw t5, t5, 20
	.word	0x614f5f1b
	# roriw t6, t6, 20
	.word	0x614fdf9b
	# roriw a4, a4, 20
	.word	0x6147571b
	# roriw t4, t4, 20
	.word	0x614ede9b
#else
	slli	s6, t5, 12
	slli	s7, t6, 12
	slli	s8, a4, 12
	slli	s9, t4, 12
	srliw	t5, t5, 20
	srliw	t6, t6, 20
	srliw	a4, a4, 20
	srliw	t4, t4, 20
	or	t5, t5, s6
	or	t6, t6, s7
	or	a4, a4, s8
	or	t4, t4, s9
#endif /* WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
#else
	vsll.vi	v20, v1, 12
	vsll.vi	v21, v5, 12
	vsll.vi	v22, v9, 12
	vsll.vi	v23, v13, 12
	vsll.vi	v24, v17, 12
	vsrl.vi	v1, v1, 20
	vsrl.vi	v5, v5, 20
	vsrl.vi	v9, v9, 20
	vsrl.vi	v13, v13, 20
	vsrl.vi	v17, v17, 20
	vor.vv	v1, v1, v20
	vor.vv	v5, v5, v21
	vor.vv	v9, v9, v22
	vor.vv	v13, v13, v23
	vor.vv	v17, v17, v24
	slli	s6, t5, 12
	slli	s7, t6, 12
	slli	s8, a4, 12
	slli	s9, t4, 12
	srliw	t5, t5, 20
	srliw	t6, t6, 20
	srliw	a4, a4, 20
	srliw	t4, t4, 20
	or	t5, t5, s6
	or	t6, t6, s7
	or	a4, a4, s8
	or	t4, t4, s9
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vadd.vv	v4, v4, v5
	vadd.vv	v8, v8, v9
	vadd.vv	v12, v12, v13
	vadd.vv	v16, v16, v17
	add	t0, t0, t5
	add	t1, t1, t6
	add	t2, t2, a4
	add	t3, t3, t4
	vxor.vv	v3, v3, v0
	vxor.vv	v7, v7, v4
	vxor.vv	v11, v11, v8
	vxor.vv	v15, v15, v12
	vxor.vv	v19, v19, v16
	xor	s5, s5, t0
	xor	s2, s2, t1
	xor	s3, s3, t2
	xor	s4, s4, t3
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
	vror.vi	v7, v7, 24
	vror.vi	v11, v11, 24
	vror.vi	v15, v15, 24
	vror.vi	v19, v19, 24
#ifdef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
	# roriw s5, s5, 24
	.word	0x618ada9b
	# roriw s2, s2, 24
	.word	0x6189591b
	# roriw s3, s3, 24
	.word	0x6189d99b
	# roriw s4, s4, 24
	.word	0x618a5a1b
#else
	slli	s6, s5, 8
	slli	s7, s2, 8
	slli	s8, s3, 8
	slli	s9, s4, 8
	srliw	s5, s5, 24
	srliw	s2, s2, 24
	srliw	s3, s3, 24
	srliw	s4, s4, 24
	or	s5, s5, s6
	or	s2, s2, s7
	or	s3, s3, s8
	or	s4, s4, s9
#endif /* WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
#else
	vsll.vi	v20, v3, 8
	vsll.vi	v21, v7, 8
	vsll.vi	v22, v11, 8
	vsll.vi	v23, v15, 8
	vsll.vi	v24, v19, 8
	vsrl.vi	v3, v3, 24
	vsrl.vi	v7, v7, 24
	vsrl.vi	v11, v11, 24
	vsrl.vi	v15, v15, 24
	vsrl.vi	v19, v19, 24
	vor.vv	v3, v3, v20
	vor.vv	v7, v7, v21
	vor.vv	v11, v11, v22
	vor.vv	v15, v15, v23
	vor.vv	v19, v19, v24
	slli	s6, s5, 8
	slli	s7, s2, 8
	slli	s8, s3, 8
	slli	s9, s4, 8
	srliw	s5, s5, 24
	srliw	s2, s2, 24
	srliw	s3, s3, 24
	srliw	s4, s4, 24
	or	s5, s5, s6
	or	s2, s2, s7
	or	s3, s3, s8
	or	s4, s4, s9
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vadd.vv	v6, v6, v7
	vadd.vv	v10, v10, v11
	vadd.vv	v14, v14, v15
	vadd.vv	v18, v18, v19
	add	a7, a7, s5
	add	s1, s1, s2
	add	a5, a5, s3
	add	a6, a6, s4
	vxor.vv	v1, v1, v2
	vxor.vv	v5, v5, v6
	vxor.vv	v9, v9, v10
	vxor.vv	v13, v13, v14
	vxor.vv	v17, v17, v18
	xor	t5, t5, a7
	xor	t6, t6, s1
	xor	a4, a4, a5
	xor	t4, t4, a6
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
	vror.vi	v5, v5, 25
	vror.vi	v9, v9, 25
	vror.vi	v13, v13, 25
	vror.vi	v17, v17, 25
#ifdef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
	# roriw t5, t5, 25
	.word	0x619f5f1b
	# roriw t6, t6, 25
	.word	0x619fdf9b
	# roriw a4, a4, 25
	.word	0x6197571b
	# roriw t4, t4, 25
	.word	0x619ede9b
#else
	slli	s6, t5, 7
	slli	s7, t6, 7
	slli	s8, a4, 7
	slli	s9, t4, 7
	srliw	t5, t5, 25
	srliw	t6, t6, 25
	srliw	a4, a4, 25
	srliw	t4, t4, 25
	or	t5, t5, s6
	or	t6, t6, s7
	or	a4, a4, s8
	or	t4, t4, s9
#endif /* WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
#else
	vsll.vi	v20, v1, 7
	vsll.vi	v21, v5, 7
	vsll.vi	v22, v9, 7
	vsll.vi	v23, v13, 7
	vsll.vi	v24, v17, 7
	vsrl.vi	v1, v1, 25
	vsrl.vi	v5, v5, 25
	vsrl.vi	v9, v9, 25
	vsrl.vi	v13, v13, 25
	vsrl.vi	v17, v17, 25
	vor.vv	v1, v1, v20
	vor.vv	v5, v5, v21
	vor.vv	v9, v9, v22
	vor.vv	v13, v13, v23
	vor.vv	v17, v17, v24
	slli	s6, t5, 7
	slli	s7, t6, 7
	slli	s8, a4, 7
	slli	s9, t4, 7
	srliw	t5, t5, 25
	srliw	t6, t6, 25
	srliw	a4, a4, 25
	srliw	t4, t4, 25
	or	t5, t5, s6
	or	t6, t6, s7
	or	a4, a4, s8
	or	t4, t4, s9
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vrgather.vv	v20, v3, v25
	vrgather.vv	v21, v7, v25
	vrgather.vv	v22, v11, v25
	vrgather.vv	v23, v15, v25
	vrgather.vv	v24, v19, v25
	vmv.v.v	v3, v20
	vmv.v.v	v7, v21
	vmv.v.v	v11, v22
	vmv.v.v	v15, v23
	vmv.v.v	v19, v24
	vrgather.vv	v20, v1, v27
	vrgather.vv	v21, v5, v27
	vrgather.vv	v22, v9, v27
	vrgather.vv	v23, v13, v27
	vrgather.vv	v24, v17, v27
	vmv.v.v	v1, v20
	vmv.v.v	v5, v21
	vmv.v.v	v9, v22
	vmv.v.v	v13, v23
	vmv.v.v	v17, v24
	vrgather.vv	v20, v2, v26
	vrgather.vv	v21, v6, v26
	vrgather.vv	v22, v10, v26
	vrgather.vv	v23, v14, v26
	vrgather.vv	v24, v18, v26
	vmv.v.v	v2, v20
	vmv.v.v	v6, v21
	vmv.v.v	v10, v22
	vmv.v.v	v14, v23
	vmv.v.v	v18, v24
	addi	s10, s10, -1
	bnez	s10, L_chacha20_riscv64_vec_384_loop
	# Block 1: add back, XOR message, store
	mv	s8, a2
	vl4re32.v	v20, (s8)
	addi	a2, a2, 64
	vadd.vv	v0, v0, v28
	vadd.vv	v1, v1, v29
	vadd.vv	v2, v2, v30
	vadd.vv	v3, v3, v31
	vxor.vv	v0, v0, v20
	vxor.vv	v1, v1, v21
	vxor.vv	v2, v2, v22
	vxor.vv	v3, v3, v23
	mv	s8, a1
	vs4r.v	v0, (s8)
	addi	a1, a1, 64
	vmv.x.s	s6, v31
	# Blocks 2-5 (vector)
	addi	s6, s6, 1
	vmv.s.x	v31, s6
	mv	s8, a2
	vl4re32.v	v20, (s8)
	addi	a2, a2, 64
	vadd.vv	v4, v4, v28
	vadd.vv	v5, v5, v29
	vadd.vv	v6, v6, v30
	vadd.vv	v7, v7, v31
	vxor.vv	v4, v4, v20
	vxor.vv	v5, v5, v21
	vxor.vv	v6, v6, v22
	vxor.vv	v7, v7, v23
	mv	s8, a1
	vs4r.v	v4, (s8)
	addi	a1, a1, 64
	addi	s6, s6, 1
	vmv.s.x	v31, s6
	mv	s8, a2
	vl4re32.v	v20, (s8)
	addi	a2, a2, 64
	vadd.vv	v8, v8, v28
	vadd.vv	v9, v9, v29
	vadd.vv	v10, v10, v30
	vadd.vv	v11, v11, v31
	vxor.vv	v8, v8, v20
	vxor.vv	v9, v9, v21
	vxor.vv	v10, v10, v22
	vxor.vv	v11, v11, v23
	mv	s8, a1
	vs4r.v	v8, (s8)
	addi	a1, a1, 64
	addi	s6, s6, 1
	vmv.s.x	v31, s6
	mv	s8, a2
	vl4re32.v	v20, (s8)
	addi	a2, a2, 64
	vadd.vv	v12, v12, v28
	vadd.vv	v13, v13, v29
	vadd.vv	v14, v14, v30
	vadd.vv	v15, v15, v31
	vxor.vv	v12, v12, v20
	vxor.vv	v13, v13, v21
	vxor.vv	v14, v14, v22
	vxor.vv	v15, v15, v23
	mv	s8, a1
	vs4r.v	v12, (s8)
	addi	a1, a1, 64
	addi	s6, s6, 1
	vmv.s.x	v31, s6
	mv	s8, a2
	vl4re32.v	v20, (s8)
	addi	a2, a2, 64
	vadd.vv	v16, v16, v28
	vadd.vv	v17, v17, v29
	vadd.vv	v18, v18, v30
	vadd.vv	v19, v19, v31
	vxor.vv	v16, v16, v20
	vxor.vv	v17, v17, v21
	vxor.vv	v18, v18, v22
	vxor.vv	v19, v19, v23
	mv	s8, a1
	vs4r.v	v16, (s8)
	addi	a1, a1, 64
	# Block 6 (scalar)
	addi	s6, s6, 1
	mv	s8, a2
	vl4re32.v	v20, (s8)
	addi	a2, a2, 64
	vmv.s.x	v0, t0
	vmv.s.x	v1, t4
	vmv.s.x	v2, a5
	vmv.s.x	v3, s2
	vmv.s.x	v4, t1
	vmv.s.x	v5, t5
	vmv.s.x	v6, a6
	vmv.s.x	v7, s3
	vslideup.vi	v0, v4, 1
	vslideup.vi	v1, v5, 1
	vslideup.vi	v2, v6, 1
	vslideup.vi	v3, v7, 1
	vmv.s.x	v4, t2
	vmv.s.x	v5, t6
	vmv.s.x	v6, a7
	vmv.s.x	v7, s4
	vslideup.vi	v0, v4, 2
	vslideup.vi	v1, v5, 2
	vslideup.vi	v2, v6, 2
	vslideup.vi	v3, v7, 2
	vmv.s.x	v4, t3
	vmv.s.x	v5, a4
	vmv.s.x	v6, s1
	vmv.s.x	v7, s5
	vslideup.vi	v0, v4, 3
	vslideup.vi	v1, v5, 3
	vslideup.vi	v2, v6, 3
	vslideup.vi	v3, v7, 3
	vmv.s.x	v31, s6
	vadd.vv	v0, v0, v28
	vadd.vv	v1, v1, v29
	vadd.vv	v2, v2, v30
	vadd.vv	v3, v3, v31
	vxor.vv	v0, v0, v20
	vxor.vv	v1, v1, v21
	vxor.vv	v2, v2, v22
	vxor.vv	v3, v3, v23
	mv	s8, a1
	vs4r.v	v0, (s8)
	addi	a1, a1, 64
	# Advance running counter for next iteration
	addi	s6, s6, 1
	vmv.s.x	v31, s6
	addi	s11, s11, -1
	bnez	s11, L_chacha20_riscv64_vec_384_outer
L_chacha20_riscv64_vec_after_384:
	# Four-block (256-byte) tier
	li	s7, 256
	bltu	a3, s7, L_chacha20_riscv64_vec_after_256
	# Load state to encrypt
	mv	s8, a0
	vl4re32.v	v16, (s8)
	vid.v	v20
	vslidedown.vi	v23, v20, 1
	vslideup.vi	v23, v20, 3
	vslidedown.vi	v24, v20, 2
	vslideup.vi	v24, v20, 2
	vslidedown.vi	v25, v20, 3
	vslideup.vi	v25, v20, 1
	ld	t0, 0(a0)
	ld	t2, 8(a0)
	ld	t4, 16(a0)
	ld	t6, 24(a0)
	ld	a5, 32(a0)
	ld	a7, 40(a0)
	ld	s2, 48(a0)
	ld	s4, 56(a0)
	srli	t1, t0, 32
	srli	t3, t2, 32
	srli	t5, t4, 32
	srli	a4, t6, 32
	srli	a6, a5, 32
	srli	s1, a7, 32
	srli	s3, s2, 32
	srli	s5, s4, 32
	# Block counters: 1=base, 2=base+1, 3=base+2, 4(scalar)=base+3
	vmv4r.v	v0, v16
	addi	s6, s2, 1
	vmv4r.v	v4, v16
	addi	s7, s2, 2
	vmv4r.v	v8, v16
	addi	s2, s2, 3
	vmv.s.x	v7, s6
	vmv.s.x	v11, s7
	li	s10, 10
L_chacha20_riscv64_vec_256_loop:
	vadd.vv	v0, v0, v1
	vadd.vv	v4, v4, v5
	vadd.vv	v8, v8, v9
	add	t0, t0, t4
	add	t1, t1, t5
	add	t2, t2, t6
	add	t3, t3, a4
	vxor.vv	v3, v3, v0
	vxor.vv	v7, v7, v4
	vxor.vv	v11, v11, v8
	xor	s2, s2, t0
	xor	s3, s3, t1
	xor	s4, s4, t2
	xor	s5, s5, t3
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
	vror.vi	v7, v7, 16
	vror.vi	v11, v11, 16
#ifdef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
	# roriw s2, s2, 16
	.word	0x6109591b
	# roriw s3, s3, 16
	.word	0x6109d99b
	# roriw s4, s4, 16
	.word	0x610a5a1b
	# roriw s5, s5, 16
	.word	0x610ada9b
#else
	slli	s6, s2, 16
	slli	s7, s3, 16
	slli	s8, s4, 16
	slli	s9, s5, 16
	srliw	s2, s2, 16
	srliw	s3, s3, 16
	srliw	s4, s4, 16
	srliw	s5, s5, 16
	or	s2, s2, s6
	or	s3, s3, s7
	or	s4, s4, s8
	or	s5, s5, s9
#endif /* WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
#else
	vsll.vi	v20, v3, 16
	vsll.vi	v21, v7, 16
	vsll.vi	v22, v11, 16
	vsrl.vi	v3, v3, 16
	vsrl.vi	v7, v7, 16
	vsrl.vi	v11, v11, 16
	vor.vv	v3, v3, v20
	vor.vv	v7, v7, v21
	vor.vv	v11, v11, v22
	slli	s6, s2, 16
	slli	s7, s3, 16
	slli	s8, s4, 16
	slli	s9, s5, 16
	srliw	s2, s2, 16
	srliw	s3, s3, 16
	srliw	s4, s4, 16
	srliw	s5, s5, 16
	or	s2, s2, s6
	or	s3, s3, s7
	or	s4, s4, s8
	or	s5, s5, s9
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vadd.vv	v6, v6, v7
	vadd.vv	v10, v10, v11
	add	a5, a5, s2
	add	a6, a6, s3
	add	a7, a7, s4
	add	s1, s1, s5
	vxor.vv	v1, v1, v2
	vxor.vv	v5, v5, v6
	vxor.vv	v9, v9, v10
	xor	t4, t4, a5
	xor	t5, t5, a6
	xor	t6, t6, a7
	xor	a4, a4, s1
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
	vror.vi	v5, v5, 20
	vror.vi	v9, v9, 20
#ifdef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
	# roriw t4, t4, 20
	.word	0x614ede9b
	# roriw t5, t5, 20
	.word	0x614f5f1b
	# roriw t6, t6, 20
	.word	0x614fdf9b
	# roriw a4, a4, 20
	.word	0x6147571b
#else
	slli	s6, t4, 12
	slli	s7, t5, 12
	slli	s8, t6, 12
	slli	s9, a4, 12
	srliw	t4, t4, 20
	srliw	t5, t5, 20
	srliw	t6, t6, 20
	srliw	a4, a4, 20
	or	t4, t4, s6
	or	t5, t5, s7
	or	t6, t6, s8
	or	a4, a4, s9
#endif /* WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
#else
	vsll.vi	v20, v1, 12
	vsll.vi	v21, v5, 12
	vsll.vi	v22, v9, 12
	vsrl.vi	v1, v1, 20
	vsrl.vi	v5, v5, 20
	vsrl.vi	v9, v9, 20
	vor.vv	v1, v1, v20
	vor.vv	v5, v5, v21
	vor.vv	v9, v9, v22
	slli	s6, t4, 12
	slli	s7, t5, 12
	slli	s8, t6, 12
	slli	s9, a4, 12
	srliw	t4, t4, 20
	srliw	t5, t5, 20
	srliw	t6, t6, 20
	srliw	a4, a4, 20
	or	t4, t4, s6
	or	t5, t5, s7
	or	t6, t6, s8
	or	a4, a4, s9
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vadd.vv	v4, v4, v5
	vadd.vv	v8, v8, v9
	add	t0, t0, t4
	add	t1, t1, t5
	add	t2, t2, t6
	add	t3, t3, a4
	vxor.vv	v3, v3, v0
	vxor.vv	v7, v7, v4
	vxor.vv	v11, v11, v8
	xor	s2, s2, t0
	xor	s3, s3, t1
	xor	s4, s4, t2
	xor	s5, s5, t3
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
	vror.vi	v7, v7, 24
	vror.vi	v11, v11, 24
#ifdef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
	# roriw s2, s2, 24
	.word	0x6189591b
	# roriw s3, s3, 24
	.word	0x6189d99b
	# roriw s4, s4, 24
	.word	0x618a5a1b
	# roriw s5, s5, 24
	.word	0x618ada9b
#else
	slli	s6, s2, 8
	slli	s7, s3, 8
	slli	s8, s4, 8
	slli	s9, s5, 8
	srliw	s2, s2, 24
	srliw	s3, s3, 24
	srliw	s4, s4, 24
	srliw	s5, s5, 24
	or	s2, s2, s6
	or	s3, s3, s7
	or	s4, s4, s8
	or	s5, s5, s9
#endif /* WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
#else
	vsll.vi	v20, v3, 8
	vsll.vi	v21, v7, 8
	vsll.vi	v22, v11, 8
	vsrl.vi	v3, v3, 24
	vsrl.vi	v7, v7, 24
	vsrl.vi	v11, v11, 24
	vor.vv	v3, v3, v20
	vor.vv	v7, v7, v21
	vor.vv	v11, v11, v22
	slli	s6, s2, 8
	slli	s7, s3, 8
	slli	s8, s4, 8
	slli	s9, s5, 8
	srliw	s2, s2, 24
	srliw	s3, s3, 24
	srliw	s4, s4, 24
	srliw	s5, s5, 24
	or	s2, s2, s6
	or	s3, s3, s7
	or	s4, s4, s8
	or	s5, s5, s9
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vadd.vv	v6, v6, v7
	vadd.vv	v10, v10, v11
	add	a5, a5, s2
	add	a6, a6, s3
	add	a7, a7, s4
	add	s1, s1, s5
	vxor.vv	v1, v1, v2
	vxor.vv	v5, v5, v6
	vxor.vv	v9, v9, v10
	xor	t4, t4, a5
	xor	t5, t5, a6
	xor	t6, t6, a7
	xor	a4, a4, s1
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
	vror.vi	v5, v5, 25
	vror.vi	v9, v9, 25
#ifdef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
	# roriw t4, t4, 25
	.word	0x619ede9b
	# roriw t5, t5, 25
	.word	0x619f5f1b
	# roriw t6, t6, 25
	.word	0x619fdf9b
	# roriw a4, a4, 25
	.word	0x6197571b
#else
	slli	s6, t4, 7
	slli	s7, t5, 7
	slli	s8, t6, 7
	slli	s9, a4, 7
	srliw	t4, t4, 25
	srliw	t5, t5, 25
	srliw	t6, t6, 25
	srliw	a4, a4, 25
	or	t4, t4, s6
	or	t5, t5, s7
	or	t6, t6, s8
	or	a4, a4, s9
#endif /* WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
#else
	vsll.vi	v20, v1, 7
	vsll.vi	v21, v5, 7
	vsll.vi	v22, v9, 7
	vsrl.vi	v1, v1, 25
	vsrl.vi	v5, v5, 25
	vsrl.vi	v9, v9, 25
	vor.vv	v1, v1, v20
	vor.vv	v5, v5, v21
	vor.vv	v9, v9, v22
	slli	s6, t4, 7
	slli	s7, t5, 7
	slli	s8, t6, 7
	slli	s9, a4, 7
	srliw	t4, t4, 25
	srliw	t5, t5, 25
	srliw	t6, t6, 25
	srliw	a4, a4, 25
	or	t4, t4, s6
	or	t5, t5, s7
	or	t6, t6, s8
	or	a4, a4, s9
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vrgather.vv	v20, v3, v25
	vrgather.vv	v21, v7, v25
	vrgather.vv	v22, v11, v25
	vmv.v.v	v3, v20
	vmv.v.v	v7, v21
	vmv.v.v	v11, v22
	vrgather.vv	v20, v1, v23
	vrgather.vv	v21, v5, v23
	vrgather.vv	v22, v9, v23
	vmv.v.v	v1, v20
	vmv.v.v	v5, v21
	vmv.v.v	v9, v22
	vrgather.vv	v20, v2, v24
	vrgather.vv	v21, v6, v24
	vrgather.vv	v22, v10, v24
	vmv.v.v	v2, v20
	vmv.v.v	v6, v21
	vmv.v.v	v10, v22
	addi	s10, s10, -1
	vadd.vv	v0, v0, v1
	vadd.vv	v4, v4, v5
	vadd.vv	v8, v8, v9
	add	t0, t0, t5
	add	t1, t1, t6
	add	t2, t2, a4
	add	t3, t3, t4
	vxor.vv	v3, v3, v0
	vxor.vv	v7, v7, v4
	vxor.vv	v11, v11, v8
	xor	s5, s5, t0
	xor	s2, s2, t1
	xor	s3, s3, t2
	xor	s4, s4, t3
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
	vror.vi	v7, v7, 16
	vror.vi	v11, v11, 16
#ifdef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
	# roriw s5, s5, 16
	.word	0x610ada9b
	# roriw s2, s2, 16
	.word	0x6109591b
	# roriw s3, s3, 16
	.word	0x6109d99b
	# roriw s4, s4, 16
	.word	0x610a5a1b
#else
	slli	s6, s5, 16
	slli	s7, s2, 16
	slli	s8, s3, 16
	slli	s9, s4, 16
	srliw	s5, s5, 16
	srliw	s2, s2, 16
	srliw	s3, s3, 16
	srliw	s4, s4, 16
	or	s5, s5, s6
	or	s2, s2, s7
	or	s3, s3, s8
	or	s4, s4, s9
#endif /* WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
#else
	vsll.vi	v20, v3, 16
	vsll.vi	v21, v7, 16
	vsll.vi	v22, v11, 16
	vsrl.vi	v3, v3, 16
	vsrl.vi	v7, v7, 16
	vsrl.vi	v11, v11, 16
	vor.vv	v3, v3, v20
	vor.vv	v7, v7, v21
	vor.vv	v11, v11, v22
	slli	s6, s5, 16
	slli	s7, s2, 16
	slli	s8, s3, 16
	slli	s9, s4, 16
	srliw	s5, s5, 16
	srliw	s2, s2, 16
	srliw	s3, s3, 16
	srliw	s4, s4, 16
	or	s5, s5, s6
	or	s2, s2, s7
	or	s3, s3, s8
	or	s4, s4, s9
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vadd.vv	v6, v6, v7
	vadd.vv	v10, v10, v11
	add	a7, a7, s5
	add	s1, s1, s2
	add	a5, a5, s3
	add	a6, a6, s4
	vxor.vv	v1, v1, v2
	vxor.vv	v5, v5, v6
	vxor.vv	v9, v9, v10
	xor	t5, t5, a7
	xor	t6, t6, s1
	xor	a4, a4, a5
	xor	t4, t4, a6
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
	vror.vi	v5, v5, 20
	vror.vi	v9, v9, 20
#ifdef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
	# roriw t5, t5, 20
	.word	0x614f5f1b
	# roriw t6, t6, 20
	.word	0x614fdf9b
	# roriw a4, a4, 20
	.word	0x6147571b
	# roriw t4, t4, 20
	.word	0x614ede9b
#else
	slli	s6, t5, 12
	slli	s7, t6, 12
	slli	s8, a4, 12
	slli	s9, t4, 12
	srliw	t5, t5, 20
	srliw	t6, t6, 20
	srliw	a4, a4, 20
	srliw	t4, t4, 20
	or	t5, t5, s6
	or	t6, t6, s7
	or	a4, a4, s8
	or	t4, t4, s9
#endif /* WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
#else
	vsll.vi	v20, v1, 12
	vsll.vi	v21, v5, 12
	vsll.vi	v22, v9, 12
	vsrl.vi	v1, v1, 20
	vsrl.vi	v5, v5, 20
	vsrl.vi	v9, v9, 20
	vor.vv	v1, v1, v20
	vor.vv	v5, v5, v21
	vor.vv	v9, v9, v22
	slli	s6, t5, 12
	slli	s7, t6, 12
	slli	s8, a4, 12
	slli	s9, t4, 12
	srliw	t5, t5, 20
	srliw	t6, t6, 20
	srliw	a4, a4, 20
	srliw	t4, t4, 20
	or	t5, t5, s6
	or	t6, t6, s7
	or	a4, a4, s8
	or	t4, t4, s9
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vadd.vv	v4, v4, v5
	vadd.vv	v8, v8, v9
	add	t0, t0, t5
	add	t1, t1, t6
	add	t2, t2, a4
	add	t3, t3, t4
	vxor.vv	v3, v3, v0
	vxor.vv	v7, v7, v4
	vxor.vv	v11, v11, v8
	xor	s5, s5, t0
	xor	s2, s2, t1
	xor	s3, s3, t2
	xor	s4, s4, t3
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
	vror.vi	v7, v7, 24
	vror.vi	v11, v11, 24
#ifdef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
	# roriw s5, s5, 24
	.word	0x618ada9b
	# roriw s2, s2, 24
	.word	0x6189591b
	# roriw s3, s3, 24
	.word	0x6189d99b
	# roriw s4, s4, 24
	.word	0x618a5a1b
#else
	slli	s6, s5, 8
	slli	s7, s2, 8
	slli	s8, s3, 8
	slli	s9, s4, 8
	srliw	s5, s5, 24
	srliw	s2, s2, 24
	srliw	s3, s3, 24
	srliw	s4, s4, 24
	or	s5, s5, s6
	or	s2, s2, s7
	or	s3, s3, s8
	or	s4, s4, s9
#endif /* WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
#else
	vsll.vi	v20, v3, 8
	vsll.vi	v21, v7, 8
	vsll.vi	v22, v11, 8
	vsrl.vi	v3, v3, 24
	vsrl.vi	v7, v7, 24
	vsrl.vi	v11, v11, 24
	vor.vv	v3, v3, v20
	vor.vv	v7, v7, v21
	vor.vv	v11, v11, v22
	slli	s6, s5, 8
	slli	s7, s2, 8
	slli	s8, s3, 8
	slli	s9, s4, 8
	srliw	s5, s5, 24
	srliw	s2, s2, 24
	srliw	s3, s3, 24
	srliw	s4, s4, 24
	or	s5, s5, s6
	or	s2, s2, s7
	or	s3, s3, s8
	or	s4, s4, s9
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vadd.vv	v6, v6, v7
	vadd.vv	v10, v10, v11
	add	a7, a7, s5
	add	s1, s1, s2
	add	a5, a5, s3
	add	a6, a6, s4
	vxor.vv	v1, v1, v2
	vxor.vv	v5, v5, v6
	vxor.vv	v9, v9, v10
	xor	t5, t5, a7
	xor	t6, t6, s1
	xor	a4, a4, a5
	xor	t4, t4, a6
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
	vror.vi	v5, v5, 25
	vror.vi	v9, v9, 25
#ifdef WOLFSSL_RISCV_BASE_BIT_MANIPULATION
	# roriw t5, t5, 25
	.word	0x619f5f1b
	# roriw t6, t6, 25
	.word	0x619fdf9b
	# roriw a4, a4, 25
	.word	0x6197571b
	# roriw t4, t4, 25
	.word	0x619ede9b
#else
	slli	s6, t5, 7
	slli	s7, t6, 7
	slli	s8, a4, 7
	slli	s9, t4, 7
	srliw	t5, t5, 25
	srliw	t6, t6, 25
	srliw	a4, a4, 25
	srliw	t4, t4, 25
	or	t5, t5, s6
	or	t6, t6, s7
	or	a4, a4, s8
	or	t4, t4, s9
#endif /* WOLFSSL_RISCV_BASE_BIT_MANIPULATION */
#else
	vsll.vi	v20, v1, 7
	vsll.vi	v21, v5, 7
	vsll.vi	v22, v9, 7
	vsrl.vi	v1, v1, 25
	vsrl.vi	v5, v5, 25
	vsrl.vi	v9, v9, 25
	vor.vv	v1, v1, v20
	vor.vv	v5, v5, v21
	vor.vv	v9, v9, v22
	slli	s6, t5, 7
	slli	s7, t6, 7
	slli	s8, a4, 7
	slli	s9, t4, 7
	srliw	t5, t5, 25
	srliw	t6, t6, 25
	srliw	a4, a4, 25
	srliw	t4, t4, 25
	or	t5, t5, s6
	or	t6, t6, s7
	or	a4, a4, s8
	or	t4, t4, s9
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vrgather.vv	v20, v3, v23
	vrgather.vv	v21, v7, v23
	vrgather.vv	v22, v11, v23
	vmv.v.v	v3, v20
	vmv.v.v	v7, v21
	vmv.v.v	v11, v22
	vrgather.vv	v20, v1, v25
	vrgather.vv	v21, v5, v25
	vrgather.vv	v22, v9, v25
	vmv.v.v	v1, v20
	vmv.v.v	v5, v21
	vmv.v.v	v9, v22
	vrgather.vv	v20, v2, v24
	vrgather.vv	v21, v6, v24
	vrgather.vv	v22, v10, v24
	vmv.v.v	v2, v20
	vmv.v.v	v6, v21
	vmv.v.v	v10, v22
	bnez	s10, L_chacha20_riscv64_vec_256_loop
	# Block 1: add back, XOR message, store
	mv	s8, a2
	vl4re32.v	v12, (s8)
	addi	a2, a2, 64
	vadd.vv	v0, v0, v16
	vadd.vv	v1, v1, v17
	vadd.vv	v2, v2, v18
	vadd.vv	v3, v3, v19
	vxor.vv	v0, v0, v12
	vxor.vv	v1, v1, v13
	vxor.vv	v2, v2, v14
	vxor.vv	v3, v3, v15
	mv	s8, a2
	vl4re32.v	v12, (s8)
	addi	a2, a2, 64
	vmv.x.s	s6, v19
	mv	s8, a1
	vs4r.v	v0, (s8)
	addi	a1, a1, 64
	# Block 2
	addi	s6, s6, 1
	vmv.s.x	v19, s6
	vadd.vv	v4, v4, v16
	vadd.vv	v5, v5, v17
	vadd.vv	v6, v6, v18
	vadd.vv	v7, v7, v19
	vxor.vv	v4, v4, v12
	vxor.vv	v5, v5, v13
	vxor.vv	v6, v6, v14
	vxor.vv	v7, v7, v15
	mv	s8, a2
	vl4re32.v	v12, (s8)
	addi	a2, a2, 64
	mv	s8, a1
	vs4r.v	v4, (s8)
	addi	a1, a1, 64
	# Block 3
	addi	s6, s6, 1
	vmv.s.x	v19, s6
	vadd.vv	v8, v8, v16
	vadd.vv	v9, v9, v17
	vadd.vv	v10, v10, v18
	vadd.vv	v11, v11, v19
	vxor.vv	v8, v8, v12
	vxor.vv	v9, v9, v13
	vxor.vv	v10, v10, v14
	vxor.vv	v11, v11, v15
	mv	s8, a2
	vl4re32.v	v12, (s8)
	mv	s8, a1
	vs4r.v	v8, (s8)
	addi	a1, a1, 64
	# Block 4 (scalar): recombine, add back, XOR message, store
	addi	s6, s6, 1
	vmv.s.x	v0, t0
	vmv.s.x	v1, t4
	vmv.s.x	v2, a5
	vmv.s.x	v3, s2
	vmv.s.x	v4, t1
	vmv.s.x	v5, t5
	vmv.s.x	v6, a6
	vmv.s.x	v7, s3
	vslideup.vi	v0, v4, 1
	vslideup.vi	v1, v5, 1
	vslideup.vi	v2, v6, 1
	vslideup.vi	v3, v7, 1
	vmv.s.x	v4, t2
	vmv.s.x	v5, t6
	vmv.s.x	v6, a7
	vmv.s.x	v7, s4
	vslideup.vi	v0, v4, 2
	vslideup.vi	v1, v5, 2
	vslideup.vi	v2, v6, 2
	vslideup.vi	v3, v7, 2
	vmv.s.x	v4, t3
	vmv.s.x	v5, a4
	vmv.s.x	v6, s1
	vmv.s.x	v7, s5
	vslideup.vi	v0, v4, 3
	vslideup.vi	v1, v5, 3
	vslideup.vi	v2, v6, 3
	vslideup.vi	v3, v7, 3
	vmv.s.x	v19, s6
	vadd.vv	v0, v0, v16
	vadd.vv	v1, v1, v17
	vadd.vv	v2, v2, v18
	vadd.vv	v3, v3, v19
	vxor.vv	v0, v0, v12
	vxor.vv	v1, v1, v13
	vxor.vv	v2, v2, v14
	vxor.vv	v3, v3, v15
	mv	s8, a1
	vs4r.v	v0, (s8)
	addi	a1, a1, 64
	# Advance pointers, length and counter by 4 blocks
	addi	a2, a2, 64
	addi	a3, a3, -256
	lw	s6, 48(a0)
	addi	s6, s6, 4
	sw	s6, 48(a0)
L_chacha20_riscv64_vec_after_256:
	# Two-block (128-byte) tier
	li	s7, 128
	bltu	a3, s7, L_chacha20_riscv64_vec_after_128
	# Load state to encrypt
	mv	s8, a0
	vl4re32.v	v16, (s8)
	# Advance ctx->X[12] by 2 blocks
	lw	s6, 48(a0)
	addi	s6, s6, 2
	sw	s6, 48(a0)
	# Counter increment {1,0,0,0} and lane-rotate indices
	vmv.v.i	v22, 0
	li	s6, 1
	vmv.s.x	v22, s6
	vid.v	v20
	vslidedown.vi	v23, v20, 1
	vslideup.vi	v23, v20, 3
	vslidedown.vi	v24, v20, 2
	vslideup.vi	v24, v20, 2
	vslidedown.vi	v25, v20, 3
	vslideup.vi	v25, v20, 1
	vmv4r.v	v0, v16
	vmv4r.v	v4, v16
	# Second block counter += 1
	vadd.vv	v7, v7, v22
	li	s6, 10
L_chacha20_riscv64_vec_128_loop:
	vadd.vv	v0, v0, v1
	vadd.vv	v4, v4, v5
	vxor.vv	v3, v3, v0
	vxor.vv	v7, v7, v4
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
	vror.vi	v7, v7, 16
#else
	vsll.vi	v20, v3, 16
	vsll.vi	v21, v7, 16
	vsrl.vi	v3, v3, 16
	vsrl.vi	v7, v7, 16
	vor.vv	v3, v3, v20
	vor.vv	v7, v7, v21
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vadd.vv	v6, v6, v7
	vxor.vv	v1, v1, v2
	vxor.vv	v5, v5, v6
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
	vror.vi	v5, v5, 20
#else
	vsll.vi	v20, v1, 12
	vsll.vi	v21, v5, 12
	vsrl.vi	v1, v1, 20
	vsrl.vi	v5, v5, 20
	vor.vv	v1, v1, v20
	vor.vv	v5, v5, v21
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vadd.vv	v4, v4, v5
	vxor.vv	v3, v3, v0
	vxor.vv	v7, v7, v4
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
	vror.vi	v7, v7, 24
#else
	vsll.vi	v20, v3, 8
	vsll.vi	v21, v7, 8
	vsrl.vi	v3, v3, 24
	vsrl.vi	v7, v7, 24
	vor.vv	v3, v3, v20
	vor.vv	v7, v7, v21
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vadd.vv	v6, v6, v7
	vxor.vv	v1, v1, v2
	vxor.vv	v5, v5, v6
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
	vror.vi	v5, v5, 25
#else
	vsll.vi	v20, v1, 7
	vsll.vi	v21, v5, 7
	vsrl.vi	v1, v1, 25
	vsrl.vi	v5, v5, 25
	vor.vv	v1, v1, v20
	vor.vv	v5, v5, v21
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vrgather.vv	v20, v3, v25
	vrgather.vv	v21, v7, v25
	vmv.v.v	v3, v20
	vmv.v.v	v7, v21
	vrgather.vv	v20, v1, v23
	vrgather.vv	v21, v5, v23
	vmv.v.v	v1, v20
	vmv.v.v	v5, v21
	vrgather.vv	v20, v2, v24
	vrgather.vv	v21, v6, v24
	vmv.v.v	v2, v20
	vmv.v.v	v6, v21
	vadd.vv	v0, v0, v1
	vadd.vv	v4, v4, v5
	vxor.vv	v3, v3, v0
	vxor.vv	v7, v7, v4
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
	vror.vi	v7, v7, 16
#else
	vsll.vi	v20, v3, 16
	vsll.vi	v21, v7, 16
	vsrl.vi	v3, v3, 16
	vsrl.vi	v7, v7, 16
	vor.vv	v3, v3, v20
	vor.vv	v7, v7, v21
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vadd.vv	v6, v6, v7
	vxor.vv	v1, v1, v2
	vxor.vv	v5, v5, v6
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
	vror.vi	v5, v5, 20
#else
	vsll.vi	v20, v1, 12
	vsll.vi	v21, v5, 12
	vsrl.vi	v1, v1, 20
	vsrl.vi	v5, v5, 20
	vor.vv	v1, v1, v20
	vor.vv	v5, v5, v21
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vadd.vv	v4, v4, v5
	vxor.vv	v3, v3, v0
	vxor.vv	v7, v7, v4
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
	vror.vi	v7, v7, 24
#else
	vsll.vi	v20, v3, 8
	vsll.vi	v21, v7, 8
	vsrl.vi	v3, v3, 24
	vsrl.vi	v7, v7, 24
	vor.vv	v3, v3, v20
	vor.vv	v7, v7, v21
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vadd.vv	v6, v6, v7
	vxor.vv	v1, v1, v2
	vxor.vv	v5, v5, v6
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
	vror.vi	v5, v5, 25
#else
	vsll.vi	v20, v1, 7
	vsll.vi	v21, v5, 7
	vsrl.vi	v1, v1, 25
	vsrl.vi	v5, v5, 25
	vor.vv	v1, v1, v20
	vor.vv	v5, v5, v21
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vrgather.vv	v20, v3, v23
	vrgather.vv	v21, v7, v23
	vmv.v.v	v3, v20
	vmv.v.v	v7, v21
	vrgather.vv	v20, v1, v25
	vrgather.vv	v21, v5, v25
	vmv.v.v	v1, v20
	vmv.v.v	v5, v21
	vrgather.vv	v20, v2, v24
	vrgather.vv	v21, v6, v24
	vmv.v.v	v2, v20
	vmv.v.v	v6, v21
	addi	s6, s6, -1
	bnez	s6, L_chacha20_riscv64_vec_128_loop
	# Add back state, XOR message, store - block 1
	vadd.vv	v0, v0, v16
	vadd.vv	v1, v1, v17
	vadd.vv	v2, v2, v18
	vadd.vv	v3, v3, v19
	mv	s8, a2
	vl4re32.v	v12, (s8)
	vxor.vv	v0, v0, v12
	vxor.vv	v1, v1, v13
	vxor.vv	v2, v2, v14
	vxor.vv	v3, v3, v15
	mv	s8, a1
	vs4r.v	v0, (s8)
	addi	a2, a2, 64
	addi	a1, a1, 64
	# Add back state, XOR message, store - block 2
	vadd.vv	v19, v19, v22
	vadd.vv	v4, v4, v16
	vadd.vv	v5, v5, v17
	vadd.vv	v6, v6, v18
	vadd.vv	v7, v7, v19
	mv	s8, a2
	vl4re32.v	v12, (s8)
	vxor.vv	v4, v4, v12
	vxor.vv	v5, v5, v13
	vxor.vv	v6, v6, v14
	vxor.vv	v7, v7, v15
	mv	s8, a1
	vs4r.v	v4, (s8)
	addi	a2, a2, 64
	addi	a1, a1, 64
	addi	a3, a3, -128
L_chacha20_riscv64_vec_after_128:
	beqz	a3, L_chacha20_riscv64_vec_done
	# Load state to encrypt
	mv	s8, a0
	vl4re32.v	v8, (s8)
	# Advance ctx->X[12] by number of blocks: (len + 63) / 64
	addi	s6, a3, 63
	srli	s6, s6, 6
	lw	s7, 48(a0)
	add	s7, s7, s6
	sw	s7, 48(a0)
	# Counter increment {1,0,0,0}
	vmv.v.i	v13, 0
	li	s6, 1
	vmv.s.x	v13, s6
L_chacha20_riscv64_vec_64_loop:
	vmv4r.v	v0, v8
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 3
	vslideup.vi	v12, v3, 1
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 1
	vslideup.vi	v12, v1, 3
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 1
	vslideup.vi	v12, v3, 3
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 3
	vslideup.vi	v12, v1, 1
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 3
	vslideup.vi	v12, v3, 1
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 1
	vslideup.vi	v12, v1, 3
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 1
	vslideup.vi	v12, v3, 3
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 3
	vslideup.vi	v12, v1, 1
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 3
	vslideup.vi	v12, v3, 1
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 1
	vslideup.vi	v12, v1, 3
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 1
	vslideup.vi	v12, v3, 3
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 3
	vslideup.vi	v12, v1, 1
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 3
	vslideup.vi	v12, v3, 1
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 1
	vslideup.vi	v12, v1, 3
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 1
	vslideup.vi	v12, v3, 3
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 3
	vslideup.vi	v12, v1, 1
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 3
	vslideup.vi	v12, v3, 1
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 1
	vslideup.vi	v12, v1, 3
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 1
	vslideup.vi	v12, v3, 3
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 3
	vslideup.vi	v12, v1, 1
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 3
	vslideup.vi	v12, v3, 1
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 1
	vslideup.vi	v12, v1, 3
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 1
	vslideup.vi	v12, v3, 3
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 3
	vslideup.vi	v12, v1, 1
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 3
	vslideup.vi	v12, v3, 1
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 1
	vslideup.vi	v12, v1, 3
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 1
	vslideup.vi	v12, v3, 3
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 3
	vslideup.vi	v12, v1, 1
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 3
	vslideup.vi	v12, v3, 1
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 1
	vslideup.vi	v12, v1, 3
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 1
	vslideup.vi	v12, v3, 3
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 3
	vslideup.vi	v12, v1, 1
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 3
	vslideup.vi	v12, v3, 1
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 1
	vslideup.vi	v12, v1, 3
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 1
	vslideup.vi	v12, v3, 3
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 3
	vslideup.vi	v12, v1, 1
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 3
	vslideup.vi	v12, v3, 1
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 1
	vslideup.vi	v12, v1, 3
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 16
#else
	vsll.vi	v12, v3, 16
	vsrl.vi	v3, v3, 16
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 20
#else
	vsll.vi	v12, v1, 12
	vsrl.vi	v1, v1, 20
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v0, v0, v1
	vxor.vv	v3, v3, v0
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v3, v3, 24
#else
	vsll.vi	v12, v3, 8
	vsrl.vi	v3, v3, 24
	vor.vv	v3, v3, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vadd.vv	v2, v2, v3
	vxor.vv	v1, v1, v2
#ifdef WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION
	vror.vi	v1, v1, 25
#else
	vsll.vi	v12, v1, 7
	vsrl.vi	v1, v1, 25
	vor.vv	v1, v1, v12
#endif /* WOLFSSL_RISCV_VECTOR_BASE_BIT_MANIPULATION */
	vslidedown.vi	v12, v3, 1
	vslideup.vi	v12, v3, 3
	vmv.v.v	v3, v12
	vslidedown.vi	v12, v1, 3
	vslideup.vi	v12, v1, 1
	vmv.v.v	v1, v12
	vslidedown.vi	v12, v2, 2
	vslideup.vi	v12, v2, 2
	vmv.v.v	v2, v12
	addi	s7, a3, -64
	# Add back state
	vadd.vv	v0, v0, v8
	vadd.vv	v1, v1, v9
	vadd.vv	v2, v2, v10
	vadd.vv	v3, v3, v11
	bltz	s7, L_chacha20_riscv64_vec_64_lt_64
	# Encipher 64 bytes
	mv	s8, a2
	vl4re32.v	v4, (s8)
	vxor.vv	v4, v4, v0
	vxor.vv	v5, v5, v1
	vxor.vv	v6, v6, v2
	vxor.vv	v7, v7, v3
	mv	s8, a1
	vs4r.v	v4, (s8)
	addi	a3, a3, -64
	addi	a1, a1, 64
	addi	a2, a2, 64
	vadd.vv	v11, v11, v13
	bnez	a3, L_chacha20_riscv64_vec_64_loop
	j	L_chacha20_riscv64_vec_done
L_chacha20_riscv64_vec_64_lt_64:
	# Store full keystream block for leftovers
	addi	s8, a0, 72
	addi	s7, a3, -32
	vs4r.v	v0, (s8)
	bltz	s7, L_chacha20_riscv64_vec_64_lt_32
	# Encipher 32 bytes
	mv	s8, a2
	vl2re32.v	v4, (s8)
	vxor.vv	v4, v4, v0
	vxor.vv	v5, v5, v1
	mv	s8, a1
	vs2r.v	v4, (s8)
	addi	a3, a3, -32
	addi	a1, a1, 32
	addi	a2, a2, 32
	beqz	a3, L_chacha20_riscv64_vec_done
	vmv2r.v	v0, v2
L_chacha20_riscv64_vec_64_lt_32:
	addi	s7, a3, -16
	bltz	s7, L_chacha20_riscv64_vec_64_lt_16
	# Encipher 16 bytes
	mv	s8, a2
	vl1re32.v	v4, (s8)
	vxor.vv	v4, v4, v0
	mv	s8, a1
	vs1r.v	v4, (s8)
	addi	a3, a3, -16
	addi	a1, a1, 16
	addi	a2, a2, 16
	beqz	a3, L_chacha20_riscv64_vec_done
	vmv.v.v	v0, v1
L_chacha20_riscv64_vec_64_lt_16:
	addi	s7, a3, -8
	bltz	s7, L_chacha20_riscv64_vec_64_lt_8
	# Encipher 8 bytes
	vsetivli	zero, 2, e64, m1, ta, ma
	vmv.x.s	s6, v0
	vsetivli	zero, 4, e32, m1, ta, ma
	ld	s7, 0(a2)
	xor	s7, s7, s6
	sd	s7, 0(a1)
	addi	a3, a3, -8
	addi	a1, a1, 8
	addi	a2, a2, 8
	beqz	a3, L_chacha20_riscv64_vec_done
	vslidedown.vi	v0, v0, 2
L_chacha20_riscv64_vec_64_lt_8:
	addi	a3, a3, -1
	vsetivli	zero, 2, e64, m1, ta, ma
	vmv.x.s	s6, v0
	vsetivli	zero, 4, e32, m1, ta, ma
L_chacha20_riscv64_vec_64_loop_lt_8:
	# Encipher byte at a time
	addi	a3, a3, -1
	lb	s7, 0(a2)
	addi	a2, a2, 1
	xor	s7, s7, s6
	sb	s7, 0(a1)
	addi	a1, a1, 1
	srli	s6, s6, 8
	bgez	a3, L_chacha20_riscv64_vec_64_loop_lt_8
L_chacha20_riscv64_vec_done:
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
	.size	wc_chacha_crypt_bytes,.-wc_chacha_crypt_bytes
#else
	.text
	.globl	wc_chacha_crypt_bytes
	.type	wc_chacha_crypt_bytes,@function
	.align	2
wc_chacha_crypt_bytes:
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
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION
	.option arch, +zbb, +zbkb
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION */
	# Ensure 64-bit length has top bits clear
	slli	a3, a3, 32
	srli	a3, a3, 32
	# ctx->left = (CHACHA_CHUNK_BYTES - (len & 63)) & 63
	andi	s6, a3, 63
	li	s7, 64
	sub	s6, s7, s6
	andi	s6, s6, 63
	sw	s6, 64(a0)
	# over = ctx->over
	addi	s11, a0, 72
L_chacha20_riscv64_outer:
	# Load state into working registers
	ld	t0, 0(a0)
	ld	t2, 8(a0)
	ld	t4, 16(a0)
	ld	t6, 24(a0)
	ld	a5, 32(a0)
	ld	a7, 40(a0)
	ld	s2, 48(a0)
	ld	s4, 56(a0)
	srli	t1, t0, 32
	srli	t3, t2, 32
	srli	t5, t4, 32
	srli	a4, t6, 32
	srli	a6, a5, 32
	srli	s1, a7, 32
	srli	s3, s2, 32
	srli	s5, s4, 32
	# 10 double rounds
	li	s10, 10
L_chacha20_riscv64_loop:
	add	t0, t0, t4
	add	t1, t1, t5
	add	t2, t2, t6
	add	t3, t3, a4
	xor	s2, s2, t0
	xor	s3, s3, t1
	xor	s4, s4, t2
	xor	s5, s5, t3
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION
	# roriw s2, s2, 16
	.word	0x6109591b
	# roriw s3, s3, 16
	.word	0x6109d99b
	# roriw s4, s4, 16
	.word	0x610a5a1b
	# roriw s5, s5, 16
	.word	0x610ada9b
#else
	slli	s6, s2, 16
	slli	s7, s3, 16
	slli	s8, s4, 16
	slli	s9, s5, 16
	srliw	s2, s2, 16
	srliw	s3, s3, 16
	srliw	s4, s4, 16
	srliw	s5, s5, 16
	or	s2, s2, s6
	or	s3, s3, s7
	or	s4, s4, s8
	or	s5, s5, s9
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION */
	add	a5, a5, s2
	add	a6, a6, s3
	add	a7, a7, s4
	add	s1, s1, s5
	xor	t4, t4, a5
	xor	t5, t5, a6
	xor	t6, t6, a7
	xor	a4, a4, s1
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION
	# roriw t4, t4, 20
	.word	0x614ede9b
	# roriw t5, t5, 20
	.word	0x614f5f1b
	# roriw t6, t6, 20
	.word	0x614fdf9b
	# roriw a4, a4, 20
	.word	0x6147571b
#else
	slli	s6, t4, 12
	slli	s7, t5, 12
	slli	s8, t6, 12
	slli	s9, a4, 12
	srliw	t4, t4, 20
	srliw	t5, t5, 20
	srliw	t6, t6, 20
	srliw	a4, a4, 20
	or	t4, t4, s6
	or	t5, t5, s7
	or	t6, t6, s8
	or	a4, a4, s9
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION */
	add	t0, t0, t4
	add	t1, t1, t5
	add	t2, t2, t6
	add	t3, t3, a4
	xor	s2, s2, t0
	xor	s3, s3, t1
	xor	s4, s4, t2
	xor	s5, s5, t3
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION
	# roriw s2, s2, 24
	.word	0x6189591b
	# roriw s3, s3, 24
	.word	0x6189d99b
	# roriw s4, s4, 24
	.word	0x618a5a1b
	# roriw s5, s5, 24
	.word	0x618ada9b
#else
	slli	s6, s2, 8
	slli	s7, s3, 8
	slli	s8, s4, 8
	slli	s9, s5, 8
	srliw	s2, s2, 24
	srliw	s3, s3, 24
	srliw	s4, s4, 24
	srliw	s5, s5, 24
	or	s2, s2, s6
	or	s3, s3, s7
	or	s4, s4, s8
	or	s5, s5, s9
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION */
	add	a5, a5, s2
	add	a6, a6, s3
	add	a7, a7, s4
	add	s1, s1, s5
	xor	t4, t4, a5
	xor	t5, t5, a6
	xor	t6, t6, a7
	xor	a4, a4, s1
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION
	# roriw t4, t4, 25
	.word	0x619ede9b
	# roriw t5, t5, 25
	.word	0x619f5f1b
	# roriw t6, t6, 25
	.word	0x619fdf9b
	# roriw a4, a4, 25
	.word	0x6197571b
#else
	slli	s6, t4, 7
	slli	s7, t5, 7
	slli	s8, t6, 7
	slli	s9, a4, 7
	srliw	t4, t4, 25
	srliw	t5, t5, 25
	srliw	t6, t6, 25
	srliw	a4, a4, 25
	or	t4, t4, s6
	or	t5, t5, s7
	or	t6, t6, s8
	or	a4, a4, s9
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION */
	addi	s10, s10, -1
	add	t0, t0, t5
	add	t1, t1, t6
	add	t2, t2, a4
	add	t3, t3, t4
	xor	s5, s5, t0
	xor	s2, s2, t1
	xor	s3, s3, t2
	xor	s4, s4, t3
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION
	# roriw s5, s5, 16
	.word	0x610ada9b
	# roriw s2, s2, 16
	.word	0x6109591b
	# roriw s3, s3, 16
	.word	0x6109d99b
	# roriw s4, s4, 16
	.word	0x610a5a1b
#else
	slli	s6, s5, 16
	slli	s7, s2, 16
	slli	s8, s3, 16
	slli	s9, s4, 16
	srliw	s5, s5, 16
	srliw	s2, s2, 16
	srliw	s3, s3, 16
	srliw	s4, s4, 16
	or	s5, s5, s6
	or	s2, s2, s7
	or	s3, s3, s8
	or	s4, s4, s9
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION */
	add	a7, a7, s5
	add	s1, s1, s2
	add	a5, a5, s3
	add	a6, a6, s4
	xor	t5, t5, a7
	xor	t6, t6, s1
	xor	a4, a4, a5
	xor	t4, t4, a6
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION
	# roriw t5, t5, 20
	.word	0x614f5f1b
	# roriw t6, t6, 20
	.word	0x614fdf9b
	# roriw a4, a4, 20
	.word	0x6147571b
	# roriw t4, t4, 20
	.word	0x614ede9b
#else
	slli	s6, t5, 12
	slli	s7, t6, 12
	slli	s8, a4, 12
	slli	s9, t4, 12
	srliw	t5, t5, 20
	srliw	t6, t6, 20
	srliw	a4, a4, 20
	srliw	t4, t4, 20
	or	t5, t5, s6
	or	t6, t6, s7
	or	a4, a4, s8
	or	t4, t4, s9
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION */
	add	t0, t0, t5
	add	t1, t1, t6
	add	t2, t2, a4
	add	t3, t3, t4
	xor	s5, s5, t0
	xor	s2, s2, t1
	xor	s3, s3, t2
	xor	s4, s4, t3
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION
	# roriw s5, s5, 24
	.word	0x618ada9b
	# roriw s2, s2, 24
	.word	0x6189591b
	# roriw s3, s3, 24
	.word	0x6189d99b
	# roriw s4, s4, 24
	.word	0x618a5a1b
#else
	slli	s6, s5, 8
	slli	s7, s2, 8
	slli	s8, s3, 8
	slli	s9, s4, 8
	srliw	s5, s5, 24
	srliw	s2, s2, 24
	srliw	s3, s3, 24
	srliw	s4, s4, 24
	or	s5, s5, s6
	or	s2, s2, s7
	or	s3, s3, s8
	or	s4, s4, s9
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION */
	add	a7, a7, s5
	add	s1, s1, s2
	add	a5, a5, s3
	add	a6, a6, s4
	xor	t5, t5, a7
	xor	t6, t6, s1
	xor	a4, a4, a5
	xor	t4, t4, a6
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION
	# roriw t5, t5, 25
	.word	0x619f5f1b
	# roriw t6, t6, 25
	.word	0x619fdf9b
	# roriw a4, a4, 25
	.word	0x6197571b
	# roriw t4, t4, 25
	.word	0x619ede9b
#else
	slli	s6, t5, 7
	slli	s7, t6, 7
	slli	s8, a4, 7
	slli	s9, t4, 7
	srliw	t5, t5, 25
	srliw	t6, t6, 25
	srliw	a4, a4, 25
	srliw	t4, t4, 25
	or	t5, t5, s6
	or	t6, t6, s7
	or	a4, a4, s8
	or	t4, t4, s9
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION */
	bnez	s10, L_chacha20_riscv64_loop
	addi	a3, a3, -64
	# Add original state back in; increment block counter X[12]
	ld	s6, 0(a0)
	ld	s7, 8(a0)
	ld	s8, 16(a0)
	ld	s9, 24(a0)
	add	t0, t0, s6
	add	t2, t2, s7
	add	t4, t4, s8
	add	t6, t6, s9
	srli	s6, s6, 32
	srli	s7, s7, 32
	srli	s8, s8, 32
	srli	s9, s9, 32
	add	t1, t1, s6
	add	t3, t3, s7
	add	t5, t5, s8
	add	a4, a4, s9
	ld	s6, 32(a0)
	ld	s7, 40(a0)
	ld	s8, 48(a0)
	ld	s9, 56(a0)
	add	a5, a5, s6
	add	a7, a7, s7
	add	s2, s2, s8
	add	s4, s4, s9
	srli	s6, s6, 32
	srli	s7, s7, 32
	srli	s9, s9, 32
	add	a6, a6, s6
	add	s1, s1, s7
	add	s5, s5, s9
	srli	s9, s8, 32
	add	s3, s3, s9
	addi	s8, s8, 1
	sw	s8, 48(a0)
	bltz	a3, L_chacha20_riscv64_over
	# XOR full 64-byte block of message and store
#ifdef WOLFSSL_RISCV_BIT_MANIPULATION
	# pack t0, t0, t1
	.word	0x0862c2b3
	# pack t2, t2, t3
	.word	0x09c3c3b3
	# pack t4, t4, t5
	.word	0x09eeceb3
	# pack t6, t6, a4
	.word	0x08efcfb3
	# pack a5, a5, a6
	.word	0x0907c7b3
	# pack a7, a7, s1
	.word	0x0898c8b3
	# pack s2, s2, s3
	.word	0x09394933
	# pack s4, s4, s5
	.word	0x095a4a33
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	t1, 0(a2)
#else
	andi	s10, a2, 7
	bnez	s10, L_ualn_ld16_w
	ld	t1, 0(a2)
	j	L_ualn_ld16_e
L_ualn_ld16_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_ld16_h
	lwu	t1, 0(a2)
	lwu	s10, 4(a2)
	slli	s10, s10, 32
	or	t1, t1, s10
	j	L_ualn_ld16_e
L_ualn_ld16_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_ld16_b
	lhu	t1, 0(a2)
	lhu	s10, 2(a2)
	slli	s10, s10, 16
	or	t1, t1, s10
	lhu	s10, 4(a2)
	slli	s10, s10, 32
	or	t1, t1, s10
	lhu	s10, 6(a2)
	slli	s10, s10, 48
	or	t1, t1, s10
	j	L_ualn_ld16_e
L_ualn_ld16_b:
	lbu	t1, 0(a2)
	lbu	s10, 1(a2)
	slli	s10, s10, 8
	or	t1, t1, s10
	lbu	s10, 2(a2)
	slli	s10, s10, 16
	or	t1, t1, s10
	lbu	s10, 3(a2)
	slli	s10, s10, 24
	or	t1, t1, s10
	lbu	s10, 4(a2)
	slli	s10, s10, 32
	or	t1, t1, s10
	lbu	s10, 5(a2)
	slli	s10, s10, 40
	or	t1, t1, s10
	lbu	s10, 6(a2)
	slli	s10, s10, 48
	or	t1, t1, s10
	lbu	s10, 7(a2)
	slli	s10, s10, 56
	or	t1, t1, s10
L_ualn_ld16_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	t3, 8(a2)
#else
	andi	s10, a2, 7
	bnez	s10, L_ualn_ld17_w
	ld	t3, 8(a2)
	j	L_ualn_ld17_e
L_ualn_ld17_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_ld17_h
	lwu	t3, 8(a2)
	lwu	s10, 12(a2)
	slli	s10, s10, 32
	or	t3, t3, s10
	j	L_ualn_ld17_e
L_ualn_ld17_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_ld17_b
	lhu	t3, 8(a2)
	lhu	s10, 10(a2)
	slli	s10, s10, 16
	or	t3, t3, s10
	lhu	s10, 12(a2)
	slli	s10, s10, 32
	or	t3, t3, s10
	lhu	s10, 14(a2)
	slli	s10, s10, 48
	or	t3, t3, s10
	j	L_ualn_ld17_e
L_ualn_ld17_b:
	lbu	t3, 8(a2)
	lbu	s10, 9(a2)
	slli	s10, s10, 8
	or	t3, t3, s10
	lbu	s10, 10(a2)
	slli	s10, s10, 16
	or	t3, t3, s10
	lbu	s10, 11(a2)
	slli	s10, s10, 24
	or	t3, t3, s10
	lbu	s10, 12(a2)
	slli	s10, s10, 32
	or	t3, t3, s10
	lbu	s10, 13(a2)
	slli	s10, s10, 40
	or	t3, t3, s10
	lbu	s10, 14(a2)
	slli	s10, s10, 48
	or	t3, t3, s10
	lbu	s10, 15(a2)
	slli	s10, s10, 56
	or	t3, t3, s10
L_ualn_ld17_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	t5, 16(a2)
#else
	andi	s10, a2, 7
	bnez	s10, L_ualn_ld18_w
	ld	t5, 16(a2)
	j	L_ualn_ld18_e
L_ualn_ld18_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_ld18_h
	lwu	t5, 16(a2)
	lwu	s10, 20(a2)
	slli	s10, s10, 32
	or	t5, t5, s10
	j	L_ualn_ld18_e
L_ualn_ld18_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_ld18_b
	lhu	t5, 16(a2)
	lhu	s10, 18(a2)
	slli	s10, s10, 16
	or	t5, t5, s10
	lhu	s10, 20(a2)
	slli	s10, s10, 32
	or	t5, t5, s10
	lhu	s10, 22(a2)
	slli	s10, s10, 48
	or	t5, t5, s10
	j	L_ualn_ld18_e
L_ualn_ld18_b:
	lbu	t5, 16(a2)
	lbu	s10, 17(a2)
	slli	s10, s10, 8
	or	t5, t5, s10
	lbu	s10, 18(a2)
	slli	s10, s10, 16
	or	t5, t5, s10
	lbu	s10, 19(a2)
	slli	s10, s10, 24
	or	t5, t5, s10
	lbu	s10, 20(a2)
	slli	s10, s10, 32
	or	t5, t5, s10
	lbu	s10, 21(a2)
	slli	s10, s10, 40
	or	t5, t5, s10
	lbu	s10, 22(a2)
	slli	s10, s10, 48
	or	t5, t5, s10
	lbu	s10, 23(a2)
	slli	s10, s10, 56
	or	t5, t5, s10
L_ualn_ld18_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a4, 24(a2)
#else
	andi	s10, a2, 7
	bnez	s10, L_ualn_ld19_w
	ld	a4, 24(a2)
	j	L_ualn_ld19_e
L_ualn_ld19_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_ld19_h
	lwu	a4, 24(a2)
	lwu	s10, 28(a2)
	slli	s10, s10, 32
	or	a4, a4, s10
	j	L_ualn_ld19_e
L_ualn_ld19_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_ld19_b
	lhu	a4, 24(a2)
	lhu	s10, 26(a2)
	slli	s10, s10, 16
	or	a4, a4, s10
	lhu	s10, 28(a2)
	slli	s10, s10, 32
	or	a4, a4, s10
	lhu	s10, 30(a2)
	slli	s10, s10, 48
	or	a4, a4, s10
	j	L_ualn_ld19_e
L_ualn_ld19_b:
	lbu	a4, 24(a2)
	lbu	s10, 25(a2)
	slli	s10, s10, 8
	or	a4, a4, s10
	lbu	s10, 26(a2)
	slli	s10, s10, 16
	or	a4, a4, s10
	lbu	s10, 27(a2)
	slli	s10, s10, 24
	or	a4, a4, s10
	lbu	s10, 28(a2)
	slli	s10, s10, 32
	or	a4, a4, s10
	lbu	s10, 29(a2)
	slli	s10, s10, 40
	or	a4, a4, s10
	lbu	s10, 30(a2)
	slli	s10, s10, 48
	or	a4, a4, s10
	lbu	s10, 31(a2)
	slli	s10, s10, 56
	or	a4, a4, s10
L_ualn_ld19_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	a6, 32(a2)
#else
	andi	s10, a2, 7
	bnez	s10, L_ualn_ld20_w
	ld	a6, 32(a2)
	j	L_ualn_ld20_e
L_ualn_ld20_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_ld20_h
	lwu	a6, 32(a2)
	lwu	s10, 36(a2)
	slli	s10, s10, 32
	or	a6, a6, s10
	j	L_ualn_ld20_e
L_ualn_ld20_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_ld20_b
	lhu	a6, 32(a2)
	lhu	s10, 34(a2)
	slli	s10, s10, 16
	or	a6, a6, s10
	lhu	s10, 36(a2)
	slli	s10, s10, 32
	or	a6, a6, s10
	lhu	s10, 38(a2)
	slli	s10, s10, 48
	or	a6, a6, s10
	j	L_ualn_ld20_e
L_ualn_ld20_b:
	lbu	a6, 32(a2)
	lbu	s10, 33(a2)
	slli	s10, s10, 8
	or	a6, a6, s10
	lbu	s10, 34(a2)
	slli	s10, s10, 16
	or	a6, a6, s10
	lbu	s10, 35(a2)
	slli	s10, s10, 24
	or	a6, a6, s10
	lbu	s10, 36(a2)
	slli	s10, s10, 32
	or	a6, a6, s10
	lbu	s10, 37(a2)
	slli	s10, s10, 40
	or	a6, a6, s10
	lbu	s10, 38(a2)
	slli	s10, s10, 48
	or	a6, a6, s10
	lbu	s10, 39(a2)
	slli	s10, s10, 56
	or	a6, a6, s10
L_ualn_ld20_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	s1, 40(a2)
#else
	andi	s10, a2, 7
	bnez	s10, L_ualn_ld21_w
	ld	s1, 40(a2)
	j	L_ualn_ld21_e
L_ualn_ld21_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_ld21_h
	lwu	s1, 40(a2)
	lwu	s10, 44(a2)
	slli	s10, s10, 32
	or	s1, s1, s10
	j	L_ualn_ld21_e
L_ualn_ld21_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_ld21_b
	lhu	s1, 40(a2)
	lhu	s10, 42(a2)
	slli	s10, s10, 16
	or	s1, s1, s10
	lhu	s10, 44(a2)
	slli	s10, s10, 32
	or	s1, s1, s10
	lhu	s10, 46(a2)
	slli	s10, s10, 48
	or	s1, s1, s10
	j	L_ualn_ld21_e
L_ualn_ld21_b:
	lbu	s1, 40(a2)
	lbu	s10, 41(a2)
	slli	s10, s10, 8
	or	s1, s1, s10
	lbu	s10, 42(a2)
	slli	s10, s10, 16
	or	s1, s1, s10
	lbu	s10, 43(a2)
	slli	s10, s10, 24
	or	s1, s1, s10
	lbu	s10, 44(a2)
	slli	s10, s10, 32
	or	s1, s1, s10
	lbu	s10, 45(a2)
	slli	s10, s10, 40
	or	s1, s1, s10
	lbu	s10, 46(a2)
	slli	s10, s10, 48
	or	s1, s1, s10
	lbu	s10, 47(a2)
	slli	s10, s10, 56
	or	s1, s1, s10
L_ualn_ld21_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	s3, 48(a2)
#else
	andi	s10, a2, 7
	bnez	s10, L_ualn_ld22_w
	ld	s3, 48(a2)
	j	L_ualn_ld22_e
L_ualn_ld22_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_ld22_h
	lwu	s3, 48(a2)
	lwu	s10, 52(a2)
	slli	s10, s10, 32
	or	s3, s3, s10
	j	L_ualn_ld22_e
L_ualn_ld22_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_ld22_b
	lhu	s3, 48(a2)
	lhu	s10, 50(a2)
	slli	s10, s10, 16
	or	s3, s3, s10
	lhu	s10, 52(a2)
	slli	s10, s10, 32
	or	s3, s3, s10
	lhu	s10, 54(a2)
	slli	s10, s10, 48
	or	s3, s3, s10
	j	L_ualn_ld22_e
L_ualn_ld22_b:
	lbu	s3, 48(a2)
	lbu	s10, 49(a2)
	slli	s10, s10, 8
	or	s3, s3, s10
	lbu	s10, 50(a2)
	slli	s10, s10, 16
	or	s3, s3, s10
	lbu	s10, 51(a2)
	slli	s10, s10, 24
	or	s3, s3, s10
	lbu	s10, 52(a2)
	slli	s10, s10, 32
	or	s3, s3, s10
	lbu	s10, 53(a2)
	slli	s10, s10, 40
	or	s3, s3, s10
	lbu	s10, 54(a2)
	slli	s10, s10, 48
	or	s3, s3, s10
	lbu	s10, 55(a2)
	slli	s10, s10, 56
	or	s3, s3, s10
L_ualn_ld22_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	s5, 56(a2)
#else
	andi	s10, a2, 7
	bnez	s10, L_ualn_ld23_w
	ld	s5, 56(a2)
	j	L_ualn_ld23_e
L_ualn_ld23_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_ld23_h
	lwu	s5, 56(a2)
	lwu	s10, 60(a2)
	slli	s10, s10, 32
	or	s5, s5, s10
	j	L_ualn_ld23_e
L_ualn_ld23_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_ld23_b
	lhu	s5, 56(a2)
	lhu	s10, 58(a2)
	slli	s10, s10, 16
	or	s5, s5, s10
	lhu	s10, 60(a2)
	slli	s10, s10, 32
	or	s5, s5, s10
	lhu	s10, 62(a2)
	slli	s10, s10, 48
	or	s5, s5, s10
	j	L_ualn_ld23_e
L_ualn_ld23_b:
	lbu	s5, 56(a2)
	lbu	s10, 57(a2)
	slli	s10, s10, 8
	or	s5, s5, s10
	lbu	s10, 58(a2)
	slli	s10, s10, 16
	or	s5, s5, s10
	lbu	s10, 59(a2)
	slli	s10, s10, 24
	or	s5, s5, s10
	lbu	s10, 60(a2)
	slli	s10, s10, 32
	or	s5, s5, s10
	lbu	s10, 61(a2)
	slli	s10, s10, 40
	or	s5, s5, s10
	lbu	s10, 62(a2)
	slli	s10, s10, 48
	or	s5, s5, s10
	lbu	s10, 63(a2)
	slli	s10, s10, 56
	or	s5, s5, s10
L_ualn_ld23_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	xor	t0, t0, t1
	xor	t2, t2, t3
	xor	t4, t4, t5
	xor	t6, t6, a4
	xor	a5, a5, a6
	xor	a7, a7, s1
	xor	s2, s2, s3
	xor	s4, s4, s5
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sd	t0, 0(a1)
#else
	andi	s10, a1, 7
	bnez	s10, L_ualn_sd24_w
	sd	t0, 0(a1)
	j	L_ualn_sd24_e
L_ualn_sd24_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_sd24_h
	sw	t0, 0(a1)
	srli	s10, t0, 32
	sw	s10, 4(a1)
	j	L_ualn_sd24_e
L_ualn_sd24_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sd24_b
	sh	t0, 0(a1)
	srli	s10, t0, 16
	sh	s10, 2(a1)
	srli	s10, t0, 32
	sh	s10, 4(a1)
	srli	s10, t0, 48
	sh	s10, 6(a1)
	j	L_ualn_sd24_e
L_ualn_sd24_b:
	sb	t0, 0(a1)
	srli	s10, t0, 8
	sb	s10, 1(a1)
	srli	s10, t0, 16
	sb	s10, 2(a1)
	srli	s10, t0, 24
	sb	s10, 3(a1)
	srli	s10, t0, 32
	sb	s10, 4(a1)
	srli	s10, t0, 40
	sb	s10, 5(a1)
	srli	s10, t0, 48
	sb	s10, 6(a1)
	srli	s10, t0, 56
	sb	s10, 7(a1)
L_ualn_sd24_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sd	t2, 8(a1)
#else
	andi	s10, a1, 7
	bnez	s10, L_ualn_sd25_w
	sd	t2, 8(a1)
	j	L_ualn_sd25_e
L_ualn_sd25_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_sd25_h
	sw	t2, 8(a1)
	srli	s10, t2, 32
	sw	s10, 12(a1)
	j	L_ualn_sd25_e
L_ualn_sd25_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sd25_b
	sh	t2, 8(a1)
	srli	s10, t2, 16
	sh	s10, 10(a1)
	srli	s10, t2, 32
	sh	s10, 12(a1)
	srli	s10, t2, 48
	sh	s10, 14(a1)
	j	L_ualn_sd25_e
L_ualn_sd25_b:
	sb	t2, 8(a1)
	srli	s10, t2, 8
	sb	s10, 9(a1)
	srli	s10, t2, 16
	sb	s10, 10(a1)
	srli	s10, t2, 24
	sb	s10, 11(a1)
	srli	s10, t2, 32
	sb	s10, 12(a1)
	srli	s10, t2, 40
	sb	s10, 13(a1)
	srli	s10, t2, 48
	sb	s10, 14(a1)
	srli	s10, t2, 56
	sb	s10, 15(a1)
L_ualn_sd25_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sd	t4, 16(a1)
#else
	andi	s10, a1, 7
	bnez	s10, L_ualn_sd26_w
	sd	t4, 16(a1)
	j	L_ualn_sd26_e
L_ualn_sd26_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_sd26_h
	sw	t4, 16(a1)
	srli	s10, t4, 32
	sw	s10, 20(a1)
	j	L_ualn_sd26_e
L_ualn_sd26_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sd26_b
	sh	t4, 16(a1)
	srli	s10, t4, 16
	sh	s10, 18(a1)
	srli	s10, t4, 32
	sh	s10, 20(a1)
	srli	s10, t4, 48
	sh	s10, 22(a1)
	j	L_ualn_sd26_e
L_ualn_sd26_b:
	sb	t4, 16(a1)
	srli	s10, t4, 8
	sb	s10, 17(a1)
	srli	s10, t4, 16
	sb	s10, 18(a1)
	srli	s10, t4, 24
	sb	s10, 19(a1)
	srli	s10, t4, 32
	sb	s10, 20(a1)
	srli	s10, t4, 40
	sb	s10, 21(a1)
	srli	s10, t4, 48
	sb	s10, 22(a1)
	srli	s10, t4, 56
	sb	s10, 23(a1)
L_ualn_sd26_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sd	t6, 24(a1)
#else
	andi	s10, a1, 7
	bnez	s10, L_ualn_sd27_w
	sd	t6, 24(a1)
	j	L_ualn_sd27_e
L_ualn_sd27_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_sd27_h
	sw	t6, 24(a1)
	srli	s10, t6, 32
	sw	s10, 28(a1)
	j	L_ualn_sd27_e
L_ualn_sd27_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sd27_b
	sh	t6, 24(a1)
	srli	s10, t6, 16
	sh	s10, 26(a1)
	srli	s10, t6, 32
	sh	s10, 28(a1)
	srli	s10, t6, 48
	sh	s10, 30(a1)
	j	L_ualn_sd27_e
L_ualn_sd27_b:
	sb	t6, 24(a1)
	srli	s10, t6, 8
	sb	s10, 25(a1)
	srli	s10, t6, 16
	sb	s10, 26(a1)
	srli	s10, t6, 24
	sb	s10, 27(a1)
	srli	s10, t6, 32
	sb	s10, 28(a1)
	srli	s10, t6, 40
	sb	s10, 29(a1)
	srli	s10, t6, 48
	sb	s10, 30(a1)
	srli	s10, t6, 56
	sb	s10, 31(a1)
L_ualn_sd27_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sd	a5, 32(a1)
#else
	andi	s10, a1, 7
	bnez	s10, L_ualn_sd28_w
	sd	a5, 32(a1)
	j	L_ualn_sd28_e
L_ualn_sd28_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_sd28_h
	sw	a5, 32(a1)
	srli	s10, a5, 32
	sw	s10, 36(a1)
	j	L_ualn_sd28_e
L_ualn_sd28_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sd28_b
	sh	a5, 32(a1)
	srli	s10, a5, 16
	sh	s10, 34(a1)
	srli	s10, a5, 32
	sh	s10, 36(a1)
	srli	s10, a5, 48
	sh	s10, 38(a1)
	j	L_ualn_sd28_e
L_ualn_sd28_b:
	sb	a5, 32(a1)
	srli	s10, a5, 8
	sb	s10, 33(a1)
	srli	s10, a5, 16
	sb	s10, 34(a1)
	srli	s10, a5, 24
	sb	s10, 35(a1)
	srli	s10, a5, 32
	sb	s10, 36(a1)
	srli	s10, a5, 40
	sb	s10, 37(a1)
	srli	s10, a5, 48
	sb	s10, 38(a1)
	srli	s10, a5, 56
	sb	s10, 39(a1)
L_ualn_sd28_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sd	a7, 40(a1)
#else
	andi	s10, a1, 7
	bnez	s10, L_ualn_sd29_w
	sd	a7, 40(a1)
	j	L_ualn_sd29_e
L_ualn_sd29_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_sd29_h
	sw	a7, 40(a1)
	srli	s10, a7, 32
	sw	s10, 44(a1)
	j	L_ualn_sd29_e
L_ualn_sd29_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sd29_b
	sh	a7, 40(a1)
	srli	s10, a7, 16
	sh	s10, 42(a1)
	srli	s10, a7, 32
	sh	s10, 44(a1)
	srli	s10, a7, 48
	sh	s10, 46(a1)
	j	L_ualn_sd29_e
L_ualn_sd29_b:
	sb	a7, 40(a1)
	srli	s10, a7, 8
	sb	s10, 41(a1)
	srli	s10, a7, 16
	sb	s10, 42(a1)
	srli	s10, a7, 24
	sb	s10, 43(a1)
	srli	s10, a7, 32
	sb	s10, 44(a1)
	srli	s10, a7, 40
	sb	s10, 45(a1)
	srli	s10, a7, 48
	sb	s10, 46(a1)
	srli	s10, a7, 56
	sb	s10, 47(a1)
L_ualn_sd29_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sd	s2, 48(a1)
#else
	andi	s10, a1, 7
	bnez	s10, L_ualn_sd30_w
	sd	s2, 48(a1)
	j	L_ualn_sd30_e
L_ualn_sd30_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_sd30_h
	sw	s2, 48(a1)
	srli	s10, s2, 32
	sw	s10, 52(a1)
	j	L_ualn_sd30_e
L_ualn_sd30_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sd30_b
	sh	s2, 48(a1)
	srli	s10, s2, 16
	sh	s10, 50(a1)
	srli	s10, s2, 32
	sh	s10, 52(a1)
	srli	s10, s2, 48
	sh	s10, 54(a1)
	j	L_ualn_sd30_e
L_ualn_sd30_b:
	sb	s2, 48(a1)
	srli	s10, s2, 8
	sb	s10, 49(a1)
	srli	s10, s2, 16
	sb	s10, 50(a1)
	srli	s10, s2, 24
	sb	s10, 51(a1)
	srli	s10, s2, 32
	sb	s10, 52(a1)
	srli	s10, s2, 40
	sb	s10, 53(a1)
	srli	s10, s2, 48
	sb	s10, 54(a1)
	srli	s10, s2, 56
	sb	s10, 55(a1)
L_ualn_sd30_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sd	s4, 56(a1)
#else
	andi	s10, a1, 7
	bnez	s10, L_ualn_sd31_w
	sd	s4, 56(a1)
	j	L_ualn_sd31_e
L_ualn_sd31_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_sd31_h
	sw	s4, 56(a1)
	srli	s10, s4, 32
	sw	s10, 60(a1)
	j	L_ualn_sd31_e
L_ualn_sd31_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sd31_b
	sh	s4, 56(a1)
	srli	s10, s4, 16
	sh	s10, 58(a1)
	srli	s10, s4, 32
	sh	s10, 60(a1)
	srli	s10, s4, 48
	sh	s10, 62(a1)
	j	L_ualn_sd31_e
L_ualn_sd31_b:
	sb	s4, 56(a1)
	srli	s10, s4, 8
	sb	s10, 57(a1)
	srli	s10, s4, 16
	sb	s10, 58(a1)
	srli	s10, s4, 24
	sb	s10, 59(a1)
	srli	s10, s4, 32
	sb	s10, 60(a1)
	srli	s10, s4, 40
	sb	s10, 61(a1)
	srli	s10, s4, 48
	sb	s10, 62(a1)
	srli	s10, s4, 56
	sb	s10, 63(a1)
L_ualn_sd31_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#else
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	s6, 0(a2)
#else
	andi	s10, a2, 7
	bnez	s10, L_ualn_ld32_w
	ld	s6, 0(a2)
	j	L_ualn_ld32_e
L_ualn_ld32_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_ld32_h
	lwu	s6, 0(a2)
	lwu	s10, 4(a2)
	slli	s10, s10, 32
	or	s6, s6, s10
	j	L_ualn_ld32_e
L_ualn_ld32_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_ld32_b
	lhu	s6, 0(a2)
	lhu	s10, 2(a2)
	slli	s10, s10, 16
	or	s6, s6, s10
	lhu	s10, 4(a2)
	slli	s10, s10, 32
	or	s6, s6, s10
	lhu	s10, 6(a2)
	slli	s10, s10, 48
	or	s6, s6, s10
	j	L_ualn_ld32_e
L_ualn_ld32_b:
	lbu	s6, 0(a2)
	lbu	s10, 1(a2)
	slli	s10, s10, 8
	or	s6, s6, s10
	lbu	s10, 2(a2)
	slli	s10, s10, 16
	or	s6, s6, s10
	lbu	s10, 3(a2)
	slli	s10, s10, 24
	or	s6, s6, s10
	lbu	s10, 4(a2)
	slli	s10, s10, 32
	or	s6, s6, s10
	lbu	s10, 5(a2)
	slli	s10, s10, 40
	or	s6, s6, s10
	lbu	s10, 6(a2)
	slli	s10, s10, 48
	or	s6, s6, s10
	lbu	s10, 7(a2)
	slli	s10, s10, 56
	or	s6, s6, s10
L_ualn_ld32_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	s7, 8(a2)
#else
	andi	s10, a2, 7
	bnez	s10, L_ualn_ld33_w
	ld	s7, 8(a2)
	j	L_ualn_ld33_e
L_ualn_ld33_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_ld33_h
	lwu	s7, 8(a2)
	lwu	s10, 12(a2)
	slli	s10, s10, 32
	or	s7, s7, s10
	j	L_ualn_ld33_e
L_ualn_ld33_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_ld33_b
	lhu	s7, 8(a2)
	lhu	s10, 10(a2)
	slli	s10, s10, 16
	or	s7, s7, s10
	lhu	s10, 12(a2)
	slli	s10, s10, 32
	or	s7, s7, s10
	lhu	s10, 14(a2)
	slli	s10, s10, 48
	or	s7, s7, s10
	j	L_ualn_ld33_e
L_ualn_ld33_b:
	lbu	s7, 8(a2)
	lbu	s10, 9(a2)
	slli	s10, s10, 8
	or	s7, s7, s10
	lbu	s10, 10(a2)
	slli	s10, s10, 16
	or	s7, s7, s10
	lbu	s10, 11(a2)
	slli	s10, s10, 24
	or	s7, s7, s10
	lbu	s10, 12(a2)
	slli	s10, s10, 32
	or	s7, s7, s10
	lbu	s10, 13(a2)
	slli	s10, s10, 40
	or	s7, s7, s10
	lbu	s10, 14(a2)
	slli	s10, s10, 48
	or	s7, s7, s10
	lbu	s10, 15(a2)
	slli	s10, s10, 56
	or	s7, s7, s10
L_ualn_ld33_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	s8, 16(a2)
#else
	andi	s10, a2, 7
	bnez	s10, L_ualn_ld34_w
	ld	s8, 16(a2)
	j	L_ualn_ld34_e
L_ualn_ld34_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_ld34_h
	lwu	s8, 16(a2)
	lwu	s10, 20(a2)
	slli	s10, s10, 32
	or	s8, s8, s10
	j	L_ualn_ld34_e
L_ualn_ld34_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_ld34_b
	lhu	s8, 16(a2)
	lhu	s10, 18(a2)
	slli	s10, s10, 16
	or	s8, s8, s10
	lhu	s10, 20(a2)
	slli	s10, s10, 32
	or	s8, s8, s10
	lhu	s10, 22(a2)
	slli	s10, s10, 48
	or	s8, s8, s10
	j	L_ualn_ld34_e
L_ualn_ld34_b:
	lbu	s8, 16(a2)
	lbu	s10, 17(a2)
	slli	s10, s10, 8
	or	s8, s8, s10
	lbu	s10, 18(a2)
	slli	s10, s10, 16
	or	s8, s8, s10
	lbu	s10, 19(a2)
	slli	s10, s10, 24
	or	s8, s8, s10
	lbu	s10, 20(a2)
	slli	s10, s10, 32
	or	s8, s8, s10
	lbu	s10, 21(a2)
	slli	s10, s10, 40
	or	s8, s8, s10
	lbu	s10, 22(a2)
	slli	s10, s10, 48
	or	s8, s8, s10
	lbu	s10, 23(a2)
	slli	s10, s10, 56
	or	s8, s8, s10
L_ualn_ld34_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	s9, 24(a2)
#else
	andi	s10, a2, 7
	bnez	s10, L_ualn_ld35_w
	ld	s9, 24(a2)
	j	L_ualn_ld35_e
L_ualn_ld35_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_ld35_h
	lwu	s9, 24(a2)
	lwu	s10, 28(a2)
	slli	s10, s10, 32
	or	s9, s9, s10
	j	L_ualn_ld35_e
L_ualn_ld35_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_ld35_b
	lhu	s9, 24(a2)
	lhu	s10, 26(a2)
	slli	s10, s10, 16
	or	s9, s9, s10
	lhu	s10, 28(a2)
	slli	s10, s10, 32
	or	s9, s9, s10
	lhu	s10, 30(a2)
	slli	s10, s10, 48
	or	s9, s9, s10
	j	L_ualn_ld35_e
L_ualn_ld35_b:
	lbu	s9, 24(a2)
	lbu	s10, 25(a2)
	slli	s10, s10, 8
	or	s9, s9, s10
	lbu	s10, 26(a2)
	slli	s10, s10, 16
	or	s9, s9, s10
	lbu	s10, 27(a2)
	slli	s10, s10, 24
	or	s9, s9, s10
	lbu	s10, 28(a2)
	slli	s10, s10, 32
	or	s9, s9, s10
	lbu	s10, 29(a2)
	slli	s10, s10, 40
	or	s9, s9, s10
	lbu	s10, 30(a2)
	slli	s10, s10, 48
	or	s9, s9, s10
	lbu	s10, 31(a2)
	slli	s10, s10, 56
	or	s9, s9, s10
L_ualn_ld35_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	xor	t0, t0, s6
	xor	t2, t2, s7
	xor	t4, t4, s8
	xor	t6, t6, s9
	srli	s6, s6, 32
	srli	s7, s7, 32
	srli	s8, s8, 32
	srli	s9, s9, 32
	xor	t1, t1, s6
	xor	t3, t3, s7
	xor	t5, t5, s8
	xor	a4, a4, s9
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	s6, 32(a2)
#else
	andi	s10, a2, 7
	bnez	s10, L_ualn_ld36_w
	ld	s6, 32(a2)
	j	L_ualn_ld36_e
L_ualn_ld36_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_ld36_h
	lwu	s6, 32(a2)
	lwu	s10, 36(a2)
	slli	s10, s10, 32
	or	s6, s6, s10
	j	L_ualn_ld36_e
L_ualn_ld36_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_ld36_b
	lhu	s6, 32(a2)
	lhu	s10, 34(a2)
	slli	s10, s10, 16
	or	s6, s6, s10
	lhu	s10, 36(a2)
	slli	s10, s10, 32
	or	s6, s6, s10
	lhu	s10, 38(a2)
	slli	s10, s10, 48
	or	s6, s6, s10
	j	L_ualn_ld36_e
L_ualn_ld36_b:
	lbu	s6, 32(a2)
	lbu	s10, 33(a2)
	slli	s10, s10, 8
	or	s6, s6, s10
	lbu	s10, 34(a2)
	slli	s10, s10, 16
	or	s6, s6, s10
	lbu	s10, 35(a2)
	slli	s10, s10, 24
	or	s6, s6, s10
	lbu	s10, 36(a2)
	slli	s10, s10, 32
	or	s6, s6, s10
	lbu	s10, 37(a2)
	slli	s10, s10, 40
	or	s6, s6, s10
	lbu	s10, 38(a2)
	slli	s10, s10, 48
	or	s6, s6, s10
	lbu	s10, 39(a2)
	slli	s10, s10, 56
	or	s6, s6, s10
L_ualn_ld36_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	s7, 40(a2)
#else
	andi	s10, a2, 7
	bnez	s10, L_ualn_ld37_w
	ld	s7, 40(a2)
	j	L_ualn_ld37_e
L_ualn_ld37_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_ld37_h
	lwu	s7, 40(a2)
	lwu	s10, 44(a2)
	slli	s10, s10, 32
	or	s7, s7, s10
	j	L_ualn_ld37_e
L_ualn_ld37_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_ld37_b
	lhu	s7, 40(a2)
	lhu	s10, 42(a2)
	slli	s10, s10, 16
	or	s7, s7, s10
	lhu	s10, 44(a2)
	slli	s10, s10, 32
	or	s7, s7, s10
	lhu	s10, 46(a2)
	slli	s10, s10, 48
	or	s7, s7, s10
	j	L_ualn_ld37_e
L_ualn_ld37_b:
	lbu	s7, 40(a2)
	lbu	s10, 41(a2)
	slli	s10, s10, 8
	or	s7, s7, s10
	lbu	s10, 42(a2)
	slli	s10, s10, 16
	or	s7, s7, s10
	lbu	s10, 43(a2)
	slli	s10, s10, 24
	or	s7, s7, s10
	lbu	s10, 44(a2)
	slli	s10, s10, 32
	or	s7, s7, s10
	lbu	s10, 45(a2)
	slli	s10, s10, 40
	or	s7, s7, s10
	lbu	s10, 46(a2)
	slli	s10, s10, 48
	or	s7, s7, s10
	lbu	s10, 47(a2)
	slli	s10, s10, 56
	or	s7, s7, s10
L_ualn_ld37_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	s8, 48(a2)
#else
	andi	s10, a2, 7
	bnez	s10, L_ualn_ld38_w
	ld	s8, 48(a2)
	j	L_ualn_ld38_e
L_ualn_ld38_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_ld38_h
	lwu	s8, 48(a2)
	lwu	s10, 52(a2)
	slli	s10, s10, 32
	or	s8, s8, s10
	j	L_ualn_ld38_e
L_ualn_ld38_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_ld38_b
	lhu	s8, 48(a2)
	lhu	s10, 50(a2)
	slli	s10, s10, 16
	or	s8, s8, s10
	lhu	s10, 52(a2)
	slli	s10, s10, 32
	or	s8, s8, s10
	lhu	s10, 54(a2)
	slli	s10, s10, 48
	or	s8, s8, s10
	j	L_ualn_ld38_e
L_ualn_ld38_b:
	lbu	s8, 48(a2)
	lbu	s10, 49(a2)
	slli	s10, s10, 8
	or	s8, s8, s10
	lbu	s10, 50(a2)
	slli	s10, s10, 16
	or	s8, s8, s10
	lbu	s10, 51(a2)
	slli	s10, s10, 24
	or	s8, s8, s10
	lbu	s10, 52(a2)
	slli	s10, s10, 32
	or	s8, s8, s10
	lbu	s10, 53(a2)
	slli	s10, s10, 40
	or	s8, s8, s10
	lbu	s10, 54(a2)
	slli	s10, s10, 48
	or	s8, s8, s10
	lbu	s10, 55(a2)
	slli	s10, s10, 56
	or	s8, s8, s10
L_ualn_ld38_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	s9, 56(a2)
#else
	andi	s10, a2, 7
	bnez	s10, L_ualn_ld39_w
	ld	s9, 56(a2)
	j	L_ualn_ld39_e
L_ualn_ld39_w:
	andi	s10, s10, 3
	bnez	s10, L_ualn_ld39_h
	lwu	s9, 56(a2)
	lwu	s10, 60(a2)
	slli	s10, s10, 32
	or	s9, s9, s10
	j	L_ualn_ld39_e
L_ualn_ld39_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_ld39_b
	lhu	s9, 56(a2)
	lhu	s10, 58(a2)
	slli	s10, s10, 16
	or	s9, s9, s10
	lhu	s10, 60(a2)
	slli	s10, s10, 32
	or	s9, s9, s10
	lhu	s10, 62(a2)
	slli	s10, s10, 48
	or	s9, s9, s10
	j	L_ualn_ld39_e
L_ualn_ld39_b:
	lbu	s9, 56(a2)
	lbu	s10, 57(a2)
	slli	s10, s10, 8
	or	s9, s9, s10
	lbu	s10, 58(a2)
	slli	s10, s10, 16
	or	s9, s9, s10
	lbu	s10, 59(a2)
	slli	s10, s10, 24
	or	s9, s9, s10
	lbu	s10, 60(a2)
	slli	s10, s10, 32
	or	s9, s9, s10
	lbu	s10, 61(a2)
	slli	s10, s10, 40
	or	s9, s9, s10
	lbu	s10, 62(a2)
	slli	s10, s10, 48
	or	s9, s9, s10
	lbu	s10, 63(a2)
	slli	s10, s10, 56
	or	s9, s9, s10
L_ualn_ld39_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	xor	a5, a5, s6
	xor	a7, a7, s7
	xor	s2, s2, s8
	xor	s4, s4, s9
	srli	s6, s6, 32
	srli	s7, s7, 32
	srli	s8, s8, 32
	srli	s9, s9, 32
	xor	a6, a6, s6
	xor	s1, s1, s7
	xor	s3, s3, s8
	xor	s5, s5, s9
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sw	t0, 0(a1)
#else
	andi	s10, a1, 3
	bnez	s10, L_ualn_sw40_h
	sw	t0, 0(a1)
	j	L_ualn_sw40_e
L_ualn_sw40_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sw40_b
	sh	t0, 0(a1)
	srli	s10, t0, 16
	sh	s10, 2(a1)
	j	L_ualn_sw40_e
L_ualn_sw40_b:
	sb	t0, 0(a1)
	srli	s10, t0, 8
	sb	s10, 1(a1)
	srli	s10, t0, 16
	sb	s10, 2(a1)
	srli	s10, t0, 24
	sb	s10, 3(a1)
L_ualn_sw40_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sw	t1, 4(a1)
#else
	andi	s10, a1, 3
	bnez	s10, L_ualn_sw41_h
	sw	t1, 4(a1)
	j	L_ualn_sw41_e
L_ualn_sw41_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sw41_b
	sh	t1, 4(a1)
	srli	s10, t1, 16
	sh	s10, 6(a1)
	j	L_ualn_sw41_e
L_ualn_sw41_b:
	sb	t1, 4(a1)
	srli	s10, t1, 8
	sb	s10, 5(a1)
	srli	s10, t1, 16
	sb	s10, 6(a1)
	srli	s10, t1, 24
	sb	s10, 7(a1)
L_ualn_sw41_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sw	t2, 8(a1)
#else
	andi	s10, a1, 3
	bnez	s10, L_ualn_sw42_h
	sw	t2, 8(a1)
	j	L_ualn_sw42_e
L_ualn_sw42_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sw42_b
	sh	t2, 8(a1)
	srli	s10, t2, 16
	sh	s10, 10(a1)
	j	L_ualn_sw42_e
L_ualn_sw42_b:
	sb	t2, 8(a1)
	srli	s10, t2, 8
	sb	s10, 9(a1)
	srli	s10, t2, 16
	sb	s10, 10(a1)
	srli	s10, t2, 24
	sb	s10, 11(a1)
L_ualn_sw42_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sw	t3, 12(a1)
#else
	andi	s10, a1, 3
	bnez	s10, L_ualn_sw43_h
	sw	t3, 12(a1)
	j	L_ualn_sw43_e
L_ualn_sw43_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sw43_b
	sh	t3, 12(a1)
	srli	s10, t3, 16
	sh	s10, 14(a1)
	j	L_ualn_sw43_e
L_ualn_sw43_b:
	sb	t3, 12(a1)
	srli	s10, t3, 8
	sb	s10, 13(a1)
	srli	s10, t3, 16
	sb	s10, 14(a1)
	srli	s10, t3, 24
	sb	s10, 15(a1)
L_ualn_sw43_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sw	t4, 16(a1)
#else
	andi	s10, a1, 3
	bnez	s10, L_ualn_sw44_h
	sw	t4, 16(a1)
	j	L_ualn_sw44_e
L_ualn_sw44_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sw44_b
	sh	t4, 16(a1)
	srli	s10, t4, 16
	sh	s10, 18(a1)
	j	L_ualn_sw44_e
L_ualn_sw44_b:
	sb	t4, 16(a1)
	srli	s10, t4, 8
	sb	s10, 17(a1)
	srli	s10, t4, 16
	sb	s10, 18(a1)
	srli	s10, t4, 24
	sb	s10, 19(a1)
L_ualn_sw44_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sw	t5, 20(a1)
#else
	andi	s10, a1, 3
	bnez	s10, L_ualn_sw45_h
	sw	t5, 20(a1)
	j	L_ualn_sw45_e
L_ualn_sw45_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sw45_b
	sh	t5, 20(a1)
	srli	s10, t5, 16
	sh	s10, 22(a1)
	j	L_ualn_sw45_e
L_ualn_sw45_b:
	sb	t5, 20(a1)
	srli	s10, t5, 8
	sb	s10, 21(a1)
	srli	s10, t5, 16
	sb	s10, 22(a1)
	srli	s10, t5, 24
	sb	s10, 23(a1)
L_ualn_sw45_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sw	t6, 24(a1)
#else
	andi	s10, a1, 3
	bnez	s10, L_ualn_sw46_h
	sw	t6, 24(a1)
	j	L_ualn_sw46_e
L_ualn_sw46_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sw46_b
	sh	t6, 24(a1)
	srli	s10, t6, 16
	sh	s10, 26(a1)
	j	L_ualn_sw46_e
L_ualn_sw46_b:
	sb	t6, 24(a1)
	srli	s10, t6, 8
	sb	s10, 25(a1)
	srli	s10, t6, 16
	sb	s10, 26(a1)
	srli	s10, t6, 24
	sb	s10, 27(a1)
L_ualn_sw46_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sw	a4, 28(a1)
#else
	andi	s10, a1, 3
	bnez	s10, L_ualn_sw47_h
	sw	a4, 28(a1)
	j	L_ualn_sw47_e
L_ualn_sw47_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sw47_b
	sh	a4, 28(a1)
	srli	s10, a4, 16
	sh	s10, 30(a1)
	j	L_ualn_sw47_e
L_ualn_sw47_b:
	sb	a4, 28(a1)
	srli	s10, a4, 8
	sb	s10, 29(a1)
	srli	s10, a4, 16
	sb	s10, 30(a1)
	srli	s10, a4, 24
	sb	s10, 31(a1)
L_ualn_sw47_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sw	a5, 32(a1)
#else
	andi	s10, a1, 3
	bnez	s10, L_ualn_sw48_h
	sw	a5, 32(a1)
	j	L_ualn_sw48_e
L_ualn_sw48_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sw48_b
	sh	a5, 32(a1)
	srli	s10, a5, 16
	sh	s10, 34(a1)
	j	L_ualn_sw48_e
L_ualn_sw48_b:
	sb	a5, 32(a1)
	srli	s10, a5, 8
	sb	s10, 33(a1)
	srli	s10, a5, 16
	sb	s10, 34(a1)
	srli	s10, a5, 24
	sb	s10, 35(a1)
L_ualn_sw48_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sw	a6, 36(a1)
#else
	andi	s10, a1, 3
	bnez	s10, L_ualn_sw49_h
	sw	a6, 36(a1)
	j	L_ualn_sw49_e
L_ualn_sw49_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sw49_b
	sh	a6, 36(a1)
	srli	s10, a6, 16
	sh	s10, 38(a1)
	j	L_ualn_sw49_e
L_ualn_sw49_b:
	sb	a6, 36(a1)
	srli	s10, a6, 8
	sb	s10, 37(a1)
	srli	s10, a6, 16
	sb	s10, 38(a1)
	srli	s10, a6, 24
	sb	s10, 39(a1)
L_ualn_sw49_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sw	a7, 40(a1)
#else
	andi	s10, a1, 3
	bnez	s10, L_ualn_sw50_h
	sw	a7, 40(a1)
	j	L_ualn_sw50_e
L_ualn_sw50_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sw50_b
	sh	a7, 40(a1)
	srli	s10, a7, 16
	sh	s10, 42(a1)
	j	L_ualn_sw50_e
L_ualn_sw50_b:
	sb	a7, 40(a1)
	srli	s10, a7, 8
	sb	s10, 41(a1)
	srli	s10, a7, 16
	sb	s10, 42(a1)
	srli	s10, a7, 24
	sb	s10, 43(a1)
L_ualn_sw50_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sw	s1, 44(a1)
#else
	andi	s10, a1, 3
	bnez	s10, L_ualn_sw51_h
	sw	s1, 44(a1)
	j	L_ualn_sw51_e
L_ualn_sw51_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sw51_b
	sh	s1, 44(a1)
	srli	s10, s1, 16
	sh	s10, 46(a1)
	j	L_ualn_sw51_e
L_ualn_sw51_b:
	sb	s1, 44(a1)
	srli	s10, s1, 8
	sb	s10, 45(a1)
	srli	s10, s1, 16
	sb	s10, 46(a1)
	srli	s10, s1, 24
	sb	s10, 47(a1)
L_ualn_sw51_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sw	s2, 48(a1)
#else
	andi	s10, a1, 3
	bnez	s10, L_ualn_sw52_h
	sw	s2, 48(a1)
	j	L_ualn_sw52_e
L_ualn_sw52_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sw52_b
	sh	s2, 48(a1)
	srli	s10, s2, 16
	sh	s10, 50(a1)
	j	L_ualn_sw52_e
L_ualn_sw52_b:
	sb	s2, 48(a1)
	srli	s10, s2, 8
	sb	s10, 49(a1)
	srli	s10, s2, 16
	sb	s10, 50(a1)
	srli	s10, s2, 24
	sb	s10, 51(a1)
L_ualn_sw52_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sw	s3, 52(a1)
#else
	andi	s10, a1, 3
	bnez	s10, L_ualn_sw53_h
	sw	s3, 52(a1)
	j	L_ualn_sw53_e
L_ualn_sw53_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sw53_b
	sh	s3, 52(a1)
	srli	s10, s3, 16
	sh	s10, 54(a1)
	j	L_ualn_sw53_e
L_ualn_sw53_b:
	sb	s3, 52(a1)
	srli	s10, s3, 8
	sb	s10, 53(a1)
	srli	s10, s3, 16
	sb	s10, 54(a1)
	srli	s10, s3, 24
	sb	s10, 55(a1)
L_ualn_sw53_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sw	s4, 56(a1)
#else
	andi	s10, a1, 3
	bnez	s10, L_ualn_sw54_h
	sw	s4, 56(a1)
	j	L_ualn_sw54_e
L_ualn_sw54_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sw54_b
	sh	s4, 56(a1)
	srli	s10, s4, 16
	sh	s10, 58(a1)
	j	L_ualn_sw54_e
L_ualn_sw54_b:
	sb	s4, 56(a1)
	srli	s10, s4, 8
	sb	s10, 57(a1)
	srli	s10, s4, 16
	sb	s10, 58(a1)
	srli	s10, s4, 24
	sb	s10, 59(a1)
L_ualn_sw54_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sw	s5, 60(a1)
#else
	andi	s10, a1, 3
	bnez	s10, L_ualn_sw55_h
	sw	s5, 60(a1)
	j	L_ualn_sw55_e
L_ualn_sw55_h:
	andi	s10, s10, 1
	bnez	s10, L_ualn_sw55_b
	sh	s5, 60(a1)
	srli	s10, s5, 16
	sh	s10, 62(a1)
	j	L_ualn_sw55_e
L_ualn_sw55_b:
	sb	s5, 60(a1)
	srli	s10, s5, 8
	sb	s10, 61(a1)
	srli	s10, s5, 16
	sb	s10, 62(a1)
	srli	s10, s5, 24
	sb	s10, 63(a1)
L_ualn_sw55_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
#endif /* WOLFSSL_RISCV_BIT_MANIPULATION */
	addi	a2, a2, 64
	addi	a1, a1, 64
	bnez	a3, L_chacha20_riscv64_outer
	j	L_chacha20_riscv64_done
L_chacha20_riscv64_over:
	# Partial last block: save keystream block, XOR remaining bytes
	addi	s10, a3, 64
	sw	t0, 0(s11)
	sw	t1, 4(s11)
	sw	t2, 8(s11)
	sw	t3, 12(s11)
	sw	t4, 16(s11)
	sw	t5, 20(s11)
	sw	t6, 24(s11)
	sw	a4, 28(s11)
	sw	a5, 32(s11)
	sw	a6, 36(s11)
	sw	a7, 40(s11)
	sw	s1, 44(s11)
	sw	s2, 48(s11)
	sw	s3, 52(s11)
	sw	s4, 56(s11)
	sw	s5, 60(s11)
L_chacha20_riscv64_over_loop_8:
	li	s8, 8
	bltu	s10, s8, L_chacha20_riscv64_over_lt_4
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	ld	s6, 0(a2)
#else
	andi	s9, a2, 7
	bnez	s9, L_ualn_ld56_w
	ld	s6, 0(a2)
	j	L_ualn_ld56_e
L_ualn_ld56_w:
	andi	s9, s9, 3
	bnez	s9, L_ualn_ld56_h
	lwu	s6, 0(a2)
	lwu	s9, 4(a2)
	slli	s9, s9, 32
	or	s6, s6, s9
	j	L_ualn_ld56_e
L_ualn_ld56_h:
	andi	s9, s9, 1
	bnez	s9, L_ualn_ld56_b
	lhu	s6, 0(a2)
	lhu	s9, 2(a2)
	slli	s9, s9, 16
	or	s6, s6, s9
	lhu	s9, 4(a2)
	slli	s9, s9, 32
	or	s6, s6, s9
	lhu	s9, 6(a2)
	slli	s9, s9, 48
	or	s6, s6, s9
	j	L_ualn_ld56_e
L_ualn_ld56_b:
	lbu	s6, 0(a2)
	lbu	s9, 1(a2)
	slli	s9, s9, 8
	or	s6, s6, s9
	lbu	s9, 2(a2)
	slli	s9, s9, 16
	or	s6, s6, s9
	lbu	s9, 3(a2)
	slli	s9, s9, 24
	or	s6, s6, s9
	lbu	s9, 4(a2)
	slli	s9, s9, 32
	or	s6, s6, s9
	lbu	s9, 5(a2)
	slli	s9, s9, 40
	or	s6, s6, s9
	lbu	s9, 6(a2)
	slli	s9, s9, 48
	or	s6, s6, s9
	lbu	s9, 7(a2)
	slli	s9, s9, 56
	or	s6, s6, s9
L_ualn_ld56_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	ld	s7, 0(s11)
	xor	s6, s6, s7
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sd	s6, 0(a1)
#else
	andi	s9, a1, 7
	bnez	s9, L_ualn_sd57_w
	sd	s6, 0(a1)
	j	L_ualn_sd57_e
L_ualn_sd57_w:
	andi	s9, s9, 3
	bnez	s9, L_ualn_sd57_h
	sw	s6, 0(a1)
	srli	s9, s6, 32
	sw	s9, 4(a1)
	j	L_ualn_sd57_e
L_ualn_sd57_h:
	andi	s9, s9, 1
	bnez	s9, L_ualn_sd57_b
	sh	s6, 0(a1)
	srli	s9, s6, 16
	sh	s9, 2(a1)
	srli	s9, s6, 32
	sh	s9, 4(a1)
	srli	s9, s6, 48
	sh	s9, 6(a1)
	j	L_ualn_sd57_e
L_ualn_sd57_b:
	sb	s6, 0(a1)
	srli	s9, s6, 8
	sb	s9, 1(a1)
	srli	s9, s6, 16
	sb	s9, 2(a1)
	srli	s9, s6, 24
	sb	s9, 3(a1)
	srli	s9, s6, 32
	sb	s9, 4(a1)
	srli	s9, s6, 40
	sb	s9, 5(a1)
	srli	s9, s6, 48
	sb	s9, 6(a1)
	srli	s9, s6, 56
	sb	s9, 7(a1)
L_ualn_sd57_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	addi	a2, a2, 8
	addi	s11, s11, 8
	addi	a1, a1, 8
	addi	s10, s10, -8
	j	L_chacha20_riscv64_over_loop_8
L_chacha20_riscv64_over_lt_4:
	li	s8, 4
	bltu	s10, s8, L_chacha20_riscv64_over_lt_2
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lw	s6, 0(a2)
#else
	andi	s9, a2, 3
	bnez	s9, L_ualn_lw58_h
	lw	s6, 0(a2)
	j	L_ualn_lw58_e
L_ualn_lw58_h:
	andi	s9, s9, 1
	bnez	s9, L_ualn_lw58_b
	lhu	s6, 0(a2)
	lhu	s9, 2(a2)
	slli	s9, s9, 16
	or	s6, s6, s9
	addiw	s6, s6, 0
	j	L_ualn_lw58_e
L_ualn_lw58_b:
	lbu	s6, 0(a2)
	lbu	s9, 1(a2)
	slli	s9, s9, 8
	or	s6, s6, s9
	lbu	s9, 2(a2)
	slli	s9, s9, 16
	or	s6, s6, s9
	lbu	s9, 3(a2)
	slli	s9, s9, 24
	or	s6, s6, s9
	addiw	s6, s6, 0
L_ualn_lw58_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	lw	s7, 0(s11)
	xor	s6, s6, s7
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sw	s6, 0(a1)
#else
	andi	s9, a1, 3
	bnez	s9, L_ualn_sw59_h
	sw	s6, 0(a1)
	j	L_ualn_sw59_e
L_ualn_sw59_h:
	andi	s9, s9, 1
	bnez	s9, L_ualn_sw59_b
	sh	s6, 0(a1)
	srli	s9, s6, 16
	sh	s9, 2(a1)
	j	L_ualn_sw59_e
L_ualn_sw59_b:
	sb	s6, 0(a1)
	srli	s9, s6, 8
	sb	s9, 1(a1)
	srli	s9, s6, 16
	sb	s9, 2(a1)
	srli	s9, s6, 24
	sb	s9, 3(a1)
L_ualn_sw59_e:
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	addi	a2, a2, 4
	addi	s11, s11, 4
	addi	a1, a1, 4
	addi	s10, s10, -4
L_chacha20_riscv64_over_lt_2:
	li	s8, 2
	bltu	s10, s8, L_chacha20_riscv64_over_lt_1
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	lh	s6, 0(a2)
#else
	lbu	s6, 0(a2)
	lb	s9, 1(a2)
	slli	s9, s9, 8
	or	s6, s6, s9
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	lh	s7, 0(s11)
	xor	s6, s6, s7
#if !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED)
	sh	s6, 0(a1)
#else
	sb	s6, 0(a1)
	srli	s9, s6, 8
	sb	s9, 1(a1)
#endif /* !defined(WOLFSSL_RISCV_ASM_NO_UNALIGNED) */
	addi	a2, a2, 2
	addi	s11, s11, 2
	addi	a1, a1, 2
	addi	s10, s10, -2
L_chacha20_riscv64_over_lt_1:
	beqz	s10, L_chacha20_riscv64_done
	lb	s6, 0(a2)
	lb	s7, 0(s11)
	xor	s6, s6, s7
	sb	s6, 0(a1)
L_chacha20_riscv64_done:
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
	.size	wc_chacha_crypt_bytes,.-wc_chacha_crypt_bytes
#endif /* WOLFSSL_RISCV_VECTOR */
#endif /* HAVE_CHACHA */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_RISCV_ASM_INLINE */
#endif /* WOLFSSL_RISCV_ASM */
