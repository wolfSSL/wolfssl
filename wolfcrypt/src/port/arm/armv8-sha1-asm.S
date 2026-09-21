/* armv8-sha1-asm
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
 *   ruby ./sha1/sha1.rb arm64 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-sha1-asm.S
 */

#define WC_FIPS_LL_CRYPTO
#define _WC_BUILDING_ARMV8_SHA1_ASM_S

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

#ifdef WOLFSSL_ARMASM
#ifdef __aarch64__
#ifndef WOLFSSL_ARMASM_INLINE
#ifndef NO_SHA
#if !defined(WOLFSSL_ARMASM_NO_BASE_IMPL) || defined(WOLFSSL_ARMASM_NO_NEON)
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_SHA1_trans_base_len_k, %object
	.size	L_SHA1_trans_base_len_k, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_SHA1_trans_base_len_k:
	.long	0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xca62c1d6
#ifndef __APPLE__
.text
.globl	Transform_Sha_Len_base
WC_ASM_ATT_HIDDEN(Transform_Sha_Len_base)
.type	Transform_Sha_Len_base,@function
.align	2
Transform_Sha_Len_base:
#else
.section	__TEXT,__text
.globl	_Transform_Sha_Len_base
WC_ASM_ATT_HIDDEN(_Transform_Sha_Len_base)
.p2align	2
_Transform_Sha_Len_base:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-112]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #24]
	stp	x20, x21, [x29, #40]
	stp	x22, x23, [x29, #56]
	stp	x24, x25, [x29, #72]
	stp	x26, x27, [x29, #88]
	str	x28, [x29, #104]
#ifndef __APPLE__
	adrp x3, L_SHA1_trans_base_len_k
	add  x3, x3, :lo12:L_SHA1_trans_base_len_k
#else
	adrp x3, L_SHA1_trans_base_len_k@PAGE
	add  x3, x3, L_SHA1_trans_base_len_k@PAGEOFF
#endif /* __APPLE__ */
	# Load digest into working vars
	ldr	w4, [x0]
	ldr	w5, [x0, #4]
	ldr	w6, [x0, #8]
	ldr	w7, [x0, #12]
	ldr	w8, [x0, #16]
	# Start of loop processing a block
L_sha1_len_base_begin:
	# Load W
	ldr	w9, [x1]
	ldr	w10, [x1, #4]
	ldr	w11, [x1, #8]
	ldr	w12, [x1, #12]
	ldr	w13, [x1, #16]
	ldr	w14, [x1, #20]
	ldr	w15, [x1, #24]
	ldr	w16, [x1, #28]
	ldr	w17, [x1, #32]
	ldr	w19, [x1, #36]
	ldr	w20, [x1, #40]
	ldr	w21, [x1, #44]
	ldr	w22, [x1, #48]
	ldr	w23, [x1, #52]
	ldr	w24, [x1, #56]
	ldr	w25, [x1, #60]
	# Reverse W
	rev	w9, w9
	rev	w10, w10
	rev	w11, w11
	rev	w12, w12
	rev	w13, w13
	rev	w14, w14
	rev	w15, w15
	rev	w16, w16
	rev	w17, w17
	rev	w19, w19
	rev	w20, w20
	rev	w21, w21
	rev	w22, w22
	rev	w23, w23
	rev	w24, w24
	rev	w25, w25
	ldr	w28, [x3]
	# Round 0
	add	w8, w8, w9
	add	w8, w8, w28
	and	w26, w5, w6
	bic	w27, w7, w5
	add	w8, w8, w26
	add	w8, w8, w27
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w23, w17
	eor	w26, w26, w11
	eor	w26, w26, w9
	ror	w9, w26, #31
	# Round 1
	add	w7, w7, w10
	add	w7, w7, w28
	and	w26, w4, w5
	bic	w27, w6, w4
	add	w7, w7, w26
	add	w7, w7, w27
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w24, w19
	eor	w26, w26, w12
	eor	w26, w26, w10
	ror	w10, w26, #31
	# Round 2
	add	w6, w6, w11
	add	w6, w6, w28
	and	w26, w8, w4
	bic	w27, w5, w8
	add	w6, w6, w26
	add	w6, w6, w27
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w25, w20
	eor	w26, w26, w13
	eor	w26, w26, w11
	ror	w11, w26, #31
	# Round 3
	add	w5, w5, w12
	add	w5, w5, w28
	and	w26, w7, w8
	bic	w27, w4, w7
	add	w5, w5, w26
	add	w5, w5, w27
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w9, w21
	eor	w26, w26, w14
	eor	w26, w26, w12
	ror	w12, w26, #31
	# Round 4
	add	w4, w4, w13
	add	w4, w4, w28
	and	w26, w6, w7
	bic	w27, w8, w6
	add	w4, w4, w26
	add	w4, w4, w27
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w10, w22
	eor	w26, w26, w15
	eor	w26, w26, w13
	ror	w13, w26, #31
	# Round 5
	add	w8, w8, w14
	add	w8, w8, w28
	and	w26, w5, w6
	bic	w27, w7, w5
	add	w8, w8, w26
	add	w8, w8, w27
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w11, w23
	eor	w26, w26, w16
	eor	w26, w26, w14
	ror	w14, w26, #31
	# Round 6
	add	w7, w7, w15
	add	w7, w7, w28
	and	w26, w4, w5
	bic	w27, w6, w4
	add	w7, w7, w26
	add	w7, w7, w27
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w12, w24
	eor	w26, w26, w17
	eor	w26, w26, w15
	ror	w15, w26, #31
	# Round 7
	add	w6, w6, w16
	add	w6, w6, w28
	and	w26, w8, w4
	bic	w27, w5, w8
	add	w6, w6, w26
	add	w6, w6, w27
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w13, w25
	eor	w26, w26, w19
	eor	w26, w26, w16
	ror	w16, w26, #31
	# Round 8
	add	w5, w5, w17
	add	w5, w5, w28
	and	w26, w7, w8
	bic	w27, w4, w7
	add	w5, w5, w26
	add	w5, w5, w27
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w14, w9
	eor	w26, w26, w20
	eor	w26, w26, w17
	ror	w17, w26, #31
	# Round 9
	add	w4, w4, w19
	add	w4, w4, w28
	and	w26, w6, w7
	bic	w27, w8, w6
	add	w4, w4, w26
	add	w4, w4, w27
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w15, w10
	eor	w26, w26, w21
	eor	w26, w26, w19
	ror	w19, w26, #31
	# Round 10
	add	w8, w8, w20
	add	w8, w8, w28
	and	w26, w5, w6
	bic	w27, w7, w5
	add	w8, w8, w26
	add	w8, w8, w27
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w16, w11
	eor	w26, w26, w22
	eor	w26, w26, w20
	ror	w20, w26, #31
	# Round 11
	add	w7, w7, w21
	add	w7, w7, w28
	and	w26, w4, w5
	bic	w27, w6, w4
	add	w7, w7, w26
	add	w7, w7, w27
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w17, w12
	eor	w26, w26, w23
	eor	w26, w26, w21
	ror	w21, w26, #31
	# Round 12
	add	w6, w6, w22
	add	w6, w6, w28
	and	w26, w8, w4
	bic	w27, w5, w8
	add	w6, w6, w26
	add	w6, w6, w27
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w19, w13
	eor	w26, w26, w24
	eor	w26, w26, w22
	ror	w22, w26, #31
	# Round 13
	add	w5, w5, w23
	add	w5, w5, w28
	and	w26, w7, w8
	bic	w27, w4, w7
	add	w5, w5, w26
	add	w5, w5, w27
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w20, w14
	eor	w26, w26, w25
	eor	w26, w26, w23
	ror	w23, w26, #31
	# Round 14
	add	w4, w4, w24
	add	w4, w4, w28
	and	w26, w6, w7
	bic	w27, w8, w6
	add	w4, w4, w26
	add	w4, w4, w27
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w21, w15
	eor	w26, w26, w9
	eor	w26, w26, w24
	ror	w24, w26, #31
	# Round 15
	add	w8, w8, w25
	add	w8, w8, w28
	and	w26, w5, w6
	bic	w27, w7, w5
	add	w8, w8, w26
	add	w8, w8, w27
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w22, w16
	eor	w26, w26, w10
	eor	w26, w26, w25
	ror	w25, w26, #31
	# Round 16
	add	w7, w7, w9
	add	w7, w7, w28
	and	w26, w4, w5
	bic	w27, w6, w4
	add	w7, w7, w26
	add	w7, w7, w27
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w23, w17
	eor	w26, w26, w11
	eor	w26, w26, w9
	ror	w9, w26, #31
	# Round 17
	add	w6, w6, w10
	add	w6, w6, w28
	and	w26, w8, w4
	bic	w27, w5, w8
	add	w6, w6, w26
	add	w6, w6, w27
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w24, w19
	eor	w26, w26, w12
	eor	w26, w26, w10
	ror	w10, w26, #31
	# Round 18
	add	w5, w5, w11
	add	w5, w5, w28
	and	w26, w7, w8
	bic	w27, w4, w7
	add	w5, w5, w26
	add	w5, w5, w27
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w25, w20
	eor	w26, w26, w13
	eor	w26, w26, w11
	ror	w11, w26, #31
	# Round 19
	add	w4, w4, w12
	add	w4, w4, w28
	and	w26, w6, w7
	bic	w27, w8, w6
	add	w4, w4, w26
	add	w4, w4, w27
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w9, w21
	eor	w26, w26, w14
	eor	w26, w26, w12
	ror	w12, w26, #31
	ldr	w28, [x3, #4]
	# Round 20
	add	w8, w8, w13
	add	w8, w8, w28
	eor	w26, w6, w7
	eor	w26, w26, w5
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w10, w22
	eor	w26, w26, w15
	eor	w26, w26, w13
	ror	w13, w26, #31
	# Round 21
	add	w7, w7, w14
	add	w7, w7, w28
	eor	w26, w5, w6
	eor	w26, w26, w4
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w11, w23
	eor	w26, w26, w16
	eor	w26, w26, w14
	ror	w14, w26, #31
	# Round 22
	add	w6, w6, w15
	add	w6, w6, w28
	eor	w26, w4, w5
	eor	w26, w26, w8
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w12, w24
	eor	w26, w26, w17
	eor	w26, w26, w15
	ror	w15, w26, #31
	# Round 23
	add	w5, w5, w16
	add	w5, w5, w28
	eor	w26, w8, w4
	eor	w26, w26, w7
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w13, w25
	eor	w26, w26, w19
	eor	w26, w26, w16
	ror	w16, w26, #31
	# Round 24
	add	w4, w4, w17
	add	w4, w4, w28
	eor	w26, w7, w8
	eor	w26, w26, w6
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w14, w9
	eor	w26, w26, w20
	eor	w26, w26, w17
	ror	w17, w26, #31
	# Round 25
	add	w8, w8, w19
	add	w8, w8, w28
	eor	w26, w6, w7
	eor	w26, w26, w5
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w15, w10
	eor	w26, w26, w21
	eor	w26, w26, w19
	ror	w19, w26, #31
	# Round 26
	add	w7, w7, w20
	add	w7, w7, w28
	eor	w26, w5, w6
	eor	w26, w26, w4
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w16, w11
	eor	w26, w26, w22
	eor	w26, w26, w20
	ror	w20, w26, #31
	# Round 27
	add	w6, w6, w21
	add	w6, w6, w28
	eor	w26, w4, w5
	eor	w26, w26, w8
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w17, w12
	eor	w26, w26, w23
	eor	w26, w26, w21
	ror	w21, w26, #31
	# Round 28
	add	w5, w5, w22
	add	w5, w5, w28
	eor	w26, w8, w4
	eor	w26, w26, w7
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w19, w13
	eor	w26, w26, w24
	eor	w26, w26, w22
	ror	w22, w26, #31
	# Round 29
	add	w4, w4, w23
	add	w4, w4, w28
	eor	w26, w7, w8
	eor	w26, w26, w6
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w20, w14
	eor	w26, w26, w25
	eor	w26, w26, w23
	ror	w23, w26, #31
	# Round 30
	add	w8, w8, w24
	add	w8, w8, w28
	eor	w26, w6, w7
	eor	w26, w26, w5
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w21, w15
	eor	w26, w26, w9
	eor	w26, w26, w24
	ror	w24, w26, #31
	# Round 31
	add	w7, w7, w25
	add	w7, w7, w28
	eor	w26, w5, w6
	eor	w26, w26, w4
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w22, w16
	eor	w26, w26, w10
	eor	w26, w26, w25
	ror	w25, w26, #31
	# Round 32
	add	w6, w6, w9
	add	w6, w6, w28
	eor	w26, w4, w5
	eor	w26, w26, w8
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w23, w17
	eor	w26, w26, w11
	eor	w26, w26, w9
	ror	w9, w26, #31
	# Round 33
	add	w5, w5, w10
	add	w5, w5, w28
	eor	w26, w8, w4
	eor	w26, w26, w7
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w24, w19
	eor	w26, w26, w12
	eor	w26, w26, w10
	ror	w10, w26, #31
	# Round 34
	add	w4, w4, w11
	add	w4, w4, w28
	eor	w26, w7, w8
	eor	w26, w26, w6
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w25, w20
	eor	w26, w26, w13
	eor	w26, w26, w11
	ror	w11, w26, #31
	# Round 35
	add	w8, w8, w12
	add	w8, w8, w28
	eor	w26, w6, w7
	eor	w26, w26, w5
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w9, w21
	eor	w26, w26, w14
	eor	w26, w26, w12
	ror	w12, w26, #31
	# Round 36
	add	w7, w7, w13
	add	w7, w7, w28
	eor	w26, w5, w6
	eor	w26, w26, w4
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w10, w22
	eor	w26, w26, w15
	eor	w26, w26, w13
	ror	w13, w26, #31
	# Round 37
	add	w6, w6, w14
	add	w6, w6, w28
	eor	w26, w4, w5
	eor	w26, w26, w8
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w11, w23
	eor	w26, w26, w16
	eor	w26, w26, w14
	ror	w14, w26, #31
	# Round 38
	add	w5, w5, w15
	add	w5, w5, w28
	eor	w26, w8, w4
	eor	w26, w26, w7
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w12, w24
	eor	w26, w26, w17
	eor	w26, w26, w15
	ror	w15, w26, #31
	# Round 39
	add	w4, w4, w16
	add	w4, w4, w28
	eor	w26, w7, w8
	eor	w26, w26, w6
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w13, w25
	eor	w26, w26, w19
	eor	w26, w26, w16
	ror	w16, w26, #31
	ldr	w28, [x3, #8]
	# Round 40
	add	w8, w8, w17
	add	w8, w8, w28
	orr	w26, w6, w7
	and	w27, w6, w7
	and	w26, w26, w5
	orr	w26, w26, w27
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w14, w9
	eor	w26, w26, w20
	eor	w26, w26, w17
	ror	w17, w26, #31
	# Round 41
	add	w7, w7, w19
	add	w7, w7, w28
	orr	w26, w5, w6
	and	w27, w5, w6
	and	w26, w26, w4
	orr	w26, w26, w27
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w15, w10
	eor	w26, w26, w21
	eor	w26, w26, w19
	ror	w19, w26, #31
	# Round 42
	add	w6, w6, w20
	add	w6, w6, w28
	orr	w26, w4, w5
	and	w27, w4, w5
	and	w26, w26, w8
	orr	w26, w26, w27
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w16, w11
	eor	w26, w26, w22
	eor	w26, w26, w20
	ror	w20, w26, #31
	# Round 43
	add	w5, w5, w21
	add	w5, w5, w28
	orr	w26, w8, w4
	and	w27, w8, w4
	and	w26, w26, w7
	orr	w26, w26, w27
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w17, w12
	eor	w26, w26, w23
	eor	w26, w26, w21
	ror	w21, w26, #31
	# Round 44
	add	w4, w4, w22
	add	w4, w4, w28
	orr	w26, w7, w8
	and	w27, w7, w8
	and	w26, w26, w6
	orr	w26, w26, w27
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w19, w13
	eor	w26, w26, w24
	eor	w26, w26, w22
	ror	w22, w26, #31
	# Round 45
	add	w8, w8, w23
	add	w8, w8, w28
	orr	w26, w6, w7
	and	w27, w6, w7
	and	w26, w26, w5
	orr	w26, w26, w27
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w20, w14
	eor	w26, w26, w25
	eor	w26, w26, w23
	ror	w23, w26, #31
	# Round 46
	add	w7, w7, w24
	add	w7, w7, w28
	orr	w26, w5, w6
	and	w27, w5, w6
	and	w26, w26, w4
	orr	w26, w26, w27
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w21, w15
	eor	w26, w26, w9
	eor	w26, w26, w24
	ror	w24, w26, #31
	# Round 47
	add	w6, w6, w25
	add	w6, w6, w28
	orr	w26, w4, w5
	and	w27, w4, w5
	and	w26, w26, w8
	orr	w26, w26, w27
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w22, w16
	eor	w26, w26, w10
	eor	w26, w26, w25
	ror	w25, w26, #31
	# Round 48
	add	w5, w5, w9
	add	w5, w5, w28
	orr	w26, w8, w4
	and	w27, w8, w4
	and	w26, w26, w7
	orr	w26, w26, w27
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w23, w17
	eor	w26, w26, w11
	eor	w26, w26, w9
	ror	w9, w26, #31
	# Round 49
	add	w4, w4, w10
	add	w4, w4, w28
	orr	w26, w7, w8
	and	w27, w7, w8
	and	w26, w26, w6
	orr	w26, w26, w27
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w24, w19
	eor	w26, w26, w12
	eor	w26, w26, w10
	ror	w10, w26, #31
	# Round 50
	add	w8, w8, w11
	add	w8, w8, w28
	orr	w26, w6, w7
	and	w27, w6, w7
	and	w26, w26, w5
	orr	w26, w26, w27
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w25, w20
	eor	w26, w26, w13
	eor	w26, w26, w11
	ror	w11, w26, #31
	# Round 51
	add	w7, w7, w12
	add	w7, w7, w28
	orr	w26, w5, w6
	and	w27, w5, w6
	and	w26, w26, w4
	orr	w26, w26, w27
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w9, w21
	eor	w26, w26, w14
	eor	w26, w26, w12
	ror	w12, w26, #31
	# Round 52
	add	w6, w6, w13
	add	w6, w6, w28
	orr	w26, w4, w5
	and	w27, w4, w5
	and	w26, w26, w8
	orr	w26, w26, w27
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w10, w22
	eor	w26, w26, w15
	eor	w26, w26, w13
	ror	w13, w26, #31
	# Round 53
	add	w5, w5, w14
	add	w5, w5, w28
	orr	w26, w8, w4
	and	w27, w8, w4
	and	w26, w26, w7
	orr	w26, w26, w27
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w11, w23
	eor	w26, w26, w16
	eor	w26, w26, w14
	ror	w14, w26, #31
	# Round 54
	add	w4, w4, w15
	add	w4, w4, w28
	orr	w26, w7, w8
	and	w27, w7, w8
	and	w26, w26, w6
	orr	w26, w26, w27
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w12, w24
	eor	w26, w26, w17
	eor	w26, w26, w15
	ror	w15, w26, #31
	# Round 55
	add	w8, w8, w16
	add	w8, w8, w28
	orr	w26, w6, w7
	and	w27, w6, w7
	and	w26, w26, w5
	orr	w26, w26, w27
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w13, w25
	eor	w26, w26, w19
	eor	w26, w26, w16
	ror	w16, w26, #31
	# Round 56
	add	w7, w7, w17
	add	w7, w7, w28
	orr	w26, w5, w6
	and	w27, w5, w6
	and	w26, w26, w4
	orr	w26, w26, w27
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w14, w9
	eor	w26, w26, w20
	eor	w26, w26, w17
	ror	w17, w26, #31
	# Round 57
	add	w6, w6, w19
	add	w6, w6, w28
	orr	w26, w4, w5
	and	w27, w4, w5
	and	w26, w26, w8
	orr	w26, w26, w27
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w15, w10
	eor	w26, w26, w21
	eor	w26, w26, w19
	ror	w19, w26, #31
	# Round 58
	add	w5, w5, w20
	add	w5, w5, w28
	orr	w26, w8, w4
	and	w27, w8, w4
	and	w26, w26, w7
	orr	w26, w26, w27
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w16, w11
	eor	w26, w26, w22
	eor	w26, w26, w20
	ror	w20, w26, #31
	# Round 59
	add	w4, w4, w21
	add	w4, w4, w28
	orr	w26, w7, w8
	and	w27, w7, w8
	and	w26, w26, w6
	orr	w26, w26, w27
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w17, w12
	eor	w26, w26, w23
	eor	w26, w26, w21
	ror	w21, w26, #31
	ldr	w28, [x3, #12]
	# Round 60
	add	w8, w8, w22
	add	w8, w8, w28
	eor	w26, w6, w7
	eor	w26, w26, w5
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w19, w13
	eor	w26, w26, w24
	eor	w26, w26, w22
	ror	w22, w26, #31
	# Round 61
	add	w7, w7, w23
	add	w7, w7, w28
	eor	w26, w5, w6
	eor	w26, w26, w4
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w20, w14
	eor	w26, w26, w25
	eor	w26, w26, w23
	ror	w23, w26, #31
	# Round 62
	add	w6, w6, w24
	add	w6, w6, w28
	eor	w26, w4, w5
	eor	w26, w26, w8
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w21, w15
	eor	w26, w26, w9
	eor	w26, w26, w24
	ror	w24, w26, #31
	# Round 63
	add	w5, w5, w25
	add	w5, w5, w28
	eor	w26, w8, w4
	eor	w26, w26, w7
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w22, w16
	eor	w26, w26, w10
	eor	w26, w26, w25
	ror	w25, w26, #31
	# Round 64
	add	w4, w4, w9
	add	w4, w4, w28
	eor	w26, w7, w8
	eor	w26, w26, w6
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	# Round 65
	add	w8, w8, w10
	add	w8, w8, w28
	eor	w26, w6, w7
	eor	w26, w26, w5
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	# Round 66
	add	w7, w7, w11
	add	w7, w7, w28
	eor	w26, w5, w6
	eor	w26, w26, w4
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	# Round 67
	add	w6, w6, w12
	add	w6, w6, w28
	eor	w26, w4, w5
	eor	w26, w26, w8
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	# Round 68
	add	w5, w5, w13
	add	w5, w5, w28
	eor	w26, w8, w4
	eor	w26, w26, w7
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	# Round 69
	add	w4, w4, w14
	add	w4, w4, w28
	eor	w26, w7, w8
	eor	w26, w26, w6
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	# Round 70
	add	w8, w8, w15
	add	w8, w8, w28
	eor	w26, w6, w7
	eor	w26, w26, w5
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	# Round 71
	add	w7, w7, w16
	add	w7, w7, w28
	eor	w26, w5, w6
	eor	w26, w26, w4
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	# Round 72
	add	w6, w6, w17
	add	w6, w6, w28
	eor	w26, w4, w5
	eor	w26, w26, w8
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	# Round 73
	add	w5, w5, w19
	add	w5, w5, w28
	eor	w26, w8, w4
	eor	w26, w26, w7
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	# Round 74
	add	w4, w4, w20
	add	w4, w4, w28
	eor	w26, w7, w8
	eor	w26, w26, w6
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	# Round 75
	add	w8, w8, w21
	add	w8, w8, w28
	eor	w26, w6, w7
	eor	w26, w26, w5
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	# Round 76
	add	w7, w7, w22
	add	w7, w7, w28
	eor	w26, w5, w6
	eor	w26, w26, w4
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	# Round 77
	add	w6, w6, w23
	add	w6, w6, w28
	eor	w26, w4, w5
	eor	w26, w26, w8
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	# Round 78
	add	w5, w5, w24
	add	w5, w5, w28
	eor	w26, w8, w4
	eor	w26, w26, w7
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	# Round 79
	add	w4, w4, w25
	add	w4, w4, w28
	eor	w26, w7, w8
	eor	w26, w26, w6
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	# Add in digest from start of block
	ldr	w9, [x0]
	ldr	w10, [x0, #4]
	ldr	w11, [x0, #8]
	ldr	w12, [x0, #12]
	ldr	w13, [x0, #16]
	add	w4, w4, w9
	add	w5, w5, w10
	add	w6, w6, w11
	add	w7, w7, w12
	add	w8, w8, w13
	# Store digest
	str	w4, [x0]
	str	w5, [x0, #4]
	str	w6, [x0, #8]
	str	w7, [x0, #12]
	str	w8, [x0, #16]
	add	x1, x1, #0x40
	subs	w2, w2, #0x40
	bne	L_sha1_len_base_begin
	ldp	x17, x19, [x29, #24]
	ldp	x20, x21, [x29, #40]
	ldp	x22, x23, [x29, #56]
	ldp	x24, x25, [x29, #72]
	ldp	x26, x27, [x29, #88]
	ldr	x28, [x29, #104]
	ldp	x29, x30, [sp], #0x70
	ret
#ifndef __APPLE__
	.size	Transform_Sha_Len_base,.-Transform_Sha_Len_base
#endif /* __APPLE__ */
#endif /* !WOLFSSL_ARMASM_NO_BASE_IMPL || WOLFSSL_ARMASM_NO_NEON */
#ifndef WOLFSSL_ARMASM_NO_NEON
#if !defined(WOLFSSL_ARMASM_NO_NEON_IMPL) || defined(WOLFSSL_ARMASM_NO_HW_CRYPTO)
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_SHA1_trans_neon_len_k, %object
	.size	L_SHA1_trans_neon_len_k, 64
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_SHA1_trans_neon_len_k:
	.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999
	.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1
	.long	0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc
	.long	0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6
#ifndef __APPLE__
.text
.globl	Transform_Sha_Len_neon
WC_ASM_ATT_HIDDEN(Transform_Sha_Len_neon)
.type	Transform_Sha_Len_neon,@function
.align	2
Transform_Sha_Len_neon:
#else
.section	__TEXT,__text
.globl	_Transform_Sha_Len_neon
WC_ASM_ATT_HIDDEN(_Transform_Sha_Len_neon)
.p2align	2
_Transform_Sha_Len_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-112]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #88]
	str	x20, [x29, #104]
#ifndef __APPLE__
	adrp x3, L_SHA1_trans_neon_len_k
	add  x3, x3, :lo12:L_SHA1_trans_neon_len_k
#else
	adrp x3, L_SHA1_trans_neon_len_k@PAGE
	add  x3, x3, L_SHA1_trans_neon_len_k@PAGEOFF
#endif /* __APPLE__ */
	# Load K into vector registers
	ld1	{v16.4s, v17.4s, v18.4s, v19.4s}, [x3]
	movi	v24.4s, #0
	# Load digest into working vars
	ldr	w4, [x0]
	ldr	w5, [x0, #4]
	ldr	w6, [x0, #8]
	ldr	w7, [x0, #12]
	ldr	w8, [x0, #16]
	# Start of loop processing a block
L_sha1_len_neon_begin:
	# Load W
	ld1	{v0.4s, v1.4s, v2.4s, v3.4s}, [x1], #0x40
	# Copy digest to add in at end
	mov	w15, w4
	mov	w16, w5
	mov	w17, w6
	mov	w19, w7
	mov	w20, w8
	rev32	v0.16b, v0.16b
	rev32	v1.16b, v1.16b
	rev32	v2.16b, v2.16b
	rev32	v3.16b, v3.16b
	# W+K for the first two groups
	add	v20.4s, v0.4s, v16.4s
	str	q20, [x29, #16]
	add	v20.4s, v1.4s, v16.4s
	str	q20, [x29, #32]
	ldp	w11, w12, [x29, #16]
	# Round 0
	ldp	w13, w14, [x29, #24]
	# Calc new W[16]-W[19]
	ext	v21.16b, v0.16b, v1.16b, #8
	add	w8, w8, w11
	eor	v21.16b, v21.16b, v0.16b
	and	w9, w5, w6
	eor	v21.16b, v21.16b, v2.16b
	bic	w10, w7, w5
	ext	v22.16b, v3.16b, v24.16b, #4
	add	w8, w8, w9
	eor	v21.16b, v21.16b, v22.16b
	add	w8, w8, w10
	shl	v4.4s, v21.4s, #1
	ror	w9, w4, #27
	sri	v4.4s, v21.4s, #31
	add	w8, w8, w9
	ext	v22.16b, v24.16b, v4.16b, #4
	ror	w5, w5, #2
	shl	v23.4s, v22.4s, #1
	# Round 1
	sri	v23.4s, v22.4s, #31
	add	w7, w7, w12
	eor	v4.16b, v4.16b, v23.16b
	and	w9, w4, w5
	# W+K for rounds 8-11
	add	v20.4s, v2.4s, v16.4s
	bic	w10, w6, w4
	str	q20, [x29, #48]
	add	w7, w7, w9
	add	w7, w7, w10
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	# Round 2
	ldp	w11, w12, [x29, #32]
	add	w6, w6, w13
	and	w9, w8, w4
	bic	w10, w5, w8
	add	w6, w6, w9
	add	w6, w6, w10
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	# Round 3
	add	w5, w5, w14
	and	w9, w7, w8
	bic	w10, w4, w7
	add	w5, w5, w9
	add	w5, w5, w10
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	# Round 4
	ldp	w13, w14, [x29, #40]
	# Calc new W[20]-W[23]
	ext	v21.16b, v1.16b, v2.16b, #8
	add	w4, w4, w11
	eor	v21.16b, v21.16b, v1.16b
	and	w9, w6, w7
	eor	v21.16b, v21.16b, v3.16b
	bic	w10, w8, w6
	ext	v22.16b, v4.16b, v24.16b, #4
	add	w4, w4, w9
	eor	v21.16b, v21.16b, v22.16b
	add	w4, w4, w10
	shl	v5.4s, v21.4s, #1
	ror	w9, w5, #27
	sri	v5.4s, v21.4s, #31
	add	w4, w4, w9
	ext	v22.16b, v24.16b, v5.16b, #4
	ror	w6, w6, #2
	shl	v23.4s, v22.4s, #1
	# Round 5
	sri	v23.4s, v22.4s, #31
	add	w8, w8, w12
	eor	v5.16b, v5.16b, v23.16b
	and	w9, w5, w6
	# W+K for rounds 12-15
	add	v20.4s, v3.4s, v16.4s
	bic	w10, w7, w5
	str	q20, [x29, #64]
	add	w8, w8, w9
	add	w8, w8, w10
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	# Round 6
	ldp	w11, w12, [x29, #48]
	add	w7, w7, w13
	and	w9, w4, w5
	bic	w10, w6, w4
	add	w7, w7, w9
	add	w7, w7, w10
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	# Round 7
	add	w6, w6, w14
	and	w9, w8, w4
	bic	w10, w5, w8
	add	w6, w6, w9
	add	w6, w6, w10
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	# Round 8
	ldp	w13, w14, [x29, #56]
	# Calc new W[24]-W[27]
	ext	v21.16b, v2.16b, v3.16b, #8
	add	w5, w5, w11
	eor	v21.16b, v21.16b, v2.16b
	and	w9, w7, w8
	eor	v21.16b, v21.16b, v4.16b
	bic	w10, w4, w7
	ext	v22.16b, v5.16b, v24.16b, #4
	add	w5, w5, w9
	eor	v21.16b, v21.16b, v22.16b
	add	w5, w5, w10
	shl	v6.4s, v21.4s, #1
	ror	w9, w6, #27
	sri	v6.4s, v21.4s, #31
	add	w5, w5, w9
	ext	v22.16b, v24.16b, v6.16b, #4
	ror	w7, w7, #2
	shl	v23.4s, v22.4s, #1
	# Round 9
	sri	v23.4s, v22.4s, #31
	add	w4, w4, w12
	eor	v6.16b, v6.16b, v23.16b
	and	w9, w6, w7
	# W+K for rounds 16-19
	add	v20.4s, v4.4s, v16.4s
	bic	w10, w8, w6
	str	q20, [x29, #16]
	add	w4, w4, w9
	add	w4, w4, w10
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	# Round 10
	ldp	w11, w12, [x29, #64]
	add	w8, w8, w13
	and	w9, w5, w6
	bic	w10, w7, w5
	add	w8, w8, w9
	add	w8, w8, w10
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	# Round 11
	add	w7, w7, w14
	and	w9, w4, w5
	bic	w10, w6, w4
	add	w7, w7, w9
	add	w7, w7, w10
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	# Round 12
	ldp	w13, w14, [x29, #72]
	# Calc new W[28]-W[31]
	ext	v21.16b, v3.16b, v4.16b, #8
	add	w6, w6, w11
	eor	v21.16b, v21.16b, v3.16b
	and	w9, w8, w4
	eor	v21.16b, v21.16b, v5.16b
	bic	w10, w5, w8
	ext	v22.16b, v6.16b, v24.16b, #4
	add	w6, w6, w9
	eor	v21.16b, v21.16b, v22.16b
	add	w6, w6, w10
	shl	v7.4s, v21.4s, #1
	ror	w9, w7, #27
	sri	v7.4s, v21.4s, #31
	add	w6, w6, w9
	ext	v22.16b, v24.16b, v7.16b, #4
	ror	w8, w8, #2
	shl	v23.4s, v22.4s, #1
	# Round 13
	sri	v23.4s, v22.4s, #31
	add	w5, w5, w12
	eor	v7.16b, v7.16b, v23.16b
	and	w9, w7, w8
	# W+K for rounds 20-23
	add	v20.4s, v5.4s, v17.4s
	bic	w10, w4, w7
	str	q20, [x29, #32]
	add	w5, w5, w9
	add	w5, w5, w10
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	# Round 14
	ldp	w11, w12, [x29, #16]
	add	w4, w4, w13
	and	w9, w6, w7
	bic	w10, w8, w6
	add	w4, w4, w9
	add	w4, w4, w10
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	# Round 15
	add	w8, w8, w14
	and	w9, w5, w6
	bic	w10, w7, w5
	add	w8, w8, w9
	add	w8, w8, w10
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	# Round 16
	ldp	w13, w14, [x29, #24]
	# Calc new W[32]-W[35]
	ext	v21.16b, v6.16b, v7.16b, #8
	add	w7, w7, w11
	eor	v21.16b, v21.16b, v4.16b
	and	w9, w4, w5
	eor	v21.16b, v21.16b, v1.16b
	bic	w10, w6, w4
	eor	v21.16b, v21.16b, v0.16b
	add	w7, w7, w9
	shl	v0.4s, v21.4s, #2
	add	w7, w7, w10
	sri	v0.4s, v21.4s, #30
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	# Round 17
	add	w6, w6, w12
	and	w9, w8, w4
	# W+K for rounds 24-27
	add	v20.4s, v6.4s, v17.4s
	bic	w10, w5, w8
	str	q20, [x29, #48]
	add	w6, w6, w9
	add	w6, w6, w10
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	# Round 18
	ldp	w11, w12, [x29, #32]
	add	w5, w5, w13
	and	w9, w7, w8
	bic	w10, w4, w7
	add	w5, w5, w9
	add	w5, w5, w10
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	# Round 19
	add	w4, w4, w14
	and	w9, w6, w7
	bic	w10, w8, w6
	add	w4, w4, w9
	add	w4, w4, w10
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	# Round 20
	ldp	w13, w14, [x29, #40]
	# Calc new W[36]-W[39]
	ext	v21.16b, v7.16b, v0.16b, #8
	add	w8, w8, w11
	eor	v21.16b, v21.16b, v5.16b
	eor	w9, w6, w7
	eor	v21.16b, v21.16b, v2.16b
	eor	w9, w9, w5
	eor	v21.16b, v21.16b, v1.16b
	add	w8, w8, w9
	shl	v1.4s, v21.4s, #2
	ror	w9, w4, #27
	sri	v1.4s, v21.4s, #30
	add	w8, w8, w9
	ror	w5, w5, #2
	# Round 21
	add	w7, w7, w12
	eor	w9, w5, w6
	eor	w9, w9, w4
	# W+K for rounds 28-31
	add	v20.4s, v7.4s, v17.4s
	add	w7, w7, w9
	str	q20, [x29, #64]
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	# Round 22
	ldp	w11, w12, [x29, #48]
	add	w6, w6, w13
	eor	w9, w4, w5
	eor	w9, w9, w8
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	# Round 23
	add	w5, w5, w14
	eor	w9, w8, w4
	eor	w9, w9, w7
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	# Round 24
	ldp	w13, w14, [x29, #56]
	# Calc new W[40]-W[43]
	ext	v21.16b, v0.16b, v1.16b, #8
	add	w4, w4, w11
	eor	v21.16b, v21.16b, v6.16b
	eor	w9, w7, w8
	eor	v21.16b, v21.16b, v3.16b
	eor	w9, w9, w6
	eor	v21.16b, v21.16b, v2.16b
	add	w4, w4, w9
	shl	v2.4s, v21.4s, #2
	ror	w9, w5, #27
	sri	v2.4s, v21.4s, #30
	add	w4, w4, w9
	ror	w6, w6, #2
	# Round 25
	add	w8, w8, w12
	eor	w9, w6, w7
	eor	w9, w9, w5
	# W+K for rounds 32-35
	add	v20.4s, v0.4s, v17.4s
	add	w8, w8, w9
	str	q20, [x29, #16]
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	# Round 26
	ldp	w11, w12, [x29, #64]
	add	w7, w7, w13
	eor	w9, w5, w6
	eor	w9, w9, w4
	add	w7, w7, w9
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	# Round 27
	add	w6, w6, w14
	eor	w9, w4, w5
	eor	w9, w9, w8
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	# Round 28
	ldp	w13, w14, [x29, #72]
	# Calc new W[44]-W[47]
	ext	v21.16b, v1.16b, v2.16b, #8
	add	w5, w5, w11
	eor	v21.16b, v21.16b, v7.16b
	eor	w9, w8, w4
	eor	v21.16b, v21.16b, v4.16b
	eor	w9, w9, w7
	eor	v21.16b, v21.16b, v3.16b
	add	w5, w5, w9
	shl	v3.4s, v21.4s, #2
	ror	w9, w6, #27
	sri	v3.4s, v21.4s, #30
	add	w5, w5, w9
	ror	w7, w7, #2
	# Round 29
	add	w4, w4, w12
	eor	w9, w7, w8
	eor	w9, w9, w6
	# W+K for rounds 36-39
	add	v20.4s, v1.4s, v17.4s
	add	w4, w4, w9
	str	q20, [x29, #32]
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	# Round 30
	ldp	w11, w12, [x29, #16]
	add	w8, w8, w13
	eor	w9, w6, w7
	eor	w9, w9, w5
	add	w8, w8, w9
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	# Round 31
	add	w7, w7, w14
	eor	w9, w5, w6
	eor	w9, w9, w4
	add	w7, w7, w9
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	# Round 32
	ldp	w13, w14, [x29, #24]
	# Calc new W[48]-W[51]
	ext	v21.16b, v2.16b, v3.16b, #8
	add	w6, w6, w11
	eor	v21.16b, v21.16b, v0.16b
	eor	w9, w4, w5
	eor	v21.16b, v21.16b, v5.16b
	eor	w9, w9, w8
	eor	v21.16b, v21.16b, v4.16b
	add	w6, w6, w9
	shl	v4.4s, v21.4s, #2
	ror	w9, w7, #27
	sri	v4.4s, v21.4s, #30
	add	w6, w6, w9
	ror	w8, w8, #2
	# Round 33
	add	w5, w5, w12
	eor	w9, w8, w4
	eor	w9, w9, w7
	# W+K for rounds 40-43
	add	v20.4s, v2.4s, v18.4s
	add	w5, w5, w9
	str	q20, [x29, #48]
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	# Round 34
	ldp	w11, w12, [x29, #32]
	add	w4, w4, w13
	eor	w9, w7, w8
	eor	w9, w9, w6
	add	w4, w4, w9
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	# Round 35
	add	w8, w8, w14
	eor	w9, w6, w7
	eor	w9, w9, w5
	add	w8, w8, w9
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	# Round 36
	ldp	w13, w14, [x29, #40]
	# Calc new W[52]-W[55]
	ext	v21.16b, v3.16b, v4.16b, #8
	add	w7, w7, w11
	eor	v21.16b, v21.16b, v1.16b
	eor	w9, w5, w6
	eor	v21.16b, v21.16b, v6.16b
	eor	w9, w9, w4
	eor	v21.16b, v21.16b, v5.16b
	add	w7, w7, w9
	shl	v5.4s, v21.4s, #2
	ror	w9, w8, #27
	sri	v5.4s, v21.4s, #30
	add	w7, w7, w9
	ror	w4, w4, #2
	# Round 37
	add	w6, w6, w12
	eor	w9, w4, w5
	eor	w9, w9, w8
	# W+K for rounds 44-47
	add	v20.4s, v3.4s, v18.4s
	add	w6, w6, w9
	str	q20, [x29, #64]
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	# Round 38
	ldp	w11, w12, [x29, #48]
	add	w5, w5, w13
	eor	w9, w8, w4
	eor	w9, w9, w7
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	# Round 39
	add	w4, w4, w14
	eor	w9, w7, w8
	eor	w9, w9, w6
	add	w4, w4, w9
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	# Round 40
	ldp	w13, w14, [x29, #56]
	# Calc new W[56]-W[59]
	ext	v21.16b, v4.16b, v5.16b, #8
	add	w8, w8, w11
	eor	v21.16b, v21.16b, v2.16b
	orr	w9, w6, w7
	eor	v21.16b, v21.16b, v7.16b
	and	w10, w6, w7
	eor	v21.16b, v21.16b, v6.16b
	and	w9, w9, w5
	shl	v6.4s, v21.4s, #2
	orr	w9, w9, w10
	sri	v6.4s, v21.4s, #30
	add	w8, w8, w9
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	# Round 41
	add	w7, w7, w12
	# W+K for rounds 48-51
	add	v20.4s, v4.4s, v18.4s
	orr	w9, w5, w6
	str	q20, [x29, #16]
	and	w10, w5, w6
	and	w9, w9, w4
	orr	w9, w9, w10
	add	w7, w7, w9
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	# Round 42
	ldp	w11, w12, [x29, #64]
	add	w6, w6, w13
	orr	w9, w4, w5
	and	w10, w4, w5
	and	w9, w9, w8
	orr	w9, w9, w10
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	# Round 43
	add	w5, w5, w14
	orr	w9, w8, w4
	and	w10, w8, w4
	and	w9, w9, w7
	orr	w9, w9, w10
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	# Round 44
	ldp	w13, w14, [x29, #72]
	# Calc new W[60]-W[63]
	ext	v21.16b, v5.16b, v6.16b, #8
	add	w4, w4, w11
	eor	v21.16b, v21.16b, v3.16b
	orr	w9, w7, w8
	eor	v21.16b, v21.16b, v0.16b
	and	w10, w7, w8
	eor	v21.16b, v21.16b, v7.16b
	and	w9, w9, w6
	shl	v7.4s, v21.4s, #2
	orr	w9, w9, w10
	sri	v7.4s, v21.4s, #30
	add	w4, w4, w9
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	# Round 45
	add	w8, w8, w12
	# W+K for rounds 52-55
	add	v20.4s, v5.4s, v18.4s
	orr	w9, w6, w7
	str	q20, [x29, #32]
	and	w10, w6, w7
	and	w9, w9, w5
	orr	w9, w9, w10
	add	w8, w8, w9
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	# Round 46
	ldp	w11, w12, [x29, #16]
	add	w7, w7, w13
	orr	w9, w5, w6
	and	w10, w5, w6
	and	w9, w9, w4
	orr	w9, w9, w10
	add	w7, w7, w9
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	# Round 47
	add	w6, w6, w14
	orr	w9, w4, w5
	and	w10, w4, w5
	and	w9, w9, w8
	orr	w9, w9, w10
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	# Round 48
	ldp	w13, w14, [x29, #24]
	# Calc new W[64]-W[67]
	ext	v21.16b, v6.16b, v7.16b, #8
	add	w5, w5, w11
	eor	v21.16b, v21.16b, v4.16b
	orr	w9, w8, w4
	eor	v21.16b, v21.16b, v1.16b
	and	w10, w8, w4
	eor	v21.16b, v21.16b, v0.16b
	and	w9, w9, w7
	shl	v0.4s, v21.4s, #2
	orr	w9, w9, w10
	sri	v0.4s, v21.4s, #30
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	# Round 49
	add	w4, w4, w12
	# W+K for rounds 56-59
	add	v20.4s, v6.4s, v18.4s
	orr	w9, w7, w8
	str	q20, [x29, #48]
	and	w10, w7, w8
	and	w9, w9, w6
	orr	w9, w9, w10
	add	w4, w4, w9
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	# Round 50
	ldp	w11, w12, [x29, #32]
	add	w8, w8, w13
	orr	w9, w6, w7
	and	w10, w6, w7
	and	w9, w9, w5
	orr	w9, w9, w10
	add	w8, w8, w9
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	# Round 51
	add	w7, w7, w14
	orr	w9, w5, w6
	and	w10, w5, w6
	and	w9, w9, w4
	orr	w9, w9, w10
	add	w7, w7, w9
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	# Round 52
	ldp	w13, w14, [x29, #40]
	# Calc new W[68]-W[71]
	ext	v21.16b, v7.16b, v0.16b, #8
	add	w6, w6, w11
	eor	v21.16b, v21.16b, v5.16b
	orr	w9, w4, w5
	eor	v21.16b, v21.16b, v2.16b
	and	w10, w4, w5
	eor	v21.16b, v21.16b, v1.16b
	and	w9, w9, w8
	shl	v1.4s, v21.4s, #2
	orr	w9, w9, w10
	sri	v1.4s, v21.4s, #30
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	# Round 53
	add	w5, w5, w12
	# W+K for rounds 60-63
	add	v20.4s, v7.4s, v19.4s
	orr	w9, w8, w4
	str	q20, [x29, #64]
	and	w10, w8, w4
	and	w9, w9, w7
	orr	w9, w9, w10
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	# Round 54
	ldp	w11, w12, [x29, #48]
	add	w4, w4, w13
	orr	w9, w7, w8
	and	w10, w7, w8
	and	w9, w9, w6
	orr	w9, w9, w10
	add	w4, w4, w9
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	# Round 55
	add	w8, w8, w14
	orr	w9, w6, w7
	and	w10, w6, w7
	and	w9, w9, w5
	orr	w9, w9, w10
	add	w8, w8, w9
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	# Round 56
	ldp	w13, w14, [x29, #56]
	# Calc new W[72]-W[75]
	ext	v21.16b, v0.16b, v1.16b, #8
	add	w7, w7, w11
	eor	v21.16b, v21.16b, v6.16b
	orr	w9, w5, w6
	eor	v21.16b, v21.16b, v3.16b
	and	w10, w5, w6
	eor	v21.16b, v21.16b, v2.16b
	and	w9, w9, w4
	shl	v2.4s, v21.4s, #2
	orr	w9, w9, w10
	sri	v2.4s, v21.4s, #30
	add	w7, w7, w9
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	# Round 57
	add	w6, w6, w12
	# W+K for rounds 64-67
	add	v20.4s, v0.4s, v19.4s
	orr	w9, w4, w5
	str	q20, [x29, #16]
	and	w10, w4, w5
	and	w9, w9, w8
	orr	w9, w9, w10
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	# Round 58
	ldp	w11, w12, [x29, #64]
	add	w5, w5, w13
	orr	w9, w8, w4
	and	w10, w8, w4
	and	w9, w9, w7
	orr	w9, w9, w10
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	# Round 59
	add	w4, w4, w14
	orr	w9, w7, w8
	and	w10, w7, w8
	and	w9, w9, w6
	orr	w9, w9, w10
	add	w4, w4, w9
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	# Round 60
	ldp	w13, w14, [x29, #72]
	# Calc new W[76]-W[79]
	ext	v21.16b, v1.16b, v2.16b, #8
	add	w8, w8, w11
	eor	v21.16b, v21.16b, v7.16b
	eor	w9, w6, w7
	eor	v21.16b, v21.16b, v4.16b
	eor	w9, w9, w5
	eor	v21.16b, v21.16b, v3.16b
	add	w8, w8, w9
	shl	v3.4s, v21.4s, #2
	ror	w9, w4, #27
	sri	v3.4s, v21.4s, #30
	add	w8, w8, w9
	ror	w5, w5, #2
	# Round 61
	add	w7, w7, w12
	eor	w9, w5, w6
	eor	w9, w9, w4
	# W+K for rounds 68-71
	add	v20.4s, v1.4s, v19.4s
	add	w7, w7, w9
	str	q20, [x29, #32]
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	# Round 62
	ldp	w11, w12, [x29, #16]
	add	w6, w6, w13
	eor	w9, w4, w5
	eor	w9, w9, w8
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	# Round 63
	add	w5, w5, w14
	eor	w9, w8, w4
	eor	w9, w9, w7
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	# Round 64
	ldp	w13, w14, [x29, #24]
	add	w4, w4, w11
	eor	w9, w7, w8
	eor	w9, w9, w6
	add	w4, w4, w9
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	# Round 65
	add	w8, w8, w12
	eor	w9, w6, w7
	eor	w9, w9, w5
	# W+K for rounds 72-75
	add	v20.4s, v2.4s, v19.4s
	add	w8, w8, w9
	str	q20, [x29, #48]
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	# Round 66
	ldp	w11, w12, [x29, #32]
	add	w7, w7, w13
	eor	w9, w5, w6
	eor	w9, w9, w4
	add	w7, w7, w9
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	# Round 67
	add	w6, w6, w14
	eor	w9, w4, w5
	eor	w9, w9, w8
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	# Round 68
	ldp	w13, w14, [x29, #40]
	add	w5, w5, w11
	eor	w9, w8, w4
	eor	w9, w9, w7
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	# Round 69
	add	w4, w4, w12
	eor	w9, w7, w8
	eor	w9, w9, w6
	# W+K for rounds 76-79
	add	v20.4s, v3.4s, v19.4s
	add	w4, w4, w9
	str	q20, [x29, #64]
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	# Round 70
	ldp	w11, w12, [x29, #48]
	add	w8, w8, w13
	eor	w9, w6, w7
	eor	w9, w9, w5
	add	w8, w8, w9
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	# Round 71
	add	w7, w7, w14
	eor	w9, w5, w6
	eor	w9, w9, w4
	add	w7, w7, w9
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	# Round 72
	ldp	w13, w14, [x29, #56]
	add	w6, w6, w11
	eor	w9, w4, w5
	eor	w9, w9, w8
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	# Round 73
	add	w5, w5, w12
	eor	w9, w8, w4
	eor	w9, w9, w7
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	# Round 74
	ldp	w11, w12, [x29, #64]
	add	w4, w4, w13
	eor	w9, w7, w8
	eor	w9, w9, w6
	add	w4, w4, w9
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	# Round 75
	add	w8, w8, w14
	eor	w9, w6, w7
	eor	w9, w9, w5
	add	w8, w8, w9
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	# Round 76
	ldp	w13, w14, [x29, #72]
	add	w7, w7, w11
	eor	w9, w5, w6
	eor	w9, w9, w4
	add	w7, w7, w9
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	# Round 77
	add	w6, w6, w12
	eor	w9, w4, w5
	eor	w9, w9, w8
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	# Round 78
	add	w5, w5, w13
	eor	w9, w8, w4
	eor	w9, w9, w7
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	# Round 79
	add	w4, w4, w14
	eor	w9, w7, w8
	eor	w9, w9, w6
	add	w4, w4, w9
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	# Add in digest from start of block
	add	w4, w4, w15
	add	w5, w5, w16
	add	w6, w6, w17
	add	w7, w7, w19
	add	w8, w8, w20
	subs	w2, w2, #0x40
	bne	L_sha1_len_neon_begin
	# Store digest
	str	w4, [x0]
	str	w5, [x0, #4]
	str	w6, [x0, #8]
	str	w7, [x0, #12]
	str	w8, [x0, #16]
	ldp	x17, x19, [x29, #88]
	ldr	x20, [x29, #104]
	ldp	x29, x30, [sp], #0x70
	ret
#ifndef __APPLE__
	.size	Transform_Sha_Len_neon,.-Transform_Sha_Len_neon
#endif /* __APPLE__ */
#endif /* !WOLFSSL_ARMASM_NO_NEON_IMPL || WOLFSSL_ARMASM_NO_HW_CRYPTO */
#ifndef WOLFSSL_ARMASM_NO_HW_CRYPTO
.arch_extension crypto
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_SHA1_trans_crypto_len_k, %object
	.size	L_SHA1_trans_crypto_len_k, 64
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 8-byte aligned, 64-bit aligned
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_SHA1_trans_crypto_len_k:
	.long	0x5a827999,0x5a827999,0x5a827999,0x5a827999
	.long	0x6ed9eba1,0x6ed9eba1,0x6ed9eba1,0x6ed9eba1
	.long	0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc,0x8f1bbcdc
	.long	0xca62c1d6,0xca62c1d6,0xca62c1d6,0xca62c1d6
#ifndef __APPLE__
.text
.globl	Transform_Sha_Len_crypto
WC_ASM_ATT_HIDDEN(Transform_Sha_Len_crypto)
.type	Transform_Sha_Len_crypto,@function
.align	2
Transform_Sha_Len_crypto:
#else
.section	__TEXT,__text
.globl	_Transform_Sha_Len_crypto
WC_ASM_ATT_HIDDEN(_Transform_Sha_Len_crypto)
.p2align	2
_Transform_Sha_Len_crypto:
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_SHA1_trans_crypto_len_k
	add  x3, x3, :lo12:L_SHA1_trans_crypto_len_k
#else
	adrp x3, L_SHA1_trans_crypto_len_k@PAGE
	add  x3, x3, L_SHA1_trans_crypto_len_k@PAGEOFF
#endif /* __APPLE__ */
	# Load K into vector registers
	ld1	{v4.4s, v5.4s, v6.4s, v7.4s}, [x3]
	# Load digest into working vars
	ld1	{v16.4s}, [x0]
	ldr	s17, [x0, #16]
	# Start of loop processing a block
L_sha1_len_crypto_begin:
	# Load W
	ld1	{v0.4s, v1.4s, v2.4s, v3.4s}, [x1], #0x40
	rev32	v0.16b, v0.16b
	rev32	v1.16b, v1.16b
	rev32	v2.16b, v2.16b
	rev32	v3.16b, v3.16b
	# Copy digest to add in at end
	mov	v19.16b, v16.16b
	mov	v20.16b, v17.16b
	# Start 80 rounds
	add	v21.4s, v0.4s, v4.4s
	# Rounds 0-3
	sha1su0	v0.4s, v1.4s, v2.4s
	add	v22.4s, v1.4s, v4.4s
	sha1h	s18, s16
	sha1c	q16, s17, v21.4s
	sha1su1	v0.4s, v3.4s
	# Rounds 4-7
	sha1su0	v1.4s, v2.4s, v3.4s
	add	v21.4s, v2.4s, v4.4s
	sha1h	s17, s16
	sha1c	q16, s18, v22.4s
	sha1su1	v1.4s, v0.4s
	# Rounds 8-11
	sha1su0	v2.4s, v3.4s, v0.4s
	add	v22.4s, v3.4s, v4.4s
	sha1h	s18, s16
	sha1c	q16, s17, v21.4s
	sha1su1	v2.4s, v1.4s
	# Rounds 12-15
	sha1su0	v3.4s, v0.4s, v1.4s
	add	v21.4s, v0.4s, v4.4s
	sha1h	s17, s16
	sha1c	q16, s18, v22.4s
	sha1su1	v3.4s, v2.4s
	# Rounds 16-19
	sha1su0	v0.4s, v1.4s, v2.4s
	add	v22.4s, v1.4s, v5.4s
	sha1h	s18, s16
	sha1c	q16, s17, v21.4s
	sha1su1	v0.4s, v3.4s
	# Rounds 20-23
	sha1su0	v1.4s, v2.4s, v3.4s
	add	v21.4s, v2.4s, v5.4s
	sha1h	s17, s16
	sha1p	q16, s18, v22.4s
	sha1su1	v1.4s, v0.4s
	# Rounds 24-27
	sha1su0	v2.4s, v3.4s, v0.4s
	add	v22.4s, v3.4s, v5.4s
	sha1h	s18, s16
	sha1p	q16, s17, v21.4s
	sha1su1	v2.4s, v1.4s
	# Rounds 28-31
	sha1su0	v3.4s, v0.4s, v1.4s
	add	v21.4s, v0.4s, v5.4s
	sha1h	s17, s16
	sha1p	q16, s18, v22.4s
	sha1su1	v3.4s, v2.4s
	# Rounds 32-35
	sha1su0	v0.4s, v1.4s, v2.4s
	add	v22.4s, v1.4s, v5.4s
	sha1h	s18, s16
	sha1p	q16, s17, v21.4s
	sha1su1	v0.4s, v3.4s
	# Rounds 36-39
	sha1su0	v1.4s, v2.4s, v3.4s
	add	v21.4s, v2.4s, v6.4s
	sha1h	s17, s16
	sha1p	q16, s18, v22.4s
	sha1su1	v1.4s, v0.4s
	# Rounds 40-43
	sha1su0	v2.4s, v3.4s, v0.4s
	add	v22.4s, v3.4s, v6.4s
	sha1h	s18, s16
	sha1m	q16, s17, v21.4s
	sha1su1	v2.4s, v1.4s
	# Rounds 44-47
	sha1su0	v3.4s, v0.4s, v1.4s
	add	v21.4s, v0.4s, v6.4s
	sha1h	s17, s16
	sha1m	q16, s18, v22.4s
	sha1su1	v3.4s, v2.4s
	# Rounds 48-51
	sha1su0	v0.4s, v1.4s, v2.4s
	add	v22.4s, v1.4s, v6.4s
	sha1h	s18, s16
	sha1m	q16, s17, v21.4s
	sha1su1	v0.4s, v3.4s
	# Rounds 52-55
	sha1su0	v1.4s, v2.4s, v3.4s
	add	v21.4s, v2.4s, v6.4s
	sha1h	s17, s16
	sha1m	q16, s18, v22.4s
	sha1su1	v1.4s, v0.4s
	# Rounds 56-59
	sha1su0	v2.4s, v3.4s, v0.4s
	add	v22.4s, v3.4s, v7.4s
	sha1h	s18, s16
	sha1m	q16, s17, v21.4s
	sha1su1	v2.4s, v1.4s
	# Rounds 60-63
	sha1su0	v3.4s, v0.4s, v1.4s
	add	v21.4s, v0.4s, v7.4s
	sha1h	s17, s16
	sha1p	q16, s18, v22.4s
	sha1su1	v3.4s, v2.4s
	# Rounds 64-67
	add	v22.4s, v1.4s, v7.4s
	sha1h	s18, s16
	sha1p	q16, s17, v21.4s
	# Rounds 68-71
	add	v21.4s, v2.4s, v7.4s
	sha1h	s17, s16
	sha1p	q16, s18, v22.4s
	# Rounds 72-75
	add	v22.4s, v3.4s, v7.4s
	sha1h	s18, s16
	sha1p	q16, s17, v21.4s
	# Rounds 76-79
	sha1h	s17, s16
	sha1p	q16, s18, v22.4s
	# Done 80 rounds
	add	v16.4s, v16.4s, v19.4s
	add	v17.2s, v17.2s, v20.2s
	subs	w2, w2, #0x40
	bne	L_sha1_len_crypto_begin
	# Store digest back
	st1	{v16.4s}, [x0]
	str	s17, [x0, #16]
	ret
#ifndef __APPLE__
	.size	Transform_Sha_Len_crypto,.-Transform_Sha_Len_crypto
#endif /* __APPLE__ */
#endif /* !WOLFSSL_ARMASM_NO_HW_CRYPTO */
#endif /* !WOLFSSL_ARMASM_NO_NEON */
#endif /* !NO_SHA */
#endif /* __aarch64__ */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
