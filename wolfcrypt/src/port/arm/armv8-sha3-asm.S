/* armv8-sha3-asm
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
 *   ruby ./sha3/sha3.rb arm64 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-sha3-asm.S
 */

#define WC_FIPS_LL_CRYPTO
#define _WC_BUILDING_ARMV8_SHA3_ASM_S

#include <wolfssl/wolfcrypt/libwolfssl_sources_asm.h>

#ifdef WOLFSSL_ARMASM
#ifdef __aarch64__
#ifndef WOLFSSL_ARMASM_INLINE
#ifdef WOLFSSL_SHA3
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_SHA3_transform_crypto_r, %object
	.size	L_SHA3_transform_crypto_r, 192
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_SHA3_transform_crypto_r:
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
.globl	BlockSha3_crypto
WC_ASM_ATT_HIDDEN(BlockSha3_crypto)
.type	BlockSha3_crypto,@function
.align	2
BlockSha3_crypto:
#else
.section	__TEXT,__text
.globl	_BlockSha3_crypto
WC_ASM_ATT_HIDDEN(_BlockSha3_crypto)
.p2align	2
_BlockSha3_crypto:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x1, L_SHA3_transform_crypto_r
	add  x1, x1, :lo12:L_SHA3_transform_crypto_r
#else
	adrp x1, L_SHA3_transform_crypto_r@PAGE
	add  x1, x1, L_SHA3_transform_crypto_r@PAGEOFF
#endif /* __APPLE__ */
#ifdef __APPLE__
.arch_extension sha3
#endif /* __APPLE__ */
	ld4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	ld4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	ld4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	ld4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	ld4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	ld4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	ld1	{v24.1d}, [x0]
	sub	x0, x0, #0xc0
	mov	x2, #24
	# Start of 24 rounds
L_sha3_crypto_begin:
	# Col Mix
	eor3	v31.16b, v0.16b, v5.16b, v10.16b
	eor3	v27.16b, v1.16b, v6.16b, v11.16b
	eor3	v28.16b, v2.16b, v7.16b, v12.16b
	eor3	v29.16b, v3.16b, v8.16b, v13.16b
	eor3	v30.16b, v4.16b, v9.16b, v14.16b
	eor3	v31.16b, v31.16b, v15.16b, v20.16b
	eor3	v27.16b, v27.16b, v16.16b, v21.16b
	eor3	v28.16b, v28.16b, v17.16b, v22.16b
	eor3	v29.16b, v29.16b, v18.16b, v23.16b
	eor3	v30.16b, v30.16b, v19.16b, v24.16b
	rax1	v25.2d, v30.2d, v27.2d
	rax1	v26.2d, v31.2d, v28.2d
	rax1	v27.2d, v27.2d, v29.2d
	rax1	v28.2d, v28.2d, v30.2d
	rax1	v29.2d, v29.2d, v31.2d
	eor	v0.16b, v0.16b, v25.16b
	xar	v30.2d, v1.2d, v26.2d, #63
	xar	v1.2d, v6.2d, v26.2d, #20
	xar	v6.2d, v9.2d, v29.2d, #44
	xar	v9.2d, v22.2d, v27.2d, #3
	xar	v22.2d, v14.2d, v29.2d, #25
	xar	v14.2d, v20.2d, v25.2d, #46
	xar	v20.2d, v2.2d, v27.2d, #2
	xar	v2.2d, v12.2d, v27.2d, #21
	xar	v12.2d, v13.2d, v28.2d, #39
	xar	v13.2d, v19.2d, v29.2d, #56
	xar	v19.2d, v23.2d, v28.2d, #8
	xar	v23.2d, v15.2d, v25.2d, #23
	xar	v15.2d, v4.2d, v29.2d, #37
	xar	v4.2d, v24.2d, v29.2d, #50
	xar	v24.2d, v21.2d, v26.2d, #62
	xar	v21.2d, v8.2d, v28.2d, #9
	xar	v8.2d, v16.2d, v26.2d, #19
	xar	v16.2d, v5.2d, v25.2d, #28
	xar	v5.2d, v3.2d, v28.2d, #36
	xar	v3.2d, v18.2d, v28.2d, #43
	xar	v18.2d, v17.2d, v27.2d, #49
	xar	v17.2d, v11.2d, v26.2d, #54
	xar	v11.2d, v7.2d, v27.2d, #58
	xar	v7.2d, v10.2d, v25.2d, #61
	# Row Mix
	mov	v25.16b, v0.16b
	mov	v26.16b, v1.16b
	bcax	v0.16b, v25.16b, v2.16b, v26.16b
	bcax	v1.16b, v26.16b, v3.16b, v2.16b
	bcax	v2.16b, v2.16b, v4.16b, v3.16b
	bcax	v3.16b, v3.16b, v25.16b, v4.16b
	bcax	v4.16b, v4.16b, v26.16b, v25.16b
	mov	v25.16b, v5.16b
	mov	v26.16b, v6.16b
	bcax	v5.16b, v25.16b, v7.16b, v26.16b
	bcax	v6.16b, v26.16b, v8.16b, v7.16b
	bcax	v7.16b, v7.16b, v9.16b, v8.16b
	bcax	v8.16b, v8.16b, v25.16b, v9.16b
	bcax	v9.16b, v9.16b, v26.16b, v25.16b
	mov	v26.16b, v11.16b
	bcax	v10.16b, v30.16b, v12.16b, v26.16b
	bcax	v11.16b, v26.16b, v13.16b, v12.16b
	bcax	v12.16b, v12.16b, v14.16b, v13.16b
	bcax	v13.16b, v13.16b, v30.16b, v14.16b
	bcax	v14.16b, v14.16b, v26.16b, v30.16b
	mov	v25.16b, v15.16b
	mov	v26.16b, v16.16b
	bcax	v15.16b, v25.16b, v17.16b, v26.16b
	bcax	v16.16b, v26.16b, v18.16b, v17.16b
	bcax	v17.16b, v17.16b, v19.16b, v18.16b
	bcax	v18.16b, v18.16b, v25.16b, v19.16b
	bcax	v19.16b, v19.16b, v26.16b, v25.16b
	mov	v25.16b, v20.16b
	mov	v26.16b, v21.16b
	bcax	v20.16b, v25.16b, v22.16b, v26.16b
	bcax	v21.16b, v26.16b, v23.16b, v22.16b
	bcax	v22.16b, v22.16b, v24.16b, v23.16b
	bcax	v23.16b, v23.16b, v25.16b, v24.16b
	bcax	v24.16b, v24.16b, v26.16b, v25.16b
	ld1r	{v30.2d}, [x1], #8
	subs	x2, x2, #1
	eor	v0.16b, v0.16b, v30.16b
	bne	L_sha3_crypto_begin
	st4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	st1	{v24.1d}, [x0]
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	BlockSha3_crypto,.-BlockSha3_crypto
#endif /* __APPLE__ */
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef __APPLE__
	.text
	.section	.rodata
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
WC_ASM_ATT_HIDDEN(BlockSha3_base)
.type	BlockSha3_base,@function
.align	2
BlockSha3_base:
#else
.section	__TEXT,__text
.globl	_BlockSha3_base
WC_ASM_ATT_HIDDEN(_BlockSha3_base)
.p2align	2
_BlockSha3_base:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-160]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
#ifndef __APPLE__
	adrp x27, L_SHA3_transform_base_r
	add  x27, x27, :lo12:L_SHA3_transform_base_r
#else
	adrp x27, L_SHA3_transform_base_r@PAGE
	add  x27, x27, L_SHA3_transform_base_r@PAGEOFF
#endif /* __APPLE__ */
	ldp	x1, x2, [x0]
	ldp	x3, x4, [x0, #16]
	ldp	x5, x6, [x0, #32]
	ldp	x7, x8, [x0, #48]
	ldp	x9, x10, [x0, #64]
	ldp	x11, x12, [x0, #80]
	ldp	x13, x14, [x0, #96]
	ldp	x15, x16, [x0, #112]
	ldp	x17, x19, [x0, #128]
	ldp	x20, x21, [x0, #144]
	ldp	x22, x23, [x0, #160]
	ldp	x24, x25, [x0, #176]
	ldr	x26, [x0, #192]
	str	x0, [x29, #40]
	mov	x28, #24
	# Start of 24 rounds
L_SHA3_transform_base_begin:
	stp	x27, x28, [x29, #48]
	eor	x0, x5, x10
	eor	x30, x1, x6
	eor	x28, x3, x8
	eor	x0, x0, x15
	eor	x30, x30, x11
	eor	x28, x28, x13
	eor	x0, x0, x21
	eor	x30, x30, x16
	eor	x28, x28, x19
	eor	x0, x0, x26
	eor	x30, x30, x22
	eor	x28, x28, x24
	str	x0, [x29, #32]
	str	x28, [x29, #24]
	eor	x27, x2, x7
	eor	x28, x4, x9
	eor	x27, x27, x12
	eor	x28, x28, x14
	eor	x27, x27, x17
	eor	x28, x28, x20
	eor	x27, x27, x23
	eor	x28, x28, x25
	eor	x0, x0, x27, ror 63
	eor	x27, x27, x28, ror 63
	eor	x1, x1, x0
	eor	x6, x6, x0
	eor	x11, x11, x0
	eor	x16, x16, x0
	eor	x22, x22, x0
	eor	x3, x3, x27
	eor	x8, x8, x27
	eor	x13, x13, x27
	eor	x19, x19, x27
	eor	x24, x24, x27
	ldr	x0, [x29, #32]
	ldr	x27, [x29, #24]
	eor	x28, x28, x30, ror 63
	eor	x30, x30, x27, ror 63
	eor	x27, x27, x0, ror 63
	eor	x5, x5, x28
	eor	x10, x10, x28
	eor	x15, x15, x28
	eor	x21, x21, x28
	eor	x26, x26, x28
	eor	x2, x2, x30
	eor	x7, x7, x30
	eor	x12, x12, x30
	eor	x17, x17, x30
	eor	x23, x23, x30
	eor	x4, x4, x27
	eor	x9, x9, x27
	eor	x14, x14, x27
	eor	x20, x20, x27
	eor	x25, x25, x27
	# Swap Rotate
	ror	x0, x2, #63
	ror	x2, x7, #20
	ror	x7, x10, #44
	ror	x10, x24, #3
	ror	x24, x15, #25
	ror	x15, x22, #46
	ror	x22, x3, #2
	ror	x3, x13, #21
	ror	x13, x14, #39
	ror	x14, x21, #56
	ror	x21, x25, #8
	ror	x25, x16, #23
	ror	x16, x5, #37
	ror	x5, x26, #50
	ror	x26, x23, #62
	ror	x23, x9, #9
	ror	x9, x17, #19
	ror	x17, x6, #28
	ror	x6, x4, #36
	ror	x4, x20, #43
	ror	x20, x19, #49
	ror	x19, x12, #54
	ror	x12, x8, #58
	ror	x8, x11, #61
	# Row Mix
	bic	x11, x3, x2
	bic	x27, x4, x3
	bic	x28, x1, x5
	bic	x30, x2, x1
	eor	x1, x1, x11
	eor	x2, x2, x27
	bic	x11, x5, x4
	eor	x4, x4, x28
	eor	x3, x3, x11
	eor	x5, x5, x30
	bic	x11, x8, x7
	bic	x27, x9, x8
	bic	x28, x6, x10
	bic	x30, x7, x6
	eor	x6, x6, x11
	eor	x7, x7, x27
	bic	x11, x10, x9
	eor	x9, x9, x28
	eor	x8, x8, x11
	eor	x10, x10, x30
	bic	x11, x13, x12
	bic	x27, x14, x13
	bic	x28, x0, x15
	bic	x30, x12, x0
	eor	x11, x0, x11
	eor	x12, x12, x27
	bic	x0, x15, x14
	eor	x14, x14, x28
	eor	x13, x13, x0
	eor	x15, x15, x30
	bic	x0, x19, x17
	bic	x27, x20, x19
	bic	x28, x16, x21
	bic	x30, x17, x16
	eor	x16, x16, x0
	eor	x17, x17, x27
	bic	x0, x21, x20
	eor	x20, x20, x28
	eor	x19, x19, x0
	eor	x21, x21, x30
	bic	x0, x24, x23
	bic	x27, x25, x24
	bic	x28, x22, x26
	bic	x30, x23, x22
	eor	x22, x22, x0
	eor	x23, x23, x27
	bic	x0, x26, x25
	eor	x25, x25, x28
	eor	x24, x24, x0
	eor	x26, x26, x30
	# Done transforming
	ldp	x27, x28, [x29, #48]
	ldr	x0, [x27], #8
	subs	x28, x28, #1
	eor	x1, x1, x0
	bne	L_SHA3_transform_base_begin
	ldr	x0, [x29, #40]
	stp	x1, x2, [x0]
	stp	x3, x4, [x0, #16]
	stp	x5, x6, [x0, #32]
	stp	x7, x8, [x0, #48]
	stp	x9, x10, [x0, #64]
	stp	x11, x12, [x0, #80]
	stp	x13, x14, [x0, #96]
	stp	x15, x16, [x0, #112]
	stp	x17, x19, [x0, #128]
	stp	x20, x21, [x0, #144]
	stp	x22, x23, [x0, #160]
	stp	x24, x25, [x0, #176]
	str	x26, [x0, #192]
	ldp	x17, x19, [x29, #72]
	ldp	x20, x21, [x29, #88]
	ldp	x22, x23, [x29, #104]
	ldp	x24, x25, [x29, #120]
	ldp	x26, x27, [x29, #136]
	ldr	x28, [x29, #152]
	ldp	x29, x30, [sp], #0xa0
	ret
#ifndef __APPLE__
	.size	BlockSha3_base,.-BlockSha3_base
#endif /* __APPLE__ */
#if defined(WOLFSSL_HAVE_MLKEM) || defined(WOLFSSL_HAVE_MLDSA)
#ifndef __APPLE__
	.text
	.section	.rodata
	.type	L_sha3_aarch64_r, %object
	.size	L_sha3_aarch64_r, 192
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
	# 16-byte aligned, 128-bit aligned
#ifndef __APPLE__
	.align	4
#else
	.p2align	4
#endif /* __APPLE__ */
L_sha3_aarch64_r:
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
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
#ifndef __APPLE__
.text
.globl	sha3_blocksx3_crypto
WC_ASM_ATT_HIDDEN(sha3_blocksx3_crypto)
.type	sha3_blocksx3_crypto,@function
.align	2
sha3_blocksx3_crypto:
#else
.section	__TEXT,__text
.globl	_sha3_blocksx3_crypto
WC_ASM_ATT_HIDDEN(_sha3_blocksx3_crypto)
.p2align	2
_sha3_blocksx3_crypto:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	d8, d9, [x29, #160]
	stp	d10, d11, [x29, #176]
	stp	d12, d13, [x29, #192]
	stp	d14, d15, [x29, #208]
#ifndef __APPLE__
	adrp x27, L_sha3_aarch64_r
	add  x27, x27, :lo12:L_sha3_aarch64_r
#else
	adrp x27, L_sha3_aarch64_r@PAGE
	add  x27, x27, L_sha3_aarch64_r@PAGEOFF
#endif /* __APPLE__ */
#ifdef __APPLE__
.arch_extension sha3
#endif /* __APPLE__ */
	str	x0, [x29, #40]
	ld4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	ld4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	ld4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	ld4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	ld4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	ld4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	ld1	{v24.d}[0], [x0]
	add	x0, x0, #8
	ld4	{v0.d, v1.d, v2.d, v3.d}[1], [x0], #32
	ld4	{v4.d, v5.d, v6.d, v7.d}[1], [x0], #32
	ld4	{v8.d, v9.d, v10.d, v11.d}[1], [x0], #32
	ld4	{v12.d, v13.d, v14.d, v15.d}[1], [x0], #32
	ld4	{v16.d, v17.d, v18.d, v19.d}[1], [x0], #32
	ld4	{v20.d, v21.d, v22.d, v23.d}[1], [x0], #32
	ld1	{v24.d}[1], [x0]
	add	x0, x0, #8
	ldp	x1, x2, [x0]
	ldp	x3, x4, [x0, #16]
	ldp	x5, x6, [x0, #32]
	ldp	x7, x8, [x0, #48]
	ldp	x9, x10, [x0, #64]
	ldp	x11, x12, [x0, #80]
	ldp	x13, x14, [x0, #96]
	ldp	x15, x16, [x0, #112]
	ldp	x17, x19, [x0, #128]
	ldp	x20, x21, [x0, #144]
	ldp	x22, x23, [x0, #160]
	ldp	x24, x25, [x0, #176]
	ldr	x26, [x0, #192]
	mov	x28, #24
	# Start of 24 rounds
L_SHA3_transform_blocksx3_crypto_begin:
	stp	x27, x28, [x29, #48]
	# Col Mix
	eor3	v31.16b, v0.16b, v5.16b, v10.16b
	eor	x0, x5, x10
	eor3	v27.16b, v1.16b, v6.16b, v11.16b
	eor	x30, x1, x6
	eor3	v28.16b, v2.16b, v7.16b, v12.16b
	eor	x28, x3, x8
	eor3	v29.16b, v3.16b, v8.16b, v13.16b
	eor	x0, x0, x15
	eor3	v30.16b, v4.16b, v9.16b, v14.16b
	eor	x30, x30, x11
	eor3	v31.16b, v31.16b, v15.16b, v20.16b
	eor	x28, x28, x13
	eor3	v27.16b, v27.16b, v16.16b, v21.16b
	eor	x0, x0, x21
	eor3	v28.16b, v28.16b, v17.16b, v22.16b
	eor	x30, x30, x16
	eor3	v29.16b, v29.16b, v18.16b, v23.16b
	eor	x28, x28, x19
	eor3	v30.16b, v30.16b, v19.16b, v24.16b
	eor	x0, x0, x26
	rax1	v25.2d, v30.2d, v27.2d
	eor	x30, x30, x22
	rax1	v26.2d, v31.2d, v28.2d
	eor	x28, x28, x24
	rax1	v27.2d, v27.2d, v29.2d
	str	x0, [x29, #32]
	rax1	v28.2d, v28.2d, v30.2d
	str	x28, [x29, #24]
	rax1	v29.2d, v29.2d, v31.2d
	eor	x27, x2, x7
	eor	v0.16b, v0.16b, v25.16b
	xar	v30.2d, v1.2d, v26.2d, #63
	eor	x28, x4, x9
	xar	v1.2d, v6.2d, v26.2d, #20
	eor	x27, x27, x12
	xar	v6.2d, v9.2d, v29.2d, #44
	eor	x28, x28, x14
	xar	v9.2d, v22.2d, v27.2d, #3
	eor	x27, x27, x17
	xar	v22.2d, v14.2d, v29.2d, #25
	eor	x28, x28, x20
	xar	v14.2d, v20.2d, v25.2d, #46
	eor	x27, x27, x23
	xar	v20.2d, v2.2d, v27.2d, #2
	eor	x28, x28, x25
	xar	v2.2d, v12.2d, v27.2d, #21
	eor	x0, x0, x27, ror 63
	xar	v12.2d, v13.2d, v28.2d, #39
	eor	x27, x27, x28, ror 63
	xar	v13.2d, v19.2d, v29.2d, #56
	eor	x1, x1, x0
	xar	v19.2d, v23.2d, v28.2d, #8
	eor	x6, x6, x0
	xar	v23.2d, v15.2d, v25.2d, #23
	eor	x11, x11, x0
	xar	v15.2d, v4.2d, v29.2d, #37
	eor	x16, x16, x0
	xar	v4.2d, v24.2d, v29.2d, #50
	eor	x22, x22, x0
	xar	v24.2d, v21.2d, v26.2d, #62
	eor	x3, x3, x27
	xar	v21.2d, v8.2d, v28.2d, #9
	eor	x8, x8, x27
	xar	v8.2d, v16.2d, v26.2d, #19
	eor	x13, x13, x27
	xar	v16.2d, v5.2d, v25.2d, #28
	eor	x19, x19, x27
	xar	v5.2d, v3.2d, v28.2d, #36
	eor	x24, x24, x27
	xar	v3.2d, v18.2d, v28.2d, #43
	ldr	x0, [x29, #32]
	xar	v18.2d, v17.2d, v27.2d, #49
	ldr	x27, [x29, #24]
	xar	v17.2d, v11.2d, v26.2d, #54
	eor	x28, x28, x30, ror 63
	xar	v11.2d, v7.2d, v27.2d, #58
	eor	x30, x30, x27, ror 63
	xar	v7.2d, v10.2d, v25.2d, #61
	eor	x27, x27, x0, ror 63
	# Row Mix
	mov	v25.16b, v0.16b
	eor	x5, x5, x28
	mov	v26.16b, v1.16b
	eor	x10, x10, x28
	bcax	v0.16b, v25.16b, v2.16b, v26.16b
	eor	x15, x15, x28
	bcax	v1.16b, v26.16b, v3.16b, v2.16b
	eor	x21, x21, x28
	bcax	v2.16b, v2.16b, v4.16b, v3.16b
	eor	x26, x26, x28
	bcax	v3.16b, v3.16b, v25.16b, v4.16b
	eor	x2, x2, x30
	bcax	v4.16b, v4.16b, v26.16b, v25.16b
	eor	x7, x7, x30
	mov	v25.16b, v5.16b
	eor	x12, x12, x30
	mov	v26.16b, v6.16b
	eor	x17, x17, x30
	bcax	v5.16b, v25.16b, v7.16b, v26.16b
	eor	x23, x23, x30
	bcax	v6.16b, v26.16b, v8.16b, v7.16b
	eor	x4, x4, x27
	bcax	v7.16b, v7.16b, v9.16b, v8.16b
	eor	x9, x9, x27
	bcax	v8.16b, v8.16b, v25.16b, v9.16b
	eor	x14, x14, x27
	bcax	v9.16b, v9.16b, v26.16b, v25.16b
	eor	x20, x20, x27
	mov	v26.16b, v11.16b
	eor	x25, x25, x27
	# Swap Rotate Base
	bcax	v10.16b, v30.16b, v12.16b, v26.16b
	ror	x0, x2, #63
	bcax	v11.16b, v26.16b, v13.16b, v12.16b
	ror	x2, x7, #20
	bcax	v12.16b, v12.16b, v14.16b, v13.16b
	ror	x7, x10, #44
	bcax	v13.16b, v13.16b, v30.16b, v14.16b
	ror	x10, x24, #3
	bcax	v14.16b, v14.16b, v26.16b, v30.16b
	ror	x24, x15, #25
	mov	v25.16b, v15.16b
	ror	x15, x22, #46
	mov	v26.16b, v16.16b
	ror	x22, x3, #2
	bcax	v15.16b, v25.16b, v17.16b, v26.16b
	ror	x3, x13, #21
	bcax	v16.16b, v26.16b, v18.16b, v17.16b
	ror	x13, x14, #39
	bcax	v17.16b, v17.16b, v19.16b, v18.16b
	ror	x14, x21, #56
	bcax	v18.16b, v18.16b, v25.16b, v19.16b
	ror	x21, x25, #8
	bcax	v19.16b, v19.16b, v26.16b, v25.16b
	ror	x25, x16, #23
	mov	v25.16b, v20.16b
	ror	x16, x5, #37
	mov	v26.16b, v21.16b
	ror	x5, x26, #50
	bcax	v20.16b, v25.16b, v22.16b, v26.16b
	ror	x26, x23, #62
	bcax	v21.16b, v26.16b, v23.16b, v22.16b
	ror	x23, x9, #9
	bcax	v22.16b, v22.16b, v24.16b, v23.16b
	ror	x9, x17, #19
	bcax	v23.16b, v23.16b, v25.16b, v24.16b
	ror	x17, x6, #28
	bcax	v24.16b, v24.16b, v26.16b, v25.16b
	ror	x6, x4, #36
	ror	x4, x20, #43
	ror	x20, x19, #49
	ror	x19, x12, #54
	ror	x12, x8, #58
	ror	x8, x11, #61
	# Row Mix Base
	bic	x11, x3, x2
	bic	x27, x4, x3
	bic	x28, x1, x5
	bic	x30, x2, x1
	eor	x1, x1, x11
	eor	x2, x2, x27
	bic	x11, x5, x4
	eor	x4, x4, x28
	eor	x3, x3, x11
	eor	x5, x5, x30
	bic	x11, x8, x7
	bic	x27, x9, x8
	bic	x28, x6, x10
	bic	x30, x7, x6
	eor	x6, x6, x11
	eor	x7, x7, x27
	bic	x11, x10, x9
	eor	x9, x9, x28
	eor	x8, x8, x11
	eor	x10, x10, x30
	bic	x11, x13, x12
	bic	x27, x14, x13
	bic	x28, x0, x15
	bic	x30, x12, x0
	eor	x11, x0, x11
	eor	x12, x12, x27
	bic	x0, x15, x14
	eor	x14, x14, x28
	eor	x13, x13, x0
	eor	x15, x15, x30
	bic	x0, x19, x17
	bic	x27, x20, x19
	bic	x28, x16, x21
	bic	x30, x17, x16
	eor	x16, x16, x0
	eor	x17, x17, x27
	bic	x0, x21, x20
	eor	x20, x20, x28
	eor	x19, x19, x0
	eor	x21, x21, x30
	bic	x0, x24, x23
	bic	x27, x25, x24
	bic	x28, x22, x26
	bic	x30, x23, x22
	eor	x22, x22, x0
	eor	x23, x23, x27
	bic	x0, x26, x25
	eor	x25, x25, x28
	eor	x24, x24, x0
	eor	x26, x26, x30
	# Done transforming
	ldp	x27, x28, [x29, #48]
	ldr	x0, [x27], #8
	subs	x28, x28, #1
	mov	v30.d[0], x0
	mov	v30.d[1], x0
	eor	x1, x1, x0
	eor	v0.16b, v0.16b, v30.16b
	bne	L_SHA3_transform_blocksx3_crypto_begin
	ldr	x0, [x29, #40]
	st4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	st1	{v24.d}[0], [x0]
	add	x0, x0, #8
	st4	{v0.d, v1.d, v2.d, v3.d}[1], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[1], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[1], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[1], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[1], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[1], [x0], #32
	st1	{v24.d}[1], [x0]
	add	x0, x0, #8
	stp	x1, x2, [x0]
	stp	x3, x4, [x0, #16]
	stp	x5, x6, [x0, #32]
	stp	x7, x8, [x0, #48]
	stp	x9, x10, [x0, #64]
	stp	x11, x12, [x0, #80]
	stp	x13, x14, [x0, #96]
	stp	x15, x16, [x0, #112]
	stp	x17, x19, [x0, #128]
	stp	x20, x21, [x0, #144]
	stp	x22, x23, [x0, #160]
	stp	x24, x25, [x0, #176]
	str	x26, [x0, #192]
	ldp	x17, x19, [x29, #72]
	ldp	x20, x21, [x29, #88]
	ldp	x22, x23, [x29, #104]
	ldp	x24, x25, [x29, #120]
	ldp	x26, x27, [x29, #136]
	ldr	x28, [x29, #152]
	ldp	d8, d9, [x29, #160]
	ldp	d10, d11, [x29, #176]
	ldp	d12, d13, [x29, #192]
	ldp	d14, d15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
#ifndef __APPLE__
	.size	sha3_blocksx3_crypto,.-sha3_blocksx3_crypto
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	sha3_128_blocksx3_seed_crypto
WC_ASM_ATT_HIDDEN(sha3_128_blocksx3_seed_crypto)
.type	sha3_128_blocksx3_seed_crypto,@function
.align	2
sha3_128_blocksx3_seed_crypto:
#else
.section	__TEXT,__text
.globl	_sha3_128_blocksx3_seed_crypto
WC_ASM_ATT_HIDDEN(_sha3_128_blocksx3_seed_crypto)
.p2align	2
_sha3_128_blocksx3_seed_crypto:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	d8, d9, [x29, #160]
	stp	d10, d11, [x29, #176]
	stp	d12, d13, [x29, #192]
	stp	d14, d15, [x29, #208]
#ifndef __APPLE__
	adrp x28, L_sha3_aarch64_r
	add  x28, x28, :lo12:L_sha3_aarch64_r
#else
	adrp x28, L_sha3_aarch64_r@PAGE
	add  x28, x28, L_sha3_aarch64_r@PAGEOFF
#endif /* __APPLE__ */
#ifdef __APPLE__
.arch_extension sha3
#endif /* __APPLE__ */
	str	x0, [x29, #40]
	add	x0, x0, #32
	ld1	{v4.d}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{v4.d}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldr	x6, [x0, #200]
	eor	v5.16b, v5.16b, v5.16b
	eor	x7, x7, x7
	eor	v6.16b, v6.16b, v6.16b
	eor	x8, x8, x8
	eor	v7.16b, v7.16b, v7.16b
	eor	x9, x9, x9
	eor	v8.16b, v8.16b, v8.16b
	eor	x10, x10, x10
	eor	v9.16b, v9.16b, v9.16b
	eor	x11, x11, x11
	eor	v10.16b, v10.16b, v10.16b
	eor	x12, x12, x12
	eor	v11.16b, v11.16b, v11.16b
	eor	x13, x13, x13
	eor	v12.16b, v12.16b, v12.16b
	eor	x14, x14, x14
	eor	v13.16b, v13.16b, v13.16b
	eor	x15, x15, x15
	eor	v14.16b, v14.16b, v14.16b
	eor	x16, x16, x16
	eor	v15.16b, v15.16b, v15.16b
	eor	x17, x17, x17
	eor	v16.16b, v16.16b, v16.16b
	eor	x19, x19, x19
	eor	v17.16b, v17.16b, v17.16b
	eor	x20, x20, x20
	eor	v18.16b, v18.16b, v18.16b
	eor	x21, x21, x21
	eor	v19.16b, v19.16b, v19.16b
	eor	x22, x22, x22
	movz	x23, #0x8000, lsl 48
	eor	v21.16b, v21.16b, v21.16b
	eor	x24, x24, x24
	eor	v22.16b, v22.16b, v22.16b
	eor	x25, x25, x25
	eor	v23.16b, v23.16b, v23.16b
	eor	x26, x26, x26
	eor	v24.16b, v24.16b, v24.16b
	eor	x27, x27, x27
	dup	v0.2d, x2
	dup	v1.2d, x3
	dup	v2.2d, x4
	dup	v3.2d, x5
	dup	v20.2d, x23
	mov	x1, #24
	# Start of 24 rounds
L_SHA3_shake128_blocksx3_seed_crypto_begin:
	stp	x28, x1, [x29, #48]
	# Col Mix
	eor3	v31.16b, v0.16b, v5.16b, v10.16b
	eor	x0, x6, x11
	eor3	v27.16b, v1.16b, v6.16b, v11.16b
	eor	x30, x2, x7
	eor3	v28.16b, v2.16b, v7.16b, v12.16b
	eor	x28, x4, x9
	eor3	v29.16b, v3.16b, v8.16b, v13.16b
	eor	x0, x0, x16
	eor3	v30.16b, v4.16b, v9.16b, v14.16b
	eor	x30, x30, x12
	eor3	v31.16b, v31.16b, v15.16b, v20.16b
	eor	x28, x28, x14
	eor3	v27.16b, v27.16b, v16.16b, v21.16b
	eor	x0, x0, x22
	eor3	v28.16b, v28.16b, v17.16b, v22.16b
	eor	x30, x30, x17
	eor3	v29.16b, v29.16b, v18.16b, v23.16b
	eor	x28, x28, x20
	eor3	v30.16b, v30.16b, v19.16b, v24.16b
	eor	x0, x0, x27
	rax1	v25.2d, v30.2d, v27.2d
	eor	x30, x30, x23
	rax1	v26.2d, v31.2d, v28.2d
	eor	x28, x28, x25
	rax1	v27.2d, v27.2d, v29.2d
	str	x0, [x29, #32]
	rax1	v28.2d, v28.2d, v30.2d
	str	x28, [x29, #24]
	rax1	v29.2d, v29.2d, v31.2d
	eor	x1, x3, x8
	eor	v0.16b, v0.16b, v25.16b
	xar	v30.2d, v1.2d, v26.2d, #63
	eor	x28, x5, x10
	xar	v1.2d, v6.2d, v26.2d, #20
	eor	x1, x1, x13
	xar	v6.2d, v9.2d, v29.2d, #44
	eor	x28, x28, x15
	xar	v9.2d, v22.2d, v27.2d, #3
	eor	x1, x1, x19
	xar	v22.2d, v14.2d, v29.2d, #25
	eor	x28, x28, x21
	xar	v14.2d, v20.2d, v25.2d, #46
	eor	x1, x1, x24
	xar	v20.2d, v2.2d, v27.2d, #2
	eor	x28, x28, x26
	xar	v2.2d, v12.2d, v27.2d, #21
	eor	x0, x0, x1, ror 63
	xar	v12.2d, v13.2d, v28.2d, #39
	eor	x1, x1, x28, ror 63
	xar	v13.2d, v19.2d, v29.2d, #56
	eor	x2, x2, x0
	xar	v19.2d, v23.2d, v28.2d, #8
	eor	x7, x7, x0
	xar	v23.2d, v15.2d, v25.2d, #23
	eor	x12, x12, x0
	xar	v15.2d, v4.2d, v29.2d, #37
	eor	x17, x17, x0
	xar	v4.2d, v24.2d, v29.2d, #50
	eor	x23, x23, x0
	xar	v24.2d, v21.2d, v26.2d, #62
	eor	x4, x4, x1
	xar	v21.2d, v8.2d, v28.2d, #9
	eor	x9, x9, x1
	xar	v8.2d, v16.2d, v26.2d, #19
	eor	x14, x14, x1
	xar	v16.2d, v5.2d, v25.2d, #28
	eor	x20, x20, x1
	xar	v5.2d, v3.2d, v28.2d, #36
	eor	x25, x25, x1
	xar	v3.2d, v18.2d, v28.2d, #43
	ldr	x0, [x29, #32]
	xar	v18.2d, v17.2d, v27.2d, #49
	ldr	x1, [x29, #24]
	xar	v17.2d, v11.2d, v26.2d, #54
	eor	x28, x28, x30, ror 63
	xar	v11.2d, v7.2d, v27.2d, #58
	eor	x30, x30, x1, ror 63
	xar	v7.2d, v10.2d, v25.2d, #61
	eor	x1, x1, x0, ror 63
	# Row Mix
	mov	v25.16b, v0.16b
	eor	x6, x6, x28
	mov	v26.16b, v1.16b
	eor	x11, x11, x28
	bcax	v0.16b, v25.16b, v2.16b, v26.16b
	eor	x16, x16, x28
	bcax	v1.16b, v26.16b, v3.16b, v2.16b
	eor	x22, x22, x28
	bcax	v2.16b, v2.16b, v4.16b, v3.16b
	eor	x27, x27, x28
	bcax	v3.16b, v3.16b, v25.16b, v4.16b
	eor	x3, x3, x30
	bcax	v4.16b, v4.16b, v26.16b, v25.16b
	eor	x8, x8, x30
	mov	v25.16b, v5.16b
	eor	x13, x13, x30
	mov	v26.16b, v6.16b
	eor	x19, x19, x30
	bcax	v5.16b, v25.16b, v7.16b, v26.16b
	eor	x24, x24, x30
	bcax	v6.16b, v26.16b, v8.16b, v7.16b
	eor	x5, x5, x1
	bcax	v7.16b, v7.16b, v9.16b, v8.16b
	eor	x10, x10, x1
	bcax	v8.16b, v8.16b, v25.16b, v9.16b
	eor	x15, x15, x1
	bcax	v9.16b, v9.16b, v26.16b, v25.16b
	eor	x21, x21, x1
	mov	v26.16b, v11.16b
	eor	x26, x26, x1
	# Swap Rotate Base
	bcax	v10.16b, v30.16b, v12.16b, v26.16b
	ror	x0, x3, #63
	bcax	v11.16b, v26.16b, v13.16b, v12.16b
	ror	x3, x8, #20
	bcax	v12.16b, v12.16b, v14.16b, v13.16b
	ror	x8, x11, #44
	bcax	v13.16b, v13.16b, v30.16b, v14.16b
	ror	x11, x25, #3
	bcax	v14.16b, v14.16b, v26.16b, v30.16b
	ror	x25, x16, #25
	mov	v25.16b, v15.16b
	ror	x16, x23, #46
	mov	v26.16b, v16.16b
	ror	x23, x4, #2
	bcax	v15.16b, v25.16b, v17.16b, v26.16b
	ror	x4, x14, #21
	bcax	v16.16b, v26.16b, v18.16b, v17.16b
	ror	x14, x15, #39
	bcax	v17.16b, v17.16b, v19.16b, v18.16b
	ror	x15, x22, #56
	bcax	v18.16b, v18.16b, v25.16b, v19.16b
	ror	x22, x26, #8
	bcax	v19.16b, v19.16b, v26.16b, v25.16b
	ror	x26, x17, #23
	mov	v25.16b, v20.16b
	ror	x17, x6, #37
	mov	v26.16b, v21.16b
	ror	x6, x27, #50
	bcax	v20.16b, v25.16b, v22.16b, v26.16b
	ror	x27, x24, #62
	bcax	v21.16b, v26.16b, v23.16b, v22.16b
	ror	x24, x10, #9
	bcax	v22.16b, v22.16b, v24.16b, v23.16b
	ror	x10, x19, #19
	bcax	v23.16b, v23.16b, v25.16b, v24.16b
	ror	x19, x7, #28
	bcax	v24.16b, v24.16b, v26.16b, v25.16b
	ror	x7, x5, #36
	ror	x5, x21, #43
	ror	x21, x20, #49
	ror	x20, x13, #54
	ror	x13, x9, #58
	ror	x9, x12, #61
	# Row Mix Base
	bic	x12, x4, x3
	bic	x1, x5, x4
	bic	x28, x2, x6
	bic	x30, x3, x2
	eor	x2, x2, x12
	eor	x3, x3, x1
	bic	x12, x6, x5
	eor	x5, x5, x28
	eor	x4, x4, x12
	eor	x6, x6, x30
	bic	x12, x9, x8
	bic	x1, x10, x9
	bic	x28, x7, x11
	bic	x30, x8, x7
	eor	x7, x7, x12
	eor	x8, x8, x1
	bic	x12, x11, x10
	eor	x10, x10, x28
	eor	x9, x9, x12
	eor	x11, x11, x30
	bic	x12, x14, x13
	bic	x1, x15, x14
	bic	x28, x0, x16
	bic	x30, x13, x0
	eor	x12, x0, x12
	eor	x13, x13, x1
	bic	x0, x16, x15
	eor	x15, x15, x28
	eor	x14, x14, x0
	eor	x16, x16, x30
	bic	x0, x20, x19
	bic	x1, x21, x20
	bic	x28, x17, x22
	bic	x30, x19, x17
	eor	x17, x17, x0
	eor	x19, x19, x1
	bic	x0, x22, x21
	eor	x21, x21, x28
	eor	x20, x20, x0
	eor	x22, x22, x30
	bic	x0, x25, x24
	bic	x1, x26, x25
	bic	x28, x23, x27
	bic	x30, x24, x23
	eor	x23, x23, x0
	eor	x24, x24, x1
	bic	x0, x27, x26
	eor	x26, x26, x28
	eor	x25, x25, x0
	eor	x27, x27, x30
	# Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	v30.d[0], x0
	mov	v30.d[1], x0
	eor	x2, x2, x0
	eor	v0.16b, v0.16b, v30.16b
	bne	L_SHA3_shake128_blocksx3_seed_crypto_begin
	ldr	x0, [x29, #40]
	st4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	st1	{v24.d}[0], [x0]
	add	x0, x0, #8
	st4	{v0.d, v1.d, v2.d, v3.d}[1], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[1], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[1], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[1], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[1], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[1], [x0], #32
	st1	{v24.d}[1], [x0]
	add	x0, x0, #8
	stp	x2, x3, [x0]
	stp	x4, x5, [x0, #16]
	stp	x6, x7, [x0, #32]
	stp	x8, x9, [x0, #48]
	stp	x10, x11, [x0, #64]
	stp	x12, x13, [x0, #80]
	stp	x14, x15, [x0, #96]
	stp	x16, x17, [x0, #112]
	stp	x19, x20, [x0, #128]
	stp	x21, x22, [x0, #144]
	stp	x23, x24, [x0, #160]
	stp	x25, x26, [x0, #176]
	str	x27, [x0, #192]
	ldp	x17, x19, [x29, #72]
	ldp	x20, x21, [x29, #88]
	ldp	x22, x23, [x29, #104]
	ldp	x24, x25, [x29, #120]
	ldp	x26, x27, [x29, #136]
	ldr	x28, [x29, #152]
	ldp	d8, d9, [x29, #160]
	ldp	d10, d11, [x29, #176]
	ldp	d12, d13, [x29, #192]
	ldp	d14, d15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
#ifndef __APPLE__
	.size	sha3_128_blocksx3_seed_crypto,.-sha3_128_blocksx3_seed_crypto
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	sha3_256_blocksx3_seed_crypto
WC_ASM_ATT_HIDDEN(sha3_256_blocksx3_seed_crypto)
.type	sha3_256_blocksx3_seed_crypto,@function
.align	2
sha3_256_blocksx3_seed_crypto:
#else
.section	__TEXT,__text
.globl	_sha3_256_blocksx3_seed_crypto
WC_ASM_ATT_HIDDEN(_sha3_256_blocksx3_seed_crypto)
.p2align	2
_sha3_256_blocksx3_seed_crypto:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	d8, d9, [x29, #160]
	stp	d10, d11, [x29, #176]
	stp	d12, d13, [x29, #192]
	stp	d14, d15, [x29, #208]
#ifndef __APPLE__
	adrp x28, L_sha3_aarch64_r
	add  x28, x28, :lo12:L_sha3_aarch64_r
#else
	adrp x28, L_sha3_aarch64_r@PAGE
	add  x28, x28, L_sha3_aarch64_r@PAGEOFF
#endif /* __APPLE__ */
#ifdef __APPLE__
.arch_extension sha3
#endif /* __APPLE__ */
	str	x0, [x29, #40]
	add	x0, x0, #32
	ld1	{v4.d}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{v4.d}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldr	x6, [x0, #200]
	eor	v5.16b, v5.16b, v5.16b
	eor	x7, x7, x7
	eor	v6.16b, v6.16b, v6.16b
	eor	x8, x8, x8
	eor	v7.16b, v7.16b, v7.16b
	eor	x9, x9, x9
	eor	v8.16b, v8.16b, v8.16b
	eor	x10, x10, x10
	eor	v9.16b, v9.16b, v9.16b
	eor	x11, x11, x11
	eor	v10.16b, v10.16b, v10.16b
	eor	x12, x12, x12
	eor	v11.16b, v11.16b, v11.16b
	eor	x13, x13, x13
	eor	v12.16b, v12.16b, v12.16b
	eor	x14, x14, x14
	eor	v13.16b, v13.16b, v13.16b
	eor	x15, x15, x15
	eor	v14.16b, v14.16b, v14.16b
	eor	x16, x16, x16
	eor	v15.16b, v15.16b, v15.16b
	eor	x17, x17, x17
	movz	x19, #0x8000, lsl 48
	eor	v17.16b, v17.16b, v17.16b
	eor	x20, x20, x20
	eor	v18.16b, v18.16b, v18.16b
	eor	x21, x21, x21
	eor	v19.16b, v19.16b, v19.16b
	eor	x22, x22, x22
	eor	v20.16b, v20.16b, v20.16b
	eor	x23, x23, x23
	eor	v21.16b, v21.16b, v21.16b
	eor	x24, x24, x24
	eor	v22.16b, v22.16b, v22.16b
	eor	x25, x25, x25
	eor	v23.16b, v23.16b, v23.16b
	eor	x26, x26, x26
	eor	v24.16b, v24.16b, v24.16b
	eor	x27, x27, x27
	dup	v0.2d, x2
	dup	v1.2d, x3
	dup	v2.2d, x4
	dup	v3.2d, x5
	dup	v16.2d, x19
	mov	x1, #24
	# Start of 24 rounds
L_SHA3_shake256_blocksx3_seed_crypto_begin:
	stp	x28, x1, [x29, #48]
	# Col Mix
	eor3	v31.16b, v0.16b, v5.16b, v10.16b
	eor	x0, x6, x11
	eor3	v27.16b, v1.16b, v6.16b, v11.16b
	eor	x30, x2, x7
	eor3	v28.16b, v2.16b, v7.16b, v12.16b
	eor	x28, x4, x9
	eor3	v29.16b, v3.16b, v8.16b, v13.16b
	eor	x0, x0, x16
	eor3	v30.16b, v4.16b, v9.16b, v14.16b
	eor	x30, x30, x12
	eor3	v31.16b, v31.16b, v15.16b, v20.16b
	eor	x28, x28, x14
	eor3	v27.16b, v27.16b, v16.16b, v21.16b
	eor	x0, x0, x22
	eor3	v28.16b, v28.16b, v17.16b, v22.16b
	eor	x30, x30, x17
	eor3	v29.16b, v29.16b, v18.16b, v23.16b
	eor	x28, x28, x20
	eor3	v30.16b, v30.16b, v19.16b, v24.16b
	eor	x0, x0, x27
	rax1	v25.2d, v30.2d, v27.2d
	eor	x30, x30, x23
	rax1	v26.2d, v31.2d, v28.2d
	eor	x28, x28, x25
	rax1	v27.2d, v27.2d, v29.2d
	str	x0, [x29, #32]
	rax1	v28.2d, v28.2d, v30.2d
	str	x28, [x29, #24]
	rax1	v29.2d, v29.2d, v31.2d
	eor	x1, x3, x8
	eor	v0.16b, v0.16b, v25.16b
	xar	v30.2d, v1.2d, v26.2d, #63
	eor	x28, x5, x10
	xar	v1.2d, v6.2d, v26.2d, #20
	eor	x1, x1, x13
	xar	v6.2d, v9.2d, v29.2d, #44
	eor	x28, x28, x15
	xar	v9.2d, v22.2d, v27.2d, #3
	eor	x1, x1, x19
	xar	v22.2d, v14.2d, v29.2d, #25
	eor	x28, x28, x21
	xar	v14.2d, v20.2d, v25.2d, #46
	eor	x1, x1, x24
	xar	v20.2d, v2.2d, v27.2d, #2
	eor	x28, x28, x26
	xar	v2.2d, v12.2d, v27.2d, #21
	eor	x0, x0, x1, ror 63
	xar	v12.2d, v13.2d, v28.2d, #39
	eor	x1, x1, x28, ror 63
	xar	v13.2d, v19.2d, v29.2d, #56
	eor	x2, x2, x0
	xar	v19.2d, v23.2d, v28.2d, #8
	eor	x7, x7, x0
	xar	v23.2d, v15.2d, v25.2d, #23
	eor	x12, x12, x0
	xar	v15.2d, v4.2d, v29.2d, #37
	eor	x17, x17, x0
	xar	v4.2d, v24.2d, v29.2d, #50
	eor	x23, x23, x0
	xar	v24.2d, v21.2d, v26.2d, #62
	eor	x4, x4, x1
	xar	v21.2d, v8.2d, v28.2d, #9
	eor	x9, x9, x1
	xar	v8.2d, v16.2d, v26.2d, #19
	eor	x14, x14, x1
	xar	v16.2d, v5.2d, v25.2d, #28
	eor	x20, x20, x1
	xar	v5.2d, v3.2d, v28.2d, #36
	eor	x25, x25, x1
	xar	v3.2d, v18.2d, v28.2d, #43
	ldr	x0, [x29, #32]
	xar	v18.2d, v17.2d, v27.2d, #49
	ldr	x1, [x29, #24]
	xar	v17.2d, v11.2d, v26.2d, #54
	eor	x28, x28, x30, ror 63
	xar	v11.2d, v7.2d, v27.2d, #58
	eor	x30, x30, x1, ror 63
	xar	v7.2d, v10.2d, v25.2d, #61
	eor	x1, x1, x0, ror 63
	# Row Mix
	mov	v25.16b, v0.16b
	eor	x6, x6, x28
	mov	v26.16b, v1.16b
	eor	x11, x11, x28
	bcax	v0.16b, v25.16b, v2.16b, v26.16b
	eor	x16, x16, x28
	bcax	v1.16b, v26.16b, v3.16b, v2.16b
	eor	x22, x22, x28
	bcax	v2.16b, v2.16b, v4.16b, v3.16b
	eor	x27, x27, x28
	bcax	v3.16b, v3.16b, v25.16b, v4.16b
	eor	x3, x3, x30
	bcax	v4.16b, v4.16b, v26.16b, v25.16b
	eor	x8, x8, x30
	mov	v25.16b, v5.16b
	eor	x13, x13, x30
	mov	v26.16b, v6.16b
	eor	x19, x19, x30
	bcax	v5.16b, v25.16b, v7.16b, v26.16b
	eor	x24, x24, x30
	bcax	v6.16b, v26.16b, v8.16b, v7.16b
	eor	x5, x5, x1
	bcax	v7.16b, v7.16b, v9.16b, v8.16b
	eor	x10, x10, x1
	bcax	v8.16b, v8.16b, v25.16b, v9.16b
	eor	x15, x15, x1
	bcax	v9.16b, v9.16b, v26.16b, v25.16b
	eor	x21, x21, x1
	mov	v26.16b, v11.16b
	eor	x26, x26, x1
	# Swap Rotate Base
	bcax	v10.16b, v30.16b, v12.16b, v26.16b
	ror	x0, x3, #63
	bcax	v11.16b, v26.16b, v13.16b, v12.16b
	ror	x3, x8, #20
	bcax	v12.16b, v12.16b, v14.16b, v13.16b
	ror	x8, x11, #44
	bcax	v13.16b, v13.16b, v30.16b, v14.16b
	ror	x11, x25, #3
	bcax	v14.16b, v14.16b, v26.16b, v30.16b
	ror	x25, x16, #25
	mov	v25.16b, v15.16b
	ror	x16, x23, #46
	mov	v26.16b, v16.16b
	ror	x23, x4, #2
	bcax	v15.16b, v25.16b, v17.16b, v26.16b
	ror	x4, x14, #21
	bcax	v16.16b, v26.16b, v18.16b, v17.16b
	ror	x14, x15, #39
	bcax	v17.16b, v17.16b, v19.16b, v18.16b
	ror	x15, x22, #56
	bcax	v18.16b, v18.16b, v25.16b, v19.16b
	ror	x22, x26, #8
	bcax	v19.16b, v19.16b, v26.16b, v25.16b
	ror	x26, x17, #23
	mov	v25.16b, v20.16b
	ror	x17, x6, #37
	mov	v26.16b, v21.16b
	ror	x6, x27, #50
	bcax	v20.16b, v25.16b, v22.16b, v26.16b
	ror	x27, x24, #62
	bcax	v21.16b, v26.16b, v23.16b, v22.16b
	ror	x24, x10, #9
	bcax	v22.16b, v22.16b, v24.16b, v23.16b
	ror	x10, x19, #19
	bcax	v23.16b, v23.16b, v25.16b, v24.16b
	ror	x19, x7, #28
	bcax	v24.16b, v24.16b, v26.16b, v25.16b
	ror	x7, x5, #36
	ror	x5, x21, #43
	ror	x21, x20, #49
	ror	x20, x13, #54
	ror	x13, x9, #58
	ror	x9, x12, #61
	# Row Mix Base
	bic	x12, x4, x3
	bic	x1, x5, x4
	bic	x28, x2, x6
	bic	x30, x3, x2
	eor	x2, x2, x12
	eor	x3, x3, x1
	bic	x12, x6, x5
	eor	x5, x5, x28
	eor	x4, x4, x12
	eor	x6, x6, x30
	bic	x12, x9, x8
	bic	x1, x10, x9
	bic	x28, x7, x11
	bic	x30, x8, x7
	eor	x7, x7, x12
	eor	x8, x8, x1
	bic	x12, x11, x10
	eor	x10, x10, x28
	eor	x9, x9, x12
	eor	x11, x11, x30
	bic	x12, x14, x13
	bic	x1, x15, x14
	bic	x28, x0, x16
	bic	x30, x13, x0
	eor	x12, x0, x12
	eor	x13, x13, x1
	bic	x0, x16, x15
	eor	x15, x15, x28
	eor	x14, x14, x0
	eor	x16, x16, x30
	bic	x0, x20, x19
	bic	x1, x21, x20
	bic	x28, x17, x22
	bic	x30, x19, x17
	eor	x17, x17, x0
	eor	x19, x19, x1
	bic	x0, x22, x21
	eor	x21, x21, x28
	eor	x20, x20, x0
	eor	x22, x22, x30
	bic	x0, x25, x24
	bic	x1, x26, x25
	bic	x28, x23, x27
	bic	x30, x24, x23
	eor	x23, x23, x0
	eor	x24, x24, x1
	bic	x0, x27, x26
	eor	x26, x26, x28
	eor	x25, x25, x0
	eor	x27, x27, x30
	# Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	v30.d[0], x0
	mov	v30.d[1], x0
	eor	x2, x2, x0
	eor	v0.16b, v0.16b, v30.16b
	bne	L_SHA3_shake256_blocksx3_seed_crypto_begin
	ldr	x0, [x29, #40]
	st4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	st1	{v24.d}[0], [x0]
	add	x0, x0, #8
	st4	{v0.d, v1.d, v2.d, v3.d}[1], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[1], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[1], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[1], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[1], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[1], [x0], #32
	st1	{v24.d}[1], [x0]
	add	x0, x0, #8
	stp	x2, x3, [x0]
	stp	x4, x5, [x0, #16]
	stp	x6, x7, [x0, #32]
	stp	x8, x9, [x0, #48]
	stp	x10, x11, [x0, #64]
	stp	x12, x13, [x0, #80]
	stp	x14, x15, [x0, #96]
	stp	x16, x17, [x0, #112]
	stp	x19, x20, [x0, #128]
	stp	x21, x22, [x0, #144]
	stp	x23, x24, [x0, #160]
	stp	x25, x26, [x0, #176]
	str	x27, [x0, #192]
	ldp	x17, x19, [x29, #72]
	ldp	x20, x21, [x29, #88]
	ldp	x22, x23, [x29, #104]
	ldp	x24, x25, [x29, #120]
	ldp	x26, x27, [x29, #136]
	ldr	x28, [x29, #152]
	ldp	d8, d9, [x29, #160]
	ldp	d10, d11, [x29, #176]
	ldp	d12, d13, [x29, #192]
	ldp	d14, d15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
#ifndef __APPLE__
	.size	sha3_256_blocksx3_seed_crypto,.-sha3_256_blocksx3_seed_crypto
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	sha3_256_blocksx3_seed_64_crypto
WC_ASM_ATT_HIDDEN(sha3_256_blocksx3_seed_64_crypto)
.type	sha3_256_blocksx3_seed_64_crypto,@function
.align	2
sha3_256_blocksx3_seed_64_crypto:
#else
.section	__TEXT,__text
.globl	_sha3_256_blocksx3_seed_64_crypto
WC_ASM_ATT_HIDDEN(_sha3_256_blocksx3_seed_64_crypto)
.p2align	2
_sha3_256_blocksx3_seed_64_crypto:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	d8, d9, [x29, #160]
	stp	d10, d11, [x29, #176]
	stp	d12, d13, [x29, #192]
	stp	d14, d15, [x29, #208]
#ifndef __APPLE__
	adrp x28, L_sha3_aarch64_r
	add  x28, x28, :lo12:L_sha3_aarch64_r
#else
	adrp x28, L_sha3_aarch64_r@PAGE
	add  x28, x28, L_sha3_aarch64_r@PAGEOFF
#endif /* __APPLE__ */
#ifdef __APPLE__
.arch_extension sha3
#endif /* __APPLE__ */
	str	x0, [x29, #40]
	add	x0, x0, #0x40
	ld1	{v8.d}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{v8.d}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldp	x6, x7, [x1], #16
	ldp	x8, x9, [x1], #16
	ldr	x10, [x0, #200]
	eor	v9.16b, v9.16b, v9.16b
	eor	x11, x11, x11
	eor	v10.16b, v10.16b, v10.16b
	eor	x12, x12, x12
	eor	v11.16b, v11.16b, v11.16b
	eor	x13, x13, x13
	eor	v12.16b, v12.16b, v12.16b
	eor	x14, x14, x14
	eor	v13.16b, v13.16b, v13.16b
	eor	x15, x15, x15
	eor	v14.16b, v14.16b, v14.16b
	eor	x16, x16, x16
	eor	v15.16b, v15.16b, v15.16b
	eor	x17, x17, x17
	movz	x19, #0x8000, lsl 48
	eor	v17.16b, v17.16b, v17.16b
	eor	x20, x20, x20
	eor	v18.16b, v18.16b, v18.16b
	eor	x21, x21, x21
	eor	v19.16b, v19.16b, v19.16b
	eor	x22, x22, x22
	eor	v20.16b, v20.16b, v20.16b
	eor	x23, x23, x23
	eor	v21.16b, v21.16b, v21.16b
	eor	x24, x24, x24
	eor	v22.16b, v22.16b, v22.16b
	eor	x25, x25, x25
	eor	v23.16b, v23.16b, v23.16b
	eor	x26, x26, x26
	eor	v24.16b, v24.16b, v24.16b
	eor	x27, x27, x27
	dup	v0.2d, x2
	dup	v1.2d, x3
	dup	v2.2d, x4
	dup	v3.2d, x5
	dup	v4.2d, x6
	dup	v5.2d, x7
	dup	v6.2d, x8
	dup	v7.2d, x9
	dup	v16.2d, x19
	mov	x1, #24
	# Start of 24 rounds
L_SHA3_shake256_blocksx3_seed_64_crypto_begin:
	stp	x28, x1, [x29, #48]
	# Col Mix
	eor3	v31.16b, v0.16b, v5.16b, v10.16b
	eor	x0, x6, x11
	eor3	v27.16b, v1.16b, v6.16b, v11.16b
	eor	x30, x2, x7
	eor3	v28.16b, v2.16b, v7.16b, v12.16b
	eor	x28, x4, x9
	eor3	v29.16b, v3.16b, v8.16b, v13.16b
	eor	x0, x0, x16
	eor3	v30.16b, v4.16b, v9.16b, v14.16b
	eor	x30, x30, x12
	eor3	v31.16b, v31.16b, v15.16b, v20.16b
	eor	x28, x28, x14
	eor3	v27.16b, v27.16b, v16.16b, v21.16b
	eor	x0, x0, x22
	eor3	v28.16b, v28.16b, v17.16b, v22.16b
	eor	x30, x30, x17
	eor3	v29.16b, v29.16b, v18.16b, v23.16b
	eor	x28, x28, x20
	eor3	v30.16b, v30.16b, v19.16b, v24.16b
	eor	x0, x0, x27
	rax1	v25.2d, v30.2d, v27.2d
	eor	x30, x30, x23
	rax1	v26.2d, v31.2d, v28.2d
	eor	x28, x28, x25
	rax1	v27.2d, v27.2d, v29.2d
	str	x0, [x29, #32]
	rax1	v28.2d, v28.2d, v30.2d
	str	x28, [x29, #24]
	rax1	v29.2d, v29.2d, v31.2d
	eor	x1, x3, x8
	eor	v0.16b, v0.16b, v25.16b
	xar	v30.2d, v1.2d, v26.2d, #63
	eor	x28, x5, x10
	xar	v1.2d, v6.2d, v26.2d, #20
	eor	x1, x1, x13
	xar	v6.2d, v9.2d, v29.2d, #44
	eor	x28, x28, x15
	xar	v9.2d, v22.2d, v27.2d, #3
	eor	x1, x1, x19
	xar	v22.2d, v14.2d, v29.2d, #25
	eor	x28, x28, x21
	xar	v14.2d, v20.2d, v25.2d, #46
	eor	x1, x1, x24
	xar	v20.2d, v2.2d, v27.2d, #2
	eor	x28, x28, x26
	xar	v2.2d, v12.2d, v27.2d, #21
	eor	x0, x0, x1, ror 63
	xar	v12.2d, v13.2d, v28.2d, #39
	eor	x1, x1, x28, ror 63
	xar	v13.2d, v19.2d, v29.2d, #56
	eor	x2, x2, x0
	xar	v19.2d, v23.2d, v28.2d, #8
	eor	x7, x7, x0
	xar	v23.2d, v15.2d, v25.2d, #23
	eor	x12, x12, x0
	xar	v15.2d, v4.2d, v29.2d, #37
	eor	x17, x17, x0
	xar	v4.2d, v24.2d, v29.2d, #50
	eor	x23, x23, x0
	xar	v24.2d, v21.2d, v26.2d, #62
	eor	x4, x4, x1
	xar	v21.2d, v8.2d, v28.2d, #9
	eor	x9, x9, x1
	xar	v8.2d, v16.2d, v26.2d, #19
	eor	x14, x14, x1
	xar	v16.2d, v5.2d, v25.2d, #28
	eor	x20, x20, x1
	xar	v5.2d, v3.2d, v28.2d, #36
	eor	x25, x25, x1
	xar	v3.2d, v18.2d, v28.2d, #43
	ldr	x0, [x29, #32]
	xar	v18.2d, v17.2d, v27.2d, #49
	ldr	x1, [x29, #24]
	xar	v17.2d, v11.2d, v26.2d, #54
	eor	x28, x28, x30, ror 63
	xar	v11.2d, v7.2d, v27.2d, #58
	eor	x30, x30, x1, ror 63
	xar	v7.2d, v10.2d, v25.2d, #61
	eor	x1, x1, x0, ror 63
	# Row Mix
	mov	v25.16b, v0.16b
	eor	x6, x6, x28
	mov	v26.16b, v1.16b
	eor	x11, x11, x28
	bcax	v0.16b, v25.16b, v2.16b, v26.16b
	eor	x16, x16, x28
	bcax	v1.16b, v26.16b, v3.16b, v2.16b
	eor	x22, x22, x28
	bcax	v2.16b, v2.16b, v4.16b, v3.16b
	eor	x27, x27, x28
	bcax	v3.16b, v3.16b, v25.16b, v4.16b
	eor	x3, x3, x30
	bcax	v4.16b, v4.16b, v26.16b, v25.16b
	eor	x8, x8, x30
	mov	v25.16b, v5.16b
	eor	x13, x13, x30
	mov	v26.16b, v6.16b
	eor	x19, x19, x30
	bcax	v5.16b, v25.16b, v7.16b, v26.16b
	eor	x24, x24, x30
	bcax	v6.16b, v26.16b, v8.16b, v7.16b
	eor	x5, x5, x1
	bcax	v7.16b, v7.16b, v9.16b, v8.16b
	eor	x10, x10, x1
	bcax	v8.16b, v8.16b, v25.16b, v9.16b
	eor	x15, x15, x1
	bcax	v9.16b, v9.16b, v26.16b, v25.16b
	eor	x21, x21, x1
	mov	v26.16b, v11.16b
	eor	x26, x26, x1
	# Swap Rotate Base
	bcax	v10.16b, v30.16b, v12.16b, v26.16b
	ror	x0, x3, #63
	bcax	v11.16b, v26.16b, v13.16b, v12.16b
	ror	x3, x8, #20
	bcax	v12.16b, v12.16b, v14.16b, v13.16b
	ror	x8, x11, #44
	bcax	v13.16b, v13.16b, v30.16b, v14.16b
	ror	x11, x25, #3
	bcax	v14.16b, v14.16b, v26.16b, v30.16b
	ror	x25, x16, #25
	mov	v25.16b, v15.16b
	ror	x16, x23, #46
	mov	v26.16b, v16.16b
	ror	x23, x4, #2
	bcax	v15.16b, v25.16b, v17.16b, v26.16b
	ror	x4, x14, #21
	bcax	v16.16b, v26.16b, v18.16b, v17.16b
	ror	x14, x15, #39
	bcax	v17.16b, v17.16b, v19.16b, v18.16b
	ror	x15, x22, #56
	bcax	v18.16b, v18.16b, v25.16b, v19.16b
	ror	x22, x26, #8
	bcax	v19.16b, v19.16b, v26.16b, v25.16b
	ror	x26, x17, #23
	mov	v25.16b, v20.16b
	ror	x17, x6, #37
	mov	v26.16b, v21.16b
	ror	x6, x27, #50
	bcax	v20.16b, v25.16b, v22.16b, v26.16b
	ror	x27, x24, #62
	bcax	v21.16b, v26.16b, v23.16b, v22.16b
	ror	x24, x10, #9
	bcax	v22.16b, v22.16b, v24.16b, v23.16b
	ror	x10, x19, #19
	bcax	v23.16b, v23.16b, v25.16b, v24.16b
	ror	x19, x7, #28
	bcax	v24.16b, v24.16b, v26.16b, v25.16b
	ror	x7, x5, #36
	ror	x5, x21, #43
	ror	x21, x20, #49
	ror	x20, x13, #54
	ror	x13, x9, #58
	ror	x9, x12, #61
	# Row Mix Base
	bic	x12, x4, x3
	bic	x1, x5, x4
	bic	x28, x2, x6
	bic	x30, x3, x2
	eor	x2, x2, x12
	eor	x3, x3, x1
	bic	x12, x6, x5
	eor	x5, x5, x28
	eor	x4, x4, x12
	eor	x6, x6, x30
	bic	x12, x9, x8
	bic	x1, x10, x9
	bic	x28, x7, x11
	bic	x30, x8, x7
	eor	x7, x7, x12
	eor	x8, x8, x1
	bic	x12, x11, x10
	eor	x10, x10, x28
	eor	x9, x9, x12
	eor	x11, x11, x30
	bic	x12, x14, x13
	bic	x1, x15, x14
	bic	x28, x0, x16
	bic	x30, x13, x0
	eor	x12, x0, x12
	eor	x13, x13, x1
	bic	x0, x16, x15
	eor	x15, x15, x28
	eor	x14, x14, x0
	eor	x16, x16, x30
	bic	x0, x20, x19
	bic	x1, x21, x20
	bic	x28, x17, x22
	bic	x30, x19, x17
	eor	x17, x17, x0
	eor	x19, x19, x1
	bic	x0, x22, x21
	eor	x21, x21, x28
	eor	x20, x20, x0
	eor	x22, x22, x30
	bic	x0, x25, x24
	bic	x1, x26, x25
	bic	x28, x23, x27
	bic	x30, x24, x23
	eor	x23, x23, x0
	eor	x24, x24, x1
	bic	x0, x27, x26
	eor	x26, x26, x28
	eor	x25, x25, x0
	eor	x27, x27, x30
	# Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	v30.d[0], x0
	mov	v30.d[1], x0
	eor	x2, x2, x0
	eor	v0.16b, v0.16b, v30.16b
	bne	L_SHA3_shake256_blocksx3_seed_64_crypto_begin
	ldr	x0, [x29, #40]
	st4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	st1	{v24.d}[0], [x0]
	add	x0, x0, #8
	st4	{v0.d, v1.d, v2.d, v3.d}[1], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[1], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[1], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[1], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[1], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[1], [x0], #32
	st1	{v24.d}[1], [x0]
	add	x0, x0, #8
	stp	x2, x3, [x0]
	stp	x4, x5, [x0, #16]
	stp	x6, x7, [x0, #32]
	stp	x8, x9, [x0, #48]
	stp	x10, x11, [x0, #64]
	stp	x12, x13, [x0, #80]
	stp	x14, x15, [x0, #96]
	stp	x16, x17, [x0, #112]
	stp	x19, x20, [x0, #128]
	stp	x21, x22, [x0, #144]
	stp	x23, x24, [x0, #160]
	stp	x25, x26, [x0, #176]
	str	x27, [x0, #192]
	ldp	x17, x19, [x29, #72]
	ldp	x20, x21, [x29, #88]
	ldp	x22, x23, [x29, #104]
	ldp	x24, x25, [x29, #120]
	ldp	x26, x27, [x29, #136]
	ldr	x28, [x29, #152]
	ldp	d8, d9, [x29, #160]
	ldp	d10, d11, [x29, #176]
	ldp	d12, d13, [x29, #192]
	ldp	d14, d15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
#ifndef __APPLE__
	.size	sha3_256_blocksx3_seed_64_crypto,.-sha3_256_blocksx3_seed_64_crypto
#endif /* __APPLE__ */
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef __APPLE__
.text
.globl	sha3_blocksx3_neon
WC_ASM_ATT_HIDDEN(sha3_blocksx3_neon)
.type	sha3_blocksx3_neon,@function
.align	2
sha3_blocksx3_neon:
#else
.section	__TEXT,__text
.globl	_sha3_blocksx3_neon
WC_ASM_ATT_HIDDEN(_sha3_blocksx3_neon)
.p2align	2
_sha3_blocksx3_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	d8, d9, [x29, #160]
	stp	d10, d11, [x29, #176]
	stp	d12, d13, [x29, #192]
	stp	d14, d15, [x29, #208]
#ifndef __APPLE__
	adrp x27, L_sha3_aarch64_r
	add  x27, x27, :lo12:L_sha3_aarch64_r
#else
	adrp x27, L_sha3_aarch64_r@PAGE
	add  x27, x27, L_sha3_aarch64_r@PAGEOFF
#endif /* __APPLE__ */
	str	x0, [x29, #40]
	ld4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	ld4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	ld4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	ld4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	ld4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	ld4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	ld1	{v24.d}[0], [x0]
	add	x0, x0, #8
	ld4	{v0.d, v1.d, v2.d, v3.d}[1], [x0], #32
	ld4	{v4.d, v5.d, v6.d, v7.d}[1], [x0], #32
	ld4	{v8.d, v9.d, v10.d, v11.d}[1], [x0], #32
	ld4	{v12.d, v13.d, v14.d, v15.d}[1], [x0], #32
	ld4	{v16.d, v17.d, v18.d, v19.d}[1], [x0], #32
	ld4	{v20.d, v21.d, v22.d, v23.d}[1], [x0], #32
	ld1	{v24.d}[1], [x0]
	add	x0, x0, #8
	ldp	x1, x2, [x0]
	ldp	x3, x4, [x0, #16]
	ldp	x5, x6, [x0, #32]
	ldp	x7, x8, [x0, #48]
	ldp	x9, x10, [x0, #64]
	ldp	x11, x12, [x0, #80]
	ldp	x13, x14, [x0, #96]
	ldp	x15, x16, [x0, #112]
	ldp	x17, x19, [x0, #128]
	ldp	x20, x21, [x0, #144]
	ldp	x22, x23, [x0, #160]
	ldp	x24, x25, [x0, #176]
	ldr	x26, [x0, #192]
	mov	x28, #24
	# Start of 24 rounds
L_SHA3_transform_blocksx3_neon_begin:
	stp	x27, x28, [x29, #48]
	# Col Mix NEON
	eor	v30.16b, v4.16b, v9.16b
	eor	x0, x5, x10
	eor	v27.16b, v1.16b, v6.16b
	eor	x30, x1, x6
	eor	v30.16b, v30.16b, v14.16b
	eor	x28, x3, x8
	eor	v27.16b, v27.16b, v11.16b
	eor	x0, x0, x15
	eor	v30.16b, v30.16b, v19.16b
	eor	x30, x30, x11
	eor	v27.16b, v27.16b, v16.16b
	eor	x28, x28, x13
	eor	v30.16b, v30.16b, v24.16b
	eor	x0, x0, x21
	eor	v27.16b, v27.16b, v21.16b
	eor	x30, x30, x16
	ushr	v25.2d, v27.2d, #63
	eor	x28, x28, x19
	sli	v25.2d, v27.2d, #1
	eor	x0, x0, x26
	eor	v25.16b, v25.16b, v30.16b
	eor	x30, x30, x22
	eor	v31.16b, v0.16b, v5.16b
	eor	x28, x28, x24
	eor	v28.16b, v2.16b, v7.16b
	str	x0, [x29, #32]
	eor	v31.16b, v31.16b, v10.16b
	str	x28, [x29, #24]
	eor	v28.16b, v28.16b, v12.16b
	eor	x27, x2, x7
	eor	v31.16b, v31.16b, v15.16b
	eor	x28, x4, x9
	eor	v28.16b, v28.16b, v17.16b
	eor	x27, x27, x12
	eor	v31.16b, v31.16b, v20.16b
	eor	x28, x28, x14
	eor	v28.16b, v28.16b, v22.16b
	eor	x27, x27, x17
	ushr	v29.2d, v30.2d, #63
	eor	x28, x28, x20
	ushr	v26.2d, v28.2d, #63
	eor	x27, x27, x23
	sli	v29.2d, v30.2d, #1
	eor	x28, x28, x25
	sli	v26.2d, v28.2d, #1
	eor	x0, x0, x27, ror 63
	eor	v28.16b, v28.16b, v29.16b
	eor	x27, x27, x28, ror 63
	eor	v29.16b, v3.16b, v8.16b
	eor	x1, x1, x0
	eor	v26.16b, v26.16b, v31.16b
	eor	x6, x6, x0
	eor	v29.16b, v29.16b, v13.16b
	eor	x11, x11, x0
	eor	v29.16b, v29.16b, v18.16b
	eor	x16, x16, x0
	eor	v29.16b, v29.16b, v23.16b
	eor	x22, x22, x0
	ushr	v30.2d, v29.2d, #63
	eor	x3, x3, x27
	sli	v30.2d, v29.2d, #1
	eor	x8, x8, x27
	eor	v27.16b, v27.16b, v30.16b
	eor	x13, x13, x27
	ushr	v30.2d, v31.2d, #63
	eor	x19, x19, x27
	sli	v30.2d, v31.2d, #1
	eor	x24, x24, x27
	eor	v29.16b, v29.16b, v30.16b
	ldr	x0, [x29, #32]
	# Swap Rotate NEON
	eor	v0.16b, v0.16b, v25.16b
	eor	v31.16b, v1.16b, v26.16b
	ldr	x27, [x29, #24]
	eor	v6.16b, v6.16b, v26.16b
	eor	x28, x28, x30, ror 63
	ushr	v30.2d, v31.2d, #63
	eor	x30, x30, x27, ror 63
	ushr	v1.2d, v6.2d, #20
	eor	x27, x27, x0, ror 63
	sli	v30.2d, v31.2d, #1
	eor	x5, x5, x28
	sli	v1.2d, v6.2d, #44
	eor	x10, x10, x28
	eor	v31.16b, v9.16b, v29.16b
	eor	x15, x15, x28
	eor	v22.16b, v22.16b, v27.16b
	eor	x21, x21, x28
	ushr	v6.2d, v31.2d, #44
	eor	x26, x26, x28
	ushr	v9.2d, v22.2d, #3
	eor	x2, x2, x30
	sli	v6.2d, v31.2d, #20
	eor	x7, x7, x30
	sli	v9.2d, v22.2d, #61
	eor	x12, x12, x30
	eor	v31.16b, v14.16b, v29.16b
	eor	x17, x17, x30
	eor	v20.16b, v20.16b, v25.16b
	eor	x23, x23, x30
	ushr	v22.2d, v31.2d, #25
	eor	x4, x4, x27
	ushr	v14.2d, v20.2d, #46
	eor	x9, x9, x27
	sli	v22.2d, v31.2d, #39
	eor	x14, x14, x27
	sli	v14.2d, v20.2d, #18
	eor	x20, x20, x27
	eor	v31.16b, v2.16b, v27.16b
	eor	x25, x25, x27
	# Swap Rotate Base
	eor	v12.16b, v12.16b, v27.16b
	ror	x0, x2, #63
	ushr	v20.2d, v31.2d, #2
	ror	x2, x7, #20
	ushr	v2.2d, v12.2d, #21
	ror	x7, x10, #44
	sli	v20.2d, v31.2d, #62
	ror	x10, x24, #3
	sli	v2.2d, v12.2d, #43
	ror	x24, x15, #25
	eor	v31.16b, v13.16b, v28.16b
	ror	x15, x22, #46
	eor	v19.16b, v19.16b, v29.16b
	ror	x22, x3, #2
	ushr	v12.2d, v31.2d, #39
	ror	x3, x13, #21
	ushr	v13.2d, v19.2d, #56
	ror	x13, x14, #39
	sli	v12.2d, v31.2d, #25
	ror	x14, x21, #56
	sli	v13.2d, v19.2d, #8
	ror	x21, x25, #8
	eor	v31.16b, v23.16b, v28.16b
	ror	x25, x16, #23
	eor	v15.16b, v15.16b, v25.16b
	ror	x16, x5, #37
	ushr	v19.2d, v31.2d, #8
	ror	x5, x26, #50
	ushr	v23.2d, v15.2d, #23
	ror	x26, x23, #62
	sli	v19.2d, v31.2d, #56
	ror	x23, x9, #9
	sli	v23.2d, v15.2d, #41
	ror	x9, x17, #19
	eor	v31.16b, v4.16b, v29.16b
	ror	x17, x6, #28
	eor	v24.16b, v24.16b, v29.16b
	ror	x6, x4, #36
	ushr	v15.2d, v31.2d, #37
	ror	x4, x20, #43
	ushr	v4.2d, v24.2d, #50
	ror	x20, x19, #49
	sli	v15.2d, v31.2d, #27
	ror	x19, x12, #54
	sli	v4.2d, v24.2d, #14
	ror	x12, x8, #58
	eor	v31.16b, v21.16b, v26.16b
	ror	x8, x11, #61
	# Row Mix Base
	eor	v8.16b, v8.16b, v28.16b
	bic	x11, x3, x2
	ushr	v24.2d, v31.2d, #62
	bic	x27, x4, x3
	ushr	v21.2d, v8.2d, #9
	bic	x28, x1, x5
	sli	v24.2d, v31.2d, #2
	bic	x30, x2, x1
	sli	v21.2d, v8.2d, #55
	eor	x1, x1, x11
	eor	v31.16b, v16.16b, v26.16b
	eor	x2, x2, x27
	eor	v5.16b, v5.16b, v25.16b
	bic	x11, x5, x4
	ushr	v8.2d, v31.2d, #19
	eor	x4, x4, x28
	ushr	v16.2d, v5.2d, #28
	eor	x3, x3, x11
	sli	v8.2d, v31.2d, #45
	eor	x5, x5, x30
	sli	v16.2d, v5.2d, #36
	bic	x11, x8, x7
	eor	v31.16b, v3.16b, v28.16b
	bic	x27, x9, x8
	eor	v18.16b, v18.16b, v28.16b
	bic	x28, x6, x10
	ushr	v5.2d, v31.2d, #36
	bic	x30, x7, x6
	ushr	v3.2d, v18.2d, #43
	eor	x6, x6, x11
	sli	v5.2d, v31.2d, #28
	eor	x7, x7, x27
	sli	v3.2d, v18.2d, #21
	bic	x11, x10, x9
	eor	v31.16b, v17.16b, v27.16b
	eor	x9, x9, x28
	eor	v11.16b, v11.16b, v26.16b
	eor	x8, x8, x11
	ushr	v18.2d, v31.2d, #49
	eor	x10, x10, x30
	ushr	v17.2d, v11.2d, #54
	bic	x11, x13, x12
	sli	v18.2d, v31.2d, #15
	bic	x27, x14, x13
	sli	v17.2d, v11.2d, #10
	bic	x28, x0, x15
	eor	v31.16b, v7.16b, v27.16b
	bic	x30, x12, x0
	eor	v10.16b, v10.16b, v25.16b
	eor	x11, x0, x11
	ushr	v11.2d, v31.2d, #58
	eor	x12, x12, x27
	ushr	v7.2d, v10.2d, #61
	bic	x0, x15, x14
	sli	v11.2d, v31.2d, #6
	eor	x14, x14, x28
	sli	v7.2d, v10.2d, #3
	eor	x13, x13, x0
	# Row Mix NEON
	bic	v25.16b, v2.16b, v1.16b
	eor	x15, x15, x30
	bic	v26.16b, v3.16b, v2.16b
	bic	x0, x19, x17
	bic	v27.16b, v4.16b, v3.16b
	bic	x27, x20, x19
	bic	v28.16b, v0.16b, v4.16b
	bic	x28, x16, x21
	bic	v29.16b, v1.16b, v0.16b
	bic	x30, x17, x16
	eor	v0.16b, v0.16b, v25.16b
	eor	x16, x16, x0
	eor	v1.16b, v1.16b, v26.16b
	eor	x17, x17, x27
	eor	v2.16b, v2.16b, v27.16b
	bic	x0, x21, x20
	eor	v3.16b, v3.16b, v28.16b
	eor	x20, x20, x28
	eor	v4.16b, v4.16b, v29.16b
	eor	x19, x19, x0
	bic	v25.16b, v7.16b, v6.16b
	eor	x21, x21, x30
	bic	v26.16b, v8.16b, v7.16b
	bic	x0, x24, x23
	bic	v27.16b, v9.16b, v8.16b
	bic	x27, x25, x24
	bic	v28.16b, v5.16b, v9.16b
	bic	x28, x22, x26
	bic	v29.16b, v6.16b, v5.16b
	bic	x30, x23, x22
	eor	v5.16b, v5.16b, v25.16b
	eor	x22, x22, x0
	eor	v6.16b, v6.16b, v26.16b
	eor	x23, x23, x27
	eor	v7.16b, v7.16b, v27.16b
	bic	x0, x26, x25
	eor	v8.16b, v8.16b, v28.16b
	eor	x25, x25, x28
	eor	v9.16b, v9.16b, v29.16b
	eor	x24, x24, x0
	bic	v25.16b, v12.16b, v11.16b
	eor	x26, x26, x30
	bic	v26.16b, v13.16b, v12.16b
	bic	v27.16b, v14.16b, v13.16b
	bic	v28.16b, v30.16b, v14.16b
	bic	v29.16b, v11.16b, v30.16b
	eor	v10.16b, v30.16b, v25.16b
	eor	v11.16b, v11.16b, v26.16b
	eor	v12.16b, v12.16b, v27.16b
	eor	v13.16b, v13.16b, v28.16b
	eor	v14.16b, v14.16b, v29.16b
	bic	v25.16b, v17.16b, v16.16b
	bic	v26.16b, v18.16b, v17.16b
	bic	v27.16b, v19.16b, v18.16b
	bic	v28.16b, v15.16b, v19.16b
	bic	v29.16b, v16.16b, v15.16b
	eor	v15.16b, v15.16b, v25.16b
	eor	v16.16b, v16.16b, v26.16b
	eor	v17.16b, v17.16b, v27.16b
	eor	v18.16b, v18.16b, v28.16b
	eor	v19.16b, v19.16b, v29.16b
	bic	v25.16b, v22.16b, v21.16b
	bic	v26.16b, v23.16b, v22.16b
	bic	v27.16b, v24.16b, v23.16b
	bic	v28.16b, v20.16b, v24.16b
	bic	v29.16b, v21.16b, v20.16b
	eor	v20.16b, v20.16b, v25.16b
	eor	v21.16b, v21.16b, v26.16b
	eor	v22.16b, v22.16b, v27.16b
	eor	v23.16b, v23.16b, v28.16b
	eor	v24.16b, v24.16b, v29.16b
	# Done transforming
	ldp	x27, x28, [x29, #48]
	ldr	x0, [x27], #8
	subs	x28, x28, #1
	mov	v30.d[0], x0
	mov	v30.d[1], x0
	eor	x1, x1, x0
	eor	v0.16b, v0.16b, v30.16b
	bne	L_SHA3_transform_blocksx3_neon_begin
	ldr	x0, [x29, #40]
	st4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	st1	{v24.d}[0], [x0]
	add	x0, x0, #8
	st4	{v0.d, v1.d, v2.d, v3.d}[1], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[1], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[1], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[1], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[1], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[1], [x0], #32
	st1	{v24.d}[1], [x0]
	add	x0, x0, #8
	stp	x1, x2, [x0]
	stp	x3, x4, [x0, #16]
	stp	x5, x6, [x0, #32]
	stp	x7, x8, [x0, #48]
	stp	x9, x10, [x0, #64]
	stp	x11, x12, [x0, #80]
	stp	x13, x14, [x0, #96]
	stp	x15, x16, [x0, #112]
	stp	x17, x19, [x0, #128]
	stp	x20, x21, [x0, #144]
	stp	x22, x23, [x0, #160]
	stp	x24, x25, [x0, #176]
	str	x26, [x0, #192]
	ldp	x17, x19, [x29, #72]
	ldp	x20, x21, [x29, #88]
	ldp	x22, x23, [x29, #104]
	ldp	x24, x25, [x29, #120]
	ldp	x26, x27, [x29, #136]
	ldr	x28, [x29, #152]
	ldp	d8, d9, [x29, #160]
	ldp	d10, d11, [x29, #176]
	ldp	d12, d13, [x29, #192]
	ldp	d14, d15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
#ifndef __APPLE__
	.size	sha3_blocksx3_neon,.-sha3_blocksx3_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	sha3_128_blocksx3_seed_neon
WC_ASM_ATT_HIDDEN(sha3_128_blocksx3_seed_neon)
.type	sha3_128_blocksx3_seed_neon,@function
.align	2
sha3_128_blocksx3_seed_neon:
#else
.section	__TEXT,__text
.globl	_sha3_128_blocksx3_seed_neon
WC_ASM_ATT_HIDDEN(_sha3_128_blocksx3_seed_neon)
.p2align	2
_sha3_128_blocksx3_seed_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	d8, d9, [x29, #160]
	stp	d10, d11, [x29, #176]
	stp	d12, d13, [x29, #192]
	stp	d14, d15, [x29, #208]
#ifndef __APPLE__
	adrp x28, L_sha3_aarch64_r
	add  x28, x28, :lo12:L_sha3_aarch64_r
#else
	adrp x28, L_sha3_aarch64_r@PAGE
	add  x28, x28, L_sha3_aarch64_r@PAGEOFF
#endif /* __APPLE__ */
	str	x0, [x29, #40]
	add	x0, x0, #32
	ld1	{v4.d}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{v4.d}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldr	x6, [x0, #200]
	eor	v5.16b, v5.16b, v5.16b
	eor	x7, x7, x7
	eor	v6.16b, v6.16b, v6.16b
	eor	x8, x8, x8
	eor	v7.16b, v7.16b, v7.16b
	eor	x9, x9, x9
	eor	v8.16b, v8.16b, v8.16b
	eor	x10, x10, x10
	eor	v9.16b, v9.16b, v9.16b
	eor	x11, x11, x11
	eor	v10.16b, v10.16b, v10.16b
	eor	x12, x12, x12
	eor	v11.16b, v11.16b, v11.16b
	eor	x13, x13, x13
	eor	v12.16b, v12.16b, v12.16b
	eor	x14, x14, x14
	eor	v13.16b, v13.16b, v13.16b
	eor	x15, x15, x15
	eor	v14.16b, v14.16b, v14.16b
	eor	x16, x16, x16
	eor	v15.16b, v15.16b, v15.16b
	eor	x17, x17, x17
	eor	v16.16b, v16.16b, v16.16b
	eor	x19, x19, x19
	eor	v17.16b, v17.16b, v17.16b
	eor	x20, x20, x20
	eor	v18.16b, v18.16b, v18.16b
	eor	x21, x21, x21
	eor	v19.16b, v19.16b, v19.16b
	eor	x22, x22, x22
	movz	x23, #0x8000, lsl 48
	eor	v21.16b, v21.16b, v21.16b
	eor	x24, x24, x24
	eor	v22.16b, v22.16b, v22.16b
	eor	x25, x25, x25
	eor	v23.16b, v23.16b, v23.16b
	eor	x26, x26, x26
	eor	v24.16b, v24.16b, v24.16b
	eor	x27, x27, x27
	dup	v0.2d, x2
	dup	v1.2d, x3
	dup	v2.2d, x4
	dup	v3.2d, x5
	dup	v20.2d, x23
	mov	x1, #24
	# Start of 24 rounds
L_SHA3_shake128_blocksx3_seed_neon_begin:
	stp	x28, x1, [x29, #48]
	# Col Mix NEON
	eor	v30.16b, v4.16b, v9.16b
	eor	x0, x6, x11
	eor	v27.16b, v1.16b, v6.16b
	eor	x30, x2, x7
	eor	v30.16b, v30.16b, v14.16b
	eor	x28, x4, x9
	eor	v27.16b, v27.16b, v11.16b
	eor	x0, x0, x16
	eor	v30.16b, v30.16b, v19.16b
	eor	x30, x30, x12
	eor	v27.16b, v27.16b, v16.16b
	eor	x28, x28, x14
	eor	v30.16b, v30.16b, v24.16b
	eor	x0, x0, x22
	eor	v27.16b, v27.16b, v21.16b
	eor	x30, x30, x17
	ushr	v25.2d, v27.2d, #63
	eor	x28, x28, x20
	sli	v25.2d, v27.2d, #1
	eor	x0, x0, x27
	eor	v25.16b, v25.16b, v30.16b
	eor	x30, x30, x23
	eor	v31.16b, v0.16b, v5.16b
	eor	x28, x28, x25
	eor	v28.16b, v2.16b, v7.16b
	str	x0, [x29, #32]
	eor	v31.16b, v31.16b, v10.16b
	str	x28, [x29, #24]
	eor	v28.16b, v28.16b, v12.16b
	eor	x1, x3, x8
	eor	v31.16b, v31.16b, v15.16b
	eor	x28, x5, x10
	eor	v28.16b, v28.16b, v17.16b
	eor	x1, x1, x13
	eor	v31.16b, v31.16b, v20.16b
	eor	x28, x28, x15
	eor	v28.16b, v28.16b, v22.16b
	eor	x1, x1, x19
	ushr	v29.2d, v30.2d, #63
	eor	x28, x28, x21
	ushr	v26.2d, v28.2d, #63
	eor	x1, x1, x24
	sli	v29.2d, v30.2d, #1
	eor	x28, x28, x26
	sli	v26.2d, v28.2d, #1
	eor	x0, x0, x1, ror 63
	eor	v28.16b, v28.16b, v29.16b
	eor	x1, x1, x28, ror 63
	eor	v29.16b, v3.16b, v8.16b
	eor	x2, x2, x0
	eor	v26.16b, v26.16b, v31.16b
	eor	x7, x7, x0
	eor	v29.16b, v29.16b, v13.16b
	eor	x12, x12, x0
	eor	v29.16b, v29.16b, v18.16b
	eor	x17, x17, x0
	eor	v29.16b, v29.16b, v23.16b
	eor	x23, x23, x0
	ushr	v30.2d, v29.2d, #63
	eor	x4, x4, x1
	sli	v30.2d, v29.2d, #1
	eor	x9, x9, x1
	eor	v27.16b, v27.16b, v30.16b
	eor	x14, x14, x1
	ushr	v30.2d, v31.2d, #63
	eor	x20, x20, x1
	sli	v30.2d, v31.2d, #1
	eor	x25, x25, x1
	eor	v29.16b, v29.16b, v30.16b
	ldr	x0, [x29, #32]
	# Swap Rotate NEON
	eor	v0.16b, v0.16b, v25.16b
	eor	v31.16b, v1.16b, v26.16b
	ldr	x1, [x29, #24]
	eor	v6.16b, v6.16b, v26.16b
	eor	x28, x28, x30, ror 63
	ushr	v30.2d, v31.2d, #63
	eor	x30, x30, x1, ror 63
	ushr	v1.2d, v6.2d, #20
	eor	x1, x1, x0, ror 63
	sli	v30.2d, v31.2d, #1
	eor	x6, x6, x28
	sli	v1.2d, v6.2d, #44
	eor	x11, x11, x28
	eor	v31.16b, v9.16b, v29.16b
	eor	x16, x16, x28
	eor	v22.16b, v22.16b, v27.16b
	eor	x22, x22, x28
	ushr	v6.2d, v31.2d, #44
	eor	x27, x27, x28
	ushr	v9.2d, v22.2d, #3
	eor	x3, x3, x30
	sli	v6.2d, v31.2d, #20
	eor	x8, x8, x30
	sli	v9.2d, v22.2d, #61
	eor	x13, x13, x30
	eor	v31.16b, v14.16b, v29.16b
	eor	x19, x19, x30
	eor	v20.16b, v20.16b, v25.16b
	eor	x24, x24, x30
	ushr	v22.2d, v31.2d, #25
	eor	x5, x5, x1
	ushr	v14.2d, v20.2d, #46
	eor	x10, x10, x1
	sli	v22.2d, v31.2d, #39
	eor	x15, x15, x1
	sli	v14.2d, v20.2d, #18
	eor	x21, x21, x1
	eor	v31.16b, v2.16b, v27.16b
	eor	x26, x26, x1
	# Swap Rotate Base
	eor	v12.16b, v12.16b, v27.16b
	ror	x0, x3, #63
	ushr	v20.2d, v31.2d, #2
	ror	x3, x8, #20
	ushr	v2.2d, v12.2d, #21
	ror	x8, x11, #44
	sli	v20.2d, v31.2d, #62
	ror	x11, x25, #3
	sli	v2.2d, v12.2d, #43
	ror	x25, x16, #25
	eor	v31.16b, v13.16b, v28.16b
	ror	x16, x23, #46
	eor	v19.16b, v19.16b, v29.16b
	ror	x23, x4, #2
	ushr	v12.2d, v31.2d, #39
	ror	x4, x14, #21
	ushr	v13.2d, v19.2d, #56
	ror	x14, x15, #39
	sli	v12.2d, v31.2d, #25
	ror	x15, x22, #56
	sli	v13.2d, v19.2d, #8
	ror	x22, x26, #8
	eor	v31.16b, v23.16b, v28.16b
	ror	x26, x17, #23
	eor	v15.16b, v15.16b, v25.16b
	ror	x17, x6, #37
	ushr	v19.2d, v31.2d, #8
	ror	x6, x27, #50
	ushr	v23.2d, v15.2d, #23
	ror	x27, x24, #62
	sli	v19.2d, v31.2d, #56
	ror	x24, x10, #9
	sli	v23.2d, v15.2d, #41
	ror	x10, x19, #19
	eor	v31.16b, v4.16b, v29.16b
	ror	x19, x7, #28
	eor	v24.16b, v24.16b, v29.16b
	ror	x7, x5, #36
	ushr	v15.2d, v31.2d, #37
	ror	x5, x21, #43
	ushr	v4.2d, v24.2d, #50
	ror	x21, x20, #49
	sli	v15.2d, v31.2d, #27
	ror	x20, x13, #54
	sli	v4.2d, v24.2d, #14
	ror	x13, x9, #58
	eor	v31.16b, v21.16b, v26.16b
	ror	x9, x12, #61
	# Row Mix Base
	eor	v8.16b, v8.16b, v28.16b
	bic	x12, x4, x3
	ushr	v24.2d, v31.2d, #62
	bic	x1, x5, x4
	ushr	v21.2d, v8.2d, #9
	bic	x28, x2, x6
	sli	v24.2d, v31.2d, #2
	bic	x30, x3, x2
	sli	v21.2d, v8.2d, #55
	eor	x2, x2, x12
	eor	v31.16b, v16.16b, v26.16b
	eor	x3, x3, x1
	eor	v5.16b, v5.16b, v25.16b
	bic	x12, x6, x5
	ushr	v8.2d, v31.2d, #19
	eor	x5, x5, x28
	ushr	v16.2d, v5.2d, #28
	eor	x4, x4, x12
	sli	v8.2d, v31.2d, #45
	eor	x6, x6, x30
	sli	v16.2d, v5.2d, #36
	bic	x12, x9, x8
	eor	v31.16b, v3.16b, v28.16b
	bic	x1, x10, x9
	eor	v18.16b, v18.16b, v28.16b
	bic	x28, x7, x11
	ushr	v5.2d, v31.2d, #36
	bic	x30, x8, x7
	ushr	v3.2d, v18.2d, #43
	eor	x7, x7, x12
	sli	v5.2d, v31.2d, #28
	eor	x8, x8, x1
	sli	v3.2d, v18.2d, #21
	bic	x12, x11, x10
	eor	v31.16b, v17.16b, v27.16b
	eor	x10, x10, x28
	eor	v11.16b, v11.16b, v26.16b
	eor	x9, x9, x12
	ushr	v18.2d, v31.2d, #49
	eor	x11, x11, x30
	ushr	v17.2d, v11.2d, #54
	bic	x12, x14, x13
	sli	v18.2d, v31.2d, #15
	bic	x1, x15, x14
	sli	v17.2d, v11.2d, #10
	bic	x28, x0, x16
	eor	v31.16b, v7.16b, v27.16b
	bic	x30, x13, x0
	eor	v10.16b, v10.16b, v25.16b
	eor	x12, x0, x12
	ushr	v11.2d, v31.2d, #58
	eor	x13, x13, x1
	ushr	v7.2d, v10.2d, #61
	bic	x0, x16, x15
	sli	v11.2d, v31.2d, #6
	eor	x15, x15, x28
	sli	v7.2d, v10.2d, #3
	eor	x14, x14, x0
	# Row Mix NEON
	bic	v25.16b, v2.16b, v1.16b
	eor	x16, x16, x30
	bic	v26.16b, v3.16b, v2.16b
	bic	x0, x20, x19
	bic	v27.16b, v4.16b, v3.16b
	bic	x1, x21, x20
	bic	v28.16b, v0.16b, v4.16b
	bic	x28, x17, x22
	bic	v29.16b, v1.16b, v0.16b
	bic	x30, x19, x17
	eor	v0.16b, v0.16b, v25.16b
	eor	x17, x17, x0
	eor	v1.16b, v1.16b, v26.16b
	eor	x19, x19, x1
	eor	v2.16b, v2.16b, v27.16b
	bic	x0, x22, x21
	eor	v3.16b, v3.16b, v28.16b
	eor	x21, x21, x28
	eor	v4.16b, v4.16b, v29.16b
	eor	x20, x20, x0
	bic	v25.16b, v7.16b, v6.16b
	eor	x22, x22, x30
	bic	v26.16b, v8.16b, v7.16b
	bic	x0, x25, x24
	bic	v27.16b, v9.16b, v8.16b
	bic	x1, x26, x25
	bic	v28.16b, v5.16b, v9.16b
	bic	x28, x23, x27
	bic	v29.16b, v6.16b, v5.16b
	bic	x30, x24, x23
	eor	v5.16b, v5.16b, v25.16b
	eor	x23, x23, x0
	eor	v6.16b, v6.16b, v26.16b
	eor	x24, x24, x1
	eor	v7.16b, v7.16b, v27.16b
	bic	x0, x27, x26
	eor	v8.16b, v8.16b, v28.16b
	eor	x26, x26, x28
	eor	v9.16b, v9.16b, v29.16b
	eor	x25, x25, x0
	bic	v25.16b, v12.16b, v11.16b
	eor	x27, x27, x30
	bic	v26.16b, v13.16b, v12.16b
	bic	v27.16b, v14.16b, v13.16b
	bic	v28.16b, v30.16b, v14.16b
	bic	v29.16b, v11.16b, v30.16b
	eor	v10.16b, v30.16b, v25.16b
	eor	v11.16b, v11.16b, v26.16b
	eor	v12.16b, v12.16b, v27.16b
	eor	v13.16b, v13.16b, v28.16b
	eor	v14.16b, v14.16b, v29.16b
	bic	v25.16b, v17.16b, v16.16b
	bic	v26.16b, v18.16b, v17.16b
	bic	v27.16b, v19.16b, v18.16b
	bic	v28.16b, v15.16b, v19.16b
	bic	v29.16b, v16.16b, v15.16b
	eor	v15.16b, v15.16b, v25.16b
	eor	v16.16b, v16.16b, v26.16b
	eor	v17.16b, v17.16b, v27.16b
	eor	v18.16b, v18.16b, v28.16b
	eor	v19.16b, v19.16b, v29.16b
	bic	v25.16b, v22.16b, v21.16b
	bic	v26.16b, v23.16b, v22.16b
	bic	v27.16b, v24.16b, v23.16b
	bic	v28.16b, v20.16b, v24.16b
	bic	v29.16b, v21.16b, v20.16b
	eor	v20.16b, v20.16b, v25.16b
	eor	v21.16b, v21.16b, v26.16b
	eor	v22.16b, v22.16b, v27.16b
	eor	v23.16b, v23.16b, v28.16b
	eor	v24.16b, v24.16b, v29.16b
	# Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	v30.d[0], x0
	mov	v30.d[1], x0
	eor	x2, x2, x0
	eor	v0.16b, v0.16b, v30.16b
	bne	L_SHA3_shake128_blocksx3_seed_neon_begin
	ldr	x0, [x29, #40]
	st4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	st1	{v24.d}[0], [x0]
	add	x0, x0, #8
	st4	{v0.d, v1.d, v2.d, v3.d}[1], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[1], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[1], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[1], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[1], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[1], [x0], #32
	st1	{v24.d}[1], [x0]
	add	x0, x0, #8
	stp	x2, x3, [x0]
	stp	x4, x5, [x0, #16]
	stp	x6, x7, [x0, #32]
	stp	x8, x9, [x0, #48]
	stp	x10, x11, [x0, #64]
	stp	x12, x13, [x0, #80]
	stp	x14, x15, [x0, #96]
	stp	x16, x17, [x0, #112]
	stp	x19, x20, [x0, #128]
	stp	x21, x22, [x0, #144]
	stp	x23, x24, [x0, #160]
	stp	x25, x26, [x0, #176]
	str	x27, [x0, #192]
	ldp	x17, x19, [x29, #72]
	ldp	x20, x21, [x29, #88]
	ldp	x22, x23, [x29, #104]
	ldp	x24, x25, [x29, #120]
	ldp	x26, x27, [x29, #136]
	ldr	x28, [x29, #152]
	ldp	d8, d9, [x29, #160]
	ldp	d10, d11, [x29, #176]
	ldp	d12, d13, [x29, #192]
	ldp	d14, d15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
#ifndef __APPLE__
	.size	sha3_128_blocksx3_seed_neon,.-sha3_128_blocksx3_seed_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	sha3_256_blocksx3_seed_neon
WC_ASM_ATT_HIDDEN(sha3_256_blocksx3_seed_neon)
.type	sha3_256_blocksx3_seed_neon,@function
.align	2
sha3_256_blocksx3_seed_neon:
#else
.section	__TEXT,__text
.globl	_sha3_256_blocksx3_seed_neon
WC_ASM_ATT_HIDDEN(_sha3_256_blocksx3_seed_neon)
.p2align	2
_sha3_256_blocksx3_seed_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	d8, d9, [x29, #160]
	stp	d10, d11, [x29, #176]
	stp	d12, d13, [x29, #192]
	stp	d14, d15, [x29, #208]
#ifndef __APPLE__
	adrp x28, L_sha3_aarch64_r
	add  x28, x28, :lo12:L_sha3_aarch64_r
#else
	adrp x28, L_sha3_aarch64_r@PAGE
	add  x28, x28, L_sha3_aarch64_r@PAGEOFF
#endif /* __APPLE__ */
	str	x0, [x29, #40]
	add	x0, x0, #32
	ld1	{v4.d}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{v4.d}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldr	x6, [x0, #200]
	eor	v5.16b, v5.16b, v5.16b
	eor	x7, x7, x7
	eor	v6.16b, v6.16b, v6.16b
	eor	x8, x8, x8
	eor	v7.16b, v7.16b, v7.16b
	eor	x9, x9, x9
	eor	v8.16b, v8.16b, v8.16b
	eor	x10, x10, x10
	eor	v9.16b, v9.16b, v9.16b
	eor	x11, x11, x11
	eor	v10.16b, v10.16b, v10.16b
	eor	x12, x12, x12
	eor	v11.16b, v11.16b, v11.16b
	eor	x13, x13, x13
	eor	v12.16b, v12.16b, v12.16b
	eor	x14, x14, x14
	eor	v13.16b, v13.16b, v13.16b
	eor	x15, x15, x15
	eor	v14.16b, v14.16b, v14.16b
	eor	x16, x16, x16
	eor	v15.16b, v15.16b, v15.16b
	eor	x17, x17, x17
	movz	x19, #0x8000, lsl 48
	eor	v17.16b, v17.16b, v17.16b
	eor	x20, x20, x20
	eor	v18.16b, v18.16b, v18.16b
	eor	x21, x21, x21
	eor	v19.16b, v19.16b, v19.16b
	eor	x22, x22, x22
	eor	v20.16b, v20.16b, v20.16b
	eor	x23, x23, x23
	eor	v21.16b, v21.16b, v21.16b
	eor	x24, x24, x24
	eor	v22.16b, v22.16b, v22.16b
	eor	x25, x25, x25
	eor	v23.16b, v23.16b, v23.16b
	eor	x26, x26, x26
	eor	v24.16b, v24.16b, v24.16b
	eor	x27, x27, x27
	dup	v0.2d, x2
	dup	v1.2d, x3
	dup	v2.2d, x4
	dup	v3.2d, x5
	dup	v16.2d, x19
	mov	x1, #24
	# Start of 24 rounds
L_SHA3_shake256_blocksx3_seed_neon_begin:
	stp	x28, x1, [x29, #48]
	# Col Mix NEON
	eor	v30.16b, v4.16b, v9.16b
	eor	x0, x6, x11
	eor	v27.16b, v1.16b, v6.16b
	eor	x30, x2, x7
	eor	v30.16b, v30.16b, v14.16b
	eor	x28, x4, x9
	eor	v27.16b, v27.16b, v11.16b
	eor	x0, x0, x16
	eor	v30.16b, v30.16b, v19.16b
	eor	x30, x30, x12
	eor	v27.16b, v27.16b, v16.16b
	eor	x28, x28, x14
	eor	v30.16b, v30.16b, v24.16b
	eor	x0, x0, x22
	eor	v27.16b, v27.16b, v21.16b
	eor	x30, x30, x17
	ushr	v25.2d, v27.2d, #63
	eor	x28, x28, x20
	sli	v25.2d, v27.2d, #1
	eor	x0, x0, x27
	eor	v25.16b, v25.16b, v30.16b
	eor	x30, x30, x23
	eor	v31.16b, v0.16b, v5.16b
	eor	x28, x28, x25
	eor	v28.16b, v2.16b, v7.16b
	str	x0, [x29, #32]
	eor	v31.16b, v31.16b, v10.16b
	str	x28, [x29, #24]
	eor	v28.16b, v28.16b, v12.16b
	eor	x1, x3, x8
	eor	v31.16b, v31.16b, v15.16b
	eor	x28, x5, x10
	eor	v28.16b, v28.16b, v17.16b
	eor	x1, x1, x13
	eor	v31.16b, v31.16b, v20.16b
	eor	x28, x28, x15
	eor	v28.16b, v28.16b, v22.16b
	eor	x1, x1, x19
	ushr	v29.2d, v30.2d, #63
	eor	x28, x28, x21
	ushr	v26.2d, v28.2d, #63
	eor	x1, x1, x24
	sli	v29.2d, v30.2d, #1
	eor	x28, x28, x26
	sli	v26.2d, v28.2d, #1
	eor	x0, x0, x1, ror 63
	eor	v28.16b, v28.16b, v29.16b
	eor	x1, x1, x28, ror 63
	eor	v29.16b, v3.16b, v8.16b
	eor	x2, x2, x0
	eor	v26.16b, v26.16b, v31.16b
	eor	x7, x7, x0
	eor	v29.16b, v29.16b, v13.16b
	eor	x12, x12, x0
	eor	v29.16b, v29.16b, v18.16b
	eor	x17, x17, x0
	eor	v29.16b, v29.16b, v23.16b
	eor	x23, x23, x0
	ushr	v30.2d, v29.2d, #63
	eor	x4, x4, x1
	sli	v30.2d, v29.2d, #1
	eor	x9, x9, x1
	eor	v27.16b, v27.16b, v30.16b
	eor	x14, x14, x1
	ushr	v30.2d, v31.2d, #63
	eor	x20, x20, x1
	sli	v30.2d, v31.2d, #1
	eor	x25, x25, x1
	eor	v29.16b, v29.16b, v30.16b
	ldr	x0, [x29, #32]
	# Swap Rotate NEON
	eor	v0.16b, v0.16b, v25.16b
	eor	v31.16b, v1.16b, v26.16b
	ldr	x1, [x29, #24]
	eor	v6.16b, v6.16b, v26.16b
	eor	x28, x28, x30, ror 63
	ushr	v30.2d, v31.2d, #63
	eor	x30, x30, x1, ror 63
	ushr	v1.2d, v6.2d, #20
	eor	x1, x1, x0, ror 63
	sli	v30.2d, v31.2d, #1
	eor	x6, x6, x28
	sli	v1.2d, v6.2d, #44
	eor	x11, x11, x28
	eor	v31.16b, v9.16b, v29.16b
	eor	x16, x16, x28
	eor	v22.16b, v22.16b, v27.16b
	eor	x22, x22, x28
	ushr	v6.2d, v31.2d, #44
	eor	x27, x27, x28
	ushr	v9.2d, v22.2d, #3
	eor	x3, x3, x30
	sli	v6.2d, v31.2d, #20
	eor	x8, x8, x30
	sli	v9.2d, v22.2d, #61
	eor	x13, x13, x30
	eor	v31.16b, v14.16b, v29.16b
	eor	x19, x19, x30
	eor	v20.16b, v20.16b, v25.16b
	eor	x24, x24, x30
	ushr	v22.2d, v31.2d, #25
	eor	x5, x5, x1
	ushr	v14.2d, v20.2d, #46
	eor	x10, x10, x1
	sli	v22.2d, v31.2d, #39
	eor	x15, x15, x1
	sli	v14.2d, v20.2d, #18
	eor	x21, x21, x1
	eor	v31.16b, v2.16b, v27.16b
	eor	x26, x26, x1
	# Swap Rotate Base
	eor	v12.16b, v12.16b, v27.16b
	ror	x0, x3, #63
	ushr	v20.2d, v31.2d, #2
	ror	x3, x8, #20
	ushr	v2.2d, v12.2d, #21
	ror	x8, x11, #44
	sli	v20.2d, v31.2d, #62
	ror	x11, x25, #3
	sli	v2.2d, v12.2d, #43
	ror	x25, x16, #25
	eor	v31.16b, v13.16b, v28.16b
	ror	x16, x23, #46
	eor	v19.16b, v19.16b, v29.16b
	ror	x23, x4, #2
	ushr	v12.2d, v31.2d, #39
	ror	x4, x14, #21
	ushr	v13.2d, v19.2d, #56
	ror	x14, x15, #39
	sli	v12.2d, v31.2d, #25
	ror	x15, x22, #56
	sli	v13.2d, v19.2d, #8
	ror	x22, x26, #8
	eor	v31.16b, v23.16b, v28.16b
	ror	x26, x17, #23
	eor	v15.16b, v15.16b, v25.16b
	ror	x17, x6, #37
	ushr	v19.2d, v31.2d, #8
	ror	x6, x27, #50
	ushr	v23.2d, v15.2d, #23
	ror	x27, x24, #62
	sli	v19.2d, v31.2d, #56
	ror	x24, x10, #9
	sli	v23.2d, v15.2d, #41
	ror	x10, x19, #19
	eor	v31.16b, v4.16b, v29.16b
	ror	x19, x7, #28
	eor	v24.16b, v24.16b, v29.16b
	ror	x7, x5, #36
	ushr	v15.2d, v31.2d, #37
	ror	x5, x21, #43
	ushr	v4.2d, v24.2d, #50
	ror	x21, x20, #49
	sli	v15.2d, v31.2d, #27
	ror	x20, x13, #54
	sli	v4.2d, v24.2d, #14
	ror	x13, x9, #58
	eor	v31.16b, v21.16b, v26.16b
	ror	x9, x12, #61
	# Row Mix Base
	eor	v8.16b, v8.16b, v28.16b
	bic	x12, x4, x3
	ushr	v24.2d, v31.2d, #62
	bic	x1, x5, x4
	ushr	v21.2d, v8.2d, #9
	bic	x28, x2, x6
	sli	v24.2d, v31.2d, #2
	bic	x30, x3, x2
	sli	v21.2d, v8.2d, #55
	eor	x2, x2, x12
	eor	v31.16b, v16.16b, v26.16b
	eor	x3, x3, x1
	eor	v5.16b, v5.16b, v25.16b
	bic	x12, x6, x5
	ushr	v8.2d, v31.2d, #19
	eor	x5, x5, x28
	ushr	v16.2d, v5.2d, #28
	eor	x4, x4, x12
	sli	v8.2d, v31.2d, #45
	eor	x6, x6, x30
	sli	v16.2d, v5.2d, #36
	bic	x12, x9, x8
	eor	v31.16b, v3.16b, v28.16b
	bic	x1, x10, x9
	eor	v18.16b, v18.16b, v28.16b
	bic	x28, x7, x11
	ushr	v5.2d, v31.2d, #36
	bic	x30, x8, x7
	ushr	v3.2d, v18.2d, #43
	eor	x7, x7, x12
	sli	v5.2d, v31.2d, #28
	eor	x8, x8, x1
	sli	v3.2d, v18.2d, #21
	bic	x12, x11, x10
	eor	v31.16b, v17.16b, v27.16b
	eor	x10, x10, x28
	eor	v11.16b, v11.16b, v26.16b
	eor	x9, x9, x12
	ushr	v18.2d, v31.2d, #49
	eor	x11, x11, x30
	ushr	v17.2d, v11.2d, #54
	bic	x12, x14, x13
	sli	v18.2d, v31.2d, #15
	bic	x1, x15, x14
	sli	v17.2d, v11.2d, #10
	bic	x28, x0, x16
	eor	v31.16b, v7.16b, v27.16b
	bic	x30, x13, x0
	eor	v10.16b, v10.16b, v25.16b
	eor	x12, x0, x12
	ushr	v11.2d, v31.2d, #58
	eor	x13, x13, x1
	ushr	v7.2d, v10.2d, #61
	bic	x0, x16, x15
	sli	v11.2d, v31.2d, #6
	eor	x15, x15, x28
	sli	v7.2d, v10.2d, #3
	eor	x14, x14, x0
	# Row Mix NEON
	bic	v25.16b, v2.16b, v1.16b
	eor	x16, x16, x30
	bic	v26.16b, v3.16b, v2.16b
	bic	x0, x20, x19
	bic	v27.16b, v4.16b, v3.16b
	bic	x1, x21, x20
	bic	v28.16b, v0.16b, v4.16b
	bic	x28, x17, x22
	bic	v29.16b, v1.16b, v0.16b
	bic	x30, x19, x17
	eor	v0.16b, v0.16b, v25.16b
	eor	x17, x17, x0
	eor	v1.16b, v1.16b, v26.16b
	eor	x19, x19, x1
	eor	v2.16b, v2.16b, v27.16b
	bic	x0, x22, x21
	eor	v3.16b, v3.16b, v28.16b
	eor	x21, x21, x28
	eor	v4.16b, v4.16b, v29.16b
	eor	x20, x20, x0
	bic	v25.16b, v7.16b, v6.16b
	eor	x22, x22, x30
	bic	v26.16b, v8.16b, v7.16b
	bic	x0, x25, x24
	bic	v27.16b, v9.16b, v8.16b
	bic	x1, x26, x25
	bic	v28.16b, v5.16b, v9.16b
	bic	x28, x23, x27
	bic	v29.16b, v6.16b, v5.16b
	bic	x30, x24, x23
	eor	v5.16b, v5.16b, v25.16b
	eor	x23, x23, x0
	eor	v6.16b, v6.16b, v26.16b
	eor	x24, x24, x1
	eor	v7.16b, v7.16b, v27.16b
	bic	x0, x27, x26
	eor	v8.16b, v8.16b, v28.16b
	eor	x26, x26, x28
	eor	v9.16b, v9.16b, v29.16b
	eor	x25, x25, x0
	bic	v25.16b, v12.16b, v11.16b
	eor	x27, x27, x30
	bic	v26.16b, v13.16b, v12.16b
	bic	v27.16b, v14.16b, v13.16b
	bic	v28.16b, v30.16b, v14.16b
	bic	v29.16b, v11.16b, v30.16b
	eor	v10.16b, v30.16b, v25.16b
	eor	v11.16b, v11.16b, v26.16b
	eor	v12.16b, v12.16b, v27.16b
	eor	v13.16b, v13.16b, v28.16b
	eor	v14.16b, v14.16b, v29.16b
	bic	v25.16b, v17.16b, v16.16b
	bic	v26.16b, v18.16b, v17.16b
	bic	v27.16b, v19.16b, v18.16b
	bic	v28.16b, v15.16b, v19.16b
	bic	v29.16b, v16.16b, v15.16b
	eor	v15.16b, v15.16b, v25.16b
	eor	v16.16b, v16.16b, v26.16b
	eor	v17.16b, v17.16b, v27.16b
	eor	v18.16b, v18.16b, v28.16b
	eor	v19.16b, v19.16b, v29.16b
	bic	v25.16b, v22.16b, v21.16b
	bic	v26.16b, v23.16b, v22.16b
	bic	v27.16b, v24.16b, v23.16b
	bic	v28.16b, v20.16b, v24.16b
	bic	v29.16b, v21.16b, v20.16b
	eor	v20.16b, v20.16b, v25.16b
	eor	v21.16b, v21.16b, v26.16b
	eor	v22.16b, v22.16b, v27.16b
	eor	v23.16b, v23.16b, v28.16b
	eor	v24.16b, v24.16b, v29.16b
	# Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	v30.d[0], x0
	mov	v30.d[1], x0
	eor	x2, x2, x0
	eor	v0.16b, v0.16b, v30.16b
	bne	L_SHA3_shake256_blocksx3_seed_neon_begin
	ldr	x0, [x29, #40]
	st4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	st1	{v24.d}[0], [x0]
	add	x0, x0, #8
	st4	{v0.d, v1.d, v2.d, v3.d}[1], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[1], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[1], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[1], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[1], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[1], [x0], #32
	st1	{v24.d}[1], [x0]
	add	x0, x0, #8
	stp	x2, x3, [x0]
	stp	x4, x5, [x0, #16]
	stp	x6, x7, [x0, #32]
	stp	x8, x9, [x0, #48]
	stp	x10, x11, [x0, #64]
	stp	x12, x13, [x0, #80]
	stp	x14, x15, [x0, #96]
	stp	x16, x17, [x0, #112]
	stp	x19, x20, [x0, #128]
	stp	x21, x22, [x0, #144]
	stp	x23, x24, [x0, #160]
	stp	x25, x26, [x0, #176]
	str	x27, [x0, #192]
	ldp	x17, x19, [x29, #72]
	ldp	x20, x21, [x29, #88]
	ldp	x22, x23, [x29, #104]
	ldp	x24, x25, [x29, #120]
	ldp	x26, x27, [x29, #136]
	ldr	x28, [x29, #152]
	ldp	d8, d9, [x29, #160]
	ldp	d10, d11, [x29, #176]
	ldp	d12, d13, [x29, #192]
	ldp	d14, d15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
#ifndef __APPLE__
	.size	sha3_256_blocksx3_seed_neon,.-sha3_256_blocksx3_seed_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	sha3_256_blocksx3_seed_64_neon
WC_ASM_ATT_HIDDEN(sha3_256_blocksx3_seed_64_neon)
.type	sha3_256_blocksx3_seed_64_neon,@function
.align	2
sha3_256_blocksx3_seed_64_neon:
#else
.section	__TEXT,__text
.globl	_sha3_256_blocksx3_seed_64_neon
WC_ASM_ATT_HIDDEN(_sha3_256_blocksx3_seed_64_neon)
.p2align	2
_sha3_256_blocksx3_seed_64_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	d8, d9, [x29, #160]
	stp	d10, d11, [x29, #176]
	stp	d12, d13, [x29, #192]
	stp	d14, d15, [x29, #208]
#ifndef __APPLE__
	adrp x28, L_sha3_aarch64_r
	add  x28, x28, :lo12:L_sha3_aarch64_r
#else
	adrp x28, L_sha3_aarch64_r@PAGE
	add  x28, x28, L_sha3_aarch64_r@PAGEOFF
#endif /* __APPLE__ */
	str	x0, [x29, #40]
	add	x0, x0, #0x40
	ld1	{v8.d}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{v8.d}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldp	x6, x7, [x1], #16
	ldp	x8, x9, [x1], #16
	ldr	x10, [x0, #200]
	eor	v9.16b, v9.16b, v9.16b
	eor	x11, x11, x11
	eor	v10.16b, v10.16b, v10.16b
	eor	x12, x12, x12
	eor	v11.16b, v11.16b, v11.16b
	eor	x13, x13, x13
	eor	v12.16b, v12.16b, v12.16b
	eor	x14, x14, x14
	eor	v13.16b, v13.16b, v13.16b
	eor	x15, x15, x15
	eor	v14.16b, v14.16b, v14.16b
	eor	x16, x16, x16
	eor	v15.16b, v15.16b, v15.16b
	eor	x17, x17, x17
	movz	x19, #0x8000, lsl 48
	eor	v17.16b, v17.16b, v17.16b
	eor	x20, x20, x20
	eor	v18.16b, v18.16b, v18.16b
	eor	x21, x21, x21
	eor	v19.16b, v19.16b, v19.16b
	eor	x22, x22, x22
	eor	v20.16b, v20.16b, v20.16b
	eor	x23, x23, x23
	eor	v21.16b, v21.16b, v21.16b
	eor	x24, x24, x24
	eor	v22.16b, v22.16b, v22.16b
	eor	x25, x25, x25
	eor	v23.16b, v23.16b, v23.16b
	eor	x26, x26, x26
	eor	v24.16b, v24.16b, v24.16b
	eor	x27, x27, x27
	dup	v0.2d, x2
	dup	v1.2d, x3
	dup	v2.2d, x4
	dup	v3.2d, x5
	dup	v4.2d, x6
	dup	v5.2d, x7
	dup	v6.2d, x8
	dup	v7.2d, x9
	dup	v16.2d, x19
	mov	x1, #24
	# Start of 24 rounds
L_SHA3_shake256_blocksx3_seed_64_neon_begin:
	stp	x28, x1, [x29, #48]
	# Col Mix NEON
	eor	v30.16b, v4.16b, v9.16b
	eor	x0, x6, x11
	eor	v27.16b, v1.16b, v6.16b
	eor	x30, x2, x7
	eor	v30.16b, v30.16b, v14.16b
	eor	x28, x4, x9
	eor	v27.16b, v27.16b, v11.16b
	eor	x0, x0, x16
	eor	v30.16b, v30.16b, v19.16b
	eor	x30, x30, x12
	eor	v27.16b, v27.16b, v16.16b
	eor	x28, x28, x14
	eor	v30.16b, v30.16b, v24.16b
	eor	x0, x0, x22
	eor	v27.16b, v27.16b, v21.16b
	eor	x30, x30, x17
	ushr	v25.2d, v27.2d, #63
	eor	x28, x28, x20
	sli	v25.2d, v27.2d, #1
	eor	x0, x0, x27
	eor	v25.16b, v25.16b, v30.16b
	eor	x30, x30, x23
	eor	v31.16b, v0.16b, v5.16b
	eor	x28, x28, x25
	eor	v28.16b, v2.16b, v7.16b
	str	x0, [x29, #32]
	eor	v31.16b, v31.16b, v10.16b
	str	x28, [x29, #24]
	eor	v28.16b, v28.16b, v12.16b
	eor	x1, x3, x8
	eor	v31.16b, v31.16b, v15.16b
	eor	x28, x5, x10
	eor	v28.16b, v28.16b, v17.16b
	eor	x1, x1, x13
	eor	v31.16b, v31.16b, v20.16b
	eor	x28, x28, x15
	eor	v28.16b, v28.16b, v22.16b
	eor	x1, x1, x19
	ushr	v29.2d, v30.2d, #63
	eor	x28, x28, x21
	ushr	v26.2d, v28.2d, #63
	eor	x1, x1, x24
	sli	v29.2d, v30.2d, #1
	eor	x28, x28, x26
	sli	v26.2d, v28.2d, #1
	eor	x0, x0, x1, ror 63
	eor	v28.16b, v28.16b, v29.16b
	eor	x1, x1, x28, ror 63
	eor	v29.16b, v3.16b, v8.16b
	eor	x2, x2, x0
	eor	v26.16b, v26.16b, v31.16b
	eor	x7, x7, x0
	eor	v29.16b, v29.16b, v13.16b
	eor	x12, x12, x0
	eor	v29.16b, v29.16b, v18.16b
	eor	x17, x17, x0
	eor	v29.16b, v29.16b, v23.16b
	eor	x23, x23, x0
	ushr	v30.2d, v29.2d, #63
	eor	x4, x4, x1
	sli	v30.2d, v29.2d, #1
	eor	x9, x9, x1
	eor	v27.16b, v27.16b, v30.16b
	eor	x14, x14, x1
	ushr	v30.2d, v31.2d, #63
	eor	x20, x20, x1
	sli	v30.2d, v31.2d, #1
	eor	x25, x25, x1
	eor	v29.16b, v29.16b, v30.16b
	ldr	x0, [x29, #32]
	# Swap Rotate NEON
	eor	v0.16b, v0.16b, v25.16b
	eor	v31.16b, v1.16b, v26.16b
	ldr	x1, [x29, #24]
	eor	v6.16b, v6.16b, v26.16b
	eor	x28, x28, x30, ror 63
	ushr	v30.2d, v31.2d, #63
	eor	x30, x30, x1, ror 63
	ushr	v1.2d, v6.2d, #20
	eor	x1, x1, x0, ror 63
	sli	v30.2d, v31.2d, #1
	eor	x6, x6, x28
	sli	v1.2d, v6.2d, #44
	eor	x11, x11, x28
	eor	v31.16b, v9.16b, v29.16b
	eor	x16, x16, x28
	eor	v22.16b, v22.16b, v27.16b
	eor	x22, x22, x28
	ushr	v6.2d, v31.2d, #44
	eor	x27, x27, x28
	ushr	v9.2d, v22.2d, #3
	eor	x3, x3, x30
	sli	v6.2d, v31.2d, #20
	eor	x8, x8, x30
	sli	v9.2d, v22.2d, #61
	eor	x13, x13, x30
	eor	v31.16b, v14.16b, v29.16b
	eor	x19, x19, x30
	eor	v20.16b, v20.16b, v25.16b
	eor	x24, x24, x30
	ushr	v22.2d, v31.2d, #25
	eor	x5, x5, x1
	ushr	v14.2d, v20.2d, #46
	eor	x10, x10, x1
	sli	v22.2d, v31.2d, #39
	eor	x15, x15, x1
	sli	v14.2d, v20.2d, #18
	eor	x21, x21, x1
	eor	v31.16b, v2.16b, v27.16b
	eor	x26, x26, x1
	# Swap Rotate Base
	eor	v12.16b, v12.16b, v27.16b
	ror	x0, x3, #63
	ushr	v20.2d, v31.2d, #2
	ror	x3, x8, #20
	ushr	v2.2d, v12.2d, #21
	ror	x8, x11, #44
	sli	v20.2d, v31.2d, #62
	ror	x11, x25, #3
	sli	v2.2d, v12.2d, #43
	ror	x25, x16, #25
	eor	v31.16b, v13.16b, v28.16b
	ror	x16, x23, #46
	eor	v19.16b, v19.16b, v29.16b
	ror	x23, x4, #2
	ushr	v12.2d, v31.2d, #39
	ror	x4, x14, #21
	ushr	v13.2d, v19.2d, #56
	ror	x14, x15, #39
	sli	v12.2d, v31.2d, #25
	ror	x15, x22, #56
	sli	v13.2d, v19.2d, #8
	ror	x22, x26, #8
	eor	v31.16b, v23.16b, v28.16b
	ror	x26, x17, #23
	eor	v15.16b, v15.16b, v25.16b
	ror	x17, x6, #37
	ushr	v19.2d, v31.2d, #8
	ror	x6, x27, #50
	ushr	v23.2d, v15.2d, #23
	ror	x27, x24, #62
	sli	v19.2d, v31.2d, #56
	ror	x24, x10, #9
	sli	v23.2d, v15.2d, #41
	ror	x10, x19, #19
	eor	v31.16b, v4.16b, v29.16b
	ror	x19, x7, #28
	eor	v24.16b, v24.16b, v29.16b
	ror	x7, x5, #36
	ushr	v15.2d, v31.2d, #37
	ror	x5, x21, #43
	ushr	v4.2d, v24.2d, #50
	ror	x21, x20, #49
	sli	v15.2d, v31.2d, #27
	ror	x20, x13, #54
	sli	v4.2d, v24.2d, #14
	ror	x13, x9, #58
	eor	v31.16b, v21.16b, v26.16b
	ror	x9, x12, #61
	# Row Mix Base
	eor	v8.16b, v8.16b, v28.16b
	bic	x12, x4, x3
	ushr	v24.2d, v31.2d, #62
	bic	x1, x5, x4
	ushr	v21.2d, v8.2d, #9
	bic	x28, x2, x6
	sli	v24.2d, v31.2d, #2
	bic	x30, x3, x2
	sli	v21.2d, v8.2d, #55
	eor	x2, x2, x12
	eor	v31.16b, v16.16b, v26.16b
	eor	x3, x3, x1
	eor	v5.16b, v5.16b, v25.16b
	bic	x12, x6, x5
	ushr	v8.2d, v31.2d, #19
	eor	x5, x5, x28
	ushr	v16.2d, v5.2d, #28
	eor	x4, x4, x12
	sli	v8.2d, v31.2d, #45
	eor	x6, x6, x30
	sli	v16.2d, v5.2d, #36
	bic	x12, x9, x8
	eor	v31.16b, v3.16b, v28.16b
	bic	x1, x10, x9
	eor	v18.16b, v18.16b, v28.16b
	bic	x28, x7, x11
	ushr	v5.2d, v31.2d, #36
	bic	x30, x8, x7
	ushr	v3.2d, v18.2d, #43
	eor	x7, x7, x12
	sli	v5.2d, v31.2d, #28
	eor	x8, x8, x1
	sli	v3.2d, v18.2d, #21
	bic	x12, x11, x10
	eor	v31.16b, v17.16b, v27.16b
	eor	x10, x10, x28
	eor	v11.16b, v11.16b, v26.16b
	eor	x9, x9, x12
	ushr	v18.2d, v31.2d, #49
	eor	x11, x11, x30
	ushr	v17.2d, v11.2d, #54
	bic	x12, x14, x13
	sli	v18.2d, v31.2d, #15
	bic	x1, x15, x14
	sli	v17.2d, v11.2d, #10
	bic	x28, x0, x16
	eor	v31.16b, v7.16b, v27.16b
	bic	x30, x13, x0
	eor	v10.16b, v10.16b, v25.16b
	eor	x12, x0, x12
	ushr	v11.2d, v31.2d, #58
	eor	x13, x13, x1
	ushr	v7.2d, v10.2d, #61
	bic	x0, x16, x15
	sli	v11.2d, v31.2d, #6
	eor	x15, x15, x28
	sli	v7.2d, v10.2d, #3
	eor	x14, x14, x0
	# Row Mix NEON
	bic	v25.16b, v2.16b, v1.16b
	eor	x16, x16, x30
	bic	v26.16b, v3.16b, v2.16b
	bic	x0, x20, x19
	bic	v27.16b, v4.16b, v3.16b
	bic	x1, x21, x20
	bic	v28.16b, v0.16b, v4.16b
	bic	x28, x17, x22
	bic	v29.16b, v1.16b, v0.16b
	bic	x30, x19, x17
	eor	v0.16b, v0.16b, v25.16b
	eor	x17, x17, x0
	eor	v1.16b, v1.16b, v26.16b
	eor	x19, x19, x1
	eor	v2.16b, v2.16b, v27.16b
	bic	x0, x22, x21
	eor	v3.16b, v3.16b, v28.16b
	eor	x21, x21, x28
	eor	v4.16b, v4.16b, v29.16b
	eor	x20, x20, x0
	bic	v25.16b, v7.16b, v6.16b
	eor	x22, x22, x30
	bic	v26.16b, v8.16b, v7.16b
	bic	x0, x25, x24
	bic	v27.16b, v9.16b, v8.16b
	bic	x1, x26, x25
	bic	v28.16b, v5.16b, v9.16b
	bic	x28, x23, x27
	bic	v29.16b, v6.16b, v5.16b
	bic	x30, x24, x23
	eor	v5.16b, v5.16b, v25.16b
	eor	x23, x23, x0
	eor	v6.16b, v6.16b, v26.16b
	eor	x24, x24, x1
	eor	v7.16b, v7.16b, v27.16b
	bic	x0, x27, x26
	eor	v8.16b, v8.16b, v28.16b
	eor	x26, x26, x28
	eor	v9.16b, v9.16b, v29.16b
	eor	x25, x25, x0
	bic	v25.16b, v12.16b, v11.16b
	eor	x27, x27, x30
	bic	v26.16b, v13.16b, v12.16b
	bic	v27.16b, v14.16b, v13.16b
	bic	v28.16b, v30.16b, v14.16b
	bic	v29.16b, v11.16b, v30.16b
	eor	v10.16b, v30.16b, v25.16b
	eor	v11.16b, v11.16b, v26.16b
	eor	v12.16b, v12.16b, v27.16b
	eor	v13.16b, v13.16b, v28.16b
	eor	v14.16b, v14.16b, v29.16b
	bic	v25.16b, v17.16b, v16.16b
	bic	v26.16b, v18.16b, v17.16b
	bic	v27.16b, v19.16b, v18.16b
	bic	v28.16b, v15.16b, v19.16b
	bic	v29.16b, v16.16b, v15.16b
	eor	v15.16b, v15.16b, v25.16b
	eor	v16.16b, v16.16b, v26.16b
	eor	v17.16b, v17.16b, v27.16b
	eor	v18.16b, v18.16b, v28.16b
	eor	v19.16b, v19.16b, v29.16b
	bic	v25.16b, v22.16b, v21.16b
	bic	v26.16b, v23.16b, v22.16b
	bic	v27.16b, v24.16b, v23.16b
	bic	v28.16b, v20.16b, v24.16b
	bic	v29.16b, v21.16b, v20.16b
	eor	v20.16b, v20.16b, v25.16b
	eor	v21.16b, v21.16b, v26.16b
	eor	v22.16b, v22.16b, v27.16b
	eor	v23.16b, v23.16b, v28.16b
	eor	v24.16b, v24.16b, v29.16b
	# Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	v30.d[0], x0
	mov	v30.d[1], x0
	eor	x2, x2, x0
	eor	v0.16b, v0.16b, v30.16b
	bne	L_SHA3_shake256_blocksx3_seed_64_neon_begin
	ldr	x0, [x29, #40]
	st4	{v0.d, v1.d, v2.d, v3.d}[0], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[0], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[0], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[0], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[0], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[0], [x0], #32
	st1	{v24.d}[0], [x0]
	add	x0, x0, #8
	st4	{v0.d, v1.d, v2.d, v3.d}[1], [x0], #32
	st4	{v4.d, v5.d, v6.d, v7.d}[1], [x0], #32
	st4	{v8.d, v9.d, v10.d, v11.d}[1], [x0], #32
	st4	{v12.d, v13.d, v14.d, v15.d}[1], [x0], #32
	st4	{v16.d, v17.d, v18.d, v19.d}[1], [x0], #32
	st4	{v20.d, v21.d, v22.d, v23.d}[1], [x0], #32
	st1	{v24.d}[1], [x0]
	add	x0, x0, #8
	stp	x2, x3, [x0]
	stp	x4, x5, [x0, #16]
	stp	x6, x7, [x0, #32]
	stp	x8, x9, [x0, #48]
	stp	x10, x11, [x0, #64]
	stp	x12, x13, [x0, #80]
	stp	x14, x15, [x0, #96]
	stp	x16, x17, [x0, #112]
	stp	x19, x20, [x0, #128]
	stp	x21, x22, [x0, #144]
	stp	x23, x24, [x0, #160]
	stp	x25, x26, [x0, #176]
	str	x27, [x0, #192]
	ldp	x17, x19, [x29, #72]
	ldp	x20, x21, [x29, #88]
	ldp	x22, x23, [x29, #104]
	ldp	x24, x25, [x29, #120]
	ldp	x26, x27, [x29, #136]
	ldr	x28, [x29, #152]
	ldp	d8, d9, [x29, #160]
	ldp	d10, d11, [x29, #176]
	ldp	d12, d13, [x29, #192]
	ldp	d14, d15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
#ifndef __APPLE__
	.size	sha3_256_blocksx3_seed_64_neon,.-sha3_256_blocksx3_seed_64_neon
#endif /* __APPLE__ */
#endif /* defined(WOLFSSL_HAVE_MLKEM) || defined(WOLFSSL_HAVE_MLDSA) */
#endif /* WOLFSSL_SHA3 */
#endif /* __aarch64__ */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
