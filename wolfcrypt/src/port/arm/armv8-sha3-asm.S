/* armv8-sha3-asm
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>

/* Generated using (from wolfssl):
 *   cd ../scripts
 *   ruby ./sha3/sha3.rb arm64 ../wolfssl/wolfcrypt/src/port/arm/armv8-sha3-asm.S
 */
#ifdef WOLFSSL_ARMASM
#ifdef __aarch64__
#ifndef WOLFSSL_ARMASM_INLINE
#ifdef WOLFSSL_SHA3
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
#ifndef __APPLE__
	.text
	.type	L_SHA3_transform_crypto_r, %object
	.section	.rodata
	.size	L_SHA3_transform_crypto_r, 192
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_SHA3_transform_crypto_r:
	.xword	0x0000000000000001
	.xword	0x0000000000008082
	.xword	0x800000000000808a
	.xword	0x8000000080008000
	.xword	0x000000000000808b
	.xword	0x0000000080000001
	.xword	0x8000000080008081
	.xword	0x8000000000008009
	.xword	0x000000000000008a
	.xword	0x0000000000000088
	.xword	0x0000000080008009
	.xword	0x000000008000000a
	.xword	0x000000008000808b
	.xword	0x800000000000008b
	.xword	0x8000000000008089
	.xword	0x8000000000008003
	.xword	0x8000000000008002
	.xword	0x8000000000000080
	.xword	0x000000000000800a
	.xword	0x800000008000000a
	.xword	0x8000000080008081
	.xword	0x8000000000008080
	.xword	0x0000000080000001
	.xword	0x8000000080008008
#ifndef __APPLE__
.text
.globl	BlockSha3_crypto
.type	BlockSha3_crypto,@function
.align	2
BlockSha3_crypto:
#else
.section	__TEXT,__text
.globl	_BlockSha3_crypto
.p2align	2
_BlockSha3_crypto:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifdef __APPLE__
.arch_extension sha3
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x1, L_SHA3_transform_crypto_r
	add  x1, x1, :lo12:L_SHA3_transform_crypto_r
#else
	adrp x1, L_SHA3_transform_crypto_r@PAGE
	add  x1, x1, :lo12:L_SHA3_transform_crypto_r@PAGEOFF
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
	.type	L_SHA3_transform_base_r, %object
	.section	.rodata
	.size	L_SHA3_transform_base_r, 192
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_SHA3_transform_base_r:
	.xword	0x0000000000000001
	.xword	0x0000000000008082
	.xword	0x800000000000808a
	.xword	0x8000000080008000
	.xword	0x000000000000808b
	.xword	0x0000000080000001
	.xword	0x8000000080008081
	.xword	0x8000000000008009
	.xword	0x000000000000008a
	.xword	0x0000000000000088
	.xword	0x0000000080008009
	.xword	0x000000008000000a
	.xword	0x000000008000808b
	.xword	0x800000000000008b
	.xword	0x8000000000008089
	.xword	0x8000000000008003
	.xword	0x8000000000008002
	.xword	0x8000000000000080
	.xword	0x000000000000800a
	.xword	0x800000008000000a
	.xword	0x8000000080008081
	.xword	0x8000000000008080
	.xword	0x0000000080000001
	.xword	0x8000000080008008
#ifndef __APPLE__
.text
.globl	BlockSha3_base
.type	BlockSha3_base,@function
.align	2
BlockSha3_base:
#else
.section	__TEXT,__text
.globl	_BlockSha3_base
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
	add  x27, x27, :lo12:L_SHA3_transform_base_r@PAGEOFF
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
#endif /* WOLFSSL_SHA3 */
#endif /* __aarch64__ */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
