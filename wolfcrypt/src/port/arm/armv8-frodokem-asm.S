/* armv8-frodokem-asm
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
 *   ruby ./frodokem/frodokem.rb arm64 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-frodokem-asm.S
 */
#ifdef WOLFSSL_ARMASM
#ifdef __aarch64__
#ifndef WOLFSSL_ARMASM_INLINE
#ifdef WOLFSSL_HAVE_FRODOKEM
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
#ifndef __APPLE__
.text
.globl	frodokem_sha3_x2_neon
.type	frodokem_sha3_x2_neon,@function
.align	2
frodokem_sha3_x2_neon:
#else
.section	__TEXT,__text
.globl	_frodokem_sha3_x2_neon
.p2align	2
_frodokem_sha3_x2_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x1, L_sha3_aarch64_r
	add  x1, x1, :lo12:L_sha3_aarch64_r
#else
	adrp x1, L_sha3_aarch64_r@PAGE
	add  x1, x1, L_sha3_aarch64_r@PAGEOFF
#endif /* __APPLE__ */
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
	sub	x0, x0, #0x190
	mov	x2, #24
L_frodokem_sha3_x2_neon_begin:
	# Col Mix NEON
	eor	v30.16b, v4.16b, v9.16b
	eor	v27.16b, v1.16b, v6.16b
	eor	v30.16b, v30.16b, v14.16b
	eor	v27.16b, v27.16b, v11.16b
	eor	v30.16b, v30.16b, v19.16b
	eor	v27.16b, v27.16b, v16.16b
	eor	v30.16b, v30.16b, v24.16b
	eor	v27.16b, v27.16b, v21.16b
	ushr	v25.2d, v27.2d, #63
	sli	v25.2d, v27.2d, #1
	eor	v25.16b, v25.16b, v30.16b
	eor	v31.16b, v0.16b, v5.16b
	eor	v28.16b, v2.16b, v7.16b
	eor	v31.16b, v31.16b, v10.16b
	eor	v28.16b, v28.16b, v12.16b
	eor	v31.16b, v31.16b, v15.16b
	eor	v28.16b, v28.16b, v17.16b
	eor	v31.16b, v31.16b, v20.16b
	eor	v28.16b, v28.16b, v22.16b
	ushr	v29.2d, v30.2d, #63
	ushr	v26.2d, v28.2d, #63
	sli	v29.2d, v30.2d, #1
	sli	v26.2d, v28.2d, #1
	eor	v28.16b, v28.16b, v29.16b
	eor	v29.16b, v3.16b, v8.16b
	eor	v26.16b, v26.16b, v31.16b
	eor	v29.16b, v29.16b, v13.16b
	eor	v29.16b, v29.16b, v18.16b
	eor	v29.16b, v29.16b, v23.16b
	ushr	v30.2d, v29.2d, #63
	sli	v30.2d, v29.2d, #1
	eor	v27.16b, v27.16b, v30.16b
	ushr	v30.2d, v31.2d, #63
	sli	v30.2d, v31.2d, #1
	eor	v29.16b, v29.16b, v30.16b
	# Swap Rotate NEON
	eor	v0.16b, v0.16b, v25.16b
	eor	v31.16b, v1.16b, v26.16b
	eor	v6.16b, v6.16b, v26.16b
	ushr	v30.2d, v31.2d, #63
	ushr	v1.2d, v6.2d, #20
	sli	v30.2d, v31.2d, #1
	sli	v1.2d, v6.2d, #44
	eor	v31.16b, v9.16b, v29.16b
	eor	v22.16b, v22.16b, v27.16b
	ushr	v6.2d, v31.2d, #44
	ushr	v9.2d, v22.2d, #3
	sli	v6.2d, v31.2d, #20
	sli	v9.2d, v22.2d, #61
	eor	v31.16b, v14.16b, v29.16b
	eor	v20.16b, v20.16b, v25.16b
	ushr	v22.2d, v31.2d, #25
	ushr	v14.2d, v20.2d, #46
	sli	v22.2d, v31.2d, #39
	sli	v14.2d, v20.2d, #18
	eor	v31.16b, v2.16b, v27.16b
	eor	v12.16b, v12.16b, v27.16b
	ushr	v20.2d, v31.2d, #2
	ushr	v2.2d, v12.2d, #21
	sli	v20.2d, v31.2d, #62
	sli	v2.2d, v12.2d, #43
	eor	v31.16b, v13.16b, v28.16b
	eor	v19.16b, v19.16b, v29.16b
	ushr	v12.2d, v31.2d, #39
	ushr	v13.2d, v19.2d, #56
	sli	v12.2d, v31.2d, #25
	sli	v13.2d, v19.2d, #8
	eor	v31.16b, v23.16b, v28.16b
	eor	v15.16b, v15.16b, v25.16b
	ushr	v19.2d, v31.2d, #8
	ushr	v23.2d, v15.2d, #23
	sli	v19.2d, v31.2d, #56
	sli	v23.2d, v15.2d, #41
	eor	v31.16b, v4.16b, v29.16b
	eor	v24.16b, v24.16b, v29.16b
	ushr	v15.2d, v31.2d, #37
	ushr	v4.2d, v24.2d, #50
	sli	v15.2d, v31.2d, #27
	sli	v4.2d, v24.2d, #14
	eor	v31.16b, v21.16b, v26.16b
	eor	v8.16b, v8.16b, v28.16b
	ushr	v24.2d, v31.2d, #62
	ushr	v21.2d, v8.2d, #9
	sli	v24.2d, v31.2d, #2
	sli	v21.2d, v8.2d, #55
	eor	v31.16b, v16.16b, v26.16b
	eor	v5.16b, v5.16b, v25.16b
	ushr	v8.2d, v31.2d, #19
	ushr	v16.2d, v5.2d, #28
	sli	v8.2d, v31.2d, #45
	sli	v16.2d, v5.2d, #36
	eor	v31.16b, v3.16b, v28.16b
	eor	v18.16b, v18.16b, v28.16b
	ushr	v5.2d, v31.2d, #36
	ushr	v3.2d, v18.2d, #43
	sli	v5.2d, v31.2d, #28
	sli	v3.2d, v18.2d, #21
	eor	v31.16b, v17.16b, v27.16b
	eor	v11.16b, v11.16b, v26.16b
	ushr	v18.2d, v31.2d, #49
	ushr	v17.2d, v11.2d, #54
	sli	v18.2d, v31.2d, #15
	sli	v17.2d, v11.2d, #10
	eor	v31.16b, v7.16b, v27.16b
	eor	v10.16b, v10.16b, v25.16b
	ushr	v11.2d, v31.2d, #58
	ushr	v7.2d, v10.2d, #61
	sli	v11.2d, v31.2d, #6
	sli	v7.2d, v10.2d, #3
	# Row Mix NEON
	bic	v25.16b, v2.16b, v1.16b
	bic	v26.16b, v3.16b, v2.16b
	bic	v27.16b, v4.16b, v3.16b
	bic	v28.16b, v0.16b, v4.16b
	bic	v29.16b, v1.16b, v0.16b
	eor	v0.16b, v0.16b, v25.16b
	eor	v1.16b, v1.16b, v26.16b
	eor	v2.16b, v2.16b, v27.16b
	eor	v3.16b, v3.16b, v28.16b
	eor	v4.16b, v4.16b, v29.16b
	bic	v25.16b, v7.16b, v6.16b
	bic	v26.16b, v8.16b, v7.16b
	bic	v27.16b, v9.16b, v8.16b
	bic	v28.16b, v5.16b, v9.16b
	bic	v29.16b, v6.16b, v5.16b
	eor	v5.16b, v5.16b, v25.16b
	eor	v6.16b, v6.16b, v26.16b
	eor	v7.16b, v7.16b, v27.16b
	eor	v8.16b, v8.16b, v28.16b
	eor	v9.16b, v9.16b, v29.16b
	bic	v25.16b, v12.16b, v11.16b
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
	ldr	x3, [x1], #8
	subs	x2, x2, #1
	mov	v30.d[0], x3
	mov	v30.d[1], x3
	eor	v0.16b, v0.16b, v30.16b
	bne	L_frodokem_sha3_x2_neon_begin
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
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	frodokem_sha3_x2_neon,.-frodokem_sha3_x2_neon
#endif /* __APPLE__ */
#ifdef WOLFSSL_ARMASM_CRYPTO_SHA3
	.arch_extension	sha3
#ifndef __APPLE__
.text
.globl	frodokem_sha3_x2_crypto
.type	frodokem_sha3_x2_crypto,@function
.align	2
frodokem_sha3_x2_crypto:
#else
.section	__TEXT,__text
.globl	_frodokem_sha3_x2_crypto
.p2align	2
_frodokem_sha3_x2_crypto:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
#ifndef __APPLE__
	adrp x1, L_sha3_aarch64_r
	add  x1, x1, :lo12:L_sha3_aarch64_r
#else
	adrp x1, L_sha3_aarch64_r@PAGE
	add  x1, x1, L_sha3_aarch64_r@PAGEOFF
#endif /* __APPLE__ */
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
	sub	x0, x0, #0x190
	mov	x2, #24
L_frodokem_sha3_x2_crypto_begin:
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
	ldr	x3, [x1], #8
	subs	x2, x2, #1
	mov	v30.d[0], x3
	mov	v30.d[1], x3
	eor	v0.16b, v0.16b, v30.16b
	bne	L_frodokem_sha3_x2_crypto_begin
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
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	frodokem_sha3_x2_crypto,.-frodokem_sha3_x2_crypto
#endif /* __APPLE__ */
#endif /* WOLFSSL_ARMASM_CRYPTO_SHA3 */
#ifndef __APPLE__
.text
.globl	frodokem_add_neon
.type	frodokem_add_neon,@function
.align	2
frodokem_add_neon:
#else
.section	__TEXT,__text
.globl	_frodokem_add_neon
.p2align	2
_frodokem_add_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
	dup	v16.8h, w2
	ld1	{v0.8h, v1.8h, v2.8h, v3.8h}, [x0], #0x40
	ld1	{v4.8h, v5.8h, v6.8h, v7.8h}, [x0], #0x40
	sub	x0, x0, #0x80
	ld1	{v8.8h, v9.8h, v10.8h, v11.8h}, [x1], #0x40
	ld1	{v12.8h, v13.8h, v14.8h, v15.8h}, [x1], #0x40
	add	v0.8h, v0.8h, v8.8h
	and	v0.16b, v0.16b, v16.16b
	add	v1.8h, v1.8h, v9.8h
	and	v1.16b, v1.16b, v16.16b
	add	v2.8h, v2.8h, v10.8h
	and	v2.16b, v2.16b, v16.16b
	add	v3.8h, v3.8h, v11.8h
	and	v3.16b, v3.16b, v16.16b
	add	v4.8h, v4.8h, v12.8h
	and	v4.16b, v4.16b, v16.16b
	add	v5.8h, v5.8h, v13.8h
	and	v5.16b, v5.16b, v16.16b
	add	v6.8h, v6.8h, v14.8h
	and	v6.16b, v6.16b, v16.16b
	add	v7.8h, v7.8h, v15.8h
	and	v7.16b, v7.16b, v16.16b
	st1	{v0.8h, v1.8h, v2.8h, v3.8h}, [x0], #0x40
	st1	{v4.8h, v5.8h, v6.8h, v7.8h}, [x0], #0x40
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	frodokem_add_neon,.-frodokem_add_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	frodokem_sample_neon
.type	frodokem_sample_neon,@function
.align	2
frodokem_sample_neon:
#else
.section	__TEXT,__text
.globl	_frodokem_sample_neon
.p2align	2
_frodokem_sample_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	cmp	w1, #16
	blt	L_frodokem_sample_neon_rem
L_frodokem_sample_neon_blk16:
	ld1	{v0.8h}, [x0], #16
	ld1	{v1.8h}, [x0], #16
	sub	x0, x0, #32
	ushr	v2.8h, v0.8h, #1
	movi	v4.8h, #1
	and	v4.16b, v4.16b, v0.16b
	movi	v6.8h, #0
	ushr	v3.8h, v1.8h, #1
	movi	v5.8h, #1
	and	v5.16b, v5.16b, v1.16b
	movi	v7.8h, #0
	mov	x4, x2
	mov	w5, w3
L_frodokem_sample_neon_cdf16:
	ld1r	{v12.8h}, [x4], #2
	sub	v10.8h, v12.8h, v2.8h
	ushr	v10.8h, v10.8h, #15
	add	v6.8h, v6.8h, v10.8h
	sub	v11.8h, v12.8h, v3.8h
	ushr	v11.8h, v11.8h, #15
	add	v7.8h, v7.8h, v11.8h
	subs	w5, w5, #1
	bne	L_frodokem_sample_neon_cdf16
	neg	v8.8h, v4.8h
	eor	v6.16b, v6.16b, v8.16b
	add	v6.8h, v6.8h, v4.8h
	st1	{v6.8h}, [x0], #16
	neg	v9.8h, v5.8h
	eor	v7.16b, v7.16b, v9.16b
	add	v7.8h, v7.8h, v5.8h
	st1	{v7.8h}, [x0], #16
	subs	w1, w1, #16
	cmp	w1, #16
	bge	L_frodokem_sample_neon_blk16
L_frodokem_sample_neon_rem:
	cmp	w1, #0
	beq	L_frodokem_sample_neon_done
L_frodokem_sample_neon_blk:
	ld1	{v0.8h}, [x0]
	ushr	v2.8h, v0.8h, #1
	movi	v4.8h, #1
	and	v4.16b, v4.16b, v0.16b
	movi	v6.8h, #0
	mov	x4, x2
	mov	w5, w3
L_frodokem_sample_neon_cdf:
	ld1r	{v12.8h}, [x4], #2
	sub	v12.8h, v12.8h, v2.8h
	ushr	v12.8h, v12.8h, #15
	add	v6.8h, v6.8h, v12.8h
	subs	w5, w5, #1
	bne	L_frodokem_sample_neon_cdf
	neg	v8.8h, v4.8h
	eor	v6.16b, v6.16b, v8.16b
	add	v6.8h, v6.8h, v4.8h
	st1	{v6.8h}, [x0], #16
	subs	w1, w1, #8
	bne	L_frodokem_sample_neon_blk
L_frodokem_sample_neon_done:
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	x29, x30, [sp], #0x40
	ret
#ifndef __APPLE__
	.size	frodokem_sample_neon,.-frodokem_sample_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	frodokem_sa_accum_neon
.type	frodokem_sa_accum_neon,@function
.align	2
frodokem_sa_accum_neon:
#else
.section	__TEXT,__text
.globl	_frodokem_sa_accum_neon
.p2align	2
_frodokem_sa_accum_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	str	x17, [x29, #24]
	stp	d8, d9, [x29, #32]
	stp	d10, d11, [x29, #48]
	stp	d12, d13, [x29, #64]
	sxtw	x5, w4
	lsl	x5, x5, #1
	lsl	x6, x5, #2
	sxtw	x7, w3
	lsl	x7, x7, #1
	add	x7, x1, x7
	mov	x8, x0
	mov	x12, #2
L_frodokem_sa_accum_neon_t:
	ldr	w13, [x7]
	dup	v0.8h, w13
	lsr	w13, w13, #16
	dup	v4.8h, w13
	add	x7, x7, x5
	ldr	w13, [x7]
	dup	v1.8h, w13
	lsr	w13, w13, #16
	dup	v5.8h, w13
	add	x7, x7, x5
	ldr	w13, [x7]
	dup	v2.8h, w13
	lsr	w13, w13, #16
	dup	v6.8h, w13
	add	x7, x7, x5
	ldr	w13, [x7]
	dup	v3.8h, w13
	lsr	w13, w13, #16
	dup	v7.8h, w13
	add	x7, x7, x5
	mov	x14, x8
	add	x15, x14, x5
	add	x16, x15, x5
	add	x17, x16, x5
	mov	x9, x2
	add	x10, x2, x5
	lsr	x11, x5, #4
L_frodokem_sa_accum_neon_k:
	ld1	{v8.8h}, [x9], #16
	ld1	{v9.8h}, [x10], #16
	ld1	{v10.8h}, [x14]
	mla	v10.8h, v8.8h, v0.8h
	mla	v10.8h, v9.8h, v4.8h
	st1	{v10.8h}, [x14], #16
	ld1	{v11.8h}, [x15]
	mla	v11.8h, v8.8h, v1.8h
	mla	v11.8h, v9.8h, v5.8h
	st1	{v11.8h}, [x15], #16
	ld1	{v12.8h}, [x16]
	mla	v12.8h, v8.8h, v2.8h
	mla	v12.8h, v9.8h, v6.8h
	st1	{v12.8h}, [x16], #16
	ld1	{v13.8h}, [x17]
	mla	v13.8h, v8.8h, v3.8h
	mla	v13.8h, v9.8h, v7.8h
	st1	{v13.8h}, [x17], #16
	subs	x11, x11, #1
	bne	L_frodokem_sa_accum_neon_k
	add	x8, x8, x6
	subs	x12, x12, #1
	bne	L_frodokem_sa_accum_neon_t
	ldr	x17, [x29, #24]
	ldp	d8, d9, [x29, #32]
	ldp	d10, d11, [x29, #48]
	ldp	d12, d13, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	frodokem_sa_accum_neon,.-frodokem_sa_accum_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	frodokem_sa_accum_x4_neon
.type	frodokem_sa_accum_x4_neon,@function
.align	2
frodokem_sa_accum_x4_neon:
#else
.section	__TEXT,__text
.globl	_frodokem_sa_accum_x4_neon
.p2align	2
_frodokem_sa_accum_x4_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-112]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #24]
	str	x20, [x29, #40]
	stp	d8, d9, [x29, #48]
	stp	d10, d11, [x29, #64]
	stp	d12, d13, [x29, #80]
	stp	d14, d15, [x29, #96]
	sxtw	x5, w4
	lsl	x5, x5, #1
	lsl	x6, x5, #2
	sxtw	x7, w3
	lsl	x7, x7, #1
	add	x7, x1, x7
	mov	x8, x0
	mov	x14, #2
L_frodokem_sa_accum_x4_neon_t:
	ldr	x15, [x7]
	dup	v0.8h, w15
	lsr	x15, x15, #16
	dup	v1.8h, w15
	lsr	x15, x15, #16
	dup	v2.8h, w15
	lsr	x15, x15, #16
	dup	v3.8h, w15
	add	x7, x7, x5
	ldr	x15, [x7]
	dup	v4.8h, w15
	lsr	x15, x15, #16
	dup	v5.8h, w15
	lsr	x15, x15, #16
	dup	v6.8h, w15
	lsr	x15, x15, #16
	dup	v7.8h, w15
	add	x7, x7, x5
	ldr	x15, [x7]
	dup	v8.8h, w15
	lsr	x15, x15, #16
	dup	v9.8h, w15
	lsr	x15, x15, #16
	dup	v10.8h, w15
	lsr	x15, x15, #16
	dup	v11.8h, w15
	add	x7, x7, x5
	ldr	x15, [x7]
	dup	v12.8h, w15
	lsr	x15, x15, #16
	dup	v13.8h, w15
	lsr	x15, x15, #16
	dup	v14.8h, w15
	lsr	x15, x15, #16
	dup	v15.8h, w15
	add	x7, x7, x5
	mov	x16, x8
	add	x17, x16, x5
	add	x19, x17, x5
	add	x20, x19, x5
	mov	x9, x2
	add	x10, x9, x5
	add	x11, x10, x5
	add	x12, x11, x5
	lsr	x13, x5, #4
L_frodokem_sa_accum_x4_neon_k:
	ld1	{v16.8h}, [x9], #16
	ld1	{v17.8h}, [x10], #16
	ld1	{v18.8h}, [x11], #16
	ld1	{v19.8h}, [x12], #16
	ld1	{v20.8h}, [x16]
	mla	v20.8h, v16.8h, v0.8h
	mla	v20.8h, v17.8h, v1.8h
	mla	v20.8h, v18.8h, v2.8h
	mla	v20.8h, v19.8h, v3.8h
	st1	{v20.8h}, [x16], #16
	ld1	{v21.8h}, [x17]
	mla	v21.8h, v16.8h, v4.8h
	mla	v21.8h, v17.8h, v5.8h
	mla	v21.8h, v18.8h, v6.8h
	mla	v21.8h, v19.8h, v7.8h
	st1	{v21.8h}, [x17], #16
	ld1	{v22.8h}, [x19]
	mla	v22.8h, v16.8h, v8.8h
	mla	v22.8h, v17.8h, v9.8h
	mla	v22.8h, v18.8h, v10.8h
	mla	v22.8h, v19.8h, v11.8h
	st1	{v22.8h}, [x19], #16
	ld1	{v23.8h}, [x20]
	mla	v23.8h, v16.8h, v12.8h
	mla	v23.8h, v17.8h, v13.8h
	mla	v23.8h, v18.8h, v14.8h
	mla	v23.8h, v19.8h, v15.8h
	st1	{v23.8h}, [x20], #16
	subs	x13, x13, #1
	bne	L_frodokem_sa_accum_x4_neon_k
	add	x8, x8, x6
	subs	x14, x14, #1
	bne	L_frodokem_sa_accum_x4_neon_t
	ldp	x17, x19, [x29, #24]
	ldr	x20, [x29, #40]
	ldp	d8, d9, [x29, #48]
	ldp	d10, d11, [x29, #64]
	ldp	d12, d13, [x29, #80]
	ldp	d14, d15, [x29, #96]
	ldp	x29, x30, [sp], #0x70
	ret
#ifndef __APPLE__
	.size	frodokem_sa_accum_x4_neon,.-frodokem_sa_accum_x4_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	frodokem_as_accum_neon
.type	frodokem_as_accum_neon,@function
.align	2
frodokem_as_accum_neon:
#else
.section	__TEXT,__text
.globl	_frodokem_as_accum_neon
.p2align	2
_frodokem_as_accum_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-96]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #24]
	str	x20, [x29, #40]
	stp	d8, d9, [x29, #48]
	stp	d10, d11, [x29, #64]
	stp	d12, d13, [x29, #80]
	sxtw	x5, w4
	lsl	x5, x5, #1
	lsl	x6, x5, #2
	sxtw	x15, w3
	lsl	x15, x15, #4
	add	x7, x0, x15
	add	x8, x7, #16
	mov	x9, x2
	add	x10, x2, x5
	mov	x13, x1
	mov	x16, x13
	add	x17, x16, x5
	add	x19, x17, x5
	add	x20, x19, x5
	mov	x11, x9
	mov	x12, x10
	movi	v0.8h, #0
	movi	v1.8h, #0
	movi	v2.8h, #0
	movi	v3.8h, #0
	movi	v4.8h, #0
	movi	v5.8h, #0
	movi	v6.8h, #0
	movi	v7.8h, #0
	lsr	x14, x5, #4
L_frodokem_as_accum_neon_k0:
	ld1	{v8.8h}, [x11], #16
	ld1	{v9.8h}, [x12], #16
	ld1	{v10.8h}, [x16], #16
	mla	v0.8h, v8.8h, v10.8h
	mla	v4.8h, v9.8h, v10.8h
	ld1	{v10.8h}, [x17], #16
	mla	v1.8h, v8.8h, v10.8h
	mla	v5.8h, v9.8h, v10.8h
	ld1	{v10.8h}, [x19], #16
	mla	v2.8h, v8.8h, v10.8h
	mla	v6.8h, v9.8h, v10.8h
	ld1	{v10.8h}, [x20], #16
	mla	v3.8h, v8.8h, v10.8h
	mla	v7.8h, v9.8h, v10.8h
	subs	x14, x14, #1
	bne	L_frodokem_as_accum_neon_k0
	addv	h13, v0.8h
	ins	v11.h[0], v13.h[0]
	addv	h13, v4.8h
	ins	v12.h[0], v13.h[0]
	addv	h13, v1.8h
	ins	v11.h[1], v13.h[0]
	addv	h13, v5.8h
	ins	v12.h[1], v13.h[0]
	addv	h13, v2.8h
	ins	v11.h[2], v13.h[0]
	addv	h13, v6.8h
	ins	v12.h[2], v13.h[0]
	addv	h13, v3.8h
	ins	v11.h[3], v13.h[0]
	addv	h13, v7.8h
	ins	v12.h[3], v13.h[0]
	add	x13, x13, x6
	mov	x16, x13
	add	x17, x16, x5
	add	x19, x17, x5
	add	x20, x19, x5
	mov	x11, x9
	mov	x12, x10
	movi	v0.8h, #0
	movi	v1.8h, #0
	movi	v2.8h, #0
	movi	v3.8h, #0
	movi	v4.8h, #0
	movi	v5.8h, #0
	movi	v6.8h, #0
	movi	v7.8h, #0
	lsr	x14, x5, #4
L_frodokem_as_accum_neon_k1:
	ld1	{v8.8h}, [x11], #16
	ld1	{v9.8h}, [x12], #16
	ld1	{v10.8h}, [x16], #16
	mla	v0.8h, v8.8h, v10.8h
	mla	v4.8h, v9.8h, v10.8h
	ld1	{v10.8h}, [x17], #16
	mla	v1.8h, v8.8h, v10.8h
	mla	v5.8h, v9.8h, v10.8h
	ld1	{v10.8h}, [x19], #16
	mla	v2.8h, v8.8h, v10.8h
	mla	v6.8h, v9.8h, v10.8h
	ld1	{v10.8h}, [x20], #16
	mla	v3.8h, v8.8h, v10.8h
	mla	v7.8h, v9.8h, v10.8h
	subs	x14, x14, #1
	bne	L_frodokem_as_accum_neon_k1
	addv	h13, v0.8h
	ins	v11.h[4], v13.h[0]
	addv	h13, v4.8h
	ins	v12.h[4], v13.h[0]
	addv	h13, v1.8h
	ins	v11.h[5], v13.h[0]
	addv	h13, v5.8h
	ins	v12.h[5], v13.h[0]
	addv	h13, v2.8h
	ins	v11.h[6], v13.h[0]
	addv	h13, v6.8h
	ins	v12.h[6], v13.h[0]
	addv	h13, v3.8h
	ins	v11.h[7], v13.h[0]
	addv	h13, v7.8h
	ins	v12.h[7], v13.h[0]
	add	x13, x13, x6
	ld1	{v8.8h}, [x7]
	add	v11.8h, v11.8h, v8.8h
	st1	{v11.8h}, [x7], #16
	ld1	{v9.8h}, [x8]
	add	v12.8h, v12.8h, v9.8h
	st1	{v12.8h}, [x8], #16
	ldp	x17, x19, [x29, #24]
	ldr	x20, [x29, #40]
	ldp	d8, d9, [x29, #48]
	ldp	d10, d11, [x29, #64]
	ldp	d12, d13, [x29, #80]
	ldp	x29, x30, [sp], #0x60
	ret
#ifndef __APPLE__
	.size	frodokem_as_accum_neon,.-frodokem_as_accum_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	frodokem_as_accum_x4_neon
.type	frodokem_as_accum_x4_neon,@function
.align	2
frodokem_as_accum_x4_neon:
#else
.section	__TEXT,__text
.globl	_frodokem_as_accum_x4_neon
.p2align	2
_frodokem_as_accum_x4_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-160]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #24]
	stp	x20, x21, [x29, #40]
	stp	x22, x23, [x29, #56]
	stp	x24, x25, [x29, #72]
	str	x26, [x29, #88]
	stp	d8, d9, [x29, #96]
	stp	d10, d11, [x29, #112]
	stp	d12, d13, [x29, #128]
	stp	d14, d15, [x29, #144]
	sxtw	x5, w4
	lsl	x5, x5, #1
	lsl	x6, x5, #2
	sxtw	x22, w3
	lsl	x22, x22, #4
	add	x7, x0, x22
	add	x8, x7, #16
	add	x9, x8, #16
	add	x10, x9, #16
	mov	x11, x2
	add	x12, x11, x5
	add	x13, x12, x5
	add	x14, x13, x5
	mov	x20, x1
	mov	x23, x20
	add	x24, x23, x5
	add	x25, x24, x5
	add	x26, x25, x5
	mov	x15, x11
	mov	x16, x12
	mov	x17, x13
	mov	x19, x14
	movi	v0.8h, #0
	movi	v1.8h, #0
	movi	v2.8h, #0
	movi	v3.8h, #0
	movi	v4.8h, #0
	movi	v5.8h, #0
	movi	v6.8h, #0
	movi	v7.8h, #0
	movi	v8.8h, #0
	movi	v9.8h, #0
	movi	v10.8h, #0
	movi	v11.8h, #0
	movi	v12.8h, #0
	movi	v13.8h, #0
	movi	v14.8h, #0
	movi	v15.8h, #0
	lsr	x21, x5, #4
L_frodokem_as_accum_x4_neon_k0:
	ld1	{v16.8h}, [x15], #16
	ld1	{v17.8h}, [x16], #16
	ld1	{v18.8h}, [x17], #16
	ld1	{v19.8h}, [x19], #16
	ld1	{v20.8h}, [x23], #16
	mla	v0.8h, v16.8h, v20.8h
	mla	v4.8h, v17.8h, v20.8h
	mla	v8.8h, v18.8h, v20.8h
	mla	v12.8h, v19.8h, v20.8h
	ld1	{v20.8h}, [x24], #16
	mla	v1.8h, v16.8h, v20.8h
	mla	v5.8h, v17.8h, v20.8h
	mla	v9.8h, v18.8h, v20.8h
	mla	v13.8h, v19.8h, v20.8h
	ld1	{v20.8h}, [x25], #16
	mla	v2.8h, v16.8h, v20.8h
	mla	v6.8h, v17.8h, v20.8h
	mla	v10.8h, v18.8h, v20.8h
	mla	v14.8h, v19.8h, v20.8h
	ld1	{v20.8h}, [x26], #16
	mla	v3.8h, v16.8h, v20.8h
	mla	v7.8h, v17.8h, v20.8h
	mla	v11.8h, v18.8h, v20.8h
	mla	v15.8h, v19.8h, v20.8h
	subs	x21, x21, #1
	bne	L_frodokem_as_accum_x4_neon_k0
	addv	h25, v0.8h
	ins	v21.h[0], v25.h[0]
	addv	h25, v4.8h
	ins	v22.h[0], v25.h[0]
	addv	h25, v8.8h
	ins	v23.h[0], v25.h[0]
	addv	h25, v12.8h
	ins	v24.h[0], v25.h[0]
	addv	h25, v1.8h
	ins	v21.h[1], v25.h[0]
	addv	h25, v5.8h
	ins	v22.h[1], v25.h[0]
	addv	h25, v9.8h
	ins	v23.h[1], v25.h[0]
	addv	h25, v13.8h
	ins	v24.h[1], v25.h[0]
	addv	h25, v2.8h
	ins	v21.h[2], v25.h[0]
	addv	h25, v6.8h
	ins	v22.h[2], v25.h[0]
	addv	h25, v10.8h
	ins	v23.h[2], v25.h[0]
	addv	h25, v14.8h
	ins	v24.h[2], v25.h[0]
	addv	h25, v3.8h
	ins	v21.h[3], v25.h[0]
	addv	h25, v7.8h
	ins	v22.h[3], v25.h[0]
	addv	h25, v11.8h
	ins	v23.h[3], v25.h[0]
	addv	h25, v15.8h
	ins	v24.h[3], v25.h[0]
	add	x20, x20, x6
	mov	x23, x20
	add	x24, x23, x5
	add	x25, x24, x5
	add	x26, x25, x5
	mov	x15, x11
	mov	x16, x12
	mov	x17, x13
	mov	x19, x14
	movi	v0.8h, #0
	movi	v1.8h, #0
	movi	v2.8h, #0
	movi	v3.8h, #0
	movi	v4.8h, #0
	movi	v5.8h, #0
	movi	v6.8h, #0
	movi	v7.8h, #0
	movi	v8.8h, #0
	movi	v9.8h, #0
	movi	v10.8h, #0
	movi	v11.8h, #0
	movi	v12.8h, #0
	movi	v13.8h, #0
	movi	v14.8h, #0
	movi	v15.8h, #0
	lsr	x21, x5, #4
L_frodokem_as_accum_x4_neon_k1:
	ld1	{v16.8h}, [x15], #16
	ld1	{v17.8h}, [x16], #16
	ld1	{v18.8h}, [x17], #16
	ld1	{v19.8h}, [x19], #16
	ld1	{v20.8h}, [x23], #16
	mla	v0.8h, v16.8h, v20.8h
	mla	v4.8h, v17.8h, v20.8h
	mla	v8.8h, v18.8h, v20.8h
	mla	v12.8h, v19.8h, v20.8h
	ld1	{v20.8h}, [x24], #16
	mla	v1.8h, v16.8h, v20.8h
	mla	v5.8h, v17.8h, v20.8h
	mla	v9.8h, v18.8h, v20.8h
	mla	v13.8h, v19.8h, v20.8h
	ld1	{v20.8h}, [x25], #16
	mla	v2.8h, v16.8h, v20.8h
	mla	v6.8h, v17.8h, v20.8h
	mla	v10.8h, v18.8h, v20.8h
	mla	v14.8h, v19.8h, v20.8h
	ld1	{v20.8h}, [x26], #16
	mla	v3.8h, v16.8h, v20.8h
	mla	v7.8h, v17.8h, v20.8h
	mla	v11.8h, v18.8h, v20.8h
	mla	v15.8h, v19.8h, v20.8h
	subs	x21, x21, #1
	bne	L_frodokem_as_accum_x4_neon_k1
	addv	h25, v0.8h
	ins	v21.h[4], v25.h[0]
	addv	h25, v4.8h
	ins	v22.h[4], v25.h[0]
	addv	h25, v8.8h
	ins	v23.h[4], v25.h[0]
	addv	h25, v12.8h
	ins	v24.h[4], v25.h[0]
	addv	h25, v1.8h
	ins	v21.h[5], v25.h[0]
	addv	h25, v5.8h
	ins	v22.h[5], v25.h[0]
	addv	h25, v9.8h
	ins	v23.h[5], v25.h[0]
	addv	h25, v13.8h
	ins	v24.h[5], v25.h[0]
	addv	h25, v2.8h
	ins	v21.h[6], v25.h[0]
	addv	h25, v6.8h
	ins	v22.h[6], v25.h[0]
	addv	h25, v10.8h
	ins	v23.h[6], v25.h[0]
	addv	h25, v14.8h
	ins	v24.h[6], v25.h[0]
	addv	h25, v3.8h
	ins	v21.h[7], v25.h[0]
	addv	h25, v7.8h
	ins	v22.h[7], v25.h[0]
	addv	h25, v11.8h
	ins	v23.h[7], v25.h[0]
	addv	h25, v15.8h
	ins	v24.h[7], v25.h[0]
	add	x20, x20, x6
	ld1	{v16.8h}, [x7]
	add	v21.8h, v21.8h, v16.8h
	st1	{v21.8h}, [x7], #16
	ld1	{v16.8h}, [x8]
	add	v22.8h, v22.8h, v16.8h
	st1	{v22.8h}, [x8], #16
	ld1	{v16.8h}, [x9]
	add	v23.8h, v23.8h, v16.8h
	st1	{v23.8h}, [x9], #16
	ld1	{v16.8h}, [x10]
	add	v24.8h, v24.8h, v16.8h
	st1	{v24.8h}, [x10], #16
	ldp	x17, x19, [x29, #24]
	ldp	x20, x21, [x29, #40]
	ldp	x22, x23, [x29, #56]
	ldp	x24, x25, [x29, #72]
	ldr	x26, [x29, #88]
	ldp	d8, d9, [x29, #96]
	ldp	d10, d11, [x29, #112]
	ldp	d12, d13, [x29, #128]
	ldp	d14, d15, [x29, #144]
	ldp	x29, x30, [sp], #0xa0
	ret
#ifndef __APPLE__
	.size	frodokem_as_accum_x4_neon,.-frodokem_as_accum_x4_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	frodokem_mul_bs_neon
.type	frodokem_mul_bs_neon,@function
.align	2
frodokem_mul_bs_neon:
#else
.section	__TEXT,__text
.globl	_frodokem_mul_bs_neon
.p2align	2
_frodokem_mul_bs_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-160]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #16]
	stp	x20, x21, [x29, #32]
	stp	x22, x23, [x29, #48]
	stp	x24, x25, [x29, #64]
	stp	x26, x27, [x29, #80]
	stp	d8, d9, [x29, #96]
	stp	d10, d11, [x29, #112]
	stp	d12, d13, [x29, #128]
	stp	d14, d15, [x29, #144]
	sxtw	x5, w3
	lsl	x5, x5, #1
	lsl	x6, x5, #2
	dup	v26.8h, w4
	mov	x7, x0
	add	x8, x7, #16
	add	x9, x8, #16
	add	x10, x9, #16
	mov	x11, x1
	mov	x23, #2
L_frodokem_mul_bs_neon_p:
	mov	x12, x11
	add	x13, x12, x5
	add	x14, x13, x5
	add	x15, x14, x5
	mov	x21, x2
	mov	x24, x21
	add	x25, x24, x5
	add	x26, x25, x5
	add	x27, x26, x5
	mov	x16, x12
	mov	x17, x13
	mov	x19, x14
	mov	x20, x15
	movi	v0.8h, #0
	movi	v1.8h, #0
	movi	v2.8h, #0
	movi	v3.8h, #0
	movi	v4.8h, #0
	movi	v5.8h, #0
	movi	v6.8h, #0
	movi	v7.8h, #0
	movi	v8.8h, #0
	movi	v9.8h, #0
	movi	v10.8h, #0
	movi	v11.8h, #0
	movi	v12.8h, #0
	movi	v13.8h, #0
	movi	v14.8h, #0
	movi	v15.8h, #0
	lsr	x22, x5, #4
L_frodokem_mul_bs_neon_k0:
	ld1	{v16.8h}, [x16], #16
	ld1	{v17.8h}, [x17], #16
	ld1	{v18.8h}, [x19], #16
	ld1	{v19.8h}, [x20], #16
	ld1	{v20.8h}, [x24], #16
	mla	v0.8h, v16.8h, v20.8h
	mla	v4.8h, v17.8h, v20.8h
	mla	v8.8h, v18.8h, v20.8h
	mla	v12.8h, v19.8h, v20.8h
	ld1	{v20.8h}, [x25], #16
	mla	v1.8h, v16.8h, v20.8h
	mla	v5.8h, v17.8h, v20.8h
	mla	v9.8h, v18.8h, v20.8h
	mla	v13.8h, v19.8h, v20.8h
	ld1	{v20.8h}, [x26], #16
	mla	v2.8h, v16.8h, v20.8h
	mla	v6.8h, v17.8h, v20.8h
	mla	v10.8h, v18.8h, v20.8h
	mla	v14.8h, v19.8h, v20.8h
	ld1	{v20.8h}, [x27], #16
	mla	v3.8h, v16.8h, v20.8h
	mla	v7.8h, v17.8h, v20.8h
	mla	v11.8h, v18.8h, v20.8h
	mla	v15.8h, v19.8h, v20.8h
	subs	x22, x22, #1
	bne	L_frodokem_mul_bs_neon_k0
	addv	h25, v0.8h
	ins	v21.h[0], v25.h[0]
	addv	h25, v4.8h
	ins	v22.h[0], v25.h[0]
	addv	h25, v8.8h
	ins	v23.h[0], v25.h[0]
	addv	h25, v12.8h
	ins	v24.h[0], v25.h[0]
	addv	h25, v1.8h
	ins	v21.h[1], v25.h[0]
	addv	h25, v5.8h
	ins	v22.h[1], v25.h[0]
	addv	h25, v9.8h
	ins	v23.h[1], v25.h[0]
	addv	h25, v13.8h
	ins	v24.h[1], v25.h[0]
	addv	h25, v2.8h
	ins	v21.h[2], v25.h[0]
	addv	h25, v6.8h
	ins	v22.h[2], v25.h[0]
	addv	h25, v10.8h
	ins	v23.h[2], v25.h[0]
	addv	h25, v14.8h
	ins	v24.h[2], v25.h[0]
	addv	h25, v3.8h
	ins	v21.h[3], v25.h[0]
	addv	h25, v7.8h
	ins	v22.h[3], v25.h[0]
	addv	h25, v11.8h
	ins	v23.h[3], v25.h[0]
	addv	h25, v15.8h
	ins	v24.h[3], v25.h[0]
	add	x21, x21, x6
	mov	x24, x21
	add	x25, x24, x5
	add	x26, x25, x5
	add	x27, x26, x5
	mov	x16, x12
	mov	x17, x13
	mov	x19, x14
	mov	x20, x15
	movi	v0.8h, #0
	movi	v1.8h, #0
	movi	v2.8h, #0
	movi	v3.8h, #0
	movi	v4.8h, #0
	movi	v5.8h, #0
	movi	v6.8h, #0
	movi	v7.8h, #0
	movi	v8.8h, #0
	movi	v9.8h, #0
	movi	v10.8h, #0
	movi	v11.8h, #0
	movi	v12.8h, #0
	movi	v13.8h, #0
	movi	v14.8h, #0
	movi	v15.8h, #0
	lsr	x22, x5, #4
L_frodokem_mul_bs_neon_k1:
	ld1	{v16.8h}, [x16], #16
	ld1	{v17.8h}, [x17], #16
	ld1	{v18.8h}, [x19], #16
	ld1	{v19.8h}, [x20], #16
	ld1	{v20.8h}, [x24], #16
	mla	v0.8h, v16.8h, v20.8h
	mla	v4.8h, v17.8h, v20.8h
	mla	v8.8h, v18.8h, v20.8h
	mla	v12.8h, v19.8h, v20.8h
	ld1	{v20.8h}, [x25], #16
	mla	v1.8h, v16.8h, v20.8h
	mla	v5.8h, v17.8h, v20.8h
	mla	v9.8h, v18.8h, v20.8h
	mla	v13.8h, v19.8h, v20.8h
	ld1	{v20.8h}, [x26], #16
	mla	v2.8h, v16.8h, v20.8h
	mla	v6.8h, v17.8h, v20.8h
	mla	v10.8h, v18.8h, v20.8h
	mla	v14.8h, v19.8h, v20.8h
	ld1	{v20.8h}, [x27], #16
	mla	v3.8h, v16.8h, v20.8h
	mla	v7.8h, v17.8h, v20.8h
	mla	v11.8h, v18.8h, v20.8h
	mla	v15.8h, v19.8h, v20.8h
	subs	x22, x22, #1
	bne	L_frodokem_mul_bs_neon_k1
	addv	h25, v0.8h
	ins	v21.h[4], v25.h[0]
	addv	h25, v4.8h
	ins	v22.h[4], v25.h[0]
	addv	h25, v8.8h
	ins	v23.h[4], v25.h[0]
	addv	h25, v12.8h
	ins	v24.h[4], v25.h[0]
	addv	h25, v1.8h
	ins	v21.h[5], v25.h[0]
	addv	h25, v5.8h
	ins	v22.h[5], v25.h[0]
	addv	h25, v9.8h
	ins	v23.h[5], v25.h[0]
	addv	h25, v13.8h
	ins	v24.h[5], v25.h[0]
	addv	h25, v2.8h
	ins	v21.h[6], v25.h[0]
	addv	h25, v6.8h
	ins	v22.h[6], v25.h[0]
	addv	h25, v10.8h
	ins	v23.h[6], v25.h[0]
	addv	h25, v14.8h
	ins	v24.h[6], v25.h[0]
	addv	h25, v3.8h
	ins	v21.h[7], v25.h[0]
	addv	h25, v7.8h
	ins	v22.h[7], v25.h[0]
	addv	h25, v11.8h
	ins	v23.h[7], v25.h[0]
	addv	h25, v15.8h
	ins	v24.h[7], v25.h[0]
	add	x21, x21, x6
	and	v21.16b, v21.16b, v26.16b
	st1	{v21.8h}, [x7]
	and	v22.16b, v22.16b, v26.16b
	st1	{v22.8h}, [x8]
	and	v23.16b, v23.16b, v26.16b
	st1	{v23.8h}, [x9]
	and	v24.16b, v24.16b, v26.16b
	st1	{v24.8h}, [x10]
	add	x11, x11, x6
	add	x7, x7, #0x40
	add	x8, x8, #0x40
	add	x9, x9, #0x40
	add	x10, x10, #0x40
	subs	x23, x23, #1
	bne	L_frodokem_mul_bs_neon_p
	ldp	x17, x19, [x29, #16]
	ldp	x20, x21, [x29, #32]
	ldp	x22, x23, [x29, #48]
	ldp	x24, x25, [x29, #64]
	ldp	x26, x27, [x29, #80]
	ldp	d8, d9, [x29, #96]
	ldp	d10, d11, [x29, #112]
	ldp	d12, d13, [x29, #128]
	ldp	d14, d15, [x29, #144]
	ldp	x29, x30, [sp], #0xa0
	ret
#ifndef __APPLE__
	.size	frodokem_mul_bs_neon,.-frodokem_mul_bs_neon
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	frodokem_mul_add_sb_plus_e_neon
.type	frodokem_mul_add_sb_plus_e_neon,@function
.align	2
frodokem_mul_add_sb_plus_e_neon:
#else
.section	__TEXT,__text
.globl	_frodokem_mul_add_sb_plus_e_neon
.p2align	2
_frodokem_mul_add_sb_plus_e_neon:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-48]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	sxtw	x5, w3
	lsl	x5, x5, #1
	dup	v10.8h, w4
	mov	x6, x2
	add	x7, x6, x5
	add	x8, x7, x5
	add	x9, x8, x5
	add	x10, x9, x5
	add	x11, x10, x5
	add	x12, x11, x5
	add	x13, x12, x5
	mov	x14, x1
	mov	x16, x0
	ld1	{v0.8h, v1.8h, v2.8h, v3.8h}, [x16], #0x40
	ld1	{v4.8h, v5.8h, v6.8h, v7.8h}, [x16], #0x40
	sub	x16, x16, #0x80
	sxtw	x15, w3
L_frodokem_mul_add_sb_plus_e_neon_j:
	ld1	{v8.8h}, [x14], #16
	ld1r	{v9.8h}, [x6], #2
	mla	v0.8h, v8.8h, v9.8h
	ld1r	{v9.8h}, [x7], #2
	mla	v1.8h, v8.8h, v9.8h
	ld1r	{v9.8h}, [x8], #2
	mla	v2.8h, v8.8h, v9.8h
	ld1r	{v9.8h}, [x9], #2
	mla	v3.8h, v8.8h, v9.8h
	ld1r	{v9.8h}, [x10], #2
	mla	v4.8h, v8.8h, v9.8h
	ld1r	{v9.8h}, [x11], #2
	mla	v5.8h, v8.8h, v9.8h
	ld1r	{v9.8h}, [x12], #2
	mla	v6.8h, v8.8h, v9.8h
	ld1r	{v9.8h}, [x13], #2
	mla	v7.8h, v8.8h, v9.8h
	subs	x15, x15, #1
	bne	L_frodokem_mul_add_sb_plus_e_neon_j
	and	v0.16b, v0.16b, v10.16b
	and	v1.16b, v1.16b, v10.16b
	and	v2.16b, v2.16b, v10.16b
	and	v3.16b, v3.16b, v10.16b
	and	v4.16b, v4.16b, v10.16b
	and	v5.16b, v5.16b, v10.16b
	and	v6.16b, v6.16b, v10.16b
	and	v7.16b, v7.16b, v10.16b
	st1	{v0.8h, v1.8h, v2.8h, v3.8h}, [x16], #0x40
	st1	{v4.8h, v5.8h, v6.8h, v7.8h}, [x16], #0x40
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	x29, x30, [sp], #48
	ret
#ifndef __APPLE__
	.size	frodokem_mul_add_sb_plus_e_neon,.-frodokem_mul_add_sb_plus_e_neon
#endif /* __APPLE__ */
#endif /* WOLFSSL_HAVE_FRODOKEM */
#ifdef WOLFSSL_HAVE_FRODOKEM
	.arch	armv8-a+crypto
#ifndef __APPLE__
.text
.globl	frodokem_gen_a_rows_aes_arm64
.type	frodokem_gen_a_rows_aes_arm64,@function
.align	2
frodokem_gen_a_rows_aes_arm64:
#else
.section	__TEXT,__text
.globl	_frodokem_gen_a_rows_aes_arm64
.p2align	2
_frodokem_gen_a_rows_aes_arm64:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	d8, d9, [x29, #16]
	stp	d10, d11, [x29, #32]
	stp	d12, d13, [x29, #48]
	stp	d14, d15, [x29, #64]
	ld1	{v0.16b, v1.16b, v2.16b, v3.16b}, [x2], #0x40
	ld1	{v4.16b, v5.16b, v6.16b, v7.16b}, [x2], #0x40
	ld1	{v8.16b, v9.16b, v10.16b}, [x2], #48
	dup	v19.8h, w6
	sxtw	x13, w3
	sxtw	x7, w5
	lsl	x7, x7, #1
	sxtw	x8, w4
	mul	x8, x8, x7
	movz	w14, #8, lsl 16
	mov	x9, x0
L_frodokem_gen_a_rows_aes_arm64_row:
	mov	w11, w13
	add	x10, x9, x7
L_frodokem_gen_a_rows_aes_arm64_blk:
	add	x12, x11, x14
	stp	x11, xzr, [x9], #16
	stp	x12, xzr, [x9], #16
	add	x11, x12, x14
	cmp	x9, x10
	blt	L_frodokem_gen_a_rows_aes_arm64_blk
	add	x13, x13, #1
	add	x10, x0, x8
	cmp	x9, x10
	blt	L_frodokem_gen_a_rows_aes_arm64_row
	cmp	x8, #0x80
	blt	L_frodokem_gen_a_rows_aes_arm64_tail
L_frodokem_gen_a_rows_aes_arm64_aes:
	ld1	{v11.16b, v12.16b, v13.16b, v14.16b}, [x0], #0x40
	ld1	{v15.16b, v16.16b, v17.16b, v18.16b}, [x0], #0x40
	aese	v11.16b, v0.16b
	aesmc	v11.16b, v11.16b
	aese	v12.16b, v0.16b
	aesmc	v12.16b, v12.16b
	aese	v13.16b, v0.16b
	aesmc	v13.16b, v13.16b
	aese	v14.16b, v0.16b
	aesmc	v14.16b, v14.16b
	aese	v15.16b, v0.16b
	aesmc	v15.16b, v15.16b
	aese	v16.16b, v0.16b
	aesmc	v16.16b, v16.16b
	aese	v17.16b, v0.16b
	aesmc	v17.16b, v17.16b
	aese	v18.16b, v0.16b
	aesmc	v18.16b, v18.16b
	aese	v11.16b, v1.16b
	aesmc	v11.16b, v11.16b
	aese	v12.16b, v1.16b
	aesmc	v12.16b, v12.16b
	aese	v13.16b, v1.16b
	aesmc	v13.16b, v13.16b
	aese	v14.16b, v1.16b
	aesmc	v14.16b, v14.16b
	aese	v15.16b, v1.16b
	aesmc	v15.16b, v15.16b
	aese	v16.16b, v1.16b
	aesmc	v16.16b, v16.16b
	aese	v17.16b, v1.16b
	aesmc	v17.16b, v17.16b
	aese	v18.16b, v1.16b
	aesmc	v18.16b, v18.16b
	aese	v11.16b, v2.16b
	aesmc	v11.16b, v11.16b
	aese	v12.16b, v2.16b
	aesmc	v12.16b, v12.16b
	aese	v13.16b, v2.16b
	aesmc	v13.16b, v13.16b
	aese	v14.16b, v2.16b
	aesmc	v14.16b, v14.16b
	aese	v15.16b, v2.16b
	aesmc	v15.16b, v15.16b
	aese	v16.16b, v2.16b
	aesmc	v16.16b, v16.16b
	aese	v17.16b, v2.16b
	aesmc	v17.16b, v17.16b
	aese	v18.16b, v2.16b
	aesmc	v18.16b, v18.16b
	aese	v11.16b, v3.16b
	aesmc	v11.16b, v11.16b
	aese	v12.16b, v3.16b
	aesmc	v12.16b, v12.16b
	aese	v13.16b, v3.16b
	aesmc	v13.16b, v13.16b
	aese	v14.16b, v3.16b
	aesmc	v14.16b, v14.16b
	aese	v15.16b, v3.16b
	aesmc	v15.16b, v15.16b
	aese	v16.16b, v3.16b
	aesmc	v16.16b, v16.16b
	aese	v17.16b, v3.16b
	aesmc	v17.16b, v17.16b
	aese	v18.16b, v3.16b
	aesmc	v18.16b, v18.16b
	aese	v11.16b, v4.16b
	aesmc	v11.16b, v11.16b
	aese	v12.16b, v4.16b
	aesmc	v12.16b, v12.16b
	aese	v13.16b, v4.16b
	aesmc	v13.16b, v13.16b
	aese	v14.16b, v4.16b
	aesmc	v14.16b, v14.16b
	aese	v15.16b, v4.16b
	aesmc	v15.16b, v15.16b
	aese	v16.16b, v4.16b
	aesmc	v16.16b, v16.16b
	aese	v17.16b, v4.16b
	aesmc	v17.16b, v17.16b
	aese	v18.16b, v4.16b
	aesmc	v18.16b, v18.16b
	aese	v11.16b, v5.16b
	aesmc	v11.16b, v11.16b
	aese	v12.16b, v5.16b
	aesmc	v12.16b, v12.16b
	aese	v13.16b, v5.16b
	aesmc	v13.16b, v13.16b
	aese	v14.16b, v5.16b
	aesmc	v14.16b, v14.16b
	aese	v15.16b, v5.16b
	aesmc	v15.16b, v15.16b
	aese	v16.16b, v5.16b
	aesmc	v16.16b, v16.16b
	aese	v17.16b, v5.16b
	aesmc	v17.16b, v17.16b
	aese	v18.16b, v5.16b
	aesmc	v18.16b, v18.16b
	aese	v11.16b, v6.16b
	aesmc	v11.16b, v11.16b
	aese	v12.16b, v6.16b
	aesmc	v12.16b, v12.16b
	aese	v13.16b, v6.16b
	aesmc	v13.16b, v13.16b
	aese	v14.16b, v6.16b
	aesmc	v14.16b, v14.16b
	aese	v15.16b, v6.16b
	aesmc	v15.16b, v15.16b
	aese	v16.16b, v6.16b
	aesmc	v16.16b, v16.16b
	aese	v17.16b, v6.16b
	aesmc	v17.16b, v17.16b
	aese	v18.16b, v6.16b
	aesmc	v18.16b, v18.16b
	aese	v11.16b, v7.16b
	aesmc	v11.16b, v11.16b
	aese	v12.16b, v7.16b
	aesmc	v12.16b, v12.16b
	aese	v13.16b, v7.16b
	aesmc	v13.16b, v13.16b
	aese	v14.16b, v7.16b
	aesmc	v14.16b, v14.16b
	aese	v15.16b, v7.16b
	aesmc	v15.16b, v15.16b
	aese	v16.16b, v7.16b
	aesmc	v16.16b, v16.16b
	aese	v17.16b, v7.16b
	aesmc	v17.16b, v17.16b
	aese	v18.16b, v7.16b
	aesmc	v18.16b, v18.16b
	aese	v11.16b, v8.16b
	aesmc	v11.16b, v11.16b
	aese	v12.16b, v8.16b
	aesmc	v12.16b, v12.16b
	aese	v13.16b, v8.16b
	aesmc	v13.16b, v13.16b
	aese	v14.16b, v8.16b
	aesmc	v14.16b, v14.16b
	aese	v15.16b, v8.16b
	aesmc	v15.16b, v15.16b
	aese	v16.16b, v8.16b
	aesmc	v16.16b, v16.16b
	aese	v17.16b, v8.16b
	aesmc	v17.16b, v17.16b
	aese	v18.16b, v8.16b
	aesmc	v18.16b, v18.16b
	aese	v11.16b, v9.16b
	aese	v12.16b, v9.16b
	aese	v13.16b, v9.16b
	aese	v14.16b, v9.16b
	aese	v15.16b, v9.16b
	aese	v16.16b, v9.16b
	aese	v17.16b, v9.16b
	aese	v18.16b, v9.16b
	eor	v11.16b, v11.16b, v10.16b
	eor	v12.16b, v12.16b, v10.16b
	eor	v13.16b, v13.16b, v10.16b
	eor	v14.16b, v14.16b, v10.16b
	eor	v15.16b, v15.16b, v10.16b
	eor	v16.16b, v16.16b, v10.16b
	eor	v17.16b, v17.16b, v10.16b
	eor	v18.16b, v18.16b, v10.16b
	and	v11.16b, v11.16b, v19.16b
	and	v12.16b, v12.16b, v19.16b
	and	v13.16b, v13.16b, v19.16b
	and	v14.16b, v14.16b, v19.16b
	and	v15.16b, v15.16b, v19.16b
	and	v16.16b, v16.16b, v19.16b
	and	v17.16b, v17.16b, v19.16b
	and	v18.16b, v18.16b, v19.16b
	st1	{v11.16b, v12.16b, v13.16b, v14.16b}, [x1], #0x40
	st1	{v15.16b, v16.16b, v17.16b, v18.16b}, [x1], #0x40
	subs	x8, x8, #0x80
	cmp	x8, #0x80
	bge	L_frodokem_gen_a_rows_aes_arm64_aes
L_frodokem_gen_a_rows_aes_arm64_tail:
	cmp	x8, #0
	beq	L_frodokem_gen_a_rows_aes_arm64_done
	ld1	{v11.16b, v12.16b, v13.16b, v14.16b}, [x0], #0x40
	aese	v11.16b, v0.16b
	aesmc	v11.16b, v11.16b
	aese	v12.16b, v0.16b
	aesmc	v12.16b, v12.16b
	aese	v13.16b, v0.16b
	aesmc	v13.16b, v13.16b
	aese	v14.16b, v0.16b
	aesmc	v14.16b, v14.16b
	aese	v11.16b, v1.16b
	aesmc	v11.16b, v11.16b
	aese	v12.16b, v1.16b
	aesmc	v12.16b, v12.16b
	aese	v13.16b, v1.16b
	aesmc	v13.16b, v13.16b
	aese	v14.16b, v1.16b
	aesmc	v14.16b, v14.16b
	aese	v11.16b, v2.16b
	aesmc	v11.16b, v11.16b
	aese	v12.16b, v2.16b
	aesmc	v12.16b, v12.16b
	aese	v13.16b, v2.16b
	aesmc	v13.16b, v13.16b
	aese	v14.16b, v2.16b
	aesmc	v14.16b, v14.16b
	aese	v11.16b, v3.16b
	aesmc	v11.16b, v11.16b
	aese	v12.16b, v3.16b
	aesmc	v12.16b, v12.16b
	aese	v13.16b, v3.16b
	aesmc	v13.16b, v13.16b
	aese	v14.16b, v3.16b
	aesmc	v14.16b, v14.16b
	aese	v11.16b, v4.16b
	aesmc	v11.16b, v11.16b
	aese	v12.16b, v4.16b
	aesmc	v12.16b, v12.16b
	aese	v13.16b, v4.16b
	aesmc	v13.16b, v13.16b
	aese	v14.16b, v4.16b
	aesmc	v14.16b, v14.16b
	aese	v11.16b, v5.16b
	aesmc	v11.16b, v11.16b
	aese	v12.16b, v5.16b
	aesmc	v12.16b, v12.16b
	aese	v13.16b, v5.16b
	aesmc	v13.16b, v13.16b
	aese	v14.16b, v5.16b
	aesmc	v14.16b, v14.16b
	aese	v11.16b, v6.16b
	aesmc	v11.16b, v11.16b
	aese	v12.16b, v6.16b
	aesmc	v12.16b, v12.16b
	aese	v13.16b, v6.16b
	aesmc	v13.16b, v13.16b
	aese	v14.16b, v6.16b
	aesmc	v14.16b, v14.16b
	aese	v11.16b, v7.16b
	aesmc	v11.16b, v11.16b
	aese	v12.16b, v7.16b
	aesmc	v12.16b, v12.16b
	aese	v13.16b, v7.16b
	aesmc	v13.16b, v13.16b
	aese	v14.16b, v7.16b
	aesmc	v14.16b, v14.16b
	aese	v11.16b, v8.16b
	aesmc	v11.16b, v11.16b
	aese	v12.16b, v8.16b
	aesmc	v12.16b, v12.16b
	aese	v13.16b, v8.16b
	aesmc	v13.16b, v13.16b
	aese	v14.16b, v8.16b
	aesmc	v14.16b, v14.16b
	aese	v11.16b, v9.16b
	aese	v12.16b, v9.16b
	aese	v13.16b, v9.16b
	aese	v14.16b, v9.16b
	eor	v11.16b, v11.16b, v10.16b
	eor	v12.16b, v12.16b, v10.16b
	eor	v13.16b, v13.16b, v10.16b
	eor	v14.16b, v14.16b, v10.16b
	and	v11.16b, v11.16b, v19.16b
	and	v12.16b, v12.16b, v19.16b
	and	v13.16b, v13.16b, v19.16b
	and	v14.16b, v14.16b, v19.16b
	st1	{v11.16b, v12.16b, v13.16b, v14.16b}, [x1], #0x40
L_frodokem_gen_a_rows_aes_arm64_done:
	ldp	d8, d9, [x29, #16]
	ldp	d10, d11, [x29, #32]
	ldp	d12, d13, [x29, #48]
	ldp	d14, d15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	frodokem_gen_a_rows_aes_arm64,.-frodokem_gen_a_rows_aes_arm64
#endif /* __APPLE__ */
#endif /* WOLFSSL_HAVE_FRODOKEM */
#ifdef WOLFSSL_HAVE_FRODOKEM
#ifdef WOLFSSL_FRODOKEM_SVE
	.arch	armv9-a+sve2
#ifndef __APPLE__
.text
.globl	frodokem_sa_accum_sve
.type	frodokem_sa_accum_sve,@function
.align	2
frodokem_sa_accum_sve:
#else
.section	__TEXT,__text
.globl	_frodokem_sa_accum_sve
.p2align	2
_frodokem_sa_accum_sve:
#endif /* __APPLE__ */
	sxtw	x5, w4
	lsl	x6, x5, #1
	add	x7, x2, x6
	sxtw	x8, w3
	lsl	x8, x8, #1
	add	x8, x1, x8
	mov	x9, #8
L_frodokem_sa_accum_sve_i:
	ldr	w11, [x8]
	mov	z0.h, w11
	lsr	w11, w11, #16
	mov	z1.h, w11
	add	x8, x8, x6
	mov	x10, #0
L_frodokem_sa_accum_sve_k:
	whilelt	p0.h, x10, x5
	ld1h	{z2.h}, p0/z, [x0, x10, lsl #1]
	ld1h	{z3.h}, p0/z, [x2, x10, lsl #1]
	ld1h	{z4.h}, p0/z, [x7, x10, lsl #1]
	mla	z2.h, p0/m, z3.h, z0.h
	mla	z2.h, p0/m, z4.h, z1.h
	st1h	{z2.h}, p0, [x0, x10, lsl #1]
	inch	x10
	cmp	x10, x5
	blt	L_frodokem_sa_accum_sve_k
	add	x0, x0, x6
	subs	x9, x9, #1
	bne	L_frodokem_sa_accum_sve_i
	ret
#ifndef __APPLE__
	.size	frodokem_sa_accum_sve,.-frodokem_sa_accum_sve
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	frodokem_as_accum_sve
.type	frodokem_as_accum_sve,@function
.align	2
frodokem_as_accum_sve:
#else
.section	__TEXT,__text
.globl	_frodokem_as_accum_sve
.p2align	2
_frodokem_as_accum_sve:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-112]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #24]
	str	x20, [x29, #40]
	stp	d8, d9, [x29, #48]
	stp	d10, d11, [x29, #64]
	stp	d12, d13, [x29, #80]
	stp	d14, d15, [x29, #96]
	sxtw	x5, w4
	lsl	x6, x5, #1
	add	x7, x2, x6
	mov	x12, x1
	add	x13, x12, x6
	add	x14, x13, x6
	add	x15, x14, x6
	add	x16, x15, x6
	add	x17, x16, x6
	add	x19, x17, x6
	add	x20, x19, x6
	mov	z0.h, #0
	mov	z1.h, #0
	mov	z2.h, #0
	mov	z3.h, #0
	mov	z4.h, #0
	mov	z5.h, #0
	mov	z6.h, #0
	mov	z7.h, #0
	mov	z8.h, #0
	mov	z9.h, #0
	mov	z10.h, #0
	mov	z11.h, #0
	mov	z12.h, #0
	mov	z13.h, #0
	mov	z14.h, #0
	mov	z15.h, #0
	mov	x9, #0
L_frodokem_as_accum_sve_k:
	whilelt	p0.h, x9, x5
	ld1h	{z16.h}, p0/z, [x2, x9, lsl #1]
	ld1h	{z17.h}, p0/z, [x7, x9, lsl #1]
	ld1h	{z18.h}, p0/z, [x12, x9, lsl #1]
	mla	z0.h, p0/m, z16.h, z18.h
	mla	z8.h, p0/m, z17.h, z18.h
	ld1h	{z18.h}, p0/z, [x13, x9, lsl #1]
	mla	z1.h, p0/m, z16.h, z18.h
	mla	z9.h, p0/m, z17.h, z18.h
	ld1h	{z18.h}, p0/z, [x14, x9, lsl #1]
	mla	z2.h, p0/m, z16.h, z18.h
	mla	z10.h, p0/m, z17.h, z18.h
	ld1h	{z18.h}, p0/z, [x15, x9, lsl #1]
	mla	z3.h, p0/m, z16.h, z18.h
	mla	z11.h, p0/m, z17.h, z18.h
	ld1h	{z18.h}, p0/z, [x16, x9, lsl #1]
	mla	z4.h, p0/m, z16.h, z18.h
	mla	z12.h, p0/m, z17.h, z18.h
	ld1h	{z18.h}, p0/z, [x17, x9, lsl #1]
	mla	z5.h, p0/m, z16.h, z18.h
	mla	z13.h, p0/m, z17.h, z18.h
	ld1h	{z18.h}, p0/z, [x19, x9, lsl #1]
	mla	z6.h, p0/m, z16.h, z18.h
	mla	z14.h, p0/m, z17.h, z18.h
	ld1h	{z18.h}, p0/z, [x20, x9, lsl #1]
	mla	z7.h, p0/m, z16.h, z18.h
	mla	z15.h, p0/m, z17.h, z18.h
	inch	x9
	cmp	x9, x5
	blt	L_frodokem_as_accum_sve_k
	ptrue	p1.h
	sxtw	x10, w3
	lsl	x10, x10, #4
	add	x8, x0, x10
	uaddv	d19, p1, z0.h
	umov	w11, v19.h[0]
	ldrh	w10, [x8]
	add	w11, w11, w10
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d19, p1, z1.h
	umov	w11, v19.h[0]
	ldrh	w10, [x8]
	add	w11, w11, w10
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d19, p1, z2.h
	umov	w11, v19.h[0]
	ldrh	w10, [x8]
	add	w11, w11, w10
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d19, p1, z3.h
	umov	w11, v19.h[0]
	ldrh	w10, [x8]
	add	w11, w11, w10
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d19, p1, z4.h
	umov	w11, v19.h[0]
	ldrh	w10, [x8]
	add	w11, w11, w10
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d19, p1, z5.h
	umov	w11, v19.h[0]
	ldrh	w10, [x8]
	add	w11, w11, w10
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d19, p1, z6.h
	umov	w11, v19.h[0]
	ldrh	w10, [x8]
	add	w11, w11, w10
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d19, p1, z7.h
	umov	w11, v19.h[0]
	ldrh	w10, [x8]
	add	w11, w11, w10
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d19, p1, z8.h
	umov	w11, v19.h[0]
	ldrh	w10, [x8]
	add	w11, w11, w10
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d19, p1, z9.h
	umov	w11, v19.h[0]
	ldrh	w10, [x8]
	add	w11, w11, w10
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d19, p1, z10.h
	umov	w11, v19.h[0]
	ldrh	w10, [x8]
	add	w11, w11, w10
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d19, p1, z11.h
	umov	w11, v19.h[0]
	ldrh	w10, [x8]
	add	w11, w11, w10
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d19, p1, z12.h
	umov	w11, v19.h[0]
	ldrh	w10, [x8]
	add	w11, w11, w10
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d19, p1, z13.h
	umov	w11, v19.h[0]
	ldrh	w10, [x8]
	add	w11, w11, w10
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d19, p1, z14.h
	umov	w11, v19.h[0]
	ldrh	w10, [x8]
	add	w11, w11, w10
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d19, p1, z15.h
	umov	w11, v19.h[0]
	ldrh	w10, [x8]
	add	w11, w11, w10
	strh	w11, [x8]
	add	x8, x8, #2
	ldp	x17, x19, [x29, #24]
	ldr	x20, [x29, #40]
	ldp	d8, d9, [x29, #48]
	ldp	d10, d11, [x29, #64]
	ldp	d12, d13, [x29, #80]
	ldp	d14, d15, [x29, #96]
	ldp	x29, x30, [sp], #0x70
	ret
#ifndef __APPLE__
	.size	frodokem_as_accum_sve,.-frodokem_as_accum_sve
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	frodokem_mul_bs_sve
.type	frodokem_mul_bs_sve,@function
.align	2
frodokem_mul_bs_sve:
#else
.section	__TEXT,__text
.globl	_frodokem_mul_bs_sve
.p2align	2
_frodokem_mul_bs_sve:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #24]
	str	x20, [x29, #40]
	stp	d8, d9, [x29, #48]
	stp	d10, d11, [x29, #64]
	sxtw	x5, w3
	lsl	x6, x5, #1
	mov	x12, x2
	add	x13, x12, x6
	add	x14, x13, x6
	add	x15, x14, x6
	add	x16, x15, x6
	add	x17, x16, x6
	add	x19, x17, x6
	add	x20, x19, x6
	mov	x7, x1
	mov	x8, x0
	ptrue	p1.h
	mov	x9, #8
L_frodokem_mul_bs_sve_i:
	mov	z0.h, #0
	mov	z1.h, #0
	mov	z2.h, #0
	mov	z3.h, #0
	mov	z4.h, #0
	mov	z5.h, #0
	mov	z6.h, #0
	mov	z7.h, #0
	mov	x10, #0
L_frodokem_mul_bs_sve_k:
	whilelt	p0.h, x10, x5
	ld1h	{z8.h}, p0/z, [x7, x10, lsl #1]
	ld1h	{z9.h}, p0/z, [x12, x10, lsl #1]
	mla	z0.h, p0/m, z8.h, z9.h
	ld1h	{z9.h}, p0/z, [x13, x10, lsl #1]
	mla	z1.h, p0/m, z8.h, z9.h
	ld1h	{z9.h}, p0/z, [x14, x10, lsl #1]
	mla	z2.h, p0/m, z8.h, z9.h
	ld1h	{z9.h}, p0/z, [x15, x10, lsl #1]
	mla	z3.h, p0/m, z8.h, z9.h
	ld1h	{z9.h}, p0/z, [x16, x10, lsl #1]
	mla	z4.h, p0/m, z8.h, z9.h
	ld1h	{z9.h}, p0/z, [x17, x10, lsl #1]
	mla	z5.h, p0/m, z8.h, z9.h
	ld1h	{z9.h}, p0/z, [x19, x10, lsl #1]
	mla	z6.h, p0/m, z8.h, z9.h
	ld1h	{z9.h}, p0/z, [x20, x10, lsl #1]
	mla	z7.h, p0/m, z8.h, z9.h
	inch	x10
	cmp	x10, x5
	blt	L_frodokem_mul_bs_sve_k
	uaddv	d10, p1, z0.h
	umov	w11, v10.h[0]
	and	w11, w11, w4
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d10, p1, z1.h
	umov	w11, v10.h[0]
	and	w11, w11, w4
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d10, p1, z2.h
	umov	w11, v10.h[0]
	and	w11, w11, w4
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d10, p1, z3.h
	umov	w11, v10.h[0]
	and	w11, w11, w4
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d10, p1, z4.h
	umov	w11, v10.h[0]
	and	w11, w11, w4
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d10, p1, z5.h
	umov	w11, v10.h[0]
	and	w11, w11, w4
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d10, p1, z6.h
	umov	w11, v10.h[0]
	and	w11, w11, w4
	strh	w11, [x8]
	add	x8, x8, #2
	uaddv	d10, p1, z7.h
	umov	w11, v10.h[0]
	and	w11, w11, w4
	strh	w11, [x8]
	add	x8, x8, #2
	add	x7, x7, x6
	subs	x9, x9, #1
	bne	L_frodokem_mul_bs_sve_i
	ldp	x17, x19, [x29, #24]
	ldr	x20, [x29, #40]
	ldp	d8, d9, [x29, #48]
	ldp	d10, d11, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
#ifndef __APPLE__
	.size	frodokem_mul_bs_sve,.-frodokem_mul_bs_sve
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	frodokem_add_sve
.type	frodokem_add_sve,@function
.align	2
frodokem_add_sve:
#else
.section	__TEXT,__text
.globl	_frodokem_add_sve
.p2align	2
_frodokem_add_sve:
#endif /* __APPLE__ */
	mov	z2.h, w2
	mov	x3, #0x40
	mov	x4, #0
L_frodokem_add_sve_k:
	whilelt	p0.h, x4, x3
	ld1h	{z0.h}, p0/z, [x0, x4, lsl #1]
	ld1h	{z1.h}, p0/z, [x1, x4, lsl #1]
	add	z0.h, z0.h, z1.h
	and	z0.d, z0.d, z2.d
	st1h	{z0.h}, p0, [x0, x4, lsl #1]
	inch	x4
	cmp	x4, x3
	blt	L_frodokem_add_sve_k
	ret
#ifndef __APPLE__
	.size	frodokem_add_sve,.-frodokem_add_sve
#endif /* __APPLE__ */
#endif /* WOLFSSL_FRODOKEM_SVE */
#endif /* WOLFSSL_HAVE_FRODOKEM */
#ifdef WOLFSSL_HAVE_FRODOKEM
#ifdef WOLFSSL_FRODOKEM_SME
	.arch	armv9-a+sve2+sme+sme2
#ifndef __APPLE__
.text
.globl	frodokem_mul_bs_sme
.type	frodokem_mul_bs_sme,@function
.align	2
frodokem_mul_bs_sme:
#else
.section	__TEXT,__text
.globl	_frodokem_mul_bs_sme
.p2align	2
_frodokem_mul_bs_sme:
#endif /* __APPLE__ */
	smstart
	zero	{za}
	mov	x6, #16
	whilelt	p0.h, xzr, x6
	sxtw	x5, w3
	lsr	x5, x5, #1
L_frodokem_mul_bs_sme_k:
	ld1h	{z0.h}, p0/z, [x1]
	ld1h	{z1.h}, p0/z, [x2]
	umopa	za0.s, p0/m, p0/m, z0.h, z1.h
	add	x1, x1, #32
	add	x2, x2, #32
	subs	x5, x5, #1
	bne	L_frodokem_mul_bs_sme_k
	mov	z3.h, w4
	mov	x6, #8
	whilelt	p1.h, xzr, x6
	whilelt	p2.s, xzr, x6
	mov	w12, #0
L_frodokem_mul_bs_sme_e:
	mova	z2.s, p2/m, za0h.s[w12, 0]
	uzp1	z2.h, z2.h, z2.h
	and	z2.d, z2.d, z3.d
	st1h	{z2.h}, p1, [x0]
	add	x0, x0, #16
	add	w12, w12, #1
	cmp	w12, #8
	bne	L_frodokem_mul_bs_sme_e
	smstop
	ret
#ifndef __APPLE__
	.size	frodokem_mul_bs_sme,.-frodokem_mul_bs_sme
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	frodokem_sa_accum_sme
.type	frodokem_sa_accum_sme,@function
.align	2
frodokem_sa_accum_sme:
#else
.section	__TEXT,__text
.globl	_frodokem_sa_accum_sme
.p2align	2
_frodokem_sa_accum_sme:
#endif /* __APPLE__ */
	smstart
	mov	x10, #16
	whilelt	p0.h, xzr, x10
	mov	x10, #8
	whilelt	p1.h, xzr, x10
	whilelt	p2.s, xzr, x10
	ld1h	{z0.h}, p0/z, [x1]
	sxtw	x10, w3
	lsr	x9, x10, #3
	lsl	x4, x10, #1
	mov	x5, x2
	add	x6, x2, x4
	mov	x7, x0
L_frodokem_sa_accum_sme_k:
	zero	{za}
	ld1h	{z1.h}, p1/z, [x5]
	ld1h	{z2.h}, p1/z, [x6]
	zip1	z3.h, z1.h, z2.h
	umopa	za0.s, p0/m, p0/m, z0.h, z3.h
	add	x5, x5, #16
	add	x6, x6, #16
	mov	x8, x7
	mov	w12, #0
L_frodokem_sa_accum_sme_e:
	mova	z4.s, p2/m, za0h.s[w12, 0]
	uzp1	z4.h, z4.h, z4.h
	ld1h	{z5.h}, p1/z, [x8]
	add	z4.h, z4.h, z5.h
	st1h	{z4.h}, p1, [x8]
	add	x8, x8, x4
	add	w12, w12, #1
	cmp	w12, #8
	blt	L_frodokem_sa_accum_sme_e
	add	x7, x7, #16
	subs	x9, x9, #1
	bne	L_frodokem_sa_accum_sme_k
	smstop
	ret
#ifndef __APPLE__
	.size	frodokem_sa_accum_sme,.-frodokem_sa_accum_sme
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	frodokem_as_accum_sme
.type	frodokem_as_accum_sme,@function
.align	2
frodokem_as_accum_sme:
#else
.section	__TEXT,__text
.globl	_frodokem_as_accum_sme
.p2align	2
_frodokem_as_accum_sme:
#endif /* __APPLE__ */
	smstart
	zero	{za}
	mov	x8, #4
	whilelt	p0.h, xzr, x8
	mov	x8, #16
	whilelt	p1.h, xzr, x8
	sxtw	x7, w4
	lsr	x7, x7, #1
L_frodokem_as_accum_sme_k:
	ld1h	{z0.h}, p0/z, [x1]
	ld1h	{z1.h}, p1/z, [x2]
	umopa	za0.s, p0/m, p1/m, z0.h, z1.h
	add	x1, x1, #8
	add	x2, x2, #32
	subs	x7, x7, #1
	bne	L_frodokem_as_accum_sme_k
	mov	x8, #8
	whilelt	p2.h, xzr, x8
	whilelt	p3.s, xzr, x8
	sxtw	x5, w3
	lsl	x5, x5, #4
	add	x5, x0, x5
	add	x6, x5, #16
	mov	w12, #0
	mova	z2.s, p3/m, za0h.s[w12, 0]
	uzp1	z2.h, z2.h, z2.h
	ld1h	{z3.h}, p2/z, [x5]
	add	z2.h, z2.h, z3.h
	st1h	{z2.h}, p2, [x5]
	mov	w12, #1
	mova	z2.s, p3/m, za0h.s[w12, 0]
	uzp1	z2.h, z2.h, z2.h
	ld1h	{z3.h}, p2/z, [x6]
	add	z2.h, z2.h, z3.h
	st1h	{z2.h}, p2, [x6]
	smstop
	ret
#ifndef __APPLE__
	.size	frodokem_as_accum_sme,.-frodokem_as_accum_sme
#endif /* __APPLE__ */
#endif /* WOLFSSL_FRODOKEM_SME */
#endif /* WOLFSSL_HAVE_FRODOKEM */
#endif /* __aarch64__ */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
