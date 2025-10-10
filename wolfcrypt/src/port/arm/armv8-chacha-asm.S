/* armv8-chacha-asm
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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
 *   ruby ./chacha/chacha.rb arm64 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-chacha-asm.S
 */
#ifdef WOLFSSL_ARMASM
#ifdef __aarch64__
#ifndef WOLFSSL_ARMASM_INLINE
#ifdef HAVE_CHACHA
#ifndef __APPLE__
	.text
	.type	L_chacha20_arm64_ctr, %object
	.section	.rodata
	.size	L_chacha20_arm64_ctr, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_chacha20_arm64_ctr:
	.word	0x00000000
	.word	0x00000001
	.word	0x00000002
	.word	0x00000003
#ifndef __APPLE__
	.text
	.type	L_chacha20_arm64_rol8, %object
	.section	.rodata
	.size	L_chacha20_arm64_rol8, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_chacha20_arm64_rol8:
	.word	0x02010003
	.word	0x06050407
	.word	0x0a09080b
	.word	0x0e0d0c0f
#ifndef WOLFSSL_ARMASM_NO_NEON
#ifndef __APPLE__
.text
.globl	wc_chacha_crypt_bytes
.type	wc_chacha_crypt_bytes,@function
.align	2
wc_chacha_crypt_bytes:
#else
.section	__TEXT,__text
.globl	_wc_chacha_crypt_bytes
.p2align	2
_wc_chacha_crypt_bytes:
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
#ifndef __APPLE__
	adrp x5, L_chacha20_arm64_rol8
	add  x5, x5, :lo12:L_chacha20_arm64_rol8
#else
	adrp x5, L_chacha20_arm64_rol8@PAGE
	add  x5, x5, :lo12:L_chacha20_arm64_rol8@PAGEOFF
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x6, L_chacha20_arm64_ctr
	add  x6, x6, :lo12:L_chacha20_arm64_ctr
#else
	adrp x6, L_chacha20_arm64_ctr@PAGE
	add  x6, x6, :lo12:L_chacha20_arm64_ctr@PAGEOFF
#endif /* __APPLE__ */
	eor	v29.16b, v29.16b, v29.16b
	mov	x26, #5
	eor	v31.16b, v31.16b, v31.16b
	mov	w7, #1
	ld1	{v30.16b}, [x5]
	ld1	{v28.4s}, [x6]
	add	x4, x0, #0x44
	mov	v29.s[0], w26
	mov	v31.s[0], w7
	# Load state to encrypt
	ld1	{v16.4s, v17.4s, v18.4s, v19.4s}, [x0]
	cmp	x3, #0x140
	blt	L_chacha_crypt_bytes_arm64_lt_320
	mov	w25, #4
L_chacha_crypt_bytes_arm64_loop_320:
	# Move state into regular register
	mov	x8, v16.d[0]
	mov	x10, v16.d[1]
	mov	x12, v17.d[0]
	mov	x14, v17.d[1]
	mov	x16, v18.d[0]
	mov	x19, v18.d[1]
	mov	x21, v19.d[0]
	mov	x23, v19.d[1]
	sub	x3, x3, #0x140
	# Move state into vector registers
	dup	v0.4s, v16.s[0]
	dup	v1.4s, v16.s[1]
	lsr	x9, x8, #32
	dup	v2.4s, v16.s[2]
	dup	v3.4s, v16.s[3]
	lsr	x11, x10, #32
	dup	v4.4s, v17.s[0]
	dup	v5.4s, v17.s[1]
	lsr	x13, x12, #32
	dup	v6.4s, v17.s[2]
	dup	v7.4s, v17.s[3]
	lsr	x15, x14, #32
	dup	v8.4s, v18.s[0]
	dup	v9.4s, v18.s[1]
	lsr	x17, x16, #32
	dup	v10.4s, v18.s[2]
	dup	v11.4s, v18.s[3]
	lsr	x20, x19, #32
	dup	v12.4s, v19.s[0]
	dup	v13.4s, v19.s[1]
	lsr	x22, x21, #32
	dup	v14.4s, v19.s[2]
	dup	v15.4s, v19.s[3]
	lsr	x24, x23, #32
	# Add to counter word
	add	v12.4s, v12.4s, v28.4s
	add	w21, w21, w25
	# Set number of odd+even rounds to perform
	mov	x26, #10
L_chacha_crypt_bytes_arm64_round_start_320:
	subs	x26, x26, #1
	# Round odd
	# a += b; d ^= a; d <<<= 16;
	add	v0.4s, v0.4s, v4.4s
	add	w8, w8, w12
	add	v1.4s, v1.4s, v5.4s
	add	w9, w9, w13
	add	v2.4s, v2.4s, v6.4s
	add	w10, w10, w14
	add	v3.4s, v3.4s, v7.4s
	add	w11, w11, w15
	eor	v12.16b, v12.16b, v0.16b
	eor	w21, w21, w8
	eor	v13.16b, v13.16b, v1.16b
	eor	w22, w22, w9
	eor	v14.16b, v14.16b, v2.16b
	eor	w23, w23, w10
	eor	v15.16b, v15.16b, v3.16b
	eor	w24, w24, w11
	rev32	v12.8h, v12.8h
	ror	w21, w21, #16
	rev32	v13.8h, v13.8h
	ror	w22, w22, #16
	rev32	v14.8h, v14.8h
	ror	w23, w23, #16
	rev32	v15.8h, v15.8h
	ror	w24, w24, #16
	# c += d; b ^= c; b <<<= 12;
	add	v8.4s, v8.4s, v12.4s
	add	w16, w16, w21
	add	v9.4s, v9.4s, v13.4s
	add	w17, w17, w22
	add	v10.4s, v10.4s, v14.4s
	add	w19, w19, w23
	add	v11.4s, v11.4s, v15.4s
	add	w20, w20, w24
	eor	v20.16b, v4.16b, v8.16b
	eor	w12, w12, w16
	eor	v21.16b, v5.16b, v9.16b
	eor	w13, w13, w17
	eor	v22.16b, v6.16b, v10.16b
	eor	w14, w14, w19
	eor	v23.16b, v7.16b, v11.16b
	eor	w15, w15, w20
	shl	v4.4s, v20.4s, #12
	ror	w12, w12, #20
	shl	v5.4s, v21.4s, #12
	ror	w13, w13, #20
	shl	v6.4s, v22.4s, #12
	ror	w14, w14, #20
	shl	v7.4s, v23.4s, #12
	ror	w15, w15, #20
	sri	v4.4s, v20.4s, #20
	sri	v5.4s, v21.4s, #20
	sri	v6.4s, v22.4s, #20
	sri	v7.4s, v23.4s, #20
	# a += b; d ^= a; d <<<= 8;
	add	v0.4s, v0.4s, v4.4s
	add	w8, w8, w12
	add	v1.4s, v1.4s, v5.4s
	add	w9, w9, w13
	add	v2.4s, v2.4s, v6.4s
	add	w10, w10, w14
	add	v3.4s, v3.4s, v7.4s
	add	w11, w11, w15
	eor	v12.16b, v12.16b, v0.16b
	eor	w21, w21, w8
	eor	v13.16b, v13.16b, v1.16b
	eor	w22, w22, w9
	eor	v14.16b, v14.16b, v2.16b
	eor	w23, w23, w10
	eor	v15.16b, v15.16b, v3.16b
	eor	w24, w24, w11
	tbl	v12.16b, {v12.16b}, v30.16b
	ror	w21, w21, #24
	tbl	v13.16b, {v13.16b}, v30.16b
	ror	w22, w22, #24
	tbl	v14.16b, {v14.16b}, v30.16b
	ror	w23, w23, #24
	tbl	v15.16b, {v15.16b}, v30.16b
	ror	w24, w24, #24
	# c += d; b ^= c; b <<<= 7;
	add	v8.4s, v8.4s, v12.4s
	add	w16, w16, w21
	add	v9.4s, v9.4s, v13.4s
	add	w17, w17, w22
	add	v10.4s, v10.4s, v14.4s
	add	w19, w19, w23
	add	v11.4s, v11.4s, v15.4s
	add	w20, w20, w24
	eor	v20.16b, v4.16b, v8.16b
	eor	w12, w12, w16
	eor	v21.16b, v5.16b, v9.16b
	eor	w13, w13, w17
	eor	v22.16b, v6.16b, v10.16b
	eor	w14, w14, w19
	eor	v23.16b, v7.16b, v11.16b
	eor	w15, w15, w20
	shl	v4.4s, v20.4s, #7
	ror	w12, w12, #25
	shl	v5.4s, v21.4s, #7
	ror	w13, w13, #25
	shl	v6.4s, v22.4s, #7
	ror	w14, w14, #25
	shl	v7.4s, v23.4s, #7
	ror	w15, w15, #25
	sri	v4.4s, v20.4s, #25
	sri	v5.4s, v21.4s, #25
	sri	v6.4s, v22.4s, #25
	sri	v7.4s, v23.4s, #25
	# Round even
	# a += b; d ^= a; d <<<= 16;
	add	v0.4s, v0.4s, v5.4s
	add	w8, w8, w13
	add	v1.4s, v1.4s, v6.4s
	add	w9, w9, w14
	add	v2.4s, v2.4s, v7.4s
	add	w10, w10, w15
	add	v3.4s, v3.4s, v4.4s
	add	w11, w11, w12
	eor	v15.16b, v15.16b, v0.16b
	eor	w24, w24, w8
	eor	v12.16b, v12.16b, v1.16b
	eor	w21, w21, w9
	eor	v13.16b, v13.16b, v2.16b
	eor	w22, w22, w10
	eor	v14.16b, v14.16b, v3.16b
	eor	w23, w23, w11
	rev32	v15.8h, v15.8h
	ror	w24, w24, #16
	rev32	v12.8h, v12.8h
	ror	w21, w21, #16
	rev32	v13.8h, v13.8h
	ror	w22, w22, #16
	rev32	v14.8h, v14.8h
	ror	w23, w23, #16
	# c += d; b ^= c; b <<<= 12;
	add	v10.4s, v10.4s, v15.4s
	add	w19, w19, w24
	add	v11.4s, v11.4s, v12.4s
	add	w20, w20, w21
	add	v8.4s, v8.4s, v13.4s
	add	w16, w16, w22
	add	v9.4s, v9.4s, v14.4s
	add	w17, w17, w23
	eor	v20.16b, v5.16b, v10.16b
	eor	w13, w13, w19
	eor	v21.16b, v6.16b, v11.16b
	eor	w14, w14, w20
	eor	v22.16b, v7.16b, v8.16b
	eor	w15, w15, w16
	eor	v23.16b, v4.16b, v9.16b
	eor	w12, w12, w17
	shl	v5.4s, v20.4s, #12
	ror	w13, w13, #20
	shl	v6.4s, v21.4s, #12
	ror	w14, w14, #20
	shl	v7.4s, v22.4s, #12
	ror	w15, w15, #20
	shl	v4.4s, v23.4s, #12
	ror	w12, w12, #20
	sri	v5.4s, v20.4s, #20
	sri	v6.4s, v21.4s, #20
	sri	v7.4s, v22.4s, #20
	sri	v4.4s, v23.4s, #20
	# a += b; d ^= a; d <<<= 8;
	add	v0.4s, v0.4s, v5.4s
	add	w8, w8, w13
	add	v1.4s, v1.4s, v6.4s
	add	w9, w9, w14
	add	v2.4s, v2.4s, v7.4s
	add	w10, w10, w15
	add	v3.4s, v3.4s, v4.4s
	add	w11, w11, w12
	eor	v15.16b, v15.16b, v0.16b
	eor	w24, w24, w8
	eor	v12.16b, v12.16b, v1.16b
	eor	w21, w21, w9
	eor	v13.16b, v13.16b, v2.16b
	eor	w22, w22, w10
	eor	v14.16b, v14.16b, v3.16b
	eor	w23, w23, w11
	tbl	v15.16b, {v15.16b}, v30.16b
	ror	w24, w24, #24
	tbl	v12.16b, {v12.16b}, v30.16b
	ror	w21, w21, #24
	tbl	v13.16b, {v13.16b}, v30.16b
	ror	w22, w22, #24
	tbl	v14.16b, {v14.16b}, v30.16b
	ror	w23, w23, #24
	# c += d; b ^= c; b <<<= 7;
	add	v10.4s, v10.4s, v15.4s
	add	w19, w19, w24
	add	v11.4s, v11.4s, v12.4s
	add	w20, w20, w21
	add	v8.4s, v8.4s, v13.4s
	add	w16, w16, w22
	add	v9.4s, v9.4s, v14.4s
	add	w17, w17, w23
	eor	v20.16b, v5.16b, v10.16b
	eor	w13, w13, w19
	eor	v21.16b, v6.16b, v11.16b
	eor	w14, w14, w20
	eor	v22.16b, v7.16b, v8.16b
	eor	w15, w15, w16
	eor	v23.16b, v4.16b, v9.16b
	eor	w12, w12, w17
	shl	v5.4s, v20.4s, #7
	ror	w13, w13, #25
	shl	v6.4s, v21.4s, #7
	ror	w14, w14, #25
	shl	v7.4s, v22.4s, #7
	ror	w15, w15, #25
	shl	v4.4s, v23.4s, #7
	ror	w12, w12, #25
	sri	v5.4s, v20.4s, #25
	sri	v6.4s, v21.4s, #25
	sri	v7.4s, v22.4s, #25
	sri	v4.4s, v23.4s, #25
	bne	L_chacha_crypt_bytes_arm64_round_start_320
	# Add counter now rather than after transposed
	add	v12.4s, v12.4s, v28.4s
	add	w21, w21, w25
	# Load message
	ld1	{v24.16b, v25.16b, v26.16b, v27.16b}, [x2], #0x40
	# Transpose vectors
	trn1	v20.4s, v0.4s, v1.4s
	trn1	v22.4s, v2.4s, v3.4s
	orr	x8, x8, x9, lsl 32
	trn2	v21.4s, v0.4s, v1.4s
	trn2	v23.4s, v2.4s, v3.4s
	trn1	v0.2d, v20.2d, v22.2d
	trn1	v1.2d, v21.2d, v23.2d
	orr	x10, x10, x11, lsl 32
	trn2	v2.2d, v20.2d, v22.2d
	trn2	v3.2d, v21.2d, v23.2d
	trn1	v20.4s, v4.4s, v5.4s
	trn1	v22.4s, v6.4s, v7.4s
	orr	x12, x12, x13, lsl 32
	trn2	v21.4s, v4.4s, v5.4s
	trn2	v23.4s, v6.4s, v7.4s
	trn1	v4.2d, v20.2d, v22.2d
	trn1	v5.2d, v21.2d, v23.2d
	orr	x14, x14, x15, lsl 32
	trn2	v6.2d, v20.2d, v22.2d
	trn2	v7.2d, v21.2d, v23.2d
	trn1	v20.4s, v8.4s, v9.4s
	trn1	v22.4s, v10.4s, v11.4s
	orr	x16, x16, x17, lsl 32
	trn2	v21.4s, v8.4s, v9.4s
	trn2	v23.4s, v10.4s, v11.4s
	trn1	v8.2d, v20.2d, v22.2d
	trn1	v9.2d, v21.2d, v23.2d
	orr	x19, x19, x20, lsl 32
	trn2	v10.2d, v20.2d, v22.2d
	trn2	v11.2d, v21.2d, v23.2d
	trn1	v20.4s, v12.4s, v13.4s
	trn1	v22.4s, v14.4s, v15.4s
	orr	x21, x21, x22, lsl 32
	trn2	v21.4s, v12.4s, v13.4s
	trn2	v23.4s, v14.4s, v15.4s
	trn1	v12.2d, v20.2d, v22.2d
	trn1	v13.2d, v21.2d, v23.2d
	orr	x23, x23, x24, lsl 32
	trn2	v14.2d, v20.2d, v22.2d
	trn2	v15.2d, v21.2d, v23.2d
	# Add back state, XOR in message and store (load next block)
	add	v20.4s, v0.4s, v16.4s
	add	v21.4s, v4.4s, v17.4s
	add	v22.4s, v8.4s, v18.4s
	add	v23.4s, v12.4s, v19.4s
	eor	v20.16b, v20.16b, v24.16b
	eor	v21.16b, v21.16b, v25.16b
	eor	v22.16b, v22.16b, v26.16b
	eor	v23.16b, v23.16b, v27.16b
	ld1	{v24.16b, v25.16b, v26.16b, v27.16b}, [x2], #0x40
	st1	{v20.16b, v21.16b, v22.16b, v23.16b}, [x1], #0x40
	add	v20.4s, v1.4s, v16.4s
	add	v21.4s, v5.4s, v17.4s
	add	v22.4s, v9.4s, v18.4s
	add	v23.4s, v13.4s, v19.4s
	eor	v20.16b, v20.16b, v24.16b
	eor	v21.16b, v21.16b, v25.16b
	eor	v22.16b, v22.16b, v26.16b
	eor	v23.16b, v23.16b, v27.16b
	ld1	{v24.16b, v25.16b, v26.16b, v27.16b}, [x2], #0x40
	st1	{v20.16b, v21.16b, v22.16b, v23.16b}, [x1], #0x40
	add	v20.4s, v2.4s, v16.4s
	add	v21.4s, v6.4s, v17.4s
	add	v22.4s, v10.4s, v18.4s
	add	v23.4s, v14.4s, v19.4s
	eor	v20.16b, v20.16b, v24.16b
	eor	v21.16b, v21.16b, v25.16b
	eor	v22.16b, v22.16b, v26.16b
	eor	v23.16b, v23.16b, v27.16b
	ld1	{v24.16b, v25.16b, v26.16b, v27.16b}, [x2], #0x40
	st1	{v20.16b, v21.16b, v22.16b, v23.16b}, [x1], #0x40
	add	v20.4s, v3.4s, v16.4s
	add	v21.4s, v7.4s, v17.4s
	add	v22.4s, v11.4s, v18.4s
	add	v23.4s, v15.4s, v19.4s
	eor	v20.16b, v20.16b, v24.16b
	eor	v21.16b, v21.16b, v25.16b
	eor	v22.16b, v22.16b, v26.16b
	eor	v23.16b, v23.16b, v27.16b
	ld1	{v24.16b, v25.16b, v26.16b, v27.16b}, [x2], #0x40
	st1	{v20.16b, v21.16b, v22.16b, v23.16b}, [x1], #0x40
	# Move regular registers into vector registers for adding and xor
	mov	v0.d[0], x8
	mov	v0.d[1], x10
	mov	v1.d[0], x12
	mov	v1.d[1], x14
	mov	v2.d[0], x16
	mov	v2.d[1], x19
	mov	v3.d[0], x21
	mov	v3.d[1], x23
	# Add back state, XOR in message and store
	add	v0.4s, v0.4s, v16.4s
	add	v1.4s, v1.4s, v17.4s
	add	v2.4s, v2.4s, v18.4s
	add	v3.4s, v3.4s, v19.4s
	eor	v0.16b, v0.16b, v24.16b
	eor	v1.16b, v1.16b, v25.16b
	eor	v2.16b, v2.16b, v26.16b
	eor	v3.16b, v3.16b, v27.16b
	st1	{v0.4s, v1.4s, v2.4s, v3.4s}, [x1], #0x40
	cmp	x3, #0x140
	add	v19.4s, v19.4s, v29.4s
	bge	L_chacha_crypt_bytes_arm64_loop_320
	# Done doing 320 bytes at a time
L_chacha_crypt_bytes_arm64_lt_320:
	cmp	x3, #0x100
	blt	L_chacha_crypt_bytes_arm64_lt_256
	# Move state into regular register
	mov	x8, v16.d[0]
	mov	x10, v16.d[1]
	mov	x12, v17.d[0]
	mov	x14, v17.d[1]
	mov	x16, v18.d[0]
	mov	x19, v18.d[1]
	mov	x21, v19.d[0]
	mov	x23, v19.d[1]
	# Move state into vector registers
	mov	v0.16b, v16.16b
	mov	v1.16b, v17.16b
	lsr	x9, x8, #32
	mov	v2.16b, v18.16b
	add	w5, w21, #1
	mov	v3.16b, v19.16b
	lsr	x11, x10, #32
	mov	v4.16b, v16.16b
	mov	v5.16b, v17.16b
	lsr	x13, x12, #32
	mov	v6.16b, v18.16b
	add	w6, w21, #2
	mov	v7.16b, v19.16b
	lsr	x15, x14, #32
	mov	v8.16b, v16.16b
	mov	v9.16b, v17.16b
	lsr	x17, x16, #32
	mov	v10.16b, v18.16b
	add	w21, w21, #3
	mov	v11.16b, v19.16b
	lsr	x20, x19, #32
	mov	v7.s[0], w5
	lsr	x22, x21, #32
	mov	v11.s[0], w6
	lsr	x24, x23, #32
	add	w7, w21, #1
	# Set number of odd+even rounds to perform
	mov	x26, #10
L_chacha_crypt_bytes_arm64_round_start_256:
	subs	x26, x26, #1
	# Round odd
	# a += b; d ^= a; d <<<= 16;
	add	v0.4s, v0.4s, v1.4s
	add	w8, w8, w12
	add	v4.4s, v4.4s, v5.4s
	add	w9, w9, w13
	add	v8.4s, v8.4s, v9.4s
	add	w10, w10, w14
	eor	v3.16b, v3.16b, v0.16b
	add	w11, w11, w15
	eor	v7.16b, v7.16b, v4.16b
	eor	w21, w21, w8
	eor	v11.16b, v11.16b, v8.16b
	eor	w22, w22, w9
	rev32	v3.8h, v3.8h
	eor	w23, w23, w10
	rev32	v7.8h, v7.8h
	eor	w24, w24, w11
	rev32	v11.8h, v11.8h
	ror	w21, w21, #16
	# c += d; b ^= c; b <<<= 12;
	add	v2.4s, v2.4s, v3.4s
	ror	w22, w22, #16
	add	v6.4s, v6.4s, v7.4s
	ror	w23, w23, #16
	add	v10.4s, v10.4s, v11.4s
	ror	w24, w24, #16
	eor	v20.16b, v1.16b, v2.16b
	add	w16, w16, w21
	eor	v21.16b, v5.16b, v6.16b
	add	w17, w17, w22
	eor	v22.16b, v9.16b, v10.16b
	add	w19, w19, w23
	shl	v1.4s, v20.4s, #12
	add	w20, w20, w24
	shl	v5.4s, v21.4s, #12
	eor	w12, w12, w16
	shl	v9.4s, v22.4s, #12
	eor	w13, w13, w17
	sri	v1.4s, v20.4s, #20
	eor	w14, w14, w19
	sri	v5.4s, v21.4s, #20
	eor	w15, w15, w20
	sri	v9.4s, v22.4s, #20
	ror	w12, w12, #20
	# a += b; d ^= a; d <<<= 8;
	add	v0.4s, v0.4s, v1.4s
	ror	w13, w13, #20
	add	v4.4s, v4.4s, v5.4s
	ror	w14, w14, #20
	add	v8.4s, v8.4s, v9.4s
	ror	w15, w15, #20
	eor	v3.16b, v3.16b, v0.16b
	add	w8, w8, w12
	eor	v7.16b, v7.16b, v4.16b
	add	w9, w9, w13
	eor	v11.16b, v11.16b, v8.16b
	add	w10, w10, w14
	tbl	v3.16b, {v3.16b}, v30.16b
	add	w11, w11, w15
	tbl	v7.16b, {v7.16b}, v30.16b
	eor	w21, w21, w8
	tbl	v11.16b, {v11.16b}, v30.16b
	eor	w22, w22, w9
	# c += d; b ^= c; b <<<= 7;
	add	v2.4s, v2.4s, v3.4s
	eor	w23, w23, w10
	add	v6.4s, v6.4s, v7.4s
	eor	w24, w24, w11
	add	v10.4s, v10.4s, v11.4s
	ror	w21, w21, #24
	eor	v20.16b, v1.16b, v2.16b
	ror	w22, w22, #24
	eor	v21.16b, v5.16b, v6.16b
	ror	w23, w23, #24
	eor	v22.16b, v9.16b, v10.16b
	ror	w24, w24, #24
	shl	v1.4s, v20.4s, #7
	add	w16, w16, w21
	shl	v5.4s, v21.4s, #7
	add	w17, w17, w22
	shl	v9.4s, v22.4s, #7
	add	w19, w19, w23
	sri	v1.4s, v20.4s, #25
	add	w20, w20, w24
	sri	v5.4s, v21.4s, #25
	eor	w12, w12, w16
	sri	v9.4s, v22.4s, #25
	eor	w13, w13, w17
	ext	v3.16b, v3.16b, v3.16b, #12
	eor	w14, w14, w19
	ext	v7.16b, v7.16b, v7.16b, #12
	eor	w15, w15, w20
	ext	v11.16b, v11.16b, v11.16b, #12
	ror	w12, w12, #25
	ext	v1.16b, v1.16b, v1.16b, #4
	ror	w13, w13, #25
	ext	v5.16b, v5.16b, v5.16b, #4
	ror	w14, w14, #25
	ext	v9.16b, v9.16b, v9.16b, #4
	ror	w15, w15, #25
	ext	v2.16b, v2.16b, v2.16b, #8
	ext	v6.16b, v6.16b, v6.16b, #8
	ext	v10.16b, v10.16b, v10.16b, #8
	# Round even
	# a += b; d ^= a; d <<<= 16;
	add	v0.4s, v0.4s, v1.4s
	add	w8, w8, w13
	add	v4.4s, v4.4s, v5.4s
	add	w9, w9, w14
	add	v8.4s, v8.4s, v9.4s
	add	w10, w10, w15
	eor	v3.16b, v3.16b, v0.16b
	add	w11, w11, w12
	eor	v7.16b, v7.16b, v4.16b
	eor	w24, w24, w8
	eor	v11.16b, v11.16b, v8.16b
	eor	w21, w21, w9
	rev32	v3.8h, v3.8h
	eor	w22, w22, w10
	rev32	v7.8h, v7.8h
	eor	w23, w23, w11
	rev32	v11.8h, v11.8h
	ror	w24, w24, #16
	# c += d; b ^= c; b <<<= 12;
	add	v2.4s, v2.4s, v3.4s
	ror	w21, w21, #16
	add	v6.4s, v6.4s, v7.4s
	ror	w22, w22, #16
	add	v10.4s, v10.4s, v11.4s
	ror	w23, w23, #16
	eor	v20.16b, v1.16b, v2.16b
	add	w19, w19, w24
	eor	v21.16b, v5.16b, v6.16b
	add	w20, w20, w21
	eor	v22.16b, v9.16b, v10.16b
	add	w16, w16, w22
	shl	v1.4s, v20.4s, #12
	add	w17, w17, w23
	shl	v5.4s, v21.4s, #12
	eor	w13, w13, w19
	shl	v9.4s, v22.4s, #12
	eor	w14, w14, w20
	sri	v1.4s, v20.4s, #20
	eor	w15, w15, w16
	sri	v5.4s, v21.4s, #20
	eor	w12, w12, w17
	sri	v9.4s, v22.4s, #20
	ror	w13, w13, #20
	# a += b; d ^= a; d <<<= 8;
	add	v0.4s, v0.4s, v1.4s
	ror	w14, w14, #20
	add	v4.4s, v4.4s, v5.4s
	ror	w15, w15, #20
	add	v8.4s, v8.4s, v9.4s
	ror	w12, w12, #20
	eor	v3.16b, v3.16b, v0.16b
	add	w8, w8, w13
	eor	v7.16b, v7.16b, v4.16b
	add	w9, w9, w14
	eor	v11.16b, v11.16b, v8.16b
	add	w10, w10, w15
	tbl	v3.16b, {v3.16b}, v30.16b
	add	w11, w11, w12
	tbl	v7.16b, {v7.16b}, v30.16b
	eor	w24, w24, w8
	tbl	v11.16b, {v11.16b}, v30.16b
	eor	w21, w21, w9
	# c += d; b ^= c; b <<<= 7;
	add	v2.4s, v2.4s, v3.4s
	eor	w22, w22, w10
	add	v6.4s, v6.4s, v7.4s
	eor	w23, w23, w11
	add	v10.4s, v10.4s, v11.4s
	ror	w24, w24, #24
	eor	v20.16b, v1.16b, v2.16b
	ror	w21, w21, #24
	eor	v21.16b, v5.16b, v6.16b
	ror	w22, w22, #24
	eor	v22.16b, v9.16b, v10.16b
	ror	w23, w23, #24
	shl	v1.4s, v20.4s, #7
	add	w19, w19, w24
	shl	v5.4s, v21.4s, #7
	add	w20, w20, w21
	shl	v9.4s, v22.4s, #7
	add	w16, w16, w22
	sri	v1.4s, v20.4s, #25
	add	w17, w17, w23
	sri	v5.4s, v21.4s, #25
	eor	w13, w13, w19
	sri	v9.4s, v22.4s, #25
	eor	w14, w14, w20
	ext	v3.16b, v3.16b, v3.16b, #4
	eor	w15, w15, w16
	ext	v7.16b, v7.16b, v7.16b, #4
	eor	w12, w12, w17
	ext	v11.16b, v11.16b, v11.16b, #4
	ror	w13, w13, #25
	ext	v1.16b, v1.16b, v1.16b, #12
	ror	w14, w14, #25
	ext	v5.16b, v5.16b, v5.16b, #12
	ror	w15, w15, #25
	ext	v9.16b, v9.16b, v9.16b, #12
	ror	w12, w12, #25
	ext	v2.16b, v2.16b, v2.16b, #8
	ext	v6.16b, v6.16b, v6.16b, #8
	ext	v10.16b, v10.16b, v10.16b, #8
	bne	L_chacha_crypt_bytes_arm64_round_start_256
	# Load message
	ld1	{v20.16b, v21.16b, v22.16b, v23.16b}, [x2], #0x40
	# Add one (2 added during calculating vector results)
	add	w21, w21, #1
	# Add back state, XOR msg, store (load next block)
	add	v0.4s, v0.4s, v16.4s
	add	v1.4s, v1.4s, v17.4s
	add	v2.4s, v2.4s, v18.4s
	add	v3.4s, v3.4s, v19.4s
	eor	v0.16b, v0.16b, v20.16b
	eor	v1.16b, v1.16b, v21.16b
	eor	v2.16b, v2.16b, v22.16b
	eor	v3.16b, v3.16b, v23.16b
	ld1	{v20.16b, v21.16b, v22.16b, v23.16b}, [x2], #0x40
	st1	{v0.4s, v1.4s, v2.4s, v3.4s}, [x1], #0x40
	mov	v19.s[0], w5
	add	v4.4s, v4.4s, v16.4s
	add	v5.4s, v5.4s, v17.4s
	add	v6.4s, v6.4s, v18.4s
	add	v7.4s, v7.4s, v19.4s
	eor	v4.16b, v4.16b, v20.16b
	eor	v5.16b, v5.16b, v21.16b
	eor	v6.16b, v6.16b, v22.16b
	eor	v7.16b, v7.16b, v23.16b
	ld1	{v20.16b, v21.16b, v22.16b, v23.16b}, [x2], #0x40
	st1	{v4.4s, v5.4s, v6.4s, v7.4s}, [x1], #0x40
	mov	v19.s[0], w6
	add	v8.4s, v8.4s, v16.4s
	add	v9.4s, v9.4s, v17.4s
	add	v10.4s, v10.4s, v18.4s
	add	v11.4s, v11.4s, v19.4s
	eor	v8.16b, v8.16b, v20.16b
	eor	v9.16b, v9.16b, v21.16b
	eor	v10.16b, v10.16b, v22.16b
	eor	v11.16b, v11.16b, v23.16b
	ld1	{v20.16b, v21.16b, v22.16b, v23.16b}, [x2], #0x40
	st1	{v8.4s, v9.4s, v10.4s, v11.4s}, [x1], #0x40
	# Move regular registers into vector registers for adding and xor
	orr	x8, x8, x9, lsl 32
	orr	x10, x10, x11, lsl 32
	orr	x12, x12, x13, lsl 32
	mov	v0.d[0], x8
	orr	x14, x14, x15, lsl 32
	mov	v0.d[1], x10
	orr	x16, x16, x17, lsl 32
	mov	v1.d[0], x12
	orr	x19, x19, x20, lsl 32
	mov	v1.d[1], x14
	orr	x21, x21, x22, lsl 32
	mov	v2.d[0], x16
	orr	x23, x23, x24, lsl 32
	mov	v2.d[1], x19
	mov	v3.d[0], x21
	mov	v3.d[1], x23
	# Add back state, XOR in message and store
	add	v0.4s, v0.4s, v16.4s
	add	v1.4s, v1.4s, v17.4s
	add	v2.4s, v2.4s, v18.4s
	add	v3.4s, v3.4s, v19.4s
	eor	v0.16b, v0.16b, v20.16b
	eor	v1.16b, v1.16b, v21.16b
	eor	v2.16b, v2.16b, v22.16b
	eor	v3.16b, v3.16b, v23.16b
	st1	{v0.4s, v1.4s, v2.4s, v3.4s}, [x1], #0x40
	mov	v19.d[0], x7
	sub	x3, x3, #0x100
	# Done 256-byte block
L_chacha_crypt_bytes_arm64_lt_256:
	cmp	x3, #0x80
	blt	L_chacha_crypt_bytes_arm64_lt_128
	ld1	{v24.16b, v25.16b, v26.16b, v27.16b}, [x2], #0x40
	# Move state into vector registers
	mov	v4.16b, v16.16b
	mov	v5.16b, v17.16b
	mov	v6.16b, v18.16b
	mov	v7.16b, v19.16b
	mov	v0.16b, v16.16b
	mov	v1.16b, v17.16b
	mov	v2.16b, v18.16b
	mov	v3.16b, v19.16b
	# Add counter word
	add	v7.4s, v7.4s, v31.4s
	# Set number of odd+even rounds to perform
	mov	x26, #10
L_chacha_crypt_bytes_arm64_round_start_128:
	subs	x26, x26, #1
	# Round odd
	# a += b; d ^= a; d <<<= 16;
	add	v0.4s, v0.4s, v1.4s
	add	v4.4s, v4.4s, v5.4s
	eor	v3.16b, v3.16b, v0.16b
	eor	v7.16b, v7.16b, v4.16b
	rev32	v3.8h, v3.8h
	rev32	v7.8h, v7.8h
	# c += d; b ^= c; b <<<= 12;
	add	v2.4s, v2.4s, v3.4s
	add	v6.4s, v6.4s, v7.4s
	eor	v20.16b, v1.16b, v2.16b
	eor	v21.16b, v5.16b, v6.16b
	shl	v1.4s, v20.4s, #12
	shl	v5.4s, v21.4s, #12
	sri	v1.4s, v20.4s, #20
	sri	v5.4s, v21.4s, #20
	# a += b; d ^= a; d <<<= 8;
	add	v0.4s, v0.4s, v1.4s
	add	v4.4s, v4.4s, v5.4s
	eor	v3.16b, v3.16b, v0.16b
	eor	v7.16b, v7.16b, v4.16b
	tbl	v3.16b, {v3.16b}, v30.16b
	tbl	v7.16b, {v7.16b}, v30.16b
	# c += d; b ^= c; b <<<= 7;
	add	v2.4s, v2.4s, v3.4s
	add	v6.4s, v6.4s, v7.4s
	eor	v20.16b, v1.16b, v2.16b
	eor	v21.16b, v5.16b, v6.16b
	shl	v1.4s, v20.4s, #7
	shl	v5.4s, v21.4s, #7
	sri	v1.4s, v20.4s, #25
	sri	v5.4s, v21.4s, #25
	ext	v3.16b, v3.16b, v3.16b, #12
	ext	v7.16b, v7.16b, v7.16b, #12
	ext	v1.16b, v1.16b, v1.16b, #4
	ext	v5.16b, v5.16b, v5.16b, #4
	ext	v2.16b, v2.16b, v2.16b, #8
	ext	v6.16b, v6.16b, v6.16b, #8
	# Round even
	# a += b; d ^= a; d <<<= 16;
	add	v0.4s, v0.4s, v1.4s
	add	v4.4s, v4.4s, v5.4s
	eor	v3.16b, v3.16b, v0.16b
	eor	v7.16b, v7.16b, v4.16b
	rev32	v3.8h, v3.8h
	rev32	v7.8h, v7.8h
	# c += d; b ^= c; b <<<= 12;
	add	v2.4s, v2.4s, v3.4s
	add	v6.4s, v6.4s, v7.4s
	eor	v20.16b, v1.16b, v2.16b
	eor	v21.16b, v5.16b, v6.16b
	shl	v1.4s, v20.4s, #12
	shl	v5.4s, v21.4s, #12
	sri	v1.4s, v20.4s, #20
	sri	v5.4s, v21.4s, #20
	# a += b; d ^= a; d <<<= 8;
	add	v0.4s, v0.4s, v1.4s
	add	v4.4s, v4.4s, v5.4s
	eor	v3.16b, v3.16b, v0.16b
	eor	v7.16b, v7.16b, v4.16b
	tbl	v3.16b, {v3.16b}, v30.16b
	tbl	v7.16b, {v7.16b}, v30.16b
	# c += d; b ^= c; b <<<= 7;
	add	v2.4s, v2.4s, v3.4s
	add	v6.4s, v6.4s, v7.4s
	eor	v20.16b, v1.16b, v2.16b
	eor	v21.16b, v5.16b, v6.16b
	shl	v1.4s, v20.4s, #7
	shl	v5.4s, v21.4s, #7
	sri	v1.4s, v20.4s, #25
	sri	v5.4s, v21.4s, #25
	ext	v3.16b, v3.16b, v3.16b, #4
	ext	v7.16b, v7.16b, v7.16b, #4
	ext	v1.16b, v1.16b, v1.16b, #12
	ext	v5.16b, v5.16b, v5.16b, #12
	ext	v2.16b, v2.16b, v2.16b, #8
	ext	v6.16b, v6.16b, v6.16b, #8
	bne	L_chacha_crypt_bytes_arm64_round_start_128
	# Add back state, XOR in message and store (load next block)
	add	v0.4s, v0.4s, v16.4s
	add	v1.4s, v1.4s, v17.4s
	add	v2.4s, v2.4s, v18.4s
	add	v3.4s, v3.4s, v19.4s
	eor	v24.16b, v24.16b, v0.16b
	eor	v25.16b, v25.16b, v1.16b
	eor	v26.16b, v26.16b, v2.16b
	eor	v27.16b, v27.16b, v3.16b
	ld1	{v20.16b, v21.16b, v22.16b, v23.16b}, [x2], #0x40
	st1	{v24.16b, v25.16b, v26.16b, v27.16b}, [x1], #0x40
	add	v19.4s, v19.4s, v31.4s
	add	v4.4s, v4.4s, v16.4s
	add	v5.4s, v5.4s, v17.4s
	add	v6.4s, v6.4s, v18.4s
	add	v7.4s, v7.4s, v19.4s
	eor	v20.16b, v20.16b, v4.16b
	eor	v21.16b, v21.16b, v5.16b
	eor	v22.16b, v22.16b, v6.16b
	eor	v23.16b, v23.16b, v7.16b
	st1	{v20.16b, v21.16b, v22.16b, v23.16b}, [x1], #0x40
	add	v19.4s, v19.4s, v31.4s
	sub	x3, x3, #0x80
	# Done 128-byte block
L_chacha_crypt_bytes_arm64_lt_128:
	cmp	x3, #0
	beq	L_chacha_crypt_bytes_arm64_done_all
	mov	w5, #0x40
L_chacha_crypt_bytes_arm64_loop_64:
	# Move state into vector registers
	mov	v0.16b, v16.16b
	mov	v1.16b, v17.16b
	mov	v2.16b, v18.16b
	mov	v3.16b, v19.16b
	# Set number of odd+even rounds to perform
	mov	x26, #10
L_chacha_crypt_bytes_arm64_round_64:
	subs	x26, x26, #1
	# Round odd
	# a += b; d ^= a; d <<<= 16;
	add	v0.4s, v0.4s, v1.4s
	eor	v3.16b, v3.16b, v0.16b
	rev32	v3.8h, v3.8h
	# c += d; b ^= c; b <<<= 12;
	add	v2.4s, v2.4s, v3.4s
	eor	v20.16b, v1.16b, v2.16b
	shl	v1.4s, v20.4s, #12
	sri	v1.4s, v20.4s, #20
	# a += b; d ^= a; d <<<= 8;
	add	v0.4s, v0.4s, v1.4s
	eor	v3.16b, v3.16b, v0.16b
	tbl	v3.16b, {v3.16b}, v30.16b
	# c += d; b ^= c; b <<<= 7;
	add	v2.4s, v2.4s, v3.4s
	eor	v20.16b, v1.16b, v2.16b
	shl	v1.4s, v20.4s, #7
	sri	v1.4s, v20.4s, #25
	ext	v3.16b, v3.16b, v3.16b, #12
	ext	v1.16b, v1.16b, v1.16b, #4
	ext	v2.16b, v2.16b, v2.16b, #8
	# Round even
	# a += b; d ^= a; d <<<= 16;
	add	v0.4s, v0.4s, v1.4s
	eor	v3.16b, v3.16b, v0.16b
	rev32	v3.8h, v3.8h
	# c += d; b ^= c; b <<<= 12;
	add	v2.4s, v2.4s, v3.4s
	eor	v20.16b, v1.16b, v2.16b
	shl	v1.4s, v20.4s, #12
	sri	v1.4s, v20.4s, #20
	# a += b; d ^= a; d <<<= 8;
	add	v0.4s, v0.4s, v1.4s
	eor	v3.16b, v3.16b, v0.16b
	tbl	v3.16b, {v3.16b}, v30.16b
	# c += d; b ^= c; b <<<= 7;
	add	v2.4s, v2.4s, v3.4s
	eor	v20.16b, v1.16b, v2.16b
	shl	v1.4s, v20.4s, #7
	sri	v1.4s, v20.4s, #25
	ext	v3.16b, v3.16b, v3.16b, #4
	ext	v1.16b, v1.16b, v1.16b, #12
	ext	v2.16b, v2.16b, v2.16b, #8
	bne	L_chacha_crypt_bytes_arm64_round_64
	# Add back state
	add	v0.4s, v0.4s, v16.4s
	add	v1.4s, v1.4s, v17.4s
	add	v2.4s, v2.4s, v18.4s
	add	v3.4s, v3.4s, v19.4s
	# Check if data is less than 64 bytes - store in over
	cmp	x3, #0x40
	add	v19.4s, v19.4s, v31.4s
	blt	L_chacha_crypt_bytes_arm64_lt_64
	# Encipher 64 bytes
	ld1	{v24.16b, v25.16b, v26.16b, v27.16b}, [x2], #0x40
	eor	v24.16b, v24.16b, v0.16b
	eor	v25.16b, v25.16b, v1.16b
	eor	v26.16b, v26.16b, v2.16b
	eor	v27.16b, v27.16b, v3.16b
	st1	{v24.16b, v25.16b, v26.16b, v27.16b}, [x1], #0x40
	# Check for more bytes to be enciphered
	subs	x3, x3, #0x40
	bne	L_chacha_crypt_bytes_arm64_loop_64
	b	L_chacha_crypt_bytes_arm64_done
L_chacha_crypt_bytes_arm64_lt_64:
	# Calculate bytes left in block not used
	sub	w5, w5, w3
	# Store encipher block in over for further operations and left
	st1	{v0.4s, v1.4s, v2.4s, v3.4s}, [x4]
	str	w5, [x0, #64]
	# Encipher 32 bytes
	cmp	x3, #32
	blt	L_chacha_crypt_bytes_arm64_lt_32
	ld1	{v24.16b, v25.16b}, [x2], #32
	eor	v24.16b, v24.16b, v0.16b
	eor	v25.16b, v25.16b, v1.16b
	st1	{v24.16b, v25.16b}, [x1], #32
	subs	x3, x3, #32
	mov	v0.16b, v2.16b
	mov	v1.16b, v3.16b
	beq	L_chacha_crypt_bytes_arm64_done
L_chacha_crypt_bytes_arm64_lt_32:
	cmp	x3, #16
	blt	L_chacha_crypt_bytes_arm64_lt_16
	# Encipher 16 bytes
	ld1	{v24.16b}, [x2], #16
	eor	v24.16b, v24.16b, v0.16b
	st1	{v24.16b}, [x1], #16
	subs	x3, x3, #16
	mov	v0.16b, v1.16b
	beq	L_chacha_crypt_bytes_arm64_done
L_chacha_crypt_bytes_arm64_lt_16:
	cmp	x3, #8
	blt	L_chacha_crypt_bytes_arm64_lt_8
	# Encipher 8 bytes
	ld1	{v24.8b}, [x2], #8
	eor	v24.8b, v24.8b, v0.8b
	st1	{v24.8b}, [x1], #8
	subs	x3, x3, #8
	mov	v0.d[0], v0.d[1]
	beq	L_chacha_crypt_bytes_arm64_done
L_chacha_crypt_bytes_arm64_lt_8:
	mov	x5, v0.d[0]
L_chacha_crypt_bytes_arm64loop_lt_8:
	# Encipher 1 byte at a time
	ldrb	w6, [x2], #1
	eor	w6, w6, w5
	strb	w6, [x1], #1
	subs	x3, x3, #1
	lsr	x5, x5, #8
	bgt	L_chacha_crypt_bytes_arm64loop_lt_8
L_chacha_crypt_bytes_arm64_done:
L_chacha_crypt_bytes_arm64_done_all:
	st1	{v16.4s, v17.4s, v18.4s, v19.4s}, [x0]
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
	.size	wc_chacha_crypt_bytes,.-wc_chacha_crypt_bytes
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_chacha_setiv
.type	wc_chacha_setiv,@function
.align	2
wc_chacha_setiv:
#else
.section	__TEXT,__text
.globl	_wc_chacha_setiv
.p2align	2
_wc_chacha_setiv:
#endif /* __APPLE__ */
	ldr	x3, [x1]
	ldr	w4, [x1, #8]
	str	x2, [x0, #48]
	str	x3, [x0, #52]
	str	w4, [x0, #60]
	ret
#ifndef __APPLE__
	.size	wc_chacha_setiv,.-wc_chacha_setiv
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.type	L_chacha_setkey_arm64_constant, %object
	.section	.rodata
	.size	L_chacha_setkey_arm64_constant, 32
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_chacha_setkey_arm64_constant:
	.word	0x61707865
	.word	0x3120646e
	.word	0x79622d36
	.word	0x6b206574
	.word	0x61707865
	.word	0x3320646e
	.word	0x79622d32
	.word	0x6b206574
#ifndef __APPLE__
.text
.globl	wc_chacha_setkey
.type	wc_chacha_setkey,@function
.align	2
wc_chacha_setkey:
#else
.section	__TEXT,__text
.globl	_wc_chacha_setkey
.p2align	2
_wc_chacha_setkey:
#endif /* __APPLE__ */
#ifndef __APPLE__
	adrp x3, L_chacha_setkey_arm64_constant
	add  x3, x3, :lo12:L_chacha_setkey_arm64_constant
#else
	adrp x3, L_chacha_setkey_arm64_constant@PAGE
	add  x3, x3, :lo12:L_chacha_setkey_arm64_constant@PAGEOFF
#endif /* __APPLE__ */
	subs	x2, x2, #16
	add	x3, x3, x2
	# Start with constants
	ld1	{v0.4s}, [x3]
	ld1	{v1.16b}, [x1], #16
#ifdef BIG_ENDIAN_ORDER
	rev32	v1.8h, v1.8h
#endif /* BIG_ENDIAN_ORDER */
	st1	{v0.4s}, [x0], #16
	st1	{v1.4s}, [x0], #16
	beq	L_chacha_setkey_arm64_done
	ld1	{v1.16b}, [x1]
#ifdef BIG_ENDIAN_ORDER
	rev32	v1.8h, v1.8h
#endif /* BIG_ENDIAN_ORDER */
L_chacha_setkey_arm64_done:
	st1	{v1.4s}, [x0]
	ret
#ifndef __APPLE__
	.size	wc_chacha_setkey,.-wc_chacha_setkey
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	wc_chacha_use_over
.type	wc_chacha_use_over,@function
.align	2
wc_chacha_use_over:
#else
.section	__TEXT,__text
.globl	_wc_chacha_use_over
.p2align	2
_wc_chacha_use_over:
#endif /* __APPLE__ */
L_chacha_use_over_arm64_16byte_loop:
	cmp	x3, #16
	blt	L_chacha_use_over_arm64_word_loop
	# 16 bytes of state XORed into message.
	ld1	{v0.16b}, [x0], #16
	ld1	{v1.16b}, [x2], #16
	eor	v1.16b, v1.16b, v0.16b
	subs	x3, x3, #16
	st1	{v1.16b}, [x1], #16
	beq	L_chacha_use_over_arm64_done
	b	L_chacha_use_over_arm64_16byte_loop
L_chacha_use_over_arm64_word_loop:
	cmp	x3, #4
	blt	L_chacha_use_over_arm64_byte_loop
	# 4 bytes of state XORed into message.
	ldr	w4, [x0], #4
	ldr	w5, [x2], #4
	eor	w5, w5, w4
	subs	x3, x3, #4
	str	w5, [x1], #4
	beq	L_chacha_use_over_arm64_done
	b	L_chacha_use_over_arm64_word_loop
L_chacha_use_over_arm64_byte_loop:
	# 1 bytes of state XORed into message.
	ldrb	w4, [x0], #1
	ldrb	w5, [x2], #1
	eor	w5, w5, w4
	subs	x3, x3, #1
	strb	w5, [x1], #1
	beq	L_chacha_use_over_arm64_done
	b	L_chacha_use_over_arm64_byte_loop
L_chacha_use_over_arm64_done:
	ret
#ifndef __APPLE__
	.size	wc_chacha_use_over,.-wc_chacha_use_over
#endif /* __APPLE__ */
#endif /* !WOLFSSL_ARMASM_NO_NEON */
#endif /* HAVE_CHACHA */
#endif /* __aarch64__ */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
