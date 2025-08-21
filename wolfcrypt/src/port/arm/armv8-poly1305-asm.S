/* armv8-poly1305-asm
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
 *   ruby ./poly1305/poly1305.rb arm64 \
 *       ../wolfssl/wolfcrypt/src/port/arm/armv8-poly1305-asm.S
 */
#ifdef WOLFSSL_ARMASM
#ifdef __aarch64__
#ifndef WOLFSSL_ARMASM_INLINE
#ifndef __APPLE__
.text
.globl	poly1305_arm64_block_16
.type	poly1305_arm64_block_16,@function
.align	2
poly1305_arm64_block_16:
#else
.section	__TEXT,__text
.globl	_poly1305_arm64_block_16
.p2align	2
_poly1305_arm64_block_16:
#endif /* __APPLE__ */
	# Load h
	ldp	w2, w3, [x0, #96]
	ldp	w4, w11, [x0, #104]
	ldr	w12, [x0, #112]
	# Load m
	ldr	x14, [x1]
	ldr	x15, [x1, #8]
	# Load r
	ldp	x5, x6, [x0]
	# h: Base26 -> Base 64
	add	x2, x2, x3, lsl 26
	lsr	x3, x4, #12
	add	x2, x2, x4, lsl 52
	add	x3, x3, x11, lsl 14
	lsr	x4, x12, #24
	add	x3, x3, x12, lsl 40
	# Add m and !finished at bit 128
	adds	x2, x2, x14
	adcs	x3, x3, x15
	adc	x4, x4, xzr
	# Multiply h by r
	# b[0] * a[0]
	mul	x7, x5, x2
	umulh	x8, x5, x2
	# b[0] * a[1]
	mul	x10, x5, x3
	umulh	x9, x5, x3
	# b[1] * a[0]
	mul	x11, x6, x2
	umulh	x12, x6, x2
	adds	x8, x8, x10
	# b[1] * a[1]
	mul	x13, x6, x3
	umulh	x10, x6, x3
	adc	x9, x9, x12
	adds	x8, x8, x11
	# b[0] * a[2]
	mul	x11, x5, x4
	adcs	x9, x9, x13
	# b[1] * a[2]
	mul	x12, x6, x4
	adc	x10, x10, xzr
	adds	x9, x9, x11
	adc	x10, x10, x12
	# Reduce mod 2^130 - 5
	# Get high bits
	and	x11, x9, #-4
	# Get top two bits
	and	x9, x9, #3
	# Add top bits * 4
	adds	x2, x7, x11
	# Move down 2 bits
	extr	x11, x10, x11, #2
	adcs	x3, x8, x10
	lsr	x10, x10, #2
	adc	x4, x9, xzr
	# Add top bits.
	adds	x2, x2, x11
	adcs	x3, x3, x10
	adc	x4, x4, xzr
	extr	x12, x4, x3, #40
	ubfx	x4, x2, #52, #12
	ubfx	x11, x3, #14, #26
	bfi	x4, x3, #12, #14
	ubfx	x3, x2, #26, #26
	ubfx	x2, x2, #0, #26
	stp	w2, w3, [x0, #96]
	stp	w4, w11, [x0, #104]
	str	w12, [x0, #112]
	ret
#ifndef __APPLE__
	.size	poly1305_arm64_block_16,.-poly1305_arm64_block_16
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	poly1305_arm64_blocks
.type	poly1305_arm64_blocks,@function
.align	2
poly1305_arm64_blocks:
#else
.section	__TEXT,__text
.globl	_poly1305_arm64_blocks
.p2align	2
_poly1305_arm64_blocks:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-96]!
	add	x29, sp, #0
	str	x17, [x29, #24]
	stp	d8, d9, [x29, #32]
	stp	d10, d11, [x29, #48]
	stp	d12, d13, [x29, #64]
	stp	d14, d15, [x29, #80]
	cmp	x2, #0x40
	blt	L_poly1305_arm64_blocks_done
	# Set mask (0x3ffffff), hi bit and 5 into vector registers
	movi	v25.16b, #0xff
	movi	v27.4s, #1, lsl 24
	ushr	v25.4s, v25.4s, #6
	movi	v24.4s, #5
	uxtl	v26.2d, v25.2s
	add	x14, x0, #16
	ld4	{v15.4s, v16.4s, v17.4s, v18.4s}, [x14], #0x40
	ld1	{v19.4s}, [x14]
	add	x14, x0, #0x60
	movi	v0.4s, #0
	movi	v1.4s, #0
	movi	v2.4s, #0
	movi	v3.4s, #0
	movi	v4.4s, #0
	ld4	{v0.s, v1.s, v2.s, v3.s}[0], [x14], #16
	ld1	{v4.s}[0], [x14]
	mul	v20.4s, v16.4s, v24.4s
	mul	v21.4s, v17.4s, v24.4s
	mul	v22.4s, v18.4s, v24.4s
	mul	v23.4s, v19.4s, v24.4s
L_poly1305_arm64_blocks_loop_64:
	# Load message of 64 bytes - setting hi bit for not finished
	ld4	{v5.4s, v6.4s, v7.4s, v8.4s}, [x1], #0x40
	sub	x2, x2, #0x40
	ushr	v9.4s, v8.4s, #8
	shl	v8.4s, v8.4s, #18
	orr	v9.16b, v9.16b, v27.16b
	sri	v8.4s, v7.4s, #14
	shl	v7.4s, v7.4s, #12
	and	v8.16b, v8.16b, v25.16b
	sri	v7.4s, v6.4s, #20
	shl	v6.4s, v6.4s, #6
	and	v7.16b, v7.16b, v25.16b
	sri	v6.4s, v5.4s, #26
	and	v5.16b, v5.16b, v25.16b
	and	v6.16b, v6.16b, v25.16b
	umull2	v10.2d, v5.4s, v15.4s
	umull2	v11.2d, v5.4s, v16.4s
	umull2	v12.2d, v5.4s, v17.4s
	umull2	v13.2d, v5.4s, v18.4s
	umull2	v14.2d, v5.4s, v19.4s
	umlal2	v10.2d, v6.4s, v23.4s
	umlal2	v11.2d, v6.4s, v15.4s
	umlal2	v12.2d, v6.4s, v16.4s
	umlal2	v13.2d, v6.4s, v17.4s
	umlal2	v14.2d, v6.4s, v18.4s
	umlal2	v10.2d, v7.4s, v22.4s
	umlal2	v11.2d, v7.4s, v23.4s
	umlal2	v12.2d, v7.4s, v15.4s
	umlal2	v13.2d, v7.4s, v16.4s
	umlal2	v14.2d, v7.4s, v17.4s
	umlal2	v10.2d, v8.4s, v21.4s
	umlal2	v11.2d, v8.4s, v22.4s
	umlal2	v12.2d, v8.4s, v23.4s
	umlal2	v13.2d, v8.4s, v15.4s
	umlal2	v14.2d, v8.4s, v16.4s
	umlal2	v10.2d, v9.4s, v20.4s
	umlal2	v11.2d, v9.4s, v21.4s
	umlal2	v12.2d, v9.4s, v22.4s
	umlal2	v13.2d, v9.4s, v23.4s
	umlal2	v14.2d, v9.4s, v15.4s
	add	v5.4s, v5.4s, v0.4s
	add	v6.4s, v6.4s, v1.4s
	add	v7.4s, v7.4s, v2.4s
	add	v8.4s, v8.4s, v3.4s
	add	v9.4s, v9.4s, v4.4s
	umlal	v10.2d, v5.2s, v15.2s
	umlal	v11.2d, v5.2s, v16.2s
	umlal	v12.2d, v5.2s, v17.2s
	umlal	v13.2d, v5.2s, v18.2s
	umlal	v14.2d, v5.2s, v19.2s
	umlal	v10.2d, v6.2s, v23.2s
	umlal	v11.2d, v6.2s, v15.2s
	umlal	v12.2d, v6.2s, v16.2s
	umlal	v13.2d, v6.2s, v17.2s
	umlal	v14.2d, v6.2s, v18.2s
	umlal	v10.2d, v7.2s, v22.2s
	umlal	v11.2d, v7.2s, v23.2s
	umlal	v12.2d, v7.2s, v15.2s
	umlal	v13.2d, v7.2s, v16.2s
	umlal	v14.2d, v7.2s, v17.2s
	umlal	v10.2d, v8.2s, v21.2s
	umlal	v11.2d, v8.2s, v22.2s
	umlal	v12.2d, v8.2s, v23.2s
	umlal	v13.2d, v8.2s, v15.2s
	umlal	v14.2d, v8.2s, v16.2s
	umlal	v10.2d, v9.2s, v20.2s
	umlal	v11.2d, v9.2s, v21.2s
	umlal	v12.2d, v9.2s, v22.2s
	umlal	v13.2d, v9.2s, v23.2s
	umlal	v14.2d, v9.2s, v15.2s
	addp	d10, v10.2d
	addp	d11, v11.2d
	addp	d12, v12.2d
	addp	d13, v13.2d
	addp	d14, v14.2d
	# Redistribute and handle overflow
	usra	v11.2d, v10.2d, #26
	and	v10.16b, v10.16b, v26.16b
	usra	v14.2d, v13.2d, #26
	and	v3.16b, v13.16b, v26.16b
	ushr	v2.2d, v14.2d, #26
	usra	v12.2d, v11.2d, #26
	shl	v0.2d, v2.2d, #2
	and	v1.16b, v11.16b, v26.16b
	add	v0.2d, v0.2d, v2.2d
	and	v4.16b, v14.16b, v26.16b
	add	v10.2d, v10.2d, v0.2d
	usra	v3.2d, v12.2d, #26
	and	v2.16b, v12.16b, v26.16b
	usra	v1.2d, v10.2d, #26
	and	v0.16b, v10.16b, v26.16b
	usra	v4.2d, v3.2d, #26
	and	v3.16b, v3.16b, v26.16b
	cmp	x2, #0x40
	bge	L_poly1305_arm64_blocks_loop_64
	cmp	x2, #16
	ble	L_poly1305_arm64_blocks_done_32
	# Start 32
	ld4	{v5.2s, v6.2s, v7.2s, v8.2s}, [x1], #32
	sub	x2, x2, #32
	mov	v15.d[0], v15.d[1]
	mov	v16.d[0], v16.d[1]
	mov	v17.d[0], v17.d[1]
	mov	v18.d[0], v18.d[1]
	mov	v19.d[0], v19.d[1]
	mov	v20.d[0], v20.d[1]
	mov	v21.d[0], v21.d[1]
	mov	v22.d[0], v22.d[1]
	mov	v23.d[0], v23.d[1]
	ushr	v9.2s, v8.2s, #8
	shl	v8.2s, v8.2s, #18
	orr	v9.8b, v9.8b, v27.8b
	sri	v8.2s, v7.2s, #14
	shl	v7.2s, v7.2s, #12
	and	v8.8b, v8.8b, v25.8b
	sri	v7.2s, v6.2s, #20
	shl	v6.2s, v6.2s, #6
	and	v7.8b, v7.8b, v25.8b
	sri	v6.2s, v5.2s, #26
	and	v5.8b, v5.8b, v25.8b
	and	v6.8b, v6.8b, v25.8b
	add	v5.2s, v5.2s, v0.2s
	add	v6.2s, v6.2s, v1.2s
	add	v7.2s, v7.2s, v2.2s
	add	v8.2s, v8.2s, v3.2s
	add	v9.2s, v9.2s, v4.2s
	umull	v10.2d, v5.2s, v15.2s
	umull	v11.2d, v5.2s, v16.2s
	umull	v12.2d, v5.2s, v17.2s
	umull	v13.2d, v5.2s, v18.2s
	umull	v14.2d, v5.2s, v19.2s
	umlal	v10.2d, v6.2s, v23.2s
	umlal	v11.2d, v6.2s, v15.2s
	umlal	v12.2d, v6.2s, v16.2s
	umlal	v13.2d, v6.2s, v17.2s
	umlal	v14.2d, v6.2s, v18.2s
	umlal	v10.2d, v7.2s, v22.2s
	umlal	v11.2d, v7.2s, v23.2s
	umlal	v12.2d, v7.2s, v15.2s
	umlal	v13.2d, v7.2s, v16.2s
	umlal	v14.2d, v7.2s, v17.2s
	umlal	v10.2d, v8.2s, v21.2s
	umlal	v11.2d, v8.2s, v22.2s
	umlal	v12.2d, v8.2s, v23.2s
	umlal	v13.2d, v8.2s, v15.2s
	umlal	v14.2d, v8.2s, v16.2s
	umlal	v10.2d, v9.2s, v20.2s
	umlal	v11.2d, v9.2s, v21.2s
	umlal	v12.2d, v9.2s, v22.2s
	umlal	v13.2d, v9.2s, v23.2s
	umlal	v14.2d, v9.2s, v15.2s
	addp	d10, v10.2d
	addp	d11, v11.2d
	addp	d12, v12.2d
	addp	d13, v13.2d
	addp	d14, v14.2d
	# Redistribute and handle overflow
	usra	v11.2d, v10.2d, #26
	and	v10.16b, v10.16b, v26.16b
	usra	v14.2d, v13.2d, #26
	and	v3.16b, v13.16b, v26.16b
	ushr	v2.2d, v14.2d, #26
	usra	v12.2d, v11.2d, #26
	shl	v0.2d, v2.2d, #2
	and	v1.16b, v11.16b, v26.16b
	add	v0.2d, v0.2d, v2.2d
	and	v4.16b, v14.16b, v26.16b
	add	v10.2d, v10.2d, v0.2d
	usra	v3.2d, v12.2d, #26
	and	v2.16b, v12.16b, v26.16b
	usra	v1.2d, v10.2d, #26
	and	v0.16b, v10.16b, v26.16b
	usra	v4.2d, v3.2d, #26
	and	v3.16b, v3.16b, v26.16b
L_poly1305_arm64_blocks_done_32:
	cmp	x2, #16
	beq	L_poly1305_arm64_blocks_transfer
	add	x14, x0, #0x60
	st4	{v0.s, v1.s, v2.s, v3.s}[0], [x14], #16
	st1	{v4.s}[0], [x14]
	b	L_poly1305_arm64_blocks_done_all
L_poly1305_arm64_blocks_transfer:
	mov	w3, v0.s[0]
	mov	w4, v1.s[0]
	mov	w5, v2.s[0]
	mov	w6, v3.s[0]
	mov	w7, v4.s[0]
	b	L_poly1305_arm64_blocks_start
L_poly1305_arm64_blocks_done:
	cmp	x2, #16
	blt	L_poly1305_arm64_blocks_done_all
	# Load h
	ldp	w3, w4, [x0, #96]
	ldp	w5, w6, [x0, #104]
	ldr	w7, [x0, #112]
L_poly1305_arm64_blocks_start:
	mov	x17, #1
	# Load r
	ldp	x8, x9, [x0]
	# Base26 -> Base 64
	add	x3, x3, x4, lsl 26
	lsr	x4, x5, #12
	add	x3, x3, x5, lsl 52
	add	x4, x4, x6, lsl 14
	lsr	x5, x7, #24
	add	x4, x4, x7, lsl 40
L_poly1305_arm64_blocks_loop:
	# Load m
	ldr	x14, [x1]
	ldr	x15, [x1, #8]
	# Add m and !finished at bit 128
	adds	x3, x3, x14
	adcs	x4, x4, x15
	adc	x5, x5, x17
	# Multiply h by r
	# b[0] * a[0]
	mul	x10, x8, x3
	umulh	x11, x8, x3
	# b[0] * a[1]
	mul	x13, x8, x4
	umulh	x12, x8, x4
	# b[1] * a[0]
	mul	x14, x9, x3
	umulh	x15, x9, x3
	adds	x11, x11, x13
	# b[1] * a[1]
	mul	x16, x9, x4
	umulh	x13, x9, x4
	adc	x12, x12, x15
	adds	x11, x11, x14
	# b[0] * a[2]
	mul	x14, x8, x5
	adcs	x12, x12, x16
	# b[1] * a[2]
	mul	x15, x9, x5
	adc	x13, x13, xzr
	adds	x12, x12, x14
	adc	x13, x13, x15
	# Reduce mod 2^130 - 5
	# Get high bits
	and	x14, x12, #-4
	# Get top two bits
	and	x12, x12, #3
	# Add top bits * 4
	adds	x3, x10, x14
	# Move down 2 bits
	extr	x14, x13, x14, #2
	adcs	x4, x11, x13
	lsr	x13, x13, #2
	adc	x5, x12, xzr
	# Add top bits.
	adds	x3, x3, x14
	adcs	x4, x4, x13
	adc	x5, x5, xzr
	# Sub 16 from length.
	subs	x2, x2, #16
	add	x1, x1, #16
	# Loop again if more message to do.
	bgt	L_poly1305_arm64_blocks_loop
	extr	x7, x5, x4, #40
	ubfx	x5, x3, #52, #12
	ubfx	x6, x4, #14, #26
	bfi	x5, x4, #12, #14
	ubfx	x4, x3, #26, #26
	ubfx	x3, x3, #0, #26
	stp	w3, w4, [x0, #96]
	stp	w5, w6, [x0, #104]
	str	w7, [x0, #112]
L_poly1305_arm64_blocks_done_all:
	ldr	x17, [x29, #24]
	ldp	d8, d9, [x29, #32]
	ldp	d10, d11, [x29, #48]
	ldp	d12, d13, [x29, #64]
	ldp	d14, d15, [x29, #80]
	ldp	x29, x30, [sp], #0x60
	ret
#ifndef __APPLE__
	.size	poly1305_arm64_blocks,.-poly1305_arm64_blocks
#endif /* __APPLE__ */
#ifndef __APPLE__
	.text
	.type	L_poly1305_set_key_arm64_clamp, %object
	.section	.rodata
	.size	L_poly1305_set_key_arm64_clamp, 16
#else
	.section	__DATA,__data
#endif /* __APPLE__ */
#ifndef __APPLE__
	.align	3
#else
	.p2align	3
#endif /* __APPLE__ */
L_poly1305_set_key_arm64_clamp:
	.word	0x0fffffff
	.word	0x0ffffffc
	.word	0x0ffffffc
	.word	0x0ffffffc
#ifndef __APPLE__
.text
.globl	poly1305_set_key
.type	poly1305_set_key,@function
.align	2
poly1305_set_key:
#else
.section	__TEXT,__text
.globl	_poly1305_set_key
.p2align	2
_poly1305_set_key:
#endif /* __APPLE__ */
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	str	x17, [x29, #24]
#ifndef __APPLE__
	adrp x2, L_poly1305_set_key_arm64_clamp
	add  x2, x2, :lo12:L_poly1305_set_key_arm64_clamp
#else
	adrp x2, L_poly1305_set_key_arm64_clamp@PAGE
	add  x2, x2, :lo12:L_poly1305_set_key_arm64_clamp@PAGEOFF
#endif /* __APPLE__ */
	# Load key and pad.
	ldp	x11, x12, [x1]
	ldp	x14, x15, [x1, #16]
	# Load mask.
	ldp	x16, x17, [x2]
	# Save pad for later
	stp	x14, x15, [x0, #120]
	# Apply clamp.
	# r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
	and	x11, x11, x16
	and	x12, x12, x17
	# Store r - 64-bit version.
	stp	x11, x12, [x0]
	# 128-bits: Base 64 -> Base 26
	lsr	x7, x12, #40
	ubfx	x5, x11, #52, #12
	ubfx	x6, x12, #14, #26
	bfi	x5, x12, #12, #14
	ubfx	x4, x11, #26, #26
	ubfx	x3, x11, #0, #26
	stp	w3, w4, [x0, #64]
	stp	w5, w6, [x0, #72]
	str	w7, [x0, #92]
	# Compute r^2
	# a[0] * a[0]
	mul	x3, x11, x11
	umulh	x4, x11, x11
	# 2 * a[0] * a[1]
	mul	x14, x11, x12
	umulh	x5, x11, x12
	# a[1] * a[1]
	mul	x15, x12, x12
	umulh	x6, x12, x12
	adds	x4, x4, x14, lsl 1
	extr	x5, x5, x14, #63
	adcs	x5, x5, x15
	adc	x6, x6, xzr
	# Reduce mod 2^130 - 5
	# Get high bits
	and	x14, x5, #-4
	# Get top two bits
	and	x5, x5, #3
	# Add top bits * 4
	adds	x8, x3, x14
	# Move down 2 bits
	extr	x14, x6, x14, #2
	adcs	x9, x4, x6
	lsr	x6, x6, #2
	adc	x10, x5, xzr
	# Add top bits.
	adds	x8, x8, x14
	adcs	x9, x9, x6
	adc	x10, x10, xzr
	# 130-bits: Base 64 -> Base 26
	extr	x7, x10, x9, #40
	ubfx	x5, x8, #52, #12
	ubfx	x6, x9, #14, #26
	bfi	x5, x9, #12, #14
	ubfx	x4, x8, #26, #26
	ubfx	x3, x8, #0, #26
	stp	w3, w4, [x0, #48]
	stp	w5, w6, [x0, #56]
	str	w7, [x0, #88]
	# Compute r^3
	# b[0] * a[0]
	mul	x3, x11, x8
	umulh	x4, x11, x8
	# b[0] * a[1]
	mul	x6, x11, x9
	umulh	x5, x11, x9
	# b[1] * a[0]
	mul	x14, x12, x8
	umulh	x15, x12, x8
	adds	x4, x4, x6
	# b[1] * a[1]
	mul	x16, x12, x9
	umulh	x6, x12, x9
	adc	x5, x5, x15
	adds	x4, x4, x14
	# b[0] * a[2]
	mul	x14, x11, x10
	adcs	x5, x5, x16
	# b[1] * a[2]
	mul	x15, x12, x10
	adc	x6, x6, xzr
	adds	x5, x5, x14
	adc	x6, x6, x15
	# Reduce mod 2^130 - 5
	# Get high bits
	and	x14, x5, #-4
	# Get top two bits
	and	x5, x5, #3
	# Add top bits * 4
	adds	x8, x3, x14
	# Move down 2 bits
	extr	x14, x6, x14, #2
	adcs	x9, x4, x6
	lsr	x6, x6, #2
	adc	x10, x5, xzr
	# Add top bits.
	adds	x8, x8, x14
	adcs	x9, x9, x6
	adc	x10, x10, xzr
	# 130-bits: Base 64 -> Base 26
	extr	x7, x10, x9, #40
	ubfx	x5, x8, #52, #12
	ubfx	x6, x9, #14, #26
	bfi	x5, x9, #12, #14
	ubfx	x4, x8, #26, #26
	ubfx	x3, x8, #0, #26
	stp	w3, w4, [x0, #32]
	stp	w5, w6, [x0, #40]
	str	w7, [x0, #84]
	# Compute r^4
	# b[0] * a[0]
	mul	x3, x11, x8
	umulh	x4, x11, x8
	# b[0] * a[1]
	mul	x6, x11, x9
	umulh	x5, x11, x9
	# b[1] * a[0]
	mul	x14, x12, x8
	umulh	x15, x12, x8
	adds	x4, x4, x6
	# b[1] * a[1]
	mul	x16, x12, x9
	umulh	x6, x12, x9
	adc	x5, x5, x15
	adds	x4, x4, x14
	# b[0] * a[2]
	mul	x14, x11, x10
	adcs	x5, x5, x16
	# b[1] * a[2]
	mul	x15, x12, x10
	adc	x6, x6, xzr
	adds	x5, x5, x14
	adc	x6, x6, x15
	# Reduce mod 2^130 - 5
	# Get high bits
	and	x14, x5, #-4
	# Get top two bits
	and	x5, x5, #3
	# Add top bits * 4
	adds	x11, x3, x14
	# Move down 2 bits
	extr	x14, x6, x14, #2
	adcs	x12, x4, x6
	lsr	x6, x6, #2
	adc	x13, x5, xzr
	# Add top bits.
	adds	x11, x11, x14
	adcs	x12, x12, x6
	adc	x13, x13, xzr
	# 130-bits: Base 64 -> Base 26
	extr	x7, x13, x12, #40
	ubfx	x5, x11, #52, #12
	ubfx	x6, x12, #14, #26
	bfi	x5, x12, #12, #14
	ubfx	x4, x11, #26, #26
	ubfx	x3, x11, #0, #26
	stp	w3, w4, [x0, #16]
	stp	w5, w6, [x0, #24]
	str	w7, [x0, #80]
	# h (accumulator) = 0
	stp	xzr, xzr, [x0, #96]
	str	wzr, [x0, #112]
	# Zero leftover
	str	xzr, [x0, #136]
	# Zero finished
	strb	wzr, [x0, #160]
	ldr	x17, [x29, #24]
	ldp	x29, x30, [sp], #32
	ret
#ifndef __APPLE__
	.size	poly1305_set_key,.-poly1305_set_key
#endif /* __APPLE__ */
#ifndef __APPLE__
.text
.globl	poly1305_final
.type	poly1305_final,@function
.align	2
poly1305_final:
#else
.section	__TEXT,__text
.globl	_poly1305_final
.p2align	2
_poly1305_final:
#endif /* __APPLE__ */
	ldp	x8, x9, [x0, #120]
	ldp	w2, w3, [x0, #96]
	ldp	w4, w5, [x0, #104]
	ldr	w6, [x0, #112]
	add	x2, x2, x3, lsl 26
	lsr	x3, x4, #12
	add	x2, x2, x4, lsl 52
	add	x3, x3, x5, lsl 14
	lsr	x4, x6, #24
	add	x3, x3, x6, lsl 40
	# Add 5 to h.
	adds	x5, x2, #5
	adcs	x6, x3, xzr
	adc	x7, x4, xzr
	# Check if h+5 s larger than p.
	cmp	x7, #3
	csel	x2, x5, x2, hi
	csel	x3, x6, x3, hi
	# Add padding
	adds	x2, x2, x8
	adc	x3, x3, x9
	# Store MAC
	stp	x2, x3, [x1]
	# Zero out h.
	stp	xzr, xzr, [x0, #96]
	str	wzr, [x0, #112]
	# Zero out r64.
	stp	xzr, xzr, [x0]
	# Zero out r.
	stp	xzr, xzr, [x0, #16]
	# Zero out r_2.
	stp	xzr, xzr, [x0, #48]
	str	xzr, [x0, #64]
	# Zero out r_4.
	stp	xzr, xzr, [x0, #16]
	str	xzr, [x0, #32]
	# Zero out pad.
	stp	xzr, xzr, [x0, #120]
	ret
#ifndef __APPLE__
	.size	poly1305_final,.-poly1305_final
#endif /* __APPLE__ */
#endif /* __aarch64__ */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
