; /* armv8-poly1305-asm
;  *
;  * Copyright (C) 2006-2026 wolfSSL Inc.
;  *
;  * This file is part of wolfSSL.
;  *
;  * wolfSSL is free software; you can redistribute it and/or modify
;  * it under the terms of the GNU General Public License as published by
;  * the Free Software Foundation; either version 3 of the License, or
;  * (at your option) any later version.
;  *
;  * wolfSSL is distributed in the hope that it will be useful,
;  * but WITHOUT ANY WARRANTY; without even the implied warranty of
;  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;  * GNU General Public License for more details.
;  *
;  * You should have received a copy of the GNU General Public License
;  * along with this program; if not, write to the Free Software
;  * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
;  */


; Generated using (from wolfssl):
;   cd ../scripts
;   ruby ./poly1305/poly1305.rb arm64 \
;       ../wolfssl/wolfcrypt/src/port/arm/armv8-poly1305-asm.asm
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	poly1305_arm64_block_16
poly1305_arm64_block_16 PROC
	; Load h
	ldp	w2, w3, [x0, #96]
	ldp	w4, w11, [x0, #104]
	ldr	w12, [x0, #112]
	; Load m
	ldr	x14, [x1]
	ldr	x15, [x1, #8]
	; Load r
	ldp	x5, x6, [x0]
	; h: Base26 -> Base 64
	add	x2, x2, x3, lsl 26
	lsr	x3, x4, #12
	add	x2, x2, x4, lsl 52
	add	x3, x3, x11, lsl 14
	lsr	x4, x12, #24
	add	x3, x3, x12, lsl 40
	; Add m and !finished at bit 128
	adds	x2, x2, x14
	adcs	x3, x3, x15
	adc	x4, x4, xzr
	; Multiply h by r
	; b[0] * a[0]
	mul	x7, x5, x2
	umulh	x8, x5, x2
	; b[0] * a[1]
	mul	x10, x5, x3
	umulh	x9, x5, x3
	; b[1] * a[0]
	mul	x11, x6, x2
	umulh	x12, x6, x2
	adds	x8, x8, x10
	; b[1] * a[1]
	mul	x13, x6, x3
	umulh	x10, x6, x3
	adc	x9, x9, x12
	adds	x8, x8, x11
	; b[0] * a[2]
	mul	x11, x5, x4
	adcs	x9, x9, x13
	; b[1] * a[2]
	mul	x12, x6, x4
	adc	x10, x10, xzr
	adds	x9, x9, x11
	adc	x10, x10, x12
	; Reduce mod 2^130 - 5
	; Get high bits
	and	x11, x9, #-4
	; Get top two bits
	and	x9, x9, #3
	; Add top bits * 4
	adds	x2, x7, x11
	; Move down 2 bits
	extr	x11, x10, x11, #2
	adcs	x3, x8, x10
	lsr	x10, x10, #2
	adc	x4, x9, xzr
	; Add top bits.
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
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	poly1305_arm64_blocks
poly1305_arm64_blocks PROC
	stp	x29, x30, [sp, #-96]!
	add	x29, sp, #0
	str	x17, [x29, #24]
	stp	D8, D9, [x29, #32]
	stp	D10, D11, [x29, #48]
	stp	D12, D13, [x29, #64]
	stp	D14, D15, [x29, #80]
	cmp	x2, #0x40
	blt	L_poly1305_arm64_blocks_done
	; Set mask (0x3ffffff), hi bit and 5 into vector registers
	movi	V25.16B, #0xff
	movi	V27.4S, #1, lsl 24
	ushr	V25.4S, V25.4S, #6
	movi	V24.4S, #5
	ushll	V26.2D, V25.2S, #0
	add	x14, x0, #16
	ld4	{V15.4S, V16.4S, V17.4S, V18.4S}, [x14], #0x40
	ld1	{V19.4S}, [x14]
	add	x14, x0, #0x60
	movi	V0.4S, #0
	movi	V1.4S, #0
	movi	V2.4S, #0
	movi	V3.4S, #0
	movi	V4.4S, #0
	ld4	{V0.S, V1.S, V2.S, V3.S}[0], [x14], #16
	ld1	{V4.S}[0], [x14]
	mul	V20.4S, V16.4S, V24.4S
	mul	V21.4S, V17.4S, V24.4S
	mul	V22.4S, V18.4S, V24.4S
	mul	V23.4S, V19.4S, V24.4S
L_poly1305_arm64_blocks_loop_64
	; Load message of 64 bytes - setting hi bit for not finished
	ld4	{V5.4S, V6.4S, V7.4S, V8.4S}, [x1], #0x40
	sub	x2, x2, #0x40
	ushr	V9.4S, V8.4S, #8
	shl	V8.4S, V8.4S, #18
	orr	V9.16B, V9.16B, V27.16B
	sri	V8.4S, V7.4S, #14
	shl	V7.4S, V7.4S, #12
	and	V8.16B, V8.16B, V25.16B
	sri	V7.4S, V6.4S, #20
	shl	V6.4S, V6.4S, #6
	and	V7.16B, V7.16B, V25.16B
	sri	V6.4S, V5.4S, #26
	and	V5.16B, V5.16B, V25.16B
	and	V6.16B, V6.16B, V25.16B
	umull2	V10.2D, V5.4S, V15.4S
	umull2	V11.2D, V5.4S, V16.4S
	umull2	V12.2D, V5.4S, V17.4S
	umull2	V13.2D, V5.4S, V18.4S
	umull2	V14.2D, V5.4S, V19.4S
	umlal2	V10.2D, V6.4S, V23.4S
	umlal2	V11.2D, V6.4S, V15.4S
	umlal2	V12.2D, V6.4S, V16.4S
	umlal2	V13.2D, V6.4S, V17.4S
	umlal2	V14.2D, V6.4S, V18.4S
	umlal2	V10.2D, V7.4S, V22.4S
	umlal2	V11.2D, V7.4S, V23.4S
	umlal2	V12.2D, V7.4S, V15.4S
	umlal2	V13.2D, V7.4S, V16.4S
	umlal2	V14.2D, V7.4S, V17.4S
	umlal2	V10.2D, V8.4S, V21.4S
	umlal2	V11.2D, V8.4S, V22.4S
	umlal2	V12.2D, V8.4S, V23.4S
	umlal2	V13.2D, V8.4S, V15.4S
	umlal2	V14.2D, V8.4S, V16.4S
	umlal2	V10.2D, V9.4S, V20.4S
	umlal2	V11.2D, V9.4S, V21.4S
	umlal2	V12.2D, V9.4S, V22.4S
	umlal2	V13.2D, V9.4S, V23.4S
	umlal2	V14.2D, V9.4S, V15.4S
	add	V5.4S, V5.4S, V0.4S
	add	V6.4S, V6.4S, V1.4S
	add	V7.4S, V7.4S, V2.4S
	add	V8.4S, V8.4S, V3.4S
	add	V9.4S, V9.4S, V4.4S
	umlal	V10.2D, V5.2S, V15.2S
	umlal	V11.2D, V5.2S, V16.2S
	umlal	V12.2D, V5.2S, V17.2S
	umlal	V13.2D, V5.2S, V18.2S
	umlal	V14.2D, V5.2S, V19.2S
	umlal	V10.2D, V6.2S, V23.2S
	umlal	V11.2D, V6.2S, V15.2S
	umlal	V12.2D, V6.2S, V16.2S
	umlal	V13.2D, V6.2S, V17.2S
	umlal	V14.2D, V6.2S, V18.2S
	umlal	V10.2D, V7.2S, V22.2S
	umlal	V11.2D, V7.2S, V23.2S
	umlal	V12.2D, V7.2S, V15.2S
	umlal	V13.2D, V7.2S, V16.2S
	umlal	V14.2D, V7.2S, V17.2S
	umlal	V10.2D, V8.2S, V21.2S
	umlal	V11.2D, V8.2S, V22.2S
	umlal	V12.2D, V8.2S, V23.2S
	umlal	V13.2D, V8.2S, V15.2S
	umlal	V14.2D, V8.2S, V16.2S
	umlal	V10.2D, V9.2S, V20.2S
	umlal	V11.2D, V9.2S, V21.2S
	umlal	V12.2D, V9.2S, V22.2S
	umlal	V13.2D, V9.2S, V23.2S
	umlal	V14.2D, V9.2S, V15.2S
	addp	D10, V10.2D
	addp	D11, V11.2D
	addp	D12, V12.2D
	addp	D13, V13.2D
	addp	D14, V14.2D
	; Redistribute and handle overflow
	usra	V11.2D, V10.2D, #26
	and	V10.16B, V10.16B, V26.16B
	usra	V14.2D, V13.2D, #26
	and	V3.16B, V13.16B, V26.16B
	ushr	V2.2D, V14.2D, #26
	usra	V12.2D, V11.2D, #26
	shl	V0.2D, V2.2D, #2
	and	V1.16B, V11.16B, V26.16B
	add	V0.2D, V0.2D, V2.2D
	and	V4.16B, V14.16B, V26.16B
	add	V10.2D, V10.2D, V0.2D
	usra	V3.2D, V12.2D, #26
	and	V2.16B, V12.16B, V26.16B
	usra	V1.2D, V10.2D, #26
	and	V0.16B, V10.16B, V26.16B
	usra	V4.2D, V3.2D, #26
	and	V3.16B, V3.16B, V26.16B
	cmp	x2, #0x40
	bge	L_poly1305_arm64_blocks_loop_64
	cmp	x2, #16
	ble	L_poly1305_arm64_blocks_done_32
	; Start 32
	ld4	{V5.2S, V6.2S, V7.2S, V8.2S}, [x1], #32
	sub	x2, x2, #32
	mov	V15.D[0], V15.D[1]
	mov	V16.D[0], V16.D[1]
	mov	V17.D[0], V17.D[1]
	mov	V18.D[0], V18.D[1]
	mov	V19.D[0], V19.D[1]
	mov	V20.D[0], V20.D[1]
	mov	V21.D[0], V21.D[1]
	mov	V22.D[0], V22.D[1]
	mov	V23.D[0], V23.D[1]
	ushr	V9.2S, V8.2S, #8
	shl	V8.2S, V8.2S, #18
	orr	V9.8B, V9.8B, V27.8B
	sri	V8.2S, V7.2S, #14
	shl	V7.2S, V7.2S, #12
	and	V8.8B, V8.8B, V25.8B
	sri	V7.2S, V6.2S, #20
	shl	V6.2S, V6.2S, #6
	and	V7.8B, V7.8B, V25.8B
	sri	V6.2S, V5.2S, #26
	and	V5.8B, V5.8B, V25.8B
	and	V6.8B, V6.8B, V25.8B
	add	V5.2S, V5.2S, V0.2S
	add	V6.2S, V6.2S, V1.2S
	add	V7.2S, V7.2S, V2.2S
	add	V8.2S, V8.2S, V3.2S
	add	V9.2S, V9.2S, V4.2S
	umull	V10.2D, V5.2S, V15.2S
	umull	V11.2D, V5.2S, V16.2S
	umull	V12.2D, V5.2S, V17.2S
	umull	V13.2D, V5.2S, V18.2S
	umull	V14.2D, V5.2S, V19.2S
	umlal	V10.2D, V6.2S, V23.2S
	umlal	V11.2D, V6.2S, V15.2S
	umlal	V12.2D, V6.2S, V16.2S
	umlal	V13.2D, V6.2S, V17.2S
	umlal	V14.2D, V6.2S, V18.2S
	umlal	V10.2D, V7.2S, V22.2S
	umlal	V11.2D, V7.2S, V23.2S
	umlal	V12.2D, V7.2S, V15.2S
	umlal	V13.2D, V7.2S, V16.2S
	umlal	V14.2D, V7.2S, V17.2S
	umlal	V10.2D, V8.2S, V21.2S
	umlal	V11.2D, V8.2S, V22.2S
	umlal	V12.2D, V8.2S, V23.2S
	umlal	V13.2D, V8.2S, V15.2S
	umlal	V14.2D, V8.2S, V16.2S
	umlal	V10.2D, V9.2S, V20.2S
	umlal	V11.2D, V9.2S, V21.2S
	umlal	V12.2D, V9.2S, V22.2S
	umlal	V13.2D, V9.2S, V23.2S
	umlal	V14.2D, V9.2S, V15.2S
	addp	D10, V10.2D
	addp	D11, V11.2D
	addp	D12, V12.2D
	addp	D13, V13.2D
	addp	D14, V14.2D
	; Redistribute and handle overflow
	usra	V11.2D, V10.2D, #26
	and	V10.16B, V10.16B, V26.16B
	usra	V14.2D, V13.2D, #26
	and	V3.16B, V13.16B, V26.16B
	ushr	V2.2D, V14.2D, #26
	usra	V12.2D, V11.2D, #26
	shl	V0.2D, V2.2D, #2
	and	V1.16B, V11.16B, V26.16B
	add	V0.2D, V0.2D, V2.2D
	and	V4.16B, V14.16B, V26.16B
	add	V10.2D, V10.2D, V0.2D
	usra	V3.2D, V12.2D, #26
	and	V2.16B, V12.16B, V26.16B
	usra	V1.2D, V10.2D, #26
	and	V0.16B, V10.16B, V26.16B
	usra	V4.2D, V3.2D, #26
	and	V3.16B, V3.16B, V26.16B
L_poly1305_arm64_blocks_done_32
	cmp	x2, #16
	beq	L_poly1305_arm64_blocks_transfer
	add	x14, x0, #0x60
	st4	{V0.S, V1.S, V2.S, V3.S}[0], [x14], #16
	st1	{V4.S}[0], [x14]
	b	L_poly1305_arm64_blocks_done_all
L_poly1305_arm64_blocks_transfer
	mov	w3, V0.S[0]
	mov	w4, V1.S[0]
	mov	w5, V2.S[0]
	mov	w6, V3.S[0]
	mov	w7, V4.S[0]
	b	L_poly1305_arm64_blocks_start
L_poly1305_arm64_blocks_done
	cmp	x2, #16
	blt	L_poly1305_arm64_blocks_done_all
	; Load h
	ldp	w3, w4, [x0, #96]
	ldp	w5, w6, [x0, #104]
	ldr	w7, [x0, #112]
L_poly1305_arm64_blocks_start
	mov	x17, #1
	; Load r
	ldp	x8, x9, [x0]
	; Base26 -> Base 64
	add	x3, x3, x4, lsl 26
	lsr	x4, x5, #12
	add	x3, x3, x5, lsl 52
	add	x4, x4, x6, lsl 14
	lsr	x5, x7, #24
	add	x4, x4, x7, lsl 40
L_poly1305_arm64_blocks_loop
	; Load m
	ldr	x14, [x1]
	ldr	x15, [x1, #8]
	; Add m and !finished at bit 128
	adds	x3, x3, x14
	adcs	x4, x4, x15
	adc	x5, x5, x17
	; Multiply h by r
	; b[0] * a[0]
	mul	x10, x8, x3
	umulh	x11, x8, x3
	; b[0] * a[1]
	mul	x13, x8, x4
	umulh	x12, x8, x4
	; b[1] * a[0]
	mul	x14, x9, x3
	umulh	x15, x9, x3
	adds	x11, x11, x13
	; b[1] * a[1]
	mul	x16, x9, x4
	umulh	x13, x9, x4
	adc	x12, x12, x15
	adds	x11, x11, x14
	; b[0] * a[2]
	mul	x14, x8, x5
	adcs	x12, x12, x16
	; b[1] * a[2]
	mul	x15, x9, x5
	adc	x13, x13, xzr
	adds	x12, x12, x14
	adc	x13, x13, x15
	; Reduce mod 2^130 - 5
	; Get high bits
	and	x14, x12, #-4
	; Get top two bits
	and	x12, x12, #3
	; Add top bits * 4
	adds	x3, x10, x14
	; Move down 2 bits
	extr	x14, x13, x14, #2
	adcs	x4, x11, x13
	lsr	x13, x13, #2
	adc	x5, x12, xzr
	; Add top bits.
	adds	x3, x3, x14
	adcs	x4, x4, x13
	adc	x5, x5, xzr
	; Sub 16 from length.
	subs	x2, x2, #16
	add	x1, x1, #16
	; Loop again if more message to do.
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
L_poly1305_arm64_blocks_done_all
	ldr	x17, [x29, #24]
	ldp	D8, D9, [x29, #32]
	ldp	D10, D11, [x29, #48]
	ldp	D12, D13, [x29, #64]
	ldp	D14, D15, [x29, #80]
	ldp	x29, x30, [sp], #0x60
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_poly1305_set_key_arm64_clamp
	DCD	0x0fffffff, 0x0ffffffc, 0x0ffffffc, 0x0ffffffc
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	poly1305_set_key
poly1305_set_key PROC
	stp	x29, x30, [sp, #-32]!
	add	x29, sp, #0
	str	x17, [x29, #24]
	adrp	x2, L_poly1305_set_key_arm64_clamp
	add	x2, x2, L_poly1305_set_key_arm64_clamp
	; Load key and pad.
	ldp	x11, x12, [x1]
	ldp	x14, x15, [x1, #16]
	; Load mask.
	ldp	x16, x17, [x2]
	; Save pad for later
	stp	x14, x15, [x0, #120]
	; Apply clamp.
	; r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
	and	x11, x11, x16
	and	x12, x12, x17
	; Store r - 64-bit version.
	stp	x11, x12, [x0]
	; 128-bits: Base 64 -> Base 26
	lsr	x7, x12, #40
	ubfx	x5, x11, #52, #12
	ubfx	x6, x12, #14, #26
	bfi	x5, x12, #12, #14
	ubfx	x4, x11, #26, #26
	ubfx	x3, x11, #0, #26
	stp	w3, w4, [x0, #64]
	stp	w5, w6, [x0, #72]
	str	w7, [x0, #92]
	; Compute r^2
	; a[0] * a[0]
	mul	x3, x11, x11
	umulh	x4, x11, x11
	; 2 * a[0] * a[1]
	mul	x14, x11, x12
	umulh	x5, x11, x12
	; a[1] * a[1]
	mul	x15, x12, x12
	umulh	x6, x12, x12
	adds	x4, x4, x14, lsl 1
	extr	x5, x5, x14, #63
	adcs	x5, x5, x15
	adc	x6, x6, xzr
	; Reduce mod 2^130 - 5
	; Get high bits
	and	x14, x5, #-4
	; Get top two bits
	and	x5, x5, #3
	; Add top bits * 4
	adds	x8, x3, x14
	; Move down 2 bits
	extr	x14, x6, x14, #2
	adcs	x9, x4, x6
	lsr	x6, x6, #2
	adc	x10, x5, xzr
	; Add top bits.
	adds	x8, x8, x14
	adcs	x9, x9, x6
	adc	x10, x10, xzr
	; 130-bits: Base 64 -> Base 26
	extr	x7, x10, x9, #40
	ubfx	x5, x8, #52, #12
	ubfx	x6, x9, #14, #26
	bfi	x5, x9, #12, #14
	ubfx	x4, x8, #26, #26
	ubfx	x3, x8, #0, #26
	stp	w3, w4, [x0, #48]
	stp	w5, w6, [x0, #56]
	str	w7, [x0, #88]
	; Compute r^3
	; b[0] * a[0]
	mul	x3, x11, x8
	umulh	x4, x11, x8
	; b[0] * a[1]
	mul	x6, x11, x9
	umulh	x5, x11, x9
	; b[1] * a[0]
	mul	x14, x12, x8
	umulh	x15, x12, x8
	adds	x4, x4, x6
	; b[1] * a[1]
	mul	x16, x12, x9
	umulh	x6, x12, x9
	adc	x5, x5, x15
	adds	x4, x4, x14
	; b[0] * a[2]
	mul	x14, x11, x10
	adcs	x5, x5, x16
	; b[1] * a[2]
	mul	x15, x12, x10
	adc	x6, x6, xzr
	adds	x5, x5, x14
	adc	x6, x6, x15
	; Reduce mod 2^130 - 5
	; Get high bits
	and	x14, x5, #-4
	; Get top two bits
	and	x5, x5, #3
	; Add top bits * 4
	adds	x8, x3, x14
	; Move down 2 bits
	extr	x14, x6, x14, #2
	adcs	x9, x4, x6
	lsr	x6, x6, #2
	adc	x10, x5, xzr
	; Add top bits.
	adds	x8, x8, x14
	adcs	x9, x9, x6
	adc	x10, x10, xzr
	; 130-bits: Base 64 -> Base 26
	extr	x7, x10, x9, #40
	ubfx	x5, x8, #52, #12
	ubfx	x6, x9, #14, #26
	bfi	x5, x9, #12, #14
	ubfx	x4, x8, #26, #26
	ubfx	x3, x8, #0, #26
	stp	w3, w4, [x0, #32]
	stp	w5, w6, [x0, #40]
	str	w7, [x0, #84]
	; Compute r^4
	; b[0] * a[0]
	mul	x3, x11, x8
	umulh	x4, x11, x8
	; b[0] * a[1]
	mul	x6, x11, x9
	umulh	x5, x11, x9
	; b[1] * a[0]
	mul	x14, x12, x8
	umulh	x15, x12, x8
	adds	x4, x4, x6
	; b[1] * a[1]
	mul	x16, x12, x9
	umulh	x6, x12, x9
	adc	x5, x5, x15
	adds	x4, x4, x14
	; b[0] * a[2]
	mul	x14, x11, x10
	adcs	x5, x5, x16
	; b[1] * a[2]
	mul	x15, x12, x10
	adc	x6, x6, xzr
	adds	x5, x5, x14
	adc	x6, x6, x15
	; Reduce mod 2^130 - 5
	; Get high bits
	and	x14, x5, #-4
	; Get top two bits
	and	x5, x5, #3
	; Add top bits * 4
	adds	x11, x3, x14
	; Move down 2 bits
	extr	x14, x6, x14, #2
	adcs	x12, x4, x6
	lsr	x6, x6, #2
	adc	x13, x5, xzr
	; Add top bits.
	adds	x11, x11, x14
	adcs	x12, x12, x6
	adc	x13, x13, xzr
	; 130-bits: Base 64 -> Base 26
	extr	x7, x13, x12, #40
	ubfx	x5, x11, #52, #12
	ubfx	x6, x12, #14, #26
	bfi	x5, x12, #12, #14
	ubfx	x4, x11, #26, #26
	ubfx	x3, x11, #0, #26
	stp	w3, w4, [x0, #16]
	stp	w5, w6, [x0, #24]
	str	w7, [x0, #80]
	; h (accumulator) = 0
	stp	xzr, xzr, [x0, #96]
	str	wzr, [x0, #112]
	; Zero leftover
	str	xzr, [x0, #136]
	; Zero finished
	strb	wzr, [x0, #160]
	ldr	x17, [x29, #24]
	ldp	x29, x30, [sp], #32
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	poly1305_final
poly1305_final PROC
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
	; Add 5 to h.
	adds	x5, x2, #5
	adcs	x6, x3, xzr
	adc	x7, x4, xzr
	; Check if h+5 s larger than p.
	cmp	x7, #3
	csel	x2, x5, x2, hi
	csel	x3, x6, x3, hi
	; Add padding
	adds	x2, x2, x8
	adc	x3, x3, x9
	; Store MAC
	stp	x2, x3, [x1]
	; Zero out h.
	stp	xzr, xzr, [x0, #96]
	str	wzr, [x0, #112]
	; Zero out r64.
	stp	xzr, xzr, [x0]
	; Zero out r.
	stp	xzr, xzr, [x0, #16]
	; Zero out r_2.
	stp	xzr, xzr, [x0, #48]
	str	xzr, [x0, #64]
	; Zero out r_4.
	stp	xzr, xzr, [x0, #16]
	str	xzr, [x0, #32]
	; Zero out pad.
	stp	xzr, xzr, [x0, #120]
	ret
	ENDP
	END
