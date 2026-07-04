; /* armv8-chacha-asm
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
;   ruby ./chacha/chacha.rb arm64 \
;       ../wolfssl/wolfcrypt/src/port/arm/armv8-chacha-asm.asm
	IF :DEF:HAVE_CHACHA
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_chacha20_arm64_ctr
	DCD	0x00000000, 0x00000001, 0x00000002, 0x00000003
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_chacha20_arm64_rol8
	DCD	0x02010003, 0x06050407, 0x0a09080b, 0x0e0d0c0f
	IF :LNOT::DEF:WOLFSSL_ARMASM_NO_NEON
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	wc_chacha_crypt_bytes
wc_chacha_crypt_bytes PROC
	stp	x29, x30, [sp, #-160]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #24]
	stp	x20, x21, [x29, #40]
	stp	x22, x23, [x29, #56]
	stp	x24, x25, [x29, #72]
	str	x26, [x29, #88]
	stp	D8, D9, [x29, #96]
	stp	D10, D11, [x29, #112]
	stp	D12, D13, [x29, #128]
	stp	D14, D15, [x29, #144]
	adrp	x5, L_chacha20_arm64_rol8
	add	x5, x5, L_chacha20_arm64_rol8
	adrp	x6, L_chacha20_arm64_ctr
	add	x6, x6, L_chacha20_arm64_ctr
	eor	V29.16B, V29.16B, V29.16B
	mov	x26, #5
	eor	V31.16B, V31.16B, V31.16B
	mov	w7, #1
	ld1	{V30.16B}, [x5]
	ld1	{V28.4S}, [x6]
	add	x4, x0, #0x44
	mov	V29.S[0], w26
	mov	V31.S[0], w7
	; Load state to encrypt
	ld1	{V16.4S, V17.4S, V18.4S, V19.4S}, [x0]
	cmp	x3, #0x140
	blt	L_chacha_crypt_bytes_arm64_lt_320
	mov	w25, #4
L_chacha_crypt_bytes_arm64_loop_320
	; Move state into regular register
	mov	x8, V16.D[0]
	mov	x10, V16.D[1]
	mov	x12, V17.D[0]
	mov	x14, V17.D[1]
	mov	x16, V18.D[0]
	mov	x19, V18.D[1]
	mov	x21, V19.D[0]
	mov	x23, V19.D[1]
	sub	x3, x3, #0x140
	; Move state into vector registers
	dup	V0.4S, V16.S[0]
	dup	V1.4S, V16.S[1]
	lsr	x9, x8, #32
	dup	V2.4S, V16.S[2]
	dup	V3.4S, V16.S[3]
	lsr	x11, x10, #32
	dup	V4.4S, V17.S[0]
	dup	V5.4S, V17.S[1]
	lsr	x13, x12, #32
	dup	V6.4S, V17.S[2]
	dup	V7.4S, V17.S[3]
	lsr	x15, x14, #32
	dup	V8.4S, V18.S[0]
	dup	V9.4S, V18.S[1]
	lsr	x17, x16, #32
	dup	V10.4S, V18.S[2]
	dup	V11.4S, V18.S[3]
	lsr	x20, x19, #32
	dup	V12.4S, V19.S[0]
	dup	V13.4S, V19.S[1]
	lsr	x22, x21, #32
	dup	V14.4S, V19.S[2]
	dup	V15.4S, V19.S[3]
	lsr	x24, x23, #32
	; Add to counter word
	add	V12.4S, V12.4S, V28.4S
	add	w21, w21, w25
	; Set number of odd+even rounds to perform
	mov	x26, #10
L_chacha_crypt_bytes_arm64_round_start_320
	subs	x26, x26, #1
	; Round odd
	; a += b; d ^= a; d <<<= 16;
	add	V0.4S, V0.4S, V4.4S
	add	w8, w8, w12
	add	V1.4S, V1.4S, V5.4S
	add	w9, w9, w13
	add	V2.4S, V2.4S, V6.4S
	add	w10, w10, w14
	add	V3.4S, V3.4S, V7.4S
	add	w11, w11, w15
	eor	V12.16B, V12.16B, V0.16B
	eor	w21, w21, w8
	eor	V13.16B, V13.16B, V1.16B
	eor	w22, w22, w9
	eor	V14.16B, V14.16B, V2.16B
	eor	w23, w23, w10
	eor	V15.16B, V15.16B, V3.16B
	eor	w24, w24, w11
	rev32	V12.8H, V12.8H
	ror	w21, w21, #16
	rev32	V13.8H, V13.8H
	ror	w22, w22, #16
	rev32	V14.8H, V14.8H
	ror	w23, w23, #16
	rev32	V15.8H, V15.8H
	ror	w24, w24, #16
	; c += d; b ^= c; b <<<= 12;
	add	V8.4S, V8.4S, V12.4S
	add	w16, w16, w21
	add	V9.4S, V9.4S, V13.4S
	add	w17, w17, w22
	add	V10.4S, V10.4S, V14.4S
	add	w19, w19, w23
	add	V11.4S, V11.4S, V15.4S
	add	w20, w20, w24
	eor	V20.16B, V4.16B, V8.16B
	eor	w12, w12, w16
	eor	V21.16B, V5.16B, V9.16B
	eor	w13, w13, w17
	eor	V22.16B, V6.16B, V10.16B
	eor	w14, w14, w19
	eor	V23.16B, V7.16B, V11.16B
	eor	w15, w15, w20
	shl	V4.4S, V20.4S, #12
	ror	w12, w12, #20
	shl	V5.4S, V21.4S, #12
	ror	w13, w13, #20
	shl	V6.4S, V22.4S, #12
	ror	w14, w14, #20
	shl	V7.4S, V23.4S, #12
	ror	w15, w15, #20
	sri	V4.4S, V20.4S, #20
	sri	V5.4S, V21.4S, #20
	sri	V6.4S, V22.4S, #20
	sri	V7.4S, V23.4S, #20
	; a += b; d ^= a; d <<<= 8;
	add	V0.4S, V0.4S, V4.4S
	add	w8, w8, w12
	add	V1.4S, V1.4S, V5.4S
	add	w9, w9, w13
	add	V2.4S, V2.4S, V6.4S
	add	w10, w10, w14
	add	V3.4S, V3.4S, V7.4S
	add	w11, w11, w15
	eor	V12.16B, V12.16B, V0.16B
	eor	w21, w21, w8
	eor	V13.16B, V13.16B, V1.16B
	eor	w22, w22, w9
	eor	V14.16B, V14.16B, V2.16B
	eor	w23, w23, w10
	eor	V15.16B, V15.16B, V3.16B
	eor	w24, w24, w11
	tbl	V12.16B, {V12.16B}, V30.16B
	ror	w21, w21, #24
	tbl	V13.16B, {V13.16B}, V30.16B
	ror	w22, w22, #24
	tbl	V14.16B, {V14.16B}, V30.16B
	ror	w23, w23, #24
	tbl	V15.16B, {V15.16B}, V30.16B
	ror	w24, w24, #24
	; c += d; b ^= c; b <<<= 7;
	add	V8.4S, V8.4S, V12.4S
	add	w16, w16, w21
	add	V9.4S, V9.4S, V13.4S
	add	w17, w17, w22
	add	V10.4S, V10.4S, V14.4S
	add	w19, w19, w23
	add	V11.4S, V11.4S, V15.4S
	add	w20, w20, w24
	eor	V20.16B, V4.16B, V8.16B
	eor	w12, w12, w16
	eor	V21.16B, V5.16B, V9.16B
	eor	w13, w13, w17
	eor	V22.16B, V6.16B, V10.16B
	eor	w14, w14, w19
	eor	V23.16B, V7.16B, V11.16B
	eor	w15, w15, w20
	shl	V4.4S, V20.4S, #7
	ror	w12, w12, #25
	shl	V5.4S, V21.4S, #7
	ror	w13, w13, #25
	shl	V6.4S, V22.4S, #7
	ror	w14, w14, #25
	shl	V7.4S, V23.4S, #7
	ror	w15, w15, #25
	sri	V4.4S, V20.4S, #25
	sri	V5.4S, V21.4S, #25
	sri	V6.4S, V22.4S, #25
	sri	V7.4S, V23.4S, #25
	; Round even
	; a += b; d ^= a; d <<<= 16;
	add	V0.4S, V0.4S, V5.4S
	add	w8, w8, w13
	add	V1.4S, V1.4S, V6.4S
	add	w9, w9, w14
	add	V2.4S, V2.4S, V7.4S
	add	w10, w10, w15
	add	V3.4S, V3.4S, V4.4S
	add	w11, w11, w12
	eor	V15.16B, V15.16B, V0.16B
	eor	w24, w24, w8
	eor	V12.16B, V12.16B, V1.16B
	eor	w21, w21, w9
	eor	V13.16B, V13.16B, V2.16B
	eor	w22, w22, w10
	eor	V14.16B, V14.16B, V3.16B
	eor	w23, w23, w11
	rev32	V15.8H, V15.8H
	ror	w24, w24, #16
	rev32	V12.8H, V12.8H
	ror	w21, w21, #16
	rev32	V13.8H, V13.8H
	ror	w22, w22, #16
	rev32	V14.8H, V14.8H
	ror	w23, w23, #16
	; c += d; b ^= c; b <<<= 12;
	add	V10.4S, V10.4S, V15.4S
	add	w19, w19, w24
	add	V11.4S, V11.4S, V12.4S
	add	w20, w20, w21
	add	V8.4S, V8.4S, V13.4S
	add	w16, w16, w22
	add	V9.4S, V9.4S, V14.4S
	add	w17, w17, w23
	eor	V20.16B, V5.16B, V10.16B
	eor	w13, w13, w19
	eor	V21.16B, V6.16B, V11.16B
	eor	w14, w14, w20
	eor	V22.16B, V7.16B, V8.16B
	eor	w15, w15, w16
	eor	V23.16B, V4.16B, V9.16B
	eor	w12, w12, w17
	shl	V5.4S, V20.4S, #12
	ror	w13, w13, #20
	shl	V6.4S, V21.4S, #12
	ror	w14, w14, #20
	shl	V7.4S, V22.4S, #12
	ror	w15, w15, #20
	shl	V4.4S, V23.4S, #12
	ror	w12, w12, #20
	sri	V5.4S, V20.4S, #20
	sri	V6.4S, V21.4S, #20
	sri	V7.4S, V22.4S, #20
	sri	V4.4S, V23.4S, #20
	; a += b; d ^= a; d <<<= 8;
	add	V0.4S, V0.4S, V5.4S
	add	w8, w8, w13
	add	V1.4S, V1.4S, V6.4S
	add	w9, w9, w14
	add	V2.4S, V2.4S, V7.4S
	add	w10, w10, w15
	add	V3.4S, V3.4S, V4.4S
	add	w11, w11, w12
	eor	V15.16B, V15.16B, V0.16B
	eor	w24, w24, w8
	eor	V12.16B, V12.16B, V1.16B
	eor	w21, w21, w9
	eor	V13.16B, V13.16B, V2.16B
	eor	w22, w22, w10
	eor	V14.16B, V14.16B, V3.16B
	eor	w23, w23, w11
	tbl	V15.16B, {V15.16B}, V30.16B
	ror	w24, w24, #24
	tbl	V12.16B, {V12.16B}, V30.16B
	ror	w21, w21, #24
	tbl	V13.16B, {V13.16B}, V30.16B
	ror	w22, w22, #24
	tbl	V14.16B, {V14.16B}, V30.16B
	ror	w23, w23, #24
	; c += d; b ^= c; b <<<= 7;
	add	V10.4S, V10.4S, V15.4S
	add	w19, w19, w24
	add	V11.4S, V11.4S, V12.4S
	add	w20, w20, w21
	add	V8.4S, V8.4S, V13.4S
	add	w16, w16, w22
	add	V9.4S, V9.4S, V14.4S
	add	w17, w17, w23
	eor	V20.16B, V5.16B, V10.16B
	eor	w13, w13, w19
	eor	V21.16B, V6.16B, V11.16B
	eor	w14, w14, w20
	eor	V22.16B, V7.16B, V8.16B
	eor	w15, w15, w16
	eor	V23.16B, V4.16B, V9.16B
	eor	w12, w12, w17
	shl	V5.4S, V20.4S, #7
	ror	w13, w13, #25
	shl	V6.4S, V21.4S, #7
	ror	w14, w14, #25
	shl	V7.4S, V22.4S, #7
	ror	w15, w15, #25
	shl	V4.4S, V23.4S, #7
	ror	w12, w12, #25
	sri	V5.4S, V20.4S, #25
	sri	V6.4S, V21.4S, #25
	sri	V7.4S, V22.4S, #25
	sri	V4.4S, V23.4S, #25
	bne	L_chacha_crypt_bytes_arm64_round_start_320
	; Add counter now rather than after transposed
	add	V12.4S, V12.4S, V28.4S
	add	w21, w21, w25
	; Load message
	ld1	{V24.16B, V25.16B, V26.16B, V27.16B}, [x2], #0x40
	; Transpose vectors
	trn1	V20.4S, V0.4S, V1.4S
	trn1	V22.4S, V2.4S, V3.4S
	orr	x8, x8, x9, lsl 32
	trn2	V21.4S, V0.4S, V1.4S
	trn2	V23.4S, V2.4S, V3.4S
	trn1	V0.2D, V20.2D, V22.2D
	trn1	V1.2D, V21.2D, V23.2D
	orr	x10, x10, x11, lsl 32
	trn2	V2.2D, V20.2D, V22.2D
	trn2	V3.2D, V21.2D, V23.2D
	trn1	V20.4S, V4.4S, V5.4S
	trn1	V22.4S, V6.4S, V7.4S
	orr	x12, x12, x13, lsl 32
	trn2	V21.4S, V4.4S, V5.4S
	trn2	V23.4S, V6.4S, V7.4S
	trn1	V4.2D, V20.2D, V22.2D
	trn1	V5.2D, V21.2D, V23.2D
	orr	x14, x14, x15, lsl 32
	trn2	V6.2D, V20.2D, V22.2D
	trn2	V7.2D, V21.2D, V23.2D
	trn1	V20.4S, V8.4S, V9.4S
	trn1	V22.4S, V10.4S, V11.4S
	orr	x16, x16, x17, lsl 32
	trn2	V21.4S, V8.4S, V9.4S
	trn2	V23.4S, V10.4S, V11.4S
	trn1	V8.2D, V20.2D, V22.2D
	trn1	V9.2D, V21.2D, V23.2D
	orr	x19, x19, x20, lsl 32
	trn2	V10.2D, V20.2D, V22.2D
	trn2	V11.2D, V21.2D, V23.2D
	trn1	V20.4S, V12.4S, V13.4S
	trn1	V22.4S, V14.4S, V15.4S
	orr	x21, x21, x22, lsl 32
	trn2	V21.4S, V12.4S, V13.4S
	trn2	V23.4S, V14.4S, V15.4S
	trn1	V12.2D, V20.2D, V22.2D
	trn1	V13.2D, V21.2D, V23.2D
	orr	x23, x23, x24, lsl 32
	trn2	V14.2D, V20.2D, V22.2D
	trn2	V15.2D, V21.2D, V23.2D
	; Add back state, XOR in message and store (load next block)
	add	V20.4S, V0.4S, V16.4S
	add	V21.4S, V4.4S, V17.4S
	add	V22.4S, V8.4S, V18.4S
	add	V23.4S, V12.4S, V19.4S
	eor	V20.16B, V20.16B, V24.16B
	eor	V21.16B, V21.16B, V25.16B
	eor	V22.16B, V22.16B, V26.16B
	eor	V23.16B, V23.16B, V27.16B
	ld1	{V24.16B, V25.16B, V26.16B, V27.16B}, [x2], #0x40
	st1	{V20.16B, V21.16B, V22.16B, V23.16B}, [x1], #0x40
	add	V20.4S, V1.4S, V16.4S
	add	V21.4S, V5.4S, V17.4S
	add	V22.4S, V9.4S, V18.4S
	add	V23.4S, V13.4S, V19.4S
	eor	V20.16B, V20.16B, V24.16B
	eor	V21.16B, V21.16B, V25.16B
	eor	V22.16B, V22.16B, V26.16B
	eor	V23.16B, V23.16B, V27.16B
	ld1	{V24.16B, V25.16B, V26.16B, V27.16B}, [x2], #0x40
	st1	{V20.16B, V21.16B, V22.16B, V23.16B}, [x1], #0x40
	add	V20.4S, V2.4S, V16.4S
	add	V21.4S, V6.4S, V17.4S
	add	V22.4S, V10.4S, V18.4S
	add	V23.4S, V14.4S, V19.4S
	eor	V20.16B, V20.16B, V24.16B
	eor	V21.16B, V21.16B, V25.16B
	eor	V22.16B, V22.16B, V26.16B
	eor	V23.16B, V23.16B, V27.16B
	ld1	{V24.16B, V25.16B, V26.16B, V27.16B}, [x2], #0x40
	st1	{V20.16B, V21.16B, V22.16B, V23.16B}, [x1], #0x40
	add	V20.4S, V3.4S, V16.4S
	add	V21.4S, V7.4S, V17.4S
	add	V22.4S, V11.4S, V18.4S
	add	V23.4S, V15.4S, V19.4S
	eor	V20.16B, V20.16B, V24.16B
	eor	V21.16B, V21.16B, V25.16B
	eor	V22.16B, V22.16B, V26.16B
	eor	V23.16B, V23.16B, V27.16B
	ld1	{V24.16B, V25.16B, V26.16B, V27.16B}, [x2], #0x40
	st1	{V20.16B, V21.16B, V22.16B, V23.16B}, [x1], #0x40
	; Move regular registers into vector registers for adding and xor
	mov	V0.D[0], x8
	mov	V0.D[1], x10
	mov	V1.D[0], x12
	mov	V1.D[1], x14
	mov	V2.D[0], x16
	mov	V2.D[1], x19
	mov	V3.D[0], x21
	mov	V3.D[1], x23
	; Add back state, XOR in message and store
	add	V0.4S, V0.4S, V16.4S
	add	V1.4S, V1.4S, V17.4S
	add	V2.4S, V2.4S, V18.4S
	add	V3.4S, V3.4S, V19.4S
	eor	V0.16B, V0.16B, V24.16B
	eor	V1.16B, V1.16B, V25.16B
	eor	V2.16B, V2.16B, V26.16B
	eor	V3.16B, V3.16B, V27.16B
	st1	{V0.4S, V1.4S, V2.4S, V3.4S}, [x1], #0x40
	cmp	x3, #0x140
	add	V19.4S, V19.4S, V29.4S
	bge	L_chacha_crypt_bytes_arm64_loop_320
	; Done doing 320 bytes at a time
L_chacha_crypt_bytes_arm64_lt_320
	cmp	x3, #0x100
	blt	L_chacha_crypt_bytes_arm64_lt_256
	; Move state into vector registers
	dup	V0.4S, V16.S[0]
	dup	V1.4S, V16.S[1]
	dup	V2.4S, V16.S[2]
	dup	V3.4S, V16.S[3]
	dup	V4.4S, V17.S[0]
	dup	V5.4S, V17.S[1]
	dup	V6.4S, V17.S[2]
	dup	V7.4S, V17.S[3]
	dup	V8.4S, V18.S[0]
	dup	V9.4S, V18.S[1]
	dup	V10.4S, V18.S[2]
	dup	V11.4S, V18.S[3]
	dup	V12.4S, V19.S[0]
	dup	V13.4S, V19.S[1]
	dup	V14.4S, V19.S[2]
	dup	V15.4S, V19.S[3]
	; Add to counter word
	add	V12.4S, V12.4S, V28.4S
	; Set number of odd+even rounds to perform
	mov	x26, #10
L_chacha_crypt_bytes_arm64_round_start_256
	subs	x26, x26, #1
	; Round odd
	; a += b; d ^= a; d <<<= 16;
	add	V0.4S, V0.4S, V4.4S
	add	V1.4S, V1.4S, V5.4S
	add	V2.4S, V2.4S, V6.4S
	add	V3.4S, V3.4S, V7.4S
	eor	V12.16B, V12.16B, V0.16B
	eor	V13.16B, V13.16B, V1.16B
	eor	V14.16B, V14.16B, V2.16B
	eor	V15.16B, V15.16B, V3.16B
	rev32	V12.8H, V12.8H
	rev32	V13.8H, V13.8H
	rev32	V14.8H, V14.8H
	rev32	V15.8H, V15.8H
	; c += d; b ^= c; b <<<= 12;
	add	V8.4S, V8.4S, V12.4S
	add	V9.4S, V9.4S, V13.4S
	add	V10.4S, V10.4S, V14.4S
	add	V11.4S, V11.4S, V15.4S
	eor	V20.16B, V4.16B, V8.16B
	eor	V21.16B, V5.16B, V9.16B
	eor	V22.16B, V6.16B, V10.16B
	eor	V23.16B, V7.16B, V11.16B
	shl	V4.4S, V20.4S, #12
	shl	V5.4S, V21.4S, #12
	shl	V6.4S, V22.4S, #12
	shl	V7.4S, V23.4S, #12
	sri	V4.4S, V20.4S, #20
	sri	V5.4S, V21.4S, #20
	sri	V6.4S, V22.4S, #20
	sri	V7.4S, V23.4S, #20
	; a += b; d ^= a; d <<<= 8;
	add	V0.4S, V0.4S, V4.4S
	add	V1.4S, V1.4S, V5.4S
	add	V2.4S, V2.4S, V6.4S
	add	V3.4S, V3.4S, V7.4S
	eor	V12.16B, V12.16B, V0.16B
	eor	V13.16B, V13.16B, V1.16B
	eor	V14.16B, V14.16B, V2.16B
	eor	V15.16B, V15.16B, V3.16B
	tbl	V12.16B, {V12.16B}, V30.16B
	tbl	V13.16B, {V13.16B}, V30.16B
	tbl	V14.16B, {V14.16B}, V30.16B
	tbl	V15.16B, {V15.16B}, V30.16B
	; c += d; b ^= c; b <<<= 7;
	add	V8.4S, V8.4S, V12.4S
	add	V9.4S, V9.4S, V13.4S
	add	V10.4S, V10.4S, V14.4S
	add	V11.4S, V11.4S, V15.4S
	eor	V20.16B, V4.16B, V8.16B
	eor	V21.16B, V5.16B, V9.16B
	eor	V22.16B, V6.16B, V10.16B
	eor	V23.16B, V7.16B, V11.16B
	shl	V4.4S, V20.4S, #7
	shl	V5.4S, V21.4S, #7
	shl	V6.4S, V22.4S, #7
	shl	V7.4S, V23.4S, #7
	sri	V4.4S, V20.4S, #25
	sri	V5.4S, V21.4S, #25
	sri	V6.4S, V22.4S, #25
	sri	V7.4S, V23.4S, #25
	; Round even
	; a += b; d ^= a; d <<<= 16;
	add	V0.4S, V0.4S, V5.4S
	add	V1.4S, V1.4S, V6.4S
	add	V2.4S, V2.4S, V7.4S
	add	V3.4S, V3.4S, V4.4S
	eor	V15.16B, V15.16B, V0.16B
	eor	V12.16B, V12.16B, V1.16B
	eor	V13.16B, V13.16B, V2.16B
	eor	V14.16B, V14.16B, V3.16B
	rev32	V15.8H, V15.8H
	rev32	V12.8H, V12.8H
	rev32	V13.8H, V13.8H
	rev32	V14.8H, V14.8H
	; c += d; b ^= c; b <<<= 12;
	add	V10.4S, V10.4S, V15.4S
	add	V11.4S, V11.4S, V12.4S
	add	V8.4S, V8.4S, V13.4S
	add	V9.4S, V9.4S, V14.4S
	eor	V20.16B, V5.16B, V10.16B
	eor	V21.16B, V6.16B, V11.16B
	eor	V22.16B, V7.16B, V8.16B
	eor	V23.16B, V4.16B, V9.16B
	shl	V5.4S, V20.4S, #12
	shl	V6.4S, V21.4S, #12
	shl	V7.4S, V22.4S, #12
	shl	V4.4S, V23.4S, #12
	sri	V5.4S, V20.4S, #20
	sri	V6.4S, V21.4S, #20
	sri	V7.4S, V22.4S, #20
	sri	V4.4S, V23.4S, #20
	; a += b; d ^= a; d <<<= 8;
	add	V0.4S, V0.4S, V5.4S
	add	V1.4S, V1.4S, V6.4S
	add	V2.4S, V2.4S, V7.4S
	add	V3.4S, V3.4S, V4.4S
	eor	V15.16B, V15.16B, V0.16B
	eor	V12.16B, V12.16B, V1.16B
	eor	V13.16B, V13.16B, V2.16B
	eor	V14.16B, V14.16B, V3.16B
	tbl	V15.16B, {V15.16B}, V30.16B
	tbl	V12.16B, {V12.16B}, V30.16B
	tbl	V13.16B, {V13.16B}, V30.16B
	tbl	V14.16B, {V14.16B}, V30.16B
	; c += d; b ^= c; b <<<= 7;
	add	V10.4S, V10.4S, V15.4S
	add	V11.4S, V11.4S, V12.4S
	add	V8.4S, V8.4S, V13.4S
	add	V9.4S, V9.4S, V14.4S
	eor	V20.16B, V5.16B, V10.16B
	eor	V21.16B, V6.16B, V11.16B
	eor	V22.16B, V7.16B, V8.16B
	eor	V23.16B, V4.16B, V9.16B
	shl	V5.4S, V20.4S, #7
	shl	V6.4S, V21.4S, #7
	shl	V7.4S, V22.4S, #7
	shl	V4.4S, V23.4S, #7
	sri	V5.4S, V20.4S, #25
	sri	V6.4S, V21.4S, #25
	sri	V7.4S, V22.4S, #25
	sri	V4.4S, V23.4S, #25
	bne	L_chacha_crypt_bytes_arm64_round_start_256
	mov	x26, #4
	; Add counter now rather than after transposed
	add	V12.4S, V12.4S, V28.4S
	; Load message
	ld1	{V24.16B, V25.16B, V26.16B, V27.16B}, [x2], #0x40
	; Transpose vectors
	trn1	V20.4S, V0.4S, V1.4S
	trn1	V22.4S, V2.4S, V3.4S
	trn2	V21.4S, V0.4S, V1.4S
	trn2	V23.4S, V2.4S, V3.4S
	trn1	V0.2D, V20.2D, V22.2D
	trn1	V1.2D, V21.2D, V23.2D
	trn2	V2.2D, V20.2D, V22.2D
	trn2	V3.2D, V21.2D, V23.2D
	trn1	V20.4S, V4.4S, V5.4S
	trn1	V22.4S, V6.4S, V7.4S
	trn2	V21.4S, V4.4S, V5.4S
	trn2	V23.4S, V6.4S, V7.4S
	trn1	V4.2D, V20.2D, V22.2D
	trn1	V5.2D, V21.2D, V23.2D
	trn2	V6.2D, V20.2D, V22.2D
	trn2	V7.2D, V21.2D, V23.2D
	trn1	V20.4S, V8.4S, V9.4S
	trn1	V22.4S, V10.4S, V11.4S
	trn2	V21.4S, V8.4S, V9.4S
	trn2	V23.4S, V10.4S, V11.4S
	trn1	V8.2D, V20.2D, V22.2D
	trn1	V9.2D, V21.2D, V23.2D
	trn2	V10.2D, V20.2D, V22.2D
	trn2	V11.2D, V21.2D, V23.2D
	trn1	V20.4S, V12.4S, V13.4S
	trn1	V22.4S, V14.4S, V15.4S
	trn2	V21.4S, V12.4S, V13.4S
	trn2	V23.4S, V14.4S, V15.4S
	trn1	V12.2D, V20.2D, V22.2D
	trn1	V13.2D, V21.2D, V23.2D
	trn2	V14.2D, V20.2D, V22.2D
	trn2	V15.2D, V21.2D, V23.2D
	; Add back state, XOR in message and store (load next block)
	add	V20.4S, V0.4S, V16.4S
	add	V21.4S, V4.4S, V17.4S
	add	V22.4S, V8.4S, V18.4S
	add	V23.4S, V12.4S, V19.4S
	eor	V20.16B, V20.16B, V24.16B
	eor	V21.16B, V21.16B, V25.16B
	eor	V22.16B, V22.16B, V26.16B
	eor	V23.16B, V23.16B, V27.16B
	ld1	{V24.16B, V25.16B, V26.16B, V27.16B}, [x2], #0x40
	st1	{V20.16B, V21.16B, V22.16B, V23.16B}, [x1], #0x40
	add	V20.4S, V1.4S, V16.4S
	add	V21.4S, V5.4S, V17.4S
	add	V22.4S, V9.4S, V18.4S
	add	V23.4S, V13.4S, V19.4S
	eor	V20.16B, V20.16B, V24.16B
	eor	V21.16B, V21.16B, V25.16B
	eor	V22.16B, V22.16B, V26.16B
	eor	V23.16B, V23.16B, V27.16B
	ld1	{V24.16B, V25.16B, V26.16B, V27.16B}, [x2], #0x40
	st1	{V20.16B, V21.16B, V22.16B, V23.16B}, [x1], #0x40
	add	V20.4S, V2.4S, V16.4S
	add	V21.4S, V6.4S, V17.4S
	add	V22.4S, V10.4S, V18.4S
	add	V23.4S, V14.4S, V19.4S
	eor	V20.16B, V20.16B, V24.16B
	eor	V21.16B, V21.16B, V25.16B
	eor	V22.16B, V22.16B, V26.16B
	eor	V23.16B, V23.16B, V27.16B
	ld1	{V24.16B, V25.16B, V26.16B, V27.16B}, [x2], #0x40
	st1	{V20.16B, V21.16B, V22.16B, V23.16B}, [x1], #0x40
	add	V20.4S, V3.4S, V16.4S
	add	V21.4S, V7.4S, V17.4S
	add	V22.4S, V11.4S, V18.4S
	add	V23.4S, V15.4S, V19.4S
	eor	V20.16B, V20.16B, V24.16B
	eor	V21.16B, V21.16B, V25.16B
	eor	V22.16B, V22.16B, V26.16B
	eor	V23.16B, V23.16B, V27.16B
	st1	{V20.16B, V21.16B, V22.16B, V23.16B}, [x1], #0x40
	mov	V29.S[0], w26
	sub	x3, x3, #0x100
	add	V19.4S, V19.4S, V29.4S
	; Done 256-byte block
L_chacha_crypt_bytes_arm64_lt_256
	cmp	x3, #0x80
	blt	L_chacha_crypt_bytes_arm64_lt_128
	ld1	{V24.16B, V25.16B, V26.16B, V27.16B}, [x2], #0x40
	; Move state into vector registers
	mov	V4.16B, V16.16B
	mov	V5.16B, V17.16B
	mov	V6.16B, V18.16B
	mov	V7.16B, V19.16B
	mov	V0.16B, V16.16B
	mov	V1.16B, V17.16B
	mov	V2.16B, V18.16B
	mov	V3.16B, V19.16B
	; Add counter word
	add	V7.4S, V7.4S, V31.4S
	; Set number of odd+even rounds to perform
	mov	x26, #10
L_chacha_crypt_bytes_arm64_round_start_128
	subs	x26, x26, #1
	; Round odd
	; a += b; d ^= a; d <<<= 16;
	add	V0.4S, V0.4S, V1.4S
	add	V4.4S, V4.4S, V5.4S
	eor	V3.16B, V3.16B, V0.16B
	eor	V7.16B, V7.16B, V4.16B
	rev32	V3.8H, V3.8H
	rev32	V7.8H, V7.8H
	; c += d; b ^= c; b <<<= 12;
	add	V2.4S, V2.4S, V3.4S
	add	V6.4S, V6.4S, V7.4S
	eor	V20.16B, V1.16B, V2.16B
	eor	V21.16B, V5.16B, V6.16B
	shl	V1.4S, V20.4S, #12
	shl	V5.4S, V21.4S, #12
	sri	V1.4S, V20.4S, #20
	sri	V5.4S, V21.4S, #20
	; a += b; d ^= a; d <<<= 8;
	add	V0.4S, V0.4S, V1.4S
	add	V4.4S, V4.4S, V5.4S
	eor	V3.16B, V3.16B, V0.16B
	eor	V7.16B, V7.16B, V4.16B
	tbl	V3.16B, {V3.16B}, V30.16B
	tbl	V7.16B, {V7.16B}, V30.16B
	; c += d; b ^= c; b <<<= 7;
	add	V2.4S, V2.4S, V3.4S
	add	V6.4S, V6.4S, V7.4S
	eor	V20.16B, V1.16B, V2.16B
	eor	V21.16B, V5.16B, V6.16B
	shl	V1.4S, V20.4S, #7
	shl	V5.4S, V21.4S, #7
	sri	V1.4S, V20.4S, #25
	sri	V5.4S, V21.4S, #25
	ext8	V3.16B, V3.16B, V3.16B, #12
	ext8	V7.16B, V7.16B, V7.16B, #12
	ext8	V1.16B, V1.16B, V1.16B, #4
	ext8	V5.16B, V5.16B, V5.16B, #4
	ext8	V2.16B, V2.16B, V2.16B, #8
	ext8	V6.16B, V6.16B, V6.16B, #8
	; Round even
	; a += b; d ^= a; d <<<= 16;
	add	V0.4S, V0.4S, V1.4S
	add	V4.4S, V4.4S, V5.4S
	eor	V3.16B, V3.16B, V0.16B
	eor	V7.16B, V7.16B, V4.16B
	rev32	V3.8H, V3.8H
	rev32	V7.8H, V7.8H
	; c += d; b ^= c; b <<<= 12;
	add	V2.4S, V2.4S, V3.4S
	add	V6.4S, V6.4S, V7.4S
	eor	V20.16B, V1.16B, V2.16B
	eor	V21.16B, V5.16B, V6.16B
	shl	V1.4S, V20.4S, #12
	shl	V5.4S, V21.4S, #12
	sri	V1.4S, V20.4S, #20
	sri	V5.4S, V21.4S, #20
	; a += b; d ^= a; d <<<= 8;
	add	V0.4S, V0.4S, V1.4S
	add	V4.4S, V4.4S, V5.4S
	eor	V3.16B, V3.16B, V0.16B
	eor	V7.16B, V7.16B, V4.16B
	tbl	V3.16B, {V3.16B}, V30.16B
	tbl	V7.16B, {V7.16B}, V30.16B
	; c += d; b ^= c; b <<<= 7;
	add	V2.4S, V2.4S, V3.4S
	add	V6.4S, V6.4S, V7.4S
	eor	V20.16B, V1.16B, V2.16B
	eor	V21.16B, V5.16B, V6.16B
	shl	V1.4S, V20.4S, #7
	shl	V5.4S, V21.4S, #7
	sri	V1.4S, V20.4S, #25
	sri	V5.4S, V21.4S, #25
	ext8	V3.16B, V3.16B, V3.16B, #4
	ext8	V7.16B, V7.16B, V7.16B, #4
	ext8	V1.16B, V1.16B, V1.16B, #12
	ext8	V5.16B, V5.16B, V5.16B, #12
	ext8	V2.16B, V2.16B, V2.16B, #8
	ext8	V6.16B, V6.16B, V6.16B, #8
	bne	L_chacha_crypt_bytes_arm64_round_start_128
	; Add back state, XOR in message and store (load next block)
	add	V0.4S, V0.4S, V16.4S
	add	V1.4S, V1.4S, V17.4S
	add	V2.4S, V2.4S, V18.4S
	add	V3.4S, V3.4S, V19.4S
	eor	V24.16B, V24.16B, V0.16B
	eor	V25.16B, V25.16B, V1.16B
	eor	V26.16B, V26.16B, V2.16B
	eor	V27.16B, V27.16B, V3.16B
	ld1	{V20.16B, V21.16B, V22.16B, V23.16B}, [x2], #0x40
	st1	{V24.16B, V25.16B, V26.16B, V27.16B}, [x1], #0x40
	add	V19.4S, V19.4S, V31.4S
	add	V4.4S, V4.4S, V16.4S
	add	V5.4S, V5.4S, V17.4S
	add	V6.4S, V6.4S, V18.4S
	add	V7.4S, V7.4S, V19.4S
	eor	V20.16B, V20.16B, V4.16B
	eor	V21.16B, V21.16B, V5.16B
	eor	V22.16B, V22.16B, V6.16B
	eor	V23.16B, V23.16B, V7.16B
	st1	{V20.16B, V21.16B, V22.16B, V23.16B}, [x1], #0x40
	add	V19.4S, V19.4S, V31.4S
	sub	x3, x3, #0x80
	; Done 128-byte block
L_chacha_crypt_bytes_arm64_lt_128
	cmp	x3, #0
	beq	L_chacha_crypt_bytes_arm64_done_all
	mov	w5, #0x40
L_chacha_crypt_bytes_arm64_loop_64
	; Move state into vector registers
	mov	V0.16B, V16.16B
	mov	V1.16B, V17.16B
	mov	V2.16B, V18.16B
	mov	V3.16B, V19.16B
	; Set number of odd+even rounds to perform
	mov	x26, #10
L_chacha_crypt_bytes_arm64_round_64
	subs	x26, x26, #1
	; Round odd
	; a += b; d ^= a; d <<<= 16;
	add	V0.4S, V0.4S, V1.4S
	eor	V3.16B, V3.16B, V0.16B
	rev32	V3.8H, V3.8H
	; c += d; b ^= c; b <<<= 12;
	add	V2.4S, V2.4S, V3.4S
	eor	V20.16B, V1.16B, V2.16B
	shl	V1.4S, V20.4S, #12
	sri	V1.4S, V20.4S, #20
	; a += b; d ^= a; d <<<= 8;
	add	V0.4S, V0.4S, V1.4S
	eor	V3.16B, V3.16B, V0.16B
	tbl	V3.16B, {V3.16B}, V30.16B
	; c += d; b ^= c; b <<<= 7;
	add	V2.4S, V2.4S, V3.4S
	eor	V20.16B, V1.16B, V2.16B
	shl	V1.4S, V20.4S, #7
	sri	V1.4S, V20.4S, #25
	ext8	V3.16B, V3.16B, V3.16B, #12
	ext8	V1.16B, V1.16B, V1.16B, #4
	ext8	V2.16B, V2.16B, V2.16B, #8
	; Round even
	; a += b; d ^= a; d <<<= 16;
	add	V0.4S, V0.4S, V1.4S
	eor	V3.16B, V3.16B, V0.16B
	rev32	V3.8H, V3.8H
	; c += d; b ^= c; b <<<= 12;
	add	V2.4S, V2.4S, V3.4S
	eor	V20.16B, V1.16B, V2.16B
	shl	V1.4S, V20.4S, #12
	sri	V1.4S, V20.4S, #20
	; a += b; d ^= a; d <<<= 8;
	add	V0.4S, V0.4S, V1.4S
	eor	V3.16B, V3.16B, V0.16B
	tbl	V3.16B, {V3.16B}, V30.16B
	; c += d; b ^= c; b <<<= 7;
	add	V2.4S, V2.4S, V3.4S
	eor	V20.16B, V1.16B, V2.16B
	shl	V1.4S, V20.4S, #7
	sri	V1.4S, V20.4S, #25
	ext8	V3.16B, V3.16B, V3.16B, #4
	ext8	V1.16B, V1.16B, V1.16B, #12
	ext8	V2.16B, V2.16B, V2.16B, #8
	bne	L_chacha_crypt_bytes_arm64_round_64
	; Add back state
	add	V0.4S, V0.4S, V16.4S
	add	V1.4S, V1.4S, V17.4S
	add	V2.4S, V2.4S, V18.4S
	add	V3.4S, V3.4S, V19.4S
	; Check if data is less than 64 bytes - store in over
	cmp	x3, #0x40
	add	V19.4S, V19.4S, V31.4S
	blt	L_chacha_crypt_bytes_arm64_lt_64
	; Encipher 64 bytes
	ld1	{V24.16B, V25.16B, V26.16B, V27.16B}, [x2], #0x40
	eor	V24.16B, V24.16B, V0.16B
	eor	V25.16B, V25.16B, V1.16B
	eor	V26.16B, V26.16B, V2.16B
	eor	V27.16B, V27.16B, V3.16B
	st1	{V24.16B, V25.16B, V26.16B, V27.16B}, [x1], #0x40
	; Check for more bytes to be enciphered
	subs	x3, x3, #0x40
	bne	L_chacha_crypt_bytes_arm64_loop_64
	b	L_chacha_crypt_bytes_arm64_done
L_chacha_crypt_bytes_arm64_lt_64
	; Calculate bytes left in block not used
	sub	w5, w5, w3
	; Store encipher block in over for further operations and left
	st1	{V0.4S, V1.4S, V2.4S, V3.4S}, [x4]
	str	w5, [x0, #64]
	; Encipher 32 bytes
	cmp	x3, #32
	blt	L_chacha_crypt_bytes_arm64_lt_32
	ld1	{V24.16B, V25.16B}, [x2], #32
	eor	V24.16B, V24.16B, V0.16B
	eor	V25.16B, V25.16B, V1.16B
	st1	{V24.16B, V25.16B}, [x1], #32
	subs	x3, x3, #32
	mov	V0.16B, V2.16B
	mov	V1.16B, V3.16B
	beq	L_chacha_crypt_bytes_arm64_done
L_chacha_crypt_bytes_arm64_lt_32
	cmp	x3, #16
	blt	L_chacha_crypt_bytes_arm64_lt_16
	; Encipher 16 bytes
	ld1	{V24.16B}, [x2], #16
	eor	V24.16B, V24.16B, V0.16B
	st1	{V24.16B}, [x1], #16
	subs	x3, x3, #16
	mov	V0.16B, V1.16B
	beq	L_chacha_crypt_bytes_arm64_done
L_chacha_crypt_bytes_arm64_lt_16
	cmp	x3, #8
	blt	L_chacha_crypt_bytes_arm64_lt_8
	; Encipher 8 bytes
	ld1	{V24.8B}, [x2], #8
	eor	V24.8B, V24.8B, V0.8B
	st1	{V24.8B}, [x1], #8
	subs	x3, x3, #8
	mov	V0.D[0], V0.D[1]
	beq	L_chacha_crypt_bytes_arm64_done
L_chacha_crypt_bytes_arm64_lt_8
	mov	x5, V0.D[0]
L_chacha_crypt_bytes_arm64_loop_lt_8
	; Encipher 1 byte at a time
	ldrb	w6, [x2], #1
	eor	w6, w6, w5
	strb	w6, [x1], #1
	subs	x3, x3, #1
	lsr	x5, x5, #8
	bgt	L_chacha_crypt_bytes_arm64_loop_lt_8
L_chacha_crypt_bytes_arm64_done
L_chacha_crypt_bytes_arm64_done_all
	st1	{V16.4S, V17.4S, V18.4S, V19.4S}, [x0]
	ldp	x17, x19, [x29, #24]
	ldp	x20, x21, [x29, #40]
	ldp	x22, x23, [x29, #56]
	ldp	x24, x25, [x29, #72]
	ldr	x26, [x29, #88]
	ldp	D8, D9, [x29, #96]
	ldp	D10, D11, [x29, #112]
	ldp	D12, D13, [x29, #128]
	ldp	D14, D15, [x29, #144]
	ldp	x29, x30, [sp], #0xa0
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	wc_chacha_setiv
wc_chacha_setiv PROC
	ldr	x3, [x1]
	ldr	w4, [x1, #8]
	str	x2, [x0, #48]
	str	x3, [x0, #52]
	str	w4, [x0, #60]
	ret
	ENDP
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_chacha_setkey_arm64_constant
	DCD	0x61707865, 0x3120646e, 0x79622d36, 0x6b206574
	DCD	0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	wc_chacha_setkey
wc_chacha_setkey PROC
	adrp	x3, L_chacha_setkey_arm64_constant
	add	x3, x3, L_chacha_setkey_arm64_constant
	subs	x2, x2, #16
	add	x3, x3, x2
	; Start with constants
	ld1	{V0.4S}, [x3]
	ld1	{V1.16B}, [x1], #16
	IF :DEF:BIG_ENDIAN_ORDER
	rev32	V1.8H, V1.8H
	ENDIF
	st1	{V0.4S}, [x0], #16
	st1	{V1.4S}, [x0], #16
	beq	L_chacha_setkey_arm64_done
	ld1	{V1.16B}, [x1]
	IF :DEF:BIG_ENDIAN_ORDER
	rev32	V1.8H, V1.8H
	ENDIF
L_chacha_setkey_arm64_done
	st1	{V1.4S}, [x0]
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	wc_chacha_use_over
wc_chacha_use_over PROC
L_chacha_use_over_arm64_16byte_loop
	cmp	x3, #16
	blt	L_chacha_use_over_arm64_word_loop
	; 16 bytes of state XORed into message.
	ld1	{V0.16B}, [x0], #16
	ld1	{V1.16B}, [x2], #16
	eor	V1.16B, V1.16B, V0.16B
	subs	x3, x3, #16
	st1	{V1.16B}, [x1], #16
	beq	L_chacha_use_over_arm64_done
	b	L_chacha_use_over_arm64_16byte_loop
L_chacha_use_over_arm64_word_loop
	cmp	x3, #4
	blt	L_chacha_use_over_arm64_byte_loop
	; 4 bytes of state XORed into message.
	ldr	w4, [x0], #4
	ldr	w5, [x2], #4
	eor	w5, w5, w4
	subs	x3, x3, #4
	str	w5, [x1], #4
	beq	L_chacha_use_over_arm64_done
	b	L_chacha_use_over_arm64_word_loop
L_chacha_use_over_arm64_byte_loop
	; 1 bytes of state XORed into message.
	ldrb	w4, [x0], #1
	ldrb	w5, [x2], #1
	eor	w5, w5, w4
	subs	x3, x3, #1
	strb	w5, [x1], #1
	bne	L_chacha_use_over_arm64_byte_loop
L_chacha_use_over_arm64_done
	ret
	ENDP
	ENDIF
	ENDIF
	END
