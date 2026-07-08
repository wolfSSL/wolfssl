; /* armv8-sha3-asm
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
;   ruby ./sha3/sha3.rb arm64 \
;       ../wolfssl/wolfcrypt/src/port/arm/armv8-sha3-asm.asm
	IF :DEF:WOLFSSL_SHA3
	IF :DEF:WOLFSSL_ARMASM_CRYPTO_SHA3
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	16
L_SHA3_transform_crypto_r
	DCQ	0x0000000000000001, 0x0000000000008082
	DCQ	0x800000000000808a, 0x8000000080008000
	DCQ	0x000000000000808b, 0x0000000080000001
	DCQ	0x8000000080008081, 0x8000000000008009
	DCQ	0x000000000000008a, 0x0000000000000088
	DCQ	0x0000000080008009, 0x000000008000000a
	DCQ	0x000000008000808b, 0x800000000000008b
	DCQ	0x8000000000008089, 0x8000000000008003
	DCQ	0x8000000000008002, 0x8000000000000080
	DCQ	0x000000000000800a, 0x800000008000000a
	DCQ	0x8000000080008081, 0x8000000000008080
	DCQ	0x0000000080000001, 0x8000000080008008
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	BlockSha3_crypto
BlockSha3_crypto PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x1, L_SHA3_transform_crypto_r
	add	x1, x1, L_SHA3_transform_crypto_r
; .arch_extension sha3
	ld4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	ld4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	ld4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	ld4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	ld4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	ld4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	ld1	{V24.1D}, [x0]
	sub	x0, x0, #0xc0
	mov	x2, #24
	; Start of 24 rounds
L_sha3_crypto_begin
	; Col Mix
	eor3	V31.16B, V0.16B, V5.16B, V10.16B
	eor3	V27.16B, V1.16B, V6.16B, V11.16B
	eor3	V28.16B, V2.16B, V7.16B, V12.16B
	eor3	V29.16B, V3.16B, V8.16B, V13.16B
	eor3	V30.16B, V4.16B, V9.16B, V14.16B
	eor3	V31.16B, V31.16B, V15.16B, V20.16B
	eor3	V27.16B, V27.16B, V16.16B, V21.16B
	eor3	V28.16B, V28.16B, V17.16B, V22.16B
	eor3	V29.16B, V29.16B, V18.16B, V23.16B
	eor3	V30.16B, V30.16B, V19.16B, V24.16B
	rax1	V25.2D, V30.2D, V27.2D
	rax1	V26.2D, V31.2D, V28.2D
	rax1	V27.2D, V27.2D, V29.2D
	rax1	V28.2D, V28.2D, V30.2D
	rax1	V29.2D, V29.2D, V31.2D
	eor	V0.16B, V0.16B, V25.16B
	xar	V30.2D, V1.2D, V26.2D, #63
	xar	V1.2D, V6.2D, V26.2D, #20
	xar	V6.2D, V9.2D, V29.2D, #44
	xar	V9.2D, V22.2D, V27.2D, #3
	xar	V22.2D, V14.2D, V29.2D, #25
	xar	V14.2D, V20.2D, V25.2D, #46
	xar	V20.2D, V2.2D, V27.2D, #2
	xar	V2.2D, V12.2D, V27.2D, #21
	xar	V12.2D, V13.2D, V28.2D, #39
	xar	V13.2D, V19.2D, V29.2D, #56
	xar	V19.2D, V23.2D, V28.2D, #8
	xar	V23.2D, V15.2D, V25.2D, #23
	xar	V15.2D, V4.2D, V29.2D, #37
	xar	V4.2D, V24.2D, V29.2D, #50
	xar	V24.2D, V21.2D, V26.2D, #62
	xar	V21.2D, V8.2D, V28.2D, #9
	xar	V8.2D, V16.2D, V26.2D, #19
	xar	V16.2D, V5.2D, V25.2D, #28
	xar	V5.2D, V3.2D, V28.2D, #36
	xar	V3.2D, V18.2D, V28.2D, #43
	xar	V18.2D, V17.2D, V27.2D, #49
	xar	V17.2D, V11.2D, V26.2D, #54
	xar	V11.2D, V7.2D, V27.2D, #58
	xar	V7.2D, V10.2D, V25.2D, #61
	; Row Mix
	mov	V25.16B, V0.16B
	mov	V26.16B, V1.16B
	bcax	V0.16B, V25.16B, V2.16B, V26.16B
	bcax	V1.16B, V26.16B, V3.16B, V2.16B
	bcax	V2.16B, V2.16B, V4.16B, V3.16B
	bcax	V3.16B, V3.16B, V25.16B, V4.16B
	bcax	V4.16B, V4.16B, V26.16B, V25.16B
	mov	V25.16B, V5.16B
	mov	V26.16B, V6.16B
	bcax	V5.16B, V25.16B, V7.16B, V26.16B
	bcax	V6.16B, V26.16B, V8.16B, V7.16B
	bcax	V7.16B, V7.16B, V9.16B, V8.16B
	bcax	V8.16B, V8.16B, V25.16B, V9.16B
	bcax	V9.16B, V9.16B, V26.16B, V25.16B
	mov	V26.16B, V11.16B
	bcax	V10.16B, V30.16B, V12.16B, V26.16B
	bcax	V11.16B, V26.16B, V13.16B, V12.16B
	bcax	V12.16B, V12.16B, V14.16B, V13.16B
	bcax	V13.16B, V13.16B, V30.16B, V14.16B
	bcax	V14.16B, V14.16B, V26.16B, V30.16B
	mov	V25.16B, V15.16B
	mov	V26.16B, V16.16B
	bcax	V15.16B, V25.16B, V17.16B, V26.16B
	bcax	V16.16B, V26.16B, V18.16B, V17.16B
	bcax	V17.16B, V17.16B, V19.16B, V18.16B
	bcax	V18.16B, V18.16B, V25.16B, V19.16B
	bcax	V19.16B, V19.16B, V26.16B, V25.16B
	mov	V25.16B, V20.16B
	mov	V26.16B, V21.16B
	bcax	V20.16B, V25.16B, V22.16B, V26.16B
	bcax	V21.16B, V26.16B, V23.16B, V22.16B
	bcax	V22.16B, V22.16B, V24.16B, V23.16B
	bcax	V23.16B, V23.16B, V25.16B, V24.16B
	bcax	V24.16B, V24.16B, V26.16B, V25.16B
	ld1r	{V30.2D}, [x1], #8
	subs	x2, x2, #1
	eor	V0.16B, V0.16B, V30.16B
	bne	L_sha3_crypto_begin
	st4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	st1	{V24.1D}, [x0]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	ENDIF
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	16
L_SHA3_transform_base_r
	DCQ	0x0000000000000001, 0x0000000000008082
	DCQ	0x800000000000808a, 0x8000000080008000
	DCQ	0x000000000000808b, 0x0000000080000001
	DCQ	0x8000000080008081, 0x8000000000008009
	DCQ	0x000000000000008a, 0x0000000000000088
	DCQ	0x0000000080008009, 0x000000008000000a
	DCQ	0x000000008000808b, 0x800000000000008b
	DCQ	0x8000000000008089, 0x8000000000008003
	DCQ	0x8000000000008002, 0x8000000000000080
	DCQ	0x000000000000800a, 0x800000008000000a
	DCQ	0x8000000080008081, 0x8000000000008080
	DCQ	0x0000000080000001, 0x8000000080008008
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	BlockSha3_base
BlockSha3_base PROC
	stp	x29, x30, [sp, #-160]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	adrp	x27, L_SHA3_transform_base_r
	add	x27, x27, L_SHA3_transform_base_r
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
	; Start of 24 rounds
L_SHA3_transform_base_begin
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
	; Swap Rotate
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
	; Row Mix
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
	; Done transforming
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
	ENDP
	ENDIF
	END
