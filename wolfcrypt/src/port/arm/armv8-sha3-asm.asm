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
	IF :DEF:WOLFSSL_HAVE_MLKEM :LOR: :DEF:WOLFSSL_HAVE_MLDSA
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	16
L_sha3_aarch64_r
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
	IF :DEF:WOLFSSL_ARMASM_CRYPTO_SHA3
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	sha3_blocksx3_crypto
sha3_blocksx3_crypto PROC
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	D8, D9, [x29, #160]
	stp	D10, D11, [x29, #176]
	stp	D12, D13, [x29, #192]
	stp	D14, D15, [x29, #208]
	adrp	x27, L_sha3_aarch64_r
	add	x27, x27, L_sha3_aarch64_r
; .arch_extension sha3
	str	x0, [x29, #40]
	ld4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	ld4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	ld4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	ld4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	ld4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	ld4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	ld1	{V24.D}[0], [x0]
	add	x0, x0, #8
	ld4	{V0.D, V1.D, V2.D, V3.D}[1], [x0], #32
	ld4	{V4.D, V5.D, V6.D, V7.D}[1], [x0], #32
	ld4	{V8.D, V9.D, V10.D, V11.D}[1], [x0], #32
	ld4	{V12.D, V13.D, V14.D, V15.D}[1], [x0], #32
	ld4	{V16.D, V17.D, V18.D, V19.D}[1], [x0], #32
	ld4	{V20.D, V21.D, V22.D, V23.D}[1], [x0], #32
	ld1	{V24.D}[1], [x0]
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
	; Start of 24 rounds
L_SHA3_transform_blocksx3_crypto_begin
	stp	x27, x28, [x29, #48]
	; Col Mix
	eor3	V31.16B, V0.16B, V5.16B, V10.16B
	eor	x0, x5, x10
	eor3	V27.16B, V1.16B, V6.16B, V11.16B
	eor	x30, x1, x6
	eor3	V28.16B, V2.16B, V7.16B, V12.16B
	eor	x28, x3, x8
	eor3	V29.16B, V3.16B, V8.16B, V13.16B
	eor	x0, x0, x15
	eor3	V30.16B, V4.16B, V9.16B, V14.16B
	eor	x30, x30, x11
	eor3	V31.16B, V31.16B, V15.16B, V20.16B
	eor	x28, x28, x13
	eor3	V27.16B, V27.16B, V16.16B, V21.16B
	eor	x0, x0, x21
	eor3	V28.16B, V28.16B, V17.16B, V22.16B
	eor	x30, x30, x16
	eor3	V29.16B, V29.16B, V18.16B, V23.16B
	eor	x28, x28, x19
	eor3	V30.16B, V30.16B, V19.16B, V24.16B
	eor	x0, x0, x26
	rax1	V25.2D, V30.2D, V27.2D
	eor	x30, x30, x22
	rax1	V26.2D, V31.2D, V28.2D
	eor	x28, x28, x24
	rax1	V27.2D, V27.2D, V29.2D
	str	x0, [x29, #32]
	rax1	V28.2D, V28.2D, V30.2D
	str	x28, [x29, #24]
	rax1	V29.2D, V29.2D, V31.2D
	eor	x27, x2, x7
	eor	V0.16B, V0.16B, V25.16B
	xar	V30.2D, V1.2D, V26.2D, #63
	eor	x28, x4, x9
	xar	V1.2D, V6.2D, V26.2D, #20
	eor	x27, x27, x12
	xar	V6.2D, V9.2D, V29.2D, #44
	eor	x28, x28, x14
	xar	V9.2D, V22.2D, V27.2D, #3
	eor	x27, x27, x17
	xar	V22.2D, V14.2D, V29.2D, #25
	eor	x28, x28, x20
	xar	V14.2D, V20.2D, V25.2D, #46
	eor	x27, x27, x23
	xar	V20.2D, V2.2D, V27.2D, #2
	eor	x28, x28, x25
	xar	V2.2D, V12.2D, V27.2D, #21
	eor	x0, x0, x27, ror 63
	xar	V12.2D, V13.2D, V28.2D, #39
	eor	x27, x27, x28, ror 63
	xar	V13.2D, V19.2D, V29.2D, #56
	eor	x1, x1, x0
	xar	V19.2D, V23.2D, V28.2D, #8
	eor	x6, x6, x0
	xar	V23.2D, V15.2D, V25.2D, #23
	eor	x11, x11, x0
	xar	V15.2D, V4.2D, V29.2D, #37
	eor	x16, x16, x0
	xar	V4.2D, V24.2D, V29.2D, #50
	eor	x22, x22, x0
	xar	V24.2D, V21.2D, V26.2D, #62
	eor	x3, x3, x27
	xar	V21.2D, V8.2D, V28.2D, #9
	eor	x8, x8, x27
	xar	V8.2D, V16.2D, V26.2D, #19
	eor	x13, x13, x27
	xar	V16.2D, V5.2D, V25.2D, #28
	eor	x19, x19, x27
	xar	V5.2D, V3.2D, V28.2D, #36
	eor	x24, x24, x27
	xar	V3.2D, V18.2D, V28.2D, #43
	ldr	x0, [x29, #32]
	xar	V18.2D, V17.2D, V27.2D, #49
	ldr	x27, [x29, #24]
	xar	V17.2D, V11.2D, V26.2D, #54
	eor	x28, x28, x30, ror 63
	xar	V11.2D, V7.2D, V27.2D, #58
	eor	x30, x30, x27, ror 63
	xar	V7.2D, V10.2D, V25.2D, #61
	eor	x27, x27, x0, ror 63
	; Row Mix
	mov	V25.16B, V0.16B
	eor	x5, x5, x28
	mov	V26.16B, V1.16B
	eor	x10, x10, x28
	bcax	V0.16B, V25.16B, V2.16B, V26.16B
	eor	x15, x15, x28
	bcax	V1.16B, V26.16B, V3.16B, V2.16B
	eor	x21, x21, x28
	bcax	V2.16B, V2.16B, V4.16B, V3.16B
	eor	x26, x26, x28
	bcax	V3.16B, V3.16B, V25.16B, V4.16B
	eor	x2, x2, x30
	bcax	V4.16B, V4.16B, V26.16B, V25.16B
	eor	x7, x7, x30
	mov	V25.16B, V5.16B
	eor	x12, x12, x30
	mov	V26.16B, V6.16B
	eor	x17, x17, x30
	bcax	V5.16B, V25.16B, V7.16B, V26.16B
	eor	x23, x23, x30
	bcax	V6.16B, V26.16B, V8.16B, V7.16B
	eor	x4, x4, x27
	bcax	V7.16B, V7.16B, V9.16B, V8.16B
	eor	x9, x9, x27
	bcax	V8.16B, V8.16B, V25.16B, V9.16B
	eor	x14, x14, x27
	bcax	V9.16B, V9.16B, V26.16B, V25.16B
	eor	x20, x20, x27
	mov	V26.16B, V11.16B
	eor	x25, x25, x27
	; Swap Rotate Base
	bcax	V10.16B, V30.16B, V12.16B, V26.16B
	ror	x0, x2, #63
	bcax	V11.16B, V26.16B, V13.16B, V12.16B
	ror	x2, x7, #20
	bcax	V12.16B, V12.16B, V14.16B, V13.16B
	ror	x7, x10, #44
	bcax	V13.16B, V13.16B, V30.16B, V14.16B
	ror	x10, x24, #3
	bcax	V14.16B, V14.16B, V26.16B, V30.16B
	ror	x24, x15, #25
	mov	V25.16B, V15.16B
	ror	x15, x22, #46
	mov	V26.16B, V16.16B
	ror	x22, x3, #2
	bcax	V15.16B, V25.16B, V17.16B, V26.16B
	ror	x3, x13, #21
	bcax	V16.16B, V26.16B, V18.16B, V17.16B
	ror	x13, x14, #39
	bcax	V17.16B, V17.16B, V19.16B, V18.16B
	ror	x14, x21, #56
	bcax	V18.16B, V18.16B, V25.16B, V19.16B
	ror	x21, x25, #8
	bcax	V19.16B, V19.16B, V26.16B, V25.16B
	ror	x25, x16, #23
	mov	V25.16B, V20.16B
	ror	x16, x5, #37
	mov	V26.16B, V21.16B
	ror	x5, x26, #50
	bcax	V20.16B, V25.16B, V22.16B, V26.16B
	ror	x26, x23, #62
	bcax	V21.16B, V26.16B, V23.16B, V22.16B
	ror	x23, x9, #9
	bcax	V22.16B, V22.16B, V24.16B, V23.16B
	ror	x9, x17, #19
	bcax	V23.16B, V23.16B, V25.16B, V24.16B
	ror	x17, x6, #28
	bcax	V24.16B, V24.16B, V26.16B, V25.16B
	ror	x6, x4, #36
	ror	x4, x20, #43
	ror	x20, x19, #49
	ror	x19, x12, #54
	ror	x12, x8, #58
	ror	x8, x11, #61
	; Row Mix Base
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
	mov	V30.D[0], x0
	mov	V30.D[1], x0
	eor	x1, x1, x0
	eor	V0.16B, V0.16B, V30.16B
	bne	L_SHA3_transform_blocksx3_crypto_begin
	ldr	x0, [x29, #40]
	st4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	st1	{V24.D}[0], [x0]
	add	x0, x0, #8
	st4	{V0.D, V1.D, V2.D, V3.D}[1], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[1], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[1], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[1], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[1], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[1], [x0], #32
	st1	{V24.D}[1], [x0]
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
	ldp	D8, D9, [x29, #160]
	ldp	D10, D11, [x29, #176]
	ldp	D12, D13, [x29, #192]
	ldp	D14, D15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	sha3_128_blocksx3_seed_crypto
sha3_128_blocksx3_seed_crypto PROC
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	D8, D9, [x29, #160]
	stp	D10, D11, [x29, #176]
	stp	D12, D13, [x29, #192]
	stp	D14, D15, [x29, #208]
	adrp	x28, L_sha3_aarch64_r
	add	x28, x28, L_sha3_aarch64_r
; .arch_extension sha3
	str	x0, [x29, #40]
	add	x0, x0, #32
	ld1	{V4.D}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{V4.D}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldr	x6, [x0, #200]
	eor	V5.16B, V5.16B, V5.16B
	eor	x7, x7, x7
	eor	V6.16B, V6.16B, V6.16B
	eor	x8, x8, x8
	eor	V7.16B, V7.16B, V7.16B
	eor	x9, x9, x9
	eor	V8.16B, V8.16B, V8.16B
	eor	x10, x10, x10
	eor	V9.16B, V9.16B, V9.16B
	eor	x11, x11, x11
	eor	V10.16B, V10.16B, V10.16B
	eor	x12, x12, x12
	eor	V11.16B, V11.16B, V11.16B
	eor	x13, x13, x13
	eor	V12.16B, V12.16B, V12.16B
	eor	x14, x14, x14
	eor	V13.16B, V13.16B, V13.16B
	eor	x15, x15, x15
	eor	V14.16B, V14.16B, V14.16B
	eor	x16, x16, x16
	eor	V15.16B, V15.16B, V15.16B
	eor	x17, x17, x17
	eor	V16.16B, V16.16B, V16.16B
	eor	x19, x19, x19
	eor	V17.16B, V17.16B, V17.16B
	eor	x20, x20, x20
	eor	V18.16B, V18.16B, V18.16B
	eor	x21, x21, x21
	eor	V19.16B, V19.16B, V19.16B
	eor	x22, x22, x22
	movz	x23, #0x8000, lsl 48
	eor	V21.16B, V21.16B, V21.16B
	eor	x24, x24, x24
	eor	V22.16B, V22.16B, V22.16B
	eor	x25, x25, x25
	eor	V23.16B, V23.16B, V23.16B
	eor	x26, x26, x26
	eor	V24.16B, V24.16B, V24.16B
	eor	x27, x27, x27
	dup	V0.2D, x2
	dup	V1.2D, x3
	dup	V2.2D, x4
	dup	V3.2D, x5
	dup	V20.2D, x23
	mov	x1, #24
	; Start of 24 rounds
L_SHA3_shake128_blocksx3_seed_crypto_begin
	stp	x28, x1, [x29, #48]
	; Col Mix
	eor3	V31.16B, V0.16B, V5.16B, V10.16B
	eor	x0, x6, x11
	eor3	V27.16B, V1.16B, V6.16B, V11.16B
	eor	x30, x2, x7
	eor3	V28.16B, V2.16B, V7.16B, V12.16B
	eor	x28, x4, x9
	eor3	V29.16B, V3.16B, V8.16B, V13.16B
	eor	x0, x0, x16
	eor3	V30.16B, V4.16B, V9.16B, V14.16B
	eor	x30, x30, x12
	eor3	V31.16B, V31.16B, V15.16B, V20.16B
	eor	x28, x28, x14
	eor3	V27.16B, V27.16B, V16.16B, V21.16B
	eor	x0, x0, x22
	eor3	V28.16B, V28.16B, V17.16B, V22.16B
	eor	x30, x30, x17
	eor3	V29.16B, V29.16B, V18.16B, V23.16B
	eor	x28, x28, x20
	eor3	V30.16B, V30.16B, V19.16B, V24.16B
	eor	x0, x0, x27
	rax1	V25.2D, V30.2D, V27.2D
	eor	x30, x30, x23
	rax1	V26.2D, V31.2D, V28.2D
	eor	x28, x28, x25
	rax1	V27.2D, V27.2D, V29.2D
	str	x0, [x29, #32]
	rax1	V28.2D, V28.2D, V30.2D
	str	x28, [x29, #24]
	rax1	V29.2D, V29.2D, V31.2D
	eor	x1, x3, x8
	eor	V0.16B, V0.16B, V25.16B
	xar	V30.2D, V1.2D, V26.2D, #63
	eor	x28, x5, x10
	xar	V1.2D, V6.2D, V26.2D, #20
	eor	x1, x1, x13
	xar	V6.2D, V9.2D, V29.2D, #44
	eor	x28, x28, x15
	xar	V9.2D, V22.2D, V27.2D, #3
	eor	x1, x1, x19
	xar	V22.2D, V14.2D, V29.2D, #25
	eor	x28, x28, x21
	xar	V14.2D, V20.2D, V25.2D, #46
	eor	x1, x1, x24
	xar	V20.2D, V2.2D, V27.2D, #2
	eor	x28, x28, x26
	xar	V2.2D, V12.2D, V27.2D, #21
	eor	x0, x0, x1, ror 63
	xar	V12.2D, V13.2D, V28.2D, #39
	eor	x1, x1, x28, ror 63
	xar	V13.2D, V19.2D, V29.2D, #56
	eor	x2, x2, x0
	xar	V19.2D, V23.2D, V28.2D, #8
	eor	x7, x7, x0
	xar	V23.2D, V15.2D, V25.2D, #23
	eor	x12, x12, x0
	xar	V15.2D, V4.2D, V29.2D, #37
	eor	x17, x17, x0
	xar	V4.2D, V24.2D, V29.2D, #50
	eor	x23, x23, x0
	xar	V24.2D, V21.2D, V26.2D, #62
	eor	x4, x4, x1
	xar	V21.2D, V8.2D, V28.2D, #9
	eor	x9, x9, x1
	xar	V8.2D, V16.2D, V26.2D, #19
	eor	x14, x14, x1
	xar	V16.2D, V5.2D, V25.2D, #28
	eor	x20, x20, x1
	xar	V5.2D, V3.2D, V28.2D, #36
	eor	x25, x25, x1
	xar	V3.2D, V18.2D, V28.2D, #43
	ldr	x0, [x29, #32]
	xar	V18.2D, V17.2D, V27.2D, #49
	ldr	x1, [x29, #24]
	xar	V17.2D, V11.2D, V26.2D, #54
	eor	x28, x28, x30, ror 63
	xar	V11.2D, V7.2D, V27.2D, #58
	eor	x30, x30, x1, ror 63
	xar	V7.2D, V10.2D, V25.2D, #61
	eor	x1, x1, x0, ror 63
	; Row Mix
	mov	V25.16B, V0.16B
	eor	x6, x6, x28
	mov	V26.16B, V1.16B
	eor	x11, x11, x28
	bcax	V0.16B, V25.16B, V2.16B, V26.16B
	eor	x16, x16, x28
	bcax	V1.16B, V26.16B, V3.16B, V2.16B
	eor	x22, x22, x28
	bcax	V2.16B, V2.16B, V4.16B, V3.16B
	eor	x27, x27, x28
	bcax	V3.16B, V3.16B, V25.16B, V4.16B
	eor	x3, x3, x30
	bcax	V4.16B, V4.16B, V26.16B, V25.16B
	eor	x8, x8, x30
	mov	V25.16B, V5.16B
	eor	x13, x13, x30
	mov	V26.16B, V6.16B
	eor	x19, x19, x30
	bcax	V5.16B, V25.16B, V7.16B, V26.16B
	eor	x24, x24, x30
	bcax	V6.16B, V26.16B, V8.16B, V7.16B
	eor	x5, x5, x1
	bcax	V7.16B, V7.16B, V9.16B, V8.16B
	eor	x10, x10, x1
	bcax	V8.16B, V8.16B, V25.16B, V9.16B
	eor	x15, x15, x1
	bcax	V9.16B, V9.16B, V26.16B, V25.16B
	eor	x21, x21, x1
	mov	V26.16B, V11.16B
	eor	x26, x26, x1
	; Swap Rotate Base
	bcax	V10.16B, V30.16B, V12.16B, V26.16B
	ror	x0, x3, #63
	bcax	V11.16B, V26.16B, V13.16B, V12.16B
	ror	x3, x8, #20
	bcax	V12.16B, V12.16B, V14.16B, V13.16B
	ror	x8, x11, #44
	bcax	V13.16B, V13.16B, V30.16B, V14.16B
	ror	x11, x25, #3
	bcax	V14.16B, V14.16B, V26.16B, V30.16B
	ror	x25, x16, #25
	mov	V25.16B, V15.16B
	ror	x16, x23, #46
	mov	V26.16B, V16.16B
	ror	x23, x4, #2
	bcax	V15.16B, V25.16B, V17.16B, V26.16B
	ror	x4, x14, #21
	bcax	V16.16B, V26.16B, V18.16B, V17.16B
	ror	x14, x15, #39
	bcax	V17.16B, V17.16B, V19.16B, V18.16B
	ror	x15, x22, #56
	bcax	V18.16B, V18.16B, V25.16B, V19.16B
	ror	x22, x26, #8
	bcax	V19.16B, V19.16B, V26.16B, V25.16B
	ror	x26, x17, #23
	mov	V25.16B, V20.16B
	ror	x17, x6, #37
	mov	V26.16B, V21.16B
	ror	x6, x27, #50
	bcax	V20.16B, V25.16B, V22.16B, V26.16B
	ror	x27, x24, #62
	bcax	V21.16B, V26.16B, V23.16B, V22.16B
	ror	x24, x10, #9
	bcax	V22.16B, V22.16B, V24.16B, V23.16B
	ror	x10, x19, #19
	bcax	V23.16B, V23.16B, V25.16B, V24.16B
	ror	x19, x7, #28
	bcax	V24.16B, V24.16B, V26.16B, V25.16B
	ror	x7, x5, #36
	ror	x5, x21, #43
	ror	x21, x20, #49
	ror	x20, x13, #54
	ror	x13, x9, #58
	ror	x9, x12, #61
	; Row Mix Base
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
	; Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	V30.D[0], x0
	mov	V30.D[1], x0
	eor	x2, x2, x0
	eor	V0.16B, V0.16B, V30.16B
	bne	L_SHA3_shake128_blocksx3_seed_crypto_begin
	ldr	x0, [x29, #40]
	st4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	st1	{V24.D}[0], [x0]
	add	x0, x0, #8
	st4	{V0.D, V1.D, V2.D, V3.D}[1], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[1], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[1], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[1], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[1], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[1], [x0], #32
	st1	{V24.D}[1], [x0]
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
	ldp	D8, D9, [x29, #160]
	ldp	D10, D11, [x29, #176]
	ldp	D12, D13, [x29, #192]
	ldp	D14, D15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	sha3_256_blocksx3_seed_crypto
sha3_256_blocksx3_seed_crypto PROC
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	D8, D9, [x29, #160]
	stp	D10, D11, [x29, #176]
	stp	D12, D13, [x29, #192]
	stp	D14, D15, [x29, #208]
	adrp	x28, L_sha3_aarch64_r
	add	x28, x28, L_sha3_aarch64_r
; .arch_extension sha3
	str	x0, [x29, #40]
	add	x0, x0, #32
	ld1	{V4.D}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{V4.D}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldr	x6, [x0, #200]
	eor	V5.16B, V5.16B, V5.16B
	eor	x7, x7, x7
	eor	V6.16B, V6.16B, V6.16B
	eor	x8, x8, x8
	eor	V7.16B, V7.16B, V7.16B
	eor	x9, x9, x9
	eor	V8.16B, V8.16B, V8.16B
	eor	x10, x10, x10
	eor	V9.16B, V9.16B, V9.16B
	eor	x11, x11, x11
	eor	V10.16B, V10.16B, V10.16B
	eor	x12, x12, x12
	eor	V11.16B, V11.16B, V11.16B
	eor	x13, x13, x13
	eor	V12.16B, V12.16B, V12.16B
	eor	x14, x14, x14
	eor	V13.16B, V13.16B, V13.16B
	eor	x15, x15, x15
	eor	V14.16B, V14.16B, V14.16B
	eor	x16, x16, x16
	eor	V15.16B, V15.16B, V15.16B
	eor	x17, x17, x17
	movz	x19, #0x8000, lsl 48
	eor	V17.16B, V17.16B, V17.16B
	eor	x20, x20, x20
	eor	V18.16B, V18.16B, V18.16B
	eor	x21, x21, x21
	eor	V19.16B, V19.16B, V19.16B
	eor	x22, x22, x22
	eor	V20.16B, V20.16B, V20.16B
	eor	x23, x23, x23
	eor	V21.16B, V21.16B, V21.16B
	eor	x24, x24, x24
	eor	V22.16B, V22.16B, V22.16B
	eor	x25, x25, x25
	eor	V23.16B, V23.16B, V23.16B
	eor	x26, x26, x26
	eor	V24.16B, V24.16B, V24.16B
	eor	x27, x27, x27
	dup	V0.2D, x2
	dup	V1.2D, x3
	dup	V2.2D, x4
	dup	V3.2D, x5
	dup	V16.2D, x19
	mov	x1, #24
	; Start of 24 rounds
L_SHA3_shake256_blocksx3_seed_crypto_begin
	stp	x28, x1, [x29, #48]
	; Col Mix
	eor3	V31.16B, V0.16B, V5.16B, V10.16B
	eor	x0, x6, x11
	eor3	V27.16B, V1.16B, V6.16B, V11.16B
	eor	x30, x2, x7
	eor3	V28.16B, V2.16B, V7.16B, V12.16B
	eor	x28, x4, x9
	eor3	V29.16B, V3.16B, V8.16B, V13.16B
	eor	x0, x0, x16
	eor3	V30.16B, V4.16B, V9.16B, V14.16B
	eor	x30, x30, x12
	eor3	V31.16B, V31.16B, V15.16B, V20.16B
	eor	x28, x28, x14
	eor3	V27.16B, V27.16B, V16.16B, V21.16B
	eor	x0, x0, x22
	eor3	V28.16B, V28.16B, V17.16B, V22.16B
	eor	x30, x30, x17
	eor3	V29.16B, V29.16B, V18.16B, V23.16B
	eor	x28, x28, x20
	eor3	V30.16B, V30.16B, V19.16B, V24.16B
	eor	x0, x0, x27
	rax1	V25.2D, V30.2D, V27.2D
	eor	x30, x30, x23
	rax1	V26.2D, V31.2D, V28.2D
	eor	x28, x28, x25
	rax1	V27.2D, V27.2D, V29.2D
	str	x0, [x29, #32]
	rax1	V28.2D, V28.2D, V30.2D
	str	x28, [x29, #24]
	rax1	V29.2D, V29.2D, V31.2D
	eor	x1, x3, x8
	eor	V0.16B, V0.16B, V25.16B
	xar	V30.2D, V1.2D, V26.2D, #63
	eor	x28, x5, x10
	xar	V1.2D, V6.2D, V26.2D, #20
	eor	x1, x1, x13
	xar	V6.2D, V9.2D, V29.2D, #44
	eor	x28, x28, x15
	xar	V9.2D, V22.2D, V27.2D, #3
	eor	x1, x1, x19
	xar	V22.2D, V14.2D, V29.2D, #25
	eor	x28, x28, x21
	xar	V14.2D, V20.2D, V25.2D, #46
	eor	x1, x1, x24
	xar	V20.2D, V2.2D, V27.2D, #2
	eor	x28, x28, x26
	xar	V2.2D, V12.2D, V27.2D, #21
	eor	x0, x0, x1, ror 63
	xar	V12.2D, V13.2D, V28.2D, #39
	eor	x1, x1, x28, ror 63
	xar	V13.2D, V19.2D, V29.2D, #56
	eor	x2, x2, x0
	xar	V19.2D, V23.2D, V28.2D, #8
	eor	x7, x7, x0
	xar	V23.2D, V15.2D, V25.2D, #23
	eor	x12, x12, x0
	xar	V15.2D, V4.2D, V29.2D, #37
	eor	x17, x17, x0
	xar	V4.2D, V24.2D, V29.2D, #50
	eor	x23, x23, x0
	xar	V24.2D, V21.2D, V26.2D, #62
	eor	x4, x4, x1
	xar	V21.2D, V8.2D, V28.2D, #9
	eor	x9, x9, x1
	xar	V8.2D, V16.2D, V26.2D, #19
	eor	x14, x14, x1
	xar	V16.2D, V5.2D, V25.2D, #28
	eor	x20, x20, x1
	xar	V5.2D, V3.2D, V28.2D, #36
	eor	x25, x25, x1
	xar	V3.2D, V18.2D, V28.2D, #43
	ldr	x0, [x29, #32]
	xar	V18.2D, V17.2D, V27.2D, #49
	ldr	x1, [x29, #24]
	xar	V17.2D, V11.2D, V26.2D, #54
	eor	x28, x28, x30, ror 63
	xar	V11.2D, V7.2D, V27.2D, #58
	eor	x30, x30, x1, ror 63
	xar	V7.2D, V10.2D, V25.2D, #61
	eor	x1, x1, x0, ror 63
	; Row Mix
	mov	V25.16B, V0.16B
	eor	x6, x6, x28
	mov	V26.16B, V1.16B
	eor	x11, x11, x28
	bcax	V0.16B, V25.16B, V2.16B, V26.16B
	eor	x16, x16, x28
	bcax	V1.16B, V26.16B, V3.16B, V2.16B
	eor	x22, x22, x28
	bcax	V2.16B, V2.16B, V4.16B, V3.16B
	eor	x27, x27, x28
	bcax	V3.16B, V3.16B, V25.16B, V4.16B
	eor	x3, x3, x30
	bcax	V4.16B, V4.16B, V26.16B, V25.16B
	eor	x8, x8, x30
	mov	V25.16B, V5.16B
	eor	x13, x13, x30
	mov	V26.16B, V6.16B
	eor	x19, x19, x30
	bcax	V5.16B, V25.16B, V7.16B, V26.16B
	eor	x24, x24, x30
	bcax	V6.16B, V26.16B, V8.16B, V7.16B
	eor	x5, x5, x1
	bcax	V7.16B, V7.16B, V9.16B, V8.16B
	eor	x10, x10, x1
	bcax	V8.16B, V8.16B, V25.16B, V9.16B
	eor	x15, x15, x1
	bcax	V9.16B, V9.16B, V26.16B, V25.16B
	eor	x21, x21, x1
	mov	V26.16B, V11.16B
	eor	x26, x26, x1
	; Swap Rotate Base
	bcax	V10.16B, V30.16B, V12.16B, V26.16B
	ror	x0, x3, #63
	bcax	V11.16B, V26.16B, V13.16B, V12.16B
	ror	x3, x8, #20
	bcax	V12.16B, V12.16B, V14.16B, V13.16B
	ror	x8, x11, #44
	bcax	V13.16B, V13.16B, V30.16B, V14.16B
	ror	x11, x25, #3
	bcax	V14.16B, V14.16B, V26.16B, V30.16B
	ror	x25, x16, #25
	mov	V25.16B, V15.16B
	ror	x16, x23, #46
	mov	V26.16B, V16.16B
	ror	x23, x4, #2
	bcax	V15.16B, V25.16B, V17.16B, V26.16B
	ror	x4, x14, #21
	bcax	V16.16B, V26.16B, V18.16B, V17.16B
	ror	x14, x15, #39
	bcax	V17.16B, V17.16B, V19.16B, V18.16B
	ror	x15, x22, #56
	bcax	V18.16B, V18.16B, V25.16B, V19.16B
	ror	x22, x26, #8
	bcax	V19.16B, V19.16B, V26.16B, V25.16B
	ror	x26, x17, #23
	mov	V25.16B, V20.16B
	ror	x17, x6, #37
	mov	V26.16B, V21.16B
	ror	x6, x27, #50
	bcax	V20.16B, V25.16B, V22.16B, V26.16B
	ror	x27, x24, #62
	bcax	V21.16B, V26.16B, V23.16B, V22.16B
	ror	x24, x10, #9
	bcax	V22.16B, V22.16B, V24.16B, V23.16B
	ror	x10, x19, #19
	bcax	V23.16B, V23.16B, V25.16B, V24.16B
	ror	x19, x7, #28
	bcax	V24.16B, V24.16B, V26.16B, V25.16B
	ror	x7, x5, #36
	ror	x5, x21, #43
	ror	x21, x20, #49
	ror	x20, x13, #54
	ror	x13, x9, #58
	ror	x9, x12, #61
	; Row Mix Base
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
	; Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	V30.D[0], x0
	mov	V30.D[1], x0
	eor	x2, x2, x0
	eor	V0.16B, V0.16B, V30.16B
	bne	L_SHA3_shake256_blocksx3_seed_crypto_begin
	ldr	x0, [x29, #40]
	st4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	st1	{V24.D}[0], [x0]
	add	x0, x0, #8
	st4	{V0.D, V1.D, V2.D, V3.D}[1], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[1], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[1], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[1], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[1], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[1], [x0], #32
	st1	{V24.D}[1], [x0]
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
	ldp	D8, D9, [x29, #160]
	ldp	D10, D11, [x29, #176]
	ldp	D12, D13, [x29, #192]
	ldp	D14, D15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	sha3_256_blocksx3_seed_64_crypto
sha3_256_blocksx3_seed_64_crypto PROC
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	D8, D9, [x29, #160]
	stp	D10, D11, [x29, #176]
	stp	D12, D13, [x29, #192]
	stp	D14, D15, [x29, #208]
	adrp	x28, L_sha3_aarch64_r
	add	x28, x28, L_sha3_aarch64_r
; .arch_extension sha3
	str	x0, [x29, #40]
	add	x0, x0, #0x40
	ld1	{V8.D}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{V8.D}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldp	x6, x7, [x1], #16
	ldp	x8, x9, [x1], #16
	ldr	x10, [x0, #200]
	eor	V9.16B, V9.16B, V9.16B
	eor	x11, x11, x11
	eor	V10.16B, V10.16B, V10.16B
	eor	x12, x12, x12
	eor	V11.16B, V11.16B, V11.16B
	eor	x13, x13, x13
	eor	V12.16B, V12.16B, V12.16B
	eor	x14, x14, x14
	eor	V13.16B, V13.16B, V13.16B
	eor	x15, x15, x15
	eor	V14.16B, V14.16B, V14.16B
	eor	x16, x16, x16
	eor	V15.16B, V15.16B, V15.16B
	eor	x17, x17, x17
	movz	x19, #0x8000, lsl 48
	eor	V17.16B, V17.16B, V17.16B
	eor	x20, x20, x20
	eor	V18.16B, V18.16B, V18.16B
	eor	x21, x21, x21
	eor	V19.16B, V19.16B, V19.16B
	eor	x22, x22, x22
	eor	V20.16B, V20.16B, V20.16B
	eor	x23, x23, x23
	eor	V21.16B, V21.16B, V21.16B
	eor	x24, x24, x24
	eor	V22.16B, V22.16B, V22.16B
	eor	x25, x25, x25
	eor	V23.16B, V23.16B, V23.16B
	eor	x26, x26, x26
	eor	V24.16B, V24.16B, V24.16B
	eor	x27, x27, x27
	dup	V0.2D, x2
	dup	V1.2D, x3
	dup	V2.2D, x4
	dup	V3.2D, x5
	dup	V4.2D, x6
	dup	V5.2D, x7
	dup	V6.2D, x8
	dup	V7.2D, x9
	dup	V16.2D, x19
	mov	x1, #24
	; Start of 24 rounds
L_SHA3_shake256_blocksx3_seed_64_crypto_begin
	stp	x28, x1, [x29, #48]
	; Col Mix
	eor3	V31.16B, V0.16B, V5.16B, V10.16B
	eor	x0, x6, x11
	eor3	V27.16B, V1.16B, V6.16B, V11.16B
	eor	x30, x2, x7
	eor3	V28.16B, V2.16B, V7.16B, V12.16B
	eor	x28, x4, x9
	eor3	V29.16B, V3.16B, V8.16B, V13.16B
	eor	x0, x0, x16
	eor3	V30.16B, V4.16B, V9.16B, V14.16B
	eor	x30, x30, x12
	eor3	V31.16B, V31.16B, V15.16B, V20.16B
	eor	x28, x28, x14
	eor3	V27.16B, V27.16B, V16.16B, V21.16B
	eor	x0, x0, x22
	eor3	V28.16B, V28.16B, V17.16B, V22.16B
	eor	x30, x30, x17
	eor3	V29.16B, V29.16B, V18.16B, V23.16B
	eor	x28, x28, x20
	eor3	V30.16B, V30.16B, V19.16B, V24.16B
	eor	x0, x0, x27
	rax1	V25.2D, V30.2D, V27.2D
	eor	x30, x30, x23
	rax1	V26.2D, V31.2D, V28.2D
	eor	x28, x28, x25
	rax1	V27.2D, V27.2D, V29.2D
	str	x0, [x29, #32]
	rax1	V28.2D, V28.2D, V30.2D
	str	x28, [x29, #24]
	rax1	V29.2D, V29.2D, V31.2D
	eor	x1, x3, x8
	eor	V0.16B, V0.16B, V25.16B
	xar	V30.2D, V1.2D, V26.2D, #63
	eor	x28, x5, x10
	xar	V1.2D, V6.2D, V26.2D, #20
	eor	x1, x1, x13
	xar	V6.2D, V9.2D, V29.2D, #44
	eor	x28, x28, x15
	xar	V9.2D, V22.2D, V27.2D, #3
	eor	x1, x1, x19
	xar	V22.2D, V14.2D, V29.2D, #25
	eor	x28, x28, x21
	xar	V14.2D, V20.2D, V25.2D, #46
	eor	x1, x1, x24
	xar	V20.2D, V2.2D, V27.2D, #2
	eor	x28, x28, x26
	xar	V2.2D, V12.2D, V27.2D, #21
	eor	x0, x0, x1, ror 63
	xar	V12.2D, V13.2D, V28.2D, #39
	eor	x1, x1, x28, ror 63
	xar	V13.2D, V19.2D, V29.2D, #56
	eor	x2, x2, x0
	xar	V19.2D, V23.2D, V28.2D, #8
	eor	x7, x7, x0
	xar	V23.2D, V15.2D, V25.2D, #23
	eor	x12, x12, x0
	xar	V15.2D, V4.2D, V29.2D, #37
	eor	x17, x17, x0
	xar	V4.2D, V24.2D, V29.2D, #50
	eor	x23, x23, x0
	xar	V24.2D, V21.2D, V26.2D, #62
	eor	x4, x4, x1
	xar	V21.2D, V8.2D, V28.2D, #9
	eor	x9, x9, x1
	xar	V8.2D, V16.2D, V26.2D, #19
	eor	x14, x14, x1
	xar	V16.2D, V5.2D, V25.2D, #28
	eor	x20, x20, x1
	xar	V5.2D, V3.2D, V28.2D, #36
	eor	x25, x25, x1
	xar	V3.2D, V18.2D, V28.2D, #43
	ldr	x0, [x29, #32]
	xar	V18.2D, V17.2D, V27.2D, #49
	ldr	x1, [x29, #24]
	xar	V17.2D, V11.2D, V26.2D, #54
	eor	x28, x28, x30, ror 63
	xar	V11.2D, V7.2D, V27.2D, #58
	eor	x30, x30, x1, ror 63
	xar	V7.2D, V10.2D, V25.2D, #61
	eor	x1, x1, x0, ror 63
	; Row Mix
	mov	V25.16B, V0.16B
	eor	x6, x6, x28
	mov	V26.16B, V1.16B
	eor	x11, x11, x28
	bcax	V0.16B, V25.16B, V2.16B, V26.16B
	eor	x16, x16, x28
	bcax	V1.16B, V26.16B, V3.16B, V2.16B
	eor	x22, x22, x28
	bcax	V2.16B, V2.16B, V4.16B, V3.16B
	eor	x27, x27, x28
	bcax	V3.16B, V3.16B, V25.16B, V4.16B
	eor	x3, x3, x30
	bcax	V4.16B, V4.16B, V26.16B, V25.16B
	eor	x8, x8, x30
	mov	V25.16B, V5.16B
	eor	x13, x13, x30
	mov	V26.16B, V6.16B
	eor	x19, x19, x30
	bcax	V5.16B, V25.16B, V7.16B, V26.16B
	eor	x24, x24, x30
	bcax	V6.16B, V26.16B, V8.16B, V7.16B
	eor	x5, x5, x1
	bcax	V7.16B, V7.16B, V9.16B, V8.16B
	eor	x10, x10, x1
	bcax	V8.16B, V8.16B, V25.16B, V9.16B
	eor	x15, x15, x1
	bcax	V9.16B, V9.16B, V26.16B, V25.16B
	eor	x21, x21, x1
	mov	V26.16B, V11.16B
	eor	x26, x26, x1
	; Swap Rotate Base
	bcax	V10.16B, V30.16B, V12.16B, V26.16B
	ror	x0, x3, #63
	bcax	V11.16B, V26.16B, V13.16B, V12.16B
	ror	x3, x8, #20
	bcax	V12.16B, V12.16B, V14.16B, V13.16B
	ror	x8, x11, #44
	bcax	V13.16B, V13.16B, V30.16B, V14.16B
	ror	x11, x25, #3
	bcax	V14.16B, V14.16B, V26.16B, V30.16B
	ror	x25, x16, #25
	mov	V25.16B, V15.16B
	ror	x16, x23, #46
	mov	V26.16B, V16.16B
	ror	x23, x4, #2
	bcax	V15.16B, V25.16B, V17.16B, V26.16B
	ror	x4, x14, #21
	bcax	V16.16B, V26.16B, V18.16B, V17.16B
	ror	x14, x15, #39
	bcax	V17.16B, V17.16B, V19.16B, V18.16B
	ror	x15, x22, #56
	bcax	V18.16B, V18.16B, V25.16B, V19.16B
	ror	x22, x26, #8
	bcax	V19.16B, V19.16B, V26.16B, V25.16B
	ror	x26, x17, #23
	mov	V25.16B, V20.16B
	ror	x17, x6, #37
	mov	V26.16B, V21.16B
	ror	x6, x27, #50
	bcax	V20.16B, V25.16B, V22.16B, V26.16B
	ror	x27, x24, #62
	bcax	V21.16B, V26.16B, V23.16B, V22.16B
	ror	x24, x10, #9
	bcax	V22.16B, V22.16B, V24.16B, V23.16B
	ror	x10, x19, #19
	bcax	V23.16B, V23.16B, V25.16B, V24.16B
	ror	x19, x7, #28
	bcax	V24.16B, V24.16B, V26.16B, V25.16B
	ror	x7, x5, #36
	ror	x5, x21, #43
	ror	x21, x20, #49
	ror	x20, x13, #54
	ror	x13, x9, #58
	ror	x9, x12, #61
	; Row Mix Base
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
	; Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	V30.D[0], x0
	mov	V30.D[1], x0
	eor	x2, x2, x0
	eor	V0.16B, V0.16B, V30.16B
	bne	L_SHA3_shake256_blocksx3_seed_64_crypto_begin
	ldr	x0, [x29, #40]
	st4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	st1	{V24.D}[0], [x0]
	add	x0, x0, #8
	st4	{V0.D, V1.D, V2.D, V3.D}[1], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[1], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[1], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[1], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[1], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[1], [x0], #32
	st1	{V24.D}[1], [x0]
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
	ldp	D8, D9, [x29, #160]
	ldp	D10, D11, [x29, #176]
	ldp	D12, D13, [x29, #192]
	ldp	D14, D15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
	ENDP
	ENDIF
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	sha3_blocksx3_neon
sha3_blocksx3_neon PROC
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	D8, D9, [x29, #160]
	stp	D10, D11, [x29, #176]
	stp	D12, D13, [x29, #192]
	stp	D14, D15, [x29, #208]
	adrp	x27, L_sha3_aarch64_r
	add	x27, x27, L_sha3_aarch64_r
	str	x0, [x29, #40]
	ld4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	ld4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	ld4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	ld4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	ld4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	ld4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	ld1	{V24.D}[0], [x0]
	add	x0, x0, #8
	ld4	{V0.D, V1.D, V2.D, V3.D}[1], [x0], #32
	ld4	{V4.D, V5.D, V6.D, V7.D}[1], [x0], #32
	ld4	{V8.D, V9.D, V10.D, V11.D}[1], [x0], #32
	ld4	{V12.D, V13.D, V14.D, V15.D}[1], [x0], #32
	ld4	{V16.D, V17.D, V18.D, V19.D}[1], [x0], #32
	ld4	{V20.D, V21.D, V22.D, V23.D}[1], [x0], #32
	ld1	{V24.D}[1], [x0]
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
	; Start of 24 rounds
L_SHA3_transform_blocksx3_neon_begin
	stp	x27, x28, [x29, #48]
	; Col Mix NEON
	eor	V30.16B, V4.16B, V9.16B
	eor	x0, x5, x10
	eor	V27.16B, V1.16B, V6.16B
	eor	x30, x1, x6
	eor	V30.16B, V30.16B, V14.16B
	eor	x28, x3, x8
	eor	V27.16B, V27.16B, V11.16B
	eor	x0, x0, x15
	eor	V30.16B, V30.16B, V19.16B
	eor	x30, x30, x11
	eor	V27.16B, V27.16B, V16.16B
	eor	x28, x28, x13
	eor	V30.16B, V30.16B, V24.16B
	eor	x0, x0, x21
	eor	V27.16B, V27.16B, V21.16B
	eor	x30, x30, x16
	ushr	V25.2D, V27.2D, #63
	eor	x28, x28, x19
	sli	V25.2D, V27.2D, #1
	eor	x0, x0, x26
	eor	V25.16B, V25.16B, V30.16B
	eor	x30, x30, x22
	eor	V31.16B, V0.16B, V5.16B
	eor	x28, x28, x24
	eor	V28.16B, V2.16B, V7.16B
	str	x0, [x29, #32]
	eor	V31.16B, V31.16B, V10.16B
	str	x28, [x29, #24]
	eor	V28.16B, V28.16B, V12.16B
	eor	x27, x2, x7
	eor	V31.16B, V31.16B, V15.16B
	eor	x28, x4, x9
	eor	V28.16B, V28.16B, V17.16B
	eor	x27, x27, x12
	eor	V31.16B, V31.16B, V20.16B
	eor	x28, x28, x14
	eor	V28.16B, V28.16B, V22.16B
	eor	x27, x27, x17
	ushr	V29.2D, V30.2D, #63
	eor	x28, x28, x20
	ushr	V26.2D, V28.2D, #63
	eor	x27, x27, x23
	sli	V29.2D, V30.2D, #1
	eor	x28, x28, x25
	sli	V26.2D, V28.2D, #1
	eor	x0, x0, x27, ror 63
	eor	V28.16B, V28.16B, V29.16B
	eor	x27, x27, x28, ror 63
	eor	V29.16B, V3.16B, V8.16B
	eor	x1, x1, x0
	eor	V26.16B, V26.16B, V31.16B
	eor	x6, x6, x0
	eor	V29.16B, V29.16B, V13.16B
	eor	x11, x11, x0
	eor	V29.16B, V29.16B, V18.16B
	eor	x16, x16, x0
	eor	V29.16B, V29.16B, V23.16B
	eor	x22, x22, x0
	ushr	V30.2D, V29.2D, #63
	eor	x3, x3, x27
	sli	V30.2D, V29.2D, #1
	eor	x8, x8, x27
	eor	V27.16B, V27.16B, V30.16B
	eor	x13, x13, x27
	ushr	V30.2D, V31.2D, #63
	eor	x19, x19, x27
	sli	V30.2D, V31.2D, #1
	eor	x24, x24, x27
	eor	V29.16B, V29.16B, V30.16B
	ldr	x0, [x29, #32]
	; Swap Rotate NEON
	eor	V0.16B, V0.16B, V25.16B
	eor	V31.16B, V1.16B, V26.16B
	ldr	x27, [x29, #24]
	eor	V6.16B, V6.16B, V26.16B
	eor	x28, x28, x30, ror 63
	ushr	V30.2D, V31.2D, #63
	eor	x30, x30, x27, ror 63
	ushr	V1.2D, V6.2D, #20
	eor	x27, x27, x0, ror 63
	sli	V30.2D, V31.2D, #1
	eor	x5, x5, x28
	sli	V1.2D, V6.2D, #44
	eor	x10, x10, x28
	eor	V31.16B, V9.16B, V29.16B
	eor	x15, x15, x28
	eor	V22.16B, V22.16B, V27.16B
	eor	x21, x21, x28
	ushr	V6.2D, V31.2D, #44
	eor	x26, x26, x28
	ushr	V9.2D, V22.2D, #3
	eor	x2, x2, x30
	sli	V6.2D, V31.2D, #20
	eor	x7, x7, x30
	sli	V9.2D, V22.2D, #61
	eor	x12, x12, x30
	eor	V31.16B, V14.16B, V29.16B
	eor	x17, x17, x30
	eor	V20.16B, V20.16B, V25.16B
	eor	x23, x23, x30
	ushr	V22.2D, V31.2D, #25
	eor	x4, x4, x27
	ushr	V14.2D, V20.2D, #46
	eor	x9, x9, x27
	sli	V22.2D, V31.2D, #39
	eor	x14, x14, x27
	sli	V14.2D, V20.2D, #18
	eor	x20, x20, x27
	eor	V31.16B, V2.16B, V27.16B
	eor	x25, x25, x27
	; Swap Rotate Base
	eor	V12.16B, V12.16B, V27.16B
	ror	x0, x2, #63
	ushr	V20.2D, V31.2D, #2
	ror	x2, x7, #20
	ushr	V2.2D, V12.2D, #21
	ror	x7, x10, #44
	sli	V20.2D, V31.2D, #62
	ror	x10, x24, #3
	sli	V2.2D, V12.2D, #43
	ror	x24, x15, #25
	eor	V31.16B, V13.16B, V28.16B
	ror	x15, x22, #46
	eor	V19.16B, V19.16B, V29.16B
	ror	x22, x3, #2
	ushr	V12.2D, V31.2D, #39
	ror	x3, x13, #21
	ushr	V13.2D, V19.2D, #56
	ror	x13, x14, #39
	sli	V12.2D, V31.2D, #25
	ror	x14, x21, #56
	sli	V13.2D, V19.2D, #8
	ror	x21, x25, #8
	eor	V31.16B, V23.16B, V28.16B
	ror	x25, x16, #23
	eor	V15.16B, V15.16B, V25.16B
	ror	x16, x5, #37
	ushr	V19.2D, V31.2D, #8
	ror	x5, x26, #50
	ushr	V23.2D, V15.2D, #23
	ror	x26, x23, #62
	sli	V19.2D, V31.2D, #56
	ror	x23, x9, #9
	sli	V23.2D, V15.2D, #41
	ror	x9, x17, #19
	eor	V31.16B, V4.16B, V29.16B
	ror	x17, x6, #28
	eor	V24.16B, V24.16B, V29.16B
	ror	x6, x4, #36
	ushr	V15.2D, V31.2D, #37
	ror	x4, x20, #43
	ushr	V4.2D, V24.2D, #50
	ror	x20, x19, #49
	sli	V15.2D, V31.2D, #27
	ror	x19, x12, #54
	sli	V4.2D, V24.2D, #14
	ror	x12, x8, #58
	eor	V31.16B, V21.16B, V26.16B
	ror	x8, x11, #61
	; Row Mix Base
	eor	V8.16B, V8.16B, V28.16B
	bic	x11, x3, x2
	ushr	V24.2D, V31.2D, #62
	bic	x27, x4, x3
	ushr	V21.2D, V8.2D, #9
	bic	x28, x1, x5
	sli	V24.2D, V31.2D, #2
	bic	x30, x2, x1
	sli	V21.2D, V8.2D, #55
	eor	x1, x1, x11
	eor	V31.16B, V16.16B, V26.16B
	eor	x2, x2, x27
	eor	V5.16B, V5.16B, V25.16B
	bic	x11, x5, x4
	ushr	V8.2D, V31.2D, #19
	eor	x4, x4, x28
	ushr	V16.2D, V5.2D, #28
	eor	x3, x3, x11
	sli	V8.2D, V31.2D, #45
	eor	x5, x5, x30
	sli	V16.2D, V5.2D, #36
	bic	x11, x8, x7
	eor	V31.16B, V3.16B, V28.16B
	bic	x27, x9, x8
	eor	V18.16B, V18.16B, V28.16B
	bic	x28, x6, x10
	ushr	V5.2D, V31.2D, #36
	bic	x30, x7, x6
	ushr	V3.2D, V18.2D, #43
	eor	x6, x6, x11
	sli	V5.2D, V31.2D, #28
	eor	x7, x7, x27
	sli	V3.2D, V18.2D, #21
	bic	x11, x10, x9
	eor	V31.16B, V17.16B, V27.16B
	eor	x9, x9, x28
	eor	V11.16B, V11.16B, V26.16B
	eor	x8, x8, x11
	ushr	V18.2D, V31.2D, #49
	eor	x10, x10, x30
	ushr	V17.2D, V11.2D, #54
	bic	x11, x13, x12
	sli	V18.2D, V31.2D, #15
	bic	x27, x14, x13
	sli	V17.2D, V11.2D, #10
	bic	x28, x0, x15
	eor	V31.16B, V7.16B, V27.16B
	bic	x30, x12, x0
	eor	V10.16B, V10.16B, V25.16B
	eor	x11, x0, x11
	ushr	V11.2D, V31.2D, #58
	eor	x12, x12, x27
	ushr	V7.2D, V10.2D, #61
	bic	x0, x15, x14
	sli	V11.2D, V31.2D, #6
	eor	x14, x14, x28
	sli	V7.2D, V10.2D, #3
	eor	x13, x13, x0
	; Row Mix NEON
	bic	V25.16B, V2.16B, V1.16B
	eor	x15, x15, x30
	bic	V26.16B, V3.16B, V2.16B
	bic	x0, x19, x17
	bic	V27.16B, V4.16B, V3.16B
	bic	x27, x20, x19
	bic	V28.16B, V0.16B, V4.16B
	bic	x28, x16, x21
	bic	V29.16B, V1.16B, V0.16B
	bic	x30, x17, x16
	eor	V0.16B, V0.16B, V25.16B
	eor	x16, x16, x0
	eor	V1.16B, V1.16B, V26.16B
	eor	x17, x17, x27
	eor	V2.16B, V2.16B, V27.16B
	bic	x0, x21, x20
	eor	V3.16B, V3.16B, V28.16B
	eor	x20, x20, x28
	eor	V4.16B, V4.16B, V29.16B
	eor	x19, x19, x0
	bic	V25.16B, V7.16B, V6.16B
	eor	x21, x21, x30
	bic	V26.16B, V8.16B, V7.16B
	bic	x0, x24, x23
	bic	V27.16B, V9.16B, V8.16B
	bic	x27, x25, x24
	bic	V28.16B, V5.16B, V9.16B
	bic	x28, x22, x26
	bic	V29.16B, V6.16B, V5.16B
	bic	x30, x23, x22
	eor	V5.16B, V5.16B, V25.16B
	eor	x22, x22, x0
	eor	V6.16B, V6.16B, V26.16B
	eor	x23, x23, x27
	eor	V7.16B, V7.16B, V27.16B
	bic	x0, x26, x25
	eor	V8.16B, V8.16B, V28.16B
	eor	x25, x25, x28
	eor	V9.16B, V9.16B, V29.16B
	eor	x24, x24, x0
	bic	V25.16B, V12.16B, V11.16B
	eor	x26, x26, x30
	bic	V26.16B, V13.16B, V12.16B
	bic	V27.16B, V14.16B, V13.16B
	bic	V28.16B, V30.16B, V14.16B
	bic	V29.16B, V11.16B, V30.16B
	eor	V10.16B, V30.16B, V25.16B
	eor	V11.16B, V11.16B, V26.16B
	eor	V12.16B, V12.16B, V27.16B
	eor	V13.16B, V13.16B, V28.16B
	eor	V14.16B, V14.16B, V29.16B
	bic	V25.16B, V17.16B, V16.16B
	bic	V26.16B, V18.16B, V17.16B
	bic	V27.16B, V19.16B, V18.16B
	bic	V28.16B, V15.16B, V19.16B
	bic	V29.16B, V16.16B, V15.16B
	eor	V15.16B, V15.16B, V25.16B
	eor	V16.16B, V16.16B, V26.16B
	eor	V17.16B, V17.16B, V27.16B
	eor	V18.16B, V18.16B, V28.16B
	eor	V19.16B, V19.16B, V29.16B
	bic	V25.16B, V22.16B, V21.16B
	bic	V26.16B, V23.16B, V22.16B
	bic	V27.16B, V24.16B, V23.16B
	bic	V28.16B, V20.16B, V24.16B
	bic	V29.16B, V21.16B, V20.16B
	eor	V20.16B, V20.16B, V25.16B
	eor	V21.16B, V21.16B, V26.16B
	eor	V22.16B, V22.16B, V27.16B
	eor	V23.16B, V23.16B, V28.16B
	eor	V24.16B, V24.16B, V29.16B
	; Done transforming
	ldp	x27, x28, [x29, #48]
	ldr	x0, [x27], #8
	subs	x28, x28, #1
	mov	V30.D[0], x0
	mov	V30.D[1], x0
	eor	x1, x1, x0
	eor	V0.16B, V0.16B, V30.16B
	bne	L_SHA3_transform_blocksx3_neon_begin
	ldr	x0, [x29, #40]
	st4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	st1	{V24.D}[0], [x0]
	add	x0, x0, #8
	st4	{V0.D, V1.D, V2.D, V3.D}[1], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[1], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[1], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[1], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[1], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[1], [x0], #32
	st1	{V24.D}[1], [x0]
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
	ldp	D8, D9, [x29, #160]
	ldp	D10, D11, [x29, #176]
	ldp	D12, D13, [x29, #192]
	ldp	D14, D15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	sha3_128_blocksx3_seed_neon
sha3_128_blocksx3_seed_neon PROC
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	D8, D9, [x29, #160]
	stp	D10, D11, [x29, #176]
	stp	D12, D13, [x29, #192]
	stp	D14, D15, [x29, #208]
	adrp	x28, L_sha3_aarch64_r
	add	x28, x28, L_sha3_aarch64_r
	str	x0, [x29, #40]
	add	x0, x0, #32
	ld1	{V4.D}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{V4.D}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldr	x6, [x0, #200]
	eor	V5.16B, V5.16B, V5.16B
	eor	x7, x7, x7
	eor	V6.16B, V6.16B, V6.16B
	eor	x8, x8, x8
	eor	V7.16B, V7.16B, V7.16B
	eor	x9, x9, x9
	eor	V8.16B, V8.16B, V8.16B
	eor	x10, x10, x10
	eor	V9.16B, V9.16B, V9.16B
	eor	x11, x11, x11
	eor	V10.16B, V10.16B, V10.16B
	eor	x12, x12, x12
	eor	V11.16B, V11.16B, V11.16B
	eor	x13, x13, x13
	eor	V12.16B, V12.16B, V12.16B
	eor	x14, x14, x14
	eor	V13.16B, V13.16B, V13.16B
	eor	x15, x15, x15
	eor	V14.16B, V14.16B, V14.16B
	eor	x16, x16, x16
	eor	V15.16B, V15.16B, V15.16B
	eor	x17, x17, x17
	eor	V16.16B, V16.16B, V16.16B
	eor	x19, x19, x19
	eor	V17.16B, V17.16B, V17.16B
	eor	x20, x20, x20
	eor	V18.16B, V18.16B, V18.16B
	eor	x21, x21, x21
	eor	V19.16B, V19.16B, V19.16B
	eor	x22, x22, x22
	movz	x23, #0x8000, lsl 48
	eor	V21.16B, V21.16B, V21.16B
	eor	x24, x24, x24
	eor	V22.16B, V22.16B, V22.16B
	eor	x25, x25, x25
	eor	V23.16B, V23.16B, V23.16B
	eor	x26, x26, x26
	eor	V24.16B, V24.16B, V24.16B
	eor	x27, x27, x27
	dup	V0.2D, x2
	dup	V1.2D, x3
	dup	V2.2D, x4
	dup	V3.2D, x5
	dup	V20.2D, x23
	mov	x1, #24
	; Start of 24 rounds
L_SHA3_shake128_blocksx3_seed_neon_begin
	stp	x28, x1, [x29, #48]
	; Col Mix NEON
	eor	V30.16B, V4.16B, V9.16B
	eor	x0, x6, x11
	eor	V27.16B, V1.16B, V6.16B
	eor	x30, x2, x7
	eor	V30.16B, V30.16B, V14.16B
	eor	x28, x4, x9
	eor	V27.16B, V27.16B, V11.16B
	eor	x0, x0, x16
	eor	V30.16B, V30.16B, V19.16B
	eor	x30, x30, x12
	eor	V27.16B, V27.16B, V16.16B
	eor	x28, x28, x14
	eor	V30.16B, V30.16B, V24.16B
	eor	x0, x0, x22
	eor	V27.16B, V27.16B, V21.16B
	eor	x30, x30, x17
	ushr	V25.2D, V27.2D, #63
	eor	x28, x28, x20
	sli	V25.2D, V27.2D, #1
	eor	x0, x0, x27
	eor	V25.16B, V25.16B, V30.16B
	eor	x30, x30, x23
	eor	V31.16B, V0.16B, V5.16B
	eor	x28, x28, x25
	eor	V28.16B, V2.16B, V7.16B
	str	x0, [x29, #32]
	eor	V31.16B, V31.16B, V10.16B
	str	x28, [x29, #24]
	eor	V28.16B, V28.16B, V12.16B
	eor	x1, x3, x8
	eor	V31.16B, V31.16B, V15.16B
	eor	x28, x5, x10
	eor	V28.16B, V28.16B, V17.16B
	eor	x1, x1, x13
	eor	V31.16B, V31.16B, V20.16B
	eor	x28, x28, x15
	eor	V28.16B, V28.16B, V22.16B
	eor	x1, x1, x19
	ushr	V29.2D, V30.2D, #63
	eor	x28, x28, x21
	ushr	V26.2D, V28.2D, #63
	eor	x1, x1, x24
	sli	V29.2D, V30.2D, #1
	eor	x28, x28, x26
	sli	V26.2D, V28.2D, #1
	eor	x0, x0, x1, ror 63
	eor	V28.16B, V28.16B, V29.16B
	eor	x1, x1, x28, ror 63
	eor	V29.16B, V3.16B, V8.16B
	eor	x2, x2, x0
	eor	V26.16B, V26.16B, V31.16B
	eor	x7, x7, x0
	eor	V29.16B, V29.16B, V13.16B
	eor	x12, x12, x0
	eor	V29.16B, V29.16B, V18.16B
	eor	x17, x17, x0
	eor	V29.16B, V29.16B, V23.16B
	eor	x23, x23, x0
	ushr	V30.2D, V29.2D, #63
	eor	x4, x4, x1
	sli	V30.2D, V29.2D, #1
	eor	x9, x9, x1
	eor	V27.16B, V27.16B, V30.16B
	eor	x14, x14, x1
	ushr	V30.2D, V31.2D, #63
	eor	x20, x20, x1
	sli	V30.2D, V31.2D, #1
	eor	x25, x25, x1
	eor	V29.16B, V29.16B, V30.16B
	ldr	x0, [x29, #32]
	; Swap Rotate NEON
	eor	V0.16B, V0.16B, V25.16B
	eor	V31.16B, V1.16B, V26.16B
	ldr	x1, [x29, #24]
	eor	V6.16B, V6.16B, V26.16B
	eor	x28, x28, x30, ror 63
	ushr	V30.2D, V31.2D, #63
	eor	x30, x30, x1, ror 63
	ushr	V1.2D, V6.2D, #20
	eor	x1, x1, x0, ror 63
	sli	V30.2D, V31.2D, #1
	eor	x6, x6, x28
	sli	V1.2D, V6.2D, #44
	eor	x11, x11, x28
	eor	V31.16B, V9.16B, V29.16B
	eor	x16, x16, x28
	eor	V22.16B, V22.16B, V27.16B
	eor	x22, x22, x28
	ushr	V6.2D, V31.2D, #44
	eor	x27, x27, x28
	ushr	V9.2D, V22.2D, #3
	eor	x3, x3, x30
	sli	V6.2D, V31.2D, #20
	eor	x8, x8, x30
	sli	V9.2D, V22.2D, #61
	eor	x13, x13, x30
	eor	V31.16B, V14.16B, V29.16B
	eor	x19, x19, x30
	eor	V20.16B, V20.16B, V25.16B
	eor	x24, x24, x30
	ushr	V22.2D, V31.2D, #25
	eor	x5, x5, x1
	ushr	V14.2D, V20.2D, #46
	eor	x10, x10, x1
	sli	V22.2D, V31.2D, #39
	eor	x15, x15, x1
	sli	V14.2D, V20.2D, #18
	eor	x21, x21, x1
	eor	V31.16B, V2.16B, V27.16B
	eor	x26, x26, x1
	; Swap Rotate Base
	eor	V12.16B, V12.16B, V27.16B
	ror	x0, x3, #63
	ushr	V20.2D, V31.2D, #2
	ror	x3, x8, #20
	ushr	V2.2D, V12.2D, #21
	ror	x8, x11, #44
	sli	V20.2D, V31.2D, #62
	ror	x11, x25, #3
	sli	V2.2D, V12.2D, #43
	ror	x25, x16, #25
	eor	V31.16B, V13.16B, V28.16B
	ror	x16, x23, #46
	eor	V19.16B, V19.16B, V29.16B
	ror	x23, x4, #2
	ushr	V12.2D, V31.2D, #39
	ror	x4, x14, #21
	ushr	V13.2D, V19.2D, #56
	ror	x14, x15, #39
	sli	V12.2D, V31.2D, #25
	ror	x15, x22, #56
	sli	V13.2D, V19.2D, #8
	ror	x22, x26, #8
	eor	V31.16B, V23.16B, V28.16B
	ror	x26, x17, #23
	eor	V15.16B, V15.16B, V25.16B
	ror	x17, x6, #37
	ushr	V19.2D, V31.2D, #8
	ror	x6, x27, #50
	ushr	V23.2D, V15.2D, #23
	ror	x27, x24, #62
	sli	V19.2D, V31.2D, #56
	ror	x24, x10, #9
	sli	V23.2D, V15.2D, #41
	ror	x10, x19, #19
	eor	V31.16B, V4.16B, V29.16B
	ror	x19, x7, #28
	eor	V24.16B, V24.16B, V29.16B
	ror	x7, x5, #36
	ushr	V15.2D, V31.2D, #37
	ror	x5, x21, #43
	ushr	V4.2D, V24.2D, #50
	ror	x21, x20, #49
	sli	V15.2D, V31.2D, #27
	ror	x20, x13, #54
	sli	V4.2D, V24.2D, #14
	ror	x13, x9, #58
	eor	V31.16B, V21.16B, V26.16B
	ror	x9, x12, #61
	; Row Mix Base
	eor	V8.16B, V8.16B, V28.16B
	bic	x12, x4, x3
	ushr	V24.2D, V31.2D, #62
	bic	x1, x5, x4
	ushr	V21.2D, V8.2D, #9
	bic	x28, x2, x6
	sli	V24.2D, V31.2D, #2
	bic	x30, x3, x2
	sli	V21.2D, V8.2D, #55
	eor	x2, x2, x12
	eor	V31.16B, V16.16B, V26.16B
	eor	x3, x3, x1
	eor	V5.16B, V5.16B, V25.16B
	bic	x12, x6, x5
	ushr	V8.2D, V31.2D, #19
	eor	x5, x5, x28
	ushr	V16.2D, V5.2D, #28
	eor	x4, x4, x12
	sli	V8.2D, V31.2D, #45
	eor	x6, x6, x30
	sli	V16.2D, V5.2D, #36
	bic	x12, x9, x8
	eor	V31.16B, V3.16B, V28.16B
	bic	x1, x10, x9
	eor	V18.16B, V18.16B, V28.16B
	bic	x28, x7, x11
	ushr	V5.2D, V31.2D, #36
	bic	x30, x8, x7
	ushr	V3.2D, V18.2D, #43
	eor	x7, x7, x12
	sli	V5.2D, V31.2D, #28
	eor	x8, x8, x1
	sli	V3.2D, V18.2D, #21
	bic	x12, x11, x10
	eor	V31.16B, V17.16B, V27.16B
	eor	x10, x10, x28
	eor	V11.16B, V11.16B, V26.16B
	eor	x9, x9, x12
	ushr	V18.2D, V31.2D, #49
	eor	x11, x11, x30
	ushr	V17.2D, V11.2D, #54
	bic	x12, x14, x13
	sli	V18.2D, V31.2D, #15
	bic	x1, x15, x14
	sli	V17.2D, V11.2D, #10
	bic	x28, x0, x16
	eor	V31.16B, V7.16B, V27.16B
	bic	x30, x13, x0
	eor	V10.16B, V10.16B, V25.16B
	eor	x12, x0, x12
	ushr	V11.2D, V31.2D, #58
	eor	x13, x13, x1
	ushr	V7.2D, V10.2D, #61
	bic	x0, x16, x15
	sli	V11.2D, V31.2D, #6
	eor	x15, x15, x28
	sli	V7.2D, V10.2D, #3
	eor	x14, x14, x0
	; Row Mix NEON
	bic	V25.16B, V2.16B, V1.16B
	eor	x16, x16, x30
	bic	V26.16B, V3.16B, V2.16B
	bic	x0, x20, x19
	bic	V27.16B, V4.16B, V3.16B
	bic	x1, x21, x20
	bic	V28.16B, V0.16B, V4.16B
	bic	x28, x17, x22
	bic	V29.16B, V1.16B, V0.16B
	bic	x30, x19, x17
	eor	V0.16B, V0.16B, V25.16B
	eor	x17, x17, x0
	eor	V1.16B, V1.16B, V26.16B
	eor	x19, x19, x1
	eor	V2.16B, V2.16B, V27.16B
	bic	x0, x22, x21
	eor	V3.16B, V3.16B, V28.16B
	eor	x21, x21, x28
	eor	V4.16B, V4.16B, V29.16B
	eor	x20, x20, x0
	bic	V25.16B, V7.16B, V6.16B
	eor	x22, x22, x30
	bic	V26.16B, V8.16B, V7.16B
	bic	x0, x25, x24
	bic	V27.16B, V9.16B, V8.16B
	bic	x1, x26, x25
	bic	V28.16B, V5.16B, V9.16B
	bic	x28, x23, x27
	bic	V29.16B, V6.16B, V5.16B
	bic	x30, x24, x23
	eor	V5.16B, V5.16B, V25.16B
	eor	x23, x23, x0
	eor	V6.16B, V6.16B, V26.16B
	eor	x24, x24, x1
	eor	V7.16B, V7.16B, V27.16B
	bic	x0, x27, x26
	eor	V8.16B, V8.16B, V28.16B
	eor	x26, x26, x28
	eor	V9.16B, V9.16B, V29.16B
	eor	x25, x25, x0
	bic	V25.16B, V12.16B, V11.16B
	eor	x27, x27, x30
	bic	V26.16B, V13.16B, V12.16B
	bic	V27.16B, V14.16B, V13.16B
	bic	V28.16B, V30.16B, V14.16B
	bic	V29.16B, V11.16B, V30.16B
	eor	V10.16B, V30.16B, V25.16B
	eor	V11.16B, V11.16B, V26.16B
	eor	V12.16B, V12.16B, V27.16B
	eor	V13.16B, V13.16B, V28.16B
	eor	V14.16B, V14.16B, V29.16B
	bic	V25.16B, V17.16B, V16.16B
	bic	V26.16B, V18.16B, V17.16B
	bic	V27.16B, V19.16B, V18.16B
	bic	V28.16B, V15.16B, V19.16B
	bic	V29.16B, V16.16B, V15.16B
	eor	V15.16B, V15.16B, V25.16B
	eor	V16.16B, V16.16B, V26.16B
	eor	V17.16B, V17.16B, V27.16B
	eor	V18.16B, V18.16B, V28.16B
	eor	V19.16B, V19.16B, V29.16B
	bic	V25.16B, V22.16B, V21.16B
	bic	V26.16B, V23.16B, V22.16B
	bic	V27.16B, V24.16B, V23.16B
	bic	V28.16B, V20.16B, V24.16B
	bic	V29.16B, V21.16B, V20.16B
	eor	V20.16B, V20.16B, V25.16B
	eor	V21.16B, V21.16B, V26.16B
	eor	V22.16B, V22.16B, V27.16B
	eor	V23.16B, V23.16B, V28.16B
	eor	V24.16B, V24.16B, V29.16B
	; Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	V30.D[0], x0
	mov	V30.D[1], x0
	eor	x2, x2, x0
	eor	V0.16B, V0.16B, V30.16B
	bne	L_SHA3_shake128_blocksx3_seed_neon_begin
	ldr	x0, [x29, #40]
	st4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	st1	{V24.D}[0], [x0]
	add	x0, x0, #8
	st4	{V0.D, V1.D, V2.D, V3.D}[1], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[1], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[1], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[1], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[1], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[1], [x0], #32
	st1	{V24.D}[1], [x0]
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
	ldp	D8, D9, [x29, #160]
	ldp	D10, D11, [x29, #176]
	ldp	D12, D13, [x29, #192]
	ldp	D14, D15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	sha3_256_blocksx3_seed_neon
sha3_256_blocksx3_seed_neon PROC
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	D8, D9, [x29, #160]
	stp	D10, D11, [x29, #176]
	stp	D12, D13, [x29, #192]
	stp	D14, D15, [x29, #208]
	adrp	x28, L_sha3_aarch64_r
	add	x28, x28, L_sha3_aarch64_r
	str	x0, [x29, #40]
	add	x0, x0, #32
	ld1	{V4.D}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{V4.D}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldr	x6, [x0, #200]
	eor	V5.16B, V5.16B, V5.16B
	eor	x7, x7, x7
	eor	V6.16B, V6.16B, V6.16B
	eor	x8, x8, x8
	eor	V7.16B, V7.16B, V7.16B
	eor	x9, x9, x9
	eor	V8.16B, V8.16B, V8.16B
	eor	x10, x10, x10
	eor	V9.16B, V9.16B, V9.16B
	eor	x11, x11, x11
	eor	V10.16B, V10.16B, V10.16B
	eor	x12, x12, x12
	eor	V11.16B, V11.16B, V11.16B
	eor	x13, x13, x13
	eor	V12.16B, V12.16B, V12.16B
	eor	x14, x14, x14
	eor	V13.16B, V13.16B, V13.16B
	eor	x15, x15, x15
	eor	V14.16B, V14.16B, V14.16B
	eor	x16, x16, x16
	eor	V15.16B, V15.16B, V15.16B
	eor	x17, x17, x17
	movz	x19, #0x8000, lsl 48
	eor	V17.16B, V17.16B, V17.16B
	eor	x20, x20, x20
	eor	V18.16B, V18.16B, V18.16B
	eor	x21, x21, x21
	eor	V19.16B, V19.16B, V19.16B
	eor	x22, x22, x22
	eor	V20.16B, V20.16B, V20.16B
	eor	x23, x23, x23
	eor	V21.16B, V21.16B, V21.16B
	eor	x24, x24, x24
	eor	V22.16B, V22.16B, V22.16B
	eor	x25, x25, x25
	eor	V23.16B, V23.16B, V23.16B
	eor	x26, x26, x26
	eor	V24.16B, V24.16B, V24.16B
	eor	x27, x27, x27
	dup	V0.2D, x2
	dup	V1.2D, x3
	dup	V2.2D, x4
	dup	V3.2D, x5
	dup	V16.2D, x19
	mov	x1, #24
	; Start of 24 rounds
L_SHA3_shake256_blocksx3_seed_neon_begin
	stp	x28, x1, [x29, #48]
	; Col Mix NEON
	eor	V30.16B, V4.16B, V9.16B
	eor	x0, x6, x11
	eor	V27.16B, V1.16B, V6.16B
	eor	x30, x2, x7
	eor	V30.16B, V30.16B, V14.16B
	eor	x28, x4, x9
	eor	V27.16B, V27.16B, V11.16B
	eor	x0, x0, x16
	eor	V30.16B, V30.16B, V19.16B
	eor	x30, x30, x12
	eor	V27.16B, V27.16B, V16.16B
	eor	x28, x28, x14
	eor	V30.16B, V30.16B, V24.16B
	eor	x0, x0, x22
	eor	V27.16B, V27.16B, V21.16B
	eor	x30, x30, x17
	ushr	V25.2D, V27.2D, #63
	eor	x28, x28, x20
	sli	V25.2D, V27.2D, #1
	eor	x0, x0, x27
	eor	V25.16B, V25.16B, V30.16B
	eor	x30, x30, x23
	eor	V31.16B, V0.16B, V5.16B
	eor	x28, x28, x25
	eor	V28.16B, V2.16B, V7.16B
	str	x0, [x29, #32]
	eor	V31.16B, V31.16B, V10.16B
	str	x28, [x29, #24]
	eor	V28.16B, V28.16B, V12.16B
	eor	x1, x3, x8
	eor	V31.16B, V31.16B, V15.16B
	eor	x28, x5, x10
	eor	V28.16B, V28.16B, V17.16B
	eor	x1, x1, x13
	eor	V31.16B, V31.16B, V20.16B
	eor	x28, x28, x15
	eor	V28.16B, V28.16B, V22.16B
	eor	x1, x1, x19
	ushr	V29.2D, V30.2D, #63
	eor	x28, x28, x21
	ushr	V26.2D, V28.2D, #63
	eor	x1, x1, x24
	sli	V29.2D, V30.2D, #1
	eor	x28, x28, x26
	sli	V26.2D, V28.2D, #1
	eor	x0, x0, x1, ror 63
	eor	V28.16B, V28.16B, V29.16B
	eor	x1, x1, x28, ror 63
	eor	V29.16B, V3.16B, V8.16B
	eor	x2, x2, x0
	eor	V26.16B, V26.16B, V31.16B
	eor	x7, x7, x0
	eor	V29.16B, V29.16B, V13.16B
	eor	x12, x12, x0
	eor	V29.16B, V29.16B, V18.16B
	eor	x17, x17, x0
	eor	V29.16B, V29.16B, V23.16B
	eor	x23, x23, x0
	ushr	V30.2D, V29.2D, #63
	eor	x4, x4, x1
	sli	V30.2D, V29.2D, #1
	eor	x9, x9, x1
	eor	V27.16B, V27.16B, V30.16B
	eor	x14, x14, x1
	ushr	V30.2D, V31.2D, #63
	eor	x20, x20, x1
	sli	V30.2D, V31.2D, #1
	eor	x25, x25, x1
	eor	V29.16B, V29.16B, V30.16B
	ldr	x0, [x29, #32]
	; Swap Rotate NEON
	eor	V0.16B, V0.16B, V25.16B
	eor	V31.16B, V1.16B, V26.16B
	ldr	x1, [x29, #24]
	eor	V6.16B, V6.16B, V26.16B
	eor	x28, x28, x30, ror 63
	ushr	V30.2D, V31.2D, #63
	eor	x30, x30, x1, ror 63
	ushr	V1.2D, V6.2D, #20
	eor	x1, x1, x0, ror 63
	sli	V30.2D, V31.2D, #1
	eor	x6, x6, x28
	sli	V1.2D, V6.2D, #44
	eor	x11, x11, x28
	eor	V31.16B, V9.16B, V29.16B
	eor	x16, x16, x28
	eor	V22.16B, V22.16B, V27.16B
	eor	x22, x22, x28
	ushr	V6.2D, V31.2D, #44
	eor	x27, x27, x28
	ushr	V9.2D, V22.2D, #3
	eor	x3, x3, x30
	sli	V6.2D, V31.2D, #20
	eor	x8, x8, x30
	sli	V9.2D, V22.2D, #61
	eor	x13, x13, x30
	eor	V31.16B, V14.16B, V29.16B
	eor	x19, x19, x30
	eor	V20.16B, V20.16B, V25.16B
	eor	x24, x24, x30
	ushr	V22.2D, V31.2D, #25
	eor	x5, x5, x1
	ushr	V14.2D, V20.2D, #46
	eor	x10, x10, x1
	sli	V22.2D, V31.2D, #39
	eor	x15, x15, x1
	sli	V14.2D, V20.2D, #18
	eor	x21, x21, x1
	eor	V31.16B, V2.16B, V27.16B
	eor	x26, x26, x1
	; Swap Rotate Base
	eor	V12.16B, V12.16B, V27.16B
	ror	x0, x3, #63
	ushr	V20.2D, V31.2D, #2
	ror	x3, x8, #20
	ushr	V2.2D, V12.2D, #21
	ror	x8, x11, #44
	sli	V20.2D, V31.2D, #62
	ror	x11, x25, #3
	sli	V2.2D, V12.2D, #43
	ror	x25, x16, #25
	eor	V31.16B, V13.16B, V28.16B
	ror	x16, x23, #46
	eor	V19.16B, V19.16B, V29.16B
	ror	x23, x4, #2
	ushr	V12.2D, V31.2D, #39
	ror	x4, x14, #21
	ushr	V13.2D, V19.2D, #56
	ror	x14, x15, #39
	sli	V12.2D, V31.2D, #25
	ror	x15, x22, #56
	sli	V13.2D, V19.2D, #8
	ror	x22, x26, #8
	eor	V31.16B, V23.16B, V28.16B
	ror	x26, x17, #23
	eor	V15.16B, V15.16B, V25.16B
	ror	x17, x6, #37
	ushr	V19.2D, V31.2D, #8
	ror	x6, x27, #50
	ushr	V23.2D, V15.2D, #23
	ror	x27, x24, #62
	sli	V19.2D, V31.2D, #56
	ror	x24, x10, #9
	sli	V23.2D, V15.2D, #41
	ror	x10, x19, #19
	eor	V31.16B, V4.16B, V29.16B
	ror	x19, x7, #28
	eor	V24.16B, V24.16B, V29.16B
	ror	x7, x5, #36
	ushr	V15.2D, V31.2D, #37
	ror	x5, x21, #43
	ushr	V4.2D, V24.2D, #50
	ror	x21, x20, #49
	sli	V15.2D, V31.2D, #27
	ror	x20, x13, #54
	sli	V4.2D, V24.2D, #14
	ror	x13, x9, #58
	eor	V31.16B, V21.16B, V26.16B
	ror	x9, x12, #61
	; Row Mix Base
	eor	V8.16B, V8.16B, V28.16B
	bic	x12, x4, x3
	ushr	V24.2D, V31.2D, #62
	bic	x1, x5, x4
	ushr	V21.2D, V8.2D, #9
	bic	x28, x2, x6
	sli	V24.2D, V31.2D, #2
	bic	x30, x3, x2
	sli	V21.2D, V8.2D, #55
	eor	x2, x2, x12
	eor	V31.16B, V16.16B, V26.16B
	eor	x3, x3, x1
	eor	V5.16B, V5.16B, V25.16B
	bic	x12, x6, x5
	ushr	V8.2D, V31.2D, #19
	eor	x5, x5, x28
	ushr	V16.2D, V5.2D, #28
	eor	x4, x4, x12
	sli	V8.2D, V31.2D, #45
	eor	x6, x6, x30
	sli	V16.2D, V5.2D, #36
	bic	x12, x9, x8
	eor	V31.16B, V3.16B, V28.16B
	bic	x1, x10, x9
	eor	V18.16B, V18.16B, V28.16B
	bic	x28, x7, x11
	ushr	V5.2D, V31.2D, #36
	bic	x30, x8, x7
	ushr	V3.2D, V18.2D, #43
	eor	x7, x7, x12
	sli	V5.2D, V31.2D, #28
	eor	x8, x8, x1
	sli	V3.2D, V18.2D, #21
	bic	x12, x11, x10
	eor	V31.16B, V17.16B, V27.16B
	eor	x10, x10, x28
	eor	V11.16B, V11.16B, V26.16B
	eor	x9, x9, x12
	ushr	V18.2D, V31.2D, #49
	eor	x11, x11, x30
	ushr	V17.2D, V11.2D, #54
	bic	x12, x14, x13
	sli	V18.2D, V31.2D, #15
	bic	x1, x15, x14
	sli	V17.2D, V11.2D, #10
	bic	x28, x0, x16
	eor	V31.16B, V7.16B, V27.16B
	bic	x30, x13, x0
	eor	V10.16B, V10.16B, V25.16B
	eor	x12, x0, x12
	ushr	V11.2D, V31.2D, #58
	eor	x13, x13, x1
	ushr	V7.2D, V10.2D, #61
	bic	x0, x16, x15
	sli	V11.2D, V31.2D, #6
	eor	x15, x15, x28
	sli	V7.2D, V10.2D, #3
	eor	x14, x14, x0
	; Row Mix NEON
	bic	V25.16B, V2.16B, V1.16B
	eor	x16, x16, x30
	bic	V26.16B, V3.16B, V2.16B
	bic	x0, x20, x19
	bic	V27.16B, V4.16B, V3.16B
	bic	x1, x21, x20
	bic	V28.16B, V0.16B, V4.16B
	bic	x28, x17, x22
	bic	V29.16B, V1.16B, V0.16B
	bic	x30, x19, x17
	eor	V0.16B, V0.16B, V25.16B
	eor	x17, x17, x0
	eor	V1.16B, V1.16B, V26.16B
	eor	x19, x19, x1
	eor	V2.16B, V2.16B, V27.16B
	bic	x0, x22, x21
	eor	V3.16B, V3.16B, V28.16B
	eor	x21, x21, x28
	eor	V4.16B, V4.16B, V29.16B
	eor	x20, x20, x0
	bic	V25.16B, V7.16B, V6.16B
	eor	x22, x22, x30
	bic	V26.16B, V8.16B, V7.16B
	bic	x0, x25, x24
	bic	V27.16B, V9.16B, V8.16B
	bic	x1, x26, x25
	bic	V28.16B, V5.16B, V9.16B
	bic	x28, x23, x27
	bic	V29.16B, V6.16B, V5.16B
	bic	x30, x24, x23
	eor	V5.16B, V5.16B, V25.16B
	eor	x23, x23, x0
	eor	V6.16B, V6.16B, V26.16B
	eor	x24, x24, x1
	eor	V7.16B, V7.16B, V27.16B
	bic	x0, x27, x26
	eor	V8.16B, V8.16B, V28.16B
	eor	x26, x26, x28
	eor	V9.16B, V9.16B, V29.16B
	eor	x25, x25, x0
	bic	V25.16B, V12.16B, V11.16B
	eor	x27, x27, x30
	bic	V26.16B, V13.16B, V12.16B
	bic	V27.16B, V14.16B, V13.16B
	bic	V28.16B, V30.16B, V14.16B
	bic	V29.16B, V11.16B, V30.16B
	eor	V10.16B, V30.16B, V25.16B
	eor	V11.16B, V11.16B, V26.16B
	eor	V12.16B, V12.16B, V27.16B
	eor	V13.16B, V13.16B, V28.16B
	eor	V14.16B, V14.16B, V29.16B
	bic	V25.16B, V17.16B, V16.16B
	bic	V26.16B, V18.16B, V17.16B
	bic	V27.16B, V19.16B, V18.16B
	bic	V28.16B, V15.16B, V19.16B
	bic	V29.16B, V16.16B, V15.16B
	eor	V15.16B, V15.16B, V25.16B
	eor	V16.16B, V16.16B, V26.16B
	eor	V17.16B, V17.16B, V27.16B
	eor	V18.16B, V18.16B, V28.16B
	eor	V19.16B, V19.16B, V29.16B
	bic	V25.16B, V22.16B, V21.16B
	bic	V26.16B, V23.16B, V22.16B
	bic	V27.16B, V24.16B, V23.16B
	bic	V28.16B, V20.16B, V24.16B
	bic	V29.16B, V21.16B, V20.16B
	eor	V20.16B, V20.16B, V25.16B
	eor	V21.16B, V21.16B, V26.16B
	eor	V22.16B, V22.16B, V27.16B
	eor	V23.16B, V23.16B, V28.16B
	eor	V24.16B, V24.16B, V29.16B
	; Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	V30.D[0], x0
	mov	V30.D[1], x0
	eor	x2, x2, x0
	eor	V0.16B, V0.16B, V30.16B
	bne	L_SHA3_shake256_blocksx3_seed_neon_begin
	ldr	x0, [x29, #40]
	st4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	st1	{V24.D}[0], [x0]
	add	x0, x0, #8
	st4	{V0.D, V1.D, V2.D, V3.D}[1], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[1], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[1], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[1], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[1], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[1], [x0], #32
	st1	{V24.D}[1], [x0]
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
	ldp	D8, D9, [x29, #160]
	ldp	D10, D11, [x29, #176]
	ldp	D12, D13, [x29, #192]
	ldp	D14, D15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	sha3_256_blocksx3_seed_64_neon
sha3_256_blocksx3_seed_64_neon PROC
	stp	x29, x30, [sp, #-224]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #72]
	stp	x20, x21, [x29, #88]
	stp	x22, x23, [x29, #104]
	stp	x24, x25, [x29, #120]
	stp	x26, x27, [x29, #136]
	str	x28, [x29, #152]
	stp	D8, D9, [x29, #160]
	stp	D10, D11, [x29, #176]
	stp	D12, D13, [x29, #192]
	stp	D14, D15, [x29, #208]
	adrp	x28, L_sha3_aarch64_r
	add	x28, x28, L_sha3_aarch64_r
	str	x0, [x29, #40]
	add	x0, x0, #0x40
	ld1	{V8.D}[0], [x0]
	ldp	x2, x3, [x1], #16
	add	x0, x0, #0xc8
	ld1	{V8.D}[1], [x0]
	ldp	x4, x5, [x1], #16
	ldp	x6, x7, [x1], #16
	ldp	x8, x9, [x1], #16
	ldr	x10, [x0, #200]
	eor	V9.16B, V9.16B, V9.16B
	eor	x11, x11, x11
	eor	V10.16B, V10.16B, V10.16B
	eor	x12, x12, x12
	eor	V11.16B, V11.16B, V11.16B
	eor	x13, x13, x13
	eor	V12.16B, V12.16B, V12.16B
	eor	x14, x14, x14
	eor	V13.16B, V13.16B, V13.16B
	eor	x15, x15, x15
	eor	V14.16B, V14.16B, V14.16B
	eor	x16, x16, x16
	eor	V15.16B, V15.16B, V15.16B
	eor	x17, x17, x17
	movz	x19, #0x8000, lsl 48
	eor	V17.16B, V17.16B, V17.16B
	eor	x20, x20, x20
	eor	V18.16B, V18.16B, V18.16B
	eor	x21, x21, x21
	eor	V19.16B, V19.16B, V19.16B
	eor	x22, x22, x22
	eor	V20.16B, V20.16B, V20.16B
	eor	x23, x23, x23
	eor	V21.16B, V21.16B, V21.16B
	eor	x24, x24, x24
	eor	V22.16B, V22.16B, V22.16B
	eor	x25, x25, x25
	eor	V23.16B, V23.16B, V23.16B
	eor	x26, x26, x26
	eor	V24.16B, V24.16B, V24.16B
	eor	x27, x27, x27
	dup	V0.2D, x2
	dup	V1.2D, x3
	dup	V2.2D, x4
	dup	V3.2D, x5
	dup	V4.2D, x6
	dup	V5.2D, x7
	dup	V6.2D, x8
	dup	V7.2D, x9
	dup	V16.2D, x19
	mov	x1, #24
	; Start of 24 rounds
L_SHA3_shake256_blocksx3_seed_64_neon_begin
	stp	x28, x1, [x29, #48]
	; Col Mix NEON
	eor	V30.16B, V4.16B, V9.16B
	eor	x0, x6, x11
	eor	V27.16B, V1.16B, V6.16B
	eor	x30, x2, x7
	eor	V30.16B, V30.16B, V14.16B
	eor	x28, x4, x9
	eor	V27.16B, V27.16B, V11.16B
	eor	x0, x0, x16
	eor	V30.16B, V30.16B, V19.16B
	eor	x30, x30, x12
	eor	V27.16B, V27.16B, V16.16B
	eor	x28, x28, x14
	eor	V30.16B, V30.16B, V24.16B
	eor	x0, x0, x22
	eor	V27.16B, V27.16B, V21.16B
	eor	x30, x30, x17
	ushr	V25.2D, V27.2D, #63
	eor	x28, x28, x20
	sli	V25.2D, V27.2D, #1
	eor	x0, x0, x27
	eor	V25.16B, V25.16B, V30.16B
	eor	x30, x30, x23
	eor	V31.16B, V0.16B, V5.16B
	eor	x28, x28, x25
	eor	V28.16B, V2.16B, V7.16B
	str	x0, [x29, #32]
	eor	V31.16B, V31.16B, V10.16B
	str	x28, [x29, #24]
	eor	V28.16B, V28.16B, V12.16B
	eor	x1, x3, x8
	eor	V31.16B, V31.16B, V15.16B
	eor	x28, x5, x10
	eor	V28.16B, V28.16B, V17.16B
	eor	x1, x1, x13
	eor	V31.16B, V31.16B, V20.16B
	eor	x28, x28, x15
	eor	V28.16B, V28.16B, V22.16B
	eor	x1, x1, x19
	ushr	V29.2D, V30.2D, #63
	eor	x28, x28, x21
	ushr	V26.2D, V28.2D, #63
	eor	x1, x1, x24
	sli	V29.2D, V30.2D, #1
	eor	x28, x28, x26
	sli	V26.2D, V28.2D, #1
	eor	x0, x0, x1, ror 63
	eor	V28.16B, V28.16B, V29.16B
	eor	x1, x1, x28, ror 63
	eor	V29.16B, V3.16B, V8.16B
	eor	x2, x2, x0
	eor	V26.16B, V26.16B, V31.16B
	eor	x7, x7, x0
	eor	V29.16B, V29.16B, V13.16B
	eor	x12, x12, x0
	eor	V29.16B, V29.16B, V18.16B
	eor	x17, x17, x0
	eor	V29.16B, V29.16B, V23.16B
	eor	x23, x23, x0
	ushr	V30.2D, V29.2D, #63
	eor	x4, x4, x1
	sli	V30.2D, V29.2D, #1
	eor	x9, x9, x1
	eor	V27.16B, V27.16B, V30.16B
	eor	x14, x14, x1
	ushr	V30.2D, V31.2D, #63
	eor	x20, x20, x1
	sli	V30.2D, V31.2D, #1
	eor	x25, x25, x1
	eor	V29.16B, V29.16B, V30.16B
	ldr	x0, [x29, #32]
	; Swap Rotate NEON
	eor	V0.16B, V0.16B, V25.16B
	eor	V31.16B, V1.16B, V26.16B
	ldr	x1, [x29, #24]
	eor	V6.16B, V6.16B, V26.16B
	eor	x28, x28, x30, ror 63
	ushr	V30.2D, V31.2D, #63
	eor	x30, x30, x1, ror 63
	ushr	V1.2D, V6.2D, #20
	eor	x1, x1, x0, ror 63
	sli	V30.2D, V31.2D, #1
	eor	x6, x6, x28
	sli	V1.2D, V6.2D, #44
	eor	x11, x11, x28
	eor	V31.16B, V9.16B, V29.16B
	eor	x16, x16, x28
	eor	V22.16B, V22.16B, V27.16B
	eor	x22, x22, x28
	ushr	V6.2D, V31.2D, #44
	eor	x27, x27, x28
	ushr	V9.2D, V22.2D, #3
	eor	x3, x3, x30
	sli	V6.2D, V31.2D, #20
	eor	x8, x8, x30
	sli	V9.2D, V22.2D, #61
	eor	x13, x13, x30
	eor	V31.16B, V14.16B, V29.16B
	eor	x19, x19, x30
	eor	V20.16B, V20.16B, V25.16B
	eor	x24, x24, x30
	ushr	V22.2D, V31.2D, #25
	eor	x5, x5, x1
	ushr	V14.2D, V20.2D, #46
	eor	x10, x10, x1
	sli	V22.2D, V31.2D, #39
	eor	x15, x15, x1
	sli	V14.2D, V20.2D, #18
	eor	x21, x21, x1
	eor	V31.16B, V2.16B, V27.16B
	eor	x26, x26, x1
	; Swap Rotate Base
	eor	V12.16B, V12.16B, V27.16B
	ror	x0, x3, #63
	ushr	V20.2D, V31.2D, #2
	ror	x3, x8, #20
	ushr	V2.2D, V12.2D, #21
	ror	x8, x11, #44
	sli	V20.2D, V31.2D, #62
	ror	x11, x25, #3
	sli	V2.2D, V12.2D, #43
	ror	x25, x16, #25
	eor	V31.16B, V13.16B, V28.16B
	ror	x16, x23, #46
	eor	V19.16B, V19.16B, V29.16B
	ror	x23, x4, #2
	ushr	V12.2D, V31.2D, #39
	ror	x4, x14, #21
	ushr	V13.2D, V19.2D, #56
	ror	x14, x15, #39
	sli	V12.2D, V31.2D, #25
	ror	x15, x22, #56
	sli	V13.2D, V19.2D, #8
	ror	x22, x26, #8
	eor	V31.16B, V23.16B, V28.16B
	ror	x26, x17, #23
	eor	V15.16B, V15.16B, V25.16B
	ror	x17, x6, #37
	ushr	V19.2D, V31.2D, #8
	ror	x6, x27, #50
	ushr	V23.2D, V15.2D, #23
	ror	x27, x24, #62
	sli	V19.2D, V31.2D, #56
	ror	x24, x10, #9
	sli	V23.2D, V15.2D, #41
	ror	x10, x19, #19
	eor	V31.16B, V4.16B, V29.16B
	ror	x19, x7, #28
	eor	V24.16B, V24.16B, V29.16B
	ror	x7, x5, #36
	ushr	V15.2D, V31.2D, #37
	ror	x5, x21, #43
	ushr	V4.2D, V24.2D, #50
	ror	x21, x20, #49
	sli	V15.2D, V31.2D, #27
	ror	x20, x13, #54
	sli	V4.2D, V24.2D, #14
	ror	x13, x9, #58
	eor	V31.16B, V21.16B, V26.16B
	ror	x9, x12, #61
	; Row Mix Base
	eor	V8.16B, V8.16B, V28.16B
	bic	x12, x4, x3
	ushr	V24.2D, V31.2D, #62
	bic	x1, x5, x4
	ushr	V21.2D, V8.2D, #9
	bic	x28, x2, x6
	sli	V24.2D, V31.2D, #2
	bic	x30, x3, x2
	sli	V21.2D, V8.2D, #55
	eor	x2, x2, x12
	eor	V31.16B, V16.16B, V26.16B
	eor	x3, x3, x1
	eor	V5.16B, V5.16B, V25.16B
	bic	x12, x6, x5
	ushr	V8.2D, V31.2D, #19
	eor	x5, x5, x28
	ushr	V16.2D, V5.2D, #28
	eor	x4, x4, x12
	sli	V8.2D, V31.2D, #45
	eor	x6, x6, x30
	sli	V16.2D, V5.2D, #36
	bic	x12, x9, x8
	eor	V31.16B, V3.16B, V28.16B
	bic	x1, x10, x9
	eor	V18.16B, V18.16B, V28.16B
	bic	x28, x7, x11
	ushr	V5.2D, V31.2D, #36
	bic	x30, x8, x7
	ushr	V3.2D, V18.2D, #43
	eor	x7, x7, x12
	sli	V5.2D, V31.2D, #28
	eor	x8, x8, x1
	sli	V3.2D, V18.2D, #21
	bic	x12, x11, x10
	eor	V31.16B, V17.16B, V27.16B
	eor	x10, x10, x28
	eor	V11.16B, V11.16B, V26.16B
	eor	x9, x9, x12
	ushr	V18.2D, V31.2D, #49
	eor	x11, x11, x30
	ushr	V17.2D, V11.2D, #54
	bic	x12, x14, x13
	sli	V18.2D, V31.2D, #15
	bic	x1, x15, x14
	sli	V17.2D, V11.2D, #10
	bic	x28, x0, x16
	eor	V31.16B, V7.16B, V27.16B
	bic	x30, x13, x0
	eor	V10.16B, V10.16B, V25.16B
	eor	x12, x0, x12
	ushr	V11.2D, V31.2D, #58
	eor	x13, x13, x1
	ushr	V7.2D, V10.2D, #61
	bic	x0, x16, x15
	sli	V11.2D, V31.2D, #6
	eor	x15, x15, x28
	sli	V7.2D, V10.2D, #3
	eor	x14, x14, x0
	; Row Mix NEON
	bic	V25.16B, V2.16B, V1.16B
	eor	x16, x16, x30
	bic	V26.16B, V3.16B, V2.16B
	bic	x0, x20, x19
	bic	V27.16B, V4.16B, V3.16B
	bic	x1, x21, x20
	bic	V28.16B, V0.16B, V4.16B
	bic	x28, x17, x22
	bic	V29.16B, V1.16B, V0.16B
	bic	x30, x19, x17
	eor	V0.16B, V0.16B, V25.16B
	eor	x17, x17, x0
	eor	V1.16B, V1.16B, V26.16B
	eor	x19, x19, x1
	eor	V2.16B, V2.16B, V27.16B
	bic	x0, x22, x21
	eor	V3.16B, V3.16B, V28.16B
	eor	x21, x21, x28
	eor	V4.16B, V4.16B, V29.16B
	eor	x20, x20, x0
	bic	V25.16B, V7.16B, V6.16B
	eor	x22, x22, x30
	bic	V26.16B, V8.16B, V7.16B
	bic	x0, x25, x24
	bic	V27.16B, V9.16B, V8.16B
	bic	x1, x26, x25
	bic	V28.16B, V5.16B, V9.16B
	bic	x28, x23, x27
	bic	V29.16B, V6.16B, V5.16B
	bic	x30, x24, x23
	eor	V5.16B, V5.16B, V25.16B
	eor	x23, x23, x0
	eor	V6.16B, V6.16B, V26.16B
	eor	x24, x24, x1
	eor	V7.16B, V7.16B, V27.16B
	bic	x0, x27, x26
	eor	V8.16B, V8.16B, V28.16B
	eor	x26, x26, x28
	eor	V9.16B, V9.16B, V29.16B
	eor	x25, x25, x0
	bic	V25.16B, V12.16B, V11.16B
	eor	x27, x27, x30
	bic	V26.16B, V13.16B, V12.16B
	bic	V27.16B, V14.16B, V13.16B
	bic	V28.16B, V30.16B, V14.16B
	bic	V29.16B, V11.16B, V30.16B
	eor	V10.16B, V30.16B, V25.16B
	eor	V11.16B, V11.16B, V26.16B
	eor	V12.16B, V12.16B, V27.16B
	eor	V13.16B, V13.16B, V28.16B
	eor	V14.16B, V14.16B, V29.16B
	bic	V25.16B, V17.16B, V16.16B
	bic	V26.16B, V18.16B, V17.16B
	bic	V27.16B, V19.16B, V18.16B
	bic	V28.16B, V15.16B, V19.16B
	bic	V29.16B, V16.16B, V15.16B
	eor	V15.16B, V15.16B, V25.16B
	eor	V16.16B, V16.16B, V26.16B
	eor	V17.16B, V17.16B, V27.16B
	eor	V18.16B, V18.16B, V28.16B
	eor	V19.16B, V19.16B, V29.16B
	bic	V25.16B, V22.16B, V21.16B
	bic	V26.16B, V23.16B, V22.16B
	bic	V27.16B, V24.16B, V23.16B
	bic	V28.16B, V20.16B, V24.16B
	bic	V29.16B, V21.16B, V20.16B
	eor	V20.16B, V20.16B, V25.16B
	eor	V21.16B, V21.16B, V26.16B
	eor	V22.16B, V22.16B, V27.16B
	eor	V23.16B, V23.16B, V28.16B
	eor	V24.16B, V24.16B, V29.16B
	; Done transforming
	ldp	x28, x1, [x29, #48]
	ldr	x0, [x28], #8
	subs	x1, x1, #1
	mov	V30.D[0], x0
	mov	V30.D[1], x0
	eor	x2, x2, x0
	eor	V0.16B, V0.16B, V30.16B
	bne	L_SHA3_shake256_blocksx3_seed_64_neon_begin
	ldr	x0, [x29, #40]
	st4	{V0.D, V1.D, V2.D, V3.D}[0], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[0], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[0], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[0], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[0], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[0], [x0], #32
	st1	{V24.D}[0], [x0]
	add	x0, x0, #8
	st4	{V0.D, V1.D, V2.D, V3.D}[1], [x0], #32
	st4	{V4.D, V5.D, V6.D, V7.D}[1], [x0], #32
	st4	{V8.D, V9.D, V10.D, V11.D}[1], [x0], #32
	st4	{V12.D, V13.D, V14.D, V15.D}[1], [x0], #32
	st4	{V16.D, V17.D, V18.D, V19.D}[1], [x0], #32
	st4	{V20.D, V21.D, V22.D, V23.D}[1], [x0], #32
	st1	{V24.D}[1], [x0]
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
	ldp	D8, D9, [x29, #160]
	ldp	D10, D11, [x29, #176]
	ldp	D12, D13, [x29, #192]
	ldp	D14, D15, [x29, #208]
	ldp	x29, x30, [sp], #0xe0
	ret
	ENDP
	ENDIF
	ENDIF
	END
