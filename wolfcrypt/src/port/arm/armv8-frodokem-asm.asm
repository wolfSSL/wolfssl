; /* armv8-frodokem-asm
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
;   ruby ./frodokem/frodokem.rb arm64 \
;       ../wolfssl/wolfcrypt/src/port/arm/armv8-frodokem-asm.asm
	IF :DEF:WOLFSSL_HAVE_FRODOKEM
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
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	frodokem_sha3_x2_neon
frodokem_sha3_x2_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x1, L_sha3_aarch64_r
	add	x1, x1, L_sha3_aarch64_r
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
	sub	x0, x0, #0x190
	mov	x2, #24
L_frodokem_sha3_x2_neon_begin
	; Col Mix NEON
	eor	V30.16B, V4.16B, V9.16B
	eor	V27.16B, V1.16B, V6.16B
	eor	V30.16B, V30.16B, V14.16B
	eor	V27.16B, V27.16B, V11.16B
	eor	V30.16B, V30.16B, V19.16B
	eor	V27.16B, V27.16B, V16.16B
	eor	V30.16B, V30.16B, V24.16B
	eor	V27.16B, V27.16B, V21.16B
	ushr	V25.2D, V27.2D, #63
	sli	V25.2D, V27.2D, #1
	eor	V25.16B, V25.16B, V30.16B
	eor	V31.16B, V0.16B, V5.16B
	eor	V28.16B, V2.16B, V7.16B
	eor	V31.16B, V31.16B, V10.16B
	eor	V28.16B, V28.16B, V12.16B
	eor	V31.16B, V31.16B, V15.16B
	eor	V28.16B, V28.16B, V17.16B
	eor	V31.16B, V31.16B, V20.16B
	eor	V28.16B, V28.16B, V22.16B
	ushr	V29.2D, V30.2D, #63
	ushr	V26.2D, V28.2D, #63
	sli	V29.2D, V30.2D, #1
	sli	V26.2D, V28.2D, #1
	eor	V28.16B, V28.16B, V29.16B
	eor	V29.16B, V3.16B, V8.16B
	eor	V26.16B, V26.16B, V31.16B
	eor	V29.16B, V29.16B, V13.16B
	eor	V29.16B, V29.16B, V18.16B
	eor	V29.16B, V29.16B, V23.16B
	ushr	V30.2D, V29.2D, #63
	sli	V30.2D, V29.2D, #1
	eor	V27.16B, V27.16B, V30.16B
	ushr	V30.2D, V31.2D, #63
	sli	V30.2D, V31.2D, #1
	eor	V29.16B, V29.16B, V30.16B
	; Swap Rotate NEON
	eor	V0.16B, V0.16B, V25.16B
	eor	V31.16B, V1.16B, V26.16B
	eor	V6.16B, V6.16B, V26.16B
	ushr	V30.2D, V31.2D, #63
	ushr	V1.2D, V6.2D, #20
	sli	V30.2D, V31.2D, #1
	sli	V1.2D, V6.2D, #44
	eor	V31.16B, V9.16B, V29.16B
	eor	V22.16B, V22.16B, V27.16B
	ushr	V6.2D, V31.2D, #44
	ushr	V9.2D, V22.2D, #3
	sli	V6.2D, V31.2D, #20
	sli	V9.2D, V22.2D, #61
	eor	V31.16B, V14.16B, V29.16B
	eor	V20.16B, V20.16B, V25.16B
	ushr	V22.2D, V31.2D, #25
	ushr	V14.2D, V20.2D, #46
	sli	V22.2D, V31.2D, #39
	sli	V14.2D, V20.2D, #18
	eor	V31.16B, V2.16B, V27.16B
	eor	V12.16B, V12.16B, V27.16B
	ushr	V20.2D, V31.2D, #2
	ushr	V2.2D, V12.2D, #21
	sli	V20.2D, V31.2D, #62
	sli	V2.2D, V12.2D, #43
	eor	V31.16B, V13.16B, V28.16B
	eor	V19.16B, V19.16B, V29.16B
	ushr	V12.2D, V31.2D, #39
	ushr	V13.2D, V19.2D, #56
	sli	V12.2D, V31.2D, #25
	sli	V13.2D, V19.2D, #8
	eor	V31.16B, V23.16B, V28.16B
	eor	V15.16B, V15.16B, V25.16B
	ushr	V19.2D, V31.2D, #8
	ushr	V23.2D, V15.2D, #23
	sli	V19.2D, V31.2D, #56
	sli	V23.2D, V15.2D, #41
	eor	V31.16B, V4.16B, V29.16B
	eor	V24.16B, V24.16B, V29.16B
	ushr	V15.2D, V31.2D, #37
	ushr	V4.2D, V24.2D, #50
	sli	V15.2D, V31.2D, #27
	sli	V4.2D, V24.2D, #14
	eor	V31.16B, V21.16B, V26.16B
	eor	V8.16B, V8.16B, V28.16B
	ushr	V24.2D, V31.2D, #62
	ushr	V21.2D, V8.2D, #9
	sli	V24.2D, V31.2D, #2
	sli	V21.2D, V8.2D, #55
	eor	V31.16B, V16.16B, V26.16B
	eor	V5.16B, V5.16B, V25.16B
	ushr	V8.2D, V31.2D, #19
	ushr	V16.2D, V5.2D, #28
	sli	V8.2D, V31.2D, #45
	sli	V16.2D, V5.2D, #36
	eor	V31.16B, V3.16B, V28.16B
	eor	V18.16B, V18.16B, V28.16B
	ushr	V5.2D, V31.2D, #36
	ushr	V3.2D, V18.2D, #43
	sli	V5.2D, V31.2D, #28
	sli	V3.2D, V18.2D, #21
	eor	V31.16B, V17.16B, V27.16B
	eor	V11.16B, V11.16B, V26.16B
	ushr	V18.2D, V31.2D, #49
	ushr	V17.2D, V11.2D, #54
	sli	V18.2D, V31.2D, #15
	sli	V17.2D, V11.2D, #10
	eor	V31.16B, V7.16B, V27.16B
	eor	V10.16B, V10.16B, V25.16B
	ushr	V11.2D, V31.2D, #58
	ushr	V7.2D, V10.2D, #61
	sli	V11.2D, V31.2D, #6
	sli	V7.2D, V10.2D, #3
	; Row Mix NEON
	bic	V25.16B, V2.16B, V1.16B
	bic	V26.16B, V3.16B, V2.16B
	bic	V27.16B, V4.16B, V3.16B
	bic	V28.16B, V0.16B, V4.16B
	bic	V29.16B, V1.16B, V0.16B
	eor	V0.16B, V0.16B, V25.16B
	eor	V1.16B, V1.16B, V26.16B
	eor	V2.16B, V2.16B, V27.16B
	eor	V3.16B, V3.16B, V28.16B
	eor	V4.16B, V4.16B, V29.16B
	bic	V25.16B, V7.16B, V6.16B
	bic	V26.16B, V8.16B, V7.16B
	bic	V27.16B, V9.16B, V8.16B
	bic	V28.16B, V5.16B, V9.16B
	bic	V29.16B, V6.16B, V5.16B
	eor	V5.16B, V5.16B, V25.16B
	eor	V6.16B, V6.16B, V26.16B
	eor	V7.16B, V7.16B, V27.16B
	eor	V8.16B, V8.16B, V28.16B
	eor	V9.16B, V9.16B, V29.16B
	bic	V25.16B, V12.16B, V11.16B
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
	ldr	x3, [x1], #8
	subs	x2, x2, #1
	mov	V30.D[0], x3
	mov	V30.D[1], x3
	eor	V0.16B, V0.16B, V30.16B
	bne	L_frodokem_sha3_x2_neon_begin
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
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	IF :DEF:WOLFSSL_ARMASM_CRYPTO_SHA3
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	frodokem_sha3_x2_crypto
frodokem_sha3_x2_crypto PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x1, L_sha3_aarch64_r
	add	x1, x1, L_sha3_aarch64_r
; .arch_extension sha3
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
	sub	x0, x0, #0x190
	mov	x2, #24
L_frodokem_sha3_x2_crypto_begin
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
	ldr	x3, [x1], #8
	subs	x2, x2, #1
	mov	V30.D[0], x3
	mov	V30.D[1], x3
	eor	V0.16B, V0.16B, V30.16B
	bne	L_frodokem_sha3_x2_crypto_begin
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
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	ENDIF
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	frodokem_add_neon
frodokem_add_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	dup	V16.8H, w2
	ld1	{V0.8H, V1.8H, V2.8H, V3.8H}, [x0], #0x40
	ld1	{V4.8H, V5.8H, V6.8H, V7.8H}, [x0], #0x40
	sub	x0, x0, #0x80
	ld1	{V8.8H, V9.8H, V10.8H, V11.8H}, [x1], #0x40
	ld1	{V12.8H, V13.8H, V14.8H, V15.8H}, [x1], #0x40
	add	V0.8H, V0.8H, V8.8H
	and	V0.16B, V0.16B, V16.16B
	add	V1.8H, V1.8H, V9.8H
	and	V1.16B, V1.16B, V16.16B
	add	V2.8H, V2.8H, V10.8H
	and	V2.16B, V2.16B, V16.16B
	add	V3.8H, V3.8H, V11.8H
	and	V3.16B, V3.16B, V16.16B
	add	V4.8H, V4.8H, V12.8H
	and	V4.16B, V4.16B, V16.16B
	add	V5.8H, V5.8H, V13.8H
	and	V5.16B, V5.16B, V16.16B
	add	V6.8H, V6.8H, V14.8H
	and	V6.16B, V6.16B, V16.16B
	add	V7.8H, V7.8H, V15.8H
	and	V7.16B, V7.16B, V16.16B
	st1	{V0.8H, V1.8H, V2.8H, V3.8H}, [x0], #0x40
	st1	{V4.8H, V5.8H, V6.8H, V7.8H}, [x0], #0x40
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	frodokem_sample_neon
frodokem_sample_neon PROC
	stp	x29, x30, [sp, #-64]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	cmp	w1, #16
	blt	L_frodokem_sample_neon_rem
L_frodokem_sample_neon_blk16
	ld1	{V0.8H}, [x0], #16
	ld1	{V1.8H}, [x0], #16
	sub	x0, x0, #32
	ushr	V2.8H, V0.8H, #1
	movi	V4.8H, #1
	and	V4.16B, V4.16B, V0.16B
	movi	V6.8H, #0
	ushr	V3.8H, V1.8H, #1
	movi	V5.8H, #1
	and	V5.16B, V5.16B, V1.16B
	movi	V7.8H, #0
	mov	x4, x2
	mov	w5, w3
L_frodokem_sample_neon_cdf16
	ld1r	{V12.8H}, [x4], #2
	sub	V10.8H, V12.8H, V2.8H
	ushr	V10.8H, V10.8H, #15
	add	V6.8H, V6.8H, V10.8H
	sub	V11.8H, V12.8H, V3.8H
	ushr	V11.8H, V11.8H, #15
	add	V7.8H, V7.8H, V11.8H
	subs	w5, w5, #1
	bne	L_frodokem_sample_neon_cdf16
	neg	V8.8H, V4.8H
	eor	V6.16B, V6.16B, V8.16B
	add	V6.8H, V6.8H, V4.8H
	st1	{V6.8H}, [x0], #16
	neg	V9.8H, V5.8H
	eor	V7.16B, V7.16B, V9.16B
	add	V7.8H, V7.8H, V5.8H
	st1	{V7.8H}, [x0], #16
	subs	w1, w1, #16
	cmp	w1, #16
	bge	L_frodokem_sample_neon_blk16
L_frodokem_sample_neon_rem
	cmp	w1, #0
	beq	L_frodokem_sample_neon_done
L_frodokem_sample_neon_blk
	ld1	{V0.8H}, [x0]
	ushr	V2.8H, V0.8H, #1
	movi	V4.8H, #1
	and	V4.16B, V4.16B, V0.16B
	movi	V6.8H, #0
	mov	x4, x2
	mov	w5, w3
L_frodokem_sample_neon_cdf
	ld1r	{V12.8H}, [x4], #2
	sub	V12.8H, V12.8H, V2.8H
	ushr	V12.8H, V12.8H, #15
	add	V6.8H, V6.8H, V12.8H
	subs	w5, w5, #1
	bne	L_frodokem_sample_neon_cdf
	neg	V8.8H, V4.8H
	eor	V6.16B, V6.16B, V8.16B
	add	V6.8H, V6.8H, V4.8H
	st1	{V6.8H}, [x0], #16
	subs	w1, w1, #8
	bne	L_frodokem_sample_neon_blk
L_frodokem_sample_neon_done
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	x29, x30, [sp], #0x40
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	frodokem_sa_accum_neon
frodokem_sa_accum_neon PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	str	x17, [x29, #24]
	stp	D8, D9, [x29, #32]
	stp	D10, D11, [x29, #48]
	stp	D12, D13, [x29, #64]
	sxtw	x5, w4
	lsl	x5, x5, #1
	lsl	x6, x5, #2
	sxtw	x7, w3
	lsl	x7, x7, #1
	add	x7, x1, x7
	mov	x8, x0
	mov	x12, #2
L_frodokem_sa_accum_neon_t
	ldr	w13, [x7]
	dup	V0.8H, w13
	lsr	w13, w13, #16
	dup	V4.8H, w13
	add	x7, x7, x5
	ldr	w13, [x7]
	dup	V1.8H, w13
	lsr	w13, w13, #16
	dup	V5.8H, w13
	add	x7, x7, x5
	ldr	w13, [x7]
	dup	V2.8H, w13
	lsr	w13, w13, #16
	dup	V6.8H, w13
	add	x7, x7, x5
	ldr	w13, [x7]
	dup	V3.8H, w13
	lsr	w13, w13, #16
	dup	V7.8H, w13
	add	x7, x7, x5
	mov	x14, x8
	add	x15, x14, x5
	add	x16, x15, x5
	add	x17, x16, x5
	mov	x9, x2
	add	x10, x2, x5
	lsr	x11, x5, #4
L_frodokem_sa_accum_neon_k
	ld1	{V8.8H}, [x9], #16
	ld1	{V9.8H}, [x10], #16
	ld1	{V10.8H}, [x14]
	mla	V10.8H, V8.8H, V0.8H
	mla	V10.8H, V9.8H, V4.8H
	st1	{V10.8H}, [x14], #16
	ld1	{V11.8H}, [x15]
	mla	V11.8H, V8.8H, V1.8H
	mla	V11.8H, V9.8H, V5.8H
	st1	{V11.8H}, [x15], #16
	ld1	{V12.8H}, [x16]
	mla	V12.8H, V8.8H, V2.8H
	mla	V12.8H, V9.8H, V6.8H
	st1	{V12.8H}, [x16], #16
	ld1	{V13.8H}, [x17]
	mla	V13.8H, V8.8H, V3.8H
	mla	V13.8H, V9.8H, V7.8H
	st1	{V13.8H}, [x17], #16
	subs	x11, x11, #1
	bne	L_frodokem_sa_accum_neon_k
	add	x8, x8, x6
	subs	x12, x12, #1
	bne	L_frodokem_sa_accum_neon_t
	ldr	x17, [x29, #24]
	ldp	D8, D9, [x29, #32]
	ldp	D10, D11, [x29, #48]
	ldp	D12, D13, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	frodokem_sa_accum_x4_neon
frodokem_sa_accum_x4_neon PROC
	stp	x29, x30, [sp, #-112]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #24]
	str	x20, [x29, #40]
	stp	D8, D9, [x29, #48]
	stp	D10, D11, [x29, #64]
	stp	D12, D13, [x29, #80]
	stp	D14, D15, [x29, #96]
	sxtw	x5, w4
	lsl	x5, x5, #1
	lsl	x6, x5, #2
	sxtw	x7, w3
	lsl	x7, x7, #1
	add	x7, x1, x7
	mov	x8, x0
	mov	x14, #2
L_frodokem_sa_accum_x4_neon_t
	ldr	x15, [x7]
	dup	V0.8H, w15
	lsr	x15, x15, #16
	dup	V1.8H, w15
	lsr	x15, x15, #16
	dup	V2.8H, w15
	lsr	x15, x15, #16
	dup	V3.8H, w15
	add	x7, x7, x5
	ldr	x15, [x7]
	dup	V4.8H, w15
	lsr	x15, x15, #16
	dup	V5.8H, w15
	lsr	x15, x15, #16
	dup	V6.8H, w15
	lsr	x15, x15, #16
	dup	V7.8H, w15
	add	x7, x7, x5
	ldr	x15, [x7]
	dup	V8.8H, w15
	lsr	x15, x15, #16
	dup	V9.8H, w15
	lsr	x15, x15, #16
	dup	V10.8H, w15
	lsr	x15, x15, #16
	dup	V11.8H, w15
	add	x7, x7, x5
	ldr	x15, [x7]
	dup	V12.8H, w15
	lsr	x15, x15, #16
	dup	V13.8H, w15
	lsr	x15, x15, #16
	dup	V14.8H, w15
	lsr	x15, x15, #16
	dup	V15.8H, w15
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
L_frodokem_sa_accum_x4_neon_k
	ld1	{V16.8H}, [x9], #16
	ld1	{V17.8H}, [x10], #16
	ld1	{V18.8H}, [x11], #16
	ld1	{V19.8H}, [x12], #16
	ld1	{V20.8H}, [x16]
	mla	V20.8H, V16.8H, V0.8H
	mla	V20.8H, V17.8H, V1.8H
	mla	V20.8H, V18.8H, V2.8H
	mla	V20.8H, V19.8H, V3.8H
	st1	{V20.8H}, [x16], #16
	ld1	{V21.8H}, [x17]
	mla	V21.8H, V16.8H, V4.8H
	mla	V21.8H, V17.8H, V5.8H
	mla	V21.8H, V18.8H, V6.8H
	mla	V21.8H, V19.8H, V7.8H
	st1	{V21.8H}, [x17], #16
	ld1	{V22.8H}, [x19]
	mla	V22.8H, V16.8H, V8.8H
	mla	V22.8H, V17.8H, V9.8H
	mla	V22.8H, V18.8H, V10.8H
	mla	V22.8H, V19.8H, V11.8H
	st1	{V22.8H}, [x19], #16
	ld1	{V23.8H}, [x20]
	mla	V23.8H, V16.8H, V12.8H
	mla	V23.8H, V17.8H, V13.8H
	mla	V23.8H, V18.8H, V14.8H
	mla	V23.8H, V19.8H, V15.8H
	st1	{V23.8H}, [x20], #16
	subs	x13, x13, #1
	bne	L_frodokem_sa_accum_x4_neon_k
	add	x8, x8, x6
	subs	x14, x14, #1
	bne	L_frodokem_sa_accum_x4_neon_t
	ldp	x17, x19, [x29, #24]
	ldr	x20, [x29, #40]
	ldp	D8, D9, [x29, #48]
	ldp	D10, D11, [x29, #64]
	ldp	D12, D13, [x29, #80]
	ldp	D14, D15, [x29, #96]
	ldp	x29, x30, [sp], #0x70
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	frodokem_as_accum_neon
frodokem_as_accum_neon PROC
	stp	x29, x30, [sp, #-96]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #24]
	str	x20, [x29, #40]
	stp	D8, D9, [x29, #48]
	stp	D10, D11, [x29, #64]
	stp	D12, D13, [x29, #80]
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
	movi	V0.8H, #0
	movi	V1.8H, #0
	movi	V2.8H, #0
	movi	V3.8H, #0
	movi	V4.8H, #0
	movi	V5.8H, #0
	movi	V6.8H, #0
	movi	V7.8H, #0
	lsr	x14, x5, #4
L_frodokem_as_accum_neon_k0
	ld1	{V8.8H}, [x11], #16
	ld1	{V9.8H}, [x12], #16
	ld1	{V10.8H}, [x16], #16
	mla	V0.8H, V8.8H, V10.8H
	mla	V4.8H, V9.8H, V10.8H
	ld1	{V10.8H}, [x17], #16
	mla	V1.8H, V8.8H, V10.8H
	mla	V5.8H, V9.8H, V10.8H
	ld1	{V10.8H}, [x19], #16
	mla	V2.8H, V8.8H, V10.8H
	mla	V6.8H, V9.8H, V10.8H
	ld1	{V10.8H}, [x20], #16
	mla	V3.8H, V8.8H, V10.8H
	mla	V7.8H, V9.8H, V10.8H
	subs	x14, x14, #1
	bne	L_frodokem_as_accum_neon_k0
	addv	H13, V0.8H
	ins	V11.H[0], V13.H[0]
	addv	H13, V4.8H
	ins	V12.H[0], V13.H[0]
	addv	H13, V1.8H
	ins	V11.H[1], V13.H[0]
	addv	H13, V5.8H
	ins	V12.H[1], V13.H[0]
	addv	H13, V2.8H
	ins	V11.H[2], V13.H[0]
	addv	H13, V6.8H
	ins	V12.H[2], V13.H[0]
	addv	H13, V3.8H
	ins	V11.H[3], V13.H[0]
	addv	H13, V7.8H
	ins	V12.H[3], V13.H[0]
	add	x13, x13, x6
	mov	x16, x13
	add	x17, x16, x5
	add	x19, x17, x5
	add	x20, x19, x5
	mov	x11, x9
	mov	x12, x10
	movi	V0.8H, #0
	movi	V1.8H, #0
	movi	V2.8H, #0
	movi	V3.8H, #0
	movi	V4.8H, #0
	movi	V5.8H, #0
	movi	V6.8H, #0
	movi	V7.8H, #0
	lsr	x14, x5, #4
L_frodokem_as_accum_neon_k1
	ld1	{V8.8H}, [x11], #16
	ld1	{V9.8H}, [x12], #16
	ld1	{V10.8H}, [x16], #16
	mla	V0.8H, V8.8H, V10.8H
	mla	V4.8H, V9.8H, V10.8H
	ld1	{V10.8H}, [x17], #16
	mla	V1.8H, V8.8H, V10.8H
	mla	V5.8H, V9.8H, V10.8H
	ld1	{V10.8H}, [x19], #16
	mla	V2.8H, V8.8H, V10.8H
	mla	V6.8H, V9.8H, V10.8H
	ld1	{V10.8H}, [x20], #16
	mla	V3.8H, V8.8H, V10.8H
	mla	V7.8H, V9.8H, V10.8H
	subs	x14, x14, #1
	bne	L_frodokem_as_accum_neon_k1
	addv	H13, V0.8H
	ins	V11.H[4], V13.H[0]
	addv	H13, V4.8H
	ins	V12.H[4], V13.H[0]
	addv	H13, V1.8H
	ins	V11.H[5], V13.H[0]
	addv	H13, V5.8H
	ins	V12.H[5], V13.H[0]
	addv	H13, V2.8H
	ins	V11.H[6], V13.H[0]
	addv	H13, V6.8H
	ins	V12.H[6], V13.H[0]
	addv	H13, V3.8H
	ins	V11.H[7], V13.H[0]
	addv	H13, V7.8H
	ins	V12.H[7], V13.H[0]
	add	x13, x13, x6
	ld1	{V8.8H}, [x7]
	add	V11.8H, V11.8H, V8.8H
	st1	{V11.8H}, [x7], #16
	ld1	{V9.8H}, [x8]
	add	V12.8H, V12.8H, V9.8H
	st1	{V12.8H}, [x8], #16
	ldp	x17, x19, [x29, #24]
	ldr	x20, [x29, #40]
	ldp	D8, D9, [x29, #48]
	ldp	D10, D11, [x29, #64]
	ldp	D12, D13, [x29, #80]
	ldp	x29, x30, [sp], #0x60
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	frodokem_as_accum_x4_neon
frodokem_as_accum_x4_neon PROC
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
	movi	V0.8H, #0
	movi	V1.8H, #0
	movi	V2.8H, #0
	movi	V3.8H, #0
	movi	V4.8H, #0
	movi	V5.8H, #0
	movi	V6.8H, #0
	movi	V7.8H, #0
	movi	V8.8H, #0
	movi	V9.8H, #0
	movi	V10.8H, #0
	movi	V11.8H, #0
	movi	V12.8H, #0
	movi	V13.8H, #0
	movi	V14.8H, #0
	movi	V15.8H, #0
	lsr	x21, x5, #4
L_frodokem_as_accum_x4_neon_k0
	ld1	{V16.8H}, [x15], #16
	ld1	{V17.8H}, [x16], #16
	ld1	{V18.8H}, [x17], #16
	ld1	{V19.8H}, [x19], #16
	ld1	{V20.8H}, [x23], #16
	mla	V0.8H, V16.8H, V20.8H
	mla	V4.8H, V17.8H, V20.8H
	mla	V8.8H, V18.8H, V20.8H
	mla	V12.8H, V19.8H, V20.8H
	ld1	{V20.8H}, [x24], #16
	mla	V1.8H, V16.8H, V20.8H
	mla	V5.8H, V17.8H, V20.8H
	mla	V9.8H, V18.8H, V20.8H
	mla	V13.8H, V19.8H, V20.8H
	ld1	{V20.8H}, [x25], #16
	mla	V2.8H, V16.8H, V20.8H
	mla	V6.8H, V17.8H, V20.8H
	mla	V10.8H, V18.8H, V20.8H
	mla	V14.8H, V19.8H, V20.8H
	ld1	{V20.8H}, [x26], #16
	mla	V3.8H, V16.8H, V20.8H
	mla	V7.8H, V17.8H, V20.8H
	mla	V11.8H, V18.8H, V20.8H
	mla	V15.8H, V19.8H, V20.8H
	subs	x21, x21, #1
	bne	L_frodokem_as_accum_x4_neon_k0
	addv	H25, V0.8H
	ins	V21.H[0], V25.H[0]
	addv	H25, V4.8H
	ins	V22.H[0], V25.H[0]
	addv	H25, V8.8H
	ins	V23.H[0], V25.H[0]
	addv	H25, V12.8H
	ins	V24.H[0], V25.H[0]
	addv	H25, V1.8H
	ins	V21.H[1], V25.H[0]
	addv	H25, V5.8H
	ins	V22.H[1], V25.H[0]
	addv	H25, V9.8H
	ins	V23.H[1], V25.H[0]
	addv	H25, V13.8H
	ins	V24.H[1], V25.H[0]
	addv	H25, V2.8H
	ins	V21.H[2], V25.H[0]
	addv	H25, V6.8H
	ins	V22.H[2], V25.H[0]
	addv	H25, V10.8H
	ins	V23.H[2], V25.H[0]
	addv	H25, V14.8H
	ins	V24.H[2], V25.H[0]
	addv	H25, V3.8H
	ins	V21.H[3], V25.H[0]
	addv	H25, V7.8H
	ins	V22.H[3], V25.H[0]
	addv	H25, V11.8H
	ins	V23.H[3], V25.H[0]
	addv	H25, V15.8H
	ins	V24.H[3], V25.H[0]
	add	x20, x20, x6
	mov	x23, x20
	add	x24, x23, x5
	add	x25, x24, x5
	add	x26, x25, x5
	mov	x15, x11
	mov	x16, x12
	mov	x17, x13
	mov	x19, x14
	movi	V0.8H, #0
	movi	V1.8H, #0
	movi	V2.8H, #0
	movi	V3.8H, #0
	movi	V4.8H, #0
	movi	V5.8H, #0
	movi	V6.8H, #0
	movi	V7.8H, #0
	movi	V8.8H, #0
	movi	V9.8H, #0
	movi	V10.8H, #0
	movi	V11.8H, #0
	movi	V12.8H, #0
	movi	V13.8H, #0
	movi	V14.8H, #0
	movi	V15.8H, #0
	lsr	x21, x5, #4
L_frodokem_as_accum_x4_neon_k1
	ld1	{V16.8H}, [x15], #16
	ld1	{V17.8H}, [x16], #16
	ld1	{V18.8H}, [x17], #16
	ld1	{V19.8H}, [x19], #16
	ld1	{V20.8H}, [x23], #16
	mla	V0.8H, V16.8H, V20.8H
	mla	V4.8H, V17.8H, V20.8H
	mla	V8.8H, V18.8H, V20.8H
	mla	V12.8H, V19.8H, V20.8H
	ld1	{V20.8H}, [x24], #16
	mla	V1.8H, V16.8H, V20.8H
	mla	V5.8H, V17.8H, V20.8H
	mla	V9.8H, V18.8H, V20.8H
	mla	V13.8H, V19.8H, V20.8H
	ld1	{V20.8H}, [x25], #16
	mla	V2.8H, V16.8H, V20.8H
	mla	V6.8H, V17.8H, V20.8H
	mla	V10.8H, V18.8H, V20.8H
	mla	V14.8H, V19.8H, V20.8H
	ld1	{V20.8H}, [x26], #16
	mla	V3.8H, V16.8H, V20.8H
	mla	V7.8H, V17.8H, V20.8H
	mla	V11.8H, V18.8H, V20.8H
	mla	V15.8H, V19.8H, V20.8H
	subs	x21, x21, #1
	bne	L_frodokem_as_accum_x4_neon_k1
	addv	H25, V0.8H
	ins	V21.H[4], V25.H[0]
	addv	H25, V4.8H
	ins	V22.H[4], V25.H[0]
	addv	H25, V8.8H
	ins	V23.H[4], V25.H[0]
	addv	H25, V12.8H
	ins	V24.H[4], V25.H[0]
	addv	H25, V1.8H
	ins	V21.H[5], V25.H[0]
	addv	H25, V5.8H
	ins	V22.H[5], V25.H[0]
	addv	H25, V9.8H
	ins	V23.H[5], V25.H[0]
	addv	H25, V13.8H
	ins	V24.H[5], V25.H[0]
	addv	H25, V2.8H
	ins	V21.H[6], V25.H[0]
	addv	H25, V6.8H
	ins	V22.H[6], V25.H[0]
	addv	H25, V10.8H
	ins	V23.H[6], V25.H[0]
	addv	H25, V14.8H
	ins	V24.H[6], V25.H[0]
	addv	H25, V3.8H
	ins	V21.H[7], V25.H[0]
	addv	H25, V7.8H
	ins	V22.H[7], V25.H[0]
	addv	H25, V11.8H
	ins	V23.H[7], V25.H[0]
	addv	H25, V15.8H
	ins	V24.H[7], V25.H[0]
	add	x20, x20, x6
	ld1	{V16.8H}, [x7]
	add	V21.8H, V21.8H, V16.8H
	st1	{V21.8H}, [x7], #16
	ld1	{V16.8H}, [x8]
	add	V22.8H, V22.8H, V16.8H
	st1	{V22.8H}, [x8], #16
	ld1	{V16.8H}, [x9]
	add	V23.8H, V23.8H, V16.8H
	st1	{V23.8H}, [x9], #16
	ld1	{V16.8H}, [x10]
	add	V24.8H, V24.8H, V16.8H
	st1	{V24.8H}, [x10], #16
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
	EXPORT	frodokem_mul_bs_neon
frodokem_mul_bs_neon PROC
	stp	x29, x30, [sp, #-160]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #16]
	stp	x20, x21, [x29, #32]
	stp	x22, x23, [x29, #48]
	stp	x24, x25, [x29, #64]
	stp	x26, x27, [x29, #80]
	stp	D8, D9, [x29, #96]
	stp	D10, D11, [x29, #112]
	stp	D12, D13, [x29, #128]
	stp	D14, D15, [x29, #144]
	sxtw	x5, w3
	lsl	x5, x5, #1
	lsl	x6, x5, #2
	dup	V26.8H, w4
	mov	x7, x0
	add	x8, x7, #16
	add	x9, x8, #16
	add	x10, x9, #16
	mov	x11, x1
	mov	x23, #2
L_frodokem_mul_bs_neon_p
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
	movi	V0.8H, #0
	movi	V1.8H, #0
	movi	V2.8H, #0
	movi	V3.8H, #0
	movi	V4.8H, #0
	movi	V5.8H, #0
	movi	V6.8H, #0
	movi	V7.8H, #0
	movi	V8.8H, #0
	movi	V9.8H, #0
	movi	V10.8H, #0
	movi	V11.8H, #0
	movi	V12.8H, #0
	movi	V13.8H, #0
	movi	V14.8H, #0
	movi	V15.8H, #0
	lsr	x22, x5, #4
L_frodokem_mul_bs_neon_k0
	ld1	{V16.8H}, [x16], #16
	ld1	{V17.8H}, [x17], #16
	ld1	{V18.8H}, [x19], #16
	ld1	{V19.8H}, [x20], #16
	ld1	{V20.8H}, [x24], #16
	mla	V0.8H, V16.8H, V20.8H
	mla	V4.8H, V17.8H, V20.8H
	mla	V8.8H, V18.8H, V20.8H
	mla	V12.8H, V19.8H, V20.8H
	ld1	{V20.8H}, [x25], #16
	mla	V1.8H, V16.8H, V20.8H
	mla	V5.8H, V17.8H, V20.8H
	mla	V9.8H, V18.8H, V20.8H
	mla	V13.8H, V19.8H, V20.8H
	ld1	{V20.8H}, [x26], #16
	mla	V2.8H, V16.8H, V20.8H
	mla	V6.8H, V17.8H, V20.8H
	mla	V10.8H, V18.8H, V20.8H
	mla	V14.8H, V19.8H, V20.8H
	ld1	{V20.8H}, [x27], #16
	mla	V3.8H, V16.8H, V20.8H
	mla	V7.8H, V17.8H, V20.8H
	mla	V11.8H, V18.8H, V20.8H
	mla	V15.8H, V19.8H, V20.8H
	subs	x22, x22, #1
	bne	L_frodokem_mul_bs_neon_k0
	addv	H25, V0.8H
	ins	V21.H[0], V25.H[0]
	addv	H25, V4.8H
	ins	V22.H[0], V25.H[0]
	addv	H25, V8.8H
	ins	V23.H[0], V25.H[0]
	addv	H25, V12.8H
	ins	V24.H[0], V25.H[0]
	addv	H25, V1.8H
	ins	V21.H[1], V25.H[0]
	addv	H25, V5.8H
	ins	V22.H[1], V25.H[0]
	addv	H25, V9.8H
	ins	V23.H[1], V25.H[0]
	addv	H25, V13.8H
	ins	V24.H[1], V25.H[0]
	addv	H25, V2.8H
	ins	V21.H[2], V25.H[0]
	addv	H25, V6.8H
	ins	V22.H[2], V25.H[0]
	addv	H25, V10.8H
	ins	V23.H[2], V25.H[0]
	addv	H25, V14.8H
	ins	V24.H[2], V25.H[0]
	addv	H25, V3.8H
	ins	V21.H[3], V25.H[0]
	addv	H25, V7.8H
	ins	V22.H[3], V25.H[0]
	addv	H25, V11.8H
	ins	V23.H[3], V25.H[0]
	addv	H25, V15.8H
	ins	V24.H[3], V25.H[0]
	add	x21, x21, x6
	mov	x24, x21
	add	x25, x24, x5
	add	x26, x25, x5
	add	x27, x26, x5
	mov	x16, x12
	mov	x17, x13
	mov	x19, x14
	mov	x20, x15
	movi	V0.8H, #0
	movi	V1.8H, #0
	movi	V2.8H, #0
	movi	V3.8H, #0
	movi	V4.8H, #0
	movi	V5.8H, #0
	movi	V6.8H, #0
	movi	V7.8H, #0
	movi	V8.8H, #0
	movi	V9.8H, #0
	movi	V10.8H, #0
	movi	V11.8H, #0
	movi	V12.8H, #0
	movi	V13.8H, #0
	movi	V14.8H, #0
	movi	V15.8H, #0
	lsr	x22, x5, #4
L_frodokem_mul_bs_neon_k1
	ld1	{V16.8H}, [x16], #16
	ld1	{V17.8H}, [x17], #16
	ld1	{V18.8H}, [x19], #16
	ld1	{V19.8H}, [x20], #16
	ld1	{V20.8H}, [x24], #16
	mla	V0.8H, V16.8H, V20.8H
	mla	V4.8H, V17.8H, V20.8H
	mla	V8.8H, V18.8H, V20.8H
	mla	V12.8H, V19.8H, V20.8H
	ld1	{V20.8H}, [x25], #16
	mla	V1.8H, V16.8H, V20.8H
	mla	V5.8H, V17.8H, V20.8H
	mla	V9.8H, V18.8H, V20.8H
	mla	V13.8H, V19.8H, V20.8H
	ld1	{V20.8H}, [x26], #16
	mla	V2.8H, V16.8H, V20.8H
	mla	V6.8H, V17.8H, V20.8H
	mla	V10.8H, V18.8H, V20.8H
	mla	V14.8H, V19.8H, V20.8H
	ld1	{V20.8H}, [x27], #16
	mla	V3.8H, V16.8H, V20.8H
	mla	V7.8H, V17.8H, V20.8H
	mla	V11.8H, V18.8H, V20.8H
	mla	V15.8H, V19.8H, V20.8H
	subs	x22, x22, #1
	bne	L_frodokem_mul_bs_neon_k1
	addv	H25, V0.8H
	ins	V21.H[4], V25.H[0]
	addv	H25, V4.8H
	ins	V22.H[4], V25.H[0]
	addv	H25, V8.8H
	ins	V23.H[4], V25.H[0]
	addv	H25, V12.8H
	ins	V24.H[4], V25.H[0]
	addv	H25, V1.8H
	ins	V21.H[5], V25.H[0]
	addv	H25, V5.8H
	ins	V22.H[5], V25.H[0]
	addv	H25, V9.8H
	ins	V23.H[5], V25.H[0]
	addv	H25, V13.8H
	ins	V24.H[5], V25.H[0]
	addv	H25, V2.8H
	ins	V21.H[6], V25.H[0]
	addv	H25, V6.8H
	ins	V22.H[6], V25.H[0]
	addv	H25, V10.8H
	ins	V23.H[6], V25.H[0]
	addv	H25, V14.8H
	ins	V24.H[6], V25.H[0]
	addv	H25, V3.8H
	ins	V21.H[7], V25.H[0]
	addv	H25, V7.8H
	ins	V22.H[7], V25.H[0]
	addv	H25, V11.8H
	ins	V23.H[7], V25.H[0]
	addv	H25, V15.8H
	ins	V24.H[7], V25.H[0]
	add	x21, x21, x6
	and	V21.16B, V21.16B, V26.16B
	st1	{V21.8H}, [x7]
	and	V22.16B, V22.16B, V26.16B
	st1	{V22.8H}, [x8]
	and	V23.16B, V23.16B, V26.16B
	st1	{V23.8H}, [x9]
	and	V24.16B, V24.16B, V26.16B
	st1	{V24.8H}, [x10]
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
	ldp	D8, D9, [x29, #96]
	ldp	D10, D11, [x29, #112]
	ldp	D12, D13, [x29, #128]
	ldp	D14, D15, [x29, #144]
	ldp	x29, x30, [sp], #0xa0
	ret
	ENDP
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	frodokem_mul_add_sb_plus_e_neon
frodokem_mul_add_sb_plus_e_neon PROC
	stp	x29, x30, [sp, #-48]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	sxtw	x5, w3
	lsl	x5, x5, #1
	dup	V10.8H, w4
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
	ld1	{V0.8H, V1.8H, V2.8H, V3.8H}, [x16], #0x40
	ld1	{V4.8H, V5.8H, V6.8H, V7.8H}, [x16], #0x40
	sub	x16, x16, #0x80
	sxtw	x15, w3
L_frodokem_mul_add_sb_plus_e_neon_j
	ld1	{V8.8H}, [x14], #16
	ld1r	{V9.8H}, [x6], #2
	mla	V0.8H, V8.8H, V9.8H
	ld1r	{V9.8H}, [x7], #2
	mla	V1.8H, V8.8H, V9.8H
	ld1r	{V9.8H}, [x8], #2
	mla	V2.8H, V8.8H, V9.8H
	ld1r	{V9.8H}, [x9], #2
	mla	V3.8H, V8.8H, V9.8H
	ld1r	{V9.8H}, [x10], #2
	mla	V4.8H, V8.8H, V9.8H
	ld1r	{V9.8H}, [x11], #2
	mla	V5.8H, V8.8H, V9.8H
	ld1r	{V9.8H}, [x12], #2
	mla	V6.8H, V8.8H, V9.8H
	ld1r	{V9.8H}, [x13], #2
	mla	V7.8H, V8.8H, V9.8H
	subs	x15, x15, #1
	bne	L_frodokem_mul_add_sb_plus_e_neon_j
	and	V0.16B, V0.16B, V10.16B
	and	V1.16B, V1.16B, V10.16B
	and	V2.16B, V2.16B, V10.16B
	and	V3.16B, V3.16B, V10.16B
	and	V4.16B, V4.16B, V10.16B
	and	V5.16B, V5.16B, V10.16B
	and	V6.16B, V6.16B, V10.16B
	and	V7.16B, V7.16B, V10.16B
	st1	{V0.8H, V1.8H, V2.8H, V3.8H}, [x16], #0x40
	st1	{V4.8H, V5.8H, V6.8H, V7.8H}, [x16], #0x40
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	x29, x30, [sp], #48
	ret
	ENDP
	ENDIF
	IF :DEF:WOLFSSL_HAVE_FRODOKEM
; 	.arch	armv8-a+crypto
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	frodokem_gen_a_rows_aes_arm64
frodokem_gen_a_rows_aes_arm64 PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	ld1	{V0.16B, V1.16B, V2.16B, V3.16B}, [x2], #0x40
	ld1	{V4.16B, V5.16B, V6.16B, V7.16B}, [x2], #0x40
	ld1	{V8.16B, V9.16B, V10.16B}, [x2], #48
	dup	V19.8H, w6
	sxtw	x13, w3
	sxtw	x7, w5
	lsl	x7, x7, #1
	sxtw	x8, w4
	mul	x8, x8, x7
	movz	w14, #8, lsl 16
	mov	x9, x0
L_frodokem_gen_a_rows_aes_arm64_row
	mov	w11, w13
	add	x10, x9, x7
L_frodokem_gen_a_rows_aes_arm64_blk
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
L_frodokem_gen_a_rows_aes_arm64_aes
	ld1	{V11.16B, V12.16B, V13.16B, V14.16B}, [x0], #0x40
	ld1	{V15.16B, V16.16B, V17.16B, V18.16B}, [x0], #0x40
	aese	V11.16B, V0.16B
	aesmc	V11.16B, V11.16B
	aese	V12.16B, V0.16B
	aesmc	V12.16B, V12.16B
	aese	V13.16B, V0.16B
	aesmc	V13.16B, V13.16B
	aese	V14.16B, V0.16B
	aesmc	V14.16B, V14.16B
	aese	V15.16B, V0.16B
	aesmc	V15.16B, V15.16B
	aese	V16.16B, V0.16B
	aesmc	V16.16B, V16.16B
	aese	V17.16B, V0.16B
	aesmc	V17.16B, V17.16B
	aese	V18.16B, V0.16B
	aesmc	V18.16B, V18.16B
	aese	V11.16B, V1.16B
	aesmc	V11.16B, V11.16B
	aese	V12.16B, V1.16B
	aesmc	V12.16B, V12.16B
	aese	V13.16B, V1.16B
	aesmc	V13.16B, V13.16B
	aese	V14.16B, V1.16B
	aesmc	V14.16B, V14.16B
	aese	V15.16B, V1.16B
	aesmc	V15.16B, V15.16B
	aese	V16.16B, V1.16B
	aesmc	V16.16B, V16.16B
	aese	V17.16B, V1.16B
	aesmc	V17.16B, V17.16B
	aese	V18.16B, V1.16B
	aesmc	V18.16B, V18.16B
	aese	V11.16B, V2.16B
	aesmc	V11.16B, V11.16B
	aese	V12.16B, V2.16B
	aesmc	V12.16B, V12.16B
	aese	V13.16B, V2.16B
	aesmc	V13.16B, V13.16B
	aese	V14.16B, V2.16B
	aesmc	V14.16B, V14.16B
	aese	V15.16B, V2.16B
	aesmc	V15.16B, V15.16B
	aese	V16.16B, V2.16B
	aesmc	V16.16B, V16.16B
	aese	V17.16B, V2.16B
	aesmc	V17.16B, V17.16B
	aese	V18.16B, V2.16B
	aesmc	V18.16B, V18.16B
	aese	V11.16B, V3.16B
	aesmc	V11.16B, V11.16B
	aese	V12.16B, V3.16B
	aesmc	V12.16B, V12.16B
	aese	V13.16B, V3.16B
	aesmc	V13.16B, V13.16B
	aese	V14.16B, V3.16B
	aesmc	V14.16B, V14.16B
	aese	V15.16B, V3.16B
	aesmc	V15.16B, V15.16B
	aese	V16.16B, V3.16B
	aesmc	V16.16B, V16.16B
	aese	V17.16B, V3.16B
	aesmc	V17.16B, V17.16B
	aese	V18.16B, V3.16B
	aesmc	V18.16B, V18.16B
	aese	V11.16B, V4.16B
	aesmc	V11.16B, V11.16B
	aese	V12.16B, V4.16B
	aesmc	V12.16B, V12.16B
	aese	V13.16B, V4.16B
	aesmc	V13.16B, V13.16B
	aese	V14.16B, V4.16B
	aesmc	V14.16B, V14.16B
	aese	V15.16B, V4.16B
	aesmc	V15.16B, V15.16B
	aese	V16.16B, V4.16B
	aesmc	V16.16B, V16.16B
	aese	V17.16B, V4.16B
	aesmc	V17.16B, V17.16B
	aese	V18.16B, V4.16B
	aesmc	V18.16B, V18.16B
	aese	V11.16B, V5.16B
	aesmc	V11.16B, V11.16B
	aese	V12.16B, V5.16B
	aesmc	V12.16B, V12.16B
	aese	V13.16B, V5.16B
	aesmc	V13.16B, V13.16B
	aese	V14.16B, V5.16B
	aesmc	V14.16B, V14.16B
	aese	V15.16B, V5.16B
	aesmc	V15.16B, V15.16B
	aese	V16.16B, V5.16B
	aesmc	V16.16B, V16.16B
	aese	V17.16B, V5.16B
	aesmc	V17.16B, V17.16B
	aese	V18.16B, V5.16B
	aesmc	V18.16B, V18.16B
	aese	V11.16B, V6.16B
	aesmc	V11.16B, V11.16B
	aese	V12.16B, V6.16B
	aesmc	V12.16B, V12.16B
	aese	V13.16B, V6.16B
	aesmc	V13.16B, V13.16B
	aese	V14.16B, V6.16B
	aesmc	V14.16B, V14.16B
	aese	V15.16B, V6.16B
	aesmc	V15.16B, V15.16B
	aese	V16.16B, V6.16B
	aesmc	V16.16B, V16.16B
	aese	V17.16B, V6.16B
	aesmc	V17.16B, V17.16B
	aese	V18.16B, V6.16B
	aesmc	V18.16B, V18.16B
	aese	V11.16B, V7.16B
	aesmc	V11.16B, V11.16B
	aese	V12.16B, V7.16B
	aesmc	V12.16B, V12.16B
	aese	V13.16B, V7.16B
	aesmc	V13.16B, V13.16B
	aese	V14.16B, V7.16B
	aesmc	V14.16B, V14.16B
	aese	V15.16B, V7.16B
	aesmc	V15.16B, V15.16B
	aese	V16.16B, V7.16B
	aesmc	V16.16B, V16.16B
	aese	V17.16B, V7.16B
	aesmc	V17.16B, V17.16B
	aese	V18.16B, V7.16B
	aesmc	V18.16B, V18.16B
	aese	V11.16B, V8.16B
	aesmc	V11.16B, V11.16B
	aese	V12.16B, V8.16B
	aesmc	V12.16B, V12.16B
	aese	V13.16B, V8.16B
	aesmc	V13.16B, V13.16B
	aese	V14.16B, V8.16B
	aesmc	V14.16B, V14.16B
	aese	V15.16B, V8.16B
	aesmc	V15.16B, V15.16B
	aese	V16.16B, V8.16B
	aesmc	V16.16B, V16.16B
	aese	V17.16B, V8.16B
	aesmc	V17.16B, V17.16B
	aese	V18.16B, V8.16B
	aesmc	V18.16B, V18.16B
	aese	V11.16B, V9.16B
	aese	V12.16B, V9.16B
	aese	V13.16B, V9.16B
	aese	V14.16B, V9.16B
	aese	V15.16B, V9.16B
	aese	V16.16B, V9.16B
	aese	V17.16B, V9.16B
	aese	V18.16B, V9.16B
	eor	V11.16B, V11.16B, V10.16B
	eor	V12.16B, V12.16B, V10.16B
	eor	V13.16B, V13.16B, V10.16B
	eor	V14.16B, V14.16B, V10.16B
	eor	V15.16B, V15.16B, V10.16B
	eor	V16.16B, V16.16B, V10.16B
	eor	V17.16B, V17.16B, V10.16B
	eor	V18.16B, V18.16B, V10.16B
	and	V11.16B, V11.16B, V19.16B
	and	V12.16B, V12.16B, V19.16B
	and	V13.16B, V13.16B, V19.16B
	and	V14.16B, V14.16B, V19.16B
	and	V15.16B, V15.16B, V19.16B
	and	V16.16B, V16.16B, V19.16B
	and	V17.16B, V17.16B, V19.16B
	and	V18.16B, V18.16B, V19.16B
	st1	{V11.16B, V12.16B, V13.16B, V14.16B}, [x1], #0x40
	st1	{V15.16B, V16.16B, V17.16B, V18.16B}, [x1], #0x40
	subs	x8, x8, #0x80
	cmp	x8, #0x80
	bge	L_frodokem_gen_a_rows_aes_arm64_aes
L_frodokem_gen_a_rows_aes_arm64_tail
	cmp	x8, #0
	beq	L_frodokem_gen_a_rows_aes_arm64_done
	ld1	{V11.16B, V12.16B, V13.16B, V14.16B}, [x0], #0x40
	aese	V11.16B, V0.16B
	aesmc	V11.16B, V11.16B
	aese	V12.16B, V0.16B
	aesmc	V12.16B, V12.16B
	aese	V13.16B, V0.16B
	aesmc	V13.16B, V13.16B
	aese	V14.16B, V0.16B
	aesmc	V14.16B, V14.16B
	aese	V11.16B, V1.16B
	aesmc	V11.16B, V11.16B
	aese	V12.16B, V1.16B
	aesmc	V12.16B, V12.16B
	aese	V13.16B, V1.16B
	aesmc	V13.16B, V13.16B
	aese	V14.16B, V1.16B
	aesmc	V14.16B, V14.16B
	aese	V11.16B, V2.16B
	aesmc	V11.16B, V11.16B
	aese	V12.16B, V2.16B
	aesmc	V12.16B, V12.16B
	aese	V13.16B, V2.16B
	aesmc	V13.16B, V13.16B
	aese	V14.16B, V2.16B
	aesmc	V14.16B, V14.16B
	aese	V11.16B, V3.16B
	aesmc	V11.16B, V11.16B
	aese	V12.16B, V3.16B
	aesmc	V12.16B, V12.16B
	aese	V13.16B, V3.16B
	aesmc	V13.16B, V13.16B
	aese	V14.16B, V3.16B
	aesmc	V14.16B, V14.16B
	aese	V11.16B, V4.16B
	aesmc	V11.16B, V11.16B
	aese	V12.16B, V4.16B
	aesmc	V12.16B, V12.16B
	aese	V13.16B, V4.16B
	aesmc	V13.16B, V13.16B
	aese	V14.16B, V4.16B
	aesmc	V14.16B, V14.16B
	aese	V11.16B, V5.16B
	aesmc	V11.16B, V11.16B
	aese	V12.16B, V5.16B
	aesmc	V12.16B, V12.16B
	aese	V13.16B, V5.16B
	aesmc	V13.16B, V13.16B
	aese	V14.16B, V5.16B
	aesmc	V14.16B, V14.16B
	aese	V11.16B, V6.16B
	aesmc	V11.16B, V11.16B
	aese	V12.16B, V6.16B
	aesmc	V12.16B, V12.16B
	aese	V13.16B, V6.16B
	aesmc	V13.16B, V13.16B
	aese	V14.16B, V6.16B
	aesmc	V14.16B, V14.16B
	aese	V11.16B, V7.16B
	aesmc	V11.16B, V11.16B
	aese	V12.16B, V7.16B
	aesmc	V12.16B, V12.16B
	aese	V13.16B, V7.16B
	aesmc	V13.16B, V13.16B
	aese	V14.16B, V7.16B
	aesmc	V14.16B, V14.16B
	aese	V11.16B, V8.16B
	aesmc	V11.16B, V11.16B
	aese	V12.16B, V8.16B
	aesmc	V12.16B, V12.16B
	aese	V13.16B, V8.16B
	aesmc	V13.16B, V13.16B
	aese	V14.16B, V8.16B
	aesmc	V14.16B, V14.16B
	aese	V11.16B, V9.16B
	aese	V12.16B, V9.16B
	aese	V13.16B, V9.16B
	aese	V14.16B, V9.16B
	eor	V11.16B, V11.16B, V10.16B
	eor	V12.16B, V12.16B, V10.16B
	eor	V13.16B, V13.16B, V10.16B
	eor	V14.16B, V14.16B, V10.16B
	and	V11.16B, V11.16B, V19.16B
	and	V12.16B, V12.16B, V19.16B
	and	V13.16B, V13.16B, V19.16B
	and	V14.16B, V14.16B, V19.16B
	st1	{V11.16B, V12.16B, V13.16B, V14.16B}, [x1], #0x40
L_frodokem_gen_a_rows_aes_arm64_done
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	ENDIF
	END
