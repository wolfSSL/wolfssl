; /* armv8-sha1-asm
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
;   ruby ./sha1/sha1.rb arm64 \
;       ../wolfssl/wolfcrypt/src/port/arm/armv8-sha1-asm.asm
	IF :LNOT::DEF:NO_SHA
	IF :LNOT::DEF:WOLFSSL_ARMASM_NO_BASE_IMPL :LOR: :DEF:WOLFSSL_ARMASM_NO_NEON
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_SHA1_trans_base_len_k
	DCD	0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	Transform_Sha_Len_base
Transform_Sha_Len_base PROC
	stp	x29, x30, [sp, #-112]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #24]
	stp	x20, x21, [x29, #40]
	stp	x22, x23, [x29, #56]
	stp	x24, x25, [x29, #72]
	stp	x26, x27, [x29, #88]
	str	x28, [x29, #104]
	adrp	x3, L_SHA1_trans_base_len_k
	add	x3, x3, L_SHA1_trans_base_len_k
	; Load digest into working vars
	ldr	w4, [x0]
	ldr	w5, [x0, #4]
	ldr	w6, [x0, #8]
	ldr	w7, [x0, #12]
	ldr	w8, [x0, #16]
	; Start of loop processing a block
L_sha1_len_base_begin
	; Load W
	ldr	w9, [x1]
	ldr	w10, [x1, #4]
	ldr	w11, [x1, #8]
	ldr	w12, [x1, #12]
	ldr	w13, [x1, #16]
	ldr	w14, [x1, #20]
	ldr	w15, [x1, #24]
	ldr	w16, [x1, #28]
	ldr	w17, [x1, #32]
	ldr	w19, [x1, #36]
	ldr	w20, [x1, #40]
	ldr	w21, [x1, #44]
	ldr	w22, [x1, #48]
	ldr	w23, [x1, #52]
	ldr	w24, [x1, #56]
	ldr	w25, [x1, #60]
	; Reverse W
	rev	w9, w9
	rev	w10, w10
	rev	w11, w11
	rev	w12, w12
	rev	w13, w13
	rev	w14, w14
	rev	w15, w15
	rev	w16, w16
	rev	w17, w17
	rev	w19, w19
	rev	w20, w20
	rev	w21, w21
	rev	w22, w22
	rev	w23, w23
	rev	w24, w24
	rev	w25, w25
	ldr	w28, [x3]
	; Round 0
	add	w8, w8, w9
	add	w8, w8, w28
	and	w26, w5, w6
	bic	w27, w7, w5
	add	w8, w8, w26
	add	w8, w8, w27
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w23, w17
	eor	w26, w26, w11
	eor	w26, w26, w9
	ror	w9, w26, #31
	; Round 1
	add	w7, w7, w10
	add	w7, w7, w28
	and	w26, w4, w5
	bic	w27, w6, w4
	add	w7, w7, w26
	add	w7, w7, w27
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w24, w19
	eor	w26, w26, w12
	eor	w26, w26, w10
	ror	w10, w26, #31
	; Round 2
	add	w6, w6, w11
	add	w6, w6, w28
	and	w26, w8, w4
	bic	w27, w5, w8
	add	w6, w6, w26
	add	w6, w6, w27
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w25, w20
	eor	w26, w26, w13
	eor	w26, w26, w11
	ror	w11, w26, #31
	; Round 3
	add	w5, w5, w12
	add	w5, w5, w28
	and	w26, w7, w8
	bic	w27, w4, w7
	add	w5, w5, w26
	add	w5, w5, w27
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w9, w21
	eor	w26, w26, w14
	eor	w26, w26, w12
	ror	w12, w26, #31
	; Round 4
	add	w4, w4, w13
	add	w4, w4, w28
	and	w26, w6, w7
	bic	w27, w8, w6
	add	w4, w4, w26
	add	w4, w4, w27
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w10, w22
	eor	w26, w26, w15
	eor	w26, w26, w13
	ror	w13, w26, #31
	; Round 5
	add	w8, w8, w14
	add	w8, w8, w28
	and	w26, w5, w6
	bic	w27, w7, w5
	add	w8, w8, w26
	add	w8, w8, w27
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w11, w23
	eor	w26, w26, w16
	eor	w26, w26, w14
	ror	w14, w26, #31
	; Round 6
	add	w7, w7, w15
	add	w7, w7, w28
	and	w26, w4, w5
	bic	w27, w6, w4
	add	w7, w7, w26
	add	w7, w7, w27
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w12, w24
	eor	w26, w26, w17
	eor	w26, w26, w15
	ror	w15, w26, #31
	; Round 7
	add	w6, w6, w16
	add	w6, w6, w28
	and	w26, w8, w4
	bic	w27, w5, w8
	add	w6, w6, w26
	add	w6, w6, w27
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w13, w25
	eor	w26, w26, w19
	eor	w26, w26, w16
	ror	w16, w26, #31
	; Round 8
	add	w5, w5, w17
	add	w5, w5, w28
	and	w26, w7, w8
	bic	w27, w4, w7
	add	w5, w5, w26
	add	w5, w5, w27
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w14, w9
	eor	w26, w26, w20
	eor	w26, w26, w17
	ror	w17, w26, #31
	; Round 9
	add	w4, w4, w19
	add	w4, w4, w28
	and	w26, w6, w7
	bic	w27, w8, w6
	add	w4, w4, w26
	add	w4, w4, w27
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w15, w10
	eor	w26, w26, w21
	eor	w26, w26, w19
	ror	w19, w26, #31
	; Round 10
	add	w8, w8, w20
	add	w8, w8, w28
	and	w26, w5, w6
	bic	w27, w7, w5
	add	w8, w8, w26
	add	w8, w8, w27
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w16, w11
	eor	w26, w26, w22
	eor	w26, w26, w20
	ror	w20, w26, #31
	; Round 11
	add	w7, w7, w21
	add	w7, w7, w28
	and	w26, w4, w5
	bic	w27, w6, w4
	add	w7, w7, w26
	add	w7, w7, w27
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w17, w12
	eor	w26, w26, w23
	eor	w26, w26, w21
	ror	w21, w26, #31
	; Round 12
	add	w6, w6, w22
	add	w6, w6, w28
	and	w26, w8, w4
	bic	w27, w5, w8
	add	w6, w6, w26
	add	w6, w6, w27
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w19, w13
	eor	w26, w26, w24
	eor	w26, w26, w22
	ror	w22, w26, #31
	; Round 13
	add	w5, w5, w23
	add	w5, w5, w28
	and	w26, w7, w8
	bic	w27, w4, w7
	add	w5, w5, w26
	add	w5, w5, w27
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w20, w14
	eor	w26, w26, w25
	eor	w26, w26, w23
	ror	w23, w26, #31
	; Round 14
	add	w4, w4, w24
	add	w4, w4, w28
	and	w26, w6, w7
	bic	w27, w8, w6
	add	w4, w4, w26
	add	w4, w4, w27
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w21, w15
	eor	w26, w26, w9
	eor	w26, w26, w24
	ror	w24, w26, #31
	; Round 15
	add	w8, w8, w25
	add	w8, w8, w28
	and	w26, w5, w6
	bic	w27, w7, w5
	add	w8, w8, w26
	add	w8, w8, w27
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w22, w16
	eor	w26, w26, w10
	eor	w26, w26, w25
	ror	w25, w26, #31
	; Round 16
	add	w7, w7, w9
	add	w7, w7, w28
	and	w26, w4, w5
	bic	w27, w6, w4
	add	w7, w7, w26
	add	w7, w7, w27
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w23, w17
	eor	w26, w26, w11
	eor	w26, w26, w9
	ror	w9, w26, #31
	; Round 17
	add	w6, w6, w10
	add	w6, w6, w28
	and	w26, w8, w4
	bic	w27, w5, w8
	add	w6, w6, w26
	add	w6, w6, w27
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w24, w19
	eor	w26, w26, w12
	eor	w26, w26, w10
	ror	w10, w26, #31
	; Round 18
	add	w5, w5, w11
	add	w5, w5, w28
	and	w26, w7, w8
	bic	w27, w4, w7
	add	w5, w5, w26
	add	w5, w5, w27
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w25, w20
	eor	w26, w26, w13
	eor	w26, w26, w11
	ror	w11, w26, #31
	; Round 19
	add	w4, w4, w12
	add	w4, w4, w28
	and	w26, w6, w7
	bic	w27, w8, w6
	add	w4, w4, w26
	add	w4, w4, w27
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w9, w21
	eor	w26, w26, w14
	eor	w26, w26, w12
	ror	w12, w26, #31
	ldr	w28, [x3, #4]
	; Round 20
	add	w8, w8, w13
	add	w8, w8, w28
	eor	w26, w6, w7
	eor	w26, w26, w5
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w10, w22
	eor	w26, w26, w15
	eor	w26, w26, w13
	ror	w13, w26, #31
	; Round 21
	add	w7, w7, w14
	add	w7, w7, w28
	eor	w26, w5, w6
	eor	w26, w26, w4
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w11, w23
	eor	w26, w26, w16
	eor	w26, w26, w14
	ror	w14, w26, #31
	; Round 22
	add	w6, w6, w15
	add	w6, w6, w28
	eor	w26, w4, w5
	eor	w26, w26, w8
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w12, w24
	eor	w26, w26, w17
	eor	w26, w26, w15
	ror	w15, w26, #31
	; Round 23
	add	w5, w5, w16
	add	w5, w5, w28
	eor	w26, w8, w4
	eor	w26, w26, w7
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w13, w25
	eor	w26, w26, w19
	eor	w26, w26, w16
	ror	w16, w26, #31
	; Round 24
	add	w4, w4, w17
	add	w4, w4, w28
	eor	w26, w7, w8
	eor	w26, w26, w6
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w14, w9
	eor	w26, w26, w20
	eor	w26, w26, w17
	ror	w17, w26, #31
	; Round 25
	add	w8, w8, w19
	add	w8, w8, w28
	eor	w26, w6, w7
	eor	w26, w26, w5
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w15, w10
	eor	w26, w26, w21
	eor	w26, w26, w19
	ror	w19, w26, #31
	; Round 26
	add	w7, w7, w20
	add	w7, w7, w28
	eor	w26, w5, w6
	eor	w26, w26, w4
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w16, w11
	eor	w26, w26, w22
	eor	w26, w26, w20
	ror	w20, w26, #31
	; Round 27
	add	w6, w6, w21
	add	w6, w6, w28
	eor	w26, w4, w5
	eor	w26, w26, w8
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w17, w12
	eor	w26, w26, w23
	eor	w26, w26, w21
	ror	w21, w26, #31
	; Round 28
	add	w5, w5, w22
	add	w5, w5, w28
	eor	w26, w8, w4
	eor	w26, w26, w7
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w19, w13
	eor	w26, w26, w24
	eor	w26, w26, w22
	ror	w22, w26, #31
	; Round 29
	add	w4, w4, w23
	add	w4, w4, w28
	eor	w26, w7, w8
	eor	w26, w26, w6
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w20, w14
	eor	w26, w26, w25
	eor	w26, w26, w23
	ror	w23, w26, #31
	; Round 30
	add	w8, w8, w24
	add	w8, w8, w28
	eor	w26, w6, w7
	eor	w26, w26, w5
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w21, w15
	eor	w26, w26, w9
	eor	w26, w26, w24
	ror	w24, w26, #31
	; Round 31
	add	w7, w7, w25
	add	w7, w7, w28
	eor	w26, w5, w6
	eor	w26, w26, w4
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w22, w16
	eor	w26, w26, w10
	eor	w26, w26, w25
	ror	w25, w26, #31
	; Round 32
	add	w6, w6, w9
	add	w6, w6, w28
	eor	w26, w4, w5
	eor	w26, w26, w8
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w23, w17
	eor	w26, w26, w11
	eor	w26, w26, w9
	ror	w9, w26, #31
	; Round 33
	add	w5, w5, w10
	add	w5, w5, w28
	eor	w26, w8, w4
	eor	w26, w26, w7
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w24, w19
	eor	w26, w26, w12
	eor	w26, w26, w10
	ror	w10, w26, #31
	; Round 34
	add	w4, w4, w11
	add	w4, w4, w28
	eor	w26, w7, w8
	eor	w26, w26, w6
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w25, w20
	eor	w26, w26, w13
	eor	w26, w26, w11
	ror	w11, w26, #31
	; Round 35
	add	w8, w8, w12
	add	w8, w8, w28
	eor	w26, w6, w7
	eor	w26, w26, w5
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w9, w21
	eor	w26, w26, w14
	eor	w26, w26, w12
	ror	w12, w26, #31
	; Round 36
	add	w7, w7, w13
	add	w7, w7, w28
	eor	w26, w5, w6
	eor	w26, w26, w4
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w10, w22
	eor	w26, w26, w15
	eor	w26, w26, w13
	ror	w13, w26, #31
	; Round 37
	add	w6, w6, w14
	add	w6, w6, w28
	eor	w26, w4, w5
	eor	w26, w26, w8
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w11, w23
	eor	w26, w26, w16
	eor	w26, w26, w14
	ror	w14, w26, #31
	; Round 38
	add	w5, w5, w15
	add	w5, w5, w28
	eor	w26, w8, w4
	eor	w26, w26, w7
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w12, w24
	eor	w26, w26, w17
	eor	w26, w26, w15
	ror	w15, w26, #31
	; Round 39
	add	w4, w4, w16
	add	w4, w4, w28
	eor	w26, w7, w8
	eor	w26, w26, w6
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w13, w25
	eor	w26, w26, w19
	eor	w26, w26, w16
	ror	w16, w26, #31
	ldr	w28, [x3, #8]
	; Round 40
	add	w8, w8, w17
	add	w8, w8, w28
	orr	w26, w6, w7
	and	w27, w6, w7
	and	w26, w26, w5
	orr	w26, w26, w27
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w14, w9
	eor	w26, w26, w20
	eor	w26, w26, w17
	ror	w17, w26, #31
	; Round 41
	add	w7, w7, w19
	add	w7, w7, w28
	orr	w26, w5, w6
	and	w27, w5, w6
	and	w26, w26, w4
	orr	w26, w26, w27
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w15, w10
	eor	w26, w26, w21
	eor	w26, w26, w19
	ror	w19, w26, #31
	; Round 42
	add	w6, w6, w20
	add	w6, w6, w28
	orr	w26, w4, w5
	and	w27, w4, w5
	and	w26, w26, w8
	orr	w26, w26, w27
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w16, w11
	eor	w26, w26, w22
	eor	w26, w26, w20
	ror	w20, w26, #31
	; Round 43
	add	w5, w5, w21
	add	w5, w5, w28
	orr	w26, w8, w4
	and	w27, w8, w4
	and	w26, w26, w7
	orr	w26, w26, w27
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w17, w12
	eor	w26, w26, w23
	eor	w26, w26, w21
	ror	w21, w26, #31
	; Round 44
	add	w4, w4, w22
	add	w4, w4, w28
	orr	w26, w7, w8
	and	w27, w7, w8
	and	w26, w26, w6
	orr	w26, w26, w27
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w19, w13
	eor	w26, w26, w24
	eor	w26, w26, w22
	ror	w22, w26, #31
	; Round 45
	add	w8, w8, w23
	add	w8, w8, w28
	orr	w26, w6, w7
	and	w27, w6, w7
	and	w26, w26, w5
	orr	w26, w26, w27
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w20, w14
	eor	w26, w26, w25
	eor	w26, w26, w23
	ror	w23, w26, #31
	; Round 46
	add	w7, w7, w24
	add	w7, w7, w28
	orr	w26, w5, w6
	and	w27, w5, w6
	and	w26, w26, w4
	orr	w26, w26, w27
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w21, w15
	eor	w26, w26, w9
	eor	w26, w26, w24
	ror	w24, w26, #31
	; Round 47
	add	w6, w6, w25
	add	w6, w6, w28
	orr	w26, w4, w5
	and	w27, w4, w5
	and	w26, w26, w8
	orr	w26, w26, w27
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w22, w16
	eor	w26, w26, w10
	eor	w26, w26, w25
	ror	w25, w26, #31
	; Round 48
	add	w5, w5, w9
	add	w5, w5, w28
	orr	w26, w8, w4
	and	w27, w8, w4
	and	w26, w26, w7
	orr	w26, w26, w27
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w23, w17
	eor	w26, w26, w11
	eor	w26, w26, w9
	ror	w9, w26, #31
	; Round 49
	add	w4, w4, w10
	add	w4, w4, w28
	orr	w26, w7, w8
	and	w27, w7, w8
	and	w26, w26, w6
	orr	w26, w26, w27
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w24, w19
	eor	w26, w26, w12
	eor	w26, w26, w10
	ror	w10, w26, #31
	; Round 50
	add	w8, w8, w11
	add	w8, w8, w28
	orr	w26, w6, w7
	and	w27, w6, w7
	and	w26, w26, w5
	orr	w26, w26, w27
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w25, w20
	eor	w26, w26, w13
	eor	w26, w26, w11
	ror	w11, w26, #31
	; Round 51
	add	w7, w7, w12
	add	w7, w7, w28
	orr	w26, w5, w6
	and	w27, w5, w6
	and	w26, w26, w4
	orr	w26, w26, w27
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w9, w21
	eor	w26, w26, w14
	eor	w26, w26, w12
	ror	w12, w26, #31
	; Round 52
	add	w6, w6, w13
	add	w6, w6, w28
	orr	w26, w4, w5
	and	w27, w4, w5
	and	w26, w26, w8
	orr	w26, w26, w27
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w10, w22
	eor	w26, w26, w15
	eor	w26, w26, w13
	ror	w13, w26, #31
	; Round 53
	add	w5, w5, w14
	add	w5, w5, w28
	orr	w26, w8, w4
	and	w27, w8, w4
	and	w26, w26, w7
	orr	w26, w26, w27
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w11, w23
	eor	w26, w26, w16
	eor	w26, w26, w14
	ror	w14, w26, #31
	; Round 54
	add	w4, w4, w15
	add	w4, w4, w28
	orr	w26, w7, w8
	and	w27, w7, w8
	and	w26, w26, w6
	orr	w26, w26, w27
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w12, w24
	eor	w26, w26, w17
	eor	w26, w26, w15
	ror	w15, w26, #31
	; Round 55
	add	w8, w8, w16
	add	w8, w8, w28
	orr	w26, w6, w7
	and	w27, w6, w7
	and	w26, w26, w5
	orr	w26, w26, w27
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w13, w25
	eor	w26, w26, w19
	eor	w26, w26, w16
	ror	w16, w26, #31
	; Round 56
	add	w7, w7, w17
	add	w7, w7, w28
	orr	w26, w5, w6
	and	w27, w5, w6
	and	w26, w26, w4
	orr	w26, w26, w27
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w14, w9
	eor	w26, w26, w20
	eor	w26, w26, w17
	ror	w17, w26, #31
	; Round 57
	add	w6, w6, w19
	add	w6, w6, w28
	orr	w26, w4, w5
	and	w27, w4, w5
	and	w26, w26, w8
	orr	w26, w26, w27
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w15, w10
	eor	w26, w26, w21
	eor	w26, w26, w19
	ror	w19, w26, #31
	; Round 58
	add	w5, w5, w20
	add	w5, w5, w28
	orr	w26, w8, w4
	and	w27, w8, w4
	and	w26, w26, w7
	orr	w26, w26, w27
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w16, w11
	eor	w26, w26, w22
	eor	w26, w26, w20
	ror	w20, w26, #31
	; Round 59
	add	w4, w4, w21
	add	w4, w4, w28
	orr	w26, w7, w8
	and	w27, w7, w8
	and	w26, w26, w6
	orr	w26, w26, w27
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	eor	w26, w17, w12
	eor	w26, w26, w23
	eor	w26, w26, w21
	ror	w21, w26, #31
	ldr	w28, [x3, #12]
	; Round 60
	add	w8, w8, w22
	add	w8, w8, w28
	eor	w26, w6, w7
	eor	w26, w26, w5
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	eor	w26, w19, w13
	eor	w26, w26, w24
	eor	w26, w26, w22
	ror	w22, w26, #31
	; Round 61
	add	w7, w7, w23
	add	w7, w7, w28
	eor	w26, w5, w6
	eor	w26, w26, w4
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	eor	w26, w20, w14
	eor	w26, w26, w25
	eor	w26, w26, w23
	ror	w23, w26, #31
	; Round 62
	add	w6, w6, w24
	add	w6, w6, w28
	eor	w26, w4, w5
	eor	w26, w26, w8
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	eor	w26, w21, w15
	eor	w26, w26, w9
	eor	w26, w26, w24
	ror	w24, w26, #31
	; Round 63
	add	w5, w5, w25
	add	w5, w5, w28
	eor	w26, w8, w4
	eor	w26, w26, w7
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	eor	w26, w22, w16
	eor	w26, w26, w10
	eor	w26, w26, w25
	ror	w25, w26, #31
	; Round 64
	add	w4, w4, w9
	add	w4, w4, w28
	eor	w26, w7, w8
	eor	w26, w26, w6
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	; Round 65
	add	w8, w8, w10
	add	w8, w8, w28
	eor	w26, w6, w7
	eor	w26, w26, w5
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	; Round 66
	add	w7, w7, w11
	add	w7, w7, w28
	eor	w26, w5, w6
	eor	w26, w26, w4
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	; Round 67
	add	w6, w6, w12
	add	w6, w6, w28
	eor	w26, w4, w5
	eor	w26, w26, w8
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	; Round 68
	add	w5, w5, w13
	add	w5, w5, w28
	eor	w26, w8, w4
	eor	w26, w26, w7
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	; Round 69
	add	w4, w4, w14
	add	w4, w4, w28
	eor	w26, w7, w8
	eor	w26, w26, w6
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	; Round 70
	add	w8, w8, w15
	add	w8, w8, w28
	eor	w26, w6, w7
	eor	w26, w26, w5
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	; Round 71
	add	w7, w7, w16
	add	w7, w7, w28
	eor	w26, w5, w6
	eor	w26, w26, w4
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	; Round 72
	add	w6, w6, w17
	add	w6, w6, w28
	eor	w26, w4, w5
	eor	w26, w26, w8
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	; Round 73
	add	w5, w5, w19
	add	w5, w5, w28
	eor	w26, w8, w4
	eor	w26, w26, w7
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	; Round 74
	add	w4, w4, w20
	add	w4, w4, w28
	eor	w26, w7, w8
	eor	w26, w26, w6
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	; Round 75
	add	w8, w8, w21
	add	w8, w8, w28
	eor	w26, w6, w7
	eor	w26, w26, w5
	add	w8, w8, w26
	ror	w26, w4, #27
	add	w8, w8, w26
	ror	w5, w5, #2
	; Round 76
	add	w7, w7, w22
	add	w7, w7, w28
	eor	w26, w5, w6
	eor	w26, w26, w4
	add	w7, w7, w26
	ror	w26, w8, #27
	add	w7, w7, w26
	ror	w4, w4, #2
	; Round 77
	add	w6, w6, w23
	add	w6, w6, w28
	eor	w26, w4, w5
	eor	w26, w26, w8
	add	w6, w6, w26
	ror	w26, w7, #27
	add	w6, w6, w26
	ror	w8, w8, #2
	; Round 78
	add	w5, w5, w24
	add	w5, w5, w28
	eor	w26, w8, w4
	eor	w26, w26, w7
	add	w5, w5, w26
	ror	w26, w6, #27
	add	w5, w5, w26
	ror	w7, w7, #2
	; Round 79
	add	w4, w4, w25
	add	w4, w4, w28
	eor	w26, w7, w8
	eor	w26, w26, w6
	add	w4, w4, w26
	ror	w26, w5, #27
	add	w4, w4, w26
	ror	w6, w6, #2
	; Add in digest from start of block
	ldr	w9, [x0]
	ldr	w10, [x0, #4]
	ldr	w11, [x0, #8]
	ldr	w12, [x0, #12]
	ldr	w13, [x0, #16]
	add	w4, w4, w9
	add	w5, w5, w10
	add	w6, w6, w11
	add	w7, w7, w12
	add	w8, w8, w13
	; Store digest
	str	w4, [x0]
	str	w5, [x0, #4]
	str	w6, [x0, #8]
	str	w7, [x0, #12]
	str	w8, [x0, #16]
	add	x1, x1, #0x40
	subs	w2, w2, #0x40
	bne	L_sha1_len_base_begin
	ldp	x17, x19, [x29, #24]
	ldp	x20, x21, [x29, #40]
	ldp	x22, x23, [x29, #56]
	ldp	x24, x25, [x29, #72]
	ldp	x26, x27, [x29, #88]
	ldr	x28, [x29, #104]
	ldp	x29, x30, [sp], #0x70
	ret
	ENDP
	ENDIF
	IF :LNOT::DEF:WOLFSSL_ARMASM_NO_NEON
	IF :LNOT::DEF:WOLFSSL_ARMASM_NO_NEON_IMPL :LOR: :DEF:WOLFSSL_ARMASM_NO_HW_CRYPTO
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_SHA1_trans_neon_len_k
	DCD	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999
	DCD	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1
	DCD	0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc
	DCD	0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	Transform_Sha_Len_neon
Transform_Sha_Len_neon PROC
	stp	x29, x30, [sp, #-112]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #88]
	str	x20, [x29, #104]
	adrp	x3, L_SHA1_trans_neon_len_k
	add	x3, x3, L_SHA1_trans_neon_len_k
	; Load K into vector registers
	ld1	{V16.4S, V17.4S, V18.4S, V19.4S}, [x3]
	movi	V24.4S, #0
	; Load digest into working vars
	ldr	w4, [x0]
	ldr	w5, [x0, #4]
	ldr	w6, [x0, #8]
	ldr	w7, [x0, #12]
	ldr	w8, [x0, #16]
	; Start of loop processing a block
L_sha1_len_neon_begin
	; Load W
	ld1	{V0.4S, V1.4S, V2.4S, V3.4S}, [x1], #0x40
	; Copy digest to add in at end
	mov	w15, w4
	mov	w16, w5
	mov	w17, w6
	mov	w19, w7
	mov	w20, w8
	rev32	V0.16B, V0.16B
	rev32	V1.16B, V1.16B
	rev32	V2.16B, V2.16B
	rev32	V3.16B, V3.16B
	; W+K for the first two groups
	add	V20.4S, V0.4S, V16.4S
	str	Q20, [x29, #16]
	add	V20.4S, V1.4S, V16.4S
	str	Q20, [x29, #32]
	ldp	w11, w12, [x29, #16]
	; Round 0
	ldp	w13, w14, [x29, #24]
	; Calc new W[16]-W[19]
	ext8	V21.16B, V0.16B, V1.16B, #8
	add	w8, w8, w11
	eor	V21.16B, V21.16B, V0.16B
	and	w9, w5, w6
	eor	V21.16B, V21.16B, V2.16B
	bic	w10, w7, w5
	ext8	V22.16B, V3.16B, V24.16B, #4
	add	w8, w8, w9
	eor	V21.16B, V21.16B, V22.16B
	add	w8, w8, w10
	shl	V4.4S, V21.4S, #1
	ror	w9, w4, #27
	sri	V4.4S, V21.4S, #31
	add	w8, w8, w9
	ext8	V22.16B, V24.16B, V4.16B, #4
	ror	w5, w5, #2
	shl	V23.4S, V22.4S, #1
	; Round 1
	sri	V23.4S, V22.4S, #31
	add	w7, w7, w12
	eor	V4.16B, V4.16B, V23.16B
	and	w9, w4, w5
	; W+K for rounds 8-11
	add	V20.4S, V2.4S, V16.4S
	bic	w10, w6, w4
	str	Q20, [x29, #48]
	add	w7, w7, w9
	add	w7, w7, w10
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	; Round 2
	ldp	w11, w12, [x29, #32]
	add	w6, w6, w13
	and	w9, w8, w4
	bic	w10, w5, w8
	add	w6, w6, w9
	add	w6, w6, w10
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	; Round 3
	add	w5, w5, w14
	and	w9, w7, w8
	bic	w10, w4, w7
	add	w5, w5, w9
	add	w5, w5, w10
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	; Round 4
	ldp	w13, w14, [x29, #40]
	; Calc new W[20]-W[23]
	ext8	V21.16B, V1.16B, V2.16B, #8
	add	w4, w4, w11
	eor	V21.16B, V21.16B, V1.16B
	and	w9, w6, w7
	eor	V21.16B, V21.16B, V3.16B
	bic	w10, w8, w6
	ext8	V22.16B, V4.16B, V24.16B, #4
	add	w4, w4, w9
	eor	V21.16B, V21.16B, V22.16B
	add	w4, w4, w10
	shl	V5.4S, V21.4S, #1
	ror	w9, w5, #27
	sri	V5.4S, V21.4S, #31
	add	w4, w4, w9
	ext8	V22.16B, V24.16B, V5.16B, #4
	ror	w6, w6, #2
	shl	V23.4S, V22.4S, #1
	; Round 5
	sri	V23.4S, V22.4S, #31
	add	w8, w8, w12
	eor	V5.16B, V5.16B, V23.16B
	and	w9, w5, w6
	; W+K for rounds 12-15
	add	V20.4S, V3.4S, V16.4S
	bic	w10, w7, w5
	str	Q20, [x29, #64]
	add	w8, w8, w9
	add	w8, w8, w10
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	; Round 6
	ldp	w11, w12, [x29, #48]
	add	w7, w7, w13
	and	w9, w4, w5
	bic	w10, w6, w4
	add	w7, w7, w9
	add	w7, w7, w10
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	; Round 7
	add	w6, w6, w14
	and	w9, w8, w4
	bic	w10, w5, w8
	add	w6, w6, w9
	add	w6, w6, w10
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	; Round 8
	ldp	w13, w14, [x29, #56]
	; Calc new W[24]-W[27]
	ext8	V21.16B, V2.16B, V3.16B, #8
	add	w5, w5, w11
	eor	V21.16B, V21.16B, V2.16B
	and	w9, w7, w8
	eor	V21.16B, V21.16B, V4.16B
	bic	w10, w4, w7
	ext8	V22.16B, V5.16B, V24.16B, #4
	add	w5, w5, w9
	eor	V21.16B, V21.16B, V22.16B
	add	w5, w5, w10
	shl	V6.4S, V21.4S, #1
	ror	w9, w6, #27
	sri	V6.4S, V21.4S, #31
	add	w5, w5, w9
	ext8	V22.16B, V24.16B, V6.16B, #4
	ror	w7, w7, #2
	shl	V23.4S, V22.4S, #1
	; Round 9
	sri	V23.4S, V22.4S, #31
	add	w4, w4, w12
	eor	V6.16B, V6.16B, V23.16B
	and	w9, w6, w7
	; W+K for rounds 16-19
	add	V20.4S, V4.4S, V16.4S
	bic	w10, w8, w6
	str	Q20, [x29, #16]
	add	w4, w4, w9
	add	w4, w4, w10
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	; Round 10
	ldp	w11, w12, [x29, #64]
	add	w8, w8, w13
	and	w9, w5, w6
	bic	w10, w7, w5
	add	w8, w8, w9
	add	w8, w8, w10
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	; Round 11
	add	w7, w7, w14
	and	w9, w4, w5
	bic	w10, w6, w4
	add	w7, w7, w9
	add	w7, w7, w10
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	; Round 12
	ldp	w13, w14, [x29, #72]
	; Calc new W[28]-W[31]
	ext8	V21.16B, V3.16B, V4.16B, #8
	add	w6, w6, w11
	eor	V21.16B, V21.16B, V3.16B
	and	w9, w8, w4
	eor	V21.16B, V21.16B, V5.16B
	bic	w10, w5, w8
	ext8	V22.16B, V6.16B, V24.16B, #4
	add	w6, w6, w9
	eor	V21.16B, V21.16B, V22.16B
	add	w6, w6, w10
	shl	V7.4S, V21.4S, #1
	ror	w9, w7, #27
	sri	V7.4S, V21.4S, #31
	add	w6, w6, w9
	ext8	V22.16B, V24.16B, V7.16B, #4
	ror	w8, w8, #2
	shl	V23.4S, V22.4S, #1
	; Round 13
	sri	V23.4S, V22.4S, #31
	add	w5, w5, w12
	eor	V7.16B, V7.16B, V23.16B
	and	w9, w7, w8
	; W+K for rounds 20-23
	add	V20.4S, V5.4S, V17.4S
	bic	w10, w4, w7
	str	Q20, [x29, #32]
	add	w5, w5, w9
	add	w5, w5, w10
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	; Round 14
	ldp	w11, w12, [x29, #16]
	add	w4, w4, w13
	and	w9, w6, w7
	bic	w10, w8, w6
	add	w4, w4, w9
	add	w4, w4, w10
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	; Round 15
	add	w8, w8, w14
	and	w9, w5, w6
	bic	w10, w7, w5
	add	w8, w8, w9
	add	w8, w8, w10
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	; Round 16
	ldp	w13, w14, [x29, #24]
	; Calc new W[32]-W[35]
	ext8	V21.16B, V6.16B, V7.16B, #8
	add	w7, w7, w11
	eor	V21.16B, V21.16B, V4.16B
	and	w9, w4, w5
	eor	V21.16B, V21.16B, V1.16B
	bic	w10, w6, w4
	eor	V21.16B, V21.16B, V0.16B
	add	w7, w7, w9
	shl	V0.4S, V21.4S, #2
	add	w7, w7, w10
	sri	V0.4S, V21.4S, #30
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	; Round 17
	add	w6, w6, w12
	and	w9, w8, w4
	; W+K for rounds 24-27
	add	V20.4S, V6.4S, V17.4S
	bic	w10, w5, w8
	str	Q20, [x29, #48]
	add	w6, w6, w9
	add	w6, w6, w10
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	; Round 18
	ldp	w11, w12, [x29, #32]
	add	w5, w5, w13
	and	w9, w7, w8
	bic	w10, w4, w7
	add	w5, w5, w9
	add	w5, w5, w10
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	; Round 19
	add	w4, w4, w14
	and	w9, w6, w7
	bic	w10, w8, w6
	add	w4, w4, w9
	add	w4, w4, w10
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	; Round 20
	ldp	w13, w14, [x29, #40]
	; Calc new W[36]-W[39]
	ext8	V21.16B, V7.16B, V0.16B, #8
	add	w8, w8, w11
	eor	V21.16B, V21.16B, V5.16B
	eor	w9, w6, w7
	eor	V21.16B, V21.16B, V2.16B
	eor	w9, w9, w5
	eor	V21.16B, V21.16B, V1.16B
	add	w8, w8, w9
	shl	V1.4S, V21.4S, #2
	ror	w9, w4, #27
	sri	V1.4S, V21.4S, #30
	add	w8, w8, w9
	ror	w5, w5, #2
	; Round 21
	add	w7, w7, w12
	eor	w9, w5, w6
	eor	w9, w9, w4
	; W+K for rounds 28-31
	add	V20.4S, V7.4S, V17.4S
	add	w7, w7, w9
	str	Q20, [x29, #64]
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	; Round 22
	ldp	w11, w12, [x29, #48]
	add	w6, w6, w13
	eor	w9, w4, w5
	eor	w9, w9, w8
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	; Round 23
	add	w5, w5, w14
	eor	w9, w8, w4
	eor	w9, w9, w7
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	; Round 24
	ldp	w13, w14, [x29, #56]
	; Calc new W[40]-W[43]
	ext8	V21.16B, V0.16B, V1.16B, #8
	add	w4, w4, w11
	eor	V21.16B, V21.16B, V6.16B
	eor	w9, w7, w8
	eor	V21.16B, V21.16B, V3.16B
	eor	w9, w9, w6
	eor	V21.16B, V21.16B, V2.16B
	add	w4, w4, w9
	shl	V2.4S, V21.4S, #2
	ror	w9, w5, #27
	sri	V2.4S, V21.4S, #30
	add	w4, w4, w9
	ror	w6, w6, #2
	; Round 25
	add	w8, w8, w12
	eor	w9, w6, w7
	eor	w9, w9, w5
	; W+K for rounds 32-35
	add	V20.4S, V0.4S, V17.4S
	add	w8, w8, w9
	str	Q20, [x29, #16]
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	; Round 26
	ldp	w11, w12, [x29, #64]
	add	w7, w7, w13
	eor	w9, w5, w6
	eor	w9, w9, w4
	add	w7, w7, w9
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	; Round 27
	add	w6, w6, w14
	eor	w9, w4, w5
	eor	w9, w9, w8
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	; Round 28
	ldp	w13, w14, [x29, #72]
	; Calc new W[44]-W[47]
	ext8	V21.16B, V1.16B, V2.16B, #8
	add	w5, w5, w11
	eor	V21.16B, V21.16B, V7.16B
	eor	w9, w8, w4
	eor	V21.16B, V21.16B, V4.16B
	eor	w9, w9, w7
	eor	V21.16B, V21.16B, V3.16B
	add	w5, w5, w9
	shl	V3.4S, V21.4S, #2
	ror	w9, w6, #27
	sri	V3.4S, V21.4S, #30
	add	w5, w5, w9
	ror	w7, w7, #2
	; Round 29
	add	w4, w4, w12
	eor	w9, w7, w8
	eor	w9, w9, w6
	; W+K for rounds 36-39
	add	V20.4S, V1.4S, V17.4S
	add	w4, w4, w9
	str	Q20, [x29, #32]
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	; Round 30
	ldp	w11, w12, [x29, #16]
	add	w8, w8, w13
	eor	w9, w6, w7
	eor	w9, w9, w5
	add	w8, w8, w9
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	; Round 31
	add	w7, w7, w14
	eor	w9, w5, w6
	eor	w9, w9, w4
	add	w7, w7, w9
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	; Round 32
	ldp	w13, w14, [x29, #24]
	; Calc new W[48]-W[51]
	ext8	V21.16B, V2.16B, V3.16B, #8
	add	w6, w6, w11
	eor	V21.16B, V21.16B, V0.16B
	eor	w9, w4, w5
	eor	V21.16B, V21.16B, V5.16B
	eor	w9, w9, w8
	eor	V21.16B, V21.16B, V4.16B
	add	w6, w6, w9
	shl	V4.4S, V21.4S, #2
	ror	w9, w7, #27
	sri	V4.4S, V21.4S, #30
	add	w6, w6, w9
	ror	w8, w8, #2
	; Round 33
	add	w5, w5, w12
	eor	w9, w8, w4
	eor	w9, w9, w7
	; W+K for rounds 40-43
	add	V20.4S, V2.4S, V18.4S
	add	w5, w5, w9
	str	Q20, [x29, #48]
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	; Round 34
	ldp	w11, w12, [x29, #32]
	add	w4, w4, w13
	eor	w9, w7, w8
	eor	w9, w9, w6
	add	w4, w4, w9
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	; Round 35
	add	w8, w8, w14
	eor	w9, w6, w7
	eor	w9, w9, w5
	add	w8, w8, w9
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	; Round 36
	ldp	w13, w14, [x29, #40]
	; Calc new W[52]-W[55]
	ext8	V21.16B, V3.16B, V4.16B, #8
	add	w7, w7, w11
	eor	V21.16B, V21.16B, V1.16B
	eor	w9, w5, w6
	eor	V21.16B, V21.16B, V6.16B
	eor	w9, w9, w4
	eor	V21.16B, V21.16B, V5.16B
	add	w7, w7, w9
	shl	V5.4S, V21.4S, #2
	ror	w9, w8, #27
	sri	V5.4S, V21.4S, #30
	add	w7, w7, w9
	ror	w4, w4, #2
	; Round 37
	add	w6, w6, w12
	eor	w9, w4, w5
	eor	w9, w9, w8
	; W+K for rounds 44-47
	add	V20.4S, V3.4S, V18.4S
	add	w6, w6, w9
	str	Q20, [x29, #64]
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	; Round 38
	ldp	w11, w12, [x29, #48]
	add	w5, w5, w13
	eor	w9, w8, w4
	eor	w9, w9, w7
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	; Round 39
	add	w4, w4, w14
	eor	w9, w7, w8
	eor	w9, w9, w6
	add	w4, w4, w9
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	; Round 40
	ldp	w13, w14, [x29, #56]
	; Calc new W[56]-W[59]
	ext8	V21.16B, V4.16B, V5.16B, #8
	add	w8, w8, w11
	eor	V21.16B, V21.16B, V2.16B
	orr	w9, w6, w7
	eor	V21.16B, V21.16B, V7.16B
	and	w10, w6, w7
	eor	V21.16B, V21.16B, V6.16B
	and	w9, w9, w5
	shl	V6.4S, V21.4S, #2
	orr	w9, w9, w10
	sri	V6.4S, V21.4S, #30
	add	w8, w8, w9
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	; Round 41
	add	w7, w7, w12
	; W+K for rounds 48-51
	add	V20.4S, V4.4S, V18.4S
	orr	w9, w5, w6
	str	Q20, [x29, #16]
	and	w10, w5, w6
	and	w9, w9, w4
	orr	w9, w9, w10
	add	w7, w7, w9
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	; Round 42
	ldp	w11, w12, [x29, #64]
	add	w6, w6, w13
	orr	w9, w4, w5
	and	w10, w4, w5
	and	w9, w9, w8
	orr	w9, w9, w10
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	; Round 43
	add	w5, w5, w14
	orr	w9, w8, w4
	and	w10, w8, w4
	and	w9, w9, w7
	orr	w9, w9, w10
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	; Round 44
	ldp	w13, w14, [x29, #72]
	; Calc new W[60]-W[63]
	ext8	V21.16B, V5.16B, V6.16B, #8
	add	w4, w4, w11
	eor	V21.16B, V21.16B, V3.16B
	orr	w9, w7, w8
	eor	V21.16B, V21.16B, V0.16B
	and	w10, w7, w8
	eor	V21.16B, V21.16B, V7.16B
	and	w9, w9, w6
	shl	V7.4S, V21.4S, #2
	orr	w9, w9, w10
	sri	V7.4S, V21.4S, #30
	add	w4, w4, w9
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	; Round 45
	add	w8, w8, w12
	; W+K for rounds 52-55
	add	V20.4S, V5.4S, V18.4S
	orr	w9, w6, w7
	str	Q20, [x29, #32]
	and	w10, w6, w7
	and	w9, w9, w5
	orr	w9, w9, w10
	add	w8, w8, w9
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	; Round 46
	ldp	w11, w12, [x29, #16]
	add	w7, w7, w13
	orr	w9, w5, w6
	and	w10, w5, w6
	and	w9, w9, w4
	orr	w9, w9, w10
	add	w7, w7, w9
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	; Round 47
	add	w6, w6, w14
	orr	w9, w4, w5
	and	w10, w4, w5
	and	w9, w9, w8
	orr	w9, w9, w10
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	; Round 48
	ldp	w13, w14, [x29, #24]
	; Calc new W[64]-W[67]
	ext8	V21.16B, V6.16B, V7.16B, #8
	add	w5, w5, w11
	eor	V21.16B, V21.16B, V4.16B
	orr	w9, w8, w4
	eor	V21.16B, V21.16B, V1.16B
	and	w10, w8, w4
	eor	V21.16B, V21.16B, V0.16B
	and	w9, w9, w7
	shl	V0.4S, V21.4S, #2
	orr	w9, w9, w10
	sri	V0.4S, V21.4S, #30
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	; Round 49
	add	w4, w4, w12
	; W+K for rounds 56-59
	add	V20.4S, V6.4S, V18.4S
	orr	w9, w7, w8
	str	Q20, [x29, #48]
	and	w10, w7, w8
	and	w9, w9, w6
	orr	w9, w9, w10
	add	w4, w4, w9
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	; Round 50
	ldp	w11, w12, [x29, #32]
	add	w8, w8, w13
	orr	w9, w6, w7
	and	w10, w6, w7
	and	w9, w9, w5
	orr	w9, w9, w10
	add	w8, w8, w9
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	; Round 51
	add	w7, w7, w14
	orr	w9, w5, w6
	and	w10, w5, w6
	and	w9, w9, w4
	orr	w9, w9, w10
	add	w7, w7, w9
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	; Round 52
	ldp	w13, w14, [x29, #40]
	; Calc new W[68]-W[71]
	ext8	V21.16B, V7.16B, V0.16B, #8
	add	w6, w6, w11
	eor	V21.16B, V21.16B, V5.16B
	orr	w9, w4, w5
	eor	V21.16B, V21.16B, V2.16B
	and	w10, w4, w5
	eor	V21.16B, V21.16B, V1.16B
	and	w9, w9, w8
	shl	V1.4S, V21.4S, #2
	orr	w9, w9, w10
	sri	V1.4S, V21.4S, #30
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	; Round 53
	add	w5, w5, w12
	; W+K for rounds 60-63
	add	V20.4S, V7.4S, V19.4S
	orr	w9, w8, w4
	str	Q20, [x29, #64]
	and	w10, w8, w4
	and	w9, w9, w7
	orr	w9, w9, w10
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	; Round 54
	ldp	w11, w12, [x29, #48]
	add	w4, w4, w13
	orr	w9, w7, w8
	and	w10, w7, w8
	and	w9, w9, w6
	orr	w9, w9, w10
	add	w4, w4, w9
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	; Round 55
	add	w8, w8, w14
	orr	w9, w6, w7
	and	w10, w6, w7
	and	w9, w9, w5
	orr	w9, w9, w10
	add	w8, w8, w9
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	; Round 56
	ldp	w13, w14, [x29, #56]
	; Calc new W[72]-W[75]
	ext8	V21.16B, V0.16B, V1.16B, #8
	add	w7, w7, w11
	eor	V21.16B, V21.16B, V6.16B
	orr	w9, w5, w6
	eor	V21.16B, V21.16B, V3.16B
	and	w10, w5, w6
	eor	V21.16B, V21.16B, V2.16B
	and	w9, w9, w4
	shl	V2.4S, V21.4S, #2
	orr	w9, w9, w10
	sri	V2.4S, V21.4S, #30
	add	w7, w7, w9
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	; Round 57
	add	w6, w6, w12
	; W+K for rounds 64-67
	add	V20.4S, V0.4S, V19.4S
	orr	w9, w4, w5
	str	Q20, [x29, #16]
	and	w10, w4, w5
	and	w9, w9, w8
	orr	w9, w9, w10
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	; Round 58
	ldp	w11, w12, [x29, #64]
	add	w5, w5, w13
	orr	w9, w8, w4
	and	w10, w8, w4
	and	w9, w9, w7
	orr	w9, w9, w10
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	; Round 59
	add	w4, w4, w14
	orr	w9, w7, w8
	and	w10, w7, w8
	and	w9, w9, w6
	orr	w9, w9, w10
	add	w4, w4, w9
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	; Round 60
	ldp	w13, w14, [x29, #72]
	; Calc new W[76]-W[79]
	ext8	V21.16B, V1.16B, V2.16B, #8
	add	w8, w8, w11
	eor	V21.16B, V21.16B, V7.16B
	eor	w9, w6, w7
	eor	V21.16B, V21.16B, V4.16B
	eor	w9, w9, w5
	eor	V21.16B, V21.16B, V3.16B
	add	w8, w8, w9
	shl	V3.4S, V21.4S, #2
	ror	w9, w4, #27
	sri	V3.4S, V21.4S, #30
	add	w8, w8, w9
	ror	w5, w5, #2
	; Round 61
	add	w7, w7, w12
	eor	w9, w5, w6
	eor	w9, w9, w4
	; W+K for rounds 68-71
	add	V20.4S, V1.4S, V19.4S
	add	w7, w7, w9
	str	Q20, [x29, #32]
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	; Round 62
	ldp	w11, w12, [x29, #16]
	add	w6, w6, w13
	eor	w9, w4, w5
	eor	w9, w9, w8
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	; Round 63
	add	w5, w5, w14
	eor	w9, w8, w4
	eor	w9, w9, w7
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	; Round 64
	ldp	w13, w14, [x29, #24]
	add	w4, w4, w11
	eor	w9, w7, w8
	eor	w9, w9, w6
	add	w4, w4, w9
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	; Round 65
	add	w8, w8, w12
	eor	w9, w6, w7
	eor	w9, w9, w5
	; W+K for rounds 72-75
	add	V20.4S, V2.4S, V19.4S
	add	w8, w8, w9
	str	Q20, [x29, #48]
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	; Round 66
	ldp	w11, w12, [x29, #32]
	add	w7, w7, w13
	eor	w9, w5, w6
	eor	w9, w9, w4
	add	w7, w7, w9
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	; Round 67
	add	w6, w6, w14
	eor	w9, w4, w5
	eor	w9, w9, w8
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	; Round 68
	ldp	w13, w14, [x29, #40]
	add	w5, w5, w11
	eor	w9, w8, w4
	eor	w9, w9, w7
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	; Round 69
	add	w4, w4, w12
	eor	w9, w7, w8
	eor	w9, w9, w6
	; W+K for rounds 76-79
	add	V20.4S, V3.4S, V19.4S
	add	w4, w4, w9
	str	Q20, [x29, #64]
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	; Round 70
	ldp	w11, w12, [x29, #48]
	add	w8, w8, w13
	eor	w9, w6, w7
	eor	w9, w9, w5
	add	w8, w8, w9
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	; Round 71
	add	w7, w7, w14
	eor	w9, w5, w6
	eor	w9, w9, w4
	add	w7, w7, w9
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	; Round 72
	ldp	w13, w14, [x29, #56]
	add	w6, w6, w11
	eor	w9, w4, w5
	eor	w9, w9, w8
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	; Round 73
	add	w5, w5, w12
	eor	w9, w8, w4
	eor	w9, w9, w7
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	; Round 74
	ldp	w11, w12, [x29, #64]
	add	w4, w4, w13
	eor	w9, w7, w8
	eor	w9, w9, w6
	add	w4, w4, w9
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	; Round 75
	add	w8, w8, w14
	eor	w9, w6, w7
	eor	w9, w9, w5
	add	w8, w8, w9
	ror	w9, w4, #27
	add	w8, w8, w9
	ror	w5, w5, #2
	; Round 76
	ldp	w13, w14, [x29, #72]
	add	w7, w7, w11
	eor	w9, w5, w6
	eor	w9, w9, w4
	add	w7, w7, w9
	ror	w9, w8, #27
	add	w7, w7, w9
	ror	w4, w4, #2
	; Round 77
	add	w6, w6, w12
	eor	w9, w4, w5
	eor	w9, w9, w8
	add	w6, w6, w9
	ror	w9, w7, #27
	add	w6, w6, w9
	ror	w8, w8, #2
	; Round 78
	add	w5, w5, w13
	eor	w9, w8, w4
	eor	w9, w9, w7
	add	w5, w5, w9
	ror	w9, w6, #27
	add	w5, w5, w9
	ror	w7, w7, #2
	; Round 79
	add	w4, w4, w14
	eor	w9, w7, w8
	eor	w9, w9, w6
	add	w4, w4, w9
	ror	w9, w5, #27
	add	w4, w4, w9
	ror	w6, w6, #2
	; Add in digest from start of block
	add	w4, w4, w15
	add	w5, w5, w16
	add	w6, w6, w17
	add	w7, w7, w19
	add	w8, w8, w20
	subs	w2, w2, #0x40
	bne	L_sha1_len_neon_begin
	; Store digest
	str	w4, [x0]
	str	w5, [x0, #4]
	str	w6, [x0, #8]
	str	w7, [x0, #12]
	str	w8, [x0, #16]
	ldp	x17, x19, [x29, #88]
	ldr	x20, [x29, #104]
	ldp	x29, x30, [sp], #0x70
	ret
	ENDP
	ENDIF
	IF :LNOT::DEF:WOLFSSL_ARMASM_NO_HW_CRYPTO
; .arch_extension crypto
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_SHA1_trans_crypto_len_k
	DCD	0x5a827999, 0x5a827999, 0x5a827999, 0x5a827999
	DCD	0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1, 0x6ed9eba1
	DCD	0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc, 0x8f1bbcdc
	DCD	0xca62c1d6, 0xca62c1d6, 0xca62c1d6, 0xca62c1d6
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	Transform_Sha_Len_crypto
Transform_Sha_Len_crypto PROC
	adrp	x3, L_SHA1_trans_crypto_len_k
	add	x3, x3, L_SHA1_trans_crypto_len_k
	; Load K into vector registers
	ld1	{V4.4S, V5.4S, V6.4S, V7.4S}, [x3]
	; Load digest into working vars
	ld1	{V16.4S}, [x0]
	ldr	S17, [x0, #16]
	; Start of loop processing a block
L_sha1_len_crypto_begin
	; Load W
	ld1	{V0.4S, V1.4S, V2.4S, V3.4S}, [x1], #0x40
	rev32	V0.16B, V0.16B
	rev32	V1.16B, V1.16B
	rev32	V2.16B, V2.16B
	rev32	V3.16B, V3.16B
	; Copy digest to add in at end
	mov	V19.16B, V16.16B
	mov	V20.16B, V17.16B
	; Start 80 rounds
	add	V21.4S, V0.4S, V4.4S
	; Rounds 0-3
	sha1su0	V0.4S, V1.4S, V2.4S
	add	V22.4S, V1.4S, V4.4S
	sha1h	S18, S16
	sha1c	Q16, S17, V21.4S
	sha1su1	V0.4S, V3.4S
	; Rounds 4-7
	sha1su0	V1.4S, V2.4S, V3.4S
	add	V21.4S, V2.4S, V4.4S
	sha1h	S17, S16
	sha1c	Q16, S18, V22.4S
	sha1su1	V1.4S, V0.4S
	; Rounds 8-11
	sha1su0	V2.4S, V3.4S, V0.4S
	add	V22.4S, V3.4S, V4.4S
	sha1h	S18, S16
	sha1c	Q16, S17, V21.4S
	sha1su1	V2.4S, V1.4S
	; Rounds 12-15
	sha1su0	V3.4S, V0.4S, V1.4S
	add	V21.4S, V0.4S, V4.4S
	sha1h	S17, S16
	sha1c	Q16, S18, V22.4S
	sha1su1	V3.4S, V2.4S
	; Rounds 16-19
	sha1su0	V0.4S, V1.4S, V2.4S
	add	V22.4S, V1.4S, V5.4S
	sha1h	S18, S16
	sha1c	Q16, S17, V21.4S
	sha1su1	V0.4S, V3.4S
	; Rounds 20-23
	sha1su0	V1.4S, V2.4S, V3.4S
	add	V21.4S, V2.4S, V5.4S
	sha1h	S17, S16
	sha1p	Q16, S18, V22.4S
	sha1su1	V1.4S, V0.4S
	; Rounds 24-27
	sha1su0	V2.4S, V3.4S, V0.4S
	add	V22.4S, V3.4S, V5.4S
	sha1h	S18, S16
	sha1p	Q16, S17, V21.4S
	sha1su1	V2.4S, V1.4S
	; Rounds 28-31
	sha1su0	V3.4S, V0.4S, V1.4S
	add	V21.4S, V0.4S, V5.4S
	sha1h	S17, S16
	sha1p	Q16, S18, V22.4S
	sha1su1	V3.4S, V2.4S
	; Rounds 32-35
	sha1su0	V0.4S, V1.4S, V2.4S
	add	V22.4S, V1.4S, V5.4S
	sha1h	S18, S16
	sha1p	Q16, S17, V21.4S
	sha1su1	V0.4S, V3.4S
	; Rounds 36-39
	sha1su0	V1.4S, V2.4S, V3.4S
	add	V21.4S, V2.4S, V6.4S
	sha1h	S17, S16
	sha1p	Q16, S18, V22.4S
	sha1su1	V1.4S, V0.4S
	; Rounds 40-43
	sha1su0	V2.4S, V3.4S, V0.4S
	add	V22.4S, V3.4S, V6.4S
	sha1h	S18, S16
	sha1m	Q16, S17, V21.4S
	sha1su1	V2.4S, V1.4S
	; Rounds 44-47
	sha1su0	V3.4S, V0.4S, V1.4S
	add	V21.4S, V0.4S, V6.4S
	sha1h	S17, S16
	sha1m	Q16, S18, V22.4S
	sha1su1	V3.4S, V2.4S
	; Rounds 48-51
	sha1su0	V0.4S, V1.4S, V2.4S
	add	V22.4S, V1.4S, V6.4S
	sha1h	S18, S16
	sha1m	Q16, S17, V21.4S
	sha1su1	V0.4S, V3.4S
	; Rounds 52-55
	sha1su0	V1.4S, V2.4S, V3.4S
	add	V21.4S, V2.4S, V6.4S
	sha1h	S17, S16
	sha1m	Q16, S18, V22.4S
	sha1su1	V1.4S, V0.4S
	; Rounds 56-59
	sha1su0	V2.4S, V3.4S, V0.4S
	add	V22.4S, V3.4S, V7.4S
	sha1h	S18, S16
	sha1m	Q16, S17, V21.4S
	sha1su1	V2.4S, V1.4S
	; Rounds 60-63
	sha1su0	V3.4S, V0.4S, V1.4S
	add	V21.4S, V0.4S, V7.4S
	sha1h	S17, S16
	sha1p	Q16, S18, V22.4S
	sha1su1	V3.4S, V2.4S
	; Rounds 64-67
	add	V22.4S, V1.4S, V7.4S
	sha1h	S18, S16
	sha1p	Q16, S17, V21.4S
	; Rounds 68-71
	add	V21.4S, V2.4S, V7.4S
	sha1h	S17, S16
	sha1p	Q16, S18, V22.4S
	; Rounds 72-75
	add	V22.4S, V3.4S, V7.4S
	sha1h	S18, S16
	sha1p	Q16, S17, V21.4S
	; Rounds 76-79
	sha1h	S17, S16
	sha1p	Q16, S18, V22.4S
	; Done 80 rounds
	add	V16.4S, V16.4S, V19.4S
	add	V17.2S, V17.2S, V20.2S
	subs	w2, w2, #0x40
	bne	L_sha1_len_crypto_begin
	; Store digest back
	st1	{V16.4S}, [x0]
	str	S17, [x0, #16]
	ret
	ENDP
	ENDIF
	ENDIF
	ENDIF
	END
