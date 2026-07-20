; /* armv8-sha512-asm
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
;   ruby ./sha2/sha512.rb arm64 \
;       ../wolfssl/wolfcrypt/src/port/arm/armv8-sha512-asm.asm
	IF :DEF:WOLFSSL_SHA512 :LOR: :DEF:WOLFSSL_SHA384
	IF :LNOT::DEF:WOLFSSL_ARMASM_NO_NEON
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	16
L_SHA512_transform_neon_len_k
	DCQ	0x428a2f98d728ae22, 0x7137449123ef65cd
	DCQ	0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc
	DCQ	0x3956c25bf348b538, 0x59f111f1b605d019
	DCQ	0x923f82a4af194f9b, 0xab1c5ed5da6d8118
	DCQ	0xd807aa98a3030242, 0x12835b0145706fbe
	DCQ	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
	DCQ	0x72be5d74f27b896f, 0x80deb1fe3b1696b1
	DCQ	0x9bdc06a725c71235, 0xc19bf174cf692694
	DCQ	0xe49b69c19ef14ad2, 0xefbe4786384f25e3
	DCQ	0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65
	DCQ	0x2de92c6f592b0275, 0x4a7484aa6ea6e483
	DCQ	0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
	DCQ	0x983e5152ee66dfab, 0xa831c66d2db43210
	DCQ	0xb00327c898fb213f, 0xbf597fc7beef0ee4
	DCQ	0xc6e00bf33da88fc2, 0xd5a79147930aa725
	DCQ	0x06ca6351e003826f, 0x142929670a0e6e70
	DCQ	0x27b70a8546d22ffc, 0x2e1b21385c26c926
	DCQ	0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
	DCQ	0x650a73548baf63de, 0x766a0abb3c77b2a8
	DCQ	0x81c2c92e47edaee6, 0x92722c851482353b
	DCQ	0xa2bfe8a14cf10364, 0xa81a664bbc423001
	DCQ	0xc24b8b70d0f89791, 0xc76c51a30654be30
	DCQ	0xd192e819d6ef5218, 0xd69906245565a910
	DCQ	0xf40e35855771202a, 0x106aa07032bbd1b8
	DCQ	0x19a4c116b8d2d0c8, 0x1e376c085141ab53
	DCQ	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8
	DCQ	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb
	DCQ	0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3
	DCQ	0x748f82ee5defb2fc, 0x78a5636f43172f60
	DCQ	0x84c87814a1f0ab72, 0x8cc702081a6439ec
	DCQ	0x90befffa23631e28, 0xa4506cebde82bde9
	DCQ	0xbef9a3f7b2c67915, 0xc67178f2e372532b
	DCQ	0xca273eceea26619c, 0xd186b8c721c0c207
	DCQ	0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178
	DCQ	0x06f067aa72176fba, 0x0a637dc5a2c898a6
	DCQ	0x113f9804bef90dae, 0x1b710b35131c471b
	DCQ	0x28db77f523047d84, 0x32caab7b40c72493
	DCQ	0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c
	DCQ	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a
	DCQ	0x5fcb6fab3ad6faec, 0x6c44198c4a475817
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	16
L_SHA512_transform_neon_len_r8
	DCQ	0x0007060504030201, 0x080f0e0d0c0b0a09
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	Transform_Sha512_Len_neon
Transform_Sha512_Len_neon PROC
	stp	x29, x30, [sp, #-128]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #16]
	stp	x20, x21, [x29, #32]
	stp	x22, x23, [x29, #48]
	stp	x24, x25, [x29, #64]
	stp	x26, x27, [x29, #80]
	stp	D8, D9, [x29, #96]
	stp	D10, D11, [x29, #112]
	adrp	x3, L_SHA512_transform_neon_len_k
	add	x3, x3, L_SHA512_transform_neon_len_k
	adrp	x27, L_SHA512_transform_neon_len_r8
	add	x27, x27, L_SHA512_transform_neon_len_r8
	ld1	{V11.16B}, [x27]
	; Load digest into working vars
	ldp	x4, x5, [x0]
	ldp	x6, x7, [x0, #16]
	ldp	x8, x9, [x0, #32]
	ldp	x10, x11, [x0, #48]
	; Start of loop processing a block
L_sha512_len_neon_begin
	; Load W
	; Copy digest to add in at end
	ld1	{V0.16B, V1.16B, V2.16B, V3.16B}, [x1], #0x40
	mov	x19, x4
	ld1	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	mov	x20, x5
	rev64	V0.16B, V0.16B
	mov	x21, x6
	rev64	V1.16B, V1.16B
	mov	x22, x7
	rev64	V2.16B, V2.16B
	mov	x23, x8
	rev64	V3.16B, V3.16B
	mov	x24, x9
	rev64	V4.16B, V4.16B
	mov	x25, x10
	rev64	V5.16B, V5.16B
	mov	x26, x11
	rev64	V6.16B, V6.16B
	rev64	V7.16B, V7.16B
	; Pre-calc: b ^ c
	eor	x16, x5, x6
	mov	x27, #4
	; Start of 16 rounds
L_sha512_len_neon_start
	; Round 0
	mov	x13, V0.D[0]
	ldr	x15, [x3], #8
	ror	x12, x8, #14
	ror	x14, x4, #28
	eor	x12, x12, x8, ror 18
	eor	x14, x14, x4, ror 34
	eor	x12, x12, x8, ror 41
	eor	x14, x14, x4, ror 39
	add	x11, x11, x12
	eor	x17, x4, x5
	eor	x12, x9, x10
	and	x16, x17, x16
	and	x12, x12, x8
	add	x11, x11, x13
	eor	x12, x12, x10
	add	x11, x11, x15
	eor	x16, x16, x5
	add	x11, x11, x12
	add	x14, x14, x16
	add	x7, x7, x11
	add	x11, x11, x14
	; Round 1
	mov	x13, V0.D[1]
	ldr	x15, [x3], #8
	ext8	V10.16B, V0.16B, V1.16B, #8
	ror	x12, x7, #14
	shl	V8.2D, V7.2D, #45
	ror	x14, x11, #28
	sri	V8.2D, V7.2D, #19
	eor	x12, x12, x7, ror 18
	shl	V9.2D, V7.2D, #3
	eor	x14, x14, x11, ror 34
	sri	V9.2D, V7.2D, #61
	eor	x12, x12, x7, ror 41
	eor	V9.16B, V9.16B, V8.16B
	eor	x14, x14, x11, ror 39
	ushr	V8.2D, V7.2D, #6
	add	x10, x10, x12
	eor	V9.16B, V9.16B, V8.16B
	eor	x16, x11, x4
	add	V0.2D, V0.2D, V9.2D
	eor	x12, x8, x9
	ext8	V9.16B, V4.16B, V5.16B, #8
	and	x17, x16, x17
	add	V0.2D, V0.2D, V9.2D
	and	x12, x12, x7
	shl	V8.2D, V10.2D, #63
	add	x10, x10, x13
	sri	V8.2D, V10.2D, #1
	eor	x12, x12, x9
	tbl	V9.16B, {V10.16B}, V11.16B
	add	x10, x10, x15
	eor	V9.16B, V9.16B, V8.16B
	eor	x17, x17, x4
	ushr	V10.2D, V10.2D, #7
	add	x10, x10, x12
	eor	V9.16B, V9.16B, V10.16B
	add	x14, x14, x17
	add	V0.2D, V0.2D, V9.2D
	add	x6, x6, x10
	add	x10, x10, x14
	; Round 2
	mov	x13, V1.D[0]
	ldr	x15, [x3], #8
	ror	x12, x6, #14
	ror	x14, x10, #28
	eor	x12, x12, x6, ror 18
	eor	x14, x14, x10, ror 34
	eor	x12, x12, x6, ror 41
	eor	x14, x14, x10, ror 39
	add	x9, x9, x12
	eor	x17, x10, x11
	eor	x12, x7, x8
	and	x16, x17, x16
	and	x12, x12, x6
	add	x9, x9, x13
	eor	x12, x12, x8
	add	x9, x9, x15
	eor	x16, x16, x11
	add	x9, x9, x12
	add	x14, x14, x16
	add	x5, x5, x9
	add	x9, x9, x14
	; Round 3
	mov	x13, V1.D[1]
	ldr	x15, [x3], #8
	ext8	V10.16B, V1.16B, V2.16B, #8
	ror	x12, x5, #14
	shl	V8.2D, V0.2D, #45
	ror	x14, x9, #28
	sri	V8.2D, V0.2D, #19
	eor	x12, x12, x5, ror 18
	shl	V9.2D, V0.2D, #3
	eor	x14, x14, x9, ror 34
	sri	V9.2D, V0.2D, #61
	eor	x12, x12, x5, ror 41
	eor	V9.16B, V9.16B, V8.16B
	eor	x14, x14, x9, ror 39
	ushr	V8.2D, V0.2D, #6
	add	x8, x8, x12
	eor	V9.16B, V9.16B, V8.16B
	eor	x16, x9, x10
	add	V1.2D, V1.2D, V9.2D
	eor	x12, x6, x7
	ext8	V9.16B, V5.16B, V6.16B, #8
	and	x17, x16, x17
	add	V1.2D, V1.2D, V9.2D
	and	x12, x12, x5
	shl	V8.2D, V10.2D, #63
	add	x8, x8, x13
	sri	V8.2D, V10.2D, #1
	eor	x12, x12, x7
	tbl	V9.16B, {V10.16B}, V11.16B
	add	x8, x8, x15
	eor	V9.16B, V9.16B, V8.16B
	eor	x17, x17, x10
	ushr	V10.2D, V10.2D, #7
	add	x8, x8, x12
	eor	V9.16B, V9.16B, V10.16B
	add	x14, x14, x17
	add	V1.2D, V1.2D, V9.2D
	add	x4, x4, x8
	add	x8, x8, x14
	; Round 4
	mov	x13, V2.D[0]
	ldr	x15, [x3], #8
	ror	x12, x4, #14
	ror	x14, x8, #28
	eor	x12, x12, x4, ror 18
	eor	x14, x14, x8, ror 34
	eor	x12, x12, x4, ror 41
	eor	x14, x14, x8, ror 39
	add	x7, x7, x12
	eor	x17, x8, x9
	eor	x12, x5, x6
	and	x16, x17, x16
	and	x12, x12, x4
	add	x7, x7, x13
	eor	x12, x12, x6
	add	x7, x7, x15
	eor	x16, x16, x9
	add	x7, x7, x12
	add	x14, x14, x16
	add	x11, x11, x7
	add	x7, x7, x14
	; Round 5
	mov	x13, V2.D[1]
	ldr	x15, [x3], #8
	ext8	V10.16B, V2.16B, V3.16B, #8
	ror	x12, x11, #14
	shl	V8.2D, V1.2D, #45
	ror	x14, x7, #28
	sri	V8.2D, V1.2D, #19
	eor	x12, x12, x11, ror 18
	shl	V9.2D, V1.2D, #3
	eor	x14, x14, x7, ror 34
	sri	V9.2D, V1.2D, #61
	eor	x12, x12, x11, ror 41
	eor	V9.16B, V9.16B, V8.16B
	eor	x14, x14, x7, ror 39
	ushr	V8.2D, V1.2D, #6
	add	x6, x6, x12
	eor	V9.16B, V9.16B, V8.16B
	eor	x16, x7, x8
	add	V2.2D, V2.2D, V9.2D
	eor	x12, x4, x5
	ext8	V9.16B, V6.16B, V7.16B, #8
	and	x17, x16, x17
	add	V2.2D, V2.2D, V9.2D
	and	x12, x12, x11
	shl	V8.2D, V10.2D, #63
	add	x6, x6, x13
	sri	V8.2D, V10.2D, #1
	eor	x12, x12, x5
	tbl	V9.16B, {V10.16B}, V11.16B
	add	x6, x6, x15
	eor	V9.16B, V9.16B, V8.16B
	eor	x17, x17, x8
	ushr	V10.2D, V10.2D, #7
	add	x6, x6, x12
	eor	V9.16B, V9.16B, V10.16B
	add	x14, x14, x17
	add	V2.2D, V2.2D, V9.2D
	add	x10, x10, x6
	add	x6, x6, x14
	; Round 6
	mov	x13, V3.D[0]
	ldr	x15, [x3], #8
	ror	x12, x10, #14
	ror	x14, x6, #28
	eor	x12, x12, x10, ror 18
	eor	x14, x14, x6, ror 34
	eor	x12, x12, x10, ror 41
	eor	x14, x14, x6, ror 39
	add	x5, x5, x12
	eor	x17, x6, x7
	eor	x12, x11, x4
	and	x16, x17, x16
	and	x12, x12, x10
	add	x5, x5, x13
	eor	x12, x12, x4
	add	x5, x5, x15
	eor	x16, x16, x7
	add	x5, x5, x12
	add	x14, x14, x16
	add	x9, x9, x5
	add	x5, x5, x14
	; Round 7
	mov	x13, V3.D[1]
	ldr	x15, [x3], #8
	ext8	V10.16B, V3.16B, V4.16B, #8
	ror	x12, x9, #14
	shl	V8.2D, V2.2D, #45
	ror	x14, x5, #28
	sri	V8.2D, V2.2D, #19
	eor	x12, x12, x9, ror 18
	shl	V9.2D, V2.2D, #3
	eor	x14, x14, x5, ror 34
	sri	V9.2D, V2.2D, #61
	eor	x12, x12, x9, ror 41
	eor	V9.16B, V9.16B, V8.16B
	eor	x14, x14, x5, ror 39
	ushr	V8.2D, V2.2D, #6
	add	x4, x4, x12
	eor	V9.16B, V9.16B, V8.16B
	eor	x16, x5, x6
	add	V3.2D, V3.2D, V9.2D
	eor	x12, x10, x11
	ext8	V9.16B, V7.16B, V0.16B, #8
	and	x17, x16, x17
	add	V3.2D, V3.2D, V9.2D
	and	x12, x12, x9
	shl	V8.2D, V10.2D, #63
	add	x4, x4, x13
	sri	V8.2D, V10.2D, #1
	eor	x12, x12, x11
	tbl	V9.16B, {V10.16B}, V11.16B
	add	x4, x4, x15
	eor	V9.16B, V9.16B, V8.16B
	eor	x17, x17, x6
	ushr	V10.2D, V10.2D, #7
	add	x4, x4, x12
	eor	V9.16B, V9.16B, V10.16B
	add	x14, x14, x17
	add	V3.2D, V3.2D, V9.2D
	add	x8, x8, x4
	add	x4, x4, x14
	; Round 8
	mov	x13, V4.D[0]
	ldr	x15, [x3], #8
	ror	x12, x8, #14
	ror	x14, x4, #28
	eor	x12, x12, x8, ror 18
	eor	x14, x14, x4, ror 34
	eor	x12, x12, x8, ror 41
	eor	x14, x14, x4, ror 39
	add	x11, x11, x12
	eor	x17, x4, x5
	eor	x12, x9, x10
	and	x16, x17, x16
	and	x12, x12, x8
	add	x11, x11, x13
	eor	x12, x12, x10
	add	x11, x11, x15
	eor	x16, x16, x5
	add	x11, x11, x12
	add	x14, x14, x16
	add	x7, x7, x11
	add	x11, x11, x14
	; Round 9
	mov	x13, V4.D[1]
	ldr	x15, [x3], #8
	ext8	V10.16B, V4.16B, V5.16B, #8
	ror	x12, x7, #14
	shl	V8.2D, V3.2D, #45
	ror	x14, x11, #28
	sri	V8.2D, V3.2D, #19
	eor	x12, x12, x7, ror 18
	shl	V9.2D, V3.2D, #3
	eor	x14, x14, x11, ror 34
	sri	V9.2D, V3.2D, #61
	eor	x12, x12, x7, ror 41
	eor	V9.16B, V9.16B, V8.16B
	eor	x14, x14, x11, ror 39
	ushr	V8.2D, V3.2D, #6
	add	x10, x10, x12
	eor	V9.16B, V9.16B, V8.16B
	eor	x16, x11, x4
	add	V4.2D, V4.2D, V9.2D
	eor	x12, x8, x9
	ext8	V9.16B, V0.16B, V1.16B, #8
	and	x17, x16, x17
	add	V4.2D, V4.2D, V9.2D
	and	x12, x12, x7
	shl	V8.2D, V10.2D, #63
	add	x10, x10, x13
	sri	V8.2D, V10.2D, #1
	eor	x12, x12, x9
	tbl	V9.16B, {V10.16B}, V11.16B
	add	x10, x10, x15
	eor	V9.16B, V9.16B, V8.16B
	eor	x17, x17, x4
	ushr	V10.2D, V10.2D, #7
	add	x10, x10, x12
	eor	V9.16B, V9.16B, V10.16B
	add	x14, x14, x17
	add	V4.2D, V4.2D, V9.2D
	add	x6, x6, x10
	add	x10, x10, x14
	; Round 10
	mov	x13, V5.D[0]
	ldr	x15, [x3], #8
	ror	x12, x6, #14
	ror	x14, x10, #28
	eor	x12, x12, x6, ror 18
	eor	x14, x14, x10, ror 34
	eor	x12, x12, x6, ror 41
	eor	x14, x14, x10, ror 39
	add	x9, x9, x12
	eor	x17, x10, x11
	eor	x12, x7, x8
	and	x16, x17, x16
	and	x12, x12, x6
	add	x9, x9, x13
	eor	x12, x12, x8
	add	x9, x9, x15
	eor	x16, x16, x11
	add	x9, x9, x12
	add	x14, x14, x16
	add	x5, x5, x9
	add	x9, x9, x14
	; Round 11
	mov	x13, V5.D[1]
	ldr	x15, [x3], #8
	ext8	V10.16B, V5.16B, V6.16B, #8
	ror	x12, x5, #14
	shl	V8.2D, V4.2D, #45
	ror	x14, x9, #28
	sri	V8.2D, V4.2D, #19
	eor	x12, x12, x5, ror 18
	shl	V9.2D, V4.2D, #3
	eor	x14, x14, x9, ror 34
	sri	V9.2D, V4.2D, #61
	eor	x12, x12, x5, ror 41
	eor	V9.16B, V9.16B, V8.16B
	eor	x14, x14, x9, ror 39
	ushr	V8.2D, V4.2D, #6
	add	x8, x8, x12
	eor	V9.16B, V9.16B, V8.16B
	eor	x16, x9, x10
	add	V5.2D, V5.2D, V9.2D
	eor	x12, x6, x7
	ext8	V9.16B, V1.16B, V2.16B, #8
	and	x17, x16, x17
	add	V5.2D, V5.2D, V9.2D
	and	x12, x12, x5
	shl	V8.2D, V10.2D, #63
	add	x8, x8, x13
	sri	V8.2D, V10.2D, #1
	eor	x12, x12, x7
	tbl	V9.16B, {V10.16B}, V11.16B
	add	x8, x8, x15
	eor	V9.16B, V9.16B, V8.16B
	eor	x17, x17, x10
	ushr	V10.2D, V10.2D, #7
	add	x8, x8, x12
	eor	V9.16B, V9.16B, V10.16B
	add	x14, x14, x17
	add	V5.2D, V5.2D, V9.2D
	add	x4, x4, x8
	add	x8, x8, x14
	; Round 12
	mov	x13, V6.D[0]
	ldr	x15, [x3], #8
	ror	x12, x4, #14
	ror	x14, x8, #28
	eor	x12, x12, x4, ror 18
	eor	x14, x14, x8, ror 34
	eor	x12, x12, x4, ror 41
	eor	x14, x14, x8, ror 39
	add	x7, x7, x12
	eor	x17, x8, x9
	eor	x12, x5, x6
	and	x16, x17, x16
	and	x12, x12, x4
	add	x7, x7, x13
	eor	x12, x12, x6
	add	x7, x7, x15
	eor	x16, x16, x9
	add	x7, x7, x12
	add	x14, x14, x16
	add	x11, x11, x7
	add	x7, x7, x14
	; Round 13
	mov	x13, V6.D[1]
	ldr	x15, [x3], #8
	ext8	V10.16B, V6.16B, V7.16B, #8
	ror	x12, x11, #14
	shl	V8.2D, V5.2D, #45
	ror	x14, x7, #28
	sri	V8.2D, V5.2D, #19
	eor	x12, x12, x11, ror 18
	shl	V9.2D, V5.2D, #3
	eor	x14, x14, x7, ror 34
	sri	V9.2D, V5.2D, #61
	eor	x12, x12, x11, ror 41
	eor	V9.16B, V9.16B, V8.16B
	eor	x14, x14, x7, ror 39
	ushr	V8.2D, V5.2D, #6
	add	x6, x6, x12
	eor	V9.16B, V9.16B, V8.16B
	eor	x16, x7, x8
	add	V6.2D, V6.2D, V9.2D
	eor	x12, x4, x5
	ext8	V9.16B, V2.16B, V3.16B, #8
	and	x17, x16, x17
	add	V6.2D, V6.2D, V9.2D
	and	x12, x12, x11
	shl	V8.2D, V10.2D, #63
	add	x6, x6, x13
	sri	V8.2D, V10.2D, #1
	eor	x12, x12, x5
	tbl	V9.16B, {V10.16B}, V11.16B
	add	x6, x6, x15
	eor	V9.16B, V9.16B, V8.16B
	eor	x17, x17, x8
	ushr	V10.2D, V10.2D, #7
	add	x6, x6, x12
	eor	V9.16B, V9.16B, V10.16B
	add	x14, x14, x17
	add	V6.2D, V6.2D, V9.2D
	add	x10, x10, x6
	add	x6, x6, x14
	; Round 14
	mov	x13, V7.D[0]
	ldr	x15, [x3], #8
	ror	x12, x10, #14
	ror	x14, x6, #28
	eor	x12, x12, x10, ror 18
	eor	x14, x14, x6, ror 34
	eor	x12, x12, x10, ror 41
	eor	x14, x14, x6, ror 39
	add	x5, x5, x12
	eor	x17, x6, x7
	eor	x12, x11, x4
	and	x16, x17, x16
	and	x12, x12, x10
	add	x5, x5, x13
	eor	x12, x12, x4
	add	x5, x5, x15
	eor	x16, x16, x7
	add	x5, x5, x12
	add	x14, x14, x16
	add	x9, x9, x5
	add	x5, x5, x14
	; Round 15
	mov	x13, V7.D[1]
	ldr	x15, [x3], #8
	ext8	V10.16B, V7.16B, V0.16B, #8
	ror	x12, x9, #14
	shl	V8.2D, V6.2D, #45
	ror	x14, x5, #28
	sri	V8.2D, V6.2D, #19
	eor	x12, x12, x9, ror 18
	shl	V9.2D, V6.2D, #3
	eor	x14, x14, x5, ror 34
	sri	V9.2D, V6.2D, #61
	eor	x12, x12, x9, ror 41
	eor	V9.16B, V9.16B, V8.16B
	eor	x14, x14, x5, ror 39
	ushr	V8.2D, V6.2D, #6
	add	x4, x4, x12
	eor	V9.16B, V9.16B, V8.16B
	eor	x16, x5, x6
	add	V7.2D, V7.2D, V9.2D
	eor	x12, x10, x11
	ext8	V9.16B, V3.16B, V4.16B, #8
	and	x17, x16, x17
	add	V7.2D, V7.2D, V9.2D
	and	x12, x12, x9
	shl	V8.2D, V10.2D, #63
	add	x4, x4, x13
	sri	V8.2D, V10.2D, #1
	eor	x12, x12, x11
	tbl	V9.16B, {V10.16B}, V11.16B
	add	x4, x4, x15
	eor	V9.16B, V9.16B, V8.16B
	eor	x17, x17, x6
	ushr	V10.2D, V10.2D, #7
	add	x4, x4, x12
	eor	V9.16B, V9.16B, V10.16B
	add	x14, x14, x17
	add	V7.2D, V7.2D, V9.2D
	add	x8, x8, x4
	add	x4, x4, x14
	subs	x27, x27, #1
	bne	L_sha512_len_neon_start
	; Round 0
	mov	x13, V0.D[0]
	ldr	x15, [x3], #8
	ror	x12, x8, #14
	ror	x14, x4, #28
	eor	x12, x12, x8, ror 18
	eor	x14, x14, x4, ror 34
	eor	x12, x12, x8, ror 41
	eor	x14, x14, x4, ror 39
	add	x11, x11, x12
	eor	x17, x4, x5
	eor	x12, x9, x10
	and	x16, x17, x16
	and	x12, x12, x8
	add	x11, x11, x13
	eor	x12, x12, x10
	add	x11, x11, x15
	eor	x16, x16, x5
	add	x11, x11, x12
	add	x14, x14, x16
	add	x7, x7, x11
	add	x11, x11, x14
	; Round 1
	mov	x13, V0.D[1]
	ldr	x15, [x3], #8
	ror	x12, x7, #14
	ror	x14, x11, #28
	eor	x12, x12, x7, ror 18
	eor	x14, x14, x11, ror 34
	eor	x12, x12, x7, ror 41
	eor	x14, x14, x11, ror 39
	add	x10, x10, x12
	eor	x16, x11, x4
	eor	x12, x8, x9
	and	x17, x16, x17
	and	x12, x12, x7
	add	x10, x10, x13
	eor	x12, x12, x9
	add	x10, x10, x15
	eor	x17, x17, x4
	add	x10, x10, x12
	add	x14, x14, x17
	add	x6, x6, x10
	add	x10, x10, x14
	; Round 2
	mov	x13, V1.D[0]
	ldr	x15, [x3], #8
	ror	x12, x6, #14
	ror	x14, x10, #28
	eor	x12, x12, x6, ror 18
	eor	x14, x14, x10, ror 34
	eor	x12, x12, x6, ror 41
	eor	x14, x14, x10, ror 39
	add	x9, x9, x12
	eor	x17, x10, x11
	eor	x12, x7, x8
	and	x16, x17, x16
	and	x12, x12, x6
	add	x9, x9, x13
	eor	x12, x12, x8
	add	x9, x9, x15
	eor	x16, x16, x11
	add	x9, x9, x12
	add	x14, x14, x16
	add	x5, x5, x9
	add	x9, x9, x14
	; Round 3
	mov	x13, V1.D[1]
	ldr	x15, [x3], #8
	ror	x12, x5, #14
	ror	x14, x9, #28
	eor	x12, x12, x5, ror 18
	eor	x14, x14, x9, ror 34
	eor	x12, x12, x5, ror 41
	eor	x14, x14, x9, ror 39
	add	x8, x8, x12
	eor	x16, x9, x10
	eor	x12, x6, x7
	and	x17, x16, x17
	and	x12, x12, x5
	add	x8, x8, x13
	eor	x12, x12, x7
	add	x8, x8, x15
	eor	x17, x17, x10
	add	x8, x8, x12
	add	x14, x14, x17
	add	x4, x4, x8
	add	x8, x8, x14
	; Round 4
	mov	x13, V2.D[0]
	ldr	x15, [x3], #8
	ror	x12, x4, #14
	ror	x14, x8, #28
	eor	x12, x12, x4, ror 18
	eor	x14, x14, x8, ror 34
	eor	x12, x12, x4, ror 41
	eor	x14, x14, x8, ror 39
	add	x7, x7, x12
	eor	x17, x8, x9
	eor	x12, x5, x6
	and	x16, x17, x16
	and	x12, x12, x4
	add	x7, x7, x13
	eor	x12, x12, x6
	add	x7, x7, x15
	eor	x16, x16, x9
	add	x7, x7, x12
	add	x14, x14, x16
	add	x11, x11, x7
	add	x7, x7, x14
	; Round 5
	mov	x13, V2.D[1]
	ldr	x15, [x3], #8
	ror	x12, x11, #14
	ror	x14, x7, #28
	eor	x12, x12, x11, ror 18
	eor	x14, x14, x7, ror 34
	eor	x12, x12, x11, ror 41
	eor	x14, x14, x7, ror 39
	add	x6, x6, x12
	eor	x16, x7, x8
	eor	x12, x4, x5
	and	x17, x16, x17
	and	x12, x12, x11
	add	x6, x6, x13
	eor	x12, x12, x5
	add	x6, x6, x15
	eor	x17, x17, x8
	add	x6, x6, x12
	add	x14, x14, x17
	add	x10, x10, x6
	add	x6, x6, x14
	; Round 6
	mov	x13, V3.D[0]
	ldr	x15, [x3], #8
	ror	x12, x10, #14
	ror	x14, x6, #28
	eor	x12, x12, x10, ror 18
	eor	x14, x14, x6, ror 34
	eor	x12, x12, x10, ror 41
	eor	x14, x14, x6, ror 39
	add	x5, x5, x12
	eor	x17, x6, x7
	eor	x12, x11, x4
	and	x16, x17, x16
	and	x12, x12, x10
	add	x5, x5, x13
	eor	x12, x12, x4
	add	x5, x5, x15
	eor	x16, x16, x7
	add	x5, x5, x12
	add	x14, x14, x16
	add	x9, x9, x5
	add	x5, x5, x14
	; Round 7
	mov	x13, V3.D[1]
	ldr	x15, [x3], #8
	ror	x12, x9, #14
	ror	x14, x5, #28
	eor	x12, x12, x9, ror 18
	eor	x14, x14, x5, ror 34
	eor	x12, x12, x9, ror 41
	eor	x14, x14, x5, ror 39
	add	x4, x4, x12
	eor	x16, x5, x6
	eor	x12, x10, x11
	and	x17, x16, x17
	and	x12, x12, x9
	add	x4, x4, x13
	eor	x12, x12, x11
	add	x4, x4, x15
	eor	x17, x17, x6
	add	x4, x4, x12
	add	x14, x14, x17
	add	x8, x8, x4
	add	x4, x4, x14
	; Round 8
	mov	x13, V4.D[0]
	ldr	x15, [x3], #8
	ror	x12, x8, #14
	ror	x14, x4, #28
	eor	x12, x12, x8, ror 18
	eor	x14, x14, x4, ror 34
	eor	x12, x12, x8, ror 41
	eor	x14, x14, x4, ror 39
	add	x11, x11, x12
	eor	x17, x4, x5
	eor	x12, x9, x10
	and	x16, x17, x16
	and	x12, x12, x8
	add	x11, x11, x13
	eor	x12, x12, x10
	add	x11, x11, x15
	eor	x16, x16, x5
	add	x11, x11, x12
	add	x14, x14, x16
	add	x7, x7, x11
	add	x11, x11, x14
	; Round 9
	mov	x13, V4.D[1]
	ldr	x15, [x3], #8
	ror	x12, x7, #14
	ror	x14, x11, #28
	eor	x12, x12, x7, ror 18
	eor	x14, x14, x11, ror 34
	eor	x12, x12, x7, ror 41
	eor	x14, x14, x11, ror 39
	add	x10, x10, x12
	eor	x16, x11, x4
	eor	x12, x8, x9
	and	x17, x16, x17
	and	x12, x12, x7
	add	x10, x10, x13
	eor	x12, x12, x9
	add	x10, x10, x15
	eor	x17, x17, x4
	add	x10, x10, x12
	add	x14, x14, x17
	add	x6, x6, x10
	add	x10, x10, x14
	; Round 10
	mov	x13, V5.D[0]
	ldr	x15, [x3], #8
	ror	x12, x6, #14
	ror	x14, x10, #28
	eor	x12, x12, x6, ror 18
	eor	x14, x14, x10, ror 34
	eor	x12, x12, x6, ror 41
	eor	x14, x14, x10, ror 39
	add	x9, x9, x12
	eor	x17, x10, x11
	eor	x12, x7, x8
	and	x16, x17, x16
	and	x12, x12, x6
	add	x9, x9, x13
	eor	x12, x12, x8
	add	x9, x9, x15
	eor	x16, x16, x11
	add	x9, x9, x12
	add	x14, x14, x16
	add	x5, x5, x9
	add	x9, x9, x14
	; Round 11
	mov	x13, V5.D[1]
	ldr	x15, [x3], #8
	ror	x12, x5, #14
	ror	x14, x9, #28
	eor	x12, x12, x5, ror 18
	eor	x14, x14, x9, ror 34
	eor	x12, x12, x5, ror 41
	eor	x14, x14, x9, ror 39
	add	x8, x8, x12
	eor	x16, x9, x10
	eor	x12, x6, x7
	and	x17, x16, x17
	and	x12, x12, x5
	add	x8, x8, x13
	eor	x12, x12, x7
	add	x8, x8, x15
	eor	x17, x17, x10
	add	x8, x8, x12
	add	x14, x14, x17
	add	x4, x4, x8
	add	x8, x8, x14
	; Round 12
	mov	x13, V6.D[0]
	ldr	x15, [x3], #8
	ror	x12, x4, #14
	ror	x14, x8, #28
	eor	x12, x12, x4, ror 18
	eor	x14, x14, x8, ror 34
	eor	x12, x12, x4, ror 41
	eor	x14, x14, x8, ror 39
	add	x7, x7, x12
	eor	x17, x8, x9
	eor	x12, x5, x6
	and	x16, x17, x16
	and	x12, x12, x4
	add	x7, x7, x13
	eor	x12, x12, x6
	add	x7, x7, x15
	eor	x16, x16, x9
	add	x7, x7, x12
	add	x14, x14, x16
	add	x11, x11, x7
	add	x7, x7, x14
	; Round 13
	mov	x13, V6.D[1]
	ldr	x15, [x3], #8
	ror	x12, x11, #14
	ror	x14, x7, #28
	eor	x12, x12, x11, ror 18
	eor	x14, x14, x7, ror 34
	eor	x12, x12, x11, ror 41
	eor	x14, x14, x7, ror 39
	add	x6, x6, x12
	eor	x16, x7, x8
	eor	x12, x4, x5
	and	x17, x16, x17
	and	x12, x12, x11
	add	x6, x6, x13
	eor	x12, x12, x5
	add	x6, x6, x15
	eor	x17, x17, x8
	add	x6, x6, x12
	add	x14, x14, x17
	add	x10, x10, x6
	add	x6, x6, x14
	; Round 14
	mov	x13, V7.D[0]
	ldr	x15, [x3], #8
	ror	x12, x10, #14
	ror	x14, x6, #28
	eor	x12, x12, x10, ror 18
	eor	x14, x14, x6, ror 34
	eor	x12, x12, x10, ror 41
	eor	x14, x14, x6, ror 39
	add	x5, x5, x12
	eor	x17, x6, x7
	eor	x12, x11, x4
	and	x16, x17, x16
	and	x12, x12, x10
	add	x5, x5, x13
	eor	x12, x12, x4
	add	x5, x5, x15
	eor	x16, x16, x7
	add	x5, x5, x12
	add	x14, x14, x16
	add	x9, x9, x5
	add	x5, x5, x14
	; Round 15
	mov	x13, V7.D[1]
	ldr	x15, [x3], #8
	ror	x12, x9, #14
	ror	x14, x5, #28
	eor	x12, x12, x9, ror 18
	eor	x14, x14, x5, ror 34
	eor	x12, x12, x9, ror 41
	eor	x14, x14, x5, ror 39
	add	x4, x4, x12
	eor	x16, x5, x6
	eor	x12, x10, x11
	and	x17, x16, x17
	and	x12, x12, x9
	add	x4, x4, x13
	eor	x12, x12, x11
	add	x4, x4, x15
	eor	x17, x17, x6
	add	x4, x4, x12
	add	x14, x14, x17
	add	x8, x8, x4
	add	x4, x4, x14
	add	x11, x11, x26
	add	x10, x10, x25
	add	x9, x9, x24
	add	x8, x8, x23
	add	x7, x7, x22
	add	x6, x6, x21
	add	x5, x5, x20
	add	x4, x4, x19
	subs	w2, w2, #0x80
	sub	x3, x3, #0x280
	bne	L_sha512_len_neon_begin
	stp	x4, x5, [x0]
	stp	x6, x7, [x0, #16]
	stp	x8, x9, [x0, #32]
	stp	x10, x11, [x0, #48]
	ldp	x17, x19, [x29, #16]
	ldp	x20, x21, [x29, #32]
	ldp	x22, x23, [x29, #48]
	ldp	x24, x25, [x29, #64]
	ldp	x26, x27, [x29, #80]
	ldp	D8, D9, [x29, #96]
	ldp	D10, D11, [x29, #112]
	ldp	x29, x30, [sp], #0x80
	ret
	ENDP
	IF :DEF:WOLFSSL_ARMASM_CRYPTO_SHA512
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	16
L_SHA512_trans_crypto_len_k
	DCQ	0x428a2f98d728ae22, 0x7137449123ef65cd
	DCQ	0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc
	DCQ	0x3956c25bf348b538, 0x59f111f1b605d019
	DCQ	0x923f82a4af194f9b, 0xab1c5ed5da6d8118
	DCQ	0xd807aa98a3030242, 0x12835b0145706fbe
	DCQ	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
	DCQ	0x72be5d74f27b896f, 0x80deb1fe3b1696b1
	DCQ	0x9bdc06a725c71235, 0xc19bf174cf692694
	DCQ	0xe49b69c19ef14ad2, 0xefbe4786384f25e3
	DCQ	0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65
	DCQ	0x2de92c6f592b0275, 0x4a7484aa6ea6e483
	DCQ	0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
	DCQ	0x983e5152ee66dfab, 0xa831c66d2db43210
	DCQ	0xb00327c898fb213f, 0xbf597fc7beef0ee4
	DCQ	0xc6e00bf33da88fc2, 0xd5a79147930aa725
	DCQ	0x06ca6351e003826f, 0x142929670a0e6e70
	DCQ	0x27b70a8546d22ffc, 0x2e1b21385c26c926
	DCQ	0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
	DCQ	0x650a73548baf63de, 0x766a0abb3c77b2a8
	DCQ	0x81c2c92e47edaee6, 0x92722c851482353b
	DCQ	0xa2bfe8a14cf10364, 0xa81a664bbc423001
	DCQ	0xc24b8b70d0f89791, 0xc76c51a30654be30
	DCQ	0xd192e819d6ef5218, 0xd69906245565a910
	DCQ	0xf40e35855771202a, 0x106aa07032bbd1b8
	DCQ	0x19a4c116b8d2d0c8, 0x1e376c085141ab53
	DCQ	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8
	DCQ	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb
	DCQ	0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3
	DCQ	0x748f82ee5defb2fc, 0x78a5636f43172f60
	DCQ	0x84c87814a1f0ab72, 0x8cc702081a6439ec
	DCQ	0x90befffa23631e28, 0xa4506cebde82bde9
	DCQ	0xbef9a3f7b2c67915, 0xc67178f2e372532b
	DCQ	0xca273eceea26619c, 0xd186b8c721c0c207
	DCQ	0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178
	DCQ	0x06f067aa72176fba, 0x0a637dc5a2c898a6
	DCQ	0x113f9804bef90dae, 0x1b710b35131c471b
	DCQ	0x28db77f523047d84, 0x32caab7b40c72493
	DCQ	0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c
	DCQ	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a
	DCQ	0x5fcb6fab3ad6faec, 0x6c44198c4a475817
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	Transform_Sha512_Len_crypto
Transform_Sha512_Len_crypto PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x4, L_SHA512_trans_crypto_len_k
	add	x4, x4, L_SHA512_trans_crypto_len_k
; .arch_extension sha3
	; Load K into vector registers
	ld1	{V8.2D, V9.2D, V10.2D, V11.2D}, [x4], #0x40
	ld1	{V12.2D, V13.2D, V14.2D, V15.2D}, [x4], #0x40
	; Load digest into working vars
	ld1	{V24.2D, V25.2D, V26.2D, V27.2D}, [x0]
	; Start of loop processing a block
L_sha512_len_crypto_begin
	mov	x3, x4
	; Load W
	ld1	{V0.16B, V1.16B, V2.16B, V3.16B}, [x1], #0x40
	ld1	{V4.16B, V5.16B, V6.16B, V7.16B}, [x1], #0x40
	rev64	V0.16B, V0.16B
	rev64	V1.16B, V1.16B
	rev64	V2.16B, V2.16B
	rev64	V3.16B, V3.16B
	rev64	V4.16B, V4.16B
	rev64	V5.16B, V5.16B
	rev64	V6.16B, V6.16B
	rev64	V7.16B, V7.16B
	; Copy digest to add in at end
	mov	V28.16B, V24.16B
	mov	V29.16B, V25.16B
	mov	V30.16B, V26.16B
	mov	V31.16B, V27.16B
	; Start of 16 rounds
	; Round 0
	add	V20.2D, V0.2D, V8.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V26.16B, V27.16B, #8
	ext8	V22.16B, V25.16B, V26.16B, #8
	add	V27.2D, V27.2D, V20.2D
	sha512h	Q27, Q21, V22.2D
	add	V23.2D, V25.2D, V27.2D
	sha512h2	Q27, Q25, V24.2D
	; Round 1
	add	V20.2D, V1.2D, V9.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V23.16B, V26.16B, #8
	ext8	V22.16B, V24.16B, V23.16B, #8
	add	V26.2D, V26.2D, V20.2D
	sha512h	Q26, Q21, V22.2D
	add	V25.2D, V24.2D, V26.2D
	sha512h2	Q26, Q24, V27.2D
	; Round 2
	add	V20.2D, V2.2D, V10.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V25.16B, V23.16B, #8
	ext8	V22.16B, V27.16B, V25.16B, #8
	add	V23.2D, V23.2D, V20.2D
	sha512h	Q23, Q21, V22.2D
	add	V24.2D, V27.2D, V23.2D
	sha512h2	Q23, Q27, V26.2D
	; Round 3
	add	V20.2D, V3.2D, V11.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V24.16B, V25.16B, #8
	ext8	V22.16B, V26.16B, V24.16B, #8
	add	V25.2D, V25.2D, V20.2D
	sha512h	Q25, Q21, V22.2D
	add	V27.2D, V26.2D, V25.2D
	sha512h2	Q25, Q26, V23.2D
	; Round 4
	add	V20.2D, V4.2D, V12.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V27.16B, V24.16B, #8
	ext8	V22.16B, V23.16B, V27.16B, #8
	add	V24.2D, V24.2D, V20.2D
	sha512h	Q24, Q21, V22.2D
	add	V26.2D, V23.2D, V24.2D
	sha512h2	Q24, Q23, V25.2D
	; Round 5
	add	V20.2D, V5.2D, V13.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V26.16B, V27.16B, #8
	ext8	V22.16B, V25.16B, V26.16B, #8
	add	V27.2D, V27.2D, V20.2D
	sha512h	Q27, Q21, V22.2D
	add	V23.2D, V25.2D, V27.2D
	sha512h2	Q27, Q25, V24.2D
	; Round 6
	add	V20.2D, V6.2D, V14.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V23.16B, V26.16B, #8
	ext8	V22.16B, V24.16B, V23.16B, #8
	add	V26.2D, V26.2D, V20.2D
	sha512h	Q26, Q21, V22.2D
	add	V25.2D, V24.2D, V26.2D
	sha512h2	Q26, Q24, V27.2D
	; Round 7
	add	V20.2D, V7.2D, V15.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V25.16B, V23.16B, #8
	ext8	V22.16B, V27.16B, V25.16B, #8
	add	V23.2D, V23.2D, V20.2D
	sha512h	Q23, Q21, V22.2D
	add	V24.2D, V27.2D, V23.2D
	sha512h2	Q23, Q27, V26.2D
	; Load next 8 64-bit words of K
	ld1	{V16.2D, V17.2D, V18.2D, V19.2D}, [x3], #0x40
	; Round 8
	sha512su0	V0.2D, V1.2D
	ext8	V21.16B, V4.16B, V5.16B, #8
	sha512su1	V0.2D, V7.2D, V21.2D
	add	V20.2D, V0.2D, V16.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V24.16B, V25.16B, #8
	ext8	V22.16B, V26.16B, V24.16B, #8
	add	V25.2D, V25.2D, V20.2D
	sha512h	Q25, Q21, V22.2D
	add	V27.2D, V26.2D, V25.2D
	sha512h2	Q25, Q26, V23.2D
	; Round 9
	sha512su0	V1.2D, V2.2D
	ext8	V21.16B, V5.16B, V6.16B, #8
	sha512su1	V1.2D, V0.2D, V21.2D
	add	V20.2D, V1.2D, V17.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V27.16B, V24.16B, #8
	ext8	V22.16B, V23.16B, V27.16B, #8
	add	V24.2D, V24.2D, V20.2D
	sha512h	Q24, Q21, V22.2D
	add	V26.2D, V23.2D, V24.2D
	sha512h2	Q24, Q23, V25.2D
	; Round 10
	sha512su0	V2.2D, V3.2D
	ext8	V21.16B, V6.16B, V7.16B, #8
	sha512su1	V2.2D, V1.2D, V21.2D
	add	V20.2D, V2.2D, V18.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V26.16B, V27.16B, #8
	ext8	V22.16B, V25.16B, V26.16B, #8
	add	V27.2D, V27.2D, V20.2D
	sha512h	Q27, Q21, V22.2D
	add	V23.2D, V25.2D, V27.2D
	sha512h2	Q27, Q25, V24.2D
	; Round 11
	sha512su0	V3.2D, V4.2D
	ext8	V21.16B, V7.16B, V0.16B, #8
	sha512su1	V3.2D, V2.2D, V21.2D
	add	V20.2D, V3.2D, V19.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V23.16B, V26.16B, #8
	ext8	V22.16B, V24.16B, V23.16B, #8
	add	V26.2D, V26.2D, V20.2D
	sha512h	Q26, Q21, V22.2D
	add	V25.2D, V24.2D, V26.2D
	sha512h2	Q26, Q24, V27.2D
	; Load next 8 64-bit words of K
	ld1	{V16.2D, V17.2D, V18.2D, V19.2D}, [x3], #0x40
	; Round 12
	sha512su0	V4.2D, V5.2D
	ext8	V21.16B, V0.16B, V1.16B, #8
	sha512su1	V4.2D, V3.2D, V21.2D
	add	V20.2D, V4.2D, V16.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V25.16B, V23.16B, #8
	ext8	V22.16B, V27.16B, V25.16B, #8
	add	V23.2D, V23.2D, V20.2D
	sha512h	Q23, Q21, V22.2D
	add	V24.2D, V27.2D, V23.2D
	sha512h2	Q23, Q27, V26.2D
	; Round 13
	sha512su0	V5.2D, V6.2D
	ext8	V21.16B, V1.16B, V2.16B, #8
	sha512su1	V5.2D, V4.2D, V21.2D
	add	V20.2D, V5.2D, V17.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V24.16B, V25.16B, #8
	ext8	V22.16B, V26.16B, V24.16B, #8
	add	V25.2D, V25.2D, V20.2D
	sha512h	Q25, Q21, V22.2D
	add	V27.2D, V26.2D, V25.2D
	sha512h2	Q25, Q26, V23.2D
	; Round 14
	sha512su0	V6.2D, V7.2D
	ext8	V21.16B, V2.16B, V3.16B, #8
	sha512su1	V6.2D, V5.2D, V21.2D
	add	V20.2D, V6.2D, V18.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V27.16B, V24.16B, #8
	ext8	V22.16B, V23.16B, V27.16B, #8
	add	V24.2D, V24.2D, V20.2D
	sha512h	Q24, Q21, V22.2D
	add	V26.2D, V23.2D, V24.2D
	sha512h2	Q24, Q23, V25.2D
	; Round 15
	sha512su0	V7.2D, V0.2D
	ext8	V21.16B, V3.16B, V4.16B, #8
	sha512su1	V7.2D, V6.2D, V21.2D
	add	V20.2D, V7.2D, V19.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V26.16B, V27.16B, #8
	ext8	V22.16B, V25.16B, V26.16B, #8
	add	V27.2D, V27.2D, V20.2D
	sha512h	Q27, Q21, V22.2D
	add	V23.2D, V25.2D, V27.2D
	sha512h2	Q27, Q25, V24.2D
	; Load next 8 64-bit words of K
	ld1	{V16.2D, V17.2D, V18.2D, V19.2D}, [x3], #0x40
	; Round 16
	sha512su0	V0.2D, V1.2D
	ext8	V21.16B, V4.16B, V5.16B, #8
	sha512su1	V0.2D, V7.2D, V21.2D
	add	V20.2D, V0.2D, V16.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V23.16B, V26.16B, #8
	ext8	V22.16B, V24.16B, V23.16B, #8
	add	V26.2D, V26.2D, V20.2D
	sha512h	Q26, Q21, V22.2D
	add	V25.2D, V24.2D, V26.2D
	sha512h2	Q26, Q24, V27.2D
	; Round 17
	sha512su0	V1.2D, V2.2D
	ext8	V21.16B, V5.16B, V6.16B, #8
	sha512su1	V1.2D, V0.2D, V21.2D
	add	V20.2D, V1.2D, V17.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V25.16B, V23.16B, #8
	ext8	V22.16B, V27.16B, V25.16B, #8
	add	V23.2D, V23.2D, V20.2D
	sha512h	Q23, Q21, V22.2D
	add	V24.2D, V27.2D, V23.2D
	sha512h2	Q23, Q27, V26.2D
	; Round 18
	sha512su0	V2.2D, V3.2D
	ext8	V21.16B, V6.16B, V7.16B, #8
	sha512su1	V2.2D, V1.2D, V21.2D
	add	V20.2D, V2.2D, V18.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V24.16B, V25.16B, #8
	ext8	V22.16B, V26.16B, V24.16B, #8
	add	V25.2D, V25.2D, V20.2D
	sha512h	Q25, Q21, V22.2D
	add	V27.2D, V26.2D, V25.2D
	sha512h2	Q25, Q26, V23.2D
	; Round 19
	sha512su0	V3.2D, V4.2D
	ext8	V21.16B, V7.16B, V0.16B, #8
	sha512su1	V3.2D, V2.2D, V21.2D
	add	V20.2D, V3.2D, V19.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V27.16B, V24.16B, #8
	ext8	V22.16B, V23.16B, V27.16B, #8
	add	V24.2D, V24.2D, V20.2D
	sha512h	Q24, Q21, V22.2D
	add	V26.2D, V23.2D, V24.2D
	sha512h2	Q24, Q23, V25.2D
	; Load next 8 64-bit words of K
	ld1	{V16.2D, V17.2D, V18.2D, V19.2D}, [x3], #0x40
	; Round 20
	sha512su0	V4.2D, V5.2D
	ext8	V21.16B, V0.16B, V1.16B, #8
	sha512su1	V4.2D, V3.2D, V21.2D
	add	V20.2D, V4.2D, V16.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V26.16B, V27.16B, #8
	ext8	V22.16B, V25.16B, V26.16B, #8
	add	V27.2D, V27.2D, V20.2D
	sha512h	Q27, Q21, V22.2D
	add	V23.2D, V25.2D, V27.2D
	sha512h2	Q27, Q25, V24.2D
	; Round 21
	sha512su0	V5.2D, V6.2D
	ext8	V21.16B, V1.16B, V2.16B, #8
	sha512su1	V5.2D, V4.2D, V21.2D
	add	V20.2D, V5.2D, V17.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V23.16B, V26.16B, #8
	ext8	V22.16B, V24.16B, V23.16B, #8
	add	V26.2D, V26.2D, V20.2D
	sha512h	Q26, Q21, V22.2D
	add	V25.2D, V24.2D, V26.2D
	sha512h2	Q26, Q24, V27.2D
	; Round 22
	sha512su0	V6.2D, V7.2D
	ext8	V21.16B, V2.16B, V3.16B, #8
	sha512su1	V6.2D, V5.2D, V21.2D
	add	V20.2D, V6.2D, V18.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V25.16B, V23.16B, #8
	ext8	V22.16B, V27.16B, V25.16B, #8
	add	V23.2D, V23.2D, V20.2D
	sha512h	Q23, Q21, V22.2D
	add	V24.2D, V27.2D, V23.2D
	sha512h2	Q23, Q27, V26.2D
	; Round 23
	sha512su0	V7.2D, V0.2D
	ext8	V21.16B, V3.16B, V4.16B, #8
	sha512su1	V7.2D, V6.2D, V21.2D
	add	V20.2D, V7.2D, V19.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V24.16B, V25.16B, #8
	ext8	V22.16B, V26.16B, V24.16B, #8
	add	V25.2D, V25.2D, V20.2D
	sha512h	Q25, Q21, V22.2D
	add	V27.2D, V26.2D, V25.2D
	sha512h2	Q25, Q26, V23.2D
	; Load next 8 64-bit words of K
	ld1	{V16.2D, V17.2D, V18.2D, V19.2D}, [x3], #0x40
	; Round 24
	sha512su0	V0.2D, V1.2D
	ext8	V21.16B, V4.16B, V5.16B, #8
	sha512su1	V0.2D, V7.2D, V21.2D
	add	V20.2D, V0.2D, V16.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V27.16B, V24.16B, #8
	ext8	V22.16B, V23.16B, V27.16B, #8
	add	V24.2D, V24.2D, V20.2D
	sha512h	Q24, Q21, V22.2D
	add	V26.2D, V23.2D, V24.2D
	sha512h2	Q24, Q23, V25.2D
	; Round 25
	sha512su0	V1.2D, V2.2D
	ext8	V21.16B, V5.16B, V6.16B, #8
	sha512su1	V1.2D, V0.2D, V21.2D
	add	V20.2D, V1.2D, V17.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V26.16B, V27.16B, #8
	ext8	V22.16B, V25.16B, V26.16B, #8
	add	V27.2D, V27.2D, V20.2D
	sha512h	Q27, Q21, V22.2D
	add	V23.2D, V25.2D, V27.2D
	sha512h2	Q27, Q25, V24.2D
	; Round 26
	sha512su0	V2.2D, V3.2D
	ext8	V21.16B, V6.16B, V7.16B, #8
	sha512su1	V2.2D, V1.2D, V21.2D
	add	V20.2D, V2.2D, V18.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V23.16B, V26.16B, #8
	ext8	V22.16B, V24.16B, V23.16B, #8
	add	V26.2D, V26.2D, V20.2D
	sha512h	Q26, Q21, V22.2D
	add	V25.2D, V24.2D, V26.2D
	sha512h2	Q26, Q24, V27.2D
	; Round 27
	sha512su0	V3.2D, V4.2D
	ext8	V21.16B, V7.16B, V0.16B, #8
	sha512su1	V3.2D, V2.2D, V21.2D
	add	V20.2D, V3.2D, V19.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V25.16B, V23.16B, #8
	ext8	V22.16B, V27.16B, V25.16B, #8
	add	V23.2D, V23.2D, V20.2D
	sha512h	Q23, Q21, V22.2D
	add	V24.2D, V27.2D, V23.2D
	sha512h2	Q23, Q27, V26.2D
	; Load next 8 64-bit words of K
	ld1	{V16.2D, V17.2D, V18.2D, V19.2D}, [x3], #0x40
	; Round 28
	sha512su0	V4.2D, V5.2D
	ext8	V21.16B, V0.16B, V1.16B, #8
	sha512su1	V4.2D, V3.2D, V21.2D
	add	V20.2D, V4.2D, V16.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V24.16B, V25.16B, #8
	ext8	V22.16B, V26.16B, V24.16B, #8
	add	V25.2D, V25.2D, V20.2D
	sha512h	Q25, Q21, V22.2D
	add	V27.2D, V26.2D, V25.2D
	sha512h2	Q25, Q26, V23.2D
	; Round 29
	sha512su0	V5.2D, V6.2D
	ext8	V21.16B, V1.16B, V2.16B, #8
	sha512su1	V5.2D, V4.2D, V21.2D
	add	V20.2D, V5.2D, V17.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V27.16B, V24.16B, #8
	ext8	V22.16B, V23.16B, V27.16B, #8
	add	V24.2D, V24.2D, V20.2D
	sha512h	Q24, Q21, V22.2D
	add	V26.2D, V23.2D, V24.2D
	sha512h2	Q24, Q23, V25.2D
	; Round 30
	sha512su0	V6.2D, V7.2D
	ext8	V21.16B, V2.16B, V3.16B, #8
	sha512su1	V6.2D, V5.2D, V21.2D
	add	V20.2D, V6.2D, V18.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V26.16B, V27.16B, #8
	ext8	V22.16B, V25.16B, V26.16B, #8
	add	V27.2D, V27.2D, V20.2D
	sha512h	Q27, Q21, V22.2D
	add	V23.2D, V25.2D, V27.2D
	sha512h2	Q27, Q25, V24.2D
	; Round 31
	sha512su0	V7.2D, V0.2D
	ext8	V21.16B, V3.16B, V4.16B, #8
	sha512su1	V7.2D, V6.2D, V21.2D
	add	V20.2D, V7.2D, V19.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V23.16B, V26.16B, #8
	ext8	V22.16B, V24.16B, V23.16B, #8
	add	V26.2D, V26.2D, V20.2D
	sha512h	Q26, Q21, V22.2D
	add	V25.2D, V24.2D, V26.2D
	sha512h2	Q26, Q24, V27.2D
	; Load next 8 64-bit words of K
	ld1	{V16.2D, V17.2D, V18.2D, V19.2D}, [x3], #0x40
	; Round 32
	sha512su0	V0.2D, V1.2D
	ext8	V21.16B, V4.16B, V5.16B, #8
	sha512su1	V0.2D, V7.2D, V21.2D
	add	V20.2D, V0.2D, V16.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V25.16B, V23.16B, #8
	ext8	V22.16B, V27.16B, V25.16B, #8
	add	V23.2D, V23.2D, V20.2D
	sha512h	Q23, Q21, V22.2D
	add	V24.2D, V27.2D, V23.2D
	sha512h2	Q23, Q27, V26.2D
	; Round 33
	sha512su0	V1.2D, V2.2D
	ext8	V21.16B, V5.16B, V6.16B, #8
	sha512su1	V1.2D, V0.2D, V21.2D
	add	V20.2D, V1.2D, V17.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V24.16B, V25.16B, #8
	ext8	V22.16B, V26.16B, V24.16B, #8
	add	V25.2D, V25.2D, V20.2D
	sha512h	Q25, Q21, V22.2D
	add	V27.2D, V26.2D, V25.2D
	sha512h2	Q25, Q26, V23.2D
	; Round 34
	sha512su0	V2.2D, V3.2D
	ext8	V21.16B, V6.16B, V7.16B, #8
	sha512su1	V2.2D, V1.2D, V21.2D
	add	V20.2D, V2.2D, V18.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V27.16B, V24.16B, #8
	ext8	V22.16B, V23.16B, V27.16B, #8
	add	V24.2D, V24.2D, V20.2D
	sha512h	Q24, Q21, V22.2D
	add	V26.2D, V23.2D, V24.2D
	sha512h2	Q24, Q23, V25.2D
	; Round 35
	sha512su0	V3.2D, V4.2D
	ext8	V21.16B, V7.16B, V0.16B, #8
	sha512su1	V3.2D, V2.2D, V21.2D
	add	V20.2D, V3.2D, V19.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V26.16B, V27.16B, #8
	ext8	V22.16B, V25.16B, V26.16B, #8
	add	V27.2D, V27.2D, V20.2D
	sha512h	Q27, Q21, V22.2D
	add	V23.2D, V25.2D, V27.2D
	sha512h2	Q27, Q25, V24.2D
	; Load next 8 64-bit words of K
	ld1	{V16.2D, V17.2D, V18.2D, V19.2D}, [x3], #0x40
	; Round 36
	sha512su0	V4.2D, V5.2D
	ext8	V21.16B, V0.16B, V1.16B, #8
	sha512su1	V4.2D, V3.2D, V21.2D
	add	V20.2D, V4.2D, V16.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V23.16B, V26.16B, #8
	ext8	V22.16B, V24.16B, V23.16B, #8
	add	V26.2D, V26.2D, V20.2D
	sha512h	Q26, Q21, V22.2D
	add	V25.2D, V24.2D, V26.2D
	sha512h2	Q26, Q24, V27.2D
	; Round 37
	sha512su0	V5.2D, V6.2D
	ext8	V21.16B, V1.16B, V2.16B, #8
	sha512su1	V5.2D, V4.2D, V21.2D
	add	V20.2D, V5.2D, V17.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V25.16B, V23.16B, #8
	ext8	V22.16B, V27.16B, V25.16B, #8
	add	V23.2D, V23.2D, V20.2D
	sha512h	Q23, Q21, V22.2D
	add	V24.2D, V27.2D, V23.2D
	sha512h2	Q23, Q27, V26.2D
	; Round 38
	sha512su0	V6.2D, V7.2D
	ext8	V21.16B, V2.16B, V3.16B, #8
	sha512su1	V6.2D, V5.2D, V21.2D
	add	V20.2D, V6.2D, V18.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V24.16B, V25.16B, #8
	ext8	V22.16B, V26.16B, V24.16B, #8
	add	V25.2D, V25.2D, V20.2D
	sha512h	Q25, Q21, V22.2D
	add	V27.2D, V26.2D, V25.2D
	sha512h2	Q25, Q26, V23.2D
	; Round 39
	sha512su0	V7.2D, V0.2D
	ext8	V21.16B, V3.16B, V4.16B, #8
	sha512su1	V7.2D, V6.2D, V21.2D
	add	V20.2D, V7.2D, V19.2D
	ext8	V20.16B, V20.16B, V20.16B, #8
	ext8	V21.16B, V27.16B, V24.16B, #8
	ext8	V22.16B, V23.16B, V27.16B, #8
	add	V24.2D, V24.2D, V20.2D
	sha512h	Q24, Q21, V22.2D
	add	V26.2D, V23.2D, V24.2D
	sha512h2	Q24, Q23, V25.2D
	add	V27.2D, V27.2D, V31.2D
	add	V26.2D, V26.2D, V30.2D
	add	V25.2D, V25.2D, V29.2D
	add	V24.2D, V24.2D, V28.2D
	subs	w2, w2, #0x80
	bne	L_sha512_len_crypto_begin
	; Store digest back
	st1	{V24.2D, V25.2D, V26.2D, V27.2D}, [x0]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	ENDIF
	ENDIF
	ENDIF
	END
