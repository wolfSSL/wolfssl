; /* armv8-sha256-asm
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
;   ruby ./sha2/sha256.rb arm64 \
;       ../wolfssl/wolfcrypt/src/port/arm/armv8-sha256-asm.asm
	IF :LNOT::DEF:NO_SHA256 :LOR: :DEF:WOLFSSL_SHA224
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_SHA256_transform_neon_len_k
	DCD	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
	DCD	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
	DCD	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
	DCD	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
	DCD	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
	DCD	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
	DCD	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
	DCD	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
	DCD	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
	DCD	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
	DCD	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
	DCD	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
	DCD	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
	DCD	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
	DCD	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
	DCD	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	Transform_Sha256_Len_neon
Transform_Sha256_Len_neon PROC
	stp	x29, x30, [sp, #-112]!
	add	x29, sp, #0
	stp	x17, x19, [x29, #24]
	stp	x20, x21, [x29, #40]
	stp	x22, x23, [x29, #56]
	str	x24, [x29, #72]
	stp	D8, D9, [x29, #80]
	stp	D10, D11, [x29, #96]
	adrp	x3, L_SHA256_transform_neon_len_k
	add	x3, x3, L_SHA256_transform_neon_len_k
	; Load digest into working vars
	ldr	w4, [x0]
	ldr	w5, [x0, #4]
	ldr	w6, [x0, #8]
	ldr	w7, [x0, #12]
	ldr	w8, [x0, #16]
	ldr	w9, [x0, #20]
	ldr	w10, [x0, #24]
	ldr	w11, [x0, #28]
	; Start of loop processing a block
L_sha256_len_neon_begin
	; Load W
	; Copy digest to add in at end
	ld1	{V0.8B, V1.8B, V2.8B, V3.8B}, [x1], #32
	mov	w15, w4
	ld1	{V4.8B, V5.8B, V6.8B, V7.8B}, [x1], #32
	mov	w16, w5
	rev32	V0.8B, V0.8B
	mov	w17, w6
	rev32	V1.8B, V1.8B
	mov	w19, w7
	rev32	V2.8B, V2.8B
	mov	w20, w8
	rev32	V3.8B, V3.8B
	mov	w21, w9
	rev32	V4.8B, V4.8B
	mov	w22, w10
	rev32	V5.8B, V5.8B
	mov	w23, w11
	rev32	V6.8B, V6.8B
	rev32	V7.8B, V7.8B
	mov	x24, #3
	; Start of 16 rounds
L_sha256_len_neon_start
	; Round 0
	mov	w14, V0.S[0]
	ror	w12, w8, #6
	eor	w13, w9, w10
	eor	w12, w12, w8, ror 11
	and	w13, w13, w8
	eor	w12, w12, w8, ror 25
	eor	w13, w13, w10
	add	w11, w11, w12
	add	w11, w11, w13
	ldr	w12, [x3]
	add	w11, w11, w14
	add	w11, w11, w12
	add	w7, w7, w11
	ror	w12, w4, #2
	eor	w13, w4, w5
	eor	w12, w12, w4, ror 13
	eor	w14, w5, w6
	and	w13, w13, w14
	eor	w12, w12, w4, ror 22
	eor	w13, w13, w5
	add	w11, w11, w12
	add	w11, w11, w13
	; Round 1
	mov	w14, V0.S[1]
	; Calc new W[0]-W[1]
	ext8	V10.8B, V0.8B, V1.8B, #4
	ror	w12, w7, #6
	shl	V8.2S, V7.2S, #15
	eor	w13, w8, w9
	sri	V8.2S, V7.2S, #17
	eor	w12, w12, w7, ror 11
	shl	V9.2S, V7.2S, #13
	and	w13, w13, w7
	sri	V9.2S, V7.2S, #19
	eor	w12, w12, w7, ror 25
	eor	V9.8B, V9.8B, V8.8B
	eor	w13, w13, w9
	ushr	V8.2S, V7.2S, #10
	add	w10, w10, w12
	eor	V9.8B, V9.8B, V8.8B
	add	w10, w10, w13
	add	V0.2S, V0.2S, V9.2S
	ldr	w12, [x3, #4]
	ext8	V11.8B, V4.8B, V5.8B, #4
	add	w10, w10, w14
	add	V0.2S, V0.2S, V11.2S
	add	w10, w10, w12
	shl	V8.2S, V10.2S, #25
	add	w6, w6, w10
	sri	V8.2S, V10.2S, #7
	ror	w12, w11, #2
	shl	V9.2S, V10.2S, #14
	eor	w13, w11, w4
	sri	V9.2S, V10.2S, #18
	eor	w12, w12, w11, ror 13
	eor	V9.8B, V9.8B, V8.8B
	eor	w14, w4, w5
	ushr	V10.2S, V10.2S, #3
	and	w13, w13, w14
	eor	V9.8B, V9.8B, V10.8B
	eor	w12, w12, w11, ror 22
	add	V0.2S, V0.2S, V9.2S
	eor	w13, w13, w4
	add	w10, w10, w12
	add	w10, w10, w13
	; Round 2
	mov	w14, V1.S[0]
	ror	w12, w6, #6
	eor	w13, w7, w8
	eor	w12, w12, w6, ror 11
	and	w13, w13, w6
	eor	w12, w12, w6, ror 25
	eor	w13, w13, w8
	add	w9, w9, w12
	add	w9, w9, w13
	ldr	w12, [x3, #8]
	add	w9, w9, w14
	add	w9, w9, w12
	add	w5, w5, w9
	ror	w12, w10, #2
	eor	w13, w10, w11
	eor	w12, w12, w10, ror 13
	eor	w14, w11, w4
	and	w13, w13, w14
	eor	w12, w12, w10, ror 22
	eor	w13, w13, w11
	add	w9, w9, w12
	add	w9, w9, w13
	; Round 3
	mov	w14, V1.S[1]
	; Calc new W[2]-W[3]
	ext8	V10.8B, V1.8B, V2.8B, #4
	ror	w12, w5, #6
	shl	V8.2S, V0.2S, #15
	eor	w13, w6, w7
	sri	V8.2S, V0.2S, #17
	eor	w12, w12, w5, ror 11
	shl	V9.2S, V0.2S, #13
	and	w13, w13, w5
	sri	V9.2S, V0.2S, #19
	eor	w12, w12, w5, ror 25
	eor	V9.8B, V9.8B, V8.8B
	eor	w13, w13, w7
	ushr	V8.2S, V0.2S, #10
	add	w8, w8, w12
	eor	V9.8B, V9.8B, V8.8B
	add	w8, w8, w13
	add	V1.2S, V1.2S, V9.2S
	ldr	w12, [x3, #12]
	ext8	V11.8B, V5.8B, V6.8B, #4
	add	w8, w8, w14
	add	V1.2S, V1.2S, V11.2S
	add	w8, w8, w12
	shl	V8.2S, V10.2S, #25
	add	w4, w4, w8
	sri	V8.2S, V10.2S, #7
	ror	w12, w9, #2
	shl	V9.2S, V10.2S, #14
	eor	w13, w9, w10
	sri	V9.2S, V10.2S, #18
	eor	w12, w12, w9, ror 13
	eor	V9.8B, V9.8B, V8.8B
	eor	w14, w10, w11
	ushr	V10.2S, V10.2S, #3
	and	w13, w13, w14
	eor	V9.8B, V9.8B, V10.8B
	eor	w12, w12, w9, ror 22
	add	V1.2S, V1.2S, V9.2S
	eor	w13, w13, w10
	add	w8, w8, w12
	add	w8, w8, w13
	; Round 4
	mov	w14, V2.S[0]
	ror	w12, w4, #6
	eor	w13, w5, w6
	eor	w12, w12, w4, ror 11
	and	w13, w13, w4
	eor	w12, w12, w4, ror 25
	eor	w13, w13, w6
	add	w7, w7, w12
	add	w7, w7, w13
	ldr	w12, [x3, #16]
	add	w7, w7, w14
	add	w7, w7, w12
	add	w11, w11, w7
	ror	w12, w8, #2
	eor	w13, w8, w9
	eor	w12, w12, w8, ror 13
	eor	w14, w9, w10
	and	w13, w13, w14
	eor	w12, w12, w8, ror 22
	eor	w13, w13, w9
	add	w7, w7, w12
	add	w7, w7, w13
	; Round 5
	mov	w14, V2.S[1]
	; Calc new W[4]-W[5]
	ext8	V10.8B, V2.8B, V3.8B, #4
	ror	w12, w11, #6
	shl	V8.2S, V1.2S, #15
	eor	w13, w4, w5
	sri	V8.2S, V1.2S, #17
	eor	w12, w12, w11, ror 11
	shl	V9.2S, V1.2S, #13
	and	w13, w13, w11
	sri	V9.2S, V1.2S, #19
	eor	w12, w12, w11, ror 25
	eor	V9.8B, V9.8B, V8.8B
	eor	w13, w13, w5
	ushr	V8.2S, V1.2S, #10
	add	w6, w6, w12
	eor	V9.8B, V9.8B, V8.8B
	add	w6, w6, w13
	add	V2.2S, V2.2S, V9.2S
	ldr	w12, [x3, #20]
	ext8	V11.8B, V6.8B, V7.8B, #4
	add	w6, w6, w14
	add	V2.2S, V2.2S, V11.2S
	add	w6, w6, w12
	shl	V8.2S, V10.2S, #25
	add	w10, w10, w6
	sri	V8.2S, V10.2S, #7
	ror	w12, w7, #2
	shl	V9.2S, V10.2S, #14
	eor	w13, w7, w8
	sri	V9.2S, V10.2S, #18
	eor	w12, w12, w7, ror 13
	eor	V9.8B, V9.8B, V8.8B
	eor	w14, w8, w9
	ushr	V10.2S, V10.2S, #3
	and	w13, w13, w14
	eor	V9.8B, V9.8B, V10.8B
	eor	w12, w12, w7, ror 22
	add	V2.2S, V2.2S, V9.2S
	eor	w13, w13, w8
	add	w6, w6, w12
	add	w6, w6, w13
	; Round 6
	mov	w14, V3.S[0]
	ror	w12, w10, #6
	eor	w13, w11, w4
	eor	w12, w12, w10, ror 11
	and	w13, w13, w10
	eor	w12, w12, w10, ror 25
	eor	w13, w13, w4
	add	w5, w5, w12
	add	w5, w5, w13
	ldr	w12, [x3, #24]
	add	w5, w5, w14
	add	w5, w5, w12
	add	w9, w9, w5
	ror	w12, w6, #2
	eor	w13, w6, w7
	eor	w12, w12, w6, ror 13
	eor	w14, w7, w8
	and	w13, w13, w14
	eor	w12, w12, w6, ror 22
	eor	w13, w13, w7
	add	w5, w5, w12
	add	w5, w5, w13
	; Round 7
	mov	w14, V3.S[1]
	; Calc new W[6]-W[7]
	ext8	V10.8B, V3.8B, V4.8B, #4
	ror	w12, w9, #6
	shl	V8.2S, V2.2S, #15
	eor	w13, w10, w11
	sri	V8.2S, V2.2S, #17
	eor	w12, w12, w9, ror 11
	shl	V9.2S, V2.2S, #13
	and	w13, w13, w9
	sri	V9.2S, V2.2S, #19
	eor	w12, w12, w9, ror 25
	eor	V9.8B, V9.8B, V8.8B
	eor	w13, w13, w11
	ushr	V8.2S, V2.2S, #10
	add	w4, w4, w12
	eor	V9.8B, V9.8B, V8.8B
	add	w4, w4, w13
	add	V3.2S, V3.2S, V9.2S
	ldr	w12, [x3, #28]
	ext8	V11.8B, V7.8B, V0.8B, #4
	add	w4, w4, w14
	add	V3.2S, V3.2S, V11.2S
	add	w4, w4, w12
	shl	V8.2S, V10.2S, #25
	add	w8, w8, w4
	sri	V8.2S, V10.2S, #7
	ror	w12, w5, #2
	shl	V9.2S, V10.2S, #14
	eor	w13, w5, w6
	sri	V9.2S, V10.2S, #18
	eor	w12, w12, w5, ror 13
	eor	V9.8B, V9.8B, V8.8B
	eor	w14, w6, w7
	ushr	V10.2S, V10.2S, #3
	and	w13, w13, w14
	eor	V9.8B, V9.8B, V10.8B
	eor	w12, w12, w5, ror 22
	add	V3.2S, V3.2S, V9.2S
	eor	w13, w13, w6
	add	w4, w4, w12
	add	w4, w4, w13
	; Round 8
	mov	w14, V4.S[0]
	ror	w12, w8, #6
	eor	w13, w9, w10
	eor	w12, w12, w8, ror 11
	and	w13, w13, w8
	eor	w12, w12, w8, ror 25
	eor	w13, w13, w10
	add	w11, w11, w12
	add	w11, w11, w13
	ldr	w12, [x3, #32]
	add	w11, w11, w14
	add	w11, w11, w12
	add	w7, w7, w11
	ror	w12, w4, #2
	eor	w13, w4, w5
	eor	w12, w12, w4, ror 13
	eor	w14, w5, w6
	and	w13, w13, w14
	eor	w12, w12, w4, ror 22
	eor	w13, w13, w5
	add	w11, w11, w12
	add	w11, w11, w13
	; Round 9
	mov	w14, V4.S[1]
	; Calc new W[8]-W[9]
	ext8	V10.8B, V4.8B, V5.8B, #4
	ror	w12, w7, #6
	shl	V8.2S, V3.2S, #15
	eor	w13, w8, w9
	sri	V8.2S, V3.2S, #17
	eor	w12, w12, w7, ror 11
	shl	V9.2S, V3.2S, #13
	and	w13, w13, w7
	sri	V9.2S, V3.2S, #19
	eor	w12, w12, w7, ror 25
	eor	V9.8B, V9.8B, V8.8B
	eor	w13, w13, w9
	ushr	V8.2S, V3.2S, #10
	add	w10, w10, w12
	eor	V9.8B, V9.8B, V8.8B
	add	w10, w10, w13
	add	V4.2S, V4.2S, V9.2S
	ldr	w12, [x3, #36]
	ext8	V11.8B, V0.8B, V1.8B, #4
	add	w10, w10, w14
	add	V4.2S, V4.2S, V11.2S
	add	w10, w10, w12
	shl	V8.2S, V10.2S, #25
	add	w6, w6, w10
	sri	V8.2S, V10.2S, #7
	ror	w12, w11, #2
	shl	V9.2S, V10.2S, #14
	eor	w13, w11, w4
	sri	V9.2S, V10.2S, #18
	eor	w12, w12, w11, ror 13
	eor	V9.8B, V9.8B, V8.8B
	eor	w14, w4, w5
	ushr	V10.2S, V10.2S, #3
	and	w13, w13, w14
	eor	V9.8B, V9.8B, V10.8B
	eor	w12, w12, w11, ror 22
	add	V4.2S, V4.2S, V9.2S
	eor	w13, w13, w4
	add	w10, w10, w12
	add	w10, w10, w13
	; Round 10
	mov	w14, V5.S[0]
	ror	w12, w6, #6
	eor	w13, w7, w8
	eor	w12, w12, w6, ror 11
	and	w13, w13, w6
	eor	w12, w12, w6, ror 25
	eor	w13, w13, w8
	add	w9, w9, w12
	add	w9, w9, w13
	ldr	w12, [x3, #40]
	add	w9, w9, w14
	add	w9, w9, w12
	add	w5, w5, w9
	ror	w12, w10, #2
	eor	w13, w10, w11
	eor	w12, w12, w10, ror 13
	eor	w14, w11, w4
	and	w13, w13, w14
	eor	w12, w12, w10, ror 22
	eor	w13, w13, w11
	add	w9, w9, w12
	add	w9, w9, w13
	; Round 11
	mov	w14, V5.S[1]
	; Calc new W[10]-W[11]
	ext8	V10.8B, V5.8B, V6.8B, #4
	ror	w12, w5, #6
	shl	V8.2S, V4.2S, #15
	eor	w13, w6, w7
	sri	V8.2S, V4.2S, #17
	eor	w12, w12, w5, ror 11
	shl	V9.2S, V4.2S, #13
	and	w13, w13, w5
	sri	V9.2S, V4.2S, #19
	eor	w12, w12, w5, ror 25
	eor	V9.8B, V9.8B, V8.8B
	eor	w13, w13, w7
	ushr	V8.2S, V4.2S, #10
	add	w8, w8, w12
	eor	V9.8B, V9.8B, V8.8B
	add	w8, w8, w13
	add	V5.2S, V5.2S, V9.2S
	ldr	w12, [x3, #44]
	ext8	V11.8B, V1.8B, V2.8B, #4
	add	w8, w8, w14
	add	V5.2S, V5.2S, V11.2S
	add	w8, w8, w12
	shl	V8.2S, V10.2S, #25
	add	w4, w4, w8
	sri	V8.2S, V10.2S, #7
	ror	w12, w9, #2
	shl	V9.2S, V10.2S, #14
	eor	w13, w9, w10
	sri	V9.2S, V10.2S, #18
	eor	w12, w12, w9, ror 13
	eor	V9.8B, V9.8B, V8.8B
	eor	w14, w10, w11
	ushr	V10.2S, V10.2S, #3
	and	w13, w13, w14
	eor	V9.8B, V9.8B, V10.8B
	eor	w12, w12, w9, ror 22
	add	V5.2S, V5.2S, V9.2S
	eor	w13, w13, w10
	add	w8, w8, w12
	add	w8, w8, w13
	; Round 12
	mov	w14, V6.S[0]
	ror	w12, w4, #6
	eor	w13, w5, w6
	eor	w12, w12, w4, ror 11
	and	w13, w13, w4
	eor	w12, w12, w4, ror 25
	eor	w13, w13, w6
	add	w7, w7, w12
	add	w7, w7, w13
	ldr	w12, [x3, #48]
	add	w7, w7, w14
	add	w7, w7, w12
	add	w11, w11, w7
	ror	w12, w8, #2
	eor	w13, w8, w9
	eor	w12, w12, w8, ror 13
	eor	w14, w9, w10
	and	w13, w13, w14
	eor	w12, w12, w8, ror 22
	eor	w13, w13, w9
	add	w7, w7, w12
	add	w7, w7, w13
	; Round 13
	mov	w14, V6.S[1]
	; Calc new W[12]-W[13]
	ext8	V10.8B, V6.8B, V7.8B, #4
	ror	w12, w11, #6
	shl	V8.2S, V5.2S, #15
	eor	w13, w4, w5
	sri	V8.2S, V5.2S, #17
	eor	w12, w12, w11, ror 11
	shl	V9.2S, V5.2S, #13
	and	w13, w13, w11
	sri	V9.2S, V5.2S, #19
	eor	w12, w12, w11, ror 25
	eor	V9.8B, V9.8B, V8.8B
	eor	w13, w13, w5
	ushr	V8.2S, V5.2S, #10
	add	w6, w6, w12
	eor	V9.8B, V9.8B, V8.8B
	add	w6, w6, w13
	add	V6.2S, V6.2S, V9.2S
	ldr	w12, [x3, #52]
	ext8	V11.8B, V2.8B, V3.8B, #4
	add	w6, w6, w14
	add	V6.2S, V6.2S, V11.2S
	add	w6, w6, w12
	shl	V8.2S, V10.2S, #25
	add	w10, w10, w6
	sri	V8.2S, V10.2S, #7
	ror	w12, w7, #2
	shl	V9.2S, V10.2S, #14
	eor	w13, w7, w8
	sri	V9.2S, V10.2S, #18
	eor	w12, w12, w7, ror 13
	eor	V9.8B, V9.8B, V8.8B
	eor	w14, w8, w9
	ushr	V10.2S, V10.2S, #3
	and	w13, w13, w14
	eor	V9.8B, V9.8B, V10.8B
	eor	w12, w12, w7, ror 22
	add	V6.2S, V6.2S, V9.2S
	eor	w13, w13, w8
	add	w6, w6, w12
	add	w6, w6, w13
	; Round 14
	mov	w14, V7.S[0]
	ror	w12, w10, #6
	eor	w13, w11, w4
	eor	w12, w12, w10, ror 11
	and	w13, w13, w10
	eor	w12, w12, w10, ror 25
	eor	w13, w13, w4
	add	w5, w5, w12
	add	w5, w5, w13
	ldr	w12, [x3, #56]
	add	w5, w5, w14
	add	w5, w5, w12
	add	w9, w9, w5
	ror	w12, w6, #2
	eor	w13, w6, w7
	eor	w12, w12, w6, ror 13
	eor	w14, w7, w8
	and	w13, w13, w14
	eor	w12, w12, w6, ror 22
	eor	w13, w13, w7
	add	w5, w5, w12
	add	w5, w5, w13
	; Round 15
	mov	w14, V7.S[1]
	; Calc new W[14]-W[15]
	ext8	V10.8B, V7.8B, V0.8B, #4
	ror	w12, w9, #6
	shl	V8.2S, V6.2S, #15
	eor	w13, w10, w11
	sri	V8.2S, V6.2S, #17
	eor	w12, w12, w9, ror 11
	shl	V9.2S, V6.2S, #13
	and	w13, w13, w9
	sri	V9.2S, V6.2S, #19
	eor	w12, w12, w9, ror 25
	eor	V9.8B, V9.8B, V8.8B
	eor	w13, w13, w11
	ushr	V8.2S, V6.2S, #10
	add	w4, w4, w12
	eor	V9.8B, V9.8B, V8.8B
	add	w4, w4, w13
	add	V7.2S, V7.2S, V9.2S
	ldr	w12, [x3, #60]
	ext8	V11.8B, V3.8B, V4.8B, #4
	add	w4, w4, w14
	add	V7.2S, V7.2S, V11.2S
	add	w4, w4, w12
	shl	V8.2S, V10.2S, #25
	add	w8, w8, w4
	sri	V8.2S, V10.2S, #7
	ror	w12, w5, #2
	shl	V9.2S, V10.2S, #14
	eor	w13, w5, w6
	sri	V9.2S, V10.2S, #18
	eor	w12, w12, w5, ror 13
	eor	V9.8B, V9.8B, V8.8B
	eor	w14, w6, w7
	ushr	V10.2S, V10.2S, #3
	and	w13, w13, w14
	eor	V9.8B, V9.8B, V10.8B
	eor	w12, w12, w5, ror 22
	add	V7.2S, V7.2S, V9.2S
	eor	w13, w13, w6
	add	w4, w4, w12
	add	w4, w4, w13
	add	x3, x3, #0x40
	subs	x24, x24, #1
	bne	L_sha256_len_neon_start
	; Round 0
	mov	w14, V0.S[0]
	ror	w12, w8, #6
	eor	w13, w9, w10
	eor	w12, w12, w8, ror 11
	and	w13, w13, w8
	eor	w12, w12, w8, ror 25
	eor	w13, w13, w10
	add	w11, w11, w12
	add	w11, w11, w13
	ldr	w12, [x3]
	add	w11, w11, w14
	add	w11, w11, w12
	add	w7, w7, w11
	ror	w12, w4, #2
	eor	w13, w4, w5
	eor	w12, w12, w4, ror 13
	eor	w14, w5, w6
	and	w13, w13, w14
	eor	w12, w12, w4, ror 22
	eor	w13, w13, w5
	add	w11, w11, w12
	add	w11, w11, w13
	; Round 1
	mov	w14, V0.S[1]
	ror	w12, w7, #6
	eor	w13, w8, w9
	eor	w12, w12, w7, ror 11
	and	w13, w13, w7
	eor	w12, w12, w7, ror 25
	eor	w13, w13, w9
	add	w10, w10, w12
	add	w10, w10, w13
	ldr	w12, [x3, #4]
	add	w10, w10, w14
	add	w10, w10, w12
	add	w6, w6, w10
	ror	w12, w11, #2
	eor	w13, w11, w4
	eor	w12, w12, w11, ror 13
	eor	w14, w4, w5
	and	w13, w13, w14
	eor	w12, w12, w11, ror 22
	eor	w13, w13, w4
	add	w10, w10, w12
	add	w10, w10, w13
	; Round 2
	mov	w14, V1.S[0]
	ror	w12, w6, #6
	eor	w13, w7, w8
	eor	w12, w12, w6, ror 11
	and	w13, w13, w6
	eor	w12, w12, w6, ror 25
	eor	w13, w13, w8
	add	w9, w9, w12
	add	w9, w9, w13
	ldr	w12, [x3, #8]
	add	w9, w9, w14
	add	w9, w9, w12
	add	w5, w5, w9
	ror	w12, w10, #2
	eor	w13, w10, w11
	eor	w12, w12, w10, ror 13
	eor	w14, w11, w4
	and	w13, w13, w14
	eor	w12, w12, w10, ror 22
	eor	w13, w13, w11
	add	w9, w9, w12
	add	w9, w9, w13
	; Round 3
	mov	w14, V1.S[1]
	ror	w12, w5, #6
	eor	w13, w6, w7
	eor	w12, w12, w5, ror 11
	and	w13, w13, w5
	eor	w12, w12, w5, ror 25
	eor	w13, w13, w7
	add	w8, w8, w12
	add	w8, w8, w13
	ldr	w12, [x3, #12]
	add	w8, w8, w14
	add	w8, w8, w12
	add	w4, w4, w8
	ror	w12, w9, #2
	eor	w13, w9, w10
	eor	w12, w12, w9, ror 13
	eor	w14, w10, w11
	and	w13, w13, w14
	eor	w12, w12, w9, ror 22
	eor	w13, w13, w10
	add	w8, w8, w12
	add	w8, w8, w13
	; Round 4
	mov	w14, V2.S[0]
	ror	w12, w4, #6
	eor	w13, w5, w6
	eor	w12, w12, w4, ror 11
	and	w13, w13, w4
	eor	w12, w12, w4, ror 25
	eor	w13, w13, w6
	add	w7, w7, w12
	add	w7, w7, w13
	ldr	w12, [x3, #16]
	add	w7, w7, w14
	add	w7, w7, w12
	add	w11, w11, w7
	ror	w12, w8, #2
	eor	w13, w8, w9
	eor	w12, w12, w8, ror 13
	eor	w14, w9, w10
	and	w13, w13, w14
	eor	w12, w12, w8, ror 22
	eor	w13, w13, w9
	add	w7, w7, w12
	add	w7, w7, w13
	; Round 5
	mov	w14, V2.S[1]
	ror	w12, w11, #6
	eor	w13, w4, w5
	eor	w12, w12, w11, ror 11
	and	w13, w13, w11
	eor	w12, w12, w11, ror 25
	eor	w13, w13, w5
	add	w6, w6, w12
	add	w6, w6, w13
	ldr	w12, [x3, #20]
	add	w6, w6, w14
	add	w6, w6, w12
	add	w10, w10, w6
	ror	w12, w7, #2
	eor	w13, w7, w8
	eor	w12, w12, w7, ror 13
	eor	w14, w8, w9
	and	w13, w13, w14
	eor	w12, w12, w7, ror 22
	eor	w13, w13, w8
	add	w6, w6, w12
	add	w6, w6, w13
	; Round 6
	mov	w14, V3.S[0]
	ror	w12, w10, #6
	eor	w13, w11, w4
	eor	w12, w12, w10, ror 11
	and	w13, w13, w10
	eor	w12, w12, w10, ror 25
	eor	w13, w13, w4
	add	w5, w5, w12
	add	w5, w5, w13
	ldr	w12, [x3, #24]
	add	w5, w5, w14
	add	w5, w5, w12
	add	w9, w9, w5
	ror	w12, w6, #2
	eor	w13, w6, w7
	eor	w12, w12, w6, ror 13
	eor	w14, w7, w8
	and	w13, w13, w14
	eor	w12, w12, w6, ror 22
	eor	w13, w13, w7
	add	w5, w5, w12
	add	w5, w5, w13
	; Round 7
	mov	w14, V3.S[1]
	ror	w12, w9, #6
	eor	w13, w10, w11
	eor	w12, w12, w9, ror 11
	and	w13, w13, w9
	eor	w12, w12, w9, ror 25
	eor	w13, w13, w11
	add	w4, w4, w12
	add	w4, w4, w13
	ldr	w12, [x3, #28]
	add	w4, w4, w14
	add	w4, w4, w12
	add	w8, w8, w4
	ror	w12, w5, #2
	eor	w13, w5, w6
	eor	w12, w12, w5, ror 13
	eor	w14, w6, w7
	and	w13, w13, w14
	eor	w12, w12, w5, ror 22
	eor	w13, w13, w6
	add	w4, w4, w12
	add	w4, w4, w13
	; Round 8
	mov	w14, V4.S[0]
	ror	w12, w8, #6
	eor	w13, w9, w10
	eor	w12, w12, w8, ror 11
	and	w13, w13, w8
	eor	w12, w12, w8, ror 25
	eor	w13, w13, w10
	add	w11, w11, w12
	add	w11, w11, w13
	ldr	w12, [x3, #32]
	add	w11, w11, w14
	add	w11, w11, w12
	add	w7, w7, w11
	ror	w12, w4, #2
	eor	w13, w4, w5
	eor	w12, w12, w4, ror 13
	eor	w14, w5, w6
	and	w13, w13, w14
	eor	w12, w12, w4, ror 22
	eor	w13, w13, w5
	add	w11, w11, w12
	add	w11, w11, w13
	; Round 9
	mov	w14, V4.S[1]
	ror	w12, w7, #6
	eor	w13, w8, w9
	eor	w12, w12, w7, ror 11
	and	w13, w13, w7
	eor	w12, w12, w7, ror 25
	eor	w13, w13, w9
	add	w10, w10, w12
	add	w10, w10, w13
	ldr	w12, [x3, #36]
	add	w10, w10, w14
	add	w10, w10, w12
	add	w6, w6, w10
	ror	w12, w11, #2
	eor	w13, w11, w4
	eor	w12, w12, w11, ror 13
	eor	w14, w4, w5
	and	w13, w13, w14
	eor	w12, w12, w11, ror 22
	eor	w13, w13, w4
	add	w10, w10, w12
	add	w10, w10, w13
	; Round 10
	mov	w14, V5.S[0]
	ror	w12, w6, #6
	eor	w13, w7, w8
	eor	w12, w12, w6, ror 11
	and	w13, w13, w6
	eor	w12, w12, w6, ror 25
	eor	w13, w13, w8
	add	w9, w9, w12
	add	w9, w9, w13
	ldr	w12, [x3, #40]
	add	w9, w9, w14
	add	w9, w9, w12
	add	w5, w5, w9
	ror	w12, w10, #2
	eor	w13, w10, w11
	eor	w12, w12, w10, ror 13
	eor	w14, w11, w4
	and	w13, w13, w14
	eor	w12, w12, w10, ror 22
	eor	w13, w13, w11
	add	w9, w9, w12
	add	w9, w9, w13
	; Round 11
	mov	w14, V5.S[1]
	ror	w12, w5, #6
	eor	w13, w6, w7
	eor	w12, w12, w5, ror 11
	and	w13, w13, w5
	eor	w12, w12, w5, ror 25
	eor	w13, w13, w7
	add	w8, w8, w12
	add	w8, w8, w13
	ldr	w12, [x3, #44]
	add	w8, w8, w14
	add	w8, w8, w12
	add	w4, w4, w8
	ror	w12, w9, #2
	eor	w13, w9, w10
	eor	w12, w12, w9, ror 13
	eor	w14, w10, w11
	and	w13, w13, w14
	eor	w12, w12, w9, ror 22
	eor	w13, w13, w10
	add	w8, w8, w12
	add	w8, w8, w13
	; Round 12
	mov	w14, V6.S[0]
	ror	w12, w4, #6
	eor	w13, w5, w6
	eor	w12, w12, w4, ror 11
	and	w13, w13, w4
	eor	w12, w12, w4, ror 25
	eor	w13, w13, w6
	add	w7, w7, w12
	add	w7, w7, w13
	ldr	w12, [x3, #48]
	add	w7, w7, w14
	add	w7, w7, w12
	add	w11, w11, w7
	ror	w12, w8, #2
	eor	w13, w8, w9
	eor	w12, w12, w8, ror 13
	eor	w14, w9, w10
	and	w13, w13, w14
	eor	w12, w12, w8, ror 22
	eor	w13, w13, w9
	add	w7, w7, w12
	add	w7, w7, w13
	; Round 13
	mov	w14, V6.S[1]
	ror	w12, w11, #6
	eor	w13, w4, w5
	eor	w12, w12, w11, ror 11
	and	w13, w13, w11
	eor	w12, w12, w11, ror 25
	eor	w13, w13, w5
	add	w6, w6, w12
	add	w6, w6, w13
	ldr	w12, [x3, #52]
	add	w6, w6, w14
	add	w6, w6, w12
	add	w10, w10, w6
	ror	w12, w7, #2
	eor	w13, w7, w8
	eor	w12, w12, w7, ror 13
	eor	w14, w8, w9
	and	w13, w13, w14
	eor	w12, w12, w7, ror 22
	eor	w13, w13, w8
	add	w6, w6, w12
	add	w6, w6, w13
	; Round 14
	mov	w14, V7.S[0]
	ror	w12, w10, #6
	eor	w13, w11, w4
	eor	w12, w12, w10, ror 11
	and	w13, w13, w10
	eor	w12, w12, w10, ror 25
	eor	w13, w13, w4
	add	w5, w5, w12
	add	w5, w5, w13
	ldr	w12, [x3, #56]
	add	w5, w5, w14
	add	w5, w5, w12
	add	w9, w9, w5
	ror	w12, w6, #2
	eor	w13, w6, w7
	eor	w12, w12, w6, ror 13
	eor	w14, w7, w8
	and	w13, w13, w14
	eor	w12, w12, w6, ror 22
	eor	w13, w13, w7
	add	w5, w5, w12
	add	w5, w5, w13
	; Round 15
	mov	w14, V7.S[1]
	ror	w12, w9, #6
	eor	w13, w10, w11
	eor	w12, w12, w9, ror 11
	and	w13, w13, w9
	eor	w12, w12, w9, ror 25
	eor	w13, w13, w11
	add	w4, w4, w12
	add	w4, w4, w13
	ldr	w12, [x3, #60]
	add	w4, w4, w14
	add	w4, w4, w12
	add	w8, w8, w4
	ror	w12, w5, #2
	eor	w13, w5, w6
	eor	w12, w12, w5, ror 13
	eor	w14, w6, w7
	and	w13, w13, w14
	eor	w12, w12, w5, ror 22
	eor	w13, w13, w6
	add	w4, w4, w12
	add	w4, w4, w13
	add	w11, w11, w23
	add	w10, w10, w22
	add	w9, w9, w21
	add	w8, w8, w20
	add	w7, w7, w19
	add	w6, w6, w17
	add	w5, w5, w16
	add	w4, w4, w15
	subs	w2, w2, #0x40
	sub	x3, x3, #0xc0
	bne	L_sha256_len_neon_begin
	str	w4, [x0]
	str	w5, [x0, #4]
	str	w6, [x0, #8]
	str	w7, [x0, #12]
	str	w8, [x0, #16]
	str	w9, [x0, #20]
	str	w10, [x0, #24]
	str	w11, [x0, #28]
	ldp	x17, x19, [x29, #24]
	ldp	x20, x21, [x29, #40]
	ldp	x22, x23, [x29, #56]
	ldr	x24, [x29, #72]
	ldp	D8, D9, [x29, #80]
	ldp	D10, D11, [x29, #96]
	ldp	x29, x30, [sp], #0x70
	ret
	ENDP
	IF :LNOT::DEF:WOLFSSL_ARMASM_NO_HW_CRYPTO
	AREA	|.rodata|, DATA, READONLY, ALIGN=4
	ALIGN	8
L_SHA256_trans_crypto_len_k
	DCD	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
	DCD	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
	DCD	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
	DCD	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
	DCD	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
	DCD	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
	DCD	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
	DCD	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
	DCD	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
	DCD	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
	DCD	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
	DCD	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
	DCD	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
	DCD	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
	DCD	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
	DCD	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	AREA	|.text|, CODE, READONLY
	ALIGN	4
	EXPORT	Transform_Sha256_Len_crypto
Transform_Sha256_Len_crypto PROC
	stp	x29, x30, [sp, #-80]!
	add	x29, sp, #0
	stp	D8, D9, [x29, #16]
	stp	D10, D11, [x29, #32]
	stp	D12, D13, [x29, #48]
	stp	D14, D15, [x29, #64]
	adrp	x3, L_SHA256_trans_crypto_len_k
	add	x3, x3, L_SHA256_trans_crypto_len_k
	; Load K into vector registers
	ld1	{V8.4S, V9.4S, V10.4S, V11.4S}, [x3], #0x40
	ld1	{V12.4S, V13.4S, V14.4S, V15.4S}, [x3], #0x40
	ld1	{V16.4S, V17.4S, V18.4S, V19.4S}, [x3], #0x40
	ld1	{V20.4S, V21.4S, V22.4S, V23.4S}, [x3], #0x40
	; Load digest into working vars
	ld1	{V0.4S, V1.4S}, [x0]
	; Start of loop processing a block
L_sha256_len_crypto_begin
	; Load W
	ld1	{V4.4S, V5.4S, V6.4S, V7.4S}, [x1], #0x40
	rev32	V4.16B, V4.16B
	rev32	V5.16B, V5.16B
	rev32	V6.16B, V6.16B
	rev32	V7.16B, V7.16B
	; Copy digest to add in at end
	mov	V2.16B, V0.16B
	mov	V3.16B, V1.16B
	; Start 16 rounds
	; Round 1
	add	V24.4S, V4.4S, V8.4S
	mov	V25.16B, V0.16B
	sha256h	Q0, Q1, V24.4S
	sha256h2	Q1, Q25, V24.4S
	; Round 2
	sha256su0	V4.4S, V5.4S
	add	V24.4S, V5.4S, V9.4S
	mov	V25.16B, V0.16B
	sha256su1	V4.4S, V6.4S, V7.4S
	sha256h	Q0, Q1, V24.4S
	sha256h2	Q1, Q25, V24.4S
	; Round 3
	sha256su0	V5.4S, V6.4S
	add	V24.4S, V6.4S, V10.4S
	mov	V25.16B, V0.16B
	sha256su1	V5.4S, V7.4S, V4.4S
	sha256h	Q0, Q1, V24.4S
	sha256h2	Q1, Q25, V24.4S
	; Round 4
	sha256su0	V6.4S, V7.4S
	add	V24.4S, V7.4S, V11.4S
	mov	V25.16B, V0.16B
	sha256su1	V6.4S, V4.4S, V5.4S
	sha256h	Q0, Q1, V24.4S
	sha256h2	Q1, Q25, V24.4S
	; Round 5
	sha256su0	V7.4S, V4.4S
	add	V24.4S, V4.4S, V12.4S
	mov	V25.16B, V0.16B
	sha256su1	V7.4S, V5.4S, V6.4S
	sha256h	Q0, Q1, V24.4S
	sha256h2	Q1, Q25, V24.4S
	; Round 6
	sha256su0	V4.4S, V5.4S
	add	V24.4S, V5.4S, V13.4S
	mov	V25.16B, V0.16B
	sha256su1	V4.4S, V6.4S, V7.4S
	sha256h	Q0, Q1, V24.4S
	sha256h2	Q1, Q25, V24.4S
	; Round 7
	sha256su0	V5.4S, V6.4S
	add	V24.4S, V6.4S, V14.4S
	mov	V25.16B, V0.16B
	sha256su1	V5.4S, V7.4S, V4.4S
	sha256h	Q0, Q1, V24.4S
	sha256h2	Q1, Q25, V24.4S
	; Round 8
	sha256su0	V6.4S, V7.4S
	add	V24.4S, V7.4S, V15.4S
	mov	V25.16B, V0.16B
	sha256su1	V6.4S, V4.4S, V5.4S
	sha256h	Q0, Q1, V24.4S
	sha256h2	Q1, Q25, V24.4S
	; Round 9
	sha256su0	V7.4S, V4.4S
	add	V24.4S, V4.4S, V16.4S
	mov	V25.16B, V0.16B
	sha256su1	V7.4S, V5.4S, V6.4S
	sha256h	Q0, Q1, V24.4S
	sha256h2	Q1, Q25, V24.4S
	; Round 10
	sha256su0	V4.4S, V5.4S
	add	V24.4S, V5.4S, V17.4S
	mov	V25.16B, V0.16B
	sha256su1	V4.4S, V6.4S, V7.4S
	sha256h	Q0, Q1, V24.4S
	sha256h2	Q1, Q25, V24.4S
	; Round 11
	sha256su0	V5.4S, V6.4S
	add	V24.4S, V6.4S, V18.4S
	mov	V25.16B, V0.16B
	sha256su1	V5.4S, V7.4S, V4.4S
	sha256h	Q0, Q1, V24.4S
	sha256h2	Q1, Q25, V24.4S
	; Round 12
	sha256su0	V6.4S, V7.4S
	add	V24.4S, V7.4S, V19.4S
	mov	V25.16B, V0.16B
	sha256su1	V6.4S, V4.4S, V5.4S
	sha256h	Q0, Q1, V24.4S
	sha256h2	Q1, Q25, V24.4S
	; Round 13
	sha256su0	V7.4S, V4.4S
	add	V24.4S, V4.4S, V20.4S
	mov	V25.16B, V0.16B
	sha256su1	V7.4S, V5.4S, V6.4S
	sha256h	Q0, Q1, V24.4S
	sha256h2	Q1, Q25, V24.4S
	; Round 14
	add	V24.4S, V5.4S, V21.4S
	mov	V25.16B, V0.16B
	sha256h	Q0, Q1, V24.4S
	sha256h2	Q1, Q25, V24.4S
	; Round 15
	add	V24.4S, V6.4S, V22.4S
	mov	V25.16B, V0.16B
	sha256h	Q0, Q1, V24.4S
	sha256h2	Q1, Q25, V24.4S
	; Round 16
	add	V24.4S, V7.4S, V23.4S
	mov	V25.16B, V0.16B
	sha256h	Q0, Q1, V24.4S
	sha256h2	Q1, Q25, V24.4S
	; Done 16 rounds
	add	V0.4S, V0.4S, V2.4S
	add	V1.4S, V1.4S, V3.4S
	subs	w2, w2, #0x40
	bne	L_sha256_len_crypto_begin
	; Store digest back
	st1	{V0.4S, V1.4S}, [x0]
	ldp	D8, D9, [x29, #16]
	ldp	D10, D11, [x29, #32]
	ldp	D12, D13, [x29, #48]
	ldp	D14, D15, [x29, #64]
	ldp	x29, x30, [sp], #0x50
	ret
	ENDP
	ENDIF
	ENDIF
	END
