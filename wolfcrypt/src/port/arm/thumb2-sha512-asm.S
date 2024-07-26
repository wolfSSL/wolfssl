/* thumb2-sha512-asm
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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

/* Generated using (from wolfssl):
 *   cd ../scripts
 *   ruby ./sha2/sha512.rb thumb2 ../wolfssl/wolfcrypt/src/port/arm/thumb2-sha512-asm.S
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_ARMASM
#if !defined(__aarch64__) && defined(__thumb__)
#ifndef WOLFSSL_ARMASM_INLINE
	.thumb
	.syntax unified
#ifdef WOLFSSL_SHA512
#ifdef WOLFSSL_ARMASM_NO_NEON
	.text
	.type	L_SHA512_transform_len_k, %object
	.size	L_SHA512_transform_len_k, 640
	.align	8
L_SHA512_transform_len_k:
	.word	0xd728ae22
	.word	0x428a2f98
	.word	0x23ef65cd
	.word	0x71374491
	.word	0xec4d3b2f
	.word	0xb5c0fbcf
	.word	0x8189dbbc
	.word	0xe9b5dba5
	.word	0xf348b538
	.word	0x3956c25b
	.word	0xb605d019
	.word	0x59f111f1
	.word	0xaf194f9b
	.word	0x923f82a4
	.word	0xda6d8118
	.word	0xab1c5ed5
	.word	0xa3030242
	.word	0xd807aa98
	.word	0x45706fbe
	.word	0x12835b01
	.word	0x4ee4b28c
	.word	0x243185be
	.word	0xd5ffb4e2
	.word	0x550c7dc3
	.word	0xf27b896f
	.word	0x72be5d74
	.word	0x3b1696b1
	.word	0x80deb1fe
	.word	0x25c71235
	.word	0x9bdc06a7
	.word	0xcf692694
	.word	0xc19bf174
	.word	0x9ef14ad2
	.word	0xe49b69c1
	.word	0x384f25e3
	.word	0xefbe4786
	.word	0x8b8cd5b5
	.word	0xfc19dc6
	.word	0x77ac9c65
	.word	0x240ca1cc
	.word	0x592b0275
	.word	0x2de92c6f
	.word	0x6ea6e483
	.word	0x4a7484aa
	.word	0xbd41fbd4
	.word	0x5cb0a9dc
	.word	0x831153b5
	.word	0x76f988da
	.word	0xee66dfab
	.word	0x983e5152
	.word	0x2db43210
	.word	0xa831c66d
	.word	0x98fb213f
	.word	0xb00327c8
	.word	0xbeef0ee4
	.word	0xbf597fc7
	.word	0x3da88fc2
	.word	0xc6e00bf3
	.word	0x930aa725
	.word	0xd5a79147
	.word	0xe003826f
	.word	0x6ca6351
	.word	0xa0e6e70
	.word	0x14292967
	.word	0x46d22ffc
	.word	0x27b70a85
	.word	0x5c26c926
	.word	0x2e1b2138
	.word	0x5ac42aed
	.word	0x4d2c6dfc
	.word	0x9d95b3df
	.word	0x53380d13
	.word	0x8baf63de
	.word	0x650a7354
	.word	0x3c77b2a8
	.word	0x766a0abb
	.word	0x47edaee6
	.word	0x81c2c92e
	.word	0x1482353b
	.word	0x92722c85
	.word	0x4cf10364
	.word	0xa2bfe8a1
	.word	0xbc423001
	.word	0xa81a664b
	.word	0xd0f89791
	.word	0xc24b8b70
	.word	0x654be30
	.word	0xc76c51a3
	.word	0xd6ef5218
	.word	0xd192e819
	.word	0x5565a910
	.word	0xd6990624
	.word	0x5771202a
	.word	0xf40e3585
	.word	0x32bbd1b8
	.word	0x106aa070
	.word	0xb8d2d0c8
	.word	0x19a4c116
	.word	0x5141ab53
	.word	0x1e376c08
	.word	0xdf8eeb99
	.word	0x2748774c
	.word	0xe19b48a8
	.word	0x34b0bcb5
	.word	0xc5c95a63
	.word	0x391c0cb3
	.word	0xe3418acb
	.word	0x4ed8aa4a
	.word	0x7763e373
	.word	0x5b9cca4f
	.word	0xd6b2b8a3
	.word	0x682e6ff3
	.word	0x5defb2fc
	.word	0x748f82ee
	.word	0x43172f60
	.word	0x78a5636f
	.word	0xa1f0ab72
	.word	0x84c87814
	.word	0x1a6439ec
	.word	0x8cc70208
	.word	0x23631e28
	.word	0x90befffa
	.word	0xde82bde9
	.word	0xa4506ceb
	.word	0xb2c67915
	.word	0xbef9a3f7
	.word	0xe372532b
	.word	0xc67178f2
	.word	0xea26619c
	.word	0xca273ece
	.word	0x21c0c207
	.word	0xd186b8c7
	.word	0xcde0eb1e
	.word	0xeada7dd6
	.word	0xee6ed178
	.word	0xf57d4f7f
	.word	0x72176fba
	.word	0x6f067aa
	.word	0xa2c898a6
	.word	0xa637dc5
	.word	0xbef90dae
	.word	0x113f9804
	.word	0x131c471b
	.word	0x1b710b35
	.word	0x23047d84
	.word	0x28db77f5
	.word	0x40c72493
	.word	0x32caab7b
	.word	0x15c9bebc
	.word	0x3c9ebe0a
	.word	0x9c100d4c
	.word	0x431d67c4
	.word	0xcb3e42b6
	.word	0x4cc5d4be
	.word	0xfc657e2a
	.word	0x597f299c
	.word	0x3ad6faec
	.word	0x5fcb6fab
	.word	0x4a475817
	.word	0x6c44198c
	.text
	.align	4
	.globl	Transform_Sha512_Len
	.type	Transform_Sha512_Len, %function
Transform_Sha512_Len:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0xc0
	ADR	r3, L_SHA512_transform_len_k
	/* Copy digest to add in at end */
	LDRD	r4, r5, [r0]
	LDRD	r6, r7, [r0, #8]
	LDRD	r8, r9, [r0, #16]
	LDRD	r10, r11, [r0, #24]
	STRD	r4, r5, [sp, #128]
	STRD	r6, r7, [sp, #136]
	STRD	r8, r9, [sp, #144]
	STRD	r10, r11, [sp, #152]
	LDRD	r4, r5, [r0, #32]
	LDRD	r6, r7, [r0, #40]
	LDRD	r8, r9, [r0, #48]
	LDRD	r10, r11, [r0, #56]
	STRD	r4, r5, [sp, #160]
	STRD	r6, r7, [sp, #168]
	STRD	r8, r9, [sp, #176]
	STRD	r10, r11, [sp, #184]
	/* Start of loop processing a block */
L_SHA512_transform_len_begin:
	/* Load, Reverse and Store W */
	LDR	r4, [r1]
	LDR	r5, [r1, #4]
	LDR	r6, [r1, #8]
	LDR	r7, [r1, #12]
	LDR	r8, [r1, #16]
	LDR	r9, [r1, #20]
	LDR	r10, [r1, #24]
	LDR	r11, [r1, #28]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	REV	r8, r8
	REV	r9, r9
	REV	r10, r10
	REV	r11, r11
	STR	r5, [sp]
	STR	r4, [sp, #4]
	STR	r7, [sp, #8]
	STR	r6, [sp, #12]
	STR	r9, [sp, #16]
	STR	r8, [sp, #20]
	STR	r11, [sp, #24]
	STR	r10, [sp, #28]
	LDR	r4, [r1, #32]
	LDR	r5, [r1, #36]
	LDR	r6, [r1, #40]
	LDR	r7, [r1, #44]
	LDR	r8, [r1, #48]
	LDR	r9, [r1, #52]
	LDR	r10, [r1, #56]
	LDR	r11, [r1, #60]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	REV	r8, r8
	REV	r9, r9
	REV	r10, r10
	REV	r11, r11
	STR	r5, [sp, #32]
	STR	r4, [sp, #36]
	STR	r7, [sp, #40]
	STR	r6, [sp, #44]
	STR	r9, [sp, #48]
	STR	r8, [sp, #52]
	STR	r11, [sp, #56]
	STR	r10, [sp, #60]
	LDR	r4, [r1, #64]
	LDR	r5, [r1, #68]
	LDR	r6, [r1, #72]
	LDR	r7, [r1, #76]
	LDR	r8, [r1, #80]
	LDR	r9, [r1, #84]
	LDR	r10, [r1, #88]
	LDR	r11, [r1, #92]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	REV	r8, r8
	REV	r9, r9
	REV	r10, r10
	REV	r11, r11
	STR	r5, [sp, #64]
	STR	r4, [sp, #68]
	STR	r7, [sp, #72]
	STR	r6, [sp, #76]
	STR	r9, [sp, #80]
	STR	r8, [sp, #84]
	STR	r11, [sp, #88]
	STR	r10, [sp, #92]
	LDR	r4, [r1, #96]
	LDR	r5, [r1, #100]
	LDR	r6, [r1, #104]
	LDR	r7, [r1, #108]
	LDR	r8, [r1, #112]
	LDR	r9, [r1, #116]
	LDR	r10, [r1, #120]
	LDR	r11, [r1, #124]
	REV	r4, r4
	REV	r5, r5
	REV	r6, r6
	REV	r7, r7
	REV	r8, r8
	REV	r9, r9
	REV	r10, r10
	REV	r11, r11
	STR	r5, [sp, #96]
	STR	r4, [sp, #100]
	STR	r7, [sp, #104]
	STR	r6, [sp, #108]
	STR	r9, [sp, #112]
	STR	r8, [sp, #116]
	STR	r11, [sp, #120]
	STR	r10, [sp, #124]
	/* Pre-calc: b ^ c */
	LDRD	r10, r11, [r0, #8]
	LDRD	r4, r5, [r0, #16]
	EOR	r10, r10, r4
	EOR	r11, r11, r5
	MOV	r12, #0x4
	/* Start of 16 rounds */
L_SHA512_transform_len_start:
	/* Round 0 */
	LDRD	r4, r5, [r0, #32]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #56]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #56]
	LDRD	r4, r5, [r0, #32]
	LDRD	r6, r7, [r0, #40]
	LDRD	r8, r9, [r0, #48]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #56]
	LDRD	r8, r9, [sp]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #24]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #56]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0]
	STRD	r8, r9, [r0, #24]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #56]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0]
	LDRD	r6, r7, [r0, #8]
	STRD	r4, r5, [r0, #56]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #56]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #56]
	MOV	r10, r8
	MOV	r11, r9
	/* Calc new W[0] */
	LDRD	r4, r5, [sp, #112]
	LSRS	r6, r4, #19
	LSRS	r7, r5, #19
	ORR	r7, r7, r4, LSL #13
	ORR	r6, r6, r5, LSL #13
	LSLS	r8, r4, #3
	LSLS	r9, r5, #3
	ORR	r9, r9, r4, LSR #29
	ORR	r8, r8, r5, LSR #29
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #6
	LSRS	r9, r5, #6
	ORR	r8, r8, r5, LSL #26
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp]
	LDRD	r8, r9, [sp, #72]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	STRD	r4, r5, [sp]
	LDRD	r4, r5, [sp, #8]
	LSRS	r6, r4, #1
	LSRS	r7, r5, #1
	ORR	r7, r7, r4, LSL #31
	ORR	r6, r6, r5, LSL #31
	LSRS	r8, r4, #8
	LSRS	r9, r5, #8
	ORR	r9, r9, r4, LSL #24
	ORR	r8, r8, r5, LSL #24
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #7
	LSRS	r9, r5, #7
	ORR	r8, r8, r5, LSL #25
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [sp]
	/* Round 1 */
	LDRD	r4, r5, [r0, #24]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #48]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #48]
	LDRD	r4, r5, [r0, #24]
	LDRD	r6, r7, [r0, #32]
	LDRD	r8, r9, [r0, #40]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #48]
	LDRD	r8, r9, [sp, #8]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #8]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #16]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #48]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #56]
	STRD	r8, r9, [r0, #16]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #48]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #56]
	LDRD	r6, r7, [r0]
	STRD	r4, r5, [r0, #48]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #48]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #48]
	MOV	r10, r8
	MOV	r11, r9
	/* Calc new W[1] */
	LDRD	r4, r5, [sp, #120]
	LSRS	r6, r4, #19
	LSRS	r7, r5, #19
	ORR	r7, r7, r4, LSL #13
	ORR	r6, r6, r5, LSL #13
	LSLS	r8, r4, #3
	LSLS	r9, r5, #3
	ORR	r9, r9, r4, LSR #29
	ORR	r8, r8, r5, LSR #29
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #6
	LSRS	r9, r5, #6
	ORR	r8, r8, r5, LSL #26
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #8]
	LDRD	r8, r9, [sp, #80]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	STRD	r4, r5, [sp, #8]
	LDRD	r4, r5, [sp, #16]
	LSRS	r6, r4, #1
	LSRS	r7, r5, #1
	ORR	r7, r7, r4, LSL #31
	ORR	r6, r6, r5, LSL #31
	LSRS	r8, r4, #8
	LSRS	r9, r5, #8
	ORR	r9, r9, r4, LSL #24
	ORR	r8, r8, r5, LSL #24
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #7
	LSRS	r9, r5, #7
	ORR	r8, r8, r5, LSL #25
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #8]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [sp, #8]
	/* Round 2 */
	LDRD	r4, r5, [r0, #16]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #40]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #40]
	LDRD	r4, r5, [r0, #16]
	LDRD	r6, r7, [r0, #24]
	LDRD	r8, r9, [r0, #32]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #40]
	LDRD	r8, r9, [sp, #16]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #16]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #8]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #40]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #48]
	STRD	r8, r9, [r0, #8]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #40]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #48]
	LDRD	r6, r7, [r0, #56]
	STRD	r4, r5, [r0, #40]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #40]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #40]
	MOV	r10, r8
	MOV	r11, r9
	/* Calc new W[2] */
	LDRD	r4, r5, [sp]
	LSRS	r6, r4, #19
	LSRS	r7, r5, #19
	ORR	r7, r7, r4, LSL #13
	ORR	r6, r6, r5, LSL #13
	LSLS	r8, r4, #3
	LSLS	r9, r5, #3
	ORR	r9, r9, r4, LSR #29
	ORR	r8, r8, r5, LSR #29
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #6
	LSRS	r9, r5, #6
	ORR	r8, r8, r5, LSL #26
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #16]
	LDRD	r8, r9, [sp, #88]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	STRD	r4, r5, [sp, #16]
	LDRD	r4, r5, [sp, #24]
	LSRS	r6, r4, #1
	LSRS	r7, r5, #1
	ORR	r7, r7, r4, LSL #31
	ORR	r6, r6, r5, LSL #31
	LSRS	r8, r4, #8
	LSRS	r9, r5, #8
	ORR	r9, r9, r4, LSL #24
	ORR	r8, r8, r5, LSL #24
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #7
	LSRS	r9, r5, #7
	ORR	r8, r8, r5, LSL #25
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #16]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [sp, #16]
	/* Round 3 */
	LDRD	r4, r5, [r0, #8]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #32]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #32]
	LDRD	r4, r5, [r0, #8]
	LDRD	r6, r7, [r0, #16]
	LDRD	r8, r9, [r0, #24]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #32]
	LDRD	r8, r9, [sp, #24]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #24]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #32]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #40]
	STRD	r8, r9, [r0]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #32]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #40]
	LDRD	r6, r7, [r0, #48]
	STRD	r4, r5, [r0, #32]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #32]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #32]
	MOV	r10, r8
	MOV	r11, r9
	/* Calc new W[3] */
	LDRD	r4, r5, [sp, #8]
	LSRS	r6, r4, #19
	LSRS	r7, r5, #19
	ORR	r7, r7, r4, LSL #13
	ORR	r6, r6, r5, LSL #13
	LSLS	r8, r4, #3
	LSLS	r9, r5, #3
	ORR	r9, r9, r4, LSR #29
	ORR	r8, r8, r5, LSR #29
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #6
	LSRS	r9, r5, #6
	ORR	r8, r8, r5, LSL #26
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #24]
	LDRD	r8, r9, [sp, #96]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	STRD	r4, r5, [sp, #24]
	LDRD	r4, r5, [sp, #32]
	LSRS	r6, r4, #1
	LSRS	r7, r5, #1
	ORR	r7, r7, r4, LSL #31
	ORR	r6, r6, r5, LSL #31
	LSRS	r8, r4, #8
	LSRS	r9, r5, #8
	ORR	r9, r9, r4, LSL #24
	ORR	r8, r8, r5, LSL #24
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #7
	LSRS	r9, r5, #7
	ORR	r8, r8, r5, LSL #25
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #24]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [sp, #24]
	/* Round 4 */
	LDRD	r4, r5, [r0]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #24]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #24]
	LDRD	r4, r5, [r0]
	LDRD	r6, r7, [r0, #8]
	LDRD	r8, r9, [r0, #16]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #24]
	LDRD	r8, r9, [sp, #32]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #32]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #56]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #24]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #32]
	STRD	r8, r9, [r0, #56]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #24]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #32]
	LDRD	r6, r7, [r0, #40]
	STRD	r4, r5, [r0, #24]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #24]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #24]
	MOV	r10, r8
	MOV	r11, r9
	/* Calc new W[4] */
	LDRD	r4, r5, [sp, #16]
	LSRS	r6, r4, #19
	LSRS	r7, r5, #19
	ORR	r7, r7, r4, LSL #13
	ORR	r6, r6, r5, LSL #13
	LSLS	r8, r4, #3
	LSLS	r9, r5, #3
	ORR	r9, r9, r4, LSR #29
	ORR	r8, r8, r5, LSR #29
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #6
	LSRS	r9, r5, #6
	ORR	r8, r8, r5, LSL #26
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #32]
	LDRD	r8, r9, [sp, #104]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	STRD	r4, r5, [sp, #32]
	LDRD	r4, r5, [sp, #40]
	LSRS	r6, r4, #1
	LSRS	r7, r5, #1
	ORR	r7, r7, r4, LSL #31
	ORR	r6, r6, r5, LSL #31
	LSRS	r8, r4, #8
	LSRS	r9, r5, #8
	ORR	r9, r9, r4, LSL #24
	ORR	r8, r8, r5, LSL #24
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #7
	LSRS	r9, r5, #7
	ORR	r8, r8, r5, LSL #25
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #32]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [sp, #32]
	/* Round 5 */
	LDRD	r4, r5, [r0, #56]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #16]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #16]
	LDRD	r4, r5, [r0, #56]
	LDRD	r6, r7, [r0]
	LDRD	r8, r9, [r0, #8]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #16]
	LDRD	r8, r9, [sp, #40]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #40]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #48]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #16]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #24]
	STRD	r8, r9, [r0, #48]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #16]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #24]
	LDRD	r6, r7, [r0, #32]
	STRD	r4, r5, [r0, #16]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #16]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #16]
	MOV	r10, r8
	MOV	r11, r9
	/* Calc new W[5] */
	LDRD	r4, r5, [sp, #24]
	LSRS	r6, r4, #19
	LSRS	r7, r5, #19
	ORR	r7, r7, r4, LSL #13
	ORR	r6, r6, r5, LSL #13
	LSLS	r8, r4, #3
	LSLS	r9, r5, #3
	ORR	r9, r9, r4, LSR #29
	ORR	r8, r8, r5, LSR #29
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #6
	LSRS	r9, r5, #6
	ORR	r8, r8, r5, LSL #26
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #40]
	LDRD	r8, r9, [sp, #112]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	STRD	r4, r5, [sp, #40]
	LDRD	r4, r5, [sp, #48]
	LSRS	r6, r4, #1
	LSRS	r7, r5, #1
	ORR	r7, r7, r4, LSL #31
	ORR	r6, r6, r5, LSL #31
	LSRS	r8, r4, #8
	LSRS	r9, r5, #8
	ORR	r9, r9, r4, LSL #24
	ORR	r8, r8, r5, LSL #24
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #7
	LSRS	r9, r5, #7
	ORR	r8, r8, r5, LSL #25
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #40]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [sp, #40]
	/* Round 6 */
	LDRD	r4, r5, [r0, #48]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #8]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #8]
	LDRD	r4, r5, [r0, #48]
	LDRD	r6, r7, [r0, #56]
	LDRD	r8, r9, [r0]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #8]
	LDRD	r8, r9, [sp, #48]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #48]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #40]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #8]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #16]
	STRD	r8, r9, [r0, #40]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #8]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #16]
	LDRD	r6, r7, [r0, #24]
	STRD	r4, r5, [r0, #8]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #8]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #8]
	MOV	r10, r8
	MOV	r11, r9
	/* Calc new W[6] */
	LDRD	r4, r5, [sp, #32]
	LSRS	r6, r4, #19
	LSRS	r7, r5, #19
	ORR	r7, r7, r4, LSL #13
	ORR	r6, r6, r5, LSL #13
	LSLS	r8, r4, #3
	LSLS	r9, r5, #3
	ORR	r9, r9, r4, LSR #29
	ORR	r8, r8, r5, LSR #29
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #6
	LSRS	r9, r5, #6
	ORR	r8, r8, r5, LSL #26
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #48]
	LDRD	r8, r9, [sp, #120]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	STRD	r4, r5, [sp, #48]
	LDRD	r4, r5, [sp, #56]
	LSRS	r6, r4, #1
	LSRS	r7, r5, #1
	ORR	r7, r7, r4, LSL #31
	ORR	r6, r6, r5, LSL #31
	LSRS	r8, r4, #8
	LSRS	r9, r5, #8
	ORR	r9, r9, r4, LSL #24
	ORR	r8, r8, r5, LSL #24
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #7
	LSRS	r9, r5, #7
	ORR	r8, r8, r5, LSL #25
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #48]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [sp, #48]
	/* Round 7 */
	LDRD	r4, r5, [r0, #40]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0]
	LDRD	r4, r5, [r0, #40]
	LDRD	r6, r7, [r0, #48]
	LDRD	r8, r9, [r0, #56]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0]
	LDRD	r8, r9, [sp, #56]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #56]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #32]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #8]
	STRD	r8, r9, [r0, #32]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #8]
	LDRD	r6, r7, [r0, #16]
	STRD	r4, r5, [r0]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0]
	MOV	r10, r8
	MOV	r11, r9
	/* Calc new W[7] */
	LDRD	r4, r5, [sp, #40]
	LSRS	r6, r4, #19
	LSRS	r7, r5, #19
	ORR	r7, r7, r4, LSL #13
	ORR	r6, r6, r5, LSL #13
	LSLS	r8, r4, #3
	LSLS	r9, r5, #3
	ORR	r9, r9, r4, LSR #29
	ORR	r8, r8, r5, LSR #29
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #6
	LSRS	r9, r5, #6
	ORR	r8, r8, r5, LSL #26
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #56]
	LDRD	r8, r9, [sp]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	STRD	r4, r5, [sp, #56]
	LDRD	r4, r5, [sp, #64]
	LSRS	r6, r4, #1
	LSRS	r7, r5, #1
	ORR	r7, r7, r4, LSL #31
	ORR	r6, r6, r5, LSL #31
	LSRS	r8, r4, #8
	LSRS	r9, r5, #8
	ORR	r9, r9, r4, LSL #24
	ORR	r8, r8, r5, LSL #24
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #7
	LSRS	r9, r5, #7
	ORR	r8, r8, r5, LSL #25
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #56]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [sp, #56]
	/* Round 8 */
	LDRD	r4, r5, [r0, #32]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #56]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #56]
	LDRD	r4, r5, [r0, #32]
	LDRD	r6, r7, [r0, #40]
	LDRD	r8, r9, [r0, #48]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #56]
	LDRD	r8, r9, [sp, #64]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #64]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #24]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #56]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0]
	STRD	r8, r9, [r0, #24]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #56]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0]
	LDRD	r6, r7, [r0, #8]
	STRD	r4, r5, [r0, #56]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #56]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #56]
	MOV	r10, r8
	MOV	r11, r9
	/* Calc new W[8] */
	LDRD	r4, r5, [sp, #48]
	LSRS	r6, r4, #19
	LSRS	r7, r5, #19
	ORR	r7, r7, r4, LSL #13
	ORR	r6, r6, r5, LSL #13
	LSLS	r8, r4, #3
	LSLS	r9, r5, #3
	ORR	r9, r9, r4, LSR #29
	ORR	r8, r8, r5, LSR #29
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #6
	LSRS	r9, r5, #6
	ORR	r8, r8, r5, LSL #26
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #64]
	LDRD	r8, r9, [sp, #8]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	STRD	r4, r5, [sp, #64]
	LDRD	r4, r5, [sp, #72]
	LSRS	r6, r4, #1
	LSRS	r7, r5, #1
	ORR	r7, r7, r4, LSL #31
	ORR	r6, r6, r5, LSL #31
	LSRS	r8, r4, #8
	LSRS	r9, r5, #8
	ORR	r9, r9, r4, LSL #24
	ORR	r8, r8, r5, LSL #24
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #7
	LSRS	r9, r5, #7
	ORR	r8, r8, r5, LSL #25
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #64]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [sp, #64]
	/* Round 9 */
	LDRD	r4, r5, [r0, #24]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #48]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #48]
	LDRD	r4, r5, [r0, #24]
	LDRD	r6, r7, [r0, #32]
	LDRD	r8, r9, [r0, #40]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #48]
	LDRD	r8, r9, [sp, #72]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #72]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #16]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #48]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #56]
	STRD	r8, r9, [r0, #16]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #48]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #56]
	LDRD	r6, r7, [r0]
	STRD	r4, r5, [r0, #48]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #48]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #48]
	MOV	r10, r8
	MOV	r11, r9
	/* Calc new W[9] */
	LDRD	r4, r5, [sp, #56]
	LSRS	r6, r4, #19
	LSRS	r7, r5, #19
	ORR	r7, r7, r4, LSL #13
	ORR	r6, r6, r5, LSL #13
	LSLS	r8, r4, #3
	LSLS	r9, r5, #3
	ORR	r9, r9, r4, LSR #29
	ORR	r8, r8, r5, LSR #29
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #6
	LSRS	r9, r5, #6
	ORR	r8, r8, r5, LSL #26
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #72]
	LDRD	r8, r9, [sp, #16]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	STRD	r4, r5, [sp, #72]
	LDRD	r4, r5, [sp, #80]
	LSRS	r6, r4, #1
	LSRS	r7, r5, #1
	ORR	r7, r7, r4, LSL #31
	ORR	r6, r6, r5, LSL #31
	LSRS	r8, r4, #8
	LSRS	r9, r5, #8
	ORR	r9, r9, r4, LSL #24
	ORR	r8, r8, r5, LSL #24
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #7
	LSRS	r9, r5, #7
	ORR	r8, r8, r5, LSL #25
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #72]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [sp, #72]
	/* Round 10 */
	LDRD	r4, r5, [r0, #16]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #40]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #40]
	LDRD	r4, r5, [r0, #16]
	LDRD	r6, r7, [r0, #24]
	LDRD	r8, r9, [r0, #32]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #40]
	LDRD	r8, r9, [sp, #80]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #80]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #8]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #40]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #48]
	STRD	r8, r9, [r0, #8]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #40]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #48]
	LDRD	r6, r7, [r0, #56]
	STRD	r4, r5, [r0, #40]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #40]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #40]
	MOV	r10, r8
	MOV	r11, r9
	/* Calc new W[10] */
	LDRD	r4, r5, [sp, #64]
	LSRS	r6, r4, #19
	LSRS	r7, r5, #19
	ORR	r7, r7, r4, LSL #13
	ORR	r6, r6, r5, LSL #13
	LSLS	r8, r4, #3
	LSLS	r9, r5, #3
	ORR	r9, r9, r4, LSR #29
	ORR	r8, r8, r5, LSR #29
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #6
	LSRS	r9, r5, #6
	ORR	r8, r8, r5, LSL #26
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #80]
	LDRD	r8, r9, [sp, #24]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	STRD	r4, r5, [sp, #80]
	LDRD	r4, r5, [sp, #88]
	LSRS	r6, r4, #1
	LSRS	r7, r5, #1
	ORR	r7, r7, r4, LSL #31
	ORR	r6, r6, r5, LSL #31
	LSRS	r8, r4, #8
	LSRS	r9, r5, #8
	ORR	r9, r9, r4, LSL #24
	ORR	r8, r8, r5, LSL #24
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #7
	LSRS	r9, r5, #7
	ORR	r8, r8, r5, LSL #25
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #80]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [sp, #80]
	/* Round 11 */
	LDRD	r4, r5, [r0, #8]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #32]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #32]
	LDRD	r4, r5, [r0, #8]
	LDRD	r6, r7, [r0, #16]
	LDRD	r8, r9, [r0, #24]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #32]
	LDRD	r8, r9, [sp, #88]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #88]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #32]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #40]
	STRD	r8, r9, [r0]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #32]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #40]
	LDRD	r6, r7, [r0, #48]
	STRD	r4, r5, [r0, #32]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #32]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #32]
	MOV	r10, r8
	MOV	r11, r9
	/* Calc new W[11] */
	LDRD	r4, r5, [sp, #72]
	LSRS	r6, r4, #19
	LSRS	r7, r5, #19
	ORR	r7, r7, r4, LSL #13
	ORR	r6, r6, r5, LSL #13
	LSLS	r8, r4, #3
	LSLS	r9, r5, #3
	ORR	r9, r9, r4, LSR #29
	ORR	r8, r8, r5, LSR #29
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #6
	LSRS	r9, r5, #6
	ORR	r8, r8, r5, LSL #26
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #88]
	LDRD	r8, r9, [sp, #32]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	STRD	r4, r5, [sp, #88]
	LDRD	r4, r5, [sp, #96]
	LSRS	r6, r4, #1
	LSRS	r7, r5, #1
	ORR	r7, r7, r4, LSL #31
	ORR	r6, r6, r5, LSL #31
	LSRS	r8, r4, #8
	LSRS	r9, r5, #8
	ORR	r9, r9, r4, LSL #24
	ORR	r8, r8, r5, LSL #24
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #7
	LSRS	r9, r5, #7
	ORR	r8, r8, r5, LSL #25
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #88]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [sp, #88]
	/* Round 12 */
	LDRD	r4, r5, [r0]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #24]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #24]
	LDRD	r4, r5, [r0]
	LDRD	r6, r7, [r0, #8]
	LDRD	r8, r9, [r0, #16]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #24]
	LDRD	r8, r9, [sp, #96]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #96]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #56]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #24]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #32]
	STRD	r8, r9, [r0, #56]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #24]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #32]
	LDRD	r6, r7, [r0, #40]
	STRD	r4, r5, [r0, #24]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #24]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #24]
	MOV	r10, r8
	MOV	r11, r9
	/* Calc new W[12] */
	LDRD	r4, r5, [sp, #80]
	LSRS	r6, r4, #19
	LSRS	r7, r5, #19
	ORR	r7, r7, r4, LSL #13
	ORR	r6, r6, r5, LSL #13
	LSLS	r8, r4, #3
	LSLS	r9, r5, #3
	ORR	r9, r9, r4, LSR #29
	ORR	r8, r8, r5, LSR #29
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #6
	LSRS	r9, r5, #6
	ORR	r8, r8, r5, LSL #26
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #96]
	LDRD	r8, r9, [sp, #40]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	STRD	r4, r5, [sp, #96]
	LDRD	r4, r5, [sp, #104]
	LSRS	r6, r4, #1
	LSRS	r7, r5, #1
	ORR	r7, r7, r4, LSL #31
	ORR	r6, r6, r5, LSL #31
	LSRS	r8, r4, #8
	LSRS	r9, r5, #8
	ORR	r9, r9, r4, LSL #24
	ORR	r8, r8, r5, LSL #24
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #7
	LSRS	r9, r5, #7
	ORR	r8, r8, r5, LSL #25
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #96]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [sp, #96]
	/* Round 13 */
	LDRD	r4, r5, [r0, #56]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #16]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #16]
	LDRD	r4, r5, [r0, #56]
	LDRD	r6, r7, [r0]
	LDRD	r8, r9, [r0, #8]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #16]
	LDRD	r8, r9, [sp, #104]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #104]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #48]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #16]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #24]
	STRD	r8, r9, [r0, #48]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #16]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #24]
	LDRD	r6, r7, [r0, #32]
	STRD	r4, r5, [r0, #16]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #16]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #16]
	MOV	r10, r8
	MOV	r11, r9
	/* Calc new W[13] */
	LDRD	r4, r5, [sp, #88]
	LSRS	r6, r4, #19
	LSRS	r7, r5, #19
	ORR	r7, r7, r4, LSL #13
	ORR	r6, r6, r5, LSL #13
	LSLS	r8, r4, #3
	LSLS	r9, r5, #3
	ORR	r9, r9, r4, LSR #29
	ORR	r8, r8, r5, LSR #29
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #6
	LSRS	r9, r5, #6
	ORR	r8, r8, r5, LSL #26
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #104]
	LDRD	r8, r9, [sp, #48]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	STRD	r4, r5, [sp, #104]
	LDRD	r4, r5, [sp, #112]
	LSRS	r6, r4, #1
	LSRS	r7, r5, #1
	ORR	r7, r7, r4, LSL #31
	ORR	r6, r6, r5, LSL #31
	LSRS	r8, r4, #8
	LSRS	r9, r5, #8
	ORR	r9, r9, r4, LSL #24
	ORR	r8, r8, r5, LSL #24
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #7
	LSRS	r9, r5, #7
	ORR	r8, r8, r5, LSL #25
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #104]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [sp, #104]
	/* Round 14 */
	LDRD	r4, r5, [r0, #48]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #8]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #8]
	LDRD	r4, r5, [r0, #48]
	LDRD	r6, r7, [r0, #56]
	LDRD	r8, r9, [r0]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #8]
	LDRD	r8, r9, [sp, #112]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #112]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #40]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #8]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #16]
	STRD	r8, r9, [r0, #40]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #8]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #16]
	LDRD	r6, r7, [r0, #24]
	STRD	r4, r5, [r0, #8]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #8]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #8]
	MOV	r10, r8
	MOV	r11, r9
	/* Calc new W[14] */
	LDRD	r4, r5, [sp, #96]
	LSRS	r6, r4, #19
	LSRS	r7, r5, #19
	ORR	r7, r7, r4, LSL #13
	ORR	r6, r6, r5, LSL #13
	LSLS	r8, r4, #3
	LSLS	r9, r5, #3
	ORR	r9, r9, r4, LSR #29
	ORR	r8, r8, r5, LSR #29
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #6
	LSRS	r9, r5, #6
	ORR	r8, r8, r5, LSL #26
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #112]
	LDRD	r8, r9, [sp, #56]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	STRD	r4, r5, [sp, #112]
	LDRD	r4, r5, [sp, #120]
	LSRS	r6, r4, #1
	LSRS	r7, r5, #1
	ORR	r7, r7, r4, LSL #31
	ORR	r6, r6, r5, LSL #31
	LSRS	r8, r4, #8
	LSRS	r9, r5, #8
	ORR	r9, r9, r4, LSL #24
	ORR	r8, r8, r5, LSL #24
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #7
	LSRS	r9, r5, #7
	ORR	r8, r8, r5, LSL #25
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #112]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [sp, #112]
	/* Round 15 */
	LDRD	r4, r5, [r0, #40]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0]
	LDRD	r4, r5, [r0, #40]
	LDRD	r6, r7, [r0, #48]
	LDRD	r8, r9, [r0, #56]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0]
	LDRD	r8, r9, [sp, #120]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #120]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #32]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #8]
	STRD	r8, r9, [r0, #32]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #8]
	LDRD	r6, r7, [r0, #16]
	STRD	r4, r5, [r0]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0]
	MOV	r10, r8
	MOV	r11, r9
	/* Calc new W[15] */
	LDRD	r4, r5, [sp, #104]
	LSRS	r6, r4, #19
	LSRS	r7, r5, #19
	ORR	r7, r7, r4, LSL #13
	ORR	r6, r6, r5, LSL #13
	LSLS	r8, r4, #3
	LSLS	r9, r5, #3
	ORR	r9, r9, r4, LSR #29
	ORR	r8, r8, r5, LSR #29
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #6
	LSRS	r9, r5, #6
	ORR	r8, r8, r5, LSL #26
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #120]
	LDRD	r8, r9, [sp, #64]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	STRD	r4, r5, [sp, #120]
	LDRD	r4, r5, [sp]
	LSRS	r6, r4, #1
	LSRS	r7, r5, #1
	ORR	r7, r7, r4, LSL #31
	ORR	r6, r6, r5, LSL #31
	LSRS	r8, r4, #8
	LSRS	r9, r5, #8
	ORR	r9, r9, r4, LSL #24
	ORR	r8, r8, r5, LSL #24
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LSRS	r8, r4, #7
	LSRS	r9, r5, #7
	ORR	r8, r8, r5, LSL #25
	EOR	r7, r7, r9
	EOR	r6, r6, r8
	LDRD	r4, r5, [sp, #120]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [sp, #120]
	ADD	r3, r3, #0x80
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_SHA512_transform_len_start
#else
	BNE.W	L_SHA512_transform_len_start
#endif
	/* Round 0 */
	LDRD	r4, r5, [r0, #32]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #56]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #56]
	LDRD	r4, r5, [r0, #32]
	LDRD	r6, r7, [r0, #40]
	LDRD	r8, r9, [r0, #48]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #56]
	LDRD	r8, r9, [sp]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #24]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #56]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0]
	STRD	r8, r9, [r0, #24]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #56]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0]
	LDRD	r6, r7, [r0, #8]
	STRD	r4, r5, [r0, #56]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #56]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #56]
	MOV	r10, r8
	MOV	r11, r9
	/* Round 1 */
	LDRD	r4, r5, [r0, #24]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #48]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #48]
	LDRD	r4, r5, [r0, #24]
	LDRD	r6, r7, [r0, #32]
	LDRD	r8, r9, [r0, #40]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #48]
	LDRD	r8, r9, [sp, #8]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #8]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #16]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #48]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #56]
	STRD	r8, r9, [r0, #16]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #48]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #56]
	LDRD	r6, r7, [r0]
	STRD	r4, r5, [r0, #48]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #48]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #48]
	MOV	r10, r8
	MOV	r11, r9
	/* Round 2 */
	LDRD	r4, r5, [r0, #16]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #40]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #40]
	LDRD	r4, r5, [r0, #16]
	LDRD	r6, r7, [r0, #24]
	LDRD	r8, r9, [r0, #32]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #40]
	LDRD	r8, r9, [sp, #16]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #16]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #8]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #40]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #48]
	STRD	r8, r9, [r0, #8]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #40]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #48]
	LDRD	r6, r7, [r0, #56]
	STRD	r4, r5, [r0, #40]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #40]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #40]
	MOV	r10, r8
	MOV	r11, r9
	/* Round 3 */
	LDRD	r4, r5, [r0, #8]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #32]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #32]
	LDRD	r4, r5, [r0, #8]
	LDRD	r6, r7, [r0, #16]
	LDRD	r8, r9, [r0, #24]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #32]
	LDRD	r8, r9, [sp, #24]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #24]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #32]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #40]
	STRD	r8, r9, [r0]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #32]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #40]
	LDRD	r6, r7, [r0, #48]
	STRD	r4, r5, [r0, #32]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #32]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #32]
	MOV	r10, r8
	MOV	r11, r9
	/* Round 4 */
	LDRD	r4, r5, [r0]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #24]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #24]
	LDRD	r4, r5, [r0]
	LDRD	r6, r7, [r0, #8]
	LDRD	r8, r9, [r0, #16]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #24]
	LDRD	r8, r9, [sp, #32]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #32]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #56]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #24]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #32]
	STRD	r8, r9, [r0, #56]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #24]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #32]
	LDRD	r6, r7, [r0, #40]
	STRD	r4, r5, [r0, #24]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #24]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #24]
	MOV	r10, r8
	MOV	r11, r9
	/* Round 5 */
	LDRD	r4, r5, [r0, #56]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #16]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #16]
	LDRD	r4, r5, [r0, #56]
	LDRD	r6, r7, [r0]
	LDRD	r8, r9, [r0, #8]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #16]
	LDRD	r8, r9, [sp, #40]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #40]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #48]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #16]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #24]
	STRD	r8, r9, [r0, #48]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #16]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #24]
	LDRD	r6, r7, [r0, #32]
	STRD	r4, r5, [r0, #16]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #16]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #16]
	MOV	r10, r8
	MOV	r11, r9
	/* Round 6 */
	LDRD	r4, r5, [r0, #48]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #8]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #8]
	LDRD	r4, r5, [r0, #48]
	LDRD	r6, r7, [r0, #56]
	LDRD	r8, r9, [r0]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #8]
	LDRD	r8, r9, [sp, #48]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #48]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #40]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #8]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #16]
	STRD	r8, r9, [r0, #40]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #8]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #16]
	LDRD	r6, r7, [r0, #24]
	STRD	r4, r5, [r0, #8]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #8]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #8]
	MOV	r10, r8
	MOV	r11, r9
	/* Round 7 */
	LDRD	r4, r5, [r0, #40]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0]
	LDRD	r4, r5, [r0, #40]
	LDRD	r6, r7, [r0, #48]
	LDRD	r8, r9, [r0, #56]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0]
	LDRD	r8, r9, [sp, #56]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #56]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #32]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #8]
	STRD	r8, r9, [r0, #32]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #8]
	LDRD	r6, r7, [r0, #16]
	STRD	r4, r5, [r0]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0]
	MOV	r10, r8
	MOV	r11, r9
	/* Round 8 */
	LDRD	r4, r5, [r0, #32]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #56]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #56]
	LDRD	r4, r5, [r0, #32]
	LDRD	r6, r7, [r0, #40]
	LDRD	r8, r9, [r0, #48]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #56]
	LDRD	r8, r9, [sp, #64]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #64]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #24]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #56]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0]
	STRD	r8, r9, [r0, #24]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #56]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0]
	LDRD	r6, r7, [r0, #8]
	STRD	r4, r5, [r0, #56]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #56]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #56]
	MOV	r10, r8
	MOV	r11, r9
	/* Round 9 */
	LDRD	r4, r5, [r0, #24]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #48]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #48]
	LDRD	r4, r5, [r0, #24]
	LDRD	r6, r7, [r0, #32]
	LDRD	r8, r9, [r0, #40]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #48]
	LDRD	r8, r9, [sp, #72]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #72]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #16]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #48]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #56]
	STRD	r8, r9, [r0, #16]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #48]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #56]
	LDRD	r6, r7, [r0]
	STRD	r4, r5, [r0, #48]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #48]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #48]
	MOV	r10, r8
	MOV	r11, r9
	/* Round 10 */
	LDRD	r4, r5, [r0, #16]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #40]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #40]
	LDRD	r4, r5, [r0, #16]
	LDRD	r6, r7, [r0, #24]
	LDRD	r8, r9, [r0, #32]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #40]
	LDRD	r8, r9, [sp, #80]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #80]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #8]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #40]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #48]
	STRD	r8, r9, [r0, #8]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #40]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #48]
	LDRD	r6, r7, [r0, #56]
	STRD	r4, r5, [r0, #40]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #40]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #40]
	MOV	r10, r8
	MOV	r11, r9
	/* Round 11 */
	LDRD	r4, r5, [r0, #8]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #32]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #32]
	LDRD	r4, r5, [r0, #8]
	LDRD	r6, r7, [r0, #16]
	LDRD	r8, r9, [r0, #24]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #32]
	LDRD	r8, r9, [sp, #88]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #88]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #32]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #40]
	STRD	r8, r9, [r0]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #32]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #40]
	LDRD	r6, r7, [r0, #48]
	STRD	r4, r5, [r0, #32]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #32]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #32]
	MOV	r10, r8
	MOV	r11, r9
	/* Round 12 */
	LDRD	r4, r5, [r0]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #24]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #24]
	LDRD	r4, r5, [r0]
	LDRD	r6, r7, [r0, #8]
	LDRD	r8, r9, [r0, #16]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #24]
	LDRD	r8, r9, [sp, #96]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #96]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #56]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #24]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #32]
	STRD	r8, r9, [r0, #56]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #24]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #32]
	LDRD	r6, r7, [r0, #40]
	STRD	r4, r5, [r0, #24]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #24]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #24]
	MOV	r10, r8
	MOV	r11, r9
	/* Round 13 */
	LDRD	r4, r5, [r0, #56]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #16]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #16]
	LDRD	r4, r5, [r0, #56]
	LDRD	r6, r7, [r0]
	LDRD	r8, r9, [r0, #8]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #16]
	LDRD	r8, r9, [sp, #104]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #104]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #48]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #16]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #24]
	STRD	r8, r9, [r0, #48]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #16]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #24]
	LDRD	r6, r7, [r0, #32]
	STRD	r4, r5, [r0, #16]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #16]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #16]
	MOV	r10, r8
	MOV	r11, r9
	/* Round 14 */
	LDRD	r4, r5, [r0, #48]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0, #8]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #8]
	LDRD	r4, r5, [r0, #48]
	LDRD	r6, r7, [r0, #56]
	LDRD	r8, r9, [r0]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0, #8]
	LDRD	r8, r9, [sp, #112]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #112]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #40]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0, #8]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #16]
	STRD	r8, r9, [r0, #40]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0, #8]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #16]
	LDRD	r6, r7, [r0, #24]
	STRD	r4, r5, [r0, #8]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0, #8]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0, #8]
	MOV	r10, r8
	MOV	r11, r9
	/* Round 15 */
	LDRD	r4, r5, [r0, #40]
	LSRS	r6, r4, #14
	LSRS	r7, r5, #14
	ORR	r7, r7, r4, LSL #18
	ORR	r6, r6, r5, LSL #18
	LSRS	r8, r4, #18
	LSRS	r9, r5, #18
	ORR	r9, r9, r4, LSL #14
	ORR	r8, r8, r5, LSL #14
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #23
	LSLS	r9, r5, #23
	ORR	r9, r9, r4, LSR #9
	ORR	r8, r8, r5, LSR #9
	LDRD	r4, r5, [r0]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0]
	LDRD	r4, r5, [r0, #40]
	LDRD	r6, r7, [r0, #48]
	LDRD	r8, r9, [r0, #56]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	AND	r6, r6, r4
	AND	r7, r7, r5
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LDRD	r4, r5, [r0]
	LDRD	r8, r9, [sp, #120]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r6, r7, [r3, #120]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	LDRD	r8, r9, [r0, #32]
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	STRD	r4, r5, [r0]
	ADDS	r8, r8, r4
	ADC	r9, r9, r5
	LDRD	r4, r5, [r0, #8]
	STRD	r8, r9, [r0, #32]
	LSRS	r6, r4, #28
	LSRS	r7, r5, #28
	ORR	r7, r7, r4, LSL #4
	ORR	r6, r6, r5, LSL #4
	LSLS	r8, r4, #30
	LSLS	r9, r5, #30
	ORR	r9, r9, r4, LSR #2
	ORR	r8, r8, r5, LSR #2
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	LSLS	r8, r4, #25
	LSLS	r9, r5, #25
	ORR	r9, r9, r4, LSR #7
	ORR	r8, r8, r5, LSR #7
	LDRD	r4, r5, [r0]
	EOR	r6, r6, r8
	EOR	r7, r7, r9
	ADDS	r4, r4, r6
	ADC	r5, r5, r7
	LDRD	r8, r9, [r0, #8]
	LDRD	r6, r7, [r0, #16]
	STRD	r4, r5, [r0]
	EOR	r8, r8, r6
	EOR	r9, r9, r7
	AND	r10, r10, r8
	AND	r11, r11, r9
	EOR	r10, r10, r6
	EOR	r11, r11, r7
	LDRD	r6, r7, [r0]
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r6, r7, [r0]
	MOV	r10, r8
	MOV	r11, r9
	/* Add in digest from start */
	LDRD	r4, r5, [r0]
	LDRD	r6, r7, [r0, #8]
	LDRD	r8, r9, [sp, #128]
	LDRD	r10, r11, [sp, #136]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r4, r5, [r0]
	STRD	r6, r7, [r0, #8]
	STRD	r4, r5, [sp, #128]
	STRD	r6, r7, [sp, #136]
	LDRD	r4, r5, [r0, #16]
	LDRD	r6, r7, [r0, #24]
	LDRD	r8, r9, [sp, #144]
	LDRD	r10, r11, [sp, #152]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r4, r5, [r0, #16]
	STRD	r6, r7, [r0, #24]
	STRD	r4, r5, [sp, #144]
	STRD	r6, r7, [sp, #152]
	LDRD	r4, r5, [r0, #32]
	LDRD	r6, r7, [r0, #40]
	LDRD	r8, r9, [sp, #160]
	LDRD	r10, r11, [sp, #168]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r4, r5, [r0, #32]
	STRD	r6, r7, [r0, #40]
	STRD	r4, r5, [sp, #160]
	STRD	r6, r7, [sp, #168]
	LDRD	r4, r5, [r0, #48]
	LDRD	r6, r7, [r0, #56]
	LDRD	r8, r9, [sp, #176]
	LDRD	r10, r11, [sp, #184]
	ADDS	r4, r4, r8
	ADC	r5, r5, r9
	ADDS	r6, r6, r10
	ADC	r7, r7, r11
	STRD	r4, r5, [r0, #48]
	STRD	r6, r7, [r0, #56]
	STRD	r4, r5, [sp, #176]
	STRD	r6, r7, [sp, #184]
	SUBS	r2, r2, #0x80
	SUB	r3, r3, #0x200
	ADD	r1, r1, #0x80
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_SHA512_transform_len_begin
#else
	BNE.W	L_SHA512_transform_len_begin
#endif
	EOR	r0, r0, r0
	ADD	sp, sp, #0xc0
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 5021 */
	.size	Transform_Sha512_Len,.-Transform_Sha512_Len
#endif /* WOLFSSL_ARMASM_NO_NEON */
#endif /* WOLFSSL_SHA512 */
#endif /* !__aarch64__ && __thumb__ */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section        .note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
