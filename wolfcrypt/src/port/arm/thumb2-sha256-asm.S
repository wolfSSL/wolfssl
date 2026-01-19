/* thumb2-sha256-asm
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
 *   ruby ./sha2/sha256.rb thumb2 ../wolfssl/wolfcrypt/src/port/arm/thumb2-sha256-asm.S
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif /* HAVE_CONFIG_H */
#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_ARMASM
#ifdef WOLFSSL_ARMASM_THUMB2
#ifndef WOLFSSL_ARMASM_INLINE
	.thumb
	.syntax unified
#ifndef NO_SHA256
#ifdef WOLFSSL_ARMASM_NO_NEON
	.text
	.type	L_SHA256_transform_len_k, %object
	.size	L_SHA256_transform_len_k, 256
	.align	4
L_SHA256_transform_len_k:
	.word	0x428a2f98
	.word	0x71374491
	.word	0xb5c0fbcf
	.word	0xe9b5dba5
	.word	0x3956c25b
	.word	0x59f111f1
	.word	0x923f82a4
	.word	0xab1c5ed5
	.word	0xd807aa98
	.word	0x12835b01
	.word	0x243185be
	.word	0x550c7dc3
	.word	0x72be5d74
	.word	0x80deb1fe
	.word	0x9bdc06a7
	.word	0xc19bf174
	.word	0xe49b69c1
	.word	0xefbe4786
	.word	0xfc19dc6
	.word	0x240ca1cc
	.word	0x2de92c6f
	.word	0x4a7484aa
	.word	0x5cb0a9dc
	.word	0x76f988da
	.word	0x983e5152
	.word	0xa831c66d
	.word	0xb00327c8
	.word	0xbf597fc7
	.word	0xc6e00bf3
	.word	0xd5a79147
	.word	0x6ca6351
	.word	0x14292967
	.word	0x27b70a85
	.word	0x2e1b2138
	.word	0x4d2c6dfc
	.word	0x53380d13
	.word	0x650a7354
	.word	0x766a0abb
	.word	0x81c2c92e
	.word	0x92722c85
	.word	0xa2bfe8a1
	.word	0xa81a664b
	.word	0xc24b8b70
	.word	0xc76c51a3
	.word	0xd192e819
	.word	0xd6990624
	.word	0xf40e3585
	.word	0x106aa070
	.word	0x19a4c116
	.word	0x1e376c08
	.word	0x2748774c
	.word	0x34b0bcb5
	.word	0x391c0cb3
	.word	0x4ed8aa4a
	.word	0x5b9cca4f
	.word	0x682e6ff3
	.word	0x748f82ee
	.word	0x78a5636f
	.word	0x84c87814
	.word	0x8cc70208
	.word	0x90befffa
	.word	0xa4506ceb
	.word	0xbef9a3f7
	.word	0xc67178f2
	.text
	.align	4
	.globl	Transform_Sha256_Len
	.type	Transform_Sha256_Len, %function
Transform_Sha256_Len:
	PUSH	{r4, r5, r6, r7, r8, r9, r10, r11, lr}
	SUB	sp, sp, #0xc0
	ADR	r3, L_SHA256_transform_len_k
	/* Copy digest to add in at end */
	LDRD	r4, r5, [r0]
	LDRD	r6, r7, [r0, #8]
	LDRD	r8, r9, [r0, #16]
	LDRD	r10, r11, [r0, #24]
	STRD	r4, r5, [sp, #64]
	STRD	r6, r7, [sp, #72]
	STRD	r8, r9, [sp, #80]
	STRD	r10, r11, [sp, #88]
	/* Start of loop processing a block */
L_SHA256_transform_len_begin:
	/* Load, Reverse and Store W - 64 bytes */
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
	STRD	r4, r5, [sp]
	STRD	r6, r7, [sp, #8]
	STRD	r8, r9, [sp, #16]
	STRD	r10, r11, [sp, #24]
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
	STRD	r4, r5, [sp, #32]
	STRD	r6, r7, [sp, #40]
	STRD	r8, r9, [sp, #48]
	STRD	r10, r11, [sp, #56]
	LDR	r11, [r0, #4]
	LDR	r4, [r0, #8]
	EOR	r11, r11, r4
	MOV	r12, #0x3
	/* Start of 16 rounds */
L_SHA256_transform_len_start:
	/* Round 0 */
	LDR	r5, [r0, #16]
	LDR	r6, [r0, #20]
	LDR	r7, [r0, #24]
	LDR	r9, [r0, #28]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp]
	LDR	r6, [r3]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0]
	LDR	r6, [r0, #4]
	LDR	r7, [r0, #8]
	LDR	r8, [r0, #12]
	ROR	r4, r5, #2
	EOR	r10, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r11, r11, r10
	EOR	r4, r4, r5, ROR #22
	EOR	r11, r11, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r11
	STR	r8, [r0, #12]
	STR	r9, [r0, #28]
	/* Calc new W[0] */
	LDR	r6, [sp, #56]
	LDR	r7, [sp, #36]
	LDR	r8, [sp, #4]
	LDR	r9, [sp]
	ROR	r4, r6, #17
	ROR	r5, r8, #7
	EOR	r4, r4, r6, ROR #19
	EOR	r5, r5, r8, ROR #18
	EOR	r4, r4, r6, LSR #10
	EOR	r5, r5, r8, LSR #3
	ADD	r9, r9, r7
	ADD	r4, r4, r5
	ADD	r9, r9, r4
	STR	r9, [sp]
	/* Round 1 */
	LDR	r5, [r0, #12]
	LDR	r6, [r0, #16]
	LDR	r7, [r0, #20]
	LDR	r9, [r0, #24]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #4]
	LDR	r6, [r3, #4]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #28]
	LDR	r6, [r0]
	LDR	r7, [r0, #4]
	LDR	r8, [r0, #8]
	ROR	r4, r5, #2
	EOR	r11, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r10, r10, r11
	EOR	r4, r4, r5, ROR #22
	EOR	r10, r10, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r10
	STR	r8, [r0, #8]
	STR	r9, [r0, #24]
	/* Calc new W[1] */
	LDR	r6, [sp, #60]
	LDR	r7, [sp, #40]
	LDR	r8, [sp, #8]
	LDR	r9, [sp, #4]
	ROR	r4, r6, #17
	ROR	r5, r8, #7
	EOR	r4, r4, r6, ROR #19
	EOR	r5, r5, r8, ROR #18
	EOR	r4, r4, r6, LSR #10
	EOR	r5, r5, r8, LSR #3
	ADD	r9, r9, r7
	ADD	r4, r4, r5
	ADD	r9, r9, r4
	STR	r9, [sp, #4]
	/* Round 2 */
	LDR	r5, [r0, #8]
	LDR	r6, [r0, #12]
	LDR	r7, [r0, #16]
	LDR	r9, [r0, #20]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #8]
	LDR	r6, [r3, #8]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #24]
	LDR	r6, [r0, #28]
	LDR	r7, [r0]
	LDR	r8, [r0, #4]
	ROR	r4, r5, #2
	EOR	r10, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r11, r11, r10
	EOR	r4, r4, r5, ROR #22
	EOR	r11, r11, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r11
	STR	r8, [r0, #4]
	STR	r9, [r0, #20]
	/* Calc new W[2] */
	LDR	r6, [sp]
	LDR	r7, [sp, #44]
	LDR	r8, [sp, #12]
	LDR	r9, [sp, #8]
	ROR	r4, r6, #17
	ROR	r5, r8, #7
	EOR	r4, r4, r6, ROR #19
	EOR	r5, r5, r8, ROR #18
	EOR	r4, r4, r6, LSR #10
	EOR	r5, r5, r8, LSR #3
	ADD	r9, r9, r7
	ADD	r4, r4, r5
	ADD	r9, r9, r4
	STR	r9, [sp, #8]
	/* Round 3 */
	LDR	r5, [r0, #4]
	LDR	r6, [r0, #8]
	LDR	r7, [r0, #12]
	LDR	r9, [r0, #16]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #12]
	LDR	r6, [r3, #12]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #20]
	LDR	r6, [r0, #24]
	LDR	r7, [r0, #28]
	LDR	r8, [r0]
	ROR	r4, r5, #2
	EOR	r11, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r10, r10, r11
	EOR	r4, r4, r5, ROR #22
	EOR	r10, r10, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r10
	STR	r8, [r0]
	STR	r9, [r0, #16]
	/* Calc new W[3] */
	LDR	r6, [sp, #4]
	LDR	r7, [sp, #48]
	LDR	r8, [sp, #16]
	LDR	r9, [sp, #12]
	ROR	r4, r6, #17
	ROR	r5, r8, #7
	EOR	r4, r4, r6, ROR #19
	EOR	r5, r5, r8, ROR #18
	EOR	r4, r4, r6, LSR #10
	EOR	r5, r5, r8, LSR #3
	ADD	r9, r9, r7
	ADD	r4, r4, r5
	ADD	r9, r9, r4
	STR	r9, [sp, #12]
	/* Round 4 */
	LDR	r5, [r0]
	LDR	r6, [r0, #4]
	LDR	r7, [r0, #8]
	LDR	r9, [r0, #12]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #16]
	LDR	r6, [r3, #16]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #16]
	LDR	r6, [r0, #20]
	LDR	r7, [r0, #24]
	LDR	r8, [r0, #28]
	ROR	r4, r5, #2
	EOR	r10, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r11, r11, r10
	EOR	r4, r4, r5, ROR #22
	EOR	r11, r11, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r11
	STR	r8, [r0, #28]
	STR	r9, [r0, #12]
	/* Calc new W[4] */
	LDR	r6, [sp, #8]
	LDR	r7, [sp, #52]
	LDR	r8, [sp, #20]
	LDR	r9, [sp, #16]
	ROR	r4, r6, #17
	ROR	r5, r8, #7
	EOR	r4, r4, r6, ROR #19
	EOR	r5, r5, r8, ROR #18
	EOR	r4, r4, r6, LSR #10
	EOR	r5, r5, r8, LSR #3
	ADD	r9, r9, r7
	ADD	r4, r4, r5
	ADD	r9, r9, r4
	STR	r9, [sp, #16]
	/* Round 5 */
	LDR	r5, [r0, #28]
	LDR	r6, [r0]
	LDR	r7, [r0, #4]
	LDR	r9, [r0, #8]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #20]
	LDR	r6, [r3, #20]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #12]
	LDR	r6, [r0, #16]
	LDR	r7, [r0, #20]
	LDR	r8, [r0, #24]
	ROR	r4, r5, #2
	EOR	r11, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r10, r10, r11
	EOR	r4, r4, r5, ROR #22
	EOR	r10, r10, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r10
	STR	r8, [r0, #24]
	STR	r9, [r0, #8]
	/* Calc new W[5] */
	LDR	r6, [sp, #12]
	LDR	r7, [sp, #56]
	LDR	r8, [sp, #24]
	LDR	r9, [sp, #20]
	ROR	r4, r6, #17
	ROR	r5, r8, #7
	EOR	r4, r4, r6, ROR #19
	EOR	r5, r5, r8, ROR #18
	EOR	r4, r4, r6, LSR #10
	EOR	r5, r5, r8, LSR #3
	ADD	r9, r9, r7
	ADD	r4, r4, r5
	ADD	r9, r9, r4
	STR	r9, [sp, #20]
	/* Round 6 */
	LDR	r5, [r0, #24]
	LDR	r6, [r0, #28]
	LDR	r7, [r0]
	LDR	r9, [r0, #4]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #24]
	LDR	r6, [r3, #24]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #8]
	LDR	r6, [r0, #12]
	LDR	r7, [r0, #16]
	LDR	r8, [r0, #20]
	ROR	r4, r5, #2
	EOR	r10, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r11, r11, r10
	EOR	r4, r4, r5, ROR #22
	EOR	r11, r11, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r11
	STR	r8, [r0, #20]
	STR	r9, [r0, #4]
	/* Calc new W[6] */
	LDR	r6, [sp, #16]
	LDR	r7, [sp, #60]
	LDR	r8, [sp, #28]
	LDR	r9, [sp, #24]
	ROR	r4, r6, #17
	ROR	r5, r8, #7
	EOR	r4, r4, r6, ROR #19
	EOR	r5, r5, r8, ROR #18
	EOR	r4, r4, r6, LSR #10
	EOR	r5, r5, r8, LSR #3
	ADD	r9, r9, r7
	ADD	r4, r4, r5
	ADD	r9, r9, r4
	STR	r9, [sp, #24]
	/* Round 7 */
	LDR	r5, [r0, #20]
	LDR	r6, [r0, #24]
	LDR	r7, [r0, #28]
	LDR	r9, [r0]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #28]
	LDR	r6, [r3, #28]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #4]
	LDR	r6, [r0, #8]
	LDR	r7, [r0, #12]
	LDR	r8, [r0, #16]
	ROR	r4, r5, #2
	EOR	r11, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r10, r10, r11
	EOR	r4, r4, r5, ROR #22
	EOR	r10, r10, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r10
	STR	r8, [r0, #16]
	STR	r9, [r0]
	/* Calc new W[7] */
	LDR	r6, [sp, #20]
	LDR	r7, [sp]
	LDR	r8, [sp, #32]
	LDR	r9, [sp, #28]
	ROR	r4, r6, #17
	ROR	r5, r8, #7
	EOR	r4, r4, r6, ROR #19
	EOR	r5, r5, r8, ROR #18
	EOR	r4, r4, r6, LSR #10
	EOR	r5, r5, r8, LSR #3
	ADD	r9, r9, r7
	ADD	r4, r4, r5
	ADD	r9, r9, r4
	STR	r9, [sp, #28]
	/* Round 8 */
	LDR	r5, [r0, #16]
	LDR	r6, [r0, #20]
	LDR	r7, [r0, #24]
	LDR	r9, [r0, #28]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #32]
	LDR	r6, [r3, #32]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0]
	LDR	r6, [r0, #4]
	LDR	r7, [r0, #8]
	LDR	r8, [r0, #12]
	ROR	r4, r5, #2
	EOR	r10, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r11, r11, r10
	EOR	r4, r4, r5, ROR #22
	EOR	r11, r11, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r11
	STR	r8, [r0, #12]
	STR	r9, [r0, #28]
	/* Calc new W[8] */
	LDR	r6, [sp, #24]
	LDR	r7, [sp, #4]
	LDR	r8, [sp, #36]
	LDR	r9, [sp, #32]
	ROR	r4, r6, #17
	ROR	r5, r8, #7
	EOR	r4, r4, r6, ROR #19
	EOR	r5, r5, r8, ROR #18
	EOR	r4, r4, r6, LSR #10
	EOR	r5, r5, r8, LSR #3
	ADD	r9, r9, r7
	ADD	r4, r4, r5
	ADD	r9, r9, r4
	STR	r9, [sp, #32]
	/* Round 9 */
	LDR	r5, [r0, #12]
	LDR	r6, [r0, #16]
	LDR	r7, [r0, #20]
	LDR	r9, [r0, #24]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #36]
	LDR	r6, [r3, #36]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #28]
	LDR	r6, [r0]
	LDR	r7, [r0, #4]
	LDR	r8, [r0, #8]
	ROR	r4, r5, #2
	EOR	r11, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r10, r10, r11
	EOR	r4, r4, r5, ROR #22
	EOR	r10, r10, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r10
	STR	r8, [r0, #8]
	STR	r9, [r0, #24]
	/* Calc new W[9] */
	LDR	r6, [sp, #28]
	LDR	r7, [sp, #8]
	LDR	r8, [sp, #40]
	LDR	r9, [sp, #36]
	ROR	r4, r6, #17
	ROR	r5, r8, #7
	EOR	r4, r4, r6, ROR #19
	EOR	r5, r5, r8, ROR #18
	EOR	r4, r4, r6, LSR #10
	EOR	r5, r5, r8, LSR #3
	ADD	r9, r9, r7
	ADD	r4, r4, r5
	ADD	r9, r9, r4
	STR	r9, [sp, #36]
	/* Round 10 */
	LDR	r5, [r0, #8]
	LDR	r6, [r0, #12]
	LDR	r7, [r0, #16]
	LDR	r9, [r0, #20]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #40]
	LDR	r6, [r3, #40]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #24]
	LDR	r6, [r0, #28]
	LDR	r7, [r0]
	LDR	r8, [r0, #4]
	ROR	r4, r5, #2
	EOR	r10, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r11, r11, r10
	EOR	r4, r4, r5, ROR #22
	EOR	r11, r11, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r11
	STR	r8, [r0, #4]
	STR	r9, [r0, #20]
	/* Calc new W[10] */
	LDR	r6, [sp, #32]
	LDR	r7, [sp, #12]
	LDR	r8, [sp, #44]
	LDR	r9, [sp, #40]
	ROR	r4, r6, #17
	ROR	r5, r8, #7
	EOR	r4, r4, r6, ROR #19
	EOR	r5, r5, r8, ROR #18
	EOR	r4, r4, r6, LSR #10
	EOR	r5, r5, r8, LSR #3
	ADD	r9, r9, r7
	ADD	r4, r4, r5
	ADD	r9, r9, r4
	STR	r9, [sp, #40]
	/* Round 11 */
	LDR	r5, [r0, #4]
	LDR	r6, [r0, #8]
	LDR	r7, [r0, #12]
	LDR	r9, [r0, #16]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #44]
	LDR	r6, [r3, #44]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #20]
	LDR	r6, [r0, #24]
	LDR	r7, [r0, #28]
	LDR	r8, [r0]
	ROR	r4, r5, #2
	EOR	r11, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r10, r10, r11
	EOR	r4, r4, r5, ROR #22
	EOR	r10, r10, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r10
	STR	r8, [r0]
	STR	r9, [r0, #16]
	/* Calc new W[11] */
	LDR	r6, [sp, #36]
	LDR	r7, [sp, #16]
	LDR	r8, [sp, #48]
	LDR	r9, [sp, #44]
	ROR	r4, r6, #17
	ROR	r5, r8, #7
	EOR	r4, r4, r6, ROR #19
	EOR	r5, r5, r8, ROR #18
	EOR	r4, r4, r6, LSR #10
	EOR	r5, r5, r8, LSR #3
	ADD	r9, r9, r7
	ADD	r4, r4, r5
	ADD	r9, r9, r4
	STR	r9, [sp, #44]
	/* Round 12 */
	LDR	r5, [r0]
	LDR	r6, [r0, #4]
	LDR	r7, [r0, #8]
	LDR	r9, [r0, #12]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #48]
	LDR	r6, [r3, #48]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #16]
	LDR	r6, [r0, #20]
	LDR	r7, [r0, #24]
	LDR	r8, [r0, #28]
	ROR	r4, r5, #2
	EOR	r10, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r11, r11, r10
	EOR	r4, r4, r5, ROR #22
	EOR	r11, r11, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r11
	STR	r8, [r0, #28]
	STR	r9, [r0, #12]
	/* Calc new W[12] */
	LDR	r6, [sp, #40]
	LDR	r7, [sp, #20]
	LDR	r8, [sp, #52]
	LDR	r9, [sp, #48]
	ROR	r4, r6, #17
	ROR	r5, r8, #7
	EOR	r4, r4, r6, ROR #19
	EOR	r5, r5, r8, ROR #18
	EOR	r4, r4, r6, LSR #10
	EOR	r5, r5, r8, LSR #3
	ADD	r9, r9, r7
	ADD	r4, r4, r5
	ADD	r9, r9, r4
	STR	r9, [sp, #48]
	/* Round 13 */
	LDR	r5, [r0, #28]
	LDR	r6, [r0]
	LDR	r7, [r0, #4]
	LDR	r9, [r0, #8]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #52]
	LDR	r6, [r3, #52]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #12]
	LDR	r6, [r0, #16]
	LDR	r7, [r0, #20]
	LDR	r8, [r0, #24]
	ROR	r4, r5, #2
	EOR	r11, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r10, r10, r11
	EOR	r4, r4, r5, ROR #22
	EOR	r10, r10, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r10
	STR	r8, [r0, #24]
	STR	r9, [r0, #8]
	/* Calc new W[13] */
	LDR	r6, [sp, #44]
	LDR	r7, [sp, #24]
	LDR	r8, [sp, #56]
	LDR	r9, [sp, #52]
	ROR	r4, r6, #17
	ROR	r5, r8, #7
	EOR	r4, r4, r6, ROR #19
	EOR	r5, r5, r8, ROR #18
	EOR	r4, r4, r6, LSR #10
	EOR	r5, r5, r8, LSR #3
	ADD	r9, r9, r7
	ADD	r4, r4, r5
	ADD	r9, r9, r4
	STR	r9, [sp, #52]
	/* Round 14 */
	LDR	r5, [r0, #24]
	LDR	r6, [r0, #28]
	LDR	r7, [r0]
	LDR	r9, [r0, #4]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #56]
	LDR	r6, [r3, #56]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #8]
	LDR	r6, [r0, #12]
	LDR	r7, [r0, #16]
	LDR	r8, [r0, #20]
	ROR	r4, r5, #2
	EOR	r10, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r11, r11, r10
	EOR	r4, r4, r5, ROR #22
	EOR	r11, r11, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r11
	STR	r8, [r0, #20]
	STR	r9, [r0, #4]
	/* Calc new W[14] */
	LDR	r6, [sp, #48]
	LDR	r7, [sp, #28]
	LDR	r8, [sp, #60]
	LDR	r9, [sp, #56]
	ROR	r4, r6, #17
	ROR	r5, r8, #7
	EOR	r4, r4, r6, ROR #19
	EOR	r5, r5, r8, ROR #18
	EOR	r4, r4, r6, LSR #10
	EOR	r5, r5, r8, LSR #3
	ADD	r9, r9, r7
	ADD	r4, r4, r5
	ADD	r9, r9, r4
	STR	r9, [sp, #56]
	/* Round 15 */
	LDR	r5, [r0, #20]
	LDR	r6, [r0, #24]
	LDR	r7, [r0, #28]
	LDR	r9, [r0]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #60]
	LDR	r6, [r3, #60]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #4]
	LDR	r6, [r0, #8]
	LDR	r7, [r0, #12]
	LDR	r8, [r0, #16]
	ROR	r4, r5, #2
	EOR	r11, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r10, r10, r11
	EOR	r4, r4, r5, ROR #22
	EOR	r10, r10, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r10
	STR	r8, [r0, #16]
	STR	r9, [r0]
	/* Calc new W[15] */
	LDR	r6, [sp, #52]
	LDR	r7, [sp, #32]
	LDR	r8, [sp]
	LDR	r9, [sp, #60]
	ROR	r4, r6, #17
	ROR	r5, r8, #7
	EOR	r4, r4, r6, ROR #19
	EOR	r5, r5, r8, ROR #18
	EOR	r4, r4, r6, LSR #10
	EOR	r5, r5, r8, LSR #3
	ADD	r9, r9, r7
	ADD	r4, r4, r5
	ADD	r9, r9, r4
	STR	r9, [sp, #60]
	ADD	r3, r3, #0x40
	SUBS	r12, r12, #0x1
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_SHA256_transform_len_start
#else
	BNE.W	L_SHA256_transform_len_start
#endif
	/* Round 0 */
	LDR	r5, [r0, #16]
	LDR	r6, [r0, #20]
	LDR	r7, [r0, #24]
	LDR	r9, [r0, #28]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp]
	LDR	r6, [r3]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0]
	LDR	r6, [r0, #4]
	LDR	r7, [r0, #8]
	LDR	r8, [r0, #12]
	ROR	r4, r5, #2
	EOR	r10, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r11, r11, r10
	EOR	r4, r4, r5, ROR #22
	EOR	r11, r11, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r11
	STR	r8, [r0, #12]
	STR	r9, [r0, #28]
	/* Round 1 */
	LDR	r5, [r0, #12]
	LDR	r6, [r0, #16]
	LDR	r7, [r0, #20]
	LDR	r9, [r0, #24]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #4]
	LDR	r6, [r3, #4]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #28]
	LDR	r6, [r0]
	LDR	r7, [r0, #4]
	LDR	r8, [r0, #8]
	ROR	r4, r5, #2
	EOR	r11, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r10, r10, r11
	EOR	r4, r4, r5, ROR #22
	EOR	r10, r10, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r10
	STR	r8, [r0, #8]
	STR	r9, [r0, #24]
	/* Round 2 */
	LDR	r5, [r0, #8]
	LDR	r6, [r0, #12]
	LDR	r7, [r0, #16]
	LDR	r9, [r0, #20]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #8]
	LDR	r6, [r3, #8]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #24]
	LDR	r6, [r0, #28]
	LDR	r7, [r0]
	LDR	r8, [r0, #4]
	ROR	r4, r5, #2
	EOR	r10, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r11, r11, r10
	EOR	r4, r4, r5, ROR #22
	EOR	r11, r11, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r11
	STR	r8, [r0, #4]
	STR	r9, [r0, #20]
	/* Round 3 */
	LDR	r5, [r0, #4]
	LDR	r6, [r0, #8]
	LDR	r7, [r0, #12]
	LDR	r9, [r0, #16]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #12]
	LDR	r6, [r3, #12]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #20]
	LDR	r6, [r0, #24]
	LDR	r7, [r0, #28]
	LDR	r8, [r0]
	ROR	r4, r5, #2
	EOR	r11, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r10, r10, r11
	EOR	r4, r4, r5, ROR #22
	EOR	r10, r10, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r10
	STR	r8, [r0]
	STR	r9, [r0, #16]
	/* Round 4 */
	LDR	r5, [r0]
	LDR	r6, [r0, #4]
	LDR	r7, [r0, #8]
	LDR	r9, [r0, #12]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #16]
	LDR	r6, [r3, #16]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #16]
	LDR	r6, [r0, #20]
	LDR	r7, [r0, #24]
	LDR	r8, [r0, #28]
	ROR	r4, r5, #2
	EOR	r10, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r11, r11, r10
	EOR	r4, r4, r5, ROR #22
	EOR	r11, r11, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r11
	STR	r8, [r0, #28]
	STR	r9, [r0, #12]
	/* Round 5 */
	LDR	r5, [r0, #28]
	LDR	r6, [r0]
	LDR	r7, [r0, #4]
	LDR	r9, [r0, #8]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #20]
	LDR	r6, [r3, #20]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #12]
	LDR	r6, [r0, #16]
	LDR	r7, [r0, #20]
	LDR	r8, [r0, #24]
	ROR	r4, r5, #2
	EOR	r11, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r10, r10, r11
	EOR	r4, r4, r5, ROR #22
	EOR	r10, r10, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r10
	STR	r8, [r0, #24]
	STR	r9, [r0, #8]
	/* Round 6 */
	LDR	r5, [r0, #24]
	LDR	r6, [r0, #28]
	LDR	r7, [r0]
	LDR	r9, [r0, #4]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #24]
	LDR	r6, [r3, #24]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #8]
	LDR	r6, [r0, #12]
	LDR	r7, [r0, #16]
	LDR	r8, [r0, #20]
	ROR	r4, r5, #2
	EOR	r10, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r11, r11, r10
	EOR	r4, r4, r5, ROR #22
	EOR	r11, r11, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r11
	STR	r8, [r0, #20]
	STR	r9, [r0, #4]
	/* Round 7 */
	LDR	r5, [r0, #20]
	LDR	r6, [r0, #24]
	LDR	r7, [r0, #28]
	LDR	r9, [r0]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #28]
	LDR	r6, [r3, #28]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #4]
	LDR	r6, [r0, #8]
	LDR	r7, [r0, #12]
	LDR	r8, [r0, #16]
	ROR	r4, r5, #2
	EOR	r11, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r10, r10, r11
	EOR	r4, r4, r5, ROR #22
	EOR	r10, r10, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r10
	STR	r8, [r0, #16]
	STR	r9, [r0]
	/* Round 8 */
	LDR	r5, [r0, #16]
	LDR	r6, [r0, #20]
	LDR	r7, [r0, #24]
	LDR	r9, [r0, #28]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #32]
	LDR	r6, [r3, #32]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0]
	LDR	r6, [r0, #4]
	LDR	r7, [r0, #8]
	LDR	r8, [r0, #12]
	ROR	r4, r5, #2
	EOR	r10, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r11, r11, r10
	EOR	r4, r4, r5, ROR #22
	EOR	r11, r11, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r11
	STR	r8, [r0, #12]
	STR	r9, [r0, #28]
	/* Round 9 */
	LDR	r5, [r0, #12]
	LDR	r6, [r0, #16]
	LDR	r7, [r0, #20]
	LDR	r9, [r0, #24]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #36]
	LDR	r6, [r3, #36]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #28]
	LDR	r6, [r0]
	LDR	r7, [r0, #4]
	LDR	r8, [r0, #8]
	ROR	r4, r5, #2
	EOR	r11, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r10, r10, r11
	EOR	r4, r4, r5, ROR #22
	EOR	r10, r10, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r10
	STR	r8, [r0, #8]
	STR	r9, [r0, #24]
	/* Round 10 */
	LDR	r5, [r0, #8]
	LDR	r6, [r0, #12]
	LDR	r7, [r0, #16]
	LDR	r9, [r0, #20]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #40]
	LDR	r6, [r3, #40]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #24]
	LDR	r6, [r0, #28]
	LDR	r7, [r0]
	LDR	r8, [r0, #4]
	ROR	r4, r5, #2
	EOR	r10, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r11, r11, r10
	EOR	r4, r4, r5, ROR #22
	EOR	r11, r11, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r11
	STR	r8, [r0, #4]
	STR	r9, [r0, #20]
	/* Round 11 */
	LDR	r5, [r0, #4]
	LDR	r6, [r0, #8]
	LDR	r7, [r0, #12]
	LDR	r9, [r0, #16]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #44]
	LDR	r6, [r3, #44]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #20]
	LDR	r6, [r0, #24]
	LDR	r7, [r0, #28]
	LDR	r8, [r0]
	ROR	r4, r5, #2
	EOR	r11, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r10, r10, r11
	EOR	r4, r4, r5, ROR #22
	EOR	r10, r10, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r10
	STR	r8, [r0]
	STR	r9, [r0, #16]
	/* Round 12 */
	LDR	r5, [r0]
	LDR	r6, [r0, #4]
	LDR	r7, [r0, #8]
	LDR	r9, [r0, #12]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #48]
	LDR	r6, [r3, #48]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #16]
	LDR	r6, [r0, #20]
	LDR	r7, [r0, #24]
	LDR	r8, [r0, #28]
	ROR	r4, r5, #2
	EOR	r10, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r11, r11, r10
	EOR	r4, r4, r5, ROR #22
	EOR	r11, r11, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r11
	STR	r8, [r0, #28]
	STR	r9, [r0, #12]
	/* Round 13 */
	LDR	r5, [r0, #28]
	LDR	r6, [r0]
	LDR	r7, [r0, #4]
	LDR	r9, [r0, #8]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #52]
	LDR	r6, [r3, #52]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #12]
	LDR	r6, [r0, #16]
	LDR	r7, [r0, #20]
	LDR	r8, [r0, #24]
	ROR	r4, r5, #2
	EOR	r11, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r10, r10, r11
	EOR	r4, r4, r5, ROR #22
	EOR	r10, r10, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r10
	STR	r8, [r0, #24]
	STR	r9, [r0, #8]
	/* Round 14 */
	LDR	r5, [r0, #24]
	LDR	r6, [r0, #28]
	LDR	r7, [r0]
	LDR	r9, [r0, #4]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #56]
	LDR	r6, [r3, #56]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #8]
	LDR	r6, [r0, #12]
	LDR	r7, [r0, #16]
	LDR	r8, [r0, #20]
	ROR	r4, r5, #2
	EOR	r10, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r11, r11, r10
	EOR	r4, r4, r5, ROR #22
	EOR	r11, r11, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r11
	STR	r8, [r0, #20]
	STR	r9, [r0, #4]
	/* Round 15 */
	LDR	r5, [r0, #20]
	LDR	r6, [r0, #24]
	LDR	r7, [r0, #28]
	LDR	r9, [r0]
	ROR	r4, r5, #6
	EOR	r6, r6, r7
	EOR	r4, r4, r5, ROR #11
	AND	r6, r6, r5
	EOR	r4, r4, r5, ROR #25
	EOR	r6, r6, r7
	ADD	r9, r9, r4
	ADD	r9, r9, r6
	LDR	r5, [sp, #60]
	LDR	r6, [r3, #60]
	ADD	r9, r9, r5
	ADD	r9, r9, r6
	LDR	r5, [r0, #4]
	LDR	r6, [r0, #8]
	LDR	r7, [r0, #12]
	LDR	r8, [r0, #16]
	ROR	r4, r5, #2
	EOR	r11, r5, r6
	EOR	r4, r4, r5, ROR #13
	AND	r10, r10, r11
	EOR	r4, r4, r5, ROR #22
	EOR	r10, r10, r6
	ADD	r8, r8, r9
	ADD	r9, r9, r4
	ADD	r9, r9, r10
	STR	r8, [r0, #16]
	STR	r9, [r0]
	/* Add in digest from start */
	LDRD	r4, r5, [r0]
	LDRD	r6, r7, [r0, #8]
	LDRD	r8, r9, [sp, #64]
	LDRD	r10, r11, [sp, #72]
	ADD	r4, r4, r8
	ADD	r5, r5, r9
	ADD	r6, r6, r10
	ADD	r7, r7, r11
	STRD	r4, r5, [r0]
	STRD	r6, r7, [r0, #8]
	STRD	r4, r5, [sp, #64]
	STRD	r6, r7, [sp, #72]
	LDRD	r4, r5, [r0, #16]
	LDRD	r6, r7, [r0, #24]
	LDRD	r8, r9, [sp, #80]
	LDRD	r10, r11, [sp, #88]
	ADD	r4, r4, r8
	ADD	r5, r5, r9
	ADD	r6, r6, r10
	ADD	r7, r7, r11
	STRD	r4, r5, [r0, #16]
	STRD	r6, r7, [r0, #24]
	STRD	r4, r5, [sp, #80]
	STRD	r6, r7, [sp, #88]
	SUBS	r2, r2, #0x40
	SUB	r3, r3, #0xc0
	ADD	r1, r1, #0x40
#if defined(__GNUC__) || defined(__ICCARM__) || defined(__IAR_SYSTEMS_ICC__)
	BNE	L_SHA256_transform_len_begin
#else
	BNE.W	L_SHA256_transform_len_begin
#endif
	ADD	sp, sp, #0xc0
	POP	{r4, r5, r6, r7, r8, r9, r10, r11, pc}
	/* Cycle Count = 1874 */
	.size	Transform_Sha256_Len,.-Transform_Sha256_Len
#endif /* WOLFSSL_ARMASM_NO_NEON */
#endif /* !NO_SHA256 */
#endif /* WOLFSSL_ARMASM_THUMB2 */
#endif /* WOLFSSL_ARMASM */

#if defined(__linux__) && defined(__ELF__)
.section        .note.GNU-stack,"",%progbits
#endif
#endif /* !WOLFSSL_ARMASM_INLINE */
